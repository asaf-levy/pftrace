#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <lf-queue/lf_shm_queue.h>
#include <unistd.h>
#include "pf_internal.h"
#include "pf_writer.h"

typedef struct trace_proc {
    pf_writer_t writer;
    lf_shm_queue *trace_queue;
    pid_t pid;
    bool proc_lost;
} trace_proc_t;

#define MAX_TRACE_PROCS 8
typedef struct daemon_ctx {
    lf_shm_queue *daemon_shm_queue;
    trace_proc_t trace_procs[MAX_TRACE_PROCS];
    bool stop;
} daemon_ctx_t;

static daemon_ctx_t dctx;

static void proc_stop(trace_proc_t *proc, bool process_lost)
{
	printf("stopping trace for pid=%d\n", proc->pid);
	pf_writer_stop(&proc->writer);
	if (process_lost) {
		// if the process was lost destroy so the shared memory segment
		// will be unlinked
		lf_shm_queue_destroy(proc->trace_queue);
	} else {
		lf_shm_queue_deattach(proc->trace_queue);
	}
	proc->pid = 0;
}

static void proc_start(daemon_setup_msg_t *msg, trace_proc_t *proc)
{
	int res;

	proc->pid = 0;

	printf("Start tracing for file_name=%s shm_name=%s pid=%d\n",
	       msg->file_name_prefix, msg->shm_name, msg->proc_pid);
	proc->trace_queue = lf_shm_queue_attach(msg->shm_name,
	                          msg->cfg.trace_queue_size,
	                          msg->cfg.max_trace_message_size);
	if (proc->trace_queue == NULL) {
		printf("lf_shm_queue_attach failed\n");
		return;
	}

	res = pf_writer_start(&proc->writer,
	                      lf_shm_queue_get_underlying_handle(proc->trace_queue),
	                      msg->file_name_prefix, msg->proc_pid);
	if (res != 0) {
		lf_shm_queue_deattach(proc->trace_queue);
		printf("pf_writer_start failed err=%d\n", res);
		return;
	}
	proc->pid = msg->proc_pid;
	proc->proc_lost = false;
}

static void proc_pid_stop(pid_t proc_pid)
{
	int i;

	for (i = 0; i < MAX_TRACE_PROCS; ++i) {
		if (dctx.trace_procs[i].pid == proc_pid) {
			proc_stop(&dctx.trace_procs[i], false);
		}
	}
}

static int init()
{
	int i;

	dctx.daemon_shm_queue = lf_shm_queue_init(DEAMON_SHM_NAME, DEAMON_QUEUE_SIZE,
	                                          sizeof(daemon_msg_t));
	if (dctx.daemon_shm_queue == NULL) {
		printf("lf_shm_queue_init failed\n");
		return ENOMEM;
	}

	for (i = 0; i < MAX_TRACE_PROCS; ++i) {
		dctx.trace_procs[i].pid = 0;
	}
	return 0;
}

static int terminate()
{
	int i;

	for (i = 0; i < MAX_TRACE_PROCS; ++i) {
		if (dctx.trace_procs[i].pid != 0) {
			proc_stop(&dctx.trace_procs[i], false);
		}
	}
	lf_shm_queue_destroy(dctx.daemon_shm_queue);

	return 0;
}

static void sig_handler(int sig)
{
	dctx.stop = true;
}

static trace_proc_t *get_free_trace_proc()
{
	int i;

	for (i = 0; i < MAX_TRACE_PROCS; ++i) {
		if (dctx.trace_procs[i].pid == 0) {
			return &dctx.trace_procs[i];
		}
	}
	return NULL;
}

static void handle_daemon_msg(daemon_msg_t *msg)
{
	switch (msg->type) {
	case DSETUP_MSG_TYPE:
		proc_start(&msg->setup_msg, get_free_trace_proc());
		break;
	case DTEARDOWN_MSG_TYPE:
		proc_pid_stop(msg->teardown_msg.proc_pid);
		break;
	default:
		printf("unknown msg type %d", msg->type);
	}
}

static void monitor_procs()
{
	int i;
	trace_proc_t *proc;

	for (i = 0; i < MAX_TRACE_PROCS; ++i) {
		proc = &dctx.trace_procs[i];
		if (proc->pid != 0 && kill(proc->pid, 0) != 0) {
			if (proc->proc_lost) {
				proc_stop(proc, true);
			} else {
				// stop the process tracing only after the second
				// time it fails to answer the signal in order to
				// give us a chance to process the teardown message
				proc->proc_lost = true;
			}
		}
	}
}

static void handle_msgs()
{
	lf_element_t element;
	lf_queue *queue;
	int res;

	queue = lf_shm_queue_get_underlying_handle(dctx.daemon_shm_queue);

	while (!dctx.stop) {
		res = lf_queue_dequeue(queue, &element);
		if (res == 0) {
			handle_daemon_msg(element.data);
		}
		monitor_procs();
		sleep(1);
	}
}

int main()
{
	int res = init();
	if (res != 0) {
		printf("init failed");
		return 1;
	}
	signal(SIGINT, sig_handler);
	printf("pf trace daemon started\n");

	handle_msgs();

	printf("pf trace daemon existing\n");
	terminate();
	return 0;
}