#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include <lf-queue/lf_shm_queue.h>
#include <unistd.h>
#include "pf_internal.h"
#include "pf_writer.h"

typedef struct trace_proc {
    pf_writer_t writer;
    lf_shm_queue_handle_t trace_queue;
    pid_t pid;
} trace_proc_t;

#define MAX_TRACE_PROCS 8
typedef struct daemon_ctx {
    lf_shm_queue_handle_t daemon_shm_queue;
    trace_proc_t trace_procs[MAX_TRACE_PROCS];
    bool stop;
} daemon_ctx_t;

static daemon_ctx_t dctx;

static int init()
{
	int res;
	int i;

	res = lf_shm_queue_init(&dctx.daemon_shm_queue, DEAMON_SHM_NAME,
	                        DEAMON_QUEUE_SIZE, sizeof(daemon_msg_t));
	if (res != 0) {
		printf("lf_shm_queue_init failed res=%d\n", res);
		return res;
	}

	for (i = 0; i < MAX_TRACE_PROCS; ++i) {
		dctx.trace_procs[i].pid = 0;
	}
	return 0;
}

static int terminate()
{
	// TODO cleanup
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

static void proc_start(daemon_msg_t *msg, trace_proc_t *proc)
{
	int res;

	proc->pid = 0;

	res = lf_shm_queue_attach(&proc->trace_queue, msg->shm_name,
	                          msg->cfg.trace_queue_size,
	                          msg->cfg.max_trace_message_size);
	if (res != 0) {
		printf("lf_shm_queue_attach failed err=%d\n", res);
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
}

static void proc_stop(trace_proc_t *proc)
{
	printf("stopping trace for pid=%d\n", proc->pid);
	pf_writer_stop(&proc->writer);
	lf_shm_queue_destroy(proc->trace_queue);
	proc->pid = 0;
}

static void handle_daemon_msg(daemon_msg_t *msg)
{

	printf("got msg file_name=%s shm_name=%s pid=%d\n",
	       msg->file_name_prefix, msg->shm_name, msg->proc_pid);
	proc_start(msg, get_free_trace_proc());
}

static void monitor_procs()
{
	int i;

	for (i = 0; i < MAX_TRACE_PROCS; ++i) {
		if (dctx.trace_procs[i].pid != 0 && kill(dctx.trace_procs[i].pid, 0) != 0) {
			proc_stop(&dctx.trace_procs[i]);
		}
	}
}

static void handle_msgs()
{
	lf_element_t element;
	lf_queue_handle_t queue;
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