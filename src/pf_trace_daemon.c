#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include <lf-queue/lf_shm_queue.h>
#include <unistd.h>
#include "pf_internal.h"
#include "pf_writer.h"

typedef struct daemon_ctx {
    lf_shm_queue_handle_t daemon_shm_queue;
    pf_writer_t writer;
    lf_shm_queue_handle_t trace_queue;
    bool stop;
} daemon_ctx_t;

static daemon_ctx_t dctx;

static int init()
{
	int res;

	res = lf_shm_queue_init(&dctx.daemon_shm_queue, DEAMON_SHM_NAME,
	                        DEAMON_QUEUE_SIZE, sizeof(daemon_msg_t));
	if (res != 0) {
		printf("lf_shm_queue_init failed res=%d\n", res);
		return res;
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

static void handle_daemon_msg(daemon_msg_t *msg)
{
	int res;
	printf("got msg file_name=%s shm_name=%s pid=%d\n",
	       msg->file_name_prefix, msg->shm_name, msg->proc_pid);

	res = lf_shm_queue_attach(&dctx.trace_queue, msg->shm_name,
	                          msg->cfg.trace_queue_size,
	                          msg->cfg.max_trace_message_size);
	if (res != 0) {
		printf("lf_shm_queue_attach failed err=%d\n", res);
		return;
	}

	res = pf_writer_start(&dctx.writer,
	                      lf_shm_queue_get_underlying_handle(dctx.trace_queue),
	                      msg->file_name_prefix);
	if (res != 0) {
		printf("pf_writer_start failed err=%d\n", res);
		return;
	}
	return;
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