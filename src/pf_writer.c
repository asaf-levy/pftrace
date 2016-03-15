#include "pf_writer.h"
#include "pf_internal.h"
#include <stdbool.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

typedef struct writer_ctx {
    bool stop;
    pthread_t writer_thread;
    lf_queue_handle_t queue;
} writer_ctx_t;

static writer_ctx_t wctx;

void handle_queue_msg(lf_element_t *lfe)
{
	queue_msg_t *msg = lfe->data;
	switch (msg->type) {
	case FMT_MSG_TYPE:
		printf("got fmt msg len=%u fmt=%s\n", msg->fmt_msg.fmt_len, msg->fmt_msg.fmt);
		break;
	case TRC_MSG_TYPE:
		printf("got trc msg len=%u\n", msg->trc_msg.buf_len);
		break;
	default:
		printf("[ERR] unknown msg type %d\n", msg->type);
	}
}

void *writer(void *arg)
{
	lf_element_t *lfe;

	while (!wctx.stop) {
		if (lf_queue_dequeue(wctx.queue, &lfe) == 0) {
			handle_queue_msg(lfe);
			lf_queue_put(wctx.queue, lfe);
		} else {
			usleep(1000);
		}
	}
	return 0;
}

int start_writer(lf_queue_handle_t queue)
{
	wctx.queue = queue;
	wctx.stop = false;
	return pthread_create(&wctx.writer_thread, NULL, writer, NULL);
}

int stop_writer()
{
	wctx.stop = true;
	return pthread_join(wctx.writer_thread, NULL);
}
