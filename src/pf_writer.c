#include "pf_writer.h"
#include "pf_internal.h"
#include <stdbool.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <linux/limits.h>
#include <errno.h>

typedef struct writer_ctx {
    bool stop;
    pthread_t writer_thread;
    lf_queue_handle_t queue;
    FILE *md_file;
    FILE *trc_file;
} writer_ctx_t;

static writer_ctx_t wctx;

void write_fmt_msg(fmt_msg_t *msg)
{
	size_t written;
	size_t write_size = sizeof(*msg) - sizeof(*msg->fmt);

	written = fwrite_unlocked(msg, 1, write_size, wctx.md_file);
	if (written != write_size) {
		printf("md write failed written=%lu err=%d\n", written, errno);
		return;
	}
	written = fwrite_unlocked(msg->fmt, 1, msg->fmt_len, wctx.md_file);
	if (written !=  msg->fmt_len) {
		printf("md write failed  written=%lu err=%d\n", written, errno);
		return;
	}
}

void write_trc_msg(trc_msg_t *msg)
{
	size_t written;
	size_t write_size = sizeof(*msg) - sizeof(*msg->buf);

	written = fwrite_unlocked(msg, 1, write_size, wctx.trc_file);
	if (written != write_size) {
		printf("md write failed written=%lu err=%d\n", written, errno);
		return;
	}
	written = fwrite_unlocked(msg->buf, 1, msg->buf_len, wctx.trc_file);
	if (written !=  msg->buf_len) {
		printf("md write failed  written=%lu err=%d\n", written, errno);
		return;
	}
}

void handle_queue_msg(lf_element_t *lfe)
{
	queue_msg_t *msg = lfe->data;
	switch (msg->type) {
	case FMT_MSG_TYPE:
		printf("got fmt msg len=%u fmt=%s\n", msg->fmt_msg.fmt_len, msg->fmt_msg.fmt);
		write_fmt_msg(&msg->fmt_msg);
		break;
	case TRC_MSG_TYPE:
		printf("got trc msg len=%u\n", msg->trc_msg.buf_len);
		write_trc_msg(&msg->trc_msg);
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

int open_files(const char *file_name_prefix)
{
	char file_path[PATH_MAX];
	char link_path[PATH_MAX];

	snprintf(file_path, sizeof(file_path), "%s.%d.md", file_name_prefix, getpid());
	wctx.md_file = fopen(file_path, "w");
	if (wctx.md_file == NULL) {
		printf("failed to open %s err=%d\n", file_path, errno);
		return errno;
	}
	snprintf(file_path, sizeof(file_path), "%s.%d.trc", file_name_prefix, getpid());
	wctx.trc_file = fopen(file_path, "w");
	if (wctx.trc_file == NULL) {
		fclose(wctx.md_file);
		printf("failed to open %s err=%d\n", file_path, errno);
		return errno;
	}
	snprintf(link_path, sizeof(link_path), "%s.latest.trc", file_name_prefix);
	symlink(file_path, link_path);

	return 0;
}

void close_files(void)
{
	// TODO error handling
	fclose(wctx.md_file);
	fclose(wctx.trc_file);
}

int start_writer(lf_queue_handle_t queue, const char *file_name_prefix)
{
	int res ;
	wctx.queue = queue;
	wctx.stop = false;

	res = open_files(file_name_prefix);
	if (res != 0) {
		return res;
	}

	return pthread_create(&wctx.writer_thread, NULL, writer, NULL);
}

int stop_writer()
{
	wctx.stop = true;
	pthread_join(wctx.writer_thread, NULL);
	close_files();
	return 0;
}
