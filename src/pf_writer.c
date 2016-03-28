#include "pf_writer.h"
#include "pf_internal.h"
#include <stdbool.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <linux/limits.h>
#include <errno.h>
#include <stdlib.h>

typedef struct pf_writer_impl {
    bool stop;
    pthread_t writer_thread;
    lf_queue_handle_t queue;
    FILE *md_file;
    FILE *trc_file;
} pf_writer_impl_t;

static void write_fmt_msg(pf_writer_impl_t *writer, fmt_msg_t *msg, char *fmt_buf)
{
	size_t written;

	written = fwrite_unlocked(msg, 1, sizeof(*msg), writer->md_file);
	if (written != sizeof(*msg)) {
		printf("md write failed written=%lu err=%d\n", written, errno);
		return;
	}
	written = fwrite_unlocked(fmt_buf, 1, msg->fmt_len, writer->md_file);
	if (written !=  msg->fmt_len) {
		printf("md write failed  written=%lu err=%d\n", written, errno);
		return;
	}
}

static void write_trc_msg(pf_writer_impl_t *writer, trc_msg_t *msg, char *msg_buffer)
{
	size_t written;

	written = fwrite_unlocked(msg, 1, sizeof(*msg), writer->trc_file);
	if (written != sizeof(*msg)) {
		printf("write failed written=%lu err=%d\n", written, errno);
		return;
	}
	if (msg->buf_len > 0) {
		written = fwrite_unlocked(msg_buffer, 1, msg->buf_len,
		                          writer->trc_file);
		if (written != msg->buf_len) {
			printf("write failed written=%lu err=%d\n", written,
			       errno);
			return;
		}
	}
}

static void handle_queue_msg(pf_writer_impl_t *writer, lf_element_t *lfe)
{
	queue_msg_t *msg = lfe->data;
	switch (msg->type) {
	case FMT_MSG_TYPE:
		printf("got fmt msg len=%u fmt=%s\n", msg->fmt_msg.fmt_len,
		       qmsg_buffer(msg));
		write_fmt_msg(writer, &msg->fmt_msg, qmsg_buffer(msg));
		break;
	case TRC_MSG_TYPE:
		write_trc_msg(writer, &msg->trc_msg, qmsg_buffer(msg));
		break;
	default:
		printf("[ERR] unknown msg type %d\n", msg->type);
	}
}

static void *writer_func(void *arg)
{
	pf_writer_impl_t *writer = arg;
	lf_element_t lfe;

	while (!writer->stop) {
		if (lf_queue_dequeue(writer->queue, &lfe) == 0) {
			handle_queue_msg(writer, &lfe);
			lf_queue_put(writer->queue, &lfe);
		} else {
			usleep(1000);
		}
	}
	return 0;
}

static int writer_init(pf_writer_impl_t *writer, const char *file_name_prefix)
{
	char file_path[PATH_MAX];
	char link_path[PATH_MAX];

	snprintf(file_path, sizeof(file_path), "%s.%d.md", file_name_prefix, getpid());
	writer->md_file = fopen(file_path, "w");
	if (writer->md_file == NULL) {
		printf("failed to open %s err=%d\n", file_path, errno);
		return errno;
	}
	snprintf(file_path, sizeof(file_path), "%s.%d.trc", file_name_prefix, getpid());
	writer->trc_file = fopen(file_path, "w");
	if (writer->trc_file == NULL) {
		fclose(writer->md_file);
		printf("failed to open %s err=%d\n", file_path, errno);
		return errno;
	}
	snprintf(link_path, sizeof(link_path), "%s.latest.trc", file_name_prefix);
	unlink(link_path);
	symlink(file_path, link_path);

	return 0;
}

static void close_file(FILE *file)
{
	if (file != NULL) {
		fflush(file);
		fsync(fileno(file));
		fclose(file);
	}
}

static void writer_terminate(pf_writer_impl_t *writer)
{
	// TODO error handling
	close_file(writer->md_file);
	close_file(writer->trc_file);
}

int pf_writer_start(pf_writer_t *writer, lf_queue_handle_t queue, const char *file_name_prefix)
{
	int res;
	pf_writer_impl_t *writer_impl;

	writer_impl = malloc(sizeof(*writer_impl));
	if (writer_impl == NULL) {
		return ENOMEM;
	}

	writer_impl->queue = queue;
	writer_impl->stop = false;

	res = writer_init(writer_impl, file_name_prefix);
	if (res != 0) {
		return res;
	}

	res = pthread_create(&writer_impl->writer_thread, NULL, writer_func, writer_impl);
	if (res != 0) {
		free(writer_impl);
		return res;
	}
	writer->handle = writer_impl;
	return 0;
}

int pf_writer_stop(pf_writer_t *writer)
{
	pf_writer_impl_t *writer_impl = writer->handle;
	writer_impl->stop = true;
	pthread_join(writer_impl->writer_thread, NULL);
	writer_terminate(writer_impl);
	return 0;
}
