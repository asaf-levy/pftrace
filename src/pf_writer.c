#include "pf_writer.h"
#include "pf_internal.h"
#include <stdbool.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <linux/limits.h>
#include <errno.h>
#include <stdlib.h>

struct pf_writer {
    bool stop;
    pthread_t writer_thread;
    lf_queue *queue;
    FILE *md_file;
    FILE *trc_file;
};

static void write_fmt_msg(pf_writer *writer, fmt_msg_t *msg, char *fmt_buf)
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

static void write_trc_msg(pf_writer *writer, trc_msg_t *msg, char *msg_buffer)
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

static void handle_queue_msg(pf_writer *writer, queue_msg_t *msg)
{
	switch (msg->type) {
	case FMT_MSG_TYPE:
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
	pf_writer *writer = arg;
	bool flush = false;

	while (!writer->stop) {
		queue_msg_t *msg = lf_queue_dequeue(writer->queue);
		if (msg != NULL) {
			handle_queue_msg(writer, msg);
			lf_queue_put(writer->queue, msg);
			flush = true;
		} else {
			if (flush) {
				fflush(writer->md_file);
				fflush(writer->trc_file);
				flush = false;
			} else {
				usleep(1000);
			}
		}
	}
	return 0;
}

static void flush_queue(pf_writer *writer)
{
	queue_msg_t *msg = lf_queue_dequeue(writer->queue);
	while (msg != NULL) {
		handle_queue_msg(writer, msg);
		lf_queue_put(writer->queue, msg);
		msg = lf_queue_dequeue(writer->queue);
	}
}

static int write_version(FILE *fd, uint64_t magic, uint64_t version)
{
	version_msg_t msg = {
		.magic = magic,
		.version = version,
	};

	size_t written = fwrite_unlocked(&msg, 1, sizeof(msg), fd);
	if (written != sizeof(msg)) {
		printf("write failed written=%lu err=%d\n", written, errno);
		return - 1;
	}
	return 0;
}

static int writer_init(pf_writer *writer, const char *file_name_prefix, int pid)
{
	int res;
	char file_path[PATH_MAX];
	char link_path[PATH_MAX];

	snprintf(file_path, sizeof(file_path), "%s.%d.md", file_name_prefix, pid);
	writer->md_file = fopen(file_path, "w");
	if (writer->md_file == NULL) {
		printf("failed to open %s err=%d\n", file_path, errno);
		return errno;
	}
	res = write_version(writer->md_file, MD_FILE_MAGIC, MD_FILE_VERSION);
	if (res != 0) {
		printf("md file write_version failed\n");
		fclose(writer->md_file);
		return res;
	}

	snprintf(file_path, sizeof(file_path), "%s.%d.trc", file_name_prefix, pid);
	writer->trc_file = fopen(file_path, "w");
	if (writer->trc_file == NULL) {
		fclose(writer->md_file);
		printf("failed to open %s err=%d\n", file_path, errno);
		return errno;
	}
	res = write_version(writer->trc_file, TRC_FILE_MAGIC, TRC_FILE_VERSION);
	if (res != 0) {
		printf("trc file write_version failed\n");
		fclose(writer->md_file);
		fclose(writer->trc_file);
		return res;
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

static void writer_terminate(pf_writer *writer)
{
	close_file(writer->md_file);
	close_file(writer->trc_file);
}

pf_writer *pf_writer_start(lf_queue *queue, const char *file_name_prefix, int pid)
{
	int res;

	pf_writer *writer = malloc(sizeof(*writer));
	if (writer == NULL) {
		return NULL;
	}

	writer->queue = queue;
	writer->stop = false;

	res = writer_init(writer, file_name_prefix, pid);
	if (res != 0) {
		free(writer);
		return NULL;
	}

	res = pthread_create(&writer->writer_thread, NULL, writer_func, writer);
	if (res != 0) {
		writer_terminate(writer);
		free(writer);
		return NULL;
	}
	return writer;
}

int pf_writer_stop(pf_writer *writer)
{
	writer->stop = true;
	pthread_join(writer->writer_thread, NULL);
	flush_queue(writer);
	writer_terminate(writer);
	free(writer);
	return 0;
}
