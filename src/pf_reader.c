#include <stdio.h>
#include <linux/limits.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "pf_internal.h"

typedef struct reader_ctx {
    FILE *md_file;
    FILE *trc_file;
    char *formats[PF_MAX_MSG_ID];
} reader_ctx_t;

static reader_ctx_t rctx;

int init(const char *trc_file_name)
{
	char tmp_path[PATH_MAX];
	char md_path[PATH_MAX];
	char *trc_pos;
	int i;

	// TODO follow sym link

	strncpy(tmp_path, trc_file_name, sizeof(tmp_path));
	trc_pos = strstr(tmp_path, "trc");
	if (trc_pos == NULL) {
		printf("invalid trace file name %s\n", trc_file_name);
		return EINVAL;
	}
	*trc_pos = 0;
	snprintf(md_path, sizeof(md_path), "%smd", tmp_path);

	rctx.trc_file = fopen(trc_file_name, "r");
	if (rctx.trc_file == NULL) {
		printf("failed to open %s err=%d\n", trc_file_name, errno);
		return errno;
	}

	rctx.md_file = fopen(md_path, "r");
	if (rctx.md_file == NULL) {
		fclose(rctx.trc_file);
		printf("failed to open %s err=%d\n", md_path, errno);
		return errno;
	}

	for (i = 0; i < PF_MAX_MSG_ID; ++i) {
		rctx.formats[i] = NULL;
	}

	return 0;
}

void terminate(void)
{
	int i;

	fclose(rctx.trc_file);
	fclose(rctx.md_file);
	for (i = 0; i < PF_MAX_MSG_ID; ++i) {
		free(rctx.formats[i]);
	}

}

void usage(const char *exec_name)
{
	printf("%s [trace file path]\n", exec_name);
	exit(1);
}

size_t read_fmt_msg(void)
{
	size_t bytes_read;
	fmt_msg_t fmt_msg;

	bytes_read = fread_unlocked(&fmt_msg, 1, sizeof(fmt_msg), rctx.md_file);
	if (bytes_read == 0) {
		// probably EOF
		return 0;
	}
	if (bytes_read != sizeof(fmt_msg)) {
		printf("read failed, bytes_read=%lu\n", bytes_read);
		return EIO;
	}
	if (rctx.formats[fmt_msg.msg_id] != NULL) {
		return 0;
	}
	if (fmt_msg.fmt_len == 0) {
		return 0;
	}
	rctx.formats[fmt_msg.msg_id] = malloc(fmt_msg.fmt_len + 1);
	if (rctx.formats[fmt_msg.msg_id] == NULL) {
		return ENOMEM;
	}
	bytes_read = fread_unlocked(rctx.formats[fmt_msg.msg_id], 1, fmt_msg.fmt_len, rctx.md_file);
	if (bytes_read != fmt_msg.fmt_len) {
		printf("read failed, bytes_read=%lu\n", bytes_read);
		free(rctx.formats[fmt_msg.msg_id]);
		rctx.formats[fmt_msg.msg_id] = NULL;
		return EIO;
	}
	printf("read %s\n", rctx.formats[fmt_msg.msg_id]);
	return 0;
}

void read_md_file(void)
{
	while (feof(rctx.md_file) == 0) {
		read_fmt_msg();
	}
}

void print_traces(void)
{
	read_md_file();
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
	}
	if (init(argv[1]) != 0) {
		return 1;
	}
	print_traces();
	terminate();
	return 0;
}