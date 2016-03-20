#include <stdio.h>
#include <linux/limits.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <printf.h>
#include <unistd.h>
#include <time.h>
#include "pf_internal.h"

typedef struct reader_ctx {
    FILE *md_file;
    FILE *trc_file;
    char *formats[PF_MAX_MSG_ID];
    uint16_t *type_info[PF_MAX_MSG_ID];

} reader_ctx_t;

static reader_ctx_t rctx;

int init(const char *trc_file_name)
{
	ssize_t len;
	char tmp_path[PATH_MAX];
	char md_path[PATH_MAX];
	char *trc_pos;
	int i;

	// check if we got a symlink
	len = readlink(trc_file_name, tmp_path, sizeof(tmp_path)-1);
	if (len == -1) {
		if (errno != EINVAL) {
			printf("failed to read %s\n", trc_file_name);
			return 1;
		}
		// not a link use the name we got
		strncpy(tmp_path, trc_file_name, sizeof(tmp_path));
		tmp_path[len] = '\0';
	}

	rctx.trc_file = fopen(tmp_path, "r");
	if (rctx.trc_file == NULL) {
		printf("failed to open %s err=%d\n", trc_file_name, errno);
		return errno;
	}

	trc_pos = strstr(tmp_path, "trc");
	if (trc_pos == NULL) {
		fclose(rctx.trc_file);
		printf("invalid trace file name %s\n", trc_file_name);
		return EINVAL;
	}
	*trc_pos = 0;
	snprintf(md_path, sizeof(md_path), "%smd", tmp_path);
	rctx.md_file = fopen(md_path, "r");
	if (rctx.md_file == NULL) {
		fclose(rctx.trc_file);
		printf("failed to open %s err=%d\n", md_path, errno);
		return errno;
	}

	for (i = 0; i < PF_MAX_MSG_ID; ++i) {
		rctx.formats[i] = NULL;
		rctx.type_info[i] = NULL;
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
		free(rctx.type_info[i]);
	}
}

void usage(const char *exec_name)
{
	printf("%s [trace file path]\n", exec_name);
	exit(1);
}

void read_fmt_msg(void)
{
	int types[128];
	size_t i;
	size_t n_types;
	size_t bytes_read;
	fmt_msg_t fmt_msg;

	bytes_read = fread_unlocked(&fmt_msg, 1, sizeof(fmt_msg), rctx.md_file);
	if (bytes_read == 0) {
		// probably EOF
		return;
	}
	if (bytes_read != sizeof(fmt_msg)) {
		printf("read failed, bytes_read=%lu\n", bytes_read);
		return;
	}
	if (rctx.formats[fmt_msg.msg_id] != NULL) {
		return;
	}
	if (fmt_msg.fmt_len == 0) {
		printf("empty format message\n");
		return;
	}
	rctx.formats[fmt_msg.msg_id] = malloc(fmt_msg.fmt_len + 1);
	if (rctx.formats[fmt_msg.msg_id] == NULL) {
		printf("memory allocation failed\n");
		return;
	}
	bytes_read = fread_unlocked(rctx.formats[fmt_msg.msg_id], 1, fmt_msg.fmt_len, rctx.md_file);
	if (bytes_read != fmt_msg.fmt_len) {
		printf("read failed, bytes_read=%lu\n", bytes_read);
		free(rctx.formats[fmt_msg.msg_id]);
		rctx.formats[fmt_msg.msg_id] = NULL;
		return;
	}

	n_types = parse_printf_format(rctx.formats[fmt_msg.msg_id], sizeof(types), types);
	rctx.type_info[fmt_msg.msg_id] = calloc(n_types + 1, sizeof(uint16_t));
	if (rctx.type_info[fmt_msg.msg_id] == NULL) {
		printf("memory allocation failed\n");
		return;
	}
	for (i = 0; i < n_types; ++i) {
		// thou the types are ints in practice only 16 bits are used
		rctx.type_info[fmt_msg.msg_id][i] = (uint16_t)types[i];
	}
	rctx.type_info[fmt_msg.msg_id][i] = PA_LAST;
}

void read_md_file(void)
{
	while (feof(rctx.md_file) == 0) {
		read_fmt_msg();
	}
}

#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#pragma GCC diagnostic ignored "-Wformat-security"
#define MAX_OUTPUT_SIZE 4096
void parse_trc_msg(char *p_out, char *p_fmt, char *buf, uint16_t *type_info)
{
	int i = 0;
	char *lit_end;
	char tmp;
	char *p_buf = buf;
	int spres;

	#define PARSE_ARG(T, TSTR) \
                if (((size_t)(p_buf - buf) + sizeof(T)) > MAX_OUTPUT_SIZE) { \
                        break; \
                } \
                p_out += sprintf(p_out, TSTR, *((T*)p_buf)); \
                p_buf += sizeof(T);

	while (*p_fmt) {
		if (*p_fmt == '%' && *(p_fmt + 1) != '%') {
			lit_end = p_fmt;
			for ( ; *lit_end != ' ' && *lit_end != '\0' ; lit_end++) { }
			tmp = *lit_end;
			*lit_end = '\0';

			switch (type_info[i]) {
			case PA_INT:
			PARSE_ARG(int, p_fmt);
				break;
			case PA_INT | PA_FLAG_LONG:
			PARSE_ARG(long, p_fmt);
				break;
			case PA_INT | PA_FLAG_LONG_LONG:
			PARSE_ARG(long long, p_fmt);
				break;
			case PA_INT | PA_FLAG_SHORT:
			PARSE_ARG(short, p_fmt);
				break;
			case PA_CHAR:
			PARSE_ARG(char, p_fmt);
				break;
			case PA_STRING:
				spres = sprintf(p_out, p_fmt, p_buf);
				p_out += spres;
				p_buf += spres + 1;
				break;
			case PA_POINTER:
			PARSE_ARG(void*, p_fmt);
				break;
			case PA_FLOAT:
			PARSE_ARG(float, p_fmt);
				break;
			case PA_DOUBLE:
			PARSE_ARG(double, p_fmt);
				break;
			case PA_DOUBLE | PA_FLAG_LONG_DOUBLE:
			PARSE_ARG(long double, p_fmt);
				break;
			case PA_LAST:
				// TODO handle truncation
				break;
			default:
				printf("[ERR]: unknown string format %d\n", type_info[i]);
				break;
			}
			i++;
			*lit_end = tmp;
			p_fmt = lit_end;
		} else {
			*p_out = *p_fmt;
			++p_fmt;
			++p_out;
		}
	}
	*p_out = '\n';
	p_out++;
	*p_out = '\0';
}

size_t append_time(trc_msg_t *trc_msg, char *p_out)
{
	time_t nsec = trc_msg->timestamp_nsec % NSEC_IN_SEC;
	time_t sec = trc_msg->timestamp_nsec / NSEC_IN_SEC;
	size_t res;

	struct tm *lt = localtime(&sec);
	if (lt == NULL) {
		printf("local time failed, error %d\n", errno);
		return 0;
	}
	res = strftime(p_out, MAX_OUTPUT_SIZE, "%Y-%m-%d %T", lt);
	if (res == 0) {
		printf("strftime failed, error %d\n", errno);
		return 0;
	}
	return res + sprintf(p_out + res, ".%09ld (%u) ", nsec, trc_msg->tid);
}

void print_trc_msg(trc_msg_t *trc_msg, char *buf)
{
	char output[MAX_OUTPUT_SIZE];
	size_t res;

	if (rctx.formats[trc_msg->msg_id] == NULL) {
		printf("trace msg %u has no format\n", trc_msg->msg_id);
		return;
	}

	res = append_time(trc_msg, output);
	parse_trc_msg(output + res, rctx.formats[trc_msg->msg_id], buf,
	              rctx.type_info[trc_msg->msg_id]);

	printf(output);
}
#pragma GCC diagnostic warning "-Wformat-nonliteral"
#pragma GCC diagnostic warning "-Wformat-security"

void read_trc_msg(void)
{
	char buf[512];
	size_t bytes_read;
	trc_msg_t trc_msg;

	bytes_read = fread_unlocked(&trc_msg, 1, sizeof(trc_msg), rctx.trc_file);
	if (bytes_read == 0) {
		// probably EOF
		return;
	}
	if (bytes_read != sizeof(trc_msg)) {
		printf("read failed, bytes_read=%lu\n", bytes_read);
		return;
	}
	if (trc_msg.buf_len > 0) {
		bytes_read = fread_unlocked(buf, 1, trc_msg.buf_len,
		                            rctx.trc_file);
		if (bytes_read != trc_msg.buf_len) {
			printf("read failed, bytes_read=%lu\n", bytes_read);
			return;
		}
	}
	print_trc_msg(&trc_msg, buf);
}

void read_trc_file(void)
{
	while (feof(rctx.trc_file) == 0) {
		read_trc_msg();
	}
}

void print_traces(void)
{
	read_md_file();
	read_trc_file();
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