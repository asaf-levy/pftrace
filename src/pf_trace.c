#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <printf.h>
#include <malloc.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <syscall.h>
#include <lf-queue/lf_queue.h>
#include <lf-queue/lf_shm_queue.h>
#include "pf_trace.h"
#include "pf_internal.h"
#include "pf_writer.h"

#define INITIAL_MSG_ID 8

typedef struct pf_trace {
    pf_trace_config_t trace_cfg;
    pf_writer *writer;
    lf_queue *trace_queue;
    lf_shm_queue *shm_trace_queue;
    uint16_t current_msg_id;
    uint16_t *type_info[PF_MAX_MSG_ID];
    lf_shm_queue *daemon_shm_queue;
} pf_trace_t;

static pf_trace_t trace_ctx;

__thread pid_t g_tid = 0;
pid_t get_tid(void)
{
	if (!g_tid) {
		g_tid = (pid_t)syscall(SYS_gettid);
	}
	return g_tid;
}

static int local_init() {
	trace_ctx.trace_queue = lf_queue_init(trace_ctx.trace_cfg.trace_queue_size,
	                                      trace_ctx.trace_cfg.max_trace_message_size);
	if (trace_ctx.trace_queue == NULL) {
		return ENOMEM;
	}
	trace_ctx.writer = pf_writer_start(trace_ctx.trace_queue, trace_ctx.trace_cfg.file_name_prefix, getpid());
	if (trace_ctx.writer == NULL) {
		lf_queue_destroy(trace_ctx.trace_queue);
		return ENOMEM;
	}
	return 0;
}

static int send_setup_message(const char *shm_name)
{
	lf_queue *queue = lf_shm_queue_get_underlying_handle(trace_ctx.daemon_shm_queue);
	daemon_msg_t *msg = lf_queue_get(queue);
	if (msg == NULL) {
		printf("lf_queue_get failed");
		return ENOMEM;
	}
	msg->type = DSETUP_MSG_TYPE;
	daemon_setup_msg_t *smsg = &msg->setup_msg;

	strncpy(smsg->file_name_prefix, trace_ctx.trace_cfg.file_name_prefix,
	        sizeof(smsg->file_name_prefix));
	smsg->proc_pid = getpid();
	strncpy(smsg->shm_name, shm_name, sizeof(smsg->shm_name));
	smsg->cfg = trace_ctx.trace_cfg;

	lf_queue_enqueue(queue, msg);
	return 0;
}

static int send_teardown_message()
{
	lf_queue *queue = lf_shm_queue_get_underlying_handle(trace_ctx.daemon_shm_queue);
	daemon_msg_t *msg = lf_queue_get(queue);
	if (msg == NULL) {
		printf("lf_queue_get failed");
		return ENOMEM;
	}

	msg->type = DTEARDOWN_MSG_TYPE;
	msg->teardown_msg.proc_pid = getpid();

	lf_queue_enqueue(queue, msg);
	return 0;
}

static int daemon_init()
{
	char shm_name[PF_MAX_NAME];
	pid_t pid = getpid();

	snprintf(shm_name, sizeof(shm_name), "pf_trace_mem.%d", pid);
	trace_ctx.shm_trace_queue = lf_shm_queue_init(shm_name, trace_ctx.trace_cfg.trace_queue_size,
	                                              trace_ctx.trace_cfg.max_trace_message_size);
	if (trace_ctx.shm_trace_queue == NULL) {
		printf("lf_shm_queue_init failed");
		return ENOMEM;
	}
	trace_ctx.trace_queue = lf_shm_queue_get_underlying_handle(trace_ctx.shm_trace_queue);

	trace_ctx.daemon_shm_queue = lf_shm_queue_attach(DEAMON_SHM_NAME, DEAMON_QUEUE_SIZE, sizeof(daemon_msg_t));
	if (trace_ctx.daemon_shm_queue == NULL) {
		printf("lf_shm_queue_attach failed");
		return ENOMEM;
	}

	return send_setup_message(shm_name);
}

int pf_trace_init(pf_trace_config_t *trace_cfg)
{
	int i;

	trace_ctx.current_msg_id = INITIAL_MSG_ID;
	for (i = 0; i < PF_MAX_MSG_ID; ++i) {
		trace_ctx.type_info[i] = NULL;
	}
	trace_ctx.trace_cfg = *trace_cfg;

	if (trace_cfg->use_trace_daemon) {
		return daemon_init();
	} else {
		return local_init();
	}
}

int pf_trace_destroy(void)
{
	int i;

	if (trace_ctx.trace_cfg.use_trace_daemon) {
		send_teardown_message();
		lf_shm_queue_deattach(trace_ctx.daemon_shm_queue);
		lf_shm_queue_destroy(trace_ctx.shm_trace_queue);
	} else {
		pf_writer_stop(trace_ctx.writer);
		lf_queue_destroy(trace_ctx.trace_queue);
	}
	for (i = 0; i < PF_MAX_MSG_ID; ++i) {
		free(trace_ctx.type_info[i]);
	}
	return 0;
}

uint16_t gen_msg_id()
{
	return __sync_add_and_fetch(&trace_ctx.current_msg_id, 1);
}

pf_trc_level_t get_trc_level(void)
{
	return trace_ctx.trace_cfg.level;
}

void pf_trace_set_level(pf_trc_level_t level)
{
	trace_ctx.trace_cfg.level = level;
}

const char *trc_level_to_str(pf_trc_level_t level)
{
	switch (level) {
	case PF_TRC_DEBUG:      return "DBG";
	case PF_TRC_INFO:       return "INF";
	case PF_TRC_NOTICE:     return "NTC";
	case PF_TRC_WARNING:    return "WRN";
	case PF_TRC_ERROR:      return "ERR";
	case PF_TRC_FATAL:      return "FTL";
	default:                return "N/A";
	}
}

static int build_fmt(char *fmt_buffer, uint16_t msg_id, const char *file, int line,
              const char *func, pf_trc_level_t level, const char *fmt)
{
	return snprintf(fmt_buffer,
	                trace_ctx.trace_cfg.max_trace_message_size - sizeof(queue_msg_t),
	                "[%s] %s:%d %s() %s", trc_level_to_str(level),
	                basename(file), line, func, fmt);
}

static int store_fmt_info(uint16_t msg_id, const char *fmt)
{
	size_t i;
	int types[128];
	size_t n_types;
	uint16_t *type_info;
	bool swap_res;

	n_types = parse_printf_format(fmt, sizeof(types), types);
	type_info = calloc(n_types + 1, sizeof(uint16_t));
	if (type_info == NULL) {
		return ENOMEM;
	}
	for (i = 0; i < n_types; ++i) {
		// thou the types are ints in practice only 16 bits are used
		type_info[i] = (uint16_t)types[i];
	}
	type_info[i] = PA_LAST;
	swap_res = __sync_bool_compare_and_swap(&trace_ctx.type_info[msg_id], NULL, type_info);
	if (!swap_res) {
		// some other thread already filled in the types info
		free(type_info);
		return EALREADY;
	}

	return 0;
}

int pf_trace_fmt(uint16_t msg_id, const char *file, int line,
                 const char *func, pf_trc_level_t level,
                 const char *fmt)
{
	fmt_msg_t *fmt_msg;
	int res;

	if (trace_ctx.type_info[msg_id] != NULL) {
		// format for this message was already processed
		return EALREADY;
	}
	queue_msg_t *q_msg = lf_queue_get(trace_ctx.trace_queue);
	if (q_msg == NULL) {
		// no place in the trace queue now
		return ENOMEM;
	}

	res = store_fmt_info(msg_id, fmt);
	if (res != 0) {
		lf_queue_put(trace_ctx.trace_queue, q_msg);
		return res;
	}
	q_msg->type = FMT_MSG_TYPE;
	fmt_msg = &q_msg->fmt_msg;
	fmt_msg->msg_id = msg_id;
	// TODO handle truncation
	fmt_msg->fmt_len = build_fmt(qmsg_buffer(q_msg), msg_id, file, line,
	                             func, level, fmt);
	lf_queue_enqueue(trace_ctx.trace_queue, q_msg);
	return 0;
}

static void store_arg(void *p, size_t sz, trc_msg_t *trc_msg, char *msg_buffer)
{
	// TODO handle buffer overrun
	memcpy(msg_buffer + trc_msg->buf_len, p, sz);
	trc_msg->buf_len += sz;
}

static void store_args(uint16_t msg_id, va_list vl, trc_msg_t *trc_msg, char *msg_buffer)
{
	int i;
	int val_int;
	long int val_l_int;
	long long int val_ll_int;
	short int val_s_int;
	char val_chr;
	char *val_str;
	void *val_ptr;
	float val_flt;
	double val_dbl;
	long double val_l_dbl;

	uint16_t *types = trace_ctx.type_info[msg_id];
	trc_msg->buf_len = 0;

	for (i = 0 ; types[i] != PA_LAST ; i++) {
		switch (types[i]) {
		case PA_INT:
			val_int = va_arg(vl, int);
			store_arg((void *) &val_int, sizeof(val_int), trc_msg, msg_buffer);
			break;
		case PA_INT | PA_FLAG_LONG:
			val_l_int = va_arg(vl, long int);
			store_arg((void *) &val_l_int, sizeof(val_l_int), trc_msg, msg_buffer);
			break;
		case PA_INT | PA_FLAG_LONG_LONG:
			val_ll_int = va_arg(vl, long long int);
			store_arg((void *) &val_ll_int, sizeof(val_ll_int), trc_msg, msg_buffer);
			break;
		case PA_INT | PA_FLAG_SHORT:
			val_int = va_arg(vl, int);
			val_s_int = (short int)val_int;
			store_arg((void *) &val_s_int, sizeof(val_s_int), trc_msg, msg_buffer);
			break;
		case PA_CHAR:
			val_int = va_arg(vl, int);
			val_chr = (char)val_int;
			store_arg((void *) &val_chr, sizeof(val_chr), trc_msg, msg_buffer);
			break;
		case PA_STRING:
			val_str = va_arg(vl, char *);
			if (!val_str) {
				val_str = (char *)"<NULL>";
			}
			store_arg((void *)val_str, strlen(val_str), trc_msg, msg_buffer);
			break;
		case PA_POINTER:
			val_ptr = va_arg(vl, void *);
			store_arg(&val_ptr, sizeof(val_ptr), trc_msg, msg_buffer);
			break;
		case PA_FLOAT:
			val_dbl = va_arg(vl, double);
			val_flt = (float) val_dbl;
			store_arg((void *) &val_flt, sizeof(val_flt), trc_msg, msg_buffer);
			break;
		case PA_DOUBLE:
			val_dbl = va_arg(vl, double);
			store_arg((void *) &val_dbl, sizeof(val_dbl), trc_msg, msg_buffer);
			break;
		case PA_DOUBLE | PA_FLAG_LONG_DOUBLE:
			val_l_dbl = va_arg(vl, long double);
			store_arg((void *) &val_l_dbl, sizeof(val_l_dbl), trc_msg, msg_buffer);
			break;
		case PA_LAST:
			break;
		default:
			printf("[ERR]: unknown string format %d\n", types[i]);
			break;
		}
	}
}

void pf_trace(uint16_t msg_id, const char *fmt, ...)
{
	va_list vl;
	trc_msg_t *trc_msg;
	struct timespec now;

	if (trace_ctx.type_info[msg_id] == NULL) {
		return;
	}
	queue_msg_t *q_msg = lf_queue_get(trace_ctx.trace_queue);
	if (q_msg == NULL) {
		// no place in the trace queue now
		return;
	}
	clock_gettime(CLOCK_REALTIME, &now);

	va_start(vl, fmt);
	q_msg->type = TRC_MSG_TYPE;
	trc_msg = &q_msg->trc_msg;
	trc_msg->msg_id = msg_id;
	trc_msg->tid = (uint16_t)get_tid();
	trc_msg->timestamp_nsec = (uint64_t)(now.tv_nsec + (now.tv_sec * NSEC_IN_SEC));
	store_args(msg_id, vl, trc_msg, qmsg_buffer(q_msg));
	lf_queue_enqueue(trace_ctx.trace_queue, q_msg);
	va_end(vl);
}
