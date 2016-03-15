#include <syscall.h>
#include <unistd.h>
#include <printf.h>
#include <malloc.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include "pf_trace.h"
#include "lf-queue/lf_queue.h"

#define TRACE_MSG_SIZE 512
#define INITIAL_MSG_ID 8
#define MAX_MSG_ID 65535

typedef struct pf_trace {
    pf_trace_config_t trace_cfg;
    lf_queue_handle_t trace_queue;
    uint16_t current_msg_id;
    uint16_t *type_info[MAX_MSG_ID];
} pf_trace_t;

typedef struct fmt_msg {
    uint16_t msg_id;
    uint16_t fmt_len;
    char *fmt;
} fmt_msg_t;

typedef struct trc_msg {
    uint16_t msg_id;
    uint16_t buf_len;
    uint32_t tid;
    uint64_t timestamp;
    char *buff;
} trc_msg_t;

#define FMT_MSG_TYPE 1
#define TRC_MSG_TYPE 2
typedef struct queue_msg {
    uint8_t type;
    union {
        fmt_msg_t fmt_msg;
        trc_msg_t trc_msg;
    };
} queue_msg_t;

static pf_trace_t trace_ctx;

__thread pid_t g_tid = 0;
pid_t get_tid(void)
{
	if (!g_tid) {
		g_tid = (pid_t)syscall(SYS_gettid);
	}
	return g_tid;
}

int pf_trace_init(pf_trace_config_t *trace_cfg)
{
	int i;
	int err = lf_queue_init(&trace_ctx.trace_queue,
	                        trace_cfg->trace_queue_size,
	                        TRACE_MSG_SIZE);
	if (err) {
		return err;
	}
	trace_ctx.current_msg_id = INITIAL_MSG_ID;
	for (i = 0; i < MAX_MSG_ID; ++i) {
		trace_ctx.type_info[i] = NULL;
	}
	trace_ctx.trace_cfg = *trace_cfg;
	return 0;
}

int pf_trace_destroy(void)
{
	int i;

	for (i = 0; i < MAX_MSG_ID; ++i) {
		free(trace_ctx.type_info[i]);
	}
	lf_queue_destroy(trace_ctx.trace_queue);
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

void build_fmt_msg(fmt_msg_t *fmt_msg, uint16_t msg_id, const char *file, int line,
                   const char *func, pf_trc_level_t level, const char *fmt)
{
	fmt_msg->msg_id = msg_id;
	// TODO handle truncation
	fmt_msg->fmt_len = snprintf(fmt_msg->fmt, TRACE_MSG_SIZE - sizeof(queue_msg_t),
	                           "%s:%d %s [%s] %s", file, line, func,
	                            trc_level_to_str(level), fmt);
}

int store_fmt_info(uint16_t msg_id, const char *fmt)
{
	size_t i;
	int types[128];
	size_t n_types;
	uint16_t *type_info;
	bool swap_res;

	n_types = parse_printf_format(fmt, sizeof(types), types);
	type_info = calloc(n_types + 1, sizeof(uint16_t));
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
	queue_msg_t *q_msg;
	fmt_msg_t *fmt_msg;
	lf_element_t *lfe;
	int res;

	if (trace_ctx.type_info[msg_id] != NULL) {
		// format for this message was already processed
		return EALREADY;
	}
	res = lf_queue_get(trace_ctx.trace_queue, &lfe);
	if (res != 0) {
		// no place in the trace queue now
		return ENOMEM;
	}

	res = store_fmt_info(msg_id, fmt);
	if (!res) {
		lf_queue_put(trace_ctx.trace_queue, lfe);
		return res;
	}
	q_msg = lfe->data;
	q_msg->type = FMT_MSG_TYPE;
	fmt_msg = &q_msg->fmt_msg;
	build_fmt_msg(fmt_msg, msg_id, file, line, func, level, fmt);
	return 0;
}

void store_arg(void *p, size_t sz, trc_msg_t *trc_msg)
{

	if (TRACE_MSG_SIZE - sizeof(queue_msg_t) < sz) {
		return;
	} else {
		memcpy(trc_msg->buff + trc_msg->buf_len, p, sz);
		trc_msg->buf_len += sz;
	}
}

void store_args(uint16_t msg_id, va_list vl, trc_msg_t *trc_msg)
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

	for (i = 0 ; types[i] != PA_LAST ; i++) {
		switch (types[i]) {
		case PA_INT:
			val_int = va_arg(vl, int);
			store_arg((void *) &val_int, sizeof(val_int), trc_msg);
			break;
		case PA_INT | PA_FLAG_LONG:
			val_l_int = va_arg(vl, long int);
			store_arg((void *) &val_l_int, sizeof(val_l_int), trc_msg);
			break;
		case PA_INT | PA_FLAG_LONG_LONG:
			val_ll_int = va_arg(vl, long long int);
			store_arg((void *) &val_ll_int, sizeof(val_ll_int), trc_msg);
			break;
		case PA_INT | PA_FLAG_SHORT:
			val_int = va_arg(vl, int);
			val_s_int = (short int)val_int;
			store_arg((void *) &val_s_int, sizeof(val_s_int), trc_msg);
			break;
		case PA_CHAR:
			val_int = va_arg(vl, int);
			val_chr = (char)val_int;
			store_arg((void *) &val_chr, sizeof(val_chr), trc_msg);
			break;
		case PA_STRING:
			val_str = va_arg(vl, char *);
			if (!val_str) {
				val_str = (char *)"<NULL>";
			}
			store_arg((void *)val_str, strnlen(val_str, TRACE_MSG_SIZE + 1), trc_msg);
			break;
		case PA_POINTER:
			val_ptr = va_arg(vl, void *);
			store_arg(&val_ptr, sizeof(val_ptr), trc_msg);
			break;
		case PA_FLOAT:
			val_dbl = va_arg(vl, double);
			val_flt = (float) val_dbl;
			store_arg((void *) &val_flt, sizeof(val_flt), trc_msg);
			break;
		case PA_DOUBLE:
			val_dbl = va_arg(vl, double);
			store_arg((void *) &val_dbl, sizeof(val_dbl), trc_msg);
			break;
		case PA_DOUBLE | PA_FLAG_LONG_DOUBLE:
			val_l_dbl = va_arg(vl, long double);
			store_arg((void *) &val_l_dbl, sizeof(val_l_dbl), trc_msg);
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
	int res;
	va_list vl;
	lf_element_t *lfe;
	queue_msg_t *q_msg;
	trc_msg_t *trc_msg;

	if (trace_ctx.type_info[msg_id] != NULL) {
		return;
	}
	res = lf_queue_get(trace_ctx.trace_queue, &lfe);
	if (res != 0) {
		// no place in the trace queue now
		return;
	}
	q_msg = lfe->data;
	q_msg->type = TRC_MSG_TYPE;
	trc_msg = &q_msg->trc_msg;
	trc_msg->msg_id = msg_id;
	trc_msg->tid = 0; // TODO
	trc_msg->timestamp = 0; // TODO
	store_args(msg_id, vl, trc_msg);
	lf_queue_enqueue(trace_ctx.trace_queue, lfe);
	va_end(vl);
}


