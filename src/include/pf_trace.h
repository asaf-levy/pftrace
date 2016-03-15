#ifndef __PF_TRACE_H_INCLUDED__
#define __PF_TRACE_H_INCLUDED__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum pf_trc_level {
    PF_TRC_DEBUG,
    PF_TRC_INFO,
    PF_TRC_NOTICE,
    PF_TRC_WARNING,
    PF_TRC_ERROR,
    PF_TRC_FATAL
} pf_trc_level_t;

typedef struct pf_trace_config {
    uint64_t trace_queue_size;
    pf_trc_level_t level;
} pf_trace_config_t;

int pf_trace_init(pf_trace_config_t *trace_cfg);
int pf_trace_destroy(void);

uint16_t gen_msg_id(void);
pf_trc_level_t get_trc_level(void);

int pf_trace_fmt(uint16_t msg_id, const char *file, int line,
                  const char *func, pf_trc_level_t level, const char *fmt);

void pf_trace(uint16_t msg_id, const char *fmt, ...)
__attribute__((format(printf, 2, 3)));

#define TRACE(TRC_LVL, FMT, ARGS...)    \
	do {                            \
		static uint16_t msg_id = 0;     \
		if (TRC_LVL < get_trc_level()) {        \
			break;  \
		}       \
		if (__builtin_expect(msg_id == 0, 0)) {  \
			msg_id = gen_msg_id();  \
		} \
		pf_trace_fmt(msg_id, __FILE__, __LINE__, __PRETTY_FUNCTION__, TRC_LVL, FMT); \
		pf_trace(msg_id, FMT, ##ARGS); \
	} while (0);

#ifdef __cplusplus
}
#endif

#endif
