#ifndef __PF_TRACE_H_INCLUDED__
#define __PF_TRACE_H_INCLUDED__

#include <stdint.h>
#include <stdbool.h>

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

#define PF_MAX_NAME 1024
typedef struct pf_trace_config {
    uint64_t max_trace_message_size;
    uint64_t trace_queue_size;
    pf_trc_level_t level;
    bool use_trace_daemon;
    char file_name_prefix[PF_MAX_NAME];
} pf_trace_config_t;

int pf_trace_init(pf_trace_config_t *trace_cfg);
int pf_trace_destroy(void);

void pf_trace_set_level(pf_trc_level_t level);

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

#define trc_dbg(FMT, ARGS...) TRACE(PF_TRC_DEBUG, FMT, ##ARGS)
#define trc_inf(FMT, ARGS...) TRACE(PF_TRC_INFO, FMT, ##ARGS)
#define trc_ntc(FMT, ARGS...) TRACE(PF_TRC_NOTICE, FMT, ##ARGS)
#define trc_wrn(FMT, ARGS...) TRACE(PF_TRC_WARNING, FMT, ##ARGS)
#define trc_err(FMT, ARGS...) TRACE(PF_TRC_ERROR, FMT, ##ARGS)
#define trc_ftl(FMT, ARGS...) TRACE(PF_TRC_FATAL, FMT, ##ARGS)

#ifdef __cplusplus
}
#endif

#endif
