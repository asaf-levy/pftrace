#ifndef __PF_TRACE_H_INCLUDED__
#define __PF_TRACE_H_INCLUDED__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pf_trace_config {
    uint64_t trace_queue_size;

} pf_trace_config_t;

int pf_trace_init(pf_trace_config_t *trace_cfg);
int pf_trace_destroy(void);

#ifdef __cplusplus
}
#endif

#endif
