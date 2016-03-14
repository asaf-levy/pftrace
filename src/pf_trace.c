#include "pf_trace.h"
#include "lf-queue/lf_queue.h"

typedef struct pf_trace {
    lf_queue_handle_t trace_queue;
} pf_trace_t;

static pf_trace_t trace_ctx;

#define TRACE_MSG_SIZE 512

int pf_trace_init(pf_trace_config_t *trace_cfg)
{
	int err = lf_queue_init(&trace_ctx.trace_queue,
	                        trace_cfg->trace_queue_size,
	                        TRACE_MSG_SIZE);
	if (err) {
		return err;
	}
	return 0;
}

int pf_trace_destroy(void)
{
	lf_queue_destroy(trace_ctx.trace_queue);
	return 0;
}

