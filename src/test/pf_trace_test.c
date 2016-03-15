#include <assert.h>
#include "pf_trace.h"

int main(void) {
	int res;
	pf_trace_config_t trace_cfg = {
		.trace_queue_size = 10000,
		.level = PF_TRC_DEBUG,
	};

	res = pf_trace_init(&trace_cfg);
	assert(res == 0);
	TRACE(PF_TRC_DEBUG, "hello");
	TRACE(PF_TRC_DEBUG, "hello %d", 1);
	TRACE(PF_TRC_DEBUG, "hello %s", "bla");

	pf_trace_destroy();
	return 0;
}