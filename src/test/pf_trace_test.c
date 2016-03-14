#include <assert.h>
#include "pf_trace.h"

int main(void) {
	int res;
	pf_trace_config_t trace_cfg = {
		.trace_queue_size = 10000,
	};

	res = pf_trace_init(&trace_cfg);
	assert(res == 0);
	pf_trace_destroy();
	return 0;
}