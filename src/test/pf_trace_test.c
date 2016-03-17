#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <bits/time.h>
#include <time.h>
#include "pf_trace.h"

void trc_func()
{
	int i;
	struct timespec start;
	struct timespec end;

	clock_gettime(CLOCK_REALTIME, &start);
	for (i = 0; i < 1000000; i++) {
		TRACE(PF_TRC_DEBUG, "i=%d", i);
	}
	clock_gettime(CLOCK_REALTIME, &end);

	printf("msec=%lu\n", (((end.tv_sec - start.tv_sec) * 1000000000) + end.tv_nsec - start.tv_nsec) / 1000000);

}

int main(void)
{
	int res;
	pf_trace_config_t trace_cfg = {
		.max_trace_message_size = 64,
		.trace_queue_size = 500000,
		.level = PF_TRC_DEBUG,
	};

	res = pf_trace_init(&trace_cfg);
	assert(res == 0);
	TRACE(PF_TRC_DEBUG, "hello");
	TRACE(PF_TRC_DEBUG, "hello %d %lu %0.2f", 1, 8LU, 1.513123);
	TRACE(PF_TRC_DEBUG, "hello %s", "bla");
	trc_func();

	sleep(1);
	pf_trace_destroy();
	return 0;
}