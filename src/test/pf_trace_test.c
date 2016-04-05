#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <bits/time.h>
#include <time.h>
#include "pf_trace.h"

static void batch_test()
{
	int i;
	struct timespec start;
	struct timespec end;

	pf_trace_config_t trace_cfg = PF_TRC_DEFAULT_INIT;
	sprintf(trace_cfg.file_name_prefix, "batch_test");
	trace_cfg.max_trace_message_size = 64;
	trace_cfg.trace_queue_size = 1000000;
	int res = pf_trace_init(&trace_cfg);
	assert(res == 0);

	clock_gettime(CLOCK_REALTIME, &start);
	for (i = 0; i < 1000000; i++) {
		trcntc("i=%d", i);
	}
	clock_gettime(CLOCK_REALTIME, &end);

	printf("msec=%lu\n", (((end.tv_sec - start.tv_sec) * 1000000000) + end.tv_nsec - start.tv_nsec) / 1000000);

	pf_trace_destroy();
}

#define TRACE_EXPECTED(FMT, ARGS...) \
	do { \
		char expected[1024]; \
		snprintf(expected, sizeof(expected), FMT, ##ARGS); \
		trcdbg("expected [%s] actual ["FMT"]", expected, ##ARGS); \
	} while (0);

static void expected_test()
{
	pf_trace_config_t trace_cfg = PF_TRC_DEFAULT_INIT;
	sprintf(trace_cfg.file_name_prefix, "expected_test");
	int res = pf_trace_init(&trace_cfg);
	assert(res == 0);

	int i = 8;
	char *str = "str";

	TRACE_EXPECTED("hello");
	TRACE_EXPECTED("hello %d %lu %0.2f", 1, 8LU, 1.513123);
	TRACE_EXPECTED("hello %c %s %c", '1', "b", '2');
	TRACE_EXPECTED("hello %d %s %lu", 1, "baba", 123412348LU);
	TRACE_EXPECTED("hello %c %s %c %d %s %llu %x", '1', "b", '2', 87, "wowow", 978687658LLU, -87);
	TRACE_EXPECTED("hello %d \"%%%s1232131 %%%lu!@#$%%", 1, "baba", 123412348LU);
	TRACE_EXPECTED("hello %d %p %d %s", i, &i, i * 2, "iii");
	TRACE_EXPECTED("hello %d %s %s %s %p %lu", 1, str, str, str, str, 123412348LU);

	pf_trace_destroy();
}

static void basic_test()
{
	pf_trace_config_t trace_cfg = PF_TRC_DEFAULT_INIT;
	int res = pf_trace_init(&trace_cfg);
	assert(res == 0);

	trcntc("hello world");

	pf_trace_destroy();
}

int main(void)
{
	basic_test();
	expected_test();
	batch_test();
	return 0;
}
