#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <bits/time.h>
#include <time.h>
#include <stdbool.h>
#include "pf_trace.h"

static void trc_func()
{
	int i;
	struct timespec start;
	struct timespec end;

	clock_gettime(CLOCK_REALTIME, &start);
	for (i = 0; i < 10; i++) {
//	for (i = 0; i < 1000000; i++) {
		trcntc("i=%d", i);
	}
	clock_gettime(CLOCK_REALTIME, &end);

	printf("msec=%lu\n", (((end.tv_sec - start.tv_sec) * 1000000000) + end.tv_nsec - start.tv_nsec) / 1000000);
}

#define TRACE_EXPECTED(FMT, ARGS...) \
	do { \
		char expected[1024]; \
		snprintf(expected, sizeof(expected), FMT, ##ARGS); \
		trcdbg("expected [%s] actual ["FMT"]", expected, ##ARGS); \
	} while (0);

static void expected_test()
{
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
}

int main(void)
{
	int res;
	pf_trace_config_t trace_cfg = {
		.max_trace_message_size = 128,
		.trace_queue_size = 1000000,
		.level = PF_TRC_DEBUG,
		.use_trace_daemon = false,
		.file_name_prefix = "./pf_trace_test",
	};

	res = pf_trace_init(&trace_cfg);
	assert(res == 0);

	expected_test();
	sleep(1);
	trc_func();

	pf_trace_destroy();
	return 0;
}