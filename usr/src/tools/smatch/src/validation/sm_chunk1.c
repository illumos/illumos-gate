#include "check_debug.h"

static void perf_calculate_period(unsigned long nsec, unsigned long count)
{
	if (nsec + count > 64)
		return;

	__smatch_implied(nsec + count);
	nsec = 100;
	__smatch_implied(nsec + count);
}


/*
 * check-name: smatch chunk #1
 * check-command: smatch -I.. sm_chunk1.c
 *
 * check-output-start
sm_chunk1.c:8 perf_calculate_period() implied: nsec + count = '0-64'
sm_chunk1.c:10 perf_calculate_period() implied: nsec + count = ''
 * check-output-end
 */
