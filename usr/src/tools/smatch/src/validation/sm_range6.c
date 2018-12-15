#include "check_debug.h"

void func(void)
{
	long a = __smatch_rl("1-10+");
	long b = __smatch_rl("0,+");
	long c = __smatch_rl("10,23,45-+");

	__smatch_implied(a);
	__smatch_implied(b);
	__smatch_implied(c);
}

/*
 * check-name: smatch range #6
 * check-command: smatch -I.. sm_range6.c
 *
 * check-output-start
sm_range6.c:9 func() implied: a = '1-s64max'
sm_range6.c:10 func() implied: b = '0-s64max'
sm_range6.c:11 func() implied: c = '10,23,45-s64max'
 * check-output-end
 */
