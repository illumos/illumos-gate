#include "check_debug.h"

int a, b, c;

static int frob(void)
{
	if (a > 5)
		return;
	if (b > 5)
		return;
	if (c != 5)
		return;

	if (a == 10)
		__smatch_value("a");
	if (b != 10)
		__smatch_value("b");
	if (c != 5)
		__smatch_value("c");
	if (5 != c)
		__smatch_value("c");

	__smatch_value("a");
	__smatch_value("b");
	__smatch_value("c");
}

/*
 * check-name: Smatch Comparison
 * check-command: smatch -I.. sm_compare.c
 *
 * check-output-start
sm_compare.c:15 frob() a = empty
sm_compare.c:17 frob() b = s32min-5
sm_compare.c:19 frob() c = empty
sm_compare.c:21 frob() c = empty
sm_compare.c:23 frob() a = s32min-5
sm_compare.c:24 frob() b = s32min-5
sm_compare.c:25 frob() c = 5
 * check-output-end
 */
