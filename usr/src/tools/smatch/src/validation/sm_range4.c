#include "check_debug.h"

int a, b, c;

static int frob(void)
{
	if (a > 5) {
		__smatch_value("a");
		return;
	}
	if (b++ > 5) {
		__smatch_value("b");
		return;
	}
	if (++c > 5) {
		__smatch_value("c");
		return;
	}
	__smatch_value("a");
	__smatch_value("b");
	__smatch_value("c");
}


/*
 * check-name: Smatch Range #4
 * check-command: smatch -I.. sm_range4.c
 *
 * check-output-start
sm_range4.c:8 frob() a = 6-s32max
sm_range4.c:12 frob() b = 7-s32max
sm_range4.c:16 frob() c = 6-s32max
sm_range4.c:19 frob() a = s32min-5
sm_range4.c:20 frob() b = s32min-6
sm_range4.c:21 frob() c = s32min-5
 * check-output-end
 */
