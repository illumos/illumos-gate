#include "check_debug.h"
int some_func();
int a, b, c, d, e;
int frob(void) {
	if (a)
		__smatch_value("a");
	else
		__smatch_value("a");
	__smatch_value("a");
	if (a) {
		b = 0;
		__smatch_value("b");
	}
	__smatch_value("b");
	c = 0;
	c = some_func();
	__smatch_value("c");
	if (d < -3 || d > 99)
		return;
	__smatch_value("d");
	if (d) {
		if (!e)
			return;
	}
	__smatch_value("d");
	__smatch_value("e");
}
/*
 * check-name: Smatch range test #2
 * check-command: smatch -I.. sm_range2.c
 *
 * check-output-start
sm_range2.c:6 frob() a = s32min-(-1),1-s32max
sm_range2.c:8 frob() a = 0
sm_range2.c:9 frob() a = s32min-s32max
sm_range2.c:12 frob() b = 0
sm_range2.c:14 frob() b = s32min-s32max
sm_range2.c:17 frob() c = s32min-s32max
sm_range2.c:20 frob() d = (-3)-99
sm_range2.c:25 frob() d = (-3)-99
sm_range2.c:26 frob() e = s32min-s32max
 * check-output-end
 */
