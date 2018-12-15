#include "check_debug.h"
int a, b, c;
int frob(void) {
	if (a && b != 1)
		return;

	__smatch_value("a");
	if (b == 0 && c) {
		__smatch_value("a");
	}
	__smatch_value("a");
}
/*
 * check-name: Smatch implied #7
 * check-command: smatch -I.. sm_implied7.c
 *
 * check-output-start
sm_implied7.c:7 frob() a = s32min-s32max
sm_implied7.c:9 frob() a = 0
sm_implied7.c:11 frob() a = s32min-s32max
 * check-output-end
 */
