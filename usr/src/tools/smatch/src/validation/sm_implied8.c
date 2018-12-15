#include "check_debug.h"

void frob();

int test, test2;

int x;
void func (void)
{
	if (({int test = !!x; frob(); frob(); frob(); test;}))
		__smatch_value("x");
	else
		__smatch_value("x");
	if (test)
		__smatch_value("x");
	if (({test2 = !(x == 3); frob(); frob(); frob(); test2;}))
		__smatch_value("x");
	else
		__smatch_value("x");
	test = !!(x == 10);
	if (!test)
		__smatch_value("x");
	__smatch_value("x");
}
/*
 * check-name: smatch implied #8
 * check-command: smatch -I.. sm_implied8.c
 *
 * check-output-start
sm_implied8.c:11 func() x = s32min-(-1),1-s32max
sm_implied8.c:13 func() x = 0
sm_implied8.c:15 func() x = s32min-(-1),1-s32max
sm_implied8.c:17 func() x = s32min-2,4-s32max
sm_implied8.c:19 func() x = 3
sm_implied8.c:22 func() x = s32min-9,11-s32max
sm_implied8.c:23 func() x = s32min-s32max
 * check-output-end
 */
