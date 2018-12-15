#include "check_debug.h"

void frob(void){}

void func(int y)
{
	int test2;

	if (({int test2 = !!(y < 0 || y >= 10); frob(); frob(); frob(); test2;}))
		__smatch_value("y");
	else
		__smatch_value("y");

	test2 = (y < 3 || y >= 5);
	if (test2)
		__smatch_value("y");
	else
		__smatch_value("y");

	if (({int test3 = y < -98; frob(); frob(); frob(); test3;}))
		__smatch_value("y");
}
/*
 * check-name: smatch implied #9
 * check-command: smatch -I.. sm_implied9.c
 *
 * check-output-start
sm_implied9.c:10 func() y = s32min-(-1),10-s32max
sm_implied9.c:12 func() y = 0-9
sm_implied9.c:16 func() y = s32min-2,5-s32max
sm_implied9.c:18 func() y = 3-4
sm_implied9.c:21 func() y = s32min-(-99)
 * check-output-end
 */
