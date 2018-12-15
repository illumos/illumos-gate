#include "check_debug.h"

int something();

void func(void)
{
	int x = 3;
	int y = 42;
	int z = 7;

	x--;
	y -= 100;
	__smatch_value("y");
	while (something()) {
		y++;
		__smatch_value("y");
	}
	z += something();
	__smatch_value("z");
	__smatch_value("x");
label_I1:
	x--;
	__smatch_value("x");
	goto label_I1;
}
/*
 * check-name: smatch math test #1
 * check-command: smatch -I.. sm_math1.c
 *
 * check-output-start
sm_math1.c:13 func() y = (-58)
sm_math1.c:16 func() y = (-57)-s32max
sm_math1.c:19 func() z = s32min-s32max
sm_math1.c:20 func() x = 2
sm_math1.c:23 func() x = s32min-1
 * check-output-end
 */
