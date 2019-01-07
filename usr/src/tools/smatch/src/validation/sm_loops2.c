#include "check_debug.h"

int checker(void);

int x;
int y;
void func(void)
{
	while (x--)
		__smatch_value("x");
	__smatch_value("x");
	for (x = 0; x < y; x++) {
		if (checker())
			break;
	}
	__smatch_value("x");
	while (x--)
		__smatch_value("x");
	__smatch_value("x");
	x = 10;
	while (x--)
		__smatch_value("x");
	__smatch_value("x");
	x = 10;
	while (--x)
		__smatch_value("x");
	__smatch_value("x");
}
/*
 * check-name: smatch loops #1
 * check-command: smatch -I.. sm_loops2.c
 *
 * check-output-start
sm_loops2.c:10 func() x = s32min-s32max
sm_loops2.c:11 func() x = s32min-s32max
sm_loops2.c:16 func() x = 0-s32max
sm_loops2.c:18 func() x = 0-s32max
sm_loops2.c:19 func() x = (-1)
sm_loops2.c:22 func() x = 0-9
sm_loops2.c:23 func() x = (-1)
sm_loops2.c:26 func() x = 1-9
sm_loops2.c:27 func() x = 0
 * check-output-end
 */
