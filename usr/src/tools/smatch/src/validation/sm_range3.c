#include "check_debug.h"

int x;
void func(void)
{

	if (x < 1)
		__smatch_value("x");
	else
		__smatch_value("x");

	if (12 < x)
		__smatch_value("x");
	else
		__smatch_value("x");

	if (x <= 23)
		__smatch_value("x");
	else
		__smatch_value("x");

	if (34 <= x)
		__smatch_value("x");
	else
		__smatch_value("x");

	if (x >= 45)
		__smatch_value("x");
	else
		__smatch_value("x");

	if (56 >= x)
		__smatch_value("x");
	else
		__smatch_value("x");

	if (x > 67)
		__smatch_value("x");
	else
		__smatch_value("x");

	if (78 > x)
		__smatch_value("x");
	else
		__smatch_value("x");

	if (89 == x)
		__smatch_value("x");
	else
		__smatch_value("x");

	if (100 != x)
		__smatch_value("x");
	else
		__smatch_value("x");

	return;
}
/*
 * check-name: smatch range comparison
 * check-command: smatch -I.. sm_range3.c
 *
 * check-output-start
sm_range3.c:8 func() x = s32min-0
sm_range3.c:10 func() x = 1-s32max
sm_range3.c:13 func() x = 13-s32max
sm_range3.c:15 func() x = s32min-12
sm_range3.c:18 func() x = s32min-23
sm_range3.c:20 func() x = 24-s32max
sm_range3.c:23 func() x = 34-s32max
sm_range3.c:25 func() x = s32min-33
sm_range3.c:28 func() x = 45-s32max
sm_range3.c:30 func() x = s32min-44
sm_range3.c:33 func() x = s32min-56
sm_range3.c:35 func() x = 57-s32max
sm_range3.c:38 func() x = 68-s32max
sm_range3.c:40 func() x = s32min-67
sm_range3.c:43 func() x = s32min-77
sm_range3.c:45 func() x = 78-s32max
sm_range3.c:48 func() x = 89
sm_range3.c:50 func() x = s32min-88,90-s32max
sm_range3.c:53 func() x = s32min-99,101-s32max
sm_range3.c:55 func() x = 100
 * check-output-end
 */
