#include "check_debug.h"

int *something();

int red;
int blue;
int x;
int func(void)
{
	red = 0;

	if (x) {
		red = 5;
	}
	blue = red;

	if (x) {
		__smatch_value("red");
		__smatch_value("blue");
	}
	__smatch_value("red");
	__smatch_value("blue");
	return 0;
}
/*
 * check-name: smatch equivalent variables #2 (implications)
 * check-command: smatch -I.. sm_equiv2.c
 *
 * check-output-start
sm_equiv2.c:18 func() red = 5
sm_equiv2.c:19 func() blue = 5
sm_equiv2.c:21 func() red = 0,5
sm_equiv2.c:22 func() blue = 0,5
 * check-output-end
 */
