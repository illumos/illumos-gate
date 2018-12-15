#include "check_debug.h"

int *something();
void frob();

int red;
int blue;
int x;
int func(void)
{

	red = something();
	if (x < 4)
		red = something();
	else if (x > 5)
		red = 0;

	blue = red;
	red = 0;
	if (!blue)
		return;
	__smatch_value("red");
	__smatch_value("blue");
	return 0;
}
/*
 * check-name: smatch equivalent variables #3
 * check-command: smatch -I.. sm_equiv3.c
 *
 * check-output-start
sm_equiv3.c:22 func() red = 0
sm_equiv3.c:23 func() blue = s32min-(-1),1-s32max
 * check-output-end
 */
