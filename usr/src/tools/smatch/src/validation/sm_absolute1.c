#include "check_debug.h"

char x;
int y;
int func(void)
{
	y = x;
	__smatch_absolute_min(y);
	__smatch_absolute_max(y);
}

/*
 * check-name: smatch: absolute #1
 * check-command: smatch -I.. sm_absolute1.c
 *
 * check-output-start
sm_absolute1.c:8 func() absolute min: y = (-128)
sm_absolute1.c:9 func() absolute max: y = 127
 * check-output-end
 */
