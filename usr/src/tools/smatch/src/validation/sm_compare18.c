#include "check_debug.h"

int a, b;
static int options_write(void)
{
	if (a == b)
		return;

	if (a < 10)
		return;
	if (b > 10)
		return;
	__smatch_compare(a, b);
}


/*
 * check-name: smatch compare #18
 * check-command: smatch -I.. sm_compare18.c
 *
 * check-output-start
sm_compare18.c:13 options_write() a > b
 * check-output-end
 */
