#include "check_debug.h"

int a, b, c;
static int options_write(void)
{
	if (c <= b)
		return;
	if (a >= b)
		return;
	__smatch_compare(a, c);
}

/*
 * check-name: smatch compare #10
 * check-command: smatch -I.. sm_compare10.c
 *
 * check-output-start
sm_compare10.c:10 options_write() a < c
 * check-output-end
 */
