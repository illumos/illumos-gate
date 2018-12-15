#include "check_debug.h"

int a, b, c, e, f, g;
static int options_write(void)
{
	if (b >= c)
		return;
	a = c;
	__smatch_compare(a, b);
	if (f >= e)
		return;
	g = f;
	__smatch_compare(g, e);
}

/*
 * check-name: smatch compare #7
 * check-command: smatch -I.. sm_compare7.c
 *
 * check-output-start
sm_compare7.c:9 options_write() a > b
sm_compare7.c:13 options_write() g < e
 * check-output-end
 */
