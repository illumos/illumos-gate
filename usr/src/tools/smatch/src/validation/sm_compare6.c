#include "check_debug.h"

int returns_less(int x)
{
	int y;

	if (x > 10)
		y = 10;
	else
		y = x;

	__smatch_compare(x, y);
	return y;
}

/*
 * check-name: smatch compare #6
 * check-command: smatch -I.. sm_compare6.c
 *
 * check-output-start
sm_compare6.c:12 returns_less() x >= y
 * check-output-end
 */
