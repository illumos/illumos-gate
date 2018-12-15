#include <stdio.h>
#include <string.h>
#include "check_debug.h"

int cmp_x(int x, int y)
{
	if (x < y)
		return -1;
	if (x == y)
		return 0;
	return 1;
}

int x, y;
int test(void)
{
	if (cmp_x(x, 4) < 0) {
		__smatch_implied(x);
	} else
		__smatch_implied(x);
}
/*
 * check-name: smatch compare #14
 * check-command: smatch -I.. sm_compare14.c
 *
 * check-output-start
sm_compare14.c:18 test() implied: x = 's32min-3'
sm_compare14.c:20 test() implied: x = '4-s32max'
 * check-output-end
 */
