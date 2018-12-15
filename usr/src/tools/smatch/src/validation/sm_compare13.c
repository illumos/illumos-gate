#include <stdio.h>
#include <string.h>
#include "check_debug.h"

int cmp_x(int x, int y)
{
	if (x < y) {
		__smatch_compare(x, y);
		return -1;
	}
	if (x == y) {
		__smatch_compare(x, y);
		return 0;
	}
	__smatch_compare(x, y);
	return 1;
}

/*
 * check-name: smatch compare #13
 * check-command: smatch -I.. sm_compare13.c
 *
 * check-output-start
sm_compare13.c:8 cmp_x() x < y
sm_compare13.c:12 cmp_x() x == y
sm_compare13.c:15 cmp_x() x > y
 * check-output-end
 */
