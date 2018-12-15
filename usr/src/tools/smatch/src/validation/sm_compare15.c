#include <stdio.h>
#include <string.h>
#include "check_debug.h"

int __fswab(int x)
{
	return x;
}

int a;
int cmp_x(int x, int y)
{
	if (__fswab(a) > 5)
		return;
	__smatch_implied(a);
}


/*
 * check-name: smatch compare #15
 * check-command: smatch -I.. sm_compare15.c
 *
 * check-output-start
sm_compare15.c:15 cmp_x() implied: a = 's32min-5'
 * check-output-end
 */
