#include <stdio.h>
#include <string.h>
#include "check_debug.h"

int return_x(int x)
{
	return x;
}

int a;
int cmp_x(int x, int y)
{
	if (a > return_x(5))
		return;
	__smatch_implied(a);
}


/*
 * check-name: smatch compare #16
 * check-command: smatch -I.. sm_compare16.c
 *
 * check-output-start
sm_compare16.c:15 cmp_x() implied: a = 's32min-5'
 * check-output-end
 */
