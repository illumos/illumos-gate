#include "check_debug.h"


void *p;
int min1, min2;
void func(unsigned long x)
{
	min1 = 18;
	min2 = (((unsigned char *)p)[12] + 8);
	if (min2 < min1)
		__smatch_implied(min2);
}

/*
 * check-name: Smatch real absolute #1
 * check-command: smatch -I.. sm_real_absolute1.c
 *
 * check-output-start
sm_real_absolute1.c:11 func() implied: min2 = '8-17'
 * check-output-end
 */
