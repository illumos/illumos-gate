#include "check_debug.h"

int a, b, c, d;
void func(void)
{
	a = b + 3;
	c = d - 3;

	if (a > 10)
		return;
	__smatch_implied(a);
	__smatch_implied(b);
	if (10 > c)
		return;
	__smatch_implied(c);
	__smatch_implied(d);
}

/*
 * check-name: Smatch compare #5
 * check-command: smatch -I.. sm_compare5.c
 *
 * check-output-start
sm_compare5.c:11 func() implied: a = 's32min-10'
sm_compare5.c:12 func() implied: b = 's32min-7'
sm_compare5.c:15 func() implied: c = '10-s32max'
sm_compare5.c:16 func() implied: d = '13-s32max'
 * check-output-end
 */
