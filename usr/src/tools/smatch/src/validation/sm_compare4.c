#include "check_debug.h"

int some_func();

int a, b, c, d;

void func (void)
{
	d = some_func();

	if (a + 3 > 100)
		return;
	__smatch_implied(a);
	if (3 + b > 100)
		return;
	__smatch_implied(b);
	if (c - 3 > 100)
		return;
	__smatch_implied(c);
	if (3 - d > 100)
		return;
	__smatch_implied(d);
}

/*
 * check-name: Smatch compare #4
 * check-command: smatch -I.. sm_compare4.c
 *
 * check-output-start
sm_compare4.c:13 func() implied: a = 's32min-97'
sm_compare4.c:16 func() implied: b = 's32min-97'
sm_compare4.c:19 func() implied: c = 's32min-103'
sm_compare4.c:22 func() implied: d = 's32min-s32max'
 * check-output-end
 */
