#include "check_debug.h"

static int test(int x)
{
	if (x == 12)
		return 10;
	return 0;
}

int a, b;
static void func(void)
{
	if (a == 12)
		b = 1;
	else
		b = 4;
	if (test(a) == 10) {
		__smatch_implied(a);
		__smatch_implied(b);
	} else {
		__smatch_implied(a);
		__smatch_implied(b);
	}

	if (a == 12)
		b = 10;
	else
		b = 40;

	if (test(a))
		__smatch_implied(b);
	else
		__smatch_implied(b);
}
/*
 * check-name: smatch implied #14
 * check-command: smatch -I.. sm_implied14.c
 *
 * check-output-start
sm_implied14.c:18 func() implied: a = '12'
sm_implied14.c:19 func() implied: b = '1'
sm_implied14.c:21 func() implied: a = 's32min-11,13-s32max'
sm_implied14.c:22 func() implied: b = '4'
sm_implied14.c:31 func() implied: b = '10'
sm_implied14.c:33 func() implied: b = '40'
 * check-output-end
 */
