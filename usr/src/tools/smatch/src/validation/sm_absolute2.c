#include "check_debug.h"

static int my_var;

int x;
int func(int *p)
{
	unsigned int a = -1;

	x = a;
	__smatch_absolute_min(a);
	__smatch_absolute_max(a);
	__smatch_absolute_min(x);
	__smatch_absolute_max(x);
	__smatch_implied(a);
	__smatch_implied(x);
	__smatch_sval_info(a);
	__smatch_sval_info(x);
}
/*
 * check-name: smatch: absolute #2
 * check-command: smatch -I.. sm_absolute2.c
 *
 * check-output-start
sm_absolute2.c:11 func() absolute min: a = u32max
sm_absolute2.c:12 func() absolute max: a = u32max
sm_absolute2.c:13 func() absolute min: x = (-1)
sm_absolute2.c:14 func() absolute max: x = (-1)
sm_absolute2.c:15 func() implied: a = 'u32max'
sm_absolute2.c:16 func() implied: x = '(-1)'
sm_absolute2.c:17 func() implied: a u32 ->value = ffffffff
sm_absolute2.c:18 func() implied: x s32 ->value = ffffffffffffffff
 * check-output-end
 */
