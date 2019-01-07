#include "check_debug.h"

unsigned int a;
int b;
int func(void)
{
	b = a;
	__smatch_implied(a);
	__smatch_implied(b);
}

/*
 * check-name: smatch: casts #3
 * check-command: smatch -I.. sm_casts3.c
 *
 * check-output-start
sm_casts3.c:8 func() implied: a = ''
sm_casts3.c:9 func() implied: b = 's32min-s32max'
 * check-output-end
 */
