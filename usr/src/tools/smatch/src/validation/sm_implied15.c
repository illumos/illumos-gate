#include "check_debug.h"

int some_func(void);

int a;
int frob(int *p)
{
	int ret = 0;

	*p = 4;
	if (a)
		goto out;

	*p = some_func();
	if (*p < 10 || *p > 100) {
		ret = -12;
		goto out;
	}

out:
	return ret;
}

void test(void)
{
	int var = 0;
	int ret;

	ret = frob(&var);
	__smatch_implied(var);
	if (ret)
		return;
	__smatch_implied(var);
}
/*
 * check-name: smatch implied #15
 * check-command: smatch -I.. sm_implied15.c
 *
 * check-output-start
sm_implied15.c:30 test() implied: var = 's32min-s32max'
sm_implied15.c:33 test() implied: var = '4,10-100'
 * check-output-end
 */
