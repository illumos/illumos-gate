#include "check_debug.h"

int a, b;

int frob(int *data)
{
	if (a)
		return 0;
	if (b)
		return -1;
	*data = 42;
	return 1;
}

void test(void)
{
	int x = -1;
	int ret;

	ret = frob(&x);
	if (ret < 0)
		return;
	if (ret == 0)
		return;
	__smatch_implied(x);
}

/*
 * check-name: smatch implied #18
 * check-command: smatch -I.. sm_implied18.c
 *
 * check-output-start
sm_implied18.c:25 test() implied: x = '42'
 * check-output-end
 */
