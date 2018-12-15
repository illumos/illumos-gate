#include "check_debug.h"

int clear_user();

int func(int *p)
{
	int ret;

	ret = clear_user();
	if (ret)
		return ret;
	return 0;
}
/*
 * check-name: smatch return -EFAULT
 * check-command: smatch -p=kernel -I.. sm_efault.c
 *
 * check-output-start
sm_efault.c:11 func() warn: maybe return -EFAULT instead of the bytes remaining?
 * check-output-end
 */
