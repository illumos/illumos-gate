#include "check_debug.h"

int a;

int frob(int size)
{
	int *p = &a;

	*p = 42;
	__smatch_implied(a);

	return 0;
}

/*
 * check-name: smatch: pointer indirection #1
 * check-command: smatch -p=kernel -I.. sm_indirection1.c
 *
 * check-output-start
sm_indirection1.c:10 frob() implied: a = '42'
 * check-output-end
 */
