#include <stdio.h>
#include <string.h>
#include "check_debug.h"

int frob(int *x)
{
	*x = *x * 3;
	return 0;
}

int *x;
int main(void)
{
	frob(x);
	if (x)
		return 1;
	return 0;
}


/*
 * check-name: smatch: inline #2
 * check-command: smatch -I.. sm_inline2.c
 *
 * check-output-start
sm_inline2.c:15 main() warn: variable dereferenced before check 'x' (see line 14)
 * check-output-end
 */
