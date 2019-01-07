#include <stdio.h>
#include <string.h>
#include "check_debug.h"

int a;
int x;

int main(void)
{
	a = (unsigned short)x;
	__smatch_implied(a);

	return 0;
}


/*
 * check-name: smatch: casts #7
 * check-command: smatch -I.. sm_casts7.c
 *
 * check-output-start
sm_casts7.c:11 main() implied: a = '0-u16max'
 * check-output-end
 */
