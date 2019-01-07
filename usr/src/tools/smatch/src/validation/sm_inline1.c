#include <stdio.h>
#include <string.h>
#include "check_debug.h"

int frob(int *x)
{
	*x = *x * 3;
	return 0;
}

int *x;
int y;
int main(void)
{
	*x = 1;
	frob(x);
	__smatch_implied(*x);
	frob(x);
	__smatch_implied(*x);

	y = 2;
	frob(&y);
	__smatch_implied(y);
	frob(&y);
	__smatch_implied(y);

	return 0;
}


/*
 * check-name: smatch: inline #1
 * check-command: smatch -I.. sm_inline1.c
 *
 * check-output-start
sm_inline1.c:17 main() implied: *x = '3'
sm_inline1.c:19 main() implied: *x = '9'
sm_inline1.c:23 main() implied: y = '6'
sm_inline1.c:25 main() implied: y = '18'
 * check-output-end
 */
