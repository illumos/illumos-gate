#include <stdio.h>
#include "check_debug.h"

int *aaa, *bbb;

int main(void)
{
	if (*aaa < 0 || *aaa > 34)
		return -1;
	bbb = aaa;
	__smatch_implied(*bbb);

	return 0;
}

/*
 * check-name: smatch pointer assign
 * check-command: smatch -I.. sm_pointer_assign.c
 *
 * check-output-start
sm_pointer_assign.c:11 main() implied: *bbb = '0-34'
 * check-output-end
 */
