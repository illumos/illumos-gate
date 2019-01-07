#include "check_debug.h"

unsigned int x;
int y;
void test(void)
{
	if (x & 0x1)
		__smatch_implied(x);
	if (y & 0x4)
		__smatch_implied(y);

}

/*
 * check-name: smatch bitwise #2
 * check-command: smatch -I.. sm_bitwise2.c
 *
 * check-output-start
sm_bitwise2.c:8 test() implied: x = '1-u32max'
sm_bitwise2.c:10 test() implied: y = 's32min-(-1),4-s32max'
 * check-output-end
 */
