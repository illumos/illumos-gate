#include "check_debug.h"

unsigned int x;
void test(void)
{
	__smatch_implied(x & 0x1);
	__smatch_implied(x & 0x2);
	__smatch_implied(x & ~(0xffU));
	__smatch_implied(x & ~(0xff));
}

/*
 * check-name: smatch bitwise #1
 * check-command: smatch -I.. sm_bitwise1.c
 *
 * check-output-start
sm_bitwise1.c:6 test() implied: x & 1 = '0-1'
sm_bitwise1.c:7 test() implied: x & 2 = '0,2'
sm_bitwise1.c:8 test() implied: x & ~(255) = '0,256-4294967040'
sm_bitwise1.c:9 test() implied: x & ~(255) = '0,256-4294967040'
 * check-output-end
 */
