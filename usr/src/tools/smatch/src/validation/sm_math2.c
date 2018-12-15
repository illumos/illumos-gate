#include "check_debug.h"

unsigned char buf[2];

void test(void)
{
	int a = buf[1];
	int b = buf[0] << 8;
	int c = (buf[0] << 8) | buf[1];

	__smatch_implied(a);
	__smatch_implied(b);
	__smatch_implied(c);
}

/*
 * check-name: smatch math #2
 * check-command: smatch -I.. sm_math2.c
 *
 * check-output-start
sm_math2.c:11 test() implied: a = '0-255'
sm_math2.c:12 test() implied: b = '0,256-65280'
sm_math2.c:13 test() implied: c = '0-u16max'
 * check-output-end
 */
