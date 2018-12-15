#include "check_debug.h"

int test(void)
{
	int a[] = { [1] = 2 };
	int b[] = { 1, 2, 3 };
	int c[] = { 0, [0] = 1, 2, 3};
	int d[] = { 0, [3] = 4, 5};

	__smatch_buf_size(a);
	__smatch_buf_size(b);
	__smatch_buf_size(c);
	__smatch_buf_size(d);
}

/*
 * check-name: smatch buf size #7
 * check-command: smatch -I.. sm_buf_size7.c
 *
 * check-output-start
sm_buf_size7.c:10 test() buf size: 'a' 2 elements, 8 bytes
sm_buf_size7.c:11 test() buf size: 'b' 3 elements, 12 bytes
sm_buf_size7.c:12 test() buf size: 'c' 3 elements, 12 bytes
sm_buf_size7.c:13 test() buf size: 'd' 5 elements, 20 bytes
 * check-output-end
 */
