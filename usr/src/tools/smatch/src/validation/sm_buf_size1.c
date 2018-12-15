#include "check_debug.h"

void func(void)
{
	int a[4];
	char b[4];
	char *c = (char *)a;
	int *d = (int *)b;

	__smatch_buf_size(a);
	__smatch_buf_size(b);
	__smatch_buf_size(c);
	__smatch_buf_size(d);
}

/*
 * check-name: smatch buf size #1
 * check-command: smatch -I.. sm_buf_size1.c
 *
 * check-output-start
sm_buf_size1.c:10 func() buf size: 'a' 4 elements, 16 bytes
sm_buf_size1.c:11 func() buf size: 'b' 4 elements, 4 bytes
sm_buf_size1.c:12 func() buf size: 'c' 16 elements, 16 bytes
sm_buf_size1.c:13 func() buf size: 'd' 1 elements, 4 bytes
 * check-output-end
 */
