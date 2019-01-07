#include "check_debug.h"

void *malloc(int);

void func(void)
{
	int *a;
	short *b;
	long long *c;

	a = malloc(sizeof(int) * 4);
	b = a;
	c = b;
	__smatch_buf_size(a);
	__smatch_buf_size(b);
	__smatch_buf_size(c);
}

/*
 * check-name: smatch buf size #2
 * check-command: smatch -I.. sm_buf_size2.c
 *
 * check-output-start
sm_buf_size2.c:14 func() buf size: 'a' 4 elements, 16 bytes
sm_buf_size2.c:15 func() buf size: 'b' 8 elements, 16 bytes
sm_buf_size2.c:16 func() buf size: 'c' 2 elements, 16 bytes
 * check-output-end
 */
