#include "check_debug.h"

void *malloc(int);

void func(void)
{
	char *a;

	a = malloc(sizeof(int) * 4);
	__smatch_buf_size(a);
	__smatch_buf_size((int *)a);
}

/*
 * check-name: smatch buf size #3
 * check-command: smatch -I.. sm_buf_size3.c
 *
 * check-output-start
sm_buf_size3.c:10 func() buf size: 'a' 16 elements, 16 bytes
sm_buf_size3.c:11 func() buf size: 'a' 4 elements, 16 bytes
 * check-output-end
 */
