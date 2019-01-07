#include <stdlib.h>

void func (void)
{
	void *x;

	x = malloc(42);

	free(x);
	free(x);

	return 0;
}
/*
 * check-name: double free test #1
 * check-command: smatch sm_double_free1.c
 *
 * check-output-start
sm_double_free1.c:10 func() error: double free of 'x'
 * check-output-end
 */
