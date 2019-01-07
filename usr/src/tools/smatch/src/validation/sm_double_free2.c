#include <stdlib.h>

struct ture {
	int a;
};

void func (void)
{
	void *x;

	x = malloc(sizeof(struct ture));
	x->a = 1;

	if (x->a)
		free(x);

	free(x);

	return 0;
}
/*
 * check-name: double free test #2
 * check-command: smatch sm_double_free2.c
 *
 * check-output-start
sm_double_free2.c:17 func() error: double free of 'x'
 * check-output-end
 */
