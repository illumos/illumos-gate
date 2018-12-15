#include <stdlib.h>

void func (void)
{
	void *ptr;

	ptr = malloc(42);
	ptr = (void *) 0;

	return;
}
/*
 * check-name: leak test #2
 * check-command: smatch sm_memleak2.c
 *
 * check-output-start
sm_memleak2.c:8 func() warn: overwrite may leak 'ptr'
 * check-output-end
 */
