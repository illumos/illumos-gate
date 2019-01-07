#include "check_debug.h"

char *some_func(void);

int x,y;
int i;
void func(void)
{
	char *p;
	char *p2;

	if (x > 0)
		p = some_func();
	for (i = 0; i < x; i++)
		*p = 'x';
	*p = 'x';
	if (y > 0)
		p2 = some_func();
	i = 0;
	if (i < y)
		*p2 = 'x';
}
/*
 * check-name: smatch loops #4
 * check-command: smatch -I.. sm_loops4.c
 *
 * check-output-start
sm_loops4.c:16 func() error: potentially dereferencing uninitialized 'p'.
 * check-output-end
 */
