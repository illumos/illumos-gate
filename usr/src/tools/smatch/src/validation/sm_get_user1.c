#include "check_debug.h"

int frob(void);
#define get_user(x, y) ({ int __val_gu = frob(); x = __val_gu; 0; })

void func(void)
{
	int *user_ptr;
	int foo, bar;
	unsigned int x;

	get_user(foo, user_ptr);
	bar = foo + 1;

	get_user(bar, user_ptr);
	if (bar > foo)
		bar = foo;
	foo = bar * 8;

	get_user(x, user_ptr);
	if (x > foo)
		x = foo;
	foo = x * 8;

	get_user(x, user_ptr);
	foo = x * 8;
}
/*
 * check-name: smatch get_user() #1
 * check-command: smatch -p=kernel -I.. sm_get_user1.c
 *
 * check-output-start
sm_get_user1.c:13 func() warn: check for integer over/underflow 'foo'
sm_get_user1.c:18 func() warn: check for integer underflow 'bar'
sm_get_user1.c:26 func() warn: check for integer overflow 'x'
 * check-output-end
 */
