#include "check_debug.h"

void memset(void *p, char pat, int size);

struct foo {
	int a, b;
};

void my_func(struct foo *p)
{
	memset(p, 0, sizeof(*p));
	p->a = 1;
}

struct foo *my_pointer;

void test(void)
{
	struct foo foo;

	my_func(my_pointer);
	my_func(&foo);
	__smatch_implied(my_pointer->a);
	__smatch_implied(my_pointer->b);
	__smatch_implied(foo.a);
	__smatch_implied(foo.b);
}

/*
 * check-name: smatch: inline #3
 * check-command: smatch -I.. sm_inline3.c
 *
 * check-output-start
sm_inline3.c:23 test() implied: my_pointer->a = '1'
sm_inline3.c:24 test() implied: my_pointer->b = '0'
sm_inline3.c:25 test() implied: foo.a = '1'
sm_inline3.c:26 test() implied: foo.b = '0'
 * check-output-end
 */
