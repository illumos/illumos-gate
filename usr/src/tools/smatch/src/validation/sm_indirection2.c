#include "check_debug.h"

struct foo {
	int a, b, c;
};

struct bar {
	struct foo *foo;
};

struct foo *get_foo(struct bar *bar)
{
	return bar->foo;
}

void frob(struct bar *bar)
{
	struct foo *f = bar->foo;
	f->a = 5;
}

int test(struct bar *bar)
{
	struct foo *f = get_foo(bar);

	f->a = 1;
	frob(bar);
	__smatch_implied(bar->foo->a);
	__smatch_implied(f->a);

	return 0;
}

/*
 * check-name: smatch: indirection #2
 * check-command: smatch -I.. sm_indirection2.c
 *
 * check-output-start
sm_indirection2.c:28 test() implied: bar->foo->a = '5'
sm_indirection2.c:29 test() implied: f->a = '5'
 * check-output-end
 */
