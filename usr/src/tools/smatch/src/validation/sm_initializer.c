#include "check_debug.h"

struct bar {
	int a, b, c;
};

struct foo {
	struct bar bar;
	int x, y, z;
};

int test(int size)
{
	struct foo foo = {
		.bar.a = 42,
		.bar.b = 43,
		-1,
	};
	__smatch_implied(foo.bar.b);
	__smatch_implied(foo.bar.c);
	__smatch_implied(foo.x);
	__smatch_implied(foo.y);

	return 0;
}

/*
 * check-name: smatch: nested initializer
 * check-command: smatch -I.. sm_initializer.c
 *
 * check-output-start
sm_initializer.c:19 test() implied: foo.bar.b = '43'
sm_initializer.c:20 test() implied: foo.bar.c = '0'
sm_initializer.c:21 test() implied: foo.x = '(-1)'
sm_initializer.c:22 test() implied: foo.y = '0'
 * check-output-end
 */
