#include "check_debug.h"

struct ture {
	int x, y;
};

struct ture outside = {
	.x = 1,
	.y = 2,
};

struct ture buf[10];
void test(void)
{
	int a, b;

	a = 0;
	b = 0;
	buf[a++] = outside;
	buf[++b] = outside;
	__smatch_implied(a);
	__smatch_implied(b);
}

/*
 * check-name: smatch fake assignment
 * check-command: smatch -I.. sm_fake_assignment.c
 *
 * check-output-start
sm_fake_assignment.c:21 test() implied: a = '1'
sm_fake_assignment.c:22 test() implied: b = '1'
 * check-output-end
 */
