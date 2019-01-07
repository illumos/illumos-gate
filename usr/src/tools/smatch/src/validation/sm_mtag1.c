#include <stdio.h>
#include "check_debug.h"

static int xxx = 234;

struct foo {
	int a, b, c;
	int (*func)(struct foo *p);
};

static int frob1(struct foo *p)
{
	printf("%d\n", p->a);
	__smatch_implied(p->a);
	return p->a + 1;
}
static int frob2(struct foo *p)
{
	printf("%d\n", p->a);
	__smatch_implied(p->a);
	return p->a + 1;
}

static struct foo one_struct = {
	.a = 1,
	.func = frob1,
};
static struct foo two_struct = {
	.a = 2,
	.func = frob2,
};

int main(void)
{
	struct foo *p = &one_struct;
	int ret;

	ret = p->func(p);
//	__smatch_implied(ret);

	return 0;
}

/*
 * check-name: smatch mtag #1
 * check-command: validation/smatch_db_test.sh -I.. sm_mtag1.c
 *
 * check-output-start
sm_mtag1.c:14 frob1() implied: p->a = '1'
sm_mtag1.c:20 frob2() implied: p->a = '2'
 * check-output-end
 */
