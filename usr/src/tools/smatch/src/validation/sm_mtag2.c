#include <stdio.h>
#include "check_debug.h"

struct foo {
	int a, b, c;
	int (*func)(int *p);
	void (*func2)(int a);
	void *data;
};

static int frob1(int *val)
{
	__smatch_implied(*val);
	return *val + 1;
}

static int frob2(int *val)
{
	__smatch_implied(*val);
	return *val + 1;
}

static struct foo one_struct = {
	.a = 1,
	.func = frob1,
};

static struct foo two_struct = {
	.a = 2,
	.func = frob2,
};

struct foo *unknown(void);
struct foo *p;

int main(void)
{
	int ret;

	p = unknown();
	ret = p->func(&p->a);

	return 0;
}

/*
 * check-name: smatch mtag #2
 * check-command: validation/smatch_db_test.sh -I.. sm_mtag2.c
 *
 * check-output-start
sm_mtag2.c:13 frob1() implied: *val = '1'
sm_mtag2.c:19 frob2() implied: *val = '2'
 * check-output-end
 */
