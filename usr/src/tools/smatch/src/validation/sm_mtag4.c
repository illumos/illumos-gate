#include <stdio.h>
#include "check_debug.h"

struct foo {
	int a, b, c;
	int (*func)(int *p);
	void (*func2)(int a);
	void *data;
};

static void frob_int1(int val)
{
	__smatch_implied(val);
}

static void frob_int2(int val)
{
	__smatch_implied(val);
}

static struct foo one_struct = {
	.b = 41,
	.func2 = frob_int1,
};

static struct foo two_struct = {
	.b = 42,
	.func2 = frob_int2,
};

struct foo *unknown(void);
struct foo *p;

int main(void)
{
	int ret;

	p = unknown();
	p->func2(p->b);

	return 0;
}

/*
 * check-name: smatch mtag #4
 * check-command: validation/smatch_db_test.sh -I.. sm_mtag4.c
 *
 * check-output-start
sm_mtag4.c:13 frob_int1() implied: val = '41'
sm_mtag4.c:18 frob_int2() implied: val = '42'
 * check-output-end
 */
