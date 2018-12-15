#include <stdio.h>
#include "check_debug.h"

struct foo {
	int (*func)(struct foo *);
	int a, b, c;
	int *p;
};

int frob1(struct foo *p)
{
	__smatch_implied(*p->p);
}

int frob2(struct foo *p)
{
	__smatch_implied(*p->p);
}

int x = 42;
int y = 43;

struct foo aaa = {
	.func = frob1,
	.a = 1, .b = 2, .c = 3,
	.p = &x,
};
struct foo bbb = {
	.func = frob2,
	.a = 10, .b = 11, .c = 13,
	.p = &y,
};

int main(void)
{
	aaa.func(&aaa);
	bbb.func(&bbb);
	return 0;
}

/*
 * check-name: smatch mtag #7
 * check-command: validation/smatch_db_test.sh -I.. sm_mtag7.c
 *
 * check-output-start
sm_mtag7.c:12 frob1() implied: *p->p = '42'
sm_mtag7.c:17 frob2() implied: *p->p = '43'
 * check-output-end
 */
