#include <stdio.h>
#include "check_debug.h"

int frob1(int *p)
{
	__smatch_implied(*p);
}

int frob2(int *p)
{
	__smatch_implied(*p);
}

int x = 42;

struct foo {
	int a, b, c;
};
struct foo aaa = {
	.a = 1, .b = 2, .c = 3,
};

int array[10];

int main(void)
{
	frob1(&x);
	frob2(&aaa.b);

	return 0;
}

/*
 * check-name: smatch mtag #6
 * check-command: validation/smatch_db_test.sh -I.. sm_mtag6.c
 *
 * check-output-start
sm_mtag6.c:6 frob1() implied: *p = '42'
sm_mtag6.c:11 frob2() implied: *p = '2'
 * check-output-end
 */
