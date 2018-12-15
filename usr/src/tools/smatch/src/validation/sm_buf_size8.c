#include <stdlib.h>
#include "check_debug.h"

struct foo {
	int x, y, z;
	int count;
	char msg[0];
};

struct bar {
	int x, y, z;
	int count;
	char msg[1];
};

struct outer1 {
	int x, y, z;
	struct foo foo;
};

struct outer2 {
	int x, y, z;
	struct bar bar;
};

int test(void)
{
	struct foo *p;
	struct bar *q;
	struct outer1 *a;
	struct outer2 *b;

	p = malloc(sizeof(*p) + 100);
	__smatch_buf_size(p->msg);

	q = malloc(sizeof(*q) + 100);
	__smatch_buf_size(q->msg);

	a = malloc(sizeof(*a) + 100);
	__smatch_buf_size(a->foo);

	b = malloc(sizeof(*b) + 100);
	__smatch_buf_size(b->bar);
}

/*
 * check-name: smatch buf size #8
 * check-command: smatch -I.. sm_buf_size8.c
 *
 * check-output-start
sm_buf_size8.c:34 test() buf size: 'p->msg' 100 elements, 100 bytes
sm_buf_size8.c:37 test() buf size: 'q->msg' 101 elements, 101 bytes
sm_buf_size8.c:40 test() buf size: 'a->foo' 0 elements, 116 bytes
sm_buf_size8.c:43 test() buf size: 'b->bar' 0 elements, 120 bytes
 * check-output-end
 */
