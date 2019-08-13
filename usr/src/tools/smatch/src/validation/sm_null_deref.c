#include "check_debug.h"

struct foo {
	int a;
};

struct foo *a;
struct foo *b;
struct foo *c;
struct foo *d;

static void func (void)
{
	struct foo *aa;
	int ab = 0;
	int ac = 1;

	aa->a = 1;

	if (a) {
		a->a = 1;
	}
	a->a = 1;

	if (a && b) {
		b->a = 1;
	}

	if (a || b) {
		b->a = 1;
	}

	if (c) {
		ab = 1;
	}

	if (ab) {
		c->a = 1;
	}
}
/*
 * check-name: Null Dereferences
 * check-command: smatch --spammy -I.. sm_null_deref.c
 *
 * check-output-start
sm_null_deref.c:18 func() error: potentially dereferencing uninitialized 'aa'.
sm_null_deref.c:18 func() error: potentially dereferencing uninitialized 'aa'.
sm_null_deref.c:23 func() error: we previously assumed 'a' could be null (see line 20)
sm_null_deref.c:25 func() warn: variable dereferenced before check 'a' (see line 23)
sm_null_deref.c:30 func() error: we previously assumed 'b' could be null (see line 25)
 * check-output-end
 */

