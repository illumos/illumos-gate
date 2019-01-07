struct foo {
	int a;
};

struct foo *a;
struct foo *b;

struct foo *c;
struct foo *d;
struct foo *e;
void func (void)
{
	if (a?b:0) {
		a->a = 1;
		b->a = 1;
	}
	a->a = 1;
	b->a = 1;
	e->a = 1;
	d = returns_nonnull();
	if (c?d:e) {
		c->a = 1;
		d->a = 1;
		e->a = 1;
	}
	e->a = 1;
}

/*
 * check-name: Ternary Conditions
 * check-command: smatch sm_select.c
 *
 * check-output-start
sm_select.c:17 func() error: we previously assumed 'a' could be null (see line 13)
sm_select.c:18 func() error: we previously assumed 'b' could be null (see line 13)
sm_select.c:21 func() warn: variable dereferenced before check 'e' (see line 19)
sm_select.c:22 func() error: we previously assumed 'c' could be null (see line 21)
 * check-output-end
 */

