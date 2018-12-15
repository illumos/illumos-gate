//#include <stdlib.h>

struct foo {
	int a;
};

struct foo *a;
struct foo *b;
struct foo *c;
struct foo *d;
int x;

void func (void)
{
	a = 0;
	b = 0;
	c = 0;
	d = 0;

	switch(x) {
	case 1:
		a = returns_nonnull();
		break;
	case 2:
		b = returns_nonnull();
		break;
	case 3:
		c = returns_nonnull();
		break;
	default:
		d = returns_nonnull();
	}

	switch(x) {
	case 1:
		a->a = 1;
	case 2:
		a->a = 2;
		b->a = 3;
		break;
	case 3:
		c->a = 4;
		break;
	case 4:
		d->a = 5;
		break;
	}
}
/*
 * check-name: Smatch switch handling
 * check-command: smatch --spammy sm_switch.c
 * check-known-to-fail
 *
 * check-output-start
sm_switch.c:38 func() warn: missing break? reassigning 'a->a'
sm_switch.c:38 func() error: potential NULL dereference 'a'.
sm_switch.c:39 func() error: potential NULL dereference 'b'.
 * check-output-end
 */
