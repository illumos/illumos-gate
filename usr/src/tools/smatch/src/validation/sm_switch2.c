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

	if (x == 1)
		a = some_func();
	else if (x == 2)
		b = some_func();
	else if (x == 3)
		c = some_func();
	else
		d = some_func();

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
 * check-name: Smatch switch handling #2
 * check-command: smatch --spammy sm_switch2.c
 *
 * check-output-start
sm_switch2.c:31 func() warn: missing break? reassigning 'a->a'
sm_switch2.c:31 func() error: potential NULL dereference 'a'.
sm_switch2.c:32 func() error: potential NULL dereference 'b'.
 * check-output-end
 */
