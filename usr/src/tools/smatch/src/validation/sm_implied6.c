struct foo {
	int a;
};

struct foo *a;
struct foo *b;
struct foo *c;
struct foo *d;
int x, y, z;

void func (void)
{
	a = 0;
	b = 0;
	c = 0;
	d = 0;

	if (x)
		a = returns_nonnull();
	else
		b = returns_nonnull();
	if (y)
		a = returns_nonnull();
	else
		c = returns_nonnull();
	__smatch_extra_values();
	if (x || y) {
		a->a = 1;
		b->a = 2;
	}else {
		c->a = 3;
	}
}
/*
 * check-name: Smatch implied #6
 * check-command: smatch --spammy sm_implied6.c
 *
 * check-output-start
sm_implied6.c:29 func() error: potential NULL dereference 'b'.
 * check-output-end
 */
