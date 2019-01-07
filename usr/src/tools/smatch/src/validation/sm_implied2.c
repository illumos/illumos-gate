struct ture {
	int a;
};

struct ture *a;
struct ture *b;
struct ture *c;

void func (void)
{
	struct ture *aa, *ab;

	b = 0;
	if (a) {
		aa = returns_nonnull();
		ab = returns_nonnull();
	} else {
		b = -1;
	}
	if (!(b)) {
		if (c) {
			aa = (void *)0;
			ab = (void *)0;
			b = -1;
		}
	}
	if (!c)
		aa->a = 1;
	if (b)
		return;
	ab->a = 1;
	return;
}
/*
 * check-name: Smatch implied #2
 * check-command: smatch --spammy sm_implied2.c
 *
 * check-output-start
sm_implied2.c:28 func() error: potentially dereferencing uninitialized 'aa'.
 * check-output-end
 */
