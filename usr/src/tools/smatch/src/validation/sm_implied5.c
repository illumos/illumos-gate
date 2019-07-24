struct ture {
	int a;
};

int out_a;

void func (void)
{
	struct ture *aa;
	int a = 0;

	if (out_a) {	
		aa = returns_nonnull();
		a = something();
	}
	if (a)
		aa->a = 1;
	aa->a = 0xF00D;
}
/*
 * check-name: Smatch implied #5
 * check-command: smatch --spammy sm_implied5.c
 *
 * check-output-start
sm_implied5.c:18 func() error: potentially dereferencing uninitialized 'aa'.
sm_implied5.c:18 func() error: potentially dereferencing uninitialized 'aa'.
 * check-output-end
 */
