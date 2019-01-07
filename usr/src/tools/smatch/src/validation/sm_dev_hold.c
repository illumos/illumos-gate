void dev_hold(int *x);

void dev_put(int *x){}

extern int y,z;
int *x;

int func (void)
{
	dev_hold(x);
	if (y) {
		dev_put(x);
		return -1;
	}
	if (z) {
		return -1;
	}
	return 0;
}
/*
 * check-name: dev_hold() check
 * check-command: smatch --project=kernel sm_dev_hold.c
 *
 * check-output-start
sm_dev_hold.c:16 func() warn: 'x' held on error path.
 * check-output-end
 */
