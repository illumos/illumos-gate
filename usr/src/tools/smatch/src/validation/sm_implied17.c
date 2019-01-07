#include "check_debug.h"

int frob(void);

int a;
int func (char *input)
{
	int x = frob();

	if (a == 1) {
		if (x != -5)
			return;
	} else if (a == 2) {
		if (x < 0 || x > 10)
			return;
	} else {
		return;
	}

	if (x)
		;

	if (x == -5)
		__smatch_implied(a);

	return 0;
}

/*
 * check-name: smatch implied #17
 * check-command: smatch -I.. sm_implied17.c
 *
 * check-output-start
sm_implied17.c:24 func() implied: a = '1'
 * check-output-end
 */
