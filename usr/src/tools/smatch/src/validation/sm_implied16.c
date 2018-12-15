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
		if (x != 0)
			return;
	} else if (a == 3) {
		if (x != 42)
			return;
	} else {
		return;
	}

	if (x) {
		__smatch_implied(x);
		__smatch_implied(a);
	}

	if (x == -5)
		__smatch_implied(a);

	return 0;
}

/*
 * check-name: smatch implied #16
 * check-command: smatch -I.. sm_implied16.c
 *
 * check-output-start
sm_implied16.c:24 func() implied: x = '(-5),42'
sm_implied16.c:25 func() implied: a = '1,3'
sm_implied16.c:29 func() implied: a = '1'
 * check-output-end
 */
