#include "check_debug.h"

int a, b;

int frob(int size)
{
	if (a <= 0 || a > 10)
		return;
	if (a % 4) {
		__smatch_implied(a);
	} else {
		__smatch_implied(a);
	}

	if (b <= 0 || b > 100)
		return;
	if (b % 4) {
		__smatch_implied(b);
	} else {
		__smatch_implied(b);
	}



	return 0;
}

/*
 * check-name: smatch mod condition
 * check-command: smatch -I.. sm_mod.c
 *
 * check-output-start
sm_mod.c:10 frob() implied: a = '1-10'
sm_mod.c:12 frob() implied: a = '4,8'
sm_mod.c:18 frob() implied: b = '1-99'
sm_mod.c:20 frob() implied: b = '4-100'
 * check-output-end
 */
