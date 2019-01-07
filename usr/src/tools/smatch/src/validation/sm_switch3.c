#include "check_debug.h"

int a, b;

int frob(void);

int test(int size)
{
	a = 0;

	if (({switch (frob()) {
		case 1:
			a = 2;
			break;
		default:
			a = 3;
	     }
	     b;}))
		;
	__smatch_implied(a);

	a = 4;

	if (({switch (2) {
		case 1:
			a = 5;
			break;
		case 2:
			a = 6;
			break;
		default:
			a = 7;
	     }
	     b;}))
		;
	__smatch_implied(a);

	return 0;
}

/*
 * check-name: smatch: switch #3
 * check-command: smatch -I.. sm_switch3.c
 *
 * check-output-start
sm_switch3.c:20 test() implied: a = '2-3'
sm_switch3.c:36 test() implied: a = '6'
 * check-output-end
 */
