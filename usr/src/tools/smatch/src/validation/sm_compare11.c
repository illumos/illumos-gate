#include "check_debug.h"

int frob();

static int options_write(void)
{
	int a = frob();
	int b = frob();
	int c = frob();
	int d = frob();

	a = d;
	if (a > b + c) {
		a = b + c;
	}
	__smatch_compare(a, d);
}

/*
 * check-name: smatch compare #11
 * check-command: smatch -I.. sm_compare11.c
 *
 * check-output-start
sm_compare11.c:16 options_write() a <= d
 * check-output-end
 */
