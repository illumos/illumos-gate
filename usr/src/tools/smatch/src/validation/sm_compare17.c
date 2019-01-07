#include "check_debug.h"

int frob();

int xxx;
static int options_write(void)
{
	int a = -1;
	int found = 0;

	if (xxx < 0)
		return;
	while (frob()) {
		if (++a == xxx) {
			found = 1;
			break;
		}
	}
	if (!found)
		__smatch_compare(a, xxx);
}

/*
 * check-name: smatch compare #17
 * check-command: smatch -I.. sm_compare17.c
 *
 * check-output-start
sm_compare17.c:20 options_write() a < xxx
 * check-output-end
 */
