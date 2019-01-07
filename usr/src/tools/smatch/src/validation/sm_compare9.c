#include "check_debug.h"

void *a, *b;
static int options_write(void)
{
	a = b / 2;
	__smatch_compare(a, b);
}

/*
 * check-name: smatch compare #9
 * check-command: smatch -I.. sm_compare9.c
 *
 * check-output-start
sm_compare9.c:7 options_write() a < b
 * check-output-end
 */
