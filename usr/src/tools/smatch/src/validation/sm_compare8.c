#include "check_debug.h"

void *a, *b;
static int options_write(void)
{
	a = b + 1;
	__smatch_compare(a, b);
}

/*
 * check-name: smatch compare #8
 * check-command: smatch -I.. sm_compare8.c
 *
 * check-output-start
sm_compare8.c:7 options_write() a > b
 * check-output-end
 */
