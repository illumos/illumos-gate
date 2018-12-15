#include "check_debug.h"

int frob();

int a, b, c;
void func(unsigned long x)
{
	if (x >= 4)
		return;

	__smatch_value("x");
	if ((!(a) ? -19 : (((b && c) ? frob() : -515))))
		__smatch_value("x");
	__smatch_value("x");
}
/*
 * check-name: Smatch Ternary #4
 * check-command: smatch -I.. sm_select4.c
 *
 * check-output-start
sm_select4.c:11 func() x = 0-3
sm_select4.c:13 func() x = 0-3
sm_select4.c:14 func() x = 0-3
 * check-output-end
 */
