#include "check_debug.h"

int *something();

int *one;
int *two;
int func(void)
{
	one = something();
	two = one;

	if (two == 1) {
		__smatch_value("one");
		__smatch_value("two");
	}
	__smatch_value("one");
	__smatch_value("two");
	if (one == 2) {
		__smatch_value("one");
		__smatch_value("two");
	}
	__smatch_value("one");
	__smatch_value("two");
	return 0;
}
/*
 * check-name: smatch equivalent variables #1
 * check-command: smatch -I.. -m64 sm_equiv1.c
 *
 * check-output-start
sm_equiv1.c:13 func() one = 1
sm_equiv1.c:14 func() two = 1
sm_equiv1.c:16 func() one = 0-u64max
sm_equiv1.c:17 func() two = 0-u64max
sm_equiv1.c:19 func() one = 2
sm_equiv1.c:20 func() two = 2
sm_equiv1.c:22 func() one = 0-u64max
sm_equiv1.c:23 func() two = 0-u64max
 * check-output-end
 */
