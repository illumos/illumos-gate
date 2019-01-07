#include "check_debug.h"

int aaa;
int x, y, z;

void func (void)
{
	aaa = 0;
	if (y)
		aaa = 1;
	if (x)
		aaa = 2;

	if (x) {
		__smatch_value("aaa");
		if (y)
			__smatch_value("aaa");
		else
			__smatch_value("aaa");
	}
	if (!x) {		
		__smatch_value("aaa");
		if (y)		
			__smatch_value("aaa");
		else
			__smatch_value("aaa");
	}
	if (y) {
		__smatch_value("aaa");
		if (x)
			__smatch_value("aaa");
		else
			__smatch_value("aaa");
	}
	if (!y) {
		__smatch_value("aaa");
		if (x)		
			__smatch_value("aaa");
		else
			__smatch_value("aaa");
	}
	if (x && y)
		__smatch_value("aaa");
	if (x || y)
		__smatch_value("aaa");
	else
		__smatch_value("aaa");
	if (!x && !y)
		__smatch_value("aaa");
}
/*
 * check-name: Compound Conditions #2
 * check-command: smatch -I.. sm_compound_conditions2.c
 *
 * check-output-start
sm_compound_conditions2.c:15 func() aaa = 2
sm_compound_conditions2.c:17 func() aaa = 2
sm_compound_conditions2.c:19 func() aaa = 2
sm_compound_conditions2.c:22 func() aaa = 0-1
sm_compound_conditions2.c:24 func() aaa = 1
sm_compound_conditions2.c:26 func() aaa = 0
sm_compound_conditions2.c:29 func() aaa = 1-2
sm_compound_conditions2.c:31 func() aaa = 2
sm_compound_conditions2.c:33 func() aaa = 1
sm_compound_conditions2.c:36 func() aaa = 0,2
sm_compound_conditions2.c:38 func() aaa = 2
sm_compound_conditions2.c:40 func() aaa = 0
sm_compound_conditions2.c:43 func() aaa = 2
sm_compound_conditions2.c:45 func() aaa = 1-2
sm_compound_conditions2.c:47 func() aaa = 0
sm_compound_conditions2.c:49 func() aaa = 0
 * check-output-end
 */
