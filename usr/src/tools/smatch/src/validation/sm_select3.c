#include "check_debug.h"

int a, b, c;
int func(void)
{
	if (a ? b : c)
		__smatch_value("a");

	__smatch_note("Test #1 a ? 1 : c");
	if (a ? 1 : c) {	
		__smatch_value("a");
		__smatch_value("c");
		if (!a)
			__smatch_value("c");
		if (!c)
			__smatch_value("a");
	} else {
		__smatch_value("a");
		__smatch_value("c");
	}

	__smatch_note("Test #2 a ? 0 : c");
	if (a ? 0 : c) {	
		__smatch_value("a");
		__smatch_value("c");
		if (!a)
			__smatch_value("c");
	} else {
		__smatch_value("a");
		__smatch_value("c");
		if (!a)
			__smatch_value("c");
		if (!c)
			__smatch_value("a");
	}

	__smatch_note("Test #3 a ? b : 1");
	if (a ? b : 1) {	
		__smatch_value("a");
		__smatch_value("b");
		if (!a)
			__smatch_value("b");
		if (!b)
			__smatch_value("a");
	} else {
		__smatch_value("a");
		__smatch_value("b");
		if (!b)
			__smatch_value("a");
	}

	__smatch_note("Test #2 a ? b : 0");
	if (a ? b : 0) {	
		__smatch_value("a");
		__smatch_value("b");
	} else {
		__smatch_value("a");
		__smatch_value("b");
		if (a)
			__smatch_value("b");
		if (b)
			__smatch_value("a");
	}
}


/*
 * check-name: Ternary Conditions #3
 * check-command: smatch -I.. sm_select3.c
 *
 * check-output-start
sm_select3.c:7 func() a = s32min-s32max
sm_select3.c:9 func() Test #1 a ? 1 : c
sm_select3.c:11 func() a = s32min-s32max
sm_select3.c:12 func() c = s32min-s32max
sm_select3.c:14 func() c = s32min-(-1),1-s32max
sm_select3.c:16 func() a = s32min-(-1),1-s32max
sm_select3.c:18 func() a = 0
sm_select3.c:19 func() c = 0
sm_select3.c:22 func() Test #2 a ? 0 : c
sm_select3.c:24 func() a = 0
sm_select3.c:25 func() c = s32min-(-1),1-s32max
sm_select3.c:27 func() c = s32min-(-1),1-s32max
sm_select3.c:29 func() a = s32min-s32max
sm_select3.c:30 func() c = s32min-s32max
sm_select3.c:32 func() c = 0
sm_select3.c:34 func() a = s32min-s32max
sm_select3.c:37 func() Test #3 a ? b : 1
sm_select3.c:39 func() a = s32min-s32max
sm_select3.c:40 func() b = s32min-s32max
sm_select3.c:42 func() b = s32min-s32max
sm_select3.c:44 func() a = 0
sm_select3.c:46 func() a = s32min-(-1),1-s32max
sm_select3.c:47 func() b = 0
sm_select3.c:49 func() a = s32min-(-1),1-s32max
sm_select3.c:52 func() Test #2 a ? b : 0
sm_select3.c:54 func() a = s32min-(-1),1-s32max
sm_select3.c:55 func() b = s32min-(-1),1-s32max
sm_select3.c:57 func() a = s32min-s32max
sm_select3.c:58 func() b = s32min-s32max
sm_select3.c:60 func() b = 0
sm_select3.c:62 func() a = 0
 * check-output-end
 */
