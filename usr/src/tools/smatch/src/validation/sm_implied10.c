#include "check_debug.h"

void frob(void){}

int x[10];
int offset;
void func(int *y)
{
	if (({int test2 = !!(!y || !*y); frob(); frob(); frob(); test2;}))
		__smatch_value("y");
	else
		__smatch_value("y");

	if (({int test2 = !!(offset >= 10 || x[offset] == 1); frob(); frob(); frob(); test2;}))
		__smatch_value("offset");
	else
		__smatch_value("offset");

}
/*
 * check-name: smatch implied #10
 * check-command: smatch -I.. -m64 sm_implied10.c
 *
 * check-output-start
sm_implied10.c:10 func() y = 0,4096-2117777777777777777
sm_implied10.c:12 func() y = 4096-2117777777777777777
sm_implied10.c:15 func() offset = 0-s32max
sm_implied10.c:17 func() offset = 0-9
 * check-output-end
 */
