#include "check_debug.h"

int checker(void);

int x;
int i;
void func(void)
{
	int ar[10];

	if (i < 0)
		return;
	if(i == 0)
		x = 11;
	else
		x = 1;

	while(i--) {
		__smatch_value("x");
		ar[x] = 1;
	}
}
/*
 * check-name: smatch loops #3
 * check-command: smatch -I.. sm_loops3.c
 *
 * check-output-start
sm_loops3.c:19 func() x = 1
 * check-output-end
 */
