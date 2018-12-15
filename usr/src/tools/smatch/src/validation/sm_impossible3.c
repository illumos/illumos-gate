#include "check_debug.h"

int frob(void);

int main(void)
{
	int x;

	x = frob();

	if (x != -28)
		return;

	if (x != -28 && x != -30)
		__smatch_implied(x);
	__smatch_implied(x);

	return 0;
}

/*
 * check-name: smatch impossible #3
 * check-command: smatch -I.. sm_impossible3.c
 *
 * check-output-start
sm_impossible3.c:15 main() implied: x = ''
sm_impossible3.c:16 main() implied: x = '(-28)'
 * check-output-end
 */
