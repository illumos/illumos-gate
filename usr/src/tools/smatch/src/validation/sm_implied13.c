#include "check_debug.h"

int main(int x)
{
	int a = 1;

	if (x & 12)
		a = 2;
	__smatch_implied(a);
	if (!(x & 12))
		return 0;
	__smatch_implied(a);
	return 0;
}

/*
 * check-name: smatch implied #13
 * check-command: smatch -I.. sm_implied13.c
 *
 * check-output-start
sm_implied13.c:9 main() implied: a = '1-2'
sm_implied13.c:12 main() implied: a = '2'
 * check-output-end
 */
