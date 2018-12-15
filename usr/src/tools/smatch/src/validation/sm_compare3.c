#include <stdio.h>
#include <string.h>
#include "check_debug.h"

int a, b, c, d;
int e, f, g;
int main(void)
{
	if (b > 1000000000)
		return 0;

	if (a >= b)
		return 1;
	if (a < 0 || b < 0)
		return 1;
	c = b - a;
	__smatch_implied(c);
	__smatch_compare(b, c);

	if (e < 0 || e > b)
		return;
	if (f <= 0 || f > b)
		return;
	g = e + f;

	__smatch_implied(g);
	__smatch_implied(e);
	__smatch_compare(g, e);
	__smatch_compare(e, g);
	__smatch_implied(g - e);
	__smatch_implied(g - f);

	return 0;
}

/*
 * check-name: Smatch compare #3
 * check-command: smatch -I.. sm_compare3.c
 *
 * check-output-start
sm_compare3.c:17 main() implied: c = '1-1000000000'
sm_compare3.c:18 main() b <= c
sm_compare3.c:26 main() implied: g = '1-2000000000'
sm_compare3.c:27 main() implied: e = '0-1000000000'
sm_compare3.c:28 main() g > e
sm_compare3.c:29 main() e < g
sm_compare3.c:30 main() implied: g - e = '1-2000000000'
sm_compare3.c:31 main() implied: g - f = '0-1999999999'
 * check-output-end
 */
