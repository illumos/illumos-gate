#include "check_debug.h"

extern int xxx;

int test(struct bar *bar)
{
	int a = 10, b = 10, c = 10, d = 10, e = 10;

	while (a--)
		__smatch_implied(a);
	__smatch_implied(a);

	while (--b)
		__smatch_implied(b);
	__smatch_implied(b);

	while (--c >= 0)
		__smatch_implied(c);
	__smatch_implied(c);

	while (d-- >= 0)
		__smatch_implied(d);
	__smatch_implied(d);

	while (e-- >= 0) {
		if (xxx)
			break;
		__smatch_implied(e);
	}
	__smatch_implied(e);

	return 0;
}


/*
 * check-name: smatch loops #6
 * check-command: smatch -I.. sm_loops6.c
 *
 * check-output-start
sm_loops6.c:10 test() implied: a = '0-9'
sm_loops6.c:11 test() implied: a = '(-1)'
sm_loops6.c:14 test() implied: b = '1-9'
sm_loops6.c:15 test() implied: b = '0'
sm_loops6.c:18 test() implied: c = '0-9'
sm_loops6.c:19 test() implied: c = '(-1)'
sm_loops6.c:22 test() implied: d = '(-1)-9'
sm_loops6.c:23 test() implied: d = '(-2)'
sm_loops6.c:28 test() implied: e = '(-1)-9'
sm_loops6.c:30 test() implied: e = '(-2)-9'
 * check-output-end
 */
