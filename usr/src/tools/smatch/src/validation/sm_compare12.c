#include "check_debug.h"

#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1: __min2; })

int frob();

static int options_write(void)
{
	int a = frob();
	int b = frob();
	int c = frob();
	int d = frob();

	a = min_t(int, b + c, d);
	__smatch_compare(a, d);
	__smatch_compare(a, b + c);
	b++;
	__smatch_compare(a, b + c);
	a++;  /* argh...  really one increment should mean a <= b + c */
	a++;
	__smatch_compare(a, b + c);

}

/*
 * check-name: smatch compare #12
 * check-command: smatch -I.. sm_compare12.c
 *
 * check-output-start
sm_compare12.c:18 options_write() a <= d
sm_compare12.c:19 options_write() a <= b + c
sm_compare12.c:21 options_write() a < b + c
sm_compare12.c:24 options_write() a <none> b + c
 * check-output-end
 */
