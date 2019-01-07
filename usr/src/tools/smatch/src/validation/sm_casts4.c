#include <stdio.h>
#include <string.h>
#include "check_debug.h"

long long l;
unsigned long long ul;
int i;
unsigned int ui;
signed char c;
unsigned char uc;

int main(void)
{
	int idx;

	if (c < -2)
		return 1;
	if (uc < -2)
		return 1;
	if (i < -2)
		return 1;
	if (ui < -2)
		return 1;
	if (l < -2)
		return 1;
	if (ul < -2)
		return 1;

	__smatch_implied(l);
	__smatch_implied(ul);
	__smatch_implied(i);
	__smatch_implied(ui);
	__smatch_implied(c);
	__smatch_implied(uc);

	return 0;
}


/*
 * check-name: smatch: casts #4
 * check-command: smatch -I.. sm_casts4.c
 *
 * check-output-start
sm_casts4.c:18 main() warn: impossible condition '(uc < -2) => (0-255 < (-2))'
sm_casts4.c:29 main() implied: l = '(-2)-s64max'
sm_casts4.c:30 main() implied: ul = '18446744073709551614-u64max'
sm_casts4.c:31 main() implied: i = '(-2)-s32max'
sm_casts4.c:32 main() implied: ui = '4294967294-u32max'
sm_casts4.c:33 main() implied: c = '(-2)-127'
sm_casts4.c:34 main() implied: uc = ''
 * check-output-end
 */
