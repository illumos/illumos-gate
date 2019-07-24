#include "check_debug.h"

int load_sig(unsigned long sig)
{
	return sig < 4 ? 0 : -12;
}

int a;
void test(void)
{
	int ret;

	ret = load_sig(a);
	if (ret) {
		__smatch_implied(ret);
		__smatch_implied(a);
	} else {
		__smatch_implied(a);
	}
}

/*
 * check-name: smatch select #5
 * check-command: smatch -I.. sm_select5.c
 *
 * check-output-start
sm_select5.c:15 test() implied: ret = '(-12)'
sm_select5.c:16 test() implied: a = 's32min-(-1),4-s32max'
sm_select5.c:18 test() implied: a = '0-3'
 * check-output-end
 */
