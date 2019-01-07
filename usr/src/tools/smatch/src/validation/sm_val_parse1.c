#include "check_debug.h"

int main(int x)
{
	x = __smatch_type_rl(int, "s32min-s32max[$2 + 4]", 5);
	__smatch_implied(x);

	return 0;
}
/*
 * check-name: smatch parse value
 * check-command: smatch -I.. sm_val_parse1.c
 *
 * check-output-start
sm_val_parse1.c:6 main() implied: x = '9'
 * check-output-end
 */
