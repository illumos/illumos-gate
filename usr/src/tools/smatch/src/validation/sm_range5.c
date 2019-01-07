#include "check_debug.h"

int main(unsigned int x, unsigned int y)
{
	switch (x) {
	case 0 ... 9:
		__smatch_implied(x);
		break;
	default:
		__smatch_implied(x);
	}
}

/*
 * check-name: smatch range #5
 * check-command: smatch -I.. sm_range5.c
 *
 * check-output-start
sm_range5.c:7 main() implied: x = '0-9'
sm_range5.c:10 main() implied: x = '10-u32max'
 * check-output-end
 */
