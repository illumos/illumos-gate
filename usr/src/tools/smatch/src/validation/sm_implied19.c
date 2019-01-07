#include "check_debug.h"

int xxx, yyy;
int aaa, bbb;
int id, vbus;
void frob(void)
{
	if (xxx)
		id = yyy;
	else
		id = 1;

	if (aaa)
		vbus = bbb;
	else
		vbus = id;

	if (id)
		;
	if (!vbus)
		;

	if (!id)
		__smatch_implied(vbus);
}

/*
 * check-name: smatch implied #19
 * check-command: smatch -I.. sm_implied19.c
 *
 * check-output-start
sm_implied19.c:24 frob() implied: vbus = 's32min-s32max'
 * check-output-end
 */
