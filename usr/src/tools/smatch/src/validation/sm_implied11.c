#include "check_debug.h"

struct foo {
	int x;
};

void *frob();

struct foo *foo;

static void ad_agg_selection_logic(void)
{
	int a;


	if (foo && foo->x)
		a = 1;
	else
		a = 0;

	if (frob())
		a = frob();

	if (a)
		__smatch_implied(foo);
}
/*
 * check-name: smatch implied #11
 * check-command: smatch -I.. -m64 sm_implied11.c
 *
 * check-output-start
sm_implied11.c:25 ad_agg_selection_logic() implied: foo = '0,4096-ptr_max'
 * check-output-end
 */
