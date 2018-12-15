#include "check_debug.h"

int one(void)
{
	return 1;
}


int main(unsigned int x, unsigned int y)
{
	if (one())
		__smatch_states("register_impossible_return");
	else
		__smatch_states("register_impossible_return");
}

/*
 * check-name: smatch impossible #2
 * check-command: smatch -I.. sm_impossible2.c
 *
 * check-output-start
sm_impossible2.c:12 main() register_impossible_return: no states
sm_impossible2.c:14 main() [register_impossible_return] 'impossible' = 'impossible'
 * check-output-end
 */
