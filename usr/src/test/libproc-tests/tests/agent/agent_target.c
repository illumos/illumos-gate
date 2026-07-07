/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2026 Oxide Computer Company
 */

/*
 * This program serves as a target for the agent_destroy program to run.
 * agent_target_hook() is used as a place to set a breakpoint at which the
 * controller performs its injections. There is no state to verify afterwards.
 * The test is that this program remains controllable throughout and runs to
 * completion undamaged.
 */

#include <stdlib.h>

/*
 * This is used as a place to set a breakpoint for the controller to find us.
 * It is a weak symbol to help avoid compiler optimisation.
 */
#pragma weak agent_target_hook
void
agent_target_hook(void)
{
}

int
main(void)
{
	agent_target_hook();
	return (EXIT_SUCCESS);
}
