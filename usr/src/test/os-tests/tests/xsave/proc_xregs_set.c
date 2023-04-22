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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * This program pairs with the xregs_dump.32 and xregs_dump.64 program. It's
 * main purpose is to use /proc to overwrite the FPU contents right before our
 * target program calls xsu_getfpu().
 *
 * To accomplish this we end up using libproc for some mischief via support
 * routines. In particular we go through the following to logically accomplish
 * this:
 *
 *   o Generate the target FPU contents that we'll write (seeded from the CLI)
 *   o Explicitly create the process, which will be stopped.
 *   o Set it to be killed if we die.
 *   o Find the xsu_getfpu() symbol in the target and set a breakpoint.
 *   o Resume execution of the process.
 *   o When the break point hits, use libproc to set the FPU.
 *   o Delete the breakpoint and resume the process, which will print the FPU
 *     regs to a designated file.
 *   o Verify the process successfully terminates and returns 0.
 *
 * A critical assumption here is that our hardware support is not going to
 * change between processes (something that may be mucked around with via
 * environment variables for rtld).
 */

#include <err.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

#include "xsave_util.h"

static xsu_fpu_t fpu;

int
main(int argc, char *argv[])
{
	uint32_t seed, hwsup;
	unsigned long ul;
	char *eptr;
	prxregset_t *prx;
	size_t prx_len;
	xsu_proc_t xp;

	if (argc != 5) {
		errx(EXIT_FAILURE, "missing args: <prog> <output file> "
		    "<seed> <func>");
	}

	errno = 0;
	ul = strtoul(argv[3], &eptr, 0);
	if (errno != 0 || *eptr != '\0') {
		errx(EXIT_FAILURE, "seed value is bad: %s", argv[3]);
	}

#if defined(_LP64)
	if (ul > UINT32_MAX) {
		errx(EXIT_FAILURE, "seed %s, exceeds [0, UINT32_MAX]", argv[3]);
	}
#endif

	seed = (uint32_t)ul;
	hwsup = xsu_hwsupport();
	xsu_fill(&fpu, hwsup, seed);
	xsu_fpu_to_xregs(&fpu, hwsup, &prx, &prx_len);

	(void) memset(&xp, 0, sizeof (xsu_proc_t));
	xp.xp_prog = argv[1];
	xp.xp_arg = argv[2];
	xp.xp_object = "a.out";
	xp.xp_symname = argv[4];

	xsu_proc_bkpt(&xp);
	/* We know that libc always creates a default thread with id of 1 */
	if (Plwp_setxregs(xp.xp_proc, 1, prx, prx_len) != 0) {
		err(EXIT_FAILURE, "failed to set target's xregs");
	}

	xsu_proc_finish(&xp);

	if (WEXITSTATUS(xp.xp_wait) != EXIT_SUCCESS) {
		errx(EXIT_FAILURE, "our target process didn't exit non-zero, "
		    "got %d", WEXITSTATUS(xp.xp_wait));
	}

	return (EXIT_SUCCESS);
}
