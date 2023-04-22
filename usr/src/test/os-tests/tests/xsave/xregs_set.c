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
 * This is a program that is meant to be used as a target for libproc and mdb.
 * It uses a CLI-based seed and sets its FPU to a set of known values. After
 * that, we call a function that can be used as a no-op target to dump the FPU
 * state, attempting to minimize the number of instructions inbetween
 * operations. We use the 'yield(2)' system call and library function in libc
 * for that as it's something that'll not really do much and it is very unlikely
 * the compiler will use the FPU between function calls.
 */

#include <err.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "xsave_util.h"

static xsu_fpu_t fpu;

int
main(int argc, char *argv[])
{
	uint32_t hwsup;
	char *eptr;
	unsigned long ul;

	if (argc != 2) {
		errx(EXIT_FAILURE, "missing required seed");
	}

	errno = 0;
	ul = strtoul(argv[1], &eptr, 0);
	if (errno != 0 || *eptr != '\0') {
		errx(EXIT_FAILURE, "seed value is bad: %s", argv[3]);
	}

	hwsup = xsu_hwsupport();
	xsu_fill(&fpu, hwsup, (uint32_t)ul);
	xsu_setfpu(&fpu, hwsup);

	yield();
	return (EXIT_SUCCESS);
}
