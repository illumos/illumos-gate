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
 * This is a simple program that is meant for use as other programs consuming
 * it. It simply reads the extended registers and dumps them. The expectation
 * is someone else is showing up and doing something ahead of that.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "xsave_util.h"

static xsu_fpu_t fpu;

int
main(int argc, char *argv[])
{
	FILE *f;
	uint32_t hwsup;

	if (argc != 2) {
		warnx("missing required filename to write to");
		(void) fprintf(stderr, "Usage:  %s <file>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	hwsup = xsu_hwsupport();
	f = fopen(argv[1], "w+");
	if (f == NULL) {
		err(EXIT_FAILURE, "failed to open %s", argv[1]);
	}

	xsu_getfpu(&fpu, hwsup);
	xsu_dump(f, &fpu, hwsup);

	return (EXIT_SUCCESS);
}
