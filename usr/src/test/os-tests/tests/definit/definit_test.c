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
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 */

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <definit.h>

int
main(int argc, char **argv)
{
	void *state;
	const char *p;

	if (argc != 2) {
		fprintf(stderr, "Syntax: %s <init file>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (definit_open(argv[1], &state) != 0)
		err(EXIT_FAILURE, "Open of %s failed.", argv[1]);

	while ((p = definit_token(state)) != NULL)
		printf(":%s:\n", p);

	definit_close(state);

	return (0);
}
