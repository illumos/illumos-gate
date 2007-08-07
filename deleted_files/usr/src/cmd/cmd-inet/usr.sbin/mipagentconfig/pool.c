/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1999 - 2002 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * pool.c - Functions to manipulate address pools for dynamically allocated
 *          ip numbers.
 *
 *    Example of good entry:
 *
 *   [ pool 7 ]
 *      BaseAddress = 192.168.168.1
 *      Size = 10
 *
 *   The above entry would allocate 192.168.168.1 - 192.168.168.11 to incoming
 *   NAI users.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <conflib.h>
#include "mipagentconfig.h"
#include "utils.h"
#include "pool.h"


static FuncEntry poolFunctions[] = {
	{ "BaseAddress", NULL, "BaseAddress", ipFunc, ipFunc, ipFunc, ipFunc },
	{ "Size", NULL, "Size", posIntFunc, posIntFunc, posIntFunc,
	    posIntFunc},
	{ NULL, NULL, NULL, NULL, NULL }
};



/*
 * Function: poolFunc
 *
 * Arguments: char *configFile, char *Section, char *Label, int command,
 *            int argc, char *argv[]
 *
 * Description: This function implements all the manipulation functions
 *		for the Pools.  All the functions used are generic ones in
 *              utils.c
 * Returns: int
 */
int
poolFunc(char *configFile, char *Section, char *Label, int command, int argc,
    char *argv[])
{
	char DestSection[MAX_SECTION_LEN];
	FuncEntry *funcEntry = NULL;
	int (*function)(char *, char *, char *, int, int, char **) = NULL;
	int value;

	/* Get rid of lint warnings about unused parameters */
	Section = Label;

	/* ARGV[0] should be the Number */
	if (argc < 1) {
		(void) fprintf(stderr,
		    gettext("Error: pool number was not specified.  "
		    "Please specify a Pool number.\n"));
		return (-1);
	}

	/* Build our Section */
	(void) sprintf(DestSection, "Pool %s", argv[0]);

	/*
	 * Now, verify that the label is valid.
	 */
	value = atoi(argv[0]);
	if (value <= 0) {
		(void) fprintf(stderr,
		    gettext("Error: SPI <%s> is not valid.\n"),
		    argv[0]);
		return (-1);
	}

	/* Finally, look up our functions and call them based on the dest */
	if (argc > 1) {
		funcEntry = getFunctions(poolFunctions, argv[1]);
		if (!funcEntry) {
			(void) fprintf(stderr,
			    gettext("Error: <%s> is not valid for <%s>.\n"),
			    argv[1], Command2Str(command));
			return (-1);
		}
	}

	/* Now check the particular function we need. */
	switch (command) {
	case Add:
		if (argc == 1) {
			/* A raw add Warn the user */
			(void) fprintf(stderr,
			    gettext("Warning: Pool will be created as "
			    "parameters are added.\n\tExample:"
			    "mipagentconfig add Pool 5 SPI 3\n"
			    "will add the Pool, and add the SPI to it.\n"));
			return (0);
		}
		function = funcEntry->addFunc;
		break;
	case Change:
		if (argc == 1) {
			(void) fprintf(stderr,
			    gettext("Error: cannot change the identifier "
			    "of an [Address <identifier>] section.  "
			    "Delete, and create a new section.\n"));
			return (-1);
		}
		function = funcEntry->changeFunc;
		break;
	case Delete:
		if (argc == 1) {
			return (DeletePrivateProfileSection(DestSection,
			    configFile));
		}
		function = funcEntry->deleteFunc;
		break;
	case Get:
		if (argc == 1) {
			sectionDump(configFile, DestSection,
			    poolFunctions);
			return (0);
		}
		function = funcEntry->getFunc;
		break;
	}

	if (!function) {
		(void) fprintf(stderr,
		    gettext("Error: %s does not support '%s'.\n"),
		    Command2Str(command), argv[0]);
		return (-1);
	}

	/* And finally, call function */
	return (function(configFile, DestSection, funcEntry->Label,
	    command, argc-2, &argv[2]));

} /* poolFunc */
