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
 * Copyright (c) 1999-2002 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Functions to manipulate advertisements
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <conflib.h>
#include "mipagentconfig.h"
#include "utils.h"
#include "advertisements.h"


static FuncEntry advFunctions[] = {
	{ "advLifeTime", NULL, "advLifeTime", posIntFunc, posIntFunc,
	    posIntFunc, posIntFunc},
	{ "regLifeTime", NULL, "regLifeTime", posIntFunc, posIntFunc,
	    posIntFunc, posIntFunc},
	{ "advFrequency", NULL, "advFrequency", posIntFunc, posIntFunc,
	    posIntFunc, posIntFunc},
	{ "homeAgent", NULL, "homeAgent", ynFunc, ynFunc, ynFunc, ynFunc},
	{ "foreignAgent", NULL, "foreignAgent", ynFunc, ynFunc, ynFunc,
	    ynFunc},
	{ "prefixLengthExt", NULL, "prefixLengthExt", ynFunc, ynFunc, ynFunc,
	    ynFunc},
	{ "reverseTunnel", NULL, "reverseTunnel", fhFunc, fhFunc, fhFunc,
	    fhFunc},
	{ "reverseTunnelRequired", NULL, "reverseTunnelRequired", fhFunc,
	    fhFunc, fhFunc, fhFunc},
	{ "advInitCount", NULL, "advInitCount", posIntFunc, posIntFunc,
	    posIntFunc, posIntFunc},
	{ "advLimitUnsolicited", NULL, "advLimitUnsolicited", ynFunc,
	    ynFunc, ynFunc, ynFunc},
	{ NULL, NULL, NULL, NULL, NULL }
};

/*
 * Function: advFunc
 *
 * Arguments: char *configFile, char *Section, char *Label, int command,
 *            int argc, char *argv[]
 *
 * Description: This function implements all the manipulation functions
 *		for the advertisements sections
 *
 * Returns: int
 */
int
advFunc(char *configFile, char *Section, char *Label, int command, int argc,
    char *argv[])
{
	char DestSection[MAX_SECTION_LEN];
	FuncEntry *funcEntry = NULL;
	int (*function)(char *, char *, char *, int, int, char **) = NULL;

	/* Get rid of lint warnings about unused parameters */
	Section = Label;

	/* ARGV[0] should be the interface */
	if (argc < 1) {
		(void) fprintf(stderr,
		    gettext("Error: advertisement interface not specified.  "
		    "Please specify the interface name.\n"));
		return (-1);
	}

	/* Build our Section */
	(void) sprintf(DestSection, "Advertisements %s", argv[0]);

	/* Finally, look up our functions and call them based on the dest */
	if (argc > 1) {
		funcEntry = getFunctions(advFunctions, argv[1]);
		if (!funcEntry) {
			(void) fprintf(stderr,
			    gettext("Error: %s does not support '%s'.\n"),
			    Command2Str(command), argv[1]);
			return (-1);
		}
	}

	/* Now check the particular function we need. */
	switch (command) {
	case Add:
		if (argc == 1) {
			/*
			 * A raw add.  Add an empty section by adding
			 * a lable, then deleting it.
			 */
			return (addEmptySection(configFile, DestSection));
		}
		function = funcEntry->addFunc;
		break;
	case Change:
		if (argc == 1) {
			(void) fprintf(stderr,
			    gettext("Error: cannot change the identifier of an "
			    "Address section.  Delete, and make a new one.\n"));
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
			    advFunctions);
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

} /* advFunc */
