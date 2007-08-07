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
 * general.c -- General variable modification
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <conflib.h>
#include "mipagentconfig.h"
#include "utils.h"
#include "general.h"


/*
 * Function: logFunc
 *
 * Arguments: char *configFile, char *Section, char *Label, int command
 *            int argc, char *argv[]
 *
 * Description: This function implements all the manipulation functions
 *		for the logVerbosity key.
 *
 * Returns: int
 */
int
logFunc(char *configFile, char *Section, char *Label, int command,
    int argc, char *argv[])
{
	char buffer[MAX_VALUE_LEN] = {0};
	int rc;
	int LabelExists;
	char *validStrings[] = {
		"quiet",
		"low",
		"norm",
		"all",
		NULL
	};

	/* Check to see if label already exists */
	rc = GetPrivateProfileString(Section, Label, "", buffer,
	    MAX_VALUE_LEN-1, configFile);
	if (!rc)
		LabelExists = TRUE;
	else
		LabelExists = FALSE;

	switch (command) {
	case Add:
		/* Check to see if label already exists */
		if (LabelExists) {
			(void) fprintf(stderr,
			    gettext("Error: %s is already configured in [%s]:\n"
			    "\t%s = %s\n"),
			    Label, Section, Label, buffer);
			return (-1);
		}

		/* Now, check for the parameters. */
		if (argc != 1) {
			(void) fprintf(stderr,
			    gettext("Error: Must specify log level (one of: "));
			printValidStrings(validStrings);
			(void) fprintf(stderr, ").\n");
			return (-1);
		}

		if (!checkValidStrings(validStrings, argv[0])) {
			/* Add it! */
			rc = WritePrivateProfileString(Section, Label,
			    argv[0], configFile);
			if (rc) {
				(void) fprintf(stderr, "%s\n", ErrorString);
				return (rc);
			}
			return (0);
		} else {
			(void) fprintf(stderr,
			    gettext("Error: [%s] configuration for %s must be "
			    "one of ("), Section, Label);
			printValidStrings(validStrings);
			(void) fprintf(stderr, ").\n");
			return (-1);
		}
		break;


	case Delete:
		if (!LabelExists) {
			(void) fprintf(stderr,
			    gettext("Error: %s is not configured in [%s].\n"),
			    Label, Section);
			return (-1);
		}
		rc = DeletePrivateProfileLabel(Section, Label, configFile);
		if (rc)
			(void) fprintf(stderr, "Error: %s\n", ErrorString);

		return (rc);


	case Change:
		if (!LabelExists) {
			(void) fprintf(stderr,
			    gettext("Error: %s is not configured in [%s].\n"),
			    Label, Section);
			return (-1);
		}

		/* Now, check for the parameters. */
		if (argc != 1) {
			(void) fprintf(stderr,
			    gettext("Error: log level was not specified.  "
			    "Please specify the desired log level.  "
			    "Valid log levels are one of ("));
			printValidStrings(validStrings);
			(void) fprintf(stderr, ").\n");
			return (-1);
		}

		if (!checkValidStrings(validStrings, argv[0])) {
			/* Change it! */
			rc = WritePrivateProfileString(Section, Label,
			    argv[0], configFile);
			if (rc) {
				(void) fprintf(stderr, "%s\n", ErrorString);
				return (rc);
			}
			return (0);
		} else {
			(void) fprintf(stderr,
			    gettext("Error: Log level %s is not supported.  "
			    "Log level must be one of ("),
			    argv[0]);
			printValidStrings(validStrings);
			(void) fprintf(stderr, ").\n");
			return (-1);
		}
		break;

	case Get:
		if (!LabelExists) {
			(void) fprintf(stderr,
			    gettext("Error: %s is not configured in [%s].\n"),
			    Label, Section);
			return (-1);
		}
		(void) printf(gettext("[%s]\n\t%s = %s\n"),
		    Section, Label, buffer);
		return (0);
		break;

	default:
		(void) fprintf(stderr,
		    gettext("Error: Invalid command code!\n"));
		return (-1);
	} /* switch (command) */
} /* logFunc */
