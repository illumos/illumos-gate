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
 * gsp.c -- GlobalSecurityParameters variable modification
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <conflib.h>
#include "mipagentconfig.h"
#include "utils.h"
#include "gsp.h"

/*
 * Function: keyDistributionFunc
 *
 * Arguments: configFile, command, arguments
 *
 * Description: This function sets the "keyDistribution" label of the
 *              GlobalSecurityParameters section.  The only valid value
 *              at this time is "files".  Eventually, we will allow some
 *              kind of external AAA to be configured here (diameter,
 *              RADIUS, SunDS, etc.)
 *
 * Returns: int
 *
 */
int
keyDistributionFunc(char *configFile, char *Section, char *Label, int command,
    int argc, char *argv[])
{
	char buffer[MAX_VALUE_LEN] = {0};
	int rc;
	int LabelExists;
	char *validStrings[] = {
		"files",
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
			    gettext("Usage: add keyDistribution <type>\n"
			    "\tWhere <type> is one of ("));
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
			    gettext("Error: keyDistribution must be one of ("));
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
		if (rc) {
			(void) fprintf(stderr, "%s\n", ErrorString);
			return (rc);
		}
		return (rc);
		break;


	case Change:
		/* Now, check for the parameters. */
		if (argc != 1) {
			(void) fprintf(stderr,
			    gettext("Usage: change keyDistribution <type>\n"
			    "<\tWhere <type> is one of ("));
			printValidStrings(validStrings);
			(void) fprintf(stderr, ").\n");
			return (-1);
		}

		if (!LabelExists) {
			(void) fprintf(stderr,
			    gettext("Error: %s is not configured in [%s].\n"),
			    Section, Label);
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
			    gettext("Error: keyDistribution must be one of ("));
			printValidStrings(validStrings);
			(void) fprintf(stderr, ").\n");
			return (-1);
		}
		break;

	case Get:
		rc = GetPrivateProfileString(Section, Label, "", buffer,
		    MAX_VALUE_LEN-1, configFile);
		if (rc) {
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
} /* keyDistributionFunc */
