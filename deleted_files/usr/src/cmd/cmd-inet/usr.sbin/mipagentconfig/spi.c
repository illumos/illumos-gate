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
 * spi.c - Functions to manipulate Security parameters.
 *
 *    Example of good entry:
 *
 *   [ spi 7 ]
 *      Key = 0123456789abcdef0123456789abcdef
 *      replayMethod = timestamps
 *
 *   The above entry would allocate a SPI with the provided key and replay
 *   method.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <conflib.h>
#include "mipagentconfig.h"
#include "utils.h"
#include "spi.h"

/* Private Prototypes */
static int spiKeyFunc(char *, char *, char *, int, int, char **);
static int spiReplayFunc(char *, char *, char *, int, int, char **);


static FuncEntry spiFunctions[] = {
	{ "key", NULL, "Key", spiKeyFunc, spiKeyFunc, spiKeyFunc, spiKeyFunc },
	{ "replayMethod", NULL, "replayMethod", spiReplayFunc, spiReplayFunc,
	    spiReplayFunc, spiReplayFunc},
	{ NULL, NULL, NULL, NULL, NULL }

};


/*
 * Function: spiFunc
 *
 * Arguments: char *configFile, char *Section, char *Label, int command,
 *            int argc, char *argv[]
 *
 * Description: This function implements all the manipulation functions
 *		for the SPI sections.
 *
 * Returns: int
 */
int
spiFunc(char *configFile, char *Section, char *Label, int command, int argc,
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
		    gettext("Error: SPI value was not specified.  "
		    "Please specify the SPI number.\n"));
		return (-1);
	}

	/*
	 * Now, verify that the label is valid.
	 */
	value = atoi(argv[0]);
	if (value <= 0) {
		(void) fprintf(stderr,
		    gettext("Error: <%s> is not a valid SPI.\n"),
		    argv[0]);
		return (-1);
	}

	/* Build our Section */
	(void) sprintf(DestSection, "SPI %s", argv[0]);

	/* Finally, look up our functions and call them based on the dest */
	if (argc > 1) {
		funcEntry = getFunctions(spiFunctions, argv[1]);
		if (!funcEntry) {
			(void) fprintf(stderr,
			    gettext("Error: <%s> is not valid "
			    "for '%s' command.\n"),
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
			    gettext("Warning: SPI will need to be created as "
			    "parameters are added.\n\tExample: "
			    "mipagentconfig add SPI 5 key 123456\n"
			    "will add the SPI, and add the key to it.\n"));
			return (0);
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
			    spiFunctions);
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

} /* spiFunc */


/*
 * Function: spiKeyFunc
 *
 * Arguments: char *configFile, char *Section, char *Label, int command
 *            int argc, char *argv[]
 *
 * Description: This function will get and validate an spi key.
 *
 * Returns: int
 */
static int
spiKeyFunc(char *configFile, char *Section, char *Label, int command,
    int argc, char *argv[])
{
	char buffer[MAX_VALUE_LEN] = {0};
	int rc, LabelExists;

	/* Check to see if label already exists */
	rc = GetPrivateProfileString(Section, Label, "", buffer,
	    MAX_VALUE_LEN-1, configFile);
	if (!rc)
		LabelExists = TRUE;
	else
		LabelExists = FALSE;

	switch (command) {
	case Add:
		/* Now, check for the parameters. */
		if (argc != 1) {
			(void) fprintf(stderr,
			    gettext("Error: the SPI value wasn't specified.  "
			    "Please specify a value.\n"));
			return (-1);
		}
		if (LabelExists) {
			(void) fprintf(stderr,
			    gettext("Error: %s is already configured in [%s]:\n"
			    "\t%s = %s\n"),
			    Label, Section, Label, buffer);
			return (-1);
		}
		if (hexValid(argv[0])) {
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
			    gettext("Error: value must be a valid "
			    "hexadecimal string.\n"));
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
			    gettext("Error: the new value wasn't specified.  "
			    "Please specify a value to change %s to.\n"),
			    Label);
			return (-1);
		}

		if (!LabelExists) {
			(void) fprintf(stderr,
			    gettext("Error: %s is not configured in [%s].\n"),
			    Section, Label);
			return (-1);
		}

		if (hexValid(argv[0])) {
			/* Add it! */
			rc = WritePrivateProfileString(Section, Label,
			    argv[0], configFile);
			if (rc) {
				(void) fprintf(stderr,
				    "%s\n", ErrorString);
				return (rc);
			}
			return (0);
		} else {
			(void) fprintf(stderr,
			    gettext("Error: SPI value must be a valid "
			    "hexadecimal string.\n"));
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
		(void) printf(gettext("[%s]\n\t%s = 0x%s\n"),
		    Section, Label, buffer);
		return (0);
		break;

	default:
		(void) fprintf(stderr,
		    gettext("Error: Invalid command code!\n"));
		return (-1);
	} /* switch (command) */


} /* spiKeyFunc */

/*
 * Function: spiReplayFunc
 *
 * Arguments: char *configFile, char *Section, char *Label, int command
 *            int argc, char *argv[]
 *
 * Description: This function sets the SPI replay function to one of the
 *              allowed values.
 *
 * Returns: int
 */
static int
spiReplayFunc(char *configFile, char *Section, char *Label, int command,
    int argc, char *argv[])
{
	char buffer[MAX_VALUE_LEN] = {0};
	int rc, LabelExists;
	char *validStrings[] = {
		"timestamps",
		"none",
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
		/* Now, check for the parameters. */
		if (argc != 1) {
			(void) fprintf(stderr,
			    gettext("Usage: add spi <value> replayMethod <type>"
			    "\n\tWhere <type> is one of ("));
			printValidStrings(validStrings);
			(void) fprintf(stderr, ").\n");
			return (-1);
		}

		if (LabelExists) {
			(void) fprintf(stderr,
			    gettext("Error: %s is already configured in [%s]:\n"
			    "\t%s = %s\n"),
			    Label, Section, Label, buffer);
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
			    gettext("Error: replay method must be one of ("));
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
			    gettext("Usage: "
			    "change spi <value> replayMethod <type>\n"
			    "\tWhere <type> is one of ("));
			printValidStrings(validStrings);
			(void) fprintf(stderr, ").\n");
			return (-1);
		}

		if (!LabelExists) {
			(void) fprintf(stderr,
			    gettext("Error: %s is not configured in [%s].\n"),
			    Label, Section);
			return (-1);
		}

		if (!checkValidStrings(validStrings, argv[0])) {
			/* Add it! */
			rc = WritePrivateProfileString(Section, Label,
			    argv[0], configFile);
			if (rc) {
				(void) fprintf(stderr,
				    "%s\n", ErrorString);
				return (rc);
			}
			return (0);
		} else {
			(void) fprintf(stderr,
			    gettext("Error: replay method must be one of ("));
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


} /* spiReplayFunc */
