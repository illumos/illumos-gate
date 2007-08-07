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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * utils.c -- Generic variable modification functions
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <conflib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "utils.h"

static int strFunc(char *configFile, char *Section, char *Label, int command,
    int argc, char *argv[], char *validStrings[], char *usageString);

/*
 * Function: ynFunc
 *
 * Arguments: char *configFile, char *Section, char *Label, int command
 *            int argc, char *argv[]
 *
 * Description: This function implements all the manipulation functions
 *		for any yes no options
 *
 * Returns: int
 */
int
ynFunc(char *configFile, char *Section, char *Label, int command,
    int argc, char *argv[])
{
	char *validStrings[] = {
		"yes",
		"no",
		NULL
	};
	char *usageString = " (yes or no)";

	return (strFunc(configFile, Section, Label, command, argc, argv,
	    validStrings, usageString));

} /* ynFunc */

/*
 * Function: fhFunc
 *
 * Arguments: char *configFile, char *Section, char *Label, int command
 *            int argc, char *argv[]
 *
 * Description: This function implements all the manipulation functions
 *		for any no/neither, fa, ha, both/yes options
 *
 * Returns: int
 */
int
fhFunc(char *configFile, char *Section, char *Label, int command,
    int argc, char *argv[])
{
	char *validStrings[] = {
		"yes",
		"both",
		"ha",
		"fa",
		"neither",
		"no",
		NULL
	};
	char *usageString = " (yes|both, ha, fa, neither|no)";

	return (strFunc(configFile, Section, Label, command, argc, argv,
	    validStrings, usageString));

} /* fin fhFunc() */


/*
 * Function: strFunc
 *
 * Arguments: char *configFile, char *Section, char *Label, int command,
 *            int argc, char *argv[], char *validStrings[], char *usageString
 *
 * Description: This function is called by wrapper functions needing to
 *              validate, and manipulate string data.  It compares the
 *              user-setting to  validStrings, then either returning
 *              usageString, passed in by each wrapper depending on the
 *              acceptable settings, or performing command appropriately.
 *
 * Note: Due to internationalization issues, this function can not print
 *       usage messages, etc, to the console - there are too many possible
 *       string combinations to consider.  The wrapper functions, therefore,
 *       spit out there own usage functions on error.
 *
 * Return: 0 on success
 *        -1 on error
 */
static int
strFunc(char *configFile, char *Section, char *Label, int command, int argc,
    char *argv[], char *validStrings[], char *usageString)
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
			    gettext("Error: invalid configuration for %s.  "
			    "Please specify any of: %s.\n"),
			    Label, gettext(usageString));
			return (-1);
		}
		/* Now, check to make sure the item isn't already here */
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
			    gettext("Error: value must be one of ("));
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
			(void) fprintf(stderr,
			    "Error: %s\n", ErrorString);
		}
		return (rc);
		break;


	case Change:
		/* Now, check for the parameters. */
		if (argc != 1) {
			(void) fprintf(stderr,
			    gettext("Error: new value for %s unspecified.  "
			    "Please specify any of: %s.\n"),
			    Label, gettext(usageString));
			return (-1);
		}

		if (!LabelExists) {
			(void) fprintf(stderr,
			    gettext("Error: %s is not configured in [%s].\n"),
			    Label, Section);
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
			    gettext("Error: value must be one of ("));
			printValidStrings(validStrings);
			(void) fprintf(stderr, ").\n");
			return (-1);
		}
		break;

	case Get:
		rc = GetPrivateProfileString(Section, Label, "",
		    buffer, MAX_VALUE_LEN-1, configFile);
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

} /* strFunc */

/*
 * Function: posIntFunc
 *
 * Arguments: char *configFile, char *Section, char *Label, int command,
 *            int argc, char *argv[]
 *
 * Description: This function implements all the manipulation functions
 *		for any positive integer functions.
 *
 * Returns: int
 */
int
posIntFunc(char *configFile, char *Section, char *Label, int command, int argc,
    char *argv[])
{
	char buffer[MAX_VALUE_LEN] = {0};
	int rc, LabelExists;
	int value;

	/* Check to see if label already exists */
	rc = GetPrivateProfileString(Section, Label, "", buffer,
	    MAX_VALUE_LEN-1, configFile);
	if (!rc)
		LabelExists = TRUE;
	else
		LabelExists = FALSE;

	switch (command) {
	case Add:
		/* Check for the parameters. */
		if (argc != 1) {
			(void) fprintf(stderr,
			    gettext("Error: value for %s was not specified.  "
			    "Please specify value.\n"), Label);
			return (-1);
		}

		/* Now, check to make sure it is not already here */
		if (LabelExists) {
			(void) fprintf(stderr,
			    gettext("Error: %s is already configured in [%s].\n"
			    "\tvalue = %s\n"),
			    Label, Section, Label, buffer);
			return (-1);
		}
		value = atoi(argv[0]);
		if (value > 0) {
			/* Add it! */
			rc = WritePrivateProfileInt(Section, Label,
			    value, configFile);
			if (rc) {
				(void) fprintf(stderr, "%s\n", ErrorString);
				return (rc);
			}
			return (0);
		} else {
			(void) fprintf(stderr,
			    gettext("Error: value must be a positive,"
			    " non-zero integer.\n"));
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
		break;


	case Change:
		/* Now, check for the parameters. */
		if (argc != 1) {
			(void) fprintf(stderr,
			    gettext("Error: New value for %s was not specified."
			    "  Please specify a value.\n"));
			return (-1);
		}

		if (!LabelExists) {
			(void) fprintf(stderr,
			    gettext("Error: %s is not configured in [%s].\n"),
			    Label, Section);
			return (-1);
		}

		value = atoi(argv[0]);

		if (value > 0) {
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
			    gettext("Error: value must be a positive,"
			    " non-zero integer.\n"));
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
} /* posIntFunc */

/*
 * Function: ipFunc
 *
 * Arguments: char *configFile, char *Section, char *Label, int command,
 *            int argc, char *argv[]
 *
 * Description: This function implements all the manipulation functions
 *		for any ip numbers or masks
 *
 * Returns: int
 */
int
ipFunc(char *configFile, char *Section, char *Label, int command, int argc,
    char *argv[])
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
		/* Check for the parameters. */
		if (argc != 1) {
			(void) fprintf(stderr,
			    gettext("Error: value for %s was not specified.  "
			    "Please specify a value.\n"), Label);
			return (-1);
		}

		if (LabelExists) {
			(void) fprintf(stderr,
			    gettext("Error: %s is already configured in [%s]:\n"
			    "\tvalue = %s\n"),
			    Label, Section, Label, buffer);
			return (-1);
		}


		if (ipValid(argv[0])) {
			/* Add it! */
			rc = WritePrivateProfileString(Section, Label, argv[0],
			    configFile);
			if (rc) {
				(void) fprintf(stderr, "%s\n", ErrorString);
				return (rc);
			}
			return (0);
		} else {
			(void) fprintf(stderr,
			    gettext("Error: %s is not a valid IP address.\n"),
			    argv[0]);
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
		break;


	case Change:
		/* Now, check for the parameters. */
		if (argc != 1) {
			(void) fprintf(stderr,
			    gettext("Error: new value for %s was not specified."
			    "   Please specify a value.\n"), Label);
			return (-1);
		}

		if (!LabelExists) {
			(void) fprintf(stderr,
			    gettext("Error: %s is not configured in [%s].\n"),
			    Label, Section);
			return (-1);
		}

		if (ipValid(argv[0])) {
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
			    gettext("Error: %s is not a valid IP address.\n"),
			    argv[0]);
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

} /* ipFunc */

/*
 * Function: getFunctions
 *
 * Arguments: FunctionArray, string
 *
 * Description: This routine returns the func entry structure associated
 *		with the dest named, "string"
 *
 * Returns: FuncEntry
 *
 */
FuncEntry *
getFunctions(FuncEntry Funcs[], char *string)
{
	int i;
	for (i = 0; Funcs[i].tag; i++)
		if (!strcasecmp(string, Funcs[i].tag)) {
			return (&Funcs[i]);
		}
	return (NULL);
} /* getFunctions */



/*
 * Function: Str2Command
 *
 * Arguments: string
 *
 * Description: This routine returns the command associated
 *		with the command string, "string"
 *
 * Returns: Command
 *
 */
Command
Str2Command(char *string)
{
	extern CommandTable Commands[];
	int i;
	for (i = 0; Commands[i].string; i++)
		if (!strcasecmp(string, Commands[i].string)) {
			return (Commands[i].command);
		}
	return (-1);
} /* Str2Command */

/*
 * Function: Command2Str
 *
 * Arguments: command
 *
 * Description: This function translates a command into a string.
 *
 * Returns: char *
 *
 */
char *
Command2Str(Command cmd)
{
	extern CommandTable Commands[];
	CommandTable *item;
	for (item = Commands; item->string; item++)
		if (item->command == cmd)
			return (item->string);
	return ("Unknown");
} /* Command2Str */


/*
 * Function: sectionDump
 *
 * Arguments: configFile, Section, funcs
 *
 * Description: This funciton will dump the value of particular
 *              labels (Funcs) in the given section.
 *
 * Returns: void
 *
 */
void
sectionDump(char *configFile, char *Section, FuncEntry Funcs[])
{
	int i;
	int rc;
	char buffer[MAX_VALUE_LEN] = {0};

	(void) printf(gettext("[%s]\n"), Section);
	for (i = 0; Funcs[i].tag; i++) {
		rc = GetPrivateProfileString(Section, Funcs[i].Label, "",
		    buffer, MAX_VALUE_LEN-1, configFile);
		/* If the item was there, and it was not null, then print it */
		if (!rc && *buffer) {
			(void) printf(gettext("\t%s = %s\n"),
			    Funcs[i].Label, buffer);
		}
	}
} /* sectionDump */

/*
 * Function: checkValidStrings
 *
 * Arguments: validStrings, string
 *
 * Description: This function returns zero if the passed in string
 *              is in validStrings.
 *
 * Returns: int
 *
 */
int
checkValidStrings(char *validStrings[], char *string)
{
	char *probe;
	int i = 0;

	for (probe = validStrings[i]; probe; probe = validStrings[++i])
		if (!strcasecmp(probe, string))
			return (0);

	return (-1);
} /* checkValidStrings */


/*
 * Function: printValidStrings
 *
 * Arguments: validStrings
 *
 * Description: This routine prints out the valid strings for
 *              display messages.
 *
 * Returns: void
 *
 */
void
printValidStrings(char *validStrings[])
{
	char *probe;
	int i = 0;

	for (probe = validStrings[i]; probe; probe = validStrings[++i])
		(void) fprintf(stderr, "%s ", probe);

} /* printValidStrings */


/*
 * Function: ipValid
 *
 * Arguments: ipString
 *
 * Description: This function returns true if the string is valid.
 *              TODO: Use inet_pton to validate string.
 *
 * Returns: int
 *
 */
int
ipValid(char *ipString)
{
#if 0
	uint32_t in_addr;

	in_addr = inet_pton(ipString);
	(void) fprintf(stderr, "DEBUG: inet_pton(\"%s\") =0x%08x\n",
	    ipString, in_addr);
	return (-1);
#else

	int a, b, c, d;
	int rc;

	rc = sscanf(ipString, "%d.%d.%d.%d", &a, &b, &c, &d);
	/* Check the parsing */
	if (rc != 4)
		return (0);

	/* Check the bounds of each number */
	if ((a < 0 || a > 255) ||
	    (b < 0 || b > 255) ||
	    (c < 0 || c > 255) ||
	    (d < 0 || d > 255))
		return (0);

	/* otherwise, it's valid */
	return (1);
#endif
} /* ipValid */


/*
 * Function: naiValid
 *
 * Arguments: string
 *
 * Description: This function returns true if the strings looks like
 *              a valid NAI.
 *              TODO: use RFC to validate NAI.
 *
 * Returns: int
 *
 */
int
naiValid(char *ipString)
{
	int atFound = FALSE;

	/*
	 * Walk through the string, checking for at least one at,
	 * and no wierd characters.
	 */

	for (; *ipString; ipString++) {
		if (*ipString == '@') {
			if (atFound) {
				/* Error: two @ symbols! */
				return (0);
			} else {
				atFound = TRUE;
			}
			continue; /* to keep the if from nesting */
		}
		if (isspace(*ipString))
			return (0);
	}

	if (atFound)
		return (1); /* Success! */
	else
		return (0);
} /* naiValid */

/*
 * Function: hexCheck
 *
 * Arguments: string
 *
 * Description: Check the string to make sure it is a valid Hex string
 *
 * Returns: int
 *
 */
int
hexValid(char *string)
{
	if (strlen(string) % 2) {
		(void) fprintf(stderr,
			gettext("Error: hex string must be of even length.\n"));
		return (0);
	}

	for (; *string; string++) {
		if (!isxdigit(*string))
			return (0);
	}
	return (1);
} /* hexValid */


/*
 * Function: addEmptySection
 *
 * Arguments: char *configFile, char *SectionName
 *
 * Description: This routine will add an empty section to a config file,
 *              by creating a section with a dummy label, then deleting
 *              the label.  NOTE:  If the section already exists, this
 *              function is a NOP.  Also, if the label "DummyLabel"
 *              already exists in the section, it will be deleted as a side
 *              effect.
 *
 * Returns: int
 *
 */
int
addEmptySection(char *configFile, char *Section)
{
	int rc;
	char *Label = "DummyLabel";
	char *Value = "DummyValue";

	rc = WritePrivateProfileString(Section, Label, Value, configFile);
	if (rc) {
		(void) fprintf(stderr, "Error: %s\n", ErrorString);
		return (1);
	}
	rc = DeletePrivateProfileLabel(Section, Label, configFile);
	if (rc) {
		(void) fprintf(stderr, "Error: %s\n", ErrorString);
		return (1);
	}
	return (0);
} /* addEmptySection */
