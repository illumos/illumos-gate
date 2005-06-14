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
 * This source file contains functions that manupilate addresses.  Addresses
 * are sections in the config file that look like:
 *
 * [ Address xxx.xxx.xxx.xxx ] or [ Address foo@bar.com ]
 * Type = agent
 * SPI = 23
 * Pool = 7
 *
 * Valid for "type = agent" entries ONLY (making these valid for type=node
 * should be fairly easy):
 * IPSecRequest = apply <properties> : permit <properties>
 * IPSecReply = apply <properties> : permit <properties>
 * IPSecTunnel = apply <properties> : permit <properties>
 * IPSecReverseTunnel = apply <properties> : permit <properties>
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <conflib.h>
#include <sys/types.h>
#include "mipagentconfig.h"
#include "utils.h"
#include "addr.h"

/* Private Prototypes */
static int addrTypeFunc(char *, char *, char *, int, int, char **);
static int ipsecFunc(char *, char *, char *, int, int, char **);

/*
 * This is the function table for the Addresses.  All of the addresses
 * use general functions found in utils.c, except the Type.
 */
static FuncEntry addrFunctions[] = {
	/* TAG, Section, Label, AddFunc, ChangeFunc, DeleteFunc, GetFunc */
	{ "SPI", NULL, "SPI", posIntFunc, posIntFunc, posIntFunc, posIntFunc},
	{ "Pool", NULL, "Pool", posIntFunc, posIntFunc, posIntFunc, posIntFunc},
	{ "Type", NULL, "Type", addrTypeFunc, addrTypeFunc, addrTypeFunc,
	    addrTypeFunc},
	{ "IPSecRequest", NULL, "IPSecRequest", ipsecFunc, ipsecFunc,
	    ipsecFunc, ipsecFunc},
	{ "IPSecReply", NULL, "IPSecReply", ipsecFunc, ipsecFunc, ipsecFunc,
	    ipsecFunc},
	{ "IPSecTunnel", NULL, "IPSecTunnel", ipsecFunc, ipsecFunc, ipsecFunc,
	    ipsecFunc},
	{ "IPSecReverseTunnel", NULL, "IPSecReverseTunnel", ipsecFunc,
	    ipsecFunc, ipsecFunc, ipsecFunc},
	{ NULL, NULL, NULL, NULL, NULL }
};


/*
 * Function: addrFunc
 *
 * Arguments: char *configFile, char *Section, char *Label, int command
 *            int argc, char *argv[]
 * Description: This function will take apart the argc/argv array, check the
 *              number of parameters, and call the appropriate function
 *              based on the command code.
 *
 * Returns: int  (zero on success)
 */
int
addrFunc(char *configFile, char *Section, char *Label, int command,
    int argc, char *argv[])
{
	char DestSection[MAX_SECTION_LEN];
	FuncEntry *funcEntry = NULL;
	int (*function)(char *, char *, char *, int, int, char **) = NULL;
	char *validStrings[] = {
		"Node-Default",
		NULL
	};

	/* Use Section and label to get rid of lint warnings */
	Section = Label;

	/* ARGV[0] should be the Address */
	if (argc < 1) {
		(void) fprintf(stderr,
		    gettext("Error: address identifier was not specified.  "
		    "Please specify an identifier for the Address section.  "
		    "Identifiers are either a valid IP address, an NAI "
		    "(e.g. bob@domain.com), or "));
		printValidStrings(validStrings);
		(void) fprintf(stderr, ".\n");
		return (-1);
	}

	/* Validate Address */
	if (!ipValid(argv[0]) && !naiValid(argv[0])) {
		/* Ok not a valid address, check for Defaults */
		if (checkValidStrings(validStrings, argv[0])) {
			(void) fprintf(stderr,
			    gettext("Error: invalid identifier for "
			    "Address section.  Identifier must "
			    "be a valid IP address, a valid NAI "
			    "(e.g. bob@domain.com), or "));
			printValidStrings(validStrings);
			(void) fprintf(stderr, ".\n");
			return (-1);
		}
	}

	/* Build our Section */
	(void) sprintf(DestSection, "Address %s", argv[0]);

	/* Finally, look up our functions and call them based on the dest */
	if (argc > 1) {
		funcEntry = getFunctions(addrFunctions, argv[1]);
		if (!funcEntry) {
			(void) fprintf(stderr,
			    gettext("Error: command '%s' is not valid "
			    "for %s.\n"),
			    Command2Str(command), argv[1]);
			return (-1);
		}
	}

	/* Now check the particular function we need. */
	switch (command) {
	case Add:
		if (argc == 1) {
			/* A raw add Warn the user */
			(void) fprintf(stderr,
			    gettext("Warning: attributes will be created as "
			    "parameters are added.\n  Example: "
			    "mipagentconfig add addr 192.168.168.1 SPI 5\n "
			    "will add the address, and add the SPI "
			    "configuration to it.\n"));
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
			return DeletePrivateProfileSection(DestSection,
			    configFile);
		}
		function = funcEntry->deleteFunc;
		break;
	case Get:
		if (argc == 1) {
			sectionDump(configFile, DestSection,
			    addrFunctions);
			return (0);
		}
		function = funcEntry->getFunc;
		break;
	}

	/* Print error if this function is not allowed (null in table) */
	if (!function) {
		(void) fprintf(stderr,
		    gettext("Error: <%s> is not valid for '%s' command.\n"),
		    argv[0], Command2Str(command));
		return (-1);
	}

	/* And finally, call function */
	return (function(configFile, DestSection, funcEntry->Label,
	    command, argc-2, &argv[2]));

} /* addrFunc */

/*
 * Function: addrTypeFunc
 *
 * Arguments: char *configFile, char *Section, char *Label, int command
 *            int argc, char *argv[]
 * Description: This function verifys the Type option in address sections.
 *
 * Returns: int
 */
static int
addrTypeFunc(char *configFile, char *Section, char *Label, int command,
    int argc, char *argv[])
{
	char  buffer[MAX_VALUE_LEN];
	int  rc, LabelExists;
	char *validStrings[] = {
		"Agent",
		"Node",
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
			    gettext("Error: entry type wasn't specified.  "
			    "Please specify the type of entry for [%s].  "
			    "The type must be one of ("), Section);
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
			    gettext("Error: Address type must be one of ("));
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
			    gettext("Error: entry type wasn't specified.  "
			    "Please specify the type [%s] is to be changed to."
			    "  Valid types are one of ("), Section);
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
			    gettext("Error: type must be one of ("));
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
} /* addrTypeFunc */


/*
 * Function: iposecFunc()
 *
 * Arguments: char *configFile, char *Section, char *Label, int command
 *            int argc, char *argv[]
 * Description: This function verifys the ipsec properties.
 *
 * Returns: int
 */
static int
ipsecFunc(char *configFile, char *Section, char *Label, int command,
    int argc, char *argv[])
{
	char buffer[MAX_VALUE_LEN], pbuf[MAX_VALUE_LEN] = "",
	    *policy, *policyP;
	int  rc, LabelExists;
	extern char *validIPsecAction[];

	/* Check to see if label already exists */
	rc = GetPrivateProfileString(Section, Label, "", buffer,
	    MAX_VALUE_LEN-1, configFile);
	if (!rc)
		LabelExists = TRUE;
	else
		LabelExists = FALSE;

	/*
	 * mipagentconfig differs from mipagent here in that the configuration
	 * is broken into argv[]'s, where as when we read this in mipagent it
	 * comes in one string.  For the sake of common code, we put all the
	 * argv[]'s into one buffer
	 */
	for (rc = 0; rc < argc; rc++) {
		(void) strcat(pbuf, argv[rc]);
		(void) strcat(pbuf, " ");
	}

	switch (command) {
	case Add:
		/* what are we adding? */
		if (argc < 2) {
			/*
			 * Must have at least "<action> {<property>}" = 2.
			 * Then again, "<action> {<<tag> <alg>>} = 3...
			 */
			(void) fprintf(stderr,
			    gettext("Error: IPsec policy is incomplete.  "
			    "Please specify the complete IPsec policy.  "
			    "See ipsec(7p).\n"));
			return (-1);
		}

		if (LabelExists) {
			(void) fprintf(stderr,
			    gettext("Error: %s is already configured in [%s]:\n"
			    "\t%s = %s\n"),
			    Label, Section, Label, buffer);
			return (-1);
		}

		/*
		 * Determine if this is a valid policy.  Note: we have to do
		 * this one IPsec Policy at a time.
		 */
		policy = strdup(pbuf);
		policyP = policy;   /* strtok() is destructive */

		while ((policy = strtok(policy, IPSP_SEPARATOR)) != NULL) {
			if (isIPsecPolicyValid(policy, NULL) != TRUE) {
				(void) fprintf(stderr,
				    gettext("Error: policy %s is not valid  "
				    "Policy may only contain <"), policy);
				(void) printValidStrings(validIPsecAction);
				(void) fprintf(stderr,
				    gettext("> as actions, and valid IPsec"
				    "<properties>.  See ipsec(7P).\n"));
				return (-1);
			}
			policy = NULL;
		}

		free(policyP);

		/* Checks out, so add it */
		rc = WritePrivateProfileString(Section, Label, pbuf,
		    configFile);

		if (rc) {
			(void) fprintf(stderr, "%s\n", ErrorString);
			return (rc);
		}

		return (0);


	case Delete:
		if (!LabelExists) {
			(void) fprintf(stderr,
			    gettext("Error: %s is not configured in [%s].\n"),
			    Label, Section);
			return (-1);
		}

		rc = DeletePrivateProfileLabel(Section, Label, configFile);
		if (rc)
			(void) fprintf(stderr, "%s\n", ErrorString);
		return (rc);


	case Change:
		if (argc < 2) {
			/* must have at least "<action> {<properties>}" = 2 */
			(void) fprintf(stderr,
			    gettext("Error: IPsec Policy incomplete.  "
			    "Please specify the complete new IPsec Policy.  "
			    "See ipsec(7P).\n"));
			return (-1);
		}

		if (!LabelExists) {
			(void) fprintf(stderr,
			    gettext("Error: %s is not configured in [%s].\n"),
			    Label, Section);
			return (-1);
		}

		/*
		 * Is the format of this setting valid?  Note: we have to do
		 * this one IPsec Policy at a time.
		 */
		policy = strdup(pbuf);
		policyP = policy;   /* strtok() is destructive */

		while ((policy = strtok(policy, IPSP_SEPARATOR)) != NULL) {
			if (isIPsecPolicyValid(policy, NULL) != TRUE) {
				(void) fprintf(stderr,
				    gettext("Error: %s is not a valid IPsec "
				    "policy.  Policy may only contain <"),
				    policy);
				(void) printValidStrings(validIPsecAction);
				(void) fprintf(stderr,
				    gettext("> as actions, and valid IPsec "
				    "<properties>.  See ipsec(7P).\n"));
				return (-1);
			}
			policy = NULL;
		}

		free(policyP);

		/* Checks out, so change it */
		rc = WritePrivateProfileString(Section, Label, pbuf,
		    configFile);

		if (rc) {
			(void) fprintf(stderr, "%s\n", ErrorString);
			return (rc);
		}

		return (0);


	case Get:
		if (!LabelExists) {
			(void) fprintf(stderr,
			    gettext("Error: %s is not configigured in [%s].\n"),
			    Label, Section);
			return (-1);
		}
		(void) printf(gettext("[%s]\n\t%s = %s\n"),
		    Section, Label, buffer);
		return (0);


	default:
		(void) fprintf(stderr,
		    gettext("Error: Invalid command code!\n"));
		return (-1);
	} /* switch (command) */
} /* ipsecFunc */
