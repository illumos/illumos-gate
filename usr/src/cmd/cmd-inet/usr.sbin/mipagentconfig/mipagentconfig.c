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
 * mipagentconfig.c
 *
 * This program is used to manipulate configuration files for mobile ip.
 * It is used as follows (for more info on usage, check the man page(s):
 *
 * foo$ mipagentconfig add address 192.168.168.10 SPI 7
 *
 * The parameters are: Command, destination, [values . . . ]
 *
 * For each command/destination, an entry is looked up in a function table, and
 * the appropriate function is called with the rest of the command line as
 * parameters.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <locale.h>
#include "mipagentconfig.h"
#include "utils.h"

#include "general.h"
#include "gsp.h"
#include "advertisements.h"
#include "spi.h"
#include "pool.h"
#include "addr.h"

/*
 * This is the string - to - enum table for command codes.
 */
CommandTable Commands[] = {
	{ "add", Add },
	{ "change", Change },
	{ "delete", Delete },
	{ "del", Delete },   /* for lazy typers */
	{ "get", Get },
	{ NULL, NULL }
};

/*
 * Function Notes:
 *
 *  The first parameter passed to all functions is the command.	 This
 *  is to allow the same function to be used for all commands, add
 *  change, delete or get.
 *
 *  You do not have to support all commands.  For any unsupported command,
 *  just use NULL.
 */
static FuncEntry Functions[] = {
	/* Lable or tag,  Section, SectionLabel, ADD, CHANGE, DELETE, GET */
	/* From general.h */
	{ "logVerbosity", "General", "logVerbosity", logFunc,
	    logFunc, logFunc, logFunc },
	{ "AdvertiseNAI", "General", "AdvertiseNAI", ynFunc, ynFunc, ynFunc,
	    ynFunc },
	/* from gsp.h */
	{ "HA-FAauth", "GlobalSecurityParameters", "HA-FAauth", ynFunc,
	    ynFunc, ynFunc, ynFunc },
	{ "MN-FAauth", "GlobalSecurityParameters", "MN-FAauth", ynFunc,
	    ynFunc, ynFunc, ynFunc },
	{ "Challenge", "GlobalSecurityParameters", "Challenge", ynFunc,
	    ynFunc, ynFunc, ynFunc },
	{ "maxClockSkew", "GlobalSecurityParameters", "maxClockSkew",
	    posIntFunc, posIntFunc, posIntFunc, posIntFunc },
	{ "keyDistribution", "GlobalSecurityParameters", "keyDistribution",
	    keyDistributionFunc, keyDistributionFunc, keyDistributionFunc,
	    keyDistributionFunc },
	{ "adv", NULL, NULL, advFunc, advFunc, advFunc, advFunc},
	{ "SPI", NULL, NULL, spiFunc, spiFunc, spiFunc, spiFunc},
	{ "Pool", NULL, NULL, poolFunc, poolFunc, poolFunc, poolFunc},
	{ "addr", NULL, NULL, addrFunc, addrFunc, addrFunc, addrFunc },
	{ NULL, NULL, NULL, NULL, NULL }
};

#define	USAGE "%s: [ -f configfile ] command dest [parameters . . .] \n"

#define	CONFIG_FILE "/etc/inet/mipagent.conf"

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	int c;
	char *configFile = CONFIG_FILE;
	int argsLeft;
	FuncEntry *funcEntry;
	Command command = Add;
	int (*function)(char *, char *, char *, int, int, char **) = NULL;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "f:?h")) != EOF) {
		switch (c) {
		case 'f' : /* Change the config file */
			configFile = optarg;
			break;
		case '?':
		case 'h': /* print usage */
			(void) fprintf(stderr, USAGE, argv[0]);
			return (0);
		}
	} /* while . . . getopt */

	argsLeft = argc-optind;

	if (argsLeft < 2) {
		(void) fprintf(stderr,
		    gettext("Error: Not enough arguments.\n"));
		(void) fprintf(stderr, USAGE, argv[0]);
		return (-1);
	}

	/* Now, Check the command */
	command = Str2Command(argv[optind]);
	if (command < 0) {
		(void) fprintf(stderr, gettext("Error: Invalid command <%s>\n"),
		    argv[optind]);
		(void) fprintf(stderr, USAGE, argv[0]);
		return (-1);
	}


	/* Finally, look up our functions and call them based on the dest */
	funcEntry = getFunctions(Functions, argv[optind+1]);

	if (funcEntry) {
		/* Now check the particular function we need. */
		switch (command) {
		case Add:
			function = funcEntry->addFunc;
			break;
		case Change:
			function = funcEntry->changeFunc;
			break;
		case Delete:
			function = funcEntry->deleteFunc;
			break;
		case Get:
			function = funcEntry->getFunc;
			break;
		}
	} else {
		(void) fprintf(stderr,
		    gettext("Error: <%s> is not valid for <%s>\n"),
		    argv[optind+1], argv[optind]);
		(void) fprintf(stderr, USAGE, argv[0]);
		return (-1);
	}

	if (!function) {
		(void) fprintf(stderr,
		    gettext("Error: %s does not support '%s'.\n"),
		    argv[optind+1], argv[optind]);
		(void) fprintf(stderr, USAGE, argv[0]);
		return (-1);
	}

	/* And finally, call function */
	return (function(configFile, funcEntry->Section, funcEntry->Label,
	    command, argsLeft-2, &argv[optind+2]));

} /* main */
