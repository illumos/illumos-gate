/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <errno.h>
#include <zone.h>
#include <sasinfo.h>

#define	VERSION_STRING_MAX_LEN	10
/*
 * Version number:
 *  MAJOR - This should only change when there is an incompatible change made
 *  to the interfaces or the output.
 *
 *  MINOR - This should change whenever there is a new command or new feature
 *  with no incompatible change.
 */
#define	VERSION_STRING_MAJOR	    "1"
#define	VERSION_STRING_MINOR	    "0"

/* globals */
static char *cmdName;

/* forward declarations */
static int listHbaFunc(int, char **, cmdOptions_t *, void *);
static int listHbaPortFunc(int, char **, cmdOptions_t *, void *);
static int listExpanderFunc(int, char **, cmdOptions_t *, void *);
static int listTargetPortFunc(int, char **, cmdOptions_t *, void *);
static int listLogicalUnitFunc(int, char **, cmdOptions_t *, void *);
static char *getExecBasename(char *);

/*
 * Add new options here
 *
 * Optional option-arguments are not allowed by CLIP
 */
optionTbl_t sasinfolongOptions[] = {
	{"hba", required_argument,	'a', "HBA Name"},
	{"hba-port", required_argument,	'p', "HBA Port Name"},
	{"phy", no_argument,		'y', NULL},
	{"phy-linkstat", no_argument,	'l', NULL},
	{"scsi-target", no_argument,	's', NULL},
	{"verbose", no_argument,	'v', NULL},
	{"target", no_argument,	't', NULL},
	{NULL, 0, 0}
};

/*
 * Add new subcommands here
 */
subCommandProps_t sasinfosubcommands[] = {
	{"hba", listHbaFunc, "v", NULL, NULL,
		OPERAND_OPTIONAL_MULTIPLE, "HBA Name"},
	{"hba-port", listHbaPortFunc, "ylva", NULL, NULL,
		OPERAND_OPTIONAL_MULTIPLE, "HBA Port Name"},
	{"expander", listExpanderFunc, "ptv", NULL, NULL,
		OPERAND_OPTIONAL_MULTIPLE, "Expander Device SAS Address"},
	{"target-port", listTargetPortFunc, "sv", NULL, "sv",
		OPERAND_OPTIONAL_MULTIPLE, "Target Port SAS Address"},
	{"logical-unit", listLogicalUnitFunc, "v", NULL, NULL,
		OPERAND_OPTIONAL_MULTIPLE, "OS Device Name"},
	{"lu", listLogicalUnitFunc, "v", NULL, NULL,
		OPERAND_OPTIONAL_MULTIPLE, "OS Device Name"},
	{NULL, 0, NULL, NULL, NULL, 0, NULL, NULL}
};

/*
 * Pass in options/arguments, rest of arguments
 */
/*ARGSUSED*/
static int
listHbaFunc(int objects, char *argv[], cmdOptions_t *options, void *addArgs)
{
	return (sas_util_list_hba(objects, argv, options));
}

/*ARGSUSED*/
static int
listHbaPortFunc(int objects, char *argv[], cmdOptions_t *options, void *addArgs)
{
	return (sas_util_list_hbaport(objects, argv, options));
}

/*
 * Pass in options/arguments, rest of arguments
 */
/*ARGSUSED*/
static int
listExpanderFunc(int objects, char *argv[], cmdOptions_t *options,
    void *addArgs)
{
	return (sas_util_list_expander(objects, argv, options));
}

/*ARGSUSED*/
static int
listTargetPortFunc(int objects, char *argv[], cmdOptions_t *options,
    void *addArgs)
{
	return (sas_util_list_targetport(objects, argv, options));
}

/*
 * Pass in options/arguments, rest of arguments
 */
/*ARGSUSED*/
static int
listLogicalUnitFunc(int objects, char *argv[], cmdOptions_t *options,
    void *addArgs)
{
	return (sas_util_list_logicalunit(objects, argv, options));
}

/*
 * input:
 *  execFullName - exec name of program (argv[0])
 *
 * Returns:
 *  command name portion of execFullName
 */
static char *
getExecBasename(char *execFullname)
{
	char *lastSlash, *execBasename;

	/* guard against '/' at end of command invocation */
	for (;;) {
		lastSlash = strrchr(execFullname, '/');
		if (lastSlash == NULL) {
			execBasename = execFullname;
			break;
		} else {
			execBasename = lastSlash + 1;
			if (*execBasename == '\0') {
				*lastSlash = '\0';
				continue;
			}
			break;
		}
	}
	return (execBasename);
}

/*
 * main calls a parser that checks syntax of the input command against
 * various rules tables.
 *
 * The return value from the function is placed in funcRet
 */
int
main(int argc, char *argv[])
{
	synTables_t synTables;
	char versionString[VERSION_STRING_MAX_LEN];
	int ret;
	int funcRet;
	void *subcommandArgs = NULL;

	/* to support locale */
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* set global command name */
	cmdName = getExecBasename(argv[0]);

	/* check if is global zone */
	if (getzoneid() != GLOBAL_ZONEID) {
		(void *) fprintf(stdout, "%s %s\n",
		    cmdName, gettext("does not support non-global zone."));
		return (1);
	}

	(void *) snprintf(versionString, sizeof (versionString), "%s.%s",
	    VERSION_STRING_MAJOR, VERSION_STRING_MINOR);
	synTables.versionString = versionString;

	synTables.longOptionTbl = &sasinfolongOptions[0];
	synTables.subCommandPropsTbl = &sasinfosubcommands[0];

	/* call the CLI parser */
	ret = cmdParse(argc, argv, synTables, subcommandArgs, &funcRet);
	if (ret == 1) {
		(void *) fprintf(stdout, "%s %s(8)\n",
		    gettext("For more information, please see"), cmdName);
		return (1);
	} else if (ret == -1) {
		(void *) fprintf(stderr, "%s %s\n",
		    cmdName, strerror(errno));
		return (1);
	}

	if (funcRet != 0) {
		return (1);
	}
	return (0);
}
