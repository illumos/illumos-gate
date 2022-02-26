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

#include <fcinfo.h>



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

#define	OPTIONSTRING1		"HBA Port WWN"
#define	OPTIONSTRING2		"HBA Node WWN"
/* forward declarations */
static int listHbaPortFunc(int, char **, cmdOptions_t *, void *);
static int listRemotePortFunc(int, char **, cmdOptions_t *, void *);
static int listLogicalUnitFunc(int, char **, cmdOptions_t *, void *);
static int npivCreatePortFunc(int, char **, cmdOptions_t *, void *);
static int npivDeletePortFunc(int, char **, cmdOptions_t *, void *);
static int npivCreatePortListFunc(int, char **, cmdOptions_t *, void *);
static int npivListHbaPortFunc(int, char **, cmdOptions_t *, void *);
static int npivListRemotePortFunc(int, char **, cmdOptions_t *, void *);
static int fcoeAdmCreatePortFunc(int, char **, cmdOptions_t *, void *);
static int fcoeListPortsFunc(int, char **, cmdOptions_t *, void *);
static int fcoeAdmDeletePortFunc(int, char **, cmdOptions_t *, void *);
static int fcadmForceLipFunc(int, char **, cmdOptions_t *, void *);
static char *getExecBasename(char *);

/*
 * Add new options here
 *
 * Optional option-arguments are not allowed by CLIP
 */
optionTbl_t fcinfolongOptions[] = {
	{"port", required_argument,	'p', OPTIONSTRING1},
	{"target", no_argument,		't', NULL},
	{"initiator", no_argument,	'i', NULL},
	{"linkstat", no_argument,	'l', NULL},
	{"scsi-target", no_argument,	's', NULL},
	{"fcoe", no_argument,		'e', NULL},
	{"verbose", no_argument,	'v', NULL},
	{NULL, 0, 0}
};

optionTbl_t fcadmlongOptions[] = {
	{"port", required_argument,	'p', OPTIONSTRING1},
	{"node", required_argument,	'n', OPTIONSTRING2},
	{"linkstat", no_argument,	'l', NULL},
	{"scsi-target", no_argument,	's', NULL},
	{"fcoe-force-promisc", no_argument, 'f', NULL},
	{"target", no_argument,		't', NULL},
	{"initiator", no_argument,	'i', NULL},
	{NULL, 0, 0}
};

/*
 * Add new subcommands here
 */
subCommandProps_t fcinfosubcommands[] = {
	{"hba-port", listHbaPortFunc, "itel", NULL, NULL,
		OPERAND_OPTIONAL_MULTIPLE, "WWN"},
	{"remote-port", listRemotePortFunc, "lsp", "p", NULL,
		OPERAND_OPTIONAL_MULTIPLE, "WWN"},
	{"logical-unit", listLogicalUnitFunc, "v", NULL, NULL,
		OPERAND_OPTIONAL_MULTIPLE, "OS Device Path"},
	{"lu", listLogicalUnitFunc, "v", NULL, NULL,
		OPERAND_OPTIONAL_MULTIPLE, "OS Device Path"},
	{NULL, 0, NULL, NULL, NULL, 0, NULL, NULL}
};

subCommandProps_t fcadmsubcommands[] = {
	{"create-npiv-port",
	    npivCreatePortFunc, "pn", NULL, NULL,
	    OPERAND_MANDATORY_SINGLE,  "WWN"},
	{"delete-npiv-port",
	    npivDeletePortFunc, "p", "p", NULL,
	    OPERAND_MANDATORY_SINGLE,  "WWN"},
	{"hba-port",
	    npivListHbaPortFunc, "l", NULL, NULL,
	    OPERAND_OPTIONAL_MULTIPLE, "WWN"},
	{"remote-port",
	    npivListRemotePortFunc, "psl", "p", NULL,
	    OPERAND_OPTIONAL_MULTIPLE, "WWN"},
	{"create-port-list",
	    npivCreatePortListFunc, NULL, NULL, NULL,
	    OPERAND_NONE, NULL},
	{"create-fcoe-port",
	    fcoeAdmCreatePortFunc, "itpnf", NULL, NULL,
		OPERAND_MANDATORY_SINGLE, "Network Interface Name"},
	{"delete-fcoe-port",
	    fcoeAdmDeletePortFunc, NULL, NULL, NULL,
		OPERAND_MANDATORY_SINGLE, "Network Interface Name"},
	{"list-fcoe-ports",
	    fcoeListPortsFunc, "it", NULL, NULL,
		OPERAND_NONE, NULL},
	{"force-lip",
	    fcadmForceLipFunc, NULL, NULL, NULL,
		OPERAND_MANDATORY_SINGLE, "WWN"},
	{NULL, 0, NULL, NULL, NULL, 0, NULL, NULL}
};

/*
 * Pass in options/arguments, rest of arguments
 */
/*ARGSUSED*/
static int
listHbaPortFunc(int objects, char *argv[], cmdOptions_t *options, void *addArgs)
{
	return (fc_util_list_hbaport(objects, argv, options));
}

/*
 * Pass in options/arguments, rest of arguments
 */
/*ARGSUSED*/
static int
listRemotePortFunc(int objects, char *argv[], cmdOptions_t *options,
    void *addArgs)
{
	return (fc_util_list_remoteport(objects, argv, options));
}

/*
 * Pass in options/arguments, rest of arguments
 */
/*ARGSUSED*/
static int
listLogicalUnitFunc(int objects, char *argv[], cmdOptions_t *options,
    void *addArgs)
{
	return (fc_util_list_logicalunit(objects, argv, options));
}

/*
 * Pass in options/arguments, rest of arguments
 */
/*ARGSUSED*/
static int
npivCreatePortFunc(int objects, char *argv[],
    cmdOptions_t *options, void *addArgs) {
	return (fc_util_create_npivport(objects, argv, options));
}

static int
npivCreatePortListFunc(int objects, char *argv[],
    cmdOptions_t *options, void *addArgs) {
	if ((objects == 0) && addArgs && options && argv) {
		objects = 1;
	}
	return (fc_util_create_portlist());
}

/*
 * Pass in options/arguments, rest of arguments
 */
/*ARGSUSED*/
static int
npivDeletePortFunc(int objects, char *argv[],
    cmdOptions_t *options, void *addArgs) {
	return (fc_util_delete_npivport(objects, argv, options));
}

/*
 * Pass in options/arguments, rest of arguments
 */
/*ARGSUSED*/
static int
npivListHbaPortFunc(int objects, char *argv[],
    cmdOptions_t *options, void *addArgs) {
	return (fc_util_list_hbaport(objects, argv, options));
}

/*
 * Pass in options/arguments, rest of arguments
 */
/*ARGSUSED*/
static int
npivListRemotePortFunc(int objects, char *argv[],
    cmdOptions_t *options, void *addArgs) {
	return (fc_util_list_remoteport(objects, argv, options));
}

/*
 * Pass in options/arguments, rest of arguments
 */
/*ARGSUSED*/
static int
fcoeAdmCreatePortFunc(int objects, char *argv[], cmdOptions_t *options,
    void *addArgs)
{
	return (fcoe_adm_create_port(objects, argv, options));
}

/*
 * Pass in options/arguments, rest of arguments
 */
/*ARGSUSED*/
static int
fcoeAdmDeletePortFunc(int objects, char *argv[], cmdOptions_t *options,
    void *addArgs)
{
	return (fcoe_adm_delete_port(objects, argv));
}

/*
 * Pass in options/arguments, rest of arguments
 */
/*ARGSUSED*/
static int
fcoeListPortsFunc(int objects, char *argv[], cmdOptions_t *options,
    void *addArgs)
{
	return (fcoe_adm_list_ports(options));
}

/*
 * Pass in options/arguments, rest of arguments
 */
/*ARGSUSED*/
static int
fcadmForceLipFunc(int objects, char *argv[], cmdOptions_t *options,
    void *addArgs)
{
	return (fc_util_force_lip(objects, argv));
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
 * The parser provides usage feedback based upon same tables by calling
 * two usage functions, usage and subUsage, handling command and subcommand
 * usage respectively.
 *
 * The parser handles all printing of usage syntactical errors
 *
 * When syntax is successfully validated, the parser calls the associated
 * function using the subcommands table functions.
 *
 * Syntax is as follows:
 *	command subcommand [options] resource-type [<object>]
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

	(void) setlocale(LC_ALL, "");
#if	!defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* set global command name */
	cmdName = getExecBasename(argv[0]);

	sprintf(versionString, "%s.%s",
	    VERSION_STRING_MAJOR, VERSION_STRING_MINOR);
	synTables.versionString = versionString;
	if (strcmp(cmdName, "fcadm") == 0) {
		synTables.longOptionTbl = &fcadmlongOptions[0];
		synTables.subCommandPropsTbl = &fcadmsubcommands[0];
	} else {
		synTables.longOptionTbl = &fcinfolongOptions[0];
		synTables.subCommandPropsTbl = &fcinfosubcommands[0];
	}

	/* call the CLI parser */
	ret = cmdParse(argc, argv, synTables, subcommandArgs, &funcRet);
	if (ret == 1) {
		fprintf(stdout, "%s %s(8)\n",
		    gettext("For more information, please see"), cmdName);
		return (1);
	} else if (ret == -1) {
		perror(cmdName);
		return (1);
	}

	if (funcRet != 0) {
		return (1);
	}
	return (0);
}
