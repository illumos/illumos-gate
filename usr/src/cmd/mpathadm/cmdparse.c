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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <libintl.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include "cmdparse.h"

/* Usage types */
#define	GENERAL_USAGE	1
#define	HELP_USAGE	2
#define	DETAIL_USAGE	3

/* printable ascii character set len */
#define	MAXOPTIONS	(uint_t)('~' - '!' + 1)

/*
 * MAXOPTIONSTRING is the max length of the options string used in getopt and
 * will be the printable character set + ':' for each character,
 * providing for options with arguments. e.g. "t:Cs:hglr:"
 */
#define	MAXOPTIONSTRING		MAXOPTIONS * 2

/* standard command options table to support -?, -V */
struct option standardCmdOptions[] = {
	{"help", no_argument, NULL, '?'},
	{"version", no_argument, NULL, 'V'},
	{NULL, 0, NULL, 0}
};

/* standard subcommand options table to support -? */
struct option standardSubCmdOptions[] = {
	{"help", no_argument, NULL, '?'},
	{NULL, 0, NULL, 0}
};

/* forward declarations */
static int getSubcommand(char *, subcommand_t **);
static char *getExecBasename(char *);
static void usage(uint_t);
static void subUsage(uint_t, subcommand_t *);
static void subUsageObject(uint_t, subcommand_t *, object_t *);
static int getObject(char *, object_t **);
static int getObjectRules(uint_t, objectRules_t **);
static char *getLongOption(int);
static optionProp_t *getOptions(uint_t, uint_t);
static char *getOptionArgDesc(int);

/* global data */
static struct option *_longOptions;
static subcommand_t *_subcommands;
static object_t *_objects;
static objectRules_t *_objectRules;
static optionRules_t *_optionRules;
static optionTbl_t *_clientOptionTbl;
static char *commandName;


/*
 * input:
 *  object - object value
 * output:
 *  opCmd - pointer to opCmd_t structure allocated by caller
 *
 * On successful return, opCmd contains the rules for the value in
 * object. On failure, the contents of opCmd is unspecified.
 *
 * Returns:
 *  zero on success
 *  non-zero on failure
 *
 */
static int
getObjectRules(uint_t object, objectRules_t **objectRules)
{
	objectRules_t *sp;

	for (sp = _objectRules; sp->value; sp++) {
		if (sp->value == object) {
			*objectRules = sp;
			return (0);
		}
	}
	return (1);
}

/*
 * input:
 *  arg - pointer to array of char containing object string
 *
 * output:
 *  object - pointer to object_t structure pointer
 *	on success, contains the matching object structure based on
 *	input object name
 *
 * Returns:
 *  zero on success
 *  non-zero otherwise
 *
 */
static int
getObject(char *arg, object_t **object)
{

	object_t *op;
	int len;

	for (op = _objects; op->name; op++) {
		len = strlen(arg);
		if (len == strlen(op->name) &&
		    strncasecmp(arg, op->name, len) == 0) {
			*object = op;
			return (0);
		}
	}
	return (1);
}

/*
 * input:
 *  arg - pointer to array of char containing subcommand string
 * output:
 *  subcommand - pointer to subcommand_t pointer
 *	on success, contains the matching subcommand structure based on
 *	input subcommand name
 *
 * Returns:
 *  zero on success
 *  non-zero on failure
 */
static int
getSubcommand(char *arg, subcommand_t **subcommand)
{
	subcommand_t *sp;
	int len;

	for (sp = _subcommands; sp->name; sp++) {
		len = strlen(arg);
		if (len == strlen(sp->name) &&
		    strncasecmp(arg, sp->name, len) == 0) {
			*subcommand = sp;
			return (0);
		}
	}
	return (1);
}

/*
 * input:
 *  object - object for which to get options
 *  subcommand - subcommand for which to get options
 *
 * Returns:
 *  on success, optionsProp_t pointer to structure matching input object
 *  value
 *  on failure, NULL is returned
 */
static optionProp_t *
getOptions(uint_t object, uint_t subcommand)
{
	uint_t currObject;
	optionRules_t *op = _optionRules;
	while (op && ((currObject = op->objectValue) != 0)) {
		if ((currObject == object) &&
		    (op->subcommandValue == subcommand)) {
		    return (&(op->optionProp));
		}
		op++;
	}
	return (NULL);
}

/*
 * input:
 *  shortOption - short option character for which to return the
 *	associated long option string
 *
 * Returns:
 *  on success, long option name
 *  on failure, NULL
 */
static char *
getLongOption(int shortOption)
{
	struct option *op;
	for (op = _longOptions; op->name; op++) {
		if (shortOption == op->val) {
			return (op->name);
		}
	}
	return (NULL);
}

/*
 * input
 *  shortOption - short option character for which to return the
 *	option argument
 * Returns:
 *  on success, argument string
 *  on failure, NULL
 */
static char *
getOptionArgDesc(int shortOption)
{
	optionTbl_t *op;
	for (op = _clientOptionTbl; op->name; op++) {
		if (op->val == shortOption &&
		    op->has_arg == required_argument) {
			return (op->argDesc);
		}
	}
	return (NULL);
}


/*
 * Print usage for a subcommand.
 *
 * input:
 *  usage type - GENERAL_USAGE, HELP_USAGE, DETAIL_USAGE
 *  subcommand - pointer to subcommand_t structure
 *
 * Returns:
 *  none
 *
 */
static void
subUsage(uint_t usageType, subcommand_t *subcommand)
{
	int i;
	object_t *objp;


	(void) fprintf(stdout, "%s:\t%s %s [",
	    gettext("Usage"), commandName, subcommand->name);

	for (i = 0; standardSubCmdOptions[i].name; i++) {
		(void) fprintf(stdout, "-%c",
		    standardSubCmdOptions[i].val);
		if (standardSubCmdOptions[i+1].name)
			(void) fprintf(stdout, ",");
	}

	(void) fprintf(stdout, "] %s [", "<OBJECT>");

	for (i = 0; standardSubCmdOptions[i].name; i++) {
		(void) fprintf(stdout, "-%c",
		    standardSubCmdOptions[i].val);
		if (standardSubCmdOptions[i+1].name)
			(void) fprintf(stdout, ",");
	}

	(void) fprintf(stdout, "] %s", "[<OPERAND>]");
	(void) fprintf(stdout, "\n");

	if (usageType == GENERAL_USAGE) {
		return;
	}

	(void) fprintf(stdout, "%s:\n", gettext("Usage by OBJECT"));

	/*
	 * iterate through object table
	 * For each object, print appropriate usage
	 * based on rules tables
	 */
	for (objp = _objects; objp->value; objp++) {
		subUsageObject(usageType, subcommand, objp);
	}
}

/*
 * Print usage for a subcommand and object.
 *
 * input:
 *  usage type - GENERAL_USAGE, HELP_USAGE, DETAIL_USAGE
 *  subcommand - pointer to subcommand_t structure
 *  objp - pointer to a object_t structure
 *
 * Returns:
 *  none
 *
 */
static void
subUsageObject(uint_t usageType, subcommand_t *subcommand, object_t *objp)
{
	int i;
	objectRules_t *objRules = NULL;
	opCmd_t *opCmd = NULL;
	optionProp_t *options;
	char *optionArgDesc;
	char *longOpt;


	if (getObjectRules(objp->value, &objRules) != 0) {
		/*
		 * internal subcommand rules table error
		 * no object entry in object
		 */
		assert(0);
	}

	opCmd = &(objRules->opCmd);

	if (opCmd->invOpCmd & subcommand->value) {
		return;
	}

	options = getOptions(objp->value, subcommand->value);

	/* print generic subcommand usage */
	(void) fprintf(stdout, "\t%s %s ", commandName, subcommand->name);

	/* print object */
	(void) fprintf(stdout, "%s ", objp->name);

	/* print options if applicable */
	if (options != NULL) {
		if (options->required) {
			(void) fprintf(stdout, "%s", gettext("<"));
		} else {
			(void) fprintf(stdout, "%s", gettext("["));
		}
		(void) fprintf(stdout, "%s", gettext("OPTIONS"));
		if (options->required) {
			(void) fprintf(stdout, "%s ", gettext(">"));
		} else {
			(void) fprintf(stdout, "%s ", gettext("]"));
		}
	}

	/* print operand requirements */
	if (opCmd->optOpCmd & subcommand->value) {
		(void) fprintf(stdout, gettext("["));
	}
	if (!(opCmd->noOpCmd & subcommand->value)) {
		(void) fprintf(stdout, gettext("<"));
		if (objRules->operandDefinition) {
			(void) fprintf(stdout, "%s",
			    objRules->operandDefinition);
		} else {
			/*
			 * Missing operand description
			 * from table
			 */
			assert(0);
		}
	}
	if (opCmd->multOpCmd & subcommand->value) {
		(void) fprintf(stdout, gettext(" ..."));
	}
	if (!(opCmd->noOpCmd & subcommand->value)) {
		(void) fprintf(stdout, gettext(">"));
	}
	if (opCmd->optOpCmd & subcommand->value) {
		(void) fprintf(stdout, gettext("]"));
	}

	if (usageType == HELP_USAGE) {
		(void) fprintf(stdout, "\n");
		return;
	}

	/* print options for subcommand, object */
	if (options != NULL && options->optionString != NULL) {
		(void) fprintf(stdout, "\n\t%s:", gettext("OPTIONS"));
		for (i = 0; i < strlen(options->optionString); i++) {
			if ((longOpt = getLongOption(
					    options->optionString[i]))
			    == NULL) {
			    /* no long option exists for short option */
			    assert(0);
			}
			(void) fprintf(stdout, "\n\t\t-%c, --%s  ",
			    options->optionString[i], longOpt);
			optionArgDesc =
			    getOptionArgDesc(options->optionString[i]);
			if (optionArgDesc != NULL) {
				(void) fprintf(stdout, "<%s>", optionArgDesc);
			}
			if (options->exclusive &&
			    strchr(options->exclusive,
				    options->optionString[i])) {
				(void) fprintf(stdout, " (%s)",
				gettext("exclusive"));
			}
		}
	}
	(void) fprintf(stdout, "\n");
}

/*
 * input:
 *  type of usage statement to print
 *
 * Returns:
 *  return value of subUsage
 */
static void
usage(uint_t usageType)
{
	int i;
	subcommand_t subcommand;
	subcommand_t *sp;

	/* print general command usage */
	(void) fprintf(stdout, "%s:\t%s ",
	    gettext("Usage"), commandName);

	for (i = 0; standardCmdOptions[i].name; i++) {
		(void) fprintf(stdout, "-%c",
		    standardCmdOptions[i].val);
		if (standardCmdOptions[i+1].name)
			(void) fprintf(stdout, ",");
	}

	if (usageType == HELP_USAGE || usageType == GENERAL_USAGE) {
		for (i = 0; standardSubCmdOptions[i].name; i++) {
			(void) fprintf(stdout, ",--%s",
				standardSubCmdOptions[i].name);
			if (standardSubCmdOptions[i+1].name)
				(void) fprintf(stdout, ",");
		}
	}

	(void) fprintf(stdout, "\n");


	/* print all subcommand usage */
	for (sp = _subcommands; sp->name; sp++) {
		subcommand.name = sp->name;
		subcommand.value = sp->value;
		if (usageType == HELP_USAGE) {
			(void) fprintf(stdout, "\n");
		}
		subUsage(usageType, &subcommand);
	}
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
 * cmdParse is a parser that checks syntax of the input command against
 * various rules tables.
 *
 * It provides usage feedback based upon the passed rules tables by calling
 * two usage functions, usage, subUsage, and subUsageObject handling command,
 * subcommand and object usage respectively.
 *
 * When syntax is successfully validated, the associated function is called
 * using the subcommands table functions.
 *
 * Syntax is as follows:
 *	command subcommand object [<options>] [<operand>]
 *
 * There are two standard short and long options assumed:
 *	-?, --help	Provides usage on a command or subcommand
 *			and stops further processing of the arguments
 *
 *	-V, --version	Provides version information on the command
 *			and stops further processing of the arguments
 *
 *	These options are loaded by this function.
 *
 * input:
 *  argc, argv from main
 *  syntax rules tables (synTables_t structure)
 *  callArgs - void * passed by caller to be passed to subcommand function
 *
 * output:
 *  funcRet - pointer to int that holds subcommand function return value
 *
 * Returns:
 *
 *     zero on successful syntax parse and function call
 *
 *     1 on unsuccessful syntax parse (no function has been called)
 *		This could be due to a version or help call or simply a
 *		general usage call.
 *
 *     -1 check errno, call failed
 *
 *  This module is not MT-safe.
 *
 */
int
cmdParse(int argc, char *argv[], synTables_t synTable, void *callArgs,
    int *funcRet)
{
	int	getoptargc;
	char	**getoptargv;
	int	opt;
	int	operInd;
	int	i, j;
	int	len;
	char	*versionString;
	char	optionStringAll[MAXOPTIONSTRING + 1];
	optionProp_t	*availOptions;
	objectRules_t *objRules = NULL;
	opCmd_t *opCmd = NULL;
	subcommand_t *subcommand;
	object_t *object;
	cmdOptions_t cmdOptions[MAXOPTIONS + 1];
	struct option *lp;
	optionTbl_t *optionTbl;
	struct option intLongOpt[MAXOPTIONS + 1];

	/*
	 * Check for NULLs on mandatory input arguments
	 *
	 * Note: longOptionTbl and optionRulesTbl can be NULL in the case
	 * where there is no caller defined options
	 *
	 */
	if (synTable.versionString == NULL ||
	    synTable.subcommandTbl == NULL ||
	    synTable.objectRulesTbl == NULL ||
	    synTable.objectTbl == NULL ||
	    funcRet == NULL) {
		assert(0);
	}


	versionString = synTable.versionString;

	/* set global command name */
	commandName = getExecBasename(argv[0]);

	/* Set unbuffered output */
	setbuf(stdout, NULL);

	/* load globals */
	_subcommands = synTable.subcommandTbl;
	_objectRules = synTable.objectRulesTbl;
	_optionRules = synTable.optionRulesTbl;
	_objects = synTable.objectTbl;
	_clientOptionTbl = synTable.longOptionTbl;

	/* There must be at least two arguments */
	if (argc < 2) {
		usage(GENERAL_USAGE);
		return (1);
	}

	(void) memset(&intLongOpt[0], 0, sizeof (intLongOpt));

	/*
	 * load standard subcommand options to internal long options table
	 * Two separate getopt_long(3C) tables are used.
	 */
	for (i = 0; standardSubCmdOptions[i].name; i++) {
		intLongOpt[i].name = standardSubCmdOptions[i].name;
		intLongOpt[i].has_arg = standardSubCmdOptions[i].has_arg;
		intLongOpt[i].flag = standardSubCmdOptions[i].flag;
		intLongOpt[i].val = standardSubCmdOptions[i].val;
	}

	/*
	 * copy caller's long options into internal long options table
	 * We do this for two reasons:
	 *  1) We need to use the getopt_long option structure internally
	 *  2) We need to prepend the table with the standard option
	 *	for all subcommands (currently -?)
	 */
	for (optionTbl = synTable.longOptionTbl;
	    optionTbl && optionTbl->name; optionTbl++, i++) {
		if (i > MAXOPTIONS - 1) {
			/* option table too long */
			assert(0);
		}
		intLongOpt[i].name = optionTbl->name;
		intLongOpt[i].has_arg = optionTbl->has_arg;
		intLongOpt[i].flag = NULL;
		intLongOpt[i].val = optionTbl->val;
	}

	/* set option table global */
	_longOptions = &intLongOpt[0];


	/*
	 * Check for help/version request immediately following command
	 * '+' in option string ensures POSIX compliance in getopt_long()
	 * which means that processing will stop at first non-option
	 * argument.
	 */
	while ((opt = getopt_long(argc, argv, "+?V", standardCmdOptions,
			    NULL)) != EOF) {
		switch (opt) {
			case '?':
				/*
				 * getopt can return a '?' when no
				 * option letters match string. Check for
				 * the 'real' '?' in optopt.
				 */
				if (optopt == '?') {
					usage(HELP_USAGE);
					return (1);
				} else {
					usage(GENERAL_USAGE);
					return (1);
				}
			case 'V':
				(void) fprintf(stdout, "%s: %s %s\n",
				    commandName, gettext("Version"),
				    versionString);
				return (1);
			default:
				break;
		}
	}

	/*
	 * subcommand is always in the second argument. If there is no
	 * recognized subcommand in the second argument, print error,
	 * general usage and then return.
	 */
	if (getSubcommand(argv[1], &subcommand) != 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    commandName, gettext("invalid subcommand"));
		usage(GENERAL_USAGE);
		return (1);
	}

	if (argc == 2) {
		(void) fprintf(stderr, "%s: %s\n",
		    commandName, gettext("missing object"));
		subUsage(GENERAL_USAGE, subcommand);
		return (1);
	}

	getoptargv = argv;
	getoptargv++;
	getoptargc = argc;
	getoptargc -= 1;

	while ((opt = getopt_long(getoptargc, getoptargv, "+?",
			    standardSubCmdOptions, NULL)) != EOF) {
		switch (opt) {
			case '?':
				/*
				 * getopt can return a '?' when no
				 * option letters match string. Check for
				 * the 'real' '?' in optopt.
				 */
				if (optopt == '?') {
					subUsage(HELP_USAGE, subcommand);
					return (1);
				} else {
					subUsage(GENERAL_USAGE, subcommand);
					return (1);
				}
			default:
				break;
		}
	}


	/*
	 * object is always in the third argument. If there is no
	 * recognized object in the third argument, print error,
	 * help usage for the subcommand and then return.
	 */
	if (getObject(argv[2], &object) != 0) {
	    (void) fprintf(stderr, "%s: %s\n",
		commandName, gettext("invalid object"));
	    subUsage(HELP_USAGE, subcommand);
	    return (1);
	}

	if (getObjectRules(object->value, &objRules) != 0) {
		/*
		 * internal subcommand rules table error
		 * no object entry in object table
		 */
		assert(0);
	}

	opCmd = &(objRules->opCmd);

	/*
	 * Is command valid for this object?
	 */
	if (opCmd->invOpCmd & subcommand->value) {
		(void) fprintf(stderr, "%s: %s %s\n", commandName,
		    gettext("invalid subcommand for"), object->name);
		subUsage(HELP_USAGE, subcommand);
		return (1);
	}

	/*
	 * offset getopt arg begin since
	 * getopt(3C) assumes options
	 * follow first argument
	 */
	getoptargv = argv;
	getoptargv++;
	getoptargv++;
	getoptargc = argc;
	getoptargc -= 2;

	(void) memset(optionStringAll, 0, sizeof (optionStringAll));
	(void) memset(&cmdOptions[0], 0, sizeof (cmdOptions));

	j = 0;
	/*
	 * Build optionStringAll from long options table
	 */
	for (lp = _longOptions;  lp->name; lp++, j++) {
		/* sanity check on string length */
		if (j + 1 >= sizeof (optionStringAll)) {
			/* option table too long */
			assert(0);
		}
		optionStringAll[j] = lp->val;
		if (lp->has_arg == required_argument) {
			optionStringAll[++j] = ':';
		}
	}

	i = 0;
	/*
	 * Run getopt for all arguments against all possible options
	 * Store all options/option arguments in an array for retrieval
	 * later.
	 * Once all options are retrieved, check against object
	 * and subcommand (option rules table) for validity.
	 * This is done later.
	 */
	while ((opt = getopt_long(getoptargc, getoptargv, optionStringAll,
			    _longOptions, NULL)) != EOF) {
		switch (opt) {
			case '?':
				if (optopt == '?') {
					subUsageObject(DETAIL_USAGE,
					    subcommand, object);
					return (1);
				} else {
					subUsage(GENERAL_USAGE, subcommand);
					return (1);
				}
			default:
				cmdOptions[i].optval = opt;
				if (optarg) {
					len = strlen(optarg);
					if (len > sizeof (cmdOptions[i].optarg)
					    - 1) {
						(void) fprintf(stderr,
						    "%s: %s\n", commandName,
						    gettext("option too long"));
						errno = EINVAL;
						return (-1);
					}
					(void) strncpy(cmdOptions[i].optarg,
					    optarg, len);
				}
				i++;
				break;
		}
	}

	/*
	 * increment past last option
	 */
	operInd = optind + 2;

	/*
	 * Check validity of given options, if any were given
	 */

	/* get option string for this object and subcommand */
	availOptions = getOptions(object->value, subcommand->value);

	if (cmdOptions[0].optval != 0) { /* options were input */
		if (availOptions == NULL) { /* no options permitted */
			(void) fprintf(stderr, "%s: %s\n",
				commandName, gettext("no options permitted"));
			subUsageObject(HELP_USAGE, subcommand, object);
			return (1);
		}
		for (i = 0; cmdOptions[i].optval; i++) {
			/* Check for invalid options */
			if (availOptions->optionString == NULL) {
				/*
				 * internal option table error
				 * There must be an option string if
				 * there is an entry in the table
				 */
				assert(0);
			}
			/* is the option in the available option string? */

			if (!(strchr(availOptions->optionString,
				cmdOptions[i].optval))) {
				(void) fprintf(stderr,
					"%s: '-%c': %s\n",
					commandName, cmdOptions[i].optval,
					gettext("invalid option"));
				subUsageObject(DETAIL_USAGE, subcommand,
					object);
				return (1);

			/* Check for exclusive options */
			} else if (cmdOptions[1].optval != 0 &&
				availOptions->exclusive &&
				strchr(availOptions->exclusive,
					cmdOptions[i].optval)) {
					(void) fprintf(stderr,
					"%s: '-%c': %s\n",
					commandName, cmdOptions[i].optval,
					gettext("is an exclusive option"));
				subUsageObject(DETAIL_USAGE, subcommand,
					object);
					return (1);
			}
		}
	} else { /* no options were input */
		if (availOptions != NULL &&
			(availOptions->required)) {
			(void) fprintf(stderr, "%s: %s\n",
				commandName,
				gettext("at least one option required"));
			subUsageObject(DETAIL_USAGE, subcommand,
				object);
			return (1);
		}
	}

	/*
	 * If there are no more arguments (operands),
	 * check to see if this is okay
	 */
	if ((operInd == argc) &&
		(opCmd->reqOpCmd & subcommand->value)) {
		(void) fprintf(stderr, "%s: %s %s %s\n",
			commandName, subcommand->name,
			object->name, gettext("requires an operand"));
		subUsageObject(HELP_USAGE, subcommand, object);
		return (1);
	}

	/*
	 * If there are more operands,
	 * check to see if this is okay
	 */
	if ((argc > operInd) &&
		(opCmd->noOpCmd & subcommand->value)) {
		(void) fprintf(stderr, "%s: %s %s %s\n",
			commandName, subcommand->name,
			object->name, gettext("takes no operands"));
		subUsageObject(HELP_USAGE, subcommand, object);
		return (1);
	}

	/*
	 * If there is more than one more operand,
	 * check to see if this is okay
	 */
	if ((argc > operInd) && ((argc - operInd) != 1) &&
		!(opCmd->multOpCmd & subcommand->value)) {
		(void) fprintf(stderr, "%s: %s %s %s\n",
			commandName, subcommand->name, object->name,
			gettext("accepts only a single operand"));
		subUsageObject(HELP_USAGE, subcommand, object);
		return (1);
	}

	/* Finished syntax checks */


	/* Call appropriate function */
	*funcRet = subcommand->handler(argc - operInd, &argv[operInd],
		object->value, &cmdOptions[0], callArgs);

	return (0);
}
