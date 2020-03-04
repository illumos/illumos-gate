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

/*
 * Copyright 2020 Joyent Inc.
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
#include <cmdparse.h>


/* Usage types */
#define	GENERAL_USAGE	1
#define	DETAIL_USAGE	2

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
static int getSubcommandProps(char *, subCommandProps_t **);
static char *getExecBasename(char *);
static void usage(uint_t);
static void subUsage(uint_t, subCommandProps_t *);
static const char *getLongOption(int);
static char *getOptionArgDesc(int);

/* global data */
static struct option *_longOptions;
static subCommandProps_t *_subCommandProps;
static optionTbl_t *_clientOptionTbl;
static char *commandName;


/*
 * input:
 *  subCommand - subcommand value
 * output:
 *  subCommandProps - pointer to subCommandProps_t structure allocated by caller
 *
 * On successful return, subCommandProps contains the properties for the value
 * in subCommand. On failure, the contents of subCommandProps is unspecified.
 *
 * Returns:
 *  zero on success
 *  non-zero on failure
 *
 */
static int
getSubcommandProps(char *subCommand, subCommandProps_t **subCommandProps)
{
	subCommandProps_t *sp;
	int len;

	for (sp = _subCommandProps; sp->name; sp++) {
		len = strlen(subCommand);
		if (len == strlen(sp->name) &&
		    strncasecmp(subCommand, sp->name, len) == 0) {
			*subCommandProps = sp;
			return (0);
		}
	}
	return (1);
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
static const char *
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
 *  usage type - GENERAL_USAGE, DETAIL_USAGE
 *  subcommand - pointer to subCommandProps_t structure
 *
 * Returns:
 *  none
 *
 */
static void
subUsage(uint_t usageType, subCommandProps_t *subcommand)
{
	int i;
	char *optionArgDesc;
	const char *longOpt;

	if (usageType == GENERAL_USAGE) {
		(void) printf("%s:\t%s %s [", gettext("Usage"), commandName,
		    subcommand->name);
		for (i = 0; standardSubCmdOptions[i].name; i++) {
			(void) printf("-%c", standardSubCmdOptions[i].val);
			if (standardSubCmdOptions[i+1].name)
				(void) printf(",");
		}
		(void) fprintf(stdout, "]\n");
		return;
	}

	/* print subcommand usage */
	(void) printf("\n%s:\t%s %s ", gettext("Usage"), commandName,
	    subcommand->name);

	/* print options if applicable */
	if (subcommand->optionString != NULL) {
		if (subcommand->required) {
			(void) printf("%s", gettext("<"));
		} else {
			(void) printf("%s", gettext("["));
		}
		(void) printf("%s", gettext("OPTIONS"));
		if (subcommand->required) {
			(void) printf("%s ", gettext(">"));
		} else {
			(void) printf("%s ", gettext("]"));
		}
	}

	/* print operand requirements */
	if (!(subcommand->operand & OPERAND_NONE) &&
	    !(subcommand->operand & OPERAND_MANDATORY)) {
		(void) printf(gettext("["));
	}

	if (subcommand->operand & OPERAND_MANDATORY) {
		(void) printf(gettext("<"));
	}

	if (!(subcommand->operand & OPERAND_NONE)) {
		assert(subcommand->operandDefinition);
		(void) printf("%s", subcommand->operandDefinition);
	}

	if (subcommand->operand & OPERAND_MULTIPLE) {
		(void) printf(gettext(" ..."));
	}

	if (subcommand->operand & OPERAND_MANDATORY) {
		(void) printf(gettext(">"));
	}

	if (!(subcommand->operand & OPERAND_NONE) &&
	    !(subcommand->operand & OPERAND_MANDATORY)) {
		(void) printf(gettext("]"));
	}

	/* print options for subcommand */
	if (subcommand->optionString != NULL) {
		(void) printf("\n\t%s:", gettext("OPTIONS"));
		for (i = 0; i < strlen(subcommand->optionString); i++) {
			assert((longOpt = getLongOption(
			    subcommand->optionString[i])) != NULL);
			(void) printf("\n\t\t-%c, --%s  ",
			    subcommand->optionString[i],
			    longOpt);
			optionArgDesc =
			    getOptionArgDesc(subcommand->optionString[i]);
			if (optionArgDesc != NULL) {
				(void) printf("<%s>", optionArgDesc);
			}
			if (subcommand->exclusive &&
			    strchr(subcommand->exclusive,
			    subcommand->optionString[i])) {
				(void) printf(" (%s)", gettext("exclusive"));
			}
		}
	}
	(void) fprintf(stdout, "\n");
	if (subcommand->helpText) {
		(void) printf("%s\n", subcommand->helpText);
	}
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
	subCommandProps_t *sp;

	/* print general command usage */
	(void) printf("%s:\t%s ", gettext("Usage"), commandName);

	for (i = 0; standardCmdOptions[i].name; i++) {
		(void) printf("-%c", standardCmdOptions[i].val);
		if (standardCmdOptions[i+1].name)
			(void) printf(",");
	}

	if (usageType == GENERAL_USAGE) {
		for (i = 0; standardSubCmdOptions[i].name; i++) {
			(void) printf(",--%s", standardSubCmdOptions[i].name);
			if (standardSubCmdOptions[i+1].name)
				(void) printf(",");
		}
	}

	(void) fprintf(stdout, "\n");


	/* print all subcommand usage */
	for (sp = _subCommandProps; sp->name; sp++) {
		subUsage(usageType, sp);
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
 * two usage functions, usage, subUsage
 *
 * When syntax is successfully validated, the associated function is called
 * using the subcommands table functions.
 *
 * Syntax is as follows:
 *	command subcommand [<options>] [<operand>]
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
	int	requiredOptionCnt = 0, requiredOptionEntered = 0;
	char	*availOptions;
	char	*versionString;
	char	optionStringAll[MAXOPTIONSTRING + 1];
	subCommandProps_t *subcommand;
	cmdOptions_t cmdOptions[MAXOPTIONS + 1];
	optionTbl_t *optionTbl;
	struct option *lp;
	struct option intLongOpt[MAXOPTIONS + 1];

	/*
	 * Check for NULLs on mandatory input arguments
	 *
	 * Note: longOptionTbl can be NULL in the case
	 * where there is no caller defined options
	 *
	 */
	assert(synTable.versionString);
	assert(synTable.subCommandPropsTbl);
	assert(funcRet);

	versionString = synTable.versionString;

	/* set global command name */
	commandName = getExecBasename(argv[0]);

	/* Set unbuffered output */
	setbuf(stdout, NULL);

	/* load globals */
	_subCommandProps = synTable.subCommandPropsTbl;
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
					usage(DETAIL_USAGE);
					exit(0);
				} else {
					usage(GENERAL_USAGE);
					return (1);
				}
				break;
			case 'V':
				(void) fprintf(stdout, "%s: %s %s\n",
				    commandName, gettext("Version"),
				    versionString);
				exit(0);
				break;
			default:
				break;
		}
	}

	/*
	 * subcommand is always in the second argument. If there is no
	 * recognized subcommand in the second argument, print error,
	 * general usage and then return.
	 */
	if (getSubcommandProps(argv[1], &subcommand) != 0) {
		(void) printf("%s: %s\n", commandName,
		    gettext("invalid subcommand"));
		usage(GENERAL_USAGE);
		return (1);
	}

	getoptargv = argv;
	getoptargv++;
	getoptargc = argc;
	getoptargc -= 1;

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
	 *
	 * Once all options are retrieved, a validity check against
	 * subcommand table is performed.
	 */
	while ((opt = getopt_long(getoptargc, getoptargv, optionStringAll,
	    _longOptions, NULL)) != EOF) {
		switch (opt) {
			case '?':
				subUsage(DETAIL_USAGE, subcommand);
				/*
				 * getopt can return a '?' when no
				 * option letters match string. Check for
				 * the 'real' '?' in optopt.
				 */
				if (optopt == '?') {
					exit(0);
				} else {
					exit(1);
				}
			default:
				cmdOptions[i].optval = opt;
				if (optarg) {
					len = strlen(optarg);
					if (len > sizeof (cmdOptions[i].optarg)
					    - 1) {
						(void) printf("%s: %s\n",
						    commandName,
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
	operInd = optind + 1;

	/*
	 * Check validity of given options, if any were given
	 */

	/* get option string for this subcommand */
	availOptions = subcommand->optionString;

	/* Get count of required options */
	if (subcommand->required) {
		requiredOptionCnt = strlen(subcommand->required);
	}

	if (cmdOptions[0].optval != 0) { /* options were input */
		if (availOptions == NULL) { /* no options permitted */
			(void) printf("%s: %s\n", commandName,
			    gettext("no options permitted"));
			subUsage(DETAIL_USAGE, subcommand);
			return (1);
		}
		for (i = 0; cmdOptions[i].optval; i++) {
			/* is the option in the available option string? */
			if (!(strchr(availOptions, cmdOptions[i].optval))) {
				(void) printf("%s: '-%c': %s\n", commandName,
				    cmdOptions[i].optval,
				    gettext("invalid option"));
				subUsage(DETAIL_USAGE, subcommand);
				return (1);
			/* increment required options entered */
			} else if (subcommand->required &&
			    (strchr(subcommand->required,
			    cmdOptions[i].optval))) {
				requiredOptionEntered++;
			/* Check for exclusive options */
			} else if (cmdOptions[1].optval != 0 &&
			    subcommand->exclusive &&
			    strchr(subcommand->exclusive,
			    cmdOptions[i].optval)) {
				(void) printf("%s: '-%c': %s\n",
				    commandName, cmdOptions[i].optval,
				    gettext("is an exclusive option"));
				subUsage(DETAIL_USAGE, subcommand);
				return (1);
			}
		}
	} else { /* no options were input */
		if (availOptions != NULL && subcommand->required) {
			(void) printf("%s: %s\n", commandName,
			    gettext("at least one option required"));
			subUsage(DETAIL_USAGE, subcommand);
			return (1);
		}
	}

	/* Were all required options entered? */
	if (requiredOptionEntered != requiredOptionCnt) {
		(void) printf("%s: %s: %s\n", commandName,
		    gettext("Following option(s) required"),
		    subcommand->required);
		subUsage(DETAIL_USAGE, subcommand);
		return (1);
	}


	/*
	 * If there are no operands,
	 * check to see if this is okay
	 */
	if ((operInd == argc) &&
	    (subcommand->operand & OPERAND_MANDATORY)) {
		(void) printf("%s: %s %s\n", commandName, subcommand->name,
		    gettext("requires an operand"));
		subUsage(DETAIL_USAGE, subcommand);
		return (1);
	}

	/*
	 * If there are more operands,
	 * check to see if this is okay
	 */
	if ((argc > operInd) &&
	    (subcommand->operand & OPERAND_NONE)) {
		(void) fprintf(stderr, "%s: %s %s\n", commandName,
		    subcommand->name, gettext("takes no operands"));
		subUsage(DETAIL_USAGE, subcommand);
		return (1);
	}

	/*
	 * If there is more than one more operand,
	 * check to see if this is okay
	 */
	if ((argc > operInd) && ((argc - operInd) != 1) &&
	    (subcommand->operand & OPERAND_SINGLE)) {
		(void) printf("%s: %s %s\n", commandName,
		    subcommand->name, gettext("accepts only a single operand"));
		subUsage(DETAIL_USAGE, subcommand);
		return (1);
	}

	/* Finished syntax checks */


	/* Call appropriate function */
	*funcRet = subcommand->handler(argc - operInd, &argv[operInd],
	    &cmdOptions[0], callArgs);

	return (0);
}
