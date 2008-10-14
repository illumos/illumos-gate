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

#ifndef	_CMDPARSE_H
#define	_CMDPARSE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <getopt.h>

/* subcommands must have a single bit on and must have exclusive values */
#define	SUBCOMMAND_BASE  1
#define	SUBCOMMAND(x)  (SUBCOMMAND_BASE << x)

#define	OBJECT_BASE  1
#define	OBJECT(x) (OBJECT_BASE << x)

/* maximum length of an option argument */
#define	MAXOPTARGLEN   256


/*
 * Add objects here
 *
 * EXAMPLE:
 *	object_t object[] = {
 *	    {"target", TARGET},
 *	    {NULL, 0}
 *	};
 */
typedef struct _object {
	char *name;
	uint_t value;
} object_t;

/*
 * This structure is passed into the caller's callback function and
 * will contain a list of all options entered and their associated
 * option arguments if applicable
 */
typedef struct _cmdOptions {
	int optval;
	char optarg[MAXOPTARGLEN + 1];
} cmdOptions_t;


/*
 * list of objects, subcommands, valid short options, required flag and
 * exlusive option string
 *
 * objectValue -> object
 * subcommandValue -> subcommand value
 * optionProp.optionString -> short options that are valid
 * optionProp.required -> flag indicating whether at least one option is
 *                        required
 * optionProp.exclusive -> short options that are required to be exclusively
 *                         entered
 *
 *
 * If it's not here, there are no options for that object.
 *
 * The long options table specifies whether an option argument is required.
 *
 *
 * EXAMPLE:
 *
 * Based on DISCOVERY entry below:
 *
 *  MODIFY DISCOVERY accepts -i, -s, -t and -l
 *  MODIFY DISCOVERY requires at least one option
 *  MODIFY DISCOVERY has no exclusive options
 *
 *
 *	optionRules_t optionRules[] = {
 *	    {DISCOVERY, MODIFY, "istl", B_TRUE, NULL},
 *	    {0, 0, NULL, 0, NULL}
 *	};
 */
typedef struct _optionProp {
	char *optionString;
	boolean_t required;
	char *exclusive;
} optionProp_t;

typedef struct _optionRules {
	uint_t objectValue;
	uint_t subcommandValue;
	optionProp_t	optionProp;
} optionRules_t;

/*
 * Rules for subcommands and object operands
 *
 * Every object requires an entry
 *
 * value, reqOpCmd, optOpCmd, noOpCmd, invCmd, multOpCmd
 *
 * value -> numeric value of object
 *
 * The following five fields are comprised of values that are
 * a bitwise OR of the subcommands related to the object
 *
 * reqOpCmd -> subcommands that must have an operand
 * optOpCmd -> subcommands that may have an operand
 * noOpCmd -> subcommands that will have no operand
 * invCmd -> subcommands that are invalid
 * multOpCmd -> subcommands that can accept multiple operands
 * operandDefinition -> Usage definition for the operand of this object
 *
 *
 * EXAMPLE:
 *
 * based on TARGET entry below:
 *  MODIFY and DELETE subcomamnds require an operand
 *  LIST optionally requires an operand
 *  There are no subcommands that requires that no operand is specified
 *  ADD and REMOVE are invalid subcommands for this operand
 *  DELETE can accept multiple operands
 *
 *	objectRules_t objectRules[] = {
 *	    {TARGET, MODIFY|DELETE, LIST, 0, ADD|REMOVE, DELETE,
 *	    "target-name"},
 *	    {0, 0, 0, 0, 0, NULL}
 *	};
 */
typedef struct _opCmd {
	uint_t reqOpCmd;
	uint_t optOpCmd;
	uint_t noOpCmd;
	uint_t invOpCmd;
	uint_t multOpCmd;
} opCmd_t;

typedef struct _objectRules {
	uint_t value;
	opCmd_t opCmd;
	char *operandDefinition;
} objectRules_t;


/*
 * subcommand callback function
 *
 * argc - number of arguments in argv
 * argv - operand arguments
 * options - options entered on command line
 * callData - pointer to caller data to be passed to subcommand function
 */
typedef int (*handler_t)(int argc, char *argv[], int, cmdOptions_t *options,
    void *callData);

/*
 * Add new subcommands here
 *
 * EXAMPLE:
 *	subcommand_t subcommands[] = {
 *	    {"add", ADD, addFunc},
 *	    {NULL, 0, NULL}
 *	};
 */
typedef struct _subcommand {
	char *name;
	uint_t value;
	handler_t handler;
} subcommand_t;

#define	required_arg	required_argument
#define	no_arg		no_argument

/*
 * Add short options and long options here
 *
 *  name -> long option name
 *  has_arg -> required_arg, no_arg
 *  val -> short option character
 *  argDesc -> description of option argument
 *
 * Note: This structure may not be used if your CLI has no
 * options. However, -?, --help and -V, --version will still be supported
 * as they are standard for every CLI.
 *
 * EXAMPLE:
 *
 *	optionTbl_t options[] = {
 *	    {"filename", arg_required, 'f', "out-filename"},
 *	    {NULL, 0, 0}
 *	};
 *
 */
typedef struct _optionTbl {
	char *name;
	int has_arg;
	int val;
	char *argDesc;
} optionTbl_t;

/*
 * After tables are set, assign them to this structure
 * for passing into cmdparse()
 */
typedef struct _synTables {
	char *versionString;
	optionTbl_t *longOptionTbl;
	subcommand_t *subcommandTbl;
	object_t *objectTbl;
	objectRules_t *objectRulesTbl;
	optionRules_t *optionRulesTbl;
} synTables_t;

/*
 * cmdParse is a parser that checks syntax of the input command against
 * various rules tables.
 *
 * When syntax is successfully validated, the function associated with the
 * subcommand is called using the subcommands table functions.
 *
 * Syntax for the command is as follows:
 *
 *	command subcommand [<options>] object [<operand ...>]
 *
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
 */
int cmdParse(int numOperands, char *operands[], synTables_t synTables,
    void *callerArgs, int *funcRet);

#ifdef	__cplusplus
}
#endif

#endif	/* _CMDPARSE_H */
