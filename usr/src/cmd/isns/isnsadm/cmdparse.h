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

#define	SUBCOMMAND_BASE  1

/* bit defines for operand macros */
#define	OPERAND_SINGLE		0x2
#define	OPERAND_MULTIPLE	0x4
#define	OPERAND_MANDATORY	0x8
#define	OPERAND_OPTIONAL	0x10

/* maximum length of an option argument */
#define	MAXOPTARGLEN   256


/* Following are used to express operand requirements */
#define	OPERAND_NONE		    0x1
#define	OPERAND_MANDATORY_SINGLE    (OPERAND_MANDATORY | OPERAND_SINGLE)
#define	OPERAND_OPTIONAL_SINGLE	    (OPERAND_OPTIONAL | OPERAND_SINGLE)
#define	OPERAND_MANDATORY_MULTIPLE  (OPERAND_MANDATORY | OPERAND_MULTIPLE)
#define	OPERAND_OPTIONAL_MULTIPLE   (OPERAND_OPTIONAL | OPERAND_MULTIPLE)

/* subcommands must have a single bit on and must have exclusive values */
#define	SUBCOMMAND(x)  (SUBCOMMAND_BASE << x)

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
 * subcommand callback function
 *
 * argc - number of arguments in argv
 * argv - operand arguments
 * options - options entered on command line
 * callData - pointer to caller data to be passed to subcommand function
 */
typedef int (*handler_t)(int argc, char *argv[], cmdOptions_t *options,
    void *callData);

/*
 * list of subcommands and associated properties
 *
 * name -> subcommand name
 * value -> subcommand value
 * handler -> function to call on successful syntax check
 * optionString -> short options that are valid
 * required -> Does it require at least one option?
 * exclusive -> short options that are required to be exclusively entered
 * operand -> Type of operand input. Can be:
 *
 *		NO_OPERAND
 *		OPERAND_MANDATORY_SINGLE
 *		OPERAND_OPTIONAL_SINGLE
 *		OPERAND_MANDATORY_MULTIPLE
 *		OPERAND_OPTIONAL_MULTIPLE
 *
 * operandDefinition -> char * definition of the operand
 *
 * The long options table specifies whether an option argument is required.
 *
 *
 * EXAMPLE:
 *
 * Based on "list-target" entry below:
 *
 *  "list-target" is expected as the subcommand input
 *  LIST-TARGET is the subcommand value
 *  listTarget is the function to be called on success
 *  LIST_TARGET accepts -i, -s, -t and -l
 *  LIST_TARGET requires at least one option
 *  LIST_TARGET has no exclusive options
 *  LIST_TARGET may have one or more operands
 *  LIST_TARGET operand description is "target-name"
 *
 *
 *	optionRules_t optionRules[] = {
 *	    {"list-target", LIST-TARGET, listTarget, "istl", B_TRUE, NULL,
 *		OPERAND_OPTIONAL_MULTIPLE, "target-name"},
 *	    {"modify-target", MODIFY-TARGET, modifyTarget, "t", B_TRUE, NULL,
 *		OPERAND_MANDATORY_MULTIPLE, "target-name"},
 *	    {"enable", ENABLE, enable, NULL, B_TRUE, NULL, NO_OPERAND, NULL},
 *	    {NULL, 0, 0, NULL, 0, NULL}
 *	};
 */
typedef struct _subCommandProps {
	char *name;
	uint_t value;
	handler_t handler;
	char *optionString;
	boolean_t required;
	char *exclusive;
	int operand;
	char *operandDefinition;
	uint8_t reserved[64];
} subCommandProps_t;



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
	subCommandProps_t *subCommandPropsTbl;
} synTables_t;

/*
 * cmdParse is a parser that checks syntax of the input command against
 * rules and property tables.
 *
 * When syntax is successfully validated, the function associated with the
 * subcommand is called using the subcommands table functions.
 *
 * Syntax for the command is as follows:
 *
 *	command [options] subcommand [<options>] [<operand ...>]
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
