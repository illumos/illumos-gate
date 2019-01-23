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
 * Copyright (c) 1997-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * interceptor.c -- a functional decomposition of generate.c,
 *	the code generator for apptrace
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "parser.h"
#include "trace.h"
#include "util.h"
#include "db.h"
#include "symtab.h"
#include "io.h"
#include "bindings.h"
#include "printfuncs.h"
#include "errlog.h"
#include "parseproto.h"

static void generate_i_declarations(char *, int, char *);
static void generate_i_preamble(ENTRY *);
static void generate_i_call();
static int  generate_i_bindings(int);
static void generate_i_postamble(ENTRY *, int, char *, char *);
static void generate_i_evaluations(ENTRY *);
static void generate_i_prints(ENTRY *, char *, char *);
static void generate_i_closedown(char *, int);
static void generate_i_live_vars(ENTRY *);
static void generate_return_printf(int);
static char *variables_get_errorname(void);

/*
 * generate_interceptor -- make code for an individual interceptor, written
 *	as an output grammar
 */
void
generate_interceptor(ENTRY *function)
{
	char	*prototype = symtab_get_prototype(),
		*library_name = db_get_current_library(),
		*function_name,
		*error_name;
	int	void_func;

	errlog(BEGIN, "generate_interceptor() {");

	/* Check for required information. */
	if (validity_of(function) == NO) {
		symtab_set_skip(YES);
		errlog(WARNING|INPUT, "No prototype for interface, "
			"it will be skipped");
		errlog(END, "}");
		return;
	}

	/* Collect things we'll use more than once. */
	function_name = name_of(function);

	error_name = variables_get_errorname();

	void_func = is_void(function);

	/*
	 * Emit "artificial" prototype here so that if there's a
	 * disagreement between it and the prototype contained in the
	 * declaring header, the compiler will flag it.
	 * First #undef the function to make sure the prototype in the header
	 * is exposed and to avoid breaking the artificial prototype if it's
	 * not.
	 */
	{
		decl_t *dp;
		char *buf;
		char const *err;
		size_t s;

		s = strlen(prototype) + 2;
		buf = malloc(s);
		if (buf == NULL)
			abort();
		(void) strcpy(buf, prototype);
		buf[s - 2] = ';';
		buf[s - 1] = '\0';

		err = decl_Parse(buf, &dp);
		if (err != NULL)
			errlog(FATAL, "\"%s\", line %d: %s: %s",
			    symtab_get_filename(), line_of(function),
			    err, prototype);

		/* generate the mapfile entry */
		(void) fprintf(Mapfp, "\t__abi_%s;\n", decl_GetName(dp));

		(void) decl_ToString(buf, DTS_DECL, dp, function_name);
		(void) fprintf(Bodyfp, "#line %d \"%s\"\n",
		    line_of(function), symtab_get_filename());
		(void) fprintf(Bodyfp, "#undef %s\n", function_name);
		(void) fprintf(Bodyfp, "extern %s;\n", buf);

		(void) fprintf(Bodyfp, "static %s\n{\n", prototype);

		(void) decl_ToString(buf, DTS_RET, dp, "_return");
		generate_i_declarations(error_name, void_func, buf);
		decl_Destroy(dp);
		free(buf);
	}

	generate_i_preamble(function);
	generate_i_call(function, void_func, library_name, error_name);
	generate_i_postamble(function, void_func, error_name, library_name);

	errlog(END, "}");
}

/*
 * print_function_signature -- print the line defining the function, without
 *      an ``extern'' prefix or either a ``;'' or ''{'' suffix.
 */
void
print_function_signature(char *xtype, char *name, char *formals)
{
	char	buffer[MAXLINE];

	(void) snprintf(buffer, sizeof (buffer), "%s", name);
	(void) fprintf(Bodyfp,  xtype, buffer);
	if (strstr(xtype, "(*") == NULL) {
		(void) fprintf(Bodyfp,  "(%s)", formals);
	}
}


/*
 * generate_i_declarations -- generate the declarations which
 *      are local to the interceptor function itself.
 */
static void
generate_i_declarations(char *errname, int voidfunc, char *ret_str)
{

	errlog(BEGIN, "generate_i_declarations() {");
	if (*errname != '\0') {
		/* Create locals for errno-type variable, */
		(void) fprintf(Bodyfp,
		    "    int saved_errvar = %s;\n", errname);
		(void) fprintf(Bodyfp,  "    int functions_errvar;\n");
	}

	if (need_exception_binding()) {
		/* Create a local for that. */
		(void) fprintf(Bodyfp,  "    int exception = 0;\n");
	}
	if (! voidfunc) {
		/* Create a return value. */
		(void) fprintf(Bodyfp,  "    %s;\n", ret_str);
	}
	(void) fprintf(Bodyfp, "    sigset_t omask;\n");
	(void) putc('\n', Bodyfp);
	errlog(END, "}");
}


/*
 * generate_i_preamble -- do the actions which must occur
 *      before the call.
 */
static void
generate_i_preamble(ENTRY *function)
{
	errlog(BEGIN, "generate_i_preamble() {");
	generate_i_live_vars(function); /* Deferred. */

	if (symtab_get_nonreturn() == YES) {
		/* Make things safe for printing */
		(void) fprintf(Bodyfp,
		    "    abilock(&omask);\n");
		/* Print all the args in terse format. */
		generate_printf(function);
		(void) fputs("    putc('\\n', ABISTREAM);\n\n", Bodyfp);
		/* unlock stdio */
		(void) fprintf(Bodyfp,
		    "    abiunlock(&omask);\n");
	}

	errlog(END, "}");
}

/*
 * generate_i_call -- implement the save/call/restore cycle
 */
static void
generate_i_call(
	ENTRY	*function,
	int	void_func,
	char	*library_name,
	char	*error_name)
{
	char	*function_name = name_of(function),
		*function_cast = symtab_get_cast(),
		*actual_args = symtab_get_actuals();

	errlog(BEGIN, "generate_i_call() {");
	/* Zero the error variable. */
	if (*error_name != '\0') {
		(void) fprintf(Bodyfp,  "    %s = 0;\n", error_name);
	}

	/* Then print the call itself. */
	if (void_func) {
		(void) fprintf(Bodyfp,
		    "    (void) ABI_CALL_REAL(%s, %s, %s)(%s);\n",
		    library_name, function_name, function_cast, actual_args);
	} else {
		(void) fprintf(Bodyfp,
		    "    _return = ABI_CALL_REAL(%s, %s, %s)(%s);\n",
		    library_name, function_name, function_cast, actual_args);
	}

	/* Then set the local copy of the error variable. */
	if (*error_name != '\0') {
		(void) fprintf(Bodyfp,
		    "    functions_errvar = %s;\n", error_name);
	}
	(void) putc('\n', Bodyfp);

	/* Make things safe for printing */
	(void) fprintf(Bodyfp,
	    "    abilock(&omask);\n");

	errlog(END, "}");
}

/*
 * generate_i_postamble -- do all the things which come
 *      after the call.  In the case of apptrace, this is most of the work.
 */
static void
generate_i_postamble(ENTRY *function, int void_func,
    char *error_name, char *library_name)
{
	errlog(BEGIN, "generate_i_postamble() {");
	if (symtab_get_nonreturn() == NO) {
		/* Print all the args in terse format. */
		generate_printf(function);
	}

	/* If it isn't supposed to return, and actually ends up here, */
	/* we'd better be prepared to print all sorts of diagnostic stuff */
	(void) putc('\n', Bodyfp);
	if (generate_i_bindings(void_func) == YES) {
		generate_return_printf(void_func);
	}

	generate_i_prints(function, library_name, name_of(function));
	generate_i_evaluations(function); /* Deferred */
	generate_i_closedown(error_name, void_func);
	errlog(END, "}");
}

/*
 * generate_i_bindings -- see about success and failure, so we can decide
 *      what to do next.
 */
static int
generate_i_bindings(int void_func)
{
	ENTRY   *e;
	char *exception;

	exception  = ((e = symtab_get_exception()) != NULL)?
	    (name_of(e)? name_of(e): ""): "";

	errlog(BEGIN, "generate_i_bindings() {");
	if (void_func && bindings_exist()) {
		/* To become a warning, as there are spec errors! TBD */
		errlog(FATAL, "exception bindings found in a "
			"void function");
	} else if (void_func || need_bindings(exception) == NO) {
		(void) fprintf(Bodyfp,
		    "    (void) putc('\\n', ABISTREAM);\n");
		(void) putc('\n', Bodyfp);
		errlog(END, "}");
		return (NO);
	} else {
		/*
		 * Then there is a return value, so we try to
		 * generate exception bindings
		 * and code to print errno on exception.
		 */
		if ((generate_bindings(exception)) != ANTONYMS) {
			/* Generate code to cross-evaluate them. */
			(void) fprintf(Bodyfp,
			    "    if (!exception) {\n");
			errlog(END, "}");
			return (YES);
		}
	}

	/* should not get here */
	errlog(END, "}");
	return (NO);
}

/*
 * generate_return_printf -- print the return value and end the line
 */
static void
generate_return_printf(int void_func)
{
	errlog(BEGIN, "generate_return_printf() {");
	if (void_func) {
		(void) fprintf(Bodyfp,  "    putc('\\n', ABISTREAM);\n");
		errlog(END, "}");
		return;
	}
	/* If its a non-void function there are bindings. */
	(void) fprintf(Bodyfp,
	    "\t/* Just end the line */\n"
	    "\tputc('\\n', ABISTREAM);\n"
	    "    }\n"
	    "    else {\n"
	    "        fprintf(ABISTREAM, \"%%s%%d (%%s)\\n\", errnostr, "
	    "functions_errvar, strerror((int)functions_errvar));\n"
	    "    }\n\n");
	errlog(END, "}");
}

/*
 * generate_i_prints -- if we're doing the verbose stuff,
 *      generate verbose printouts of the variables.
 */
static void
generate_i_prints(ENTRY *function, char *lib, char *func)
{
	ENTRY   *e;

	errlog(BEGIN, "generate_i_prints() {");
	if ((e = symtab_get_first_arg()) != NULL || !is_void(e)) {
		/* Then we have to generate code for verbose reports. */
		(void) fprintf(Bodyfp,  "    if (ABI_VFLAG(%s, %s) != 0) {\n",
			lib, func);
		generate_printfunc_calls(function);
		(void) fprintf(Bodyfp,  "    }\n");
	}
	(void) putc('\n', Bodyfp);
	errlog(END, "}");
}

/*
 * generate_i_closedown -- restore error variables and return.
 */
static void
generate_i_closedown(char *error_name, int void_func)
{
	errlog(BEGIN, "generate_i_closedown() {");

	/* unlock stdio */
	(void) fprintf(Bodyfp,
	    "    abiunlock(&omask);\n");

	if (*error_name != '\0') {
		/* Restore error variables. */
		(void) fprintf(Bodyfp,
		    "    %s = (functions_errvar == 0)? "
		    "            saved_errvar: functions_errvar;\n",
		    error_name);
	}

	/* And return. */
	(void) fprintf(Bodyfp,
	    "    return%s;\n",
	    (void_func)? "": " _return");
	(void) fprintf(Bodyfp,  "}\n");
	(void) putc('\n', Bodyfp);
	errlog(END, "}");
}


/*
 * generate_i_live_vars -- generate temps for any ``out''
 *	or ``inout'' variables in the function.  Deferred.
 */
/*ARGSUSED*/
static void
generate_i_live_vars(ENTRY *function)
{
	errlog(BEGIN, "generate_i_live_vars() {");
	errlog(END, "}");
}

/*
 * generate_i_evaluations -- generate evaluations for
 *	all the expressions. Deferred.
 */
/*ARGSUSED*/
static void
generate_i_evaluations(ENTRY *function)
{
	errlog(BEGIN, "generate_i_evaluations() {");
	errlog(END, "}");
}


static char *
variables_get_errorname(void)
{
	return ("ABI_ERRNO");
}
