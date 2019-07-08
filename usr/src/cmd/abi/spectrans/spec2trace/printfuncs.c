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
 * Copyright (c) 1997-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "parser.h"
#include "trace.h"
#include "util.h"
#include "db.h"
#include "symtab.h"
#include "io.h"
#include "printfuncs.h"
#include "errlog.h"

static int	 prepare_printf_part(ENTRY *, char *, char *, int);
static char	 *space_to_uscore(char const *);

static char	arglist[_POSIX_ARG_MAX];

/*
 * generate_printf -- make the cleanest possible printf for the
 *	parameters, in a relatively terse apptrace/dbx-like format,
 *	ending in ") = ", or ) if its a void function we're doing.
 */
void
generate_printf(ENTRY *f)
{
	ENTRY	*e;
	char	*p, *name;
	int	l, n;

	errlog(BEGIN, "generate_printf");
	(void) fprintf(Bodyfp, "    fprintf(ABISTREAM, \"");
	p = &arglist[0];
	l = (int)sizeof (arglist);
	*p = '\0';
	for (e = symtab_get_first_arg(); e != NULL; e = symtab_get_next_arg()) {
		errlog(TRACING, "arglist = '%s'", arglist);

		if (is_void(e)) {
			/* This placeholder means there are no real args. */
			break;
		}
		/* Insert punctuation. */
		if (p != &arglist[0]) {
			(void) fprintf(Bodyfp, ", ");
		}
		if (*(name =  name_of(e)) == '\0') {
			/* It's a varargs indicator instead */
			(void) fprintf(Bodyfp, "...");
		} else {
			(void) fprintf(Bodyfp, "%s = ", name);
			n = prepare_printf_part(e, name, p, l);
			l -= n;
			p += n;
			*(p+1) = '\0';
		}
	}

	if (is_void(f) || symtab_get_nonreturn() == YES) {
		/* It is a function returning void, or a function */
		/* which doesn't return. Close off args. */
		(void) fprintf(Bodyfp, ")\"");
	} else {
		/* Make some more printf for the return type. */
		(void) fprintf(Bodyfp, ") = ");
		(void) prepare_printf_part(f, "_return", p, l);
		(void) fprintf(Bodyfp, "\"");

	}
	(void) fprintf(Bodyfp, "%s);\n", arglist);
	errlog(END, "}");
}


/*
 * prepare_printf_part -- do one element of a printf/argument string,
 *	for printing non-verbose parameter lists
 */
static int
prepare_printf_part(ENTRY *e, char *name, char *place, int size)
{
	char	*bt;
	int	li;

	errlog(BEGIN, "prepare_printf_part() {");
	errlog(TRACING, "name = '%s'", name);

	bt = basetype_of(e);
	li = levels_of(e);

	if (li == 1 && (strcmp(bt, "char") == 0)) {
		/* It's a string, print the beginning of it. */
		(void) fputs("\\\"%.*s\\\"", Bodyfp);
		size = snprintf(place, size,
		    /*CSTYLED*/
		    ",\n\tabi_strpsz, (%s) ? %s : nilstr",
		    name, name);
	} else {
		/* Just print a hex value */
		(void) fprintf(Bodyfp, "%s", "0x%p");
		size = snprintf(place, size, ", \n\t%s", name);
	}

	errlog(TRACING, "place='%s'\n", place);
	errlog(END, "}");
	return (size);

}


/*
 * generate_printfunc_calls -- generate print commands for primitive types
 *	and calls to print functions for composite types, cleanly.
 *	Needs to know about base types of primitives, difference
 *	between primitives and composite types: TBD.
 */
void
generate_printfunc_calls(ENTRY *f)
{
	ENTRY	*e;
	char	*name;
	char	*pf_str_name;
	int	li;
	char	*format;

	errlog(BEGIN, "generate_printfunc_calls() {");
	for (e = symtab_get_first_arg(); e != NULL; e = symtab_get_next_arg()) {
		if (is_void(e)) {
			break;
		}
		if (*(name = name_of(e)) == '\0') {
			(void) fprintf(Bodyfp, "        fputs(\"  ...\\n\", "
				"ABISTREAM);\n");
		}
		errlog(TRACING, "name = '%s'\n", name);
		(void) fprintf(Bodyfp,
		    "        fprintf(ABISTREAM, \"  %s = \");\n",
		    name);

		pf_str_name = space_to_uscore(basetype_of(e));

		/*
		 * If we're dealing with a scalar (non-pointer) then
		 * we need to call the printer with a &
		 */
		li = levels_of(e);
		if (li)
			format = "\tspf_prtype(ABISTREAM, pf_%s_str, %d, "
			    "(void const *)%s);\n";
		else
			format = "\tspf_prtype(ABISTREAM, pf_%s_str, %d, "
			    "(void const *)&%s);\n";

		(void) fprintf(Bodyfp, format, pf_str_name, li, name);

		free(pf_str_name);
	}

	if (is_void(f)) {
		/*EMPTY*/;
	} else {
		pf_str_name = space_to_uscore(basetype_of(f));

		li = levels_of(f);
		if (li)
			format = "\tspf_prtype(ABISTREAM, pf_%s_str, %d, "
			    "(void const *)_return);\n";
		else
			format = "\tspf_prtype(ABISTREAM, pf_%s_str, %d, "
			    "(void const *)&_return);\n";

		(void) fputs("        fputs(retstr, ABISTREAM);\n", Bodyfp);
		(void) fprintf(Bodyfp, format, pf_str_name, li);

		free(pf_str_name);
	}

	errlog(END, "}");
}


/*
 * Print Function Pointers -- definition, declaration and initialization.
 *	Use is above...
 */

/*
 * generate_print_definitions -- generate variable definitions and
 *	initialize them to NULL.
 *      These will be set non-null by a lazy evaluation in the
 *	main.c file if and only if the print function will be used.
 *	All print functions which can be called must be defined.
 */
void
generate_print_definitions(FILE *fp)
{
	char	*print_type,
		*c_type,
		*pf_str_name;

	errlog(BEGIN, "generate_print_definitions() {");
	for (print_type = db_get_first_print_type();
		print_type != NULL;
			print_type = db_get_next_print_type()) {
		c_type = strchr(print_type, ','); /* Safe by construction. */
		*c_type++ = '\0';
		errlog(TRACING,  "print_type=%s\n", print_type);

		pf_str_name = space_to_uscore(print_type);

		(void) fprintf(fp,
		    "char const *pf_%s_str = \"%s\";\n",
		    pf_str_name, print_type);

		free(pf_str_name);

		*--c_type = ',';
	}

	errlog(END, "}");
}

/*
 * generate_print_declarations -- generate variable declarations
 *	for the strings that'll be used as arguments to the type
 *	printing function.
 */
void
generate_print_declarations(FILE *fp)
{
	char	*print_type,
		*c_type,
		*pf_str_name;

	errlog(BEGIN, "generate_print_declarations() {");
	for (print_type = symtab_get_first_print_type();
	    print_type != NULL;
	    print_type = symtab_get_next_print_type()) {

		errlog(TRACING,  "print_type, c_type=%s\n", print_type);

		c_type = strchr(print_type, ','); /* Safe by construction. */
		*c_type++ = '\0';

		pf_str_name = space_to_uscore(print_type);

		(void) fprintf(fp, "extern char const *pf_%s_str;\n",
		    pf_str_name);

		free(pf_str_name);

		*--c_type = ',';
	}

	errlog(END, "}");
}

/*
 * is_void -- see if a type is void.
 */
int
is_void(ENTRY *e)
{
	if ((e != NULL) &&
	    levels_of(e) == 0 && (strcmp(basetype_of(e), "void") == 0))
		return (1);
	else
		return (0);
}

static char *
space_to_uscore(char const *str)
{
	char *strp, *p;

	strp = strdup(str);

	assert(strp != NULL, "strdup failed");

	for (p = strp; *p != '\0'; p++)
		if (*p == ' ')
			*p = '_';

	return (strp);
}
