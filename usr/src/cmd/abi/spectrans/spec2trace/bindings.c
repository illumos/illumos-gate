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

#include <stdio.h>
#include <string.h>
#include "parser.h"
#include "trace.h"
#include "util.h"
#include "symtab.h"
#include "io.h"
#include "bindings.h"
#include "errlog.h"


/* File globals. */
static void generate_a_binding(char *, char *);

static int strpqcmp(char *, char *, char *);
static void strpqprint(char *, char *, FILE *);

/*
 * Bindings: do three-valued logic, where a binding can be
 *	an expression to evaluate for truthfulness,
 *	true,
 *	false, or
 *	empty.
 *
 *	Exception	Result	Evaluate?	Notes
 *	---------	------	---------	-----
 *
 *	true		ok	yes		warn[1]
 *	false		ok	no
 *	empty		ok	no		treat as true
 *	expr		ok	yes		s = !e
 *
 * Notes:
 *	[1] Always exceptional, shows errno at run-time
 *
 */

/*
 * need_bindings -- see if we have to do anything at all. Implements
 *	the following rows from the table above (die and evaluate=no lines)
 *	Returns NO if we don't have to evaluate bindings at all.
 *
 *	Exception	Result	Evaluate?	Notes
 *	---------	------	---------	-----
 *	false		ok	no
 *	empty		ok	no		treat as true
 */
int
need_bindings(char *exception)
{

	errlog(BEGIN, "need_bindings() {");

	if (exception == NULL)
		exception = "";

	/*	empty		false		ok	no */
	/*	empty		empty		ok	no, treat as true */
	if (strcmp(exception, "false") == 0 ||
	    *exception == '\0') {
		errlog(END, "}");
		return (NO);
	}
	errlog(END, "}");
	return (YES);
}


int
need_exception_binding(void)
{
	ENTRY	*e;
	char *exception;

	exception = ((e = symtab_get_exception()) != NULL)?
	    (name_of(e)? name_of(e): ""): "";

	return (need_bindings(exception));

}

/*
 * generate_bindings -- make the code for exception bindings
 *
 *	Exception	Result	Evaluate?	Notes
 *	---------	------	---------	-----
 *	true		ok	yes		warn[2]
 *	expr		ok	yes		s::= !e
 *
 *	Returns NO if we need both bindings, YES (ANTONYM) if we
 *	only need to evaluate success.
 */
int
generate_bindings(char *exception)
{
	int ret = NO;

	errlog(BEGIN, "generate_bindings() {");
	errlog(TRACING,  "exception=%s\n", exception ? exception : "NULL");

	/* Exception	Result	Evaluate?	Notes	*/
	/* ---------	------	---------	-----	*/
	/* true		ok	yes		warn[2] */
	if (exception != NULL) {
		generate_a_binding("exception", exception);
		errlog(END, "}");
	}

	return (ret);
}

/*
 * bindings_exist -- make sure we don't use one if they're not there.
 */
int
bindings_exist(void)
{
	int ret;

	errlog(BEGIN, "bindings_exist() {");
	errlog(END, "}");

	ret = validity_of(symtab_get_exception()) == YES;

	return (ret);
}



/*
 * generate_a_binding -- generate just one, with a set of transformations
 *	applied. Eg, return->_return, errno->functions_errvar,
 *	unchanged(x)->x == 0, etc. Oneof and someof TBD.
 */
static void
generate_a_binding(char *name, char *value)
{
	char *p = value;
	ENTRY	*e = symtab_get_errval();
	char	*errvar = (e == NULL)? NULL: name_of(e);
	char	*q;

	errlog(BEGIN, "generate_a_binding() {");
	if (*value == '\0') {
		errlog(FATAL, "programmer error: asked to generate an "
			"empty binding");
	}

	{
		/*
		 * XXX - friggin spaghetti
		 */
		ENTRY	*exc = symtab_get_exception();

		if (exc != NULL)
			(void) fprintf(Bodyfp,
			    "#line %d \"%s\"\n",
			    line_of(exc), symtab_get_filename());
	}

	/* Generate prefix. */
	(void) fprintf(Bodyfp, "    %s = (", name);

	/* Walk across line, emitting tokens and transformed tokens */

	for (; *p != '\0'; p = q) {
		p = skipb(p);
		q = nextsep(p);

		if (p == q) {
			/* We're at the end, a "(", ")" or an operator. */
			if (*p == '(') {
				/* We're at a parenthesized expression */
				q++;
			} else if (*p == ')') {
				/* And the end of an expression. */
				q++;
			} else if (*p == '!' && *(p+1) != '=') {
				/* Or a negated expression */
				q++;
			} else if ((q = nextb(p)) == p) {
				/* Real end! */
				break;
			}

			/* Else it was an operator, boogy onwards. */
		}
		if (strpqcmp("$return", p, q) == 0) {
			(void) fputs("_return", Bodyfp);
		} else if (errvar != NULL && strpqcmp(errvar, p, q) == 0) {
			(void) fputs("functions_errvar", Bodyfp);
		} else if (strpqcmp("unchanged", p, q) == 0) {
			/* This will look odd. */
			(void) fputs("0 == ", Bodyfp);
		} else if (strpqcmp("oneof", p, q) == 0) {
			errlog(WARNING,  "Oneof unimplemented in spec2trace"
				"It will be treated as the token 'false'");
			(void) fputs("false", Bodyfp);
			break;
		} else if (strpqcmp("someof", p, q) == 0) {
			errlog(WARNING, "Someof unimplemented in spec2trace, "
				"It will be treated as the token 'false'");
			(void) fputs("false", Bodyfp);
			break;
		} else if (strpqcmp("errno", p, q) == 0) {
			(void) fputs("ABI_ERRNO", Bodyfp);
		} else {
			/* Just copy it. */

			strpqprint(p, q, Bodyfp);
		}
		(void) putc(' ', Bodyfp);
	}
	(void) (void) fputs(");\n", Bodyfp);
	errlog(END, "}");
}

/*
 * strpqcmp -- compare a null-terminated string with a pq-bracketed string.
 */
static int
strpqcmp(char *v1, char *p, char *q)
{
	int	rc;
	char	saved;

	errlog(BEGIN, "strpqcmp() {");
	saved = *q;
	*q = '\0';
	rc = (strcmp(v1, p));
	*q = saved;
	errlog(END, "}");
	return (rc);
}

/*
 * strpqprint -- print a pq-bracketed string
 */
static void
strpqprint(char *p, char *q, FILE *fp)
{
	char	saved;

	errlog(BEGIN, "strpqprint() {");
	saved = *q;
	*q = '\0';
	(void) fputs(p, fp);
	*q = saved;
	errlog(END, "}");
}
