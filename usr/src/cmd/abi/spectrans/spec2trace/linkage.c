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

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include "parser.h"
#include "trace.h"
#include "util.h"
#include "db.h"
#include "symtab.h"
#include "io.h"
#include "printfuncs.h"
#include "errlog.h"
#include "parseproto.h"

static void generate_interface_predeclaration(char *, ENTRY *);
static void generate_linkage_function(char *, char *);


/*
 * generate_linkage -- make code for the linkage part of an individual
 *	interface. Assumes Bodyfp.
 */
void
generate_linkage(ENTRY *function)
{
	char	*library_name = db_get_current_library(),
		*function_name;
	char	composite_name[MAXLINE];

	errlog(BEGIN, "generate_linkage() {");

	function_name = name_of(function);
	(void) snprintf(composite_name, sizeof (composite_name),
		"%s_%s", library_name, function_name);

	/* Print the predeclaration of the interceptor. */
	generate_interface_predeclaration(composite_name, function);
	/* Collect things we'll use more than once. */

	/* Next the struct used to pass parameters. */
	(void) fprintf(Bodyfp, "static abisym_t __abi_%s_%s_sym;\n",
		library_name, function_name);

	/* The linkage function, */
	generate_linkage_function(library_name, function_name);

	(void) fputs("\n\n", Bodyfp);
	errlog(END, "}");
}


/*
 *  generate_interface_predeclaration -- make things know so the compiler
 *	won't kak.
 */
static void
generate_interface_predeclaration(char *composite_name, ENTRY *function)
{
	decl_t *pp;
	char *p = symtab_get_prototype();
	char buf[BUFSIZ];

	(void) fprintf(Bodyfp, "\n/* from \"%s\", line %d */\n",
		symtab_get_filename(), line_of(function));
	(void) fprintf(Bodyfp, "static ");

	if (p[strlen(p)-1] != ';')
		(void) snprintf(buf, BUFSIZ, "%s;", strnormalize(p));
	else
		(void) snprintf(buf, BUFSIZ, "%s", strnormalize(p));

	decl_Parse(buf, &pp);
	decl_AddArgNames(pp);
	symtab_set_prototype(decl_ToString(buf, DTS_DECL, pp, composite_name));
	(void) fprintf(Bodyfp, "%s;\n", symtab_get_prototype());
	decl_Destroy(pp);
}



/*
 * generate_linkage_function --  The linkage function itself.
 */
static void
generate_linkage_function(char *lib, char *func)
{
	(void) fprintf(Bodyfp,
	    "void *__abi_%s_%s(void *real, int vflag) { \n", lib, func);
	(void) fprintf(Bodyfp, "    ABI_REAL(%s, %s) = real;\n", lib, func);
	(void) fprintf(Bodyfp, "    ABI_VFLAG(%s, %s) = vflag;\n", lib, func);
	(void) fprintf(Bodyfp,
	    "    return ((void *) %s_%s);\n}\n", lib, func);
}
