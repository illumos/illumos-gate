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
 * Copyright 1995 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Included files
 */
#include <libintl.h>

#include <mk/defs.h>
#include <mksh/misc.h>		/* getmem() */

/*
 * This file deals with "Dependency Variables".
 * The "-V var" command line option is used to indicate
 * that var is a dependency variable.  Used in conjunction with
 * the -P option the user is asking if the named variables affect
 * the dependencies of the given target.
 */

struct _Depvar {
	Name		name;		/* Name of variable */
	struct _Depvar	*next;		/* Linked list */
	Boolean		cmdline;	/* Macro defined on the cmdline? */
};

typedef	struct _Depvar	*Depvar;

static	Depvar		depvar_list;
static	Depvar		*bpatch = &depvar_list;
static	Boolean		variant_deps;

/*
 * Add a name to the list.
 */

void
depvar_add_to_list(Name name, Boolean cmdline)
{
	Depvar		dv;

	dv = ALLOC(Depvar);
	dv->name = name;
	dv->next = NULL;
	dv->cmdline = cmdline;
	*bpatch = dv;
	bpatch = &dv->next;
}

/*
 * The macro `name' has been used in either the left-hand or
 * right-hand side of a dependency.  See if it is in the
 * list.  Two things are looked for.  Names given as args
 * to the -V list are checked so as to set the same/differ
 * output for the -P option.  Names given as macro=value
 * command-line args are checked and, if found, an NSE
 * warning is produced.
 */
void
depvar_dep_macro_used(Name name)
{
	Depvar		dv;

	for (dv = depvar_list; dv != NULL; dv = dv->next) {
		if (name == dv->name) {
			variant_deps = true;
			break;
		}
	}
}


/*
 * Print the results.  If any of the Dependency Variables
 * affected the dependencies then the dependencies potentially
 * differ because of these variables.
 */
void
depvar_print_results(void)
{
	if (variant_deps) {
		printf(gettext("differ\n"));
	} else {
		printf(gettext("same\n"));
	}
}

