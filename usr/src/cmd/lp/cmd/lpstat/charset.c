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
 * Copyright 1991 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.6	*/

#include "string.h"
#include "sys/types.h"
#include "stdlib.h"

#include "lp.h"
#include "form.h"
#include "access.h"
#include "printers.h"

#define	WHO_AM_I	I_AM_LPSTAT
#include "oam.h"

#include "lpstat.h"
#include <locale.h>

extern char		*tparm();

#if	defined(__STDC__)
static void		putsline ( MOUNTED * );
#else
static void		putsline();
#endif

/**
 ** do_charset()
 **/

void
#if	defined(__STDC__)
do_charset (
	char **			list
)
#else
do_charset (list)
	char **			list;
#endif
{
	register MOUNTED *	pm;

	register int		found;


	while (*list) {
		if (STREQU(NAME_ALL, *list))
			for (pm = mounted_pwheels; pm->name; pm = pm->forward)
				putsline (pm);

		else {
			found = 0;
			for (pm = mounted_pwheels; pm->name; pm = pm->forward)
				if (
					pm->name[0] == '!'
				     && STREQU(pm->name + 1, *list)
				     || STREQU(pm->name, *list)
				) {
					putsline (pm);
					found = 1;
				}
			if (!found) {
				LP_ERRMSG1 (ERROR, E_STAT_BADSET, *list);
				exit_rc = 1;
			}
		}
		list++;
	}
	return;
}

/**
 ** putsline()
 **/

static void
#if	defined(__STDC__)
putsline (
	MOUNTED *		pm
)
#else
putsline (pm)
	register MOUNTED	*pm;
#endif
{
	register char **	pp;
	register char *		sep;


	if (pm->name[0] != '!') {

		if ((pp = pm->printers))
			if (verbosity & V_LONG) {
				(void)printf (gettext("print wheel %s\n\tavailable on:"), pm->name);
				while (*pp) {
					if ((*pp)[0] == '!')
						(void)printf (
							gettext("\n\t\t%s (mounted)"),
							*pp + 1
						);
					else
						(void)printf ("\n\t\t%s", *pp);
					pp++;
				}
			} else {
				sep = ", mounted on ";
				while (*pp) {
					if ((verbosity & V_LONG) || (*pp)[0] == '!') {
						(void)printf (
							"%s%s",
							sep,
					((*pp)[0] == '!'? *pp + 1 : *pp)
						);
						sep = ",";
					}
					pp++;
				}
			}

		(void)printf ("\n");

	} else {

		(void)printf (gettext("character set %s\n"), pm->name + 1);

		if ((verbosity & V_LONG) && (pp = pm->printers)) {
			(void)printf (gettext("\tavailable on:\n"));
			while (*pp) {
				(void)printf (
					"\t\t%s (as %s)\n",
					strtok(*pp, "="),
					strtok((char *)0, "=")
				);
				pp++;
			}
		}

	}
	return;
}

/**
 ** get_charsets() - CONSTRUCT (char **) LIST OF CHARSETS FROM csnm
 **/

char **
#if	defined(__STDC__)
get_charsets (
	PRINTER *		prbufp,
	int			addcs
)
#else
get_charsets (prbufp, addcs)
	PRINTER			*prbufp;
	register int		addcs;
#endif
{
	register int		cs		= 0;

	register char *		name;

	register char **	pt;

	char *			csnm;
	char **			list		= 0;


	if (
		prbufp->printer_types
	     && !STREQU(*(prbufp->printer_types), NAME_UNKNOWN)
	     && !prbufp->daisy
	)
	  for (pt = prbufp->printer_types; *pt; pt++)
	    if (tidbit(*pt, "csnm", &csnm) != -1 && csnm && *csnm) {
		for (cs = 0; cs <= 63; cs++)
			if ((name = tparm(csnm, cs)) && *name) {

				if (addcs) {
					register char	 *nm = Malloc(
						2+2+1 + strlen(name) + 1
					);

					sprintf (nm, "cs%d=%s", cs, name);
					name = nm;
				}

				if (addlist(&list, name) == -1) {
					LP_ERRMSG (ERROR, E_LP_MALLOC);
					done (1);
				}

			} else
				/*
				 * Assume that a break in the
				 * numbers means we're done.
				 */
				break;
	    }

	return (list);
}
