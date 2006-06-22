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


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.9	*/

#include <locale.h>
#include "sys/types.h"
#include "string.h"

#include "lp.h"
#include "printers.h"

#define	WHO_AM_I	I_AM_LPSTAT
#include "oam.h"

#include "lpstat.h"


#if	defined(__STDC__)
static void		putdline ( PRINTER * );
#else
static void		putdline();
#endif

/**
 ** do_device()
 **/

void
#if	defined(__STDC__)
do_device (
	char **			list
)
#else
do_device (list)
	char			**list;
#endif
{
	register PRINTER	*pp;


	while (*list) {
		if (STREQU(NAME_ALL, *list))
			while ((pp = getprinter(NAME_ALL)))
				putdline (pp);

		else if ((pp = getprinter(*list)))
			putdline (pp);

		else {
			LP_ERRMSG1 (ERROR, E_LP_NOPRINTER, *list);
			exit_rc = 1;
		}

		list++;
	}
	return;
}

/**
 ** putdline()
 **/

static void
#if	defined(__STDC__)
putdline (
	PRINTER *		pp
)
#else
putdline (pp)
	register PRINTER	*pp;
#endif
{
	if (!pp->device && !pp->dial_info && !pp->remote) {
		LP_ERRMSG1 (ERROR, E_LP_PGONE, pp->name);

	} else if (pp->remote) {
		char *			cp = strchr(pp->remote, BANG_C);


		if (cp)
			*cp++ = 0;
		(void)printf (gettext("system for %s: %s"), pp->name, pp->remote);
		if (cp)
			(void)printf (gettext(" (as printer %s)"), cp);
		(void)printf ("\n");

	} else if (pp->dial_info) {
		(void)printf (gettext("dial token for %s: %s"), pp->name, pp->dial_info);
		if (pp->device)
			(void)printf (gettext(" (on port %s)"), pp->device);
		(void)printf ("\n");

	} else {
		(void)printf (gettext("device for %s: %s"), pp->name, pp->device);
#if	defined(CAN_DO_MODULES)
		if (verbosity & V_MODULES)
			if (
				emptylist(pp->modules)
			     || STREQU(NAME_NONE, pp->modules[0])
			)
				(void)printf (gettext(" (no modules)"));
			else if (STREQU(NAME_KEEP, pp->modules[0]))
				(void)printf (gettext(" (keep startup modules)"));
			else if (STREQU(NAME_DEFAULT, pp->modules[0]))
				(void)printf (gettext(" %s (default)"), DEFMODULES);
			else {
				(void)printf (" ");
				printlist_setup ("", 0, ",", "");
				printlist (stdout, pp->modules);
				printlist_unsetup ();
			}
#endif
		(void)printf ("\n");
	}

	return;
}
