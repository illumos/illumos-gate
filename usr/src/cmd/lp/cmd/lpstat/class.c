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


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5	*/

#include <locale.h>
#include "stdio.h"

#include "lp.h"
#include "class.h"

#define	WHO_AM_I	I_AM_LPSTAT
#include "oam.h"

#include "lpstat.h"


#if	defined(__STDC__)
static void		putcline ( CLASS * );
#else
static void		putcline();
#endif

/**
 ** do_class()
 **/

void
#if	defined(__STDC__)
do_class (
	char **			list
)
#else
do_class (list)
	char			**list;
#endif
{
	register CLASS		*pc;

	printlist_setup ("\t", 0, 0, 0);
	while (*list) {
		if (STREQU(NAME_ALL, *list))
			while ((pc = getclass(NAME_ALL)))
				putcline (pc);

		else if ((pc = getclass(*list)))
			putcline (pc);

		else {
			LP_ERRMSG1 (ERROR, E_LP_NOCLASS, *list);
			exit_rc = 1;
		}
		list++;
	}
	printlist_unsetup ();
	return;
}

/**
 ** putcline()
 **/

static void
#if	defined(__STDC__)
putcline (
	CLASS *			pc
)
#else
putcline (pc)
	register CLASS		*pc;
#endif
{
	(void) printf(gettext("members of class %s:\n"), pc->name);
		printlist (stdout, pc->members);
	return;
}
