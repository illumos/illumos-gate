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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5	*/

#include "stdio.h"
#include "errno.h"
#include "sys/types.h"

#include "lp.h"
#include "printers.h"

#define	WHO_AM_I	I_AM_LPADMIN
#include "oam.h"

#include "lpadmin.h"


/**
 ** getdflt() - RETURN DEFAULT DESTINATION
 **/

char			*getdflt ()
{
	char			*name;

	if ((name = getdefault()))
		return (name);
	else
		return ("");
}

/**
 ** newdflt() - ESTABLISH NEW DEFAULT DESTINATION
 **/

void			newdflt (name)
	char			*name;
{
	BEGIN_CRITICAL
		if (name && *name && !STREQU(name, NAME_NONE)) {
			if (putdefault(name) == -1) {
				LP_ERRMSG1 (ERROR, E_ADM_WRDEFAULT, PERROR);
				done (1);
			}

		} else {
			if (deldefault() == -1) {
				LP_ERRMSG1 (ERROR, E_ADM_WRDEFAULT, PERROR);
				done (1);
			}

		}
	END_CRITICAL

	return;
}
