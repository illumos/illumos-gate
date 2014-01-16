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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.6	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "stdio.h"
#include "stdlib.h"

#include "lp.h"

/**
 ** getdefault() - READ THE NAME OF THE DEFAULT DESTINATION FROM DISK
 **/

char *
getdefault(void)
{
	return (loadline(Lp_Default));
}

/**
 ** putdefault() - WRITE THE NAME OF THE DEFAULT DESTINATION TO DISK
 **/

int
putdefault(char *dflt)
{
	int fd;

	if (!dflt || !*dflt)
		return (deldefault());

	if ((fd = open_locked(Lp_Default, "w", MODE_READ)) < 0)
		return (-1);

	fdprintf(fd, "%s\n", dflt);

	close(fd);
	return (0);
}

/**
 ** deldefault() - REMOVE THE NAME OF THE DEFAULT DESTINATION
 **/

int
deldefault(void)
{
	return (rmfile(Lp_Default));
}
