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

#include "errno.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"

#include "lp.h"
#include "filters.h"

/**
 ** get_and_load() - LOAD REGULAR FILTER TABLE
 **/

int
get_and_load()
{
	register char		*file;

	if (!(file = getfilterfile(FILTERTABLE)))
		return (-1);
	if (loadfilters(file) == -1) {
		Free (file);
		return (-1);
	}
	Free (file);
	return (0);
}

/**
 ** open_filtertable()
 **/

int
open_filtertable(char *file, char *mode)
{
	int			freeit;

	int fd;

	if (!file) {
		if (!(file = getfilterfile(FILTERTABLE)))
			return (0);
		freeit = 1;
	} else
		freeit = 0;
	
	fd = open_locked(file, mode, MODE_READ);

	if (freeit)
		Free (file);

	return (fd);
}
