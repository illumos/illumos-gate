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


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "stdio.h"
#include "errno.h"
#include "sys/types.h"
#include "string.h"

#include "lp.h"
#include "class.h"

/**
 ** putclass() - WRITE CLASS OUT TO DISK
 **/

int
putclass(char *name, CLASS *clsbufp)
{
	char			*file;
	int fd;

	if (!name || !*name) {
		errno = EINVAL;
		return (-1);
	}

	if (STREQU(NAME_ALL, name)) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Open the class file and write out the class members.
	 */

	if (!(file = getclassfile(name)))
		return (-1);

	if ((fd = open_locked(file, "w", MODE_READ)) < 0) {
		Free (file);
		return (-1);
	}
	Free (file);

	errno = 0;
	fdprintlist(fd, clsbufp->members);
	if (errno != 0) {
		close(fd);
		return (-1);
	}
	close(fd);

	return (0);
}
