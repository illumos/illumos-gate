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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "stdio.h"
#include "string.h"
#include "errno.h"
#include "sys/types.h"
#include <syslog.h>

#include "lp.h"
#include "class.h"

/**
 ** getclass() - READ CLASS FROM TO DISK
 **/

CLASS *
getclass(char *name)
{
	static long		lastdir		= -1;

	CLASS		*clsp;

	char			*file,
				buf[BUFSIZ];

	int fd;

	syslog(LOG_DEBUG, "getclass(%s)", name ? name : "");

	if (!name || !*name) {
		errno = EINVAL;
		return (0);
	}

	/*
	 * Getting ``all''? If so, jump into the directory
	 * wherever we left off.
	 */
	if (STREQU(NAME_ALL, name)) {
		if (!(name = next_file(Lp_A_Classes, &lastdir)))
			return (0);
	} else
		lastdir = -1;

	/*
	 * Get the class list.
	 */

	if (!(file = getclassfile(name)))
		return (0);

	if ((fd = open_locked(file, "r", 0)) < 0) {
		Free (file);
		return (0);
	}
	Free (file);

	clsp = (CLASS *)calloc(sizeof (*clsp), 1);

	if (!(clsp->name = Strdup(name))) {
		Free (clsp);
		close(fd);
		errno = ENOMEM;
		return (0);
	}

	clsp->members = 0;
	errno = 0;
	while (fdgets(buf, BUFSIZ, fd)) {
		buf[strlen(buf) - 1] = 0;
		addlist (&clsp->members, buf);
	}
	if (errno != 0) {
		int			save_errno = errno;

		freelist (clsp->members);
		Free (clsp->name);
		Free (clsp);
		close(fd);
		errno = save_errno;
		return (0);
	}
	close(fd);

	if (!clsp->members) {
		Free (clsp->name);
		Free (clsp);
		errno = EBADF;
		return (0);
	}

	return (clsp);
}
