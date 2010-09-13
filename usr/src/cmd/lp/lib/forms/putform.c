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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.10	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "sys/types.h"
#include "sys/stat.h"
#include "stdio.h"
#include "string.h"
#include "errno.h"
#include "stdlib.h"

#include "lp.h"
#include "form.h"

/**
 ** putform() - WRITE FORM STRUCTURE TO DISK FILES
 **/

int
putform(char *name, FORM *formp, FALERT *alertp, FILE **p_align_fp)
{
	register char *		path;

	int fd;

	struct stat		statbuf;


	if (!name || !*name) {
		errno = EINVAL;
		return (-1);
	}

	if (STREQU(NAME_ALL, name)) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Create the parent directory for this form
	 * if it doesn't yet exist.
	 */
	if (!(path = getformfile(name, (char *)0)))
		return (-1);
	if (Stat(path, &statbuf) == 0) {
		if (!S_ISDIR(statbuf.st_mode)) {
			Free (path);
			errno = ENOTDIR;
			return (-1);
		}
	} else if (errno != ENOENT || mkdir_lpdir(path, MODE_DIR) == -1) {
		Free (path);
		return (-1);
	}
	Free (path);

	/*
	 * Open the configuration file and write out the form
	 * configuration (?)
	 */
	if (formp) {
		if (!(path = getformfile(name, DESCRIBE)))
			return (-1);
		if ((fd = open_locked(path, "w", MODE_READ)) < 0) {
			Free (path);
			return (-1);
		}
		Free (path);

		if (wrform(name, formp, fd, 0, (int *)0) == -1) {
			close(fd);
			return (-1);
		}
		close(fd);
	}

	/*
	 * Write out the alert condition (?)
	 */
	if (alertp) {
		if (
			alertp->shcmd
		     && putalert(Lp_A_Forms, name, alertp) == -1
		)
			return (-1);
	}

	/*
	 * Write out the alignment pattern (?)
	 */
	if (p_align_fp && *p_align_fp) {

		int			size	= 0,
					n;

		char			buf[BUFSIZ];


		if (!(path = getformfile(name, ALIGN_PTRN)))
			return (-1);
		if ((fd = open_locked(path, "w", MODE_READ)) < 0) {
			Free (path);
			return (-1);
		}

		while ((n = fread(buf, 1, BUFSIZ, *p_align_fp)) != 0) {
			size += n;
			write (fd, buf, n);
		}
		close(fd);

		if (!size)
			Unlink(path);

		Free(path);
	}

	return (0);
}
