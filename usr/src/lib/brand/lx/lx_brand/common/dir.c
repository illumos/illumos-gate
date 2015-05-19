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
 * Copyright 2015 Joyent, Inc.
 */

#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/dirent.h>
#include <sys/lx_misc.h>
#include <sys/lx_debug.h>
#include <sys/lx_syscall.h>

#define	LX_NAMEMAX	256

struct lx_old_dirent {
	long		d_ino;  /* not l_ino_t */
	long		d_off;
	ushort_t	d_reclen;
	char 		d_name[LX_NAMEMAX];
};

/*
 * Read in one dirent structure from fd into dirp.
 * p3 (count) is ignored.
 */
/*ARGSUSED*/
long
lx_readdir(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int fd = (int)p1;
	struct lx_old_dirent *dirp = (struct lx_old_dirent *)p2;
	uint_t count = sizeof (struct lx_old_dirent);
	int rc = 0;
	struct lx_old_dirent _ld;
	struct dirent *sd = (struct dirent *)&_ld;

	/*
	 * The return value from getdents is not applicable, as
	 * it might have squeezed more than one dirent in the buffer
	 * we provided.
	 *
	 * getdents() will deal with the case of dirp == NULL
	 */
	if ((rc = getdents(fd, sd, count)) < 0)
		return (-errno);

	/*
	 * Set rc 1 (pass), or 0 (end of directory).
	 */
	rc = (sd->d_reclen == 0) ? 0 : 1;

	if (uucopy(sd, dirp, count) != 0)
		return (-errno);

	return (rc);
}
