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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <sys/param.h>
#include <sys/isa_defs.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/debug.h>
#include <sys/file.h>
#include <sys/fcntl.h>

/*
 * Rename a file relative to a given directory
 */
int
renameat(int fromfd, char *old, int tofd, char *new)
{
	file_t *fromfp;
	file_t *tofp;
	vnode_t	*fromvp, *tovp;
	int error;
	proc_t *p = curproc;
	char oldstart, newstart;

	tovp = fromvp = NULL;

	if ((fromfd == AT_FDCWD && old == NULL) ||
	    (tofd == AT_FDCWD && new == NULL))
		return (set_errno(EFAULT));

	if (fromfd == AT_FDCWD || tofd == AT_FDCWD) {
		mutex_enter(&p->p_lock);
		if (fromfd == AT_FDCWD) {
			fromvp = PTOU(p)->u_cdir;
			VN_HOLD(fromvp);
		}
		if (tofd == AT_FDCWD) {
			tovp = PTOU(p)->u_cdir;
			VN_HOLD(tovp);
		}
		mutex_exit(&p->p_lock);
	}

	if (copyin(old, &oldstart, sizeof (char)))
		return (set_errno(EFAULT));

	if (copyin(new, &newstart, sizeof (char)))
		return (set_errno(EFAULT));

	if (fromvp == NULL) {
		if (oldstart != '/') {
			if ((fromfp = getf(fromfd)) == NULL) {
				if (tovp != NULL)
					VN_RELE(tovp);
				return (set_errno(EBADF));
			}
			fromvp = fromfp->f_vnode;
			VN_HOLD(fromvp);
			releasef(fromfd);
		} else {
			fromvp = NULL;
		}
	}

	if (tovp == NULL) {
		if (newstart != '/') {
			if ((tofp = getf(tofd)) == NULL) {
				if (fromvp != NULL)
					VN_RELE(fromvp);
				return (set_errno(EBADF));
			}
			tovp = tofp->f_vnode;
			VN_HOLD(tovp);
			releasef(tofd);
		} else {
			tovp = NULL;
		}
	}

	error = vn_renameat(fromvp, old, tovp, new, UIO_USERSPACE);

	if (fromvp != NULL)
		VN_RELE(fromvp);
	if (tovp != NULL)
		VN_RELE(tovp);
	if (error != 0)
		return (set_errno(error));
	return (error);
}

int
rename(char *old, char *new)
{
	return (renameat(AT_FDCWD, old, AT_FDCWD, new));
}
