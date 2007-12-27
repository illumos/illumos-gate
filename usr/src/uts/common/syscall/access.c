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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/isa_defs.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/cred_impl.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/pathname.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/file.h>
#include <fs/fs_subr.h>
#include <c2/audit.h>

/*
 * Determine accessibility of file.
 */

#define	E_OK	010	/* use effective ids */
#define	R_OK	004
#define	W_OK	002
#define	X_OK	001

static int
caccess(char *fname, int fmode, vnode_t *startvp)
{
	vnode_t *vp;
	cred_t *tmpcr;
	int error;
	int mode;
	int eok;
	cred_t *cr;
	int estale_retry = 0;

	if (fmode & ~(E_OK|R_OK|W_OK|X_OK))
		return (set_errno(EINVAL));

	mode = ((fmode & (R_OK|W_OK|X_OK)) << 6);

	cr = CRED();

	/* OK to use effective uid/gid, i.e., no need to crdup(CRED())? */
	eok = (fmode & E_OK) ||
	    (cr->cr_uid == cr->cr_ruid && cr->cr_gid == cr->cr_rgid);

	if (eok)
		tmpcr = cr;
	else {
		tmpcr = crdup(cr);
		tmpcr->cr_uid = cr->cr_ruid;
		tmpcr->cr_gid = cr->cr_rgid;
		tmpcr->cr_ruid = cr->cr_uid;
		tmpcr->cr_rgid = cr->cr_gid;
	}

lookup:
	if (error = lookupnameat(fname, UIO_USERSPACE, FOLLOW, NULLVPP, &vp,
	    startvp)) {
		if ((error == ESTALE) && fs_need_estale_retry(estale_retry++))
			goto lookup;
		if (!eok)
			crfree(tmpcr);
		return (set_errno(error));
	}

	if (mode) {
		error = VOP_ACCESS(vp, mode, 0, tmpcr, NULL);
		if (error) {
			if ((error == ESTALE) &&
			    fs_need_estale_retry(estale_retry++)) {
				VN_RELE(vp);
				goto lookup;
			}
			(void) set_errno(error);
		}
	}

	if (!eok)
		crfree(tmpcr);
	VN_RELE(vp);
	return (error);
}

int
access(char *fname, int fmode)
{
	return (caccess(fname, fmode, NULL));
}

int
accessat(int fd, char *fname, int fmode)
{
	file_t *dirfp;
	vnode_t *dirvp;
	int error;
	char startchar;

	if (fd == AT_FDCWD && fname == NULL)
		return (set_errno(EFAULT));

	if (fname != NULL) {
		if (copyin(fname, &startchar, sizeof (char)))
			return (set_errno(EFAULT));
	} else
		startchar = '\0';

	if (fd == AT_FDCWD) {
		dirvp = NULL;
	} else {
		if (startchar != '/') {
			if ((dirfp = getf(fd)) == NULL) {
				return (set_errno(EBADF));
			}
			dirvp = dirfp->f_vnode;
			VN_HOLD(dirvp);
			releasef(fd);
		} else {
			dirvp = NULL;
		}
	}

	if (audit_active)
		audit_setfsat_path(1);

	error = caccess(fname, fmode, dirvp);
	if (dirvp != NULL)
		VN_RELE(dirvp);

	return (error);
}
