/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 *     All Rights Reserved
 *
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 *
 * Copyright 2016 Joyent, Inc.
 */

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
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/mode.h>
#include <sys/lx_brand.h>
#include <sys/lx_fcntl.h>

/*
 * Determine accessibility of file.
 */

#define	E_OK	010	/* use effective ids */
#define	R_OK	004
#define	W_OK	002
#define	X_OK	001

/*
 * Convert Linux LX_AT_* flags to SunOS AT_* flags but skip verifying allowed
 * flags have been passed. This also allows EACCESS/REMOVEDIR to be translated
 * correctly since on linux they have the same value.
 *
 * Some code can actually pass in other bits in the flag. We may have to simply
 * ignore these, as indicated by the enforce parameter. See lx_fchmodat for
 * another example of this type of behavior.
 */
static int
ltos_at_flag(int lflag, int allow, boolean_t enforce)
{
	int sflag = 0;

	if ((lflag & LX_AT_EACCESS) && (allow & AT_EACCESS)) {
		lflag &= ~LX_AT_EACCESS;
		sflag |= AT_EACCESS;
	}

	if ((lflag & LX_AT_REMOVEDIR) && (allow & AT_REMOVEDIR)) {
		lflag &= ~LX_AT_REMOVEDIR;
		sflag |= AT_REMOVEDIR;
	}

	if ((lflag & LX_AT_SYMLINK_NOFOLLOW) && (allow & AT_SYMLINK_NOFOLLOW)) {
		lflag &= ~LX_AT_SYMLINK_NOFOLLOW;
		sflag |= AT_SYMLINK_NOFOLLOW;
	}

	/* right now solaris doesn't have a _FOLLOW flag, so use a fake one */
	if ((lflag & LX_AT_SYMLINK_FOLLOW) && (allow & LX_AT_SYMLINK_FOLLOW)) {
		lflag &= ~LX_AT_SYMLINK_FOLLOW;
		sflag |= LX_AT_SYMLINK_FOLLOW;
	}

	/* If lflag is not zero than some flags did not hit the above code. */
	if (enforce && lflag)
		return (-EINVAL);

	return (sflag);
}

/*
 * For illumos, access() does this:
 *    If the process has appropriate privileges, an implementation may indicate
 *    success for X_OK even if none of the execute file permission bits are set.
 *
 * But for Linux, access() does this:
 *    If the calling process is privileged (i.e., its real UID is zero), then
 *    an X_OK check is successful for a regular file if execute permission is
 *    enabled for any of the file owner, group, or other.
 *
 * Linux used to behave more like illumos on older kernels:
 *    In  kernel  2.4 (and earlier) there is some strangeness in the handling
 *    of X_OK tests for superuser.  If all categories of  execute  permission
 *    are  disabled for a nondirectory file, then the only access() test that
 *    returns -1 is when mode is specified as just X_OK; if R_OK or  W_OK  is
 *    also  specified in mode, then access() returns 0 for such files.
 *
 * So we need to handle the case where a privileged process is checking for
 * X_OK but none of the execute bits are set on the file. We'll keep the old
 * 2.4 behavior for 2.4 emulation but use the new behavior for any other
 * kernel rev.
 */
static int
lx_common_access(char *fname, int fmode, vnode_t *startvp)
{
	vnode_t *vp;
	cred_t *tmpcr;
	int error;
	int mode;
	cred_t *cr;
	int estale_retry = 0;

	if (fmode & ~(E_OK|R_OK|W_OK|X_OK))
		return (EINVAL);

	mode = ((fmode & (R_OK|W_OK|X_OK)) << 6);

	cr = CRED();

	/* OK to use effective uid/gid, i.e., no need to crdup(CRED())? */
	if ((fmode & E_OK) != 0 ||
	    (cr->cr_uid == cr->cr_ruid && cr->cr_gid == cr->cr_rgid)) {
		tmpcr = cr;
		crhold(tmpcr);
	} else {
		tmpcr = crdup(cr);
		tmpcr->cr_uid = cr->cr_ruid;
		tmpcr->cr_gid = cr->cr_rgid;
		tmpcr->cr_ruid = cr->cr_uid;
		tmpcr->cr_rgid = cr->cr_gid;
	}

lookup:
	if ((error = lookupnameatcred(fname, UIO_USERSPACE, FOLLOW, NULLVPP,
	    &vp, startvp, tmpcr)) != 0) {
		if ((error == ESTALE) && fs_need_estale_retry(estale_retry++))
			goto lookup;
		crfree(tmpcr);
		return (error);
	}

	if (mode != 0) {
		error = VOP_ACCESS(vp, mode, 0, tmpcr, NULL);
		if (error != 0) {
			if ((error == ESTALE) &&
			    fs_need_estale_retry(estale_retry++)) {
				VN_RELE(vp);
				goto lookup;
			}

		} else if ((fmode & X_OK) != 0 && cr->cr_ruid == 0 &&
		    lx_kern_release_cmp(curproc->p_zone, "2.4.0") > 0) {
			/* check for incorrect execute success */
			vattr_t va;

			va.va_mask = AT_MODE;
			if ((error = VOP_GETATTR(vp, &va, 0, cr, NULL)) == 0) {
				mode_t m = VTTOIF(va.va_type) | va.va_mode;

				if ((m & S_IFMT) == S_IFREG &&
				    !(m & (S_IXUSR | S_IXGRP | S_IXOTH))) {
					/* no execute bits set in the mode */
					error = EACCES;
				}
			}
		}
	}

	crfree(tmpcr);
	VN_RELE(vp);
	return (error);
}

int
lx_faccessat(int atfd, char *fname, int fmode, int flag)
{
	vnode_t *startvp;
	int error;

	if (atfd == LX_AT_FDCWD)
		atfd = AT_FDCWD;

	if ((flag = ltos_at_flag(flag, AT_EACCESS, B_FALSE)) < 0)
		return (set_errno(EINVAL));

	if (fname == NULL)
		return (set_errno(EFAULT));
	if ((error = fgetstartvp(atfd, fname, &startvp)) != 0)
		return (set_errno(error));
	if (AU_AUDITING() && startvp != NULL)
		audit_setfsat_path(1);

	/* Do not allow E_OK unless AT_EACCESS flag is set */
	if ((flag & AT_EACCESS) == 0)
		fmode &= ~E_OK;

	error = lx_common_access(fname, fmode, startvp);
	if (startvp != NULL)
		VN_RELE(startvp);
	if (error)
		return (set_errno(error));
	return (0);
}

int
lx_access(char *fname, int fmode)
{
	return (lx_faccessat(LX_AT_FDCWD, fname, fmode, 0));
}
