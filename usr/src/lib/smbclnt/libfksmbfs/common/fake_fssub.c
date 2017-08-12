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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Joyent, Inc.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Generic vnode operations.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/cred.h>
#include <sys/poll.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/share.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/nbmlock.h>
#include <sys/acl.h>

#include <acl/acl_common.h>
#include <fs/fs_subr.h>

/*
 * Tunable to limit the number of retry to recover from STALE error.
 */
int fs_estale_retry = 5;

/*
 * The associated operation is not supported by the file system.
 */
int
fs_nosys()
{
	return (ENOSYS);
}

/*
 * The associated operation is invalid (on this vnode).
 */
int
fs_inval()
{
	return (EINVAL);
}

/*
 * The associated operation is valid only for directories.
 */
int
fs_notdir()
{
	return (ENOTDIR);
}

/*
 * Free the file system specific resources. For the file systems that
 * do not support the forced unmount, it will be a nop function.
 */

/*ARGSUSED*/
void
fs_freevfs(vfs_t *vfsp)
{
}

/* ARGSUSED */
int
fs_nosys_map(struct vnode *vp, offset_t off, struct as *as, caddr_t *addrp,
    size_t len, uchar_t prot, uchar_t maxprot, uint_t flags, struct cred *cr,
    caller_context_t *ct)
{
	return (ENOSYS);
}

/* ARGSUSED */
int
fs_nosys_addmap(struct vnode *vp, offset_t off, struct as *as, caddr_t addr,
    size_t len, uchar_t prot, uchar_t maxprot, uint_t flags, struct cred *cr,
    caller_context_t *ct)
{
	return (ENOSYS);
}

/* ARGSUSED */
int
fs_nosys_poll(vnode_t *vp, short events, int anyyet, short *reventsp,
    struct pollhead **phpp, caller_context_t *ct)
{
	return (ENOSYS);
}


/*
 * The file system has nothing to sync to disk.  However, the
 * VFS_SYNC operation must not fail.
 */
/* ARGSUSED */
int
fs_sync(struct vfs *vfspp, short flag, cred_t *cr)
{
	return (0);
}

/*
 * Does nothing but VOP_FSYNC must not fail.
 */
/* ARGSUSED */
int
fs_fsync(vnode_t *vp, int syncflag, cred_t *cr, caller_context_t *ct)
{
	return (0);
}

/*
 * Does nothing but VOP_PUTPAGE must not fail.
 */
/* ARGSUSED */
int
fs_putpage(vnode_t *vp, offset_t off, size_t len, int flags, cred_t *cr,
    caller_context_t *ctp)
{
	return (0);
}

/*
 * Does nothing but VOP_IOCTL must not fail.
 */
/* ARGSUSED */
int
fs_ioctl(vnode_t *vp, int com, intptr_t data, int flag, cred_t *cred,
    int *rvalp)
{
	return (0);
}

/*
 * Read/write lock/unlock.  Does nothing.
 */
/* ARGSUSED */
int
fs_rwlock(vnode_t *vp, int write_lock, caller_context_t *ctp)
{
	return (-1);
}

/* ARGSUSED */
void
fs_rwunlock(vnode_t *vp, int write_lock, caller_context_t *ctp)
{
}

/*
 * Compare two vnodes.
 */
/*ARGSUSED2*/
int
fs_cmp(vnode_t *vp1, vnode_t *vp2, caller_context_t *ct)
{
	return (vp1 == vp2);
}

/*
 * No-op seek operation.
 */
/* ARGSUSED */
int
fs_seek(vnode_t *vp, offset_t ooff, offset_t *noffp, caller_context_t *ct)
{
	return ((*noffp < 0 || *noffp > MAXOFFSET_T) ? EINVAL : 0);
}

/*
 * File and record locking.
 */
/* ARGSUSED */
int
fs_frlock(vnode_t *vp, int cmd, struct flock64 *bfp, int flag, offset_t offset,
    flk_callback_t *flk_cbp, cred_t *cr, caller_context_t *ct)
{
	return (ENOSYS);
}

/*
 * Allow any flags.
 */
/* ARGSUSED */
int
fs_setfl(vnode_t *vp, int oflags, int nflags, cred_t *cr, caller_context_t *ct)
{
	return (0);
}

/*
 * Return the answer requested to poll() for non-device files.
 * Only POLLIN, POLLRDNORM, and POLLOUT are recognized.
 */
struct pollhead fs_pollhd;

/* ARGSUSED */
int
fs_poll(vnode_t *vp, short events, int anyyet, short *reventsp,
    struct pollhead **phpp, caller_context_t *ct)
{
	if (events & POLLET) {
		return (EPERM);
	}

	*reventsp = 0;
	if (events & POLLIN)
		*reventsp |= POLLIN;
	if (events & POLLRDNORM)
		*reventsp |= POLLRDNORM;
	if (events & POLLRDBAND)
		*reventsp |= POLLRDBAND;
	if (events & POLLOUT)
		*reventsp |= POLLOUT;
	if (events & POLLWRBAND)
		*reventsp |= POLLWRBAND;
	if (*reventsp == 0 && !anyyet) {
		*phpp = &fs_pollhd;
	}
	return (0);
}

/*
 * POSIX pathconf() support.
 */
/* ARGSUSED */
int
fs_pathconf(vnode_t *vp, int cmd, ulong_t *valp, cred_t *cr,
    caller_context_t *ct)
{
	/* not called */
	return (EINVAL);
}

/*
 * Dispose of a page.
 */
/* ARGSUSED */
void
fs_dispose(struct vnode *vp, page_t *pp, int fl, int dn, struct cred *cr,
    caller_context_t *ct)
{
}

/* ARGSUSED */
void
fs_nodispose(struct vnode *vp, page_t *pp, int fl, int dn, struct cred *cr,
    caller_context_t *ct)
{
	cmn_err(CE_PANIC, "fs_nodispose invoked");
}

/*
 * fabricate acls for file systems that do not support acls.
 */
/* ARGSUSED */
int
fs_fab_acl(vnode_t *vp, vsecattr_t *vsecattr, int flag, cred_t *cr,
    caller_context_t *ct)
{
	struct vattr	vattr;
	int		error;

	vsecattr->vsa_aclcnt	= 0;
	vsecattr->vsa_aclentsz	= 0;
	vsecattr->vsa_aclentp	= NULL;
	vsecattr->vsa_dfaclcnt	= 0;	/* Default ACLs are not fabricated */
	vsecattr->vsa_dfaclentp	= NULL;

	vattr.va_mask = AT_MODE | AT_UID | AT_GID;
	if (error = VOP_GETATTR(vp, &vattr, 0, cr, ct))
		return (error);

	if (vsecattr->vsa_mask & (VSA_ACLCNT | VSA_ACL)) {
		return (ENOSYS);
	}

	if (vsecattr->vsa_mask & (VSA_ACECNT | VSA_ACE)) {
		VERIFY(0 == acl_trivial_create(vattr.va_mode,
		    (vp->v_type == VDIR), (ace_t **)&vsecattr->vsa_aclentp,
		    &vsecattr->vsa_aclcnt));
		vsecattr->vsa_aclentsz = vsecattr->vsa_aclcnt * sizeof (ace_t);
	}

	return (error);
}

/*
 * Common code for implementing DOS share reservations
 */
/* ARGSUSED */
int
fs_shrlock(struct vnode *vp, int cmd, struct shrlock *shr, int flag, cred_t *cr,
    caller_context_t *ct)
{
	return (ENOSYS);
}

/*ARGSUSED1*/
int
fs_vnevent_nosupport(vnode_t *vp, vnevent_t e, vnode_t *dvp, char *fnm,
    caller_context_t *ct)
{
	ASSERT(vp != NULL);
	return (ENOTSUP);
}

/*ARGSUSED1*/
int
fs_vnevent_support(vnode_t *vp, vnevent_t e, vnode_t *dvp, char *fnm,
    caller_context_t *ct)
{
	ASSERT(vp != NULL);
	return (0);
}

// fs_acl_nontrivial

/*
 * Check whether we need a retry to recover from STALE error.
 */
int
fs_need_estale_retry(int retry_count)
{
	if (retry_count < fs_estale_retry)
		return (1);
	else
		return (0);
}

// fs_vscan...
// reparse...

/*
 * A few things from os/flock.c
 */

/* ARGSUSED */
void
cleanlocks(vnode_t *vp, pid_t pid, int sysid)
{
}

/* ARGSUSED */
void
cleanshares(struct vnode *vp, pid_t pid)
{
}

/*
 * convoff - converts the given data (start, whence) to the
 * given whence.
 */
int
convoff(struct vnode *vp, struct flock64 *lckdat, int whence, offset_t offset)
{
	int 		error;
	struct vattr 	vattr;

	if ((lckdat->l_whence == 2) || (whence == 2)) {
		vattr.va_mask = AT_SIZE;
		if (error = VOP_GETATTR(vp, &vattr, 0, CRED(), NULL))
			return (error);
	}

	switch (lckdat->l_whence) {
	case 1:
		lckdat->l_start += offset;
		break;
	case 2:
		lckdat->l_start += vattr.va_size;
		/* FALLTHRU */
	case 0:
		break;
	default:
		return (EINVAL);
	}

	if (lckdat->l_start < 0)
		return (EINVAL);

	switch (whence) {
	case 1:
		lckdat->l_start -= offset;
		break;
	case 2:
		lckdat->l_start -= vattr.va_size;
		/* FALLTHRU */
	case 0:
		break;
	default:
		return (EINVAL);
	}

	lckdat->l_whence = (short)whence;
	return (0);
}
