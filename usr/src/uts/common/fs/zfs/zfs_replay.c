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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/thread.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/vfs.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_dir.h>
#include <sys/zfs_acl.h>
#include <sys/spa.h>
#include <sys/zil.h>
#include <sys/byteorder.h>
#include <sys/stat.h>
#include <sys/mode.h>
#include <sys/acl.h>
#include <sys/atomic.h>
#include <sys/cred.h>

/*
 * Functions to replay ZFS intent log (ZIL) records
 * The functions are called through a function vector (zfs_replay_vector)
 * which is indexed by the transaction type.
 */

static void
zfs_init_vattr(vattr_t *vap, uint64_t mask, uint64_t mode,
	uint64_t uid, uint64_t gid, uint64_t rdev, uint64_t nodeid)
{
	bzero(vap, sizeof (*vap));
	vap->va_mask = (uint_t)mask;
	vap->va_type = IFTOVT(mode);
	vap->va_mode = mode & MODEMASK;
	vap->va_uid = (uid_t)uid;
	vap->va_gid = (gid_t)gid;
	vap->va_rdev = zfs_cmpldev(rdev);
	vap->va_nodeid = nodeid;
}

/* ARGSUSED */
static int
zfs_replay_error(zfsvfs_t *zfsvfs, lr_t *lr, boolean_t byteswap)
{
	return (ENOTSUP);
}

static int
zfs_replay_create(zfsvfs_t *zfsvfs, lr_create_t *lr, boolean_t byteswap)
{
	char *name = (char *)(lr + 1);	/* name follows lr_create_t */
	char *link;			/* symlink content follows name */
	znode_t *dzp;
	vnode_t *vp = NULL;
	vattr_t va;
	int error;

	if (byteswap)
		byteswap_uint64_array(lr, sizeof (*lr));

	if ((error = zfs_zget(zfsvfs, lr->lr_doid, &dzp)) != 0)
		return (error);

	zfs_init_vattr(&va, AT_TYPE | AT_MODE | AT_UID | AT_GID,
	    lr->lr_mode, lr->lr_uid, lr->lr_gid, lr->lr_rdev, lr->lr_foid);

	/*
	 * All forms of zfs create (create, mkdir, mkxattrdir, symlink)
	 * eventually end up in zfs_mknode(), which assigns the object's
	 * creation time and generation number.  The generic VOP_CREATE()
	 * doesn't have either concept, so we smuggle the values inside
	 * the vattr's otherwise unused va_ctime and va_nblocks fields.
	 */
	ZFS_TIME_DECODE(&va.va_ctime, lr->lr_crtime);
	va.va_nblocks = lr->lr_gen;

	switch ((int)lr->lr_common.lrc_txtype) {
	case TX_CREATE:
		error = VOP_CREATE(ZTOV(dzp), name, &va, 0, 0, &vp, kcred, 0);
		break;
	case TX_MKDIR:
		error = VOP_MKDIR(ZTOV(dzp), name, &va, &vp, kcred);
		break;
	case TX_MKXATTR:
		error = zfs_make_xattrdir(dzp, &va, &vp, kcred);
		break;
	case TX_SYMLINK:
		link = name + strlen(name) + 1;
		error = VOP_SYMLINK(ZTOV(dzp), name, &va, link, kcred);
		break;
	default:
		error = ENOTSUP;
	}

	if (error == 0 && vp != NULL)
		VN_RELE(vp);

	VN_RELE(ZTOV(dzp));

	return (error);
}

static int
zfs_replay_remove(zfsvfs_t *zfsvfs, lr_remove_t *lr, boolean_t byteswap)
{
	char *name = (char *)(lr + 1);	/* name follows lr_remove_t */
	znode_t *dzp;
	int error;

	if (byteswap)
		byteswap_uint64_array(lr, sizeof (*lr));

	if ((error = zfs_zget(zfsvfs, lr->lr_doid, &dzp)) != 0)
		return (error);

	switch ((int)lr->lr_common.lrc_txtype) {
	case TX_REMOVE:
		error = VOP_REMOVE(ZTOV(dzp), name, kcred);
		break;
	case TX_RMDIR:
		error = VOP_RMDIR(ZTOV(dzp), name, NULL, kcred);
		break;
	default:
		error = ENOTSUP;
	}

	VN_RELE(ZTOV(dzp));

	return (error);
}

static int
zfs_replay_link(zfsvfs_t *zfsvfs, lr_link_t *lr, boolean_t byteswap)
{
	char *name = (char *)(lr + 1);	/* name follows lr_link_t */
	znode_t *dzp, *zp;
	int error;

	if (byteswap)
		byteswap_uint64_array(lr, sizeof (*lr));

	if ((error = zfs_zget(zfsvfs, lr->lr_doid, &dzp)) != 0)
		return (error);

	if ((error = zfs_zget(zfsvfs, lr->lr_link_obj, &zp)) != 0) {
		VN_RELE(ZTOV(dzp));
		return (error);
	}

	error = VOP_LINK(ZTOV(dzp), ZTOV(zp), name, kcred);

	VN_RELE(ZTOV(zp));
	VN_RELE(ZTOV(dzp));

	return (error);
}

static int
zfs_replay_rename(zfsvfs_t *zfsvfs, lr_rename_t *lr, boolean_t byteswap)
{
	char *sname = (char *)(lr + 1);	/* sname and tname follow lr_rename_t */
	char *tname = sname + strlen(sname) + 1;
	znode_t *sdzp, *tdzp;
	int error;

	if (byteswap)
		byteswap_uint64_array(lr, sizeof (*lr));

	if ((error = zfs_zget(zfsvfs, lr->lr_sdoid, &sdzp)) != 0)
		return (error);

	if ((error = zfs_zget(zfsvfs, lr->lr_tdoid, &tdzp)) != 0) {
		VN_RELE(ZTOV(sdzp));
		return (error);
	}

	error = VOP_RENAME(ZTOV(sdzp), sname, ZTOV(tdzp), tname, kcred);

	VN_RELE(ZTOV(tdzp));
	VN_RELE(ZTOV(sdzp));

	return (error);
}

static int
zfs_replay_write(zfsvfs_t *zfsvfs, lr_write_t *lr, boolean_t byteswap)
{
	char *data = (char *)(lr + 1);	/* data follows lr_write_t */
	znode_t	*zp;
	int error;
	ssize_t resid;

	if (byteswap)
		byteswap_uint64_array(lr, sizeof (*lr));

	if ((error = zfs_zget(zfsvfs, lr->lr_foid, &zp)) != 0)
		return (error);

	error = vn_rdwr(UIO_WRITE, ZTOV(zp), data, lr->lr_length,
	    lr->lr_offset, UIO_SYSSPACE, 0, RLIM64_INFINITY, kcred, &resid);

	VN_RELE(ZTOV(zp));

	return (error);
}

static int
zfs_replay_truncate(zfsvfs_t *zfsvfs, lr_truncate_t *lr, boolean_t byteswap)
{
	znode_t *zp;
	flock64_t fl;
	int error;

	if (byteswap)
		byteswap_uint64_array(lr, sizeof (*lr));

	if ((error = zfs_zget(zfsvfs, lr->lr_foid, &zp)) != 0)
		return (error);

	bzero(&fl, sizeof (fl));
	fl.l_type = F_WRLCK;
	fl.l_whence = 0;
	fl.l_start = lr->lr_offset;
	fl.l_len = lr->lr_length;

	error = VOP_SPACE(ZTOV(zp), F_FREESP, &fl, FWRITE | FOFFMAX,
	    lr->lr_offset, kcred, NULL);

	VN_RELE(ZTOV(zp));

	return (error);
}

static int
zfs_replay_setattr(zfsvfs_t *zfsvfs, lr_setattr_t *lr, boolean_t byteswap)
{
	znode_t *zp;
	vattr_t va;
	int error;

	if (byteswap)
		byteswap_uint64_array(lr, sizeof (*lr));

	if ((error = zfs_zget(zfsvfs, lr->lr_foid, &zp)) != 0)
		return (error);

	zfs_init_vattr(&va, lr->lr_mask, lr->lr_mode,
	    lr->lr_uid, lr->lr_gid, 0, lr->lr_foid);

	va.va_size = lr->lr_size;
	ZFS_TIME_DECODE(&va.va_atime, lr->lr_atime);
	ZFS_TIME_DECODE(&va.va_mtime, lr->lr_mtime);

	error = VOP_SETATTR(ZTOV(zp), &va, 0, kcred, NULL);

	VN_RELE(ZTOV(zp));

	return (error);
}

static int
zfs_replay_acl(zfsvfs_t *zfsvfs, lr_acl_t *lr, boolean_t byteswap)
{
	ace_t *ace = (ace_t *)(lr + 1);	/* ace array follows lr_acl_t */
	vsecattr_t vsa;
	znode_t *zp;
	int error;

	if (byteswap) {
		byteswap_uint64_array(lr, sizeof (*lr));
		zfs_ace_byteswap(ace, lr->lr_aclcnt);
	}

	if ((error = zfs_zget(zfsvfs, lr->lr_foid, &zp)) != 0)
		return (error);

	bzero(&vsa, sizeof (vsa));
	vsa.vsa_mask = VSA_ACE | VSA_ACECNT;
	vsa.vsa_aclcnt = lr->lr_aclcnt;
	vsa.vsa_aclentp = ace;

	error = VOP_SETSECATTR(ZTOV(zp), &vsa, 0, kcred);

	VN_RELE(ZTOV(zp));

	return (error);
}

/*
 * Callback vectors for replaying records
 */
zil_replay_func_t *zfs_replay_vector[TX_MAX_TYPE] = {
	zfs_replay_error,	/* 0 no such transaction type */
	zfs_replay_create,	/* TX_CREATE */
	zfs_replay_create,	/* TX_MKDIR */
	zfs_replay_create,	/* TX_MKXATTR */
	zfs_replay_create,	/* TX_SYMLINK */
	zfs_replay_remove,	/* TX_REMOVE */
	zfs_replay_remove,	/* TX_RMDIR */
	zfs_replay_link,	/* TX_LINK */
	zfs_replay_rename,	/* TX_RENAME */
	zfs_replay_write,	/* TX_WRITE */
	zfs_replay_truncate,	/* TX_TRUNCATE */
	zfs_replay_setattr,	/* TX_SETATTR */
	zfs_replay_acl,		/* TX_ACL */
};
