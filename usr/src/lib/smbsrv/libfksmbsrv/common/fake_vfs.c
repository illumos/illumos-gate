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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/pathname.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/mode.h>
#include <sys/conf.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/acl.h>
#include <sys/nbmlock.h>
#include <sys/fcntl.h>
#include <sys/poll.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "vncache.h"

#define	VFTBITS(feature)	((feature) & 0xFFFFFFFFLL)

static uint64_t vfs_features = VFSFT_XVATTR;

vnode_t *rootdir = NULL;	/* pointer to root inode vnode. */

static struct vfs fake_rootvfs;
struct vfs *rootvfs = NULL;

int
fksmbsrv_vfs_init(void)
{
	struct stat st;
	int err, fd;
	vnode_t *vp;
	char *name = "/";

	if (rootvfs == NULL) {
		rootvfs = &fake_rootvfs;
		rootvfs->vfs_mntpt = refstr_alloc(name);
		rootvfs->vfs_fsid.val[0] = 1;
	}

	if (rootdir == NULL) {
		if (lstat(name, &st) == -1)
			return (errno);
		fd = open(name, O_RDONLY, 0);
		if (fd < 0) {
			return (errno);
		}
		if (fstat(fd, &st) == -1) {
			err = errno;
			(void) close(fd);
			return (err);
		}
		vp = vncache_enter(&st, NULL, "", fd);
		/* extra hold for rootvp */
		vn_hold(vp);
		rootdir = vp;

		/* VFS stuff in global zone struct. */
		zone0.zone_rootvp = rootdir;
		zone0.zone_rootpath = "/";
	}

	return (0);

}


/*
 * Query a vfs for a feature.
 * Returns 1 if feature is present, 0 if not
 */
/* ARGSUSED */
int
vfs_has_feature(vfs_t *vfsp, vfs_feature_t feature)
{
	int	ret = 0;

	if (vfs_features & VFTBITS(feature))
		ret = 1;

	return (ret);
}

/* ARGSUSED */
struct vfs *
getvfs(fsid_t *fsid)
{
	return (rootvfs);
}

vfsops_t *
vfs_getops(vfs_t *vfsp)
{
	return (vfsp->vfs_op);
}

/* ARGSUSED */
struct vfssw *
vfs_getvfsswbyvfsops(vfsops_t *vfsops)
{
	return (NULL);
}

/* ARGSUSED */
void
vfs_unrefvfssw(struct vfssw *vswp)
{
}

/* ARGSUSED */
int
fsop_root(vfs_t *vfsp, vnode_t **vpp)
{
	vnode_t *vp;

	if ((vp = rootdir) == NULL)
		return (ENXIO);

	vn_hold(vp);
	*vpp = vp;
	return (0);
}

/* ARGSUSED */
int
fsop_statfs(vfs_t *vfsp, statvfs64_t *sp)
{
	vnode_t *vp;
	int rc;

	if ((vp = rootdir) == NULL)
		return (ENXIO);

	rc = fstatvfs64(vp->v_fd, sp);
	if (rc == -1) {
		rc = errno;
	}

	return (rc);
}

refstr_t *
vfs_getmntpoint(const struct vfs *vfsp)
{
	refstr_t *mntpt;

	mntpt = vfsp->vfs_mntpt;
	refstr_hold(mntpt);

	return (mntpt);
}

/* ARGSUSED */
void
vfs_hold(vfs_t *vfsp)
{
}

/* ARGSUSED */
void
vfs_rele(vfs_t *vfsp)
{
}

/* ARGSUSED */
int
vfs_lock(vfs_t *vfsp)
{
	return (0);
}

/* ARGSUSED */
int
vfs_rlock(vfs_t *vfsp)
{
	return (0);
}

/* ARGSUSED */
void
vfs_lock_wait(vfs_t *vfsp)
{
}

/* ARGSUSED */
void
vfs_rlock_wait(vfs_t *vfsp)
{
}

/* ARGSUSED */
void
vfs_unlock(vfs_t *vfsp)
{
}


static u_longlong_t fs_caller_id;
u_longlong_t
fs_new_caller_id(void)
{
	return (++fs_caller_id);
}

static sysid_t lm_sysid;
sysid_t
lm_alloc_sysidt(void)
{
	return (++lm_sysid);
}

/* ARGSUSED */
void
lm_free_sysidt(sysid_t id)
{
}
