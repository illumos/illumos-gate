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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/uio.h>
#include <sys/tiuser.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/utsname.h>
#include <sys/bootconf.h>
#include <sys/reboot.h>
#include <sys/modctl.h>
#include <rpc/types.h>

#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_log.h>
#include <sys/mkdev.h>
#include <sys/dnlc.h>
#include <sys/policy.h>
#include "fs/fs_subr.h"

extern kmutex_t cachefs_kmem_lock;
kmutex_t cachefs_kstat_key_lock;

/* forward declarations */
static int cachefs_remount(struct vfs *, struct mounta *);
static void cachefs_delete_cachep(cachefscache_t *);

#define	CFS_MAPSIZE	256

kmutex_t cachefs_cachelock;			/* Cache list mutex */
cachefscache_t *cachefs_cachelist = NULL;		/* Cache struct list */

int cachefs_mount_retries = 3;
kmutex_t cachefs_minor_lock;		/* Lock for minor device map */
major_t cachefs_major = 0;
minor_t cachefs_minor = 0;
cachefs_kstat_key_t *cachefs_kstat_key = NULL;
int cachefs_kstat_key_n = 0;
static uint32_t cachefs_nfsv4_warnmsg = FALSE;

/*
 * cachefs vfs operations.
 */
static	int cachefs_mount(vfs_t *, vnode_t *, struct mounta *, cred_t *);
static	int cachefs_unmount(vfs_t *, int, cred_t *);
static	int cachefs_root(vfs_t *, vnode_t **);
static	int cachefs_statvfs(register vfs_t *, struct statvfs64 *);
static	int cachefs_sync(vfs_t *, short, cred_t *);

/*
 * Initialize the vfs structure
 */
int cachefsfstyp;
int cnodesize = 0;

int
cachefs_init_vfsops(int fstype)
{
	static const fs_operation_def_t cachefs_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = cachefs_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = cachefs_unmount },
		VFSNAME_ROOT,		{ .vfs_root = cachefs_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = cachefs_statvfs },
		VFSNAME_SYNC,		{ .vfs_sync = cachefs_sync },
		NULL,			NULL
	};
	int error;

	error = vfs_setfsops(fstype, cachefs_vfsops_template, NULL);
	if (error != 0)
		return (error);

	cachefsfstyp = fstype;

	return (0);
}

dev_t
cachefs_mkmntdev(void)
{
	dev_t cachefs_dev;

	mutex_enter(&cachefs_minor_lock);
	do {
		cachefs_minor = (cachefs_minor + 1) & MAXMIN32;
		cachefs_dev = makedevice(cachefs_major, cachefs_minor);
	} while (vfs_devismounted(cachefs_dev));
	mutex_exit(&cachefs_minor_lock);

	return (cachefs_dev);
}

/*
 * vfs operations
 */
static int
cachefs_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr)
{
	char *data = uap->dataptr;
	STRUCT_DECL(cachefs_mountargs, map);
	struct cachefsoptions	*cfs_options;
	char			*backfs, *cacheid, *cachedir;
	vnode_t *cachedirvp = NULL;
	vnode_t *backrootvp = NULL;
	cachefscache_t *cachep = NULL;
	fscache_t *fscp = NULL;
	cnode_t *cp;
	struct fid *cookiep = NULL;
	struct vattr *attrp = NULL;
	dev_t cachefs_dev;			/* devid for this mount */
	int error = 0;
	int retries = cachefs_mount_retries;
	ino64_t fsid;
	cfs_cid_t cid;
	char *backmntpt;
	ino64_t backfileno;
	struct vfs *backvfsp;
	size_t strl;
	char tmpstr[MAXPATHLEN];
	vnode_t *tmpdirvp = NULL;
	ulong_t maxfilesizebits;
	uint32_t valid_fid;

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_VFSOP)
		printf("cachefs_mount: ENTER cachefs_mntargs %p\n", data);
#endif

	/*
	 * Make sure we have sufficient privileges.
	 */
	if ((error = secpolicy_fs_mount(cr, mvp, vfsp)) != 0)
		goto out;

	/*
	 * make sure we're mounting on a directory
	 */
	if (mvp->v_type != VDIR) {
		error = ENOTDIR;
		goto out;
	}

	/*
	 * Determine the zone we're being mounted into, and make sure it's the
	 * global zone.
	 */
	if (getzoneid() == GLOBAL_ZONEID) {
		zone_t *mntzone;

		mntzone = zone_find_by_path(refstr_value(vfsp->vfs_mntpt));
		ASSERT(mntzone != NULL);
		zone_rele(mntzone);
		if (mntzone != curproc->p_zone) {
			error = EBUSY;
			goto out;
		}
	} else {
		error = EPERM;
		goto out;
	}

	if (uap->flags & MS_REMOUNT) {
		error = cachefs_remount(vfsp, uap);
		goto out;
	}

	/*
	 * Assign a unique device id to the mount
	 */
	cachefs_dev = cachefs_mkmntdev();
#ifdef _LP64
	/*
	 * It's not a good idea to make fsid bigger since that'll
	 * have adverse effects on nfs filehandles.  For now assume that
	 * cachefs be used on devices that fit into dev32_t's.
	 */
	if (cachefs_dev == NODEV) {
		error = EOVERFLOW;
		goto out;
	}
#endif

	/*
	 * Copy in the arguments
	 */
	STRUCT_INIT(map, get_udatamodel());
	error = copyin(data, STRUCT_BUF(map),
			SIZEOF_STRUCT(cachefs_mountargs, DATAMODEL_NATIVE));
	if (error) {
		goto out;
	}

	cfs_options = (struct cachefsoptions *)STRUCT_FADDR(map, cfs_options);
	cacheid = (char *)STRUCT_FGETP(map, cfs_cacheid);
	if ((cfs_options->opt_flags &
	    (CFS_WRITE_AROUND|CFS_NONSHARED|CFS_BACKFS_NFSV4)) == 0) {
		error = EINVAL;
		goto out;
	}
	if ((cfs_options->opt_popsize % MAXBSIZE) != 0) {
		error = EINVAL;
		goto out;
	}
	/*
	 * Get the cache directory vp
	 */
	/*LINTED 32-bit pointer casting okay*/
	cachedir = (char *)STRUCT_FGETP(map, cfs_cachedir);
	error = lookupname(cachedir, UIO_USERSPACE, FOLLOW,
			NULLVPP, &cachedirvp);
	if (error)
		goto out;

	/*
	 * Make sure the thing we just looked up is a directory
	 */
	if (cachedirvp->v_type != VDIR) {
		cmn_err(CE_WARN, "cachefs_mount: cachedir not a directory\n");
		error = EINVAL;
		goto out;
	}

	/*
	 * Make sure the cache doesn't live in cachefs!
	 */
	if (vn_matchops(cachedirvp, cachefs_getvnodeops())) {
		cmn_err(CE_WARN, "cachefs_mount: cachedir in cachefs!\n");
		error = EINVAL;
		goto out;
	}

	/* if the backfs is mounted */
	/*LINTED 32-bit pointer casting okay*/
	if ((backfs = STRUCT_FGETP(map, cfs_backfs)) != NULL) {
		/*
		 * Get the back file system root vp
		 */
		error = lookupname(backfs, UIO_USERSPACE, FOLLOW,
			NULLVPP, &backrootvp);
		if (error)
			goto out;

		/*
		 * Make sure the thing we just looked up is a directory
		 * and a root of a file system
		 */
		if (backrootvp->v_type != VDIR ||
		    !(backrootvp->v_flag & VROOT)) {
			cmn_err(CE_WARN,
			    "cachefs_mount: backpath not a directory\n");
			error = EINVAL;
			goto out;
		}

		/*
		 * Get the fid and attributes for the root of the
		 * backfilesystem, except if NFSv4 is in use,
		 * in which case we get the attributes only (the
		 * (VOP_FID() operation called by cachefs_get_cookie()
		 * is not supported in NFSv4).
		 */
		cookiep = cachefs_kmem_alloc(sizeof (struct fid), KM_SLEEP);
		attrp = cachefs_kmem_alloc(sizeof (struct vattr), KM_SLEEP);

		if ((cfs_options->opt_flags & CFS_BACKFS_NFSV4)) {
			valid_fid = FALSE;
		} else {
			valid_fid = TRUE;
		}
		error = cachefs_getcookie(backrootvp, cookiep, attrp, cr,
						valid_fid);

		if (error)
			goto out;

		backmntpt = backfs;
		backfileno = attrp->va_nodeid;
		backvfsp = backrootvp->v_vfsp;
	} else {
		backmntpt = NULL;
		backfileno = 0;
		backvfsp = NULL;
	}

again:

	/*
	 * In SVR4 it's not acceptable to stack up mounts
	 * unless MS_OVERLAY specified.
	 */
	mutex_enter(&mvp->v_lock);
	if (((uap->flags & MS_OVERLAY) == 0) &&
	    ((mvp->v_count != 1) || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		error = EBUSY;
		goto out;
	}
	mutex_exit(&mvp->v_lock);

	/*
	 * Lock out other mounts and unmounts until we safely have
	 * a mounted fscache object.
	 */
	mutex_enter(&cachefs_cachelock);

	/*
	 * Find the cache structure
	 */
	for (cachep = cachefs_cachelist; cachep != NULL;
		cachep = cachep->c_next) {
		if (cachep->c_dirvp == cachedirvp)
			break;
	}

	/* if the cache object does not exist, then create it */
	if (cachep == NULL) {
		cachep = cachefs_cache_create();
		error = cachefs_cache_activate_ro(cachep, cachedirvp);
		if (error) {
			cachefs_cache_destroy(cachep);
			cachep = NULL;
			goto out;
		}
		if ((cfs_options->opt_flags & CFS_NOFILL) == 0)
			cachefs_cache_activate_rw(cachep);
		else
			cfs_options->opt_flags &= ~CFS_NOFILL;

		cachep->c_next = cachefs_cachelist;
		cachefs_cachelist = cachep;
	} else if (cfs_options->opt_flags & CFS_NOFILL) {
		cmn_err(CE_WARN,
		    "CacheFS: attempt to convert nonempty cache "
		    "to NOFILL mode");
		error = EINVAL;
		goto out;
	}

	/* get the fscache id for this name */
	error = fscache_name_to_fsid(cachep, cacheid, &fsid);
	if (error) {
		fsid = 0;
	}

	/* find the fscache object for this mount point or create it */
	mutex_enter(&cachep->c_fslistlock);
	fscp = fscache_list_find(cachep, fsid);
	if (fscp == NULL) {
		fscp = fscache_create(cachep);
		error = fscache_activate(fscp, fsid, cacheid,
			cfs_options, backfileno);
		if (error) {
			fscache_destroy(fscp);
			fscp = NULL;
			mutex_exit(&cachep->c_fslistlock);
			if ((error == ENOSPC) && (retries-- > 0)) {
				mutex_exit(&cachefs_cachelock);
				delay(6 * hz);
				goto again;
			}
			goto out;
		}
		fscache_list_add(cachep, fscp);
	} else {
		/* compare the options to make sure they are compatible */
		error = fscache_compare_options(fscp, cfs_options);
		if (error) {
			cmn_err(CE_WARN,
				"CacheFS: mount failed, options do not match.");
			fscp = NULL;
			mutex_exit(&cachep->c_fslistlock);
			goto out;
		}

		/* copy options into the fscache */
		mutex_enter(&fscp->fs_fslock);
		fscp->fs_info.fi_mntflags = cfs_options->opt_flags;
		fscp->fs_info.fi_popsize = cfs_options->opt_popsize;
		fscp->fs_info.fi_fgsize = cfs_options->opt_fgsize;
		fscp->fs_flags |= CFS_FS_DIRTYINFO;
		mutex_exit(&fscp->fs_fslock);
	}
	fscache_hold(fscp);

	error = 0;
	if (fscp->fs_fscdirvp) {
		error = VOP_LOOKUP(fscp->fs_fscdirvp, CACHEFS_DLOG_FILE,
		    &tmpdirvp, NULL, 0, NULL, kcred, NULL, NULL, NULL);

		/*
		 * If a log file exists and the cache is being mounted without
		 * the snr (aka disconnectable) option, return an error.
		 */
		if ((error == 0) &&
		    !(cfs_options->opt_flags & CFS_DISCONNECTABLE)) {
			mutex_exit(&cachep->c_fslistlock);
			cmn_err(CE_WARN, "cachefs: log exists and "
			    "disconnectable option not specified\n");
			error = EINVAL;
			goto out;
		}
	}

	/*
	 * Acquire the name of the mount point
	 */
	if (fscp->fs_mntpt == NULL) {
		/*
		 * the string length returned by copystr includes the
		 * terminating NULL character, unless a NULL string is
		 * passed in, then the string length is unchanged.
		 */
		strl = 0;
		tmpstr[0] = '\0';
		(void) copyinstr(uap->dir, tmpstr, MAXPATHLEN, &strl);
		if (strl > 1) {
			fscp->fs_mntpt = kmem_alloc(strl, KM_SLEEP);
			(void) strncpy(fscp->fs_mntpt, tmpstr, strl);
		}
		/*
		 * else fscp->fs_mntpt is unchanged(still NULL) try again
		 * next time
		 */
	}

	/*
	 * Acquire the name of the server
	 */
	if (fscp->fs_hostname == NULL) {
		strl = 0;
		tmpstr[0] = '\0';
		/*LINTED 32-bit pointer casting okay*/
		(void) copyinstr((char *)STRUCT_FGETP(map, cfs_hostname),
				tmpstr, MAXPATHLEN, &strl);
		if (strl > 1) {
			fscp->fs_hostname = kmem_alloc(strl, KM_SLEEP);
			(void) strncpy(fscp->fs_hostname, tmpstr, strl);
		}
		/*
		 * else fscp->fs_hostname remains unchanged (is still NULL)
		 */
	}

	/*
	 * Acquire name of the back filesystem
	 */
	if (fscp->fs_backfsname == NULL) {
		strl = 0;
		tmpstr[0] = '\0';
		/*LINTED 32-bit pointer casting okay*/
		(void) copyinstr((char *)STRUCT_FGETP(map, cfs_backfsname),
				tmpstr, MAXPATHLEN, &strl);
		if (strl > 1) {
			fscp->fs_backfsname = kmem_alloc(strl, KM_SLEEP);
			(void) strncpy(fscp->fs_backfsname, tmpstr, strl);
		}
		/*
		 * else fscp->fs_backfsname remains unchanged (is still NULL)
		 */
	}

	backfileno = fscp->fs_info.fi_root;
	mutex_exit(&cachep->c_fslistlock);

	/* see if fscache object is already mounted, it not, make it so */
	error = fscache_mounted(fscp, vfsp, backvfsp);
	if (error) {
		/* fs cache was already mounted */
		error = EBUSY;
		goto out;
	}

	cachefs_kstat_mount(fscp, uap->dir, backmntpt, cachedir, cacheid);

	/* set nfs style time out parameters */
	fscache_acset(fscp, STRUCT_FGET(map, cfs_acregmin),
	    STRUCT_FGET(map, cfs_acregmax),
	    STRUCT_FGET(map, cfs_acdirmin), STRUCT_FGET(map, cfs_acdirmax));

	vfsp->vfs_dev = cachefs_dev;
	vfsp->vfs_data = (caddr_t)fscp;
	vfs_make_fsid(&vfsp->vfs_fsid, cachefs_dev, cachefsfstyp);
	vfsp->vfs_fstype = cachefsfstyp;
	if (backvfsp)
		vfsp->vfs_bsize = backvfsp->vfs_bsize;
	else
		vfsp->vfs_bsize = MAXBSIZE;	/* XXX */

	/* make a cnode for the root of the file system */
	cid.cid_flags = 0;
	cid.cid_fileno = backfileno;
	error = cachefs_cnode_make(&cid, fscp, (valid_fid ? cookiep : NULL),
				attrp, backrootvp, cr, CN_ROOT, &cp);

	if (error) {
		cmn_err(CE_WARN, "cachefs_mount: can't create root cnode\n");
		goto out;
	}

	/* stick the root cnode in the fscache object */
	mutex_enter(&fscp->fs_fslock);
	fscp->fs_rootvp = CTOV(cp);
	fscp->fs_rootvp->v_flag |= VROOT;
	fscp->fs_rootvp->v_type |= cp->c_attr.va_type;
	ASSERT(fscp->fs_rootvp->v_type == VDIR);

	/*
	 * Get the maxfilesize bits of the back file system.
	 */

	error = VOP_PATHCONF(backrootvp, _PC_FILESIZEBITS, &maxfilesizebits,
		    kcred, NULL);

	if (error) {
		cmn_err(CE_WARN,
	"cachefs_mount: Can't get the FILESIZEBITS of the back root vnode \n");
		goto out;
	}

	fscp->fs_offmax = (1LL << (maxfilesizebits - 1)) - 1;
	mutex_exit(&fscp->fs_fslock);

	/* remove the unmount file if it is there */
	(void) VOP_REMOVE(fscp->fs_fscdirvp, CACHEFS_UNMNT_FILE, kcred, NULL,
	    0);

	/* wake up the cache worker if ANY packed pending work */
	mutex_enter(&cachep->c_contentslock);
	if (cachep->c_flags & CACHE_PACKED_PENDING)
		cv_signal(&cachep->c_cwcv);
	mutex_exit(&cachep->c_contentslock);

	/*
	 * Warn that caching is disabled with NFSv4 first time around.
	 */
	if (!cachefs_nfsv4_warnmsg && CFS_ISFS_BACKFS_NFSV4(fscp)) {
		cmn_err(CE_WARN,
			"Cachefs has detected a mount with NFSv4: caching will"
			" be disabled for this and other NFSv4 mounts\n");
		cachefs_nfsv4_warnmsg = TRUE;
	}

out:
	/*
	 * make a log entry, if appropriate
	 */

	if ((cachep != NULL) &&
	    CACHEFS_LOG_LOGGING(cachep, CACHEFS_LOG_MOUNT))
		cachefs_log_mount(cachep, error, vfsp, fscp,
		    uap->dir, UIO_USERSPACE,
		    (STRUCT_BUF(map) != NULL) ? cacheid : NULL);

	/*
	 * Cleanup our mess
	 */
	if (cookiep != NULL)
		cachefs_kmem_free(cookiep, sizeof (struct fid));
	if (cachedirvp != NULL)
		VN_RELE(cachedirvp);
	if (backrootvp != NULL)
		VN_RELE(backrootvp);
	if (fscp)
		fscache_rele(fscp);
	if (attrp)
		cachefs_kmem_free(attrp, sizeof (struct vattr));

	if (error) {
		if (cachep) {
			int xx;

			/* lock the cachep's fslist */
			mutex_enter(&cachep->c_fslistlock);

			/*
			 * gc isn't necessary for list_mounted(), but
			 * we want to do it anyway.
			 */

			fscache_list_gc(cachep);
			xx = fscache_list_mounted(cachep);

			mutex_exit(&cachep->c_fslistlock);

			/* if no more references to this cachep, punt it. */
			if (xx == 0)
				cachefs_delete_cachep(cachep);
			mutex_exit(&cachefs_cachelock);
		}
	} else {
		mutex_exit(&cachefs_cachelock);
	}

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_VFSOP)
		printf("cachefs_mount: EXIT\n");
#endif
	return (error);
}

void
cachefs_kstat_mount(struct fscache *fscp,
    char *umountpoint, char *ubackfs, char *ucachedir, char *cacheid)
{
	cachefscache_t *cachep = fscp->fs_cache;
	cachefs_kstat_key_t *key;
	char *mountpoint = NULL, *backfs = NULL, *cachedir = NULL;
	size_t len;
	kstat_t *ksp;
	int i, rc;

	mountpoint = cachefs_kmem_alloc(MAXPATHLEN, KM_SLEEP);
	if (copyinstr(umountpoint, mountpoint, MAXPATHLEN, &len) != 0)
		goto out;

	cachedir = cachefs_kmem_alloc(MAXPATHLEN, KM_SLEEP);
	if (copyinstr(ucachedir, cachedir, MAXPATHLEN, &len) != 0)
		goto out;

	backfs = cachefs_kmem_alloc(MAXPATHLEN, KM_SLEEP);
	if (backfs) {
		if (copyinstr(ubackfs, backfs, MAXPATHLEN, &len) != 0)
			goto out;
	} else {
		(void) strcpy(backfs, "no back file system");
	}

	ASSERT(strlen(mountpoint) < MAXPATHLEN);
	ASSERT(strlen(backfs) < MAXPATHLEN);
	ASSERT(strlen(cachedir) < MAXPATHLEN);

	/* protect cachefs_kstat_key */
	mutex_enter(&cachefs_kstat_key_lock);
	/*
	 * XXXX If already there, why not go straight to it?
	 * We know that fscp->fs_kstat_id == i + 1
	 */
	i = fscp->fs_kstat_id - 1;
	if ((i >= 0) && (i < cachefs_kstat_key_n))
		rc = 1;
	else
		rc = i = 0;
	for (; i < cachefs_kstat_key_n; i++) {
		key = cachefs_kstat_key + i;
		if (strcmp((char *)(uintptr_t)key->ks_mountpoint,
		    mountpoint) == 0 &&
		    strcmp((char *)(uintptr_t)key->ks_cachedir,
		    cachedir) == 0 &&
		    strcmp((char *)(uintptr_t)key->ks_cacheid, cacheid) == 0)
			break;
		if (rc) {	/* direct key did not work - check all */
			i = -1;	/* will increment to zero in loop */
			rc = 0;
		}
	}

	if (i >= cachefs_kstat_key_n) {
		key = cachefs_kmem_alloc((cachefs_kstat_key_n + 1) *
		    sizeof (cachefs_kstat_key_t), KM_SLEEP);
		if (cachefs_kstat_key != NULL) {
			bcopy(cachefs_kstat_key, key,
			    cachefs_kstat_key_n * sizeof (*key));
			cachefs_kmem_free(cachefs_kstat_key,
			    cachefs_kstat_key_n * sizeof (*key));
		}
		cachefs_kstat_key = key;
		key = cachefs_kstat_key + cachefs_kstat_key_n;
		++cachefs_kstat_key_n;
		rc = key->ks_id = cachefs_kstat_key_n; /* offset + 1 */

		key->ks_mountpoint = (uint64_t)(uintptr_t)
		    cachefs_strdup(mountpoint);
		key->ks_backfs = (uint64_t)(uintptr_t)cachefs_strdup(backfs);
		key->ks_cachedir = (uint64_t)(uintptr_t)
		    cachefs_strdup(cachedir);
		key->ks_cacheid = (uint64_t)(uintptr_t)cachefs_strdup(cacheid);
	} else
		rc = key->ks_id;

	mutex_enter(&fscp->fs_fslock); /* protect fscp */

	fscp->fs_kstat_id = rc;

	mutex_exit(&fscp->fs_fslock); /* finished with fscp */
	/* finished cachefs_kstat_key */
	mutex_exit(&cachefs_kstat_key_lock);

	key->ks_vfsp = (uint64_t)(uintptr_t)fscp->fs_cfsvfsp;
	key->ks_mounted = 1;

	/*
	 * we must not be holding any mutex that is a ks_lock field
	 * for one of the kstats when we invoke kstat_create,
	 * kstat_install, and friends.
	 */
	ASSERT(MUTEX_NOT_HELD(&cachefs_kstat_key_lock));
	/* really should be EVERY cachep's c_log_mutex */
	ASSERT(MUTEX_NOT_HELD(&cachep->c_log_mutex));

	/* cachefs.#.log */
	ksp = kstat_create("cachefs", fscp->fs_kstat_id, "log",
	    "misc", KSTAT_TYPE_RAW, 1,
	    KSTAT_FLAG_WRITABLE | KSTAT_FLAG_VIRTUAL);
	if (ksp != NULL) {
		ksp->ks_data = cachep->c_log_ctl;
		ksp->ks_data_size = sizeof (cachefs_log_control_t);
		ksp->ks_lock = &cachep->c_log_mutex;
		ksp->ks_snapshot = cachefs_log_kstat_snapshot;
		kstat_install(ksp);
	}
	/* cachefs.#.stats */
	ksp = kstat_create("cachefs", fscp->fs_kstat_id, "stats",
	    "misc", KSTAT_TYPE_RAW, 1,
	    KSTAT_FLAG_WRITABLE | KSTAT_FLAG_VIRTUAL);
	if (ksp != NULL) {
		ksp->ks_data = fscp;
		ksp->ks_data_size = sizeof (cachefs_stats_t);
		ksp->ks_snapshot = cachefs_stats_kstat_snapshot;
		kstat_install(ksp);
	}

out:
	if (mountpoint != NULL)
		cachefs_kmem_free(mountpoint, MAXPATHLEN);
	if (backfs != NULL)
		cachefs_kmem_free(backfs, MAXPATHLEN);
	if (cachedir != NULL)
		cachefs_kmem_free(cachedir, MAXPATHLEN);
}

void
cachefs_kstat_umount(int ksid)
{
	cachefs_kstat_key_t *k = cachefs_kstat_key + (ksid - 1);

	ASSERT(k->ks_id == ksid);

	k->ks_mounted = 0;

	kstat_delete_byname("cachefs", ksid, "stats");
	kstat_delete_byname("cachefs", ksid, "log");
}

int
cachefs_kstat_key_update(kstat_t *ksp, int rw)
{
	cachefs_kstat_key_t *key = *((cachefs_kstat_key_t **)ksp->ks_data);
	cachefs_kstat_key_t *k;
	int i;

	if (rw == KSTAT_WRITE)
		return (EIO);
	if (key == NULL)
		return (EIO);

	ksp->ks_data_size = cachefs_kstat_key_n * sizeof (*key);
	for (i = 0; i < cachefs_kstat_key_n; i++) {
		k = key + i;

		ksp->ks_data_size +=
		    strlen((char *)(uintptr_t)k->ks_mountpoint) + 1;
		ksp->ks_data_size +=
		    strlen((char *)(uintptr_t)k->ks_backfs) + 1;
		ksp->ks_data_size +=
		    strlen((char *)(uintptr_t)k->ks_cachedir) + 1;
		ksp->ks_data_size +=
		    strlen((char *)(uintptr_t)k->ks_cacheid) + 1;
	}

	ksp->ks_ndata = cachefs_kstat_key_n;

	return (0);
}

int
cachefs_kstat_key_snapshot(kstat_t *ksp, void *buf, int rw)
{
	cachefs_kstat_key_t *key = *((cachefs_kstat_key_t **)ksp->ks_data);
	cachefs_kstat_key_t *k;
	caddr_t s;
	int i;

	if (rw == KSTAT_WRITE)
		return (EIO);

	if (key == NULL)
		return (0); /* paranoid */

	bcopy(key, buf, cachefs_kstat_key_n * sizeof (*key));
	key = buf;
	s = (caddr_t)(key + cachefs_kstat_key_n);

	for (i = 0; i < cachefs_kstat_key_n; i++) {
		k = key + i;

		(void) strcpy(s, (char *)(uintptr_t)k->ks_mountpoint);
		k->ks_mountpoint = (uint64_t)(uintptr_t)(s - (uintptr_t)buf);
		s += strlen(s) + 1;
		(void) strcpy(s, (char *)(uintptr_t)k->ks_backfs);
		k->ks_backfs = (uint64_t)(uintptr_t)(s - (uintptr_t)buf);
		s += strlen(s) + 1;
		(void) strcpy(s, (char *)(uintptr_t)k->ks_cachedir);
		k->ks_cachedir = (uint64_t)(uintptr_t)(s - (uintptr_t)buf);
		s += strlen(s) + 1;
		(void) strcpy(s, (char *)(uintptr_t)k->ks_cacheid);
		k->ks_cacheid = (uint64_t)(uintptr_t)(s - (uintptr_t)buf);
		s += strlen(s) + 1;
	}

	return (0);
}

extern void  cachefs_inactivate();

static int
cachefs_unmount(vfs_t *vfsp, int flag, cred_t *cr)
{
	fscache_t *fscp = VFS_TO_FSCACHE(vfsp);
	struct cachefscache *cachep = fscp->fs_cache;
	int error;
	int xx;
	vnode_t *nmvp;
	struct vattr attr;

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_VFSOP)
		printf("cachefs_unmount: ENTER fscp %p\n", fscp);
#endif

	if ((error = secpolicy_fs_unmount(cr, vfsp)) != 0)
		goto out;

	/*
	 * forced unmount is not supported by this file system
	 * and thus, ENOTSUP, is being returned.
	 */
	if (flag & MS_FORCE) {
		error = ENOTSUP;
		goto out;
	}
	/* if a log file exists don't allow the unmount */
	if (fscp->fs_dlogfile) {
		error = EBUSY;
		goto out;
	}

	/*
	 * wait for the cache-wide async queue to drain.  Someone
	 * here may be trying to sync our fscache...
	 */
	while (cachefs_async_halt(&fscp->fs_cache->c_workq, 0) == EBUSY) {
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_VFSOP)
			printf("unmount: waiting for cache async queue...\n");
#endif
	}

	error = cachefs_async_halt(&fscp->fs_workq, 1);
	if (error) {
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_VFSOP)
			printf("cachefs_unmount: "
			    "cachefs_async_halt error %d\n", error);
#endif
		goto out;
	}

	/*
	 * No active cnodes on this cache && rootvp refcnt == 1
	 */
	mutex_enter(&fscp->fs_fslock);
	xx = fscp->fs_cnodecnt - fscp->fs_idlecnt;
	ASSERT(xx >= 1);
	if (xx > 1 || fscp->fs_rootvp->v_count != 1) {
		mutex_exit(&fscp->fs_fslock);
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_VFSOP)
			printf("cachefs_unmount: busy (cnodes active %d, idle "
				"%d)\n", fscp->fs_cnodecnt, fscp->fs_idlecnt);
#endif
		error = EBUSY;
		goto out;
	}
	mutex_exit(&fscp->fs_fslock);

	/* get rid of anything on the idle list */
	ASSERT(fscp->fs_idleclean == 0);
	cachefs_cnode_idleclean(fscp, 1);
	if (fscp->fs_cnodecnt > 1) {
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_VFSOP)
			printf("cachefs_unmount: busy (cnode count %d)\n",
				fscp->fs_cnodecnt);
#endif
		error = EBUSY;
		goto out;
	}

	fscache_hold(fscp);

	/* get rid of the root cnode */
	if (cachefs_cnode_inactive(fscp->fs_rootvp, cr) == EBUSY) {
		fscache_rele(fscp);
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_VFSOP)
			printf("cachefs_unmount: busy (inactive failed)\n");
#endif
		error = EBUSY;
		goto out;
	}

	/* create the file indicating not mounted */
	attr.va_mode = S_IFREG | 0666;
	attr.va_uid = 0;
	attr.va_gid = 0;
	attr.va_type = VREG;
	attr.va_mask = AT_TYPE | AT_MODE | AT_UID | AT_GID;
	if (fscp->fs_fscdirvp != NULL)
		xx = VOP_CREATE(fscp->fs_fscdirvp, CACHEFS_UNMNT_FILE, &attr,
		    NONEXCL, 0600, &nmvp, kcred, 0, NULL, NULL);
	else
		xx = ENOENT; /* for unmounting when NOCACHE */
	if (xx == 0) {
		VN_RELE(nmvp);
	} else {
		printf("could not create %s %d\n", CACHEFS_UNMNT_FILE, xx);
	}

	ASSERT(fscp->fs_cnodecnt == 0);

	/* sync the file system just in case */
	fscache_sync(fscp);

	/* lock out other unmounts and mount */
	mutex_enter(&cachefs_cachelock);

	/* mark the file system as not mounted */
	mutex_enter(&fscp->fs_fslock);
	fscp->fs_flags &= ~CFS_FS_MOUNTED;
	fscp->fs_rootvp = NULL;
	if (fscp->fs_kstat_id > 0)
		cachefs_kstat_umount(fscp->fs_kstat_id);
	fscp->fs_kstat_id = 0;

	/* drop the inum translation table */
	if (fscp->fs_inum_size > 0) {
		cachefs_kmem_free(fscp->fs_inum_trans,
		    fscp->fs_inum_size * sizeof (cachefs_inum_trans_t));
		fscp->fs_inum_size = 0;
		fscp->fs_inum_trans = NULL;
		fscp->fs_flags &= ~CFS_FS_HASHPRINT;
	}
	mutex_exit(&fscp->fs_fslock);

	fscache_rele(fscp);

	/* get rid of any unused fscache objects */
	mutex_enter(&cachep->c_fslistlock);
	fscache_list_gc(cachep);
	mutex_exit(&cachep->c_fslistlock);

	/* get the number of mounts on this cache */
	mutex_enter(&cachep->c_fslistlock);
	xx = fscache_list_mounted(cachep);
	mutex_exit(&cachep->c_fslistlock);

	if (CACHEFS_LOG_LOGGING(cachep, CACHEFS_LOG_UMOUNT))
		cachefs_log_umount(cachep, 0, vfsp);

	/* if no mounts left, deactivate the cache */
	if (xx == 0)
		cachefs_delete_cachep(cachep);

	mutex_exit(&cachefs_cachelock);

out:
	if (error) {
		if (CACHEFS_LOG_LOGGING(cachep, CACHEFS_LOG_UMOUNT))
			cachefs_log_umount(cachep, error, vfsp);
	}
#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_VFSOP)
		printf("cachefs_unmount: EXIT\n");
#endif
	return (error);
}

/*
 * remove the cache from the list of caches
 */

static void
cachefs_delete_cachep(cachefscache_t *cachep)
{
	struct cachefscache **cachepp;
	int found = 0;

	ASSERT(MUTEX_HELD(&cachefs_cachelock));

	for (cachepp = &cachefs_cachelist;
	    *cachepp != NULL;
	    cachepp = &(*cachepp)->c_next) {
		if (*cachepp == cachep) {
			*cachepp = cachep->c_next;
			found++;
			break;
		}
	}
	ASSERT(found);

	/* shut down the cache */
	cachefs_cache_destroy(cachep);
}

static int
cachefs_root(vfs_t *vfsp, vnode_t **vpp)
{
	/*LINTED alignment okay*/
	struct fscache *fscp = (struct fscache *)vfsp->vfs_data;

	ASSERT(fscp != NULL);
	ASSERT(fscp->fs_rootvp != NULL);

	if (getzoneid() != GLOBAL_ZONEID)
		return (EPERM);
	*vpp = fscp->fs_rootvp;
	VN_HOLD(*vpp);
	return (0);
}

/*
 * Get file system statistics.
 */
static int
cachefs_statvfs(register vfs_t *vfsp, struct statvfs64 *sbp)
{
	struct fscache *fscp = VFS_TO_FSCACHE(vfsp);
	struct cache_label *lp = &fscp->fs_cache->c_label;
	struct cache_usage *up = &fscp->fs_cache->c_usage;
	int error;

	if (getzoneid() != GLOBAL_ZONEID)
		return (EPERM);
	error = cachefs_cd_access(fscp, 0, 0);
	if (error)
		return (error);

	if (fscp->fs_cdconnected == CFS_CD_CONNECTED) {
		/*
		 * When connected return backfs stats
		 */
		error = VFS_STATVFS(fscp->fs_backvfsp, sbp);
	} else {
		/*
		 * Otherwise, just return the frontfs stats
		 */
		ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);
		error = VFS_STATVFS(fscp->fs_fscdirvp->v_vfsp, sbp);
		if (!error) {
			dev32_t	d32;

			sbp->f_frsize = MAXBSIZE;
			sbp->f_blocks = lp->cl_maxblks;
			sbp->f_bfree = sbp->f_bavail =
			    lp->cl_maxblks - up->cu_blksused;
			sbp->f_files = lp->cl_maxinodes;
			sbp->f_ffree = sbp->f_favail =
			    lp->cl_maxinodes - up->cu_filesused;
			(void) cmpldev(&d32, vfsp->vfs_dev);
			sbp->f_fsid = d32;
		}
	}
	cachefs_cd_release(fscp);
	if (error)
		return (error);

	/*
	 * Make sure fstype is CFS.
	 */
	(void) strcpy(sbp->f_basetype, vfssw[vfsp->vfs_fstype].vsw_name);
	bzero(sbp->f_fstr, sizeof (sbp->f_fstr));

	return (0);
}

/*
 * queue a request to sync the given fscache
 */
static void
queue_sync(struct cachefscache *cachep, cred_t *cr)
{
	struct cachefs_req *rp;

	rp = kmem_cache_alloc(cachefs_req_cache, KM_SLEEP);
	rp->cfs_cmd = CFS_CACHE_SYNC;
	rp->cfs_cr = cr;
	rp->cfs_req_u.cu_fs_sync.cf_cachep = cachep;
	crhold(rp->cfs_cr);
	cachefs_addqueue(rp, &cachep->c_workq);
}

/*ARGSUSED*/
static int
cachefs_sync(vfs_t *vfsp, short flag, cred_t *cr)
{
	struct fscache *fscp;
	struct cachefscache *cachep;

	if (getzoneid() != GLOBAL_ZONEID)
		return (EPERM);
	if (!(flag & SYNC_ATTR)) {
		/*
		 * queue an async request to do the sync.
		 * We always sync an entire cache (as opposed to an
		 * individual fscache) so that we have an opportunity
		 * to set the clean flag.
		 */
		if (vfsp) {
			/*LINTED alignment okay*/
			fscp = (struct fscache *)vfsp->vfs_data;
			queue_sync(fscp->fs_cache, cr);
		} else {
			mutex_enter(&cachefs_cachelock);
			for (cachep = cachefs_cachelist; cachep != NULL;
			    cachep = cachep->c_next) {
				queue_sync(cachep, cr);
			}
			mutex_exit(&cachefs_cachelock);
		}
	}
	return (0);
}

static int
cachefs_remount(struct vfs *vfsp, struct mounta *uap)
{
	fscache_t *fscp = VFS_TO_FSCACHE(vfsp);
	cachefscache_t *cachep = fscp->fs_cache;
	int error = 0;
	STRUCT_DECL(cachefs_mountargs, map);
	struct cachefsoptions	*cfs_options;
	char			*backfs, *cacheid, *cachedir;
	struct vnode *cachedirvp = NULL;
	ino64_t fsid;
	vnode_t *backrootvp = NULL;
	struct vnode *tmpdirvp = NULL;

	STRUCT_INIT(map, get_udatamodel());
	error = copyin(uap->dataptr, STRUCT_BUF(map),
			SIZEOF_STRUCT(cachefs_mountargs, DATAMODEL_NATIVE));
	if (error)
		goto out;

	/*
	 * get cache directory vp
	 */
	cachedir = (char *)STRUCT_FGETP(map, cfs_cachedir);
	error = lookupname(cachedir, UIO_USERSPACE, FOLLOW,
	    NULLVPP, &cachedirvp);
	if (error)
		goto out;
	if (cachedirvp->v_type != VDIR) {
		error = EINVAL;
		goto out;
	}

	error = 0;
	if (cachedirvp) {
		error = VOP_LOOKUP(cachedirvp, CACHEFS_DLOG_FILE,
		    &tmpdirvp, NULL, 0, NULL, kcred, NULL, NULL, NULL);
	}
	cfs_options = (struct cachefsoptions *)STRUCT_FADDR(map, cfs_options);
	cacheid = (char *)STRUCT_FGETP(map, cfs_cacheid);
/* XXX not quite right */
#if 0
	/*
	 * If a log file exists and the cache is being mounted without
	 * the snr (aka disconnectable) option, return an error.
	 */
	if ((error == 0) &&
	    !(cfs_options->opt_flags & CFS_DISCONNECTABLE)) {
		cmn_err(CE_WARN,
		    "cachefs_mount: log exists and disconnectable"
		    "option not specified\n");
		error = EINVAL;
		goto out;
	}
#endif
	error = 0;

	/*
	 * If the user is using NFSv4 and there are other options
	 * specified, make sure we ignore the other options.
	 */
	if (CFS_ISFS_BACKFS_NFSV4(fscp)) {
		cfs_options->opt_flags = CFS_BACKFS_NFSV4;
	}

	/* XXX need mount options "nocache" and "nofill" */

	/* if nocache is being turned off */
	if (cachep->c_flags & CACHE_NOCACHE) {
		error = cachefs_cache_activate_ro(cachep, cachedirvp);
		if (error)
			goto out;
		cachefs_cache_activate_rw(cachep);

		/* get the fsid for the fscache */
		error = fscache_name_to_fsid(cachep, cacheid, &fsid);
		if (error)
			fsid = 0;

		/* activate the fscache */
		mutex_enter(&cachep->c_fslistlock);
		error = fscache_enable(fscp, fsid, cacheid,
			cfs_options, fscp->fs_info.fi_root);
		mutex_exit(&cachep->c_fslistlock);
		if (error) {
			cmn_err(CE_WARN, "cachefs: cannot remount %s\n",
				cacheid);
			goto out;
		}

		/* enable the cache */
		cachefs_enable_caching(fscp);
		fscache_activate_rw(fscp);
	}

	/* else if nofill is being turn off */
	else if (cachep->c_flags & CACHE_NOFILL) {
		ASSERT(cachep->c_flags & CACHE_NOFILL);
		cachefs_cache_activate_rw(cachep);

		/* enable the cache */
		cachefs_enable_caching(fscp);
		fscache_activate_rw(fscp);
	}

	fscache_acset(fscp, STRUCT_FGET(map, cfs_acregmin),
	    STRUCT_FGET(map, cfs_acregmax),
	    STRUCT_FGET(map, cfs_acdirmin), STRUCT_FGET(map, cfs_acdirmax));

	/* if the backfs is mounted now or we have a new backfs */
	backfs = (char *)STRUCT_FGETP(map, cfs_backfs);
	if (backfs && (cfs_options->opt_flags & CFS_SLIDE)) {
		/* get the back file system root vp */
		error = lookupname(backfs, UIO_USERSPACE, FOLLOW,
			NULLVPP, &backrootvp);
		if (error)
			goto out;

		/*
		 * Make sure the thing we just looked up is a directory
		 * and a root of a file system
		 */
		if (backrootvp->v_type != VDIR ||
		    !(backrootvp->v_flag & VROOT)) {
			cmn_err(CE_WARN,
			    "cachefs_mount: backpath not a directory\n");
			error = EINVAL;
			goto out;
		}

		/*
		 * XXX
		 * Kind of dangerous to just set this but we do
		 * not have locks around usage of fs_backvfsp.
		 * Hope for the best for now.
		 * Probably should also spin through vnodes and fix them up.
		 * Krishna - fixed c_backvp to reflect the change.
		 */
		fscp->fs_backvfsp = backrootvp->v_vfsp;
		((cnode_t *)(fscp->fs_rootvp->v_data))->c_backvp = backrootvp;

		/*
		 * Now the root cnode structure is an owner of
		 * the opened back root vnode structure; we must
		 * clear the pointer to back root vnode here as
		 * we don't need it since now, and the root cnode
		 * structure will control the vnode
		 */
		backrootvp = (vnode_t *)NULL;
	}

	if (fscp->fs_kstat_id > 0)
		cachefs_kstat_umount(fscp->fs_kstat_id);
	fscp->fs_kstat_id = 0;
	cachefs_kstat_mount(fscp, uap->dir, backfs, cachedir, cacheid);

	if (CACHEFS_LOG_LOGGING(cachep, CACHEFS_LOG_MOUNT))
		cachefs_log_mount(cachep, error, vfsp, fscp,
		    uap->dir, UIO_USERSPACE,
		    (STRUCT_BUF(map) != NULL) ? cacheid : NULL);

out:
	if (cachedirvp)
		VN_RELE(cachedirvp);
	if (backrootvp)
		VN_RELE(backrootvp);
	return (error);
}
