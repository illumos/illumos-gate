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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

/*
 * utility routines for the /dev fs
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/cred.h>
#include <sys/dirent.h>
#include <sys/pathname.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/mode.h>
#include <sys/policy.h>
#include <fs/fs_subr.h>
#include <sys/mount.h>
#include <sys/fs/snode.h>
#include <sys/fs/dv_node.h>
#include <sys/fs/sdev_impl.h>
#include <sys/sunndi.h>
#include <sys/sunmdi.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/modctl.h>

#ifdef DEBUG
int sdev_debug = 0x00000001;
int sdev_debug_cache_flags = 0;
#endif

/*
 * globals
 */
/* prototype memory vattrs */
vattr_t sdev_vattr_dir = {
	AT_TYPE|AT_MODE|AT_UID|AT_GID,		/* va_mask */
	VDIR,					/* va_type */
	SDEV_DIRMODE_DEFAULT,			/* va_mode */
	SDEV_UID_DEFAULT,			/* va_uid */
	SDEV_GID_DEFAULT,			/* va_gid */
	0,					/* va_fsid */
	0,					/* va_nodeid */
	0,					/* va_nlink */
	0,					/* va_size */
	0,					/* va_atime */
	0,					/* va_mtime */
	0,					/* va_ctime */
	0,					/* va_rdev */
	0,					/* va_blksize */
	0,					/* va_nblocks */
	0					/* va_vcode */
};

vattr_t sdev_vattr_lnk = {
	AT_TYPE|AT_MODE,			/* va_mask */
	VLNK,					/* va_type */
	SDEV_LNKMODE_DEFAULT,			/* va_mode */
	SDEV_UID_DEFAULT,			/* va_uid */
	SDEV_GID_DEFAULT,			/* va_gid */
	0,					/* va_fsid */
	0,					/* va_nodeid */
	0,					/* va_nlink */
	0,					/* va_size */
	0,					/* va_atime */
	0,					/* va_mtime */
	0,					/* va_ctime */
	0,					/* va_rdev */
	0,					/* va_blksize */
	0,					/* va_nblocks */
	0					/* va_vcode */
};

vattr_t sdev_vattr_blk = {
	AT_TYPE|AT_MODE|AT_UID|AT_GID,		/* va_mask */
	VBLK,					/* va_type */
	S_IFBLK | SDEV_DEVMODE_DEFAULT,		/* va_mode */
	SDEV_UID_DEFAULT,			/* va_uid */
	SDEV_GID_DEFAULT,			/* va_gid */
	0,					/* va_fsid */
	0,					/* va_nodeid */
	0,					/* va_nlink */
	0,					/* va_size */
	0,					/* va_atime */
	0,					/* va_mtime */
	0,					/* va_ctime */
	0,					/* va_rdev */
	0,					/* va_blksize */
	0,					/* va_nblocks */
	0					/* va_vcode */
};

vattr_t sdev_vattr_chr = {
	AT_TYPE|AT_MODE|AT_UID|AT_GID,		/* va_mask */
	VCHR,					/* va_type */
	S_IFCHR | SDEV_DEVMODE_DEFAULT,		/* va_mode */
	SDEV_UID_DEFAULT,			/* va_uid */
	SDEV_GID_DEFAULT,			/* va_gid */
	0,					/* va_fsid */
	0,					/* va_nodeid */
	0,					/* va_nlink */
	0,					/* va_size */
	0,					/* va_atime */
	0,					/* va_mtime */
	0,					/* va_ctime */
	0,					/* va_rdev */
	0,					/* va_blksize */
	0,					/* va_nblocks */
	0					/* va_vcode */
};

kmem_cache_t	*sdev_node_cache;	/* sdev_node cache */
int		devtype;		/* fstype */

/* static */
static struct vnodeops *sdev_get_vop(struct sdev_node *);
static void sdev_set_no_negcache(struct sdev_node *);
static fs_operation_def_t *sdev_merge_vtab(const fs_operation_def_t []);
static void sdev_free_vtab(fs_operation_def_t *);

static void
sdev_prof_free(struct sdev_node *dv)
{
	ASSERT(!SDEV_IS_GLOBAL(dv));
	if (dv->sdev_prof.dev_name)
		nvlist_free(dv->sdev_prof.dev_name);
	if (dv->sdev_prof.dev_map)
		nvlist_free(dv->sdev_prof.dev_map);
	if (dv->sdev_prof.dev_symlink)
		nvlist_free(dv->sdev_prof.dev_symlink);
	if (dv->sdev_prof.dev_glob_incdir)
		nvlist_free(dv->sdev_prof.dev_glob_incdir);
	if (dv->sdev_prof.dev_glob_excdir)
		nvlist_free(dv->sdev_prof.dev_glob_excdir);
	bzero(&dv->sdev_prof, sizeof (dv->sdev_prof));
}

/* sdev_node cache constructor */
/*ARGSUSED1*/
static int
i_sdev_node_ctor(void *buf, void *cfarg, int flag)
{
	struct sdev_node *dv = (struct sdev_node *)buf;
	struct vnode *vp;

	bzero(buf, sizeof (struct sdev_node));
	vp = dv->sdev_vnode = vn_alloc(flag);
	if (vp == NULL) {
		return (-1);
	}
	vp->v_data = dv;
	rw_init(&dv->sdev_contents, NULL, RW_DEFAULT, NULL);
	return (0);
}

/* sdev_node cache destructor */
/*ARGSUSED1*/
static void
i_sdev_node_dtor(void *buf, void *arg)
{
	struct sdev_node *dv = (struct sdev_node *)buf;
	struct vnode *vp = SDEVTOV(dv);

	rw_destroy(&dv->sdev_contents);
	vn_free(vp);
}

/* initialize sdev_node cache */
void
sdev_node_cache_init()
{
	int flags = 0;

#ifdef	DEBUG
	flags = sdev_debug_cache_flags;
	if (flags)
		sdcmn_err(("cache debug flags 0x%x\n", flags));
#endif	/* DEBUG */

	ASSERT(sdev_node_cache == NULL);
	sdev_node_cache = kmem_cache_create("sdev_node_cache",
	    sizeof (struct sdev_node), 0, i_sdev_node_ctor, i_sdev_node_dtor,
	    NULL, NULL, NULL, flags);
}

/* destroy sdev_node cache */
void
sdev_node_cache_fini()
{
	ASSERT(sdev_node_cache != NULL);
	kmem_cache_destroy(sdev_node_cache);
	sdev_node_cache = NULL;
}

/*
 * Compare two nodes lexographically to balance avl tree
 */
static int
sdev_compare_nodes(const struct sdev_node *dv1, const struct sdev_node *dv2)
{
	int rv;
	if ((rv = strcmp(dv1->sdev_name, dv2->sdev_name)) == 0)
		return (0);
	return ((rv < 0) ? -1 : 1);
}

void
sdev_set_nodestate(struct sdev_node *dv, sdev_node_state_t state)
{
	ASSERT(dv);
	ASSERT(RW_WRITE_HELD(&dv->sdev_contents));
	dv->sdev_state = state;
}

static void
sdev_attr_update(struct sdev_node *dv, vattr_t *vap)
{
	timestruc_t	now;
	struct vattr	*attrp;
	uint_t		mask;

	ASSERT(dv->sdev_attr);
	ASSERT(vap);

	attrp = dv->sdev_attr;
	mask = vap->va_mask;
	if (mask & AT_TYPE)
		attrp->va_type = vap->va_type;
	if (mask & AT_MODE)
		attrp->va_mode = vap->va_mode;
	if (mask & AT_UID)
		attrp->va_uid = vap->va_uid;
	if (mask & AT_GID)
		attrp->va_gid = vap->va_gid;
	if (mask & AT_RDEV)
		attrp->va_rdev = vap->va_rdev;

	gethrestime(&now);
	attrp->va_atime = (mask & AT_ATIME) ? vap->va_atime : now;
	attrp->va_mtime = (mask & AT_MTIME) ? vap->va_mtime : now;
	attrp->va_ctime = (mask & AT_CTIME) ? vap->va_ctime : now;
}

static void
sdev_attr_alloc(struct sdev_node *dv, vattr_t *vap)
{
	ASSERT(dv->sdev_attr == NULL);
	ASSERT(vap->va_mask & AT_TYPE);
	ASSERT(vap->va_mask & AT_MODE);

	dv->sdev_attr = kmem_zalloc(sizeof (struct vattr), KM_SLEEP);
	sdev_attr_update(dv, vap);
}

/* alloc and initialize a sdev_node */
int
sdev_nodeinit(struct sdev_node *ddv, char *nm, struct sdev_node **newdv,
    vattr_t *vap)
{
	struct sdev_node *dv = NULL;
	struct vnode *vp;
	size_t nmlen, len;
	devname_handle_t  *dhl;

	nmlen = strlen(nm) + 1;
	if (nmlen > MAXNAMELEN) {
		sdcmn_err9(("sdev_nodeinit: node name %s"
		    " too long\n", nm));
		*newdv = NULL;
		return (ENAMETOOLONG);
	}

	dv = kmem_cache_alloc(sdev_node_cache, KM_SLEEP);

	dv->sdev_name = kmem_alloc(nmlen, KM_SLEEP);
	bcopy(nm, dv->sdev_name, nmlen);
	dv->sdev_namelen = nmlen - 1;	/* '\0' not included */
	len = strlen(ddv->sdev_path) + strlen(nm) + 2;
	dv->sdev_path = kmem_alloc(len, KM_SLEEP);
	(void) snprintf(dv->sdev_path, len, "%s/%s", ddv->sdev_path, nm);
	/* overwritten for VLNK nodes */
	dv->sdev_symlink = NULL;

	vp = SDEVTOV(dv);
	vn_reinit(vp);
	vp->v_vfsp = SDEVTOV(ddv)->v_vfsp;
	if (vap)
		vp->v_type = vap->va_type;

	/*
	 * initialized to the parent's vnodeops.
	 * maybe overwriten for a VDIR
	 */
	vn_setops(vp, vn_getops(SDEVTOV(ddv)));
	vn_exists(vp);

	dv->sdev_dotdot = NULL;
	dv->sdev_attrvp = NULL;
	if (vap) {
		sdev_attr_alloc(dv, vap);
	} else {
		dv->sdev_attr = NULL;
	}

	dv->sdev_ino = sdev_mkino(dv);
	dv->sdev_nlink = 0;		/* updated on insert */
	dv->sdev_flags = ddv->sdev_flags; /* inherit from the parent first */
	dv->sdev_flags |= SDEV_BUILD;
	mutex_init(&dv->sdev_lookup_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&dv->sdev_lookup_cv, NULL, CV_DEFAULT, NULL);
	if (SDEV_IS_GLOBAL(ddv)) {
		dv->sdev_flags |= SDEV_GLOBAL;
		dhl = &(dv->sdev_handle);
		dhl->dh_data = dv;
		dhl->dh_args = NULL;
		sdev_set_no_negcache(dv);
		dv->sdev_gdir_gen = 0;
	} else {
		dv->sdev_flags &= ~SDEV_GLOBAL;
		dv->sdev_origin = NULL; /* set later */
		bzero(&dv->sdev_prof, sizeof (dv->sdev_prof));
		dv->sdev_ldir_gen = 0;
		dv->sdev_devtree_gen = 0;
	}

	rw_enter(&dv->sdev_contents, RW_WRITER);
	sdev_set_nodestate(dv, SDEV_INIT);
	rw_exit(&dv->sdev_contents);
	*newdv = dv;

	return (0);
}

/*
 * Transition a sdev_node into SDEV_READY state. If this fails, it is up to the
 * caller to transition the node to the SDEV_ZOMBIE state.
 */
int
sdev_nodeready(struct sdev_node *dv, struct vattr *vap, struct vnode *avp,
    void *args, struct cred *cred)
{
	int error = 0;
	struct vnode *vp = SDEVTOV(dv);
	vtype_t type;

	ASSERT(dv && (dv->sdev_state != SDEV_READY) && vap);

	type = vap->va_type;
	vp->v_type = type;
	vp->v_rdev = vap->va_rdev;
	rw_enter(&dv->sdev_contents, RW_WRITER);
	if (type == VDIR) {
		dv->sdev_nlink = 2;
		dv->sdev_flags &= ~SDEV_PERSIST;
		dv->sdev_flags &= ~SDEV_DYNAMIC;
		vn_setops(vp, sdev_get_vop(dv)); /* from internal vtab */
		ASSERT(dv->sdev_dotdot);
		ASSERT(SDEVTOV(dv->sdev_dotdot)->v_type == VDIR);
		vp->v_rdev = SDEVTOV(dv->sdev_dotdot)->v_rdev;
		avl_create(&dv->sdev_entries,
		    (int (*)(const void *, const void *))sdev_compare_nodes,
		    sizeof (struct sdev_node),
		    offsetof(struct sdev_node, sdev_avllink));
	} else if (type == VLNK) {
		ASSERT(args);
		dv->sdev_nlink = 1;
		dv->sdev_symlink = i_ddi_strdup((char *)args, KM_SLEEP);
	} else {
		dv->sdev_nlink = 1;
	}

	if (!(SDEV_IS_GLOBAL(dv))) {
		dv->sdev_origin = (struct sdev_node *)args;
		dv->sdev_flags &= ~SDEV_PERSIST;
	}

	/*
	 * shadow node is created here OR
	 * if failed (indicated by dv->sdev_attrvp == NULL),
	 * created later in sdev_setattr
	 */
	if (avp) {
		dv->sdev_attrvp = avp;
	} else {
		if (dv->sdev_attr == NULL) {
			sdev_attr_alloc(dv, vap);
		} else {
			sdev_attr_update(dv, vap);
		}

		if ((dv->sdev_attrvp == NULL) && SDEV_IS_PERSIST(dv))
			error = sdev_shadow_node(dv, cred);
	}

	if (error == 0) {
		/* transition to READY state */
		sdev_set_nodestate(dv, SDEV_READY);
		sdev_nc_node_exists(dv);
	}
	rw_exit(&dv->sdev_contents);
	return (error);
}

/*
 * Build the VROOT sdev_node.
 */
/*ARGSUSED*/
struct sdev_node *
sdev_mkroot(struct vfs *vfsp, dev_t devdev, struct vnode *mvp,
    struct vnode *avp, struct cred *cred)
{
	struct sdev_node *dv;
	struct vnode *vp;
	char devdir[] = "/dev";

	ASSERT(sdev_node_cache != NULL);
	ASSERT(avp);
	dv = kmem_cache_alloc(sdev_node_cache, KM_SLEEP);
	vp = SDEVTOV(dv);
	vn_reinit(vp);
	vp->v_flag |= VROOT;
	vp->v_vfsp = vfsp;
	vp->v_type = VDIR;
	vp->v_rdev = devdev;
	vn_setops(vp, sdev_vnodeops); /* apply the default vnodeops at /dev */
	vn_exists(vp);

	if (vfsp->vfs_mntpt)
		dv->sdev_name = i_ddi_strdup(
		    (char *)refstr_value(vfsp->vfs_mntpt), KM_SLEEP);
	else
		/* vfs_mountdev1 set mount point later */
		dv->sdev_name = i_ddi_strdup("/dev", KM_SLEEP);
	dv->sdev_namelen = strlen(dv->sdev_name); /* '\0' not included */
	dv->sdev_path = i_ddi_strdup(devdir, KM_SLEEP);
	dv->sdev_ino = SDEV_ROOTINO;
	dv->sdev_nlink = 2;		/* name + . (no sdev_insert) */
	dv->sdev_dotdot = dv;		/* .. == self */
	dv->sdev_attrvp = avp;
	dv->sdev_attr = NULL;
	mutex_init(&dv->sdev_lookup_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&dv->sdev_lookup_cv, NULL, CV_DEFAULT, NULL);
	if (strcmp(dv->sdev_name, "/dev") == 0) {
		dv->sdev_flags = SDEV_BUILD|SDEV_GLOBAL|SDEV_PERSIST;
		bzero(&dv->sdev_handle, sizeof (dv->sdev_handle));
		dv->sdev_gdir_gen = 0;
	} else {
		dv->sdev_flags = SDEV_BUILD;
		dv->sdev_flags &= ~SDEV_PERSIST;
		bzero(&dv->sdev_prof, sizeof (dv->sdev_prof));
		dv->sdev_ldir_gen = 0;
		dv->sdev_devtree_gen = 0;
	}

	avl_create(&dv->sdev_entries,
	    (int (*)(const void *, const void *))sdev_compare_nodes,
	    sizeof (struct sdev_node),
	    offsetof(struct sdev_node, sdev_avllink));

	rw_enter(&dv->sdev_contents, RW_WRITER);
	sdev_set_nodestate(dv, SDEV_READY);
	rw_exit(&dv->sdev_contents);
	sdev_nc_node_exists(dv);
	return (dv);
}

/* directory dependent vop table */
struct sdev_vop_table {
	char *vt_name;				/* subdirectory name */
	const fs_operation_def_t *vt_service;	/* vnodeops table */
	struct vnodeops *vt_vops;		/* constructed vop */
	struct vnodeops **vt_global_vops;	/* global container for vop */
	int (*vt_vtor)(struct sdev_node *);	/* validate sdev_node */
	int vt_flags;
};

/*
 * A nice improvement would be to provide a plug-in mechanism
 * for this table instead of a const table.
 */
static struct sdev_vop_table vtab[] =
{
	{ "pts", devpts_vnodeops_tbl, NULL, &devpts_vnodeops, devpts_validate,
	SDEV_DYNAMIC | SDEV_VTOR },

	{ "vt", devvt_vnodeops_tbl, NULL, &devvt_vnodeops, devvt_validate,
	SDEV_DYNAMIC | SDEV_VTOR },

	{ "zvol", devzvol_vnodeops_tbl, NULL, &devzvol_vnodeops,
	devzvol_validate, SDEV_ZONED | SDEV_DYNAMIC | SDEV_VTOR | SDEV_SUBDIR },

	{ "zcons", NULL, NULL, NULL, NULL, SDEV_NO_NCACHE },

	{ "net", devnet_vnodeops_tbl, NULL, &devnet_vnodeops, devnet_validate,
	SDEV_DYNAMIC | SDEV_VTOR },

	{ "ipnet", devipnet_vnodeops_tbl, NULL, &devipnet_vnodeops,
	devipnet_validate, SDEV_DYNAMIC | SDEV_VTOR | SDEV_NO_NCACHE },

	/*
	 * SDEV_DYNAMIC: prevent calling out to devfsadm, since only the
	 * lofi driver controls child nodes.
	 *
	 * SDEV_PERSIST: ensure devfsadm knows to clean up any persisted
	 * stale nodes (e.g. from devfsadm -R).
	 *
	 * In addition, devfsadm knows not to attempt a rmdir: a zone
	 * may hold a reference, which would zombify the node,
	 * preventing a mkdir.
	 */

	{ "lofi", NULL, NULL, NULL, NULL,
	    SDEV_ZONED | SDEV_DYNAMIC | SDEV_PERSIST },
	{ "rlofi", NULL, NULL, NULL, NULL,
	    SDEV_ZONED | SDEV_DYNAMIC | SDEV_PERSIST },

	{ NULL, NULL, NULL, NULL, NULL, 0}
};

/*
 * We need to match off of the sdev_path, not the sdev_name. We are only allowed
 * to exist directly under /dev.
 */
struct sdev_vop_table *
sdev_match(struct sdev_node *dv)
{
	int vlen;
	int i;
	const char *path;

	if (strlen(dv->sdev_path) <= 5)
		return (NULL);

	if (strncmp(dv->sdev_path, "/dev/", 5) != 0)
		return (NULL);
	path = dv->sdev_path + 5;

	for (i = 0; vtab[i].vt_name; i++) {
		if (strcmp(vtab[i].vt_name, path) == 0)
			return (&vtab[i]);
		if (vtab[i].vt_flags & SDEV_SUBDIR) {
			vlen = strlen(vtab[i].vt_name);
			if ((strncmp(vtab[i].vt_name, path,
			    vlen - 1) == 0) && path[vlen] == '/')
				return (&vtab[i]);
		}

	}
	return (NULL);
}

/*
 *  sets a directory's vnodeops if the directory is in the vtab;
 */
static struct vnodeops *
sdev_get_vop(struct sdev_node *dv)
{
	struct sdev_vop_table *vtp;
	char *path;

	path = dv->sdev_path;
	ASSERT(path);

	/* gets the relative path to /dev/ */
	path += 5;

	/* gets the vtab entry it matches */
	if ((vtp = sdev_match(dv)) != NULL) {
		dv->sdev_flags |= vtp->vt_flags;
		if (SDEV_IS_PERSIST(dv->sdev_dotdot) &&
		    (SDEV_IS_PERSIST(dv) || !SDEV_IS_DYNAMIC(dv)))
			dv->sdev_flags |= SDEV_PERSIST;

		if (vtp->vt_vops) {
			if (vtp->vt_global_vops)
				*(vtp->vt_global_vops) = vtp->vt_vops;

			return (vtp->vt_vops);
		}

		if (vtp->vt_service) {
			fs_operation_def_t *templ;
			templ = sdev_merge_vtab(vtp->vt_service);
			if (vn_make_ops(vtp->vt_name,
			    (const fs_operation_def_t *)templ,
			    &vtp->vt_vops) != 0) {
				cmn_err(CE_PANIC, "%s: malformed vnode ops\n",
				    vtp->vt_name);
				/*NOTREACHED*/
			}
			if (vtp->vt_global_vops) {
				*(vtp->vt_global_vops) = vtp->vt_vops;
			}
			sdev_free_vtab(templ);

			return (vtp->vt_vops);
		}

		return (sdev_vnodeops);
	}

	/* child inherits the persistence of the parent */
	if (SDEV_IS_PERSIST(dv->sdev_dotdot))
		dv->sdev_flags |= SDEV_PERSIST;

	return (sdev_vnodeops);
}

static void
sdev_set_no_negcache(struct sdev_node *dv)
{
	int i;
	char *path;

	ASSERT(dv->sdev_path);
	path = dv->sdev_path + strlen("/dev/");

	for (i = 0; vtab[i].vt_name; i++) {
		if (strcmp(vtab[i].vt_name, path) == 0) {
			if (vtab[i].vt_flags & SDEV_NO_NCACHE)
				dv->sdev_flags |= SDEV_NO_NCACHE;
			break;
		}
	}
}

void *
sdev_get_vtor(struct sdev_node *dv)
{
	struct sdev_vop_table *vtp;

	vtp = sdev_match(dv);
	if (vtp)
		return ((void *)vtp->vt_vtor);
	else
		return (NULL);
}

/*
 * Build the base root inode
 */
ino_t
sdev_mkino(struct sdev_node *dv)
{
	ino_t	ino;

	/*
	 * for now, follow the lead of tmpfs here
	 * need to someday understand the requirements here
	 */
	ino = (ino_t)(uint32_t)((uintptr_t)dv >> 3);
	ino += SDEV_ROOTINO + 1;

	return (ino);
}

int
sdev_getlink(struct vnode *linkvp, char **link)
{
	int err;
	char *buf;
	struct uio uio = {0};
	struct iovec iov = {0};

	if (linkvp == NULL)
		return (ENOENT);
	ASSERT(linkvp->v_type == VLNK);

	buf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	iov.iov_base = buf;
	iov.iov_len = MAXPATHLEN;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = MAXPATHLEN;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_llimit = MAXOFFSET_T;

	err = VOP_READLINK(linkvp, &uio, kcred, NULL);
	if (err) {
		cmn_err(CE_WARN, "readlink %s failed in dev\n", buf);
		kmem_free(buf, MAXPATHLEN);
		return (ENOENT);
	}

	/* mission complete */
	*link = i_ddi_strdup(buf, KM_SLEEP);
	kmem_free(buf, MAXPATHLEN);
	return (0);
}

/*
 * A convenient wrapper to get the devfs node vnode for a device
 * minor functionality: readlink() of a /dev symlink
 * Place the link into dv->sdev_symlink
 */
static int
sdev_follow_link(struct sdev_node *dv)
{
	int err;
	struct vnode *linkvp;
	char *link = NULL;

	linkvp = SDEVTOV(dv);
	if (linkvp == NULL)
		return (ENOENT);
	ASSERT(linkvp->v_type == VLNK);
	err = sdev_getlink(linkvp, &link);
	if (err) {
		dv->sdev_symlink = NULL;
		return (ENOENT);
	}

	ASSERT(link != NULL);
	dv->sdev_symlink = link;
	return (0);
}

static int
sdev_node_check(struct sdev_node *dv, struct vattr *nvap, void *nargs)
{
	vtype_t otype = SDEVTOV(dv)->v_type;

	/*
	 * existing sdev_node has a different type.
	 */
	if (otype != nvap->va_type) {
		sdcmn_err9(("sdev_node_check: existing node "
		    "  %s type %d does not match new node type %d\n",
		    dv->sdev_name, otype, nvap->va_type));
		return (EEXIST);
	}

	/*
	 * For a symlink, the target should be the same.
	 */
	if (otype == VLNK) {
		ASSERT(nargs != NULL);
		ASSERT(dv->sdev_symlink != NULL);
		if (strcmp(dv->sdev_symlink, (char *)nargs) != 0) {
			sdcmn_err9(("sdev_node_check: existing node "
			    " %s has different symlink %s as new node "
			    " %s\n", dv->sdev_name, dv->sdev_symlink,
			    (char *)nargs));
			return (EEXIST);
		}
	}

	return (0);
}

/*
 * sdev_mknode - a wrapper for sdev_nodeinit(), sdev_nodeready()
 *
 * arguments:
 *	- ddv (parent)
 *	- nm (child name)
 *	- newdv (sdev_node for nm is returned here)
 *	- vap (vattr for the node to be created, va_type should be set.
 *	- avp (attribute vnode)
 *	  the defaults should be used if unknown)
 *	- cred
 *	- args
 *	    . tnm (for VLNK)
 *	    . global sdev_node (for !SDEV_GLOBAL)
 * 	- state: SDEV_INIT, SDEV_READY
 *
 * only ddv, nm, newddv, vap, cred are required for sdev_mknode(SDEV_INIT)
 *
 * NOTE:  directory contents writers lock needs to be held before
 *	  calling this routine.
 */
int
sdev_mknode(struct sdev_node *ddv, char *nm, struct sdev_node **newdv,
    struct vattr *vap, struct vnode *avp, void *args, struct cred *cred,
    sdev_node_state_t state)
{
	int error = 0;
	sdev_node_state_t node_state;
	struct sdev_node *dv = NULL;

	ASSERT(state != SDEV_ZOMBIE);
	ASSERT(RW_WRITE_HELD(&ddv->sdev_contents));

	if (*newdv) {
		dv = *newdv;
	} else {
		/* allocate and initialize a sdev_node */
		if (ddv->sdev_state == SDEV_ZOMBIE) {
			sdcmn_err9(("sdev_mknode: parent %s ZOMBIEd\n",
			    ddv->sdev_path));
			return (ENOENT);
		}

		error = sdev_nodeinit(ddv, nm, &dv, vap);
		if (error != 0) {
			sdcmn_err9(("sdev_mknode: error %d,"
			    " name %s can not be initialized\n",
			    error, nm));
			return (error);
		}
		ASSERT(dv);

		/* insert into the directory cache */
		sdev_cache_update(ddv, &dv, nm, SDEV_CACHE_ADD);
	}

	ASSERT(dv);
	node_state = dv->sdev_state;
	ASSERT(node_state != SDEV_ZOMBIE);

	if (state == SDEV_READY) {
		switch (node_state) {
		case SDEV_INIT:
			error = sdev_nodeready(dv, vap, avp, args, cred);
			if (error) {
				sdcmn_err9(("sdev_mknode: node %s can NOT"
				    " be transitioned into READY state, "
				    "error %d\n", nm, error));
			}
			break;
		case SDEV_READY:
			/*
			 * Do some sanity checking to make sure
			 * the existing sdev_node is what has been
			 * asked for.
			 */
			error = sdev_node_check(dv, vap, args);
			break;
		default:
			break;
		}
	}

	if (!error) {
		*newdv = dv;
		ASSERT((*newdv)->sdev_state != SDEV_ZOMBIE);
	} else {
		sdev_cache_update(ddv, &dv, nm, SDEV_CACHE_DELETE);
		/*
		 * We created this node, it wasn't passed into us. Therefore it
		 * is up to us to delete it.
		 */
		if (*newdv == NULL)
			SDEV_SIMPLE_RELE(dv);
		*newdv = NULL;
	}

	return (error);
}

/*
 * convenient wrapper to change vp's ATIME, CTIME and MTIME
 */
void
sdev_update_timestamps(struct vnode *vp, cred_t *cred, uint_t mask)
{
	struct vattr attr;
	timestruc_t now;
	int err;

	ASSERT(vp);
	gethrestime(&now);
	if (mask & AT_CTIME)
		attr.va_ctime = now;
	if (mask & AT_MTIME)
		attr.va_mtime = now;
	if (mask & AT_ATIME)
		attr.va_atime = now;

	attr.va_mask = (mask & AT_TIMES);
	err = VOP_SETATTR(vp, &attr, 0, cred, NULL);
	if (err && (err != EROFS)) {
		sdcmn_err(("update timestamps error %d\n", err));
	}
}

/*
 * the backing store vnode is released here
 */
/*ARGSUSED1*/
void
sdev_nodedestroy(struct sdev_node *dv, uint_t flags)
{
	/* no references */
	ASSERT(dv->sdev_nlink == 0);

	if (dv->sdev_attrvp != NULLVP) {
		VN_RELE(dv->sdev_attrvp);
		/*
		 * reset the attrvp so that no more
		 * references can be made on this already
		 * vn_rele() vnode
		 */
		dv->sdev_attrvp = NULLVP;
	}

	if (dv->sdev_attr != NULL) {
		kmem_free(dv->sdev_attr, sizeof (struct vattr));
		dv->sdev_attr = NULL;
	}

	if (dv->sdev_name != NULL) {
		kmem_free(dv->sdev_name, dv->sdev_namelen + 1);
		dv->sdev_name = NULL;
	}

	if (dv->sdev_symlink != NULL) {
		kmem_free(dv->sdev_symlink, strlen(dv->sdev_symlink) + 1);
		dv->sdev_symlink = NULL;
	}

	if (dv->sdev_path) {
		kmem_free(dv->sdev_path, strlen(dv->sdev_path) + 1);
		dv->sdev_path = NULL;
	}

	if (!SDEV_IS_GLOBAL(dv))
		sdev_prof_free(dv);

	if (SDEVTOV(dv)->v_type == VDIR) {
		ASSERT(SDEV_FIRST_ENTRY(dv) == NULL);
		avl_destroy(&dv->sdev_entries);
	}

	mutex_destroy(&dv->sdev_lookup_lock);
	cv_destroy(&dv->sdev_lookup_cv);

	/* return node to initial state as per constructor */
	(void) memset((void *)&dv->sdev_instance_data, 0,
	    sizeof (dv->sdev_instance_data));
	vn_invalid(SDEVTOV(dv));
	kmem_cache_free(sdev_node_cache, dv);
}

/*
 * DIRECTORY CACHE lookup
 */
struct sdev_node *
sdev_findbyname(struct sdev_node *ddv, char *nm)
{
	struct sdev_node *dv;
	struct sdev_node dvtmp;
	avl_index_t	where;

	ASSERT(RW_LOCK_HELD(&ddv->sdev_contents));

	dvtmp.sdev_name = nm;
	dv = avl_find(&ddv->sdev_entries, &dvtmp, &where);
	if (dv) {
		ASSERT(dv->sdev_dotdot == ddv);
		ASSERT(strcmp(dv->sdev_name, nm) == 0);
		ASSERT(dv->sdev_state != SDEV_ZOMBIE);
		SDEV_HOLD(dv);
		return (dv);
	}
	return (NULL);
}

/*
 * Inserts a new sdev_node in a parent directory
 */
void
sdev_direnter(struct sdev_node *ddv, struct sdev_node *dv)
{
	avl_index_t where;

	ASSERT(RW_WRITE_HELD(&ddv->sdev_contents));
	ASSERT(SDEVTOV(ddv)->v_type == VDIR);
	ASSERT(ddv->sdev_nlink >= 2);
	ASSERT(dv->sdev_nlink == 0);
	ASSERT(dv->sdev_state != SDEV_ZOMBIE);

	dv->sdev_dotdot = ddv;
	VERIFY(avl_find(&ddv->sdev_entries, dv, &where) == NULL);
	avl_insert(&ddv->sdev_entries, dv, where);
	ddv->sdev_nlink++;
}

/*
 * The following check is needed because while sdev_nodes are linked
 * in SDEV_INIT state, they have their link counts incremented only
 * in SDEV_READY state.
 */
static void
decr_link(struct sdev_node *dv)
{
	VERIFY(RW_WRITE_HELD(&dv->sdev_contents));
	if (dv->sdev_state != SDEV_INIT) {
		VERIFY(dv->sdev_nlink >= 1);
		dv->sdev_nlink--;
	} else {
		VERIFY(dv->sdev_nlink == 0);
	}
}

/*
 * Delete an existing dv from directory cache
 *
 * In the case of a node is still held by non-zero reference count, the node is
 * put into ZOMBIE state. The node is always unlinked from its parent, but it is
 * not destroyed via sdev_inactive until its reference count reaches "0".
 */
static void
sdev_dirdelete(struct sdev_node *ddv, struct sdev_node *dv)
{
	struct vnode *vp;
	sdev_node_state_t os;

	ASSERT(RW_WRITE_HELD(&ddv->sdev_contents));

	vp = SDEVTOV(dv);
	mutex_enter(&vp->v_lock);
	rw_enter(&dv->sdev_contents, RW_WRITER);
	os = dv->sdev_state;
	ASSERT(os != SDEV_ZOMBIE);
	dv->sdev_state = SDEV_ZOMBIE;

	/*
	 * unlink ourselves from the parent directory now to take care of the ..
	 * link. However, if we're a directory, we don't remove our reference to
	 * ourself eg. '.' until we are torn down in the inactive callback.
	 */
	decr_link(ddv);
	avl_remove(&ddv->sdev_entries, dv);
	/*
	 * sdev_inactive expects nodes to have a link to themselves when we're
	 * tearing them down. If we're transitioning from the initial state to
	 * zombie and not via ready, then we're not going to have this link that
	 * comes from the node being ready. As a result, we need to increment
	 * our link count by one to account for this.
	 */
	if (os == SDEV_INIT && dv->sdev_nlink == 0)
		dv->sdev_nlink++;
	rw_exit(&dv->sdev_contents);
	mutex_exit(&vp->v_lock);
}

/*
 * check if the source is in the path of the target
 *
 * source and target are different
 */
/*ARGSUSED2*/
static int
sdev_checkpath(struct sdev_node *sdv, struct sdev_node *tdv, struct cred *cred)
{
	int error = 0;
	struct sdev_node *dotdot, *dir;

	dotdot = tdv->sdev_dotdot;
	ASSERT(dotdot);

	/* fs root */
	if (dotdot == tdv) {
		return (0);
	}

	for (;;) {
		/*
		 * avoid error cases like
		 *	mv a a/b
		 *	mv a a/b/c
		 *	etc.
		 */
		if (dotdot == sdv) {
			error = EINVAL;
			break;
		}

		dir = dotdot;
		dotdot = dir->sdev_dotdot;

		/* done checking because root is reached */
		if (dir == dotdot) {
			break;
		}
	}
	return (error);
}

int
sdev_rnmnode(struct sdev_node *oddv, struct sdev_node *odv,
    struct sdev_node *nddv, struct sdev_node **ndvp, char *nnm,
    struct cred *cred)
{
	int error = 0;
	struct vnode *ovp = SDEVTOV(odv);
	struct vnode *nvp;
	struct vattr vattr;
	int doingdir = (ovp->v_type == VDIR);
	char *link = NULL;
	int samedir = (oddv == nddv) ? 1 : 0;
	int bkstore = 0;
	struct sdev_node *idv = NULL;
	struct sdev_node *ndv = NULL;
	timestruc_t now;

	vattr.va_mask = AT_TYPE|AT_MODE|AT_UID|AT_GID;
	error = VOP_GETATTR(ovp, &vattr, 0, cred, NULL);
	if (error)
		return (error);

	if (!samedir)
		rw_enter(&oddv->sdev_contents, RW_WRITER);
	rw_enter(&nddv->sdev_contents, RW_WRITER);

	/*
	 * the source may have been deleted by another thread before
	 * we gets here.
	 */
	if (odv->sdev_state != SDEV_READY) {
		error = ENOENT;
		goto err_out;
	}

	if (doingdir && (odv == nddv)) {
		error = EINVAL;
		goto err_out;
	}

	/*
	 * If renaming a directory, and the parents are different (".." must be
	 * changed) then the source dir must not be in the dir hierarchy above
	 * the target since it would orphan everything below the source dir.
	 */
	if (doingdir && (oddv != nddv)) {
		error = sdev_checkpath(odv, nddv, cred);
		if (error)
			goto err_out;
	}

	/* fix the source for a symlink */
	if (vattr.va_type == VLNK) {
		if (odv->sdev_symlink == NULL) {
			error = sdev_follow_link(odv);
			if (error) {
				/*
				 * The underlying symlink doesn't exist. This
				 * node probably shouldn't even exist. While
				 * it's a bit jarring to consumers, we're going
				 * to remove the node from /dev.
				 */
				if (SDEV_IS_PERSIST((*ndvp)))
					bkstore = 1;
				sdev_dirdelete(oddv, odv);
				if (bkstore) {
					ASSERT(nddv->sdev_attrvp);
					error = VOP_REMOVE(nddv->sdev_attrvp,
					    nnm, cred, NULL, 0);
					if (error)
						goto err_out;
				}
				error = ENOENT;
				goto err_out;
			}
		}
		ASSERT(odv->sdev_symlink);
		link = i_ddi_strdup(odv->sdev_symlink, KM_SLEEP);
	}

	/* destination existing */
	if (*ndvp) {
		nvp = SDEVTOV(*ndvp);
		ASSERT(nvp);

		/* handling renaming to itself */
		if (odv == *ndvp) {
			error = 0;
			goto err_out;
		}

		if (nvp->v_type == VDIR) {
			if (!doingdir) {
				error = EISDIR;
				goto err_out;
			}

			if (vn_vfswlock(nvp)) {
				error = EBUSY;
				goto err_out;
			}

			if (vn_mountedvfs(nvp) != NULL) {
				vn_vfsunlock(nvp);
				error = EBUSY;
				goto err_out;
			}

			/* in case dir1 exists in dir2 and "mv dir1 dir2" */
			if ((*ndvp)->sdev_nlink > 2) {
				vn_vfsunlock(nvp);
				error = EEXIST;
				goto err_out;
			}
			vn_vfsunlock(nvp);

			/*
			 * We did not place the hold on *ndvp, so even though
			 * we're deleting the node, we should not get rid of our
			 * reference.
			 */
			sdev_dirdelete(nddv, *ndvp);
			*ndvp = NULL;
			ASSERT(nddv->sdev_attrvp);
			error = VOP_RMDIR(nddv->sdev_attrvp, nnm,
			    nddv->sdev_attrvp, cred, NULL, 0);
			if (error)
				goto err_out;
		} else {
			if (doingdir) {
				error = ENOTDIR;
				goto err_out;
			}

			if (SDEV_IS_PERSIST((*ndvp))) {
				bkstore = 1;
			}

			/*
			 * Get rid of the node from the directory cache note.
			 * Don't forget that it's not up to us to remove the vn
			 * ref on the sdev node, as we did not place it.
			 */
			sdev_dirdelete(nddv, *ndvp);
			*ndvp = NULL;
			if (bkstore) {
				ASSERT(nddv->sdev_attrvp);
				error = VOP_REMOVE(nddv->sdev_attrvp,
				    nnm, cred, NULL, 0);
				if (error)
					goto err_out;
			}
		}
	}

	/*
	 * make a fresh node from the source attrs
	 */
	ASSERT(RW_WRITE_HELD(&nddv->sdev_contents));
	error = sdev_mknode(nddv, nnm, ndvp, &vattr,
	    NULL, (void *)link, cred, SDEV_READY);

	if (link != NULL) {
		kmem_free(link, strlen(link) + 1);
		link = NULL;
	}

	if (error)
		goto err_out;
	ASSERT(*ndvp);
	ASSERT((*ndvp)->sdev_state == SDEV_READY);

	/* move dir contents */
	if (doingdir) {
		for (idv = SDEV_FIRST_ENTRY(odv); idv;
		    idv = SDEV_NEXT_ENTRY(odv, idv)) {
			SDEV_HOLD(idv);
			error = sdev_rnmnode(odv, idv,
			    (struct sdev_node *)(*ndvp), &ndv,
			    idv->sdev_name, cred);
			SDEV_RELE(idv);
			if (error)
				goto err_out;
			ndv = NULL;
		}
	}

	if ((*ndvp)->sdev_attrvp) {
		sdev_update_timestamps((*ndvp)->sdev_attrvp, kcred,
		    AT_CTIME|AT_ATIME);
	} else {
		ASSERT((*ndvp)->sdev_attr);
		gethrestime(&now);
		(*ndvp)->sdev_attr->va_ctime = now;
		(*ndvp)->sdev_attr->va_atime = now;
	}

	if (nddv->sdev_attrvp) {
		sdev_update_timestamps(nddv->sdev_attrvp, kcred,
		    AT_MTIME|AT_ATIME);
	} else {
		ASSERT(nddv->sdev_attr);
		gethrestime(&now);
		nddv->sdev_attr->va_mtime = now;
		nddv->sdev_attr->va_atime = now;
	}
	rw_exit(&nddv->sdev_contents);
	if (!samedir)
		rw_exit(&oddv->sdev_contents);

	SDEV_RELE(*ndvp);
	return (error);

err_out:
	if (link != NULL) {
		kmem_free(link, strlen(link) + 1);
		link = NULL;
	}

	rw_exit(&nddv->sdev_contents);
	if (!samedir)
		rw_exit(&oddv->sdev_contents);
	return (error);
}

/*
 * Merge sdev_node specific information into an attribute structure.
 *
 * note: sdev_node is not locked here
 */
void
sdev_vattr_merge(struct sdev_node *dv, struct vattr *vap)
{
	struct vnode *vp = SDEVTOV(dv);

	vap->va_nlink = dv->sdev_nlink;
	vap->va_nodeid = dv->sdev_ino;
	vap->va_fsid = SDEVTOV(dv->sdev_dotdot)->v_rdev;
	vap->va_type = vp->v_type;

	if (vp->v_type == VDIR) {
		vap->va_rdev = 0;
		vap->va_fsid = vp->v_rdev;
	} else if (vp->v_type == VLNK) {
		vap->va_rdev = 0;
		vap->va_mode  &= ~S_IFMT;
		vap->va_mode |= S_IFLNK;
	} else if ((vp->v_type == VCHR) || (vp->v_type == VBLK)) {
		vap->va_rdev = vp->v_rdev;
		vap->va_mode &= ~S_IFMT;
		if (vap->va_type == VCHR)
			vap->va_mode |= S_IFCHR;
		else
			vap->va_mode |= S_IFBLK;
	} else {
		vap->va_rdev = 0;
	}
}

struct vattr *
sdev_getdefault_attr(enum vtype type)
{
	if (type == VDIR)
		return (&sdev_vattr_dir);
	else if (type == VCHR)
		return (&sdev_vattr_chr);
	else if (type == VBLK)
		return (&sdev_vattr_blk);
	else if (type == VLNK)
		return (&sdev_vattr_lnk);
	else
		return (NULL);
}
int
sdev_to_vp(struct sdev_node *dv, struct vnode **vpp)
{
	int rv = 0;
	struct vnode *vp = SDEVTOV(dv);

	switch (vp->v_type) {
	case VCHR:
	case VBLK:
		/*
		 * If vnode is a device, return special vnode instead
		 * (though it knows all about -us- via sp->s_realvp)
		 */
		*vpp = specvp(vp, vp->v_rdev, vp->v_type, kcred);
		VN_RELE(vp);
		if (*vpp == NULLVP)
			rv = ENOSYS;
		break;
	default:	/* most types are returned as is */
		*vpp = vp;
		break;
	}
	return (rv);
}

/*
 * junction between devname and root file system, e.g. ufs
 */
int
devname_backstore_lookup(struct sdev_node *ddv, char *nm, struct vnode **rvp)
{
	struct vnode *rdvp = ddv->sdev_attrvp;
	int rval = 0;

	ASSERT(rdvp);

	rval = VOP_LOOKUP(rdvp, nm, rvp, NULL, 0, NULL, kcred, NULL, NULL,
	    NULL);
	return (rval);
}

static int
sdev_filldir_from_store(struct sdev_node *ddv, int dlen, struct cred *cred)
{
	struct sdev_node *dv = NULL;
	char	*nm;
	struct vnode *dirvp;
	int	error;
	vnode_t	*vp;
	int eof;
	struct iovec iov;
	struct uio uio;
	struct dirent64 *dp;
	dirent64_t *dbuf;
	size_t dbuflen;
	struct vattr vattr;
	char *link = NULL;

	if (ddv->sdev_attrvp == NULL)
		return (0);
	if (!(ddv->sdev_flags & SDEV_BUILD))
		return (0);

	dirvp = ddv->sdev_attrvp;
	VN_HOLD(dirvp);
	dbuf = kmem_zalloc(dlen, KM_SLEEP);

	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_extflg = UIO_COPY_CACHED;
	uio.uio_loffset = 0;
	uio.uio_llimit = MAXOFFSET_T;

	eof = 0;
	error = 0;
	while (!error && !eof) {
		uio.uio_resid = dlen;
		iov.iov_base = (char *)dbuf;
		iov.iov_len = dlen;
		(void) VOP_RWLOCK(dirvp, V_WRITELOCK_FALSE, NULL);
		error = VOP_READDIR(dirvp, &uio, kcred, &eof, NULL, 0);
		VOP_RWUNLOCK(dirvp, V_WRITELOCK_FALSE, NULL);

		dbuflen = dlen - uio.uio_resid;
		if (error || dbuflen == 0)
			break;

		if (!(ddv->sdev_flags & SDEV_BUILD))
			break;

		for (dp = dbuf; ((intptr_t)dp <
		    (intptr_t)dbuf + dbuflen);
		    dp = (dirent64_t *)((intptr_t)dp + dp->d_reclen)) {
			nm = dp->d_name;

			if (strcmp(nm, ".") == 0 ||
			    strcmp(nm, "..") == 0)
				continue;

			vp = NULLVP;
			dv = sdev_cache_lookup(ddv, nm);
			if (dv) {
				VERIFY(dv->sdev_state != SDEV_ZOMBIE);
				SDEV_SIMPLE_RELE(dv);
				continue;
			}

			/* refill the cache if not already */
			error = devname_backstore_lookup(ddv, nm, &vp);
			if (error)
				continue;

			vattr.va_mask = AT_TYPE|AT_MODE|AT_UID|AT_GID;
			error = VOP_GETATTR(vp, &vattr, 0, cred, NULL);
			if (error)
				continue;

			if (vattr.va_type == VLNK) {
				error = sdev_getlink(vp, &link);
				if (error) {
					continue;
				}
				ASSERT(link != NULL);
			}

			if (!rw_tryupgrade(&ddv->sdev_contents)) {
				rw_exit(&ddv->sdev_contents);
				rw_enter(&ddv->sdev_contents, RW_WRITER);
			}
			error = sdev_mknode(ddv, nm, &dv, &vattr, vp, link,
			    cred, SDEV_READY);
			rw_downgrade(&ddv->sdev_contents);

			if (link != NULL) {
				kmem_free(link, strlen(link) + 1);
				link = NULL;
			}

			if (!error) {
				ASSERT(dv);
				ASSERT(dv->sdev_state != SDEV_ZOMBIE);
				SDEV_SIMPLE_RELE(dv);
			}
			vp = NULL;
			dv = NULL;
		}
	}

done:
	VN_RELE(dirvp);
	kmem_free(dbuf, dlen);

	return (error);
}

void
sdev_filldir_dynamic(struct sdev_node *ddv)
{
	int error;
	int i;
	struct vattr vattr;
	struct vattr *vap = &vattr;
	char *nm = NULL;
	struct sdev_node *dv = NULL;

	ASSERT(RW_WRITE_HELD(&ddv->sdev_contents));
	ASSERT((ddv->sdev_flags & SDEV_BUILD));

	*vap = *sdev_getdefault_attr(VDIR);	/* note structure copy here */
	gethrestime(&vap->va_atime);
	vap->va_mtime = vap->va_atime;
	vap->va_ctime = vap->va_atime;
	for (i = 0; vtab[i].vt_name != NULL; i++) {
		/*
		 * This early, we may be in a read-only /dev environment: leave
		 * the creation of any nodes we'd attempt to persist to
		 * devfsadm. Because /dev itself is normally persistent, any
		 * node which is not marked dynamic will end up being marked
		 * persistent. However, some nodes are both dynamic and
		 * persistent, mostly lofi and rlofi, so we need to be careful
		 * in our check.
		 */
		if ((vtab[i].vt_flags & SDEV_PERSIST) ||
		    !(vtab[i].vt_flags & SDEV_DYNAMIC))
			continue;
		nm = vtab[i].vt_name;
		ASSERT(RW_WRITE_HELD(&ddv->sdev_contents));
		dv = NULL;
		error = sdev_mknode(ddv, nm, &dv, vap, NULL,
		    NULL, kcred, SDEV_READY);
		if (error) {
			cmn_err(CE_WARN, "%s/%s: error %d\n",
			    ddv->sdev_name, nm, error);
		} else {
			ASSERT(dv);
			ASSERT(dv->sdev_state != SDEV_ZOMBIE);
			SDEV_SIMPLE_RELE(dv);
		}
	}
}

/*
 * Creating a backing store entry based on sdev_attr.
 * This is called either as part of node creation in a persistent directory
 * or from setattr/setsecattr to persist access attributes across reboot.
 */
int
sdev_shadow_node(struct sdev_node *dv, struct cred *cred)
{
	int error = 0;
	struct vnode *dvp = SDEVTOV(dv->sdev_dotdot);
	struct vnode *rdvp = VTOSDEV(dvp)->sdev_attrvp;
	struct vattr *vap = dv->sdev_attr;
	char *nm = dv->sdev_name;
	struct vnode *tmpvp, **rvp = &tmpvp, *rrvp = NULL;

	ASSERT(dv && dv->sdev_name && rdvp);
	ASSERT(RW_WRITE_HELD(&dv->sdev_contents) && dv->sdev_attrvp == NULL);

lookup:
	/* try to find it in the backing store */
	error = VOP_LOOKUP(rdvp, nm, rvp, NULL, 0, NULL, cred, NULL, NULL,
	    NULL);
	if (error == 0) {
		if (VOP_REALVP(*rvp, &rrvp, NULL) == 0) {
			VN_HOLD(rrvp);
			VN_RELE(*rvp);
			*rvp = rrvp;
		}

		kmem_free(dv->sdev_attr, sizeof (vattr_t));
		dv->sdev_attr = NULL;
		dv->sdev_attrvp = *rvp;
		return (0);
	}

	/* let's try to persist the node */
	gethrestime(&vap->va_atime);
	vap->va_mtime = vap->va_atime;
	vap->va_ctime = vap->va_atime;
	vap->va_mask |= AT_TYPE|AT_MODE;
	switch (vap->va_type) {
	case VDIR:
		error = VOP_MKDIR(rdvp, nm, vap, rvp, cred, NULL, 0, NULL);
		sdcmn_err9(("sdev_shadow_node: mkdir vp %p error %d\n",
		    (void *)(*rvp), error));
		if (!error)
			VN_RELE(*rvp);
		break;
	case VCHR:
	case VBLK:
	case VREG:
	case VDOOR:
		error = VOP_CREATE(rdvp, nm, vap, NONEXCL, VREAD|VWRITE,
		    rvp, cred, 0, NULL, NULL);
		sdcmn_err9(("sdev_shadow_node: create vp %p, error %d\n",
		    (void *)(*rvp), error));
		if (!error)
			VN_RELE(*rvp);
		break;
	case VLNK:
		ASSERT(dv->sdev_symlink);
		error = VOP_SYMLINK(rdvp, nm, vap, dv->sdev_symlink, cred,
		    NULL, 0);
		sdcmn_err9(("sdev_shadow_node: create symlink error %d\n",
		    error));
		break;
	default:
		cmn_err(CE_PANIC, "dev: %s: sdev_shadow_node "
		    "create\n", nm);
		/*NOTREACHED*/
	}

	/* go back to lookup to factor out spec node and set attrvp */
	if (error == 0)
		goto lookup;

	sdcmn_err(("cannot persist %s - error %d\n", dv->sdev_path, error));
	return (error);
}

static void
sdev_cache_add(struct sdev_node *ddv, struct sdev_node **dv, char *nm)
{
	struct sdev_node *dup = NULL;

	ASSERT(RW_WRITE_HELD(&ddv->sdev_contents));
	if ((dup = sdev_findbyname(ddv, nm)) == NULL) {
		sdev_direnter(ddv, *dv);
	} else {
		VERIFY(dup->sdev_state != SDEV_ZOMBIE);
		SDEV_SIMPLE_RELE(*dv);
		sdev_nodedestroy(*dv, 0);
		*dv = dup;
	}
}

static void
sdev_cache_delete(struct sdev_node *ddv, struct sdev_node **dv)
{
	ASSERT(RW_WRITE_HELD(&ddv->sdev_contents));
	sdev_dirdelete(ddv, *dv);
}

/*
 * update the in-core directory cache
 */
void
sdev_cache_update(struct sdev_node *ddv, struct sdev_node **dv, char *nm,
    sdev_cache_ops_t ops)
{
	ASSERT((SDEV_HELD(*dv)));

	ASSERT(RW_WRITE_HELD(&ddv->sdev_contents));
	switch (ops) {
	case SDEV_CACHE_ADD:
		sdev_cache_add(ddv, dv, nm);
		break;
	case SDEV_CACHE_DELETE:
		sdev_cache_delete(ddv, dv);
		break;
	default:
		break;
	}
}

/*
 * retrieve the named entry from the directory cache
 */
struct sdev_node *
sdev_cache_lookup(struct sdev_node *ddv, char *nm)
{
	struct sdev_node *dv = NULL;

	ASSERT(RW_LOCK_HELD(&ddv->sdev_contents));
	dv = sdev_findbyname(ddv, nm);

	return (dv);
}

/*
 * Implicit reconfig for nodes constructed by a link generator
 * Start devfsadm if needed, or if devfsadm is in progress,
 * prepare to block on devfsadm either completing or
 * constructing the desired node.  As devfsadmd is global
 * in scope, constructing all necessary nodes, we only
 * need to initiate it once.
 */
static int
sdev_call_devfsadmd(struct sdev_node *ddv, struct sdev_node *dv, char *nm)
{
	int error = 0;

	if (DEVNAME_DEVFSADM_IS_RUNNING(devfsadm_state)) {
		sdcmn_err6(("lookup: waiting for %s/%s, 0x%x\n",
		    ddv->sdev_name, nm, devfsadm_state));
		mutex_enter(&dv->sdev_lookup_lock);
		SDEV_BLOCK_OTHERS(dv, (SDEV_LOOKUP | SDEV_LGWAITING));
		mutex_exit(&dv->sdev_lookup_lock);
		error = 0;
	} else if (!DEVNAME_DEVFSADM_HAS_RUN(devfsadm_state)) {
		sdcmn_err6(("lookup %s/%s starting devfsadm, 0x%x\n",
		    ddv->sdev_name, nm, devfsadm_state));

		sdev_devfsadmd_thread(ddv, dv, kcred);
		mutex_enter(&dv->sdev_lookup_lock);
		SDEV_BLOCK_OTHERS(dv,
		    (SDEV_LOOKUP | SDEV_LGWAITING));
		mutex_exit(&dv->sdev_lookup_lock);
		error = 0;
	} else {
		error = -1;
	}

	return (error);
}

/*
 *  Support for specialized device naming construction mechanisms
 */
static int
sdev_call_dircallback(struct sdev_node *ddv, struct sdev_node **dvp, char *nm,
    int (*callback)(struct sdev_node *, char *, void **, struct cred *,
    void *, char *), int flags, struct cred *cred)
{
	int rv = 0;
	char *physpath = NULL;
	struct vattr vattr;
	struct vattr *vap = &vattr;
	struct sdev_node *dv = NULL;

	ASSERT(RW_WRITE_HELD(&ddv->sdev_contents));
	if (flags & SDEV_VLINK) {
		physpath = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
		rv = callback(ddv, nm, (void *)&physpath, kcred, NULL,
		    NULL);
		if (rv) {
			kmem_free(physpath, MAXPATHLEN);
			return (-1);
		}

		*vap = *sdev_getdefault_attr(VLNK);	/* structure copy */
		vap->va_size = strlen(physpath);
		gethrestime(&vap->va_atime);
		vap->va_mtime = vap->va_atime;
		vap->va_ctime = vap->va_atime;

		rv = sdev_mknode(ddv, nm, &dv, vap, NULL,
		    (void *)physpath, cred, SDEV_READY);
		kmem_free(physpath, MAXPATHLEN);
		if (rv)
			return (rv);
	} else if (flags & SDEV_VATTR) {
		/*
		 * /dev/pts
		 *
		 * callback is responsible to set the basic attributes,
		 * e.g. va_type/va_uid/va_gid/
		 *    dev_t if VCHR or VBLK/
		 */
		ASSERT(callback);
		rv = callback(ddv, nm, (void *)&vattr, kcred, NULL, NULL);
		if (rv) {
			sdcmn_err3(("devname_lookup_func: SDEV_NONE "
			    "callback failed \n"));
			return (-1);
		}

		rv = sdev_mknode(ddv, nm, &dv, &vattr, NULL, NULL,
		    cred, SDEV_READY);

		if (rv)
			return (rv);

	} else {
		impossible(("lookup: %s/%s by %s not supported (%d)\n",
		    SDEVTOV(ddv)->v_path, nm, curproc->p_user.u_comm,
		    __LINE__));
		rv = -1;
	}

	*dvp = dv;
	return (rv);
}

static int
is_devfsadm_thread(char *exec_name)
{
	/*
	 * note: because devfsadmd -> /usr/sbin/devfsadm
	 * it is safe to use "devfsadm" to capture the lookups
	 * from devfsadm and its daemon version.
	 */
	if (strcmp(exec_name, "devfsadm") == 0)
		return (1);
	return (0);
}

/*
 * Lookup Order:
 *	sdev_node cache;
 *	backing store (SDEV_PERSIST);
 *	DBNR: a. dir_ops implemented in the loadable modules;
 *	      b. vnode ops in vtab.
 */
int
devname_lookup_func(struct sdev_node *ddv, char *nm, struct vnode **vpp,
    struct cred *cred, int (*callback)(struct sdev_node *, char *, void **,
    struct cred *, void *, char *), int flags)
{
	int rv = 0, nmlen;
	struct vnode *rvp = NULL;
	struct sdev_node *dv = NULL;
	int	retried = 0;
	int	error = 0;
	struct vattr vattr;
	char *lookup_thread = curproc->p_user.u_comm;
	int failed_flags = 0;
	int (*vtor)(struct sdev_node *) = NULL;
	int state;
	int parent_state;
	char *link = NULL;

	if (SDEVTOV(ddv)->v_type != VDIR)
		return (ENOTDIR);

	/*
	 * Empty name or ., return node itself.
	 */
	nmlen = strlen(nm);
	if ((nmlen == 0) || ((nmlen == 1) && (nm[0] == '.'))) {
		*vpp = SDEVTOV(ddv);
		VN_HOLD(*vpp);
		return (0);
	}

	/*
	 * .., return the parent directory
	 */
	if ((nmlen == 2) && (strcmp(nm, "..") == 0)) {
		*vpp = SDEVTOV(ddv->sdev_dotdot);
		VN_HOLD(*vpp);
		return (0);
	}

	rw_enter(&ddv->sdev_contents, RW_READER);
	if (ddv->sdev_flags & SDEV_VTOR) {
		vtor = (int (*)(struct sdev_node *))sdev_get_vtor(ddv);
		ASSERT(vtor);
	}

tryagain:
	/*
	 * (a) directory cache lookup:
	 */
	ASSERT(RW_READ_HELD(&ddv->sdev_contents));
	parent_state = ddv->sdev_state;
	dv = sdev_cache_lookup(ddv, nm);
	if (dv) {
		state = dv->sdev_state;
		switch (state) {
		case SDEV_INIT:
			if (is_devfsadm_thread(lookup_thread))
				break;

			/* ZOMBIED parent won't allow node creation */
			if (parent_state == SDEV_ZOMBIE) {
				SD_TRACE_FAILED_LOOKUP(ddv, nm,
				    retried);
				goto nolock_notfound;
			}

			mutex_enter(&dv->sdev_lookup_lock);
			/* compensate the threads started after devfsadm */
			if (DEVNAME_DEVFSADM_IS_RUNNING(devfsadm_state) &&
			    !(SDEV_IS_LOOKUP(dv)))
				SDEV_BLOCK_OTHERS(dv,
				    (SDEV_LOOKUP | SDEV_LGWAITING));

			if (SDEV_IS_LOOKUP(dv)) {
				failed_flags |= SLF_REBUILT;
				rw_exit(&ddv->sdev_contents);
				error = sdev_wait4lookup(dv, SDEV_LOOKUP);
				mutex_exit(&dv->sdev_lookup_lock);
				rw_enter(&ddv->sdev_contents, RW_READER);

				if (error != 0) {
					SD_TRACE_FAILED_LOOKUP(ddv, nm,
					    retried);
					goto nolock_notfound;
				}

				state = dv->sdev_state;
				if (state == SDEV_INIT) {
					SD_TRACE_FAILED_LOOKUP(ddv, nm,
					    retried);
					goto nolock_notfound;
				} else if (state == SDEV_READY) {
					goto found;
				} else if (state == SDEV_ZOMBIE) {
					rw_exit(&ddv->sdev_contents);
					SD_TRACE_FAILED_LOOKUP(ddv, nm,
					    retried);
					SDEV_RELE(dv);
					goto lookup_failed;
				}
			} else {
				mutex_exit(&dv->sdev_lookup_lock);
			}
			break;
		case SDEV_READY:
			goto found;
		case SDEV_ZOMBIE:
			rw_exit(&ddv->sdev_contents);
			SD_TRACE_FAILED_LOOKUP(ddv, nm, retried);
			SDEV_RELE(dv);
			goto lookup_failed;
		default:
			rw_exit(&ddv->sdev_contents);
			SD_TRACE_FAILED_LOOKUP(ddv, nm, retried);
			sdev_lookup_failed(ddv, nm, failed_flags);
			*vpp = NULLVP;
			return (ENOENT);
		}
	}
	ASSERT(RW_READ_HELD(&ddv->sdev_contents));

	/*
	 * ZOMBIED parent does not allow new node creation.
	 * bail out early
	 */
	if (parent_state == SDEV_ZOMBIE) {
		rw_exit(&ddv->sdev_contents);
		*vpp = NULLVP;
		SD_TRACE_FAILED_LOOKUP(ddv, nm, retried);
		return (ENOENT);
	}

	/*
	 * (b0): backing store lookup
	 *	SDEV_PERSIST is default except:
	 *		1) pts nodes
	 *		2) non-chmod'ed local nodes
	 *		3) zvol nodes
	 */
	if (SDEV_IS_PERSIST(ddv)) {
		error = devname_backstore_lookup(ddv, nm, &rvp);

		if (!error) {

			vattr.va_mask = AT_TYPE|AT_MODE|AT_UID|AT_GID;
			error = VOP_GETATTR(rvp, &vattr, 0, cred, NULL);
			if (error) {
				rw_exit(&ddv->sdev_contents);
				if (dv)
					SDEV_RELE(dv);
				SD_TRACE_FAILED_LOOKUP(ddv, nm, retried);
				sdev_lookup_failed(ddv, nm, failed_flags);
				*vpp = NULLVP;
				return (ENOENT);
			}

			if (vattr.va_type == VLNK) {
				error = sdev_getlink(rvp, &link);
				if (error) {
					rw_exit(&ddv->sdev_contents);
					if (dv)
						SDEV_RELE(dv);
					SD_TRACE_FAILED_LOOKUP(ddv, nm,
					    retried);
					sdev_lookup_failed(ddv, nm,
					    failed_flags);
					*vpp = NULLVP;
					return (ENOENT);
				}
				ASSERT(link != NULL);
			}

			if (!rw_tryupgrade(&ddv->sdev_contents)) {
				rw_exit(&ddv->sdev_contents);
				rw_enter(&ddv->sdev_contents, RW_WRITER);
			}
			error = sdev_mknode(ddv, nm, &dv, &vattr,
			    rvp, link, cred, SDEV_READY);
			rw_downgrade(&ddv->sdev_contents);

			if (link != NULL) {
				kmem_free(link, strlen(link) + 1);
				link = NULL;
			}

			if (error) {
				SD_TRACE_FAILED_LOOKUP(ddv, nm, retried);
				rw_exit(&ddv->sdev_contents);
				if (dv)
					SDEV_RELE(dv);
				goto lookup_failed;
			} else {
				goto found;
			}
		} else if (retried) {
			rw_exit(&ddv->sdev_contents);
			sdcmn_err3(("retry of lookup of %s/%s: failed\n",
			    ddv->sdev_name, nm));
			if (dv)
				SDEV_RELE(dv);
			SD_TRACE_FAILED_LOOKUP(ddv, nm, retried);
			sdev_lookup_failed(ddv, nm, failed_flags);
			*vpp = NULLVP;
			return (ENOENT);
		}
	}

lookup_create_node:
	/* first thread that is doing the lookup on this node */
	if (callback) {
		ASSERT(dv == NULL);
		if (!rw_tryupgrade(&ddv->sdev_contents)) {
			rw_exit(&ddv->sdev_contents);
			rw_enter(&ddv->sdev_contents, RW_WRITER);
		}
		error = sdev_call_dircallback(ddv, &dv, nm, callback,
		    flags, cred);
		rw_downgrade(&ddv->sdev_contents);
		if (error == 0) {
			goto found;
		} else {
			SD_TRACE_FAILED_LOOKUP(ddv, nm, retried);
			rw_exit(&ddv->sdev_contents);
			goto lookup_failed;
		}
	}
	if (!dv) {
		if (!rw_tryupgrade(&ddv->sdev_contents)) {
			rw_exit(&ddv->sdev_contents);
			rw_enter(&ddv->sdev_contents, RW_WRITER);
		}
		error = sdev_mknode(ddv, nm, &dv, NULL, NULL, NULL,
		    cred, SDEV_INIT);
		if (!dv) {
			rw_exit(&ddv->sdev_contents);
			SD_TRACE_FAILED_LOOKUP(ddv, nm, retried);
			sdev_lookup_failed(ddv, nm, failed_flags);
			*vpp = NULLVP;
			return (ENOENT);
		}
		rw_downgrade(&ddv->sdev_contents);
	}

	/*
	 * (b1) invoking devfsadm once per life time for devfsadm nodes
	 */
	ASSERT(SDEV_HELD(dv));

	if (SDEV_IS_NO_NCACHE(dv))
		failed_flags |= SLF_NO_NCACHE;
	if (sdev_reconfig_boot || !i_ddi_io_initialized() ||
	    SDEV_IS_DYNAMIC(ddv) || SDEV_IS_NO_NCACHE(dv) ||
	    ((moddebug & MODDEBUG_FINI_EBUSY) != 0)) {
		ASSERT(SDEV_HELD(dv));
		SD_TRACE_FAILED_LOOKUP(ddv, nm, retried);
		goto nolock_notfound;
	}

	/*
	 * filter out known non-existent devices recorded
	 * during initial reconfiguration boot for which
	 * reconfig should not be done and lookup may
	 * be short-circuited now.
	 */
	if (sdev_lookup_filter(ddv, nm)) {
		SD_TRACE_FAILED_LOOKUP(ddv, nm, retried);
		goto nolock_notfound;
	}

	/* bypassing devfsadm internal nodes */
	if (is_devfsadm_thread(lookup_thread)) {
		SD_TRACE_FAILED_LOOKUP(ddv, nm, retried);
		goto nolock_notfound;
	}

	if (sdev_reconfig_disable) {
		SD_TRACE_FAILED_LOOKUP(ddv, nm, retried);
		goto nolock_notfound;
	}

	error = sdev_call_devfsadmd(ddv, dv, nm);
	if (error == 0) {
		sdcmn_err8(("lookup of %s/%s by %s: reconfig\n",
		    ddv->sdev_name, nm, curproc->p_user.u_comm));
		if (sdev_reconfig_verbose) {
			cmn_err(CE_CONT,
			    "?lookup of %s/%s by %s: reconfig\n",
			    ddv->sdev_name, nm, curproc->p_user.u_comm);
		}
		retried = 1;
		failed_flags |= SLF_REBUILT;
		ASSERT(dv->sdev_state != SDEV_ZOMBIE);
		SDEV_SIMPLE_RELE(dv);
		goto tryagain;
	} else {
		SD_TRACE_FAILED_LOOKUP(ddv, nm, retried);
		goto nolock_notfound;
	}

found:
	ASSERT(dv->sdev_state == SDEV_READY);
	if (vtor) {
		/*
		 * Check validity of returned node
		 */
		switch (vtor(dv)) {
		case SDEV_VTOR_VALID:
			break;
		case SDEV_VTOR_STALE:
			/*
			 * The name exists, but the cache entry is
			 * stale and needs to be re-created.
			 */
			ASSERT(RW_READ_HELD(&ddv->sdev_contents));
			if (rw_tryupgrade(&ddv->sdev_contents) == 0) {
				rw_exit(&ddv->sdev_contents);
				rw_enter(&ddv->sdev_contents, RW_WRITER);
			}
			sdev_cache_update(ddv, &dv, nm, SDEV_CACHE_DELETE);
			rw_downgrade(&ddv->sdev_contents);
			SDEV_RELE(dv);
			dv = NULL;
			goto lookup_create_node;
			/* FALLTHRU */
		case SDEV_VTOR_INVALID:
			SD_TRACE_FAILED_LOOKUP(ddv, nm, retried);
			sdcmn_err7(("lookup: destroy invalid "
			    "node: %s(%p)\n", dv->sdev_name, (void *)dv));
			goto nolock_notfound;
		case SDEV_VTOR_SKIP:
			sdcmn_err7(("lookup: node not applicable - "
			    "skipping: %s(%p)\n", dv->sdev_name, (void *)dv));
			rw_exit(&ddv->sdev_contents);
			SD_TRACE_FAILED_LOOKUP(ddv, nm, retried);
			SDEV_RELE(dv);
			goto lookup_failed;
		default:
			cmn_err(CE_PANIC,
			    "dev fs: validator failed: %s(%p)\n",
			    dv->sdev_name, (void *)dv);
			break;
		}
	}

	rw_exit(&ddv->sdev_contents);
	rv = sdev_to_vp(dv, vpp);
	sdcmn_err3(("devname_lookup_func: returning vp %p v_count %d state %d "
	    "for nm %s, error %d\n", (void *)*vpp, (*vpp)->v_count,
	    dv->sdev_state, nm, rv));
	return (rv);

nolock_notfound:
	/*
	 * Destroy the node that is created for synchronization purposes.
	 */
	sdcmn_err3(("devname_lookup_func: %s with state %d\n",
	    nm, dv->sdev_state));
	ASSERT(RW_READ_HELD(&ddv->sdev_contents));
	if (dv->sdev_state == SDEV_INIT) {
		if (!rw_tryupgrade(&ddv->sdev_contents)) {
			rw_exit(&ddv->sdev_contents);
			rw_enter(&ddv->sdev_contents, RW_WRITER);
		}

		/*
		 * Node state may have changed during the lock
		 * changes. Re-check.
		 */
		if (dv->sdev_state == SDEV_INIT) {
			sdev_dirdelete(ddv, dv);
			rw_exit(&ddv->sdev_contents);
			sdev_lookup_failed(ddv, nm, failed_flags);
			SDEV_RELE(dv);
			*vpp = NULL;
			return (ENOENT);
		}
	}

	rw_exit(&ddv->sdev_contents);
	SDEV_RELE(dv);

lookup_failed:
	sdev_lookup_failed(ddv, nm, failed_flags);
	*vpp = NULL;
	return (ENOENT);
}

/*
 * Given a directory node, mark all nodes beneath as
 * STALE, i.e. nodes that don't exist as far as new
 * consumers are concerned.  Remove them from the
 * list of directory entries so that no lookup or
 * directory traversal will find them.  The node
 * not deallocated so existing holds are not affected.
 */
void
sdev_stale(struct sdev_node *ddv)
{
	struct sdev_node *dv;
	struct vnode *vp;

	ASSERT(SDEVTOV(ddv)->v_type == VDIR);

	rw_enter(&ddv->sdev_contents, RW_WRITER);
	while ((dv = SDEV_FIRST_ENTRY(ddv)) != NULL) {
		vp = SDEVTOV(dv);
		SDEV_HOLD(dv);
		if (vp->v_type == VDIR)
			sdev_stale(dv);

		sdev_dirdelete(ddv, dv);
		SDEV_RELE(dv);
	}
	ddv->sdev_flags |= SDEV_BUILD;
	rw_exit(&ddv->sdev_contents);
}

/*
 * Given a directory node, clean out all the nodes beneath.
 * If expr is specified, clean node with names matching expr.
 * If SDEV_ENFORCE is specified in flags, busy nodes are made stale,
 *	so they are excluded from future lookups.
 */
int
sdev_cleandir(struct sdev_node *ddv, char *expr, uint_t flags)
{
	int error = 0;
	int busy = 0;
	struct vnode *vp;
	struct sdev_node *dv;
	int bkstore = 0;
	int len = 0;
	char *bks_name = NULL;

	ASSERT(SDEVTOV(ddv)->v_type == VDIR);

	/*
	 * We try our best to destroy all unused sdev_node's
	 */
	rw_enter(&ddv->sdev_contents, RW_WRITER);
	while ((dv = SDEV_FIRST_ENTRY(ddv)) != NULL) {
		vp = SDEVTOV(dv);

		if (expr && gmatch(dv->sdev_name, expr) == 0)
			continue;

		if (vp->v_type == VDIR &&
		    sdev_cleandir(dv, NULL, flags) != 0) {
			sdcmn_err9(("sdev_cleandir: dir %s busy\n",
			    dv->sdev_name));
			busy++;
			continue;
		}

		if (vp->v_count > 0 && (flags & SDEV_ENFORCE) == 0) {
			sdcmn_err9(("sdev_cleandir: dir %s busy\n",
			    dv->sdev_name));
			busy++;
			continue;
		}

		/*
		 * at this point, either dv is not held or SDEV_ENFORCE
		 * is specified. In either case, dv needs to be deleted
		 */
		SDEV_HOLD(dv);

		bkstore = SDEV_IS_PERSIST(dv) ? 1 : 0;
		if (bkstore && (vp->v_type == VDIR))
			bkstore += 1;

		if (bkstore) {
			len = strlen(dv->sdev_name) + 1;
			bks_name = kmem_alloc(len, KM_SLEEP);
			bcopy(dv->sdev_name, bks_name, len);
		}

		sdev_dirdelete(ddv, dv);

		/* take care the backing store clean up */
		if (bkstore) {
			ASSERT(bks_name);
			ASSERT(ddv->sdev_attrvp);

			if (bkstore == 1) {
				error = VOP_REMOVE(ddv->sdev_attrvp,
				    bks_name, kcred, NULL, 0);
			} else if (bkstore == 2) {
				error = VOP_RMDIR(ddv->sdev_attrvp,
				    bks_name, ddv->sdev_attrvp, kcred, NULL, 0);
			}

			/* do not propagate the backing store errors */
			if (error) {
				sdcmn_err9(("sdev_cleandir: backing store"
				    "not cleaned\n"));
				error = 0;
			}

			bkstore = 0;
			kmem_free(bks_name, len);
			bks_name = NULL;
			len = 0;
		}

		ddv->sdev_flags |= SDEV_BUILD;
		SDEV_RELE(dv);
	}

	ddv->sdev_flags |= SDEV_BUILD;
	rw_exit(&ddv->sdev_contents);

	if (busy) {
		error = EBUSY;
	}

	return (error);
}

/*
 * a convenient wrapper for readdir() funcs
 */
size_t
add_dir_entry(dirent64_t *de, char *nm, size_t size, ino_t ino, offset_t off)
{
	size_t reclen = DIRENT64_RECLEN(strlen(nm));
	if (reclen > size)
		return (0);

	de->d_ino = (ino64_t)ino;
	de->d_off = (off64_t)off + 1;
	de->d_reclen = (ushort_t)reclen;
	(void) strncpy(de->d_name, nm, DIRENT64_NAMELEN(reclen));
	return (reclen);
}

/*
 * sdev_mount service routines
 */
int
sdev_copyin_mountargs(struct mounta *uap, struct sdev_mountargs *args)
{
	int	error;

	if (uap->datalen != sizeof (*args))
		return (EINVAL);

	if (error = copyin(uap->dataptr, args, sizeof (*args))) {
		cmn_err(CE_WARN, "sdev_copyin_mountargs: can not"
		    "get user data. error %d\n", error);
		return (EFAULT);
	}

	return (0);
}

#ifdef nextdp
#undef nextdp
#endif
#define	nextdp(dp)	((struct dirent64 *) \
			    (intptr_t)((char *)(dp) + (dp)->d_reclen))

/*
 * readdir helper func
 */
int
devname_readdir_func(vnode_t *vp, uio_t *uiop, cred_t *cred, int *eofp,
    int flags)
{
	struct sdev_node *ddv = VTOSDEV(vp);
	struct sdev_node *dv;
	dirent64_t	*dp;
	ulong_t		outcount = 0;
	size_t		namelen;
	ulong_t		alloc_count;
	void		*outbuf;
	struct iovec	*iovp;
	int		error = 0;
	size_t		reclen;
	offset_t	diroff;
	offset_t	soff;
	int		this_reclen;
	int (*vtor)(struct sdev_node *) = NULL;
	struct vattr attr;
	timestruc_t now;

	ASSERT(ddv->sdev_attr || ddv->sdev_attrvp);
	ASSERT(RW_READ_HELD(&ddv->sdev_contents));

	if (uiop->uio_loffset >= MAXOFF_T) {
		if (eofp)
			*eofp = 1;
		return (0);
	}

	if (uiop->uio_iovcnt != 1)
		return (EINVAL);

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	if (ddv->sdev_flags & SDEV_VTOR) {
		vtor = (int (*)(struct sdev_node *))sdev_get_vtor(ddv);
		ASSERT(vtor);
	}

	if (eofp != NULL)
		*eofp = 0;

	soff = uiop->uio_loffset;
	iovp = uiop->uio_iov;
	alloc_count = iovp->iov_len;
	dp = outbuf = kmem_alloc(alloc_count, KM_SLEEP);
	outcount = 0;

	if (ddv->sdev_state == SDEV_ZOMBIE)
		goto get_cache;

	if (SDEV_IS_GLOBAL(ddv)) {

		if ((sdev_boot_state == SDEV_BOOT_STATE_COMPLETE) &&
		    !sdev_reconfig_boot && (flags & SDEV_BROWSE) &&
		    !SDEV_IS_DYNAMIC(ddv) && !SDEV_IS_NO_NCACHE(ddv) &&
		    ((moddebug & MODDEBUG_FINI_EBUSY) == 0) &&
		    !DEVNAME_DEVFSADM_HAS_RUN(devfsadm_state) &&
		    !DEVNAME_DEVFSADM_IS_RUNNING(devfsadm_state) &&
		    !sdev_reconfig_disable) {
			/*
			 * invoking "devfsadm" to do system device reconfig
			 */
			mutex_enter(&ddv->sdev_lookup_lock);
			SDEV_BLOCK_OTHERS(ddv,
			    (SDEV_READDIR|SDEV_LGWAITING));
			mutex_exit(&ddv->sdev_lookup_lock);

			sdcmn_err8(("readdir of %s by %s: reconfig\n",
			    ddv->sdev_path, curproc->p_user.u_comm));
			if (sdev_reconfig_verbose) {
				cmn_err(CE_CONT,
				    "?readdir of %s by %s: reconfig\n",
				    ddv->sdev_path, curproc->p_user.u_comm);
			}

			sdev_devfsadmd_thread(ddv, NULL, kcred);
		} else if (DEVNAME_DEVFSADM_IS_RUNNING(devfsadm_state)) {
			/*
			 * compensate the "ls" started later than "devfsadm"
			 */
			mutex_enter(&ddv->sdev_lookup_lock);
			SDEV_BLOCK_OTHERS(ddv, (SDEV_READDIR|SDEV_LGWAITING));
			mutex_exit(&ddv->sdev_lookup_lock);
		}

		/*
		 * release the contents lock so that
		 * the cache may be updated by devfsadmd
		 */
		rw_exit(&ddv->sdev_contents);
		mutex_enter(&ddv->sdev_lookup_lock);
		if (SDEV_IS_READDIR(ddv))
			(void) sdev_wait4lookup(ddv, SDEV_READDIR);
		mutex_exit(&ddv->sdev_lookup_lock);
		rw_enter(&ddv->sdev_contents, RW_READER);

		sdcmn_err4(("readdir of directory %s by %s\n",
		    ddv->sdev_name, curproc->p_user.u_comm));
		if (ddv->sdev_flags & SDEV_BUILD) {
			if (SDEV_IS_PERSIST(ddv)) {
				error = sdev_filldir_from_store(ddv,
				    alloc_count, cred);
			}
			ddv->sdev_flags &= ~SDEV_BUILD;
		}
	}

get_cache:
	/* handle "." and ".." */
	diroff = 0;
	if (soff == 0) {
		/* first time */
		this_reclen = DIRENT64_RECLEN(1);
		if (alloc_count < this_reclen) {
			error = EINVAL;
			goto done;
		}

		dp->d_ino = (ino64_t)ddv->sdev_ino;
		dp->d_off = (off64_t)1;
		dp->d_reclen = (ushort_t)this_reclen;

		(void) strncpy(dp->d_name, ".",
		    DIRENT64_NAMELEN(this_reclen));
		outcount += dp->d_reclen;
		dp = nextdp(dp);
	}

	diroff++;
	if (soff <= 1) {
		this_reclen = DIRENT64_RECLEN(2);
		if (alloc_count < outcount + this_reclen) {
			error = EINVAL;
			goto done;
		}

		dp->d_reclen = (ushort_t)this_reclen;
		dp->d_ino = (ino64_t)ddv->sdev_dotdot->sdev_ino;
		dp->d_off = (off64_t)2;

		(void) strncpy(dp->d_name, "..",
		    DIRENT64_NAMELEN(this_reclen));
		outcount += dp->d_reclen;

		dp = nextdp(dp);
	}


	/* gets the cache */
	diroff++;
	for (dv = SDEV_FIRST_ENTRY(ddv); dv;
	    dv = SDEV_NEXT_ENTRY(ddv, dv), diroff++) {
		sdcmn_err3(("sdev_readdir: diroff %lld soff %lld for '%s' \n",
		    diroff, soff, dv->sdev_name));

		/* bypassing pre-matured nodes */
		if (diroff < soff || (dv->sdev_state != SDEV_READY)) {
			sdcmn_err3(("sdev_readdir: pre-mature node  "
			    "%s %d\n", dv->sdev_name, dv->sdev_state));
			continue;
		}

		/*
		 * Check validity of node
		 * Drop invalid and nodes to be skipped.
		 * A node the validator indicates as stale needs
		 * to be returned as presumably the node name itself
		 * is valid and the node data itself will be refreshed
		 * on lookup.  An application performing a readdir then
		 * stat on each entry should thus always see consistent
		 * data.  In any case, it is not possible to synchronize
		 * with dynamic kernel state, and any view we return can
		 * never be anything more than a snapshot at a point in time.
		 */
		if (vtor) {
			switch (vtor(dv)) {
			case SDEV_VTOR_VALID:
				break;
			case SDEV_VTOR_INVALID:
			case SDEV_VTOR_SKIP:
				continue;
			case SDEV_VTOR_STALE:
				sdcmn_err3(("sdev_readir: %s stale\n",
				    dv->sdev_name));
				break;
			default:
				cmn_err(CE_PANIC,
				    "dev fs: validator failed: %s(%p)\n",
				    dv->sdev_name, (void *)dv);
				break;
			/*NOTREACHED*/
			}
		}

		namelen = strlen(dv->sdev_name);
		reclen = DIRENT64_RECLEN(namelen);
		if (outcount + reclen > alloc_count) {
			goto full;
		}
		dp->d_reclen = (ushort_t)reclen;
		dp->d_ino = (ino64_t)dv->sdev_ino;
		dp->d_off = (off64_t)diroff + 1;
		(void) strncpy(dp->d_name, dv->sdev_name,
		    DIRENT64_NAMELEN(reclen));
		outcount += reclen;
		dp = nextdp(dp);
	}

full:
	sdcmn_err4(("sdev_readdir: moving %lu bytes: "
	    "diroff %lld, soff %lld, dv %p\n", outcount, diroff, soff,
	    (void *)dv));

	if (outcount)
		error = uiomove(outbuf, outcount, UIO_READ, uiop);

	if (!error) {
		uiop->uio_loffset = diroff;
		if (eofp)
			*eofp = dv ? 0 : 1;
	}


	if (ddv->sdev_attrvp) {
		gethrestime(&now);
		attr.va_ctime = now;
		attr.va_atime = now;
		attr.va_mask = AT_CTIME|AT_ATIME;

		(void) VOP_SETATTR(ddv->sdev_attrvp, &attr, 0, kcred, NULL);
	}
done:
	kmem_free(outbuf, alloc_count);
	return (error);
}

static int
sdev_modctl_lookup(const char *path, vnode_t **r_vp)
{
	vnode_t *vp;
	vnode_t *cvp;
	struct sdev_node *svp;
	char *nm;
	struct pathname pn;
	int error;
	int persisted = 0;

	ASSERT(INGLOBALZONE(curproc));

	if (error = pn_get((char *)path, UIO_SYSSPACE, &pn))
		return (error);
	nm = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	vp = rootdir;
	VN_HOLD(vp);

	while (pn_pathleft(&pn)) {
		ASSERT(vp->v_type == VDIR || vp->v_type == VLNK);
		(void) pn_getcomponent(&pn, nm);

		/*
		 * Deal with the .. special case where we may be
		 * traversing up across a mount point, to the
		 * root of this filesystem or global root.
		 */
		if (nm[0] == '.' && nm[1] == '.' && nm[2] == 0) {
checkforroot:
			if (VN_CMP(vp, rootdir)) {
				nm[1] = 0;
			} else if (vp->v_flag & VROOT) {
				vfs_t *vfsp;
				cvp = vp;
				vfsp = cvp->v_vfsp;
				vfs_rlock_wait(vfsp);
				vp = cvp->v_vfsp->vfs_vnodecovered;
				if (vp == NULL ||
				    (cvp->v_vfsp->vfs_flag & VFS_UNMOUNTED)) {
					vfs_unlock(vfsp);
					VN_RELE(cvp);
					error = EIO;
					break;
				}
				VN_HOLD(vp);
				vfs_unlock(vfsp);
				VN_RELE(cvp);
				cvp = NULL;
				goto checkforroot;
			}
		}

		error = VOP_LOOKUP(vp, nm, &cvp, NULL, 0, NULL, kcred, NULL,
		    NULL, NULL);
		if (error) {
			VN_RELE(vp);
			break;
		}

		/* traverse mount points encountered on our journey */
		if (vn_ismntpt(cvp) && (error = traverse(&cvp)) != 0) {
			VN_RELE(vp);
			VN_RELE(cvp);
			break;
		}

		/*
		 * symbolic link, can be either relative and absolute
		 */
		if ((cvp->v_type == VLNK) && pn_pathleft(&pn)) {
			struct pathname linkpath;
			pn_alloc(&linkpath);
			if (error = pn_getsymlink(cvp, &linkpath, kcred)) {
				pn_free(&linkpath);
				break;
			}
			if (pn_pathleft(&linkpath) == 0)
				(void) pn_set(&linkpath, ".");
			error = pn_insert(&pn, &linkpath, strlen(nm));
			pn_free(&linkpath);
			if (pn.pn_pathlen == 0) {
				VN_RELE(vp);
				return (ENOENT);
			}
			if (pn.pn_path[0] == '/') {
				pn_skipslash(&pn);
				VN_RELE(vp);
				VN_RELE(cvp);
				vp = rootdir;
				VN_HOLD(vp);
			} else {
				VN_RELE(cvp);
			}
			continue;
		}

		VN_RELE(vp);

		/*
		 * Direct the operation to the persisting filesystem
		 * underlying /dev.  Bail if we encounter a
		 * non-persistent dev entity here.
		 */
		if (cvp->v_vfsp->vfs_fstype == devtype) {

			if ((VTOSDEV(cvp)->sdev_flags & SDEV_PERSIST) == 0) {
				error = ENOENT;
				VN_RELE(cvp);
				break;
			}

			if (VTOSDEV(cvp) == NULL) {
				error = ENOENT;
				VN_RELE(cvp);
				break;
			}
			svp = VTOSDEV(cvp);
			if ((vp = svp->sdev_attrvp) == NULL) {
				error = ENOENT;
				VN_RELE(cvp);
				break;
			}
			persisted = 1;
			VN_HOLD(vp);
			VN_RELE(cvp);
			cvp = vp;
		}

		vp = cvp;
		pn_skipslash(&pn);
	}

	kmem_free(nm, MAXNAMELEN);
	pn_free(&pn);

	if (error)
		return (error);

	/*
	 * Only return persisted nodes in the filesystem underlying /dev.
	 */
	if (!persisted) {
		VN_RELE(vp);
		return (ENOENT);
	}

	*r_vp = vp;
	return (0);
}

int
sdev_modctl_readdir(const char *dir, char ***dirlistp,
	int *npathsp, int *npathsp_alloc, int checking_empty)
{
	char	**pathlist = NULL;
	char	**newlist = NULL;
	int	npaths = 0;
	int	npaths_alloc = 0;
	dirent64_t *dbuf = NULL;
	int	n;
	char	*s;
	int error;
	vnode_t *vp;
	int eof;
	struct iovec iov;
	struct uio uio;
	struct dirent64 *dp;
	size_t dlen;
	size_t dbuflen;
	int ndirents = 64;
	char *nm;

	error = sdev_modctl_lookup(dir, &vp);
	sdcmn_err11(("modctl readdir: %s by %s: %s\n",
	    dir, curproc->p_user.u_comm,
	    (error == 0) ? "ok" : "failed"));
	if (error)
		return (error);

	dlen = ndirents * (sizeof (*dbuf));
	dbuf = kmem_alloc(dlen, KM_SLEEP);

	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_extflg = UIO_COPY_CACHED;
	uio.uio_loffset = 0;
	uio.uio_llimit = MAXOFFSET_T;

	eof = 0;
	error = 0;
	while (!error && !eof) {
		uio.uio_resid = dlen;
		iov.iov_base = (char *)dbuf;
		iov.iov_len = dlen;

		(void) VOP_RWLOCK(vp, V_WRITELOCK_FALSE, NULL);
		error = VOP_READDIR(vp, &uio, kcred, &eof, NULL, 0);
		VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, NULL);

		dbuflen = dlen - uio.uio_resid;

		if (error || dbuflen == 0)
			break;

		for (dp = dbuf; ((intptr_t)dp < (intptr_t)dbuf + dbuflen);
		    dp = (dirent64_t *)((intptr_t)dp + dp->d_reclen)) {

			nm = dp->d_name;

			if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0)
				continue;
			if (npaths == npaths_alloc) {
				npaths_alloc += 64;
				newlist = (char **)
				    kmem_zalloc((npaths_alloc + 1) *
				    sizeof (char *), KM_SLEEP);
				if (pathlist) {
					bcopy(pathlist, newlist,
					    npaths * sizeof (char *));
					kmem_free(pathlist,
					    (npaths + 1) * sizeof (char *));
				}
				pathlist = newlist;
			}
			n = strlen(nm) + 1;
			s = kmem_alloc(n, KM_SLEEP);
			bcopy(nm, s, n);
			pathlist[npaths++] = s;
			sdcmn_err11(("  %s/%s\n", dir, s));

			/* if checking empty, one entry is as good as many */
			if (checking_empty) {
				eof = 1;
				break;
			}
		}
	}

exit:
	VN_RELE(vp);

	if (dbuf)
		kmem_free(dbuf, dlen);

	if (error)
		return (error);

	*dirlistp = pathlist;
	*npathsp = npaths;
	*npathsp_alloc = npaths_alloc;

	return (0);
}

void
sdev_modctl_readdir_free(char **pathlist, int npaths, int npaths_alloc)
{
	int	i, n;

	for (i = 0; i < npaths; i++) {
		n = strlen(pathlist[i]) + 1;
		kmem_free(pathlist[i], n);
	}

	kmem_free(pathlist, (npaths_alloc + 1) * sizeof (char *));
}

int
sdev_modctl_devexists(const char *path)
{
	vnode_t *vp;
	int error;

	error = sdev_modctl_lookup(path, &vp);
	sdcmn_err11(("modctl dev exists: %s by %s: %s\n",
	    path, curproc->p_user.u_comm,
	    (error == 0) ? "ok" : "failed"));
	if (error == 0)
		VN_RELE(vp);

	return (error);
}

extern int sdev_vnodeops_tbl_size;

/*
 * construct a new template with overrides from vtab
 */
static fs_operation_def_t *
sdev_merge_vtab(const fs_operation_def_t tab[])
{
	fs_operation_def_t *new;
	const fs_operation_def_t *tab_entry;

	/* make a copy of standard vnode ops table */
	new = kmem_alloc(sdev_vnodeops_tbl_size, KM_SLEEP);
	bcopy((void *)sdev_vnodeops_tbl, new, sdev_vnodeops_tbl_size);

	/* replace the overrides from tab */
	for (tab_entry = tab; tab_entry->name != NULL; tab_entry++) {
		fs_operation_def_t *std_entry = new;
		while (std_entry->name) {
			if (strcmp(tab_entry->name, std_entry->name) == 0) {
				std_entry->func = tab_entry->func;
				break;
			}
			std_entry++;
		}
		if (std_entry->name == NULL)
			cmn_err(CE_NOTE, "sdev_merge_vtab: entry %s unused.",
			    tab_entry->name);
	}

	return (new);
}

/* free memory allocated by sdev_merge_vtab */
static void
sdev_free_vtab(fs_operation_def_t *new)
{
	kmem_free(new, sdev_vnodeops_tbl_size);
}

/*
 * a generic setattr() function
 *
 * note: flags only supports AT_UID and AT_GID.
 *	 Future enhancements can be done for other types, e.g. AT_MODE
 */
int
devname_setattr_func(struct vnode *vp, struct vattr *vap, int flags,
    struct cred *cred, int (*callback)(struct sdev_node *, struct vattr *,
    int), int protocol)
{
	struct sdev_node	*dv = VTOSDEV(vp);
	struct sdev_node	*parent = dv->sdev_dotdot;
	struct vattr		*get;
	uint_t			mask = vap->va_mask;
	int 			error;

	/* some sanity checks */
	if (vap->va_mask & AT_NOSET)
		return (EINVAL);

	if (vap->va_mask & AT_SIZE) {
		if (vp->v_type == VDIR) {
			return (EISDIR);
		}
	}

	/* no need to set attribute, but do not fail either */
	ASSERT(parent);
	rw_enter(&parent->sdev_contents, RW_READER);
	if (dv->sdev_state == SDEV_ZOMBIE) {
		rw_exit(&parent->sdev_contents);
		return (0);
	}

	/* If backing store exists, just set it. */
	if (dv->sdev_attrvp) {
		rw_exit(&parent->sdev_contents);
		return (VOP_SETATTR(dv->sdev_attrvp, vap, flags, cred, NULL));
	}

	/*
	 * Otherwise, for nodes with the persistence attribute, create it.
	 */
	ASSERT(dv->sdev_attr);
	if (SDEV_IS_PERSIST(dv) ||
	    ((vap->va_mask & ~AT_TIMES) != 0 && !SDEV_IS_DYNAMIC(dv))) {
		sdev_vattr_merge(dv, vap);
		rw_enter(&dv->sdev_contents, RW_WRITER);
		error = sdev_shadow_node(dv, cred);
		rw_exit(&dv->sdev_contents);
		rw_exit(&parent->sdev_contents);

		if (error)
			return (error);
		return (VOP_SETATTR(dv->sdev_attrvp, vap, flags, cred, NULL));
	}


	/*
	 * sdev_attr was allocated in sdev_mknode
	 */
	rw_enter(&dv->sdev_contents, RW_WRITER);
	error = secpolicy_vnode_setattr(cred, vp, vap,
	    dv->sdev_attr, flags, sdev_unlocked_access, dv);
	if (error) {
		rw_exit(&dv->sdev_contents);
		rw_exit(&parent->sdev_contents);
		return (error);
	}

	get = dv->sdev_attr;
	if (mask & AT_MODE) {
		get->va_mode &= S_IFMT;
		get->va_mode |= vap->va_mode & ~S_IFMT;
	}

	if ((mask & AT_UID) || (mask & AT_GID)) {
		if (mask & AT_UID)
			get->va_uid = vap->va_uid;
		if (mask & AT_GID)
			get->va_gid = vap->va_gid;
		/*
		 * a callback must be provided if the protocol is set
		 */
		if ((protocol & AT_UID) || (protocol & AT_GID)) {
			ASSERT(callback);
			error = callback(dv, get, protocol);
			if (error) {
				rw_exit(&dv->sdev_contents);
				rw_exit(&parent->sdev_contents);
				return (error);
			}
		}
	}

	if (mask & AT_ATIME)
		get->va_atime = vap->va_atime;
	if (mask & AT_MTIME)
		get->va_mtime = vap->va_mtime;
	if (mask & (AT_MODE | AT_UID | AT_GID | AT_CTIME)) {
		gethrestime(&get->va_ctime);
	}

	sdev_vattr_merge(dv, get);
	rw_exit(&dv->sdev_contents);
	rw_exit(&parent->sdev_contents);
	return (0);
}

/*
 * a generic inactive() function
 */
/*ARGSUSED*/
void
devname_inactive_func(struct vnode *vp, struct cred *cred,
    void (*callback)(struct vnode *))
{
	int clean;
	struct sdev_node *dv = VTOSDEV(vp);
	int state;

	mutex_enter(&vp->v_lock);
	ASSERT(vp->v_count >= 1);


	if (vp->v_count == 1 && callback != NULL)
		callback(vp);

	rw_enter(&dv->sdev_contents, RW_WRITER);
	state = dv->sdev_state;

	clean = (vp->v_count == 1) && (state == SDEV_ZOMBIE);

	/*
	 * sdev is a rather bad public citizen. It violates the general
	 * agreement that in memory nodes should always have a valid reference
	 * count on their vnode. But that's not the case here. This means that
	 * we do actually have to distinguish between getting inactive callbacks
	 * for zombies and otherwise. This should probably be fixed.
	 */
	if (clean) {
		/* Remove the . entry to ourselves */
		if (vp->v_type == VDIR) {
			decr_link(dv);
		}
		VERIFY(dv->sdev_nlink == 1);
		decr_link(dv);
		--vp->v_count;
		rw_exit(&dv->sdev_contents);
		mutex_exit(&vp->v_lock);
		sdev_nodedestroy(dv, 0);
	} else {
		--vp->v_count;
		rw_exit(&dv->sdev_contents);
		mutex_exit(&vp->v_lock);
	}
}
