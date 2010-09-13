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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * miscellaneous routines for the devfs
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
#include <sys/modctl.h>
#include <fs/fs_subr.h>
#include <sys/fs/dv_node.h>
#include <sys/fs/snode.h>
#include <sys/sunndi.h>
#include <sys/sunmdi.h>
#include <sys/conf.h>

#ifdef DEBUG
int devfs_debug = 0x0;
#endif

const char	dvnm[] = "devfs";
kmem_cache_t	*dv_node_cache;	/* dv_node cache */

/*
 * The devfs_clean_key is taken during a devfs_clean operation: it is used to
 * prevent unnecessary code execution and for detection of potential deadlocks.
 */
uint_t		devfs_clean_key;

struct dv_node *dvroot;

/* prototype memory vattrs */
vattr_t dv_vattr_dir = {
	AT_TYPE|AT_MODE|AT_UID|AT_GID, 		/* va_mask */
	VDIR,					/* va_type */
	DV_DIRMODE_DEFAULT,			/* va_mode */
	DV_UID_DEFAULT,				/* va_uid */
	DV_GID_DEFAULT,				/* va_gid */
	0,					/* va_fsid; */
	0,					/* va_nodeid; */
	0,					/* va_nlink; */
	0,					/* va_size; */
	0,					/* va_atime; */
	0,					/* va_mtime; */
	0,					/* va_ctime; */
	0,					/* va_rdev; */
	0,					/* va_blksize; */
	0,					/* va_nblocks; */
	0,					/* va_seq; */
};

vattr_t dv_vattr_file = {
	AT_TYPE|AT_MODE|AT_SIZE|AT_UID|AT_GID|AT_RDEV,	/* va_mask */
	0,					/* va_type */
	DV_DEVMODE_DEFAULT,			/* va_mode */
	DV_UID_DEFAULT,				/* va_uid */
	DV_GID_DEFAULT,				/* va_gid */
	0,					/* va_fsid; */
	0,					/* va_nodeid; */
	0,					/* va_nlink; */
	0,					/* va_size; */
	0,					/* va_atime; */
	0,					/* va_mtime; */
	0,					/* va_ctime; */
	0,					/* va_rdev; */
	0,					/* va_blksize; */
	0,					/* va_nblocks; */
	0,					/* va_seq; */
};

vattr_t dv_vattr_priv = {
	AT_TYPE|AT_MODE|AT_SIZE|AT_UID|AT_GID|AT_RDEV,	/* va_mask */
	0,					/* va_type */
	DV_DEVMODE_PRIV,			/* va_mode */
	DV_UID_DEFAULT,				/* va_uid */
	DV_GID_DEFAULT,				/* va_gid */
	0,					/* va_fsid; */
	0,					/* va_nodeid; */
	0,					/* va_nlink; */
	0,					/* va_size; */
	0,					/* va_atime; */
	0,					/* va_mtime; */
	0,					/* va_ctime; */
	0,					/* va_rdev; */
	0,					/* va_blksize; */
	0,					/* va_nblocks; */
	0,					/* va_seq; */
};

extern dev_info_t	*clone_dip;
extern major_t		clone_major;
extern struct dev_ops	*ddi_hold_driver(major_t);

/* dv_node node constructor for kmem cache */
static int
i_dv_node_ctor(void *buf, void *cfarg, int flag)
{
	_NOTE(ARGUNUSED(cfarg, flag))
	struct dv_node	*dv = (struct dv_node *)buf;
	struct vnode	*vp;

	bzero(buf, sizeof (struct dv_node));
	vp = dv->dv_vnode = vn_alloc(flag);
	if (vp == NULL) {
		return (-1);
	}
	vp->v_data = dv;
	rw_init(&dv->dv_contents, NULL, RW_DEFAULT, NULL);
	return (0);
}

/* dv_node node destructor for kmem cache */
static void
i_dv_node_dtor(void *buf, void *arg)
{
	_NOTE(ARGUNUSED(arg))
	struct dv_node	*dv = (struct dv_node *)buf;
	struct vnode	*vp = DVTOV(dv);

	rw_destroy(&dv->dv_contents);
	vn_invalid(vp);
	vn_free(vp);
}


/* initialize dv_node node cache */
void
dv_node_cache_init()
{
	ASSERT(dv_node_cache == NULL);
	dv_node_cache = kmem_cache_create("dv_node_cache",
	    sizeof (struct dv_node), 0, i_dv_node_ctor, i_dv_node_dtor,
	    NULL, NULL, NULL, 0);

	tsd_create(&devfs_clean_key, NULL);
}

/* destroy dv_node node cache */
void
dv_node_cache_fini()
{
	ASSERT(dv_node_cache != NULL);
	kmem_cache_destroy(dv_node_cache);
	dv_node_cache = NULL;

	tsd_destroy(&devfs_clean_key);
}

/*
 * dv_mkino - Generate a unique inode number for devfs nodes.
 *
 * Although ino_t is 64 bits, the inode number is truncated to 32 bits for 32
 * bit non-LARGEFILE applications. This means that there is a requirement to
 * maintain the inode number as a 32 bit value or applications will have
 * stat(2) calls fail with EOVERFLOW.  We form a 32 bit inode number from the
 * dev_t. but if the minor number is larger than L_MAXMIN32 we fold extra minor
 *
 * To generate inode numbers for directories, we assume that we will never use
 * more than half the major space - this allows for ~8190 drivers. We use this
 * upper major number space to allocate inode numbers for directories by
 * encoding the major and instance into this space.
 *
 * We also skew the result so that inode 2 is reserved for the root of the file
 * system.
 *
 * As part of the future support for 64-bit dev_t APIs, the upper minor bits
 * should be folded into the high inode bits by adding the following code
 * after "ino |= 1":
 *
 * #if (L_BITSMINOR32 != L_BITSMINOR)
 *		|* fold overflow minor bits into high bits of inode number *|
 *		ino |= ((ino_t)(minor >> L_BITSMINOR32)) << L_BITSMINOR;
 * #endif |* (L_BITSMINOR32 != L_BITSMINOR) *|
 *
 * This way only applications that use devices that overflow their minor
 * space will have an application level impact.
 */
static ino_t
dv_mkino(dev_info_t *devi, vtype_t typ, dev_t dev)
{
	major_t		major;
	minor_t		minor;
	ino_t		ino;
	static int	warn;

	if (typ == VDIR) {
		major = ((L_MAXMAJ32 + 1) >> 1) + DEVI(devi)->devi_major;
		minor = ddi_get_instance(devi);

		/* makedevice32 in high half of major number space */
		ino = (ino_t)((major << L_BITSMINOR32) | (minor & L_MAXMIN32));

		major = DEVI(devi)->devi_major;
	} else {
		major = getmajor(dev);
		minor = getminor(dev);

		/* makedevice32 */
		ino = (ino_t)((major << L_BITSMINOR32) | (minor & L_MAXMIN32));

		/* make ino for VCHR different than VBLK */
		ino <<= 1;
		if (typ == VCHR)
			ino |= 1;
	}

	ino += DV_ROOTINO + 1;		/* skew */

	/*
	 * diagnose things a little early because adding the skew to a large
	 * minor number could roll over the major.
	 */
	if ((major >= (L_MAXMAJ32 >> 1)) && (warn == 0)) {
		warn = 1;
		cmn_err(CE_WARN, "%s: inode numbers are not unique", dvnm);
	}

	return (ino);
}

/*
 * Compare two nodes lexographically to balance avl tree
 */
static int
dv_compare_nodes(const struct dv_node *dv1, const struct dv_node *dv2)
{
	int	rv;

	if ((rv = strcmp(dv1->dv_name, dv2->dv_name)) == 0)
		return (0);
	return ((rv < 0) ? -1 : 1);
}

/*
 * dv_mkroot
 *
 * Build the first VDIR dv_node.
 */
struct dv_node *
dv_mkroot(struct vfs *vfsp, dev_t devfsdev)
{
	struct dv_node	*dv;
	struct vnode	*vp;

	ASSERT(ddi_root_node() != NULL);
	ASSERT(dv_node_cache != NULL);

	dcmn_err3(("dv_mkroot\n"));
	dv = kmem_cache_alloc(dv_node_cache, KM_SLEEP);
	vp = DVTOV(dv);
	vn_reinit(vp);
	vp->v_flag = VROOT;
	vp->v_vfsp = vfsp;
	vp->v_type = VDIR;
	vp->v_rdev = devfsdev;
	vn_setops(vp, dv_vnodeops);
	vn_exists(vp);

	dvroot = dv;

	dv->dv_name = NULL;		/* not needed */
	dv->dv_namelen = 0;

	dv->dv_devi = ddi_root_node();

	dv->dv_ino = DV_ROOTINO;
	dv->dv_nlink = 2;		/* name + . (no dv_insert) */
	dv->dv_dotdot = dv;		/* .. == self */
	dv->dv_attrvp = NULLVP;
	dv->dv_attr = NULL;
	dv->dv_flags = DV_BUILD;
	dv->dv_priv = NULL;
	dv->dv_busy = 0;
	dv->dv_dflt_mode = 0;

	avl_create(&dv->dv_entries,
	    (int (*)(const void *, const void *))dv_compare_nodes,
	    sizeof (struct dv_node), offsetof(struct dv_node, dv_avllink));

	return (dv);
}

/*
 * dv_mkdir
 *
 * Given an probed or attached nexus node, create a VDIR dv_node.
 * No dv_attrvp is created at this point.
 */
struct dv_node *
dv_mkdir(struct dv_node *ddv, dev_info_t *devi, char *nm)
{
	struct dv_node	*dv;
	struct vnode	*vp;
	size_t		nmlen;

	ASSERT((devi));
	dcmn_err4(("dv_mkdir: %s\n", nm));

	dv = kmem_cache_alloc(dv_node_cache, KM_SLEEP);
	nmlen = strlen(nm) + 1;
	dv->dv_name = kmem_alloc(nmlen, KM_SLEEP);
	bcopy(nm, dv->dv_name, nmlen);
	dv->dv_namelen = nmlen - 1;	/* '\0' not included */

	vp = DVTOV(dv);
	vn_reinit(vp);
	vp->v_flag = 0;
	vp->v_vfsp = DVTOV(ddv)->v_vfsp;
	vp->v_type = VDIR;
	vp->v_rdev = DVTOV(ddv)->v_rdev;
	vn_setops(vp, vn_getops(DVTOV(ddv)));
	vn_exists(vp);

	dv->dv_devi = devi;
	ndi_hold_devi(devi);

	dv->dv_ino = dv_mkino(devi, VDIR, NODEV);
	dv->dv_nlink = 0;		/* updated on insert */
	dv->dv_dotdot = ddv;
	dv->dv_attrvp = NULLVP;
	dv->dv_attr = NULL;
	dv->dv_flags = DV_BUILD;
	dv->dv_priv = NULL;
	dv->dv_busy = 0;
	dv->dv_dflt_mode = 0;

	avl_create(&dv->dv_entries,
	    (int (*)(const void *, const void *))dv_compare_nodes,
	    sizeof (struct dv_node), offsetof(struct dv_node, dv_avllink));

	return (dv);
}

/*
 * dv_mknod
 *
 * Given a minor node, create a VCHR or VBLK dv_node.
 * No dv_attrvp is created at this point.
 */
static struct dv_node *
dv_mknod(struct dv_node *ddv, dev_info_t *devi, char *nm,
	struct ddi_minor_data *dmd)
{
	struct dv_node	*dv;
	struct vnode	*vp;
	size_t		nmlen;

	dcmn_err4(("dv_mknod: %s\n", nm));

	dv = kmem_cache_alloc(dv_node_cache, KM_SLEEP);
	nmlen = strlen(nm) + 1;
	dv->dv_name = kmem_alloc(nmlen, KM_SLEEP);
	bcopy(nm, dv->dv_name, nmlen);
	dv->dv_namelen = nmlen - 1;	/* no '\0' */

	vp = DVTOV(dv);
	vn_reinit(vp);
	vp->v_flag = 0;
	vp->v_vfsp = DVTOV(ddv)->v_vfsp;
	vp->v_type = dmd->ddm_spec_type == S_IFCHR ? VCHR : VBLK;
	vp->v_rdev = dmd->ddm_dev;
	vn_setops(vp, vn_getops(DVTOV(ddv)));
	vn_exists(vp);

	/* increment dev_ref with devi_lock held */
	ASSERT(DEVI_BUSY_OWNED(devi));
	mutex_enter(&DEVI(devi)->devi_lock);
	dv->dv_devi = devi;
	DEVI(devi)->devi_ref++;		/* ndi_hold_devi(dip) */
	mutex_exit(&DEVI(devi)->devi_lock);

	dv->dv_ino = dv_mkino(devi, vp->v_type, vp->v_rdev);
	dv->dv_nlink = 0;		/* updated on insert */
	dv->dv_dotdot = ddv;
	dv->dv_attrvp = NULLVP;
	dv->dv_attr = NULL;
	dv->dv_flags = 0;

	if (dmd->type == DDM_INTERNAL_PATH)
		dv->dv_flags |= DV_INTERNAL;
	if (dmd->ddm_flags & DM_NO_FSPERM)
		dv->dv_flags |= DV_NO_FSPERM;

	dv->dv_priv = dmd->ddm_node_priv;
	if (dv->dv_priv)
		dphold(dv->dv_priv);

	/*
	 * Minors created with ddi_create_priv_minor_node can specify
	 * a default mode permission other than the devfs default.
	 */
	if (dv->dv_priv || dv->dv_flags & DV_NO_FSPERM) {
		dcmn_err5(("%s: dv_mknod default priv mode 0%o\n",
		    dv->dv_name, dmd->ddm_priv_mode));
		dv->dv_flags |= DV_DFLT_MODE;
		dv->dv_dflt_mode = dmd->ddm_priv_mode & S_IAMB;
	}

	return (dv);
}

/*
 * dv_destroy
 *
 * Destroy what we created in dv_mkdir or dv_mknod.
 * In the case of a *referenced* directory, do nothing.
 */
void
dv_destroy(struct dv_node *dv, uint_t flags)
{
	vnode_t *vp = DVTOV(dv);
	ASSERT(dv->dv_nlink == 0);		/* no references */

	dcmn_err4(("dv_destroy: %s\n", dv->dv_name));

	/*
	 * We may be asked to unlink referenced directories.
	 * In this case, there is nothing to be done.
	 * The eventual memory free will be done in
	 * devfs_inactive.
	 */
	if (vp->v_count != 0) {
		ASSERT(vp->v_type == VDIR);
		ASSERT(flags & DV_CLEAN_FORCE);
		ASSERT(DV_STALE(dv));
		return;
	}

	if (vp->v_type == VDIR) {
		ASSERT(DV_FIRST_ENTRY(dv) == NULL);
		avl_destroy(&dv->dv_entries);
	}

	if (dv->dv_attrvp != NULLVP)
		VN_RELE(dv->dv_attrvp);
	if (dv->dv_attr != NULL)
		kmem_free(dv->dv_attr, sizeof (struct vattr));
	if (dv->dv_name != NULL)
		kmem_free(dv->dv_name, dv->dv_namelen + 1);
	if (dv->dv_devi != NULL) {
		ndi_rele_devi(dv->dv_devi);
	}
	if (dv->dv_priv != NULL) {
		dpfree(dv->dv_priv);
	}

	kmem_cache_free(dv_node_cache, dv);
}

/*
 * Find and hold dv_node by name
 */
static struct dv_node *
dv_findbyname(struct dv_node *ddv, char *nm)
{
	struct dv_node  *dv;
	avl_index_t	where;
	struct dv_node	dvtmp;

	ASSERT(RW_LOCK_HELD(&ddv->dv_contents));
	dcmn_err3(("dv_findbyname: %s\n", nm));

	dvtmp.dv_name = nm;
	dv = avl_find(&ddv->dv_entries, &dvtmp, &where);
	if (dv) {
		ASSERT(dv->dv_dotdot == ddv);
		ASSERT(strcmp(dv->dv_name, nm) == 0);
		VN_HOLD(DVTOV(dv));
		return (dv);
	}
	return (NULL);
}

/*
 * Inserts a new dv_node in a parent directory
 */
void
dv_insert(struct dv_node *ddv, struct dv_node *dv)
{
	avl_index_t	where;

	ASSERT(RW_WRITE_HELD(&ddv->dv_contents));
	ASSERT(DVTOV(ddv)->v_type == VDIR);
	ASSERT(ddv->dv_nlink >= 2);
	ASSERT(dv->dv_nlink == 0);

	dcmn_err3(("dv_insert: %s\n", dv->dv_name));

	dv->dv_dotdot = ddv;
	if (DVTOV(dv)->v_type == VDIR) {
		ddv->dv_nlink++;	/* .. to containing directory */
		dv->dv_nlink = 2;	/* name + . */
	} else {
		dv->dv_nlink = 1;	/* name */
	}

	/* enter node in the avl tree */
	VERIFY(avl_find(&ddv->dv_entries, dv, &where) == NULL);
	avl_insert(&ddv->dv_entries, dv, where);
}

/*
 * Unlink a dv_node from a perent directory
 */
void
dv_unlink(struct dv_node *ddv, struct dv_node *dv)
{
	/* verify linkage of arguments */
	ASSERT(ddv && dv);
	ASSERT(dv->dv_dotdot == ddv);
	ASSERT(RW_WRITE_HELD(&ddv->dv_contents));
	ASSERT(DVTOV(ddv)->v_type == VDIR);

	dcmn_err3(("dv_unlink: %s\n", dv->dv_name));

	if (DVTOV(dv)->v_type == VDIR) {
		ddv->dv_nlink--;	/* .. to containing directory */
		dv->dv_nlink -= 2;	/* name + . */
	} else {
		dv->dv_nlink -= 1;	/* name */
	}
	ASSERT(ddv->dv_nlink >= 2);
	ASSERT(dv->dv_nlink == 0);

	dv->dv_dotdot = NULL;

	/* remove from avl tree */
	avl_remove(&ddv->dv_entries, dv);
}

/*
 * Merge devfs node specific information into an attribute structure.
 *
 * NOTE: specfs provides ATIME,MTIME,CTIME,SIZE,BLKSIZE,NBLOCKS on leaf node.
 */
void
dv_vattr_merge(struct dv_node *dv, struct vattr *vap)
{
	struct vnode	*vp = DVTOV(dv);

	vap->va_nodeid = dv->dv_ino;
	vap->va_nlink = dv->dv_nlink;

	if (vp->v_type == VDIR) {
		vap->va_rdev = 0;
		vap->va_fsid = vp->v_rdev;
	} else {
		vap->va_rdev = vp->v_rdev;
		vap->va_fsid = DVTOV(dv->dv_dotdot)->v_rdev;
		vap->va_type = vp->v_type;
		/* don't trust the shadow file type */
		vap->va_mode &= ~S_IFMT;
		if (vap->va_type == VCHR)
			vap->va_mode |= S_IFCHR;
		else
			vap->va_mode |= S_IFBLK;
	}
}

/*
 * Get default device permission by consulting rules in
 * privilege specification in minor node and /etc/minor_perm.
 *
 * This function is called from the devname filesystem to get default
 * permissions for a device exported to a non-global zone.
 */
void
devfs_get_defattr(struct vnode *vp, struct vattr *vap, int *no_fs_perm)
{
	mperm_t		mp;
	struct dv_node	*dv;

	/* If vp isn't a dv_node, return something sensible */
	if (!vn_matchops(vp, dv_vnodeops)) {
		if (no_fs_perm)
			*no_fs_perm = 0;
		*vap = dv_vattr_file;
		return;
	}

	/*
	 * For minors not created by ddi_create_priv_minor_node(),
	 * use devfs defaults.
	 */
	dv = VTODV(vp);
	if (vp->v_type == VDIR) {
		*vap = dv_vattr_dir;
	} else if (dv->dv_flags & DV_NO_FSPERM) {
		if (no_fs_perm)
			*no_fs_perm = 1;
		*vap = dv_vattr_priv;
	} else {
		/*
		 * look up perm bits from minor_perm
		 */
		*vap = dv_vattr_file;
		if (dev_minorperm(dv->dv_devi, dv->dv_name, &mp) == 0) {
			VATTR_MP_MERGE((*vap), mp);
			dcmn_err5(("%s: minor perm mode 0%o\n",
			    dv->dv_name, vap->va_mode));
		} else if (dv->dv_flags & DV_DFLT_MODE) {
			ASSERT((dv->dv_dflt_mode & ~S_IAMB) == 0);
			vap->va_mode &= ~S_IAMB;
			vap->va_mode |= dv->dv_dflt_mode;
			dcmn_err5(("%s: priv mode 0%o\n",
			    dv->dv_name, vap->va_mode));
		}
	}
}

/*
 * dv_shadow_node
 *
 * Given a VDIR dv_node, find/create the associated VDIR
 * node in the shadow attribute filesystem.
 *
 * Given a VCHR/VBLK dv_node, find the associated VREG
 * node in the shadow attribute filesystem.  These nodes
 * are only created to persist non-default attributes.
 * Lack of such a node implies the default permissions
 * are sufficient.
 *
 * Managing the attribute file entries is slightly tricky (mostly
 * because we can't intercept VN_HOLD and VN_RELE except on the last
 * release).
 *
 * We assert that if the dv_attrvp pointer is non-NULL, it points
 * to a singly-held (by us) vnode that represents the shadow entry
 * in the underlying filesystem.  To avoid store-ordering issues,
 * we assert that the pointer can only be tested under the dv_contents
 * READERS lock.
 */

void
dv_shadow_node(
	struct vnode *dvp,	/* devfs parent directory vnode */
	char *nm,		/* name component */
	struct vnode *vp,	/* devfs vnode */
	struct pathname *pnp,	/* the path .. */
	struct vnode *rdir,	/* the root .. */
	struct cred *cred,	/* who's asking? */
	int flags)		/* optionally create shadow node */
{
	struct dv_node	*dv;	/* dv_node of named directory */
	struct vnode	*rdvp;	/* shadow parent directory vnode */
	struct vnode	*rvp;	/* shadow vnode */
	struct vnode	*rrvp;	/* realvp of shadow vnode */
	struct vattr	vattr;
	int		create_tried;
	int		error;

	ASSERT(vp->v_type == VDIR || vp->v_type == VCHR || vp->v_type == VBLK);
	dv = VTODV(vp);
	dcmn_err3(("dv_shadow_node: name %s attr %p\n",
	    nm, (void *)dv->dv_attrvp));

	if ((flags & DV_SHADOW_WRITE_HELD) == 0) {
		ASSERT(RW_READ_HELD(&dv->dv_contents));
		if (dv->dv_attrvp != NULLVP)
			return;
		if (!rw_tryupgrade(&dv->dv_contents)) {
			rw_exit(&dv->dv_contents);
			rw_enter(&dv->dv_contents, RW_WRITER);
			if (dv->dv_attrvp != NULLVP) {
				rw_downgrade(&dv->dv_contents);
				return;
			}
		}
	} else {
		ASSERT(RW_WRITE_HELD(&dv->dv_contents));
		if (dv->dv_attrvp != NULLVP)
			return;
	}

	ASSERT(RW_WRITE_HELD(&dv->dv_contents) && dv->dv_attrvp == NULL);

	rdvp = VTODV(dvp)->dv_attrvp;
	create_tried = 0;
lookup:
	if (rdvp && (dv->dv_flags & DV_NO_FSPERM) == 0) {
		error = VOP_LOOKUP(rdvp, nm, &rvp, pnp, LOOKUP_DIR, rdir, cred,
		    NULL, NULL, NULL);

		/* factor out the snode since we only want the attribute node */
		if ((error == 0) && (VOP_REALVP(rvp, &rrvp, NULL) == 0)) {
			VN_HOLD(rrvp);
			VN_RELE(rvp);
			rvp = rrvp;
		}
	} else
		error = EROFS;		/* no parent, no entry */

	/*
	 * All we want is the permissions (and maybe ACLs and
	 * extended attributes), and we want to perform lookups
	 * by name.  Drivers occasionally change their minor
	 * number space.  If something changes, there's no
	 * much we can do about it here.
	 */

	/* The shadow node checks out. We are done */
	if (error == 0) {
		dv->dv_attrvp = rvp;	/* with one hold */

		/*
		 * Determine if we have non-trivial ACLs on this node.
		 * It is not necessary to VOP_RWLOCK since fs_acl_nontrivial
		 * only does VOP_GETSECATTR.
		 */
		dv->dv_flags &= ~DV_ACL;

		if (fs_acl_nontrivial(rvp, cred))
			dv->dv_flags |= DV_ACL;

		/*
		 * If we have synced out the memory attributes, free
		 * them and switch back to using the persistent store.
		 */
		if (rvp && dv->dv_attr) {
			kmem_free(dv->dv_attr, sizeof (struct vattr));
			dv->dv_attr = NULL;
		}
		if ((flags & DV_SHADOW_WRITE_HELD) == 0)
			rw_downgrade(&dv->dv_contents);
		ASSERT(RW_LOCK_HELD(&dv->dv_contents));
		return;
	}

	/*
	 * Failed to find attribute in persistent backing store,
	 * get default permission bits.
	 */
	devfs_get_defattr(vp, &vattr, NULL);

	dv_vattr_merge(dv, &vattr);
	gethrestime(&vattr.va_atime);
	vattr.va_mtime = vattr.va_atime;
	vattr.va_ctime = vattr.va_atime;

	/*
	 * Try to create shadow dir. This is necessary in case
	 * we need to create a shadow leaf node later, when user
	 * executes chmod.
	 */
	if ((error == ENOENT) && !create_tried) {
		switch (vp->v_type) {
		case VDIR:
			error = VOP_MKDIR(rdvp, nm, &vattr, &rvp, kcred,
			    NULL, 0, NULL);
			dsysdebug(error, ("vop_mkdir %s %s %d\n",
			    VTODV(dvp)->dv_name, nm, error));
			create_tried = 1;
			break;

		case VCHR:
		case VBLK:
			/*
			 * Shadow nodes are only created on demand
			 */
			if (flags & DV_SHADOW_CREATE) {
				error = VOP_CREATE(rdvp, nm, &vattr, NONEXCL,
				    VREAD|VWRITE, &rvp, kcred, 0, NULL, NULL);
				dsysdebug(error, ("vop_create %s %s %d\n",
				    VTODV(dvp)->dv_name, nm, error));
				create_tried = 1;
			}
			break;

		default:
			cmn_err(CE_PANIC, "devfs: %s: create", dvnm);
			/*NOTREACHED*/
		}

		if (create_tried &&
		    (error == 0) || (error == EEXIST)) {
			VN_RELE(rvp);
			goto lookup;
		}
	}

	/* Store attribute in memory */
	if (dv->dv_attr == NULL) {
		dv->dv_attr = kmem_alloc(sizeof (struct vattr), KM_SLEEP);
		*(dv->dv_attr) = vattr;
	}

	if ((flags & DV_SHADOW_WRITE_HELD) == 0)
		rw_downgrade(&dv->dv_contents);
	ASSERT(RW_LOCK_HELD(&dv->dv_contents));
}

/*
 * Given a devinfo node, and a name, returns the appropriate
 * minor information for that named node, if it exists.
 */
static int
dv_find_leafnode(dev_info_t *devi, char *minor_nm, struct ddi_minor_data *r_mi)
{
	struct ddi_minor_data	*dmd;

	ASSERT(i_ddi_devi_attached(devi));

	dcmn_err3(("dv_find_leafnode: %s\n", minor_nm));
	ASSERT(DEVI_BUSY_OWNED(devi));
	for (dmd = DEVI(devi)->devi_minor; dmd; dmd = dmd->next) {

		/*
		 * Skip alias nodes and nodes without a name.
		 */
		if ((dmd->type == DDM_ALIAS) || (dmd->ddm_name == NULL))
			continue;

		dcmn_err4(("dv_find_leafnode: (%s,%s)\n",
		    minor_nm, dmd->ddm_name));
		if (strcmp(minor_nm, dmd->ddm_name) == 0) {
			r_mi->ddm_dev = dmd->ddm_dev;
			r_mi->ddm_spec_type = dmd->ddm_spec_type;
			r_mi->type = dmd->type;
			r_mi->ddm_flags = dmd->ddm_flags;
			r_mi->ddm_node_priv = dmd->ddm_node_priv;
			r_mi->ddm_priv_mode = dmd->ddm_priv_mode;
			if (r_mi->ddm_node_priv)
				dphold(r_mi->ddm_node_priv);
			return (0);
		}
	}

	dcmn_err3(("dv_find_leafnode: %s: ENOENT\n", minor_nm));
	return (ENOENT);
}

/*
 * Special handling for clone node:
 *	Clone minor name is a driver name, the minor number will
 *	be the major number of the driver. There is no minor
 *	node under the clone driver, so we'll manufacture the
 *	dev_t.
 */
static struct dv_node *
dv_clone_mknod(struct dv_node *ddv, char *drvname)
{
	major_t			major;
	struct dv_node		*dvp;
	char			*devnm;
	struct ddi_minor_data	*dmd;

	/*
	 * Make sure drvname is a STREAMS driver. We load the driver,
	 * but don't attach to any instances. This makes stat(2)
	 * relatively cheap.
	 */
	major = ddi_name_to_major(drvname);
	if (major == DDI_MAJOR_T_NONE)
		return (NULL);

	if (ddi_hold_driver(major) == NULL)
		return (NULL);

	if (STREAMSTAB(major) == NULL) {
		ddi_rele_driver(major);
		return (NULL);
	}

	ddi_rele_driver(major);
	devnm = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	(void) snprintf(devnm, MAXNAMELEN, "clone@0:%s", drvname);
	dmd = kmem_zalloc(sizeof (*dmd), KM_SLEEP);
	dmd->ddm_dev = makedevice(clone_major, (minor_t)major);
	dmd->ddm_spec_type = S_IFCHR;
	dvp = dv_mknod(ddv, clone_dip, devnm, dmd);
	kmem_free(dmd, sizeof (*dmd));
	kmem_free(devnm, MAXNAMELEN);
	return (dvp);
}

/*
 * Given the parent directory node, and a name in it, returns the
 * named dv_node to the caller (as a vnode).
 *
 * (We need pnp and rdir for doing shadow lookups; they can be NULL)
 */
int
dv_find(struct dv_node *ddv, char *nm, struct vnode **vpp, struct pathname *pnp,
	struct vnode *rdir, struct cred *cred, uint_t ndi_flags)
{
	extern int isminiroot;	/* see modctl.c */

	int			circ;
	int			rv = 0, was_busy = 0, nmlen, write_held = 0;
	struct vnode		*vp;
	struct dv_node		*dv, *dup;
	dev_info_t		*pdevi, *devi = NULL;
	char			*mnm;
	struct ddi_minor_data	*dmd;

	dcmn_err3(("dv_find %s\n", nm));

	if (!rw_tryenter(&ddv->dv_contents, RW_READER)) {
		if (tsd_get(devfs_clean_key))
			return (EBUSY);
		rw_enter(&ddv->dv_contents, RW_READER);
	}
start:
	if (DV_STALE(ddv)) {
		rw_exit(&ddv->dv_contents);
		return (ESTALE);
	}

	/*
	 * Empty name or ., return node itself.
	 */
	nmlen = strlen(nm);
	if ((nmlen == 0) || ((nmlen == 1) && (nm[0] == '.'))) {
		*vpp = DVTOV(ddv);
		rw_exit(&ddv->dv_contents);
		VN_HOLD(*vpp);
		return (0);
	}

	/*
	 * .., return the parent directory
	 */
	if ((nmlen == 2) && (strcmp(nm, "..") == 0)) {
		*vpp = DVTOV(ddv->dv_dotdot);
		rw_exit(&ddv->dv_contents);
		VN_HOLD(*vpp);
		return (0);
	}

	/*
	 * Fail anything without a valid device name component
	 */
	if (nm[0] == '@' || nm[0] == ':') {
		dcmn_err3(("devfs: no driver '%s'\n", nm));
		rw_exit(&ddv->dv_contents);
		return (ENOENT);
	}

	/*
	 * So, now we have to deal with the trickier stuff.
	 *
	 * (a) search the existing list of dv_nodes on this directory
	 */
	if ((dv = dv_findbyname(ddv, nm)) != NULL) {
founddv:
		ASSERT(RW_LOCK_HELD(&ddv->dv_contents));

		if (!rw_tryenter(&dv->dv_contents, RW_READER)) {
			if (tsd_get(devfs_clean_key)) {
				VN_RELE(DVTOV(dv));
				rw_exit(&ddv->dv_contents);
				return (EBUSY);
			}
			rw_enter(&dv->dv_contents, RW_READER);
		}

		vp = DVTOV(dv);
		if ((dv->dv_attrvp != NULLVP) ||
		    (vp->v_type != VDIR && dv->dv_attr != NULL)) {
			/*
			 * Common case - we already have attributes
			 */
			rw_exit(&dv->dv_contents);
			rw_exit(&ddv->dv_contents);
			goto found;
		}

		/*
		 * No attribute vp, try and build one.
		 *
		 * dv_shadow_node() can briefly drop &dv->dv_contents lock
		 * if it is unable to upgrade it to a write lock. If the
		 * current thread has come in through the bottom-up device
		 * configuration devfs_clean() path, we may deadlock against
		 * a thread performing top-down device configuration if it
		 * grabs the contents lock. To avoid this, when we are on the
		 * devfs_clean() path we attempt to upgrade the dv_contents
		 * lock before we call dv_shadow_node().
		 */
		if (tsd_get(devfs_clean_key)) {
			if (!rw_tryupgrade(&dv->dv_contents)) {
				VN_RELE(DVTOV(dv));
				rw_exit(&dv->dv_contents);
				rw_exit(&ddv->dv_contents);
				return (EBUSY);
			}

			write_held = DV_SHADOW_WRITE_HELD;
		}

		dv_shadow_node(DVTOV(ddv), nm, vp, pnp, rdir, cred,
		    write_held);

		rw_exit(&dv->dv_contents);
		rw_exit(&ddv->dv_contents);
		goto found;
	}

	/*
	 * (b) Search the child devinfo nodes of our parent directory,
	 * looking for the named node.  If we find it, build a new
	 * node, then grab the writers lock, search the directory
	 * if it's still not there, then insert it.
	 *
	 * We drop the devfs locks before accessing the device tree.
	 * Take care to mark the node BUSY so that a forced devfs_clean
	 * doesn't mark the directory node stale.
	 *
	 * Also, check if we are called as part of devfs_clean or
	 * reset_perm. If so, simply return not found because there
	 * is nothing to clean.
	 */
	if (tsd_get(devfs_clean_key)) {
		rw_exit(&ddv->dv_contents);
		return (ENOENT);
	}

	/*
	 * We could be either READ or WRITE locked at
	 * this point. Upgrade if we are read locked.
	 */
	ASSERT(RW_LOCK_HELD(&ddv->dv_contents));
	if (rw_read_locked(&ddv->dv_contents) &&
	    !rw_tryupgrade(&ddv->dv_contents)) {
		rw_exit(&ddv->dv_contents);
		rw_enter(&ddv->dv_contents, RW_WRITER);
		/*
		 * Things may have changed when we dropped
		 * the contents lock, so start from top again
		 */
		goto start;
	}
	ddv->dv_busy++;		/* mark busy before dropping lock */
	was_busy++;
	rw_exit(&ddv->dv_contents);

	pdevi = ddv->dv_devi;
	ASSERT(pdevi != NULL);

	mnm = strchr(nm, ':');
	if (mnm)
		*mnm = (char)0;

	/*
	 * Configure one nexus child, will call nexus's bus_ops
	 * If successful, devi is held upon returning.
	 * Note: devfs lookup should not be configuring grandchildren.
	 */
	ASSERT((ndi_flags & NDI_CONFIG) == 0);

	rv = ndi_devi_config_one(pdevi, nm, &devi, ndi_flags | NDI_NO_EVENT);
	if (mnm)
		*mnm = ':';
	if (rv != NDI_SUCCESS) {
		rv = ENOENT;
		goto notfound;
	}

	ASSERT(devi);

	/* Check if this is a path alias */
	if (ddi_aliases_present == B_TRUE && ddi_get_parent(devi) != pdevi) {
		char *curr = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		(void) ddi_pathname(devi, curr);

		vp = NULL;
		if (devfs_lookupname(curr, NULL, &vp) == 0 && vp) {
			dv = VTODV(vp);
			kmem_free(curr, MAXPATHLEN);
			goto found;
		}
		kmem_free(curr, MAXPATHLEN);
	}

	/*
	 * If we configured a hidden node, consider it notfound.
	 */
	if (ndi_dev_is_hidden_node(devi)) {
		ndi_rele_devi(devi);
		rv = ENOENT;
		goto notfound;
	}

	/*
	 * Don't make vhci clients visible under phci, unless we
	 * are in miniroot.
	 */
	if (isminiroot == 0 && ddi_get_parent(devi) != pdevi) {
		ndi_rele_devi(devi);
		rv = ENOENT;
		goto notfound;
	}

	ASSERT(devi && i_ddi_devi_attached(devi));

	/*
	 * Invalidate cache to notice newly created minor nodes.
	 */
	rw_enter(&ddv->dv_contents, RW_WRITER);
	ddv->dv_flags |= DV_BUILD;
	rw_exit(&ddv->dv_contents);

	/*
	 * mkdir for nexus drivers and leaf nodes as well.  If we are racing
	 * and create a duplicate, the duplicate will be destroyed below.
	 */
	if (mnm == NULL) {
		dv = dv_mkdir(ddv, devi, nm);
	} else {
		/*
		 * Allocate dmd first to avoid KM_SLEEP with active
		 * ndi_devi_enter.
		 */
		dmd = kmem_zalloc(sizeof (*dmd), KM_SLEEP);
		ndi_devi_enter(devi, &circ);
		if (devi == clone_dip) {
			/*
			 * For clone minors, load the driver indicated by
			 * minor name.
			 */
			dv = dv_clone_mknod(ddv, mnm + 1);
		} else {
			/*
			 * Find minor node and make a dv_node
			 */
			if (dv_find_leafnode(devi, mnm + 1, dmd) == 0) {
				dv = dv_mknod(ddv, devi, nm, dmd);
				if (dmd->ddm_node_priv)
					dpfree(dmd->ddm_node_priv);
			}
		}
		ndi_devi_exit(devi, circ);
		kmem_free(dmd, sizeof (*dmd));
	}
	/*
	 * Release hold from ndi_devi_config_one()
	 */
	ndi_rele_devi(devi);

	if (dv == NULL) {
		rv = ENOENT;
		goto notfound;
	}

	/*
	 * We have released the dv_contents lock, need to check
	 * if another thread already created a duplicate node
	 */
	rw_enter(&ddv->dv_contents, RW_WRITER);
	if ((dup = dv_findbyname(ddv, nm)) == NULL) {
		dv_insert(ddv, dv);
	} else {
		/*
		 * Duplicate found, use the existing node
		 */
		VN_RELE(DVTOV(dv));
		dv_destroy(dv, 0);
		dv = dup;
	}
	goto founddv;
	/*NOTREACHED*/

found:
	/*
	 * Fail lookup of device that has now become hidden (typically via
	 * hot removal of open device).
	 */
	if (dv->dv_devi && ndi_dev_is_hidden_node(dv->dv_devi)) {
		dcmn_err2(("dv_find: nm %s failed: hidden/removed\n", nm));
		VN_RELE(vp);
		rv = ENOENT;
		goto notfound;
	}

	/*
	 * Skip non-kernel lookups of internal nodes.
	 * This use of kcred to distinguish between user and
	 * internal kernel lookups is unfortunate.  The information
	 * provided by the seg argument to lookupnameat should
	 * evolve into a lookup flag for filesystems that need
	 * this distinction.
	 */
	if ((dv->dv_flags & DV_INTERNAL) && (cred != kcred)) {
		dcmn_err2(("dv_find: nm %s failed: internal\n", nm));
		VN_RELE(vp);
		rv = ENOENT;
		goto notfound;
	}

	dcmn_err2(("dv_find: returning vp for nm %s\n", nm));
	if (vp->v_type == VCHR || vp->v_type == VBLK) {
		/*
		 * If vnode is a device, return special vnode instead
		 * (though it knows all about -us- via sp->s_realvp,
		 * sp->s_devvp, and sp->s_dip)
		 */
		*vpp = specvp_devfs(vp, vp->v_rdev, vp->v_type, cred,
		    dv->dv_devi);
		VN_RELE(vp);
		if (*vpp == NULLVP)
			rv = ENOSYS;
	} else
		*vpp = vp;

notfound:
	if (was_busy) {
		/*
		 * Non-zero was_busy tells us that we are not in the
		 * devfs_clean() path which in turn means that we can afford
		 * to take the contents lock unconditionally.
		 */
		rw_enter(&ddv->dv_contents, RW_WRITER);
		ddv->dv_busy--;
		rw_exit(&ddv->dv_contents);
	}
	return (rv);
}

/*
 * The given directory node is out-of-date; that is, it has been
 * marked as needing to be rebuilt, possibly because some new devinfo
 * node has come into existence, or possibly because this is the first
 * time we've been here.
 */
void
dv_filldir(struct dv_node *ddv)
{
	struct dv_node		*dv;
	dev_info_t		*devi, *pdevi;
	struct ddi_minor_data	*dmd;
	char			devnm[MAXNAMELEN];
	int			circ, ccirc;

	ASSERT(DVTOV(ddv)->v_type == VDIR);
	ASSERT(RW_WRITE_HELD(&ddv->dv_contents));
	ASSERT(ddv->dv_flags & DV_BUILD);

	dcmn_err3(("dv_filldir: %s\n", ddv->dv_name));
	if (DV_STALE(ddv))
		return;
	pdevi = ddv->dv_devi;

	if (ndi_devi_config(pdevi, NDI_NO_EVENT) != NDI_SUCCESS) {
		dcmn_err3(("dv_filldir: config error %s\n", ddv->dv_name));
	}

	ndi_devi_enter(pdevi, &circ);
	for (devi = ddi_get_child(pdevi); devi;
	    devi = ddi_get_next_sibling(devi)) {
		/*
		 * While we know enough to create a directory at DS_INITIALIZED,
		 * the directory will be empty until DS_ATTACHED. The existence
		 * of an empty directory dv_node will cause a devi_ref, which
		 * has caused problems for existing code paths doing offline/DR
		 * type operations - making devfs_clean coordination even more
		 * sensitive and error prone. Given this, the 'continue' below
		 * is checking for DS_ATTACHED instead of DS_INITIALIZED.
		 */
		if (i_ddi_node_state(devi) < DS_ATTACHED)
			continue;

		/* skip hidden nodes */
		if (ndi_dev_is_hidden_node(devi))
			continue;

		dcmn_err3(("dv_filldir: node %s\n", ddi_node_name(devi)));

		ndi_devi_enter(devi, &ccirc);
		for (dmd = DEVI(devi)->devi_minor; dmd; dmd = dmd->next) {
			char *addr;

			/*
			 * Skip alias nodes, internal nodes, and nodes
			 * without a name.  We allow DDM_DEFAULT nodes
			 * to appear in readdir.
			 */
			if ((dmd->type == DDM_ALIAS) ||
			    (dmd->type == DDM_INTERNAL_PATH) ||
			    (dmd->ddm_name == NULL))
				continue;

			addr = ddi_get_name_addr(devi);
			if (addr && *addr)
				(void) sprintf(devnm, "%s@%s:%s",
				    ddi_node_name(devi), addr, dmd->ddm_name);
			else
				(void) sprintf(devnm, "%s:%s",
				    ddi_node_name(devi), dmd->ddm_name);

			if ((dv = dv_findbyname(ddv, devnm)) != NULL) {
				/* dv_node already exists */
				VN_RELE(DVTOV(dv));
				continue;
			}

			dv = dv_mknod(ddv, devi, devnm, dmd);
			dv_insert(ddv, dv);
			VN_RELE(DVTOV(dv));
		}
		ndi_devi_exit(devi, ccirc);

		(void) ddi_deviname(devi, devnm);
		if ((dv = dv_findbyname(ddv, devnm + 1)) == NULL) {
			/* directory doesn't exist */
			dv = dv_mkdir(ddv, devi, devnm + 1);
			dv_insert(ddv, dv);
		}
		VN_RELE(DVTOV(dv));
	}
	ndi_devi_exit(pdevi, circ);

	ddv->dv_flags &= ~DV_BUILD;
}

/*
 * Given a directory node, clean out all the nodes beneath.
 *
 * VDIR:	Reinvoke to clean them, then delete the directory.
 * VCHR, VBLK:	Just blow them away.
 *
 * Mark the directories touched as in need of a rebuild, in case
 * we fall over part way through. When DV_CLEAN_FORCE is specified,
 * we mark referenced empty directories as stale to facilitate DR.
 */
int
dv_cleandir(struct dv_node *ddv, char *devnm, uint_t flags)
{
	struct dv_node	*dv;
	struct dv_node	*next;
	struct vnode	*vp;
	int		busy = 0;

	/*
	 * We should always be holding the tsd_clean_key here: dv_cleandir()
	 * will be called as a result of a devfs_clean request and the
	 * tsd_clean_key will be set in either in devfs_clean() itself or in
	 * devfs_clean_vhci().
	 *
	 * Since we are on the devfs_clean path, we return EBUSY if we cannot
	 * get the contents lock: if we blocked here we might deadlock against
	 * a thread performing top-down device configuration.
	 */
	ASSERT(tsd_get(devfs_clean_key));

	dcmn_err3(("dv_cleandir: %s\n", ddv->dv_name));

	if (!(flags & DV_CLEANDIR_LCK) &&
	    !rw_tryenter(&ddv->dv_contents, RW_WRITER))
		return (EBUSY);

	for (dv = DV_FIRST_ENTRY(ddv); dv; dv = next) {
		next = DV_NEXT_ENTRY(ddv, dv);

		/*
		 * If devnm is specified, the non-minor portion of the
		 * name must match devnm.
		 */
		if (devnm &&
		    (strncmp(devnm, dv->dv_name, strlen(devnm)) ||
		    (dv->dv_name[strlen(devnm)] != ':' &&
		    dv->dv_name[strlen(devnm)] != '\0')))
			continue;

		/* check type of what we are cleaning */
		vp = DVTOV(dv);
		if (vp->v_type == VDIR) {
			/* recurse on directories */
			rw_enter(&dv->dv_contents, RW_WRITER);
			if (dv_cleandir(dv, NULL,
			    flags | DV_CLEANDIR_LCK) == EBUSY) {
				rw_exit(&dv->dv_contents);
				goto set_busy;
			}

			/* A clean directory is an empty directory... */
			ASSERT(dv->dv_nlink == 2);
			mutex_enter(&vp->v_lock);
			if (vp->v_count > 0) {
				/*
				 * ... but an empty directory can still have
				 * references to it. If we have dv_busy or
				 * DV_CLEAN_FORCE is *not* specified then a
				 * referenced directory is considered busy.
				 */
				if (dv->dv_busy || !(flags & DV_CLEAN_FORCE)) {
					mutex_exit(&vp->v_lock);
					rw_exit(&dv->dv_contents);
					goto set_busy;
				}

				/*
				 * Mark referenced directory stale so that DR
				 * will succeed even if a shell has
				 * /devices/xxx as current directory (causing
				 * VN_HOLD reference to an empty directory).
				 */
				ASSERT(!DV_STALE(dv));
				ndi_rele_devi(dv->dv_devi);
				dv->dv_devi = NULL;	/* mark DV_STALE */
			}
		} else {
			ASSERT((vp->v_type == VCHR) || (vp->v_type == VBLK));
			ASSERT(dv->dv_nlink == 1);	/* no hard links */
			mutex_enter(&vp->v_lock);
			if (vp->v_count > 0) {
				mutex_exit(&vp->v_lock);
				goto set_busy;
			}
		}

		/* unlink from directory */
		dv_unlink(ddv, dv);

		/* drop locks */
		mutex_exit(&vp->v_lock);
		if (vp->v_type == VDIR)
			rw_exit(&dv->dv_contents);

		/* destroy vnode if ref count is zero */
		if (vp->v_count == 0)
			dv_destroy(dv, flags);

		continue;

		/*
		 * If devnm is not NULL we return immediately on busy,
		 * otherwise we continue destroying unused dv_node's.
		 */
set_busy:	busy++;
		if (devnm)
			break;
	}

	/*
	 * This code may be invoked to inform devfs that a new node has
	 * been created in the kernel device tree. So we always set
	 * the DV_BUILD flag to allow the next dv_filldir() to pick
	 * the new devinfo nodes.
	 */
	ddv->dv_flags |= DV_BUILD;

	if (!(flags & DV_CLEANDIR_LCK))
		rw_exit(&ddv->dv_contents);

	return (busy ? EBUSY : 0);
}

/*
 * Walk through the devfs hierarchy, correcting the permissions of
 * devices with default permissions that do not match those specified
 * by minor perm.  This can only be done for all drivers for now.
 */
static int
dv_reset_perm_dir(struct dv_node *ddv, uint_t flags)
{
	struct dv_node	*dv;
	struct vnode	*vp;
	int		retval = 0;
	struct vattr	*attrp;
	mperm_t		mp;
	char		*nm;
	uid_t		old_uid;
	gid_t		old_gid;
	mode_t		old_mode;

	rw_enter(&ddv->dv_contents, RW_WRITER);
	for (dv = DV_FIRST_ENTRY(ddv); dv; dv = DV_NEXT_ENTRY(ddv, dv)) {
		int error = 0;
		nm = dv->dv_name;

		rw_enter(&dv->dv_contents, RW_READER);
		vp = DVTOV(dv);
		if (vp->v_type == VDIR) {
			rw_exit(&dv->dv_contents);
			if (dv_reset_perm_dir(dv, flags) != 0) {
				error = EBUSY;
			}
		} else {
			ASSERT(vp->v_type == VCHR || vp->v_type == VBLK);

			/*
			 * Check for permissions from minor_perm
			 * If there are none, we're done
			 */
			rw_exit(&dv->dv_contents);
			if (dev_minorperm(dv->dv_devi, nm, &mp) != 0)
				continue;

			rw_enter(&dv->dv_contents, RW_READER);

			/*
			 * Allow a node's permissions to be altered
			 * permanently from the defaults by chmod,
			 * using the shadow node as backing store.
			 * Otherwise, update node to minor_perm permissions.
			 */
			if (dv->dv_attrvp == NULLVP) {
				/*
				 * No attribute vp, try to find one.
				 */
				dv_shadow_node(DVTOV(ddv), nm, vp,
				    NULL, NULLVP, kcred, 0);
			}
			if (dv->dv_attrvp != NULLVP || dv->dv_attr == NULL) {
				rw_exit(&dv->dv_contents);
				continue;
			}

			attrp = dv->dv_attr;

			if (VATTRP_MP_CMP(attrp, mp) == 0) {
				dcmn_err5(("%s: no perm change: "
				    "%d %d 0%o\n", nm, attrp->va_uid,
				    attrp->va_gid, attrp->va_mode));
				rw_exit(&dv->dv_contents);
				continue;
			}

			old_uid = attrp->va_uid;
			old_gid = attrp->va_gid;
			old_mode = attrp->va_mode;

			VATTRP_MP_MERGE(attrp, mp);
			mutex_enter(&vp->v_lock);
			if (vp->v_count > 0) {
				error = EBUSY;
			}
			mutex_exit(&vp->v_lock);

			dcmn_err5(("%s: perm %d/%d/0%o -> %d/%d/0%o (%d)\n",
			    nm, old_uid, old_gid, old_mode, attrp->va_uid,
			    attrp->va_gid, attrp->va_mode, error));

			rw_exit(&dv->dv_contents);
		}

		if (error != 0) {
			retval = error;
		}
	}

	ddv->dv_flags |= DV_BUILD;

	rw_exit(&ddv->dv_contents);

	return (retval);
}

int
devfs_reset_perm(uint_t flags)
{
	struct dv_node	*dvp;
	int		rval;

	if ((dvp = devfs_dip_to_dvnode(ddi_root_node())) == NULL)
		return (0);

	VN_HOLD(DVTOV(dvp));
	rval = dv_reset_perm_dir(dvp, flags);
	VN_RELE(DVTOV(dvp));
	return (rval);
}

/*
 * Clean up dangling devfs shadow nodes for removed
 * drivers so that, in the event the driver is re-added
 * to the system, newly created nodes won't incorrectly
 * pick up these stale shadow node permissions.
 *
 * This is accomplished by walking down the pathname
 * to the directory, starting at the root's attribute
 * node, then removing all minors matching the specified
 * node name.  Care must be taken to remove all entries
 * in a directory before the directory itself, so that
 * the clean-up associated with rem_drv'ing a nexus driver
 * does not inadvertently result in an inconsistent
 * filesystem underlying devfs.
 */

static int
devfs_remdrv_rmdir(vnode_t *dirvp, const char *dir, vnode_t *rvp)
{
	int		error;
	vnode_t		*vp;
	int		eof;
	struct iovec	iov;
	struct uio	uio;
	struct dirent64	*dp;
	dirent64_t	*dbuf;
	size_t		dlen;
	size_t		dbuflen;
	int		ndirents = 64;
	char		*nm;

	VN_HOLD(dirvp);

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

		(void) VOP_RWLOCK(dirvp, V_WRITELOCK_FALSE, NULL);
		error = VOP_READDIR(dirvp, &uio, kcred, &eof, NULL, 0);
		VOP_RWUNLOCK(dirvp, V_WRITELOCK_FALSE, NULL);

		dbuflen = dlen - uio.uio_resid;

		if (error || dbuflen == 0)
			break;

		for (dp = dbuf; ((intptr_t)dp < (intptr_t)dbuf + dbuflen);
		    dp = (dirent64_t *)((intptr_t)dp + dp->d_reclen)) {

			nm = dp->d_name;

			if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0)
				continue;

			error = VOP_LOOKUP(dirvp, nm,
			    &vp, NULL, 0, NULL, kcred, NULL, NULL, NULL);

			dsysdebug(error,
			    ("rem_drv %s/%s lookup (%d)\n",
			    dir, nm, error));

			if (error)
				continue;

			ASSERT(vp->v_type == VDIR ||
			    vp->v_type == VCHR || vp->v_type == VBLK);

			if (vp->v_type == VDIR) {
				error = devfs_remdrv_rmdir(vp, nm, rvp);
				if (error == 0) {
					error = VOP_RMDIR(dirvp,
					    (char *)nm, rvp, kcred, NULL, 0);
					dsysdebug(error,
					    ("rem_drv %s/%s rmdir (%d)\n",
					    dir, nm, error));
				}
			} else {
				error = VOP_REMOVE(dirvp, (char *)nm, kcred,
				    NULL, 0);
				dsysdebug(error,
				    ("rem_drv %s/%s remove (%d)\n",
				    dir, nm, error));
			}

			VN_RELE(vp);
			if (error) {
				goto exit;
			}
		}
	}

exit:
	VN_RELE(dirvp);
	kmem_free(dbuf, dlen);

	return (error);
}

int
devfs_remdrv_cleanup(const char *dir, const char *nodename)
{
	int		error;
	vnode_t		*vp;
	vnode_t		*dirvp;
	int		eof;
	struct iovec	iov;
	struct uio	uio;
	struct dirent64	*dp;
	dirent64_t	*dbuf;
	size_t		dlen;
	size_t		dbuflen;
	int		ndirents = 64;
	int		nodenamelen = strlen(nodename);
	char		*nm;
	struct pathname	pn;
	vnode_t		*rvp;	/* root node of the underlying attribute fs */

	dcmn_err5(("devfs_remdrv_cleanup: %s %s\n", dir, nodename));

	if (error = pn_get((char *)dir, UIO_SYSSPACE, &pn))
		return (0);

	rvp = dvroot->dv_attrvp;
	ASSERT(rvp != NULL);
	VN_HOLD(rvp);

	pn_skipslash(&pn);
	dirvp = rvp;
	VN_HOLD(dirvp);

	nm = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	while (pn_pathleft(&pn)) {
		ASSERT(dirvp->v_type == VDIR);
		(void) pn_getcomponent(&pn, nm);
		ASSERT((strcmp(nm, ".") != 0) && (strcmp(nm, "..") != 0));
		error = VOP_LOOKUP(dirvp, nm, &vp, NULL, 0, rvp, kcred,
		    NULL, NULL, NULL);
		if (error) {
			dcmn_err5(("remdrv_cleanup %s lookup error %d\n",
			    nm, error));
			VN_RELE(dirvp);
			if (dirvp != rvp)
				VN_RELE(rvp);
			pn_free(&pn);
			kmem_free(nm, MAXNAMELEN);
			return (0);
		}
		VN_RELE(dirvp);
		dirvp = vp;
		pn_skipslash(&pn);
	}

	ASSERT(dirvp->v_type == VDIR);
	if (dirvp != rvp)
		VN_RELE(rvp);
	pn_free(&pn);
	kmem_free(nm, MAXNAMELEN);

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

		(void) VOP_RWLOCK(dirvp, V_WRITELOCK_FALSE, NULL);
		error = VOP_READDIR(dirvp, &uio, kcred, &eof, NULL, 0);
		VOP_RWUNLOCK(dirvp, V_WRITELOCK_FALSE, NULL);

		dbuflen = dlen - uio.uio_resid;

		if (error || dbuflen == 0)
			break;

		for (dp = dbuf; ((intptr_t)dp < (intptr_t)dbuf + dbuflen);
		    dp = (dirent64_t *)((intptr_t)dp + dp->d_reclen)) {

			nm = dp->d_name;

			if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0)
				continue;

			if (strncmp(nm, nodename, nodenamelen) != 0)
				continue;

			error = VOP_LOOKUP(dirvp, nm, &vp,
			    NULL, 0, NULL, kcred, NULL, NULL, NULL);

			dsysdebug(error,
			    ("rem_drv %s/%s lookup (%d)\n",
			    dir, nm, error));

			if (error)
				continue;

			ASSERT(vp->v_type == VDIR ||
			    vp->v_type == VCHR || vp->v_type == VBLK);

			if (vp->v_type == VDIR) {
				error = devfs_remdrv_rmdir(vp, nm, rvp);
				if (error == 0) {
					error = VOP_RMDIR(dirvp, (char *)nm,
					    rvp, kcred, NULL, 0);
					dsysdebug(error,
					    ("rem_drv %s/%s rmdir (%d)\n",
					    dir, nm, error));
				}
			} else {
				error = VOP_REMOVE(dirvp, (char *)nm, kcred,
				    NULL, 0);
				dsysdebug(error,
				    ("rem_drv %s/%s remove (%d)\n",
				    dir, nm, error));
			}

			VN_RELE(vp);
			if (error)
				goto exit;
		}
	}

exit:
	VN_RELE(dirvp);

	kmem_free(dbuf, dlen);

	return (0);
}

struct dv_list {
	struct dv_node	*dv;
	struct dv_list	*next;
};

void
dv_walk(
	struct dv_node	*ddv,
	char		*devnm,
	void		(*callback)(struct dv_node *, void *),
	void		*arg)
{
	struct vnode	*dvp;
	struct dv_node	*dv;
	struct dv_list	*head, *tail, *next;
	int		len;

	dcmn_err3(("dv_walk: ddv = %s, devnm = %s\n",
	    ddv->dv_name, devnm ? devnm : "<null>"));

	dvp = DVTOV(ddv);

	ASSERT(dvp->v_type == VDIR);

	head = tail = next = NULL;

	rw_enter(&ddv->dv_contents, RW_READER);
	mutex_enter(&dvp->v_lock);
	for (dv = DV_FIRST_ENTRY(ddv); dv; dv = DV_NEXT_ENTRY(ddv, dv)) {
		/*
		 * If devnm is not NULL and is not the empty string,
		 * select only dv_nodes with matching non-minor name
		 */
		if (devnm && (len = strlen(devnm)) &&
		    (strncmp(devnm, dv->dv_name, len) ||
		    (dv->dv_name[len] != ':' && dv->dv_name[len] != '\0')))
			continue;

		callback(dv, arg);

		if (DVTOV(dv)->v_type != VDIR)
			continue;

		next = kmem_zalloc(sizeof (*next), KM_SLEEP);
		next->dv = dv;

		if (tail)
			tail->next = next;
		else
			head = next;

		tail = next;
	}

	while (head) {
		dv_walk(head->dv, NULL, callback, arg);
		next = head->next;
		kmem_free(head, sizeof (*head));
		head = next;
	}
	rw_exit(&ddv->dv_contents);
	mutex_exit(&dvp->v_lock);
}
