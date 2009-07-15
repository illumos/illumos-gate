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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_DV_NODE_H
#define	_SYS_DV_NODE_H

/*
 * dv_nodes are the file-system specific part of the
 * vnodes for the device filesystem.
 *
 * The device filesystem exports two node types:
 *
 * VDIR	nodes		to represent nexus drivers
 * VCHR & VBLK nodes	to represent devices
 */

#include <sys/dirent.h>
#include <sys/sunddi.h>
#include <sys/devops.h>
#include <sys/ddi_impldefs.h>
#include <sys/fs/sdev_impl.h>
#include <sys/devpolicy.h>
#include <sys/avl.h>

#ifdef _KERNEL
#include <sys/vfs_opreg.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL


/*
 * Here's the focal point of this filesystem
 */
typedef struct dv_node {
	char		*dv_name;	/* pointer to name */
	size_t		dv_namelen;	/* strlen(dv_name) */
	struct vnode	*dv_vnode;	/* vnode for this dv_node */

	/*
	 * The dv_contents lock should be held (read) before looking at
	 * any of the fields below, and held (write) before modifying them.
	 */
	krwlock_t	dv_contents;	/* held while anything is changing */

	dev_info_t	*dv_devi;	/* VDIR: underlying devinfo node */
					/* has ndi_devi_hold on device */

	struct dv_node	*dv_dotdot;	/* parent: my parent dv_node */
	avl_tree_t	dv_entries;	/* VDIR: contents as avl tree */
	avl_node_t	dv_avllink;	/* avl node linkage */

	struct vnode	*dv_attrvp;	/* persistent attribute store */
	struct vattr	*dv_attr;	/* attributes not yet persistent */

	ino64_t		dv_ino;		/* fake inode */
	int		dv_flags;	/* state bits and stuff */
	uint_t		dv_nlink;	/* link count */
	uint_t		dv_busy;	/* directory busy count */
	devplcy_t	*dv_priv;	/* access privilege */
	mode_t		dv_dflt_mode;	/* create_priv_minor_node mode */
	struct sdev_dv	*dv_sdev;	/* sdev node[s] if exists */
} dvnode_t;

#define	DV_BUILD	0x1		/* directory out-of-date */
#define	DV_NO_FSPERM	0x2		/* ignore fs permissions */
#define	DV_INTERNAL	0x04		/* internal node */
#define	DV_ACL		0x08		/* node has acl */
#define	DV_DFLT_MODE	0x010		/* dv_dflt_mode set */

#define	DV_ROOTINO	((ino_t)2)	/* root inode no. for devfs */

#define	DVTOV(n)	((struct vnode *)(n)->dv_vnode)
#define	VTODV(vp)	((struct dv_node *)(vp)->v_data)
#define	DV_STALE(dv)	(dv->dv_devi == NULL)

#define	DV_UID_DEFAULT	0	/* default uid for devs and dirs */
#define	DV_GID_DEFAULT	3	/* default gid for devs and dirs */
#define	DV_DIRMODE_DEFAULT	(S_IFDIR | 0755)	/* directories */
#define	DV_DEVMODE_DEFAULT	(0600)			/* special files */
#define	DV_DEVMODE_PRIV		(0666)		/* priv based access only */

/* flags for devfs_clean() */
#define	DV_CLEAN_FORCE	0x01	/* force clean of refed directories */
#define	DV_RESET_PERM	0x02	/* force resetting of node permission */
#define	DV_CLEANDIR_LCK	0x04	/* dv_contents already held */

struct devfs_data {
	struct	dv_node	*devfs_root;
	struct	vfs	*devfs_vfsp;
};

#define	VFSTODVFS(vfsp)	((struct devfs_data *)((vfsp)->vfs_data))

/* dv_fid overlays the fid structure (for VFS_VGET) */
struct dv_fid {
	uint16_t	dvfid_len;
	ino32_t		dvfid_ino;
	int32_t		dvfid_gen;
};

/*
 * Compare a vattr's and mperm_t's minor permissions (uid, gid & mode)
 */
#define	VATTRP_MP_CMP(attrp, mp)				\
	(!((attrp->va_uid == mp.mp_uid) &&			\
	(attrp->va_gid == mp.mp_gid) &&				\
	((attrp->va_mode & S_IAMB) == (mp.mp_mode & S_IAMB))))

/*
 * Merge an mperm_t's minor permissions into a vattr
 */
#define	VATTR_MP_MERGE(attr, mp)				\
	attr.va_uid = mp.mp_uid;				\
	attr.va_gid = mp.mp_gid;				\
	attr.va_mode = 						\
	    (attr.va_mode & ~S_IAMB) | (mp.mp_mode & S_IAMB);

#define	VATTRP_MP_MERGE(attrp, mp)				\
	attrp->va_uid = mp.mp_uid;				\
	attrp->va_gid = mp.mp_gid;				\
	attrp->va_mode = 					\
	    (attrp->va_mode & ~S_IAMB) | (mp.mp_mode & S_IAMB);

/*
 * dv_shadow_node flags
 */
#define	DV_SHADOW_CREATE	0x01		/* create attribute node */
#define	DV_SHADOW_WRITE_HELD	0x02		/* dv_contents write held */

/*
 * Directory tree traversal
 */
#define	DV_FIRST_ENTRY(ddv)	avl_first(&(ddv)->dv_entries)
#define	DV_NEXT_ENTRY(ddv, dv)	AVL_NEXT(&(ddv)->dv_entries, (dv))

extern uint_t devfs_clean_key;	/* tsd key */
extern const char dvnm[];	/* share some space.. */
extern struct dv_node *dvroot;	/* devfs root node */

extern void dv_node_cache_init(void);
extern void dv_node_cache_fini(void);
extern struct dv_node *dv_mkdir(struct dv_node *, dev_info_t *, char *);
extern struct dv_node *dv_mkroot(struct vfs *, dev_t);
extern void dv_destroy(struct dv_node *, uint_t);
extern void dv_insert(struct dv_node *, struct dv_node *);
extern void dv_shadow_node(struct vnode *, char *nm, struct vnode *,
    struct pathname *, struct vnode *, struct cred *, int);
extern int dv_find(struct dv_node *, char *, struct vnode **,
    struct pathname *, struct vnode *, struct cred *, uint_t);
extern void dv_filldir(struct dv_node *);
extern int dv_cleandir(struct dv_node *, char *, uint_t);
extern void dv_vattr_merge(struct dv_node *, struct vattr *);
extern void dv_walk(struct dv_node *, char *,
    void (*f)(struct dv_node *, void *), void *);

extern int devfs_clean(dev_info_t *, char *, uint_t);
extern int devfs_lookupname(char *, vnode_t **, vnode_t **);
extern int devfs_walk(char *, void (*f)(struct dv_node *, void *), void *);
extern int devfs_devpolicy(vnode_t *, devplcy_t **);
extern void devfs_get_defattr(vnode_t *, struct vattr *, int *);

extern struct dv_node *devfs_dip_to_dvnode(dev_info_t *);
extern int devfs_reset_perm(uint_t);
extern int devfs_remdrv_cleanup(const char *, const char *);

extern struct vnodeops *dv_vnodeops;
extern const struct fs_operation_def dv_vnodeops_template[];


#ifdef DEBUG
extern int devfs_debug;
#define	DV_DEBUG	0x01
#define	DV_DEBUG2	0x02
#define	DV_DEBUG3	0x04
#define	DV_DEBUG4	0x08
#define	DV_DEBUG5	0x10
#define	DV_SYSERR	0x1000
#define	DV_SYSTRACE	0x2000
#define	dcmn_err(args) if (devfs_debug & DV_DEBUG) printf args
#define	dcmn_err2(args) if (devfs_debug & DV_DEBUG2) printf args
#define	dcmn_err3(args) if (devfs_debug & DV_DEBUG3) printf args
#define	dcmn_err4(args) if (devfs_debug & DV_DEBUG4) printf args
#define	dcmn_err5(args) if (devfs_debug & DV_DEBUG5) printf args

#define	dsysdebug(err, args)				\
	if ((err && (devfs_debug & DV_SYSERR)) ||	\
	    (devfs_debug & DV_SYSTRACE)) printf args
#else
#define	dcmn_err(args) /* nothing */
#define	dcmn_err2(args) /* nothing */
#define	dcmn_err3(args) /* nothing */
#define	dcmn_err4(args) /* nothing */
#define	dcmn_err5(args) /* nothing */
#define	dsysdebug(err, args) /* nothing */
#endif


#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_DV_NODE_H */
