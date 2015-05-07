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
 * Copyright 2015 Joyent, Inc.
 */

#ifndef	_LXSYSFS_H
#define	_LXSYSFS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * lx_sysfs.h: declarations, data structures and macros for lx_sysfs
 */


#include <sys/types.h>
#include <sys/param.h>
#include <sys/policy.h>
#include <sys/debug.h>
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/pathname.h>
#include <sys/systm.h>
#include <sys/var.h>
#include <sys/user.h>
#include <sys/t_lock.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/priv.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/cmn_err.h>
#include <sys/zone.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/dnlc.h>
#include <sys/atomic.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <vm/as.h>
#include <vm/anon.h>

/*
 * Convert a vnode into an lxsys_mnt_t
 */
#define	VTOLXSM(vp)	((lxsys_mnt_t *)(vp)->v_vfsp->vfs_data)

/*
 * convert a vnode into an lxsys_node
 */
#define	VTOLXS(vp)	((lxsys_node_t *)(vp)->v_data)

/*
 * convert a lxsys_node into a vnode
 */
#define	LXSTOV(lxsnp)	((lxsnp)->lxsys_vnode)

/*
 * convert a lxsys_node into zone for fs
 */
#define	LXSTOZ(lxsnp) \
	(((lxsys_mnt_t *)(lxsnp)->lxsys_vnode->v_vfsp->vfs_data)->lxsysm_zone)

#define	LXSNSIZ		256	/* max size of lx /sys file name entries */

/*
 * Pretend that a directory entry takes 16 bytes
 */
#define	LXSYS_SDSIZE	16

/*
 * Node/file types for lx /sys files
 * (directories and files contained therein).
 */
typedef enum lxsys_nodetype {
	LXSYS_SYSDIR,		/* /sys			*/
	LXSYS_FSDIR,		/* /sys/fs		*/
	LXSYS_FS_CGROUPDIR,	/* /sys/fs/cgroup	*/
	LXSYS_NFILES		/* number of lx /sys file types */
} lxsys_nodetype_t;

/*
 * external dirent characteristics
 */
typedef struct {
	lxsys_nodetype_t	d_type;
	char			*d_name;
} lxsys_dirent_t;

/*
 * This is the lx sysfs private data object
 * which is attached to v_data in the vnode structure
 */
typedef struct lxsys_node {
	lxsys_nodetype_t lxsys_type;	/* type of this node 		*/
	vnode_t		*lxsys_vnode;	/* vnode for the node		*/
	vnode_t		*lxsys_parent;	/* parent directory		*/
	vnode_t		*lxsys_realvp;	/* real vnode, file in dirs	*/
	timestruc_t	lxsys_time;	/* creation etc time for file	*/
	mode_t		lxsys_mode;	/* file mode bits		*/
	uid_t		lxsys_uid;	/* file owner			*/
	gid_t		lxsys_gid;	/* file group owner		*/
	ino_t		lxsys_ino;	/* node id 			*/
} lxsys_node_t;

struct zone;    /* forward declaration */

/*
 * This is the lxsysfs private data object
 * which is attached to vfs_data in the vfs structure
 */
typedef struct lxsys_mnt {
	lxsys_node_t	*lxsysm_node;	/* node at root of sys mount */
	struct zone	*lxsysm_zone;	/* zone for this mount */
} lxsys_mnt_t;

extern vnodeops_t	*lxsys_vnodeops;

typedef struct mounta	mounta_t;

extern void lxsys_initnodecache();
extern void lxsys_fininodecache();
extern ino_t lxsys_inode(lxsys_nodetype_t);
extern ino_t lxsys_parentinode(lxsys_node_t *);
extern lxsys_node_t *lxsys_getnode(vnode_t *, lxsys_nodetype_t, proc_t *);
extern void lxsys_freenode(lxsys_node_t *);

#ifdef	__cplusplus
}
#endif

#ifndef islower
#define	islower(x)	(((unsigned)(x) >= 'a') && ((unsigned)(x) <= 'z'))
#endif
#ifndef toupper
#define	toupper(x)	(islower(x) ? (x) - 'a' + 'A' : (x))
#endif

#endif /* _LXSYSFS_H */
