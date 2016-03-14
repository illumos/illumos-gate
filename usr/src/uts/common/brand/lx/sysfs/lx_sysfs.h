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
 * Copyright 2016 Joyent, Inc.
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
#include <sys/netstack.h>
#include <inet/ip.h>
#include <inet/ip_if.h>

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

/* Root sysfs lxsys_instance */
#define	LXSYS_INST_ROOT	0

/*
 * Node/file types for lx /sys files
 * (directories and files contained therein).
 */
typedef enum lxsys_nodetype {
	LXSYS_NONE,		/* None-type to keep inodes non-zero	*/
	LXSYS_STATIC,		/* Statically defined entries		*/
	LXSYS_CLASS_NET,	/* /sys/class/net/<iface>		*/
	LXSYS_DEV_NET,		/* /sys/devices/virtual/net/<iface>	*/
	LXSYS_BLOCK,		/* /sys/block/<dev>			*/
	LXSYS_DEV_ZFS,		/* /sys/devices/zfs/<dev>		*/
	LXSYS_DEV_SYS_CPU,	/* /sys/devices/system/cpu/<cpu>	*/
	LXSYS_DEV_SYS_CPUINFO,	/* /sys/devices/system/cpu/cpuN/<info>	*/
	LXSYS_DEV_SYS_NODE,	/* /sys/devices/system/node/node0/<info> */
	LXSYS_MAXTYPE,		/* type limit				*/
} lxsys_nodetype_t;

/*
 * external dirent characteristics
 */
typedef struct {
	unsigned int	d_idnum;
	char		*d_name;
} lxsys_dirent_t;

typedef struct {
	unsigned int	dl_instance;
	lxsys_dirent_t	*dl_list;
	int		dl_length;
} lxsys_dirlookup_t;

/*
 * This is the lx sysfs private data object
 * which is attached to v_data in the vnode structure
 */
struct lxsys_node;
typedef struct lxsys_node lxsys_node_t;
struct lxsys_node {
	lxsys_nodetype_t	lxsys_type;	/* type ID of node 	*/
	unsigned int		lxsys_instance;	/* instance ID node	*/
	unsigned int		lxsys_endpoint;	/* endpoint ID node	*/
	vnode_t			*lxsys_vnode;	/* vnode for the node	*/
	vnode_t			*lxsys_parentvp; /* parent directory	*/
	lxsys_node_t		*lxsys_next;	/* next list entry	*/
	timestruc_t		lxsys_time;	/* creation time	*/
	mode_t			lxsys_mode;	/* file mode bits	*/
	uid_t			lxsys_uid;	/* file owner		*/
	gid_t			lxsys_gid;	/* file group owner	*/
	ino_t			lxsys_ino;	/* node id		*/
};

/*
 * This is the lxsysfs private data object
 * which is attached to vfs_data in the vfs structure
 */
typedef struct lxsys_mnt {
	kmutex_t	lxsysm_lock;	/* protects fields		*/
	lxsys_node_t	*lxsysm_node;	/* node at root of sys mount	*/
	zone_t		*lxsysm_zone;	/* zone for this mount		*/
} lxsys_mnt_t;

extern vnodeops_t	*lxsys_vnodeops;

typedef struct mounta	mounta_t;

extern void lxsys_initnodecache();
extern void lxsys_fininodecache();
extern ino_t lxsys_inode(lxsys_nodetype_t, unsigned int, unsigned int);
extern ino_t lxsys_parentinode(lxsys_node_t *);
extern lxsys_node_t *lxsys_getnode(vnode_t *, lxsys_nodetype_t, unsigned int,
    unsigned int);
extern lxsys_node_t *lxsys_getnode_static(vnode_t *, unsigned int);
extern void lxsys_freenode(lxsys_node_t *);

extern netstack_t *lxsys_netstack(lxsys_node_t *);
extern ill_t *lxsys_find_ill(ip_stack_t *, uint_t);

typedef struct lxpr_uiobuf {
	uio_t *uiop;
	char *buffer;
	uint32_t bufsize;
	char *pos;
	size_t beg;
	int error;
} lxsys_uiobuf_t;

extern lxsys_uiobuf_t *lxsys_uiobuf_new(uio_t *);
extern void lxsys_uiobuf_free(lxsys_uiobuf_t *);
extern void lxsys_uiobuf_seterr(lxsys_uiobuf_t *, int);
extern int lxsys_uiobuf_flush(lxsys_uiobuf_t *);
extern void lxsys_uiobuf_write(lxsys_uiobuf_t *, const char *, size_t);
extern void lxsys_uiobuf_printf(lxsys_uiobuf_t *uiobuf, const char *fmt, ...);

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
