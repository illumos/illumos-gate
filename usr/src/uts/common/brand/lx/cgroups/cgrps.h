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

#ifndef	_LXCGRPS_H
#define	_LXCGRPS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * cgrps.h: declarations, data structures and macros for lx_cgroup
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/policy.h>
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/pathname.h>
#include <sys/systm.h>
#include <sys/var.h>
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
#include <sys/atomic.h>
#include <vm/anon.h>

/*
 * cgrpmgr ioctl interface.
 */
#define	CGRPFS_IOC	('C' << 16 | 'G' << 8)
#define	CGRPFS_GETEVNT	(CGRPFS_IOC | 1)

typedef struct cgrpmgr_info {
	pid_t	cgmi_pid;
	char	*cgmi_rel_agent_path;
	char	*cgmi_cgroup_path;
} cgrpmgr_info_t;

#if defined(_KERNEL)

#include <sys/lx_brand.h>

typedef struct cgrpmgr_info32 {
	pid_t		cgmi_pid;
	caddr32_t	cgmi_rel_agent_path;
	caddr32_t	cgmi_cgroup_path;
} cgrpmgr_info32_t;

#define	CG_PSNSIZE	256	/* max size of pseudo file name entries */
#define	CG_PSDSIZE	16	/* pretend that a dir entry takes 16 bytes */

/*
 * The order of these entries must be in sync with the cg_ssde_dir array.
 */
typedef enum cgrp_ssid {
	CG_SSID_GENERIC = 1,
	CG_SSID_NUM		/* last ssid for range checking */
} cgrp_ssid_t;

typedef enum cgrp_nodetype {
	CG_CGROUP_DIR = 1,	/* cgroup directory entry */
	CG_NOTIFY,		/* notify_on_release file */
	CG_PROCS,		/* cgroup.procs file */
	CG_REL_AGENT,		/* release_agent file */
	CG_TASKS,		/* tasks file */
} cgrp_nodetype_t;

typedef struct cgrp_subsys_dirent {
	cgrp_nodetype_t cgrp_ssd_type;
	char		*cgrp_ssd_name;
} cgrp_subsys_dirent_t;

#define	N_DIRENTS(m)	(cgrp_num_pseudo_ents((m)->cg_ssid) + 2)

/*
 * A modern systemd-based Linux system typically has 50-60 cgroups so
 * we size the hash for 2x that number.
 */
#define	CGRP_HASH_SZ	128
#define	CGRP_AGENT_LEN	(MAXPATHLEN + 1)

/*
 * cgroups per-mount data structure.
 *
 * All but the event related fields are protected by cg_contents.
 * The evnt_list and counter is protected by cg_events.
 */
typedef struct cgrp_mnt {
	struct vfs	*cg_vfsp;	/* filesystem's vfs struct */
	struct cgrp_node *cg_rootnode;	/* root cgrp_node */
	char 		*cg_mntpath;	/* name of cgroup mount point */
	cgrp_ssid_t	cg_ssid;	/* subsystem type */
	dev_t		cg_dev;		/* unique dev # of mounted `device' */
	uint_t		cg_gen;		/* node ID source for files */
	uint_t		cg_grp_gen;	/* ID source for cgroups */
	kmutex_t	cg_contents;	/* global lock for most fs activity */
	char		cg_agent[CGRP_AGENT_LEN]; /* release_agent path */
	/* ptr to zone data for containing zone */
	lx_zone_data_t	*cg_lxzdata;
	struct cgrp_node **cg_grp_hash;	/* hash list of cgroups in the fs */
} cgrp_mnt_t;

/*
 * cgrp_node is the file system dependent node for cgroups.
 *
 * The node is used to represent both directories (a cgroup) and pseudo files
 * within the directory.
 *
 * Members are tagged in the comment to note which type of node they apply to:
 * A - all
 * D - dir (i.e. a cgroup)
 * F - pseudo file
 */

typedef struct cgrp_node {
	struct cgrp_node	*cgn_back;	/* A lnked lst of cgrp_nodes */
	struct cgrp_node	*cgn_forw;	/* A lnked lst of cgrp_nodes */
	struct cgrp_dirent	*cgn_dir;	/* D dirent list */
	struct cgrp_node	*cgn_parent;	/* A dir containing this node */
	struct cgrp_node	*cgn_next;	/* D link in per-mount cgroup */
						/*   hash table */
	uint_t			cgn_dirents;	/* D number of dirents */
	cgrp_nodetype_t		cgn_type;	/* A type for this node */
	uint_t			cgn_notify;	/* D notify_on_release value */
	uint_t			cgn_task_cnt;	/* D number of threads in grp */
	struct vnode 		*cgn_vnode;	/* A vnode for this cgrp_node */
	uint_t 			cgn_id;		/* D ID number for the cgroup */
	struct vattr		cgn_attr;	/* A attributes */
} cgrp_node_t;

/*
 * File system independent to cgroups conversion macros
 */
#define	VFSTOCGM(vfsp)		((cgrp_mnt_t *)(vfsp)->vfs_data)
#define	VTOCGM(vp)		((cgrp_mnt_t *)(vp)->v_vfsp->vfs_data)
#define	VTOCGN(vp)		((struct cgrp_node *)(vp)->v_data)
#define	CGNTOV(cn)		((cn)->cgn_vnode)
#define	cgnode_hold(cn)		VN_HOLD(CGNTOV(cn))
#define	cgnode_rele(cn)		VN_RELE(CGNTOV(cn))

/*
 * Attributes
 */
#define	cgn_mask	cgn_attr.va_mask
#define	cgn_mode	cgn_attr.va_mode
#define	cgn_uid		cgn_attr.va_uid
#define	cgn_gid		cgn_attr.va_gid
#define	cgn_fsid	cgn_attr.va_fsid
#define	cgn_nodeid	cgn_attr.va_nodeid
#define	cgn_nlink	cgn_attr.va_nlink
#define	cgn_size	cgn_attr.va_size
#define	cgn_atime	cgn_attr.va_atime
#define	cgn_mtime	cgn_attr.va_mtime
#define	cgn_ctime	cgn_attr.va_ctime
#define	cgn_rdev	cgn_attr.va_rdev
#define	cgn_blksize	cgn_attr.va_blksize
#define	cgn_nblocks	cgn_attr.va_nblocks
#define	cgn_seq		cgn_attr.va_seq

/*
 * cgroup directories are made up of a linked list of cg_dirent structures
 * hanging off directory cgrp_nodes.  File names are not fixed length,
 * but are null terminated.
 */
typedef struct cgrp_dirent {
	struct cgrp_node	*cgd_cgrp_node;	/* cg node for this file */
	struct cgrp_dirent	*cgd_next;	/* next directory entry */
	struct cgrp_dirent	*cgd_prev;	/* prev directory entry */
	uint_t			cgd_offset;	/* "offset" of dir entry */
	uint_t			cgd_hash;	/* a hash of cgd_name */
	struct cgrp_dirent	*cgd_link;	/* linked via hash table */
	struct cgrp_node	*cgd_parent;	/* parent, dir we are in */
	char			*cgd_name;	/* null terminated */
} cgrp_dirent_t;

enum de_op	{ DE_CREATE, DE_MKDIR, DE_RENAME };	/* direnter ops */
enum dr_op	{ DR_REMOVE, DR_RMDIR, DR_RENAME };	/* dirremove ops */

extern struct vnodeops *cgrp_vnodeops;

int cgrp_dirdelete(cgrp_node_t *, cgrp_node_t *, char *, enum dr_op, cred_t *);
int cgrp_direnter(cgrp_mnt_t *, cgrp_node_t *, char *, enum de_op,
    cgrp_node_t *, struct vattr *, cgrp_node_t **, cred_t *);
void cgrp_dirinit(cgrp_node_t *, cgrp_node_t *, cred_t *);
int cgrp_dirlookup(cgrp_node_t *, char *, cgrp_node_t **, cred_t *);
void cgrp_dirtrunc(cgrp_node_t *);
void cgrp_node_init(cgrp_mnt_t *, cgrp_node_t *, vattr_t *, cred_t *);
int cgrp_taccess(void *, int, cred_t *);
ino_t cgrp_inode(cgrp_nodetype_t, unsigned int);
int cgrp_num_pseudo_ents(cgrp_ssid_t);
cgrp_node_t *cgrp_cg_hash_lookup(cgrp_mnt_t *, uint_t);
void cgrp_rel_agent_event(cgrp_mnt_t *, cgrp_node_t *);

#endif /* KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _LXCGRPS_H */
