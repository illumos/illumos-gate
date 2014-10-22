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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_FS_AUTOFS_H
#define	_SYS_FS_AUTOFS_H

#include <rpc/clnt.h>
#include <gssapi/gssapi.h>
#include <sys/vfs.h>
#include <sys/dirent.h>
#include <sys/types.h>
#include <sys/types32.h>
#include <sys/note.h>
#include <sys/time_impl.h>
#include <sys/mntent.h>
#include <nfs/mount.h>
#include <rpc/rpcsec_gss.h>
#include <sys/zone.h>
#include <sys/door.h>
#include <rpcsvc/autofs_prot.h>

#ifdef _KERNEL
#include <sys/vfs_opreg.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif


#ifdef	_KERNEL


/*
 * Tracing macro; expands to nothing for non-debug kernels.
 */
#ifndef DEBUG
#define	AUTOFS_DPRINT(x)
#else
#define	AUTOFS_DPRINT(x)	auto_dprint x
#endif

/*
 * Per AUTOFS mountpoint information.
 */
typedef struct fninfo {
	struct vfs	*fi_mountvfs;		/* mounted-here VFS */
	struct vnode	*fi_rootvp;		/* root vnode */
	struct knetconfig fi_knconf;		/* netconfig */
	struct netbuf	fi_addr;		/* daemon address */
	char		*fi_path;		/* autofs mountpoint */
	char 		*fi_map;		/* context/map-name */
	char		*fi_subdir;		/* subdir within map */
	char		*fi_key;		/* key to use on direct maps */
	char		*fi_opts;		/* default mount options */
	int		fi_pathlen;		/* autofs mountpoint len */
	int		fi_maplen;		/* size of context */
	int		fi_subdirlen;
	int		fi_keylen;
	int		fi_optslen;		/* default mount options len */
	int		fi_refcnt;		/* reference count */
	int		fi_flags;
	int		fi_mount_to;
	int		fi_rpc_to;
	zoneid_t	fi_zoneid;		/* zone mounted in */
} fninfo_t;

/*
 * The AUTOFS locking scheme:
 *
 * The locks:
 * 	fn_lock: protects the fn_node. It must be grabbed to change any
 *		 field on the fn_node, except for those protected by
 *		 fn_rwlock.
 *
 * 	fn_rwlock: readers/writers lock to protect the subdirectory and
 *		   top level list traversal.
 *		   Protects: fn_dirents
 *			     fn_next
 *		             fn_size
 *		             fn_linkcnt
 *                 - Grab readers when checking if certain fn_node exists
 *                   under fn_dirents.
 *		   - Grab readers when attempting to reference a node
 *                   pointed to by fn_dirents, fn_next, and fn_parent.
 *                 - Grab writers to add a new fnnode under fn_dirents and
 *		     to remove a node pointed to by fn_dirents or fn_next.
 *
 *	Lock ordering:
 *		fn_rwlock > fn_lock
 *
 * The flags:
 *	MF_INPROG:
 *		- Indicates a mount request has been sent to the daemon.
 *		- If this flag is set, the thread sets MF_WAITING on the
 *                fnnode and sleeps.
 *
 *	MF_WAITING:
 *		- Set by a thread when it puts itself to sleep waiting for
 *		  the ongoing operation on this fnnode to be done.
 *
 * 	MF_LOOKUP:
 * 		- Indicates a lookup request has been sent to the daemon.
 *		- If this flag is set, the thread sets MF_WAITING on the
 *                fnnode and sleeps.
 *
 *	MF_IK_MOUNT:
 *		- This flag is set to indicate the mount was done in the
 *		  kernel, and so should the unmount.
 *
 *	MF_DIRECT:
 *		- Direct mountpoint if set, indirect otherwise.
 *
 *	MF_TRIGGER:
 *		- This is a trigger node.
 *
 *	MF_THISUID_MATCH_RQD:
 *		- User-relative context binding kind of node.
 *		- Node with this flag set requires a name match as well
 *		  as a cred match in order to be returned from the directory
 *		  hierarchy.
 *
 * 	MF_MOUNTPOINT:
 * 		- At some point automountd mounted a filesystem on this node.
 * 		If fn_trigger is non-NULL, v_vfsmountedhere is NULL and this
 * 		flag is set then the filesystem must have been forcibly
 * 		unmounted.
 */

/*
 * The inode of AUTOFS
 */
typedef struct fnnode {
	char		*fn_name;
	char		*fn_symlink;		/* if VLNK, this is what it */
						/* points to */
	int		fn_namelen;
	int		fn_symlinklen;
	uint_t		fn_linkcnt;		/* link count */
	mode_t		fn_mode;		/* file mode bits */
	uid_t		fn_uid;			/* owner's uid */
	gid_t		fn_gid;			/* group's uid */
	int		fn_error;		/* mount/lookup error */
	ino_t		fn_nodeid;
	off_t		fn_offset;		/* offset into directory */
	int		fn_flags;
	uint_t		fn_size;		/* size of directory */
	struct vnode	*fn_vnode;
	struct fnnode	*fn_parent;
	struct fnnode	*fn_next;		/* sibling */
	struct fnnode	*fn_dirents;		/* children */
	struct fnnode	*fn_trigger; 		/* pointer to next level */
						/* AUTOFS trigger nodes */
	struct action_list *fn_alp;		/* Pointer to mount info */
						/* used for remounting */
						/* trigger nodes */
	cred_t		*fn_cred;		/* pointer to cred, used for */
						/* "thisuser" processing */
	krwlock_t	fn_rwlock;		/* protects list traversal */
	kmutex_t	fn_lock;		/* protects the fnnode */
	timestruc_t	fn_atime;
	timestruc_t	fn_mtime;
	timestruc_t	fn_ctime;
	time_t		fn_ref_time;		/* time last referenced */
	time_t		fn_unmount_ref_time;	/* last time unmount was done */
	kcondvar_t	fn_cv_mount;		/* mount blocking variable */
	struct vnode	*fn_seen;		/* vnode already traversed */
	kthread_t	*fn_thread;		/* thread that has currently */
						/* modified fn_seen */
	struct autofs_globals *fn_globals;	/* global variables */
} fnnode_t;


#define	vntofn(vp)	((struct fnnode *)((vp)->v_data))
#define	fntovn(fnp)	(((fnp)->fn_vnode))
#define	vfstofni(vfsp)	((struct fninfo *)((vfsp)->vfs_data))

#define	MF_DIRECT	0x001
#define	MF_INPROG	0x002		/* Mount in progress */
#define	MF_WAITING	0x004
#define	MF_LOOKUP	0x008		/* Lookup in progress */
#define	MF_ATTR_WAIT	0x010
#define	MF_IK_MOUNT	0x040
#define	MF_TRIGGER	0x080
#define	MF_THISUID_MATCH_RQD	0x100	/* UID match required for this node */
					/* required for thisuser kind of */
					/* nodes */
#define	MF_MOUNTPOINT	0x200		/* Node is/was a mount point */

#define	AUTOFS_MODE		0555
#define	AUTOFS_BLOCKSIZE	1024

struct autofs_callargs {
	fnnode_t	*fnc_fnp;	/* fnnode */
	char		*fnc_name;	/* path to lookup/mount */
	kthread_t	*fnc_origin;	/* thread that fired up this thread */
					/* used for debugging purposes */
	cred_t		*fnc_cred;
};

struct autofs_globals {
	fnnode_t		*fng_rootfnnodep;
	int			fng_fnnode_count;
	int			fng_printed_not_running_msg;
	kmutex_t		fng_unmount_threads_lock;
	int			fng_unmount_threads;
	int			fng_verbose;
	zoneid_t		fng_zoneid;
	pid_t			fng_autofs_pid;
	kmutex_t		fng_autofs_daemon_lock;
	/*
	 * autofs_daemon_lock protects fng_autofs_daemon_dh
	 */
	door_handle_t		fng_autofs_daemon_dh;
};

extern kmutex_t autofs_minor_lock;
extern zone_key_t autofs_key;

/*
 * Sets the MF_INPROG flag on this fnnode.
 * fnp->fn_lock should be held before this macro is called,
 * operation is either MF_INPROG or MF_LOOKUP.
 */
#define	AUTOFS_BLOCK_OTHERS(fnp, operation)	{ \
	ASSERT(MUTEX_HELD(&(fnp)->fn_lock)); \
	ASSERT(!((fnp)->fn_flags & operation)); \
	(fnp)->fn_flags |= (operation); \
}

#define	AUTOFS_UNBLOCK_OTHERS(fnp, operation)	{ \
	auto_unblock_others((fnp), (operation)); \
}

extern struct vnodeops *auto_vnodeops;
extern const struct fs_operation_def auto_vnodeops_template[];

/*
 * Utility routines
 */
extern int auto_search(fnnode_t *, char *, fnnode_t **, cred_t *);
extern int auto_enter(fnnode_t *, char *, fnnode_t **, cred_t *);
extern void auto_unblock_others(fnnode_t *, uint_t);
extern int auto_wait4mount(fnnode_t *);
extern fnnode_t *auto_makefnnode(vtype_t, vfs_t *, char *, cred_t *,
    struct autofs_globals *);
extern void auto_freefnnode(fnnode_t *);
extern void auto_disconnect(fnnode_t *, fnnode_t *);
extern void auto_do_unmount(struct autofs_globals *);
/*PRINTFLIKE4*/
extern void auto_log(int verbose, zoneid_t zoneid, int level,
	const char *fmt, ...)
    __KPRINTFLIKE(4);
/*PRINTFLIKE2*/
extern void auto_dprint(int level, const char *fmt, ...)
    __KPRINTFLIKE(2);
extern int auto_calldaemon(zoneid_t, int, xdrproc_t, void *, xdrproc_t,
	void *, int, bool_t);
extern int auto_lookup_aux(fnnode_t *, char *, cred_t *);
extern void auto_new_mount_thread(fnnode_t *, char *, cred_t *);
extern int auto_nobrowse_option(char *);

extern int unmount_subtree(fnnode_t *, boolean_t);
extern void unmount_tree(struct autofs_globals *, boolean_t);
extern void autofs_free_globals(struct autofs_globals *);
extern void autofs_shutdown_zone(struct autofs_globals *);

#endif	/* _KERNEL */

/*
 * autofs structures and defines needed for use with doors.
 */
#define	AUTOFS_NULL	0
#define	AUTOFS_MOUNT	1
#define	AUTOFS_UNMOUNT	2
#define	AUTOFS_READDIR	3
#define	AUTOFS_LOOKUP	4
#define	AUTOFS_SRVINFO	5
#define	AUTOFS_MNTINFO	6

/*
 * autofs_door_args is a generic structure used to grab the command
 * from any of the argument structures passed in.
 */

typedef struct {
	int cmd;
	int xdr_len;
	char xdr_arg[1];	/* buffer holding xdr encoded data */
} autofs_door_args_t;


typedef struct {
	int res_status;
	int xdr_len;
	char xdr_res[1];	/* buffer holding xdr encoded data */
} autofs_door_res_t;

typedef enum autofs_res autofs_res_t;
typedef enum autofs_stat autofs_stat_t;
typedef enum autofs_action autofs_action_t;

typedef struct {
	void *	atsd_buf;
	size_t	atsd_len;
} autofs_tsd_t;

typedef struct sec_desdata {
	int		nd_sec_syncaddr_len;
	int		nd_sec_knc_semantics;
	int		nd_sec_netnamelen;
	uint64_t	nd_sec_knc_rdev;
	int		nd_sec_knc_unused[8];
} sec_desdata_t;

typedef struct sec_gssdata {
	int			element_length;
	rpc_gss_service_t	service;
	char			uname[MAX_NAME_LEN];
	char			inst[MAX_NAME_LEN];
	char			realm[MAX_NAME_LEN];
	uint_t			qop;
} sec_gssdata_t;

typedef struct nfs_secdata  {
	sec_desdata_t	nfs_des_clntdata;
	sec_gssdata_t	nfs_gss_clntdata;
} nfs_secdata_t;

/*
 * Comma separated list of mntoptions which are inherited when the
 * "restrict" option is present.  The RESTRICT option must be first!
 * This define is shared between the kernel and the automount daemon.
 */
#define	RESTRICTED_MNTOPTS	\
	MNTOPT_RESTRICT, MNTOPT_NOSUID, MNTOPT_NOSETUID, MNTOPT_NODEVICES

/*
 * AUTOFS syscall entry point
 */
enum autofssys_op { AUTOFS_UNMOUNTALL, AUTOFS_SETDOOR };

#ifdef	_KERNEL
extern int autofssys(enum autofssys_op, uintptr_t);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_AUTOFS_H */
