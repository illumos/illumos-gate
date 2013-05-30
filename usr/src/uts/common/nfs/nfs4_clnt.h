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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef _NFS4_CLNT_H
#define	_NFS4_CLNT_H

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/kstat.h>
#include <sys/time.h>
#include <sys/flock.h>
#include <vm/page.h>
#include <nfs/nfs4_kprot.h>
#include <nfs/nfs4.h>
#include <nfs/rnode.h>
#include <sys/avl.h>
#include <sys/list.h>
#include <rpc/auth.h>
#include <sys/door.h>
#include <sys/condvar_impl.h>
#include <sys/zone.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	NFS4_SIZE_OK(size)	((size) <= MAXOFFSET_T)

/* Four states of nfs4_server's lease_valid */
#define	NFS4_LEASE_INVALID		0
#define	NFS4_LEASE_VALID		1
#define	NFS4_LEASE_UNINITIALIZED	2
#define	NFS4_LEASE_NOT_STARTED		3

/* flag to tell the renew thread it should exit */
#define	NFS4_THREAD_EXIT	1

/* Default number of seconds to wait on GRACE and DELAY errors */
#define	NFS4ERR_DELAY_TIME	10

/* Number of hash buckets for open owners for each nfs4_server */
#define	NFS4_NUM_OO_BUCKETS	53

/* Number of freed open owners (per mntinfo4_t) to keep around */
#define	NFS4_NUM_FREED_OPEN_OWNERS	8

/* Number of seconds to wait before retrying a SETCLIENTID(_CONFIRM) op */
#define	NFS4_RETRY_SCLID_DELAY	10

/* Number of times we should retry a SETCLIENTID(_CONFIRM) op */
#define	NFS4_NUM_SCLID_RETRIES	3

/* Number of times we should retry on open after getting NFS4ERR_BAD_SEQID */
#define	NFS4_NUM_RETRY_BAD_SEQID	3

/*
 * Macro to wakeup sleeping async worker threads.
 */
#define	NFS4_WAKE_ASYNC_WORKER(work_cv)	{				\
	if (CV_HAS_WAITERS(&work_cv[NFS4_ASYNC_QUEUE])) 		\
		cv_signal(&work_cv[NFS4_ASYNC_QUEUE]);			\
	else if (CV_HAS_WAITERS(&work_cv[NFS4_ASYNC_PGOPS_QUEUE])) 	\
		cv_signal(&work_cv[NFS4_ASYNC_PGOPS_QUEUE]);		\
}

#define	NFS4_WAKEALL_ASYNC_WORKERS(work_cv) {				\
		cv_broadcast(&work_cv[NFS4_ASYNC_QUEUE]);		\
		cv_broadcast(&work_cv[NFS4_ASYNC_PGOPS_QUEUE]);		\
}

/*
 * Is the attribute cache valid?  If client holds a delegation, then attrs
 * are by definition valid.  If not, then check to see if attrs have timed out.
 */
#define	ATTRCACHE4_VALID(vp) (VTOR4(vp)->r_deleg_type != OPEN_DELEGATE_NONE || \
	gethrtime() < VTOR4(vp)->r_time_attr_inval)

/*
 * Flags to indicate whether to purge the DNLC for non-directory vnodes
 * in a call to nfs_purge_caches.
 */
#define	NFS4_NOPURGE_DNLC	0
#define	NFS4_PURGE_DNLC		1

/*
 * Is cache valid?
 * Swap is always valid, if no attributes (attrtime == 0) or
 * if mtime matches cached mtime it is valid
 * NOTE: mtime is now a timestruc_t.
 * Caller should be holding the rnode r_statelock mutex.
 */
#define	CACHE4_VALID(rp, mtime, fsize)				\
	((RTOV4(rp)->v_flag & VISSWAP) == VISSWAP ||		\
	(((mtime).tv_sec == (rp)->r_attr.va_mtime.tv_sec &&	\
	(mtime).tv_nsec == (rp)->r_attr.va_mtime.tv_nsec) &&	\
	((fsize) == (rp)->r_attr.va_size)))

/*
 * Macro to detect forced unmount or a zone shutdown.
 */
#define	FS_OR_ZONE_GONE4(vfsp) \
	(((vfsp)->vfs_flag & VFS_UNMOUNTED) || \
	zone_status_get(curproc->p_zone) >= ZONE_IS_SHUTTING_DOWN)

/*
 * Macro to help determine whether a request failed because the underlying
 * filesystem has been forcibly unmounted or because of zone shutdown.
 */
#define	NFS4_FRC_UNMT_ERR(err, vfsp) \
	((err) == EIO && FS_OR_ZONE_GONE4((vfsp)))

/*
 * Due to the way the address space callbacks are used to execute a delmap,
 * we must keep track of how many times the same thread has called
 * VOP_DELMAP()->nfs4_delmap().  This is done by having a list of
 * nfs4_delmapcall_t's associated with each rnode4_t.  This list is protected
 * by the rnode4_t's r_statelock.  The individual elements do not need to be
 * protected as they will only ever be created, modified and destroyed by
 * one thread (the call_id).
 * See nfs4_delmap() for further explanation.
 */
typedef struct nfs4_delmapcall {
	kthread_t	*call_id;
	int		error;	/* error from delmap */
	list_node_t	call_node;
} nfs4_delmapcall_t;

/*
 * delmap address space callback args
 */
typedef struct nfs4_delmap_args {
	vnode_t			*vp;
	offset_t		off;
	caddr_t			addr;
	size_t			len;
	uint_t			prot;
	uint_t			maxprot;
	uint_t			flags;
	cred_t			*cr;
	nfs4_delmapcall_t	*caller; /* to retrieve errors from the cb */
} nfs4_delmap_args_t;

/*
 * client side statistics
 */
/*
 * Per-zone counters
 */
struct clstat4 {
	kstat_named_t	calls;			/* client requests */
	kstat_named_t	badcalls;		/* rpc failures */
	kstat_named_t	referrals;		/* referrals */
	kstat_named_t	referlinks;		/* referrals as symlinks */
	kstat_named_t	clgets;			/* client handle gets */
	kstat_named_t	cltoomany;		/* client handle cache misses */
#ifdef DEBUG
	kstat_named_t	clalloc;		/* number of client handles */
	kstat_named_t	noresponse;		/* server not responding cnt */
	kstat_named_t	failover;		/* server failover count */
	kstat_named_t	remap;			/* server remap count */
#endif
};

#ifdef DEBUG
/*
 * The following are statistics that describe the behavior of the system as a
 * whole and don't correspond to any particular zone.
 */
struct clstat4_debug {
	kstat_named_t	nrnode;			/* number of allocated rnodes */
	kstat_named_t	access;			/* size of access cache */
	kstat_named_t	dirent;			/* size of readdir cache */
	kstat_named_t	dirents;		/* size of readdir buf cache */
	kstat_named_t	reclaim;		/* number of reclaims */
	kstat_named_t	clreclaim;		/* number of cl reclaims */
	kstat_named_t	f_reclaim;		/* number of free reclaims */
	kstat_named_t	a_reclaim;		/* number of active reclaims */
	kstat_named_t	r_reclaim;		/* number of rnode reclaims */
	kstat_named_t	rpath;			/* bytes used to store rpaths */
};
extern struct clstat4_debug clstat4_debug;

#endif

/*
 * The NFS specific async_reqs structure. iotype4 is grouped to support two
 * types of async thread pools, please read comments section of mntinfo4_t
 * definition for more information. Care should be taken while adding new
 * members to this group.
 */

enum iotype4 {
	NFS4_PUTAPAGE,
	NFS4_PAGEIO,
	NFS4_COMMIT,
	NFS4_READ_AHEAD,
	NFS4_READDIR,
	NFS4_INACTIVE,
	NFS4_ASYNC_TYPES
};
#define	NFS4_ASYNC_PGOPS_TYPES	(NFS4_COMMIT + 1)

/*
 * NFS async requests queue type.
 */
enum ioqtype4 {
	NFS4_ASYNC_QUEUE,
	NFS4_ASYNC_PGOPS_QUEUE,
	NFS4_MAX_ASYNC_QUEUES
};

/*
 * Number of NFS async threads operating exclusively on page op requests.
 */
#define	NUM_ASYNC_PGOPS_THREADS	0x2

struct nfs4_async_read_req {
	void (*readahead)();		/* pointer to readahead function */
	u_offset_t blkoff;		/* offset in file */
	struct seg *seg;		/* segment to do i/o to */
	caddr_t addr;			/* address to do i/o to */
};

struct nfs4_pageio_req {
	int (*pageio)();		/* pointer to pageio function */
	page_t *pp;			/* page list */
	u_offset_t io_off;		/* offset in file */
	uint_t io_len;			/* size of request */
	int flags;
};

struct nfs4_readdir_req {
	int (*readdir)();		/* pointer to readdir function */
	struct rddir4_cache *rdc;	/* pointer to cache entry to fill */
};

struct nfs4_commit_req {
	void (*commit)();		/* pointer to commit function */
	page_t *plist;			/* page list */
	offset4 offset;			/* starting offset */
	count4 count;			/* size of range to be commited */
};

struct nfs4_async_reqs {
	struct nfs4_async_reqs *a_next;	/* pointer to next arg struct */
#ifdef DEBUG
	kthread_t *a_queuer;		/* thread id of queueing thread */
#endif
	struct vnode *a_vp;		/* vnode pointer */
	struct cred *a_cred;		/* cred pointer */
	enum iotype4 a_io;		/* i/o type */
	union {
		struct nfs4_async_read_req a_read_args;
		struct nfs4_pageio_req a_pageio_args;
		struct nfs4_readdir_req a_readdir_args;
		struct nfs4_commit_req a_commit_args;
	} a_args;
};

#define	a_nfs4_readahead a_args.a_read_args.readahead
#define	a_nfs4_blkoff a_args.a_read_args.blkoff
#define	a_nfs4_seg a_args.a_read_args.seg
#define	a_nfs4_addr a_args.a_read_args.addr

#define	a_nfs4_putapage a_args.a_pageio_args.pageio
#define	a_nfs4_pageio a_args.a_pageio_args.pageio
#define	a_nfs4_pp a_args.a_pageio_args.pp
#define	a_nfs4_off a_args.a_pageio_args.io_off
#define	a_nfs4_len a_args.a_pageio_args.io_len
#define	a_nfs4_flags a_args.a_pageio_args.flags

#define	a_nfs4_readdir a_args.a_readdir_args.readdir
#define	a_nfs4_rdc a_args.a_readdir_args.rdc

#define	a_nfs4_commit a_args.a_commit_args.commit
#define	a_nfs4_plist a_args.a_commit_args.plist
#define	a_nfs4_offset a_args.a_commit_args.offset
#define	a_nfs4_count a_args.a_commit_args.count

/*
 * Security information
 */
typedef struct sv_secinfo {
	uint_t		count;	/* how many sdata there are */
	uint_t		index;	/* which sdata[index] */
	struct sec_data	*sdata;
} sv_secinfo_t;

/*
 * Hash bucket for the mi's open owner list (mi_oo_list).
 */
typedef struct nfs4_oo_hash_bucket {
	list_t			b_oo_hash_list;
	kmutex_t		b_lock;
} nfs4_oo_hash_bucket_t;

/*
 * Global array of ctags.
 */
extern ctag_t nfs4_ctags[];

typedef enum nfs4_tag_type {
	TAG_NONE,
	TAG_ACCESS,
	TAG_CLOSE,
	TAG_CLOSE_LOST,
	TAG_CLOSE_UNDO,
	TAG_COMMIT,
	TAG_DELEGRETURN,
	TAG_FSINFO,
	TAG_GET_SYMLINK,
	TAG_GETATTR,
	TAG_GETATTR_FSLOCATION,
	TAG_INACTIVE,
	TAG_LINK,
	TAG_LOCK,
	TAG_LOCK_RECLAIM,
	TAG_LOCK_RESEND,
	TAG_LOCK_REINSTATE,
	TAG_LOCK_UNKNOWN,
	TAG_LOCKT,
	TAG_LOCKU,
	TAG_LOCKU_RESEND,
	TAG_LOCKU_REINSTATE,
	TAG_LOOKUP,
	TAG_LOOKUP_PARENT,
	TAG_LOOKUP_VALID,
	TAG_LOOKUP_VPARENT,
	TAG_MKDIR,
	TAG_MKNOD,
	TAG_MOUNT,
	TAG_OPEN,
	TAG_OPEN_CONFIRM,
	TAG_OPEN_CONFIRM_LOST,
	TAG_OPEN_DG,
	TAG_OPEN_DG_LOST,
	TAG_OPEN_LOST,
	TAG_OPENATTR,
	TAG_PATHCONF,
	TAG_PUTROOTFH,
	TAG_READ,
	TAG_READAHEAD,
	TAG_READDIR,
	TAG_READLINK,
	TAG_RELOCK,
	TAG_REMAP_LOOKUP,
	TAG_REMAP_LOOKUP_AD,
	TAG_REMAP_LOOKUP_NA,
	TAG_REMAP_MOUNT,
	TAG_RMDIR,
	TAG_REMOVE,
	TAG_RENAME,
	TAG_RENAME_VFH,
	TAG_RENEW,
	TAG_REOPEN,
	TAG_REOPEN_LOST,
	TAG_SECINFO,
	TAG_SETATTR,
	TAG_SETCLIENTID,
	TAG_SETCLIENTID_CF,
	TAG_SYMLINK,
	TAG_WRITE
} nfs4_tag_type_t;

#define	NFS4_TAG_INITIALIZER	{				\
		{TAG_NONE,		"",			\
			{0x20202020, 0x20202020, 0x20202020}},	\
		{TAG_ACCESS,		"access",		\
			{0x61636365, 0x73732020, 0x20202020}},	\
		{TAG_CLOSE,		"close",		\
			{0x636c6f73, 0x65202020, 0x20202020}},	\
		{TAG_CLOSE_LOST,	"lost close",		\
			{0x6c6f7374, 0x20636c6f, 0x73652020}},	\
		{TAG_CLOSE_UNDO,	"undo close",		\
			{0x756e646f, 0x20636c6f, 0x73652020}},	\
		{TAG_COMMIT,		"commit",		\
			{0x636f6d6d, 0x69742020, 0x20202020}},	\
		{TAG_DELEGRETURN,	"delegreturn",		\
			{0x64656c65, 0x67726574, 0x75726e20}},	\
		{TAG_FSINFO,		"fsinfo",		\
			{0x6673696e, 0x666f2020, 0x20202020}},	\
		{TAG_GET_SYMLINK,	"get symlink text",	\
			{0x67657420, 0x736c6e6b, 0x20747874}},	\
		{TAG_GETATTR,		"getattr",		\
			{0x67657461, 0x74747220, 0x20202020}},	\
		{TAG_GETATTR_FSLOCATION, "getattr fslocation",	\
			{0x67657461, 0x74747220, 0x66736c6f}},	\
		{TAG_INACTIVE,		"inactive",		\
			{0x696e6163, 0x74697665, 0x20202020}},	\
		{TAG_LINK,		"link",			\
			{0x6c696e6b, 0x20202020, 0x20202020}},	\
		{TAG_LOCK,		"lock",			\
			{0x6c6f636b, 0x20202020, 0x20202020}},	\
		{TAG_LOCK_RECLAIM,	"reclaim lock",		\
			{0x7265636c, 0x61696d20, 0x6c6f636b}},	\
		{TAG_LOCK_RESEND,	"resend lock",		\
			{0x72657365, 0x6e64206c, 0x6f636b20}},	\
		{TAG_LOCK_REINSTATE,	"reinstate lock",	\
			{0x7265696e, 0x7374206c, 0x6f636b20}},	\
		{TAG_LOCK_UNKNOWN,	"unknown lock",		\
			{0x756e6b6e, 0x6f776e20, 0x6c6f636b}},	\
		{TAG_LOCKT,		"lock test",		\
			{0x6c6f636b, 0x5f746573, 0x74202020}},	\
		{TAG_LOCKU,		"unlock",		\
			{0x756e6c6f, 0x636b2020, 0x20202020}},	\
		{TAG_LOCKU_RESEND,	"resend locku",		\
			{0x72657365, 0x6e64206c, 0x6f636b75}},	\
		{TAG_LOCKU_REINSTATE,	"reinstate unlock",	\
			{0x7265696e, 0x73742075, 0x6e6c636b}},	\
		{TAG_LOOKUP,		"lookup",		\
			{0x6c6f6f6b, 0x75702020, 0x20202020}},	\
		{TAG_LOOKUP_PARENT,	"lookup parent",	\
			{0x6c6f6f6b, 0x75702070, 0x6172656e}},	\
		{TAG_LOOKUP_VALID,	"lookup valid",		\
			{0x6c6f6f6b, 0x75702076, 0x616c6964}},	\
		{TAG_LOOKUP_VPARENT,	"lookup valid parent",	\
			{0x6c6f6f6b, 0x766c6420, 0x7061726e}},	\
		{TAG_MKDIR,		"mkdir",		\
			{0x6d6b6469, 0x72202020, 0x20202020}},	\
		{TAG_MKNOD,		"mknod",		\
			{0x6d6b6e6f, 0x64202020, 0x20202020}},	\
		{TAG_MOUNT,		"mount",		\
			{0x6d6f756e, 0x74202020, 0x20202020}},	\
		{TAG_OPEN,		"open",			\
			{0x6f70656e, 0x20202020, 0x20202020}},	\
		{TAG_OPEN_CONFIRM,	"open confirm",		\
			{0x6f70656e, 0x5f636f6e, 0x6669726d}},	\
		{TAG_OPEN_CONFIRM_LOST,	"lost open confirm",	\
			{0x6c6f7374, 0x206f7065, 0x6e5f636f}},	\
		{TAG_OPEN_DG,		"open downgrade",	\
			{0x6f70656e, 0x20646772, 0x61646520}},	\
		{TAG_OPEN_DG_LOST,	"lost open downgrade",	\
			{0x6c737420, 0x6f70656e, 0x20646772}},	\
		{TAG_OPEN_LOST,		"lost open",		\
			{0x6c6f7374, 0x206f7065, 0x6e202020}},	\
		{TAG_OPENATTR,		"openattr",		\
			{0x6f70656e, 0x61747472, 0x20202020}},	\
		{TAG_PATHCONF,		"pathconf",		\
			{0x70617468, 0x636f6e66, 0x20202020}},	\
		{TAG_PUTROOTFH,		"putrootfh",		\
			{0x70757472, 0x6f6f7466, 0x68202020}},	\
		{TAG_READ,		"read",			\
			{0x72656164, 0x20202020, 0x20202020}},	\
		{TAG_READAHEAD,		"readahead",		\
			{0x72656164, 0x61686561, 0x64202020}},	\
		{TAG_READDIR,		"readdir",		\
			{0x72656164, 0x64697220, 0x20202020}},	\
		{TAG_READLINK,		"readlink",		\
			{0x72656164, 0x6c696e6b, 0x20202020}},	\
		{TAG_RELOCK,		"relock",		\
			{0x72656c6f, 0x636b2020, 0x20202020}},	\
		{TAG_REMAP_LOOKUP,	"remap lookup",		\
			{0x72656d61, 0x70206c6f, 0x6f6b7570}},	\
		{TAG_REMAP_LOOKUP_AD,	"remap lookup attr dir",	\
			{0x72656d70, 0x206c6b75, 0x70206164}},	\
		{TAG_REMAP_LOOKUP_NA,	"remap lookup named attrs",	\
			{0x72656d70, 0x206c6b75, 0x70206e61}},	\
		{TAG_REMAP_MOUNT,	"remap mount",		\
			{0x72656d61, 0x70206d6f, 0x756e7420}},	\
		{TAG_RMDIR,		"rmdir",		\
			{0x726d6469, 0x72202020, 0x20202020}},	\
		{TAG_REMOVE,		"remove",		\
			{0x72656d6f, 0x76652020, 0x20202020}},	\
		{TAG_RENAME,		"rename",		\
			{0x72656e61, 0x6d652020, 0x20202020}},	\
		{TAG_RENAME_VFH,	"rename volatile fh",	\
			{0x72656e61, 0x6d652028, 0x76666829}},	\
		{TAG_RENEW,		"renew",		\
			{0x72656e65, 0x77202020, 0x20202020}},	\
		{TAG_REOPEN,		"reopen",		\
			{0x72656f70, 0x656e2020, 0x20202020}},	\
		{TAG_REOPEN_LOST,	"lost reopen",		\
			{0x6c6f7374, 0x2072656f, 0x70656e20}},	\
		{TAG_SECINFO,		"secinfo",		\
			{0x73656369, 0x6e666f20, 0x20202020}},	\
		{TAG_SETATTR,		"setattr",		\
			{0x73657461, 0x74747220, 0x20202020}},	\
		{TAG_SETCLIENTID,	"setclientid",		\
			{0x73657463, 0x6c69656e, 0x74696420}},	\
		{TAG_SETCLIENTID_CF,	"setclientid_confirm",	\
			{0x73636c6e, 0x7469645f, 0x636f6e66}},	\
		{TAG_SYMLINK,		"symlink",		\
			{0x73796d6c, 0x696e6b20, 0x20202020}},	\
		{TAG_WRITE,		"write",		\
			{0x77726974, 0x65202020, 0x20202020}}	\
	}

/*
 * These flags are for differentiating the search criterian for
 * find_open_owner().  The comparison is done with the open_owners's
 * 'oo_just_created' flag.
 */
#define	NFS4_PERM_CREATED	0x0
#define	NFS4_JUST_CREATED	0x1

/*
 * Hashed by the cr_uid and cr_ruid of credential 'oo_cred'. 'oo_cred_otw'
 * is stored upon a successful OPEN.  This is needed when the user's effective
 * and real uid's don't match.  The 'oo_cred_otw' overrides the credential
 * passed down by VFS for async read/write, commit, lock, and close operations.
 *
 * The oo_ref_count keeps track the number of active references on this
 * data structure + number of nfs4_open_streams point to this structure.
 *
 * 'oo_valid' tells whether this stuct is about to be freed or not.
 *
 * 'oo_just_created' tells us whether this struct has just been created but
 * not been fully finalized (that is created upon an OPEN request and
 * finalized upon the OPEN success).
 *
 * The 'oo_seqid_inuse' is for the open seqid synchronization.  If a thread
 * is currently using the open owner and it's open_seqid, then it sets the
 * oo_seqid_inuse to true if it currently is not set.  If it is set then it
 * does a cv_wait on the oo_cv_seqid_sync condition variable.  When the thread
 * is done it unsets the oo_seqid_inuse and does a cv_signal to wake a process
 * waiting on the condition variable.
 *
 * 'oo_last_good_seqid' is the last valid seqid this open owner sent OTW,
 * and 'oo_last_good_op' is the operation that issued the last valid seqid.
 *
 * Lock ordering:
 *	mntinfo4_t::mi_lock > oo_lock (for searching mi_oo_list)
 *
 *	oo_seqid_inuse > mntinfo4_t::mi_lock
 *	oo_seqid_inuse > rnode4_t::r_statelock
 *	oo_seqid_inuse > rnode4_t::r_statev4_lock
 *	oo_seqid_inuse > nfs4_open_stream_t::os_sync_lock
 *
 * The 'oo_seqid_inuse'/'oo_cv_seqid_sync' protects:
 *	oo_last_good_op
 *	oo_last_good_seqid
 *	oo_name
 *	oo_seqid
 *
 * The 'oo_lock' protects:
 *	oo_cred
 *	oo_cred_otw
 *	oo_foo_node
 *	oo_hash_node
 *	oo_just_created
 *	oo_ref_count
 *	oo_valid
 */

typedef struct nfs4_open_owner {
	cred_t			*oo_cred;
	int			oo_ref_count;
	int			oo_valid;
	int			oo_just_created;
	seqid4			oo_seqid;
	seqid4			oo_last_good_seqid;
	nfs4_tag_type_t		oo_last_good_op;
	unsigned		oo_seqid_inuse:1;
	cred_t			*oo_cred_otw;
	kcondvar_t		oo_cv_seqid_sync;
	/*
	 * Fix this to always be 8 bytes
	 */
	uint64_t		oo_name;
	list_node_t		oo_hash_node;
	list_node_t		oo_foo_node;
	kmutex_t		oo_lock;
} nfs4_open_owner_t;

/*
 * Static server information.
 * These fields are read-only once they are initialized; sv_lock
 * should be held as writer if they are changed during mount:
 *	sv_addr
 *	sv_dhsec
 *	sv_hostname
 *	sv_hostnamelen
 *	sv_knconf
 *	sv_next
 *	sv_origknconf
 *
 * These fields are protected by sv_lock:
 *	sv_currsec
 *	sv_fhandle
 *	sv_flags
 *	sv_fsid
 *	sv_path
 *	sv_pathlen
 *	sv_pfhandle
 *	sv_save_secinfo
 *	sv_savesec
 *	sv_secdata
 *	sv_secinfo
 *	sv_supp_attrs
 *
 * Lock ordering:
 * nfs_rtable4_lock > sv_lock
 * rnode4_t::r_statelock > sv_lock
 */
typedef struct servinfo4 {
	struct knetconfig *sv_knconf;   /* bound TLI fd */
	struct knetconfig *sv_origknconf;	/* For RDMA save orig knconf */
	struct netbuf	   sv_addr;	/* server's address */
	nfs4_fhandle_t	   sv_fhandle;	/* this server's filehandle */
	nfs4_fhandle_t	   sv_pfhandle; /* parent dir filehandle */
	int		   sv_pathlen;	/* Length of server path */
	char		  *sv_path;	/* Path name on server */
	uint32_t	   sv_flags;	/* flags for this server */
	sec_data_t	  *sv_secdata;	/* client initiated security data */
	sv_secinfo_t	  *sv_secinfo;	/* server security information */
	sec_data_t	  *sv_currsec;	/* security data currently used; */
					/* points to one of the sec_data */
					/* entries in sv_secinfo */
	sv_secinfo_t	  *sv_save_secinfo; /* saved secinfo */
	sec_data_t	  *sv_savesec;	/* saved security data */
	sec_data_t	  *sv_dhsec;    /* AUTH_DH data from the user land */
	char		  *sv_hostname;	/* server's hostname */
	int		   sv_hostnamelen;  /* server's hostname length */
	fattr4_fsid		sv_fsid;    /* fsid of shared obj	*/
	fattr4_supported_attrs	sv_supp_attrs;
	struct servinfo4  *sv_next;	/* next in list */
	nfs_rwlock_t	   sv_lock;
} servinfo4_t;

/* sv_flags fields */
#define	SV4_TRYSECINFO		0x001	/* try secinfo data from the server */
#define	SV4_TRYSECDEFAULT	0x002	/* try a default flavor */
#define	SV4_NOTINUSE		0x004	/* servinfo4_t had fatal errors */
#define	SV4_ROOT_STALE		0x008	/* root vnode got ESTALE */

/*
 * Lock call types.  See nfs4frlock().
 */
typedef enum nfs4_lock_call_type {
	NFS4_LCK_CTYPE_NORM,
	NFS4_LCK_CTYPE_RECLAIM,
	NFS4_LCK_CTYPE_RESEND,
	NFS4_LCK_CTYPE_REINSTATE
} nfs4_lock_call_type_t;

/*
 * This structure holds the information for a lost open/close/open downgrade/
 * lock/locku request.  It is also used for requests that are queued up so
 * that the recovery thread can release server state after a forced
 * unmount.
 * "lr_op" is 0 if the struct is uninitialized.  Otherwise, it is set to
 * the proper OP_* nfs_opnum4 number.  The other fields contain information
 * to reconstruct the call.
 *
 * lr_dvp is used for OPENs with CREATE, so that we can do a PUTFH of the
 * parent directroy without relying on vtodv (since we may not have a vp
 * for the file we wish to create).
 *
 * lr_putfirst means that the request should go to the front of the resend
 * queue, rather than the end.
 */
typedef struct nfs4_lost_rqst {
	list_node_t			lr_node;
	nfs_opnum4			lr_op;
	vnode_t				*lr_vp;
	vnode_t				*lr_dvp;
	nfs4_open_owner_t		*lr_oop;
	struct nfs4_open_stream		*lr_osp;
	struct nfs4_lock_owner		*lr_lop;
	cred_t				*lr_cr;
	flock64_t			*lr_flk;
	bool_t				lr_putfirst;
	union {
		struct {
			nfs4_lock_call_type_t lru_ctype;
			nfs_lock_type4	lru_locktype;
		} lru_lockargs;		/* LOCK, LOCKU */
		struct {
			uint32_t		lru_oaccess;
			uint32_t		lru_odeny;
			enum open_claim_type4	lru_oclaim;
			stateid4		lru_ostateid; /* reopen only */
			component4		lru_ofile;
		} lru_open_args;
		struct {
			uint32_t	lru_dg_access;
			uint32_t	lru_dg_deny;
		} lru_open_dg_args;
	} nfs4_lr_u;
} nfs4_lost_rqst_t;

#define	lr_oacc		nfs4_lr_u.lru_open_args.lru_oaccess
#define	lr_odeny	nfs4_lr_u.lru_open_args.lru_odeny
#define	lr_oclaim	nfs4_lr_u.lru_open_args.lru_oclaim
#define	lr_ostateid	nfs4_lr_u.lru_open_args.lru_ostateid
#define	lr_ofile	nfs4_lr_u.lru_open_args.lru_ofile
#define	lr_dg_acc	nfs4_lr_u.lru_open_dg_args.lru_dg_access
#define	lr_dg_deny	nfs4_lr_u.lru_open_dg_args.lru_dg_deny
#define	lr_ctype	nfs4_lr_u.lru_lockargs.lru_ctype
#define	lr_locktype	nfs4_lr_u.lru_lockargs.lru_locktype

/*
 * Recovery actions.  Some actions can imply further recovery using a
 * different recovery action (e.g., recovering the clientid leads to
 * recovering open files and locks).
 */

typedef enum {
	NR_UNUSED,
	NR_CLIENTID,
	NR_OPENFILES,
	NR_FHEXPIRED,
	NR_FAILOVER,
	NR_WRONGSEC,
	NR_EXPIRED,
	NR_BAD_STATEID,
	NR_BADHANDLE,
	NR_BAD_SEQID,
	NR_OLDSTATEID,
	NR_GRACE,
	NR_DELAY,
	NR_LOST_LOCK,
	NR_LOST_STATE_RQST,
	NR_STALE,
	NR_MOVED
} nfs4_recov_t;

/*
 * Administrative and debug message framework.
 */

#define	NFS4_MSG_MAX	100
extern int nfs4_msg_max;

#define	NFS4_REFERRAL_LOOP_MAX	20

typedef enum {
	RE_BAD_SEQID,
	RE_BADHANDLE,
	RE_CLIENTID,
	RE_DEAD_FILE,
	RE_END,
	RE_FAIL_RELOCK,
	RE_FAIL_REMAP_LEN,
	RE_FAIL_REMAP_OP,
	RE_FAILOVER,
	RE_FILE_DIFF,
	RE_LOST_STATE,
	RE_OPENS_CHANGED,
	RE_SIGLOST,
	RE_SIGLOST_NO_DUMP,
	RE_START,
	RE_UNEXPECTED_ACTION,
	RE_UNEXPECTED_ERRNO,
	RE_UNEXPECTED_STATUS,
	RE_WRONGSEC,
	RE_LOST_STATE_BAD_OP,
	RE_REFERRAL
} nfs4_event_type_t;

typedef enum {
	RFS_NO_INSPECT,
	RFS_INSPECT
} nfs4_fact_status_t;

typedef enum {
	RF_BADOWNER,
	RF_ERR,
	RF_RENEW_EXPIRED,
	RF_SRV_NOT_RESPOND,
	RF_SRV_OK,
	RF_SRVS_NOT_RESPOND,
	RF_SRVS_OK,
	RF_DELMAP_CB_ERR,
	RF_SENDQ_FULL
} nfs4_fact_type_t;

typedef enum {
	NFS4_MS_DUMP,
	NFS4_MS_NO_DUMP
} nfs4_msg_status_t;

typedef struct nfs4_rfact {
	nfs4_fact_type_t	rf_type;
	nfs4_fact_status_t	rf_status;
	bool_t			rf_reboot;
	nfs4_recov_t		rf_action;
	nfs_opnum4		rf_op;
	nfsstat4		rf_stat4;
	timespec_t		rf_time;
	int			rf_error;
	struct rnode4		*rf_rp1;
	char			*rf_char1;
} nfs4_rfact_t;

typedef struct nfs4_revent {
	nfs4_event_type_t	re_type;
	nfsstat4		re_stat4;
	uint_t			re_uint;
	pid_t			re_pid;
	struct mntinfo4		*re_mi;
	struct rnode4		*re_rp1;
	struct rnode4		*re_rp2;
	char			*re_char1;
	char			*re_char2;
	nfs4_tag_type_t		re_tag1;
	nfs4_tag_type_t		re_tag2;
	seqid4			re_seqid1;
	seqid4			re_seqid2;
} nfs4_revent_t;

typedef enum {
	RM_EVENT,
	RM_FACT
} nfs4_msg_type_t;

typedef struct nfs4_debug_msg {
	timespec_t		msg_time;
	nfs4_msg_type_t		msg_type;
	char			*msg_srv;
	char			*msg_mntpt;
	union {
		nfs4_rfact_t	msg_fact;
		nfs4_revent_t	msg_event;
	} rmsg_u;
	nfs4_msg_status_t	msg_status;
	list_node_t		msg_node;
} nfs4_debug_msg_t;

/*
 * NFS private data per mounted file system
 *	The mi_lock mutex protects the following fields:
 *		mi_flags
 *		mi_in_recovery
 *		mi_recovflags
 *		mi_recovthread
 *		mi_error
 *		mi_printed
 *		mi_down
 *		mi_stsize
 *		mi_curread
 *		mi_curwrite
 *		mi_timers
 *		mi_curr_serv
 *		mi_klmconfig
 *		mi_oo_list
 *		mi_foo_list
 *		mi_foo_num
 *		mi_foo_max
 *		mi_lost_state
 *		mi_bseqid_list
 *		mi_ephemeral
 *		mi_ephemeral_tree
 *
 *	Normally the netconfig information for the mount comes from
 *	mi_curr_serv and mi_klmconfig is NULL.  If NLM calls need to use a
 *	different transport, mi_klmconfig contains the necessary netconfig
 *	information.
 *
 *	The mi_async_lock mutex protects the following fields:
 *		mi_async_reqs
 *		mi_async_req_count
 *		mi_async_tail
 *		mi_async_curr[NFS4_MAX_ASYNC_QUEUES]
 *		mi_async_clusters
 *		mi_async_init_clusters
 *		mi_threads[NFS4_MAX_ASYNC_QUEUES]
 *		mi_inactive_thread
 *		mi_manager_thread
 *
 *	The nfs4_server_t::s_lock protects the following fields:
 *		mi_clientid
 *		mi_clientid_next
 *		mi_clientid_prev
 *		mi_open_files
 *
 *	The mntinfo4_t::mi_recovlock protects the following fields:
 *		mi_srvsettime
 *		mi_srvset_cnt
 *		mi_srv
 *
 * Changing mi_srv from one nfs4_server_t to a different one requires
 * holding the mi_recovlock as RW_WRITER.
 * Exception: setting mi_srv the first time in mount/mountroot is done
 * holding the mi_recovlock as RW_READER.
 *
 *	Locking order:
 *	  mi4_globals::mig_lock > mi_async_lock
 *	  mi_async_lock > nfs4_server_t::s_lock > mi_lock
 *	  mi_recovlock > mi_rename_lock > nfs_rtable4_lock
 *	  nfs4_server_t::s_recovlock > mi_recovlock
 *	  rnode4_t::r_rwlock > mi_rename_lock
 *	  nfs_rtable4_lock > mi_lock
 *	  nfs4_server_t::s_lock > mi_msg_list_lock
 *	  mi_recovlock > nfs4_server_t::s_lock
 *	  mi_recovlock > nfs4_server_lst_lock
 *
 * The 'mi_oo_list' represents the hash buckets that contain the
 * nfs4_open_owenrs for this particular mntinfo4.
 *
 * The 'mi_foo_list' represents the freed nfs4_open_owners for this mntinfo4.
 * 'mi_foo_num' is the current number of freed open owners on the list,
 * 'mi_foo_max' is the maximum number of freed open owners that are allowable
 * on the list.
 *
 * mi_rootfh and mi_srvparentfh are read-only once created, but that just
 * refers to the pointer.  The contents must be updated to keep in sync
 * with mi_curr_serv.
 *
 * The mi_msg_list_lock protects against adding/deleting entries to the
 * mi_msg_list, and also the updating/retrieving of mi_lease_period;
 *
 * 'mi_zone' is initialized at structure creation time, and never
 * changes; it may be read without a lock.
 *
 * mi_zone_node is linkage into the mi4_globals.mig_list, and is
 * protected by mi4_globals.mig_list_lock.
 *
 * If MI4_EPHEMERAL is set in mi_flags, then mi_ephemeral points to an
 * ephemeral structure for this ephemeral mount point. It can not be
 * NULL. Also, mi_ephemeral_tree points to the root of the ephemeral
 * tree.
 *
 * If MI4_EPHEMERAL is not set in mi_flags, then mi_ephemeral has
 * to be NULL. If mi_ephemeral_tree is non-NULL, then this node
 * is the enclosing mntinfo4 for the ephemeral tree.
 */
struct zone;
struct nfs4_ephemeral;
struct nfs4_ephemeral_tree;
struct nfs4_server;
typedef struct mntinfo4 {
	kmutex_t	mi_lock;	/* protects mntinfo4 fields */
	struct servinfo4 *mi_servers;   /* server list */
	struct servinfo4 *mi_curr_serv; /* current server */
	struct nfs4_sharedfh *mi_rootfh; /* root filehandle */
	struct nfs4_sharedfh *mi_srvparentfh; /* root's parent on server */
	kcondvar_t	mi_failover_cv;	/* failover synchronization */
	struct vfs	*mi_vfsp;	/* back pointer to vfs */
	enum vtype	mi_type;	/* file type of the root vnode */
	uint_t		mi_flags;	/* see below */
	uint_t		mi_recovflags;	/* if recovery active; see below */
	kthread_t	*mi_recovthread; /* active recov thread or NULL */
	uint_t		mi_error;	/* only set/valid when MI4_RECOV_FAIL */
					/* is set in mi_flags */
	int		mi_tsize;	/* transfer size (bytes) */
					/* really read size */
	int		mi_stsize;	/* server's max transfer size (bytes) */
					/* really write size */
	int		mi_timeo;	/* inital timeout in 10th sec */
	int		mi_retrans;	/* times to retry request */
	hrtime_t	mi_acregmin;	/* min time to hold cached file attr */
	hrtime_t	mi_acregmax;	/* max time to hold cached file attr */
	hrtime_t	mi_acdirmin;	/* min time to hold cached dir attr */
	hrtime_t	mi_acdirmax;	/* max time to hold cached dir attr */
	len_t		mi_maxfilesize; /* for pathconf _PC_FILESIZEBITS */
	int		mi_curread;	/* current read size */
	int		mi_curwrite;	/* current write size */
	uint_t 		mi_count; 	/* ref count */
	/*
	 * Async I/O management
	 * We have 2 pools of threads working on async I/O:
	 * 	(1) Threads which work on all async queues. Default number of
	 *	threads in this queue is 8. Threads in this pool work on async
	 *	queue pointed by mi_async_curr[NFS4_ASYNC_QUEUE]. Number of
	 *	active threads in this pool is tracked by
	 *	mi_threads[NFS4_ASYNC_QUEUE].
	 * 	(ii)Threads which work only on page op async queues.
	 *	Page ops queue comprises of NFS4_PUTAPAGE, NFS4_PAGEIO &
	 *	NFS4_COMMIT. Default number of threads in this queue is 2
	 *	(NUM_ASYNC_PGOPS_THREADS). Threads in this pool work on async
	 *	queue pointed by mi_async_curr[NFS4_ASYNC_PGOPS_QUEUE]. Number
	 *	of active threads in this pool is tracked by
	 *	mi_threads[NFS4_ASYNC_PGOPS_QUEUE].
	 *
	 * In addition to above two pools, there is always one thread that
	 * handles over-the-wire requests for VOP_INACTIVE.
	 */
	struct nfs4_async_reqs *mi_async_reqs[NFS4_ASYNC_TYPES];
	struct nfs4_async_reqs *mi_async_tail[NFS4_ASYNC_TYPES];
	struct nfs4_async_reqs **mi_async_curr[NFS4_MAX_ASYNC_QUEUES];
						/* current async queue */
	uint_t		mi_async_clusters[NFS4_ASYNC_TYPES];
	uint_t		mi_async_init_clusters;
	uint_t		mi_async_req_count; /* # outstanding work requests */
	kcondvar_t	mi_async_reqs_cv; /* signaled when there's work */
	ushort_t	mi_threads[NFS4_MAX_ASYNC_QUEUES];
					/* number of active async threads */
	ushort_t	mi_max_threads;	/* max number of async threads */
	kthread_t	*mi_manager_thread; /* async manager thread id */
	kthread_t	*mi_inactive_thread; /* inactive thread id */
	kcondvar_t	mi_inact_req_cv; /* notify VOP_INACTIVE thread */
	kcondvar_t	mi_async_work_cv[NFS4_MAX_ASYNC_QUEUES];
					/* tell workers to work */
	kcondvar_t	mi_async_cv;	/* all pool threads exited */
	kmutex_t	mi_async_lock;
	/*
	 * Other stuff
	 */
	struct pathcnf	*mi_pathconf;	/* static pathconf kludge */
	rpcprog_t	mi_prog;	/* RPC program number */
	rpcvers_t	mi_vers;	/* RPC program version number */
	char		**mi_rfsnames;	/* mapping to proc names */
	kstat_named_t	*mi_reqs;	/* count of requests */
	clock_t		mi_printftime;	/* last error printf time */
	nfs_rwlock_t	mi_recovlock;	/* separate ops from recovery (v4) */
	time_t		mi_grace_wait;	/* non-zero represents time to wait */
	/* when we switched nfs4_server_t - only for observability purposes */
	time_t		mi_srvsettime;
	nfs_rwlock_t	mi_rename_lock;	/* atomic volfh rename  */
	struct nfs4_fname *mi_fname;	/* root fname */
	list_t		mi_lost_state;	/* resend list */
	list_t		mi_bseqid_list; /* bad seqid list */
	/*
	 * Client Side Failover stats
	 */
	uint_t		mi_noresponse;	/* server not responding count */
	uint_t		mi_failover; 	/* failover to new server count */
	uint_t		mi_remap;	/* remap to new server count */
	/*
	 * Kstat statistics
	 */
	struct kstat	*mi_io_kstats;
	struct kstat	*mi_ro_kstats;
	kstat_t		*mi_recov_ksp;	/* ptr to the recovery kstat */

	/*
	 * Volatile fh flags (nfsv4)
	 */
	uint32_t	mi_fh_expire_type;
	/*
	 * Lease Management
	 */
	struct mntinfo4	*mi_clientid_next;
	struct mntinfo4	*mi_clientid_prev;
	clientid4	mi_clientid; /* redundant info found in nfs4_server */
	int		mi_open_files;	/* count of open files */
	int		mi_in_recovery;	/* count of recovery instances */
	kcondvar_t	mi_cv_in_recov; /* cv for recovery threads */
	/*
	 * Open owner stuff.
	 */
	struct nfs4_oo_hash_bucket	mi_oo_list[NFS4_NUM_OO_BUCKETS];
	list_t				mi_foo_list;
	int				mi_foo_num;
	int				mi_foo_max;
	/*
	 * Shared filehandle pool.
	 */
	nfs_rwlock_t			mi_fh_lock;
	avl_tree_t			mi_filehandles;

	/*
	 * Debug message queue.
	 */
	list_t			mi_msg_list;
	int			mi_msg_count;
	time_t			mi_lease_period;
					/*
					 * not guaranteed to be accurate.
					 * only should be used by debug queue.
					 */
	kmutex_t		mi_msg_list_lock;
	/*
	 * Zones support.
	 */
	struct zone	*mi_zone;	/* Zone in which FS is mounted */
	zone_ref_t	mi_zone_ref;	/* Reference to aforementioned zone */
	list_node_t	mi_zone_node;  /* linkage into per-zone mi list */

	/*
	 * Links for unmounting ephemeral mounts.
	 */
	struct nfs4_ephemeral		*mi_ephemeral;
	struct nfs4_ephemeral_tree	*mi_ephemeral_tree;

	uint_t mi_srvset_cnt; /* increment when changing the nfs4_server_t */
	struct nfs4_server *mi_srv; /* backpointer to nfs4_server_t */
	/*
	 * Referral related info.
	 */
	int		mi_vfs_referral_loop_cnt;
} mntinfo4_t;

/*
 * The values for mi_flags.
 *
 *	MI4_HARD		 hard or soft mount
 *	MI4_PRINTED		 responding message printed
 *	MI4_INT			 allow INTR on hard mount
 * 	MI4_DOWN		 server is down
 *	MI4_NOAC		 don't cache attributes
 *	MI4_NOCTO		 no close-to-open consistency
 *	MI4_LLOCK		 local locking only (no lockmgr)
 *	MI4_GRPID		 System V group id inheritance
 *	MI4_SHUTDOWN		 System is rebooting or shutting down
 *	MI4_LINK		 server supports link
 *	MI4_SYMLINK		 server supports symlink
 *	MI4_EPHEMERAL_RECURSED	 an ephemeral mount being unmounted
 *				 due to a recursive call - no need
 *				 for additional recursion
 *	MI4_ACL			 server supports NFSv4 ACLs
 *	MI4_MIRRORMOUNT		 is a mirrormount
 *	MI4_NOPRINT		 don't print messages
 *	MI4_DIRECTIO		 do direct I/O
 *	MI4_RECOV_ACTIV		 filesystem has recovery a thread
 *	MI4_REMOVE_ON_LAST_CLOSE remove from server's list
 *	MI4_RECOV_FAIL		 client recovery failed
 *	MI4_PUBLIC		 public/url option used
 *	MI4_MOUNTING		 mount in progress, don't failover
 *	MI4_POSIX_LOCK		 if server is using POSIX locking
 *	MI4_LOCK_DEBUG		 cmn_err'd posix lock err msg
 *	MI4_DEAD		 zone has released it
 *	MI4_INACTIVE_IDLE	 inactive thread idle
 *	MI4_BADOWNER_DEBUG	 badowner error msg per mount
 *	MI4_ASYNC_MGR_STOP	 tell async manager to die
 *	MI4_TIMEDOUT		 saw a timeout during zone shutdown
 *	MI4_EPHEMERAL		 is an ephemeral mount
 */
#define	MI4_HARD		 0x1
#define	MI4_PRINTED		 0x2
#define	MI4_INT			 0x4
#define	MI4_DOWN		 0x8
#define	MI4_NOAC		 0x10
#define	MI4_NOCTO		 0x20
#define	MI4_LLOCK		 0x80
#define	MI4_GRPID		 0x100
#define	MI4_SHUTDOWN		 0x200
#define	MI4_LINK		 0x400
#define	MI4_SYMLINK		 0x800
#define	MI4_EPHEMERAL_RECURSED	 0x1000
#define	MI4_ACL			 0x2000
/* MI4_MIRRORMOUNT is also defined in nfsstat.c */
#define	MI4_MIRRORMOUNT		 0x4000
#define	MI4_REFERRAL		 0x8000
/* 0x10000 is available */
#define	MI4_NOPRINT		 0x20000
#define	MI4_DIRECTIO		 0x40000
/* 0x80000 is available */
#define	MI4_RECOV_ACTIV		 0x100000
#define	MI4_REMOVE_ON_LAST_CLOSE 0x200000
#define	MI4_RECOV_FAIL		 0x400000
#define	MI4_PUBLIC		 0x800000
#define	MI4_MOUNTING		 0x1000000
#define	MI4_POSIX_LOCK		 0x2000000
#define	MI4_LOCK_DEBUG		 0x4000000
#define	MI4_DEAD		 0x8000000
#define	MI4_INACTIVE_IDLE	 0x10000000
#define	MI4_BADOWNER_DEBUG	 0x20000000
#define	MI4_ASYNC_MGR_STOP	 0x40000000
#define	MI4_TIMEDOUT		 0x80000000

#define	MI4_EPHEMERAL		(MI4_MIRRORMOUNT | MI4_REFERRAL)

#define	INTR4(vp)	(VTOMI4(vp)->mi_flags & MI4_INT)

#define	FAILOVER_MOUNT4(mi)	(mi->mi_servers->sv_next)

/*
 * Recovery flags.
 *
 * MI4R_NEED_CLIENTID is sort of redundant (it's the nfs4_server_t flag
 * that's important), but some flag is needed to indicate that recovery is
 * going on for the filesystem.
 */
#define	MI4R_NEED_CLIENTID	0x1
#define	MI4R_REOPEN_FILES	0x2
#define	MI4R_NEED_SECINFO	0x4
#define	MI4R_NEED_NEW_SERVER	0x8
#define	MI4R_REMAP_FILES	0x10
#define	MI4R_SRV_REBOOT		0x20	/* server has rebooted */
#define	MI4R_LOST_STATE		0x40
#define	MI4R_BAD_SEQID		0x80
#define	MI4R_MOVED		0x100

#define	MI4_HOLD(mi) {		\
	mi_hold(mi);		\
}

#define	MI4_RELE(mi) {		\
	mi_rele(mi);		\
}

/*
 * vfs pointer to mount info
 */
#define	VFTOMI4(vfsp)	((mntinfo4_t *)((vfsp)->vfs_data))

/*
 * vnode pointer to mount info
 */
#define	VTOMI4(vp)	((mntinfo4_t *)(((vp)->v_vfsp)->vfs_data))

/*
 * Lease Management
 *
 * lease_valid is initially set to NFS4_LEASE_NOT_STARTED.  This is when the
 * nfs4_server is first created.  lease_valid is then set to
 * NFS4_LEASE_UNITIALIZED when the renew thread is started.  The extra state of
 * NFS4_LEASE_NOT_STARTED is needed for client recovery (so we know if a thread
 * already exists when we do SETCLIENTID).  lease_valid is then set to
 * NFS4_LEASE_VALID (if it is at NFS4_LEASE_UNITIALIZED) when a state creating
 * operation (OPEN) is done. lease_valid stays at NFS4_LEASE_VALID as long as
 * the lease is renewed.  It is set to NFS4_LEASE_INVALID when the lease
 * expires.  Client recovery is needed to set the lease back to
 * NFS4_LEASE_VALID from NFS4_LEASE_INVALID.
 *
 * The s_cred is the credential used to mount the first file system for this
 * server.  It used as the credential for the renew thread's calls to the
 * server.
 *
 * The renew thread waits on the condition variable cv_thread_exit.  If the cv
 * is signalled, then the thread knows it must check s_thread_exit to see if
 * it should exit.  The cv is signaled when the last file system is unmounted
 * from a particular server.  s_thread_exit is set to 0 upon thread startup,
 * and set to NFS4_THREAD_EXIT, when the last file system is unmounted thereby
 * telling the thread to exit.  s_thread_exit is needed to avoid spurious
 * wakeups.
 *
 * state_ref_count is incremented every time a new file is opened and
 * decremented every time a file is closed otw.  This keeps track of whether
 * the nfs4_server has state associated with it or not.
 *
 * s_refcnt is the reference count for storage management of the struct
 * itself.
 *
 * mntinfo4_list points to the doubly linked list of mntinfo4s that share
 * this nfs4_server (ie: <clientid, saddr> pair) in the current zone.  This is
 * needed for a nfs4_server to get a mntinfo4 for use in rfs4call.
 *
 * s_recovlock is used to synchronize recovery operations.  The thread
 * that is recovering the client must acquire it as a writer.  If the
 * thread is using the clientid (including recovery operations on other
 * state), acquire it as a reader.
 *
 * The 's_otw_call_count' keeps track of the number of outstanding over the
 * wire requests for this structure.  The struct will not go away as long
 * as this is non-zero (or s_refcnt is non-zero).
 *
 * The 's_cv_otw_count' is used in conjuntion with the 's_otw_call_count'
 * variable to let the renew thread when an outstanding otw request has
 * finished.
 *
 * 'zoneid' and 'zone_globals' are set at creation of this structure
 * and are read-only after that; no lock is required to read them.
 *
 * s_lock protects: everything except cv_thread_exit and s_recovlock.
 *
 * s_program is used as the index into the nfs4_callback_globals's
 * nfs4prog2server table.  When a callback request comes in, we can
 * use that request's program number (minus NFS4_CALLBACK) as an index
 * into the nfs4prog2server.  That entry will hold the nfs4_server_t ptr.
 * We can then access that nfs4_server_t and its 's_deleg_list' (its list of
 * delegated rnode4_ts).
 *
 * Lock order:
 * nfs4_server::s_lock > mntinfo4::mi_lock
 * nfs_rtable4_lock > s_lock
 * nfs4_server_lst_lock > s_lock
 * s_recovlock > s_lock
 */
struct nfs4_callback_globals;

typedef struct nfs4_server {
	struct nfs4_server	*forw;
	struct nfs4_server	*back;
	struct netbuf		saddr;
	uint_t			s_flags; /* see below */
	uint_t			s_refcnt;
	clientid4		clientid;	/* what we get from server */
	nfs_client_id4		clidtosend;	/* what we send to server */
	mntinfo4_t		*mntinfo4_list;
	int			lease_valid;
	time_t			s_lease_time;
	time_t			last_renewal_time;
	timespec_t		propagation_delay;
	cred_t			*s_cred;
	kcondvar_t		cv_thread_exit;
	int			s_thread_exit;
	int			state_ref_count;
	int			s_otw_call_count;
	kcondvar_t		s_cv_otw_count;
	kcondvar_t		s_clientid_pend;
	kmutex_t		s_lock;
	list_t			s_deleg_list;
	rpcprog_t		s_program;
	nfs_rwlock_t		s_recovlock;
	kcondvar_t		wait_cb_null; /* used to wait for CB_NULL */
	zoneid_t		zoneid;	/* zone using this nfs4_server_t */
	struct nfs4_callback_globals *zone_globals;	/* globals */
} nfs4_server_t;

/* nfs4_server flags */
#define	N4S_CLIENTID_SET	1	/* server has our clientid */
#define	N4S_CLIENTID_PEND	0x2	/* server doesn't have clientid */
#define	N4S_CB_PINGED		0x4	/* server has sent us a CB_NULL */
#define	N4S_CB_WAITER		0x8	/* is/has wait{ing/ed} for cb_null */
#define	N4S_INSERTED		0x10	/* list has reference for server */
#define	N4S_BADOWNER_DEBUG	0x20	/* bad owner err msg per client */

#define	N4S_CB_PAUSE_TIME	10000	/* Amount of time to pause (10ms) */

struct lease_time_arg {
	time_t	lease_time;
};

enum nfs4_delegreturn_policy {
	IMMEDIATE,
	FIRSTCLOSE,
	LASTCLOSE,
	INACTIVE
};

/*
 * Operation hints for the recovery framework (mostly).
 *
 * EXCEPTIONS:
 * OH_ACCESS, OH_GETACL, OH_GETATTR, OH_LOOKUP, OH_READDIR
 *	These hints exist to allow user visit/readdir a R4SRVSTUB dir.
 *	(dir represents the root of a server fs that has not yet been
 *	mounted at client)
 */
typedef enum {
	OH_OTHER,
	OH_READ,
	OH_WRITE,
	OH_COMMIT,
	OH_VFH_RENAME,
	OH_MOUNT,
	OH_CLOSE,
	OH_LOCKU,
	OH_DELEGRETURN,
	OH_ACCESS,
	OH_GETACL,
	OH_GETATTR,
	OH_LOOKUP,
	OH_READDIR
} nfs4_op_hint_t;

/*
 * This data structure is used to track ephemeral mounts for both
 * mirror mounts and referrals.
 *
 * Note that each nfs4_ephemeral can only have one other nfs4_ephemeral
 * pointing at it. So we don't need two backpointers to walk
 * back up the tree.
 *
 * An ephemeral tree is pointed to by an enclosing non-ephemeral
 * mntinfo4. The root is also pointed to by its ephemeral
 * mntinfo4. ne_child will get us back to it, while ne_prior
 * will get us back to the non-ephemeral mntinfo4. This is an
 * edge case we will need to be wary of when walking back up the
 * tree.
 *
 * The way we handle this edge case is to have ne_prior be NULL
 * for the root nfs4_ephemeral node.
 */
typedef struct nfs4_ephemeral {
	mntinfo4_t		*ne_mount;	/* who encloses us */
	struct nfs4_ephemeral	*ne_child;	/* first child node */
	struct nfs4_ephemeral	*ne_peer;	/* next sibling */
	struct nfs4_ephemeral	*ne_prior;	/* who points at us */
	time_t			ne_ref_time;	/* time last referenced */
	uint_t			ne_mount_to;	/* timeout at */
	int			ne_state;	/* used to traverse */
} nfs4_ephemeral_t;

/*
 * State for the node (set in ne_state):
 */
#define	NFS4_EPHEMERAL_OK		0x0
#define	NFS4_EPHEMERAL_VISIT_CHILD	0x1
#define	NFS4_EPHEMERAL_VISIT_SIBLING	0x2
#define	NFS4_EPHEMERAL_PROCESS_ME	0x4
#define	NFS4_EPHEMERAL_CHILD_ERROR	0x8
#define	NFS4_EPHEMERAL_PEER_ERROR	0x10

/*
 * These are the locks used in processing ephemeral data:
 *
 * mi->mi_lock
 *
 * net->net_tree_lock
 *     This lock is used to gate all tree operations.
 *     If it is held, then no other process may
 *     traverse the tree. This allows us to not
 *     throw a hold on each vfs_t in the tree.
 *     Can be held for a "long" time.
 *
 * net->net_cnt_lock
 *     Used to protect refcnt and status.
 *     Must be held for a really short time.
 *
 * nfs4_ephemeral_thread_lock
 *     Is only held to create the harvester for the zone.
 *     There is no ordering imposed on it.
 *     Held for a really short time.
 *
 * Some further detail on the interactions:
 *
 * net_tree_lock controls access to net_root. Access needs to first be
 * attempted in a non-blocking check.
 *
 * net_cnt_lock controls access to net_refcnt and net_status. It must only be
 * held for very short periods of time, unless the refcnt is 0 and the status
 * is INVALID.
 *
 * Before a caller can grab net_tree_lock, it must first grab net_cnt_lock
 * to bump the net_refcnt. It then releases it and does the action specific
 * algorithm to get the net_tree_lock. Once it has that, then it is okay to
 * grab the net_cnt_lock and change the status. The status can only be
 * changed if the caller has the net_tree_lock held as well.
 *
 * Note that the initial grab of net_cnt_lock must occur whilst
 * mi_lock is being held. This prevents stale data in that if the
 * ephemeral tree is non-NULL, then the harvester can not remove
 * the tree from the mntinfo node until it grabs that lock. I.e.,
 * we get the pointer to the tree and hold the lock atomically
 * with respect to being in mi_lock.
 *
 * When a caller is done with net_tree_lock, it can decrement the net_refcnt
 * either before it releases net_tree_lock or after.
 *
 * In either event, to decrement net_refcnt, it must hold net_cnt_lock.
 *
 * Note that the overall locking scheme for the nodes is to control access
 * via the tree. The current scheme could easily be extended such that
 * the enclosing root referenced a "forest" of trees. The underlying trees
 * would be autonomous with respect to locks.
 *
 * Note that net_next is controlled by external locks
 * particular to the data structure that the tree is being added to.
 */
typedef struct nfs4_ephemeral_tree {
	mntinfo4_t			*net_mount;
	nfs4_ephemeral_t		*net_root;
	struct nfs4_ephemeral_tree	*net_next;
	kmutex_t			net_tree_lock;
	kmutex_t			net_cnt_lock;
	uint_t				net_status;
	uint_t				net_refcnt;
} nfs4_ephemeral_tree_t;

/*
 * State for the tree (set in net_status):
 */
#define	NFS4_EPHEMERAL_TREE_OK		0x0
#define	NFS4_EPHEMERAL_TREE_BUILDING	0x1
#define	NFS4_EPHEMERAL_TREE_DEROOTING	0x2
#define	NFS4_EPHEMERAL_TREE_INVALID	0x4
#define	NFS4_EPHEMERAL_TREE_MOUNTING	0x8
#define	NFS4_EPHEMERAL_TREE_UMOUNTING	0x10
#define	NFS4_EPHEMERAL_TREE_LOCKED	0x20

#define	NFS4_EPHEMERAL_TREE_PROCESSING	(NFS4_EPHEMERAL_TREE_DEROOTING | \
	NFS4_EPHEMERAL_TREE_INVALID | NFS4_EPHEMERAL_TREE_UMOUNTING | \
	NFS4_EPHEMERAL_TREE_LOCKED)

/*
 * This macro evaluates to non-zero if the given op releases state at the
 * server.
 */
#define	OH_IS_STATE_RELE(op)	((op) == OH_CLOSE || (op) == OH_LOCKU || \
				(op) == OH_DELEGRETURN)

#ifdef _KERNEL

extern void	nfs4_async_manager(struct vfs *);
extern void	nfs4_async_manager_stop(struct vfs *);
extern void	nfs4_async_stop(struct vfs *);
extern int	nfs4_async_stop_sig(struct vfs *);
extern int	nfs4_async_readahead(vnode_t *, u_offset_t, caddr_t,
				struct seg *, cred_t *,
				void (*)(vnode_t *, u_offset_t,
				caddr_t, struct seg *, cred_t *));
extern int	nfs4_async_putapage(vnode_t *, page_t *, u_offset_t, size_t,
				int, cred_t *, int (*)(vnode_t *, page_t *,
				u_offset_t, size_t, int, cred_t *));
extern int	nfs4_async_pageio(vnode_t *, page_t *, u_offset_t, size_t,
				int, cred_t *, int (*)(vnode_t *, page_t *,
				u_offset_t, size_t, int, cred_t *));
extern void	nfs4_async_commit(vnode_t *, page_t *, offset3, count3,
				cred_t *, void (*)(vnode_t *, page_t *,
				offset3, count3, cred_t *));
extern void	nfs4_async_inactive(vnode_t *, cred_t *);
extern void	nfs4_inactive_thread(mntinfo4_t *mi);
extern void	nfs4_inactive_otw(vnode_t *, cred_t *);
extern int	nfs4_putpages(vnode_t *, u_offset_t, size_t, int, cred_t *);

extern int	nfs4_setopts(vnode_t *, model_t, struct nfs_args *);
extern void	nfs4_mnt_kstat_init(struct vfs *);

extern void	rfs4call(struct mntinfo4 *, struct COMPOUND4args_clnt *,
			struct COMPOUND4res_clnt *, cred_t *, int *, int,
			nfs4_error_t *);
extern void	nfs4_acl_fill_cache(struct rnode4 *, vsecattr_t *);
extern int	nfs4_attr_otw(vnode_t *, nfs4_tag_type_t,
				nfs4_ga_res_t *, bitmap4, cred_t *);

extern void	nfs4_attrcache_noinval(vnode_t *, nfs4_ga_res_t *, hrtime_t);
extern void	nfs4_attr_cache(vnode_t *, nfs4_ga_res_t *,
				hrtime_t, cred_t *, int,
				change_info4 *);
extern void	nfs4_purge_rddir_cache(vnode_t *);
extern void	nfs4_invalidate_pages(vnode_t *, u_offset_t, cred_t *);
extern void	nfs4_purge_caches(vnode_t *, int, cred_t *, int);
extern void	nfs4_purge_stale_fh(int, vnode_t *, cred_t *);
extern void	nfs4_flush_pages(vnode_t *vp, cred_t *cr);

extern void	nfs4rename_update(vnode_t *, vnode_t *, nfs_fh4 *, char *);
extern void	nfs4_update_paths(vnode_t *, char *, vnode_t *, char *,
			vnode_t *);

extern void	nfs4args_lookup_free(nfs_argop4 *, int);
extern void	nfs4args_copen_free(OPEN4cargs *);

extern void	nfs4_printfhandle(nfs4_fhandle_t *);

extern void	nfs_free_mi4(mntinfo4_t *);
extern void	sv4_free(servinfo4_t *);
extern void	nfs4_mi_zonelist_add(mntinfo4_t *);
extern int	nfs4_mi_zonelist_remove(mntinfo4_t *);
extern int 	nfs4_secinfo_recov(mntinfo4_t *, vnode_t *, vnode_t *);
extern void	nfs4_secinfo_init(void);
extern void	nfs4_secinfo_fini(void);
extern int	nfs4_secinfo_path(mntinfo4_t *, cred_t *, int);
extern int 	nfs4_secinfo_vnode_otw(vnode_t *, char *, cred_t *);
extern void	secinfo_free(sv_secinfo_t *);
extern void	save_mnt_secinfo(servinfo4_t *);
extern void	check_mnt_secinfo(servinfo4_t *, vnode_t *);
extern int	vattr_to_fattr4(vattr_t *, vsecattr_t *, fattr4 *, int,
				enum nfs_opnum4, bitmap4 supp_mask);
extern int	nfs4_putapage(vnode_t *, page_t *, u_offset_t *, size_t *,
			int, cred_t *);
extern void	nfs4_write_error(vnode_t *, int, cred_t *);
extern void	nfs4_lockcompletion(vnode_t *, int);
extern bool_t	nfs4_map_lost_lock_conflict(vnode_t *);
extern int	vtodv(vnode_t *, vnode_t **, cred_t *, bool_t);
extern int	vtoname(vnode_t *, char *, ssize_t);
extern void	nfs4open_confirm(vnode_t *, seqid4*, stateid4 *, cred_t *,
		    bool_t, bool_t *, nfs4_open_owner_t *, bool_t,
		    nfs4_error_t *, int *);
extern void	nfs4_error_zinit(nfs4_error_t *);
extern void	nfs4_error_init(nfs4_error_t *, int);
extern void	nfs4_free_args(struct nfs_args *);

extern void 	mi_hold(mntinfo4_t *);
extern void	mi_rele(mntinfo4_t *);

extern vnode_t	*find_referral_stubvp(vnode_t *, char *, cred_t *);
extern int	 nfs4_setup_referral(vnode_t *, char *, vnode_t **, cred_t *);

extern sec_data_t	*copy_sec_data(sec_data_t *);
extern gss_clntdata_t	*copy_sec_data_gss(gss_clntdata_t *);

#ifdef DEBUG
extern int	nfs4_consistent_type(vnode_t *);
#endif

extern void	nfs4_init_dot_entries(void);
extern void	nfs4_destroy_dot_entries(void);
extern struct nfs4_callback_globals	*nfs4_get_callback_globals(void);

extern struct nfs4_server nfs4_server_lst;

extern clock_t nfs_write_error_interval;

#endif /* _KERNEL */

/*
 * Flags for nfs4getfh_otw.
 */

#define	NFS4_GETFH_PUBLIC	0x01
#define	NFS4_GETFH_NEEDSOP	0x02

/*
 * Found through rnodes.
 *
 * The os_open_ref_count keeps track the number of open file descriptor
 * refernces on this data structure.  It will be bumped for any successful
 * OTW OPEN call and any OPEN call that determines the OTW call is not
 * necessary and the open stream hasn't just been created (see
 * nfs4_is_otw_open_necessary).
 *
 * os_mapcnt is a count of the number of mmapped pages for a particular
 * open stream; this in conjunction w/ os_open_ref_count is used to
 * determine when to do a close to the server.  This is necessary because
 * of the semantics of doing open, mmap, close; the OTW close must be wait
 * until all open and mmap references have vanished.
 *
 * 'os_valid' tells us whether this structure is about to be freed or not,
 * if it is then don't return it in find_open_stream().
 *
 * 'os_final_close' is set when a CLOSE OTW was attempted.  This is needed
 * so we can properly count the os_open_ref_count in cases where we VOP_CLOSE
 * without a VOP_OPEN, and have nfs4_inactive() drive the OTW CLOSE.  It
 * also helps differentiate the VOP_OPEN/VN_RELE case from the VOP_CLOSE
 * that tried to close OTW but failed, and left the state cleanup to
 * nfs4_inactive/CLOSE_FORCE.
 *
 * 'os_force_close' is used to let us know if an intervening thread came
 * and reopened the open stream after we decided to issue a CLOSE_FORCE,
 * but before we could actually process the CLOSE_FORCE.
 *
 * 'os_pending_close' is set when an over-the-wire CLOSE is deferred to the
 * lost state queue.
 *
 * 'open_stateid' is set the last open stateid returned by the server unless
 * 'os_delegation' is 1, in which case 'open_stateid' refers to the
 * delegation stateid returned by the server.  This is used in cases where the
 * client tries to OPEN a file but already has a suitable delegation, so we
 * just stick the delegation stateid in the open stream.
 *
 * os_dc_openacc are open access bits which have been granted to the
 * open stream by virtue of a delegation, but which have not been seen
 * by the server.  This applies even if the open stream does not have
 * os_delegation set.  These bits are used when setting file locks to
 * determine whether an open with CLAIM_DELEGATE_CUR needs to be done
 * before the lock request can be sent to the server.  See
 * nfs4frlock_check_deleg().
 *
 * 'os_mmap_read/write' keep track of the read and write access our memory
 * maps require.  We need to keep track of this so we can provide the proper
 * access bits in the open/mmap/close/reboot/reopen case.
 *
 * 'os_failed_reopen' tells us that we failed to successfully reopen this
 * open stream; therefore, we should not use this open stateid as it is
 * not valid anymore. This flag is also used to indicate an unsuccessful
 * attempt to reopen a delegation open stream with CLAIM_DELEGATE_CUR.
 *
 * If 'os_orig_oo_name' is different than os_open_owner's oo_name
 * then this tells us that this open stream's open owner used a
 * bad seqid (that is, got NFS4ERR_BAD_SEQID).  If different, this open
 * stream will no longer be used for future OTW state releasing calls.
 *
 * Lock ordering:
 * rnode4_t::r_os_lock > os_sync_lock
 * os_sync_lock > rnode4_t::r_statelock
 * os_sync_lock > rnode4_t::r_statev4_lock
 * os_sync_lock > mntinfo4_t::mi_lock (via hold over rfs4call)
 *
 * The 'os_sync_lock' protects:
 *	open_stateid
 *	os_dc_openacc
 *	os_delegation
 *	os_failed_reopen
 *	os_final_close
 *	os_force_close
 *	os_mapcnt
 *	os_mmap_read
 *	os_mmap_write
 *	os_open_ref_count
 *	os_pending_close
 *	os_share_acc_read
 *	os_share_acc_write
 *	os_share_deny_none
 *	os_share_deny_read
 *	os_share_deny_write
 *	os_ref_count
 *	os_valid
 *
 * The rnode4_t::r_os_lock protects:
 *	os_node
 *
 * These fields are set at creation time and
 * read only after that:
 *	os_open_owner
 *	os_orig_oo_name
 */
typedef struct nfs4_open_stream {
	uint64_t		os_share_acc_read;
	uint64_t		os_share_acc_write;
	uint64_t		os_mmap_read;
	uint64_t		os_mmap_write;
	uint32_t		os_share_deny_none;
	uint32_t		os_share_deny_read;
	uint32_t		os_share_deny_write;
	stateid4		open_stateid;
	int			os_dc_openacc;
	int			os_ref_count;
	unsigned		os_valid:1;
	unsigned 		os_delegation:1;
	unsigned		os_final_close:1;
	unsigned 		os_pending_close:1;
	unsigned 		os_failed_reopen:1;
	unsigned		os_force_close:1;
	int			os_open_ref_count;
	long			os_mapcnt;
	list_node_t		os_node;
	struct nfs4_open_owner	*os_open_owner;
	uint64_t		os_orig_oo_name;
	kmutex_t		os_sync_lock;
} nfs4_open_stream_t;

/*
 * This structure describes the format of the lock_owner_name
 * field of the lock owner.
 */

typedef struct nfs4_lo_name {
	uint64_t	ln_seq_num;
	pid_t		ln_pid;
} nfs4_lo_name_t;

/*
 * Flags for lo_flags.
 */
#define	NFS4_LOCK_SEQID_INUSE	0x1
#define	NFS4_BAD_SEQID_LOCK	0x2

/*
 * The lo_prev_rnode and lo_next_rnode are for a circular list that hangs
 * off the rnode.  If the links are NULL it means this object is not on the
 * list.
 *
 * 'lo_pending_rqsts' is non-zero if we ever tried to send a request and
 * didn't get a response back.  This is used to figure out if we have
 * possible remote v4 locks, so that we can clean up at process exit.  In
 * theory, the client should be able to figure out if the server received
 * the request (based on what seqid works), so maybe we can get rid of this
 * flag someday.
 *
 * 'lo_ref_count' tells us how many processes/threads are using this data
 * structure.  The rnode's list accounts for one reference.
 *
 * 'lo_just_created' is set to NFS4_JUST_CREATED when we first create the
 * data structure.  It is then set to NFS4_PERM_CREATED when a lock request
 * is successful using this lock owner structure.  We need to keep 'temporary'
 * lock owners around so we can properly keep the lock seqid synchronization
 * when multiple processes/threads are trying to create the lock owner for the
 * first time (especially with the DENIED error case).  Once
 * 'lo_just_created' is set to NFS4_PERM_CREATED, it doesn't change.
 *
 * 'lo_valid' tells us whether this structure is about to be freed or not,
 * if it is then don't return it from find_lock_owner().
 *
 * Retrieving and setting of 'lock_seqid' is protected by the
 * NFS4_LOCK_SEQID_INUSE flag.  Waiters for NFS4_LOCK_SEQID_INUSE should
 * use 'lo_cv_seqid_sync'.
 *
 * The setting of 'lock_stateid' is protected by the
 * NFS4_LOCK_SEQID_INUSE flag and 'lo_lock'.  The retrieving of the
 * 'lock_stateid' is protected by 'lo_lock', with the additional
 * requirement that the calling function can handle NFS4ERR_OLD_STATEID and
 * NFS4ERR_BAD_STATEID as appropiate.
 *
 * The setting of NFS4_BAD_SEQID_LOCK to lo_flags tells us whether this lock
 * owner used a bad seqid (that is, got NFS4ERR_BAD_SEQID).  With this set,
 * this lock owner will no longer be used for future OTW calls.  Once set,
 * it is never unset.
 *
 * Lock ordering:
 * rnode4_t::r_statev4_lock > lo_lock
 */
typedef struct nfs4_lock_owner {
	struct nfs4_lock_owner	*lo_next_rnode;
	struct nfs4_lock_owner	*lo_prev_rnode;
	int			lo_pid;
	stateid4		lock_stateid;
	seqid4			lock_seqid;
	/*
	 * Fix this to always be 12 bytes
	 */
	nfs4_lo_name_t		lock_owner_name;
	int			lo_ref_count;
	int			lo_valid;
	int			lo_pending_rqsts;
	int			lo_just_created;
	int			lo_flags;
	kcondvar_t		lo_cv_seqid_sync;
	kmutex_t		lo_lock;
	kthread_t		*lo_seqid_holder; /* debugging aid */
} nfs4_lock_owner_t;

/* for nfs4_lock_owner_t lookups */
typedef enum {LOWN_ANY, LOWN_VALID_STATEID} lown_which_t;

/* Number of times to retry a call that fails with state independent error */
#define	NFS4_NUM_RECOV_RETRIES	3

typedef enum {
	NO_SID,
	DEL_SID,
	LOCK_SID,
	OPEN_SID,
	SPEC_SID
} nfs4_stateid_type_t;

typedef struct nfs4_stateid_types {
	stateid4 d_sid;
	stateid4 l_sid;
	stateid4 o_sid;
	nfs4_stateid_type_t cur_sid_type;
} nfs4_stateid_types_t;

/*
 * Per-zone data for dealing with callbacks.  Included here solely for the
 * benefit of MDB.
 */
struct nfs4_callback_stats {
	kstat_named_t	delegations;
	kstat_named_t	cb_getattr;
	kstat_named_t	cb_recall;
	kstat_named_t	cb_null;
	kstat_named_t	cb_dispatch;
	kstat_named_t	delegaccept_r;
	kstat_named_t	delegaccept_rw;
	kstat_named_t	delegreturn;
	kstat_named_t	callbacks;
	kstat_named_t	claim_cur;
	kstat_named_t	claim_cur_ok;
	kstat_named_t	recall_trunc;
	kstat_named_t	recall_failed;
	kstat_named_t	return_limit_write;
	kstat_named_t	return_limit_addmap;
	kstat_named_t	deleg_recover;
	kstat_named_t	cb_illegal;
};

struct nfs4_callback_globals {
	kmutex_t nfs4_cb_lock;
	kmutex_t nfs4_dlist_lock;
	int nfs4_program_hint;
	/* this table maps the program number to the nfs4_server structure */
	struct nfs4_server **nfs4prog2server;
	list_t nfs4_dlist;
	list_t nfs4_cb_ports;
	struct nfs4_callback_stats nfs4_callback_stats;
#ifdef DEBUG
	int nfs4_dlistadd_c;
	int nfs4_dlistclean_c;
#endif
};

typedef enum {
	CLOSE_NORM,
	CLOSE_DELMAP,
	CLOSE_FORCE,
	CLOSE_RESEND,
	CLOSE_AFTER_RESEND
} nfs4_close_type_t;

/*
 * Structure to hold the bad seqid information that is passed
 * to the recovery framework.
 */
typedef struct nfs4_bseqid_entry {
	nfs4_open_owner_t	*bs_oop;
	nfs4_lock_owner_t	*bs_lop;
	vnode_t			*bs_vp;
	pid_t			bs_pid;
	nfs4_tag_type_t		bs_tag;
	seqid4			bs_seqid;
	list_node_t		bs_node;
} nfs4_bseqid_entry_t;

#ifdef _KERNEL

extern void	nfs4close_one(vnode_t *, nfs4_open_stream_t *, cred_t *, int,
		    nfs4_lost_rqst_t *, nfs4_error_t *, nfs4_close_type_t,
		    size_t, uint_t, uint_t);
extern void	nfs4close_notw(vnode_t *, nfs4_open_stream_t *, int *);
extern void	nfs4_set_lock_stateid(nfs4_lock_owner_t *, stateid4);
extern void	open_owner_hold(nfs4_open_owner_t *);
extern void	open_owner_rele(nfs4_open_owner_t *);
extern nfs4_open_stream_t	*find_or_create_open_stream(nfs4_open_owner_t *,
					struct rnode4 *, int *);
extern nfs4_open_stream_t *find_open_stream(nfs4_open_owner_t *,
				struct rnode4 *);
extern nfs4_open_stream_t *create_open_stream(nfs4_open_owner_t *oop,
				struct rnode4 *rp);
extern void	open_stream_hold(nfs4_open_stream_t *);
extern void	open_stream_rele(nfs4_open_stream_t *, struct rnode4 *);
extern int	nfs4close_all(vnode_t *, cred_t *);
extern void	lock_owner_hold(nfs4_lock_owner_t *);
extern void	lock_owner_rele(nfs4_lock_owner_t *);
extern nfs4_lock_owner_t *create_lock_owner(struct rnode4 *, pid_t);
extern nfs4_lock_owner_t *find_lock_owner(struct rnode4 *, pid_t, lown_which_t);
extern void	nfs4_rnode_remove_lock_owner(struct rnode4 *,
			nfs4_lock_owner_t *);
extern void	nfs4_flush_lock_owners(struct rnode4 *);
extern void nfs4_setlockowner_args(lock_owner4 *, struct rnode4 *, pid_t);
extern void	nfs4_set_open_seqid(seqid4, nfs4_open_owner_t *,
		    nfs4_tag_type_t);
extern void	nfs4_set_lock_seqid(seqid4, nfs4_lock_owner_t *);
extern void	nfs4_get_and_set_next_open_seqid(nfs4_open_owner_t *,
		    nfs4_tag_type_t);
extern void	nfs4_end_open_seqid_sync(nfs4_open_owner_t *);
extern int	nfs4_start_open_seqid_sync(nfs4_open_owner_t *, mntinfo4_t *);
extern void	nfs4_end_lock_seqid_sync(nfs4_lock_owner_t *);
extern int	nfs4_start_lock_seqid_sync(nfs4_lock_owner_t *, mntinfo4_t *);
extern void	nfs4_setup_lock_args(nfs4_lock_owner_t *, nfs4_open_owner_t *,
			nfs4_open_stream_t *, clientid4, locker4 *);
extern void	nfs4_destroy_open_owner(nfs4_open_owner_t *);

extern void		nfs4_renew_lease_thread(nfs4_server_t *);
extern nfs4_server_t	*find_nfs4_server(mntinfo4_t *);
extern nfs4_server_t	*find_nfs4_server_all(mntinfo4_t *, int all);
extern nfs4_server_t	*new_nfs4_server(servinfo4_t *,	cred_t *);
extern void		nfs4_mark_srv_dead(nfs4_server_t *);
extern nfs4_server_t	*servinfo4_to_nfs4_server(servinfo4_t *);
extern void		nfs4_inc_state_ref_count(mntinfo4_t *);
extern void		nfs4_inc_state_ref_count_nolock(nfs4_server_t *,
				mntinfo4_t *);
extern void		nfs4_dec_state_ref_count(mntinfo4_t *);
extern void		nfs4_dec_state_ref_count_nolock(nfs4_server_t *,
				mntinfo4_t *);
extern clientid4	mi2clientid(mntinfo4_t *);
extern int		nfs4_server_in_recovery(nfs4_server_t *);
extern bool_t		nfs4_server_vlock(nfs4_server_t *, int);
extern nfs4_open_owner_t *create_open_owner(cred_t *, mntinfo4_t *);
extern uint64_t		nfs4_get_new_oo_name(void);
extern nfs4_open_owner_t *find_open_owner(cred_t *, int, mntinfo4_t *);
extern nfs4_open_owner_t *find_open_owner_nolock(cred_t *, int, mntinfo4_t *);
extern void	nfs4frlock(nfs4_lock_call_type_t, vnode_t *, int, flock64_t *,
			int, u_offset_t, cred_t *, nfs4_error_t *,
			nfs4_lost_rqst_t *, int *);
extern void	nfs4open_dg_save_lost_rqst(int, nfs4_lost_rqst_t *,
		    nfs4_open_owner_t *, nfs4_open_stream_t *, cred_t *,
		    vnode_t *, int, int);
extern void	nfs4_open_downgrade(int, int, nfs4_open_owner_t *,
		    nfs4_open_stream_t *, vnode_t *, cred_t *,
		    nfs4_lost_rqst_t *, nfs4_error_t *, cred_t **, seqid4 *);
extern seqid4	nfs4_get_open_seqid(nfs4_open_owner_t *);
extern cred_t	*nfs4_get_otw_cred(cred_t *, mntinfo4_t *, nfs4_open_owner_t *);
extern void	nfs4_init_stateid_types(nfs4_stateid_types_t *);
extern void	nfs4_save_stateid(stateid4 *, nfs4_stateid_types_t *);

extern kmutex_t nfs4_server_lst_lock;

extern void	nfs4callback_destroy(nfs4_server_t *);
extern void	nfs4_callback_init(void);
extern void	nfs4_callback_fini(void);
extern void	nfs4_cb_args(nfs4_server_t *, struct knetconfig *,
			SETCLIENTID4args *);
extern void	nfs4delegreturn_async(struct rnode4 *, int, bool_t);

extern enum nfs4_delegreturn_policy nfs4_delegreturn_policy;

extern void	nfs4_add_mi_to_server(nfs4_server_t *, mntinfo4_t *);
extern void	nfs4_remove_mi_from_server(mntinfo4_t *, nfs4_server_t *);
extern nfs4_server_t *nfs4_move_mi(mntinfo4_t *, servinfo4_t *, servinfo4_t *);
extern bool_t	nfs4_fs_active(nfs4_server_t *);
extern void	nfs4_server_rele(nfs4_server_t *);
extern bool_t	inlease(nfs4_server_t *);
extern bool_t	nfs4_has_pages(vnode_t *);
extern void	nfs4_log_badowner(mntinfo4_t *, nfs_opnum4);

#endif /* _KERNEL */

/*
 * Client State Recovery
 */

/*
 * The following defines are used for rs_flags in
 * a nfs4_recov_state_t structure.
 *
 * NFS4_RS_RENAME_HELD		Indicates that the mi_rename_lock was held.
 * NFS4_RS_GRACE_MSG		Set once we have uprintf'ed a grace message.
 * NFS4_RS_DELAY_MSG		Set once we have uprintf'ed a delay message.
 * NFS4_RS_RECALL_HELD1		r_deleg_recall_lock for vp1 was held.
 * NFS4_RS_RECALL_HELD2		r_deleg_recall_lock for vp2 was held.
 */
#define	NFS4_RS_RENAME_HELD	0x000000001
#define	NFS4_RS_GRACE_MSG	0x000000002
#define	NFS4_RS_DELAY_MSG	0x000000004
#define	NFS4_RS_RECALL_HELD1	0x000000008
#define	NFS4_RS_RECALL_HELD2	0x000000010

/*
 * Information that is retrieved from nfs4_start_op() and that is
 * passed into nfs4_end_op().
 *
 * rs_sp is a reference to the nfs4_server that was found, or NULL.
 *
 * rs_num_retry_despite_err is the number times client retried an
 * OTW op despite a recovery error.  It is only incremented for hints
 * exempt to normal R4RECOVERR processing
 * (OH_CLOSE/OH_LOCKU/OH_DELEGRETURN).  (XXX this special-case code
 * needs review for possible removal.)
 * It is initialized wherever nfs4_recov_state_t is declared -- usually
 * very near initialization of rs_flags.
 */
typedef struct {
	nfs4_server_t	*rs_sp;
	int		rs_flags;
	int		rs_num_retry_despite_err;
} nfs4_recov_state_t;

/*
 * Flags for nfs4_check_remap, nfs4_remap_file and nfs4_remap_root.
 */

#define	NFS4_REMAP_CKATTRS	1
#define	NFS4_REMAP_NEEDSOP	2

#ifdef _KERNEL

extern int	nfs4_is_otw_open_necessary(nfs4_open_owner_t *, int,
			vnode_t *, int, int *, int, nfs4_recov_state_t *);
extern void	nfs4setclientid(struct mntinfo4 *, struct cred *, bool_t,
			nfs4_error_t *);
extern void	nfs4_reopen(vnode_t *, nfs4_open_stream_t *, nfs4_error_t *,
			open_claim_type4, bool_t, bool_t);
extern void	nfs4_remap_root(struct mntinfo4 *, nfs4_error_t *, int);
extern void	nfs4_check_remap(mntinfo4_t *mi, vnode_t *vp, int,
			nfs4_error_t *);
extern void	nfs4_remap_file(mntinfo4_t *mi, vnode_t *vp, int,
			nfs4_error_t *);
extern int	nfs4_make_dotdot(struct nfs4_sharedfh *, hrtime_t,
			vnode_t *, cred_t *, vnode_t **, int);
extern void	nfs4_fail_recov(vnode_t *, char *, int, nfsstat4);

extern int	nfs4_needs_recovery(nfs4_error_t *, bool_t, vfs_t *);
extern int	nfs4_recov_marks_dead(nfsstat4);
extern bool_t	nfs4_start_recovery(nfs4_error_t *, struct mntinfo4 *,
			vnode_t *, vnode_t *, stateid4 *,
			nfs4_lost_rqst_t *, nfs_opnum4, nfs4_bseqid_entry_t *,
			vnode_t *, char *);
extern int	nfs4_start_op(struct mntinfo4 *, vnode_t *, vnode_t *,
			nfs4_recov_state_t *);
extern void	nfs4_end_op(struct mntinfo4 *, vnode_t *, vnode_t *,
			nfs4_recov_state_t *, bool_t);
extern int	nfs4_start_fop(struct mntinfo4 *, vnode_t *, vnode_t *,
			nfs4_op_hint_t, nfs4_recov_state_t *, bool_t *);
extern void	nfs4_end_fop(struct mntinfo4 *, vnode_t *, vnode_t *,
				nfs4_op_hint_t, nfs4_recov_state_t *, bool_t);
extern char	*nfs4_recov_action_to_str(nfs4_recov_t);

/*
 * In sequence, code desiring to unmount an ephemeral tree must
 * call nfs4_ephemeral_umount, nfs4_ephemeral_umount_activate,
 * and nfs4_ephemeral_umount_unlock. The _unlock must also be
 * called on all error paths that occur before it would naturally
 * be invoked.
 *
 * The caller must also provde a pointer to a boolean to keep track
 * of whether or not the code in _unlock is to be ran.
 */
extern void	nfs4_ephemeral_umount_activate(mntinfo4_t *,
    bool_t *, nfs4_ephemeral_tree_t **);
extern int	nfs4_ephemeral_umount(mntinfo4_t *, int, cred_t *,
    bool_t *, nfs4_ephemeral_tree_t **);
extern void	nfs4_ephemeral_umount_unlock(bool_t *,
    nfs4_ephemeral_tree_t **);

extern int	nfs4_record_ephemeral_mount(mntinfo4_t *mi, vnode_t *mvp);

extern int	nfs4_callmapid(utf8string *, struct nfs_fsl_info *);
extern int	nfs4_fetch_locations(mntinfo4_t *, struct nfs4_sharedfh *,
    char *, cred_t *, nfs4_ga_res_t *, COMPOUND4res_clnt *, bool_t);

extern int	wait_for_recall(vnode_t *, vnode_t *, nfs4_op_hint_t,
			nfs4_recov_state_t *);
extern void	nfs4_end_op_recall(vnode_t *, vnode_t *, nfs4_recov_state_t *);
extern void	nfs4_send_siglost(pid_t, mntinfo4_t *mi, vnode_t *vp, bool_t,
		    int, nfsstat4);
extern time_t	nfs4err_delay_time;
extern void	nfs4_set_grace_wait(mntinfo4_t *);
extern void	nfs4_set_delay_wait(vnode_t *);
extern int	nfs4_wait_for_grace(mntinfo4_t *, nfs4_recov_state_t *);
extern int	nfs4_wait_for_delay(vnode_t *, nfs4_recov_state_t *);
extern nfs4_bseqid_entry_t *nfs4_create_bseqid_entry(nfs4_open_owner_t *,
		    nfs4_lock_owner_t *, vnode_t *, pid_t, nfs4_tag_type_t,
		    seqid4);

extern void	nfs4_resend_open_otw(vnode_t **, nfs4_lost_rqst_t *,
			nfs4_error_t *);
extern void	nfs4_resend_delegreturn(nfs4_lost_rqst_t *, nfs4_error_t *,
			nfs4_server_t *);
extern int	nfs4_rpc_retry_error(int);
extern int	nfs4_try_failover(nfs4_error_t *);
extern void	nfs4_free_msg(nfs4_debug_msg_t *);
extern void	nfs4_mnt_recov_kstat_init(vfs_t *);
extern void	nfs4_mi_kstat_inc_delay(mntinfo4_t *);
extern void	nfs4_mi_kstat_inc_no_grace(mntinfo4_t *);
extern char	*nfs4_stat_to_str(nfsstat4);
extern char	*nfs4_op_to_str(nfs_opnum4);

extern void	nfs4_queue_event(nfs4_event_type_t, mntinfo4_t *, char *,
		    uint_t, vnode_t *, vnode_t *, nfsstat4, char *, pid_t,
		    nfs4_tag_type_t, nfs4_tag_type_t, seqid4, seqid4);
extern void	nfs4_queue_fact(nfs4_fact_type_t, mntinfo4_t *, nfsstat4,
		    nfs4_recov_t, nfs_opnum4, bool_t, char *, int, vnode_t *);
#pragma	rarely_called(nfs4_queue_event)
#pragma	rarely_called(nfs4_queue_fact)

/* Used for preformed "." and ".." dirents */
extern char	*nfs4_dot_entries;
extern char	*nfs4_dot_dot_entry;

#ifdef	DEBUG
extern uint_t	nfs4_tsd_key;
#endif

#endif /* _KERNEL */

/*
 * Filehandle management.
 *
 * Filehandles can change in v4, so rather than storing the filehandle
 * directly in the rnode, etc., we manage the filehandle through one of
 * these objects.
 * Locking: sfh_fh and sfh_tree is protected by the filesystem's
 * mi_fh_lock.  The reference count and flags are protected by sfh_lock.
 * sfh_mi is read-only.
 *
 * mntinfo4_t::mi_fh_lock > sfh_lock.
 */

typedef struct nfs4_sharedfh {
	nfs_fh4 sfh_fh;			/* key and current filehandle */
	kmutex_t sfh_lock;
	uint_t sfh_refcnt;		/* reference count */
	uint_t sfh_flags;
	mntinfo4_t *sfh_mi;		/* backptr to filesystem */
	avl_node_t sfh_tree;		/* used by avl package */
} nfs4_sharedfh_t;

#define	SFH4_SAME(sfh1, sfh2)	((sfh1) == (sfh2))

/*
 * Flags.
 */
#define	SFH4_IN_TREE	0x1		/* currently in an AVL tree */

#ifdef _KERNEL

extern void sfh4_createtab(avl_tree_t *);
extern nfs4_sharedfh_t *sfh4_get(const nfs_fh4 *, mntinfo4_t *);
extern nfs4_sharedfh_t *sfh4_put(const nfs_fh4 *, mntinfo4_t *,
				nfs4_sharedfh_t *);
extern void sfh4_update(nfs4_sharedfh_t *, const nfs_fh4 *);
extern void sfh4_copyval(const nfs4_sharedfh_t *, nfs4_fhandle_t *);
extern void sfh4_hold(nfs4_sharedfh_t *);
extern void sfh4_rele(nfs4_sharedfh_t **);
extern void sfh4_printfhandle(const nfs4_sharedfh_t *);

#endif

/*
 * Path and file name management.
 *
 * This type stores the name of an entry in the filesystem and keeps enough
 * information that it can provide a complete path.  All fields are
 * protected by fn_lock, except for the reference count, which is managed
 * using atomic add/subtract.
 *
 * Additionally shared filehandle for this fname is stored.
 * Normally, fn_get() when it creates this fname stores the passed in
 * shared fh in fn_sfh by doing sfh_hold. Similarly the path which
 * destroys this fname releases the reference on this fh by doing sfh_rele.
 *
 * fn_get uses the fn_sfh to refine the comparision in cases
 * where we have matched the name but have differing file handles,
 * this normally happens due to
 *
 *	1. Server side rename of a file/directory.
 *	2. Another client renaming a file/directory on the server.
 *
 * Differing names but same filehandle is possible as in the case of hardlinks,
 * but differing filehandles with same name component will later confuse
 * the client and can cause various panics.
 *
 * Lock order: child and then parent.
 */

typedef struct nfs4_fname {
	struct nfs4_fname *fn_parent;	/* parent name; null if fs root */
	char *fn_name;			/* the actual name */
	ssize_t fn_len;			/* strlen(fn_name) */
	uint32_t fn_refcnt;		/* reference count */
	kmutex_t fn_lock;
	avl_node_t fn_tree;
	avl_tree_t fn_children;		/* children, if any */
	nfs4_sharedfh_t *fn_sfh;	/* The fh for this fname */
} nfs4_fname_t;

#ifdef _KERNEL

extern vnode_t	nfs4_xattr_notsupp_vnode;
#define	NFS4_XATTR_DIR_NOTSUPP	&nfs4_xattr_notsupp_vnode

extern nfs4_fname_t *fn_get(nfs4_fname_t *, char *, nfs4_sharedfh_t *);
extern void fn_hold(nfs4_fname_t *);
extern void fn_rele(nfs4_fname_t **);
extern char *fn_name(nfs4_fname_t *);
extern char *fn_path(nfs4_fname_t *);
extern void fn_move(nfs4_fname_t *, nfs4_fname_t *, char *);
extern nfs4_fname_t *fn_parent(nfs4_fname_t *);

/* Referral Support */
extern int nfs4_process_referral(mntinfo4_t *, nfs4_sharedfh_t *, char *,
    cred_t *, nfs4_ga_res_t *, COMPOUND4res_clnt *, struct nfs_fsl_info *);

#endif

/*
 * Per-zone data for managing client handles, included in this file for the
 * benefit of MDB.
 */
struct nfs4_clnt {
	struct chhead	*nfscl_chtable4;
	kmutex_t	nfscl_chtable4_lock;
	zoneid_t	nfscl_zoneid;
	list_node_t	nfscl_node;
	struct clstat4	nfscl_stat;
};

#ifdef	__cplusplus
}
#endif

#endif /* _NFS4_CLNT_H */
