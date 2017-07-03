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
 * Copyright (c) 1986, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef	_NFS_NFS_CLNT_H
#define	_NFS_NFS_CLNT_H

#include <sys/utsname.h>
#include <sys/kstat.h>
#include <sys/time.h>
#include <vm/page.h>
#include <sys/thread.h>
#include <nfs/rnode.h>
#include <sys/list.h>
#include <sys/condvar_impl.h>
#include <sys/zone.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	HOSTNAMESZ	32
#define	ACREGMIN	3	/* min secs to hold cached file attr */
#define	ACREGMAX	60	/* max secs to hold cached file attr */
#define	ACDIRMIN	30	/* min secs to hold cached dir attr */
#define	ACDIRMAX	60	/* max secs to hold cached dir attr */
#define	ACMINMAX	3600	/* 1 hr is longest min timeout */
#define	ACMAXMAX	36000	/* 10 hr is longest max timeout */

#define	NFS_CALLTYPES	3	/* Lookups, Reads, Writes */

/*
 * rfscall() flags
 */
#define	RFSCALL_SOFT	0x00000001	/* Do op as if fs was soft-mounted */

/*
 * Fake errno passed back from rfscall to indicate transfer size adjustment
 */
#define	ENFS_TRYAGAIN	999

/*
 * The NFS specific async_reqs structure. iotype is grouped to support two
 * types of async thread pools, please read comments section of mntinfo_t
 * definition for more information. Care should be taken while adding new
 * members to this group.
 */

enum iotype {
	NFS_PUTAPAGE,
	NFS_PAGEIO,
	NFS_COMMIT,
	NFS_READ_AHEAD,
	NFS_READDIR,
	NFS_INACTIVE,
	NFS_ASYNC_TYPES
};
#define	NFS_ASYNC_PGOPS_TYPES	(NFS_COMMIT + 1)

/*
 * NFS async requests queue type.
 */

enum ioqtype {
	NFS_ASYNC_QUEUE,
	NFS_ASYNC_PGOPS_QUEUE,
	NFS_MAX_ASYNC_QUEUES
};

/*
 * Number of NFS async threads operating exclusively on page op requests.
 */
#define	NUM_ASYNC_PGOPS_THREADS	0x2

struct nfs_async_read_req {
	void (*readahead)();		/* pointer to readahead function */
	u_offset_t blkoff;		/* offset in file */
	struct seg *seg;		/* segment to do i/o to */
	caddr_t addr;			/* address to do i/o to */
};

struct nfs_pageio_req {
	int (*pageio)();		/* pointer to pageio function */
	page_t *pp;			/* page list */
	u_offset_t io_off;		/* offset in file */
	uint_t io_len;			/* size of request */
	int flags;
};

struct nfs_readdir_req {
	int (*readdir)();		/* pointer to readdir function */
	struct rddir_cache *rdc;	/* pointer to cache entry to fill */
};

struct nfs_commit_req {
	void (*commit)();		/* pointer to commit function */
	page_t *plist;			/* page list */
	offset3 offset;			/* starting offset */
	count3 count;			/* size of range to be commited */
};

struct nfs_inactive_req {
	void (*inactive)();		/* pointer to inactive function */
};

struct nfs_async_reqs {
	struct nfs_async_reqs *a_next;	/* pointer to next arg struct */
#ifdef DEBUG
	kthread_t *a_queuer;		/* thread id of queueing thread */
#endif
	struct vnode *a_vp;		/* vnode pointer */
	struct cred *a_cred;		/* cred pointer */
	enum iotype a_io;		/* i/o type */
	union {
		struct nfs_async_read_req a_read_args;
		struct nfs_pageio_req a_pageio_args;
		struct nfs_readdir_req a_readdir_args;
		struct nfs_commit_req a_commit_args;
		struct nfs_inactive_req a_inactive_args;
	} a_args;
};

#define	a_nfs_readahead a_args.a_read_args.readahead
#define	a_nfs_blkoff a_args.a_read_args.blkoff
#define	a_nfs_seg a_args.a_read_args.seg
#define	a_nfs_addr a_args.a_read_args.addr

#define	a_nfs_putapage a_args.a_pageio_args.pageio
#define	a_nfs_pageio a_args.a_pageio_args.pageio
#define	a_nfs_pp a_args.a_pageio_args.pp
#define	a_nfs_off a_args.a_pageio_args.io_off
#define	a_nfs_len a_args.a_pageio_args.io_len
#define	a_nfs_flags a_args.a_pageio_args.flags

#define	a_nfs_readdir a_args.a_readdir_args.readdir
#define	a_nfs_rdc a_args.a_readdir_args.rdc

#define	a_nfs_commit a_args.a_commit_args.commit
#define	a_nfs_plist a_args.a_commit_args.plist
#define	a_nfs_offset a_args.a_commit_args.offset
#define	a_nfs_count a_args.a_commit_args.count

#define	a_nfs_inactive a_args.a_inactive_args.inactive

/*
 * Due to the way the address space callbacks are used to execute a delmap,
 * we must keep track of how many times the same thread has called
 * VOP_DELMAP()->nfs_delmap()/nfs3_delmap().  This is done by having a list of
 * nfs_delmapcall_t's associated with each rnode_t.  This list is protected
 * by the rnode_t's r_statelock.  The individual elements do not need to be
 * protected as they will only ever be created, modified and destroyed by
 * one thread (the call_id).
 * See nfs_delmap()/nfs3_delmap() for further explanation.
 */
typedef struct nfs_delmapcall {
	kthread_t	*call_id;
	int		error;	/* error from delmap */
	list_node_t	call_node;
} nfs_delmapcall_t;

/*
 * delmap address space callback args
 */
typedef struct nfs_delmap_args {
	vnode_t			*vp;
	offset_t		off;
	caddr_t			addr;
	size_t			len;
	uint_t			prot;
	uint_t			maxprot;
	uint_t			flags;
	cred_t			*cr;
	nfs_delmapcall_t	*caller; /* to retrieve errors from the cb */
} nfs_delmap_args_t;

#ifdef _KERNEL
extern nfs_delmapcall_t	*nfs_init_delmapcall(void);
extern void	nfs_free_delmapcall(nfs_delmapcall_t *);
extern int	nfs_find_and_delete_delmapcall(rnode_t *, int *errp);
#endif /* _KERNEL */

/*
 * The following structures, chhead and chtab,  make up the client handle
 * cache.  chhead represents a quadruple(RPC program, RPC version, Protocol
 * Family, and Transport).  For example, a chhead entry could represent
 * NFS/V3/IPv4/TCP requests.  chhead nodes are linked together as a singly
 * linked list and is referenced from chtable.
 *
 * chtab represents an allocated client handle bound to a particular
 * quadruple. These nodes chain down from a chhead node.  chtab
 * entries which are on the chain are considered free, so a thread may simply
 * unlink the first node without traversing the chain.  When the thread is
 * completed with its request, it puts the chtab node back on the chain.
 */
typedef struct chhead {
	struct chhead *ch_next;	/* next quadruple */
	struct chtab *ch_list;	/* pointer to free client handle(s) */
	uint64_t ch_timesused;	/* times this quadruple was requested */
	rpcprog_t ch_prog;	/* RPC program number */
	rpcvers_t ch_vers;	/* RPC version number */
	dev_t ch_dev;		/* pseudo device number (i.e. /dev/udp) */
	char *ch_protofmly;	/* protocol (i.e. NC_INET, NC_LOOPBACK) */
} chhead_t;

typedef struct chtab {
	struct chtab *ch_list;	/* next free client handle */
	struct chhead *ch_head;	/* associated quadruple */
	time_t ch_freed;	/* timestamp when freed */
	CLIENT *ch_client;	/* pointer to client handle */
} chtab_t;

/*
 * clinfo is a structure which encapsulates data that is needed to
 * obtain a client handle from the cache
 */
typedef struct clinfo {
	rpcprog_t cl_prog;	/* RPC program number */
	rpcvers_t cl_vers;	/* RPC version number */
	uint_t cl_readsize;	/* transfer size */
	int cl_retrans;		/* times to retry request */
	uint_t cl_flags;	/* info flags */
} clinfo_t;

/*
 * Failover information, passed opaquely through rfscall()
 */
typedef struct failinfo {
	struct vnode	*vp;
	caddr_t		fhp;
	void (*copyproc)(caddr_t, vnode_t *);
	int (*lookupproc)(vnode_t *, char *, vnode_t **, struct pathname *,
			int, vnode_t *, struct cred *, int);
	int (*xattrdirproc)(vnode_t *, vnode_t **, bool_t, cred_t *, int);
} failinfo_t;

/*
 * Static server information
 *
 * These fields are protected by sv_lock:
 *	sv_flags
 */
typedef struct servinfo {
	struct knetconfig *sv_knconf;   /* bound TLI fd */
	struct knetconfig *sv_origknconf;	/* For RDMA save orig knconf */
	struct netbuf	sv_addr;	/* server's address */
	nfs_fhandle	sv_fhandle;	/* this server's filehandle */
	struct sec_data *sv_secdata;	/* security data for rpcsec module */
	char	*sv_hostname;		/* server's hostname */
	int	sv_hostnamelen;		/* server's hostname length */
	uint_t	sv_flags;		/* see below */
	struct servinfo	*sv_next;	/* next in list */
	kmutex_t sv_lock;
} servinfo_t;

/*
 * The values for sv_flags.
 */
#define	SV_ROOT_STALE	0x1		/* root vnode got ESTALE */

/*
 * Switch from RDMA knconf to original mount knconf
 */

#define	ORIG_KNCONF(mi) (mi->mi_curr_serv->sv_origknconf ? \
	mi->mi_curr_serv->sv_origknconf : mi->mi_curr_serv->sv_knconf)

#if	defined(_KERNEL)
/*
 * NFS private data per mounted file system
 *	The mi_lock mutex protects the following fields:
 *		mi_flags
 *		mi_printed
 *		mi_down
 *		mi_tsize
 *		mi_stsize
 *		mi_curread
 *		mi_curwrite
 *		mi_timers
 *		mi_curr_serv
 *		mi_readers
 *		mi_klmconfig
 *
 *	The mi_async_lock mutex protects the following fields:
 *		mi_async_reqs
 *		mi_async_req_count
 *		mi_async_tail
 *		mi_async_curr[NFS_MAX_ASYNC_QUEUES]
 *		mi_async_clusters
 *		mi_async_init_clusters
 *		mi_threads[NFS_MAX_ASYNC_QUEUES]
 *		mi_manager_thread
 *
 *	Normally the netconfig information for the mount comes from
 *	mi_curr_serv and mi_klmconfig is NULL.  If NLM calls need to use a
 *	different transport, mi_klmconfig contains the necessary netconfig
 *	information.
 *
 *	'mi_zone' is initialized at structure creation time, and never
 *	changes; it may be read without a lock.
 *
 *	mi_zone_node is linkage into the mi4_globals.mig_list, and is
 *	protected by mi4_globals.mig_list_lock.
 *
 *	Locking order:
 *	  mi_globals::mig_lock > mi_async_lock > mi_lock
 */
typedef struct mntinfo {
	kmutex_t	mi_lock;	/* protects mntinfo fields */
	struct servinfo *mi_servers;    /* server list */
	struct servinfo *mi_curr_serv;  /* current server */
	kcondvar_t	mi_failover_cv;	/* failover synchronization */
	int		mi_readers;	/* failover - users of mi_curr_serv */
	struct vfs	*mi_vfsp;	/* back pointer to vfs */
	enum vtype	mi_type;	/* file type of the root vnode */
	uint_t		mi_flags;	/* see below */
	uint_t		mi_tsize;	/* max read transfer size (bytes) */
	uint_t		mi_stsize;	/* max write transfer size (bytes) */
	int		mi_timeo;	/* inital timeout in 10th sec */
	int		mi_retrans;	/* times to retry request */
	hrtime_t	mi_acregmin;	/* min time to hold cached file attr */
	hrtime_t	mi_acregmax;	/* max time to hold cached file attr */
	hrtime_t	mi_acdirmin;	/* min time to hold cached dir attr */
	hrtime_t	mi_acdirmax;	/* max time to hold cached dir attr */
	len_t		mi_maxfilesize; /* for pathconf _PC_FILESIZEBITS */
	/*
	 * Extra fields for congestion control, one per NFS call type,
	 * plus one global one.
	 */
	struct rpc_timers mi_timers[NFS_CALLTYPES+1];
	int		mi_curread;	/* current read size */
	int		mi_curwrite;	/* current write size */
	/*
	 * Async I/O management
	 * We have 2 pools of threads working on async I/O:
	 *	(i) Threads which work on all async queues. Default number of
	 *	threads in this queue is 8. Threads in this pool work on async
	 *	queue pointed by mi_async_curr[NFS_ASYNC_QUEUE]. Number of
	 *	active threads in this pool is tracked by
	 *	mi_threads[NFS_ASYNC_QUEUE].
	 * 	(ii)Threads which work only on page op async queues.
	 *	Page ops queue comprises of NFS_PUTAPAGE, NFS_PAGEIO &
	 *	NFS_COMMIT. Default number of threads in this queue is 2
	 *	(NUM_ASYNC_PGOPS_THREADS). Threads in this pool work on async
	 *	queue pointed by mi_async_curr[NFS_ASYNC_PGOPS_QUEUE]. Number
	 *	of active threads in this pool is tracked by
	 *	mi_threads[NFS_ASYNC_PGOPS_QUEUE].
	 */
	struct nfs_async_reqs *mi_async_reqs[NFS_ASYNC_TYPES];
	struct nfs_async_reqs *mi_async_tail[NFS_ASYNC_TYPES];
	struct nfs_async_reqs **mi_async_curr[NFS_MAX_ASYNC_QUEUES];
						/* current async queue */
	uint_t		mi_async_clusters[NFS_ASYNC_TYPES];
	uint_t		mi_async_init_clusters;
	uint_t		mi_async_req_count; /* # outstanding work requests */
	kcondvar_t	mi_async_reqs_cv; /* signaled when there's work */
	ushort_t	mi_threads[NFS_MAX_ASYNC_QUEUES];
					/* number of active async threads */
	ushort_t	mi_max_threads;	/* max number of async worker threads */
	kthread_t	*mi_manager_thread;  /* async manager thread */
	kcondvar_t	mi_async_cv; /* signaled when the last worker dies */
	kcondvar_t	mi_async_work_cv[NFS_MAX_ASYNC_QUEUES];
					/* tell workers to work */
	kmutex_t	mi_async_lock;	/* lock to protect async list */
	/*
	 * Other stuff
	 */
	struct pathcnf *mi_pathconf;	/* static pathconf kludge */
	rpcprog_t	mi_prog;	/* RPC program number */
	rpcvers_t	mi_vers;	/* RPC program version number */
	char		**mi_rfsnames;	/* mapping to proc names */
	kstat_named_t	*mi_reqs;	/* count of requests */
	uchar_t		*mi_call_type;	/* dynamic retrans call types */
	uchar_t		*mi_ss_call_type;	/* semisoft call type */
	uchar_t		*mi_timer_type;	/* dynamic retrans timer types */
	clock_t		mi_printftime;	/* last error printf time */
	/*
	 * ACL entries
	 */
	char		**mi_aclnames;	/* mapping to proc names */
	kstat_named_t	*mi_aclreqs;	/* count of acl requests */
	uchar_t		*mi_acl_call_type; /* dynamic retrans call types */
	uchar_t		*mi_acl_ss_call_type; /* semisoft call types */
	uchar_t		*mi_acl_timer_type; /* dynamic retrans timer types */
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
	struct knetconfig *mi_klmconfig;
	/*
	 * Zones support.
	 */
	struct zone	*mi_zone;	/* Zone in which FS is mounted */
	zone_ref_t	mi_zone_ref;	/* Reference to aforementioned zone */
	list_node_t	mi_zone_node;	/* Linkage into per-zone mi list */
	/*
	 * Serializes threads in failover_remap.
	 * Need to acquire this lock first in failover_remap() function
	 * before acquiring any other rnode lock.
	 */
	kmutex_t	mi_remap_lock;
} mntinfo_t;
#endif	/* _KERNEL */

/*
 * vfs pointer to mount info
 */
#define	VFTOMI(vfsp)	((mntinfo_t *)((vfsp)->vfs_data))

/*
 * vnode pointer to mount info
 */
#define	VTOMI(vp)	((mntinfo_t *)(((vp)->v_vfsp)->vfs_data))

/*
 * The values for mi_flags.
 */
#define	MI_HARD		0x1		/* hard or soft mount */
#define	MI_PRINTED	0x2		/* not responding message printed */
#define	MI_INT		0x4		/* interrupts allowed on hard mount */
#define	MI_DOWN		0x8		/* server is down */
#define	MI_NOAC		0x10		/* don't cache attributes */
#define	MI_NOCTO	0x20		/* no close-to-open consistency */
#define	MI_DYNAMIC	0x40		/* dynamic transfer size adjustment */
#define	MI_LLOCK	0x80		/* local locking only (no lockmgr) */
#define	MI_GRPID	0x100		/* System V group id inheritance */
#define	MI_RPCTIMESYNC	0x200		/* RPC time sync */
#define	MI_LINK		0x400		/* server supports link */
#define	MI_SYMLINK	0x800		/* server supports symlink */
#define	MI_READDIRONLY	0x1000		/* use readdir instead of readdirplus */
#define	MI_ACL		0x2000		/* server supports NFS_ACL */
#define	MI_BINDINPROG	0x4000		/* binding to server is changing */
#define	MI_LOOPBACK	0x8000		/* Set if this is a loopback mount */
#define	MI_SEMISOFT	0x10000		/* soft reads, hard modify */
#define	MI_NOPRINT	0x20000		/* don't print messages */
#define	MI_DIRECTIO	0x40000		/* do direct I/O */
#define	MI_EXTATTR	0x80000		/* server supports extended attrs */
#define	MI_ASYNC_MGR_STOP	0x100000	/* tell async mgr to die */
#define	MI_DEAD		0x200000	/* mount has been terminated */

/*
 * Read-only mntinfo statistics
 */
struct mntinfo_kstat {
	char		mik_proto[KNC_STRSIZE];
	uint32_t	mik_vers;
	uint_t		mik_flags;
	uint_t		mik_secmod;
	uint32_t	mik_curread;
	uint32_t	mik_curwrite;
	int		mik_timeo;
	int		mik_retrans;
	uint_t		mik_acregmin;
	uint_t		mik_acregmax;
	uint_t		mik_acdirmin;
	uint_t		mik_acdirmax;
	struct {
		uint32_t srtt;
		uint32_t deviate;
		uint32_t rtxcur;
	} mik_timers[NFS_CALLTYPES+1];
	uint32_t	mik_noresponse;
	uint32_t	mik_failover;
	uint32_t	mik_remap;
	char		mik_curserver[SYS_NMLN];
};

/*
 * Macro to wakeup sleeping async worker threads.
 */
#define	NFS_WAKE_ASYNC_WORKER(work_cv)	{				\
	if (CV_HAS_WAITERS(&work_cv[NFS_ASYNC_QUEUE]))			\
		cv_signal(&work_cv[NFS_ASYNC_QUEUE]);			\
	else if (CV_HAS_WAITERS(&work_cv[NFS_ASYNC_PGOPS_QUEUE]))	\
		cv_signal(&work_cv[NFS_ASYNC_PGOPS_QUEUE]);		\
}

#define	NFS_WAKEALL_ASYNC_WORKERS(work_cv) {				\
	cv_broadcast(&work_cv[NFS_ASYNC_QUEUE]);			\
	cv_broadcast(&work_cv[NFS_ASYNC_PGOPS_QUEUE]);			\
}

/*
 * Mark cached attributes as timed out
 *
 * The caller must not be holding the rnode r_statelock mutex.
 */
#define	PURGE_ATTRCACHE(vp)	{				\
	rnode_t *rp = VTOR(vp);					\
	mutex_enter(&rp->r_statelock);				\
	PURGE_ATTRCACHE_LOCKED(rp);				\
	mutex_exit(&rp->r_statelock);				\
}

#define	PURGE_ATTRCACHE_LOCKED(rp)	{			\
	ASSERT(MUTEX_HELD(&rp->r_statelock));			\
	rp->r_attrtime = gethrtime();				\
	rp->r_mtime = rp->r_attrtime;				\
}

/*
 * Is the attribute cache valid?
 */
#define	ATTRCACHE_VALID(vp)	(gethrtime() < VTOR(vp)->r_attrtime)

/*
 * Flags to indicate whether to purge the DNLC for non-directory vnodes
 * in a call to nfs_purge_caches.
 */
#define	NFS_NOPURGE_DNLC	0
#define	NFS_PURGE_DNLC		1

/*
 * If returned error is ESTALE flush all caches.
 */
#define	PURGE_STALE_FH(error, vp, cr)				\
	if ((error) == ESTALE) {				\
		struct rnode *rp = VTOR(vp);			\
		if (vp->v_flag & VROOT) {			\
			servinfo_t *svp = rp->r_server;		\
			mutex_enter(&svp->sv_lock);		\
			svp->sv_flags |= SV_ROOT_STALE;		\
			mutex_exit(&svp->sv_lock);		\
		}						\
		mutex_enter(&rp->r_statelock);			\
		rp->r_flags |= RSTALE;				\
		if (!rp->r_error)				\
			rp->r_error = (error);			\
		mutex_exit(&rp->r_statelock);			\
		if (vn_has_cached_data(vp))			\
			nfs_invalidate_pages((vp), (u_offset_t)0, (cr)); \
		nfs_purge_caches((vp), NFS_PURGE_DNLC, (cr));	\
	}

/*
 * Is cache valid?
 * Swap is always valid, if no attributes (attrtime == 0) or
 * if mtime matches cached mtime it is valid
 * NOTE: mtime is now a timestruc_t.
 * Caller should be holding the rnode r_statelock mutex.
 */
#define	CACHE_VALID(rp, mtime, fsize)				\
	((RTOV(rp)->v_flag & VISSWAP) == VISSWAP ||		\
	(((mtime).tv_sec == (rp)->r_attr.va_mtime.tv_sec &&	\
	(mtime).tv_nsec == (rp)->r_attr.va_mtime.tv_nsec) &&	\
	((fsize) == (rp)->r_attr.va_size)))

/*
 * Macro to detect forced unmount or a zone shutdown.
 */
#define	FS_OR_ZONE_GONE(vfsp) \
	(((vfsp)->vfs_flag & VFS_UNMOUNTED) || \
	zone_status_get(curproc->p_zone) >= ZONE_IS_SHUTTING_DOWN)

/*
 * Convert NFS tunables to hrtime_t units, seconds to nanoseconds.
 */
#define	SEC2HR(sec)	((sec) * (long long)NANOSEC)
#define	HR2SEC(hr)	((hr) / (long long)NANOSEC)

/*
 * Structure to identify owner of a PC file share reservation.
 */
struct nfs_owner {
	int	magic;		/* magic uniquifying number */
	char	hname[16];	/* first 16 bytes of hostname */
	char	lowner[8];	/* local owner from fcntl */
};

/*
 * Values for magic.
 */
#define	NFS_OWNER_MAGIC	0x1D81E

/*
 * Support for extended attributes
 */
#define	XATTR_DIR_NAME	"/@/"		/* used for DNLC entries */
#define	XATTR_RPATH	"ExTaTtR"	/* used for r_path for failover */

/*
 * Short hand for checking to see whether the file system was mounted
 * interruptible or not.
 */
#define	INTR(vp)	(VTOMI(vp)->mi_flags & MI_INT)

/*
 * Short hand for checking whether failover is enabled or not
 */
#define	FAILOVER_MOUNT(mi)	(mi->mi_servers->sv_next)

/*
 * How long will async threads wait for additional work.
 */
#define	NFS_ASYNC_TIMEOUT	(60 * 1 * hz)	/* 1 minute */

#ifdef _KERNEL
extern int	clget(clinfo_t *, servinfo_t *, cred_t *, CLIENT **,
		    struct chtab **);
extern void	clfree(CLIENT *, struct chtab *);
extern void	nfs_mi_zonelist_add(mntinfo_t *);
extern void	nfs_free_mi(mntinfo_t *);
extern void	nfs_mnt_kstat_init(struct vfs *);
#endif

/*
 * Per-zone data for managing client handles.  Included here solely for the
 * benefit of MDB.
 */
/*
 * client side statistics
 */
struct clstat {
	kstat_named_t	calls;			/* client requests */
	kstat_named_t	badcalls;		/* rpc failures */
	kstat_named_t	clgets;			/* client handle gets */
	kstat_named_t	cltoomany;		/* client handle cache misses */
#ifdef DEBUG
	kstat_named_t	clalloc;		/* number of client handles */
	kstat_named_t	noresponse;		/* server not responding cnt */
	kstat_named_t	failover;		/* server failover count */
	kstat_named_t	remap;			/* server remap count */
#endif
};

struct nfs_clnt {
	struct chhead	*nfscl_chtable;
	kmutex_t	nfscl_chtable_lock;
	zoneid_t	nfscl_zoneid;
	list_node_t	nfscl_node;
	struct clstat	nfscl_stat;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _NFS_NFS_CLNT_H */
