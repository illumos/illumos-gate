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
 *	Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef	_NFS_RNODE4_H
#define	_NFS_RNODE4_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <nfs/rnode.h>		/* for symlink_cache, nfs_rwlock_t, etc. */
#include <nfs/nfs4.h>
#include <nfs/nfs4_clnt.h>
#include <sys/thread.h>
#include <sys/sysmacros.h>	/* for offsetof */

typedef enum nfs4_stub_type {
	NFS4_STUB_NONE,
	NFS4_STUB_MIRRORMOUNT,
	NFS4_STUB_REFERRAL
} nfs4_stub_type_t;

typedef enum nfs4_access_type {
	NFS4_ACCESS_UNKNOWN,
	NFS4_ACCESS_ALLOWED,
	NFS4_ACCESS_DENIED
} nfs4_access_type_t;

/*
 * Access cache
 */
typedef struct acache4_hash {
	struct acache4 *next;
	struct acache4 *prev;
	krwlock_t lock;
} acache4_hash_t;

typedef struct acache4 {
	struct acache4 *next;	/* next and prev must be first */
	struct acache4 *prev;
	uint32_t known;
	uint32_t allowed;
	struct rnode4 *rnode;
	cred_t *cred;
	struct acache4 *list;
	struct acache4_hash *hashq;
} acache4_t;

/*
 * Note on the different buffer sizes in rddir4_cache:
 * There seems to be some discrepancy between the intended and actual
 * use of entlen and buflen, which does not correspond to the comment below.
 *	entlen - nfsv2/3 used as both alloc'd size of entries buffer and
 *		as the actual size of the entries (XXX is this correct?).
 *		nfsv4 will use it only as the alloc'd size.
 *	buflen - used for calculations of readahead.
 *	actlen - added for nfsv4 to serve as the size of the useful
 *		portion of the entries buffer. That is because in
 *		nfsv4, the otw entries are converted to system entries,
 *		and may not be the same size - thus buffer may not be full.
 */
typedef struct rddir4_cache {
	lloff_t _cookie;	/* cookie used to find this cache entry */
	lloff_t _ncookie;	/* cookie used to find the next cache entry */
	char *entries;		/* buffer containing dirent entries */
	int eof;		/* EOF reached after this request */
	int entlen;		/* size of dirent entries in buf */
	int buflen;		/* size of the buffer used to store entries */
	int actlen;		/* size of the actual entries (nfsv4 only) */
	int flags;		/* control flags, see below */
	kcondvar_t cv;		/* cv for blocking */
	int error;		/* error from RPC operation */
	void *data;		/* private data */
} rddir4_cache;

#define	nfs4_cookie	_cookie._f
#define	nfs4_ncookie	_ncookie._f

/*
 * Shadow vnode, v4 only.
 *
 * A file's shadow vnode list is protected by its hash bucket lock,
 * r_hashq->r_lock.
 *
 * sv_r_vnode is protected by the appropriate vnode locks.
 *
 * sv_dfh, sv_name, sv_dfileid, and sv_dfileid_valid are protected
 * by rp->r_svlock.
 */

typedef struct insq_link {
	void	*forw;
	void	*back;
} insq_link_t;

typedef struct svnode {
	insq_link_t	sv_link;	/* must be first for insque */
	vnode_t		*sv_r_vnode;	/* vnode for this shadow */
	nfs4_fname_t	*sv_name;	/* component name */
	nfs4_sharedfh_t	*sv_dfh;	/* directory file handle */
} svnode_t;

#define	sv_forw			sv_link.forw
#define	sv_back			sv_link.back
extern svnode_t			*vtosv(vnode_t *);
#define	VTOSV(vp)		vtosv(vp)
#define	SVTOV(svp)		(((svp)->sv_r_vnode))
#define	IS_SHADOW(vp, rp)	((vp) != (rp)->r_vnode)

/*
 * The format of the hash bucket used to lookup rnodes from a file handle.
 */
typedef struct r4hashq {
	struct rnode4 *r_hashf;
	struct rnode4 *r_hashb;
	krwlock_t r_lock;
} r4hashq_t;

/*
 * Remote file information structure.
 *
 * The rnode is the "inode" for remote files.  It contains all the
 * information necessary to handle remote file on the client side.
 *
 * Note on file sizes:  we keep two file sizes in the rnode: the size
 * according to the client (r_size) and the size according to the server
 * (r_attr.va_size).  They can differ because we modify r_size during a
 * write system call (nfs_rdwr), before the write request goes over the
 * wire (before the file is actually modified on the server).  If an OTW
 * request occurs before the cached data is written to the server the file
 * size returned from the server (r_attr.va_size) may not match r_size.
 * r_size is the one we use, in general.  r_attr.va_size is only used to
 * determine whether or not our cached data is valid.
 *
 * Each rnode has 5 locks associated with it (not including the rnode
 * hash table and free list locks):
 *
 *	r_rwlock:	Serializes nfs_write and nfs_setattr requests
 *			and allows nfs_read requests to proceed in parallel.
 *			Serializes reads/updates to directories.
 *
 *	r_lkserlock:	Serializes lock requests with map, write, and
 *			readahead operations.
 *
 *	r_statelock:	Protects all fields in the rnode except for
 *			those listed below.  This lock is intented
 *			to be held for relatively short periods of
 *			time (not accross entire putpage operations,
 *			for example).
 *
 *	r_statev4_lock:	Protects the created_v4 flag, the lock_owners list,
 *			and all the delegation fields except r_deleg_list.
 *
 *	r_os_lock:	Protects r_open_streams.
 *
 *
 * The following members are protected by the mutex rp4freelist_lock:
 *	r_freef
 *	r_freeb
 *
 * The following members are protected by the hash bucket rwlock:
 *	r_hashf
 *	r_hashb
 *
 * r_fh is read-only except when an rnode is created (or recycled from the
 * free list).
 *
 * The following members are protected by nfs4_server_t::s_lock:
 *	r_deleg_list
 *
 * Note: r_modaddr is only accessed when the r_statelock mutex is held.
 *	Its value is also controlled via r_rwlock.  It is assumed that
 *	there will be only 1 writer active at a time, so it safe to
 *	set r_modaddr and release r_statelock as long as the r_rwlock
 *	writer lock is held.
 *
 * r_inmap informs nfs4_read()/write() that there is a call to nfs4_map()
 * in progress. nfs4_read()/write() check r_inmap to decide whether
 * to perform directio on the file or not. r_inmap is atomically
 * incremented in nfs4_map() before the address space routines are
 * called and atomically decremented just before nfs4_map() exits.
 * r_inmap is not protected by any lock.
 *
 * r_mapcnt tells that the rnode has mapped pages. r_inmap can be 0
 * while the rnode has mapped pages.
 *
 * 64-bit offsets: the code formerly assumed that atomic reads of
 * r_size were safe and reliable; on 32-bit architectures, this is
 * not true since an intervening bus cycle from another processor
 * could update half of the size field.  The r_statelock must now
 * be held whenever any kind of access of r_size is made.
 *
 * Lock ordering:
 * 	r_rwlock > r_lkserlock > r_os_lock > r_statelock > r_statev4_lock
 *	vnode_t::v_lock > r_os_lock
 */
struct exportinfo;	/* defined in nfs/export.h */
struct servinfo4;	/* defined in nfs/nfs4_clnt.h */
struct failinfo;	/* defined in nfs/nfs_clnt.h */
struct mntinfo4;	/* defined in nfs/nfs4_clnt.h */

typedef struct rnode4 {
	/* the hash fields must be first to match the rhashq_t */
	struct rnode4	*r_hashf;	/* hash queue forward pointer */
	struct rnode4	*r_hashb;	/* hash queue back pointer */
	struct rnode4	*r_freef;	/* free list forward pointer */
	struct rnode4	*r_freeb;	/* free list back pointer */
	r4hashq_t	*r_hashq;	/* pointer to the hash bucket */

	svnode_t	r_svnode;	/* "master" shadow vnode for file */
	kmutex_t	r_svlock;	/* serializes access to svnode list */
	nfs_rwlock_t	r_rwlock;	/* serializes write/setattr requests */
	nfs_rwlock_t	r_lkserlock;	/* serialize lock with other ops */
	kmutex_t	r_statelock;	/* protects (most of) rnode contents */
	nfs4_sharedfh_t	*r_fh;		/* file handle */
	struct servinfo4
			*r_server;	/* current server */
	u_offset_t	r_nextr;	/* next byte read offset (read-ahead) */
	uint_t		r_flags;	/* flags, see below */
	short		r_error;	/* async write error */
	cred_t		*r_unlcred;	/* unlinked credentials */
	char		*r_unlname;	/* unlinked file name */
	vnode_t		*r_unldvp;	/* parent dir of unlinked file */
	vnode_t		*r_xattr_dir;	/* cached xattr dir vnode */
	len_t		r_size;		/* client's view of file size */
	vattr_t		r_attr;		/* cached vnode attributes */
	hrtime_t	r_time_attr_saved; /* time attributes were cached */
	hrtime_t	r_time_attr_inval; /* time attributes become invalid */
	hrtime_t	r_time_cache_inval; /* time caches become invalid */
	time_t		r_delay_wait;	/* future time for DELAY handling */
	int		r_delay_interval; /* Number of Secs of last DELAY */
	time_t		r_last_recov;	/* time of last recovery operation */
	nfs4_recov_t	r_recov_act;	/* action from last recovery op */
	long		r_mapcnt;	/* count of mmapped pages */
	uint_t		r_count;	/* # of refs not reflect in v_count */
	uint_t		r_awcount;	/* # of outstanding async write */
	uint_t		r_gcount;	/* getattrs waiting to flush pages */
	kcondvar_t	r_cv;		/* condvar for blocked threads */
	int		(*r_putapage)	/* address of putapage routine */
		(vnode_t *, page_t *, u_offset_t *, size_t *, int, cred_t *);
	void		*r_dir;		/* cache of readdir responses */
	rddir4_cache	*r_direof;	/* pointer to the EOF entry */
	symlink_cache	r_symlink;	/* cached readlink response */
	verifier4	r_writeverf;	/* file data write verifier */
	u_offset_t	r_modaddr;	/* address for page in writerp */
	commit_t	r_commit;	/* commit information */
	u_offset_t	r_truncaddr;	/* base for truncate operation */
	vsecattr_t	*r_secattr;	/* cached security attributes (acls) */
	verifier4	r_cookieverf4;	/* version 4 readdir cookie verifier */
	nfs4_pathconf_info_t r_pathconf; /* cached pathconf info */
	acache4_t	*r_acache;	/* list of access cache entries */
	list_t		r_open_streams;	/* open streams list */
	kmutex_t	r_os_lock;	/* protects r_open_streams */
	nfs4_lock_owner_t
			r_lo_head;	/* lock owners list head */
	int		created_v4;	/* 1 if file has been created in v4 */
	kmutex_t	r_statev4_lock;	/* protects created_v4, state4ptr */

	list_node_t	r_deleg_link;	/* linkage into list of */
					/* delegated rnodes for this server */
	open_delegation_type4
			r_deleg_type;	/* type of delegation granted */
	stateid4	r_deleg_stateid;
					/* delegation state id */
	nfs_space_limit4
			r_deleg_limit;	/* file limits returned from */
					/* server on delegated open */
	nfsace4		r_deleg_perms;	/* file permissions returned from */
					/* server on delegated open */
	fattr4_change	r_deleg_change;	/* current deleg change attr */
	fattr4_change	r_deleg_change_grant;
					/* change @ write deleg grant */
	cred_t		*r_deleg_cred;	/* credential in force when the */
					/* delegation was granted */
	open_delegation_type4
			r_deleg_needs_recovery;
					/* delegation needs recovery */
					/* This contains the delegation type */
					/* for use with CLAIM_PREVIOUS. */
					/* OPEN_DELEGATE_NONE means recovery */
					/* is not needed. */
	unsigned	r_deleg_needs_recall:1;
					/* delegation has been recalled by */
					/* the server during open with */
					/* CLAIM_PREVIOUS */
	unsigned 	r_deleg_return_pending:1;
					/* delegreturn is pending, don't use */
					/* the delegation stateid, set in */
					/* nfs4_dlistadd */
	unsigned 	r_deleg_return_inprog:1;
					/* delegreturn is in progress, may */
					/* only be set by nfs4delegreturn. */
	nfs_rwlock_t    r_deleg_recall_lock;
					/* lock for synchronizing delegreturn */
					/* with in other operations, acquired */
					/* in read mode by nfs4_start_fop, */
					/* acquired in write mode in */
					/* nfs4delegreturn */
	fattr4_change	r_change;	/* GETATTR4 change attr;  client  */
					/* should always request change   */
					/* when c/mtime requested to keep */
					/* change and c/mtime in sync	  */
	fattr4_fileid	r_mntd_fid;	/* mounted on fileid attr	  */
	kthread_t	*r_serial;	/* attrcache validation thread */
	kthread_t	*r_pgflush;	/* thread flushing page cache */
	list_t		r_indelmap;	/* list of delmap callers */
	fattr4_fsid	r_srv_fsid;	/* fsid of srv fs containing object */
					/* when rnode created; compare with */
					/* sv_fsid (servinfo4_t) to see why */
					/* stub type was set		    */
	nfs4_stub_type_t	r_stub_type;
					/* e.g. mirror-mount or referral */
	uint_t		r_inmap;	/* to serialize read/write and mmap */
	list_node_t	r_mi_link;	/* linkage into list of rnodes for */
					/* this mntinfo */
} rnode4_t;

#define	r_vnode	r_svnode.sv_r_vnode

/*
 * Flags
 */
#define	R4READDIRWATTR	0x1	/* Use READDIR with attributes */
#define	R4DIRTY		0x2	/* dirty pages from write operation */
#define	R4STALE		0x4	/* stale, don't even attempt to write */
#define	R4MODINPROGRESS	0x8	/* page modification happening */
#define	R4TRUNCATE	0x10	/* truncating, don't commit */
#define	R4HAVEVERF	0x20	/* have a write verifier to compare against */
#define	R4COMMIT	0x40	/* commit in progress */
#define	R4COMMITWAIT	0x80	/* someone is waiting to do a commit */
#define	R4HASHED	0x100	/* rnode is in hash queues */
#define	R4OUTOFSPACE	0x200	/* an out of space error has happened */
#define	R4LODANGLERS	0x400	/* rnode has dangling lock_owners to cleanup */
#define	R4WRITEMODIFIED	0x800	/* file data has been modified by write */
#define	R4DIRECTIO	0x1000	/* bypass the buffer cache */
#define	R4RECOVERR	0x2000	/* couldn't recover */
#define	R4RECEXPFH	0x4000	/* recovering expired filehandle */
#define	R4RECOVERRP	0x8000	/* R4RECOVERR pending, but not set (yet) */
#define	R4ISXATTR	0x20000	/* rnode is a named attribute */
#define	R4DELMAPLIST	0x40000	/* delmap callers tracked for as callback */
#define	R4PGFLUSH	0x80000	/* page flush thread active */
#define	R4INCACHEPURGE	0x100000 /* purging caches due to file size change */
#define	R4LOOKUP	0x200000 /* a lookup has been done in the directory */
/*
 * Convert between vnode and rnode
 */
#define	RTOV4(rp)	((rp)->r_vnode)
#define	VTOR4(vp)	((rnode4_t *)((vp)->v_data))

#define	RP_ISSTUB(rp)	(((rp)->r_stub_type != NFS4_STUB_NONE))
#define	RP_ISSTUB_MIRRORMOUNT(rp) ((rp)->r_stub_type == NFS4_STUB_MIRRORMOUNT)
#define	RP_ISSTUB_REFERRAL(rp)	((rp)->r_stub_type == NFS4_STUB_REFERRAL)

/*
 * Open file instances.
 */

typedef struct nfs4_opinst {
	struct nfs4_opinst	*re_next; /* next in list */
	vnode_t			*re_vp;	/* held reference */
	uint32_t		re_numosp; /* number of valid open streams */
	nfs4_open_stream_t	**re_osp; /* held reference */
} nfs4_opinst_t;

#ifdef _KERNEL

extern long nrnode;

/* Used for r_delay_interval */
#define	NFS4_INITIAL_DELAY_INTERVAL	 1
#define	NFS4_MAX_DELAY_INTERVAL		20

extern rnode4_t	*r4find(r4hashq_t *, nfs4_sharedfh_t *, struct vfs *);
extern rnode4_t	*r4find_unlocked(nfs4_sharedfh_t *, struct vfs *);
extern void	r4flush(struct vfs *, cred_t *);
extern void	destroy_rtable4(struct vfs *, cred_t *);
extern int	check_rtable4(struct vfs *);
extern void	rp4_addfree(rnode4_t *, cred_t *);
extern void	rp4_addhash(rnode4_t *);
extern void	rp4_rmhash(rnode4_t *);
extern void	rp4_rmhash_locked(rnode4_t *);
extern int	rtable4hash(nfs4_sharedfh_t *);

extern vnode_t *makenfs4node(nfs4_sharedfh_t *, nfs4_ga_res_t *, struct vfs *,
				hrtime_t, cred_t *, vnode_t *, nfs4_fname_t *);
extern vnode_t *makenfs4node_by_fh(nfs4_sharedfh_t *, nfs4_sharedfh_t *,
    nfs4_fname_t **, nfs4_ga_res_t *, mntinfo4_t *, cred_t *, hrtime_t);

extern nfs4_opinst_t *r4mkopenlist(struct mntinfo4 *);
extern void	r4releopenlist(nfs4_opinst_t *);
extern int	r4find_by_fsid(mntinfo4_t *, fattr4_fsid *);

/* Access cache calls */
extern nfs4_access_type_t nfs4_access_check(rnode4_t *, uint32_t, cred_t *);
extern void	nfs4_access_cache(rnode4_t *rp, uint32_t, uint32_t, cred_t *);
extern int	nfs4_access_purge_rp(rnode4_t *);

extern int	nfs4_free_data_reclaim(rnode4_t *);
extern void	nfs4_rnode_invalidate(struct vfs *);

extern time_t	r2lease_time(rnode4_t *);
extern int	nfs4_directio(vnode_t *, int, cred_t *);

/* shadow vnode functions */
extern void	sv_activate(vnode_t **, vnode_t *, nfs4_fname_t **, int);
extern vnode_t	*sv_find(vnode_t *, vnode_t *, nfs4_fname_t **);
extern void	sv_update_path(vnode_t *, char *, char *);
extern void	sv_inactive(vnode_t *);
extern void	sv_exchange(vnode_t **);
extern void	sv_uninit(svnode_t *);
extern void	nfs4_clear_open_streams(rnode4_t *);

/*
 * Mark cached attributes as timed out
 *
 * The caller must not be holding the rnode r_statelock mutex.
 */
#define	PURGE_ATTRCACHE4_LOCKED(rp)				\
	rp->r_time_attr_inval = gethrtime();			\
	rp->r_time_attr_saved = rp->r_time_attr_inval;		\
	rp->r_pathconf.pc4_xattr_valid = 0;			\
	rp->r_pathconf.pc4_cache_valid = 0;

#define	PURGE_ATTRCACHE4(vp)	{				\
	rnode4_t *rp = VTOR4(vp);				\
	mutex_enter(&rp->r_statelock);				\
	PURGE_ATTRCACHE4_LOCKED(rp);				\
	mutex_exit(&rp->r_statelock);				\
}


extern void	nfs4_async_readdir(vnode_t *, rddir4_cache *,
			cred_t *, int (*)(vnode_t *, rddir4_cache *, cred_t *));
extern char	*rnode4info(rnode4_t *rp);

extern int	writerp4(rnode4_t *, caddr_t, int, struct uio *, int);
extern void	nfs4_set_nonvattrs(rnode4_t *, struct nfs4attr_to_vattr *);
extern void	nfs4delegabandon(rnode4_t *);
extern stateid4 nfs4_get_w_stateid(cred_t *, rnode4_t *, pid_t, mntinfo4_t *,
			nfs_opnum4, nfs4_stateid_types_t *);
extern stateid4 nfs4_get_stateid(cred_t *, rnode4_t *, pid_t, mntinfo4_t *,
			nfs_opnum4, nfs4_stateid_types_t *, bool_t);
extern nfsstat4 nfs4_find_or_create_lock_owner(pid_t, rnode4_t *, cred_t *,
			nfs4_open_owner_t **, nfs4_open_stream_t **,
			nfs4_lock_owner_t **);
extern cred_t   *nfs4_get_otw_cred_by_osp(rnode4_t *, cred_t *,
			nfs4_open_stream_t **, bool_t *, bool_t *);


/*
 * Defines for the flag argument of nfs4delegreturn
 */
#define	NFS4_DR_FORCE	0x1	/* discard even if start_op fails */
#define	NFS4_DR_PUSH	0x2	/* push modified data back to the server */
#define	NFS4_DR_DISCARD	0x4	/* discard the delegation w/o delegreturn */
#define	NFS4_DR_DID_OP	0x8	/* calling function did nfs4_start_op */
#define	NFS4_DR_RECALL	0x10	/* delegreturn done in response to CB_RECALL */
#define	NFS4_DR_REOPEN	0x20	/* perform file reopens, if applicable */

extern int nfs4delegreturn(rnode4_t *, int);
extern void	nfs4_delegreturn_all(nfs4_server_t *);
extern void	nfs4delegreturn_cleanup(rnode4_t *, nfs4_server_t *);
extern void nfs4_delegation_accept(rnode4_t *, open_claim_type4, OPEN4res *,
		nfs4_ga_res_t *, cred_t *);

extern void	nfs4_dlistclean(void);
extern void	nfs4_deleg_discard(mntinfo4_t *, nfs4_server_t *);

extern void	rddir4_cache_create(rnode4_t *);
extern void	rddir4_cache_purge(rnode4_t *);
extern void	rddir4_cache_destroy(rnode4_t *);
extern rddir4_cache *rddir4_cache_lookup(rnode4_t *, offset_t, int);
extern void	rddir4_cache_rele(rnode4_t *, rddir4_cache *);

extern void	r4_stub_mirrormount(rnode4_t *);
extern void	r4_stub_referral(rnode4_t *);
extern void	r4_stub_none(rnode4_t *);

#ifdef DEBUG
extern char	*rddir4_cache_buf_alloc(size_t, int);
extern void	rddir4_cache_buf_free(void *, size_t);
#endif



#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _NFS_RNODE4_H */
