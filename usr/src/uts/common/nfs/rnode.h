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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef	_NFS_RNODE_H
#define	_NFS_RNODE_H

#include <sys/avl.h>
#include <sys/list.h>
#include <nfs/nfs.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum nfs_access_type {
	NFS_ACCESS_UNKNOWN,
	NFS_ACCESS_ALLOWED,
	NFS_ACCESS_DENIED
} nfs_access_type_t;

typedef struct acache_hash {
	struct acache *next;	/* next and prev must be first */
	struct acache *prev;
	krwlock_t lock;
} acache_hash_t;

typedef struct acache {
	struct acache *next;	/* next and prev must be first */
	struct acache *prev;
	uint32_t known;
	uint32_t allowed;
	struct rnode *rnode;
	cred_t *cred;
	struct acache *list;
	struct acache_hash *hashq;
} acache_t;

#define	NFS_FHANDLE_LEN	72

typedef struct nfs_fhandle {
	int fh_len;
	char fh_buf[NFS_FHANDLE_LEN];
} nfs_fhandle;

typedef struct rddir_cache {
	lloff_t _cookie;	/* cookie used to find this cache entry */
	lloff_t _ncookie;	/* cookie used to find the next cache entry */
	char *entries;		/* buffer containing dirent entries */
	int eof;		/* EOF reached after this request */
	int entlen;		/* size of dirent entries in buf */
	int buflen;		/* size of the buffer used to store entries */
	int flags;		/* control flags, see below */
	kcondvar_t cv;		/* cv for blocking */
	int error;		/* error from RPC operation */
	kmutex_t lock;
	uint_t count;		/* reference count */
	avl_node_t tree;	/* AVL tree links */
} rddir_cache;

#define	nfs_cookie	_cookie._p._l
#define	nfs_ncookie	_ncookie._p._l
#define	nfs3_cookie	_cookie._f
#define	nfs3_ncookie	_ncookie._f

#define	RDDIR		0x1	/* readdir operation in progress */
#define	RDDIRWAIT	0x2	/* waiting on readdir in progress */
#define	RDDIRREQ	0x4	/* a new readdir is required */
#define	RDDIRCACHED	0x8	/* entry is in the cache */

#define	HAVE_RDDIR_CACHE(rp)	(avl_numnodes(&(rp)->r_dir) > 0)

typedef struct symlink_cache {
	char *contents;		/* contents of the symbolic link */
	int len;		/* length of the contents */
	int size;		/* size of the allocated buffer */
} symlink_cache;

typedef struct commit {
	page_t *c_pages;	/* list of pages to commit */
	offset3 c_commbase;	/* base offset to do commit from */
	count3 c_commlen;	/* len to commit */
	kcondvar_t c_cv;	/* condvar for waiting for commit */
} commit_t;

/*
 * The various values for the commit states.  These are stored in
 * the p_fsdata byte in the page struct.
 * NFSv3,4 can use asynchronous writes - the NFS server can send a response
 * before storing the data to the stable store (disk). The response contains
 * information if the data are on a disk or not. NFS client marks pages
 * which are already on the stable store as C_NOCOMMIT. The pages which were
 * sent but are not yet on the stable store are only partially 'safe' and are
 * marked as C_DELAYCOMMIT, which can be later changed to C_COMMIT if the
 * commit operation is in progress. If the NFS server is e.g. rebooted, the
 * client needs to resend all the uncommitted data. The client walks all the
 * vp->v_pages and if C_DELAYCOMMIT or C_COMMIT is set, the page is marked as
 * dirty and thus will be written to the server again.
 */
#define	C_NOCOMMIT	0	/* no commit is required */
#define	C_COMMIT	1	/* a commit is required so do it now */
#define	C_DELAYCOMMIT	2	/* a commit is required, but can be delayed */

/*
 * The lock manager holds state making it possible for the client
 * and server to be out of sync.  For example, if the response from
 * the server granting a lock request is lost, the server will think
 * the lock is granted and the client will think the lock is lost.
 * To deal with this, a list of processes for which the client is
 * not sure if the server holds a lock is attached to the rnode.
 * When such a process closes the rnode, an unlock request is sent
 * to the server to unlock the entire file.
 *
 * The list is kept as a singularly linked NULL terminated list.
 * Because it is  only added to under extreme error conditions, the
 * list shouldn't get very big.  DEBUG kernels print a console warning
 * when the number of entries on a list go beyond nfs_lmpl_high_water
 * an  arbitrary number defined in nfs_add_locking_id()
 */
#define	RLMPL_PID	1
#define	RLMPL_OWNER	2
typedef struct lock_manager_pid_list {
	int lmpl_type;
	pid_t lmpl_pid;
	union {
		pid_t _pid;
		struct {
			int len;
			char *owner;
		} _own;
	} un;
	struct lock_manager_pid_list *lmpl_next;
} lmpl_t;

#define	lmpl_opid un._pid
#define	lmpl_own_len un._own.len
#define	lmpl_owner un._own.owner

/*
 * A homegrown reader/writer lock implementation.  It addresses
 * two requirements not addressed by the system primitives.  They
 * are that the `enter" operation is optionally interruptible and
 * that they can be re`enter'ed by writers without deadlock.
 */
typedef struct nfs_rwlock {
	int count;
	int waiters;
	kthread_t *owner;
	kmutex_t lock;
	kcondvar_t cv;
	kcondvar_t cv_rd;
} nfs_rwlock_t;

/*
 * The format of the hash bucket used to lookup rnodes from a file handle.
 */
typedef struct rhashq {
	struct rnode *r_hashf;
	struct rnode *r_hashb;
	krwlock_t r_lock;
} rhashq_t;

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
 * Each rnode has 3 locks associated with it (not including the rnode
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
 * The following members are protected by the mutex rpfreelist_lock:
 *	r_freef
 *	r_freeb
 *
 * The following members are protected by the hash bucket rwlock:
 *	r_hashf
 *	r_hashb
 *
 * Note: r_modaddr is only accessed when the r_statelock mutex is held.
 *	Its value is also controlled via r_rwlock.  It is assumed that
 *	there will be only 1 writer active at a time, so it safe to
 *	set r_modaddr and release r_statelock as long as the r_rwlock
 *	writer lock is held.
 *
 * r_inmap informs nfsX_read()/write() that there is a call to nfsX_map()
 * in progress. nfsX_read()/write() check r_inmap to decide whether
 * to perform directio on the file or not. r_inmap is atomically
 * incremented in nfsX_map() before the address space routines are
 * called and atomically decremented just before nfsX_map() exits.
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
 * 	r_rwlock > r_lkserlock > r_statelock
 */
struct exportinfo;	/* defined in nfs/export.h */
struct servinfo;	/* defined in nfs/nfs_clnt.h */
struct failinfo;	/* defined in nfs/nfs_clnt.h */
struct mntinfo;		/* defined in nfs/nfs_clnt.h */

#ifdef _KERNEL

typedef struct rnode {
	/* the hash fields must be first to match the rhashq_t */
	struct rnode	*r_hashf;	/* hash queue forward pointer */
	struct rnode	*r_hashb;	/* hash queue back pointer */
	struct rnode	*r_freef;	/* free list forward pointer */
	struct rnode	*r_freeb;	/* free list back pointer */
	rhashq_t	*r_hashq;	/* pointer to the hash bucket */
	vnode_t		*r_vnode;	/* vnode for remote file */
	nfs_rwlock_t	r_rwlock;	/* serializes write/setattr requests */
	nfs_rwlock_t	r_lkserlock;	/* serialize lock with other ops */
	kmutex_t	r_statelock;	/* protects (most of) rnode contents */
	nfs_fhandle	r_fh;		/* file handle */
	struct servinfo	*r_server;	/* current server */
	char		*r_path;	/* path to this rnode */
	u_offset_t	r_nextr;	/* next byte read offset (read-ahead) */
	cred_t		*r_cred;	/* current credentials */
	cred_t		*r_unlcred;	/* unlinked credentials */
	char		*r_unlname;	/* unlinked file name */
	vnode_t		*r_unldvp;	/* parent dir of unlinked file */
	len_t		r_size;		/* client's view of file size */
	struct vattr	r_attr;		/* cached vnode attributes */
	hrtime_t	r_attrtime;	/* time attributes become invalid */
	hrtime_t	r_mtime;	/* client time file last modified */
	long		r_mapcnt;	/* count of mmapped pages */
	uint_t		r_count;	/* # of refs not reflect in v_count */
	uint_t		r_awcount;	/* # of outstanding async write */
	uint_t		r_gcount;	/* getattrs waiting to flush pages */
	ushort_t	r_flags;	/* flags, see below */
	short		r_error;	/* async write error */
	kcondvar_t	r_cv;		/* condvar for blocked threads */
	int		(*r_putapage)	/* address of putapage routine */
		(vnode_t *, page_t *, u_offset_t *, size_t *, int, cred_t *);
	avl_tree_t	r_dir;		/* cache of readdir responses */
	rddir_cache	*r_direof;	/* pointer to the EOF entry */
	symlink_cache	r_symlink;	/* cached readlink response */
	writeverf3	r_verf;		/* version 3 write verifier */
	u_offset_t	r_modaddr;	/* address for page in writerp */
	commit_t	r_commit;	/* commit information */
	u_offset_t	r_truncaddr;	/* base for truncate operation */
	vsecattr_t	*r_secattr;	/* cached security attributes (acls) */
	cookieverf3	r_cookieverf;	/* version 3 readdir cookie verifier */
	lmpl_t		*r_lmpl;	/* pids that may be holding locks */
	nfs3_pathconf_info *r_pathconf;	/* cached pathconf information */
	acache_t	*r_acache;	/* list of access cache entries */
	kthread_t	*r_serial;	/* id of purging thread */
	list_t		r_indelmap;	/* list of delmap callers */
	uint_t		r_inmap;	/* to serialize read/write and mmap */
} rnode_t;
#endif /* _KERNEL */

/*
 * Flags
 */
#define	RREADDIRPLUS	0x1	/* issue a READDIRPLUS instead of READDIR */
#define	RDIRTY		0x2	/* dirty pages from write operation */
#define	RSTALE		0x4	/* file handle is stale */
#define	RMODINPROGRESS	0x8	/* page modification happening */
#define	RTRUNCATE	0x10	/* truncating, don't commit */
#define	RHAVEVERF	0x20	/* have a write verifier to compare against */
#define	RCOMMIT		0x40	/* commit in progress */
#define	RCOMMITWAIT	0x80	/* someone is waiting to do a commit */
#define	RHASHED		0x100	/* rnode is in hash queues */
#define	ROUTOFSPACE	0x200	/* an out of space error has happened */
#define	RDIRECTIO	0x400	/* bypass the buffer cache */
#define	RLOOKUP		0x800	/* a lookup has been performed */
#define	RWRITEATTR	0x1000	/* attributes came from WRITE */
#define	RINDNLCPURGE	0x2000	/* in the process of purging DNLC references */
#define	RDELMAPLIST	0x4000	/* delmap callers tracking for as callback */
#define	RINCACHEPURGE	0x8000	/* purging caches due to file size change */

/*
 * Convert between vnode and rnode
 */
#define	RTOV(rp)	((rp)->r_vnode)
#define	VTOR(vp)	((rnode_t *)((vp)->v_data))

#define	VTOFH(vp)	(RTOFH(VTOR(vp)))
#define	RTOFH(rp)	((fhandle_t *)(&(rp)->r_fh.fh_buf))
#define	VTOFH3(vp)	(RTOFH3(VTOR(vp)))
#define	RTOFH3(rp)	((nfs_fh3 *)(&(rp)->r_fh))

#ifdef _KERNEL
extern int	nfs_async_readahead(vnode_t *, u_offset_t, caddr_t,
				struct seg *, cred_t *,
				void (*)(vnode_t *, u_offset_t,
				caddr_t, struct seg *, cred_t *));
extern int	nfs_async_putapage(vnode_t *, page_t *, u_offset_t, size_t,
				int, cred_t *, int (*)(vnode_t *, page_t *,
				u_offset_t, size_t, int, cred_t *));
extern int	nfs_async_pageio(vnode_t *, page_t *, u_offset_t, size_t,
				int, cred_t *, int (*)(vnode_t *, page_t *,
				u_offset_t, size_t, int, cred_t *));
extern void	nfs_async_readdir(vnode_t *, rddir_cache *,
				cred_t *, int (*)(vnode_t *,
				rddir_cache *, cred_t *));
extern void	nfs_async_commit(vnode_t *, page_t *, offset3, count3,
				cred_t *, void (*)(vnode_t *, page_t *,
				offset3, count3, cred_t *));
extern void	nfs_async_inactive(vnode_t *, cred_t *, void (*)(vnode_t *,
				cred_t *, caller_context_t *));
extern int	writerp(rnode_t *, caddr_t, int, struct uio *, int);
extern int	nfs_putpages(vnode_t *, u_offset_t, size_t, int, cred_t *);
extern void	nfs_invalidate_pages(vnode_t *, u_offset_t, cred_t *);
extern int	rfs2call(struct mntinfo *, rpcproc_t, xdrproc_t, caddr_t,
			xdrproc_t, caddr_t, cred_t *, int *, enum nfsstat *,
			int, struct failinfo *);
extern int	rfs3call(struct mntinfo *, rpcproc_t, xdrproc_t, caddr_t,
			xdrproc_t, caddr_t, cred_t *, int *, nfsstat3 *,
			int, struct failinfo *);
extern void	nfs_setswaplike(vnode_t *, vattr_t *);
extern vnode_t	*makenfsnode(fhandle_t *, struct nfsfattr *, struct vfs *,
			hrtime_t, cred_t *, char *, char *);
extern vnode_t	*makenfs3node_va(nfs_fh3 *, vattr_t *, struct vfs *, hrtime_t,
			cred_t *, char *, char *);
extern vnode_t	*makenfs3node(nfs_fh3 *, fattr3 *, struct vfs *, hrtime_t,
			cred_t *, char *, char *);
extern void	rp_addfree(rnode_t *, cred_t *);
extern void	rp_rmhash(rnode_t *);
extern int	check_rtable(struct vfs *);
extern void	destroy_rtable(struct vfs *, cred_t *);
extern void	rflush(struct vfs *, cred_t *);
extern nfs_access_type_t nfs_access_check(rnode_t *, uint32_t, cred_t *);
extern void	nfs_access_cache(rnode_t *rp, uint32_t, uint32_t, cred_t *);
extern int	nfs_access_purge_rp(rnode_t *);
extern int	nfs_putapage(vnode_t *, page_t *, u_offset_t *, size_t *,
			int, cred_t *);
extern int	nfs3_putapage(vnode_t *, page_t *, u_offset_t *, size_t *,
			int, cred_t *);
extern void	nfs_printfhandle(nfs_fhandle *);
extern void	nfs_write_error(vnode_t *, int, cred_t *);
extern rddir_cache	*rddir_cache_alloc(int);
extern void		rddir_cache_hold(rddir_cache *);
extern void		rddir_cache_rele(rddir_cache *);
#ifdef DEBUG
extern char		*rddir_cache_buf_alloc(size_t, int);
extern void		rddir_cache_buf_free(void *, size_t);
#endif
extern int	nfs_rw_enter_sig(nfs_rwlock_t *, krw_t, int);
extern int	nfs_rw_tryenter(nfs_rwlock_t *, krw_t);
extern void	nfs_rw_exit(nfs_rwlock_t *);
extern int	nfs_rw_lock_held(nfs_rwlock_t *, krw_t);
extern void	nfs_rw_init(nfs_rwlock_t *, char *, krw_type_t, void *);
extern void	nfs_rw_destroy(nfs_rwlock_t *);
extern int	nfs_directio(vnode_t *, int, cred_t *);
extern int	nfs3_rddir_compar(const void *, const void *);
extern int	nfs_rddir_compar(const void *, const void *);
extern struct zone *nfs_zone(void);
extern zoneid_t nfs_zoneid(void);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _NFS_RNODE_H */
