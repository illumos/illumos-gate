/*
 * Copyright (c) 2000-2001, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: smbfs_node.h,v 1.31.52.1 2005/05/27 02:35:28 lindak Exp $
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FS_SMBFS_NODE_H_
#define	_FS_SMBFS_NODE_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Much code copied into here from Sun NFS.
 */

#include <sys/avl.h>
#include <sys/list.h>

#ifdef __cplusplus
extern "C" {
#endif

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

#define	smbfs_cookie	_cookie._p._l
#define	smbfs_ncookie	_ncookie._p._l
#define	smbfs3_cookie	_cookie._f
#define	smbfs3_ncookie	_ncookie._f

#define	RDDIR		0x1	/* readdir operation in progress */
#define	RDDIRWAIT	0x2	/* waiting on readdir in progress */
#define	RDDIRREQ	0x4	/* a new readdir is required */
#define	RDDIRCACHED	0x8	/* entry is in the cache */

#define	HAVE_RDDIR_CACHE(rp)	(avl_numnodes(&(rp)->r_dir) > 0)

/*
 * A homegrown reader/writer lock implementation.  It addresses
 * two requirements not addressed by the system primitives.  They
 * are that the `enter" operation is optionally interruptible and
 * that that they can be re`enter'ed by writers without deadlock.
 */
typedef struct smbfs_rwlock {
	int count;
	int waiters;
	kthread_t *owner;
	kmutex_t lock;
	kcondvar_t cv;
} smbfs_rwlock_t;

/*
 * The format of the hash bucket used to lookup smbnodes from a file handle.
 */
typedef struct rhashq {
	struct smbnode *r_hashf;
	struct smbnode *r_hashb;
	krwlock_t r_lock;
} rhashq_t;

/*
 * Remote file information structure.
 *
 * The smbnode is the "inode" for remote files.  It contains all the
 * information necessary to handle remote file on the client side.
 *
 * Note on file sizes:  we keep two file sizes in the smbnode: the size
 * according to the client (r_size) and the size according to the server
 * (r_attr.va_size).  They can differ because we modify r_size during a
 * write system call (smbfs_rdwr), before the write request goes over the
 * wire (before the file is actually modified on the server).  If an OTW
 * request occurs before the cached data is written to the server the file
 * size returned from the server (r_attr.va_size) may not match r_size.
 * r_size is the one we use, in general.  r_attr.va_size is only used to
 * determine whether or not our cached data is valid.
 *
 * Each smbnode has 3 locks associated with it (not including the smbnode
 * hash table and free list locks):
 *
 *	r_rwlock:	Serializes smbfs_write and smbfs_setattr requests
 *			and allows smbfs_read requests to proceed in parallel.
 *			Serializes reads/updates to directories.
 *
 *	r_lkserlock:	Serializes lock requests with map, write, and
 *			readahead operations.
 *
 *	r_statelock:	Protects all fields in the smbnode except for
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
 * 64-bit offsets: the code formerly assumed that atomic reads of
 * r_size were safe and reliable; on 32-bit architectures, this is
 * not true since an intervening bus cycle from another processor
 * could update half of the size field.  The r_statelock must now
 * be held whenever any kind of access of r_size is made.
 *
 * Lock ordering:
 * 	r_rwlock > r_lkserlock > r_statelock
 */
struct exportinfo;	/* defined in smbfs/export.h */
struct failinfo;	/* defined in smbfs/smbfs_clnt.h */
struct mntinfo;		/* defined in smbfs/smbfs_clnt.h */

#ifdef _KERNEL
/* Bits for smbnode.n_flag */
#define	NFLUSHINPROG	0x00001
#define	NFLUSHWANT	0x00002 /* they should gone ... */
#define	NMODIFIED	0x00004 /* bogus, until async IO implemented */
#define	NREFPARENT	0x00010 /* node holds parent from recycling */
#define	NGOTIDS		0x00020
#define	NRDIRSERIAL	0x00080	/* serialize readdir operation */
#define	NISMAPPED	0x00800
#define	NFLUSHWIRE	0x01000
#define	NATTRCHANGED	0x02000 /* use smbfs_attr_cacheremove at close */
#define	NALLOC		0x04000 /* being created */
#define	NWALLOC		0x08000 /* awaiting creation */
#define	N_XATTR 	0x10000 /* extended attribute (dir or file) */

typedef struct smbnode {
	/* from Sun NFS struct rnode (XXX: cleanup needed) */
	/* the hash fields must be first to match the rhashq_t */
	/* Lock for the hash queue is: np->r_hashq->r_lock */
	struct smbnode	*r_hashf;	/* hash queue forward pointer */
	struct smbnode	*r_hashb;	/* hash queue back pointer */
	/* Lock for the free list is: smbfreelist_lock */
	struct smbnode	*r_freef;	/* free list forward pointer */
	struct smbnode	*r_freeb;	/* free list back pointer */
	rhashq_t	*r_hashq;	/* pointer to the hash bucket */
	vnode_t		*r_vnode;	/* vnode for remote file */
	smbfs_rwlock_t	r_rwlock;	/* serializes write/setattr requests */
	smbfs_rwlock_t	r_lkserlock;	/* serialize lock with other ops */
	kmutex_t	r_statelock;	/* protects (most of) smbnode fields */
	u_offset_t	r_nextr;	/* next byte read offset (read-ahead) */
	cred_t		*r_cred;	/* current credentials */
	len_t		r_size;		/* client's view of file size */
	struct vattr	r_attr;		/* cached vnode attributes */
	hrtime_t	r_attrtime;	/* time attributes become invalid */
	long		r_mapcnt;	/* count of mmapped pages */
	uint_t		r_count;	/* # of refs not reflect in v_count */
	uint_t		r_awcount;	/* # of outstanding async write */
	uint_t		r_gcount;	/* getattrs waiting to flush pages */
	ushort_t	r_flags;	/* flags, see below */
	short		r_error;	/* async write error */
	kcondvar_t	r_cv;		/* condvar for blocked threads */
	avl_tree_t	r_dir;		/* cache of readdir responses */
	rddir_cache	*r_direof;	/* pointer to the EOF entry */
	kthread_t	*r_serial;	/* id of purging thread */
	list_t		r_indelmap;	/* list of delmap callers */
	/*
	 * Members derived from Darwin struct smbnode.
	 * Note: n_parent node pointer removed because it
	 * caused unwanted "holds" on nodes in our cache.
	 * Now keeping just the full remote path instead,
	 * in server form, relative to the share root.
	 */
	char		*n_rpath;
	int		n_rplen;
	uint32_t	n_flag;
	smbmntinfo_t	*n_mount;
	ino64_t		n_ino;
	/* Lock for the next 8 is r_lkserlock */
	enum vtype	n_ovtype;	/* vnode type opened */
	int		n_dirrefs;
	struct smbfs_fctx	*n_dirseq;	/* ff context */
	long		n_dirofs;	/* last ff offset */
	long		n_direof;	/* End of dir. offset. */
	int		n_fidrefs;
	uint16_t	n_fid;		/* file handle */
	uint32_t	n_rights;	/* granted rights */
	/* Lock for the rest is r_statelock */
	uid_t		n_uid;
	gid_t		n_gid;
	mode_t		n_mode;
	timestruc_t	r_atime;
	timestruc_t	r_ctime;
	timestruc_t	r_mtime;
	int		n_dosattr;
	/*
	 * XXX: Maybe use this instead:
	 *   #define n_atime  r_attr.va_atime
	 * etc.
	 */
#define	n_size		r_size
#define	n_atime		r_atime
#define	n_ctime		r_ctime
#define	n_mtime		r_mtime
#define	n_attrage	r_attrtime
} smbnode_t;
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
#define	RHASHED		0x100	/* smbnode is in hash queues */
#define	ROUTOFSPACE	0x200	/* an out of space error has happened */
#define	RDIRECTIO	0x400	/* bypass the buffer cache */
#define	RLOOKUP		0x800	/* a lookup has been performed */
#define	RWRITEATTR	0x1000	/* attributes came from WRITE */
#define	RINDNLCPURGE	0x2000	/* in the process of purging DNLC references */
#define	RDELMAPLIST	0x4000	/* delmap callers tracking for as callback */

/*
 * Convert between vnode and smbnode
 */
#define	VTOSMB(vp)	((smbnode_t *)((vp)->v_data))
#define	SMBTOV(np)	((np)->r_vnode)

/* Attribute cache timeouts in seconds */
#define	SMB_MINATTRTIMO 2
#define	SMB_MAXATTRTIMO 30

/*
 * Function definitions.
 */
struct smb_cred;
int smbfs_nget(vnode_t *dvp, const char *name, int nmlen,
	struct smbfattr *fap, vnode_t **vpp);
void smbfs_attr_cacheenter(vnode_t *vp, struct smbfattr *fap);
int  smbfs_attr_cachelookup(vnode_t *vp, struct vattr *va);
void smbfs_attr_touchdir(struct smbnode *dnp);
char    *smbfs_name_alloc(const char *name, int nmlen);
void	smbfs_name_free(const char *name, int nmlen);
uint32_t smbfs_hash(const char *name, int nmlen);
uint32_t smbfs_hash3(uint32_t ival, const char *name, int nmlen);
uint32_t smbfs_getino(struct smbnode *dnp, const char *name, int nmlen);
int smb_check_table(struct vfs *vfsp, smbnode_t *srp);

#define	smbfs_attr_cacheremove(np)	(np)->n_attrage = 0

#ifdef __cplusplus
}
#endif

#endif /* _FS_SMBFS_NODE_H_ */
