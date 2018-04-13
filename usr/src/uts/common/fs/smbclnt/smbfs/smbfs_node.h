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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FS_SMBFS_NODE_H_
#define	_FS_SMBFS_NODE_H_

/*
 * Much code copied into here from Sun NFS.
 * Compare with nfs_clnt.h
 */

#include <sys/avl.h>
#include <sys/list.h>
#include <netsmb/smb_subr.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Cache whole directories (not yet)
 */
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
 * The format of the smbfs node header, which contains the
 * fields used to link nodes in the AVL tree, and those
 * fields needed by the AVL node comparison functions.
 * It's a separate struct so we can call avl_find with
 * this relatively small struct as a stack local.
 *
 * The AVL tree is mntinfo.smi_hash_avl,
 * and its lock is mntinfo.smi_hash_lk.
 */
typedef struct smbfs_node_hdr {
	/*
	 * Our linkage in the node cache AVL tree.
	 */
	avl_node_t	hdr_avl_node;

	/*
	 * Identity of this node:  The full path name,
	 * in server form, relative to the share root.
	 */
	char		*hdr_n_rpath;
	int		hdr_n_rplen;
} smbfs_node_hdr_t;

/*
 * Below is the SMBFS-specific representation of a "node".
 * This struct is a mixture of Sun NFS and Darwin code.
 * Fields starting with "r_" came from NFS struct "rnode"
 * and fields starting with "n_" came from Darwin, or
 * were added during the Solaris port.  We have avoided
 * renaming fields so we would not cause excessive
 * changes in the code using this struct.
 *
 * Now using an AVL tree instead of hash lists, but kept the
 * "hash" in some member names and functions to reduce churn.
 * One AVL tree per mount replaces the global hash buckets.
 *
 * Notes carried over from the NFS code:
 *
 * The smbnode is the "inode" for remote files.  It contains all the
 * information necessary to handle remote file on the client side.
 *
 * Note on file sizes:  we keep two file sizes in the smbnode: the size
 * according to the client (r_size) and the size according to the server
 * (r_attr.fa_size).  They can differ because we modify r_size during a
 * write system call (smbfs_rdwr), before the write request goes over the
 * wire (before the file is actually modified on the server).  If an OTW
 * request occurs before the cached data is written to the server the file
 * size returned from the server (r_attr.fa_size) may not match r_size.
 * r_size is the one we use, in general.  r_attr.fa_size is only used to
 * determine whether or not our cached data is valid.
 *
 * Each smbnode has 3 locks associated with it (not including the smbnode
 * "hash" AVL tree and free list locks):
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
 * The following members are protected by the mutex smbfreelist_lock:
 *	r_freef
 *	r_freeb
 *
 * The following members are protected by the AVL tree rwlock:
 *	r_avl_node	(r__hdr.hdr_avl_node)
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
 *	r_rwlock > r_lkserlock > r_statelock
 */

typedef struct smbnode {
	/* Our linkage in the node cache AVL tree (see above). */
	smbfs_node_hdr_t	r__hdr;

	/* short-hand names for r__hdr members */
#define	r_avl_node	r__hdr.hdr_avl_node
#define	n_rpath		r__hdr.hdr_n_rpath
#define	n_rplen		r__hdr.hdr_n_rplen

	smbmntinfo_t	*n_mount;	/* VFS data */
	vnode_t		*r_vnode;	/* associated vnode */

	/*
	 * Linkage in smbfreelist, for reclaiming nodes.
	 * Lock for the free list is: smbfreelist_lock
	 */
	struct smbnode	*r_freef;	/* free list forward pointer */
	struct smbnode	*r_freeb;	/* free list back pointer */

	smbfs_rwlock_t	r_rwlock;	/* serialize write/setattr requests */
	smbfs_rwlock_t	r_lkserlock;	/* serialize lock with other ops */
	kmutex_t	r_statelock;	/* protect (most) smbnode fields */

	/*
	 * File handle, directory search handle,
	 * and reference counts for them, etc.
	 * Lock for these is: r_lkserlock
	 */
	int		n_dirrefs;
	struct smbfs_fctx	*n_dirseq;	/* ff context */
	int		n_dirofs;	/* last ff offset */
	int		n_fidrefs;
	uint16_t	n_fid;		/* file handle */
	enum vtype	n_ovtype;	/* vnode type opened */
	uint32_t	n_rights;	/* granted rights */
	int		n_vcgenid;	/* gereration no. (reconnect) */

	/*
	 * Misc. bookkeeping
	 */
	cred_t		*r_cred;	/* current credentials */
	u_offset_t	r_nextr;	/* next read offset (read-ahead) */
	long		r_mapcnt;	/* count of mmapped pages */
	uint_t		r_inmap;	/* to serialize read/write and mmap */
	uint_t		r_count;	/* # of refs not reflect in v_count */
	uint_t		r_awcount;	/* # of outstanding async write */
	uint_t		r_gcount;	/* getattrs waiting to flush pages */
	uint_t		r_flags;	/* flags, see below */
	uint32_t	n_flag;		/* N--- flags below */
	uint_t		r_error;	/* async write error */
	kcondvar_t	r_cv;		/* condvar for blocked threads */
	avl_tree_t	r_dir;		/* cache of readdir responses */
	rddir_cache	*r_direof;	/* pointer to the EOF entry */
	u_offset_t	r_modaddr;	/* address for page in writenp */
	kthread_t	*r_serial;	/* id of purging thread */
	list_t		r_indelmap;	/* list of delmap callers */

	/*
	 * Attributes: local, and as last seen on the server.
	 * See notes above re: r_size vs r_attr.fa_size, etc.
	 */
	smbfattr_t	r_attr;		/* attributes from the server */
	hrtime_t	r_attrtime;	/* time attributes become invalid */
	hrtime_t	r_mtime;	/* client time file last modified */
	len_t		r_size;		/* client's view of file size */

	/*
	 * Security attributes.
	 */
	vsecattr_t	r_secattr;
	hrtime_t	r_sectime;

	/*
	 * Other attributes, not carried in smbfattr_t
	 */
	u_longlong_t	n_ino;
	uid_t		n_uid;
	gid_t		n_gid;
	mode_t		n_mode;
} smbnode_t;

/*
 * Flag bits in: smbnode_t .n_flag
 */
#define	NFLUSHINPROG	0x00001
#define	NFLUSHWANT	0x00002 /* they should gone ... */
#define	NMODIFIED	0x00004 /* bogus, until async IO implemented */
#define	NREFPARENT	0x00010 /* node holds parent from recycling */
#define	NGOTIDS		0x00020
#define	NRDIRSERIAL	0x00080	/* serialize readdir operation */
#define	NISMAPPED	0x00800
#define	NFLUSHWIRE	0x01000
#define	NATTRCHANGED	0x02000 /* kill cached attributes at close */
#define	NALLOC		0x04000 /* being created */
#define	NWALLOC		0x08000 /* awaiting creation */
#define	N_XATTR		0x10000 /* extended attribute (dir or file) */

/*
 * Flag bits in: smbnode_t .r_flags
 */
#define	RREADDIRPLUS	0x1	/* issue a READDIRPLUS instead of READDIR */
#define	RDIRTY		0x2	/* dirty pages from write operation */
#define	RSTALE		0x4	/* file handle is stale */
#define	RMODINPROGRESS	0x8	/* page modification happening */
#define	RTRUNCATE	0x10	/* truncating, don't commit */
#define	RHAVEVERF	0x20	/* have a write verifier to compare against */
#define	RCOMMIT		0x40	/* commit in progress */
#define	RCOMMITWAIT	0x80	/* someone is waiting to do a commit */
#define	RHASHED		0x100	/* smbnode is in the "hash" AVL tree */
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

/*
 * A macro to compute the separator that should be used for
 * names under some directory.  See smbfs_fullpath().
 */
#define	SMBFS_DNP_SEP(dnp) \
	(((dnp->n_flag & N_XATTR) == 0 && dnp->n_rplen > 1) ? '\\' : '\0')

#ifdef __cplusplus
}
#endif

#endif /* _FS_SMBFS_NODE_H_ */
