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
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef	_NFS_EXPORT_H
#define	_NFS_EXPORT_H

#include <nfs/nfs_sec.h>
#include <nfs/auth.h>
#include <sys/vnode.h>
#include <nfs/nfs4.h>
#include <sys/kiconv.h>
#include <sys/avl.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * nfs pseudo flavor number is owned by IANA. Need to make sure the
 * Solaris specific NFS_FLAVOR_NOMAP number will not overlap with any
 * new IANA defined pseudo flavor numbers. The chance for the overlap
 * is very small since the growth of new flavor numbers is expected
 * to be limited.
 */
#define	NFS_FLAVOR_NOMAP	999999	/* no nfs flavor mapping */

/*
 * As duplicate flavors can be passed into exportfs in the arguments, we
 * allocate a cleaned up array with non duplicate flavors on the stack.
 * So we need to know how much to allocate.
 */
#define	MAX_FLAVORS		6	/* none, sys, dh, krb5, krb5i krb5p */

/*
 * Note: exported_lock is currently used to ensure the integrity of
 * the secinfo fields.
 */
struct secinfo {
	seconfig_t	s_secinfo;	/* /etc/nfssec.conf entry */
	unsigned int	s_flags;	/* flags (see below) */
	int32_t		s_refcnt;	/* reference count for tracking */
					/* how many children (self included) */
					/* use this flavor. */
	int 		s_window;	/* window */
	uint_t		s_rootid;	/* UID to use for authorized roots */
	int		s_rootcnt;	/* count of root names */
	caddr_t		*s_rootnames;	/* array of root names */
					/* they are strings for AUTH_DES and */
					/* rpc_gss_principal_t for RPCSEC_GSS */
};

#ifdef _SYSCALL32
struct secinfo32 {
	seconfig32_t	s_secinfo;	/* /etc/nfssec.conf entry */
	uint32_t	s_flags;	/* flags (see below) */
	int32_t		s_refcnt;	/* reference count for tracking */
					/* how many children (self included) */
					/* use this flavor. */
	int32_t 	s_window;	/* window */
	uint32_t	s_rootid;	/* UID to use for authorized roots */
	int32_t		s_rootcnt;	/* count of root names */
	caddr32_t	s_rootnames;	/* array of root names */
					/* they are strings for AUTH_DES and */
					/* rpc_gss_principal_t for RPCSEC_GSS */
};
#endif /* _SYSCALL32 */

/*
 * security negotiation related
 */

#define	SEC_QUERY	0x01	/* query sec modes */

struct sec_ol {
	int		sec_flags;	/* security nego flags */
	uint_t		sec_index;	/* index into sec flavor array */
};

/*
 * Per-mode flags (secinfo.s_flags)
 */
#define	M_RO		0x01	/* exported ro to all */
#define	M_ROL		0x02	/* exported ro to all listed */
#define	M_RW		0x04	/* exported rw to all */
#define	M_RWL		0x08	/* exported ro to all listed */
#define	M_ROOT		0x10	/* root list is defined */
#define	M_4SEC_EXPORTED	0x20	/* this is an explicitly shared flavor */
#define	M_NONE		0x40	/* none list is defined */
#define	M_MAP		0x80	/* uidmap and/or gidmap is defined */

/* invalid secinfo reference count */
#define	SEC_REF_INVALID(p) ((p)->s_refcnt < 1)

/* last secinfo reference */
#define	SEC_REF_LAST(p) ((p)->s_refcnt == 1)

/* sec flavor explicitly shared for the exported node */
#define	SEC_REF_EXPORTED(p) ((p)->s_flags & M_4SEC_EXPORTED)

/* the only reference count left is for referring itself */
#define	SEC_REF_SELF(p) (SEC_REF_LAST(p) && SEC_REF_EXPORTED(p))

/*
 * The export information passed to exportfs() (Version 2)
 */
#define	EX_CURRENT_VERSION 2	/* current version of exportdata struct */

struct exportdata {
	int		ex_version;	/* structure version */
	char		*ex_path;	/* exported path */
	size_t		ex_pathlen;	/* path length */
	int		ex_flags;	/* flags */
	unsigned int	ex_anon;	/* uid for unauthenticated requests */
	int		ex_seccnt;	/* count of security modes */
	struct secinfo	*ex_secinfo;	/* security mode info */
	char		*ex_index;	/* index file for public filesystem */
	char		*ex_log_buffer;	/* path to logging buffer file */
	size_t		ex_log_bufferlen;	/* buffer file path len */
	char		*ex_tag;	/* tag used to identify log config */
	size_t		ex_taglen;	/* tag length */
};

#ifdef _SYSCALL32
struct exportdata32 {
	int32_t		ex_version;	/* structure version */
	caddr32_t	ex_path;	/* exported path */
	int32_t		ex_pathlen;	/* path length */
	int32_t		ex_flags;	/* flags */
	uint32_t	ex_anon;	/* uid for unauthenticated requests */
	int32_t		ex_seccnt;	/* count of security modes */
	caddr32_t	ex_secinfo;	/* security mode info */
	caddr32_t	ex_index;	/* index file for public filesystem */
	caddr32_t	ex_log_buffer;	/* path to logging buffer file */
	int32_t		ex_log_bufferlen;	/* buffer file path len */
	caddr32_t	ex_tag;		/* tag used to identify log config */
	int32_t		ex_taglen;	/* tag length */
};
#endif /* _SYSCALL32 */

/*
 * exported vfs flags.
 */

#define	EX_NOSUID	0x01	/* exported with unsetable set[ug]ids */
#define	EX_ACLOK	0x02	/* exported with maximal access if acl exists */
#define	EX_PUBLIC	0x04	/* exported with public filehandle */
#define	EX_NOSUB	0x08	/* no nfs_getfh or MCL below export point */
#define	EX_INDEX	0x10	/* exported with index file specified */
#define	EX_LOG		0x20	/* logging enabled */
#define	EX_LOG_ALLOPS	0x40	/* logging of all RPC operations enabled */
				/* by default only operations which affect */
				/* transaction logging are enabled */
#define	EX_PSEUDO	0x80	/* pseudo filesystem export */
#ifdef VOLATILE_FH_TEST
#define	EX_VOLFH	0x100	/* XXX nfsv4 fh may expire anytime */
#define	EX_VOLRNM	0x200	/* XXX nfsv4 fh expire at rename */
#define	EX_VOLMIG	0x400	/* XXX nfsv4 fh expire at migration */
#define	EX_NOEXPOPEN	0x800	/* XXX nfsv4 fh no expire with open */
#endif /* VOLATILE_FH_TEST */

#define	EX_CHARMAP	0x1000	/* NFS may need a character set conversion */
#define	EX_NOACLFAB	0x2000	/* If set, NFSv2 and v3 servers doesn't */
				/* fabricate ACL for VOP_GETSECATTR OTW call */

#ifdef	_KERNEL

#define	RPC_IDEMPOTENT	0x1	/* idempotent or not */
/*
 * Be very careful about which NFS procedures get the RPC_ALLOWANON bit.
 * Right now, if this bit is on, we ignore the results of per NFS request
 * access control.
 */
#define	RPC_ALLOWANON	0x2	/* allow anonymous access */
#define	RPC_MAPRESP	0x4	/* use mapped response buffer */
#define	RPC_AVOIDWORK	0x8	/* do work avoidance for dups */
#define	RPC_PUBLICFH_OK	0x10	/* allow use of public filehandle */

/*
 * RPC_ALL is an or of all above bits to be used with "don't care"
 * nfsv4 ops. The flags of an nfsv4 request is the bit-AND of the
 * per-op flags.
 */
#define	RPC_ALL	(RPC_IDEMPOTENT|RPC_ALLOWANON|RPC_AVOIDWORK|RPC_PUBLICFH_OK)


#ifdef VOLATILE_FH_TEST
struct ex_vol_rename {
	nfs_fh4_fmt_t vrn_fh_fmt;
	struct ex_vol_rename *vrn_next;
};
#endif /* VOLATILE_FH_TEST */

/*
 * An auth cache client entry.  This is the umbrella structure and contains all
 * related auth_cache entries in the authc_tree AVL tree.
 */
struct auth_cache_clnt {
	avl_node_t		authc_link;
	struct netbuf		authc_addr;	/* address of the client */
	krwlock_t		authc_lock;	/* protects authc_tree */
	avl_tree_t		authc_tree;	/* auth_cache entries */
};

/*
 * An auth cache entry can exist in 6 states.
 *
 * A NEW entry was recently allocated and added to the cache.  It does not
 * contain the valid auth state yet.
 *
 * A WAITING entry is one which is actively engaging the user land mountd code
 * to authenticate or re-authenticate it.  The auth state might not be valid
 * yet.  The other threads should wait on auth_cv until the retrieving thread
 * finishes the retrieval and changes the auth cache entry to FRESH, or NEW (in
 * a case this entry had no valid auth state yet).
 *
 * A REFRESHING entry is one which is actively engaging the user land mountd
 * code to re-authenticate the cache entry.  There is currently no other thread
 * waiting for the results of the refresh.
 *
 * A FRESH entry is one which is valid (it is either newly retrieved or has
 * been refreshed at least once).
 *
 * A STALE entry is one which has been detected to be too old.  The transition
 * from FRESH to STALE prevents multiple threads from submitting refresh
 * requests.
 *
 * An INVALID entry is one which was either STALE or REFRESHING and was deleted
 * out of the encapsulating exi.  Since we can't delete it yet, we mark it as
 * INVALID, which lets the refresh thread know not to work on it and free it
 * instead.
 *
 * Note that the auth state of the entry is valid, even if the entry is STALE.
 * Just as you can eat stale bread, you can consume a stale cache entry. The
 * only time the contents change could be during the transition from REFRESHING
 * or WAITING to FRESH.
 *
 * Valid state transitions:
 *
 *          alloc
 *            |
 *            v
 *         +-----+
 *    +--->| NEW |------>free
 *    |    +-----+
 *    |       |
 *    |       v
 *    |  +---------+
 *    +<-| WAITING |
 *    ^  +---------+
 *    |       |
 *    |       v
 *    |       +<--------------------------+<---------------+
 *    |       |                           ^                |
 *    |       v                           |                |
 *    |   +-------+    +-------+    +------------+    +---------+
 *    +---| FRESH |--->| STALE |--->| REFRESHING |--->| WAITING |
 *        +-------+    +-------+    +------------+    +---------+
 *            |            |              |
 *            |            v              |
 *            v       +---------+         |
 *          free<-----| INVALID |<--------+
 *                    +---------+
 */
typedef enum auth_state {
	NFS_AUTH_FRESH,
	NFS_AUTH_STALE,
	NFS_AUTH_REFRESHING,
	NFS_AUTH_INVALID,
	NFS_AUTH_NEW,
	NFS_AUTH_WAITING
} auth_state_t;

/*
 * An authorization cache entry
 *
 * Either the state in auth_state will protect the
 * contents or auth_lock must be held.
 */
struct auth_cache {
	avl_node_t		auth_link;
	struct auth_cache_clnt	*auth_clnt;
	int			auth_flavor;
	cred_t			*auth_clnt_cred;
	uid_t			auth_srv_uid;
	gid_t			auth_srv_gid;
	uint_t			auth_srv_ngids;
	gid_t			*auth_srv_gids;
	int			auth_access;
	time_t			auth_time;
	time_t			auth_freshness;
	auth_state_t		auth_state;
	kmutex_t		auth_lock;
	kcondvar_t		auth_cv;
};

#define	AUTH_TABLESIZE	32

/*
 * Structure containing log file meta-data.
 */
struct log_file {
	unsigned int	lf_flags;	/* flags (see below) */
	int		lf_writers;	/* outstanding writers */
	int		lf_refcnt;	/* references to this struct */
	caddr_t		lf_path;	/* buffer file location */
	vnode_t		*lf_vp;		/* vnode for the buffer file */
	kmutex_t	lf_lock;
	kcondvar_t	lf_cv_waiters;
};

/*
 * log_file and log_buffer flags.
 */
#define	L_WAITING	0x01		/* flush of in-core data to stable */
					/* storage in progress */
#define	L_PRINTED	0x02		/* error message printed to console */
#define	L_ERROR		0x04		/* error condition detected */

/*
 * The logging buffer information.
 * This structure may be shared by multiple exportinfo structures,
 * if they share the same buffer file.
 * This structure contains the basic information about the buffer, such
 * as it's location in the filesystem.
 *
 * 'lb_lock' protects all the fields in this structure except for 'lb_path',
 * and 'lb_next'.
 * 'lb_path' is a write-once/read-many field which needs no locking, it is
 * set before the structure is linked to any exportinfo structure.
 * 'lb_next' is protected by the log_buffer_list_lock.
 */
struct log_buffer {
	unsigned int	lb_flags;	/* L_ONLIST set? */
	int		lb_refcnt;	/* references to this struct */
	unsigned int	lb_rec_id;	/* used to generate unique id */
	caddr_t		lb_path;	/* buffer file pathname */
	struct log_file	*lb_logfile;	/* points to log_file structure */
	kmutex_t	lb_lock;
	struct log_buffer	*lb_next;
	kcondvar_t	lb_cv_waiters;
	caddr_t		lb_records;	/* linked list of records to write */
	int		lb_num_recs;	/* # of records to write */
	ssize_t		lb_size_queued; /* number of bytes queued for write */
};

#define	LOG_BUFFER_HOLD(lbp)	{ \
	mutex_enter(&(lbp)->lb_lock); \
	(lbp)->lb_refcnt++; \
	mutex_exit(&(lbp)->lb_lock); \
}

#define	LOG_BUFFER_RELE(lbp)	{ \
	log_buffer_rele(lbp); \
}

/*
 * Structure for character set conversion mapping based on client address.
 */
struct charset_cache {
	struct charset_cache *next;
	kiconv_t	inbound;
	kiconv_t	outbound;
	struct sockaddr	client_addr;
};

/* Forward declarations */
struct exportinfo;
struct exp_visible;
struct svc_req;

/*
 * Treenodes are used to build tree representing every node which is part
 * of nfs server pseudo namespace. They are connected with both exportinfo
 * and exp_visible struct. They were introduced to avoid lookup of ".."
 * in the underlying file system during unshare, which was failing if the
 * file system was forcibly unmounted or if the directory was removed.
 * One exp_visible_t can be shared via several treenode_t, i.e.
 * different tree_vis can point to the same exp_visible_t.
 * This will happen if some directory is on two different shared paths:
 * E.g. after share /tmp/a/b1 and share /tmp/a/b2 there will be two treenodes
 * corresponding to /tmp/a and both will have same value in tree_vis.
 *
 *
 *
 *     NEW DATA STRUCT         ORIGINAL DATA STRUCT
 *
 * ns_root +---+               +----------+
 *         | / |               |PSEUDO EXP|-->+---+   +---+   +---+
 *         +---+---------  ----+----------+   | a |-->| k |-->| b |
 *          /\                                +---+   +---+   +---+
 *         /  \                                .       .       .
 *     +---+...\.........  .....................       .       .
 *    *| a |    \              +----------+            .       .
 *     +---+-----\-------  ----|REAL EXP a|            .       .
 *       /        \            +----------+            .       .
 *      /        +===+...  .............................       .
 *     /        *| k |         +----------+                    .
 *    /          +===+---  ----|REAL EXP k|                    .
 *   /                         +----------+                    .
 *  +===+................  .....................................
 * *| b |                      +----------+
 *  +===+----------------  ----|REAL EXP b|-->+---+
 *     \                       +----------+   | d |
 *     +===+.............  ...................+---+
 *     | d |                   +----------+
 *     +===+-------------  ----|PSEUDO EXP|-->+---+   +---+
 *     /                       +----------+   | e |-->| g |
 * +---+.................  ...................+---+   +---+
 * | e |                                              .
 * +---+                                              .
 *    \                                               .
 *    +---+..............  ............................
 *   *| g |                    +----------+
 *    +---+--------------  ----|REAL EXP g|
 *                             +----------+
 *
 *
 *
 * +===+               +---+                    +---+
 * | b |..mountpoint   | e |..directory/file   *| a |..node is shared
 * +===+  (VROOT)      +---+                    +---+
 *
 *
 * Bi-directional interconnect:
 * treenode_t::tree_exi ---------  exportinfo_t::exi_tree
 * One-way direction connection:
 * treenode_t::tree_vis .........> exp_visible_t
 */
/* Access to treenode_t is under protection of exported_lock RW_LOCK */
typedef struct treenode {
	/* support for generic n-ary trees */
	struct treenode *tree_parent;
	struct treenode *tree_child_first;
	struct treenode *tree_sibling; /* next sibling */
	/* private, nfs specific part */
	struct exportinfo  *tree_exi;
	struct exp_visible *tree_vis;
} treenode_t;

/*
 * TREE_ROOT checks if the node corresponds to a filesystem root
 * TREE_EXPORTED checks if the node is explicitly shared
 */

#define	TREE_ROOT(t) \
	((t)->tree_exi && (t)->tree_exi->exi_vp->v_flag & VROOT)

#define	TREE_EXPORTED(t) \
	((t)->tree_exi && !PSEUDO((t)->tree_exi))

/* Root of nfs pseudo namespace */
extern treenode_t *ns_root;

#define	EXPTABLESIZE   256

struct exp_hash {
	struct exportinfo	*prev;  /* ptr to the previous exportinfo */
	struct exportinfo	*next;  /* ptr to the next exportinfo */
	struct exportinfo	**bckt; /* backpointer to the hash bucket */
};

/*
 * A node associated with an export entry on the
 * list of exported filesystems.
 *
 * exi_count+exi_lock protects an individual exportinfo from being freed
 * when in use.
 *
 * You must have the writer lock on exported_lock to add/delete an exportinfo
 * structure to/from the list.
 *
 * exi_volatile_dev maps to VSW_VOLATILEDEV.  It means that the
 * underlying fs devno can change on each mount.  When set, the server
 * should not use va_fsid for a GETATTR(FATTR4_FSID) reply.  It must
 * use exi_fsid because it is guaranteed to be persistent.  This isn't
 * in any way related to NFS4 volatile filehandles.
 *
 * The exi_cache_lock protects the exi_cache AVL trees.
 */
struct exportinfo {
	struct exportdata	exi_export;
	fsid_t			exi_fsid;
	struct fid		exi_fid;
	struct exp_hash		fid_hash;
	struct exp_hash		path_hash;
	struct treenode		*exi_tree;
	fhandle_t		exi_fh;
	krwlock_t		exi_cache_lock;
	kmutex_t		exi_lock;
	uint_t			exi_count;
	vnode_t			*exi_vp;
	vnode_t			*exi_dvp;
	avl_tree_t		*exi_cache[AUTH_TABLESIZE];
	struct log_buffer	*exi_logbuffer;
	struct exp_visible	*exi_visible;
	struct charset_cache	*exi_charset;
	unsigned		exi_volatile_dev:1;
	unsigned		exi_moved:1;
#ifdef VOLATILE_FH_TEST
	uint32_t		exi_volatile_id;
	struct ex_vol_rename	*exi_vol_rename;
	kmutex_t		exi_vol_rename_lock;
#endif /* VOLATILE_FH_TEST */
};

typedef struct exportinfo exportinfo_t;
typedef struct exportdata exportdata_t;
typedef struct secinfo secinfo_t;

/*
 * exp_visible is a visible list per filesystem. It is for filesystems
 * that may need a limited view of its contents. A pseudo export and
 * a real export at the mount point (VROOT) which has a subtree shared
 * has a visible list.
 *
 * The exi_visible field is NULL for normal, non=pseudo filesystems
 * which do not have any subtree exported. If the field is non-null,
 * it points to a list of visible entries, identified by vis_fid and/or
 * vis_ino. The presence of a "visible" list means that if this export
 * can only have a limited view, it can only view the entries in the
 * exp_visible list. The directories in the fid list comprise paths that
 * lead to exported directories.
 *
 * The vis_count field records the number of paths in this filesystem
 * that use this directory. The vis_exported field is non-zero if the
 * entry is an exported directory (leaf node).
 *
 * exp_visible itself is not reference counted. Each exp_visible is
 * referenced twice:
 * 1) from treenode::tree_vis
 * 2) linked from exportinfo::exi_visible
 * The 'owner' of exp_visible is the exportinfo structure. exp_visible should
 * be always freed only from exportinfo_t, never from treenode::tree_vis.
 */

struct exp_visible {
	vnode_t			*vis_vp;
	fid_t			vis_fid;
	u_longlong_t		vis_ino;
	int			vis_count;
	int			vis_exported;
	struct exp_visible	*vis_next;
	struct secinfo		*vis_secinfo;
	int			vis_seccnt;
};
typedef struct exp_visible exp_visible_t;

#define	PSEUDO(exi)	((exi)->exi_export.ex_flags & EX_PSEUDO)
#define	EXP_LINKED(exi)	((exi)->fid_hash.bckt != NULL)

#define	EQFSID(fsidp1, fsidp2)	\
	(((fsidp1)->val[0] == (fsidp2)->val[0]) && \
	    ((fsidp1)->val[1] == (fsidp2)->val[1]))

#define	EQFID(fidp1, fidp2)	\
	((fidp1)->fid_len == (fidp2)->fid_len && \
	    bcmp((char *)(fidp1)->fid_data, (char *)(fidp2)->fid_data, \
	    (uint_t)(fidp1)->fid_len) == 0)

#define	exportmatch(exi, fsid, fid)	\
	(EQFSID(&(exi)->exi_fsid, (fsid)) && EQFID(&(exi)->exi_fid, (fid)))

/*
 * Returns true iff exported filesystem is read-only to the given host.
 *
 * Note:  this macro should be as fast as possible since it's called
 * on each NFS modification request.
 */
#define	rdonly(ro, vp)	((ro) || vn_is_readonly(vp))
#define	rdonly4(req, cs)  \
	(vn_is_readonly((cs)->vp) || \
	    (nfsauth4_access((cs)->exi, (cs)->vp, (req), (cs)->basecr, NULL, \
	    NULL, NULL, NULL) & (NFSAUTH_RO | NFSAUTH_LIMITED)))

extern int	nfsauth4_access(struct exportinfo *, vnode_t *,
    struct svc_req *, cred_t *, uid_t *, gid_t *, uint_t *, gid_t **);
extern int	nfsauth4_secinfo_access(struct exportinfo *,
    struct svc_req *, int, int, cred_t *);
extern int	nfsauth_cache_clnt_compar(const void *, const void *);
extern int	nfs_fhbcmp(char *, char *, int);
extern int	nfs_exportinit(void);
extern void	nfs_exportfini(void);
extern int	chk_clnt_sec(struct exportinfo *, struct svc_req *);
extern int	makefh(fhandle_t *, struct vnode *, struct exportinfo *);
extern int	makefh_ol(fhandle_t *, struct exportinfo *, uint_t);
extern int	makefh3(nfs_fh3 *, struct vnode *, struct exportinfo *);
extern int	makefh3_ol(nfs_fh3 *, struct exportinfo *, uint_t);
extern vnode_t *nfs_fhtovp(fhandle_t *, struct exportinfo *);
extern vnode_t *nfs3_fhtovp(nfs_fh3 *, struct exportinfo *);
extern struct	exportinfo *checkexport(fsid_t *, struct fid *);
extern struct	exportinfo *checkexport4(fsid_t *, struct fid *, vnode_t *);
extern void	exi_hold(struct exportinfo *);
extern void	exi_rele(struct exportinfo *);
extern struct exportinfo *nfs_vptoexi(vnode_t *, vnode_t *, cred_t *, int *,
    int *, bool_t);
extern int	nfs_check_vpexi(vnode_t *, vnode_t *, cred_t *,
			struct exportinfo **);
extern void	export_link(struct exportinfo *);
extern void	export_unlink(struct exportinfo *);
extern vnode_t *untraverse(vnode_t *);
extern int	vn_is_nfs_reparse(vnode_t *, cred_t *);
extern int	client_is_downrev(struct svc_req *);
extern char    *build_symlink(vnode_t *, cred_t *, size_t *);

/*
 * Functions that handle the NFSv4 server namespace
 */
extern exportinfo_t *vis2exi(treenode_t *);
extern int	treeclimb_export(struct exportinfo *);
extern void	treeclimb_unexport(struct exportinfo *);
extern int	nfs_visible(struct exportinfo *, vnode_t *, int *);
extern int	nfs_visible_inode(struct exportinfo *, ino64_t, int *);
extern int	has_visible(struct exportinfo *, vnode_t *);
extern void	free_visible(struct exp_visible *);
extern int	nfs_exported(struct exportinfo *, vnode_t *);
extern struct exportinfo *pseudo_exportfs(vnode_t *, fid_t *,
    struct exp_visible *, struct exportdata *);
extern int	vop_fid_pseudo(vnode_t *, fid_t *);
extern int	nfs4_vget_pseudo(struct exportinfo *, vnode_t **, fid_t *);
/*
 * Functions that handle the NFSv4 server namespace security flavors
 * information.
 */
extern void	srv_secinfo_exp2pseu(struct exportdata *, struct exportdata *);
extern void	srv_secinfo_list_free(struct secinfo *, int);

/*
 * "public" and default (root) location for public filehandle
 */
extern struct exportinfo *exi_public, *exi_root;
extern fhandle_t nullfh2;	/* for comparing V2 filehandles */
extern krwlock_t exported_lock;
extern struct exportinfo *exptable[];

/*
 * Two macros for identifying public filehandles.
 * A v2 public filehandle is 32 zero bytes.
 * A v3 public filehandle is zero length.
 */
#define	PUBLIC_FH2(fh) \
	((fh)->fh_fsid.val[1] == 0 && \
	bcmp((fh), &nullfh2, sizeof (fhandle_t)) == 0)

#define	PUBLIC_FH3(fh) \
	((fh)->fh3_length == 0)

extern int	makefh4(nfs_fh4 *, struct vnode *, struct exportinfo *);
extern vnode_t *nfs4_fhtovp(nfs_fh4 *, struct exportinfo *, nfsstat4 *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _NFS_EXPORT_H */
