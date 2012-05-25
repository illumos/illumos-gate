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
 * $Id: smbfs_subr.h,v 1.25 2005/03/17 01:23:40 lindak Exp $
 */

/*
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FS_SMBFS_SMBFS_SUBR_H_
#define	_FS_SMBFS_SMBFS_SUBR_H_

#include <sys/cmn_err.h>
#include <netsmb/mchain.h>
#include <netsmb/smb_subr.h>
#include <smbfs/smbfs_node.h>

#if defined(DEBUG) || defined(lint)
#define	SMB_VNODE_DEBUG 1
#endif

#ifndef FALSE
#define	FALSE   (0)
#endif

#ifndef TRUE
#define	TRUE    (1)
#endif

/*
 * Let's use C99 standard variadic macros!
 * Also the C99 __func__ (function name) feature.
 */
#define	SMBFSERR(...) \
	smb_errmsg(CE_NOTE, __func__, __VA_ARGS__)
#define	SMBVDEBUG(...) \
	smb_errmsg(CE_CONT, __func__, __VA_ARGS__)

/*
 * Possible lock commands
 */
#define	SMB_LOCK_EXCL		0
#define	SMB_LOCK_SHARED		1
#define	SMB_LOCK_RELEASE	2

struct smb_cred;
struct smb_vc;
struct statvfs;
struct timespec;

/*
 * Types of find_first, find_next context objects
 */
typedef enum {
	ft_LM1 = 1,
	ft_LM2,
	ft_XA
} smbfs_fctx_type_t;

/*
 * Context to perform findfirst/findnext/findclose operations
 */
#define	SMBFS_RDD_FINDFIRST	0x01
#define	SMBFS_RDD_EOF		0x02
#define	SMBFS_RDD_FINDSINGLE	0x04
/* note	SMBFS_RDD_USESEARCH	0x08 replaced by smbfs_fctx_type */
#define	SMBFS_RDD_NOCLOSE	0x10

/*
 * Search context supplied by server
 */
#define	SMB_SKEYLEN		21			/* search context */
#define	SMB_DENTRYLEN		(SMB_SKEYLEN + 22)	/* entire entry */

struct smbfs_fctx {
	/*
	 * Setable values
	 */
	smbfs_fctx_type_t	f_type;
	int		f_flags;	/* SMBFS_RDD_ */
	/*
	 * Return values
	 */
	struct smbfattr	f_attr;		/* current attributes */
	u_longlong_t	f_inum;		/* current I number */
	char		*f_name;	/* current file name */
	int		f_nmlen;	/* name len */
	int		f_namesz;	/* memory allocated */
	/*
	 * Internal variables
	 */
	uint16_t	f_limit;	/* maximum number of entries */
	uint16_t	f_attrmask;	/* SMB_FA_ */
	int		f_wclen;
	const char	*f_wildcard;
	struct smbnode	*f_dnp;
	struct smb_cred	*f_scred;
	struct smb_share	*f_ssp;
	union {
		struct smb_rq *uf_rq;
		struct smb_t2rq *uf_t2;
	} f_urq;
	int		f_left;		/* entries left */
	int		f_ecnt;		/* entries left in current response */
	int		f_eofs;		/* entry offset in data block */
	uchar_t		f_skey[SMB_SKEYLEN]; /* server side search context */
	uchar_t		f_fname[8 + 1 + 3 + 1]; /* for 8.3 filenames */
	uint16_t	f_Sid;		/* Search handle (like a FID) */
	uint16_t	f_infolevel;
	int		f_rnamelen;
	char		*f_rname;	/* resume name */
	int		f_rnameofs;
	int		f_otws;		/* # over-the-wire ops so far */
	char		*f_firstnm;	/* first filename we got back */
	int		f_firstnmlen;
	int		f_rkey;		/* resume key */
};
typedef struct smbfs_fctx smbfs_fctx_t;

#define	f_rq	f_urq.uf_rq
#define	f_t2	f_urq.uf_t2

/*
 * smb level (smbfs_smb.c)
 */
int  smbfs_smb_lock(struct smbnode *np, int op, caddr_t id,
	offset_t start, uint64_t len,	int largelock,
	struct smb_cred *scrp, uint32_t timeout);
int  smbfs_smb_qfsattr(struct smb_share *ssp, struct smb_fs_attr_info *,
	struct smb_cred *scrp);
int  smbfs_smb_statfs(struct smb_share *ssp, statvfs64_t *sbp,
	struct smb_cred *scrp);

int  smbfs_smb_setdisp(struct smbnode *np, uint16_t fid, uint8_t newdisp,
	struct smb_cred *scrp);
int  smbfs_smb_setfsize(struct smbnode *np, uint16_t fid, uint64_t newsize,
	struct smb_cred *scrp);

int  smbfs_smb_getfattr(struct smbnode *np, struct smbfattr *fap,
	struct smb_cred *scrp);

int  smbfs_smb_setfattr(struct smbnode *np, int fid,
	uint32_t attr, struct timespec *mtime, struct timespec *atime,
	struct smb_cred *scrp);

int  smbfs_smb_open(struct smbnode *np, const char *name, int nmlen,
	int xattr, uint32_t rights, struct smb_cred *scrp,
	uint16_t *fidp, uint32_t *rightsp, struct smbfattr *fap);
int  smbfs_smb_tmpopen(struct smbnode *np, uint32_t rights,
	struct smb_cred *scrp, uint16_t *fidp);
int  smbfs_smb_close(struct smb_share *ssp, uint16_t fid,
	struct timespec *mtime, struct smb_cred *scrp);
int  smbfs_smb_tmpclose(struct smbnode *ssp, uint16_t fid,
	struct smb_cred *scrp);
int  smbfs_smb_create(struct smbnode *dnp, const char *name, int nmlen,
	int xattr, uint32_t disp, struct smb_cred *scrp, uint16_t *fidp);
int  smbfs_smb_delete(struct smbnode *np, struct smb_cred *scrp,
	const char *name, int len, int xattr);
int  smbfs_smb_rename(struct smbnode *src, struct smbnode *tdnp,
	const char *tname, int tnmlen, struct smb_cred *scrp);
int  smbfs_smb_t2rename(struct smbnode *np, const char *tname, int tnmlen,
	struct smb_cred *scrp, uint16_t fid, int replace);
int  smbfs_smb_move(struct smbnode *src, struct smbnode *tdnp,
	const char *tname, int tnmlen, uint16_t flags, struct smb_cred *scrp);
int  smbfs_smb_mkdir(struct smbnode *dnp, const char *name, int len,
	struct smb_cred *scrp);
int  smbfs_smb_rmdir(struct smbnode *np, struct smb_cred *scrp);
int  smbfs_smb_findopen(struct smbnode *dnp, const char *wildcard, int wclen,
	int attr, struct smb_cred *scrp, struct smbfs_fctx **ctxpp);
int  smbfs_smb_findnext(struct smbfs_fctx *ctx, int limit,
	struct smb_cred *scrp);
int  smbfs_smb_findclose(struct smbfs_fctx *ctx, struct smb_cred *scrp);
int  smbfs_fullpath(struct mbchain *mbp, struct smb_vc *vcp,
	struct smbnode *dnp, const char *name, int nmlen, uint8_t sep);
int  smbfs_smb_lookup(struct smbnode *dnp, const char **namep, int *nmlenp,
	struct smbfattr *fap, struct smb_cred *scrp);
int  smbfs_smb_hideit(struct smbnode *np, const char *name, int len,
	struct smb_cred *scrp);
int  smbfs_smb_unhideit(struct smbnode *np, const char *name, int len,
			struct smb_cred *scrp);
int smbfs_smb_flush(struct smbnode *np, struct smb_cred *scrp);
int smbfs_0extend(vnode_t *vp, uint16_t fid, len_t from, len_t to,
		struct smb_cred *scredp, int timo);

/* get/set security descriptor */
int  smbfs_smb_getsec_m(struct smb_share *ssp, uint16_t fid,
	struct smb_cred *scrp, uint32_t selector,
	mblk_t **res, uint32_t *reslen);
int  smbfs_smb_setsec_m(struct smb_share *ssp, uint16_t fid,
	struct smb_cred *scrp, uint32_t selector, mblk_t **mp);

/*
 * VFS-level init, fini stuff
 */

int smbfs_vfsinit(void);
void smbfs_vfsfini(void);
int smbfs_subrinit(void);
void smbfs_subrfini(void);
int smbfs_clntinit(void);
void smbfs_clntfini(void);

void smbfs_zonelist_add(smbmntinfo_t *smi);
void smbfs_zonelist_remove(smbmntinfo_t *smi);

int smbfs_check_table(struct vfs *vfsp, struct smbnode *srp);
void smbfs_destroy_table(struct vfs *vfsp);
void smbfs_rflush(struct vfs *vfsp, cred_t *cr);
void smbfs_flushall(cred_t *cr);

int smbfs_directio(vnode_t *vp, int cmd, cred_t *cr);

uint32_t smbfs_newnum(void);
int smbfs_newname(char *buf, size_t buflen);

/*
 * Function definitions - those having to do with
 * smbfs nodes, vnodes, etc
 */

void smbfs_attrcache_prune(struct smbnode *np);
void smbfs_attrcache_remove(struct smbnode *np);
void smbfs_attrcache_rm_locked(struct smbnode *np);
#ifndef	DEBUG
#define	smbfs_attrcache_rm_locked(np)	(np)->r_attrtime = gethrtime()
#endif
void smbfs_attr_touchdir(struct smbnode *dnp);
void smbfs_attrcache_fa(vnode_t *vp, struct smbfattr *fap);

int smbfs_validate_caches(struct vnode *vp, cred_t *cr);
void smbfs_purge_caches(struct vnode *vp, cred_t *cr);

void smbfs_addfree(struct smbnode *sp);
void smbfs_rmhash(struct smbnode *);

/* See avl_create in smbfs_vfsops.c */
void smbfs_init_hash_avl(avl_tree_t *);

uint32_t smbfs_gethash(const char *rpath, int prlen);
uint32_t smbfs_getino(struct smbnode *dnp, const char *name, int nmlen);

extern struct smbfattr smbfs_fattr0;
smbnode_t *smbfs_node_findcreate(smbmntinfo_t *mi,
    const char *dir, int dirlen,
    const char *name, int nmlen,
    char sep, struct smbfattr *fap);

int smbfs_nget(vnode_t *dvp, const char *name, int nmlen,
	struct smbfattr *fap, vnode_t **vpp);

void smbfs_fname_tolocal(struct smbfs_fctx *ctx);
char    *smbfs_name_alloc(const char *name, int nmlen);
void	smbfs_name_free(const char *name, int nmlen);

int smbfs_readvnode(vnode_t *, uio_t *, cred_t *, struct vattr *);
int smbfs_writevnode(vnode_t *vp, uio_t *uiop, cred_t *cr,
			int ioflag, int timo);
int smbfsgetattr(vnode_t *vp, struct vattr *vap, cred_t *cr);

void smbfs_invalidate_pages(vnode_t *vp, u_offset_t off, cred_t *cr);

/* smbfs ACL support */
int smbfs_acl_getids(vnode_t *, cred_t *);
int smbfs_acl_setids(vnode_t *, vattr_t *, cred_t *);
int smbfs_acl_getvsa(vnode_t *, vsecattr_t *, int, cred_t *);
int smbfs_acl_setvsa(vnode_t *, vsecattr_t *, int, cred_t *);
int smbfs_acl_iocget(vnode_t *, intptr_t, int, cred_t *);
int smbfs_acl_iocset(vnode_t *, intptr_t, int, cred_t *);

/* smbfs_xattr.c */
int smbfs_get_xattrdir(vnode_t *dvp, vnode_t **vpp, cred_t *cr, int);
int smbfs_xa_parent(vnode_t *vp, vnode_t **vpp);
int smbfs_xa_exists(vnode_t *vp, cred_t *cr);
int smbfs_xa_getfattr(struct smbnode *np, struct smbfattr *fap,
	struct smb_cred *scrp);
int smbfs_xa_findopen(struct smbfs_fctx *ctx, struct smbnode *dnp,
	const char *name, int nmlen);
int smbfs_xa_findnext(struct smbfs_fctx *ctx, uint16_t limit);
int smbfs_xa_findclose(struct smbfs_fctx *ctx);

/* For Solaris, interruptible rwlock */
int smbfs_rw_enter_sig(smbfs_rwlock_t *l, krw_t rw, int intr);
int smbfs_rw_tryenter(smbfs_rwlock_t *l, krw_t rw);
void smbfs_rw_exit(smbfs_rwlock_t *l);
int smbfs_rw_lock_held(smbfs_rwlock_t *l, krw_t rw);
void smbfs_rw_init(smbfs_rwlock_t *l, char *name, krw_type_t type, void *arg);
void smbfs_rw_destroy(smbfs_rwlock_t *l);

#endif /* !_FS_SMBFS_SMBFS_SUBR_H_ */
