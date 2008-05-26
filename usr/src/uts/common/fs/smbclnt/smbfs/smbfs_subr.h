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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FS_SMBFS_SMBFS_SUBR_H_
#define	_FS_SMBFS_SMBFS_SUBR_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/cmn_err.h>
#include <netsmb/mchain.h>

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
 * Context to perform findfirst/findnext/findclose operations
 */
#define	SMBFS_RDD_FINDFIRST	0x01
#define	SMBFS_RDD_EOF		0x02
#define	SMBFS_RDD_FINDSINGLE	0x04
#define	SMBFS_RDD_USESEARCH	0x08
#define	SMBFS_RDD_NOCLOSE	0x10
#define	SMBFS_RDD_GOTRNAME	0x1000

/*
 * Search context supplied by server
 */
#define	SMB_SKEYLEN		21			/* search context */
#define	SMB_DENTRYLEN		(SMB_SKEYLEN + 22)	/* entire entry */

struct smbfs_fctx {
	/*
	 * Setable values
	 */
	int		f_flags;	/* SMBFS_RDD_ */
	/*
	 * Return values
	 */
	struct smbfattr	f_attr;		/* current attributes */
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
	uchar_t 	f_skey[SMB_SKEYLEN]; /* server side search context */
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
 * smb level
 */
int  smbfs_smb_lock(struct smbnode *np, int op, caddr_t id,
	offset_t start, uint64_t len,	int largelock,
	struct smb_cred *scrp, uint32_t timeout);
int  smbfs_smb_qfsattr(struct smb_share *ssp, uint32_t *attrp,
	struct smb_cred *scrp);
int  smbfs_smb_statfs(struct smb_share *ssp, statvfs64_t *sbp,
	struct smb_cred *scrp);
int  smbfs_smb_setfsize(struct smbnode *np, uint16_t fid, uint64_t newsize,
	struct smb_cred *scrp);

int  smbfs_smb_getfattr(struct smbnode *np, struct smbfattr *fap,
	struct smb_cred *scrp);

int  smbfs_smb_setfattr(struct smbnode *np, uint16_t fid,
	uint32_t attr, struct timespec *mtime, struct timespec *atime,
	struct smb_cred *scrp);

int  smbfs_smb_setpattr(struct smbnode *np,
	uint32_t attr, struct timespec *mtime, struct timespec *atime,
	struct smb_cred *scrp);

int  smbfs_smb_open(struct smbnode *np, uint32_t rights, struct smb_cred *scrp,
	int *attrcacheupdated, uint16_t *fidp, const char *name, int nmlen,
	int xattr, len_t *sizep, uint32_t *rightsp);
int  smbfs_smb_tmpopen(struct smbnode *np, uint32_t rights,
	struct smb_cred *scrp, uint16_t *fidp);
int  smbfs_smb_close(struct smb_share *ssp, uint16_t fid,
	struct timespec *mtime, struct smb_cred *scrp);
int  smbfs_smb_tmpclose(struct smbnode *ssp, uint16_t fid,
	struct smb_cred *scrp);
int  smbfs_smb_create(struct smbnode *dnp, const char *name, int len,
	struct smb_cred *scrp, uint16_t *fidp, uint32_t disp, int xattr);
int  smbfs_smb_delete(struct smbnode *np, struct smb_cred *scrp,
	const char *name, int len, int xattr);
int  smbfs_smb_rename(struct smbnode *src, struct smbnode *tdnp,
	const char *tname, int tnmlen, struct smb_cred *scrp);
int  smbfs_smb_t2rename(struct smbnode *np, struct smbnode *tdnp,
	const char *tname, int tnmlen, struct smb_cred *scrp, int overwrite);
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
	struct smbnode *dnp, const char *name, int *nmlenp, uint8_t sep);
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

int  smbfs_getacl(vnode_t *vp, vsecattr_t *vsecattr,
	int *uidp, int *gidp, int flag, cred_t *cr);
int  smbfs_setacl(vnode_t *vp, vsecattr_t *vsecattr,
	int uid, int gid, int flag, cred_t *cr);

int  smbfs_getsd(vnode_t *vp, uint32_t sel, mblk_t **mp, cred_t *cr);
int  smbfs_setsd(vnode_t *vp, uint32_t sel, mblk_t **mp, cred_t *cr);
int  smbfs_ioc_getsd(vnode_t *vp, intptr_t arg, int flag, cred_t *cr);
int  smbfs_ioc_setsd(vnode_t *vp, intptr_t arg, int flag, cred_t *cr);

#ifdef NOT_YET
int  smbfs_smb_getsec(struct smb_share *ssp, uint16_t fid,
	struct smb_cred *scrp, uint32_t selector, struct ntsecdesc **res);
int  smbfs_smb_setsec(struct smb_share *ssp, uint16_t fid,
	struct smb_cred *scrp, uint32_t selector, uint16_t flags,
	struct ntsid *owner, struct ntsid *group, struct ntacl *sacl,
	struct ntacl *dacl);
int  smbfs_smb_qstreaminfo(struct smbnode *np, struct smb_cred *scrp,
	uio_t uio, size_t *sizep);
#endif /* NOT_YET */

void smbfs_fname_tolocal(struct smbfs_fctx *ctx);

void  smb_time_local2server(struct timespec *tsp, int tzoff, long *seconds);
void  smb_time_server2local(ulong_t seconds, int tzoff, struct timespec *tsp);
void  smb_time_NT2local(uint64_t nsec, int tzoff, struct timespec *tsp);
void  smb_time_local2NT(struct timespec *tsp, int tzoff, uint64_t *nsec);
void  smb_time_unix2dos(struct timespec *tsp, int tzoff, uint16_t *ddp,
	uint16_t *dtp, uint8_t *dhp);
void smb_dos2unixtime(uint_t dd, uint_t dt, uint_t dh, int tzoff,
	struct timespec *tsp);

/* Stuff borrowed from NFS (and then hacked) */
vnode_t *smbfs_make_node(vfs_t *vfsp,
    const char *dir, int dirlen,
    const char *name, int nmlen,
    struct smbfattr *fap);
void smb_addfree(smbnode_t *sp);
void smb_addhash(smbnode_t *sp);
void smb_rmhash(smbnode_t *);

int smbfs_subrinit(void);
void smbfs_subrfini(void);
int smbfs_clntinit(void);
void smbfs_clntfini(void);
void smbfs_zonelist_add(smbmntinfo_t *smi);
void smbfs_zonelist_remove(smbmntinfo_t *smi);
void smbfs_destroy_table(struct vfs *vfsp);
int smbfs_readvnode(vnode_t *, uio_t *, cred_t *, struct vattr *);
int smbfs_writevnode(vnode_t *vp, uio_t *uiop, cred_t *cr,
			int ioflag, int timo);
int smbfsgetattr(vnode_t *vp, struct vattr *vap, cred_t *cr);

/* For Solaris, interruptible rwlock */
int smbfs_rw_enter_sig(smbfs_rwlock_t *l, krw_t rw, int intr);
int smbfs_rw_tryenter(smbfs_rwlock_t *l, krw_t rw);
void smbfs_rw_exit(smbfs_rwlock_t *l);
int smbfs_rw_lock_held(smbfs_rwlock_t *l, krw_t rw);
void smbfs_rw_init(smbfs_rwlock_t *l, char *name, krw_type_t type, void *arg);
void smbfs_rw_destroy(smbfs_rwlock_t *l);

#endif /* !_FS_SMBFS_SMBFS_SUBR_H_ */
