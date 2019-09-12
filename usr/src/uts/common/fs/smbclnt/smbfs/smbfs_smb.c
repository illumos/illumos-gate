/*
 * Copyright (c) 2000-2001 Boris Popov
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
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2019 Nexenta by DDN, Inc.  All rights reserved.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/inttypes.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>

#include <netsmb/smb_osdep.h>

#include <netsmb/smb.h>
#include <netsmb/smb2.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_rq.h>

#include <smbfs/smbfs.h>
#include <smbfs/smbfs_node.h>
#include <smbfs/smbfs_subr.h>

/*
 * Jan 1 1980 as 64 bit NT time.
 * (tenths of microseconds since 1601)
 */
const uint64_t NT1980 = 11960035200ULL*10000000ULL;


/*
 * Helper for smbfs_getattr_otw
 * used when we have an open FID
 */
int
smbfs_smb_getfattr(
	struct smbnode *np,
	smb_fh_t *fhp,
	struct smbfattr *fap,
	struct smb_cred *scrp)
{
	struct smb_share *ssp = np->n_mount->smi_share;
	int error;

	if (SSTOVC(ssp)->vc_flags & SMBV_SMB2) {
		error = smbfs_smb2_qfileinfo(ssp, &fhp->fh_fid2, fap, scrp);
	} else {
		error = smbfs_smb1_trans2_query(np, fhp->fh_fid1, fap, scrp);
	}

	return (error);
}

/*
 * Helper for smbfs_getattr_otw
 * used when we don't have an open FID
 *
 * For SMB1 we can just use the path form of trans2 query.
 * For SMB2 we need to do an attribute-only open.
 * See smbfs_smb2_getpattr()
 */
int
smbfs_smb_getpattr(
	struct smbnode *np,
	struct smbfattr *fap,
	struct smb_cred *scrp)
{
	struct smb_share *ssp = np->n_mount->smi_share;
	int error;

	if (SSTOVC(ssp)->vc_flags & SMBV_SMB2) {
		error = smbfs_smb2_getpattr(np, fap, scrp);
	} else {
		uint16_t fid = SMB_FID_UNUSED;
		error = smbfs_smb1_trans2_query(np, fid, fap, scrp);
	}

	return (error);
}

/*
 * Get and parse FileFsAttributeInformation
 */
int
smbfs_smb_qfsattr(struct smb_share *ssp, struct smb_fs_attr_info *fsa,
	struct smb_cred *scrp)
{
	int error;

	if (SSTOVC(ssp)->vc_flags & SMBV_SMB2) {
		error = smbfs_smb2_qfsattr(ssp, fsa, scrp);
	} else {
		error = smbfs_smb1_qfsattr(ssp, fsa, scrp);
	}

	/*
	 * If fs_name starts with FAT, we can't set dates before 1980
	 */
	if (0 == strncmp(fsa->fsa_tname, "FAT", 3)) {
		SMB_SS_LOCK(ssp);
		ssp->ss_flags |= SMBS_FST_FAT;
		SMB_SS_UNLOCK(ssp);
	}

	return (error);
}

int
smbfs_smb_statfs(struct smb_share *ssp, statvfs64_t *sbp,
	struct smb_cred *scp)
{
	struct smb_fs_size_info info;
	struct smb_vc *vcp = SSTOVC(ssp);
	uint32_t bps, spu;
	int error;

	if (vcp->vc_flags & SMBV_SMB2) {
		error = smbfs_smb2_statfs(ssp, &info, scp);
	} else {
		error = smbfs_smb1_statfs(ssp, &info, scp);
	}
	if (error)
		return (error);

	/* A bit of paranoia. */
	bps = info.bytes_per_sect;
	if (bps < DEV_BSIZE)
		bps = DEV_BSIZE;
	spu = info.sect_per_unit;
	if (spu == 0)
		spu = 1;

	/* preferred file system block size */
	sbp->f_bsize = bps * spu;

	/* file system block size ("fragment size") */
	sbp->f_frsize = bps;

	/* total blocks of f_frsize */
	sbp->f_blocks = info.total_units * spu;

	/* free blocks of f_frsize */
	sbp->f_bfree = info.actual_avail * spu;

	/* free blocks avail to non-superuser */
	sbp->f_bavail = info.caller_avail * spu;

	sbp->f_files = (-1);	/* total file nodes in file system */
	sbp->f_ffree = (-1);	/* free file nodes in fs */

	return (error);
}

int
smbfs_smb_setdisp(struct smb_share *ssp, smb_fh_t *fhp,
	uint8_t disp, struct smb_cred *scrp)
{
	int err;

	if (SSTOVC(ssp)->vc_flags & SMBV_SMB2) {
		err = smbfs_smb2_setdisp(ssp, &fhp->fh_fid2, disp, scrp);
	} else {
		err = smbfs_smb1_setdisp(ssp, fhp->fh_fid1, disp, scrp);
	}

	return (err);
}

int
smbfs_smb_setfsize(struct smb_share *ssp, smb_fh_t *fhp,
	uint64_t size, struct smb_cred *scrp)
{
	int error;

	if (SSTOVC(ssp)->vc_flags & SMBV_SMB2) {
		error = smbfs_smb2_seteof(ssp, &fhp->fh_fid2, size, scrp);
	} else {
		error = smbfs_smb1_seteof(ssp, fhp->fh_fid1, size, scrp);
	}

	return (error);
}


/*
 * Set file attributes (optionally: DOS attr, atime, mtime)
 * Always have an open FID with set attr rights.
 */
int
smbfs_smb_setfattr(
	struct smb_share *ssp,
	smb_fh_t *fhp,
	uint32_t attr,
	struct timespec *mtime,
	struct timespec *atime,
	struct smb_cred *scrp)
{
	struct mbchain mb_info;
	struct mbchain *mbp = &mb_info;
	uint64_t tm;
	int error;

	/*
	 * Build a struct FILE_BASIC_INFORMATION in mbp
	 *	LARGE_INTEGER CreationTime;
	 *	LARGE_INTEGER LastAccessTime;
	 *	LARGE_INTEGER LastWriteTime;
	 *	LARGE_INTEGER ChangeTime;
	 *	ULONG FileAttributes;
	 * Zero in times means "no change".
	 */
	mb_init(mbp);
	mb_put_uint64le(mbp, 0);		/* creation time */
	if (atime) {
		smb_time_local2NT(atime, &tm);
		if (tm != 0 && (ssp->ss_flags & SMBS_FST_FAT) &&
		    tm < NT1980)
			tm = NT1980;
	} else
		tm = 0;
	mb_put_uint64le(mbp, tm);		/* last access time */
	if (mtime) {
		smb_time_local2NT(mtime, &tm);
		if (tm != 0 && (ssp->ss_flags & SMBS_FST_FAT) &&
		    tm < NT1980)
			tm = NT1980;
	} else
		tm = 0;
	mb_put_uint64le(mbp, tm);		/* last write time */
	mb_put_uint64le(mbp, 0);		/* change time */
	mb_put_uint32le(mbp, attr);
	mb_put_uint32le(mbp, 0);		/* reserved */

	if (SSTOVC(ssp)->vc_flags & SMBV_SMB2) {
		error = smbfs_smb2_setfattr(ssp, &fhp->fh_fid2, mbp, scrp);
	} else {
		error = smbfs_smb1_setfattr(ssp, fhp->fh_fid1, mbp, scrp);
	}

	return (error);
}

int
smbfs_smb_flush(struct smb_share *ssp, smb_fh_t *fhp,
	struct smb_cred *scrp)
{
	int error;

	if (SSTOVC(ssp)->vc_flags & SMBV_SMB2) {
		error = smbfs_smb2_flush(ssp, &fhp->fh_fid2, scrp);
	} else {
		error = smbfs_smb1_flush(ssp, fhp->fh_fid1, scrp);
	}
	return (error);
}

/*
 * Modern create/open of file or directory.
 * On success, fills in fhp->fh_fid* and fhp->fh_rights
 */
int
smbfs_smb_ntcreatex(
	struct smbnode *np,
	const char *name,
	int nmlen,
	int xattr,		/* is named stream? */
	uint32_t req_acc,	/* requested access */
	uint32_t efa,		/* ext. file attrs (DOS attr +) */
	uint32_t share_acc,
	uint32_t disp,		/* open disposition */
	uint32_t createopt,	/* NTCREATEX_OPTIONS_ */
	struct smb_cred *scrp,
	smb_fh_t *fhp,		/* pre-made file handle to fill in */
	uint32_t *cr_act_p,	/* optional returned create action */
	struct smbfattr *fap)	/* optional returned attributes */
{
	struct mbchain name_mb;
	struct smb_share *ssp = np->n_mount->smi_share;
	int err;

	mb_init(&name_mb);

	if (name == NULL)
		nmlen = 0;
	err = smbfs_fullpath(&name_mb, SSTOVC(ssp),
	    np, name, nmlen, xattr ? ':' : '\\');
	if (err)
		goto out;

	err = smb_smb_ntcreate(ssp, &name_mb,
	    0,	/* NTCREATEX_FLAGS... */
	    req_acc, efa, share_acc, disp, createopt,
	    NTCREATEX_IMPERSONATION_IMPERSONATION,
	    scrp, fhp, cr_act_p, fap);

out:
	mb_done(&name_mb);

	return (err);
}

/*
 * Get a file handle with (at least) the specified rights.
 *
 * We'll try to borrow the node ->n_fid if we can.  When we
 * borrow n_fid, just take a hold on the smb_fh_t, and don't
 * bump n_fidrefs as that tracks VFS-level opens.  Similarly
 * in _tmpclose we just release the smb_fh_t, not n_fidrefs.
 */
int
smbfs_smb_tmpopen(struct smbnode *np, uint32_t rights, struct smb_cred *scrp,
	smb_fh_t **fhpp)
{
	struct smb_share *ssp = np->n_mount->smi_share;
	smb_fh_t *fhp = NULL;
	int error;

	/* Can we re-use n_fid? or must we open anew? */
	mutex_enter(&np->r_statelock);
	if (np->n_fidrefs > 0 &&
	   (fhp = np->n_fid) != NULL &&
	   fhp->fh_vcgenid == ssp->ss_vcgenid &&
	   (fhp->fh_rights & rights) == rights) {
		smb_fh_hold(fhp);
		*fhpp = fhp;
		mutex_exit(&np->r_statelock);
		return (0);
	}
	mutex_exit(&np->r_statelock);

	error = smb_fh_create(ssp, &fhp);
	if (error != 0)
		goto out;

	/* re-open an existing file. */
	error = smbfs_smb_ntcreatex(np,
	    NULL, 0, 0,	/* name nmlen xattr */
	    rights, SMB_EFA_NORMAL,
	    NTCREATEX_SHARE_ACCESS_ALL,
	    NTCREATEX_DISP_OPEN,
	    0, /* create options */
	    scrp, fhp,
	    NULL, NULL); /* cr_act_p fa_p */
	if (error != 0)
		goto out;

	fhp->fh_rights = rights;
	smb_fh_opened(fhp);
	*fhpp = fhp;
	fhp = NULL;

out:
	if (fhp != NULL)
		smb_fh_rele(fhp);

	return (error);
}

/* ARGSUSED */
void
smbfs_smb_tmpclose(struct smbnode *np, smb_fh_t *fhp)
{
	smb_fh_rele(fhp);
}

int
smbfs_smb_open(
	struct smbnode *np,
	const char *name,
	int nmlen,
	int xattr,
	uint32_t rights,
	struct smb_cred *scrp,
	smb_fh_t **fhpp,
	smbfattr_t *fap)
{
	struct smb_share *ssp = np->n_mount->smi_share;
	// struct smb_vc *vcp = SSTOVC(ssp);
	smb_fh_t *fhp = NULL;
	int error;

	error = smb_fh_create(ssp, &fhp);
	if (error != 0)
		goto out;

	/* open an existing file */
	error = smbfs_smb_ntcreatex(np,
	    name, nmlen, xattr,
	    rights, SMB_EFA_NORMAL,
	    NTCREATEX_SHARE_ACCESS_ALL,
	    NTCREATEX_DISP_OPEN,
	    0, /* create options */
	    scrp, fhp, NULL, fap);
	if (error != 0)
		goto out;

	fhp->fh_rights = rights;
	smb_fh_opened(fhp);
	*fhpp = fhp;
	fhp = NULL;

out:
	if (fhp != NULL)
		smb_fh_rele(fhp);

	return (0);
}

void
smbfs_smb_close(smb_fh_t *fhp)
{

	smb_fh_close(fhp);
	smb_fh_rele(fhp);
}

int
smbfs_smb_create(
	struct smbnode *dnp,
	const char *name,
	int nmlen,
	int xattr,
	uint32_t disp,
	struct smb_cred *scrp,
	smb_fh_t **fhpp)
{
	struct smb_share *ssp = dnp->n_mount->smi_share;
	// struct smb_vc *vcp = SSTOVC(ssp);
	smb_fh_t *fhp = NULL;
	uint32_t efa, rights;
	int error;

	error = smb_fh_create(ssp, &fhp);
	if (error != 0)
		goto out;

	/*
	 * At present the only access we might need is to WRITE data,
	 * and that only if we are creating a "symlink".  When/if the
	 * access needed gets more complex it should made a parameter
	 * and be set upstream.
	 */
	rights = SA_RIGHT_FILE_WRITE_DATA;
	efa = SMB_EFA_NORMAL;
	if (!xattr && name && *name == '.')
		efa = SMB_EFA_HIDDEN;
	error = smbfs_smb_ntcreatex(dnp,
	    name, nmlen, xattr, rights, efa,
	    NTCREATEX_SHARE_ACCESS_ALL,
	    disp, /* != NTCREATEX_DISP_OPEN */
	    NTCREATEX_OPTIONS_NON_DIRECTORY_FILE,
	    scrp, fhp, NULL, NULL);
	if (error != 0)
		goto out;

	fhp->fh_rights = rights;
	smb_fh_opened(fhp);
	*fhpp = fhp;
	fhp = NULL;

out:
	if (fhp != NULL)
		smb_fh_rele(fhp);

	return (error);
}

int
smbfs_smb_rename(struct smbnode *sdnp, struct smbnode *np,
    struct smbnode *tdnp, const char *tname, int tnlen,
    smb_fh_t *fhp, struct smb_cred *scrp)
{
	struct smb_share *ssp = np->n_mount->smi_share;
	struct smb_vc *vcp = SSTOVC(ssp);
	int err;

	if (vcp->vc_flags & SMBV_SMB2) {
		err = smbfs_smb2_rename(np, tdnp, tname, tnlen, 0,
		    &fhp->fh_fid2, scrp);
		return (err);
	}

	/*
	 * SMB1 -- Want to use _t2rename if we can
	 * (rename in same dir and cap pass-through)
	 * Most SMB1 servers have cap pass-through.
	 */
	if (sdnp == tdnp &&
	    (vcp->vc_sopt.sv_caps & SMB_CAP_INFOLEVEL_PASSTHRU) != 0) {
		err = smbfs_smb1_t2rename(np, tname, tnlen, fhp->fh_fid1, scrp);
	} else {
		err = smbfs_smb1_oldrename(np, tdnp, tname, tnlen, scrp);
	}

	return (err);
}

int
smbfs_smb_mkdir(struct smbnode *dnp, const char *name, int nmlen,
		struct smb_cred *scrp)
{
	smb_fh_t tmp_fh;
	struct smb_share *ssp = dnp->n_mount->smi_share;
	uint32_t efa, rights;
	int error;

	/*
	 * Using a faked-up handle here to avoid the work of
	 * creating and destroying a real "conn obj".
	 */
	bzero(&tmp_fh, sizeof (tmp_fh));

	/*
	 * We ask for SA_RIGHT_FILE_READ_DATA not because we need it, but
	 * just to be asking for something.  The rights==0 case could
	 * easily be broken on some old or unusual servers.
	 */
	rights = SA_RIGHT_FILE_READ_DATA;
	efa = SMB_EFA_NORMAL;
	if (name && *name == '.')
		efa |= SMB_EFA_HIDDEN;
	error = smbfs_smb_ntcreatex(dnp,
	    name, nmlen, 0, /* xattr */
	    rights, SMB_EFA_DIRECTORY,
	    NTCREATEX_SHARE_ACCESS_ALL,
	    NTCREATEX_DISP_CREATE,
	    NTCREATEX_OPTIONS_DIRECTORY,
	    scrp, &tmp_fh, NULL, NULL);
	if (error == 0) {
		(void) smb_smb_close(ssp, &tmp_fh, scrp);
	}

	return (error);
}

/*
 * Protocol-level directory open
 */
int
smbfs_smb_findopen(struct smbnode *dnp, const char *wild, int wlen,
			int attr, struct smb_cred *scrp,
			struct smbfs_fctx **ctxpp)
{
	struct smb_share *ssp = dnp->n_mount->smi_share;
	struct smb_vc *vcp = SSTOVC(ssp);
	struct smbfs_fctx *ctx;
	int error;

	ctx = kmem_zalloc(sizeof (*ctx), KM_SLEEP);

	ctx->f_flags = SMBFS_RDD_FINDFIRST;
	ctx->f_dnp = dnp;
	ctx->f_scred = scrp;
	ctx->f_ssp = ssp;

	if (dnp->n_flag & N_XATTR) {
		error = smbfs_xa_findopen(ctx, dnp, wild, wlen);
		goto out;
	}

	if (vcp->vc_flags & SMBV_SMB2) {
		error = smbfs_smb2_findopen(ctx, dnp, wild, wlen, attr);
	} else {
		error = smbfs_smb_findopenLM2(ctx, dnp, wild, wlen, attr);
	}

out:
	ctx->f_scred = NULL;
	if (error) {
		kmem_free(ctx, sizeof (*ctx));
	} else {
		*ctxpp = ctx;
	}

	return (error);
}

int
smbfs_smb_findnext(struct smbfs_fctx *ctx, int limit, struct smb_cred *scrp)
{
	int error = 0;
	uint16_t lim;

	/*
	 * Note: "limit" (maxcount) needs to fit in a short!
	 */
	if (limit > 0xffff)
		limit = 0xffff;
	lim = (uint16_t)limit;

	ctx->f_scred = scrp;
	for (;;) {
		bzero(&ctx->f_attr, sizeof (ctx->f_attr));
		switch (ctx->f_type) {

		case ft_SMB2:
			error = smbfs_smb2_findnext(ctx, lim);
			break;
		case ft_LM2:
			error = smbfs_smb_findnextLM2(ctx, lim);
			break;
		case ft_XA:
			error = smbfs_xa_findnext(ctx, lim);
			break;
		default:
			ASSERT(0);
			error = EINVAL;
			break;
		}
		if (error)
			break;
		/*
		 * Skip "." or ".." - easy now that ctx->f_name
		 * has already been converted to utf-8 format.
		 */
		if ((ctx->f_nmlen == 1 && ctx->f_name[0] == '.') ||
		    (ctx->f_nmlen == 2 && ctx->f_name[0] == '.' &&
		    ctx->f_name[1] == '.'))
			continue;
		break;
	}
	ctx->f_scred = NULL;
	if (error != 0)
		return (error);

	ctx->f_inum = smbfs_getino(ctx->f_dnp,
	    ctx->f_name, ctx->f_nmlen);

#ifdef	DEBUG
	SMBVDEBUG("findnext: (%s)\n", ctx->f_name);
#endif

	return (error);
}


int
smbfs_smb_findclose(struct smbfs_fctx *ctx, struct smb_cred *scrp)
{
	int error;

	ctx->f_scred = scrp;
	switch (ctx->f_type) {
	case ft_SMB2:
		error = smbfs_smb2_findclose(ctx);
		break;
	case ft_LM2:
		error = smbfs_smb_findcloseLM2(ctx);
		break;
	case ft_XA:
		error = smbfs_xa_findclose(ctx);
		break;
	default:
		error = ENOSYS;
		break;
	}
	ctx->f_scred = NULL;
	if (ctx->f_rname)
		kmem_free(ctx->f_rname, ctx->f_rnamelen);
	if (ctx->f_firstnm)
		kmem_free(ctx->f_firstnm, ctx->f_firstnmlen);
	kmem_free(ctx, sizeof (*ctx));
	return (error);
}


int
smbfs_smb_lookup(struct smbnode *dnp, const char **namep, int *nmlenp,
	struct smbfattr *fap, struct smb_cred *scrp)
{
	struct smbfs_fctx *ctx;
	int error, intr;
	const char *name = (namep ? *namep : NULL);
	int nmlen = (nmlenp ? *nmlenp : 0);

	/* This is no longer called with a null dnp */
	ASSERT(dnp);

	/*
	 * Should not get here with "" anymore.
	 */
	if (!name || !nmlen) {
		DEBUG_ENTER("smbfs_smb_lookup: name is NULL");
		return (EINVAL);
	}

	/*
	 * Should not get here with "." or ".." anymore.
	 */
	if ((nmlen == 1 && name[0] == '.') ||
	    (nmlen == 2 && name[0] == '.' && name[1] == '.')) {
		DEBUG_ENTER("smbfs_smb_lookup: name is '.' or '..'");
		return (EINVAL);
	}

	/*
	 * Shared lock for n_fid use (smb_flush).
	 */
	intr = dnp->n_mount->smi_flags & SMI_INT;
	if (smbfs_rw_enter_sig(&dnp->r_lkserlock, RW_READER, intr))
		return (EINTR);

	error = smbfs_smb_findopen(dnp, name, nmlen,
	    SMB_FA_SYSTEM | SMB_FA_HIDDEN | SMB_FA_DIR, scrp, &ctx);
	if (error)
		goto out;
	ctx->f_flags |= SMBFS_RDD_FINDSINGLE;
	error = smbfs_smb_findnext(ctx, 1, scrp);
	if (error == 0) {
		*fap = ctx->f_attr;
		/*
		 * Solaris smbfattr doesn't have fa_ino,
		 * and we don't allow name==NULL in this
		 * function anymore.
		 */
		if (namep)
			*namep = (const char *)smbfs_name_alloc(
			    ctx->f_name, ctx->f_nmlen);
		if (nmlenp)
			*nmlenp = ctx->f_nmlen;
	}
	(void) smbfs_smb_findclose(ctx, scrp);

out:
	smbfs_rw_exit(&dnp->r_lkserlock);
	return (error);
}

/*
 * OTW function to Get a security descriptor (SD).
 *
 * Note: On success, this fills in mdp->md_top,
 * which the caller should free.
 */
int
smbfs_smb_getsec(struct smb_share *ssp, smb_fh_t *fhp,
	uint32_t selector, mblk_t **res, uint32_t *reslen,
	struct smb_cred *scrp)
{
	struct smb_vc *vcp = SSTOVC(ssp);
	int error, len;

	*res = NULL;

	if (vcp->vc_flags & SMBV_SMB2) {
		error = smbfs_smb2_getsec(ssp, &fhp->fh_fid2,
		    selector, res, reslen, scrp);
	} else {
		error = smbfs_smb1_getsec(ssp, fhp->fh_fid1,
		    selector, res, reslen, scrp);
	}

	/*
	 * get the data part.
	 */
	if (*res == NULL) {
		error = EBADRPC;
		goto done;
	}

	/*
	 * If message length is < returned SD_length,
	 * correct *reslen (reduce it).  It greater,
	 * just ignore the extra data.
	 */
	len = m_fixhdr(*res);
	if (len < *reslen)
		*reslen = len;

done:
	if (error == 0 && *res == NULL) {
		ASSERT(*res);
		error = EBADRPC;
	}

	return (error);
}

/*
 * OTW function to Set a security descriptor (SD).
 * Caller data are carried in an mbchain_t.
 *
 * Note: This normally consumes mbp->mb_top, and clears
 * that pointer when it does.
 */
int
smbfs_smb_setsec(struct smb_share *ssp, smb_fh_t *fhp,
	uint32_t selector, mblk_t **mp,
	struct smb_cred *scrp)
{
	struct smb_vc *vcp = SSTOVC(ssp);
	int error;

	if (vcp->vc_flags & SMBV_SMB2) {
		error = smbfs_smb2_setsec(ssp, &fhp->fh_fid2,
		    selector, mp, scrp);
	} else {
		error = smbfs_smb1_setsec(ssp, fhp->fh_fid1,
		    selector, mp, scrp);
	}

	return (error);
}
