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
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
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
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_rq.h>

#include <smbfs/smbfs.h>
#include <smbfs/smbfs_node.h>
#include <smbfs/smbfs_subr.h>


/*
 * Todo: locking over-the-wire
 */
#if 0	// todo

int
smbfs_smb1_lockandx(struct smbnode *np, int op, uint32_t pid,
	offset_t start, uint64_t len, int largelock,
	struct smb_cred *scrp, uint32_t timeout)
{
	struct smb_share *ssp = np->n_mount->smi_share;
	struct smb_rq rq, *rqp = &rq;
	struct mbchain *mbp;
	uint8_t ltype = 0;
	int error;

	/* Shared lock for n_fid use below. */
	ASSERT(smbfs_rw_lock_held(&np->r_lkserlock, RW_READER));

	/* After reconnect, n_fid is invalid */
	if (np->n_vcgenid != ssp->ss_vcgenid)
		return (ESTALE);

	if (op == SMB_LOCK_SHARED)
		ltype |= SMB_LOCKING_ANDX_SHARED_LOCK;
	/* XXX: if (SSTOVC(ssp)->vc_sopt.sv_caps & SMB_CAP_LARGE_FILES)? */
	if (largelock)
		ltype |= SMB_LOCKING_ANDX_LARGE_FILES;
	error = smb_rq_init(rqp, SSTOCP(ssp), SMB_COM_LOCKING_ANDX, scrp);
	if (error)
		return (error);
	smb_rq_getrequest(rqp, &mbp);
	smb_rq_wstart(rqp);
	mb_put_uint8(mbp, 0xff);	/* secondary command */
	mb_put_uint8(mbp, 0);		/* MBZ */
	mb_put_uint16le(mbp, 0);
	mb_put_uint16le(mbp, np->n_fid);
	mb_put_uint8(mbp, ltype);	/* locktype */
	mb_put_uint8(mbp, 0);		/* oplocklevel - 0 seems is NO_OPLOCK */
	mb_put_uint32le(mbp, timeout);	/* 0 nowait, -1 infinite wait */
	mb_put_uint16le(mbp, op == SMB_LOCK_RELEASE ? 1 : 0);
	mb_put_uint16le(mbp, op == SMB_LOCK_RELEASE ? 0 : 1);
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	mb_put_uint16le(mbp, pid);
	if (!largelock) {
		mb_put_uint32le(mbp, start);
		mb_put_uint32le(mbp, len);
	} else {
		mb_put_uint16le(mbp, 0); /* pad */
		mb_put_uint32le(mbp, start >> 32); /* OffsetHigh */
		mb_put_uint32le(mbp, start & 0xffffffff); /* OffsetLow */
		mb_put_uint32le(mbp, len >> 32); /* LengthHigh */
		mb_put_uint32le(mbp, len & 0xffffffff); /* LengthLow */
	}
	smb_rq_bend(rqp);
	/*
	 * Don't want to risk missing a successful
	 * unlock send or lock response, or we could
	 * lose track of an outstanding lock.
	 */
	if (op == SMB_LOCK_RELEASE)
		rqp->sr_flags |= SMBR_NOINTR_SEND;
	else
		rqp->sr_flags |= SMBR_NOINTR_RECV;

	error = smb_rq_simple(rqp);
	smb_rq_done(rqp);
	return (error);
}

#endif	// todo

/*
 * Common function for QueryFileInfo, QueryPathInfo.
 */
int
smbfs_smb1_trans2_query(struct smbnode *np,  uint16_t fid,
	struct smbfattr *fap, struct smb_cred *scrp)
{
	struct smb_share *ssp = np->n_mount->smi_share;
	struct smb_vc *vcp = SSTOVC(ssp);
	struct smb_t2rq *t2p;
	struct mbchain *mbp;
	struct mdchain *mdp;
	uint16_t cmd;
	uint16_t infolevel = SMB_QFILEINFO_ALL_INFO;
	int error;

	/*
	 * If we have a valid open FID, use it.
	 */
	if (fid != SMB_FID_UNUSED)
		cmd = SMB_TRANS2_QUERY_FILE_INFORMATION;
	else
		cmd = SMB_TRANS2_QUERY_PATH_INFORMATION;

	error = smb_t2_alloc(SSTOCP(ssp), cmd, scrp, &t2p);
	if (error)
		return (error);
	mbp = &t2p->t2_tparam;
	mb_init(mbp);

	if (cmd == SMB_TRANS2_QUERY_FILE_INFORMATION)
		mb_put_uint16le(mbp, fid);

	mb_put_uint16le(mbp, infolevel);

	if (cmd == SMB_TRANS2_QUERY_PATH_INFORMATION) {
		mb_put_uint32le(mbp, 0);
		/* mb_put_uint8(mbp, SMB_DT_ASCII); specs are wrong */
		error = smbfs_fullpath(mbp, vcp, np, NULL, 0, '\\');
		if (error)
			goto out;
	}

	t2p->t2_maxpcount = 2;
	t2p->t2_maxdcount = vcp->vc_txmax;
	error = smb_t2_request(t2p);
	if (error)
		goto out;

	/*
	 * Parse the SMB_QFILEINFO_ALL_INFO
	 */
	mdp = &t2p->t2_rdata;
	error = smbfs_decode_file_all_info(ssp, mdp, fap);

out:
	smb_t2_done(t2p);

	return (error);
}

/*
 * Get some FS information
 */
static int
smbfs_smb1_query_fs_info(struct smb_share *ssp, struct mdchain *info_mdp,
	uint16_t level, struct smb_cred *scrp)
{
	struct smb_t2rq *t2p;
	struct mbchain *mbp;
	struct mdchain *mdp;
	int error;

	error = smb_t2_alloc(SSTOCP(ssp), SMB_TRANS2_QUERY_FS_INFORMATION,
	    scrp, &t2p);
	if (error)
		return (error);
	mbp = &t2p->t2_tparam;
	mb_init(mbp);
	mb_put_uint16le(mbp, level);
	t2p->t2_maxpcount = 4;
	t2p->t2_maxdcount = 1024;
	error = smb_t2_request(t2p);
	if (error)
		goto out;

	mdp = &t2p->t2_rdata;
	*info_mdp = *mdp;
	bzero(mdp, sizeof (*mdp));

out:
	smb_t2_done(t2p);
	return (error);
}

/*
 * Get FILE_FS_ATTRIBUTE_INFORMATION
 */
int
smbfs_smb1_qfsattr(struct smb_share *ssp, struct smb_fs_attr_info *fsa,
	struct smb_cred *scrp)
{
	struct mdchain info_mdc, *mdp = &info_mdc;
	int error;

	bzero(mdp, sizeof (*mdp));

	error = smbfs_smb1_query_fs_info(ssp, mdp,
	    SMB_QFS_ATTRIBUTE_INFO, scrp);
	if (error)
		goto out;
	error = smbfs_decode_fs_attr_info(ssp, mdp, fsa);

out:
	md_done(mdp);

	return (error);
}

/*
 * Get FileFsFullSizeInformation and
 * parse into *info
 */
int
smbfs_smb1_statfs(struct smb_share *ssp,
	struct smb_fs_size_info *info,
	struct smb_cred *scrp)
{
	struct mdchain info_mdc, *mdp = &info_mdc;
	struct smb_vc *vcp = SSTOVC(ssp);
	uint16_t level;
	int error;

	bzero(mdp, sizeof (*mdp));

	if (vcp->vc_sopt.sv_caps & SMB_CAP_INFOLEVEL_PASSTHRU)
		level = SMB_QFS_FULL_SIZE_INFORMATION;
	else
		level = SMB_QFS_SIZE_INFO;
	error = smbfs_smb1_query_fs_info(ssp, mdp, level, scrp);
	if (error)
		goto out;

	md_get_uint64le(mdp, &info->total_units);
	md_get_uint64le(mdp, &info->caller_avail);
	if (level == SMB_QFS_FULL_SIZE_INFORMATION)
		md_get_uint64le(mdp, &info->actual_avail);
	else
		info->actual_avail = info->caller_avail;

	md_get_uint32le(mdp, &info->sect_per_unit);
	error = md_get_uint32le(mdp, &info->bytes_per_sect);

out:
	md_done(mdp);

	return (error);
}

int
smbfs_smb1_flush(struct smb_share *ssp, uint16_t fid, struct smb_cred *scrp)
{
	struct smb_rq rq, *rqp = &rq;
	struct mbchain *mbp;
	int error;

	error = smb_rq_init(rqp, SSTOCP(ssp), SMB_COM_FLUSH, scrp);
	if (error)
		return (error);
	smb_rq_getrequest(rqp, &mbp);
	smb_rq_wstart(rqp);
	mb_put_uint16le(mbp, fid);
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	smb_rq_bend(rqp);
	error = smb_rq_simple(rqp);
	smb_rq_done(rqp);
	return (error);
}

/*
 * Set file info via an open handle.
 * Caller provides payload, info level.
 */
static int
smbfs_smb1_setinfo_file(struct smb_share *ssp, uint16_t fid,
	struct mbchain *info_mbp, uint16_t level, struct smb_cred *scrp)
{
	struct smb_t2rq *t2p = NULL;
	struct mbchain *mbp;
	uint16_t cmd = SMB_TRANS2_SET_FILE_INFORMATION;
	int error;

	ASSERT(fid != SMB_FID_UNUSED);

	error = smb_t2_alloc(SSTOCP(ssp), cmd, scrp, &t2p);
	if (error)
		return (error);
	mbp = &t2p->t2_tparam;
	mb_init(mbp);
	mb_put_uint16le(mbp, fid);
	mb_put_uint16le(mbp, level);
	mb_put_uint16le(mbp, 0); /* pad */

	/* put the payload */
	mbp = &t2p->t2_tdata;
	mb_init(mbp);
	error = mb_put_mbchain(mbp, info_mbp);
	if (error)
		goto out;

	t2p->t2_maxpcount = 2;
	t2p->t2_maxdcount = 0;
	error = smb_t2_request(t2p);

out:
	smb_t2_done(t2p);

	return (error);
}

int
smbfs_smb1_seteof(struct smb_share *ssp, uint16_t fid,
	uint64_t newsize, struct smb_cred *scrp)
{
	struct mbchain data_mb, *mbp = &data_mb;
	uint16_t level;
	int error;

	if (SSTOVC(ssp)->vc_sopt.sv_caps & SMB_CAP_INFOLEVEL_PASSTHRU)
		level = SMB_SFILEINFO_END_OF_FILE_INFORMATION;
	else
		level = SMB_SFILEINFO_END_OF_FILE_INFO;

	mb_init(mbp);
	error = mb_put_uint64le(mbp, newsize);
	if (error)
		goto out;
	error = smbfs_smb1_setinfo_file(ssp, fid, mbp, level, scrp);

out:
	mb_done(mbp);
	return (error);
}

int
smbfs_smb1_setdisp(struct smb_share *ssp, uint16_t fid,
	uint8_t newdisp, struct smb_cred *scrp)
{
	struct mbchain data_mb, *mbp = &data_mb;
	uint16_t level;
	int error;

	if (SSTOVC(ssp)->vc_sopt.sv_caps & SMB_CAP_INFOLEVEL_PASSTHRU)
		level = SMB_SFILEINFO_DISPOSITION_INFORMATION;
	else
		level = SMB_SFILEINFO_DISPOSITION_INFO;

	mb_init(mbp);
	error = mb_put_uint8(mbp, newdisp);
	if (error)
		goto out;
	error = smbfs_smb1_setinfo_file(ssp, fid, mbp, level, scrp);

out:
	mb_done(mbp);

	return (error);
}

/*
 * Set FileBasicInformation on an open handle
 * Caller builds the mbchain.
 * Always have a FID here.
 */
int
smbfs_smb1_setfattr(struct smb_share *ssp, uint16_t fid,
	struct mbchain *mbp, struct smb_cred *scrp)
{
	uint16_t level;
	int error;

	if (SSTOVC(ssp)->vc_sopt.sv_caps & SMB_CAP_INFOLEVEL_PASSTHRU)
		level = SMB_SFILEINFO_BASIC_INFORMATION;
	else
		level = SMB_SFILEINFO_BASIC_INFO;
	error = smbfs_smb1_setinfo_file(ssp, fid, mbp, level, scrp);

	return (error);
}

/*
 * On SMB1, the trans2 rename only allows a rename where the
 * source and target are in the same directory.  If you give
 * the server any separators, you get "status not supported".
 *
 * Why bother using this instead of smbfs_smb1_oldrename?
 * Because it works with an open file, and some servers don't
 * allow oldrename of a file that's currently open.  We call
 * this when deleting an open file in smbfsremove(), where
 * the rename is always in the same directory.
 */
/*ARGSUSED*/
int
smbfs_smb1_t2rename(struct smbnode *np,
	const char *tname, int tnlen,
	uint16_t fid, struct smb_cred *scrp)
{
	struct smb_share *ssp = np->n_mount->smi_share;
	struct mbchain data_mb, *mbp = &data_mb;
	struct smb_vc *vcp = SSTOVC(ssp);
	uint32_t *name_lenp;
	uint16_t level = SMB_SFILEINFO_RENAME_INFORMATION;
	int base, len;
	int error;

	mb_init(mbp);
	mb_put_uint32le(mbp, 0); /* don't overwrite */
	mb_put_uint32le(mbp, 0); /* obsolete target dir fid */
	name_lenp = mb_reserve(mbp, 4);	/* name len */

	/* New name */
	base = mbp->mb_count;
	error = smb_put_dmem(mbp, vcp, tname, tnlen, SMB_CS_NONE, NULL);
	if (error)
		goto out;
	len = mbp->mb_count - base;
	*name_lenp = htolel(len);

	error = smbfs_smb1_setinfo_file(ssp, fid, mbp, level, scrp);

out:
	mb_done(mbp);
	return (error);
}

/*
 * Do an SMB1 (old style) rename using a full dest. path.
 * This is used when renaming to a different directory,
 * because the (preferred) t2rename can't do that.
 */
int
smbfs_smb1_oldrename(struct smbnode *src, struct smbnode *tdnp,
    const char *tname, int tnmlen, struct smb_cred *scrp)
{
	struct smb_rq rq, *rqp = &rq;
	struct smb_share *ssp = src->n_mount->smi_share;
	struct mbchain *mbp;
	int error;
	uint16_t fa;
	char sep;

	error = smb_rq_init(rqp, SSTOCP(ssp), SMB_COM_RENAME, scrp);
	if (error)
		return (error);
	smb_rq_getrequest(rqp, &mbp);
	smb_rq_wstart(rqp);
	/* freebsd bug: Let directories be renamed - Win98 requires DIR bit */
	fa = (SMBTOV(src)->v_type == VDIR) ? SMB_FA_DIR : 0;
	fa |= SMB_FA_SYSTEM | SMB_FA_HIDDEN;
	mb_put_uint16le(mbp, fa);
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);

	/*
	 * When we're not adding any component name, the
	 * passed sep is ignored, so just pass sep=0.
	 */
	mb_put_uint8(mbp, SMB_DT_ASCII);
	error = smbfs_fullpath(mbp, SSTOVC(ssp), src, NULL, 0, 0);
	if (error)
		goto out;

	/*
	 * After XATTR directories, separator is ":"
	 */
	sep = (src->n_flag & N_XATTR) ? ':' : '\\';
	mb_put_uint8(mbp, SMB_DT_ASCII);
	error = smbfs_fullpath(mbp, SSTOVC(ssp), tdnp, tname, tnmlen, sep);
	if (error)
		goto out;

	smb_rq_bend(rqp);
	error = smb_rq_simple(rqp);
out:
	smb_rq_done(rqp);
	return (error);
}


/*
 * TRANS2_FIND_FIRST2/NEXT2, used for NT LM12 dialect
 */
static int
smbfs_smb1_trans2find2(struct smbfs_fctx *ctx)
{
	struct smb_t2rq *t2p;
	struct smb_vc *vcp = SSTOVC(ctx->f_ssp);
	struct mbchain *mbp;
	struct mdchain *mdp;
	uint16_t ecnt, eos, lno, flags;
	uint16_t amask, limit;
	int error;

	/* smbfs_smb_findnextLM2 sets this */
	limit = ctx->f_limit;
	amask = (uint16_t)ctx->f_attrmask;

	if (ctx->f_t2) {
		smb_t2_done(ctx->f_t2);
		ctx->f_t2 = NULL;
	}
	flags = FIND2_RETURN_RESUME_KEYS | FIND2_CLOSE_ON_EOS;
	if (ctx->f_flags & SMBFS_RDD_FINDSINGLE) {
		flags |= FIND2_CLOSE_AFTER_REQUEST;
		ctx->f_flags |= SMBFS_RDD_NOCLOSE;
	}
	if (ctx->f_flags & SMBFS_RDD_FINDFIRST) {
		error = smb_t2_alloc(SSTOCP(ctx->f_ssp), SMB_TRANS2_FIND_FIRST2,
		    ctx->f_scred, &t2p);
		if (error)
			return (error);
		ctx->f_t2 = t2p;
		mbp = &t2p->t2_tparam;
		mb_init(mbp);
		mb_put_uint16le(mbp, amask);
		mb_put_uint16le(mbp, limit);
		mb_put_uint16le(mbp, flags);
		mb_put_uint16le(mbp, ctx->f_infolevel);
		mb_put_uint32le(mbp, 0);
		error = smbfs_fullpath(mbp, vcp, ctx->f_dnp,
		    ctx->f_wildcard, ctx->f_wclen, '\\');
		if (error)
			return (error);
	} else	{
		error = smb_t2_alloc(SSTOCP(ctx->f_ssp), SMB_TRANS2_FIND_NEXT2,
		    ctx->f_scred, &t2p);
		if (error)
			return (error);
		ctx->f_t2 = t2p;
		mbp = &t2p->t2_tparam;
		mb_init(mbp);
		mb_put_uint16le(mbp, ctx->f_Sid);
		mb_put_uint16le(mbp, limit);
		mb_put_uint16le(mbp, ctx->f_infolevel);
		/* Send whatever resume key we received... */
		mb_put_uint32le(mbp, ctx->f_rkey);
		mb_put_uint16le(mbp, flags);
		/* ... and the resume name if we have one. */
		if (ctx->f_rname) {
			/* resume file name */
			mb_put_mem(mbp, ctx->f_rname, ctx->f_rnamelen,
			    MB_MSYSTEM);
		}
		/* Add trailing null - 1 byte if ASCII, 2 if Unicode */
		if (SMB_UNICODE_STRINGS(SSTOVC(ctx->f_ssp)))
			mb_put_uint8(mbp, 0);	/* 1st byte NULL Unicode char */
		mb_put_uint8(mbp, 0);
	}
	t2p->t2_maxpcount = 5 * 2;
	t2p->t2_maxdcount = 0xF000;	/* 64K less some overhead */
	error = smb_t2_request(t2p);
	if (error)
		return (error);

	/*
	 * This is the "resume name" we just sent.
	 * We want the new one (if any) that may be
	 * found in the response we just received and
	 * will now begin parsing.  Free the old one
	 * now so we'll know if we found a new one.
	 */
	if (ctx->f_rname) {
		kmem_free(ctx->f_rname, ctx->f_rnamelen);
		ctx->f_rname = NULL;
		ctx->f_rnamelen = 0;
	}

	mdp = &t2p->t2_rparam;
	if (ctx->f_flags & SMBFS_RDD_FINDFIRST) {
		if ((error = md_get_uint16le(mdp, &ctx->f_Sid)) != 0)
			goto nodata;
		ctx->f_flags &= ~SMBFS_RDD_FINDFIRST;
	}
	md_get_uint16le(mdp, &ecnt);		/* entry count */
	md_get_uint16le(mdp, &eos);		/* end of search */
	md_get_uint16le(mdp, NULL);		/* EA err. off. */
	error = md_get_uint16le(mdp, &lno);	/* last name off. */
	if (error != 0)
		goto nodata;

	/*
	 * The "end of search" flag from an XP server sometimes
	 * comes back zero when the prior find_next returned exactly
	 * the number of entries requested.  in which case we'd try again
	 * but the search has in fact been closed so an EBADF results.
	 * our circumvention is to check here for a zero entry count.
	 */
	ctx->f_ecnt = ecnt;
	if (eos || ctx->f_ecnt == 0)
		ctx->f_flags |= SMBFS_RDD_EOF | SMBFS_RDD_NOCLOSE;
	if (ctx->f_ecnt == 0)
		return (ENOENT);

	/* Last Name Off (LNO) is the entry with the resume name. */
	ctx->f_rnameofs = lno;
	ctx->f_eofs = 0;

	/*
	 * Have data. Put the payload in ctx->f_mdchain
	 * Note struct assignments here.
	 */
	mdp = &t2p->t2_rdata;
	md_done(&ctx->f_mdchain);
	ctx->f_mdchain = *mdp;
	ctx->f_left = m_fixhdr(mdp->md_top);
	bzero(mdp, sizeof (*mdp));

	return (0);

nodata:
	/*
	 * Failed parsing the FindFirst or FindNext response.
	 * Force this directory listing closed, otherwise the
	 * calling process may hang in an infinite loop.
	 */
	ctx->f_ecnt = 0; /* Force closed. */
	ctx->f_flags |= SMBFS_RDD_EOF;
	return (EIO);
}

static int
smbfs_smb1_findclose2(struct smbfs_fctx *ctx)
{
	struct smb_rq rq, *rqp = &rq;
	struct mbchain *mbp;
	int error;

	error = smb_rq_init(rqp, SSTOCP(ctx->f_ssp), SMB_COM_FIND_CLOSE2,
	    ctx->f_scred);
	if (error)
		return (error);
	smb_rq_getrequest(rqp, &mbp);
	smb_rq_wstart(rqp);
	mb_put_uint16le(mbp, ctx->f_Sid);
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	smb_rq_bend(rqp);
	/* Ditto comments at _smb_close */
	rqp->sr_flags |= SMBR_NOINTR_SEND;
	error = smb_rq_simple(rqp);
	smb_rq_done(rqp);
	return (error);
}

/*ARGSUSED*/
int
smbfs_smb_findopenLM2(struct smbfs_fctx *ctx, struct smbnode *dnp,
    const char *wildcard, int wclen, uint32_t attr)
{

	ctx->f_type = ft_LM2;
	ctx->f_namesz = SMB_MAXFNAMELEN + 1;
	ctx->f_name = kmem_alloc(ctx->f_namesz, KM_SLEEP);
	ctx->f_infolevel = SMB_FIND_FULL_DIRECTORY_INFO;
	ctx->f_attrmask = attr;
	ctx->f_wildcard = wildcard;
	ctx->f_wclen = wclen;
	return (0);
}

int
smbfs_smb_findcloseLM2(struct smbfs_fctx *ctx)
{
	int error = 0;
	if (ctx->f_name)
		kmem_free(ctx->f_name, ctx->f_namesz);
	if (ctx->f_t2)
		smb_t2_done(ctx->f_t2);
	md_done(&ctx->f_mdchain);

	/*
	 * If SMBFS_RDD_FINDFIRST is still set, we were opened
	 * but never saw a findfirst, so we don't have any
	 * search handle to close.
	 */
	if ((ctx->f_flags & (SMBFS_RDD_FINDFIRST | SMBFS_RDD_NOCLOSE)) == 0)
		error = smbfs_smb1_findclose2(ctx);
	return (error);
}

/*
 * Get a buffer of directory entries (if we don't already have
 * some remaining in the current buffer) then decode one.
 */
int
smbfs_smb_findnextLM2(struct smbfs_fctx *ctx, uint16_t limit)
{
	int error;

	/*
	 * If we've scanned to the end of the current buffer
	 * try to read anohther buffer of dir entries.
	 * Treat anything less than 8 bytes as an "empty"
	 * buffer to ensure we can read something.
	 * (There may be up to 8 bytes of padding.)
	 */
	if ((ctx->f_eofs + 8) > ctx->f_left) {
		/* Scanned the whole buffer. */
		if (ctx->f_flags & SMBFS_RDD_EOF)
			return (ENOENT);
		ctx->f_limit = limit;
		error = smbfs_smb1_trans2find2(ctx);
		if (error)
			return (error);
		ctx->f_otws++;
	}

	/*
	 * Decode one entry, advance f_eofs
	 */
	error = smbfs_decode_dirent(ctx);

	return (error);
}

/*
 * Helper for smbfs_xa_get_streaminfo
 * Query stream info
 */
int
smbfs_smb1_get_streaminfo(smbnode_t *np, struct mdchain *mdp,
	struct smb_cred *scrp)
{
	smb_share_t *ssp = np->n_mount->smi_share;
	struct smb_vc *vcp = SSTOVC(ssp);
	struct smb_t2rq *t2p = NULL;
	struct mbchain *mbp;
	mblk_t *m;
	uint16_t cmd = SMB_TRANS2_QUERY_PATH_INFORMATION;
	int error;

	error = smb_t2_alloc(SSTOCP(ssp), cmd, scrp, &t2p);
	if (error)
		return (error);

	mbp = &t2p->t2_tparam;
	(void) mb_init(mbp);
	(void) mb_put_uint16le(mbp, SMB_QFILEINFO_STREAM_INFO);
	(void) mb_put_uint32le(mbp, 0);
	error = smbfs_fullpath(mbp, vcp, np, NULL, NULL, 0);
	if (error)
		goto out;

	t2p->t2_maxpcount = 2;
	t2p->t2_maxdcount = INT16_MAX;
	error = smb_t2_request(t2p);
	if (error) {
		if (t2p->t2_sr_error == NT_STATUS_INVALID_PARAMETER)
			error = ENOTSUP;
		goto out;
	}

	/*
	 * Have data.  Move it to *mdp
	 */
	m = t2p->t2_rdata.md_top;
	if (m == NULL) {
		error = EBADRPC;
		goto out;
	}
	t2p->t2_rdata.md_top = NULL;
	md_initm(mdp, m);

out:
	smb_t2_done(t2p);
	return (error);
}

/*
 * OTW function to Get a security descriptor (SD).
 *
 * The *reslen param is bufsize(in) / length(out)
 * Note: On success, this fills in mdp->md_top,
 * which the caller should free.
 */
int
smbfs_smb1_getsec(struct smb_share *ssp, uint16_t fid,
	uint32_t selector, mblk_t **res, uint32_t *reslen,
	struct smb_cred *scrp)
{
	struct smb_ntrq *ntp;
	struct mbchain *mbp;
	struct mdchain *mdp;
	uint32_t dlen;
	int error;

	*res = NULL;

	error = smb_nt_alloc(SSTOCP(ssp), NT_TRANSACT_QUERY_SECURITY_DESC,
	    scrp, &ntp);
	if (error)
		return (error);

	/* Parameters part */
	mbp = &ntp->nt_tparam;
	mb_init(mbp);
	mb_put_uint16le(mbp, fid);
	mb_put_uint16le(mbp, 0); /* reserved */
	mb_put_uint32le(mbp, selector);
	/* Data part (none) */

	/* Max. returned parameters and data. */
	ntp->nt_maxpcount = 4;
	ntp->nt_maxdcount = *reslen;	// out buf size

	error = smb_nt_request(ntp);
	if (error && !(ntp->nt_flags & SMBT2_MOREDATA))
		goto done;

	/* Get data len */
	mdp = &ntp->nt_rparam;
	error = md_get_uint32le(mdp, &dlen);
	if (error)
		goto done;

	/*
	 * if there's more data than we said we could receive,
	 * here is where we pick up the length of it
	 */
	*reslen = dlen;
	if (dlen == 0) {
		error = EBADRPC;
		goto done;
	}

	/*
	 * get the SD data part.
	 */
	mdp = &ntp->nt_rdata;
	error = md_get_mbuf(mdp, dlen, res);

done:
	if (error == 0 && *res == NULL) {
		ASSERT(*res);
		error = EBADRPC;
	}

	smb_nt_done(ntp);
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
smbfs_smb1_setsec(struct smb_share *ssp, uint16_t fid,
	uint32_t selector, mblk_t **mp, struct smb_cred *scrp)
{
	struct smb_ntrq *ntp;
	struct mbchain *mbp;
	int error;

	error = smb_nt_alloc(SSTOCP(ssp), NT_TRANSACT_SET_SECURITY_DESC,
	    scrp, &ntp);
	if (error)
		return (error);

	/* Parameters part */
	mbp = &ntp->nt_tparam;
	mb_init(mbp);
	mb_put_uint16le(mbp, fid);
	mb_put_uint16le(mbp, 0); /* reserved */
	mb_put_uint32le(mbp, selector);

	/* Data part */
	mbp = &ntp->nt_tdata;
	mb_initm(mbp, *mp);
	*mp = NULL; /* consumed */

	/* No returned parameters or data. */
	ntp->nt_maxpcount = 0;
	ntp->nt_maxdcount = 0;

	error = smb_nt_request(ntp);
	smb_nt_done(ntp);

	return (error);
}
