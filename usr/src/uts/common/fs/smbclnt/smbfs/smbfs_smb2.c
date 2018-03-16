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
 * Copyright (c) 2011 - 2013 Apple Inc. All rights reserved.
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
#include <netsmb/smb2.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_rq.h>
#include <netsmb/smb2_rq.h>

#include <smbfs/smbfs.h>
#include <smbfs/smbfs_node.h>
#include <smbfs/smbfs_subr.h>


/*
 * Todo: locking over-the-wire
 */
#if 0	// todo

int
smbfs_smb2_locking(struct smbnode *np, int op, uint32_t pid,
	offset_t start, uint64_t len, int largelock,
	struct smb_cred *scrp, uint32_t timeout)
{
	return (ENOTSUP);
}

#endif	// todo

/*
 * Helper for smbfs_getattr_otw
 * used when we don't have an open FID
 *
 * For SMB2 we need to do an attribute-only open.  The
 * data returned by open gets us everything we need, so
 * just close the handle and we're done.
 */
int
smbfs_smb2_getpattr(
	struct smbnode *np,
	struct smbfattr *fap,
	struct smb_cred *scrp)
{
	smb_fh_t tmp_fh;
	struct smb_share *ssp = np->n_mount->smi_share;
	uint32_t rights = (STD_RIGHT_READ_CONTROL_ACCESS |
	    SA_RIGHT_FILE_READ_ATTRIBUTES);
	int error;

	bzero(&tmp_fh, sizeof (tmp_fh));
	error = smbfs_smb_ntcreatex(np,
	    NULL, 0, 0,	/* name nmlen xattr */
	    rights, SMB_EFA_NORMAL,
	    NTCREATEX_SHARE_ACCESS_ALL,
	    NTCREATEX_DISP_OPEN,
	    0, /* create options */
	    scrp, &tmp_fh,
	    NULL, fap);
	if (error == 0) {
		(void) smb_smb_close(ssp, &tmp_fh, scrp);
	}

	return (error);
}

/*
 * Common SMB2 query file info
 */
static int
smbfs_smb2_query_info(struct smb_share *ssp, smb2fid_t *fid,
	struct mdchain *info_mdp, uint32_t *iolen,
	uint8_t type, uint8_t level, uint32_t addl_info,
	struct smb_cred *scrp)
{
	struct smb_rq *rqp = NULL;
	struct mbchain *mbp;
	struct mdchain *mdp;
	uint32_t dlen = 0;
	uint16_t doff = 0;
	uint16_t ssize = 0;
	int error;

	error = smb_rq_alloc(SSTOCP(ssp), SMB2_QUERY_INFO, scrp, &rqp);
	if (error)
		goto out;

	/*
	 * Build the SMB 2 Query Info req.
	 */
	smb_rq_getrequest(rqp, &mbp);
	mb_put_uint16le(mbp, 41);		// struct size
	mb_put_uint8(mbp, type);
	mb_put_uint8(mbp, level);
	mb_put_uint32le(mbp, *iolen);		// out buf len
	mb_put_uint16le(mbp, 0);		// in buf off
	mb_put_uint16le(mbp, 0);		// reserved
	mb_put_uint32le(mbp, 0);		// in buf len
	mb_put_uint32le(mbp, addl_info);
	mb_put_uint32le(mbp, 0);		// flags
	mb_put_uint64le(mbp, fid->fid_persistent);
	mb_put_uint64le(mbp, fid->fid_volatile);

	error = smb2_rq_simple(rqp);
	if (error) {
		if (rqp->sr_error == NT_STATUS_INVALID_PARAMETER)
			error = ENOTSUP;
		goto out;
	}

	/*
	 * Parse SMB 2 Query Info response
	 */
	smb_rq_getreply(rqp, &mdp);

	/* Check structure size is 9 */
	md_get_uint16le(mdp, &ssize);
	if (ssize != 9) {
		error = EBADRPC;
		goto out;
	}

	/* Get data off, len */
	md_get_uint16le(mdp, &doff);
	md_get_uint32le(mdp, &dlen);
	*iolen = dlen;

	/*
	 * Skip ahead to the payload, as needed.
	 * Current offset is SMB2_HDRLEN + 8.
	 */
	if (dlen != 0) {
		mblk_t *m = NULL;
		int skip = (int)doff - (SMB2_HDRLEN + 8);
		if (skip < 0) {
			error = EBADRPC;
			goto out;
		}
		if (skip > 0) {
			md_get_mem(mdp, NULL, skip, MB_MSYSTEM);
		}
		error = md_get_mbuf(mdp, dlen, &m);
		if (error)
			goto out;
		md_initm(info_mdp, m);
	}

out:
	smb_rq_done(rqp);

	return (error);
}


/*
 * Get FileAllInformation for an open file
 * and parse into *fap
 */
int
smbfs_smb2_qfileinfo(struct smb_share *ssp, smb2fid_t *fid,
	struct smbfattr *fap, struct smb_cred *scrp)
{
	struct mdchain info_mdc, *mdp = &info_mdc;
	uint32_t iolen = 1024;
	int error;

	bzero(mdp, sizeof (*mdp));

	error = smbfs_smb2_query_info(ssp, fid, mdp, &iolen,
	    SMB2_0_INFO_FILE, FileAllInformation, 0, scrp);
	if (error)
		goto out;

	error = smbfs_decode_file_all_info(ssp, mdp, fap);

out:
	md_done(mdp);

	return (error);
}

/*
 * Get some SMB2_0_INFO_FILESYSTEM info
 *
 * Note: This can be called during mount.  We don't have any
 * smbfs_node_t or pathname, so do our own attr. open on
 * the root of the share to get a handle for this request.
 */
static int
smbfs_smb2_query_fs_info(struct smb_share *ssp, struct mdchain *mdp,
	uint8_t level, struct smb_cred *scrp)
{
	smb2fid_t fid;
	uint32_t iolen = 1024;
	boolean_t opened = B_FALSE;
	int error;

	/*
	 * Need a FID for smb2, and this is called during mount
	 * so "go behind" the usual open/close functions.
	 */
	error = smb2_smb_ntcreate(
	    ssp, NULL,	// name
	    NULL, NULL, // create ctx in, out
	    0,	/* NTCREATEX_FLAGS... */
	    SA_RIGHT_FILE_READ_ATTRIBUTES,
	    SMB_EFA_NORMAL,
	    NTCREATEX_SHARE_ACCESS_ALL,
	    NTCREATEX_DISP_OPEN,
	    0, /* create options */
	    NTCREATEX_IMPERSONATION_IMPERSONATION,
	    scrp, &fid, NULL, NULL);
	if (error != 0)
		goto out;
	opened = B_TRUE;

	error = smbfs_smb2_query_info(ssp, &fid, mdp, &iolen,
	    SMB2_0_INFO_FILESYSTEM, level, 0, scrp);

out:
	if (opened)
		(void) smb2_smb_close(ssp, &fid, scrp);

	return (error);
}

/*
 * Get FileFsAttributeInformation and
 * parse into *info
 */
int
smbfs_smb2_qfsattr(struct smb_share *ssp, struct smb_fs_attr_info *info,
	struct smb_cred *scrp)
{
	struct mdchain info_mdc, *mdp = &info_mdc;
	int error;

	bzero(mdp, sizeof (*mdp));

	error = smbfs_smb2_query_fs_info(ssp, mdp,
	    FileFsAttributeInformation, scrp);
	if (error)
		goto out;
	error = smbfs_decode_fs_attr_info(ssp, mdp, info);

out:
	md_done(mdp);

	return (error);
}

/*
 * Get FileFsFullSizeInformation and
 * parse into *info
 */
int
smbfs_smb2_statfs(struct smb_share *ssp,
	struct smb_fs_size_info *info,
	struct smb_cred *scrp)
{
	struct mdchain info_mdc, *mdp = &info_mdc;
	int error;

	bzero(mdp, sizeof (*mdp));

	error = smbfs_smb2_query_fs_info(ssp, mdp,
	    FileFsFullSizeInformation, scrp);
	if (error)
		goto out;

	md_get_uint64le(mdp, &info->total_units);
	md_get_uint64le(mdp, &info->caller_avail);
	md_get_uint64le(mdp, &info->actual_avail);

	md_get_uint32le(mdp, &info->sect_per_unit);
	error = md_get_uint32le(mdp, &info->bytes_per_sect);

out:
	md_done(mdp);

	return (error);
}

int
smbfs_smb2_flush(struct smb_share *ssp, smb2fid_t *fid,
	struct smb_cred *scrp)
{
	struct smb_rq *rqp;
	struct mbchain *mbp;
	int error;

	error = smb_rq_alloc(SSTOCP(ssp), SMB2_FLUSH, scrp, &rqp);
	if (error)
		return (error);

	/*
	 * Build the SMB 2 Flush Request
	 */
	smb_rq_getrequest(rqp, &mbp);
	mb_put_uint16le(mbp, 24);	/* struct size */
	mb_put_uint16le(mbp, 0);	/* reserved */
	mb_put_uint32le(mbp, 0);	/* reserved */

	mb_put_uint64le(mbp, fid->fid_persistent);
	mb_put_uint64le(mbp, fid->fid_volatile);

	rqp->sr_flags |= SMBR_NORECONNECT;
	error = smb2_rq_simple(rqp);
	smb_rq_done(rqp);

	return (error);
}

/*
 * Set file info via an open handle.
 * Caller provides payload, info level.
 */
static int
smbfs_smb2_set_info(struct smb_share *ssp, smb2fid_t *fid,
	struct mbchain *info_mbp, uint8_t type, uint8_t level,
	uint32_t addl_info, struct smb_cred *scrp)
{
	struct smb_rq *rqp = NULL;
	struct mbchain *mbp;
	uint32_t *buffer_lenp;
	int base, len;
	int error;

	error = smb_rq_alloc(SSTOCP(ssp), SMB2_SET_INFO, scrp, &rqp);
	if (error)
		goto out;

	/*
	 * Build the SMB 2 Set Info req.
	 */
	smb_rq_getrequest(rqp, &mbp);
	mb_put_uint16le(mbp, 33);		// struct size
	mb_put_uint8(mbp, type);
	mb_put_uint8(mbp, level);
	buffer_lenp = mb_reserve(mbp, sizeof (uint32_t));
	mb_put_uint16le(mbp, SMB2_HDRLEN + 32);	// Buffer Offset
	mb_put_uint16le(mbp, 0);		// Reserved
	mb_put_uint32le(mbp, addl_info);	// Additional Info

	mb_put_uint64le(mbp, fid->fid_persistent);
	mb_put_uint64le(mbp, fid->fid_volatile);

	/*
	 * Now the payload
	 */
	base = mbp->mb_count;
	error = mb_put_mbchain(mbp, info_mbp);
	if (error)
		goto out;
	len = mbp->mb_count - base;
	*buffer_lenp = htolel(len);
	if (error)
		goto out;

	/*
	 * Run the request.
	 * Don't care about the (empty) reply.
	 */
	error = smb2_rq_simple(rqp);

out:
	smb_rq_done(rqp);

	return (error);
}

int
smbfs_smb2_seteof(struct smb_share *ssp, smb2fid_t *fid,
	uint64_t newsize, struct smb_cred *scrp)
{
	struct mbchain data_mb, *mbp = &data_mb;
	uint8_t level = FileEndOfFileInformation;
	int error;

	mb_init(mbp);
	mb_put_uint64le(mbp, newsize);
	error = smbfs_smb2_set_info(ssp, fid, mbp,
	    SMB2_0_INFO_FILE, level, 0, scrp);
	mb_done(mbp);

	return (error);
}

int
smbfs_smb2_setdisp(struct smb_share *ssp, smb2fid_t *fid,
	uint8_t newdisp, struct smb_cred *scrp)
{
	struct mbchain data_mb, *mbp = &data_mb;
	uint8_t level = FileDispositionInformation;
	int error;

	mb_init(mbp);
	mb_put_uint8(mbp, newdisp);
	error = smbfs_smb2_set_info(ssp, fid, mbp,
	    SMB2_0_INFO_FILE,  level, 0, scrp);
	mb_done(mbp);

	return (error);
}

/*
 * Set FileBasicInformation on an open handle
 * Caller builds the mbchain.
 */
int
smbfs_smb2_setfattr(struct smb_share *ssp, smb2fid_t *fid,
	struct mbchain *mbp, struct smb_cred *scrp)
{
	uint8_t level = FileBasicInformation;
	int error;

	error = smbfs_smb2_set_info(ssp, fid, mbp,
	    SMB2_0_INFO_FILE,  level, 0, scrp);
	return (error);
}

/*
 * Build a FileRenameInformation and call setinfo
 */
int
smbfs_smb2_rename(struct smbnode *np, struct smbnode *tdnp,
	const char *tname, int tnlen, int overwrite,
	smb2fid_t *fid, struct smb_cred *scrp)
{
	struct smb_share *ssp = np->n_mount->smi_share;
	struct mbchain data_mb, *mbp = &data_mb;
	uint32_t *name_lenp;
	uint8_t level = FileRenameInformation;
	int base, len;
	int error;

	mb_init(mbp);

	mb_put_uint32le(mbp, (overwrite & 1));
	mb_put_uint32le(mbp, 0);		// reserved
	mb_put_uint64le(mbp, 0);		// Root Dir
	name_lenp = mb_reserve(mbp, 4);

	/* Target name (full path) */
	base = mbp->mb_count;
	if (tnlen > 0) {
		error = smbfs_fullpath(mbp, SSTOVC(ssp),
		    tdnp, tname, tnlen, '\\');
		if (error)
			goto out;
	}
	len = mbp->mb_count - base;
	*name_lenp = htolel(len);

	error = smbfs_smb2_set_info(ssp, fid, mbp,
	    SMB2_0_INFO_FILE,  level, 0, scrp);

out:
	mb_done(mbp);

	return (error);
}

/*
 * Later servers have maxtransact at a megabyte or more,
 * but we don't want to buffer up that much data, so use
 * the lesser of that or 64k.
 */
#define	SMBFS_QDIR_MAX_BUF	(1<<16)

/*
 * SMB2 query directory
 */
static int
smbfs_smb2_qdir(struct smbfs_fctx *ctx)
{
	smb_fh_t *fhp = ctx->f_fhp;
	smb_share_t *ssp = ctx->f_ssp;
	smb_vc_t *vcp = SSTOVC(ssp);
	struct smb_rq *rqp;
	struct mbchain *mbp;
	struct mdchain *mdp;
	uint16_t *name_lenp;
	uint8_t level, flags;
	uint16_t ssize = 0;
	uint16_t obuf_off = 0;
	uint32_t obuf_len = 0;
	uint32_t obuf_req;
	int error;

	level = (uint8_t)ctx->f_infolevel;
	flags = 0;
	if (ctx->f_flags & SMBFS_RDD_FINDSINGLE)
		flags |= SMB2_QDIR_FLAG_SINGLE;
	if (ctx->f_flags & SMBFS_RDD_FINDFIRST)
		ctx->f_rkey = 0;
	else
		flags |= SMB2_QDIR_FLAG_INDEX;

	obuf_req = SMBFS_QDIR_MAX_BUF;
	if (obuf_req > vcp->vc_sopt.sv2_maxtransact)
		obuf_req = vcp->vc_sopt.sv2_maxtransact;

	if (ctx->f_rq) {
		smb_rq_done(ctx->f_rq);
		ctx->f_rq = NULL;
	}
	error = smb_rq_alloc(SSTOCP(ctx->f_ssp), SMB2_QUERY_DIRECTORY,
	    ctx->f_scred, &rqp);
	if (error)
		return (error);
	ctx->f_rq = rqp;

	/*
	 * Build an SMB2 Query Dir req.
	 */
	smb_rq_getrequest(rqp, &mbp);

	mb_put_uint16le(mbp, 33);			/* Struct size */
	mb_put_uint8(mbp, level);
	mb_put_uint8(mbp, flags);
	mb_put_uint32le(mbp, ctx->f_rkey);		/* FileIndex */

	mb_put_uint64le(mbp, fhp->fh_fid2.fid_persistent);
	mb_put_uint64le(mbp, fhp->fh_fid2.fid_volatile);

	mb_put_uint16le(mbp, 96);
	name_lenp = mb_reserve(mbp, sizeof (uint16_t));	/* FileNameLen */
	mb_put_uint32le(mbp, obuf_req);			/* Output Buf Len */

	/* Add in the name if any */
	if (ctx->f_wclen > 0) {
		int base, len;

		/* Put the match pattern. */
		base = mbp->mb_count;
		error = smb_put_dmem(mbp, vcp,
		    ctx->f_wildcard, ctx->f_wclen,
		    SMB_CS_NONE, NULL);
		if (error)
			return (error);

		/* Update the FileNameLen */
		len = mbp->mb_count - base;
		*name_lenp = htoles(len);
	} else {
		/* Empty string */
		mb_put_uint16le(mbp, 0);
		*name_lenp = 0;
	}

	error = smb2_rq_simple(rqp);
	if (error != 0)
		goto out;

	/*
	 * Parse the SMB2 Query Dir response
	 */
	smb_rq_getreply(rqp, &mdp);

	/* Check structure size is 9 */
	md_get_uint16le(mdp, &ssize);
	if (ssize != 9) {
		error = EBADRPC;
		goto out;
	}

	/* Get output buffer offset, length */
	md_get_uint16le(mdp, &obuf_off);
	md_get_uint32le(mdp, &obuf_len);

	/*
	 * After read at EOF we'll have just one word:
	 * NextEntryOffset == 0  Allow some padding.
	 */
	if (obuf_len < 8) {
		error = ENOENT;
		goto out;
	}

	/*
	 * If this reply is shorter than requested by 1k
	 * or more, we must have reached EOF.
	 */
	if ((obuf_len + 1024) < obuf_req)
		ctx->f_flags |= SMBFS_RDD_EOF;

	/*
	 * Have data. Put the payload in ctx->f_mdchain
	 * Current offset is SMB2_HDRLEN + 8.
	 */
	{
		mblk_t *m = NULL;
		int skip = (int)obuf_off - (SMB2_HDRLEN + 8);
		if (skip < 0) {
			error = EBADRPC;
			goto out;
		}
		if (skip > 0) {
			md_get_mem(mdp, NULL, skip, MB_MSYSTEM);
		}
		error = md_get_mbuf(mdp, obuf_len, &m);
		if (error)
			goto out;
		md_done(&ctx->f_mdchain);
		md_initm(&ctx->f_mdchain, m);
	}

	/*
	 * SMB2 Query Directory does not provie an EntryCount.
	 * Instead, we'll advance f_eofs (entry offset)
	 * through the range [0..f_left]
	 */
	ctx->f_left = obuf_len;
	ctx->f_eofs = 0;
	return (0);

out:
	if (error != 0) {
		/*
		 * Failed parsing the FindFirst or FindNext response.
		 * Force this directory listing closed, otherwise the
		 * calling process may hang in an infinite loop.
		 */
		ctx->f_left = 0;
		ctx->f_eofs = 0;
		ctx->f_flags |= SMBFS_RDD_EOF;
	}

	return (error);
}

int
smbfs_smb2_findopen(struct smbfs_fctx *ctx, struct smbnode *dnp,
    const char *wildcard, int wclen, uint32_t attr)
{
	smb_fh_t *fhp = NULL;
	uint32_t rights =
	    STD_RIGHT_READ_CONTROL_ACCESS |
	    SA_RIGHT_FILE_READ_ATTRIBUTES |
	    SA_RIGHT_FILE_READ_DATA;
	int error;

	/*
	 * Set f_type no matter what, so cleanup will call
	 * smbfs_smb2_findclose, error or not.
	 */
	ctx->f_type = ft_SMB2;
	ASSERT(ctx->f_dnp == dnp);

	/*
	 * Get a file handle on the directory
	 */
	error = smb_fh_create(ctx->f_ssp, &fhp);
	if (error != 0)
		goto errout;

	error = smbfs_smb_ntcreatex(dnp,
	    NULL, 0, 0,	/* name nmlen xattr */
	    rights, SMB_EFA_NORMAL,
	    NTCREATEX_SHARE_ACCESS_ALL,
	    NTCREATEX_DISP_OPEN,
	    0, /* create options */
	    ctx->f_scred, fhp,
	    NULL, NULL); /* cr_act_p fa_p */
	if (error != 0)
		goto errout;

	fhp->fh_rights = rights;
	smb_fh_opened(fhp);
	ctx->f_fhp = fhp;

	ctx->f_namesz = SMB_MAXFNAMELEN + 1;
	ctx->f_name = kmem_alloc(ctx->f_namesz, KM_SLEEP);
	ctx->f_infolevel = FileFullDirectoryInformation;
	ctx->f_attrmask = attr;
	ctx->f_wildcard = wildcard;
	ctx->f_wclen = wclen;

	return (0);

errout:
	if (fhp != NULL)
		smb_fh_rele(fhp);
	return (error);
}

int
smbfs_smb2_findclose(struct smbfs_fctx *ctx)
{
	smb_fh_t *fhp = NULL;

	if ((fhp = ctx->f_fhp) != NULL) {
		ctx->f_fhp = NULL;
		smb_fh_rele(fhp);
	}
	if (ctx->f_name)
		kmem_free(ctx->f_name, ctx->f_namesz);
	if (ctx->f_rq)
		smb_rq_done(ctx->f_rq);
	md_done(&ctx->f_mdchain);

	return (0);
}

/*
 * Get a buffer of directory entries (if we don't already have
 * some remaining in the current buffer) then decode one.
 */
int
smbfs_smb2_findnext(struct smbfs_fctx *ctx, uint16_t limit)
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
		error = smbfs_smb2_qdir(ctx);
		if (error)
			return (error);
		ctx->f_otws++;
	}

	/*
	 * Decode one entry
	 */
	error = smbfs_decode_dirent(ctx);

	return (error);
}


/*
 * Helper for smbfs_xa_get_streaminfo
 * Query stream info
 */
int
smbfs_smb2_get_streaminfo(smbnode_t *np, struct mdchain *mdp,
	struct smb_cred *scrp)
{
	smb_share_t *ssp = np->n_mount->smi_share;
	smb_fh_t *fhp = NULL;
	uint32_t rights =
	    STD_RIGHT_READ_CONTROL_ACCESS |
	    SA_RIGHT_FILE_READ_ATTRIBUTES;
	uint32_t iolen = INT16_MAX;
	int error;

	/*
	 * Get a file handle on the object
	 * with read attr. rights.
	 */
	error = smb_fh_create(ssp, &fhp);
	if (error != 0)
		goto out;
	error = smbfs_smb_ntcreatex(np,
	    NULL, 0, 0,	/* name nmlen xattr */
	    rights, SMB_EFA_NORMAL,
	    NTCREATEX_SHARE_ACCESS_ALL,
	    NTCREATEX_DISP_OPEN,
	    0, /* create options */
	    scrp, fhp, NULL, NULL);
	if (error != 0)
		goto out;

	smb_fh_opened(fhp);

	/*
	 * Query stream info
	 */
	error = smbfs_smb2_query_info(ssp, &fhp->fh_fid2, mdp, &iolen,
	    SMB2_0_INFO_FILE, FileStreamInformation, 0, scrp);

out:
	if (fhp != NULL)
		smb_fh_rele(fhp);
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
smbfs_smb2_getsec(struct smb_share *ssp, smb2fid_t *fid,
	uint32_t selector, mblk_t **res, uint32_t *reslen,
	struct smb_cred *scrp)
{
	struct mdchain info_mdc, *mdp = &info_mdc;
	int error;

	bzero(mdp, sizeof (*mdp));

	error = smbfs_smb2_query_info(ssp, fid, mdp, reslen,
	    SMB2_0_INFO_SECURITY, 0, selector, scrp);
	if (error)
		goto out;

	if (mdp->md_top == NULL) {
		error = EBADRPC;
		goto out;
	}
	*res = mdp->md_top;
	mdp->md_top = NULL;

out:
	md_done(mdp);
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
smbfs_smb2_setsec(struct smb_share *ssp, smb2fid_t *fid,
	uint32_t selector, mblk_t **mp, struct smb_cred *scrp)
{
	struct mbchain info_mbp, *mbp = &info_mbp;
	int error;

	ASSERT(*mp != NULL);
	mb_initm(mbp, *mp);
	*mp = NULL; /* consumed */

	error = smbfs_smb2_set_info(ssp, fid, mbp,
	    SMB2_0_INFO_SECURITY, 0, selector, scrp);

	mb_done(mbp);

	return (error);
}
