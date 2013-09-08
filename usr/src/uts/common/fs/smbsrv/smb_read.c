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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>

/*
 * The maximum number of bytes to return from SMB Core
 * SmbRead or SmbLockAndRead.
 */
#define	SMB_CORE_READ_MAX	4432

/*
 * The limit in bytes for SmbReadX.
 */
#define	SMB_READX_MAX		0x10000

int smb_common_read(smb_request_t *, smb_rw_param_t *);

/*
 * Read bytes from a file or named pipe (SMB Core).
 *
 * The requested count specifies the number of bytes desired.  Offset
 * is limited to 32 bits, so this client request is inappropriate for
 * files with 64 bit offsets.
 *
 * On return, count is the number of bytes actually being returned, which
 * may be less than the count requested only if a read specifies bytes
 * beyond the current file size.  In this case only the bytes that exist
 * are returned.  A read completely beyond the end of file results in a
 * response of length zero.  This is the only circumstance when a zero
 * length response is generated.  A count returned which is less than the
 * count requested is the end of file indicator.
 */
smb_sdrc_t
smb_pre_read(smb_request_t *sr)
{
	smb_rw_param_t *param;
	uint32_t off_low;
	uint16_t count;
	uint16_t remcnt;
	int rc;

	param = kmem_zalloc(sizeof (smb_rw_param_t), KM_SLEEP);
	sr->arg.rw = param;

	rc = smbsr_decode_vwv(sr, "wwlw", &sr->smb_fid,
	    &count, &off_low, &remcnt);

	param->rw_offset = (uint64_t)off_low;
	param->rw_count = (uint32_t)count;
	param->rw_mincnt = 0;

	DTRACE_SMB_2(op__Read__start, smb_request_t *, sr,
	    smb_rw_param_t *, param);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_read(smb_request_t *sr)
{
	DTRACE_SMB_2(op__Read__done, smb_request_t *, sr,
	    smb_rw_param_t *, sr->arg.rw);

	kmem_free(sr->arg.rw, sizeof (smb_rw_param_t));
}

smb_sdrc_t
smb_com_read(smb_request_t *sr)
{
	smb_rw_param_t *param = sr->arg.rw;
	uint16_t count;
	int rc;

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	sr->user_cr = smb_ofile_getcred(sr->fid_ofile);

	if (param->rw_count > SMB_CORE_READ_MAX)
		param->rw_count = SMB_CORE_READ_MAX;

	if ((rc = smb_common_read(sr, param)) != 0) {
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	count = (uint16_t)param->rw_count;
	rc = smbsr_encode_result(sr, 5, VAR_BCC, "bw8.wbwC",
	    5, count, VAR_BCC, 0x01, count, &sr->raw_data);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * Lock and read bytes from a file (SMB Core Plus).  The SmbLockAndRead/
 * SmbLockAndWrite sub-dialect is only valid on disk files: reject any
 * attempt to use it on non-disk shares.
 *
 * The requested count specifies the number of bytes desired.  Offset
 * specifies the offset in the file of the first byte to be locked then
 * read. Note that offset is limited to 32 bits, so this client request
 * is inappropriate for files with 64 bit offsets.
 *
 * As with SMB_LOCK_BYTE_RANGE request, if the lock cannot be granted
 * immediately an error should be returned to the client.  If an error
 * occurs on the lock, the bytes should not be read.
 *
 * On return, count is the number of bytes actually being returned, which
 * may be less than the count requested only if a read specifies bytes
 * beyond the current file size.  In this case only the bytes that exist
 * are returned.  A read completely beyond the end of file results in a
 * response of length zero.  This is the only circumstance when a zero
 * length response is generated.  A count returned which is less than the
 * count requested is the end of file indicator.
 */
smb_sdrc_t
smb_pre_lock_and_read(smb_request_t *sr)
{
	smb_rw_param_t *param;
	uint32_t off_low;
	uint16_t count;
	uint16_t remcnt;
	int rc;

	param = kmem_zalloc(sizeof (smb_rw_param_t), KM_SLEEP);
	sr->arg.rw = param;

	rc = smbsr_decode_vwv(sr, "wwlw", &sr->smb_fid,
	    &count, &off_low, &remcnt);

	param->rw_offset = (uint64_t)off_low;
	param->rw_count = (uint32_t)count;
	param->rw_mincnt = 0;

	DTRACE_SMB_2(op__LockAndRead__start, smb_request_t *, sr,
	    smb_rw_param_t *, param);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_lock_and_read(smb_request_t *sr)
{
	DTRACE_SMB_2(op__LockAndRead__done, smb_request_t *, sr,
	    smb_rw_param_t *, sr->arg.rw);

	kmem_free(sr->arg.rw, sizeof (smb_rw_param_t));
}

smb_sdrc_t
smb_com_lock_and_read(smb_request_t *sr)
{
	smb_rw_param_t *param = sr->arg.rw;
	DWORD status;
	uint16_t count;
	int rc;

	if (STYPE_ISDSK(sr->tid_tree->t_res_type) == 0) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS, ERRnoaccess);
		return (SDRC_ERROR);
	}

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	sr->user_cr = smb_ofile_getcred(sr->fid_ofile);

	status = smb_lock_range(sr, param->rw_offset, (uint64_t)param->rw_count,
	    0, SMB_LOCK_TYPE_READWRITE);

	if (status != NT_STATUS_SUCCESS) {
		smb_lock_range_error(sr, status);
		return (SDRC_ERROR);
	}

	if (param->rw_count > SMB_CORE_READ_MAX)
		param->rw_count = SMB_CORE_READ_MAX;

	if ((rc = smb_common_read(sr, param)) != 0) {
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	count = (uint16_t)param->rw_count;
	rc = smbsr_encode_result(sr, 5, VAR_BCC, "bw8.wbwC",
	    5, count, VAR_BCC, 0x1, count, &sr->raw_data);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * Read bytes from a file (SMB Core).  This request was extended in
 * LM 0.12 to support 64-bit offsets, indicated by sending a wct of
 * 12 and including additional offset information.
 *
 * MS-SMB 3.3.5.7 update to LM 0.12 4.2.4:
 * If wct is 12 and CAP_LARGE_READX is set, the count may be larger
 * than the negotiated buffer size.  If maxcnt_high is 0xFF, it must
 * be ignored.  Otherwise, maxcnt_high represents the upper 16 bits
 * of rw_count.
 */
smb_sdrc_t
smb_pre_read_andx(smb_request_t *sr)
{
	smb_rw_param_t *param;
	uint32_t off_low;
	uint32_t off_high;
	uint32_t maxcnt_high;
	uint16_t maxcnt_low;
	uint16_t mincnt;
	uint16_t remcnt;
	int rc;

	param = kmem_zalloc(sizeof (smb_rw_param_t), KM_SLEEP);
	sr->arg.rw = param;

	if (sr->smb_wct == 12) {
		rc = smbsr_decode_vwv(sr, "b3.wlwwlwl", &param->rw_andx,
		    &sr->smb_fid, &off_low, &maxcnt_low, &mincnt, &maxcnt_high,
		    &remcnt, &off_high);

		param->rw_offset = ((uint64_t)off_high << 32) |
		    (uint64_t)off_low;

		param->rw_count = (uint32_t)maxcnt_low;

		if ((sr->session->capabilities & CAP_LARGE_READX) &&
		    (maxcnt_high < 0xFF))
			param->rw_count |= maxcnt_high << 16;
	} else {
		rc = smbsr_decode_vwv(sr, "b3.wlwwlw", &param->rw_andx,
		    &sr->smb_fid, &off_low, &maxcnt_low, &mincnt, &maxcnt_high,
		    &remcnt);

		param->rw_offset = (uint64_t)off_low;
		param->rw_count = (uint32_t)maxcnt_low;
	}

	param->rw_mincnt = 0;

	DTRACE_SMB_2(op__ReadX__start, smb_request_t *, sr,
	    smb_rw_param_t *, param);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_read_andx(smb_request_t *sr)
{
	DTRACE_SMB_2(op__ReadX__done, smb_request_t *, sr,
	    smb_rw_param_t *, sr->arg.rw);

	kmem_free(sr->arg.rw, sizeof (smb_rw_param_t));
}

smb_sdrc_t
smb_com_read_andx(smb_request_t *sr)
{
	smb_rw_param_t *param = sr->arg.rw;
	uint16_t datalen_high;
	uint16_t datalen_low;
	uint16_t data_offset;
	uint16_t offset2;
	int rc;

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	sr->user_cr = smb_ofile_getcred(sr->fid_ofile);

	if (param->rw_count >= SMB_READX_MAX)
		param->rw_count = 0;

	if ((rc = smb_common_read(sr, param)) != 0) {
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	datalen_low = param->rw_count & 0xFFFF;
	datalen_high = (param->rw_count >> 16) & 0xFF;

	/*
	 * If this is a secondary command, the data offset
	 * includes the previous wct + sizeof(wct).
	 */
	data_offset = (sr->andx_prev_wct == 0) ? 0 : sr->andx_prev_wct + 1;

	if (STYPE_ISIPC(sr->tid_tree->t_res_type)) {
		data_offset += 60;
		offset2 = (param->rw_andx == 0xFF) ? 0 : param->rw_count + 60;

		rc = smbsr_encode_result(sr, 12, VAR_BCC, "bb1.ww4.www8.wbC",
		    12,			/* wct */
		    param->rw_andx,	/* secondary andx command */
		    offset2,		/* offset to next command */
		    0,			/* set to 0 for named pipes */
		    datalen_low,	/* data byte count */
		    data_offset,	/* offset from start to data */
		    datalen_high,	/* data byte count */
		    VAR_BCC,		/* BCC marker */
		    0x00,		/* padding */
		    &sr->raw_data);
	} else {
		data_offset += 59;
		offset2 = (param->rw_andx == 0xFF) ? 0 : param->rw_count + 59;

		rc = smbsr_encode_result(sr, 12, VAR_BCC, "bb1.ww4.www8.wC",
		    12,			/* wct */
		    param->rw_andx,	/* secondary andx command */
		    offset2,		/* offset to next command */
		    -1,			/* must be -1 for regular files */
		    datalen_low,	/* data byte count */
		    data_offset,	/* offset from start to data */
		    datalen_high,	/* data byte count */
		    VAR_BCC,		/* BCC marker */
		    &sr->raw_data);
	}

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * Common function for reading files or IPC/MSRPC named pipes.  All
 * protocol read functions should lookup the fid before calling this
 * function.  We can't move the fid lookup here because lock-and-read
 * requires the fid to do locking before attempting the read.
 *
 * Reading from a file should break oplocks on the file to LEVEL_II.
 * A call to smb_oplock_break(SMB_OPLOCK_BREAK_TO_LEVEL_II) is not
 * required as it is a no-op. If there's anything greater than a
 * LEVEL_II oplock on the file, the oplock MUST be owned by the ofile
 * on which the read is occuring and therefore would not be broken.
 *
 * Returns errno values.
 */
int
smb_common_read(smb_request_t *sr, smb_rw_param_t *param)
{
	smb_ofile_t *ofile = sr->fid_ofile;
	smb_node_t *node;
	smb_vdb_t *vdb = &param->rw_vdb;
	struct mbuf *top;
	int rc;

	vdb->vdb_tag = 0;
	vdb->vdb_uio.uio_iov = &vdb->vdb_iovec[0];
	vdb->vdb_uio.uio_iovcnt = MAX_IOVEC;
	vdb->vdb_uio.uio_resid = param->rw_count;
	vdb->vdb_uio.uio_loffset = (offset_t)param->rw_offset;
	vdb->vdb_uio.uio_segflg = UIO_SYSSPACE;
	vdb->vdb_uio.uio_extflg = UIO_COPY_DEFAULT;

	switch (sr->tid_tree->t_res_type & STYPE_MASK) {
	case STYPE_DISKTREE:
		node = ofile->f_node;

		if (!smb_node_is_dir(node)) {
			rc = smb_lock_range_access(sr, node, param->rw_offset,
			    param->rw_count, B_FALSE);
			if (rc != NT_STATUS_SUCCESS) {
				rc = ERANGE;
				break;
			}
		}

		if ((ofile->f_flags & SMB_OFLAGS_EXECONLY) &&
		    !(sr->smb_flg2 & SMB_FLAGS2_READ_IF_EXECUTE)) {
			/*
			 * SMB_FLAGS2_READ_IF_EXECUTE: permit execute-only
			 * reads.
			 *
			 * Reject request if the file has been opened
			 * execute-only and SMB_FLAGS2_READ_IF_EXECUTE is not
			 * set.
			 */
			rc = EACCES;
			break;
		}

		sr->raw_data.max_bytes = vdb->vdb_uio.uio_resid;
		top = smb_mbuf_allocate(&vdb->vdb_uio);

		rc = smb_fsop_read(sr, sr->user_cr, node, &vdb->vdb_uio);

		sr->raw_data.max_bytes -= vdb->vdb_uio.uio_resid;
		smb_mbuf_trim(top, sr->raw_data.max_bytes);
		MBC_ATTACH_MBUF(&sr->raw_data, top);
		break;

	case STYPE_IPC:
		sr->raw_data.max_bytes = vdb->vdb_uio.uio_resid;
		top = smb_mbuf_allocate(&vdb->vdb_uio);

		rc = smb_opipe_read(sr, &vdb->vdb_uio);

		sr->raw_data.max_bytes -= vdb->vdb_uio.uio_resid;
		smb_mbuf_trim(top, sr->raw_data.max_bytes);
		MBC_ATTACH_MBUF(&sr->raw_data, top);
		break;

	default:
		rc = EACCES;
		break;
	}

	param->rw_count -= vdb->vdb_uio.uio_resid;

	if (rc != 0)
		return (rc);

	if (param->rw_mincnt != 0 && param->rw_count < param->rw_mincnt) {
		/*
		 * mincnt is only used by read-raw and is typically
		 * zero.  If mincnt is greater than zero and the
		 * number of bytes read is less than mincnt, tell
		 * the client that we read nothing.
		 */
		param->rw_count = 0;
	}

	param->rw_offset += param->rw_count;
	mutex_enter(&sr->fid_ofile->f_mutex);
	ofile->f_seek_pos = param->rw_offset;
	mutex_exit(&sr->fid_ofile->f_mutex);
	return (rc);
}
