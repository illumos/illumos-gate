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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/syslog.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>


typedef struct smb_read_param {
	uint64_t r_offset;
	uint16_t r_count;
	uint16_t r_mincnt;
} smb_read_param_t;


int smb_common_read(struct smb_request *sr, smb_read_param_t *param);


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
int
smb_com_read(struct smb_request *sr)
{
	smb_read_param_t param;
	uint32_t off_low;
	uint16_t remcnt;
	int rc;

	rc = smbsr_decode_vwv(sr, "wwlw", &sr->smb_fid,
	    &param.r_count, &off_low, &remcnt);
	if (rc != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	param.r_offset = (uint64_t)off_low;
	param.r_mincnt = 0;

	sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree, sr->smb_fid);
	if (sr->fid_ofile == NULL) {
		smbsr_raise_cifs_error(sr, NT_STATUS_INVALID_HANDLE,
		    ERRDOS, ERRbadfid);
		/* NOTREACHED */
	}

	if ((rc = smb_common_read(sr, &param)) != 0) {
		smbsr_raise_errno(sr, rc);
		/* NOTREACHED */
	}

	smbsr_encode_result(sr, 5, VAR_BCC, "bw8.wbwC",
	    5, param.r_count, VAR_BCC, 0x01, param.r_count, &sr->raw_data);

	return (SDRC_NORMAL_REPLY);
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
int
smb_com_lock_and_read(struct smb_request *sr)
{
	smb_read_param_t param;
	uint16_t remcnt;
	uint32_t off_low;
	DWORD result;
	int rc;

	if (STYPE_ISDSK(sr->tid_tree->t_res_type) == 0) {
		smbsr_raise_error(sr, ERRDOS, ERRnoaccess);
		/* NOTREACHED */
	}

	rc = smbsr_decode_vwv(sr, "wwlw", &sr->smb_fid,
	    &param.r_count, &off_low, &remcnt);
	if (rc != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	param.r_offset = (uint64_t)off_low;
	param.r_mincnt = 0;

	sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree, sr->smb_fid);
	if (sr->fid_ofile == NULL) {
		smbsr_raise_cifs_error(sr, NT_STATUS_INVALID_HANDLE,
		    ERRDOS, ERRbadfid);
		/* NOTREACHED */
	}

	result = smb_lock_range(sr, sr->fid_ofile, param.r_offset,
	    (uint64_t)param.r_count, 0xffffffff, SMB_LOCK_TYPE_READWRITE);
	if (result != NT_STATUS_SUCCESS) {
		smb_lock_range_raise_error(sr, result);
	}

	if ((rc = smb_common_read(sr, &param)) != 0) {
		smbsr_raise_errno(sr, rc);
		/* NOTREACHED */
	}

	smbsr_encode_result(sr, 5, VAR_BCC, "bw8.wbwC",
	    5, param.r_count, VAR_BCC, 0x1, param.r_count, &sr->raw_data);

	return (SDRC_NORMAL_REPLY);
}

/*
 * The SMB_COM_READ_RAW protocol is a negotiated option introduced in
 * SMB Core Plus to maximize performance when reading a large block
 * of data from a server.  This request was extended in LM 0.12 to
 * support 64-bit offsets; the server can indicate support by setting
 * CAP_LARGE_FILES in the negotiated capabilities.
 *
 * The client must guarantee that there is (and will be) no other request
 * to the server for the duration of the SMB_COM_READ_RAW, since the
 * server response has no header or trailer. To help ensure that there
 * are no interruptions, we block all I/O for the session during read raw.
 *
 * If this is the first SMB request received since we sent an oplock break
 * to this client, we don't know if it's safe to send the raw data because
 * the requests may have crossed on the wire and the client may have
 * interpreted the oplock break as part of the raw data. To avoid problems,
 * we send a zero length session packet, which will force the client to
 * retry the read.
 *
 * Read errors are handled by sending a zero length response.
 */
int
smb_com_read_raw(struct smb_request *sr)
{
	smb_read_param_t	param;
	smb_node_t		*node;
	uint32_t		off_low;
	uint32_t		off_high;
	uint32_t		timeout;
	int			rc;

	switch (sr->session->s_state) {
	case SMB_SESSION_STATE_NEGOTIATED:
		if (sr->smb_wct == 8) {
			rc = smbsr_decode_vwv(sr, "wlwwl2.", &sr->smb_fid,
			    &off_low, &param.r_count, &param.r_mincnt,
			    &timeout);
			param.r_offset = (uint64_t)off_low;
		} else {
			rc = smbsr_decode_vwv(sr, "wlwwl2.l", &sr->smb_fid,
			    &off_low, &param.r_count, &param.r_mincnt, &timeout,
			    &off_high);
			param.r_offset = ((uint64_t)off_high << 32) | off_low;
		}

		if (rc != 0) {
			smbsr_decode_error(sr);
			/* NOTREACHED */
		}

		sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree,
		    sr->smb_fid);
		if (sr->fid_ofile == NULL) {
			smbsr_raise_cifs_error(sr, NT_STATUS_INVALID_HANDLE,
			    ERRDOS, ERRbadfid);
			/* NOTREACHED */
		}

		rc = smb_common_read(sr, &param);
		/*
		 * XXX Do we need to handle errors here?  What if we have an
		 * access error (either permissions or range lock violations?
		 */
		if (STYPE_ISDSK(sr->tid_tree->t_res_type)) {
			node = sr->fid_ofile->f_node;
			if (node->n_oplock.op_flags & OPLOCK_FLAG_BREAKING) {
				rc = EAGAIN;
			}
		}

		if (rc != 0) {
			(void) smb_session_send(sr->session, 0, NULL);
			m_freem(sr->raw_data.chain);
			sr->raw_data.chain = 0;
		} else {
			(void) smb_session_send(sr->session, 0, &sr->raw_data);
		}
		return (SDRC_NO_REPLY);

	case SMB_SESSION_STATE_OPLOCK_BREAKING:
		(void) smb_session_send(sr->session, 0, NULL);
		sr->session->s_state = SMB_SESSION_STATE_NEGOTIATED;
		return (SDRC_NO_REPLY);

	case SMB_SESSION_STATE_WRITE_RAW_ACTIVE:
		ASSERT(0);
		return (SDRC_DROP_VC);

	case SMB_SESSION_STATE_TERMINATED:
		ASSERT(0);
		return (SDRC_NO_REPLY);

	case SMB_SESSION_STATE_DISCONNECTED:
		return (SDRC_NO_REPLY);

	case SMB_SESSION_STATE_CONNECTED:
	case SMB_SESSION_STATE_ESTABLISHED:
	default:
		ASSERT(0);
		return (SDRC_DROP_VC);
	}
}

/*
 * Read bytes from a file (SMB Core).  This request was extended in
 * LM 0.12 to support 64-bit offsets, indicated by sending a wct of
 * 12 and including additional offset information.
 */
int
smb_com_read_andx(struct smb_request *sr)
{
	smb_read_param_t param;
	uint32_t off_low;
	uint32_t off_high;
	uint16_t remcnt;
	uint16_t offset2;
	uint8_t secondary;
	int rc;

	if (sr->smb_wct == 12) {
		rc = smbsr_decode_vwv(sr, "b3.wlw6.wl", &secondary,
		    &sr->smb_fid, &off_low, &param.r_count, &remcnt, &off_high);

		param.r_offset = ((uint64_t)off_high << 32) | off_low;
	} else {
		rc = smbsr_decode_vwv(sr, "b3.wlw6.w", &secondary,
		    &sr->smb_fid, &off_low, &param.r_count, &remcnt);

		param.r_offset = (uint64_t)off_low;
	}

	if (rc != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	param.r_mincnt = 0;

	sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree, sr->smb_fid);
	if (sr->fid_ofile == NULL) {
		smbsr_raise_cifs_error(sr, NT_STATUS_INVALID_HANDLE,
		    ERRDOS, ERRbadfid);
		/* NOTREACHED */
	}

	if ((rc = smb_common_read(sr, &param)) != 0) {
		smbsr_raise_errno(sr, rc);
		/* NOTREACHED */
	}

	/*
	 * Ensure that the next response offset is zero
	 * if there is no secondary command.
	 */
	offset2 = (secondary == 0xFF) ? 0 : param.r_count + 59;

	/*
	 * The STYPE_IPC response format is different.
	 * The unknown value (2) may be to indicate that it
	 * is a follow-up to an earlier RPC transaction.
	 */
	if (STYPE_ISIPC(sr->tid_tree->t_res_type)) {
		smbsr_encode_result(sr, 12, VAR_BCC, "bb1.ww4.ww10.wbC",
		    12,			/* wct */
		    secondary,		/* Secondary andx command */
		    offset2,		/* offset to next */
		    0,			/* must be 0 */
		    param.r_count,	/* data byte count */
		    60,			/* Offset from start to data */
		    VAR_BCC,		/* BCC marker */
		    0x02,		/* unknown */
		    &sr->raw_data);
	} else {
		smbsr_encode_result(sr, 12, VAR_BCC, "bb1.ww4.ww10.wC",
		    12,			/* wct */
		    secondary,		/* Secondary andx command */
		    offset2,		/* offset to next */
		    -1,			/* must be -1 */
		    param.r_count,	/* data byte count */
		    59,			/* Offset from start to data */
		    VAR_BCC,		/* BCC marker */
		    &sr->raw_data);
	}

	return (SDRC_NORMAL_REPLY);
}

/*
 * Common function for reading files or IPC/MSRPC named pipes.  All
 * protocol read functions should lookup the fid before calling this
 * function.  We can't move the fid lookup here because lock-and-read
 * requires the fid to do locking before attempting the read.
 *
 * Returns errno values.
 */
int
smb_common_read(struct smb_request *sr, smb_read_param_t *param)
{
	smb_ofile_t *ofile = sr->fid_ofile;
	smb_node_t *node;
	struct vardata_block *vdb;
	struct mbuf *top;
	int rc;

	vdb = kmem_alloc(sizeof (struct vardata_block), KM_SLEEP);
	vdb->tag = 0;
	vdb->uio.uio_iov = &vdb->iovec[0];
	vdb->uio.uio_iovcnt = MAX_IOVEC;
	vdb->uio.uio_resid = param->r_count;
	vdb->uio.uio_offset = param->r_offset;
	vdb->uio.uio_segflg = UIO_SYSSPACE;

	switch (sr->tid_tree->t_res_type & STYPE_MASK) {
	case STYPE_DISKTREE:
		node = ofile->f_node;

		if (node->attr.sa_vattr.va_type != VDIR) {
			rc = smb_lock_range_access(sr, node, param->r_offset,
			    param->r_count, FILE_READ_DATA);
			if (rc != NT_STATUS_SUCCESS) {
				rc = ERANGE;
				break;
			}
		}

		(void) smb_sync_fsattr(sr, sr->user_cr, node);

		sr->raw_data.max_bytes = vdb->uio.uio_resid;
		top = smb_mbuf_allocate(&vdb->uio);

		rc = smb_fsop_read(sr, sr->user_cr, node, &vdb->uio,
		    &node->attr);

		sr->raw_data.max_bytes -= vdb->uio.uio_resid;
		smb_mbuf_trim(top, sr->raw_data.max_bytes);
		MBC_ATTACH_MBUF(&sr->raw_data, top);
		break;

	case STYPE_IPC:
		rc = smb_rpc_read(sr, &vdb->uio);
		break;

	default:
		rc = EACCES;
		break;
	}

	param->r_count -= vdb->uio.uio_resid;
	kmem_free(vdb, sizeof (struct vardata_block));

	if (rc != 0)
		return (rc);

	if (param->r_mincnt != 0 && param->r_count < param->r_mincnt) {
		/*
		 * mincnt is only used by read-raw and is typically
		 * zero.  If mincnt is greater than zero and the
		 * number of bytes read is less than mincnt, tell
		 * the client that we read nothing.
		 */
		param->r_count = 0;
	}

	param->r_offset += param->r_count;
	mutex_enter(&sr->fid_ofile->f_mutex);
	ofile->f_seek_pos = param->r_offset;
	mutex_exit(&sr->fid_ofile->f_mutex);
	return (rc);
}

/*
 * The Read Block Multiplexed protocol is used to maximize performance
 * when reading a large block of data from server to client while still
 * allowing other operations to take place between the client and server
 * in parallel.
 *
 * The mpx sub protocol is not supported because we support only
 * connection oriented transports and NT supports SMB_COM_READ_MPX
 * only over connectionless transports.
 */
/*ARGSUSED*/
int
smb_com_read_mpx(struct smb_request *sr)
{
	return (SDRC_UNIMPLEMENTED);
}

/*ARGSUSED*/
int
smb_com_read_mpx_secondary(struct smb_request *sr)
{
	return (SDRC_UNIMPLEMENTED);
}
