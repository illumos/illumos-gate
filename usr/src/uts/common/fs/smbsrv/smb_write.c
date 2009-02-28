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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/sdt.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/mbuf.h>
#include <smbsrv/netbios.h>


#define	SMB_WRMODE_WRITE_THRU	0x0001
#define	SMB_WRMODE_IS_STABLE(M)	((M) & SMB_WRMODE_WRITE_THRU)

/*
 * The limit in bytes that the marshalling will grow the buffer
 * chain to accomodate incoming data on SmbWriteX requests.
 * This sets the upper limit for the data-count per SmbWriteX
 * request.
 */
#define	SMB_WRITEX_MAX		102400

static int smb_write_common(smb_request_t *, smb_rw_param_t *);
static int smb_write_truncate(smb_request_t *, smb_rw_param_t *);


/*
 * Write count bytes at the specified offset in a file.  The offset is
 * limited to 32-bits.  If the count is zero, the file is truncated to
 * the length specified by the offset.
 *
 * The response count indicates the actual number of bytes written, which
 * will equal the requested count on success.  If request and response
 * counts differ but there is no error, the client will assume that the
 * server encountered a resource issue.
 */
smb_sdrc_t
smb_pre_write(smb_request_t *sr)
{
	smb_rw_param_t *param;
	uint32_t off;
	uint16_t count;
	int rc;

	param = kmem_zalloc(sizeof (smb_rw_param_t), KM_SLEEP);
	sr->arg.rw = param;
	param->rw_magic = SMB_RW_MAGIC;

	rc = smbsr_decode_vwv(sr, "wwl", &sr->smb_fid, &count, &off);

	param->rw_count = (uint32_t)count;
	param->rw_offset = (uint64_t)off;
	param->rw_vdb.vdb_uio.uio_loffset = (offset_t)param->rw_offset;

	DTRACE_SMB_2(op__Write__start, smb_request_t *, sr,
	    smb_rw_param_t *, param);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_write(smb_request_t *sr)
{
	DTRACE_SMB_2(op__Write__done, smb_request_t *, sr,
	    smb_rw_param_t *, sr->arg.rw);

	kmem_free(sr->arg.rw, sizeof (smb_rw_param_t));
}

smb_sdrc_t
smb_com_write(smb_request_t *sr)
{
	smb_rw_param_t *param = sr->arg.rw;
	int rc;

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	sr->user_cr = smb_ofile_getcred(sr->fid_ofile);

	if (param->rw_count == 0) {
		rc = smb_write_truncate(sr, param);
	} else {
		rc = smbsr_decode_data(sr, "D", &param->rw_vdb);

		if ((rc != 0) || (param->rw_vdb.vdb_len != param->rw_count)) {
			smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
			    ERRDOS, ERROR_INVALID_PARAMETER);
			return (SDRC_ERROR);
		}

		param->rw_vdb.vdb_uio.uio_loffset = (offset_t)param->rw_offset;

		rc = smb_write_common(sr, param);
	}

	if (rc != 0) {
		if (sr->smb_error.status != NT_STATUS_FILE_LOCK_CONFLICT)
			smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	rc = smbsr_encode_result(sr, 1, 0, "bww", 1,
	    (uint16_t)param->rw_count, 0);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * Write count bytes to a file and then close the file.  This function
 * can only be used to write to 32-bit offsets and the client must set
 * WordCount (6 or 12) correctly in order to locate the data to be
 * written.  If an error occurs on the write, the file should still be
 * closed.  If Count is 0, the file is truncated (or extended) to offset.
 *
 * If the last_write time is non-zero, last_write should be used to set
 * the mtime.  Otherwise the file system stamps the mtime.  Failure to
 * set mtime should not result in an error response.
 */
smb_sdrc_t
smb_pre_write_and_close(smb_request_t *sr)
{
	smb_rw_param_t *param;
	uint32_t off;
	uint16_t count;
	int rc;

	param = kmem_zalloc(sizeof (smb_rw_param_t), KM_SLEEP);
	sr->arg.rw = param;
	param->rw_magic = SMB_RW_MAGIC;

	if (sr->smb_wct == 12) {
		rc = smbsr_decode_vwv(sr, "wwll12.", &sr->smb_fid,
		    &count, &off, &param->rw_last_write);
	} else {
		rc = smbsr_decode_vwv(sr, "wwll", &sr->smb_fid,
		    &count, &off, &param->rw_last_write);
	}

	param->rw_count = (uint32_t)count;
	param->rw_offset = (uint64_t)off;

	DTRACE_SMB_2(op__WriteAndClose__start, smb_request_t *, sr,
	    smb_rw_param_t *, param);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_write_and_close(smb_request_t *sr)
{
	DTRACE_SMB_2(op__WriteAndClose__done, smb_request_t *, sr,
	    smb_rw_param_t *, sr->arg.rw);

	kmem_free(sr->arg.rw, sizeof (smb_rw_param_t));
}

smb_sdrc_t
smb_com_write_and_close(smb_request_t *sr)
{
	smb_rw_param_t *param = sr->arg.rw;
	uint16_t count;
	int rc = 0;

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	sr->user_cr = smb_ofile_getcred(sr->fid_ofile);

	if (param->rw_count == 0) {
		rc = smb_write_truncate(sr, param);
	} else {
		/*
		 * There may be a bug here: should this be "3.#B"?
		 */
		rc = smbsr_decode_data(sr, ".#B", param->rw_count,
		    &param->rw_vdb);

		if ((rc != 0) || (param->rw_vdb.vdb_len != param->rw_count)) {
			smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
			    ERRDOS, ERROR_INVALID_PARAMETER);
			return (SDRC_ERROR);
		}

		param->rw_vdb.vdb_uio.uio_loffset = (offset_t)param->rw_offset;

		rc = smb_write_common(sr, param);
	}

	if (rc != 0) {
		if (sr->smb_error.status != NT_STATUS_FILE_LOCK_CONFLICT)
			smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	smb_ofile_close(sr->fid_ofile, param->rw_last_write);

	count = (uint16_t)param->rw_count;
	rc = smbsr_encode_result(sr, 1, 0, "bww", 1, count, 0);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * Write count bytes to a file at the specified offset and then unlock
 * them.  Write behind is safe because the client should have the range
 * locked and this request is allowed to extend the file - note that
 * offset is limited to 32-bits.
 *
 * Spec advice: it is an error for count to be zero.  For compatibility,
 * we take no action and return success.
 *
 * The SmbLockAndRead/SmbWriteAndUnlock sub-dialect is only valid on disk
 * files.  Reject any attempt to use it on other shares.
 *
 * The response count indicates the actual number of bytes written, which
 * will equal the requested count on success.  If request and response
 * counts differ but there is no error, the client will assume that the
 * server encountered a resource issue.
 */
smb_sdrc_t
smb_pre_write_and_unlock(smb_request_t *sr)
{
	smb_rw_param_t *param;
	uint32_t off;
	uint16_t count;
	uint16_t remcnt;
	int rc;

	param = kmem_zalloc(sizeof (smb_rw_param_t), KM_SLEEP);
	sr->arg.rw = param;
	param->rw_magic = SMB_RW_MAGIC;

	rc = smbsr_decode_vwv(sr, "wwlw", &sr->smb_fid, &count, &off, &remcnt);

	param->rw_count = (uint32_t)count;
	param->rw_offset = (uint64_t)off;

	DTRACE_SMB_2(op__WriteAndUnlock__start, smb_request_t *, sr,
	    smb_rw_param_t *, param);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_write_and_unlock(smb_request_t *sr)
{
	DTRACE_SMB_2(op__WriteAndUnlock__done, smb_request_t *, sr,
	    smb_rw_param_t *, sr->arg.rw);

	kmem_free(sr->arg.rw, sizeof (smb_rw_param_t));
}

smb_sdrc_t
smb_com_write_and_unlock(smb_request_t *sr)
{
	smb_rw_param_t *param = sr->arg.rw;
	uint32_t status;
	int rc = 0;

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

	if (param->rw_count == 0) {
		rc = smbsr_encode_result(sr, 1, 0, "bww", 1, 0, 0);
		return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
	}


	rc = smbsr_decode_data(sr, "D", &param->rw_vdb);

	if ((rc != 0) || (param->rw_count != param->rw_vdb.vdb_len)) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERROR_INVALID_PARAMETER);
		return (SDRC_ERROR);
	}

	param->rw_vdb.vdb_uio.uio_loffset = (offset_t)param->rw_offset;

	if ((rc = smb_write_common(sr, param)) != 0) {
		if (sr->smb_error.status != NT_STATUS_FILE_LOCK_CONFLICT)
			smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	status = smb_unlock_range(sr, sr->fid_ofile->f_node, param->rw_offset,
	    (uint64_t)param->rw_count);
	if (status != NT_STATUS_SUCCESS) {
		smbsr_error(sr, NT_STATUS_RANGE_NOT_LOCKED,
		    ERRDOS, ERRnotlocked);
		return (SDRC_ERROR);
	}

	rc = smbsr_encode_result(sr, 1, 0, "bww", 1,
	    (uint16_t)param->rw_count, 0);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * Write bytes to a file (SMB Core).  This request was extended in
 * LM 0.12 to support 64-bit offsets, indicated by sending a wct of
 * 14, instead of 12, and including additional offset information.
 *
 * A ByteCount of 0 does not truncate the file - use SMB_COM_WRITE
 * to truncate a file.  A zero length merely transfers zero bytes.
 *
 * If bit 0 of WriteMode is set, Fid must refer to a disk file and
 * the data must be on stable storage before responding.
 *
 * MS-SMB 3.3.5.8 update to LM 0.12 4.2.5:
 * If CAP_LARGE_WRITEX is set, the byte count may be larger than the
 * negotiated buffer size and the server is expected to write the
 * number of bytes specified.
 */
smb_sdrc_t
smb_pre_write_andx(smb_request_t *sr)
{
	smb_rw_param_t *param;
	uint32_t off_low;
	uint32_t off_high;
	uint16_t datalen_low;
	uint16_t datalen_high;
	uint16_t remcnt;
	int rc;

	param = kmem_zalloc(sizeof (smb_rw_param_t), KM_SLEEP);
	sr->arg.rw = param;
	param->rw_magic = SMB_RW_MAGIC;

	if (sr->smb_wct == 14) {
		rc = smbsr_decode_vwv(sr, "4.wl4.wwwwwl", &sr->smb_fid,
		    &off_low, &param->rw_mode, &remcnt, &datalen_high,
		    &datalen_low, &param->rw_dsoff, &off_high);

		param->rw_dsoff -= 63;
		param->rw_offset = ((uint64_t)off_high << 32) | off_low;
	} else {
		rc = smbsr_decode_vwv(sr, "4.wl4.wwwww", &sr->smb_fid,
		    &off_low, &param->rw_mode, &remcnt, &datalen_high,
		    &datalen_low, &param->rw_dsoff);

		param->rw_offset = (uint64_t)off_low;
		param->rw_dsoff -= 59;
	}

	param->rw_count = ((uint32_t)datalen_high << 16) |
	    (uint32_t)datalen_low;

	DTRACE_SMB_2(op__WriteX__start, smb_request_t *, sr,
	    smb_rw_param_t *, param);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_write_andx(smb_request_t *sr)
{
	DTRACE_SMB_2(op__WriteX__done, smb_request_t *, sr,
	    smb_rw_param_t *, sr->arg.rw);

	kmem_free(sr->arg.rw, sizeof (smb_rw_param_t));
}

smb_sdrc_t
smb_com_write_andx(smb_request_t *sr)
{
	smb_rw_param_t *param = sr->arg.rw;
	uint16_t count_high;
	uint16_t count_low;
	int rc;

	ASSERT(param);
	ASSERT(param->rw_magic == SMB_RW_MAGIC);

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	sr->user_cr = smb_ofile_getcred(sr->fid_ofile);

	if (SMB_WRMODE_IS_STABLE(param->rw_mode) &&
	    STYPE_ISDSK(sr->tid_tree->t_res_type) == 0) {
		smbsr_error(sr, 0, ERRSRV, ERRaccess);
		return (SDRC_ERROR);
	}

	sr->smb_data.max_bytes = SMB_WRITEX_MAX;
	rc = smbsr_decode_data(sr, "#.#B", param->rw_dsoff, param->rw_count,
	    &param->rw_vdb);

	if ((rc != 0) || (param->rw_vdb.vdb_len != param->rw_count)) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERROR_INVALID_PARAMETER);
		return (SDRC_ERROR);
	}

	param->rw_vdb.vdb_uio.uio_loffset = (offset_t)param->rw_offset;

	if (param->rw_count != 0) {
		if ((rc = smb_write_common(sr, param)) != 0) {
			if (sr->smb_error.status !=
			    NT_STATUS_FILE_LOCK_CONFLICT)
				smbsr_errno(sr, rc);
			return (SDRC_ERROR);
		}
	}

	count_low = param->rw_count & 0xFFFF;
	count_high = (param->rw_count >> 16) & 0xFF;

	rc = smbsr_encode_result(sr, 6, 0, "bb1.wwwwww",
	    6, sr->andx_com, 15, count_low, 0, count_high, 0, 0);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * Common function for writing files or IPC/MSRPC named pipes.
 *
 * Returns errno values.
 */
static int
smb_write_common(smb_request_t *sr, smb_rw_param_t *param)
{
	struct smb_ofile *ofile = sr->fid_ofile;
	smb_node_t *node;
	int stability = 0;
	uint32_t lcount;
	int rc = 0;

	switch (sr->tid_tree->t_res_type & STYPE_MASK) {
	case STYPE_DISKTREE:
		node = ofile->f_node;

		if (node->attr.sa_vattr.va_type != VDIR) {
			rc = smb_lock_range_access(sr, node, param->rw_offset,
			    param->rw_count, B_TRUE);
			if (rc != NT_STATUS_SUCCESS) {
				smbsr_error(sr, NT_STATUS_FILE_LOCK_CONFLICT,
				    ERRDOS, ERROR_LOCK_VIOLATION);
				return (EACCES);
			}
		}

		if (SMB_WRMODE_IS_STABLE(param->rw_mode) ||
		    (node->flags & NODE_FLAGS_WRITE_THROUGH)) {
			stability = FSYNC;
		}

		rc = smb_fsop_write(sr, sr->user_cr, node,
		    &param->rw_vdb.vdb_uio, &lcount, &node->attr, stability);

		if (rc)
			return (rc);

		node->flags |= NODE_FLAGS_SYNCATIME;

		if (node->flags & NODE_FLAGS_SET_SIZE) {
			if ((param->rw_offset + lcount) >= node->n_size) {
				node->flags &= ~NODE_FLAGS_SET_SIZE;
				node->n_size = param->rw_offset + lcount;
			}
		}

		param->rw_count = lcount;
		break;

	case STYPE_IPC:
		param->rw_count = param->rw_vdb.vdb_uio.uio_resid;

		if ((rc = smb_opipe_write(sr, &param->rw_vdb.vdb_uio)) != 0)
			param->rw_count = 0;
		break;

	default:
		rc = EACCES;
		break;
	}

	if (rc != 0)
		return (rc);

	mutex_enter(&ofile->f_mutex);
	ofile->f_seek_pos = param->rw_offset + param->rw_count;
	mutex_exit(&ofile->f_mutex);
	return (rc);
}

/*
 * Truncate a disk file to the specified offset.
 * Typically, w_count will be zero here.
 *
 * Returns errno values.
 */
static int
smb_write_truncate(smb_request_t *sr, smb_rw_param_t *param)
{
	struct smb_ofile *ofile = sr->fid_ofile;
	smb_node_t *node = ofile->f_node;
	boolean_t append_only = B_FALSE;
	uint32_t status;
	int rc;

	if (STYPE_ISDSK(sr->tid_tree->t_res_type) == 0)
		return (0);

	status = smb_ofile_access(sr->fid_ofile, sr->user_cr, FILE_WRITE_DATA);
	if (status != NT_STATUS_SUCCESS) {
		status = smb_ofile_access(sr->fid_ofile, sr->user_cr,
		    FILE_APPEND_DATA);
		if (status != NT_STATUS_SUCCESS)
			return (EACCES);
		else
			append_only = B_TRUE;
	}

	mutex_enter(&node->n_mutex);

	if (append_only && (param->rw_offset < node->n_size)) {
		mutex_exit(&node->n_mutex);
		return (EACCES);
	}

	if (node->attr.sa_vattr.va_type != VDIR) {
		status = smb_lock_range_access(sr, node, param->rw_offset,
		    param->rw_count, B_TRUE);
		if (status != NT_STATUS_SUCCESS) {
			mutex_exit(&node->n_mutex);
			smbsr_error(sr, NT_STATUS_FILE_LOCK_CONFLICT,
			    ERRDOS, ERROR_LOCK_VIOLATION);
			return (EACCES);
		}
	}

	node->flags |= NODE_FLAGS_SET_SIZE;
	node->n_size = param->rw_offset;

	mutex_exit(&node->n_mutex);

	if ((rc = smb_set_file_size(sr, node)) != 0)
		return (rc);

	mutex_enter(&ofile->f_mutex);
	ofile->f_seek_pos = param->rw_offset + param->rw_count;
	mutex_exit(&ofile->f_mutex);
	return (0);
}

/*
 * Set the file size using the value in the node. The file will only be
 * updated if NODE_FLAGS_SET_SIZE is set.  It is safe to pass a null node
 * pointer, we just return success.
 *
 * The node attributes are refreshed here from the file system. So any
 * attributes that are affected by file size changes, i.e. the mtime,
 * will be current.
 *
 * Note that smb_write_andx cannot be used to reduce the file size so,
 * if this is required, smb_write is called with a count of zero and
 * the appropriate file length in offset. The file should be resized
 * to the length specified by the offset.
 */
int
smb_set_file_size(smb_request_t *sr, smb_node_t *node)
{
	smb_attr_t new_attr;

	if (node == NULL)
		return (0);

	if ((node->flags & NODE_FLAGS_SET_SIZE) == 0)
		return (0);

	node->flags &= ~NODE_FLAGS_SET_SIZE;

	bzero(&new_attr, sizeof (new_attr));
	new_attr.sa_vattr.va_size = node->n_size;
	new_attr.sa_mask = SMB_AT_SIZE;

	return (smb_fsop_setattr(sr, sr->user_cr, node, &new_attr,
	    &node->attr));
}
