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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * SMB print interface.
 */

#include <smbsrv/smb_kproto.h>

/*
 * Create a new printer file, which should be deleted automatically once
 * it has been closed and printed.
 *
 * SetupLength is the number of bytes in the first part of the resulting
 * print spool file which contains printer-specific control strings.
 *
 * Mode can have the following values:
 *      0     Text mode.  The server may optionally
 *            expand tabs to a series of spaces.
 *      1     Graphics mode.  No conversion of data
 *            should be done by the server.
 *
 * IdentifierString can be used by the server to provide some sort of
 * per-client identifying component to the print file.
 *
 * When the file is closed, it will be sent to the spooler and printed.
 */
smb_sdrc_t
smb_pre_open_print_file(smb_request_t *sr)
{
	static uint32_t		tmp_id = 10000;
	struct open_param	*op = &sr->arg.open;
	char			*path;
	char			*identifier;
	uint16_t		setup;
	uint16_t		mode;
	int			rc;

	bzero(op, sizeof (sr->arg.open));

	rc = smbsr_decode_vwv(sr, "ww", &setup, &mode);
	if (rc == 0)
		rc = smbsr_decode_data(sr, "%S", sr, &identifier);

	atomic_inc_32(&tmp_id);

	path = smb_srm_alloc(sr, MAXPATHLEN);
	(void) snprintf(path, MAXPATHLEN, "%s%05u", identifier, tmp_id);
	op->fqi.fq_path.pn_path = path;

	op->create_disposition = FILE_OVERWRITE_IF;
	op->create_options = FILE_NON_DIRECTORY_FILE;

	DTRACE_SMB_2(op__OpenPrintFile__start, smb_request_t *, sr,
	    struct open_param *, op);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_open_print_file(smb_request_t *sr)
{
	DTRACE_SMB_1(op__OpenPrintFile__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_open_print_file(smb_request_t *sr)
{
	int rc;

	if (!STYPE_ISPRN(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_BAD_DEVICE_TYPE,
		    ERRDOS, ERROR_BAD_DEV_TYPE);
		return (SDRC_ERROR);
	}

	if (smb_common_create(sr) != NT_STATUS_SUCCESS)
		return (SDRC_ERROR);

	rc = smbsr_encode_result(sr, 1, 0, "bww", 1, sr->smb_fid, 0);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * Close the specified file handle and queue the file for printing.
 * The fid refers to a file previously created as a print spool file.
 * On successful completion of this request, the file is queued for
 * printing by the server.
 *
 * Servers that negotiate LANMAN1.0 or later allow all the the fid
 * to be closed and printed via any close request.
 */
smb_sdrc_t
smb_pre_close_print_file(smb_request_t *sr)
{
	int rc;

	rc = smbsr_decode_vwv(sr, "w", &sr->smb_fid);

	DTRACE_SMB_1(op__ClosePrintFile__start, smb_request_t *, sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_close_print_file(smb_request_t *sr)
{
	DTRACE_SMB_1(op__ClosePrintFile__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_close_print_file(smb_request_t *sr)
{
	if (!STYPE_ISPRN(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_BAD_DEVICE_TYPE,
		    ERRDOS, ERROR_BAD_DEV_TYPE);
		return (SDRC_ERROR);
	}

	return (smb_com_close(sr));
}

/*
 * Get a list of print queue entries on the server.  Support for
 * this request is optional (not required for Windows clients).
 */
smb_sdrc_t
smb_pre_get_print_queue(smb_request_t *sr)
{
	DTRACE_SMB_1(op__GetPrintQueue__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_get_print_queue(smb_request_t *sr)
{
	DTRACE_SMB_1(op__GetPrintQueue__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_get_print_queue(smb_request_t *sr)
{
	unsigned short max_count, start_ix;

	if (smbsr_decode_vwv(sr, "ww", &max_count, &start_ix) != 0)
		return (SDRC_ERROR);

	if (smbsr_encode_result(sr, 2, 3, "bwwwbw", 2, 0, 0, 3, 1, 0))
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}

/*
 * Write (append) data to a print spool file.  The fid must refer to
 * a print spool file.
 *
 * The first SetupLength bytes (see SMB_COM_OPEN_PRINT_FILE) in the
 * print spool file contain printer setup data.
 *
 * Servers that negotiate LANMAN1.0 or later also support the use of
 * normal write requests with print spool files.
 */
smb_sdrc_t
smb_pre_write_print_file(smb_request_t *sr)
{
	smb_rw_param_t	*param;
	int		rc;

	param = kmem_zalloc(sizeof (smb_rw_param_t), KM_SLEEP);
	sr->arg.rw = param;
	param->rw_magic = SMB_RW_MAGIC;

	rc = smbsr_decode_vwv(sr, "w", &sr->smb_fid);

	DTRACE_SMB_1(op__WritePrintFile__start, smb_request_t *, sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_write_print_file(smb_request_t *sr)
{
	DTRACE_SMB_1(op__WritePrintFile__done, smb_request_t *, sr);

	kmem_free(sr->arg.rw, sizeof (smb_rw_param_t));
}

smb_sdrc_t
smb_com_write_print_file(smb_request_t *sr)
{
	smb_rw_param_t	*param = sr->arg.rw;
	smb_node_t	*node;
	smb_attr_t	attr;
	int		rc;

	if (!STYPE_ISPRN(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_BAD_DEVICE_TYPE,
		    ERRDOS, ERROR_BAD_DEV_TYPE);
		return (SDRC_ERROR);
	}

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	node = sr->fid_ofile->f_node;
	sr->user_cr = smb_ofile_getcred(sr->fid_ofile);

	if (smb_node_getattr(sr, node, &attr) != 0) {
		smbsr_error(sr, NT_STATUS_INTERNAL_ERROR,
		    ERRDOS, ERROR_INTERNAL_ERROR);
		return (SDRC_ERROR);
	}

	if ((smbsr_decode_data(sr, "D", &param->rw_vdb)) != 0) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERROR_INVALID_PARAMETER);
		return (SDRC_ERROR);
	}

	param->rw_count = param->rw_vdb.vdb_len;
	param->rw_offset = attr.sa_vattr.va_size;
	param->rw_vdb.vdb_uio.uio_loffset = (offset_t)param->rw_offset;

	if ((rc = smb_common_write(sr, param)) != 0) {
		if (sr->smb_error.status != NT_STATUS_FILE_LOCK_CONFLICT)
			smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	rc = smbsr_encode_empty_result(sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}
