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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/winioctl.h>


static uint32_t smb_nt_trans_ioctl_noop(smb_request_t *, smb_xa_t *);
static uint32_t smb_nt_trans_ioctl_invalid_parm(smb_request_t *, smb_xa_t *);
static uint32_t smb_nt_trans_ioctl_set_sparse(smb_request_t *, smb_xa_t *);
static uint32_t smb_nt_trans_ioctl_query_alloc_ranges(smb_request_t *,
    smb_xa_t *);
static uint32_t smb_nt_trans_ioctl_set_zero_data(smb_request_t *, smb_xa_t *);
static uint32_t smb_nt_trans_ioctl_enum_snaps(smb_request_t *, smb_xa_t *);

/*
 * This table defines the list of FSCTL values for which we'll
 * call a funtion to perform specific processing.
 *
 * Note: If support is added for FSCTL_SET_ZERO_DATA, it must break
 * any oplocks on the file to none:
 *   smb_oplock_break(sr, node, SMB_OPLOCK_BREAK_TO_NONE);
 */
static const struct {
	uint32_t fcode;
	uint32_t (*ioctl_func)(smb_request_t *sr, smb_xa_t *xa);
} ioctl_ret_tbl[] = {
	{ FSCTL_GET_OBJECT_ID, smb_nt_trans_ioctl_invalid_parm },
	{ FSCTL_QUERY_ALLOCATED_RANGES, smb_nt_trans_ioctl_query_alloc_ranges },
	{ FSCTL_SET_ZERO_DATA, smb_nt_trans_ioctl_set_zero_data },
	{ FSCTL_SRV_ENUMERATE_SNAPSHOTS, smb_nt_trans_ioctl_enum_snaps },
	{ FSCTL_SET_SPARSE, smb_nt_trans_ioctl_set_sparse },
	{ FSCTL_FIND_FILES_BY_SID, smb_nt_trans_ioctl_noop }
};

/*
 * smb_nt_transact_ioctl
 *
 * This command allows device and file system control functions to be
 * transferred transparently from client to server.
 *
 * Setup Words Encoding        Description
 * =========================== =========================================
 * ULONG FunctionCode;         NT device or file system control code
 * USHORT Fid;                 Handle for io or fs control. Unless BIT0
 *                             of ISFLAGS is set.
 * BOOLEAN IsFsctl;            Indicates whether the command is a device
 *                             control (FALSE) or a file system control
 *                             (TRUE).
 * UCHAR   IsFlags;            BIT0 - command is to be applied to share
 *                             root handle. Share must be a DFS share.
 *
 * Data Block Encoding         Description
 * =========================== =========================================
 * Data[ TotalDataCount ]      Passed to the Fsctl or Ioctl
 *
 * Server Response             Description
 * =========================== ==================================
 * SetupCount                  1
 * Setup[0]                    Length of information returned by
 *                             io or fs control.
 * DataCount                   Length of information returned by
 *                             io or fs control.
 * Data[ DataCount ]           The results of the io or fs control.
 */
smb_sdrc_t
smb_nt_transact_ioctl(smb_request_t *sr, smb_xa_t *xa)
{
	uint32_t status = NT_STATUS_NOT_SUPPORTED;
	uint32_t fcode;
	unsigned char is_fsctl;
	unsigned char is_flags;
	int i;

	if (smb_mbc_decodef(&xa->req_setup_mb, "lwbb",
	    &fcode, &sr->smb_fid, &is_fsctl, &is_flags) != 0) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER, 0, 0);
		return (SDRC_ERROR);
	}

	/*
	 * Invoke handler if specified, otherwise the default
	 * behavior is to return NT_STATUS_NOT_SUPPORTED
	 */
	for (i = 0; i < sizeof (ioctl_ret_tbl) / sizeof (ioctl_ret_tbl[0]);
	    i++) {
		if (ioctl_ret_tbl[i].fcode == fcode) {
			status = ioctl_ret_tbl[i].ioctl_func(sr, xa);
			break;
		}
	}

	if (status != NT_STATUS_SUCCESS) {
		smbsr_error(sr, status, 0, 0);
		return (SDRC_ERROR);
	}

	(void) smb_mbc_encodef(&xa->rep_param_mb, "l", 0);
	return (SDRC_SUCCESS);
}

/* ARGSUSED */
static uint32_t
smb_nt_trans_ioctl_noop(smb_request_t *sr, smb_xa_t *xa)
{
	return (NT_STATUS_SUCCESS);
}

/* ARGSUSED */
static uint32_t
smb_nt_trans_ioctl_invalid_parm(smb_request_t *sr, smb_xa_t *xa)
{
	return (NT_STATUS_INVALID_PARAMETER);
}

/*
 * smb_nt_trans_ioctl_set_sparse
 *
 * There may, or may not be a data block in this request.
 * If there IS a data block, the first byte is a boolean
 * specifying whether to set (non zero) or clear (zero)
 * the sparse attribute of the file.
 * If there is no data block, this indicates a request to
 * set the sparse attribute.
 */
static uint32_t
smb_nt_trans_ioctl_set_sparse(smb_request_t *sr, smb_xa_t *xa)
{
	int		rc = 0;
	uint8_t		set = 1;
	smb_ofile_t	*of;
	smb_attr_t	attr;

	if (SMB_TREE_IS_READONLY(sr))
		return (NT_STATUS_ACCESS_DENIED);

	if (STYPE_ISIPC(sr->tid_tree->t_res_type))
		return (NT_STATUS_INVALID_PARAMETER);

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL)
		return (NT_STATUS_INVALID_HANDLE);

	if (!SMB_FTYPE_IS_DISK(sr->fid_ofile->f_ftype)) {
		smbsr_release_file(sr);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	of = sr->fid_ofile;
	if (smb_node_is_dir(of->f_node)) {
		smbsr_release_file(sr);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (smbsr_decode_data_avail(sr)) {
		if (smb_mbc_decodef(&xa->req_data_mb, "b", &set) != 0) {
			smbsr_release_file(sr);
			return (sr->smb_error.status);
		}
	}

	/*
	 * Using kcred because we just want the DOS attrs
	 * and don't want access errors for this.
	 */
	bzero(&attr, sizeof (smb_attr_t));
	attr.sa_mask = SMB_AT_DOSATTR;
	rc = smb_node_getattr(sr, of->f_node, zone_kcred(), of, &attr);
	if (rc != 0) {
		smbsr_errno(sr, rc);
		smbsr_release_file(sr);
		return (sr->smb_error.status);
	}

	attr.sa_mask = 0;
	if ((set == 0) &&
	    (attr.sa_dosattr & FILE_ATTRIBUTE_SPARSE_FILE)) {
		attr.sa_dosattr &= ~FILE_ATTRIBUTE_SPARSE_FILE;
		attr.sa_mask = SMB_AT_DOSATTR;
	} else if ((set != 0) &&
	    !(attr.sa_dosattr & FILE_ATTRIBUTE_SPARSE_FILE)) {
		attr.sa_dosattr |= FILE_ATTRIBUTE_SPARSE_FILE;
		attr.sa_mask = SMB_AT_DOSATTR;
	}

	if (attr.sa_mask != 0) {
		rc = smb_node_setattr(sr, of->f_node, of->f_cr, of, &attr);
		if (rc != 0) {
			smbsr_errno(sr, rc);
			smbsr_release_file(sr);
			return (sr->smb_error.status);
		}
	}

	smbsr_release_file(sr);
	return (NT_STATUS_SUCCESS);
}

/*
 * smb_nt_trans_ioctl_set_zero_data
 *
 * Check that the request is valid on the specified file.
 * The implementation is a noop.
 */
/* ARGSUSED */
static uint32_t
smb_nt_trans_ioctl_set_zero_data(smb_request_t *sr, smb_xa_t *xa)
{
	smb_node_t *node;

	if (SMB_TREE_IS_READONLY(sr))
		return (NT_STATUS_ACCESS_DENIED);

	if (STYPE_ISIPC(sr->tid_tree->t_res_type))
		return (NT_STATUS_INVALID_PARAMETER);

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL)
		return (NT_STATUS_INVALID_HANDLE);

	if (!SMB_FTYPE_IS_DISK(sr->fid_ofile->f_ftype)) {
		smbsr_release_file(sr);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	node = sr->fid_ofile->f_node;
	if (smb_node_is_dir(node)) {
		smbsr_release_file(sr);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	smbsr_release_file(sr);
	return (NT_STATUS_SUCCESS);
}

/*
 * smb_nt_trans_ioctl_query_alloc_ranges
 *
 * Responds with either:
 * - no data if the file is zero size
 * - a single range containing the starting point and length requested
 */
static uint32_t
smb_nt_trans_ioctl_query_alloc_ranges(smb_request_t *sr, smb_xa_t *xa)
{
	int		rc;
	uint64_t	offset, len;
	smb_ofile_t	*of;
	smb_attr_t	attr;

	if (STYPE_ISIPC(sr->tid_tree->t_res_type))
		return (NT_STATUS_INVALID_PARAMETER);

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL)
		return (NT_STATUS_INVALID_HANDLE);

	if (!SMB_FTYPE_IS_DISK(sr->fid_ofile->f_ftype)) {
		smbsr_release_file(sr);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	of = sr->fid_ofile;
	if (smb_node_is_dir(of->f_node)) {
		smbsr_release_file(sr);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	/* If zero size file don't return any data */
	bzero(&attr, sizeof (smb_attr_t));
	attr.sa_mask = SMB_AT_SIZE;
	rc = smb_node_getattr(sr, of->f_node, of->f_cr, of, &attr);
	if (rc != 0) {
		smbsr_errno(sr, rc);
		smbsr_release_file(sr);
		return (sr->smb_error.status);
	}

	if (attr.sa_vattr.va_size == 0) {
		smbsr_release_file(sr);
		return (NT_STATUS_SUCCESS);
	}

	if (smb_mbc_decodef(&xa->req_data_mb, "qq", &offset, &len) != 0) {
		smbsr_release_file(sr);
		return (sr->smb_error.status);
	}

	/*
	 * Return a single range regardless of whether the file
	 * is sparse or not.
	 */
	if (MBC_ROOM_FOR(&xa->rep_data_mb, 16) == 0) {
		smbsr_release_file(sr);
		return (NT_STATUS_BUFFER_TOO_SMALL);
	}

	if (smb_mbc_encodef(&xa->rep_data_mb, "qq", offset, len) != 0) {
		smbsr_release_file(sr);
		return (sr->smb_error.status);
	}

	smbsr_release_file(sr);
	return (NT_STATUS_SUCCESS);
}

static uint32_t
smb_nt_trans_ioctl_enum_snaps(smb_request_t *sr, smb_xa_t *xa)
{
	smb_fsctl_t fsctl;
	uint32_t status;

	if (STYPE_ISIPC(sr->tid_tree->t_res_type))
		return (NT_STATUS_INVALID_PARAMETER);

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL)
		return (NT_STATUS_INVALID_HANDLE);

	if (!SMB_FTYPE_IS_DISK(sr->fid_ofile->f_ftype)) {
		smbsr_release_file(sr);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	fsctl.CtlCode = FSCTL_SRV_ENUMERATE_SNAPSHOTS;
	fsctl.InputCount = xa->smb_tpscnt;
	fsctl.OutputCount = 0;
	fsctl.MaxOutputResp = xa->smb_mdrcnt;
	fsctl.in_mbc = &xa->req_param_mb;
	fsctl.out_mbc = &xa->rep_data_mb;

	status = smb_vss_enum_snapshots(sr, &fsctl);

	smbsr_release_file(sr);
	return (status);
}
