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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * This command is used to create or open a file or directory, when EAs
 * or an SD must be applied to the file. The functionality is similar
 * to SmbNtCreateAndx with the option to supply extended attributes or
 * a security descriptor.
 *
 * Note: we don't decode the extended attributes because we don't
 * support them at this time.
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>

/*
 * smb_nt_transact_create
 *
 * This command is used to create or open a file or directory, when EAs
 * or an SD must be applied to the file. The request parameter block
 * encoding, data block encoding and output parameter block encoding are
 * described in CIFS section 4.2.2.
 *
 * The format of the command is SmbNtTransact but it is basically the same
 * as SmbNtCreateAndx with the option to supply extended attributes or a
 * security descriptor. For information not defined in CIFS section 4.2.2
 * see section 4.2.1 (NT_CREATE_ANDX).
 */
smb_sdrc_t
smb_pre_nt_transact_create(smb_request_t *sr, smb_xa_t *xa)
{
	struct open_param *op = &sr->arg.open;
	uint8_t SecurityFlags;
	uint32_t EaLength;
	uint32_t ImpersonationLevel;
	uint32_t NameLength;
	uint32_t sd_len;
	uint32_t status;
	smb_sd_t sd;
	int rc;

	bzero(op, sizeof (sr->arg.open));

	rc = smb_mbc_decodef(&xa->req_param_mb, "%lllqllllllllb",
	    sr,
	    &op->nt_flags,
	    &op->rootdirfid,
	    &op->desired_access,
	    &op->dsize,
	    &op->dattr,
	    &op->share_access,
	    &op->create_disposition,
	    &op->create_options,
	    &sd_len,
	    &EaLength,
	    &NameLength,
	    &ImpersonationLevel,
	    &SecurityFlags);

	if (rc == 0) {
		if (NameLength == 0) {
			op->fqi.fq_path.pn_path = "\\";
		} else if (NameLength >= MAXPATHLEN) {
			smbsr_error(sr, NT_STATUS_OBJECT_PATH_NOT_FOUND,
			    ERRDOS, ERROR_PATH_NOT_FOUND);
			rc = -1;
		} else {
			rc = smb_mbc_decodef(&xa->req_param_mb, "%#u",
			    sr, NameLength, &op->fqi.fq_path.pn_path);
		}
	}

	op->op_oplock_level = SMB_OPLOCK_NONE;
	if (op->nt_flags & NT_CREATE_FLAG_REQUEST_OPLOCK) {
		if (op->nt_flags & NT_CREATE_FLAG_REQUEST_OPBATCH)
			op->op_oplock_level = SMB_OPLOCK_BATCH;
		else
			op->op_oplock_level = SMB_OPLOCK_EXCLUSIVE;
	}

	if (sd_len) {
		status = smb_decode_sd(&xa->req_data_mb, &sd);
		if (status != NT_STATUS_SUCCESS) {
			smbsr_error(sr, status, 0, 0);
			return (SDRC_ERROR);
		}
		op->sd = kmem_alloc(sizeof (smb_sd_t), KM_SLEEP);
		*op->sd = sd;
	} else {
		op->sd = NULL;
	}

	DTRACE_SMB_2(op__NtTransactCreate__start, smb_request_t *, sr,
	    struct open_param *, op);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_nt_transact_create(smb_request_t *sr, smb_xa_t *xa)
{
	smb_sd_t *sd = sr->arg.open.sd;

	DTRACE_SMB_2(op__NtTransactCreate__done, smb_request_t *, sr,
	    smb_xa_t *, xa);

	if (sd) {
		smb_sd_term(sd);
		kmem_free(sd, sizeof (smb_sd_t));
	}

	if (sr->arg.open.dir != NULL)
		smb_ofile_release(sr->arg.open.dir);
}

smb_sdrc_t
smb_nt_transact_create(smb_request_t *sr, smb_xa_t *xa)
{
	struct open_param *op = &sr->arg.open;
	uint8_t			DirFlag;
	smb_attr_t		attr;
	smb_ofile_t		*of;
	uint32_t		status;
	int			rc;

	if ((op->create_options & FILE_DELETE_ON_CLOSE) &&
	    !(op->desired_access & DELETE)) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERRbadaccess);
		return (SDRC_ERROR);
	}

	if (op->create_disposition > FILE_MAXIMUM_DISPOSITION) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERRbadaccess);
		return (SDRC_ERROR);
	}

	if (op->dattr & FILE_FLAG_WRITE_THROUGH)
		op->create_options |= FILE_WRITE_THROUGH;

	if (op->dattr & FILE_FLAG_DELETE_ON_CLOSE)
		op->create_options |= FILE_DELETE_ON_CLOSE;

	if (op->dattr & FILE_FLAG_BACKUP_SEMANTICS)
		op->create_options |= FILE_OPEN_FOR_BACKUP_INTENT;

	if (op->create_options & FILE_OPEN_FOR_BACKUP_INTENT)
		sr->user_cr = smb_user_getprivcred(sr->uid_user);

	if (op->rootdirfid == 0) {
		op->fqi.fq_dnode = sr->tid_tree->t_snode;
	} else {
		op->dir = smb_ofile_lookup_by_fid(sr, (uint16_t)op->rootdirfid);
		if (op->dir == NULL) {
			smbsr_error(sr, NT_STATUS_INVALID_HANDLE,
			    ERRDOS, ERRbadfid);
			return (SDRC_ERROR);
		}
		op->fqi.fq_dnode = op->dir->f_node;
	}

	op->op_oplock_levelII = B_TRUE;

	status = smb_common_open(sr);
	if (status != NT_STATUS_SUCCESS) {
		smbsr_status(sr, status, 0, 0);
		return (SDRC_ERROR);
	}

	/*
	 * NB: after the above smb_common_open() success,
	 * we have a handle allocated (sr->fid_ofile).
	 * If we don't return success, we must close it.
	 */
	of = sr->fid_ofile;

	switch (sr->tid_tree->t_res_type & STYPE_MASK) {
	case STYPE_DISKTREE:
	case STYPE_PRINTQ:
		if (op->create_options & FILE_DELETE_ON_CLOSE)
			smb_ofile_set_delete_on_close(of);

		DirFlag = smb_node_is_dir(of->f_node) ? 1 : 0;
		bzero(&attr, sizeof (attr));
		attr.sa_mask = SMB_AT_ALL;
		rc = smb_node_getattr(sr, of->f_node, of->f_cr, of, &attr);
		if (rc != 0) {
			smbsr_errno(sr, rc);
			goto errout;
		}

		rc = smb_mbc_encodef(&xa->rep_param_mb, "b.wllTTTTlqqwwb",
		    op->op_oplock_level,
		    sr->smb_fid,
		    op->action_taken,
		    0,	/* EaErrorOffset */
		    &attr.sa_crtime,
		    &attr.sa_vattr.va_atime,
		    &attr.sa_vattr.va_mtime,
		    &attr.sa_vattr.va_ctime,
		    op->dattr & FILE_ATTRIBUTE_MASK,
		    attr.sa_allocsz,
		    attr.sa_vattr.va_size,
		    op->ftype,
		    op->devstate,
		    DirFlag);
		break;

	case STYPE_IPC:
		bzero(&attr, sizeof (smb_attr_t));
		rc = smb_mbc_encodef(&xa->rep_param_mb, "b.wllTTTTlqqwwb",
		    0,
		    sr->smb_fid,
		    op->action_taken,
		    0,	/* EaErrorOffset */
		    &attr.sa_crtime,
		    &attr.sa_vattr.va_atime,
		    &attr.sa_vattr.va_mtime,
		    &attr.sa_vattr.va_ctime,
		    op->dattr,
		    0x1000LL,
		    0LL,
		    op->ftype,
		    op->devstate,
		    0);
		break;

	default:
		smbsr_error(sr, NT_STATUS_INVALID_DEVICE_REQUEST,
		    ERRDOS, ERROR_INVALID_FUNCTION);
		goto errout;
	}
	return (SDRC_SUCCESS);

errout:
	smb_ofile_close(of, 0);
	return (SDRC_ERROR);
}
