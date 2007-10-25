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

#include <smbsrv/smb_incl.h>

#define	SMB_CREATE_NAMEBUF_SZ	16

static uint32_t smb_common_create(struct smb_request *sr);

/*
 * Create a new file, or truncate an existing file to zero length,
 * open the file and return a fid.  The file is specified using a
 * fully qualified name relative to the tree.
 */
int
smb_com_create(struct smb_request *sr)
{
	struct open_param *op = &sr->arg.open;
	uint32_t status;

	bzero(op, sizeof (sr->arg.open));

	if (smbsr_decode_vwv(sr, "wl", &op->dattr, &op->utime.tv_sec) != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	if (smbsr_decode_data(sr, "%S", sr, &op->fqi.path) != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	op->create_disposition = FILE_OVERWRITE_IF;
	status = smb_common_create(sr);

	switch (status) {
	case NT_STATUS_SUCCESS:
		break;

	case NT_STATUS_SHARING_VIOLATION:
		smbsr_raise_cifs_error(sr, NT_STATUS_SHARING_VIOLATION,
		    ERRDOS, ERROR_SHARING_VIOLATION);
		/* NOTREACHED */
		break;

	default:
		smbsr_raise_nt_error(sr, status);
		/* NOTREACHED */
		break;
	}

	smbsr_encode_result(sr, 1, 0, "bww", 1, sr->smb_fid, 0);
	return (SDRC_NORMAL_REPLY);
}

/*
 * Create a new file and return a fid.  The file is specified using
 * a fully qualified name relative to the tree.
 */
int
smb_com_create_new(struct smb_request *sr)
{
	struct open_param *op = &sr->arg.open;
	uint32_t status;

	bzero(op, sizeof (sr->arg.open));

	if (smbsr_decode_vwv(sr, "wl", &op->dattr, &op->utime.tv_sec) != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	if (smbsr_decode_data(sr, "%S", sr, &op->fqi.path) != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	op->create_disposition = FILE_CREATE;
	status = smb_common_create(sr);

	switch (status) {
	case NT_STATUS_SUCCESS:
		break;

	case NT_STATUS_SHARING_VIOLATION:
		smbsr_raise_cifs_error(sr, NT_STATUS_SHARING_VIOLATION,
		    ERRDOS, ERROR_SHARING_VIOLATION);
		/* NOTREACHED */
		break;

	default:
		smbsr_raise_nt_error(sr, status);
		/* NOTREACHED */
		break;
	}

	smbsr_encode_result(sr, 1, 0, "bww", 1, sr->smb_fid, 0);
	return (SDRC_NORMAL_REPLY);
}


/*
 * Create a unique file in the specified directory relative to the
 * current tree.  No attributes are specified.
 */
int
smb_com_create_temporary(struct smb_request *sr)
{
	static uint16_t tmp_id = 10000;
	struct open_param *op = &sr->arg.open;
	char name[SMB_CREATE_NAMEBUF_SZ];
	char *buf;
	uint32_t status;
	uint16_t reserved;
	uint16_t bcc;

	bzero(op, sizeof (sr->arg.open));

	if (smbsr_decode_vwv(sr, "wl", &reserved, &op->utime.tv_sec) != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	if (smbsr_decode_data(sr, "%S", sr, &op->fqi.path) != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	++tmp_id;
	bcc = 1; /* null terminator */
	bcc += snprintf(name, SMB_CREATE_NAMEBUF_SZ, "tt%05d.tmp", tmp_id);

	buf = smbsr_malloc(&sr->request_storage, MAXPATHLEN);
	(void) snprintf(buf, MAXPATHLEN, "%s\\%s", op->fqi.path, name);
	op->fqi.path = buf;
	op->create_disposition = FILE_CREATE;
	status = smb_common_create(sr);

	switch (status) {
	case NT_STATUS_SUCCESS:
		break;

	case NT_STATUS_SHARING_VIOLATION:
		smbsr_raise_cifs_error(sr, NT_STATUS_SHARING_VIOLATION,
		    ERRDOS, ERROR_SHARING_VIOLATION);
		/* NOTREACHED */
		break;

	default:
		smbsr_raise_nt_error(sr, status);
		/* NOTREACHED */
		break;
	}

	smbsr_encode_result(sr, 1, 0, "bwwwbs", 1, sr->smb_fid, bcc, 4, name);
	return (SDRC_NORMAL_REPLY);
}

/*
 * Common create file function.  The file is opened in compatibility
 * mode with read/write access.
 */
uint32_t
smb_common_create(struct smb_request *sr)
{
	struct open_param *op = &sr->arg.open;
	uint32_t status;

	op->utime.tv_sec = smb_local_time_to_gmt(op->utime.tv_sec);
	op->utime.tv_nsec = 0;
	op->omode = SMB_DA_ACCESS_READ_WRITE | SMB_DA_SHARE_COMPATIBILITY;
	op->desired_access = smb_omode_to_amask(op->omode);
	op->share_access = smb_denymode_to_sharemode(op->omode, op->fqi.path);

	if ((op->desired_access == ((uint32_t)SMB_INVALID_AMASK)) ||
	    (op->share_access == ((uint32_t)SMB_INVALID_SHAREMODE))) {
		smbsr_raise_cifs_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERROR_INVALID_PARAMETER);
		/* NOTREACHED */
	}

	op->dsize = 0;

	if (sr->smb_flg & SMB_FLAGS_OPLOCK) {
		if (sr->smb_flg & SMB_FLAGS_OPLOCK_NOTIFY_ANY) {
			op->my_flags = MYF_BATCH_OPLOCK;
		} else {
			op->my_flags = MYF_EXCLUSIVE_OPLOCK;
		}
	}

	status = smb_open_subr(sr);

	if (MYF_OPLOCK_TYPE(op->my_flags) == MYF_OPLOCK_NONE) {
		sr->smb_flg &=
		    ~(SMB_FLAGS_OPLOCK | SMB_FLAGS_OPLOCK_NOTIFY_ANY);
	}

	return (status);
}
