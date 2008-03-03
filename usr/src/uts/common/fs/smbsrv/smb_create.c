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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <smbsrv/smb_incl.h>

#define	SMB_CREATE_NAMEBUF_SZ	16

static uint32_t smb_common_create(smb_request_t *sr);

/*
 * Create a new file, or truncate an existing file to zero length,
 * open the file and return a fid.  The file is specified using a
 * fully qualified name relative to the tree.
 */
smb_sdrc_t
smb_pre_create(smb_request_t *sr)
{
	struct open_param *op = &sr->arg.open;
	int rc;

	bzero(op, sizeof (sr->arg.open));

	rc = smbsr_decode_vwv(sr, "wl", &op->dattr, &op->utime.tv_sec);
	if (rc == 0)
		rc = smbsr_decode_data(sr, "%S", sr, &op->fqi.path);

	op->create_disposition = FILE_OVERWRITE_IF;

	DTRACE_SMB_2(op__Create__start, smb_request_t *, sr,
	    struct open_param *, op);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_create(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Create__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_create(smb_request_t *sr)
{
	if (smb_common_create(sr) != NT_STATUS_SUCCESS)
		return (SDRC_ERROR);

	if (smbsr_encode_result(sr, 1, 0, "bww", 1, sr->smb_fid, 0))
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}

/*
 * Create a new file and return a fid.  The file is specified using
 * a fully qualified name relative to the tree.
 */
smb_sdrc_t
smb_pre_create_new(smb_request_t *sr)
{
	struct open_param *op = &sr->arg.open;
	int rc;

	bzero(op, sizeof (sr->arg.open));

	rc = smbsr_decode_vwv(sr, "wl", &op->dattr, &op->utime.tv_sec);
	if (rc == 0)
		rc = smbsr_decode_data(sr, "%S", sr, &op->fqi.path);

	op->create_disposition = FILE_CREATE;

	DTRACE_SMB_2(op__CreateNew__start, smb_request_t *, sr,
	    struct open_param *, op);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_create_new(smb_request_t *sr)
{
	DTRACE_SMB_1(op__CreateNew__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_create_new(smb_request_t *sr)
{
	if (smb_common_create(sr) != NT_STATUS_SUCCESS)
		return (SDRC_ERROR);

	if (smbsr_encode_result(sr, 1, 0, "bww", 1, sr->smb_fid, 0))
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}

/*
 * Create a unique file in the specified directory relative to the
 * current tree.  No attributes are specified.
 */
smb_sdrc_t
smb_pre_create_temporary(smb_request_t *sr)
{
	struct open_param *op = &sr->arg.open;
	uint16_t reserved;
	int rc;

	bzero(op, sizeof (sr->arg.open));

	rc = smbsr_decode_vwv(sr, "wl", &reserved, &op->utime.tv_sec);
	if (rc == 0)
		rc = smbsr_decode_data(sr, "%S", sr, &op->fqi.path);

	op->create_disposition = FILE_CREATE;

	DTRACE_SMB_2(op__CreateTemporary__start, smb_request_t *, sr,
	    struct open_param *, op);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_create_temporary(smb_request_t *sr)
{
	DTRACE_SMB_1(op__CreateTemporary__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_create_temporary(smb_request_t *sr)
{
	static uint16_t tmp_id = 10000;
	struct open_param *op = &sr->arg.open;
	char name[SMB_CREATE_NAMEBUF_SZ];
	char *buf;
	uint16_t bcc;

	++tmp_id;
	bcc = 1; /* null terminator */
	bcc += snprintf(name, SMB_CREATE_NAMEBUF_SZ, "tt%05d.tmp", tmp_id);

	buf = smbsr_malloc(&sr->request_storage, MAXPATHLEN);
	(void) snprintf(buf, MAXPATHLEN, "%s\\%s", op->fqi.path, name);
	op->fqi.path = buf;

	if (smb_common_create(sr) != NT_STATUS_SUCCESS)
		return (SDRC_ERROR);

	if (smbsr_encode_result(sr, 1, VAR_BCC, "bww%S", 1, sr->smb_fid,
	    VAR_BCC, sr, name))
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}

/*
 * Common create file function.  The file is opened in compatibility
 * mode with read/write access.
 */
uint32_t
smb_common_create(smb_request_t *sr)
{
	struct open_param *op = &sr->arg.open;
	uint32_t status;

	op->utime.tv_sec = smb_local2gmt(sr, op->utime.tv_sec);
	op->utime.tv_nsec = 0;
	op->omode = SMB_DA_ACCESS_READ_WRITE | SMB_DA_SHARE_COMPATIBILITY;
	op->desired_access = smb_omode_to_amask(op->omode);
	op->share_access = smb_denymode_to_sharemode(op->omode, op->fqi.path);

	if ((op->desired_access == ((uint32_t)SMB_INVALID_AMASK)) ||
	    (op->share_access == ((uint32_t)SMB_INVALID_SHAREMODE))) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERROR_INVALID_PARAMETER);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	op->dsize = 0;

	if (sr->smb_flg & SMB_FLAGS_OPLOCK) {
		if (sr->smb_flg & SMB_FLAGS_OPLOCK_NOTIFY_ANY) {
			op->my_flags = MYF_BATCH_OPLOCK;
		} else {
			op->my_flags = MYF_EXCLUSIVE_OPLOCK;
		}
	}

	status = smb_common_open(sr);

	if (MYF_OPLOCK_TYPE(op->my_flags) == MYF_OPLOCK_NONE) {
		sr->smb_flg &=
		    ~(SMB_FLAGS_OPLOCK | SMB_FLAGS_OPLOCK_NOTIFY_ANY);
	}

	return (status);
}
