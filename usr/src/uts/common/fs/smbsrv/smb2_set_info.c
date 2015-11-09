/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_SET_INFO
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/ntifs.h>

smb_sdrc_t
smb2_set_info(smb_request_t *sr)
{
	smb_setinfo_t sinfo;
	uint16_t StructSize;
	uint16_t iBufOffset;
	uint32_t iBufLength;
	uint32_t AddlInfo;
	smb2fid_t smb2fid;
	uint32_t status;
	uint8_t InfoType, InfoClass;
	smb_sdrc_t sdrc = SDRC_SUCCESS;
	int rc = 0;

	bzero(&sinfo, sizeof (sinfo));

	/*
	 * SMB2 Set Info request
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data, "wbblw..lqq",
	    &StructSize,		/* w */
	    &InfoType,			/* b */
	    &InfoClass,			/* b */
	    &iBufLength,		/* l */
	    &iBufOffset,		/* w */
	    /* reserved			  .. */
	    &AddlInfo,			/* l */
	    &smb2fid.persistent,	/* q */
	    &smb2fid.temporal);		/* q */
	if (rc || StructSize != 33) {
		sdrc = SDRC_ERROR;
		return (sdrc);
	}

	if (iBufLength > smb2_max_trans) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto errout;
	}

	status = smb2sr_lookup_fid(sr, &smb2fid);
	if (status)
		goto errout;

	sinfo.si_node = sr->fid_ofile->f_node;
	sr->user_cr = sr->fid_ofile->f_cr;

	/*
	 * If there's an input buffer, setup a shadow.
	 */
	if (iBufLength) {
		rc = MBC_SHADOW_CHAIN(&sinfo.si_data, &sr->smb_data,
		    sr->smb2_cmd_hdr + iBufOffset, iBufLength);
		if (rc) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto errout;
		}
	}

	/* No output data. */
	sr->raw_data.max_bytes = 0;

	switch (InfoType) {
	case SMB2_0_INFO_FILE:
		status = smb2_setinfo_file(sr, &sinfo, InfoClass);
		break;
	case SMB2_0_INFO_FILESYSTEM:
		status = smb2_setinfo_fs(sr, &sinfo, InfoClass);
		break;
	case SMB2_0_INFO_SECURITY:
		status = smb2_setinfo_sec(sr, &sinfo, AddlInfo);
		break;
	case SMB2_0_INFO_QUOTA:
		status = smb2_setinfo_quota(sr, &sinfo);
		break;
	default:
		status = NT_STATUS_INVALID_PARAMETER;
		break;
	}

	if (status) {
	errout:
		smb2sr_put_error(sr, status);
		return (sdrc);
	}

	/*
	 * SMB2 Query Info reply
	 */
	rc = smb_mbc_encodef(
	    &sr->reply, "w..",
	    2);	/* StructSize */	/* w */
	if (rc)
		sdrc = SDRC_ERROR;

	return (sdrc);
}
