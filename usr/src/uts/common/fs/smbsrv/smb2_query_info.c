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
 * Dispatch function for SMB2_QUERY_INFO
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/ntifs.h>

smb_sdrc_t
smb2_query_info(smb_request_t *sr)
{
	smb_queryinfo_t *qi;
	uint16_t StructSize;
	uint32_t oBufLength;
	uint16_t iBufOffset;
	uint32_t iBufLength;
	smb2fid_t smb2fid;
	uint16_t DataOff;
	uint32_t status;
	smb_sdrc_t sdrc = SDRC_SUCCESS;
	int rc = 0;

	qi = kmem_zalloc(sizeof (*qi), KM_SLEEP);

	/*
	 * SMB2 Query Info request
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data, "wbblw..lllqq",
	    &StructSize,		/* w */
	    &qi->qi_InfoType,		/* b */
	    &qi->qi_InfoClass,		/* b */
	    &oBufLength,		/* l */
	    &iBufOffset,		/* w */
	    /* reserved			  .. */
	    &iBufLength,		/* l */
	    &qi->qi_AddlInfo,		/* l */
	    &qi->qi_Flags,		/* l */
	    &smb2fid.persistent,	/* q */
	    &smb2fid.temporal);		/* q */
	if (rc || StructSize != 41) {
		sdrc = SDRC_ERROR;
		goto out;
	}

	status = smb2sr_lookup_fid(sr, &smb2fid);
	if (status) {
		smb2sr_put_error(sr, status);
		goto out;
	}

	if (oBufLength > smb2_max_trans)
		oBufLength = smb2_max_trans;

	/*
	 * If there's an input buffer, setup a shadow.
	 */
	if (iBufLength) {
		rc = MBC_SHADOW_CHAIN(&qi->in_data, &sr->smb_data,
		    sr->smb2_cmd_hdr + iBufOffset, iBufLength);
		if (rc) {
			smb2sr_put_error(sr, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}
	}

	sr->raw_data.max_bytes = oBufLength;

	switch (qi->qi_InfoType) {
	case SMB2_0_INFO_FILE:
		status = smb2_qinfo_file(sr, qi);
		break;
	case SMB2_0_INFO_FILESYSTEM:
		status = smb2_qinfo_fs(sr, qi);
		break;
	case SMB2_0_INFO_SECURITY:
		status = smb2_qinfo_sec(sr, qi);
		break;
	case SMB2_0_INFO_QUOTA:
		status = smb2_qinfo_quota(sr, qi);
		break;
	default:
		status = NT_STATUS_INVALID_PARAMETER;
		break;
	}

	switch (status) {

	case 0: /* success */
		break;

	case NT_STATUS_BUFFER_OVERFLOW:
		/* Not really an error, per se.  Advisory. */
		sr->smb2_status = status;
		break;

	case NT_STATUS_BUFFER_TOO_SMALL:
	case NT_STATUS_INFO_LENGTH_MISMATCH:
		/*
		 * These are special, per. [MS-SMB2] 3.2.5.17
		 * The error data is a 4-byte count of the size
		 * required to successfully query the data.
		 * That error data is built by the functions
		 * that returns one of these errors.
		 */
		smb2sr_put_error_data(sr, status, &sr->raw_data);
		goto out;

	default:
		smb2sr_put_error(sr, status);
		goto out;
	}

	/*
	 * SMB2 Query Info reply
	 */
	DataOff = SMB2_HDR_SIZE + 8;
	oBufLength = MBC_LENGTH(&sr->raw_data);
	rc = smb_mbc_encodef(
	    &sr->reply, "wwlC",
	    9,	/* StructSize */	/* w */
	    DataOff,			/* w */
	    oBufLength,			/* l */
	    &sr->raw_data);		/* C */
	if (rc)
		sdrc = SDRC_ERROR;

out:
	kmem_free(qi, sizeof (*qi));

	return (sdrc);
}
