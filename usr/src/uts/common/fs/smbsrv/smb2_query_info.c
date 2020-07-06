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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2020 RackTop Systems, Inc.
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
	int rc = 0;

	qi = smb_srm_zalloc(sr, sizeof (*qi));

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
	if (rc || StructSize != 41)
		return (SDRC_ERROR);

	/*
	 * If there's an input buffer, setup a shadow.
	 */
	if (iBufLength) {
		rc = MBC_SHADOW_CHAIN(&qi->in_data, &sr->smb_data,
		    sr->smb2_cmd_hdr + iBufOffset, iBufLength);
		if (rc) {
			return (SDRC_ERROR);
		}
	}

	if (oBufLength > smb2_max_trans)
		oBufLength = smb2_max_trans;
	sr->raw_data.max_bytes = oBufLength;

	status = smb2sr_lookup_fid(sr, &smb2fid);
	DTRACE_SMB2_START(op__QueryInfo, smb_request_t *, sr);

	if (status)
		goto errout;

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

errout:
	sr->smb2_status = status;
	DTRACE_SMB2_DONE(op__QueryInfo, smb_request_t *, sr);

	switch (status) {

	case 0: /* success */
		break;

	case NT_STATUS_BUFFER_OVERFLOW:
		/* Not really an error, per se.  Advisory. */
		break;

	case NT_STATUS_BUFFER_TOO_SMALL:	/* only in smb2_qinfo_sec.c */
		/*
		 * [MS-SMB2] 3.3.5.20.3
		 * Handling SMB2_0_INFO_SECURITY
		 *  If dialect 3.1.1 must return 4-byte value
		 *  containing required buffer size.
		 *  ByteCount==12, ErrorContextCount==1,
		 *  ErrorData: ErrorDataLength==4,ErrorId==0
		 *  ErrorContextData==<buffer size>
		 *  Otherwise ByteCount==4
		 *
		 * When returning with data, 3.1.1 encapsulate.
		 */
		if (sr->session->dialect < SMB_VERS_3_11) {
			smb2sr_put_error_data(sr, status, &sr->raw_data);
		} else {
			smb2sr_put_error_ctx0(sr, status, &sr->raw_data);
		}
		return (SDRC_SUCCESS);

	case NT_STATUS_INFO_LENGTH_MISMATCH: /* there is no in smb2_qinfo_*.c */
		/*
		 * [MS-SMB2] 3.3.5.20.1
		 * SMB 3.1.1 Handling SMB2_0_INFO_FILE
		 * [MS-SMB2] 3.3.5.20.2
		 * SMB 3.1.1 Handling SMB2_0_INFO_FILESYSTEM
		 *
		 *  ByteCount==8, ErrorContextCount==1,
		 *  ErrorData: ErrorDataLength==0,ErrorId==0
		 *  Otherwise ByteCount==0
		 */
		if (sr->session->dialect < SMB_VERS_3_11) {
			smb2sr_put_error_data(sr, status, NULL);
		} else {
			smb2sr_put_error_ctx0(sr, status, NULL);
		}
		return (SDRC_SUCCESS);

	default:
		smb2sr_put_error(sr, status);
		return (SDRC_SUCCESS);
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
		sr->smb2_status = NT_STATUS_INTERNAL_ERROR;

	return (SDRC_SUCCESS);
}
