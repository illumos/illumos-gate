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
 * Copyright 2016 Syneto S.R.L. All rights reserved.
 * Copyright 2023 RackTop Systems, Inc.
 */

/*
 * Dispatch function for SMB2_FLUSH
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>

smb_sdrc_t
smb2_flush(smb_request_t *sr)
{
	uint16_t StructSize;
	uint16_t reserved1;
	uint32_t reserved2;
	smb2fid_t smb2fid;
	uint32_t status;
	int rc = 0;

	/*
	 * Decode SMB2 Flush request
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data, "wwlqq",
	    &StructSize,		/* w */
	    &reserved1,			/* w */
	    &reserved2,			/* l */
	    &smb2fid.persistent,	/* q */
	    &smb2fid.temporal);		/* q */
	if (rc || StructSize != 24)
		return (SDRC_ERROR);

	/*
	 * Want FID lookup before the start probe.
	 */
	status = smb2sr_lookup_fid(sr, &smb2fid);
	DTRACE_SMB2_START(op__Flush, smb_request_t *, sr);

	if (status == 0)
		smb_ofile_flush(sr, sr->fid_ofile);

	sr->smb2_status = status;
	DTRACE_SMB2_DONE(op__Flush, smb_request_t *, sr);

	if (status) {
		smb2sr_put_error(sr, status);
		return (SDRC_SUCCESS);
	}

	/*
	 * SMB2 Flush reply
	 */
	(void) smb_mbc_encodef(
	    &sr->reply, "ww",
	    4,	/* StructSize */	/* w */
	    0); /* reserved */		/* w */

	return (SDRC_SUCCESS);
}
