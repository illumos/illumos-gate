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
 * Copyright 2016 Syneto S.R.L. All rights reserved.
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
	 * SMB2 Flush request
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data, "wwlqq",
	    &StructSize,		/* w */
	    &reserved1,			/* w */
	    &reserved2,			/* l */
	    &smb2fid.persistent,	/* q */
	    &smb2fid.temporal);		/* q */
	if (rc)
		return (SDRC_ERROR);
	if (StructSize != 24)
		return (SDRC_ERROR);

	status = smb2sr_lookup_fid(sr, &smb2fid);
	if (status) {
		smb2sr_put_error(sr, status);
		return (SDRC_SUCCESS);
	}

	smb_ofile_flush(sr, sr->fid_ofile);

	/*
	 * SMB2 Flush reply
	 */
	(void) smb_mbc_encodef(
	    &sr->reply, "wwl",
	    4,	/* StructSize */	/* w */
	    0); /* reserved */		/* w */

	return (SDRC_SUCCESS);
}
