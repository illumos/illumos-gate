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
 * Dispatch function for SMB2_CLOSE
 */

#include <smbsrv/smb2_kproto.h>

smb_sdrc_t
smb2_close(smb_request_t *sr)
{
	smb_attr_t attr;
	smb_ofile_t *of;
	uint16_t StructSize;
	uint16_t Flags;
	uint32_t reserved;
	smb2fid_t smb2fid;
	uint32_t status;
	int rc = 0;

	/*
	 * SMB2 Close request
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data, "wwlqq",
	    &StructSize,		/* w */
	    &Flags,			/* w */
	    &reserved,			/* l */
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
	of = sr->fid_ofile;

	bzero(&attr, sizeof (attr));
	if (Flags & SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB) {
		attr.sa_mask = SMB_AT_ALL;
		status = smb2_ofile_getattr(sr, of, &attr);
		if (status) {
			/*
			 * We could not stat the open file.
			 * Let's not fail the close call,
			 * but just turn off the flag.
			 */
			Flags = 0;
		}
	}

	smb_ofile_close(of, 0);

	/*
	 * SMB2 Close reply
	 */
	(void) smb_mbc_encodef(
	    &sr->reply,
	    "wwlTTTTqql",
	    60,	/* StructSize */	/* w */
	    Flags,			/* w */
	    0, /* reserved */		/* l */
	    &attr.sa_crtime,		/* T */
	    &attr.sa_vattr.va_atime,	/* T */
	    &attr.sa_vattr.va_mtime,	/* T */
	    &attr.sa_vattr.va_ctime,	/* T */
	    attr.sa_allocsz,		/* q */
	    attr.sa_vattr.va_size,	/* q */
	    attr.sa_dosattr);		/* l */

	return (SDRC_SUCCESS);
}
