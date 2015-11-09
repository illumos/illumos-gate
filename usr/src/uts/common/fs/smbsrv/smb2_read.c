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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_READ
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>

smb_sdrc_t
smb2_read(smb_request_t *sr)
{
	smb_ofile_t *of = NULL;
	smb_vdb_t *vdb = NULL;
	struct mbuf *m = NULL;
	uint16_t StructSize;
	uint8_t Padding;
	uint8_t DataOff;
	uint32_t Length;
	uint64_t Offset;
	smb2fid_t smb2fid;
	uint32_t MinCount;
	uint32_t Channel;
	uint32_t Remaining;
	uint16_t ChanInfoOffset;
	uint16_t ChanInfoLength;
	uint32_t XferCount;
	uint32_t status;
	int rc = 0;

	/*
	 * SMB2 Read request
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data,
	    "wb.lqqqlllww",
	    &StructSize,		/* w */
	    &Padding,			/* b. */
	    &Length,			/* l */
	    &Offset,			/* q */
	    &smb2fid.persistent,	/* q */
	    &smb2fid.temporal,		/* q */
	    &MinCount,			/* l */
	    &Channel,			/* l */
	    &Remaining,			/* l */
	    &ChanInfoOffset,		/* w */
	    &ChanInfoLength);		/* w */
	if (rc)
		return (SDRC_ERROR);
	if (StructSize != 49)
		return (SDRC_ERROR);

	status = smb2sr_lookup_fid(sr, &smb2fid);
	if (status) {
		smb2sr_put_error(sr, status);
		return (SDRC_SUCCESS);
	}
	of = sr->fid_ofile;

	if (Length > smb2_max_rwsize) {
		smb2sr_put_error(sr, NT_STATUS_INVALID_PARAMETER);
		return (SDRC_SUCCESS);
	}
	if (MinCount > Length)
		MinCount = Length;

	/* This is automatically free'd. */
	vdb = smb_srm_zalloc(sr, sizeof (*vdb));
	vdb->vdb_tag = 0;
	vdb->vdb_uio.uio_iov = &vdb->vdb_iovec[0];
	vdb->vdb_uio.uio_iovcnt = MAX_IOVEC;
	vdb->vdb_uio.uio_resid = Length;
	vdb->vdb_uio.uio_loffset = (offset_t)Offset;
	vdb->vdb_uio.uio_segflg = UIO_SYSSPACE;
	vdb->vdb_uio.uio_extflg = UIO_COPY_DEFAULT;

	sr->raw_data.max_bytes = Length;
	m = smb_mbuf_allocate(&vdb->vdb_uio);

	switch (of->f_tree->t_res_type & STYPE_MASK) {
	case STYPE_DISKTREE:
		if (!smb_node_is_dir(of->f_node)) {
			/* Check for conflicting locks. */
			rc = smb_lock_range_access(sr, of->f_node,
			    Offset, Length, B_FALSE);
			if (rc) {
				rc = ERANGE;
				break;
			}
		}
		rc = smb_fsop_read(sr, of->f_cr, of->f_node, &vdb->vdb_uio);
		break;
	case STYPE_IPC:
		rc = smb_opipe_read(sr, &vdb->vdb_uio);
		break;
	default:
	case STYPE_PRINTQ:
		rc = EACCES;
		break;
	}

	/* How much data we moved. */
	XferCount = Length - vdb->vdb_uio.uio_resid;

	sr->raw_data.max_bytes = XferCount;
	smb_mbuf_trim(m, XferCount);
	MBC_ATTACH_MBUF(&sr->raw_data, m);

	/*
	 * Checking the error return _after_ dealing with
	 * the returned data so that if m was allocated,
	 * it will be free'd via sr->raw_data cleanup.
	 */
	if (rc) {
		smb2sr_put_errno(sr, rc);
		return (SDRC_SUCCESS);
	}

	/*
	 * SMB2 Read reply
	 */
	DataOff = SMB2_HDR_SIZE + 16;
	rc = smb_mbc_encodef(
	    &sr->reply,
	    "wb.lllC",
	    17,	/* StructSize */	/* w */
	    DataOff,			/* b. */
	    XferCount,			/* l */
	    0, /* DataRemaining */	/* l */
	    0, /* reserved */		/* l */
	    &sr->raw_data);		/* C */
	if (rc)
		return (SDRC_ERROR);

	mutex_enter(&of->f_mutex);
	of->f_seek_pos = Offset + XferCount;
	mutex_exit(&of->f_mutex);

	return (SDRC_SUCCESS);
}
