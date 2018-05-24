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
 * Copyright 2019 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_READ
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>

extern boolean_t smb_allow_unbuffered;

smb_sdrc_t
smb2_read(smb_request_t *sr)
{
	smb_rw_param_t *param = NULL;
	smb_ofile_t *of = NULL;
	smb_vdb_t *vdb = NULL;
	struct mbuf *m = NULL;
	uint16_t StructSize;
	uint8_t Padding;
	uint8_t Flags;
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
	boolean_t unbuffered = B_FALSE;
	int ioflag = 0;

	/*
	 * SMB2 Read request
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data,
	    "wbblqqqlllww",
	    &StructSize,		/* w */
	    &Padding,			/* b */
	    &Flags,			/* b */
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

	/*
	 * Setup an smb_rw_param_t which contains the VDB we need.
	 * This is automatically free'd.
	 */
	param = smb_srm_zalloc(sr, sizeof (*param));
	param->rw_offset = Offset;
	param->rw_count = Length;
	/* Note that the dtrace provider uses sr->arg.rw */
	sr->arg.rw = param;

	/*
	 * Want FID lookup before the start probe.
	 */
	status = smb2sr_lookup_fid(sr, &smb2fid);
	of = sr->fid_ofile;

	DTRACE_SMB2_START(op__Read, smb_request_t *, sr); /* arg.rw */

	if (status)
		goto errout; /* Bad FID */

	if (Length > smb2_max_rwsize) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto errout;
	}
	if (MinCount > Length)
		MinCount = Length;

	vdb = &param->rw_vdb;
	vdb->vdb_tag = 0;
	vdb->vdb_uio.uio_iov = &vdb->vdb_iovec[0];
	vdb->vdb_uio.uio_iovcnt = MAX_IOVEC;
	vdb->vdb_uio.uio_resid = Length;
	vdb->vdb_uio.uio_loffset = (offset_t)Offset;
	vdb->vdb_uio.uio_segflg = UIO_SYSSPACE;
	vdb->vdb_uio.uio_extflg = UIO_COPY_DEFAULT;

	sr->raw_data.max_bytes = Length;
	m = smb_mbuf_allocate(&vdb->vdb_uio);

	/*
	 * Unbuffered refers to the MS-FSA Read argument by the same name.
	 * It indicates that the cache for this range should be flushed to disk,
	 * and data read directly from disk, bypassing the cache.
	 * We don't allow that degree of cache management.
	 * Translate this directly as FRSYNC,
	 * which should at least flush the cache first.
	 */

	if (smb_allow_unbuffered &&
	    (Flags & SMB2_READFLAG_READ_UNBUFFERED) != 0) {
		unbuffered = B_TRUE;
		ioflag = FRSYNC;
	}

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
		rc = smb_fsop_read(sr, of->f_cr, of->f_node, of,
		    &vdb->vdb_uio, ioflag);
		break;
	case STYPE_IPC:
		if (unbuffered)
			rc = EINVAL;
		else
			rc = smb_opipe_read(sr, &vdb->vdb_uio);
		break;
	default:
	case STYPE_PRINTQ:
		rc = EACCES;
		break;
	}
	status = smb_errno2status(rc);

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
errout:
	sr->smb2_status = status;
	DTRACE_SMB2_DONE(op__Read, smb_request_t *, sr); /* arg.rw */
	if (status) {
		smb2sr_put_error(sr, status);
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
	if (rc) {
		sr->smb2_status = NT_STATUS_INTERNAL_ERROR;
		return (SDRC_ERROR);
	}

	mutex_enter(&of->f_mutex);
	of->f_seek_pos = Offset + XferCount;
	mutex_exit(&of->f_mutex);

	return (SDRC_SUCCESS);
}
