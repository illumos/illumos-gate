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
 * Dispatch function for SMB2_WRITE
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>

boolean_t smb_allow_unbuffered = B_TRUE;

smb_sdrc_t
smb2_write(smb_request_t *sr)
{
	smb_rw_param_t *param = NULL;
	smb_ofile_t *of = NULL;
	smb_vdb_t *vdb = NULL;
	uint16_t StructSize;
	uint16_t DataOff;
	uint32_t Length;
	uint64_t Offset;
	smb2fid_t smb2fid;
	uint32_t Channel;
	uint32_t Remaining;
	uint16_t ChanInfoOffset;
	uint16_t ChanInfoLength;
	uint32_t Flags;
	uint32_t XferCount;
	uint32_t status;
	int data_chain_off, skip;
	int stability = 0;
	int rc = 0;
	boolean_t unbuffered = B_FALSE;

	/*
	 * Decode SMB2 Write request
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data,
	    "wwlqqqllwwl",
	    &StructSize,		/* w */
	    &DataOff,			/* w */
	    &Length,			/* l */
	    &Offset,			/* q */
	    &smb2fid.persistent,	/* q */
	    &smb2fid.temporal,		/* q */
	    &Channel,			/* l */
	    &Remaining,			/* l */
	    &ChanInfoOffset,		/* w */
	    &ChanInfoLength,		/* w */
	    &Flags);			/* l */
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
	 * Skip any padding before the write data.
	 */
	data_chain_off = sr->smb2_cmd_hdr + DataOff;
	skip = data_chain_off - sr->smb_data.chain_offset;
	if (skip < 0)
		return (SDRC_ERROR);
	if (skip > 0)
		(void) smb_mbc_decodef(&sr->smb_data, "#.", skip);

	/*
	 * Decode the write data (payload)
	 */
	if (Length > smb2_max_rwsize)
		return (SDRC_ERROR);
	vdb = &param->rw_vdb;
	rc = smb_mbc_decodef(&sr->smb_data, "#B", Length, vdb);
	if (rc != 0 || vdb->vdb_len != Length)
		return (SDRC_ERROR);
	vdb->vdb_uio.uio_loffset = (offset_t)Offset;

	/*
	 * Want FID lookup before the start probe.
	 */
	status = smb2sr_lookup_fid(sr, &smb2fid);
	of = sr->fid_ofile;

	DTRACE_SMB2_START(op__Write, smb_request_t *, sr); /* arg.rw */

	if (status)
		goto errout; /* Bad FID */


	XferCount = 0;
	if (Length == 0)
		goto errout;

	/*
	 * Unbuffered refers to the MS-FSA Write argument by the same name.
	 * It indicates that the cache for this range should be flushed to disk,
	 * and data written directly to disk, bypassing the cache.
	 * We don't allow that degree of cache management.
	 * Translate this directly as FSYNC,
	 * which should at least flush the cache.
	 */

	if (smb_allow_unbuffered &&
	    (Flags & SMB2_WRITEFLAG_WRITE_UNBUFFERED) != 0)
		unbuffered = B_TRUE;

	switch (of->f_tree->t_res_type & STYPE_MASK) {
	case STYPE_DISKTREE:
	case STYPE_PRINTQ:
		if (!smb_node_is_dir(of->f_node)) {
			/* Check for conflicting locks. */
			rc = smb_lock_range_access(sr, of->f_node,
			    Offset, Length, B_TRUE);
			if (rc) {
				rc = ERANGE;
				break;
			}
		}

		if (unbuffered || (Flags & SMB2_WRITEFLAG_WRITE_THROUGH) != 0 ||
		    (of->f_node->flags & NODE_FLAGS_WRITE_THROUGH) != 0) {
			stability = FSYNC;
		}
		rc = smb_fsop_write(sr, of->f_cr, of->f_node, of,
		    &vdb->vdb_uio, &XferCount, stability);
		if (rc)
			break;
		of->f_written = B_TRUE;
		/* This revokes read cache delegations. */
		(void) smb_oplock_break_WRITE(of->f_node, of);
		break;

	case STYPE_IPC:
		if (unbuffered || (Flags & SMB2_WRITEFLAG_WRITE_THROUGH) != 0)
			rc = EINVAL;
		else
			rc = smb_opipe_write(sr, &vdb->vdb_uio);
		if (rc == 0)
			XferCount = Length;
		break;

	default:
		rc = EACCES;
		break;
	}
	status = smb_errno2status(rc);

errout:
	sr->smb2_status = status;
	DTRACE_SMB2_DONE(op__Write, smb_request_t *, sr); /* arg.rw */

	if (status) {
		smb2sr_put_error(sr, status);
		return (SDRC_SUCCESS);
	}

	/*
	 * Encode SMB2 Write reply
	 */
	DataOff = SMB2_HDR_SIZE + 16;
	rc = smb_mbc_encodef(
	    &sr->reply, "wwlll",
	    17,	/* StructSize */	/* w */
	    0, /* reserved */		/* w */
	    XferCount,			/* l */
	    0, /* DataRemaining */	/* l */
	    0); /* Channel Info */	/* l */
	if (rc) {
		sr->smb2_status = NT_STATUS_INTERNAL_ERROR;
		return (SDRC_ERROR);
	}

	mutex_enter(&of->f_mutex);
	of->f_seek_pos = Offset + XferCount;
	mutex_exit(&of->f_mutex);

	return (SDRC_SUCCESS);
}
