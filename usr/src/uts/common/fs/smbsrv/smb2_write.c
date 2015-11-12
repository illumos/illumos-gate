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
 * Dispatch function for SMB2_WRITE
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>

smb_sdrc_t
smb2_write(smb_request_t *sr)
{
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

	/*
	 * SMB2 Write request
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

	/*
	 * Skip any padding before the write data.
	 */
	data_chain_off = sr->smb2_cmd_hdr + DataOff;
	skip = data_chain_off - sr->smb_data.chain_offset;
	if (skip < 0) {
		smb2sr_put_error(sr, NT_STATUS_INVALID_PARAMETER);
		return (SDRC_SUCCESS);
	}
	if (skip > 0) {
		(void) smb_mbc_decodef(&sr->smb_data, "#.", skip);
	}

	/* This is automatically free'd. */
	vdb = smb_srm_zalloc(sr, sizeof (*vdb));
	rc = smb_mbc_decodef(&sr->smb_data, "#B", Length, vdb);
	if (rc != 0 || vdb->vdb_len != Length) {
		smb2sr_put_error(sr, NT_STATUS_INVALID_PARAMETER);
		return (SDRC_SUCCESS);
	}
	vdb->vdb_uio.uio_loffset = (offset_t)Offset;

	XferCount = 0;
	if (Length == 0)
		goto doreply;

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
		if ((Flags & SMB2_WRITEFLAG_WRITE_THROUGH) ||
		    (of->f_node->flags & NODE_FLAGS_WRITE_THROUGH)) {
			stability = FSYNC;
		}
		rc = smb_fsop_write(sr, of->f_cr, of->f_node,
		    &vdb->vdb_uio, &XferCount, stability);
		if (rc)
			break;
		of->f_written = B_TRUE;
		if (!smb_node_is_dir(of->f_node))
			smb_oplock_break_levelII(of->f_node);
		break;

	case STYPE_IPC:
		rc = smb_opipe_write(sr, &vdb->vdb_uio);
		if (rc == 0)
			XferCount = Length;
		break;

	default:
		rc = EACCES;
		break;
	}

	if (rc) {
		smb2sr_put_errno(sr, rc);
		return (SDRC_SUCCESS);
	}

	/*
	 * SMB2 Write reply
	 */
doreply:
	DataOff = SMB2_HDR_SIZE + 16;
	rc = smb_mbc_encodef(
	    &sr->reply, "wwlll",
	    17,	/* StructSize */	/* w */
	    0, /* reserved */		/* w */
	    XferCount,			/* l */
	    0, /* DataRemaining */	/* l */
	    0); /* Channel Info */	/* l */
	if (rc)
		return (SDRC_ERROR);

	mutex_enter(&of->f_mutex);
	of->f_seek_pos = Offset + XferCount;
	mutex_exit(&of->f_mutex);

	return (SDRC_SUCCESS);
}
