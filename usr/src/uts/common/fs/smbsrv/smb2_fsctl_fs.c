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
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Support functions for smb2_ioctl/fsctl categories:
 * FILE_DEVICE_FILE_SYSTEM (9)
 * FILE_DEVICE_NETWORK_FILE_SYSTEM (20)
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smb/winioctl.h>

/* ARGSUSED */
static uint32_t
smb2_fsctl_notsup(smb_request_t *sr, smb_fsctl_t *fsctl)
{
	return (NT_STATUS_NOT_SUPPORTED);
}

/*
 * Same as smb2_fsctl_notsup, but make some noise (if DEBUG)
 * so we'll learn about new fsctl codes clients start using.
 */
/* ARGSUSED */
static uint32_t
smb2_fsctl_unknown(smb_request_t *sr, smb_fsctl_t *fsctl)
{
#ifdef	DEBUG
	cmn_err(CE_NOTE, "smb2_fsctl_unknown: code 0x%x", fsctl->CtlCode);
#endif
	return (NT_STATUS_NOT_SUPPORTED);
}

/*
 * FSCTL_GET_COMPRESSION
 */
static uint32_t
smb2_fsctl_get_compression(smb_request_t *sr, smb_fsctl_t *fsctl)
{
	_NOTE(ARGUNUSED(sr))
	uint16_t compress_state = 0;

	(void) smb_mbc_encodef(fsctl->in_mbc, "w",
	    compress_state);

	return (NT_STATUS_SUCCESS);
}

/*
 * FSCTL_SET_COMPRESSION
 */
static uint32_t
smb2_fsctl_set_compression(smb_request_t *sr, smb_fsctl_t *fsctl)
{
	_NOTE(ARGUNUSED(sr))

	uint16_t compress_state;
	(void) smb_mbc_decodef(fsctl->in_mbc, "w",
	    &compress_state);

	if (compress_state > 0)
		return (NT_STATUS_COMPRESSION_DISABLED);

	return (NT_STATUS_SUCCESS);
}

/*
 * FSCTL_SRV_REQUEST_RESUME_KEY
 *
 * The returned data is an (opaque to the client) 24-byte blob
 * in which we stash the SMB2 "file ID" (both parts). Later,
 * copychunk may lookup the ofile using that file ID.
 * See: smb2_fsctl_copychunk()
 *
 * Note that Mac clients make this request on a directory
 * (even though this only makes sense on a file) just to
 * find out if the server supports server-side copy.
 * There's no harm letting a client have a resume key
 * for a directory.  They'll never be able to DO anything
 * with it because we check for a plain file later.
 */
static uint32_t
smb2_fsctl_get_resume_key(smb_request_t *sr, smb_fsctl_t *fsctl)
{
	smb_ofile_t *of = sr->fid_ofile;
	smb2fid_t smb2fid;

	/* Caller makes sure we have of = sr->fid_ofile */
	/* Don't insist on a plain file (see above). */

	smb2fid.persistent = of->f_persistid;
	smb2fid.temporal = of->f_fid;

	(void) smb_mbc_encodef(
	    fsctl->out_mbc, "qq16.",
	    smb2fid.persistent,
	    smb2fid.temporal);

	return (NT_STATUS_SUCCESS);
}

/*
 * FILE_DEVICE_FILE_SYSTEM (9)
 */
uint32_t
smb2_fsctl_fs(smb_request_t *sr, smb_fsctl_t *fsctl)
{
	uint32_t (*func)(smb_request_t *, smb_fsctl_t *);
	uint32_t status;

	switch (fsctl->CtlCode) {
	case FSCTL_GET_COMPRESSION:		/* 15 */
		func = smb2_fsctl_get_compression;
		break;
	case FSCTL_SET_COMPRESSION:		/* 16 */
		func = smb2_fsctl_set_compression;
		break;
	case FSCTL_SET_REPARSE_POINT:		/* 41 */
	case FSCTL_GET_REPARSE_POINT:		/* 42 */
	case FSCTL_CREATE_OR_GET_OBJECT_ID:	/* 48 */
		func = smb2_fsctl_notsup;
		break;
	case FSCTL_SET_SPARSE:			/* 49 */
		func = smb2_fsctl_set_sparse;
		break;
	case FSCTL_SET_ZERO_DATA:		/* 50 */
		func = smb2_fsctl_set_zero_data;
		break;
	case FSCTL_QUERY_ALLOCATED_RANGES:	/* 51 */
		func = smb2_fsctl_query_alloc_ranges;
		break;
	case FSCTL_FILE_LEVEL_TRIM:		/* 130 */
		func = smb2_fsctl_notsup;
		break;
	case FSCTL_OFFLOAD_READ:		/* 153 */
		func = smb2_fsctl_odx_read;
		break;
	case FSCTL_OFFLOAD_WRITE:		/* 154 */
		func = smb2_fsctl_odx_write;
		break;
	case FSCTL_SET_INTEGRITY_INFORMATION:	/* 160 */
		func = smb2_fsctl_notsup;
		break;
	case FSCTL_QUERY_FILE_REGIONS:		/* 161 */
		func = smb2_fsctl_query_file_regions;
		break;

	default:
		func = smb2_fsctl_unknown;
		break;
	}

	/*
	 * All "fs" sub-codes require a disk file.
	 */
	if (sr->fid_ofile == NULL ||
	    !SMB_FTYPE_IS_DISK(sr->fid_ofile->f_ftype))
		return (NT_STATUS_INVALID_PARAMETER);

	status = (*func)(sr, fsctl);
	return (status);
}

/*
 * FILE_DEVICE_NETWORK_FILE_SYSTEM (20)
 */
uint32_t
smb2_fsctl_netfs(smb_request_t *sr, smb_fsctl_t *fsctl)
{
	uint32_t (*func)(smb_request_t *, smb_fsctl_t *);
	uint32_t status;
	boolean_t need_disk_file = B_TRUE;

	switch (fsctl->CtlCode) {
	case FSCTL_SRV_ENUMERATE_SNAPSHOTS:	/* 0x19 */
		func = smb_vss_enum_snapshots;
		break;
	case FSCTL_SRV_REQUEST_RESUME_KEY:	/* 0x1e */
		func = smb2_fsctl_get_resume_key;
		break;
	case FSCTL_SRV_COPYCHUNK:		/* 0x3c(r) */
	case FSCTL_SRV_COPYCHUNK_WRITE:		/* 0x3c(w) */
		func = smb2_fsctl_copychunk;
		break;
	case FSCTL_SRV_READ_HASH:		/* 0x6e */
		func = smb2_fsctl_notsup;
		break;
	case FSCTL_LMR_REQUEST_RESILIENCY:	/* 0x75 */
		func = smb2_fsctl_set_resilient;
		break;
	case FSCTL_QUERY_NETWORK_INTERFACE_INFO: /* 0x7f */
		need_disk_file = B_FALSE;
		func = smb2_fsctl_notsup;
		break;
	case FSCTL_VALIDATE_NEGOTIATE_INFO:	/* 0x81 */
		need_disk_file = B_FALSE;
		func = smb2_nego_validate;
		break;
	default:
		func = smb2_fsctl_unknown;
		break;
	}

	/*
	 * Most "net fs" sub-codes require a disk file,
	 * except a couple that clear need_disk_file.
	 */
	if (need_disk_file && (sr->fid_ofile == NULL ||
	    !SMB_FTYPE_IS_DISK(sr->fid_ofile->f_ftype)))
		return (NT_STATUS_INVALID_PARAMETER);

	status = (*func)(sr, fsctl);
	return (status);
}
