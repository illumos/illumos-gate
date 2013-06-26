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
 * Dispatch function for SMB2_SET_INFO
 *
 * [MS-FSCC 2.4] If a file system does not support ...
 * an Information Classs, NT_STATUS_INVALID_PARAMETER...
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/ntifs.h>

static uint32_t smb2_setf_rename(smb_request_t *, smb_setinfo_t *);
static uint32_t smb2_setf_link(smb_request_t *, smb_setinfo_t *);

static uint32_t smb2_setf_seek(smb_request_t *, smb_setinfo_t *);
static uint32_t smb2_setf_full_ea(smb_request_t *, smb_setinfo_t *);
static uint32_t smb2_setf_mode(smb_request_t *, smb_setinfo_t *);

static uint32_t smb2_setf_pipe(smb_request_t *, smb_setinfo_t *);
static uint32_t smb2_setf_valid_len(smb_request_t *, smb_setinfo_t *);
static uint32_t smb2_setf_shortname(smb_request_t *, smb_setinfo_t *);


uint32_t
smb2_setinfo_file(smb_request_t *sr, smb_setinfo_t *si, int InfoClass)
{
	smb_ofile_t *of = sr->fid_ofile;
	uint32_t status;

	si->si_node = of->f_node;

	switch (InfoClass) {
	case FileBasicInformation:		/* 4 */
		status = smb_set_basic_info(sr, si);
		break;
	case FileRenameInformation:		/* 10 */
		status = smb2_setf_rename(sr, si);
		break;
	case FileLinkInformation:		/* 11 */
		status = smb2_setf_link(sr, si);
		break;
	case FileDispositionInformation:	/* 13 */
		status = smb_set_disposition_info(sr, si);
		break;
	case FilePositionInformation:		/* 14 */
		status = smb2_setf_seek(sr, si);
		break;
	case FileFullEaInformation:		/* 15 */
		status = smb2_setf_full_ea(sr, si);
		break;
	case FileModeInformation:		/* 16 */
		status = smb2_setf_mode(sr, si);
		break;
	case FileAllocationInformation:		/* 19 */
		status = smb_set_alloc_info(sr, si);
		break;
	case FileEndOfFileInformation:		/* 20 */
		status = smb_set_eof_info(sr, si);
		break;
	case FilePipeInformation:		/* 23 */
		status = smb2_setf_pipe(sr, si);
		break;
	case FileValidDataLengthInformation:	/* 39 */
		status = smb2_setf_valid_len(sr, si);
		break;
	case FileShortNameInformation:		/* 40 */
		status = smb2_setf_shortname(sr, si);
		break;
	default:
		status = NT_STATUS_INVALID_INFO_CLASS;
		break;
	}

	return (status);
}


/*
 * FileRenameInformation
 * See also: smb_set_rename_info()
 */
static uint32_t
smb2_setf_rename(smb_request_t *sr, smb_setinfo_t *si)
{
	char *fname;
	uint8_t flags;
	uint64_t rootdir;
	uint32_t namelen;
	uint32_t status = 0;
	int rc;

	rc = smb_mbc_decodef(&si->si_data, "b7.ql",
	    &flags, &rootdir, &namelen);
	if (rc == 0) {
		rc = smb_mbc_decodef(&si->si_data, "%#U",
		    sr, namelen, &fname);
	}
	if (rc != 0)
		return (NT_STATUS_INFO_LENGTH_MISMATCH);

	if ((rootdir != 0) || (namelen == 0) || (namelen >= SMB_MAXPATHLEN)) {
		return (NT_STATUS_INVALID_PARAMETER);
	}

	status = smb_setinfo_rename(sr, si->si_node, fname, flags);

	return (status);
}

/*
 * FileLinkInformation
 */
static uint32_t
smb2_setf_link(smb_request_t *sr, smb_setinfo_t *si)
{
	char *fname;
	uint8_t flags;
	uint64_t rootdir;
	uint32_t namelen;
	uint32_t status = 0;
	int rc;

	rc = smb_mbc_decodef(&si->si_data, "b7.ql",
	    &flags, &rootdir, &namelen);
	if (rc == 0) {
		rc = smb_mbc_decodef(&si->si_data, "%#U",
		    sr, namelen, &fname);
	}
	if (rc != 0)
		return (NT_STATUS_INFO_LENGTH_MISMATCH);

	if ((rootdir != 0) || (namelen == 0) || (namelen >= SMB_MAXPATHLEN)) {
		return (NT_STATUS_INVALID_PARAMETER);
	}

	status = smb_setinfo_link(sr, si->si_node, fname, flags);

	return (status);
}


/*
 * FilePositionInformation
 */
static uint32_t
smb2_setf_seek(smb_request_t *sr, smb_setinfo_t *si)
{
	smb_ofile_t *of = sr->fid_ofile;
	uint64_t newoff;

	if (smb_mbc_decodef(&si->si_data, "q", &newoff) != 0)
		return (NT_STATUS_INVALID_PARAMETER);

	ASSERT(of->f_magic == SMB_OFILE_MAGIC);
	mutex_enter(&of->f_mutex);
	of->f_seek_pos = newoff;
	mutex_exit(&of->f_mutex);

	return (0);
}

/*
 * FileFullEaInformation
 * We could put EAs in a named stream...
 */
/* ARGSUSED */
static uint32_t
smb2_setf_full_ea(smb_request_t *sr, smb_setinfo_t *si)
{
	return (NT_STATUS_EAS_NOT_SUPPORTED);
}

/*
 * FileModeInformation [MS-FSCC 2.4.24]
 *	FILE_WRITE_THROUGH
 *	FILE_SEQUENTIAL_ONLY
 *	FILE_NO_INTERMEDIATE_BUFFERING
 *	etc.
 */
static uint32_t
smb2_setf_mode(smb_request_t *sr, smb_setinfo_t *si)
{
	_NOTE(ARGUNUSED(sr))
	uint32_t	Mode;

	if (smb_mbc_decodef(&si->si_data, "l", &Mode) != 0)
		return (NT_STATUS_INVALID_PARAMETER);

#if 0	/* XXX - todo */
	if (Mode & FILE_WRITE_THROUGH) {
		/* store this in the ofile */
	}
#endif

	return (NT_STATUS_SUCCESS);
}



/*
 * FilePipeInformation
 */
static uint32_t
smb2_setf_pipe(smb_request_t *sr, smb_setinfo_t *si)
{
	_NOTE(ARGUNUSED(si))
	smb_ofile_t *of = sr->fid_ofile;
	uint32_t	ReadMode;
	uint32_t	CompletionMode;
	uint32_t	status;

	if (smb_mbc_decodef(&si->si_data, "ll",
	    &ReadMode, &CompletionMode) != 0)
		return (NT_STATUS_INFO_LENGTH_MISMATCH);

	switch (of->f_ftype) {
	case SMB_FTYPE_BYTE_PIPE:
	case SMB_FTYPE_MESG_PIPE:
		/*
		 * XXX: Do we need to actually do anything with
		 * ReadMode or CompletionMode?  If so, (later)
		 * store these in the opipe object.
		 *
		 * See also: smb2_sif_pipe()
		 */
		status = 0;
		break;
	case SMB_FTYPE_DISK:
	case SMB_FTYPE_PRINTER:
	default:
		status = NT_STATUS_INVALID_PARAMETER;
	}

	return (status);
}

/*
 * FileValidDataLengthInformation
 */
/* ARGSUSED */
static uint32_t
smb2_setf_valid_len(smb_request_t *sr, smb_setinfo_t *si)
{
	smb_ofile_t *of = sr->fid_ofile;
	uint64_t eod;
	int rc;

	if (smb_mbc_decodef(&si->si_data, "q", &eod) != 0)
		return (NT_STATUS_INFO_LENGTH_MISMATCH);

	rc = smb_fsop_set_data_length(sr, of->f_cr, of->f_node, eod);
	if (rc != 0)
		return (smb_errno2status(rc));

	return (0);
}

/*
 * FileShortNameInformation
 *	We can (optionally) support supply short names,
 *	but you can't change them.
 */
static uint32_t
smb2_setf_shortname(smb_request_t *sr, smb_setinfo_t *si)
{
	_NOTE(ARGUNUSED(si))
	smb_ofile_t *of = sr->fid_ofile;

	if (of->f_ftype != SMB_FTYPE_DISK)
		return (NT_STATUS_INVALID_PARAMETER);
	if ((of->f_tree->t_flags & SMB_TREE_SHORTNAMES) == 0)
		return (NT_STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME);

	return (NT_STATUS_ACCESS_DENIED);
}
