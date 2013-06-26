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
 * Dispatch function for SMB2_QUERY_INFO
 *
 * [MS-FSCC 2.4] If a file system does not support ...
 * an Information Classs, NT_STATUS_INVALID_PARAMETER...
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/ntifs.h>

static uint32_t smb2_qif_all(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_basic(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_standard(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_internal(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_ea_size(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_access(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_name(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_position(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_full_ea(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_mode(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_alignment(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_all(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_altname(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_stream(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_pipe(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_pipe_lcl(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_pipe_rem(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_compr(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_opens(smb_request_t *, smb_queryinfo_t *);
static uint32_t smb2_qif_tags(smb_request_t *, smb_queryinfo_t *);


uint32_t
smb2_qinfo_file(smb_request_t *sr, smb_queryinfo_t *qi)
{
	smb_ofile_t *of = sr->fid_ofile;
	uint_t mask = 0;
	boolean_t getstd = B_FALSE;
	boolean_t getname = B_FALSE;
	uint32_t status;

	/*
	 * Which attributes do we need from the FS?
	 */
	switch (qi->qi_InfoClass) {
	case FileBasicInformation:
		mask = SMB_AT_BASIC;
		break;
	case FileStandardInformation:
		mask = SMB_AT_STANDARD;
		getstd = B_TRUE;
		break;
	case FileInternalInformation:
		mask = SMB_AT_NODEID;
		break;
	case FileAllInformation:
		mask = SMB_AT_ALL;
		getstd = B_TRUE;
		getname = B_TRUE;
		break;

	case FileNameInformation:
		getname = B_TRUE;
		break;

	case FileAlternateNameInformation:
		mask = SMB_AT_NODEID;
		getname = B_TRUE;
		break;

	case FileStreamInformation:
		mask = SMB_AT_STANDARD;
		break;

	case FileCompressionInformation:
		mask = SMB_AT_SIZE | SMB_AT_ALLOCSZ;
		break;

	case FileNetworkOpenInformation:
		mask = SMB_AT_BASIC | SMB_AT_STANDARD;

	default:
		break;
	}

	qi->qi_attr.sa_mask = mask;
	qi->qi_node = of->f_node;
	if (mask & SMB_AT_ALL) {
		status = smb2_ofile_getattr(sr, of, &qi->qi_attr);
		if (status)
			return (status);
	}
	if (getstd) {
		status = smb2_ofile_getstd(of, qi);
		if (status)
			return (status);
	}
	if (getname) {
		status = smb2_ofile_getname(of, qi);
		if (status)
			return (status);
	}

	switch (qi->qi_InfoClass) {
	case FileBasicInformation:
		status = smb2_qif_basic(sr, qi);
		break;
	case FileStandardInformation:
		status = smb2_qif_standard(sr, qi);
		break;
	case FileInternalInformation:
		status = smb2_qif_internal(sr, qi);
		break;
	case FileEaInformation:
		status = smb2_qif_ea_size(sr, qi);
		break;
	case FileAccessInformation:
		status = smb2_qif_access(sr, qi);
		break;
	case FileNameInformation:
		status = smb2_qif_name(sr, qi);
		break;
	case FilePositionInformation:
		status = smb2_qif_position(sr, qi);
		break;
	case FileFullEaInformation:
		status = smb2_qif_full_ea(sr, qi);
		break;
	case FileModeInformation:
		status = smb2_qif_mode(sr, qi);
		break;
	case FileAlignmentInformation:
		status = smb2_qif_alignment(sr, qi);
		break;
	case FileAllInformation:
		status = smb2_qif_all(sr, qi);
		break;
	case FileAlternateNameInformation:
		status = smb2_qif_altname(sr, qi);
		break;
	case FileStreamInformation:
		status = smb2_qif_stream(sr, qi);
		break;
	case FilePipeInformation:
		status = smb2_qif_pipe(sr, qi);
		break;
	case FilePipeLocalInformation:
		status = smb2_qif_pipe_lcl(sr, qi);
		break;
	case FilePipeRemoteInformation:
		status = smb2_qif_pipe_rem(sr, qi);
		break;
	case FileCompressionInformation:
		status = smb2_qif_compr(sr, qi);
		break;
	case FileNetworkOpenInformation:
		status = smb2_qif_opens(sr, qi);
		break;
	case FileAttributeTagInformation:
		status = smb2_qif_tags(sr, qi);
		break;
	default:
		status = NT_STATUS_INVALID_INFO_CLASS;
		break;
	}

	return (status);
}

/*
 * FileAllInformation
 *
 * This returns a concatenation of:
 *	FileBasicInformation
 *	FileStandardInformation
 *	FileInternalInformation
 *	FileEaInformation
 *	FilePositionInformation
 *	FileModeInformation
 *	FileAlignmentInformation
 *	FileNameInformation
 */
static uint32_t
smb2_qif_all(smb_request_t *sr, smb_queryinfo_t *qi)
{
	uint32_t status;

	status = smb2_qif_basic(sr, qi);
	if (status)
		return (status);
	status = smb2_qif_standard(sr, qi);
	if (status)
		return (status);
	status = smb2_qif_internal(sr, qi);
	if (status)
		return (status);
	status = smb2_qif_ea_size(sr, qi);
	if (status)
		return (status);
	status = smb2_qif_position(sr, qi);
	if (status)
		return (status);
	status = smb2_qif_mode(sr, qi);
	if (status)
		return (status);
	status = smb2_qif_alignment(sr, qi);
	if (status)
		return (status);
	status = smb2_qif_name(sr, qi);
	if (status)
		return (status);

	return (0);
}

/*
 * FileBasicInformation
 * See also:
 *	case SMB_QUERY_FILE_BASIC_INFO:
 *	case SMB_FILE_BASIC_INFORMATION:
 */
static uint32_t
smb2_qif_basic(smb_request_t *sr, smb_queryinfo_t *qi)
{
	smb_attr_t *sa = &qi->qi_attr;

	ASSERT((sa->sa_mask & SMB_AT_BASIC) == SMB_AT_BASIC);

	(void) smb_mbc_encodef(
	    &sr->raw_data, "TTTTll",
	    &sa->sa_crtime,		/* T */
	    &sa->sa_vattr.va_atime,	/* T */
	    &sa->sa_vattr.va_mtime,	/* T */
	    &sa->sa_vattr.va_ctime,	/* T */
	    sa->sa_dosattr,		/* l */
	    0); /* reserved */		/* l */

	return (0);
}

/*
 * FileStandardInformation
 * See also:
 *	SMB_QUERY_FILE_STANDARD_INFO
 *	SMB_FILE_STANDARD_INFORMATION
 */
static uint32_t
smb2_qif_standard(smb_request_t *sr, smb_queryinfo_t *qi)
{
	smb_attr_t *sa = &qi->qi_attr;

	ASSERT((sa->sa_mask & SMB_AT_STANDARD) == SMB_AT_STANDARD);

	(void) smb_mbc_encodef(
	    &sr->raw_data, "qqlbbw",
	    sa->sa_allocsz,		/* q */
	    sa->sa_vattr.va_size,	/* q */
	    sa->sa_vattr.va_nlink,	/* l */
	    qi->qi_delete_on_close,	/* b */
	    qi->qi_isdir,		/* b */
	    0); /* reserved */		/* w */

	return (0);
}

/*
 * FileInternalInformation
 * See also:
 *	SMB_FILE_INTERNAL_INFORMATION
 */
static uint32_t
smb2_qif_internal(smb_request_t *sr, smb_queryinfo_t *qi)
{
	smb_attr_t *sa = &qi->qi_attr;

	ASSERT((sa->sa_mask & SMB_AT_NODEID) == SMB_AT_NODEID);

	(void) smb_mbc_encodef(
	    &sr->raw_data, "q",
	    sa->sa_vattr.va_nodeid);	/* q */

	return (0);
}

/*
 * FileEaInformation
 * See also:
 *	SMB_QUERY_FILE_EA_INFO
 *	SMB_FILE_EA_INFORMATION
 */
static uint32_t
smb2_qif_ea_size(smb_request_t *sr, smb_queryinfo_t *qi)
{
	_NOTE(ARGUNUSED(qi))

	(void) smb_mbc_encodef(
	    &sr->raw_data, "l", 0);

	return (0);
}

/*
 * FileFullEaInformation
 * We could put EAs in a named stream...
 */
/* ARGSUSED */
static uint32_t
smb2_qif_full_ea(smb_request_t *sr, smb_queryinfo_t *qi)
{
	return (NT_STATUS_NO_EAS_ON_FILE);
}

/*
 * FileAccessInformation
 */
static uint32_t
smb2_qif_access(smb_request_t *sr, smb_queryinfo_t *qi)
{
	_NOTE(ARGUNUSED(qi))
	smb_ofile_t *of = sr->fid_ofile;

	(void) smb_mbc_encodef(
	    &sr->raw_data, "l",
	    of->f_granted_access);

	return (0);
}

/*
 * FileNameInformation
 * See also:
 *	SMB_QUERY_FILE_NAME_INFO
 *	SMB_FILE_NAME_INFORMATION
 */
static uint32_t
smb2_qif_name(smb_request_t *sr, smb_queryinfo_t *qi)
{

	ASSERT(qi->qi_namelen > 0);

	(void) smb_mbc_encodef(
	    &sr->raw_data, "llU",
	    0, /* FileIndex	 (l) */
	    qi->qi_namelen,	/* l */
	    qi->qi_name);	/* U */

	return (0);
}

/*
 * FilePositionInformation
 */
static uint32_t
smb2_qif_position(smb_request_t *sr, smb_queryinfo_t *qi)
{
	_NOTE(ARGUNUSED(qi))
	smb_ofile_t *of = sr->fid_ofile;
	uint64_t pos;

	mutex_enter(&of->f_mutex);
	pos = of->f_seek_pos;
	mutex_exit(&of->f_mutex);

	(void) smb_mbc_encodef(
	    &sr->raw_data, "q", pos);

	return (0);
}

/*
 * FileModeInformation [MS-FSA 2.4.24]
 * XXX: These mode flags are supposed to be on the open handle,
 * XXX: or I think so.  Not yet...  (just put zero for now)
 */
static uint32_t
smb2_qif_mode(smb_request_t *sr, smb_queryinfo_t *qi)
{
	_NOTE(ARGUNUSED(qi))

	(void) smb_mbc_encodef(
	    &sr->raw_data, "l", 0);

	return (0);
}

/*
 * FileAlignmentInformation
 */
static uint32_t
smb2_qif_alignment(smb_request_t *sr, smb_queryinfo_t *qi)
{
	_NOTE(ARGUNUSED(qi))

	(void) smb_mbc_encodef(
	    &sr->raw_data, "l", 0);

	return (0);
}

/*
 * FileAlternateNameInformation
 * See also:
 *	SMB_QUERY_FILE_ALT_NAME_INFO
 *	SMB_FILE_ALT_NAME_INFORMATION
 */
static uint32_t
smb2_qif_altname(smb_request_t *sr, smb_queryinfo_t *qi)
{
	smb_ofile_t *of = sr->fid_ofile;

	ASSERT(qi->qi_namelen > 0);
	ASSERT(qi->qi_attr.sa_mask & SMB_AT_NODEID);

	if (of->f_ftype != SMB_FTYPE_DISK)
		return (NT_STATUS_OBJECT_NAME_NOT_FOUND);
	if ((of->f_tree->t_flags & SMB_TREE_SHORTNAMES) == 0)
		return (NT_STATUS_OBJECT_NAME_NOT_FOUND);

	/* fill in qi->qi_shortname */
	smb_query_shortname(of->f_node, qi);

	(void) smb_mbc_encodef(
	    &sr->raw_data, "%lU", sr,
	    smb_wcequiv_strlen(qi->qi_shortname),
	    qi->qi_shortname);

	return (0);
}

/*
 * FileStreamInformation
 */
static uint32_t
smb2_qif_stream(smb_request_t *sr, smb_queryinfo_t *qi)
{
	smb_ofile_t *of = sr->fid_ofile;
	smb_attr_t *attr = &qi->qi_attr;
	uint32_t status;

	ASSERT((attr->sa_mask & SMB_AT_STANDARD) == SMB_AT_STANDARD);
	if (of->f_ftype != SMB_FTYPE_DISK) {
		(void) smb_mbc_encodef(
		    &sr->raw_data, "l", 0);
		return (0);
	}

	status = smb_query_stream_info(sr, &sr->raw_data, qi);
	return (status);
}

/*
 * FilePipeInformation
 */
static uint32_t
smb2_qif_pipe(smb_request_t *sr, smb_queryinfo_t *qi)
{
	_NOTE(ARGUNUSED(qi))
	smb_ofile_t *of = sr->fid_ofile;
	uint32_t	pipe_mode;
	uint32_t	nonblock;

	switch (of->f_ftype) {
	case SMB_FTYPE_BYTE_PIPE:
		pipe_mode = 0;	/* FILE_PIPE_BYTE_STREAM_MODE */
		break;
	case SMB_FTYPE_MESG_PIPE:
		pipe_mode = 1;	/* FILE_PIPE_MESSAGE_MODE */
		break;
	case SMB_FTYPE_DISK:
	case SMB_FTYPE_PRINTER:
	default:
		return (NT_STATUS_INVALID_PARAMETER);
	}
	nonblock = 0;	/* XXX todo: Get this from the pipe handle. */

	(void) smb_mbc_encodef(
	    &sr->raw_data, "ll",
	    pipe_mode, nonblock);

	return (0);
}

/*
 * FilePipeLocalInformation
 */
/* ARGSUSED */
static uint32_t
smb2_qif_pipe_lcl(smb_request_t *sr, smb_queryinfo_t *qi)
{
	return (NT_STATUS_INVALID_PARAMETER); /* XXX todo */
}

/*
 * FilePipeRemoteInformation
 */
/* ARGSUSED */
static uint32_t
smb2_qif_pipe_rem(smb_request_t *sr, smb_queryinfo_t *qi)
{
	return (NT_STATUS_INVALID_PARAMETER); /* XXX todo */
}

/*
 * FileCompressionInformation
 * XXX: For now, just say "not compressed".
 */
static uint32_t
smb2_qif_compr(smb_request_t *sr, smb_queryinfo_t *qi)
{
	smb_attr_t *sa = &qi->qi_attr;
	uint16_t CompressionFormat = 0;	/* COMPRESSION_FORMAT_NONE */

	ASSERT(sa->sa_mask & SMB_AT_SIZE);

	(void) smb_mbc_encodef(
	    &sr->raw_data, "qw6.",
	    sa->sa_vattr.va_size,	/* q */
	    CompressionFormat);		/* w */

	return (0);
}

/*
 * FileNetworkOpenInformation
 */
static uint32_t
smb2_qif_opens(smb_request_t *sr, smb_queryinfo_t *qi)
{
	smb_attr_t *sa = &qi->qi_attr;

	(void) smb_mbc_encodef(
	    &sr->raw_data, "TTTTqqll",
	    &sa->sa_crtime,		/* T */
	    &sa->sa_vattr.va_atime,	/* T */
	    &sa->sa_vattr.va_mtime,	/* T */
	    &sa->sa_vattr.va_ctime,	/* T */
	    sa->sa_allocsz,		/* q */
	    sa->sa_vattr.va_size,	/* q */
	    sa->sa_dosattr,		/* l */
	    0); /* reserved */		/* l */

	return (0);
}

/*
 * FileAttributeTagInformation
 *
 * If dattr includes FILE_ATTRIBUTE_REPARSE_POINT, the
 * second dword should be the reparse tag.  Otherwise
 * the tag value should be set to zero.
 * We don't support reparse points, so we set the tag
 * to zero.
 */
static uint32_t
smb2_qif_tags(smb_request_t *sr, smb_queryinfo_t *qi)
{
	_NOTE(ARGUNUSED(qi))
	(void) smb_mbc_encodef(
	    &sr->raw_data, "ll", 0, 0);

	return (0);
}
