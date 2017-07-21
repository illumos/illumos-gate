/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_QUERY_DIRECTORY
 *
 * Similar to smb_trans2_find.c (from SMB1)
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb2_aapl.h>

/*
 * Internally defined info. level for MacOS support.
 * Make sure this does not conflict with real values in
 * FILE_INFORMATION_CLASS, and that it fits in 8-bits.
 */
#define	FileIdMacOsDirectoryInformation (FileMaximumInformation + 10)

/*
 * Args (and other state) that we carry around among the
 * various functions involved in SMB2 Query Directory.
 */
typedef struct smb2_find_args {
	uint32_t fa_maxdata;
	uint8_t fa_infoclass;
	uint8_t fa_fflags;
	uint16_t fa_maxcount;
	uint16_t fa_eos;	/* End Of Search */
	uint16_t fa_fixedsize;	/* size of fixed part of a returned entry */
	uint32_t fa_lastkey;	/* Last resume key */
	int fa_last_entry;	/* offset of last entry */

	/* Normal info, per dir. entry */
	smb_fileinfo_t fa_fi;

	/* MacOS AAPL extension stuff. */
	smb_macinfo_t fa_mi;
} smb2_find_args_t;

static uint32_t smb2_find_entries(smb_request_t *,
    smb_odir_t *, smb2_find_args_t *);
static uint32_t smb2_find_mbc_encode(smb_request_t *, smb2_find_args_t *);

/*
 * Tunable parameter to limit the maximum
 * number of entries to be returned.
 */
uint16_t smb2_find_max = 128;

smb_sdrc_t
smb2_query_dir(smb_request_t *sr)
{
	smb2_find_args_t args;
	smb_odir_resume_t odir_resume;
	smb_ofile_t *of = NULL;
	smb_odir_t *od = NULL;
	char *pattern = NULL;
	uint16_t StructSize;
	uint32_t FileIndex;
	uint16_t NameOffset;
	uint16_t NameLength;
	smb2fid_t smb2fid;
	uint16_t sattr = SMB_SEARCH_ATTRIBUTES;
	uint16_t DataOff;
	uint32_t DataLen;
	uint32_t status;
	int skip, rc = 0;

	bzero(&args, sizeof (args));
	bzero(&odir_resume, sizeof (odir_resume));

	/*
	 * SMB2 Query Directory request
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data, "wbblqqwwl",
	    &StructSize,		/* w */
	    &args.fa_infoclass,		/* b */
	    &args.fa_fflags,		/* b */
	    &FileIndex,			/* l */
	    &smb2fid.persistent,	/* q */
	    &smb2fid.temporal,		/* q */
	    &NameOffset,		/* w */
	    &NameLength,		/* w */
	    &args.fa_maxdata);		/* l */
	if (rc || StructSize != 33)
		return (SDRC_ERROR);

	status = smb2sr_lookup_fid(sr, &smb2fid);
	of = sr->fid_ofile;

	DTRACE_SMB2_START(op__QueryDirectory, smb_request_t *, sr);

	if (status)
		goto errout;

	/*
	 * If there's an input buffer (search pattern), decode it.
	 * Two times MAXNAMELEN because it represents the UNICODE string
	 * length in bytes.
	 */
	if (NameLength >= (2 * MAXNAMELEN)) {
		status = NT_STATUS_OBJECT_PATH_INVALID;
		goto errout;
	}
	if (NameLength != 0) {
		/*
		 * We're normally positioned at the pattern now,
		 * but there could be some padding before it.
		 */
		skip = (sr->smb2_cmd_hdr + NameOffset) -
		    sr->smb_data.chain_offset;
		if (skip < 0) {
			status = NT_STATUS_OBJECT_PATH_INVALID;
			goto errout;
		}
		if (skip > 0)
			(void) smb_mbc_decodef(&sr->smb_data, "#.", skip);
		rc = smb_mbc_decodef(&sr->smb_data, "%#U", sr,
		    NameLength, &pattern);
		if (rc || pattern == NULL) {
			status = NT_STATUS_OBJECT_PATH_INVALID;
			goto errout;
		}
	} else
		pattern = "*";

	/*
	 * Setup the output buffer.
	 */
	if (args.fa_maxdata > smb2_max_trans)
		args.fa_maxdata = smb2_max_trans;
	sr->raw_data.max_bytes = args.fa_maxdata;

	/*
	 * Get the fixed size of entries we will return, which
	 * lets us estimate the number of entries we'll need.
	 *
	 * Also use this opportunity to validate fa_infoclass.
	 */

	switch (args.fa_infoclass) {
	case FileDirectoryInformation:		/* 1 */
		args.fa_fixedsize = 64;
		break;
	case FileFullDirectoryInformation:	/* 2 */
		args.fa_fixedsize = 68;
		break;
	case FileBothDirectoryInformation:	/* 3 */
		args.fa_fixedsize = 94;
		break;
	case FileNamesInformation:		/* 12 */
		args.fa_fixedsize = 12;
		break;
	case FileIdBothDirectoryInformation:	/* 37 */
		args.fa_fixedsize = 96;
		break;
	case FileIdFullDirectoryInformation:	/* 38 */
		args.fa_fixedsize = 84;
		break;
	default:
		status = NT_STATUS_INVALID_INFO_CLASS;
		goto errout;
	}

	/*
	 * MacOS, when using the AAPL CreateContext extensions
	 * and the "read dir attr" feature, uses a non-standard
	 * information format for directory entries.  Internally
	 * we'll use a fake info level to represent this case.
	 * (Wish they had just defined a new info level.)
	 */
	if ((sr->session->s_flags & SMB_SSN_AAPL_READDIR) != 0 &&
	    args.fa_infoclass == FileIdBothDirectoryInformation) {
		args.fa_infoclass = FileIdMacOsDirectoryInformation;
		args.fa_fixedsize = 96; /* yes, same size */
	}

	args.fa_maxcount = args.fa_maxdata / (args.fa_fixedsize + 4);
	if (args.fa_maxcount == 0)
		args.fa_maxcount = 1;
	if ((smb2_find_max != 0) && (args.fa_maxcount > smb2_find_max))
		args.fa_maxcount = smb2_find_max;
	if (args.fa_fflags & SMB2_QDIR_FLAG_SINGLE)
		args.fa_maxcount = 1;

	/*
	 * If this ofile does not have an odir yet, get one.
	 */
	mutex_enter(&of->f_mutex);
	if ((od = of->f_odir) == NULL) {
		status = smb_odir_openfh(sr, pattern, sattr, &od);
		of->f_odir = od;
	}
	mutex_exit(&of->f_mutex);
	if (od == NULL) {
		if (status == 0)
			status = NT_STATUS_INTERNAL_ERROR;
		goto errout;
	}

	/*
	 * "Reopen" sets a new pattern and restart.
	 */
	if (args.fa_fflags & SMB2_QDIR_FLAG_REOPEN) {
		smb_odir_reopen(od, pattern, sattr);
	}

	/*
	 * Set the correct position in the directory.
	 */
	if (args.fa_fflags & SMB2_QDIR_FLAG_RESTART) {
		odir_resume.or_type = SMB_ODIR_RESUME_COOKIE;
		odir_resume.or_cookie = 0;
	} else if (args.fa_fflags & SMB2_QDIR_FLAG_INDEX) {
		odir_resume.or_type = SMB_ODIR_RESUME_COOKIE;
		odir_resume.or_cookie = FileIndex;
	} else {
		odir_resume.or_type = SMB_ODIR_RESUME_CONT;
	}
	smb_odir_resume_at(od, &odir_resume);
	of->f_seek_pos = od->d_offset;

	/*
	 * The real work of readdir and format conversion.
	 */
	status = smb2_find_entries(sr, od, &args);

	of->f_seek_pos = od->d_offset;

	if ((args.fa_fflags & SMB2_QDIR_FLAG_SINGLE) &&
	    status == NT_STATUS_NO_MORE_FILES) {
		status = NT_STATUS_NO_SUCH_FILE;
	}

errout:
	sr->smb2_status = status;
	DTRACE_SMB2_DONE(op__QueryDirectory, smb_request_t *, sr);

	/*
	 * Note: NT_STATUS_NO_MORE_FILES is a warning
	 * used to tell the client that this data return
	 * is the last of the enumeration.  Returning this
	 * warning now (with the data) saves the client a
	 * round trip that would otherwise be needed to
	 * find out it's at the end.
	 */
	if (status != 0 &&
	    status != NT_STATUS_NO_MORE_FILES) {
		smb2sr_put_error(sr, status);
		return (SDRC_SUCCESS);
	}

	/*
	 * SMB2 Query Directory reply
	 */
	StructSize = 9;
	DataOff = SMB2_HDR_SIZE + 8;
	DataLen = MBC_LENGTH(&sr->raw_data);
	rc = smb_mbc_encodef(
	    &sr->reply, "wwlC",
	    StructSize,		/* w */
	    DataOff,		/* w */
	    DataLen,		/* l */
	    &sr->raw_data);	/* C */
	if (DataLen == 0)
		(void) smb_mbc_encodef(&sr->reply, ".");

	if (rc)
		sr->smb2_status = NT_STATUS_INTERNAL_ERROR;

	return (SDRC_SUCCESS);
}

/*
 * smb2_find_entries
 *
 * Find and encode up to args->fa_maxcount directory entries.
 *
 * Returns:
 *   NT status
 */
static uint32_t
smb2_find_entries(smb_request_t *sr, smb_odir_t *od, smb2_find_args_t *args)
{
	smb_odir_resume_t odir_resume;
	char		*tbuf = NULL;
	size_t		tbuflen = 0;
	uint16_t	count;
	uint16_t	minsize;
	uint32_t	status = 0;
	int		rc = -1;

	/*
	 * Let's stop when the remaining space will not hold a
	 * minimum size entry.  That's the fixed part plus the
	 * storage size of a 1 char unicode string.
	 */
	minsize = args->fa_fixedsize + 2;

	/*
	 * FileIdMacOsDirectoryInformation needs some buffer space
	 * for composing directory entry + stream name for lookup.
	 * Get the buffer now to avoid alloc/free per entry.
	 */
	if (args->fa_infoclass == FileIdMacOsDirectoryInformation) {
		tbuflen = 2 * MAXNAMELEN;
		tbuf = kmem_alloc(tbuflen, KM_SLEEP);
	}

	count = 0;
	while (count < args->fa_maxcount) {

		if (!MBC_ROOM_FOR(&sr->raw_data, minsize)) {
			status = NT_STATUS_BUFFER_OVERFLOW;
			break;
		}

		rc = smb_odir_read_fileinfo(sr, od,
		    &args->fa_fi, &args->fa_eos);
		if (rc == ENOENT) {
			status = NT_STATUS_NO_MORE_FILES;
			break;
		}
		if (rc != 0) {
			status = smb_errno2status(rc);
			break;
		}
		if (args->fa_eos != 0) {
			/* The readdir call hit the end. */
			status = NT_STATUS_NO_MORE_FILES;
			break;
		}

		if (args->fa_infoclass == FileIdMacOsDirectoryInformation)
			(void) smb2_aapl_get_macinfo(sr, od,
			    &args->fa_fi, &args->fa_mi, tbuf, tbuflen);

		if (smb2_aapl_use_file_ids == 0 &&
		    (sr->session->s_flags & SMB_SSN_AAPL_CCEXT) != 0)
			args->fa_fi.fi_nodeid = 0;

		status = smb2_find_mbc_encode(sr, args);
		if (status) {
			/*
			 * We read a directory entry but failed to
			 * copy it into the output buffer.  Rewind
			 * the directory pointer so this will be
			 * the first entry read next time.
			 */
			bzero(&odir_resume, sizeof (odir_resume));
			odir_resume.or_type = SMB_ODIR_RESUME_COOKIE;
			odir_resume.or_cookie = args->fa_lastkey;
			smb_odir_resume_at(od, &odir_resume);
			break;
		}

		/*
		 * Save the offset of the next entry we'll read.
		 * If we fail copying, we'll need this offset.
		 */
		args->fa_lastkey = args->fa_fi.fi_cookie;
		++count;
	}

	if (count == 0) {
		ASSERT(status != 0);
	} else {
		/*
		 * We copied some directory entries, but stopped for
		 * NT_STATUS_NO_MORE_FILES, or something.
		 *
		 * Per [MS-FSCC] sec. 2.4, the last entry in the
		 * enumeration MUST have its NextEntryOffset value
		 * set to zero.  Overwrite that in the last entry.
		 */
		(void) smb_mbc_poke(&sr->raw_data,
		    args->fa_last_entry, "l", 0);
		status = 0;
	}

	if (tbuf != NULL)
		kmem_free(tbuf, tbuflen);

	return (status);
}

/*
 * smb2_mbc_encode
 *
 * This function encodes the mbc for one directory entry.
 *
 * The function returns -1 when the max data requested by client
 * is reached. If the entry is valid and successful encoded, 0
 * will be returned; otherwise, 1 will be returned.
 *
 * We always null terminate the filename. The space for the null
 * is included in the maxdata calculation and is therefore included
 * in the next_entry_offset. namelen is the unterminated length of
 * the filename. For levels except STANDARD and EA_SIZE, if the
 * filename is ascii the name length returned to the client should
 * include the null terminator. Otherwise the length returned to
 * the client should not include the terminator.
 *
 * Returns: 0 - data successfully encoded
 *      NT status
 */
static uint32_t
smb2_find_mbc_encode(smb_request_t *sr, smb2_find_args_t *args)
{
	smb_fileinfo_t	*fileinfo = &args->fa_fi;
	smb_macinfo_t	*macinfo = &args->fa_mi;
	uint8_t		buf83[26];
	smb_msgbuf_t	mb;
	int		namelen;
	int		shortlen = 0;
	int		rc, starting_offset;
	uint32_t	next_entry_offset;
	uint32_t	mb_flags = SMB_MSGBUF_UNICODE;
	uint32_t	resume_key;

	namelen = smb_wcequiv_strlen(fileinfo->fi_name);
	if (namelen == -1)
		return (NT_STATUS_INTERNAL_ERROR);

	/*
	 * Keep track of where the last entry starts so we can
	 * come back and poke the NextEntryOffset field.  Also,
	 * after enumeration finishes, the caller uses this to
	 * poke the last entry again with zero to mark it as
	 * the end of the enumeration.
	 */
	starting_offset = sr->raw_data.chain_offset;

	/*
	 * Technically (per MS-SMB2) resume keys are optional.
	 * Windows doesn't need them, but MacOS does.
	 */
	resume_key = fileinfo->fi_cookie;

	/*
	 * This switch handles all the "information levels" (formats)
	 * that we support.  Note that all formats have the file name
	 * placed after some fixed-size data, and the code to write
	 * the file name is factored out at the end of this switch.
	 */
	switch (args->fa_infoclass) {

	/* See also: SMB_FIND_FILE_DIRECTORY_INFO */
	case FileDirectoryInformation:		/* 1 */
		rc = smb_mbc_encodef(
		    &sr->raw_data, "llTTTTqqll",
		    0,	/* NextEntryOffset (set later) */
		    resume_key,
		    &fileinfo->fi_crtime,
		    &fileinfo->fi_atime,
		    &fileinfo->fi_mtime,
		    &fileinfo->fi_ctime,
		    fileinfo->fi_size,
		    fileinfo->fi_alloc_size,
		    fileinfo->fi_dosattr,
		    namelen);
		break;

	/* See also: SMB_FIND_FILE_FULL_DIRECTORY_INFO */
	case FileFullDirectoryInformation:	/* 2 */
		rc = smb_mbc_encodef(
		    &sr->raw_data, "llTTTTqqlll",
		    0,	/* NextEntryOffset (set later) */
		    resume_key,
		    &fileinfo->fi_crtime,
		    &fileinfo->fi_atime,
		    &fileinfo->fi_mtime,
		    &fileinfo->fi_ctime,
		    fileinfo->fi_size,
		    fileinfo->fi_alloc_size,
		    fileinfo->fi_dosattr,
		    namelen,
		    0L);	/* EaSize */
		break;

	/* See also: SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO */
	case FileIdFullDirectoryInformation:	/* 38 */
		rc = smb_mbc_encodef(
		    &sr->raw_data, "llTTTTqqllllq",
		    0,	/* NextEntryOffset (set later) */
		    resume_key,
		    &fileinfo->fi_crtime,
		    &fileinfo->fi_atime,
		    &fileinfo->fi_mtime,
		    &fileinfo->fi_ctime,
		    fileinfo->fi_size,
		    fileinfo->fi_alloc_size,
		    fileinfo->fi_dosattr,
		    namelen,
		    0L,		/* EaSize */
		    0L,		/* reserved */
		    fileinfo->fi_nodeid);
		break;

	/* See also: SMB_FIND_FILE_BOTH_DIRECTORY_INFO */
	case FileBothDirectoryInformation:	/* 3 */
		bzero(buf83, sizeof (buf83));
		smb_msgbuf_init(&mb, buf83, sizeof (buf83), mb_flags);
		if (!smb_msgbuf_encode(&mb, "U", fileinfo->fi_shortname))
			shortlen = smb_wcequiv_strlen(fileinfo->fi_shortname);

		rc = smb_mbc_encodef(
		    &sr->raw_data, "llTTTTqqlllb.24c",
		    0,	/* NextEntryOffset (set later) */
		    resume_key,
		    &fileinfo->fi_crtime,
		    &fileinfo->fi_atime,
		    &fileinfo->fi_mtime,
		    &fileinfo->fi_ctime,
		    fileinfo->fi_size,
		    fileinfo->fi_alloc_size,
		    fileinfo->fi_dosattr,
		    namelen,
		    0L,		/* EaSize */
		    shortlen,
		    buf83);

		smb_msgbuf_term(&mb);
		break;

	/* See also: SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO */
	case FileIdBothDirectoryInformation:	/* 37 */
		bzero(buf83, sizeof (buf83));
		smb_msgbuf_init(&mb, buf83, sizeof (buf83), mb_flags);
		if (!smb_msgbuf_encode(&mb, "U", fileinfo->fi_shortname))
			shortlen = smb_wcequiv_strlen(fileinfo->fi_shortname);

		rc = smb_mbc_encodef(
		    &sr->raw_data, "llTTTTqqlllb.24c..q",
		    0,	/* NextEntryOffset (set later) */
		    resume_key,
		    &fileinfo->fi_crtime,
		    &fileinfo->fi_atime,
		    &fileinfo->fi_mtime,
		    &fileinfo->fi_ctime,
		    fileinfo->fi_size,		/* q */
		    fileinfo->fi_alloc_size,	/* q */
		    fileinfo->fi_dosattr,	/* l */
		    namelen,			/* l */
		    0L,		/* EaSize	   l */
		    shortlen,			/* b. */
		    buf83,			/* 24c */
		    /* reserved			   .. */
		    fileinfo->fi_nodeid);	/* q */

		smb_msgbuf_term(&mb);
		break;

	/*
	 * MacOS, when using the AAPL extensions (see smb2_create)
	 * uses modified directory listing responses where the
	 * "EA size" field is replaced with "maximum access".
	 * This avoids the need for MacOS Finder to come back
	 * N times to get the maximum access for every file.
	 */
	case FileIdMacOsDirectoryInformation:
		rc = smb_mbc_encodef(
		    &sr->raw_data, "llTTTTqqll",
		    0,	/* NextEntryOffset (set later) */
		    resume_key,		/* a.k.a. file index */
		    &fileinfo->fi_crtime,
		    &fileinfo->fi_atime,
		    &fileinfo->fi_mtime,
		    &fileinfo->fi_ctime,
		    fileinfo->fi_size,		/* q */
		    fileinfo->fi_alloc_size,	/* q */
		    fileinfo->fi_dosattr,	/* l */
		    namelen);			/* l */
		if (rc != 0)
			break;
		/*
		 * This where FileIdMacOsDirectoryInformation
		 * differs from FileIdBothDirectoryInformation
		 * Instead of: EaSize, ShortNameLen, ShortName;
		 * MacOS wants: MaxAccess, ResourceForkSize, and
		 * 16 bytes of "compressed finder info".
		 * mi_rforksize + mi_finderinfo falls where
		 * the 24 byte shortname would normally be.
		 */
		rc = smb_mbc_encodef(
		    &sr->raw_data, "l..q16cwq",
		    macinfo->mi_maxaccess,	/* l */
		    /* short_name_len, reserved  (..) */
		    macinfo->mi_rforksize,	/* q */
		    macinfo->mi_finderinfo,	/* 16c */
		    macinfo->mi_unixmode,	/* w */
		    fileinfo->fi_nodeid);	/* q */
		break;

	/* See also: SMB_FIND_FILE_NAMES_INFO */
	case FileNamesInformation:		/* 12 */
		rc = smb_mbc_encodef(
		    &sr->raw_data, "lll",
		    0,	/* NextEntryOffset (set later) */
		    resume_key,
		    namelen);
		break;

	default:
		return (NT_STATUS_INVALID_INFO_CLASS);
	}
	if (rc)	/* smb_mbc_encodef failed */
		return (NT_STATUS_BUFFER_OVERFLOW);

	/*
	 * At this point we have written all the fixed-size data
	 * for the specified info. class.  Now put the name and
	 * alignment padding, and then patch the NextEntryOffset.
	 * Also store this offset for the caller so they can
	 * patch this (again) to zero on the very last entry.
	 */
	rc = smb_mbc_encodef(
	    &sr->raw_data, "U",
	    fileinfo->fi_name);
	if (rc)
		return (NT_STATUS_BUFFER_OVERFLOW);

	/* Next entry needs to be 8-byte aligned. */
	(void) smb_mbc_put_align(&sr->raw_data, 8);

	next_entry_offset = sr->raw_data.chain_offset -	starting_offset;
	(void) smb_mbc_poke(&sr->raw_data, starting_offset, "l",
	    next_entry_offset);
	args->fa_last_entry = starting_offset;

	return (0);
}
