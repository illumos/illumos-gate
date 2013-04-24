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
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * This module provides functions for TRANS2_FIND_FIRST2 and
 * TRANS2_FIND_NEXT2 requests. The requests allow the client to search
 * for the file(s) which match the file specification.  The search is
 * started with TRANS2_FIND_FIRST2 and can be continued if necessary with
 * TRANS2_FIND_NEXT2. There are numerous levels of information which may be
 * obtained for the returned files, the desired level is specified in the
 * InformationLevel field of the requests.
 *
 *  InformationLevel Name              Value
 *  =================================  ================
 *
 *  SMB_INFO_STANDARD                  1
 *  SMB_INFO_QUERY_EA_SIZE             2
 *  SMB_INFO_QUERY_EAS_FROM_LIST       3
 *  SMB_FIND_FILE_DIRECTORY_INFO       0x101
 *  SMB_FIND_FILE_FULL_DIRECTORY_INFO  0x102
 *  SMB_FIND_FILE_NAMES_INFO           0x103
 *  SMB_FIND_FILE_BOTH_DIRECTORY_INFO  0x104
 *  SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO  0x105
 *  SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO  0x106
 *
 * The following sections detail the data returned for each
 * InformationLevel. The requested information is placed in the Data
 * portion of the transaction response. Note: a client which does not
 * support long names can only request SMB_INFO_STANDARD.
 *
 * A four-byte resume key precedes each data item (described below) if bit
 * 2 in the Flags field is set, i.e. if the request indicates the server
 * should return resume keys. Note: it is not always the case. If the
 * data item already includes the resume key, the resume key should not be
 * added again.
 *
 * 4.3.4.1   SMB_INFO_STANDARD
 *
 *  Response Field                    Description
 *  ================================  ==================================
 *
 *  SMB_DATE CreationDate;            Date when file was created
 *  SMB_TIME CreationTime;            Time when file was created
 *  SMB_DATE LastAccessDate;          Date of last file access
 *  SMB_TIME LastAccessTime;          Time of last file access
 *  SMB_DATE LastWriteDate;           Date of last write to the file
 *  SMB_TIME LastWriteTime;           Time of last write to the file
 *  ULONG  DataSize;                  File Size
 *  ULONG AllocationSize;             Size of filesystem allocation unit
 *  USHORT Attributes;                File Attributes
 *  UCHAR FileNameLength;             Length of filename in bytes
 *  STRING FileName;                  Name of found file
 *
 * 4.3.4.2   SMB_INFO_QUERY_EA_SIZE
 *
 *  Response Field                     Description
 *  =================================  ==================================
 *
 *   SMB_DATE CreationDate;            Date when file was created
 *   SMB_TIME CreationTime;            Time when file was created
 *   SMB_DATE LastAccessDate;          Date of last file access
 *   SMB_TIME LastAccessTime;          Time of last file access
 *   SMB_DATE LastWriteDate;           Date of last write to the file
 *   SMB_TIME LastWriteTime;           Time of last write to the file
 *   ULONG DataSize;                   File Size
 *   ULONG AllocationSize;             Size of filesystem allocation unit
 *   USHORT Attributes;                File Attributes
 *   ULONG EaSize;                     Size of file's EA information
 *   UCHAR FileNameLength;             Length of filename in bytes
 *   STRING FileName;                  Name of found file
 *
 * 4.3.4.3   SMB_INFO_QUERY_EAS_FROM_LIST
 *
 * This request returns the same information as SMB_INFO_QUERY_EA_SIZE, but
 * only for files which have an EA list which match the EA information in
 * the Data part of the request.
 *
 * 4.3.4.4   SMB_FIND_FILE_DIRECTORY_INFO
 *
 *  Response Field                     Description
 *  =================================  ==================================
 *
 *  ULONG NextEntryOffset;             Offset from this structure to
 *					beginning of next one
 *  ULONG FileIndex;
 *  LARGE_INTEGER CreationTime;        file creation time
 *  LARGE_INTEGER LastAccessTime;      last access time
 *  LARGE_INTEGER LastWriteTime;       last write time
 *  LARGE_INTEGER ChangeTime;          last attribute change time
 *  LARGE_INTEGER EndOfFile;           file size
 *  LARGE_INTEGER AllocationSize;      size of filesystem allocation information
 *  ULONG ExtFileAttributes;           Extended file attributes
 *					(see section 3.11)
 *  ULONG FileNameLength;              Length of filename in bytes
 *  STRING FileName;                   Name of the file
 *
 * 4.3.4.5   SMB_FIND_FILE_FULL_DIRECTORY_INFO
 *
 *  Response Field                     Description
 *  =================================  ==================================
 *
 *  ULONG NextEntryOffset;             Offset from this structure to
 *					beginning of next one
 *  ULONG FileIndex;
 *  LARGE_INTEGER CreationTime;        file creation time
 *  LARGE_INTEGER LastAccessTime;      last access time
 *  LARGE_INTEGER LastWriteTime;       last write time
 *  LARGE_INTEGER ChangeTime;          last attribute change time
 *  LARGE_INTEGER EndOfFile;           file size
 *  LARGE_INTEGER AllocationSize;      size of filesystem allocation information
 *  ULONG ExtFileAttributes;           Extended file attributes
 *					(see section 3.11)
 *  ULONG FileNameLength;              Length of filename in bytes
 *  ULONG EaSize;                      Size of file's extended attributes
 *  STRING FileName;                   Name of the file
 *
 *
 *  SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO
 *
 *  This is the same as SMB_FIND_FILE_FULL_DIRECTORY_INFO but with
 *  FileId inserted after EaSize. FileId is preceded by a 4 byte
 *  alignment padding.
 *
 *  Response Field                     Description
 *  =================================  ==================================
 *  ...
 *  ULONG EaSize;                      Size of file's extended attributes
 *  UCHAR Reserved[4]
 *  LARGE_INTEGER FileId               Internal file system unique id.
 *  STRING FileName;                   Name of the file
 *
 * 4.3.4.6   SMB_FIND_FILE_BOTH_DIRECTORY_INFO
 *
 *  Response Field                     Description
 *  =================================  ==================================
 *
 *  ULONG NextEntryOffset;             Offset from this structure to
 *					beginning of next one
 *  ULONG FileIndex;
 *  LARGE_INTEGER CreationTime;        file creation time
 *  LARGE_INTEGER LastAccessTime;      last access time
 *  LARGE_INTEGER LastWriteTime;       last write time
 *  LARGE_INTEGER ChangeTime;          last attribute change time
 *  LARGE_INTEGER EndOfFile;           file size
 *  LARGE_INTEGER AllocationSize;      size of filesystem allocation information
 *  ULONG ExtFileAttributes;           Extended file attributes
 *					(see section 3.11)
 *  ULONG FileNameLength;              Length of FileName in bytes
 *  ULONG EaSize;                      Size of file's extended attributes
 *  UCHAR ShortNameLength;             Length of file's short name in bytes
 *  UCHAR Reserved
 *  WCHAR ShortName[12];               File's 8.3 conformant name in Unicode
 *  STRING FileName;                   Files full length name
 *
 *
 *  SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO
 *
 *  This is the same as SMB_FIND_FILE_BOTH_DIRECTORY_INFO but with
 *  FileId inserted after ShortName. FileId is preceded by a 2 byte
 *  alignment pad.
 *
 *  Response Field                     Description
 *  =================================  ==================================
 *  ...
 *  WCHAR ShortName[12];               File's 8.3 conformant name in Unicode
 *  UCHAR Reserved[2]
 *  LARGE_INTEGER FileId               Internal file system unique id.
 *  STRING FileName;                   Files full length name
 *
 * 4.3.4.7   SMB_FIND_FILE_NAMES_INFO
 *
 *  Response Field                     Description
 *  =================================  ==================================
 *
 *  ULONG NextEntryOffset;             Offset from this structure to
 *                                     beginning of next one
 *  ULONG FileIndex;
 *  ULONG FileNameLength;              Length of FileName in bytes
 *  STRING FileName;                   Files full length name
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/msgbuf.h>
#include <smbsrv/smb_fsops.h>

/*
 * Args (and other state) that we carry around among the
 * various functions involved in FindFirst, FindNext.
 */
typedef struct smb_find_args {
	uint32_t fa_maxdata;
	uint16_t fa_infolev;
	uint16_t fa_maxcount;
	uint16_t fa_fflag;
	uint16_t fa_eos;	/* End Of Search */
	uint16_t fa_lno;	/* Last Name Offset */
	uint32_t fa_lastkey;	/* Last resume key */
	char fa_lastname[MAXNAMELEN]; /* and name */
} smb_find_args_t;

static int smb_trans2_find_entries(smb_request_t *, smb_xa_t *,
    smb_odir_t *, smb_find_args_t *);
static int smb_trans2_find_get_maxdata(smb_request_t *, uint16_t, uint16_t);
static int smb_trans2_find_mbc_encode(smb_request_t *, smb_xa_t *,
    smb_fileinfo_t *, smb_find_args_t *);

/*
 * Tunable parameter to limit the maximum
 * number of entries to be returned.
 */
uint16_t smb_trans2_find_max = 128;

/*
 * smb_com_trans2_find_first2
 *
 *  Client Request                Value
 *  ============================  ==================================
 *
 *  UCHAR  WordCount              15
 *  UCHAR  TotalDataCount         Total size of extended attribute list
 *  UCHAR  SetupCount             1
 *  UCHAR  Setup[0]               TRANS2_FIND_FIRST2
 *
 *  Parameter Block Encoding      Description
 *  ============================  ==================================
 *  USHORT SearchAttributes;
 *  USHORT SearchCount;           Maximum number of entries to return
 *  USHORT Flags;                 Additional information:
 *                                Bit 0 - close search after this request
 *                                Bit 1 - close search if end of search
 *                                reached
 *                                Bit 2 - return resume keys for each
 *                                entry found
 *                                Bit 3 - continue search from previous
 *                                ending place
 *                                Bit 4 - find with backup intent
 *  USHORT InformationLevel;      See below
 *  ULONG SearchStorageType;
 *  STRING FileName;              Pattern for the search
 *  UCHAR Data[ TotalDataCount ]  FEAList if InformationLevel is
 *                                QUERY_EAS_FROM_LIST
 *
 *  Response Parameter Block      Description
 *  ============================  ==================================
 *
 *  USHORT Sid;                   Search handle
 *  USHORT SearchCount;           Number of entries returned
 *  USHORT EndOfSearch;           Was last entry returned?
 *  USHORT EaErrorOffset;         Offset into EA list if EA error
 *  USHORT LastNameOffset;        Offset into data to file name of last
 *                                entry, if server needs it to resume
 *                                search; else 0
 *  UCHAR Data[ TotalDataCount ]  Level dependent info about the matches
 *                                found in the search
 */
smb_sdrc_t
smb_com_trans2_find_first2(smb_request_t *sr, smb_xa_t *xa)
{
	int		count;
	uint16_t	sattr, odid;
	smb_pathname_t	*pn;
	smb_odir_t	*od;
	smb_find_args_t	args;
	uint32_t	odir_flags = 0;

	bzero(&args, sizeof (smb_find_args_t));

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	pn = &sr->arg.dirop.fqi.fq_path;

	if (smb_mbc_decodef(&xa->req_param_mb, "%wwww4.u", sr, &sattr,
	    &args.fa_maxcount, &args.fa_fflag, &args.fa_infolev,
	    &pn->pn_path) != 0) {
		return (SDRC_ERROR);
	}

	smb_pathname_init(sr, pn, pn->pn_path);
	if (!smb_pathname_validate(sr, pn))
		return (-1);

	if (smb_is_stream_name(pn->pn_path)) {
		smbsr_error(sr, NT_STATUS_OBJECT_NAME_INVALID,
		    ERRDOS, ERROR_INVALID_NAME);
		return (SDRC_ERROR);
	}

	if (args.fa_fflag & SMB_FIND_WITH_BACKUP_INTENT) {
		sr->user_cr = smb_user_getprivcred(sr->uid_user);
		odir_flags = SMB_ODIR_OPENF_BACKUP_INTENT;
	}

	args.fa_maxdata =
	    smb_trans2_find_get_maxdata(sr, args.fa_infolev, args.fa_fflag);
	if (args.fa_maxdata == 0)
		return (SDRC_ERROR);

	odid = smb_odir_open(sr, pn->pn_path, sattr, odir_flags);
	if (odid == 0) {
		if (sr->smb_error.status == NT_STATUS_OBJECT_PATH_NOT_FOUND) {
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_NOT_FOUND,
			    ERRDOS, ERROR_FILE_NOT_FOUND);
		}
		return (SDRC_ERROR);
	}

	od = smb_tree_lookup_odir(sr, odid);
	if (od == NULL)
		return (SDRC_ERROR);

	count = smb_trans2_find_entries(sr, xa, od, &args);

	if (count == -1) {
		smb_odir_close(od);
		smb_odir_release(od);
		return (SDRC_ERROR);
	}

	if (count == 0) {
		smb_odir_close(od);
		smb_odir_release(od);
		smbsr_errno(sr, ENOENT);
		return (SDRC_ERROR);
	}

	if ((args.fa_fflag & SMB_FIND_CLOSE_AFTER_REQUEST) ||
	    (args.fa_eos && (args.fa_fflag & SMB_FIND_CLOSE_AT_EOS))) {
		smb_odir_close(od);
	} /* else leave odir open for trans2_find_next2 */

	smb_odir_release(od);

	(void) smb_mbc_encodef(&xa->rep_param_mb, "wwwww",
	    odid,	/* Search ID */
	    count,	/* Search Count */
	    args.fa_eos, /* End Of Search */
	    0,		/* EA Error Offset */
	    args.fa_lno); /* Last Name Offset */

	return (SDRC_SUCCESS);
}

/*
 * smb_com_trans2_find_next2
 *
 *  Client Request                     Value
 *  ================================== =================================
 *
 *  WordCount                          15
 *  SetupCount                         1
 *  Setup[0]                           TRANS2_FIND_NEXT2
 *
 *  Parameter Block Encoding           Description
 *  ================================== =================================
 *
 *  USHORT Sid;                        Search handle
 *  USHORT SearchCount;                Maximum number of entries to
 *                                      return
 *  USHORT InformationLevel;           Levels described in
 *                                      TRANS2_FIND_FIRST2 request
 *  ULONG ResumeKey;                   Value returned by previous find2
 *                                      call
 *  USHORT Flags;                      Additional information: bit set-
 *                                      0 - close search after this
 *                                      request
 *                                      1 - close search if end of search
 *                                      reached
 *                                      2 - return resume keys for each
 *                                      entry found
 *                                      3 - resume/continue from previous
 *                                      ending place
 *                                      4 - find with backup intent
 *  STRING FileName;                   Resume file name
 *
 * Sid is the value returned by a previous successful TRANS2_FIND_FIRST2
 * call.  If Bit3 of Flags is set, then FileName may be the NULL string,
 * since the search is continued from the previous TRANS2_FIND request.
 * Otherwise, FileName must not be more than 256 characters long.
 *
 *  Response Field                     Description
 *  ================================== =================================
 *
 *  USHORT SearchCount;                Number of entries returned
 *  USHORT EndOfSearch;                Was last entry returned?
 *  USHORT EaErrorOffset;              Offset into EA list if EA error
 *  USHORT LastNameOffset;             Offset into data to file name of
 *                                      last entry, if server needs it to
 *                                      resume search; else 0
 *  UCHAR Data[TotalDataCount]         Level dependent info about the
 *                                      matches found in the search
 *
 *
 * The last parameter in the request is a filename, which is a
 * null-terminated unicode string.
 *
 * smb_mbc_decodef(&xa->req_param_mb, "%www lwu", sr,
 *    &odid, &fa_maxcount, &fa_infolev, &cookie, &fa_fflag, &fname)
 *
 * The filename parameter is not currently decoded because we
 * expect a 2-byte null but Mac OS 10 clients send a 1-byte null,
 * which leads to a decode error.
 * Thus, we do not support resume by filename.  We treat a request
 * to resume by filename as SMB_FIND_CONTINUE_FROM_LAST.
 */
smb_sdrc_t
smb_com_trans2_find_next2(smb_request_t *sr, smb_xa_t *xa)
{
	int			count;
	uint16_t		odid;
	smb_odir_t		*od;
	smb_find_args_t		args;
	smb_odir_resume_t	odir_resume;

	bzero(&args, sizeof (args));
	bzero(&odir_resume, sizeof (odir_resume));

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	if (smb_mbc_decodef(&xa->req_param_mb, "%wwwlwu", sr,
	    &odid, &args.fa_maxcount, &args.fa_infolev,
	    &odir_resume.or_cookie, &args.fa_fflag,
	    &odir_resume.or_fname) != 0) {
		return (SDRC_ERROR);
	}

	if (args.fa_fflag & SMB_FIND_WITH_BACKUP_INTENT)
		sr->user_cr = smb_user_getprivcred(sr->uid_user);

	args.fa_maxdata =
	    smb_trans2_find_get_maxdata(sr, args.fa_infolev, args.fa_fflag);
	if (args.fa_maxdata == 0)
		return (SDRC_ERROR);

	od = smb_tree_lookup_odir(sr, odid);
	if (od == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE,
		    ERRDOS, ERROR_INVALID_HANDLE);
		return (SDRC_ERROR);
	}

	/*
	 * Set the correct position in the directory.
	 *
	 * "Continue from last" is easy, but due to a history of
	 * buggy server implementations, most clients don't use
	 * that method.  The most widely used (and reliable) is
	 * resume by file name.  Unfortunately, that can't really
	 * be fully supported unless your file system stores all
	 * directory entries in some sorted order (like NTFS).
	 * We can partially support resume by name, where the only
	 * name we're ever asked to resume on is the same as the
	 * most recent we returned.  That's always what the client
	 * gives us as the resume name, so we can simply remember
	 * the last name/offset pair and use that to position on
	 * the following FindNext call.  In the unlikely event
	 * that the client asks to resume somewhere else, we'll
	 * use the numeric resume key, and hope the client gives
	 * correctly uses one of the resume keys we provided.
	 */
	if (args.fa_fflag & SMB_FIND_CONTINUE_FROM_LAST) {
		odir_resume.or_type = SMB_ODIR_RESUME_CONT;
	} else {
		odir_resume.or_type = SMB_ODIR_RESUME_FNAME;
	}
	smb_odir_resume_at(od, &odir_resume);

	count = smb_trans2_find_entries(sr, xa, od, &args);
	if (count == -1) {
		smb_odir_close(od);
		smb_odir_release(od);
		return (SDRC_ERROR);
	}

	if ((args.fa_fflag & SMB_FIND_CLOSE_AFTER_REQUEST) ||
	    (args.fa_eos && (args.fa_fflag & SMB_FIND_CLOSE_AT_EOS))) {
		smb_odir_close(od);
	} /* else leave odir open for trans2_find_next2 */

	smb_odir_release(od);

	(void) smb_mbc_encodef(&xa->rep_param_mb, "wwww",
	    count,	/* Search Count */
	    args.fa_eos, /* End Of Search */
	    0,		/* EA Error Offset */
	    args.fa_lno); /* Last Name Offset */

	return (SDRC_SUCCESS);
}


/*
 * smb_trans2_find_entries
 *
 * Find and encode up to args->fa_maxcount directory entries.
 * For compatibilty with Windows, if args->fa_maxcount is zero treat it as 1.
 *
 * Returns:
 *   count - count of entries encoded
 *           *eos = B_TRUE if no more directory entries
 *      -1 - error
 */
static int
smb_trans2_find_entries(smb_request_t *sr, smb_xa_t *xa, smb_odir_t *od,
    smb_find_args_t *args)
{
	int		rc;
	uint16_t	count, maxcount;
	smb_fileinfo_t	fileinfo;
	smb_odir_resume_t odir_resume;

	if ((maxcount = args->fa_maxcount) == 0)
		maxcount = 1;

	if ((smb_trans2_find_max != 0) && (maxcount > smb_trans2_find_max))
		maxcount = smb_trans2_find_max;

	count = 0;
	while (count < maxcount) {
		if (smb_odir_read_fileinfo(sr, od, &fileinfo, &args->fa_eos)
		    != 0)
			return (-1);
		if (args->fa_eos != 0)
			break;

		rc = smb_trans2_find_mbc_encode(sr, xa, &fileinfo, args);
		if (rc == -1)
			return (-1);
		if (rc == 1)
			break;

		/*
		 * Save the info about the last file returned.
		 */
		args->fa_lastkey = fileinfo.fi_cookie;
		bcopy(fileinfo.fi_name, args->fa_lastname, MAXNAMELEN);

		++count;
	}

	/* save the last cookie returned to client */
	if (count != 0)
		smb_odir_save_fname(od, args->fa_lastkey, args->fa_lastname);

	/*
	 * If all retrieved entries have been successfully encoded
	 * and eos has not already been detected, check if there are
	 * any more entries. eos will be set if there are no more.
	 */
	if ((rc == 0) && (args->fa_eos == 0))
		(void) smb_odir_read_fileinfo(sr, od, &fileinfo, &args->fa_eos);

	/*
	 * When the last entry we read from the directory did not
	 * fit in the return buffer, we will have read one entry
	 * that will not be returned in this call.  That, and the
	 * check for EOS just above both can leave the directory
	 * position incorrect for the next call.  Fix that now.
	 */
	bzero(&odir_resume, sizeof (odir_resume));
	odir_resume.or_type = SMB_ODIR_RESUME_COOKIE;
	odir_resume.or_cookie = args->fa_lastkey;
	smb_odir_resume_at(od, &odir_resume);

	return (count);
}

/*
 * smb_trans2_find_get_maxdata
 *
 * Calculate the minimum response space required for the specified
 * information level.
 *
 * A non-zero return value provides the minimum space required.
 * A return value of zero indicates an unknown information level.
 */
static int
smb_trans2_find_get_maxdata(smb_request_t *sr, uint16_t infolev, uint16_t fflag)
{
	int maxdata;

	maxdata = smb_ascii_or_unicode_null_len(sr);

	switch (infolev) {
	case SMB_INFO_STANDARD :
		if (fflag & SMB_FIND_RETURN_RESUME_KEYS)
			maxdata += sizeof (int32_t);
		maxdata += 2 + 2 + 2 + 4 + 4 + 2 + 1;
		break;

	case SMB_INFO_QUERY_EA_SIZE:
		if (fflag & SMB_FIND_RETURN_RESUME_KEYS)
			maxdata += sizeof (int32_t);
		maxdata += 2 + 2 + 2 + 4 + 4 + 2 + 4 + 1;
		break;

	case SMB_FIND_FILE_DIRECTORY_INFO:
		maxdata += 4 + 4 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 4;
		break;

	case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
		maxdata += 4 + 4 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 4 + 4;
		break;

	case SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO:
		maxdata += 4 + 4 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 4 + 4 + 4 + 8;
		break;

	case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
		maxdata += 4 + 4 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 4 + 4 + 2 + 24;
		break;

	case SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO:
		maxdata += 4 + 4 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 4 + 4 + 2 + 24
		    + 2 + 8;
		break;

	case SMB_FIND_FILE_NAMES_INFO:
		maxdata += 4 + 4 + 4;
		break;

	case SMB_MAC_FIND_BOTH_HFS_INFO:
		maxdata += 4 + 4 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 1 + 1 + 2 +
		    4 + 32 + 4 + 1 + 1 + 24 + 4;
		break;

	default:
		maxdata = 0;
		smbsr_error(sr, NT_STATUS_INVALID_LEVEL,
		    ERRDOS, ERROR_INVALID_LEVEL);
	}

	return (maxdata);
}

/*
 * This is an experimental feature that allows us to return zero
 * for all numeric resume keys, to match Windows behavior with an
 * NTFS share.  Setting this variable to zero does that.
 *
 * It's possible we could remove this variable and always set
 * numeric resume keys to zero, but that would leave us unable
 * to handle a FindNext call with an arbitrary start position.
 * In practice we never see these, but in theory we could.
 *
 * See the long comment above smb_com_trans2_find_next2() for
 * more details about resume key / resume name handling.
 */
int smbd_use_resume_keys = 1;

/*
 * smb_trans2_mbc_encode
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
 *          1 - client request's maxdata limit reached
 *	   -1 - error
 */
static int
smb_trans2_find_mbc_encode(smb_request_t *sr, smb_xa_t *xa,
    smb_fileinfo_t *fileinfo, smb_find_args_t *args)
{
	int		namelen, shortlen;
	uint32_t	next_entry_offset;
	uint32_t	dsize32, asize32;
	uint32_t	mb_flags = 0;
	uint32_t	resume_key;
	char		buf83[26];
	smb_msgbuf_t	mb;

	namelen = smb_ascii_or_unicode_strlen(sr, fileinfo->fi_name);
	if (namelen == -1)
		return (-1);

	/*
	 * If ascii the filename length returned to the client should
	 * include the null terminator for levels except STANDARD and
	 * EASIZE.
	 */
	if (!(sr->smb_flg2 & SMB_FLAGS2_UNICODE)) {
		if ((args->fa_infolev != SMB_INFO_STANDARD) &&
		    (args->fa_infolev != SMB_INFO_QUERY_EA_SIZE))
			namelen += 1;
	}

	next_entry_offset = args->fa_maxdata + namelen;

	if (MBC_ROOM_FOR(&xa->rep_data_mb, (args->fa_maxdata + namelen)) == 0)
		return (1);

	mb_flags = (sr->smb_flg2 & SMB_FLAGS2_UNICODE) ? SMB_MSGBUF_UNICODE : 0;
	dsize32 = (fileinfo->fi_size > UINT_MAX) ?
	    UINT_MAX : (uint32_t)fileinfo->fi_size;
	asize32 = (fileinfo->fi_alloc_size > UINT_MAX) ?
	    UINT_MAX : (uint32_t)fileinfo->fi_alloc_size;

	resume_key = fileinfo->fi_cookie;
	if (smbd_use_resume_keys == 0)
		resume_key = 0;

	/*
	 * This switch handles all the "information levels" (formats)
	 * that we support.  Note that all formats have the file name
	 * placed after some fixed-size data, and the code to write
	 * the file name is factored out at the end of this switch.
	 */
	switch (args->fa_infolev) {
	case SMB_INFO_STANDARD:
		if (args->fa_fflag & SMB_FIND_RETURN_RESUME_KEYS)
			(void) smb_mbc_encodef(&xa->rep_data_mb, "l",
			    resume_key);

		(void) smb_mbc_encodef(&xa->rep_data_mb, "%yyyllwb", sr,
		    smb_time_gmt_to_local(sr, fileinfo->fi_crtime.tv_sec),
		    smb_time_gmt_to_local(sr, fileinfo->fi_atime.tv_sec),
		    smb_time_gmt_to_local(sr, fileinfo->fi_mtime.tv_sec),
		    dsize32,
		    asize32,
		    fileinfo->fi_dosattr,
		    namelen);
		break;

	case SMB_INFO_QUERY_EA_SIZE:
		if (args->fa_fflag & SMB_FIND_RETURN_RESUME_KEYS)
			(void) smb_mbc_encodef(&xa->rep_data_mb, "l",
			    resume_key);

		(void) smb_mbc_encodef(&xa->rep_data_mb, "%yyyllwlb", sr,
		    smb_time_gmt_to_local(sr, fileinfo->fi_crtime.tv_sec),
		    smb_time_gmt_to_local(sr, fileinfo->fi_atime.tv_sec),
		    smb_time_gmt_to_local(sr, fileinfo->fi_mtime.tv_sec),
		    dsize32,
		    asize32,
		    fileinfo->fi_dosattr,
		    0L,		/* EA Size */
		    namelen);
		break;

	case SMB_FIND_FILE_DIRECTORY_INFO:
		(void) smb_mbc_encodef(&xa->rep_data_mb, "%llTTTTqqll", sr,
		    next_entry_offset,
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

	case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
		(void) smb_mbc_encodef(&xa->rep_data_mb, "%llTTTTqqlll", sr,
		    next_entry_offset,
		    resume_key,
		    &fileinfo->fi_crtime,
		    &fileinfo->fi_atime,
		    &fileinfo->fi_mtime,
		    &fileinfo->fi_ctime,
		    fileinfo->fi_size,
		    fileinfo->fi_alloc_size,
		    fileinfo->fi_dosattr,
		    namelen,
		    0L);
		break;

	case SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO:
		(void) smb_mbc_encodef(&xa->rep_data_mb, "%llTTTTqqlll4.q", sr,
		    next_entry_offset,
		    resume_key,
		    &fileinfo->fi_crtime,
		    &fileinfo->fi_atime,
		    &fileinfo->fi_mtime,
		    &fileinfo->fi_ctime,
		    fileinfo->fi_size,
		    fileinfo->fi_alloc_size,
		    fileinfo->fi_dosattr,
		    namelen,
		    0L,
		    fileinfo->fi_nodeid);
		break;

	case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
		bzero(buf83, sizeof (buf83));
		smb_msgbuf_init(&mb, (uint8_t *)buf83, sizeof (buf83),
		    mb_flags);
		if (smb_msgbuf_encode(&mb, "U", fileinfo->fi_shortname) < 0) {
			smb_msgbuf_term(&mb);
			return (-1);
		}
		shortlen = smb_wcequiv_strlen(fileinfo->fi_shortname);

		(void) smb_mbc_encodef(&xa->rep_data_mb, "%llTTTTqqlllb.24c",
		    sr,
		    next_entry_offset,
		    resume_key,
		    &fileinfo->fi_crtime,
		    &fileinfo->fi_atime,
		    &fileinfo->fi_mtime,
		    &fileinfo->fi_ctime,
		    fileinfo->fi_size,
		    fileinfo->fi_alloc_size,
		    fileinfo->fi_dosattr,
		    namelen,
		    0L,
		    shortlen,
		    buf83);

		smb_msgbuf_term(&mb);
		break;

	case SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO:
		bzero(buf83, sizeof (buf83));
		smb_msgbuf_init(&mb, (uint8_t *)buf83, sizeof (buf83),
		    mb_flags);
		if (smb_msgbuf_encode(&mb, "u", fileinfo->fi_shortname) < 0) {
			smb_msgbuf_term(&mb);
			return (-1);
		}
		shortlen = smb_ascii_or_unicode_strlen(sr,
		    fileinfo->fi_shortname);

		(void) smb_mbc_encodef(&xa->rep_data_mb,
		    "%llTTTTqqlllb.24c2.q",
		    sr,
		    next_entry_offset,
		    resume_key,
		    &fileinfo->fi_crtime,
		    &fileinfo->fi_atime,
		    &fileinfo->fi_mtime,
		    &fileinfo->fi_ctime,
		    fileinfo->fi_size,
		    fileinfo->fi_alloc_size,
		    fileinfo->fi_dosattr,
		    namelen,
		    0L,
		    shortlen,
		    buf83,
		    fileinfo->fi_nodeid);

		smb_msgbuf_term(&mb);
		break;

	case SMB_FIND_FILE_NAMES_INFO:
		(void) smb_mbc_encodef(&xa->rep_data_mb, "%lll", sr,
		    next_entry_offset,
		    resume_key,
		    namelen);
		break;

	default:
		/* invalid info. level */
		return (-1);
	}

	/*
	 * At this point we have written all the fixed-size data
	 * for the specified info. level, and we're about to put
	 * the file name string in the message.  We may later
	 * need the offset in the trans2 data where this string
	 * is placed, so save the message position now.  Note:
	 * We also need to account for the alignment padding
	 * that may precede the unicode string.
	 */
	args->fa_lno = xa->rep_data_mb.chain_offset;
	if ((sr->smb_flg2 & SMB_FLAGS2_UNICODE) != 0 &&
	    (args->fa_lno & 1) != 0)
		args->fa_lno++;

	(void) smb_mbc_encodef(&xa->rep_data_mb, "%u", sr,
	    fileinfo->fi_name);

	return (0);
}

/*
 * Close a search started by a Trans2FindFirst2 request.
 */
smb_sdrc_t
smb_pre_find_close2(smb_request_t *sr)
{
	DTRACE_SMB_1(op__FindClose2__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_find_close2(smb_request_t *sr)
{
	DTRACE_SMB_1(op__FindClose2__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_find_close2(smb_request_t *sr)
{
	uint16_t	odid;
	smb_odir_t	*od;

	if (smbsr_decode_vwv(sr, "w", &odid) != 0)
		return (SDRC_ERROR);

	od = smb_tree_lookup_odir(sr, odid);
	if (od == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE,
		    ERRDOS, ERROR_INVALID_HANDLE);
		return (SDRC_ERROR);
	}

	smb_odir_close(od);
	smb_odir_release(od);

	if (smbsr_encode_empty_result(sr))
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}
