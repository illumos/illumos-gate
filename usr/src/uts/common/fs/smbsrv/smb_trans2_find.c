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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"@(#)smb_trans2_find.c	1.13	08/08/07 SMI"

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

#include <smbsrv/smb_incl.h>
#include <smbsrv/msgbuf.h>
#include <smbsrv/smbtrans.h>
#include <smbsrv/smb_fsops.h>

static int smb_trans2_find_get_maxdata(smb_request_t *, uint16_t, uint16_t);

int smb_trans2_find_get_dents(smb_request_t *, smb_xa_t *,
    uint16_t, uint16_t, int, smb_node_t *,
    uint16_t, uint16_t, int, char *, uint32_t *, int *, int *);

int smb_gather_dents_info(char *, ino_t, int, char *, uint32_t, int32_t *,
    smb_attr_t *, smb_node_t *, char *, char *);

int smb_trans2_find_process_ients(smb_request_t *, smb_xa_t *,
    smb_dent_info_hdr_t *, uint16_t, uint16_t, int,
    smb_node_t *, int *, uint32_t *);

int smb_trans2_find_mbc_encode(smb_request_t *, smb_xa_t *,
    smb_dent_info_t *, int, uint16_t, uint16_t,
    uint32_t, smb_node_t *, smb_node_t *);

/*
 * The UNIX characters below are considered illegal in Windows file names.
 * The following character conversions are used to support sites in which
 * Catia v4 is in use on UNIX and Catia v5 is in use on Windows.
 *
 * ---------------------------
 * Unix-char	| Windows-char
 * ---------------------------
 *   "		| (0x00a8) Diaeresis
 *   *		| (0x00a4) Currency Sign
 *   :		| (0x00f7) Division Sign
 *   <		| (0x00ab) Left-Pointing Double Angle Quotation Mark
 *   >		| (0x00bb) Right-Pointing Double Angle Quotation Mark
 *   ?		| (0x00bf) Inverted Question mark
 *   \		| (0x00ff) Latin Small Letter Y with Diaeresis
 *   |		| (0x00a6) Broken Bar
 */
static int (*catia_callback)(uint8_t *, uint8_t *, int) = NULL;
void smb_register_catia_callback(
    int (*catia_v4tov5)(uint8_t *, uint8_t *, int));
void smb_unregister_catia_callback();

/*
 * Tunable parameter to limit the maximum
 * number of entries to be returned.
 */
uint16_t smb_trans2_find_max = 128;

/*
 * smb_register_catia_callback
 *
 * This function will be invoked by the catia module to register its
 * function that translates filename in version 4 to a format that is
 * compatible to version 5.
 */
void
smb_register_catia_callback(
    int (*catia_v4tov5)(uint8_t *, uint8_t *, int))
{
	catia_callback = catia_v4tov5;
}

/*
 * smb_unregister_catia_callback
 *
 * This function will unregister the catia callback prior to the catia
 * module gets unloaded.
 */
void
smb_unregister_catia_callback()
{
	catia_callback = 0;
}

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
	int		more = 0, rc;
	uint16_t	sattr, fflag, infolev;
	uint16_t	maxcount = 0;
	int		maxdata;
	int		count, wildcards;
	uint32_t	cookie;
	char		*path;
	smb_node_t	*dir_snode;
	char		*pattern;
	uint16_t	sid;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	if (smb_mbc_decodef(&xa->req_param_mb, "%wwww4.u", sr,
	    &sattr, &maxcount, &fflag, &infolev, &path) != 0) {
		return (SDRC_ERROR);
	}

	maxdata = smb_trans2_find_get_maxdata(sr, infolev, fflag);
	if (maxdata == 0) {
		smbsr_error(sr, NT_STATUS_INVALID_LEVEL,
		    ERRDOS, ERROR_INVALID_LEVEL);
		return (SDRC_ERROR);
	}

	/*
	 * When maxcount is zero Windows behaves as if it was 1.
	 */
	if (maxcount == 0)
		maxcount = 1;

	if ((smb_trans2_find_max != 0) && (maxcount > smb_trans2_find_max))
		maxcount = smb_trans2_find_max;

	if (sr->smb_flg2 & SMB_FLAGS2_UNICODE)
		(void) smb_convert_unicode_wildcards(path);

	if (smb_rdir_open(sr, path, sattr) != 0)
		return (SDRC_ERROR);

	/*
	 * Get a copy of information
	 */
	dir_snode = sr->sid_odir->d_dir_snode;
	pattern = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	(void) strcpy(pattern, sr->sid_odir->d_pattern);

	if (strcmp(pattern, "*.*") == 0)
		(void) strncpy(pattern, "*", sizeof (pattern));

	wildcards = sr->sid_odir->d_wildcards;
	sattr = sr->sid_odir->d_sattr;
	cookie = 0;

	rc = smb_trans2_find_get_dents(sr, xa, fflag, infolev, maxdata,
	    dir_snode, sattr, maxcount, wildcards,
	    pattern, &cookie, &more, &count);

	if (!count)
		rc = ENOENT;

	if (rc) {
		smb_rdir_close(sr);
		kmem_free(pattern, MAXNAMELEN);
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	/*
	 * Save the sid here in case the search is closed below,
	 * which will invalidate sr->smb_sid.  We return the
	 * sid, even though the search has been closed, to be
	 * compatible with Windows.
	 */
	sid = sr->smb_sid;

	if (fflag & SMB_FIND_CLOSE_AFTER_REQUEST ||
	    (!more && fflag & SMB_FIND_CLOSE_AT_EOS)) {
		smb_rdir_close(sr);
	} else {
		mutex_enter(&sr->sid_odir->d_mutex);
		sr->sid_odir->d_cookie = cookie;
		mutex_exit(&sr->sid_odir->d_mutex);
	}

	(void) smb_mbc_encodef(&xa->rep_param_mb, "wwwww",
	    sid, count, (more ? 0 : 1), 0, 0);

	kmem_free(pattern, MAXNAMELEN);
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
 */
smb_sdrc_t
smb_com_trans2_find_next2(smb_request_t *sr, smb_xa_t *xa)
{
	uint16_t fflag, infolev;
	int	maxdata, count, wildcards, more = 0, rc;
	uint32_t cookie;
	uint16_t maxcount = 0;
	smb_node_t *dir_snode;
	char *pattern;
	uint16_t sattr;

	/*
	 * The last parameter in the request is a path, which is a
	 * null-terminated unicode string.
	 *
	 * smb_mbc_decodef(&xa->req_param_mb, "%www lwu", sr,
	 *    &sr->smb_sid, &maxcount, &infolev, &cookie, &fflag, &path)
	 *
	 * We don't reference this parameter and it is not currently
	 * decoded because we a expect 2-byte null but Mac OS 10
	 * clients send a 1-byte null, which leads to a decode error.
	 */
	if (smb_mbc_decodef(&xa->req_param_mb, "%wwwlw", sr,
	    &sr->smb_sid, &maxcount, &infolev, &cookie, &fflag) != 0) {
		return (SDRC_ERROR);
	}

	sr->sid_odir = smb_odir_lookup_by_sid(sr->tid_tree, sr->smb_sid);
	if (sr->sid_odir == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	maxdata = smb_trans2_find_get_maxdata(sr, infolev, fflag);
	if (maxdata == 0) {
		smb_rdir_close(sr);
		smbsr_error(sr, NT_STATUS_INVALID_LEVEL,
		    ERRDOS, ERROR_INVALID_LEVEL);
		return (SDRC_ERROR);
	}

	/*
	 * When maxcount is zero Windows behaves as if it was 1.
	 */
	if (maxcount == 0)
		maxcount = 1;

	if ((smb_trans2_find_max != 0) && (maxcount > smb_trans2_find_max))
		maxcount = smb_trans2_find_max;

	/*
	 * Get a copy of information
	 */
	dir_snode = sr->sid_odir->d_dir_snode;
	pattern = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	(void) strcpy(pattern, sr->sid_odir->d_pattern);
	wildcards = sr->sid_odir->d_wildcards;
	sattr = sr->sid_odir->d_sattr;
	if (fflag & SMB_FIND_CONTINUE_FROM_LAST) {
		mutex_enter(&sr->sid_odir->d_mutex);
		cookie = sr->sid_odir->d_cookie;
		mutex_exit(&sr->sid_odir->d_mutex);
	}

	rc = smb_trans2_find_get_dents(sr, xa, fflag, infolev, maxdata,
	    dir_snode, sattr, maxcount, wildcards, pattern, &cookie,
	    &more, &count);

	if (rc) {
		smb_rdir_close(sr);
		kmem_free(pattern, MAXNAMELEN);
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	if (fflag & SMB_FIND_CLOSE_AFTER_REQUEST ||
	    (!more && fflag & SMB_FIND_CLOSE_AT_EOS))
		smb_rdir_close(sr);
	else {
		mutex_enter(&sr->sid_odir->d_mutex);
		sr->sid_odir->d_cookie = cookie;
		mutex_exit(&sr->sid_odir->d_mutex);
	}

	(void) smb_mbc_encodef(&xa->rep_param_mb, "wwww",
	    count, (more ? 0 : 1), 0, 0);

	kmem_free(pattern, MAXNAMELEN);
	return (SDRC_SUCCESS);
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

	case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
		maxdata += 4 + 4 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 4 + 4 + 2 + 24;
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
	}

	return (maxdata);
}

/*
 * smb_trans2_find_get_dents
 *
 * This function will get all the directory entry information and mbc
 * encode it in the xa. If there is an error, it will be returned;
 * otherwise, 0 is returned.
 *
 * The more field will be updated. If the value returned is one, it means
 * there are more entries; otherwise, the returned value will be zero. The
 * cookie will also be updated to indicate the next start point for the
 * search. The count value will also be updated to stores the total entries
 * encoded.
 */
int smb_trans2_find_get_dents(
    smb_request_t	*sr,
    smb_xa_t		*xa,
    uint16_t		fflag,
    uint16_t		infolev,
    int			maxdata,
    smb_node_t		*dir_snode,
    uint16_t		sattr,
    uint16_t		maxcount,
    int			wildcards,
    char		*pattern,
    uint32_t		*cookie,
    int			*more,
    int			*count)
{
	smb_dent_info_hdr_t	*ihdr;
	smb_dent_info_t		*ient;
	int			dent_buf_size;
	int			i;
	int			total;
	int			maxentries;
	int			rc;

	ihdr = kmem_zalloc(sizeof (smb_dent_info_hdr_t), KM_SLEEP);
	*count = 0;

	if (!wildcards)
		maxentries = maxcount = 1;
	else {
		maxentries = (xa->rep_data_mb.max_bytes -
		    xa->rep_data_mb.chain_offset) / maxdata;
		if (maxcount > SMB_MAX_DENTS_IOVEC)
			maxcount = SMB_MAX_DENTS_IOVEC;
		if (maxentries > maxcount)
			maxentries = maxcount;
	}

	/* Each entry will need to be aligned so add _POINTER_ALIGNMENT */
	dent_buf_size =
	    maxentries * (SMB_MAX_DENT_INFO_SIZE + _POINTER_ALIGNMENT);
	ihdr->iov->iov_base = kmem_alloc(dent_buf_size, KM_SLEEP);

	ihdr->sattr = sattr;
	ihdr->pattern = pattern;
	ihdr->sr = sr;

	ihdr->uio.uio_iovcnt = maxcount;
	ihdr->uio.uio_resid = dent_buf_size;
	ihdr->uio.uio_iov = ihdr->iov;
	ihdr->uio.uio_loffset = 0;

	rc = smb_get_dents(sr, cookie, dir_snode, wildcards, ihdr, more);
	if (rc != 0) {
		goto out;
	}

	if (ihdr->iov->iov_len == 0)
		*count = 0;
	else
		*count = smb_trans2_find_process_ients(sr, xa, ihdr, fflag,
		    infolev, maxdata, dir_snode, more, cookie);
	rc = 0;

out:

	total = maxcount - ihdr->uio.uio_iovcnt;
	ASSERT((total >= 0) && (total <= SMB_MAX_DENTS_IOVEC));
	for (i = 0; i < total; i++) {
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		ient = (smb_dent_info_t *)ihdr->iov[i].iov_base;
		ASSERT(ient);
		smb_node_release(ient->snode);
	}

	kmem_free(ihdr->iov->iov_base, dent_buf_size);
	kmem_free(ihdr, sizeof (smb_dent_info_hdr_t));
	return (0);
}



/*
 * smb_get_dents
 *
 * This function utilizes "smb_fsop_getdents()" to get dir entries.
 * The "smb_gather_dents_info()" is the call back function called
 * inside the file system. It is very important that the function
 * does not sleep or yield since it is processed inside a file
 * system transaction.
 *
 * The function returns 0 when successful and error code when failed.
 * If more is provided, the return value of 1 is returned indicating
 * more entries; otherwise, 0 is returned.
 */
int smb_get_dents(
    smb_request_t	*sr,
    uint32_t		*cookie,
    smb_node_t		*dir_snode,
    uint32_t		wildcards,
    smb_dent_info_hdr_t	*ihdr,
    int			*more)
{
	int		rc;
	char		*namebuf;
	smb_node_t	*snode;
	smb_attr_t	file_attr;
	uint32_t	maxcnt = ihdr->uio.uio_iovcnt;
	char		shortname[SMB_SHORTNAMELEN], name83[SMB_SHORTNAMELEN];

	namebuf = kmem_zalloc(MAXNAMELEN, KM_SLEEP);
	if (more)
		*more = 0;

	if (!wildcards) {
		/* Already found entry? */
		if (*cookie != 0)
			return (0);
		shortname[0] = '\0';

		rc = smb_fsop_lookup(sr, sr->user_cr, 0, sr->tid_tree->t_snode,
		    dir_snode, ihdr->pattern, &snode, &file_attr, shortname,
		    name83);

		if (rc) {
			kmem_free(namebuf, MAXNAMELEN);
			return (rc);
		}

		(void) strlcpy(namebuf, ihdr->pattern, MAXNAMELEN);

		/*
		 * It is not necessary to set the "force" flag (i.e. to
		 * take into account mangling for case-insensitive collisions)
		 */

		if (shortname[0] == '\0')
			(void) smb_mangle_name(snode->attr.sa_vattr.va_nodeid,
			    namebuf, shortname, name83, 0);
		(void) smb_gather_dents_info((char *)ihdr,
		    snode->attr.sa_vattr.va_nodeid,
		    strlen(namebuf), namebuf, -1, (int *)&maxcnt,
		    &snode->attr, snode, shortname, name83);
		kmem_free(namebuf, MAXNAMELEN);
		return (0);
	}

	if ((rc = smb_fsop_getdents(sr, sr->user_cr, dir_snode, cookie,
	    0, (int *)&maxcnt, (char *)ihdr, ihdr->pattern)) != 0) {
		if (rc == ENOENT) {
			kmem_free(namebuf, MAXNAMELEN);
			return (0);
		}
		kmem_free(namebuf, MAXNAMELEN);
		return (rc);
	}

	if (*cookie != 0x7FFFFFFF && more)
		*more = 1;

	kmem_free(namebuf, MAXNAMELEN);
	return (0);
}




/*
 * smb_gather_dents_info
 *
 * The function will accept information of each directory entry and put
 * the needed information in the buffer. It is passed as the call back
 * function for smb_fsop_getdents() to gather trans2 find info.
 *
 * If the buffer space is not enough, -1 will be returned. Regardless
 * of valid entry or not, 0 will be returned; however, only valid entry
 * will be stored in the buffer.
 */
int /*ARGSUSED*/
smb_gather_dents_info(
    char	*args,
    ino_t	fileid,
    int		namelen,
    char	*name,
    uint32_t	cookie,
    int32_t	*countp,
    smb_attr_t	*attr,
    smb_node_t	*snode,
    char	*shortname,
    char	*name83)
{
	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	smb_dent_info_hdr_t	*ihdr = (smb_dent_info_hdr_t *)args;
	smb_dent_info_t		*ient;
	uint8_t			*v5_name = NULL;
	uint8_t			*np = (uint8_t *)name;
	int			reclen = sizeof (smb_dent_info_t) + namelen;

	v5_name = kmem_alloc(MAXNAMELEN-1, KM_SLEEP);

	if (!ihdr->uio.uio_iovcnt || ihdr->uio.uio_resid < reclen) {
		kmem_free(v5_name, MAXNAMELEN-1);
		smb_node_release(snode);
		return (-1);
	}

	if (!smb_sattr_check(attr, name, ihdr->sattr)) {
		kmem_free(v5_name, MAXNAMELEN-1);
		smb_node_release(snode);
		return (0);
	}

	if (catia_callback) {
		catia_callback(v5_name, (uint8_t *)name,  MAXNAMELEN-1);
		np = v5_name;
		reclen = sizeof (smb_dent_info_t) + strlen((char *)v5_name);
	}

	ASSERT(snode);
	ASSERT(snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(snode->n_state != SMB_NODE_STATE_DESTROYING);

	/*
	 * Each entry needs to be properly aligned or we may get an alignment
	 * fault on sparc.
	 */
	ihdr->uio.uio_loffset = (offset_t)PTRALIGN(ihdr->uio.uio_loffset);
	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	ient = (smb_dent_info_t *)&ihdr->iov->iov_base[ihdr->uio.uio_loffset];

	ient->cookie = cookie;
	ient->attr = *attr;
	ient->snode = snode;

	(void) strcpy(ient->name, (char *)np);
	(void) strcpy(ient->shortname, shortname);
	(void) strcpy(ient->name83, name83);
	ihdr->uio.uio_iov->iov_base = (char *)ient;
	ihdr->uio.uio_iov->iov_len = reclen;

	ihdr->uio.uio_iov++;
	ihdr->uio.uio_iovcnt--;
	ihdr->uio.uio_resid -= reclen;
	ihdr->uio.uio_loffset += reclen;

	kmem_free(v5_name, MAXNAMELEN-1);
	return (0);
}



/*
 * smb_trans2_find_process_ients
 *
 * This function encodes the directory entry information store in
 * the iov structure of the ihdr structure.
 *
 * The total entries encoded will be returned. If the entries encoded
 * is less than the total entries in the iov, the more field will
 * be updated to 1. Also, the next cookie wil be updated as well.
 */
int
smb_trans2_find_process_ients(
    smb_request_t	*sr,
    smb_xa_t		*xa,
    smb_dent_info_hdr_t	*ihdr,
    uint16_t		fflag,
    uint16_t		infolev,
    int			maxdata,
    smb_node_t		*dir_snode,
    int			*more,
    uint32_t		*cookie)
{
	int i, err = 0;
	smb_dent_info_t *ient;
	uint32_t mb_flags = (sr->smb_flg2 & SMB_FLAGS2_UNICODE)
	    ? SMB_MSGBUF_UNICODE : 0;

	for (i = 0; i < SMB_MAX_DENTS_IOVEC; i++) {
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		if ((ient = (smb_dent_info_t *)ihdr->iov[i].iov_base) == 0)
			break;

		/*
		 * Observed differences between our response and Windows
		 * response, which hasn't caused a problem yet!
		 *
		 * 1. The NextEntryOffset field for the last entry should
		 * be 0.  This code always calculate the record length
		 * and puts the result in the NextEntryOffset field.
		 *
		 * 2. The FileIndex field is always 0.  This code puts
		 * the cookie in the FileIndex field.
		 */
		err = smb_trans2_find_mbc_encode(sr, xa, ient, maxdata, infolev,
		    fflag, mb_flags, dir_snode, NULL);

		if (err)
			break;
	}

	/*
	 * Not enough space to store all the entries returned,
	 * which is indicated by setting more.
	 */
	if (more && err < 0) {
		*more = 1;

		/*
		 * Assume the space will be at least enough for 1 entry.
		 */
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		ient = (smb_dent_info_t *)ihdr->iov[i-1].iov_base;
		*cookie = ient->cookie;
	}
	return (i);
}

/*
 * smb_trans2_find_mbc_encode
 *
 * This function encodes the mbc for one directory entry.
 *
 * The function returns -1 when the max data requested by client
 * is reached. If the entry is valid and successful encoded, 0
 * will be returned; otherwise, 1 will be returned.
 */
int /*ARGSUSED*/
smb_trans2_find_mbc_encode(
    smb_request_t	*sr,
    smb_xa_t		*xa,
    smb_dent_info_t	*ient,
    int			maxdata,
    uint16_t		infolev,
    uint16_t		fflag,
    uint32_t		mb_flags,
    smb_node_t		*dir_snode,
    smb_node_t		*sd_snode)
{
	int uni_namelen;
	int shortlen;
	uint32_t next_entry_offset;
	char buf83[26];
	smb_msgbuf_t mb;
	uint32_t dattr = 0;
	uint32_t dsize32 = 0;
	uint32_t asize32 = 0;
	u_offset_t datasz = 0;
	u_offset_t allocsz = 0;
	smb_node_t *lnk_snode;
	smb_attr_t lnkattr;
	int rc;

	uni_namelen = smb_ascii_or_unicode_strlen(sr, ient->name);
	if (uni_namelen == -1)
		return (1);

	next_entry_offset = maxdata + uni_namelen;

	if (MBC_ROOM_FOR(&xa->rep_data_mb, (maxdata + uni_namelen)) == 0)
		return (-1);

	if (ient->attr.sa_vattr.va_type == VLNK) {
		rc = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS,
		    sr->tid_tree->t_snode, dir_snode, ient->name, &lnk_snode,
		    &lnkattr, 0, 0);

		/*
		 * We normally want to resolve the object to which a symlink
		 * refers so that CIFS clients can access sub-directories and
		 * find the correct association for files. This causes a
		 * problem, however, if a symlink in a sub-directory points
		 * to a parent directory (some UNIX GUI's create a symlink in
		 * $HOME/.desktop that points to the user's home directory).
		 * Some Windows applications (i.e. virus scanning) loop/hang
		 * trying to follow this recursive path and there is little
		 * we can do because the path is constructed on the client.
		 * skc_dirsymlink_enable allows an end-user to disable
		 * symlinks to directories. Symlinks to other object types
		 * should be unaffected.
		 */
		if (rc == 0) {
			if (smb_dirsymlink_enable ||
			    (lnkattr.sa_vattr.va_type != VDIR)) {
				smb_node_release(ient->snode);
				ient->snode = lnk_snode;
				ient->attr = lnkattr;
			} else {
				smb_node_release(lnk_snode);
			}
		}
	}

	if (infolev != SMB_FIND_FILE_NAMES_INFO) {
		/* data size */
		datasz = smb_node_get_size(ient->snode, &ient->attr);
		dsize32 = (datasz > UINT_MAX) ? UINT_MAX : (uint32_t)datasz;

		/* allocation size */
		allocsz = ient->attr.sa_vattr.va_nblocks * DEV_BSIZE;
		asize32 = (allocsz > UINT_MAX) ? UINT_MAX : (uint32_t)allocsz;

		dattr = smb_node_get_dosattr(ient->snode);
	}

	switch (infolev) {
	case SMB_INFO_STANDARD:
		if (fflag & SMB_FIND_RETURN_RESUME_KEYS)
			(void) smb_mbc_encodef(&xa->rep_data_mb, "l",
			    ient->cookie);

		(void) smb_mbc_encodef(&xa->rep_data_mb, "%yyyllwbu", sr,
		    ient->attr.sa_crtime.tv_sec ?
		    smb_gmt2local(sr, ient->attr.sa_crtime.tv_sec) :
		    smb_gmt2local(sr, ient->attr.sa_vattr.va_mtime.tv_sec),
		    smb_gmt2local(sr, ient->attr.sa_vattr.va_atime.tv_sec),
		    smb_gmt2local(sr, ient->attr.sa_vattr.va_mtime.tv_sec),
		    dsize32,
		    asize32,
		    dattr,
		    uni_namelen,
		    ient->name);
		break;

	case SMB_INFO_QUERY_EA_SIZE:
		if (fflag & SMB_FIND_RETURN_RESUME_KEYS)
			(void) smb_mbc_encodef(&xa->rep_data_mb, "l",
			    ient->cookie);

		(void) smb_mbc_encodef(&xa->rep_data_mb, "%yyyllwlbz", sr,
		    ient->attr.sa_crtime.tv_sec ?
		    smb_gmt2local(sr, ient->attr.sa_crtime.tv_sec) :
		    smb_gmt2local(sr, ient->attr.sa_vattr.va_mtime.tv_sec),
		    smb_gmt2local(sr, ient->attr.sa_vattr.va_atime.tv_sec),
		    smb_gmt2local(sr, ient->attr.sa_vattr.va_mtime.tv_sec),
		    dsize32,
		    asize32,
		    dattr,
		    0L,		/* EA Size */
		    uni_namelen,
		    ient->name);
		break;

	case SMB_FIND_FILE_DIRECTORY_INFO:
		(void) smb_mbc_encodef(&xa->rep_data_mb, "%llTTTTqqllu", sr,
		    next_entry_offset,
		    ient->cookie,
		    ient->attr.sa_crtime.tv_sec ? &ient->attr.sa_crtime :
		    &ient->attr.sa_vattr.va_mtime,
		    &ient->attr.sa_vattr.va_atime,
		    &ient->attr.sa_vattr.va_mtime,
		    &ient->attr.sa_vattr.va_ctime,
		    (uint64_t)datasz,
		    (uint64_t)allocsz,
		    dattr,
		    uni_namelen,
		    ient->name);
		break;

	case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
		bzero(buf83, sizeof (buf83));
		smb_msgbuf_init(&mb, (uint8_t *)buf83, sizeof (buf83),
		    mb_flags);
		if (smb_msgbuf_encode(&mb, "u", ient->shortname) < 0) {
			smb_msgbuf_term(&mb);
			return (-1);
		}
		shortlen = smb_ascii_or_unicode_strlen(sr, ient->shortname);

		(void) smb_mbc_encodef(&xa->rep_data_mb, "%llTTTTqqlllb.24cu",
		    sr,
		    next_entry_offset,
		    ient->cookie,
		    ient->attr.sa_crtime.tv_sec ? &ient->attr.sa_crtime :
		    &ient->attr.sa_vattr.va_mtime,
		    &ient->attr.sa_vattr.va_atime,
		    &ient->attr.sa_vattr.va_mtime,
		    &ient->attr.sa_vattr.va_ctime,
		    (uint64_t)datasz,
		    (uint64_t)allocsz,
		    dattr,
		    uni_namelen,
		    0L,
		    shortlen,
		    buf83,
		    ient->name);

		smb_msgbuf_term(&mb);
		break;

	case SMB_FIND_FILE_NAMES_INFO:
		(void) smb_mbc_encodef(&xa->rep_data_mb, "%lllu", sr,
		    next_entry_offset,
		    ient->cookie,
		    uni_namelen,
		    ient->name);
		break;
	}

	return (0);
}

/*
 * Close a search started by a Trans2FindFirst2 request.
 */
smb_sdrc_t
smb_pre_find_close2(smb_request_t *sr)
{
	int rc;

	rc = smbsr_decode_vwv(sr, "w", &sr->smb_sid);

	DTRACE_SMB_1(op__FindClose2__start, smb_request_t *, sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_find_close2(smb_request_t *sr)
{
	DTRACE_SMB_1(op__FindClose2__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_find_close2(smb_request_t *sr)
{
	sr->sid_odir = smb_odir_lookup_by_sid(sr->tid_tree, sr->smb_sid);
	if (sr->sid_odir == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	smb_rdir_close(sr);

	if (smbsr_encode_empty_result(sr))
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}
