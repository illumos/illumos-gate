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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

#include <smbsrv/smb_kproto.h>

/*
 * smb_com_search
 * smb_com_find, smb_com_find_close
 * smb_find_unique
 *
 * These commands are used for directory searching. They share the same
 * message formats, defined below:
 *
 * Client Request                     Description
 * ---------------------------------- ---------------------------------
 *
 * UCHAR WordCount;                   Count of parameter words = 2
 * USHORT MaxCount;                   Number of dir. entries to return
 * USHORT SearchAttributes;
 * USHORT ByteCount;                  Count of data bytes;  min = 5
 * UCHAR BufferFormat1;               0x04 -- ASCII
 * UCHAR FileName[];                  File name, may be null
 * UCHAR BufferFormat2;               0x05 -- Variable block
 * USHORT ResumeKeyLength;            Length of resume key, may be 0
 * UCHAR ResumeKey[];                 Resume key
 *
 * FileName specifies the file to be sought.  SearchAttributes indicates
 * the attributes that the file must have.  If  SearchAttributes is
 * zero then only normal files are returned.  If the system file, hidden or
 * directory attributes are specified then the search is inclusive - both the
 * specified type(s) of files and normal files are returned.  If the volume
 * label attribute is specified then the search is exclusive, and only the
 * volume label entry is returned.
 *
 * MaxCount specifies the number of directory entries to be returned.
 *
 * Server Response                    Description
 * ---------------------------------- ---------------------------------
 *
 * UCHAR WordCount;                   Count of parameter words = 1
 * USHORT Count;                      Number of entries returned
 * USHORT ByteCount;                  Count of data bytes;  min = 3
 * UCHAR BufferFormat;                0x05 -- Variable block
 * USHORT DataLength;                 Length of data
 * UCHAR DirectoryInformationData[];  Data
 *
 * The response will contain one or more directory entries as determined by
 * the Count field.  No more than MaxCount entries will be returned.  Only
 * entries that match the sought FileName and SearchAttributes combination
 * will be returned.
 *
 * ResumeKey must be null (length = 0) on the initial search request.
 * Subsequent search requests intended to continue a search must contain
 * the ResumeKey field extracted from the last directory entry of the
 * previous response.  ResumeKey is self-contained, for calls containing
 * a non-zero ResumeKey neither the SearchAttributes or FileName fields
 * will be valid in the request.  ResumeKey has the following format:
 *
 * Resume Key Field                   Description
 * ---------------------------------- ---------------------------------
 *
 * UCHAR Reserved;                    bit 7 - consumer use
 *                                    bits 5,6 - system use (must preserve)
 *                                    bits 0-4 - server use (must preserve)
 * UCHAR FileName[11];                Name of the returned file
 * UCHAR ReservedForServer[5];        Client must not modify
 *                                    byte 0 - uniquely identifies find
 *                                    through find_close
 *                                    bytes 1-4 - available for server use
 *                                    (must be non-zero)
 * UCHAR ReservedForConsumer[4];      Server must not modify
 *
 * FileName is 8.3 format, with the three character extension left
 * justified into FileName[9-11].
 *
 * There may be multiple matching entries in response to a single request
 * as wildcards are supported in the last component of FileName of the
 * initial request.
 *
 * Returned directory entries in the DirectoryInformationData field of the
 * response each have the following format:
 *
 * Directory Information Field        Description
 * ---------------------------------- ---------------------------------
 *
 * SMB_RESUME_KEY ResumeKey;          Described above
 * UCHAR FileAttributes;              Attributes of the found file
 * SMB_TIME LastWriteTime;            Time file was last written
 * SMB_DATE LastWriteDate;            Date file was last written
 * ULONG FileSize;                    Size of the file
 * UCHAR FileName[13];                ASCII, space-filled null terminated
 *
 * FileName must conform to 8.3 rules, and is padded after the extension
 * with 0x20 characters if necessary.
 *
 * As can be seen from the above structure, these commands cannot return
 * long filenames, and cannot return UNICODE filenames.
 *
 * Files which have a size greater than 2^32 bytes should have the least
 * significant 32 bits of their size returned in FileSize.
 *
 * smb_com_search
 * --------------
 *
 * If the client is prior to the LANMAN1.0 dialect, the returned FileName
 * should be uppercased.
 * If the client has negotiated a dialect prior to the LANMAN1.0 dialect,
 * or if bit0 of the Flags2 SMB header field of the request is clear,
 * the returned FileName should be uppercased.
 *
 * SMB_COM_SEARCH terminates when either the requested maximum number of
 * entries that match the named file are found, or the end of directory is
 * reached without the maximum number of matches being found.  A response
 * containing no entries indicates that no matching entries were found
 * between the starting point of the search and the end of directory.
 *
 *
 * The find, find_close and find_unique protocols may be used in place of
 * the core "search" protocol when LANMAN 1.0 dialect has been negotiated.
 *
 * smb_com_find
 * ------------
 *
 * The find protocol is used to match the find OS/2 system call.
 *
 * The format of the find protocol is the same as the core "search" protocol.
 * The difference is that the directory is logically Opened with a find protocol
 * and logically closed with the find close protocol.
 * As is true of a failing open, if a find request (find "first" request where
 * resume_key is null) fails (no entries are found), no find close protocol is
 * expected.
 *
 * If no global characters are present, a "find unique" protocol should be used
 * (only one entry is expected and find close need not be sent).
 *
 * A find request will terminate when either the requested maximum number of
 * entries that match the named file are found, or the end of directory is
 * reached without the maximum number of matches being found. A response
 * containing no entries indicates that no matching entries were found between
 * the starting point of the search and the end of directory.
 *
 * If a find requests more data than can be placed in a message of the
 * max-xmit-size for the TID specified, the server will return only the number
 * of entries which will fit.
 *
 *
 * smb_com_find_close
 * ------------------
 *
 * The find close protocol is used to match the find close OS/2 system call.
 *
 * Whereas the first find protocol logically opens the directory, subsequent
 * find  protocols presenting a resume_key further "read" the directory, the
 * find close  protocol "closes" the  directory allowing the server to free any
 * resources held in support of the directory search.
 *
 * In our implementation this translates to closing the odir.
 *
 *
 * smb_com_find_unique
 * -------------------
 *
 * The format of the find unique protocol is the same as the core "search"
 * protocol. The difference is that the directory is logically opened, any
 * matching entries returned, and then the directory is logically closed.
 *
 * The resume search key key will be returned as in the find protocol and
 * search protocol however it may NOT be returned to continue the search.
 * Only one buffer of entries is expected and find close need not be sent.
 *
 * If a find unique requests more data than can be placed in a message of the
 * max-xmit-size for the TID specified, the server will abort the virtual
 * circuit to the consumer.
 */

#define	SMB_NAME83_BUFLEN	12
static void smb_name83(const char *, char *, size_t);

/* *** smb_com_search *** */

smb_sdrc_t
smb_pre_search(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Search__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_search(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Search__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_search(smb_request_t *sr)
{
	int			rc;
	uint16_t		count, maxcount, index;
	uint16_t		sattr, odid;
	uint16_t		key_len;
	uint32_t		client_key;
	char			name[SMB_SHORTNAMELEN];
	char			name83[SMB_SHORTNAMELEN];
	smb_pathname_t		*pn;
	unsigned char		resume_char;
	unsigned char		type;
	boolean_t		find_first, to_upper;
	smb_tree_t		*tree;
	smb_odir_t		*od;
	smb_fileinfo_t		fileinfo;
	smb_odir_resume_t	odir_resume;
	uint16_t		eos;

	to_upper = B_FALSE;
	if ((sr->session->dialect <= LANMAN1_0) ||
	    ((sr->smb_flg2 & SMB_FLAGS2_KNOWS_LONG_NAMES) == 0)) {
		to_upper = B_TRUE;
	}

	/* We only handle 8.3 name here */
	sr->smb_flg2 &= ~SMB_FLAGS2_KNOWS_LONG_NAMES;
	sr->smb_flg &= ~SMB_FLAGS_CASE_INSENSITIVE;

	if (smbsr_decode_vwv(sr, "ww", &maxcount, &sattr) != 0)
		return (SDRC_ERROR);

	pn = &sr->arg.dirop.fqi.fq_path;
	rc = smbsr_decode_data(sr, "%Abw", sr, &pn->pn_path, &type, &key_len);
	if ((rc != 0) || (type != 0x05))
		return (SDRC_ERROR);

	smb_pathname_init(sr, pn, pn->pn_path);
	if (!smb_pathname_validate(sr, pn) ||
	    smb_is_stream_name(pn->pn_path)) {
		smbsr_warn(sr, NT_STATUS_NO_MORE_FILES,
		    ERRDOS, ERROR_NO_MORE_FILES);
		return (SDRC_ERROR);
	}

	tree = sr->tid_tree;

	/* Volume information only */
	if ((sattr == FILE_ATTRIBUTE_VOLUME) && (key_len != 21)) {
		(void) memset(name, ' ', sizeof (name));
		(void) strncpy(name, tree->t_volume, sizeof (name));

		if (key_len >= 21) {
			(void) smb_mbc_decodef(&sr->smb_data, "17.l",
			    &client_key);
		} else {
			client_key = 0;
		}

		(void) smb_mbc_encodef(&sr->reply, "bwwbwb11c5.lb8.13c",
		    1, 0, VAR_BCC, 5, 0, 0, pn->pn_path+1,
		    client_key, sattr, name);

		rc = (sr->reply.chain_offset - sr->cur_reply_offset) - 8;
		(void) smb_mbc_poke(&sr->reply, sr->cur_reply_offset, "bwwbw",
		    1, 1, rc+3, 5, rc);

		return (SDRC_SUCCESS);
	}

	if ((key_len != 0) && (key_len != 21))
		return (SDRC_ERROR);

	find_first = (key_len == 0);
	resume_char = 0;
	client_key = 0;

	if (find_first) {
		odid = smb_odir_open(sr, pn->pn_path, sattr, 0);
		if (odid == 0) {
			if (sr->smb_error.status == NT_STATUS_ACCESS_DENIED)
				smbsr_warn(sr, NT_STATUS_NO_MORE_FILES,
				    ERRDOS, ERROR_NO_MORE_FILES);
			return (SDRC_ERROR);
		}
	} else {
		if (smb_mbc_decodef(&sr->smb_data, "b12.wwl",
		    &resume_char, &index, &odid, &client_key) != 0) {
			return (SDRC_ERROR);
		}
	}

	od = smb_tree_lookup_odir(sr, odid);
	if (od == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE,
		    ERRDOS, ERROR_INVALID_HANDLE);
		return (SDRC_ERROR);
	}

	if (!find_first) {
		odir_resume.or_type = SMB_ODIR_RESUME_IDX;
		odir_resume.or_idx = index;
		smb_odir_resume_at(od, &odir_resume);
	}

	(void) smb_mbc_encodef(&sr->reply, "bwwbw", 1, 0, VAR_BCC, 5, 0);

	rc = 0;
	index = 0;
	count = 0;
	if (maxcount > SMB_MAX_SEARCH)
		maxcount = SMB_MAX_SEARCH;

	while (count < maxcount) {
		rc = smb_odir_read_fileinfo(sr, od, &fileinfo, &eos);
		if (rc != 0 || eos != 0)
			break;

		if (*fileinfo.fi_shortname == '\0') {
			if (smb_needs_mangled(fileinfo.fi_name))
				continue;
			(void) strlcpy(fileinfo.fi_shortname, fileinfo.fi_name,
			    SMB_SHORTNAMELEN - 1);
			if (to_upper)
				(void) smb_strupr(fileinfo.fi_shortname);
		}
		smb_name83(fileinfo.fi_shortname, name83, SMB_SHORTNAMELEN);

		(void) smb_mbc_encodef(&sr->reply, "b11c.wwlbYl13c",
		    resume_char, name83, index, odid, client_key,
		    fileinfo.fi_dosattr & 0xff,
		    smb_time_gmt_to_local(sr, fileinfo.fi_mtime.tv_sec),
		    (int32_t)fileinfo.fi_size,
		    fileinfo.fi_shortname);

		smb_odir_save_cookie(od, index, fileinfo.fi_cookie);

		count++;
		index++;
	}

	if (rc != 0) {
		smb_odir_close(od);
		smb_odir_release(od);
		return (SDRC_ERROR);
	}

	if (count == 0 && find_first) {
		smb_odir_close(od);
		smb_odir_release(od);
		smbsr_warn(sr, NT_STATUS_NO_MORE_FILES,
		    ERRDOS, ERROR_NO_MORE_FILES);
		return (SDRC_ERROR);
	}

	rc = (sr->reply.chain_offset - sr->cur_reply_offset) - 8;
	if (smb_mbc_poke(&sr->reply, sr->cur_reply_offset, "bwwbw",
	    1, count, rc+3, 5, rc) < 0) {
		smb_odir_close(od);
		smb_odir_release(od);
		return (SDRC_ERROR);
	}

	smb_odir_release(od);
	return (SDRC_SUCCESS);
}


/* *** smb_com_find *** */

smb_sdrc_t
smb_pre_find(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Find__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_find(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Find__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_find(smb_request_t *sr)
{
	int			rc;
	uint16_t		count, maxcount, index;
	uint16_t		sattr, odid;
	uint16_t		key_len;
	uint32_t		client_key;
	char			name83[SMB_SHORTNAMELEN];
	smb_odir_t		*od;
	smb_fileinfo_t		fileinfo;
	uint16_t		eos;

	smb_pathname_t		*pn;
	unsigned char		resume_char;
	unsigned char		type;
	boolean_t		find_first = B_TRUE;
	smb_odir_resume_t	odir_resume;

	if (smbsr_decode_vwv(sr, "ww", &maxcount, &sattr) != 0)
		return (SDRC_ERROR);

	pn = &sr->arg.dirop.fqi.fq_path;
	rc = smbsr_decode_data(sr, "%Abw", sr, &pn->pn_path, &type, &key_len);
	if ((rc != 0) || (type != 0x05))
		return (SDRC_ERROR);

	if ((key_len != 0) && (key_len != 21))
		return (SDRC_ERROR);

	smb_pathname_init(sr, pn, pn->pn_path);
	if (!smb_pathname_validate(sr, pn))
		return (SDRC_ERROR);

	if (smb_is_stream_name(pn->pn_path)) {
		smbsr_error(sr, NT_STATUS_OBJECT_NAME_INVALID,
		    ERRDOS, ERROR_INVALID_NAME);
		return (SDRC_ERROR);
	}

	find_first = (key_len == 0);
	resume_char = 0;
	client_key = 0;

	if (find_first) {
		odid = smb_odir_open(sr, pn->pn_path, sattr, 0);
		if (odid == 0)
			return (SDRC_ERROR);
	} else {
		if (smb_mbc_decodef(&sr->smb_data, "b12.wwl",
		    &resume_char, &index, &odid, &client_key) != 0) {
			return (SDRC_ERROR);
		}
	}

	od = smb_tree_lookup_odir(sr, odid);
	if (od == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE,
		    ERRDOS, ERROR_INVALID_HANDLE);
		return (SDRC_ERROR);
	}

	if (!find_first) {
		odir_resume.or_type = SMB_ODIR_RESUME_IDX;
		odir_resume.or_idx = index;
		smb_odir_resume_at(od, &odir_resume);
	}

	(void) smb_mbc_encodef(&sr->reply, "bwwbw", 1, 0, VAR_BCC, 5, 0);

	rc = 0;
	index = 0;
	count = 0;
	if (maxcount > SMB_MAX_SEARCH)
		maxcount = SMB_MAX_SEARCH;

	while (count < maxcount) {
		rc = smb_odir_read_fileinfo(sr, od, &fileinfo, &eos);
		if (rc != 0 || eos != 0)
			break;

		if (*fileinfo.fi_shortname == '\0') {
			if (smb_needs_mangled(fileinfo.fi_name))
				continue;
			(void) strlcpy(fileinfo.fi_shortname, fileinfo.fi_name,
			    SMB_SHORTNAMELEN - 1);
		}
		smb_name83(fileinfo.fi_shortname, name83, SMB_SHORTNAMELEN);

		(void) smb_mbc_encodef(&sr->reply, "b11c.wwlbYl13c",
		    resume_char, name83, index, odid, client_key,
		    fileinfo.fi_dosattr & 0xff,
		    smb_time_gmt_to_local(sr, fileinfo.fi_mtime.tv_sec),
		    (int32_t)fileinfo.fi_size,
		    fileinfo.fi_shortname);

		smb_odir_save_cookie(od, index, fileinfo.fi_cookie);

		count++;
		index++;
	}

	if (rc != 0) {
		smb_odir_close(od);
		smb_odir_release(od);
		return (SDRC_ERROR);
	}

	if (count == 0 && find_first) {
		smb_odir_close(od);
		smb_odir_release(od);
		smbsr_warn(sr, NT_STATUS_NO_MORE_FILES,
		    ERRDOS, ERROR_NO_MORE_FILES);
		return (SDRC_ERROR);
	}

	rc = (MBC_LENGTH(&sr->reply) - sr->cur_reply_offset) - 8;
	if (smb_mbc_poke(&sr->reply, sr->cur_reply_offset, "bwwbw",
	    1, count, rc+3, 5, rc) < 0) {
		smb_odir_close(od);
		smb_odir_release(od);
		return (SDRC_ERROR);
	}

	smb_odir_release(od);
	return (SDRC_SUCCESS);
}


/* *** smb_com_find_close *** */

smb_sdrc_t
smb_pre_find_close(smb_request_t *sr)
{
	DTRACE_SMB_1(op__FindClose__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_find_close(smb_request_t *sr)
{
	DTRACE_SMB_1(op__FindClose__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_find_close(smb_request_t *sr)
{
	int		rc;
	uint16_t	maxcount, index;
	uint16_t	sattr, odid;
	uint16_t	key_len;
	uint32_t	client_key;
	char		*path;
	unsigned char	resume_char;
	unsigned char	type;
	smb_odir_t	*od;

	if (smbsr_decode_vwv(sr, "ww", &maxcount, &sattr) != 0)
		return (SDRC_ERROR);

	rc = smbsr_decode_data(sr, "%Abw", sr, &path, &type, &key_len);
	if ((rc != 0) || (type != 0x05))
		return (SDRC_ERROR);

	if (key_len == 0) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE,
		    ERRDOS, ERROR_INVALID_HANDLE);
		return (SDRC_ERROR);
	} else if (key_len != 21) {
		return (SDRC_ERROR);
	}

	odid = 0;
	if (smb_mbc_decodef(&sr->smb_data, "b12.wwl",
	    &resume_char, &index, &odid, &client_key) != 0) {
		return (SDRC_ERROR);
	}

	od = smb_tree_lookup_odir(sr, odid);
	if (od == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE,
		    ERRDOS, ERROR_INVALID_HANDLE);
		return (SDRC_ERROR);
	}

	smb_odir_close(od);
	smb_odir_release(od);

	if (smbsr_encode_result(sr, 1, 3, "bwwbw", 1, 0, 3, 5, 0))
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}


/* *** smb_com_find_unique *** */

smb_sdrc_t
smb_pre_find_unique(smb_request_t *sr)
{
	DTRACE_SMB_1(op__FindUnique__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_find_unique(smb_request_t *sr)
{
	DTRACE_SMB_1(op__FindUnique__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_find_unique(struct smb_request *sr)
{
	int			rc;
	uint16_t		count, maxcount, index;
	uint16_t		sattr, odid;
	smb_pathname_t		*pn;
	unsigned char		resume_char = '\0';
	uint32_t		client_key = 0;
	char			name83[SMB_SHORTNAMELEN];
	smb_odir_t		*od;
	smb_fileinfo_t		fileinfo;
	uint16_t		eos;
	smb_vdb_t		*vdb;

	if (smbsr_decode_vwv(sr, "ww", &maxcount, &sattr) != 0)
		return (SDRC_ERROR);

	pn = &sr->arg.dirop.fqi.fq_path;
	vdb = kmem_alloc(sizeof (smb_vdb_t), KM_SLEEP);
	if ((smbsr_decode_data(sr, "%AV", sr, &pn->pn_path, vdb) != 0) ||
	    (vdb->vdb_len != 0)) {
		kmem_free(vdb, sizeof (smb_vdb_t));
		return (SDRC_ERROR);
	}
	kmem_free(vdb, sizeof (smb_vdb_t));

	smb_pathname_init(sr, pn, pn->pn_path);
	if (!smb_pathname_validate(sr, pn))
		return (SDRC_ERROR);

	if (smb_is_stream_name(pn->pn_path)) {
		smbsr_error(sr, NT_STATUS_OBJECT_NAME_INVALID,
		    ERRDOS, ERROR_INVALID_NAME);
		return (SDRC_ERROR);
	}

	(void) smb_mbc_encodef(&sr->reply, "bwwbw", 1, 0, VAR_BCC, 5, 0);

	odid = smb_odir_open(sr, pn->pn_path, sattr, 0);
	if (odid == 0)
		return (SDRC_ERROR);
	od = smb_tree_lookup_odir(sr, odid);
	if (od == NULL)
		return (SDRC_ERROR);

	rc = 0;
	count = 0;
	index = 0;
	if (maxcount > SMB_MAX_SEARCH)
		maxcount = SMB_MAX_SEARCH;

	while (count < maxcount) {
		rc = smb_odir_read_fileinfo(sr, od, &fileinfo, &eos);
		if (rc != 0 || eos != 0)
			break;

		if (*fileinfo.fi_shortname == '\0') {
			if (smb_needs_mangled(fileinfo.fi_name))
				continue;
			(void) strlcpy(fileinfo.fi_shortname, fileinfo.fi_name,
			    SMB_SHORTNAMELEN - 1);
		}
		smb_name83(fileinfo.fi_shortname, name83, SMB_SHORTNAMELEN);

		(void) smb_mbc_encodef(&sr->reply, "b11c.wwlbYl13c",
		    resume_char, name83, index, odid, client_key,
		    fileinfo.fi_dosattr & 0xff,
		    smb_time_gmt_to_local(sr, fileinfo.fi_mtime.tv_sec),
		    (int32_t)fileinfo.fi_size,
		    fileinfo.fi_shortname);

		count++;
		index++;
	}

	smb_odir_close(od);
	smb_odir_release(od);

	if (rc != 0)
		return (SDRC_ERROR);

	if (count == 0) {
		smbsr_warn(sr, NT_STATUS_NO_MORE_FILES,
		    ERRDOS, ERROR_NO_MORE_FILES);
		return (SDRC_ERROR);
	}

	rc = (MBC_LENGTH(&sr->reply) - sr->cur_reply_offset) - 8;
	if (smb_mbc_poke(&sr->reply, sr->cur_reply_offset,
	    "bwwbw", 1, count, rc+3, 5, rc) < 0) {
		return (SDRC_ERROR);
	}

	return (SDRC_SUCCESS);
}

/*
 * smb_name83
 *
 * Format the filename for inclusion in the resume key. The filename
 * returned in the resume key is 11 bytes:
 * - up to 8 bytes of filename, space padded to 8 bytes
 * - up to 3 bytes of ext, space padded to 3 bytes
 *
 * The name passed to smb_name83 should be a shortname or a name that
 * doesn't require mangling.
 *
 * Examples:
 *	"fname.txt"    -> "FNAME   TXT"
 *	"fname.tx"     -> "FNAME   TX "
 *	"filename"     -> "FILENAME   "
 *	"filename.txt" -> "FILENAMETXT"
 *	"FILE~1.TXT"   -> "FILE~1  TXT"
 */
static void
smb_name83(const char *name, char *buf, size_t buflen)
{
	const char *p;
	char *pbuf;
	int i;

	ASSERT(name && buf && (buflen >= SMB_NAME83_BUFLEN));

	(void) strlcpy(buf, "           ", SMB_NAME83_BUFLEN);

	/* Process "." and ".." up front */
	if ((strcmp(name, ".") == 0) || (strcmp(name, "..") == 0)) {
		(void) strncpy(buf, name, strlen(name));
		return;
	}

	ASSERT(smb_needs_mangled(name) == B_FALSE);

	/* Process basename */
	for (i = 0, p = name, pbuf = buf;
	    (i < SMB_NAME83_BASELEN) && (*p != '\0') && (*p != '.'); ++i)
		*pbuf++ = *p++;

	/* Process the extension from the last dot in name */
	if ((p = strchr(name, '.')) != NULL) {
		++p;
		pbuf = &buf[SMB_NAME83_BASELEN];
		for (i = 0; (i < SMB_NAME83_EXTLEN) && (*p != '\0'); ++i)
			*pbuf++ = *p++;
	}

	(void) smb_strupr(buf);
}
