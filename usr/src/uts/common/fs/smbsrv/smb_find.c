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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <smbsrv/smb_incl.h>


/*
 * smb_com_find
 *
 * Request Format: (same as core Search Protocol - "Find First" form)
 *
 *  Client Request                     Description
 *  ================================== =================================
 *
 *  BYTE  smb_wct;			value = 2
 *  WORD  smb_count;			max number of entries to find
 *  WORD  smb_attr;			search attribute
 *  WORD  smb_bcc;			minimum value = 5
 *  BYTE  smb_ident1;			ASCII  (04)
 *  BYTE  smb_pathname[];		filename (may contain global characters)
 *  BYTE  smb_ident2;			Variable Block (05)
 *  WORD  smb_keylen;			resume key length (zero if "Find First")
 *  BYTE  smb_resumekey[*];		"Find Next" key, * = value of smb_keylen
 *
 * Response Format: (same as core Search Protocol)
 *
 *  Server Response                    Description
 *  ================================== =================================
 *  BYTE  smb_wct;			value = 1
 *  WORD  smb_count;			number of entries found
 *  WORD  smb_bcc;			minimum value = 3
 *  BYTE  smb_ident;			Variable Block (05)
 *  WORD  smb_datalen;			data length
 *  BYTE  smb_data[*];			directory entries
 *
 * Directory Information Entry (dir_info) Format: (same as core Search Protocol)
 *
 *  BYTE  find_buf_reserved[21];	reserved (resume_key)
 *  BYTE  find_buf_attr;		attribute
 *  WORD  find_buf_time;		modification time (hhhhh mmmmmm xxxxx)
 *					 where 'xxxxx' is in 2 second increments
 *  WORD  find_buf_date;		modification date (yyyyyyy mmmm ddddd)
 *  DWORD  find_buf_size;		file size
 *  STRING find_buf_pname[13];		file name -- ASCII (null terminated)
 *
 * The resume_key has the following format:
 *
 *  BYTE  sr_res;			reserved:
 *					bit  7 - reserved for consumer use
 *					bit  5,6 - reserved for system use
 *					   (must be preserved)
 *					bits 0-4 - reserved for server
 *					   (must be preserved)
 *  BYTE  sr_name[11];			pathname sought.
 *					 Format: 1-8 character file name,
 *					 left justified 0-3 character extension,
 *  BYTE  sr_findid[1];			uniquely identifies find through
 *					 find_close
 *  BYTE  sr_server[4];			available for server use
 *					 (must be non-zero)
 *  BYTE  sr_res[4];			reserved for consumer use
 *
 * Service:
 *
 * The Find protocol finds the directory entry or group of entries matching the
 * specified file pathname. The filename portion of the pathname may contain
 * global (wild card) characters.
 *
 * The Find protocol is used to match the find OS/2 system call. The protocols
 * "Find", "Find_Unique" and "Find_Close" are methods of reading (or searching)
 * a directory. These protocols may be used in place of the core "Search"
 * protocol when LANMAN 1.0 dialect has been negotiated. There may be cases
 * where the Search protocol will still be used.
 *
 * The format of the Find protocol is the same as the core "Search" protocol.
 * The difference is that the directory is logically Opened with a Find protocol
 * and logically closed with the Find Close protocol. This allows the Server to
 * make better use of its resources. Search buffers are thus held (allowing
 * search resumption via presenting a "resume_key") until a Find Close protocol
 * is received. The sr_findid field of each resume key is a unique identifier
 * (within the session) of the search from "Find" through "Find close". Thus if
 * the consumer does "Find ahead", any find buffers containing resume keys with
 * the matching find id may be released when the Find Close is requested.
 *
 * As is true of a failing open, if a Find request (Find "first" request where
 * resume_key is null) fails (no entries are found), no find close protocol is
 * expected.
 *
 * If no global characters are present, a "Find Unique" protocol should be used
 * (only one entry is expected and find close need not be sent).
 *
 * The file path name in the request specifies the file to be sought. The
 * attribute field indicates the attributes that the file must have. If the
 * attribute is zero then only normal files are returned. If the system file,
 * hidden or directory attributes are specified then the search is inclusive --
 * both the specified type(s) of files and normal files are returned. If the
 * volume label attribute is specified then the search is exclusive, and only
 * the volume label entry is returned
 *
 * The max-count field specifies the number of directory entries to be returned.
 * The response will contain zero or more directory entries as determined by the
 * count-returned field. No more than max-count entries will be returned. Only
 * entries that match the sought filename/attribute will be returned.
 *
 * The resume_key field must be null (length = 0) on the initial ("Find First")
 * find request. Subsequent find requests intended to continue a search must
 * contain the resume_key field extracted from the last directory entry of the
 * previous response. The resume_key field is self-contained, for on calls
 * containing a resume_key neither the attribute or pathname fields will be
 * valid in the request. A find request will terminate when either the
 * requested maximum number of entries that match the named file are found, or
 * the end of directory is reached without the maximum number of matches being
 * found. A response containing no entries indicates that no matching entries
 * were found between the starting point of the search and the end of directory.
 *
 * There may be multiple matching entries in response to a single request as
 * Find supports "wild cards" in the file name (last component of the pathname).
 * "?" is the wild single characters, "*" or "null" will match any number of
 * filename characters within a single part of the filename component. The
 * filename is divided into two parts -- an eight character name and a three
 * character extension. The name and extension are divided by a ".".
 *
 * If a filename part commences with one or more "?"s then exactly that number
 * of characters will be matched by the Wild Cards, e.g., "??x" will equal "abx"
 * but not "abcx" or "ax". When a filename part has trailing "?"s then it will
 * match the specified number of characters  or less, e.g., "x??" will match
 * "xab", "xa" and "x", but not "xabc". If only "?"s are present in the filename
 * part, then it is handled as for trailing "?"s "*" or "null" match entire
 * pathname parts, thus "*.abc" or ".abc" will match any file with an extension
 * of "abc". "*.*", "*" or "null" will match all files in a directory.
 *
 * Unprotected servers require the requester to have read permission on the
 * subtree containing the directory searched (the share specifies read
 * permission).
 *
 * Protected servers require the requester to have permission to search the
 * specified directory.
 *
 * If a Find requests more data than can be placed in a message of the
 * max-xmit-size for the TID specified, the server will return only the number
 * of entries which will fit.
 *
 * The number of entries returned will be the minimum of:
 *    1. The number of entries requested.
 *    2. The number of (complete) entries that will fit in the negotiated SMB
 *       buffer.
 *    3. The number of entries that match the requested name pattern and
 *       attributes.
 *
 * The error ERRnofiles set in smb_err field of the response header or a zero
 * value in smb_count of the response indicates no matching entry was found.
 *
 * The resume search key returned along with each directory entry is a server
 * defined key which when returned in the Find Next protocol, allows the
 * directory search to be resumed at the directory entry fol lowing the one
 * denoted by the resume search key.
 *
 * The date is in the following format:
 *   bits:
 *	1 1 1 1  1 1
 *	5 4 3 2  1 0 9 8  7 6 5 4  3 2 1 0
 *	y y y y  y y y m  m m m d  d d d d
 *   where:
 *	y - bit of year 0-119 (1980-2099)
 *	m - bit of month 1-12
 *	d - bit of day 1-31
 *
 * The time is in the following format:
 *   bits:
 *	1 1 1 1  1 1
 *	5 4 3 2  1 0 9 8  7 6 5 4  3 2 1 0
 *	h h h h  h m m m  m m m x  x x x x
 *   where:
 *	h - bit of hour (0-23)
 *	m - bit of minute (0-59)
 *	x - bit of 2 second increment
 *
 * Find may generate the following errors.
 *	ERRDOS/ERRnofiles
 *	ERRDOS/ERRbadpath
 *	ERRDOS/ERRnoaccess
 *	ERRDOS/ERRbadaccess
 *	ERRDOS/ERRbadshare
 *	ERRSRV/ERRerror
 *	ERRSRV/ERRaccess
 *	ERRSRV/ERRinvnid
 */
int
smb_com_find(struct smb_request *sr)
{
	int			rc;
	unsigned short		sattr, count, maxcount;
	char			*path;
	char			filename[14];
	uint32_t		cookie;
	struct smb_node		*node;
	unsigned char		type;
	unsigned short		key_len;
	smb_odir_context_t *pc;

	if (smbsr_decode_vwv(sr, "ww", &maxcount, &sattr) != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	if ((smbsr_decode_data(sr, "%Abw", sr, &path, &type, &key_len) != 0) ||
	    (type != 0x05)) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	if (key_len == 0) {		/* begin search */
		(void) smb_rdir_open(sr, path, sattr);
		cookie = 0;
	} else if (key_len == 21) {
		sr->smb_sid = 0;
		if (smb_decode_mbc(&sr->smb_data, SMB_RESUME_KEY_FMT,
		    filename, &sr->smb_sid, &cookie) != 0) {
			/* We don't know which rdir to close */
			smbsr_decode_error(sr);
			/* NOTREACHED */
		}

		sr->sid_odir = smb_odir_lookup_by_sid(sr->tid_tree,
		    sr->smb_sid);
		if (sr->sid_odir == NULL) {
			smbsr_error(sr, NT_STATUS_INVALID_HANDLE,
			    ERRDOS, ERRbadfid);
			/* NOTREACHED */
		}

		cookie--;			/* +1 when returned */
	} else {
		/* We don't know which rdir to close */
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	(void) smb_encode_mbc(&sr->reply, "bwwbw", 1, 0, VAR_BCC, 5, 0);

	pc = MEM_ZALLOC("smb", sizeof (*pc));
	pc->dc_cookie = cookie;
	count = 0;
	node = (struct smb_node *)0;
	rc = 0;
	while (count < maxcount) {
		if ((rc = smb_rdir_next(sr, &node, pc)) != 0)
			break;

		(void) smb_encode_mbc(&sr->reply, ".8c3cbl4.bYl13c",
		    pc->dc_name83, pc->dc_name83+9, sr->smb_sid,
		    pc->dc_cookie+1, pc->dc_dattr,
		    smb_gmt_to_local_time(pc->dc_attr.sa_vattr.va_mtime.tv_sec),
		    (int32_t)smb_node_get_size(node, &pc->dc_attr),
		    (*pc->dc_shortname) ? pc->dc_shortname : pc->dc_name);
		smb_node_release(node);
		node = (struct smb_node *)0;
		count++;
	}
	MEM_FREE("smb", pc);

	if ((rc != 0) && (rc != ENOENT)) {
		/* returned error by smb_rdir_next() */
		smb_rdir_close(sr);
		smbsr_errno(sr, rc);
		/* NOTREACHED */
	}

	if (count == 0) {
		smb_rdir_close(sr);
		smbsr_error(sr, 0, ERRDOS, ERRnofiles);
		/* NOTREACHED */
	}

	rc = (MBC_LENGTH(&sr->reply) - sr->cur_reply_offset) - 8;
	if (smb_poke_mbc(&sr->reply, sr->cur_reply_offset,
	    "bwwbw", 1, count, rc+3, 5, rc) < 0) {
		smb_rdir_close(sr);
		smbsr_encode_error(sr);
		/* NOTREACHED */
	}

	return (SDRC_NORMAL_REPLY);
}

/*
 * smb_com_find_close
 *
 * Request Format: (same as core Search Protocol - "Find Next" form)
 *
 *  Client Request                     Description
 *  ================================== =================================
 *
 *  BYTE  smb_wct;			value = 2
 *  WORD  smb_count;			max number of entries to find
 *  WORD  smb_attr;			search attribute
 *  WORD  smb_bcc;			minimum value = 5
 *  BYTE  smb_ident1;			ASCII  (04)
 *  BYTE  smb_pathname[];		null (may contain only null)
 *  BYTE  smb_ident2;			Variable Block (05)
 *  WORD  smb_keylen;			resume (close) key length
 *					 (may not be zero)
 *  BYTE  smb_resumekey[*];		"Find Close" key
 *					 (* = value of smb_keylen)
 *
 * Response Format: (same format as core Search Protocol)
 *
 *  Server Response                    Description
 *  ================================== =================================
 *
 *  BYTE  smb_wct;			value = 1
 *  WORD  smb_reserved;			reserved
 *  WORD  smb_bcc;			value = 3
 *  BYTE  smb_ident;			Variable Block (05)
 *  WORD  smb_datalen;			data length (value = 0)
 *
 *  The resume_key (or close key) has the following format:
 *
 *  BYTE  sr_res;			reserved:
 * 					bit  7 - reserved for consumer use
 *					bit  5,6 - reserved for system use
 *					  (must be preserved)
 *					bits 0-4 - rsvd for server
 *					  (must be preserved by consumer)
 *  BYTE  sr_name[11];			pathname sought.
 * 					Format: 1-8 character file name,
 *					left justified 0-3 character extension,
 *					left justified (in last 3 chars)
 *  BYTE  sr_findid[1];			uniquely identifies find
 * 					through find_close
 *  BYTE  sr_server[4];			available for server use
 * 					(must be non-zero)
 *  BYTE  sr_res[4];			reserved for consumer use
 *
 *  Service:
 *
 * The  Find_Close  protocol  closes  the  association  between  a  Find  id
 * returned  (in  the  resume_key)  by  the Find protocol and the directory
 * search.
 *
 * Whereas  the  First  Find  protocol  logically  opens  the  directory,
 * subsequent  find  protocols  presenting  a resume_key  further "read" the
 * directory,  the  Find  Close  protocol "closes" the  directory  allowing  the
 * server to free any resources held in support of the directory search.
 *
 * The  Find  Close  protocol  is  used  to  match  the  find  Close  OS/2
 * system call.  The  protocols "Find", "Find Unique" and "Find  Close" are
 * methods  of reading  (or  searching)  a  directory.  These  protocols  may
 * be used in place of the core "Search" protocol when LANMAN 1.0 dialect has
 * been negotiated.  There may be cases where the Search protocol will still be
 * used.
 *
 * Although  only  the  find  id  portion  the  resume  key  should  be
 * required to  identify  the  search  being  ter minated,  the entire
 * resume_key as returned in  the previous Find, either a "Find  First" or "Find
 * Next" is sent to the server in this protocol.
 *
 * Find Close may generate the following errors:
 *
 *	ERRDOS/ERRbadfid
 *	ERRSRV/ERRerror
 *	ERRSRV/ERRinvnid
 */
int
smb_com_find_close(struct smb_request *sr)
{
	unsigned short		sattr, maxcount;
	char			*path;
	char			filename[14];
	uint32_t		cookie;
	unsigned char		type;
	unsigned short		key_len;
	int			rc;

	if (smbsr_decode_vwv(sr, "ww", &maxcount, &sattr) != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	rc = smbsr_decode_data(sr, "%Abw", sr, &path, &type, &key_len);
	if ((rc != 0) || (type != 0x05)) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	if (key_len == 0) {		/* begin search */
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		/* NOTREACHED */
	}

	if (key_len == 21) {
		sr->smb_sid = 0;
		if (smb_decode_mbc(&sr->smb_data, SMB_RESUME_KEY_FMT,
		    filename, &sr->smb_sid, &cookie) != 0) {
			smbsr_decode_error(sr);
			/* NOTREACHED */
		}

		sr->sid_odir = smb_odir_lookup_by_sid(sr->tid_tree,
		    sr->smb_sid);
		if (sr->sid_odir == NULL) {
			smbsr_error(sr, NT_STATUS_INVALID_HANDLE,
			    ERRDOS, ERRbadfid);
			/* NOTREACHED */
		}

		cookie--;		/* +1 when returned */
	} else {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	smb_rdir_close(sr);
	smbsr_encode_result(sr, 1, 3, "bwwbw", 1, 0, 3, 5, 0);
	return (SDRC_NORMAL_REPLY);
}
