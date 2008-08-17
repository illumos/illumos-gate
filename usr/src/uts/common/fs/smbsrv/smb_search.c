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

#pragma ident	"@(#)smb_search.c	1.9	08/08/07 SMI"

/*
 * SMB: search
 *
 * This command is used to search directories.
 *
 * Client Request                     Description
 * ================================== =================================
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
 * the attributes that the file must have, and is described in the "File
 * Attribute Encoding" section of this document.  If  SearchAttributes is
 * zero then only normal files are returned.  If the system file, hidden or
 * directory attributes are specified then the search is inclusive@both the
 * specified type(s) of files and normal files are returned.  If the volume
 * label attribute is specified then the search is exclusive, and only the
 * volume label entry is returned.
 *
 * MaxCount specifies the number of directory entries to be returned.
 *
 * Server Response                    Description
 * ================================== =================================
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
 * previous response.  ResumeKey is self-contained, for on calls containing
 * a non-zero ResumeKey neither the SearchAttributes or FileName fields
 * will be valid in the request.  ResumeKey has the following format:
 *
 * Resume Key Field                   Description
 * ================================== =================================
 *
 * UCHAR Reserved;                    bit 7 - consumer use
 *                                     bits 5,6 - system use (must
 *                                     preserve)
 *                                     bits 0-4 - server use (must
 *                                     preserve)
 * UCHAR FileName[11];                Name of the returned file
 * UCHAR ReservedForServer[5];        Client must not modify
 * UCHAR ReservedForConsumer[4];      Server must not modify
 *
 * FileName is 8.3 format, with the three character extension left
 * justified into FileName[9-11].  If the client is prior to the LANMAN1.0
 * dialect, the returned FileName should be uppercased.
 *
 * SMB_COM_SEARCH terminates when either the requested maximum number of
 * entries that match the named file are found, or the end of directory is
 * reached without the maximum number of matches being found.  A response
 * containing no entries indicates that no matching entries were found
 * between the starting point of the search and the end of directory.
 *
 * There may be multiple matching entries in response to a single request
 * as SMB_COM_SEARCH supports wildcards in the last component of FileName
 * of the initial request.
 *
 * Returned directory entries in the DirectoryInformationData field of the
 * response each have the following format:
 *
 * Directory Information Field        Description
 * ================================== =================================
 *
 * SMB_RESUME_KEY ResumeKey;          Described above
 * UCHAR FileAttributes;              Attributes of the found file
 * SMB_TIME LastWriteTime;            Time file was last written
 * SMB_DATE LastWriteDate;            Date file was last written
 * ULONG FileSize;                    Size of the file
 * UCHAR FileName[13];                ASCII, space-filled null
 *                                     terminated
 *
 * FileName must conform to 8.3 rules, and is padded after the extension
 * with 0x20 characters if necessary.  If the client has negotiated a
 * dialect prior to the LANMAN1.0 dialect, or if bit0 of the Flags2 SMB
 * header field of the request is clear, the returned FileName should be
 * uppercased.
 *
 * As can be seen from the above structure, SMB_COM_SEARCH can not return
 * long filenames, and can not return UNICODE filenames.  Files which have
 * a size greater than 2^32 bytes should have the least significant 32 bits
 * of their size returned in FileSize.
 */

#include <smbsrv/smb_incl.h>

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
	int		rc;
	unsigned short	sattr, count, maxcount;
	char		*path;
	uint16_t	index;
	uint32_t	cookie;
	char		name[SMB_SHORTNAMELEN];
	unsigned char	resume_char;
	uint32_t	client_key;
	smb_tree_t	*tree;
	smb_node_t	*node;
	unsigned char	type;
	unsigned short	key_len;
	smb_odir_context_t *pc;
	boolean_t	find_first = B_TRUE;
	boolean_t	to_upper = B_FALSE;

	if ((sr->session->dialect <= LANMAN1_0) ||
	    ((sr->smb_flg2 & SMB_FLAGS2_KNOWS_LONG_NAMES) == 0)) {
			to_upper = B_TRUE;
	}

	/* We only handle 8.3 name here */
	sr->smb_flg2 &= ~SMB_FLAGS2_KNOWS_LONG_NAMES;
	sr->smb_flg &= ~SMB_FLAGS_CASE_INSENSITIVE;

	if (smbsr_decode_vwv(sr, "ww", &maxcount, &sattr) != 0)
		return (SDRC_ERROR);

	rc = smbsr_decode_data(sr, "%Abw", sr, &path, &type, &key_len);
	if ((rc != 0) || (type != 0x05))
		return (SDRC_ERROR);

	tree = sr->tid_tree;
	count = 0;

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
		    1, 0, VAR_BCC, 5, 0, 0, path+1,
		    client_key, sattr, name);
		count++;
	} else {
		index = 0;
		cookie = 0;

		if (key_len == 0) {		/* begin search */
			/*
			 * Some MS clients pass NULL file names
			 * NT interprets this as "\"
			 */
			if (strlen(path) == 0) path = "\\";

			rc = smb_rdir_open(sr, path, sattr);
			if (rc == -1)
				return (SDRC_ERROR);
			if (rc == -2) {
				sr->reply.chain_offset = sr->cur_reply_offset;
				(void) smb_mbc_encodef(&sr->reply, "bw", 0, 0);
				return (SDRC_SUCCESS);
			}
			resume_char = 0;
			client_key = 0;
		} else if (key_len == 21) {
			if (smb_mbc_decodef(&sr->smb_data, "b12.wwl",
			    &resume_char, &index, &sr->smb_sid, &client_key)
			    != 0) {
				/* We don't know which search to close! */
				return (SDRC_ERROR);
			}

			sr->sid_odir = smb_odir_lookup_by_sid(tree,
			    sr->smb_sid);
			if (sr->sid_odir == NULL) {
				smbsr_error(sr, NT_STATUS_INVALID_HANDLE,
				    ERRDOS, ERRbadfid);
				return (SDRC_ERROR);
			}
			cookie = sr->sid_odir->d_cookies[index];
			if (cookie != 0)
				find_first = B_FALSE;
		} else {
			/* We don't know which search to close! */
			return (SDRC_ERROR);
		}

		(void) smb_mbc_encodef(&sr->reply, "bwwbw", 1, 0,
		    VAR_BCC, 5, 0);

		pc = kmem_zalloc(sizeof (smb_odir_context_t), KM_SLEEP);
		pc->dc_cookie = cookie;
		node = NULL;
		rc = 0;
		index = 0;

		if (maxcount > SMB_MAX_SEARCH)
			maxcount = SMB_MAX_SEARCH;

		while (count < maxcount) {
			if ((rc = smb_rdir_next(sr, &node, pc)) != 0)
				break;

			if (smb_is_dot_or_dotdot(pc->dc_name)) {
				if (node) {
					smb_node_release(node);
					node = NULL;
				}
				continue;
			}

			(void) memset(name, ' ', sizeof (name));
			if (*pc->dc_shortname) {
				(void) strlcpy(name, pc->dc_shortname,
				    SMB_SHORTNAMELEN - 1);
			} else {
				(void) strlcpy(name, pc->dc_name,
				    SMB_SHORTNAMELEN - 1);
				if (to_upper)
					(void) utf8_strupr(name);
			}

			(void) smb_mbc_encodef(&sr->reply, "b8c3c.wwlbYl13c",
			    resume_char,
			    pc->dc_name83, pc->dc_name83+9,
			    index, sr->smb_sid, client_key,
			    pc->dc_dattr & 0xff,
			    smb_gmt2local(sr,
			    pc->dc_attr.sa_vattr.va_mtime.tv_sec),
			    (int32_t)smb_node_get_size(node, &pc->dc_attr),
			    name);
			smb_node_release(node);
			node = NULL;
			sr->sid_odir->d_cookies[index] = pc->dc_cookie;
			count++;
			index++;
		}

		kmem_free(pc, sizeof (smb_odir_context_t));

		if ((rc != 0) && (rc != ENOENT)) {
			/* returned error by smb_rdir_next() */
			smb_rdir_close(sr);
			smbsr_errno(sr, rc);
			return (SDRC_ERROR);
		}

		if (count == 0 && find_first) {
			smb_rdir_close(sr);
			smbsr_warn(sr, NT_STATUS_NO_MORE_FILES,
			    ERRDOS, ERROR_NO_MORE_FILES);
			return (SDRC_ERROR);
		}
	}

	rc = (sr->reply.chain_offset - sr->cur_reply_offset) - 8;
	(void) smb_mbc_poke(&sr->reply, sr->cur_reply_offset, "bwwbw",
	    1, count, rc+3, 5, rc);

	return (SDRC_SUCCESS);
}
