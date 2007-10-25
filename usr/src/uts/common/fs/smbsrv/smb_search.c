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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

int
smb_com_search(struct smb_request *sr)
{
	int			rc;
	unsigned short		sattr, count, maxcount;
	char			*path;
	uint32_t		cookie;
	char			name[14];
	unsigned char		resume_char;
	uint32_t		resume_key;
	struct smb_node		*node;
	unsigned char		type;
	unsigned short		key_len;
	fsvol_attr_t vol_attr;
	smb_odir_context_t *pc;

	/* We only handle 8.3 name here */
	sr->smb_flg2 &= ~SMB_FLAGS2_KNOWS_LONG_NAMES;
	sr->smb_flg &= ~SMB_FLAGS_CASE_INSENSITIVE;

	if (smbsr_decode_vwv(sr, "ww", &maxcount, &sattr) != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	if ((smbsr_decode_data(sr, "%Abw", sr, &path, &type, &key_len) != 0) ||
	    (type != 0x05)) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	if ((rc = fsd_getattr(&sr->tid_tree->t_fsd, &vol_attr)) != 0) {
		smbsr_raise_errno(sr, rc);
		/* NOTREACHED */
	}

	count = 0;

	if ((sattr == SMB_FA_VOLUME) && (key_len != 21)) {
		(void) memset(name, ' ', sizeof (name));
		(void) strncpy(name, vol_attr.name, sizeof (name));

		if (key_len >= 21) {
			(void) smb_decode_mbc(&sr->smb_data, "17.l",
			    &resume_key);
		} else {
			resume_key = 0;
		}

		(void) smb_encode_mbc(&sr->reply, "bwwbwb11c5.lb8.13c",
		    1, 0, VAR_BCC, 5, 0, 0, path+1,
		    resume_key, sattr, name);
		count++;
	} else {
		cookie = 0;
		if (key_len == 0) {		/* begin search */
			/*
			 * Some MS clients pass NULL file names
			 * NT interprets this as "\"
			 */
			if (strlen(path) == 0) path = "\\";

			rc = smb_rdir_open(sr, path, sattr);
			if (rc == SDRC_NORMAL_REPLY) {
				sr->reply.chain_offset = sr->cur_reply_offset;
				(void) smb_encode_mbc(&sr->reply, "bw", 0, 0);
				return (rc);
			}
			resume_char = 0;
			resume_key = 0;
		} else if (key_len == 21) {
			if (smb_decode_mbc(&sr->smb_data, "b12.wwl",
			    &resume_char, &cookie, &sr->smb_sid,
			    &resume_key) != 0) {
				/* We don't know which search to close! */
				smbsr_decode_error(sr);
				/* NOTREACHED */
			}

			sr->sid_odir = smb_odir_lookup_by_sid(sr->tid_tree,
			    sr->smb_sid);
			if (sr->sid_odir == NULL) {
				smbsr_raise_cifs_error(sr,
				    NT_STATUS_INVALID_HANDLE,
				    ERRDOS, ERRbadfid);
				/* NOTREACHED */
			}
		} else {
			/* We don't know which search to close! */
			smbsr_decode_error(sr);
			/* NOTREACHED */
		}

		(void) smb_encode_mbc(&sr->reply, "bwwbw", 1, 0, VAR_BCC, 5, 0);

		pc = MEM_ZALLOC("smb", sizeof (*pc));
		pc->dc_cookie = cookie;
		node = (struct smb_node *)0;
		rc = 0;
		while (count < maxcount) {
			if ((rc = smb_rdir_next(sr, &node, pc)) != 0)
				break;
			if ((strcmp(pc->dc_name, ".") == 0) ||
			    (strcmp(pc->dc_name, "..") == 0)) {
				if (node) {
					smb_node_release(node);
					node = (struct smb_node *)0;
				}
				continue;
			}

			(void) memset(name, ' ', sizeof (name));
			if (*pc->dc_shortname)
				(void) strncpy(name, pc->dc_shortname, 13);
			else {
				(void) strncpy(name, pc->dc_name, 13);
				if ((sr->session->dialect <= LANMAN1_0) ||
				    ((sr->smb_flg2 &
				    SMB_FLAGS2_KNOWS_LONG_NAMES) == 0))
					(void) utf8_strupr(name);
			}

			(void) smb_encode_mbc(&sr->reply, "b8c3c.wwlbYl13c",
			    resume_char,
			    pc->dc_name83, pc->dc_name83+9,
			    pc->dc_cookie, sr->smb_sid,
			    resume_key,
			    pc->dc_dattr & 0xff,
			    pc->dc_attr.sa_vattr.va_mtime.tv_sec,
			    (int32_t)smb_node_get_size(node, &pc->dc_attr),
			    name);
			smb_node_release(node);
			node = (struct smb_node *)0;
			count++;
		}
		MEM_FREE("smb", pc);

		if ((rc != 0) && (rc != ENOENT)) {
			/* returned error by smb_rdir_next() */
			smb_rdir_close(sr);
			smbsr_raise_errno(sr, rc);
			/* NOTREACHED */
		}

		if (count == 0) {
			smb_rdir_close(sr);
			smbsr_raise_error(sr, ERRDOS, ERRnofiles);
			/* NOTREACHED */
		}
	}

	rc = (sr->reply.chain_offset - sr->cur_reply_offset) - 8;
	(void) smb_poke_mbc(&sr->reply, sr->cur_reply_offset, "bwwbw",
	    1, count, rc+3, 5, rc);

	return (SDRC_NORMAL_REPLY);
}
