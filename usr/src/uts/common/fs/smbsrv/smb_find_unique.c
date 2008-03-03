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
 *  WORD  smb_keylen;			must be zero ("Find First" only)
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
 * global (wild card) characters.  The search may not be resumed and no Find
 * Close protocol is expected.
 *
 * The Find protocol is used to match the find OS/2 system call. The protocols
 * "Find", "Find_Unique" and "Find_Close" are methods of reading (or searching)
 * a directory. These protocols may be used in place of the core "Search"
 * protocol when LANMAN 1.0 dialect has been negotiated. There may be cases
 * where the Search protocol will still be used.
 *
 * The format of the Find Unique protocol is the same as the core "Search"
 * protocol.  The difference is that the  directory  is  logically  opened  ,
 * any matching  entries  returned,  and  then  the  directory  is  logically
 * closed.
 *
 * This allows the Server to make better use of its resources. No Search buffers
 * are held (search resumption via presenting a "resume_key" will not be
 * allowed).
 *
 * Only one buffer of entries is expected and find close need not be sent).
 *
 * The  file  path  name  in  the  request  specifies  the  file  to  be
 * sought. The  attribute  field  indicates  the  attributes  that  the  file
 * must have. If  the  attribute  is  zero  then  only  normal  files  are
 * returned. If  the system file,  hidden  or  directory  attributes  are
 * specified  then the search  is  inclusive  --  both  the  specified  type(s)
 * of files  and normal files  are  returned.  If  the  volume  label attribute
 * is specified then the  search  is exclusive, and only the volume label entry
 * is returned
 *
 * The  max-count  field  specifies  the  number  of  directory  entries  to  be
 * returned.  The  response  will  contain zero  or  more  directory  entries
 * as determined  by  the  count-returned  field.  No  more  than  max-count
 * entries will be returned.  Only entries that match the sought
 * filename/attribute will be returned.
 *
 * The resume_key field must be null (length = 0).
 *
 * A Find_Unique  request will  terminate  when either  the  requested maximum
 * number  of  entries  that  match the  named  file  are  found,  or  the end
 * of directory  is  reached  without  the  maximum  number  of  matches being
 * found. A  response  containing  no  entries  indicates  that  no  matching
 * entries were  found  between the starting point of the search and the end of
 * directory.
 *
 * There  may  be  multiple  matching  entries  in  response  to  a  single
 * request  as  Find  Unique  supports "wild cards" in  the  file  name  (last
 * component  of  the  pathname). "?" is  the  wild  card  for  single
 * characters, "*" or "null" will  match  any  number  of  filename  characters
 * within  a single  part  of  the  filename  component. The  filename  is
 * divided into two parts  --  an  eight  character  name  and  a  three
 * character extension. The name and extension are divided by a ".".
 *
 * If  a  filename  part  commences  with  one  or  more "?"s  then  exactly
 * that number  of  characters  will  be matched  by  the  Wild  Cards,  e.g.,
 * "??x" will  equal "abx" but  not "abcx" or "ax".  When  a  filename  part has
 * trailing "?"s  then  it  will  match  the  specified  number  of  characters
 * or less,  e.g., "x??" will  match "xab", "xa" and "x",  but  not "xabc".  If
 * only "?"s  are  present  in  the  filename  part,  then  it  is  handled  as
 * for trailing "?"s
 *
 * "*" or "null" match  entire  pathname  parts,  thus "*.abc" or ".abc" will
 * match  any  file  with  an  extension of "abc". "*.*", "*" or "null" will
 * match all files in a directory.
 *
 * Unprotected servers require the requester to have read permission on the
 * subtree containing the directory searched, the share specifies read
 * permission.
 *
 * Protected servers require the requester to have permission to search the
 * specified directory.
 *
 * If  a  Find  Unique  requests  more  data  than  can  be  placed  in  a
 * message  of  the  max-xmit-size  for  the  TID specified, the server will
 * abort the virtual circuit to the consumer.
 *
 * The number of entries returned will be the minimum of:
 *
 *   1. The number of entries requested.
 *   2. The number of complete entries that will fit in the
 *	negotiated SMB buffer.
 *   3. The number of entries that match the requested name pattern and
 *	attributes.
 *
 * The error ERRnofiles set in smb_err field of the response header or a zero
 * value in smb_count of the response indicates no matching entry was found.
 *
 * The resume search key returned along with each directory entry is a server
 * defined key. This key will be returned as in the Find protocol and Search
 * protocol however it may NOT be returned to continue the search.
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
 * 	1 1 1 1  1 1
 * 	5 4 3 2  1 0 9 8  7 6 5 4  3 2 1 0
 *	h h h h  h m m m  m m m x  x x x x
 *   where:
 *	h - bit of hour (0-23)
 *	m - bit of minute (0-59)
 *	x - bit of 2 second increment
 *
 * Find Unique may generate the following errors.
 *	ERRDOS/ERRnofiles
 *	ERRDOS/ERRbadpath
 *	ERRDOS/ERRnoaccess
 *	ERRDOS/ERRbadaccess
 *	ERRDOS/ERRbadshare
 *	ERRSRV/ERRerror
 *	ERRSRV/ERRaccess
 *	ERRSRV/ERRinvnid
 */
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
	unsigned short		sattr, count, maxcount;
	char			*path;
	struct vardata_block	*vdb;
	struct smb_node		*node;
	smb_odir_context_t *pc;

	vdb = kmem_alloc(sizeof (struct vardata_block), KM_SLEEP);
	if (smbsr_decode_vwv(sr, "ww", &maxcount, &sattr) != 0) {
		kmem_free(vdb, sizeof (struct vardata_block));
		return (SDRC_ERROR);
	}

	if (smbsr_decode_data(sr, "%AV", sr, &path, vdb) != 0) {
		kmem_free(vdb, sizeof (struct vardata_block));
		return (SDRC_ERROR);
	}

	if (vdb->len != 0) {
		kmem_free(vdb, sizeof (struct vardata_block));
		return (SDRC_ERROR);
	}

	(void) smb_encode_mbc(&sr->reply, "bwwbw", 1, 0, VAR_BCC, 5, 0);

	/* begin search */
	if (smb_rdir_open(sr, path, sattr) != 0) {
		kmem_free(vdb, sizeof (struct vardata_block));
		return (SDRC_ERROR);
	}

	pc = kmem_zalloc(sizeof (*pc), KM_SLEEP);
	pc->dc_cookie = 0;
	count = 0;
	node = (struct smb_node *)0;
	rc = 0;
	while (count < maxcount) {
		if ((rc = smb_rdir_next(sr, &node, pc)) != 0)
			break;

		(void) smb_encode_mbc(&sr->reply, ".8c3cbl4.bYl13c",
		    pc->dc_name83, pc->dc_name83+9, sr->smb_sid,
		    pc->dc_cookie+1, pc->dc_dattr,
		    smb_gmt2local(sr, pc->dc_attr.sa_vattr.va_mtime.tv_sec),
		    (int32_t)smb_node_get_size(node, &pc->dc_attr),
		    (*pc->dc_shortname) ? pc->dc_shortname : pc->dc_name);
		smb_node_release(node);
		node = (struct smb_node *)0;
		count++;
	}
	kmem_free(pc, sizeof (*pc));

	smb_rdir_close(sr);

	if ((rc != 0) && (rc != ENOENT)) {
		/* returned error by smb_rdir_next() */
		kmem_free(vdb, sizeof (struct vardata_block));
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	if (count == 0) {
		kmem_free(vdb, sizeof (struct vardata_block));
		smbsr_error(sr, 0, ERRDOS, ERRnofiles);
		return (SDRC_ERROR);
	}

	rc = (MBC_LENGTH(&sr->reply) - sr->cur_reply_offset) - 8;
	if (smb_poke_mbc(&sr->reply, sr->cur_reply_offset,
	    "bwwbw", 1, count, rc+3, 5, rc) < 0) {
		kmem_free(vdb, sizeof (struct vardata_block));
		return (SDRC_ERROR);
	}
	kmem_free(vdb, sizeof (struct vardata_block));
	return (SDRC_SUCCESS);
}
