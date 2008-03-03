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

/*
 * SMB: trans2_query_file_information
 *
 * This request is used to get information about a specific file or
 * subdirectory given a handle to it.
 *
 *  Client Request             Value
 *  ========================== ==========================================
 *
 *  WordCount                  15
 *  MaxSetupCount              0
 *  SetupCount                 1
 *  Setup[0]                   TRANS2_QUERY_FILE_INFORMATION
 *
 *  Parameter Block Encoding   Description
 *  ========================== ==========================================
 *
 *  USHORT Fid;                Handle of file for request
 *  USHORT InformationLevel;   Level of information requested
 *
 * The available information levels, as well as the format of the response
 * are identical to TRANS2_QUERY_PATH_INFORMATION.
 */

#include <smbsrv/mlsvc.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>

uint32_t smb_pad_align(uint32_t offset, uint32_t align);


/*
 * smb_com_trans2_query_file_information
 *
 * Observation of Windows 2000 indicates the following:
 *
 * 1) If a file is opened with delete-on-close create options, the
 * delete-on-close status returned by the Trans2QueryFileInfo will not
 * be set.  The delete-on-close status will only be set when the above
 * file handle is closed.
 *
 * 2) If a file is not opened with delete-on-close create options but the
 * delete-on-close is set via Trans2SetFileInfo/DispositionInfo, the
 * delete-on-close status returned by Trans2QueryFileInfo will be set
 * immediately.
 */

smb_sdrc_t
smb_com_trans2_query_file_information(struct smb_request *sr, struct smb_xa *xa)
{
	static smb_attr_t pipe_attr;
	unsigned short	infolev, dattr = 0;
	u_offset_t	dsize = 0, dused = 0;
	smb_attr_t	*ap = NULL;
	char		*namep = NULL;
	char		*filename = NULL, *alt_nm_ptr = NULL;
	int		filename_len = 0;
	struct smb_node	*dir_snode = NULL;
	timestruc_t	*creation_time = NULL;
	unsigned char	delete_on_close = 0;
	unsigned char	is_dir = 0;
	char		*filebuf = NULL;

	/*
	 *  buffer for mangled name and shortname are allocated
	 *  much higher than required space. Optimization
	 *  here should be performed along with mangled_name & shortname
	 *  of query path information.
	 */
	char *mangled_name = 0;

	if (smb_decode_mbc(&xa->req_param_mb, "ww", &sr->smb_fid,
	    &infolev) != 0) {
		return (SDRC_ERROR);
	}

	sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree, sr->smb_fid);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	switch (sr->fid_ofile->f_ftype) {
	case SMB_FTYPE_DISK:
		{
		/*
		 * The node is only valid for SMB_FTYPE_DISK files.
		 */
		struct smb_node *node = sr->fid_ofile->f_node;

		/*
		 * For some reason NT will not show the security tab in the root
		 * directory of a mapped drive unless the filename length is
		 * greater than one.
		 * This may be a NT vs Windows9x UNICODE check.
		 * So we hack the length here to persuade NT to show the tab. It
		 * should be safe because of the null terminator character.
		 */
		/* be careful here we need od_name now rather than node_name */
		/* do we want to use node_name in the case of softlinks ?? */
		namep = node->od_name;
		filename = namep;
		filename_len = smb_ascii_or_unicode_strlen(sr, filename);
		if (strcmp(namep, ".") == 0 && filename_len == 1)
			filename_len = 2;

		creation_time = smb_node_get_crtime(node);
		dattr = smb_node_get_dosattr(node);

		ap = &node->attr;
		if (ap->sa_vattr.va_type == VDIR) {
			is_dir = 1;
			dsize = dused = 0;
		} else {
			is_dir = 0;
			dsize = ap->sa_vattr.va_size;
			dused = ap->sa_vattr.va_blksize *
			    ap->sa_vattr.va_nblocks;
		}

		dir_snode = node->dir_snode;
		delete_on_close =
		    (node->flags & NODE_FLAGS_DELETE_ON_CLOSE) != 0;
		}
		break;

	case SMB_FTYPE_MESG_PIPE:
		{
		/*
		 * The pipe is only valid for SMB_FTYPE_MESG_PIPE files.
		 */
		mlsvc_pipe_t *pipe_info = sr->fid_ofile->f_pipe_info;
		namep = pipe_info->pipe_name;

		filename = namep;
		filename_len = smb_ascii_or_unicode_strlen(sr, filename);

		ap = &pipe_attr;
		creation_time = (timestruc_t *)&ap->sa_vattr.va_ctime;
		dattr = SMB_FA_NORMAL;
		dsize = dused = 0;

		delete_on_close = 0;
		is_dir = 0;
		}
		break;

	default:
		smbsr_error(sr, 0, ERRDOS, ERRbadfile);
		return (SDRC_ERROR);
	}

	filebuf = kmem_alloc(MAXNAMELEN+1, KM_SLEEP);
	mangled_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	if (infolev > SMB_INFO_PASSTHROUGH)
		infolev -= SMB_INFO_PASSTHROUGH;

	switch (infolev) {
	case FileAccessInformation:
		(void) smb_encode_mbc(&xa->rep_data_mb, "l",
		    sr->fid_ofile->f_granted_access);
		break;

	case SMB_INFO_STANDARD:
		if (dsize > UINT_MAX)
			dsize = UINT_MAX;
		if (dused > UINT_MAX)
			dused = UINT_MAX;

		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		(void) smb_encode_mbc(&xa->rep_data_mb,
		    ((sr->session->native_os == NATIVE_OS_WIN95)
		    ? "YYYllw" : "yyyllw"),
		    smb_gmt2local(sr, creation_time->tv_sec),
		    smb_gmt2local(sr, ap->sa_vattr.va_atime.tv_sec),
		    smb_gmt2local(sr, ap->sa_vattr.va_mtime.tv_sec),
		    (uint32_t)dsize,
		    (uint32_t)dused,
		    dattr);
		break;

	case SMB_INFO_QUERY_EA_SIZE:
		if (dsize > UINT_MAX)
			dsize = UINT_MAX;
		if (dused > UINT_MAX)
			dused = UINT_MAX;

		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		(void) smb_encode_mbc(&xa->rep_data_mb,
		    ((sr->session->native_os == NATIVE_OS_WIN95)
		    ? "YYYllwl" : "yyyllwl"),
		    smb_gmt2local(sr, creation_time->tv_sec),
		    smb_gmt2local(sr, ap->sa_vattr.va_atime.tv_sec),
		    smb_gmt2local(sr, ap->sa_vattr.va_mtime.tv_sec),
		    (uint32_t)dsize,
		    (uint32_t)dused,
		    dattr, 0);
		break;

	case SMB_INFO_QUERY_EAS_FROM_LIST:
	case SMB_INFO_QUERY_ALL_EAS:
		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		(void) smb_encode_mbc(&xa->rep_data_mb, "l", 0);
		break;

	case SMB_INFO_IS_NAME_VALID:
		break;

	case SMB_QUERY_FILE_BASIC_INFO:
		/*
		 * NT includes 6 undocumented bytes at the end of this
		 * response, which are required by NetBench 5.01.
		 * Similar change in smb_trans2_query_path_information.c.
		 */
		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		(void) smb_encode_mbc(&xa->rep_data_mb, "TTTTw6.",
		    creation_time,
		    &ap->sa_vattr.va_atime,
		    &ap->sa_vattr.va_mtime,
		    &ap->sa_vattr.va_ctime,
		    dattr);
		break;

	case SMB_QUERY_FILE_STANDARD_INFO:
		(void) smb_encode_mbc(&xa->rep_param_mb, "w",
		    SMB_QUERY_FILE_STANDARD_INFO);
		/*
		 * Add 2 bytes to pad data to long. It is
		 * necessary because Win2k expects the padded bytes.
		 */
		(void) smb_encode_mbc(&xa->rep_data_mb, "qqlbb2.",
		    dused,
		    dsize,
		    ap->sa_vattr.va_nlink,
		    delete_on_close,
		    is_dir);
		break;

	case SMB_QUERY_FILE_EA_INFO:
		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		(void) smb_encode_mbc(&xa->rep_data_mb, "l", 0);
		break;

	case SMB_QUERY_FILE_NAME_INFO:
		/*
		 * It looks like NT doesn't know what to do with the name "."
		 * so we convert it to "\\" to indicate the root directory.
		 *
		 * If the leading \ is missing, add it.
		 */
		if (strcmp(namep, ".") == 0) {
			filename = "\\";
			filename_len = 2;
		} else if (*namep != '\\') {
			filename = filebuf;
			(void) snprintf(filename, MAXNAMELEN + 1, "\\%s",
			    namep);
			filename_len =
			    smb_ascii_or_unicode_strlen(sr, filename);
		} else {
			filename = namep;
			filename_len =
			    smb_ascii_or_unicode_strlen(sr, filename);
		}

		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		(void) smb_encode_mbc(&xa->rep_data_mb, "%lu", sr,
		    filename_len, filename);
		break;

	case SMB_QUERY_FILE_ALL_INFO:
		/*
		 * The reply of this information level on the
		 * wire doesn't match with protocol specification.
		 * This is what spec. needs: "TTTTwqqlbbqllqqll"
		 * But this is actually is sent on the wire:
		 * "TTTTw6.qqlbb2.l"
		 * So, there is a 6-byte pad between Attributes and
		 * AllocationSize. Also there is a 2-byte pad After
		 * Directory field. Between Directory and FileNameLength
		 * there is just 4 bytes that it seems is AlignmentRequirement.
		 * There are 6 other fields between Directory and
		 * AlignmentRequirement in spec. that aren't sent
		 * on the wire.
		 */
		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		(void) smb_encode_mbc(&xa->rep_data_mb, "TTTTw6.qqlbb2.l",
		    creation_time,
		    &ap->sa_vattr.va_atime,
		    &ap->sa_vattr.va_mtime,
		    &ap->sa_vattr.va_ctime,
		    dattr,
		    (int64_t)dused,
		    (int64_t)dsize,
		    ap->sa_vattr.va_nlink,
		    delete_on_close,
		    is_dir,
		    0);
		(void) smb_encode_mbc(&xa->rep_data_mb, "%lu",
		    sr, filename_len, filename);
		break;

	case SMB_QUERY_FILE_ALT_NAME_INFO:
		/*
		 * Conform to the rule used by Windows NT/2003 servers.
		 * Shortname is created only if either the
		 * filename or extension portion of a file is made up of
		 * mixed case. This is handled in os/libnt/nt_mangle_name.c.
		 *
		 * If the shortname is generated, it will be returned as
		 * the alternative name.  Otherwise, converts the original
		 * name to all upper-case and returns it as the alternative
		 * name.  This is how Windows NT/2003 servers behave.  However,
		 * Windows 2000 seems to preserve the case of the original
		 * name, and returns it as the alternative name.
		 */
		alt_nm_ptr = (*mangled_name == 0) ?
		    utf8_strupr(filename) : mangled_name;
		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		(void) smb_encode_mbc(&xa->rep_data_mb, "%lu", sr,
		    smb_ascii_or_unicode_strlen(sr, alt_nm_ptr), alt_nm_ptr);
		break;

	case SMB_QUERY_FILE_STREAM_INFO:
		{
		struct smb_node *node = sr->fid_ofile->f_node;
		if (dir_snode == NULL) {
			kmem_free(filebuf, MAXNAMELEN+1);
			kmem_free(mangled_name, MAXNAMELEN);
			smbsr_error(sr, 0, ERRDOS, ERRbadfile);
			return (SDRC_ERROR);
		}
		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		if (SMB_IS_STREAM(node)) {
			ASSERT(node->unnamed_stream_node);
			ASSERT(node->unnamed_stream_node->n_magic ==
			    SMB_NODE_MAGIC);
			ASSERT(node->unnamed_stream_node->n_state !=
			    SMB_NODE_STATE_DESTROYING);

			(void) smb_encode_stream_info(sr, xa,
			    node->unnamed_stream_node, ap);
		} else {
			(void) smb_encode_stream_info(sr, xa, node, ap);
		}
		break;
		}
	case SMB_QUERY_FILE_COMPRESSION_INFO:
		(void) smb_encode_mbc(&xa->rep_param_mb, "w", 0);
		(void) smb_encode_mbc(&xa->rep_data_mb, "qwbbb3.",
		    dsize, 0, 0, 0, 0);
		break;

	default:
		kmem_free(filebuf, MAXNAMELEN+1);
		kmem_free(mangled_name, MAXNAMELEN);
		smbsr_error(sr, 0, ERRDOS, ERRunknownlevel);
		return (SDRC_ERROR);
	}

	kmem_free(filebuf, MAXNAMELEN+1);
	kmem_free(mangled_name, MAXNAMELEN);
	return (SDRC_SUCCESS);
}

/*
 * smb_encode_stream_info
 *
 * This function encodes the streams information for both T2QueryFileInfo
 * and T2QueryPathInfo. The rules about how to do this are not documented.
 * They have been derived using observed NT behaviour and the IR's listed
 * below.
 *
 * IR101680: ArcServe2000 problem. ArcServe doesn't like the null-
 * stream data on directories that don't have any associated streams.
 *
 * IR103484 and KB article Q234765: Citrix problem. If there are no
 * streams, only return the unnamed stream data if the target is a
 * file. The Citrix Metaframe cdm.sys driver crashes the Windows server,
 * on which it's running, if it receives the unexpected stream data
 * for a directory.
 *
 * If there are streams, on files or directories, we need to return
 * them to support Mac/DAVE clients. Mac clients make this request
 * to see if there is a comment stream. If we don't provide the
 * information, the client won't try to access the comment stream.
 *
 * If the target is a file:
 * 1. If there are no named streams, the response should still contain
 *    an entry for the unnamed stream.
 * 2. If there are named streams, the response should contain an entry
 *    for the unnamed stream followed by the entries for the named
 *    streams.
 *
 * If the target is a directory:
 * 1. If there are no streams, the response is complete. Directories
 *    do not report the unnamed stream.
 * 2. If there are streams, the response should contain entries for
 *    those streams but there should not be an entry for the unnamed
 *    stream.
 *
 * Note that the stream name lengths exclude the null terminator but
 * the field lengths (i.e. next offset calculations) need to include
 * the null terminator and be padded to a multiple of 8 bytes. The
 * last entry does not seem to need any padding.
 */

void
smb_encode_stream_info(
    struct smb_request *sr,
    struct smb_xa *xa,
    struct smb_node *snode,
    smb_attr_t *attr)
{
	char *stream_name;
	uint32_t next_offset;
	uint32_t stream_nlen;
	uint32_t pad;
	u_offset_t dsize;
	int is_dir;
	uint32_t cookie = 0;
	struct fs_stream_info *stream_info;
	struct fs_stream_info *stream_info_next;
	int rc = 0;
	int done = 0;
	char *fname;

	stream_info = kmem_alloc(sizeof (struct fs_stream_info), KM_SLEEP);
	stream_info_next = kmem_alloc(sizeof (struct fs_stream_info), KM_SLEEP);
	is_dir = (attr->sa_vattr.va_type == VDIR) ? 1 : 0;
	dsize = attr->sa_vattr.va_size;
	fname = MEM_MALLOC("smb", MAXPATHLEN);

	rc = smb_fsop_stream_readdir(sr, kcred, snode, &cookie, stream_info,
	    NULL, NULL);

	if ((cookie == 0x7FFFFFFF) || (rc == EACCES) || (rc == ENOENT)) {
		if (is_dir == 0) {
			stream_name = "::$DATA";
			stream_nlen =
			    smb_ascii_or_unicode_strlen(sr, stream_name);
			next_offset = 0;

			(void) smb_encode_mbc(&xa->rep_data_mb, "%llqqu",
			    sr, next_offset, stream_nlen, dsize, dsize,
			    stream_name);
		}
		/* No named streams, we're done  */
		kmem_free(stream_info, sizeof (struct fs_stream_info));
		kmem_free(stream_info_next, sizeof (struct fs_stream_info));
		MEM_FREE("smb", fname);
		return;
	}

	if (is_dir == 0) {
		stream_name = "::$DATA";
		stream_nlen = smb_ascii_or_unicode_strlen(sr, stream_name);

		/*
		 * Offset calculation:
		 * 2 dwords + 2 quadwords => 4 + 4 + 8 + 8 => 24
		 */
		next_offset = 24 + stream_nlen +
		    smb_ascii_or_unicode_null_len(sr);

		(void) smb_encode_mbc(&xa->rep_data_mb, "%llqqu", sr,
		    next_offset, stream_nlen, dsize, dsize, stream_name);
	}

	while (!done) {
		/*
		 * Named streams.
		 */
		stream_nlen = smb_ascii_or_unicode_strlen(sr,
		    stream_info->name);
		next_offset = 0;
		pad = 0;

		/*
		 * this is a little kludgy, since we use a cookie now and last
		 * packet does not have a pad we need to check the next item
		 * before we encode the current one
		 */
		stream_info_next->name[0] = 0;
		rc = smb_fsop_stream_readdir(sr, kcred, snode, &cookie,
		    stream_info_next, NULL, NULL);
		if (cookie == 0x7FFFFFFF) {
			done = 1;
		} else {
			if (cookie == 0) {
				break;
			}
			next_offset = 24 + stream_nlen +
			    smb_ascii_or_unicode_null_len(sr);
			pad = smb_pad_align(next_offset, 8);
			next_offset += pad;
		}
		(void) smb_encode_mbc(&xa->rep_data_mb, "%llqqu#.",
		    sr, next_offset, stream_nlen,
		    stream_info->size, stream_info->size,
		    stream_info->name, pad);

		(void) memcpy(stream_info, stream_info_next,
		    sizeof (struct fs_stream_info));
	}
	kmem_free(stream_info, sizeof (struct fs_stream_info));
	kmem_free(stream_info_next, sizeof (struct fs_stream_info));
	MEM_FREE("smb", fname);
}

/*
 * smb_pad_align
 *
 * Returns the number of bytes required to get pad an offset to the
 * specified alignment.
 */
uint32_t
smb_pad_align(uint32_t offset, uint32_t align)
{
	uint32_t pad = offset % align;

	if (pad != 0)
		pad = align - pad;

	return (pad);
}
