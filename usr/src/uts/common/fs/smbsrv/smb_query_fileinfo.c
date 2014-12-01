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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/smb_fsops.h>

/*
 * Trans2 Query File/Path Information Levels:
 *
 * SMB_INFO_STANDARD
 * SMB_INFO_QUERY_EA_SIZE
 * SMB_INFO_QUERY_EAS_FROM_LIST
 * SMB_INFO_QUERY_ALL_EAS - not valid for pipes
 * SMB_INFO_IS_NAME_VALID - only valid when query is by path
 *
 * SMB_QUERY_FILE_BASIC_INFO
 * SMB_QUERY_FILE_STANDARD_INFO
 * SMB_QUERY_FILE_EA_INFO
 * SMB_QUERY_FILE_NAME_INFO
 * SMB_QUERY_FILE_ALL_INFO
 * SMB_QUERY_FILE_ALT_NAME_INFO - not valid for pipes
 * SMB_QUERY_FILE_STREAM_INFO - not valid for pipes
 * SMB_QUERY_FILE_COMPRESSION_INFO - not valid for pipes
 *
 * Supported Passthrough levels:
 * SMB_FILE_BASIC_INFORMATION
 * SMB_FILE_STANDARD_INFORMATION
 * SMB_FILE_INTERNAL_INFORMATION
 * SMB_FILE_EA_INFORMATION
 * SMB_FILE_ACCESS_INFORMATION - not yet supported when query by path
 * SMB_FILE_NAME_INFORMATION
 * SMB_FILE_ALL_INFORMATION
 * SMB_FILE_ALT_NAME_INFORMATION - not valid for pipes
 * SMB_FILE_STREAM_INFORMATION - not valid for pipes
 * SMB_FILE_COMPRESSION_INFORMATION - not valid for pipes
 * SMB_FILE_NETWORK_OPEN_INFORMATION - not valid for pipes
 * SMB_FILE_ATTR_TAG_INFORMATION - not valid for pipes
 *
 * Internal levels representing non trans2 requests
 * SMB_QUERY_INFORMATION
 * SMB_QUERY_INFORMATION2
 */

/*
 * SMB_STREAM_ENCODE_FIXED_SIZE:
 * 2 dwords + 2 quadwords => 4 + 4 + 8 + 8 => 24
 */
#define	SMB_STREAM_ENCODE_FIXED_SZ	24

typedef struct smb_queryinfo {
	smb_node_t	*qi_node;	/* NULL for pipes */
	smb_attr_t	qi_attr;
	boolean_t	qi_delete_on_close;
	uint32_t	qi_namelen;
	char		qi_shortname[SMB_SHORTNAMELEN];
	char		qi_name[MAXPATHLEN];
} smb_queryinfo_t;
#define	qi_mtime	qi_attr.sa_vattr.va_mtime
#define	qi_ctime	qi_attr.sa_vattr.va_ctime
#define	qi_atime	qi_attr.sa_vattr.va_atime
#define	qi_crtime	qi_attr.sa_crtime

static int smb_query_by_fid(smb_request_t *, smb_xa_t *, uint16_t);
static int smb_query_by_path(smb_request_t *, smb_xa_t *, uint16_t);

static int smb_query_fileinfo(smb_request_t *, smb_node_t *,
    uint16_t, smb_queryinfo_t *);
static int smb_query_pipeinfo(smb_request_t *, smb_opipe_t *,
    uint16_t, smb_queryinfo_t *);
static boolean_t smb_query_pipe_valid_infolev(smb_request_t *, uint16_t);

static int smb_query_encode_response(smb_request_t *, smb_xa_t *,
    uint16_t, smb_queryinfo_t *);
static void smb_encode_stream_info(smb_request_t *, smb_xa_t *,
    smb_queryinfo_t *);
static boolean_t smb_stream_fits(smb_request_t *, smb_xa_t *, char *, uint32_t);
static int smb_query_pathname(smb_request_t *, smb_node_t *, boolean_t,
    smb_queryinfo_t *);
static void smb_query_shortname(smb_node_t *, smb_queryinfo_t *);

int smb_query_passthru;

/*
 * smb_com_trans2_query_file_information
 */
smb_sdrc_t
smb_com_trans2_query_file_information(struct smb_request *sr, struct smb_xa *xa)
{
	uint16_t infolev;

	if (smb_mbc_decodef(&xa->req_param_mb, "ww",
	    &sr->smb_fid, &infolev) != 0)
		return (SDRC_ERROR);

	if (smb_query_by_fid(sr, xa, infolev) != 0)
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}

/*
 * smb_com_trans2_query_path_information
 */
smb_sdrc_t
smb_com_trans2_query_path_information(smb_request_t *sr, smb_xa_t *xa)
{
	uint16_t	infolev;
	smb_fqi_t	*fqi = &sr->arg.dirop.fqi;

	if (STYPE_ISIPC(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_INVALID_DEVICE_REQUEST,
		    ERRDOS, ERROR_INVALID_FUNCTION);
		return (SDRC_ERROR);
	}

	if (smb_mbc_decodef(&xa->req_param_mb, "%w4.u",
	    sr, &infolev, &fqi->fq_path.pn_path) != 0)
		return (SDRC_ERROR);

	if (smb_query_by_path(sr, xa, infolev) != 0)
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}

/*
 * smb_com_query_information (aka getattr)
 */
smb_sdrc_t
smb_pre_query_information(smb_request_t *sr)
{
	int rc;
	smb_fqi_t *fqi = &sr->arg.dirop.fqi;

	rc = smbsr_decode_data(sr, "%S", sr, &fqi->fq_path.pn_path);

	DTRACE_SMB_2(op__QueryInformation__start, smb_request_t *, sr,
	    smb_fqi_t *, fqi);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_query_information(smb_request_t *sr)
{
	DTRACE_SMB_1(op__QueryInformation__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_query_information(smb_request_t *sr)
{
	uint16_t infolev = SMB_QUERY_INFORMATION;

	if (STYPE_ISIPC(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	if (smb_query_by_path(sr, NULL, infolev) != 0)
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}

/*
 * smb_com_query_information2 (aka getattre)
 */
smb_sdrc_t
smb_pre_query_information2(smb_request_t *sr)
{
	int rc;
	rc = smbsr_decode_vwv(sr, "w", &sr->smb_fid);

	DTRACE_SMB_1(op__QueryInformation2__start, smb_request_t *, sr);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_query_information2(smb_request_t *sr)
{
	DTRACE_SMB_1(op__QueryInformation2__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_query_information2(smb_request_t *sr)
{
	uint16_t infolev = SMB_QUERY_INFORMATION2;

	if (smb_query_by_fid(sr, NULL, infolev) != 0)
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}

/*
 * smb_query_by_fid
 *
 * Common code for querying file information by open file (or pipe) id.
 * Use the id to identify the node / pipe object and request the
 * smb_queryinfo_t data for that object.
 */
static int
smb_query_by_fid(smb_request_t *sr, smb_xa_t *xa, uint16_t infolev)
{
	int		rc;
	smb_queryinfo_t	*qinfo;
	smb_node_t	*node;
	smb_opipe_t	*opipe;

	smbsr_lookup_file(sr);

	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (-1);
	}

	if (infolev == SMB_INFO_IS_NAME_VALID) {
		smbsr_error(sr, 0, ERRDOS, ERROR_INVALID_LEVEL);
		smbsr_release_file(sr);
		return (-1);
	}

	if ((sr->fid_ofile->f_ftype == SMB_FTYPE_MESG_PIPE) &&
	    (!smb_query_pipe_valid_infolev(sr, infolev))) {
		smbsr_release_file(sr);
		return (-1);
	}

	sr->user_cr = smb_ofile_getcred(sr->fid_ofile);
	qinfo = kmem_alloc(sizeof (smb_queryinfo_t), KM_SLEEP);

	switch (sr->fid_ofile->f_ftype) {
	case SMB_FTYPE_DISK:
		node = sr->fid_ofile->f_node;
		rc = smb_query_fileinfo(sr, node, infolev, qinfo);
		break;
	case SMB_FTYPE_MESG_PIPE:
		opipe = sr->fid_ofile->f_pipe;
		rc = smb_query_pipeinfo(sr, opipe, infolev, qinfo);
		break;
	default:
		smbsr_error(sr, 0, ERRDOS, ERRbadfile);
		rc = -1;
		break;
	}

	if (rc == 0)
		rc = smb_query_encode_response(sr, xa, infolev, qinfo);

	kmem_free(qinfo, sizeof (smb_queryinfo_t));
	smbsr_release_file(sr);
	return (rc);
}

/*
 * smb_query_by_path
 *
 * Common code for querying file information by file name.
 * Use the file name to identify the node object and request the
 * smb_queryinfo_t data for that node.
 *
 * Path should be set in sr->arg.dirop.fqi.fq_path prior to
 * calling smb_query_by_path.
 *
 * Querying attributes on a named pipe by name is an error and
 * is handled in the calling functions so that they can return
 * the appropriate error status code (which differs by caller).
 */
static int
smb_query_by_path(smb_request_t *sr, smb_xa_t *xa, uint16_t infolev)
{
	smb_queryinfo_t	*qinfo;
	smb_node_t	*node, *dnode;
	smb_pathname_t	*pn;
	int		rc;

	/*
	 * The function smb_query_fileinfo is used here and in
	 * smb_query_by_fid.  That common function needs this
	 * one to call it with a NULL fid_ofile, so check here.
	 * Note: smb_query_by_fid enforces the opposite.
	 *
	 * In theory we could ASSERT this, but whether we have
	 * fid_ofile set here depends on what sequence of SMB
	 * commands the client has sent in this message, so
	 * let's be cautious and handle it as an error.
	 */
	if (sr->fid_ofile != NULL)
		return (-1);


	/* VALID, but not yet supported */
	if (infolev == SMB_FILE_ACCESS_INFORMATION) {
		smbsr_error(sr, 0, ERRDOS, ERROR_INVALID_LEVEL);
		return (-1);
	}

	pn = &sr->arg.dirop.fqi.fq_path;
	smb_pathname_init(sr, pn, pn->pn_path);
	if (!smb_pathname_validate(sr, pn))
		return (-1);

	qinfo = kmem_alloc(sizeof (smb_queryinfo_t), KM_SLEEP);

	rc = smb_pathname_reduce(sr, sr->user_cr, pn->pn_path,
	    sr->tid_tree->t_snode, sr->tid_tree->t_snode, &dnode,
	    qinfo->qi_name);

	if (rc == 0) {
		rc = smb_fsop_lookup_name(sr, sr->user_cr, SMB_FOLLOW_LINKS,
		    sr->tid_tree->t_snode, dnode, qinfo->qi_name, &node);
		smb_node_release(dnode);
	}

	if (rc != 0) {
		if (rc == ENOENT)
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_NOT_FOUND,
			    ERRDOS, ERROR_FILE_NOT_FOUND);
		else
			smbsr_errno(sr, rc);

		kmem_free(qinfo, sizeof (smb_queryinfo_t));
		return (-1);
	}

	if ((sr->smb_flg2 & SMB_FLAGS2_DFS) && smb_node_is_dfslink(node)) {
		smbsr_error(sr, NT_STATUS_PATH_NOT_COVERED, ERRSRV, ERRbadpath);
		kmem_free(qinfo, sizeof (smb_queryinfo_t));
		smb_node_release(node);
		return (-1);
	}

	rc = smb_query_fileinfo(sr, node, infolev, qinfo);
	if (rc != 0) {
		kmem_free(qinfo, sizeof (smb_queryinfo_t));
		smb_node_release(node);
		return (rc);
	}

	/* If delete_on_close - NT_STATUS_DELETE_PENDING */
	if (qinfo->qi_delete_on_close) {
		smbsr_error(sr, NT_STATUS_DELETE_PENDING,
		    ERRDOS, ERROR_ACCESS_DENIED);
		kmem_free(qinfo, sizeof (smb_queryinfo_t));
		smb_node_release(node);
		return (-1);
	}

	rc = smb_query_encode_response(sr, xa, infolev, qinfo);
	kmem_free(qinfo, sizeof (smb_queryinfo_t));
	smb_node_release(node);
	return (rc);
}

/*
 * smb_size32
 * Some responses only support 32 bit file sizes. If the file size
 * exceeds UINT_MAX (32 bit) we return UINT_MAX in the response.
 */
static uint32_t
smb_size32(u_offset_t size)
{
	return ((size > UINT_MAX) ? UINT_MAX : (uint32_t)size);
}

/*
 * smb_query_encode_response
 *
 * Encode the data from smb_queryinfo_t into client response
 */
int
smb_query_encode_response(smb_request_t *sr, smb_xa_t *xa,
    uint16_t infolev, smb_queryinfo_t *qinfo)
{
	uint16_t dattr;
	u_offset_t datasz, allocsz;
	uint32_t isdir;

	dattr = qinfo->qi_attr.sa_dosattr & FILE_ATTRIBUTE_MASK;
	datasz = qinfo->qi_attr.sa_vattr.va_size;
	allocsz = qinfo->qi_attr.sa_allocsz;
	isdir = ((dattr & FILE_ATTRIBUTE_DIRECTORY) != 0);

	switch (infolev) {
	case SMB_QUERY_INFORMATION:
		(void) smbsr_encode_result(sr, 10, 0, "bwll10.w",
		    10,
		    dattr,
		    smb_time_gmt_to_local(sr, qinfo->qi_mtime.tv_sec),
		    smb_size32(datasz),
		    0);
		break;

	case SMB_QUERY_INFORMATION2:
		(void) smbsr_encode_result(sr, 11, 0, "byyyllww",
		    11,
		    smb_time_gmt_to_local(sr, qinfo->qi_crtime.tv_sec),
		    smb_time_gmt_to_local(sr, qinfo->qi_atime.tv_sec),
		    smb_time_gmt_to_local(sr, qinfo->qi_mtime.tv_sec),
		    smb_size32(datasz), smb_size32(allocsz), dattr, 0);
	break;

	case SMB_FILE_ACCESS_INFORMATION:
		ASSERT(sr->fid_ofile);
		(void) smb_mbc_encodef(&xa->rep_data_mb, "l",
		    sr->fid_ofile->f_granted_access);
		break;

	case SMB_INFO_STANDARD:
		(void) smb_mbc_encodef(&xa->rep_param_mb, "w", 0);
		(void) smb_mbc_encodef(&xa->rep_data_mb,
		    ((sr->session->native_os == NATIVE_OS_WIN95) ?
		    "YYYllw" : "yyyllw"),
		    smb_time_gmt_to_local(sr, qinfo->qi_crtime.tv_sec),
		    smb_time_gmt_to_local(sr, qinfo->qi_atime.tv_sec),
		    smb_time_gmt_to_local(sr, qinfo->qi_mtime.tv_sec),
		    smb_size32(datasz), smb_size32(allocsz), dattr);
		break;

	case SMB_INFO_QUERY_EA_SIZE:
		(void) smb_mbc_encodef(&xa->rep_param_mb, "w", 0);
		(void) smb_mbc_encodef(&xa->rep_data_mb,
		    ((sr->session->native_os == NATIVE_OS_WIN95) ?
		    "YYYllwl" : "yyyllwl"),
		    smb_time_gmt_to_local(sr, qinfo->qi_crtime.tv_sec),
		    smb_time_gmt_to_local(sr, qinfo->qi_atime.tv_sec),
		    smb_time_gmt_to_local(sr, qinfo->qi_mtime.tv_sec),
		    smb_size32(datasz), smb_size32(allocsz), dattr, 0);
		break;

	case SMB_INFO_QUERY_ALL_EAS:
	case SMB_INFO_QUERY_EAS_FROM_LIST:
		(void) smb_mbc_encodef(&xa->rep_param_mb, "w", 0);
		(void) smb_mbc_encodef(&xa->rep_data_mb, "l", 0);
		break;

	case SMB_INFO_IS_NAME_VALID:
		break;

	case SMB_QUERY_FILE_BASIC_INFO:
	case SMB_FILE_BASIC_INFORMATION:
		/*
		 * NT includes 6 bytes (spec says 4) at the end of this
		 * response, which are required by NetBench 5.01.
		 */
		(void) smb_mbc_encodef(&xa->rep_param_mb, "w", 0);
		(void) smb_mbc_encodef(&xa->rep_data_mb, "TTTTw6.",
		    &qinfo->qi_crtime,
		    &qinfo->qi_atime,
		    &qinfo->qi_mtime,
		    &qinfo->qi_ctime,
		    dattr);
		break;

	case SMB_QUERY_FILE_STANDARD_INFO:
	case SMB_FILE_STANDARD_INFORMATION:
		/* 2-byte pad at end */
		(void) smb_mbc_encodef(&xa->rep_param_mb, "w", 0);
		(void) smb_mbc_encodef(&xa->rep_data_mb, "qqlbb2.",
		    (uint64_t)allocsz,
		    (uint64_t)datasz,
		    qinfo->qi_attr.sa_vattr.va_nlink,
		    qinfo->qi_delete_on_close,
		    (uint8_t)isdir);
		break;

	case SMB_QUERY_FILE_EA_INFO:
	case SMB_FILE_EA_INFORMATION:
		(void) smb_mbc_encodef(&xa->rep_param_mb, "w", 0);
		(void) smb_mbc_encodef(&xa->rep_data_mb, "l", 0);
		break;

	case SMB_QUERY_FILE_NAME_INFO:
	case SMB_FILE_NAME_INFORMATION:
		(void) smb_mbc_encodef(&xa->rep_param_mb, "w", 0);
		(void) smb_mbc_encodef(&xa->rep_data_mb, "%lu", sr,
		    qinfo->qi_namelen, qinfo->qi_name);
		break;

	case SMB_QUERY_FILE_ALL_INFO:
	case SMB_FILE_ALL_INFORMATION:
		/*
		 * There is a 6-byte pad between Attributes and AllocationSize,
		 * and a 2-byte pad after the Directory field.
		 */
		(void) smb_mbc_encodef(&xa->rep_param_mb, "w", 0);
		(void) smb_mbc_encodef(&xa->rep_data_mb, "TTTTw6.qqlbb2.l",
		    &qinfo->qi_crtime,
		    &qinfo->qi_atime,
		    &qinfo->qi_mtime,
		    &qinfo->qi_ctime,
		    dattr,
		    (uint64_t)allocsz,
		    (uint64_t)datasz,
		    qinfo->qi_attr.sa_vattr.va_nlink,
		    qinfo->qi_delete_on_close,
		    isdir,
		    0);

		(void) smb_mbc_encodef(&xa->rep_data_mb, "%lu",
		    sr, qinfo->qi_namelen, qinfo->qi_name);
		break;

	case SMB_QUERY_FILE_ALT_NAME_INFO:
	case SMB_FILE_ALT_NAME_INFORMATION:
		(void) smb_mbc_encodef(&xa->rep_param_mb, "w", 0);
		(void) smb_mbc_encodef(&xa->rep_data_mb, "%lU", sr,
		    smb_wcequiv_strlen(qinfo->qi_shortname),
		    qinfo->qi_shortname);
		break;

	case SMB_QUERY_FILE_STREAM_INFO:
	case SMB_FILE_STREAM_INFORMATION:
		(void) smb_mbc_encodef(&xa->rep_param_mb, "w", 0);
		smb_encode_stream_info(sr, xa, qinfo);
		break;

	case SMB_QUERY_FILE_COMPRESSION_INFO:
	case SMB_FILE_COMPRESSION_INFORMATION:
		(void) smb_mbc_encodef(&xa->rep_param_mb, "w", 0);
		(void) smb_mbc_encodef(&xa->rep_data_mb, "qwbbb3.",
		    datasz, 0, 0, 0, 0);
		break;

	case SMB_FILE_INTERNAL_INFORMATION:
		(void) smb_mbc_encodef(&xa->rep_param_mb, "w", 0);
		(void) smb_mbc_encodef(&xa->rep_data_mb, "q",
		    qinfo->qi_attr.sa_vattr.va_nodeid);
		break;

	case SMB_FILE_NETWORK_OPEN_INFORMATION:
		(void) smb_mbc_encodef(&xa->rep_param_mb, "w", 0);
		(void) smb_mbc_encodef(&xa->rep_data_mb, "TTTTqql4.",
		    &qinfo->qi_crtime,
		    &qinfo->qi_atime,
		    &qinfo->qi_mtime,
		    &qinfo->qi_ctime,
		    (uint64_t)allocsz,
		    (uint64_t)datasz,
		    (uint32_t)dattr);
		break;

	case SMB_FILE_ATTR_TAG_INFORMATION:
		/*
		 * If dattr includes FILE_ATTRIBUTE_REPARSE_POINT, the
		 * second dword should be the reparse tag.  Otherwise
		 * the tag value should be set to zero.
		 * We don't support reparse points, so we set the tag
		 * to zero.
		 */
		(void) smb_mbc_encodef(&xa->rep_param_mb, "w", 0);
		(void) smb_mbc_encodef(&xa->rep_data_mb, "ll",
		    (uint32_t)dattr, 0);
		break;

	default:
		if ((infolev > 1000) && smb_query_passthru)
			smbsr_error(sr, NT_STATUS_NOT_SUPPORTED,
			    ERRDOS, ERROR_NOT_SUPPORTED);
		else
			smbsr_error(sr, 0, ERRDOS, ERROR_INVALID_LEVEL);
		return (-1);
	}

	return (0);
}

/*
 * smb_encode_stream_info
 *
 * This function encodes the streams information.
 * The following rules about how have been derived from observed NT
 * behaviour.
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
 *
 * If an error is encountered when trying to read the stream entries
 * (smb_odir_read_streaminfo) it is treated as if there are no [more]
 * entries. The entries that have been read so far are returned and
 * no error is reported.
 *
 * If the response buffer is not large enough to return all of the
 * named stream entries, the entries that do fit are returned and
 * a warning code is set (NT_STATUS_BUFFER_OVERFLOW). The next_offset
 * value in the last returned entry must be 0.
 */
static void
smb_encode_stream_info(smb_request_t *sr, smb_xa_t *xa, smb_queryinfo_t *qinfo)
{
	char *stream_name;
	uint32_t next_offset;
	uint32_t stream_nlen;
	uint32_t pad;
	u_offset_t datasz, allocsz;
	boolean_t is_dir;
	smb_streaminfo_t *sinfo, *sinfo_next;
	int rc = 0;
	boolean_t done = B_FALSE;
	boolean_t eos = B_FALSE;
	uint16_t odid;
	smb_odir_t *od = NULL;

	smb_node_t *fnode = qinfo->qi_node;
	smb_attr_t *attr = &qinfo->qi_attr;

	ASSERT(fnode);
	if (SMB_IS_STREAM(fnode)) {
		fnode = fnode->n_unode;
		ASSERT(fnode);
	}
	ASSERT(fnode->n_magic == SMB_NODE_MAGIC);
	ASSERT(fnode->n_state != SMB_NODE_STATE_DESTROYING);

	sinfo = kmem_alloc(sizeof (smb_streaminfo_t), KM_SLEEP);
	sinfo_next = kmem_alloc(sizeof (smb_streaminfo_t), KM_SLEEP);
	is_dir = ((attr->sa_dosattr & FILE_ATTRIBUTE_DIRECTORY) != 0);
	datasz = attr->sa_vattr.va_size;
	allocsz = attr->sa_allocsz;

	odid = smb_odir_openat(sr, fnode);
	if (odid != 0)
		od = smb_tree_lookup_odir(sr->tid_tree, odid);
	if (od != NULL)
		rc = smb_odir_read_streaminfo(sr, od, sinfo, &eos);

	if ((od == NULL) || (rc != 0) || (eos))
		done = B_TRUE;

	/* If not a directory, encode an entry for the unnamed stream. */
	if (!is_dir) {
		stream_name = "::$DATA";
		stream_nlen = smb_ascii_or_unicode_strlen(sr, stream_name);
		next_offset = SMB_STREAM_ENCODE_FIXED_SZ + stream_nlen +
		    smb_ascii_or_unicode_null_len(sr);

		/* Can unnamed stream fit in response buffer? */
		if (MBC_ROOM_FOR(&xa->rep_data_mb, next_offset) == 0) {
			done = B_TRUE;
			smbsr_warn(sr, NT_STATUS_BUFFER_OVERFLOW,
			    ERRDOS, ERROR_MORE_DATA);
		} else {
			/* Can first named stream fit in rsp buffer? */
			if (!done && !smb_stream_fits(sr, xa, sinfo->si_name,
			    next_offset)) {
				done = B_TRUE;
				smbsr_warn(sr, NT_STATUS_BUFFER_OVERFLOW,
				    ERRDOS, ERROR_MORE_DATA);
			}

			if (done)
				next_offset = 0;

			(void) smb_mbc_encodef(&xa->rep_data_mb, "%llqqu", sr,
			    next_offset, stream_nlen, datasz, allocsz,
			    stream_name);
		}
	}

	/*
	 * If there is no next entry, or there is not enough space in
	 * the response buffer for the next entry, the next_offset and
	 * padding are 0.
	 */
	while (!done) {
		stream_nlen = smb_ascii_or_unicode_strlen(sr, sinfo->si_name);
		sinfo_next->si_name[0] = 0;

		rc = smb_odir_read_streaminfo(sr, od, sinfo_next, &eos);
		if ((rc != 0) || (eos)) {
			done = B_TRUE;
		} else {
			next_offset = SMB_STREAM_ENCODE_FIXED_SZ +
			    stream_nlen +
			    smb_ascii_or_unicode_null_len(sr);
			pad = smb_pad_align(next_offset, 8);
			next_offset += pad;

			/* Can next named stream fit in response buffer? */
			if (!smb_stream_fits(sr, xa, sinfo_next->si_name,
			    next_offset)) {
				done = B_TRUE;
				smbsr_warn(sr, NT_STATUS_BUFFER_OVERFLOW,
				    ERRDOS, ERROR_MORE_DATA);
			}
		}

		if (done) {
			next_offset = 0;
			pad = 0;
		}

		rc = smb_mbc_encodef(&xa->rep_data_mb, "%llqqu#.",
		    sr, next_offset, stream_nlen,
		    sinfo->si_size, sinfo->si_alloc_size,
		    sinfo->si_name, pad);

		(void) memcpy(sinfo, sinfo_next, sizeof (smb_streaminfo_t));
	}

	kmem_free(sinfo, sizeof (smb_streaminfo_t));
	kmem_free(sinfo_next, sizeof (smb_streaminfo_t));
	if (od) {
		smb_odir_close(od);
		smb_odir_release(od);
	}
}

/*
 * smb_stream_fits
 *
 * Check if the named stream entry can fit in the response buffer.
 *
 * Required space =
 *	offset (size of current entry)
 *	+ SMB_STREAM_ENCODE_FIXED_SIZE
 *      + length of encoded stream name
 *	+ length of null terminator
 *	+ alignment padding
 */
static boolean_t
smb_stream_fits(smb_request_t *sr, smb_xa_t *xa, char *name, uint32_t offset)
{
	uint32_t len, pad;

	len = SMB_STREAM_ENCODE_FIXED_SZ +
	    smb_ascii_or_unicode_strlen(sr, name) +
	    smb_ascii_or_unicode_null_len(sr);
	pad = smb_pad_align(len, 8);
	len += pad;

	return (MBC_ROOM_FOR(&xa->rep_data_mb, offset + len) != 0);
}

/*
 * smb_query_fileinfo
 *
 * Populate smb_queryinfo_t structure for SMB_FTYPE_DISK
 * (This should become an smb_ofile / smb_node function.)
 */
int
smb_query_fileinfo(smb_request_t *sr, smb_node_t *node, uint16_t infolev,
    smb_queryinfo_t *qinfo)
{
	int rc = 0;

	/* If shortname required but not supported -> OBJECT_NAME_NOT_FOUND */
	if ((infolev == SMB_QUERY_FILE_ALT_NAME_INFO) ||
	    (infolev == SMB_FILE_ALT_NAME_INFORMATION)) {
		if (!smb_tree_has_feature(sr->tid_tree, SMB_TREE_SHORTNAMES)) {
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_NOT_FOUND,
			    ERRDOS, ERROR_FILE_NOT_FOUND);
			return (-1);
		}
	}

	(void) bzero(qinfo, sizeof (smb_queryinfo_t));

	/* See: smb_query_encode_response */
	qinfo->qi_attr.sa_mask = SMB_AT_ALL;
	rc = smb_node_getattr(sr, node, sr->user_cr, sr->fid_ofile,
	    &qinfo->qi_attr);
	if (rc != 0) {
		smbsr_error(sr, NT_STATUS_INTERNAL_ERROR,
		    ERRDOS, ERROR_INTERNAL_ERROR);
		return (-1);
	}

	qinfo->qi_node = node;
	qinfo->qi_delete_on_close =
	    (node->flags & NODE_FLAGS_DELETE_ON_CLOSE) != 0;

	/*
	 * The number of links reported should be the number of
	 * non-deleted links. Thus if delete_on_close is set,
	 * decrement the link count.
	 */
	if (qinfo->qi_delete_on_close &&
	    qinfo->qi_attr.sa_vattr.va_nlink > 0) {
		--(qinfo->qi_attr.sa_vattr.va_nlink);
	}

	/*
	 * populate name, namelen and shortname ONLY for the information
	 * levels that require these fields
	 */
	switch (infolev) {
	case SMB_QUERY_FILE_ALL_INFO:
	case SMB_FILE_ALL_INFORMATION:
		rc = smb_query_pathname(sr, node, B_TRUE, qinfo);
		break;
	case SMB_QUERY_FILE_NAME_INFO:
	case SMB_FILE_NAME_INFORMATION:
		rc = smb_query_pathname(sr, node, B_FALSE, qinfo);
		break;
	case SMB_QUERY_FILE_ALT_NAME_INFO:
	case SMB_FILE_ALT_NAME_INFORMATION:
		smb_query_shortname(node, qinfo);
		break;
	default:
		break;
	}

	if (rc != 0) {
		smbsr_errno(sr, rc);
		return (-1);
	}
	return (0);
}

/*
 * smb_query_pathname
 *
 * Determine the absolute pathname of 'node' within the share.
 * For some levels (e.g. ALL_INFO) the pathname should include the
 * sharename for others (e.g. NAME_INFO) the pathname should be
 * relative to the share.
 * For example if the node represents file "test1.txt" in directory
 * "dir1" on share "share1"
 * - if include_share is TRUE the pathname would be: \share1\dir1\test1.txt
 * - if include_share is FALSE the pathname would be: \dir1\test1.txt
 *
 * For some reason NT will not show the security tab in the root
 * directory of a mapped drive unless the filename length is greater
 * than one. So if the length is 1 we set it to 2 to persuade NT to
 * show the tab. It should be safe because of the null terminator.
 */
static int
smb_query_pathname(smb_request_t *sr, smb_node_t *node, boolean_t include_share,
    smb_queryinfo_t *qinfo)
{
	smb_tree_t *tree = sr->tid_tree;
	char *buf = qinfo->qi_name;
	size_t buflen = MAXPATHLEN;
	size_t len;
	int rc;

	if (include_share) {
		len = snprintf(buf, buflen, "\\%s", tree->t_sharename);
		if (len == (buflen - 1))
			return (ENAMETOOLONG);

		buf += len;
		buflen -= len;
	}

	if (node == tree->t_snode) {
		if (!include_share)
			(void) strlcpy(buf, "\\", buflen);
		return (0);
	}

	rc =  smb_node_getshrpath(node, tree, buf, buflen);
	if (rc == 0) {
		qinfo->qi_namelen =
		    smb_ascii_or_unicode_strlen(sr, qinfo->qi_name);
		if (qinfo->qi_namelen == 1)
			qinfo->qi_namelen = 2;
	}
	return (rc);
}

/*
 * smb_query_shortname
 *
 * If the node is a named stream, use its associated
 * unnamed stream name to determine the shortname.
 * If a shortname is required (smb_needs_mangle()), generate it
 * using smb_mangle(), otherwise, convert the original name to
 * upper-case and return it as the alternative name.
 */
static void
smb_query_shortname(smb_node_t *node, smb_queryinfo_t *qinfo)
{
	char *namep;

	if (SMB_IS_STREAM(node))
		namep = node->n_unode->od_name;
	else
		namep = node->od_name;

	if (smb_needs_mangled(namep)) {
		smb_mangle(namep, qinfo->qi_attr.sa_vattr.va_nodeid,
		    qinfo->qi_shortname, SMB_SHORTNAMELEN);
	} else {
		(void) strlcpy(qinfo->qi_shortname, namep, SMB_SHORTNAMELEN);
		(void) smb_strupr(qinfo->qi_shortname);
	}
}

/*
 * smb_query_pipeinfo
 *
 * Populate smb_queryinfo_t structure for SMB_FTYPE_MESG_PIPE
 * (This should become an smb_opipe function.)
 */
static int
smb_query_pipeinfo(smb_request_t *sr, smb_opipe_t *opipe, uint16_t infolev,
    smb_queryinfo_t *qinfo)
{
	char *namep = opipe->p_name;

	(void) bzero(qinfo, sizeof (smb_queryinfo_t));
	qinfo->qi_node = NULL;
	qinfo->qi_attr.sa_vattr.va_nlink = 1;
	qinfo->qi_delete_on_close = 1;

	if ((infolev == SMB_INFO_STANDARD) ||
	    (infolev == SMB_INFO_QUERY_EA_SIZE) ||
	    (infolev == SMB_QUERY_INFORMATION2)) {
		qinfo->qi_attr.sa_dosattr = 0;
	} else {
		qinfo->qi_attr.sa_dosattr = FILE_ATTRIBUTE_NORMAL;
	}

	/* If the leading \ is missing from the pipe name, add it. */
	if (*namep != '\\')
		(void) snprintf(qinfo->qi_name, MAXNAMELEN, "\\%s", namep);
	else
		(void) strlcpy(qinfo->qi_name, namep, MAXNAMELEN);

	qinfo->qi_namelen=
	    smb_ascii_or_unicode_strlen(sr, qinfo->qi_name);

	return (0);
}

/*
 * smb_query_pipe_valid_infolev
 *
 * If the infolev is not valid for a message pipe, the error
 * information is set in sr and B_FALSE is returned.
 * Otherwise, returns B_TRUE.
 */
static boolean_t
smb_query_pipe_valid_infolev(smb_request_t *sr, uint16_t infolev)
{
	switch (infolev) {
	case SMB_INFO_QUERY_ALL_EAS:
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (B_FALSE);

	case SMB_QUERY_FILE_ALT_NAME_INFO:
	case SMB_FILE_ALT_NAME_INFORMATION:
	case SMB_QUERY_FILE_STREAM_INFO:
	case SMB_FILE_STREAM_INFORMATION:
	case SMB_QUERY_FILE_COMPRESSION_INFO:
	case SMB_FILE_COMPRESSION_INFORMATION:
	case SMB_FILE_NETWORK_OPEN_INFORMATION:
	case SMB_FILE_ATTR_TAG_INFORMATION:
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERROR_INVALID_PARAMETER);
		return (B_FALSE);
	}

	return (B_TRUE);
}
