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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <smbsrv/nterror.h>
#include <sys/synch.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>
#include <sys/nbmlock.h>

/*
 * NT_RENAME InformationLevels:
 *
 * SMB_NT_RENAME_MOVE_CLUSTER_INFO	Server returns invalid parameter.
 * SMB_NT_RENAME_SET_LINK_INFO		Create a hard link to a file.
 * SMB_NT_RENAME_RENAME_FILE		In-place rename of a file.
 * SMB_NT_RENAME_MOVE_FILE		Move (rename) a file.
 */
#define	SMB_NT_RENAME_MOVE_CLUSTER_INFO	0x0102
#define	SMB_NT_RENAME_SET_LINK_INFO	0x0103
#define	SMB_NT_RENAME_RENAME_FILE	0x0104
#define	SMB_NT_RENAME_MOVE_FILE		0x0105

static int smb_do_rename(smb_request_t *, smb_fqi_t *, smb_fqi_t *);
static int smb_make_link(smb_request_t *, smb_fqi_t *, smb_fqi_t *);
static int smb_rename_check_attr(smb_request_t *, smb_node_t *, uint16_t);
static void smb_rename_set_error(smb_request_t *, int);

/*
 * smb_com_rename
 *
 * Rename a file. Files OldFileName must exist and NewFileName must not.
 * Both pathnames must be relative to the Tid specified in the request.
 * Open files may be renamed.
 *
 * Multiple files may be renamed in response to a single request as Rename
 * File supports wildcards in the file name (last component of the path).
 * NOTE: we don't support rename with wildcards.
 *
 * SearchAttributes indicates the attributes that the target file(s) must
 * have. If SearchAttributes is zero then only normal files are renamed.
 * If the system file or hidden attributes are specified then the rename
 * is inclusive - both the specified type(s) of files and normal files are
 * renamed. The encoding of SearchAttributes is described in section 3.10
 * - File Attribute Encoding.
 */
smb_sdrc_t
smb_pre_rename(smb_request_t *sr)
{
	smb_fqi_t *src_fqi = &sr->arg.dirop.fqi;
	smb_fqi_t *dst_fqi = &sr->arg.dirop.dst_fqi;
	int rc;

	if ((rc = smbsr_decode_vwv(sr, "w", &src_fqi->fq_sattr)) == 0) {
		rc = smbsr_decode_data(sr, "%SS", sr, &src_fqi->fq_path.pn_path,
		    &dst_fqi->fq_path.pn_path);

		dst_fqi->fq_sattr = 0;
	}

	DTRACE_SMB_2(op__Rename__start, smb_request_t *, sr,
	    struct dirop *, &sr->arg.dirop);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_rename(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Rename__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_rename(smb_request_t *sr)
{
	smb_fqi_t *src_fqi = &sr->arg.dirop.fqi;
	smb_fqi_t *dst_fqi = &sr->arg.dirop.dst_fqi;
	int rc;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	rc = smb_do_rename(sr, src_fqi, dst_fqi);

	if (rc != 0) {
		smb_rename_set_error(sr, rc);
		return (SDRC_ERROR);
	}

	rc = smbsr_encode_empty_result(sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * smb_do_rename
 *
 * Common code for renaming a file.
 *
 * If the source and destination are identical, we go through all
 * the checks but we don't actually do the rename.  If the source
 * and destination files differ only in case, we do a case-sensitive
 * rename.  Otherwise, we do a full case-insensitive rename.
 *
 * Returns errno values.
 */
static int
smb_do_rename(smb_request_t *sr, smb_fqi_t *src_fqi, smb_fqi_t *dst_fqi)
{
	smb_node_t *src_node, *tnode;
	char *dstname;
	DWORD status;
	int rc;
	int count;
	char *path;

	tnode = sr->tid_tree->t_snode;

	/* Lookup the source node. It MUST exist. */
	path = src_fqi->fq_path.pn_path;
	rc = smb_pathname_reduce(sr, sr->user_cr, path, tnode, tnode,
	    &src_fqi->fq_dnode, src_fqi->fq_last_comp);
	if (rc != 0)
		return (rc);

	rc = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS, tnode,
	    src_fqi->fq_dnode, src_fqi->fq_last_comp, &src_fqi->fq_fnode);
	if (rc != 0) {
		smb_node_release(src_fqi->fq_dnode);
		return (rc);
	}

	src_node = src_fqi->fq_fnode;
	rc = smb_rename_check_attr(sr, src_node, src_fqi->fq_sattr);
	if (rc != 0) {
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		return (rc);
	}

	/*
	 * Break the oplock before access checks. If a client
	 * has a file open, this will force a flush or close,
	 * which may affect the outcome of any share checking.
	 */
	(void) smb_oplock_break(src_node, sr->session, B_FALSE);

	for (count = 0; count <= 3; count++) {
		if (count) {
			smb_node_end_crit(src_node);
			delay(MSEC_TO_TICK(400));
		}

		smb_node_start_crit(src_node, RW_READER);

		status = smb_node_rename_check(src_node);

		if (status != NT_STATUS_SHARING_VIOLATION)
			break;
	}

	if (status == NT_STATUS_SHARING_VIOLATION) {
		smb_node_end_crit(src_node);
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		return (EPIPE); /* = ERRbadshare */
	}

	status = smb_range_check(sr, src_node, 0, UINT64_MAX, B_TRUE);

	if (status != NT_STATUS_SUCCESS) {
		smb_node_end_crit(src_node);
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		return (EACCES);
	}

	/* Lookup destination node. */
	path = dst_fqi->fq_path.pn_path;
	rc = smb_pathname_reduce(sr, sr->user_cr, path, tnode, tnode,
	    &dst_fqi->fq_dnode, dst_fqi->fq_last_comp);
	if (rc != 0) {
		smb_node_end_crit(src_node);
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		return (rc);
	}

	rc = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS, tnode,
	    dst_fqi->fq_dnode, dst_fqi->fq_last_comp, &dst_fqi->fq_fnode);
	if ((rc != 0) && (rc != ENOENT)) {
		smb_node_end_crit(src_node);
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		smb_node_release(dst_fqi->fq_dnode);
		return (rc);
	}

	if (utf8_strcasecmp(src_fqi->fq_path.pn_path,
	    dst_fqi->fq_path.pn_path) == 0) {

		if (dst_fqi->fq_fnode)
			smb_node_release(dst_fqi->fq_fnode);

		rc = strcmp(src_fqi->fq_fnode->od_name, dst_fqi->fq_last_comp);
		if (rc == 0) {
			smb_node_end_crit(src_node);
			smb_node_release(src_fqi->fq_fnode);
			smb_node_release(src_fqi->fq_dnode);
			smb_node_release(dst_fqi->fq_dnode);
			return (0);
		}

		rc = smb_fsop_rename(sr, sr->user_cr,
		    src_fqi->fq_dnode, src_fqi->fq_fnode->od_name,
		    dst_fqi->fq_dnode, dst_fqi->fq_last_comp);

		smb_node_end_crit(src_node);
		if (rc == 0)
			smb_node_notify_change(dst_fqi->fq_dnode);
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		smb_node_release(dst_fqi->fq_dnode);
		return (rc);
	}

	/* dst node must not exist */
	if (dst_fqi->fq_fnode) {
		smb_node_end_crit(src_node);
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		smb_node_release(dst_fqi->fq_fnode);
		smb_node_release(dst_fqi->fq_dnode);
		return (EEXIST);
	}

	/*
	 * If the source name is mangled but the source and destination
	 * on-disk names are identical, we'll use the on-disk name.
	 */
	if ((smb_maybe_mangled_name(src_fqi->fq_last_comp)) &&
	    (strcmp(src_fqi->fq_last_comp, dst_fqi->fq_last_comp) == 0)) {
		dstname = src_fqi->fq_fnode->od_name;
	} else {
		dstname = dst_fqi->fq_last_comp;
	}

	rc = smb_fsop_rename(sr, sr->user_cr,
	    src_fqi->fq_dnode, src_fqi->fq_fnode->od_name,
	    dst_fqi->fq_dnode, dstname);

	smb_node_end_crit(src_node);
	if (rc == 0)
		smb_node_notify_change(dst_fqi->fq_dnode);
	smb_node_release(src_fqi->fq_fnode);
	smb_node_release(src_fqi->fq_dnode);
	smb_node_release(dst_fqi->fq_dnode);
	return (rc);
}

/*
 * smb_com_nt_rename
 *
 * Rename a file. Files OldFileName must exist and NewFileName must not.
 * Both pathnames must be relative to the Tid specified in the request.
 * Open files may be renamed.
 *
 * Multiple files may be renamed in response to a single request as Rename
 * File supports wildcards in the file name (last component of the path).
 * NOTE: we don't support rename with wildcards.
 *
 * SearchAttributes indicates the attributes that the target file(s) must
 * have. If SearchAttributes is zero then only normal files are renamed.
 * If the system file or hidden attributes are specified then the rename
 * is inclusive - both the specified type(s) of files and normal files are
 * renamed. The encoding of SearchAttributes is described in section 3.10
 * - File Attribute Encoding.
 *
 *  Client Request                     Description
 *  =================================  ==================================
 *  UCHAR WordCount;                   Count of parameter words = 4
 *  USHORT SearchAttributes;
 *  USHORT InformationLevel;           0x0103 Create a hard link
 *                                     0x0104 In-place rename
 *                                     0x0105 Move (rename) a file
 *  ULONG ClusterCount                 Servers should ignore this value
 *  USHORT ByteCount;                  Count of data bytes; min = 4
 *  UCHAR Buffer[];                    Buffer containing:
 *                                     UCHAR BufferFormat1 0x04
 *                                     UCHAR OldFileName[] OldFileName
 *                                     UCHAR BufferFormat1 0x04
 *                                     UCHAR OldFileName[] NewFileName
 *
 *  Server Response                    Description
 *  =================================  ==================================
 *  UCHAR WordCount;                   Count of parameter words = 0
 *  UCHAR ByteCount;                   Count of data bytes = 0
 */
smb_sdrc_t
smb_pre_nt_rename(smb_request_t *sr)
{
	smb_fqi_t *src_fqi = &sr->arg.dirop.fqi;
	smb_fqi_t *dst_fqi = &sr->arg.dirop.dst_fqi;
	uint32_t clusters;
	int rc;

	rc = smbsr_decode_vwv(sr, "wwl", &src_fqi->fq_sattr,
	    &sr->arg.dirop.info_level, &clusters);
	if (rc == 0) {
		rc = smbsr_decode_data(sr, "%SS", sr,
		    &src_fqi->fq_path.pn_path, &dst_fqi->fq_path.pn_path);

		dst_fqi->fq_sattr = 0;
	}

	DTRACE_SMB_2(op__NtRename__start, smb_request_t *, sr,
	    struct dirop *, &sr->arg.dirop);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_nt_rename(smb_request_t *sr)
{
	DTRACE_SMB_1(op__NtRename__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_nt_rename(smb_request_t *sr)
{
	smb_fqi_t *src_fqi = &sr->arg.dirop.fqi;
	smb_fqi_t *dst_fqi = &sr->arg.dirop.dst_fqi;
	int rc;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	if (smb_convert_wildcards(src_fqi->fq_path.pn_path) != 0) {
		smbsr_error(sr, NT_STATUS_OBJECT_PATH_SYNTAX_BAD,
		    ERRDOS, ERROR_BAD_PATHNAME);
		return (SDRC_ERROR);
	}

	switch (sr->arg.dirop.info_level) {
	case SMB_NT_RENAME_SET_LINK_INFO:
		rc = smb_make_link(sr, src_fqi, dst_fqi);
		break;
	case SMB_NT_RENAME_RENAME_FILE:
	case SMB_NT_RENAME_MOVE_FILE:
		rc = smb_do_rename(sr, src_fqi, dst_fqi);
		break;
	case SMB_NT_RENAME_MOVE_CLUSTER_INFO:
		rc = EINVAL;
		break;
	default:
		rc = EACCES;
		break;
	}

	if (rc != 0) {
		smb_rename_set_error(sr, rc);
		return (SDRC_ERROR);
	}

	rc = smbsr_encode_empty_result(sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * smb_make_link
 *
 * Common code for creating a hard link (adding an additional name
 * for a file.
 *
 * If the source and destination are identical, we go through all
 * the checks but we don't create a link.
 *
 * Returns errno values.
 */
static int
smb_make_link(smb_request_t *sr, smb_fqi_t *src_fqi, smb_fqi_t *dst_fqi)
{
	smb_node_t *src_fnode, *tnode;
	DWORD status;
	int rc;
	int count;
	char *path;

	tnode = sr->tid_tree->t_snode;

	/* Lookup the source node. It MUST exist. */
	path = src_fqi->fq_path.pn_path;
	rc = smb_pathname_reduce(sr, sr->user_cr, path, tnode, tnode,
	    &src_fqi->fq_dnode, src_fqi->fq_last_comp);
	if (rc != 0)
		return (rc);

	rc = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS, tnode,
	    src_fqi->fq_dnode, src_fqi->fq_last_comp, &src_fqi->fq_fnode);
	if (rc != 0) {
		smb_node_release(src_fqi->fq_dnode);
		return (rc);
	}

	src_fnode = src_fqi->fq_fnode;
	rc = smb_rename_check_attr(sr, src_fnode, src_fqi->fq_sattr);
	if (rc != 0) {
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		return (rc);
	}

	/*
	 * Break the oplock before access checks. If a client
	 * has a file open, this will force a flush or close,
	 * which may affect the outcome of any share checking.
	 */
	(void) smb_oplock_break(src_fnode, sr->session, B_FALSE);

	for (count = 0; count <= 3; count++) {
		if (count) {
			smb_node_end_crit(src_fnode);
			delay(MSEC_TO_TICK(400));
		}

		smb_node_start_crit(src_fnode, RW_READER);
		status = smb_node_rename_check(src_fnode);

		if (status != NT_STATUS_SHARING_VIOLATION)
			break;
	}

	if (status == NT_STATUS_SHARING_VIOLATION) {
		smb_node_end_crit(src_fnode);
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		return (EPIPE); /* = ERRbadshare */
	}

	status = smb_range_check(sr, src_fnode, 0, UINT64_MAX, B_TRUE);
	if (status != NT_STATUS_SUCCESS) {
		smb_node_end_crit(src_fnode);
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		return (EACCES);
	}

	if (utf8_strcasecmp(src_fqi->fq_path.pn_path,
	    dst_fqi->fq_path.pn_path) == 0) {
		smb_node_end_crit(src_fnode);
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		return (0);
	}

	/* Lookup the destination node. It MUST NOT exist. */
	path = dst_fqi->fq_path.pn_path;
	rc = smb_pathname_reduce(sr, sr->user_cr, path, tnode, tnode,
	    &dst_fqi->fq_dnode, dst_fqi->fq_last_comp);
	if (rc != 0) {
		smb_node_end_crit(src_fnode);
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		return (rc);
	}

	rc = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS, tnode,
	    dst_fqi->fq_dnode, dst_fqi->fq_last_comp, &dst_fqi->fq_fnode);
	if (rc == 0) {
		smb_node_release(dst_fqi->fq_fnode);
		rc = EEXIST;
	}
	if (rc != ENOENT) {
		smb_node_end_crit(src_fnode);
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		smb_node_release(dst_fqi->fq_dnode);
		return (rc);
	}

	rc = smb_fsop_link(sr, sr->user_cr, dst_fqi->fq_dnode, src_fnode,
	    dst_fqi->fq_last_comp);

	smb_node_end_crit(src_fnode);
	if (rc == 0)
		smb_node_notify_change(dst_fqi->fq_dnode);
	smb_node_release(src_fqi->fq_fnode);
	smb_node_release(src_fqi->fq_dnode);
	smb_node_release(dst_fqi->fq_dnode);
	return (rc);
}

static int
smb_rename_check_attr(smb_request_t *sr, smb_node_t *node, uint16_t sattr)
{
	smb_attr_t attr;

	if (smb_node_getattr(sr, node, &attr) != 0)
		return (EIO);

	if ((attr.sa_dosattr & FILE_ATTRIBUTE_HIDDEN) &&
	    !(SMB_SEARCH_HIDDEN(sattr)))
		return (ESRCH);

	if ((attr.sa_dosattr & FILE_ATTRIBUTE_SYSTEM) &&
	    !(SMB_SEARCH_SYSTEM(sattr)))
		return (ESRCH);

	return (0);
}

/*
 * The following values are based on observed WFWG, Windows 9x, Windows NT
 * and Windows 2000 behaviour.
 *
 * ERROR_FILE_EXISTS doesn't work for Windows 98 clients.
 *
 * Windows 95 clients don't see the problem because the target is deleted
 * before the rename request.
 */
static void
smb_rename_set_error(smb_request_t *sr, int errnum)
{
	static struct {
		int errnum;
		uint16_t errcode;
		uint32_t status32;
	} rc_map[] = {
	{ EEXIST, ERROR_ALREADY_EXISTS,	NT_STATUS_OBJECT_NAME_COLLISION },
	{ EPIPE,  ERROR_SHARING_VIOLATION, NT_STATUS_SHARING_VIOLATION },
	{ ENOENT, ERROR_FILE_NOT_FOUND,	NT_STATUS_OBJECT_NAME_NOT_FOUND },
	{ ESRCH,  ERROR_FILE_NOT_FOUND,	NT_STATUS_NO_SUCH_FILE },
	{ EINVAL, ERROR_INVALID_PARAMETER, NT_STATUS_INVALID_PARAMETER },
	{ EACCES, ERROR_ACCESS_DENIED,	NT_STATUS_ACCESS_DENIED },
	{ EIO,    ERROR_INTERNAL_ERROR,	NT_STATUS_INTERNAL_ERROR }
	};

	int i;

	if (errnum == 0)
		return;

	for (i = 0; i < sizeof (rc_map)/sizeof (rc_map[0]); ++i) {
		if (rc_map[i].errnum == errnum) {
			smbsr_error(sr, rc_map[i].status32,
			    ERRDOS, rc_map[i].errcode);
			return;
		}
	}

	smbsr_errno(sr, errnum);
}
