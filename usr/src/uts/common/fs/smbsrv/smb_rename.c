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

#include <sys/synch.h>
#include <smbsrv/smb_kproto.h>
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

/*
 * SMB_TRANS2_SET_FILE/PATH_INFO (RENAME_INFORMATION level) flag
 */
#define	SMB_RENAME_FLAG_OVERWRITE	0x001

static int smb_common_rename(smb_request_t *, smb_fqi_t *, smb_fqi_t *);
static int smb_make_link(smb_request_t *, smb_fqi_t *, smb_fqi_t *);
static int smb_rename_check_stream(smb_fqi_t *, smb_fqi_t *);
static int smb_rename_check_attr(smb_request_t *, smb_node_t *, uint16_t);
static void smb_rename_set_error(smb_request_t *, int);

static int smb_rename_lookup_src(smb_request_t *);
static void smb_rename_release_src(smb_request_t *);

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
 * renamed.
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
	int		rc;
	smb_fqi_t	*src_fqi = &sr->arg.dirop.fqi;
	smb_fqi_t	*dst_fqi = &sr->arg.dirop.dst_fqi;
	smb_pathname_t	*src_pn = &src_fqi->fq_path;
	smb_pathname_t	*dst_pn = &dst_fqi->fq_path;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	smb_pathname_init(sr, src_pn, src_pn->pn_path);
	smb_pathname_init(sr, dst_pn, dst_pn->pn_path);
	if (!smb_pathname_validate(sr, src_pn) ||
	    !smb_pathname_validate(sr, dst_pn)) {
		return (SDRC_ERROR);
	}

	rc = smb_common_rename(sr, src_fqi, dst_fqi);

	if (rc != 0) {
		smb_rename_set_error(sr, rc);
		return (SDRC_ERROR);
	}

	rc = smbsr_encode_empty_result(sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * smb_com_nt_rename
 *
 * Rename a file. Files OldFileName must exist and NewFileName must not.
 * Both pathnames must be relative to the Tid specified in the request.
 * Open files may be renamed.
 *
 * SearchAttributes indicates the attributes that the target file(s) must
 * have. If SearchAttributes is zero then only normal files are renamed.
 * If the system file or hidden attributes are specified then the rename
 * is inclusive - both the specified type(s) of files and normal files are
 * renamed.
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
	int		rc;
	smb_fqi_t	*src_fqi = &sr->arg.dirop.fqi;
	smb_fqi_t	*dst_fqi = &sr->arg.dirop.dst_fqi;
	smb_pathname_t	*src_pn = &src_fqi->fq_path;
	smb_pathname_t	*dst_pn = &dst_fqi->fq_path;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	smb_pathname_init(sr, src_pn, src_pn->pn_path);
	smb_pathname_init(sr, dst_pn, dst_pn->pn_path);
	if (!smb_pathname_validate(sr, src_pn) ||
	    !smb_pathname_validate(sr, dst_pn)) {
		return (SDRC_ERROR);
	}

	if (smb_contains_wildcards(src_pn->pn_path)) {
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
		rc = smb_common_rename(sr, src_fqi, dst_fqi);
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
 * smb_nt_transact_rename
 *
 * Windows servers return SUCCESS without renaming file.
 * The only check required is to check that the handle (fid) is valid.
 */
smb_sdrc_t
smb_nt_transact_rename(smb_request_t *sr, smb_xa_t *xa)
{
	if (smb_mbc_decodef(&xa->req_param_mb, "w", &sr->smb_fid) != 0)
		return (SDRC_ERROR);

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}
	smbsr_release_file(sr);

	return (SDRC_SUCCESS);
}

/*
 * smb_trans2_rename
 *
 * Implements SMB_FILE_RENAME_INFORMATION level of Trans2_Set_FileInfo
 * and Trans2_Set_PathInfo.
 * If the new filename (dst_fqi) already exists it may be overwritten
 * if flags == 1.
 */
int
smb_trans2_rename(smb_request_t *sr, smb_node_t *node, char *fname, int flags)
{
	int		rc = 0;
	smb_fqi_t	*src_fqi = &sr->arg.dirop.fqi;
	smb_fqi_t	*dst_fqi = &sr->arg.dirop.dst_fqi;
	smb_pathname_t	*dst_pn = &dst_fqi->fq_path;
	char		*path;
	int		len;

	sr->arg.dirop.flags = flags ? SMB_RENAME_FLAG_OVERWRITE : 0;
	sr->arg.dirop.info_level = SMB_NT_RENAME_RENAME_FILE;

	src_fqi->fq_sattr = SMB_SEARCH_ATTRIBUTES;
	src_fqi->fq_fnode = node;
	src_fqi->fq_dnode = node->n_dnode;

	/* costruct and validate the dst pathname */
	path = smb_srm_zalloc(sr, MAXPATHLEN);
	if (src_fqi->fq_path.pn_pname) {
		(void) snprintf(path, MAXPATHLEN, "%s\\%s",
		    src_fqi->fq_path.pn_pname, fname);
	} else {
		rc = smb_node_getshrpath(node->n_dnode, sr->tid_tree,
		    path, MAXPATHLEN);
		if (rc != 0) {
			smb_rename_set_error(sr, rc);
			return (-1);
		}
		len = strlen(path);
		(void) snprintf(path + len, MAXPATHLEN - len, "\\%s", fname);
	}

	smb_pathname_init(sr, dst_pn, path);
	if (!smb_pathname_validate(sr, dst_pn))
		return (-1);

	dst_fqi->fq_dnode = node->n_dnode;
	(void) strlcpy(dst_fqi->fq_last_comp, dst_pn->pn_fname, MAXNAMELEN);

	rc = smb_common_rename(sr, src_fqi, dst_fqi);
	if (rc != 0) {
		smb_rename_set_error(sr, rc);
		return (-1);
	}

	return (0);
}

/*
 * smb_common_rename
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
smb_common_rename(smb_request_t *sr, smb_fqi_t *src_fqi, smb_fqi_t *dst_fqi)
{
	smb_node_t *src_fnode, *src_dnode, *dst_fnode, *dst_dnode;
	smb_node_t *tnode;
	int rc, count;
	DWORD status;
	char *new_name, *path;

	path = dst_fqi->fq_path.pn_path;

	/* Check if attempting to rename a stream - not yet supported */
	rc = smb_rename_check_stream(src_fqi, dst_fqi);
	if (rc != 0)
		return (rc);

	/* The source node may already have been provided */
	if (src_fqi->fq_fnode) {
		smb_node_start_crit(src_fqi->fq_fnode, RW_READER);
		smb_node_ref(src_fqi->fq_fnode);
		smb_node_ref(src_fqi->fq_dnode);
	} else {
		/* lookup and validate src node */
		rc = smb_rename_lookup_src(sr);
		if (rc != 0)
			return (rc);
	}

	src_fnode = src_fqi->fq_fnode;
	src_dnode = src_fqi->fq_dnode;
	tnode = sr->tid_tree->t_snode;

	/* Find destination dnode and last_comp */
	if (dst_fqi->fq_dnode) {
		smb_node_ref(dst_fqi->fq_dnode);
	} else {
		rc = smb_pathname_reduce(sr, sr->user_cr, path, tnode, tnode,
		    &dst_fqi->fq_dnode, dst_fqi->fq_last_comp);
		if (rc != 0) {
			smb_rename_release_src(sr);
			return (rc);
		}
	}

	dst_dnode = dst_fqi->fq_dnode;
	new_name = dst_fqi->fq_last_comp;

	/* If exact name match in same directory, we're done */
	if ((src_dnode == dst_dnode) &&
	    (strcmp(src_fnode->od_name, new_name) == 0)) {
		smb_rename_release_src(sr);
		smb_node_release(dst_dnode);
		return (0);
	}

	/* Lookup destination node */
	rc = smb_fsop_lookup(sr, sr->user_cr, 0, tnode,
	    dst_dnode, new_name, &dst_fqi->fq_fnode);

	/* If the destination node doesn't already exist, validate new_name. */
	if (rc == ENOENT) {
		if (smb_is_invalid_filename(new_name)) {
			smb_rename_release_src(sr);
			smb_node_release(dst_dnode);
			return (EILSEQ); /* NT_STATUS_OBJECT_NAME_INVALID */
		}
	}

	/*
	 * Handle case where changing case of the same directory entry.
	 *
	 * If we found the dst node in the same directory as the src node,
	 * and their names differ only in case:
	 *
	 * If the tree is case sensitive (or mixed):
	 *  Do case sensitive lookup to see if exact match exists.
	 *  If the exact match is the same node as src_node we're done.
	 *
	 * If the tree is case insensitive:
	 *  There is currently no way to tell if the case is different
	 *  or not, so do the rename (unless the specified new name was
	 *  mangled).
	 */
	if ((rc == 0) &&
	    (src_dnode == dst_dnode) &&
	    (smb_strcasecmp(src_fnode->od_name,
	    dst_fqi->fq_fnode->od_name, 0) == 0)) {
		smb_node_release(dst_fqi->fq_fnode);
		dst_fqi->fq_fnode = NULL;

		if (smb_tree_has_feature(sr->tid_tree,
		    SMB_TREE_NO_CASESENSITIVE)) {
			if (smb_strcasecmp(src_fnode->od_name,
			    dst_fqi->fq_last_comp, 0) != 0) {
				smb_rename_release_src(sr);
				smb_node_release(dst_dnode);
				return (0);
			}
		} else {
			rc = smb_fsop_lookup(sr, sr->user_cr,
			    SMB_CASE_SENSITIVE, tnode, dst_dnode, new_name,
			    &dst_fqi->fq_fnode);

			if ((rc == 0) &&
			    (dst_fqi->fq_fnode == src_fnode)) {
				smb_rename_release_src(sr);
				smb_node_release(dst_fqi->fq_fnode);
				smb_node_release(dst_dnode);
				return (0);
			}
		}
	}

	if ((rc != 0) && (rc != ENOENT)) {
		smb_rename_release_src(sr);
		smb_node_release(dst_fqi->fq_dnode);
		return (rc);
	}

	if (dst_fqi->fq_fnode) {
		/*
		 * Destination already exists.  Do delete checks.
		 */
		dst_fnode = dst_fqi->fq_fnode;

		if (!(sr->arg.dirop.flags && SMB_RENAME_FLAG_OVERWRITE)) {
			smb_rename_release_src(sr);
			smb_node_release(dst_fnode);
			smb_node_release(dst_dnode);
			return (EEXIST);
		}

		(void) smb_oplock_break(sr, dst_fnode,
		    SMB_OPLOCK_BREAK_TO_NONE | SMB_OPLOCK_BREAK_BATCH);

		/*
		 * Wait (a little) for the oplock break to be
		 * responded to by clients closing handles.
		 * Hold node->n_lock as reader to keep new
		 * ofiles from showing up after we check.
		 */
		smb_node_rdlock(dst_fnode);
		for (count = 0; count <= 12; count++) {
			status = smb_node_delete_check(dst_fnode);
			if (status != NT_STATUS_SHARING_VIOLATION)
				break;
			smb_node_unlock(dst_fnode);
			delay(MSEC_TO_TICK(100));
			smb_node_rdlock(dst_fnode);
		}
		if (status != NT_STATUS_SUCCESS) {
			smb_node_unlock(dst_fnode);
			smb_rename_release_src(sr);
			smb_node_release(dst_fnode);
			smb_node_release(dst_dnode);
			return (EACCES);
		}

		/*
		 * Note, the combination of these two:
		 *	smb_node_rdlock(node);
		 *	nbl_start_crit(node->vp, RW_READER);
		 * is equivalent to this call:
		 *	smb_node_start_crit(node, RW_READER)
		 *
		 * Cleanup after this point should use:
		 *	smb_node_end_crit(dst_fnode)
		 */
		nbl_start_crit(dst_fnode->vp, RW_READER);

		/*
		 * This checks nbl_share_conflict, nbl_lock_conflict
		 */
		status = smb_nbl_conflict(dst_fnode, 0, UINT64_MAX, NBL_REMOVE);
		if (status != NT_STATUS_SUCCESS) {
			smb_node_end_crit(dst_fnode);
			smb_rename_release_src(sr);
			smb_node_release(dst_fnode);
			smb_node_release(dst_dnode);
			return (EACCES);
		}

		new_name = dst_fnode->od_name;
	}

	rc = smb_fsop_rename(sr, sr->user_cr,
	    src_dnode, src_fnode->od_name,
	    dst_dnode, new_name);

	if (rc == 0) {
		/*
		 * Note that renames in the same directory are normally
		 * delivered in {old,new} pairs, and clients expect them
		 * in that order, if both events are delivered.
		 */
		int a_src, a_dst; /* action codes */
		if (src_dnode == dst_dnode) {
			a_src = FILE_ACTION_RENAMED_OLD_NAME;
			a_dst = FILE_ACTION_RENAMED_NEW_NAME;
		} else {
			a_src = FILE_ACTION_REMOVED;
			a_dst = FILE_ACTION_ADDED;
		}
		smb_node_notify_change(src_dnode, a_src, src_fnode->od_name);
		smb_node_notify_change(dst_dnode, a_dst, new_name);
	}

	smb_rename_release_src(sr);

	if (dst_fqi->fq_fnode) {
		smb_node_end_crit(dst_fnode);
		smb_node_release(dst_fnode);
	}
	smb_node_release(dst_dnode);

	return (rc);
}

/*
 * smb_rename_check_stream
 *
 * For a stream rename the dst path must begin with ':', or "\\:".
 * We don't yet support stream rename, Return EACCES.
 *
 * If not a stream rename, in accordance with the above rule,
 * it is not valid for either the src or dst to be a stream.
 * Return EINVAL.
 */
static int
smb_rename_check_stream(smb_fqi_t *src_fqi, smb_fqi_t *dst_fqi)
{
	smb_node_t *src_fnode = src_fqi->fq_fnode;
	char *src_path = src_fqi->fq_path.pn_path;
	char *dst_path = dst_fqi->fq_path.pn_path;

	/* We do not yet support named stream rename - ACCESS DENIED */
	if ((dst_path[0] == ':') ||
	    ((dst_path[0] == '\\') && (dst_path[1] == ':'))) {
		return (EACCES);
	}

	/*
	 * If not stream rename (above) neither src or dst can be
	 * a named stream.
	 */

	if (smb_is_stream_name(dst_path))
		return (EINVAL);

	if (src_fqi->fq_fnode) {
		if (SMB_IS_STREAM(src_fnode))
			return (EINVAL);
	} else {
		if (smb_is_stream_name(src_path))
			return (EINVAL);
	}

	return (0);
}


/*
 * smb_make_link
 *
 * Creating a hard link (adding an additional name) for a file.
 *
 * If the source and destination are identical, we go through all
 * the checks but we don't create a link.
 *
 * If the file is a symlink we create the hardlink on the target
 * of the symlink (i.e. use SMB_FOLLOW_LINKS when looking up src).
 * If the target of the symlink does not exist we fail with ENOENT.
 *
 * Returns errno values.
 */
static int
smb_make_link(smb_request_t *sr, smb_fqi_t *src_fqi, smb_fqi_t *dst_fqi)
{
	smb_node_t *tnode;
	char *path;
	int rc;

	/* Cannnot create link on named stream */
	if (smb_is_stream_name(src_fqi->fq_path.pn_path) ||
	    smb_is_stream_name(dst_fqi->fq_path.pn_path)) {
		return (EINVAL);
	}

	/* lookup and validate src node */
	rc = smb_rename_lookup_src(sr);
	if (rc != 0)
		return (rc);

	/* if src and dest paths match we're done */
	if (smb_strcasecmp(src_fqi->fq_path.pn_path,
	    dst_fqi->fq_path.pn_path, 0) == 0) {
		smb_rename_release_src(sr);
		return (0);
	}

	/* find the destination dnode and last_comp */
	tnode = sr->tid_tree->t_snode;
	path = dst_fqi->fq_path.pn_path;
	rc = smb_pathname_reduce(sr, sr->user_cr, path, tnode, tnode,
	    &dst_fqi->fq_dnode, dst_fqi->fq_last_comp);
	if (rc != 0) {
		smb_rename_release_src(sr);
		return (rc);
	}

	/* If name match in same directory, we're done */
	if ((src_fqi->fq_dnode == dst_fqi->fq_dnode) &&
	    (smb_strcasecmp(src_fqi->fq_fnode->od_name,
	    dst_fqi->fq_last_comp, 0) == 0)) {
		smb_rename_release_src(sr);
		smb_node_release(dst_fqi->fq_dnode);
		return (0);
	}

	if (smb_is_invalid_filename(dst_fqi->fq_last_comp)) {
		smb_rename_release_src(sr);
		smb_node_release(dst_fqi->fq_dnode);
		return (EILSEQ); /* NT_STATUS_INVALID_OBJECT_NAME */
	}

	/* Lookup the destination node. It MUST NOT exist. */
	rc = smb_fsop_lookup(sr, sr->user_cr, 0, tnode,
	    dst_fqi->fq_dnode, dst_fqi->fq_last_comp, &dst_fqi->fq_fnode);
	if (rc == 0) {
		smb_node_release(dst_fqi->fq_fnode);
		rc = EEXIST;
	}
	if (rc != ENOENT) {
		smb_rename_release_src(sr);
		smb_node_release(dst_fqi->fq_dnode);
		return (rc);
	}

	rc = smb_fsop_link(sr, sr->user_cr, src_fqi->fq_fnode,
	    dst_fqi->fq_dnode, dst_fqi->fq_last_comp);

	if (rc == 0) {
		smb_node_notify_change(dst_fqi->fq_dnode,
		    FILE_ACTION_ADDED, dst_fqi->fq_last_comp);
	}

	smb_rename_release_src(sr);
	smb_node_release(dst_fqi->fq_dnode);
	return (rc);
}

/*
 * smb_rename_lookup_src
 *
 * Lookup the src node, checking for sharing violations and
 * breaking any existing BATCH oplock.
 * Populate sr->arg.dirop.fqi
 *
 * Upon success, the dnode and fnode will have holds and the
 * fnode will be in a critical section. These should be
 * released using smb_rename_release_src().
 *
 * Returns errno values.
 */
static int
smb_rename_lookup_src(smb_request_t *sr)
{
	smb_node_t *src_node, *tnode;
	DWORD status;
	int rc;
	int count;
	char *path;

	struct dirop *dirop = &sr->arg.dirop;
	smb_fqi_t *src_fqi = &sr->arg.dirop.fqi;

	if (smb_is_stream_name(src_fqi->fq_path.pn_path))
		return (EINVAL);

	/* Lookup the source node */
	tnode = sr->tid_tree->t_snode;
	path = src_fqi->fq_path.pn_path;
	rc = smb_pathname_reduce(sr, sr->user_cr, path, tnode, tnode,
	    &src_fqi->fq_dnode, src_fqi->fq_last_comp);
	if (rc != 0)
		return (rc);

	rc = smb_fsop_lookup(sr, sr->user_cr, 0, tnode,
	    src_fqi->fq_dnode, src_fqi->fq_last_comp, &src_fqi->fq_fnode);
	if (rc != 0) {
		smb_node_release(src_fqi->fq_dnode);
		return (rc);
	}

	/* Not valid to create hardlink for directory */
	if ((dirop->info_level == SMB_NT_RENAME_SET_LINK_INFO) &&
	    (smb_node_is_dir(src_fqi->fq_fnode))) {
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		return (EISDIR);
	}

	src_node = src_fqi->fq_fnode;

	rc = smb_rename_check_attr(sr, src_node, src_fqi->fq_sattr);
	if (rc != 0) {
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		return (rc);
	}

	/*
	 * Break BATCH oplock before ofile checks. If a client
	 * has a file open, this will force a flush or close,
	 * which may affect the outcome of any share checking.
	 */
	(void) smb_oplock_break(sr, src_node,
	    SMB_OPLOCK_BREAK_TO_LEVEL_II | SMB_OPLOCK_BREAK_BATCH);

	/*
	 * Wait (a little) for the oplock break to be
	 * responded to by clients closing handles.
	 * Hold node->n_lock as reader to keep new
	 * ofiles from showing up after we check.
	 */
	smb_node_rdlock(src_node);
	for (count = 0; count <= 12; count++) {
		status = smb_node_rename_check(src_node);
		if (status != NT_STATUS_SHARING_VIOLATION)
			break;
		smb_node_unlock(src_node);
		delay(MSEC_TO_TICK(100));
		smb_node_rdlock(src_node);
	}
	if (status != NT_STATUS_SUCCESS) {
		smb_node_unlock(src_node);
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		return (EPIPE); /* = ERRbadshare */
	}

	/*
	 * Note, the combination of these two:
	 *	smb_node_rdlock(node);
	 *	nbl_start_crit(node->vp, RW_READER);
	 * is equivalent to this call:
	 *	smb_node_start_crit(node, RW_READER)
	 *
	 * Cleanup after this point should use:
	 *	smb_node_end_crit(src_node)
	 */
	nbl_start_crit(src_node->vp, RW_READER);

	/*
	 * This checks nbl_share_conflict, nbl_lock_conflict
	 */
	status = smb_nbl_conflict(src_node, 0, UINT64_MAX, NBL_RENAME);
	if (status != NT_STATUS_SUCCESS) {
		smb_node_end_crit(src_node);
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		if (status == NT_STATUS_SHARING_VIOLATION)
			return (EPIPE); /* = ERRbadshare */
		return (EACCES);
	}

	/* NB: Caller expects holds on src_fqi fnode, dnode */
	return (0);
}

/*
 * smb_rename_release_src
 */
static void
smb_rename_release_src(smb_request_t *sr)
{
	smb_fqi_t *src_fqi = &sr->arg.dirop.fqi;

	smb_node_end_crit(src_fqi->fq_fnode);
	smb_node_release(src_fqi->fq_fnode);
	smb_node_release(src_fqi->fq_dnode);
}


static int
smb_rename_check_attr(smb_request_t *sr, smb_node_t *node, uint16_t sattr)
{
	smb_attr_t attr;

	bzero(&attr, sizeof (attr));
	attr.sa_mask = SMB_AT_DOSATTR;
	if (smb_node_getattr(sr, node, zone_kcred(), NULL, &attr) != 0)
		return (EACCES);

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
	{ EISDIR, ERROR_ACCESS_DENIED,	NT_STATUS_FILE_IS_A_DIRECTORY },
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
