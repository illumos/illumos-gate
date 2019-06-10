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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/synch.h>
#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <sys/nbmlock.h>

/*
 * SMB_TRANS2_SET_FILE/PATH_INFO (RENAME_INFORMATION level) flag
 */
#define	SMB_RENAME_FLAG_OVERWRITE	0x001

static int smb_rename_check_stream(smb_fqi_t *, smb_fqi_t *);
static int smb_rename_check_attr(smb_request_t *, smb_node_t *, uint16_t);
static int smb_rename_lookup_src(smb_request_t *);
static uint32_t smb_rename_check_src(smb_request_t *, smb_fqi_t *);
static void smb_rename_release_src(smb_request_t *);
static uint32_t smb_rename_errno2status(int);

/*
 * smb_setinfo_rename
 *
 * Implements SMB_FILE_RENAME_INFORMATION level of Trans2_Set_FileInfo
 * and Trans2_Set_PathInfo and SMB2 set_info, FileRenameInformation.
 * If the new filename (dst_fqi) already exists it may be overwritten
 * if flags == 1.
 *
 * The passed path is a full path relative to the share root.
 *
 * Returns NT status codes.
 *
 * Similar to smb_setinfo_link(), below.
 */
uint32_t
smb_setinfo_rename(smb_request_t *sr, smb_node_t *node, char *path, int flags)
{
	smb_fqi_t	*src_fqi = &sr->arg.dirop.fqi;
	smb_fqi_t	*dst_fqi = &sr->arg.dirop.dst_fqi;
	smb_pathname_t	*dst_pn = &dst_fqi->fq_path;
	uint32_t	status;

	sr->arg.dirop.flags = flags ? SMB_RENAME_FLAG_OVERWRITE : 0;
	sr->arg.dirop.info_level = FileRenameInformation;

	src_fqi->fq_sattr = SMB_SEARCH_ATTRIBUTES;
	src_fqi->fq_fnode = node;
	src_fqi->fq_dnode = node->n_dnode;

	/* validate the dst pathname */
	smb_pathname_init(sr, dst_pn, path);
	if (!smb_pathname_validate(sr, dst_pn))
		return (NT_STATUS_OBJECT_NAME_INVALID);

	status = smb_common_rename(sr, src_fqi, dst_fqi);
	return (status);
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
 * Returns NT status values.
 *
 * Similar to smb_make_link(), below.
 */
uint32_t
smb_common_rename(smb_request_t *sr, smb_fqi_t *src_fqi, smb_fqi_t *dst_fqi)
{
	smb_node_t *src_fnode, *src_dnode, *dst_dnode;
	smb_node_t *dst_fnode = 0;
	smb_node_t *tnode;
	char *new_name, *path;
	DWORD status;
	int rc;

	tnode = sr->tid_tree->t_snode;
	path = dst_fqi->fq_path.pn_path;

	/* Check if attempting to rename a stream - not yet supported */
	rc = smb_rename_check_stream(src_fqi, dst_fqi);
	if (rc != 0)
		return (smb_rename_errno2status(rc));

	/*
	 * The source node may already have been provided,
	 * i.e. when called by SMB1/SMB2 smb_setinfo_rename
	 * with an ofile.  When we have an ofile, open has
	 * already checked for sharing violations.  For
	 * path-based operations, do sharing check here.
	 */
	if (src_fqi->fq_fnode) {
		smb_node_ref(src_fqi->fq_dnode);
		smb_node_ref(src_fqi->fq_fnode);
	} else {
		/* lookup and validate src node */
		rc = smb_rename_lookup_src(sr);
		if (rc != 0)
			return (smb_rename_errno2status(rc));
		/* Holding refs on dnode, fnode */
	}
	src_fnode = src_fqi->fq_fnode;
	src_dnode = src_fqi->fq_dnode;

	/* Break oplocks, and check share modes. */
	status = smb_rename_check_src(sr, src_fqi);
	if (status != NT_STATUS_SUCCESS) {
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		return (status);
	}
	/*
	 * NB: src_fnode is now "in crit" (critical section)
	 * as if we did smb_node_start_crit(..., RW_READER);
	 * Call smb_rename_release_src(sr) on errors.
	 */

	/*
	 * Find the destination dnode and last component.
	 * May already be provided, i.e. when called via
	 * SMB1 trans2 setinfo.
	 */
	if (dst_fqi->fq_dnode) {
		/* called via smb_set_rename_info */
		smb_node_ref(dst_fqi->fq_dnode);
	} else {
		/* called via smb2_setf_rename, smb_com_rename, etc. */
		rc = smb_pathname_reduce(sr, sr->user_cr, path, tnode, tnode,
		    &dst_fqi->fq_dnode, dst_fqi->fq_last_comp);
		if (rc != 0) {
			smb_rename_release_src(sr);
			return (smb_rename_errno2status(rc));
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
			return (NT_STATUS_OBJECT_NAME_INVALID);
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
		return (smb_rename_errno2status(rc));
	}

	if (dst_fqi->fq_fnode) {
		/*
		 * Destination already exists.  Do delete checks.
		 */
		dst_fnode = dst_fqi->fq_fnode;

		if ((sr->arg.dirop.flags & SMB_RENAME_FLAG_OVERWRITE) == 0) {
			smb_rename_release_src(sr);
			smb_node_release(dst_fnode);
			smb_node_release(dst_dnode);
			return (NT_STATUS_OBJECT_NAME_COLLISION);
		}

		status = smb_oplock_break_DELETE(dst_fnode, NULL);
		if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS) {
			if (sr->session->dialect >= SMB_VERS_2_BASE)
				(void) smb2sr_go_async(sr);
			(void) smb_oplock_wait_break(dst_fnode, 0);
			status = 0;
		}
		if (status != 0) {
			smb_rename_release_src(sr);
			smb_node_release(dst_fnode);
			smb_node_release(dst_dnode);
			return (status);
		}

		smb_node_rdlock(dst_fnode);
		status = smb_node_delete_check(dst_fnode);
		if (status != NT_STATUS_SUCCESS) {
			smb_node_unlock(dst_fnode);
			smb_rename_release_src(sr);
			smb_node_release(dst_fnode);
			smb_node_release(dst_dnode);
			return (NT_STATUS_ACCESS_DENIED);
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
			return (NT_STATUS_ACCESS_DENIED);
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

	return (smb_rename_errno2status(rc));
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
 * smb_setinfo_link
 *
 * Implements FileRenameInformation for SMB1 Trans2 setinfo, SMB2 setinfo.
 * If the new filename (dst_fqi) already exists it may be overwritten
 * if flags == 1.
 *
 * The passed path is a full path relative to the share root.
 *
 * Returns NT status codes.
 *
 * Similar to smb_setinfo_rename(), above.
 */
uint32_t
smb_setinfo_link(smb_request_t *sr, smb_node_t *node, char *path, int flags)
{
	smb_fqi_t	*src_fqi = &sr->arg.dirop.fqi;
	smb_fqi_t	*dst_fqi = &sr->arg.dirop.dst_fqi;
	smb_pathname_t	*dst_pn = &dst_fqi->fq_path;
	uint32_t	status;

	sr->arg.dirop.flags = flags ? SMB_RENAME_FLAG_OVERWRITE : 0;
	sr->arg.dirop.info_level = FileLinkInformation;

	src_fqi->fq_sattr = SMB_SEARCH_ATTRIBUTES;
	src_fqi->fq_fnode = node;
	src_fqi->fq_dnode = node->n_dnode;

	/* validate the dst pathname */
	smb_pathname_init(sr, dst_pn, path);
	if (!smb_pathname_validate(sr, dst_pn))
		return (NT_STATUS_OBJECT_NAME_INVALID);

	status = smb_make_link(sr, src_fqi, dst_fqi);
	return (status);
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
 * Returns NT status values.
 *
 * Similar to smb_common_rename() above.
 */
uint32_t
smb_make_link(smb_request_t *sr, smb_fqi_t *src_fqi, smb_fqi_t *dst_fqi)
{
	smb_node_t *tnode;
	char *path;
	int rc;

	tnode = sr->tid_tree->t_snode;
	path = dst_fqi->fq_path.pn_path;

	/* Cannnot create link on named stream */
	if (smb_is_stream_name(src_fqi->fq_path.pn_path) ||
	    smb_is_stream_name(dst_fqi->fq_path.pn_path)) {
		return (NT_STATUS_INVALID_PARAMETER);
	}

	/* The source node may already have been provided */
	if (src_fqi->fq_fnode) {
		smb_node_ref(src_fqi->fq_dnode);
		smb_node_ref(src_fqi->fq_fnode);
	} else {
		/* lookup and validate src node */
		rc = smb_rename_lookup_src(sr);
		if (rc != 0)
			return (smb_rename_errno2status(rc));
		/* Holding refs on dnode, fnode */
	}

	/* Not valid to create hardlink for directory */
	if (smb_node_is_dir(src_fqi->fq_fnode)) {
		smb_node_release(src_fqi->fq_dnode);
		smb_node_release(src_fqi->fq_fnode);
		return (NT_STATUS_FILE_IS_A_DIRECTORY);
	}

	/*
	 * Unlike in rename, we will not unlink the src,
	 * so skip the smb_rename_check_src() call, and
	 * just "start crit" instead.
	 */
	smb_node_start_crit(src_fqi->fq_fnode, RW_READER);

	/*
	 * Find the destination dnode and last component.
	 * May already be provided, i.e. when called via
	 * SMB1 trans2 setinfo.
	 */
	if (dst_fqi->fq_dnode) {
		smb_node_ref(dst_fqi->fq_dnode);
	} else {
		rc = smb_pathname_reduce(sr, sr->user_cr, path, tnode, tnode,
		    &dst_fqi->fq_dnode, dst_fqi->fq_last_comp);
		if (rc != 0) {
			smb_rename_release_src(sr);
			return (smb_rename_errno2status(rc));
		}
	}

	/* If CI name match in same directory, we're done */
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
		return (NT_STATUS_OBJECT_NAME_INVALID);
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
		return (smb_rename_errno2status(rc));
	}

	rc = smb_fsop_link(sr, sr->user_cr, src_fqi->fq_fnode,
	    dst_fqi->fq_dnode, dst_fqi->fq_last_comp);

	if (rc == 0) {
		smb_node_notify_change(dst_fqi->fq_dnode,
		    FILE_ACTION_ADDED, dst_fqi->fq_last_comp);
	}

	smb_rename_release_src(sr);
	smb_node_release(dst_fqi->fq_dnode);
	return (smb_rename_errno2status(rc));
}

/*
 * smb_rename_lookup_src
 *
 * Lookup the src node for a path-based link or rename.
 *
 * On success, fills in sr->arg.dirop.fqi, and returns with
 * holds on the source dnode and fnode.
 *
 * Returns errno values.
 */
static int
smb_rename_lookup_src(smb_request_t *sr)
{
	smb_node_t *tnode;
	char *path;
	int rc;

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
	/* hold fq_dnode */

	rc = smb_fsop_lookup(sr, sr->user_cr, 0, tnode,
	    src_fqi->fq_dnode, src_fqi->fq_last_comp, &src_fqi->fq_fnode);
	if (rc != 0) {
		smb_node_release(src_fqi->fq_dnode);
		return (rc);
	}
	/* hold fq_dnode, fq_fnode */

	rc = smb_rename_check_attr(sr, src_fqi->fq_fnode, src_fqi->fq_sattr);
	if (rc != 0) {
		smb_node_release(src_fqi->fq_fnode);
		smb_node_release(src_fqi->fq_dnode);
		return (rc);
	}

	return (0);
}

/*
 * smb_rename_check_src
 *
 * Check for sharing violations on the file we'll unlink, and
 * break oplocks for the rename operation.  Note that we've
 * already done oplock breaks associated with opening a handle
 * on the file to rename.
 *
 * On success, returns with fnode in a critical section,
 * as if smb_node_start_crit were called with the node.
 * Caller should release using smb_rename_release_src().
 */
static uint32_t
smb_rename_check_src(smb_request_t *sr, smb_fqi_t *src_fqi)
{
	smb_node_t *src_node = src_fqi->fq_fnode;
	uint32_t status;

	/*
	 * Break BATCH oplock before ofile checks. If a client
	 * has a file open, this will force a flush or close,
	 * which may affect the outcome of any share checking.
	 *
	 * This operation may have either a handle or path for
	 * the source node (that will be unlinked via rename).
	 */

	if (sr->fid_ofile != NULL) {
		status = smb_oplock_break_SETINFO(src_node, sr->fid_ofile,
		    FileRenameInformation);
		if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS) {
			if (sr->session->dialect >= SMB_VERS_2_BASE)
				(void) smb2sr_go_async(sr);
			(void) smb_oplock_wait_break(src_node, 0);
			status = 0;
		}

		/*
		 * Sharing violations were checked at open time.
		 * Just "start crit" to be consistent with the
		 * state returned for path-based rename.
		 */
		smb_node_start_crit(src_fqi->fq_fnode, RW_READER);
		return (NT_STATUS_SUCCESS);
	}

	/*
	 * This code path operates without a real open, so
	 * break oplocks now as if we opened for delete.
	 * Note: SMB2 does only ofile-based rename.
	 *
	 * Todo:  Use an "internal open" for path-based
	 * rename and delete, then delete this code.
	 */
	ASSERT(sr->session->dialect < SMB_VERS_2_BASE);
	status = smb_oplock_break_DELETE(src_node, NULL);
	if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS) {
		(void) smb_oplock_wait_break(src_node, 0);
	}

	/*
	 * Path-based access to the src file (no ofile)
	 * so check for sharing violations here.
	 */
	smb_node_rdlock(src_node);
	status = smb_node_rename_check(src_node);
	if (status != NT_STATUS_SUCCESS) {
		smb_node_unlock(src_node);
		return (status);
	}

	status = smb_oplock_break_SETINFO(src_node, NULL,
	    FileRenameInformation);
	if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS) {
		(void) smb_oplock_wait_break(src_node, 0);
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
	}

	/* NB: Caller expects to be "in crit" on fnode. */
	return (status);
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
static uint32_t
smb_rename_errno2status(int errnum)
{
	static struct {
		int errnum;
		uint32_t status32;
	} rc_map[] = {
	{ EEXIST, NT_STATUS_OBJECT_NAME_COLLISION },
	{ EPIPE,  NT_STATUS_SHARING_VIOLATION },
	{ ENOENT, NT_STATUS_OBJECT_NAME_NOT_FOUND },
	{ ESRCH,  NT_STATUS_NO_SUCH_FILE },
	{ EINVAL, NT_STATUS_INVALID_PARAMETER },
	{ EACCES, NT_STATUS_ACCESS_DENIED },
	{ EISDIR, NT_STATUS_FILE_IS_A_DIRECTORY },
	{ EIO,    NT_STATUS_INTERNAL_ERROR }
	};

	int i;

	if (errnum == 0)
		return (0);

	for (i = 0; i < sizeof (rc_map)/sizeof (rc_map[0]); ++i) {
		if (rc_map[i].errnum == errnum) {
			return (rc_map[i].status32);
		}
	}

	return (smb_errno2status(errnum));
}
