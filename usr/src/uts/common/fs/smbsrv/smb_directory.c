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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_fsops.h>

/*
 * The create directory message is sent to create a new directory.  The
 * appropriate Tid and additional pathname are passed.  The directory must
 * not exist for it to be created.
 *
 * Client Request                     Description
 * ================================== =================================
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes; min = 2
 * UCHAR BufferFormat;                0x04
 * STRING DirectoryName[];            Directory name
 *
 * Servers require clients to have at least create permission for the
 * subtree containing the directory in order to create a new directory.
 * The creator's access rights to the new directory are be determined by
 * local policy on the server.
 *
 * Server Response                    Description
 * ================================== =================================
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes = 0
 */
smb_sdrc_t
smb_pre_create_directory(smb_request_t *sr)
{
	int rc;

	rc = smbsr_decode_data(sr, "%S", sr,
	    &sr->arg.dirop.fqi.fq_path.pn_path);

	DTRACE_SMB_2(op__CreateDirectory__start, smb_request_t *, sr,
	    struct dirop *, &sr->arg.dirop);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_create_directory(smb_request_t *sr)
{
	DTRACE_SMB_1(op__CreateDirectory__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_create_directory(smb_request_t *sr)
{
	int rc = 0;
	smb_pathname_t *pn = &sr->arg.dirop.fqi.fq_path;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	smb_pathname_init(sr, pn, pn->pn_path);
	if (!smb_pathname_validate(sr, pn) ||
	    !smb_validate_dirname(sr, pn)) {
		return (SDRC_ERROR);
	}

	if ((rc = smb_common_create_directory(sr)) != 0) {
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	rc = smbsr_encode_empty_result(sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * smb_common_create_directory
 *
 * Currently called from:
 *		smb_com_create_directory
 *		smb_com_trans2_create_directory
 *
 * Returns errno values.
 */
int
smb_common_create_directory(smb_request_t *sr)
{
	int rc;
	smb_attr_t new_attr;
	smb_fqi_t *fqi;
	smb_node_t *tnode;

	fqi = &sr->arg.dirop.fqi;
	tnode = sr->tid_tree->t_snode;

	rc = smb_pathname_reduce(sr, sr->user_cr, fqi->fq_path.pn_path,
	    tnode, tnode, &fqi->fq_dnode, fqi->fq_last_comp);
	if (rc != 0)
		return (rc);

	if (smb_is_invalid_filename(fqi->fq_last_comp)) {
		smb_node_release(fqi->fq_dnode);
		return (EILSEQ); /* NT_STATUS_OBJECT_NAME_INVALID */
	}

	/* lookup node - to ensure that it does NOT exist */
	rc = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS,
	    tnode, fqi->fq_dnode, fqi->fq_last_comp, &fqi->fq_fnode);
	if (rc == 0) {
		smb_node_release(fqi->fq_dnode);
		smb_node_release(fqi->fq_fnode);
		return (EEXIST);
	}
	if (rc != ENOENT) {
		smb_node_release(fqi->fq_dnode);
		return (rc);
	}

	rc = smb_fsop_access(sr, sr->user_cr, fqi->fq_dnode,
	    FILE_ADD_SUBDIRECTORY);
	if (rc != NT_STATUS_SUCCESS) {
		smb_node_release(fqi->fq_dnode);
		return (EACCES);
	}

	/*
	 * Explicitly set sa_dosattr, otherwise the file system may
	 * automatically apply FILE_ATTRIBUTE_ARCHIVE which, for
	 * compatibility with windows servers, should not be set.
	 */
	bzero(&new_attr, sizeof (new_attr));
	new_attr.sa_dosattr = FILE_ATTRIBUTE_DIRECTORY;
	new_attr.sa_vattr.va_type = VDIR;
	new_attr.sa_vattr.va_mode = 0777;
	new_attr.sa_mask = SMB_AT_TYPE | SMB_AT_MODE | SMB_AT_DOSATTR;

	rc = smb_fsop_mkdir(sr, sr->user_cr, fqi->fq_dnode, fqi->fq_last_comp,
	    &new_attr, &fqi->fq_fnode);
	if (rc != 0) {
		smb_node_release(fqi->fq_dnode);
		return (rc);
	}

	sr->arg.open.create_options = FILE_DIRECTORY_FILE;

	smb_node_release(fqi->fq_dnode);
	smb_node_release(fqi->fq_fnode);
	return (0);
}

/*
 * The delete directory message is sent to delete an empty directory. The
 * appropriate Tid and additional pathname are passed. The directory must
 * be empty for it to be deleted.
 *
 * NT supports a hidden permission known as File Delete Child (FDC). If
 * the user has FullControl access to a directory, the user is permitted
 * to delete any object in the directory regardless of the permissions
 * on the object.
 *
 * Client Request                     Description
 * ================================== =================================
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes; min = 2
 * UCHAR BufferFormat;                0x04
 * STRING DirectoryName[];            Directory name
 *
 * The directory to be deleted cannot be the root of the share specified
 * by Tid.
 *
 * Server Response                    Description
 * ================================== =================================
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes = 0
 */
smb_sdrc_t
smb_pre_delete_directory(smb_request_t *sr)
{
	int rc;

	rc = smbsr_decode_data(sr, "%S", sr,
	    &sr->arg.dirop.fqi.fq_path.pn_path);

	DTRACE_SMB_2(op__DeleteDirectory__start, smb_request_t *, sr,
	    struct dirop *, &sr->arg.dirop);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_delete_directory(smb_request_t *sr)
{
	DTRACE_SMB_1(op__DeleteDirectory__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_delete_directory(smb_request_t *sr)
{
	int rc;
	uint32_t flags = 0;
	smb_fqi_t *fqi;
	smb_node_t *tnode;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	fqi = &sr->arg.dirop.fqi;
	tnode = sr->tid_tree->t_snode;

	smb_pathname_init(sr, &fqi->fq_path, fqi->fq_path.pn_path);
	if (!smb_pathname_validate(sr, &fqi->fq_path) ||
	    !smb_validate_dirname(sr, &fqi->fq_path)) {
		return (SDRC_ERROR);
	}

	rc = smb_pathname_reduce(sr, sr->user_cr, fqi->fq_path.pn_path,
	    tnode, tnode, &fqi->fq_dnode, fqi->fq_last_comp);

	if (rc != 0) {
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	rc = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS,
	    tnode, fqi->fq_dnode, fqi->fq_last_comp, &fqi->fq_fnode);
	if (rc != 0) {
		if (rc == ENOENT)
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_NOT_FOUND,
			    ERRDOS, ERROR_FILE_NOT_FOUND);
		else
			smbsr_errno(sr, rc);
		smb_node_release(fqi->fq_dnode);
		return (SDRC_ERROR);
	}

	/*
	 * Delete should fail if this is the root of a share
	 * or a DFS link
	 */
	if ((fqi->fq_fnode == tnode) || smb_node_is_dfslink(fqi->fq_fnode)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		smb_node_release(fqi->fq_dnode);
		smb_node_release(fqi->fq_fnode);
		return (SDRC_ERROR);
	}

	if (!smb_node_is_dir(fqi->fq_fnode)) {
		smbsr_error(sr, NT_STATUS_NOT_A_DIRECTORY,
		    ERRDOS, ERROR_PATH_NOT_FOUND);
		smb_node_release(fqi->fq_dnode);
		smb_node_release(fqi->fq_fnode);
		return (SDRC_ERROR);
	}

	/*
	 * Using kcred because we just want the DOS attrs
	 * and don't want access errors for this.
	 */
	fqi->fq_fattr.sa_mask = SMB_AT_DOSATTR;
	rc = smb_node_getattr(sr, fqi->fq_fnode, kcred, NULL,
	    &fqi->fq_fattr);
	if (rc != 0) {
		smbsr_errno(sr, rc);
		smb_node_release(fqi->fq_dnode);
		smb_node_release(fqi->fq_fnode);
		return (SDRC_ERROR);
	}

	if ((fqi->fq_fattr.sa_dosattr & FILE_ATTRIBUTE_READONLY) ||
	    (smb_fsop_access(sr, sr->user_cr, fqi->fq_fnode, DELETE)
	    != NT_STATUS_SUCCESS)) {
		smbsr_error(sr, NT_STATUS_CANNOT_DELETE,
		    ERRDOS, ERROR_ACCESS_DENIED);
		smb_node_release(fqi->fq_dnode);
		smb_node_release(fqi->fq_fnode);
		return (SDRC_ERROR);
	}

	if (SMB_TREE_SUPPORTS_CATIA(sr))
		flags |= SMB_CATIA;

	rc = smb_fsop_rmdir(sr, sr->user_cr, fqi->fq_dnode,
	    fqi->fq_fnode->od_name, flags);

	smb_node_release(fqi->fq_fnode);
	smb_node_release(fqi->fq_dnode);

	if (rc != 0) {
		if (rc == EEXIST)
			smbsr_error(sr, NT_STATUS_DIRECTORY_NOT_EMPTY,
			    ERRDOS, ERROR_DIR_NOT_EMPTY);
		else
			smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	rc = smbsr_encode_empty_result(sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * This SMB is used to verify that a path exists and is a directory.  No
 * error is returned if the given path exists and the client has read
 * access to it.  Client machines which maintain a concept of a "working
 * directory" will find this useful to verify the validity of a "change
 * working directory" command.  Note that the servers do NOT have a concept
 * of working directory for a particular client.  The client must always
 * supply full pathnames relative to the Tid in the SMB header.
 *
 * Client Request                     Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes;    min = 2
 * UCHAR BufferFormat;                0x04
 * STRING DirectoryPath[];            Directory path
 *
 * Server Response                    Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 * DOS clients, in particular, depend on ERRbadpath if the directory is
 * not found.
 */
smb_sdrc_t
smb_pre_check_directory(smb_request_t *sr)
{
	int rc;

	rc = smbsr_decode_data(sr, "%S", sr,
	    &sr->arg.dirop.fqi.fq_path.pn_path);

	DTRACE_SMB_2(op__CheckDirectory__start, smb_request_t *, sr,
	    struct dirop *, &sr->arg.dirop);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_check_directory(smb_request_t *sr)
{
	DTRACE_SMB_1(op__CheckDirectory__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_check_directory(smb_request_t *sr)
{
	int rc;
	smb_fqi_t *fqi;
	smb_node_t *tnode;
	smb_node_t *node;
	char *path;
	smb_pathname_t *pn;

	if (STYPE_ISIPC(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS,
		    ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	fqi = &sr->arg.dirop.fqi;
	pn = &fqi->fq_path;

	if (pn->pn_path[0] == '\0') {
		rc = smbsr_encode_empty_result(sr);
		return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
	}

	smb_pathname_init(sr, pn, pn->pn_path);
	if (!smb_pathname_validate(sr, pn) ||
	    !smb_validate_dirname(sr, pn)) {
		return (SDRC_ERROR);
	}

	path = pn->pn_path;
	tnode = sr->tid_tree->t_snode;

	rc = smb_pathname_reduce(sr, sr->user_cr, path, tnode, tnode,
	    &fqi->fq_dnode, fqi->fq_last_comp);
	if (rc != 0) {
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	rc = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS,
	    tnode, fqi->fq_dnode, fqi->fq_last_comp, &fqi->fq_fnode);
	smb_node_release(fqi->fq_dnode);
	if (rc != 0) {
		if (rc == ENOENT)
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_NOT_FOUND,
			    ERRDOS, ERROR_PATH_NOT_FOUND);
		else
			smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	node = fqi->fq_fnode;
	if (!smb_node_is_dir(node)) {
		smbsr_error(sr, NT_STATUS_NOT_A_DIRECTORY,
		    ERRDOS, ERROR_PATH_NOT_FOUND);
		smb_node_release(node);
		return (SDRC_ERROR);
	}

	if ((sr->smb_flg2 & SMB_FLAGS2_DFS) && smb_node_is_dfslink(node)) {
		smbsr_error(sr, NT_STATUS_PATH_NOT_COVERED, ERRSRV, ERRbadpath);
		smb_node_release(node);
		return (SDRC_ERROR);
	}

	rc = smb_fsop_access(sr, sr->user_cr, node, FILE_TRAVERSE);

	smb_node_release(node);

	if (rc != 0) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	rc = smbsr_encode_empty_result(sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}
