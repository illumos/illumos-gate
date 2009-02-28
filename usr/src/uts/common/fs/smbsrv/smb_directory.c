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
#include <smbsrv/ntstatus.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>

typedef struct smb_dirpath {
	char	*sp_path;	/* Original path */
	char	*sp_curp;	/* Current pointer into the original path */
	smb_request_t *sp_sr;	/* Current request pointer */
} smb_dirpath_t;

static smb_dirpath_t *smb_dirpath_new(smb_request_t *);
static int smb_dirpath_next(smb_dirpath_t *);
static boolean_t smb_dirpath_isvalid(const char *);

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

	rc = smbsr_decode_data(sr, "%S", sr, &sr->arg.dirop.fqi.path);

	DTRACE_SMB_2(op__CreateDirectory__start, smb_request_t *, sr,
	    struct dirop *, &sr->arg.dirop);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_create_directory(smb_request_t *sr)
{
	DTRACE_SMB_1(op__CreateDirectory__done, smb_request_t *, sr);
}

/*
 * smb_com_create_directory
 *
 * It is possible to get a full pathname here and the client expects any
 * or all of the components to be created if they don't already exist.
 */
smb_sdrc_t
smb_com_create_directory(smb_request_t *sr)
{
	smb_dirpath_t *spp;
	smb_attr_t *attr;
	DWORD status;
	int rc = 0;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	if (!smb_dirpath_isvalid(sr->arg.dirop.fqi.path)) {
		smbsr_error(sr, NT_STATUS_OBJECT_PATH_SYNTAX_BAD,
		    ERRDOS, ERROR_BAD_PATHNAME);
		return (SDRC_ERROR);
	}

	if ((status = smb_validate_dirname(sr->arg.dirop.fqi.path)) != 0) {
		smbsr_error(sr, status, ERRDOS, ERROR_INVALID_NAME);
		return (SDRC_ERROR);
	}

	/*
	 * Try each component of the path.  EEXIST on path
	 * components is okay except on the last one.
	 */
	spp = smb_dirpath_new(sr);

	while (smb_dirpath_next(spp)) {
		rc = smb_common_create_directory(sr);

		switch (rc) {
		case 0:
			break;
		case EEXIST:
			attr = &sr->arg.dirop.fqi.last_attr;

			if (attr->sa_vattr.va_type != VDIR) {
				smbsr_error(sr, NT_STATUS_OBJECT_NAME_COLLISION,
				    ERRDOS, ERROR_PATH_NOT_FOUND);
				return (SDRC_ERROR);
			}
			break;
		case ENOENT:
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_NOT_FOUND,
			    ERRDOS, ERROR_FILE_NOT_FOUND);
			return (SDRC_ERROR);
		case ENOTDIR:
			smbsr_error(sr, NT_STATUS_NOT_A_DIRECTORY,
			    ERRDOS, ERROR_PATH_NOT_FOUND);
			return (SDRC_ERROR);
		default:
			smbsr_errno(sr, rc);
			return (SDRC_ERROR);
		}
	}

	if (rc != 0) {
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	rc = smbsr_encode_empty_result(sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * smb_validate_dirname
 *
 * Very basic directory name validation: checks for colons in a path.
 * Need to skip the drive prefix since it contains a colon.
 *
 * Returns 0 if the name is valid, otherwise NT_STATUS_NOT_A_DIRECTORY.
 */
DWORD
smb_validate_dirname(char *path)
{
	char *name;

	if ((name = path) != 0) {
		name += strspn(name, "\\");

		if (strchr(name, ':') != 0)
			return (NT_STATUS_NOT_A_DIRECTORY);
	}

	return (0);
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
	smb_node_t *dnode;
	smb_node_t *node;

	sr->arg.dirop.fqi.srch_attr = 0;

	rc = smbd_fs_query(sr, &sr->arg.dirop.fqi, FQM_PATH_MUST_NOT_EXIST);
	if (rc)
		return (rc);

	/*
	 * Because of FQM_PATH_MUST_NOT_EXIST and the successful return
	 * value, only fqi.dir_snode has a valid parameter (fqi.last_snode
	 * is NULL).
	 */
	dnode = sr->arg.dirop.fqi.dir_snode;

	rc = smb_fsop_access(sr, sr->user_cr, dnode, FILE_ADD_SUBDIRECTORY);
	if (rc != NT_STATUS_SUCCESS)
		return (EACCES);

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

	if ((rc = smb_fsop_mkdir(sr, sr->user_cr, dnode,
	    sr->arg.dirop.fqi.last_comp, &new_attr,
	    &sr->arg.dirop.fqi.last_snode,
	    &sr->arg.dirop.fqi.last_attr)) != 0) {
		smb_node_release(dnode);
		SMB_NULL_FQI_NODES(sr->arg.dirop.fqi);
		return (rc);
	}

	node = sr->arg.dirop.fqi.last_snode;
	node->flags |= NODE_FLAGS_CREATED;

	sr->arg.open.create_options = FILE_DIRECTORY_FILE;

	smb_node_release(node);
	smb_node_release(dnode);
	SMB_NULL_FQI_NODES(sr->arg.dirop.fqi);
	return (0);
}

static smb_dirpath_t *
smb_dirpath_new(smb_request_t *sr)
{
	int pathLen;
	char *xpath;
	smb_dirpath_t *spp;

	/* Malloc from the request storage area. This is freed automatically */
	/* so we don't need to worry about freeing it later */
	spp = smbsr_malloc(&sr->request_storage, sizeof (smb_dirpath_t));
	spp->sp_path = sr->arg.dirop.fqi.path;
	pathLen = strlen(spp->sp_path);
	spp->sp_curp = spp->sp_path;
	xpath = smbsr_malloc(&sr->request_storage, pathLen + 1);
	sr->arg.dirop.fqi.path = xpath;
	spp->sp_sr = sr;

	return (spp);
}

/*
 * Perhaps somewhat dangerous since everything happens as a side effect. The
 * returns 1 if there is a valid component updated to the fqi, 0 otherwise.
 */
static int
smb_dirpath_next(smb_dirpath_t *spp)
{
	char *xp;
	int xlen;

	if (spp == 0)
		return (0);

	/* Move the index to the "next" "\" and copy the path to the fqi */
	/* path for the next component. */

	/* First look for the next component */
	while (*spp->sp_curp == '\\')
		spp->sp_curp++;

	/* Now get to the end of the component */
	xp = spp->sp_curp; /* Remember from where we started */
	while (*spp->sp_curp != '\0' && *spp->sp_curp != '\\') {
		spp->sp_curp++;
	}

	/* If we made no progress, we are done */
	if (xp == spp->sp_curp)
		return (0);

	/*
	 * Now copy the original path up to but not including our current
	 * pointer
	 */

	/*LINTED E_PTRDIFF_OVERFLOW*/
	xlen = spp->sp_curp - spp->sp_path;
	(void) strncpy(spp->sp_sr->arg.dirop.fqi.path, spp->sp_path, xlen);

	/* Now NULL terminate it */
	spp->sp_sr->arg.dirop.fqi.path[xlen] = '\0';
	return (1);
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

	rc = smbsr_decode_data(sr, "%S", sr, &sr->arg.dirop.fqi.path);

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
	smb_node_t *dnode;
	smb_attr_t *attr;
	int rc;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	sr->arg.dirop.fqi.srch_attr = 0;

	rc = smbd_fs_query(sr, &sr->arg.dirop.fqi, FQM_PATH_MUST_EXIST);
	if (rc) {
		if (rc == ENOENT)
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_NOT_FOUND,
			    ERRDOS, ERROR_FILE_NOT_FOUND);
		else
			smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	attr = &sr->arg.dirop.fqi.last_attr;
	if (attr->sa_vattr.va_type != VDIR) {
		smbsr_error(sr, NT_STATUS_NOT_A_DIRECTORY,
		    ERRDOS, ERROR_PATH_NOT_FOUND);
		return (SDRC_ERROR);
	}

	dnode = sr->arg.dirop.fqi.last_snode;
	rc = smb_fsop_access(sr, sr->user_cr, dnode, DELETE);

	if ((rc != NT_STATUS_SUCCESS) ||
	    (dnode->attr.sa_dosattr & FILE_ATTRIBUTE_READONLY)) {
		smb_node_release(dnode);
		smb_node_release(sr->arg.dirop.fqi.dir_snode);
		SMB_NULL_FQI_NODES(sr->arg.dirop.fqi);
		smbsr_error(sr, NT_STATUS_CANNOT_DELETE,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	smb_node_release(dnode);

	dnode = sr->arg.dirop.fqi.dir_snode;

	rc = smb_fsop_rmdir(sr, sr->user_cr, dnode,
	    sr->arg.dirop.fqi.last_comp_od, 1);
	if (rc != 0) {
		smb_node_release(dnode);
		SMB_NULL_FQI_NODES(sr->arg.dirop.fqi);
		if (rc == EEXIST)
			smbsr_error(sr, NT_STATUS_DIRECTORY_NOT_EMPTY,
			    ERRDOS, ERROR_DIR_NOT_EMPTY);
		else
			smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	smb_node_release(dnode);
	SMB_NULL_FQI_NODES(sr->arg.dirop.fqi);

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

	rc = smbsr_decode_data(sr, "%S", sr, &sr->arg.dirop.fqi.path);

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
	smb_node_t *dnode;
	int rc;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS,
		    ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	if (sr->arg.dirop.fqi.path[0] == '\0') {
		rc = smbsr_encode_empty_result(sr);
		return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
	}

	if (!smb_dirpath_isvalid(sr->arg.dirop.fqi.path)) {
		smbsr_error(sr, NT_STATUS_OBJECT_NAME_INVALID,
		    ERRDOS, ERROR_PATH_NOT_FOUND);
		return (SDRC_ERROR);
	}

	sr->arg.dirop.fqi.srch_attr = 0;

	rc = smbd_fs_query(sr, &sr->arg.dirop.fqi, FQM_PATH_MUST_EXIST);
	if (rc) {
		if (rc == ENOENT)
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_NOT_FOUND,
			    ERRDOS, ERROR_PATH_NOT_FOUND);
		else
			smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	smb_node_release(sr->arg.dirop.fqi.dir_snode);

	dnode = sr->arg.dirop.fqi.last_snode;

	if (sr->arg.dirop.fqi.last_attr.sa_vattr.va_type != VDIR) {
		smb_node_release(dnode);
		SMB_NULL_FQI_NODES(sr->arg.dirop.fqi);
		smbsr_error(sr, NT_STATUS_NOT_A_DIRECTORY,
		    ERRDOS, ERROR_PATH_NOT_FOUND);
		return (SDRC_ERROR);
	}

	rc = smb_fsop_access(sr, sr->user_cr, dnode, FILE_TRAVERSE);

	smb_node_release(dnode);
	SMB_NULL_FQI_NODES(sr->arg.dirop.fqi);

	if (rc != 0) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	rc = smbsr_encode_empty_result(sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

static boolean_t
smb_dirpath_isvalid(const char *path)
{
	struct {
		char *name;
		int len;
	} *bad, bad_paths[] = {
		{ ".\0",   2 },
		{ ".\\\0", 3 },
		{ "..\0",  3 },
		{ "..\\",  3 }
	};

	char *cp;
	char *p;
	int i;

	if (*path == '\0')
		return (B_TRUE);

	cp = smb_kstrdup(path, MAXPATHLEN);
	p = strcanon(cp, "\\");
	p += strspn(p, "\\");

	for (i = 0; i < sizeof (bad_paths) / sizeof (bad_paths[0]); ++i) {
		bad = &bad_paths[i];

		if (strncmp(p, bad->name, bad->len) == 0) {
			kmem_free(cp, MAXPATHLEN);
			return (B_FALSE);
		}
	}

	kmem_free(cp, MAXPATHLEN);
	return (B_TRUE);
}
