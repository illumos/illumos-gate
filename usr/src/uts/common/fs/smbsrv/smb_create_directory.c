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
 * SMB: create_directory
 *
 * The create directory message is sent to create a new directory.  The
 * appropriate Tid and additional pathname are passed.  The directory must
 * not exist for it to be created.
 *
 * Client Request                     Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes;    min = 2
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
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 *
 * USHORT ByteCount;                  Count of data bytes = 0
 */

#include <smbsrv/nterror.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>

typedef struct smb_request SmbRequest;

typedef struct {
	char	*sp_path;	/* Original path */
	char	*sp_curp;	/* Current pointer into the original path */
	SmbRequest *sp_sr;	/* Current request pointer */
} SmbPath;


extern int smb_common_create_directory(struct smb_request *sr);


static int smbpath_next(SmbPath* spp);
static SmbPath* smbpath_new(SmbRequest* sr);


/*
 * smb_com_create_directory
 *
 * It is possible to get a full pathname here and the client expects any
 * or all of the components to be created if they don't already exist.
 */
int
smb_com_create_directory(struct smb_request *sr)
{
	SmbPath* spp;
	DWORD status;
	int rc = 0;

	if (smbsr_decode_data(sr, "%S", sr, &sr->arg.dirop.fqi.path) != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	if ((status = smb_validate_dirname(sr->arg.dirop.fqi.path)) != 0) {
		smbsr_error(sr, status, ERRDOS, ERROR_INVALID_NAME);
		/* NOTREACHED */
	}

	/*
	 * Try each component of the path. It is all right to get an EEXIST
	 * on each component except the last.
	 */
	spp = smbpath_new(sr);

	while (smbpath_next(spp)) {
		rc = smb_common_create_directory(sr);
		if (rc != 0 && rc != EEXIST)
			smbsr_errno(sr, rc);
	}

	/* We should have created one directory successfully! */
	if (rc != 0)
		smbsr_errno(sr, rc);

	smbsr_encode_empty_result(sr);
	return (SDRC_NORMAL_REPLY);
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
smb_common_create_directory(struct smb_request *sr)
{
	int rc;
	smb_attr_t new_attr;
	struct smb_node *dnode;
	struct smb_node *node;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		/* NOTREACHED */
	}

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

	bzero(&new_attr, sizeof (new_attr));
	new_attr.sa_vattr.va_type = VDIR;
	new_attr.sa_vattr.va_mode = 0777;
	new_attr.sa_mask = SMB_AT_TYPE | SMB_AT_MODE;

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

SmbPath*
smbpath_new(SmbRequest* sr)
{
	int pathLen;
	char *xpath;
	SmbPath *spp;

	/* Malloc from the request storage area. This is freed automatically */
	/* so we don't need to worry about freeing it later */
	spp = smbsr_malloc(&sr->request_storage, sizeof (SmbPath));
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
int
smbpath_next(SmbPath* spp)
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
