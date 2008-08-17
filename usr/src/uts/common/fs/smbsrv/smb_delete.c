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

#pragma ident	"@(#)smb_delete.c	1.10	08/08/07 SMI"

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smbinfo.h>
#include <sys/nbmlock.h>

static uint32_t smb_delete_check(smb_request_t *, smb_node_t *);
static boolean_t smb_delete_check_path(smb_request_t *, boolean_t *);

/*
 * smb_com_delete
 *
 * The delete file message is sent to delete a data file. The appropriate
 * Tid and additional pathname are passed. Read only files may not be
 * deleted, the read-only attribute must be reset prior to file deletion.
 *
 * NT supports a hidden permission known as File Delete Child (FDC). If
 * the user has FullControl access to a directory, the user is permitted
 * to delete any object in the directory regardless of the permissions
 * on the object.
 *
 * Client Request                     Description
 * ================================== =================================
 * UCHAR WordCount;                   Count of parameter words = 1
 * USHORT SearchAttributes;
 * USHORT ByteCount;                  Count of data bytes; min = 2
 * UCHAR BufferFormat;                0x04
 * STRING FileName[];                 File name
 *
 * Multiple files may be deleted in response to a single request as
 * SMB_COM_DELETE supports wildcards
 *
 * SearchAttributes indicates the attributes that the target file(s) must
 * have. If the attribute is zero then only normal files are deleted. If
 * the system file or hidden attributes are specified then the delete is
 * inclusive -both the specified type(s) of files and normal files are
 * deleted. Attributes are described in the "Attribute Encoding" section
 * of this document.
 *
 * If bit0 of the Flags2 field of the SMB header is set, a pattern is
 * passed in, and the file has a long name, then the passed pattern  much
 * match the long file name for the delete to succeed. If bit0 is clear, a
 * pattern is passed in, and the file has a long name, then the passed
 * pattern must match the file's short name for the deletion to succeed.
 *
 * Server Response                    Description
 * ================================== =================================
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 * 4.2.10.1  Errors
 *
 * ERRDOS/ERRbadpath
 * ERRDOS/ERRbadfile
 * ERRDOS/ERRnoaccess
 * ERRDOS/ERRbadshare	# returned by NT for files that are already open
 * ERRHRD/ERRnowrite
 * ERRSRV/ERRaccess
 * ERRSRV/ERRinvdevice
 * ERRSRV/ERRinvid
 * ERRSRV/ERRbaduid
 */
smb_sdrc_t
smb_pre_delete(smb_request_t *sr)
{
	struct smb_fqi *fqi = &sr->arg.dirop.fqi;
	int rc;

	if ((rc = smbsr_decode_vwv(sr, "w", &fqi->srch_attr)) == 0)
		rc = smbsr_decode_data(sr, "%S", sr, &fqi->path);

	DTRACE_SMB_2(op__Delete__start, smb_request_t *, sr,
	    struct smb_fqi *, fqi);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_delete(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Delete__done, smb_request_t *, sr);
}

/*
 * smb_com_delete
 *
 * readonly
 * If a readonly entry is matched the search aborts with status
 * NT_STATUS_CANNOT_DELETE. Entries found prior to the readonly
 * entry will have been deleted.
 *
 * directories:
 * smb_com_delete does not delete directories:
 * A non-wildcard delete that finds a directory should result in
 * NT_STATUS_FILE_IS_A_DIRECTORY.
 * A wildcard delete that finds a directory will either:
 *	- abort with status NT_STATUS_FILE_IS_A_DIRECTORY, if
 *	  FILE_ATTRIBUTE_DIRECTORY is specified in the search attributes, or
 *	- skip that entry, if FILE_ATTRIBUTE_DIRECTORY is NOT specified
 *	  in the search attributes
 * Entries found prior to the directory entry will have been deleted.
 *
 * search attribute not matched
 * If an entry is found but it is either hidden or system and those
 * attributes are not specified in the search attributes:
 *	- if deleting a single file, status NT_STATUS_NO_SUCH_FILE
 *	- if wildcard delete, skip the entry and continue
 *
 * path not found
 * If smb_rdir_open cannot find the specified path, the error code
 * is set to NT_STATUS_OBJECT_PATH_NOT_FOUND. If there are wildcards
 * in the last_component, NT_STATUS_OBJECT_NAME_NOT_FOUND should be set
 * instead.
 *
 * smb_delete_check_path() - checks dot, bad path syntax, wildcards in path
 */

smb_sdrc_t
smb_com_delete(smb_request_t *sr)
{
	struct smb_fqi *fqi = &sr->arg.dirop.fqi;
	int rc;
	int deleted = 0;
	struct smb_node *node = NULL;
	smb_odir_context_t *pc;
	unsigned short sattr;
	boolean_t wildcards;

	if (smb_delete_check_path(sr, &wildcards) != B_TRUE)
		return (SDRC_ERROR);

	/*
	 * specify all search attributes so that delete-specific
	 * search attribute handling can be performed
	 */
	sattr = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN |
	    FILE_ATTRIBUTE_SYSTEM;

	if (smb_rdir_open(sr, fqi->path, sattr) != 0) {
		/*
		 * If there are wildcards in the last_component,
		 * NT_STATUS_OBJECT_NAME_NOT_FOUND
		 * should be used in place of NT_STATUS_OBJECT_PATH_NOT_FOUND
		 */
		if ((wildcards == B_TRUE) &&
		    (sr->smb_error.status == NT_STATUS_OBJECT_PATH_NOT_FOUND)) {
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_NOT_FOUND,
			    ERRDOS, ERROR_FILE_NOT_FOUND);
		}

		return (SDRC_ERROR);
	}

	pc = kmem_zalloc(sizeof (*pc), KM_SLEEP);

	/*
	 * This while loop is meant to deal with wildcards.
	 * It is not expected that wildcards will exist for
	 * streams.  For the streams case, it is expected
	 * that the below loop will be executed only once.
	 */

	while ((rc = smb_rdir_next(sr, &node, pc)) == 0) {
		/* check directory */
		if (pc->dc_dattr & FILE_ATTRIBUTE_DIRECTORY) {
			smb_node_release(node);
			if (wildcards == B_FALSE) {
				smbsr_error(sr, NT_STATUS_FILE_IS_A_DIRECTORY,
				    ERRDOS, ERROR_ACCESS_DENIED);
				goto delete_error;
			} else {
				if (SMB_SEARCH_DIRECTORY(fqi->srch_attr) != 0)
					break;
				else
					continue;
			}
		}

		/* check readonly */
		if (SMB_PATHFILE_IS_READONLY(sr, node)) {
			smb_node_release(node);
			smbsr_error(sr, NT_STATUS_CANNOT_DELETE,
			    ERRDOS, ERROR_ACCESS_DENIED);
			goto delete_error;
		}

		/* check search attributes */
		if (((pc->dc_dattr & FILE_ATTRIBUTE_HIDDEN) &&
		    !(SMB_SEARCH_HIDDEN(fqi->srch_attr))) ||
		    ((pc->dc_dattr & FILE_ATTRIBUTE_SYSTEM) &&
		    !(SMB_SEARCH_SYSTEM(fqi->srch_attr)))) {
			smb_node_release(node);
			if (wildcards == B_FALSE) {
				smbsr_error(sr, NT_STATUS_NO_SUCH_FILE,
				    ERRDOS, ERROR_FILE_NOT_FOUND);
				goto delete_error;
			} else {
				continue;
			}
		}

		/*
		 * NT does not always close a file immediately, which
		 * can cause the share and access checking to fail
		 * (the node refcnt is greater than one), and the file
		 * doesn't get deleted. Breaking the oplock before
		 * share and access checking gives the client a chance
		 * to close the file.
		 */

		smb_oplock_break(node);

		smb_node_start_crit(node, RW_READER);

		if (smb_delete_check(sr, node) != NT_STATUS_SUCCESS) {
			smb_node_end_crit(node);
			smb_node_release(node);
			goto delete_error;
		}

		/*
		 * Use node->od_name so as to skip mangle checks and
		 * stream processing (which have already been done in
		 * smb_rdir_next()).
		 * Use node->dir_snode to obtain the correct parent node
		 * (especially for streams).
		 */
		rc = smb_fsop_remove(sr, sr->user_cr, node->dir_snode,
		    node->od_name, 1);

		smb_node_end_crit(node);
		smb_node_release(node);
		node = NULL;

		if (rc != 0) {
			if (rc != ENOENT) {
				smbsr_errno(sr, rc);
				goto delete_error;
			}
		} else {
			deleted++;
		}
	}

	if ((rc != 0) && (rc != ENOENT)) {
		smbsr_errno(sr, rc);
		goto delete_error;
	}

	if (deleted == 0) {
		if (wildcards == B_FALSE)
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_NOT_FOUND,
			    ERRDOS, ERROR_FILE_NOT_FOUND);
		else
			smbsr_error(sr, NT_STATUS_NO_SUCH_FILE,
			    ERRDOS, ERROR_FILE_NOT_FOUND);
		goto delete_error;
	}

	smb_rdir_close(sr);
	kmem_free(pc, sizeof (*pc));

	rc = smbsr_encode_empty_result(sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);

delete_error:
	smb_rdir_close(sr);
	kmem_free(pc, sizeof (*pc));
	return (SDRC_ERROR);
}

/*
 * smb_delete_check_path
 *
 * Perform initial validation on the pathname and last_component.
 *
 * dot:
 * A filename of '.' should result in NT_STATUS_OBJECT_NAME_INVALID
 * Any wildcard filename that resolves to '.' should result in
 * NT_STATUS_OBJECT_NAME_INVALID if the search attributes include
 * FILE_ATTRIBUTE_DIRECTORY, otherwise handled as directory (see above).
 *
 * bad path syntax:
 * On unix .. at the root of a file system links to the root. Thus
 * an attempt to lookup "/../../.." will be the same as looking up "/"
 * CIFs clients expect the above to result in
 * NT_STATUS_OBJECT_PATH_SYNTAX_BAD. It is currently not possible
 * (and questionable if it's desirable) to deal with all cases
 * but paths beginning with \\.. are handled. See bad_paths[].
 * Cases like "\\dir\\..\\.." will still result in "\\" which is
 * contrary to windows behavior.
 *
 * wildcards in path:
 * Wildcards in the path (excluding the last_component) should result
 * in NT_STATUS_OBJECT_NAME_INVALID.
 *
 * Returns:
 *	B_TRUE:  path is valid. Sets *wildcard to TRUE if wildcard delete
 *	         i.e. if wildcards in last component
 *	B_FALSE: path is invalid. Sets error information in sr.
 */
static boolean_t
smb_delete_check_path(smb_request_t *sr, boolean_t *wildcard)
{
	struct smb_fqi *fqi = &sr->arg.dirop.fqi;
	char *p, *last_component;
	int i, wildcards;

	struct {
		char *name;
		int len;
	} *bad, bad_paths[] = {
		{"\\..\0", 4},
		{"\\..\\", 4},
		{"..\0", 3},
		{"..\\", 3}
	};

	wildcards = smb_convert_unicode_wildcards(fqi->path);

	/* find last component, strip trailing '\\' */
	p = fqi->path + strlen(fqi->path) - 1;
	while (*p == '\\') {
		*p = '\0';
		--p;
	}
	if ((p = strrchr(fqi->path, '\\')) == NULL) {
		last_component = fqi->path;
	} else {
		last_component = ++p;

		/*
		 * Any wildcards in path (excluding last_component) should
		 * result in NT_STATUS_OBJECT_NAME_INVALID
		 */
		if (smb_convert_unicode_wildcards(last_component)
		    != wildcards) {
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_INVALID,
			    ERRDOS, ERROR_INVALID_NAME);
			return (B_FALSE);
		}
	}

	/*
	 * path above the mount point => NT_STATUS_OBJECT_PATH_SYNTAX_BAD
	 * This test doesn't cover all cases: e.g. \dir\..\..
	 */
	for (i = 0; i < sizeof (bad_paths) / sizeof (bad_paths[0]); ++i) {
		bad = &bad_paths[i];
		if (strncmp(fqi->path, bad->name, bad->len) == 0) {
			smbsr_error(sr, NT_STATUS_OBJECT_PATH_SYNTAX_BAD,
			    ERRDOS, ERROR_BAD_PATHNAME);
			return (B_FALSE);
		}
	}

	/*
	 * Any file pattern that resolves to '.' is considered invalid.
	 * In the wildcard case, only an error if FILE_ATTRIBUTE_DIRECTORY
	 * is specified in search attributes, otherwise skipped (below)
	 */
	if ((strcmp(last_component, ".") == 0) ||
	    (SMB_SEARCH_DIRECTORY(fqi->srch_attr) &&
	    (smb_match(last_component, ".")))) {
		smbsr_error(sr, NT_STATUS_OBJECT_NAME_INVALID,
		    ERRDOS, ERROR_INVALID_NAME);
		return (B_FALSE);
	}

	*wildcard = (wildcards != 0);
	return (B_TRUE);
}

/*
 * For consistency with Windows 2000, the range check should be done
 * after checking for sharing violations.  Attempting to delete a
 * locked file will result in sharing violation, which is the same
 * thing that will happen if you try to delete a non-locked open file.
 *
 * Note that windows 2000 rejects lock requests on open files that
 * have been opened with metadata open modes.  The error is
 * STATUS_ACCESS_DENIED.
 */
static uint32_t
smb_delete_check(smb_request_t *sr, smb_node_t *node)
{
	uint32_t status;

	status = smb_node_delete_check(node);

	if (status == NT_STATUS_SHARING_VIOLATION) {
		smbsr_error(sr, NT_STATUS_SHARING_VIOLATION,
		    ERRDOS, ERROR_SHARING_VIOLATION);
		return (status);
	}

	status = smb_range_check(sr, node, 0, UINT64_MAX, B_TRUE);

	if (status != NT_STATUS_SUCCESS) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
	}

	return (status);
}
