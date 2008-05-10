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
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smbinfo.h>
#include <sys/nbmlock.h>

static uint32_t smb_delete_check(smb_request_t *, smb_node_t *);

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

smb_sdrc_t
smb_com_delete(smb_request_t *sr)
{
	struct smb_fqi *fqi = &sr->arg.dirop.fqi;
	int	rc;
	int	od = 0;
	int	deleted = 0;
	struct smb_node *dir_snode;
	struct smb_node *node = 0;
	char *name;
	char *fname;
	char *sname;
	char *fullname;
	int is_stream;
	smb_odir_context_t *pc;

	if (smb_rdir_open(sr, fqi->path, fqi->srch_attr) != 0)
		return (SDRC_ERROR);

	pc = kmem_zalloc(sizeof (*pc), KM_SLEEP);
	fname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	sname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	fullname = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	is_stream = smb_stream_parse_name(fqi->path, fname, sname);
	dir_snode = sr->sid_odir->d_dir_snode;

	/*
	 * This while loop is meant to deal with wildcards.
	 * It is not expected that wildcards will exist for
	 * streams.  For the streams case, it is expected
	 * that the below loop will be executed only once.
	 */

	while ((rc = smb_rdir_next(sr, &node, pc)) == 0) {
		(void) strlcpy(name, pc->dc_name, MAXNAMELEN);

		if (pc->dc_dattr & SMB_FA_DIRECTORY) {
			smbsr_error(sr, NT_STATUS_FILE_IS_A_DIRECTORY,
			    ERRDOS, ERROR_ACCESS_DENIED);
			smb_node_release(node);
			goto delete_error;
		}

		if ((pc->dc_dattr & SMB_FA_READONLY) ||
		    (node->flags & NODE_CREATED_READONLY)) {
			smbsr_error(sr, NT_STATUS_CANNOT_DELETE,
			    ERRDOS, ERROR_ACCESS_DENIED);
			smb_node_release(node);
			goto delete_error;
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

		if (is_stream) {
			/*
			 * It is assumed that fname does not contain
			 * any wildcards .
			 * smb_fsop_remove() requires filename+streamname
			 */
			(void) snprintf(fullname, MAXPATHLEN, "%s%s",
			    fname, sname);
			rc = smb_fsop_remove(sr, sr->user_cr, dir_snode,
			    fullname, 0);
		} else {
			/*
			 * name (i.e. pc->dc_name) is the on-disk name
			 * unless there is a case collision, in which
			 * case readdir will have returned a mangled name.
			 */
			if (smb_maybe_mangled_name(name) == 0)
				od = 1;

			rc = smb_fsop_remove(sr, sr->user_cr, dir_snode,
			    name, od);
		}

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
		if (sr->sid_odir->d_wildcards == 0)
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_NOT_FOUND,
			    ERRDOS, ERROR_FILE_NOT_FOUND);
		else
			smbsr_error(sr, NT_STATUS_NO_SUCH_FILE,
			    ERRDOS, ERROR_FILE_NOT_FOUND);
		goto delete_error;
	}

	smb_rdir_close(sr);
	kmem_free(pc, sizeof (*pc));
	kmem_free(name, MAXNAMELEN);
	kmem_free(fname, MAXNAMELEN);
	kmem_free(sname, MAXNAMELEN);
	kmem_free(fullname, MAXPATHLEN);

	rc = smbsr_encode_empty_result(sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);

delete_error:
	smb_rdir_close(sr);
	kmem_free(pc, sizeof (*pc));
	kmem_free(name, MAXNAMELEN);
	kmem_free(fname, MAXNAMELEN);
	kmem_free(sname, MAXNAMELEN);
	kmem_free(fullname, MAXPATHLEN);
	return (SDRC_ERROR);
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

	status = smb_range_check(sr, sr->user_cr, node, 0, UINT64_MAX, B_TRUE);

	if (status != NT_STATUS_SUCCESS) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
	}

	return (status);
}
