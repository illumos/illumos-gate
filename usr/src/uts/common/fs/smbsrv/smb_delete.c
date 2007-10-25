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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smbinfo.h>

static DWORD smb_delete_check(struct smb_request *sr, struct smb_node *node,
    uint16_t dattr, smb_error_t *smberr);
static DWORD smb_delete_share_check(struct smb_node *node);

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
int
smb_com_delete(struct smb_request *sr)
{
	int	rc;
	int	od = 0;
	int	deleted = 0;
	unsigned short sattr;
	char *path;
	struct smb_node *dir_snode;
	struct smb_node *node = 0;
	char *name;
	char *fname;
	char *sname;
	char *fullname;
	smb_error_t smberr;
	int is_stream;
	smb_odir_context_t *pc;

	pc = kmem_zalloc(sizeof (*pc), KM_SLEEP);
	fname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	sname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	fullname = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	if (smbsr_decode_vwv(sr, "w", &sattr) != 0) {
		kmem_free(pc, sizeof (*pc));
		kmem_free(name, MAXNAMELEN);
		kmem_free(fname, MAXNAMELEN);
		kmem_free(sname, MAXNAMELEN);
		kmem_free(fullname, MAXPATHLEN);
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	if (smbsr_decode_data(sr, "%S", sr, &path) != 0) {
		kmem_free(pc, sizeof (*pc));
		kmem_free(name, MAXNAMELEN);
		kmem_free(fname, MAXNAMELEN);
		kmem_free(sname, MAXNAMELEN);
		kmem_free(fullname, MAXPATHLEN);
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	is_stream = smb_stream_parse_name(path, fname, sname);

	(void) smb_rdir_open(sr, path, sattr);
	dir_snode = sr->sid_odir->d_dir_snode;

	/*
	 * This while loop is meant to deal with wildcards.
	 * It is not expected that wildcards will exist for
	 * streams.  For the streams case, it is expected
	 * that the below loop will be executed only once.
	 */

	while ((rc = smb_rdir_next(sr, &node, pc)) == 0) {
		(void) strlcpy(name, pc->dc_name, MAXNAMELEN);

		if (smb_delete_check(sr, node, pc->dc_dattr, &smberr)
		    != NT_STATUS_SUCCESS) {
			smb_node_release(node);
			goto delete_error;
		}

		smb_node_release(node);
		node = NULL;

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

		if (rc != 0) {
			if (rc != ENOENT) {
				smb_rdir_close(sr);
				kmem_free(pc, sizeof (*pc));
				kmem_free(name, MAXNAMELEN);
				kmem_free(fname, MAXNAMELEN);
				kmem_free(sname, MAXNAMELEN);
				kmem_free(fullname, MAXPATHLEN);
				smbsr_raise_errno(sr, rc);
				/* NOTREACHED */
			}
		} else {
			deleted++;
		}
	}

	if ((rc != 0) && (rc != ENOENT)) {
		/* rc returned by smb_rdir_next() */
		smb_rdir_close(sr);
		kmem_free(pc, sizeof (*pc));
		kmem_free(name, MAXNAMELEN);
		kmem_free(fname, MAXNAMELEN);
		kmem_free(sname, MAXNAMELEN);
		kmem_free(fullname, MAXPATHLEN);
		smbsr_raise_errno(sr, rc);
		/* NOTREACHED */
	}

	if (deleted == 0) {
		smberr.errcls = ERRDOS;
		smberr.errcode = ERROR_FILE_NOT_FOUND;
		smberr.status = (sr->sid_odir->d_wildcards == 0)
		    ? NT_STATUS_OBJECT_NAME_NOT_FOUND : NT_STATUS_NO_SUCH_FILE;
		goto delete_error;
	}

	smb_rdir_close(sr);

	smbsr_encode_empty_result(sr);

	kmem_free(pc, sizeof (*pc));
	kmem_free(name, MAXNAMELEN);
	kmem_free(fname, MAXNAMELEN);
	kmem_free(sname, MAXNAMELEN);
	kmem_free(fullname, MAXPATHLEN);
	return (SDRC_NORMAL_REPLY);

delete_error:
	smb_rdir_close(sr);
	kmem_free(pc, sizeof (*pc));
	kmem_free(name, MAXNAMELEN);
	kmem_free(fname, MAXNAMELEN);
	kmem_free(sname, MAXNAMELEN);
	kmem_free(fullname, MAXPATHLEN);
	smbsr_raise_cifs_error(sr,
	    smberr.status, smberr.errcls, smberr.errcode);
	/* NOTREACHED */
	return (SDRC_NORMAL_REPLY); /* compiler complains otherwise */
}

static DWORD
smb_delete_check(
    struct smb_request *sr,
    struct smb_node *node,
    uint16_t dattr,
    smb_error_t *smberr)
{
	if (dattr & SMB_FA_DIRECTORY) {
		smberr->errcls = ERRDOS;
		smberr->errcode = ERROR_ACCESS_DENIED;
		smberr->status = NT_STATUS_FILE_IS_A_DIRECTORY;
		return (NT_STATUS_UNSUCCESSFUL);
	}

	if ((dattr & SMB_FA_READONLY) ||
	    (node->flags & NODE_CREATED_READONLY)) {
		smberr->errcls = ERRDOS;
		smberr->errcode = ERROR_ACCESS_DENIED;
		smberr->status = NT_STATUS_CANNOT_DELETE;
		return (NT_STATUS_UNSUCCESSFUL);
	}

	/*
	 * NT does not always close a file immediately, which
	 * can cause the share and access checking to fail
	 * (the node refcnt is greater than one), and the file
	 * doesn't get deleted. Breaking the oplock before
	 * share and access checking gives the client a chance
	 * to close the file.
	 */
	if (OPLOCKS_IN_FORCE(node)) {
		smberr->status = smb_break_oplock(sr, node);

		if (smberr->status != NT_STATUS_SUCCESS) {
			smberr->errcls = ERRDOS;
			smberr->errcode = ERROR_VC_DISCONNECTED;
			return (NT_STATUS_UNSUCCESSFUL);
		}
	}

	smberr->status = smb_delete_share_check(node);
	if (smberr->status == NT_STATUS_SHARING_VIOLATION) {
		smberr->errcls = ERRDOS;
		smberr->errcode = ERROR_SHARING_VIOLATION;
		return (NT_STATUS_UNSUCCESSFUL);
	}

	/*
	 * This should be done after Share checking due to tests with
	 * W2K. I got sharing violation error trying to delete a
	 * locked file which is basically the same error if you
	 * try to delete a non-locked open file.
	 *
	 * One thing that I discovered during these tests is that
	 * W2K rejects lock requests on open files which are opened
	 * with Metadata open modes. The error is STATUS_ACCESS_DENIED.
	 */
	if (smb_lock_range_access(sr, node, 0, 0, FILE_WRITE_DATA) !=
	    NT_STATUS_SUCCESS) {
		smberr->errcls = ERRDOS;
		smberr->errcode = ERROR_ACCESS_DENIED;
		smberr->status = NT_STATUS_ACCESS_DENIED;
		return (NT_STATUS_UNSUCCESSFUL);
	}


	return (NT_STATUS_SUCCESS);
}

/*
 * smb_delete_share_check
 *
 * An open file can be deleted only if opened for
 * accessing meta data. Share modes aren't important
 * in this case.
 *
 * NOTE: there is another mechanism for deleting an
 * open file that NT clients usually use this method.
 * That's setting "Delete on close" flag for an open
 * file, in this way the file will be deleted after
 * last close. This flag can be set by SmbTrans2SetFileInfo
 * with FILE_DISPOSITION_INFO information level.
 * For setting this flag file should be opened by
 * DELETE access in the FID that is passed in the Trans2
 * request.
 */
static DWORD
smb_delete_share_check(struct smb_node *node)
{
	smb_ofile_t	*file;

	if (node == 0 || node->n_refcnt <= 1)
		return (NT_STATUS_SUCCESS);

	if (node->attr.sa_vattr.va_type == VDIR)
		return (NT_STATUS_SUCCESS);

	smb_llist_enter(&node->n_ofile_list, RW_READER);
	file = smb_llist_head(&node->n_ofile_list);
	while (file) {
		ASSERT(file->f_magic == SMB_OFILE_MAGIC);
		if (file->f_granted_access &
		    (FILE_READ_DATA |
		    FILE_WRITE_DATA |
		    FILE_APPEND_DATA |
		    FILE_EXECUTE |
		    DELETE)) {
			smb_llist_exit(&node->n_ofile_list);
			return (NT_STATUS_SHARING_VIOLATION);
		}
		file = smb_llist_next(&node->n_ofile_list, file);
	}
	smb_llist_exit(&node->n_ofile_list);
	return (NT_STATUS_SUCCESS);
}
