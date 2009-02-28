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

/*
 * This module provides the common open functionality to the various
 * open and create SMB interface functions.
 */

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/nterror.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/smbinfo.h>
#include <sys/fcntl.h>
#include <sys/nbmlock.h>

volatile uint32_t smb_fids = 0;

static uint32_t smb_open_subr(smb_request_t *);

extern uint32_t smb_is_executable(char *);

/*
 * This macro is used to delete a newly created object
 * if any error happens after creation of object.
 */
#define	SMB_DEL_NEWOBJ(obj) \
	if (created) {							\
		if (is_dir)						\
			(void) smb_fsop_rmdir(sr, sr->user_cr,		\
			    obj.dir_snode, obj.last_comp, 0);		\
		else							\
			(void) smb_fsop_remove(sr, sr->user_cr,		\
			    obj.dir_snode, obj.last_comp, 0);		\
	}

/*
 * smb_access_generic_to_file
 *
 * Search MSDN for IoCreateFile to see following mapping.
 *
 * GENERIC_READ		STANDARD_RIGHTS_READ, FILE_READ_DATA,
 *			FILE_READ_ATTRIBUTES and FILE_READ_EA
 *
 * GENERIC_WRITE	STANDARD_RIGHTS_WRITE, FILE_WRITE_DATA,
 *               FILE_WRITE_ATTRIBUTES, FILE_WRITE_EA, and FILE_APPEND_DATA
 *
 * GENERIC_EXECUTE	STANDARD_RIGHTS_EXECUTE, SYNCHRONIZE, and FILE_EXECUTE.
 */
uint32_t
smb_access_generic_to_file(uint32_t desired_access)
{
	uint32_t access = 0;

	if (desired_access & GENERIC_ALL)
		return (FILE_ALL_ACCESS & ~SYNCHRONIZE);

	if (desired_access & GENERIC_EXECUTE) {
		desired_access &= ~GENERIC_EXECUTE;
		access |= (STANDARD_RIGHTS_EXECUTE |
		    SYNCHRONIZE | FILE_EXECUTE);
	}

	if (desired_access & GENERIC_WRITE) {
		desired_access &= ~GENERIC_WRITE;
		access |= (FILE_GENERIC_WRITE & ~SYNCHRONIZE);
	}

	if (desired_access & GENERIC_READ) {
		desired_access &= ~GENERIC_READ;
		access |= FILE_GENERIC_READ;
	}

	return (access | desired_access);
}

/*
 * smb_omode_to_amask
 *
 * This function converts open modes used by Open and Open AndX
 * commands to desired access bits used by NT Create AndX command.
 */
uint32_t
smb_omode_to_amask(uint32_t desired_access)
{
	switch (desired_access & SMB_DA_ACCESS_MASK) {
	case SMB_DA_ACCESS_READ:
		return (FILE_GENERIC_READ);

	case SMB_DA_ACCESS_WRITE:
		return (FILE_GENERIC_WRITE);

	case SMB_DA_ACCESS_READ_WRITE:
		return (FILE_GENERIC_READ | FILE_GENERIC_WRITE);

	case SMB_DA_ACCESS_EXECUTE:
		return (FILE_GENERIC_EXECUTE);

	default:
		return (FILE_GENERIC_ALL);
	}
}

/*
 * smb_denymode_to_sharemode
 *
 * This function converts deny modes used by Open and Open AndX
 * commands to share access bits used by NT Create AndX command.
 */
uint32_t
smb_denymode_to_sharemode(uint32_t desired_access, char *fname)
{
	switch (desired_access & SMB_DA_SHARE_MASK) {
	case SMB_DA_SHARE_COMPATIBILITY:
		if (smb_is_executable(fname))
			return (FILE_SHARE_READ | FILE_SHARE_WRITE);

		return (FILE_SHARE_ALL);

	case SMB_DA_SHARE_EXCLUSIVE:
		return (FILE_SHARE_NONE);

	case SMB_DA_SHARE_DENY_WRITE:
		return (FILE_SHARE_READ);

	case SMB_DA_SHARE_DENY_READ:
		return (FILE_SHARE_WRITE);

	case SMB_DA_SHARE_DENY_NONE:
	default:
		return (FILE_SHARE_READ | FILE_SHARE_WRITE);
	}
}

/*
 * smb_ofun_to_crdisposition
 *
 * This function converts open function values used by Open and Open AndX
 * commands to create disposition values used by NT Create AndX command.
 */
uint32_t
smb_ofun_to_crdisposition(uint16_t  ofun)
{
	static int ofun_cr_map[3][2] =
	{
		{ -1,			FILE_CREATE },
		{ FILE_OPEN,		FILE_OPEN_IF },
		{ FILE_OVERWRITE,	FILE_OVERWRITE_IF }
	};

	int row = ofun & SMB_OFUN_OPEN_MASK;
	int col = (ofun & SMB_OFUN_CREATE_MASK) >> 4;

	if (row == 3)
		return (FILE_MAXIMUM_DISPOSITION + 1);

	return (ofun_cr_map[row][col]);
}

/*
 * Retry opens to avoid spurious sharing violations, due to timing
 * issues between closes and opens.  The client that already has the
 * file open may be in the process of closing it.
 */
uint32_t
smb_common_open(smb_request_t *sr)
{
	uint32_t status = NT_STATUS_SUCCESS;
	int count;

	for (count = 0; count <= 4; count++) {
		if (count)
			delay(MSEC_TO_TICK(400));

		status = smb_open_subr(sr);
		if (status != NT_STATUS_SHARING_VIOLATION)
			break;
	}

	if (status == NT_STATUS_SHARING_VIOLATION) {
		smbsr_error(sr, NT_STATUS_SHARING_VIOLATION,
		    ERRDOS, ERROR_SHARING_VIOLATION);
	}

	if (status == NT_STATUS_NO_SUCH_FILE) {
		smbsr_error(sr, NT_STATUS_OBJECT_NAME_NOT_FOUND,
		    ERRDOS, ERROR_FILE_NOT_FOUND);
	}

	return (status);
}

/*
 * smb_open_subr
 *
 * Notes on write-through behaviour. It looks like pre-LM0.12 versions
 * of the protocol specify the write-through mode when a file is opened,
 * (SmbOpen, SmbOpenAndX) so the write calls (SmbWrite, SmbWriteAndClose,
 * SmbWriteAndUnlock) don't need to contain a write-through flag.
 *
 * With LM0.12, the open calls (SmbCreateAndX, SmbNtTransactCreate)
 * don't indicate which write-through mode to use. Instead the write
 * calls (SmbWriteAndX, SmbWriteRaw) specify the mode on a per call
 * basis.
 *
 * We don't care which open call was used to get us here, we just need
 * to ensure that the write-through mode flag is copied from the open
 * parameters to the node. We test the omode write-through flag in all
 * write functions.
 *
 * This function will return NT status codes but it also raises errors,
 * in which case it won't return to the caller. Be careful how you
 * handle things in here.
 *
 * The following rules apply when processing a file open request:
 *
 * - Oplocks must be broken prior to share checking to prevent open
 * starvation due to batch oplocks.  Checking share reservations first
 * could potentially result in unnecessary open failures due to
 * open/close batching on the client.
 *
 * - Share checks must take place prior to access checks for correct
 * Windows semantics and to prevent unnecessary NFS delegation recalls.
 *
 * - Oplocks must be acquired after open to ensure the correct
 * synchronization with NFS delegation and FEM installation.
 *
 *
 * DOS readonly bit rules
 *
 * 1. The creator of a readonly file can write to/modify the size of the file
 * using the original create fid, even though the file will appear as readonly
 * to all other fids and via a CIFS getattr call.
 *
 * 2. A setinfo operation (using either an open fid or a path) to set/unset
 * readonly will be successful regardless of whether a creator of a readonly
 * file has an open fid (and has the special privilege mentioned in #1,
 * above).  I.e., the creator of a readonly fid holding that fid will no longer
 * have a special privilege.
 *
 * 3. The DOS readonly bit affects only data and some metadata.
 * The following metadata can be changed regardless of the readonly bit:
 * 	- security descriptors
 *	- DOS attributes
 *	- timestamps
 *
 * In the current implementation, the file size cannot be changed (except for
 * the exceptions in #1 and #2, above).
 *
 *
 * DOS attribute rules
 *
 * These rules are specific to creating / opening files and directories.
 * How the attribute value (specifically ZERO or FILE_ATTRIBUTE_NORMAL)
 * should be interpreted may differ in other requests.
 *
 * - An attribute value equal to ZERO or FILE_ATTRIBUTE_NORMAL means that the
 *   file's attributes should be cleared.
 * - If FILE_ATTRIBUTE_NORMAL is specified with any other attributes,
 *   FILE_ATTRIBUTE_NORMAL is ignored.
 *
 * 1. Creating a new file
 * - The request attributes + FILE_ATTRIBUTE_ARCHIVE are applied to the file.
 *
 * 2. Creating a new directory
 * - The request attributes + FILE_ATTRIBUTE_DIRECTORY are applied to the file.
 * - FILE_ATTRIBUTE_ARCHIVE does not get set.
 *
 * 3. Overwriting an existing file
 * - the request attributes are used as search attributes. If the existing
 *   file does not meet the search criteria access is denied.
 * - otherwise, applies attributes + FILE_ATTRIBUTE_ARCHIVE.
 *
 * 4. Opening an existing file or directory
 *    The request attributes are ignored.
 */
static uint32_t
smb_open_subr(smb_request_t *sr)
{
	int		created = 0;
	smb_node_t	*node = NULL;
	smb_node_t	*dnode = NULL;
	smb_node_t	*cur_node;
	open_param_t	*op = &sr->arg.open;
	int		rc;
	smb_ofile_t	*of;
	smb_attr_t	new_attr;
	int		pathlen;
	int		max_requested = 0;
	uint32_t	max_allowed;
	uint32_t	status = NT_STATUS_SUCCESS;
	int		is_dir;
	smb_error_t	err;
	boolean_t	is_stream = B_FALSE;
	int		lookup_flags = SMB_FOLLOW_LINKS;
	uint32_t	daccess;
	uint32_t	uniq_fid;

	is_dir = (op->create_options & FILE_DIRECTORY_FILE) ? 1 : 0;

	if (is_dir) {
		/*
		 * The object being created or opened is a directory,
		 * and the Disposition parameter must be one of
		 * FILE_CREATE, FILE_OPEN, or FILE_OPEN_IF
		 */
		if ((op->create_disposition != FILE_CREATE) &&
		    (op->create_disposition != FILE_OPEN_IF) &&
		    (op->create_disposition != FILE_OPEN)) {
			smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
			    ERRDOS, ERROR_INVALID_ACCESS);
			return (NT_STATUS_INVALID_PARAMETER);
		}
	}

	if (op->desired_access & MAXIMUM_ALLOWED) {
		max_requested = 1;
		op->desired_access &= ~MAXIMUM_ALLOWED;
	}
	op->desired_access = smb_access_generic_to_file(op->desired_access);

	if (sr->session->s_file_cnt >= SMB_SESSION_OFILE_MAX) {
		ASSERT(sr->uid_user);
		cmn_err(CE_NOTE, "smbd[%s\\%s]: %s", sr->uid_user->u_domain,
		    sr->uid_user->u_name,
		    xlate_nt_status(NT_STATUS_TOO_MANY_OPENED_FILES));

		smbsr_error(sr, NT_STATUS_TOO_MANY_OPENED_FILES,
		    ERRDOS, ERROR_TOO_MANY_OPEN_FILES);
		return (NT_STATUS_TOO_MANY_OPENED_FILES);
	}

	/* This must be NULL at this point */
	sr->fid_ofile = NULL;

	op->devstate = 0;

	switch (sr->tid_tree->t_res_type & STYPE_MASK) {
	case STYPE_DISKTREE:
		break;

	case STYPE_IPC:
		/*
		 * No further processing for IPC, we need to either
		 * raise an exception or return success here.
		 */
		if ((status = smb_opipe_open(sr)) != NT_STATUS_SUCCESS)
			smbsr_error(sr, status, 0, 0);
		return (status);

	default:
		smbsr_error(sr, NT_STATUS_BAD_DEVICE_TYPE,
		    ERRDOS, ERROR_BAD_DEV_TYPE);
		return (NT_STATUS_BAD_DEVICE_TYPE);
	}

	if ((pathlen = strlen(op->fqi.path)) >= MAXPATHLEN) {
		smbsr_error(sr, 0, ERRSRV, ERRfilespecs);
		return (NT_STATUS_NAME_TOO_LONG);
	}

	/*
	 * Some clients pass null file names; NT interprets this as "\".
	 */
	if (pathlen == 0) {
		op->fqi.path = "\\";
		pathlen = 1;
	}

	op->fqi.srch_attr = op->fqi.srch_attr;

	if ((status = smb_validate_object_name(op->fqi.path, is_dir)) != 0) {
		smbsr_error(sr, status, ERRDOS, ERROR_INVALID_NAME);
		return (status);
	}

	cur_node = op->fqi.dir_snode ?
	    op->fqi.dir_snode : sr->tid_tree->t_snode;

	if (rc = smb_pathname_reduce(sr, sr->user_cr, op->fqi.path,
	    sr->tid_tree->t_snode, cur_node, &op->fqi.dir_snode,
	    op->fqi.last_comp)) {
		smbsr_errno(sr, rc);
		return (sr->smb_error.status);
	}

	/*
	 * If the access mask has only DELETE set (ignore
	 * FILE_READ_ATTRIBUTES), then assume that this
	 * is a request to delete the link (if a link)
	 * and do not follow links.  Otherwise, follow
	 * the link to the target.
	 */

	daccess = op->desired_access & ~FILE_READ_ATTRIBUTES;

	if (daccess == DELETE)
		lookup_flags &= ~SMB_FOLLOW_LINKS;

	rc = smb_fsop_lookup_name(sr, kcred, lookup_flags,
	    sr->tid_tree->t_snode, op->fqi.dir_snode, op->fqi.last_comp,
	    &op->fqi.last_snode, &op->fqi.last_attr);

	if (rc == 0) {
		op->fqi.last_comp_was_found = 1;
		(void) strcpy(op->fqi.last_comp_od,
		    op->fqi.last_snode->od_name);
	} else if (rc == ENOENT) {
		op->fqi.last_comp_was_found = 0;
		op->fqi.last_snode = NULL;
		rc = 0;
	} else {
		smb_node_release(op->fqi.dir_snode);
		SMB_NULL_FQI_NODES(op->fqi);
		smbsr_errno(sr, rc);
		return (sr->smb_error.status);
	}

	/*
	 * The uniq_fid is a CIFS-server-wide unique identifier for an ofile
	 * which is used to uniquely identify open instances for the
	 * VFS share reservation and POSIX locks.
	 */

	uniq_fid = SMB_UNIQ_FID();

	if (op->fqi.last_comp_was_found) {

		if ((op->fqi.last_attr.sa_vattr.va_type != VREG) &&
		    (op->fqi.last_attr.sa_vattr.va_type != VDIR) &&
		    (op->fqi.last_attr.sa_vattr.va_type != VLNK)) {

			smb_node_release(op->fqi.last_snode);
			smb_node_release(op->fqi.dir_snode);
			SMB_NULL_FQI_NODES(op->fqi);
			smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS,
			    ERRnoaccess);
			return (NT_STATUS_ACCESS_DENIED);
		}

		node = op->fqi.last_snode;
		dnode = op->fqi.dir_snode;

		/*
		 * Reject this request if either:
		 * - the target IS a directory and the client requires that
		 *   it must NOT be (required by Lotus Notes)
		 * - the target is NOT a directory and client requires that
		 *   it MUST be.
		 */
		if (op->fqi.last_attr.sa_vattr.va_type == VDIR) {
			if (op->create_options & FILE_NON_DIRECTORY_FILE) {
				smb_node_release(node);
				smb_node_release(dnode);
				SMB_NULL_FQI_NODES(op->fqi);
				smbsr_error(sr, NT_STATUS_FILE_IS_A_DIRECTORY,
				    ERRDOS, ERROR_ACCESS_DENIED);
				return (NT_STATUS_FILE_IS_A_DIRECTORY);
			}
		} else {
			if ((op->create_options & FILE_DIRECTORY_FILE) ||
			    (op->nt_flags & NT_CREATE_FLAG_OPEN_TARGET_DIR)) {
				smb_node_release(node);
				smb_node_release(dnode);
				SMB_NULL_FQI_NODES(op->fqi);
				smbsr_error(sr, NT_STATUS_NOT_A_DIRECTORY,
				    ERRDOS, ERROR_DIRECTORY);
				return (NT_STATUS_NOT_A_DIRECTORY);
			}
		}

		/*
		 * No more open should be accepted when "Delete on close"
		 * flag is set.
		 */
		if (node->flags & NODE_FLAGS_DELETE_ON_CLOSE) {
			smb_node_release(node);
			smb_node_release(dnode);
			SMB_NULL_FQI_NODES(op->fqi);
			smbsr_error(sr, NT_STATUS_DELETE_PENDING,
			    ERRDOS, ERROR_ACCESS_DENIED);
			return (NT_STATUS_DELETE_PENDING);
		}

		/*
		 * Specified file already exists so the operation should fail.
		 */
		if (op->create_disposition == FILE_CREATE) {
			smb_node_release(node);
			smb_node_release(dnode);
			SMB_NULL_FQI_NODES(op->fqi);
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_COLLISION,
			    ERRDOS, ERROR_FILE_EXISTS);
			return (NT_STATUS_OBJECT_NAME_COLLISION);
		}

		/*
		 * Windows seems to check read-only access before file
		 * sharing check.
		 *
		 * Check to see if the file is currently readonly (irrespective
		 * of whether this open will make it readonly).
		 */
		if (SMB_PATHFILE_IS_READONLY(sr, node)) {
			/* Files data only */
			if (node->attr.sa_vattr.va_type != VDIR) {
				if (op->desired_access & (FILE_WRITE_DATA |
				    FILE_APPEND_DATA)) {
					smb_node_release(node);
					smb_node_release(dnode);
					SMB_NULL_FQI_NODES(op->fqi);
					smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
					    ERRDOS, ERRnoaccess);
					return (NT_STATUS_ACCESS_DENIED);
				}
			}
		}

		if (smb_oplock_conflict(node, sr->session, op))
			(void) smb_oplock_break(node,
			    SMB_SESSION_GET_ID(sr->session), B_FALSE);

		smb_node_wrlock(node);

		if ((op->create_disposition == FILE_SUPERSEDE) ||
		    (op->create_disposition == FILE_OVERWRITE_IF) ||
		    (op->create_disposition == FILE_OVERWRITE)) {

			if ((!(op->desired_access &
			    (FILE_WRITE_DATA | FILE_APPEND_DATA |
			    FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA))) ||
			    (!smb_sattr_check(node->attr.sa_dosattr,
			    op->dattr))) {
				smb_node_unlock(node);
				smb_node_release(node);
				smb_node_release(dnode);
				SMB_NULL_FQI_NODES(op->fqi);
				smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
				    ERRDOS, ERRnoaccess);
				return (NT_STATUS_ACCESS_DENIED);
			}
		}

		status = smb_fsop_shrlock(sr->user_cr, node, uniq_fid,
		    op->desired_access, op->share_access);

		if (status == NT_STATUS_SHARING_VIOLATION) {
			smb_node_unlock(node);
			smb_node_release(node);
			smb_node_release(dnode);
			SMB_NULL_FQI_NODES(op->fqi);
			return (status);
		}

		status = smb_fsop_access(sr, sr->user_cr, node,
		    op->desired_access);

		if (status != NT_STATUS_SUCCESS) {
			smb_fsop_unshrlock(sr->user_cr, node, uniq_fid);

			smb_node_unlock(node);
			smb_node_release(node);
			smb_node_release(dnode);
			SMB_NULL_FQI_NODES(op->fqi);

			if (status == NT_STATUS_PRIVILEGE_NOT_HELD) {
				smbsr_error(sr, status,
				    ERRDOS, ERROR_PRIVILEGE_NOT_HELD);
				return (status);
			} else {
				smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
				    ERRDOS, ERROR_ACCESS_DENIED);
				return (NT_STATUS_ACCESS_DENIED);
			}
		}

		switch (op->create_disposition) {
		case FILE_SUPERSEDE:
		case FILE_OVERWRITE_IF:
		case FILE_OVERWRITE:
			if (node->attr.sa_vattr.va_type == VDIR) {
				smb_fsop_unshrlock(sr->user_cr, node, uniq_fid);
				smb_node_unlock(node);
				smb_node_release(node);
				smb_node_release(dnode);
				SMB_NULL_FQI_NODES(op->fqi);
				smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
				    ERRDOS, ERROR_ACCESS_DENIED);
				return (NT_STATUS_ACCESS_DENIED);
			}

			if (node->attr.sa_vattr.va_size != op->dsize) {
				node->flags &= ~NODE_FLAGS_SET_SIZE;
				bzero(&new_attr, sizeof (new_attr));
				new_attr.sa_vattr.va_size = op->dsize;
				new_attr.sa_mask = SMB_AT_SIZE;

				rc = smb_fsop_setattr(sr, sr->user_cr,
				    node, &new_attr, &op->fqi.last_attr);

				if (rc) {
					smb_fsop_unshrlock(sr->user_cr, node,
					    uniq_fid);
					smb_node_unlock(node);
					smb_node_release(node);
					smb_node_release(dnode);
					SMB_NULL_FQI_NODES(op->fqi);
					smbsr_errno(sr, rc);
					return (sr->smb_error.status);
				}

				op->dsize = op->fqi.last_attr.sa_vattr.va_size;
			}

			op->dattr |= FILE_ATTRIBUTE_ARCHIVE;
			if (op->dattr & FILE_ATTRIBUTE_READONLY) {
				op->created_readonly = B_TRUE;
				op->dattr &= ~FILE_ATTRIBUTE_READONLY;
			}

			smb_node_set_dosattr(node, op->dattr);
			(void) smb_sync_fsattr(sr, sr->user_cr, node);

			/*
			 * If file is being replaced,
			 * we should remove existing streams
			 */
			if (SMB_IS_STREAM(node) == 0)
				(void) smb_fsop_remove_streams(sr, sr->user_cr,
				    node);

			op->action_taken = SMB_OACT_TRUNCATED;
			break;

		default:
			/*
			 * FILE_OPEN or FILE_OPEN_IF.
			 */
			op->action_taken = SMB_OACT_OPENED;
			break;
		}
	} else {
		/* Last component was not found. */
		dnode = op->fqi.dir_snode;

		if (is_dir == 0)
			is_stream = smb_is_stream_name(op->fqi.path);

		if ((op->create_disposition == FILE_OPEN) ||
		    (op->create_disposition == FILE_OVERWRITE)) {
			smb_node_release(dnode);
			SMB_NULL_FQI_NODES(op->fqi);
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_NOT_FOUND,
			    ERRDOS, ERROR_FILE_NOT_FOUND);
			return (NT_STATUS_OBJECT_NAME_NOT_FOUND);
		}

		if ((is_dir == 0) && (!is_stream) &&
		    smb_is_invalid_filename(op->fqi.last_comp)) {
			smb_node_release(dnode);
			SMB_NULL_FQI_NODES(op->fqi);
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_INVALID,
			    ERRDOS, ERROR_INVALID_NAME);
			return (NT_STATUS_OBJECT_NAME_INVALID);
		}

		/*
		 * lock the parent dir node in case another create
		 * request to the same parent directory comes in.
		 */
		smb_node_wrlock(dnode);

		bzero(&new_attr, sizeof (new_attr));
		new_attr.sa_dosattr = op->dattr;
		new_attr.sa_mask |= SMB_AT_DOSATTR;

		/*
		 * A file created with the readonly bit should not
		 * stop the creator writing to the file until it is
		 * closed.  Although the readonly bit will not be set
		 * on the file until it is closed, it will be accounted
		 * for on other fids and on queries based on the node
		 * state.
		 */
		if (op->dattr & FILE_ATTRIBUTE_READONLY)
			new_attr.sa_dosattr &= ~FILE_ATTRIBUTE_READONLY;


		if ((op->crtime.tv_sec != 0) &&
		    (op->crtime.tv_sec != UINT_MAX)) {

			new_attr.sa_mask |= SMB_AT_CRTIME;
			new_attr.sa_crtime = op->crtime;
		}

		if (is_dir == 0) {
			new_attr.sa_dosattr |= FILE_ATTRIBUTE_ARCHIVE;
			new_attr.sa_vattr.va_type = VREG;
			new_attr.sa_vattr.va_mode = is_stream ? S_IRUSR :
			    S_IRUSR | S_IRGRP | S_IROTH |
			    S_IWUSR | S_IWGRP | S_IWOTH;
			new_attr.sa_mask |= SMB_AT_TYPE | SMB_AT_MODE;

			if (op->dsize) {
				new_attr.sa_vattr.va_size = op->dsize;
				new_attr.sa_mask |= SMB_AT_SIZE;
			}

			rc = smb_fsop_create(sr, sr->user_cr, dnode,
			    op->fqi.last_comp, &new_attr,
			    &op->fqi.last_snode, &op->fqi.last_attr);

			if (rc != 0) {
				smb_node_unlock(dnode);
				smb_node_release(dnode);
				SMB_NULL_FQI_NODES(op->fqi);
				smbsr_errno(sr, rc);
				return (sr->smb_error.status);
			}

			node = op->fqi.last_snode;

			op->fqi.last_attr = node->attr;

			smb_node_wrlock(node);

			status = smb_fsop_shrlock(sr->user_cr, node, uniq_fid,
			    op->desired_access, op->share_access);

			if (status == NT_STATUS_SHARING_VIOLATION) {
				smb_node_unlock(node);
				SMB_DEL_NEWOBJ(op->fqi);
				smb_node_release(node);
				smb_node_unlock(dnode);
				smb_node_release(dnode);
				SMB_NULL_FQI_NODES(op->fqi);
				return (status);
			}
		} else {
			op->dattr |= FILE_ATTRIBUTE_DIRECTORY;
			new_attr.sa_vattr.va_type = VDIR;
			new_attr.sa_vattr.va_mode = 0777;
			new_attr.sa_mask |= SMB_AT_TYPE | SMB_AT_MODE;

			rc = smb_fsop_mkdir(sr, sr->user_cr, dnode,
			    op->fqi.last_comp, &new_attr,
			    &op->fqi.last_snode, &op->fqi.last_attr);
			if (rc != 0) {
				smb_node_unlock(dnode);
				smb_node_release(dnode);
				SMB_NULL_FQI_NODES(op->fqi);
				smbsr_errno(sr, rc);
				return (sr->smb_error.status);
			}

			node = op->fqi.last_snode;
			smb_node_wrlock(node);
		}

		created = 1;
		op->action_taken = SMB_OACT_CREATED;
		node->flags |= NODE_FLAGS_CREATED;

		if (op->dattr & FILE_ATTRIBUTE_READONLY) {
			op->created_readonly = B_TRUE;
			op->dattr &= ~FILE_ATTRIBUTE_READONLY;
		}
	}

	op->dattr = smb_node_get_dosattr(node);

	if (max_requested) {
		smb_fsop_eaccess(sr, sr->user_cr, node, &max_allowed);
		op->desired_access |= max_allowed;
	}

	/*
	 * if last_write time was in request and is not 0 or -1,
	 * use it as file's mtime
	 */
	if ((op->mtime.tv_sec != 0) && (op->mtime.tv_sec != UINT_MAX)) {
		smb_node_set_time(node, NULL, &op->mtime, NULL, NULL,
		    SMB_AT_MTIME);
		(void) smb_sync_fsattr(sr, sr->user_cr, node);
	}

	/*
	 * smb_ofile_open() will copy node to of->node.  Hence
	 * the hold on node (i.e. op->fqi.last_snode) will be "transferred"
	 * to the "of" structure.
	 */

	of = smb_ofile_open(sr->tid_tree, node, sr->smb_pid, op, SMB_FTYPE_DISK,
	    uniq_fid, &err);

	if (of == NULL) {
		smb_fsop_unshrlock(sr->user_cr, node, uniq_fid);

		SMB_DEL_NEWOBJ(op->fqi);
		smb_node_unlock(node);
		smb_node_release(node);
		if (created)
			smb_node_unlock(dnode);
		smb_node_release(dnode);
		SMB_NULL_FQI_NODES(op->fqi);
		smbsr_error(sr, err.status, err.errcls, err.errcode);
		return (err.status);
	}

	/*
	 * Propagate the write-through mode from the open params
	 * to the node: see the notes in the function header.
	 */
	if (sr->sr_cfg->skc_sync_enable ||
	    (op->create_options & FILE_WRITE_THROUGH))
		node->flags |= NODE_FLAGS_WRITE_THROUGH;

	op->fileid = op->fqi.last_attr.sa_vattr.va_nodeid;

	/*
	 * Set up the file type in open_param for the response
	 */
	op->ftype = SMB_FTYPE_DISK;
	sr->smb_fid = of->f_fid;
	sr->fid_ofile = of;

	smb_node_unlock(node);

	if (created)
		smb_node_unlock(dnode);

	if (op->fqi.last_attr.sa_vattr.va_type == VREG) {
		smb_oplock_acquire(node, of, op);
		op->dsize = op->fqi.last_attr.sa_vattr.va_size;
	} else { /* VDIR or VLNK */
		op->op_oplock_level = SMB_OPLOCK_NONE;
		op->dsize = 0;
	}

	smb_node_release(dnode);
	SMB_NULL_FQI_NODES(op->fqi);

	return (NT_STATUS_SUCCESS);
}

/*
 * smb_validate_object_name
 *
 * Very basic file name validation.
 * Directory validation is handed off to smb_validate_dirname.
 * For filenames, we check for names of the form "AAAn:". Names that
 * contain three characters, a single digit and a colon (:) are reserved
 * as DOS device names, i.e. "COM1:".
 * Stream name validation is handed off to smb_validate_stream_name
 *
 * Returns NT status codes.
 */
uint32_t
smb_validate_object_name(char *path, unsigned int ftype)
{
	char *filename;

	if (path == 0)
		return (0);

	if (ftype)
		return (smb_validate_dirname(path));

	/*
	 * Basename with backslashes.
	 */
	if ((filename = strrchr(path, '\\')) != 0)
		++filename;
	else
		filename = path;

	if (strlen(filename) == 5 &&
	    mts_isdigit(filename[3]) &&
	    filename[4] == ':') {
		return (NT_STATUS_OBJECT_NAME_INVALID);
	}

	if (smb_is_stream_name(path))
		return (smb_validate_stream_name(path));

	return (0);
}

/*
 * smb_preset_delete_on_close
 *
 * Set the DeleteOnClose flag on the smb file. When the file is closed,
 * the flag will be transferred to the smb node, which will commit the
 * delete operation and inhibit subsequent open requests.
 *
 * When DeleteOnClose is set on an smb_node, the common open code will
 * reject subsequent open requests for the file. Observation of Windows
 * 2000 indicates that subsequent opens should be allowed (assuming
 * there would be no sharing violation) until the file is closed using
 * the fid on which the DeleteOnClose was requested.
 */
void
smb_preset_delete_on_close(smb_ofile_t *file)
{
	mutex_enter(&file->f_mutex);
	file->f_flags |= SMB_OFLAGS_SET_DELETE_ON_CLOSE;
	mutex_exit(&file->f_mutex);
}
