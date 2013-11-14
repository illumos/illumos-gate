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

/*
 * This module provides the common open functionality to the various
 * open and create SMB interface functions.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/fcntl.h>
#include <sys/nbmlock.h>
#include <smbsrv/string.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smbinfo.h>

volatile uint32_t smb_fids = 0;

static uint32_t smb_open_subr(smb_request_t *);
extern uint32_t smb_is_executable(char *);
static void smb_delete_new_object(smb_request_t *);
static int smb_set_open_attributes(smb_request_t *, smb_ofile_t *);
static void smb_open_oplock_break(smb_request_t *, smb_node_t *);
static boolean_t smb_open_attr_only(smb_arg_open_t *);
static boolean_t smb_open_overwrite(smb_arg_open_t *);

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
 *
 * Careful, we have to emulate some Windows behavior here.
 * When requested access == zero, you get READ_CONTROL.
 * MacOS 10.7 depends on this.
 */
uint32_t
smb_access_generic_to_file(uint32_t desired_access)
{
	uint32_t access = READ_CONTROL;

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
	smb_arg_open_t	*parg;
	uint32_t	status = NT_STATUS_SUCCESS;
	int		count;

	parg = kmem_alloc(sizeof (*parg), KM_SLEEP);
	bcopy(&sr->arg.open, parg, sizeof (*parg));

	for (count = 0; count <= 4; count++) {
		if (count != 0)
			delay(MSEC_TO_TICK(400));

		status = smb_open_subr(sr);
		if (status != NT_STATUS_SHARING_VIOLATION)
			break;

		bcopy(parg, &sr->arg.open, sizeof (*parg));
	}

	if (status == NT_STATUS_SHARING_VIOLATION) {
		smbsr_error(sr, NT_STATUS_SHARING_VIOLATION,
		    ERRDOS, ERROR_SHARING_VIOLATION);
	}

	if (status == NT_STATUS_NO_SUCH_FILE) {
		smbsr_error(sr, NT_STATUS_OBJECT_NAME_NOT_FOUND,
		    ERRDOS, ERROR_FILE_NOT_FOUND);
	}

	kmem_free(parg, sizeof (*parg));
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
 * - Oplocks must be broken prior to share checking as the break may
 *   cause other clients to close the file, which would affect sharing
 *   checks.
 *
 * - Share checks must take place prior to access checks for correct
 * Windows semantics and to prevent unnecessary NFS delegation recalls.
 *
 * - Oplocks must be acquired after open to ensure the correct
 * synchronization with NFS delegation and FEM installation.
 *
 * DOS readonly bit rules
 *
 * 1. The creator of a readonly file can write to/modify the size of the file
 * using the original create fid, even though the file will appear as readonly
 * to all other fids and via a CIFS getattr call.
 * The readonly bit therefore cannot be set in the filesystem until the file
 * is closed (smb_ofile_close). It is accounted for via ofile and node flags.
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
	boolean_t	created = B_FALSE;
	boolean_t	last_comp_found = B_FALSE;
	smb_node_t	*node = NULL;
	smb_node_t	*dnode = NULL;
	smb_node_t	*cur_node = NULL;
	smb_arg_open_t	*op = &sr->sr_open;
	int		rc;
	smb_ofile_t	*of;
	smb_attr_t	new_attr;
	int		max_requested = 0;
	uint32_t	max_allowed;
	uint32_t	status = NT_STATUS_SUCCESS;
	int		is_dir;
	smb_error_t	err;
	boolean_t	is_stream = B_FALSE;
	int		lookup_flags = SMB_FOLLOW_LINKS;
	uint32_t	uniq_fid;
	smb_pathname_t	*pn = &op->fqi.fq_path;
	smb_server_t	*sv = sr->sr_server;

	is_dir = (op->create_options & FILE_DIRECTORY_FILE) ? 1 : 0;

	/*
	 * If the object being created or opened is a directory
	 * the Disposition parameter must be one of FILE_CREATE,
	 * FILE_OPEN, or FILE_OPEN_IF
	 */
	if (is_dir) {
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
		cmn_err(CE_NOTE, "smbsrv[%s\\%s]: TOO_MANY_OPENED_FILES",
		    sr->uid_user->u_domain, sr->uid_user->u_name);

		smbsr_error(sr, NT_STATUS_TOO_MANY_OPENED_FILES,
		    ERRDOS, ERROR_TOO_MANY_OPEN_FILES);
		return (NT_STATUS_TOO_MANY_OPENED_FILES);
	}

	/* This must be NULL at this point */
	sr->fid_ofile = NULL;

	op->devstate = 0;

	switch (sr->tid_tree->t_res_type & STYPE_MASK) {
	case STYPE_DISKTREE:
	case STYPE_PRINTQ:
		break;

	case STYPE_IPC:

		if ((rc = smb_threshold_enter(&sv->sv_opipe_ct)) != 0) {
			status = RPC_NT_SERVER_TOO_BUSY;
			smbsr_error(sr, status, 0, 0);
			return (status);
		}

		/*
		 * No further processing for IPC, we need to either
		 * raise an exception or return success here.
		 */
		if ((status = smb_opipe_open(sr)) != NT_STATUS_SUCCESS)
			smbsr_error(sr, status, 0, 0);

		smb_threshold_exit(&sv->sv_opipe_ct);
		return (status);

	default:
		smbsr_error(sr, NT_STATUS_BAD_DEVICE_TYPE,
		    ERRDOS, ERROR_BAD_DEV_TYPE);
		return (NT_STATUS_BAD_DEVICE_TYPE);
	}

	smb_pathname_init(sr, pn, pn->pn_path);
	if (!smb_pathname_validate(sr, pn))
		return (sr->smb_error.status);

	if (strlen(pn->pn_path) >= MAXPATHLEN) {
		smbsr_error(sr, 0, ERRSRV, ERRfilespecs);
		return (NT_STATUS_NAME_TOO_LONG);
	}

	if (is_dir) {
		if (!smb_validate_dirname(sr, pn))
			return (sr->smb_error.status);
	} else {
		if (!smb_validate_object_name(sr, pn))
			return (sr->smb_error.status);
	}

	cur_node = op->fqi.fq_dnode ?
	    op->fqi.fq_dnode : sr->tid_tree->t_snode;

	/*
	 * if no path or filename are specified the stream should be
	 * created on cur_node
	 */
	if (!is_dir && !pn->pn_pname && !pn->pn_fname && pn->pn_sname) {
		/*
		 * Can't currently handle a stream on the tree root.
		 * If a stream is being opened return "not found", otherwise
		 * return "access denied".
		 */
		if (cur_node == sr->tid_tree->t_snode) {
			if (op->create_disposition == FILE_OPEN) {
				smbsr_error(sr, NT_STATUS_OBJECT_NAME_NOT_FOUND,
				    ERRDOS, ERROR_FILE_NOT_FOUND);
				return (NT_STATUS_OBJECT_NAME_NOT_FOUND);
			}
			smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS,
			    ERROR_ACCESS_DENIED);
			return (NT_STATUS_ACCESS_DENIED);
		}

		(void) snprintf(op->fqi.fq_last_comp,
		    sizeof (op->fqi.fq_last_comp),
		    "%s%s", cur_node->od_name, pn->pn_sname);

		op->fqi.fq_dnode = cur_node->n_dnode;
		smb_node_ref(op->fqi.fq_dnode);
	} else {
		if (rc = smb_pathname_reduce(sr, sr->user_cr, pn->pn_path,
		    sr->tid_tree->t_snode, cur_node, &op->fqi.fq_dnode,
		    op->fqi.fq_last_comp)) {
			smbsr_errno(sr, rc);
			return (sr->smb_error.status);
		}
	}

	/*
	 * If the access mask has only DELETE set (ignore
	 * FILE_READ_ATTRIBUTES), then assume that this
	 * is a request to delete the link (if a link)
	 * and do not follow links.  Otherwise, follow
	 * the link to the target.
	 */
	if ((op->desired_access & ~FILE_READ_ATTRIBUTES) == DELETE)
		lookup_flags &= ~SMB_FOLLOW_LINKS;

	rc = smb_fsop_lookup_name(sr, zone_kcred(), lookup_flags,
	    sr->tid_tree->t_snode, op->fqi.fq_dnode, op->fqi.fq_last_comp,
	    &op->fqi.fq_fnode);

	if (rc == 0) {
		last_comp_found = B_TRUE;
		/*
		 * Need the DOS attributes below, where we
		 * check the search attributes (sattr).
		 */
		op->fqi.fq_fattr.sa_mask = SMB_AT_DOSATTR;
		rc = smb_node_getattr(sr, op->fqi.fq_fnode, zone_kcred(),
		    NULL, &op->fqi.fq_fattr);
		if (rc != 0) {
			smb_node_release(op->fqi.fq_fnode);
			smb_node_release(op->fqi.fq_dnode);
			smbsr_error(sr, NT_STATUS_INTERNAL_ERROR,
			    ERRDOS, ERROR_INTERNAL_ERROR);
			return (sr->smb_error.status);
		}
	} else if (rc == ENOENT) {
		last_comp_found = B_FALSE;
		op->fqi.fq_fnode = NULL;
		rc = 0;
	} else {
		smb_node_release(op->fqi.fq_dnode);
		smbsr_errno(sr, rc);
		return (sr->smb_error.status);
	}


	/*
	 * The uniq_fid is a CIFS-server-wide unique identifier for an ofile
	 * which is used to uniquely identify open instances for the
	 * VFS share reservation and POSIX locks.
	 */

	uniq_fid = SMB_UNIQ_FID();

	if (last_comp_found) {

		node = op->fqi.fq_fnode;
		dnode = op->fqi.fq_dnode;

		if (!smb_node_is_file(node) && !smb_node_is_dir(node) &&
		    !smb_node_is_symlink(node)) {
			smb_node_release(node);
			smb_node_release(dnode);
			smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS,
			    ERRnoaccess);
			return (NT_STATUS_ACCESS_DENIED);
		}

		/*
		 * Reject this request if either:
		 * - the target IS a directory and the client requires that
		 *   it must NOT be (required by Lotus Notes)
		 * - the target is NOT a directory and client requires that
		 *   it MUST be.
		 */
		if (smb_node_is_dir(node)) {
			if (op->create_options & FILE_NON_DIRECTORY_FILE) {
				smb_node_release(node);
				smb_node_release(dnode);
				smbsr_error(sr, NT_STATUS_FILE_IS_A_DIRECTORY,
				    ERRDOS, ERROR_ACCESS_DENIED);
				return (NT_STATUS_FILE_IS_A_DIRECTORY);
			}
		} else {
			if ((op->create_options & FILE_DIRECTORY_FILE) ||
			    (op->nt_flags & NT_CREATE_FLAG_OPEN_TARGET_DIR)) {
				smb_node_release(node);
				smb_node_release(dnode);
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
			if (!smb_node_is_dir(node)) {
				if (op->desired_access & (FILE_WRITE_DATA |
				    FILE_APPEND_DATA)) {
					smb_node_release(node);
					smb_node_release(dnode);
					smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
					    ERRDOS, ERRnoaccess);
					return (NT_STATUS_ACCESS_DENIED);
				}
			}
		}

		/*
		 * Oplock break is done prior to sharing checks as the break
		 * may cause other clients to close the file which would
		 * affect the sharing checks.
		 */
		smb_node_inc_opening_count(node);
		smb_open_oplock_break(sr, node);

		smb_node_wrlock(node);

		if ((op->create_disposition == FILE_SUPERSEDE) ||
		    (op->create_disposition == FILE_OVERWRITE_IF) ||
		    (op->create_disposition == FILE_OVERWRITE)) {

			if ((!(op->desired_access &
			    (FILE_WRITE_DATA | FILE_APPEND_DATA |
			    FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA))) ||
			    (!smb_sattr_check(op->fqi.fq_fattr.sa_dosattr,
			    op->dattr))) {
				smb_node_unlock(node);
				smb_node_dec_opening_count(node);
				smb_node_release(node);
				smb_node_release(dnode);
				smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
				    ERRDOS, ERRnoaccess);
				return (NT_STATUS_ACCESS_DENIED);
			}
		}

		status = smb_fsop_shrlock(sr->user_cr, node, uniq_fid,
		    op->desired_access, op->share_access);

		if (status == NT_STATUS_SHARING_VIOLATION) {
			smb_node_unlock(node);
			smb_node_dec_opening_count(node);
			smb_node_release(node);
			smb_node_release(dnode);
			return (status);
		}

		status = smb_fsop_access(sr, sr->user_cr, node,
		    op->desired_access);

		if (status != NT_STATUS_SUCCESS) {
			smb_fsop_unshrlock(sr->user_cr, node, uniq_fid);

			smb_node_unlock(node);
			smb_node_dec_opening_count(node);
			smb_node_release(node);
			smb_node_release(dnode);

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
			if (smb_node_is_dir(node)) {
				smb_fsop_unshrlock(sr->user_cr, node, uniq_fid);
				smb_node_unlock(node);
				smb_node_dec_opening_count(node);
				smb_node_release(node);
				smb_node_release(dnode);
				smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
				    ERRDOS, ERROR_ACCESS_DENIED);
				return (NT_STATUS_ACCESS_DENIED);
			}

			op->dattr |= FILE_ATTRIBUTE_ARCHIVE;
			/* Don't apply readonly bit until smb_ofile_close */
			if (op->dattr & FILE_ATTRIBUTE_READONLY) {
				op->created_readonly = B_TRUE;
				op->dattr &= ~FILE_ATTRIBUTE_READONLY;
			}

			bzero(&new_attr, sizeof (new_attr));
			new_attr.sa_dosattr = op->dattr;
			new_attr.sa_vattr.va_size = op->dsize;
			new_attr.sa_mask = SMB_AT_DOSATTR | SMB_AT_SIZE;
			rc = smb_fsop_setattr(sr, sr->user_cr, node, &new_attr);
			if (rc != 0) {
				smb_fsop_unshrlock(sr->user_cr, node, uniq_fid);
				smb_node_unlock(node);
				smb_node_dec_opening_count(node);
				smb_node_release(node);
				smb_node_release(dnode);
				smbsr_errno(sr, rc);
				return (sr->smb_error.status);
			}

			/*
			 * If file is being replaced, remove existing streams
			 */
			if (SMB_IS_STREAM(node) == 0) {
				rc = smb_fsop_remove_streams(sr, sr->user_cr,
				    node);
				if (rc != 0) {
					smb_fsop_unshrlock(sr->user_cr, node,
					    uniq_fid);
					smb_node_unlock(node);
					smb_node_dec_opening_count(node);
					smb_node_release(node);
					smb_node_release(dnode);
					return (sr->smb_error.status);
				}
			}

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
		dnode = op->fqi.fq_dnode;

		if (is_dir == 0)
			is_stream = smb_is_stream_name(pn->pn_path);

		if ((op->create_disposition == FILE_OPEN) ||
		    (op->create_disposition == FILE_OVERWRITE)) {
			smb_node_release(dnode);
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_NOT_FOUND,
			    ERRDOS, ERROR_FILE_NOT_FOUND);
			return (NT_STATUS_OBJECT_NAME_NOT_FOUND);
		}

		if (pn->pn_fname && smb_is_invalid_filename(pn->pn_fname)) {
			smb_node_release(dnode);
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_INVALID,
			    ERRDOS, ERROR_INVALID_NAME);
			return (NT_STATUS_OBJECT_NAME_INVALID);
		}

		/*
		 * lock the parent dir node in case another create
		 * request to the same parent directory comes in.
		 */
		smb_node_wrlock(dnode);

		/* Don't apply readonly bit until smb_ofile_close */
		if (op->dattr & FILE_ATTRIBUTE_READONLY) {
			op->dattr &= ~FILE_ATTRIBUTE_READONLY;
			op->created_readonly = B_TRUE;
		}

		bzero(&new_attr, sizeof (new_attr));
		if ((op->crtime.tv_sec != 0) &&
		    (op->crtime.tv_sec != UINT_MAX)) {

			new_attr.sa_mask |= SMB_AT_CRTIME;
			new_attr.sa_crtime = op->crtime;
		}

		if (is_dir == 0) {
			op->dattr |= FILE_ATTRIBUTE_ARCHIVE;
			new_attr.sa_dosattr = op->dattr;
			new_attr.sa_vattr.va_type = VREG;
			new_attr.sa_vattr.va_mode = is_stream ? S_IRUSR :
			    S_IRUSR | S_IRGRP | S_IROTH |
			    S_IWUSR | S_IWGRP | S_IWOTH;
			new_attr.sa_mask |=
			    SMB_AT_DOSATTR | SMB_AT_TYPE | SMB_AT_MODE;

			if (op->dsize) {
				new_attr.sa_vattr.va_size = op->dsize;
				new_attr.sa_mask |= SMB_AT_SIZE;
			}

			rc = smb_fsop_create(sr, sr->user_cr, dnode,
			    op->fqi.fq_last_comp, &new_attr, &op->fqi.fq_fnode);

			if (rc != 0) {
				smb_node_unlock(dnode);
				smb_node_release(dnode);
				smbsr_errno(sr, rc);
				return (sr->smb_error.status);
			}

			node = op->fqi.fq_fnode;
			smb_node_inc_opening_count(node);
			smb_node_wrlock(node);

			status = smb_fsop_shrlock(sr->user_cr, node, uniq_fid,
			    op->desired_access, op->share_access);

			if (status == NT_STATUS_SHARING_VIOLATION) {
				smb_node_unlock(node);
				smb_node_dec_opening_count(node);
				smb_delete_new_object(sr);
				smb_node_release(node);
				smb_node_unlock(dnode);
				smb_node_release(dnode);
				return (status);
			}
		} else {
			op->dattr |= FILE_ATTRIBUTE_DIRECTORY;
			new_attr.sa_dosattr = op->dattr;
			new_attr.sa_vattr.va_type = VDIR;
			new_attr.sa_vattr.va_mode = 0777;
			new_attr.sa_mask |=
			    SMB_AT_DOSATTR | SMB_AT_TYPE | SMB_AT_MODE;

			rc = smb_fsop_mkdir(sr, sr->user_cr, dnode,
			    op->fqi.fq_last_comp, &new_attr, &op->fqi.fq_fnode);
			if (rc != 0) {
				smb_node_unlock(dnode);
				smb_node_release(dnode);
				smbsr_errno(sr, rc);
				return (sr->smb_error.status);
			}

			node = op->fqi.fq_fnode;
			smb_node_inc_opening_count(node);
			smb_node_wrlock(node);
		}

		created = B_TRUE;
		op->action_taken = SMB_OACT_CREATED;
	}

	if (max_requested) {
		smb_fsop_eaccess(sr, sr->user_cr, node, &max_allowed);
		op->desired_access |= max_allowed;
	}

	status = NT_STATUS_SUCCESS;

	of = smb_ofile_open(sr, node, sr->smb_pid, op, SMB_FTYPE_DISK, uniq_fid,
	    &err);
	if (of == NULL) {
		smbsr_error(sr, err.status, err.errcls, err.errcode);
		status = err.status;
	}

	if (status == NT_STATUS_SUCCESS) {
		if (!smb_tree_is_connected(sr->tid_tree)) {
			smbsr_error(sr, 0, ERRSRV, ERRinvnid);
			status = NT_STATUS_UNSUCCESSFUL;
		}
	}

	/*
	 * This MUST be done after ofile creation, so that explicitly
	 * set timestamps can be remembered on the ofile, and the
	 * readonly flag will be stored "pending" on the node.
	 */
	if (status == NT_STATUS_SUCCESS) {
		if ((rc = smb_set_open_attributes(sr, of)) != 0) {
			smbsr_errno(sr, rc);
			status = sr->smb_error.status;
		}
	}

	if (status == NT_STATUS_SUCCESS) {
		/*
		 * We've already done access checks above,
		 * and want this call to succeed even when
		 * !(desired_access & FILE_READ_ATTRIBUTES),
		 * so pass kcred here.
		 */
		op->fqi.fq_fattr.sa_mask = SMB_AT_ALL;
		rc = smb_node_getattr(sr, node, zone_kcred(), of,
		    &op->fqi.fq_fattr);
		if (rc != 0) {
			smbsr_error(sr, NT_STATUS_INTERNAL_ERROR,
			    ERRDOS, ERROR_INTERNAL_ERROR);
			status = NT_STATUS_INTERNAL_ERROR;
		}
	}

	/*
	 * smb_fsop_unshrlock is a no-op if node is a directory
	 * smb_fsop_unshrlock is done in smb_ofile_close
	 */
	if (status != NT_STATUS_SUCCESS) {
		if (of == NULL) {
			smb_fsop_unshrlock(sr->user_cr, node, uniq_fid);
		} else {
			smb_ofile_close(of, 0);
			smb_ofile_release(of);
		}
		if (created)
			smb_delete_new_object(sr);
		smb_node_unlock(node);
		smb_node_dec_opening_count(node);
		smb_node_release(node);
		if (created)
			smb_node_unlock(dnode);
		smb_node_release(dnode);
		return (status);
	}

	/*
	 * Propagate the write-through mode from the open params
	 * to the node: see the notes in the function header.
	 */
	if (sr->sr_cfg->skc_sync_enable ||
	    (op->create_options & FILE_WRITE_THROUGH))
		node->flags |= NODE_FLAGS_WRITE_THROUGH;

	/*
	 * Set up the fileid and dosattr in open_param for response
	 */
	op->fileid = op->fqi.fq_fattr.sa_vattr.va_nodeid;
	op->dattr = op->fqi.fq_fattr.sa_dosattr;

	/*
	 * Set up the file type in open_param for the response
	 */
	op->ftype = SMB_FTYPE_DISK;
	sr->smb_fid = of->f_fid;
	sr->fid_ofile = of;

	if (smb_node_is_file(node)) {
		smb_oplock_acquire(sr, node, of);
		op->dsize = op->fqi.fq_fattr.sa_vattr.va_size;
	} else {
		/* directory or symlink */
		op->op_oplock_level = SMB_OPLOCK_NONE;
		op->dsize = 0;
	}

	smb_node_dec_opening_count(node);

	smb_node_unlock(node);
	if (created)
		smb_node_unlock(dnode);

	smb_node_release(node);
	smb_node_release(dnode);

	return (NT_STATUS_SUCCESS);
}

/*
 * smb_open_oplock_break
 *
 * If the node has an ofile opened with share access none,
 * (smb_node_share_check = FALSE) only break BATCH oplock.
 * Otherwise:
 * If overwriting, break to SMB_OPLOCK_NONE, else
 * If opening for anything other than attribute access,
 * break oplock to LEVEL_II.
 */
static void
smb_open_oplock_break(smb_request_t *sr, smb_node_t *node)
{
	smb_arg_open_t	*op = &sr->sr_open;
	uint32_t	flags = 0;

	if (!smb_node_share_check(node))
		flags |= SMB_OPLOCK_BREAK_BATCH;

	if (smb_open_overwrite(op)) {
		flags |= SMB_OPLOCK_BREAK_TO_NONE;
		(void) smb_oplock_break(sr, node, flags);
	} else if (!smb_open_attr_only(op)) {
		flags |= SMB_OPLOCK_BREAK_TO_LEVEL_II;
		(void) smb_oplock_break(sr, node, flags);
	}
}

/*
 * smb_open_attr_only
 *
 * Determine if file is being opened for attribute access only.
 * This is used to determine whether it is necessary to break
 * existing oplocks on the file.
 */
static boolean_t
smb_open_attr_only(smb_arg_open_t *op)
{
	if (((op->desired_access & ~(FILE_READ_ATTRIBUTES |
	    FILE_WRITE_ATTRIBUTES | SYNCHRONIZE)) == 0) &&
	    (op->create_disposition != FILE_SUPERSEDE) &&
	    (op->create_disposition != FILE_OVERWRITE)) {
		return (B_TRUE);
	}
	return (B_FALSE);
}

static boolean_t
smb_open_overwrite(smb_arg_open_t *op)
{
	if ((op->create_disposition == FILE_SUPERSEDE) ||
	    (op->create_disposition == FILE_OVERWRITE_IF) ||
	    (op->create_disposition == FILE_OVERWRITE)) {
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * smb_set_open_attributes
 *
 * Last write time:
 * - If the last_write time specified in the open params is not 0 or -1,
 *   use it as file's mtime. This will be considered an explicitly set
 *   timestamps, not reset by subsequent writes.
 *
 * DOS attributes
 * - If we created_readonly, we now store the real DOS attributes
 *   (including the readonly bit) so subsequent opens will see it.
 *
 * Both are stored "pending" rather than in the file system.
 *
 * Returns: errno
 */
static int
smb_set_open_attributes(smb_request_t *sr, smb_ofile_t *of)
{
	smb_attr_t	attr;
	smb_arg_open_t	*op = &sr->sr_open;
	smb_node_t	*node = of->f_node;
	int		rc = 0;

	bzero(&attr, sizeof (smb_attr_t));

	if (op->created_readonly) {
		attr.sa_dosattr = op->dattr | FILE_ATTRIBUTE_READONLY;
		attr.sa_mask |= SMB_AT_DOSATTR;
	}

	if ((op->mtime.tv_sec != 0) && (op->mtime.tv_sec != UINT_MAX)) {
		attr.sa_vattr.va_mtime = op->mtime;
		attr.sa_mask |= SMB_AT_MTIME;
	}

	/*
	 * Used to have code here to set mtime, ctime, atime
	 * when the open op->create_disposition is any of:
	 * FILE_SUPERSEDE, FILE_OVERWRITE_IF, FILE_OVERWRITE.
	 * We know that in those cases we will have set the
	 * file size, in which case the file system will
	 * update those times, so we don't have to.
	 *
	 * However, keep track of the fact that we modified
	 * the file via this handle, so we can do the evil,
	 * gratuitious mtime update on close that Windows
	 * clients appear to expect.
	 */
	if (op->action_taken == SMB_OACT_TRUNCATED)
		of->f_written = B_TRUE;

	if (attr.sa_mask != 0)
		rc = smb_node_setattr(sr, node, of->f_cr, of, &attr);

	return (rc);
}

/*
 * This function is used to delete a newly created object (file or
 * directory) if an error occurs after creation of the object.
 */
static void
smb_delete_new_object(smb_request_t *sr)
{
	smb_arg_open_t	*op = &sr->sr_open;
	smb_fqi_t	*fqi = &(op->fqi);
	uint32_t	flags = 0;

	if (SMB_TREE_IS_CASEINSENSITIVE(sr))
		flags |= SMB_IGNORE_CASE;
	if (SMB_TREE_SUPPORTS_CATIA(sr))
		flags |= SMB_CATIA;

	if (op->create_options & FILE_DIRECTORY_FILE)
		(void) smb_fsop_rmdir(sr, sr->user_cr, fqi->fq_dnode,
		    fqi->fq_last_comp, flags);
	else
		(void) smb_fsop_remove(sr, sr->user_cr, fqi->fq_dnode,
		    fqi->fq_last_comp, flags);
}
