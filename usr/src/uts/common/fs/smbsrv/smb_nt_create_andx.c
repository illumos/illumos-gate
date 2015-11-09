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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * This command is used to create or open a file or directory.
 */


#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smb_vops.h>

/*
 * smb_com_nt_create_andx
 *
 * This command is used to create or open a file or directory.
 *
 *  Client Request                     Description
 *  =================================  ==================================
 *
 *  UCHAR WordCount;                   Count of parameter words = 24
 *  UCHAR AndXCommand;                 Secondary command;  0xFF = None
 *  UCHAR AndXReserved;                Reserved (must be 0)
 *  USHORT AndXOffset;                 Offset to next command WordCount
 *  UCHAR Reserved;                    Reserved (must be 0)
 *  USHORT NameLength;                 Length of Name[] in bytes
 *  ULONG Flags;                       Create bit set:
 *                                     0x02 - Request an oplock
 *                                     0x04 - Request a batch oplock
 *                                     0x08 - Target of open must be
 *                                     directory
 *  ULONG RootDirectoryFid;            If non-zero, open is relative to
 *                                     this directory
 *  ACCESS_MASK DesiredAccess;         access desired
 *  LARGE_INTEGER AllocationSize;      Initial allocation size
 *  ULONG ExtFileAttributes;           File attributes
 *  ULONG ShareAccess;                 Type of share access
 *  ULONG CreateDisposition;           Action to take if file exists or
 *                                     not
 *  ULONG CreateOptions;               Options to use if creating a file
 *  ULONG ImpersonationLevel;          Security QOS information
 *  UCHAR SecurityFlags;               Security tracking mode flags:
 *                                     0x1 - SECURITY_CONTEXT_TRACKING
 *                                     0x2 - SECURITY_EFFECTIVE_ONLY
 *  USHORT ByteCount;                  Length of byte parameters
 *  STRING Name[];                     File to open or create
 *
 * The DesiredAccess parameter is specified in section 3.7 on  Access Mask
 * Encoding.
 *
 * If no value is specified, it still allows an application to query
 * attributes without actually accessing the file.
 *
 * The ExtFIleAttributes parameter specifies the file attributes and flags
 * for the file. The parameter's value is the sum of allowed attributes and
 * flags defined in section 3.11 on  Extended File Attribute Encoding
 *
 * The ShareAccess field Specifies how this file can be shared. This
 * parameter must be some combination of the following values:
 *
 * Name              Value      Meaning
 *                   0          Prevents the file from being shared.
 * FILE_SHARE_READ   0x00000001 Other open operations can be performed on
 *                               the file for read access.
 * FILE_SHARE_WRITE  0x00000002 Other open operations can be performed on
 *                               the file for write access.
 * FILE_SHARE_DELETE 0x00000004 Other open operations can be performed on
 *                               the file for delete access.
 *
 * The CreateDisposition parameter can contain one of the following values:
 *
 * CREATE_NEW        Creates a new file. The function fails if the
 *                   specified file already exists.
 * CREATE_ALWAYS     Creates a new file. The function overwrites the file
 *                   if it exists.
 * OPEN_EXISTING     Opens the file. The function fails if the file does
 *                   not exist.
 * OPEN_ALWAYS       Opens the file, if it exists. If the file does not
 *                   exist, act like CREATE_NEW.
 * TRUNCATE_EXISTING Opens the file. Once opened, the file is truncated so
 *                   that its size is zero bytes. The calling process must
 *                   open the file with at least GENERIC_WRITE access. The
 *                   function fails if the file does not exist.
 *
 * The ImpersonationLevel parameter can contain one or more of the
 * following values:
 *
 * SECURITY_ANONYMOUS        Specifies to impersonate the client at the
 *                           Anonymous impersonation level.
 * SECURITY_IDENTIFICATION   Specifies to impersonate the client at the
 *                           Identification impersonation level.
 * SECURITY_IMPERSONATION    Specifies to impersonate the client at the
 *                           Impersonation impersonation level.
 * SECURITY_DELEGATION       Specifies to impersonate the client at the
 *                           Delegation impersonation level.
 *
 * The SecurityFlags parameter can have either of the following two flags
 * set:
 *
 * SECURITY_CONTEXT_TRACKING  Specifies that the security tracking mode is
 *                            dynamic. If this flag is not specified,
 *                            Security Tracking Mode is static.
 * SECURITY_EFFECTIVE_ONLY    Specifies that only the enabled aspects of
 *                            the client's security context are available
 *                            to the server. If you do not specify this
 *                            flag, all aspects of the client's security
 *                            context are available. This flag allows the
 *                            client to limit the groups and privileges
 *                            that a server can use while impersonating the
 *                            client.
 *
 * The response is as follows:
 *
 *  Server Response                    Description
 *  =================================  ==================================
 *
 *  UCHAR WordCount;                   Count of parameter words = 26
 *  UCHAR AndXCommand;  Secondary      0xFF = None
 *  command;
 *  UCHAR AndXReserved;                MBZ
 *  USHORT AndXOffset;                 Offset to next command WordCount
 *  UCHAR OplockLevel;                 The oplock level granted
 *                                     0 - No oplock granted
 *                                     1 - Exclusive oplock granted
 *                                     2 - Batch oplock granted
 *                                     3 - Level II oplock granted
 *  USHORT Fid;                        The file ID
 *  ULONG CreateAction;                The action taken
 *  TIME CreationTime;                 The time the file was created
 *  TIME LastAccessTime;               The time the file was accessed
 *  TIME LastWriteTime;                The time the file was last written
 *  TIME ChangeTime;                   The time the file was last changed
 *  ULONG ExtFileAttributes;           The file attributes
 *  LARGE_INTEGER AllocationSize;      The number of bytes allocated
 *  LARGE_INTEGER EndOfFile;           The end of file offset
 *  USHORT FileType;
 *  USHORT DeviceState;                state of IPC device (e.g. pipe)
 *  BOOLEAN Directory;                 TRUE if this is a directory
 *  USHORT ByteCount;                  = 0
 *
 * The following SMBs may follow SMB_COM_NT_CREATE_ANDX:
 *
 *    SMB_COM_READ    SMB_COM_READ_ANDX
 *    SMB_COM_IOCTL
 */
smb_sdrc_t
smb_pre_nt_create_andx(smb_request_t *sr)
{
	struct open_param *op = &sr->arg.open;
	uint8_t SecurityFlags;
	uint32_t ImpersonationLevel;
	uint16_t NameLength;
	int rc;

	bzero(op, sizeof (sr->arg.open));

	rc = smbsr_decode_vwv(sr, "5.wlllqlllllb",
	    &NameLength,
	    &op->nt_flags,
	    &op->rootdirfid,
	    &op->desired_access,
	    &op->dsize,
	    &op->dattr,
	    &op->share_access,
	    &op->create_disposition,
	    &op->create_options,
	    &ImpersonationLevel,
	    &SecurityFlags);

	if (rc == 0) {
		if (NameLength == 0) {
			op->fqi.fq_path.pn_path = "\\";
		} else if (NameLength >= SMB_MAXPATHLEN) {
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_INVALID,
			    ERRDOS, ERROR_PATH_NOT_FOUND);
			rc = -1;
		} else {
			rc = smbsr_decode_data(sr, "%#u", sr, NameLength,
			    &op->fqi.fq_path.pn_path);
		}
	}

	op->op_oplock_level = SMB_OPLOCK_NONE;
	if (op->nt_flags & NT_CREATE_FLAG_REQUEST_OPLOCK) {
		if (op->nt_flags & NT_CREATE_FLAG_REQUEST_OPBATCH)
			op->op_oplock_level = SMB_OPLOCK_BATCH;
		else
			op->op_oplock_level = SMB_OPLOCK_EXCLUSIVE;
	}

	DTRACE_SMB_2(op__NtCreateX__start, smb_request_t *, sr,
	    struct open_param *, op);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_nt_create_andx(smb_request_t *sr)
{
	DTRACE_SMB_1(op__NtCreateX__done, smb_request_t *, sr);

	if (sr->arg.open.dir != NULL) {
		smb_ofile_release(sr->arg.open.dir);
		sr->arg.open.dir = NULL;
	}
}

smb_sdrc_t
smb_com_nt_create_andx(struct smb_request *sr)
{
	struct open_param	*op = &sr->arg.open;
	smb_attr_t		*ap = &op->fqi.fq_fattr;
	smb_ofile_t		*of;
	int			rc;
	unsigned char		DirFlag;
	uint32_t		status;

	if ((op->create_options & FILE_DELETE_ON_CLOSE) &&
	    !(op->desired_access & DELETE)) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERRbadaccess);
		return (SDRC_ERROR);
	}

	if (op->create_disposition > FILE_MAXIMUM_DISPOSITION) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERRbadaccess);
		return (SDRC_ERROR);
	}

	if (op->dattr & FILE_FLAG_WRITE_THROUGH)
		op->create_options |= FILE_WRITE_THROUGH;

	if (op->dattr & FILE_FLAG_DELETE_ON_CLOSE)
		op->create_options |= FILE_DELETE_ON_CLOSE;

	if (op->dattr & FILE_FLAG_BACKUP_SEMANTICS)
		op->create_options |= FILE_OPEN_FOR_BACKUP_INTENT;

	if (op->create_options & FILE_OPEN_FOR_BACKUP_INTENT)
		sr->user_cr = smb_user_getprivcred(sr->uid_user);

	if (op->rootdirfid == 0) {
		op->fqi.fq_dnode = sr->tid_tree->t_snode;
	} else {
		op->dir = smb_ofile_lookup_by_fid(sr, (uint16_t)op->rootdirfid);
		if (op->dir == NULL) {
			smbsr_error(sr, NT_STATUS_INVALID_HANDLE,
			    ERRDOS, ERRbadfid);
			return (SDRC_ERROR);
		}
		op->fqi.fq_dnode = op->dir->f_node;
	}

	op->op_oplock_levelII = B_TRUE;

	status = smb_common_open(sr);
	if (status != NT_STATUS_SUCCESS) {
		smbsr_status(sr, status, 0, 0);
		return (SDRC_ERROR);
	}

	/*
	 * NB: after the above smb_common_open() success,
	 * we have a handle allocated (sr->fid_ofile).
	 * If we don't return success, we must close it.
	 */
	of = sr->fid_ofile;

	switch (sr->tid_tree->t_res_type & STYPE_MASK) {
	case STYPE_DISKTREE:
	case STYPE_PRINTQ:
		if (op->create_options & FILE_DELETE_ON_CLOSE)
			smb_ofile_set_delete_on_close(of);

		DirFlag = smb_node_is_dir(of->f_node) ? 1 : 0;
		rc = smbsr_encode_result(sr, 34, 0, "bb.wbwlTTTTlqqwwbw",
		    34,
		    sr->andx_com,
		    0x67,
		    op->op_oplock_level,
		    sr->smb_fid,
		    op->action_taken,
		    &ap->sa_crtime,
		    &ap->sa_vattr.va_atime,
		    &ap->sa_vattr.va_mtime,
		    &ap->sa_vattr.va_ctime,
		    op->dattr & FILE_ATTRIBUTE_MASK,
		    ap->sa_allocsz,
		    ap->sa_vattr.va_size,
		    op->ftype,
		    op->devstate,
		    DirFlag,
		    0);
		break;

	case STYPE_IPC:
		rc = smbsr_encode_result(sr, 34, 0, "bb.wbwlqqqqlqqwwbw",
		    34,
		    sr->andx_com,
		    0x67,
		    0,
		    sr->smb_fid,
		    op->action_taken,
		    0LL,
		    0LL,
		    0LL,
		    0LL,
		    FILE_ATTRIBUTE_NORMAL,
		    0x1000LL,
		    0LL,
		    op->ftype,
		    op->devstate,
		    0,
		    0);
		break;

	default:
		smbsr_error(sr, NT_STATUS_INVALID_DEVICE_REQUEST,
		    ERRDOS, ERROR_INVALID_FUNCTION);
		goto errout;
	}
	if (rc == 0)
		return (SDRC_SUCCESS);

errout:
	smb_ofile_close(of, 0);
	return (SDRC_ERROR);
}
