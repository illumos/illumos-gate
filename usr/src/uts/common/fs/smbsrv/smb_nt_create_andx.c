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

/*
 * This command is used to create or open a file or directory.
 */


#include <smbsrv/smb_incl.h>
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
int
smb_com_nt_create_andx(struct smb_request *sr)
{
	struct open_param	*op = &sr->arg.open;
	unsigned char		OplockLevel;
	unsigned char		DirFlag;
	unsigned char		SecurityFlags;
	uint32_t		ExtFileAttributes;
	uint32_t		Flags;
	uint32_t		ImpersonationLevel;
	uint32_t		RootDirFid;
	unsigned short		NameLength;
	smb_attr_t		new_attr;
	smb_node_t		*node;
	DWORD status;
	int count;
	int rc;

	op->dsize = 0;

	rc = smbsr_decode_vwv(sr, "5.wlllqlllllb",
	    &NameLength,
	    &Flags,
	    &RootDirFid,
	    &op->desired_access,
	    &op->dsize,
	    &ExtFileAttributes,
	    &op->share_access,
	    &op->create_disposition,
	    &op->create_options,
	    &ImpersonationLevel,
	    &SecurityFlags);

	if (rc != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	if (NameLength >= MAXPATHLEN) {
		smbsr_raise_nt_error(sr, NT_STATUS_OBJECT_PATH_NOT_FOUND);
		/* NOTREACHED */
	}

	if (smbsr_decode_data(sr, "%#u", sr, NameLength, &op->fqi.path) != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	if ((op->create_options & FILE_DELETE_ON_CLOSE) &&
	    !(op->desired_access & DELETE)) {
		smbsr_raise_nt_error(sr, NT_STATUS_INVALID_PARAMETER);
		/* NOTREACHED */
	}

	op->fqi.srch_attr = 0;
	op->omode = 0;
	op->utime.tv_sec = op->utime.tv_nsec = 0;
	op->my_flags = 0;
	op->dattr = ExtFileAttributes;

	if (Flags) {
		if (Flags & NT_CREATE_FLAG_REQUEST_OPLOCK) {
			if (Flags & NT_CREATE_FLAG_REQUEST_OPBATCH) {
				op->my_flags = MYF_BATCH_OPLOCK;
			} else {
				op->my_flags = MYF_EXCLUSIVE_OPLOCK;
			}
		}
		if (Flags & NT_CREATE_FLAG_OPEN_TARGET_DIR)
			op->my_flags |= MYF_MUST_BE_DIRECTORY;
	}

	if (ExtFileAttributes & FILE_FLAG_WRITE_THROUGH)
		op->create_options |= FILE_WRITE_THROUGH;

	if (ExtFileAttributes & FILE_FLAG_DELETE_ON_CLOSE)
		op->create_options |= FILE_DELETE_ON_CLOSE;

	if (RootDirFid == 0) {
		op->fqi.dir_snode = sr->tid_tree->t_snode;
	} else {
		sr->smb_fid = (ushort_t)RootDirFid;

		sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree,
		    sr->smb_fid);
		if (sr->fid_ofile == NULL) {
			smbsr_raise_cifs_error(sr, NT_STATUS_INVALID_HANDLE,
			    ERRDOS, ERRbadfid);
			/* NOTREACHED */
		}

		op->fqi.dir_snode = sr->fid_ofile->f_node;
		smbsr_disconnect_file(sr);
	}

	status = NT_STATUS_SUCCESS;
	/*
	 * According to NT, when exclusive share access failed,
	 * instead of raising "access deny" error immediately,
	 * we should wait for the client holding the exclusive
	 * file to close the file. If the wait timed out, we
	 * report a sharing violation; otherwise, we grant access.
	 * smb_open_subr returns NT_STATUS_SHARING_VIOLATION when
	 * it encounters an exclusive share access deny: we wait
	 * and retry.
	 */
	for (count = 0; count <= 4; count++) {
		if (count) {
			delay(MSEC_TO_TICK(400));
		}

		if ((status = smb_open_subr(sr)) == NT_STATUS_SUCCESS)
			break;
	}

	if (status != NT_STATUS_SUCCESS) {
		if (status == NT_STATUS_SHARING_VIOLATION)
			smbsr_raise_cifs_error(sr,
			    NT_STATUS_SHARING_VIOLATION,
			    ERRDOS, ERROR_SHARING_VIOLATION);
		else
			smbsr_raise_nt_error(sr, status);

		/* NOTREACHED */
	}

	if (STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		switch (MYF_OPLOCK_TYPE(op->my_flags)) {
		case MYF_EXCLUSIVE_OPLOCK :
			OplockLevel = 1;
			break;
		case MYF_BATCH_OPLOCK :
			OplockLevel = 2;
			break;
		case MYF_LEVEL_II_OPLOCK :
			OplockLevel = 3;
			break;
		case MYF_OPLOCK_NONE :
		default:
			OplockLevel = 0;
			break;
		}

		if (op->create_options & FILE_DELETE_ON_CLOSE)
			smb_preset_delete_on_close(sr->fid_ofile);

		/*
		 * Set up the directory flag and ensure that
		 * we don't return a stale file size.
		 */
		node = sr->fid_ofile->f_node;
		if (node->attr.sa_vattr.va_type == VDIR) {
			DirFlag = 1;
			new_attr.sa_vattr.va_size = 0;
		} else {
			DirFlag = 0;
			new_attr.sa_mask = SMB_AT_SIZE;
			(void) smb_fsop_getattr(sr, kcred, node, &new_attr);
			node->attr.sa_vattr.va_size = new_attr.sa_vattr.va_size;
		}

		smbsr_encode_result(sr, 34, 0, "bb.wbwlTTTTlqqwwbw",
		    34,
		    sr->andx_com,
		    0x67,
		    OplockLevel,
		    sr->smb_fid,
		    op->action_taken,
		    &node->attr.sa_crtime,
		    &node->attr.sa_vattr.va_atime,
		    &node->attr.sa_vattr.va_mtime,
		    &node->attr.sa_vattr.va_ctime,
		    op->dattr & FILE_ATTRIBUTE_MASK,
		    new_attr.sa_vattr.va_size,
		    new_attr.sa_vattr.va_size,
		    op->ftype,
		    op->devstate,
		    DirFlag,
		    0);
	} else {
		/* Named PIPE */
		OplockLevel = 0;
		smbsr_encode_result(sr, 34, 0, "bb.wbwlqqqqlqqwwbw",
		    34,
		    sr->andx_com,
		    0x67,
		    OplockLevel,
		    sr->smb_fid,
		    op->action_taken,
		    0LL,
		    0LL,
		    0LL,
		    0LL,
		    SMB_FA_NORMAL,
		    0x1000LL,
		    0LL,
		    op->ftype,
		    op->devstate,
		    0,
		    0);
	}

	return (SDRC_NORMAL_REPLY);
}
