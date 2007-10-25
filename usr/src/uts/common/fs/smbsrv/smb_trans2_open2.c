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
 * SMB: trans2_open2
 *
 * This transaction is used to open or create a file having extended
 * attributes.
 *
 * Client Request                Value
 * ============================  =======================================
 *
 * WordCount                     15
 * TotalDataCount                Total size of extended attribute list
 * DataOffset                    Offset to extended attribute list in
 *                               this request
 * SetupCount                    1
 * Setup[0]                      TRANS2_OPEN2
 *
 * Parameter Block Encoding      Description
 * ============================  =======================================
 *
 * USHORT Flags;                 Additional information: bit set-
 *                               0 - return additional info
 *                               1 - exclusive oplock requested
 *                               2 - batch oplock requested
 *                               3 - return total length of EAs
 * USHORT DesiredAccess;         Requested file access
 * USHORT Reserved1;             Ought to be zero.  Ignored by the
 *                               server.
 * USHORT FileAttributes;        Attributes for file if create
 * SMB_TIME CreationTime;        Creation time to apply to file if
 *                               create
 * SMB_DATE CreationDate;        Creation date to apply to file if
 *                               create
 * USHORT OpenFunction;          Open function
 * ULONG AllocationSize;         Bytes to reserve on create or truncate
 * USHORT Reserved [5];          Must be zero
 * STRING FileName;              Name of file to open or create
 * UCHAR Data[ TotalDataCount ]  FEAList structure for file to be
 *                               created
 *
 * If secondary requests are required, they must contain 0 parameter bytes,
 * and the Fid in the secondary request is 0xFFFF.
 *
 * DesiredAccess is encoded as described in the "Access Mode Encoding"
 * section elsewhere in this document.
 *
 * FileAttributes are encoded as described in the "File Attribute Encoding"
 * section elsewhere in this document.
 *
 * OpenFunction specifies the action to be taken depending on whether or
 * not the file exists (see section 3.7) .
 *
 * Action in the response specifies the action as a result of this request
 * (see section 3.8).
 *
 *  Response Parameter Block    Description
 *  ==========================  =========================================
 *
 *  USHORT Fid;                 File handle
 *  USHORT FileAttributes;      Attributes of file
 *  SMB_TIME CreationTime;      Last modification time
 *  SMB_DATE CreationDate;      Last modification date
 *  ULONG DataSize;             Current file size
 *  USHORT GrantedAccess;       Access permissions actually allowed
 *  USHORT FileType;            Type of file
 *  USHORT DeviceState;         State of IPC device (e.g. pipe)
 *  USHORT Action;              Action taken
 *  ULONG Reserved;
 *  USHORT EaErrorOffset;       Offset into EA list if EA error
 *  ULONG EaLength;             Total EA length for opened file
 *
 * FileType returns the kind of resource actually opened:
 *
 *  Name                     Value  Description
 *  =======================  ====== =====================================
 *
 *  FileTypeDisk             0      Disk file or directory as defined in
 *                                  the attribute field
 *  FileTypeByteModePipe     1      Named pipe in byte mode
 *  FileTypeMessageModePipe  2      Named pipe in message mode
 *  FileTypePrinter          3      Spooled printer
 *  FileTypeUnknown          0xFFFF Unrecognized resource type
 *
 * DeviceState is applicable only if the FileType is FileTypeByteModePipe
 * or FileTypeMessageModePipe and is encoded as in section 3.9.
 *
 * If an error was detected in the incoming EA list, the offset of the
 * error is returned in EaErrorOffset.
 *
 * If bit0 of Flags in the request is clear, the FileAttributes,
 * CreationTime, CreationDate, DataSize, GrantedAccess, FileType, and
 * DeviceState have indeterminate values in the response.  Similarly, if
 *
 * bit3 of the request is clear, EaLength in the response has an
 * indeterminate value in the response.
 *
 * This SMB can request an oplock on the opened file.  Oplocks are fully
 * described in the "Oplocks" section elsewhere in this document, and there
 * is also discussion of oplocks in the SMB_COM_LOCKING_ANDX SMB
 * description.  Bit1 and bit2 of the Flags field are used to request
 * oplocks during open.
 */

#include <smbsrv/smb_incl.h>

int /*ARGSUSED*/
smb_com_trans2_open2(struct smb_request *sr)
{
	/* TODO: smb_com_trans2_open2 */
	return (SDRC_UNIMPLEMENTED);
}
