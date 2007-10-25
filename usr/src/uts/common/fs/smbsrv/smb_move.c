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
 * SMB: move
 *
 * The source file is copied to the destination and the source is
 * subsequently deleted.
 *
 *  Client Request                     Description
 *  ================================== =================================
 *
 *  UCHAR WordCount;                   Count of parameter words = 3
 *  USHORT Tid2;                       Second (target) file id
 *  USHORT OpenFunction;               what to do if target file exists
 *  USHORT Flags;                      Flags to control move operations:
 *                                      0 - target must be a file
 *                                      1 - target must be a directory
 *                                      2 - reserved (must be 0)
 *                                      3 - reserved (must be 0)
 *                                      4 - verify all writes
 *  USHORT ByteCount;                  Count of data bytes;    min = 2
 *  UCHAR Format1;                     0x04
 *  STRING OldFileName[];              Old file name
 *  UCHAR FormatNew;                   0x04
 *  STRING NewFileName[];              New file name
 *
 * OldFileName is copied to NewFileName, then OldFileName is deleted.  Both
 * OldFileName and  NewFileName must refer to paths on the same server.
 * NewFileName can refer to either a file or a directory.  All file
 * components except the last must exist; directories will not be created.
 *
 * NewFileName can be required to be a file or a directory by the Flags
 * field.
 *
 * The Tid in the header is associated with the source while Tid2 is
 * associated with the destination.  These fields may contain the same or
 * differing valid values. Tid2 can be set to -1 indicating that this is to
 *
 * be the same Tid as in the SMB header.  This allows use of the move
 * protocol with SMB_TREE_CONNECT_ANDX.
 *
 *  Server Response                    Description
 *  ================================== =================================
 *
 *  UCHAR WordCount;                   Count of parameter words = 1
 *  USHORT Count;                      Number of files moved
 *  USHORT ByteCount;                  Count of data bytes;    min = 0
 *  UCHAR ErrorFileFormat;             0x04  (only if error)
 *  STRING ErrorFileName[];            Pathname of file where error
 *                                      occurred
 *
 * The source path must refer to an existing file or files.  Wildcards are
 * permitted.  Source files specified by wildcards are processed until an
 * error is encountered. If an error is encountered, the expanded name of
 * the file is returned in ErrorFileName.  Wildcards are not permitted in
 * NewFileName.
 *
 * OpenFunction controls what should happen if the destination file exists.
 * If (OpenFunction & 0x30) == 0, the operation should fail if the
 * destination exists.  If (OpenFunction & 0x30) == 0x20, the destination
 * file should be overwritten.
 *
 * 4.2.12.1  Errors
 *
 * ERRDOS/ERRfilexists
 * ERRDOS/ERRbadfile
 * ERRDOS/ERRnoaccess
 * ERRDOS/ERRnofiles
 * ERRDOS/ERRbadshare
 * ERRHRD/ERRnowrite
 * ERRSRV/ERRnoaccess
 * ERRSRV/ERRinvdevice
 * ERRSRV/ERRinvid
 * ERRSRV/ERRbaduid
 * ERRSRV/ERRnosupport
 * ERRSRV/ERRaccess
 */

#include <smbsrv/smb_incl.h>
/*ARGSUSED*/
int
smb_com_move(struct smb_request *sr)
{
	/* TODO move */
	/* TODO move wildcards */
	/* TODO move */

	return (SDRC_UNIMPLEMENTED);
}
