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
 * SMB: copy_file
 *
 *  Client Request                     Description
 *  ================================== =================================
 *
 *  UCHAR WordCount;                   Count of parameter words = 3
 *  USHORT Tid2;                       Second (target) path TID
 *  USHORT OpenFunction;               What to do if target file exists
 *  USHORT Flags;                      Flags to control copy operation:
 *                                      bit 0 - target must be a file
 *                                      bit 1 - target must be a dir.
 *                                      bit 2 - copy target mode:
 *                                      0 = binary, 1 = ASCII
 *                                      bit 3 - copy source mode:
 *                                      0 = binary, 1 = ASCII
 *                                      bit 4 - verify all writes
 *                                      bit 5 - tree copy
 *  USHORT ByteCount;                  Count of data bytes;    min = 2
 *  UCHAR SourceFileNameFormat;        0x04
 *  STRING SourceFileName;             Pathname of source file
 *  UCHAR TargetFileNameFormat;        0x04
 *  STRING TargetFileName;             Pathname of target file
 *
 * The file at SourceName is copied to TargetFileName, both of which must refer
 * to paths on the same server.
 *
 * The Tid in the header is associated with the source while Tid2 is
 * associated with the destination.  These fields may contain the same or
 * differing valid values. Tid2 can be set to -1 indicating that this is to
 * be the same Tid as in the SMB header.  This allows use of the move
 * protocol with SMB_TREE_CONNECT_ANDX.
 *
 *  Server Response                    Description
 *  ================================== =================================
 *
 *  UCHAR WordCount;                   Count of parameter words = 1
 *  USHORT Count;                      Number of files copied
 *  USHORT ByteCount;                  Count of data bytes;    min = 0
 *  UCHAR ErrorFileFormat;             0x04 (only if error)
 *  STRING ErrorFileName;
 *
 * The source path must refer to an existing file or files.  Wildcards are
 * permitted.  Source files specified by wildcards are processed until an
 * error is encountered. If an error is encountered, the expanded name of
 * the file is returned in ErrorFileName.  Wildcards are not permitted in
 * TargetFileName.  TargetFileName can refer to either a file or a direc-
 * tory.
 *
 * The destination can be required to be a file or a directory by the bits
 * in Flags.  If neither bit0 nor bit1 are set, the destination may be
 * either a file or a directory.  Flags also controls the copy mode.  In a
 * ascii copy for the source, the copy stops the first time an EOF
 * (control-Z) is encountered. In a ascii copy for the target, the server
 *
 * must make sure that there is exactly one EOF in the target file and that
 * it is the last character of the file.
 *
 * If the destination is a file and the source contains wildcards, the
 * destination file will either be truncated or appended to at the start of
 * the operation depending on bits in OpenFunction (see section 3.7).
 * Subsequent files will then be appended to the file.
 *
 * If the negotiated dialect is  LM1.2X002 or later, bit5 of Flags is used
 * to specify a tree copy on the remote server.  When this option is
 * selected the destination must not be an existing file and the source
 * mode must be binary.  A request with bit5 set and either bit0 or bit3
 * set is therefore an error.  When the tree copy mode is selected, the
 * Count field in the server response is undefined.
 *
 * 4.2.13.1  Errors
 *
 * ERRDOS/ERRfilexists
 * ERRDOS/ERRshare
 * ERRDOS/ERRnofids
 * ERRDOS/ERRbadfile
 * ERRDOS/ERRnoaccess
 * ERRDOS/ERRnofiles
 * ERRDOS/ERRbadshare
 * ERRSRV/ERRnoaccess
 * ERRSRV/ERRinvdevice
 * ERRSRV/ERRinvid
 * ERRSRV/ERRbaduid
 * ERRSRV/ERRaccess
 */

#include <smbsrv/smb_incl.h>

/*ARGSUSED*/
int
smb_com_copy(struct smb_request *sr)
{
	return (SDRC_UNIMPLEMENTED);
}
