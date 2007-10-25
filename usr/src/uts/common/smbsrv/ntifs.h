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

#ifndef _SMBSRV_NTIFS_H
#define	_SMBSRV_NTIFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file provides definitions compatible with the NT Installable
 * File System (IFS) interface.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * File creation flags must start at the high end since they
 * are combined with the attributes
 */

#define	FILE_FLAG_WRITE_THROUGH			0x80000000
#define	FILE_FLAG_OVERLAPPED			0x40000000
#define	FILE_FLAG_NO_BUFFERING			0x20000000
#define	FILE_FLAG_RANDOM_ACCESS			0x10000000
#define	FILE_FLAG_SEQUENTIAL_SCAN		0x08000000
#define	FILE_FLAG_DELETE_ON_CLOSE		0x04000000
#define	FILE_FLAG_BACKUP_SEMANTICS		0x02000000
#define	FILE_FLAG_POSIX_SEMANTICS		0x01000000
#define	FILE_FLAG_OPEN_REPARSE_POINT		0x00200000
#define	FILE_FLAG_OPEN_NO_RECALL		0x00100000

/*
 * The create/open option flags: used in NtCreateAndx and NtTransactCreate
 * SMB requests.
 *
 * The CreateOptions specify the options to be applied when creating or
 * opening the file, as a compatible combination of the following flags:
 *
 * FILE_DIRECTORY_FILE
 *	The file being created or opened is a directory file. With this
 *	flag, the Disposition parameter must be set to one of FILE_CREATE,
 *	FILE_OPEN, or FILE_OPEN_IF. With this flag, other compatible
 *	CreateOptions flags include only the following:
 *			FILE_SYNCHRONOUS_IO_ALERT
 *			FILE_SYNCHRONOUS_IO_NONALERT
 *			FILE_WRITE_THROUGH
 *			FILE_OPEN_FOR_BACKUP_INTENT
 *			FILE_OPEN_BY_FILE_ID
 *
 * FILE_NON_DIRECTORY_FILE
 *	The file being opened must not be a directory file or this call
 *	will fail. The file object being opened can represent a data file,
 *	a logical, virtual, or physical device, or a volume.
 *
 * FILE_WRITE_THROUGH
 *	System services, FSDs, and drivers that write data to the file must
 *	actually transfer the data into the file before any requested write
 *	operation is considered complete. This flag is automatically set if
 *	the CreateOptions flag FILE_NO_INTERMEDIATE _BUFFERING is set.
 *
 * FILE_SEQUENTIAL_ONLY
 *	All accesses to the file will be sequential.
 *
 * FILE_RANDOM_ACCESS
 *	Accesses to the file can be random, so no sequential read-ahead
 *	operations should be performed on the file by FSDs or the system.
 *	FILE_NO_INTERMEDIATE _BUFFERING	The file cannot be cached or
 *	buffered in a driver's internal buffers. This flag is incompatible
 *	with the DesiredAccess FILE_APPEND_DATA flag.
 *
 * FILE_SYNCHRONOUS_IO_ALERT
 *	All operations on the file are performed synchronously. Any wait
 *	on behalf of the caller is subject to premature termination from
 *	alerts. This flag also causes the I/O system to maintain the file
 *	position context. If this flag is set, the DesiredAccess
 *	SYNCHRONIZE flag also must be set.
 *
 * FILE_SYNCHRONOUS_IO _NONALERT
 *	All operations on the file are performed synchronously. Waits in
 *	the system to synchronize I/O queuing and completion are not subject
 *	to alerts. This flag also causes the I/O system to maintain the file
 *	position context. If this flag is set, the DesiredAccess SYNCHRONIZE
 *	flag also must be set.
 *
 * FILE_CREATE_TREE _CONNECTION
 *	Create a tree connection for this file in order to open it over the
 *	network. This flag is irrelevant to device and intermediate drivers.
 *
 * FILE_COMPLETE_IF_OPLOCKED
 *	Complete this operation immediately with an alternate success code
 *	if the target file is oplocked, rather than blocking the caller's
 *	thread. If the file is oplocked, another caller already has access
 *	to the file over the network. This flag is irrelevant to device and
 *	intermediate drivers.
 *
 * FILE_NO_EA_KNOWLEDGE
 *	If the extended attributes on an existing file being opened indicate
 *	that the caller must understand EAs to properly interpret the file,
 *	fail this request because the caller does not understand how to deal
 *	with EAs. Device and intermediate drivers can ignore this flag.
 *
 * FILE_DELETE_ON_CLOSE
 *	Delete the file when the last reference to it is passed to close.
 *
 * FILE_OPEN_BY_FILE_ID
 *	The file name contains the name of a device and a 64-bit ID to
 *	be used to open the file. This flag is irrelevant to device and
 *	intermediate drivers.
 *
 * FILE_OPEN_FOR_BACKUP _INTENT
 *	The file is being opened for backup intent, hence, the system should
 *	check for certain access rights and grant the caller the appropriate
 *	accesses to the file before checking the input DesiredAccess against
 *	the file's security descriptor. This flag is irrelevant to device
 *	and intermediate drivers.
 */
#define	FILE_DIRECTORY_FILE			0x00000001
#define	FILE_WRITE_THROUGH			0x00000002
#define	FILE_SEQUENTIAL_ONLY			0x00000004
#define	FILE_NO_INTERMEDIATE_BUFFERING		0x00000008

#define	FILE_SYNCHRONOUS_IO_ALERT		0x00000010
#define	FILE_SYNCHRONOUS_IO_NONALERT		0x00000020
#define	FILE_NON_DIRECTORY_FILE			0x00000040
#define	FILE_CREATE_TREE_CONNECTION		0x00000080

#define	FILE_COMPLETE_IF_OPLOCKED		0x00000100
#define	FILE_NO_EA_KNOWLEDGE			0x00000200
/* UNUSED					0x00000400 */
#define	FILE_RANDOM_ACCESS			0x00000800

#define	FILE_DELETE_ON_CLOSE			0x00001000
#define	FILE_OPEN_BY_FILE_ID			0x00002000
#define	FILE_OPEN_FOR_BACKUP_INTENT		0x00004000
#define	FILE_NO_COMPRESSION			0x00008000

#define	FILE_RESERVE_OPFILTER			0x00100000
#define	FILE_RESERVED0				0x00200000
#define	FILE_RESERVED1				0x00400000
#define	FILE_RESERVED2				0x00800000

#define	FILE_VALID_OPTION_FLAGS			0x007fffff
#define	FILE_VALID_PIPE_OPTION_FLAGS		0x00000032
#define	FILE_VALID_MAILSLOT_OPTION_FLAGS	0x00000032
#define	FILE_VALID_SET_FLAGS			0x00000036

/*
 * Define the file information class values used by the NT DDK and HAL.
 */
typedef enum _FILE_INFORMATION_CLASS {
	FileDirectoryInformation	= 1,
	FileFullDirectoryInformation,	/* 2 */
	FileBothDirectoryInformation,	/* 3 */
	FileBasicInformation,		/* 4 */
	FileStandardInformation,	/* 5 */
	FileInternalInformation,	/* 6 */
	FileEaInformation,		/* 7 */
	FileAccessInformation,		/* 8 */
	FileNameInformation,		/* 9 */
	FileRenameInformation,		/* 10 */
	FileLinkInformation,		/* 11 */
	FileNamesInformation,		/* 12 */
	FileDispositionInformation,	/* 13 */
	FilePositionInformation,	/* 14 */
	FileFullEaInformation,		/* 15 */
	FileModeInformation,		/* 16 */
	FileAlignmentInformation,	/* 17 */
	FileAllInformation,		/* 18 */
	FileAllocationInformation,	/* 19 */
	FileEndOfFileInformation,	/* 20 */
	FileAlternateNameInformation,	/* 21 */
	FileStreamInformation,		/* 22 */
	FilePipeInformation,		/* 23 */
	FilePipeLocalInformation,	/* 24 */
	FilePipeRemoteInformation,	/* 25 */
	FileMailslotQueryInformation,	/* 26 */
	FileMailslotSetInformation,	/* 27 */
	FileCompressionInformation,	/* 28 */
	FileObjectIdInformation,	/* 29 */
	FileCompletionInformation,	/* 30 */
	FileMoveClusterInformation,	/* 31 */
	FileInformationReserved32,	/* 32 */
	FileInformationReserved33,	/* 33 */
	FileNetworkOpenInformation,	/* 34 */
	FileMaximumInformation
} FILE_INFORMATION_CLASS;

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_NTIFS_H */
