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

#ifndef _SMBSRV_SMB_H
#define	_SMBSRV_SMB_H


/*
 * SMB definitions and interfaces, mostly defined in the SMB and CIFS specs.
 */
#include <sys/types.h>
#include <smbsrv/string.h>
#include <smbsrv/msgbuf.h>

#include <smb/ntstatus.h>
#include <smb/nterror.h>
#include <smb/lmerr.h>
#include <smb/doserror.h>
#include <smbsrv/ntaccess.h>

/*
 * Macintosh Extensions for CIFS
 */
#include <smbsrv/mac_cifs.h>

/*
 * NT Installable File System (IFS) interface.
 */
#include <smbsrv/ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The msgbuf format and length of an SMB header.
 */
#define	SMB_HEADER_DOS_FMT	"Mbbbwbww10.wwww"
#define	SMB_HEADER_NT_FMT	"Mblbww#c2.wwww"
#define	SMB_HEADER_LEN		32
#define	SMB_SIG_SIZE		8	/* SMB signature size */

#define	SMB_HEADER_ED_FMT	"Mbbbwbww8c2.wwww"
#define	SMB_HEADER_ED_LEN	(4+1+1+1+2+1+2+12+2+2+2+2)
#define	SMB_TRANSHDR_ED_FMT	"wwwwb.wl2.wwwwb."
#define	SMB_TRANSHDR_ED_LEN	(2+2+2+2+1+1+2+4+2+2+2+2+2+1+1)
#define	SMB_TRANSSHDR_ED_FMT	"wwwwwwwww"
#define	SMB_TRANSSHDR_ED_LEN	(2+2+2+2+2+2+2+2)
#define	SMB_TRANS2SHDR_ED_FMT	"wwwwwwwww"
#define	SMB_TRANS2SHDR_ED_LEN	(2+2+2+2+2+2+2+2+2)
/* There is something wrong with this. Should be 38 bytes. It is 37 bytes */
#define	SMB_NT_TRANSHDR_ED_FMT	"b2.llllllllbw"
#define	SMB_NT_TRANSHDR_ED_LEN	(1+2+4+4+4+4+4+4+4+4+1+2)

/*
 * CIFS definition for the SMB header (CIFS Section 3.2). Note that the
 * pid_high field is not documented in the 1997 CIFS specificaction. This
 * is a decoded or memory-based definition, which may be padded to align
 * its elements on word boundaries. See smb_hdrbuf_t for the network
 * ready structure.
 */
typedef struct smb_hdr {
	uint8_t protocol[4];
	uint8_t command;

	union {
		struct {
			uint8_t error_class;
			uint8_t reserved;
			uint16_t error;
		} dos_error;
		uint32_t ntstatus;
	} status;

	uint8_t flags;
	uint16_t flags2;
	uint16_t pid_high;

	union {
		uint16_t pad[5];
		struct {
			uint16_t reserved;
			uint8_t security_sig[SMB_SIG_SIZE];
		} extra;
	} extra;

	uint16_t tid;
	uint16_t pid;
	uint16_t uid;
	uint16_t mid;
} smb_hdr_t;

/*
 * Encoded or packed SMB header in network ready format.
 */
typedef struct smb_hdrbuf {
	uint8_t hdr[SMB_HEADER_LEN];
} smb_hdrbuf_t;

/*
 * Protocol magic value as a 32-bit.  This will be 0xff 0x53 0x4d 0x42 on
 * the wire.
 */

#define	SMB_PROTOCOL_MAGIC	0x424d53ff
#define	SMB2_PROTOCOL_MAGIC	0x424d53fe

/*
 * Time and date encoding (CIFS Section 3.6). The date is encoded such
 * that the year has a range of 0-119, which represents 1980-2099. The
 * month range is 1-12, and the day range is 1-31.
 */
typedef struct smb_date {
	uint16_t day   : 5;
	uint16_t month : 4;
	uint16_t year  : 7;
} smb_date_t;

/*
 * The hours range is 0-23, the minutes range is 0-59 and the two_sec
 * range is 0-29.
 */
typedef struct smb_time {
	uint16_t two_sec : 5;
	uint16_t minutes : 6;
	uint16_t hours    : 5;
} smb_time_t;

/*
 * This is a 64-bit signed absolute time representing 100ns increments.
 * A positive value represents the absolute time since 1601AD. A
 * negative value represents a context specific relative time.
 */
typedef struct smb_time2 {
	uint32_t low_time;
	int32_t high_time;
} smb_time2_t;

/*
 * The number of seconds since Jan 1, 1970, 00:00:00.0.
 */
typedef uint32_t smb_utime_t;

#define	SMB_LM_NEGOTIATE_WORDCNT		13
#define	SMB_NT_NEGOTIATE_WORDCNT		17

#define	SMB_NAME83_EXTLEN			3
#define	SMB_NAME83_BASELEN			8
#define	SMB_NAME83_LEN				12

/* Share types */
#ifndef _SHARE_TYPES_DEFINED_
#define	_SHARE_TYPES_DEFINED_
#define	STYPE_DISKTREE			0x00000000
#define	STYPE_PRINTQ			0x00000001
#define	STYPE_DEVICE			0x00000002
#define	STYPE_IPC			0x00000003
#define	STYPE_MASK			0x0000000F
#define	STYPE_DFS			0x00000064
#define	STYPE_HIDDEN			0x80000000
#define	STYPE_SPECIAL			0x80000000
#endif /* _SHARE_TYPES_DEFINED_ */

#define	STYPE_ISDSK(S)	(((S) & STYPE_MASK) == STYPE_DISKTREE)
#define	STYPE_ISPRN(S)	(((S) & STYPE_MASK) == STYPE_PRINTQ)
#define	STYPE_ISDEV(S)	(((S) & STYPE_MASK) == STYPE_DEVICE)
#define	STYPE_ISIPC(S)	(((S) & STYPE_MASK) == STYPE_IPC)

/*
 * NtCreateAndX and NtTransactCreate creation flags: defined in CIFS
 * section 4.2.2
 *
 * Creation Flag Name         Value  Description
 * ========================== ====== ==================================
 * NT_CREATE_REQUEST_OPLOCK   0x02   Level I oplock requested
 * NT_CREATE_REQUEST_OPBATCH  0x04   Batch oplock requested
 * NT_CREATE_OPEN_TARGET_DIR  0x08   Target for open is a directory
 */
#define	NT_CREATE_FLAG_REQUEST_OPLOCK		0x02
#define	NT_CREATE_FLAG_REQUEST_OPBATCH		0x04
#define	NT_CREATE_FLAG_OPEN_TARGET_DIR		0x08


/*
 * Define the filter flags for NtNotifyChangeDirectoryFile
 */
#define	FILE_NOTIFY_CHANGE_FILE_NAME	0x00000001
#define	FILE_NOTIFY_CHANGE_DIR_NAME	0x00000002
#define	FILE_NOTIFY_CHANGE_NAME		0x00000003
#define	FILE_NOTIFY_CHANGE_ATTRIBUTES	0x00000004
#define	FILE_NOTIFY_CHANGE_SIZE		0x00000008
#define	FILE_NOTIFY_CHANGE_LAST_WRITE	0x00000010
#define	FILE_NOTIFY_CHANGE_LAST_ACCESS	0x00000020
#define	FILE_NOTIFY_CHANGE_CREATION	0x00000040
#define	FILE_NOTIFY_CHANGE_EA		0x00000080
#define	FILE_NOTIFY_CHANGE_SECURITY	0x00000100
#define	FILE_NOTIFY_CHANGE_STREAM_NAME	0x00000200
#define	FILE_NOTIFY_CHANGE_STREAM_SIZE	0x00000400
#define	FILE_NOTIFY_CHANGE_STREAM_WRITE	0x00000800
#define	FILE_NOTIFY_VALID_MASK		0x00000fff


/*
 * Define the file action type codes for NtNotifyChangeDirectoryFile
 */
#define	FILE_ACTION_ADDED		0x00000001
#define	FILE_ACTION_REMOVED		0x00000002
#define	FILE_ACTION_MODIFIED		0x00000003
#define	FILE_ACTION_RENAMED_OLD_NAME	0x00000004
#define	FILE_ACTION_RENAMED_NEW_NAME	0x00000005
#define	FILE_ACTION_ADDED_STREAM	0x00000006
#define	FILE_ACTION_REMOVED_STREAM	0x00000007
#define	FILE_ACTION_MODIFIED_STREAM	0x00000008
/*
 * Note: These action values are not from MS-FSCC.
 * FILE_ACTION_SUBDIR_CHANGED is used internally for
 * "watch tree" support, posted to all parents of a
 * directory that had one of the changes above.
 * FILE_ACTION_DELETE_PENDING is used internally to tell
 * notify change requests when the "delete-on-close" flag
 * has been set on the directory being watched.
 */
#define	FILE_ACTION_SUBDIR_CHANGED	0x00000009
#define	FILE_ACTION_DELETE_PENDING	0x0000000a


/* Lock type flags */
#define	LOCKING_ANDX_NORMAL_LOCK	0x00
#define	LOCKING_ANDX_SHARED_LOCK	0x01
#define	LOCKING_ANDX_OPLOCK_RELEASE	0x02
#define	LOCKING_ANDX_CHANGE_LOCK_TYPE	0x04
#define	LOCKING_ANDX_CANCEL_LOCK	0x08
#define	LOCKING_ANDX_LARGE_FILES	0x10

#define	SMB_COM_CREATE_DIRECTORY	0x00
#define	SMB_COM_DELETE_DIRECTORY	0x01
#define	SMB_COM_OPEN			0x02
#define	SMB_COM_CREATE			0x03
#define	SMB_COM_CLOSE			0x04
#define	SMB_COM_FLUSH			0x05
#define	SMB_COM_DELETE			0x06
#define	SMB_COM_RENAME			0x07
#define	SMB_COM_QUERY_INFORMATION	0x08
#define	SMB_COM_SET_INFORMATION		0x09
#define	SMB_COM_READ			0x0A
#define	SMB_COM_WRITE			0x0B
#define	SMB_COM_LOCK_BYTE_RANGE		0x0C
#define	SMB_COM_UNLOCK_BYTE_RANGE	0x0D
#define	SMB_COM_CREATE_TEMPORARY	0x0E
#define	SMB_COM_CREATE_NEW		0x0F
#define	SMB_COM_CHECK_DIRECTORY		0x10
#define	SMB_COM_PROCESS_EXIT		0x11
#define	SMB_COM_SEEK			0x12
#define	SMB_COM_LOCK_AND_READ		0x13
#define	SMB_COM_WRITE_AND_UNLOCK	0x14

#define	SMB_COM_READ_RAW		0x1A
#define	SMB_COM_READ_MPX		0x1B
#define	SMB_COM_READ_MPX_SECONDARY	0x1C
#define	SMB_COM_WRITE_RAW		0x1D
#define	SMB_COM_WRITE_MPX		0x1E
#define	SMB_COM_WRITE_MPX_SECONDARY	0x1F
#define	SMB_COM_WRITE_COMPLETE		0x20

#define	SMB_COM_SET_INFORMATION2	0x22
#define	SMB_COM_QUERY_INFORMATION2	0x23
#define	SMB_COM_LOCKING_ANDX		0x24
#define	SMB_COM_TRANSACTION		0x25
#define	SMB_COM_TRANSACTION_SECONDARY	0x26
#define	SMB_COM_IOCTL			0x27
#define	SMB_COM_IOCTL_SECONDARY		0x28
#define	SMB_COM_COPY			0x29
#define	SMB_COM_MOVE			0x2A
#define	SMB_COM_ECHO			0x2B
#define	SMB_COM_WRITE_AND_CLOSE		0x2C
#define	SMB_COM_OPEN_ANDX		0x2D
#define	SMB_COM_READ_ANDX		0x2E
#define	SMB_COM_WRITE_ANDX		0x2F

#define	SMB_COM_CLOSE_AND_TREE_DISC	0x31
#define	SMB_COM_TRANSACTION2		0x32
#define	SMB_COM_TRANSACTION2_SECONDARY	0x33
#define	SMB_COM_FIND_CLOSE2		0x34
#define	SMB_COM_FIND_NOTIFY_CLOSE	0x35

#define	SMB_COM_TREE_CONNECT		0x70
#define	SMB_COM_TREE_DISCONNECT		0x71
#define	SMB_COM_NEGOTIATE		0x72
#define	SMB_COM_SESSION_SETUP_ANDX	0x73
#define	SMB_COM_LOGOFF_ANDX		0x74
#define	SMB_COM_TREE_CONNECT_ANDX	0x75

#define	SMB_COM_QUERY_INFORMATION_DISK	0x80
#define	SMB_COM_SEARCH			0x81
#define	SMB_COM_FIND			0x82
#define	SMB_COM_FIND_UNIQUE		0x83
#define	SMB_COM_FIND_CLOSE		0x84

#define	SMB_COM_NT_TRANSACT		0xA0
#define	SMB_COM_NT_TRANSACT_SECONDARY	0xA1
#define	SMB_COM_NT_CREATE_ANDX		0xA2
#define	SMB_COM_NT_CANCEL		0xA4

#define	SMB_COM_OPEN_PRINT_FILE		0xC0
#define	SMB_COM_WRITE_PRINT_FILE	0xC1
#define	SMB_COM_CLOSE_PRINT_FILE	0xC2
#define	SMB_COM_GET_PRINT_QUEUE		0xC3

#define	SMB_COM_NUM			0x100

/*
 * Flags field of the SMB header. The names in parenthesis represent
 * alternative names for the flags.
 *
 * SMB_FLAGS_LOCK_AND_READ_OK     If the server supports LockAndRead and
 * (SMB_FLAGS_LOCKS_SUBDIALECT)   WriteAndUnlock, it sets this bit in the
 *                                Negotiate response.
 *
 * SMB_FLAGS_SEND_NO_ACK          When on, the client guarantees that there
 * (SMB_FLAGS_RCV_BUF_POSTED)     is a receive buffer posted such that a
 *                                "Send-No-Ack" can be used by the server
 *                                to respond to the client's request.
 *
 * SMB_FLAGS_CASE_INSENSITIVE     This is part of the Flags field of every
 *                                SMB header. If this bit is set, then all
 *                                pathnames in the SMB should be treated as
 *                                case-insensitive. Otherwise pathnames are
 *                                case-sensitive.
 *
 * SMB_FLAGS_CANONICALIZED_PATHS  When on in SessionSetupX, this indicates
 *                                that all paths sent to the server are
 *                                already in OS/2 canonicalized format.
 *
 * OS/2 canonical format means that file/directory names are in upper case,
 * are valid characters, . and .. have been removed and single backslashes
 * are used as separators.
 *
 * SMB_FLAGS_OPLOCK               When set in an open file request SMBs
 *                                (Open, Create, OpenX, etc.) this bit
 *                                indicates a request for an oplock on the
 *                                file. When set in the response, this bit
 *                                indicates that the oplock was granted.
 *
 * SMB_FLAGS_OPLOCK_NOTIFY_ANY    When on, this bit indicates that the server
 *                                should notify the client on any request
 *                                that could cause the file to be changed.
 *                                If not set, the server only notifies the
 *                                client on other open requests on the file.
 *                                This bit is only relevant when
 *                                SMB_FLAGS_OPLOCK is set.
 *
 * SMB_FLAGS_SERVER_TO_REDIR      This bit indicates that the SMB is being
 * (SMB_FLAGS_REPLY)              sent from server to (client) redirector.
 */
#define	SMB_FLAGS_LOCK_AND_READ_OK	0x01
#define	SMB_FLAGS_SEND_NO_ACK		0x02
#define	SMB_FLAGS_RESERVED		0x04
#define	SMB_FLAGS_CASE_INSENSITIVE	0x08
#define	SMB_FLAGS_CANONICALIZED_PATHS	0x10
#define	SMB_FLAGS_OPLOCK		0x20
#define	SMB_FLAGS_OPLOCK_NOTIFY_ANY	0x40
#define	SMB_FLAGS_REPLY			0x80


/*
 * Flags2 field of the SMB header.
 *
 * SMB_FLAGS2_READ_IF_EXECUTE is also known as SMB_FLAGS2_PAGING_IO
 */
#define	SMB_FLAGS2_KNOWS_LONG_NAMES		0x0001
#define	SMB_FLAGS2_KNOWS_EAS			0x0002
#define	SMB_FLAGS2_SMB_SECURITY_SIGNATURE	0x0004
#define	SMB_FLAGS2_IS_LONG_NAME			0x0040
#define	SMB_FLAGS2_REPARSE_PATH			0x0400
#define	SMB_FLAGS2_EXT_SEC			0x0800
#define	SMB_FLAGS2_DFS				0x1000
#define	SMB_FLAGS2_READ_IF_EXECUTE		0x2000
#define	SMB_FLAGS2_NT_STATUS			0x4000
#define	SMB_FLAGS2_UNICODE			0x8000

#define	DIALECT_UNKNOWN		 0
#define	PC_NETWORK_PROGRAM_1_0	 1  /* The original MSNET SMB protocol */
#define	PCLAN1_0		 2  /* Some versions of the original MSNET */
#define	MICROSOFT_NETWORKS_1_03	 3  /* This is used for the MS-NET 1.03 */
#define	MICROSOFT_NETWORKS_3_0	 4  /* This is the  DOS LANMAN 1.0 specific */
#define	LANMAN1_0		 5  /* This is the first version of the full */
#define	LM1_2X002		 6  /* This is the first version of the full */
#define	DOS_LM1_2X002		 7  /* This is the dos equivalent of the */
#define	DOS_LANMAN2_1		 8  /* DOS LANMAN2.1 */
#define	LANMAN2_1		 9  /* OS/2 LANMAN2.1 */
#define	Windows_for_Workgroups_3_1a 10 /* Windows for Workgroups Version 1.0 */
#define	NT_LM_0_12		11  /* The SMB protocol designed for NT */
#define	DIALECT_SMB2002		12  /* SMB 2.002 (switch to SMB2) */
#define	DIALECT_SMB2XXX		13  /* SMB 2.??? (switch to SMB2) */

/*
 * SMB_TREE_CONNECT_ANDX OptionalSupport flags
 *
 * SMB_SUPPORT_SEARCH_BITS    The server supports SearchAttributes.
 * SMB_SHARE_IS_IN_DFS        The share is managed by DFS.
 * SMB_CSC_MASK               Offline-caching mask - see CSC values.
 * SMB_UNIQUE_FILE_NAME       The server uses long names and does not support
 *                            short names.  This indicates to clients that
 *                            they may perform directory name-space caching.
 * SMB_EXTENDED_SIGNATURES    The server will use signing key protection.
 *
 * SMB_CSC_CACHE_MANUAL_REINT Clients are allowed to cache files for offline
 *                            use as requested by users but automatic
 *                            file-by-file reintegration is not allowed.
 * SMB_CSC_CACHE_AUTO_REINT   Clients are allowed to automatically cache
 *                            files for offline use and file-by-file
 *                            reintegration is allowed.
 * SMB_CSC_CACHE_VDO          Clients are allowed to automatically cache files
 *                            for offline use, file-by-file reintegration is
 *                            allowed and clients are permitted to work from
 *                            their local cache even while offline.
 * SMB_CSC_CACHE_NONE         Client-side caching is disabled for this share.
 *
 * SHI1005_FLAGS_ACCESS_BASED_DIRECTORY_ENUM
 *			      The server will filter directory entries based
 *			      on the access permissions of the client.
 */
#define	SMB_SUPPORT_SEARCH_BITS		0x0001
#define	SMB_SHARE_IS_IN_DFS		0x0002
#define	SMB_CSC_MASK			0x000C
#define	SMB_UNIQUE_FILE_NAME		0x0010
#define	SMB_EXTENDED_SIGNATURES		0x0020

#define	SMB_CSC_CACHE_MANUAL_REINT	0x0000
#define	SMB_CSC_CACHE_AUTO_REINT	0x0004
#define	SMB_CSC_CACHE_VDO		0x0008
#define	SMB_CSC_CACHE_NONE		0x000C

#define	SHI1005_FLAGS_ACCESS_BASED_DIRECTORY_ENUM	0x0800
#define	SHI1005_FLAGS_ALLOW_NAMESPACE_CACHING		0x0400

/*
 * The subcommand codes, placed in SETUP[0], for named pipe operations are:
 * SubCommand Code	Value Description
 * ===================	===== =========================================
 */

#define	CallNamedPipe	0x54	/* open/write/read/close pipe */
#define	WaitNamedPipe	0x53	/* wait for pipe to be nonbusy */
#define	PeekNmPipe	0x23	/* read but don't remove data */
#define	QNmPHandState	0x21	/* query pipe handle modes */
#define	SetNmPHandState	0x01	/* set pipe handle modes */
#define	QNmPipeInfo	0x22	/* query pipe attributes */
#define	TransactNmPipe	0x26	/* write/read operation on pipe */
#define	RawReadNmPipe	0x11	/* read pipe in "raw" (non message mode) */
#define	RawWriteNmPipe	0x31	/* write pipe "raw" (non message mode) */



/*
 * Setup[0] Transaction2       Value  Description
 * Subcommand Code
 * ==========================  =====  =============================
 */

#define	TRANS2_OPEN2		0x00	/* Create file, extended attributes */
#define	TRANS2_FIND_FIRST2	0x01	/* Begin search for files */
#define	TRANS2_FIND_NEXT2	0x02	/* Resume search for files */
#define	TRANS2_QUERY_FS_INFORMATION 0x03 /* Get file system information */
#define	TRANS2_SET_FS_INFORMATION	0x04	/* Set file system info. */
#define	TRANS2_QUERY_PATH_INFORMATION 0x05 /* Get info, named file or dir */
#define	TRANS2_SET_PATH_INFORMATION 0x06 /* Set info, named file or dir */
#define	TRANS2_QUERY_FILE_INFORMATION 0x07 /* Get info, handle */
#define	TRANS2_SET_FILE_INFORMATION 0x08 /* Set info, handle */
#define	TRANS2_FSCTL		0x09	/* Not implemented by NT server */
#define	TRANS2_IOCTL2		0x0A	/* Not implemented by NT server */
#define	TRANS2_FIND_NOTIFY_FIRST 0x0B	/* Not implemented by NT server */
#define	TRANS2_FIND_NOTIFY_NEXT 0x0C	/* Not implemented by NT server */
#define	TRANS2_CREATE_DIRECTORY 0x0D	/* Create dir, extended attributes */
#define	TRANS2_SESSION_SETUP	0x0E	/* Session setup, extended security */
#define	TRANS2_GET_DFS_REFERRAL	0x10	/* Get a Dfs referral */
#define	TRANS2_REPORT_DFS_INCONSISTENCY 0x11 /* Report a Dfs inconsistency */

/*
 * Access Mode Encoding (CIFS/1.0 1996 Section 3.8).
 *
 * The desired access mode passed in SmbOpen and SmbOpenAndX has the following
 * mapping:
 *
 *    1111 11
 *    5432 1098 7654 3210
 *    rWrC rLLL rSSS rAAA
 *
 * where:
 *
 *    W - Write through mode.  No read ahead or write behind allowed on
 *        this file or device.  When protocol is returned, data is expected
 *        to be on the disk or device.
 *
 *    S - Sharing mode:
 *        0 - Compatibility mode (as in core open)
 *        1 - Deny read/write/execute (exclusive)
 *        2 - Deny write
 *        3 - Deny read/execute
 *        4 - Deny none
 *
 *    A - Access mode
 *        0 - Open for reading
 *        1 - Open for writing
 *        2 - Open for reading and writing
 *        3 - Open for execute
 *
 *    rSSSrAAA = 11111111 (hex FF) indicates FCB open (as in core protocol)
 *
 *    C - Cache mode
 *        0 - Normal file
 *        1 - Do not cache this file
 *
 *    L - Locality of reference
 *        0 - Locality of reference is unknown
 *        1 - Mainly sequential access
 *        2 - Mainly random access
 *        3 - Random access with some locality
 *        4 to 7 - Currently undefined
 */


#define	SMB_DA_SHARE_MASK		0x70
#define	SMB_DA_ACCESS_MASK		0x07
#define	SMB_DA_FCB_MASK			(UCHAR)0xFF

#define	SMB_DA_ACCESS_READ		0x00
#define	SMB_DA_ACCESS_WRITE		0x01
#define	SMB_DA_ACCESS_READ_WRITE	0x02
#define	SMB_DA_ACCESS_EXECUTE		0x03

#define	SMB_DA_SHARE_COMPATIBILITY	0x00
#define	SMB_DA_SHARE_EXCLUSIVE		0x10
#define	SMB_DA_SHARE_DENY_WRITE		0x20
#define	SMB_DA_SHARE_DENY_READ		0x30
#define	SMB_DA_SHARE_DENY_NONE		0x40

#define	SMB_DA_FCB			(UCHAR)0xFF

#define	SMB_CACHE_NORMAL		0x0000
#define	SMB_DO_NOT_CACHE		0x1000

#define	SMB_LR_UNKNOWN			0x0000
#define	SMB_LR_SEQUENTIAL		0x0100
#define	SMB_LR_RANDOM			0x0200
#define	SMB_LR_RANDOM_WITH_LOCALITY	0x0300
#define	SMB_LR_MASK			0x0F00

#define	SMB_DA_WRITE_THROUGH		0x4000

/*
 * Macros used for share reservation rule checking
 */

#define	SMB_DENY_READ(share_access) ((share_access & FILE_SHARE_READ) == 0)

#define	SMB_DENY_WRITE(share_access) ((share_access & FILE_SHARE_WRITE) == 0)

#define	SMB_DENY_DELETE(share_access) ((share_access & FILE_SHARE_DELETE) == 0)

#define	SMB_DENY_RW(share_access) \
	((share_access & (FILE_SHARE_READ | FILE_SHARE_WRITE)) == 0)

#define	SMB_DENY_ALL(share_access) (share_access == 0)

#define	SMB_DENY_NONE(share_access) (share_access == FILE_SHARE_ALL)

/*
 * The SMB open function determines what action should be taken depending
 * on the existence or lack thereof of files used in the operation.  It
 * has the following mapping:
 *
 *    1111 1
 *    5432 1098 7654 3210
 *    rrrr rrrr rrrC rrOO
 *
 * where:
 *
 *    O - Open (action to be taken if the target file exists)
 *        0 - Fail
 *        1 - Open or Append file
 *        2 - Truncate file
 *
 *    C - Create (action to be taken if the target file does not exist)
 *        0 - Fail
 *        1 - Create file
 */

#define	SMB_OFUN_OPEN_MASK		0x3
#define	SMB_OFUN_CREATE_MASK		0x10

#define	SMB_OFUN_OPEN_FAIL		0
#define	SMB_OFUN_OPEN_APPEND		1
#define	SMB_OFUN_OPEN_OPEN		1
#define	SMB_OFUN_OPEN_TRUNCATE		2

#define	SMB_OFUN_CREATE_FAIL		0x00
#define	SMB_OFUN_CREATE_CREATE		0x10

/*
 * The Action field of OpenAndX has the following format:
 *
 *    1111 11
 *    5432 1098 7654 3210
 *    Lrrr rrrr rrrr rrOO
 *
 * where:
 *
 *    L - Opportunistic lock.  1 if lock granted, else 0.
 *
 *    O - Open action:
 *        1 - The file existed and was opened
 *        2 - The file did not exist but was created
 *        3 - The file existed and was truncated
 */

#define	SMB_OACT_LOCK			0x8000
#define	SMB_OACT_OPENED			0x01
#define	SMB_OACT_CREATED		0x02
#define	SMB_OACT_TRUNCATED		0x03

#define	SMB_OACT_OPLOCK			0x8000

#define	SMB_FTYPE_DISK			0
#define	SMB_FTYPE_BYTE_PIPE		1
#define	SMB_FTYPE_MESG_PIPE		2
#define	SMB_FTYPE_PRINTER		3
#define	SMB_FTYPE_UNKNOWN		0xFFFF

#define	SMB_DEVST_BLOCKING		0x8000
#define	SMB_DEVST_ENDPOINT		0x4000
#define	SMB_DEVST_TYPE_MASK		0x0C00
#define	SMB_DEVST_TYPE_BYTE_PIPE	0x0000
#define	SMB_DEVST_TYPE_MESG_PIPE	0x0400
#define	SMB_DEVST_RMODE_MASK		0x0300
#define	SMB_DEVST_RMODE_BYTES		0x0000
#define	SMB_DEVST_RMODE_MESGS		0x0100
#define	SMB_DEVST_ICOUNT_MASK		0x00FF		/* not used */

#define	SMB_FTYPE_IS_DISK(F)		((F) == SMB_FTYPE_DISK)
#define	SMB_FTYPE_IS_PIPE(F) \
	(((F) == SMB_FTYPE_BYTE_PIPE) || ((F) == SMB_FTYPE_MESG_PIPE))
#define	SMB_FTYPE_IS_PRINTER(F)		((F) == SMB_FTYPE_PRINTER)

/*
 * TRANS2_FIND
 */
#define	SMB_FIND_FILE_DIRECTORY_INFO		0x101
#define	SMB_FIND_FILE_FULL_DIRECTORY_INFO	0x102
#define	SMB_FIND_FILE_NAMES_INFO		0x103
#define	SMB_FIND_FILE_BOTH_DIRECTORY_INFO	0x104
#define	SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO	0x105
#define	SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO	0x106
#define	SMB_MAC_FIND_BOTH_HFS_INFO		MAC_FIND_BOTH_HFS_INFO


/*
 * Flags for TRANS2_FIND_FIRST2 and TRANS2_FIND_NEXT2 (NTDDK).
 *
 * If SMB_FIND_RETURN_RESUME_KEYS was set in the request parameters,
 * each entry is preceded by a four-byte resume key.
 */
#define	SMB_FIND_CLOSE_AFTER_REQUEST	0x01
#define	SMB_FIND_CLOSE_AT_EOS		0x02
#define	SMB_FIND_RETURN_RESUME_KEYS	0x04
#define	SMB_FIND_CONTINUE_FROM_LAST	0x08
#define	SMB_FIND_WITH_BACKUP_INTENT	0x10


/*
 * TRANS2_QUERY_FS_INFORMATION
 *
 * SMB_QUERY_FS_QUOTA_INFO, SMB_QUERY_FS_CONTROL_INFO are not used in Windows
 * NT, and are not used in any post NT Windows operating systems. If a server
 * receives these information levels from a client, it should handle them as
 * invalid information levels.
 */
#define	SMB_INFO_ALLOCATION		1
#define	SMB_INFO_VOLUME			2
#define	SMB_QUERY_FS_LABEL_INFO		0x101
#define	SMB_QUERY_FS_VOLUME_INFO	0x102
#define	SMB_QUERY_FS_SIZE_INFO		0x103
#define	SMB_QUERY_FS_DEVICE_INFO	0x104
#define	SMB_QUERY_FS_ATTRIBUTE_INFO	0x105
#define	SMB_QUERY_FS_QUOTA_INFO		0x106
#define	SMB_QUERY_FS_CONTROL_INFO	0x107

#define	SMB_MAC_QUERY_FS_INFO		MAC_QUERY_FS_INFO

/*
 * Internal use only.
 * Define information levels to represent the following requests:
 *    smb_query_information
 *    smb_query_information2
 *    smb_set_information
 *    smb_set_information2
 */
#define	SMB_QUERY_INFORMATION	0x3001
#define	SMB_QUERY_INFORMATION2	0x3002
#define	SMB_SET_INFORMATION	0x3001
#define	SMB_SET_INFORMATION2	0x3002

/* TRANS2_QUERY_{PATH,FILE}_INFORMATION */
#define	SMB_INFO_STANDARD		 1	/* query, set */
#define	SMB_INFO_QUERY_EA_SIZE		 2	/* query */
#define	SMB_INFO_SET_EAS		 2	/* set */
#define	SMB_INFO_QUERY_EAS_FROM_LIST	 3	/* query */
#define	SMB_INFO_QUERY_ALL_EAS		 4	/* query */
#define	SMB_INFO_QUERY_FULL_NAME	 5	/* unused */
#define	SMB_INFO_IS_NAME_VALID		 6	/* query */

#define	SMB_QUERY_FILE_BASIC_INFO	 0x101
#define	SMB_QUERY_FILE_STANDARD_INFO	 0x102
#define	SMB_QUERY_FILE_EA_INFO		 0x103
#define	SMB_QUERY_FILE_NAME_INFO	 0x104
#define	SMB_QUERY_FILE_ALLOCATION_INFO	 0x105	/* unused */
#define	SMB_QUERY_FILE_END_OF_FILE_INFO	 0x106	/* unused */
#define	SMB_QUERY_FILE_ALL_INFO		 0x107
#define	SMB_QUERY_FILE_ALT_NAME_INFO	 0x108
#define	SMB_QUERY_FILE_STREAM_INFO	 0x109
#define	SMB_QUERY_FILE_COMPRESSION_INFO	 0x10B

#define	SMB_MAC_SET_FINDER_INFO		MAC_SET_FINDER_INFO
#define	SMB_MAC_DT_ADD_APPL		MAC_DT_ADD_APPL
#define	SMB_MAC_DT_REMOVE_APPL		MAC_DT_REMOVE_APPL
#define	SMB_MAC_DT_GET_APPL		MAC_DT_GET_APPL
#define	SMB_MAC_DT_GET_ICON		MAC_DT_GET_ICON
#define	SMB_MAC_DT_GET_ICON_INFO	MAC_DT_GET_ICON_INFO
#define	SMB_MAC_DT_ADD_ICON		MAC_DT_ADD_ICON

#define	SMB_SET_FILE_BASIC_INFO		0x101
#define	SMB_SET_FILE_DISPOSITION_INFO	0x102
#define	SMB_SET_FILE_ALLOCATION_INFO	0x103
#define	SMB_SET_FILE_END_OF_FILE_INFO	0x104


/* NT passthrough levels - see ntifs.h FILE_INFORMATION_CLASS */
#define	SMB_FILE_BASIC_INFORMATION		1004
#define	SMB_FILE_STANDARD_INFORMATION		1005
#define	SMB_FILE_INTERNAL_INFORMATION		1006
#define	SMB_FILE_EA_INFORMATION			1007
#define	SMB_FILE_ACCESS_INFORMATION		1008
#define	SMB_FILE_NAME_INFORMATION		1009
#define	SMB_FILE_RENAME_INFORMATION		1010
#define	SMB_FILE_LINK_INFORMATION		1011
#define	SMB_FILE_DISPOSITION_INFORMATION	1013
#define	SMB_FILE_ALL_INFORMATION		1018
#define	SMB_FILE_ALLOCATION_INFORMATION		1019
#define	SMB_FILE_END_OF_FILE_INFORMATION	1020
#define	SMB_FILE_ALT_NAME_INFORMATION		1021
#define	SMB_FILE_STREAM_INFORMATION		1022
#define	SMB_FILE_COMPRESSION_INFORMATION	1028
#define	SMB_FILE_NETWORK_OPEN_INFORMATION	1034
#define	SMB_FILE_ATTR_TAG_INFORMATION		1035

/* NT passthrough levels - see ntifs.h FILE_FS_INFORMATION_CLASS */
#define	SMB_FILE_FS_VOLUME_INFORMATION		1001
#define	SMB_FILE_FS_LABEL_INFORMATION		1002
#define	SMB_FILE_FS_SIZE_INFORMATION		1003
#define	SMB_FILE_FS_DEVICE_INFORMATION		1004
#define	SMB_FILE_FS_ATTRIBUTE_INFORMATION	1005
#define	SMB_FILE_FS_CONTROL_INFORMATION		1006
#define	SMB_FILE_FS_FULLSIZE_INFORMATION	1007
#define	SMB_FILE_FS_OBJECTID_INFORMATION	1008
#define	SMB_FILE_FS_DRIVERPATH_INFORMATION	1009

/*
 * The following bits may be set in the SecurityMode field of the
 * SMB_COM_NEGOTIATE response.
 *
 * Note: Same as the NTDDK definitions.
 */
#define	NEGOTIATE_USER_SECURITY				0x01
#define	NEGOTIATE_ENCRYPT_PASSWORDS			0x02
#define	NEGOTIATE_SECURITY_SIGNATURES_ENABLED		0x04
#define	NEGOTIATE_SECURITY_SIGNATURES_REQUIRED		0x08


/*
 * Negotiated Capabilities (CIFS/1.0 section 4.1.1)
 *
 * Capabilities allow the server to tell the client what it supports.
 * Undefined bits MUST be set to zero by servers, and MUST be ignored
 * by clients. The bit definitions are:
 *
 * Capability Name	 Encoding   Meaning
 * ====================	 ========   ==================================
 * CAP_RAW_MODE		 0x0001	    The server supports SMB_COM_READ_RAW and
 *				    SMB_COM_WRITE_RAW (obsolescent)
 * CAP_MPX_MODE		 0x0002	    The server supports SMB_COM_READ_MPX and
 *				    SMB_COM_WRITE_MPX (obsolescent)
 * CAP_UNICODE		 0x0004	    The server supports Unicode strings
 * CAP_LARGE_FILES	 0x0008	    The server supports large files with 64
 *				    bit offsets
 * CAP_NT_SMBS		 0x0010	    The server supports the SMBs particular
 *				    to the NT LM 0.12 dialect.
 *				    Implies CAP_NT_FIND.
 * CAP_RPC_REMOTE_APIS	 0x0020	    The server supports remote admin API
 *				    requests via DCE RPC
 * CAP_STATUS32		 0x0040	    The server can respond with 32 bit
 *				    status codes in Status.Status
 * CAP_LEVEL_II_OPLOCKS	 0x0080	    The server supports level 2 oplocks
 * CAP_LOCK_AND_READ	 0x0100	    The server supports the
 *				    SMB_COM_LOCK_AND_READ SMB
 * CAP_NT_FIND		 0x0200
 * CAP_BULK_TRANSFER	 0x0400
 * CAP_COMPRESSED_BULK	 0x0800
 * CAP_DFS		 0x1000	    The server is DFS aware
 * CAP_INFOLEVEL_PASSTHRU 0x2000    The server supports passthru information
 *				    level processing capability.
 * CAP_LARGE_READX	 0x4000	    The server supports large
 *				    SMB_COM_READ_ANDX
 * CAP_LARGE_WRITEX	 0x8000	    The server supports large
 *				    SMB_COM_WRITE_ANDX
 * CAP_RESERVED		 0x02000000 Reserved for future use.
 * CAP_EXTENDED_SECURITY 0x80000000 The server supports extended security
 *				    exchanges.
 *
 * Extended security exchanges provides a means of supporting arbitrary
 * authentication protocols within CIFS. Security blobs are opaque to the
 * CIFS protocol; they are messages in some authentication protocol that
 * has been agreed upon by client and server by some out of band mechanism,
 * for which CIFS merely functions as a transport. When
 * CAP_EXTENDED_SECURITY is negotiated, the server includes a first
 * security blob in its response; subsequent security blobs are exchanged
 * in SMB_COM_SESSION_SETUP_ANDX requests and responses until the
 * authentication protocol terminates.
 */
#define	CAP_RAW_MODE			0x0001
#define	CAP_MPX_MODE			0x0002
#define	CAP_UNICODE			0x0004
#define	CAP_LARGE_FILES			0x0008
#define	CAP_NT_SMBS			0x0010
#define	CAP_RPC_REMOTE_APIS		0x0020
#define	CAP_STATUS32			0x0040
#define	CAP_LEVEL_II_OPLOCKS		0x0080
#define	CAP_LOCK_AND_READ		0x0100
#define	CAP_NT_FIND			0x0200
#define	CAP_BULK_TRANSFER		0x0400
#define	CAP_COMPRESSED_BULK		0x0800
#define	CAP_DFS				0x1000
#define	CAP_INFOLEVEL_PASSTHRU		0x2000
#define	CAP_LARGE_READX			0x4000
#define	CAP_LARGE_WRITEX		0x8000
#define	CAP_RESERVED			0x02000000
#define	CAP_EXTENDED_SECURITY		0x80000000


/*
 * Different device types according to NT
 */
#define	FILE_DEVICE_BEEP		0x00000001
#define	FILE_DEVICE_CD_ROM		0x00000002
#define	FILE_DEVICE_CD_ROM_FILE_SYSTEM	0x00000003
#define	FILE_DEVICE_CONTROLLER		0x00000004
#define	FILE_DEVICE_DATALINK		0x00000005
#define	FILE_DEVICE_DFS			0x00000006
#define	FILE_DEVICE_DISK		0x00000007
#define	FILE_DEVICE_DISK_FILE_SYSTEM	0x00000008
#define	FILE_DEVICE_FILE_SYSTEM		0x00000009
#define	FILE_DEVICE_INPORT_PORT		0x0000000a
#define	FILE_DEVICE_KEYBOARD		0x0000000b
#define	FILE_DEVICE_MAILSLOT		0x0000000c
#define	FILE_DEVICE_MIDI_IN		0x0000000d
#define	FILE_DEVICE_MIDI_OUT		0x0000000e
#define	FILE_DEVICE_MOUSE		0x0000000f
#define	FILE_DEVICE_MULTI_UNC_PROVIDER	0x00000010
#define	FILE_DEVICE_NAMED_PIPE		0x00000011
#define	FILE_DEVICE_NETWORK		0x00000012
#define	FILE_DEVICE_NETWORK_BROWSER	0x00000013
#define	FILE_DEVICE_NETWORK_FILE_SYSTEM 0x00000014
#define	FILE_DEVICE_NULL		0x00000015
#define	FILE_DEVICE_PARALLEL_PORT	0x00000016
#define	FILE_DEVICE_PHYSICAL_NETCARD	0x00000017
#define	FILE_DEVICE_PRINTER		0x00000018
#define	FILE_DEVICE_SCANNER		0x00000019
#define	FILE_DEVICE_SERIAL_MOUSE_PORT	0x0000001a
#define	FILE_DEVICE_SERIAL_PORT		0x0000001b
#define	FILE_DEVICE_SCREEN		0x0000001c
#define	FILE_DEVICE_SOUND		0x0000001d
#define	FILE_DEVICE_STREAMS		0x0000001e
#define	FILE_DEVICE_TAPE		0x0000001f
#define	FILE_DEVICE_TAPE_FILE_SYSTEM	0x00000020
#define	FILE_DEVICE_TRANSPORT		0x00000021
#define	FILE_DEVICE_UNKNOWN		0x00000022
#define	FILE_DEVICE_VIDEO		0x00000023
#define	FILE_DEVICE_VIRTUAL_DISK	0x00000024
#define	FILE_DEVICE_WAVE_IN		0x00000025
#define	FILE_DEVICE_WAVE_OUT		0x00000026
#define	FILE_DEVICE_8042_PORT		0x00000027
#define	FILE_DEVICE_NETWORK_REDIRECTOR	0x00000028
#define	FILE_DEVICE_BATTERY		0x00000029
#define	FILE_DEVICE_BUS_EXTENDER	0x0000002a
#define	FILE_DEVICE_MODEM		0x0000002b
#define	FILE_DEVICE_VDM			0x0000002c

/*
 * Some of these device types are not currently accessible over the network
 * and may never be accessible over the network. Some may change to be
 *
 * accessible over the network. The values for device types that may never
 * be accessible over the network may be redefined to be just reserved at
 * some date in the future.
 *
 * Characteristics is the sum of any of the following:
 */

#define	FILE_REMOVABLE_MEDIA		0x00000001
#define	FILE_READ_ONLY_DEVICE		0x00000002
#define	FILE_FLOPPY_DISKETTE		0x00000004
#define	FILE_WRITE_ONE_MEDIA		0x00000008
#define	FILE_REMOTE_DEVICE		0x00000010
#define	FILE_DEVICE_IS_MOUNTED		0x00000020
#define	FILE_VIRTUAL_VOLUME		0x00000040

/*
 * File System Control Flags for smb_com_trans2_query|set_fs_information
 * level SMB_FILE_FS_CONTROL_INFORMATION
 */
#define	FILE_VC_QUOTA_TRACK		0x00000001
#define	FILE_VC_QUOTA_ENFORCE		0x00000002
#define	FILE_VC_CONTENT_INDEX_DISABLED	0x00000008
#define	FILE_VC_LOG_QUOTA_THRESHOLD	0x00000010
#define	FILE_VC_LOG_QUOTA_LIMIT		0x00000020
#define	FILE_VC_LOG_VOLUME_THRESHOLD	0x00000040
#define	FILE_VC_LOG_VOLUME_LIMIT	0x00000080
#define	FILE_VC_QUOTAS_INCOMPLETE	0x00000100
#define	FILE_VC_QUOTAS_REBUILDING	0x00000200

/*
 * CREATE_ANDX ShareAccess Flags
 */

#define	FILE_SHARE_NONE			0x00000000
#define	FILE_SHARE_READ			0x00000001
#define	FILE_SHARE_WRITE		0x00000002
#define	FILE_SHARE_DELETE		0x00000004
#define	FILE_SHARE_ALL			0x00000007
#define	FILE_SHARE_VALID_FLAGS		0x00000007


/*
 * CREATE_ANDX CreateDisposition flags
 *
 * FILE_SUPERSEDE     If the file already exists it should be superseded
 *		      by the specified file. If the file does not already
 *		      exist then it should be created.
 *
 * FILE_CREATE	      If the file already exists the operation should fail.
 *		      If the file does not already exist then it should be
 *		      created. (aka CREATE_NEW)
 *
 * FILE_OPEN	      If the file already exists then it should be opened.
 *		      If the file does not already exist then the operation
 *		      should fail. (aka OPEN_EXISTING)
 *
 * FILE_OPEN_IF	      If the file already exists then it should be opened.
 *		      If the file does not already exist then it should be
 *		      created. (aka OPEN_ALWAYS)
 *
 * FILE_OVERWRITE     If the file already exists, it should be opened and
 *		      overwritten. If the file does not already exist then
 *		      the operation should fail. (aka TRUNCATE_EXISTING)
 *
 * FILE_OVERWRITE_IF  If the file already exists, it should be opened and
 *		      overwritten. If the file does not already exist then
 *		      it should be created. (aka CREATE_ALWAYS)
 */
#define	FILE_SUPERSEDE			0x00000000
#define	FILE_OPEN			0x00000001
#define	FILE_CREATE			0x00000002
#define	FILE_OPEN_IF			0x00000003
#define	FILE_OVERWRITE			0x00000004
#define	FILE_OVERWRITE_IF		0x00000005
#define	FILE_MAXIMUM_DISPOSITION	0x00000005

/*
 * CREATE_ANDX Impersonation levels
 */

#define	SECURITY_ANONYMOUS	0x00000001
#define	SECURITY_IDENTIFICATION	0x00000002
#define	SECURITY_IMPERSONATION	0x00000003
#define	SECURITY_DELEGATION	0x00000004

/*
 * CREATE_ANDX SecurityFlags
 */

#define	SECURITY_CONTEXT_TRACKING	0x00000001
#define	SECURITY_EFFECTIVE_ONLY		0x00000002

/*
 * Server types
 */
#define	SV_WORKSTATION		0x00000001	/* All workstations */
#define	SV_SERVER		0x00000002	/* All servers */
#define	SV_SQLSERVER		0x00000004	/* running with SQL server */
#define	SV_DOMAIN_CTRL		0x00000008	/* Primary domain controller */
#define	SV_DOMAIN_BAKCTRL	0x00000010	/* Backup domain controller */
#define	SV_TIME_SOURCE		0x00000020	/* running timesource service */
#define	SV_AFP			0x00000040	/* Apple File Protocol */
#define	SV_NOVELL		0x00000080	/* Novell servers */
#define	SV_DOMAIN_MEMBER	0x00000100	/* Domain Member */
#define	SV_PRINTQ_SERVER	0x00000200	/* Server sharing print queue */
#define	SV_DIALIN_SERVER	0x00000400	/* Server running dialin */
#define	SV_XENIX_SERVER		0x00000800	/* Xenix server */
#define	SV_NT			0x00001000	/* NT server */
#define	SV_WFW			0x00002000	/* Server running Windows for */
#define	SV_SERVER_NT		0x00008000	/* Windows NT non DC server */
#define	SV_POTENTIAL_BROWSER	0x00010000	/* can run browser service */
#define	SV_BACKUP_BROWSER	0x00020000	/* Backup browser server */
#define	SV_MASTER_BROWSER	0x00040000	/* Master browser server */
#define	SV_DOMAIN_MASTER	0x00080000	/* Domain Master Browser */
#define	SV_OSF			0x00100000	/* OSF operating system */
#define	SV_VMS			0x00200000	/* VMS operating system */
#define	SV_WINDOWS_95_PLUS	0x00400000	/* Windows 95 or better */

#define	SV_LOCAL_LIST_ONLY	0x40000000	/* Enumerate only "local" */
#define	SV_TYPE_DOMAIN_ENUM	0x80000000	/*  Enumerate Domains */

#define	MY_SERVER_TYPE	(SV_SERVER | SV_NT | SV_SERVER_NT)


#define	PRQ_ACTIVE	0	/* Active */
#define	PRQ_PAUSE	1	/* Paused */
#define	PRQ_ERROR	2	/* Error Occurred */
#define	PRQ_PENDING	3	/* Deletion pending */

#define	PRJ_QS_QUEUED	0	/* Active */
#define	PRJ_QS_PAUSED	1	/* Paused */
#define	PRJ_QS_SPOOLING	2	/* Paused */
#define	PRJ_QS_PRINTING	3	/* Paused */


#define	SHARE_ACCESS_READ	0x01	/* read & execute from resource	*/
#define	SHARE_ACCESS_WRITE	0x02	/* write data to resource	*/
#define	SHARE_ACCESS_CREATE	0x04	/* create an instance of	*/
#define	SHARE_ACCESS_EXEC	0x08	/* execute from resource	*/
#define	SHARE_ACCESS_DELETE	0x10	/* Permission to delete the resource */
#define	SHARE_ACCESS_ATTRIB	0x20	/* Permission to modify the resource */
#define	SHARE_ACCESS_PERM	0x40	/* Permission to change permissions */
#define	SHARE_ACCESS_ALL	0x7F	/* All of the above permissions	*/


/*
 * SMB_COM_NT_TRANSACTION sub-command codes (CIFS/1.0 section 5.3)
 *
 * SubCommand Code		   Value Description
 * =============================== ===== =================================
 * NT_TRANSACT_CREATE		   1	 File open/create
 * NT_TRANSACT_IOCTL		   2	 Device IOCTL
 * NT_TRANSACT_SET_SECURITY_DESC   3	 Set security descriptor
 * NT_TRANSACT_NOTIFY_CHANGE	   4	 Start directory watch
 * NT_TRANSACT_RENAME		   5	 Reserved (handle-based rename)
 * NT_TRANSACT_QUERY_SECURITY_DESC 6	 Retrieve security descriptor
 * NT_TRANSACT_QUERY_QUOTA	   7	 Retrieve quota information
 * NT_TRANSACT_SET_QUOTA	   8	 Set quota information
 */
#define	NT_TRANSACT_MIN_FUNCTION	1

#define	NT_TRANSACT_CREATE		1
#define	NT_TRANSACT_IOCTL		2
#define	NT_TRANSACT_SET_SECURITY_DESC	3
#define	NT_TRANSACT_NOTIFY_CHANGE	4
#define	NT_TRANSACT_RENAME		5
#define	NT_TRANSACT_QUERY_SECURITY_DESC 6
#define	NT_TRANSACT_QUERY_QUOTA		7
#define	NT_TRANSACT_SET_QUOTA		8

#define	NT_TRANSACT_MAX_FUNCTION	8


/*
 * Pipe states
 */
#define	SMB_PIPE_READMODE_BYTE		0x0000
#define	SMB_PIPE_READMODE_MESSAGE	0x0100
#define	SMB_PIPE_TYPE_BYTE		0x0000
#define	SMB_PIPE_TYPE_MESSAGE		0x0400
#define	SMB_PIPE_END_CLIENT		0x0000
#define	SMB_PIPE_END_SERVER		0x4000
#define	SMB_PIPE_WAIT			0x0000
#define	SMB_PIPE_NOWAIT			0x8000
#define	SMB_PIPE_UNLIMITED_INSTANCES	0x00FF

/*
 * smb_com_seek request
 */
#define	SMB_SEEK_SET	0 /* set file offset to specified offset */
#define	SMB_SEEK_CUR	1 /* set file offset to current plus specified offset */
#define	SMB_SEEK_END	2 /* set file offset to EOF plus specified offset */

/*
 * API Numbers for Transact based RAP (Remote Administration Protocol) calls
 */
#define	API_WshareEnum			0
#define	API_WshareGetInfo		1
#define	API_WshareSetInfo		2
#define	API_WshareAdd			3
#define	API_WshareDel			4
#define	API_NetShareCheck		5
#define	API_WsessionEnum		6
#define	API_WsessionGetInfo		7
#define	API_WsessionDel			8
#define	API_WconnectionEnum		9
#define	API_WfileEnum			10
#define	API_WfileGetInfo		11
#define	API_WfileClose			12
#define	API_WserverGetInfo		13
#define	API_WserverSetInfo		14
#define	API_WserverDiskEnum		15
#define	API_WserverAdminCommand		16
#define	API_NetAuditOpen		17
#define	API_WauditClear			18
#define	API_NetErrorLogOpen		19
#define	API_WerrorLogClear		20
#define	API_NetCharDevEnum		21
#define	API_NetCharDevGetInfo		22
#define	API_WCharDevControl		23
#define	API_NetCharDevQEnum		24
#define	API_NetCharDevQGetInfo		25
#define	API_WCharDevQSetInfo		26
#define	API_WCharDevQPurge		27
#define	API_WCharDevQPurgeSelf		28
#define	API_WMessageNameEnum		29
#define	API_WMessageNameGetInfo		30
#define	API_WMessageNameAdd		31
#define	API_WMessageNameDel		32
#define	API_WMessageNameFwd		33
#define	API_WMessageNameUnFwd		34
#define	API_WMessageBufferSend		35
#define	API_WMessageFileSend		36
#define	API_WMessageLogFileSet		37
#define	API_WMessageLogFileGet		38
#define	API_WServiceEnum		39
#define	API_WServiceInstall		40
#define	API_WServiceControl		41
#define	API_WAccessEnum			42
#define	API_WAccessGetInfo		43
#define	API_WAccessSetInfo		44
#define	API_WAccessAdd			45
#define	API_WAccessDel			46
#define	API_WGroupEnum			47
#define	API_WGroupAdd			48
#define	API_WGroupDel			49
#define	API_WGroupAddUser		50
#define	API_WGroupDelUser		51
#define	API_WGroupGetUsers		52
#define	API_WUserEnum			53
#define	API_WUserAdd			54
#define	API_WUserDel			55
#define	API_WUserGetInfo		56
#define	API_WUserSetInfo		57
#define	API_WUserPasswordSet		58
#define	API_WUserGetGroups		59
#define	API_DeadTableEntry		60
#define	API_WWkstaSetUID		62
#define	API_WWkstaGetInfo		63
#define	API_WWkstaSetInfo		64
#define	API_WUseEnum			65
#define	API_WUseAdd			66
#define	API_WUseDel			67
#define	API_WUseGetInfo			68
#define	API_WPrintQEnum			69
#define	API_WPrintQGetInfo		70
#define	API_WPrintQSetInfo		71
#define	API_WPrintQAdd			72
#define	API_WPrintQDel			73
#define	API_WPrintQPause		74
#define	API_WPrintQContinue		75
#define	API_WPrintJobEnum		76
#define	API_WPrintJobGetInfo		77
#define	API_WPrintJobSetInfo_OLD	78
#define	API_WPrintJobDel		81
#define	API_WPrintJobPause		82
#define	API_WPrintJobContinue		83
#define	API_WPrintDestEnum		84
#define	API_WPrintDestGetInfo		85
#define	API_WPrintDestControl		86
#define	API_WProfileSave		87
#define	API_WProfileLoad		88
#define	API_WStatisticsGet		89
#define	API_WStatisticsClear		90
#define	API_NetRemoteTOD		91
#define	API_WNetBiosEnum		92
#define	API_WNetBiosGetInfo		93
#define	API_NetServerEnum		94
#define	API_I_NetServerEnum		95
#define	API_WServiceGetInfo		96
#define	API_WPrintQPurge		103
#define	API_NetServerEnum2		104
#define	API_WAccessGetUserPerms		105
#define	API_WGroupGetInfo		106
#define	API_WGroupSetInfo		107
#define	API_WGroupSetUsers		108
#define	API_WUserSetGroups		109
#define	API_WUserModalsGet		110
#define	API_WUserModalsSet		111
#define	API_WFileEnum2			112
#define	API_WUserAdd2			113
#define	API_WUserSetInfo2		114
#define	API_WUserPasswordSet2		115
#define	API_I_NetServerEnum2		116
#define	API_WConfigGet2			117
#define	API_WConfigGetAll2		118
#define	API_WGetDCName			119
#define	API_NetHandleGetInfo		120
#define	API_NetHandleSetInfo		121
#define	API_WStatisticsGet2		122
#define	API_WBuildGetInfo		123
#define	API_WFileGetInfo2		124
#define	API_WFileClose2			125
#define	API_WNetServerReqChallenge	126
#define	API_WNetServerAuthenticate	127
#define	API_WNetServerPasswordSet	128
#define	API_WNetAccountDeltas		129
#define	API_WNetAccountSync		130
#define	API_WUserEnum2			131
#define	API_WWkstaUserLogon		132
#define	API_WWkstaUserLogoff		133
#define	API_WLogonEnum			134
#define	API_WErrorLogRead		135
#define	API_WI_NetPathType		136
#define	API_WI_NetPathCanonicalize	137
#define	API_WI_NetPathCompare		138
#define	API_WI_NetNameValidate		139
#define	API_WI_NetNameCanonicalize	140
#define	API_WI_NetNameCompare		141
#define	API_WAuditRead			142
#define	API_WPrintDestAdd		143
#define	API_WPrintDestSetInfo		144
#define	API_WPrintDestDel		145
#define	API_WUserValidate2		146
#define	API_WPrintJobSetInfo		147
#define	API_TI_NetServerDiskEnum	148
#define	API_TI_NetServerDiskGetInfo	149
#define	API_TI_FTVerifyMirror		150
#define	API_TI_FTAbortVerify		151
#define	API_TI_FTGetInfo		152
#define	API_TI_FTSetInfo		153
#define	API_TI_FTLockDisk		154
#define	API_TI_FTFixError		155
#define	API_TI_FTAbortFix		156
#define	API_TI_FTDiagnoseError		157
#define	API_TI_FTGetDriveStats		158
#define	API_TI_FTErrorGetInfo		160
#define	API_NetAccessCheck		163
#define	API_NetAlertRaise		164
#define	API_NetAlertStart		165
#define	API_NetAlertStop		166
#define	API_NetAuditWrite		167
#define	API_NetIRemoteAPI		168
#define	API_NetServiceStatus		169
#define	API_I_NetServerRegister		170
#define	API_I_NetServerDeregister	171
#define	API_I_NetSessionEntryMake	172
#define	API_I_NetSessionEntryClear	173
#define	API_I_NetSessionEntryGetInfo	174
#define	API_I_NetSessionEntrySetInfo	175
#define	API_I_NetConnectionEntryMake	176
#define	API_I_NetConnectionEntryClear	177
#define	API_I_NetConnectionEntrySetInfo	178
#define	API_I_NetConnectionEntryGetInfo	179
#define	API_I_NetFileEntryMake		180
#define	API_I_NetFileEntryClear		181
#define	API_I_NetFileEntrySetInfo	182
#define	API_I_NetFileEntryGetInfo	183
#define	API_AltSrvMessageBufferSend	184
#define	API_AltSrvMessageFileSend	185
#define	API_wI_NetRplWkstaEnum		186
#define	API_wI_NetRplWkstaGetInfo	187
#define	API_wI_NetRplWkstaSetInfo	188
#define	API_wI_NetRplWkstaAdd		189
#define	API_wI_NetRplWkstaDel		190
#define	API_wI_NetRplProfileEnum	191
#define	API_wI_NetRplProfileGetInfo	192
#define	API_wI_NetRplProfileSetInfo	193
#define	API_wI_NetRplProfileAdd		194
#define	API_wI_NetRplProfileDel		195
#define	API_wI_NetRplProfileClone	196
#define	API_wI_NetRplBaseProfileEnum	197
#define	API_WIServerSetInfo		201
#define	API_WPrintDriverEnum		205
#define	API_WPrintQProcessorEnum	206
#define	API_WPrintPortEnum		207
#define	API_WNetWriteUpdateLog		208
#define	API_WNetAccountUpdate		209
#define	API_WNetAccountConfirmUpdate	210
#define	API_WConfigSet			211
#define	API_WAccountsReplicate		212
#define	API_SamOEMChgPasswordUser2_P	214
#define	API_NetServerEnum3		215
#define	API_WprintDriverGetInfo		250
#define	API_WprintDriverSetInfo		251
#define	API_WaliasAdd			252
#define	API_WaliasDel			253
#define	API_WaliasGetInfo		254
#define	API_WaliasSetInfo		255
#define	API_WaliasEnum			256
#define	API_WuserGetLogonAsn		257
#define	API_WuserSetLogonAsn		258
#define	API_WuserGetAppSel		259
#define	API_WuserSetAppSel		260
#define	API_WappAdd			261
#define	API_WappDel			262
#define	API_WappGetInfo			263
#define	API_WappSetInfo			264
#define	API_WappEnum			265
#define	API_WUserDCDBInit		266
#define	API_WDASDAdd			267
#define	API_WDASDDel			268
#define	API_WDASDGetInfo		269
#define	API_WDASDSetInfo		270
#define	API_WDASDEnum			271
#define	API_WDASDCheck			272
#define	API_WDASDCtl			273
#define	API_WuserRemoteLogonCheck	274
#define	API_WUserPasswordSet3		275
#define	API_WCreateRIPLMachine		276
#define	API_WDeleteRIPLMachine		277
#define	API_WGetRIPLMachineInfo		278
#define	API_WSetRIPLMachineInfo		279
#define	API_WEnumRIPLMachine		280
#define	API_WI_ShareAdd			281
#define	API_WI_AliasEnum		282
#define	API_WaccessApply		283
#define	API_WPrt16Query			284
#define	API_WPrt16Set			285
#define	API_WUserDel100			286
#define	API_WUserRemoteLogonCheck2	287
#define	API_WRemoteTODSet		294
#define	API_WprintJobMoveAll		295
#define	API_W16AppParmAdd		296
#define	API_W16AppParmDel		297
#define	API_W16AppParmGet		298
#define	API_W16AppParmSet		299
#define	API_W16RIPLMachineCreate	300
#define	API_W16RIPLMachineGetInfo	301
#define	API_W16RIPLMachineSetInfo	302
#define	API_W16RIPLMachineEnum		303
#define	API_W16RIPLMachineListParmEnum	304
#define	API_W16RIPLMachClassGetInfo	305
#define	API_W16RIPLMachClassEnum	306
#define	API_W16RIPLMachClassCreate	307
#define	API_W16RIPLMachClassSetInfo	308
#define	API_W16RIPLMachClassDelete	309
#define	API_W16RIPLMachClassLPEnum	310
#define	API_W16RIPLMachineDelete	311
#define	API_W16WSLevelGetInfo		312
#define	API_WserverNameAdd		313
#define	API_WserverNameDel		314
#define	API_WserverNameEnum		315
#define	API_I_WDASDEnum			316
#define	API_I_WDASDEnumTerminate	317
#define	API_I_WDASDSetInfo2		318
#define	MAX_RAP_API			318

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_SMB_H */
