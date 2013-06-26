/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMB_SMB2_H
#define	_SMB_SMB2_H

#ifdef __cplusplus
extern "C" {
#endif

#define	SMB2_PROTOCOL_ID	{ 0xFE, 'S', 'M', 'B' }
#define	SMB2_HDR_SIZE	64

/*
 * SMB2 header command codes.
 * These are uint16_t on the wire.
 */
typedef enum {
	SMB2_NEGOTIATE = 0,
	SMB2_SESSION_SETUP,
	SMB2_LOGOFF,
	SMB2_TREE_CONNECT,
	SMB2_TREE_DISCONNECT,
	SMB2_CREATE,
	SMB2_CLOSE,
	SMB2_FLUSH,
	SMB2_READ,
	SMB2_WRITE,
	SMB2_LOCK,
	SMB2_IOCTL,
	SMB2_CANCEL,
	SMB2_ECHO,
	SMB2_QUERY_DIRECTORY,
	SMB2_CHANGE_NOTIFY,
	SMB2_QUERY_INFO,
	SMB2_SET_INFO,
	SMB2_OPLOCK_BREAK,
	/*
	 * The above (oplock break) is the last real SMB2 op-code.
	 * We use one more slot to represent invalid commands, and
	 * the final enum value is used for array sizes. Keep last!
	 */
	SMB2_INVALID_CMD,
	SMB2__NCMDS
} SMB2_cmd_code;

/*
 * SMB2 header flags.
 */

/*
 * SERVER_TO_REDIR
 * When set, indicates the message is a response rather than
 * a request. This MUST be set on responses sent from the
 * server to the client, and MUST NOT be set on requests
 * sent from the client to the server.
 */
#define	SMB2_FLAGS_SERVER_TO_REDIR	0x00000001

/*
 * ASYNC_COMMAND
 * When set, indicates that this is an ASYNC SMB2 header.
 * Always set for headers of the form described in this
 * section.
 */
#define	SMB2_FLAGS_ASYNC_COMMAND	0x00000002

/*
 * RELATED_OPERATIONS
 * When set in an SMB2 request, indicates that this request
 * is a related operation in a compounded request chain.
 * [MS-SMB2 sec. 3.2.4.1.4]
 *
 * When set in an SMB2 compound response, indicates that
 * the request corresponding to this response was part of a
 * related operation in a compounded request chain.
 * [MS-SMB2 sec. 3.3.5.2.7.2]
 */
#define	SMB2_FLAGS_RELATED_OPERATIONS	0x00000004

/*
 * SIGNED
 * When set, indicates that this packet has been signed.
 * [MS-SMB2 3.1.5.1]
 */
#define	SMB2_FLAGS_SIGNED	0x00000008

/*
 * [MS-SMB2] 3.2.5.3.1 The SessionKey MUST be set to the
 * first 16 bytes of the cryptographic key from GSSAPI.
 * (Padded with zeros if the GSSAPI key is shorter.)
 */
#define	SMB2_SESSION_KEY_LEN	16

/*
 * DFS_OPERATIONS
 * When set, indicates that this command is a Distributed
 * File System (DFS) operation.  [MS-SMB2 3.3.5.9]
 */
#define	SMB2_FLAGS_DFS_OPERATIONS	0x10000000

/*
 * REPLAY_OPERATION
 * This flag is only valid for the SMB 3.0 dialect. When set,
 * it indicates that this command is a replay operation.
 * The client MUST ignore this bit on receipt.
 */
#define	SMB2_FLAGS_REPLAY_OPERATION	0x20000000

/*
 * SMB2 Netgotiate [MS-SMB2 2.2.3]
 */

#define	SMB2_NEGOTIATE_SIGNING_ENABLED   0x01
#define	SMB2_NEGOTIATE_SIGNING_REQUIRED  0x02

#define	SMB2_CAP_DFS			0x00000001

/* Added with SMB2.1 */
#define	SMB2_CAP_DFS			0x00000001
#define	SMB2_CAP_LEASING		0x00000002
/*
 * LARGE_MTU:
 * When set, indicates that the client supports multi-credit operations.
 */
#define	SMB2_CAP_LARGE_MTU		0x00000004

/* Added with SMB3.0 */
#define	SMB2_CAP_MULTI_CHANNEL		0x00000008
#define	SMB2_CAP_PERSISTENT_HANDLES	0x00000010
#define	SMB2_CAP_DIRECTORY_LEASING	0x00000020
#define	SMB2_CAP_ENCRYPTION		0x00000040

/* SMB2 session flags */
#define	SMB2_SESSION_FLAG_IS_GUEST	0x0001
#define	SMB2_SESSION_FLAG_IS_NULL	0x0002
#define	SMB2_SESSION_FLAG_ENCRYPT_DATA	0x0004

/*
 * SMB2 Tree connect, disconnect
 */

/* SMB2 sharetype flags */
#define	SMB2_SHARE_TYPE_DISK		0x1
#define	SMB2_SHARE_TYPE_PIPE		0x2
#define	SMB2_SHARE_TYPE_PRINT		0x3

/* SMB2 share flags */
#define	SMB2_SHAREFLAG_MANUAL_CACHING			0x00000000
#define	SMB2_SHAREFLAG_AUTO_CACHING			0x00000010
#define	SMB2_SHAREFLAG_VDO_CACHING			0x00000020
#define	SMB2_SHAREFLAG_NO_CACHING			0x00000030
#define	SMB2_SHAREFLAG_DFS				0x00000001
#define	SMB2_SHAREFLAG_DFS_ROOT				0x00000002
#define	SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS		0x00000100
#define	SMB2_SHAREFLAG_FORCE_SHARED_DELETE		0x00000200
#define	SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING		0x00000400
#define	SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM	0x00000800
#define	SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK		0x00001000
/* SMB 3.0 */
#define	SMB2_SHAREFLAG_ENABLE_HASH_V1			0x00002000
#define	SMB2_SHAREFLAG_ENABLE_HASH_V2			0x00004000
#define	SMB2_SHAREFLAG_ENCRYPT_DATA			0x00008000

/* SMB2 share capabilities */
#define	SMB2_SHARE_CAP_DFS				0x00000008
/* SMB 3.0 */
#define	SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY		0x00000010
#define	SMB2_SHARE_CAP_SCALEOUT				0x00000020
#define	SMB2_SHARE_CAP_CLUSTER				0x00000040

/*
 * SMB2 Create (open)
 */

/* SMB2 requested oplock levels */
#define	SMB2_OPLOCK_LEVEL_NONE				0x00
#define	SMB2_OPLOCK_LEVEL_II				0x01
#define	SMB2_OPLOCK_LEVEL_EXCLUSIVE			0x08
#define	SMB2_OPLOCK_LEVEL_BATCH				0x09
#define	SMB2_OPLOCK_LEVEL_LEASE				0xFF

/* SMB2 impersonation levels */
#define	SMB2_IMPERSONATION_ANONYMOUS			0x00
#define	SMB2_IMPERSONATION_IDENTIFICATION		0x01
#define	SMB2_IMPERSONATION_IMPERSONATION		0x02
#define	SMB2_IMPERSONATION_DELEGATE			0x03

/*
 * Note: ShareAccess, CreateDispositon, CreateOptions,
 * all use the same definitions as SMB1 (from MS-FSA).
 * Ditto FileAccess flags (as with ACLs)
 */

/* SMB2 Create Context tags */

#define	SMB2_CREATE_EA_BUFFER			0x45787441 /* ("ExtA") */
/*
 * The data contains the extended attributes
 * that MUST be stored on the created file.
 * This value MUST NOT be set for named
 * pipes and print files.
 */

#define	SMB2_CREATE_SD_BUFFER			0x53656344 /* ("SecD") */
/*
 * The data contains a security descriptor that
 * MUST be stored on the created file.
 * This value MUST NOT be set for named
 * pipes and print files.
 */

#define	SMB2_CREATE_DURABLE_HANDLE_REQUEST	0x44486e51 /* ("DHnQ") */
/* The client is requesting the open to be durable */

#define	SMB2_CREATE_DURABLE_HANDLE_RECONNECT	0x44486e43 /* ("DHnC") */
/*
 * The client is requesting to reconnect to a
 * durable open after being disconnected
 */

#define	SMB2_CREATE_ALLOCATION_SIZE		0x416c5369 /* ("AISi") */
/*
 * The data contains the required allocation
 * size of the newly created file.
 */

#define	SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQ	0x4d784163 /* ("MxAc") */
/*
 * The client is requesting that the server
 * return maximal access information.
 */

#define	SMB2_CREATE_TIMEWARP_TOKEN		0x54577270 /* ("TWrp") */
/*
 * The client is requesting that the server
 * open an earlier version of the file identified
 * by the provided time stamp.
 */

#define	SMB2_CREATE_QUERY_ON_DISK_ID		0x51466964 /* ("QFid") */
/*
 * The client is requesting that the server return a 32-byte
 * opaque BLOB that uniquely identifies the file being opened
 * on disk. No data is passed to the server by the client.
 */

#define	SMB2_CREATE_REQUEST_LEASE		0x52714c73 /* ("RqLs") */
/*
 * The client is requesting that the server return a lease.
 * This value is only supported for the SMB 2.1 and 3.0 dialects.
 */

/* SMB2 create request lease */
#define	SMB2_LEASE_NONE				0x00
#define	SMB2_LEASE_READ_CACHING			0x01
#define	SMB2_LEASE_HANDLE_CACHING		0x02
#define	SMB2_LEASE_WRITE_CACHING		0x04

/* SMB2 lease break notification flags */
#define	SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED  0x01

/*
 * SMB2 Close
 */
#define	SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB 	0x0001

/*
 * SMB2 Write
 */
#define	SMB2_WRITEFLAG_WRITE_THROUGH		0x00000001

/*
 * SMB2 Lock Request
 */

/* SMB2 lock flags */

/*
 * SMB2_LOCKFLAG_SHARED_LOCK
 * The range MUST be locked shared, allowing other opens
 * to read from or take a shared lock on the range. All opens
 * MUST NOT be allowed to write within the range. Other
 * locks can be requested and taken on this range.
 */
#define	SMB2_LOCKFLAG_SHARED_LOCK	0x00000001

/*
 * SMB2_LOCKFLAG_EXCLUSIVE_LOCK
 * The range MUST be locked exclusive, not allowing other
 * opens to read, write, or lock within the range.
 */
#define	SMB2_LOCKFLAG_EXCLUSIVE_LOCK	0x00000002

/*
 * SMB2_LOCKFLAG_UNLOCK
 * The range MUST be unlocked from a previous lock taken
 * on this range. The unlock range MUST be identical to the
 * lock range. Sub-ranges cannot be unlocked.
 */
#define	SMB2_LOCKFLAG_UNLOCK		0x00000004

/*
 * SMB2_LOCKFLAG_FAIL_IMMEDIATELY
 * The lock operation MUST fail immediately if it conflicts
 * with an existing lock, instead of waiting for the range to
 * become available.  This can be OR'ed with either of
 * shared_lock, exclusive_lock (nothing else).
 */
#define	SMB2_LOCKFLAG_FAIL_IMMEDIATELY	0x00000010

/*
 * SMB2 Ioctl Request
 */
#define	SMB2_0_IOCTL_IS_FSCTL 		0x00000001


/*
 * SMB2 Query Directory
 */

/*
 * SMB2 query directory info levels
 * Same as SMB1 (see ntifs.h)
 */

/*
 * SMB2 Query Directory Flags
 * (our own names for these - spec. used poor names)
 */
#define	SMB2_QDIR_FLAG_RESTART		0x01 /* SMB2_RESTART_SCANS */
#define	SMB2_QDIR_FLAG_SINGLE		0x02 /* SMB2_RETURN_SINGLE_ENTRY */
#define	SMB2_QDIR_FLAG_INDEX		0x04 /* SMB2_INDEX_SPECIFIED */
#define	SMB2_QDIR_FLAG_REOPEN		0x10 /* SMB2_REOPEN */

/*
 * SMB2 Query Info Request
 */

/* info type */
#define	SMB2_0_INFO_FILE		0x01
/* The file information is requested. */
#define	SMB2_0_INFO_FILESYSTEM		0x02
/* The underlying object store information is requested. */
#define	SMB2_0_INFO_SECURITY		0x03
/* The security information is requested. */
#define	SMB2_0_INFO_QUOTA		0x04
/* The underlying object store quota information is requested. */

/*
 * SMB2 Change Nofity Request
 */
#define	SMB2_WATCH_TREE			0x00000001

#ifdef __cplusplus
}
#endif

#endif /* _SMB_SMB2_H */
