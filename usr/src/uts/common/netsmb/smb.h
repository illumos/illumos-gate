/*
 * Copyright (c) 2000-2001 Boris Popov
 * All rights reserved.
 *
 * Now many of these defines are from samba4 code, by Andrew Tridgell.
 * (Permission given to Conrad Minshall at CIFS plugfest Aug 13 2003.)
 * (Note the main decision was whether to use defines found in MS includes
 * and web pages, versus Samba, and the deciding factor is which developers
 * are more likely to be looking at this code base.)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: smb.h,v 1.36.90.1 2005/05/27 02:35:29 lindak Exp $
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _NETSMB_SMB_H_
#define	_NETSMB_SMB_H_

/*
 * Common definitions and structures for SMB/CIFS protocol
 * This file should be purely SMB protocol definition stuff.
 * (Please don't make it a catch-all:)
 */

#include <smb/doserror.h>
#include <smb/lmerr.h>
#include <smb/nterror.h>
#include <smb/ntstatus.h>

/*
 * SMB dialects that we have to deal with.
 */
enum smb_dialects {
	SMB_DIALECT_NONE,
	SMB_DIALECT_CORE,		/* PC NETWORK PROGRAM 1.0, PCLAN1.0 */
	SMB_DIALECT_COREPLUS,		/* MICROSOFT NETWORKS 1.03 */
	SMB_DIALECT_LANMAN1_0,		/* MICROSOFT NETWORKS 3.0, LANMAN1.0 */
	SMB_DIALECT_LANMAN2_0,		/* LM1.2X002, DOS LM1.2X002, Samba */
	SMB_DIALECT_LANMAN2_1,		/* DOS LANMAN2.1, LANMAN2.1 */
	SMB_DIALECT_NTLM0_12,		/* NT LM 0.12, etc. */
	SMB_DIALECT_SMB2_FF		/* SMB1 negotiate to SMB2 */
};

/*
 * Formats of data/string buffers
 */
#define	SMB_DT_DATA		1
#define	SMB_DT_DIALECT		2
#define	SMB_DT_PATHNAME		3
#define	SMB_DT_ASCII		4
#define	SMB_DT_VARIABLE		5

/*
 * SMB header
 */

#define	SMB_SIGNATURE		"\xFFSMB"
#define	SMB_SIGLEN		4
#define	SMB_HDRCMD(p)		(*((uchar_t *)(p) + SMB_SIGLEN))
#define	SMB_HDRMID(p)		(*(ushort_t *)((uchar_t *)(p) + 30))
#define	SMB_HDR_OFF_MID		30
#define	SMB_HDRLEN		32

#define	SMB_HDR_V1	0xFF
#define	SMB_HDR_V2	0xFE
#define	SMB_HDR_V3E	0xFD	/* SMB3 encrypted */

/*
 * bits in the smb_flags field
 */
#define	SMB_FLAGS_SUPPORT_LOCKREAD	0x01
#define	SMB_FLAGS_CLIENT_BUF_AVAIL	0x02
#define	SMB_FLAGS_CASELESS		0x08
#define	SMB_FLAGS_CANONICAL_PATHNAMES	0x10
#define	SMB_FLAGS_REQUEST_OPLOCK	0x20
#define	SMB_FLAGS_REQUEST_BATCH_OPLOCK	0x40
#define	SMB_FLAGS_SERVER_RESP		0x80

/*
 * bits in the smb_flags2 field
 */
#define	SMB_FLAGS2_KNOWS_LONG_NAMES	0x0001
#define	SMB_FLAGS2_KNOWS_EAS		0x0002	/* client know about EAs */
#define	SMB_FLAGS2_SECURITY_SIGNATURE	0x0004	/* check SMB integrity */
#define	SMB_FLAGS2_IS_LONG_NAME		0x0040	/* any path name is long name */
#define	SMB_FLAGS2_EXT_SEC		0x0800	/* client aware of Extended */
						/* Security negotiation */
#define	SMB_FLAGS2_DFS			0x1000	/* resolve paths in DFS */
#define	SMB_FLAGS2_PAGING_IO		0x2000	/* for exec */
#define	SMB_FLAGS2_ERR_STATUS		0x4000	/* 1 - status.status */
#define	SMB_FLAGS2_UNICODE		0x8000	/* use Unicode for strings */

#define	SMB_UID_UNKNOWN		0xffff
#define	SMB_TID_UNKNOWN		0xffff
#define	SMB_FID_UNUSED		0xffff

/*
 * Security mode bits
 */
#define	SMB_SM_USER		0x01	/* server in the user security mode */
#define	SMB_SM_ENCRYPT		0x02	/* use challenge/responce */
#define	SMB_SM_SIGS		0x04
#define	SMB_SM_SIGS_REQUIRE	0x08

/*
 * Action bits in session setup reply
 */
#define	SMB_ACT_GUEST		0x01

/*
 * NTLM capabilities
 */
#define	SMB_CAP_RAW_MODE		0x0001
#define	SMB_CAP_MPX_MODE		0x0002
#define	SMB_CAP_UNICODE			0x0004
#define	SMB_CAP_LARGE_FILES		0x0008	/* 64 bit offsets supported */
#define	SMB_CAP_NT_SMBS			0x0010
#define	SMB_CAP_RPC_REMOTE_APIS		0x0020
#define	SMB_CAP_STATUS32		0x0040
#define	SMB_CAP_LEVEL_II_OPLOCKS	0x0080
#define	SMB_CAP_LOCK_AND_READ		0x0100
#define	SMB_CAP_NT_FIND			0x0200
#define	SMB_CAP_DFS			0x1000
#define	SMB_CAP_INFOLEVEL_PASSTHRU	0x2000
#define	SMB_CAP_LARGE_READX		0x4000
#define	SMB_CAP_LARGE_WRITEX		0x8000
#define	SMB_CAP_UNIX			0x00800000
#define	SMB_CAP_BULK_TRANSFER		0x20000000
#define	SMB_CAP_COMPRESSED_DATA		0x40000000
#define	SMB_CAP_EXT_SECURITY		0x80000000

/* SMB_COM_TREE_CONNECT_ANDX  flags. See [MS-SMB] for a complete description. */
#define	TREE_CONNECT_ANDX_DISCONNECT_TID		0x0001
#define	TREE_CONNECT_ANDX_EXTENDED_SIGNATURES	0x0004
#define	TREE_CONNECT_ANDX_EXTENDED_RESPONSE		0x0008

/*
 * SMB_COM_TREE_CONNECT_ANDX  optional support flags. See [MS-SMB] for a
 * complete description.
 */
#define	SMB_SUPPORT_SEARCH_BITS		0x0001	/* supports SearchAttributes */
#define	SMB_SHARE_IS_IN_DFS		0x0002	/* share is managed by DFS */
#define	SMB_CSC_MASK			0x000C	/* Offline-caching bits. */
#define	SMB_UNIQUE_FILE_NAME		0x0010	/* Long file names only */
#define	SMB_EXTENDED_SIGNATURES		0x0020	/* Signing key protection. */
/* See [MS-SMB] for a complete description of SMB_CSC_MASK bits. */
#define	SMB_CSC_CACHE_MANUAL_REINT	0x0000
#define	SMB_CSC_CACHE_AUTO_REINT	0x0004
#define	SMB_CSC_CACHE_VDO		0x0008

/*
 * File attributes
 */
#define	SMB_FA_RDONLY		0x01
#define	SMB_FA_HIDDEN		0x02
#define	SMB_FA_SYSTEM		0x04
#define	SMB_FA_VOLUME		0x08
#define	SMB_FA_DIR		0x10
#define	SMB_FA_ARCHIVE		0x20

/*
 * Extended file attributes
 */
#define	SMB_EFA_RDONLY			0x00000001
#define	SMB_EFA_HIDDEN			0x00000002
#define	SMB_EFA_SYSTEM			0x00000004
#define	SMB_EFA_VOLUME			0x00000008
#define	SMB_EFA_DIRECTORY		0x00000010
#define	SMB_EFA_ARCHIVE			0x00000020
#define	SMB_EFA_DEVICE			0x00000040
#define	SMB_EFA_NORMAL			0x00000080
#define	SMB_EFA_TEMPORARY		0x00000100
#define	SMB_EFA_SPARSE			0x00000200
#define	SMB_EFA_REPARSE_POINT		0x00000400
#define	SMB_EFA_COMPRESSED		0x00000800
#define	SMB_EFA_OFFLINE			0x00001000
#define	SMB_EFA_NONINDEXED		0x00002000
#define	SMB_EFA_ENCRYPTED		0x00004000
#define	SMB_EFA_POSIX_SEMANTICS		0x01000000
#define	SMB_EFA_BACKUP_SEMANTICS	0x02000000
#define	SMB_EFA_DELETE_ON_CLOSE		0x04000000
#define	SMB_EFA_SEQUENTIAL_SCAN		0x08000000
#define	SMB_EFA_RANDOM_ACCESS		0x10000000
#define	SMB_EFA_NO_BUFFERING		0x20000000
#define	SMB_EFA_WRITE_THROUGH		0x80000000

/*
 * Access Mode Encoding
 */
#define	SMB_AM_OPENREAD		0x0000
#define	SMB_AM_OPENWRITE	0x0001
#define	SMB_AM_OPENRW		0x0002
#define	SMB_AM_OPENEXEC		0x0003
#define	SMB_AM_OPENMODE		0x0003	/* mask for access mode bits */
#define	SMB_SM_COMPAT		0x0000
#define	SMB_SM_EXCLUSIVE	0x0010
#define	SMB_SM_DENYWRITE	0x0020
#define	SMB_SM_DENYREADEXEC	0x0030
#define	SMB_SM_DENYNONE		0x0040

/* NT_CREATE_ANDX flags */
#define	NTCREATEX_FLAGS_REQUEST_OPLOCK		0x02
#define	NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK	0x04
#define	NTCREATEX_FLAGS_OPEN_DIRECTORY		0x08
#define	NTCREATEX_FLAGS_EXTENDED		0x10

/* NT_CREATE_ANDX share_access (share mode) */
#define	NTCREATEX_SHARE_ACCESS_NONE		0
#define	NTCREATEX_SHARE_ACCESS_READ		1
#define	NTCREATEX_SHARE_ACCESS_WRITE		2
#define	NTCREATEX_SHARE_ACCESS_DELETE		4
#define	NTCREATEX_SHARE_ACCESS_ALL		7

/* NT_CREATE_ANDX open_disposition */
#define	NTCREATEX_DISP_SUPERSEDE	0 /* if file exists supersede it */
#define	NTCREATEX_DISP_OPEN		1 /* exists ? open it : fail */
#define	NTCREATEX_DISP_CREATE		2 /* exists ? fail : create it */
#define	NTCREATEX_DISP_OPEN_IF		3 /* exists ? open it : create it */
#define	NTCREATEX_DISP_OVERWRITE	4 /* exists ? overwrite : fail */
#define	NTCREATEX_DISP_OVERWRITE_IF	5 /* exists ? overwrite : create */

/* NT_CREATE_ANDX create_options */
#define	NTCREATEX_OPTIONS_DIRECTORY		0x0001
#define	NTCREATEX_OPTIONS_WRITE_THROUGH		0x0002
#define	NTCREATEX_OPTIONS_SEQUENTIAL_ONLY	0x0004
#define	NTCREATEX_OPTIONS_SYNC_ALERT		0x0010
#define	NTCREATEX_OPTIONS_ASYNC_ALERT		0x0020
#define	NTCREATEX_OPTIONS_NON_DIRECTORY_FILE	0x0040
#define	NTCREATEX_OPTIONS_NO_EA_KNOWLEDGE	0x0200
#define	NTCREATEX_OPTIONS_EIGHT_DOT_THREE_ONLY	0x0400
#define	NTCREATEX_OPTIONS_RANDOM_ACCESS		0x0800
#define	NTCREATEX_OPTIONS_DELETE_ON_CLOSE	0x1000
#define	NTCREATEX_OPTIONS_OPEN_BY_FILE_ID	0x2000

/* NT_CREATE_ANDX "impersonation" */
#define	NTCREATEX_IMPERSONATION_ANONYMOUS		0
#define	NTCREATEX_IMPERSONATION_IDENTIFICATION		1
#define	NTCREATEX_IMPERSONATION_IMPERSONATION		2
#define	NTCREATEX_IMPERSONATION_DELEGATION		3

/* NT_CREATE_ANDX security flags */
#define	NTCREATEX_SECURITY_DYNAMIC	1
#define	NTCREATEX_SECURITY_ALL		2

/* NT_CREATE_ANDX create_action in reply */
#define	NTCREATEX_ACTION_EXISTED	1
#define	NTCREATEX_ACTION_CREATED	2
#define	NTCREATEX_ACTION_TRUNCATED	3

/* SMB_TRANS2_FIND_FIRST2/SMB_TRANS2_FIND_NEXT2 flags */
#define	FIND2_CLOSE_AFTER_REQUEST	0x0001
#define	FIND2_CLOSE_ON_EOS		0x0002
#define	FIND2_RETURN_RESUME_KEYS	0x0004
#define	FIND2_CONTINUE_SEARCH		0x0008
#define	FIND2_BACKUP_INTENT		0x0010

/*
 * SMB commands
 */
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
#define	SMB_COM_NT_TRANSACT		0xA0
#define	SMB_COM_NT_TRANSACT_SECONDARY	0xA1
#define	SMB_COM_NT_CREATE_ANDX		0xA2
#define	SMB_COM_NT_CANCEL		0xA4
#define	SMB_COM_OPEN_PRINT_FILE		0xC0
#define	SMB_COM_WRITE_PRINT_FILE	0xC1
#define	SMB_COM_CLOSE_PRINT_FILE	0xC2
#define	SMB_COM_GET_PRINT_QUEUE		0xC3
#define	SMB_COM_READ_BULK		0xD8
#define	SMB_COM_WRITE_BULK		0xD9
#define	SMB_COM_WRITE_BULK_DATA		0xDA

/*
 * SMB_COM_TRANSACTION2 subcommands
 */
#define	SMB_TRANS2_OPEN2			0x00
#define	SMB_TRANS2_FIND_FIRST2			0x01
#define	SMB_TRANS2_FIND_NEXT2			0x02
#define	SMB_TRANS2_QUERY_FS_INFORMATION		0x03
#define	SMB_TRANS2_SETFSINFO			0x04
#define	SMB_TRANS2_QUERY_PATH_INFORMATION	0x05
#define	SMB_TRANS2_SET_PATH_INFORMATION		0x06
#define	SMB_TRANS2_QUERY_FILE_INFORMATION	0x07
#define	SMB_TRANS2_SET_FILE_INFORMATION		0x08
#define	SMB_TRANS2_FSCTL			0x09
#define	SMB_TRANS2_IOCTL2			0x0A
#define	SMB_TRANS2_FIND_NOTIFY_FIRST		0x0B
#define	SMB_TRANS2_FIND_NOTIFY_NEXT		0x0C
#define	SMB_TRANS2_CREATE_DIRECTORY		0x0D
#define	SMB_TRANS2_SESSION_SETUP		0x0E
#define	SMB_TRANS2_GET_DFS_REFERRAL		0x10
#define	SMB_TRANS2_REPORT_DFS_INCONSISTENCY	0x11

/*
 * SMB_COM_NT_TRANSACT subcommands
 */
#define	NT_TRANSACT_CREATE		0x01
#define	NT_TRANSACT_IOCTL		0x02
#define	NT_TRANSACT_SET_SECURITY_DESC	0x03
#define	NT_TRANSACT_NOTIFY_CHANGE	0x04
#define	NT_TRANSACT_RENAME		0x05
#define	NT_TRANSACT_QUERY_SECURITY_DESC	0x06
#define	NT_TRANSACT_GET_USER_QUOTA	0x07
#define	NT_TRANSACT_SET_USER_QUOTA	0x08

/*
 * SMB_TRANS2_QUERY_FS_INFORMATION levels
 */
#define	SMB_QFS_ALLOCATION			1
#define	SMB_QFS_VOLUME				2
#define	SMB_QFS_LABEL_INFO			0x101
#define	SMB_QFS_VOLUME_INFO			0x102
#define	SMB_QFS_SIZE_INFO			0x103
#define	SMB_QFS_DEVICE_INFO			0x104
#define	SMB_QFS_ATTRIBUTE_INFO			0x105
#define	SMB_QFS_UNIX_INFO			0x200
#define	SMB_QFS_POSIX_WHOAMI			0x202
#define	SMB_QFS_MAC_FS_INFO			0x301
#define	SMB_QFS_VOLUME_INFORMATION		1001
#define	SMB_QFS_SIZE_INFORMATION		1003
#define	SMB_QFS_DEVICE_INFORMATION		1004
#define	SMB_QFS_ATTRIBUTE_INFORMATION		1005
#define	SMB_QFS_QUOTA_INFORMATION		1006
#define	SMB_QFS_FULL_SIZE_INFORMATION		1007
#define	SMB_QFS_OBJECTID_INFORMATION		1008

/*
 * NT Notify Change Compeletion Filter
 * NT Notify Actions
 * (We don't use these.)
 */

/*
 * SMB_QFS_ATTRIBUTE_INFO bits.
 * The following info found in msdn
 * (http://msdn.microsoft.com/library/default.asp?
 * url=/library/en-us/wmisdk/wmi/win32_cdromdrive.asp)
 * Naming is mostly as in samba, to help Those Who Google.
 */
#define	FILE_CASE_SENSITIVE_SEARCH	0x00000001
#define	FILE_CASE_PRESERVED_NAMES	0x00000002
#define	FILE_UNICODE_ON_DISK		0x00000004
#define	FILE_PERSISTENT_ACLS		0x00000008
#define	FILE_FILE_COMPRESSION		0x00000010
#define	FILE_VOLUME_QUOTAS		0x00000020
#define	FILE_SUPPORTS_SPARSE_FILES	0x00000040
#define	FILE_SUPPORTS_REPARSE_POINTS	0x00000080
#define	FILE_SUPPORTS_REMOTE_STORAGE	0x00000100
#define	FILE_SUPPORTS_LONG_NAMES	0x00004000
#define	FILE_VOLUME_IS_COMPRESSED	0x00008000
#define	FILE_SUPPORTS_OBJECT_IDS	0x00010000
#define	FILE_SUPPORTS_ENCRYPTION	0x00020000
#define	FILE_NAMED_STREAMS		0x00040000
#define	FILE_READ_ONLY_VOLUME		0x00080000

/*
 * SMB_TRANS2_QUERY_PATH levels
 */
#define	SMB_QFILEINFO_STANDARD			1
#define	SMB_QFILEINFO_EA_SIZE			2
#define	SMB_QFILEINFO_EAS_FROM_LIST		3
#define	SMB_QFILEINFO_ALL_EAS			4
#define	SMB_QFILEINFO_IS_NAME_VALID		6	/* QPATHINFO only? */
#define	SMB_QFILEINFO_BASIC_INFO		0x101
#define	SMB_QFILEINFO_STANDARD_INFO		0x102
#define	SMB_QFILEINFO_EA_INFO			0x103
#define	SMB_QFILEINFO_NAME_INFO			0x104
#define	SMB_QFILEINFO_ALLOCATION_INFO		0x105
#define	SMB_QFILEINFO_END_OF_FILE_INFO		0x106
#define	SMB_QFILEINFO_ALL_INFO			0x107
#define	SMB_QFILEINFO_ALT_NAME_INFO		0x108
#define	SMB_QFILEINFO_STREAM_INFO		0x109
#define	SMB_QFILEINFO_COMPRESSION_INFO		0x10b
#define	SMB_QFILEINFO_UNIX_BASIC		0x200
#define	SMB_QFILEINFO_UNIX_LINK			0x201
#define	SMB_QFILEINFO_POSIX_ACL			0x204
#define	SMB_QFILEINFO_UNIX_INFO2		0x20B
#define	SMB_QFILEINFO_MAC_DT_GET_APPL		0x306
#define	SMB_QFILEINFO_MAC_DT_GET_ICON		0x307
#define	SMB_QFILEINFO_MAC_DT_GET_ICON_INFO	0x308
#define	SMB_QFILEINFO_MAC_SPOTLIGHT		0x310
#define	SMB_QFILEINFO_BASIC_INFORMATION		1004
#define	SMB_QFILEINFO_STANDARD_INFORMATION	1005
#define	SMB_QFILEINFO_INTERNAL_INFORMATION	1006
#define	SMB_QFILEINFO_EA_INFORMATION		1007
#define	SMB_QFILEINFO_ACCESS_INFORMATION	1008
#define	SMB_QFILEINFO_NAME_INFORMATION		1009
#define	SMB_QFILEINFO_POSITION_INFORMATION	1014
#define	SMB_QFILEINFO_MODE_INFORMATION		1016
#define	SMB_QFILEINFO_ALIGNMENT_INFORMATION	1017
#define	SMB_QFILEINFO_ALL_INFORMATION		1018
#define	SMB_QFILEINFO_ALT_NAME_INFORMATION	1021
#define	SMB_QFILEINFO_STREAM_INFORMATION	1022
#define	SMB_QFILEINFO_COMPRESSION_INFORMATION	1028
#define	SMB_QFILEINFO_NETWORK_OPEN_INFORMATION	1034
#define	SMB_QFILEINFO_ATTRIBUTE_TAG_INFORMATION 1035

/*
 * SMB_TRANS2_FIND_FIRST2 information levels
 */
#define	SMB_FIND_STANDARD		1
#define	SMB_FIND_EA_SIZE		2
#define	SMB_FIND_EAS_FROM_LIST		3
#define	SMB_FIND_DIRECTORY_INFO		0x101
#define	SMB_FIND_FULL_DIRECTORY_INFO	0x102
#define	SMB_FIND_NAME_INFO		0x103
#define	SMB_FIND_BOTH_DIRECTORY_INFO	0x104
#define	SMB_FIND_UNIX_INFO		0x200
/* Transact 2 Find First levels */
#define	SMB_FIND_FILE_UNIX		0x202
#define	SMB_FIND_FILE_UNIX_INFO2	0x20B /* UNIX File Info2 */

/*
 * Selectors for NT_TRANSACT_QUERY_SECURITY_DESC and
 * NT_TRANSACT_SET_SECURITY_DESC.  Details found in the MSDN
 * library by searching on security_information.
 * Note the protected/unprotected bits did not exist in NT.
 */

#define	OWNER_SECURITY_INFORMATION		0x00000001
#define	GROUP_SECURITY_INFORMATION		0x00000002
#define	DACL_SECURITY_INFORMATION		0x00000004
#define	SACL_SECURITY_INFORMATION		0x00000008
#define	UNPROTECTED_SACL_SECURITY_INFORMATION	0x10000000
#define	UNPROTECTED_DACL_SECURITY_INFORMATION	0x20000000
#define	PROTECTED_SACL_SECURITY_INFORMATION	0x40000000
#define	PROTECTED_DACL_SECURITY_INFORMATION	0x80000000

/*
 * security descriptor header
 * it is followed by the optional SIDs and ACLs
 * note this is "raw", ie little-endian
 */
struct ntsecdesc {
	uint8_t		sd_revision;	/* 0x01 observed between W2K */
	uint8_t		sd_pad1;
	uint16_t	sd_flags;
	uint32_t	sd_owneroff;	/* offset to owner SID */
	uint32_t	sd_groupoff;	/* offset to group SID */
	uint32_t	sd_sacloff;	/* offset to system/audit ACL */
	uint32_t	sd_dacloff;	/* offset to discretionary ACL */
}; /* XXX: __attribute__((__packed__)); */
typedef struct ntsecdesc ntsecdesc_t;

#define	wset_sdrevision(s) ((s)->sd_revision = 0x01)
#define	sdflags(s) (letohs((s)->sd_flags))
#define	wset_sdflags(s, f) ((s)->sd_flags = letohs(f))
#define	sdowner(s) \
	((struct ntsid *)((s)->sd_owneroff ? \
	(char *)(s) + letohl((s)->sd_owneroff) : \
	NULL))
#define	wset_sdowneroff(s, o) ((s)->sd_owneroff = htolel(o))
#define	sdgroup(s) \
	((struct ntsid *)((s)->sd_groupoff ? \
	(char *)(s) + letohl((s)->sd_groupoff) : \
	NULL))
#define	wset_sdgroupoff(s, o) ((s)->sd_groupoff = htolel(o))
#define	sdsacl(s) \
	((struct ntacl *)((s)->sd_sacloff ? \
	(char *)(s) + letohl((s)->sd_sacloff) : \
	NULL))
#define	wset_sdsacloff(s, o) ((s)->sd_sacloff = htolel(o))
#define	sddacl(s) \
	((struct ntacl *)((s)->sd_dacloff ? \
	(char *)(s) + letohl((s)->sd_dacloff) : \
	NULL))
#define	wset_sddacloff(s, o) ((s)->sd_dacloff = htolel(o))

/*
 * sd_flags bits
 */
#define	SD_OWNER_DEFAULTED		0x0001
#define	SD_GROUP_DEFAULTED		0x0002
#define	SD_DACL_PRESENT			0x0004
#define	SD_DACL_DEFAULTED		0x0008
#define	SD_SACL_PRESENT			0x0010
#define	SD_SACL_DEFAULTED		0x0020
#define	SD_DACL_TRUSTED			0x0040
#define	SD_SERVER_SECURITY		0x0080
#define	SD_DACL_AUTO_INHERIT_REQ	0x0100
#define	SD_SACL_AUTO_INHERIT_REQ	0x0200
#define	SD_DACL_AUTO_INHERITED		0x0400
#define	SD_SACL_AUTO_INHERITED		0x0800
#define	SD_DACL_PROTECTED		0x1000
#define	SD_SACL_PROTECTED		0x2000
#define	SD_RM_CONTROL_VALID		0x4000
#define	SD_SELF_RELATIVE		0x8000

/*
 * access control list header
 * it is followed by the ACEs
 * note this is "raw", ie little-endian
 */
struct ntacl {
	uint8_t	acl_revision;	/* 0x02 observed with W2K */
	uint8_t	acl_pad1;
	uint16_t	acl_len; /* bytes; includes this header */
	uint16_t	acl_acecount;
	uint16_t	acl_pad2;
}; /* XXX: __attribute__((__packed__)); */
typedef struct ntacl ntacl_t;

#define	wset_aclrevision(a) ((a)->acl_revision = 0x02)
#define	acllen(a) (letohs((a)->acl_len))
#define	wset_acllen(a, l) ((a)->acl_len = htoles(l))
#define	aclacecount(a) (letohs((a)->acl_acecount))
#define	wset_aclacecount(a, c) ((a)->acl_acecount = htoles(c))
#define	aclace(a) ((struct ntace *)((char *)(a) + sizeof (struct ntacl)))

/*
 * access control entry header
 * it is followed by type-specific ace data,
 * which for the simple types is just a SID
 * note this is "raw", ie little-endian
 */
struct ntace {
	uint8_t	ace_type;
	uint8_t	ace_flags;
	uint16_t	ace_len; /* bytes; includes this header */
	uint32_t	ace_rights; /* generic, standard, specific, etc */
}; /* XXX: __attribute__((__packed__)); */

#define	acetype(a) ((a)->ace_type)
#define	wset_acetype(a, t) ((a)->ace_type = (t))
#define	aceflags(a) ((a)->ace_flags)
#define	wset_aceflags(a, f) ((a)->ace_flags = (f))
#define	acelen(a) (letohs((a)->ace_len))
#define	wset_acelen(a, l) ((a)->ace_len = htoles(l))
#define	acerights(a) (letohl((a)->ace_rights))
#define	wset_acerights(a, r) ((a)->ace_rights = htolel(r))
#define	aceace(a) ((struct ntace *)((char *)(a) + acelen(a)))
#define	acesid(a) ((struct ntsid *)((char *)(a) + sizeof (struct ntace)))

/*
 * ace_rights
 * (Samba bit names are used here, with permission, as the shorter Windows
 * names are more likely to cause namespace collisions)
 */
#define	SA_RIGHT_FILE_READ_DATA		0x00000001
#define	SA_RIGHT_FILE_WRITE_DATA	0x00000002
#define	SA_RIGHT_FILE_APPEND_DATA	0x00000004
#define	SA_RIGHT_FILE_READ_EA		0x00000008
#define	SA_RIGHT_FILE_WRITE_EA		0x00000010
#define	SA_RIGHT_FILE_EXECUTE		0x00000020
#define	SA_RIGHT_FILE_DELETE_CHILD	0x00000040
#define	SA_RIGHT_FILE_READ_ATTRIBUTES	0x00000080
#define	SA_RIGHT_FILE_WRITE_ATTRIBUTES	0x00000100
#define	SA_RIGHT_FILE_ALL_ACCESS	0x000001FF

#define	STD_RIGHT_DELETE_ACCESS		0x00010000
#define	STD_RIGHT_READ_CONTROL_ACCESS	0x00020000
#define	STD_RIGHT_WRITE_DAC_ACCESS	0x00040000
#define	STD_RIGHT_WRITE_OWNER_ACCESS	0x00080000
#define	STD_RIGHT_SYNCHRONIZE_ACCESS	0x00100000
#define	STD_RIGHT_ALL_ACCESS		0x001F0000

#define	SEC_RIGHT_SYSTEM_SECURITY	0x01000000
/*
 * Don't use MAXIMUM_ALLOWED as Samba (2.2.3 at least) will
 * return NT_STATUS_INVALID_LOCK_SEQUENCE
 */
#define	SEC_RIGHT_MAXIMUM_ALLOWED	0x02000000

#define	GENERIC_RIGHT_ALL_ACCESS	0x10000000
#define	GENERIC_RIGHT_EXECUTE_ACCESS	0x20000000
#define	GENERIC_RIGHT_WRITE_ACCESS	0x40000000
#define	GENERIC_RIGHT_READ_ACCESS	0x80000000

/*
 * these mappings are from Windows sample code but are likely incomplete
 *
 * GENERIC_RIGHT_READ_ACCESS :
 *	STD_RIGHT_SYNCHRONIZE_ACCESS |
 *	STD_RIGHT_READ_CONTROL_ACCESS |
 *	SA_RIGHT_FILE_READ_ATTRIBUTES |
 *	SA_RIGHT_FILE_READ_EA |
 *	SA_RIGHT_FILE_READ_DATA
 * GENERIC_RIGHT_WRITE_ACCESS :
 *	STD_RIGHT_SYNCHRONIZE_ACCESS |
 *	STD_RIGHT_READ_CONTROL_ACCESS |
 *	SA_RIGHT_FILE_WRITE_ATTRIBUTES |
 *	SA_RIGHT_FILE_WRITE_EA |
 *	SA_RIGHT_FILE_APPEND_DATA |
 *	SA_RIGHT_FILE_WRITE_DATA
 * GENERIC_RIGHT_EXECUTE_ACCESS :
 *	STD_RIGHT_SYNCHRONIZE_ACCESS |
 *	STD_RIGHT_READ_CONTROL_ACCESS |
 *	SA_RIGHT_FILE_READ_ATTRIBUTES |
 *	SA_RIGHT_FILE_EXECUTE
 * GENERIC_RIGHT_ALL_ACCESS :
 *	STD_RIGHT_SYNCHRONIZE_ACCESS |
 *	STD_RIGHT_WRITE_OWNER_ACCESS |
 *	STD_RIGHT_WRITE_DAC_ACCESS |
 *	STD_RIGHT_READ_CONTROL_ACCESS |
 *	STD_RIGHT_DELETE_ACCESS |
 *	SA_RIGHT_FILE_ALL_ACCESS
 */

/*
 * security identifier header
 * it is followed by sid_numauth sub-authorities,
 * which are 32 bits each.
 * note the subauths are little-endian on the wire, but
 * need to be big-endian for memberd/DS
 */
#define	SIDAUTHSIZE 6
struct ntsid {
	uint8_t	sid_revision;
	uint8_t	sid_subauthcount;
	uint8_t	sid_authority[SIDAUTHSIZE]; /* ie not little endian */
}; /* XXX: __attribute__((__packed__)); */
typedef struct ntsid ntsid_t;

#define	sidsubauthcount(s) (s->sid_subauthcount)
#define	sidlen(s) (sizeof (struct ntsid) + 4 * (s)->sid_subauthcount)
#define	MAXSIDLEN (sizeof (struct ntsid) + 4 * KAUTH_NTSID_MAX_AUTHORITIES)
#define	sidsub(s) ((uint32_t *)((char *)(s) + sizeof (struct ntsid)))

/*
 * MS' defined values for ace_type
 */
#define	ACCESS_ALLOWED_ACE_TYPE			0x0
#define	ACCESS_DENIED_ACE_TYPE			0x1
#define	SYSTEM_AUDIT_ACE_TYPE			0x2
#define	SYSTEM_ALARM_ACE_TYPE			0x3
#define	ACCESS_ALLOWED_COMPOUND_ACE_TYPE	0x4
#define	ACCESS_ALLOWED_OBJECT_ACE_TYPE		0x5
#define	ACCESS_DENIED_OBJECT_ACE_TYPE		0x6
#define	SYSTEM_AUDIT_OBJECT_ACE_TYPE		0x7
#define	SYSTEM_ALARM_OBJECT_ACE_TYPE		0x8
#define	ACCESS_ALLOWED_CALLBACK_ACE_TYPE	0x9
#define	ACCESS_DENIED_CALLBACK_ACE_TYPE		0xA
#define	ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE	0xB
#define	ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE	0xC
#define	SYSTEM_AUDIT_CALLBACK_ACE_TYPE		0xD
#define	SYSTEM_ALARM_CALLBACK_ACE_TYPE		0xE
#define	SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE	0xF
#define	SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE	0x10

/*
 * MS' defined values for ace_flags
 */
#define	OBJECT_INHERIT_ACE_FLAG			0x01
#define	CONTAINER_INHERIT_ACE_FLAG		0x02
#define	NO_PROPAGATE_INHERIT_ACE_FLAG		0x04
#define	INHERIT_ONLY_ACE_FLAG			0x08
#define	INHERITED_ACE_FLAG			0x10
#define	UNDEF_ACE_FLAG				0x20 /* MS doesn't define it */
#define	VALID_INHERIT_ACE_FLAGS			0x1F
#define	SUCCESSFUL_ACCESS_ACE_FLAG		0x40
#define	FAILED_ACCESS_ACE_FLAG			0x80

/*
 * Set PATH/FILE information levels
 */
#define	SMB_SFILEINFO_STANDARD			1
#define	SMB_SFILEINFO_EA_SET			2
#define	SMB_SFILEINFO_BASIC_INFO		0x101
#define	SMB_SFILEINFO_DISPOSITION_INFO		0x102
#define	SMB_SFILEINFO_ALLOCATION_INFO		0x103
#define	SMB_SFILEINFO_END_OF_FILE_INFO		0x104
#define	SMB_SFILEINFO_UNIX_BASIC		0x200
#define	SMB_SFILEINFO_UNIX_LINK			0x201
#define	SMB_SFILEINFO_UNIX_HLINK		0x203
#define	SMB_SFILEINFO_POSIX_ACL			0x204
#define	SMB_SFILEINFO_POSIX_UNLINK		0x20A
#define	SMB_SFILEINFO_UNIX_INFO2		0x20B
#define	SMB_SFILEINFO_DIRECTORY_INFORMATION	1001
#define	SMB_SFILEINFO_FULL_DIRECTORY_INFORMATION	1002
#define	SMB_SFILEINFO_BOTH_DIRECTORY_INFORMATION	1003
#define	SMB_SFILEINFO_BASIC_INFORMATION		1004
#define	SMB_SFILEINFO_STANDARD_INFORMATION	1005
#define	SMB_SFILEINFO_INTERNAL_INFORMATION	1006
#define	SMB_SFILEINFO_EA_INFORMATION		1007
#define	SMB_SFILEINFO_ACCESS_INFORMATION	1008
#define	SMB_SFILEINFO_NAME_INFORMATION		1009
#define	SMB_SFILEINFO_RENAME_INFORMATION	1010
#define	SMB_SFILEINFO_LINK_INFORMATION		1011
#define	SMB_SFILEINFO_NAMES_INFORMATION		1012
#define	SMB_SFILEINFO_DISPOSITION_INFORMATION	1013
#define	SMB_SFILEINFO_POSITION_INFORMATION	1014
#define	SMB_SFILEINFO_1015			1015 /* ? */
#define	SMB_SFILEINFO_MODE_INFORMATION		1016
#define	SMB_SFILEINFO_ALIGNMENT_INFORMATION	1017
#define	SMB_SFILEINFO_ALL_INFORMATION		1018
#define	SMB_SFILEINFO_ALLOCATION_INFORMATION	1019
#define	SMB_SFILEINFO_END_OF_FILE_INFORMATION	1020
#define	SMB_SFILEINFO_ALT_NAME_INFORMATION	1021
#define	SMB_SFILEINFO_STREAM_INFORMATION	1022
#define	SMB_SFILEINFO_PIPE_INFORMATION		1023
#define	SMB_SFILEINFO_PIPE_LOCAL_INFORMATION	1024
#define	SMB_SFILEINFO_PIPE_REMOTE_INFORMATION	1025
#define	SMB_SFILEINFO_MAILSLOT_QUERY_INFORMATION	1026
#define	SMB_SFILEINFO_MAILSLOT_SET_INFORMATION		1027
#define	SMB_SFILEINFO_COMPRESSION_INFORMATION		1028
#define	SMB_SFILEINFO_OBJECT_ID_INFORMATION		1029
#define	SMB_SFILEINFO_COMPLETION_INFORMATION		1030
#define	SMB_SFILEINFO_MOVE_CLUSTER_INFORMATION		1031
#define	SMB_SFILEINFO_QUOTA_INFORMATION		1032
#define	SMB_SFILEINFO_REPARSE_POINT_INFORMATION	1033
#define	SMB_SFILEINFO_NETWORK_OPEN_INFORMATION	1034
#define	SMB_SFILEINFO_ATTRIBUTE_TAG_INFORMATION 1035
#define	SMB_SFILEINFO_TRACKING_INFORMATION	1036
#define	SMB_SFILEINFO_MAXIMUM_INFORMATION	1037

/*
 * LOCKING_ANDX LockType flags
 */
#define	SMB_LOCKING_ANDX_SHARED_LOCK	0x01
#define	SMB_LOCKING_ANDX_OPLOCK_RELEASE	0x02
#define	SMB_LOCKING_ANDX_CHANGE_LOCKTYPE 0x04
#define	SMB_LOCKING_ANDX_CANCEL_LOCK	0x08
#define	SMB_LOCKING_ANDX_LARGE_FILES	0x10


/*
 * size of the GUID returned in an extended security negotiate response
 */
#define	SMB_GUIDLEN	16

typedef uint16_t	smbfh;

/*
 * NTLMv2 blob header structure.
 */
struct ntlmv2_blobhdr {
	uint32_t	header;
	uint32_t	reserved;
	uint64_t	timestamp;
	uint64_t	client_nonce;
	uint32_t	unknown1;
};
typedef struct ntlmv2_blobhdr ntlmv2_blobhdr_t;

/*
 * NTLMv2 name header structure, for names in a blob.
 */
struct ntlmv2_namehdr {
	uint16_t	type;
	uint16_t	len;
};
typedef struct ntlmv2_namehdr ntlmv2_namehdr_t;

#define	NAMETYPE_EOL		0x0000	/* end of list of names */
#define	NAMETYPE_MACHINE_NB	0x0001	/* NetBIOS machine name */
#define	NAMETYPE_DOMAIN_NB	0x0002	/* NetBIOS domain name */
#define	NAMETYPE_MACHINE_DNS	0x0003	/* DNS machine name */
#define	NAMETYPE_DOMAIN_DNS	0x0004	/* DNS Active Directory domain name */

/*
 * Named pipe commands.
 */
#define	TRANS_CALL_NAMED_PIPE		0x54	/* open/write/read/close pipe */
#define	TRANS_WAIT_NAMED_PIPE		0x53	/* wait for pipe to be !busy */
#define	TRANS_PEEK_NAMED_PIPE		0x23	/* read but don't remove data */
#define	TRANS_Q_NAMED_PIPE_HAND_STATE	0x21	/* query pipe handle modes */
#define	TRANS_SET_NAMED_PIPE_HAND_STATE	0x01	/* set pipe handle modes */
#define	TRANS_Q_NAMED_PIPE_INFO		0x22	/* query pipe attributes */
#define	TRANS_TRANSACT_NAMED_PIPE	0x26	/* r/w operation on pipe */
#define	TRANS_READ_NAMED_PIPE		0x11	/* read pipe in "raw" mode */
						/* (non message mode) */
#define	TRANS_WRITE_NAMED_PIPE		0x31	/* write pipe "raw" mode */
						/* (non message mode) */

/*
 * Share types, visible via NetShareEnum
 */
#define	STYPE_DISKTREE			0x00000000
#define	STYPE_PRINTQ			0x00000001
#define	STYPE_DEVICE			0x00000002
#define	STYPE_IPC			0x00000003
#define	STYPE_UNKNOWN			0x00000004
#define	STYPE_MASK			0x0000000F
#define	STYPE_TEMPORARY			0x40000000
#define	STYPE_HIDDEN			0x80000000

/*
 * Characters that are not allowed in an SMB file name component.
 * From MSDN: Naming Files, Paths, ...
 *	< (less than)
 *	> (greater than)
 *	: (colon)
 *	" (double quote)
 *	/ (forward slash)
 *	\ (backslash)
 *	| (vertical bar or pipe)
 *	? (question mark)
 *	* (asterisk)
 */
#define	SMB_FILENAME_INVALID_CHARS	"<>:\"/\\|?*"

#endif /* _NETSMB_SMB_H_ */
