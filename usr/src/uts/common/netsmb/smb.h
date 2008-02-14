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
 * Common definintions and structures for SMB/CIFS protocol
 */

#ifndef _NETSMB_SMB_H_
#define	_NETSMB_SMB_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file should be purely SMB protocol definition stuff.
 * (Please don't make it a catch-all:)
 */

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
	SMB_DIALECT_NTLM0_12		/* NT LM 0.12, Windows for Workgroups */
					/* 3.1a, * NT LANMAN 1.0 */
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
#define	SMB_HDRMID(p)		(letohs(*(ushort_t *)((uchar_t *)(p) + 30)))
#define	SMB_HDRLEN		32
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
#define	SMB_QFS_MAC_FS_INFO			0x301
#define	SMB_QFS_VOLUME_INFORMATION		1001
#define	SMB_QFS_SIZE_INFORMATION		1003
#define	SMB_QFS_DEVICE_INFORMATION		1004
#define	SMB_QFS_ATTRIBUTE_INFORMATION		1005
#define	SMB_QFS_QUOTA_INFORMATION		1006
#define	SMB_QFS_FULL_SIZE_INFORMATION		1007
#define	SMB_QFS_OBJECTID_INFORMATION		1008


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
#define	SMB_QFILEINFO_MAC_DT_GET_APPL		0x306
#define	SMB_QFILEINFO_MAC_DT_GET_ICON		0x307
#define	SMB_QFILEINFO_MAC_DT_GET_ICON_INFO	0x308
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
 * Some names length limitations. Some of them aren't declared by specs,
 * but we need reasonable limits.
 */
#define	SMB_MAXSRVNAMELEN	15	/* NetBIOS limit */
#define	SMB_MAXUSERNAMELEN	128
#define	SMB_MAXPASSWORDLEN	128
#define	SMB_MAXSHARENAMELEN	128
#define	SMB_MAXPKTLEN		0x1FFFF
#define	SMB_MAXCHALLENGELEN	8
#define	SMB_MAXFNAMELEN		255	/* Keep in sync with MAXNAMLEN */

#define	SMB_RCNDELAY		2	/* seconds between reconnect attempts */
/*
 * leave this zero - we can't ssecond guess server side effects of
 * duplicate ops, this isn't nfs!
 */
#define	SMBMAXRESTARTS		0
#define	SMB_MAXSETUPWORDS	3	/* max # of setup words in trans/t2 */

/*
 * Error classes
 */
#define	SMBSUCCESS	0x00
#define	ERRDOS		0x01
#define	ERRSRV		0x02
#define	ERRHRD		0x03	/* Error is an hardware error. */
#define	ERRCMD		0xFF	/* Command was not in the "SMB" format. */

/*
 * Error codes for the ERRDOS class
 */
#define	ERRbadfunc	1	/* Invalid function */
#define	ERRbadfile	2	/* File not found (last component) */
#define	ERRbadpath	3	/* Directory invalid */
#define	ERRnofids	4	/* Too many open files */
#define	ERRnoaccess	5	/* Access denied */
#define	ERRbadfid	6	/* Invalid file handle */
#define	ERRbadmcb	7	/* Memory control blocks destroyed (huh ?) */
#define	ERRnomem	8	/* Insufficient memory */
#define	ERRbadmem	9	/* Invalid memory block address */
#define	ERRbadenv	10	/* Invalid environment */
#define	ERRbadformat	11	/* Invalid format */
#define	ERRbadaccess	12	/* Invalid open mode */
#define	ERRbaddata	13	/* Invalid data */
#define	ERRoutofmem	14	/* out of memory */
#define	ERRbaddrive	15	/* Invalid drive specified */
#define	ERRremcd	16	/* An attempt to delete current directory */
#define	ERRdiffdevice	17	/* cross fs rename/move */
#define	ERRnofiles	18	/* no more files found in file search */
#define	ERRwriteprotect	19
#define	ERRnotready	21
#define	ERRbadcmd	22
#define	ERRcrc		23
#define	ERRbadlength	24
#define	ERRsectornotfound	27
#define	ERRbadshare	32	/* Share mode can't be granted */
#define	ERRlock		33	/* Lock conflicts with existing lock */
#define	ERRwrongdisk	34
#define	ERRhandleeof	38
#define	ERRunsup	50	/* unsupported - Win 95 */
#define	ERRnetnamedel	64
#define	ERRnoipc	66	/* ipc unsupported */
#define	ERRnosuchshare	67	/* invalid share name */
#define	ERRtoomanynames	68
#define	ERRfilexists	80	/* requested file name already exists */
#define	ERRinvalidparam 87
#define	ERRcannotopen	110	/* cannot open the file */
#define	ERRinsufficientbuffer 122
#define	ERRinvalidname	123
#define	ERRunknownlevel 124
#define	ERRdirnotempty	145
#define	ERRnotlocked	158	/* region was not locked by this context */
#define	ERRrename	183
#define	ERRbadpipe	230	/* named pipe invalid */
#define	ERRpipebusy	231	/* all pipe instances are busy */
#define	ERRpipeclosing	232	/* close in progress */
#define	ERRnotconnected	233	/* nobody on other end of pipe */
#define	ERRmoredata	234	/* more data to be returned */
#define	ERRnomoreitems 259
#define	ERRbaddirectory	267	/* invalid directory name */
#define	ERReasunsupported	282	/* extended attributes not supported */
#define	ERRlogonfailure 1326
#define	ERRbuftoosmall	2123
#define	ERRunknownipc	2142
#define	ERRnosuchprintjob	2151
#define	ERRinvgroup 2455

/*
 * Error codes for the ERRSRV class
 */
#define	ERRerror	1	/* Non-specific error code */
#define	ERRbadpw	2	/* Bad password */
#define	ERRbadtype	3	/* reserved */
#define	ERRaccess	4	/* client doesn't have enough access rights */
#define	ERRinvnid	5	/* The Tid specified in a command is invalid */
#define	ERRinvnetname	6	/* Invalid server name in the tree connect */
#define	ERRinvdevice	7	/* Printer and not printer devices are mixed */
#define	ERRqfull	49	/* Print queue full */
#define	ERRqtoobig	50	/* Print queue full - no space */
#define	ERRinvpfid	52	/* Invalid print file FID */
#define	ERRsmbcmd	64	/* The server did not recognise the command */
#define	ERRsrverror	65	/* The server encountered and internal error */
#define	ERRfilespecs	67	/* The Fid and path name contains an */
				/* invalid combination */
#define	ERRbadpermits	69	/* Access mode invalid */
#define	ERRsetattrmode	71	/* Attribute mode invalid */
#define	ERRpaused	81	/* Server is paused */
#define	ERRmsgoff	82	/* Not receiving messages */
#define	ERRnoroom	83	/* No room to buffer message */
#define	ERRrmuns	87	/* Too many remote user names */
#define	ERRtimeout	88	/* Operation timed out */
#define	ERRnoresource	89	/* No resources currently available for req */
#define	ERRtoomanyuids	90	/* Too many UIDs active on this session */
#define	ERRbaduid	91	/* The UID is not known in this session */
#define	ERRusempx	250	/* Temporarily unable to support Raw, */
				/* use MPX mode */
#define	ERRusestd	251	/* Temporarily unable to support Raw, */
				/* use stdandard r/w */
#define	ERRcontmpx	252	/* Continue in MPX mode */
#define	ERRacctexpired	2239
#define	ERRnosupport	65535	/* Invalid function */

/*
 * Error codes for the ERRHRD class
 */
#define	ERRnowrite	19	/* write protected media */
#define	ERRbadunit	20	/* Unknown unit */
#define	ERRnotready	21	/* Drive not ready */
#define	ERRbadcmd	22	/* Unknown command */
#define	ERRdata		23	/* Data error (CRC) */
#define	ERRbadreq	24	/* Bad request structure length */
#define	ERRseek		25	/* Seek error */
#define	ERRbadmedia	26	/* Unknown media type */
#define	ERRbadsector	27	/* Sector not found */
#define	ERRnopaper	28	/* Printer out of paper */
#define	ERRwrite	29	/* Write fault */
#define	ERRread		30	/* Read fault */
#define	ERRgeneral	31	/* General failure */
#define	ERRbadshare	32	/* A open conflicts with an existing open */
#define	ERRlock		33	/* lock/unlock conflict */
#define	ERRwrongdisk	34	/* The wrong disk was found in a drive */
#define	ERRFCBunavail	35	/* No FCBs available */
#define	ERRsharebufexc	36	/* A sharing buffer has been exceeded */
#define	ERRdiskfull	39

/*
 * RAP error codes (it seems that they returned not only by RAP)
 */
#define	SMB_ERROR_ACCESS_DENIED		5
#define	SMB_ERROR_NETWORK_ACCESS_DENIED	65
#define	SMB_ERROR_MORE_DATA		ERRmoredata

/*
 * An INCOMPLETE list of 32 bit error codes
 * For more detail see MSDN and ntstatus.h in the MS DDK
 *
 * XXX - these should have the severity and "customer defined" fields
 * added back in, and smb_maperr32() shouldn't mask those fields out;
 * 0x80000005 is STATUS_BUFFER_OVERFLOW, with 0xC0000000 is
 * STATUS_ACCESS_VIOLATION, and we need to distinguish between them.
 * We use STATUS_BUFFER_OVERFLOW, and need to know its exact value,
 * so we #define	it correctly here; don't strip off the leading
 * 0x80000000 from it!
 */
#define	NT_STATUS_BUFFER_OVERFLOW	0x80000005
#define	NT_STATUS_UNSUCCESSFUL		0x0001
#define	NT_STATUS_NOT_IMPLEMENTED	0x0002
#define	NT_STATUS_INVALID_INFO_CLASS	0x0003
#define	NT_STATUS_INFO_LENGTH_MISMATCH	0x0004
#define	NT_STATUS_ACCESS_VIOLATION	0x0005
#define	NT_STATUS_IN_PAGE_ERROR		0x0006
#define	NT_STATUS_PAGEFILE_QUOTA	0x0007
#define	NT_STATUS_INVALID_HANDLE	0x0008
#define	NT_STATUS_BAD_INITIAL_STACK	0x0009
#define	NT_STATUS_BAD_INITIAL_PC	0x000a
#define	NT_STATUS_INVALID_CID		0x000b
#define	NT_STATUS_TIMER_NOT_CANCELED	0x000c
#define	NT_STATUS_INVALID_PARAMETER	0x000d
#define	NT_STATUS_NO_SUCH_DEVICE	0x000e
#define	NT_STATUS_NO_SUCH_FILE		0x000f
#define	NT_STATUS_INVALID_DEVICE_REQUEST	0x0010
#define	NT_STATUS_END_OF_FILE		0x0011
#define	NT_STATUS_WRONG_VOLUME		0x0012
#define	NT_STATUS_NO_MEDIA_IN_DEVICE	0x0013
#define	NT_STATUS_UNRECOGNIZED_MEDIA	0x0014
#define	NT_STATUS_NONEXISTENT_SECTOR	0x0015
#define	NT_STATUS_MORE_PROCESSING_REQUIRED	0x0016
#define	NT_STATUS_NO_MEMORY		0x0017
#define	NT_STATUS_CONFLICTING_ADDRESSES	0x0018
#define	NT_STATUS_NOT_MAPPED_VIEW	0x0019
#define	NT_STATUS_UNABLE_TO_FREE_VM	0x001a
#define	NT_STATUS_UNABLE_TO_DELETE_SECTION	0x001b
#define	NT_STATUS_INVALID_SYSTEM_SERVICE	0x001c
#define	NT_STATUS_ILLEGAL_INSTRUCTION	0x001d
#define	NT_STATUS_INVALID_LOCK_SEQUENCE	0x001e
#define	NT_STATUS_INVALID_VIEW_SIZE	0x001f
#define	NT_STATUS_INVALID_FILE_FOR_SECTION	0x0020
#define	NT_STATUS_ALREADY_COMMITTED	0x0021
#define	NT_STATUS_ACCESS_DENIED		0x0022
#define	NT_STATUS_BUFFER_TOO_SMALL	0x0023
#define	NT_STATUS_OBJECT_TYPE_MISMATCH	0x0024
#define	NT_STATUS_NONCONTINUABLE_EXCEPTION	0x0025
#define	NT_STATUS_INVALID_DISPOSITION	0x0026
#define	NT_STATUS_UNWIND		0x0027
#define	NT_STATUS_BAD_STACK		0x0028
#define	NT_STATUS_INVALID_UNWIND_TARGET	0x0029
#define	NT_STATUS_NOT_LOCKED		0x002a
#define	NT_STATUS_PARITY_ERROR		0x002b
#define	NT_STATUS_UNABLE_TO_DECOMMIT_VM	0x002c
#define	NT_STATUS_NOT_COMMITTED		0x002d
#define	NT_STATUS_INVALID_PORT_ATTRIBUTES	0x002e
#define	NT_STATUS_PORT_MESSAGE_TOO_LONG	0x002f
#define	NT_STATUS_INVALID_PARAMETER_MIX	0x0030
#define	NT_STATUS_INVALID_QUOTA_LOWER	0x0031
#define	NT_STATUS_DISK_CORRUPT_ERROR	0x0032
#define	NT_STATUS_OBJECT_NAME_INVALID	0x0033
#define	NT_STATUS_OBJECT_NAME_NOT_FOUND	0x0034
#define	NT_STATUS_OBJECT_NAME_COLLISION	0x0035
#define	NT_STATUS_HANDLE_NOT_WAITABLE	0x0036
#define	NT_STATUS_PORT_DISCONNECTED	0x0037
#define	NT_STATUS_DEVICE_ALREADY_ATTACHED	0x0038
#define	NT_STATUS_OBJECT_PATH_INVALID	0x0039
#define	NT_STATUS_OBJECT_PATH_NOT_FOUND	0x003a
#define	NT_STATUS_OBJECT_PATH_SYNTAX_BAD	0x003b
#define	NT_STATUS_DATA_OVERRUN		0x003c
#define	NT_STATUS_DATA_LATE_ERROR	0x003d
#define	NT_STATUS_DATA_ERROR		0x003e
#define	NT_STATUS_CRC_ERROR		0x003f
#define	NT_STATUS_SECTION_TOO_BIG	0x0040
#define	NT_STATUS_PORT_CONNECTION_REFUSED	0x0041
#define	NT_STATUS_INVALID_PORT_HANDLE	0x0042
#define	NT_STATUS_SHARING_VIOLATION	0x0043
#define	NT_STATUS_QUOTA_EXCEEDED	0x0044
#define	NT_STATUS_INVALID_PAGE_PROTECTION	0x0045
#define	NT_STATUS_MUTANT_NOT_OWNED	0x0046
#define	NT_STATUS_SEMAPHORE_LIMIT_EXCEEDED	0x0047
#define	NT_STATUS_PORT_ALREADY_SET	0x0048
#define	NT_STATUS_SECTION_NOT_IMAGE	0x0049
#define	NT_STATUS_SUSPEND_COUNT_EXCEEDED	0x004a
#define	NT_STATUS_THREAD_IS_TERMINATING	0x004b
#define	NT_STATUS_BAD_WORKING_SET_LIMIT	0x004c
#define	NT_STATUS_INCOMPATIBLE_FILE_MAP	0x004d
#define	NT_STATUS_SECTION_PROTECTION	0x004e
#define	NT_STATUS_EAS_NOT_SUPPORTED	0x004f
#define	NT_STATUS_EA_TOO_LARGE		0x0050
#define	NT_STATUS_NONEXISTENT_EA_ENTRY	0x0051
#define	NT_STATUS_NO_EAS_ON_FILE	0x0052
#define	NT_STATUS_EA_CORRUPT_ERROR	0x0053
#define	NT_STATUS_FILE_LOCK_CONFLICT	0x0054
#define	NT_STATUS_LOCK_NOT_GRANTED	0x0055
#define	NT_STATUS_DELETE_PENDING	0x0056
#define	NT_STATUS_CTL_FILE_NOT_SUPPORTED	0x0057
#define	NT_STATUS_UNKNOWN_REVISION	0x0058
#define	NT_STATUS_REVISION_MISMATCH	0x0059
#define	NT_STATUS_INVALID_OWNER		0x005a
#define	NT_STATUS_INVALID_PRIMARY_GROUP	0x005b
#define	NT_STATUS_NO_IMPERSONATION_TOKEN	0x005c
#define	NT_STATUS_CANT_DISABLE_MANDATORY	0x005d
#define	NT_STATUS_NO_LOGON_SERVERS	0x005e
#define	NT_STATUS_NO_SUCH_LOGON_SESSION	0x005f
#define	NT_STATUS_NO_SUCH_PRIVILEGE	0x0060
#define	NT_STATUS_PRIVILEGE_NOT_HELD	0x0061
#define	NT_STATUS_INVALID_ACCOUNT_NAME	0x0062
#define	NT_STATUS_USER_EXISTS		0x0063
#define	NT_STATUS_NO_SUCH_USER		0x0064
#define	NT_STATUS_GROUP_EXISTS		0x0065
#define	NT_STATUS_NO_SUCH_GROUP		0x0066
#define	NT_STATUS_MEMBER_IN_GROUP	0x0067
#define	NT_STATUS_MEMBER_NOT_IN_GROUP	0x0068
#define	NT_STATUS_LAST_ADMIN		0x0069
#define	NT_STATUS_WRONG_PASSWORD	0x006a
#define	NT_STATUS_ILL_FORMED_PASSWORD	0x006b
#define	NT_STATUS_PASSWORD_RESTRICTION	0x006c
#define	NT_STATUS_LOGON_FAILURE		0x006d
#define	NT_STATUS_ACCOUNT_RESTRICTION	0x006e
#define	NT_STATUS_INVALID_LOGON_HOURS	0x006f
#define	NT_STATUS_INVALID_WORKSTATION	0x0070
#define	NT_STATUS_PASSWORD_EXPIRED	0x0071
#define	NT_STATUS_ACCOUNT_DISABLED	0x0072
#define	NT_STATUS_NONE_MAPPED		0x0073
#define	NT_STATUS_TOO_MANY_LUIDS_REQUESTED	0x0074
#define	NT_STATUS_LUIDS_EXHAUSTED	0x0075
#define	NT_STATUS_INVALID_SUB_AUTHORITY	0x0076
#define	NT_STATUS_INVALID_ACL		0x0077
#define	NT_STATUS_INVALID_SID		0x0078
#define	NT_STATUS_INVALID_SECURITY_DESCR	0x0079
#define	NT_STATUS_PROCEDURE_NOT_FOUND	0x007a
#define	NT_STATUS_INVALID_IMAGE_FORMAT	0x007b
#define	NT_STATUS_NO_TOKEN		0x007c
#define	NT_STATUS_BAD_INHERITANCE_ACL	0x007d
#define	NT_STATUS_RANGE_NOT_LOCKED	0x007e
#define	NT_STATUS_DISK_FULL		0x007f
#define	NT_STATUS_SERVER_DISABLED	0x0080
#define	NT_STATUS_SERVER_NOT_DISABLED	0x0081
#define	NT_STATUS_TOO_MANY_GUIDS_REQUESTED	0x0082
#define	NT_STATUS_GUIDS_EXHAUSTED	0x0083
#define	NT_STATUS_INVALID_ID_AUTHORITY	0x0084
#define	NT_STATUS_AGENTS_EXHAUSTED	0x0085
#define	NT_STATUS_INVALID_VOLUME_LABEL	0x0086
#define	NT_STATUS_SECTION_NOT_EXTENDED	0x0087
#define	NT_STATUS_NOT_MAPPED_DATA	0x0088
#define	NT_STATUS_RESOURCE_DATA_NOT_FOUND	0x0089
#define	NT_STATUS_RESOURCE_TYPE_NOT_FOUND	0x008a
#define	NT_STATUS_RESOURCE_NAME_NOT_FOUND	0x008b
#define	NT_STATUS_ARRAY_BOUNDS_EXCEEDED	0x008c
#define	NT_STATUS_FLOAT_DENORMAL_OPERAND	0x008d
#define	NT_STATUS_FLOAT_DIVIDE_BY_ZERO	0x008e
#define	NT_STATUS_FLOAT_INEXACT_RESULT	0x008f
#define	NT_STATUS_FLOAT_INVALID_OPERATION	0x0090
#define	NT_STATUS_FLOAT_OVERFLOW	0x0091
#define	NT_STATUS_FLOAT_STACK_CHECK	0x0092
#define	NT_STATUS_FLOAT_UNDERFLOW	0x0093
#define	NT_STATUS_INTEGER_DIVIDE_BY_ZERO	0x0094
#define	NT_STATUS_INTEGER_OVERFLOW	0x0095
#define	NT_STATUS_PRIVILEGED_INSTRUCTION	0x0096
#define	NT_STATUS_TOO_MANY_PAGING_FILES	0x0097
#define	NT_STATUS_FILE_INVALID	0x0098
#define	NT_STATUS_ALLOTTED_SPACE_EXCEEDED	0x0099
#define	NT_STATUS_INSUFFICIENT_RESOURCES	0x009a
#define	NT_STATUS_DFS_EXIT_PATH_FOUND	0x009b
#define	NT_STATUS_DEVICE_DATA_ERROR	0x009c
#define	NT_STATUS_DEVICE_NOT_CONNECTED	0x009d
#define	NT_STATUS_DEVICE_POWER_FAILURE	0x009e
#define	NT_STATUS_FREE_VM_NOT_AT_BASE	0x009f
#define	NT_STATUS_MEMORY_NOT_ALLOCATED	0x00a0
#define	NT_STATUS_WORKING_SET_QUOTA	0x00a1
#define	NT_STATUS_MEDIA_WRITE_PROTECTED	0x00a2
#define	NT_STATUS_DEVICE_NOT_READY	0x00a3
#define	NT_STATUS_INVALID_GROUP_ATTRIBUTES	0x00a4
#define	NT_STATUS_BAD_IMPERSONATION_LEVEL	0x00a5
#define	NT_STATUS_CANT_OPEN_ANONYMOUS	0x00a6
#define	NT_STATUS_BAD_VALIDATION_CLASS	0x00a7
#define	NT_STATUS_BAD_TOKEN_TYPE	0x00a8
#define	NT_STATUS_BAD_MASTER_BOOT_RECORD	0x00a9
#define	NT_STATUS_INSTRUCTION_MISALIGNMENT	0x00aa
#define	NT_STATUS_INSTANCE_NOT_AVAILABLE	0x00ab
#define	NT_STATUS_PIPE_NOT_AVAILABLE	0x00ac
#define	NT_STATUS_INVALID_PIPE_STATE	0x00ad
#define	NT_STATUS_PIPE_BUSY		0x00ae
#define	NT_STATUS_ILLEGAL_FUNCTION	0x00af
#define	NT_STATUS_PIPE_DISCONNECTED	0x00b0
#define	NT_STATUS_PIPE_CLOSING		0x00b1
#define	NT_STATUS_PIPE_CONNECTED	0x00b2
#define	NT_STATUS_PIPE_LISTENING	0x00b3
#define	NT_STATUS_INVALID_READ_MODE	0x00b4
#define	NT_STATUS_IO_TIMEOUT		0x00b5
#define	NT_STATUS_FILE_FORCED_CLOSED	0x00b6
#define	NT_STATUS_PROFILING_NOT_STARTED	0x00b7
#define	NT_STATUS_PROFILING_NOT_STOPPED	0x00b8
#define	NT_STATUS_COULD_NOT_INTERPRET	0x00b9
#define	NT_STATUS_FILE_IS_A_DIRECTORY	0x00ba
#define	NT_STATUS_NOT_SUPPORTED		0x00bb
#define	NT_STATUS_REMOTE_NOT_LISTENING	0x00bc
#define	NT_STATUS_DUPLICATE_NAME	0x00bd
#define	NT_STATUS_BAD_NETWORK_PATH	0x00be
#define	NT_STATUS_NETWORK_BUSY		0x00bf
#define	NT_STATUS_DEVICE_DOES_NOT_EXIST	0x00c0
#define	NT_STATUS_TOO_MANY_COMMANDS	0x00c1
#define	NT_STATUS_ADAPTER_HARDWARE_ERROR	0x00c2
#define	NT_STATUS_INVALID_NETWORK_RESPONSE	0x00c3
#define	NT_STATUS_UNEXPECTED_NETWORK_ERROR	0x00c4
#define	NT_STATUS_BAD_REMOTE_ADAPTER	0x00c5
#define	NT_STATUS_PRINT_QUEUE_FULL	0x00c6
#define	NT_STATUS_NO_SPOOL_SPACE	0x00c7
#define	NT_STATUS_PRINT_CANCELLED	0x00c8
#define	NT_STATUS_NETWORK_NAME_DELETED	0x00c9
#define	NT_STATUS_NETWORK_ACCESS_DENIED	0x00ca
#define	NT_STATUS_BAD_DEVICE_TYPE	0x00cb
#define	NT_STATUS_BAD_NETWORK_NAME	0x00cc
#define	NT_STATUS_TOO_MANY_NAMES	0x00cd
#define	NT_STATUS_TOO_MANY_SESSIONS	0x00ce
#define	NT_STATUS_SHARING_PAUSED	0x00cf
#define	NT_STATUS_REQUEST_NOT_ACCEPTED	0x00d0
#define	NT_STATUS_REDIRECTOR_PAUSED	0x00d1
#define	NT_STATUS_NET_WRITE_FAULT	0x00d2
#define	NT_STATUS_PROFILING_AT_LIMIT	0x00d3
#define	NT_STATUS_NOT_SAME_DEVICE	0x00d4
#define	NT_STATUS_FILE_RENAMED		0x00d5
#define	NT_STATUS_VIRTUAL_CIRCUIT_CLOSED	0x00d6
#define	NT_STATUS_NO_SECURITY_ON_OBJECT	0x00d7
#define	NT_STATUS_CANT_WAIT		0x00d8
#define	NT_STATUS_PIPE_EMPTY		0x00d9
#define	NT_STATUS_CANT_ACCESS_DOMAIN_INFO	0x00da
#define	NT_STATUS_CANT_TERMINATE_SELF	0x00db
#define	NT_STATUS_INVALID_SERVER_STATE	0x00dc
#define	NT_STATUS_INVALID_DOMAIN_STATE	0x00dd
#define	NT_STATUS_INVALID_DOMAIN_ROLE	0x00de
#define	NT_STATUS_NO_SUCH_DOMAIN	0x00df
#define	NT_STATUS_DOMAIN_EXISTS		0x00e0
#define	NT_STATUS_DOMAIN_LIMIT_EXCEEDED	0x00e1
#define	NT_STATUS_OPLOCK_NOT_GRANTED	0x00e2
#define	NT_STATUS_INVALID_OPLOCK_PROTOCOL	0x00e3
#define	NT_STATUS_INTERNAL_DB_CORRUPTION	0x00e4
#define	NT_STATUS_INTERNAL_ERROR	0x00e5
#define	NT_STATUS_GENERIC_NOT_MAPPED	0x00e6
#define	NT_STATUS_BAD_DESCRIPTOR_FORMAT	0x00e7
#define	NT_STATUS_INVALID_USER_BUFFER	0x00e8
#define	NT_STATUS_UNEXPECTED_IO_ERROR	0x00e9
#define	NT_STATUS_UNEXPECTED_MM_CREATE_ERR	0x00ea
#define	NT_STATUS_UNEXPECTED_MM_MAP_ERROR	0x00eb
#define	NT_STATUS_UNEXPECTED_MM_EXTEND_ERR	0x00ec
#define	NT_STATUS_NOT_LOGON_PROCESS	0x00ed
#define	NT_STATUS_LOGON_SESSION_EXISTS	0x00ee
#define	NT_STATUS_INVALID_PARAMETER_1	0x00ef
#define	NT_STATUS_INVALID_PARAMETER_2	0x00f0
#define	NT_STATUS_INVALID_PARAMETER_3	0x00f1
#define	NT_STATUS_INVALID_PARAMETER_4	0x00f2
#define	NT_STATUS_INVALID_PARAMETER_5	0x00f3
#define	NT_STATUS_INVALID_PARAMETER_6	0x00f4
#define	NT_STATUS_INVALID_PARAMETER_7	0x00f5
#define	NT_STATUS_INVALID_PARAMETER_8	0x00f6
#define	NT_STATUS_INVALID_PARAMETER_9	0x00f7
#define	NT_STATUS_INVALID_PARAMETER_10	0x00f8
#define	NT_STATUS_INVALID_PARAMETER_11	0x00f9
#define	NT_STATUS_INVALID_PARAMETER_12	0x00fa
#define	NT_STATUS_REDIRECTOR_NOT_STARTED	0x00fb
#define	NT_STATUS_REDIRECTOR_STARTED	0x00fc
#define	NT_STATUS_STACK_OVERFLOW	0x00fd
#define	NT_STATUS_NO_SUCH_PACKAGE	0x00fe
#define	NT_STATUS_BAD_FUNCTION_TABLE	0x00ff
#define	NT_STATUS_VARIABLE_NOT_FOUND	0x0100
#define	NT_STATUS_DIRECTORY_NOT_EMPTY	0x0101
#define	NT_STATUS_FILE_CORRUPT_ERROR	0x0102
#define	NT_STATUS_NOT_A_DIRECTORY	0x0103
#define	NT_STATUS_BAD_LOGON_SESSION_STATE	0x0104
#define	NT_STATUS_LOGON_SESSION_COLLISION	0x0105
#define	NT_STATUS_NAME_TOO_LONG		0x0106
#define	NT_STATUS_FILES_OPEN		0x0107
#define	NT_STATUS_CONNECTION_IN_USE	0x0108
#define	NT_STATUS_MESSAGE_NOT_FOUND	0x0109
#define	NT_STATUS_PROCESS_IS_TERMINATING	0x010a
#define	NT_STATUS_INVALID_LOGON_TYPE	0x010b
#define	NT_STATUS_NO_GUID_TRANSLATION	0x010c
#define	NT_STATUS_CANNOT_IMPERSONATE	0x010d
#define	NT_STATUS_IMAGE_ALREADY_LOADED	0x010e
#define	NT_STATUS_ABIOS_NOT_PRESENT	0x010f
#define	NT_STATUS_ABIOS_LID_NOT_EXIST	0x0110
#define	NT_STATUS_ABIOS_LID_ALREADY_OWNED	0x0111
#define	NT_STATUS_ABIOS_NOT_LID_OWNER	0x0112
#define	NT_STATUS_ABIOS_INVALID_COMMAND	0x0113
#define	NT_STATUS_ABIOS_INVALID_LID	0x0114
#define	NT_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE	0x0115
#define	NT_STATUS_ABIOS_INVALID_SELECTOR	0x0116
#define	NT_STATUS_NO_LDT		0x0117
#define	NT_STATUS_INVALID_LDT_SIZE	0x0118
#define	NT_STATUS_INVALID_LDT_OFFSET	0x0119
#define	NT_STATUS_INVALID_LDT_DESCRIPTOR	0x011a
#define	NT_STATUS_INVALID_IMAGE_NE_FORMAT	0x011b
#define	NT_STATUS_RXACT_INVALID_STATE	0x011c
#define	NT_STATUS_RXACT_COMMIT_FAILURE	0x011d
#define	NT_STATUS_MAPPED_FILE_SIZE_ZERO	0x011e
#define	NT_STATUS_TOO_MANY_OPENED_FILES	0x011f
#define	NT_STATUS_CANCELLED		0x0120
#define	NT_STATUS_CANNOT_DELETE		0x0121
#define	NT_STATUS_INVALID_COMPUTER_NAME	0x0122
#define	NT_STATUS_FILE_DELETED		0x0123
#define	NT_STATUS_SPECIAL_ACCOUNT	0x0124
#define	NT_STATUS_SPECIAL_GROUP		0x0125
#define	NT_STATUS_SPECIAL_USER		0x0126
#define	NT_STATUS_MEMBERS_PRIMARY_GROUP	0x0127
#define	NT_STATUS_FILE_CLOSED		0x0128
#define	NT_STATUS_TOO_MANY_THREADS	0x0129
#define	NT_STATUS_THREAD_NOT_IN_PROCESS	0x012a
#define	NT_STATUS_TOKEN_ALREADY_IN_USE	0x012b
#define	NT_STATUS_PAGEFILE_QUOTA_EXCEEDED	0x012c
#define	NT_STATUS_COMMITMENT_LIMIT	0x012d
#define	NT_STATUS_INVALID_IMAGE_LE_FORMAT	0x012e
#define	NT_STATUS_INVALID_IMAGE_NOT_MZ	0x012f
#define	NT_STATUS_INVALID_IMAGE_PROTECT	0x0130
#define	NT_STATUS_INVALID_IMAGE_WIN_16	0x0131
#define	NT_STATUS_LOGON_SERVER_CONFLICT	0x0132
#define	NT_STATUS_TIME_DIFFERENCE_AT_DC	0x0133
#define	NT_STATUS_SYNCHRONIZATION_REQUIRED	0x0134
#define	NT_STATUS_DLL_NOT_FOUND		0x0135
#define	NT_STATUS_OPEN_FAILED		0x0136
#define	NT_STATUS_IO_PRIVILEGE_FAILED	0x0137
#define	NT_STATUS_ORDINAL_NOT_FOUND	0x0138
#define	NT_STATUS_ENTRYPOINT_NOT_FOUND	0x0139
#define	NT_STATUS_CONTROL_C_EXIT	0x013a
#define	NT_STATUS_LOCAL_DISCONNECT	0x013b
#define	NT_STATUS_REMOTE_DISCONNECT	0x013c
#define	NT_STATUS_REMOTE_RESOURCES	0x013d
#define	NT_STATUS_LINK_FAILED		0x013e
#define	NT_STATUS_LINK_TIMEOUT		0x013f
#define	NT_STATUS_INVALID_CONNECTION	0x0140
#define	NT_STATUS_INVALID_ADDRESS	0x0141
#define	NT_STATUS_DLL_INIT_FAILED	0x0142
#define	NT_STATUS_MISSING_SYSTEMFILE	0x0143
#define	NT_STATUS_UNHANDLED_EXCEPTION	0x0144
#define	NT_STATUS_APP_INIT_FAILURE	0x0145
#define	NT_STATUS_PAGEFILE_CREATE_FAILED	0x0146
#define	NT_STATUS_NO_PAGEFILE		0x0147
#define	NT_STATUS_INVALID_LEVEL		0x0148
#define	NT_STATUS_WRONG_PASSWORD_CORE	0x0149
#define	NT_STATUS_ILLEGAL_FLOAT_CONTEXT	0x014a
#define	NT_STATUS_PIPE_BROKEN		0x014b
#define	NT_STATUS_REGISTRY_CORRUPT	0x014c
#define	NT_STATUS_REGISTRY_IO_FAILED	0x014d
#define	NT_STATUS_NO_EVENT_PAIR		0x014e
#define	NT_STATUS_UNRECOGNIZED_VOLUME	0x014f
#define	NT_STATUS_SERIAL_NO_DEVICE_INITED	0x0150
#define	NT_STATUS_NO_SUCH_ALIAS		0x0151
#define	NT_STATUS_MEMBER_NOT_IN_ALIAS	0x0152
#define	NT_STATUS_MEMBER_IN_ALIAS	0x0153
#define	NT_STATUS_ALIAS_EXISTS		0x0154
#define	NT_STATUS_LOGON_NOT_GRANTED	0x0155
#define	NT_STATUS_TOO_MANY_SECRETS	0x0156
#define	NT_STATUS_SECRET_TOO_LONG	0x0157
#define	NT_STATUS_INTERNAL_DB_ERROR	0x0158
#define	NT_STATUS_FULLSCREEN_MODE	0x0159
#define	NT_STATUS_TOO_MANY_CONTEXT_IDS	0x015a
#define	NT_STATUS_LOGON_TYPE_NOT_GRANTED	0x015b
#define	NT_STATUS_NOT_REGISTRY_FILE	0x015c
#define	NT_STATUS_NT_CROSS_ENCRYPTION_REQUIRED	0x015d
#define	NT_STATUS_DOMAIN_CTRLR_CONFIG_ERROR	0x015e
#define	NT_STATUS_FT_MISSING_MEMBER	0x015f
#define	NT_STATUS_ILL_FORMED_SERVICE_ENTRY	0x0160
#define	NT_STATUS_ILLEGAL_CHARACTER	0x0161
#define	NT_STATUS_UNMAPPABLE_CHARACTER	0x0162
#define	NT_STATUS_UNDEFINED_CHARACTER	0x0163
#define	NT_STATUS_FLOPPY_VOLUME		0x0164
#define	NT_STATUS_FLOPPY_ID_MARK_NOT_FOUND	0x0165
#define	NT_STATUS_FLOPPY_WRONG_CYLINDER	0x0166
#define	NT_STATUS_FLOPPY_UNKNOWN_ERROR	0x0167
#define	NT_STATUS_FLOPPY_BAD_REGISTERS	0x0168
#define	NT_STATUS_DISK_RECALIBRATE_FAILED	0x0169
#define	NT_STATUS_DISK_OPERATION_FAILED	0x016a
#define	NT_STATUS_DISK_RESET_FAILED	0x016b
#define	NT_STATUS_SHARED_IRQ_BUSY	0x016c
#define	NT_STATUS_FT_ORPHANING		0x016d
#define	NT_STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT	0x016e
#define	NT_STATUS_16F		0x016f
#define	NT_STATUS_170		0x0170
#define	NT_STATUS_171		0x0171
#define	NT_STATUS_PARTITION_FAILURE	0x0172
#define	NT_STATUS_INVALID_BLOCK_LENGTH	0x0173
#define	NT_STATUS_DEVICE_NOT_PARTITIONED	0x0174
#define	NT_STATUS_UNABLE_TO_LOCK_MEDIA	0x0175
#define	NT_STATUS_UNABLE_TO_UNLOAD_MEDIA	0x0176
#define	NT_STATUS_EOM_OVERFLOW		0x0177
#define	NT_STATUS_NO_MEDIA		0x0178
#define	NT_STATUS_179		0x0179
#define	NT_STATUS_NO_SUCH_MEMBER	0x017a
#define	NT_STATUS_INVALID_MEMBER	0x017b
#define	NT_STATUS_KEY_DELETED		0x017c
#define	NT_STATUS_NO_LOG_SPACE		0x017d
#define	NT_STATUS_TOO_MANY_SIDS		0x017e
#define	NT_STATUS_LM_CROSS_ENCRYPTION_REQUIRED	0x017f
#define	NT_STATUS_KEY_HAS_CHILDREN	0x0180
#define	NT_STATUS_CHILD_MUST_BE_VOLATILE	0x0181
#define	NT_STATUS_DEVICE_CONFIGURATION_ERROR	0x0182
#define	NT_STATUS_DRIVER_INTERNAL_ERROR	0x0183
#define	NT_STATUS_INVALID_DEVICE_STATE	0x0184
#define	NT_STATUS_IO_DEVICE_ERROR	0x0185
#define	NT_STATUS_DEVICE_PROTOCOL_ERROR	0x0186
#define	NT_STATUS_BACKUP_CONTROLLER	0x0187
#define	NT_STATUS_LOG_FILE_FULL		0x0188
#define	NT_STATUS_TOO_LATE		0x0189
#define	NT_STATUS_NO_TRUST_LSA_SECRET	0x018a
#define	NT_STATUS_NO_TRUST_SAM_ACCOUNT	0x018b
#define	NT_STATUS_TRUSTED_DOMAIN_FAILURE	0x018c
#define	NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE	0x018d
#define	NT_STATUS_EVENTLOG_FILE_CORRUPT	0x018e
#define	NT_STATUS_EVENTLOG_CANT_START	0x018f
#define	NT_STATUS_TRUST_FAILURE		0x0190
#define	NT_STATUS_MUTANT_LIMIT_EXCEEDED	0x0191
#define	NT_STATUS_NETLOGON_NOT_STARTED	0x0192
#define	NT_STATUS_ACCOUNT_EXPIRED	0x0193
#define	NT_STATUS_POSSIBLE_DEADLOCK	0x0194
#define	NT_STATUS_NETWORK_CREDENTIAL_CONFLICT	0x0195
#define	NT_STATUS_REMOTE_SESSION_LIMIT	0x0196
#define	NT_STATUS_EVENTLOG_FILE_CHANGED	0x0197
#define	NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT	0x0198
#define	NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT	0x0199
#define	NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT	0x019a
#define	NT_STATUS_DOMAIN_TRUST_INCONSISTENT	0x019b
#define	NT_STATUS_FS_DRIVER_REQUIRED	0x019c
#define	NT_STATUS_NO_USER_SESSION_KEY	0x0202
#define	NT_STATUS_USER_SESSION_DELETED	0x0203
#define	NT_STATUS_RESOURCE_LANG_NOT_FOUND	0x0204
#define	NT_STATUS_INSUFF_SERVER_RESOURCES	0x0205
#define	NT_STATUS_INVALID_BUFFER_SIZE	0x0206
#define	NT_STATUS_INVALID_ADDRESS_COMPONENT	0x0207
#define	NT_STATUS_INVALID_ADDRESS_WILDCARD	0x0208
#define	NT_STATUS_TOO_MANY_ADDRESSES	0x0209
#define	NT_STATUS_ADDRESS_ALREADY_EXISTS	0x020a
#define	NT_STATUS_ADDRESS_CLOSED	0x020b
#define	NT_STATUS_CONNECTION_DISCONNECTED	0x020c
#define	NT_STATUS_CONNECTION_RESET	0x020d
#define	NT_STATUS_TOO_MANY_NODES	0x020e
#define	NT_STATUS_TRANSACTION_ABORTED	0x020f
#define	NT_STATUS_TRANSACTION_TIMED_OUT	0x0210
#define	NT_STATUS_TRANSACTION_NO_RELEASE	0x0211
#define	NT_STATUS_TRANSACTION_NO_MATCH	0x0212
#define	NT_STATUS_TRANSACTION_RESPONDED	0x0213
#define	NT_STATUS_TRANSACTION_INVALID_ID	0x0214
#define	NT_STATUS_TRANSACTION_INVALID_TYPE	0x0215
#define	NT_STATUS_NOT_SERVER_SESSION	0x0216
#define	NT_STATUS_NOT_CLIENT_SESSION	0x0217
#define	NT_STATUS_CANNOT_LOAD_REGISTRY_FILE	0x0218
#define	NT_STATUS_DEBUG_ATTACH_FAILED	0x0219
#define	NT_STATUS_SYSTEM_PROCESS_TERMINATED	0x021a
#define	NT_STATUS_DATA_NOT_ACCEPTED	0x021b
#define	NT_STATUS_NO_BROWSER_SERVERS_FOUND	0x021c
#define	NT_STATUS_VDM_HARD_ERROR	0x021d
#define	NT_STATUS_DRIVER_CANCEL_TIMEOUT	0x021e
#define	NT_STATUS_REPLY_MESSAGE_MISMATCH	0x021f
#define	NT_STATUS_MAPPED_ALIGNMENT	0x0220
#define	NT_STATUS_IMAGE_CHECKSUM_MISMATCH	0x0221
#define	NT_STATUS_LOST_WRITEBEHIND_DATA	0x0222
#define	NT_STATUS_CLIENT_SERVER_PARAMETERS_INVALID	0x0223
#define	NT_STATUS_PASSWORD_MUST_CHANGE	0x0224
#define	NT_STATUS_NOT_FOUND		0x0225
#define	NT_STATUS_NOT_TINY_STREAM	0x0226
#define	NT_STATUS_RECOVERY_FAILURE	0x0227
#define	NT_STATUS_STACK_OVERFLOW_READ	0x0228
#define	NT_STATUS_FAIL_CHECK		0x0229
#define	NT_STATUS_DUPLICATE_OBJECTID	0x022a
#define	NT_STATUS_OBJECTID_EXISTS	0x022b
#define	NT_STATUS_CONVERT_TO_LARGE	0x022c
#define	NT_STATUS_RETRY			0x022d
#define	NT_STATUS_FOUND_OUT_OF_SCOPE	0x022e
#define	NT_STATUS_ALLOCATE_BUCKET	0x022f
#define	NT_STATUS_PROPSET_NOT_FOUND	0x0230
#define	NT_STATUS_MARSHALL_OVERFLOW	0x0231
#define	NT_STATUS_INVALID_VARIANT	0x0232
#define	NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND	0x0233
#define	NT_STATUS_ACCOUNT_LOCKED_OUT	0x0234
#define	NT_STATUS_HANDLE_NOT_CLOSABLE	0x0235
#define	NT_STATUS_CONNECTION_REFUSED	0x0236
#define	NT_STATUS_GRACEFUL_DISCONNECT	0x0237
#define	NT_STATUS_ADDRESS_ALREADY_ASSOCIATED	0x0238
#define	NT_STATUS_ADDRESS_NOT_ASSOCIATED	0x0239
#define	NT_STATUS_CONNECTION_INVALID	0x023a
#define	NT_STATUS_CONNECTION_ACTIVE	0x023b
#define	NT_STATUS_NETWORK_UNREACHABLE	0x023c
#define	NT_STATUS_HOST_UNREACHABLE	0x023d
#define	NT_STATUS_PROTOCOL_UNREACHABLE	0x023e
#define	NT_STATUS_PORT_UNREACHABLE	0x023f
#define	NT_STATUS_REQUEST_ABORTED	0x0240
#define	NT_STATUS_CONNECTION_ABORTED	0x0241
#define	NT_STATUS_BAD_COMPRESSION_BUFFER	0x0242
#define	NT_STATUS_USER_MAPPED_FILE	0x0243
#define	NT_STATUS_AUDIT_FAILED		0x0244
#define	NT_STATUS_TIMER_RESOLUTION_NOT_SET	0x0245
#define	NT_STATUS_CONNECTION_COUNT_LIMIT	0x0246
#define	NT_STATUS_LOGIN_TIME_RESTRICTION	0x0247
#define	NT_STATUS_LOGIN_WKSTA_RESTRICTION	0x0248
#define	NT_STATUS_IMAGE_MP_UP_MISMATCH	0x0249
#define	NT_STATUS_INSUFFICIENT_LOGON_INFO	0x0250
#define	NT_STATUS_BAD_DLL_ENTRYPOINT	0x0251
#define	NT_STATUS_BAD_SERVICE_ENTRYPOINT	0x0252
#define	NT_STATUS_LPC_REPLY_LOST	0x0253
#define	NT_STATUS_IP_ADDRESS_CONFLICT1	0x0254
#define	NT_STATUS_IP_ADDRESS_CONFLICT2	0x0255
#define	NT_STATUS_REGISTRY_QUOTA_LIMIT	0x0256
#define	NT_STATUS_PATH_NOT_COVERED	0x0257
#define	NT_STATUS_NO_CALLBACK_ACTIVE	0x0258
#define	NT_STATUS_LICENSE_QUOTA_EXCEEDED	0x0259
#define	NT_STATUS_PWD_TOO_SHORT		0x025a
#define	NT_STATUS_PWD_TOO_RECENT	0x025b
#define	NT_STATUS_PWD_HISTORY_CONFLICT	0x025c
#define	NT_STATUS_PLUGPLAY_NO_DEVICE	0x025e
#define	NT_STATUS_UNSUPPORTED_COMPRESSION	0x025f
#define	NT_STATUS_INVALID_HW_PROFILE	0x0260
#define	NT_STATUS_INVALID_PLUGPLAY_DEVICE_PATH	0x0261
#define	NT_STATUS_DRIVER_ORDINAL_NOT_FOUND	0x0262
#define	NT_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND	0x0263
#define	NT_STATUS_RESOURCE_NOT_OWNED	0x0264
#define	NT_STATUS_TOO_MANY_LINKS	0x0265
#define	NT_STATUS_QUOTA_LIST_INCONSISTENT	0x0266
#define	NT_STATUS_FILE_IS_OFFLINE	0x0267

#define	NT_STATUS_LICENSE_VIOLATION	0x026a

#define	NT_STATUS_DFS_UNAVAILABLE	0x026d
#define	NT_STATUS_VOLUME_DISMOUNTED	0x026e

#define	NT_STATUS_NOT_A_REPARSE_POINT	0x0275

#define	NT_STATUS_REPARSE_POINT_NOT_RESOLVED	0x0280
#define	NT_STATUS_DIRECTORY_IS_A_REPARSE_POINT	0x0281

#define	NT_STATUS_ENCRYPTION_FAILED	0x028a
#define	NT_STATUS_DECRYPTION_FAILED	0x028b
#define	NT_STATUS_RANGE_NOT_FOUND	0x028c
#define	NT_STATUS_NO_RECOVERY_POLICY	0x028d
#define	NT_STATUS_NO_EFS		0x028e
#define	NT_STATUS_WRONG_EFS		0x028f
#define	NT_STATUS_NO_USER_KEYS		0x0290
#define	NT_STATUS_FILE_NOT_ENCRYPTED	0x0291

#define	NT_STATUS_FILE_ENCRYPTED	0x0293

#define	NT_STATUS_VOLUME_NOT_UPGRADED	0x029c

#define	NT_STATUS_KDC_CERT_EXPIRED	0x040e
/*
 * 0x00010000-0x0001ffff are "DBG" errors
 * 0x00020000-0x0003ffff are "RPC" errors
 * 0x00040000-0x0004ffff are "PNP" errors
 * 0x000A0000-0x000Affff are "CTX" errors
 * 0x00130000-0x0013ffff are "CLUSTER" errors
 * 0x00140000-0x0014ffff are "ACPI" errors
 * 0x00150000-0x0015ffff are "SXS" errors
 */

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

#endif /* _NETSMB_SMB_H_ */
