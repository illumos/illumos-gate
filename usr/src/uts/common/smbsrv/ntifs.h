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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#ifndef _SMBSRV_NTIFS_H
#define	_SMBSRV_NTIFS_H

/*
 * This file provides definitions compatible with the NT Installable
 * File System (IFS) interface. This header file also defines the Security
 * Descriptor module from Windows.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/acl.h>
#include <sys/list.h>
#include <smbsrv/smb_sid.h>

/*
 * The Volume and Directory bits are for SMB rather than NT.
 * NT has an explicit Normal bit; this bit is implied in SMB
 * when the Hidden, System and Directory bits are not set.
 *
 * File attributes and creation flags share the same 32-bit
 * space.
 */
#define	FILE_ATTRIBUTE_READONLY			0x00000001
#define	FILE_ATTRIBUTE_HIDDEN			0x00000002
#define	FILE_ATTRIBUTE_SYSTEM			0x00000004
#define	FILE_ATTRIBUTE_VOLUME			0x00000008
#define	FILE_ATTRIBUTE_DIRECTORY		0x00000010
#define	FILE_ATTRIBUTE_ARCHIVE			0x00000020
#define	FILE_ATTRIBUTE_DEVICE			0x00000040
#define	FILE_ATTRIBUTE_NORMAL			0x00000080
#define	FILE_ATTRIBUTE_TEMPORARY		0x00000100
#define	FILE_ATTRIBUTE_SPARSE_FILE		0x00000200
#define	FILE_ATTRIBUTE_REPARSE_POINT		0x00000400
#define	FILE_ATTRIBUTE_COMPRESSED		0x00000800
#define	FILE_ATTRIBUTE_OFFLINE			0x00001000
#define	FILE_ATTRIBUTE_NOT_CONTENT_INDEXED	0x00002000
#define	FILE_ATTRIBUTE_ENCRYPTED		0x00004000
#define	FILE_ATTRIBUTE_VIRTUAL			0x00010000
#define	FILE_FLAG_OPEN_NO_RECALL		0x00100000
#define	FILE_FLAG_OPEN_REPARSE_POINT		0x00200000
#define	FILE_FLAG_POSIX_SEMANTICS		0x01000000
#define	FILE_FLAG_BACKUP_SEMANTICS		0x02000000
#define	FILE_FLAG_DELETE_ON_CLOSE		0x04000000
#define	FILE_FLAG_SEQUENTIAL_SCAN		0x08000000
#define	FILE_FLAG_RANDOM_ACCESS			0x10000000
#define	FILE_FLAG_NO_BUFFERING			0x20000000
#define	FILE_FLAG_OVERLAPPED			0x40000000
#define	FILE_FLAG_WRITE_THROUGH			0x80000000

#define	FILE_ATTRIBUTE_VALID_FLAGS		0x00001fb7
#define	FILE_ATTRIBUTE_VALID_SET_FLAGS		0x00001fa7
#define	FILE_ATTRIBUTE_MASK			0x00003FFF

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
	FileDirectoryInformation		= 1,
	FileFullDirectoryInformation,		/* 2 */
	FileBothDirectoryInformation,		/* 3 */
	FileBasicInformation,			/* 4 */
	FileStandardInformation,		/* 5 */
	FileInternalInformation,		/* 6 */
	FileEaInformation,			/* 7 */
	FileAccessInformation,			/* 8 */
	FileNameInformation,			/* 9 */
	FileRenameInformation,			/* 10 */
	FileLinkInformation,			/* 11 */
	FileNamesInformation,			/* 12 */
	FileDispositionInformation,		/* 13 */
	FilePositionInformation,		/* 14 */
	FileFullEaInformation,			/* 15 */
	FileModeInformation,			/* 16 */
	FileAlignmentInformation,		/* 17 */
	FileAllInformation,			/* 18 */
	FileAllocationInformation,		/* 19 */
	FileEndOfFileInformation,		/* 20 */
	FileAlternateNameInformation,		/* 21 */
	FileStreamInformation,			/* 22 */
	FilePipeInformation,			/* 23 */
	FilePipeLocalInformation,		/* 24 */
	FilePipeRemoteInformation,		/* 25 */
	FileMailslotQueryInformation,		/* 26 */
	FileMailslotSetInformation,		/* 27 */
	FileCompressionInformation,		/* 28 */
	FileObjectIdInformation,		/* 29 */
	FileCompletionInformation,		/* 30 */
	FileMoveClusterInformation,		/* 31 */
	FileQuotaInformation,			/* 32 */
	FileReparsePointInformation,		/* 33 */
	FileNetworkOpenInformation,		/* 34 */
	FileAttributeTagInformation,		/* 35 */
	FileTrackingInformation,		/* 36 */
	FileIdBothDirectoryInformation,		/* 37 */
	FileIdFullDirectoryInformation,		/* 38 */
	FileValidDataLengthInformation,		/* 39 */
	FileShortNameInformation,		/* 40 */
	FileInformationReserved41,		/* 41 */
	FileInformationReserved42,		/* 42 */
	FileInformationReserved43,		/* 43 */
	FileSfioReserveInformation,		/* 44 */
	FileSfioVolumeInformation,		/* 45 */
	FileHardLinkInformation,		/* 46 */
	FileInformationReserved47,		/* 47 */
	FileNormalizedNameInformation,		/* 48 */
	FileInformationReserved49,		/* 49 */
	FileIdGlobalTxDirectoryInformation,	/* 50 */
	FileInformationReserved51,		/* 51 */
	FileInformationReserved52,		/* 52 */
	FileInformationReserved53,		/* 53 */
	FileStandardLinkInformation,		/* 54 */
	FileMaximumInformation
} FILE_INFORMATION_CLASS;

/*
 * Define the file system information class values.
 */
typedef enum _FILE_FS_INFORMATION_CLASS {
	FileFsVolumeInformation		= 1,
	FileFsLabelInformation,		/* 2 */
	FileFsSizeInformation,		/* 3 */
	FileFsDeviceInformation,	/* 4 */
	FileFsAttributeInformation,	/* 5 */
	FileFsControlInformation,	/* 6 */
	FileFsFullSizeInformation,	/* 7 */
	FileFsObjectIdInformation,	/* 8 */
	FileFsDriverPathInformation	/* 9 */
} FILE_FS_INFORMATION_CLASS;

/*
 * Discretionary Access Control List (DACL)
 *
 * A Discretionary Access Control List (DACL), often abbreviated to
 * ACL, is a list of access controls which either allow or deny access
 * for users or groups to a resource. There is a list header followed
 * by a list of access control entries (ACE). Each ACE specifies the
 * access allowed or denied to a single user or group (identified by
 * a SID).
 *
 * There is another access control list object called a System Access
 * Control List (SACL), which is used to control auditing, but no
 * support is provideed for SACLs at this time.
 *
 * ACL header format:
 *
 *    3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *    1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *   +-------------------------------+---------------+---------------+
 *   |            AclSize            |      Sbz1     |  AclRevision  |
 *   +-------------------------------+---------------+---------------+
 *   |              Sbz2             |           AceCount            |
 *   +-------------------------------+-------------------------------+
 *
 * AclRevision specifies the revision level of the ACL. This value should
 * be ACL_REVISION, unless the ACL contains an object-specific ACE, in which
 * case this value must be ACL_REVISION_DS. All ACEs in an ACL must be at the
 * same revision level.
 *
 * ACE header format:
 *
 *    3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *    1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *   +---------------+-------+-------+---------------+---------------+
 *   |            AceSize            |    AceFlags   |     AceType   |
 *   +---------------+-------+-------+---------------+---------------+
 *
 * Access mask format:
 *
 *    3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *    1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *   +---------------+---------------+-------------------------------+
 *   |G|G|G|G|Res'd|A| StandardRights|         SpecificRights        |
 *   |R|W|E|A|     |S|               |                               |
 *   +-+-------------+---------------+-------------------------------+
 *
 *   typedef struct ACCESS_MASK {
 *       WORD SpecificRights;
 *       BYTE StandardRights;
 *       BYTE AccessSystemAcl : 1;
 *       BYTE Reserved : 3;
 *       BYTE GenericAll : 1;
 *       BYTE GenericExecute : 1;
 *       BYTE GenericWrite : 1;
 *       BYTE GenericRead : 1;
 *   } ACCESS_MASK;
 *
 */

#define	ACL_REVISION1			1
#define	ACL_REVISION2			2
#define	MIN_ACL_REVISION2		ACL_REVISION2
#define	ACL_REVISION3			3
#define	ACL_REVISION4			4
#define	MAX_ACL_REVISION		ACL_REVISION4

/*
 * Current ACE and ACL revision Levels
 */
#define	ACE_REVISION			1
#define	ACL_REVISION			ACL_REVISION2
#define	ACL_REVISION_DS			ACL_REVISION4


#define	ACCESS_ALLOWED_ACE_TYPE		0
#define	ACCESS_DENIED_ACE_TYPE		1
#define	SYSTEM_AUDIT_ACE_TYPE		2
#define	SYSTEM_ALARM_ACE_TYPE		3

/*
 *  se_flags
 * ----------
 * Specifies a set of ACE type-specific control flags. This member can be a
 * combination of the following values.
 *
 * CONTAINER_INHERIT_ACE: Child objects that are containers, such as
 *		directories, inherit the ACE as an effective ACE. The inherited
 *		ACE is inheritable unless the NO_PROPAGATE_INHERIT_ACE bit flag
 *		is also set.
 *
 * INHERIT_ONLY_ACE: Indicates an inherit-only ACE which does not control
 *		access to the object to which it is attached.
 *		If this flag is not set,
 *		the ACE is an effective ACE which controls access to the object
 *		to which it is attached.
 * 		Both effective and inherit-only ACEs can be inherited
 *		depending on the state of the other inheritance flags.
 *
 * INHERITED_ACE: Windows 2000/XP: Indicates that the ACE was inherited.
 *		The system sets this bit when it propagates an
 *		inherited ACE to a child object.
 *
 * NO_PROPAGATE_INHERIT_ACE: If the ACE is inherited by a child object, the
 *		system clears the OBJECT_INHERIT_ACE and CONTAINER_INHERIT_ACE
 *		flags in the inherited ACE.
 *		This prevents the ACE from being inherited by
 *		subsequent generations of objects.
 *
 * OBJECT_INHERIT_ACE: Noncontainer child objects inherit the ACE as an
 *		effective ACE.  For child objects that are containers,
 *		the ACE is inherited as an inherit-only ACE unless the
 *		NO_PROPAGATE_INHERIT_ACE bit flag is also set.
 */
#define	OBJECT_INHERIT_ACE		0x01
#define	CONTAINER_INHERIT_ACE		0x02
#define	NO_PROPOGATE_INHERIT_ACE	0x04
#define	INHERIT_ONLY_ACE		0x08
#define	INHERITED_ACE			0x10
#define	INHERIT_MASK_ACE		0x1F


/*
 * These flags are only used in system audit or alarm ACEs to
 * indicate when an audit message should be generated, i.e.
 * on successful access or on unsuccessful access.
 */
#define	SUCCESSFUL_ACCESS_ACE_FLAG	0x40
#define	FAILED_ACCESS_ACE_FLAG		0x80

/*
 * se_bsize is the size, in bytes, of ACE as it appears on the wire.
 * se_sln is used to sort the ACL when it's required.
 */
typedef struct smb_acehdr {
	uint8_t		se_type;
	uint8_t		se_flags;
	uint16_t	se_bsize;
} smb_acehdr_t;

typedef struct smb_ace {
	smb_acehdr_t	se_hdr;
	uint32_t	se_mask;
	list_node_t	se_sln;
	smb_sid_t	*se_sid;
} smb_ace_t;

/*
 * sl_bsize is the size of ACL in bytes as it appears on the wire.
 */
typedef struct smb_acl {
	uint8_t		sl_revision;
	uint16_t	sl_bsize;
	uint16_t	sl_acecnt;
	smb_ace_t	*sl_aces;
	list_t		sl_sorted;
} smb_acl_t;

/*
 * ACE/ACL header size, in byte, as it appears on the wire
 */
#define	SMB_ACE_HDRSIZE		4
#define	SMB_ACL_HDRSIZE		8

/*
 * Security Descriptor (SD)
 *
 * Security descriptors provide protection for objects, for example
 * files and directories. It identifies the owner and primary group
 * (SIDs) and contains an access control list. When a user tries to
 * access an object their SID is compared to the permissions in the
 * DACL to determine if access should be allowed or denied. Note that
 * this is a simplification because there are other factors, such as
 * default behavior and privileges to be taken into account (see also
 * access tokens).
 *
 * The boolean flags have the following meanings when set:
 *
 * SE_OWNER_DEFAULTED indicates that the SID pointed to by the Owner
 * field was provided by a defaulting mechanism rather than explicitly
 * provided by the original provider of the security descriptor. This
 * may affect the treatment of the SID with respect to inheritance of
 * an owner.
 *
 * SE_GROUP_DEFAULTED indicates that the SID in the Group field was
 * provided by a defaulting mechanism rather than explicitly provided
 * by the original provider of the security descriptor.  This may
 * affect the treatment of the SID with respect to inheritance of a
 * primary group.
 *
 * SE_DACL_PRESENT indicates that the security descriptor contains a
 * discretionary ACL. If this flag is set and the Dacl field of the
 * SECURITY_DESCRIPTOR is null, then a null ACL is explicitly being
 * specified.
 *
 * SE_DACL_DEFAULTED indicates that the ACL pointed to by the Dacl
 * field was provided by a defaulting mechanism rather than explicitly
 * provided by the original provider of the security descriptor. This
 * may affect the treatment of the ACL with respect to inheritance of
 * an ACL. This flag is ignored if the DaclPresent flag is not set.
 *
 * SE_SACL_PRESENT indicates that the security descriptor contains a
 * system ACL pointed to by the Sacl field. If this flag is set and
 * the Sacl field of the SECURITY_DESCRIPTOR is null, then an empty
 * (but present) ACL is being specified.
 *
 * SE_SACL_DEFAULTED indicates that the ACL pointed to by the Sacl
 * field was provided by a defaulting mechanism rather than explicitly
 * provided by the original provider of the security descriptor. This
 * may affect the treatment of the ACL with respect to inheritance of
 * an ACL. This flag is ignored if the SaclPresent flag is not set.
 *
 * SE_DACL_PROTECTED Prevents ACEs set on the DACL of the parent container
 * (and any objects above the parent container in the directory hierarchy)
 * from being applied to the object's DACL.
 *
 * SE_SACL_PROTECTED Prevents ACEs set on the SACL of the parent container
 * (and any objects above the parent container in the directory hierarchy)
 * from being applied to the object's SACL.
 *
 * Note that the SE_DACL_PRESENT flag needs to be present to set
 * SE_DACL_PROTECTED and SE_SACL_PRESENT needs to be present to set
 * SE_SACL_PROTECTED.
 *
 * SE_SELF_RELATIVE indicates that the security descriptor is in self-
 * relative form. In this form, all fields of the security descriptor
 * are contiguous in memory and all pointer fields are expressed as
 * offsets from the beginning of the security descriptor.
 *
 *    3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *    1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *   +---------------------------------------------------------------+
 *   |            Control            |Reserved1 (SBZ)|   Revision    |
 *   +---------------------------------------------------------------+
 *   |                            Owner                              |
 *   +---------------------------------------------------------------+
 *   |                            Group                              |
 *   +---------------------------------------------------------------+
 *   |                            Sacl                               |
 *   +---------------------------------------------------------------+
 *   |                            Dacl                               |
 *   +---------------------------------------------------------------+
 *
 */

#define	SMB_OWNER_SECINFO	0x0001
#define	SMB_GROUP_SECINFO	0x0002
#define	SMB_DACL_SECINFO	0x0004
#define	SMB_SACL_SECINFO	0x0008
#define	SMB_ALL_SECINFO		0x000F
#define	SMB_ACL_SECINFO		(SMB_DACL_SECINFO | SMB_SACL_SECINFO)

#define	SECURITY_DESCRIPTOR_REVISION	1


#define	SE_OWNER_DEFAULTED		0x0001
#define	SE_GROUP_DEFAULTED		0x0002
#define	SE_DACL_PRESENT			0x0004
#define	SE_DACL_DEFAULTED		0x0008
#define	SE_SACL_PRESENT			0x0010
#define	SE_SACL_DEFAULTED		0x0020
#define	SE_DACL_AUTO_INHERIT_REQ	0x0100
#define	SE_SACL_AUTO_INHERIT_REQ	0x0200
#define	SE_DACL_AUTO_INHERITED		0x0400
#define	SE_SACL_AUTO_INHERITED		0x0800
#define	SE_DACL_PROTECTED		0x1000
#define	SE_SACL_PROTECTED		0x2000
#define	SE_SELF_RELATIVE		0x8000

#define	SE_DACL_INHERITANCE_MASK	0x1500
#define	SE_SACL_INHERITANCE_MASK	0x2A00

/*
 * Security descriptor structures:
 *
 * smb_sd_t     SD in SMB pointer form
 * smb_fssd_t   SD in filesystem form
 *
 * Filesystems (e.g. ZFS/UFS) don't have something equivalent
 * to SD. The items comprising a SMB SD are kept separately in
 * filesystem. smb_fssd_t is introduced as a helper to provide
 * the required abstraction for CIFS code.
 */

typedef struct smb_sd {
	uint8_t		sd_revision;
	uint16_t	sd_control;
	smb_sid_t 	*sd_owner;	/* SID file owner */
	smb_sid_t 	*sd_group;	/* SID group (for POSIX) */
	smb_acl_t 	*sd_sacl;	/* ACL System (audits) */
	smb_acl_t 	*sd_dacl;	/* ACL Discretionary (perm) */
} smb_sd_t;

/*
 * SD header size as it appears on the wire
 */
#define	SMB_SD_HDRSIZE	20

/*
 * values for smb_fssd.sd_flags
 */
#define	SMB_FSSD_FLAGS_DIR	0x01

typedef struct smb_fssd {
	uint32_t	sd_secinfo;
	uint32_t	sd_flags;
	uid_t		sd_uid;
	gid_t		sd_gid;
	acl_t		*sd_zdacl;
	acl_t		*sd_zsacl;
} smb_fssd_t;

void smb_sd_init(smb_sd_t *, uint8_t);
void smb_sd_term(smb_sd_t *);
uint32_t smb_sd_get_secinfo(smb_sd_t *);
uint32_t smb_sd_len(smb_sd_t *, uint32_t);
uint32_t smb_sd_tofs(smb_sd_t *, smb_fssd_t *);

void smb_fssd_init(smb_fssd_t *, uint32_t, uint32_t);
void smb_fssd_term(smb_fssd_t *);

void smb_acl_sort(smb_acl_t *);
void smb_acl_free(smb_acl_t *);
smb_acl_t *smb_acl_alloc(uint8_t, uint16_t, uint16_t);
smb_acl_t *smb_acl_from_zfs(acl_t *);
uint32_t smb_acl_to_zfs(smb_acl_t *, uint32_t, int, acl_t **);
uint16_t smb_acl_len(smb_acl_t *);
boolean_t smb_acl_isvalid(smb_acl_t *, int);

void smb_fsacl_free(acl_t *);
acl_t *smb_fsacl_alloc(int, int);

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_NTIFS_H */
