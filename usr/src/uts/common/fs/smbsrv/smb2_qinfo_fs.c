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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_QUERY_INFO
 *
 * [MS-FSCC 2.5] If a file system does not implement ...
 * an Information Classs, NT_STATUS_INVALID_PARAMETER...
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/ntifs.h>

uint32_t smb2_qfs_volume(smb_request_t *);
uint32_t smb2_qfs_size(smb_request_t *);
uint32_t smb2_qfs_device(smb_request_t *);
uint32_t smb2_qfs_attr(smb_request_t *);
uint32_t smb2_qfs_control(smb_request_t *);
uint32_t smb2_qfs_fullsize(smb_request_t *);
uint32_t smb2_qfs_obj_id(smb_request_t *);
uint32_t smb2_qfs_sectorsize(smb_request_t *);

uint32_t
smb2_qinfo_fs(smb_request_t *sr, smb_queryinfo_t *qi)
{
	uint32_t status;

	switch (qi->qi_InfoClass) {

	/* pg 153 */
	case FileFsVolumeInformation:	/* 1 */
		status = smb2_qfs_volume(sr);
		break;
	case FileFsSizeInformation:	/* 3 */
		status = smb2_qfs_size(sr);
		break;
	case FileFsDeviceInformation:	/* 4 */
		status = smb2_qfs_device(sr);
		break;
	case FileFsAttributeInformation: /* 5 */
		status = smb2_qfs_attr(sr);
		break;
	case FileFsControlInformation:	/* 6 */
		status = smb2_qfs_control(sr);
		break;
	case FileFsFullSizeInformation:	/* 7 */
		status = smb2_qfs_fullsize(sr);
		break;
	case FileFsObjectIdInformation:	/* 8 */
		status = smb2_qfs_obj_id(sr);
		break;
	case FileFsDriverPathInformation:	/* 9 */
	case FileFsVolumeFlagsInformation:	/* A */
		status = NT_STATUS_INVALID_INFO_CLASS;
		break;
	case FileFsSectorSizeInformation:	/* B */
		status = smb2_qfs_sectorsize(sr);
		break;
	default: /* there are some infoclasses we don't yet handle */
		status = NT_STATUS_INVALID_INFO_CLASS;
#ifdef	DEBUG
		cmn_err(CE_NOTE, "unknown InfoClass 0x%x", qi->qi_InfoClass);
#endif
		break;
	}

	return (status);
}

/*
 * FileFsVolumeInformation
 */
uint32_t
smb2_qfs_volume(smb_request_t *sr)
{
	smb_tree_t *tree = sr->tid_tree;
	smb_node_t *snode;
	fsid_t fsid;
	uint32_t LabelLength;

	if (!STYPE_ISDSK(tree->t_res_type))
		return (NT_STATUS_INVALID_PARAMETER);

	snode = tree->t_snode;
	fsid = SMB_NODE_FSID(snode);

	LabelLength = smb_wcequiv_strlen(tree->t_volume);

	/*
	 * NT has the "supports objects" flag set to 1.
	 */
	(void) smb_mbc_encodef(
	    &sr->raw_data, "qllb.U",
	    0LL,	/* Volume creation time (q) */
	    fsid.val[0],	/* serial no.   (l) */
	    LabelLength,		/*	(l) */
	    0,		/* Supports objects	(b) */
	    /* reserved				(.) */
	    tree->t_volume);		/*	(U) */

	return (0);
}

/*
 * FileFsSizeInformation
 */
uint32_t
smb2_qfs_size(smb_request_t *sr)
{
	smb_fssize_t		fssize;
	smb_tree_t *tree = sr->tid_tree;
	int rc;

	if (!STYPE_ISDSK(tree->t_res_type))
		return (NT_STATUS_INVALID_PARAMETER);

	rc = smb_fssize(sr, &fssize);
	if (rc)
		return (smb_errno2status(rc));

	(void) smb_mbc_encodef(
	    &sr->raw_data, "qqll",
	    fssize.fs_caller_units,
	    fssize.fs_caller_avail,
	    fssize.fs_sectors_per_unit,
	    fssize.fs_bytes_per_sector);

	return (0);
}

/*
 * FileFsFullSizeInformation
 */
uint32_t
smb2_qfs_fullsize(smb_request_t *sr)
{
	smb_fssize_t		fssize;
	smb_tree_t *tree = sr->tid_tree;
	int rc;

	if (!STYPE_ISDSK(tree->t_res_type))
		return (NT_STATUS_INVALID_PARAMETER);

	rc = smb_fssize(sr, &fssize);
	if (rc)
		return (smb_errno2status(rc));

	(void) smb_mbc_encodef(
	    &sr->raw_data, "qqqll",
	    fssize.fs_caller_units,
	    fssize.fs_caller_avail,
	    fssize.fs_volume_avail,
	    fssize.fs_sectors_per_unit,
	    fssize.fs_bytes_per_sector);

	return (0);
}

/*
 * FileFsDeviceInformation
 */
uint32_t
smb2_qfs_device(smb_request_t *sr)
{
	smb_tree_t *tree = sr->tid_tree;
	uint32_t DeviceType;
	uint32_t Characteristics;

	if (!STYPE_ISDSK(tree->t_res_type))
		return (NT_STATUS_INVALID_PARAMETER);

	DeviceType = FILE_DEVICE_DISK;
	Characteristics = FILE_DEVICE_IS_MOUNTED;

	(void) smb_mbc_encodef(
	    &sr->raw_data, "ll",
	    DeviceType,
	    Characteristics);

	return (0);
}

/*
 * FileFsAttributeInformation
 */
uint32_t
smb2_qfs_attr(smb_request_t *sr)
{
	smb_tree_t *tree = sr->tid_tree;
	char *fsname;
	uint32_t namelen;
	uint32_t FsAttr;

	/* This call is OK on all tree types. */
	switch (tree->t_res_type & STYPE_MASK) {
	case STYPE_IPC:
		fsname = "PIPE";
		break;
	case STYPE_DISKTREE:
		fsname = "NTFS"; /* A lie, but compatible... */
		break;
	case STYPE_PRINTQ:
	case STYPE_DEVICE:
	default: /* gcc -Wuninitialized */
		return (NT_STATUS_INVALID_PARAMETER);
	}
	namelen = smb_wcequiv_strlen(fsname);

	/*
	 * Todo: Store the FsAttributes in the tree object,
	 * then just return that directly here.
	 */
	FsAttr = FILE_CASE_PRESERVED_NAMES;
	if (tree->t_flags & SMB_TREE_UNICODE_ON_DISK)
		FsAttr |= FILE_UNICODE_ON_DISK;
	if (tree->t_flags & SMB_TREE_SUPPORTS_ACLS)
		FsAttr |= FILE_PERSISTENT_ACLS;
	if ((tree->t_flags & SMB_TREE_CASEINSENSITIVE) == 0)
		FsAttr |= FILE_CASE_SENSITIVE_SEARCH;
	if (tree->t_flags & SMB_TREE_STREAMS)
		FsAttr |= FILE_NAMED_STREAMS;
	if (tree->t_flags & SMB_TREE_QUOTA)
		FsAttr |= FILE_VOLUME_QUOTAS;
	if (tree->t_flags & SMB_TREE_SPARSE)
		FsAttr |= FILE_SUPPORTS_SPARSE_FILES;

	(void) smb_mbc_encodef(
	    &sr->raw_data, "lllU",
	    FsAttr,
	    MAXNAMELEN-1,
	    namelen,
	    fsname);

	return (0);
}

/*
 * FileFsControlInformation
 */
uint32_t
smb2_qfs_control(smb_request_t *sr)
{
	smb_tree_t *tree = sr->tid_tree;

	if (!STYPE_ISDSK(tree->t_res_type))
		return (NT_STATUS_INVALID_PARAMETER);
	if (!smb_tree_has_feature(sr->tid_tree, SMB_TREE_QUOTA)) {
		/*
		 * Strange error per. [MS-FSCC 2.5.2]
		 * which means quotas not supported.
		 */
		return (NT_STATUS_VOLUME_NOT_UPGRADED);
	}

	(void) smb_mbc_encodef(
	    &sr->raw_data, "qqqqqll",
	    0,		/* free space start filtering - MUST be 0 */
	    0,		/* free space threshold - MUST be 0 */
	    0,		/* free space stop filtering - MUST be 0 */
	    SMB_QUOTA_UNLIMITED,	/* default quota threshold */
	    SMB_QUOTA_UNLIMITED,	/* default quota limit */
	    FILE_VC_QUOTA_ENFORCE,	/* fs control flag */
	    0);				/* pad bytes */

	return (0);
}

/*
 * FileFsObjectIdInformation
 */
/* ARGSUSED */
uint32_t
smb2_qfs_obj_id(smb_request_t *sr)
{
	return (NT_STATUS_INVALID_PARAMETER);
}

/*
 * Not sure yet where these should go.
 * Flags in FileFsSectorSizeInformation
 */

#define	SSINFO_FLAGS_ALIGNED_DEVICE	0x00000001
// When set, this flag indicates that the first physical sector of the device
// is aligned with the first logical sector. When not set, the first physical
// sector of the device is misaligned with the first logical sector.

#define	SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE	0x00000002
// When set, this flag indicates that the partition is aligned to physical
// sector boundaries on the storage device.

#define	SSINFO_FLAGS_NO_SEEK_PENALTY	0x00000004
// When set, the device reports that it does not incur a seek penalty (this
// typically indicates that the device does not have rotating media, such as
// flash-based disks).

#define	SSINFO_FLAGS_TRIM_ENABLED	0x00000008
// When set, the device supports TRIM operations, either T13 (ATA) TRIM or
// T10 (SCSI/SAS) UNMAP.

#define	SSINFO_OFFSET_UNKNOWN		0xffffffff
// For "Alignment" fields below

/*
 * We have to lie to Windows Hyper-V about our logical record size,
 * because with larger sizes it fails setting up a virtual disk.
 */
int smb2_max_logical_sector_size = 4096;

/*
 * FileFsSectorSizeInformation
 *
 * Returns a FILE_FS_SECTOR_SIZE_INFORMATION
 * See: [MS-FSCC] 2.5.8 FileFsSizeInformation
 *
 * LogicalBytesPerSector (4 bytes): ... number of bytes in a logical sector
 *   for the device backing the volume. This field is the unit of logical
 *   addressing for the device and is not the unit of atomic write.
 * PhysicalBytesPerSectorForAtomicity (4 bytes): ... number of bytes in a
 *   physical sector for the device backing the volume.  This is the reported
 *   physical sector size of the device and is the unit of atomic write.
 * PhysicalBytesPerSectorForPerformance (4 bytes): ... number of bytes in a
 *   physical sector for the device backing the volume. This is the reported
 *   physical sector size of the device and is the unit of performance.
 * FileSystemEffectivePhysicalBytesPerSectorForAtomicity (4 bytes): unit, in
 *   bytes, that the file system on the volume will use for internal operations
 *   that require alignment and atomicity.
 * Flags (4 bytes): See ...
 * ByteOffsetForSectorAlignment (4 bytes): ... logical sector offset within the
 *   first physical sector where the first logical sector is placed, in bytes.
 *   If this value is set to SSINFO_OFFSET_UNKNOWN (0xffffffff), there was
 *   insufficient information to compute this field.
 * ByteOffsetForPartitionAlignment (4 bytes): ... byte offset from the first
 *   physical sector where the first partition is placed. If this value is
 *   set to SSINFO_OFFSET_UNKNOWN (0xffffffff), there was either insufficient
 *   information or an error was encountered in computing this field.
 */
uint32_t
smb2_qfs_sectorsize(smb_request_t *sr)
{
	smb_fssize_t		fssize;
	smb_tree_t *tree = sr->tid_tree;
	uint32_t lbps, pbps;
	uint32_t flags;
	int rc;

	if (!STYPE_ISDSK(tree->t_res_type))
		return (NT_STATUS_INVALID_PARAMETER);

	rc = smb_fssize(sr, &fssize);
	if (rc)
		return (smb_errno2status(rc));
	pbps = fssize.fs_bytes_per_sector;
	lbps = fssize.fs_sectors_per_unit * pbps;
	if (lbps > smb2_max_logical_sector_size)
		lbps = smb2_max_logical_sector_size;

	// LogicalBytesPerSector
	(void) smb_mbc_encodef(&sr->raw_data, "l", lbps);

	// PhysicalBytesPerSectorForAtomicity
	(void) smb_mbc_encodef(&sr->raw_data, "l", pbps);

	// PhysicalBytesPerSectorForPerformance
	// Using logical size here.
	(void) smb_mbc_encodef(&sr->raw_data, "l", lbps);

	// FileSystemEffectivePhysicalBytesPerSectorForAtomicity
	(void) smb_mbc_encodef(&sr->raw_data, "l", pbps);

	// Flags
	// We include "no seek penalty" because our files are
	// always ZFS-backed, which can reorder things on disk.
	// Leaving out SSINFO_FLAGS_TRIM_ENABLED for now.
	flags = SSINFO_FLAGS_ALIGNED_DEVICE |
		SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE |
		SSINFO_FLAGS_NO_SEEK_PENALTY;
	(void) smb_mbc_encodef(&sr->raw_data, "l", flags);

	// ByteOffsetForSectorAlignment
	// ByteOffsetForPartitionAlignment
	// Just say "unknown" for these two.
	(void) smb_mbc_encodef(
	    &sr->raw_data, "l",
	    SSINFO_OFFSET_UNKNOWN,
	    SSINFO_OFFSET_UNKNOWN);

	return (0);
}
