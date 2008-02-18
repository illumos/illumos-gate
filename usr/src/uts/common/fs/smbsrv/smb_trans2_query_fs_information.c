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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SMB: trans2_query_fs_information
 *
 * This transaction requests information about a filesystem on the server.
 *
 *  Client Request                     Value
 *  ================================== =================================
 *
 *  WordCount;                         15
 *  TotalParameterCount;               2 or 4
 *  MaxSetupCount;                     0
 *  SetupCount;                        1 or 2
 *  Setup[0];                          TRANS2_QUERY_FS_INFORMATION
 *
 *  Parameter Block Encoding           Description
 *  ================================== =================================
 *
 *  USHORT Information Level;          Level of information requested
 *
 * The  filesystem is identified by Tid in the SMB header.
 *
 * MaxDataCount in the transaction request must be large enough to
 * accommodate the response.
 *
 * The encoding of the response parameter block depends on the
 * InformationLevel requested.  Information levels whose values are greater
 * than 0x102 are mapped to corresponding calls to
 * NtQueryVolumeInformationFile calls by the server.  The two levels below
 * 0x102 are described below.  The requested information is placed in the
 * Data portion of the transaction response.
 *
 *  InformationLevel               Value
 *
 *  =============================  ======
 *
 *  SMB_INFO_ALLOCATION            1
 *  SMB_INFO_VOLUME                2
 *  SMB_QUERY_FS_VOLUME_INFO       0x102
 *  SMB_QUERY_FS_SIZE_INFO         0x103
 *  SMB_QUERY_FS_DEVICE_INFO       0x104
 *  SMB_QUERY_FS_ATTRIBUTE_INFO    0x105
 *
 * The following sections describe the InformationLevel dependent encoding
 * of the data part of the transaction response.
 *
 * 4.1.6.1   SMB_INFO_ALLOCATION
 *
 *  Data Block Encoding Description
 *  =================== ================================================
 *
 *  ULONG idFileSystem; File system identifier.  NT server always
 *                       returns 0
 *  ULONG cSectorUnit;  Number of sectors per allocation unit
 *  ULONG cUnit;        Total number of allocation units
 *  ULONG cUnitAvail;   Total number of available allocation units
 *  USHORT cbSector;    Number of bytes per sector
 *
 * 4.1.6.2   SMB_INFO_VOLUME
 *
 *  Data Block Encoding Description
 *  =================== ================================================
 *
 *  ULONG ulVsn;        Volume serial number
 *  UCHAR cch;          Number of  characters in Label
 *  STRING Label;       The volume label
 *
 * 4.1.6.3   SMB_QUERY_FS_VOLUME_INFO
 *
 *  Data Block Encoding Description
 *  =================== ================================================
 *
 *  LARGE_INTEGER       Volume Creation Time
 *  ULONG               Volume Serial Number
 *  ULONG               Length of Volume Label in bytes
 *
 *  BYTE                Reserved
 *
 *  BYTE                Reserved
 *
 *  STRING Label;       The volume label
 *
 * 4.1.6.4   SMB_QUERY_FS_SIZE_INFO
 *
 *  Data Block Encoding Description
 *  =================== ================================================
 *
 *  LARGE_INTEGER       Total Number of Allocation units on the Volume
 *  LARGE_INTEGER       Number of free Allocation units on the Volume
 *  ULONG               Number of sectors in each Allocation unit
 *
 *  ULONG               Number of bytes in each sector
 *
 * 4.1.6.5   SMB_QUERY_FS_DEVICE_INFO
 *
 *  Data Block Encoding  Value
 *  ==================== ===============================================
 *
 *  ULONG                DeviceType; Values as specified below
 *  ULONG                Characteristics of the device; Values as
 *                        specified below
 *
 * For DeviceType, note that the values 0-32767 are reserved for the
 * exclusive use of Microsoft Corporation. The following device types are
 * currently defined:
 *
 * FILE_DEVICE_BEEP             0x00000001
 *
 * FILE_DEVICE_CD_ROM           0x00000002
 * FILE_DEVICE_CD_ROM_FILE_SYST 0x00000003
 * EM
 * FILE_DEVICE_CONTROLLER       0x00000004
 * FILE_DEVICE_DATALINK         0x00000005
 * FILE_DEVICE_DFS              0x00000006
 * FILE_DEVICE_DISK             0x00000007
 * FILE_DEVICE_DISK_FILE_SYSTEM 0x00000008
 * FILE_DEVICE_FILE_SYSTEM      0x00000009
 * FILE_DEVICE_INPORT_PORT      0x0000000a
 * FILE_DEVICE_KEYBOARD         0x0000000b
 * FILE_DEVICE_MAILSLOT         0x0000000c
 * FILE_DEVICE_MIDI_IN          0x0000000d
 * FILE_DEVICE_MIDI_OUT         0x0000000e
 * FILE_DEVICE_MOUSE            0x0000000f
 * FILE_DEVICE_MULTI_UNC_PROVID 0x00000010
 * ER
 * FILE_DEVICE_NAMED_PIPE       0x00000011
 * FILE_DEVICE_NETWORK          0x00000012
 * FILE_DEVICE_NETWORK_BROWSER  0x00000013
 * FILE_DEVICE_NETWORK_FILE_SYS 0x00000014
 * TEM
 * FILE_DEVICE_NULL             0x00000015
 * FILE_DEVICE_PARALLEL_PORT    0x00000016
 * FILE_DEVICE_PHYSICAL_NETCARD 0x00000017
 * FILE_DEVICE_PRINTER          0x00000018
 * FILE_DEVICE_SCANNER          0x00000019
 * FILE_DEVICE_SERIAL_MOUSE_POR 0x0000001a
 * T
 * FILE_DEVICE_SERIAL_PORT      0x0000001b
 * FILE_DEVICE_SCREEN           0x0000001c
 * FILE_DEVICE_SOUND            0x0000001d
 * FILE_DEVICE_STREAMS          0x0000001e
 * FILE_DEVICE_TAPE             0x0000001f
 * FILE_DEVICE_TAPE_FILE_SYSTEM 0x00000020
 * FILE_DEVICE_TRANSPORT        0x00000021
 * FILE_DEVICE_UNKNOWN          0x00000022
 * FILE_DEVICE_VIDEO            0x00000023
 * FILE_DEVICE_VIRTUAL_DISK     0x00000024
 * FILE_DEVICE_WAVE_IN          0x00000025
 * FILE_DEVICE_WAVE_OUT         0x00000026
 * FILE_DEVICE_8042_PORT        0x00000027
 * FILE_DEVICE_NETWORK_REDIRECT 0x00000028
 * OR
 * FILE_DEVICE_BATTERY          0x00000029
 * FILE_DEVICE_BUS_EXTENDER     0x0000002a
 * FILE_DEVICE_MODEM            0x0000002b
 * FILE_DEVICE_VDM              0x0000002c
 *
 * Some of these device types are not currently accessible over the network
 * and may never be accessible over the network. Some may change to be
 *
 * accessible over the network. The values for device types that may never
 * be accessible over the network may be redefined to be just reserved at
 * some date in the future.
 *
 * Characteristics is the sum of any of the following:
 *
 * FILE_REMOVABLE_MEDIA         0x00000001
 * FILE_READ_ONLY_DEVICE        0x00000002
 * FILE_FLOPPY_DISKETTE         0x00000004
 * FILE_WRITE_ONE_MEDIA         0x00000008
 * FILE_REMOTE_DEVICE           0x00000010
 * FILE_DEVICE_IS_MOUNTED       0x00000020
 * FILE_VIRTUAL_VOLUME          0x00000040
 *
 * 4.1.6.6   SMB_QUERY_FS_ATTRIBUTE_INFO
 *
 *  Data Block Encoding Description
 *  =================== ================================================
 *
 *  ULONG               File System Attributes; possible values
 *                       described below
 *  LONG                Maximum length of each file name component in
 *                       number of bytes
 *  ULONG               Length, in bytes, of the name of the file system
 *
 *  STRING              Name of the file system
 *
 * Where FileSystemAttributes is the sum of any of the following:
 *
 * FILE_CASE_SENSITIVE_SEARCH   0x00000001
 * FILE_CASE_PRESERVED_NAMES    0x00000002
 * FILE_PRSISTENT_ACLS          0x00000004
 * FILE_FILE_COMPRESSION        0x00000008
 * FILE_VOLUME_QUOTAS           0x00000010
 * FILE_DEVICE_IS_MOUNTED       0x00000020
 * FILE_VOLUME_IS_COMPRESSED    0x00008000
 *
 * 4.1.6.7   Errors
 *
 * ERRSRV/invnid  - TID was invalid
 * ERRSRV/baduid  - UID was invalid
 * ERRHRD/ERRnotready  - the file system has been removed
 * ERRHRD/ERRdata - disk I/O error
 * ERRSRV/ERRaccess    - user does not have the right to perform this
 *			 operation
 * ERRSRV/ERRinvdevice - resource identified by TID is not a file system
 */

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smbinfo.h>

char ntfs[] = "NTFS";


/*
 * is_dot_or_dotdot
 *
 * Inline function to detect the "." and ".." entries in a directory.
 * Returns 1 is the name is "." or "..". Otherwise returns 0.
 */
int
is_dot_or_dotdot(char *name)
{
	if (*name != '.')
		return (0);

	if ((name[1] == 0) || (name[1] == '.' && name[2] == 0))
		return (1);

	return (0);
}


/*
 * smb_com_trans2_query_fs_information
 */
smb_sdrc_t
smb_com_trans2_query_fs_information(struct smb_request *sr, struct smb_xa *xa)
{
	int			rc;
	uint32_t		flags;
	char			*encode_str;
	uint64_t		max_int;
	unsigned short		infolev;
	struct statvfs64	df;
	int			sect_per_unit, length;
	uint32_t 		total_units, avail_units;
	struct smb_node 	*snode;
	char 			*fsname = "NTFS";
	fsvol_attr_t		vol_attr;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS, ERRnoaccess);
		return (SDRC_ERROR_REPLY);
	}

	if (smb_decode_mbc(&xa->req_param_mb, "w", &infolev) != 0)
		return (SDRC_ERROR_REPLY);

	snode = sr->tid_tree->t_snode;
	if (fsd_getattr(&sr->tid_tree->t_fsd, &vol_attr) != 0) {
		smbsr_errno(sr, ESTALE);
		return (SDRC_ERROR_REPLY);
	}

	switch (infolev) {
	case SMB_INFO_ALLOCATION:
		if ((rc = smb_fsop_statfs(sr->user_cr, snode, &df)) != 0) {
			smbsr_errno(sr, rc);
			return (SDRC_ERROR_REPLY);
		}

		max_int = (uint64_t)UINT_MAX;

		if (df.f_blocks > max_int)
			df.f_blocks = max_int;

		if (df.f_bavail > max_int)
			df.f_bavail = max_int;

		total_units = (uint32_t)df.f_blocks;
		avail_units = (uint32_t)df.f_bavail;
		length = 512;
		sect_per_unit = df.f_frsize >> 9;

		if (avail_units > total_units)
			avail_units = 0;

		(void) smb_encode_mbc(&xa->rep_data_mb, "llllw",
		    0,			/* file system ID. NT rets 0 */
		    sect_per_unit,	/* sectors/unit */
		    total_units,	/* total units */
		    avail_units,	/* avail units */
		    length);	/* bytes/sector */
		break;

	case SMB_INFO_VOLUME:
		length = strlen(vol_attr.name);
		encode_str = "%lbs";
		/*
		 * tree_fsd.val[0] is the 32-bit dev for the file system
		 * of the share's root smb_node.
		 *
		 * Together with tree_fsd.val[1] (the file system type), it
		 * comprises a system-wide unique file system ID.
		 */

		(void) smb_encode_mbc(&xa->rep_data_mb, encode_str, sr,
		    snode->tree_fsd.val[0], length, vol_attr.name);
		break;

	case SMB_QUERY_FS_VOLUME_INFO:
		if ((sr->smb_flg2 & SMB_FLAGS2_UNICODE) ||
		    (sr->session->native_os == NATIVE_OS_WIN95)) {
			length = mts_wcequiv_strlen(vol_attr.name);
			encode_str = "%qllb.U";
		} else {
			length = strlen(vol_attr.name);	/* label length */
			encode_str = "%qllb.s";
		}

		/*
		 * NT has the "supports objects" flag set to 1.
		 */

		/*
		 * tree_fsd.val[0] is the 32-bit dev for the file system
		 * of the share's root smb_node.
		 *
		 * Together with tree_fsd.val[1] (the file system type), it
		 * comprises a system-wide unique file system ID.
		 */

		(void) smb_encode_mbc(&xa->rep_data_mb, encode_str, sr,
		    0ll,			/* Volume creation time */
		    snode->tree_fsd.val[0],	/* Volume serial number */
		    length,			/* label length */
		    0,				/* Supports objects */
		    vol_attr.name);
		break;

	case SMB_QUERY_FS_SIZE_INFO:
		if ((rc = smb_fsop_statfs(sr->user_cr, snode, &df)) != 0) {
			smbsr_errno(sr, rc);
			return (SDRC_ERROR_REPLY);
		}

		length = 512;
		sect_per_unit = df.f_frsize >> 9;

		if (df.f_bavail > df.f_blocks)
			df.f_bavail = 0;

		(void) smb_encode_mbc(&xa->rep_data_mb, "qqll",
		    df.f_blocks,	/* total units */
		    df.f_bavail,	/* avail units */
		    sect_per_unit,	/* sectors/unit */
		    length);		/* bytes/sector */
		break;
	case SMB_QUERY_FS_DEVICE_INFO:
		(void) smb_encode_mbc(&xa->rep_data_mb, "ll",
		    FILE_DEVICE_FILE_SYSTEM,
		    FILE_DEVICE_IS_MOUNTED);
		break;

	case SMB_QUERY_FS_ATTRIBUTE_INFO:
		if ((sr->smb_flg2 & SMB_FLAGS2_UNICODE) ||
		    (sr->session->native_os == NATIVE_OS_WINNT) ||
		    (sr->session->native_os == NATIVE_OS_WIN2000) ||
		    (sr->session->native_os == NATIVE_OS_WIN95) ||
		    (sr->session->native_os == NATIVE_OS_MACOS)) {
			length = mts_wcequiv_strlen(fsname);
			encode_str = "%lllU";
			sr->smb_flg2 |= SMB_FLAGS2_UNICODE;
		} else {
			length = strlen(fsname);
			encode_str = "%llls";
		}

		flags = FILE_CASE_PRESERVED_NAMES;
		/* flags |= FILE_UNICODE_ON_DISK; */

		if (vol_attr.flags & FSOLF_SUPPORTS_ACLS)
			flags |= FILE_PERSISTENT_ACLS;

		if ((vol_attr.flags & FSOLF_CASE_INSENSITIVE) == 0)
			flags |= FILE_CASE_SENSITIVE_SEARCH;

		if (vol_attr.flags & FSOLF_STREAMS)
			flags |= FILE_NAMED_STREAMS;

		if (smb_info.si.skc_announce_quota)
			flags |= FILE_VOLUME_QUOTAS;

		(void) smb_encode_mbc(&xa->rep_data_mb, encode_str, sr,
		    flags,
		    MAXNAMELEN,			/* max name */
		    length,			/* label length */
		    fsname);
		break;

	default:
		smbsr_error(sr, 0, ERRDOS, ERRunknownlevel);
		return (SDRC_ERROR_REPLY);
	}

	return (SDRC_NORMAL_REPLY);
}
