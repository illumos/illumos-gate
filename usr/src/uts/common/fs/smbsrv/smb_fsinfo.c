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

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smbinfo.h>

static int smb_trans2_set_fs_ctrl_info(smb_request_t *, smb_xa_t *);

/*
 * smb_com_query_information_disk
 *
 * The SMB_COM_QUERY_INFORMATION_DISK command is used to determine the
 * capacity and remaining free space on the drive hosting the directory
 * structure indicated by Tid in the SMB header.
 *
 * The blocking/allocation units used in this response may be independent
 * of the actual physical or logical blocking/allocation algorithm(s) used
 * internally by the server.  However, they must accurately reflect the
 * amount of space on the server.
 *
 * This SMB only returns 16 bits of information for each field, which may
 * not be large enough for some disk systems.  In particular TotalUnits is
 * commonly > 64K.  Fortunately, it turns out the all the client cares
 * about is the total disk size, in bytes, and the free space, in bytes.
 * So,  it is reasonable for a server to adjust the relative values of
 * BlocksPerUnit and BlockSize to accommodate.  If after all adjustment,
 * the numbers are still too high, the largest possible values for
 * TotalUnit or FreeUnits (i.e. 0xFFFF) should be returned.
 */

smb_sdrc_t
smb_pre_query_information_disk(smb_request_t *sr)
{
	DTRACE_SMB_1(op__QueryInformationDisk__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_query_information_disk(smb_request_t *sr)
{
	DTRACE_SMB_1(op__QueryInformationDisk__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_query_information_disk(smb_request_t *sr)
{
	int			rc;
	fsblkcnt64_t		total_blocks, free_blocks;
	unsigned long		block_size, unit_size;
	unsigned short		blocks_per_unit, bytes_per_block;
	unsigned short		total_units, free_units;
	smb_fssize_t		fssize;

	if (STYPE_ISIPC(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS, ERRnoaccess);
		return (SDRC_ERROR);
	}

	if (smb_fssize(sr, &fssize) != 0)
		return (SDRC_ERROR);

	unit_size = fssize.fs_sectors_per_unit;
	block_size = fssize.fs_bytes_per_sector;
	total_blocks = fssize.fs_caller_units;
	free_blocks = fssize.fs_caller_avail;

	/*
	 * It seems that DOS clients cannot handle block sizes
	 * bigger than 512 KB. So we have to set the block size at
	 * most to 512
	 */
	while (block_size > 512) {
		block_size >>= 1;
		unit_size <<= 1;
	}

	/* adjust blocks and sizes until they fit into a word */
	while (total_blocks >= 0xFFFF) {
		total_blocks >>= 1;
		free_blocks >>= 1;
		if ((unit_size <<= 1) > 0xFFFF) {
			unit_size >>= 1;
			total_blocks = 0xFFFF;
			free_blocks <<= 1;
			break;
		}
	}

	total_units = (total_blocks >= 0xFFFF) ?
	    0xFFFF : (unsigned short)total_blocks;
	free_units = (free_blocks >= 0xFFFF) ?
	    0xFFFF : (unsigned short)free_blocks;
	bytes_per_block = (unsigned short)block_size;
	blocks_per_unit = (unsigned short)unit_size;

	rc = smbsr_encode_result(sr, 5, 0, "bwwww2.w",
	    5,
	    total_units,	/* total_units */
	    blocks_per_unit,	/* blocks_per_unit */
	    bytes_per_block,	/* blocksize */
	    free_units,		/* free_units */
	    0);			/* bcc */

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * smb_com_trans2_query_fs_information
 *
 * This transaction requests information about the filesystem.
 * The following information levels are supported:
 *
 *  InformationLevel               	Value
 *  ==================================  ======
 *  SMB_INFO_ALLOCATION            	1
 *  SMB_INFO_VOLUME                	2
 *  SMB_QUERY_FS_VOLUME_INFO       	0x102
 *  SMB_QUERY_FS_SIZE_INFO         	0x103
 *  SMB_QUERY_FS_DEVICE_INFO       	0x104
 *  SMB_QUERY_FS_ATTRIBUTE_INFO    	0x105
 *  SMB_FILE_FS_VOLUME_INFORMATION	1001
 *  SMB_FILE_FS_SIZE_INFORMATION	1003
 *  SMB_FILE_FS_DEVICE_INFORMATION	1004
 *  SMB_FILE_FS_ATTRIBUTE_INFORMATION	1005
 *  SMB_FILE_FS_CONTROL_INFORMATION	1006
 *  SMB_FILE_FS_FULLSIZE_INFORMATION	1007
 *
 * The fsid provides a system-wide unique file system ID.
 * fsid.val[0] is the 32-bit dev for the file system of the share root
 * smb_node.
 * fsid.val[1] is the file system type.
 */
smb_sdrc_t
smb_com_trans2_query_fs_information(smb_request_t *sr, smb_xa_t *xa)
{
	uint32_t		flags;
	char			*encode_str, *tmpbuf;
	uint64_t		max_int;
	uint16_t		infolev;
	int			rc, length, buflen;
	smb_tree_t		*tree;
	smb_node_t		*snode;
	char 			*fsname = "NTFS";
	fsid_t			fsid;
	smb_fssize_t		fssize;
	smb_msgbuf_t		mb;

	tree = sr->tid_tree;

	if (!STYPE_ISDSK(tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	if (smb_mbc_decodef(&xa->req_param_mb, "w", &infolev) != 0)
		return (SDRC_ERROR);

	snode = tree->t_snode;
	fsid = SMB_NODE_FSID(snode);

	switch (infolev) {
	case SMB_INFO_ALLOCATION:
		if (smb_fssize(sr, &fssize) != 0)
			return (SDRC_ERROR);

		max_int = (uint64_t)UINT_MAX;
		if (fssize.fs_caller_units > max_int)
			fssize.fs_caller_units = max_int;
		if (fssize.fs_caller_avail > max_int)
			fssize.fs_caller_avail = max_int;

		(void) smb_mbc_encodef(&xa->rep_data_mb, "llllw",
		    0,
		    fssize.fs_sectors_per_unit,
		    fssize.fs_caller_units,
		    fssize.fs_caller_avail,
		    fssize.fs_bytes_per_sector);
		break;

	case SMB_INFO_VOLUME:
		/*
		 * In this response, the unicode volume label is NOT
		 * expected to be aligned. Encode ('U') into a temporary
		 * buffer, then encode buffer as a byte stream ('#c').
		 */
		if ((sr->smb_flg2 & SMB_FLAGS2_UNICODE) ||
		    (sr->session->native_os == NATIVE_OS_WIN95)) {
			length = smb_wcequiv_strlen(tree->t_volume);
			buflen = length + sizeof (smb_wchar_t);
			tmpbuf = smb_srm_zalloc(sr, buflen);
			smb_msgbuf_init(&mb, (uint8_t *)tmpbuf, buflen,
			    SMB_MSGBUF_UNICODE);
			rc = smb_msgbuf_encode(&mb, "U", tree->t_volume);
			if (rc >= 0) {
				rc = smb_mbc_encodef(&xa->rep_data_mb,
				    "%lb#c", sr, fsid.val[0],
				    length, length, tmpbuf);
			}
			smb_msgbuf_term(&mb);
		} else {
			length = strlen(tree->t_volume);
			rc = smb_mbc_encodef(&xa->rep_data_mb, "%lbs", sr,
			    fsid.val[0], length, tree->t_volume);
		}

		if (rc < 0)
			return (SDRC_ERROR);
		break;

	case SMB_QUERY_FS_VOLUME_INFO:
	case SMB_FILE_FS_VOLUME_INFORMATION:
		if ((sr->smb_flg2 & SMB_FLAGS2_UNICODE) ||
		    (sr->session->native_os == NATIVE_OS_WIN95)) {
			length = smb_wcequiv_strlen(tree->t_volume);
			encode_str = "%qllb.U";
		} else {
			length = strlen(tree->t_volume);
			encode_str = "%qllb.s";
		}

		/*
		 * NT has the "supports objects" flag set to 1.
		 */
		(void) smb_mbc_encodef(&xa->rep_data_mb, encode_str, sr,
		    0ll,			/* Volume creation time */
		    fsid.val[0],		/* Volume serial number */
		    length,			/* label length */
		    0,				/* Supports objects */
		    tree->t_volume);
		break;

	case SMB_QUERY_FS_SIZE_INFO:
	case SMB_FILE_FS_SIZE_INFORMATION:
		if (smb_fssize(sr, &fssize) != 0)
			return (SDRC_ERROR);

		(void) smb_mbc_encodef(&xa->rep_data_mb, "qqll",
		    fssize.fs_caller_units,
		    fssize.fs_caller_avail,
		    fssize.fs_sectors_per_unit,
		    fssize.fs_bytes_per_sector);
		break;

	case SMB_QUERY_FS_DEVICE_INFO:
	case SMB_FILE_FS_DEVICE_INFORMATION:
		(void) smb_mbc_encodef(&xa->rep_data_mb, "ll",
		    FILE_DEVICE_FILE_SYSTEM,
		    FILE_DEVICE_IS_MOUNTED);
		break;

	case SMB_QUERY_FS_ATTRIBUTE_INFO:
	case SMB_FILE_FS_ATTRIBUTE_INFORMATION:
		if ((sr->smb_flg2 & SMB_FLAGS2_UNICODE) ||
		    (sr->session->native_os == NATIVE_OS_WINNT) ||
		    (sr->session->native_os == NATIVE_OS_WIN2000) ||
		    (sr->session->native_os == NATIVE_OS_WIN95) ||
		    (sr->session->native_os == NATIVE_OS_MACOS)) {
			length = smb_wcequiv_strlen(fsname);
			encode_str = "%lllU";
			sr->smb_flg2 |= SMB_FLAGS2_UNICODE;
		} else {
			length = strlen(fsname);
			encode_str = "%llls";
		}

		flags = FILE_CASE_PRESERVED_NAMES;

		if (tree->t_flags & SMB_TREE_UNICODE_ON_DISK)
			flags |= FILE_UNICODE_ON_DISK;

		if (tree->t_flags & SMB_TREE_SUPPORTS_ACLS)
			flags |= FILE_PERSISTENT_ACLS;

		if ((tree->t_flags & SMB_TREE_CASEINSENSITIVE) == 0)
			flags |= FILE_CASE_SENSITIVE_SEARCH;

		if (tree->t_flags & SMB_TREE_STREAMS)
			flags |= FILE_NAMED_STREAMS;

		if (tree->t_flags & SMB_TREE_QUOTA)
			flags |= FILE_VOLUME_QUOTAS;

		if (tree->t_flags & SMB_TREE_SPARSE)
			flags |= FILE_SUPPORTS_SPARSE_FILES;

		(void) smb_mbc_encodef(&xa->rep_data_mb, encode_str, sr,
		    flags,
		    MAXNAMELEN,	/* max name */
		    length,	/* label length */
		    fsname);
		break;

	case SMB_FILE_FS_CONTROL_INFORMATION:
		if (!smb_tree_has_feature(sr->tid_tree, SMB_TREE_QUOTA)) {
			smbsr_error(sr, NT_STATUS_NOT_SUPPORTED,
			    ERRDOS, ERROR_NOT_SUPPORTED);
			return (SDRC_ERROR);
		}

		(void) smb_mbc_encodef(&xa->rep_data_mb, "qqqqqll",
		    0,		/* free space start filtering - MUST be 0 */
		    0,		/* free space threshold - MUST be 0 */
		    0,		/* free space stop filtering - MUST be 0 */
		    SMB_QUOTA_UNLIMITED,	/* default quota threshold */
		    SMB_QUOTA_UNLIMITED,	/* default quota limit */
		    FILE_VC_QUOTA_ENFORCE,	/* fs control flag */
		    0);				/* pad bytes */
		break;

	case SMB_FILE_FS_FULLSIZE_INFORMATION:
		if (smb_fssize(sr, &fssize) != 0)
			return (SDRC_ERROR);

		(void) smb_mbc_encodef(&xa->rep_data_mb, "qqqll",
		    fssize.fs_caller_units,
		    fssize.fs_caller_avail,
		    fssize.fs_volume_avail,
		    fssize.fs_sectors_per_unit,
		    fssize.fs_bytes_per_sector);
		break;

	case SMB_FILE_FS_LABEL_INFORMATION:
	case SMB_FILE_FS_OBJECTID_INFORMATION:
	case SMB_FILE_FS_DRIVERPATH_INFORMATION:
		smbsr_error(sr, NT_STATUS_NOT_SUPPORTED,
		    ERRDOS, ERROR_NOT_SUPPORTED);
		return (SDRC_ERROR);

	default:
		smbsr_error(sr, NT_STATUS_INVALID_LEVEL,
		    ERRDOS, ERROR_INVALID_LEVEL);
		return (SDRC_ERROR);
	}

	return (SDRC_SUCCESS);
}

/*
 * smb_fssize
 *
 * File system size information, for the volume and for the user
 * initiating the request.
 *
 * If there's no quota entry for the user initiating the request,
 * caller_units and caller_avail are the total and available units
 * for the volume (volume_units, volume_avail).
 * If there is a quota entry for the user initiating the request,
 * and it is not SMB_QUOTA_UNLIMITED, calculate caller_units and
 * caller_avail as follows:
 *   caller_units = quota limit / bytes_per_unit
 *   caller_avail = remaining quota / bytes_per_unit
 *
 * A quota limit of SMB_QUOTA_UNLIMITED means that the user's quota
 * is specfied as unlimited. A quota limit of 0 means there is no
 * quota specified for the user.
 *
 * Returns: 0 (success) or an errno value
 */
int
smb_fssize(smb_request_t *sr, smb_fssize_t *fssize)
{
	smb_node_t *node;
	struct statvfs64 df;
	uid_t uid;
	smb_quota_t quota;
	int spu;	/* sectors per unit */
	int rc;

	bzero(fssize, sizeof (smb_fssize_t));
	node = sr->tid_tree->t_snode;
	if ((rc = smb_fsop_statfs(sr->user_cr, node, &df)) != 0)
		return (rc);

	if (df.f_frsize < DEV_BSIZE)
		df.f_frsize = DEV_BSIZE;
	if (df.f_bsize < df.f_frsize)
		df.f_bsize = df.f_frsize;
	spu = df.f_bsize / df.f_frsize;

	fssize->fs_bytes_per_sector = (uint16_t)df.f_frsize;
	fssize->fs_sectors_per_unit = spu;

	if (df.f_bavail > df.f_blocks)
		df.f_bavail = 0;

	fssize->fs_volume_units = df.f_blocks / spu;
	fssize->fs_volume_avail = df.f_bavail / spu;
	fssize->fs_caller_units = df.f_blocks / spu;
	fssize->fs_caller_avail = df.f_bavail / spu;

	if (!smb_tree_has_feature(sr->tid_tree, SMB_TREE_QUOTA))
		return (0);

	uid = crgetuid(sr->uid_user->u_cred);
	if (smb_quota_query_user_quota(sr, uid, &quota) != NT_STATUS_SUCCESS)
		return (0);

	if ((quota.q_limit != SMB_QUOTA_UNLIMITED) && (quota.q_limit != 0)) {
		fssize->fs_caller_units = quota.q_limit / df.f_bsize;
		if (quota.q_limit <= quota.q_used)
			fssize->fs_caller_avail = 0;
		else
			fssize->fs_caller_avail =
			    (quota.q_limit - quota.q_used) / df.f_bsize;
	}

	return (0);
}

/*
 * smb_com_trans2_set_fs_information
 *
 * This transaction sets filesystem information.
 * The following information levels are supported:
 *
 *  InformationLevel               	Value
 *  ==================================  ======
 *  SMB_FILE_FS_CONTROL_INFORMATION	1006
 */
smb_sdrc_t
smb_com_trans2_set_fs_information(smb_request_t *sr, smb_xa_t *xa)
{
	smb_tree_t		*tree;
	uint16_t		infolev;

	tree = sr->tid_tree;
	if (!STYPE_ISDSK(tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	if (smb_mbc_decodef(&xa->req_param_mb, "ww",
	    &sr->smb_fid, &infolev) != 0)
		return (SDRC_ERROR);

	switch (infolev) {
	case SMB_FILE_FS_CONTROL_INFORMATION:
		if (smb_trans2_set_fs_ctrl_info(sr, xa) != 0)
			return (SDRC_ERROR);
		break;

	case SMB_FILE_FS_VOLUME_INFORMATION:
	case SMB_FILE_FS_LABEL_INFORMATION:
	case SMB_FILE_FS_SIZE_INFORMATION:
	case SMB_FILE_FS_DEVICE_INFORMATION:
	case SMB_FILE_FS_ATTRIBUTE_INFORMATION:
	case SMB_FILE_FS_FULLSIZE_INFORMATION:
	case SMB_FILE_FS_OBJECTID_INFORMATION:
	case SMB_FILE_FS_DRIVERPATH_INFORMATION:
		smbsr_error(sr, NT_STATUS_NOT_SUPPORTED,
		    ERRDOS, ERROR_NOT_SUPPORTED);
		return (SDRC_ERROR);

	default:
		smbsr_error(sr, NT_STATUS_INVALID_LEVEL,
		    ERRDOS, ERROR_INVALID_LEVEL);
		return (SDRC_ERROR);
	}

	return (SDRC_SUCCESS);
}

/*
 * smb_trans2_set_fs_ctrl_info
 *
 * Only users with Admin privileges (i.e. of the BUILTIN/Administrators
 * group) will be allowed to set quotas.
 *
 * Currently QUOTAS are always ENFORCED and the default values
 * are always SMB_QUOTA_UNLIMITED (none). Any attempt to set
 * values other than these will result in NT_STATUS_NOT_SUPPORTED.
 */
static int
smb_trans2_set_fs_ctrl_info(smb_request_t *sr, smb_xa_t *xa)
{
	int rc;
	uint64_t fstart, fthresh, fstop, qthresh, qlimit;
	uint32_t qctrl, qpad;

	if (!smb_tree_has_feature(sr->tid_tree, SMB_TREE_QUOTA)) {
		smbsr_error(sr, NT_STATUS_NOT_SUPPORTED,
		    ERRDOS, ERROR_NOT_SUPPORTED);
		return (-1);
	}

	if (!smb_user_is_admin(sr->uid_user)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (-1);
	}

	rc = smb_mbc_decodef(&xa->req_data_mb, "qqqqqll", &fstart,
	    &fthresh, &fstop, &qthresh, &qlimit, &qctrl, &qpad);

	if ((rc != 0) || (fstart != 0) || (fthresh != 0) || (fstop != 0)) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERROR_INVALID_PARAMETER);
		return (-1);
	}

	/* Only support ENFORCED quotas with UNLIMITED default */
	if ((qctrl != FILE_VC_QUOTA_ENFORCE) ||
	    (qlimit != SMB_QUOTA_UNLIMITED) ||
	    (qthresh != SMB_QUOTA_UNLIMITED)) {
		smbsr_error(sr, NT_STATUS_NOT_SUPPORTED,
		    ERRDOS, ERROR_NOT_SUPPORTED);
		return (-1);
	}

	return (0);
}
