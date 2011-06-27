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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_STMF_SBD_IOCTL_H
#define	_STMF_SBD_IOCTL_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * error codes from sbd.
 */
typedef enum sbd_ret {
	SBD_RET_META_CREATION_FAILED = 0x01,
	SBD_RET_INVALID_BLKSIZE,
	SBD_RET_REQUIRES_SEPARATE_META,
	SBD_RET_FILE_ALREADY_REGISTERED,
	SBD_RET_GUID_ALREADY_REGISTERED,
	SBD_RET_DATA_PATH_NOT_ABSOLUTE,
	SBD_RET_META_PATH_NOT_ABSOLUTE,
	SBD_RET_META_FILE_LOOKUP_FAILED,
	SBD_RET_ZFS_META_CREATE_FAILED,
	SBD_ZVOL_META_NAME_MISMATCH,
	SBD_RET_DATA_FILE_LOOKUP_FAILED,
	SBD_RET_WRONG_META_FILE_TYPE,
	SBD_RET_WRONG_DATA_FILE_TYPE,
	SBD_RET_DATA_FILE_OPEN_FAILED,
	SBD_RET_META_FILE_OPEN_FAILED,
	SBD_RET_DATA_FILE_GETATTR_FAILED,
	SBD_RET_META_FILE_GETATTR_FAILED,
	SBD_RET_FILE_SIZE_ERROR,
	SBD_RET_FILE_ALIGN_ERROR,
	SBD_RET_SIZE_OUT_OF_RANGE,
	SBD_RET_SIZE_NOT_SUPPORTED_BY_FS,
	SBD_RET_NO_META,
	SBD_RET_VERSION_NOT_SUPPORTED,
	SBD_RET_LU_BUSY,
	SBD_RET_NOT_FOUND,
	SBD_RET_INSUFFICIENT_BUF_SPACE,
	SBD_RET_WRITE_CACHE_SET_FAILED,
	SBD_RET_ACCESS_STATE_FAILED,

	SBD_RET_MAX_VAL
} sbd_ret_t;

#define	SBD_IOCTL_DEF(n)	((((int)0x5B) << 16) | (n))
#define	SBD_IOCTL_CREATE_AND_REGISTER_LU		SBD_IOCTL_DEF(1)
#define	SBD_IOCTL_IMPORT_LU				SBD_IOCTL_DEF(2)
#define	SBD_IOCTL_DELETE_LU				SBD_IOCTL_DEF(3)
#define	SBD_IOCTL_MODIFY_LU				SBD_IOCTL_DEF(4)
#define	SBD_IOCTL_GET_LU_PROPS				SBD_IOCTL_DEF(5)
#define	SBD_IOCTL_GET_LU_LIST				SBD_IOCTL_DEF(6)
#define	SBD_IOCTL_SET_LU_STANDBY			SBD_IOCTL_DEF(7)
#define	SBD_IOCTL_SET_GLOBAL_LU				SBD_IOCTL_DEF(8)
#define	SBD_IOCTL_GET_GLOBAL_LU				SBD_IOCTL_DEF(9)
#define	SBD_IOCTL_GET_UNMAP_PROPS			SBD_IOCTL_DEF(10)

typedef struct sbd_create_and_reg_lu {
	uint32_t	slu_struct_size;
	uint16_t	slu_meta_fname_valid:1,
			slu_lu_size_valid:1,
			slu_blksize_valid:1,
			slu_vid_valid:1,
			slu_pid_valid:1,
			slu_rev_valid:1,
			slu_serial_valid:1,
			slu_alias_valid:1,
			slu_mgmt_url_valid:1,
			slu_guid_valid:1,
			slu_company_id_valid:1,
			slu_host_id_valid:1,
			slu_writeback_cache_disable_valid:1,
			slu_writeback_cache_disable:1,
			slu_write_protected:1;
	uint16_t	slu_meta_fname_off;
	uint64_t	slu_lu_size;
	uint16_t	slu_data_fname_off;
	uint16_t	slu_serial_off;
	uint8_t		slu_serial_size;
	uint8_t		slu_ret_filesize_nbits;
	uint16_t	slu_blksize;
	uint32_t	slu_company_id;
	uint16_t	slu_alias_off;
	uint16_t	slu_mgmt_url_off;
	uint32_t	slu_host_id;
	char		slu_rev[4];
	char		slu_vid[8];
	char		slu_pid[16];
	uint8_t		slu_guid[16];
	char		slu_buf[8];	/* likely more than 8 */
} sbd_create_and_reg_lu_t;

typedef struct sbd_global_props {
	uint32_t	mlu_struct_size;
	uint32_t	mlu_vid_valid:1,
			mlu_pid_valid:1,
			mlu_rev_valid:1,
			mlu_serial_valid:1,
			mlu_mgmt_url_valid:1,
			mlu_company_id_valid:1,
			mlu_host_id_valid:1;
	uint16_t	mlu_serial_off;
	uint8_t		mlu_serial_size;
	uint8_t		mlu_rsvd1;
	uint32_t	mlu_company_id;
	uint16_t	mlu_mgmt_url_off;
	uint16_t	rsvd1;
	uint32_t	mlu_host_id;
	uint32_t	mlu_buf_size_needed;
	char		mlu_rev[4];
	char		mlu_vid[8];
	char		mlu_pid[16];
	char		mlu_buf[8];	/* likely more than 8 */
} sbd_global_props_t;

typedef struct sbd_set_lu_standby {
	uint8_t		stlu_guid[16];
} sbd_set_lu_standby_t;


typedef struct sbd_import_lu {
	uint32_t	ilu_struct_size;
	uint32_t	ilu_rsvd;
	uint8_t		ilu_ret_guid[16];
	char		ilu_meta_fname[8]; /* Can be more than 8 */
} sbd_import_lu_t;

typedef struct sbd_modify_lu {
	uint32_t	mlu_struct_size;
	uint32_t	mlu_lu_size_valid:1,
			mlu_serial_valid:1,
			mlu_alias_valid:1,
			mlu_mgmt_url_valid:1,
			mlu_writeback_cache_disable_valid:1,
			mlu_writeback_cache_disable:1,
			mlu_write_protected_valid:1,
			mlu_write_protected:1,
			mlu_by_guid:1,
			mlu_by_fname:1,
			mlu_standby_valid:1,
			mlu_standby:1;
	uint64_t	mlu_lu_size;
	uint16_t	mlu_alias_off;
	uint16_t	mlu_mgmt_url_off;
	uint16_t	mlu_serial_off;
	uint16_t	mlu_serial_size;
	uint16_t	mlu_fname_off;
	uint16_t	mlu_rsvd1;
	uint32_t	mlu_rsvd2;
	uint8_t		mlu_input_guid[16];
	char		mlu_buf[8]; /* can be more than 8 */
} sbd_modify_lu_t;

typedef struct sbd_delete_lu {
	uint32_t	dlu_struct_size;
	uint16_t	dlu_by_guid:1,
			dlu_by_meta_name:1;
	uint16_t	dlu_rsvd;
	uint8_t		dlu_guid[16];
	uint8_t		dlu_meta_name[8];
} sbd_delete_lu_t;

/*
 * sbd access states
 */
#define	SBD_LU_ACTIVE			1
#define	SBD_LU_TRANSITION_TO_ACTIVE	2
#define	SBD_LU_STANDBY			3
#define	SBD_LU_TRANSITION_TO_STANDBY	4

typedef struct sbd_lu_props {
	uint32_t	slp_input_guid:1,	/* GUID or meta filename */
			slp_separate_meta:1,
			slp_meta_fname_valid:1,
			slp_data_fname_valid:1,
			slp_zfs_meta:1,
			slp_alias_valid:1,
			slp_mgmt_url_valid:1,
			slp_lu_vid:1,
			slp_lu_pid:1,
			slp_lu_rev:1,
			slp_serial_valid:1,
			slp_writeback_cache_disable_cur:1,
			slp_writeback_cache_disable_saved:1,
			slp_write_protected:1;
	uint16_t	slp_meta_fname_off;
	uint16_t	slp_data_fname_off;
	uint64_t	slp_lu_size;
	uint16_t	slp_serial_off;
	uint16_t	slp_blksize;
	uint16_t	slp_alias_off;
	uint16_t	slp_mgmt_url_off;
	uint32_t	slp_buf_size_needed;	/* Upon return */
	uint16_t	slp_serial_size;
	uint16_t	slp_access_state;
	char		slp_rev[4];
	char		slp_vid[8];
	char		slp_pid[16];
	uint8_t		slp_guid[16];
	uint8_t		slp_buf[8];	/* likely more than 8 */
} sbd_lu_props_t;

typedef struct sbd_unmap_props {
	uint32_t	sup_found_lu:1,
			sup_zvol_path_valid:1,
			sup_guid_valid:1,
			sup_unmap_enabled;
	uint32_t	sup_rsvd;
	char		sup_zvol_path[256];
	uint8_t		sup_guid[16];
} sbd_unmap_props_t;

#ifdef	__cplusplus
}
#endif

#endif /* _STMF_SBD_IOCTL_H */
