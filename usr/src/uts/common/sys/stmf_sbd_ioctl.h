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

#ifndef	_STMF_SBD_IOCTL_H
#define	_STMF_SBD_IOCTL_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	MEMDISK_MIN_SIZE	(1024 * 1024)
#define	MEMDISK_MAX_SIZE	(1024 * 1024 * 1024)

/*
 * ioctl cmds
 */
#define	SBD_IOCTL_CMD		(((uint32_t)'S') << 24)

#define	SBD_REGISTER_LU		(SBD_IOCTL_CMD | 0x01)
#define	SBD_GET_LU_ATTR		(SBD_IOCTL_CMD | 0x02)
#define	SBD_GET_LU_LIST		(SBD_IOCTL_CMD | 0x03)
#define	SBD_DEREGISTER_LU	(SBD_IOCTL_CMD | 0x04)
#define	SBD_MODIFY_LU		(SBD_IOCTL_CMD | 0x05)

typedef enum rlc_flags {
	RLC_LU_TYPE_MEMDISK = 0x01,
	RLC_LU_TYPE_FILEDISK = 0x02,
	RLC_CREATE_LU = 0x04,		/* Initialize metadata */
	RLC_REGISTER_LU = 0x10,
	RLC_DEREGISTER_LU = 0x20,
	RLC_FORCE_OP = 0x40
} rlc_flags_t;

typedef enum rlc_ret {
	RLC_RET_META_CREATION_FAILED = 0x01,
	RLC_RET_LU_NOT_INITIALIZED,
	RLC_RET_FILE_ALREADY_REGISTERED,
	RLC_RET_GUID_ALREADY_REGISTERED,
	RLC_RET_REGISTER_SST_FAILED,
	RLC_RET_DEREGISTER_SST_FAILED,
	RLC_RET_FILE_LOOKUP_FAILED,
	RLC_RET_WRONG_FILE_TYPE,
	RLC_RET_FILE_OPEN_FAILED,
	RLC_RET_FILE_GETATTR_FAILED,
	RLC_RET_FILE_SIZE_ERROR,
	RLC_RET_FILE_ALIGN_ERROR,
	RLC_RET_SIZE_OUT_OF_RANGE,
	RLC_RET_SIZE_NOT_SUPPORTED_BY_FS,

	RLC_RET_MAX_VAL
} rlc_ret_t;

typedef struct register_lu_cmd {
	uint32_t	total_struct_size;
	rlc_flags_t	flags;
	uint64_t	lu_size;	/* For memdisk only */
	rlc_ret_t	return_code;
	uint32_t	filesize_nbits;
	stmf_status_t	op_ret;
	uint64_t	lu_handle;
	uint8_t		guid[16];	/* For reporting back duplicate GUID */
	char		name[8];
} register_lu_cmd_t;

typedef struct deregister_lu_cmd {
	uint32_t	total_struct_size;
	rlc_flags_t	flags;
	rlc_ret_t	return_code;
	uint32_t	rsvd;
	uint8_t		guid[16];
} deregister_lu_cmd_t;

typedef struct modify_lu_cmd {
	uint32_t	total_struct_size;
	rlc_flags_t	flags;
	uint64_t	lu_size;
	rlc_ret_t	return_code;
	uint32_t	filesize_nbits;
	stmf_status_t	op_ret;
	uint8_t		guid[16];
	char		name[8];
} modify_lu_cmd_t;

typedef struct sbd_lu_attr {
	uint32_t	total_struct_size;
	rlc_flags_t	flags;	/* to find out the type */
	int		max_name_length;
	uint32_t	rsvd;
	uint64_t	lu_handle;
	uint64_t	total_size;
	uint64_t	data_size;
	uint8_t		guid[16];
	char		name[8];
} sbd_lu_attr_t;

typedef struct sbd_lu_list {
	uint32_t	total_struct_size;
	uint32_t	count_in;
	uint32_t	count_out;
	uint32_t	rsvd;
	uint64_t	handles[1];
} sbd_lu_list_t;

#ifdef	__cplusplus
}
#endif

#endif /* _STMF_SBD_IOCTL_H */
