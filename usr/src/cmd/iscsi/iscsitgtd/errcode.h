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

#ifndef _TARGET_ERRCODE_H
#define	_TARGET_ERRCODE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Block comment which describes the contents of this file.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	ERR_SUCCESS = 1000,
	ERR_NULL_XML_MESSAGE,
	ERR_SYNTAX_EMPTY,
	ERR_SYNTAX_MISSING_ALL,
	ERR_SYNTAX_MISSING_BACKING_STORE,
	ERR_SYNTAX_MISSING_INAME,
	ERR_SYNTAX_MISSING_IPADDR,
	ERR_SYNTAX_MISSING_NAME,
	ERR_SYNTAX_MISSING_OBJECT,
	ERR_SYNTAX_MISSING_OPERAND,
	ERR_SYNTAX_MISSING_SIZE,
	ERR_SYNTAX_MISSING_TYPE,
	ERR_SYNTAX_EMPTY_ACL,
	ERR_SYNTAX_EMPTY_ALIAS,
	ERR_SYNTAX_EMPTY_CHAPNAME,
	ERR_SYNTAX_EMPTY_CHAPSECRET,
	ERR_SYNTAX_EMPTY_IPADDR,
	ERR_SYNTAX_EMPTY_MAXRECV,
	ERR_SYNTAX_EMPTY_TPGT,
	ERR_SYNTAX_INVALID_NAME,
	ERR_INVALID_COMMAND,
	ERR_INVALID_OBJECT,
	ERR_INVALID_IP,
	ERR_INVALID_BASEDIR,
	ERR_INVALID_TPGT,
	ERR_INVALID_MAXRECV,
	ERR_INVALID_RADSRV,
	ERR_INVALID_SIZE,
	ERR_INIT_EXISTS,
	ERR_NAME_TOO_LONG,
	ERR_LUN_EXISTS,
	ERR_TPGT_EXISTS,
	ERR_ACL_NOT_FOUND,
	ERR_INIT_NOT_FOUND,
	ERR_TARG_NOT_FOUND,
	ERR_LUN_NOT_FOUND,
	ERR_LUN_INVALID_RANGE,
	ERR_TPGT_NOT_FOUND,
	ERR_ACCESS_RAW_DEVICE_FAILED,
	ERR_CREATE_METADATA_FAILED,
	ERR_CREATE_SYMLINK_FAILED,
	ERR_CREATE_NAME_TOO_LONG,
	ERR_DISK_BACKING_MUST_BE_REGULAR_FILE,
	ERR_DISK_BACKING_NOT_VALID_RAW,
	ERR_DISK_BACKING_SIZE_OR_FILE,
	ERR_STAT_BACKING_FAILED,
	ERR_RAW_PART_NOT_CAP,
	ERR_CREATE_TARGET_DIR_FAILED,
	ERR_ENCODE_GUID_FAILED,
	ERR_INIT_XML_READER_FAILED,
	ERR_INVALID_XML_REQUEST,
	ERR_OPEN_PARAM_FILE_FAILED,
	ERR_UPDATE_MAINCFG_FAILED,
	ERR_UPDATE_TARGCFG_FAILED,
	ERR_VALID_TARG_EXIST,
	ERR_TARGCFG_MISSING_INAME,
	ERR_NO_MATCH,
	ERR_NO_MEM,
	ERR_LUN_ZERO_NOT_LAST,
	ERR_LUN_ZERO_NOT_FIRST,
	ERR_SIZE_MOD_BLOCK,
	ERR_CANT_SHRINK_LU,
	ERR_RESIZE_WRONG_TYPE,
	ERR_RESIZE_WRONG_DTYPE,
	ERR_LUN_NOT_GROWN,
	ERR_FILE_TOO_BIG,
	ERR_FAILED_TO_CREATE_LU,
	ERR_TAPE_NOT_SUPPORTED_IN_32BIT,
	ERR_INTERNAL_ERROR,
	ERR_BAD_CREDS,
	ERR_NO_PERMISSION,
	ERR_INVALID_ISNS_SRV,
	ERR_ISNS_ERROR,
	ERR_TPGT_NO_IPADDR,
	ERR_TPGT_IN_USE,
	ERR_ZFS_ISCSISHARE_OFF
} err_code_t;

char *
errcode_to_str(err_code_t err_code);

#ifdef __cplusplus
}
#endif

#endif /* _TARGET_ERRCODE_H */
