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

#include <libintl.h>
#include "errcode.h"

char *
errcode_to_str(err_code_t err_code)
{
	switch (err_code) {
	case ERR_SUCCESS:
		return ((char *)gettext("Operation completed successfully"));
	case ERR_NULL_XML_MESSAGE:
		return ((char *)gettext("Null XML message"));
	case ERR_SYNTAX_EMPTY:
		return ((char *)gettext("Syntax error: "
		    "Empty XML message or syntax error"));
	case ERR_SYNTAX_MISSING_ALL:
		return ((char *)gettext("Syntax error: Missing --all"));
	case ERR_SYNTAX_MISSING_BACKING_STORE:
		return ((char *)gettext("Syntax error: Missing backing-store"));
	case ERR_SYNTAX_MISSING_INAME:
		return ((char *)gettext("Syntax error: Missing iscsi name"));
	case ERR_SYNTAX_MISSING_IPADDR:
		return ((char *)gettext("Syntax error: Missing IP address"));
	case ERR_SYNTAX_MISSING_NAME:
		return ((char *)gettext("Syntax error: Missing name"));
	case ERR_SYNTAX_MISSING_OBJECT:
		return ((char *)gettext("Syntax error: Missing object"));
	case ERR_SYNTAX_MISSING_OPERAND:
		return ((char *)gettext("Syntax error: Missing operand"));
	case ERR_SYNTAX_MISSING_SIZE:
		return ((char *)gettext("Syntax error: Missing size"));
	case ERR_SYNTAX_MISSING_TYPE:
		return ((char *)gettext("Syntax error: Missing type"));
	case ERR_SYNTAX_EMPTY_ACL:
		return ((char *)gettext("Syntax error: empty ACL"));
	case ERR_SYNTAX_EMPTY_ALIAS:
		return ((char *)gettext("Syntax error: empty alias"));
	case ERR_SYNTAX_EMPTY_CHAPNAME:
		return ((char *)gettext("Empty chap-name"));
	case ERR_SYNTAX_EMPTY_CHAPSECRET:
		return ((char *)gettext("Empty 'chap-secret' element"));
	case ERR_SYNTAX_EMPTY_IPADDR:
		return ((char *)gettext("Syntax error: empty IP address"));
	case ERR_SYNTAX_EMPTY_MAXRECV:
		return ((char *)gettext("Syntax error: empty maxrecv"));
	case ERR_SYNTAX_EMPTY_TPGT:
		return ((char *)gettext("Syntax error: empty TPGT"));
	case ERR_SYNTAX_INVALID_NAME:
		return ((char *)gettext("Syntax error: name may contain only "
		    "a..z, A..Z, 0-9, dot(.), dash(-), colon(:) characters"));
	case ERR_INVALID_COMMAND:
		return ((char *)gettext("Invalid command"));
	case ERR_INVALID_OBJECT:
		return ((char *)gettext("Invalid object"));
	case ERR_INVALID_BASEDIR:
		return ((char *)gettext("Invalid base directory"));
	case ERR_INVALID_IP:
		return ((char *)gettext("Invalid IP address"));
	case ERR_INVALID_TPGT:
		return ((char *)gettext("Invalid TPGT"));
	case ERR_INVALID_MAXRECV:
		return ((char *)gettext("Invalid MaxRecvDataSegmentLength"));
	case ERR_INVALID_RADSRV:
		return ((char *)gettext("Invalid RADIUS server name"));
	case ERR_INVALID_SIZE:
		return ((char *)gettext("Invalid size parameter"));
	case ERR_INIT_EXISTS:
		return ((char *)gettext("Initiator already exists"));
	case ERR_LUN_EXISTS:
		return ((char *)gettext("LUN already exists"));
	case ERR_LUN_INVALID_RANGE:
		return ((char *)gettext("LUN must be between 0 and 16383"));
	case ERR_TPGT_EXISTS:
		return ((char *)gettext("TPGT already exists"));
	case ERR_ACL_NOT_FOUND:
		return ((char *)gettext("ACL list not found"));
	case ERR_INIT_NOT_FOUND:
		return ((char *)gettext("Initiator not found"));
	case ERR_TARG_NOT_FOUND:
		return ((char *)gettext("Target not found"));
	case ERR_LUN_NOT_FOUND:
		return ((char *)gettext("LUN not found"));
	case ERR_TPGT_NOT_FOUND:
		return ((char *)gettext("TPGT not found"));
	case ERR_ACCESS_RAW_DEVICE_FAILED:
		return ((char *)gettext("Failed to "
		    "access a direct access device"));
	case ERR_CREATE_METADATA_FAILED:
		return ((char *)gettext("Failed to "
		    "create meta data for tape device"));
	case ERR_CREATE_SYMLINK_FAILED:
		return ((char *)gettext("Failed to "
		    "create a symbolic link to the backing store"));
	case ERR_CREATE_NAME_TOO_LONG:
		return ((char *)gettext("Name must be less than 166 "
		    "characters"));
	case ERR_NAME_TOO_LONG:
		return ((char *)gettext("Name too long, must be less than 223 "
		    "characters"));
	case ERR_DISK_BACKING_SIZE_OR_FILE:
		return ((char *)gettext("Size must be 0 if backing store "
		    "exists"));
	case ERR_DISK_BACKING_MUST_BE_REGULAR_FILE:
		return ((char *)gettext("For type "
		    "'disk' backing must be a regular file"));
	case ERR_DISK_BACKING_NOT_VALID_RAW:
		return ((char *)gettext("Backing store is not a valid raw "
		    "device"));
	case ERR_STAT_BACKING_FAILED:
		return ((char *)gettext("Failed to "
		    "stat(2) backing for 'disk'"));
	case ERR_RAW_PART_NOT_CAP:
		return ((char *)gettext("Partition size does not match capacity"
		    " of device. Use p0 or ctd name"));
	case ERR_CREATE_TARGET_DIR_FAILED:
		return ((char *)gettext("Failed to "
		    "create target directory"));
	case ERR_ENCODE_GUID_FAILED:
		return ((char *)gettext("Failed to encode GUID value"));
	case ERR_INIT_XML_READER_FAILED:
		return ((char *)gettext("Failed to initialize XML reader"));
	case ERR_INVALID_XML_REQUEST:
		return ((char *)gettext("Invalid characters in XML request"));
	case ERR_OPEN_PARAM_FILE_FAILED:
		return ((char *)gettext("Failed to open parameter file"));
	case ERR_UPDATE_MAINCFG_FAILED:
		return ((char *)gettext("Failed to "
		    "update main configuration file"));
	case ERR_UPDATE_TARGCFG_FAILED:
		return ((char *)gettext("Failed to "
		    "update target configuration file"));
	case ERR_VALID_TARG_EXIST:
		return ((char *)gettext("Valid targets "
		    "exist under current base directory"));
	case ERR_TARGCFG_MISSING_INAME:
		return ((char *)gettext("Missing "
		    "iscsi name in target configuration"));
	case ERR_NO_MATCH:
		return ((char *)gettext("No match"));
	case ERR_NO_MEM:
		return ((char *)gettext("Internal error: Out of memory"));
	case ERR_LUN_ZERO_NOT_LAST:
		return ((char *)gettext("LUN 0 must be the last one deleted"));
	case ERR_LUN_ZERO_NOT_FIRST:
		return ((char *)gettext("LUN 0 must exist before creating "
		    "other LUNs"));
	case ERR_SIZE_MOD_BLOCK:
		return ((char *)gettext("Size must be multiple of 512"));
	case ERR_CANT_SHRINK_LU:
		return ((char *)gettext("Shrinking of LU is not supported"));
	case ERR_RESIZE_WRONG_TYPE:
		return ((char *)gettext("Backing store must be regular file"));
	case ERR_RESIZE_WRONG_DTYPE:
		return ((char *)gettext("Cannot resize 'raw' targets"));
	case ERR_LUN_NOT_GROWN:
		return ((char *)gettext("Failed to grow LU"));
	case ERR_FILE_TOO_BIG:
		return ((char *)gettext("Requested size is too large for "
		    "system"));
	case ERR_FAILED_TO_CREATE_LU:
		return ((char *)gettext("Failed to create backing store"));
	case ERR_INTERNAL_ERROR:
		return ((char *)gettext("Internal error"));
	case ERR_TAPE_NOT_SUPPORTED_IN_32BIT:
		return ((char *)gettext("Tape emulation not supported in "
		    "32-bit mode"));
	case ERR_BAD_CREDS:
		return ((char *)gettext("No credentials available from door"));
	case ERR_NO_PERMISSION:
		return ((char *)gettext("Permission denied"));
	case ERR_INVALID_ISNS_SRV:
		return ((char *)gettext("Invalid ISNS Server name"));
	case ERR_ISNS_ERROR:
		return ((char *)gettext("ISNS error"));
	case ERR_TPGT_NO_IPADDR:
		return ((char *)gettext("TPGT has no ip-addr"));
	case ERR_TPGT_IN_USE:
		return ((char *)gettext("Specified TPGT is in-use"));
	case ERR_ZFS_ISCSISHARE_OFF:
		return ((char *)gettext("ZFS shareiscsi property is off"));
	default:
		return ((char *)gettext("Internal error: unknown message"));
	}
}
