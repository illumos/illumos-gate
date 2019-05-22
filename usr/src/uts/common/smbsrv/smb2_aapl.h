/*
 * Copyright (c) 2011 - 2012 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * This content was published as: smb-759.0/kernel/netsmb/smb_2.h
 * in http://opensource.apple.com/source/smb/smb-759.0.tar.gz
 */

#ifndef	_SMB2AAPL_H
#define	_SMB2AAPL_H

#include <sys/types.h>

/*
 * Apple SMB 2/3 "AAPL" Create Context extensions
 */

/* Define "AAPL" Context Command Codes */
enum {
	kAAPL_SERVER_QUERY = 1,
	kAAPL_RESOLVE_ID = 2
};

/*
 * Server Query Request
 *
 *	uint32_t command_code = kAAPL_SERVER_QUERY;
 *	uint32_t reserved = 0;
 *	uint64_t request_bitmap;
 *	uint64_t client_capabilities;
 *
 * Server Query Response
 *
 *	uint32_t command_code = kAAPL_SERVER_QUERY;
 *	uint32_t reserved = 0;
 *	uint64_t reply_bitmap;
 *	<reply specific data>
 *
 *	The reply data is packed in the response block in the order specified
 *	by the reply_bitmap.
 *
 * Server Query request/reply bitmap
 *  Bit 0 - kAAPL_SERVER_CAPS returns uint64_t bitmap of server capabilities
 *  Bit 1 - kAAPL_VOLUME_CAPS returns uint64_t bitmap of volume capabilities
 *  Bit 2 - kAAPL_MODEL_INFO returns uint32_t Pad2 followed by uint32_t length
 *	followed by the Unicode model string. The Unicode string is padded with
 *	zeros to end on an 8 byte boundary.
 *
 * Example Server Query Context Response Buffer:
 *	uint32_t Next = 0;
 *	uint16_t NameOffset = 16;
 *	uint16_t NameLength = 4;
 *	uint16_t Reserved = 0;
 *	uint16_t DataOffset = 24;
 *	uint32_t DataLength = variable based on ModelString length;
 *	uint32_t ContextName = "AAPL";
 *	uint32_t Pad = 0;
 *	uint32_t CommandCode = kAAPL_SERVER_QUERY
 *	uint32_t Reserved = 0;
 *	uint64_t ReplyBitmap = kAAPL_SERVER_CAPS | kAAPL_VOLUME_CAPS |
 *			       kAAPL_MODEL_INFO;
 *	uint64_t ServerCaps = kAAPL_SUPPORTS_READ_DIR_ATTR |
 *			      kAAPL_SUPPORTS_OSX_COPYFILE;
 *	uint64_t VolumeCaps = kAAPL_SUPPORT_RESOLVE_ID | kAAPL_CASE_SENSITIVE;
 *	uint32_t Pad2 = 0;
 *	uint32_t ModelStringLen = variable;
 *	char *   ModelString;
 *	char     PadBytes = variable to end on 8 byte boundary;
 *
 * kAAPL_SUPPORTS_NFS_ACE - Uses to set Posix permission when ACLs are off
 *	on the server. The server must allow the client to get the current
 *	ACL and then the client will return it with the desired Posix
 *	permissions in the NFS ACE in the ACL.
 */

/* Define Server Query request/response bitmap */
enum {
	kAAPL_SERVER_CAPS = 0x01,
	kAAPL_VOLUME_CAPS = 0x02,
	kAAPL_MODEL_INFO = 0x04
};

/* Define Client/Server Capabilities bitmap */
enum {
	kAAPL_SUPPORTS_READ_DIR_ATTR = 0x01,
	kAAPL_SUPPORTS_OSX_COPYFILE = 0x02,
	kAAPL_UNIX_BASED = 0x04,
	kAAPL_SUPPORTS_NFS_ACE = 0x08
};

/* Define Volume Capabilities bitmap */
enum {
	kAAPL_SUPPORT_RESOLVE_ID = 0x01,
	kAAPL_CASE_SENSITIVE = 0x02
};

/*
 * Resolve ID Request
 *
 *	uint32_t command_code = kAAPL_RESOLVE_ID;
 *	uint32_t reserved = 0;
 *	uint64_t file_id;
 *
 * Resolve ID Response
 *
 *	uint32_t command_code = kAAPL_RESOLVE_ID;
 *	uint32_t reserved = 0;
 *	uint32_t resolve_id_ntstatus;
 *	uint32_t path_string_len = variable;
 *	char *   path_string;
 *
 * Example Resolve ID Context Response Buffer:
 *	uint32_t Next = 0;
 *	uint16_t NameOffset = 16;
 *	uint16_t NameLength = 4;
 *	uint16_t Reserved = 0;
 *	uint16_t DataOffset = 24;
 *	uint32_t DataLength = variable based on PathString length;
 *	uint32_t ContextName = "AAPL";
 *	uint32_t Pad = 0;
 *	uint32_t CommandCode = kAAPL_RESOLVE_ID;
 *	uint32_t Reserved = 0;
 *	uint32_t ResolveID_NTStatus = 0;
 *	uint32_t ServerPathLen = variable;
 *	char *   ServerPath;
 *	char     PadBytes = variable to end on 8 byte boundary;
 */

/*
 * ReadDirAttr Support
 *
 * Server has to support AAPL Create Context and support the
 * command of kAAPL_SERVER_QUERY. In the ReplyBitMap, kAAPL_SERVER_CAPS
 * has to be set and in the ServerCaps field, kAAPL_SUPPORTS_READ_DIR_ATTR
 * must be set.
 *
 * Client uses FILE_ID_BOTH_DIR_INFORMATION for QueryDir
 *
 * In the Server reply for FILE_ID_BOTH_DIR_INFORMATION, fields are defined as:
 *	uint32_t ea_size;
 *	uint8_t short_name_len;
 *	uint8_t reserved;
 *	uint8_t short_name[24];
 *	uint16_t reserved2;
 *
 * If kAAPL_SUPPORTS_READ_DIR_ATTR is set, the fields will be filled in as:
 *	uint32_t max_access;
 *	uint8_t short_name_len = 0;
 *	uint8_t reserved = 0;
 *	uint64_t rsrc_fork_len;
 *	uint8_t compressed_finder_info[16];
 *	uint16_t unix_mode;  (only if kAAPL_UNIX_BASED is set)
 *
 * Notes:
 *	(1) ea_size is the max access if SMB_EFA_REPARSE_POINT is NOT set in
 *	the file attributes. For a reparse point, the SMB Client will assume
 *	full access.
 *	(2) short_name is now the Resource Fork logical length and minimal
 *	Finder Info.
 *	(3) SMB Cient will calculate the resource fork allocation size based on
 *	block size. This will be done in all places resource fork allocation
 *	size is returned by the SMB Client so we return consistent answers.
 *	(4) Compressed Finder Info will be only the fields actually still in
 *	use in the regular Finder Info and in the Ext Finder Info. SMB client
 *	will build a normal Finder Info and Ext Finder Info and fill in the
 *	other fields in with zeros.
 *	(5) If kAAPL_UNIX_BASED is set, then reserved2 is the entire Posix mode
 *
 *	struct smb_finder_file_info {
 *		uint32_t finder_type;
 *		uint32_t finder_creator;
 *		uint16_t finder_flags;
 *		uint16_t finder_ext_flags;
 *		uint32_t finder_date_added;
 *	}
 *
 *	struct smb_finder_folder_info {
 *		uint64_t reserved1;
 *		uint16_t finder_flags;
 *		uint16_t finder_ext_flags;
 *		uint32_t finder_date_added;
 *	}
 *
 *
 * Normal Finder Info and Extended Finder Info definitions
 *	struct finder_file_info {
 *		uint32_t finder_type;
 *		uint32_t finder_creator;
 *		uint16_t finder_flags;
 *		uint32_t finder_old_location = 0;
 *		uint16_t reserved = 0;
 *
 *		uint32_t reserved2 = 0;
 *		uint32_t finder_date_added;
 *		uint16_t finder_ext_flags;
 *		uint16_t reserved3 = 0;
 *		uint32_t reserved4 = 0;
 *	}
 *
 *	struct finder_folder_info {
 *		uint64_t reserved1;
 *		uint16_t finder_flags;
 *		uint32_t finder_old_location = 0;
 *		uint16_t finder_old_view_flags = 0;
 *
 *		uint32_t finder_old_scroll_position = 0;
 *		uint32_t finder_date_added;
 *		uint16_t finder_ext_flags;
 *		uint16_t reserved3 = 0;
 *		uint32_t reserved4 = 0;
 *	}
 */

/*
 * Note: If you use the above smb_finder_* structs, they must be "packed".
 * (no alignment padding).  On the server side, all of these can be
 * opaque, so for simplicity we use smb_macinfo_t below.
 */

/*
 * Implementation specific:
 */
typedef struct smb_macinfo {
	uint64_t mi_rforksize;
	uint32_t mi_finderinfo[4];
	uint32_t mi_maxaccess;
	uint16_t mi_unixmode;
} smb_macinfo_t;

int smb2_aapl_get_macinfo(smb_request_t *, smb_odir_t *,
	smb_fileinfo_t *, smb_macinfo_t *, char *, size_t);

#endif	/* _SMB2AAPL_H */
