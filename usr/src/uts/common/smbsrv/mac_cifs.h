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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMBSRV_MAC_CIFS_H
#define	_SMBSRV_MAC_CIFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file provides definitions for the Macintosh Extensions for CIFS
 * interface (see http://www.thursby.com/cifs).
 */

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Macintosh information level extensions. The entire list is presented
 * here for convenience but for consistency with the existing CIFS
 * information levels don't use these values directly. Use the SMB_MAC_
 * definitions in cifs.h.
 *
 * SmbTrans2QueryFsInformation:		MAC_QUERY_FS_INFO
 * SmbTrans2Find{First|Next}2:		MAC_FIND_BOTH_HFS_INFO
 * SmbTrans2SetPathInformation:		MAC_SET_FINDER_INFO
 * SmbTrans2QueryPathInformation:	MAC_DT_{ADD|REMOVE|GET}_{APPL|ICON}
 */
#define	MAC_QUERY_FS_INFO			0x301
#define	MAC_FIND_BOTH_HFS_INFO			0x302
#define	MAC_SET_FINDER_INFO			0x303
#define	MAC_DT_ADD_APPL				0x304
#define	MAC_DT_REMOVE_APPL			0x305
#define	MAC_DT_GET_APPL				0x306
#define	MAC_DT_GET_ICON				0x307
#define	MAC_DT_GET_ICON_INFO			0x308
#define	MAC_DT_ADD_ICON				0x309


/*
 * Macintosh extensions support bits. Returned by the server in response
 * to a TRANS2_QUERY_FS_INFORMATION request when the information level
 * is MAC_QUERY_FS_INFO.
 */
#define	MAC_SUPPORT_ACCESS_CONTROL		0x0010
#define	MAC_SUPPORT_GETSETCOMMENTS		0x0020
#define	MAC_SUPPORT_DESKTOPDB_CALLS		0x0040
#define	MAC_SUPPORT_UNIQUE_IDS			0x0080
#define	MAC_SUPPORT_NO_STREAMS			0x0100


/*
 * The MAC_ACCESS values are returned from the MAC_FIND_BOTH_HFS_INFO
 * info level of TRANS2_FIND. Set SUPPORT_MAC_ACCESS_CNTRL to enable
 * support.
 *
 * The MAC_OWNER bit indicates that the user is the owner of the file
 * or directory.
 */
#define	MAC_ACCESS_OWNER			0x0800
#define	MAC_ACCESS_OWNER_READ			0x0400
#define	MAC_ACCESS_OWNER_WRITE			0x0200
#define	MAC_ACCESS_OWNER_SEARCH			0x0100
#define	MAC_ACCESS_GROUP_READ			0x0040
#define	MAC_ACCESS_GROUP_WRITE			0x0020
#define	MAC_ACCESS_GROUP_SEARCH			0x0010
#define	MAC_ACCESS_OTHER_READ			0x0004
#define	MAC_ACCESS_OTHER_WRITE			0x0002
#define	MAC_ACCESS_OTHER_SEARCH			0x0001


/*
 * The MAC_FINDER values support the SMB_MAC_SET_FINDER_INFO info level
 * of TRANS2_SET_PATH_INFORMATION.
 */
#define	MAC_FINDER_SET_CREATE_DATE		0x0001
#define	MAC_FINDER_SET_MODE_DATE		0x0002
#define	MAC_FINDER_SET_FL_ATTRIB		0x0004
#define	MAC_FINDER_SET_INFO1			0x0008
#define	MAC_FINDER_SET_INFO2			0x0010
#define	MAC_FINDER_SET_HIDDEN			0x0020


#ifdef __cplusplus
}
#endif


#endif /* _SMBSRV_MAC_CIFS_H */
