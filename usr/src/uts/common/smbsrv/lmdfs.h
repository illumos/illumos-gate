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

#ifndef _SMBSRV_LMDFS_H
#define	_SMBSRV_LMDFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * LAN Manager DFS interface definition.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * DFS Volume state
 */
#define	DFS_VOLUME_STATE_OK		1
#define	DFS_VOLUME_STATE_INCONSISTENT	2
#define	DFS_VOLUME_STATE_OFFLINE	3
#define	DFS_VOLUME_STATE_ONLINE		4

/*
 * DFS Storage state
 */
#define	DFS_STORAGE_STATE_OFFLINE	1
#define	DFS_STORAGE_STATE_ONLINE	2

/*
 * Flags:
 * DFS_ADD_VOLUME:	Add a new volume to the DFS if not already there.
 * DFS_RESTORE_VOLUME:	Volume/Replica is being restored - do not verify
 * 			share etc.
 */
#define	DFS_ADD_VOLUME		1
#define	DFS_RESTORE_VOLUME	2


#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_LMDFS_H */
