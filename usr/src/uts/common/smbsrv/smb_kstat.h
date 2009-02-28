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
 */

/*
 * Kstat definitions for the SMB server module.
 */
#ifndef _SMBSRV_SMB_KSTAT_H
#define	_SMBSRV_SMB_KSTAT_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	SMBSRV_KSTAT_MODULE		"smbsrv"
#define	SMBSRV_KSTAT_CLASS		"net"
#define	SMBSRV_KSTAT_NAME		"smbsrv"
#define	SMBSRV_KSTAT_NAME_CMDS		"smbsrv_commands"
#define	SMBSRV_KSTAT_TXRCACHE		"smb_txreq"
#define	SMBSRV_KSTAT_UNEXPORT_CACHE	"smb_unexport_cache"
#define	SMBSRV_KSTAT_VFS_CACHE		"smb_vfs_cache"
#define	SMBSRV_KSTAT_REQUEST_CACHE	"smb_request_cache"
#define	SMBSRV_KSTAT_SESSION_CACHE	"smb_session_cache"
#define	SMBSRV_KSTAT_USER_CACHE		"smb_user_cache"
#define	SMBSRV_KSTAT_TREE_CACHE		"smb_tree_cache"
#define	SMBSRV_KSTAT_OFILE_CACHE	"smb_ofile_cache"
#define	SMBSRV_KSTAT_ODIR_CACHE		"smb_odir_cache"
#define	SMBSRV_KSTAT_NODE_CACHE		"smb_node_cache"
#define	SMBSRV_KSTAT_MBC_CACHE		"smb_mbc_cache"

#ifdef	__cplusplus
}
#endif

#endif /* _SMBSRV_SMB_KSTAT_H */
