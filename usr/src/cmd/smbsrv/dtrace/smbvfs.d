#!/usr/sbin/dtrace -qs
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

BEGIN
{
    printf("\n-->SMB Server VFS Trace Started");
    printf("\n\n");
}

END
{
    printf("\n<--SMB Server VFS Trace Ended");
    printf("\n\n");
}

sdt:smbsrv:smb_vfs_hold:smb_vfs_hold_hit
{
    printf("\nSMB VFS lookup hit");
    printf("\n    Path: %s", (string)((smb_vfs_t *)arg0)->sv_rootvp->v_path);
    printf("\n    RefCount: %d", ((smb_vfs_t *)arg0)->sv_refcnt);
}

sdt:smbsrv:smb_vfs_hold:smb_vfs_hold_miss
{
    printf("\nSMB VFS lookup miss");
    printf("\n    Path: %s", (string)((smb_vfs_t *)arg0)->sv_rootvp->v_path);
    printf("\n    RefCount: %d", ((smb_vfs_t *)arg0)->sv_refcnt);
}

sdt:smbsrv:smb_vfs_rele:smb_vfs_release
/(smb_vfs_t *)arg0 != 0/
{
    printf("\nSMB VFS release hit");
    printf("\n    Path: %s", (string)((smb_vfs_t *)arg0)->sv_rootvp->v_path);
    printf("\n    RefCount: %d", ((smb_vfs_t *)arg0)->sv_refcnt - 2);
}

sdt:smbsrv:smb_vfs_rele:smb_vfs_release
/(smb_vfs_t *)arg0 == 0/
{
    printf("\nSMB VFS release miss");
    printf("\n    Path: %s", (string)((vnode_t *)arg1)->v_path);
}

sdt:smbsrv:smb_vfs_rele_all:smb_vfs_rele_all_hit
{
    printf("\nSMB VFS free");
    printf("\n    Path: %s", (string)((smb_vfs_t *)arg0)->sv_rootvp->v_path);
    printf("\n    RefCount: %d", ((smb_vfs_t *)arg0)->sv_refcnt);
}


