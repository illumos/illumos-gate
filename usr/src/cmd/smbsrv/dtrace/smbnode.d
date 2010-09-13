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
    printf("-->SMB Server Node Trace Started");
    printf("\n\n");
}

END
{
    printf("<--SMB Server Node Trace Ended");
    printf("\n\n");
}

sdt:smbsrv:smb_node_lookup:smb_node_lookup_hit
/((smb_node_t *)arg0)->n_state == SMB_NODE_STATE_AVAILABLE/
{
    printf("\nSMB Node lookup hit/SMB_NODE_STATE_AVAILABLE");
    printf("\n\tNode: %p", arg0);
    printf("\n\tRefCnt: %d", ((smb_node_t *)arg0)->n_refcnt);
    printf("\n\tName: %s", (string)((vnode_t *)((smb_node_t *)arg0)->vp)->v_path);
    stack();
}

sdt:smbsrv:smb_node_lookup:smb_node_lookup_hit
/((smb_node_t *)arg0)->n_state == SMB_NODE_STATE_DESTROYING/
{
    printf("\nSMB Node lookup hit/SMB_NODE_STATE_DESTROYING");
    printf("\n\tNode: %p", arg0);
    printf("\n\tRefCnt: %d", ((smb_node_t *)arg0)->n_refcnt);
    printf("\n\tName: %s", (string)((vnode_t *)((smb_node_t *)arg0)->vp)->v_path);
    stack();
}

sdt:smbsrv:smb_node_lookup:smb_node_lookup_hit
/(((smb_node_t *)arg0)->n_state != SMB_NODE_STATE_DESTROYING) &&
 (((smb_node_t *)arg0)->n_state != SMB_NODE_STATE_AVAILABLE)/
{
    printf("\nSMB Node lookup hit/Unknown State");
    printf("\n\tNode: %p", arg0);
    printf("\n\tRefCnt: %d", ((smb_node_t *)arg0)->n_refcnt);
    printf("\n\tName: %s", (string)((vnode_t *)((smb_node_t *)arg0)->vp)->v_path);
    stack();
}

sdt:smbsrv:smb_node_lookup:smb_node_lookup_miss
{
    printf("\nSMB Node lookup miss");
    printf("\n\tNode: %p", arg0);
    printf("\n\tRefCnt: %d", ((smb_node_t *)arg0)->n_refcnt);
    printf("\n\tName: %s", (string)((vnode_t *)((smb_node_t *)arg0)->vp)->v_path);
    stack();
}

sdt:smbsrv:smb_node_ref:smb_node_ref_exit
{
    printf("\nSMB Node reference taken");
    printf("\n\tNode: %p", arg0);
    printf("\n\tRefCnt: %d", ((smb_node_t *)arg0)->n_refcnt);
    printf("\n\tName: %s", (string)((vnode_t *)((smb_node_t *)arg0)->vp)->v_path);
    stack();
}

sdt:smbsrv:smb_node_release:smb_node_release
/((smb_node_t *)arg0)->n_refcnt == 1/
{
    printf("\nSMB Node release(will be destroyed)");
    printf("\n\tNode: %p", arg0);
    printf("\n\tName: %s", (string)((vnode_t *)((smb_node_t *)arg0)->vp)->v_path);
    stack();
}

sdt:smbsrv:smb_node_release:smb_node_release
/((smb_node_t *)arg0)->n_refcnt > 1/
{
    printf("\nSMB Node release");
    printf("\n\tNode: %p", arg0);
    printf("\n\tRefCnt: %d", ((smb_node_t *)arg0)->n_refcnt);
    printf("\n\tName: %s", (string)((vnode_t *)((smb_node_t *)arg0)->vp)->v_path);
    stack();
}

sdt:smbsrv:smb_node_delete_on_close:smb_node_delete_on_close
/(int)arg0 == 0/
{
    printf("\nSMB Node delete on close successful");
    printf("\n\tNode: %p", arg1);
    printf("\n\tName: %s", (string)((vnode_t *)((smb_node_t *)arg1)->vp)->v_path);
    stack();
}

sdt:smbsrv:smb_node_delete_on_close:smb_node_delete_on_close
/(int)arg0 == 0/
{
    printf("\nSMB Node delete on close failed (%d)", (int)arg0);
    printf("\n\tNode: %p", arg1);
    printf("\n\tName: %s", (string)((vnode_t *)((smb_node_t *)arg1)->vp)->v_path);
    stack();
}


