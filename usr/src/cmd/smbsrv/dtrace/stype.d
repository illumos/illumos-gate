#!/usr/sbin/dtrace -s

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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#pragma D option flowindent

/*
 * Usage:	./stype.d -p `pgrep smbd`
 *
 * On multi-processor systems, it may be easier to follow the output
 * if run on a single processor: see psradm.  For example, to disable
 * the second processor on a dual-processor system:	psradm -f 1
 */

BEGIN
{
	printf("CIFS Trace Started");
	printf("\n\n");
}

END
{
	printf("CIFS Trace Ended");
	printf("\n\n");
}

sdt:smbsrv::-smb_op-SessionSetupX-start
{
	sr = (struct smb_request *)arg0;
	ssetup = (smb_arg_sessionsetup_t *)arg1;

	printf("[%s] %s %s %s",
	    (sr->session->s_local_port == 139) ? "NBT" : "TCP",
	    (sr->session->s_local_port == 139) ?
	    stringof(sr->session->workstation) : "",
	    stringof(ssetup->ssi_domain),
	    stringof(ssetup->ssi_user));

	printf(" maxmpx=%u vc=%u maxbuf=%u",
	    ssetup->ssi_maxmpxcount,
	    sr->session->vcnumber,
	    sr->session->smb_msg_size);
}

sdt:smbsrv::-smb_op-SessionSetupX-done
{
	sr = (struct smb_request *)arg0;
	ssetup = (smb_arg_sessionsetup_t *)arg1;

	printf("%s/%s: smbuid=%d (%s)",
	    stringof(sr->uid_user->u_domain),
	    stringof(sr->uid_user->u_name),
	    sr->smb_uid,
	    (ssetup->ssi_guest == 0) ? "user" : "guest");

	printf(" [status=0x%08x (class=%d code=%d)]",
	    sr->smb_error.status,
	    sr->smb_error.errcls, sr->smb_error.errcode);
}

sdt:smbsrv::-smb_op-LogoffX-start
{
	sr = (struct smb_request *)arg0;

	printf("uid %d: %s/%s", sr->smb_uid,
	    stringof(sr->uid_user->u_domain),
	    stringof(sr->uid_user->u_name));
}

sdt:smbsrv::-smb_op-TreeConnectX-start
{
	tcon = (struct tcon *)arg1;

	printf("[%s] %s",
                stringof(tcon->service),
                stringof(tcon->path));
}

sdt:smbsrv::-smb_op-TreeConnectX-done
{
	sr = (struct smb_request *)arg0;

	printf("tid %d: %s", sr->smb_tid,
	    (sr->smb_error.status == 0) ?
	    stringof(sr->tid_tree->t_sharename) : "");

	printf(" [status=0x%08x (class=%d code=%d)]",
	    sr->smb_error.status,
	    sr->smb_error.errcls, sr->smb_error.errcode);
}

sdt:smbsrv::-smb_op-TreeDisconnect-start
{
	sr = (struct smb_request *)arg0;

	printf("tid %d: %s", sr->smb_tid,
	    (sr->tid_tree == 0) ? "" :
	    stringof(sr->tid_tree->t_sharename));
}

/*
 * Error functions
 */
smbsr_status:entry
{
    printf("status=0x%08x class=%d, code=%d", arg1, arg2, arg3);
}

smbsr_errno:entry
{
    printf("errno=%d", arg1);
}

smbsr_status:return,
smbsr_errno:return
{
}

/*
 * Share/tree connect.
 */
smb_tree_connect:entry
{
}

smb_tree_get_sharename:entry
{
	printf("uncpath=%s", stringof(arg0));
}

smb_tree_connect_disk:entry
{
	printf("sharename=%s", stringof(arg1));
	self->stype = 0;
}

smb_tree_connect_printq:entry
{
	printf("sharename=%s", stringof(arg1));
	self->stype = 1;
}

smb_tree_connect_ipc:entry
{
	printf("sharename=%s", stringof(arg1));
	self->stype = 3;
}

smb_tree_connect:return,
smb_tree_get_sharename:return,
smb_tree_connect_disk:return,
smb_tree_connect_ipc:return
{
	printf("rc=0x%08x", arg1);
}

smb_tree_alloc:entry
/self->stype == 0/
{
	printf("share=%s service=%s", stringof(arg1), stringof(arg2));
}

smb_tree_alloc:return
/self->stype == 0/
{
	printf("FS=%s flags=0x%08x",
	    stringof(((smb_tree_t *)arg1)->t_typename),
	    ((smb_tree_t *)arg1)->t_flags);
}

smb_tree_disconnect:entry,
smb_tree_disconnect:return
{
}

smb_tree_log:entry
{
	printf("%s: %s", stringof(arg1), stringof(arg2));
}
