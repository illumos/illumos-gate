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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
#pragma D option flowindent
*/

/*
 * Usage:	./cifs.d -p `pgrep smbd`
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

sdt:smbsrv::-smb_op*-start
{
	sr = (struct smb_request *)arg0;

	printf("cmd=%d [uid=%d tid=%d]",
	    sr->smb_com, sr->smb_uid, sr->smb_tid);

	self->status = 0;
}

sdt:smbsrv::-smb_op*-done
{
	sr = (struct smb_request *)arg0;

	printf("cmd[%d]: status=0x%08x (class=%d code=%d)",
	    sr->smb_com, sr->smb_error.status,
	    sr->smb_error.errcls, sr->smb_error.errcode);

	self->status = sr->smb_error.status;
}

sdt:smbsrv::-smb_op-SessionSetupX-start
{
	sr = (struct smb_request *)arg0;

	printf("[%s] %s",
	    (sr->session->s_local_port == 139) ? "NBT" : "TCP",
	    (sr->session->s_local_port == 139) ?
	    stringof(sr->session->workstation) : "");
}

sdt:smbsrv::-smb_op-SessionSetupX-done,
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

sdt:smbsrv::-smb_op-TreeConnectX-done,
sdt:smbsrv::-smb_op-TreeDisconnect-start
{
	sr = (struct smb_request *)arg0;

	printf("tid %d: %s", sr->smb_tid,
	    stringof(sr->tid_tree->t_sharename));
	discard(self->status);
}

sdt:smbsrv::-smb_op-Open-start,
sdt:smbsrv::-smb_op-OpenX-start,
sdt:smbsrv::-smb_op-Create-start,
sdt:smbsrv::-smb_op-CreateNew-start,
sdt:smbsrv::-smb_op-CreateTemporary-start,
sdt:smbsrv::-smb_op-CreateDirectory-start,
sdt:smbsrv::-smb_op-NtCreateX-start,
sdt:smbsrv::-smb_op-NtTransactCreate-start
{
	op =  (struct open_param *)arg1;

	printf("%s", stringof(op->fqi.path));
}

sdt:smbsrv::-smb_op-Open-done,
sdt:smbsrv::-smb_op-OpenX-done,
sdt:smbsrv::-smb_op-Create-done,
sdt:smbsrv::-smb_op-CreateNew-done,
sdt:smbsrv::-smb_op-CreateTemporary-done,
sdt:smbsrv::-smb_op-CreateDirectory-done,
sdt:smbsrv::-smb_op-NtCreateX-done,
sdt:smbsrv::-smb_op-NtTransactCreate-done
{
	sr = (struct smb_request *)arg0;

	printf("%s: fid=%u",
	    stringof(sr->arg.open.fqi.path), sr->smb_fid);
}

sdt:smbsrv::-smb_op-Read-start,
sdt:smbsrv::-smb_op-LockAndRead-start,
sdt:smbsrv::-smb_op-ReadX-start,
sdt:smbsrv::-smb_op-ReadRaw-start,
sdt:smbsrv::-smb_op-Write-start,
sdt:smbsrv::-smb_op-WriteAndClose-start,
sdt:smbsrv::-smb_op-WriteAndUnlock-start,
sdt:smbsrv::-smb_op-WriteX-start,
sdt:smbsrv::-smb_op-WriteRaw-start
{
	sr = (struct smb_request *)arg0;
	rw =  (smb_rw_param_t *)arg1;

	printf("fid=%d: %u bytes at offset %u",
	    sr->smb_fid, rw->rw_count, rw->rw_offset);
}

sdt:smbsrv::-smb_op-Read-done,
sdt:smbsrv::-smb_op-LockAndRead-done,
sdt:smbsrv::-smb_op-ReadX-done,
sdt:smbsrv::-smb_op-ReadRaw-done
/self->status == 0/
{
	sr = (struct smb_request *)arg0;
	rw =  (smb_rw_param_t *)arg1;

	printf("fid=%d: %u bytes at offset %u",
	    sr->smb_fid, rw->rw_count, rw->rw_offset);
}

sdt:smbsrv::-smb_op-Rename-start
{
	p = (struct dirop *)arg1;

	printf("%s to %s",
	     stringof(p->fqi.path), stringof(p->dst_fqi.path));
}

sdt:smbsrv::-smb_op-CheckDirectory-start,
sdt:smbsrv::-smb_op-CreateDirectory-start,
sdt:smbsrv::-smb_op-DeleteDirectory-start,
sdt:smbsrv::-smb_op-Delete-start
{
	p = (struct dirop *)arg1;

	printf("%s", stringof(p->fqi.path));
}

/*
smb_dispatch_request:entry,
smb_dispatch_request:return,
smb_pre_*:return,
smb_com_*:return,
smb_post_*:return,
smbsr_error:return,
smbsr_errno:return
{
}

smb_pre_*:entry,
smb_com_*:entry,
smb_post_*:entry
{
	sr = (struct smb_request *)arg0;

	printf("cmd=%d [uid=%d tid=%d]",
	    sr->smb_com, sr->smb_uid, sr->smb_tid);
}

smbsr_error:entry
{
    printf("status=0x%08x class=%d, code=%d\n", arg1, arg2, arg3);
}

smbsr_errno:entry
{
    printf("errno=%d\n", arg1);
}
*/
