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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma D option flowindent

/*
 * SmbSessionSetupX, SmbLogoffX and dispatcher
 */
smb_com_session_setup_andx:entry,
smb_com_logoff_andx:entry,
smb_com_session_setup_andx:return
{
}

sdt:smbsrv::smb-dispatch-com
{
    printf("command=%d", ((smb_request_t *)arg0)->smb_com);
}

sdt:smbsrv::smb-sessionsetup-clntinfo
{
        clnt = (netr_client_t *)arg0;

        printf("domain=%s\n\n", stringof(clnt->domain));
        printf("username=%s\n\n", stringof(clnt->username));
}

smb_com_logoff_andx:return
{
	exit(0);
}

/*
 * Raise error functions (no return).
 */
smbsr_raise_error:entry
{
	printf("class=%d code=%d", arg1, arg2);
}

smbsr_raise_cifs_error:entry
{
    printf("status=0x%08x class=%d, code=%d", arg1, arg2, arg3);
}

smbsr_raise_nt_error:entry
{
    printf("error=0x%08x", arg1);
}

smbsr_raise_errno:entry
{
    printf("errno=%d", arg1);
}

/*
 * Share/tree connect.
 */
smbsr_setup_share:entry
{
	printf("sharename=%s stype=%d", stringof(arg1), arg2);
	self->stype = arg2;
}

smbsr_setup_share:return
{
	self->stype = 0;
}

smbsr_connect_tree:entry
{
}

smbsr_share_report:entry
{
	printf("%s: %s %s", stringof(arg1), stringof(arg2), stringof(arg3));
}

smbsr_connect_tree:return,
smbsr_share_report:return,
smb_pathname_reduce:return
{
	printf("rc=%d", arg1);
}

smb_get_stype:entry
{
	printf("share=%s service=%s", stringof(arg0), stringof(arg1));
}

smb_get_stype:return
{
	printf("%d", arg1);
}

smb_tree_connect:entry
/self->stype == 0/
{
	printf("share=%s service=%s volname=%s",
		stringof(arg3),
		stringof(arg4),
		stringof(((fsvol_attr_t *)arg7)->name));
}

smb_tree_connect:return
/self->stype == 0/
{
	printf("FS=%s", stringof(((smb_tree_t *)arg1)->t_typename));
}

smb_pathname_reduce:entry
{
	printf("path=%s", stringof(arg2));
}

sdt:smbsrv::smb-vfs-volume
{
	printf("mntpnt=%s volname=%s", stringof(arg0), stringof(arg1));
}

sdt:smbsrv::smb-vfs-getflags
{
	printf("flags=0x%08x", arg0);
}
