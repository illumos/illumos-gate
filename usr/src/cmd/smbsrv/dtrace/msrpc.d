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

/*
 * Usage:	./msrpc.d -p `pgrep smbd`
 *
 * On multi-processor systems, it may be easier to follow the output
 * if run on a single processor: see psradm.  For example, to disable
 * the second processor on a dual-processor system:	psradm -f 1
 */

/*
 * SmbSessionSetupX, SmbLogoffX
 * SmbTreeConnect, SmbTreeDisconnect
 */
smb_session*:entry,
smb_tree*:entry,
smb_com_*:entry,
smb_com_*:return,
smb_com_session_setup_andx:entry,
smb_com_logoff_andx:entry,
smb_tree_connect:return,
smb_tree_disconnect:entry,
smb_tree_disconnect:return
{
}

smb_com_session_setup_andx:return,
smb_session*:return,
smb_user*:return,
smb_tree*:return
{
	printf("rc=%d", arg1);
}

sdt:smbsrv::smb-sessionsetup-clntinfo
{
	clnt = (netr_client_t *)arg0;

	printf("domain=%s\n\n", stringof(clnt->domain));
	printf("username=%s\n\n", stringof(clnt->username));
}

smb_tree_connect:entry
{
	printf("share=%s service=%s",
	    stringof(arg3), stringof(arg4));
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
 * MSRPC activity.
 */
pid$target::mlrpc_s_bind:entry,
pid$target::mlrpc_s_bind:return,
pid$target::mlrpc_s_request:entry,
pid$target::mlrpc_s_request:return
{
}

pid$target::smb_trace:entry,
pid$target::mlndo_trace:entry
{
	printf("%s", copyinstr(arg0));
}

/*
 * LSARPC
 */
pid$target::lsarpc_s_CloseHandle:entry,
pid$target::lsarpc_s_QuerySecurityObject:entry,
pid$target::lsarpc_s_EnumAccounts:entry,
pid$target::lsarpc_s_EnumTrustedDomain:entry,
pid$target::lsarpc_s_OpenAccount:entry,
pid$target::lsarpc_s_EnumPrivsAccount:entry,
pid$target::lsarpc_s_LookupPrivValue:entry,
pid$target::lsarpc_s_LookupPrivName:entry,
pid$target::lsarpc_s_LookupPrivDisplayName:entry,
pid$target::lsarpc_s_Discovery:entry,
pid$target::lsarpc_s_QueryInfoPolicy:entry,
pid$target::lsarpc_s_OpenDomainHandle:entry,
pid$target::lsarpc_s_OpenDomainHandle:entry,
pid$target::lsarpc_s_LookupSids:entry,
pid$target::lsarpc_s_LookupNames:entry,
pid$target::lsarpc_s_GetConnectedUser:entry,
pid$target::lsarpc_s_LookupSids2:entry,
pid$target::lsarpc_s_LookupNames2:entry
{
}

pid$target::lsarpc_s_CloseHandle:return,
pid$target::lsarpc_s_QuerySecurityObject:return,
pid$target::lsarpc_s_EnumAccounts:return,
pid$target::lsarpc_s_EnumTrustedDomain:return,
pid$target::lsarpc_s_OpenAccount:return,
pid$target::lsarpc_s_EnumPrivsAccount:return,
pid$target::lsarpc_s_LookupPrivValue:return,
pid$target::lsarpc_s_LookupPrivName:return,
pid$target::lsarpc_s_LookupPrivDisplayName:return,
pid$target::lsarpc_s_Discovery:return,
pid$target::lsarpc_s_QueryInfoPolicy:return,
pid$target::lsarpc_s_OpenDomainHandle:return,
pid$target::lsarpc_s_OpenDomainHandle:return,
pid$target::lsarpc_s_LookupSids:return,
pid$target::lsarpc_s_LookupNames:return,
pid$target::lsarpc_s_GetConnectedUser:return,
pid$target::lsarpc_s_LookupSids2:return,
pid$target::lsarpc_s_LookupNames2:return
{
}

/*
 * NetLogon
 */
pid$target::netr_s_*:entry,
pid$target::netr_s_*:return
{
}

/*
 * SAMR
 */
pid$target::samr_s_ConnectAnon:entry,
pid$target::samr_s_CloseHandle:entry,
pid$target::samr_s_LookupDomain:entry,
pid$target::samr_s_EnumLocalDomains:entry,
pid$target::samr_s_OpenDomain:entry,
pid$target::samr_s_QueryDomainInfo:entry,
pid$target::samr_s_LookupNames:entry,
pid$target::samr_s_OpenUser:entry,
pid$target::samr_s_DeleteUser:entry,
pid$target::samr_s_QueryUserInfo:entry,
pid$target::samr_s_QueryUserGroups:entry,
pid$target::samr_s_OpenGroup:entry,
pid$target::samr_s_Connect:entry,
pid$target::samr_s_GetUserPwInfo:entry,
pid$target::samr_s_CreateUser:entry,
pid$target::samr_s_ChangeUserPasswd:entry,
pid$target::samr_s_GetDomainPwInfo:entry,
pid$target::samr_s_SetUserInfo:entry,
pid$target::samr_s_Connect3:entry,
pid$target::samr_s_Connect4:entry,
pid$target::samr_s_QueryDispInfo:entry,
pid$target::samr_s_OpenAlias:entry,
pid$target::samr_s_CreateDomainAlias:entry,
pid$target::samr_s_SetAliasInfo:entry,
pid$target::samr_s_QueryAliasInfo:entry,
pid$target::samr_s_DeleteDomainAlias:entry,
pid$target::samr_s_EnumDomainAliases:entry,
pid$target::samr_s_EnumDomainGroups:entry
{
}

pid$target::samr_s_ConnectAnon:return,
pid$target::samr_s_CloseHandle:return,
pid$target::samr_s_LookupDomain:return,
pid$target::samr_s_EnumLocalDomains:return,
pid$target::samr_s_OpenDomain:return,
pid$target::samr_s_QueryDomainInfo:return,
pid$target::samr_s_LookupNames:return,
pid$target::samr_s_OpenUser:return,
pid$target::samr_s_DeleteUser:return,
pid$target::samr_s_QueryUserInfo:return,
pid$target::samr_s_QueryUserGroups:return,
pid$target::samr_s_OpenGroup:return,
pid$target::samr_s_Connect:return,
pid$target::samr_s_GetUserPwInfo:return,
pid$target::samr_s_CreateUser:return,
pid$target::samr_s_ChangeUserPasswd:return,
pid$target::samr_s_GetDomainPwInfo:return,
pid$target::samr_s_SetUserInfo:return,
pid$target::samr_s_Connect3:return,
pid$target::samr_s_Connect4:return,
pid$target::samr_s_QueryDispInfo:return,
pid$target::samr_s_OpenAlias:return,
pid$target::samr_s_CreateDomainAlias:return,
pid$target::samr_s_SetAliasInfo:return,
pid$target::samr_s_QueryAliasInfo:return,
pid$target::samr_s_DeleteDomainAlias:return,
pid$target::samr_s_EnumDomainAliases:return,
pid$target::samr_s_EnumDomainGroups:return
{
}

/*
 * SVCCTL
 */
pid$target::svcctl_s_*:entry,
pid$target::svcctl_s_*:return
{
}

/*
 * SRVSVC
 */
pid$target::srvsvc_s_NetConnectEnum:entry,
pid$target::srvsvc_s_NetFileEnum:entry,
pid$target::srvsvc_s_NetFileClose:entry,
pid$target::srvsvc_s_NetShareGetInfo:entry,
pid$target::srvsvc_s_NetShareSetInfo:entry,
pid$target::srvsvc_s_NetSessionEnum:entry,
pid$target::srvsvc_s_NetSessionDel:entry,
pid$target::srvsvc_s_NetServerGetInfo:entry,
pid$target::srvsvc_s_NetRemoteTOD:entry,
pid$target::srvsvc_s_NetNameValidate:entry,
pid$target::srvsvc_s_NetShareAdd:entry,
pid$target::srvsvc_s_NetShareDel:entry,
pid$target::srvsvc_s_NetShareEnum:entry,
pid$target::srvsvc_s_NetShareEnumSticky:entry,
pid$target::srvsvc_s_NetGetFileSecurity:entry,
pid$target::srvsvc_s_NetSetFileSecurity:entry
{
}

pid$target::srvsvc_s_NetConnectEnum:return,
pid$target::srvsvc_s_NetFileEnum:return,
pid$target::srvsvc_s_NetFileClose:return,
pid$target::srvsvc_s_NetShareGetInfo:return,
pid$target::srvsvc_s_NetShareSetInfo:return,
pid$target::srvsvc_s_NetSessionEnum:return,
pid$target::srvsvc_s_NetSessionDel:return,
pid$target::srvsvc_s_NetServerGetInfo:return,
pid$target::srvsvc_s_NetRemoteTOD:return,
pid$target::srvsvc_s_NetNameValidate:return,
pid$target::srvsvc_s_NetShareAdd:return,
pid$target::srvsvc_s_NetShareDel:return,
pid$target::srvsvc_s_NetShareEnum:return,
pid$target::srvsvc_s_NetShareEnumSticky:return,
pid$target::srvsvc_s_NetGetFileSecurity:return,
pid$target::srvsvc_s_NetSetFileSecurity:return
{
}

/*
 * WinReg
 */
pid$target::winreg_s_*:entry,
pid$target::winreg_s_*:return
{
}

/*
 * Workstation
 */
pid$target::wkssvc_s_*:entry,
pid$target::wkssvc_s_*:return
{
}
