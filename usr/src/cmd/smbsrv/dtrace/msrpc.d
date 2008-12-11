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

/*
 * Usage:	./msrpc.d -p `pgrep smbd`
 *
 * On multi-processor systems, it may be easier to follow the output
 * if run on a single processor: see psradm.  For example, to disable
 * the second processor on a dual-processor system:	psradm -f 1
 *
 * This script can be used to trace NDR operations and MSRPC requests.
 * In order to put these operations in context, SMB session and tree
 * requests are also traced.
 *
 * Output formatting is as follows:
 *
 *      UI 03 ... rpc_vers           get 1@0   =    5 {05}
 *      UI 03 ... rpc_vers_minor     get 1@1   =    0 {00}
 *
 *      U       Marshalling flag (M=marshal, U=unmarshal)
 *      I       Direction flag (I=in, O=out)
 *      ...     Field name
 *      get     PDU operation (get or put)
 *      1@0     Bytes @ offset (i.e. 1 byte at offset 0)
 *      {05}    Value
 *
 * The value formatting is limited to 10 bytes, after which an ellipsis
 * will be inserted before the closing brace.  If the value is 1 or 2
 * bytes, an attempt will be made to present an ASCII value but this may
 * or may not be relevent.
 *
 * The following example shows the header from a bind response:
 *
 *  trace:entry MO 03 ... rpc_vers         put 1@0   =    5 {05}
 *  trace:entry MO 03 ... rpc_vers_minor   put 1@1   =    0 {00}
 *  trace:entry MO 03 ... ptype            put 1@2   =   12 {0c}
 *  trace:entry MO 03 ... pfc_flags        put 1@3   =    3 {03}
 *  trace:entry MO 04 .... intg_char_rep   put 1@4   =   16 {10}
 *  trace:entry MO 04 .... float_rep       put 1@5   =    0 {00}
 *  trace:entry MO 04 .... _spare[0]       put 1@6   =    0 {00}
 *  trace:entry MO 04 .... _spare[1]       put 1@7   =    0 {00}
 *  trace:entry MO 03 ... frag_length      put 2@8   =   68 {44 00} D
 *  trace:entry MO 03 ... auth_length      put 2@10  =    0 {00 00}
 *  trace:entry MO 03 ... call_id          put 4@12  =    1 {01 00 00 00}
 *  trace:entry MO 02 .. max_xmit_frag     put 2@16  = 4280 {b8 10}
 *  trace:entry MO 02 .. max_recv_frag     put 2@18  = 4280 {b8 10}
 *  trace:entry MO 02 .. assoc_group_id    put 4@20  = 1192620711 {a7 f2 15 47}
 *  trace:entry MO 02 .. sec_addr.length   put 2@24  =   12 {0c 00}
 *  trace:entry MO 02 .. sec_addr.port_spec[0]  put 1@26  =   92 {5c} \
 *  trace:entry MO 02 .. sec_addr.port_spec[1]  put 1@27  =   80 {50} P
 *  trace:entry MO 02 .. sec_addr.port_spec[2]  put 1@28  =   73 {49} I
 *  trace:entry MO 02 .. sec_addr.port_spec[3]  put 1@29  =   80 {50} P
 *  trace:entry MO 02 .. sec_addr.port_spec[4]  put 1@30  =   69 {45} E
 *  trace:entry MO 02 .. sec_addr.port_spec[5]  put 1@31  =   92 {5c} \
 *  trace:entry MO 02 .. sec_addr.port_spec[6]  put 1@32  =  108 {6c} l
 *  trace:entry MO 02 .. sec_addr.port_spec[7]  put 1@33  =  115 {73} s
 *  trace:entry MO 02 .. sec_addr.port_spec[8]  put 1@34  =   97 {61} a
 *  trace:entry MO 02 .. sec_addr.port_spec[9]  put 1@35  =  115 {73} s
 *  trace:entry MO 02 .. sec_addr.port_spec[10]  put 1@36  = 115 {73} s
 *  trace:entry MO 02 .. sec_addr.port_spec[11]  put 1@37  =   0 {00}
 */

BEGIN
{
	printf("MSRPC Trace Started");
	printf("\n\n");
}

END
{
	printf("MSRPC Trace Ended");
	printf("\n\n");
}

/*
 * SmbSessionSetupX, SmbLogoffX
 * SmbTreeConnect, SmbTreeDisconnect
 */
smb_tree*:entry,
smb_com_*:entry,
smb_com_*:return,
smb_com_session_setup_andx:entry,
smb_com_logoff_andx:entry,
smb_tree_connect:return,
smb_tree_disconnect:entry,
smb_tree_disconnect:return,
smb_opipe_open:entry,
smb_opipe_door_call:entry,
smb_opipe_door_upcall:entry,
door_ki_upcall:entry
{
}

smb_com_session_setup_andx:return,
smb_user*:return,
smb_tree*:return,
smb_opipe_open:return,
smb_opipe_door_call:return,
smb_opipe_door_upcall:return,
door_ki_upcall:return
{
	printf("rc=0x%08x", arg1);
}

sdt:smbsrv::smb-sessionsetup-clntinfo
{
	clnt = (netr_client_t *)arg0;

	printf("domain\\username=%s\\%s\n\n",
	    stringof(clnt->domain),
	    stringof(clnt->username));
}

smb_tree_connect:entry
{
	sr = (smb_request_t *)arg0;

	printf("share=%s service=%s",
	    stringof(sr->arg.tcon.path),
	    stringof(sr->arg.tcon.service));
}

smb_com_logoff_andx:return
{
	exit(0);
}

/*
 * Raise error functions (no return).
 */
smbsr_error:entry
{
    printf("status=0x%08x class=%d, code=%d", arg1, arg2, arg3);
}

smbsr_errno:entry
{
    printf("errno=%d", arg1);
}

smbsr_error:return,
smbsr_errno:return
{
}

/*
 * MSRPC activity.
 */
pid$target::ndr_svc_bind:entry,
pid$target::ndr_svc_bind:return,
pid$target::ndr_svc_request:entry,
pid$target::ndr_svc_request:return
{
}

pid$target::smb_trace:entry,
pid$target::ndo_trace:entry
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

/*
 * SMBRDR
 */
pid$target::smbrdr_*:entry,
pid$target::smbrdr_*:return
{
}

pid$target::smbrdr_tree_connect:entry
{
	printf("%s %s %s",
	    copyinstr(arg0),
	    copyinstr(arg1),
	    copyinstr(arg2));
}

pid$target::smbrdr_open_pipe:entry
{
	printf("%s %s %s %s",
	    copyinstr(arg0),
	    copyinstr(arg1),
	    copyinstr(arg2),
	    copyinstr(arg3));
}

pid$target::smbrdr_close_pipe:entry
{
}

pid$target::smbrdr_tree_connect:return,
pid$target::smbrdr_open_pipe:return,
pid$target::smbrdr_close_pipe:return
{
	printf("%d", arg1);
}
