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

#ifndef _SMBSRV_NMPIPES_H
#define	_SMBSRV_NMPIPES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file defines pre-defined and system common named pipes.
 *
 * Named pipes are a simple IPC mechanism supported by Windows 9x, NT
 * and 2000. The Windows named pipe implementation supports reliable
 * one-way and two-way transport independent network messaging. The
 * names follow the universal naming convention (UNC) defined for the
 * Windows redirector: \\[server]\[share]\[path]name. There is a good
 * overview of named pipes in Network Programming for Microsoft Windows
 * Chapter 4. The redirector is described in Chapter 2. UNC names are
 * case-insensitive.
 *
 * Network Programming for Microsoft Windows
 * Anthony Jones and Jim Ohlund
 * Microsoft Press, ISBN 0-7356-0560-2
 *
 * Microsoft RPC, which is derived from DCE RPC, uses SMB named pipes
 * as its transport mechanism. In addition to the pipe used to open
 * each connection, a named pipe also appears in the bind response as
 * a secondary address port. Sometimes the secondary address port is
 * the same and sometimes it is different. The following associations
 * have been observed.
 *
 *		LSARPC		lsass
 *		NETLOGON	lsass
 *		SAMR		lsass
 *		SPOOLSS		spoolss
 *		SRVSVC		ntsvcs
 *		SVCCTL		ntsvcs
 *		WINREG		winreg
 *		WKSSVC		ntsvcs
 *		EVENTLOG	ntsvcs
 *		LLSRPC		llsrpc
 *
 * Further information on RPC named pipes is available in the following
 * references.
 *
 * RPC for NT
 * Guy R. Eddon
 * R&D PUblications, ISBN 0-87930-450-2
 *
 * Network Programming in Windows NT
 * Alok K. Sinha
 * Addison-Wesley, ISBN 0-201-59056-5
 *
 * DCE/RPC over SMB Samba and Windows NT Domain Internals
 * Luke Kenneth Casson Leighton
 * Macmillan Technical Publishing, ISBN 1-57870-150-3
 */


#ifdef __cplusplus
extern "C" {
#endif


/*
 * Well-known or pre-defined Windows named pipes. Typically used
 * with SmbNtCreateAndX and/or SmbTransactNmPipe. When passed to
 * SmbNtCreateAndX the \PIPE prefix is often missing. These names
 * are presented as observed on the wire but should be treated in
 * a case-insensitive manner.
 */
#define	PIPE_LANMAN			"\\PIPE\\LANMAN"
#define	PIPE_NETLOGON			"\\PIPE\\NETLOGON"
#define	PIPE_LSARPC			"\\PIPE\\lsarpc"
#define	PIPE_SAMR			"\\PIPE\\samr"
#define	PIPE_SPOOLSS			"\\PIPE\\spoolss"
#define	PIPE_SRVSVC			"\\PIPE\\srvsvc"
#define	PIPE_SVCCTL			"\\PIPE\\svcctl"
#define	PIPE_WINREG			"\\PIPE\\winreg"
#define	PIPE_WKSSVC			"\\PIPE\\wkssvc"
#define	PIPE_EVENTLOG			"\\PIPE\\EVENTLOG"
#define	PIPE_LSASS			"\\PIPE\\lsass"
#define	PIPE_NTSVCS			"\\PIPE\\ntsvcs"
#define	PIPE_ATSVC			"\\PIPE\\atsvc"
#define	PIPE_BROWSESS			"\\PIPE\\browsess"
#define	PIPE_WINSSVC			"\\PIPE\\winssvc"
#define	PIPE_WINSMGR			"\\PIPE\\winsmgr"
#define	PIPE_LLSRPC			"\\PIPE\\llsrpc"
#define	PIPE_REPL			"\\PIPE\\repl"

/*
 * Named pipe function codes (NTDDK cifs.h).
 */
#define	TRANS_SET_NMPIPE_STATE		0x01
#define	TRANS_RAW_READ_NMPIPE		0x11
#define	TRANS_QUERY_NMPIPE_STATE	0x21
#define	TRANS_QUERY_NMPIPE_INFO		0x22
#define	TRANS_PEEK_NMPIPE		0x23
#define	TRANS_TRANSACT_NMPIPE		0x26
#define	TRANS_RAW_WRITE_NMPIPE		0x31
#define	TRANS_READ_NMPIPE		0x36
#define	TRANS_WRITE_NMPIPE		0x37
#define	TRANS_WAIT_NMPIPE		0x53
#define	TRANS_CALL_NMPIPE		0x54

/*
 * SMB pipe handle state bits used by Query/SetNamedPipeHandleState.
 * These numbers are the bit locations of the fields in the handle state.
 */
#define	PIPE_COMPLETION_MODE_BITS	15
#define	PIPE_PIPE_END_BITS		14
#define	PIPE_PIPE_TYPE_BITS		10
#define	PIPE_READ_MODE_BITS		8
#define	PIPE_MAXIMUM_INSTANCES_BITS	0

/*
 * DosPeekNmPipe pipe states.
 */
#define	PIPE_STATE_DISCONNECTED		0x0001
#define	PIPE_STATE_LISTENING		0x0002
#define	PIPE_STATE_CONNECTED		0x0003
#define	PIPE_STATE_CLOSING		0x0004

/*
 * DosCreateNPipe and DosQueryNPHState state.
 */
#define	SMB_PIPE_READMODE_BYTE		0x0000
#define	SMB_PIPE_READMODE_MESSAGE	0x0100
#define	SMB_PIPE_TYPE_BYTE		0x0000
#define	SMB_PIPE_TYPE_MESSAGE		0x0400
#define	SMB_PIPE_END_CLIENT		0x0000
#define	SMB_PIPE_END_SERVER		0x4000
#define	SMB_PIPE_WAIT			0x0000
#define	SMB_PIPE_NOWAIT			0x8000
#define	SMB_PIPE_UNLIMITED_INSTANCES	0x00FF


#ifdef __cplusplus
}
#endif


#endif /* _SMBSRV_NMPIPES_H */
