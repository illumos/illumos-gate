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
 * This module provides the SMB ForwardUserName interface:
 *	smb_com_forward_user_name
 *	smb_com_cancel_forward
 *	smb_com_get_machine_name
 *
 * The description of this interface is taken verbatim from the netmon
 * SMB protocol help. These functions are currently empty stubs that
 * return SDRC_UNIMPLEMENTED.
 */


#include <smbsrv/smb_incl.h>


/*
 * smb_com_forward_user_name
 *
 * This command informs the server that it should accept messages sent
 * to the forwarded name. The name specified in this message does not
 * include the one byte suffix ("03" or "05").
 *
 *  Client Request                     Description
 *  ================================== =================================
 *  BYTE smb_com                       SMBfwdname
 *  BYTE smb_wct                       0
 *  BYTE smb_bcc                       min = 2
 *  BYTE smb_buf[]                     ASCII -- 04
 *                                     forwarded name (max 15 bytes)
 *
 *  Server Response                    Description
 *  ================================== =================================
 *  BYTE smb_com                       SMBfwdname
 *  BYTE smb_wct                       0
 *  BYTE smb_bcc                       0
 *
 * ForwardUserName may generate the following errors.
 *	ERRDOS/<implementation specific>
 *	ERRSRV/ERRerror
 *	ERRSRV/ERRinvnid
 *	ERRSRV/ERRrmuns
 *	ERRSRV/<implementation specific>
 *	ERRHRD/<implementation specific>
 */
int /*ARGSUSED*/
smb_com_forward_user_name(struct smb_request *sr)
{
	return (SDRC_UNIMPLEMENTED);
}


/*
 * smb_com_cancel_forward
 *
 * The CancelForward command cancels the effect of a prior ForwardUserName
 * command. The addressed server will no longer accept messages for the
 * designated user name. The name specified in this message does not
 * include the one byte suffix ("05").
 *
 *  Client Request                     Description
 *  ================================== =================================
 *  BYTE smb_com                       SMBcancelf
 *  BYTE smb_wct                       0
 *  BYTE smb_bcc                       min = 2
 *  BYTE smb_buf[]                     ASCII -- 04
 *                                     forwarded name (max 15 bytes)
 *
 *  Server Response                    Description
 *  ================================== =================================
 *  BYTE smb_com                       SMBcancelf
 *  BYTE smb_wct                       0
 *  BYTE smb_bcc                       0
 *
 * CancelForward may generate the following errors.
 * 	ERRDOS/<implementation specific>
 *	ERRSRV/ERRerror
 *	ERRSRV/ERRinvnid
 *	ERRSRV/<implementation specific>
 *	ERRHRD/<implementation specific>
 */
int /*ARGSUSED*/
smb_com_cancel_forward(struct smb_request *sr)
{
	return (SDRC_UNIMPLEMENTED);
}


/*
 * smb_com_get_machine_name
 *
 * The GetMachineName command obtains the machine name of the target machine.
 * It is used prior to the CancelForward command to determine to which
 * machine the CancelForward command should be sent. GetMachineName is sent
 * to the forwarded name to be canceled, and the server then returns the
 * machine name to which the CancelForward command must be sent.
 *
 *  Client Request                     Description
 *  ================================== =================================
 *  BYTE smb_com                       SMBgetmac
 *  BYTE smb_wct                       0
 *  BYTE smb_bcc                       0
 *
 *  Server Response                    Description
 *  ================================== =================================
 *  BYTE smb_com                       SMBgetmac
 *  BYTE smb_wct                       0
 *  BYTE smb_bcc                       min = 2
 *  BYTE smb_buf[]                     ASCII -- 04
 *                                     machine name (max 15 bytes)
 *
 * GetMachineName may return the following errors.
 *	ERRRDOS/<implementation specific>
 *	ERRSRV/ERRerror
 *	ERRSRV/ERRinvnid
 *	ERRSRV/<implementation specific>
 */
int /*ARGSUSED*/
smb_com_get_machine_name(struct smb_request *sr)
{
	return (SDRC_UNIMPLEMENTED);
}
