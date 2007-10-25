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
 *  Client Request                     Description
 *  ================================== =================================
 *
 *  BYTE   smb_cmd;                    FIND_NOTIFY_CLOSE
 *  BYTE   smb_wct;                    value = 1
 *  WORD   smb_handle;                 Find notify handle
 *  WORD   smb_bcc;                    value = 0
 *
 *
 *  Server Response                    Description
 *  ================================== =================================
 *
 *  BYTE   smb_cmd;                    FIND_NOTIFY_CLOSE
 *  BYTE   smb_wct;                    value = 0
 *  WORD   smb_bcc;                    value = 0
 *
 * The FIND_NOTIFY_CLOSE request closes the association between a
 * directory handle returned following a resource monitor, established
 * using a TRANS2_FIND_NOTIFY_FIRST request to the server, and the
 * resulting system directory monitor. This request allows the server
 * to free any resources held in support of the open handle.
 *
 * The Find Close protocol is used to match the DosFindNotifyClose
 * OS/2 system call.
 *
 * Find Notify Close may generate the following errors.
 *
 *	ERRDOS/ERRbadfid
 *	ERRDOS/<implementation specific>
 *	ERRSRV/ERRerror
 *	ERRSRV/ERRinvnid
 *	ERRSRV/<implementation specific>
 *	ERRHRD/<implementation specific>
 */


#include <smbsrv/smb_incl.h>


/*
 * smb_com_find_notify_close
 *
 * As far as I can tell, this part of the protocol is not implemented
 * by NT server.
 */
int /*ARGSUSED*/
smb_com_find_notify_close(struct smb_request *sr)
{
	return (SDRC_UNIMPLEMENTED);
}
