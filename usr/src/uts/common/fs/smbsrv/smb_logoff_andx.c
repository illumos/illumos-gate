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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#include <smbsrv/smb_kproto.h>


/*
 * smb_com_logoff_andx
 *
 * This SMB is the inverse of SMB_COM_SESSION_SETUP_ANDX.
 *
 * Client Request                     Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 2
 * UCHAR AndXCommand;                 Secondary (X) command;  0xFF = none
 * UCHAR AndXReserved;                Reserved (must be 0)
 * USHORT AndXOffset;                 Offset to next command WordCount
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 * Server Response                    Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 2
 * UCHAR AndXCommand;                 Secondary (X) command;  0xFF = none
 * UCHAR AndXReserved;                Reserved (must be 0)
 * USHORT AndXOffset;                 Offset to next command WordCount
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 * The user represented by Uid in the SMB header is logged off.  The server
 * closes all files currently open by this user, and invalidates any
 * outstanding requests with this Uid.
 *
 * SMB_COM_SESSION_SETUP_ANDX is the only valid AndX command for this SMB.
 *
 * 4.1.3.1   Errors
 *
 * ERRSRV/invnid  - TID was invalid
 * ERRSRV/baduid  - UID was invalid
 */
smb_sdrc_t
smb_pre_logoff_andx(smb_request_t *sr)
{
	DTRACE_SMB_START(op__LogoffX, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_logoff_andx(smb_request_t *sr)
{
	DTRACE_SMB_DONE(op__LogoffX, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_logoff_andx(smb_request_t *sr)
{
	if (sr->uid_user == NULL) {
		smbsr_error(sr, 0, ERRSRV, ERRbaduid);
		return (SDRC_ERROR);
	}

	smb_user_logoff(sr->uid_user);

	if (smbsr_encode_result(sr, 2, 0, "bb.ww", 2, sr->andx_com, -1, 0))
		return (SDRC_ERROR);
	return (SDRC_SUCCESS);
}
