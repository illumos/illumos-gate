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
 * SMB: tree_connect
 *
 * When a client connects to a server resource, an SMB_COM_TREE_CONNECT
 * message is generated to the server. This command is almost exactly like
 * SMB_COM_TREE_CONNECT_ANDX, except that no AndX command may follow; see
 * section 4.1.4.
 *
 * Client Request                     Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes;    min = 4
 * UCHAR BufferFormat1;               0x04
 * STRING Path[];                     Server name and share name
 * UCHAR BufferFormat2;               0x04
 * STRING Password[];                 Password
 * UCHAR BufferFormat3;               0x04
 * STRING Service[];                  Service name
 *
 * The CIFS server responds with:
 *
 * Server Response                  Description
 * ================================ =================================
 *
 * UCHAR WordCount;                 Count of parameter words = 2
 * USHORT MaxBufferSize;            Max size message the server handles
 * USHORT Tid;                      Tree ID
 * USHORT ByteCount;                Count of data bytes = 0
 *
 * If the negotiated dialect is MICROSOFT NETWORKS 1.03 or earlier,
 * MaxBufferSize in the response message indicates the maximum size message
 * that the server can handle.  The client should not generate messages,
 * nor expect to receive responses, larger than this.  This must be
 * constant for a given server.  For newer dialects, this field is ignored.
 *
 * Tid should be included in any future SMBs referencing this tree
 * connection.
 */

#include <smbsrv/smb_incl.h>

int
smb_com_tree_connect(struct smb_request *sr)
{
	/*
	 * I'm not sure it this should be "%A.sA"
	 * now that unicode is enabled.
	 */
	if (smbsr_decode_data(sr, "%AAA", sr, &sr->arg.tcon.path,
	    &sr->arg.tcon.password, &sr->arg.tcon.service) != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	sr->arg.tcon.flags = 0;

	/*
	 * If the negotiated dialect is MICROSOFT NETWORKS 1.03
	 * or earlier, MaxBufferSize in the response message
	 * indicates the maximum size message that the server can
	 * handle.  The client should not generate messages, nor
	 * expect to receive responses, larger than this.  This
	 * must be constant for a given server. For newer dialects,
	 * this field is ignored.
	 *
	 * The reason for this is that the maximum buffer size is
	 * established during the NEGOTIATE.
	 */

	(void) smbsr_connect_tree(sr);

	smbsr_encode_result(sr, 2, 0, "bwww",
	    2,				/* wct */
	    (WORD)smb_maxbufsize,	/* MaxBufferSize */
	    sr->smb_tid,		/* TID */
	    0);				/* bcc */

	return (SDRC_NORMAL_REPLY);
}
