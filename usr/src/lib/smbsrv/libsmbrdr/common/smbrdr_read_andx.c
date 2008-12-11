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
 * SMB ReadX functions.
 */

#include <syslog.h>
#include <strings.h>

#include <smbsrv/libsmbrdr.h>
#include <smbsrv/netbios.h>
#include <smbsrv/ntstatus.h>
#include <smbrdr.h>

#define	SMBRDR_READX_RSP_OVERHEAD \
	(NETBIOS_HDR_SZ + SMB_HEADER_LEN + sizeof (smb_read_andx_rsp_t))
#define	SMBRDR_READX_RSP_DATA_MAXLEN \
	(SMBRDR_REQ_BUFSZ - SMBRDR_READX_RSP_OVERHEAD)

static int smbrdr_decode_readx_rsp(smb_msgbuf_t *, char *, unsigned,
    smb_read_andx_rsp_t *);

/*
 * smbrdr_readx
 *
 * Send SMB_COM_READ_ANDX request.
 */
int
smbrdr_readx(int fid, char *in_buf, int in_len)
{
	struct sdb_netuse *netuse;
	struct sdb_ofile *ofile;
	smb_read_andx_rsp_t rsp;
	smbrdr_handle_t srh;
	smb_msgbuf_t *mb;
	DWORD status;
	int rc, max_return;

	if ((ofile = smbrdr_ofile_get(fid)) == NULL)
		return (-1);

	netuse = ofile->netuse;

	status = smbrdr_request_init(&srh, SMB_COM_READ_ANDX,
	    netuse->session, &netuse->session->logon, netuse);

	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_DEBUG, "smbrdr_readx: %s", xlate_nt_status(status));
		smbrdr_ofile_put(ofile);
		return (-1);
	}

	mb = &(srh.srh_mbuf);

	max_return = (in_len > SMBRDR_READX_RSP_DATA_MAXLEN) ?
	    SMBRDR_READX_RSP_DATA_MAXLEN : in_len;

	rc = smb_msgbuf_encode(mb, "bbbwwlwwlwlw",
	    12,		/* Count of parameter words */
	    0xFF,	/* Secondary (X) command; 0xFF = none */
	    0,		/* Reserved (must be 0) */
	    0, 		/* Offset to next command WordCount */
	    ofile->fid,	/* File handle */
	    0,		/* Offset in file to begin read */
	    max_return,	/* Max number of bytes to return */
		/* Reserved for obsolescent requests [0 = non-blocking read] */
	    max_return,
		/*
		 * High 16 bits of MaxCount if CAP_LARGE_READX;
		 * else MUST BE ZERO
		 */
	    0,
	    max_return,	/* Reserved for obsolescent requests */
	    /* Upper 32 bits of offset (only if WordCount is 12) */
	    0,
	    0);		/* Count of data bytes = 0 */

	if (rc < 0) {
		syslog(LOG_DEBUG, "smbrdr_readx: prep failed");
		smbrdr_handle_free(&srh);
		smbrdr_ofile_put(ofile);
		return (rc);
	}

	smbrdr_lock_transport();

	status = smbrdr_send(&srh);
	if (status != NT_STATUS_SUCCESS) {
		smbrdr_unlock_transport();
		smbrdr_handle_free(&srh);
		smbrdr_ofile_put(ofile);
		syslog(LOG_DEBUG, "smbrdr_readx: send failed");
		return (-1);
	}

	status = smbrdr_rcv(&srh, 1);

	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_DEBUG, "smbrdr_readx: nb_rcv failed");
		smbrdr_unlock_transport();
		smbrdr_handle_free(&srh);
		smbrdr_ofile_put(ofile);
		return (-1);
	}

	rc = smbrdr_decode_readx_rsp(mb, in_buf, in_len, &rsp);

	if (rc < 0) {
		syslog(LOG_DEBUG, "smbrdr_readx: decode failed");
		smbrdr_unlock_transport();
		smbrdr_handle_free(&srh);
		smbrdr_ofile_put(ofile);
		return (-1);
	}

	smbrdr_unlock_transport();
	smbrdr_handle_free(&srh);
	smbrdr_ofile_put(ofile);

	return ((rc < 0) ? rc : rsp.DataLength);
}

/*
 * smbrdr_decode_readx_rsp
 *
 * Decode the response from the SMB_COM_READ_ANDX request. The payload
 * of the response is appended to the end of SmbTransact response data
 * in the RPC receive buffer.
 *
 * Return -1 on error, 0 upon success.
 */
static int
smbrdr_decode_readx_rsp(smb_msgbuf_t *mb,
			char *in,
			unsigned in_len,
			smb_read_andx_rsp_t *rsp)
{
	int rc;

	rc = smb_msgbuf_decode(mb, "bbbwwwwwwlwwww",
	    &rsp->WordCount,
	    &rsp->AndXCmd,
	    &rsp->AndXReserved,
	    &rsp->AndXOffset,
	    &rsp->Remaining,
	    &rsp->DataCompactionMode,
	    &rsp->Reserved,
	    &rsp->DataLength,
	    &rsp->DataOffset,
	    &rsp->DataLengthHigh,
	    &rsp->Reserved2[0],
	    &rsp->Reserved2[1],
	    &rsp->Reserved2[2],
	    &rsp->ByteCount);

	if (rc <= 0)
		return (-1);

	if (rsp->DataLength > in_len)
		return (-1);

	bcopy(mb->base + rsp->DataOffset, in, rsp->DataLength);

	return (0);
}
