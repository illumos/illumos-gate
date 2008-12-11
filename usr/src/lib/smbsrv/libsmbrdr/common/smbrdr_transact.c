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
 * SMB transaction functions.
 */

#include <syslog.h>
#include <strings.h>

#include <smbsrv/libsmbrdr.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/smb.h>
#include <smbrdr.h>

/*
 * The pipe filename, length (including the null terminator)
 * and the buffer size for the transaction. Moving to unicode
 * revealed that the length should not include the null.
 */
#define	TX_FILENAME		"\\PIPE\\"
#define	TX_FILENAME_ASCII_LEN	6
#define	TX_FILENAME_WCHAR_LEN	14


static int prep_smb_transact(smb_msgbuf_t *, unsigned short, char *,
    unsigned short, unsigned short, unsigned);
static int decode_smb_transact(smb_msgbuf_t *, char *, unsigned,
    smb_transact_rsp_t *);

/*
 * smbrdr_transact
 *
 * Send a SMB_COM_TRANSACTION request.
 */
int
smbrdr_transact(int fid, char *out_buf, int out_len, char *in_buf, int in_len)
{
	struct sdb_session *session;
	struct sdb_netuse *netuse;
	struct sdb_ofile *ofile;
	struct sdb_logon *logon;
	smb_transact_rsp_t rsp;
	smbrdr_handle_t srh;
	smb_msgbuf_t *mb;
	DWORD status;
	int rc;
	unsigned short rcv_dcnt;
	int cur_inlen;
	int first_rsp;

	if ((ofile = smbrdr_ofile_get(fid)) == 0)
		return (-1);

	netuse = ofile->netuse;
	session = netuse->session;
	logon = &session->logon;

	status = smbrdr_request_init(&srh, SMB_COM_TRANSACTION,
	    session, logon, netuse);

	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_DEBUG, "smbrdr_transact: %s",
		    xlate_nt_status(status));
		smbrdr_ofile_put(ofile);
		return (-1);
	}

	mb = &srh.srh_mbuf;

	rc = prep_smb_transact(mb, ofile->fid, out_buf, out_len, in_len,
	    session->remote_caps & CAP_UNICODE);
	if (rc < 0) {
		syslog(LOG_DEBUG, "smbrdr_transact: prep failed");
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
		syslog(LOG_DEBUG, "smbrdr_transact: send failed");
		return (-1);
	}

	rcv_dcnt = 0;
	cur_inlen = in_len;
	first_rsp = 1;

	do {
		if (smbrdr_rcv(&srh, first_rsp) != NT_STATUS_SUCCESS) {
			syslog(LOG_DEBUG, "smbrdr_transact: nb_rcv failed");
			rc = -1;
			break;
		}

		rc = decode_smb_transact(mb, in_buf, cur_inlen, &rsp);
		if (rc < 0 || rsp.TotalDataCount > in_len) {
			syslog(LOG_DEBUG,
			    "smbrdr_transact: decode failed");
			rc = -1;
			break;
		}

		rcv_dcnt += rsp.DataCount;
		cur_inlen -= rsp.DataCount;
		first_rsp = 0;

	} while (rcv_dcnt < rsp.TotalDataCount);

	smbrdr_unlock_transport();
	smbrdr_handle_free(&srh);
	smbrdr_ofile_put(ofile);

	return ((rc < 0) ? rc : rcv_dcnt);
}


/*
 * prep_smb_transact
 *
 * Prepare the SMB_COM_TRANSACTION request.
 */
static int
prep_smb_transact(smb_msgbuf_t *mb, unsigned short fid, char *out,
    unsigned short out_len, unsigned short in_max, unsigned unicode)
{
	int data_off;
	int rc;
	unsigned short bcc;

	/*
	 * The byte count seems to include the pad
	 * byte to word align the filename and two
	 * spurious pad bytes between the filename
	 * and the transaction data.
	 */
	bcc = out_len + 3;
	bcc += (unicode) ? TX_FILENAME_WCHAR_LEN : TX_FILENAME_ASCII_LEN;

	data_off  = 32;		/* sizeof SMB header up to smb_wct */
	data_off += 1;		/* sizeof smb_wct */
	data_off += 16*2;	/* sizeof word parameters */
	data_off += 2;		/* sizeof smb_bcc */
	data_off += (unicode) ? TX_FILENAME_WCHAR_LEN : TX_FILENAME_ASCII_LEN;
	data_off += 3;
	/* this is where data starts */

	rc = smb_msgbuf_encode(mb,
	    "(wct)b"
	    "(tpscnt)w (tdscnt)w (mprcnt)w (mdrcnt)w (msrcnt)b"
	    "(rsvd). (flags)w (timeo)l  (rsvd1)2."
	    "(pscnt)w (psoff)w (dscnt)w (dsoff)w (suwcnt)b"
	    "(rsvd2). (pipop)w (fid)w (bcc)w (fname)u",
	    16,				/* smb_wct */
	    0,				/* total parm bytes */
	    out_len,			/* total data bytes */
	    0,				/* max parm bytes to ret */
	    in_max,			/* max data bytes to ret */
	    0,				/* max setup words to ret */
	    0,				/* transact flags */
	    0,				/* transact timeout */
	    0,				/* parameter bytes */
	    data_off,			/* parameter offset */
	    out_len,			/* data bytes */
	    data_off,			/* data offset */
	    2,				/* total setup words */
	    0x0026,			/* OP=TransactNmPipe */
	    fid,			/* FID */
	    bcc,			/* byte count */
	    TX_FILENAME);		/* file name */

	/*
	 * Transaction data - padded.
	 */
	rc = smb_msgbuf_encode(mb, "..#c", out_len, out);
	return (rc);
}


/*
 * decode_smb_transact
 *
 * Decode the response from the SMB_COM_TRANSACTION request.
 */
static int
decode_smb_transact(smb_msgbuf_t *mb, char *in, unsigned in_len,
    smb_transact_rsp_t *rsp)
{
	int rc;

	rc = smb_msgbuf_decode(mb, "b", &rsp->WordCount);
	if (rc <= 0 || rsp->WordCount < 10) {
		return (-1);
	}

	rc = smb_msgbuf_decode(mb,
	    "(tpscnt)w (tdscnt)w (rsvd)2."
	    "(pscnt)w (psoff)w (psdisp)w (dscnt)w (dsoff)w"
	    "(dsdisp)w (suwcnt)b (rsvd). (bcc)w",
	    &rsp->TotalParamCount,		/* Total parm bytes */
	    &rsp->TotalDataCount,		/* Total data bytes */
	    &rsp->ParamCount,			/* Parm bytes this buffer */
	    &rsp->ParamOffset,			/* Parm offset from hdr */
	    &rsp->ParamDisplacement,		/* Parm displacement */
	    &rsp->DataCount,			/* Data bytes this buffer */
	    &rsp->DataOffset,			/* Data offset from hdr */
	    &rsp->DataDisplacement,		/* Data displacement */
	    &rsp->SetupCount,			/* Setup word count */
	    &rsp->BCC);				/* smb_bcc */

	if (rc <= 0)
		return (-1);

	if (rsp->DataCount > in_len)
		return (-1);

	bcopy(mb->base + rsp->DataOffset,
	    in + rsp->DataDisplacement, rsp->DataCount);

	return (0);
}
