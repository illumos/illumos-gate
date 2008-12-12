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

#pragma ident	"@(#)smb_negotiate.c	1.6	08/07/21 SMI"

/*
 * Notes on the virtual circuit (VC) values in the SMB Negotiate
 * response and SessionSetupAndx request.
 *
 * A virtual circuit (VC) represents a connection between a client and a
 * server using a reliable, session oriented transport protocol, such as
 * NetBIOS or TCP/IP. Originally, each SMB session was restricted to a
 * single underlying transport connection, i.e. a single NetBIOS session,
 * which limited performance for raw data transfers.
 *
 * The intention behind multiple VCs was to improve performance by
 * allowing parallelism over each NetBIOS session. For example, raw data
 * could be transmitted using a different VC from other types of SMB
 * requests to remove the interleaving restriction while a raw transfer
 * is in progress. So the MaxNumberVcs field was added to the negotiate
 * response to make the number of VCs configurable and to allow servers
 * to specify how many they were prepared to support per session
 * connection. This turned out to be difficult to manage and, with
 * technology improvements, it has become obsolete.
 *
 * Servers should set the MaxNumberVcs value in the Negotiate response
 * to 1. Clients should probably ignore it. If a server receives a
 * SessionSetupAndx with a VC value of 0, it should close all other
 * VCs to that client. If it receives a non-zero VC, it should leave
 * other VCs in tact.
 *
 */

/*
 * SMB: negotiate
 *
 * Client Request                Description
 * ============================  =======================================
 *
 * UCHAR WordCount;              Count of parameter words = 0
 * USHORT ByteCount;             Count of data bytes; min = 2
 * struct {
 *    UCHAR BufferFormat;        0x02 -- Dialect
 *    UCHAR DialectName[];       ASCII null-terminated string
 * } Dialects[];
 *
 * The Client sends a list of dialects that it can communicate with.  The
 * response is a selection of one of those dialects (numbered 0 through n)
 * or -1 (hex FFFF) indicating that none of the dialects were acceptable.
 * The negotiate message is binding on the virtual circuit and must be
 * sent.  One and only one negotiate message may be sent, subsequent
 * negotiate requests will be rejected with an error response and no action
 * will be taken.
 *
 * The protocol does not impose any particular structure to the dialect
 * strings.  Implementors of particular protocols may choose to include,
 * for example, version numbers in the string.
 *
 * If the server does not understand any of the dialect strings, or if PC
 * NETWORK PROGRAM 1.0 is the chosen dialect, the response format is
 *
 * Server Response               Description
 * ============================  =======================================
 *
 * UCHAR WordCount;              Count of parameter words = 1
 * USHORT DialectIndex;          Index of selected dialect
 * USHORT ByteCount;             Count of data bytes = 0
 *
 * If the chosen dialect is greater than core up to and including
 * LANMAN2.1, the protocol response format is
 *
 * Server Response               Description
 * ============================  =======================================
 *
 * UCHAR WordCount;              Count of parameter words = 13
 * USHORT  DialectIndex;         Index of selected dialect
 * USHORT  SecurityMode;         Security mode:
 *                               bit 0: 0 = share, 1 = user
 *                               bit 1: 1 = use challenge/response
 *                               authentication
 * USHORT  MaxBufferSize;        Max transmit buffer size (>= 1024)
 * USHORT  MaxMpxCount;          Max pending multiplexed requests
 * USHORT  MaxNumberVcs;         Max VCs between client and server
 * USHORT  RawMode;              Raw modes supported:
 *                                bit 0: 1 = Read Raw supported
 *                                bit 1: 1 = Write Raw supported
 * ULONG SessionKey;             Unique token identifying this session
 * SMB_TIME ServerTime;          Current time at server
 * SMB_DATE ServerDate;          Current date at server
 * USHORT ServerTimeZone;        Current time zone at server
 * USHORT  EncryptionKeyLength;  MBZ if this is not LM2.1
 * USHORT  Reserved;             MBZ
 * USHORT  ByteCount             Count of data bytes
 * UCHAR EncryptionKey[];        The challenge encryption key
 * STRING PrimaryDomain[];       The server's primary domain
 *
 * MaxBufferSize is the size of the largest message which the client can
 * legitimately send to the server
 *
 * If  bit0 of the Flags field is set in the negotiate response, this
 * indicates the server supports the SMB_COM_LOCK_AND_READ and
 * SMB_COM_WRITE_AND_UNLOCK client requests.
 *
 * If the SecurityMode field indicates the server is running in user mode,
 * the client must send appropriate SMB_COM_SESSION_SETUP_ANDX requests
 * before the server will allow the client to access resources.   If the
 * SecurityMode fields indicates the client should use challenge/response
 * authentication, the client should use the authentication mechanism
 * specified in section 2.10.
 *
 * Clients should submit no more than MaxMpxCount distinct unanswered SMBs
 * to the server when using multiplexed reads or writes (see sections 5.13
 * and 5.25)
 *
 * Clients using the  "MICROSOFT NETWORKS 1.03" dialect use a different
 * form of raw reads than documented here, and servers are better off
 * setting RawMode in this response to 0 for such sessions.
 *
 * If the negotiated dialect is "DOS LANMAN2.1" or "LANMAN2.1", then
 * PrimaryDomain string should be included in this response.
 *
 * If the negotiated dialect is NT LM 0.12, the response format is
 *
 * Server Response            Description
 * ========================== =========================================
 *
 * UCHAR WordCount;           Count of parameter words = 17
 * USHORT DialectIndex;       Index of selected dialect
 * UCHAR SecurityMode;        Security mode:
 *                             bit 0: 0 = share, 1 = user
 *                             bit 1: 1 = encrypt passwords
 * USHORT MaxMpxCount;        Max pending multiplexed requests
 * USHORT MaxNumberVcs;       Max VCs between client and server
 * ULONG MaxBufferSize;       Max transmit buffer size
 * ULONG MaxRawSize;          Maximum raw buffer size
 * ULONG SessionKey;          Unique token identifying this session
 * ULONG Capabilities;        Server capabilities
 * ULONG SystemTimeLow;       System (UTC) time of the server (low).
 * ULONG SystemTimeHigh;      System (UTC) time of the server (high).
 * USHORT ServerTimeZone;     Time zone of server (min from UTC)
 * UCHAR EncryptionKeyLength; Length of encryption key.
 * USHORT ByteCount;          Count of data bytes
 * UCHAR EncryptionKey[];     The challenge encryption key
 * UCHAR OemDomainName[];     The name of the domain (in OEM chars)
 *
 * In addition to the definitions above, MaxBufferSize is the size of the
 * largest message which the client can legitimately send to the server.
 * If the client is using a connectionless protocol,  MaxBufferSize must be
 * set to the smaller of the server's internal buffer size and the amount
 * of data which can be placed in a response packet.
 *
 * MaxRawSize specifies the maximum message size the server can send or
 * receive for SMB_COM_WRITE_RAW or SMB_COM_READ_RAW.
 *
 * Connectionless clients must set Sid to 0 in the SMB request header.
 *
 * Capabilities allows the server to tell the client what it supports.
 * The bit definitions defined in cifs.h. Bit 0x2000 used to be set in
 * the negotiate response capabilities but it caused problems with
 * Windows 2000. It is probably not valid, it doesn't appear in the
 * CIFS spec.
 *
 * 4.1.1.1   Errors
 *
 * SUCCESS/SUCCESS
 * ERRSRV/ERRerror
 */
#include <sys/types.h>
#include <sys/strsubr.h>
#include <sys/socketvar.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <netinet/in.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_i18n.h>


/*
 * Maximum buffer size for DOS: chosen to be the same as NT.
 * Do not change this value, DOS is very sensitive to it.
 */
#define	SMB_DOS_MAXBUF			0x1104

/*
 * The DOS TCP rcvbuf is set to 8700 because DOS 6.1 seems to have problems
 * with other values. DOS 6.1 seems to depend on a window value of 8700 to
 * send the next set of data. If we return a window value of 40KB, after
 * sending 8700 bytes of data, it will start the next set of data from 40KB
 * instead of 8.7k. Why 8.7k? We have no idea; it is the value that NT uses.
 * September 2000.
 *
 * IR104720 Increased smb_nt_tcp_rcvbuf from 40KB to just under 1MB to allow
 * for a larger TCP window sizei based on observations of Windows 2000 and
 * performance testing. March 2003.
 */
static uint32_t	smb_dos_tcp_rcvbuf = 8700;
static uint32_t	smb_nt_tcp_rcvbuf = 1048560;	/* scale factor of 4 */

static void smb_get_security_info(smb_request_t *, unsigned short *,
    unsigned char *, unsigned char *, uint32_t *);

/*
 * Function: int smb_com_negotiate(struct smb_request *)
 */
smb_sdrc_t
smb_pre_negotiate(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Negotiate__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_negotiate(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Negotiate__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_negotiate(smb_request_t *sr)
{
	int			dialect = 0;
	int			this_dialect;
	unsigned char		keylen;
	int			sel_pos = -1;
	int			pos;
	char 			key[32];
	char			*p;
	timestruc_t		time_val;
	unsigned short		secmode;
	uint32_t		sesskey;
	uint32_t		capabilities = 0;
	int			rc;
	unsigned short		max_mpx_count;
	int16_t			tz_correction;
	char			ipaddr_buf[INET_ADDRSTRLEN];
	char			*tmpbuf;
	int			buflen;
	smb_msgbuf_t		mb;

	if (sr->session->s_state != SMB_SESSION_STATE_ESTABLISHED) {
		/* The protocol has already been negotiated. */
		smbsr_error(sr, 0, ERRSRV, ERRerror);
		return (SDRC_ERROR);
	}

	for (pos = 0;
	    sr->smb_data.chain_offset < sr->smb_data.max_bytes;
	    pos++) {
		if (smb_mbc_decodef(&sr->smb_data, "%L", sr, &p) != 0) {
			smbsr_error(sr, 0, ERRSRV, ERRerror);
			return (SDRC_ERROR);
		}

		this_dialect = smb_xlate_dialect_str_to_cd(p);

		if (this_dialect < 0)
			continue;

		if (dialect < this_dialect) {
			dialect = this_dialect;
			sel_pos = pos;
		}
	}

	smb_get_security_info(sr, &secmode, (unsigned char *)key,
	    &keylen, &sesskey);

	(void) microtime(&time_val);
	tz_correction = sr->sr_gmtoff / 60;

	switch (dialect) {
	case PC_NETWORK_PROGRAM_1_0:	/* core */
		(void) ksocket_setsockopt(sr->session->sock, SOL_SOCKET,
		    SO_RCVBUF, (const void *)&smb_dos_tcp_rcvbuf,
		    sizeof (smb_dos_tcp_rcvbuf), CRED());
		rc = smbsr_encode_result(sr, 1, 0, "bww", 1, sel_pos, 0);
		break;

	case Windows_for_Workgroups_3_1a:
	case PCLAN1_0:
	case MICROSOFT_NETWORKS_1_03:
	case MICROSOFT_NETWORKS_3_0:
	case LANMAN1_0:
	case LM1_2X002:
	case DOS_LM1_2X002:
		(void) ksocket_setsockopt(sr->session->sock, SOL_SOCKET,
		    SO_RCVBUF, (const void *)&smb_dos_tcp_rcvbuf,
		    sizeof (smb_dos_tcp_rcvbuf), CRED());
		sr->smb_flg |= SMB_FLAGS_LOCK_AND_READ_OK;
		rc = smbsr_encode_result(sr, 13, VAR_BCC,
		    "bwwwwwwlYww2.w#c",
		    13,		/* wct */
		    sel_pos,	/* dialect index */
		    secmode,		/* security mode */
		    SMB_DOS_MAXBUF,	/* max buffer size */
		    1,		/* max MPX (temporary) */
		    1,		/* max VCs (temporary, ambiguous) */
		    3,		/* raw mode (s/b 3) */
		    sesskey,	/* session key */
		    time_val.tv_sec, /* server time/date */
		    tz_correction,
		    (short)keylen,	/* Encryption Key Length */
				/* reserved field handled 2. */
		    VAR_BCC,
		    (int)keylen,
		    key);		/* encryption key */
		break;

	case DOS_LANMAN2_1:
	case LANMAN2_1:
		(void) ksocket_setsockopt(sr->session->sock, SOL_SOCKET,
		    SO_RCVBUF, (const void *)&smb_dos_tcp_rcvbuf,
		    sizeof (smb_dos_tcp_rcvbuf), CRED());
		sr->smb_flg |= SMB_FLAGS_LOCK_AND_READ_OK;
		rc = smbsr_encode_result(sr, 13, VAR_BCC,
		    "bwwwwwwlYww2.w#cs",
		    13,		/* wct */
		    sel_pos,	/* dialect index */
		    secmode,		/* security mode */
		    SMB_DOS_MAXBUF,	/* max buffer size */
		    1,		/* max MPX (temporary) */
		    1,		/* max VCs (temporary, ambiguous) */
		    3,		/* raw mode (s/b 3) */
		    sesskey,	/* session key */
		    time_val.tv_sec, /* server time/date */
		    tz_correction,
		    (short)keylen,	/* Encryption Key Length */
				/* reserved field handled 2. */
		    VAR_BCC,
		    (int)keylen,
		    key,		/* encryption key */
		    sr->sr_cfg->skc_nbdomain);
		break;

	case NT_LM_0_12:
		(void) ksocket_setsockopt(sr->session->sock, SOL_SOCKET,
		    SO_RCVBUF, (const void *)&smb_nt_tcp_rcvbuf,
		    sizeof (smb_nt_tcp_rcvbuf), CRED());
		capabilities = CAP_LARGE_FILES
		    | CAP_NT_SMBS
		    | CAP_STATUS32
		    | CAP_NT_FIND
		    | CAP_RAW_MODE
		    | CAP_LEVEL_II_OPLOCKS
		    | CAP_LOCK_AND_READ
		    | CAP_RPC_REMOTE_APIS
		    | CAP_LARGE_READX;

		/*
		 * UNICODE support is required to enable support for long
		 * share names and long file names and streams.
		 */

		capabilities |= CAP_UNICODE;


		/*
		 * Turn off Extended Security Negotiation
		 */
		sr->smb_flg2 &= ~SMB_FLAGS2_EXT_SEC;

		/*
		 * Allow SMB signatures if security challenge response enabled
		 */
		if ((secmode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE) &&
		    sr->sr_cfg->skc_signing_enable) {
			secmode |= NEGOTIATE_SECURITY_SIGNATURES_ENABLED;
			if (sr->sr_cfg->skc_signing_required)
				secmode |=
				    NEGOTIATE_SECURITY_SIGNATURES_REQUIRED;

			sr->session->secmode = secmode;
		}

		(void) inet_ntop(AF_INET, (char *)&sr->session->ipaddr,
		    ipaddr_buf, sizeof (ipaddr_buf));

		max_mpx_count = sr->sr_cfg->skc_maxworkers;

		/*
		 * skc_nbdomain is not expected to be aligned.
		 * Use temporary buffer to avoid alignment padding
		 */
		buflen = mts_wcequiv_strlen(sr->sr_cfg->skc_nbdomain) +
		    sizeof (mts_wchar_t);
		tmpbuf = kmem_zalloc(buflen, KM_SLEEP);
		smb_msgbuf_init(&mb, (uint8_t *)tmpbuf, buflen,
		    SMB_MSGBUF_UNICODE);
		if (smb_msgbuf_encode(&mb, "U",
		    sr->sr_cfg->skc_nbdomain) < 0) {
			smb_msgbuf_term(&mb);
			kmem_free(tmpbuf, buflen);
			smbsr_error(sr, 0, ERRSRV, ERRerror);
			return (SDRC_ERROR);
		}

		rc = smbsr_encode_result(sr, 17, VAR_BCC,
		    "bwbwwllllTwbw#c#c",
		    17,		/* wct */
		    sel_pos,	/* dialect index */
		    secmode,	/* security mode */
		    max_mpx_count,		/* max MPX (temporary) */
		    1,		/* max VCs (temporary, ambiguous) */
		    (DWORD)smb_maxbufsize,	/* max buffer size */
		    0xFFFF,	/* max raw size */
		    sesskey,	/* session key */
		    capabilities,
		    &time_val,	/* system time */
		    tz_correction,
		    keylen,	/* Encryption Key Length */
		    VAR_BCC,
		    (int)keylen,
		    key,	/* encryption key */
		    buflen,
		    tmpbuf);	/* skc_nbdomain */

		smb_msgbuf_term(&mb);
		kmem_free(tmpbuf, buflen);
		break;

	default:
		sel_pos = -1;
		rc = smbsr_encode_result(sr, 1, 0, "bww", 1, sel_pos, 0);
		return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
	}

	if (rc != 0)
		return (SDRC_ERROR);

	/*
	 * Save the agreed dialect. Note that this value is also
	 * used to detect and reject attempts to re-negotiate.
	 */
	sr->session->dialect = dialect;
	sr->session->s_state = SMB_SESSION_STATE_NEGOTIATED;
	return (SDRC_SUCCESS);
}

static void
smb_get_security_info(
    struct smb_request *sr,
    unsigned short *secmode,
    unsigned char *key,
    unsigned char *keylen,
    uint32_t *sesskey)
{
	uchar_t tmp_key[8];

	(void) random_get_pseudo_bytes(tmp_key, 8);
	bcopy(tmp_key, &sr->session->challenge_key, 8);
	sr->session->challenge_len = 8;
	*keylen = 8;
	bcopy(tmp_key, key, 8);

	sr->session->secmode = NEGOTIATE_SECURITY_CHALLENGE_RESPONSE|
	    NEGOTIATE_SECURITY_USER_LEVEL;

	(void) random_get_pseudo_bytes(tmp_key, 4);
	sr->session->sesskey = tmp_key[0] | tmp_key[1] << 8 |
	    tmp_key[2] << 16 | tmp_key[3] << 24;

	*secmode = sr->session->secmode;
	*sesskey = sr->session->sesskey;
}
