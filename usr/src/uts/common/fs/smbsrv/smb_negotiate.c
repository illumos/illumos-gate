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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

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
 * The bit definitions defined in smb.h. Bit 0x2000 used to be set in
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smbinfo.h>

static const smb_xlate_t smb_dialect[] = {
	{ DIALECT_UNKNOWN,		"DIALECT_UNKNOWN" },
	{ PC_NETWORK_PROGRAM_1_0,	"PC NETWORK PROGRAM 1.0" },
	{ PCLAN1_0,			"PCLAN1.0" },
	{ MICROSOFT_NETWORKS_1_03,	"MICROSOFT NETWORKS 1.03" },
	{ MICROSOFT_NETWORKS_3_0,	"MICROSOFT NETWORKS 3.0" },
	{ LANMAN1_0,			"LANMAN1.0" },
	{ LM1_2X002,			"LM1.2X002" },
	{ DOS_LM1_2X002,		"DOS LM1.2X002" },
	{ DOS_LANMAN2_1,		"DOS LANMAN2.1" },
	{ LANMAN2_1,			"LANMAN2.1" },
	{ Windows_for_Workgroups_3_1a,	"Windows for Workgroups 3.1a" },
	{ NT_LM_0_12,			"NT LM 0.12" },
	{ DIALECT_SMB2002,		"SMB 2.002" },
	{ DIALECT_SMB2XXX,		"SMB 2.???" },
};
static int smb_ndialects = sizeof (smb_dialect) / sizeof (smb_dialect[0]);

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

/*
 * Maximum number of simultaneously pending SMB requests allowed on
 * one connection.  This is like "credits" in SMB2, but SMB1 uses a
 * fixed limit, having no way to request an increase like SMB2 does.
 * Note: Some older clients only handle the low byte of this value,
 * so this value should be less than 256.
 */
static uint16_t smb_maxmpxcount = 64;

static int smb_xlate_dialect(const char *);

/*
 * "Capabilities" offered by SMB1 Negotiate Protocol.
 * See smb.h for descriptions.
 *
 * CAP_RAW_MODE, CAP_MPX_MODE are obsolete.
 * UNICODE support is required for long share names,
 * long file names and streams.
 *
 * For testing, one can patch this, i.e. remove the high bit to
 * temporarily disable extended security, etc.
 */
uint32_t smb1srv_capabilities =
	CAP_UNICODE |
	CAP_LARGE_FILES |
	CAP_NT_SMBS |
	CAP_RPC_REMOTE_APIS |
	CAP_STATUS32 |
	CAP_LEVEL_II_OPLOCKS |
	CAP_LOCK_AND_READ |
	CAP_NT_FIND |
	CAP_DFS |
	CAP_INFOLEVEL_PASSTHRU |
	CAP_LARGE_READX |
	CAP_LARGE_WRITEX |
	CAP_EXTENDED_SECURITY;

/*
 * SMB Negotiate gets special handling.  This is called directly by
 * the reader thread (see smbsr_newrq_initial) with what _should_ be
 * an SMB1 Negotiate.  Only the "\ffSMB" header has been checked
 * when this is called, so this needs to check the SMB command,
 * if it's Negotiate execute it, then send the reply, etc.
 *
 * Since this is called directly from the reader thread, we
 * know this is the only thread currently using this session.
 * This has to duplicate some of what smb1sr_work does as a
 * result of bypassing the normal dispatch mechanism.
 *
 * The caller always frees this request.
 */
int
smb1_newrq_negotiate(smb_request_t *sr)
{
	smb_sdrc_t	sdrc;
	uint16_t	pid_hi, pid_lo;

	/*
	 * Decode the header
	 */
	if (smb_mbc_decodef(&sr->command, SMB_HEADER_ED_FMT,
	    &sr->smb_com,
	    &sr->smb_rcls,
	    &sr->smb_reh,
	    &sr->smb_err,
	    &sr->smb_flg,
	    &sr->smb_flg2,
	    &pid_hi,
	    sr->smb_sig,
	    &sr->smb_tid,
	    &pid_lo,
	    &sr->smb_uid,
	    &sr->smb_mid) != 0)
		return (-1);
	if (sr->smb_com != SMB_COM_NEGOTIATE)
		return (-1);

	sr->smb_pid = (pid_hi << 16) | pid_lo;

	/*
	 * Reserve space for the reply header.
	 */
	(void) smb_mbc_encodef(&sr->reply, "#.", SMB_HEADER_LEN);
	sr->first_smb_com = sr->smb_com;

	if (smb_mbc_decodef(&sr->command, "b", &sr->smb_wct) != 0)
		return (-1);
	(void) MBC_SHADOW_CHAIN(&sr->smb_vwv, &sr->command,
	    sr->command.chain_offset, sr->smb_wct * 2);

	if (smb_mbc_decodef(&sr->command, "#.w", sr->smb_wct*2, &sr->smb_bcc))
		return (-1);
	(void) MBC_SHADOW_CHAIN(&sr->smb_data, &sr->command,
	    sr->command.chain_offset, sr->smb_bcc);

	sr->command.chain_offset += sr->smb_bcc;
	if (sr->command.chain_offset > sr->command.max_bytes)
		return (-1);

	/* Store pointers for later */
	sr->cur_reply_offset = sr->reply.chain_offset;

	sdrc = smb_pre_negotiate(sr);
	if (sdrc == SDRC_SUCCESS)
		sdrc = smb_com_negotiate(sr);
	smb_post_negotiate(sr);

	if (sdrc != SDRC_NO_REPLY)
		smbsr_send_reply(sr);
	if (sdrc == SDRC_DROP_VC)
		return (-1);

	return (0);
}

smb_sdrc_t
smb_pre_negotiate(smb_request_t *sr)
{
	smb_kmod_cfg_t		*skc;
	smb_arg_negotiate_t	*negprot;
	int			dialect;
	int			pos;
	int			rc = 0;

	skc = &sr->session->s_cfg;
	negprot = smb_srm_zalloc(sr, sizeof (smb_arg_negotiate_t));
	negprot->ni_index = -1;
	sr->sr_negprot = negprot;

	for (pos = 0; smbsr_decode_data_avail(sr); pos++) {
		if (smbsr_decode_data(sr, "%L", sr, &negprot->ni_name) != 0) {
			smbsr_error(sr, 0, ERRSRV, ERRerror);
			rc = -1;
			break;
		}

		if ((dialect = smb_xlate_dialect(negprot->ni_name)) < 0)
			continue;

		/*
		 * Conditionally recognize the SMB2 dialects.
		 */
		if (dialect >= DIALECT_SMB2002 &&
		    skc->skc_max_protocol < SMB_VERS_2_BASE)
			continue;

		if (negprot->ni_dialect < dialect) {
			negprot->ni_dialect = dialect;
			negprot->ni_index = pos;
		}
	}

	DTRACE_SMB_2(op__Negotiate__start, smb_request_t *, sr,
	    smb_arg_negotiate_t, negprot);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_negotiate(smb_request_t *sr)
{
	smb_arg_negotiate_t	*negprot = sr->sr_negprot;

	DTRACE_SMB_2(op__Negotiate__done, smb_request_t *, sr,
	    smb_arg_negotiate_t, negprot);

	bzero(negprot, sizeof (smb_arg_negotiate_t));
}

smb_sdrc_t
smb_com_negotiate(smb_request_t *sr)
{
	smb_session_t 		*session = sr->session;
	smb_arg_negotiate_t	*negprot = sr->sr_negprot;
	uint16_t		secmode;
	uint32_t		sesskey;
	char			*nbdomain;
	uint8_t			*wcbuf;
	int			wclen;
	smb_msgbuf_t		mb;
	int			rc;

	if (session->s_state != SMB_SESSION_STATE_ESTABLISHED) {
		/* The protocol has already been negotiated. */
		smbsr_error(sr, 0, ERRSRV, ERRerror);
		return (SDRC_ERROR);
	}

	/*
	 * Special case for negotiating SMB2 from SMB1.  The client
	 * includes the  "SMB 2..." dialects in the SMB1 negotiate,
	 * and if SMB2 is enabled, we choose one of those and then
	 * send an SMB2 reply to that SMB1 request.  Yes, it's very
	 * strange, but this SMB1 request can have an SMB2 reply!
	 * To accomplish this, we let the SMB2 code send the reply
	 * and return the special code SDRC_NO_REPLY to the SMB1
	 * dispatch logic so it will NOT send an SMB1 reply.
	 * (Or possibly send an SMB1 error reply.)
	 */
	if (negprot->ni_dialect >= DIALECT_SMB2002) {
		rc = smb1_negotiate_smb2(sr);
		ASSERT(rc == SDRC_NO_REPLY ||
		    rc == SDRC_DROP_VC || rc == SDRC_ERROR);
		return (rc);
	}

	session->secmode = NEGOTIATE_ENCRYPT_PASSWORDS |
	    NEGOTIATE_USER_SECURITY;
	secmode = session->secmode;
	sesskey = session->sesskey;

	negprot->ni_servertime.tv_sec = gethrestime_sec();
	negprot->ni_servertime.tv_nsec = 0;
	negprot->ni_tzcorrection = sr->sr_gmtoff / 60;
	negprot->ni_maxmpxcount = smb_maxmpxcount;
	negprot->ni_keylen = SMB_CHALLENGE_SZ;
	bcopy(&session->challenge_key, negprot->ni_key, SMB_CHALLENGE_SZ);
	nbdomain = sr->sr_cfg->skc_nbdomain;

	negprot->ni_capabilities = smb1srv_capabilities;

	switch (negprot->ni_dialect) {
	case PC_NETWORK_PROGRAM_1_0:	/* core */
		(void) ksocket_setsockopt(session->sock, SOL_SOCKET,
		    SO_RCVBUF, (const void *)&smb_dos_tcp_rcvbuf,
		    sizeof (smb_dos_tcp_rcvbuf), CRED());
		rc = smbsr_encode_result(sr, 1, 0, "bww", 1,
		    negprot->ni_index, 0);
		break;

	case Windows_for_Workgroups_3_1a:
	case PCLAN1_0:
	case MICROSOFT_NETWORKS_1_03:
	case MICROSOFT_NETWORKS_3_0:
	case LANMAN1_0:
	case LM1_2X002:
	case DOS_LM1_2X002:
		(void) ksocket_setsockopt(session->sock, SOL_SOCKET,
		    SO_RCVBUF, (const void *)&smb_dos_tcp_rcvbuf,
		    sizeof (smb_dos_tcp_rcvbuf), CRED());
		sr->smb_flg |= SMB_FLAGS_LOCK_AND_READ_OK;
		rc = smbsr_encode_result(sr, 13, VAR_BCC,
		    "bwwwwwwlYww2.w#c",
		    13,				/* wct */
		    negprot->ni_index,		/* dialect index */
		    secmode,			/* security mode */
		    SMB_DOS_MAXBUF,		/* max buffer size */
		    1,				/* max MPX */
		    1,				/* max VCs */
		    0,				/* read/write raw */
		    sesskey,			/* session key */
		    negprot->ni_servertime.tv_sec, /* server date/time */
		    negprot->ni_tzcorrection,
		    (uint16_t)negprot->ni_keylen, /* encryption key length */
						/* reserved field handled 2. */
		    VAR_BCC,
		    (int)negprot->ni_keylen,
		    negprot->ni_key);		/* encryption key */
		break;

	case DOS_LANMAN2_1:
	case LANMAN2_1:
		(void) ksocket_setsockopt(session->sock, SOL_SOCKET,
		    SO_RCVBUF, (const void *)&smb_dos_tcp_rcvbuf,
		    sizeof (smb_dos_tcp_rcvbuf), CRED());
		sr->smb_flg |= SMB_FLAGS_LOCK_AND_READ_OK;
		rc = smbsr_encode_result(sr, 13, VAR_BCC,
		    "bwwwwwwlYww2.w#cs",
		    13,				/* wct */
		    negprot->ni_index,		/* dialect index */
		    secmode,			/* security mode */
		    SMB_DOS_MAXBUF,		/* max buffer size */
		    1,				/* max MPX */
		    1,				/* max VCs */
		    0,				/* read/write raw */
		    sesskey,			/* session key */
		    negprot->ni_servertime.tv_sec, /* server date/time */
		    negprot->ni_tzcorrection,
		    (uint16_t)negprot->ni_keylen, /* encryption key length */
						/* reserved field handled 2. */
		    VAR_BCC,
		    (int)negprot->ni_keylen,
		    negprot->ni_key,		/* encryption key */
		    nbdomain);
		break;

	case NT_LM_0_12:
		(void) ksocket_setsockopt(session->sock, SOL_SOCKET,
		    SO_RCVBUF, (const void *)&smb_nt_tcp_rcvbuf,
		    sizeof (smb_nt_tcp_rcvbuf), CRED());

		/*
		 * Allow SMB signatures if using encrypted passwords
		 */
		if ((secmode & NEGOTIATE_ENCRYPT_PASSWORDS) &&
		    sr->sr_cfg->skc_signing_enable) {
			secmode |= NEGOTIATE_SECURITY_SIGNATURES_ENABLED;
			if (sr->sr_cfg->skc_signing_required)
				secmode |=
				    NEGOTIATE_SECURITY_SIGNATURES_REQUIRED;

			session->secmode = secmode;
		}

		/*
		 * Does the client want Extended Security?
		 * (and if we have it enabled)
		 * If so, handle as if a different dialect.
		 */
		if ((sr->smb_flg2 & SMB_FLAGS2_EXT_SEC) != 0 &&
		    (negprot->ni_capabilities & CAP_EXTENDED_SECURITY) != 0)
			goto NT_LM_0_12_ext_sec;

		/* Else deny knowledge of extended security. */
		sr->smb_flg2 &= ~SMB_FLAGS2_EXT_SEC;
		negprot->ni_capabilities &= ~CAP_EXTENDED_SECURITY;

		/*
		 * nbdomain is not expected to be aligned.
		 * Use temporary buffer to avoid alignment padding
		 */
		wclen = smb_wcequiv_strlen(nbdomain) + sizeof (smb_wchar_t);
		wcbuf = smb_srm_zalloc(sr, wclen);
		smb_msgbuf_init(&mb, wcbuf, wclen, SMB_MSGBUF_UNICODE);
		if (smb_msgbuf_encode(&mb, "U", nbdomain) < 0) {
			smb_msgbuf_term(&mb);
			smbsr_error(sr, 0, ERRSRV, ERRerror);
			return (SDRC_ERROR);
		}

		rc = smbsr_encode_result(sr, 17, VAR_BCC,
		    "bwbwwllllTwbw#c#c",
		    17,				/* wct */
		    negprot->ni_index,		/* dialect index */
		    secmode,			/* security mode */
		    negprot->ni_maxmpxcount,	/* max MPX */
		    1,				/* max VCs */
		    (DWORD)smb_maxbufsize,	/* max buffer size */
		    0xFFFF,			/* max raw size */
		    sesskey,			/* session key */
		    negprot->ni_capabilities,
		    &negprot->ni_servertime,	/* system time */
		    negprot->ni_tzcorrection,
		    negprot->ni_keylen,		/* encryption key length */
		    VAR_BCC,
		    (int)negprot->ni_keylen,
		    negprot->ni_key,		/* encryption key */
		    wclen,
		    wcbuf);			/* nbdomain (unicode) */

		smb_msgbuf_term(&mb);
		break;

NT_LM_0_12_ext_sec:
		/*
		 * This is the "Extended Security" variant of
		 * dialect NT_LM_0_12.
		 */
		rc = smbsr_encode_result(sr, 17, VAR_BCC,
		    "bwbwwllllTwbw#c#c",
		    17,				/* wct */
		    negprot->ni_index,		/* dialect index */
		    secmode,			/* security mode */
		    negprot->ni_maxmpxcount,	/* max MPX */
		    1,				/* max VCs */
		    (DWORD)smb_maxbufsize,	/* max buffer size */
		    0xFFFF,			/* max raw size */
		    sesskey,			/* session key */
		    negprot->ni_capabilities,
		    &negprot->ni_servertime,	/* system time */
		    negprot->ni_tzcorrection,
		    0,		/* encryption key length (MBZ) */
		    VAR_BCC,
		    UUID_LEN,
		    sr->sr_cfg->skc_machine_uuid,
		    sr->sr_cfg->skc_negtok_len,
		    sr->sr_cfg->skc_negtok);
		break;


	default:
		rc = smbsr_encode_result(sr, 1, 0, "bww", 1, -1, 0);
		break;
	}

	if (rc != 0)
		return (SDRC_ERROR);

	/*
	 * Save the agreed dialect. Note that the state is also
	 * used to detect and reject attempts to re-negotiate.
	 */
	session->dialect = negprot->ni_dialect;
	session->s_state = SMB_SESSION_STATE_NEGOTIATED;

	/* Allow normal SMB1 requests now. */
	session->newrq_func = smb1sr_newrq;

	return (SDRC_SUCCESS);
}

static int
smb_xlate_dialect(const char *dialect)
{
	const smb_xlate_t *dp;
	int		i;

	for (i = 0; i < smb_ndialects; ++i) {
		dp = &smb_dialect[i];

		if (strcmp(dp->str, dialect) == 0)
			return (dp->code);
	}

	return (-1);
}
