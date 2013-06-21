/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * SPNEGO back-end for NTLMSSP.  See [MS-NLMP]
 */

#include <sys/types.h>
#include <sys/byteorder.h>
#include <strings.h>
#include "smbd.h"
#include "smbd_authsvc.h"
#include "netsmb/ntlmssp.h"
#include <assert.h>

/* A shorter alias for a crazy long name from [MS-NLMP] */
#define	NTLMSSP_NEGOTIATE_NTLM2 \
	NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY

/* Need this in a header somewhere */
#ifdef _LITTLE_ENDIAN
/* little-endian values on little-endian */
#define	htolel(x)	((uint32_t)(x))
#define	letohl(x)	((uint32_t)(x))
#else	/* (BYTE_ORDER == LITTLE_ENDIAN) */
/* little-endian values on big-endian (swap) */
#define	letohl(x) 	BSWAP_32(x)
#define	htolel(x) 	BSWAP_32(x)
#endif	/* (BYTE_ORDER == LITTLE_ENDIAN) */

typedef struct ntlmssp_backend {
	uint32_t expect_type;
	uint32_t clnt_flags;
	uint32_t srv_flags;
	char srv_challenge[8];
} ntlmssp_backend_t;

struct genhdr {
	char h_id[8];	/* "NTLMSSP" */
	uint32_t h_type;
};

struct sec_buf {
	uint16_t sb_length;
	uint16_t sb_maxlen;
	uint32_t sb_offset;
};

struct nego_hdr {
	char h_id[8];
	uint32_t h_type;
	uint32_t h_flags;
	/* workstation domain, name (place holders) */
	uint16_t ws_dom[4];
	uint16_t ws_name[4];
};

struct auth_hdr {
	char h_id[8];
	uint32_t h_type;
	struct sec_buf h_lm_resp;
	struct sec_buf h_nt_resp;
	struct sec_buf h_domain;
	struct sec_buf h_user;
	struct sec_buf h_wksta;
	struct sec_buf h_essn_key; /* encrypted session key */
	uint32_t h_flags;
	/* Version struct (optional) */
	/* MIC hash (optional) */
};

/* Allow turning these off for debugging, etc. */
int smbd_signing_enabled = 1;

int smbd_constant_challenge = 0;
static uint8_t constant_chal[8] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

static int smbd_ntlmssp_negotiate(authsvc_context_t *);
static int smbd_ntlmssp_authenticate(authsvc_context_t *);
static int encode_avpair_str(smb_msgbuf_t *, uint16_t, char *);
static int decode_secbuf_bin(smb_msgbuf_t *, struct sec_buf *, void **);
static int decode_secbuf_str(smb_msgbuf_t *, struct sec_buf *, char **);

/*
 * Initialize this context for NTLMSSP, if possible.
 */
int
smbd_ntlmssp_init(authsvc_context_t *ctx)
{
	ntlmssp_backend_t *be;

	be = malloc(sizeof (*be));
	if (be == 0)
		return (NT_STATUS_NO_MEMORY);
	bzero(be, sizeof (*be));
	be->expect_type = NTLMSSP_MSGTYPE_NEGOTIATE;
	ctx->ctx_backend = be;

	return (0);
}

void
smbd_ntlmssp_fini(authsvc_context_t *ctx)
{
	free(ctx->ctx_backend);
}

/*
 * Handle an auth message
 */
int
smbd_ntlmssp_work(authsvc_context_t *ctx)
{
	struct genhdr *ihdr = ctx->ctx_ibodybuf;
	ntlmssp_backend_t *be = ctx->ctx_backend;
	uint32_t mtype;
	int rc;

	if (ctx->ctx_ibodylen < sizeof (*ihdr))
		return (NT_STATUS_INVALID_PARAMETER);

	if (bcmp(ihdr->h_id, "NTLMSSP", 8))
		return (NT_STATUS_INVALID_PARAMETER);
	mtype = letohl(ihdr->h_type);
	if (mtype != be->expect_type)
		return (NT_STATUS_INVALID_PARAMETER);

	switch (mtype) {
	case NTLMSSP_MSGTYPE_NEGOTIATE:
		ctx->ctx_orawtype = LSA_MTYPE_ES_CONT;
		rc = smbd_ntlmssp_negotiate(ctx);
		break;
	case NTLMSSP_MSGTYPE_AUTHENTICATE:
		ctx->ctx_orawtype = LSA_MTYPE_ES_DONE;
		rc = smbd_ntlmssp_authenticate(ctx);
		break;

	default:
	case NTLMSSP_MSGTYPE_CHALLENGE:
		/* Sent by servers, not received. */
		rc = NT_STATUS_INVALID_PARAMETER;
		break;
	}

	return (rc);
}

#if (MAXHOSTNAMELEN < NETBIOS_NAME_SZ)
#error "MAXHOSTNAMELEN < NETBIOS_NAME_SZ"
#endif

/*
 * Handle an NTLMSSP_MSGTYPE_NEGOTIATE message, and reply
 * with an NTLMSSP_MSGTYPE_CHALLENGE message.
 * See: [MS-NLMP] 2.2.1.1, 3.2.5.1.1
 */
static int
smbd_ntlmssp_negotiate(authsvc_context_t *ctx)
{
	char tmp_name[MAXHOSTNAMELEN];
	ntlmssp_backend_t *be = ctx->ctx_backend;
	struct nego_hdr *ihdr = ctx->ctx_ibodybuf;
	smb_msgbuf_t mb;
	uint8_t *save_scan;
	int secmode;
	int mbflags;
	int rc;
	size_t var_start, var_end;
	uint16_t var_size;

	if (ctx->ctx_ibodylen < sizeof (*ihdr))
		return (NT_STATUS_INVALID_PARAMETER);
	be->clnt_flags = letohl(ihdr->h_flags);

	/*
	 * Looks like we can ignore ws_dom, ws_name.
	 * Otherwise would parse those here.
	 */

	secmode = smb_config_get_secmode();
	if (smbd_constant_challenge) {
		(void) memcpy(be->srv_challenge, constant_chal,
		    sizeof (be->srv_challenge));
	} else {
		randomize(be->srv_challenge, sizeof (be->srv_challenge));
	}

	/*
	 * Compute srv_flags
	 */
	be->srv_flags =
	    NTLMSSP_REQUEST_TARGET |
	    NTLMSSP_NEGOTIATE_NTLM |
	    NTLMSSP_NEGOTIATE_TARGET_INFO;
	be->srv_flags |= be->clnt_flags & (
	    NTLMSSP_NEGOTIATE_NTLM2 |
	    NTLMSSP_NEGOTIATE_128 |
	    NTLMSSP_NEGOTIATE_KEY_EXCH |
	    NTLMSSP_NEGOTIATE_56);

	if (smbd_signing_enabled) {
		be->srv_flags |= be->clnt_flags & (
		    NTLMSSP_NEGOTIATE_SIGN |
		    NTLMSSP_NEGOTIATE_SEAL |
		    NTLMSSP_NEGOTIATE_ALWAYS_SIGN);
	}

	if (be->clnt_flags & NTLMSSP_NEGOTIATE_UNICODE)
		be->srv_flags |= NTLMSSP_NEGOTIATE_UNICODE;
	else if (be->clnt_flags & NTLMSSP_NEGOTIATE_OEM)
		be->srv_flags |= NTLMSSP_NEGOTIATE_OEM;

	/* LM Key is mutually exclusive with NTLM2 */
	if ((be->srv_flags & NTLMSSP_NEGOTIATE_NTLM2) == 0 &&
	    (be->clnt_flags & NTLMSSP_NEGOTIATE_LM_KEY) != 0)
		be->srv_flags |= NTLMSSP_NEGOTIATE_LM_KEY;

	/* Get our "target name" */
	if (secmode == SMB_SECMODE_DOMAIN) {
		be->srv_flags |= NTLMSSP_TARGET_TYPE_DOMAIN;
		rc = smb_getdomainname(tmp_name, NETBIOS_NAME_SZ);
	} else {
		be->srv_flags |= NTLMSSP_TARGET_TYPE_SERVER;
		rc = smb_getnetbiosname(tmp_name, NETBIOS_NAME_SZ);
	}
	if (rc)
		goto errout;

	/*
	 * Build the NTLMSSP_MSGTYPE_CHALLENGE message.
	 */
	mbflags = SMB_MSGBUF_NOTERM;
	if (be->srv_flags & NTLMSSP_NEGOTIATE_UNICODE)
		mbflags |= SMB_MSGBUF_UNICODE;
	smb_msgbuf_init(&mb, ctx->ctx_obodybuf, ctx->ctx_obodylen, mbflags);

	/*
	 * Fixed size parts
	 */
	rc = smb_msgbuf_encode(
	    &mb, "8clwwll8cllwwl",	/* offset, name (fmt) */
	    "NTLMSSP",			/* 0: signature (8c) */
	    NTLMSSP_MSGTYPE_CHALLENGE,	/* 8: type	(l) */
	    0, 0, 0,	/* filled later:   12: target name (wwl) */
	    be->srv_flags,		/* 20: flags	(l) */
	    be->srv_challenge,		/* 24: 		(8c) */
	    0, 0,			/* 32: reserved (ll) */
	    0, 0, 0);	/* filled later:   40: target info (wwl) */
#define	TARGET_NAME_OFFSET	12
#define	TARGET_INFO_OFFSET	40
	if (rc < 0)
		goto errout;

	/*
	 * Variable length parts.
	 *
	 * Target name
	 */
	var_start = smb_msgbuf_used(&mb);
	rc = smb_msgbuf_encode(&mb, "u", tmp_name);
	var_end = smb_msgbuf_used(&mb);
	var_size = (uint16_t)(var_end - var_start);
	if (rc < 0)
		goto errout;

	/* overwrite target name offset+lengths */
	save_scan = mb.scan;
	mb.scan = mb.base + TARGET_NAME_OFFSET;
	(void) smb_msgbuf_encode(&mb, "wwl", var_size, var_size, var_start);
	mb.scan = save_scan;

	/*
	 * Target info (AvPairList)
	 *
	 * These AV pairs are like our name/value pairs, but have
	 * numeric identifiers instead of names.  There are many
	 * of these, but we put only the four expected by Windows:
	 *	NetBIOS computer name
	 *	NetBIOS domain name
	 *	DNS computer name
	 *	DNS domain name
	 * Note that "domain" above (even "DNS domain") refers to
	 * the AD domain of which we're a member, which may be
	 * _different_ from the configured DNS domain.
	 *
	 * Also note that in "workgroup" mode (not a domain member)
	 * all "domain" fields should be set to the same values as
	 * the "computer" fields ("bare" host name, not FQDN).
	 */
	var_start = smb_msgbuf_used(&mb);

	/* NetBIOS Computer Name */
	if (smb_getnetbiosname(tmp_name, NETBIOS_NAME_SZ))
		goto errout;
	if (encode_avpair_str(&mb, MsvAvNbComputerName, tmp_name) < 0)
		goto errout;

	if (secmode != SMB_SECMODE_DOMAIN) {
		/*
		 * Workgroup mode.  Set all to hostname.
		 * tmp_name = netbios hostname from above.
		 */
		if (encode_avpair_str(&mb, MsvAvNbDomainName, tmp_name) < 0)
			goto errout;
		/*
		 * Want the bare computer name here (not FQDN).
		 */
		if (smb_gethostname(tmp_name, MAXHOSTNAMELEN, SMB_CASE_LOWER))
			goto errout;
		if (encode_avpair_str(&mb, MsvAvDnsComputerName, tmp_name) < 0)
			goto errout;
		if (encode_avpair_str(&mb, MsvAvDnsDomainName, tmp_name) < 0)
			goto errout;
	} else {
		/*
		 * Domain mode.  Use real host and domain values.
		 */

		/* NetBIOS Domain Name */
		if (smb_getdomainname(tmp_name, NETBIOS_NAME_SZ))
			goto errout;
		if (encode_avpair_str(&mb, MsvAvNbDomainName, tmp_name) < 0)
			goto errout;

		/* DNS Computer Name */
		if (smb_getfqhostname(tmp_name, MAXHOSTNAMELEN))
			goto errout;
		if (encode_avpair_str(&mb, MsvAvDnsComputerName, tmp_name) < 0)
			goto errout;

		/* DNS Domain Name */
		if (smb_getfqdomainname(tmp_name, MAXHOSTNAMELEN))
			goto errout;
		if (encode_avpair_str(&mb, MsvAvDnsDomainName, tmp_name) < 0)
			goto errout;
	}

	/* End marker */
	if (smb_msgbuf_encode(&mb, "ww", MsvAvEOL, 0) < 0)
		goto errout;
	var_end = smb_msgbuf_used(&mb);
	var_size = (uint16_t)(var_end - var_start);

	/* overwrite target  offset+lengths */
	save_scan = mb.scan;
	mb.scan = mb.base + TARGET_INFO_OFFSET;
	(void) smb_msgbuf_encode(&mb, "wwl", var_size, var_size, var_start);
	mb.scan = save_scan;

	ctx->ctx_obodylen = smb_msgbuf_used(&mb);
	smb_msgbuf_term(&mb);

	be->expect_type = NTLMSSP_MSGTYPE_AUTHENTICATE;

	return (0);

errout:
	smb_msgbuf_term(&mb);
	return (NT_STATUS_INTERNAL_ERROR);
}

static int
encode_avpair_str(smb_msgbuf_t *mb, uint16_t AvId, char *name)
{
	int rc;
	uint16_t len;

	len = smb_wcequiv_strlen(name);
	rc = smb_msgbuf_encode(mb, "wwU", AvId, len, name);
	return (rc);
}

/*
 * Handle an NTLMSSP_MSGTYPE_AUTHENTICATE message.
 * See: [MS-NLMP] 2.2.1.3, 3.2.5.1.2
 */
static int
smbd_ntlmssp_authenticate(authsvc_context_t *ctx)
{
	struct auth_hdr hdr;
	smb_msgbuf_t mb;
	smb_logon_t	user_info;
	smb_token_t	*token = NULL;
	ntlmssp_backend_t *be = ctx->ctx_backend;
	void *lm_resp;
	void *nt_resp;
	char *domain;
	char *user;
	char *wksta;
	void *essn_key;	/* encrypted session key (optional) */
	int mbflags;
	uint_t status = NT_STATUS_INTERNAL_ERROR;
	char combined_challenge[SMBAUTH_CHAL_SZ];
	unsigned char kxkey[SMBAUTH_HASH_SZ];
	boolean_t ntlm_v1x = B_FALSE;

	bzero(&user_info, sizeof (user_info));

	/*
	 * Parse the NTLMSSP_MSGTYPE_AUTHENTICATE message.
	 */
	if (ctx->ctx_ibodylen < sizeof (hdr))
		return (NT_STATUS_INVALID_PARAMETER);
	mbflags = SMB_MSGBUF_NOTERM;
	if (be->srv_flags & NTLMSSP_NEGOTIATE_UNICODE)
		mbflags |= SMB_MSGBUF_UNICODE;
	smb_msgbuf_init(&mb, ctx->ctx_ibodybuf, ctx->ctx_ibodylen, mbflags);
	bzero(&hdr, sizeof (hdr));

	if (smb_msgbuf_decode(&mb, "12.") < 0)
		goto errout;
	if (decode_secbuf_bin(&mb, &hdr.h_lm_resp, &lm_resp) < 0)
		goto errout;
	if (decode_secbuf_bin(&mb, &hdr.h_nt_resp, &nt_resp) < 0)
		goto errout;
	if (decode_secbuf_str(&mb, &hdr.h_domain, &domain) < 0)
		goto errout;
	if (decode_secbuf_str(&mb, &hdr.h_user, &user) < 0)
		goto errout;
	if (decode_secbuf_str(&mb, &hdr.h_wksta, &wksta) < 0)
		goto errout;
	if (decode_secbuf_bin(&mb, &hdr.h_essn_key, &essn_key) < 0)
		goto errout;
	if (smb_msgbuf_decode(&mb, "l", &be->clnt_flags) < 0)
		goto errout;

	if (be->clnt_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
		if (hdr.h_essn_key.sb_length < 16 || essn_key == NULL)
			goto errout;
	}

	user_info.lg_level = NETR_NETWORK_LOGON;
	user_info.lg_flags = 0;

	user_info.lg_ntlm_flags = be->clnt_flags;
	user_info.lg_username = (user) ? user : "";
	user_info.lg_domain = (domain) ? domain : "";
	user_info.lg_workstation = (wksta) ? wksta : "";

	user_info.lg_clnt_ipaddr =
	    ctx->ctx_clinfo.lci_clnt_ipaddr;
	user_info.lg_local_port = 445;

	user_info.lg_challenge_key.len = SMBAUTH_CHAL_SZ;
	user_info.lg_challenge_key.val = (uint8_t *)be->srv_challenge;

	user_info.lg_nt_password.len = hdr.h_nt_resp.sb_length;
	user_info.lg_nt_password.val = nt_resp;

	user_info.lg_lm_password.len = hdr.h_lm_resp.sb_length;
	user_info.lg_lm_password.val = lm_resp;

	user_info.lg_native_os = ctx->ctx_clinfo.lci_native_os;
	user_info.lg_native_lm = ctx->ctx_clinfo.lci_native_lm;

	/*
	 * If we're doing extended session security, the challenge
	 * this OWF was computed with is different. [MS-NLMP 3.3.1]
	 * It's: MD5(concat(ServerChallenge,ClientChallenge))
	 * where the ClientChallenge is in the LM resp. field.
	 */
	if (user_info.lg_nt_password.len == SMBAUTH_LM_RESP_SZ &&
	    user_info.lg_lm_password.len >= SMBAUTH_CHAL_SZ &&
	    (be->clnt_flags & NTLMSSP_NEGOTIATE_NTLM2) != 0) {
		smb_auth_ntlm2_mkchallenge(combined_challenge,
		    be->srv_challenge, lm_resp);
		user_info.lg_challenge_key.val =
		    (uint8_t *)combined_challenge;
		user_info.lg_lm_password.len = 0;
		ntlm_v1x = B_TRUE;
	}

	/*
	 * This (indirectly) calls smb_auth_validate() to
	 * check that the client gave us a valid hash.
	 */
	token = smbd_user_auth_logon(&user_info);
	if (token == NULL) {
		status = NT_STATUS_ACCESS_DENIED;
		goto errout;
	}

	if (token->tkn_ssnkey.val != NULL &&
	    token->tkn_ssnkey.len == SMBAUTH_HASH_SZ) {

		/*
		 * At this point, token->tkn_session_key is the
		 * "Session Base Key" [MS-NLMP] 3.2.5.1.2
		 * Compute the final session key.  First need the
		 * "Key Exchange Key" [MS-NLMP] 3.4.5.1
		 */
		if (ntlm_v1x) {
			smb_auth_ntlm2_kxkey(kxkey,
			    be->srv_challenge, lm_resp,
			    token->tkn_ssnkey.val);
		} else {
			/* KXKEY is the Session Base Key. */
			(void) memcpy(kxkey, token->tkn_ssnkey.val,
			    SMBAUTH_HASH_SZ);
		}

		/*
		 * If the client give us an encrypted session key,
		 * decrypt it (RC4) using the "key exchange key".
		 */
		if (be->clnt_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
			/* RC4 args: result, key, data */
			(void) smb_auth_RC4(token->tkn_ssnkey.val,
			    SMBAUTH_HASH_SZ, kxkey, SMBAUTH_HASH_SZ,
			    essn_key, hdr.h_essn_key.sb_length);
		} else {
			/* Final key is the KXKEY */
			(void) memcpy(token->tkn_ssnkey.val, kxkey,
			    SMBAUTH_HASH_SZ);
		}
	}

	ctx->ctx_token = token;
	ctx->ctx_obodylen = 0;

	smb_msgbuf_term(&mb);
	return (0);

errout:
	smb_msgbuf_term(&mb);
	return (status);
}

static int
decode_secbuf_bin(smb_msgbuf_t *mb, struct sec_buf *sb, void **binp)
{
	int rc;

	*binp = NULL;
	rc = smb_msgbuf_decode(
	    mb, "wwl",
	    &sb->sb_length,
	    &sb->sb_maxlen,
	    &sb->sb_offset);
	if (rc < 0)
		return (rc);

	if (sb->sb_offset > mb->max)
		return (SMB_MSGBUF_UNDERFLOW);
	if (sb->sb_length > (mb->max - sb->sb_offset))
		return (SMB_MSGBUF_UNDERFLOW);
	if (sb->sb_length == 0)
		return (rc);

	*binp = mb->base + sb->sb_offset;
	return (0);
}

static int
decode_secbuf_str(smb_msgbuf_t *mb, struct sec_buf *sb, char **cpp)
{
	uint8_t *save_scan;
	int rc;

	*cpp = NULL;
	rc = smb_msgbuf_decode(
	    mb, "wwl",
	    &sb->sb_length,
	    &sb->sb_maxlen,
	    &sb->sb_offset);
	if (rc < 0)
		return (rc);

	if (sb->sb_offset > mb->max)
		return (SMB_MSGBUF_UNDERFLOW);
	if (sb->sb_length > (mb->max - sb->sb_offset))
		return (SMB_MSGBUF_UNDERFLOW);
	if (sb->sb_length == 0)
		return (rc);

	save_scan = mb->scan;
	mb->scan = mb->base + sb->sb_offset;
	rc = smb_msgbuf_decode(mb, "#u", (int)sb->sb_length, cpp);
	mb->scan = save_scan;

	return (rc);
}
