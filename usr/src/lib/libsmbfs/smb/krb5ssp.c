/*
 * Copyright (c) 2000, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Kerberos V Security Support Provider
 *
 * Based on code previously in ctx.c (from Boris Popov?)
 * but then mostly rewritten at Sun.
 */

#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <netdb.h>
#include <libintl.h>
#include <xti.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/byteorder.h>
#include <sys/socket.h>
#include <sys/fcntl.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <netsmb/smb.h>
#include <netsmb/smb_lib.h>
#include <netsmb/mchain.h>

#include "private.h"
#include "charsets.h"
#include "spnego.h"
#include "derparse.h"
#include "ssp.h"

#include <kerberosv5/krb5.h>
#include <kerberosv5/com_err.h>
#include <gssapi/gssapi.h>
#include <gssapi/mechs/krb5/include/auth_con.h>

/* RFC 4121 checksum type ID. */
#define	CKSUM_TYPE_RFC4121	0x8003

/* RFC 1964 token ID codes */
#define	KRB_AP_REQ	1
#define	KRB_AP_REP	2
#define	KRB_ERROR	3

extern MECH_OID g_stcMechOIDList [];

typedef struct krb5ssp_state {
	/* Filled in by krb5ssp_init_client */
	krb5_context ss_krb5ctx;	/* krb5 context (ptr) */
	krb5_ccache ss_krb5cc;		/* credentials cache (ptr) */
	krb5_principal ss_krb5clp;	/* client principal (ptr) */
	/* Filled in by krb5ssp_get_tkt */
	krb5_auth_context ss_auth;	/* auth ctx. w/ server (ptr) */
} krb5ssp_state_t;


/*
 * adds a GSSAPI wrapper
 */
int
krb5ssp_tkt2gtok(uchar_t *tkt, ulong_t tktlen,
    uchar_t **gtokp, ulong_t *gtoklenp)
{
	ulong_t		len;
	ulong_t		bloblen = tktlen;
	uchar_t		krbapreq[2] = {	KRB_AP_REQ, 0 };
	uchar_t		*blob = NULL;		/* result */
	uchar_t		*b;

	bloblen += sizeof (krbapreq);
	bloblen += g_stcMechOIDList[spnego_mech_oid_Kerberos_V5].iLen;
	len = bloblen;
	bloblen = ASNDerCalcTokenLength(bloblen, bloblen);
	if ((blob = malloc(bloblen)) == NULL) {
		DPRINT("malloc");
		return (ENOMEM);
	}

	b = blob;
	b += ASNDerWriteToken(b, SPNEGO_NEGINIT_APP_CONSTRUCT, NULL, len);
	b += ASNDerWriteOID(b, spnego_mech_oid_Kerberos_V5);
	memcpy(b, krbapreq, sizeof (krbapreq));
	b += sizeof (krbapreq);

	assert(b + tktlen == blob + bloblen);
	memcpy(b, tkt, tktlen);
	*gtoklenp = bloblen;
	*gtokp = blob;
	return (0);
}

/*
 * See "Windows 2000 Kerberos Interoperability" paper by
 * Christopher Nebergall.  RC4 HMAC is the W2K default but
 * Samba support lagged (not due to Samba itself, but due to OS'
 * Kerberos implementations.)
 *
 * Only session enc type should matter, not ticket enc type,
 * per Sam Hartman on krbdev.
 *
 * Preauthentication failure topics in krb-protocol may help here...
 * try "John Brezak" and/or "Clifford Neuman" too.
 */
static krb5_enctype kenctypes[] = {
	ENCTYPE_ARCFOUR_HMAC,	/* defined in krb5.h */
	ENCTYPE_DES_CBC_MD5,
	ENCTYPE_DES_CBC_CRC,
	ENCTYPE_NULL
};

static const int rq_opts =
    AP_OPTS_USE_SUBKEY | AP_OPTS_MUTUAL_REQUIRED;

/*
 * Obtain a kerberos ticket for the host we're connecting to.
 * (This does the KRB_TGS exchange.)
 */
static int
krb5ssp_get_tkt(krb5ssp_state_t *ss, char *server,
	uchar_t **tktp, ulong_t *tktlenp)
{
	krb5_context	kctx = ss->ss_krb5ctx;
	krb5_ccache	kcc  = ss->ss_krb5cc;
	krb5_data	indata = {0};
	krb5_data	outdata = {0};
	krb5_error_code	kerr = 0;
	const char	*fn = NULL;
	uchar_t		*tkt;

	/* Should have these from krb5ssp_init_client. */
	if (kctx == NULL || kcc == NULL) {
		fn = "null kctx or kcc";
		kerr = EINVAL;
		goto out;
	}

	kerr = krb5_set_default_tgs_enctypes(kctx, kenctypes);
	if (kerr != 0) {
		fn = "krb5_set_default_tgs_enctypes";
		goto out;
	}

	/* Get ss_auth now so we can set req_chsumtype. */
	kerr = krb5_auth_con_init(kctx, &ss->ss_auth);
	if (kerr != 0) {
		fn = "krb5_auth_con_init";
		goto out;
	}
	/* Missing krb5_auth_con_set_req_cksumtype(), so inline. */
	ss->ss_auth->req_cksumtype = CKSUM_TYPE_RFC4121;

	/*
	 * Build an RFC 4121 "checksum" with NULL channel bindings,
	 * like make_gss_checksum().  Numbers here from the RFC.
	 */
	indata.length = 24;
	if ((indata.data = calloc(1, indata.length)) == NULL) {
		kerr = ENOMEM;
		fn = "malloc checksum";
		goto out;
	}
	indata.data[0] = 16; /* length of "Bnd" field. */
	indata.data[20] = GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG;
	/* Done building the "checksum". */

	kerr = krb5_mk_req(kctx, &ss->ss_auth, rq_opts, "cifs", server,
	    &indata, kcc, &outdata);
	if (kerr != 0) {
		fn = "krb5_mk_req";
		goto out;
	}
	if ((tkt = malloc(outdata.length)) == NULL) {
		kerr = ENOMEM;
		fn = "malloc signing key";
		goto out;
	}
	memcpy(tkt, outdata.data, outdata.length);
	*tktp = tkt;
	*tktlenp = outdata.length;
	kerr = 0;

out:
	if (kerr) {
		if (fn == NULL)
			fn = "?";
		DPRINT("%s err 0x%x: %s", fn, kerr, error_message(kerr));
		if (kerr <= 0 || kerr > ESTALE)
			kerr = EAUTH;
	}

	if (outdata.data)
		krb5_free_data_contents(kctx, &outdata);

	if (indata.data)
		free(indata.data);

	/* Free kctx in krb5ssp_destroy */
	return (kerr);
}


/*
 * Build an RFC 1964 KRB_AP_REQ message
 * The caller puts on the SPNEGO wrapper.
 */
int
krb5ssp_put_request(struct ssp_ctx *sp, struct mbdata *out_mb)
{
	int err;
	struct smb_ctx *ctx = sp->smb_ctx;
	krb5ssp_state_t *ss = sp->sp_private;
	uchar_t		*tkt = NULL;
	ulong_t		tktlen;
	uchar_t		*gtok = NULL;		/* gssapi token */
	ulong_t		gtoklen;		/* gssapi token length */
	char		*prin = ctx->ct_srvname;

	if ((err = krb5ssp_get_tkt(ss, prin, &tkt, &tktlen)) != 0)
		goto out;
	if ((err = krb5ssp_tkt2gtok(tkt, tktlen, &gtok, &gtoklen)) != 0)
		goto out;

	if ((err = mb_init_sz(out_mb, gtoklen)) != 0)
		goto out;
	if ((err = mb_put_mem(out_mb, gtok, gtoklen, MB_MSYSTEM)) != 0)
		goto out;

out:
	if (gtok)
		free(gtok);
	if (tkt)
		free(tkt);

	return (err);
}

/*
 * Unwrap a GSS-API encapsulated RFC 1964 reply message,
 * i.e. type KRB_AP_REP or KRB_ERROR.
 */
int
krb5ssp_get_reply(struct ssp_ctx *sp, struct mbdata *in_mb)
{
	krb5ssp_state_t *ss = sp->sp_private;
	mbuf_t *m = in_mb->mb_top;
	int err = EBADRPC;
	int dlen, rc;
	long actual_len, token_len;
	uchar_t *data;
	krb5_data ap = {0};
	krb5_ap_rep_enc_part *reply = NULL;

	/* cheating: this mbuf is contiguous */
	assert(m->m_data == in_mb->mb_pos);
	data = (uchar_t *)m->m_data;
	dlen = m->m_len;

	/*
	 * Peel off the GSS-API wrapper.  Looks like:
	 *   AppToken: 60 81 83
	 *  OID(KRB5): 06 09 2a 86 48 86 f7 12 01 02 02
	 * KRB_AP_REP: 02 00
	 */
	rc = ASNDerCheckToken(data, SPNEGO_NEGINIT_APP_CONSTRUCT,
	    0, dlen, &token_len, &actual_len);
	if (rc != SPNEGO_E_SUCCESS) {
		DPRINT("no AppToken? rc=0x%x", rc);
		goto out;
	}
	if (dlen < actual_len)
		goto out;
	data += actual_len;
	dlen -= actual_len;

	/* OID (KRB5) */
	rc = ASNDerCheckOID(data, spnego_mech_oid_Kerberos_V5,
	    dlen, &actual_len);
	if (rc != SPNEGO_E_SUCCESS) {
		DPRINT("no OID? rc=0x%x", rc);
		goto out;
	}
	if (dlen < actual_len)
		goto out;
	data += actual_len;
	dlen -= actual_len;

	/* KRB_AP_REP or KRB_ERROR */
	if (data[0] != KRB_AP_REP) {
		DPRINT("KRB5 type: %d", data[1]);
		goto out;
	}
	if (dlen < 2)
		goto out;
	data += 2;
	dlen -= 2;

	/*
	 * Now what's left should be a krb5 reply
	 * NB: ap is NOT allocated, so don't free it.
	 */
	ap.length = dlen;
	ap.data = (char *)data;
	rc = krb5_rd_rep(ss->ss_krb5ctx, ss->ss_auth, &ap, &reply);
	if (rc != 0) {
		DPRINT("krb5_rd_rep: err 0x%x (%s)",
		    rc, error_message(rc));
		err = EAUTH;
		goto out;
	}

	/*
	 * Have the decoded reply.  Save anything?
	 *
	 * NB: If this returns an error, we will get
	 * no more calls into this back-end module.
	 */
	err = 0;

out:
	if (reply != NULL)
		krb5_free_ap_rep_enc_part(ss->ss_krb5ctx, reply);
	if (err)
		DPRINT("ret %d", err);

	return (err);
}

/*
 * krb5ssp_final
 *
 * Called after successful authentication.
 * Setup the MAC key for signing.
 */
int
krb5ssp_final(struct ssp_ctx *sp)
{
	struct smb_ctx *ctx = sp->smb_ctx;
	krb5ssp_state_t *ss = sp->sp_private;
	krb5_keyblock	*ssn_key = NULL;
	int err;

	/*
	 * Save the session key, used for SMB signing
	 * and possibly other consumers (RPC).
	 */
	err = krb5_auth_con_getlocalsubkey(
	    ss->ss_krb5ctx, ss->ss_auth, &ssn_key);
	if (err != 0) {
		DPRINT("_getlocalsubkey, err=0x%x (%s)",
		    err, error_message(err));
		if (err <= 0 || err > ESTALE)
			err = EAUTH;
		goto out;
	}

	/* Sanity check the length */
	if (ssn_key->length > 1024) {
		DPRINT("session key too long");
		err = EAUTH;
		goto out;
	}

	/*
	 * Update/save the session key.
	 */
	if (ctx->ct_ssnkey_buf != NULL) {
		free(ctx->ct_ssnkey_buf);
		ctx->ct_ssnkey_buf = NULL;
	}
	ctx->ct_ssnkey_buf = malloc(ssn_key->length);
	if (ctx->ct_ssnkey_buf == NULL) {
		err = ENOMEM;
		goto out;
	}
	ctx->ct_ssnkey_len = ssn_key->length;
	memcpy(ctx->ct_ssnkey_buf, ssn_key->contents, ctx->ct_ssnkey_len);
	err = 0;

out:
	if (ssn_key != NULL)
		krb5_free_keyblock(ss->ss_krb5ctx, ssn_key);

	return (err);
}

/*
 * krb5ssp_next_token
 *
 * See ssp.c: ssp_ctx_next_token
 */
int
krb5ssp_next_token(struct ssp_ctx *sp, struct mbdata *in_mb,
	struct mbdata *out_mb)
{
	int err;

	/*
	 * Note: in_mb == NULL on the first call.
	 */
	if (in_mb) {
		err = krb5ssp_get_reply(sp, in_mb);
		if (err)
			goto out;
	}

	if (out_mb) {
		err = krb5ssp_put_request(sp, out_mb);
	} else
		err = krb5ssp_final(sp);

out:
	if (err)
		DPRINT("ret: %d", err);
	return (err);
}

/*
 * krb5ssp_ctx_destroy
 *
 * Destroy mechanism-specific data.
 */
void
krb5ssp_destroy(struct ssp_ctx *sp)
{
	krb5ssp_state_t *ss;
	krb5_context	kctx;

	ss = sp->sp_private;
	if (ss == NULL)
		return;
	sp->sp_private = NULL;

	if ((kctx = ss->ss_krb5ctx) != NULL) {
		/* from krb5ssp_get_tkt */
		if (ss->ss_auth)
			(void) krb5_auth_con_free(kctx, ss->ss_auth);
		/* from krb5ssp_init_client */
		if (ss->ss_krb5clp)
			krb5_free_principal(kctx, ss->ss_krb5clp);
		if (ss->ss_krb5cc)
			(void) krb5_cc_close(kctx, ss->ss_krb5cc);
		krb5_free_context(kctx);
	}

	free(ss);
}

/*
 * krb5ssp_init_clnt
 *
 * Initialize a new Kerberos SSP client context.
 *
 * The user must already have a TGT in their credential cache,
 * as shown by the "klist" command.
 */
int
krb5ssp_init_client(struct ssp_ctx *sp)
{
	krb5ssp_state_t *ss;
	krb5_error_code	kerr;
	krb5_context	kctx = NULL;
	krb5_ccache	kcc = NULL;
	krb5_principal	kprin = NULL;

	if ((sp->smb_ctx->ct_authflags & SMB_AT_KRB5) == 0) {
		DPRINT("KRB5 not in authflags");
		return (ENOTSUP);
	}

	ss = calloc(1, sizeof (*ss));
	if (ss == NULL)
		return (ENOMEM);

	sp->sp_nexttok = krb5ssp_next_token;
	sp->sp_destroy = krb5ssp_destroy;
	sp->sp_private = ss;

	kerr = krb5_init_context(&kctx);
	if (kerr) {
		DPRINT("krb5_init_context, kerr 0x%x", kerr);
		goto errout;
	}
	ss->ss_krb5ctx = kctx;

	/* non-default would instead use krb5_cc_resolve */
	kerr = krb5_cc_default(kctx, &kcc);
	if (kerr) {
		DPRINT("krb5_cc_default, kerr 0x%x", kerr);
		goto errout;
	}
	ss->ss_krb5cc = kcc;

	/*
	 * Get the client principal (ticket),
	 * or discover that we don't have one.
	 */
	kerr = krb5_cc_get_principal(kctx, kcc, &kprin);
	if (kerr) {
		DPRINT("krb5_cc_get_principal, kerr 0x%x", kerr);
		goto errout;
	}
	ss->ss_krb5clp = kprin;

	/* Success! */
	DPRINT("Ticket cache: %s:%s",
	    krb5_cc_get_type(kctx, kcc),
	    krb5_cc_get_name(kctx, kcc));
	return (0);

errout:
	krb5ssp_destroy(sp);
	return (ENOTSUP);
}
