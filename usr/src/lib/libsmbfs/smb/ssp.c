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
 */

/*
 * Security Provider glue
 *
 * Modeled after SSPI for now, only because we're currently
 * using the Microsoft sample spnego code.
 *
 * ToDo: Port all of this to GSS-API plugins.
 */

#include <errno.h>
#include <stdio.h>
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

#include <netsmb/smb_lib.h>
#include <netsmb/mchain.h>

#include "private.h"
#include "charsets.h"
#include "spnego.h"
#include "derparse.h"
#include "ssp.h"


/*
 * ssp_ctx_create_client
 *
 * This is the first function called for SMB "extended security".
 * Here we select a security support provider (SSP), or mechanism,
 * and build the security context used throughout authentication.
 *
 * Note that we receive a "hint" in the SMB Negotiate response
 * that contains the list of mechanisms supported by the server.
 * We use this to help us select a mechanism.
 *
 * With SSPI this would call:
 *	ssp->InitSecurityInterface()
 *	ssp->AcquireCredentialsHandle()
 *	ssp->InitializeSecurityContext()
 * With GSS-API this will become:
 *	gss_import_name(... service_principal_name)
 *	gss_init_sec_context(), etc.
 */
int
ssp_ctx_create_client(struct smb_ctx *ctx, struct mbdata *hint_mb)
{
	struct ssp_ctx *sp;
	mbuf_t *m;
	SPNEGO_MECH_OID oid;
	int indx, rc;
	int err = ENOTSUP; /* in case nothing matches */

	sp = malloc(sizeof (*sp));
	if (sp == NULL)
		return (ENOMEM);
	bzero(sp, sizeof (*sp));
	ctx->ct_ssp_ctx = sp;
	sp->smb_ctx = ctx;

	/*
	 * Parse the SPNEGO "hint" to get the server's list of
	 * supported mechanisms.  If the "hint" is empty,
	 * assume NTLMSSP.  (Or could use "raw NTLMSSP")
	 */
	m = hint_mb->mb_top;
	if (m == NULL)
		goto use_ntlm;
	rc = spnegoInitFromBinary((uchar_t *)m->m_data, m->m_len,
	    &sp->sp_hint);
	if (rc) {
		DPRINT("parse hint, rc %d", rc);
		goto use_ntlm;
	}

	/*
	 * Did the server offer Kerberos?
	 * Either spec. OID or legacy is OK,
	 * but have to remember what we got.
	 */
	oid = spnego_mech_oid_NotUsed;
	if (0 == spnegoIsMechTypeAvailable(sp->sp_hint,
	    spnego_mech_oid_Kerberos_V5, &indx))
		oid = spnego_mech_oid_Kerberos_V5;
	else if (0 == spnegoIsMechTypeAvailable(sp->sp_hint,
	    spnego_mech_oid_Kerberos_V5_Legacy, &indx))
		oid = spnego_mech_oid_Kerberos_V5_Legacy;
	if (oid != spnego_mech_oid_NotUsed) {
		/*
		 * Yes! Server offers Kerberos.
		 * Try to init our krb5 mechanism.
		 * It will fail if the calling user
		 * does not have krb5 credentials.
		 */
		sp->sp_mech = oid;
		err = krb5ssp_init_client(sp);
		if (err == 0) {
			DPRINT("using Kerberos");
			return (0);
		}
		/* else fall back to NTLMSSP */
	}

	/*
	 * Did the server offer NTLMSSP?
	 */
	if (0 == spnegoIsMechTypeAvailable(sp->sp_hint,
	    spnego_mech_oid_NTLMSSP, &indx)) {
		/*
		 * OK, we'll use NTLMSSP
		 */
	use_ntlm:
		sp->sp_mech = spnego_mech_oid_NTLMSSP;
		err = ntlmssp_init_client(sp);
		if (err == 0) {
			DPRINT("using NTLMSSP");
			return (0);
		}
	}

	/* No supported mechanisms! */
	return (err);
}


/*
 * ssp_ctx_destroy
 *
 * Dispatch to the mechanism-specific destroy.
 */
void
ssp_ctx_destroy(struct smb_ctx *ctx)
{
	ssp_ctx_t *sp;

	sp = ctx->ct_ssp_ctx;
	ctx->ct_ssp_ctx = NULL;

	if (sp == NULL)
		return;

	if (sp->sp_destroy != NULL)
		(sp->sp_destroy)(sp);

	if (sp->sp_hint != NULL)
		spnegoFreeData(sp->sp_hint);

	free(sp);
}


/*
 * ssp_ctx_next_token
 *
 * This is the function called to generate the next token to send,
 * given a token just received, using the selected back-end method.
 * The back-end method is called a security service provider (SSP).
 *
 * This is also called to generate the first token to send
 * (when called with caller_in == NULL) and to handle the last
 * token received (when called with caller_out == NULL).
 * See caller: smb_ssnsetup_spnego
 *
 * Note that if the back-end SSP "next token" function ever
 * returns an error, the conversation ends, and there are
 * no further calls to this function for this context.
 *
 * General outline of this funcion:
 *	if (caller_in)
 *		Unwrap caller_in spnego blob,
 *		store payload in body_in
 *	Call back-end SSP "next token" method (body_in, body_out)
 *	if (caller_out)
 *		Wrap returned body_out in spnego,
 *		store in caller_out
 *
 * With SSPI this would call:
 *	ssp->InitializeSecurityContext()
 * With GSS-API this will become:
 *	gss_init_sec_context()
 */
int
ssp_ctx_next_token(struct smb_ctx *ctx,
	struct mbdata *caller_in,
	struct mbdata *caller_out)
{
	struct mbdata body_in, body_out;
	SPNEGO_TOKEN_HANDLE stok_in, stok_out;
	SPNEGO_NEGRESULT result;
	ssp_ctx_t *sp;
	struct mbuf *m;
	ulong_t toklen;
	int err, rc;

	bzero(&body_in, sizeof (body_in));
	bzero(&body_out, sizeof (body_out));
	stok_out = stok_in = NULL;
	sp = ctx->ct_ssp_ctx;

	/*
	 * If we have an spnego input token, parse it,
	 * extract the payload for the back-end SSP.
	 */
	if (caller_in != NULL) {

		/*
		 * Let the spnego code parse it.
		 */
		m = caller_in->mb_top;
		rc = spnegoInitFromBinary((uchar_t *)m->m_data,
		    m->m_len, &stok_in);
		if (rc) {
			DPRINT("parse reply, rc %d", rc);
			err = EBADRPC;
			goto out;
		}
		/* Note: Allocated stok_in  */

		/*
		 * Now get the payload.  Two calls:
		 * first gets the size, 2nd the data.
		 *
		 * Expect SPNEGO_E_BUFFER_TOO_SMALL here,
		 * but if the payload is missing, we'll
		 * get SPNEGO_E_ELEMENT_UNAVAILABLE.
		 */
		rc = spnegoGetMechToken(stok_in, NULL, &toklen);
		switch (rc) {
		case SPNEGO_E_ELEMENT_UNAVAILABLE:
			toklen = 0;
			break;
		case SPNEGO_E_BUFFER_TOO_SMALL:
			/* have toklen */
			break;
		default:
			DPRINT("GetMechTok1, rc %d", rc);
			err = EBADRPC;
			goto out;
		}
		err = mb_init(&body_in, (size_t)toklen);
		if (err)
			goto out;
		m = body_in.mb_top;
		if (toklen > 0) {
			rc = spnegoGetMechToken(stok_in,
			    (uchar_t *)m->m_data, &toklen);
			if (rc) {
				DPRINT("GetMechTok2, rc %d", rc);
				err = EBADRPC;
				goto out;
			}
			body_in.mb_count = m->m_len = (size_t)toklen;
		}
	}

	/*
	 * Call the back-end security provider (SSP) to
	 * handle the received token (if present) and
	 * generate an output token (if requested).
	 */
	err = sp->sp_nexttok(sp,
	    caller_in ? &body_in : NULL,
	    caller_out ? &body_out : NULL);
	if (err)
		goto out;

	/*
	 * Wrap the outgoing body if requested,
	 * either negTokenInit on first call, or
	 * negTokenTarg on subsequent calls.
	 */
	if (caller_out != NULL) {
		m = body_out.mb_top;

		if (caller_in == NULL) {
			/*
			 * This is the first call, so create a
			 * negTokenInit.
			 */
			rc = spnegoCreateNegTokenInit(
			    sp->sp_mech, 0,
			    (uchar_t *)m->m_data, m->m_len,
			    NULL, 0, &stok_out);
			/* Note: allocated stok_out */
		} else {
			/*
			 * Note: must pass spnego_mech_oid_NotUsed,
			 * instead of sp->sp_mech so that the spnego
			 * code will not marshal a mech OID list.
			 * The mechanism is determined at this point,
			 * and some servers won't parse an unexpected
			 * mech. OID list in a negTokenTarg
			 */
			rc = spnegoCreateNegTokenTarg(
			    spnego_mech_oid_NotUsed,
			    spnego_negresult_NotUsed,
			    (uchar_t *)m->m_data, m->m_len,
			    NULL, 0, &stok_out);
			/* Note: allocated stok_out */
		}
		if (rc) {
			DPRINT("CreateNegTokenX, rc 0x%x", rc);
			err = EBADRPC;
			goto out;
		}

		/*
		 * Copy binary from stok_out to caller_out
		 * Two calls: get the size, get the data.
		 */
		rc = spnegoTokenGetBinary(stok_out, NULL, &toklen);
		if (rc != SPNEGO_E_BUFFER_TOO_SMALL) {
			DPRINT("GetBinary1, rc 0x%x", rc);
			err = EBADRPC;
			goto out;
		}
		err = mb_init(caller_out, (size_t)toklen);
		if (err)
			goto out;
		m = caller_out->mb_top;
		rc = spnegoTokenGetBinary(stok_out,
		    (uchar_t *)m->m_data, &toklen);
		if (rc) {
			DPRINT("GetBinary2, rc 0x%x", rc);
			err = EBADRPC;
			goto out;
		}
		caller_out->mb_count = m->m_len = (size_t)toklen;
	} else {
		/*
		 * caller_out == NULL, so this is the "final" call.
		 * Get final SPNEGO result from the INPUT token.
		 */
		rc = spnegoGetNegotiationResult(stok_in, &result);
		if (rc) {
			DPRINT("rc 0x%x", rc);
			err = EBADRPC;
			goto out;
		}
		DPRINT("spnego result: 0x%x", result);
		if (result != spnego_negresult_success) {
			err = EAUTH;
			goto out;
		}
	}
	err = 0;

out:
	mb_done(&body_in);
	mb_done(&body_out);
	spnegoFreeData(stok_in);
	spnegoFreeData(stok_out);

	return (err);
}
