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
 * Copyright 2022 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * SPNEGO back-end for Kerberos.  See [MS-KILE]
 */

#include <sys/types.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#include <krb5.h>
#include "smbd.h"
#include "smbd_authsvc.h"

/* From krb5/krb/pac.c (should have been exported) */
#define	PAC_LOGON_INFO		1

typedef struct krb5ssp_backend {
	gss_ctx_id_t		be_gssctx;
	char			*be_username;
	gss_buffer_desc		be_authz_pac;
	krb5_context		be_kctx;
	krb5_pac		be_kpac;
	krb5_data		be_pac;
} krb5ssp_backend_t;

static uint32_t
get_authz_data_pac(
	gss_ctx_id_t context_handle,
	gss_buffer_t ad_data);

static uint32_t
get_ssnkey(authsvc_context_t *ctx);


/*
 * Initialize this context for Kerberos, if possible.
 *
 * Should not get here unless libsmb smb_config_get_negtok
 * includes the Kerberos5 Mech OIDs in our spnego hint.
 *
 * Todo: allocate ctx->ctx_backend
 * See: krb5_gss_accept_sec_context()
 */
int
smbd_krb5ssp_init(authsvc_context_t *ctx)
{
	krb5ssp_backend_t *be;

	be = malloc(sizeof (*be));
	if (be == 0)
		return (NT_STATUS_NO_MEMORY);
	bzero(be, sizeof (*be));
	be->be_gssctx = GSS_C_NO_CONTEXT;
	ctx->ctx_backend = be;

	return (0);
}

/*
 * Todo: free ctx->ctx_backend
 */
void
smbd_krb5ssp_fini(authsvc_context_t *ctx)
{
	krb5ssp_backend_t *be = ctx->ctx_backend;
	uint32_t minor;

	if (be == NULL)
		return;

	if (be->be_kctx != NULL) {
		krb5_free_data_contents(be->be_kctx, &be->be_pac);

		if (be->be_kpac != NULL)
			krb5_pac_free(be->be_kctx, be->be_kpac);

		krb5_free_context(be->be_kctx);
	}

	(void) gss_release_buffer(NULL, &be->be_authz_pac);

	free(be->be_username);

	if (be->be_gssctx != GSS_C_NO_CONTEXT) {
		(void) gss_delete_sec_context(&minor, &be->be_gssctx,
		    GSS_C_NO_BUFFER);
	}

	free(be);
}

static char *krb5ssp_def_username = "Unknown-Kerberos-User";
static char *krb5ssp_def_domain = "Unknown-Domain";

/*
 * Handle a Kerberos auth message.
 *
 * State across messages is in ctx->ctx_backend.
 *
 * Equivalent to smbd_user_auth_logon().
 */
int
smbd_krb5ssp_work(authsvc_context_t *ctx)
{
	gss_buffer_desc	intok, outtok;
	gss_buffer_desc namebuf;
	krb5ssp_backend_t *be = ctx->ctx_backend;
	gss_name_t gname = NULL;
	OM_uint32 major, minor, ret_flags;
	gss_OID name_type = GSS_C_NULL_OID;
	gss_OID mech_type = GSS_C_NULL_OID;
	krb5_error_code kerr;
	uint32_t status;
	smb_token_t *token = NULL;

	intok.length = ctx->ctx_ibodylen;
	intok.value  = ctx->ctx_ibodybuf;
	bzero(&outtok, sizeof (gss_buffer_desc));
	bzero(&namebuf, sizeof (gss_buffer_desc));

	assert(be->be_username == NULL);

	/* Do this early, for error message support. */
	kerr = krb5_init_context(&be->be_kctx);
	if (kerr != 0) {
		smbd_report("krb5ssp, krb5_init_ctx: %s",
		    krb5_get_error_message(be->be_kctx, kerr));
		return (NT_STATUS_INTERNAL_ERROR);
	}

	major = gss_accept_sec_context(&minor, &be->be_gssctx,
	    GSS_C_NO_CREDENTIAL, &intok,
	    GSS_C_NO_CHANNEL_BINDINGS, &gname, &mech_type, &outtok,
	    &ret_flags, NULL, NULL);

	if (outtok.length == 0)
		ctx->ctx_obodylen = 0;
	else if (outtok.length <= ctx->ctx_obodylen) {
		ctx->ctx_obodylen = outtok.length;
		(void) memcpy(ctx->ctx_obodybuf, outtok.value, outtok.length);
		free(outtok.value);
		outtok.value = NULL;
	} else {
		free(ctx->ctx_obodybuf);
		ctx->ctx_obodybuf = outtok.value;
		ctx->ctx_obodylen = outtok.length;
		outtok.value = NULL;
	}

	if (GSS_ERROR(major)) {
		smbd_report("krb5ssp: gss_accept_sec_context, "
		    "mech=0x%x, major=0x%x, minor=0x%x",
		    (int)mech_type, major, minor);
		smbd_report(" krb5: %s",
		    krb5_get_error_message(be->be_kctx, minor));
		status = NT_STATUS_WRONG_PASSWORD;
		goto out;
	}

	switch (major) {
	case GSS_S_COMPLETE:
		break;
	case GSS_S_CONTINUE_NEEDED:
		if (outtok.length > 0) {
			ctx->ctx_orawtype = LSA_MTYPE_ES_CONT;
			/* becomes NT_STATUS_MORE_PROCESSING_REQUIRED */
			return (0);
		}
		status = NT_STATUS_WRONG_PASSWORD;
		goto out;
	default:
		status = NT_STATUS_WRONG_PASSWORD;
		goto out;
	}

	/*
	 * OK, we got GSS_S_COMPLETE.  Get the name so we can use it
	 * in log messages if we get failures decoding the PAC etc.
	 * Then get the PAC, decode it, build the logon token.
	 */

	if (gname != NULL && GSS_S_COMPLETE ==
	    gss_display_name(&minor, gname, &namebuf, &name_type)) {
		/* Save the user name. */
		be->be_username = strdup(namebuf.value);
		(void) gss_release_buffer(&minor, &namebuf);
		(void) gss_release_name(&minor, &gname);
		if (be->be_username == NULL) {
			return (NT_STATUS_NO_MEMORY);
		}
	}

	/*
	 * Extract the KRB5_AUTHDATA_WIN2K_PAC data.
	 */
	status = get_authz_data_pac(be->be_gssctx,
	    &be->be_authz_pac);
	if (status)
		goto out;

	kerr = krb5_pac_parse(be->be_kctx, be->be_authz_pac.value,
	    be->be_authz_pac.length, &be->be_kpac);
	if (kerr) {
		smbd_report("krb5ssp, krb5_pac_parse: %s",
		    krb5_get_error_message(be->be_kctx, kerr));
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	kerr = krb5_pac_get_buffer(be->be_kctx, be->be_kpac,
	    PAC_LOGON_INFO, &be->be_pac);
	if (kerr) {
		smbd_report("krb5ssp, krb5_pac_get_buffer: %s",
		    krb5_get_error_message(be->be_kctx, kerr));
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	ctx->ctx_token = calloc(1, sizeof (smb_token_t));
	if (ctx->ctx_token == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	status = smb_decode_krb5_pac(ctx->ctx_token, be->be_pac.data,
	    be->be_pac.length);
	if (status)
		goto out;

	status = get_ssnkey(ctx);
	if (status)
		goto out;

	if (!smb_token_setup_common(ctx->ctx_token)) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	/* Success! */
	ctx->ctx_orawtype = LSA_MTYPE_ES_DONE;

	status = 0;
	token = ctx->ctx_token;

	/*
	 * Before we return, audit successful and failed logons.
	 *
	 * Successful logons are audited using the username and domain
	 * contained in the ticket (where the domain comes from the PAC data).
	 *
	 * Failed logins use a 'default' domain. If we fail after obtaining
	 * the username in the ticket, we audit under that username.
	 *
	 * Prior to decoding the username, we only audit failures where we'll
	 * return NT_STATUS_WRONG_PASSWORD, so that we audit attempts with
	 * invalid (or forged) tickets. These records use a 'default' username;
	 * As such, they serve only to inform an administrator that
	 * a particular client used a bad ticket, but does not contain any
	 * information on the ticket itself.
	 *
	 * Once we have a username, we'll audit all failed authentications.
	 */
out:
	status = smbd_logon_final(token, &ctx->ctx_clinfo.lci_clnt_ipaddr,
	    (be->be_username != NULL) ? be->be_username : krb5ssp_def_username,
	    krb5ssp_def_domain, status);

	return (status);
}

/*
 * See: GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID
 * and: KRB5_AUTHDATA_WIN2K_PAC
 */
static const gss_OID_desc
oid_ex_authz_data_pac = {
	13, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x0a\x81\x00" };

/*
 * See: krb5_gss_inquire_sec_context_by_oid()
 * and krb5_gss_inquire_sec_context_by_oid_ops[],
 * gss_krb5int_extract_authz_data_from_sec_context()
 */
static uint32_t
get_authz_data_pac(
	gss_ctx_id_t context_handle,
	gss_buffer_t ad_data)
{
	gss_buffer_set_t data_set = GSS_C_NO_BUFFER_SET;
	OM_uint32 major, minor;
	uint32_t status = NT_STATUS_UNSUCCESSFUL;

	if (ad_data == NULL)
		goto out;

	major = gss_inquire_sec_context_by_oid(
	    &minor,
	    context_handle,
	    (gss_OID)&oid_ex_authz_data_pac,
	    &data_set);
	if (GSS_ERROR(major)) {
		smbd_report("krb5ssp, gss_inquire...PAC, "
		    "major=0x%x, minor=0x%x", major, minor);
		goto out;
	}

	if ((data_set == GSS_C_NO_BUFFER_SET) || (data_set->count == 0)) {
		goto out;
	}

	/* Only need the first element? */
	ad_data->length = data_set->elements[0].length;
	ad_data->value = malloc(ad_data->length);
	if (ad_data->value == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	bcopy(data_set->elements[0].value, ad_data->value, ad_data->length);
	status = 0;

out:
	(void) gss_release_buffer_set(&minor, &data_set);

	return (status);
}

/*
 * Get the session key, and save it in the token.
 *
 * See: krb5_gss_inquire_sec_context_by_oid(),
 * krb5_gss_inquire_sec_context_by_oid_ops[], and
 * gss_krb5int_inq_session_key
 */
static uint32_t
get_ssnkey(authsvc_context_t *ctx)
{
	krb5ssp_backend_t *be = ctx->ctx_backend;
	gss_buffer_set_t data_set = GSS_C_NO_BUFFER_SET;
	OM_uint32 major, minor;
	size_t keylen;
	uint32_t status = NT_STATUS_UNSUCCESSFUL;

	major = gss_inquire_sec_context_by_oid(&minor,
	    be->be_gssctx, GSS_C_INQ_SSPI_SESSION_KEY, &data_set);
	if (GSS_ERROR(major)) {
		smbd_report("krb5ssp, failed to get session key, "
		    "major=0x%x, minor=0x%x", major, minor);
		goto out;
	}

	/*
	 * The key is in the first element
	 */
	if (data_set == GSS_C_NO_BUFFER_SET ||
	    data_set->count == 0 ||
	    data_set->elements[0].length == 0 ||
	    data_set->elements[0].value == NULL) {
		smbd_report("krb5ssp: Session key is missing");
		goto out;
	}
	if ((keylen = data_set->elements[0].length) < SMBAUTH_HASH_SZ) {
		smbd_report("krb5ssp: Session key too short (%d)",
		    data_set->elements[0].length);
		goto out;
	}

	ctx->ctx_token->tkn_ssnkey.val = malloc(keylen);
	if (ctx->ctx_token->tkn_ssnkey.val == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	ctx->ctx_token->tkn_ssnkey.len = keylen;
	bcopy(data_set->elements[0].value,
	    ctx->ctx_token->tkn_ssnkey.val, keylen);
	status = 0;

out:
	(void) gss_release_buffer_set(&minor, &data_set);
	return (status);
}
