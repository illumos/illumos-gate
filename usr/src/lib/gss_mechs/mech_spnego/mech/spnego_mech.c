/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (C) 2006,2008 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * A module that implements the spnego security mechanism.
 * It is used to negotiate the security mechanism between
 * peers using the GSS-API.
 *
 */

/*
 * Copyright (c) 2006-2008, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/* #pragma ident	"@(#)spnego_mech.c	1.7	04/09/28 SMI" */

#include	<sys/param.h>
#include	<unistd.h>
#include	<assert.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<k5-int.h>
#include	<krb5.h>
#include	<mglueP.h>
#include	"gssapiP_spnego.h"
#include        "gssapiP_generic.h"
#include	<gssapi_err_generic.h>
#include	<locale.h>

/*
 * SUNW17PACresync
 * MIT has diff names for these GSS utilities.  Solaris needs to change
 * them globally to get in sync w/MIT.
 * Revisit for full 1.7 resync.
 */
#define gssint_get_modOptions __gss_get_modOptions
#define gssint_der_length_size der_length_size
#define gssint_get_der_length get_der_length
#define gssint_put_der_length put_der_length
#define gssint_get_mechanism __gss_get_mechanism
#define gssint_copy_oid_set gss_copy_oid_set
#define gssint_get_mech_type __gss_get_mech_type


#undef g_token_size
#undef g_verify_token_header
#undef g_make_token_header

#define HARD_ERROR(v) ((v) != GSS_S_COMPLETE && (v) != GSS_S_CONTINUE_NEEDED)
typedef const gss_OID_desc *gss_OID_const;

/* der routines defined in libgss */
extern unsigned int gssint_der_length_size(OM_uint32);
extern int gssint_get_der_length(unsigned char **, OM_uint32, OM_uint32*);
extern int gssint_put_der_length(OM_uint32, unsigned char **, OM_uint32);


/* private routines for spnego_mechanism */
static spnego_token_t make_spnego_token(char *);
static gss_buffer_desc make_err_msg(char *);
static int g_token_size(gss_OID_const, unsigned int);
static int g_make_token_header(gss_OID_const, unsigned int,
			       unsigned char **, unsigned int);
static int g_verify_token_header(gss_OID_const, unsigned int *,
				 unsigned char **,
				 int, unsigned int);
static int g_verify_neg_token_init(unsigned char **, unsigned int);
static gss_OID get_mech_oid(OM_uint32 *, unsigned char **, size_t);
static gss_buffer_t get_input_token(unsigned char **, unsigned int);
static gss_OID_set get_mech_set(OM_uint32 *, unsigned char **, unsigned int);
static OM_uint32 get_req_flags(unsigned char **, OM_uint32, OM_uint32 *);
static OM_uint32 get_available_mechs(OM_uint32 *, gss_name_t,
	gss_cred_usage_t, gss_cred_id_t *, gss_OID_set *);
static void release_spnego_ctx(spnego_gss_ctx_id_t *);
static void check_spnego_options(spnego_gss_ctx_id_t);
static spnego_gss_ctx_id_t create_spnego_ctx(void);
static int put_mech_set(gss_OID_set mechSet, gss_buffer_t buf);
static int put_input_token(unsigned char **, gss_buffer_t, unsigned int);
static int put_mech_oid(unsigned char **, gss_OID_const, unsigned int);
static int put_negResult(unsigned char **, OM_uint32, unsigned int);

static OM_uint32
process_mic(OM_uint32 *, gss_buffer_t, spnego_gss_ctx_id_t,
	    gss_buffer_t *, OM_uint32 *, send_token_flag *);
static OM_uint32
handle_mic(OM_uint32 *, gss_buffer_t, int, spnego_gss_ctx_id_t,
	   gss_buffer_t *, OM_uint32 *, send_token_flag *);

static OM_uint32
init_ctx_new(OM_uint32 *, gss_cred_id_t, gss_ctx_id_t *,
	     gss_OID_set *, send_token_flag *);
static OM_uint32
init_ctx_nego(OM_uint32 *, spnego_gss_ctx_id_t, OM_uint32, gss_OID,
	      gss_buffer_t *, gss_buffer_t *,
	      OM_uint32 *, send_token_flag *);
static OM_uint32
init_ctx_cont(OM_uint32 *, gss_ctx_id_t *, gss_buffer_t,
	      gss_buffer_t *, gss_buffer_t *,
	      OM_uint32 *, send_token_flag *);
static OM_uint32
init_ctx_reselect(OM_uint32 *, spnego_gss_ctx_id_t, OM_uint32,
		  gss_OID, gss_buffer_t *, gss_buffer_t *,
		  OM_uint32 *, send_token_flag *);
static OM_uint32
init_ctx_call_init(OM_uint32 *, spnego_gss_ctx_id_t, gss_cred_id_t,
		   gss_name_t, OM_uint32, OM_uint32, gss_buffer_t,
		   gss_OID *, gss_buffer_t, OM_uint32 *, OM_uint32 *,
		   OM_uint32 *, send_token_flag *);

static OM_uint32
acc_ctx_new(OM_uint32 *, gss_buffer_t, gss_ctx_id_t *,
	    gss_cred_id_t, gss_buffer_t *,
	    gss_buffer_t *, OM_uint32 *, send_token_flag *);
static OM_uint32
acc_ctx_cont(OM_uint32 *, gss_buffer_t, gss_ctx_id_t *,
	     gss_buffer_t *, gss_buffer_t *,
	     OM_uint32 *, send_token_flag *);
static OM_uint32
acc_ctx_vfy_oid(OM_uint32 *, spnego_gss_ctx_id_t, gss_OID,
		OM_uint32 *, send_token_flag *);
static OM_uint32
acc_ctx_call_acc(OM_uint32 *, spnego_gss_ctx_id_t, gss_cred_id_t,
		 gss_buffer_t, gss_OID *, gss_buffer_t,
		 OM_uint32 *, OM_uint32 *, gss_cred_id_t *,
		 OM_uint32 *, send_token_flag *);

static gss_OID
negotiate_mech_type(OM_uint32 *, gss_OID_set, gss_OID_set,
		OM_uint32 *);
static int
g_get_tag_and_length(unsigned char **, int, unsigned int, unsigned int *);

static int
make_spnego_tokenInit_msg(spnego_gss_ctx_id_t,
			int,
			gss_buffer_t,
			OM_uint32, gss_buffer_t, send_token_flag,
			gss_buffer_t);
static int
make_spnego_tokenTarg_msg(OM_uint32, gss_OID, gss_buffer_t,
			gss_buffer_t, send_token_flag,
			gss_buffer_t);

static OM_uint32
get_negTokenInit(OM_uint32 *, gss_buffer_t, gss_buffer_t,
		 gss_OID_set *, OM_uint32 *, gss_buffer_t *,
		 gss_buffer_t *);
static OM_uint32
get_negTokenResp(OM_uint32 *, unsigned char *, unsigned int,
		 OM_uint32 *, gss_OID *, gss_buffer_t *, gss_buffer_t *);

static int
is_kerb_mech(gss_OID oid);

/* SPNEGO oid structure */
static const gss_OID_desc spnego_oids[] = {
	{SPNEGO_OID_LENGTH, SPNEGO_OID},
};

const gss_OID_desc * const gss_mech_spnego = spnego_oids+0;
static const gss_OID_set_desc spnego_oidsets[] = {
	{1, (gss_OID) spnego_oids+0},
};
const gss_OID_set_desc * const gss_mech_set_spnego = spnego_oidsets+0;

static int make_NegHints(OM_uint32 *, gss_cred_id_t, gss_buffer_t *);
static int put_neg_hints(unsigned char **, gss_buffer_t, unsigned int);
static OM_uint32
acc_ctx_hints(OM_uint32 *, gss_ctx_id_t *, gss_cred_id_t,
	      gss_buffer_t *, OM_uint32 *, send_token_flag *);

#ifdef _GSS_STATIC_LINK
int gss_spnegoint_lib_init(void);
void gss_spnegoint_lib_fini(void);
#else
gss_mechanism gss_mech_initialize(void);
#endif /* _GSS_STATIC_LINK */

/*
 * The Mech OID for SPNEGO:
 * { iso(1) org(3) dod(6) internet(1) security(5)
 *  mechanism(5) spnego(2) }
 */
static struct gss_config spnego_mechanism =
{
	{SPNEGO_OID_LENGTH, SPNEGO_OID},
	NULL,
	glue_spnego_gss_acquire_cred,
	glue_spnego_gss_release_cred,
	glue_spnego_gss_init_sec_context,
#ifndef LEAN_CLIENT
	glue_spnego_gss_accept_sec_context,
#else
	NULL,				
#endif  /* LEAN_CLIENT */
	NULL,  /* unseal */
	NULL,				/* gss_process_context_token */
	glue_spnego_gss_delete_sec_context,	/* gss_delete_sec_context */
	glue_spnego_gss_context_time,
	glue_spnego_gss_display_status,
	NULL,				/* gss_indicate_mechs */
	glue_spnego_gss_compare_name,
	glue_spnego_gss_display_name,
	glue_spnego_gss_import_name, /* glue */
	glue_spnego_gss_release_name,
	NULL,				/* gss_inquire_cred */
	NULL,				/* gss_add_cred */
	NULL, /* seal */
#ifndef LEAN_CLIENT
	glue_spnego_gss_export_sec_context,	/* gss_export_sec_context */
	glue_spnego_gss_import_sec_context,	/* gss_import_sec_context */
#else
	NULL,				/* gss_export_sec_context */
	NULL,				/* gss_import_sec_context */
#endif /* LEAN_CLIENT */
	NULL, 				/* gss_inquire_cred_by_mech */
	glue_spnego_gss_inquire_names_for_mech,
	glue_spnego_gss_inquire_context,
	NULL,				/* gss_internal_release_oid */
	glue_spnego_gss_wrap_size_limit,
	NULL, /* pname */
	NULL, /* userok */
	NULL, /* gss_export_name */
	NULL, /* sign */
	NULL, /* verify */
	NULL, /* gss_store_cred */
        spnego_gss_inquire_sec_context_by_oid, /* gss_inquire_sec_context_by_oid */
};

#ifdef _GSS_STATIC_LINK
#include "mglueP.h"

static
int gss_spnegomechglue_init(void)
{
	struct gss_mech_config mech_spnego;

	memset(&mech_spnego, 0, sizeof(mech_spnego));
	mech_spnego.mech = &spnego_mechanism;
	mech_spnego.mechNameStr = "spnego";
	mech_spnego.mech_type = GSS_C_NO_OID;

	return gssint_register_mechinfo(&mech_spnego);
}
#else
/* Entry point for libgss */
gss_mechanism KRB5_CALLCONV
gss_mech_initialize(void)
{
	int err;

	err = k5_key_register(K5_KEY_GSS_SPNEGO_ERROR_MESSAGE,
		spnego_gss_delete_error_info);
	if (err) {
	    syslog(LOG_NOTICE,
		"SPNEGO gss_mech_initialize: error message TSD key register fail");
	    return (NULL);
	}

	return (&spnego_mechanism);
}

#if 0 /* SUNW17PACresync */
MAKE_INIT_FUNCTION(gss_krb5int_lib_init);
MAKE_FINI_FUNCTION(gss_krb5int_lib_fini);
int gss_krb5int_lib_init(void)
#endif

#endif /* _GSS_STATIC_LINK */

static
int gss_spnegoint_lib_init(void)
{
#ifdef _GSS_STATIC_LINK
	return gss_spnegomechglue_init();
#else
	int err;

	err = k5_key_register(K5_KEY_GSS_SPNEGO_ERROR_MESSAGE,
		spnego_gss_delete_error_info);
	if (err) {
	    syslog(LOG_NOTICE,
		"SPNEGO gss_mech_initialize: error message TSD key register fail: err=%d",
		err);
	    return err;
	}

	return 0;
#endif
}

static void gss_spnegoint_lib_fini(void)
{
}

/*ARGSUSED*/
OM_uint32
glue_spnego_gss_acquire_cred(
	void *context,
	OM_uint32 *minor_status,
	gss_name_t desired_name,
	OM_uint32 time_req,
	gss_OID_set desired_mechs,
	gss_cred_usage_t cred_usage,
	gss_cred_id_t *output_cred_handle,
	gss_OID_set *actual_mechs,
	OM_uint32 *time_rec)
{
	return(spnego_gss_acquire_cred(minor_status,
					desired_name,
					time_req,
					desired_mechs,
					cred_usage,
					output_cred_handle,
					actual_mechs,
					time_rec));
}

/*ARGSUSED*/
OM_uint32
spnego_gss_acquire_cred(OM_uint32 *minor_status,
			gss_name_t desired_name,
			OM_uint32 time_req,
			gss_OID_set desired_mechs,
			gss_cred_usage_t cred_usage,
			gss_cred_id_t *output_cred_handle,
			gss_OID_set *actual_mechs,
			OM_uint32 *time_rec)
{
	OM_uint32 status;
	gss_OID_set amechs;
	dsyslog("Entering spnego_gss_acquire_cred\n");

	if (actual_mechs)
		*actual_mechs = NULL;

	if (time_rec)
		*time_rec = 0;

	/*
	 * If the user did not specify a list of mechs,
	 * use get_available_mechs to collect a list of
	 * mechs for which creds are available.
	 */
	if (desired_mechs == GSS_C_NULL_OID_SET) {
		status = get_available_mechs(minor_status,
				desired_name, cred_usage,
				output_cred_handle, &amechs);
	} else {
		/*
		 * The caller gave a specific list of mechanisms,
		 * so just get whatever creds are available.
		 * gss_acquire_creds will return the subset of mechs for
		 * which the given 'output_cred_handle' is valid.
		 */
		status = gss_acquire_cred(minor_status,
				desired_name, time_req,
				desired_mechs, cred_usage,
				output_cred_handle, &amechs,
				time_rec);
	}

	if (actual_mechs && amechs != GSS_C_NULL_OID_SET) {
		(void) gssint_copy_oid_set(minor_status, amechs, actual_mechs);
	}
	(void) gss_release_oid_set(minor_status, &amechs);

	dsyslog("Leaving spnego_gss_acquire_cred\n");
	return (status);
}

/*ARGSUSED*/
OM_uint32
glue_spnego_gss_release_cred(void *context,
			    OM_uint32 *minor_status,
			    gss_cred_id_t *cred_handle)
{
	return( spnego_gss_release_cred(minor_status, cred_handle));
}

/*ARGSUSED*/
OM_uint32
spnego_gss_release_cred(OM_uint32 *minor_status,
			gss_cred_id_t *cred_handle)
{
	OM_uint32 status;

	dsyslog("Entering spnego_gss_release_cred\n");

	if (minor_status == NULL || cred_handle == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor_status = 0;

	if (*cred_handle == GSS_C_NO_CREDENTIAL)
		return (GSS_S_COMPLETE);

	status = gss_release_cred(minor_status, cred_handle);

	dsyslog("Leaving spnego_gss_release_cred\n");
	return (status);
}

static void
check_spnego_options(spnego_gss_ctx_id_t spnego_ctx)
{
	spnego_ctx->optionStr = gssint_get_modOptions(
		(const gss_OID)&spnego_oids[0]);
}

static spnego_gss_ctx_id_t
create_spnego_ctx(void)
{
	spnego_gss_ctx_id_t spnego_ctx = NULL;
	spnego_ctx = (spnego_gss_ctx_id_t)
		malloc(sizeof (spnego_gss_ctx_id_rec));

	if (spnego_ctx == NULL) {
		return (NULL);
	}

	spnego_ctx->magic_num = SPNEGO_MAGIC_ID;
	spnego_ctx->ctx_handle = GSS_C_NO_CONTEXT;
	spnego_ctx->internal_mech = NULL;
	spnego_ctx->optionStr = NULL;
	spnego_ctx->DER_mechTypes.length = 0;
	spnego_ctx->DER_mechTypes.value = NULL;
	spnego_ctx->default_cred = GSS_C_NO_CREDENTIAL;
	spnego_ctx->mic_reqd = 0;
	spnego_ctx->mic_sent = 0;
	spnego_ctx->mic_rcvd = 0;
	spnego_ctx->mech_complete = 0;
	spnego_ctx->nego_done = 0;
	spnego_ctx->internal_name = GSS_C_NO_NAME;
	spnego_ctx->actual_mech = GSS_C_NO_OID;
	spnego_ctx->err.msg = NULL;
	spnego_ctx->err.scratch_buf[0] = 0;
	check_spnego_options(spnego_ctx);

	return (spnego_ctx);
}

/*
 * Both initiator and acceptor call here to verify and/or create
 * mechListMIC, and to consistency-check the MIC state.
 */
static OM_uint32
handle_mic(OM_uint32 *minor_status, gss_buffer_t mic_in,
	   int send_mechtok, spnego_gss_ctx_id_t sc,
	   gss_buffer_t *mic_out,
	   OM_uint32 *negState, send_token_flag *tokflag)
{
	OM_uint32 ret;

	ret = GSS_S_FAILURE;
	*mic_out = GSS_C_NO_BUFFER;
	if (mic_in != GSS_C_NO_BUFFER) {
		if (sc->mic_rcvd) {
			/* Reject MIC if we've already received a MIC. */
			*negState = REJECT;
			*tokflag = ERROR_TOKEN_SEND;
			return GSS_S_DEFECTIVE_TOKEN;
		}
	} else if (sc->mic_reqd && !send_mechtok) {
		/*
		 * If the peer sends the final mechanism token, it
		 * must send the MIC with that token if the
		 * negotiation requires MICs.
		 */
		*negState = REJECT;
		*tokflag = ERROR_TOKEN_SEND;
		return GSS_S_DEFECTIVE_TOKEN;
	}
	ret = process_mic(minor_status, mic_in, sc, mic_out,
			  negState, tokflag);
	if (ret != GSS_S_COMPLETE) {
		return ret;
	}
	if (sc->mic_reqd) {
		assert(sc->mic_sent || sc->mic_rcvd);
	}
	if (sc->mic_sent && sc->mic_rcvd) {
		ret = GSS_S_COMPLETE;
		*negState = ACCEPT_COMPLETE;
		if (*mic_out == GSS_C_NO_BUFFER) {
			/*
			 * We sent a MIC on the previous pass; we
			 * shouldn't be sending a mechanism token.
			 */
			assert(!send_mechtok);
			*tokflag = NO_TOKEN_SEND;
		} else {
			*tokflag = CONT_TOKEN_SEND;
		}
	} else if (sc->mic_reqd) {
		*negState = ACCEPT_INCOMPLETE;
		ret = GSS_S_CONTINUE_NEEDED;
	} else if (*negState == ACCEPT_COMPLETE) {
		ret = GSS_S_COMPLETE;
	} else {
		ret = GSS_S_CONTINUE_NEEDED;
	}
	return ret;
}

/*
 * Perform the actual verification and/or generation of mechListMIC.
 */
static OM_uint32
process_mic(OM_uint32 *minor_status, gss_buffer_t mic_in,
	    spnego_gss_ctx_id_t sc, gss_buffer_t *mic_out,
	    OM_uint32 *negState, send_token_flag *tokflag)
{
	OM_uint32 ret, tmpmin;
	gss_qop_t qop_state;
	gss_buffer_desc tmpmic = GSS_C_EMPTY_BUFFER;

	ret = GSS_S_FAILURE;
	if (mic_in != GSS_C_NO_BUFFER) {
		ret = gss_verify_mic(minor_status, sc->ctx_handle,
				     &sc->DER_mechTypes,
				     mic_in, &qop_state);
		if (ret != GSS_S_COMPLETE) {
			*negState = REJECT;
			*tokflag = ERROR_TOKEN_SEND;
			return ret;
		}
		/* If we got a MIC, we must send a MIC. */
		sc->mic_reqd = 1;
		sc->mic_rcvd = 1;
	}
	if (sc->mic_reqd && !sc->mic_sent) {
		ret = gss_get_mic(minor_status, sc->ctx_handle,
				  GSS_C_QOP_DEFAULT,
				  &sc->DER_mechTypes,
				  &tmpmic);
		if (ret != GSS_S_COMPLETE) {
			gss_release_buffer(&tmpmin, &tmpmic);
			*tokflag = NO_TOKEN_SEND;
			return ret;
		}
		*mic_out = malloc(sizeof(gss_buffer_desc));
		if (*mic_out == GSS_C_NO_BUFFER) {
			gss_release_buffer(&tmpmin, &tmpmic);
			*tokflag = NO_TOKEN_SEND;
			return GSS_S_FAILURE;
		}
		**mic_out = tmpmic;
		sc->mic_sent = 1;
	}
	return GSS_S_COMPLETE;
}

/*
 * Initial call to spnego_gss_init_sec_context().
 */
static OM_uint32
init_ctx_new(OM_uint32 *minor_status,
	     gss_cred_id_t cred,
	     gss_ctx_id_t *ctx,
	     gss_OID_set *mechSet,
	     send_token_flag *tokflag)
{
	OM_uint32 ret, tmpmin;
	gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
	spnego_gss_ctx_id_t sc = NULL;

	/* determine negotiation mech set */
	if (cred == GSS_C_NO_CREDENTIAL) {
		ret = get_available_mechs(minor_status, GSS_C_NO_NAME,
					  GSS_C_INITIATE, &creds, mechSet);
		gss_release_cred(&tmpmin, &creds);
	} else {
		/*
		 * Use the list of mechs included in the cred that we
		 * were given.
		 */
		ret = gss_inquire_cred(minor_status, cred,
				       NULL, NULL, NULL, mechSet);
	}
	if (ret != GSS_S_COMPLETE)
		return ret;

	sc = create_spnego_ctx();
	if (sc == NULL)
		return GSS_S_FAILURE;

	/*
	 * need to pull the first mech from mechSet to do first
	 * gss_init_sec_context()
	 */
	ret = generic_gss_copy_oid(minor_status, (*mechSet)->elements,
				   &sc->internal_mech);
	if (ret != GSS_S_COMPLETE) {
	    map_errcode(minor_status);
	    goto cleanup;
	}

	if (put_mech_set(*mechSet, &sc->DER_mechTypes) < 0) {
		generic_gss_release_oid(&tmpmin, &sc->internal_mech);
		ret = GSS_S_FAILURE;
		goto cleanup;
	}
	/*
	 * The actual context is not yet determined, set the output
	 * context handle to refer to the spnego context itself.
	 */
	sc->ctx_handle = GSS_C_NO_CONTEXT;
	*ctx = (gss_ctx_id_t)sc;
	*tokflag = INIT_TOKEN_SEND;
	ret = GSS_S_CONTINUE_NEEDED;

cleanup:
	gss_release_oid_set(&tmpmin, mechSet);
	return ret;
}

/*
 * Called by second and later calls to spnego_gss_init_sec_context()
 * to decode reply and update state.
 */
static OM_uint32
init_ctx_cont(OM_uint32 *minor_status, gss_ctx_id_t *ctx, gss_buffer_t buf,
	      gss_buffer_t *responseToken, gss_buffer_t *mechListMIC,
	      OM_uint32 *negState, send_token_flag *tokflag)
{
	OM_uint32 ret, tmpmin, acc_negState;
	unsigned char *ptr;
	spnego_gss_ctx_id_t sc;
	gss_OID supportedMech = GSS_C_NO_OID;

	sc = (spnego_gss_ctx_id_t)*ctx;
	*negState = REJECT;
	*tokflag = ERROR_TOKEN_SEND;

	ptr = buf->value;
	ret = get_negTokenResp(minor_status, ptr, buf->length,
			       &acc_negState, &supportedMech,
			       responseToken, mechListMIC);
	if (ret != GSS_S_COMPLETE)
		goto cleanup;
	if (acc_negState == ACCEPT_DEFECTIVE_TOKEN &&
	    supportedMech == GSS_C_NO_OID &&
	    *responseToken == GSS_C_NO_BUFFER &&
	    *mechListMIC == GSS_C_NO_BUFFER) {
		/* Reject "empty" token. */
		ret = GSS_S_DEFECTIVE_TOKEN;
	}
	if (acc_negState == REJECT) {
		*minor_status = ERR_SPNEGO_NEGOTIATION_FAILED;
		/* Solaris SPNEGO */
		spnego_set_error_message(sc, *minor_status,
					dgettext(TEXT_DOMAIN,
						"SPNEGO failed to negotiate a mechanism: server rejected request"));
		map_errcode(minor_status);
		*tokflag = NO_TOKEN_SEND;
		ret = GSS_S_FAILURE;
		goto cleanup;
	}
	/*
	 * nego_done is false for the first call to init_ctx_cont()
	 */
	if (!sc->nego_done) {
		ret = init_ctx_nego(minor_status, sc,
				    acc_negState,
				    supportedMech, responseToken,
				    mechListMIC,
				    negState, tokflag);
	} else if (!sc->mech_complete &&
		   *responseToken == GSS_C_NO_BUFFER) {
		/*
		 * mech not finished and mech token missing
		 */
		ret = GSS_S_DEFECTIVE_TOKEN;
	} else if (sc->mic_reqd &&
		   (sc->ctx_flags & GSS_C_INTEG_FLAG)) {
		*negState = ACCEPT_INCOMPLETE;
		*tokflag = CONT_TOKEN_SEND;
		ret = GSS_S_CONTINUE_NEEDED;
	} else {
		*negState = ACCEPT_COMPLETE;
		*tokflag = NO_TOKEN_SEND;
		ret = GSS_S_COMPLETE;
	}
cleanup:
	if (supportedMech != GSS_C_NO_OID)
		generic_gss_release_oid(&tmpmin, &supportedMech);
	return ret;
}

/*
 * Consistency checking and mechanism negotiation handling for second
 * call of spnego_gss_init_sec_context().  Call init_ctx_reselect() to
 * update internal state if acceptor has counter-proposed.
 */
static OM_uint32
init_ctx_nego(OM_uint32 *minor_status, spnego_gss_ctx_id_t sc,
	      OM_uint32 acc_negState, gss_OID supportedMech,
	      gss_buffer_t *responseToken, gss_buffer_t *mechListMIC,
	      OM_uint32 *negState, send_token_flag *tokflag)
{
	OM_uint32 ret;

	*negState = REJECT;
	*tokflag = ERROR_TOKEN_SEND;
	ret = GSS_S_DEFECTIVE_TOKEN;
	/*
	 * Both supportedMech and negState must be present in first
	 * acceptor token.
	 */
	if (supportedMech == GSS_C_NO_OID) {
		*minor_status = ERR_SPNEGO_NO_MECH_FROM_ACCEPTOR;
		map_errcode(minor_status);
		return GSS_S_DEFECTIVE_TOKEN;
	}
	if (acc_negState == ACCEPT_DEFECTIVE_TOKEN) {
		*minor_status = ERR_SPNEGO_NEGOTIATION_FAILED;
		/* Solaris SPNEGO */
		spnego_set_error_message(sc, *minor_status,
					dgettext(TEXT_DOMAIN,
						"SPNEGO failed to negotiate a mechanism: defective token"));
		map_errcode(minor_status);
		return GSS_S_DEFECTIVE_TOKEN;
	}

	/*
	 * If the mechanism we sent is not the mechanism returned from
	 * the server, we need to handle the server's counter
	 * proposal.  There is a bug in SAMBA servers that always send
	 * the old Kerberos mech OID, even though we sent the new one.
	 * So we will treat all the Kerberos mech OIDS as the same.
         */
	if (!(is_kerb_mech(supportedMech) &&
	      is_kerb_mech(sc->internal_mech)) &&
	    !g_OID_equal(supportedMech, sc->internal_mech)) {
		ret = init_ctx_reselect(minor_status, sc,
					acc_negState, supportedMech,
					responseToken, mechListMIC,
					negState, tokflag);

	} else if (*responseToken == GSS_C_NO_BUFFER) {
		if (sc->mech_complete) {
			/*
			 * Mech completed on first call to its
			 * init_sec_context().  Acceptor sends no mech
			 * token.
			 */
			*negState = ACCEPT_COMPLETE;
			*tokflag = NO_TOKEN_SEND;
			ret = GSS_S_COMPLETE;
		} else {
			/*
			 * Reject missing mech token when optimistic
			 * mech selected.
			 */
			*minor_status = ERR_SPNEGO_NO_TOKEN_FROM_ACCEPTOR;
			map_errcode(minor_status);
			ret = GSS_S_DEFECTIVE_TOKEN;
		}
	} else if (sc->mech_complete) {
		/* Reject spurious mech token. */
		ret = GSS_S_DEFECTIVE_TOKEN;
	} else {
		*negState = ACCEPT_INCOMPLETE;
		*tokflag = CONT_TOKEN_SEND;
		ret = GSS_S_CONTINUE_NEEDED;
	}
	sc->nego_done = 1;
	return ret;
}

/*
 * Handle acceptor's counter-proposal of an alternative mechanism.
 */
static OM_uint32
init_ctx_reselect(OM_uint32 *minor_status, spnego_gss_ctx_id_t sc,
		  OM_uint32 acc_negState, gss_OID supportedMech,
		  gss_buffer_t *responseToken, gss_buffer_t *mechListMIC,
		  OM_uint32 *negState, send_token_flag *tokflag)
{
	OM_uint32 ret, tmpmin;

	generic_gss_release_oid(&tmpmin, &sc->internal_mech);
	gss_delete_sec_context(&tmpmin, &sc->ctx_handle,
			       GSS_C_NO_BUFFER);

	ret = generic_gss_copy_oid(minor_status, supportedMech,
				   &sc->internal_mech);
	if (ret != GSS_S_COMPLETE) {
		map_errcode(minor_status);
		sc->internal_mech = GSS_C_NO_OID;
		*tokflag = NO_TOKEN_SEND;
		return ret;
	}
	if (*responseToken != GSS_C_NO_BUFFER) {
		/* Reject spurious mech token. */
		return GSS_S_DEFECTIVE_TOKEN;
	}
	/*
	 * Windows 2003 and earlier don't correctly send a
	 * negState of request-mic when counter-proposing a
	 * mechanism.  They probably don't handle mechListMICs
	 * properly either.
	 */
	if (acc_negState != REQUEST_MIC)
		return GSS_S_DEFECTIVE_TOKEN;

	sc->mech_complete = 0;
	sc->mic_reqd = 1;
	*negState = REQUEST_MIC;
	*tokflag = CONT_TOKEN_SEND;
	return GSS_S_CONTINUE_NEEDED;
}

/*
 * Wrap call to mechanism gss_init_sec_context() and update state
 * accordingly.
 */
static OM_uint32
init_ctx_call_init(OM_uint32 *minor_status,
		   spnego_gss_ctx_id_t sc,
		   gss_cred_id_t claimant_cred_handle,
		   gss_name_t target_name,
		   OM_uint32 req_flags,
		   OM_uint32 time_req,
		   gss_buffer_t mechtok_in,
		   gss_OID *actual_mech,
		   gss_buffer_t mechtok_out,
		   OM_uint32 *ret_flags,
		   OM_uint32 *time_rec,
		   OM_uint32 *negState,
		   send_token_flag *send_token)
{
	OM_uint32 ret;

	ret = gss_init_sec_context(minor_status,
				   claimant_cred_handle,
				   &sc->ctx_handle,
				   target_name,
				   sc->internal_mech,
				   (req_flags | GSS_C_INTEG_FLAG),
				   time_req,
				   GSS_C_NO_CHANNEL_BINDINGS,
				   mechtok_in,
				   &sc->actual_mech,
				   mechtok_out,
				   &sc->ctx_flags,
				   time_rec);
	if (ret == GSS_S_COMPLETE) {
		sc->mech_complete = 1;
		if (ret_flags != NULL)
			*ret_flags = sc->ctx_flags;
		/*
		 * If this isn't the first time we've been called,
		 * we're done unless a MIC needs to be
		 * generated/handled.
		 */
		if (*send_token == CONT_TOKEN_SEND &&
		    mechtok_out->length == 0 &&
		    (!sc->mic_reqd ||
		     !(sc->ctx_flags & GSS_C_INTEG_FLAG))) {

			*negState = ACCEPT_COMPLETE;
			ret = GSS_S_COMPLETE;
			if (mechtok_out->length == 0) {
				*send_token = NO_TOKEN_SEND;
			}
		} else {
			*negState = ACCEPT_INCOMPLETE;
			ret = GSS_S_CONTINUE_NEEDED;
		}
	} else if (ret != GSS_S_CONTINUE_NEEDED) {
		if (*send_token == INIT_TOKEN_SEND) {
			/* Don't output token on error if first call. */
			*send_token = NO_TOKEN_SEND;
		} else {
			*send_token = ERROR_TOKEN_SEND;
		}
		*negState = REJECT;
	}
	return ret;
}

/*ARGSUSED*/
OM_uint32
glue_spnego_gss_init_sec_context(
	void *context,
	OM_uint32 *minor_status,
	gss_cred_id_t claimant_cred_handle,
	gss_ctx_id_t *context_handle,
	gss_name_t target_name,
	gss_OID mech_type,
	OM_uint32 req_flags,
	OM_uint32 time_req,
	gss_channel_bindings_t input_chan_bindings,
	gss_buffer_t input_token,
	gss_OID *actual_mech,
	gss_buffer_t output_token,
	OM_uint32 *ret_flags,
	OM_uint32 *time_rec)
{
	return(spnego_gss_init_sec_context(
		    minor_status,
		    claimant_cred_handle,
		    context_handle,
		    target_name,
		    mech_type,
		    req_flags,
		    time_req,
		    input_chan_bindings,
		    input_token,
		    actual_mech,
		    output_token,
		    ret_flags,
		    time_rec));
}

/*ARGSUSED*/
OM_uint32
spnego_gss_init_sec_context(
			OM_uint32 *minor_status,
			gss_cred_id_t claimant_cred_handle,
			gss_ctx_id_t *context_handle,
			gss_name_t target_name,
			gss_OID mech_type,
			OM_uint32 req_flags,
			OM_uint32 time_req,
			gss_channel_bindings_t input_chan_bindings,
			gss_buffer_t input_token,
			gss_OID *actual_mech,
			gss_buffer_t output_token,
			OM_uint32 *ret_flags,
			OM_uint32 *time_rec)
{
	/*
	 * send_token is used to indicate in later steps
	 * what type of token, if any should be sent or processed.
	 * NO_TOKEN_SEND = no token should be sent
	 * INIT_TOKEN_SEND = initial token will be sent
	 * CONT_TOKEN_SEND = continuing tokens to be sent
	 * CHECK_MIC = no token to be sent, but have a MIC to check.
	 */
	send_token_flag send_token = NO_TOKEN_SEND;
	OM_uint32 tmpmin, ret, negState;
	gss_buffer_t mechtok_in, mechListMIC_in, mechListMIC_out;
	gss_buffer_desc mechtok_out = GSS_C_EMPTY_BUFFER;
	gss_OID_set mechSet = GSS_C_NO_OID_SET;
	spnego_gss_ctx_id_t spnego_ctx = NULL;

	dsyslog("Entering init_sec_context\n");

	mechtok_in = mechListMIC_out = mechListMIC_in = GSS_C_NO_BUFFER;
	negState = REJECT;

	if (minor_status != NULL)
		*minor_status = 0;
	if (output_token != GSS_C_NO_BUFFER) {
		output_token->length = 0;
		output_token->value = NULL;
	}
	if (minor_status == NULL ||
	    output_token == GSS_C_NO_BUFFER ||
	    context_handle == NULL)
		return GSS_S_CALL_INACCESSIBLE_WRITE;

	if (actual_mech != NULL)
		*actual_mech = GSS_C_NO_OID;

	if (*context_handle == GSS_C_NO_CONTEXT) {
		ret = init_ctx_new(minor_status, claimant_cred_handle,
				   context_handle, &mechSet, &send_token);
		if (ret != GSS_S_CONTINUE_NEEDED) {
			goto cleanup;
		}
	} else {
		ret = init_ctx_cont(minor_status, context_handle,
				    input_token, &mechtok_in,
				    &mechListMIC_in, &negState, &send_token);
		if (HARD_ERROR(ret)) {
			goto cleanup;
		}
	}
	spnego_ctx = (spnego_gss_ctx_id_t)*context_handle;

	/* Solaris SPNEGO */
	if (*minor_status == ERR_SPNEGO_NEGOTIATION_FAILED)
		spnego_gss_save_error_info(*minor_status, spnego_ctx);

	if (!spnego_ctx->mech_complete) {
		ret = init_ctx_call_init(
			minor_status, spnego_ctx,
			claimant_cred_handle,
			target_name, req_flags,
			time_req, mechtok_in,
			actual_mech, &mechtok_out,
			ret_flags, time_rec,
			&negState, &send_token);
	}
	/* create mic/check mic */
	if (!HARD_ERROR(ret) && spnego_ctx->mech_complete &&
	    (spnego_ctx->ctx_flags & GSS_C_INTEG_FLAG)) {

		ret = handle_mic(minor_status,
				 mechListMIC_in,
				 (mechtok_out.length != 0),
				 spnego_ctx, &mechListMIC_out,
				 &negState, &send_token);
	}
cleanup:
	if (send_token == INIT_TOKEN_SEND) {
		if (make_spnego_tokenInit_msg(spnego_ctx,
					      0,
					      mechListMIC_out,
					      req_flags,
					      &mechtok_out, send_token,
					      output_token) < 0) {
			ret = GSS_S_FAILURE;
		}
	} else if (send_token != NO_TOKEN_SEND) {
		if (make_spnego_tokenTarg_msg(negState, GSS_C_NO_OID,
					      &mechtok_out, mechListMIC_out,
					      send_token,
					      output_token) < 0) {
			ret = GSS_S_FAILURE;
		}
	}
	gss_release_buffer(&tmpmin, &mechtok_out);
	if (ret == GSS_S_COMPLETE) {
		/*
		 * Now, switch the output context to refer to the
		 * negotiated mechanism's context.
		 */
		*context_handle = (gss_ctx_id_t)spnego_ctx->ctx_handle;
		if (actual_mech != NULL)
			*actual_mech = spnego_ctx->actual_mech;
		if (ret_flags != NULL)
			*ret_flags = spnego_ctx->ctx_flags;
		release_spnego_ctx(&spnego_ctx);
	} else if (ret != GSS_S_CONTINUE_NEEDED) {
		if (spnego_ctx != NULL) {
			gss_delete_sec_context(&tmpmin,
					       &spnego_ctx->ctx_handle,
					       GSS_C_NO_BUFFER);
			release_spnego_ctx(&spnego_ctx);
		}
		*context_handle = GSS_C_NO_CONTEXT;
	}
	if (mechtok_in != GSS_C_NO_BUFFER) {
		gss_release_buffer(&tmpmin, mechtok_in);
		free(mechtok_in);
	}
	if (mechListMIC_in != GSS_C_NO_BUFFER) {
		gss_release_buffer(&tmpmin, mechListMIC_in);
		free(mechListMIC_in);
	}
	if (mechListMIC_out != GSS_C_NO_BUFFER) {
		gss_release_buffer(&tmpmin, mechListMIC_out);
		free(mechListMIC_out);
	}
	if (mechSet != GSS_C_NO_OID_SET) {
		gss_release_oid_set(&tmpmin, &mechSet);
	}
	return ret;
} /* init_sec_context */

/* We don't want to import KRB5 headers here */
static const gss_OID_desc gss_mech_krb5_oid =
	{ 9, "\052\206\110\206\367\022\001\002\002" };
static const gss_OID_desc gss_mech_krb5_wrong_oid =
	{ 9, "\052\206\110\202\367\022\001\002\002" };

/*
 * verify that the input token length is not 0. If it is, just return.
 * If the token length is greater than 0, der encode as a sequence
 * and place in buf_out, advancing buf_out.
 */

static int
put_neg_hints(unsigned char **buf_out, gss_buffer_t input_token,
	      unsigned int buflen)
{
	int ret;

	/* if token length is 0, we do not want to send */
	if (input_token->length == 0)
		return (0);

	if (input_token->length > buflen)
		return (-1);

	*(*buf_out)++ = SEQUENCE;
	if ((ret = gssint_put_der_length(input_token->length, buf_out,
			    input_token->length)))
		return (ret);
	TWRITE_STR(*buf_out, input_token->value, input_token->length);
	return (0);
}

/*
 * NegHints ::= SEQUENCE {
 *    hintName       [0]  GeneralString      OPTIONAL,
 *    hintAddress    [1]  OCTET STRING       OPTIONAL
 * }
 */

#define HOST_PREFIX	"host@"
#define HOST_PREFIX_LEN	(sizeof(HOST_PREFIX) - 1)

static int
make_NegHints(OM_uint32 *minor_status,
	      gss_cred_id_t cred, gss_buffer_t *outbuf)
{
	gss_buffer_desc hintNameBuf;
	gss_name_t hintName = GSS_C_NO_NAME;
	gss_name_t hintKerberosName;
	gss_OID hintNameType;
	OM_uint32 major_status;
	OM_uint32 minor;
	unsigned int tlen = 0;
	unsigned int hintNameSize = 0;
	unsigned int negHintsSize = 0;
	unsigned char *ptr;
	unsigned char *t;

	*outbuf = GSS_C_NO_BUFFER;

	if (cred != GSS_C_NO_CREDENTIAL) {
		major_status = gss_inquire_cred(minor_status,
						cred,
						&hintName,
						NULL,
						NULL,
						NULL);
		if (major_status != GSS_S_COMPLETE)
			return (major_status);
	}

	if (hintName == GSS_C_NO_NAME) {
		krb5_error_code code;
		krb5int_access kaccess;
		char hostname[HOST_PREFIX_LEN + MAXHOSTNAMELEN + 1] = HOST_PREFIX;

		code = krb5int_accessor(&kaccess, KRB5INT_ACCESS_VERSION);
		if (code != 0) {
			*minor_status = code;
			return (GSS_S_FAILURE);
		}

		/* this breaks mutual authentication but Samba relies on it */
		code = (*kaccess.clean_hostname)(NULL, NULL,
						 &hostname[HOST_PREFIX_LEN],
						 MAXHOSTNAMELEN);
		if (code != 0) {
			*minor_status = code;
			return (GSS_S_FAILURE);
		}

		hintNameBuf.value = hostname;
		hintNameBuf.length = strlen(hostname);

		major_status = gss_import_name(minor_status,
					       &hintNameBuf,
					       GSS_C_NT_HOSTBASED_SERVICE,
					       &hintName);
		if (major_status != GSS_S_COMPLETE) {
			return (major_status);
		}
	}

	hintNameBuf.value = NULL;
	hintNameBuf.length = 0;

	major_status = gss_canonicalize_name(minor_status,
					     hintName,
					     (gss_OID)&gss_mech_krb5_oid,
					     &hintKerberosName);
	if (major_status != GSS_S_COMPLETE) {
		gss_release_name(&minor, &hintName);
		return (major_status);
	}
	gss_release_name(&minor, &hintName);

	major_status = gss_display_name(minor_status,
					hintKerberosName,
					&hintNameBuf,
					&hintNameType);
	if (major_status != GSS_S_COMPLETE) {
		gss_release_name(&minor, &hintKerberosName);
		return (major_status);
	}
	gss_release_name(&minor, &hintKerberosName);

	/*
	 * Now encode the name hint into a NegHints ASN.1 type
	 */
	major_status = GSS_S_FAILURE;

	/* Length of DER encoded GeneralString */
	tlen = 1 + gssint_der_length_size(hintNameBuf.length) +
		hintNameBuf.length;
	hintNameSize = tlen;

	/* Length of DER encoded hintName */
	tlen += 1 + gssint_der_length_size(hintNameSize);
	negHintsSize = tlen;

	t = (unsigned char *)malloc(tlen);
	if (t == NULL) {
		*minor_status = ENOMEM;
		goto errout;
	}

	ptr = t;

	*ptr++ = CONTEXT | 0x00; /* hintName identifier */
	if (gssint_put_der_length(hintNameSize,
				  &ptr, tlen - (int)(ptr-t)))
		goto errout;

	*ptr++ = GENERAL_STRING;
	if (gssint_put_der_length(hintNameBuf.length,
				  &ptr, tlen - (int)(ptr-t)))
		goto errout;

	memcpy(ptr, hintNameBuf.value, hintNameBuf.length);
	ptr += hintNameBuf.length;

	*outbuf = (gss_buffer_t)malloc(sizeof(gss_buffer_desc));
	if (*outbuf == NULL) {
		*minor_status = ENOMEM;
		goto errout;
	}
	(*outbuf)->value = (void *)t;
	(*outbuf)->length = ptr - t;

	t = NULL; /* don't free */

	*minor_status = 0;
	major_status = GSS_S_COMPLETE;

errout:
	if (t != NULL) {
		free(t);
	}

	gss_release_buffer(&minor, &hintNameBuf);
	return (major_status);
}

static OM_uint32
acc_ctx_hints(OM_uint32 *minor_status,
	      gss_ctx_id_t *ctx,
	      gss_cred_id_t cred,
	      gss_buffer_t *mechListMIC,
	      OM_uint32 *negState,
	      send_token_flag *return_token)
{
	OM_uint32 tmpmin, ret;
	gss_OID_set supported_mechSet;
	spnego_gss_ctx_id_t sc = NULL;

	*mechListMIC = GSS_C_NO_BUFFER;
	supported_mechSet = GSS_C_NO_OID_SET;
	*return_token = ERROR_TOKEN_SEND;
	*negState = REJECT;
	*minor_status = 0;

	*ctx = GSS_C_NO_CONTEXT;
	ret = GSS_S_DEFECTIVE_TOKEN;

	if (cred != GSS_C_NO_CREDENTIAL) {
		ret = gss_inquire_cred(minor_status, cred, NULL, NULL,
				       NULL, &supported_mechSet);
		if (ret != GSS_S_COMPLETE) {
			*return_token = NO_TOKEN_SEND;
			goto cleanup;
		}
	} else {
		ret = get_available_mechs(minor_status, GSS_C_NO_NAME,
					  GSS_C_ACCEPT, NULL,
					  &supported_mechSet);
		if (ret != GSS_S_COMPLETE) {
			*return_token = NO_TOKEN_SEND;
			goto cleanup;
		}
	}

	ret = make_NegHints(minor_status, cred, mechListMIC);
	if (ret != GSS_S_COMPLETE) {
		*return_token = NO_TOKEN_SEND;
		goto cleanup;
	}

	/*
	 * Select the best match between the list of mechs
	 * that the initiator requested and the list that
	 * the acceptor will support.
	 */
	sc = create_spnego_ctx();
	if (sc == NULL) {
		ret = GSS_S_FAILURE;
		*return_token = NO_TOKEN_SEND;
		goto cleanup;
	}
	if (put_mech_set(supported_mechSet, &sc->DER_mechTypes) < 0) {
		ret = GSS_S_FAILURE;
		*return_token = NO_TOKEN_SEND;
		goto cleanup;
	}
	sc->internal_mech = GSS_C_NO_OID;

	*negState = ACCEPT_INCOMPLETE;
	*return_token = INIT_TOKEN_SEND;
	sc->firstpass = 1;
	*ctx = (gss_ctx_id_t)sc;
	ret = GSS_S_COMPLETE;

cleanup:
	gss_release_oid_set(&tmpmin, &supported_mechSet);
	return ret;
}

/*
 * Solaris SPNEGO
 * mechoidset2str()
 * Input an OID set of mechs and output a string like so:
 *   '{ x y z } (mechname0), { a b c } (mechname1) ...'.
 * On error return NULL.
 * Caller needs to free returned string.
 */
static const char *mech_no_map = "Can't map OID to mechname via /etc/gss/mech";
static const char *oid_no_map = "Can't map OID to string";
static char *
mechoidset2str(gss_OID_set mechset)
{
	int i, l;
	char buf[256] = {0};
	char *s = NULL;

	if (!mechset)
		return NULL;

	for (i = 0; i < mechset->count; i++) {
		OM_uint32 maj, min;
		gss_buffer_desc oidstr;
		gss_buffer_t oidstrp = &oidstr;
		gss_OID mech_oid = &mechset->elements[i];
		/* No need to free mech_name. */
		const char *mech_name = __gss_oid_to_mech(mech_oid);

		if (i > 0)
			if (strlcat(buf, ", ", sizeof (buf)) >= sizeof (buf)) {
				if (oidstrp->value)
					gss_release_buffer(&min, oidstrp);
				break;
			}

		/* Add '{ x y x ... }'. */
		maj = gss_oid_to_str(&min, mech_oid, oidstrp);
		if (strlcat(buf, maj ? oid_no_map : oidstrp->value,
			    sizeof (buf)) >= sizeof (buf)) {
			if (oidstrp->value)
				gss_release_buffer(&min, oidstrp);
			break;
		}
		if (oidstrp->value)
			gss_release_buffer(&min, oidstrp);

		/* Add '(mech name)'. */
		if (strlcat(buf, " (", sizeof (buf)) >= sizeof (buf))
			break;
		if (strlcat(buf, mech_name ? mech_name : mech_no_map,
			    sizeof (buf)) >= sizeof (buf))
			break;
		if (strlcat(buf, ") ", sizeof (buf)) >= sizeof (buf))
			break;
	}

	/* Even if we have buf overflow, let's output what we got so far. */
	if (mechset->count) {
		l = strlen(buf);
		if (l > 0) {
			s = malloc(l + 1);
			if (!s)
				return NULL;
			(void) strlcpy(s, buf, l);
		}
	}

	return s ? s : NULL;
}

/*
 * Set negState to REJECT if the token is defective, else
 * ACCEPT_INCOMPLETE or REQUEST_MIC, depending on whether initiator's
 * preferred mechanism is supported.
 */
static OM_uint32
acc_ctx_new(OM_uint32 *minor_status,
	    gss_buffer_t buf,
	    gss_ctx_id_t *ctx,
	    gss_cred_id_t cred,
	    gss_buffer_t *mechToken,
	    gss_buffer_t *mechListMIC,
	    OM_uint32 *negState,
	    send_token_flag *return_token)
{
	OM_uint32 tmpmin, ret, req_flags;
	gss_OID_set supported_mechSet, mechTypes;
	gss_buffer_desc der_mechTypes;
	gss_OID mech_wanted;
	spnego_gss_ctx_id_t sc = NULL;

	ret = GSS_S_DEFECTIVE_TOKEN;
	der_mechTypes.length = 0;
	der_mechTypes.value = NULL;
	*mechToken = *mechListMIC = GSS_C_NO_BUFFER;
	supported_mechSet = mechTypes = GSS_C_NO_OID_SET;
	*return_token = ERROR_TOKEN_SEND;
	*negState = REJECT;
	*minor_status = 0;

	ret = get_negTokenInit(minor_status, buf, &der_mechTypes,
			       &mechTypes, &req_flags,
			       mechToken, mechListMIC);
	if (ret != GSS_S_COMPLETE) {
		goto cleanup;
	}
	if (cred != GSS_C_NO_CREDENTIAL) {
		ret = gss_inquire_cred(minor_status, cred, NULL, NULL,
				       NULL, &supported_mechSet);
		if (ret != GSS_S_COMPLETE) {
			*return_token = NO_TOKEN_SEND;
			goto cleanup;
		}
	} else {
		ret = get_available_mechs(minor_status, GSS_C_NO_NAME,
					  GSS_C_ACCEPT, NULL,
					  &supported_mechSet);
		if (ret != GSS_S_COMPLETE) {
			*return_token = NO_TOKEN_SEND;
			goto cleanup;
		}
	}
	/*
	 * Select the best match between the list of mechs
	 * that the initiator requested and the list that
	 * the acceptor will support.
	 */
	mech_wanted = negotiate_mech_type(minor_status,
					supported_mechSet,
					mechTypes,
					negState);
	if (*negState == REJECT) {
		/* Solaris SPNEGO: Spruce-up error msg */
		char *mechTypesStr = mechoidset2str(mechTypes);
		spnego_gss_ctx_id_t tmpsc = create_spnego_ctx();
		if (tmpsc && *minor_status == ERR_SPNEGO_NEGOTIATION_FAILED) {
			spnego_set_error_message(tmpsc, *minor_status,
						dgettext(TEXT_DOMAIN,
							"SPNEGO failed to negotiate a mechanism: client requested mech set '%s'"),
				mechTypesStr ? mechTypesStr : "<null>");
		}
		if (mechTypesStr)
			free(mechTypesStr);

		/*
		 * We save error here cuz the tmp ctx goes away (very) soon.
		 * So callers of acc_ctx_new() should NOT call it again.
		 */
		spnego_gss_save_error_info(*minor_status, tmpsc);
		if (tmpsc)
			release_spnego_ctx(&tmpsc);
		ret = GSS_S_BAD_MECH;
		goto cleanup;
	}

	sc = (spnego_gss_ctx_id_t)*ctx;
	if (sc != NULL) {
		gss_release_buffer(&tmpmin, &sc->DER_mechTypes);
		assert(mech_wanted != GSS_C_NO_OID);
	} else
		sc = create_spnego_ctx();
	if (sc == NULL) {
		ret = GSS_S_FAILURE;
		*return_token = NO_TOKEN_SEND;
		generic_gss_release_oid(&tmpmin, &mech_wanted);
		goto cleanup;
	}
	sc->internal_mech = mech_wanted;
	sc->DER_mechTypes = der_mechTypes;
	der_mechTypes.length = 0;
	der_mechTypes.value = NULL;

	if (*negState == REQUEST_MIC)
		sc->mic_reqd = 1;

	*return_token = INIT_TOKEN_SEND;
	sc->firstpass = 1;
	*ctx = (gss_ctx_id_t)sc;
	ret = GSS_S_COMPLETE;
cleanup:
	gss_release_oid_set(&tmpmin, &mechTypes);
	gss_release_oid_set(&tmpmin, &supported_mechSet);
	if (der_mechTypes.length != 0)
		gss_release_buffer(&tmpmin, &der_mechTypes);
	return ret;
}

static OM_uint32
acc_ctx_cont(OM_uint32 *minstat,
	     gss_buffer_t buf,
	     gss_ctx_id_t *ctx,
	     gss_buffer_t *responseToken,
	     gss_buffer_t *mechListMIC,
	     OM_uint32 *negState,
	     send_token_flag *return_token)
{
	OM_uint32 ret, tmpmin;
	gss_OID supportedMech;
	spnego_gss_ctx_id_t sc;
	unsigned int len;
	unsigned char *ptr, *bufstart;

	sc = (spnego_gss_ctx_id_t)*ctx;
	ret = GSS_S_DEFECTIVE_TOKEN;
	*negState = REJECT;
	*minstat = 0;
	supportedMech = GSS_C_NO_OID;
	*return_token = ERROR_TOKEN_SEND;
	*responseToken = *mechListMIC = GSS_C_NO_BUFFER;

	ptr = bufstart = buf->value;
#define REMAIN (buf->length - (ptr - bufstart))
	if (REMAIN > INT_MAX)
		return GSS_S_DEFECTIVE_TOKEN;

	/*
	 * Attempt to work with old Sun SPNEGO.
	 */
	if (*ptr == HEADER_ID) {
		ret = g_verify_token_header(gss_mech_spnego,
					    &len, &ptr, 0, REMAIN);
		if (ret) {
			*minstat = ret;
			return GSS_S_DEFECTIVE_TOKEN;
		}
	}
	if (*ptr != (CONTEXT | 0x01)) {
		return GSS_S_DEFECTIVE_TOKEN;
	}
	ret = get_negTokenResp(minstat, ptr, REMAIN,
			       negState, &supportedMech,
			       responseToken, mechListMIC);
	if (ret != GSS_S_COMPLETE)
		goto cleanup;

	if (*responseToken == GSS_C_NO_BUFFER &&
	    *mechListMIC == GSS_C_NO_BUFFER) {

		ret = GSS_S_DEFECTIVE_TOKEN;
		goto cleanup;
	}
	if (supportedMech != GSS_C_NO_OID) {
		ret = GSS_S_DEFECTIVE_TOKEN;
		goto cleanup;
	}
	sc->firstpass = 0;
	*negState = ACCEPT_INCOMPLETE;
	*return_token = CONT_TOKEN_SEND;
cleanup:
	if (supportedMech != GSS_C_NO_OID) {
		generic_gss_release_oid(&tmpmin, &supportedMech);
	}
	return ret;
#undef REMAIN
}

/*
 * Verify that mech OID is either exactly the same as the negotiated
 * mech OID, or is a mech OID supported by the negotiated mech.  MS
 * implementations can list a most preferred mech using an incorrect
 * krb5 OID while emitting a krb5 initiator mech token having the
 * correct krb5 mech OID.
 */
static OM_uint32
acc_ctx_vfy_oid(OM_uint32 *minor_status,
		spnego_gss_ctx_id_t sc, gss_OID mechoid,
		OM_uint32 *negState, send_token_flag *tokflag)
{
	OM_uint32 ret, tmpmin;
	gss_mechanism mech = NULL;
	gss_OID_set mech_set = GSS_C_NO_OID_SET;
	int present = 0;

	if (g_OID_equal(sc->internal_mech, mechoid))
		return GSS_S_COMPLETE;

	/*
	 * SUNW17PACresync
	 * If both mechs are kerb, we are done.
	 */
	if (is_kerb_mech(mechoid) && is_kerb_mech(sc->internal_mech)) {
		return GSS_S_COMPLETE;
	}

	mech = gssint_get_mechanism(mechoid);
	if (mech == NULL || mech->gss_indicate_mechs == NULL) {
		*minor_status = ERR_SPNEGO_NEGOTIATION_FAILED;
		{
			/*
			 * Solaris SPNEGO
			 * Spruce-up error msg.
			 */
			OM_uint32 maj, maj_sc, min;
			gss_buffer_desc oidstr, oidstr_sc;
			/* No need to free mnamestr. */
			const char *mnamestr = __gss_oid_to_mech(
				sc->internal_mech);
			maj_sc = gss_oid_to_str(&min,
						sc->internal_mech,
						&oidstr_sc);
			maj = gss_oid_to_str(&min, mechoid, &oidstr);
			spnego_set_error_message(sc, *minor_status,
						dgettext(TEXT_DOMAIN,
							"SPNEGO failed to negotiate a mechanism: unsupported mech OID ('%s') in the token. Negotiated mech OID is '%s' (%s)"),
					maj ? oid_no_map: oidstr.value,
					maj_sc ? oid_no_map: oidstr_sc.value,
					mnamestr ? mnamestr : mech_no_map);
			if (!maj)
			        (void) gss_release_buffer(&min, &oidstr);
			if (!maj_sc)
			        (void) gss_release_buffer(&min, &oidstr_sc);
		}
		map_errcode(minor_status);
		*negState = REJECT;
		*tokflag = ERROR_TOKEN_SEND;
		return GSS_S_BAD_MECH;
	}
	ret = mech->gss_indicate_mechs(mech->context, minor_status, &mech_set);
	if (ret != GSS_S_COMPLETE) {
		*tokflag = NO_TOKEN_SEND;
		map_error(minor_status, mech);
		goto cleanup;
	}
	ret = gss_test_oid_set_member(minor_status, sc->internal_mech,
				      mech_set, &present);
	if (ret != GSS_S_COMPLETE)
		goto cleanup;
	if (!present) {
		{
			/*
			 * Solaris SPNEGO
			 * Spruce-up error msg.
			 */
			OM_uint32 maj, min;
			gss_buffer_desc oidstr;
			char *mech_set_str = mechoidset2str(mech_set);
			/* No need to free mnamestr. */
			const char *mnamestr =
				__gss_oid_to_mech(sc->internal_mech);
			maj = gss_oid_to_str(&min, sc->internal_mech, &oidstr);
			*minor_status = ERR_SPNEGO_NEGOTIATION_FAILED;
			spnego_set_error_message(sc, *minor_status,
						dgettext(TEXT_DOMAIN,
							"SPNEGO failed to negotiate a mechanism: negotiated mech OID '%s' (%s) not found in mechset ('%s') of token mech"),
				maj ? oid_no_map: oidstr.value,
				mnamestr ? mnamestr : mech_no_map,
				mech_set_str ? mech_set_str : "<null>");
			if (!maj)
			        (void) gss_release_buffer(&min, &oidstr);
			if (mech_set_str)
				free(mech_set_str);
		}
		map_errcode(minor_status);
		*negState = REJECT;
		*tokflag = ERROR_TOKEN_SEND;
		ret = GSS_S_BAD_MECH;
	}
cleanup:
	gss_release_oid_set(&tmpmin, &mech_set);
	return ret;
}
#ifndef LEAN_CLIENT
/*
 * Wrap call to gss_accept_sec_context() and update state
 * accordingly.
 */
static OM_uint32
acc_ctx_call_acc(OM_uint32 *minor_status, spnego_gss_ctx_id_t sc,
		 gss_cred_id_t cred, gss_buffer_t mechtok_in,
		 gss_OID *mech_type, gss_buffer_t mechtok_out,
		 OM_uint32 *ret_flags, OM_uint32 *time_rec,
		 gss_cred_id_t *delegated_cred_handle,
		 OM_uint32 *negState, send_token_flag *tokflag)
{
	OM_uint32 ret;
	gss_OID_desc mechoid;

	if (sc->ctx_handle == GSS_C_NO_CONTEXT) {
		/*
		 * mechoid is an alias; don't free it.
		 */
		ret = gssint_get_mech_type(&mechoid, mechtok_in);
		if (ret != GSS_S_COMPLETE) {
			*tokflag = NO_TOKEN_SEND;
			return ret;
		}
		ret = acc_ctx_vfy_oid(minor_status, sc, &mechoid,
				    negState, tokflag);
		if (ret != GSS_S_COMPLETE)
			return ret;
	}

	ret = gss_accept_sec_context(minor_status,
				     &sc->ctx_handle,
				     cred,
				     mechtok_in,
				     GSS_C_NO_CHANNEL_BINDINGS,
				     &sc->internal_name,
				     mech_type,
				     mechtok_out,
				     &sc->ctx_flags,
				     time_rec,
				     delegated_cred_handle);

	if (ret == GSS_S_COMPLETE) {
#ifdef MS_BUG_TEST
		/*
		 * Force MIC to be not required even if we previously
		 * requested a MIC.
		 */
		char *envstr = getenv("MS_FORCE_NO_MIC");

		if (envstr != NULL && strcmp(envstr, "1") == 0 &&
		    !(sc->ctx_flags & GSS_C_MUTUAL_FLAG) &&
		    sc->mic_reqd) {

			sc->mic_reqd = 0;
		}
#endif
		sc->mech_complete = 1;
		if (ret_flags != NULL)
			*ret_flags = sc->ctx_flags;

		if (!sc->mic_reqd) {
			*negState = ACCEPT_COMPLETE;
			ret = GSS_S_COMPLETE;
		} else {
			ret = GSS_S_CONTINUE_NEEDED;
		}
	} else if (ret != GSS_S_CONTINUE_NEEDED) {
		*negState = REJECT;
		*tokflag = ERROR_TOKEN_SEND;
	}
	return ret;
}

/*ARGSUSED*/
OM_uint32
glue_spnego_gss_accept_sec_context(
			    void *context,
			    OM_uint32 *minor_status,
			    gss_ctx_id_t *context_handle,
			    gss_cred_id_t verifier_cred_handle,
			    gss_buffer_t input_token,
			    gss_channel_bindings_t input_chan_bindings,
			    gss_name_t *src_name,
			    gss_OID *mech_type,
			    gss_buffer_t output_token,
			    OM_uint32 *ret_flags,
			    OM_uint32 *time_rec,
			    gss_cred_id_t *delegated_cred_handle)
{
	return(spnego_gss_accept_sec_context(
		    minor_status,
		    context_handle,
		    verifier_cred_handle,
		    input_token,
		    input_chan_bindings,
		    src_name,
		    mech_type,
		    output_token,
		    ret_flags,
		    time_rec,
		    delegated_cred_handle));
}

/*ARGSUSED*/
OM_uint32
spnego_gss_accept_sec_context(
			    OM_uint32 *minor_status,
			    gss_ctx_id_t *context_handle,
			    gss_cred_id_t verifier_cred_handle,
			    gss_buffer_t input_token,
			    gss_channel_bindings_t input_chan_bindings,
			    gss_name_t *src_name,
			    gss_OID *mech_type,
			    gss_buffer_t output_token,
			    OM_uint32 *ret_flags,
			    OM_uint32 *time_rec,
			    gss_cred_id_t *delegated_cred_handle)
{
	OM_uint32 ret, tmpmin, negState;
	send_token_flag return_token;
	gss_buffer_t mechtok_in, mic_in, mic_out;
	gss_buffer_desc mechtok_out = GSS_C_EMPTY_BUFFER;
	spnego_gss_ctx_id_t sc = NULL;
	OM_uint32 mechstat = GSS_S_FAILURE;
	int sendTokenInit = 0, tmpret;

	mechtok_in = mic_in = mic_out = GSS_C_NO_BUFFER;

	if (minor_status != NULL)
		*minor_status = 0;
	if (output_token != GSS_C_NO_BUFFER) {
		output_token->length = 0;
		output_token->value = NULL;
	}


	if (minor_status == NULL ||
	    output_token == GSS_C_NO_BUFFER ||
	    context_handle == NULL) {
		return GSS_S_CALL_INACCESSIBLE_WRITE;
	}

	if (input_token == GSS_C_NO_BUFFER) {
		return GSS_S_CALL_INACCESSIBLE_READ;
	}

	sc = (spnego_gss_ctx_id_t)*context_handle;
	if (sc == NULL || sc->internal_mech == GSS_C_NO_OID) {
		if (src_name != NULL)
			*src_name = GSS_C_NO_NAME;
		if (mech_type != NULL)
			*mech_type = GSS_C_NO_OID;
		if (time_rec != NULL)
			*time_rec = 0;
		if (ret_flags != NULL)
			*ret_flags = 0;
		if (delegated_cred_handle != NULL)
			*delegated_cred_handle = GSS_C_NO_CREDENTIAL;
		if (input_token->length == 0) {
			ret = acc_ctx_hints(minor_status,
					    context_handle,
					    verifier_cred_handle,
					    &mic_out,
					    &negState,
					    &return_token);
			if (ret != GSS_S_COMPLETE)
				goto cleanup;
			sendTokenInit = 1;
			ret = GSS_S_CONTINUE_NEEDED;
		} else {
			/* Can set negState to REQUEST_MIC */
			ret = acc_ctx_new(minor_status, input_token,
					  context_handle, verifier_cred_handle,
					  &mechtok_in, &mic_in,
					  &negState, &return_token);
			if (ret != GSS_S_COMPLETE)
				goto cleanup;
			ret = GSS_S_CONTINUE_NEEDED;
		}
	} else {
		/* Can set negState to ACCEPT_INCOMPLETE */
		ret = acc_ctx_cont(minor_status, input_token,
				   context_handle, &mechtok_in,
				   &mic_in, &negState, &return_token);
		if (ret != GSS_S_COMPLETE)
			goto cleanup;
		ret = GSS_S_CONTINUE_NEEDED;
	}

	sc = (spnego_gss_ctx_id_t)*context_handle;
	/*
	 * Handle mechtok_in and mic_in only if they are
	 * present in input_token.  If neither is present, whether
	 * this is an error depends on whether this is the first
	 * round-trip.  RET is set to a default value according to
	 * whether it is the first round-trip.
	 */
	mechstat = GSS_S_FAILURE;
	if (negState != REQUEST_MIC && mechtok_in != GSS_C_NO_BUFFER) {
		ret = acc_ctx_call_acc(minor_status, sc,
				       verifier_cred_handle, mechtok_in,
				       mech_type, &mechtok_out,
				       ret_flags, time_rec,
				       delegated_cred_handle,
				       &negState, &return_token);
	} else if (negState == REQUEST_MIC) {
		mechstat = GSS_S_CONTINUE_NEEDED;
	}

	/* Solaris SPNEGO */
	if (*minor_status == ERR_SPNEGO_NEGOTIATION_FAILED)
		spnego_gss_save_error_info(*minor_status, sc);

	if (!HARD_ERROR(ret) && sc->mech_complete &&
	    (sc->ctx_flags & GSS_C_INTEG_FLAG)) {

		ret = handle_mic(minor_status, mic_in,
				 (mechtok_out.length != 0),
				 sc, &mic_out,
				 &negState, &return_token);
	}

cleanup:
	if (return_token == INIT_TOKEN_SEND && sendTokenInit) {
		assert(sc != NULL);
		tmpret = make_spnego_tokenInit_msg(sc, 1, mic_out, 0,
						   GSS_C_NO_BUFFER,
						   return_token, output_token);
		if (tmpret < 0)
			ret = GSS_S_FAILURE;
	} else if (return_token != NO_TOKEN_SEND &&
		   return_token != CHECK_MIC) {
		tmpret = make_spnego_tokenTarg_msg(negState,
						   sc ? sc->internal_mech :
						   GSS_C_NO_OID,
						   &mechtok_out, mic_out,
						   return_token,
						   output_token);
		if (tmpret < 0)
			ret = GSS_S_FAILURE;
	}
	if (ret == GSS_S_COMPLETE) {
		*context_handle = (gss_ctx_id_t)sc->ctx_handle;
		if (sc->internal_name != GSS_C_NO_NAME &&
		    src_name != NULL) {
			*src_name = sc->internal_name;
		}
		release_spnego_ctx(&sc);
	}
	gss_release_buffer(&tmpmin, &mechtok_out);
	if (mechtok_in != GSS_C_NO_BUFFER) {
		gss_release_buffer(&tmpmin, mechtok_in);
		free(mechtok_in);
	}
	if (mic_in != GSS_C_NO_BUFFER) {
		gss_release_buffer(&tmpmin, mic_in);
		free(mic_in);
	}
	if (mic_out != GSS_C_NO_BUFFER) {
		gss_release_buffer(&tmpmin, mic_out);
		free(mic_out);
	}
	return ret;
}
#endif /*  LEAN_CLIENT */

/*ARGSUSED*/
OM_uint32
glue_spnego_gss_display_status(
	void *context,
		OM_uint32 *minor_status,
		OM_uint32 status_value,
		int status_type,
		gss_OID mech_type,
		OM_uint32 *message_context,
		gss_buffer_t status_string)
{
	return (spnego_gss_display_status(minor_status,
					status_value,
					status_type,
					mech_type,
					message_context,
					status_string));
}

/*ARGSUSED*/
OM_uint32
spnego_gss_display_status(
		OM_uint32 *minor_status,
		OM_uint32 status_value,
		int status_type,
		gss_OID mech_type,
		OM_uint32 *message_context,
		gss_buffer_t status_string)
{
	dsyslog("Entering display_status\n");

	*message_context = 0;
	switch (status_value) {
	    case ERR_SPNEGO_NO_MECHS_AVAILABLE:
		/* CSTYLED */
		*status_string = make_err_msg("SPNEGO cannot find mechanisms to negotiate");
		break;
	    case ERR_SPNEGO_NO_CREDS_ACQUIRED:
		/* CSTYLED */
		*status_string = make_err_msg("SPNEGO failed to acquire creds");
		break;
	    case ERR_SPNEGO_NO_MECH_FROM_ACCEPTOR:
		/* CSTYLED */
		*status_string = make_err_msg("SPNEGO acceptor did not select a mechanism");
		break;
	    case ERR_SPNEGO_NEGOTIATION_FAILED:
		/* CSTYLED */
		return(spnego_gss_display_status2(minor_status,
						    status_value,
						    status_type,
						    mech_type,
						    message_context,
						    status_string));
	    case ERR_SPNEGO_NO_TOKEN_FROM_ACCEPTOR:
		/* CSTYLED */
		*status_string = make_err_msg("SPNEGO acceptor did not return a valid token");
		break;
	    default:
		/*
		 * Solaris SPNEGO
		 * If mech_spnego calls mech_krb5 (via libgss) and an
		 * error occurs there, give it a shot.
		 */
		/* CSTYLED */
		return(krb5_gss_display_status2(minor_status,
						status_value,
						status_type,
						(gss_OID)&gss_mech_krb5_oid,
						message_context,
						status_string));

	}

	dsyslog("Leaving display_status\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
glue_spnego_gss_import_name(
	void *context,
		    OM_uint32 *minor_status,
		    gss_buffer_t input_name_buffer,
		    gss_OID input_name_type,
		    gss_name_t *output_name)
{
	return(spnego_gss_import_name(minor_status,
				    input_name_buffer,
				    input_name_type,
				    output_name));
}

/*ARGSUSED*/
OM_uint32
spnego_gss_import_name(
		    OM_uint32 *minor_status,
		    gss_buffer_t input_name_buffer,
		    gss_OID input_name_type,
		    gss_name_t *output_name)
{
	OM_uint32 status;

	dsyslog("Entering import_name\n");

	status = gss_import_name(minor_status, input_name_buffer,
			input_name_type, output_name);

	dsyslog("Leaving import_name\n");
	return (status);
}

/*ARGSUSED*/
OM_uint32
glue_spnego_gss_release_name(
	void *context,
			OM_uint32 *minor_status,
			gss_name_t *input_name)
{
	return(spnego_gss_release_name(minor_status, input_name));
}

/*ARGSUSED*/
OM_uint32
spnego_gss_release_name(
			OM_uint32 *minor_status,
			gss_name_t *input_name)
{
	OM_uint32 status;

	dsyslog("Entering release_name\n");

	status = gss_release_name(minor_status, input_name);

	dsyslog("Leaving release_name\n");
	return (status);
}

/*ARGSUSED*/
OM_uint32
glue_spnego_gss_compare_name(
	void *context,
	OM_uint32 *minor_status,
	const gss_name_t name1,
	const gss_name_t name2,
	int *name_equal)
{
	return(spnego_gss_compare_name(minor_status,
				name1,
				name2,
				name_equal));
}
/*ARGSUSED*/
OM_uint32
spnego_gss_compare_name(
			OM_uint32 *minor_status,
			const gss_name_t name1,
			const gss_name_t name2,
			int *name_equal)
{
	OM_uint32 status = GSS_S_COMPLETE;
	dsyslog("Entering compare_name\n");

	status = gss_compare_name(minor_status, name1, name2, name_equal);

	dsyslog("Leaving compare_name\n");
	return (status);
}

/*ARGSUSED*/
OM_uint32
glue_spnego_gss_display_name(
 	void *context,
			OM_uint32 *minor_status,
			gss_name_t input_name,
			gss_buffer_t output_name_buffer,
			gss_OID *output_name_type)
{
	return(spnego_gss_display_name(
		    minor_status,
		    input_name,
		    output_name_buffer,
		    output_name_type));
}

/*ARGSUSED*/
OM_uint32
spnego_gss_display_name(
			OM_uint32 *minor_status,
			gss_name_t input_name,
			gss_buffer_t output_name_buffer,
			gss_OID *output_name_type)
{
	OM_uint32 status = GSS_S_COMPLETE;
	dsyslog("Entering display_name\n");

	status = gss_display_name(minor_status, input_name,
			output_name_buffer, output_name_type);

	dsyslog("Leaving display_name\n");
	return (status);
}


/*ARGSUSED*/
OM_uint32
glue_spnego_gss_inquire_names_for_mech(
	void		*context,
	OM_uint32	*minor_status,
	gss_OID		mechanism,
	gss_OID_set	*name_types)
{
	return(spnego_gss_inquire_names_for_mech(minor_status,
						mechanism,
						name_types));
}
/*ARGSUSED*/
OM_uint32
spnego_gss_inquire_names_for_mech(
				OM_uint32	*minor_status,
				gss_OID		mechanism,
				gss_OID_set	*name_types)
{
	OM_uint32   major, minor;

	dsyslog("Entering inquire_names_for_mech\n");
	/*
	 * We only know how to handle our own mechanism.
	 */
	if ((mechanism != GSS_C_NULL_OID) &&
	    !g_OID_equal(gss_mech_spnego, mechanism)) {
		*minor_status = 0;
		return (GSS_S_FAILURE);
	}

	major = gss_create_empty_oid_set(minor_status, name_types);
	if (major == GSS_S_COMPLETE) {
		/* Now add our members. */
		if (((major = gss_add_oid_set_member(minor_status,
				(gss_OID) GSS_C_NT_USER_NAME,
				name_types)) == GSS_S_COMPLETE) &&
		    ((major = gss_add_oid_set_member(minor_status,
				(gss_OID) GSS_C_NT_MACHINE_UID_NAME,
				name_types)) == GSS_S_COMPLETE) &&
		    ((major = gss_add_oid_set_member(minor_status,
				(gss_OID) GSS_C_NT_STRING_UID_NAME,
				name_types)) == GSS_S_COMPLETE)) {
			major = gss_add_oid_set_member(minor_status,
				(gss_OID) GSS_C_NT_HOSTBASED_SERVICE,
				name_types);
		}

		if (major != GSS_S_COMPLETE)
			(void) gss_release_oid_set(&minor, name_types);
	}

	dsyslog("Leaving inquire_names_for_mech\n");
	return (major);
}

OM_uint32
spnego_gss_unwrap(
		OM_uint32 *minor_status,
		gss_ctx_id_t context_handle,
		gss_buffer_t input_message_buffer,
		gss_buffer_t output_message_buffer,
		int *conf_state,
		gss_qop_t *qop_state)
{
	OM_uint32 ret;
	ret = gss_unwrap(minor_status,
			context_handle,
			input_message_buffer,
			output_message_buffer,
			conf_state,
			qop_state);

	return (ret);
}

OM_uint32
spnego_gss_wrap(
		OM_uint32 *minor_status,
		gss_ctx_id_t context_handle,
		int conf_req_flag,
		gss_qop_t qop_req,
		gss_buffer_t input_message_buffer,
		int *conf_state,
		gss_buffer_t output_message_buffer)
{
	OM_uint32 ret;
	ret = gss_wrap(minor_status,
		    context_handle,
		    conf_req_flag,
		    qop_req,
		    input_message_buffer,
		    conf_state,
		    output_message_buffer);

	return (ret);
}

OM_uint32
spnego_gss_process_context_token(
				OM_uint32	*minor_status,
				const gss_ctx_id_t context_handle,
				const gss_buffer_t token_buffer)
{
	OM_uint32 ret;
	ret = gss_process_context_token(minor_status,
					context_handle,
					token_buffer);

	return (ret);
}

OM_uint32
glue_spnego_gss_delete_sec_context(
	void *context,
			    OM_uint32 *minor_status,
			    gss_ctx_id_t *context_handle,
			    gss_buffer_t output_token)
{
	return(spnego_gss_delete_sec_context(minor_status,
					    context_handle, output_token));
}

OM_uint32
spnego_gss_delete_sec_context(
			    OM_uint32 *minor_status,
			    gss_ctx_id_t *context_handle,
			    gss_buffer_t output_token)
{
	OM_uint32 ret = GSS_S_COMPLETE;
	spnego_gss_ctx_id_t *ctx =
		    (spnego_gss_ctx_id_t *)context_handle;

	if (context_handle == NULL)
		return (GSS_S_FAILURE);

	/*
	 * If this is still an SPNEGO mech, release it locally.
	 */
	if (*ctx != NULL &&
	    (*ctx)->magic_num == SPNEGO_MAGIC_ID) {
		(void) release_spnego_ctx(ctx);
                /* SUNW17PACresync - MIT 1.7 bug (and our fix) */
		if (output_token) {
			output_token->length = 0; 
			output_token->value = NULL;
		}
	} else {
		ret = gss_delete_sec_context(minor_status,
				    context_handle,
				    output_token);
	}

	return (ret);
}

OM_uint32
glue_spnego_gss_context_time(
	void *context,
	OM_uint32	*minor_status,
	const gss_ctx_id_t context_handle,
	OM_uint32	*time_rec)
{
	return(spnego_gss_context_time(minor_status,
				    context_handle,
				    time_rec));
}

OM_uint32
spnego_gss_context_time(
			OM_uint32	*minor_status,
			const gss_ctx_id_t context_handle,
			OM_uint32	*time_rec)
{
	OM_uint32 ret;
	ret = gss_context_time(minor_status,
			    context_handle,
			    time_rec);
	return (ret);
}

#ifndef LEAN_CLIENT
OM_uint32
glue_spnego_gss_export_sec_context(
	void *context,
	OM_uint32	  *minor_status,
	gss_ctx_id_t *context_handle,
	gss_buffer_t interprocess_token)
{
	return(spnego_gss_export_sec_context(minor_status,
				    context_handle,
				    interprocess_token));
}
OM_uint32
spnego_gss_export_sec_context(
			    OM_uint32	  *minor_status,
			    gss_ctx_id_t *context_handle,
			    gss_buffer_t interprocess_token)
{
	OM_uint32 ret;
	ret = gss_export_sec_context(minor_status,
				    context_handle,
				    interprocess_token);
	return (ret);
}

OM_uint32
glue_spnego_gss_import_sec_context(
	void *context,
	OM_uint32		*minor_status,
	const gss_buffer_t	interprocess_token,
	gss_ctx_id_t		*context_handle)
{
	return(spnego_gss_import_sec_context(minor_status,
				    interprocess_token,
				    context_handle));
}
OM_uint32
spnego_gss_import_sec_context(
	OM_uint32		*minor_status,
	const gss_buffer_t	interprocess_token,
	gss_ctx_id_t		*context_handle)
{
	OM_uint32 ret;
	ret = gss_import_sec_context(minor_status,
				    interprocess_token,
				    context_handle);
	return (ret);
}
#endif /* LEAN_CLIENT */

OM_uint32
glue_spnego_gss_inquire_context(
	void *context,
			OM_uint32	*minor_status,
			const gss_ctx_id_t context_handle,
			gss_name_t	*src_name,
			gss_name_t	*targ_name,
			OM_uint32	*lifetime_rec,
			gss_OID		*mech_type,
			OM_uint32	*ctx_flags,
			int		*locally_initiated,
			int		*opened)
{
	return(spnego_gss_inquire_context(
		    minor_status,
		    context_handle,
		    src_name,
		    targ_name,
		    lifetime_rec,
		    mech_type,
		    ctx_flags,
		    locally_initiated,
		    opened));
}

OM_uint32
spnego_gss_inquire_context(
			OM_uint32	*minor_status,
			const gss_ctx_id_t context_handle,
			gss_name_t	*src_name,
			gss_name_t	*targ_name,
			OM_uint32	*lifetime_rec,
			gss_OID		*mech_type,
			OM_uint32	*ctx_flags,
			int		*locally_initiated,
			int		*opened)
{
	OM_uint32 ret = GSS_S_COMPLETE;

	ret = gss_inquire_context(minor_status,
				context_handle,
				src_name,
				targ_name,
				lifetime_rec,
				mech_type,
				ctx_flags,
				locally_initiated,
				opened);

	return (ret);
}

OM_uint32
glue_spnego_gss_wrap_size_limit(
	void *context,
	OM_uint32	*minor_status,
	const gss_ctx_id_t context_handle,
	int		conf_req_flag,
	gss_qop_t	qop_req,
	OM_uint32	req_output_size,
	OM_uint32	*max_input_size)
{
	return(spnego_gss_wrap_size_limit(minor_status,
				context_handle,
				conf_req_flag,
				qop_req,
				req_output_size,
				max_input_size));
}

OM_uint32
spnego_gss_wrap_size_limit(
	OM_uint32	*minor_status,
	const gss_ctx_id_t context_handle,
	int		conf_req_flag,
	gss_qop_t	qop_req,
	OM_uint32	req_output_size,
	OM_uint32	*max_input_size)
{
	OM_uint32 ret;
	ret = gss_wrap_size_limit(minor_status,
				context_handle,
				conf_req_flag,
				qop_req,
				req_output_size,
				max_input_size);
	return (ret);
}

#if 0 /* SUNW17PACresync */
OM_uint32
spnego_gss_get_mic(
		OM_uint32 *minor_status,
		const gss_ctx_id_t context_handle,
		gss_qop_t  qop_req,
		const gss_buffer_t message_buffer,
		gss_buffer_t message_token)
{
	OM_uint32 ret;
	ret = gss_get_mic(minor_status,
		    context_handle,
		    qop_req,
		    message_buffer,
		    message_token);
	return (ret);
}
#endif

OM_uint32
spnego_gss_verify_mic(
		OM_uint32 *minor_status,
		const gss_ctx_id_t context_handle,
		const gss_buffer_t msg_buffer,
		const gss_buffer_t token_buffer,
		gss_qop_t *qop_state)
{
	OM_uint32 ret;
	ret = gss_verify_mic(minor_status,
			    context_handle,
			    msg_buffer,
			    token_buffer,
			    qop_state);
	return (ret);
}

OM_uint32
spnego_gss_inquire_sec_context_by_oid(
		OM_uint32 *minor_status,
		const gss_ctx_id_t context_handle,
		const gss_OID desired_object,
		gss_buffer_set_t *data_set)
{
	OM_uint32 ret;
	ret = gss_inquire_sec_context_by_oid(minor_status,
			    context_handle,
			    desired_object,
			    data_set);
	return (ret);
}

/*
 * SUNW17PACresync
 * These GSS funcs not needed yet, so disable them.
 * Revisit for full 1.7 resync.
 */
#if 0
OM_uint32
spnego_gss_set_sec_context_option(
		OM_uint32 *minor_status,
		gss_ctx_id_t *context_handle,
		const gss_OID desired_object,
		const gss_buffer_t value)
{
	OM_uint32 ret;
	ret = gss_set_sec_context_option(minor_status,
			    context_handle,
			    desired_object,
			    value);
	return (ret);
}

OM_uint32
spnego_gss_wrap_aead(OM_uint32 *minor_status,
		     gss_ctx_id_t context_handle,
		     int conf_req_flag,
		     gss_qop_t qop_req,
		     gss_buffer_t input_assoc_buffer,
		     gss_buffer_t input_payload_buffer,
		     int *conf_state,
		     gss_buffer_t output_message_buffer)
{
	OM_uint32 ret;
	ret = gss_wrap_aead(minor_status,
			    context_handle,
			    conf_req_flag,
			    qop_req,
			    input_assoc_buffer,
			    input_payload_buffer,
			    conf_state,
			    output_message_buffer);

	return (ret);
}

OM_uint32
spnego_gss_unwrap_aead(OM_uint32 *minor_status,
		       gss_ctx_id_t context_handle,
		       gss_buffer_t input_message_buffer,
		       gss_buffer_t input_assoc_buffer,
		       gss_buffer_t output_payload_buffer,
		       int *conf_state,
		       gss_qop_t *qop_state)
{
	OM_uint32 ret;
	ret = gss_unwrap_aead(minor_status,
			      context_handle,
			      input_message_buffer,
			      input_assoc_buffer,
			      output_payload_buffer,
			      conf_state,
			      qop_state);
	return (ret);
}

OM_uint32
spnego_gss_wrap_iov(OM_uint32 *minor_status,
		    gss_ctx_id_t context_handle,
		    int conf_req_flag,
		    gss_qop_t qop_req,
		    int *conf_state,
		    gss_iov_buffer_desc *iov,
		    int iov_count)
{
	OM_uint32 ret;
	ret = gss_wrap_iov(minor_status,
			   context_handle,
			   conf_req_flag,
			   qop_req,
			   conf_state,
			   iov,
			   iov_count);
	return (ret);
}

OM_uint32
spnego_gss_unwrap_iov(OM_uint32 *minor_status,
		      gss_ctx_id_t context_handle,
		      int *conf_state,
		      gss_qop_t *qop_state,
		      gss_iov_buffer_desc *iov,
		      int iov_count)
{
	OM_uint32 ret;
	ret = gss_unwrap_iov(minor_status,
			     context_handle,
			     conf_state,
			     qop_state,
			     iov,
			     iov_count);
	return (ret);
}

OM_uint32
spnego_gss_wrap_iov_length(OM_uint32 *minor_status,
			   gss_ctx_id_t context_handle,
			   int conf_req_flag,
			   gss_qop_t qop_req,
			   int *conf_state,
			   gss_iov_buffer_desc *iov,
			   int iov_count)
{
	OM_uint32 ret;
	ret = gss_wrap_iov_length(minor_status,
				  context_handle,
				  conf_req_flag,
				  qop_req,
				  conf_state,
				  iov,
				  iov_count);
	return (ret);
}


OM_uint32
spnego_gss_complete_auth_token(
		OM_uint32 *minor_status,
		const gss_ctx_id_t context_handle,
		gss_buffer_t input_message_buffer)
{
	OM_uint32 ret;
	ret = gss_complete_auth_token(minor_status,
				      context_handle,
				      input_message_buffer);
	return (ret);
}
#endif /* 0 */

/*
 * We will release everything but the ctx_handle so that it
 * can be passed back to init/accept context. This routine should
 * not be called until after the ctx_handle memory is assigned to
 * the supplied context handle from init/accept context.
 */
static void
release_spnego_ctx(spnego_gss_ctx_id_t *ctx)
{
	spnego_gss_ctx_id_t context;
	OM_uint32 minor_stat;
	context = *ctx;

	if (context != NULL) {
		(void) gss_release_buffer(&minor_stat,
					&context->DER_mechTypes);

		(void) generic_gss_release_oid(&minor_stat,
				&context->internal_mech);

		if (context->optionStr != NULL) {
			free(context->optionStr);
			context->optionStr = NULL;
		}
		free(context);
		*ctx = NULL;
	}
}

/*
 * Can't use gss_indicate_mechs by itself to get available mechs for
 * SPNEGO because it will also return the SPNEGO mech and we do not
 * want to consider SPNEGO as an available security mech for
 * negotiation. For this reason, get_available_mechs will return
 * all available mechs except SPNEGO.
 *
 * If a ptr to a creds list is given, this function will attempt
 * to acquire creds for the creds given and trim the list of
 * returned mechanisms to only those for which creds are valid.
 *
 */
static OM_uint32
get_available_mechs(OM_uint32 *minor_status,
	gss_name_t name, gss_cred_usage_t usage,
	gss_cred_id_t *creds, gss_OID_set *rmechs)
{
	unsigned int	i;
	int		found = 0;
	OM_uint32 major_status = GSS_S_COMPLETE, tmpmin;
	gss_OID_set mechs, goodmechs;

	major_status = gss_indicate_mechs(minor_status, &mechs);

	if (major_status != GSS_S_COMPLETE) {
		return (major_status);
	}

	major_status = gss_create_empty_oid_set(minor_status, rmechs);

	if (major_status != GSS_S_COMPLETE) {
		(void) gss_release_oid_set(minor_status, &mechs);
		return (major_status);
	}

	for (i = 0; i < mechs->count && major_status == GSS_S_COMPLETE; i++) {
		if ((mechs->elements[i].length
		    != spnego_mechanism.mech_type.length) ||
		    memcmp(mechs->elements[i].elements,
			spnego_mechanism.mech_type.elements,
			spnego_mechanism.mech_type.length)) {
			/*
			 * Solaris SPNEGO Kerberos: gss_indicate_mechs is stupid as
			 * it never inferences any of the related OIDs of the
			 * mechanisms configured, e.g. KRB5_OLD, KRB5_WRONG.
			 * We add KRB5_WRONG here so that old MS clients can
			 * negotiate this mechanism, which allows extensions
			 * in Kerberos (clock skew adjustment, refresh ccache).
			 */
			if (is_kerb_mech(&mechs->elements[i])) {
			    extern gss_OID_desc * const gss_mech_krb5_wrong;

				major_status =
				  gss_add_oid_set_member(minor_status,
				  gss_mech_krb5_wrong, rmechs);
			}

			major_status = gss_add_oid_set_member(minor_status,
							      &mechs->elements[i],
							      rmechs);
			if (major_status == GSS_S_COMPLETE)
				found++;
		}
	}

	/*
	 * If the caller wanted a list of creds returned,
	 * trim the list of mechanisms down to only those
	 * for which the creds are valid.
	 */
	if (found > 0 && major_status == GSS_S_COMPLETE && creds != NULL) {
		major_status = gss_acquire_cred(minor_status,
						name, GSS_C_INDEFINITE, 
						*rmechs, usage, creds,
						&goodmechs, NULL);

		/*
		 * Drop the old list in favor of the new
		 * "trimmed" list.
		 */
		(void) gss_release_oid_set(&tmpmin, rmechs);
		if (major_status == GSS_S_COMPLETE) {
			(void) gssint_copy_oid_set(&tmpmin,
					goodmechs, rmechs);
			(void) gss_release_oid_set(&tmpmin, &goodmechs);
		}
	}

	(void) gss_release_oid_set(&tmpmin, &mechs);
	if (found == 0 || major_status != GSS_S_COMPLETE) {
		*minor_status = ERR_SPNEGO_NO_MECHS_AVAILABLE;
		map_errcode(minor_status);
		if (major_status == GSS_S_COMPLETE)
			major_status = GSS_S_FAILURE;
	}

	return (major_status);
}

/* following are token creation and reading routines */

/*
 * If buff_in is not pointing to a MECH_OID, then return NULL and do not
 * advance the buffer, otherwise, decode the mech_oid from the buffer and
 * place in gss_OID.
 */
static gss_OID
get_mech_oid(OM_uint32 *minor_status, unsigned char **buff_in, size_t length)
{
	OM_uint32	status;
	gss_OID_desc 	toid;
	gss_OID		mech_out = NULL;
	unsigned char		*start, *end;

	if (length < 1 || **buff_in != MECH_OID)
		return (NULL);

	start = *buff_in;
	end = start + length;

	(*buff_in)++;
	toid.length = *(*buff_in)++;

	if ((*buff_in + toid.length) > end)
		return (NULL);

	toid.elements = *buff_in;
	*buff_in += toid.length;

	status = generic_gss_copy_oid(minor_status, &toid, &mech_out);

	if (status != GSS_S_COMPLETE) {
		map_errcode(minor_status);
		mech_out = NULL;
	}

	return (mech_out);
}

/*
 * der encode the given mechanism oid into buf_out, advancing the
 * buffer pointer.
 */

static int
put_mech_oid(unsigned char **buf_out, gss_OID_const mech, unsigned int buflen)
{
	if (buflen < mech->length + 2)
		return (-1);
	*(*buf_out)++ = MECH_OID;
	*(*buf_out)++ = (unsigned char) mech->length;
	memcpy((void *)(*buf_out), mech->elements, mech->length);
	*buf_out += mech->length;
	return (0);
}

/*
 * verify that buff_in points to an octet string, if it does not,
 * return NULL and don't advance the pointer. If it is an octet string
 * decode buff_in into a gss_buffer_t and return it, advancing the
 * buffer pointer.
 */
static gss_buffer_t
get_input_token(unsigned char **buff_in, unsigned int buff_length)
{
	gss_buffer_t input_token;
	unsigned int bytes;

	if (**buff_in != OCTET_STRING)
		return (NULL);

	(*buff_in)++;
	input_token = (gss_buffer_t)malloc(sizeof (gss_buffer_desc));

	if (input_token == NULL)
		return (NULL);

	input_token->length = gssint_get_der_length(buff_in, buff_length, &bytes);
	if ((int)input_token->length == -1) {
		free(input_token);
		return (NULL);
	}
	input_token->value = malloc(input_token->length);

	if (input_token->value == NULL) {
		free(input_token);
		return (NULL);
	}

	(void) memcpy(input_token->value, *buff_in, input_token->length);
	*buff_in += input_token->length;
	return (input_token);
}

/*
 * verify that the input token length is not 0. If it is, just return.
 * If the token length is greater than 0, der encode as an octet string
 * and place in buf_out, advancing buf_out.
 */

static int
put_input_token(unsigned char **buf_out, gss_buffer_t input_token,
		unsigned int buflen)
{
	int ret;

	/* if token length is 0, we do not want to send */
	if (input_token->length == 0)
		return (0);

	if (input_token->length > buflen)
		return (-1);

	*(*buf_out)++ = OCTET_STRING;
	if ((ret = gssint_put_der_length(input_token->length, buf_out,
			    input_token->length)))
		return (ret);
	TWRITE_STR(*buf_out, input_token->value, input_token->length);
	return (0);
}

/*
 * verify that buff_in points to a sequence of der encoding. The mech
 * set is the only sequence of encoded object in the token, so if it is
 * a sequence of encoding, decode the mechset into a gss_OID_set and
 * return it, advancing the buffer pointer.
 */
static gss_OID_set
get_mech_set(OM_uint32 *minor_status, unsigned char **buff_in,
	     unsigned int buff_length)
{
	gss_OID_set returned_mechSet;
	OM_uint32 major_status;
	int length; /* SUNW17PACresync */
	OM_uint32 bytes;
	OM_uint32 set_length;
	unsigned char		*start;
	int i;

	if (**buff_in != SEQUENCE_OF)
		return (NULL);

	start = *buff_in;
	(*buff_in)++;

	length = gssint_get_der_length(buff_in, buff_length, &bytes);
	if (length < 0) /* SUNW17PACresync - MIT17 lacks this check */
		return (NULL);

	major_status = gss_create_empty_oid_set(minor_status,
						&returned_mechSet);
	if (major_status != GSS_S_COMPLETE)
		return (NULL);

	for (set_length = 0, i = 0; set_length < length; i++) {
		gss_OID_desc *temp = get_mech_oid(minor_status, buff_in,
			buff_length - (*buff_in - start));
		if (temp != NULL) {
		    major_status = gss_add_oid_set_member(minor_status,
					temp, &returned_mechSet);
		    if (major_status == GSS_S_COMPLETE) {
			set_length += returned_mechSet->elements[i].length +2;
			if (generic_gss_release_oid(minor_status, &temp))
			    map_errcode(minor_status);
		    }
		}
	}

	return (returned_mechSet);
}

/*
 * Encode mechSet into buf.
 */
static int
put_mech_set(gss_OID_set mechSet, gss_buffer_t buf)
{
	unsigned char *ptr;
	unsigned int i;
	unsigned int tlen, ilen;

	tlen = ilen = 0;
	for (i = 0; i < mechSet->count; i++) {
		/*
		 * 0x06 [DER LEN] [OID]
		 */
		ilen += 1 +
			gssint_der_length_size(mechSet->elements[i].length) +
			mechSet->elements[i].length;
	}
	/*
	 * 0x30 [DER LEN]
	 */
	tlen = 1 + gssint_der_length_size(ilen) + ilen;
	ptr = malloc(tlen);
	if (ptr == NULL)
		return -1;

	buf->value = ptr;
	buf->length = tlen;
#define REMAIN (buf->length - ((unsigned char *)buf->value - ptr))

	*ptr++ = SEQUENCE_OF;
	if (gssint_put_der_length(ilen, &ptr, REMAIN) < 0)
		return -1;
	for (i = 0; i < mechSet->count; i++) {
		if (put_mech_oid(&ptr, &mechSet->elements[i], REMAIN) < 0) {
			return -1;
		}
	}
	return 0;
#undef REMAIN
}

/*
 * Verify that buff_in is pointing to a BIT_STRING with the correct
 * length and padding for the req_flags. If it is, decode req_flags
 * and return them, otherwise, return NULL.
 */
static OM_uint32
get_req_flags(unsigned char **buff_in, OM_uint32 bodysize,
	      OM_uint32 *req_flags)
{
	unsigned int len;

	if (**buff_in != (CONTEXT | 0x01))
		return (0);

	if (g_get_tag_and_length(buff_in, (CONTEXT | 0x01),
				bodysize, &len) < 0)
		return GSS_S_DEFECTIVE_TOKEN;

	if (*(*buff_in)++ != BIT_STRING)
		return GSS_S_DEFECTIVE_TOKEN;

	if (*(*buff_in)++ != BIT_STRING_LENGTH)
		return GSS_S_DEFECTIVE_TOKEN;

	if (*(*buff_in)++ != BIT_STRING_PADDING)
		return GSS_S_DEFECTIVE_TOKEN;

	*req_flags = (OM_uint32) (*(*buff_in)++ >> 1);
	return (0);
}

static OM_uint32
get_negTokenInit(OM_uint32 *minor_status,
		 gss_buffer_t buf,
		 gss_buffer_t der_mechSet,
		 gss_OID_set *mechSet,
		 OM_uint32 *req_flags,
		 gss_buffer_t *mechtok,
		 gss_buffer_t *mechListMIC)
{
	OM_uint32 err;
	unsigned char *ptr, *bufstart;
	unsigned int len;
	gss_buffer_desc tmpbuf;

	*minor_status = 0;
	der_mechSet->length = 0;
	der_mechSet->value = NULL;
	*mechSet = GSS_C_NO_OID_SET;
	*req_flags = 0;
	*mechtok = *mechListMIC = GSS_C_NO_BUFFER;

	ptr = bufstart = buf->value;
	if ((buf->length - (ptr - bufstart)) > INT_MAX)
		return GSS_S_FAILURE;
#define REMAIN (buf->length - (ptr - bufstart))

	err = g_verify_token_header(gss_mech_spnego,
				    &len, &ptr, 0, REMAIN);
	if (err) {
		*minor_status = err;
		map_errcode(minor_status);
		return GSS_S_FAILURE;
	}
	*minor_status = g_verify_neg_token_init(&ptr, REMAIN);
	if (*minor_status) {
		map_errcode(minor_status);
		return GSS_S_FAILURE;
	}

	/* alias into input_token */
	tmpbuf.value = ptr;
	tmpbuf.length = REMAIN;
	*mechSet = get_mech_set(minor_status, &ptr, REMAIN);
	if (*mechSet == NULL)
		return GSS_S_FAILURE;

	tmpbuf.length = ptr - (unsigned char *)tmpbuf.value;
	der_mechSet->value = malloc(tmpbuf.length);
	if (der_mechSet->value == NULL)
		return GSS_S_FAILURE;
	memcpy(der_mechSet->value, tmpbuf.value, tmpbuf.length);
	der_mechSet->length = tmpbuf.length;

	err = get_req_flags(&ptr, REMAIN, req_flags);
	if (err != GSS_S_COMPLETE) {
		return err;
	}
	if (g_get_tag_and_length(&ptr, (CONTEXT | 0x02),
				 REMAIN, &len) >= 0) {
		*mechtok = get_input_token(&ptr, len);
		if (*mechtok == GSS_C_NO_BUFFER) {
			return GSS_S_FAILURE;
		}
	}
	if (g_get_tag_and_length(&ptr, (CONTEXT | 0x03),
				 REMAIN, &len) >= 0) {
		*mechListMIC = get_input_token(&ptr, len);
		if (*mechListMIC == GSS_C_NO_BUFFER) {
			return GSS_S_FAILURE;
		}
	}
	return GSS_S_COMPLETE;
#undef REMAIN
}

static OM_uint32
get_negTokenResp(OM_uint32 *minor_status,
		 unsigned char *buf, unsigned int buflen,
		 OM_uint32 *negState,
		 gss_OID *supportedMech,
		 gss_buffer_t *responseToken,
		 gss_buffer_t *mechListMIC)
{
	unsigned char *ptr, *bufstart;
	unsigned int len;
	int tmplen;
	unsigned int tag, bytes;

	*negState = ACCEPT_DEFECTIVE_TOKEN;
	*supportedMech = GSS_C_NO_OID;
	*responseToken = *mechListMIC = GSS_C_NO_BUFFER;
	ptr = bufstart = buf;
#define REMAIN (buflen - (ptr - bufstart))

	if (g_get_tag_and_length(&ptr, (CONTEXT | 0x01), REMAIN, &len) < 0)
		return GSS_S_DEFECTIVE_TOKEN;
	if (*ptr++ == SEQUENCE) {
		tmplen = gssint_get_der_length(&ptr, REMAIN, &bytes);
		if (tmplen < 0)
			return GSS_S_DEFECTIVE_TOKEN;
	}
	if (REMAIN < 1)
		tag = 0;
	else
		tag = *ptr++;

	if (tag == CONTEXT) {
		tmplen = gssint_get_der_length(&ptr, REMAIN, &bytes);
		if (tmplen < 0)
			return GSS_S_DEFECTIVE_TOKEN;

		if (g_get_tag_and_length(&ptr, ENUMERATED,
					 REMAIN, &len) < 0)
			return GSS_S_DEFECTIVE_TOKEN;

		if (len != ENUMERATION_LENGTH)
			return GSS_S_DEFECTIVE_TOKEN;

		if (REMAIN < 1)
			return GSS_S_DEFECTIVE_TOKEN;
		*negState = *ptr++;

		if (REMAIN < 1)
			tag = 0;
		else
			tag = *ptr++;
	}
	if (tag == (CONTEXT | 0x01)) {
		tmplen = gssint_get_der_length(&ptr, REMAIN, &bytes);
		if (tmplen < 0)
			return GSS_S_DEFECTIVE_TOKEN;

		*supportedMech = get_mech_oid(minor_status, &ptr, REMAIN);
		if (*supportedMech == GSS_C_NO_OID)
			return GSS_S_DEFECTIVE_TOKEN;

		if (REMAIN < 1)
			tag = 0;
		else
			tag = *ptr++;
	}
	if (tag == (CONTEXT | 0x02)) {
		tmplen = gssint_get_der_length(&ptr, REMAIN, &bytes);
		if (tmplen < 0)
			return GSS_S_DEFECTIVE_TOKEN;

		*responseToken = get_input_token(&ptr, REMAIN);
		if (*responseToken == GSS_C_NO_BUFFER)
			return GSS_S_DEFECTIVE_TOKEN;

		if (REMAIN < 1)
			tag = 0;
		else
			tag = *ptr++;
	}
	if (tag == (CONTEXT | 0x03)) {
		tmplen = gssint_get_der_length(&ptr, REMAIN, &bytes);
		if (tmplen < 0)
			return GSS_S_DEFECTIVE_TOKEN;

		*mechListMIC = get_input_token(&ptr, REMAIN);
		if (*mechListMIC == GSS_C_NO_BUFFER)
			return GSS_S_DEFECTIVE_TOKEN;
	}
	return GSS_S_COMPLETE;
#undef REMAIN
}

/*
 * der encode the passed negResults as an ENUMERATED type and
 * place it in buf_out, advancing the buffer.
 */

static int
put_negResult(unsigned char **buf_out, OM_uint32 negResult,
	      unsigned int buflen)
{
	if (buflen < 3)
		return (-1);
	*(*buf_out)++ = ENUMERATED;
	*(*buf_out)++ = ENUMERATION_LENGTH;
	*(*buf_out)++ = (unsigned char) negResult;
	return (0);
}

/*
 * This routine compares the recieved mechset to the mechset that
 * this server can support. It looks sequentially through the mechset
 * and the first one that matches what the server can support is
 * chosen as the negotiated mechanism. If one is found, negResult
 * is set to ACCEPT_INCOMPLETE if it's the first mech, REQUEST_MIC if
 * it's not the first mech, otherwise we return NULL and negResult
 * is set to REJECT.
 *
 * NOTE: There is currently no way to specify a preference order of
 * mechanisms supported by the acceptor.
 */
static gss_OID
negotiate_mech_type(OM_uint32 *minor_status,
		    gss_OID_set supported_mechSet,
		    gss_OID_set mechset,
		    OM_uint32 *negResult)
{
	gss_OID returned_mech;
	OM_uint32 status;
	int present;
	unsigned int i;

	for (i = 0; i < mechset->count; i++) {
		gss_OID mech_oid = &mechset->elements[i];

		/*
		 * Solaris SPNEGO Kerberos: MIT compares against MS' wrong OID, but
		 * we actually want to select it if the client supports, as this
		 * will enable features on MS clients that allow credential
		 * refresh on rekeying and caching system times from servers.
		 */ 
#if 0
		/* Accept wrong mechanism OID from MS clients */
		if (mech_oid->length == gss_mech_krb5_wrong_oid.length &&
		    memcmp(mech_oid->elements, gss_mech_krb5_wrong_oid.elements, mech_oid->length) == 0)
			mech_oid = (gss_OID)&gss_mech_krb5_oid;
#endif

		gss_test_oid_set_member(minor_status, mech_oid, supported_mechSet, &present);
		if (!present)
			continue;

		if (i == 0)
			*negResult = ACCEPT_INCOMPLETE;
		else
			*negResult = REQUEST_MIC;

		status = generic_gss_copy_oid(minor_status,
					      &mechset->elements[i],
					      &returned_mech);
		if (status != GSS_S_COMPLETE) {
			*negResult = REJECT;
			map_errcode(minor_status);
			return (NULL);
		}
		return (returned_mech);
	}
	/* Solaris SPNEGO */
	*minor_status= ERR_SPNEGO_NEGOTIATION_FAILED;

	*negResult = REJECT;
	return (NULL);
}

/*
 * the next two routines make a token buffer suitable for
 * spnego_gss_display_status. These currently take the string
 * in name and place it in the token. Eventually, if
 * spnego_gss_display_status returns valid error messages,
 * these routines will be changes to return the error string.
 */
static spnego_token_t
make_spnego_token(char *name)
{
	return (spnego_token_t)strdup(name);
}

static gss_buffer_desc
make_err_msg(char *name)
{
	gss_buffer_desc buffer;

	if (name == NULL) {
		buffer.length = 0;
		buffer.value = NULL;
	} else {
		buffer.length = strlen(name)+1;
		buffer.value = make_spnego_token(name);
	}

	return (buffer);
}

/*
 * Create the client side spnego token passed back to gss_init_sec_context
 * and eventually up to the application program and over to the server.
 *
 * Use DER rules, definite length method per RFC 2478
 */
static int
make_spnego_tokenInit_msg(spnego_gss_ctx_id_t spnego_ctx,
			  int negHintsCompat,
			  gss_buffer_t mechListMIC, OM_uint32 req_flags,
			  gss_buffer_t data, send_token_flag sendtoken,
			  gss_buffer_t outbuf)
{
	int ret = 0;
	unsigned int tlen, dataLen = 0;
	unsigned int negTokenInitSize = 0;
	unsigned int negTokenInitSeqSize = 0;
	unsigned int negTokenInitContSize = 0;
	unsigned int rspTokenSize = 0;
	unsigned int mechListTokenSize = 0;
	unsigned int micTokenSize = 0;
	unsigned char *t;
	unsigned char *ptr;

	if (outbuf == GSS_C_NO_BUFFER)
		return (-1);

	outbuf->length = 0;
	outbuf->value = NULL;

	/* calculate the data length */

	/*
	 * 0xa0 [DER LEN] [mechTypes]
	 */
	mechListTokenSize = 1 +
		gssint_der_length_size(spnego_ctx->DER_mechTypes.length) +
		spnego_ctx->DER_mechTypes.length;
	dataLen += mechListTokenSize;

	/*
	 * If a token from gss_init_sec_context exists,
	 * add the length of the token + the ASN.1 overhead
	 */
	if (data != NULL) {
		/*
		 * Encoded in final output as:
		 * 0xa2 [DER LEN] 0x04 [DER LEN] [DATA]
		 * -----s--------|--------s2----------
		 */
		rspTokenSize = 1 +
			gssint_der_length_size(data->length) +
			data->length;
		dataLen += 1 + gssint_der_length_size(rspTokenSize) +
			rspTokenSize;
	}

	if (mechListMIC) {
		/*
		 * Encoded in final output as:
		 * 0xa3 [DER LEN] 0x04 [DER LEN] [DATA]
		 *	--s--     -----tlen------------
		 */
		micTokenSize = 1 +
			gssint_der_length_size(mechListMIC->length) +
			mechListMIC->length;
		dataLen += 1 +
			gssint_der_length_size(micTokenSize) +
			micTokenSize;
	}

	/*
	 * Add size of DER encoding
	 * [ SEQUENCE { MechTypeList | ReqFLags | Token | mechListMIC } ]
	 *   0x30 [DER_LEN] [data]
	 *
	 */
	negTokenInitContSize = dataLen;
	negTokenInitSeqSize = 1 + gssint_der_length_size(dataLen) + dataLen;
	dataLen = negTokenInitSeqSize;

	/*
	 * negTokenInitSize indicates the bytes needed to
	 * hold the ASN.1 encoding of the entire NegTokenInit
	 * SEQUENCE.
	 * 0xa0 [DER_LEN] + data
	 *
	 */
	negTokenInitSize = 1 +
		gssint_der_length_size(negTokenInitSeqSize) +
		negTokenInitSeqSize;

	tlen = g_token_size(gss_mech_spnego, negTokenInitSize);

	t = (unsigned char *) malloc(tlen);

	if (t == NULL) {
		return (-1);
	}

	ptr = t;

	/* create the message */
	if ((ret = g_make_token_header(gss_mech_spnego, negTokenInitSize,
			    &ptr, tlen)))
		goto errout;

	*ptr++ = CONTEXT; /* NegotiationToken identifier */
	if ((ret = gssint_put_der_length(negTokenInitSeqSize, &ptr, tlen)))
		goto errout;

	*ptr++ = SEQUENCE;
	if ((ret = gssint_put_der_length(negTokenInitContSize, &ptr,
					 tlen - (int)(ptr-t))))
		goto errout;

	*ptr++ = CONTEXT | 0x00; /* MechTypeList identifier */
	if ((ret = gssint_put_der_length(spnego_ctx->DER_mechTypes.length,
					 &ptr, tlen - (int)(ptr-t))))
		goto errout;

	/* We already encoded the MechSetList */
	(void) memcpy(ptr, spnego_ctx->DER_mechTypes.value,
		      spnego_ctx->DER_mechTypes.length);

	ptr += spnego_ctx->DER_mechTypes.length;

	if (data != NULL) {
		*ptr++ = CONTEXT | 0x02;
		if ((ret = gssint_put_der_length(rspTokenSize,
				&ptr, tlen - (int)(ptr - t))))
			goto errout;

		if ((ret = put_input_token(&ptr, data,
			tlen - (int)(ptr - t))))
			goto errout;
	}

	if (mechListMIC != GSS_C_NO_BUFFER) {
		*ptr++ = CONTEXT | 0x03;
		if ((ret = gssint_put_der_length(micTokenSize,
				&ptr, tlen - (int)(ptr - t))))
			goto errout;

		if (negHintsCompat) {
			ret = put_neg_hints(&ptr, mechListMIC,
					    tlen - (int)(ptr - t));
			if (ret)
				goto errout;
		} else if ((ret = put_input_token(&ptr, mechListMIC,
				tlen - (int)(ptr - t))))
			goto errout;
	}

errout:
	if (ret != 0) {
		if (t)
			free(t);
		t = NULL;
		tlen = 0;
	}
	outbuf->length = tlen;
	outbuf->value = (void *) t;

	return (ret);
}

/*
 * create the server side spnego token passed back to
 * gss_accept_sec_context and eventually up to the application program
 * and over to the client.
 */
static int
make_spnego_tokenTarg_msg(OM_uint32 status, gss_OID mech_wanted,
			  gss_buffer_t data, gss_buffer_t mechListMIC,
			  send_token_flag sendtoken,
			  gss_buffer_t outbuf)
{
	unsigned int tlen = 0;
	unsigned int ret = 0;
	unsigned int NegTokenTargSize = 0;
	unsigned int NegTokenSize = 0;
	unsigned int rspTokenSize = 0;
	unsigned int micTokenSize = 0;
	unsigned int dataLen = 0;
	unsigned char *t;
	unsigned char *ptr;

	if (outbuf == GSS_C_NO_BUFFER)
		return (GSS_S_DEFECTIVE_TOKEN);

	outbuf->length = 0;
	outbuf->value = NULL;

	/*
	 * ASN.1 encoding of the negResult
	 * ENUMERATED type is 3 bytes
	 *  ENUMERATED TAG, Length, Value,
	 * Plus 2 bytes for the CONTEXT id and length.
	 */
	dataLen = 5;

	/*
	 * calculate data length
	 *
	 * If this is the initial token, include length of
	 * mech_type and the negotiation result fields.
	 */
	if (sendtoken == INIT_TOKEN_SEND) {
		int mechlistTokenSize;
		/*
		 * 1 byte for the CONTEXT ID(0xa0),
		 * 1 byte for the OID ID(0x06)
		 * 1 byte for OID Length field
		 * Plus the rest... (OID Length, OID value)
		 */
		mechlistTokenSize = 3 + mech_wanted->length +
			gssint_der_length_size(mech_wanted->length);

		dataLen += mechlistTokenSize;
	}
	if (data != NULL && data->length > 0) {
		/* Length of the inner token */
		rspTokenSize = 1 + gssint_der_length_size(data->length) +
			data->length;

		dataLen += rspTokenSize;

		/* Length of the outer token */
		dataLen += 1 + gssint_der_length_size(rspTokenSize);
	}
	if (mechListMIC != NULL) {

		/* Length of the inner token */
		micTokenSize = 1 + gssint_der_length_size(mechListMIC->length) +
			mechListMIC->length;

		dataLen += micTokenSize;

		/* Length of the outer token */
		dataLen += 1 + gssint_der_length_size(micTokenSize);
	}
	/*
	 * Add size of DER encoded:
	 * NegTokenTarg [ SEQUENCE ] of
	 *    NegResult[0] ENUMERATED {
	 *	accept_completed(0),
	 *	accept_incomplete(1),
	 *	reject(2) }
	 *    supportedMech [1] MechType OPTIONAL,
	 *    responseToken [2] OCTET STRING OPTIONAL,
	 *    mechListMIC   [3] OCTET STRING OPTIONAL
	 *
	 * size = data->length + MechListMic + SupportedMech len +
	 *	Result Length + ASN.1 overhead
	 */
	NegTokenTargSize = dataLen;
	dataLen += 1 + gssint_der_length_size(NegTokenTargSize);

	/*
	 * NegotiationToken [ CHOICE ]{
	 *    negTokenInit  [0]	 NegTokenInit,
	 *    negTokenTarg  [1]	 NegTokenTarg }
	 */
	NegTokenSize = dataLen;
	dataLen += 1 + gssint_der_length_size(NegTokenSize);

	tlen = dataLen;
	t = (unsigned char *) malloc(tlen);

	if (t == NULL) {
		ret = GSS_S_DEFECTIVE_TOKEN;
		goto errout;
	}

	ptr = t;

	/*
	 * Indicate that we are sending CHOICE 1
	 * (NegTokenTarg)
	 */
	*ptr++ = CONTEXT | 0x01;
	if (gssint_put_der_length(NegTokenSize, &ptr, dataLen) < 0) {
		ret = GSS_S_DEFECTIVE_TOKEN;
		goto errout;
	}
	*ptr++ = SEQUENCE;
	if (gssint_put_der_length(NegTokenTargSize, &ptr,
				  tlen - (int)(ptr-t)) < 0) {
		ret = GSS_S_DEFECTIVE_TOKEN;
		goto errout;
	}

	/*
	 * First field of the NegTokenTarg SEQUENCE
	 * is the ENUMERATED NegResult.
	 */
	*ptr++ = CONTEXT;
	if (gssint_put_der_length(3, &ptr,
				  tlen - (int)(ptr-t)) < 0) {
		ret = GSS_S_DEFECTIVE_TOKEN;
		goto errout;
	}
	if (put_negResult(&ptr, status, tlen - (int)(ptr - t)) < 0) {
		ret = GSS_S_DEFECTIVE_TOKEN;
		goto errout;
	}
	if (sendtoken == INIT_TOKEN_SEND) {
		/*
		 * Next, is the Supported MechType
		 */
		*ptr++ = CONTEXT | 0x01;
		if (gssint_put_der_length(mech_wanted->length + 2,
					  &ptr,
					  tlen - (int)(ptr - t)) < 0) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			goto errout;
		}
		if (put_mech_oid(&ptr, mech_wanted,
				 tlen - (int)(ptr - t)) < 0) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			goto errout;
		}
	}
	if (data != NULL && data->length > 0) {
		*ptr++ = CONTEXT | 0x02;
		if (gssint_put_der_length(rspTokenSize, &ptr,
					  tlen - (int)(ptr - t)) < 0) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			goto errout;
		}
		if (put_input_token(&ptr, data,
				    tlen - (int)(ptr - t)) < 0) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			goto errout;
		}
	}
	if (mechListMIC != NULL) {
		*ptr++ = CONTEXT | 0x03;
		if (gssint_put_der_length(micTokenSize, &ptr,
					  tlen - (int)(ptr - t)) < 0) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			goto errout;
		}
		if (put_input_token(&ptr, mechListMIC,
				    tlen - (int)(ptr - t)) < 0) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			goto errout;
		}
	}
	ret = GSS_S_COMPLETE;
errout:
	if (ret != GSS_S_COMPLETE) {
		if (t)
			free(t);
	} else {
		outbuf->length = ptr - t;
		outbuf->value = (void *) t;
	}

	return (ret);
}

/* determine size of token */
static int
g_token_size(gss_OID_const mech, unsigned int body_size)
{
	int hdrsize;

	/*
	 * Initialize the header size to the
	 * MECH_OID byte + the bytes needed to indicate the
	 * length of the OID + the OID itself.
	 *
	 * 0x06 [MECHLENFIELD] MECHDATA
	 */
	hdrsize = 1 + gssint_der_length_size(mech->length) + mech->length;

	/*
	 * Now add the bytes needed for the initial header
	 * token bytes:
	 * 0x60 + [DER_LEN] + HDRSIZE
	 */
	hdrsize += 1 + gssint_der_length_size(body_size + hdrsize);

	return (hdrsize + body_size);
}

/*
 * generate token header.
 *
 * Use DER Definite Length method per RFC2478
 * Use of indefinite length encoding will not be compatible
 * with Microsoft or others that actually follow the spec.
 */
static int
g_make_token_header(gss_OID_const mech,
		    unsigned int body_size,
		    unsigned char **buf,
		    unsigned int totallen)
{
	int ret = 0;
	unsigned int hdrsize;
	unsigned char *p = *buf;

	hdrsize = 1 + gssint_der_length_size(mech->length) + mech->length;

	*(*buf)++ = HEADER_ID;
	if ((ret = gssint_put_der_length(hdrsize + body_size, buf, totallen)))
		return (ret);

	*(*buf)++ = MECH_OID;
	if ((ret = gssint_put_der_length(mech->length, buf,
			    totallen - (int)(p - *buf))))
		return (ret);
	TWRITE_STR(*buf, mech->elements, mech->length);
	return (0);
}

/*
 * NOTE: This checks that the length returned by
 * gssint_get_der_length() is not greater than the number of octets
 * remaining, even though gssint_get_der_length() already checks, in
 * theory.
 */
static int
g_get_tag_and_length(unsigned char **buf, int tag,
		     unsigned int buflen, unsigned int *outlen)
{
	unsigned char *ptr = *buf;
	int ret = -1; /* pessimists, assume failure ! */
	unsigned int encoded_len;
	unsigned int tmplen = 0;

	*outlen = 0;
	if (buflen > 1 && *ptr == tag) {
		ptr++;
		tmplen = gssint_get_der_length(&ptr, buflen - 1,
						&encoded_len);
		if (tmplen < 0) {
			ret = -1;
		} else if (tmplen > buflen - (ptr - *buf)) {
			ret = -1;
		} else
			ret = 0;
	}
	*outlen = tmplen;
	*buf = ptr;
	return (ret);
}

static int
g_verify_neg_token_init(unsigned char **buf_in, unsigned int cur_size)
{
	unsigned char *buf = *buf_in;
	unsigned char *endptr = buf + cur_size;
	unsigned int seqsize;
	int ret = 0;
	unsigned int bytes;

	/*
	 * Verify this is a NegotiationToken type token
	 * - check for a0(context specific identifier)
	 * - get length and verify that enoughd ata exists
	 */
	if (g_get_tag_and_length(&buf, CONTEXT, cur_size, &seqsize) < 0)
		return (G_BAD_TOK_HEADER);

	cur_size = seqsize; /* should indicate bytes remaining */

	/*
	 * Verify the next piece, it should identify this as
	 * a strucure of type NegTokenInit.
	 */
	if (*buf++ == SEQUENCE) {
		if ((seqsize = gssint_get_der_length(&buf, cur_size, &bytes)) < 0)
			return (G_BAD_TOK_HEADER);
		/*
		 * Make sure we have the entire buffer as described
		 */
		if (buf + seqsize > endptr)
			return (G_BAD_TOK_HEADER);
	} else {
		return (G_BAD_TOK_HEADER);
	}

	cur_size = seqsize; /* should indicate bytes remaining */

	/*
	 * Verify that the first blob is a sequence of mechTypes
	 */
	if (*buf++ == CONTEXT) {
		if ((seqsize = gssint_get_der_length(&buf, cur_size, &bytes)) < 0)
			return (G_BAD_TOK_HEADER);
		/*
		 * Make sure we have the entire buffer as described
		 */
		if (buf + bytes > endptr)
			return (G_BAD_TOK_HEADER);
	} else {
		return (G_BAD_TOK_HEADER);
	}

	/*
	 * At this point, *buf should be at the beginning of the
	 * DER encoded list of mech types that are to be negotiated.
	 */
	*buf_in = buf;

	return (ret);

}

/* verify token header. */
static int
g_verify_token_header(gss_OID_const mech,
		    unsigned int *body_size,
		    unsigned char **buf_in,
		    int tok_type,
		    unsigned int toksize)
{
	unsigned char *buf = *buf_in;
	int seqsize;
	gss_OID_desc toid;
	int ret = 0;
	unsigned int bytes;

	if (toksize-- < 1)
		return (G_BAD_TOK_HEADER);

	if (*buf++ != HEADER_ID)
		return (G_BAD_TOK_HEADER);

	if ((seqsize = gssint_get_der_length(&buf, toksize, &bytes)) < 0)
		return (G_BAD_TOK_HEADER);

	if ((seqsize + bytes) != toksize)
		return (G_BAD_TOK_HEADER);

	if (toksize-- < 1)
		return (G_BAD_TOK_HEADER);


	if (*buf++ != MECH_OID)
		return (G_BAD_TOK_HEADER);

	if (toksize-- < 1)
		return (G_BAD_TOK_HEADER);

	toid.length = *buf++;

	if (toksize < toid.length)
		return (G_BAD_TOK_HEADER);
	else
		toksize -= toid.length;

	toid.elements = buf;
	buf += toid.length;

	if (!g_OID_equal(&toid, mech))
		ret = G_WRONG_MECH;

	/*
	 * G_WRONG_MECH is not returned immediately because it's more important
	 * to return G_BAD_TOK_HEADER if the token header is in fact bad
	 */
	if (toksize < 2)
		return (G_BAD_TOK_HEADER);
	else
		toksize -= 2;

	if (!ret) {
		*buf_in = buf;
		*body_size = toksize;
	}

	return (ret);
}

/*
 * Return non-zero if the oid is one of the kerberos mech oids,
 * otherwise return zero.
 *
 * N.B. There are 3 oids that represent the kerberos mech:
 * RFC-specified GSS_MECH_KRB5_OID,
 * Old pre-RFC   GSS_MECH_KRB5_OLD_OID,
 * Incorrect MS  GSS_MECH_KRB5_WRONG_OID
 */

static int
is_kerb_mech(gss_OID oid)
{
	int answer = 0;
	OM_uint32 minor;
	extern const gss_OID_set_desc * const gss_mech_set_krb5_both;
	
	(void) gss_test_oid_set_member(&minor,
		oid, (gss_OID_set)gss_mech_set_krb5_both, &answer);
	
	return (answer);
}
