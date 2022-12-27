/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2000 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "gss_libinit.h"
#include <gssapiP_krb5.h>
#include <k5-int.h>

#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

/*
 * $Id: acquire_cred.c,v 1.25.6.2 2000/05/22 20:41:32 meeroh Exp $
 */

/* ARGSUSED */
static OM_uint32
acquire_accept_cred_with_pw(context, minor_status, desired_name, password, cred)
krb5_context context;
OM_uint32 *minor_status;
krb5_principal desired_name;
const gss_buffer_t password;
krb5_gss_cred_id_rec *cred;
{
	/*
	 * We could add support for this, but we'd need a "memory" based
	 * keytab, which we lack support for.
	 */
	return (GSS_S_UNAVAILABLE);
}

static OM_uint32
acquire_init_cred_with_pw(context, minor_status, desired_name, password, cred)
krb5_context context;
OM_uint32 *minor_status;
krb5_principal desired_name;
const gss_buffer_t password;
krb5_gss_cred_id_rec *cred;
{
	krb5_error_code code = 0;
	krb5_ccache ccache1 = NULL;
	krb5_ccache ccache2 = NULL;
	krb5_creds creds;
	char *pw;

	cred->ccache = NULL;

	if (password == NULL || password->length == 0 ||
	    password->value == NULL)
		pw = strdup("");
	else if (*((char *)password->value + (password->length - 1)) == '\0')
		pw = strdup(password->value);
	else {
		pw = malloc(password->length + 1);
		if (pw == NULL) {
			code = ENOMEM;
			goto out;
		}
		*pw = '\0';
		(void) strlcat(pw, password->value, password->length + 1);
	}

	if (pw == NULL) {
		code = ENOMEM;
		goto out;
	}

	(void) memset(&creds, 0, sizeof (creds));

	code = krb5_get_init_creds_password(context, &creds, desired_name, pw,
			NULL,	/* no prompter callback */
			NULL,	/* no prompter callback data */
			0,	/* start time (now) */
			NULL,	/* target princ; NULL -> TGS */
			NULL);	/* no options; use defaults/config */

	if (code)
		goto out;

	/* Got a TGT, now make a MEMORY ccache, stuff in the TGT */

	if ((code = krb5_cc_resolve(context, "MEMORY:GSSAPI", &ccache1)))
		goto out;

	/*
	 * Weirdness: there's no way to gen a new ccache without first
	 * opening another of well-known name.  A bug in the krb5 API,
	 * really which will have to be fixed in coordination with MIT.
	 *
	 * So we first krb5_cc_resolve() "MEMORY:GSSAPI", then we
	 * krb5_cc_gen_new(), which is a macro that finds the memory
	 * ccache ops from the first ccache but generates a new one.  If
	 * we don't close that first ccache it will leak.
	 */
	ccache2 = ccache1;
	if ((code = krb5_cc_gen_new(context, &ccache2)) != 0)
		goto out;

	(void) krb5_cc_close(context, ccache1);	    /* avoid leak; see above */

	if ((code = krb5_cc_initialize(context, ccache2, creds.client)) != 0)
		goto out;

	if ((code = krb5_cc_store_cred(context, ccache2, &creds)) != 0)
		goto out;

	krb5_free_cred_contents(context, &creds);

	cred->ccache = ccache2;

out:
	if (pw)
		free(pw);

	*minor_status = code;

	if (code == 0)
		return (GSS_S_COMPLETE);

	if (ccache2 != NULL)
		(void) krb5_cc_close(context, ccache2);

	return (GSS_S_FAILURE);
}

/*ARGSUSED*/
OM_uint32
krb5_gss_acquire_cred_with_password(minor_status,
				desired_name, password, time_req,
				desired_mechs, cred_usage,
				output_cred_handle, actual_mechs,
				time_rec)
OM_uint32 *minor_status;
gss_name_t desired_name;
const gss_buffer_t password;
OM_uint32 time_req;
gss_OID_set desired_mechs;
gss_cred_usage_t cred_usage;
gss_cred_id_t *output_cred_handle;
gss_OID_set *actual_mechs;
OM_uint32 *time_rec;
{
	krb5_context context;
	size_t i;
	krb5_gss_cred_id_t cred;
	gss_OID_set ret_mechs = GSS_C_NULL_OID_SET;
	const gss_OID_set_desc  * valid_mechs;
	int req_old, req_new;
	OM_uint32 ret;
	krb5_error_code code;

	if (desired_name == GSS_C_NO_NAME)
		return (GSS_S_BAD_NAME);

	code = gssint_initialize_library();
	if (code) {
		*minor_status = code;
		return (GSS_S_FAILURE);
	}

	code = krb5_gss_init_context(&context);
	if (code) {
		*minor_status = code;
		return (GSS_S_FAILURE);
	}

	/* make sure all outputs are valid */

	*output_cred_handle = NULL;
	if (actual_mechs)
		*actual_mechs = NULL;
	if (time_rec)
		*time_rec = 0;

	/* validate the name */
	if (!kg_validate_name(desired_name)) {
		*minor_status = (OM_uint32) G_VALIDATE_FAILED;
		krb5_free_context(context);
		return (GSS_S_CALL_BAD_STRUCTURE|GSS_S_BAD_NAME);
	}

	/*
	 * verify that the requested mechanism set is the default, or
	 * contains krb5
	 */

	if (desired_mechs == GSS_C_NULL_OID_SET) {
		valid_mechs = gss_mech_set_krb5_both;
		req_old = 1;
		req_new = 1;
	} else {
		req_old = 0;
		req_new = 0;

		for (i = 0; i < desired_mechs->count; i++) {
			if (g_OID_equal(gss_mech_krb5_old,
				    &(desired_mechs->elements[i])))
				req_old++;
			if (g_OID_equal(gss_mech_krb5,
				    &(desired_mechs->elements[i])))
				req_new++;
		}

		if (!req_old && !req_new) {
			*minor_status = 0;
			krb5_free_context(context);
			return (GSS_S_BAD_MECH);
		}
	}

	/* create the gss cred structure */
	if ((cred = (krb5_gss_cred_id_t)
		    xmalloc(sizeof (krb5_gss_cred_id_rec))) == NULL) {
		*minor_status = ENOMEM;
		krb5_free_context(context);
		return (GSS_S_FAILURE);
	}
	memset(cred, 0, sizeof (krb5_gss_cred_id_rec));

	cred->usage = cred_usage;
	cred->princ = NULL;
	cred->prerfc_mech = req_old;
	cred->rfc_mech = req_new;

	cred->keytab = NULL;
	cred->ccache = NULL;

	if ((cred_usage != GSS_C_INITIATE) &&
			(cred_usage != GSS_C_ACCEPT) &&
			(cred_usage != GSS_C_BOTH)) {
		xfree(cred);
		*minor_status = (OM_uint32) G_BAD_USAGE;
		krb5_free_context(context);
		return (GSS_S_FAILURE);
	}

	/*
	 * If requested, acquire credentials for accepting.  This will
	 * fill in cred->princ if the desired_name is not specified.
	 */

	if ((cred_usage == GSS_C_ACCEPT) ||
			(cred_usage == GSS_C_BOTH))
		if ((ret = acquire_accept_cred_with_pw(context, minor_status,
						(krb5_principal) desired_name,
						password, cred))
				!= GSS_S_COMPLETE) {
			if (cred->princ)
				krb5_free_principal(context, cred->princ);
			xfree(cred);
			krb5_free_context(context);
			/* minor_status set by acquire_accept_cred() */
			return (ret);
		}

	/*
	 * If requested, acquire credentials for initiation.  This will
	 * fill in cred->princ if it wasn't set above, and the
	 * desired_name is not specified.
	 */

	if ((cred_usage == GSS_C_INITIATE) ||
			(cred_usage == GSS_C_BOTH))
		if ((ret = acquire_init_cred_with_pw(context, minor_status,
				cred->princ ? cred->princ : (krb5_principal)
				desired_name, password, cred))
				!= GSS_S_COMPLETE) {
			if (cred->keytab)
				(void) krb5_kt_close(context, cred->keytab);
			if (cred->princ)
				krb5_free_principal(context, cred->princ);
			xfree(cred);
			krb5_free_context(context);
			/* minor_status set by acquire_init_cred() */
			return (ret);
		}

	/* if the princ wasn't filled in already, fill it in now */

	if (!cred->princ)
		if ((code = krb5_copy_principal(context, (krb5_principal)
				desired_name, &(cred->princ)))) {
			if (cred->ccache)
				(void) krb5_cc_close(context, cred->ccache);
			if (cred->keytab)
				(void) krb5_kt_close(context, cred->keytab);
			xfree(cred);
			*minor_status = code;
			krb5_free_context(context);
			return (GSS_S_FAILURE);
		}

	/* at this point, the cred structure has been completely created */

	/* compute time_rec */

	if (cred_usage == GSS_C_ACCEPT) {
		if (time_rec)
			*time_rec = GSS_C_INDEFINITE;
	} else {
		krb5_timestamp now;

		if ((code = krb5_timeofday(context, &now))) {
			if (cred->ccache)
				(void) krb5_cc_close(context, cred->ccache);
			if (cred->keytab)
				(void) krb5_kt_close(context, cred->keytab);
			if (cred->princ)
				krb5_free_principal(context, cred->princ);
			xfree(cred);
			*minor_status = code;
			krb5_free_context(context);
			return (GSS_S_FAILURE);
		}

		if (time_rec)
			*time_rec = (cred->tgt_expire > now) ?
				(cred->tgt_expire - now) : 0;
	}

	/* create mechs */

	if (actual_mechs) {
		if (GSS_ERROR(ret = gss_create_empty_oid_set(minor_status,
						&ret_mechs)) ||
		    (cred->prerfc_mech && GSS_ERROR(ret =
					gss_add_oid_set_member(minor_status,
					    (gss_OID) gss_mech_krb5_old,
					    &ret_mechs))) ||
		    (cred->rfc_mech && GSS_ERROR(ret =
					gss_add_oid_set_member(minor_status,
					    (gss_OID) gss_mech_krb5,
					    &ret_mechs)))) {
			if (cred->ccache)
				(void) krb5_cc_close(context, cred->ccache);
			if (cred->keytab)
				(void) krb5_kt_close(context, cred->keytab);
			if (cred->princ)
				krb5_free_principal(context, cred->princ);
			xfree(cred);
			krb5_free_context(context);
			/* (*minor_status) set above */
			return (ret);
		}
	}

	/* intern the credential handle */

	if (! kg_save_cred_id((gss_cred_id_t)cred)) {
		(void) gss_release_oid_set(NULL, &ret_mechs);
		free(ret_mechs->elements);
		free(ret_mechs);
		if (cred->ccache)
			(void) krb5_cc_close(context, cred->ccache);
		if (cred->keytab)
			(void) krb5_kt_close(context, cred->keytab);
		if (cred->princ)
			krb5_free_principal(context, cred->princ);
		xfree(cred);
		krb5_free_context(context);
		*minor_status = (OM_uint32) G_VALIDATE_FAILED;
		return (GSS_S_FAILURE);
	}

	krb5_free_context(context);

	/* return success */
	*minor_status = 0;
	*output_cred_handle = (gss_cred_id_t)cred;
	if (actual_mechs)
		*actual_mechs = ret_mechs;
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
gssspi_acquire_cred_with_password(ctx, minor_status, desired_name,
		password, time_req, desired_mechs, cred_usage,
		output_cred_handle, actual_mechs, time_rec)
void *ctx;
OM_uint32 *minor_status;
gss_name_t desired_name;
const gss_buffer_t password;
OM_uint32 time_req;
gss_OID_set desired_mechs;
gss_cred_usage_t cred_usage;
gss_cred_id_t *output_cred_handle;
gss_OID_set *actual_mechs;
OM_uint32 *time_rec;
{
	OM_uint32 ret;

	ret = krb5_gss_acquire_cred_with_password(minor_status,
			desired_name, password, time_req, desired_mechs,
			cred_usage, output_cred_handle, actual_mechs, time_rec);
	return (ret);
}
