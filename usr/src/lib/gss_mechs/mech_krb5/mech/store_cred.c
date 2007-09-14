/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <k5-int.h>
#include <gssapiP_krb5.h>
#include <memory.h>
#include <assert.h>

static
OM_uint32
store_init_cred(ct, minor_status, cred, dflt)
krb5_context ct;
OM_uint32 *minor_status;
const krb5_gss_cred_id_t cred;
int dflt;
{
	OM_uint32 maj = GSS_S_COMPLETE;
	krb5_error_code code;
	krb5_ccache ccache = NULL; /* current [file] ccache */
	krb5_principal ccprinc = NULL; /* default princ of current ccache */

	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);
	*minor_status = 0;

	/* Get current ccache -- respect KRB5CCNAME, or use OS default */
	if ((code = krb5_cc_default(ct, &ccache))) {
		*minor_status = code;
		return (GSS_S_FAILURE);
	}

	/*
	 * Here we should do something like:
	 *
	 * a) take all the initial tickets from the current ccache for
	 * client principals other than the given cred's
	 * b) copy them to a tmp MEMORY ccache
	 * c) copy the given cred's tickets to that same tmp ccache
	 * d) initialize the current ccache with either the same default
	 * princ as before (!dflt) or with the input cred's princ as the
	 * default princ (dflt) and copy the tmp ccache's creds to it.
	 *
	 * However, for now we just initialize the current ccache, if
	 * (dflt), and copy the input cred's tickets to it.
	 *
	 * To support the above ideal we'd need a variant of
	 * krb5_cc_copy_creds().  But then, preserving any tickets from
	 * the current ccache may be problematic if the ccache has many,
	 * many service tickets in it as that makes ccache enumeration
	 * really, really slow; we might want to address ccache perf
	 * first.
	 *
	 * So storing of non-default credentials is not supported.
	 */
	if (dflt) {
		/* Treat this as "caller asks to initialize ccache" */
		/* LINTED */
		if ((code = krb5_cc_initialize(ct, ccache, cred->princ))) {
			*minor_status = code;
			maj = GSS_S_FAILURE;
			goto cleanup;
		}
	} else {
		*minor_status = (OM_uint32) G_STORE_NON_DEFAULT_CRED_NOSUPP;
		maj = GSS_S_FAILURE;
		goto cleanup;
	}

	if ((code = krb5_cc_copy_creds(ct, cred->ccache, ccache))) {
		*minor_status = code;
		maj = GSS_S_FAILURE;
		goto cleanup;
	}

cleanup:
	if (ccprinc != NULL)
		krb5_free_principal(ct, ccprinc);
	if (ccache != NULL)
		/* LINTED */
		krb5_cc_close(ct, ccache);

	return (maj);
}

OM_uint32
krb5_gss_store_cred(minor_status, input_cred, cred_usage,
		desired_mech, overwrite_cred, default_cred, elements_stored,
		cred_usage_stored)
OM_uint32 *minor_status;
const gss_cred_id_t input_cred;
gss_cred_usage_t cred_usage;
gss_OID desired_mech;
OM_uint32 overwrite_cred;
OM_uint32 default_cred;
gss_OID_set *elements_stored;
gss_cred_usage_t *cred_usage_stored;
{
	OM_uint32 maj, maj2, min;
	krb5_context ctx = NULL;
	krb5_gss_cred_id_t cred = (krb5_gss_cred_id_t)input_cred;
	krb5_gss_cred_id_t cur_cred = (krb5_gss_cred_id_t)GSS_C_NO_CREDENTIAL;
	gss_OID_set desired_mechs = GSS_C_NULL_OID_SET;
	OM_uint32 in_time_rec;			/* lifetime of input cred */
	OM_uint32 cur_time_rec;			/* lifetime of current cred */
	gss_cred_usage_t in_usage;		/* usage of input cred */
	gss_name_t in_name = GSS_C_NO_NAME;	/* name of input cred */

	if (input_cred == GSS_C_NO_CREDENTIAL)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	/* Initialize output parameters */
	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);
	*minor_status = 0;

	if (elements_stored != NULL)
		*elements_stored = GSS_C_NULL_OID_SET;

	if (cred_usage_stored != NULL)
		*cred_usage_stored = -1; /* need GSS_C_NEITHER! */

	/* Sanity check cred_usage */
	if (cred_usage != GSS_C_BOTH && cred_usage != GSS_C_INITIATE &&
	    cred_usage != GSS_C_ACCEPT) {
		*minor_status = (OM_uint32) G_BAD_USAGE;
		return (GSS_S_CALL_BAD_STRUCTURE);
	}

	/* Not supported: storing acceptor creds -- short cut now */
	if (cred_usage == GSS_C_ACCEPT) {
		*minor_status = (OM_uint32) G_STORE_ACCEPTOR_CRED_NOSUPP;
		return (GSS_S_FAILURE);
	}
	if (cred_usage == GSS_C_BOTH)
		cred_usage = GSS_C_INITIATE;

	min = krb5_gss_init_context(&ctx);
	if (min) {
		*minor_status = min;
		return (GSS_S_FAILURE);
	}

	/* * Find out the name, lifetime and cred usage of the input cred */
	maj = krb5_gss_inquire_cred(minor_status, input_cred,
			&in_name, &in_time_rec, &in_usage, NULL);
	if (GSS_ERROR(maj))
		goto cleanup;

	/* Check that the input cred isn't expired */
	if (in_time_rec == 0) {
		maj = GSS_S_CREDENTIALS_EXPIRED;
		goto cleanup;
	}

	/* The requested and input cred usage must agree */
	if (in_usage != cred_usage && cred_usage != GSS_C_BOTH) {
		*minor_status = (OM_uint32) G_CRED_USAGE_MISMATCH;
		maj = GSS_S_NO_CRED;
		goto cleanup;
	}

	if (in_usage == GSS_C_ACCEPT) {
		*minor_status = (OM_uint32) G_STORE_ACCEPTOR_CRED_NOSUPP;
		maj = GSS_S_FAILURE;
		goto cleanup;
	}

	/* Get current cred, if any */
	if (desired_mech != GSS_C_NULL_OID) {
		/* assume that libgss gave us one of our mech OIDs */
		maj = gss_create_empty_oid_set(minor_status, &desired_mechs);
		if (GSS_ERROR(maj))
			return (maj);

		maj = gss_add_oid_set_member(minor_status, desired_mech,
				&desired_mechs);
		if (GSS_ERROR(maj))
			goto cleanup;
	}

	/*
	 * Handle overwrite_cred option.  If overwrite_cred == FALSE
	 * then we must be careful not to overwrite an existing
	 * unexpired credential.
	 */
	maj2 = krb5_gss_acquire_cred(&min,
			(default_cred) ?  GSS_C_NO_NAME : in_name,
			0, desired_mechs, cred_usage,
			(gss_cred_id_t *)&cur_cred, NULL, &cur_time_rec);

	if (GSS_ERROR(maj2))
		overwrite_cred = 1; /* nothing to overwrite */

	if (cur_time_rec > 0 && !overwrite_cred) {
		maj = GSS_S_DUPLICATE_ELEMENT; /* would overwrite */
		goto cleanup;
	}

	/* Ready to store -- store_init_cred() handles default_cred */
	maj = store_init_cred(ctx, minor_status, cred, default_cred);
	if (GSS_ERROR(maj))
		goto cleanup;

	/* Output parameters */
	if (cred_usage_stored != NULL)
		*cred_usage_stored = GSS_C_INITIATE;

	if (elements_stored != NULL) {
		maj = gss_create_empty_oid_set(minor_status, elements_stored);
		if (GSS_ERROR(maj))
			goto cleanup;

		maj = gss_add_oid_set_member(minor_status,
			    (const gss_OID)gss_mech_krb5, elements_stored);
		if (GSS_ERROR(maj)) {
			(void) gss_release_oid_set(&min, elements_stored);
			*elements_stored = GSS_C_NULL_OID_SET;
			goto cleanup;
		}
	}

cleanup:
	if (desired_mechs != GSS_C_NULL_OID_SET)
		(void) gss_release_oid_set(&min, &desired_mechs);
	if (cur_cred != (krb5_gss_cred_id_t)GSS_C_NO_CREDENTIAL)
		(void) krb5_gss_release_cred(&min,
				    (gss_cred_id_t *)&cur_cred);
	if (in_name != GSS_C_NO_NAME)
		(void) krb5_gss_release_name(&min, &in_name);

	if (ctx)
		krb5_free_context(ctx);

	return (maj);
}
