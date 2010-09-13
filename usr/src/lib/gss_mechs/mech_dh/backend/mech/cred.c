/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *	cred.c
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <sys/note.h>
#include "dh_gssapi.h"

/*
 * This module supports the GSS credential family of routines for
 * Diffie-Hellman mechanism.
 */

/*
 * __dh_gss_acquire_cred: Get the credential associated with principal
 * with the requested expire time and usage. Return the credential with
 * the optional set of supported mechs and actual time left on the credential.
 *
 * Note in Diffie-Hellman the supplied principal name must be that of
 * the caller. There is no way to delegate credentials.
 *
 * Libgss alwas sets desired_mechs to GSS_C_NO_OID_SET and set the return
 * set of mechs to NULL.
 */

OM_uint32
__dh_gss_acquire_cred(void *ctx, /* Per mechanism context */
		    OM_uint32 *minor, /* Mechanism status */
		    gss_name_t principal, /* Requested principal */
		    OM_uint32  expire_req, /* Requested Expire time */
		    gss_OID_set desired_mechs, /* Set of desired mechs */
		    gss_cred_usage_t usage, /* Usage: init, accept, both */
		    gss_cred_id_t *cred, /* The return credential */
		    gss_OID_set *mechs, /* The return set of mechs */
		    OM_uint32 *expire_rec /* The expire time received*/)
{
	/* Diffie-Hellman mechanism context is ctx */
	dh_context_t cntx = (dh_context_t)ctx;
	dh_principal netname;
	dh_cred_id_t dh_cred;

	/* Need to write to these */
	if (minor == 0 || cred == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/* Set sane outputs */
	*minor = 0;
	if (mechs)
		*mechs = GSS_C_NO_OID_SET;
	if (expire_rec)
		*expire_rec = 0;
	*cred = GSS_C_NO_CREDENTIAL;

	/*
	 * If not GSS_C_NO_OID_SET then the set must contain the
	 * Diffie-Hellman mechanism
	 */
	if (desired_mechs != GSS_C_NO_OID_SET &&
	    !__OID_is_member(desired_mechs, cntx->mech))
		return (GSS_S_BAD_MECH);

	/* See if the callers secretkey is available */
	if (!cntx->keyopts->key_secretkey_is_set())
		return (GSS_S_NO_CRED);

	/* Get the principal name of the caller */
	if ((netname = cntx->keyopts->get_principal()) == NULL)
		return (GSS_S_NO_CRED);

	/*
	 * Diffie-Hellman requires the principal to be the principal
	 * of the caller
	 */

	if (principal &&
	    strncmp(netname, (char *)principal, MAXNETNAMELEN) != 0) {
		Free(netname);
		return (GSS_S_NO_CRED);
	}

	/* Allocate the credential */
	dh_cred = New(dh_cred_id_desc, 1);
	if (dh_cred == NULL) {
		Free(netname);
		*minor = DH_NOMEM_FAILURE;
		return (GSS_S_FAILURE);
	}

	/* Set credential state */
	dh_cred->uid = geteuid();
	dh_cred->usage = usage;
	dh_cred->principal = netname;
	dh_cred->expire = expire_req ? time(0) + expire_req : GSS_C_INDEFINITE;

	/*
	 * If mechs set it to the set that contains the appropriate
	 * Diffie-Hellman mechanism
	 */
	if (mechs && (*minor = __OID_to_OID_set(mechs, cntx->mech))) {
		Free(dh_cred);
		Free(netname);
		return (GSS_S_FAILURE);
	}

	/* Register the credential */
	if ((*minor = __dh_install_cred(dh_cred)) != DH_SUCCESS) {
		Free(dh_cred);
		Free(netname);
		return (GSS_S_FAILURE);
	}

	if (expire_rec)
		*expire_rec = expire_req ? expire_req : GSS_C_INDEFINITE;

	/* Return the Diffie-Hellman credential through cred */
	*cred  = (gss_cred_id_t)dh_cred;

	return (GSS_S_COMPLETE);
}


/*
 * __dh_gss_add_cred is currently a no-op. All the work is done at the
 * libgss layer. That layer will invoke the mechanism specific gss_acquire_cred
 * routine. This entry point should never be called. The entry point for
 * this routine is set to NULL in dhmech.c.
 */

/*
 * OM_uint32
 * __dh_gss_add_cred(void * ctx, OM_uint32 *minor, gss_cred_id_t cred_in,
 *    gss_name_t name, gss_OID mech, gss_cred_usage_t usage,
 *   OM_uint32 init_time_req, OM_uint32 accep_time_req,
 *   gss_cred_id_t *cred_out, gss_OID_set *mechs,
 *   OM_uint32 *init_time_rec, OM_uint32 *accep_time_rec)
 * {
 *	return (GSS_S_UNAVAILABLE);
 * }
 */

/*
 * __dh_gss_inquire_cred: Return tracked state of the supplied credential.
 */
OM_uint32
__dh_gss_inquire_cred(void *ctx, /* Per mechanism context */
		    OM_uint32 *minor, /* Mechanism status */
		    gss_cred_id_t cred, /* cred of interest */
		    gss_name_t *name, /* name of principal */
		    OM_uint32 *lifetime, /* return the time remainning */
		    gss_cred_usage_t *usage, /* usage: init, accept, both */
		    gss_OID_set *mechs /* Set containing mech_dh */)
{
	/* cred is a Diffie-Hellman credential */
	dh_cred_id_t crid = (dh_cred_id_t)cred;
	/* ctx is a Diffie-Hellman context */
	dh_context_t cntx = (dh_context_t)ctx;
	OM_uint32 t = GSS_C_INDEFINITE;

	if (minor == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);
	if (cntx == 0)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	*minor = DH_SUCCESS;

	/* Default case */
	if (cred == GSS_C_NO_CREDENTIAL) {
		if (!(*cntx->keyopts->key_secretkey_is_set)())
			return (GSS_S_NO_CRED);
		if (name)
			*name = (gss_name_t)(*cntx->keyopts->get_principal)();
		if (lifetime)
			*lifetime = GSS_C_INDEFINITE;
		if (usage)
			*usage = GSS_C_BOTH;
	} else {
		/* Validate creditial */
		if ((*minor = __dh_validate_cred(crid)) != DH_SUCCESS)
			return (GSS_S_DEFECTIVE_CREDENTIAL);
		if (name)
			*name = (gss_name_t)strdup(crid->principal);
		if (lifetime) {
			if (crid->expire == GSS_C_INDEFINITE)
				*lifetime = GSS_C_INDEFINITE;
			else {
				time_t now = time(0);
				t = crid->expire > now ? crid->expire-now : 0;
				*lifetime = t;
			}
		}
		if (usage)
			*usage = crid->usage;
	}

	if (name && *name == 0)
		return (GSS_S_FAILURE);


	if (mechs &&
	    (*minor = __OID_to_OID_set(mechs, cntx->mech)) != DH_SUCCESS) {
		free(name);
		return (GSS_S_FAILURE);
	}

	/* Check if the credential is still valid */
	return (t ? GSS_S_COMPLETE : GSS_S_CREDENTIALS_EXPIRED);
}


/*
 * __dh_gss_inquire_cred_by_mech: Return the information associated with
 * cred and mech. Since we're a backend, mech must be our mech.
 *
 * We verify that passed in mech is correct and use the above routine
 * to do the work.
 */
OM_uint32
__dh_gss_inquire_cred_by_mech(void *ctx, /* Per mechananism context */
			    OM_uint32 *minor, /* Mechanism status */
			    gss_cred_id_t cred, /* Cred to iquire about */
			    gss_OID mech, /* Along with the mechanism */
			    gss_name_t *name, /* where to return principal */
			    OM_uint32 *init_time, /* Init time left */
			    OM_uint32 *accept_time, /* Accept time left */
			    gss_cred_usage_t *usage /* cred usage */)
{
	/* ctx is them Diffie-Hellman mechanism context */
	dh_context_t context = (dh_context_t)ctx;
	OM_uint32 lifetime;
	OM_uint32 major;
	gss_cred_usage_t use;

	/* This should never happen. It would indicate a libgss failure */
	if (!__OID_equal(mech, context->mech)) {
		*minor = DH_BAD_CONTEXT;
		return (GSS_S_FAILURE);
	}

	/* Fetch cred info */
	major = __dh_gss_inquire_cred(ctx, minor, cred, name,
				    &lifetime, &use, NULL);

	/* Return option values */
	if (major == GSS_S_COMPLETE) {
		/* set init_time if we can */
		if (init_time)
			*init_time = (use == GSS_C_BOTH ||
				    use == GSS_C_INITIATE) ? lifetime : 0;
		/* Ditto for accept time */
		if (accept_time)
			*accept_time = (use == GSS_C_BOTH ||
					use == GSS_C_ACCEPT) ? lifetime : 0;
		if (usage)
			*usage = use;
	}

	return (major);
}

/*
 * __dh_gss_release_cred: Release the resources associated with cred.
 */
OM_uint32
__dh_gss_release_cred(void *ctx, /* Per mechananism context (not used) */
		    OM_uint32 *minor, /* Mechanism status */
		    gss_cred_id_t *cred /* The cred to free */)
{
_NOTE(ARGUNUSED(ctx))
	dh_cred_id_t dh_cred = (dh_cred_id_t)*cred;

	/* Check that we can read and write required parameters */
	if (minor == 0 || cred == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/* Nothing to do */
	if (*cred == GSS_C_NO_CREDENTIAL)
		return (GSS_S_COMPLETE);

	/* Check if the credential is valid */
	if ((*minor = __dh_validate_cred(dh_cred)) != DH_SUCCESS)
		return (GSS_S_NO_CRED);

	/* Unregister the credential */
	*minor = __dh_remove_cred(dh_cred);

	/* Free the principal and the cred itself */
	Free(dh_cred->principal);
	Free(dh_cred);

	/* Set cred to no credential */
	*cred = GSS_C_NO_CREDENTIAL;

	return (GSS_S_COMPLETE);
}
