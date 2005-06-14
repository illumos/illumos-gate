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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  glue routine for gss_store_cred
 */

#include <mechglueP.h>

OM_uint32 gss_store_cred(minor_status,
			input_cred_handle,
			cred_usage,
			desired_mech,
			overwrite_cred,
			default_cred,
			elements_stored,
			cred_usage_stored)

OM_uint32		*minor_status;
const gss_cred_id_t	 input_cred_handle;
gss_cred_usage_t	 cred_usage;
const gss_OID		 desired_mech;
OM_uint32		 overwrite_cred;
OM_uint32		 default_cred;
gss_OID_set		*elements_stored;
gss_cred_usage_t	*cred_usage_stored;

{
	OM_uint32		major_status = GSS_S_FAILURE;
	gss_union_cred_t	union_cred;
	gss_cred_id_t		mech_cred;
	gss_mechanism		mech;
	gss_OID			dmech;
	int			i;

	/* Start by checking parameters */
	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE|GSS_S_NO_CRED);
	*minor_status = 0;

	if (input_cred_handle == GSS_C_NO_CREDENTIAL)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	if (elements_stored != NULL)
		*elements_stored = GSS_C_NULL_OID_SET;

	if (cred_usage_stored != NULL)
		*cred_usage_stored = GSS_C_BOTH; /* there's no GSS_C_NEITHER */

	union_cred = (gss_union_cred_t)input_cred_handle;

	/* desired_mech != GSS_C_NULL_OID -> store one element */
	if (desired_mech != GSS_C_NULL_OID) {
		mech = __gss_get_mechanism(desired_mech);
		if (mech == NULL)
			return (GSS_S_BAD_MECH);

		if (mech->gss_store_cred == NULL)
			return (major_status);

		mech_cred = __gss_get_mechanism_cred(union_cred, desired_mech);
		if (mech_cred == GSS_C_NO_CREDENTIAL)
			return (GSS_S_NO_CRED);

		return (mech->gss_store_cred(mech->context,
						minor_status,
						(gss_cred_id_t)mech_cred,
						cred_usage,
						desired_mech,
						overwrite_cred,
						default_cred,
						elements_stored,
						cred_usage_stored));
	}

	/* desired_mech == GSS_C_NULL_OID -> store all elements */

	*minor_status = 0;

	for (i = 0; i < union_cred->count; i++) {
		/* Get mech and cred element */
		dmech = &union_cred->mechs_array[i];
		mech = __gss_get_mechanism(dmech);
		if (mech == NULL)
			continue;

		if (mech->gss_store_cred == NULL)
			continue;

		mech_cred = __gss_get_mechanism_cred(union_cred, dmech);
		if (mech_cred == GSS_C_NO_CREDENTIAL)
			continue; /* can't happen, but safe to ignore */

		major_status = mech->gss_store_cred(mech->context,
						minor_status,
						(gss_cred_id_t)mech_cred,
						cred_usage,
						dmech,
						overwrite_cred,
						default_cred,
						NULL,
						cred_usage_stored);
		if (major_status != GSS_S_COMPLETE)
			continue;

		/* Succeeded for at least one mech */

		if (elements_stored == NULL)
			continue;

		if (*elements_stored == GSS_C_NULL_OID_SET) {
			major_status = gss_create_empty_oid_set(minor_status,
						elements_stored);

			if (GSS_ERROR(major_status))
				return (major_status);
		}

		major_status = gss_add_oid_set_member(minor_status, dmech,
			elements_stored);

		/* The caller should clean up elements_stored */
		if (GSS_ERROR(major_status))
			return (major_status);
	}

	/*
	 * Success with some mechs may mask failure with others, but
	 * that's what elements_stored is for.
	 */
	return (major_status);
}
