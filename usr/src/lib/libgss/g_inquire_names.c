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
 *  glue routine for gss_inquire_context
 */

#include <mechglueP.h>

#define	MAX_MECH_OID_PAIRS 32

/* Last argument new for V2 */
OM_uint32
gss_inquire_names_for_mech(minor_status, mechanism, name_types)

OM_uint32 *		minor_status;
const gss_OID 		mechanism;
gss_OID_set *		name_types;

{
	OM_uint32		status;
	gss_mechanism		mech;

	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);
	*minor_status = 0;

	if (name_types == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/*
	 * select the approprate underlying mechanism routine and
	 * call it.
	 */

	mech = __gss_get_mechanism(mechanism);

	if (mech) {

		if (mech->gss_inquire_names_for_mech)
			status = mech->gss_inquire_names_for_mech(
					mech->context,
					minor_status,
					mechanism,
					name_types);
		else
			status = GSS_S_UNAVAILABLE;

		return (status);
	}

	return (GSS_S_BAD_MECH);
}

OM_uint32
gss_inquire_mechs_for_name(minor_status, input_name, mech_set)

OM_uint32 *		minor_status;
const gss_name_t	input_name;
gss_OID_set *		mech_set;

{
	OM_uint32		status;
	static char		*mech_list[MAX_MECH_OID_PAIRS+1];
	gss_OID_set		mech_name_types;
	int			present;
	char 			*mechanism;
	gss_OID 		mechOid;
	gss_OID 		name_type;
	gss_buffer_desc		name_buffer;
	int			i;

	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);
	*minor_status = 0;

	if (input_name == NULL)
		return (GSS_S_BAD_NAME);

	status = gss_create_empty_oid_set(minor_status, mech_set);
	if (status != GSS_S_COMPLETE)
		return (status);
	*mech_list = NULL;
	status = __gss_get_mechanisms(mech_list, MAX_MECH_OID_PAIRS+1);
	if (status != GSS_S_COMPLETE)
		return (status);
	for (i = 0; i < MAX_MECH_OID_PAIRS && mech_list[i] != NULL; i++) {
		mechanism = mech_list[i];
		if (__gss_mech_to_oid(mechanism, &mechOid) == GSS_S_COMPLETE) {
			status = gss_inquire_names_for_mech(
					minor_status,
					mechOid,
					&mech_name_types);
			if (status == GSS_S_COMPLETE) {
				status = gss_display_name(minor_status,
							input_name,
							&name_buffer,
							&name_type);

				(void) gss_release_buffer(NULL, &name_buffer);

				if (status == GSS_S_COMPLETE && name_type) {
					status = gss_test_oid_set_member(
							minor_status,
							name_type,
							mech_name_types,
							&present);
					if (status == GSS_S_COMPLETE &&
						present) {
						status = gss_add_oid_set_member(
							minor_status,
							mechOid,
							mech_set);
						if (status != GSS_S_COMPLETE) {
						(void) gss_release_oid_set(
							    minor_status,
							    &mech_name_types);
						(void) gss_release_oid_set(
							    minor_status,
							    mech_set);
							return (status);
						}
					}
				}
				(void) gss_release_oid_set(
					minor_status,
					&mech_name_types);
			}
		} else {
			(void) gss_release_oid_set(
				minor_status,
				mech_set);
			return (GSS_S_FAILURE);
		}
	}
	return (GSS_S_COMPLETE);
}
