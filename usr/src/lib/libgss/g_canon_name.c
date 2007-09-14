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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * routine gss_canonicalize_name
 *
 * This routine is used to produce a mechanism specific
 * representation of name that has been previously
 * imported with gss_import_name.  The routine uses the mechanism
 * specific implementation of gss_import_name to implement this
 * function.
 *
 * We allow a NULL output_name, in which case we modify the
 * input_name to include the mechanism specific name.
 */

#include <mechglueP.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <errno.h>

OM_uint32
gss_canonicalize_name(minor_status,
				input_name,
				mech_type,
				output_name)
OM_uint32 *minor_status;
const gss_name_t input_name;
const gss_OID mech_type;
gss_name_t *output_name;
{
	gss_union_name_t in_union, out_union = NULL, dest_union = NULL;
	OM_uint32 major_status = GSS_S_FAILURE;

	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor_status = 0;

	if (output_name)
		*output_name = 0;

	/* check the input parameters */
	if (input_name == NULL || mech_type == GSS_C_NULL_OID)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	in_union = (gss_union_name_t)input_name;
	/*
	 * If the caller wants to reuse the name, and the name has already
	 * been converted, then there is nothing for us to do.
	 */
	if (!output_name && in_union->mech_type &&
		g_OID_equal(in_union->mech_type, mech_type))
		return (GSS_S_COMPLETE);

	/* ok, then we need to do something - start by creating data struct */
	if (output_name) {
		out_union =
			(gss_union_name_t)malloc(sizeof (gss_union_name_desc));
		if (!out_union)
			goto allocation_failure;

		out_union->mech_type = 0;
		out_union->mech_name = 0;
		out_union->name_type = 0;
		out_union->external_name = 0;

		/* Allocate the buffer for the user specified representation */
		if (gssint_create_copy_buffer(in_union->external_name,
				&out_union->external_name, 1))
			goto allocation_failure;

		if (in_union->name_type != GSS_C_NULL_OID) {
			if ((major_status = generic_gss_copy_oid(minor_status,
				in_union->name_type, &out_union->name_type)))
			goto allocation_failure;
		}

	}

	/*
	 * might need to delete any old mechanism names if we are
	 * reusing the buffer.
	 */
	if (!output_name) {
		if (in_union->mech_type) {
			(void) __gss_release_internal_name(minor_status,
							in_union->mech_type,
							&in_union->mech_name);
			(void) gss_release_oid(minor_status,
					    &in_union->mech_type);
			in_union->mech_type = 0;
		}
		dest_union = in_union;
	} else
		dest_union = out_union;

	/* now let's create the new mech name */
	if (major_status = generic_gss_copy_oid(minor_status, mech_type,
						&dest_union->mech_type))
		goto allocation_failure;

	if (major_status =
		__gss_import_internal_name(minor_status, mech_type,
						dest_union,
						&dest_union->mech_name))
		goto allocation_failure;

	if (output_name)
		*output_name = (gss_name_t)dest_union;

	return (GSS_S_COMPLETE);

allocation_failure:
	/* do not delete the src name external name format */
	if (output_name) {
		if (out_union->external_name) {
			if (out_union->external_name->value)
				free(out_union->external_name->value);
			free(out_union->external_name);
		}
		if (out_union->name_type)
			(void) gss_release_oid(minor_status,
					    &out_union->name_type);

		dest_union = out_union;
	} else
		dest_union = in_union;

	/*
	 * delete the partially created mech specific name
	 * applies for both src and dest which ever is being used for output
	 */

	if (dest_union->mech_name) {
		(void) __gss_release_internal_name(minor_status,
						dest_union->mech_type,
						&dest_union->mech_name);
	}

	if (dest_union->mech_type)
		(void) gss_release_oid(minor_status, &dest_union->mech_type);


	if (output_name)
		free(out_union);

	return (major_status);
} /**********  gss_canonicalize_name ********/
