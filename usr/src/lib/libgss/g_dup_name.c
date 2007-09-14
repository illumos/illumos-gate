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
 *  routine gss_duplicate_name
 *
 * This routine does not rely on mechanism implementation of this
 * name, but instead uses mechanism specific gss_import_name routine.
 */

#include <mechglueP.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <errno.h>

OM_uint32
gss_duplicate_name(minor_status,
		src_name,
		dest_name)
OM_uint32 *minor_status;
const gss_name_t src_name;
gss_name_t *dest_name;
{
		gss_union_name_t src_union, dest_union;
		OM_uint32 major_status = GSS_S_FAILURE;


	if (!minor_status)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor_status = 0;

	/* if output_name is NULL, simply return */
	if (dest_name == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE | GSS_S_BAD_NAME);

	*dest_name = 0;

	if (src_name == NULL)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	src_union = (gss_union_name_t)src_name;

	/*
	 * First create the union name struct that will hold the external
	 * name and the name type.
	 */
	dest_union = (gss_union_name_t)malloc(sizeof (gss_union_name_desc));
	if (!dest_union)
		goto allocation_failure;

	dest_union->mech_type = 0;
	dest_union->mech_name = 0;
	dest_union->name_type = 0;
	dest_union->external_name = 0;

	/* Now copy the external representaion */
	if (gssint_create_copy_buffer(src_union->external_name,
				&dest_union->external_name, 0))
		goto allocation_failure;

	if (src_union->name_type != GSS_C_NULL_OID) {
		major_status = generic_gss_copy_oid(minor_status,
						src_union->name_type,
						&dest_union->name_type);
		if (major_status != GSS_S_COMPLETE)
			goto allocation_failure;
	}

	/*
	 * See if source name is mechanim specific, if so then need to import it
	 */
	if (src_union->mech_type) {
		major_status = generic_gss_copy_oid(minor_status,
							src_union->mech_type,
							&dest_union->mech_type);
		if (major_status != GSS_S_COMPLETE)
			goto allocation_failure;

		major_status = __gss_import_internal_name(minor_status,
							dest_union->mech_type,
							dest_union,
							&dest_union->mech_name);
		if (major_status != GSS_S_COMPLETE)
			goto allocation_failure;
	}


	*dest_name = (gss_name_t)dest_union;
	return (GSS_S_COMPLETE);

allocation_failure:
	if (dest_union) {
		if (dest_union->external_name) {
			if (dest_union->external_name->value)
				free(dest_union->external_name->value);
				free(dest_union->external_name);
		}
		if (dest_union->name_type)
			(void) generic_gss_release_oid(minor_status,
							&dest_union->name_type);
		if (dest_union->mech_name)
			(void) __gss_release_internal_name(minor_status,
						dest_union->mech_type,
						&dest_union->mech_name);
		if (dest_union->mech_type)
			(void) generic_gss_release_oid(minor_status,
							&dest_union->mech_type);
		free(dest_union);
	}
	return (major_status);
} /*	gss_duplicate_name	*/
