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
 * Copyright (c) 1996,1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  glue routine for gss_release_name
 */

#include "mechglueP.h"

OM_uint32
gss_release_name(OM_uint32 *minor_status, gss_name_t *input_name)
{
	gss_union_name_t	union_name;

	/* if input_name is NULL, return error */

	if (input_name == 0)
		return (GSS_S_BAD_NAME);

	/*
	 * free up the space for the external_name, name_type
	 * and then free the union_name descriptor
	 */
	union_name = (gss_union_name_t) *input_name;
	*input_name = 0;
	*minor_status = 0;

	if (union_name == NULL)
		return (GSS_S_BAD_NAME);

	FREE(union_name->external_name->value,
		union_name->external_name->length);
	FREE(union_name->external_name, sizeof (gss_buffer_desc));

	/* free the name_type */
	FREE(union_name->name_type->elements, union_name->name_type->length);
	FREE(union_name->name_type, sizeof (gss_OID_desc));

	FREE(union_name, sizeof (gss_union_name_desc));

	return (GSS_S_COMPLETE);
}
