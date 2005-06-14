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
 *  glue routine for gss_display_name()
 */

#include <mechglueP.h>
#include <gssapi/kgssapi_defs.h>

OM_uint32
gss_display_name(OM_uint32 *minor_status,
	const gss_name_t input_name,
	gss_buffer_t output_name_buffer,
	gss_OID *output_name_type)
{
	gss_union_name_t	union_name;

	if (input_name == 0)
		return (GSS_S_BAD_NAME);

	union_name = (gss_union_name_t) input_name;

	GSSLOG(8, "union_name value %s\n",
		(char *)union_name->external_name->value);

	/*
	 * copy the value of the external_name component of the union
	 * name into the output_name_buffer and point the output_name_type
	 * to the name_type component of union_name
	 */
	if (output_name_type != NULL)
		*output_name_type = union_name->name_type;

	if (output_name_buffer != NULL) {
		output_name_buffer->length = union_name->external_name->length;

		output_name_buffer->value =
			(void *) MALLOC(output_name_buffer->length);

		(void) memcpy(output_name_buffer->value,
			union_name->external_name->value,
			output_name_buffer->length);
	}

	if (minor_status)
		*minor_status = 0;

	return (GSS_S_COMPLETE);
}
