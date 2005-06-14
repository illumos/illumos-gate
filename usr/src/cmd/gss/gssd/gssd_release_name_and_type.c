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
 * Copyright (c) 1995,1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  glue routine for gssd_release_name_and_type -- this is a hack,
 *  it is only used by the client-side rpc library.  Perhaps it should
 *  be in there?  Perhaps this should be a part of the release_name
 *  function?  Or perhaps it should always allocate it?  I don't know
 *  the right answer.
 */

#include <sys/types.h>
#include <stdlib.h>
#include <mechglueP.h>

/*ARGSUSED*/
OM_uint32
gssd_release_name_and_type(minor_status, input_name)
	OM_uint32 *		minor_status;
	gss_name_t *		input_name;

{

	gss_union_name_t	union_name;

	if (input_name == NULL)
		return (GSS_S_COMPLETE);

	/*
	 * free up the space for the external_name and also the name
	 * type data. Then free the union_name descriptor.
	 */

	union_name = (gss_union_name_t) *input_name;
	*input_name = NULL;

	if (union_name == NULL)
		return (GSS_S_COMPLETE);

	FREE(union_name->external_name->value,
	    union_name->external_name->length);
	FREE(union_name->external_name, sizeof (gss_buffer_desc));
	FREE(union_name->name_type->elements, union_name->name_type->length);
	FREE(union_name->name_type, sizeof (gss_OID_desc));
	FREE(union_name, sizeof (gss_union_name_desc));

	return (GSS_S_COMPLETE);
}

OM_uint32
gss_release_oid_set_and_oids(minor_status, set)
	OM_uint32 *		minor_status;
	gss_OID_set *		set;
{
	int i;

	if (minor_status)
		*minor_status = 0;

	if (set == NULL)
		return (GSS_S_COMPLETE);

	if (*set == GSS_C_NULL_OID_SET)
		return (GSS_S_COMPLETE);

	for (i = 0; i < (*set)->count; i++)
		FREE((*set)->elements[i].elements, (*set)->elements[i].length);

	FREE((*set)->elements, (*set)->count * sizeof (gss_OID_desc));
	FREE(*set, sizeof (gss_OID_set_desc));

	*set = GSS_C_NULL_OID_SET;

	return (GSS_S_COMPLETE);
}
