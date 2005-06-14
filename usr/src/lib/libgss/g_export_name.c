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
 * glue routine gss_export_name
 *
 * Will either call the mechanism defined gss_export_name, or if one is
 * not defined will call a generic_gss_export_name routine.
 */

#include <mechglueP.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <errno.h>

OM_uint32
gss_export_name(minor_status,
			input_name,
			exported_name)
OM_uint32 *		minor_status;
const gss_name_t	input_name;
gss_buffer_t		exported_name;
{
	gss_union_name_t		union_name;


	if (minor_status)
		*minor_status = 0;

	/* check out parameter */
	if (!exported_name)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	exported_name->value = NULL;
	exported_name->length = 0;

	/* check input parameter */
	if (!input_name)
		return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_BAD_NAME);

	union_name = (gss_union_name_t)input_name;

	/* the name must be in mechanism specific format */
	if (!union_name->mech_type)
		return (GSS_S_NAME_NOT_MN);

	return __gss_export_internal_name(minor_status, union_name->mech_type,
					union_name->mech_name, exported_name);
}
