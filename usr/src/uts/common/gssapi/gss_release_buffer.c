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
 *  glue routine for gss_release_buffer
 */

#include "mechglueP.h"

OM_uint32
gss_release_buffer(OM_uint32 *minor_status, gss_buffer_t buffer)
{

	if (minor_status)
		*minor_status = 0;

	/* if buffer is NULL, return */

	if (buffer == GSS_C_NO_BUFFER)
		return (GSS_S_COMPLETE);

	if ((buffer->length) && (buffer->value)) {
		FREE(buffer->value, buffer->length);
		buffer->length = 0;
		buffer->value = NULL;
	}

	return (GSS_S_COMPLETE);
}
