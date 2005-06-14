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
 *  glue routine for gss_release_cred
 */

#include <mechglueP.h>
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

OM_uint32
gss_release_cred(minor_status,
			cred_handle)

OM_uint32 		*minor_status;
gss_cred_id_t 		*cred_handle;

{
	OM_uint32		status, temp_status;
	int			j;
	gss_union_cred_t	union_cred;
	gss_mechanism		mech;

	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor_status = 0;

	if (cred_handle == NULL)
		return (GSS_S_NO_CRED | GSS_S_CALL_INACCESSIBLE_READ);

	/*
	 * Loop through the union_cred struct, selecting the approprate
	 * underlying mechanism routine and calling it. At the end,
	 * release all of the storage taken by the union_cred struct.
	 */

	union_cred = (gss_union_cred_t)*cred_handle;
	*cred_handle = NULL;

	if (union_cred == (gss_union_cred_t)GSS_C_NO_CREDENTIAL)
		return (GSS_S_COMPLETE);

	status = GSS_S_COMPLETE;

	for (j = 0; j < union_cred->count; j++) {

		mech = __gss_get_mechanism(&union_cred->mechs_array[j]);

		if (union_cred->mechs_array[j].elements)
			free(union_cred->mechs_array[j].elements);
		if (mech) {
			if (mech->gss_release_cred) {
				temp_status = mech->gss_release_cred
						(mech->context, minor_status,
						&union_cred->cred_array[j]);

				if (temp_status != GSS_S_COMPLETE)
					status = GSS_S_NO_CRED;
			} else
				status = GSS_S_UNAVAILABLE;
		} else
			status = GSS_S_DEFECTIVE_CREDENTIAL;
	}

	(void) gss_release_buffer(minor_status, &union_cred->auxinfo.name);
	free(union_cred->cred_array);
	free(union_cred->mechs_array);
	free(union_cred);

	return (status);
}
