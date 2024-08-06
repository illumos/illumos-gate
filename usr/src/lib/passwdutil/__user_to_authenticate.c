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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
 */

#include "passwdutil.h"

int
__user_to_authenticate(const char *name, pwu_repository_t *rep,
    char **auth_user, int *auth_self)
{
	int repositories;
	int i;
	int pwu_res;

	/*
	 * This function is called only by passwd command performing
	 * update operation, so use PWU_WRITE as the access type to
	 * find the repositories for WRITE operation.
	 */
	repositories = get_ns(rep, PWU_WRITE);

	if (repositories == 0)
		return (PWU_SYSTEM_ERROR);

	if (repositories == REP_ERANGE || repositories == REP_NSS)
		return (PWU_REPOSITORY_ERROR);

	i = REP_FILES;

	/* Loop over repositories until we find the user */
	while (i <= REP_LAST) {
		if (repositories & i) {
			pwu_res = rops[i]->user_to_authenticate(name, rep,
							auth_user, auth_self);
			if (pwu_res != PWU_NOT_FOUND)
				return (pwu_res);
		}
		i <<= 1;
	}

	return (PWU_NOT_FOUND);
}
