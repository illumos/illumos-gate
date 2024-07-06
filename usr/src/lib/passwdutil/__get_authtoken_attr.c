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

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/types.h>
#include <nsswitch.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "passwdutil.h"

int
__get_authtoken_attr(const char *name, pwu_repository_t *rep, attrlist *item)
{
	int repositories;
	int i;
	int res;

	repositories = get_ns(rep, PWU_READ);

	if (repositories == 0)
		return (PWU_SYSTEM_ERROR);

	if (repositories == REP_ERANGE) {
		/* Can't determine where to look. Fall back to NSS */
		repositories = REP_NSS;
	}

	i = REP_FILES;
	res = PWU_NOT_FOUND;

	/* Loop over repositories until the user is found */
	while ((i <= REP_LAST) && (res == PWU_NOT_FOUND)) {
		if (repositories & i)
			res = rops[i]->getattr(name, item, rep);
		i <<= 1;
	}
	return (res);
}
