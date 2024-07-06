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

#include <nsswitch.h>

#include "passwdutil.h"

/*
 *	__check_history - check if a user's new password is in the user's
 *		old password history.
 *
 *	Entry
 *		user = username.
 *		passwd = new clear text password.
 *		rep = repositories to check.
 *
 *	Exit
 *		PWU_SUCCESS, passwd found in user's old password history.
 *			The caller should only be interested and fail if
 *			PWU_SUCCESS is returned.
 *		PWU_NOT_FOUND, passwd not in user's old password history.
 *		PWU_errors, PWU_ errors from other routines.
 *
 */
int
__check_history(const char *user, const char *passwd, pwu_repository_t *rep)
{
	int repositories;
	int i;
	int res;

	repositories = get_ns(rep, PWU_READ);

	if (repositories == 0)
		return (PWU_SYSTEM_ERROR);

	if (repositories == REP_ERANGE)
		return (PWU_REPOSITORY_ERROR);

	i = REP_FILES;
	res = PWU_NOT_FOUND;

	/* Loop over repositories until the user is found */
	while ((i <= REP_LAST) && (res == PWU_NOT_FOUND)) {
		if (repositories & i)
			if (rops[i]->checkhistory != NULL)
				res = rops[i]->checkhistory(user, passwd, rep);
		i <<= 1;
	}
	return (res);
}
