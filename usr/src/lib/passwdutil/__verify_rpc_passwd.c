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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "passwdutil.h"

extern int nisplus_verify_rpc_passwd(char *name, char *oldpw,
    pwu_repository_t *rep);

int
__verify_rpc_passwd(char *name, char *oldpw, pwu_repository_t *rep)
{
	int repositories;
	int pwu_res;

	repositories = get_ns(rep, PWU_READ);

	if (repositories == 0)
		return (PWU_SYSTEM_ERROR);

	if (repositories == REP_ERANGE)
		return (PWU_REPOSITORY_ERROR);

	/*
	 * If NIS+ is not used, then there is no need for an old RPC
	 * password.
	 */
	if ((repositories & REP_NISPLUS) == 0)
		return (PWU_SUCCESS);

	pwu_res = nisplus_verify_rpc_passwd(name, oldpw, rep);

	/*
	 * If the user can't be found in NIS+ _and_ there are other
	 * repositories defined, not being able to find the user in NIS+
	 * is not necessarily fatal, so return SUCCESS here.
	 * If it turns out NIS+ the user can't be found in the other
	 * repositories, we'll bail out later on.
	 */
	if ((pwu_res == PWU_NOT_FOUND) && (repositories & ~REP_NISPLUS) != 0)
		pwu_res = PWU_SUCCESS;

	return (pwu_res);
}
