/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <errno.h>
#include <nss.h>
#include <secdb.h>
#include <stdlib.h>
#include <string.h>
#include <user_attr.h>
#include <zone.h>

#include <bsm/libbsm.h>

#include <adt_xlate.h>		/* adt_write_syslog */

/* ARGSUSED */
static int
audit_flags(const char *name, kva_t *kva, void *ctxt, void *pres)
{
	char *val;

	if ((val = kva_match(kva, USERATTR_AUDIT_FLAGS_KW)) != NULL) {
		if ((*(char **)ctxt = strdup(val)) == NULL) {
			adt_write_syslog("au_user_mask strdup failed", errno);
		}
		return (1);
	}
	return (0);
}

/*
 * Build user's audit preselection mask.
 *
 * per-user audit flags are optional and may be missing.
 * If global zone auditing is set, a local zone cannot reduce the default
 * flags.
 *
 * success flags = (system default success flags + per-user always success) -
 *			per-user never success flags
 * failure flags = (system default failure flags + per-user always failure) -
 *			per-user never failure flags
 */

int
au_user_mask(char *user, au_mask_t *mask)
{
	char		*last = NULL;
	char		*user_flags = NULL;

	if (mask == NULL) {
		return (-1);
	}

	/*
	 * Get the system wide default audit flags. If you can't get the
	 * system wide flags, return an error code now and don't bother
	 * trying to get the user specific flags.
	 */
	if (auditon(A_GETAMASK, (caddr_t)mask, sizeof (*mask)) == -1) {
		return (-1);
	}

	/*
	 * Get per-user audit flags.
	 */
	(void) _enum_attrs(user, audit_flags, &user_flags, NULL);
	if (user_flags != NULL) {
		au_user_ent_t  per_user;

		(void) getauditflagsbin(_strtok_escape(user_flags,
		    KV_AUDIT_DELIMIT, &last), &(per_user.au_always));
		(void) getauditflagsbin(_strtok_escape(NULL,
		    KV_AUDIT_DELIMIT, &last), &(per_user.au_never));
		/* merge default and per-user */
		mask->as_success |= per_user.au_always.as_success;
		mask->as_failure |= per_user.au_always.as_failure;
		mask->as_success &= ~(per_user.au_never.as_success);
		mask->as_failure &= ~(per_user.au_never.as_failure);
		free(user_flags);
	}

	return (0);
}
