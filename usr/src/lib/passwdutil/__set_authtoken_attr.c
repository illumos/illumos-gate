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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
 */

#include <errno.h>
#include <sys/types.h>
#include <sys/types.h>
#include <nsswitch.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "passwdutil.h"

int
__set_authtoken_attr(const char *name, const char *oldpw, pwu_repository_t *rep,
    attrlist *items, int *updated_reps)
{
	attrlist *p;
	int repositories;
	int i;
	void *buf;		/* workspace for repository specific funcs */
	int err = PWU_NOT_FOUND;
	int rep_success = REP_NOREP;	/* first successfull update */
	int updated = REP_NOREP;	/* (bitmask) all updates */

	/* Can't set name uid or flag */
	for (p = items; p != NULL; p = p->next) {
		switch (p->type) {
		case ATTR_NAME:
		case ATTR_UID:
		case ATTR_FLAG:
			return (EINVAL);
		}
	}

	repositories = get_ns(rep, PWU_WRITE);

	if (repositories == 0)
		return (PWU_SYSTEM_ERROR);

	/*
	 * updating requires that either
	 *  - PAM_REPOSITORY is set: we know what to update
	 *  - PAM_REPOSITORY is not set, but we recognize the nsswitch.conf
	 *    passwd: entry
	 */
	if (repositories == REP_ERANGE || repositories == REP_NSS)
		return (PWU_REPOSITORY_ERROR);

	/*
	 * Loop over selected repositories to update
	 * We should update the remote repositories first, FILES last.
	 */
	for (i = REP_LAST; i; i >>= 1) {
		if (repositories & i) {
			buf = NULL;

			if (rops[i]->lock && (err = rops[i]->lock()))  {
				return (err);
			}

			if (rops[i]->getpwnam) {
				err = rops[i]->getpwnam(name, items, rep, &buf);
			}

			if ((err == PWU_SUCCESS) && rops[i]->update)
				err = rops[i]->update(items, rep, buf);

			if ((err == PWU_SUCCESS) && rops[i]->putpwnam)
				err = rops[i]->putpwnam(name, oldpw, rep, buf);

			if (rops[i]->unlock)
				(void) rops[i]->unlock();

			if (buf) {
				(void) free(buf);
				buf = NULL;
			}
			if (err == PWU_SUCCESS) {
				rep_success = i;	/* this rep succeeded */
				updated |= i;
			} else if (err != PWU_SUCCESS && err != PWU_NOT_FOUND) {
				break;
			}
		}
	}

	if (buf)
		free(buf);

	if (updated_reps)
		*updated_reps = (updated != REP_NOREP) ? updated : i;

	/*
	 * err contains either
	 *  PWU_SUCCESS		: everyting went OK
	 *  PWU_NOT_FOUND	: none of the repositories contained the user
	 *  error-code		: the specific error that occurred
	 */
	if (rep_success != REP_NOREP) {
		return (PWU_SUCCESS);
	} else {
		return (err);
	}
}
