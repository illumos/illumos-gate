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
 *	autod_lookup.c
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <locale.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include "automount.h"

int
do_lookup1(
	char *mapname,
	char *key,
	char *subdir,
	char *mapopts,
	char *path,
	uint_t isdirect,
	uid_t uid,
	autofs_action_t *action,
	struct linka *linkp)
{
	struct mapline ml;
	struct mapent *mapents = NULL;
	int err;
	struct autofs_rddir_cache *rdcp;
	int found = 0;
	bool_t iswildcard = FALSE;
	bool_t isrestricted = hasrestrictopt(mapopts);
	char *stack[STACKSIZ];
	char **stkptr = stack;

	/*
	 * Default action is for no work to be done by kernel AUTOFS.
	 */
	*action = AUTOFS_NONE;

	/*
	 * Is there a cache for this map?
	 */
	rw_rdlock(&autofs_rddir_cache_lock);
	err = autofs_rddir_cache_lookup(mapname, &rdcp);
	if (!err && rdcp->full) {
		rw_unlock(&autofs_rddir_cache_lock);
		/*
		 * Try to lock readdir cache entry for reading, if
		 * the entry can not be locked, then avoid blocking
		 * and go to the name service. I'm assuming it is
		 * faster to go to the name service than to wait for
		 * the cache to be populated.
		 */
		if (rw_tryrdlock(&rdcp->rwlock) == 0) {
			found = (rddir_entry_lookup(key, rdcp->entp) != NULL);
			rw_unlock(&rdcp->rwlock);
		}
	} else
		rw_unlock(&autofs_rddir_cache_lock);

	if (!err) {
		/*
		 * release reference on cache entry
		 */
		mutex_lock(&rdcp->lock);
		rdcp->in_use--;
		assert(rdcp->in_use >= 0);
		mutex_unlock(&rdcp->lock);
	}

	if (found)
		return (0);

	/*
	 * entry not found in cache, try the name service now
	 */
	err = 0;

	/* initialize the stack of open files for this thread */
	stack_op(INIT, NULL, stack, &stkptr);

	err = getmapent(key, mapname, &ml, stack, &stkptr, &iswildcard,
		isrestricted);
	if (err == 0) /* call parser w default mount_access = TRUE */
		mapents = parse_entry(key, mapname, mapopts, &ml,
				    subdir, isdirect, TRUE);

	/*
	 * Now we indulge in a bit of hanky-panky.
	 * If the entry isn't found in the map and the
	 * name begins with an "=" then we assume that
	 * the name is an undocumented control message
	 * for the daemon.  This is accessible only
	 * to superusers.
	 */
	if (mapents == NULL && *action == AUTOFS_NONE) {
		if (*key == '=' && uid == 0) {
			if (isdigit(*(key+1))) {
				/*
				 * If next character is a digit
				 * then set the trace level.
				 */
				trace = atoi(key+1);
				trace_prt(1, "Automountd: trace level = %d\n",
					trace);
			} else if (*(key+1) == 'v') {
				/*
				 * If it's a "v" then
				 * toggle verbose mode.
				 */
				verbose = !verbose;
				trace_prt(1, "Automountd: verbose %s\n",
						verbose ? "on" : "off");
			}
		}

		err = ENOENT;
		goto done;
	}

	/*
	 * Each mapent in the list describes a mount to be done.
	 * Since I'm only doing a lookup, I only care whether a mapentry
	 * was found or not. The mount will be done on a later RPC to
	 * do_mount1.
	 */
	if (mapents == NULL && *action == AUTOFS_NONE)
		err = ENOENT;

done:	if (mapents)
		free_mapent(mapents);

	if (*action == AUTOFS_NONE && (iswildcard == TRUE)) {
		*action = AUTOFS_MOUNT_RQ;
	}
	if (trace > 1) {
		trace_prt(1, "  do_lookup1: action=%d wildcard=%s error=%d\n",
			*action, iswildcard ? "TRUE" : "FALSE", err);
	}
	return (err);
}
