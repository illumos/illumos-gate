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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <poll.h>
#include <sys/time.h>
#include <stdlib.h>
#include "nis_ldap.h"
#include "nis_hashitem.h"
#include "ldap_map.h"
#include "ldap_parse.h"


/*
 * Global structure keeping config state. Since it's created and modified
 * while the rpc.nisd still is single-threaded, and only read in MT mode,
 * no locking is needed.
 */
__nis_config_t	ldapConfig = {
	ini_none,			/* nisplusLDAPinitialUpdate */
	pass_error,			/* nisplusLDAPthreadCreationError */
	{
		-1,			/* Try forever */
		15			/* 15 second timeout */
	},
	de_retry,			/* nisplusLDAPdumpError */
	{
		-1,			/* Try forever */
		200			/* 200 second timeout */
	},
	directory_locked,		/* nisplusLDAPresyncService */
	accumulate,			/* nisplusLDAPupdateBatching */
	{
		-1,			/* Not used */
		120			/* Accumulate for 120 seconds */
	},
	block				/* nisplusLDAPexclusiveWaitMOde */
};


/*
 * Utility function that accepts a (__nisdb_retry_t *), decrements the
 * 'attempts' counter, and sleeps for 'timeout' seconds.
 *
 * NOTE:	Don't pass a pointer into the 'ldapConfig' structure to
 *		this function. Instead, initialize a private copy to the
 *		value from 'ldapConfig'.
 *
 * The value of 'attempts' upon entry determines action as follows:
 *
 *	< 0	Don't change 'attempts', sleep as indicated, return 1
 *
 *	  0	Don't change 'attempts', only sleep if forceSleep is set,
 *		return 0 if we didn't sleep, 1 if we slept.
 *
 *	> 0	Decrement 'attempts', sleep as indicated, return 1
 */
int
__nis_retry_sleep(__nisdb_retry_t *retry, int forceSleep) {

	if (retry == NULL)
		return (0);

	if (retry->attempts > 0) {
		retry->attempts -= 1;
	} else if (retry->attempts == 0 && !forceSleep) {
		return (0);
	}

	(void) poll(NULL, 0, retry->timeout*1000);

	return (1);
}

/*
 * The root directory is special in NIS+; it's the only directory that
 * doesn't appear as an entry in another directory. Hence, our method
 * of keeping the directory/table entry expiration time in the
 * directory/table doesn't work, and we instead implement the following
 * interface.
 */
static time_t	rootDirExpire = 0;
static int	rootDirTtl = 0;

/*
 * Return 1 if the root dir has expired, 0 otherwise.
 */
int
rootDirExpired(void) {
	struct timeval	now;

	(void) gettimeofday(&now, 0);

	if (rootDirExpire >= now.tv_sec)
		return (1);
	else
		return (0);
}

/*
 * Update the expiration time of the root dir to be now plus the TTL.
 * Also establishes the TTL if not set.
 */
int
touchRootDir(void) {
	struct timeval	now;
	int		ttl;

	(void) gettimeofday(&now, 0);

	/* Do we need to initialize the TTL ? */
	if (rootDirTtl == 0) {
		__nis_table_mapping_t	*t;

		t = __nis_find_item_mt(ROOTDIRFILE, &ldapMappingList, 0, 0);
		if (t != 0) {
			int	interval;

			interval = t->initTtlHi - t->initTtlLo + 1;

			if (interval > 1) {
				srand48(now.tv_sec);
				ttl = (lrand48() % interval);
			} else {
				ttl = t->initTtlLo;
			}

			rootDirTtl = t->ttl;
		} else {
			ttl = rootDirTtl = 3600;
		}
	} else {
		ttl = rootDirTtl;
	}

	rootDirExpire = now.tv_sec + ttl;

	return (0);
}
