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

#include "nisdb_mt.h"
#include "nisdb_rw.h"

#include "db_headers.h"
#include "db_entry.h"
#include "db.h"
#include "db_dictionary.h"


static nisdb_tsd_t	nisdb_shared_tsd;
static pthread_key_t	nisdb_tsd_key;

void
__nisdb_tsd_destroy(void *key) {

	nisdb_tsd_t	*tsd = (nisdb_tsd_t *)key;

	if (tsd != 0) {
		free(tsd);
	}
}

extern "C" {
static void
__nisdb_init_tsd_key(void)
{
	(void) pthread_key_create(&nisdb_tsd_key, __nisdb_tsd_destroy);
}
#pragma init(__nisdb_init_tsd_key)
}

nisdb_tsd_t *
__nisdb_get_tsd(void) {

	nisdb_tsd_t	*tsd;

	if ((tsd = (nisdb_tsd_t *)pthread_getspecific(nisdb_tsd_key)) == 0) {
		/* No TSD; create it */
		if ((tsd = (nisdb_tsd_t *)malloc(sizeof (*tsd))) != 0) {
			/* Initialize TSD */
			memset(tsd, 0, sizeof (*tsd));
			/* Register TSD */
			if (pthread_setspecific(nisdb_tsd_key, tsd) != 0) {
				/* Can't store key */
#ifdef	NISDB_MT_DEBUG
				abort();
#endif
				free(tsd);
				tsd = &nisdb_shared_tsd;
			}
		} else {
			/* No memory ? */
#ifdef	NISDB_MT_DEBUG
			abort();
#endif
			tsd = &nisdb_shared_tsd;
		}
	}

	return (tsd);
}

void
setMappingStatus(int nisPlusStat, int ldapStat) {
	nisdb_tsd_t	*tsd = __nisdb_get_tsd();

	if (tsd != 0) {
		tsd->nisPlusStat = nisPlusStat;
		tsd->ldapStat = ldapStat;
	}
}

/*
 * Save a copy of 'obj' in the TSD. If the TSD already holds an old object,
 * delete it before saving the new one.
 *
 * On successful exit, '*storedP' indicates whether or not the entry was
 * stored, and hence whether or not we're perfroming a modify operation.
 *
 * Return 1 if successful, 0 otherwise.
 */
int
saveOldObjForModify(entry_obj *obj, int *storedP) {
	nisdb_tsd_t	*tsd = __nisdb_get_tsd();
	int		stored;

	if (tsd == 0)
		return (0);

	if ((stored = tsd->doingModify) != 0) {
		entry_object	*eObj = tsd->oldObj;

		if (eObj != 0) {
			free_entry(eObj);
			tsd->oldObj = 0;
		}

		if (obj != 0) {
			eObj = new_entry((entry_object *)obj);
			if (eObj == 0)
				return (0);
		} else {
			eObj = 0;
		}

		tsd->oldObj = (entry_obj *)eObj;
	}

	if (storedP != 0)
		*storedP = stored;

	return (1);
}

/*
 * Retrieve (and remove) the old object (if any) from the TSD. Returns 1
 * if successful ('*oldObjP' might be NULL), 0 otherwise ('*oldObjP'
 * unchanged).
 */
int
retrieveOldObjForModify(entry_obj **oldObjP) {
	nisdb_tsd_t	*tsd = __nisdb_get_tsd();

	if (tsd == 0 || oldObjP == 0)
		return (0);

	if (tsd->doingModify) {
		*oldObjP = tsd->oldObj;
		tsd->oldObj = 0;
	} else {
		*oldObjP = 0;
	}

	return (1);
}
