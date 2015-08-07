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
 * Copyright 2015 Gary Mills
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * DESCRIPTION: Contains the map update thread and related code.
 */

#include <unistd.h>
#include <syslog.h>
#include <ndbm.h>
#include <thread.h>
#include <unistd.h>
#include <strings.h>
#include "ypsym.h"
#include "ypdefs.h"
#include "shim.h"
#include "yptol.h"
#include "../ldap_util.h"

/* Enable standard YP code features defined in ypdefs.h */
USE_YP_PREFIX
USE_YP_MASTER_NAME
USE_YP_LAST_MODIFIED
USE_YP_INPUT_FILE
USE_YP_OUTPUT_NAME
USE_YP_DOMAIN_NAME
USE_YP_SECURE
USE_YP_INTERDOMAIN

/*
 * Decs
 */
suc_code update_from_dit(map_ctrl *, datum *);
void * update_thread(void *);

/*
 * Globals
 */
extern pid_t parent_pid;

/*
 * FUNCTION:	update_entry_if_required()
 *
 * DESCRIPTION:	Determines if an entry is to be updated and if it is does the
 *		update.
 *
 * GIVEN :	Pointer to the open map ctrl
 *		Pointer to the entry key
 *
 * RETURNS :	SUCCESS = Entry is in a state to be returned to the client
 *		i.e. either got updated, did not need to be updated or we are
 *		in a mode where it is acceptable to return out of date
 *		information.
 *		FAILURE = Entry need an update but it could not be done.
 */
suc_code
update_entry_if_required(map_ctrl *map, datum *key)
{

	/* Only update individual entries if entire map is */
	/* not being updated */
	if (is_map_updating(map))
		return (SUCCESS);

	/*
	 * If we are being asked for the order then need to check if
	 * the map is in need of an update. If it is then fake a
	 * recent order. The client will then read the map, using
	 * dbm_firstkey and this will do the update.
	 */
	if (0 == strncmp(key->dptr, yp_last_modified, yp_last_modified_sz)) {
		if (has_map_expired(map))
			update_timestamp(map->entries);
		return (SUCCESS);
	}

	/* Never update special keys. Have no TTLs */
	if (is_special_key(key))
		return (SUCCESS);

	if (!has_entry_expired(map, key))
		/* Didn't need an update */
		return (SUCCESS);

	/* Do the update */
	return (update_from_dit(map, key));
}

/*
 * FUNCTION:	update_from_dit()
 *
 * DESCRIPTION:	Called to update an entry from the DIT
 *
 * INPUTS:	Map control structure for an open map
 *		Entry key
 *
 * OUTPUTS:	SUCCESS = Update complete or we are in a mode where it is
 *		acceptable to return out of date information.
 *		FAILURE =  Update failed
 *
 */
suc_code
update_from_dit(map_ctrl *map, datum *key)
{
	datum dat;
	int ret;
	suc_code res;

	/*
	 * Netgroup maps are a special case we cannot update just one entry so
	 * update the entire map instead.
	 */
	if ((0 == strcmp(map->map_name, NETGROUP_BYHOST)) ||
		(0 == strcmp(map->map_name, NETGROUP_BYUSER))) {
			return (update_map_if_required(map, FALSE));
	}

	/* Read entry from the DIT */
	ret = read_from_dit(map->map_name, map->domain, key, &dat);

	/* Check that we got something */
	if (NULL == dat.dptr) {
		if (0 == ret) {
			/*
			 * In a mode where it is acceptable to return out of
			 * date information.
			 */
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"LDAP inaccessible returning old information");
			return (SUCCESS);
		} else {
			/*
			 * In a mode where it is not acceptable to return out
			 * of date information.
			 *
			 * If the error positviely indicates that there is no
			 * such entry delete it. For errors where object may
			 * still exist in the DIT leave it.
			 */
			if (MAP_NO_MATCHING_KEY == ret) {
				/*
				 * Don't log errors. If the entry was not
				 * already present then no problem. The user
				 * just asked us for a non existant entry.
				 */
				dbm_delete(map->entries, *key);
				dbm_delete(map->ttl, *key);
			}
			return (FAILURE);
		}
	}

	/* Write it to DBM */
	res = dbm_store(map->entries, *key, dat, DBM_REPLACE);
	sfree(dat.dptr);

	if (SUCCESS != res)
		return (FAILURE);

	/* Update TTL */
	update_entry_ttl(map, key, TTL_RUNNING);

	return (SUCCESS);
}

/*
 * FUNCTION:	update_map_if_required()
 *
 * DESCRIPTION:	Called to update an entire map if it is out of date. Map ctrl
 *		must be locked before this is called. This handles checking if
 *		the map is already being updated. It is important that this is
 *		done atomically	with obtaining the maps update lock.
 *
 * INPUTS:	Map control structure for an open map
 *		Flag indication if we should wait for completion
 *
 * OUTPUTS:	SUCCESS = Map update initiated
 *		FAILURE =  Map update not initiated
 */
suc_code
update_map_if_required(map_ctrl *map, bool_t wait)
{
	thread_t tid;
	map_ctrl *new_map;
	suc_code res;
	long	 flags;

	if (wait) {
		/*
		 * Actually get the lock
		 *
		 * May block so unlock map_ctrl while it is done
		 */
		unlock_map_ctrl(map);
		res = lock_map_update(map);
		lock_map_ctrl(map);
		if (SUCCESS != res) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"Could not lock map %s for update",
								map->map_name);
			return (FAILURE);
		}
	} else {
		/* If not waiting try to get the lock */
		switch (try_lock_map_update(map)) {
			case 0:
				/*
				 * We got the lock. Continue to start an update.
				 */
				break;

			case EBUSY:
				/*
				 * Some one else got the lock. OK they are
				 * doing the update so we can just return.
				 */
				return (SUCCESS);

			default:
				/*
				 * Some serious problem with lock.
				 */
				return (FAILURE);
		}
	}

	/*
	 * If we get here are holding the update lock. Make a final check that
	 * nobody beat us to the map update while we were getting it.
	 */
	if (!has_map_expired(map)) {
		/* A big waste of time. Somebody else did the update */
		unlock_map_update(map);
		return (SUCCESS);
	}

	/*
	 * We got the lock and nobody beat us to doing the update. Start our
	 * own update.
	 *
	 * Thread will free the update lock when update is complete.
	 */


	/*
	 * Make a copy of the map_ctrl structure so the update thread has an
	 * independent version to work with. Note: Must not be on stack.
	 *
	 * On exit the update thread must free this.
	 */
	new_map = dup_map_ctrl(map);
	if (NULL == new_map) {
		unlock_map_update(map);
		return (FAILURE);
	}

	/*
	 * While thread is running unlock map so other processes can
	 * execute non update related accesses
	 */
	unlock_map_ctrl(map);

	flags = THR_BOUND | THR_NEW_LWP;

	/*
	 * If we are not going to thr_join then need to create detached.
	 * This prevents a zombie being left when nobody joins us.
	 */
	if (!wait && (getpid() == parent_pid))
		flags |= THR_DETACHED;

	/* Kick off update thread */
	if (0 != thr_create(NULL, NULL, update_thread, new_map,
							flags, &tid)) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"Could not create NIS update thread");
		free_map_ctrl(new_map);
		unlock_map_update(map);
		if (SUCCESS != lock_map_ctrl(map))
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"Could not acquire update lock for %s", map->map_name);
		return (FAILURE);
	}

	if (wait) {
		/* May block but no problem map_ctrl is already unlocked. */
		thr_join(tid, NULL, NULL);
	}

	/* Re acquire lock */
	if (1 != lock_map_ctrl(map)) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"Could not re-acquire lock for %s", map->map_name);
		return (FAILURE);
	}

	return (SUCCESS);
}

/*
 * FUNCTION:	update_thread()
 *
 * DESCRIPTION:	The update thread this is called to update an entire NIS map.
 *		if several NIS maps are found to be out of date several
 *		instances of this may be running at the same time.
 *
 *		Since we are using a duplicate map_ctrl we do not have to lock
 *		it. If we did would end up using the same mutex as the parent
 *		map ctrl an possibly deadlocking.
 *
 * INPUTS:	Map handle (because we need access to name and lock)
 *
 * OUTPUTS:	None exits when finished.
 */

void *
update_thread(void *arg)
{
	void *ret = (void *)-1;
	map_ctrl *map;

	/* Cast argument pointer to correct type */
	map = (map_ctrl *)arg;

	/* Actually do the work */
	if (SUCCESS == update_map_from_dit(map, FALSE))
		ret = 0;

	/* Update complete or failed */
	unlock_map_update(map);

	/* Free up duplicate copy of the map_ctrl */
	free_map_ctrl(map);

	thr_exit(ret);

	return (NULL);
}

/*
 * FUNCTION :	is_special_key()
 *
 * DESCRIPTION:	Works out if a given key is one of the special ones. We just
 *		check for the "YP_" prefix. This is not 100% safe but if
 *		valid keys with a "YP_" prefix exist in the DIT then a lot of
 *		other parts of NIS wont work.
 */
bool_t
is_special_key(datum *key)
{
	if (0 == strncmp(key->dptr, yp_prefix, yp_prefix_sz))
		return (TRUE);

	return (FALSE);
}
