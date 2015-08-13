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
 * Copyright 2015 Gary Mills
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * DESCRIPTION: Contains the top level shim hook functions. These must have
 *		identical interfaces to the equivalent standard dbm calls.
 *
 *		Unfortunately many of these will do a copy of a datum structure
 *		on return. This is a side effect of the original DBM function
 *		being written to pass structures rather than pointers.
 *
 * NOTE :	There is a major bug/feature in dbm. A key obtained by
 *		dbm_nextkey() of dbm_firstkey() cannot be passed to dbm_store().
 *		When the store occurs dbm's internal memory get's reorganized
 *		and the static strings pointed to by the key are destroyed. The
 *		data is then stored in the wrong place. We attempt to get round
 *		this by dbm_firstkey() and dbm_nextkey() making a copy of the
 *		key data in malloced memory. This is freed when map_ctrl is
 *		freed.
 */

#include <unistd.h>
#include <syslog.h>
#include <ndbm.h>
#include <strings.h>
#include "ypsym.h"
#include "ypdefs.h"
#include "shim.h"
#include "yptol.h"
#include "stubs.h"
#include "../ldap_parse.h"
#include "../ldap_util.h"

/*
 * Globals
 */
bool_t yptol_mode = FALSE;	/* Set if in N2L mode */
bool_t yptol_newlock = FALSE;
				/*
				 * Set if in N2L mode and we want to use the new
				 * lock mapping mechanism
				 */
bool_t ypxfrd_flag = FALSE;	/* Set if called from ypxfrd */
pid_t parent_pid;			/* ID of calling parent process */


/*
 * Decs
 */
void check_old_map_date(map_ctrl *);

/*
 * Constants
 */
/* Number of times to try to update a map before giving up */
/* #define MAX_UPDATE_ATTEMPTS 3 */
#define	MAX_UPDATE_ATTEMPTS 1

/*
 * FUNCTION:    shim_dbm_close();
 *
 * INPUTS:      Identical to equivalent dbm call.
 *
 * OUTPUTS:     Identical to equivalent dbm call.
 *
 */
void
shim_dbm_close(DBM *db)
{
	map_ctrl *map;

	/* Lock the map */
	map = get_map_ctrl(db);
	if (map == NULL)
		return;

	free_map_ctrl(map);
}

/*
 * FUNCTION:    shim_dbm_delete();
 *
 * DESCRIPTION:	This function is currently unused but is present so that the
 *		set of shim_dbm_xxx() interfaces is complete if required in
 *		future.
 *
 * INPUTS:      Identical to equivalent dbm call.
 *
 * OUTPUTS:     Identical to equivalent dbm call.
 *
 */
int
shim_dbm_delete(DBM *db, datum key)
{
	int ret;
	map_ctrl *map;

	/* Lock the map */
	map = get_map_ctrl(db);
	if (map == NULL)
		return (FAILURE);
	if (1 != lock_map_ctrl(map))
		return (FAILURE);

	if (yptol_mode) {
		/* Delete from and ttl map. Not a huge disaster if it fails. */
		dbm_delete(map->ttl, key);
	}

	ret = dbm_delete(map->entries, key);

	unlock_map_ctrl(map);

	return (ret);
}


/*
 * FUNCTION:    shim_dbm_fetch()
 *
 * DESCRIPTION:	N2L function used to handle 'normal' dbm_fetch() operations.
 *
 * INPUTS:      First two identical to equivalent dbm call.
 *
 * OUTPUTS:     Identical to equivalent dbm call.
 *
 */
datum
shim_dbm_fetch(DBM *db, datum key)
{
	datum ret = {0, NULL};
	map_ctrl *map;

	/* Lock the map */
	map = get_map_ctrl(db);
	if (map == NULL)
		return (ret);
	if (1 != lock_map_ctrl(map))
		return (ret);

	if (yptol_mode) {
		if (SUCCESS == update_entry_if_required(map, &key)) {
			/* Update thinks we should return something */
			ret = dbm_fetch(map->entries, key);
		}
	} else {
		/* Non yptol mode do a normal fetch */
		ret = dbm_fetch(map->entries, key);
	}

	unlock_map_ctrl(map);

	return (ret);
}

/*
 * FUNCTION:    shim_dbm_fetch_noupdate()
 *
 * DESCRIPTION:	A special version of shim_dbm_fetch() that never checks TTLs
 *		or updates entries.
 *
 * INPUTS:      Identical to equivalent dbm call.
 *
 * OUTPUTS:     Identical to equivalent dbm call.
 *
 */
datum
shim_dbm_fetch_noupdate(DBM *db, datum key)
{
	datum ret = {0, NULL};
	map_ctrl *map;

	/* Get the map control block */
	map = get_map_ctrl(db);
	if (map == NULL)
		return (ret);

	/* Not updating so no need to lock */
	ret = dbm_fetch(map->entries, key);

	return (ret);
}

/*
 * FUNCTION:    shim_dbm_firstkey()
 *
 * DESCRIPTION: Get firstkey in an enumeration. If the map is out of date then
 *	      this is the time to scan it and see if any new entries have been
 *	      created.
 *
 * INPUTS:      Identical to equivalent dbm call.
 *
 * OUTPUTS:     Identical to equivalent dbm call.
 *
 */
datum
shim_dbm_firstkey(DBM *db)
{
	int count;
	bool_t wait_flag;

	datum ret = {0, NULL};
	map_ctrl *map;

	/* Lock the map */
	map = get_map_ctrl(db);
	if (map == NULL)
		return (ret);
	if (1 != lock_map_ctrl(map))
		return (ret);

	if (yptol_mode) {
		/*
		 * Due to the limitations in the hashing algorithm ypxfrd
		 * may end up waiting on the wrong update. It must thus loop
		 * until the right map has been updated.
		 */
		for (count = 0; has_map_expired(map) &&
				(MAX_UPDATE_ATTEMPTS > count); count++) {
			/*
			 * Ideally ypxfr should wait for the map update
			 * to complete i.e. pass ypxfrd_flag into
			 * update_map_if_required(). This cannot be done
			 * because if there is a large map update the client
			 * side, ypxfr, can time out while waiting.
			 */
			wait_flag = FALSE;
			update_map_if_required(map, wait_flag);

			if (wait_flag) {
				/*
				 * Because ypxfrd does weird things with DBMs
				 * internal structures it's a good idea to
				 * reopen here. (Code that uses the real DBM
				 * API appears not to need this.)
				 *
				 * This should not be necessary all we have
				 * done is 'mv' the new file over the old one.
				 * Open handles should get the old data but if
				 * these lines are removed the first ypxfrd
				 * read access fail with bad file handle.
				 *
				 * NOTE : If we don't wait, because of the
				 * ypxfr timeout problem, there is no point
				 * doing this.
				 */
				dbm_close(map->entries);
				dbm_close(map->ttl);
				if (FAILURE == open_yptol_files(map)) {
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
						"Could not reopen DBM files");
				}
			} else {
				/* For daemons that don't wait just try once */
				break;
			}
		}

		if (MAX_UPDATE_ATTEMPTS < count)
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"Cannot update map %s", map->map_name);
	}

	ret = dbm_firstkey(map->entries);

	/* Move key data out of static memory. See NOTE in file header above */
	if (yptol_mode) {
		set_key_data(map, &ret);
	}
	unlock_map_ctrl(map);

	return (ret);
}

/*
 * FUNCTION:    shim_dbm_nextkey()
 *
 * DESCRIPTION: Get next key in an enumeration. Since updating an entry would
 *	      invalidate the enumeration we never do it.
 *
 * INPUTS:      Identical to equivalent dbm call.
 *
 * OUTPUTS:     Identical to equivalent dbm call.
 *
 */
datum
shim_dbm_nextkey(DBM *db)
{
	datum ret;
	map_ctrl *map;

	/* Lock the map */
	map = get_map_ctrl(db);
	if (map == NULL)
		return (ret);
	if (1 != lock_map_ctrl(map))
		return (ret);

	ret = dbm_nextkey(map->entries);

	/* Move key data out of static memory. See NOTE in file header above */
	if (yptol_mode) {
		set_key_data(map, &ret);
	}

	unlock_map_ctrl(map);

	return (ret);
}

/*
 * FUNCTION:    shim_dbm_do_nextkey()
 *
 * DESCRIPTION: Get next key in an enumeration. Since updating an entry would
 *	      invalidate the enumeration we never do it.
 *
 * NOTE :	dbm_do_nextkey is not a documented or legal DBM API.
 *		Despite this the existing NIS code calls it. One gross hack
 *		deserves another so we have this extra shim function to handle
 *		the illegal call.
 *
 * INPUTS:      Identical to equivalent dbm call.
 *
 * OUTPUTS:     Identical to equivalent dbm call.
 *
 */
datum
shim_dbm_do_nextkey(DBM *db, datum inkey)
{
	datum ret;
	map_ctrl *map;

	/* Lock the map */
	map = get_map_ctrl(db);
	if (map == NULL)
		return (ret);
	if (1 != lock_map_ctrl(map))
		return (ret);

	ret = dbm_do_nextkey(map->entries, inkey);

	/* Move key data out of static memory. See NOTE in file header above */
	if (yptol_mode) {
		set_key_data(map, &ret);
	}

	unlock_map_ctrl(map);

	return (ret);
}
/*
 * FUNCTION:    shim_dbm_open()
 *
 * INPUTS:      Identical to equivalent dbm call.
 *
 * OUTPUTS:     Identical to equivalent dbm call.
 *
 */
DBM *
shim_dbm_open(const char *file, int open_flags, mode_t file_mode)
{
	map_ctrl *map;
	suc_code ret = FAILURE;

	/* Find or create map_ctrl for this map */
	map = create_map_ctrl((char *)file);

	if (map == NULL)
		return (NULL);

	/* Lock map */
	if (1 != lock_map_ctrl(map))
		return (NULL);

	/* Remember flags and mode in case we have to reopen */
	map->open_flags = open_flags;
	map->open_mode = file_mode;

	if (yptol_mode) {
		ret = open_yptol_files(map);

		/*
		 * This is a good place to check that the
		 * equivalent old style map file has not been
		 * updated.
		 */
		if (SUCCESS == ret)
			check_old_map_date(map);

	} else {
		/* Open entries map */
		map->entries = dbm_open(map->map_path, map->open_flags,
								map->open_mode);

		if (NULL != map->entries)
			ret = SUCCESS;
	}

	/* If we were not successful unravel what we have done so far */
	if (ret != SUCCESS) {
		unlock_map_ctrl(map);
		free_map_ctrl(map);
		return (NULL);
	}

	unlock_map_ctrl(map);

	/* Return map_ctrl pointer as a DBM *. To the outside world it is */
	/* opaque. */
	return ((DBM *)map);
}

/*
 * FUNCTION: 	shim_dbm_store()
 *
 * DESCRIPTION:	Shim for dbm_store.
 *
 *		In N2L mode if we are asked to store in DBM_INSERT mode
 *		then first an attempt is made to write to the DIT (in the same
 *		mode). If this is successful then the value is forced into DBM
 *		using DBM_REPLACE. This is because the DIT is authoritative.
 *		The success of failure of an 'insert' is determined by the
 *		presence or otherwise of an entry in the DIT not DBM.
 *
 * INPUTS:	Identical to equivalent dbm call.
 *
 * OUTPUTS:	Identical to equivalent dbm call.
 *
 */
int
shim_dbm_store(DBM  *db,  datum  key,  datum  content, int store_mode)
{
	int ret;
	map_ctrl *map;

	/* Get map name */
	map = get_map_ctrl(db);
	if (map == NULL)
		return (FAILURE);

	if (yptol_mode) {
		/* Write to the DIT before doing anything else */
		if (!write_to_dit(map->map_name, map->domain, key, content,
					DBM_REPLACE == store_mode, FALSE))
			return (FAILURE);
	}

	/* Lock the map */
	if (1 != lock_map_ctrl(map))
		return (FAILURE);

	if (yptol_mode) {
		if (!is_map_updating(map)) {
			ret = dbm_store(map->entries, key, content,
								DBM_REPLACE);

			if (SUCCESS == ret)
				/* Update TTL */
				update_entry_ttl(map, &key, TTL_RAND);
		}
	} else {
		ret = dbm_store(map->entries, key, content, store_mode);
	}

	unlock_map_ctrl(map);

	return (ret);
}

/*
 * FUNCTION :	shim_exit()
 *
 * DESCRIPTION:	Intercepts exit() calls made by N2L compatible NIS components.
 *		This is required because any call to the shim_dbm... series
 *		of functions may have started an update thread. If the process
 *		exits normally then this thread may be killed before it can
 *		complete its work. We thus wait here for the thread to complete.
 *
 * GIVEN :	Same arg as exit()
 *
 * RETURNS :	Never
 */
void
shim_exit(int code)
{
	thr_join(NULL, NULL, NULL);
	exit(code);
}

/*
 * FUNCTION :	init_yptol_flag()
 *
 * DESCRIPTION: Initializes two flags these are similar but their function is
 *		subtly different.
 *
 *		yp2ldap tells the mapping system if it is to work in NIS or
 *		NIS+ mode. For N2L this is always set to NIS mode.
 *
 *		yptol tells the shim if it is to work in N2L or traditional
 *		NIS mode. For N2L this is turned on if the N2L mapping file
 *		is found to be present. In NIS+ mode it is meaningless.
 */
void
init_yptol_flag()
{
	/*
	 * yp2ldap is used to switch appropriate code in the
	 * common libnisdb library used by rpc.nisd and ypserv.
	 */
	yp2ldap = 1;
	yptol_mode = is_yptol_mode();
	/*
	 * Use the new lock mapping mechanism
	 * if in N2L mode.
	 */
	yptol_newlock = yptol_mode;
}

/*
 * FUNCTION :	set_yxfrd_flag()
 */
void
set_ypxfrd_flag()
{
	ypxfrd_flag = TRUE;
}

/*
 * FUNCTION :	check_old_map_date()
 *
 * DESCRIPTION:	Checks that an old style map has not been updated. If it has
 *		then ypmake has probably erroneously been run and an error is
 *		logged.
 *
 * GIVEN :	A map_ctrl containing details of the NEW STYLE map.
 *
 * RETURNS :	Nothing
 */
void
check_old_map_date(map_ctrl *map)
{
	datum key;
	datum value;
	struct stat stats;
	time_t old_time;

	/* Get date of last update */
	if (0 != stat(map->trad_map_path, &stats)) {
		/*
		 * No problem. We have a new style map but no old style map
		 * this will occur if the original data came from native LDAP
		 * instead of NIS.
		 */
		return;
	}

	/* Set up datum with key for recorded old map update time */
	key.dsize = strlen(MAP_OLD_MAP_DATE_KEY);
	key.dptr = MAP_OLD_MAP_DATE_KEY;
	value = dbm_fetch(map->ttl, key);

	if (NULL != value.dptr) {
		/*
		 * Because dptr may not be int aligned need to build an int
		 * out of what it points to or will get a bus error.
		 */
		bcopy(value.dptr, &old_time, sizeof (time_t));


		/* Do the comparison */
		if (stats.st_mtime <= old_time) {
			/* All is well, has not been updated */
			return;
		}

		/* If we get here the file has been updated */
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"Caution. ypmake may have been run in N2L "
			"mode. This will NOT initiate a NIS map push. In "
			"this mode pushes should be initiated with yppush");
	}

	/*
	 * If we get here then either the file was updated or there was not
	 * a valid old map date (no problem, maybe this is the first time we
	 * checked). In either case the old map date entry must be update.
	 */
	value.dptr = (char *)&(stats.st_mtime);
	value.dsize = sizeof (time_t);
	dbm_store(map->ttl, key, value, DBM_REPLACE);
}

/*
 * FUNCTION :	init_lock_system()
 *
 * DESCRIPTION:	Initializes all the systems related to map locking. This must
 *		be called before any access to the shim functions.
 *
 * GIVEN :	A flag indicating if we are being called from ypserv, which does
 *		not wait for map updates to complete, or other NIS components
 *		which do.
 *
 * RETURNS :	TRUE = Everything worked
 *		FALSE = There were problems
 */
bool_t
init_lock_system(bool_t ypxfrd)
{
	/* Remember what called us */
	if (ypxfrd)
		set_ypxfrd_flag();

	/*
	 * Remember PID of process which called us. This enables update threads
	 * created by YP children to be handled differently to those created
	 * by YP parents.
	 */
	parent_pid = getpid();

	/* Init map locks */
	if (!init_lock_map()) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"Failed to init process synchronization");
		return (FALSE);
	}

	/* If we are in yptol mode set flag indicating the fact */
	init_yptol_flag();

	/*
	 * If boot random number system. For now go for reproducible
	 * random numbers.
	 */
	srand48(0x12345678);

	/*
	 * If not N2L mode then no error but do not bother initializing update
	 * flags.
	 */
	if (yptol_mode) {
		if (!init_update_lock_map()) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"Failed to init update synchronization");
			return (FALSE);
		}
	}

	return (TRUE);
}
