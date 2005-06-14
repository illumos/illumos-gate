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

/*
 * DESCRIPTION:	Contains functions relating to the creation and manipulation
 *		of map_ctrl structures. These are used to hold information
 *		specific to one NIS map.
 *
 *		Because each of these contains a significant amount of state
 *		information about an individual map they are created (on the
 *		heap) when a map is opened and destroyed when it is closed.
 *		The overhead of doing this is less than maintaining a pool
 *		of map_ctrls.
 *
 *		If two processes access the same map two map_ctrls will be
 *		created with similar contents (but differing DBM pointers).
 *		Both will have the same hash value so when one is locked
 *		access to the other will also be prevented.
 */

#include <unistd.h>
#include <syslog.h>
#include <ndbm.h>
#include <string.h>
#include "ypsym.h"
#include "ypdefs.h"
#include "shim.h"
#include "yptol.h"
#include "../ldap_util.h"

/* Switch on parts of ypdefs.h */
USE_DBM

/*
 * FUNCTION: 	create_map_ctrl();
 *
 * DESCRIPTION: Create and a new map_ctrl in a non opened state.
 *
 * INPUTS:	Fully qualified map name
 *
 * OUTPUTS:	Pointer to map_ctrl
 *		NULL on failure.
 *
 */
map_ctrl *
create_map_ctrl(char *name)
{
	char *myself = "create_map_ctrl";
	map_ctrl *map;

	map = (map_ctrl *)am(myself, sizeof (map_ctrl));
	if (NULL == map) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR, "Could not alloc map_ctrl");
		return (NULL);
	}

	/* Clear new map (in case we have to free it) */
	map->entries = NULL;
	map->hash_val = 0;
	map->map_name = NULL;
	map->domain = NULL;
	map->map_path = NULL;
	map->ttl = NULL;
	map->ttl_path = NULL;
	map->trad_map_path = NULL;
	map->key_data.dptr = NULL;
	map->open_mode = 0;
	map->open_flags = 0;

	/*
	 * Initialize the fields of the map_ctrl. By doing this once here we
	 * can save a lot of work as map entries are accessed.
	 */
	if (SUCCESS != map_ctrl_init(map, name)) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"Could not initialize map_ctrl for %s", name);
		free_map_ctrl(map);
		return (NULL);
	}

	return (map);
}

/*
 * FUNCTION :	map_ctrl_init()
 *
 * DESCRIPTION:	Initializes the fields of a map_ctrl structure.
 *
 *		By doing this once (when the map_ctrl is created) we avoid
 *		numerous other function having to repeat this string
 *		manipulation.
 *
 * GIVEN :	Pointer to the structure
 *		Fully qualified name of the map
 *
 * RETURNS :	SUCCESS = map_ctrl fully set up.
 *		FAILURE = map_ctrl not set up CALLER MUST FREE.
 */
suc_code
map_ctrl_init(map_ctrl *map, char *name)
{
	char *myself = "map_ctrl_init";
	char *p, *q;

	/* Save map path for future reference */
	map->map_path = (char *)strdup(name);
	if (NULL ==  map->map_path) {
		logmsg(MSG_NOMEM, LOG_ERR,
				"Could not duplicate map path %s", map);
		return (FAILURE);
	}

	/* Work out map's unqualified name from path */
	p = strrchr(name, SEP_CHAR);
	if (NULL == p) {
		/* Must be at least a domain and name */
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"Could not find separator in map path %s", map);
		return (FAILURE);
	}
	q = p + 1;

	/* Check for and remove N2L prefix */
	if (yptol_mode) {
		/*
		 * Check for and remove N2L prefix. If not found not a problem
		 * we open some old style maps during DIT initialization.
		 */
		if (0 == strncmp(q, NTOL_PREFIX, strlen(NTOL_PREFIX)))
			q += strlen(NTOL_PREFIX);
	} else {
		if (0 == strncmp(q, NTOL_PREFIX, strlen(NTOL_PREFIX)))
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"Working in non N2L mode and path %s "
				"contains N2L prefix", name);
	}

	/* Save unqualified map name */
	map->map_name = strdup(q);
	if (NULL == map->map_name) {
		logmsg(MSG_NOMEM, LOG_ERR,
				"Could not duplicate map name %s", q);
		return (FAILURE);
	}

	/* Work out map's domain name from path */
	for (q = p-1; (SEP_CHAR != *q) && (q > name); q--);

	if (q <= name) {
		/* Didn't find separator */
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"Could not find domain in map path %s", name);
		return (FAILURE);
	}

	map->domain = (char *)am(myself, p - q);
	if (NULL == map->domain) {
		logmsg(MSG_NOMEM, LOG_ERR,
			"Could not alloc memory for domain in path %s", name);
		return (FAILURE);
	}
	strncpy(map->domain, q + 1, p-q-1);
	map->domain[p-q-1] = '\0';

	/* Work out extra names required by N2L */
	if (yptol_mode) {
		/*
		 * Work out what old style NIS path would have been. This is
		 * used to check for date of DBM file so add the DBM
		 * extension.
		 */
		map->trad_map_path = (char *)am(myself, strlen(map->map_name) +
					+ strlen(dbm_pag) + (p - name) + 2);
		if (NULL == map->trad_map_path) {
			logmsg(MSG_NOMEM, LOG_ERR,
				"Could not alocate memory for "
				"traditional map path derived from %s", name);
			return (FAILURE);
		}

		strncpy(map->trad_map_path, name, p - name + 1);
		map->trad_map_path[p - name + 1] = '\0';
		strcat(map->trad_map_path, map->map_name);
		strcat(map->trad_map_path, dbm_pag);

		/* Generate qualified TTL file name */
		map->ttl_path = (char *)am(myself, strlen(map->map_path) +
						strlen(TTL_POSTFIX) + 1);
		if (NULL == map->ttl_path) {
			logmsg(MSG_NOMEM, LOG_ERR,
				"Could not alocate memory for "
				"ttl path derived from %s", name);
			return (FAILURE);
		}

		strcpy(map->ttl_path, map->map_path);
		strcat(map->ttl_path, TTL_POSTFIX);
	}

	/* Work out hash value */
	map->hash_val = hash(name);

	/* Set up magic number */
	map->magic = MAP_MAGIC;

	/* Null out pointers */
	map->entries = NULL;
	map->ttl = NULL;

	/* No key data yet */
	map->key_data.dptr = NULL;
	map->key_data.dsize = 0;

	return (SUCCESS);
}

/*
 * FUNCTION: 	get_map_crtl();
 *
 * DESCRIPTION: Find an existing map_ctrl for a map of a given DBM * (i.e.
 *		handle) . If none exists return an error.
 *
 * INPUTS:	Map handle
 *
 * OUTPUTS:	Pointer to map_ctrl
 *		NULL on failure.
 *
 */
map_ctrl *
get_map_ctrl(DBM *db)
{
	/* Check that this really is a map_ctrl not a DBM */
	if (((map_ctrl *)db)->magic != MAP_MAGIC) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"SHIM called with DBM ptr not map_crtl ptr");
		return (NULL);
	}

	/* Since this is an opaque pointer just cast it */
	return ((map_ctrl *)db);
}

/*
 * FUNCTION:	dup_map_ctrl()
 *
 * DESCRIPTION:	Duplicates a map_ctrl structure
 *
 * GIVEN :	Map_ctrl to duplicate
 *
 * RETURNS :	Pointer to a new malloced map_ctrl. CALLER MUST FREE
 *		NULL on failure.
 */
map_ctrl *
dup_map_ctrl(map_ctrl *old_map)
{
	map_ctrl *new_map;

	/*
	 * Could save a little bit of time by duplicating the static parts
	 * of the old map but on balance it is cleaner to just make a new one
	 * from scratch
	 */
	new_map = create_map_ctrl(old_map->map_path);

	if (NULL == new_map)
		return (NULL);

	/* If old map had open handles duplicate them */
	if (NULL != old_map->entries) {
		new_map->open_flags = old_map->open_flags;
		new_map->open_mode = old_map->open_mode;
		if (FAILURE == open_yptol_files(new_map)) {
			free_map_ctrl(new_map);
			return (NULL);
		}
	}

	return (new_map);
}

/*
 * FUNCTION: 	free_map_crtl();
 *
 * DESCRIPTION: Free contents of a map_ctr structure and closed any open
 *		DBM files.
 *
 * INPUTS:	Pointer to pointer to a map_ctrl.
 *
 * OUTPUTS:	Nothing
 *
 */
void
free_map_ctrl(map_ctrl *map)
{

	if (NULL != map->entries) {
		dbm_close(map->entries);
		map->entries = NULL;
	}

	if (NULL != map->map_name) {
		sfree(map->map_name);
		map->map_name = NULL;
	}

	if (NULL != map->map_path) {
		sfree(map->map_path);
		map->map_path = NULL;
	}

	if (NULL != map->domain) {
		sfree(map->domain);
		map->domain = NULL;
	}

	if (yptol_mode) {
		if (NULL != map->ttl) {
			dbm_close(map->ttl);
			map->ttl = NULL;
		}

		if (NULL != map->trad_map_path) {
			sfree(map->trad_map_path);
			map->trad_map_path = NULL;
		}

		if (NULL != map->ttl_path) {
			sfree(map->ttl_path);
			map->ttl_path = NULL;
		}

		if (NULL != map->key_data.dptr) {
			sfree(map->key_data.dptr);
			map->key_data.dptr = NULL;
			map->key_data.dsize = 0;
		}
	}

	map->magic = 0;

	/* Since map_ctrls are now always in malloced memory */
	sfree(map);

}

/*
 * FUNCTION :	get_map_name()
 *
 * DESCRIPTION:	Get the name of a map from its map_ctrl. This could be done
 *		as a simple dereference but this function hides the internal
 *		implementation of map_ctrl from higher layers.
 *
 * GIVEN :	A map_ctrl pointer
 *
 * RETURNS :	A pointer to the map_ctrl. Higher levels treat this as an
 *		opaque DBM pointer.
 *		NULL on failure.
 */
char *
get_map_name(DBM *db)
{
	map_ctrl *map = (map_ctrl *)db;

	if (NULL == map)
		return (NULL);

	return (map->map_name);
}

/*
 * FUNCTION :	set_key_data()
 *
 * DESCRIPTION:	Sets up the key data freeing any that already exists.
 *
 * GIVEN :	Pointer to the map_ctrl to set up.
 *		Datum containing the key. The dptr of this will be set to
 *		point to the key data.
 *
 * RETURNS :	Nothing
 */
void
set_key_data(map_ctrl *map, datum *data)
{
	char *myself = "set_key_data";

	/*
	 * Free up any existing key data. Because each dbm file can only have
	 * one enumeration going at a time this is safe.
	 */
	if (NULL != map->key_data.dptr) {
		sfree(map->key_data.dptr);
		map->key_data.dptr = NULL;
		map->key_data.dsize = 0;
	}

	/* If nothing in key just return */
	if (NULL == data->dptr)
		return;

	/* Something is in the key so must duplicate out of static memory */
	map->key_data.dptr = (char *)am(myself, data->dsize);
	if (NULL == map->key_data.dptr) {
		logmsg(MSG_NOMEM, LOG_ERR, "Cannot alloc memory for key data");
	} else {
		memcpy(map->key_data.dptr, data->dptr, data->dsize);
		map->key_data.dsize = data->dsize;
	}

	/* Set datum to point to malloced version of the data */
	data->dptr = map->key_data.dptr;

	return;

}

/*
 * FUNCTION :	open_yptol_files()
 *
 * DESCRIPTION:	Opens both yptol files for a map. This is called both when a
 *		map is opened and when it is reopened as a result of an update
 *		operation. Must be called with map locked.
 *
 * GIVEN :	Initialized map_ctrl
 *
 * RETURNS :	SUCCESS = Maps opened
 *		FAILURE = Maps not opened (and mess tidied up)
 */
suc_code
open_yptol_files(map_ctrl *map)
{

	/* Open entries map */
	map->entries = dbm_open(map->map_path, map->open_flags, map->open_mode);

	if (NULL == map->entries) {
		/* Maybe we were asked to open a non-existent map. No problem */
		return (FAILURE);
	}

	if (yptol_mode) {
		/* Open TTLs map. Must always be writable */
		map->ttl = dbm_open(map->ttl_path, O_RDWR | O_CREAT, 0644);
		if (NULL == map->ttl) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"Cannot open TTL file %s", map->ttl_path);
			dbm_close(map->entries);
			map->entries = NULL;
			return (FAILURE);
		}
	}

	return (SUCCESS);
}
