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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * DESCRIPTION: Contains utilities relating to TTL calculation.
 */
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <strings.h>
#include <ndbm.h>
#include "ypsym.h"
#include "ypdefs.h"
#include "shim.h"
#include "yptol.h"
#include "../ldap_util.h"

/*
 * Constants used in time calculations
 */
#define	MILLION 1000000

/*
 * Decs
 */
suc_code is_greater_timeval(struct timeval *, struct timeval *);
suc_code add_to_timeval(struct timeval *, int);

/*
 * FUNCTION:	has_entry_expired()
 *
 * DESCRIPTION:	Determines if an individual entry has expired.
 *
 * INPUTS:	Map control structure for an open map
 *		Entry key
 *
 * OUTPUTS:	TRUE =  Entry has expired or cannot be found this will cause
 *			missing entries to be pulled out of the DIT.
 *		FALSE = Entry has not expired
 *
 */
bool_t
has_entry_expired(map_ctrl *map, datum *key)
{
	datum ttl;
	struct timeval	now;
	struct timeval	old_time;
	char	*key_name;
	char *myself = "has_entry_expired";

	if ((map == NULL) || (map->ttl == NULL))
		return (FALSE);

	/* Get expiry time entry for key */
	ttl = dbm_fetch(map->ttl, *key);

	if (NULL == ttl.dptr) {
		/*
		 * If we failed to get a map expiry key, which must always be
		 * present, then something is seriously wrong. Try to recreate
		 * the map.
		 */
		if ((key->dsize == strlen(MAP_EXPIRY_KEY)) &&
			(0 == strncmp(key->dptr, MAP_EXPIRY_KEY, key->dsize))) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR, "Cannot find %s TTL "
				"for map %s. Will attempt to recreate map",
				MAP_EXPIRY_KEY, map->map_name);
			return (TRUE);
		}

		/*
		 * Not a problem just no TTL entry for this entry. Maybe it has
		 * not yet been downloaded. Maybe it will be handled by a
		 * service other than NIS. Check if the entire map has expired.
		 * This prevents repeated LDAP reads when requests are made for
		 * nonexistant entries.
		 */
		if (has_map_expired(map)) {
			/* Kick of a map update */
			update_map_if_required(map, FALSE);
		}

		/* Don't update the entry */
		return (FALSE);
	}

	if (ttl.dsize != sizeof (struct timeval)) {
		/*
		 * Need to malloc some memory before can syslog the key name
		 * but this may fail. Solution log a simple message first THEn
		 * a more detailed one if it works.
		 */
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"Invalid TTL key in map %s. error %d",
					map->map_name, dbm_error(map->ttl));

		/* Log the key name */
		key_name = (char *)am(myself, key->dsize + 1);
		if (NULL == key_name) {
			logmsg(MSG_NOMEM, LOG_ERR,
					"Could not alloc memory for keyname");
		} else {
			strncpy(key_name, key->dptr, key->dsize);
			key_name[key->dsize] = '\0';
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
						"Key name was %s", key_name);
			sfree(key_name);
		}
		/* Update it Anyway */
		return (TRUE);
	}

	/* Get current time */
	gettimeofday(&now, NULL);

	/*
	 * Because dptr may not be int aligned need to build an int
	 * out of what it points to or will get a bus error
	 */
	bcopy(ttl.dptr, &old_time, sizeof (struct timeval));

	return (is_greater_timeval(&now, &old_time));
}

/*
 * FUNCTION:	has_map_expired()
 *
 * DESCRIPTION:	Determines if an entire map has expire
 *
 * INPUTS:	Map control structure for an open map
 *
 * OUTPUTS:	TRUE = Map has expired
 *		FALSE  Map has not expired
 *
 */
bool_t
has_map_expired(map_ctrl *map)
{
	datum key;

	/* Set up datum with magic expiry key */
	key.dsize = strlen(MAP_EXPIRY_KEY);
	key.dptr = MAP_EXPIRY_KEY;

	/* Call has_entry_expired() with magic map expiry key */
	return (has_entry_expired(map, &key));
}

/*
 * FUNCTION:	update_entry_ttl()
 *
 * DESCRIPTION:	Updates the TTL for one map entry
 *
 * INPUTS:	Map control structure for an open map
 *		Entry key
 *		Flag indication if TTL should be max, min or random
 *
 * OUTPUTS:	SUCCESS = TTL updated
 *		FAILURE = TTL not updated
 *
 */

suc_code
update_entry_ttl(map_ctrl *map, datum *key, TTL_TYPE type)
{
	datum expire;
	struct timeval	now;
	int	ttl;

	/* Get current time */
	gettimeofday(&now, NULL);

	/* Get TTL from mapping file */
	ttl = get_ttl_value(map, type);

	if (FAILURE == add_to_timeval(&now, ttl))
		return (FAILURE);

	/* Convert time into a datum */
	expire.dsize = sizeof (struct timeval);
	expire.dptr = (char *)&now;

	/* Set expiry time entry for key */
	errno = 0;
	if (0 > dbm_store(map->ttl, *key, expire, DBM_REPLACE)) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR, "Could not write TTL entry "
						"(errno=%d)", errno);
		return (FAILURE);
	}

	return (SUCCESS);
}

/*
 * FUNCTION:	update_map_ttl()
 *
 * DESCRIPTION:	Updates the TTL for entire map. This can be called either with
 *		the map open (map_ctrl DBM pointer set up) or the map closed
 *		(map_ctrl DBM pointers not set). The latter case will occur
 *		when we have just created a new map.
 *
 *		This function must open the TTL map but, in either case, must
 *		return with the map_ctrl in it's original state.
 *
 * INPUTS:	Map control structure for an open map
 *
 * OUTPUTS:	SUCCESS = TTL updated
 *		FAILURE = TTL not updated
 *
 */
suc_code
update_map_ttl(map_ctrl *map)
{
	datum key;
	bool_t map_was_open = TRUE;
	suc_code ret;

	/* Set up datum with magic expiry key */
	key.dsize = strlen(MAP_EXPIRY_KEY);
	key.dptr = MAP_EXPIRY_KEY;

	/* If TTL not open open it */
	if (NULL == map->ttl) {
		map->ttl = dbm_open(map->ttl_path, O_RDWR, 0644);
		if (NULL == map->ttl)
			return (FAILURE);
		map_was_open = FALSE;
	}

	/* Call update_entry_ttl() with magic map expiry key */
	ret = update_entry_ttl(map, &key, TTL_MIN);

	/* If we had to open TTL file close it */
	if (!map_was_open) {
		dbm_close(map->ttl);
		map->ttl_path = NULL;
	}

	return (ret);
}

/*
 * FUNCTION:	add_to_timeval()
 *
 * DESCRIPTION:	Adds an int to a timeval
 *
 * NOTE :	Seems strange that there is not a library function to do this
 *		if one exists then this function can be removed.
 *
 * NOTE :	Does not handle UNIX clock wrap round but this is a much bigger
 *		problem.
 *
 * INPUTS:	Time value to add to
 *		Time value to add in seconds
 *
 * OUTPUTS:	SUCCESS = Addition successful
 *		FAILURE = Addition failed (probably wrapped)
 *
 */
suc_code
add_to_timeval(struct timeval *t1, int t2)
{
	struct timeval oldval;

	oldval.tv_sec = t1->tv_sec;

	/* Add seconds part */
	t1->tv_sec += t2;

	/* Check for clock wrap */
	if (!(t1->tv_sec >= oldval.tv_sec)) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"Wrap when adding %d to %d", t2, oldval.tv_sec);
		return (FAILURE);
	}

	return (SUCCESS);
}

/*
 * FUNCTION:	is_greater_timeval()
 *
 * DESCRIPTION:	Compares two timevals
 *
 * NOTE :	Seems strange that there is not a library function to do this
 *		if one exists then this function can be removed.
 *
 * INPUTS:	First time value
 *		Time value to compare it with
 *
 * OUTPUTS:	TRUE t1 > t2
 *		FALSE t1 <= t2
 *
 */
suc_code
is_greater_timeval(struct timeval *t1, struct timeval *t2)
{
	if (t1->tv_sec > t2->tv_sec)
		return (TRUE);

	if (t1->tv_sec == t2->tv_sec) {
		if (t1->tv_usec > t2->tv_usec)
			return (TRUE);
		else
			return (FALSE);
	}

	return (FALSE);
}
