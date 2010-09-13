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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <assert.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <libdllink.h>
#include <libdlwlan.h>

#include "libnwam_impl.h"
#include <libnwam_priv.h>
#include <libnwam.h>

/*
 * Functions to support creating, modifying and destroying
 * known WLAN objects. These represent the WiFi connection history,
 * and are used by nwamd to identify and connect to known WLANs in
 * scan results.
 */

static nwam_error_t valid_keyname(nwam_value_t);
static nwam_error_t valid_keyslot(nwam_value_t);
static nwam_error_t valid_secmode(nwam_value_t);

struct nwam_prop_table_entry known_wlan_prop_table_entries[] = {
	{NWAM_KNOWN_WLAN_PROP_PRIORITY, NWAM_VALUE_TYPE_UINT64, B_FALSE,
	    1, 1, nwam_valid_uint64,
	    "specifies priority of known WLAN - lower values are prioritized",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_KNOWN_WLAN_PROP_BSSIDS, NWAM_VALUE_TYPE_STRING, B_FALSE,
	    0, NWAM_MAX_NUM_VALUES, nwam_valid_mac_addr,
	    "specifies BSSID(s) (of the form aa:bb:cc:dd:ee:ff) associated "
	    "with known WLAN",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_KNOWN_WLAN_PROP_KEYNAME, NWAM_VALUE_TYPE_STRING, B_FALSE,
	    0, 1, valid_keyname,
	    "specifies security key name used with known WLAN",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_KNOWN_WLAN_PROP_KEYSLOT, NWAM_VALUE_TYPE_UINT64, B_FALSE,
	    0, 1, valid_keyslot,
	    "specifies key slot [1-4] for security key used with known WLAN",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_KNOWN_WLAN_PROP_SECURITY_MODE, NWAM_VALUE_TYPE_UINT64, B_FALSE,
	    0, 1, valid_secmode,
	    "specifies security mode used for known WLAN",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY}
};

#define	NWAM_NUM_KNOWN_WLAN_PROPS	\
		(sizeof (known_wlan_prop_table_entries) / \
		sizeof (*known_wlan_prop_table_entries))

struct nwam_prop_table known_wlan_prop_table =
	{ NWAM_NUM_KNOWN_WLAN_PROPS, known_wlan_prop_table_entries };

nwam_error_t
nwam_known_wlan_read(const char *name, uint64_t flags,
    nwam_known_wlan_handle_t *kwhp)
{
	return (nwam_read(NWAM_OBJECT_TYPE_KNOWN_WLAN,
	    NWAM_KNOWN_WLAN_CONF_FILE, name, flags, kwhp));
}

nwam_error_t
nwam_known_wlan_create(const char *name, nwam_known_wlan_handle_t *kwhp)
{
	nwam_error_t err;
	nwam_value_t priorityval = NULL;

	assert(kwhp != NULL && name != NULL);

	if ((err = nwam_create(NWAM_OBJECT_TYPE_KNOWN_WLAN,
	    NWAM_KNOWN_WLAN_CONF_FILE, name, kwhp)) != NWAM_SUCCESS)
		return (err);

	/*
	 * Create new object list for known WLAN.  The initial priority is
	 * also set.
	 */
	if ((err = nwam_alloc_object_list(&((*kwhp)->nwh_data)))
	    != NWAM_SUCCESS)
		goto finish;
	if ((err = nwam_value_create_uint64(0, &priorityval)) != NWAM_SUCCESS)
		goto finish;
	err = nwam_set_prop_value((*kwhp)->nwh_data,
	    NWAM_KNOWN_WLAN_PROP_PRIORITY, priorityval);

finish:
	nwam_value_free(priorityval);
	if (err != NWAM_SUCCESS) {
		nwam_known_wlan_free(*kwhp);
		*kwhp = NULL;
	}
	return (err);
}

nwam_error_t
nwam_known_wlan_get_name(nwam_known_wlan_handle_t kwh, char **namep)
{
	return (nwam_get_name(kwh, namep));
}

nwam_error_t
nwam_known_wlan_set_name(nwam_known_wlan_handle_t kwh, const char *name)
{
	return (nwam_set_name(kwh, name));
}

boolean_t
nwam_known_wlan_can_set_name(nwam_known_wlan_handle_t kwh)
{
	return (!kwh->nwh_committed);
}

/*
 * Used to store wlan names/priorities for prioritized walk.
 */
struct nwam_wlan_info {
	char *wlan_name;
	uint64_t wlan_priority;
	boolean_t wlan_walked;
};

struct nwam_wlan_info_list {
	struct nwam_wlan_info **list;
	uint_t num_wlans;
};

/*
 * Used to read in each known WLAN name/priority.
 */
static int
get_wlans_cb(nwam_known_wlan_handle_t kwh, void *data)
{
	struct nwam_wlan_info_list *wil = data;
	struct nwam_wlan_info **list = wil->list;
	struct nwam_wlan_info **newlist = NULL;
	nwam_error_t err;
	nwam_value_t priorityval = NULL;
	uint_t num_wlans = wil->num_wlans;

	/* Reallocate WLAN list and allocate new info list element. */
	if ((newlist = realloc(list,
	    sizeof (struct nwam_wlan_info *) * ++num_wlans)) == NULL ||
	    (newlist[num_wlans - 1] = calloc(1,
	    sizeof (struct nwam_wlan_info))) == NULL) {
		if (newlist != NULL)
			free(newlist);
		return (NWAM_NO_MEMORY);
	}

	/* Update list since realloc() may have relocated it */
	wil->list = newlist;

	/* Retrieve name/priority */
	if ((err = nwam_known_wlan_get_name(kwh,
	    &((newlist[num_wlans - 1])->wlan_name))) != NWAM_SUCCESS ||
	    (err = nwam_known_wlan_get_prop_value(kwh,
	    NWAM_KNOWN_WLAN_PROP_PRIORITY, &priorityval)) != NWAM_SUCCESS ||
	    (err = nwam_value_get_uint64(priorityval,
	    &((newlist[num_wlans - 1])->wlan_priority))) != NWAM_SUCCESS) {
		free(newlist[num_wlans - 1]->wlan_name);
		nwam_value_free(priorityval);
		free(newlist[num_wlans - 1]);
		return (err);
	}
	nwam_value_free(priorityval);

	(newlist[num_wlans - 1])->wlan_walked = B_FALSE;

	wil->num_wlans = num_wlans;

	return (NWAM_SUCCESS);
}

/*
 * Some recursion is required here, since if _WALK_PRIORITY_ORDER is specified,
 * we need to first walk the list of known WLANs to retrieve names
 * and priorities, then utilize that list to carry out an in-order walk.
 */
nwam_error_t
nwam_walk_known_wlans(int(*cb)(nwam_known_wlan_handle_t, void *), void *data,
    uint64_t flags, int *retp)
{
	nwam_known_wlan_handle_t kwh;
	nwam_error_t err;
	int ret = 0;

	assert(cb != NULL);

	if ((err = nwam_valid_flags(flags,
	    NWAM_FLAG_KNOWN_WLAN_WALK_PRIORITY_ORDER | NWAM_FLAG_BLOCKING))
	    != NWAM_SUCCESS)
		return (err);

	if ((flags & NWAM_FLAG_KNOWN_WLAN_WALK_PRIORITY_ORDER) != 0) {
		struct nwam_wlan_info_list wil = { NULL, 0};
		uint64_t iflags = flags &~
		    NWAM_FLAG_KNOWN_WLAN_WALK_PRIORITY_ORDER;
		uint64_t minpriority;
		int errval, i, j, minindex;

		if (nwam_walk_known_wlans(get_wlans_cb, &wil, iflags, &errval)
		    != NWAM_SUCCESS) {
			err = (nwam_error_t)errval;
			goto done;
		}

		err = NWAM_SUCCESS;

		for (i = 0; i < wil.num_wlans; i++) {
			/* Find lowest priority value not walked so far. */
			minpriority = (uint64_t)-1;
			for (j = 0; j < wil.num_wlans; j++) {
				if (wil.list[j]->wlan_priority < minpriority &&
				    !(wil.list[j]->wlan_walked)) {
					minpriority =
					    wil.list[j]->wlan_priority;
					minindex = j;
				}
			}
			wil.list[minindex]->wlan_walked = B_TRUE;
			if ((err = nwam_known_wlan_read
			    (wil.list[minindex]->wlan_name,
			    iflags, &kwh)) != NWAM_SUCCESS) {
				goto done;
			}
			ret = cb(kwh, data);
			if (ret != 0) {
				nwam_known_wlan_free(kwh);
				err = NWAM_WALK_HALTED;
				goto done;
			}
			nwam_known_wlan_free(kwh);
		}
done:
		if (wil.list != NULL) {
			for (j = 0; j < wil.num_wlans; j++) {
				free(wil.list[j]->wlan_name);
				free(wil.list[j]);
			}
			free(wil.list);
		}
		if (retp != NULL)
			*retp = ret;
		return (err);
	}

	return (nwam_walk(NWAM_OBJECT_TYPE_KNOWN_WLAN,
	    NWAM_KNOWN_WLAN_CONF_FILE, cb, data, flags, retp, NULL));
}

void
nwam_known_wlan_free(nwam_known_wlan_handle_t kwh)
{
	nwam_free(kwh);
}

nwam_error_t
nwam_known_wlan_copy(nwam_known_wlan_handle_t oldkwh, const char *newname,
    nwam_known_wlan_handle_t *newkwhp)
{
	return (nwam_copy(NWAM_KNOWN_WLAN_CONF_FILE, oldkwh, newname, newkwhp));
}

nwam_error_t
nwam_known_wlan_delete_prop(nwam_known_wlan_handle_t kwh, const char *propname)
{
	nwam_error_t err;
	void *olddata;

	assert(kwh != NULL && propname != NULL);

	/*
	 * Duplicate data, remove property and validate. If validation
	 * fails, revert to data duplicated prior to remove.
	 */
	if ((err = nwam_dup_object_list(kwh->nwh_data, &olddata))
	    != NWAM_SUCCESS)
		return (err);
	if ((err = nwam_delete_prop(kwh->nwh_data, propname)) != NWAM_SUCCESS) {
		nwam_free_object_list(kwh->nwh_data);
		kwh->nwh_data = olddata;
		return (err);
	}
	if ((err = nwam_known_wlan_validate(kwh, NULL)) != NWAM_SUCCESS) {
		nwam_free_object_list(kwh->nwh_data);
		kwh->nwh_data = olddata;
		return (err);
	}
	nwam_free_object_list(olddata);

	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_known_wlan_set_prop_value(nwam_known_wlan_handle_t kwh,
    const char *propname, nwam_value_t value)
{
	nwam_error_t err;

	assert(kwh != NULL && propname != NULL && value != NULL);

	if ((err = nwam_known_wlan_validate_prop(kwh, propname, value))
	    != NWAM_SUCCESS)
		return (err);

	return (nwam_set_prop_value(kwh->nwh_data, propname, value));
}

nwam_error_t
nwam_known_wlan_get_prop_value(nwam_known_wlan_handle_t kwh,
    const char *propname, nwam_value_t *valuep)
{
	return (nwam_get_prop_value(kwh->nwh_data, propname, valuep));
}

nwam_error_t
nwam_known_wlan_walk_props(nwam_known_wlan_handle_t kwh,
    int (*cb)(const char *, nwam_value_t, void *),
    void *data, uint64_t flags, int *retp)
{
	return (nwam_walk_props(kwh, cb, data, flags, retp));
}

struct priority_collision_data {
	char *wlan_name;
	uint64_t priority;
};

static int
avoid_priority_collisions_cb(nwam_known_wlan_handle_t kwh, void *data)
{
	nwam_value_t priorityval;
	nwam_error_t err;
	struct priority_collision_data *pcd = data;
	char *name;
	uint64_t priority;

	err = nwam_known_wlan_get_name(kwh, &name);
	if (err != NWAM_SUCCESS)
		return (err);
	if (strcmp(name, pcd->wlan_name) == 0) {
		/* skip to-be-updated wlan */
		free(name);
		return (NWAM_SUCCESS);
	}
	free(name);

	err = nwam_known_wlan_get_prop_value(kwh, NWAM_KNOWN_WLAN_PROP_PRIORITY,
	    &priorityval);
	if (err != NWAM_SUCCESS)
		return (err);
	err = nwam_value_get_uint64(priorityval, &priority);
	if (err != NWAM_SUCCESS)
		return (err);
	nwam_value_free(priorityval);

	if (priority < pcd->priority)
		return (NWAM_SUCCESS);

	if (priority == pcd->priority) {
		/* Two priority values collide.  Move this one up. */
		err = nwam_value_create_uint64(priority + 1, &priorityval);
		if (err != NWAM_SUCCESS)
			return (err);
		err = nwam_known_wlan_set_prop_value(kwh,
		    NWAM_KNOWN_WLAN_PROP_PRIORITY, priorityval);
		nwam_value_free(priorityval);
		if (err != NWAM_SUCCESS) {
			return (err);
		}
		/*
		 * We are doing a walk, and will continue shifting until
		 * we find a gap in the priority numbers; thus no need to
		 * do collision checking here.
		 */
		err = nwam_known_wlan_commit(kwh,
		    NWAM_FLAG_KNOWN_WLAN_NO_COLLISION_CHECK);
		if (err != NWAM_SUCCESS)
			return (err);

		(pcd->priority)++;
		return (NWAM_SUCCESS);
	}

	/*
	 * Only possiblity left at this point is that we're looking
	 * at a priority greater than the last one we wrote, so we've
	 * found a gap.  We can halt the walk now.
	 */
	return (NWAM_WALK_HALTED);
}

nwam_error_t
nwam_known_wlan_commit(nwam_known_wlan_handle_t kwh, uint64_t flags)
{
	nwam_error_t err;
	nwam_value_t priorityval;
	int ret = 0;
	struct priority_collision_data pcd;

	assert(kwh != NULL && kwh->nwh_data != NULL);

	if ((err = nwam_known_wlan_validate(kwh, NULL)) != NWAM_SUCCESS)
		return (err);

	/*
	 * If the NO_COLLISION_CHECK flag is set, no need to check for
	 * collision.
	 */
	if (flags & NWAM_FLAG_KNOWN_WLAN_NO_COLLISION_CHECK)
		return (nwam_commit(NWAM_KNOWN_WLAN_CONF_FILE, kwh,
		    (flags & NWAM_FLAG_GLOBAL_MASK) |
		    NWAM_FLAG_ENTITY_KNOWN_WLAN));

	/*
	 * We need to do priority checking.  Walk the list, looking
	 * for the first entry with priority greater than or equal
	 * to the entry we're adding.  Commit the new one (without
	 * doing additional checking), and then increment other
	 * entries as needed.
	 */
	err = nwam_known_wlan_get_prop_value(kwh,
	    NWAM_KNOWN_WLAN_PROP_PRIORITY, &priorityval);
	if (err != NWAM_SUCCESS)
		return (err);
	err = nwam_value_get_uint64(priorityval, &(pcd.priority));
	nwam_value_free(priorityval);
	if (err != NWAM_SUCCESS)
		return (err);
	err = nwam_known_wlan_get_name(kwh, &(pcd.wlan_name));
	if (err != NWAM_SUCCESS)
		return (err);
	err = nwam_walk_known_wlans(avoid_priority_collisions_cb, &pcd,
	    NWAM_FLAG_KNOWN_WLAN_WALK_PRIORITY_ORDER, &ret);
	free(pcd.wlan_name);
	/*
	 * a halted walk is okay, it just means we didn't have
	 * to walk the entire list to resolve priorities
	 */
	if (ret != NWAM_SUCCESS && ret != NWAM_WALK_HALTED)
		return (ret);

	return (nwam_known_wlan_commit(kwh,
	    flags | NWAM_FLAG_KNOWN_WLAN_NO_COLLISION_CHECK));
}

nwam_error_t
nwam_known_wlan_destroy(nwam_known_wlan_handle_t kwh, uint64_t flags)
{
	return (nwam_destroy(NWAM_KNOWN_WLAN_CONF_FILE, kwh,
	    flags | NWAM_FLAG_ENTITY_KNOWN_WLAN));
}

nwam_error_t
nwam_known_wlan_get_prop_description(const char *propname,
    const char **descriptionp)
{
	return (nwam_get_prop_description(known_wlan_prop_table, propname,
	    descriptionp));
}

/* Property-specific value validation functions should go here. */

static nwam_error_t
valid_keyname(nwam_value_t value)
{
	char *keyname;

	if (nwam_value_get_string(value, &keyname) != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	if (!dladm_valid_secobj_name(keyname))
		return (NWAM_ENTITY_INVALID_VALUE);

	return (NWAM_SUCCESS);
}

static nwam_error_t
valid_keyslot(nwam_value_t value)
{
	uint64_t keyslot;

	if (nwam_value_get_uint64(value, &keyslot) != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	if (keyslot < 1 || keyslot > 4)
		return (NWAM_ENTITY_INVALID_VALUE);

	return (NWAM_SUCCESS);
}

static nwam_error_t
valid_secmode(nwam_value_t value)
{
	uint64_t secmode;

	if (nwam_value_get_uint64(value, &secmode) != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	if (secmode != DLADM_WLAN_SECMODE_NONE &&
	    secmode != DLADM_WLAN_SECMODE_WEP &&
	    secmode != DLADM_WLAN_SECMODE_WPA)
		return (NWAM_ENTITY_INVALID_VALUE);

	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_known_wlan_validate(nwam_known_wlan_handle_t kwh, const char **errpropp)
{
	return (nwam_validate(known_wlan_prop_table, kwh, errpropp));
}

nwam_error_t
nwam_known_wlan_validate_prop(nwam_known_wlan_handle_t kwh,
    const char *propname, nwam_value_t value)
{
	return (nwam_validate_prop(known_wlan_prop_table, kwh, propname,
	    value));
}

/*
 * Given a property, return expected property data type
 */
nwam_error_t
nwam_known_wlan_get_prop_type(const char *propname, nwam_value_type_t *typep)
{
	return (nwam_get_prop_type(known_wlan_prop_table, propname, typep));
}

nwam_error_t
nwam_known_wlan_prop_multivalued(const char *propname, boolean_t *multip)
{
	return (nwam_prop_multivalued(known_wlan_prop_table, propname, multip));
}

nwam_error_t
nwam_known_wlan_get_default_proplist(const char ***prop_list,
    uint_t *numvaluesp)
{
	return (nwam_get_default_proplist(known_wlan_prop_table,
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY, prop_list, numvaluesp));
}

/*
 * Add the given ESSID, BSSID, secmode, keyslot and key name to known WLANs.
 * BSSID and keyname can be NULL.
 */
nwam_error_t
nwam_known_wlan_add_to_known_wlans(const char *essid, const char *bssid,
    uint32_t secmode, uint_t keyslot, const char *keyname)
{
	nwam_known_wlan_handle_t kwh;
	nwam_value_t keynameval = NULL, keyslotval = NULL, bssidsval = NULL;
	nwam_value_t secmodeval = NULL, priorityval = NULL;
	char **old_bssids = NULL, **new_bssids;
	uint_t nelem = 0;
	nwam_error_t err;
	int i, j;

	/*
	 * Check if the given ESSID already exists as known WLAN.  If so,
	 * add the BSSID to the bssids property.  If not, create one with
	 * the given ESSID and add BSSID if given.
	 */
	err = nwam_known_wlan_read(essid, 0, &kwh);

	switch (err) {
	case NWAM_ENTITY_NOT_FOUND:
		if ((err = nwam_known_wlan_create(essid, &kwh)) != NWAM_SUCCESS)
			return (err);
		/* New known WLAN - set priority to 0 */
		if ((err = nwam_value_create_uint64(0, &priorityval))
		    != NWAM_SUCCESS) {
			nwam_known_wlan_free(kwh);
			return (err);
		}
		err = nwam_known_wlan_set_prop_value(kwh,
		    NWAM_KNOWN_WLAN_PROP_PRIORITY, priorityval);
		nwam_value_free(priorityval);
		if (err != NWAM_SUCCESS) {
			nwam_known_wlan_free(kwh);
			return (err);
		}
		/* If BSSID is NULL, nothing more to do here. */
		if (bssid == NULL)
			break;
		if ((err = nwam_value_create_string((char *)bssid, &bssidsval))
		    != NWAM_SUCCESS) {
			nwam_known_wlan_free(kwh);
			return (err);
		}
		/* Set the bssids property */
		err = nwam_known_wlan_set_prop_value(kwh,
		    NWAM_KNOWN_WLAN_PROP_BSSIDS, bssidsval);
		nwam_value_free(bssidsval);
		if (err != NWAM_SUCCESS) {
			nwam_known_wlan_free(kwh);
			return (err);
		}
		break;
	case NWAM_SUCCESS:
		/* If no bssid is specified, nothing to do */
		if (bssid == NULL)
			break;

		/* known WLAN exists, retrieve the existing bssids property */
		err = nwam_known_wlan_get_prop_value(kwh,
		    NWAM_KNOWN_WLAN_PROP_BSSIDS, &bssidsval);
		if (err != NWAM_SUCCESS && err != NWAM_ENTITY_NOT_FOUND) {
			nwam_known_wlan_free(kwh);
			return (err);
		}
		if (err == NWAM_SUCCESS) {
			if ((err = nwam_value_get_string_array(bssidsval,
			    &old_bssids, &nelem)) != NWAM_SUCCESS) {
				nwam_value_free(bssidsval);
				nwam_known_wlan_free(kwh);
				return (err);
			}
		}
		/* Create a new array to append given BSSID */
		new_bssids = calloc(nelem + 1, sizeof (char *));
		if (new_bssids == NULL) {
			nwam_value_free(bssidsval);
			nwam_known_wlan_free(kwh);
			return (NWAM_NO_MEMORY);
		}

		/*
		 * Copy over existing BSSIDs to the new array.  Also, check
		 * to make sure that the given BSSID doesn't already exist
		 * in the known WLAN.  If so, do abort copying and return
		 * NWAM_SUCCESS.
		 */
		for (i = 0; i < nelem; i++) {
			if (strcmp(old_bssids[i], bssid) == 0) {
				/* nothing to do, so free up everything */
				for (j = 0; j < i; j++)
					free(new_bssids[j]);
				free(new_bssids);
				nwam_value_free(bssidsval);
				goto set_key_info;
			}
			new_bssids[i] = strdup(old_bssids[i]);
		}
		new_bssids[nelem] = strdup(bssid);
		nwam_value_free(bssidsval);

		err = nwam_value_create_string_array(new_bssids, nelem + 1,
		    &bssidsval);
		for (i = 0; i < nelem + 1; i++)
			free(new_bssids[i]);
		free(new_bssids);
		if (err != NWAM_SUCCESS) {
			nwam_known_wlan_free(kwh);
			return (err);
		}
		/* Set the bssids property */
		err = nwam_known_wlan_set_prop_value(kwh,
		    NWAM_KNOWN_WLAN_PROP_BSSIDS, bssidsval);
		nwam_value_free(bssidsval);
		if (err != NWAM_SUCCESS) {
			nwam_known_wlan_free(kwh);
			return (err);
		}
		break;
	default:
		return (err);
	}

set_key_info:
	/* Set the security mode property */
	if ((err = nwam_value_create_uint64(secmode, &secmodeval))
	    != NWAM_SUCCESS) {
		nwam_known_wlan_free(kwh);
		return (err);
	}
	err = nwam_known_wlan_set_prop_value(kwh,
	    NWAM_KNOWN_WLAN_PROP_SECURITY_MODE, secmodeval);
	nwam_value_free(secmodeval);

	if (err != NWAM_SUCCESS) {
		nwam_known_wlan_free(kwh);
		return (err);
	}

	if (keyname != NULL) {
		if ((err = nwam_value_create_string((char *)keyname,
		    &keynameval)) != NWAM_SUCCESS) {
			nwam_known_wlan_free(kwh);
			return (err);
		}
		err = nwam_known_wlan_set_prop_value(kwh,
		    NWAM_KNOWN_WLAN_PROP_KEYNAME, keynameval);
		nwam_value_free(keynameval);
		if (err != NWAM_SUCCESS) {
			nwam_known_wlan_free(kwh);
			return (err);
		}
		if ((err = nwam_value_create_uint64(keyslot,
		    &keyslotval)) != NWAM_SUCCESS) {
			nwam_known_wlan_free(kwh);
			return (err);
		}
		err = nwam_known_wlan_set_prop_value(kwh,
		    NWAM_KNOWN_WLAN_PROP_KEYSLOT, keyslotval);
		nwam_value_free(keyslotval);
	}

	err = nwam_known_wlan_commit(kwh, 0);
	nwam_known_wlan_free(kwh);

	return (err);
}

/*
 * Remove the given BSSID/keyname from the bssids/keyname property for the
 * given ESSID.
 */
nwam_error_t
nwam_known_wlan_remove_from_known_wlans(const char *essid, const char *bssid,
    const char *keyname)
{
	nwam_known_wlan_handle_t kwh;
	nwam_value_t bssidsval;
	char **old_bssids, **new_bssids;
	uint_t nelem;
	nwam_error_t err;
	int i, found = -1;

	/* Retrieve the existing bssids */
	if ((err = nwam_known_wlan_read(essid, 0, &kwh)) != NWAM_SUCCESS)
		return (err);
	if ((err = nwam_known_wlan_get_prop_value(kwh,
	    NWAM_KNOWN_WLAN_PROP_BSSIDS, &bssidsval)) != NWAM_SUCCESS) {
		nwam_known_wlan_free(kwh);
		return (err);
	}
	if ((err = nwam_value_get_string_array(bssidsval, &old_bssids, &nelem))
	    != NWAM_SUCCESS) {
		nwam_value_free(bssidsval);
		nwam_known_wlan_free(kwh);
		return (err);
	}

	/* Cycle through the BSSIDs array to find the BSSID to remove */
	for (i = 0; i < nelem; i++) {
		if (strcmp(old_bssids[i], bssid)  == 0) {
			found = i;
			break;
		}
	}

	/* Given BSSID was not found in the array */
	if (found == -1) {
		nwam_value_free(bssidsval);
		nwam_known_wlan_free(kwh);
		return (NWAM_INVALID_ARG);
	}

	/* If removing the only BSSID entry, remove the bssids property */
	if (nelem == 1) {
		nwam_value_free(bssidsval);
		if ((err = nwam_known_wlan_delete_prop(kwh,
		    NWAM_KNOWN_WLAN_PROP_BSSIDS)) != NWAM_SUCCESS) {
			nwam_known_wlan_free(kwh);
			return (err);
		}
		err = nwam_known_wlan_commit(kwh, 0);
		nwam_known_wlan_free(kwh);
		return (err);
	}

	new_bssids = calloc(nelem - 1, sizeof (char *));
	if (new_bssids == NULL) {
		nwam_value_free(bssidsval);
		nwam_known_wlan_free(kwh);
		return (NWAM_NO_MEMORY);
	}

	/* Copy over other BSSIDs */
	for (i = 0; i < found; i++)
		new_bssids[i] = strdup(old_bssids[i]);
	for (i = found + 1; i < nelem; i++)
		new_bssids[i-1] = strdup(old_bssids[i]);
	nwam_value_free(bssidsval);

	err = nwam_value_create_string_array(new_bssids, nelem - 1, &bssidsval);
	for (i = 0; i < nelem - 1; i++)
		free(new_bssids[i]);
	free(new_bssids);
	if (err != NWAM_SUCCESS) {
		nwam_known_wlan_free(kwh);
		return (err);
	}

	/* Set the bssids property */
	err = nwam_known_wlan_set_prop_value(kwh, NWAM_KNOWN_WLAN_PROP_BSSIDS,
	    bssidsval);
	nwam_value_free(bssidsval);
	if (err != NWAM_SUCCESS) {
		nwam_known_wlan_free(kwh);
		return (err);
	}

	if (keyname != NULL) {
		if ((err = nwam_known_wlan_delete_prop(kwh,
		    NWAM_KNOWN_WLAN_PROP_KEYNAME)) != NWAM_SUCCESS) {
			nwam_known_wlan_free(kwh);
			return (err);
		}
		if ((err = nwam_known_wlan_delete_prop(kwh,
		    NWAM_KNOWN_WLAN_PROP_KEYSLOT)) != NWAM_SUCCESS) {
			nwam_known_wlan_free(kwh);
			return (err);
		}
	}

	err = nwam_known_wlan_commit(kwh, 0);
	nwam_known_wlan_free(kwh);

	return (err);
}
