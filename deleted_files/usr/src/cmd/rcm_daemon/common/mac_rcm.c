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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This RCM module adds support to the RCM framework for datalinks
 * managed by dladm(1M).
 */
#include <alloca.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <synch.h>
#include <libintl.h>
#include <errno.h>
#include <libdevinfo.h>
#include <sys/types.h>
#include <libdladm.h>
#include <liblaadm.h>
#include <net/if.h>
#include "rcm_module.h"

#define	_KERNEL
#include <sys/sysmacros.h>
#undef	_KERNEL

#define	CACHE_STALE	1	/* flags */
#define	CACHE_NEW	2	/* flags */

typedef enum mac_op {
	MAC_OP_SUSPEND	= 0,
	MAC_OP_OFFLINE	= 1,
	MAC_OP_ONLINE	= 2,
	MAC_OP_REMOVE	= 3,
	MAC_OP_RESUME	= 4
} mac_op_t;

char *mac_op_str[] = {
	"SUSPEND",
	"OFFLINE",
	"ONLINE",
	"REMOVE",
	"RESUME"
};

/* devfsadm post-attach nvpair values */
#define	PROP_NV_DDI_MAC		"ddi_mac"

typedef struct mac_cache {
	char		*resource;
	char		*driver;
	int		instance;
	int		flags;
	struct mac_cache *next;
	struct mac_cache *prev;
} mac_cache_t;

static mac_cache_t	cache_head;
static mac_cache_t	cache_tail;
static mutex_t		cache_lock;
static int		events_registered = 0;

struct devfs_minor_data {
	int32_t minor_type;
	char *minor_name;
	char *minor_node_type;
};

/* module interface routines */
static int mac_register(rcm_handle_t *);
static int mac_unregister(rcm_handle_t *);
static int mac_getinfo(rcm_handle_t *, char *, id_t, uint_t, char **,
    char **, nvlist_t *, rcm_info_t **);
static int mac_suspend(rcm_handle_t *, char *, id_t, timespec_t *,
    uint_t, char **, rcm_info_t **);
static int mac_resume(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int mac_offline(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int mac_online(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int mac_remove(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int mac_notify_event(rcm_handle_t *, char *, id_t, uint_t,
    char **, nvlist_t *, rcm_info_t **);

/* module private routines */
static void free_cache(void);
static void update_cache(rcm_handle_t *hd);
static int devfs_entry(di_node_t node, di_minor_t minor, void *arg);
static void cache_remove(mac_cache_t *node);
static mac_cache_t *cache_lookup(const char *resource);
static void free_node(mac_cache_t *);
static void cache_insert(mac_cache_t *);
static int process_nvlist(nvlist_t *);

/*
 * Module-Private data
 */
static struct rcm_mod_ops mac_ops = {
	RCM_MOD_OPS_VERSION,
	mac_register,
	mac_unregister,
	mac_getinfo,
	mac_suspend,
	mac_resume,
	mac_offline,
	mac_online,
	mac_remove,
	NULL,		/* request_capacity_change */
	NULL,		/* notify_capacity_change */
	mac_notify_event
};

/*
 * Module Interface Routines
 */

/*
 * rcm_mod_init()
 *
 *	Update registrations, and return the ops structure.
 */
struct rcm_mod_ops *
rcm_mod_init()
{
	cache_head.next = &cache_tail;
	cache_head.prev = NULL;
	cache_tail.prev = &cache_head;
	cache_tail.next = NULL;
	(void) mutex_init(&cache_lock, NULL, NULL);

	/* Return the ops vectors */
	return (&mac_ops);
}

/*
 * rcm_mod_info()
 *
 *	Return a string describing this module.
 */
const char *
rcm_mod_info()
{
	return ("Network namespace module %I%");
}

/*
 * rcm_mod_fini()
 *
 *	Destroy the cache.
 */
int
rcm_mod_fini()
{
	free_cache();
	(void) mutex_destroy(&cache_lock);
	return (RCM_SUCCESS);
}

/*
 * mac_register()
 *
 *	Make sure the cache is properly sync'ed, and its registrations
 *	are in order.
 *
 *	Locking: the cache is locked by update_cache, and is held
 *	throughout update_cache's execution because it reads and
 *	possibly modifies cache links continuously.
 */
static int
mac_register(rcm_handle_t *hd)
{
	if (!events_registered) {
		if (rcm_register_event(hd, RCM_RESOURCE_MAC_NEW, 0, NULL) !=
		    RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    gettext("MAC: failed to register for events %s\n"),
			    RCM_RESOURCE_MAC_NEW);
			return (RCM_FAILURE);
		} else {
			rcm_log_message(RCM_TRACE1, "MAC: registered "
			    " for events %s\n", RCM_RESOURCE_MAC_NEW);
			events_registered++;
		}
	}
	update_cache(hd);
	return (RCM_SUCCESS);
}

/*
 * mac_unregister()
 *
 *	Manually walk through the cache, unregistering all the networks.
 *
 *	Locking: the cache is locked throughout the execution of this routine
 *	because it reads and modifies cache links continuously.
 */
static int
mac_unregister(rcm_handle_t *hd)
{
	mac_cache_t *probe;

	/* Walk the cache, unregistering everything */
	(void) mutex_lock(&cache_lock);
	probe = cache_head.next;
	while (probe != &cache_tail) {
		(void) rcm_unregister_interest(hd, probe->resource, 0);
		cache_remove(probe);
		free_node(probe);
		probe = cache_head.next;
	}
	(void) mutex_unlock(&cache_lock);
	if (events_registered) {
		(void) rcm_unregister_event(hd, RCM_RESOURCE_MAC_NEW, 0);
		events_registered--;
	}
	return (RCM_SUCCESS);
}

typedef struct mac_dl_walker_state {
	char		*ws_dev_name;
	uint_t		ws_n_datalinks;
	char		**ws_datalink;
	char		**ws_paths;
} mac_dl_walker_state_t;

/*
 * Adds a datalink of the specified name to the list hanging off
 * the specified state. Invoked by mac_dl_walker_db() and mac_dl_walker().
 */
static void
mac_add_datalink(mac_dl_walker_state_t *state, const char *name)
{
	char dl_path[MAXPATHLEN];

	(void) snprintf(dl_path, sizeof (dl_path), "/devices/pseudo/dld@0:%s",
	    name);
	rcm_log_message(RCM_DEBUG, "MAC: found datalink \"%s\"\n", dl_path);

	state->ws_n_datalinks++;

	state->ws_datalink = realloc(state->ws_datalink,
	    (state->ws_n_datalinks + 1) * sizeof (char *));
	if (state->ws_datalink == NULL)
		return;
	state->ws_datalink[state->ws_n_datalinks-1] = strdup(name);
	state->ws_datalink[state->ws_n_datalinks] = NULL;

	state->ws_paths = realloc(state->ws_paths,
	    (state->ws_n_datalinks + 1) * sizeof (char *));
	if (state->ws_paths == NULL)
		return;
	state->ws_paths[state->ws_n_datalinks-1] = strdup(dl_path);
	state->ws_paths[state->ws_n_datalinks] = NULL;
}

/*
 * Invoked for each DDI_NT_NET node found by the dladm library.
 */
static
void
mac_dl_walker(void *arg, const char *name)
{
	dladm_attr_t	dl_attr;
	mac_dl_walker_state_t *state = (mac_dl_walker_state_t *)arg;

	rcm_log_message(RCM_DEBUG, "MAC: walker: DDI_NT_NET \"%s\"\n", name);

	if ((state->ws_datalink == NULL) || (state->ws_paths == NULL))
		return;

	if (dladm_info(name, &dl_attr) < 0) {
		rcm_log_message(RCM_DEBUG, "MAC: dladm_info failed "
		    "(legacy)\n");
		return;
	}

	/*
	 * We have a virtual data link that is defined on top
	 * of a MAC port. Ignore it unless the MAC port was
	 * registered by the device being acted upon.
	 */
	rcm_log_message(RCM_DEBUG, "MAC: rsrc \"%s\" matches link \"%s\"?\n",
	    state->ws_dev_name, dl_attr.da_dev);
	if (strcmp(state->ws_dev_name, dl_attr.da_dev) != 0) {
		rcm_log_message(RCM_DEBUG, "MAC: no match\n");
		return;
	}

	mac_add_datalink(state, name);
}

/*
 * Allocate and return a list of strings containing the virtual
 * data links that are currently configured on top of a device.
 */
static int
mac_list_datalinks(char *dev_name, char ***paths, char ***names)
{
	mac_dl_walker_state_t dl_state;

	/*
	 * Use the instance and driver from the cache node to find
	 * matching mac ports.
	 */
	dl_state.ws_dev_name = dev_name;
	dl_state.ws_n_datalinks = 0;

	dl_state.ws_datalink = calloc(1, sizeof (char *));
	dl_state.ws_paths = calloc(1, sizeof (char *));
	if ((dl_state.ws_datalink == NULL) || (dl_state.ws_paths == NULL)) {
		rcm_log_message(RCM_ERROR, gettext("MAC: malloc failure"));
		goto bail;
	}

	(void) dladm_walk(mac_dl_walker, &dl_state);

	if ((dl_state.ws_datalink == NULL) || (dl_state.ws_paths == NULL)) {
		rcm_log_message(RCM_ERROR, gettext("MAC: malloc failure"));
		goto bail;
	}

	if (paths != NULL)
		*paths = dl_state.ws_paths;
	if (names != NULL)
		*names = dl_state.ws_datalink;

	return (dl_state.ws_n_datalinks);

bail:
	free(dl_state.ws_datalink);
	free(dl_state.ws_paths);
	return (-1);
}

/*
 * Invoked for each virtual datalink defined in database.
 */
static void
mac_dl_walker_db(void *arg, const char *name, dladm_attr_t  *dl_attr)
{
	mac_dl_walker_state_t *state = arg;

	rcm_log_message(RCM_DEBUG, "MAC: DB walker: \"%s\"\n", name);

	if ((state->ws_datalink == NULL) || (state->ws_paths == NULL))
		return;

	/*
	 * We have a virtual data link that is defined on top
	 * of a MAC port. Ignore it unless the MAC port was
	 * registered by the device being acted upon.
	 */
	rcm_log_message(RCM_DEBUG, "MAC: DB rsrc \"%s\" matches link "
	    "\"%s\"?\n", state->ws_dev_name, dl_attr->da_dev);
	if (strcmp(state->ws_dev_name, dl_attr->da_dev) != 0) {
		rcm_log_message(RCM_DEBUG, "MAC: no match\n");
		return;
	}

	mac_add_datalink(state, name);
}

/*
 * Allocate and return a list of strings containing the virtual
 * data links that are configured on top of a device.
 */
static int
mac_list_datalinks_db(char *dev_name, char ***paths, char ***names)
{
	mac_dl_walker_state_t dl_state;

	/*
	 * Use the instance and driver from the cache node to find
	 * matching mac ports.
	 */
	dl_state.ws_dev_name = dev_name;
	dl_state.ws_n_datalinks = 0;

	dl_state.ws_datalink = calloc(1, sizeof (char *));
	dl_state.ws_paths = calloc(1, sizeof (char *));
	if ((dl_state.ws_datalink == NULL) || (dl_state.ws_paths == NULL)) {
		rcm_log_message(RCM_ERROR, gettext("MAC: malloc failure"));
		goto bail;
	}

	(void) dladm_db_walk(mac_dl_walker_db, &dl_state);

	if ((dl_state.ws_datalink == NULL) || (dl_state.ws_paths == NULL)) {
		rcm_log_message(RCM_ERROR, gettext("MAC: malloc failure"));
		goto bail;
	}

	if (paths != NULL)
		*paths = dl_state.ws_paths;
	if (names != NULL)
		*names = dl_state.ws_datalink;

	return (dl_state.ws_n_datalinks);

bail:
	free(dl_state.ws_datalink);
	free(dl_state.ws_paths);
	return (-1);
}

/*
 * Link aggregation walker state.
 */
typedef struct mac_aggr_walker_state {
	char		*as_dev_name;
	uint_t		as_n_aggr;
	uint32_t	*as_aggr;
} mac_aggr_walker_state_t;

/*
 * Link aggregation walker.
 */
static int
mac_list_aggr_walker(void *arg, laadm_grp_attr_sys_t *grp)
{
	mac_aggr_walker_state_t *state = (mac_aggr_walker_state_t *)arg;
	laadm_port_attr_sys_t *port;
	int i, j;

	rcm_log_message(RCM_TRACE1, "MAC: aggr sys walker: key %u\n",
	    grp->lg_key);

	if (state->as_aggr == NULL)
		return (0);

	/*
	 * Add an entry for each aggregated MAC port that was registered
	 * by the device being acted upon by RCM.
	 */
	for (i = 0; i < grp->lg_nports; i++) {
		port = &grp->lg_ports[i];

		rcm_log_message(RCM_TRACE1, "MAC: aggr (%d) port %s/%d\n",
		    grp->lg_key, port->lp_devname, port->lp_port);

		if (strcmp(port->lp_devname, state->as_dev_name) != 0)
			continue;

		/*
		 * Found matching port. Add aggregation key to list
		 * if it not already there, since multiple ports of
		 * the same device could be added to the same
		 * aggregation.
		 */
		for (j = 0; j < state->as_n_aggr; j++) {
			if (state->as_aggr[j] == grp->lg_key)
				break;
		}
		if (j < state->as_n_aggr)
			/* aggregation group already in list */
			continue;

		state->as_n_aggr++;
		state->as_aggr = realloc(state->as_aggr,
		    (state->as_n_aggr + 1) * sizeof (uint32_t));
		if (state->as_aggr == NULL)
			return (0);
		state->as_aggr[state->as_n_aggr-1] = grp->lg_key;
		state->as_aggr[state->as_n_aggr] = 0;
	}

	return (0);
}

/*
 * Allocate and return a list of key values of aggregations that
 * are currently configured on top of the MAC ports registered
 * by a device.
 */
static int
mac_list_aggr(char *dev_name, uint32_t **aggr)
{
	mac_aggr_walker_state_t ag_state;
	int rv;

	ag_state.as_dev_name = dev_name;
	ag_state.as_n_aggr = 0;

	ag_state.as_aggr = calloc(1, sizeof (uint32_t));
	if (ag_state.as_aggr == NULL) {
		rcm_log_message(RCM_ERROR, gettext("MAC: malloc failure"));
		return (-1);
	}

	rv = laadm_walk_sys(mac_list_aggr_walker, &ag_state);
	if (rv != 0) {
		rcm_log_message(RCM_ERROR,
		    gettext("MAC: cannot list aggregations "
		    "(%s)\n"), strerror(errno));
		free(ag_state.as_aggr);
		return (-1);
	}

	if (ag_state.as_aggr == NULL) {
		rcm_log_message(RCM_ERROR, gettext("MAC: malloc failure"));
		return (-1);
	}

	if (aggr != NULL)
		*aggr = ag_state.as_aggr;

	return (ag_state.as_n_aggr);
}

static void
mac_list_free(char **list)
{
	int i;

	if (list == NULL)
		return;

	for (i = 0; list[i] != NULL; i++)
		free(list[i]);

	free(list);
}

static int
mac_dl_down_list(char **list)
{
	int i;
	dladm_diag_t diag;

	if (list == NULL)
		return (RCM_SUCCESS);

	for (i = 0; list[i] != NULL; i++) {
		rcm_log_message(RCM_DEBUG, "MAC: dl_down() for \"%s\"\n",
		    list[i]);
		if (dladm_down(list[i], &diag) != 0) {
			char diag_str[256];

			if (diag != 0) {
				(void) snprintf(diag_str, sizeof (diag_str),
				    " (%s)", dladm_diag(diag));
			} else {
				diag_str[0] = '\0';
			}

			rcm_log_message(RCM_ERROR,
			    gettext("MAC: failed to bring "
			    "down link %s%s"), list[i], diag_str);
			goto error;
		}
	}

	return (RCM_SUCCESS);

error:
	/* bring data links back up */
	for (i--; i >= 0; i--) {
		dladm_diag_t diag;
		(void) dladm_up(list[i], &diag);
	}
	return (RCM_FAILURE);
}

static int
mac_dl_up_list(char **list)
{
	int i;
	dladm_diag_t diag;

	if (list == NULL)
		return (RCM_SUCCESS);

	for (i = 0; list[i] != NULL; i++) {
		rcm_log_message(RCM_DEBUG, "MAC: dl_up() for \"%s\"\n",
		    list[i]);
		if (dladm_up(list[i], &diag) != 0) {
			char diag_str[256];

			if (diag != 0) {
				(void) snprintf(diag_str, sizeof (diag_str),
				    " (%s)", dladm_diag(diag));
			} else {
				diag_str[0] = '\0';
			}

			rcm_log_message(RCM_ERROR,
			    gettext("MAC: failed to bring "
			    "up link %s%s\n"), list[i], diag_str);
			goto error;
		}
	}

	return (RCM_SUCCESS);

error:
	/* bring data links down */
	for (i--; i >= 0; i--) {
		dladm_diag_t diag;
		(void) dladm_down(list[i], &diag);
	}
	return (RCM_FAILURE);
}

/*
 * Since all we do is pass operations thru, we provide a general
 * routine for passing through operations.
 */
/*ARGSUSED*/
static int
mac_propagate(rcm_handle_t *hd, mac_op_t op, const char *rsrc, uint_t flag,
    char **reason, rcm_info_t **dependent_reason, void *arg)
{
	mac_cache_t	*node;
	int		rv = RCM_SUCCESS;
	int		ndep, naggr;
	char		**dl_paths = NULL;
	char		**dl_names = NULL;
	char		dev_name[MAXNAMELEN];
	uint32_t	*aggr = NULL;

	/*
	 * Lock the cache just long enough to extract information about this
	 * resource.
	 */
	(void) mutex_lock(&cache_lock);
	node = cache_lookup(rsrc);
	if (node == NULL) {
		rcm_log_message(RCM_WARNING,
		    gettext("MAC: unrecognized resource %s\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	(void) snprintf(dev_name, sizeof (dev_name), "%s%d", node->driver,
	    node->instance);
	rcm_log_message(RCM_DEBUG, "MAC: mac_propagate() %s for \"%s\" (%s)\n",
	    mac_op_str[op], rsrc, dev_name);

	/*
	 * We need to propagate the notification to the MAC clients
	 * that are configured on top of the MACs of the specified
	 * device. These MAC clients can be virtual links,
	 * or link aggregation groups.
	 */

	/*
	 * Remove notifications are unconditional in the RCM state model,
	 * so it's safe to remove the node from the cache at this point.
	 * And we need to remove it so that we will recognize it as a new
	 * resource following the reattachment of the resource.
	 */
	if (op == MAC_OP_REMOVE) {
		cache_remove(node);
		free_node(node);
	}
	(void) mutex_unlock(&cache_lock);

	/*
	 * Obtain the list of virtual datalinks configured on currently
	 * active on top of the MAC ports registered by the device.
	 */
	if ((op == MAC_OP_SUSPEND) || (op == MAC_OP_OFFLINE) ||
	    (op == MAC_OP_RESUME))
		ndep = mac_list_datalinks(dev_name, &dl_paths, &dl_names);
	else
		ndep = mac_list_datalinks_db(dev_name, &dl_paths, &dl_names);

	if (ndep == -1) {
		rv = RCM_FAILURE;
		goto done;
	} else if ((ndep == 0) && (op != MAC_OP_OFFLINE)) {
		goto done;
	}

	switch (op) {
	case MAC_OP_SUSPEND:
		rv = rcm_request_suspend_list(hd, dl_paths, flag,
		    (timespec_t *)arg, dependent_reason);
		break;

	case MAC_OP_OFFLINE:
		/* refuse operation if aggregation defined on a MAC port */
		naggr = mac_list_aggr(dev_name, &aggr);
		if (naggr == -1) {
			rv = RCM_FAILURE;
			break;
		} else if (naggr > 0) {
			/*
			 * Active link aggregation(s) defined on at least
			 * one of the MAC ports registered by the device
			 * being offlined.
			 */
			char *errstr;
			char errgrp[64];
			int i;

			errstr = strdup(gettext(
			    "Resource is in use by aggregation"));
			if (errstr == NULL) {
				rcm_log_message(RCM_ERROR,
				    gettext("MAC: malloc failure"));
				rv = RCM_FAILURE;
				goto done;
			}

			for (i = 0; i < naggr; i++) {
				(void) snprintf(errgrp, sizeof (errgrp), " %d",
				    aggr[i]);
				errstr = realloc(errstr, strlen(errstr) +
				    strlen(errgrp) + 1);
				if (errstr == NULL) {
					rcm_log_message(RCM_ERROR,
					    gettext("MAC: malloc failure"));
					rv = RCM_FAILURE;
					goto done;
				}
				(void) strcat(errstr, errgrp);
			}
			*reason = errstr;
			rcm_log_message(RCM_ERROR, "MAC: %s %s\n",
			    dev_name, *reason);
			errno = EBUSY;
			rv = RCM_FAILURE;
			break;
		}

		if (ndep == 0)
			break;

		/* propagate offline request */
		rv = rcm_request_offline_list(hd, dl_paths, flag,
		    dependent_reason);
		if (rv != RCM_SUCCESS)
			break;
		if (flag & RCM_QUERY)
			break;
		rv = mac_dl_down_list(dl_names);
		break;

	case MAC_OP_REMOVE:
		rv = rcm_notify_remove_list(hd, dl_paths, flag,
		    dependent_reason);
		break;

	case MAC_OP_ONLINE:
		rv = mac_dl_up_list(dl_names);
		if (rv != RCM_SUCCESS)
			break;
		rv = rcm_notify_online_list(hd, dl_paths, flag,
		    dependent_reason);
		break;

	case MAC_OP_RESUME:
		rv = rcm_notify_resume_list(hd, dl_paths, flag,
		    dependent_reason);
		break;

	default:
		rcm_log_message(RCM_WARNING,
		    gettext("MAC: bad RCM operation %d\n"), op);
		errno = EINVAL;
		return (RCM_FAILURE);
	}

done:
	if (rv != RCM_SUCCESS) {
		rcm_log_message(RCM_WARNING,
		    gettext("MAC: %s operation failed\n"),
		    mac_op_str[op]);
	}

	mac_list_free(dl_paths);
	mac_list_free(dl_names);
	free(aggr);

	return (rv);
}


/*
 * mac_offline()
 *
 *	Determine dependents of the resource being offlined, and offline
 *	them all.
 */
static int
mac_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **reason, rcm_info_t **dependent_reason)
{
	rcm_log_message(RCM_TRACE1, "MAC: offline(%s)\n", rsrc);

	return (mac_propagate(hd, MAC_OP_OFFLINE, rsrc, flags, reason,
	    dependent_reason, NULL));
}

/*
 * mac_online()
 *
 *	Remount the previously offlined filesystem, and online its dependents.
 */
static int
mac_online(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flag, char **reason,
    rcm_info_t **dependent_reason)
{
	rcm_log_message(RCM_DEBUG, "MAC: online(%s)\n", rsrc);

	return (mac_propagate(hd, MAC_OP_ONLINE, rsrc, flag, reason,
	    dependent_reason, NULL));
}

/*
 * mac_getinfo()
 *
 *	Gather usage information for this resource.
 *
 *	Locking: the cache is locked while this routine looks up the
 *	resource and extracts copies of any piece of information it needs.
 *	The cache is then unlocked, and this routine performs the rest of
 *	its functions without touching any part of the cache.
 */
/*ARGSUSED*/
static int
mac_getinfo(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flag,
    char **info, char **errstr, nvlist_t *proplist, rcm_info_t **depend_info)
{
	int		len;
	char		nic[LIFNAMSIZ];
	const char	*info_fmt;
	mac_cache_t	*node;
	char		**dl_paths;

	rcm_log_message(RCM_TRACE1, "MAC: getinfo(%s)\n", rsrc);

	info_fmt = "MAC %s";

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(rsrc);
	if (!node) {
		rcm_log_message(RCM_WARNING,
		    gettext("MAC: unrecognized resource %s\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	(void) snprintf(nic, sizeof (nic), "%s%d", node->driver,
	    node->instance);

	len = strlen(info_fmt) + strlen(nic) + 1;
	if ((*info = (char *)malloc(len)) == NULL) {
		rcm_log_message(RCM_ERROR, gettext("MAC: malloc failure"));
		return (RCM_FAILURE);
	}

	/* Fill in the string */
	(void) snprintf(*info, len, info_fmt, nic);

	if (flag & RCM_INCLUDE_DEPENDENT) {
		char dev_name[MAXNAMELEN];
		int ndep;

		rcm_log_message(RCM_DEBUG, "MAC: getting dependents\n");
		/* get list of configured datalinks */
		(void) snprintf(dev_name, sizeof (dev_name), "%s%d",
		    node->driver, node->instance);
		ndep = mac_list_datalinks(dev_name, &dl_paths, NULL);
		if (ndep != 0) {
			(void) rcm_get_info_list(hd, dl_paths, flag,
			    depend_info);
			mac_list_free(dl_paths);
		}
	}

	(void) mutex_unlock(&cache_lock);

	return (RCM_SUCCESS);
}

/*
 * mac_suspend()
 *
 *	Notify all dependents that the resource is being suspended.
 *	Since no real operation is involved, QUERY or not doesn't matter.
 *
 *	Locking: the cache is only used to retrieve some information about
 *	this resource, so it is only locked during that retrieval.
 */
static int
mac_suspend(rcm_handle_t *hd, char *rsrc, id_t id, timespec_t *interval,
    uint_t flag, char **reason, rcm_info_t **dependent_reason)
{
	rcm_log_message(RCM_TRACE1, "MAC: suspend(%s)\n", rsrc);

	return (mac_propagate(hd, MAC_OP_SUSPEND, rsrc, flag, reason,
	    dependent_reason, (void *)interval));
}

/*
 * mac_resume()
 *
 *	Resume all the dependents of a suspended network.
 *
 *	Locking: the cache is only used to retrieve some information about
 *	this resource, so it is only locked during that retrieval.
 */
static int
mac_resume(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flag, char **info,
    rcm_info_t **dependent_info)
{
	rcm_log_message(RCM_TRACE1, "MAC: resume(%s)\n", rsrc);

	return (mac_propagate(hd, MAC_OP_RESUME, rsrc, flag, info,
	    dependent_info, NULL));
}

/*
 * mac_remove()
 *
 *	This is another NO-OP for us, we propagate the information.  We
 *	don't need to remove it from our cache.  We don't unregister
 *	interest at this point either; the network device name is still
 *	around.  This way we don't have to change this logic when we
 *	gain the ability to learn about DR attach operations.
 */
static int
mac_remove(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flag, char **info,
    rcm_info_t **dependent_info)
{
	rcm_log_message(RCM_TRACE1, "MAC: remove(%s)\n", rsrc);

	return (mac_propagate(hd, MAC_OP_REMOVE, rsrc, flag, info,
	    dependent_info, NULL));
}

/*
 * Process post-attach notifications sent by devfs for devices
 * that created DDI_NT_MAC minor nodes. Bring up the links
 * that are configured on top of the corresponding MAC ports.
 */
/*ARGSUSED*/
static int
mac_notify_event(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flag,
    char **errstr, nvlist_t *nvl, rcm_info_t **result)
{
	rcm_log_message(RCM_DEBUG, "MAC: notify_event(%s)\n", rsrc);

	if (strcmp(rsrc, RCM_RESOURCE_MAC_NEW) != 0) {
		rcm_log_message(RCM_WARNING,
		    gettext("MAC: unrecognized event for %s\n"), rsrc);
		return (RCM_FAILURE);
	}

	/* update cache to reflect attached nodes */
	update_cache(hd);

	/* Process the nvlist for the event */
	if (process_nvlist(nvl) != 0) {
		rcm_log_message(RCM_WARNING,
		    gettext("MAC: Error processing resource attributes(%s)\n"),
		    rsrc);
		rcm_log_message(RCM_WARNING,
		    gettext("MAC: One or more devices may not be "
		    "configured.\n"));
	}

	return (RCM_SUCCESS);
}

/*
 * Cache management routines.  Note that the cache is implemented as a
 * trivial linked list, and is only required because RCM doesn't
 * provide enough state about our own registrations back to us.  This
 * linked list implementation probably clobbers the CPU cache pretty
 * well.
 */

/*
 * cache_lookup()
 *
 * Get a cache node for a resource.  Call with cache lock held.
 */
static mac_cache_t *
cache_lookup(const char *resource)
{
	mac_cache_t *probe;

	probe = cache_head.next;
	while (probe != &cache_tail) {
		if (probe->resource &&
		    (strcmp(resource, probe->resource) == 0)) {
			return (probe);
		}
		probe = probe->next;
	}
	return (NULL);
}

/*
 * free_node()
 *
 * Free a node.  Make sure it isn't in the list!
 */
static void
free_node(mac_cache_t *node)
{
	if (node != NULL) {
		free(node->resource);
		free(node->driver);
		free(node);
	}
}

/*
 * cache_insert()
 *
 * Call with the cache_lock held.
 */
static void
cache_insert(mac_cache_t *node)
{
	/* insert at the head for best performance */
	node->next = cache_head.next;
	node->prev = &cache_head;

	node->next->prev = node;
	cache_head.next = node;
}

/*
 * cache_remove()
 *
 * Call with the cache_lock held.
 */
static void
cache_remove(mac_cache_t *node)
{
	node->next->prev = node->prev;
	node->prev->next = node->next;
	node->next = NULL;
	node->prev = NULL;
}

/*
 * di_walk_minor() walker. Invoked for each DDI_NT_MAC device.
 */
/*ARGSUSED*/
static int
devfs_entry(di_node_t node, di_minor_t minor, void *arg)
{
	char		*devfspath;
	char		resource[MAXPATHLEN];
	char		*name;
	char		*cp;
	uint_t		port_num;
	int		instance;
	mac_cache_t	*probe;

	cp = di_minor_nodetype(minor);
	if ((cp == NULL) || (strcmp(cp, DDI_NT_MAC) != 0)) {
		/* doesn't look like a MAC device */
		return (DI_WALK_CONTINUE);
	}

	/*
	 * We need to register interest for devices that
	 * can be unconfigured, suspended, etc, and registered
	 * one or more MAC ports with the kernel.
	 *
	 * In our cache, we keep one entry per device that registered
	 * MAC ports. Each cache entry is also associated with a
	 * list of MAC ports that have been registered by the
	 * device associated with that cache entry.
	 */

	name = di_driver_name(node);
	if (name == NULL) {
		/* what else can we do? */
		return (DI_WALK_CONTINUE);
	}
	rcm_log_message(RCM_DEBUG, "MAC: node driver name: \"%s\"\n", name);

	instance = di_instance(node);
	rcm_log_message(RCM_DEBUG, "MAC: node instance: %d\n", instance);

	port_num = getminor(di_minor_devt(minor));
	rcm_log_message(RCM_DEBUG, "MAC: port number: %u\n", port_num);

	devfspath = di_devfs_path(node);
	if (devfspath == NULL) {
		/* no devfs path?!? */
		rcm_log_message(RCM_DEBUG, "MAC: missing devfs path\n");
		return (DI_WALK_CONTINUE);
	}

	if (strncmp("/pseudo", devfspath, strlen("/pseudo")) == 0) {
		/* ignore pseudo devices, they are not NICs */
		rcm_log_message(RCM_DEBUG, "MAC: ignoring pseudo device %s\n",
		    devfspath);
		di_devfs_path_free(devfspath);
		return (DI_WALK_CONTINUE);
	}

	(void) snprintf(resource, sizeof (resource), "/devices%s", devfspath);
	di_devfs_path_free(devfspath);

	probe = cache_lookup(resource);
	if (probe != NULL) {
		rcm_log_message(RCM_DEBUG, "MAC: %s already registered\n",
		    resource);
		probe->flags &= ~(CACHE_STALE);
	} else {
		rcm_log_message(RCM_DEBUG, "MAC: %s is new resource\n",
		    resource);
		probe = calloc(1, sizeof (mac_cache_t));
		if (probe == NULL) {
			rcm_log_message(RCM_ERROR,
			    gettext("MAC: malloc failure"));
			return (DI_WALK_CONTINUE);
		}

		probe->resource = strdup(resource);
		probe->instance = instance;
		probe->driver = strdup(name);

		if (probe->resource == NULL || probe->driver == NULL) {
			free_node(probe);
			return (DI_WALK_CONTINUE);
		}

		probe->flags |= CACHE_NEW;
		cache_insert(probe);
	}

	return (DI_WALK_CONTINUE);
}

static void
update_cache(rcm_handle_t *hd)
{
	mac_cache_t	*probe;
	di_node_t	root;
	int		rv;

	(void) mutex_lock(&cache_lock);

	/* first we walk the entire cache, marking each entry stale */
	probe = cache_head.next;
	while (probe != &cache_tail) {
		probe->flags |= CACHE_STALE;
		probe = probe->next;
	}

	root = di_init("/", DINFOSUBTREE | DINFOMINOR);
	if (root == DI_NODE_NIL) {
		goto done;
	}

	(void) di_walk_minor(root, DDI_NT_MAC, DI_CHECK_ALIAS, NULL,
	    devfs_entry);

	di_fini(root);

	probe = cache_head.next;
	while (probe != &cache_tail) {
		mac_cache_t *freeit;

		if (probe->flags & CACHE_STALE) {
			(void) rcm_unregister_interest(hd, probe->resource, 0);
			rcm_log_message(RCM_DEBUG, "MAC: unregistered %s\n",
			    probe->resource);
			freeit = probe;
			probe = probe->next;
			cache_remove(freeit);
			free_node(freeit);
			continue;
		}

		if (!(probe->flags & CACHE_NEW)) {
			probe = probe->next;
			continue;
		}

		rcm_log_message(RCM_DEBUG, "MAC: registering %s\n",
		    probe->resource);
		rv = rcm_register_interest(hd, probe->resource, 0, NULL);
		if (rv != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    gettext("MAC: failed to register %s\n"),
			    probe->resource);
		} else {
			rcm_log_message(RCM_DEBUG,
			    "MAC: registered %s\n", probe->resource);
			probe->flags &= ~(CACHE_NEW);
		}
		probe = probe->next;
	}

done:
	(void) mutex_unlock(&cache_lock);
}

static void
free_cache(void)
{
	mac_cache_t *probe;

	(void) mutex_lock(&cache_lock);
	probe = cache_head.next;
	while (probe != &cache_tail) {
		cache_remove(probe);
		free_node(probe);
		probe = cache_head.next;
	}
	(void) mutex_unlock(&cache_lock);
}

/*
 * Walker state and function used to bring up the virtual datalinks
 * that are configured on top of a MAC port for which we received
 * a post-attach notification.
 */

typedef struct dl_evt_walker_state {
	char	ws_dev_name[MAXNAMELEN];
	int	ws_port_num;
} dl_evt_walker_state_t;

static void
dl_evt_walker(void *arg, const char *name, dladm_attr_t  *dl_attr)
{
	dl_evt_walker_state_t *state = (dl_evt_walker_state_t *)arg;
	int rc;
	dladm_diag_t diag;

	rcm_log_message(RCM_DEBUG, "MAC: dl evt walker match %s/%d with "
	    "config %s/%d?\n", dl_attr->da_dev, dl_attr->da_port,
	    state->ws_dev_name, state->ws_port_num);

	if ((strcmp(state->ws_dev_name, dl_attr->da_dev) != 0) ||
	    (state->ws_port_num != dl_attr->da_port)) {
		/* no match */
		rcm_log_message(RCM_DEBUG, "MAC: no dl match, skip entry\n");
		return;
	}

	/* we have a match, bring up the datalink */
	rc = dladm_up(name, &diag);
	if (rc != 0) {
		char diag_str[256];

		if (diag != 0) {
			(void) snprintf(diag_str, sizeof (diag_str), " (%s)",
			    dladm_diag(diag));
		} else {
			diag_str[0] = '\0';
		}

		rcm_log_message(RCM_ERROR,
		    gettext("MAC: error (%s) configuring "
		    "virtual datalink %s%s\n"), strerror(rc), name, diag_str);
	}
}

/*
 * Process a notification received for a MAC minor node. Bring up
 * each link that is configured on top of the MAC port.
 */
static void
process_minor(char *devfs_path, char *name, int instance,
    struct devfs_minor_data *mdata)
{
	dl_evt_walker_state_t state;

	rcm_log_message(RCM_TRACE1, "MAC: process_minor\n");

	if ((mdata->minor_node_type != NULL) &&
	    strcmp(mdata->minor_node_type, PROP_NV_DDI_MAC) != 0) {
		/* Process MAC devices only */
		return;
	}

	rcm_log_message(RCM_TRACE1, "MAC: Examining %s (%s)\n",
	    devfs_path, mdata->minor_name);

	if (strncmp("/pseudo", devfs_path, strlen("/pseudo")) == 0) {
		rcm_log_message(RCM_TRACE1, "MAC: ignoring pseudo %s (%s)\n",
		    devfs_path, mdata->minor_name);
		return;
	}

	rcm_log_message(RCM_TRACE1, "MAC: process MAC minor "
	    "(dev=%s, name=%s, inst=%d, port=\"%s\")\n",
	    devfs_path, name, instance, mdata->minor_name);

	(void) snprintf(state.ws_dev_name, sizeof (state.ws_dev_name), "%s%d",
	    name, instance);
	state.ws_port_num = atoi(mdata->minor_name);
	(void) dladm_db_walk(dl_evt_walker, &state);
}

/*
 * Process a post-attached notification nvlist sent by devfs.
 */
static int
process_nvlist(nvlist_t *nvl)
{
	nvpair_t	*nvp = NULL;
	char *driver_name;
	char *devfs_path;
	int32_t instance;
	char *minor_byte_array;
	uint_t nminor;
	struct devfs_minor_data *mdata = NULL;
	nvlist_t *mnvl = NULL;
	nvpair_t *mnvp = NULL;

	rcm_log_message(RCM_TRACE1, "MAC: process_nvlist\n");

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		/* Get driver name */
		if (strcmp(nvpair_name(nvp), RCM_NV_DRIVER_NAME) == 0) {
			if (nvpair_value_string(nvp, &driver_name) != 0) {
				rcm_log_message(RCM_WARNING,
				    gettext("MAC: cannot get driver name\n"));
				return (-1);
			}
		}
		/* Get instance */
		if (strcmp(nvpair_name(nvp), RCM_NV_INSTANCE) == 0) {
			if (nvpair_value_int32(nvp, &instance) != 0) {
				rcm_log_message(RCM_WARNING, gettext(
				    "MAC: cannot get device instance\n"));
				return (-1);
			}
		}
		/* Get devfs_path */
		if (strcmp(nvpair_name(nvp), RCM_NV_DEVFS_PATH) == 0) {
			if (nvpair_value_string(nvp, &devfs_path) != 0) {
				rcm_log_message(RCM_WARNING,
				    gettext("MAC: cannot get device path\n"));
				return (-1);
			}
		}
		/* Get minor data */
		if (strcmp(nvpair_name(nvp), RCM_NV_MINOR_DATA) == 0) {
			if (nvpair_value_byte_array(nvp,
			    (uchar_t **)&minor_byte_array, &nminor) != 0) {
				rcm_log_message(RCM_WARNING, gettext(
				    "MAC: cannot get device minor data\n"));
				return (-1);
			}
			if (nvlist_unpack(minor_byte_array,
			    nminor, &mnvl, 0) != 0) {
				rcm_log_message(RCM_WARNING, gettext(
				    "MAC: cannot get minor node data\n"));
				return (-1);
			}
			mdata = (struct devfs_minor_data *)calloc(1,
			    sizeof (struct devfs_minor_data));
			if (mdata == NULL) {
				rcm_log_message(RCM_WARNING,
				    gettext("MAC: calloc error(%s)\n"),
				    strerror(errno));
				goto bail;
			}
			/* Enumerate minor node data */
			while ((mnvp = nvlist_next_nvpair(mnvl, mnvp)) !=
			    NULL) {
				/* Get minor type */
				if (strcmp(nvpair_name(mnvp),
				    RCM_NV_MINOR_TYPE) == 0) {
					if (nvpair_value_int32(mnvp,
					    &mdata->minor_type) != 0) {
						rcm_log_message(RCM_WARNING,
						    gettext("MAC: cannot get "
						    "minor type \n"));
						goto bail;
					}
				}
				/* Get minor name */
				if (strcmp(nvpair_name(mnvp),
				    RCM_NV_MINOR_NAME) == 0) {
					if (nvpair_value_string(mnvp,
					    &mdata->minor_name) != 0) {
						rcm_log_message(RCM_WARNING,
						    gettext("MAC: cannot get "
						    "minor name \n"));
						goto bail;
					}
				}
				/* Get minor node type */
				if (strcmp(nvpair_name(mnvp),
				    RCM_NV_MINOR_NODE_TYPE) == 0) {
					if (nvpair_value_string(mnvp,
					    &mdata->minor_node_type) != 0) {
						rcm_log_message(RCM_WARNING,
						    gettext("MAC: cannot get "
						    "minor node type \n"));
						goto bail;
					}
				}
			}
			process_minor(devfs_path, driver_name, instance,
			    mdata);
			nvlist_free(mnvl);
		}
	}

	rcm_log_message(RCM_TRACE1, "MAC: process_nvlist success\n");
	return (0);

bail:
	if (mnvl != NULL)
		nvlist_free(mnvl);
	if (mdata != NULL)
		free(mdata);
	return (-1);
}
