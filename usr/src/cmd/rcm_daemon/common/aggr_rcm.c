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
 */

/*
 * This RCM module adds support to the RCM framework for AGGR links
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <alloca.h>
#include <sys/types.h>
#include <sys/aggr.h>
#include <synch.h>
#include <assert.h>
#include <strings.h>
#include "rcm_module.h"
#include <libintl.h>
#include <libdllink.h>
#include <libdlaggr.h>

/*
 * Definitions
 */
#ifndef lint
#define	_(x)	gettext(x)
#else
#define	_(x)	x
#endif

/* Some generic well-knowns and defaults used in this module */
#define	RCM_LINK_PREFIX		"SUNW_datalink"	/* RCM datalink name prefix */
#define	RCM_LINK_RESOURCE_MAX	(13 + LINKID_STR_WIDTH)

/* AGGR link representation */
typedef struct dl_aggr {
	struct dl_aggr		*da_next;	/* next AGGR on the system */
	struct dl_aggr		*da_prev;	/* prev AGGR on the system */
	boolean_t		da_stale;	/* AGGR link is stale? */
	datalink_id_t		da_aggrid;
	datalink_id_t		da_lastport;
} dl_aggr_t;

/* AGGR Cache state flags */
typedef enum {
	CACHE_NODE_STALE		= 0x01,	/* stale cached data */
	CACHE_NODE_NEW			= 0x02,	/* new cached nodes */
	CACHE_NODE_OFFLINED		= 0x04,	/* node offlined */
	CACHE_AGGR_PORT_OFFLINED	= 0x08,	/* aggr port offlined */
	CACHE_AGGR_CONSUMER_OFFLINED	= 0x10	/* consumers offlined */
} cache_node_state_t;

/* Network Cache lookup options */
#define	CACHE_NO_REFRESH	0x1		/* cache refresh not needed */
#define	CACHE_REFRESH		0x2		/* refresh cache */

/*
 * Cache element. It is used to keep a list of links on the system and
 * their associated aggregations.
 */
typedef struct link_cache {
	struct link_cache	*vc_next;	/* next cached resource */
	struct link_cache	*vc_prev;	/* prev cached resource */
	char			*vc_resource;	/* resource name */
	datalink_id_t		vc_linkid;	/* linkid */
	dl_aggr_t		*vc_aggr;	/* AGGR on this link */
	cache_node_state_t	vc_state;	/* cache state flags */
} link_cache_t;

/*
 * Global cache for network AGGRs
 */
static link_cache_t	cache_head;
static link_cache_t	cache_tail;
static mutex_t		cache_lock;
static dl_aggr_t	aggr_head;
static dl_aggr_t	aggr_tail;
static mutex_t		aggr_list_lock;
static int		events_registered = 0;

static dladm_handle_t	dld_handle = NULL;

/*
 * RCM module interface prototypes
 */
static int		aggr_register(rcm_handle_t *);
static int		aggr_unregister(rcm_handle_t *);
static int		aggr_get_info(rcm_handle_t *, char *, id_t, uint_t,
			    char **, char **, nvlist_t *, rcm_info_t **);
static int		aggr_suspend(rcm_handle_t *, char *, id_t,
			    timespec_t *, uint_t, char **, rcm_info_t **);
static int		aggr_resume(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		aggr_offline(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		aggr_undo_offline(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		aggr_remove(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		aggr_notify_event(rcm_handle_t *, char *, id_t, uint_t,
			    char **, nvlist_t *, rcm_info_t **);
static int		aggr_configure_all(rcm_handle_t *, datalink_id_t,
			    boolean_t *);

/* Module private routines */
static int 		cache_update(rcm_handle_t *);
static void 		cache_remove(link_cache_t *);
static void 		cache_insert(link_cache_t *);
static void 		node_free(link_cache_t *);
static void 		aggr_list_remove(dl_aggr_t *);
static void 		aggr_list_insert(dl_aggr_t *);
static void 		aggr_list_free();
static link_cache_t	*cache_lookup(rcm_handle_t *, char *, char);
static int		aggr_consumer_offline(rcm_handle_t *, link_cache_t *,
			    char **, uint_t, rcm_info_t **);
static int		aggr_consumer_online(rcm_handle_t *, link_cache_t *,
			    char **, uint_t, rcm_info_t **);
static int		aggr_offline_port(link_cache_t *, cache_node_state_t);
static int		aggr_online_port(link_cache_t *, boolean_t *);
static char 		*aggr_usage(link_cache_t *);
static void 		aggr_log_err(datalink_id_t, char **, char *);
static int		aggr_consumer_notify(rcm_handle_t *, datalink_id_t,
			    char **, uint_t, rcm_info_t **);

/* Module-Private data */
static struct rcm_mod_ops aggr_ops =
{
	RCM_MOD_OPS_VERSION,
	aggr_register,
	aggr_unregister,
	aggr_get_info,
	aggr_suspend,
	aggr_resume,
	aggr_offline,
	aggr_undo_offline,
	aggr_remove,
	NULL,
	NULL,
	aggr_notify_event
};

/*
 * rcm_mod_init() - Update registrations, and return the ops structure.
 */
struct rcm_mod_ops *
rcm_mod_init(void)
{
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];

	rcm_log_message(RCM_TRACE1, "AGGR: mod_init\n");

	cache_head.vc_next = &cache_tail;
	cache_head.vc_prev = NULL;
	cache_tail.vc_prev = &cache_head;
	cache_tail.vc_next = NULL;
	(void) mutex_init(&cache_lock, 0, NULL);
	aggr_head.da_next = &aggr_tail;
	aggr_head.da_prev = NULL;
	aggr_tail.da_prev = &aggr_head;
	aggr_tail.da_next = NULL;
	(void) mutex_init(&aggr_list_lock, NULL, NULL);

	if ((status = dladm_open(&dld_handle)) != DLADM_STATUS_OK) {
		rcm_log_message(RCM_WARNING,
		    "AGGR: mod_init failed: cannot open datalink handle: %s\n",
		    dladm_status2str(status, errmsg));
		return (NULL);
	}

	/* Return the ops vectors */
	return (&aggr_ops);
}

/*
 * rcm_mod_info() - Return a string describing this module.
 */
const char *
rcm_mod_info(void)
{
	rcm_log_message(RCM_TRACE1, "AGGR: mod_info\n");

	return ("AGGR module version 1.1");
}

/*
 * rcm_mod_fini() - Destroy the network AGGR cache.
 */
int
rcm_mod_fini(void)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "AGGR: mod_fini\n");

	/*
	 * Note that aggr_unregister() does not seem to be called anywhere,
	 * therefore we free the cache nodes here. In theory we should call
	 * rcm_register_interest() for each node before we free it, the
	 * framework does not provide the rcm_handle to allow us to do so.
	 */
	(void) mutex_lock(&cache_lock);
	node = cache_head.vc_next;
	while (node != &cache_tail) {
		cache_remove(node);
		node_free(node);
		node = cache_head.vc_next;
	}
	(void) mutex_unlock(&cache_lock);
	(void) mutex_destroy(&cache_lock);

	aggr_list_free();
	(void) mutex_destroy(&aggr_list_lock);

	dladm_close(dld_handle);
	return (RCM_SUCCESS);
}

/*
 * aggr_list_insert - Insert an aggr in the global aggr list
 */
static void
aggr_list_insert(dl_aggr_t *aggr)
{
	assert(MUTEX_HELD(&aggr_list_lock));

	/* insert at the head for best performance */
	aggr->da_next = aggr_head.da_next;
	aggr->da_prev = &aggr_head;

	aggr->da_next->da_prev = aggr;
	aggr->da_prev->da_next = aggr;
}

/*
 * aggr_list_remove - Remove an aggr from the global aggr list
 */
static void
aggr_list_remove(dl_aggr_t *aggr)
{
	assert(MUTEX_HELD(&aggr_list_lock));
	aggr->da_next->da_prev = aggr->da_prev;
	aggr->da_prev->da_next = aggr->da_next;
	aggr->da_next = NULL;
	aggr->da_prev = NULL;
}

static void
aggr_list_free()
{
	dl_aggr_t *aggr;

	(void) mutex_lock(&aggr_list_lock);
	aggr = aggr_head.da_next;
	while (aggr != &aggr_tail) {
		aggr_list_remove(aggr);
		free(aggr);
		aggr = aggr_head.da_next;
	}
	(void) mutex_unlock(&aggr_list_lock);
}

/*
 * aggr_register() - Make sure the cache is properly sync'ed, and its
 *		 registrations are in order.
 */
static int
aggr_register(rcm_handle_t *hd)
{
	rcm_log_message(RCM_TRACE1, "AGGR: register\n");

	if (cache_update(hd) < 0)
		return (RCM_FAILURE);

	/*
	 * Need to register interest in all new resources
	 * getting attached, so we get attach event notifications
	 */
	if (!events_registered) {
		if (rcm_register_event(hd, RCM_RESOURCE_LINK_NEW, 0, NULL)
		    != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("AGGR: failed to register %s\n"),
			    RCM_RESOURCE_LINK_NEW);
			return (RCM_FAILURE);
		} else {
			rcm_log_message(RCM_DEBUG, "AGGR: registered %s\n",
			    RCM_RESOURCE_LINK_NEW);
			events_registered++;
		}
	}

	return (RCM_SUCCESS);
}

/*
 * aggr_unregister() - Walk the cache, unregistering all the networks.
 */
static int
aggr_unregister(rcm_handle_t *hd)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "AGGR: unregister\n");

	/* Walk the cache, unregistering everything */
	(void) mutex_lock(&cache_lock);
	node = cache_head.vc_next;
	while (node != &cache_tail) {
		if (rcm_unregister_interest(hd, node->vc_resource, 0)
		    != RCM_SUCCESS) {
			/* unregister failed for whatever reason */
			rcm_log_message(RCM_ERROR,
			    _("AGGR: failed to unregister %s\n"),
			    node->vc_resource);
			(void) mutex_unlock(&cache_lock);
			return (RCM_FAILURE);
		}
		cache_remove(node);
		node_free(node);
		node = cache_head.vc_next;
	}
	(void) mutex_unlock(&cache_lock);

	aggr_list_free();

	/*
	 * Unregister interest in all new resources
	 */
	if (events_registered) {
		if (rcm_unregister_event(hd, RCM_RESOURCE_LINK_NEW, 0)
		    != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("AGGR: failed to unregister %s\n"),
			    RCM_RESOURCE_LINK_NEW);
			return (RCM_FAILURE);
		} else {
			rcm_log_message(RCM_DEBUG, "AGGR: unregistered %s\n",
			    RCM_RESOURCE_LINK_NEW);
			events_registered--;
		}
	}

	return (RCM_SUCCESS);
}

/*
 * aggr_offline() - Offline AGGRs on a specific link.
 */
static int
aggr_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **depend_info)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "AGGR: offline(%s)\n", rsrc);

	/* Lock the cache and lookup the resource */
	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_REFRESH);
	if (node == NULL) {
		/* should not happen because the resource is registered. */
		aggr_log_err(DATALINK_INVALID_LINKID, errorp,
		    "offline, unrecognized resource");
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	/*
	 * If this given link is the only port in the aggregation, inform
	 * VLANs and IP interfaces on associated AGGRs to be offlined
	 */
	if (node->vc_aggr->da_lastport == node->vc_linkid) {
		if (aggr_consumer_offline(hd, node, errorp, flags,
		    depend_info) == RCM_SUCCESS) {
			rcm_log_message(RCM_DEBUG,
			    "AGGR: consumers agreed on offline\n");
		} else {
			aggr_log_err(node->vc_linkid, errorp,
			    "consumers offline failed");
			(void) mutex_unlock(&cache_lock);
			return (RCM_FAILURE);
		}
	}

	/* Check if it's a query */
	if (flags & RCM_QUERY) {
		rcm_log_message(RCM_TRACE1,
		    "AGGR: offline query succeeded(%s)\n", rsrc);
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	if (aggr_offline_port(node, CACHE_NODE_OFFLINED) != RCM_SUCCESS) {
		aggr_log_err(node->vc_linkid, errorp, "offline port failed");
		(void) mutex_unlock(&cache_lock);
		return (RCM_FAILURE);
	}

	rcm_log_message(RCM_TRACE1, "AGGR: Offline succeeded(%s)\n", rsrc);
	(void) mutex_unlock(&cache_lock);
	return (RCM_SUCCESS);
}

/*
 * aggr_undo_offline() - Undo offline of a previously offlined link.
 */
/*ARGSUSED*/
static int
aggr_undo_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **depend_info)
{
	link_cache_t *node;
	boolean_t up;

	rcm_log_message(RCM_TRACE1, "AGGR: online(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (node == NULL) {
		aggr_log_err(DATALINK_INVALID_LINKID, errorp,
		    "undo offline, unrecognized resource");
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	/* Check if no attempt should be made to online the link here */
	if (!(node->vc_state & CACHE_NODE_OFFLINED)) {
		aggr_log_err(node->vc_linkid, errorp, "resource not offlined");
		(void) mutex_unlock(&cache_lock);
		errno = ENOTSUP;
		return (RCM_SUCCESS);
	}

	if (aggr_online_port(node, &up) != RCM_SUCCESS) {
		aggr_log_err(node->vc_linkid, errorp, "online failed");
		(void) mutex_unlock(&cache_lock);
		return (RCM_FAILURE);
	}

	/*
	 * Inform VLANs and IP interfaces on associated AGGRs to be online
	 */
	if (!up)
		goto done;

	if (aggr_consumer_online(hd, node, errorp, flags, depend_info) ==
	    RCM_SUCCESS) {
		rcm_log_message(RCM_DEBUG, "AGGR: Consumers agree on online");
	} else {
		rcm_log_message(RCM_WARNING,
		    _("AGGR: Consumers online failed (%s)\n"), rsrc);
	}

done:
	node->vc_state &= ~CACHE_NODE_OFFLINED;
	rcm_log_message(RCM_TRACE1, "AGGR: online succeeded(%s)\n", rsrc);
	(void) mutex_unlock(&cache_lock);
	return (RCM_SUCCESS);
}

static int
aggr_offline_port(link_cache_t *node, cache_node_state_t state)
{
	dl_aggr_t *aggr;
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];
	dladm_aggr_port_attr_db_t port;

	rcm_log_message(RCM_TRACE2, "AGGR: aggr_offline_port %s\n",
	    node->vc_resource);

	aggr = node->vc_aggr;

	/*
	 * Try to remove the given port from the AGGR or delete the AGGR
	 */
	if (aggr->da_lastport == node->vc_linkid) {
		rcm_log_message(RCM_TRACE2, "AGGR: delete aggregation %u\n",
		    aggr->da_aggrid);
		status = dladm_aggr_delete(dld_handle, aggr->da_aggrid,
		    DLADM_OPT_ACTIVE);
	} else {
		rcm_log_message(RCM_TRACE2,
		    "AGGR: remove port (%s) from aggregation %u\n",
		    node->vc_resource, aggr->da_aggrid);
		port.lp_linkid = node->vc_linkid;
		status = dladm_aggr_remove(dld_handle, aggr->da_aggrid, 1,
		    &port, DLADM_OPT_ACTIVE);
	}
	if (status != DLADM_STATUS_OK) {
		rcm_log_message(RCM_WARNING,
		    _("AGGR: AGGR offline port failed (%u): %s\n"),
		    aggr->da_aggrid, dladm_status2str(status, errmsg));
		return (RCM_FAILURE);
	} else {
		rcm_log_message(RCM_TRACE1,
		    "AGGR: AGGR offline port succeeded (%u)\n",
		    aggr->da_aggrid);
		node->vc_state |= (CACHE_AGGR_PORT_OFFLINED | state);
		return (RCM_SUCCESS);
	}
}

static int
aggr_online_port(link_cache_t *node, boolean_t *up)
{
	dl_aggr_t *aggr;
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];
	dladm_aggr_port_attr_db_t port;

	rcm_log_message(RCM_TRACE2, "AGGR: aggr_online_port %s\n",
	    node->vc_resource);

	*up = B_FALSE;
	if (!(node->vc_state & CACHE_AGGR_PORT_OFFLINED))
		return (RCM_SUCCESS);

	/*
	 * Either add the port into the AGGR or recreate specific AGGR
	 * depending on whether this link is the only port in the aggregation.
	 */
	aggr = node->vc_aggr;
	if (aggr->da_lastport == node->vc_linkid) {
		rcm_log_message(RCM_TRACE2, "AGGR: delete aggregation %u\n",
		    aggr->da_aggrid);
		status = dladm_aggr_up(dld_handle, aggr->da_aggrid);
		*up = B_TRUE;
	} else {
		rcm_log_message(RCM_TRACE2,
		    "AGGR: add port (%s) to aggregation %u\n",
		    node->vc_resource, aggr->da_aggrid);
		port.lp_linkid = node->vc_linkid;
		status = dladm_aggr_add(dld_handle, aggr->da_aggrid, 1, &port,
		    DLADM_OPT_ACTIVE);
	}
	if (status != DLADM_STATUS_OK) {
		rcm_log_message(RCM_WARNING,
		    _("AGGR: AGGR online failed (%u): %s\n"),
		    aggr->da_aggrid, dladm_status2str(status, errmsg));
		*up = B_FALSE;
		return (RCM_FAILURE);
	}
	node->vc_state &= ~CACHE_AGGR_PORT_OFFLINED;
	return (RCM_SUCCESS);
}

/*
 * aggr_get_info() - Gather usage information for this resource.
 */
/*ARGSUSED*/
int
aggr_get_info(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **usagep, char **errorp, nvlist_t *props, rcm_info_t **depend_info)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "AGGR: get_info(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_REFRESH);
	if (node == NULL) {
		rcm_log_message(RCM_INFO,
		    _("AGGR: get_info(%s) unrecognized resource\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	/*
	 * *usagep will be freed by the caller.
	 */
	*usagep = aggr_usage(node);
	(void) mutex_unlock(&cache_lock);

	if (*usagep == NULL) {
		/* most likely malloc failure */
		rcm_log_message(RCM_ERROR,
		    _("AGGR: get_info(%s) malloc failure\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOMEM;
		return (RCM_FAILURE);
	}

	/* Set client/role properties */
	(void) nvlist_add_string(props, RCM_CLIENT_NAME, "AGGR");
	rcm_log_message(RCM_TRACE1, "AGGR: get_info(%s) info = %s\n",
	    rsrc, *usagep);
	return (RCM_SUCCESS);
}

/*
 * aggr_suspend() - Nothing to do, always okay
 */
/*ARGSUSED*/
static int
aggr_suspend(rcm_handle_t *hd, char *rsrc, id_t id, timespec_t *interval,
    uint_t flags, char **errorp, rcm_info_t **depend_info)
{
	rcm_log_message(RCM_TRACE1, "AGGR: suspend(%s)\n", rsrc);
	return (RCM_SUCCESS);
}

/*
 * aggr_resume() - Nothing to do, always okay
 */
/*ARGSUSED*/
static int
aggr_resume(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **depend_info)
{
	rcm_log_message(RCM_TRACE1, "AGGR: resume(%s)\n", rsrc);
	return (RCM_SUCCESS);
}

/*
 * aggr_remove() - remove a resource from cache
 */
/*ARGSUSED*/
static int
aggr_remove(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **depend_info)
{
	link_cache_t *node;
	char *exported;
	dl_aggr_t *aggr;
	int rv = RCM_SUCCESS;

	rcm_log_message(RCM_TRACE1, "AGGR: remove(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (node == NULL) {
		rcm_log_message(RCM_INFO,
		    _("AGGR: remove(%s) unrecognized resource\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	/* remove the cached entry for the resource */
	cache_remove(node);
	(void) mutex_unlock(&cache_lock);

	/*
	 * If this link is not the only port in the associated aggregation,
	 * the CACHE_AGGR_CONSUMER_OFFLINED flags won't be set.
	 */
	if (node->vc_state & CACHE_AGGR_CONSUMER_OFFLINED) {
		aggr = node->vc_aggr;
		exported = alloca(RCM_LINK_RESOURCE_MAX);
		(void) snprintf(exported, RCM_LINK_RESOURCE_MAX, "%s/%u",
		    RCM_LINK_PREFIX, aggr->da_aggrid);
		rv = rcm_notify_remove(hd, exported, flags, depend_info);
		if (rv != RCM_SUCCESS) {
			rcm_log_message(RCM_WARNING,
			    _("AGGR: failed to notify remove dependent %s\n"),
			    exported);
		}
	}

	node_free(node);
	return (rv);
}

/*
 * aggr_notify_event - Project private implementation to receive new resource
 *		   events. It intercepts all new resource events. If the
 *		   new resource is a network resource, pass up a notify
 *		   for it too. The new resource need not be cached, since
 *		   it is done at register again.
 */
/*ARGSUSED*/
static int
aggr_notify_event(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, nvlist_t *nvl, rcm_info_t **depend_info)
{
	nvpair_t	*nvp = NULL;
	datalink_id_t	linkid;
	uint64_t	id64;
	boolean_t	up;
	int		rv = RCM_SUCCESS;

	rcm_log_message(RCM_TRACE1, "AGGR: notify_event(%s)\n", rsrc);

	if (strcmp(rsrc, RCM_RESOURCE_LINK_NEW) != 0) {
		aggr_log_err(DATALINK_INVALID_LINKID, errorp,
		    "unrecognized event");
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	/* Update cache to reflect latest AGGRs */
	if (cache_update(hd) < 0) {
		aggr_log_err(DATALINK_INVALID_LINKID, errorp,
		    "private Cache update failed");
		return (RCM_FAILURE);
	}

	/* Process the nvlist for the event */
	rcm_log_message(RCM_TRACE1, "AGGR: process_nvlist\n");
	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {

		if (strcmp(nvpair_name(nvp), RCM_NV_LINKID) != 0)
			continue;

		if (nvpair_value_uint64(nvp, &id64) != 0) {
			aggr_log_err(DATALINK_INVALID_LINKID, errorp,
			    "cannot get linkid");
			return (RCM_FAILURE);
		}

		linkid = (datalink_id_t)id64;
		if (aggr_configure_all(hd, linkid, &up) != 0) {
			aggr_log_err(linkid, errorp,
			    "failed configuring AGGR links");
			rv = RCM_FAILURE;
		}

		/* Notify all VLAN and IP AGGR consumers */
		if (up && aggr_consumer_notify(hd, linkid, errorp, flags,
		    depend_info) != 0) {
			aggr_log_err(linkid, errorp, "consumer notify failed");
			rv = RCM_FAILURE;
		}
	}

	rcm_log_message(RCM_TRACE1,
	    "AGGR: notify_event: link configuration complete\n");
	return (rv);
}

/*
 * aggr_usage - Determine the usage of a link.
 *	    The returned buffer is owned by caller, and the caller
 *	    must free it up when done.
 */
static char *
aggr_usage(link_cache_t *node)
{
	char *buf;
	const char *fmt;
	char errmsg[DLADM_STRSIZE];
	char name[MAXLINKNAMELEN];
	dladm_status_t status;
	size_t bufsz;

	rcm_log_message(RCM_TRACE2, "AGGR: usage(%s)\n", node->vc_resource);
	assert(MUTEX_HELD(&cache_lock));

	if (node->vc_state & CACHE_NODE_OFFLINED)
		fmt = _("%s offlined");
	else
		fmt = _("%s is part of AGGR ");

	if ((status = dladm_datalink_id2info(dld_handle, node->vc_linkid, NULL,
	    NULL, NULL, name, sizeof (name))) != DLADM_STATUS_OK) {
		rcm_log_message(RCM_ERROR,
		    _("AGGR: usage(%s) get port name failure(%s)\n"),
		    node->vc_resource, dladm_status2str(status, errmsg));
		return (NULL);
	}

	/* space for resources and message */
	bufsz = MAXLINKNAMELEN + strlen(fmt) + strlen(name) + 1;
	if ((buf = malloc(bufsz)) == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("AGGR: usage(%s) malloc failure(%s)\n"),
		    node->vc_resource, strerror(errno));
		return (NULL);
	}
	(void) snprintf(buf, bufsz, fmt, name);

	if (node->vc_state & CACHE_NODE_OFFLINED) {
		/* Nothing else to do */
		rcm_log_message(RCM_TRACE2, "AGGR: usage (%s) info = %s\n",
		    node->vc_resource, buf);
		return (buf);
	}

	if ((status = dladm_datalink_id2info(dld_handle,
	    node->vc_aggr->da_aggrid, NULL, NULL, NULL, name,
	    sizeof (name))) != DLADM_STATUS_OK) {
		rcm_log_message(RCM_ERROR,
		    _("AGGR: usage(%s) get aggr %u name failure(%s)\n"),
		    node->vc_resource, node->vc_aggr->da_aggrid,
		    dladm_status2str(status, errmsg));
		(void) free(buf);
		return (NULL);
	}

	(void) strlcat(buf, name, bufsz);

	rcm_log_message(RCM_TRACE2, "AGGR: usage (%s) info = %s\n",
	    node->vc_resource, buf);
	return (buf);
}

/*
 * Cache management routines, all cache management functions should be
 * be called with cache_lock held.
 */

/*
 * cache_lookup() - Get a cache node for a resource.
 *		  Call with cache lock held.
 *
 * This ensures that the cache is consistent with the system state and
 * returns a pointer to the cache element corresponding to the resource.
 */
static link_cache_t *
cache_lookup(rcm_handle_t *hd, char *rsrc, char options)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE2, "AGGR: cache lookup(%s)\n", rsrc);
	assert(MUTEX_HELD(&cache_lock));

	if (options & CACHE_REFRESH) {
		/* drop lock since update locks cache again */
		(void) mutex_unlock(&cache_lock);
		(void) cache_update(hd);
		(void) mutex_lock(&cache_lock);
	}

	node = cache_head.vc_next;
	for (; node != &cache_tail; node = node->vc_next) {
		if (strcmp(rsrc, node->vc_resource) == 0) {
			rcm_log_message(RCM_TRACE2,
			    "AGGR: cache lookup succeeded(%s)\n", rsrc);
			return (node);
		}
	}
	return (NULL);
}

/*
 * node_free - Free a node from the cache
 */
static void
node_free(link_cache_t *node)
{
	free(node->vc_resource);
	free(node);
}

/*
 * cache_insert - Insert a resource node in cache
 */
static void
cache_insert(link_cache_t *node)
{
	assert(MUTEX_HELD(&cache_lock));

	/* insert at the head for best performance */
	node->vc_next = cache_head.vc_next;
	node->vc_prev = &cache_head;

	node->vc_next->vc_prev = node;
	node->vc_prev->vc_next = node;
}

/*
 * cache_remove() - Remove a resource node from cache.
 *		  Call with the cache_lock held.
 */
static void
cache_remove(link_cache_t *node)
{
	assert(MUTEX_HELD(&cache_lock));
	node->vc_next->vc_prev = node->vc_prev;
	node->vc_prev->vc_next = node->vc_next;
	node->vc_next = NULL;
	node->vc_prev = NULL;
}

static int
aggr_port_update(rcm_handle_t *hd, dl_aggr_t *aggr, datalink_id_t portid)
{
	link_cache_t *node;
	char *rsrc;
	int ret = -1;

	rcm_log_message(RCM_TRACE1,
	    "AGGR: aggr_port_update aggr:%u port:%u\n",
	    aggr->da_aggrid, portid);
	assert(MUTEX_HELD(&cache_lock));

	rsrc = malloc(RCM_LINK_RESOURCE_MAX);
	if (rsrc == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("AGGR: resource malloc error(%s)\n"), strerror(errno));
		goto done;
	}

	(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u",
	    RCM_LINK_PREFIX, portid);

	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (node != NULL) {
		rcm_log_message(RCM_DEBUG,
		    "AGGR: %s already registered (aggrid:%u)\n",
		    rsrc, aggr->da_aggrid);

		free(rsrc);
		node->vc_state &= ~CACHE_NODE_STALE;

		assert(node->vc_linkid == portid);
		/*
		 * Update vc_aggr directly as only one aggregation can be
		 * created on one port.
		 */
		node->vc_aggr = aggr;
	} else {
		rcm_log_message(RCM_DEBUG,
		    "AGGR: %s is a new resource (aggrid:%u)\n",
		    rsrc, aggr->da_aggrid);

		node = calloc(1, sizeof (link_cache_t));
		if (node == NULL) {
			free(rsrc);
			rcm_log_message(RCM_ERROR,
			    _("AGGR: calloc: %s\n"), strerror(errno));
			return (ret);
		}

		node->vc_resource = rsrc;
		node->vc_aggr = aggr;
		node->vc_linkid = portid;
		node->vc_state |= CACHE_NODE_NEW;


		cache_insert(node);
	}

	ret = 0;
done:
	return (ret);
}

typedef struct aggr_update_arg_s {
	rcm_handle_t	*hd;
	int		retval;
} aggr_update_arg_t;

/*
 * aggr_update() - Update physical interface properties
 */
static int
aggr_update(dladm_handle_t handle, datalink_id_t aggrid, void *arg)
{
	aggr_update_arg_t *aggr_update_argp = arg;
	rcm_handle_t *hd = aggr_update_argp->hd;
	dladm_aggr_grp_attr_t aggr_attr;
	dl_aggr_t *aggr;
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];
	boolean_t exist = B_FALSE;
	uint32_t i;
	int ret = -1;

	rcm_log_message(RCM_TRACE1, "AGGR: aggr_update(%u)\n", aggrid);

	assert(MUTEX_HELD(&aggr_list_lock));
	status = dladm_aggr_info(handle, aggrid, &aggr_attr,
	    DLADM_OPT_ACTIVE);
	if (status != DLADM_STATUS_OK) {
		rcm_log_message(RCM_TRACE1,
		    "AGGR: cannot get aggr information for %u error(%s)\n",
		    aggrid, dladm_status2str(status, errmsg));
		return (DLADM_WALK_CONTINUE);
	}

	/*
	 * Try to find the aggr from the aggr list.
	 */
	for (aggr = aggr_head.da_next; aggr != &aggr_tail; aggr = aggr->da_next)
		if (aggr->da_aggrid == aggr_attr.lg_linkid)
			break;

	if (aggr != NULL) {
		exist = B_TRUE;
	} else {
		if ((aggr = calloc(1, sizeof (dl_aggr_t))) == NULL) {
			rcm_log_message(RCM_ERROR, _("AGGR: malloc: %s\n"),
			    strerror(errno));
			goto done;
		}
	}

	/* Update aggregation information. */
	if (aggr_attr.lg_nports == 1)
		aggr->da_lastport = aggr_attr.lg_ports[0].lp_linkid;
	else
		aggr->da_lastport = DATALINK_INVALID_LINKID;
	aggr->da_aggrid = aggr_attr.lg_linkid;

	for (i = 0; i < aggr_attr.lg_nports; i++) {
		datalink_id_t portid = (aggr_attr.lg_ports[i]).lp_linkid;

		if (aggr_port_update(hd, aggr, portid) != 0)
			goto done;
	}

	if (!exist)
		aggr_list_insert(aggr);

	aggr->da_stale = B_FALSE;
	rcm_log_message(RCM_TRACE3,
	    "AGGR: aggr_update: succeeded(%u)\n", aggrid);

	ret = 0;
done:
	if (!exist && ret != 0)
		free(aggr);
	free(aggr_attr.lg_ports);
	aggr_update_argp->retval = ret;
	return (ret == 0 ? DLADM_WALK_CONTINUE : DLADM_WALK_TERMINATE);
}

/*
 * aggr_update_all() - Determine all AGGR links in the system
 */
static int
aggr_update_all(rcm_handle_t *hd)
{
	aggr_update_arg_t arg = {NULL, 0};

	rcm_log_message(RCM_TRACE2, "AGGR: aggr_update_all\n");
	assert(MUTEX_HELD(&cache_lock));

	arg.hd = hd;
	(void) dladm_walk_datalink_id(aggr_update, dld_handle, &arg,
	    DATALINK_CLASS_AGGR, DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
	return (arg.retval);
}

/*
 * cache_update() - Update cache with latest interface info
 */
static int
cache_update(rcm_handle_t *hd)
{
	link_cache_t *node, *next;
	dl_aggr_t *aggr;
	int ret = 0;

	rcm_log_message(RCM_TRACE2, "AGGR: cache_update\n");
	(void) mutex_lock(&aggr_list_lock);
	(void) mutex_lock(&cache_lock);

	/* first we walk the entire aggr list, marking each entry stale */
	for (aggr = aggr_head.da_next; aggr != &aggr_tail; aggr = aggr->da_next)
		aggr->da_stale = B_TRUE;

	/* then we walk the entire cache, marking each entry stale */
	node = cache_head.vc_next;
	for (; node != &cache_tail; node = node->vc_next)
		node->vc_state |= CACHE_NODE_STALE;

	ret = aggr_update_all(hd);

	/*
	 * Even aggr_update_all() fails, continue to delete all the stale
	 * resources. First, unregister links that are not offlined and
	 * still in cache.
	 */
	for (node = cache_head.vc_next; node != &cache_tail; node = next) {

		next = node->vc_next;
		if (node->vc_state & CACHE_NODE_STALE) {
			(void) rcm_unregister_interest(hd, node->vc_resource,
			    0);
			rcm_log_message(RCM_DEBUG,
			    "AGGR: unregistered %s\n", node->vc_resource);
			cache_remove(node);
			node_free(node);
			continue;
		}

		if (!(node->vc_state & CACHE_NODE_NEW))
			continue;

		if (rcm_register_interest(hd, node->vc_resource, 0,

		    NULL) != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("AGGR: failed to register %s\n"),
			    node->vc_resource);
			ret = -1;
		} else {
			rcm_log_message(RCM_DEBUG, "AGGR: registered %s\n",
			    node->vc_resource);

			node->vc_state &= ~CACHE_NODE_NEW;
		}
	}

	aggr = aggr_head.da_next;
	while (aggr != &aggr_tail) {
		dl_aggr_t *next = aggr->da_next;

		/* delete stale AGGRs */
		if (aggr->da_stale) {
			aggr_list_remove(aggr);
			free(aggr);
		}
		aggr = next;
	}

done:
	(void) mutex_unlock(&cache_lock);
	(void) mutex_unlock(&aggr_list_lock);
	return (ret);
}

/*
 * aggr_log_err() - RCM error log wrapper
 */
static void
aggr_log_err(datalink_id_t linkid, char **errorp, char *errmsg)
{
	char link[MAXLINKNAMELEN];
	char errstr[DLADM_STRSIZE];
	dladm_status_t status;
	int len;
	const char *errfmt;
	char *error;

	link[0] = '\0';
	if (linkid != DATALINK_INVALID_LINKID) {
		char rsrc[RCM_LINK_RESOURCE_MAX];

		(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u",
		    RCM_LINK_PREFIX, linkid);

		rcm_log_message(RCM_ERROR, _("AGGR: %s(%s)\n"), errmsg, rsrc);

		if ((status = dladm_datalink_id2info(dld_handle, linkid, NULL,
		    NULL, NULL, link, sizeof (link))) != DLADM_STATUS_OK) {
			rcm_log_message(RCM_WARNING,
			    _("AGGR: cannot get link name of (%s) %s\n"),
			    rsrc, dladm_status2str(status, errstr));
		}
	} else {
		rcm_log_message(RCM_ERROR, _("AGGR: %s\n"), errmsg);
	}

	errfmt = strlen(link) > 0 ? _("AGGR: %s(%s)") : _("AGGR: %s");
	len = strlen(errfmt) + strlen(errmsg) + MAXLINKNAMELEN + 1;
	if ((error = malloc(len)) != NULL) {
		if (strlen(link) > 0)
			(void) sprintf(error, errfmt, errmsg, link);
		else
			(void) sprintf(error, errfmt, errmsg);
	}

	if (errorp != NULL)
		*errorp = error;
}

/*
 * aggr_consumer_offline()
 *
 *	Offline AGGR consumers.
 */
static int
aggr_consumer_offline(rcm_handle_t *hd, link_cache_t *node, char **errorp,
    uint_t flags, rcm_info_t **depend_info)
{
	char rsrc[RCM_LINK_RESOURCE_MAX];
	int ret;

	rcm_log_message(RCM_TRACE2, "AGGR: aggr_consumer_offline %s\n",
	    node->vc_resource);

	(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u",
	    RCM_LINK_PREFIX, node->vc_aggr->da_aggrid);

	/*
	 * Inform associated VLANs and IP interfaces to be offlined
	 */
	ret = rcm_request_offline(hd, rsrc, flags, depend_info);
	if (ret != RCM_SUCCESS) {
		rcm_log_message(RCM_DEBUG,
		    "AGGR: rcm_request_offline failed (%s)\n", rsrc);
		return (ret);
	}

	node->vc_state |= CACHE_AGGR_CONSUMER_OFFLINED;
	rcm_log_message(RCM_TRACE2, "AGGR: aggr_consumer_offline done\n");
	return (ret);
}

/*
 * aggr_consumer_online()
 *
 *	online AGGR consumers.
 */
static int
aggr_consumer_online(rcm_handle_t *hd, link_cache_t *node, char **errorp,
    uint_t flags, rcm_info_t **depend_info)
{
	char rsrc[RCM_LINK_RESOURCE_MAX];
	int ret;

	rcm_log_message(RCM_TRACE2, "AGGR: aggr_consumer_online %s\n",
	    node->vc_resource);

	if (!(node->vc_state & CACHE_AGGR_CONSUMER_OFFLINED)) {
		rcm_log_message(RCM_DEBUG,
		    "AGGR: no consumers offlined (%s)\n", node->vc_resource);
		return (RCM_SUCCESS);
	}

	(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u",
	    RCM_LINK_PREFIX, node->vc_aggr->da_aggrid);

	ret = rcm_notify_online(hd, rsrc, flags, depend_info);
	if (ret != RCM_SUCCESS) {
		rcm_log_message(RCM_DEBUG,
		    "AGGR: rcm_notify_online failed (%s)\n", rsrc);
		return (ret);
	}

	node->vc_state &= ~CACHE_AGGR_CONSUMER_OFFLINED;
	rcm_log_message(RCM_TRACE2, "AGGR: aggr_consumer_online done\n");
	return (ret);
}

/*
 * Send RCM_RESOURCE_LINK_NEW events to other modules about new aggregations.
 * Return 0 on success, -1 on failure.
 */
static int
aggr_notify_new_aggr(rcm_handle_t *hd, char *rsrc)
{
	link_cache_t *node;
	dl_aggr_t *aggr;
	nvlist_t *nvl = NULL;
	uint64_t id;
	boolean_t is_only_port;
	int ret = -1;

	rcm_log_message(RCM_TRACE2, "AGGR: aggr_notify_new_aggr (%s)\n", rsrc);

	/* Check for the interface in the cache */
	(void) mutex_lock(&cache_lock);
	if ((node = cache_lookup(hd, rsrc, CACHE_REFRESH)) == NULL) {
		rcm_log_message(RCM_TRACE1,
		    "AGGR: aggr_notify_new_aggr() unrecognized resource (%s)\n",
		    rsrc);
		(void) mutex_unlock(&cache_lock);
		return (0);
	}

	if (nvlist_alloc(&nvl, 0, 0) != 0) {
		rcm_log_message(RCM_WARNING,
		    _("AGGR: failed to allocate nvlist\n"));
		(void) mutex_unlock(&cache_lock);
		goto done;
	}

	aggr = node->vc_aggr;
	is_only_port = (aggr->da_lastport == node->vc_linkid);

	if (is_only_port) {
		rcm_log_message(RCM_TRACE2,
		    "AGGR: aggr_notify_new_aggr add (%u)\n",
		    aggr->da_aggrid);

		id = aggr->da_aggrid;
		if (nvlist_add_uint64(nvl, RCM_NV_LINKID, id) != 0) {
			rcm_log_message(RCM_ERROR,
			    _("AGGR: failed to construct nvlist\n"));
			(void) mutex_unlock(&cache_lock);
			goto done;
		}
	}

	(void) mutex_unlock(&cache_lock);

	/*
	 * If this link is not the only port in the aggregation, the aggregation
	 * is not new. No need to inform other consumers in that case.
	 */
	if (is_only_port && rcm_notify_event(hd, RCM_RESOURCE_LINK_NEW,
	    0, nvl, NULL) != RCM_SUCCESS) {
		rcm_log_message(RCM_ERROR,
		    _("AGGR: failed to notify %s event for %s\n"),
		    RCM_RESOURCE_LINK_NEW, node->vc_resource);
		goto done;
	}

	ret = 0;
done:
	nvlist_free(nvl);
	return (ret);
}

/*
 * aggr_consumer_notify() - Notify consumers of AGGRs coming back online.
 */
static int
aggr_consumer_notify(rcm_handle_t *hd, datalink_id_t linkid, char **errorp,
    uint_t flags, rcm_info_t **depend_info)
{
	char rsrc[RCM_LINK_RESOURCE_MAX];
	link_cache_t *node;

	(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u",
	    RCM_LINK_PREFIX, linkid);

	rcm_log_message(RCM_TRACE1, "AGGR: aggr_consumer_notify(%s)\n", rsrc);

	/*
	 * Inform IP and VLAN consumers to be online.
	 */
	if (aggr_notify_new_aggr(hd, rsrc) != 0) {
		(void) mutex_lock(&cache_lock);
		if ((node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH)) != NULL)
			(void) aggr_offline_port(node, CACHE_NODE_STALE);
		(void) mutex_unlock(&cache_lock);
		rcm_log_message(RCM_TRACE1,
		    "AGGR: aggr_notify_new_aggr failed(%s)\n", rsrc);
		return (-1);
	}

	rcm_log_message(RCM_TRACE2, "AGGR: aggr_consumer_notify succeeded\n");
	return (0);
}

typedef struct aggr_configure_arg {
	datalink_id_t	portid;
	int		retval;
	boolean_t	up;
} aggr_configure_arg_t;

static int
aggr_configure(dladm_handle_t handle, datalink_id_t aggrid, void *arg)
{
	aggr_configure_arg_t *aggr_configure_argp = arg;
	datalink_id_t portid;
	dladm_aggr_grp_attr_t aggr_attr;
	dladm_aggr_port_attr_db_t port_attr;
	dladm_status_t status;
	uint32_t flags;
	char errmsg[DLADM_STRSIZE];
	int i;

	status = dladm_datalink_id2info(handle, aggrid, &flags, NULL, NULL,
	    NULL, 0);
	if (status != DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	status = dladm_aggr_info(handle, aggrid, &aggr_attr, DLADM_OPT_PERSIST);
	if (status != DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	portid = aggr_configure_argp->portid;
	for (i = 0; i < aggr_attr.lg_nports; i++)
		if (aggr_attr.lg_ports[i].lp_linkid == portid)
			break;

	if (i == aggr_attr.lg_nports) {
		/*
		 * The aggregation doesn't contain this port.
		 */
		free(aggr_attr.lg_ports);
		return (DLADM_WALK_CONTINUE);
	}

	/*
	 * If this aggregation already exists, add this port to this
	 * aggregation, otherwise, bring up this aggregation.
	 */
	if (flags & DLADM_OPT_ACTIVE) {
		rcm_log_message(RCM_TRACE3,
		    "AGGR: aggr_configure dladm_aggr_add port %u (%u)\n",
		    portid, aggrid);
		port_attr.lp_linkid = portid;
		status = dladm_aggr_add(handle, aggrid, 1, &port_attr,
		    DLADM_OPT_ACTIVE);
	} else {
		rcm_log_message(RCM_TRACE3,
		    "AGGR: aggr_configure dladm_aggr_up (%u)\n", aggrid);
		status = dladm_aggr_up(handle, aggrid);
	}

	if (status != DLADM_STATUS_OK) {
		/*
		 * Print a warning message and continue to UP other AGGRs.
		 */
		rcm_log_message(RCM_WARNING,
		    _("AGGR: AGGR online failed (%u): %s\n"),
		    aggrid, dladm_status2str(status, errmsg));
		aggr_configure_argp->retval = -1;
	} else if (!(flags & DLADM_OPT_ACTIVE)) {
		aggr_configure_argp->up = B_TRUE;
	}

	free(aggr_attr.lg_ports);
	return (DLADM_WALK_TERMINATE);
}

/*
 * aggr_configure_all() - Configure AGGRs over a physical link after it attaches
 */
static int
aggr_configure_all(rcm_handle_t *hd, datalink_id_t linkid, boolean_t *up)
{
	char rsrc[RCM_LINK_RESOURCE_MAX];
	link_cache_t *node;
	aggr_configure_arg_t arg = {DATALINK_INVALID_LINKID, 0, B_FALSE};

	*up = B_FALSE;

	/* Check for the AGGRs in the cache */
	(void) snprintf(rsrc, sizeof (rsrc), "%s/%u", RCM_LINK_PREFIX, linkid);

	rcm_log_message(RCM_TRACE1, "AGGR: aggr_configure_all(%s)\n", rsrc);

	/* Check if the link is new or was previously offlined */
	(void) mutex_lock(&cache_lock);
	if (((node = cache_lookup(hd, rsrc, CACHE_REFRESH)) != NULL) &&
	    (!(node->vc_state & CACHE_NODE_OFFLINED))) {
		rcm_log_message(RCM_TRACE1,
		    "AGGR: Skipping configured link(%s)\n", rsrc);
		(void) mutex_unlock(&cache_lock);
		return (0);
	}
	(void) mutex_unlock(&cache_lock);

	arg.portid = linkid;
	(void) dladm_walk_datalink_id(aggr_configure, dld_handle, &arg,
	    DATALINK_CLASS_AGGR, DATALINK_ANY_MEDIATYPE, DLADM_OPT_PERSIST);

	if (arg.retval == 0) {
		*up = arg.up;
		rcm_log_message(RCM_TRACE1,
		    "AGGR: aggr_configure_all succeeded(%s)\n", rsrc);
	}
	return (arg.retval);
}
