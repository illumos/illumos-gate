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
 * This RCM module adds support to the RCM framework for Bridge links
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <synch.h>
#include <assert.h>
#include <strings.h>
#include "rcm_module.h"
#include <libintl.h>
#include <libdllink.h>
#include <libdlbridge.h>
#include <libdlpi.h>

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

/* Bridge Cache state flags */
typedef enum {
	CACHE_NODE_STALE	= 0x1,		/* stale cached data */
	CACHE_NODE_NEW		= 0x2,		/* new cached nodes */
	CACHE_NODE_OFFLINED	= 0x4		/* nodes offlined */
} cache_node_state_t;

/* Network Cache lookup options */
#define	CACHE_NO_REFRESH	0x1		/* cache refresh not needed */
#define	CACHE_REFRESH		0x2		/* refresh cache */

/* Cache element */
typedef struct link_cache {
	struct link_cache	*vc_next;	/* next cached resource */
	struct link_cache	*vc_prev;	/* prev cached resource */
	char			*vc_resource;	/* resource name */
	datalink_id_t		vc_linkid;	/* linkid */
	cache_node_state_t	vc_state;	/* cache state flags */
	char			vc_bridge[MAXLINKNAMELEN];
} link_cache_t;

/*
 * Global cache for network Bridges
 */
static link_cache_t	cache_head;
static link_cache_t	cache_tail;
static mutex_t		cache_lock;
static boolean_t	events_registered = B_FALSE;

static dladm_handle_t	dld_handle = NULL;

/*
 * RCM module interface prototypes
 */
static int		bridge_register(rcm_handle_t *);
static int		bridge_unregister(rcm_handle_t *);
static int		bridge_get_info(rcm_handle_t *, char *, id_t, uint_t,
			    char **, char **, nvlist_t *, rcm_info_t **);
static int		bridge_suspend(rcm_handle_t *, char *, id_t,
			    timespec_t *, uint_t, char **, rcm_info_t **);
static int		bridge_resume(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		bridge_offline(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		bridge_undo_offline(rcm_handle_t *, char *, id_t,
			    uint_t, char **, rcm_info_t **);
static int		bridge_remove(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		bridge_notify_event(rcm_handle_t *, char *, id_t,
			    uint_t, char **, nvlist_t *, rcm_info_t **);
static int		bridge_configure(rcm_handle_t *, datalink_id_t);

/* Module private routines */
static void 		cache_free(void);
static int 		cache_update(rcm_handle_t *);
static void 		cache_remove(link_cache_t *);
static void 		node_free(link_cache_t *);
static void 		cache_insert(link_cache_t *);
static link_cache_t	*cache_lookup(rcm_handle_t *, char *, uint_t);
static char 		*bridge_usage(link_cache_t *);
static void 		bridge_log_err(datalink_id_t, char **, char *);

/* Module-Private data */
static struct rcm_mod_ops bridge_ops =
{
	RCM_MOD_OPS_VERSION,
	bridge_register,
	bridge_unregister,
	bridge_get_info,
	bridge_suspend,
	bridge_resume,
	bridge_offline,
	bridge_undo_offline,
	bridge_remove,
	NULL,
	NULL,
	bridge_notify_event
};

/*
 * rcm_mod_init() - Update registrations, and return the ops structure.
 */
struct rcm_mod_ops *
rcm_mod_init(void)
{
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];

	rcm_log_message(RCM_TRACE1, "Bridge: mod_init\n");

	cache_head.vc_next = &cache_tail;
	cache_head.vc_prev = NULL;
	cache_tail.vc_prev = &cache_head;
	cache_tail.vc_next = NULL;
	(void) mutex_init(&cache_lock, 0, NULL);

	if ((status = dladm_open(&dld_handle)) != DLADM_STATUS_OK) {
		rcm_log_message(RCM_WARNING,
		    "Bridge: cannot open datalink handle: %s\n",
		    dladm_status2str(status, errmsg));
		return (NULL);
	}

	/* Return the ops vectors */
	return (&bridge_ops);
}

/*
 * rcm_mod_info() - Return a string describing this module.
 */
const char *
rcm_mod_info(void)
{
	rcm_log_message(RCM_TRACE1, "Bridge: mod_info\n");

	return ("Bridge module version 1.0");
}

/*
 * rcm_mod_fini() - Destroy the network Bridge cache.
 */
int
rcm_mod_fini(void)
{
	rcm_log_message(RCM_TRACE1, "Bridge: mod_fini\n");

	/*
	 * Note that bridge_unregister() does not seem to be called anywhere,
	 * therefore we free the cache nodes here. In theory we should call
	 * rcm_register_interest() for each node before we free it, but the
	 * framework does not provide the rcm_handle to allow us to do so.
	 */
	cache_free();
	(void) mutex_destroy(&cache_lock);

	dladm_close(dld_handle);
	return (RCM_SUCCESS);
}

/*
 * bridge_register() - Make sure the cache is properly sync'ed, and its
 *		       registrations are in order.
 */
static int
bridge_register(rcm_handle_t *hd)
{
	int retv;

	rcm_log_message(RCM_TRACE1, "Bridge: register\n");

	if ((retv = cache_update(hd)) != RCM_SUCCESS)
		return (retv);

	/*
	 * Need to register interest in all new resources
	 * getting attached, so we get attach event notifications
	 */
	if (!events_registered) {
		retv = rcm_register_event(hd, RCM_RESOURCE_LINK_NEW, 0, NULL);
		if (retv != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("Bridge: failed to register %s\n"),
			    RCM_RESOURCE_LINK_NEW);
		} else {
			rcm_log_message(RCM_DEBUG, "Bridge: registered %s\n",
			    RCM_RESOURCE_LINK_NEW);
			events_registered = B_TRUE;
		}
	}

	return (retv);
}

/*
 * bridge_unregister() - Walk the cache, unregistering all the links.
 */
static int
bridge_unregister(rcm_handle_t *hd)
{
	link_cache_t *node;
	int retv = RCM_SUCCESS;

	rcm_log_message(RCM_TRACE1, "Bridge: unregister\n");

	/* Walk the cache, unregistering everything */
	(void) mutex_lock(&cache_lock);
	node = cache_head.vc_next;
	while (node != &cache_tail) {
		retv = rcm_unregister_interest(hd, node->vc_resource, 0);
		if (retv != RCM_SUCCESS)
			break;
		cache_remove(node);
		node_free(node);
		node = cache_head.vc_next;
	}
	(void) mutex_unlock(&cache_lock);
	if (retv != RCM_SUCCESS) {
		rcm_log_message(RCM_ERROR,
		    _("Bridge: failed to unregister %s\n"), node->vc_resource);
		return (retv);
	}

	/*
	 * Unregister interest in all new resources
	 */
	if (events_registered) {
		retv = rcm_unregister_event(hd, RCM_RESOURCE_LINK_NEW, 0);
		if (retv != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("Bridge: failed to unregister %s\n"),
			    RCM_RESOURCE_LINK_NEW);
		} else {
			rcm_log_message(RCM_DEBUG, "Bridge: unregistered %s\n",
			    RCM_RESOURCE_LINK_NEW);
			events_registered = B_FALSE;
		}
	}

	return (retv);
}

/*
 * bridge_offline() - Offline the bridge on a specific link.
 */
static int
bridge_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	link_cache_t *node;
	dladm_status_t status;

	rcm_log_message(RCM_TRACE1, "Bridge: offline(%s)\n", rsrc);

	/* Lock the cache and lookup the resource */
	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_REFRESH);
	if (node == NULL) {
		/* should not happen because the resource is registered. */
		bridge_log_err(DATALINK_INVALID_LINKID, errorp,
		    "unrecognized resource");
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	/* Check if it's a query */
	if (flags & RCM_QUERY) {
		rcm_log_message(RCM_TRACE1,
		    "Bridge: offline query succeeded(%s)\n", rsrc);
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	status = dladm_bridge_setlink(dld_handle, node->vc_linkid, "");
	if (status != DLADM_STATUS_OK) {
		bridge_log_err(node->vc_linkid, errorp, "offline failed");
		(void) mutex_unlock(&cache_lock);
		return (RCM_FAILURE);
	}

	node->vc_state |= CACHE_NODE_OFFLINED;

	rcm_log_message(RCM_TRACE1, "Bridge: Offline succeeded(%s %s)\n", rsrc,
	    node->vc_bridge);
	(void) mutex_unlock(&cache_lock);
	return (RCM_SUCCESS);
}

/*
 * bridge_undo_offline() - Undo offline of a previously offlined node.
 */
/*ARGSUSED*/
static int
bridge_undo_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	link_cache_t *node;
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];

	rcm_log_message(RCM_TRACE1, "Bridge: online(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (node == NULL) {
		bridge_log_err(DATALINK_INVALID_LINKID, errorp, "no such link");
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	/* Check if no attempt should be made to online the link here */
	if (!(node->vc_state & CACHE_NODE_OFFLINED)) {
		bridge_log_err(node->vc_linkid, errorp, "link not offlined");
		(void) mutex_unlock(&cache_lock);
		errno = ENOTSUP;
		return (RCM_SUCCESS);
	}

	/*
	 * Try to bring on an offlined bridge link.
	 */
	status = dladm_bridge_setlink(dld_handle, node->vc_linkid,
	    node->vc_bridge);
	if (status != DLADM_STATUS_OK) {
		/*
		 * Print a warning message.
		 */
		rcm_log_message(RCM_WARNING,
		    _("Bridge: Bridge online failed %u %s: %s\n"),
		    node->vc_linkid, node->vc_bridge,
		    dladm_status2str(status, errmsg));
	}

	node->vc_state &= ~CACHE_NODE_OFFLINED;
	rcm_log_message(RCM_TRACE1, "Bridge: online succeeded(%s)\n", rsrc);
	(void) mutex_unlock(&cache_lock);
	return (RCM_SUCCESS);
}

/*
 * bridge_get_info() - Gather usage information for this resource.
 */
/*ARGSUSED*/
int
bridge_get_info(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **usagep, char **errorp, nvlist_t *props, rcm_info_t **info)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "Bridge: get_info(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_REFRESH);
	if (node == NULL) {
		rcm_log_message(RCM_INFO,
		    _("Bridge: get_info(%s) unrecognized resource\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	*usagep = bridge_usage(node);
	(void) mutex_unlock(&cache_lock);
	if (*usagep == NULL) {
		/* most likely malloc failure */
		rcm_log_message(RCM_ERROR,
		    _("Bridge: get_info(%s) malloc failure\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOMEM;
		return (RCM_FAILURE);
	}

	/* Set client/role properties */
	(void) nvlist_add_string(props, RCM_CLIENT_NAME, "Bridge");

	rcm_log_message(RCM_TRACE1, "Bridge: get_info(%s) info = %s\n",
	    rsrc, *usagep);
	return (RCM_SUCCESS);
}

/*
 * bridge_suspend() - Nothing to do, always okay
 */
/*ARGSUSED*/
static int
bridge_suspend(rcm_handle_t *hd, char *rsrc, id_t id, timespec_t *interval,
    uint_t flags, char **errorp, rcm_info_t **info)
{
	rcm_log_message(RCM_TRACE1, "Bridge: suspend(%s)\n", rsrc);
	return (RCM_SUCCESS);
}

/*
 * bridge_resume() - Nothing to do, always okay
 */
/*ARGSUSED*/
static int
bridge_resume(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	rcm_log_message(RCM_TRACE1, "Bridge: resume(%s)\n", rsrc);
	return (RCM_SUCCESS);
}

/*
 * bridge_remove() - remove a resource from cache
 */
/*ARGSUSED*/
static int
bridge_remove(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "Bridge: remove(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (node == NULL) {
		rcm_log_message(RCM_INFO,
		    _("Bridge: remove(%s) unrecognized resource\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	/* remove the cached entry for the resource */
	rcm_log_message(RCM_TRACE2,
	    "Bridge: remove succeeded(%s, %s)\n", rsrc, node->vc_bridge);
	cache_remove(node);
	(void) mutex_unlock(&cache_lock);

	node_free(node);
	return (RCM_SUCCESS);
}

/*
 * bridge_notify_event - Project private implementation to receive new resource
 *		   events. It intercepts all new resource events. If the
 *		   new resource is a network resource, pass up a notify
 *		   for it too. The new resource need not be cached, since
 *		   it is done at register again.
 */
/*ARGSUSED*/
static int
bridge_notify_event(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, nvlist_t *nvl, rcm_info_t **info)
{
	nvpair_t	*nvp = NULL;
	datalink_id_t	linkid;
	uint64_t	id64;
	int		rv, lastrv;

	rcm_log_message(RCM_TRACE1, "Bridge: notify_event(%s)\n", rsrc);

	if (strcmp(rsrc, RCM_RESOURCE_LINK_NEW) != 0) {
		bridge_log_err(DATALINK_INVALID_LINKID, errorp,
		    "unrecognized event");
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	/* Update cache to reflect latest Bridges */
	if ((lastrv = cache_update(hd)) != RCM_SUCCESS) {
		bridge_log_err(DATALINK_INVALID_LINKID, errorp,
		    "private Cache update failed");
		return (lastrv);
	}

	/*
	 * Try best to recover all configuration.
	 */
	rcm_log_message(RCM_DEBUG, "Bridge: process_nvlist\n");
	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		if (strcmp(nvpair_name(nvp), RCM_NV_LINKID) != 0)
			continue;

		if (nvpair_value_uint64(nvp, &id64) != 0) {
			bridge_log_err(DATALINK_INVALID_LINKID, errorp,
			    "cannot get linkid");
			lastrv = RCM_FAILURE;
			continue;
		}

		linkid = (datalink_id_t)id64;
		if ((rv = bridge_configure(hd, linkid)) != RCM_SUCCESS) {
			bridge_log_err(linkid, errorp, "configuring failed");
			lastrv = rv;
		}
	}

	rcm_log_message(RCM_TRACE1,
	    "Bridge: notify_event: link configuration complete\n");
	return (lastrv);
}

/*
 * bridge_usage - Determine the usage of a link.
 *	    The returned buffer is owned by caller, and the caller
 *	    must free it up when done.
 */
static char *
bridge_usage(link_cache_t *node)
{
	char *buf;
	const char *fmt;
	char errmsg[DLADM_STRSIZE];
	char name[MAXLINKNAMELEN];
	char bridge[MAXLINKNAMELEN];
	dladm_status_t status;

	rcm_log_message(RCM_TRACE2, "Bridge: usage(%s)\n", node->vc_resource);

	assert(MUTEX_HELD(&cache_lock));

	status = dladm_datalink_id2info(dld_handle, node->vc_linkid, NULL,
	    NULL, NULL, name, sizeof (name));

	if (status != DLADM_STATUS_OK) {
		rcm_log_message(RCM_ERROR,
		    _("Bridge: usage(%s) get link name failure(%s)\n"),
		    node->vc_resource, dladm_status2str(status, errmsg));
		return (NULL);
	}

	(void) dladm_bridge_getlink(dld_handle, node->vc_linkid, bridge,
	    sizeof (bridge));

	if (node->vc_state & CACHE_NODE_OFFLINED)
		fmt = _("%1$s offlined");
	else if (bridge[0] == '\0')
		fmt = _("%1$s not bridged");
	else
		fmt = _("%1$s bridge: %2$s");

	(void) asprintf(&buf, fmt, name, bridge);

	rcm_log_message(RCM_TRACE2, "Bridge: usage (%s) info = %s\n",
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
cache_lookup(rcm_handle_t *hd, char *rsrc, uint_t options)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE2, "Bridge: cache lookup(%s)\n", rsrc);

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
			    "Bridge: cache lookup succeeded(%s, %s)\n", rsrc,
			    node->vc_bridge);
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
	if (node != NULL) {
		free(node->vc_resource);
		free(node);
	}
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

typedef struct bridge_update_arg_s {
	rcm_handle_t	*hd;
	int		retval;
} bridge_update_arg_t;

/*
 * bridge_update() - Update physical interface properties
 */
static int
bridge_update(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
	bridge_update_arg_t *bua = arg;
	rcm_handle_t *hd = bua->hd;
	link_cache_t *node;
	char *rsrc;
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];
	char bridge[MAXLINKNAMELEN];
	int ret = RCM_FAILURE;

	rcm_log_message(RCM_TRACE2, "Bridge: bridge_update(%u)\n", linkid);

	assert(MUTEX_HELD(&cache_lock));
	status = dladm_bridge_getlink(dld_handle, linkid, bridge,
	    sizeof (bridge));
	if (status != DLADM_STATUS_OK) {
		rcm_log_message(RCM_TRACE1,
		    "Bridge: no bridge information for %u (%s)\n",
		    linkid, dladm_status2str(status, errmsg));
		return (DLADM_WALK_CONTINUE);
	}

	(void) asprintf(&rsrc, "%s/%u", RCM_LINK_PREFIX, linkid);
	if (rsrc == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("Bridge: allocation failure: %s %u: %s\n"),
		    bridge, linkid, strerror(errno));
		goto done;
	}

	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (node != NULL) {
		rcm_log_message(RCM_DEBUG, "Bridge: %s already registered\n",
		    rsrc);
		free(rsrc);
		node->vc_state &= ~CACHE_NODE_STALE;
	} else {
		rcm_log_message(RCM_DEBUG,
		    "Bridge: %s is a new resource (bridge %s)\n",
		    rsrc, bridge);
		if ((node = calloc(1, sizeof (link_cache_t))) == NULL) {
			free(rsrc);
			rcm_log_message(RCM_ERROR, _("Bridge: calloc: %s\n"),
			    strerror(errno));
			goto done;
		}

		node->vc_resource = rsrc;
		node->vc_linkid = linkid;
		(void) strlcpy(node->vc_bridge, bridge,
		    sizeof (node->vc_bridge));
		node->vc_state |= CACHE_NODE_NEW;
		cache_insert(node);
	}

	rcm_log_message(RCM_TRACE3, "Bridge: bridge_update: succeeded(%u %s)\n",
	    linkid, node->vc_bridge);
	ret = RCM_SUCCESS;
done:
	bua->retval = ret;
	return (ret == RCM_SUCCESS ? DLADM_WALK_CONTINUE :
	    DLADM_WALK_TERMINATE);
}

/*
 * cache_update() - Update cache with latest interface info
 */
static int
cache_update(rcm_handle_t *hd)
{
	link_cache_t *node, *nnode;
	int rv, lastrv;
	bridge_update_arg_t bua;

	rcm_log_message(RCM_TRACE2, "Bridge: cache_update\n");

	(void) mutex_lock(&cache_lock);

	/* first we walk the entire cache, marking each entry stale */
	node = cache_head.vc_next;
	for (; node != &cache_tail; node = node->vc_next)
		node->vc_state |= CACHE_NODE_STALE;

	/* now walk the links and update all of the entries */
	bua.hd = hd;
	bua.retval = RCM_SUCCESS;
	(void) dladm_walk_datalink_id(bridge_update, dld_handle, &bua,
	    DATALINK_CLASS_AGGR | DATALINK_CLASS_PHYS |
	    DATALINK_CLASS_ETHERSTUB, DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
	lastrv = bua.retval;

	/*
	 * Continue to delete all stale nodes from the cache even if the walk
	 * above failed.  Unregister links that are not offlined and still in
	 * the cache.
	 */
	for (node = cache_head.vc_next; node != &cache_tail; node = nnode) {
		nnode = node->vc_next;

		if (node->vc_state & CACHE_NODE_STALE) {
			(void) rcm_unregister_interest(hd, node->vc_resource,
			    0);
			rcm_log_message(RCM_DEBUG,
			    "Bridge: unregistered %s %s\n",
			    node->vc_resource, node->vc_bridge);
			cache_remove(node);
			node_free(node);
			continue;
		}

		if (!(node->vc_state & CACHE_NODE_NEW))
			continue;

		rv = rcm_register_interest(hd, node->vc_resource, 0, NULL);
		if (rv != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("Bridge: failed to register %s\n"),
			    node->vc_resource);
			lastrv = rv;
		} else {
			rcm_log_message(RCM_DEBUG, "Bridge: registered %s\n",
			    node->vc_resource);
			node->vc_state &= ~CACHE_NODE_NEW;
		}
	}

	(void) mutex_unlock(&cache_lock);
	return (lastrv);
}

/*
 * cache_free() - Empty the cache
 */
static void
cache_free(void)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE2, "Bridge: cache_free\n");

	(void) mutex_lock(&cache_lock);
	node = cache_head.vc_next;
	while (node != &cache_tail) {
		cache_remove(node);
		node_free(node);
		node = cache_head.vc_next;
	}
	(void) mutex_unlock(&cache_lock);
}

/*
 * bridge_log_err() - RCM error log wrapper
 */
static void
bridge_log_err(datalink_id_t linkid, char **errorp, char *errmsg)
{
	char link[MAXLINKNAMELEN];
	char errstr[DLADM_STRSIZE];
	dladm_status_t status;
	char *error;

	link[0] = '\0';
	if (linkid != DATALINK_INVALID_LINKID) {
		char rsrc[RCM_LINK_RESOURCE_MAX];

		(void) snprintf(rsrc, sizeof (rsrc), "%s/%u",
		    RCM_LINK_PREFIX, linkid);

		rcm_log_message(RCM_ERROR, _("Bridge: %s(%s)\n"), errmsg, rsrc);
		if ((status = dladm_datalink_id2info(dld_handle, linkid, NULL,
		    NULL, NULL, link, sizeof (link))) != DLADM_STATUS_OK) {
			rcm_log_message(RCM_WARNING,
			    _("Bridge: cannot get link name for (%s) %s\n"),
			    rsrc, dladm_status2str(status, errstr));
		}
	} else {
		rcm_log_message(RCM_ERROR, _("Bridge: %s\n"), errmsg);
	}

	if (link[0] != '\0')
		(void) asprintf(&error, _("Bridge: %s(%s)"), errmsg, link);
	else
		(void) asprintf(&error, _("Bridge: %s"), errmsg);

	if (errorp != NULL)
		*errorp = error;
}

/*
 * bridge_configure() - Configure bridge on a physical link after it attaches
 */
static int
bridge_configure(rcm_handle_t *hd, datalink_id_t linkid)
{
	char rsrc[RCM_LINK_RESOURCE_MAX];
	link_cache_t *node;
	char bridge[MAXLINKNAMELEN];

	/* Check for the bridge links in the cache */
	(void) snprintf(rsrc, sizeof (rsrc), "%s/%u", RCM_LINK_PREFIX, linkid);

	rcm_log_message(RCM_TRACE2, "Bridge: bridge_configure(%s)\n", rsrc);

	/* Check if the link is new or was previously offlined */
	(void) mutex_lock(&cache_lock);
	if (((node = cache_lookup(hd, rsrc, CACHE_REFRESH)) != NULL) &&
	    (!(node->vc_state & CACHE_NODE_OFFLINED))) {
		rcm_log_message(RCM_TRACE2,
		    "Bridge: Skipping configured interface(%s)\n", rsrc);
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}
	(void) mutex_unlock(&cache_lock);

	/* clear out previous bridge, if any */
	if (dladm_bridge_getlink(dld_handle, linkid, bridge, sizeof (bridge)) ==
	    DLADM_STATUS_OK) {
		if (bridge[0] != '\0')
			(void) dladm_bridge_setlink(dld_handle, linkid, "");
	}

	/* now set up the new one */
	if (node != NULL && node->vc_bridge[0] != '\0' &&
	    dladm_bridge_setlink(dld_handle, linkid, node->vc_bridge) !=
	    DLADM_STATUS_OK)
		return (RCM_FAILURE);
	else
		return (RCM_SUCCESS);
}
