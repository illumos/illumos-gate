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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This RCM module adds support to the RCM framework for VLAN links
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
#include <libdlvlan.h>
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

/* VLAN link flags */
typedef enum {
	VLAN_OFFLINED		= 0x1,
	VLAN_CONSUMER_OFFLINED	= 0x2,
	VLAN_STALE		= 0x4
} vlan_flag_t;

/* link representation */
typedef struct dl_vlan {
	struct dl_vlan	*dv_next;		/* next VLAN on the same link */
	struct dl_vlan	*dv_prev;		/* prev VLAN on the same link */
	datalink_id_t	dv_vlanid;
	vlan_flag_t	dv_flags;		/* VLAN link flags */
} dl_vlan_t;

/* VLAN Cache state flags */
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
	dl_vlan_t		*vc_vlan;	/* VLAN list on this link */
	cache_node_state_t	vc_state;	/* cache state flags */
} link_cache_t;

/*
 * Global cache for network VLANs
 */
static link_cache_t	cache_head;
static link_cache_t	cache_tail;
static mutex_t		cache_lock;
static int		events_registered = 0;

static dladm_handle_t	dld_handle = NULL;

/*
 * RCM module interface prototypes
 */
static int		vlan_register(rcm_handle_t *);
static int		vlan_unregister(rcm_handle_t *);
static int		vlan_get_info(rcm_handle_t *, char *, id_t, uint_t,
			    char **, char **, nvlist_t *, rcm_info_t **);
static int		vlan_suspend(rcm_handle_t *, char *, id_t,
			    timespec_t *, uint_t, char **, rcm_info_t **);
static int		vlan_resume(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		vlan_offline(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		vlan_undo_offline(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		vlan_remove(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		vlan_notify_event(rcm_handle_t *, char *, id_t, uint_t,
			    char **, nvlist_t *, rcm_info_t **);
static int		vlan_configure(rcm_handle_t *, datalink_id_t);

/* Module private routines */
static void 		cache_free();
static int 		cache_update(rcm_handle_t *);
static void 		cache_remove(link_cache_t *);
static void 		node_free(link_cache_t *);
static void 		cache_insert(link_cache_t *);
static link_cache_t	*cache_lookup(rcm_handle_t *, char *, char);
static int		vlan_consumer_offline(rcm_handle_t *, link_cache_t *,
			    char **, uint_t, rcm_info_t **);
static void		vlan_consumer_online(rcm_handle_t *, link_cache_t *,
			    char **, uint_t, rcm_info_t **);
static int		vlan_offline_vlan(link_cache_t *, uint32_t,
			    cache_node_state_t);
static void		vlan_online_vlan(link_cache_t *);
static char 		*vlan_usage(link_cache_t *);
static void 		vlan_log_err(datalink_id_t, char **, char *);
static int		vlan_consumer_notify(rcm_handle_t *, datalink_id_t,
			    char **, uint_t, rcm_info_t **);

/* Module-Private data */
static struct rcm_mod_ops vlan_ops =
{
	RCM_MOD_OPS_VERSION,
	vlan_register,
	vlan_unregister,
	vlan_get_info,
	vlan_suspend,
	vlan_resume,
	vlan_offline,
	vlan_undo_offline,
	vlan_remove,
	NULL,
	NULL,
	vlan_notify_event
};

/*
 * rcm_mod_init() - Update registrations, and return the ops structure.
 */
struct rcm_mod_ops *
rcm_mod_init(void)
{
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];

	rcm_log_message(RCM_TRACE1, "VLAN: mod_init\n");

	cache_head.vc_next = &cache_tail;
	cache_head.vc_prev = NULL;
	cache_tail.vc_prev = &cache_head;
	cache_tail.vc_next = NULL;
	(void) mutex_init(&cache_lock, 0, NULL);

	if ((status = dladm_open(&dld_handle)) != DLADM_STATUS_OK) {
		rcm_log_message(RCM_WARNING,
		    "VLAN: mod_init failed: cannot open datalink handle: %s\n",
		    dladm_status2str(status, errmsg));
		return (NULL);
	}

	/* Return the ops vectors */
	return (&vlan_ops);
}

/*
 * rcm_mod_info() - Return a string describing this module.
 */
const char *
rcm_mod_info(void)
{
	rcm_log_message(RCM_TRACE1, "VLAN: mod_info\n");

	return ("VLAN module version 1.2");
}

/*
 * rcm_mod_fini() - Destroy the network VLAN cache.
 */
int
rcm_mod_fini(void)
{
	rcm_log_message(RCM_TRACE1, "VLAN: mod_fini\n");

	/*
	 * Note that vlan_unregister() does not seem to be called anywhere,
	 * therefore we free the cache nodes here. In theory we should call
	 * rcm_register_interest() for each node before we free it, the
	 * framework does not provide the rcm_handle to allow us to do so.
	 */
	cache_free();
	(void) mutex_destroy(&cache_lock);

	dladm_close(dld_handle);
	return (RCM_SUCCESS);
}

/*
 * vlan_register() - Make sure the cache is properly sync'ed, and its
 *		 registrations are in order.
 */
static int
vlan_register(rcm_handle_t *hd)
{
	rcm_log_message(RCM_TRACE1, "VLAN: register\n");

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
			    _("VLAN: failed to register %s\n"),
			    RCM_RESOURCE_LINK_NEW);
			return (RCM_FAILURE);
		} else {
			rcm_log_message(RCM_DEBUG, "VLAN: registered %s\n",
			    RCM_RESOURCE_LINK_NEW);
			events_registered++;
		}
	}

	return (RCM_SUCCESS);
}

/*
 * vlan_unregister() - Walk the cache, unregistering all the networks.
 */
static int
vlan_unregister(rcm_handle_t *hd)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "VLAN: unregister\n");

	/* Walk the cache, unregistering everything */
	(void) mutex_lock(&cache_lock);
	node = cache_head.vc_next;
	while (node != &cache_tail) {
		if (rcm_unregister_interest(hd, node->vc_resource, 0)
		    != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("VLAN: failed to unregister %s\n"),
			    node->vc_resource);
			(void) mutex_unlock(&cache_lock);
			return (RCM_FAILURE);
		}
		cache_remove(node);
		node_free(node);
		node = cache_head.vc_next;
	}
	(void) mutex_unlock(&cache_lock);

	/*
	 * Unregister interest in all new resources
	 */
	if (events_registered) {
		if (rcm_unregister_event(hd, RCM_RESOURCE_LINK_NEW, 0)
		    != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("VLAN: failed to unregister %s\n"),
			    RCM_RESOURCE_LINK_NEW);
			return (RCM_FAILURE);
		} else {
			rcm_log_message(RCM_DEBUG, "VLAN: unregistered %s\n",
			    RCM_RESOURCE_LINK_NEW);
			events_registered--;
		}
	}

	return (RCM_SUCCESS);
}

/*
 * vlan_offline() - Offline VLANs on a specific node.
 */
static int
vlan_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "VLAN: offline(%s)\n", rsrc);

	/* Lock the cache and lookup the resource */
	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_REFRESH);
	if (node == NULL) {
		/* should not happen because the resource is registered. */
		vlan_log_err(DATALINK_INVALID_LINKID, errorp,
		    "unrecognized resource");
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	/*
	 * Inform consumers (IP interfaces) of associated VLANs to be offlined
	 */
	if (vlan_consumer_offline(hd, node, errorp, flags, info) ==
	    RCM_SUCCESS) {
		rcm_log_message(RCM_DEBUG,
		    "VLAN: consumers agreed on offline\n");
	} else {
		vlan_log_err(node->vc_linkid, errorp,
		    "consumers failed to offline");
		(void) mutex_unlock(&cache_lock);
		return (RCM_FAILURE);
	}

	/* Check if it's a query */
	if (flags & RCM_QUERY) {
		rcm_log_message(RCM_TRACE1,
		    "VLAN: offline query succeeded(%s)\n", rsrc);
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	if (vlan_offline_vlan(node, VLAN_OFFLINED, CACHE_NODE_OFFLINED) !=
	    RCM_SUCCESS) {
		vlan_online_vlan(node);
		vlan_log_err(node->vc_linkid, errorp, "offline failed");
		(void) mutex_unlock(&cache_lock);
		return (RCM_FAILURE);
	}

	rcm_log_message(RCM_TRACE1, "VLAN: Offline succeeded(%s)\n", rsrc);
	(void) mutex_unlock(&cache_lock);
	return (RCM_SUCCESS);
}

/*
 * vlan_undo_offline() - Undo offline of a previously offlined node.
 */
/*ARGSUSED*/
static int
vlan_undo_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "VLAN: online(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (node == NULL) {
		vlan_log_err(DATALINK_INVALID_LINKID, errorp, "no such link");
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	/* Check if no attempt should be made to online the link here */
	if (!(node->vc_state & CACHE_NODE_OFFLINED)) {
		vlan_log_err(node->vc_linkid, errorp, "link not offlined");
		(void) mutex_unlock(&cache_lock);
		errno = ENOTSUP;
		return (RCM_SUCCESS);
	}

	vlan_online_vlan(node);

	/*
	 * Inform IP interfaces on associated VLANs to be onlined
	 */
	vlan_consumer_online(hd, node, errorp, flags, info);

	node->vc_state &= ~CACHE_NODE_OFFLINED;
	rcm_log_message(RCM_TRACE1, "VLAN: online succeeded(%s)\n", rsrc);
	(void) mutex_unlock(&cache_lock);
	return (RCM_SUCCESS);
}

static void
vlan_online_vlan(link_cache_t *node)
{
	dl_vlan_t *vlan;
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];

	/*
	 * Try to bring on all offlined VLANs
	 */
	for (vlan = node->vc_vlan; vlan != NULL; vlan = vlan->dv_next) {
		if (!(vlan->dv_flags & VLAN_OFFLINED))
			continue;

		if ((status = dladm_vlan_up(dld_handle, vlan->dv_vlanid)) !=
		    DLADM_STATUS_OK) {
			/*
			 * Print a warning message and continue to online
			 * other VLANs.
			 */
			rcm_log_message(RCM_WARNING,
			    _("VLAN: VLAN online failed (%u): %s\n"),
			    vlan->dv_vlanid, dladm_status2str(status, errmsg));
		} else {
			vlan->dv_flags &= ~VLAN_OFFLINED;
		}
	}
}

static int
vlan_offline_vlan(link_cache_t *node, uint32_t flags, cache_node_state_t state)
{
	dl_vlan_t *vlan;
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];

	rcm_log_message(RCM_TRACE2, "VLAN: vlan_offline_vlan (%s %u %u)\n",
	    node->vc_resource, flags, state);

	/*
	 * Try to delete all explicit created VLAN
	 */
	for (vlan = node->vc_vlan; vlan != NULL; vlan = vlan->dv_next) {
		if ((status = dladm_vlan_delete(dld_handle, vlan->dv_vlanid,
		    DLADM_OPT_ACTIVE)) != DLADM_STATUS_OK) {
			rcm_log_message(RCM_WARNING,
			    _("VLAN: VLAN offline failed (%u): %s\n"),
			    vlan->dv_vlanid, dladm_status2str(status, errmsg));
			return (RCM_FAILURE);
		} else {
			rcm_log_message(RCM_TRACE1,
			    "VLAN: VLAN offline succeeded(%u)\n",
			    vlan->dv_vlanid);
			vlan->dv_flags |= flags;
		}
	}

	node->vc_state |= state;
	return (RCM_SUCCESS);
}

/*
 * vlan_get_info() - Gather usage information for this resource.
 */
/*ARGSUSED*/
int
vlan_get_info(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **usagep, char **errorp, nvlist_t *props, rcm_info_t **info)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "VLAN: get_info(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_REFRESH);
	if (node == NULL) {
		rcm_log_message(RCM_INFO,
		    _("VLAN: get_info(%s) unrecognized resource\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	*usagep = vlan_usage(node);
	(void) mutex_unlock(&cache_lock);
	if (*usagep == NULL) {
		/* most likely malloc failure */
		rcm_log_message(RCM_ERROR,
		    _("VLAN: get_info(%s) malloc failure\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOMEM;
		return (RCM_FAILURE);
	}

	/* Set client/role properties */
	(void) nvlist_add_string(props, RCM_CLIENT_NAME, "VLAN");

	rcm_log_message(RCM_TRACE1, "VLAN: get_info(%s) info = %s\n",
	    rsrc, *usagep);
	return (RCM_SUCCESS);
}

/*
 * vlan_suspend() - Nothing to do, always okay
 */
/*ARGSUSED*/
static int
vlan_suspend(rcm_handle_t *hd, char *rsrc, id_t id, timespec_t *interval,
    uint_t flags, char **errorp, rcm_info_t **info)
{
	rcm_log_message(RCM_TRACE1, "VLAN: suspend(%s)\n", rsrc);
	return (RCM_SUCCESS);
}

/*
 * vlan_resume() - Nothing to do, always okay
 */
/*ARGSUSED*/
static int
vlan_resume(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	rcm_log_message(RCM_TRACE1, "VLAN: resume(%s)\n", rsrc);
	return (RCM_SUCCESS);
}

/*
 * vlan_consumer_remove()
 *
 *	Notify VLAN consumers to remove cache.
 */
static int
vlan_consumer_remove(rcm_handle_t *hd, link_cache_t *node, uint_t flags,
    rcm_info_t **info)
{
	dl_vlan_t *vlan = NULL;
	char rsrc[RCM_LINK_RESOURCE_MAX];
	int ret = RCM_SUCCESS;

	rcm_log_message(RCM_TRACE2, "VLAN: vlan_consumer_remove (%s)\n",
	    node->vc_resource);

	for (vlan = node->vc_vlan; vlan != NULL; vlan = vlan->dv_next) {

		/*
		 * This will only be called when the offline operation
		 * succeeds, so the VLAN consumers must have been offlined
		 * at this point.
		 */
		assert(vlan->dv_flags & VLAN_CONSUMER_OFFLINED);

		(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u",
		    RCM_LINK_PREFIX, vlan->dv_vlanid);

		ret = rcm_notify_remove(hd, rsrc, flags, info);
		if (ret != RCM_SUCCESS) {
			rcm_log_message(RCM_WARNING,
			    _("VLAN: notify remove failed (%s)\n"), rsrc);
			break;
		}
	}

	rcm_log_message(RCM_TRACE2, "VLAN: vlan_consumer_remove done\n");
	return (ret);
}

/*
 * vlan_remove() - remove a resource from cache
 */
/*ARGSUSED*/
static int
vlan_remove(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	link_cache_t *node;
	int rv;

	rcm_log_message(RCM_TRACE1, "VLAN: remove(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (node == NULL) {
		rcm_log_message(RCM_INFO,
		    _("VLAN: remove(%s) unrecognized resource\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	/* remove the cached entry for the resource */
	cache_remove(node);
	(void) mutex_unlock(&cache_lock);

	rv = vlan_consumer_remove(hd, node, flags, info);
	node_free(node);
	return (rv);
}

/*
 * vlan_notify_event - Project private implementation to receive new resource
 *		   events. It intercepts all new resource events. If the
 *		   new resource is a network resource, pass up a notify
 *		   for it too. The new resource need not be cached, since
 *		   it is done at register again.
 */
/*ARGSUSED*/
static int
vlan_notify_event(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, nvlist_t *nvl, rcm_info_t **info)
{
	nvpair_t	*nvp = NULL;
	datalink_id_t	linkid;
	uint64_t	id64;
	int		rv = RCM_SUCCESS;

	rcm_log_message(RCM_TRACE1, "VLAN: notify_event(%s)\n", rsrc);

	if (strcmp(rsrc, RCM_RESOURCE_LINK_NEW) != 0) {
		vlan_log_err(DATALINK_INVALID_LINKID, errorp,
		    "unrecognized event");
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	/* Update cache to reflect latest VLANs */
	if (cache_update(hd) < 0) {
		vlan_log_err(DATALINK_INVALID_LINKID, errorp,
		    "private Cache update failed");
		return (RCM_FAILURE);
	}

	/*
	 * Try best to recover all configuration.
	 */
	rcm_log_message(RCM_DEBUG, "VLAN: process_nvlist\n");
	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		if (strcmp(nvpair_name(nvp), RCM_NV_LINKID) != 0)
			continue;

		if (nvpair_value_uint64(nvp, &id64) != 0) {
			vlan_log_err(DATALINK_INVALID_LINKID, errorp,
			    "cannot get linkid");
			rv = RCM_FAILURE;
			continue;
		}

		linkid = (datalink_id_t)id64;
		if (vlan_configure(hd, linkid) != 0) {
			vlan_log_err(linkid, errorp, "configuring failed");
			rv = RCM_FAILURE;
			continue;
		}

		/* Notify all VLAN consumers */
		if (vlan_consumer_notify(hd, linkid, errorp, flags,
		    info) != 0) {
			vlan_log_err(linkid, errorp, "consumer notify failed");
			rv = RCM_FAILURE;
		}
	}

	rcm_log_message(RCM_TRACE1,
	    "VLAN: notify_event: link configuration complete\n");
	return (rv);
}

/*
 * vlan_usage - Determine the usage of a link.
 *	    The returned buffer is owned by caller, and the caller
 *	    must free it up when done.
 */
static char *
vlan_usage(link_cache_t *node)
{
	dl_vlan_t *vlan;
	int nvlan;
	char *buf;
	const char *fmt;
	char *sep;
	char errmsg[DLADM_STRSIZE];
	char name[MAXLINKNAMELEN];
	dladm_status_t status;
	size_t bufsz;

	rcm_log_message(RCM_TRACE2, "VLAN: usage(%s)\n", node->vc_resource);

	assert(MUTEX_HELD(&cache_lock));
	if ((status = dladm_datalink_id2info(dld_handle, node->vc_linkid, NULL,
	    NULL, NULL, name, sizeof (name))) != DLADM_STATUS_OK) {
		rcm_log_message(RCM_ERROR,
		    _("VLAN: usage(%s) get link name failure(%s)\n"),
		    node->vc_resource, dladm_status2str(status, errmsg));
		return (NULL);
	}

	if (node->vc_state & CACHE_NODE_OFFLINED)
		fmt = _("%1$s offlined");
	else
		fmt = _("%1$s VLANs: ");

	/* TRANSLATION_NOTE: separator used between VLAN linkids */
	sep = _(", ");

	nvlan = 0;
	for (vlan = node->vc_vlan; vlan != NULL; vlan = vlan->dv_next)
		nvlan++;

	/* space for VLANs and separators, plus message */
	bufsz = nvlan * (MAXLINKNAMELEN + strlen(sep)) +
	    strlen(fmt) + MAXLINKNAMELEN + 1;
	if ((buf = malloc(bufsz)) == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("VLAN: usage(%s) malloc failure(%s)\n"),
		    node->vc_resource, strerror(errno));
		return (NULL);
	}
	(void) snprintf(buf, bufsz, fmt, name);

	if (node->vc_state & CACHE_NODE_OFFLINED) {
		/* Nothing else to do */
		rcm_log_message(RCM_TRACE2, "VLAN: usage (%s) info = %s\n",
		    node->vc_resource, buf);
		return (buf);
	}

	for (vlan = node->vc_vlan; vlan != NULL; vlan = vlan->dv_next) {
		rcm_log_message(RCM_DEBUG, "VLAN:= %u\n", vlan->dv_vlanid);

		if ((status = dladm_datalink_id2info(dld_handle,
		    vlan->dv_vlanid, NULL, NULL, NULL, name,
		    sizeof (name))) != DLADM_STATUS_OK) {
			rcm_log_message(RCM_ERROR,
			    _("VLAN: usage(%s) get vlan %u name failure(%s)\n"),
			    node->vc_resource, vlan->dv_vlanid,
			    dladm_status2str(status, errmsg));
			free(buf);
			return (NULL);
		}

		(void) strlcat(buf, name, bufsz);
		if (vlan->dv_next != NULL)
			(void) strlcat(buf, sep, bufsz);
	}

	rcm_log_message(RCM_TRACE2, "VLAN: usage (%s) info = %s\n",
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

	rcm_log_message(RCM_TRACE2, "VLAN: cache lookup(%s)\n", rsrc);

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
			    "VLAN: cache lookup succeeded(%s)\n", rsrc);
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
	dl_vlan_t *vlan, *next;

	if (node != NULL) {
		free(node->vc_resource);

		/* free the VLAN list */
		for (vlan = node->vc_vlan; vlan != NULL; vlan = next) {
			next = vlan->dv_next;
			free(vlan);
		}
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

typedef struct vlan_update_arg_s {
	rcm_handle_t	*hd;
	int		retval;
} vlan_update_arg_t;

/*
 * vlan_update() - Update physical interface properties
 */
static int
vlan_update(dladm_handle_t handle, datalink_id_t vlanid, void *arg)
{
	vlan_update_arg_t *vlan_update_argp = arg;
	rcm_handle_t *hd = vlan_update_argp->hd;
	link_cache_t *node;
	dl_vlan_t *vlan;
	char *rsrc;
	dladm_vlan_attr_t vlan_attr;
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];
	boolean_t newnode = B_FALSE;
	int ret = -1;

	rcm_log_message(RCM_TRACE2, "VLAN: vlan_update(%u)\n", vlanid);

	assert(MUTEX_HELD(&cache_lock));
	status = dladm_vlan_info(handle, vlanid, &vlan_attr, DLADM_OPT_ACTIVE);
	if (status != DLADM_STATUS_OK) {
		rcm_log_message(RCM_TRACE1,
		    "VLAN: vlan_update() cannot get vlan information for "
		    "%u(%s)\n", vlanid, dladm_status2str(status, errmsg));
		return (DLADM_WALK_CONTINUE);
	}

	rsrc = malloc(RCM_LINK_RESOURCE_MAX);
	if (rsrc == NULL) {
		rcm_log_message(RCM_ERROR, _("VLAN: malloc error(%s): %u\n"),
		    strerror(errno), vlanid);
		goto done;
	}

	(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u",
	    RCM_LINK_PREFIX, vlan_attr.dv_linkid);

	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (node != NULL) {
		rcm_log_message(RCM_DEBUG,
		    "VLAN: %s already registered (vlanid:%d)\n",
		    rsrc, vlan_attr.dv_vid);
		free(rsrc);
	} else {
		rcm_log_message(RCM_DEBUG,
		    "VLAN: %s is a new resource (vlanid:%d)\n",
		    rsrc, vlan_attr.dv_vid);
		if ((node = calloc(1, sizeof (link_cache_t))) == NULL) {
			free(rsrc);
			rcm_log_message(RCM_ERROR, _("VLAN: calloc: %s\n"),
			    strerror(errno));
			goto done;
		}

		node->vc_resource = rsrc;
		node->vc_vlan = NULL;
		node->vc_linkid = vlan_attr.dv_linkid;
		node->vc_state |= CACHE_NODE_NEW;
		newnode = B_TRUE;
	}

	for (vlan = node->vc_vlan; vlan != NULL; vlan = vlan->dv_next) {
		if (vlan->dv_vlanid == vlanid) {
			vlan->dv_flags &= ~VLAN_STALE;
			break;
		}
	}

	if (vlan == NULL) {
		if ((vlan = calloc(1, sizeof (dl_vlan_t))) == NULL) {
			rcm_log_message(RCM_ERROR, _("VLAN: malloc: %s\n"),
			    strerror(errno));
			if (newnode) {
				free(rsrc);
				free(node);
			}
			goto done;
		}
		vlan->dv_vlanid = vlanid;
		vlan->dv_next = node->vc_vlan;
		vlan->dv_prev = NULL;
		if (node->vc_vlan != NULL)
			node->vc_vlan->dv_prev = vlan;
		node->vc_vlan = vlan;
	}

	node->vc_state &= ~CACHE_NODE_STALE;

	if (newnode)
		cache_insert(node);

	rcm_log_message(RCM_TRACE3, "VLAN: vlan_update: succeeded(%u)\n",
	    vlanid);
	ret = 0;
done:
	vlan_update_argp->retval = ret;
	return (ret == 0 ? DLADM_WALK_CONTINUE : DLADM_WALK_TERMINATE);
}

/*
 * vlan_update_all() - Determine all VLAN links in the system
 */
static int
vlan_update_all(rcm_handle_t *hd)
{
	vlan_update_arg_t arg = {NULL, 0};

	rcm_log_message(RCM_TRACE2, "VLAN: vlan_update_all\n");

	assert(MUTEX_HELD(&cache_lock));
	arg.hd = hd;
	(void) dladm_walk_datalink_id(vlan_update, dld_handle, &arg,
	    DATALINK_CLASS_VLAN, DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
	return (arg.retval);
}

/*
 * cache_update() - Update cache with latest interface info
 */
static int
cache_update(rcm_handle_t *hd)
{
	link_cache_t *node, *nnode;
	dl_vlan_t *vlan;
	int rv;

	rcm_log_message(RCM_TRACE2, "VLAN: cache_update\n");

	(void) mutex_lock(&cache_lock);

	/* first we walk the entire cache, marking each entry stale */
	node = cache_head.vc_next;
	for (; node != &cache_tail; node = node->vc_next) {
		node->vc_state |= CACHE_NODE_STALE;
		for (vlan = node->vc_vlan; vlan != NULL; vlan = vlan->dv_next)
			vlan->dv_flags |= VLAN_STALE;
	}

	rv = vlan_update_all(hd);

	/*
	 * Continue to delete all stale nodes from the cache even
	 * vlan_update_all() failed. Unregister link that are not offlined
	 * and still in cache
	 */
	for (node = cache_head.vc_next; node != &cache_tail; node = nnode) {
		dl_vlan_t *vlan, *next;

		for (vlan = node->vc_vlan; vlan != NULL; vlan = next) {
			next = vlan->dv_next;

			/* clear stale VLANs */
			if (vlan->dv_flags & VLAN_STALE) {
				if (vlan->dv_prev != NULL)
					vlan->dv_prev->dv_next = next;
				else
					node->vc_vlan = next;

				if (next != NULL)
					next->dv_prev = vlan->dv_prev;
				free(vlan);
			}
		}

		nnode = node->vc_next;
		if (node->vc_state & CACHE_NODE_STALE) {
			(void) rcm_unregister_interest(hd, node->vc_resource,
			    0);
			rcm_log_message(RCM_DEBUG, "VLAN: unregistered %s\n",
			    node->vc_resource);
			assert(node->vc_vlan == NULL);
			cache_remove(node);
			node_free(node);
			continue;
		}

		if (!(node->vc_state & CACHE_NODE_NEW))
			continue;

		if (rcm_register_interest(hd, node->vc_resource, 0, NULL) !=
		    RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("VLAN: failed to register %s\n"),
			    node->vc_resource);
			rv = -1;
		} else {
			rcm_log_message(RCM_DEBUG, "VLAN: registered %s\n",
			    node->vc_resource);
			node->vc_state &= ~CACHE_NODE_NEW;
		}
	}

	(void) mutex_unlock(&cache_lock);
	return (rv);
}

/*
 * cache_free() - Empty the cache
 */
static void
cache_free()
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE2, "VLAN: cache_free\n");

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
 * vlan_log_err() - RCM error log wrapper
 */
static void
vlan_log_err(datalink_id_t linkid, char **errorp, char *errmsg)
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

		(void) snprintf(rsrc, sizeof (rsrc), "%s/%u",
		    RCM_LINK_PREFIX, linkid);

		rcm_log_message(RCM_ERROR, _("VLAN: %s(%s)\n"), errmsg, rsrc);
		if ((status = dladm_datalink_id2info(dld_handle, linkid, NULL,
		    NULL, NULL, link, sizeof (link))) != DLADM_STATUS_OK) {
			rcm_log_message(RCM_WARNING,
			    _("VLAN: cannot get link name for (%s) %s\n"),
			    rsrc, dladm_status2str(status, errstr));
		}
	} else {
		rcm_log_message(RCM_ERROR, _("VLAN: %s\n"), errmsg);
	}

	errfmt = strlen(link) > 0 ? _("VLAN: %s(%s)") : _("VLAN: %s");
	len = strlen(errfmt) + strlen(errmsg) + MAXLINKNAMELEN + 1;
	if ((error = malloc(len)) != NULL) {
		if (strlen(link) > 0)
			(void) snprintf(error, len, errfmt, errmsg, link);
		else
			(void) snprintf(error, len, errfmt, errmsg);
	}

	if (errorp != NULL)
		*errorp = error;
}

/*
 * vlan_consumer_online()
 *
 *	Notify online to VLAN consumers.
 */
/* ARGSUSED */
static void
vlan_consumer_online(rcm_handle_t *hd, link_cache_t *node, char **errorp,
    uint_t flags, rcm_info_t **info)
{
	dl_vlan_t *vlan;
	char rsrc[RCM_LINK_RESOURCE_MAX];

	rcm_log_message(RCM_TRACE2, "VLAN: vlan_consumer_online (%s)\n",
	    node->vc_resource);

	for (vlan = node->vc_vlan; vlan != NULL; vlan = vlan->dv_next) {
		if (!(vlan->dv_flags & VLAN_CONSUMER_OFFLINED))
			continue;

		(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u",
		    RCM_LINK_PREFIX, vlan->dv_vlanid);

		if (rcm_notify_online(hd, rsrc, flags, info) == RCM_SUCCESS)
			vlan->dv_flags &= ~VLAN_CONSUMER_OFFLINED;
	}

	rcm_log_message(RCM_TRACE2, "VLAN: vlan_consumer_online done\n");
}

/*
 * vlan_consumer_offline()
 *
 *	Offline VLAN consumers.
 */
static int
vlan_consumer_offline(rcm_handle_t *hd, link_cache_t *node, char **errorp,
    uint_t flags, rcm_info_t **info)
{
	dl_vlan_t *vlan;
	char rsrc[RCM_LINK_RESOURCE_MAX];
	int ret = RCM_SUCCESS;

	rcm_log_message(RCM_TRACE2, "VLAN: vlan_consumer_offline (%s)\n",
	    node->vc_resource);

	for (vlan = node->vc_vlan; vlan != NULL; vlan = vlan->dv_next) {
		(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u",
		    RCM_LINK_PREFIX, vlan->dv_vlanid);

		ret = rcm_request_offline(hd, rsrc, flags, info);
		if (ret != RCM_SUCCESS)
			break;

		vlan->dv_flags |= VLAN_CONSUMER_OFFLINED;
	}

	if (vlan != NULL)
		vlan_consumer_online(hd, node, errorp, flags, info);

	rcm_log_message(RCM_TRACE2, "VLAN: vlan_consumer_offline done\n");
	return (ret);
}

/*
 * Send RCM_RESOURCE_LINK_NEW events to other modules about new VLANs.
 * Return 0 on success, -1 on failure.
 */
static int
vlan_notify_new_vlan(rcm_handle_t *hd, char *rsrc)
{
	link_cache_t *node;
	dl_vlan_t *vlan;
	nvlist_t *nvl = NULL;
	uint64_t id;
	int ret = -1;

	rcm_log_message(RCM_TRACE2, "VLAN: vlan_notify_new_vlan (%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	if ((node = cache_lookup(hd, rsrc, CACHE_REFRESH)) == NULL) {
		(void) mutex_unlock(&cache_lock);
		return (0);
	}

	if (nvlist_alloc(&nvl, 0, 0) != 0) {
		(void) mutex_unlock(&cache_lock);
		rcm_log_message(RCM_WARNING,
		    _("VLAN: failed to allocate nvlist\n"));
		goto done;
	}

	for (vlan = node->vc_vlan; vlan != NULL; vlan = vlan->dv_next) {
		rcm_log_message(RCM_TRACE2,
		    "VLAN: vlan_notify_new_vlan add (%u)\n",
		    vlan->dv_vlanid);

		id = vlan->dv_vlanid;
		if (nvlist_add_uint64(nvl, RCM_NV_LINKID, id) != 0) {
			rcm_log_message(RCM_ERROR,
			    _("VLAN: failed to construct nvlist\n"));
			(void) mutex_unlock(&cache_lock);
			goto done;
		}
	}
	(void) mutex_unlock(&cache_lock);

	if (rcm_notify_event(hd, RCM_RESOURCE_LINK_NEW, 0, nvl, NULL) !=
	    RCM_SUCCESS) {
		rcm_log_message(RCM_ERROR,
		    _("VLAN: failed to notify %s event for %s\n"),
		    RCM_RESOURCE_LINK_NEW, node->vc_resource);
		goto done;
	}

	ret = 0;
done:
	nvlist_free(nvl);
	return (ret);
}

/*
 * vlan_consumer_notify() - Notify consumers of VLANs coming back online.
 */
static int
vlan_consumer_notify(rcm_handle_t *hd, datalink_id_t linkid, char **errorp,
    uint_t flags, rcm_info_t **info)
{
	char rsrc[RCM_LINK_RESOURCE_MAX];
	link_cache_t *node;

	/* Check for the interface in the cache */
	(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u", RCM_LINK_PREFIX,
	    linkid);

	rcm_log_message(RCM_TRACE2, "VLAN: vlan_consumer_notify(%s)\n", rsrc);

	/*
	 * Inform IP consumers of the new link.
	 */
	if (vlan_notify_new_vlan(hd, rsrc) != 0) {
		(void) mutex_lock(&cache_lock);
		if ((node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH)) != NULL) {
			(void) vlan_offline_vlan(node, VLAN_STALE,
			    CACHE_NODE_STALE);
		}
		(void) mutex_unlock(&cache_lock);
		rcm_log_message(RCM_TRACE2,
		    "VLAN: vlan_notify_new_vlan failed(%s)\n", rsrc);
		return (-1);
	}

	rcm_log_message(RCM_TRACE2, "VLAN: vlan_consumer_notify succeeded\n");
	return (0);
}

typedef struct vlan_up_arg_s {
	datalink_id_t	linkid;
	int		retval;
} vlan_up_arg_t;

static int
vlan_up(dladm_handle_t handle, datalink_id_t vlanid, void *arg)
{
	vlan_up_arg_t *vlan_up_argp = arg;
	dladm_status_t status;
	dladm_vlan_attr_t vlan_attr;
	char errmsg[DLADM_STRSIZE];

	status = dladm_vlan_info(handle, vlanid, &vlan_attr, DLADM_OPT_PERSIST);
	if (status != DLADM_STATUS_OK) {
		rcm_log_message(RCM_TRACE1,
		    "VLAN: vlan_up(): cannot get information for VLAN %u "
		    "(%s)\n", vlanid, dladm_status2str(status, errmsg));
		return (DLADM_WALK_CONTINUE);
	}

	if (vlan_attr.dv_linkid != vlan_up_argp->linkid)
		return (DLADM_WALK_CONTINUE);

	rcm_log_message(RCM_TRACE3, "VLAN: vlan_up(%u)\n", vlanid);
	if ((status = dladm_vlan_up(handle, vlanid)) == DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	/*
	 * Prompt the warning message and continue to UP other VLANs.
	 */
	rcm_log_message(RCM_WARNING,
	    _("VLAN: VLAN up failed (%u): %s\n"),
	    vlanid, dladm_status2str(status, errmsg));

	vlan_up_argp->retval = -1;
	return (DLADM_WALK_CONTINUE);
}

/*
 * vlan_configure() - Configure VLANs over a physical link after it attaches
 */
static int
vlan_configure(rcm_handle_t *hd, datalink_id_t linkid)
{
	char rsrc[RCM_LINK_RESOURCE_MAX];
	link_cache_t *node;
	vlan_up_arg_t arg = {DATALINK_INVALID_LINKID, 0};

	/* Check for the VLANs in the cache */
	(void) snprintf(rsrc, sizeof (rsrc), "%s/%u", RCM_LINK_PREFIX, linkid);

	rcm_log_message(RCM_TRACE2, "VLAN: vlan_configure(%s)\n", rsrc);

	/* Check if the link is new or was previously offlined */
	(void) mutex_lock(&cache_lock);
	if (((node = cache_lookup(hd, rsrc, CACHE_REFRESH)) != NULL) &&
	    (!(node->vc_state & CACHE_NODE_OFFLINED))) {
		rcm_log_message(RCM_TRACE2,
		    "VLAN: Skipping configured interface(%s)\n", rsrc);
		(void) mutex_unlock(&cache_lock);
		return (0);
	}
	(void) mutex_unlock(&cache_lock);

	arg.linkid = linkid;
	(void) dladm_walk_datalink_id(vlan_up, dld_handle, &arg,
	    DATALINK_CLASS_VLAN, DATALINK_ANY_MEDIATYPE, DLADM_OPT_PERSIST);

	if (arg.retval == 0) {
		rcm_log_message(RCM_TRACE2,
		    "VLAN: vlan_configure succeeded(%s)\n", rsrc);
	}
	return (arg.retval);
}
