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
 * This RCM module adds support to the RCM framework for VNIC links
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
#include <libdlvnic.h>
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

/* VNIC link flags */
typedef enum {
	VNIC_OFFLINED		= 0x1,
	VNIC_CONSUMER_OFFLINED	= 0x2,
	VNIC_STALE		= 0x4
} vnic_flag_t;

/* link representation */
typedef struct dl_vnic {
	struct dl_vnic	*dlv_next;		/* next VNIC on the same link */
	struct dl_vnic	*dlv_prev;		/* prev VNIC on the same link */
	datalink_id_t	dlv_vnic_id;
	vnic_flag_t	dlv_flags;		/* VNIC link flags */
} dl_vnic_t;

/* VNIC Cache state flags */
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
	dl_vnic_t		*vc_vnic;	/* VNIC list on this link */
	cache_node_state_t	vc_state;	/* cache state flags */
} link_cache_t;

/*
 * Global cache for network VNICs
 */
static link_cache_t	cache_head;
static link_cache_t	cache_tail;
static mutex_t		cache_lock;
static int		events_registered = 0;

static dladm_handle_t	dld_handle = NULL;

/*
 * RCM module interface prototypes
 */
static int		vnic_register(rcm_handle_t *);
static int		vnic_unregister(rcm_handle_t *);
static int		vnic_get_info(rcm_handle_t *, char *, id_t, uint_t,
			    char **, char **, nvlist_t *, rcm_info_t **);
static int		vnic_suspend(rcm_handle_t *, char *, id_t,
			    timespec_t *, uint_t, char **, rcm_info_t **);
static int		vnic_resume(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		vnic_offline(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		vnic_undo_offline(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		vnic_remove(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		vnic_notify_event(rcm_handle_t *, char *, id_t, uint_t,
			    char **, nvlist_t *, rcm_info_t **);
static int		vnic_configure(rcm_handle_t *, datalink_id_t);

/* Module private routines */
static void 		cache_free();
static int 		cache_update(rcm_handle_t *);
static void 		cache_remove(link_cache_t *);
static void 		node_free(link_cache_t *);
static void 		cache_insert(link_cache_t *);
static link_cache_t	*cache_lookup(rcm_handle_t *, char *, char);
static int		vnic_consumer_offline(rcm_handle_t *, link_cache_t *,
			    char **, uint_t, rcm_info_t **);
static void		vnic_consumer_online(rcm_handle_t *, link_cache_t *,
			    char **, uint_t, rcm_info_t **);
static int		vnic_offline_vnic(link_cache_t *, uint32_t,
			    cache_node_state_t);
static void		vnic_online_vnic(link_cache_t *);
static char 		*vnic_usage(link_cache_t *);
static void 		vnic_log_err(datalink_id_t, char **, char *);
static int		vnic_consumer_notify(rcm_handle_t *, datalink_id_t,
			    char **, uint_t, rcm_info_t **);

/* Module-Private data */
static struct rcm_mod_ops vnic_ops =
{
	RCM_MOD_OPS_VERSION,
	vnic_register,
	vnic_unregister,
	vnic_get_info,
	vnic_suspend,
	vnic_resume,
	vnic_offline,
	vnic_undo_offline,
	vnic_remove,
	NULL,
	NULL,
	vnic_notify_event
};

/*
 * rcm_mod_init() - Update registrations, and return the ops structure.
 */
struct rcm_mod_ops *
rcm_mod_init(void)
{
	char errmsg[DLADM_STRSIZE];
	dladm_status_t status;

	rcm_log_message(RCM_TRACE1, "VNIC: mod_init\n");

	cache_head.vc_next = &cache_tail;
	cache_head.vc_prev = NULL;
	cache_tail.vc_prev = &cache_head;
	cache_tail.vc_next = NULL;
	(void) mutex_init(&cache_lock, 0, NULL);

	if ((status = dladm_open(&dld_handle)) != DLADM_STATUS_OK) {
		rcm_log_message(RCM_WARNING,
		    "VNIC: mod_init failed: cannot open datalink handle: %s\n",
		    dladm_status2str(status, errmsg));
		return (NULL);
	}

	/* Return the ops vectors */
	return (&vnic_ops);
}

/*
 * rcm_mod_info() - Return a string describing this module.
 */
const char *
rcm_mod_info(void)
{
	rcm_log_message(RCM_TRACE1, "VNIC: mod_info\n");

	return ("VNIC module");
}

/*
 * rcm_mod_fini() - Destroy the network VNIC cache.
 */
int
rcm_mod_fini(void)
{
	rcm_log_message(RCM_TRACE1, "VNIC: mod_fini\n");

	/*
	 * Note that vnic_unregister() does not seem to be called anywhere,
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
 * vnic_register() - Make sure the cache is properly sync'ed, and its
 *		 registrations are in order.
 */
static int
vnic_register(rcm_handle_t *hd)
{
	rcm_log_message(RCM_TRACE1, "VNIC: register\n");

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
			    _("VNIC: failed to register %s\n"),
			    RCM_RESOURCE_LINK_NEW);
			return (RCM_FAILURE);
		} else {
			rcm_log_message(RCM_DEBUG, "VNIC: registered %s\n",
			    RCM_RESOURCE_LINK_NEW);
			events_registered++;
		}
	}

	return (RCM_SUCCESS);
}

/*
 * vnic_unregister() - Walk the cache, unregistering all the networks.
 */
static int
vnic_unregister(rcm_handle_t *hd)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "VNIC: unregister\n");

	/* Walk the cache, unregistering everything */
	(void) mutex_lock(&cache_lock);
	node = cache_head.vc_next;
	while (node != &cache_tail) {
		if (rcm_unregister_interest(hd, node->vc_resource, 0)
		    != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("VNIC: failed to unregister %s\n"),
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
			    _("VNIC: failed to unregister %s\n"),
			    RCM_RESOURCE_LINK_NEW);
			return (RCM_FAILURE);
		} else {
			rcm_log_message(RCM_DEBUG, "VNIC: unregistered %s\n",
			    RCM_RESOURCE_LINK_NEW);
			events_registered--;
		}
	}

	return (RCM_SUCCESS);
}

/*
 * vnic_offline() - Offline VNICs on a specific node.
 */
static int
vnic_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "VNIC: offline(%s)\n", rsrc);

	/* Lock the cache and lookup the resource */
	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_REFRESH);
	if (node == NULL) {
		/* should not happen because the resource is registered. */
		vnic_log_err(DATALINK_INVALID_LINKID, errorp,
		    "unrecognized resource");
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	/*
	 * Inform consumers (IP interfaces) of associated VNICs to be offlined
	 */
	if (vnic_consumer_offline(hd, node, errorp, flags, info) ==
	    RCM_SUCCESS) {
		rcm_log_message(RCM_DEBUG,
		    "VNIC: consumers agreed on offline\n");
	} else {
		vnic_log_err(node->vc_linkid, errorp,
		    "consumers failed to offline");
		(void) mutex_unlock(&cache_lock);
		return (RCM_FAILURE);
	}

	/* Check if it's a query */
	if (flags & RCM_QUERY) {
		rcm_log_message(RCM_TRACE1,
		    "VNIC: offline query succeeded(%s)\n", rsrc);
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	if (vnic_offline_vnic(node, VNIC_OFFLINED, CACHE_NODE_OFFLINED) !=
	    RCM_SUCCESS) {
		vnic_online_vnic(node);
		vnic_log_err(node->vc_linkid, errorp, "offline failed");
		(void) mutex_unlock(&cache_lock);
		return (RCM_FAILURE);
	}

	rcm_log_message(RCM_TRACE1, "VNIC: Offline succeeded(%s)\n", rsrc);
	(void) mutex_unlock(&cache_lock);
	return (RCM_SUCCESS);
}

/*
 * vnic_undo_offline() - Undo offline of a previously offlined node.
 */
/*ARGSUSED*/
static int
vnic_undo_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "VNIC: online(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (node == NULL) {
		vnic_log_err(DATALINK_INVALID_LINKID, errorp, "no such link");
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	/* Check if no attempt should be made to online the link here */
	if (!(node->vc_state & CACHE_NODE_OFFLINED)) {
		vnic_log_err(node->vc_linkid, errorp, "link not offlined");
		(void) mutex_unlock(&cache_lock);
		errno = ENOTSUP;
		return (RCM_SUCCESS);
	}

	vnic_online_vnic(node);

	/*
	 * Inform IP interfaces on associated VNICs to be onlined
	 */
	vnic_consumer_online(hd, node, errorp, flags, info);

	node->vc_state &= ~CACHE_NODE_OFFLINED;
	rcm_log_message(RCM_TRACE1, "VNIC: online succeeded(%s)\n", rsrc);
	(void) mutex_unlock(&cache_lock);
	return (RCM_SUCCESS);
}

static void
vnic_online_vnic(link_cache_t *node)
{
	dl_vnic_t *vnic;
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];

	/*
	 * Try to bring on all offlined VNICs
	 */
	for (vnic = node->vc_vnic; vnic != NULL; vnic = vnic->dlv_next) {
		if (!(vnic->dlv_flags & VNIC_OFFLINED))
			continue;

		if ((status = dladm_vnic_up(dld_handle, vnic->dlv_vnic_id, 0))
		    != DLADM_STATUS_OK) {
			/*
			 * Print a warning message and continue to online
			 * other VNICs.
			 */
			rcm_log_message(RCM_WARNING,
			    _("VNIC: VNIC online failed (%u): %s\n"),
			    vnic->dlv_vnic_id,
			    dladm_status2str(status, errmsg));
		} else {
			vnic->dlv_flags &= ~VNIC_OFFLINED;
		}
	}
}

static int
vnic_offline_vnic(link_cache_t *node, uint32_t flags, cache_node_state_t state)
{
	dl_vnic_t *vnic;
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];

	rcm_log_message(RCM_TRACE2, "VNIC: vnic_offline_vnic (%s %u %u)\n",
	    node->vc_resource, flags, state);

	/*
	 * Try to delete all explicit created VNIC
	 */
	for (vnic = node->vc_vnic; vnic != NULL; vnic = vnic->dlv_next) {

		if ((status = dladm_vnic_delete(dld_handle, vnic->dlv_vnic_id,
		    DLADM_OPT_ACTIVE)) != DLADM_STATUS_OK) {
			rcm_log_message(RCM_WARNING,
			    _("VNIC: VNIC offline failed (%u): %s\n"),
			    vnic->dlv_vnic_id,
			    dladm_status2str(status, errmsg));
			return (RCM_FAILURE);
		} else {
			rcm_log_message(RCM_TRACE1,
			    "VNIC: VNIC offline succeeded(%u)\n",
			    vnic->dlv_vnic_id);
			vnic->dlv_flags |= flags;
		}
	}

	node->vc_state |= state;
	return (RCM_SUCCESS);
}

/*
 * vnic_get_info() - Gather usage information for this resource.
 */
/*ARGSUSED*/
int
vnic_get_info(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **usagep, char **errorp, nvlist_t *props, rcm_info_t **info)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "VNIC: get_info(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_REFRESH);
	if (node == NULL) {
		rcm_log_message(RCM_INFO,
		    _("VNIC: get_info(%s) unrecognized resource\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	*usagep = vnic_usage(node);
	(void) mutex_unlock(&cache_lock);
	if (*usagep == NULL) {
		/* most likely malloc failure */
		rcm_log_message(RCM_ERROR,
		    _("VNIC: get_info(%s) malloc failure\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOMEM;
		return (RCM_FAILURE);
	}

	/* Set client/role properties */
	(void) nvlist_add_string(props, RCM_CLIENT_NAME, "VNIC");

	rcm_log_message(RCM_TRACE1, "VNIC: get_info(%s) info = %s\n",
	    rsrc, *usagep);
	return (RCM_SUCCESS);
}

/*
 * vnic_suspend() - Nothing to do, always okay
 */
/*ARGSUSED*/
static int
vnic_suspend(rcm_handle_t *hd, char *rsrc, id_t id, timespec_t *interval,
    uint_t flags, char **errorp, rcm_info_t **info)
{
	rcm_log_message(RCM_TRACE1, "VNIC: suspend(%s)\n", rsrc);
	return (RCM_SUCCESS);
}

/*
 * vnic_resume() - Nothing to do, always okay
 */
/*ARGSUSED*/
static int
vnic_resume(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	rcm_log_message(RCM_TRACE1, "VNIC: resume(%s)\n", rsrc);
	return (RCM_SUCCESS);
}

/*
 * vnic_consumer_remove()
 *
 *	Notify VNIC consumers to remove cache.
 */
static int
vnic_consumer_remove(rcm_handle_t *hd, link_cache_t *node, uint_t flags,
    rcm_info_t **info)
{
	dl_vnic_t *vnic = NULL;
	char rsrc[RCM_LINK_RESOURCE_MAX];
	int ret = RCM_SUCCESS;

	rcm_log_message(RCM_TRACE2, "VNIC: vnic_consumer_remove (%s)\n",
	    node->vc_resource);

	for (vnic = node->vc_vnic; vnic != NULL; vnic = vnic->dlv_next) {

		/*
		 * This will only be called when the offline operation
		 * succeeds, so the VNIC consumers must have been offlined
		 * at this point.
		 */
		assert(vnic->dlv_flags & VNIC_CONSUMER_OFFLINED);

		(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u",
		    RCM_LINK_PREFIX, vnic->dlv_vnic_id);

		ret = rcm_notify_remove(hd, rsrc, flags, info);
		if (ret != RCM_SUCCESS) {
			rcm_log_message(RCM_WARNING,
			    _("VNIC: notify remove failed (%s)\n"), rsrc);
			break;
		}
	}

	rcm_log_message(RCM_TRACE2, "VNIC: vnic_consumer_remove done\n");
	return (ret);
}

/*
 * vnic_remove() - remove a resource from cache
 */
/*ARGSUSED*/
static int
vnic_remove(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	link_cache_t *node;
	int rv;

	rcm_log_message(RCM_TRACE1, "VNIC: remove(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (node == NULL) {
		rcm_log_message(RCM_INFO,
		    _("VNIC: remove(%s) unrecognized resource\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	/* remove the cached entry for the resource */
	cache_remove(node);
	(void) mutex_unlock(&cache_lock);

	rv = vnic_consumer_remove(hd, node, flags, info);
	node_free(node);
	return (rv);
}

/*
 * vnic_notify_event - Project private implementation to receive new resource
 *		   events. It intercepts all new resource events. If the
 *		   new resource is a network resource, pass up a notify
 *		   for it too. The new resource need not be cached, since
 *		   it is done at register again.
 */
/*ARGSUSED*/
static int
vnic_notify_event(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, nvlist_t *nvl, rcm_info_t **info)
{
	nvpair_t	*nvp = NULL;
	datalink_id_t	linkid;
	uint64_t	id64;
	int		rv = RCM_SUCCESS;

	rcm_log_message(RCM_TRACE1, "VNIC: notify_event(%s)\n", rsrc);

	if (strcmp(rsrc, RCM_RESOURCE_LINK_NEW) != 0) {
		vnic_log_err(DATALINK_INVALID_LINKID, errorp,
		    "unrecognized event");
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	/* Update cache to reflect latest VNICs */
	if (cache_update(hd) < 0) {
		vnic_log_err(DATALINK_INVALID_LINKID, errorp,
		    "private Cache update failed");
		return (RCM_FAILURE);
	}

	/*
	 * Try best to recover all configuration.
	 */
	rcm_log_message(RCM_DEBUG, "VNIC: process_nvlist\n");
	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		if (strcmp(nvpair_name(nvp), RCM_NV_LINKID) != 0)
			continue;

		if (nvpair_value_uint64(nvp, &id64) != 0) {
			vnic_log_err(DATALINK_INVALID_LINKID, errorp,
			    "cannot get linkid");
			rv = RCM_FAILURE;
			continue;
		}

		linkid = (datalink_id_t)id64;
		if (vnic_configure(hd, linkid) != 0) {
			vnic_log_err(linkid, errorp, "configuring failed");
			rv = RCM_FAILURE;
			continue;
		}

		/* Notify all VNIC consumers */
		if (vnic_consumer_notify(hd, linkid, errorp, flags,
		    info) != 0) {
			vnic_log_err(linkid, errorp, "consumer notify failed");
			rv = RCM_FAILURE;
		}
	}

	rcm_log_message(RCM_TRACE1,
	    "VNIC: notify_event: link configuration complete\n");
	return (rv);
}

/*
 * vnic_usage - Determine the usage of a link.
 *	    The returned buffer is owned by caller, and the caller
 *	    must free it up when done.
 */
static char *
vnic_usage(link_cache_t *node)
{
	dl_vnic_t *vnic;
	int nvnic;
	char *buf;
	const char *fmt;
	char *sep;
	char errmsg[DLADM_STRSIZE];
	char name[MAXLINKNAMELEN];
	dladm_status_t status;
	size_t bufsz;

	rcm_log_message(RCM_TRACE2, "VNIC: usage(%s)\n", node->vc_resource);

	assert(MUTEX_HELD(&cache_lock));
	if ((status = dladm_datalink_id2info(dld_handle, node->vc_linkid, NULL,
	    NULL, NULL, name, sizeof (name))) != DLADM_STATUS_OK) {
		rcm_log_message(RCM_ERROR,
		    _("VNIC: usage(%s) get link name failure(%s)\n"),
		    node->vc_resource, dladm_status2str(status, errmsg));
		return (NULL);
	}

	if (node->vc_state & CACHE_NODE_OFFLINED)
		fmt = _("%1$s offlined");
	else
		fmt = _("%1$s VNICs: ");

	/* TRANSLATION_NOTE: separator used between VNIC linkids */
	sep = _(", ");

	nvnic = 0;
	for (vnic = node->vc_vnic; vnic != NULL; vnic = vnic->dlv_next)
		nvnic++;

	/* space for VNICs and separators, plus message */
	bufsz = nvnic * (MAXLINKNAMELEN + strlen(sep)) +
	    strlen(fmt) + MAXLINKNAMELEN + 1;
	if ((buf = malloc(bufsz)) == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("VNIC: usage(%s) malloc failure(%s)\n"),
		    node->vc_resource, strerror(errno));
		return (NULL);
	}
	(void) snprintf(buf, bufsz, fmt, name);

	if (node->vc_state & CACHE_NODE_OFFLINED) {
		/* Nothing else to do */
		rcm_log_message(RCM_TRACE2, "VNIC: usage (%s) info = %s\n",
		    node->vc_resource, buf);
		return (buf);
	}

	for (vnic = node->vc_vnic; vnic != NULL; vnic = vnic->dlv_next) {
		rcm_log_message(RCM_DEBUG, "VNIC:= %u\n", vnic->dlv_vnic_id);

		if ((status = dladm_datalink_id2info(dld_handle,
		    vnic->dlv_vnic_id, NULL, NULL, NULL, name, sizeof (name)))
		    != DLADM_STATUS_OK) {
			rcm_log_message(RCM_ERROR,
			    _("VNIC: usage(%s) get vnic %u name failure(%s)\n"),
			    node->vc_resource, vnic->dlv_vnic_id,
			    dladm_status2str(status, errmsg));
			free(buf);
			return (NULL);
		}

		(void) strlcat(buf, name, bufsz);
		if (vnic->dlv_next != NULL)
			(void) strlcat(buf, sep, bufsz);
	}

	rcm_log_message(RCM_TRACE2, "VNIC: usage (%s) info = %s\n",
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

	rcm_log_message(RCM_TRACE2, "VNIC: cache lookup(%s)\n", rsrc);

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
			    "VNIC: cache lookup succeeded(%s)\n", rsrc);
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
	dl_vnic_t *vnic, *next;

	if (node != NULL) {
		free(node->vc_resource);

		/* free the VNIC list */
		for (vnic = node->vc_vnic; vnic != NULL; vnic = next) {
			next = vnic->dlv_next;
			free(vnic);
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

typedef struct vnic_update_arg_s {
	rcm_handle_t	*hd;
	int		retval;
} vnic_update_arg_t;

/*
 * vnic_update() - Update physical interface properties
 */
static int
vnic_update(dladm_handle_t handle, datalink_id_t vnicid, void *arg)
{
	vnic_update_arg_t *vnic_update_argp = arg;
	rcm_handle_t *hd = vnic_update_argp->hd;
	link_cache_t *node;
	dl_vnic_t *vnic;
	char *rsrc;
	dladm_vnic_attr_t vnic_attr;
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];
	boolean_t newnode = B_FALSE;
	int ret = -1;

	rcm_log_message(RCM_TRACE2, "VNIC: vnic_update(%u)\n", vnicid);

	assert(MUTEX_HELD(&cache_lock));
	status = dladm_vnic_info(handle, vnicid, &vnic_attr, DLADM_OPT_ACTIVE);
	if (status != DLADM_STATUS_OK) {
		rcm_log_message(RCM_TRACE1,
		    "VNIC: vnic_update() cannot get vnic information for "
		    "%u(%s)\n", vnicid, dladm_status2str(status, errmsg));
		return (DLADM_WALK_CONTINUE);
	}

	if (vnic_attr.va_link_id == DATALINK_INVALID_LINKID) {
		/*
		 * Skip the etherstubs.
		 */
		rcm_log_message(RCM_TRACE1,
		    "VNIC: vnic_update(): skip the etherstub %u\n", vnicid);
		return (DLADM_WALK_CONTINUE);
	}

	rsrc = malloc(RCM_LINK_RESOURCE_MAX);
	if (rsrc == NULL) {
		rcm_log_message(RCM_ERROR, _("VNIC: malloc error(%s): %u\n"),
		    strerror(errno), vnicid);
		goto done;
	}

	(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u",
	    RCM_LINK_PREFIX, vnic_attr.va_link_id);

	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (node != NULL) {
		rcm_log_message(RCM_DEBUG,
		    "VNIC: %s already registered (vnicid:%d)\n",
		    rsrc, vnic_attr.va_vnic_id);
		free(rsrc);
	} else {
		rcm_log_message(RCM_DEBUG,
		    "VNIC: %s is a new resource (vnicid:%d)\n",
		    rsrc, vnic_attr.va_vnic_id);
		if ((node = calloc(1, sizeof (link_cache_t))) == NULL) {
			free(rsrc);
			rcm_log_message(RCM_ERROR, _("VNIC: calloc: %s\n"),
			    strerror(errno));
			goto done;
		}

		node->vc_resource = rsrc;
		node->vc_vnic = NULL;
		node->vc_linkid = vnic_attr.va_link_id;
		node->vc_state |= CACHE_NODE_NEW;
		newnode = B_TRUE;
	}

	for (vnic = node->vc_vnic; vnic != NULL; vnic = vnic->dlv_next) {
		if (vnic->dlv_vnic_id == vnicid) {
			vnic->dlv_flags &= ~VNIC_STALE;
			break;
		}
	}

	if (vnic == NULL) {
		if ((vnic = calloc(1, sizeof (dl_vnic_t))) == NULL) {
			rcm_log_message(RCM_ERROR, _("VNIC: malloc: %s\n"),
			    strerror(errno));
			if (newnode) {
				free(rsrc);
				free(node);
			}
			goto done;
		}
		vnic->dlv_vnic_id = vnicid;
		vnic->dlv_next = node->vc_vnic;
		vnic->dlv_prev = NULL;
		if (node->vc_vnic != NULL)
			node->vc_vnic->dlv_prev = vnic;
		node->vc_vnic = vnic;
	}

	node->vc_state &= ~CACHE_NODE_STALE;

	if (newnode)
		cache_insert(node);

	rcm_log_message(RCM_TRACE3, "VNIC: vnic_update: succeeded(%u)\n",
	    vnicid);
	ret = 0;
done:
	vnic_update_argp->retval = ret;
	return (ret == 0 ? DLADM_WALK_CONTINUE : DLADM_WALK_TERMINATE);
}

/*
 * vnic_update_all() - Determine all VNIC links in the system
 */
static int
vnic_update_all(rcm_handle_t *hd)
{
	vnic_update_arg_t arg = {NULL, 0};

	rcm_log_message(RCM_TRACE2, "VNIC: vnic_update_all\n");

	assert(MUTEX_HELD(&cache_lock));
	arg.hd = hd;
	(void) dladm_walk_datalink_id(vnic_update, dld_handle, &arg,
	    DATALINK_CLASS_VNIC, DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
	return (arg.retval);
}

/*
 * cache_update() - Update cache with latest interface info
 */
static int
cache_update(rcm_handle_t *hd)
{
	link_cache_t *node, *nnode;
	dl_vnic_t *vnic;
	int rv;

	rcm_log_message(RCM_TRACE2, "VNIC: cache_update\n");

	(void) mutex_lock(&cache_lock);

	/* first we walk the entire cache, marking each entry stale */
	node = cache_head.vc_next;
	for (; node != &cache_tail; node = node->vc_next) {
		node->vc_state |= CACHE_NODE_STALE;
		for (vnic = node->vc_vnic; vnic != NULL; vnic = vnic->dlv_next)
			vnic->dlv_flags |= VNIC_STALE;
	}

	rv = vnic_update_all(hd);

	/*
	 * Continue to delete all stale nodes from the cache even
	 * vnic_update_all() failed. Unregister link that are not offlined
	 * and still in cache
	 */
	for (node = cache_head.vc_next; node != &cache_tail; node = nnode) {
		dl_vnic_t *vnic, *next;

		for (vnic = node->vc_vnic; vnic != NULL; vnic = next) {
			next = vnic->dlv_next;

			/* clear stale VNICs */
			if (vnic->dlv_flags & VNIC_STALE) {
				if (vnic->dlv_prev != NULL)
					vnic->dlv_prev->dlv_next = next;
				else
					node->vc_vnic = next;

				if (next != NULL)
					next->dlv_prev = vnic->dlv_prev;
				free(vnic);
			}
		}

		nnode = node->vc_next;
		if (node->vc_state & CACHE_NODE_STALE) {
			(void) rcm_unregister_interest(hd, node->vc_resource,
			    0);
			rcm_log_message(RCM_DEBUG, "VNIC: unregistered %s\n",
			    node->vc_resource);
			assert(node->vc_vnic == NULL);
			cache_remove(node);
			node_free(node);
			continue;
		}

		if (!(node->vc_state & CACHE_NODE_NEW))
			continue;

		if (rcm_register_interest(hd, node->vc_resource, 0, NULL) !=
		    RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("VNIC: failed to register %s\n"),
			    node->vc_resource);
			rv = -1;
		} else {
			rcm_log_message(RCM_DEBUG, "VNIC: registered %s\n",
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

	rcm_log_message(RCM_TRACE2, "VNIC: cache_free\n");

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
 * vnic_log_err() - RCM error log wrapper
 */
static void
vnic_log_err(datalink_id_t linkid, char **errorp, char *errmsg)
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

		rcm_log_message(RCM_ERROR, _("VNIC: %s(%s)\n"), errmsg, rsrc);
		if ((status = dladm_datalink_id2info(dld_handle, linkid, NULL,
		    NULL, NULL, link, sizeof (link))) != DLADM_STATUS_OK) {
			rcm_log_message(RCM_WARNING,
			    _("VNIC: cannot get link name for (%s) %s\n"),
			    rsrc, dladm_status2str(status, errstr));
		}
	} else {
		rcm_log_message(RCM_ERROR, _("VNIC: %s\n"), errmsg);
	}

	errfmt = strlen(link) > 0 ? _("VNIC: %s(%s)") : _("VNIC: %s");
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
 * vnic_consumer_online()
 *
 *	Notify online to VNIC consumers.
 */
/* ARGSUSED */
static void
vnic_consumer_online(rcm_handle_t *hd, link_cache_t *node, char **errorp,
    uint_t flags, rcm_info_t **info)
{
	dl_vnic_t *vnic;
	char rsrc[RCM_LINK_RESOURCE_MAX];

	rcm_log_message(RCM_TRACE2, "VNIC: vnic_consumer_online (%s)\n",
	    node->vc_resource);

	for (vnic = node->vc_vnic; vnic != NULL; vnic = vnic->dlv_next) {
		if (!(vnic->dlv_flags & VNIC_CONSUMER_OFFLINED))
			continue;

		(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u",
		    RCM_LINK_PREFIX, vnic->dlv_vnic_id);

		if (rcm_notify_online(hd, rsrc, flags, info) == RCM_SUCCESS)
			vnic->dlv_flags &= ~VNIC_CONSUMER_OFFLINED;
	}

	rcm_log_message(RCM_TRACE2, "VNIC: vnic_consumer_online done\n");
}

/*
 * vnic_consumer_offline()
 *
 *	Offline VNIC consumers.
 */
static int
vnic_consumer_offline(rcm_handle_t *hd, link_cache_t *node, char **errorp,
    uint_t flags, rcm_info_t **info)
{
	dl_vnic_t *vnic;
	char rsrc[RCM_LINK_RESOURCE_MAX];
	int ret = RCM_SUCCESS;

	rcm_log_message(RCM_TRACE2, "VNIC: vnic_consumer_offline (%s)\n",
	    node->vc_resource);

	for (vnic = node->vc_vnic; vnic != NULL; vnic = vnic->dlv_next) {
		(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u",
		    RCM_LINK_PREFIX, vnic->dlv_vnic_id);

		ret = rcm_request_offline(hd, rsrc, flags, info);
		if (ret != RCM_SUCCESS)
			break;

		vnic->dlv_flags |= VNIC_CONSUMER_OFFLINED;
	}

	if (vnic != NULL)
		vnic_consumer_online(hd, node, errorp, flags, info);

	rcm_log_message(RCM_TRACE2, "VNIC: vnic_consumer_offline done\n");
	return (ret);
}

/*
 * Send RCM_RESOURCE_LINK_NEW events to other modules about new VNICs.
 * Return 0 on success, -1 on failure.
 */
static int
vnic_notify_new_vnic(rcm_handle_t *hd, char *rsrc)
{
	link_cache_t *node;
	dl_vnic_t *vnic;
	nvlist_t *nvl = NULL;
	uint64_t id;
	int ret = -1;

	rcm_log_message(RCM_TRACE2, "VNIC: vnic_notify_new_vnic (%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	if ((node = cache_lookup(hd, rsrc, CACHE_REFRESH)) == NULL) {
		(void) mutex_unlock(&cache_lock);
		return (0);
	}

	if (nvlist_alloc(&nvl, 0, 0) != 0) {
		(void) mutex_unlock(&cache_lock);
		rcm_log_message(RCM_WARNING,
		    _("VNIC: failed to allocate nvlist\n"));
		goto done;
	}

	for (vnic = node->vc_vnic; vnic != NULL; vnic = vnic->dlv_next) {
		rcm_log_message(RCM_TRACE2,
		    "VNIC: vnic_notify_new_vnic add (%u)\n", vnic->dlv_vnic_id);

		id = vnic->dlv_vnic_id;
		if (nvlist_add_uint64(nvl, RCM_NV_LINKID, id) != 0) {
			rcm_log_message(RCM_ERROR,
			    _("VNIC: failed to construct nvlist\n"));
			(void) mutex_unlock(&cache_lock);
			goto done;
		}
	}
	(void) mutex_unlock(&cache_lock);

	if (rcm_notify_event(hd, RCM_RESOURCE_LINK_NEW, 0, nvl, NULL) !=
	    RCM_SUCCESS) {
		rcm_log_message(RCM_ERROR,
		    _("VNIC: failed to notify %s event for %s\n"),
		    RCM_RESOURCE_LINK_NEW, node->vc_resource);
		goto done;
	}

	ret = 0;
done:
	nvlist_free(nvl);
	return (ret);
}

/*
 * vnic_consumer_notify() - Notify consumers of VNICs coming back online.
 */
static int
vnic_consumer_notify(rcm_handle_t *hd, datalink_id_t linkid, char **errorp,
    uint_t flags, rcm_info_t **info)
{
	char rsrc[RCM_LINK_RESOURCE_MAX];
	link_cache_t *node;

	/* Check for the interface in the cache */
	(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u", RCM_LINK_PREFIX,
	    linkid);

	rcm_log_message(RCM_TRACE2, "VNIC: vnic_consumer_notify(%s)\n", rsrc);

	/*
	 * Inform IP consumers of the new link.
	 */
	if (vnic_notify_new_vnic(hd, rsrc) != 0) {
		(void) mutex_lock(&cache_lock);
		if ((node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH)) != NULL) {
			(void) vnic_offline_vnic(node, VNIC_STALE,
			    CACHE_NODE_STALE);
		}
		(void) mutex_unlock(&cache_lock);
		rcm_log_message(RCM_TRACE2,
		    "VNIC: vnic_notify_new_vnic failed(%s)\n", rsrc);
		return (-1);
	}

	rcm_log_message(RCM_TRACE2, "VNIC: vnic_consumer_notify succeeded\n");
	return (0);
}

typedef struct vnic_up_arg_s {
	datalink_id_t	linkid;
	int		retval;
} vnic_up_arg_t;

static int
vnic_up(dladm_handle_t handle, datalink_id_t vnicid, void *arg)
{
	vnic_up_arg_t *vnic_up_argp = arg;
	dladm_status_t status;
	dladm_vnic_attr_t vnic_attr;
	char errmsg[DLADM_STRSIZE];

	status = dladm_vnic_info(handle, vnicid, &vnic_attr, DLADM_OPT_PERSIST);
	if (status != DLADM_STATUS_OK) {
		rcm_log_message(RCM_TRACE1,
		    "VNIC: vnic_up(): cannot get information for VNIC %u "
		    "(%s)\n", vnicid, dladm_status2str(status, errmsg));
		return (DLADM_WALK_CONTINUE);
	}

	if (vnic_attr.va_link_id != vnic_up_argp->linkid)
		return (DLADM_WALK_CONTINUE);

	rcm_log_message(RCM_TRACE3, "VNIC: vnic_up(%u)\n", vnicid);
	if ((status = dladm_vnic_up(handle, vnicid, 0)) == DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	/*
	 * Prompt the warning message and continue to UP other VNICs.
	 */
	rcm_log_message(RCM_WARNING,
	    _("VNIC: VNIC up failed (%u): %s\n"),
	    vnicid, dladm_status2str(status, errmsg));

	vnic_up_argp->retval = -1;
	return (DLADM_WALK_CONTINUE);
}

/*
 * vnic_configure() - Configure VNICs over a physical link after it attaches
 */
static int
vnic_configure(rcm_handle_t *hd, datalink_id_t linkid)
{
	char rsrc[RCM_LINK_RESOURCE_MAX];
	link_cache_t *node;
	vnic_up_arg_t arg = {DATALINK_INVALID_LINKID, 0};

	/* Check for the VNICs in the cache */
	(void) snprintf(rsrc, sizeof (rsrc), "%s/%u", RCM_LINK_PREFIX, linkid);

	rcm_log_message(RCM_TRACE2, "VNIC: vnic_configure(%s)\n", rsrc);

	/* Check if the link is new or was previously offlined */
	(void) mutex_lock(&cache_lock);
	if (((node = cache_lookup(hd, rsrc, CACHE_REFRESH)) != NULL) &&
	    (!(node->vc_state & CACHE_NODE_OFFLINED))) {
		rcm_log_message(RCM_TRACE2,
		    "VNIC: Skipping configured interface(%s)\n", rsrc);
		(void) mutex_unlock(&cache_lock);
		return (0);
	}
	(void) mutex_unlock(&cache_lock);

	arg.linkid = linkid;
	(void) dladm_walk_datalink_id(vnic_up, dld_handle, &arg,
	    DATALINK_CLASS_VNIC, DATALINK_ANY_MEDIATYPE, DLADM_OPT_PERSIST);

	if (arg.retval == 0) {
		rcm_log_message(RCM_TRACE2,
		    "VNIC: vnic_configure succeeded(%s)\n", rsrc);
	}
	return (arg.retval);
}
