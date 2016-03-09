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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This RCM module adds support to the RCM framework for IBPART links
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
#include <libdlib.h>
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

/* IBPART link flags */
typedef enum {
	IBPART_OFFLINED			= 0x1,
	IBPART_CONSUMER_OFFLINED	= 0x2,
	IBPART_STALE			= 0x4
} ibpart_flag_t;

/* link representation */
typedef struct dl_ibpart {
	struct dl_ibpart	*dlib_next;	/* next IBPART on this link */
	struct dl_ibpart	*dlib_prev;	/* prev IBPART on this link */
	datalink_id_t	dlib_ibpart_id;
	ibpart_flag_t	dlib_flags;		/* IBPART link flags */
} dl_ibpart_t;

/* IBPART Cache state flags */
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
	struct link_cache	*pc_next;	/* next cached resource */
	struct link_cache	*pc_prev;	/* prev cached resource */
	char			*pc_resource;	/* resource name */
	datalink_id_t		pc_linkid;	/* linkid */
	dl_ibpart_t		*pc_ibpart;	/* IBPART list on this link */
	cache_node_state_t	pc_state;	/* cache state flags */
} link_cache_t;

/*
 * Global cache for network IBPARTs
 */
static link_cache_t	cache_head;
static link_cache_t	cache_tail;
static mutex_t		cache_lock;
static int		events_registered = 0;

static dladm_handle_t	dld_handle = NULL;

/*
 * RCM module interface prototypes
 */
static int		ibpart_register(rcm_handle_t *);
static int		ibpart_unregister(rcm_handle_t *);
static int		ibpart_get_info(rcm_handle_t *, char *, id_t, uint_t,
			    char **, char **, nvlist_t *, rcm_info_t **);
static int		ibpart_suspend(rcm_handle_t *, char *, id_t,
			    timespec_t *, uint_t, char **, rcm_info_t **);
static int		ibpart_resume(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		ibpart_offline(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		ibpart_undo_offline(rcm_handle_t *, char *, id_t,
			    uint_t, char **, rcm_info_t **);
static int		ibpart_remove(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		ibpart_notify_event(rcm_handle_t *, char *, id_t,
			    uint_t, char **, nvlist_t *, rcm_info_t **);
static int		ibpart_configure(rcm_handle_t *, datalink_id_t);

/* Module private routines */
static void 		cache_free();
static int 		cache_update(rcm_handle_t *);
static void 		cache_remove(link_cache_t *);
static void 		node_free(link_cache_t *);
static void 		cache_insert(link_cache_t *);
static link_cache_t	*cache_lookup(rcm_handle_t *, char *, char);
static int		ibpart_consumer_offline(rcm_handle_t *, link_cache_t *,
			    char **, uint_t, rcm_info_t **);
static void		ibpart_consumer_online(rcm_handle_t *, link_cache_t *,
			    char **, uint_t, rcm_info_t **);
static int		ibpart_offline_ibpart(link_cache_t *, uint32_t,
			    cache_node_state_t);
static void		ibpart_online_ibpart(link_cache_t *);
static char 		*ibpart_usage(link_cache_t *);
static void 		ibpart_log_err(datalink_id_t, char **, char *);
static int		ibpart_consumer_notify(rcm_handle_t *, datalink_id_t,
			    char **, uint_t, rcm_info_t **);

/* Module-Private data */
static struct rcm_mod_ops ibpart_ops =
{
	RCM_MOD_OPS_VERSION,
	ibpart_register,
	ibpart_unregister,
	ibpart_get_info,
	ibpart_suspend,
	ibpart_resume,
	ibpart_offline,
	ibpart_undo_offline,
	ibpart_remove,
	NULL,
	NULL,
	ibpart_notify_event
};

/*
 * rcm_mod_init() - Update registrations, and return the ops structure.
 */
struct rcm_mod_ops *
rcm_mod_init(void)
{
	char errmsg[DLADM_STRSIZE];
	dladm_status_t status;

	rcm_log_message(RCM_TRACE1, "IBPART: mod_init\n");

	cache_head.pc_next = &cache_tail;
	cache_head.pc_prev = NULL;
	cache_tail.pc_prev = &cache_head;
	cache_tail.pc_next = NULL;
	(void) mutex_init(&cache_lock, 0, NULL);

	if ((status = dladm_open(&dld_handle)) != DLADM_STATUS_OK) {
		rcm_log_message(RCM_WARNING,
		    "IBPART: mod_init failed: cannot open datalink "
		    "handle: %s\n", dladm_status2str(status, errmsg));
		return (NULL);
	}

	/* Return the ops vectors */
	return (&ibpart_ops);
}

/*
 * rcm_mod_info() - Return a string describing this module.
 */
const char *
rcm_mod_info(void)
{
	rcm_log_message(RCM_TRACE1, "IBPART: mod_info\n");

	return ("IBPART module");
}

/*
 * rcm_mod_fini() - Destroy the network IBPART cache.
 */
int
rcm_mod_fini(void)
{
	rcm_log_message(RCM_TRACE1, "IBPART: mod_fini\n");

	/*
	 * Note that ibpart_unregister() does not seem to be called anywhere,
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
 * ibpart_register() - Make sure the cache is properly sync'ed, and its
 *		 registrations are in order.
 */
static int
ibpart_register(rcm_handle_t *hd)
{
	rcm_log_message(RCM_TRACE1, "IBPART: register\n");

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
			    _("IBPART: failed to register %s\n"),
			    RCM_RESOURCE_LINK_NEW);
			return (RCM_FAILURE);
		} else {
			rcm_log_message(RCM_DEBUG, "IBPART: registered %s\n",
			    RCM_RESOURCE_LINK_NEW);
			events_registered++;
		}
	}

	return (RCM_SUCCESS);
}

/*
 * ibpart_unregister() - Walk the cache, unregistering all the networks.
 */
static int
ibpart_unregister(rcm_handle_t *hd)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "IBPART: unregister\n");

	/* Walk the cache, unregistering everything */
	(void) mutex_lock(&cache_lock);
	node = cache_head.pc_next;
	while (node != &cache_tail) {
		if (rcm_unregister_interest(hd, node->pc_resource, 0)
		    != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("IBPART: failed to unregister %s\n"),
			    node->pc_resource);
			(void) mutex_unlock(&cache_lock);
			return (RCM_FAILURE);
		}
		cache_remove(node);
		node_free(node);
		node = cache_head.pc_next;
	}
	(void) mutex_unlock(&cache_lock);

	/*
	 * Unregister interest in all new resources
	 */
	if (events_registered) {
		if (rcm_unregister_event(hd, RCM_RESOURCE_LINK_NEW, 0)
		    != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("IBPART: failed to unregister %s\n"),
			    RCM_RESOURCE_LINK_NEW);
			return (RCM_FAILURE);
		} else {
			rcm_log_message(RCM_DEBUG, "IBPART: unregistered %s\n",
			    RCM_RESOURCE_LINK_NEW);
			events_registered--;
		}
	}

	return (RCM_SUCCESS);
}

/*
 * ibpart_offline() - Offline IBPARTs on a specific node.
 */
static int
ibpart_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "IBPART: offline(%s)\n", rsrc);

	/* Lock the cache and lookup the resource */
	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_REFRESH);
	if (node == NULL) {
		/* should not happen because the resource is registered. */
		ibpart_log_err(node->pc_linkid, errorp,
		    "unrecognized resource");
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	/*
	 * Inform consumers (IP interfaces) of associated IBPARTs to be offlined
	 */
	if (ibpart_consumer_offline(hd, node, errorp, flags, info) ==
	    RCM_SUCCESS) {
		rcm_log_message(RCM_DEBUG,
		    "IBPART: consumers agreed on offline\n");
	} else {
		ibpart_log_err(node->pc_linkid, errorp,
		    "consumers failed to offline");
		(void) mutex_unlock(&cache_lock);
		return (RCM_FAILURE);
	}

	/* Check if it's a query */
	if (flags & RCM_QUERY) {
		rcm_log_message(RCM_TRACE1,
		    "IBPART: offline query succeeded(%s)\n", rsrc);
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	if (ibpart_offline_ibpart(node, IBPART_OFFLINED, CACHE_NODE_OFFLINED) !=
	    RCM_SUCCESS) {
		ibpart_online_ibpart(node);
		ibpart_log_err(node->pc_linkid, errorp, "offline failed");
		(void) mutex_unlock(&cache_lock);
		return (RCM_FAILURE);
	}

	rcm_log_message(RCM_TRACE1, "IBPART: Offline succeeded(%s)\n", rsrc);
	(void) mutex_unlock(&cache_lock);
	return (RCM_SUCCESS);
}

/*
 * ibpart_undo_offline() - Undo offline of a previously offlined node.
 */
/*ARGSUSED*/
static int
ibpart_undo_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "IBPART: online(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (node == NULL) {
		ibpart_log_err(DATALINK_INVALID_LINKID, errorp, "no such link");
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	/* Check if no attempt should be made to online the link here */
	if (!(node->pc_state & CACHE_NODE_OFFLINED)) {
		ibpart_log_err(node->pc_linkid, errorp, "link not offlined");
		(void) mutex_unlock(&cache_lock);
		errno = ENOTSUP;
		return (RCM_SUCCESS);
	}

	ibpart_online_ibpart(node);

	/*
	 * Inform IP interfaces on associated IBPARTs to be onlined
	 */
	ibpart_consumer_online(hd, node, errorp, flags, info);

	node->pc_state &= ~CACHE_NODE_OFFLINED;
	rcm_log_message(RCM_TRACE1, "IBPART: online succeeded(%s)\n", rsrc);
	(void) mutex_unlock(&cache_lock);
	return (RCM_SUCCESS);
}

static void
ibpart_online_ibpart(link_cache_t *node)
{
	dl_ibpart_t *ibpart;
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];

	/*
	 * Try to bring on all offlined IBPARTs
	 */
	for (ibpart = node->pc_ibpart; ibpart != NULL;
	    ibpart = ibpart->dlib_next) {
		if (!(ibpart->dlib_flags & IBPART_OFFLINED))
			continue;

		rcm_log_message(RCM_TRACE1, "IBPART: online DLID %d\n",
		    ibpart->dlib_ibpart_id);
		if ((status = dladm_part_up(dld_handle,
		    ibpart->dlib_ibpart_id, 0)) != DLADM_STATUS_OK) {
			/*
			 * Print a warning message and continue to online
			 * other IBPARTs.
			 */
			rcm_log_message(RCM_WARNING,
			    _("IBPART: IBPART online failed (%u): %s\n"),
			    ibpart->dlib_ibpart_id,
			    dladm_status2str(status, errmsg));
		} else {
			ibpart->dlib_flags &= ~IBPART_OFFLINED;
		}
	}
}

static int
ibpart_offline_ibpart(link_cache_t *node, uint32_t flags,
    cache_node_state_t state)
{
	dl_ibpart_t *ibpart;
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];

	rcm_log_message(RCM_TRACE2, "IBPART: ibpart_offline_ibpart "
	    "(%s %u %u)\n", node->pc_resource, flags, state);

	/*
	 * Try to delete all explicit created IBPART
	 */
	for (ibpart = node->pc_ibpart; ibpart != NULL;
	    ibpart = ibpart->dlib_next) {
		rcm_log_message(RCM_TRACE1, "IBPART: offline DLID %d\n",
		    ibpart->dlib_ibpart_id);
		if ((status = dladm_part_delete(dld_handle,
		    ibpart->dlib_ibpart_id, DLADM_OPT_ACTIVE)) !=
		    DLADM_STATUS_OK) {
			rcm_log_message(RCM_WARNING,
			    _("IBPART: IBPART offline failed (%u): %s\n"),
			    ibpart->dlib_ibpart_id,
			    dladm_status2str(status, errmsg));
			return (RCM_FAILURE);
		} else {
			rcm_log_message(RCM_TRACE1,
			    "IBPART: IBPART offline succeeded(%u)\n",
			    ibpart->dlib_ibpart_id);
			ibpart->dlib_flags |= flags;
		}
	}

	node->pc_state |= state;
	return (RCM_SUCCESS);
}

/*
 * ibpart_get_info() - Gather usage information for this resource.
 */
/*ARGSUSED*/
int
ibpart_get_info(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **usagep, char **errorp, nvlist_t *props, rcm_info_t **info)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "IBPART: get_info(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_REFRESH);
	if (node == NULL) {
		rcm_log_message(RCM_INFO,
		    _("IBPART: get_info(%s) unrecognized resource\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	*usagep = ibpart_usage(node);
	(void) mutex_unlock(&cache_lock);
	if (*usagep == NULL) {
		/* most likely malloc failure */
		rcm_log_message(RCM_ERROR,
		    _("IBPART: get_info(%s) malloc failure\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOMEM;
		return (RCM_FAILURE);
	}

	/* Set client/role properties */
	(void) nvlist_add_string(props, RCM_CLIENT_NAME, "IBPART");

	rcm_log_message(RCM_TRACE1, "IBPART: get_info(%s) info = %s\n",
	    rsrc, *usagep);
	return (RCM_SUCCESS);
}

/*
 * ibpart_suspend() - Nothing to do, always okay
 */
/*ARGSUSED*/
static int
ibpart_suspend(rcm_handle_t *hd, char *rsrc, id_t id, timespec_t *interval,
    uint_t flags, char **errorp, rcm_info_t **info)
{
	rcm_log_message(RCM_TRACE1, "IBPART: suspend(%s)\n", rsrc);
	return (RCM_SUCCESS);
}

/*
 * ibpart_resume() - Nothing to do, always okay
 */
/*ARGSUSED*/
static int
ibpart_resume(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	rcm_log_message(RCM_TRACE1, "IBPART: resume(%s)\n", rsrc);
	return (RCM_SUCCESS);
}

/*
 * ibpart_consumer_remove()
 *
 *	Notify IBPART consumers to remove cache.
 */
static int
ibpart_consumer_remove(rcm_handle_t *hd, link_cache_t *node, uint_t flags,
    rcm_info_t **info)
{
	dl_ibpart_t *ibpart = NULL;
	char rsrc[RCM_LINK_RESOURCE_MAX];
	int ret = RCM_SUCCESS;

	rcm_log_message(RCM_TRACE2, "IBPART: ibpart_consumer_remove (%s)\n",
	    node->pc_resource);

	for (ibpart = node->pc_ibpart; ibpart != NULL;
	    ibpart = ibpart->dlib_next) {

		/*
		 * This will only be called when the offline operation
		 * succeeds, so the IBPART consumers must have been offlined
		 * at this point.
		 */
		assert(ibpart->dlib_flags & IBPART_CONSUMER_OFFLINED);

		(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u",
		    RCM_LINK_PREFIX, ibpart->dlib_ibpart_id);

		ret = rcm_notify_remove(hd, rsrc, flags, info);
		if (ret != RCM_SUCCESS) {
			rcm_log_message(RCM_WARNING,
			    _("IBPART: notify remove failed (%s)\n"), rsrc);
			break;
		}
	}

	rcm_log_message(RCM_TRACE2, "IBPART: ibpart_consumer_remove done\n");
	return (ret);
}

/*
 * ibpart_remove() - remove a resource from cache
 */
/*ARGSUSED*/
static int
ibpart_remove(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	link_cache_t *node;
	int rv;

	rcm_log_message(RCM_TRACE1, "IBPART: remove(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (node == NULL) {
		rcm_log_message(RCM_INFO,
		    _("IBPART: remove(%s) unrecognized resource\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	/* remove the cached entry for the resource */
	cache_remove(node);
	(void) mutex_unlock(&cache_lock);

	rv = ibpart_consumer_remove(hd, node, flags, info);
	node_free(node);
	return (rv);
}

/*
 * ibpart_notify_event - Project private implementation to receive new resource
 *		   events. It intercepts all new resource events. If the
 *		   new resource is a network resource, pass up a notify
 *		   for it too. The new resource need not be cached, since
 *		   it is done at register again.
 */
/*ARGSUSED*/
static int
ibpart_notify_event(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, nvlist_t *nvl, rcm_info_t **info)
{
	nvpair_t	*nvp = NULL;
	datalink_id_t	linkid;
	uint64_t	id64;
	int		rv = RCM_SUCCESS;

	rcm_log_message(RCM_TRACE1, "IBPART: notify_event(%s)\n", rsrc);

	if (strcmp(rsrc, RCM_RESOURCE_LINK_NEW) != 0) {
		ibpart_log_err(DATALINK_INVALID_LINKID, errorp,
		    "unrecognized event");
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	/* Update cache to reflect latest IBPARTs */
	if (cache_update(hd) < 0) {
		ibpart_log_err(DATALINK_INVALID_LINKID, errorp,
		    "private Cache update failed");
		return (RCM_FAILURE);
	}

	/*
	 * Try best to recover all configuration.
	 */
	rcm_log_message(RCM_DEBUG, "IBPART: process_nvlist\n");
	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		if (strcmp(nvpair_name(nvp), RCM_NV_LINKID) != 0)
			continue;

		if (nvpair_value_uint64(nvp, &id64) != 0) {
			ibpart_log_err(DATALINK_INVALID_LINKID, errorp,
			    "cannot get linkid");
			rv = RCM_FAILURE;
			continue;
		}

		linkid = (datalink_id_t)id64;
		if (ibpart_configure(hd, linkid) != 0) {
			ibpart_log_err(linkid, errorp, "configuring failed");
			rv = RCM_FAILURE;
			continue;
		}

		/* Notify all IBPART consumers */
		if (ibpart_consumer_notify(hd, linkid, errorp, flags,
		    info) != 0) {
			ibpart_log_err(linkid, errorp,
			    "consumer notify failed");
			rv = RCM_FAILURE;
		}
	}

	rcm_log_message(RCM_TRACE1,
	    "IBPART: notify_event: link configuration complete\n");
	return (rv);
}

/*
 * ibpart_usage - Determine the usage of a link.
 *	    The returned buffer is owned by caller, and the caller
 *	    must free it up when done.
 */
static char *
ibpart_usage(link_cache_t *node)
{
	dl_ibpart_t *ibpart;
	int nibpart;
	char *buf;
	const char *fmt;
	char *sep;
	char errmsg[DLADM_STRSIZE];
	char name[MAXLINKNAMELEN];
	dladm_status_t status;
	size_t bufsz;

	rcm_log_message(RCM_TRACE2, "IBPART: usage(%s)\n", node->pc_resource);

	assert(MUTEX_HELD(&cache_lock));
	if ((status = dladm_datalink_id2info(dld_handle, node->pc_linkid, NULL,
	    NULL, NULL, name, sizeof (name))) != DLADM_STATUS_OK) {
		rcm_log_message(RCM_ERROR,
		    _("IBPART: usage(%s) get link name failure(%s)\n"),
		    node->pc_resource, dladm_status2str(status, errmsg));
		return (NULL);
	}

	if (node->pc_state & CACHE_NODE_OFFLINED)
		fmt = _("%1$s offlined");
	else
		fmt = _("%1$s IBPART: ");

	/* TRANSLATION_NOTE: separator used between IBPART linkids */
	sep = _(", ");

	nibpart = 0;
	for (ibpart = node->pc_ibpart; ibpart != NULL;
	    ibpart = ibpart->dlib_next)
		nibpart++;

	/* space for IBPARTs and separators, plus message */
	bufsz = nibpart * (MAXLINKNAMELEN + strlen(sep)) +
	    strlen(fmt) + MAXLINKNAMELEN + 1;
	if ((buf = malloc(bufsz)) == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("IBPART: usage(%s) malloc failure(%s)\n"),
		    node->pc_resource, strerror(errno));
		return (NULL);
	}
	(void) snprintf(buf, bufsz, fmt, name);

	if (node->pc_state & CACHE_NODE_OFFLINED) {
		/* Nothing else to do */
		rcm_log_message(RCM_TRACE2, "IBPART: usage (%s) info = %s\n",
		    node->pc_resource, buf);
		return (buf);
	}

	for (ibpart = node->pc_ibpart; ibpart != NULL;
	    ibpart = ibpart->dlib_next) {
		rcm_log_message(RCM_DEBUG, "IBPART:= %u\n",
		    ibpart->dlib_ibpart_id);

		if ((status = dladm_datalink_id2info(dld_handle,
		    ibpart->dlib_ibpart_id, NULL, NULL, NULL, name,
		    sizeof (name))) != DLADM_STATUS_OK) {
			rcm_log_message(RCM_ERROR,
			    _("IBPART: usage(%s) get ibpart %u name "
			    "failure(%s)\n"), node->pc_resource,
			    ibpart->dlib_ibpart_id,
			    dladm_status2str(status, errmsg));
			free(buf);
			return (NULL);
		}

		(void) strlcat(buf, name, bufsz);
		if (ibpart->dlib_next != NULL)
			(void) strlcat(buf, sep, bufsz);
	}

	rcm_log_message(RCM_TRACE2, "IBPART: usage (%s) info = %s\n",
	    node->pc_resource, buf);

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

	rcm_log_message(RCM_TRACE2, "IBPART: cache lookup(%s)\n", rsrc);

	assert(MUTEX_HELD(&cache_lock));
	if (options & CACHE_REFRESH) {
		/* drop lock since update locks cache again */
		(void) mutex_unlock(&cache_lock);
		(void) cache_update(hd);
		(void) mutex_lock(&cache_lock);
	}

	node = cache_head.pc_next;
	for (; node != &cache_tail; node = node->pc_next) {
		if (strcmp(rsrc, node->pc_resource) == 0) {
			rcm_log_message(RCM_TRACE2,
			    "IBPART: cache lookup succeeded(%s)\n", rsrc);
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
	dl_ibpart_t *ibpart, *next;

	if (node != NULL) {
		free(node->pc_resource);

		/* free the IBPART list */
		for (ibpart = node->pc_ibpart; ibpart != NULL; ibpart = next) {
			next = ibpart->dlib_next;
			free(ibpart);
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
	node->pc_next = cache_head.pc_next;
	node->pc_prev = &cache_head;

	node->pc_next->pc_prev = node;
	node->pc_prev->pc_next = node;
}

/*
 * cache_remove() - Remove a resource node from cache.
 */
static void
cache_remove(link_cache_t *node)
{
	assert(MUTEX_HELD(&cache_lock));
	node->pc_next->pc_prev = node->pc_prev;
	node->pc_prev->pc_next = node->pc_next;
	node->pc_next = NULL;
	node->pc_prev = NULL;
}

typedef struct ibpart_update_arg_s {
	rcm_handle_t	*hd;
	int		retval;
} ibpart_update_arg_t;

/*
 * ibpart_update() - Update physical interface properties
 */
static int
ibpart_update(dladm_handle_t handle, datalink_id_t ibpartid, void *arg)
{
	ibpart_update_arg_t *ibpart_update_argp = arg;
	rcm_handle_t *hd = ibpart_update_argp->hd;
	link_cache_t *node;
	dl_ibpart_t *ibpart;
	char *rsrc;
	dladm_ib_attr_t ibpart_attr;
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];
	boolean_t newnode = B_FALSE;
	int ret = -1;

	rcm_log_message(RCM_TRACE2, "IBPART: ibpart_update(%u)\n", ibpartid);

	assert(MUTEX_HELD(&cache_lock));
	status = dladm_part_info(handle, ibpartid, &ibpart_attr,
	    DLADM_OPT_ACTIVE);
	if (status != DLADM_STATUS_OK) {
		rcm_log_message(RCM_TRACE1,
		    "IBPART: ibpart_update() cannot get ibpart information for "
		    "%u(%s)\n", ibpartid, dladm_status2str(status, errmsg));
		return (DLADM_WALK_CONTINUE);
	}

	if (ibpart_attr.dia_physlinkid == DATALINK_INVALID_LINKID) {
		/*
		 * Skip the IB port nodes.
		 */
		rcm_log_message(RCM_TRACE1,
		    "IBPART: ibpart_update(): skip the PORT nodes %u\n",
		    ibpartid);
		return (DLADM_WALK_CONTINUE);
	}

	rsrc = malloc(RCM_LINK_RESOURCE_MAX);
	if (rsrc == NULL) {
		rcm_log_message(RCM_ERROR, _("IBPART: malloc error(%s): %u\n"),
		    strerror(errno), ibpartid);
		goto done;
	}

	(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u",
	    RCM_LINK_PREFIX, ibpart_attr.dia_physlinkid);

	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (node != NULL) {
		rcm_log_message(RCM_DEBUG,
		    "IBPART: %s already registered (ibpartid:%d)\n",
		    rsrc, ibpart_attr.dia_partlinkid);
		free(rsrc);
	} else {
		rcm_log_message(RCM_DEBUG,
		    "IBPART: %s is a new resource (ibpartid:%d)\n",
		    rsrc, ibpart_attr.dia_partlinkid);
		if ((node = calloc(1, sizeof (link_cache_t))) == NULL) {
			free(rsrc);
			rcm_log_message(RCM_ERROR, _("IBPART: calloc: %s\n"),
			    strerror(errno));
			goto done;
		}

		node->pc_resource = rsrc;
		node->pc_ibpart = NULL;
		node->pc_linkid = ibpart_attr.dia_physlinkid;
		node->pc_state |= CACHE_NODE_NEW;
		newnode = B_TRUE;
	}

	for (ibpart = node->pc_ibpart; ibpart != NULL;
	    ibpart = ibpart->dlib_next) {
		if (ibpart->dlib_ibpart_id == ibpartid) {
			ibpart->dlib_flags &= ~IBPART_STALE;
			break;
		}
	}

	if (ibpart == NULL) {
		if ((ibpart = calloc(1, sizeof (dl_ibpart_t))) == NULL) {
			rcm_log_message(RCM_ERROR, _("IBPART: malloc: %s\n"),
			    strerror(errno));
			if (newnode) {
				free(rsrc);
				free(node);
			}
			goto done;
		}
		ibpart->dlib_ibpart_id = ibpartid;
		ibpart->dlib_next = node->pc_ibpart;
		ibpart->dlib_prev = NULL;
		if (node->pc_ibpart != NULL)
			node->pc_ibpart->dlib_prev = ibpart;
		node->pc_ibpart = ibpart;
	}

	node->pc_state &= ~CACHE_NODE_STALE;

	if (newnode)
		cache_insert(node);

	rcm_log_message(RCM_TRACE3, "IBPART: ibpart_update: succeeded(%u)\n",
	    ibpartid);
	ret = 0;
done:
	ibpart_update_argp->retval = ret;
	return (ret == 0 ? DLADM_WALK_CONTINUE : DLADM_WALK_TERMINATE);
}

/*
 * ibpart_update_all() - Determine all IBPART links in the system
 */
static int
ibpart_update_all(rcm_handle_t *hd)
{
	ibpart_update_arg_t arg = {NULL, 0};

	rcm_log_message(RCM_TRACE2, "IBPART: ibpart_update_all\n");

	assert(MUTEX_HELD(&cache_lock));
	arg.hd = hd;
	(void) dladm_walk_datalink_id(ibpart_update, dld_handle, &arg,
	    DATALINK_CLASS_PART, DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
	return (arg.retval);
}

/*
 * cache_update() - Update cache with latest interface info
 */
static int
cache_update(rcm_handle_t *hd)
{
	link_cache_t *node, *nnode;
	dl_ibpart_t *ibpart;
	int rv;

	rcm_log_message(RCM_TRACE2, "IBPART: cache_update\n");

	(void) mutex_lock(&cache_lock);

	/* first we walk the entire cache, marking each entry stale */
	node = cache_head.pc_next;
	for (; node != &cache_tail; node = node->pc_next) {
		node->pc_state |= CACHE_NODE_STALE;
		for (ibpart = node->pc_ibpart; ibpart != NULL;
		    ibpart = ibpart->dlib_next)
			ibpart->dlib_flags |= IBPART_STALE;
	}

	rv = ibpart_update_all(hd);

	/*
	 * Continue to delete all stale nodes from the cache even
	 * ibpart_update_all() failed. Unregister link that are not offlined
	 * and still in cache
	 */
	for (node = cache_head.pc_next; node != &cache_tail; node = nnode) {
		dl_ibpart_t *ibpart, *next;

		for (ibpart = node->pc_ibpart; ibpart != NULL; ibpart = next) {
			next = ibpart->dlib_next;

			/* clear stale IBPARTs */
			if (ibpart->dlib_flags & IBPART_STALE) {
				if (ibpart->dlib_prev != NULL)
					ibpart->dlib_prev->dlib_next = next;
				else
					node->pc_ibpart = next;

				if (next != NULL)
					next->dlib_prev = ibpart->dlib_prev;
				free(ibpart);
			}
		}

		nnode = node->pc_next;
		if (node->pc_state & CACHE_NODE_STALE) {
			(void) rcm_unregister_interest(hd, node->pc_resource,
			    0);
			rcm_log_message(RCM_DEBUG, "IBPART: unregistered %s\n",
			    node->pc_resource);
			assert(node->pc_ibpart == NULL);
			cache_remove(node);
			node_free(node);
			continue;
		}

		if (!(node->pc_state & CACHE_NODE_NEW))
			continue;

		if (rcm_register_interest(hd, node->pc_resource, 0, NULL) !=
		    RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("IBPART: failed to register %s\n"),
			    node->pc_resource);
			rv = -1;
		} else {
			rcm_log_message(RCM_DEBUG, "IBPART: registered %s\n",
			    node->pc_resource);
			node->pc_state &= ~CACHE_NODE_NEW;
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

	rcm_log_message(RCM_TRACE2, "IBPART: cache_free\n");

	(void) mutex_lock(&cache_lock);
	node = cache_head.pc_next;
	while (node != &cache_tail) {
		cache_remove(node);
		node_free(node);
		node = cache_head.pc_next;
	}
	(void) mutex_unlock(&cache_lock);
}

/*
 * ibpart_log_err() - RCM error log wrapper
 */
static void
ibpart_log_err(datalink_id_t linkid, char **errorp, char *errmsg)
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

		rcm_log_message(RCM_ERROR, _("IBPART: %s(%s)\n"), errmsg, rsrc);
		if ((status = dladm_datalink_id2info(dld_handle, linkid, NULL,
		    NULL, NULL, link, sizeof (link))) != DLADM_STATUS_OK) {
			rcm_log_message(RCM_WARNING,
			    _("IBPART: cannot get link name for (%s) %s\n"),
			    rsrc, dladm_status2str(status, errstr));
		}
	} else {
		rcm_log_message(RCM_ERROR, _("IBPART: %s\n"), errmsg);
	}

	errfmt = strlen(link) > 0 ? _("IBPART: %s(%s)") : _("IBPART: %s");
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
 * ibpart_consumer_online()
 *
 *	Notify online to IBPART consumers.
 */
/* ARGSUSED */
static void
ibpart_consumer_online(rcm_handle_t *hd, link_cache_t *node, char **errorp,
    uint_t flags, rcm_info_t **info)
{
	dl_ibpart_t *ibpart;
	char rsrc[RCM_LINK_RESOURCE_MAX];

	rcm_log_message(RCM_TRACE2, "IBPART: ibpart_consumer_online (%s)\n",
	    node->pc_resource);

	for (ibpart = node->pc_ibpart; ibpart != NULL;
	    ibpart = ibpart->dlib_next) {
		if (!(ibpart->dlib_flags & IBPART_CONSUMER_OFFLINED))
			continue;

		(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u",
		    RCM_LINK_PREFIX, ibpart->dlib_ibpart_id);

		if (rcm_notify_online(hd, rsrc, flags, info) == RCM_SUCCESS)
			ibpart->dlib_flags &= ~IBPART_CONSUMER_OFFLINED;
	}

	rcm_log_message(RCM_TRACE2, "IBPART: ibpart_consumer_online done\n");
}

/*
 * ibpart_consumer_offline()
 *
 *	Offline IBPART consumers.
 */
static int
ibpart_consumer_offline(rcm_handle_t *hd, link_cache_t *node, char **errorp,
    uint_t flags, rcm_info_t **info)
{
	dl_ibpart_t *ibpart;
	char rsrc[RCM_LINK_RESOURCE_MAX];
	int ret = RCM_SUCCESS;

	rcm_log_message(RCM_TRACE2, "IBPART: ibpart_consumer_offline (%s)\n",
	    node->pc_resource);

	for (ibpart = node->pc_ibpart; ibpart != NULL;
	    ibpart = ibpart->dlib_next) {
		(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u",
		    RCM_LINK_PREFIX, ibpart->dlib_ibpart_id);

		ret = rcm_request_offline(hd, rsrc, flags, info);
		if (ret != RCM_SUCCESS)
			break;

		ibpart->dlib_flags |= IBPART_CONSUMER_OFFLINED;
	}

	if (ibpart != NULL)
		ibpart_consumer_online(hd, node, errorp, flags, info);

	rcm_log_message(RCM_TRACE2, "IBPART: ibpart_consumer_offline done\n");
	return (ret);
}

/*
 * Send RCM_RESOURCE_LINK_NEW events to other modules about new IBPARTs.
 * Return 0 on success, -1 on failure.
 */
static int
ibpart_notify_new_ibpart(rcm_handle_t *hd, char *rsrc)
{
	link_cache_t *node;
	dl_ibpart_t *ibpart;
	nvlist_t *nvl = NULL;
	uint64_t id;
	int ret = -1;

	rcm_log_message(RCM_TRACE2, "IBPART: ibpart_notify_new_ibpart (%s)\n",
	    rsrc);

	(void) mutex_lock(&cache_lock);
	if ((node = cache_lookup(hd, rsrc, CACHE_REFRESH)) == NULL) {
		(void) mutex_unlock(&cache_lock);
		return (0);
	}

	if (nvlist_alloc(&nvl, 0, 0) != 0) {
		(void) mutex_unlock(&cache_lock);
		rcm_log_message(RCM_WARNING,
		    _("IBPART: failed to allocate nvlist\n"));
		goto done;
	}

	for (ibpart = node->pc_ibpart; ibpart != NULL;
	    ibpart = ibpart->dlib_next) {
		rcm_log_message(RCM_TRACE2, "IBPART: ibpart_notify_new_ibpart "
		    "add (%u)\n", ibpart->dlib_ibpart_id);

		id = ibpart->dlib_ibpart_id;
		if (nvlist_add_uint64(nvl, RCM_NV_LINKID, id) != 0) {
			rcm_log_message(RCM_ERROR,
			    _("IBPART: failed to construct nvlist\n"));
			(void) mutex_unlock(&cache_lock);
			goto done;
		}
	}
	(void) mutex_unlock(&cache_lock);

	if (rcm_notify_event(hd, RCM_RESOURCE_LINK_NEW, 0, nvl, NULL) !=
	    RCM_SUCCESS) {
		rcm_log_message(RCM_ERROR,
		    _("IBPART: failed to notify %s event for %s\n"),
		    RCM_RESOURCE_LINK_NEW, node->pc_resource);
		goto done;
	}

	ret = 0;
done:
	nvlist_free(nvl);
	return (ret);
}

/*
 * ibpart_consumer_notify() - Notify consumers of IBPARTs coming back online.
 */
static int
ibpart_consumer_notify(rcm_handle_t *hd, datalink_id_t linkid, char **errorp,
    uint_t flags, rcm_info_t **info)
{
	char rsrc[RCM_LINK_RESOURCE_MAX];
	link_cache_t *node;

	/* Check for the interface in the cache */
	(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u", RCM_LINK_PREFIX,
	    linkid);

	rcm_log_message(RCM_TRACE2, "IBPART: ibpart_consumer_notify(%s)\n",
	    rsrc);

	/*
	 * Inform IP consumers of the new link.
	 */
	if (ibpart_notify_new_ibpart(hd, rsrc) != 0) {
		(void) mutex_lock(&cache_lock);
		if ((node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH)) != NULL) {
			(void) ibpart_offline_ibpart(node, IBPART_STALE,
			    CACHE_NODE_STALE);
		}
		(void) mutex_unlock(&cache_lock);
		rcm_log_message(RCM_TRACE2,
		    "IBPART: ibpart_notify_new_ibpart failed(%s)\n", rsrc);
		return (-1);
	}

	rcm_log_message(RCM_TRACE2, "IBPART: ibpart_consumer_notify "
	    "succeeded\n");
	return (0);
}

typedef struct ibpart_up_arg_s {
	datalink_id_t	linkid;
	int		retval;
} ibpart_up_arg_t;

static int
ibpart_up(dladm_handle_t handle, datalink_id_t ibpartid, void *arg)
{
	ibpart_up_arg_t *ibpart_up_argp = arg;
	dladm_status_t status;
	dladm_ib_attr_t ibpart_attr;
	char errmsg[DLADM_STRSIZE];

	status = dladm_part_info(handle, ibpartid, &ibpart_attr,
	    DLADM_OPT_PERSIST);
	if (status != DLADM_STATUS_OK) {
		rcm_log_message(RCM_TRACE1,
		    "IBPART: ibpart_up(): cannot get information for IBPART %u "
		    "(%s)\n", ibpartid, dladm_status2str(status, errmsg));
		return (DLADM_WALK_CONTINUE);
	}

	if (ibpart_attr.dia_physlinkid != ibpart_up_argp->linkid)
		return (DLADM_WALK_CONTINUE);

	rcm_log_message(RCM_TRACE3, "IBPART: ibpart_up(%u)\n", ibpartid);
	if ((status = dladm_part_up(handle, ibpartid, 0)) == DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	/*
	 * Prompt the warning message and continue to UP other IBPARTs.
	 */
	rcm_log_message(RCM_WARNING,
	    _("IBPART: IBPART up failed (%u): %s\n"),
	    ibpartid, dladm_status2str(status, errmsg));

	ibpart_up_argp->retval = -1;
	return (DLADM_WALK_CONTINUE);
}

/*
 * ibpart_configure() - Configure IBPARTs over a physical link after it attaches
 */
static int
ibpart_configure(rcm_handle_t *hd, datalink_id_t linkid)
{
	char rsrc[RCM_LINK_RESOURCE_MAX];
	link_cache_t *node;
	ibpart_up_arg_t arg = {DATALINK_INVALID_LINKID, 0};

	/* Check for the IBPARTs in the cache */
	(void) snprintf(rsrc, sizeof (rsrc), "%s/%u", RCM_LINK_PREFIX, linkid);

	rcm_log_message(RCM_TRACE2, "IBPART: ibpart_configure(%s)\n", rsrc);

	/* Check if the link is new or was previously offlined */
	(void) mutex_lock(&cache_lock);
	if (((node = cache_lookup(hd, rsrc, CACHE_REFRESH)) != NULL) &&
	    (!(node->pc_state & CACHE_NODE_OFFLINED))) {
		rcm_log_message(RCM_TRACE2,
		    "IBPART: Skipping configured interface(%s)\n", rsrc);
		(void) mutex_unlock(&cache_lock);
		return (0);
	}
	(void) mutex_unlock(&cache_lock);

	arg.linkid = linkid;
	(void) dladm_walk_datalink_id(ibpart_up, dld_handle, &arg,
	    DATALINK_CLASS_PART, DATALINK_ANY_MEDIATYPE, DLADM_OPT_PERSIST);

	if (arg.retval == 0) {
		rcm_log_message(RCM_TRACE2,
		    "IBPART: ibpart_configure succeeded(%s)\n", rsrc);
	}
	return (arg.retval);
}
