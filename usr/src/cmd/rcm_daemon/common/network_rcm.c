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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This RCM module adds support to the RCM framework for an abstract
 * namespace for network devices (DLPI providers).
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
#include <net/if.h>
#include <libdllink.h>
#include "rcm_module.h"

/*
 * Definitions
 */
#ifndef	lint
#define	_(x)	gettext(x)
#else
#define	_(x)	x
#endif

#define	CACHE_STALE	1	/* flags */
#define	CACHE_NEW	2	/* flags */

/* devfsadm attach nvpair values */
#define	PROP_NV_DDI_NETWORK	"ddi_network"

/*
 * Global NIC list to be configured after DR-attach
 */
struct ni_list {
	struct ni_list *next;
	char dev[MAXNAMELEN];	/* device instance name (le0, ie0, etc.) */
};

static struct ni_list *nil_head = NULL;		/* Global new if list */
static mutex_t nil_lock;			/* NIC list lock */

/* operations */
#define	NET_OFFLINE	1
#define	NET_ONLINE	2
#define	NET_REMOVE	3
#define	NET_SUSPEND	4
#define	NET_RESUME	5

typedef struct net_cache
{
	char			*resource;
	datalink_id_t		linkid;
	int			flags;
	struct net_cache	*next;
	struct net_cache	*prev;
} net_cache_t;

static net_cache_t	cache_head;
static net_cache_t	cache_tail;
static mutex_t		cache_lock;
static int		events_registered = 0;

struct devfs_minor_data {
	int32_t minor_type;
	char *minor_name;
	char *minor_node_type;
};

/* module interface routines */
static int net_register(rcm_handle_t *);
static int net_unregister(rcm_handle_t *);
static int net_getinfo(rcm_handle_t *, char *, id_t, uint_t, char **,
    char **, nvlist_t *, rcm_info_t **);
static int net_suspend(rcm_handle_t *, char *, id_t, timespec_t *,
    uint_t, char **, rcm_info_t **);
static int net_resume(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int net_offline(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int net_online(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int net_remove(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int net_notify_event(rcm_handle_t *, char *, id_t, uint_t,
    char **, nvlist_t *, rcm_info_t **);

/* module private routines */
static void free_cache(void);
static void update_cache(rcm_handle_t *hd);
static int devfs_entry(di_node_t node, di_minor_t minor, void *arg);
static void cache_remove(net_cache_t *node);
static net_cache_t *cache_lookup(const char *resource);
static void free_node(net_cache_t *);
static void cache_insert(net_cache_t *);
static int notify_new_link(rcm_handle_t *, const char *);
static void process_minor(char *, int, struct devfs_minor_data *);
static int process_nvlist(rcm_handle_t *, nvlist_t *);

/*
 * Module-Private data
 */
static struct rcm_mod_ops net_ops = {
	RCM_MOD_OPS_VERSION,
	net_register,
	net_unregister,
	net_getinfo,
	net_suspend,
	net_resume,
	net_offline,
	net_online,
	net_remove,
	NULL,
	NULL,
	net_notify_event
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
rcm_mod_init(void)
{
	cache_head.next = &cache_tail;
	cache_head.prev = NULL;
	cache_tail.prev = &cache_head;
	cache_tail.next = NULL;
	(void) mutex_init(&cache_lock, NULL, NULL);

	/* Return the ops vectors */
	return (&net_ops);
}

/*
 * rcm_mod_info()
 *
 *	Return a string describing this module.
 */
const char *
rcm_mod_info(void)
{
	return ("Network namespace module 1.13");
}

/*
 * rcm_mod_fini()
 *
 *	Destroy the cache.
 */
int
rcm_mod_fini(void)
{
	free_cache();
	(void) mutex_destroy(&cache_lock);
	return (RCM_SUCCESS);
}

/*
 * net_register()
 *
 *	Make sure the cache is properly sync'ed, and its registrations
 *	are in order.
 *
 *	Locking: the cache is locked by update_cache, and is held
 *	throughout update_cache's execution because it reads and
 *	possibly modifies cache links continuously.
 */
static int
net_register(rcm_handle_t *hd)
{
	update_cache(hd);
	/*
	 * Need to register interest in all new resources
	 * getting attached, so we get attach event notifications
	 */
	if (!events_registered) {
		if (rcm_register_event(hd, RCM_RESOURCE_NETWORK_NEW, 0, NULL)
		    != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("NET: failed to register %s\n"),
			    RCM_RESOURCE_NETWORK_NEW);
			return (RCM_FAILURE);
		} else {
			rcm_log_message(RCM_DEBUG, _("NET: registered %s\n"),
			    RCM_RESOURCE_NETWORK_NEW);
			events_registered++;
		}
	}

	return (RCM_SUCCESS);
}

/*
 * net_unregister()
 *
 *	Manually walk through the cache, unregistering all the networks.
 *
 *	Locking: the cache is locked throughout the execution of this routine
 *	because it reads and modifies cache links continuously.
 */
static int
net_unregister(rcm_handle_t *hd)
{
	net_cache_t *probe;

	assert(hd != NULL);

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

	/*
	 * Need to unregister interest in all new resources
	 */
	if (events_registered) {
		if (rcm_unregister_event(hd, RCM_RESOURCE_NETWORK_NEW, 0)
		    != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("NET: failed to unregister %s\n"),
			    RCM_RESOURCE_NETWORK_NEW);
			return (RCM_FAILURE);
		} else {
			rcm_log_message(RCM_DEBUG, _("NET: unregistered %s\n"),
			    RCM_RESOURCE_NETWORK_NEW);
			events_registered--;
		}
	}

	return (RCM_SUCCESS);
}

/*
 * Since all we do is pass operations thru, we provide a general
 * routine for passing through operations.
 */
/*ARGSUSED*/
static int
net_passthru(rcm_handle_t *hd, int op, const char *rsrc, uint_t flag,
    char **reason, rcm_info_t **dependent_reason, void *arg)
{
	net_cache_t	*node;
	char		*exported;
	datalink_id_t	linkid;
	int		len;
	int		rv;

	/*
	 * Lock the cache just long enough to extract information about this
	 * resource.
	 */
	(void) mutex_lock(&cache_lock);
	node = cache_lookup(rsrc);
	if (!node) {
		rcm_log_message(RCM_WARNING,
		    _("NET: unrecognized resource %s\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	/*
	 * Since node could be freed after we drop cache_lock, allocate a
	 * stack-local copy. We don't use malloc() because some of the
	 * operations (such as NET_REMOVE) are not allowed to fail. Note
	 * that exported is never more than MAXPATHLEN bytes.
	 */
	len = strlen("SUNW_datalink/") + LINKID_STR_WIDTH + 1;
	exported = alloca(len);
	linkid = node->linkid;
	(void) snprintf(exported, len, "SUNW_datalink/%u", linkid);

	/*
	 * Remove notifications are unconditional in the RCM state model,
	 * so it's safe to remove the node from the cache at this point.
	 * And we need to remove it so that we will recognize it as a new
	 * resource following the reattachment of the resource.
	 */
	if (op == NET_REMOVE) {
		cache_remove(node);
		free_node(node);
	}
	(void) mutex_unlock(&cache_lock);

	switch (op) {
	case NET_SUSPEND:
		rv = rcm_request_suspend(hd, exported, flag,
		    (timespec_t *)arg, dependent_reason);
		break;
	case NET_OFFLINE:
		rv = rcm_request_offline(hd, exported, flag, dependent_reason);
		break;
	case NET_ONLINE:
		rv = rcm_notify_online(hd, exported, flag, dependent_reason);
		break;
	case NET_REMOVE:
		rv = rcm_notify_remove(hd, exported, flag, dependent_reason);
		if (rv == RCM_SUCCESS) {
			rcm_log_message(RCM_DEBUG,
			    _("NET: mark link %d as removed\n"), linkid);

			/*
			 * Delete active linkprop before this active link
			 * is deleted.
			 */
			(void) dladm_set_linkprop(linkid, NULL, NULL, 0,
			    DLADM_OPT_ACTIVE);
			(void) dladm_destroy_datalink_id(linkid,
			    DLADM_OPT_ACTIVE);
		}
		break;
	case NET_RESUME:
		rv = rcm_notify_resume(hd, exported, flag, dependent_reason);
		break;
	default:
		rcm_log_message(RCM_WARNING,
		    _("NET: bad RCM operation %1$d for %2$s\n"), op, exported);
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	if (rv != RCM_SUCCESS) {
		char format[256];
		(void) snprintf(format, sizeof (format),
		    _("RCM operation on dependent %s did not succeed"),
		    exported);
		rcm_log_message(RCM_WARNING, "NET: %s\n", format);
	}
	return (rv);
}


/*
 * net_offline()
 *
 *	Determine dependents of the resource being offlined, and offline
 *	them all.
 */
static int
net_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **reason, rcm_info_t **dependent_reason)
{
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(reason != NULL);
	assert(dependent_reason != NULL);

	rcm_log_message(RCM_TRACE1, _("NET: offline(%s)\n"), rsrc);

	return (net_passthru(hd, NET_OFFLINE, rsrc, flags, reason,
	    dependent_reason, NULL));
}

/*
 * net_online()
 *
 *	Online the previously offlined resource, and online its dependents.
 */
static int
net_online(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flag, char **reason,
    rcm_info_t **dependent_reason)
{
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);

	rcm_log_message(RCM_TRACE1, _("NET: online(%s)\n"), rsrc);

	return (net_passthru(hd, NET_ONLINE, rsrc, flag, reason,
	    dependent_reason, NULL));
}

/*
 * net_getinfo()
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
net_getinfo(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flag,
    char **info, char **errstr, nvlist_t *proplist, rcm_info_t **depend_info)
{
	int		len;
	dladm_status_t	status;
	char		link[MAXLINKNAMELEN];
	char		errmsg[DLADM_STRSIZE];
	char		*exported;
	const char	*info_fmt;
	net_cache_t	*node;

	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(info != NULL);
	assert(depend_info != NULL);

	rcm_log_message(RCM_TRACE1, _("NET: getinfo(%s)\n"), rsrc);

	info_fmt = _("Network interface %s");

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(rsrc);
	if (!node) {
		rcm_log_message(RCM_WARNING,
		    _("NET: unrecognized resource %s\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	len = strlen(info_fmt) + MAXLINKNAMELEN + 1;
	if ((status = dladm_datalink_id2info(node->linkid, NULL, NULL, NULL,
	    link, sizeof (link))) != DLADM_STATUS_OK) {
		rcm_log_message(RCM_ERROR,
		    _("NET: usage(%s) get link name failure(%s)\n"),
		    node->resource, dladm_status2str(status, errmsg));
		(void) mutex_unlock(&cache_lock);
		return (RCM_FAILURE);
	} else if ((*info = (char *)malloc(len)) == NULL) {
		rcm_log_message(RCM_ERROR, _("NET: malloc failure"));
		(void) mutex_unlock(&cache_lock);
		return (RCM_FAILURE);
	}

	/* Fill in the string */
	(void) snprintf(*info, len, info_fmt, link);

	len = strlen("SUNW_datalink/") + LINKID_STR_WIDTH + 1;
	exported = malloc(len);
	if (!exported) {
		rcm_log_message(RCM_ERROR, _("NET: allocation failure"));
		free(*info);
		(void) mutex_unlock(&cache_lock);
		return (RCM_FAILURE);
	}
	(void) snprintf(exported, len, "SUNW_datalink/%u", node->linkid);
	(void) mutex_unlock(&cache_lock);

	/* Get dependent info if requested */
	if ((flag & RCM_INCLUDE_DEPENDENT) || (flag & RCM_INCLUDE_SUBTREE)) {
		(void) rcm_get_info(hd, exported, flag, depend_info);
	}

	(void) nvlist_add_string(proplist, RCM_CLIENT_NAME, "SunOS");
	(void) nvlist_add_string_array(proplist, RCM_CLIENT_EXPORTS,
	    &exported, 1);

	free(exported);
	return (RCM_SUCCESS);
}

/*
 * net_suspend()
 *
 *	Notify all dependents that the resource is being suspended.
 *	Since no real operation is involved, QUERY or not doesn't matter.
 *
 *	Locking: the cache is only used to retrieve some information about
 *	this resource, so it is only locked during that retrieval.
 */
static int
net_suspend(rcm_handle_t *hd, char *rsrc, id_t id, timespec_t *interval,
    uint_t flag, char **reason, rcm_info_t **dependent_reason)
{
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(interval != NULL);
	assert(reason != NULL);
	assert(dependent_reason != NULL);

	rcm_log_message(RCM_TRACE1, _("NET: suspend(%s)\n"), rsrc);

	return (net_passthru(hd, NET_SUSPEND, rsrc, flag, reason,
	    dependent_reason, (void *)interval));
}

/*
 * net_resume()
 *
 *	Resume all the dependents of a suspended network.
 *
 *	Locking: the cache is only used to retrieve some information about
 *	this resource, so it is only locked during that retrieval.
 */
static int
net_resume(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flag, char **info,
    rcm_info_t **dependent_info)
{
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(info != NULL);
	assert(dependent_info != NULL);

	rcm_log_message(RCM_TRACE1, _("NET: resume(%s)\n"), rsrc);

	return (net_passthru(hd, NET_RESUME, rsrc, flag, info, dependent_info,
	    NULL));
}

/*
 * net_remove()
 *
 *	This is another NO-OP for us, we just passthru the information.  We
 *	don't need to remove it from our cache.  We don't unregister
 *	interest at this point either; the network device name is still
 *	around.  This way we don't have to change this logic when we
 *	gain the ability to learn about DR attach operations.
 */
static int
net_remove(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flag, char **info,
    rcm_info_t **dependent_info)
{
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(info != NULL);
	assert(dependent_info != NULL);

	rcm_log_message(RCM_TRACE1, _("NET: remove(%s)\n"), rsrc);

	return (net_passthru(hd, NET_REMOVE, rsrc, flag, info, dependent_info,
	    NULL));
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
static net_cache_t *
cache_lookup(const char *resource)
{
	net_cache_t *probe;
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
free_node(net_cache_t *node)
{
	if (node) {
		free(node->resource);
		free(node);
	}
}

/*
 * cache_insert()
 *
 * Call with the cache_lock held.
 */
static void
cache_insert(net_cache_t *node)
{
	/* insert at the head for best performance */
	node->next = cache_head.next;
	node->prev = &cache_head;

	node->next->prev = node;
	node->prev->next = node;
}

/*
 * cache_remove()
 *
 * Call with the cache_lock held.
 */
static void
cache_remove(net_cache_t *node)
{
	node->next->prev = node->prev;
	node->prev->next = node->next;
	node->next = NULL;
	node->prev = NULL;
}

/*
 * devfs_entry()
 *
 * Call with the cache_lock held.
 */
/*ARGSUSED*/
static int
devfs_entry(di_node_t node, di_minor_t minor, void *arg)
{
	char		*devfspath;
	char		resource[MAXPATHLEN];
	char		dev[MAXNAMELEN];
	datalink_id_t	linkid;
	char		*drv;
	char		*cp;
	net_cache_t	*probe;

	cp = di_minor_nodetype(minor);
	if ((cp == NULL) || (strcmp(cp, DDI_NT_NET))) {
		/* doesn't look like a network device */
		return (DI_WALK_CONTINUE);
	}

	drv = di_driver_name(node);
	if (drv == NULL) {
		/* what else can we do? */
		return (DI_WALK_CONTINUE);
	}

	devfspath = di_devfs_path(node);
	if (!devfspath) {
		/* no devfs path?!? */
		rcm_log_message(RCM_DEBUG, _("NET: missing devfs path\n"));
		return (DI_WALK_CONTINUE);
	}

	if (strncmp("/pseudo", devfspath, strlen("/pseudo")) == 0) {
		/* ignore pseudo devices, probably not really NICs */
		rcm_log_message(RCM_DEBUG,
		    _("NET: ignoring pseudo device %s\n"), devfspath);
		di_devfs_path_free(devfspath);
		return (DI_WALK_CONTINUE);
	}

	(void) snprintf(resource, sizeof (resource), "/devices%s", devfspath);
	di_devfs_path_free(devfspath);

	(void) snprintf(dev, sizeof (dev), "%s%d", drv, di_instance(node));
	if (dladm_dev2linkid(dev, &linkid) != DLADM_STATUS_OK) {
		rcm_log_message(RCM_DEBUG,
		    _("NET: failed to find the linkid for %s\n"), dev);
		return (DI_WALK_CONTINUE);
	}

	probe = cache_lookup(resource);
	if (probe != NULL) {
		rcm_log_message(RCM_DEBUG,
		    _("NET: %s already registered (linkid %u)\n"),
		    resource, linkid);
		probe->linkid = linkid;
		probe->flags &= ~(CACHE_STALE);
	} else {
		rcm_log_message(RCM_DEBUG,
		    _("NET: %s is new resource (linkid %u)\n"),
		    resource, linkid);
		probe = calloc(1, sizeof (net_cache_t));
		if (!probe) {
			rcm_log_message(RCM_ERROR, _("NET: malloc failure"));
			return (DI_WALK_CONTINUE);
		}

		probe->resource = strdup(resource);
		probe->linkid = linkid;

		if (!probe->resource) {
			free_node(probe);
			return (DI_WALK_CONTINUE);
		}

		probe->flags |= CACHE_NEW;
		cache_insert(probe);
	}

	return (DI_WALK_CONTINUE);
}

/*
 * update_cache()
 *
 * The devinfo tree walking code is lifted from ifconfig.c.
 */
static void
update_cache(rcm_handle_t *hd)
{
	net_cache_t	*probe;
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

	(void) di_walk_minor(root, DDI_NT_NET, DI_CHECK_ALIAS, NULL,
	    devfs_entry);

	di_fini(root);

	probe = cache_head.next;
	while (probe != &cache_tail) {
		net_cache_t *freeit;
		if (probe->flags & CACHE_STALE) {
			(void) rcm_unregister_interest(hd, probe->resource, 0);
			rcm_log_message(RCM_DEBUG, _("NET: unregistered %s\n"),
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

		rcm_log_message(RCM_DEBUG, _("NET: registering %s\n"),
		    probe->resource);
		rv = rcm_register_interest(hd, probe->resource, 0, NULL);
		if (rv != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("NET: failed to register %s\n"),
			    probe->resource);
		} else {
			rcm_log_message(RCM_DEBUG,
			    _("NET: registered %s as SUNW_datalink/%u\n"),
			    probe->resource, probe->linkid);
			probe->flags &= ~(CACHE_NEW);
		}
		probe = probe->next;
	}

done:
	(void) mutex_unlock(&cache_lock);
}

/*
 * free_cache()
 */
static void
free_cache(void)
{
	net_cache_t *probe;

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
 * net_notify_event - Project private implementation to receive new
 *			resource events. It intercepts all new resource
 *			events. If the new resource is a network resource,
 *			pass up a event for the resource. The new resource
 *			need not be cached, since it is done at register again.
 */
/*ARGSUSED*/
static int
net_notify_event(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, nvlist_t *nvl, rcm_info_t **depend_info)
{
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(nvl != NULL);

	rcm_log_message(RCM_TRACE1, _("NET: notify_event(%s)\n"), rsrc);

	if (strcmp(rsrc, RCM_RESOURCE_NETWORK_NEW) != 0) {
		rcm_log_message(RCM_INFO,
		    _("NET: unrecognized event for %s\n"), rsrc);
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	/* Update cache to reflect latest physical links */
	update_cache(hd);

	/* Process the nvlist for the event */
	if (process_nvlist(hd, nvl) != 0) {
		rcm_log_message(RCM_WARNING,
		    _("NET: Error processing resource attributes(%s)\n"), rsrc);
		rcm_log_message(RCM_WARNING,
		    _("NET: One or more devices may not be configured.\n"));
	}

	rcm_log_message(RCM_TRACE1,
	    _("NET: notify_event: device configuration complete\n"));

	return (RCM_SUCCESS);
}

/*
 * process_nvlist() - Determine network interfaces on a new attach by
 *		      processing the nvlist
 */
static int
process_nvlist(rcm_handle_t *hd, nvlist_t *nvl)
{
	nvpair_t *nvp = NULL;
	char *driver;
	char *devfspath;
	int32_t instance;
	char *minor_byte_array; /* packed nvlist of minor_data */
	uint_t nminor;		  /* # of minor nodes */
	struct devfs_minor_data *mdata;
	nvlist_t *mnvl;
	nvpair_t *mnvp = NULL;
	struct ni_list *nilp, *next;

	rcm_log_message(RCM_TRACE1, "NET: process_nvlist\n");

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		/* Get driver name */
		if (strcmp(nvpair_name(nvp), RCM_NV_DRIVER_NAME) == 0) {
			if (nvpair_value_string(nvp, &driver) != 0) {
				rcm_log_message(RCM_WARNING,
				    _("NET: cannot get driver name\n"));
				return (-1);
			}
		}
		/* Get instance */
		if (strcmp(nvpair_name(nvp), RCM_NV_INSTANCE) == 0) {
			if (nvpair_value_int32(nvp, &instance) != 0) {
				rcm_log_message(RCM_WARNING,
				    _("NET: cannot get device instance\n"));
				return (-1);
			}
		}
		/* Get devfspath */
		if (strcmp(nvpair_name(nvp), RCM_NV_DEVFS_PATH) == 0) {
			if (nvpair_value_string(nvp, &devfspath) != 0) {
				rcm_log_message(RCM_WARNING,
				    _("NET: cannot get device path\n"));
				return (-1);
			}
			if (strncmp("/pseudo", devfspath,
			    strlen("/pseudo")) == 0) {
				/* Ignore pseudo devices, not really NICs */
				rcm_log_message(RCM_DEBUG,
				    _("NET: ignoring pseudo device %s\n"),
				    devfspath);
				return (0);
			}
		}

		/* Get minor data */
		if (strcmp(nvpair_name(nvp), RCM_NV_MINOR_DATA) == 0) {
			if (nvpair_value_byte_array(nvp,
			    (uchar_t **)&minor_byte_array, &nminor) != 0) {
				rcm_log_message(RCM_WARNING,
				    _("NET: cannot get device minor data\n"));
				return (-1);
			}
			if (nvlist_unpack(minor_byte_array,
			    nminor, &mnvl, 0) != 0) {
				rcm_log_message(RCM_WARNING,
				    _("NET: cannot get minor node data\n"));
				return (-1);
			}
			mdata = (struct devfs_minor_data *)calloc(1,
			    sizeof (struct devfs_minor_data));
			if (mdata == NULL) {
				rcm_log_message(RCM_WARNING,
				    _("NET: calloc error(%s)\n"),
				    strerror(errno));
				nvlist_free(mnvl);
				return (-1);
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
						    _("NET: cannot get minor "
						    "type \n"));
						nvlist_free(mnvl);
						return (-1);
					}
				}
				/* Get minor name */
				if (strcmp(nvpair_name(mnvp),
				    RCM_NV_MINOR_NAME) == 0) {
					if (nvpair_value_string(mnvp,
					    &mdata->minor_name) != 0) {
						rcm_log_message(RCM_WARNING,
						    _("NET: cannot get minor "
						    "name \n"));
						nvlist_free(mnvl);
						return (-1);
					}
				}
				/* Get minor node type */
				if (strcmp(nvpair_name(mnvp),
				    RCM_NV_MINOR_NODE_TYPE) == 0) {
					if (nvpair_value_string(mnvp,
					    &mdata->minor_node_type) != 0) {
						rcm_log_message(RCM_WARNING,
						    _("NET: cannot get minor "
						    "node type \n"));
						nvlist_free(mnvl);
						return (-1);
					}
				}
			}
			(void) process_minor(driver, instance, mdata);
			nvlist_free(mnvl);
		}
	}

	(void) mutex_lock(&nil_lock);

	/* Notify the event for all new devices found, then clean up the list */
	for (nilp = nil_head; nilp != NULL; nilp = next) {
		if (notify_new_link(hd, nilp->dev) != 0) {
			rcm_log_message(RCM_ERROR,
			    _(": Notify %s event failed (%s)\n"),
			    RCM_RESOURCE_LINK_NEW, nilp->dev);
		}
		next = nilp->next;
		free(nilp);
	}
	nil_head = NULL;

	(void) mutex_unlock(&nil_lock);

	rcm_log_message(RCM_TRACE1, _("NET: process_nvlist success\n"));
	return (0);
}

static void
process_minor(char *name, int instance, struct devfs_minor_data *mdata)
{
	char dev[MAXNAMELEN];
	struct ni_list **pp;
	struct ni_list *p;

	rcm_log_message(RCM_TRACE1, _("NET: process_minor %s%d\n"),
	    name, instance);

	if ((mdata->minor_node_type != NULL) &&
	    strcmp(mdata->minor_node_type, PROP_NV_DDI_NETWORK) != 0) {
		/* Process network devices only */
		return;
	}

	(void) snprintf(dev, sizeof (dev), "%s%d", name, instance);

	/* Add new interface to the list */
	(void) mutex_lock(&nil_lock);
	for (pp = &nil_head; (p = *pp) != NULL; pp = &(p->next)) {
		if (strcmp(dev, p->dev) == 0)
			break;
	}
	if (p != NULL) {
		rcm_log_message(RCM_TRACE1,
		    _("NET: secondary node - ignoring\n"));
		goto done;
	}

	/* Add new device to the list */
	if ((p = malloc(sizeof (struct ni_list))) == NULL) {
		rcm_log_message(RCM_ERROR, _("NET: malloc failure(%s)\n"),
		    strerror(errno));
		goto done;
	}
	(void) strncpy(p->dev, dev, sizeof (p->dev));
	p->next = NULL;
	*pp = p;

	rcm_log_message(RCM_TRACE1, _("NET: added new node %s\n"), dev);
done:
	(void) mutex_unlock(&nil_lock);
}

/*
 * Notify the RCM_RESOURCE_LINK_NEW event to other modules.
 * Return 0 on success, -1 on failure.
 */
static int
notify_new_link(rcm_handle_t *hd, const char *dev)
{
	nvlist_t *nvl = NULL;
	datalink_id_t linkid;
	uint64_t id;
	int ret = -1;

	rcm_log_message(RCM_TRACE1, _("NET: notify_new_link %s\n"), dev);
	if (dladm_dev2linkid(dev, &linkid) != DLADM_STATUS_OK) {
		rcm_log_message(RCM_TRACE1,
		    _("NET: new link %s has not attached yet\n"), dev);
		ret = 0;
		goto done;
	}

	id = linkid;
	if ((nvlist_alloc(&nvl, 0, 0) != 0) ||
	    (nvlist_add_uint64(nvl, RCM_NV_LINKID, id) != 0)) {
		rcm_log_message(RCM_ERROR,
		    _("NET: failed to construct nvlist for %s\n"), dev);
		goto done;
	}

	/*
	 * Reset the active linkprop of this specific link.
	 */
	(void) dladm_init_linkprop(linkid, B_FALSE);

	rcm_log_message(RCM_TRACE1, _("NET: notify new link %u (%s)\n"),
	    linkid, dev);

	if (rcm_notify_event(hd, RCM_RESOURCE_LINK_NEW, 0, nvl, NULL) !=
	    RCM_SUCCESS) {
		rcm_log_message(RCM_ERROR,
		    _("NET: failed to notify %s event for %s\n"),
		    RCM_RESOURCE_LINK_NEW, dev);
		goto done;
	}

	ret = 0;
done:
	if (nvl != NULL)
		nvlist_free(nvl);
	return (ret);
}
