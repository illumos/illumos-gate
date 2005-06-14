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
#include <ctype.h>
#include <sys/types.h>
#include <libdlpi.h>
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

/* operations */
#define	NET_OFFLINE	1
#define	NET_ONLINE	2
#define	NET_REMOVE	3
#define	NET_SUSPEND	4
#define	NET_RESUME	5

/*
 * PSARC decided that DLPI providers are not allowed to end in a digit.
 * If this ever changes we could add a delimiter with this macro.
 */
#define	NET_DELIMITER	""

#define	DLD_NAME	"dld"

typedef struct net_cache
{
	char			*resource;
	char			*exported;
	char			*driver;
	int			ppa;
	int			flags;
	struct net_cache	*next;
	struct net_cache	*prev;
} net_cache_t;

static net_cache_t	cache_head;
static net_cache_t	cache_tail;
static mutex_t		cache_lock;
static int		events_registered = 0;

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
	NULL,		/* request_capacity_change */
	NULL,		/* notify_capacity_change */
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
	return ("Network namespace module %I%");
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
	if (events_registered == 0) {
		(void) rcm_register_event(hd, "SUNW_resource/new", 0, NULL);
		events_registered++;
	}
	update_cache(hd);
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
	if (events_registered > 0) {
		(void) rcm_unregister_event(hd, "SUNW_resource/new", 0);
		events_registered--;
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
	 * Since node->exported could be freed after we drop cache_lock,
	 * allocate a stack-local copy.  We don't use strdup() because some of
	 * the operations (such as NET_REMOVE) are not allowed to fail.  Note
	 * that node->exported is never more than MAXPATHLEN bytes.
	 */
	exported = alloca(strlen(node->exported) + 1);
	(void) strlcpy(exported, node->exported, strlen(node->exported) + 1);

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

	rcm_log_message(RCM_TRACE1, "NET: offline(%s)\n", rsrc);

	return (net_passthru(hd, NET_OFFLINE, rsrc, flags, reason,
	    dependent_reason, NULL));
}

/*
 * net_online()
 *
 *	Remount the previously offlined filesystem, and online its dependents.
 */
static int
net_online(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flag, char **reason,
    rcm_info_t **dependent_reason)
{
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);

	rcm_log_message(RCM_TRACE1, "NET: online(%s)\n", rsrc);

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
	char		*exported;
	char		nic[64];
	const char	*info_fmt;
	net_cache_t	*node;

	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(info != NULL);
	assert(depend_info != NULL);

	rcm_log_message(RCM_TRACE1, "NET: getinfo(%s)\n", rsrc);

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
	exported = strdup(node->exported);
	if (!exported) {
		rcm_log_message(RCM_ERROR, _("NET: strdup failure"));
		(void) mutex_unlock(&cache_lock);
		return (RCM_FAILURE);
	}

	(void) snprintf(nic, sizeof (nic), "%s%d", node->driver, node->ppa);
	(void) mutex_unlock(&cache_lock);

	len = strlen(info_fmt) + strlen(nic) + 1;
	if ((*info = (char *)malloc(len)) == NULL) {
		rcm_log_message(RCM_ERROR, _("NET: malloc failure"));
		free(exported);
		return (RCM_FAILURE);
	}

	/* Fill in the string */
	(void) snprintf(*info, len, info_fmt, nic);

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

	rcm_log_message(RCM_TRACE1, "NET: suspend(%s)\n", rsrc);

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

	rcm_log_message(RCM_TRACE1, "NET: resume(%s)\n", rsrc);

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

	rcm_log_message(RCM_TRACE1, "NET: remove(%s)\n", rsrc);

	return (net_passthru(hd, NET_REMOVE, rsrc, flag, info, dependent_info,
	    NULL));
}

/*
 * net_notify_event()
 *
 *	Receive new resource events.  If the resource is a network
 *	device, then pass up a notify for it too.  No need to cache
 *	it, though, since we'll do that in our register() routine the
 *	next time we're called.
 */
/*ARGSUSED*/
static int
net_notify_event(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flag,
    char **errstr, nvlist_t *nvl, rcm_info_t **result)
{
	char		*devname = NULL, *nodetype, *driver, *kpath;
	char		ifname[MAXPATHLEN];
	di_node_t	node;
	di_minor_t	minor;
	nvlist_t	*nvlist;
	nvpair_t	*nvp = NULL;
	int		rv;

	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(nvl != NULL);
	assert(result != NULL);

	rcm_log_message(RCM_TRACE1, "NET: notify_event(%s)\n", rsrc);

	if (strcmp(rsrc, "SUNW_resource/new") != 0) {
		/* how did we get this?  we didn't ask for it! */
		rcm_log_message(RCM_WARNING,
		    _("NET: unrecognized event for %s\n"), rsrc);
		return (RCM_FAILURE);
	}

	/* is it a /devices resource? */
	/*
	 * note: we'd like to use nvlist_lookup_string, but a bug in
	 * libnvpair breaks lookups, so we have to walk it ourself.
	 */
#ifdef NVLIST_LOOKUP_NOTBROKEN
	if (nvlist_lookup_string(nvl, RCM_RSRCNAME, &devname) != 0) {
		/* resource not found */
		rcm_log_message(RCM_WARNING,
		    _("NET: event without resource name\n"));
		return (RCM_FAILURE);
	}
#else
	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		if (strcmp(nvpair_name(nvp), RCM_RSRCNAME) == 0) {
			if (nvpair_value_string(nvp, &devname) != 0) {
				rcm_log_message(RCM_WARNING,
				    _("NET: cannot get event "
					"resource value\n"));
				return (RCM_FAILURE);
			}
			break;
		}
	}
	if (devname == NULL) {
		rcm_log_message(RCM_WARNING,
		    _("NET: event without resource name\n"));
		return (RCM_FAILURE);
	}
#endif
	rcm_log_message(RCM_TRACE1, "NET: new rsrc(%s)\n", devname);
	if (strncmp(devname, "/devices/", strlen("/devices/")) != 0) {
		/* not a /devices resource, we ignore it */
		rcm_log_message(RCM_TRACE1, "NET: %s not for us\n", devname);
		return (RCM_SUCCESS);
	}
	kpath = devname + strlen("/devices");
	if (strncmp(kpath, "/pseudo/", strlen("/pseudo/")) == 0) {
		/* pseudo device , not for us */
		rcm_log_message(RCM_TRACE1, "NET: ignoring pseudo %s\n",
		    devname);
		return (RCM_SUCCESS);
	}

	/* just snapshot the specific tree we need */
	if ((node = di_init(kpath, DINFOMINOR)) == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("NET: cannot initialize device tree\n"));
		return (RCM_FAILURE);
	}

	/* network devices usually only have a single minor node */
	if ((minor = di_minor_next(node, DI_MINOR_NIL)) == DI_MINOR_NIL) {
		rcm_log_message(RCM_WARNING,
		    _("NET: cannot find minor for %s\n"),
		    devname);
		di_fini(node);
		return (RCM_FAILURE);
	}

	nodetype = di_minor_nodetype(minor);
	if ((nodetype == NULL) || (strcmp(nodetype, DDI_NT_NET) != 0)) {
		/* doesn't look like a network device */
		rcm_log_message(RCM_TRACE1, "NET: %s not a NIC\n", devname);
		goto done;
	}
	if ((driver = di_driver_name(node)) == NULL) {
		rcm_log_message(RCM_TRACE1, "NET: no driver (%s)\n", devname);
		goto done;
	}
	(void) snprintf(ifname, sizeof (ifname), "SUNW_network/%s%s%d", driver,
	    NET_DELIMITER, di_instance(node));

	rcm_log_message(RCM_TRACE1, "NET: notifying arrival of %s\n", ifname);
	/* build up our nvlist -- these shouldn't ever fail */
	if ((rv = nvlist_alloc(&nvlist, NV_UNIQUE_NAME, 0)) != 0) {
		rcm_log_message(RCM_TRACE1,
		    "NET: nvlist alloc failed %d, errno %d\n", rv, errno);
	}

	if ((rv = nvlist_add_string(nvlist, RCM_RSRCNAME, ifname)) != 0) {
		rcm_log_message(RCM_TRACE1,
		    "NET: nvlist_add_string failed %d, errno %d\n", rv, errno);
	}
	/* now we need to do our own notification */
	rv = rcm_notify_event(hd, "SUNW_resource/new", 0, nvlist, result);
	if (rv != RCM_SUCCESS) {
		rcm_log_message(RCM_TRACE1,
		    "NET: notify_event failed: %s\n", strerror(errno));
	} else {
		rcm_log_message(RCM_TRACE1, "NET: notify_event succeeded\n");
	}

	/* and clean up our nvlist */
	nvlist_free(nvlist);

done:
	di_fini(node);
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
		free(node->exported);
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
	char		ifname [MAXPATHLEN];	/* should be big enough! */
	char		*devfspath;
	char		resource[MAXPATHLEN];
	char		dev_name[MAXPATHLEN];
	char		*name;
	char		*cp;
	int		instance;
	net_cache_t	*probe;

	cp = di_minor_nodetype(minor);
	if ((cp == NULL) || (strcmp(cp, DDI_NT_NET))) {
		/* doesn't look like a network device */
		return (DI_WALK_CONTINUE);
	}

	name = di_driver_name(node);
	if (name == NULL) {
		/* what else can we do? */
		return (DI_WALK_CONTINUE);
	}

	instance = di_instance(node);

	devfspath = di_devfs_path(node);
	if (!devfspath) {
		/* no devfs path?!? */
		rcm_log_message(RCM_DEBUG, "NET: missing devfs path\n");
		return (DI_WALK_CONTINUE);
	}

	if (strncmp("/pseudo", devfspath, strlen("/pseudo")) == 0) {
		char *minor_name;

		if (strcmp(DLD_NAME, name) != 0) {
			/* ignore pseudo devices, probably not really NICs */
			rcm_log_message(RCM_DEBUG, "NET: ignoring pseudo "
			    "device %s\n", devfspath);
			di_devfs_path_free(devfspath);
			return (DI_WALK_CONTINUE);
		}

		/* we have a virtual datalink created by dld */
		di_devfs_path_free(devfspath);
		devfspath = di_devfs_minor_path(minor);
		rcm_log_message(RCM_DEBUG, "NET: virtual datalink \"%s\"\n",
		    devfspath);

		minor_name = di_minor_name(minor);
		if (dlpi_if_parse(minor_name, dev_name, &instance) < 0 ||
		    instance < 0) {
			rcm_log_message(RCM_DEBUG, "NET: ignoring \"%s\" "
			    "(style 1)\n", devfspath);
			di_devfs_path_free(devfspath);
			return (DI_WALK_CONTINUE);
		}
		name = dev_name;
	}

	(void) snprintf(resource, sizeof (resource), "/devices%s", devfspath);
	di_devfs_path_free(devfspath);

	(void) snprintf(ifname, sizeof (ifname), "SUNW_network/%s%s%d",
	    name, NET_DELIMITER, instance);

	probe = cache_lookup(resource);
	if (probe != NULL) {
		rcm_log_message(RCM_DEBUG, "NET: %s already registered\n",
		    resource);
		probe->flags &= ~(CACHE_STALE);
	} else {
		rcm_log_message(RCM_DEBUG, "NET: %s is new resource\n",
		    resource);
		probe = calloc(1, sizeof (net_cache_t));
		if (!probe) {
			rcm_log_message(RCM_ERROR, _("NET: malloc failure"));
			return (DI_WALK_CONTINUE);
		}

		probe->resource = strdup(resource);
		probe->ppa = instance;
		probe->driver = strdup(name);
		probe->exported = strdup(ifname);

		if ((!probe->resource) || (!probe->exported) ||
		    (!probe->driver)) {
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
			rcm_log_message(RCM_DEBUG, "NET: unregistered %s\n",
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

		rcm_log_message(RCM_DEBUG, "NET: registering %s\n",
		    probe->resource);
		rv = rcm_register_interest(hd, probe->resource, 0, NULL);
		if (rv != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("NET: failed to register %s\n"),
			    probe->resource);
		} else {
			rcm_log_message(RCM_DEBUG,
			    "NET: registered %s (as %s)\n",
			    probe->resource, probe->exported);
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
