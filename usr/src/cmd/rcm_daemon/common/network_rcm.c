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
#include <sys/types.h>
#include <net/if.h>
#include <liblaadm.h>
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

/* module private routines */
static void free_cache(void);
static void update_cache(rcm_handle_t *hd);
static int devfs_entry(di_node_t node, di_minor_t minor, void *arg);
static void cache_remove(net_cache_t *node);
static net_cache_t *cache_lookup(const char *resource);
static void free_node(net_cache_t *);
static void cache_insert(net_cache_t *);
static boolean_t is_aggregated(char *driver, int ppa);

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
	net_remove
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
		if (is_aggregated(node->driver, node->ppa)) {
			/* device is aggregated */
			*reason = strdup(gettext(
			    "Resource is in use by aggregation"));
			if (*reason == NULL) {
				rcm_log_message(RCM_ERROR,
				    gettext("NET: malloc failure"));
			}
			errno = EBUSY;
			return (RCM_FAILURE);
		}

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
 *	Online the previously offlined resource, and online its dependents.
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

	(void) snprintf(ifname, sizeof (ifname), "SUNW_network/%s%d",
	    name, instance);

	devfspath = di_devfs_path(node);
	if (!devfspath) {
		/* no devfs path?!? */
		rcm_log_message(RCM_DEBUG, "NET: missing devfs path\n");
		return (DI_WALK_CONTINUE);
	}

	if (strncmp("/pseudo", devfspath, strlen("/pseudo")) == 0) {
		/* ignore pseudo devices, probably not really NICs */
		rcm_log_message(RCM_DEBUG, "NET: ignoring pseudo device %s\n",
		    devfspath);
		di_devfs_path_free(devfspath);
		return (DI_WALK_CONTINUE);
	}

	(void) snprintf(resource, sizeof (resource), "/devices%s", devfspath);
	di_devfs_path_free(devfspath);

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

/*
 * is_aggregated() checks whether a NIC being removed is part of an
 * aggregation.
 */

typedef struct aggr_walker_state_s {
	uint_t naggr;
	char dev_name[LIFNAMSIZ];
} aggr_walker_state_t;

static int
aggr_walker(void *arg, laadm_grp_attr_sys_t *grp)
{
	aggr_walker_state_t *state = arg;
	laadm_port_attr_sys_t *port;
	int i;

	for (i = 0; i < grp->lg_nports; i++) {
		port = &grp->lg_ports[i];

		rcm_log_message(RCM_TRACE1, "MAC: aggr (%d) port %s/%d\n",
		    grp->lg_key, port->lp_devname, port->lp_port);

		if (strcmp(port->lp_devname, state->dev_name) != 0)
			continue;

		/* found matching MAC port */
		state->naggr++;
	}

	return (0);
}

static boolean_t
is_aggregated(char *driver, int ppa)
{
	aggr_walker_state_t state;

	state.naggr = 0;
	(void) snprintf(state.dev_name, sizeof (state.dev_name), "%s%d",
	    driver, ppa);

	if (laadm_walk_sys(aggr_walker, &state) != 0) {
		rcm_log_message(RCM_ERROR, gettext("NET: cannot walk "
		    "aggregations (%s)\n"), strerror(errno));
		return (B_FALSE);
	}

	return (state.naggr > 0);
}
