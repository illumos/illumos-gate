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
 * RCM module supporting multiplexed I/O controllers (MPxIO).
 */
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <syslog.h>
#include <string.h>
#include <synch.h>
#include <libintl.h>
#include <locale.h>
#include <ctype.h>
#include <errno.h>
#include <libdevinfo.h>
#include <sys/types.h>
#include "rcm_module.h"

#define	MPXIO_PROP_NAME		"mpxio-component"
#define	MPXIO_PROP_CLIENT	"client"

#define	CMD_GETINFO		0
#define	CMD_OFFLINE		1
#define	CMD_ONLINE		2
#define	CMD_REMOVE		3

#define	CACHE_NEW		0
#define	CACHE_REFERENCED	1
#define	CACHE_STALE		2

#define	MPXIO_MSG_CACHEFAIL	gettext("Internal analysis failure.")
#define	MPXIO_MSG_LASTPATH	gettext("Last path to busy resources.")
#define	MPXIO_MSG_USAGE		gettext("SCSI Multipathing PHCI (%s)")
#define	MPXIO_MSG_USAGEUNKNOWN	gettext("SCSI Multipathing PHCI (<unknown>)")

typedef struct {
	char *path;
	di_path_state_t state;
} phci_t;

typedef struct phci_list {
	phci_t phci;
	int referenced;
	struct phci_list *next;
} phci_list_t;

typedef struct group {
	int offline;
	int nphcis;
	int nclients;
	phci_t *phcis;
	char **clients;
	struct group *next;
} group_t;

static int mpxio_register(rcm_handle_t *);
static int mpxio_unregister(rcm_handle_t *);
static int mpxio_getinfo(rcm_handle_t *, char *, id_t, uint_t, char **, char **,
    nvlist_t *, rcm_info_t **);
static int mpxio_suspend(rcm_handle_t *, char *, id_t, timespec_t *, uint_t,
    char **, rcm_info_t **);
static int mpxio_resume(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int mpxio_offline(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int mpxio_online(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int mpxio_remove(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int get_nclients(di_node_t, void *);
static int build_groups(di_node_t, void *);
static void refresh_regs(rcm_handle_t *);
static int get_affected_clients(rcm_handle_t *, char *, int, int, char ***);
static int detect_client_change(rcm_handle_t *, int, int, group_t *, char *);
static int merge_clients(int *, char ***, group_t *);
static phci_list_t *lookup_phci(char *);
static int is_client(di_node_t);
static char *get_rsrcname(di_node_t);
static char *s_state(di_path_state_t);
static int compare_phci(const void *, const void *);
static void free_grouplist();
static void free_group(group_t *);
static void free_clients(int, char **);
static void free_phcis(int, phci_t *);

static struct rcm_mod_ops mpxio_ops =
{
	RCM_MOD_OPS_VERSION,
	mpxio_register,
	mpxio_unregister,
	mpxio_getinfo,
	mpxio_suspend,
	mpxio_resume,
	mpxio_offline,
	mpxio_online,
	mpxio_remove,
	NULL,
	NULL,
	NULL
};

static group_t *group_list;
static phci_list_t *reg_list;
static mutex_t mpxio_lock;

extern int errno;

/*
 * Return the mod-ops vector for initialization.
 */
struct rcm_mod_ops *
rcm_mod_init()
{
	rcm_log_message(RCM_TRACE1, "MPXIO: rcm_mod_init()\n");

	return (&mpxio_ops);
}

/*
 * Return name and version number for mod_info.
 */
const char *
rcm_mod_info()
{
	rcm_log_message(RCM_TRACE1, "MPXIO: rcm_mod_info()\n");

	return (gettext("RCM MPxIO module 1.6"));
}

/*
 * Destroy the cache and mutex lock when being unloaded.
 */
int
rcm_mod_fini()
{
	phci_list_t *reg;
	phci_list_t *next;

	rcm_log_message(RCM_TRACE1, "MPXIO: rcm_mod_fini()\n");

	/* Free the cache of MPxIO group information */
	free_grouplist();

	/* Free the cache of registrants */
	reg = reg_list;
	while (reg) {
		next = reg->next;
		free(reg->phci.path);
		free(reg);
		reg = next;
	}

	/* Destroy the mutex for locking the caches */
	(void) mutex_destroy(&mpxio_lock);

	return (RCM_SUCCESS);
}

/*
 * During each register callback: totally rebuild the group list from a new
 * libdevinfo snapshot, and then update the registrants.
 */
static int
mpxio_register(rcm_handle_t *hdl)
{
	int nclients = 0;
	di_node_t devroot;

	rcm_log_message(RCM_TRACE1, "MPXIO: register()\n");

	(void) mutex_lock(&mpxio_lock);

	/* Destroy the previous group list */
	free_grouplist();

	/* Get a current libdevinfo snapshot */
	if ((devroot = di_init("/", DINFOCPYALL | DINFOPATH)) == DI_NODE_NIL) {
		rcm_log_message(RCM_ERROR,
		    "MPXIO: libdevinfo initialization failed (%s).\n",
		    strerror(errno));
		(void) mutex_unlock(&mpxio_lock);
		return (RCM_FAILURE);
	}

	/*
	 * First count the total number of clients.  This'll be a useful
	 * upper bound when allocating client arrays within each group.
	 */
	(void) di_walk_node(devroot, DI_WALK_CLDFIRST, &nclients, get_nclients);

	rcm_log_message(RCM_TRACE2, gettext("MPXIO: found %d clients.\n"),
	    nclients);

	/*
	 * Then walk the libdevinfo snapshot, building up the new group list
	 * along the way.  Pass in the total number of clients (from above) to
	 * assist in group construction.
	 */
	(void) di_walk_node(devroot, DI_WALK_CLDFIRST, &nclients, build_groups);

	/* Now with a new group list constructed, refresh the registrants */
	refresh_regs(hdl);

	/* Free the libdevinfo snapshot */
	di_fini(devroot);

	(void) mutex_unlock(&mpxio_lock);

	return (0);
}

/*
 * Unregister all PHCIs and mark the whole registrants list as stale.
 */
static int
mpxio_unregister(rcm_handle_t *hdl)
{
	phci_list_t *reg;

	rcm_log_message(RCM_TRACE1, "MPXIO: unregister()\n");

	(void) mutex_lock(&mpxio_lock);

	for (reg = reg_list; reg != NULL; reg = reg->next) {
		(void) rcm_unregister_interest(hdl, reg->phci.path, 0);
		reg->referenced = CACHE_STALE;
	}

	(void) mutex_unlock(&mpxio_lock);

	return (RCM_SUCCESS);
}

/*
 * To return usage information, just lookup the PHCI in the cache and return
 * a string identifying that it's a PHCI and describing its cached MPxIO state.
 * Recurse with the cached list of disks if dependents are to be included.
 */
static int
mpxio_getinfo(rcm_handle_t *hdl, char *rsrc, id_t id, uint_t flags,
    char **infostr, char **errstr, nvlist_t *props, rcm_info_t **infop)
{
	size_t len;
	int rv = RCM_SUCCESS;
	char *buf = NULL;
	char **clients = NULL;
	phci_list_t *reg;
	char c;

	rcm_log_message(RCM_TRACE1, "MPXIO: getinfo(%s)\n", rsrc);

	*infostr = NULL;
	*errstr = NULL;

	(void) mutex_lock(&mpxio_lock);

	if ((reg = lookup_phci(rsrc)) == NULL) {
		*errstr = strdup(MPXIO_MSG_CACHEFAIL);
		(void) mutex_unlock(&mpxio_lock);
		return (RCM_FAILURE);
	}

	len = snprintf(&c, 1, MPXIO_MSG_USAGE, s_state(reg->phci.state));
	buf = calloc(len + 1, sizeof (char));
	if ((buf == NULL) || (snprintf(buf, len + 1, MPXIO_MSG_USAGE,
	    s_state(reg->phci.state)) > len + 1)) {
		*infostr = strdup(MPXIO_MSG_USAGEUNKNOWN);
		*errstr = strdup(gettext("Cannot construct usage string."));
		(void) mutex_unlock(&mpxio_lock);
		if (buf)
			free(buf);
		return (RCM_FAILURE);
	}
	*infostr = buf;

	if (flags & RCM_INCLUDE_DEPENDENT) {
		rcm_log_message(RCM_TRACE2, "MPXIO: getting clients\n");
		if (get_affected_clients(hdl, rsrc, CMD_GETINFO, flags,
		    &clients) < 0) {
			*errstr = strdup(gettext("Cannot lookup clients."));
			(void) mutex_unlock(&mpxio_lock);
			return (RCM_FAILURE);
		}
		if (clients) {
			rv = rcm_get_info_list(hdl, clients, flags, infop);
			free(clients);
		} else {
			rcm_log_message(RCM_TRACE2, "MPXIO: none found\n");
		}
	}

	(void) mutex_unlock(&mpxio_lock);
	return (rv);
}

/*
 * Nothing is implemented for suspend operations.
 */
static int
mpxio_suspend(rcm_handle_t *hdl, char *rsrc, id_t id, timespec_t *interval,
    uint_t flags, char **errstr, rcm_info_t **infop)
{
	rcm_log_message(RCM_TRACE1, "MPXIO: suspend(%s)\n", rsrc);

	return (RCM_SUCCESS);
}

/*
 * Nothing is implemented for resume operations.
 */
static int
mpxio_resume(rcm_handle_t *hdl, char *rsrc, id_t id, uint_t flags,
    char **errstr, rcm_info_t **infop)
{
	rcm_log_message(RCM_TRACE1, "MPXIO: resume(%s)\n", rsrc);

	return (RCM_SUCCESS);
}

/*
 * MPxIO has no policy against offlining.  If disks will be affected, then
 * base the return value for this request on the results of offlining the
 * list of disks.  Otherwise succeed.
 */
static int
mpxio_offline(rcm_handle_t *hdl, char *rsrc, id_t id, uint_t flags,
    char **errstr, rcm_info_t **infop)
{
	char **clients = NULL;
	int rv = RCM_SUCCESS;

	rcm_log_message(RCM_TRACE1, "MPXIO: offline(%s)\n", rsrc);

	(void) mutex_lock(&mpxio_lock);

	if (get_affected_clients(hdl, rsrc, CMD_OFFLINE, flags, &clients) < 0) {
		*errstr = strdup(gettext("Cannot lookup clients."));
		(void) mutex_unlock(&mpxio_lock);
		return (RCM_FAILURE);
	}

	if (clients) {
		rv = rcm_request_offline_list(hdl, clients, flags, infop);
		if (rv != RCM_SUCCESS)
			*errstr = strdup(MPXIO_MSG_LASTPATH);
		free(clients);
	}

	(void) mutex_unlock(&mpxio_lock);

	return (rv);
}

/*
 * If disks are affected, then they are probably offline and we need to
 * propagate this online notification to them.
 */
static int
mpxio_online(rcm_handle_t *hdl, char *rsrc, id_t id, uint_t flags,
    char **errstr, rcm_info_t **infop)
{
	char **clients;
	int rv = RCM_SUCCESS;

	rcm_log_message(RCM_TRACE1, "MPXIO: online(%s)\n", rsrc);

	(void) mutex_lock(&mpxio_lock);

	if (get_affected_clients(hdl, rsrc, CMD_ONLINE, flags, &clients) < 0) {
		*errstr = strdup(gettext("Cannot lookup clients."));
		(void) mutex_unlock(&mpxio_lock);
		return (RCM_FAILURE);
	}

	if (clients) {
		rv = rcm_notify_online_list(hdl, clients, flags, infop);
		free(clients);
	}

	(void) mutex_unlock(&mpxio_lock);

	return (rv);
}

/*
 * If clients are affected, then they are probably offline and we need to
 * propagate this removal notification to them.  We can also remove the
 * cache entry for this PHCI.  If that leaves its group empty, then the
 * group will be removed during the next register callback.
 */
static int
mpxio_remove(rcm_handle_t *hdl, char *rsrc, id_t id, uint_t flags,
    char **errstr, rcm_info_t **infop)
{
	char **clients;
	int rv = RCM_SUCCESS;

	rcm_log_message(RCM_TRACE1, "MPXIO: remove(%s)\n", rsrc);

	(void) mutex_lock(&mpxio_lock);

	if (get_affected_clients(hdl, rsrc, CMD_REMOVE, flags, &clients) < 0) {
		*errstr = strdup(gettext("Cannot lookup clients."));
		(void) mutex_unlock(&mpxio_lock);
		return (RCM_FAILURE);
	}

	if (clients) {
		rv = rcm_notify_remove_list(hdl, clients, flags, infop);
		free(clients);
	}

	(void) mutex_unlock(&mpxio_lock);

	return (rv);
}


/*
 * Returns a string representation of a given libdevinfo path state.
 */
static char *
s_state(di_path_state_t state)
{
	switch (state) {
	case DI_PATH_STATE_ONLINE:
		return ("online");
	case DI_PATH_STATE_OFFLINE:
		return ("offline");
	case DI_PATH_STATE_STANDBY:
		return ("standby");
	case DI_PATH_STATE_FAULT:
		return ("faulted");
	default:
		return ("<unknown>");
	}
}

static int
get_affected_clients(rcm_handle_t *hdl, char *rsrc, int cmd, int flags,
    char ***clientsp)
{
	int nclients = 0;
	phci_t phci;
	group_t *group;
	char **clients = NULL;

	/* Build a dummy phci_t for use with bsearch(). */
	phci.path = rsrc;

	/* Analyze the effects upon each group. */
	for (group = group_list; group != NULL; group = group->next) {

		/* If the PHCI isn't in the group, then no effects.  Skip. */
		if (bsearch(&phci, group->phcis, group->nphcis, sizeof (phci_t),
		    compare_phci) == NULL)
			continue;

		/*
		 * Merge in the clients.  All clients are merged in for getinfo
		 * operations.  Otherwise it's contingent upon a state change
		 * being transferred to the clients as a result of changing
		 * the PHCI's state.
		 */
		if ((cmd == CMD_GETINFO) ||
		    detect_client_change(hdl, cmd, flags, group, rsrc)) {
			if (merge_clients(&nclients, &clients, group) < 0) {
				free_clients(nclients, clients);
				return (-1);
			}
		}
	}

	/* Return the array of affected disks */
	*clientsp = clients;
	return (0);
}

/*
 * Iterates through the members of a PHCI list, returning the entry
 * corresponding to the named PHCI resource.  Returns NULL when the lookup
 * fails.
 */
static phci_list_t *
lookup_phci(char *rsrc)
{
	phci_list_t *reg;

	for (reg = reg_list; reg != NULL; reg = reg->next) {
		if (strcmp(reg->phci.path, rsrc) == 0)
			return (reg);
	}

	return (NULL);
}

/*
 * Tests whether or not an operation on a specific PHCI resource would affect
 * the array of client devices attached to the PHCI's MPxIO group.
 *
 * Returns: 1 if clients would be affected, 0 if not.
 */
static int
detect_client_change(rcm_handle_t *hdl, int cmd, int flags, group_t *group,
    char *rsrc)
{
	int i;
	int state;

	/*
	 * Perform a full set analysis on the set of redundant PHCIs.  When
	 * there are no unaffected and online PHCIs, then changing the state
	 * of the named PHCI results in a client state change.
	 */
	for (i = 0; i < group->nphcis; i++) {

		/* Filter the named resource out of the analysis */
		if (strcmp(group->phcis[i].path, rsrc) == 0)
			continue;

		/*
		 * If we find a path that's in the ONLINE or STANDBY state
		 * that would be left over in the system after completing
		 * whatever DR or hotplugging operation is in progress, then
		 * return a 0.
		 */
		if ((group->phcis[i].state == DI_PATH_STATE_ONLINE) ||
		    (group->phcis[i].state == DI_PATH_STATE_STANDBY)) {
			if (rcm_get_rsrcstate(hdl, group->phcis[i].path, &state)
			    != RCM_SUCCESS) {
				rcm_log_message(RCM_ERROR,
				    "MPXIO: Failed to query resource state\n");
				continue;
			}
			rcm_log_message(RCM_TRACE2, "MPXIO: state of %s: %d\n",
			    group->phcis[i].path, state);
			if (state == RCM_STATE_ONLINE) {
				return (0);
			}
		}
	}

	/*
	 * The analysis above didn't find a redundant path to take over.  So
	 * report that the state of the client resources will change.
	 */
	return (1);
}

/*
 * Merges the client disks connected to a particular MPxIO group in with a
 * previous array of disk clients.  The result is to adjust the 'nclients'
 * value with the new count of disks in the array, and to adjust the 'disks'
 * value to be a larger array of disks including its original contents along
 * with the current group's contents merged in.
 */
static int
merge_clients(int *nclients, char ***clientsp, group_t *group)
{
	int i;
	int old_nclients;
	char **clients_new;

	if (group->nclients) {
		old_nclients = *nclients;
		*nclients += group->nclients;
		clients_new = realloc(*clientsp,
		    ((*nclients) + 1) * sizeof (char *));
		if (clients_new == NULL) {
			rcm_log_message(RCM_ERROR,
			    "MPXIO: cannot reallocate client array (%s).\n",
			    strerror(errno));
			return (-1);
		}
		for (i = old_nclients; i < (*nclients); i++) {
			/*
			 * Don't allocate space for individual disks in the
			 * merged list.  Just make references to the previously
			 * allocated strings in the group_t structs themselves.
			 */
			clients_new[i] = group->clients[i - old_nclients];
		}
		clients_new[(*nclients)] = NULL;
		*clientsp = clients_new;
	}

	return (0);
}

/*
 * A libdevinfo di_walk_node() callback.  It's passed an integer pointer as an
 * argument, and it increments the integer each time it encounters an MPxIO
 * client.  By initializing the integer to zero and doing a libdevinfo walk with
 * this function, the total count of MPxIO clients in the system can be found.
 */
static int
get_nclients(di_node_t dinode, void *arg)
{
	int *nclients = arg;

	if (is_client(dinode))
		(*nclients)++;

	return (DI_WALK_CONTINUE);
}

/*
 * Tests a libdevinfo node to determine if it's an MPxIO client.
 *
 * Returns: non-zero for true, 0 for false.
 */
static int
is_client(di_node_t dinode)
{
	return (di_path_client_next_path(dinode, DI_PATH_NIL) != DI_PATH_NIL);
}

/*
 * After a new group_list has been constructed, this refreshes the RCM
 * registrations and the reg_list contents.  It uses a clock like algorithm
 * with reference bits in the reg_list to know which registrants are new or
 * old.
 */
static void
refresh_regs(rcm_handle_t *hdl)
{
	int i;
	group_t *group;
	phci_list_t *reg;
	phci_list_t *prev_reg;

	/*
	 * First part of the clock-like algorithm: clear reference bits.
	 */
	for (reg = reg_list; reg != NULL; reg = reg->next)
		reg->referenced = CACHE_STALE;

	/*
	 * Second part of the clock-like algorithm: set the reference bits
	 * on every registrant that's still active.  (Also add new list nodes
	 * for new registrants.)
	 */
	for (group = group_list; group != NULL; group = group->next) {
		for (i = 0; i < group->nphcis; i++) {

			/*
			 * If already stale in the registrants list, just set
			 * its reference bit to REFERENCED and update its state.
			 */
			if ((reg = lookup_phci(group->phcis[i].path)) != NULL) {
				if (reg->referenced == CACHE_STALE)
					reg->referenced = CACHE_REFERENCED;
				reg->phci.state = group->phcis[i].state;
				continue;
			}

			/*
			 * Otherwise, build a new list node and mark it NEW.
			 */
			reg = (phci_list_t *)calloc(1, sizeof (*reg));
			if (reg == NULL) {
				rcm_log_message(RCM_ERROR,
				    "MPXIO: cannot allocate phci_list (%s).\n",
				    strerror(errno));
				continue;
			}
			reg->phci.path = strdup(group->phcis[i].path);
			if (reg->phci.path == NULL) {
				free(reg);
				rcm_log_message(RCM_ERROR,
				    "MPXIO: cannot allocate phci path (%s).\n",
				    strerror(errno));
				continue;
			}
			reg->phci.state = group->phcis[i].state;
			reg->referenced = CACHE_NEW;

			/* Link it at the head of reg_list */
			reg->next = reg_list;
			reg_list = reg;
		}
	}

	/*
	 * Final part of the clock algorithm: unregister stale entries, and
	 * register new entries.  Stale entries get removed from the list.
	 */
	reg = reg_list;
	prev_reg = NULL;
	while (reg) {

		/* Unregister and remove stale entries. */
		if (reg->referenced == CACHE_STALE) {
			(void) rcm_unregister_interest(hdl, reg->phci.path, 0);
			free(reg->phci.path);
			if (prev_reg == NULL) {
				reg_list = reg->next;
				free(reg);
				reg = reg_list;
			} else {
				prev_reg->next = reg->next;
				free(reg);
				reg = prev_reg->next;
			}
			continue;
		}

		/* Register new entries. */
		if (reg->referenced == CACHE_NEW) {
			if (rcm_register_interest(hdl, reg->phci.path, 0, NULL)
			    != RCM_SUCCESS) {
				rcm_log_message(RCM_ERROR,
				    "MPXIO: failed to register %s (%s).\n",
				    reg->phci.path, strerror(errno));
			}
		}

		prev_reg = reg;
		reg = reg->next;
	}
}


/*
 * A libdevinfo di_walk_node() callback that builds up the MPxIO group list.
 *
 * Every node encountered that's a client node is added into a group's client
 * list.  Whenever a group doesn't already exist with a matching set of
 * related PHCIs, then a new group is constructed and put at the head of the
 * group list.
 */
static int
build_groups(di_node_t dinode, void *arg)
{
	int i = 0;
	int nphcis = 0;
	int *nclients = (int *)arg;
	phci_t *phcis;
	group_t *group;
	di_node_t phcinode;
	di_path_t dipath = DI_PATH_NIL;

	/* Safety check */
	if (nclients == NULL)
		return (DI_WALK_TERMINATE);

	/*
	 * Build a sorted array of PHCIs pertaining to the client.
	 */
	while ((dipath =
	    di_path_client_next_path(dinode, dipath)) != DI_PATH_NIL)
		nphcis++;

	/* Skip non-clients. */
	if (nphcis == 0)
		return (DI_WALK_CONTINUE);

	if ((phcis = (phci_t *)calloc(nphcis, sizeof (phci_t))) == NULL) {
		rcm_log_message(RCM_ERROR,
		    "MPXIO: failed to allocate client's PHCIs (%s).\n",
		    strerror(errno));
		return (DI_WALK_TERMINATE);
	}
	while ((dipath =
	    di_path_client_next_path(dinode, dipath)) != DI_PATH_NIL) {
		phcinode = di_path_phci_node(dipath);
		if (phcinode == DI_NODE_NIL) {
			free_phcis(i, phcis);	/* free preceeding PHCIs */
			rcm_log_message(RCM_ERROR,
			    "MPXIO: client appears to have no PHCIs.\n");
			return (DI_WALK_TERMINATE);
		}
		if ((phcis[i].path = get_rsrcname(phcinode)) == NULL) {
			free_phcis(i, phcis);
			return (DI_WALK_TERMINATE);
		}
		phcis[i].state = di_path_state(dipath);
		i++;
	}
	qsort(phcis, nphcis, sizeof (phci_t), compare_phci);

	/*
	 * Compare that PHCI set to each existing group's set.  We just add
	 * the client to the group and exit successfully once a match is made.
	 * Falling out of this loop means no match was found.
	 */
	for (group = group_list; group != NULL; group = group->next) {

		/* There is no match if the number of PHCIs is inequal */
		if (nphcis != group->nphcis)
			continue;

		/* Compare the PHCIs linearly (which is okay; they're sorted) */
		for (i = 0; i < nphcis; i++)
			if (strcmp(phcis[i].path, group->phcis[i].path) != 0)
				break;

		/*
		 * If the loop above completed, we have a match.  Add the client
		 * to the group's disk array in that case, and return
		 * successfully.
		 */
		if (i == nphcis) {
			free_phcis(nphcis, phcis);
			if ((group->clients[group->nclients] =
			    get_rsrcname(dinode)) == NULL)
				return (DI_WALK_TERMINATE);
			group->nclients++;
			return (DI_WALK_CONTINUE);
		}
	}

	/* The loop above didn't find a match.  So build a new group. */
	if ((group = (group_t *)calloc(1, sizeof (*group))) == NULL) {
		rcm_log_message(RCM_ERROR,
		    "MPXIO: failed to allocate PHCI group (%s).\n",
		    strerror(errno));
		free_phcis(nphcis, phcis);
		return (DI_WALK_TERMINATE);
	}
	if ((group->clients = (char **)calloc(*nclients, sizeof (char *))) ==
	    NULL) {
		free(group);
		free_phcis(nphcis, phcis);
		return (DI_WALK_TERMINATE);
	}
	group->nphcis = nphcis;
	group->phcis = phcis;
	if ((group->clients[0] = get_rsrcname(dinode)) == NULL) {
		free_group(group);
		return (DI_WALK_TERMINATE);
	}
	group->nclients = 1;

	/* Link the group into the group list and return successfully. */
	group->next = group_list;
	group_list = group;
	return (DI_WALK_CONTINUE);
}

/*
 * For bsearch() and qsort().  Returns the results of a strcmp() on the names
 * of two phci_t's.
 */
static int
compare_phci(const void *arg1, const void *arg2)
{
	phci_t *p1 = (phci_t *)arg1;
	phci_t *p2 = (phci_t *)arg2;

	if ((p1 == NULL) || (p2 == NULL)) {
		if (p1 != NULL)
			return (-1);
		else if (p2 != NULL)
			return (1);
		return (0);
	}

	return (strcmp(p1->path, p2->path));
}

/*
 * Free the whole list of group's in the global group_list.
 */
static void
free_grouplist()
{
	group_t *group = group_list;
	group_t *next;

	while (group) {
		next = group->next;
		free_group(group);
		group = next;
	}

	group_list = NULL;
}

/*
 * Free the contents of a single group_t.
 */
static void
free_group(group_t *group)
{
	if (group) {
		free_phcis(group->nphcis, group->phcis);
		free_clients(group->nclients, group->clients);
		free(group);
	}
}

/*
 * Free an array of clients.
 */
static void
free_clients(int nclients, char **clients)
{
	int i;

	if (clients != NULL) {
		if (nclients > 0) {
			for (i = 0; i < nclients; i++)
				if (clients[i])
					free(clients[i]);
		}
		free(clients);
	}
}

/*
 * Free an array of phci_t's.
 */
static void
free_phcis(int nphcis, phci_t *phcis)
{
	int i;

	if ((phcis != NULL) && (nphcis > 0)) {
		for (i = 0; i < nphcis; i++)
			if (phcis[i].path)
				free(phcis[i].path);
		free(phcis);
	}
}

/*
 * Converts a libdevinfo node into a /devices path.  Caller must free results.
 */
static char *
get_rsrcname(di_node_t dinode)
{
	int len;
	char *rsrcname;
	char *devfspath;
	char name[MAXPATHLEN];

	if ((devfspath = di_devfs_path(dinode)) == NULL) {
		rcm_log_message(RCM_ERROR, "MPXIO: resource has null path.\n");
		return (NULL);
	}

	len = snprintf(name, sizeof (name), "/devices%s", devfspath);
	di_devfs_path_free(devfspath);
	if (len >= sizeof (name)) {
		rcm_log_message(RCM_ERROR, "MPXIO: resource path too long.\n");
		return (NULL);
	}

	if ((rsrcname = strdup(name)) == NULL)
		rcm_log_message(RCM_ERROR,
		    "MPXIO: failed to allocate resource name (%s).\n",
		    strerror(errno));

	return (rsrcname);
}
