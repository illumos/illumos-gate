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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <librcm.h>
#include <libhotplug.h>
#include <libhotplug_impl.h>
#include <sys/sunddi.h>
#include <sys/ddi_hp.h>
#include "hotplugd_impl.h"

/*
 * Define structures for a path-to-usage lookup table.
 */
typedef struct info_entry {
	char			*rsrc;
	char			*usage;
	struct info_entry	*next;
} info_entry_t;

typedef struct {
	char		*path;
	info_entry_t	*entries;
} info_table_t;

/*
 * Define callback argument used when getting resources.
 */
typedef struct {
	int	error;
	int	n_rsrcs;
	char	**rsrcs;
	char	path[MAXPATHLEN];
	char	connection[MAXPATHLEN];
	char	dev_path[MAXPATHLEN];
} resource_cb_arg_t;

/*
 * Define callback argument used when merging info.
 */
typedef struct {
	int		error;
	info_table_t	*table;
	size_t		table_len;
	char		path[MAXPATHLEN];
	char		connection[MAXPATHLEN];
} merge_cb_arg_t;

/*
 * Local functions.
 */
static int	merge_rcm_info(hp_node_t root, rcm_info_t *info);
static int	get_rcm_usage(char **rsrcs, rcm_info_t **info_p);
static int	build_table(rcm_info_t *info, info_table_t **tablep,
		    size_t *table_lenp);
static void	free_table(info_table_t *table, size_t table_len);
static int	resource_callback(hp_node_t node, void *argp);
static int	merge_callback(hp_node_t node, void *argp);
static int	rsrc2path(const char *rsrc, char *path);
static int	compare_info(const void *a, const void *b);

/*
 * copy_usage()
 *
 *	Given an information snapshot, get the corresponding
 *	RCM usage information and merge it into the snapshot.
 */
int
copy_usage(hp_node_t root)
{
	rcm_info_t	*info = NULL;
	char		**rsrcs = NULL;
	int		rv;

	/* Get resource names */
	if ((rv = rcm_resources(root, &rsrcs)) != 0) {
		log_err("Cannot get RCM resources (%s)\n", strerror(rv));
		return (rv);
	}

	/* Do nothing if no resources */
	if (rsrcs == NULL)
		return (0);

	/* Get RCM usage information */
	if ((rv = get_rcm_usage(rsrcs, &info)) != 0) {
		log_err("Cannot get RCM information (%s)\n", strerror(rv));
		free_rcm_resources(rsrcs);
		return (rv);
	}

	/* Done with resource names */
	free_rcm_resources(rsrcs);

	/* If there is RCM usage information, merge it in */
	if (info != NULL) {
		rv = merge_rcm_info(root, info);
		rcm_free_info(info);
		return (rv);
	}

	return (0);
}

/*
 * rcm_resources()
 *
 *	Given the root of a hotplug information snapshot,
 *	construct a list of RCM compatible resource names.
 */
int
rcm_resources(hp_node_t root, char ***rsrcsp)
{
	resource_cb_arg_t	arg;

	/* Initialize results */
	*rsrcsp = NULL;

	/* Traverse snapshot to get resources */
	(void) memset(&arg, 0, sizeof (resource_cb_arg_t));
	(void) hp_traverse(root, &arg, resource_callback);

	/* Check for errors */
	if (arg.error != 0) {
		free_rcm_resources(arg.rsrcs);
		return (arg.error);
	}

	/* Success */
	*rsrcsp = arg.rsrcs;
	return (0);
}

/*
 * free_rcm_resources()
 *
 *	Free a table of RCM resource names.
 */
void
free_rcm_resources(char **rsrcs)
{
	int	i;

	if (rsrcs != NULL) {
		for (i = 0; rsrcs[i] != NULL; i++)
			free(rsrcs[i]);
		free(rsrcs);
	}
}

/*
 * rcm_offline()
 *
 *	Implement an RCM offline request.
 *
 *	NOTE: errors from RCM will be merged into the snapshot.
 */
int
rcm_offline(char **rsrcs, uint_t flags, hp_node_t root)
{
	rcm_handle_t	*handle;
	rcm_info_t	*info = NULL;
	uint_t		rcm_flags = 0;
	int		rv = 0;

	hp_dprintf("rcm_offline()\n");

	/* Set flags */
	if (flags & HPFORCE)
		rcm_flags |= RCM_FORCE;
	if (flags & HPQUERY)
		rcm_flags |= RCM_QUERY;

	/* Allocate RCM handle */
	if (rcm_alloc_handle(NULL, 0, NULL, &handle) != RCM_SUCCESS) {
		log_err("Cannot allocate RCM handle (%s)\n", strerror(errno));
		return (EFAULT);
	}

	/* Request RCM offline */
	if (rcm_request_offline_list(handle, rsrcs, rcm_flags,
	    &info) != RCM_SUCCESS)
		rv = EBUSY;

	/* RCM handle is no longer needed */
	(void) rcm_free_handle(handle);

	/*
	 * Check if RCM returned any information tuples.  If so,
	 * then also check if the RCM operation failed, and possibly
	 * merge the RCM info into the caller's hotplug snapshot.
	 */
	if (info != NULL) {
		if (rv != 0)
			(void) merge_rcm_info(root, info);
		rcm_free_info(info);
	}

	return (rv);
}

/*
 * rcm_online()
 *
 *	Implement an RCM online notification.
 */
void
rcm_online(char **rsrcs)
{
	rcm_handle_t	*handle;
	rcm_info_t	*info = NULL;

	hp_dprintf("rcm_online()\n");

	if (rcm_alloc_handle(NULL, 0, NULL, &handle) != RCM_SUCCESS) {
		log_err("Cannot allocate RCM handle (%s)\n", strerror(errno));
		return;
	}

	(void) rcm_notify_online_list(handle, rsrcs, 0, &info);

	(void) rcm_free_handle(handle);

	if (info != NULL)
		rcm_free_info(info);
}

/*
 * rcm_remove()
 *
 *	Implement an RCM remove notification.
 */
void
rcm_remove(char **rsrcs)
{
	rcm_handle_t	*handle;
	rcm_info_t	*info = NULL;

	hp_dprintf("rcm_remove()\n");

	if (rcm_alloc_handle(NULL, 0, NULL, &handle) != RCM_SUCCESS) {
		log_err("Cannot allocate RCM handle (%s)\n", strerror(errno));
		return;
	}

	(void) rcm_notify_remove_list(handle, rsrcs, 0, &info);

	(void) rcm_free_handle(handle);

	if (info != NULL)
		rcm_free_info(info);
}

/*
 * get_rcm_usage()
 *
 *	Lookup usage information for a set of resources from RCM.
 */
static int
get_rcm_usage(char **rsrcs, rcm_info_t **info_p)
{
	rcm_handle_t	*handle;
	rcm_info_t	*info = NULL;
	int		rv = 0;

	/* No-op if no RCM resources */
	if (rsrcs == NULL)
		return (0);

	/* Allocate RCM handle */
	if (rcm_alloc_handle(NULL, RCM_NOPID, NULL, &handle) != RCM_SUCCESS) {
		log_err("Cannot allocate RCM handle (%s)\n", strerror(errno));
		return (EFAULT);
	}

	/* Get usage information from RCM */
	if (rcm_get_info_list(handle, rsrcs,
	    RCM_INCLUDE_DEPENDENT | RCM_INCLUDE_SUBTREE,
	    &info) != RCM_SUCCESS) {
		log_err("Failed to get RCM information (%s)\n",
		    strerror(errno));
		rv = EFAULT;
	}

	/* RCM handle is no longer needed */
	(void) rcm_free_handle(handle);

	*info_p = info;
	return (rv);
}

/*
 * merge_rcm_info()
 *
 *	Merge RCM information into a hotplug information snapshot.
 *	First a lookup table is built to map lists of RCM usage to
 *	pathnames.  Then during a full traversal of the snapshot,
 *	the lookup table is used for each node to find matching
 *	RCM info tuples for each path in the snapshot.
 */
static int
merge_rcm_info(hp_node_t root, rcm_info_t *info)
{
	merge_cb_arg_t		arg;
	info_table_t		*table;
	size_t			table_len;
	int			rv;

	/* Build a lookup table, mapping paths to usage information */
	if ((rv = build_table(info, &table, &table_len)) != 0) {
		log_err("Cannot build RCM lookup table (%s)\n", strerror(rv));
		return (rv);
	}

	/* Stop if no valid entries were inserted in table */
	if ((table == NULL) || (table_len == 0)) {
		log_err("Unable to gather RCM usage.\n");
		return (0);
	}

	/* Initialize callback argument */
	(void) memset(&arg, 0, sizeof (merge_cb_arg_t));
	arg.table = table;
	arg.table_len = table_len;

	/* Perform a merge traversal */
	(void) hp_traverse(root, (void *)&arg, merge_callback);

	/* Done with the table */
	free_table(table, table_len);

	/* Check for errors */
	if (arg.error != 0) {
		log_err("Cannot merge RCM information (%s)\n", strerror(rv));
		return (rv);
	}

	return (0);
}

/*
 * resource_callback()
 *
 *	A callback function for hp_traverse() that builds an RCM
 *	compatible list of resource path names.  The array has
 *	been pre-allocated based on results from the related
 *	callback resource_count_callback().
 */
static int
resource_callback(hp_node_t node, void *argp)
{
	resource_cb_arg_t	*arg = (resource_cb_arg_t *)argp;
	char			**new_rsrcs;
	size_t			new_size;
	int			type;

	/* Get node type */
	type = hp_type(node);

	/* Prune OFFLINE ports */
	if ((type == HP_NODE_PORT) && HP_IS_OFFLINE(hp_state(node)))
		return (HP_WALK_PRUNECHILD);

	/* Skip past non-devices */
	if (type != HP_NODE_DEVICE)
		return (HP_WALK_CONTINUE);

	/* Lookup resource path */
	if (hp_path(node, arg->path, arg->connection) != 0) {
		log_err("Cannot get RCM resource path.\n");
		arg->error = EFAULT;
		return (HP_WALK_TERMINATE);
	}

	/* Insert "/devices" to path name */
	(void) snprintf(arg->dev_path, MAXPATHLEN, "/devices%s", arg->path);

	/*
	 * Grow resource array to accomodate new /devices path.
	 * NOTE: include an extra NULL pointer at end of array.
	 */
	new_size = (arg->n_rsrcs + 2) * sizeof (char *);
	if (arg->rsrcs == NULL)
		new_rsrcs = (char **)malloc(new_size);
	else
		new_rsrcs = (char **)realloc(arg->rsrcs, new_size);
	if (new_rsrcs != NULL) {
		arg->rsrcs = new_rsrcs;
	} else {
		log_err("Cannot allocate RCM resource array.\n");
		arg->error = ENOMEM;
		return (HP_WALK_TERMINATE);
	}

	/* Initialize new entries */
	arg->rsrcs[arg->n_rsrcs] = strdup(arg->dev_path);
	arg->rsrcs[arg->n_rsrcs + 1] = NULL;

	/* Check for errors */
	if (arg->rsrcs[arg->n_rsrcs] == NULL) {
		log_err("Cannot allocate RCM resource path.\n");
		arg->error = ENOMEM;
		return (HP_WALK_TERMINATE);
	}

	/* Increment resource count */
	arg->n_rsrcs += 1;

	/* Do not visit children */
	return (HP_WALK_PRUNECHILD);
}

/*
 * merge_callback()
 *
 *	A callback function for hp_traverse() that merges RCM information
 *	tuples into an existing hotplug information snapshot.  The RCM
 *	information will be turned into HP_NODE_USAGE nodes.
 */
static int
merge_callback(hp_node_t node, void *argp)
{
	merge_cb_arg_t	*arg = (merge_cb_arg_t *)argp;
	hp_node_t	usage;
	info_table_t	lookup;
	info_table_t	*slot;
	info_entry_t	*entry;
	int		rv;

	/* Only process device nodes (other nodes cannot have usage) */
	if (hp_type(node) != HP_NODE_DEVICE)
		return (HP_WALK_CONTINUE);

	/* Get path of current node, using buffer provided in 'arg' */
	if ((rv = hp_path(node, arg->path, arg->connection)) != 0) {
		log_err("Cannot lookup hotplug path (%s)\n", strerror(rv));
		arg->error = rv;
		return (HP_WALK_TERMINATE);
	}

	/* Check the lookup table for associated usage */
	lookup.path = arg->path;
	if ((slot = bsearch(&lookup, arg->table, arg->table_len,
	    sizeof (info_table_t), compare_info)) == NULL)
		return (HP_WALK_CONTINUE);

	/* Usage information was found.  Append HP_NODE_USAGE nodes. */
	for (entry = slot->entries; entry != NULL; entry = entry->next) {

		/* Allocate a new usage node */
		usage = (hp_node_t)calloc(1, sizeof (struct hp_node));
		if (usage == NULL) {
			log_err("Cannot allocate hotplug usage node.\n");
			arg->error = ENOMEM;
			return (HP_WALK_TERMINATE);
		}

		/* Initialize the usage node's contents */
		usage->hp_type = HP_NODE_USAGE;
		if ((usage->hp_name = strdup(entry->rsrc)) == NULL) {
			log_err("Cannot allocate hotplug usage node name.\n");
			free(usage);
			arg->error = ENOMEM;
			return (HP_WALK_TERMINATE);
		}
		if ((usage->hp_usage = strdup(entry->usage)) == NULL) {
			log_err("Cannot allocate hotplug usage node info.\n");
			free(usage->hp_name);
			free(usage);
			arg->error = ENOMEM;
			return (HP_WALK_TERMINATE);
		}

		/* Link the usage node as a child of the device node */
		usage->hp_parent = node;
		usage->hp_sibling = node->hp_child;
		node->hp_child = usage;
	}

	return (HP_WALK_CONTINUE);
}

/*
 * build_table()
 *
 *	Build a lookup table that will be used to map paths to their
 *	corresponding RCM information tuples.
 */
static int
build_table(rcm_info_t *info, info_table_t **tablep, size_t *table_lenp)
{
	rcm_info_tuple_t	*tuple;
	info_entry_t		*entry;
	info_table_t		*slot;
	info_table_t		*table;
	size_t			table_len;
	const char		*rsrc;
	const char		*usage;
	char			path[MAXPATHLEN];

	/* Initialize results */
	*tablep = NULL;
	*table_lenp = 0;

	/* Count the RCM info tuples to determine the table's size */
	table_len = 0;
	for (tuple = NULL; (tuple = rcm_info_next(info, tuple)) != NULL; )
		table_len++;

	/* If the table would be empty, then do nothing */
	if (table_len == 0)
		return (ENOENT);

	/* Allocate the lookup table */
	table = (info_table_t *)calloc(table_len, sizeof (info_table_t));
	if (table == NULL)
		return (ENOMEM);

	/*
	 * Fill in the lookup table.  Fill one slot in the table
	 * for each device path that has a set of associated RCM
	 * information tuples.  In some cases multiple tuples will
	 * be joined together within the same slot.
	 */
	slot = NULL;
	table_len = 0;
	for (tuple = NULL; (tuple = rcm_info_next(info, tuple)) != NULL; ) {

		/*
		 * Extract RCM resource name and usage description.
		 *
		 * NOTE: skip invalid tuples to return as much as possible.
		 */
		if (((rsrc = rcm_info_rsrc(tuple)) == NULL) ||
		    ((usage = rcm_info_info(tuple)) == NULL)) {
			log_err("RCM returned invalid resource or usage.\n");
			continue;
		}

		/*
		 * Try to convert the RCM resource name to a hotplug path.
		 * If conversion succeeds and this path differs from the
		 * current slot in the table, then initialize the next
		 * slot in the table.
		 */
		if ((rsrc2path(rsrc, path) == 0) &&
		    ((slot == NULL) || (strcmp(slot->path, path) != 0))) {
			slot = &table[table_len];
			if ((slot->path = strdup(path)) == NULL) {
				log_err("Cannot build info table slot.\n");
				free_table(table, table_len);
				return (ENOMEM);
			}
			table_len++;
		}

		/* Append current usage to entry list in the current slot */
		if (slot != NULL) {

			/* Allocate new entry */
			entry = (info_entry_t *)malloc(sizeof (info_entry_t));
			if (entry == NULL) {
				log_err("Cannot allocate info table entry.\n");
				free_table(table, table_len);
				return (ENOMEM);
			}

			/* Link entry into current slot list */
			entry->next = slot->entries;
			slot->entries = entry;

			/* Initialize entry values */
			if (((entry->rsrc = strdup(rsrc)) == NULL) ||
			    ((entry->usage = strdup(usage)) == NULL)) {
				log_err("Cannot build info table entry.\n");
				free_table(table, table_len);
				return (ENOMEM);
			}
		}
	}

	/* Check if valid entries were inserted in table */
	if (table_len == 0) {
		free(table);
		return (0);
	}

	/* Sort the lookup table by hotplug path */
	qsort(table, table_len, sizeof (info_table_t), compare_info);

	/* Done */
	*tablep = table;
	*table_lenp = table_len;
	return (0);
}

/*
 * free_table()
 *
 *	Destroy a lookup table.
 */
static void
free_table(info_table_t *table, size_t table_len)
{
	info_entry_t	*entry;
	int		index;

	if (table != NULL) {
		for (index = 0; index < table_len; index++) {
			if (table[index].path != NULL)
				free(table[index].path);
			while (table[index].entries != NULL) {
				entry = table[index].entries;
				table[index].entries = entry->next;
				if (entry->rsrc != NULL)
					free(entry->rsrc);
				if (entry->usage != NULL)
					free(entry->usage);
				free(entry);
			}
		}
		free(table);
	}
}

/*
 * rsrc2path()
 *
 *	Convert from an RCM resource name to a hotplug device path.
 */
static int
rsrc2path(const char *rsrc, char *path)
{
	char	*s;
	char	tmp[MAXPATHLEN];

	/* Only convert /dev and /devices paths */
	if (strncmp(rsrc, "/dev", 4) == 0) {

		/* Follow symbolic links for /dev paths */
		if (realpath(rsrc, tmp) == NULL) {
			log_err("Cannot resolve RCM resource (%s)\n",
			    strerror(errno));
			return (-1);
		}

		/* Remove the leading "/devices" part */
		(void) strlcpy(path, &tmp[strlen(S_DEVICES)], MAXPATHLEN);

		/* Remove any trailing minor node part */
		if ((s = strrchr(path, ':')) != NULL)
			*s = '\0';

		/* Successfully converted */
		return (0);
	}

	/* Not converted */
	return (-1);
}

/*
 * compare_info()
 *
 *	Compare two slots in the lookup table that maps paths to usage.
 *
 *	NOTE: for use with qsort() and bsearch().
 */
static int
compare_info(const void *a, const void *b)
{
	info_table_t	*slot_a = (info_table_t *)a;
	info_table_t	*slot_b = (info_table_t *)b;

	return (strcmp(slot_a->path, slot_b->path));
}
