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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <libdevinfo.h>
#include <inetcfg.h>

/*
 * Always traverse the device tree from the root.
 */
#define	NIC_DEVTREE_ROOT	"/"

/*
 * Private structure used to create a linked list
 * of interfaces.
 */
typedef struct niclist {
	struct niclist	*nl_next;
	char		nl_name[LIFNAMSIZ];
} niclist_t;

/*
 * Private structure used by di_walk_minor().
 */
typedef struct wlkreq {
	niclist_t	**wr_niclist;
	int		*wr_numif;
	int		*wr_syserr;
	int		*wr_err;
} wlkreq_t;

/*
 * Called by di_walk_node() to walk the list of device nodes and
 * force all nodes of type "network" to be loaded.
 *
 * Returns: DI_WALK_CONTINUE
 */
static int
process_node(di_node_t node, void *arg)
{
	di_prom_handle_t ph = (di_prom_handle_t)arg;
	char *pdevtype;
	int ret;

	/*
	 * Only want to process nodes whose device_type is "network".
	 */
	ret = di_prom_prop_lookup_strings(ph, node, "device_type", &pdevtype);
	if ((ret <= 0) || (strcmp(pdevtype, "network") != 0)) {
		return (DI_WALK_CONTINUE);
	}

	/*
	 * If the instance is '-1', then the driver for the device
	 * has not been loaded - so force it to be loaded. Ignore
	 * errors loading the driver.
	 */
	if (di_instance(node) == -1) {
		node = di_init_driver(di_driver_name(node), 0);
		if (node != DI_NODE_NIL) {
			di_fini(node);
		}
	}
	return (DI_WALK_CONTINUE);
}

/*
 * Force all "network" drivers to be loaded.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE. In the case of
 *          ICFG_FAILURE, syserr will contain the errno.
 */
static int
nic_load_drivers(int *syserr)
{
	di_node_t root_node;
	di_prom_handle_t ph;
	int ret;

	root_node = di_init(NIC_DEVTREE_ROOT, DINFOCPYALL);
	if (root_node == DI_NODE_NIL) {
		*syserr = errno;
		return (ICFG_FAILURE);
	}

	/*
	 * Create handle to PROM
	 */
	if ((ph = di_prom_init()) == DI_PROM_HANDLE_NIL) {
		*syserr = errno;
		di_fini(root_node);
		return (ICFG_FAILURE);
	}

	/*
	 * Walk nodes and make sure all network devices have
	 * drivers loaded so that devinfo has accurate data.
	 */
	ret = di_walk_node(root_node, DI_WALK_CLDFIRST, ph, process_node);
	if (ret != 0) {
		*syserr = errno;
		di_prom_fini(ph);
		di_fini(root_node);
		return (ICFG_FAILURE);
	}

	/*
	 * Clean up handles
	 */
	di_prom_fini(ph);
	di_fini(root_node);

	return (ICFG_SUCCESS);
}

/*
 * Add an interface to the niclist.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE. In the case of
 *          ICFG_FAILURE, syserr will contain the errno.
 */
static int
nic_add(niclist_t **niclist, char *name, int instance, int *syserr)
{

	niclist_t *entry;

	/*
	 * Allocate new niclist.
	 */
	if ((entry = (niclist_t *)calloc(1, sizeof (niclist_t))) == NULL) {
		*syserr = errno;
		return (ICFG_FAILURE);
	}

	/*
	 * If instance is -1, then no need to append instance.
	 */
	if (instance == -1) {
		(void) strlcpy(entry->nl_name, name, sizeof (entry->nl_name));
	} else {
		(void) snprintf(entry->nl_name, sizeof (entry->nl_name),
		    "%s%d", name, instance);
	}

	/*
	 * Add entry to list.
	 */
	entry->nl_next = *niclist;
	*niclist = entry;

	return (ICFG_SUCCESS);
}

/*
 * Called by di_walk_minor() to walk the list
 * of ddi_network minor device nodes and add
 * the interface to the niclist.
 *
 * Returns: DI_WALK_CONTINUE or DI_WALK_TERMINATE.
 */
static int
nic_process_minor_nodes(di_node_t node, di_minor_t minor, void *arg)
{
	wlkreq_t *request = (wlkreq_t *)arg;
	niclist_t **niclist = request->wr_niclist;
	char *name;
	char *nodetype;
	int instance;
	int ret;

	/*
	 * Look for network devices only. Unfortunately, our walk will
	 * include nodes with nodetypes of NULL.
	 */
	nodetype = di_minor_nodetype(minor);
	if ((nodetype == NULL) || (strcmp(nodetype, DDI_NT_NET) != 0)) {
		return (DI_WALK_CONTINUE);
	}

	/*
	 * In the case of DDM_MINOR minor nodes, the minor
	 * name is the name of the driver. However, if the name
	 * doesn't include the instance, then it's not one
	 * one we're interested in. In the case of other
	 * minor nodes, we should be able to get the driver name
	 * and its instance from the node properties. If they are
	 * not valid, then we're not interested in them.
	 */
	if (di_minor_type(minor) == DDM_MINOR) {
		name = di_minor_name(minor);
		if ((name == NULL) || (strlen(name) == 0) ||
		    (!isdigit(name[strlen(name) - 1]))) {
			return (DI_WALK_CONTINUE);
		}
		instance = -1;
	} else {
		name = di_driver_name(node);
		instance = di_instance(node);
		if ((name == NULL) || (strlen(name) == 0) ||
		    (instance == -1)) {
			return (DI_WALK_CONTINUE);
		}
	}

	/*
	 * Add this one to the niclist.
	 */
	ret = nic_add(niclist, name, instance, request->wr_syserr);
	if (ret != ICFG_SUCCESS) {
		(*request->wr_err) = ret;
		return (DI_WALK_TERMINATE);
	}
	(*request->wr_numif)++;

	return (DI_WALK_CONTINUE);

}

/*
 * Frees the resources associated with a niclist.
 */
static void
nic_free_list(niclist_t *niclist)
{
	niclist_t *entry;

	for (entry = niclist; entry != NULL; entry = niclist) {
		niclist = niclist->nl_next;
		free(entry);
	}
}

/*
 * Drives the walk of the network minor device nodes to
 * build the niclist.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE. In the case of
 *          ICFG_FAILURE, syserr will contain the errno.
 */
static int
nic_build_list(niclist_t **niclist, int *numif, int *syserr)
{
	wlkreq_t request;
	di_node_t root_node;
	int err = ICFG_SUCCESS;
	int ret;

	root_node = di_init(NIC_DEVTREE_ROOT, DINFOSUBTREE | DINFOMINOR);
	if (root_node == DI_NODE_NIL) {
		*syserr = errno;
		return (ICFG_FAILURE);
	}

	/*
	 * di_walk_minor() only allows one arg to be passed to walker.
	 */
	request.wr_niclist = niclist;
	request.wr_numif = numif;
	request.wr_syserr = syserr;
	request.wr_err = &err;

	ret = di_walk_minor(root_node, DDI_NT_NET, DI_CHECK_ALIAS, &request,
	    nic_process_minor_nodes);
	if (ret != 0) {
		*syserr = errno;
		di_fini(root_node);
		return (ICFG_FAILURE);
	}

	/*
	 * On error, free the partially formed list.
	 */
	if (err != ICFG_SUCCESS) {
		nic_free_list(*niclist);
		*numif = 0;
	}

	di_fini(root_node);
	return (err);
}

/*
 * Convert a niclist into an icfg_if_t array.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE. In the case of
 *          ICFG_FAILURE, syserr will contain the errno.
 */
static int
nic_convert_list(icfg_if_t **list, niclist_t *niclist, int numif,
    int *syserr)
{
	icfg_if_t *listp;
	niclist_t *entry;

	if ((listp = calloc(numif, sizeof (icfg_if_t))) == NULL) {
		*syserr = errno;
		return (ICFG_FAILURE);
	}
	*list = listp;

	for (entry = niclist; entry != NULL; entry = entry->nl_next) {
		(void) strlcpy(listp->if_name, entry->nl_name,
		    sizeof (listp->if_name));
		listp->if_protocol = AF_UNSPEC;
		listp++;
	}

	return (ICFG_SUCCESS);
}

/*
 * Returns the list of network devices installed
 * on the machine as an icfg_if_t array.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE. In the case of
 *          ICFG_FAILURE,  errno will be set.
 */
int
nic_get_list(icfg_if_t **list, int *numif)
{
	niclist_t *niclist = NULL;
	int syserr;
	int ret;

	if ((ret = nic_load_drivers(&syserr)) != ICFG_SUCCESS) {
		goto out;
	}

	if ((ret = nic_build_list(&niclist, numif, &syserr)) != ICFG_SUCCESS) {
		goto out;
	}

	if ((ret = nic_convert_list(list, niclist, *numif, &syserr)) !=
	    ICFG_SUCCESS) {
		goto out;
	}

out:
	nic_free_list(niclist);
	errno = syserr;
	return (ret);
}
