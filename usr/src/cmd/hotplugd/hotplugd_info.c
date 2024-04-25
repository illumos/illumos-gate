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
#include <string.h>
#include <errno.h>
#include <libdevinfo.h>
#include <libhotplug.h>
#include <libhotplug_impl.h>
#include <sys/sunddi.h>
#include <sys/ddi_hp.h>
#include "hotplugd_impl.h"

/*
 * Define a list of hotplug nodes.
 * (Only used within this module.)
 */
typedef struct {
	hp_node_t	head;
	hp_node_t	prev;
} hp_node_list_t;

/*
 * Local functions.
 */
static int		copy_devinfo(const char *, const char *, uint_t,
			    hp_node_t *);
static int		copy_devices(hp_node_t, di_node_t, uint_t, hp_node_t *);
static int		copy_hotplug(hp_node_t, di_node_t, const char *, uint_t,
			    hp_node_t *);
static char		*base_path(const char *);
static int		search_cb(di_node_t, void *);
static int		check_search(di_node_t, uint_t);
static hp_node_t	new_device_node(hp_node_t, di_node_t);
static hp_node_t	new_hotplug_node(hp_node_t, di_hp_t);
static void		node_list_add(hp_node_list_t *, hp_node_t);

/*
 * getinfo()
 *
 *	Build a hotplug information snapshot.  The path, connection,
 *	and flags indicate what information should be included.
 */
int
getinfo(const char *path, const char *connection, uint_t flags, hp_node_t *retp)
{
	hp_node_t	root = NULL;
	hp_node_t	child;
	char		*basepath;
	int		rv;

	if ((path == NULL) || (retp == NULL))
		return (EINVAL);

	hp_dprintf("getinfo: path=%s, connection=%s, flags=0x%x\n", path,
	    (connection == NULL) ? "NULL" : connection, flags);

	/* Allocate the base path */
	if ((basepath = base_path(path)) == NULL)
		return (ENOMEM);

	/* Copy in device and hotplug nodes from libdevinfo */
	if ((rv = copy_devinfo(basepath, connection, flags, &root)) != 0) {
		hp_fini(root);
		free(basepath);
		return (rv);
	}

	/* Check if there were no connections */
	if (root == NULL) {
		hp_dprintf("getinfo: no hotplug connections.\n");
		free(basepath);
		return (ENOENT);
	}

	/* Special case: exclude root nexus from snapshot */
	if (strcmp(basepath, "/") == 0) {
		child = root->hp_child;
		if (root->hp_name != NULL)
			free(root->hp_name);
		free(root);
		root = child;
		for (child = root; child; child = child->hp_sibling)
			child->hp_parent = NULL;
	}

	/* Store a pointer to the base path in each root node */
	for (child = root; child != NULL; child = child->hp_sibling)
		child->hp_basepath = basepath;

	/* Copy in usage information from RCM */
	if (flags & HPINFOUSAGE) {
		if ((rv = copy_usage(root)) != 0) {
			(void) hp_fini(root);
			return (rv);
		}
	}

	*retp = root;
	return (0);
}

/*
 * copy_devinfo()
 *
 *	Copy information about device and hotplug nodes from libdevinfo.
 *
 *	When path is set to "/", the results need to be limited only to
 *	branches that contain hotplug information.  An initial search
 *	is performed to mark which branches contain hotplug nodes.
 */
static int
copy_devinfo(const char *path, const char *connection, uint_t flags,
    hp_node_t *rootp)
{
	hp_node_t	hp_root = NULL;
	di_node_t	di_root;
	int		rv;

	/* Get libdevinfo snapshot */
	if ((di_root = di_init(path, DINFOSUBTREE | DINFOHP)) == DI_NODE_NIL)
		return (errno);

	/* Do initial search pass, if required */
	if (strcmp(path, "/") == 0) {
		flags |= HPINFOSEARCH;
		(void) di_walk_node(di_root, DI_WALK_CLDFIRST, NULL, search_cb);
	}

	/*
	 * If a connection is specified, just copy immediate hotplug info.
	 * Else, copy the device tree normally.
	 */
	if (connection != NULL)
		rv = copy_hotplug(NULL, di_root, connection, flags, &hp_root);
	else
		rv = copy_devices(NULL, di_root, flags, &hp_root);

	/* Destroy devinfo snapshot */
	di_fini(di_root);

	*rootp = (rv == 0) ? hp_root : NULL;
	return (rv);
}

/*
 * copy_devices()
 *
 *	Copy a full branch of device nodes.  Used by copy_devinfo() and
 *	copy_hotplug().
 */
static int
copy_devices(hp_node_t parent, di_node_t dev, uint_t flags, hp_node_t *rootp)
{
	hp_node_list_t	children;
	hp_node_t	self, branch;
	di_node_t	child;
	int		rv = 0;

	/* Initialize results */
	*rootp = NULL;

	/* Enforce search semantics */
	if (check_search(dev, flags) == 0)
		return (0);

	/* Allocate new node for current device */
	if ((self = new_device_node(parent, dev)) == NULL)
		return (ENOMEM);

	/*
	 * If the device has hotplug nodes, then use copy_hotplug()
	 * instead to build the branch associated with current device.
	 */
	if (di_hp_next(dev, DI_HP_NIL) != DI_HP_NIL) {
		if ((rv = copy_hotplug(self, dev, NULL, flags,
		    &self->hp_child)) != 0) {
			free(self);
			return (rv);
		}
		*rootp = self;
		return (0);
	}

	/*
	 * The device does not have hotplug nodes.  Use normal
	 * approach of iterating through its child device nodes.
	 */
	(void) memset(&children, 0, sizeof (hp_node_list_t));
	for (child = di_child_node(dev); child != DI_NODE_NIL;
	    child = di_sibling_node(child)) {
		branch = NULL;
		if ((rv = copy_devices(self, child, flags, &branch)) != 0) {
			(void) hp_fini(children.head);
			free(self);
			return (rv);
		}
		if (branch != NULL)
			node_list_add(&children, branch);
	}
	self->hp_child = children.head;

	/* Done */
	*rootp = self;
	return (0);
}

/*
 * copy_hotplug()
 *
 *	Copy a full branch of hotplug nodes.  Used by copy_devinfo()
 *	and copy_devices().
 *
 *	If a connection is specified, the results are limited only
 *	to the branch associated with that specific connection.
 */
static int
copy_hotplug(hp_node_t parent, di_node_t dev, const char *connection,
    uint_t flags, hp_node_t *retp)
{
	hp_node_list_t	connections, ports;
	hp_node_t	node, port_node;
	di_node_t	child_dev;
	di_hp_t		hp, port_hp;
	uint_t		child_flags;
	int		rv, physnum;

	/* Stop implementing the HPINFOSEARCH flag */
	child_flags = flags & ~(HPINFOSEARCH);

	/* Clear lists of discovered ports and connections */
	(void) memset(&ports, 0, sizeof (hp_node_list_t));
	(void) memset(&connections, 0, sizeof (hp_node_list_t));

	/*
	 * Scan virtual ports.
	 *
	 * If a connection is specified and it matches a virtual port,
	 * this will build the branch associated with that connection.
	 * Else, this will only build branches for virtual ports that
	 * are not associated with a physical connector.
	 */
	for (hp = DI_HP_NIL; (hp = di_hp_next(dev, hp)) != DI_HP_NIL; ) {

		/* Ignore connectors */
		if (di_hp_type(hp) != DDI_HP_CN_TYPE_VIRTUAL_PORT)
			continue;

		/*
		 * Ignore ports associated with connectors, unless
		 * a specific connection is being sought.
		 */
		if ((connection == NULL) && (di_hp_depends_on(hp) != -1))
			continue;

		/* If a connection is specified, ignore non-matching ports */
		if ((connection != NULL) &&
		    (strcmp(di_hp_name(hp), connection) != 0))
			continue;

		/* Create a new port node */
		if ((node = new_hotplug_node(parent, hp)) == NULL) {
			rv = ENOMEM;
			goto fail;
		}

		/* Add port node to connection list */
		node_list_add(&connections, node);

		/* Add branch of child devices to port node */
		if ((child_dev = di_hp_child(hp)) != DI_NODE_NIL)
			if ((rv = copy_devices(node, child_dev, child_flags,
			    &node->hp_child)) != 0)
				goto fail;
	}

	/*
	 * Scan physical connectors.
	 *
	 * If a connection is specified, the results will be limited
	 * only to the branch associated with that connection.
	 */
	for (hp = DI_HP_NIL; (hp = di_hp_next(dev, hp)) != DI_HP_NIL; ) {

		/* Ignore ports */
		if (di_hp_type(hp) == DDI_HP_CN_TYPE_VIRTUAL_PORT)
			continue;

		/* If a connection is specified, ignore non-matching ports */
		if ((connection != NULL) &&
		    (strcmp(di_hp_name(hp), connection) != 0))
			continue;

		/* Create a new connector node */
		if ((node = new_hotplug_node(parent, hp)) == NULL) {
			rv = ENOMEM;
			goto fail;
		}

		/* Add connector node to connection list */
		node_list_add(&connections, node);

		/* Add branches of associated port nodes */
		physnum = di_hp_connection(hp);
		port_hp = DI_HP_NIL;
		while ((port_hp = di_hp_next(dev, port_hp)) != DI_HP_NIL) {

			/* Ignore irrelevant connections */
			if (di_hp_depends_on(port_hp) != physnum)
				continue;

			/* Add new port node to port list */
			if ((port_node = new_hotplug_node(node,
			    port_hp)) == NULL) {
				rv = ENOMEM;
				goto fail;
			}
			node_list_add(&ports, port_node);

			/* Add branch of child devices */
			if ((child_dev = di_hp_child(port_hp)) != DI_NODE_NIL) {
				if ((rv = copy_devices(port_node, child_dev,
				    child_flags, &port_node->hp_child)) != 0)
					goto fail;
			}
		}
		node->hp_child = ports.head;
		(void) memset(&ports, 0, sizeof (hp_node_list_t));
	}

	if (connections.head == NULL)
		return (ENXIO);
	*retp = connections.head;
	return (0);

fail:
	(void) hp_fini(ports.head);
	(void) hp_fini(connections.head);
	return (rv);
}

/*
 * base_path()
 *
 *	Normalize the base path of a hotplug information snapshot.
 *	The caller must free the string that is allocated.
 */
static char *
base_path(const char *path)
{
	char	*base_path;
	size_t	devices_len;

	devices_len = strlen(S_DEVICES);

	if (strncmp(path, S_DEVICES, devices_len) == 0)
		base_path = strdup(&path[devices_len]);
	else
		base_path = strdup(path);

	return (base_path);
}

/*
 * search_cb()
 *
 *	Callback function used by di_walk_node() to search for branches
 *	of the libdevinfo snapshot that contain hotplug nodes.
 */
/*ARGSUSED*/
static int
search_cb(di_node_t node, void *arg)
{
	di_node_t	parent;
	uint_t		flags;

	(void) di_node_private_set(node, (void *)(uintptr_t)0);

	if (di_hp_next(node, DI_HP_NIL) == DI_HP_NIL)
		return (DI_WALK_CONTINUE);

	for (parent = node; parent != DI_NODE_NIL;
	    parent = di_parent_node(parent)) {
		flags = (uint_t)(uintptr_t)di_node_private_get(parent);
		flags |= HPINFOSEARCH;
		(void) di_node_private_set(parent, (void *)(uintptr_t)flags);
	}

	return (DI_WALK_CONTINUE);
}

/*
 * check_search()
 *
 *	Check if a device node was marked by an initial search pass.
 */
static int
check_search(di_node_t dev, uint_t flags)
{
	uint_t	dev_flags;

	if (flags & HPINFOSEARCH) {
		dev_flags = (uint_t)(uintptr_t)di_node_private_get(dev);
		if ((dev_flags & HPINFOSEARCH) == 0)
			return (0);
	}

	return (1);
}

/*
 * node_list_add()
 *
 *	Utility function to append one node to a list of hotplug nodes.
 */
static void
node_list_add(hp_node_list_t *listp, hp_node_t node)
{
	if (listp->prev != NULL)
		listp->prev->hp_sibling = node;
	else
		listp->head = node;

	listp->prev = node;
}

/*
 * new_device_node()
 *
 *	Build a new hotplug node based on a specified devinfo node.
 */
static hp_node_t
new_device_node(hp_node_t parent, di_node_t dev)
{
	hp_node_t	node;
	char		*node_name, *bus_addr;
	char		name[MAXPATHLEN];

	node = (hp_node_t)calloc(1, sizeof (struct hp_node));

	if (node != NULL) {
		node->hp_parent = parent;
		node->hp_type = HP_NODE_DEVICE;

		node_name = di_node_name(dev);
		bus_addr = di_bus_addr(dev);
		if (bus_addr && (strlen(bus_addr) > 0)) {
			if (snprintf(name, sizeof (name), "%s@%s", node_name,
			    bus_addr) >= sizeof (name)) {
				log_err("Path too long for device node.\n");
				free(node);
				return (NULL);
			}
			node->hp_name = strdup(name);
		} else
			node->hp_name = strdup(node_name);
	}

	return (node);
}

/*
 * new_hotplug_node()
 *
 *	Build a new hotplug node based on a specified devinfo hotplug node.
 */
static hp_node_t
new_hotplug_node(hp_node_t parent, di_hp_t hp)
{
	hp_node_t	node;
	char		*s;

	node = (hp_node_t)calloc(1, sizeof (struct hp_node));

	if (node != NULL) {
		node->hp_parent = parent;
		node->hp_state = di_hp_state(hp);
		node->hp_last_change = di_hp_last_change(hp);
		if ((s = di_hp_name(hp)) != NULL)
			node->hp_name = strdup(s);
		if ((s = di_hp_description(hp)) != NULL)
			node->hp_description = strdup(s);
		if (di_hp_type(hp) == DDI_HP_CN_TYPE_VIRTUAL_PORT)
			node->hp_type = HP_NODE_PORT;
		else
			node->hp_type = HP_NODE_CONNECTOR;
	}

	return (node);
}
