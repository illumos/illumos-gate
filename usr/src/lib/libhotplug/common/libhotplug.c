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
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <door.h>
#include <libnvpair.h>
#include <libhotplug.h>
#include <libhotplug_impl.h>
#include <sys/sunddi.h>
#include <sys/ddi_hp.h>

static void	i_hp_dprintf(const char *fmt, ...);
static int	i_hp_pack_branch(hp_node_t, char **, size_t *);
static int	i_hp_pack_node(hp_node_t, char **, size_t *);
static int	i_hp_unpack_node(char *, size_t, hp_node_t, hp_node_t *);
static int	i_hp_unpack_branch(char *, size_t, hp_node_t, hp_node_t *);
static int	i_hp_call_hotplugd(nvlist_t *, nvlist_t **);
static nvlist_t	*i_hp_set_args(hp_cmd_t, const char *, const char *, uint_t,
		    const char *, int);
static int	i_hp_parse_results(nvlist_t *, hp_node_t *, char **);

/*
 * Global flag to enable debug features.
 */
int	libhotplug_debug = 0;

/*
 * hp_init()
 *
 *	Initialize a hotplug information snapshot.
 */
hp_node_t
hp_init(const char *path, const char *connection, uint_t flags)
{
	nvlist_t	*args;
	nvlist_t	*results;
	hp_node_t	root = NULL;
	int		rv;

	i_hp_dprintf("hp_init: path=%p, connection=%p, flags=0x%x\n",
	    (void *)path, (void *)connection, flags);

	/* Check arguments */
	if ((path == NULL) || !HP_INIT_FLAGS_VALID(flags)) {
		i_hp_dprintf("hp_init: invalid arguments.\n");
		errno = EINVAL;
		return (NULL);
	}

	/* Build arguments for door call */
	if ((args = i_hp_set_args(HP_CMD_GETINFO, path, connection, flags,
	    NULL, 0)) == NULL) {
		i_hp_dprintf("hp_init: cannot build arguments nvlist.\n");
		errno = ENOMEM;
		return (NULL);
	}

	/* Make the door call to hotplugd */
	rv = i_hp_call_hotplugd(args, &results);

	/* Arguments no longer needed */
	nvlist_free(args);

	/* Parse additional results, if any */
	if ((rv == 0) && (results != NULL)) {
		rv = i_hp_parse_results(results, &root, NULL);
		nvlist_free(results);
	}

	/* Check for errors */
	if (rv != 0) {
		i_hp_dprintf("hp_init: failure (%s).\n", strerror(rv));
		if (root)
			hp_fini(root);
		errno = rv;
		return (NULL);
	}

	/* Success requires an info snapshot */
	if (root == NULL) {
		i_hp_dprintf("hp_init: missing info snapshot.\n");
		errno = EFAULT;
		return (NULL);
	}

	/* Success */
	return (root);
}

/*
 * hp_fini()
 *
 *	Terminate and clean-up a hotplug information snapshot.
 */
void
hp_fini(hp_node_t root)
{
	hp_node_t	node;
	hp_node_t	sibling;
	char		*basepath;

	i_hp_dprintf("hp_fini: root=%p\n", (void *)root);

	if (root == NULL) {
		i_hp_dprintf("hp_fini: invalid arguments.\n");
		return;
	}

	/* Extract and free base path */
	if (root->hp_basepath) {
		basepath = root->hp_basepath;
		for (node = root; node != NULL; node = node->hp_sibling)
			node->hp_basepath = NULL;
		free(basepath);
	}

	/* Destroy the nodes */
	node = root;
	while (node) {
		sibling = node->hp_sibling;
		if (node->hp_child)
			hp_fini(node->hp_child);
		if (node->hp_name)
			free(node->hp_name);
		if (node->hp_usage)
			free(node->hp_usage);
		if (node->hp_description)
			free(node->hp_description);
		free(node);
		node = sibling;
	}
}

/*
 * hp_traverse()
 *
 *	Walk a graph of hotplug nodes, executing a callback on each node.
 */
int
hp_traverse(hp_node_t root, void *arg, int (*hp_callback)(hp_node_t, void *arg))
{
	int		rv;
	hp_node_t	node;

	i_hp_dprintf("hp_traverse: root=%p, arg=%p, hp_callback=%p\n",
	    (void *)root, arg, (void *)hp_callback);

	/* Check arguments */
	if ((root == NULL) || (hp_callback == NULL)) {
		i_hp_dprintf("hp_traverse: invalid arguments.\n");
		errno = EINVAL;
		return (-1);
	}

	for (node = root; node; node = node->hp_sibling) {
		rv = hp_callback(node, arg);

		if (rv == HP_WALK_TERMINATE) {
			i_hp_dprintf("hp_traverse: walk terminated.\n");
			return (HP_WALK_TERMINATE);
		}

		if (node->hp_child && (rv != HP_WALK_PRUNECHILD))
			if (hp_traverse(node->hp_child, arg, hp_callback) ==
			    HP_WALK_TERMINATE) {
				i_hp_dprintf("hp_traverse: walk terminated.\n");
				return (HP_WALK_TERMINATE);
			}

		if (rv == HP_WALK_PRUNESIBLING)
			break;
	}

	return (0);
}

/*
 * hp_type()
 *
 *	Return a node's type.
 */
int
hp_type(hp_node_t node)
{
	i_hp_dprintf("hp_type: node=%p\n", (void *)node);

	if (node == NULL) {
		i_hp_dprintf("hp_type: invalid arguments.\n");
		errno = EINVAL;
		return (-1);
	}

	return (node->hp_type);
}

/*
 * hp_name()
 *
 *	Return a node's name.
 */
char *
hp_name(hp_node_t node)
{
	i_hp_dprintf("hp_name: node=%p\n", (void *)node);

	if (node == NULL) {
		i_hp_dprintf("hp_name: invalid arguments.\n");
		errno = EINVAL;
		return (NULL);
	}

	if (node->hp_name == NULL) {
		i_hp_dprintf("hp_name: missing name value.\n");
		errno = EFAULT;
	}

	return (node->hp_name);
}

/*
 * hp_state()
 *
 *	Return a node's current state.
 */
int
hp_state(hp_node_t node)
{
	i_hp_dprintf("hp_state: node=%p\n", (void *)node);

	if (node == NULL) {
		i_hp_dprintf("hp_state: invalid arguments.\n");
		errno = EINVAL;
		return (-1);
	}

	if ((node->hp_type != HP_NODE_CONNECTOR) &&
	    (node->hp_type != HP_NODE_PORT)) {
		i_hp_dprintf("hp_state: operation not supported.\n");
		errno = ENOTSUP;
		return (-1);
	}

	return (node->hp_state);
}

/*
 * hp_usage()
 *
 *	Return a usage description for usage nodes.
 */
char *
hp_usage(hp_node_t node)
{
	i_hp_dprintf("hp_usage: node=%p\n", (void *)node);

	if (node == NULL) {
		i_hp_dprintf("hp_usage: invalid arguments.\n");
		errno = EINVAL;
		return (NULL);
	}

	if (node->hp_type != HP_NODE_USAGE) {
		i_hp_dprintf("hp_usage: operation not supported.\n");
		errno = ENOTSUP;
		return (NULL);
	}

	if (node->hp_usage == NULL) {
		i_hp_dprintf("hp_usage: missing usage value.\n");
		errno = EFAULT;
	}

	return (node->hp_usage);
}

/*
 * hp_description()
 *
 *	Return a type description (e.g. "PCI slot") for connection nodes.
 */
char *
hp_description(hp_node_t node)
{
	i_hp_dprintf("hp_description: node=%p\n", (void *)node);

	if (node == NULL) {
		i_hp_dprintf("hp_description: invalid arguments.\n");
		errno = EINVAL;
		return (NULL);
	}

	if ((node->hp_type != HP_NODE_CONNECTOR) &&
	    (node->hp_type != HP_NODE_PORT)) {
		i_hp_dprintf("hp_description: operation not supported.\n");
		errno = ENOTSUP;
		return (NULL);
	}

	if (node->hp_description == NULL) {
		i_hp_dprintf("hp_description: missing description value.\n");
		errno = EFAULT;
	}

	return (node->hp_description);
}

/*
 * hp_last_change()
 *
 *	Return when the state of a connection was last changed.
 */
time_t
hp_last_change(hp_node_t node)
{
	i_hp_dprintf("hp_last_change: node=%p\n", (void *)node);

	if (node == NULL) {
		i_hp_dprintf("hp_last_change: invalid arguments.\n");
		errno = EINVAL;
		return (NULL);
	}

	if ((node->hp_type != HP_NODE_CONNECTOR) &&
	    (node->hp_type != HP_NODE_PORT)) {
		i_hp_dprintf("hp_last_change: operation not supported.\n");
		errno = ENOTSUP;
		return (NULL);
	}

	return (node->hp_last_change);
}

/*
 * hp_parent()
 *
 *	Return a node's parent node.
 */
hp_node_t
hp_parent(hp_node_t node)
{
	i_hp_dprintf("hp_parent: node=%p\n", (void *)node);

	if (node == NULL) {
		i_hp_dprintf("hp_parent: invalid arguments.\n");
		errno = EINVAL;
		return (NULL);
	}

	if (node->hp_parent == NULL) {
		i_hp_dprintf("hp_parent: node has no parent.\n");
		errno = ENXIO;
	}

	return (node->hp_parent);
}

/*
 * hp_child()
 *
 *	Return a node's first child node.
 */
hp_node_t
hp_child(hp_node_t node)
{
	i_hp_dprintf("hp_child: node=%p\n", (void *)node);

	if (node == NULL) {
		i_hp_dprintf("hp_child: invalid arguments.\n");
		errno = EINVAL;
		return (NULL);
	}

	if (node->hp_child == NULL) {
		i_hp_dprintf("hp_child: node has no child.\n");
		errno = ENXIO;
	}

	return (node->hp_child);
}

/*
 * hp_sibling()
 *
 *	Return a node's next sibling node.
 */
hp_node_t
hp_sibling(hp_node_t node)
{
	i_hp_dprintf("hp_sibling: node=%p\n", (void *)node);

	if (node == NULL) {
		i_hp_dprintf("hp_sibling: invalid arguments.\n");
		errno = EINVAL;
		return (NULL);
	}

	if (node->hp_sibling == NULL) {
		i_hp_dprintf("hp_sibling: node has no sibling.\n");
		errno = ENXIO;
	}

	return (node->hp_sibling);
}

/*
 * hp_path()
 *
 *	Return the path (and maybe connection name) of a node.
 *	The caller must supply two buffers, each MAXPATHLEN size.
 */
int
hp_path(hp_node_t node, char *path, char *connection)
{
	hp_node_t	root = NULL;
	hp_node_t	parent;
	int		i;
	char		*s;
	char		components[MAXPATHLEN];

	i_hp_dprintf("hp_path: node=%p, path=%p, connection=%p\n", (void *)node,
	    (void *)path, (void *)connection);

	if ((node == NULL) || (path == NULL) || (connection == NULL)) {
		i_hp_dprintf("hp_path: invalid arguments.\n");
		return (EINVAL);
	}

	(void) memset(path, 0, MAXPATHLEN);
	(void) memset(connection, 0, MAXPATHLEN);
	(void) memset(components, 0, MAXPATHLEN);

	/*  Set 'connection' only for connectors and ports */
	if ((node->hp_type == HP_NODE_CONNECTOR) ||
	    (node->hp_type == HP_NODE_PORT))
		(void) strlcpy(connection, node->hp_name, MAXPATHLEN);

	/* Trace back to the root node, accumulating components */
	for (parent = node; parent != NULL; parent = parent->hp_parent) {
		if (parent->hp_type == HP_NODE_DEVICE) {
			(void) strlcat(components, "/", MAXPATHLEN);
			(void) strlcat(components, parent->hp_name, MAXPATHLEN);
		}
		if (parent->hp_parent == NULL)
			root = parent;
	}

	/* Ensure the snapshot actually contains a base path */
	if (root->hp_basepath == NULL) {
		i_hp_dprintf("hp_path: missing base pathname.\n");
		return (EFAULT);
	}

	/*
	 * Construct the path.  Start with the base path from the root
	 * node, then append the accumulated components in reverse order.
	 */
	if (strcmp(root->hp_basepath, "/") != 0) {
		(void) strlcat(path, root->hp_basepath, MAXPATHLEN);
		if ((root->hp_type == HP_NODE_DEVICE) &&
		    ((s = strrchr(path, '/')) != NULL))
			*s = '\0';
	}
	for (i = strlen(components) - 1; i >= 0; i--) {
		if (components[i] == '/') {
			(void) strlcat(path, &components[i], MAXPATHLEN);
			components[i] = '\0';
		}
	}

	return (0);
}

/*
 * hp_set_state()
 *
 *	Initiate a state change operation on a node.
 */
int
hp_set_state(hp_node_t node, uint_t flags, int state, hp_node_t *resultsp)
{
	hp_node_t	root = NULL;
	nvlist_t	*args;
	nvlist_t	*results;
	int		rv;
	char		path[MAXPATHLEN];
	char		connection[MAXPATHLEN];

	i_hp_dprintf("hp_set_state: node=%p, flags=0x%x, state=0x%x, "
	    "resultsp=%p\n", (void *)node, flags, state, (void *)resultsp);

	/* Check arguments */
	if ((node == NULL) || (resultsp == NULL) ||
	    !HP_SET_STATE_FLAGS_VALID(flags)) {
		i_hp_dprintf("hp_set_state: invalid arguments.\n");
		return (EINVAL);
	}

	/* Check node type */
	if ((node->hp_type != HP_NODE_CONNECTOR) &&
	    (node->hp_type != HP_NODE_PORT)) {
		i_hp_dprintf("hp_set_state: operation not supported.\n");
		return (ENOTSUP);
	}

	/* Check that target state is valid */
	switch (state) {
	case DDI_HP_CN_STATE_PRESENT:
	case DDI_HP_CN_STATE_POWERED:
	case DDI_HP_CN_STATE_ENABLED:
		if (node->hp_type != HP_NODE_CONNECTOR) {
			i_hp_dprintf("hp_set_state: mismatched target.\n");
			return (ENOTSUP);
		}
		break;
	case DDI_HP_CN_STATE_PORT_PRESENT:
	case DDI_HP_CN_STATE_OFFLINE:
	case DDI_HP_CN_STATE_ONLINE:
		if (node->hp_type != HP_NODE_PORT) {
			i_hp_dprintf("hp_set_state: mismatched target.\n");
			return (ENOTSUP);
		}
		break;
	default:
		i_hp_dprintf("hp_set_state: invalid target state.\n");
		return (EINVAL);
	}

	/* Get path and connection of specified node */
	if ((rv = hp_path(node, path, connection)) != 0)
		return (rv);

	/* Build arguments for door call */
	if ((args = i_hp_set_args(HP_CMD_CHANGESTATE, path, connection, flags,
	    NULL, state)) == NULL)
		return (ENOMEM);

	/* Make the door call to hotplugd */
	rv = i_hp_call_hotplugd(args, &results);

	/* Arguments no longer needed */
	nvlist_free(args);

	/* Parse additional results, if any */
	if ((rv == 0) && (results != NULL)) {
		rv = i_hp_parse_results(results, &root, NULL);
		nvlist_free(results);
		*resultsp = root;
	}

	/* Done */
	return (rv);
}

/*
 * hp_set_private()
 *
 *	Set bus private options on the hotplug connection
 *	indicated by the given hotplug information node.
 */
int
hp_set_private(hp_node_t node, const char *options, char **resultsp)
{
	int		rv;
	nvlist_t	*args;
	nvlist_t	*results;
	char		*values = NULL;
	char		path[MAXPATHLEN];
	char		connection[MAXPATHLEN];

	i_hp_dprintf("hp_set_private: node=%p, options=%p, resultsp=%p\n",
	    (void *)node, (void *)options, (void *)resultsp);

	/* Check arguments */
	if ((node == NULL) || (options == NULL) || (resultsp == NULL)) {
		i_hp_dprintf("hp_set_private: invalid arguments.\n");
		return (EINVAL);
	}

	/* Check node type */
	if (node->hp_type != HP_NODE_CONNECTOR) {
		i_hp_dprintf("hp_set_private: operation not supported.\n");
		return (ENOTSUP);
	}

	/* Initialize results */
	*resultsp = NULL;

	/* Get path and connection of specified node */
	if ((rv = hp_path(node, path, connection)) != 0)
		return (rv);

	/* Build arguments for door call */
	if ((args = i_hp_set_args(HP_CMD_SETPRIVATE, path, connection, 0,
	    options, 0)) == NULL)
		return (ENOMEM);

	/* Make the door call to hotplugd */
	rv = i_hp_call_hotplugd(args, &results);

	/* Arguments no longer needed */
	nvlist_free(args);

	/* Parse additional results, if any */
	if ((rv == 0) && (results != NULL)) {
		rv = i_hp_parse_results(results, NULL, &values);
		nvlist_free(results);
		*resultsp = values;
	}

	/* Done */
	return (rv);
}

/*
 * hp_get_private()
 *
 *	Get bus private options on the hotplug connection
 *	indicated by the given hotplug information node.
 */
int
hp_get_private(hp_node_t node, const char *options, char **resultsp)
{
	int		rv;
	nvlist_t	*args;
	nvlist_t	*results;
	char		*values = NULL;
	char		path[MAXPATHLEN];
	char		connection[MAXPATHLEN];

	i_hp_dprintf("hp_get_private: node=%p, options=%p, resultsp=%p\n",
	    (void *)node, (void *)options, (void *)resultsp);

	/* Check arguments */
	if ((node == NULL) || (options == NULL) || (resultsp == NULL)) {
		i_hp_dprintf("hp_get_private: invalid arguments.\n");
		return (EINVAL);
	}

	/* Check node type */
	if (node->hp_type != HP_NODE_CONNECTOR) {
		i_hp_dprintf("hp_get_private: operation not supported.\n");
		return (ENOTSUP);
	}

	/* Initialize results */
	*resultsp = NULL;

	/* Get path and connection of specified node */
	if ((rv = hp_path(node, path, connection)) != 0)
		return (rv);

	/* Build arguments for door call */
	if ((args = i_hp_set_args(HP_CMD_GETPRIVATE, path, connection, 0,
	    options, 0)) == NULL)
		return (ENOMEM);

	/* Make the door call to hotplugd */
	rv = i_hp_call_hotplugd(args, &results);

	/* Arguments no longer needed */
	nvlist_free(args);

	/* Parse additional results, if any */
	if ((rv == 0) && (results != NULL)) {
		rv = i_hp_parse_results(results, NULL, &values);
		nvlist_free(results);
		*resultsp = values;
	}

	/* Done */
	return (rv);
}

/*
 * hp_pack()
 *
 *	Given the root of a hotplug information snapshot, pack
 *	it into a contiguous byte array so that it is suitable
 *	for network transport.
 */
int
hp_pack(hp_node_t root, char **bufp, size_t *lenp)
{
	hp_node_t	node;
	nvlist_t	*nvl;
	char		*buf;
	size_t		len;
	int		rv;

	i_hp_dprintf("hp_pack: root=%p, bufp=%p, lenp=%p\n", (void *)root,
	    (void *)bufp, (void *)lenp);

	if ((root == NULL) || (bufp == NULL) || (lenp == NULL)) {
		i_hp_dprintf("hp_pack: invalid arguments.\n");
		return (EINVAL);
	}

	*lenp = 0;
	*bufp = NULL;

	if (nvlist_alloc(&nvl, 0, 0) != 0) {
		i_hp_dprintf("hp_pack: nvlist_alloc() failed (%s).\n",
		    strerror(errno));
		return (ENOMEM);
	}

	if (root->hp_basepath != NULL) {
		rv = nvlist_add_string(nvl, HP_INFO_BASE, root->hp_basepath);
		if (rv != 0) {
			nvlist_free(nvl);
			return (rv);
		}
	}

	for (node = root; node != NULL; node = node->hp_sibling) {
		if ((rv = i_hp_pack_branch(node, &buf, &len)) == 0) {
			rv = nvlist_add_byte_array(nvl, HP_INFO_BRANCH,
			    (uchar_t *)buf, len);
			free(buf);
		}
		if (rv != 0) {
			nvlist_free(nvl);
			return (rv);
		}
	}

	len = 0;
	buf = NULL;
	if ((rv = nvlist_pack(nvl, &buf, &len, NV_ENCODE_NATIVE, 0)) == 0) {
		*lenp = len;
		*bufp = buf;
	}

	nvlist_free(nvl);

	return (rv);
}

/*
 * hp_unpack()
 *
 *	Unpack a hotplug information snapshot for normal usage.
 */
int
hp_unpack(char *packed_buf, size_t packed_len, hp_node_t *retp)
{
	hp_node_t	root;
	hp_node_t	root_list = NULL;
	hp_node_t	prev_root = NULL;
	nvlist_t	*nvl = NULL;
	nvpair_t	*nvp;
	char		*basepath = NULL;
	int		rv;

	i_hp_dprintf("hp_unpack: packed_buf=%p, packed_len=%u, retp=%p\n",
	    (void *)packed_buf, (uint32_t)packed_len, (void *)retp);

	if ((packed_buf == NULL) || (packed_len == 0) || (retp == NULL)) {
		i_hp_dprintf("hp_unpack: invalid arguments.\n");
		return (EINVAL);
	}

	if ((rv = nvlist_unpack(packed_buf, packed_len, &nvl, 0)) != 0)
		return (rv);

	if (nvlist_next_nvpair(nvl, NULL) == NULL) {
		nvlist_free(nvl);
		errno = EINVAL;
		return (NULL);
	}

	for (nvp = NULL; nvp = nvlist_next_nvpair(nvl, nvp); ) {

		rv = EINVAL;

		if (strcmp(nvpair_name(nvp), HP_INFO_BASE) == 0) {
			char	*val_string;

			if ((rv = nvpair_value_string(nvp, &val_string)) == 0) {
				if ((basepath = strdup(val_string)) == NULL)
					rv = ENOMEM;
			}

		} else if (strcmp(nvpair_name(nvp), HP_INFO_BRANCH) == 0) {
			size_t		len = 0;
			char		*buf = NULL;

			if ((rv = nvpair_value_byte_array(nvp,
			    (uchar_t **)&buf, (uint_t *)&len)) == 0) {
				rv = i_hp_unpack_branch(buf, len, NULL, &root);
			}

			if (rv == 0) {
				if (prev_root) {
					prev_root->hp_sibling = root;
				} else {
					root_list = root;
				}
				prev_root = root;
			}
		}

		if (rv != 0) {
			if (basepath)
				free(basepath);
			nvlist_free(nvl);
			hp_fini(root_list);
			*retp = NULL;
			return (rv);
		}
	}

	/* Store the base path in each root node */
	if (basepath) {
		for (root = root_list; root; root = root->hp_sibling)
			root->hp_basepath = basepath;
	}

	nvlist_free(nvl);
	*retp = root_list;
	return (0);
}

/*
 * i_hp_dprintf()
 *
 *	Print debug messages to stderr, but only when the debug flag
 *	(libhotplug_debug) is set.
 */
/*PRINTFLIKE1*/
static void
i_hp_dprintf(const char *fmt, ...)
{
	va_list	ap;

	if (libhotplug_debug) {
		va_start(ap, fmt);
		(void) vfprintf(stderr, fmt, ap);
		va_end(ap);
	}
}

/*
 * i_hp_pack_branch()
 *
 *	Pack an individual branch of a hotplug information snapshot.
 */
static int
i_hp_pack_branch(hp_node_t root, char **bufp, size_t *lenp)
{
	hp_node_t	child;
	nvlist_t	*nvl;
	char		*buf;
	size_t		len;
	int		rv;

	*lenp = 0;
	*bufp = NULL;

	/* Allocate an nvlist for this branch */
	if (nvlist_alloc(&nvl, 0, 0) != 0)
		return (ENOMEM);

	/* Pack the root of the branch and add it to the nvlist */
	if ((rv = i_hp_pack_node(root, &buf, &len)) == 0) {
		rv = nvlist_add_byte_array(nvl, HP_INFO_NODE,
		    (uchar_t *)buf, len);
		free(buf);
	}
	if (rv != 0) {
		nvlist_free(nvl);
		return (rv);
	}

	/* Pack each subordinate branch, and add it to the nvlist */
	for (child = root->hp_child; child != NULL; child = child->hp_sibling) {
		if ((rv = i_hp_pack_branch(child, &buf, &len)) == 0) {
			rv = nvlist_add_byte_array(nvl, HP_INFO_BRANCH,
			    (uchar_t *)buf, len);
			free(buf);
		}
		if (rv != 0) {
			nvlist_free(nvl);
			return (rv);
		}
	}

	/* Pack the resulting nvlist into a single buffer */
	len = 0;
	buf = NULL;
	if ((rv = nvlist_pack(nvl, &buf, &len, NV_ENCODE_NATIVE, 0)) == 0) {
		*lenp = len;
		*bufp = buf;
	}

	/* Free the nvlist */
	nvlist_free(nvl);

	return (rv);
}

/*
 * i_hp_pack_node()
 *
 *	Pack an individual node of a hotplug information snapshot.
 */
static int
i_hp_pack_node(hp_node_t node, char **bufp, size_t *lenp)
{
	nvlist_t	*nvl;
	char		*buf = NULL;
	size_t		len = 0;
	int		rv;

	if (nvlist_alloc(&nvl, 0, 0) != 0)
		return (ENOMEM);

	if ((rv = nvlist_add_uint32(nvl, HP_INFO_TYPE,
	    (uint32_t)node->hp_type)) != 0)
		goto fail;

	if ((node->hp_name) &&
	    ((rv = nvlist_add_string(nvl, HP_INFO_NAME, node->hp_name)) != 0))
		goto fail;

	if ((node->hp_usage) &&
	    ((rv = nvlist_add_string(nvl, HP_INFO_USAGE, node->hp_usage)) != 0))
		goto fail;

	if ((node->hp_description) &&
	    ((rv = nvlist_add_string(nvl, HP_INFO_DESC,
	    node->hp_description)) != 0))
		goto fail;

	if ((rv = nvlist_add_uint32(nvl, HP_INFO_STATE, node->hp_state)) != 0)
		goto fail;

	if ((node->hp_last_change != 0) &&
	    ((rv = nvlist_add_uint32(nvl, HP_INFO_TIME,
	    node->hp_last_change)) != 0))
		goto fail;

	if ((rv = nvlist_pack(nvl, &buf, &len, NV_ENCODE_NATIVE, 0)) != 0)
		goto fail;

	*bufp = buf;
	*lenp = len;
	nvlist_free(nvl);
	return (0);

fail:
	*bufp = NULL;
	*lenp = 0;
	nvlist_free(nvl);
	return (rv);
}

/*
 * i_hp_unpack_branch()
 *
 *	Unpack a branch of hotplug information nodes.
 */
static int
i_hp_unpack_branch(char *packed_buf, size_t packed_len, hp_node_t parent,
    hp_node_t *retp)
{
	hp_node_t	node = NULL;
	hp_node_t	child;
	hp_node_t	prev_child = NULL;
	nvlist_t	*nvl = NULL;
	nvpair_t	*nvp;
	char		*buf;
	size_t		len;
	int		rv;

	/* Initialize results */
	*retp = NULL;

	/* Unpack the nvlist for this branch */
	if ((rv = nvlist_unpack(packed_buf, packed_len, &nvl, 0)) != 0)
		return (rv);

	/*
	 * Unpack the branch.  The first item in the nvlist is
	 * always the root node.  And zero or more subordinate
	 * branches may be packed afterward.
	 */
	for (nvp = NULL; nvp = nvlist_next_nvpair(nvl, nvp); ) {

		len = 0;
		buf = NULL;

		if (strcmp(nvpair_name(nvp), HP_INFO_NODE) == 0) {

			/* Check that there is only one root node */
			if (node != NULL) {
				hp_fini(node);
				nvlist_free(nvl);
				return (EFAULT);
			}

			if ((rv = nvpair_value_byte_array(nvp, (uchar_t **)&buf,
			    (uint_t *)&len)) == 0)
				rv = i_hp_unpack_node(buf, len, parent, &node);

			if (rv != 0) {
				nvlist_free(nvl);
				return (rv);
			}

		} else if (strcmp(nvpair_name(nvp), HP_INFO_BRANCH) == 0) {

			if ((rv = nvpair_value_byte_array(nvp, (uchar_t **)&buf,
			    (uint_t *)&len)) == 0)
				rv = i_hp_unpack_branch(buf, len, node, &child);

			if (rv != 0) {
				hp_fini(node);
				nvlist_free(nvl);
				return (rv);
			}

			if (prev_child) {
				prev_child->hp_sibling = child;
			} else {
				node->hp_child = child;
			}
			prev_child = child;
		}
	}

	nvlist_free(nvl);
	*retp = node;
	return (0);
}

/*
 * i_hp_unpack_node()
 *
 *	Unpack an individual hotplug information node.
 */
static int
i_hp_unpack_node(char *buf, size_t len, hp_node_t parent, hp_node_t *retp)
{
	hp_node_t	node;
	nvlist_t	*nvl;
	nvpair_t	*nvp;
	uint32_t	val_uint32;
	char		*val_string;
	int		rv = 0;

	/* Initialize results */
	*retp = NULL;

	/* Unpack node into an nvlist */
	if ((nvlist_unpack(buf, len, &nvl, 0) != 0))
		return (EINVAL);

	/* Allocate the new node */
	if ((node = (hp_node_t)calloc(1, sizeof (struct hp_node))) == NULL) {
		nvlist_free(nvl);
		return (ENOMEM);
	}

	/* Iterate through nvlist, unpacking each field */
	for (nvp = NULL; nvp = nvlist_next_nvpair(nvl, nvp); ) {

		if ((strcmp(nvpair_name(nvp), HP_INFO_TYPE) == 0) &&
		    (nvpair_type(nvp) == DATA_TYPE_UINT32)) {

			(void) nvpair_value_uint32(nvp, &val_uint32);
			node->hp_type = val_uint32;

		} else if ((strcmp(nvpair_name(nvp), HP_INFO_NAME) == 0) &&
		    (nvpair_type(nvp) == DATA_TYPE_STRING)) {

			(void) nvpair_value_string(nvp, &val_string);
			if ((node->hp_name = strdup(val_string)) == NULL) {
				rv = ENOMEM;
				break;
			}

		} else if ((strcmp(nvpair_name(nvp), HP_INFO_STATE) == 0) &&
		    (nvpair_type(nvp) == DATA_TYPE_UINT32)) {

			(void) nvpair_value_uint32(nvp, &val_uint32);
			node->hp_state = val_uint32;

		} else if ((strcmp(nvpair_name(nvp), HP_INFO_USAGE) == 0) &&
		    (nvpair_type(nvp) == DATA_TYPE_STRING)) {

			(void) nvpair_value_string(nvp, &val_string);
			if ((node->hp_usage = strdup(val_string)) == NULL) {
				rv = ENOMEM;
				break;
			}

		} else if ((strcmp(nvpair_name(nvp), HP_INFO_DESC) == 0) &&
		    (nvpair_type(nvp) == DATA_TYPE_STRING)) {

			(void) nvpair_value_string(nvp, &val_string);
			if ((node->hp_description = strdup(val_string))
			    == NULL) {
				rv = ENOMEM;
				break;
			}

		} else if ((strcmp(nvpair_name(nvp), HP_INFO_TIME) == 0) &&
		    (nvpair_type(nvp) == DATA_TYPE_UINT32)) {

			(void) nvpair_value_uint32(nvp, &val_uint32);
			node->hp_last_change = (time_t)val_uint32;

		} else {
			i_hp_dprintf("i_hp_unpack_node: unrecognized: '%s'\n",
			    nvpair_name(nvp));
		}
	}

	/* Unpacked nvlist no longer needed */
	nvlist_free(nvl);

	/* Check for errors */
	if (rv != 0) {
		hp_fini(node);
		return (rv);
	}

	/* Success */
	node->hp_parent = parent;
	*retp = node;
	return (0);
}

/*
 * i_hp_call_hotplugd()
 *
 *	Perform a door call to the hotplug daemon.
 */
static int
i_hp_call_hotplugd(nvlist_t *args, nvlist_t **resultsp)
{
	door_arg_t	door_arg;
	nvlist_t	*results = NULL;
	char		*buf = NULL;
	size_t		len = 0;
	uint64_t	seqnum;
	int		door_fd;
	int		rv;

	/* Initialize results */
	*resultsp = NULL;

	/* Open door */
	if ((door_fd = open(HOTPLUGD_DOOR, O_RDONLY)) < 0) {
		i_hp_dprintf("i_hp_call_hotplugd: cannot open door (%s)\n",
		    strerror(errno));
		return (EBADF);
	}

	/* Pack the nvlist of arguments */
	if ((rv = nvlist_pack(args, &buf, &len, NV_ENCODE_NATIVE, 0)) != 0) {
		i_hp_dprintf("i_hp_call_hotplugd: cannot pack arguments (%s)\n",
		    strerror(rv));
		return (rv);
	}

	/* Set the door argument using the packed arguments */
	door_arg.data_ptr = buf;
	door_arg.data_size = len;
	door_arg.desc_ptr = NULL;
	door_arg.desc_num = 0;
	door_arg.rbuf = (char *)(uintptr_t)&rv;
	door_arg.rsize = sizeof (rv);

	/* Attempt the door call */
	if (door_call(door_fd, &door_arg) != 0) {
		rv = errno;
		i_hp_dprintf("i_hp_call_hotplugd: door call failed (%s)\n",
		    strerror(rv));
		(void) close(door_fd);
		free(buf);
		return (rv);
	}

	/* The arguments are no longer needed */
	free(buf);

	/*
	 * If results are not in the original buffer provided,
	 * then check and process the new results buffer.
	 */
	if (door_arg.rbuf != (char *)(uintptr_t)&rv) {

		/*
		 * First check that the buffer is valid.  Then check for
		 * the simple case where a short result code was sent.
		 * The last case is a packed nvlist was returned, which
		 * needs to be unpacked.
		 */
		if ((door_arg.rbuf == NULL) ||
		    (door_arg.data_size < sizeof (rv))) {
			i_hp_dprintf("i_hp_call_hotplugd: invalid results.\n");
			rv = EFAULT;

		} else if (door_arg.data_size == sizeof (rv)) {
			rv = *(int *)(uintptr_t)door_arg.rbuf;

		} else if ((rv = nvlist_unpack(door_arg.rbuf,
		    door_arg.data_size, &results, 0)) != 0) {
			i_hp_dprintf("i_hp_call_hotplugd: "
			    "cannot unpack results (%s).\n", strerror(rv));
			results = NULL;
			rv = EFAULT;
		}

		/* Unmap the results buffer */
		if (door_arg.rbuf != NULL)
			(void) munmap(door_arg.rbuf, door_arg.rsize);

		/*
		 * In the case of a packed nvlist, notify the daemon
		 * that it can free the result buffer from its heap.
		 */
		if ((results != NULL) &&
		    (nvlist_lookup_uint64(results, HPD_SEQNUM, &seqnum) == 0)) {
			door_arg.data_ptr = (char *)(uintptr_t)&seqnum;
			door_arg.data_size = sizeof (seqnum);
			door_arg.desc_ptr = NULL;
			door_arg.desc_num = 0;
			door_arg.rbuf = NULL;
			door_arg.rsize = 0;
			(void) door_call(door_fd, &door_arg);
			if (door_arg.rbuf != NULL)
				(void) munmap(door_arg.rbuf, door_arg.rsize);
		}

		*resultsp = results;
	}

	(void) close(door_fd);
	return (rv);
}

/*
 * i_hp_set_args()
 *
 *	Construct an nvlist of arguments for a hotplugd door call.
 */
static nvlist_t *
i_hp_set_args(hp_cmd_t cmd, const char *path, const char *connection,
    uint_t flags, const char *options, int state)
{
	nvlist_t	*args;

	/* Allocate a new nvlist */
	if (nvlist_alloc(&args, NV_UNIQUE_NAME_TYPE, 0) != 0)
		return (NULL);

	/* Add common arguments */
	if ((nvlist_add_int32(args, HPD_CMD, cmd) != 0) ||
	    (nvlist_add_string(args, HPD_PATH, path) != 0)) {
		nvlist_free(args);
		return (NULL);
	}

	/* Add connection, but only if defined */
	if ((connection != NULL) && (connection[0] != '\0') &&
	    (nvlist_add_string(args, HPD_CONNECTION, connection) != 0)) {
		nvlist_free(args);
		return (NULL);
	}

	/* Add flags, but only if defined */
	if ((flags != 0) && (nvlist_add_uint32(args, HPD_FLAGS, flags) != 0)) {
		nvlist_free(args);
		return (NULL);
	}

	/* Add options, but only if defined */
	if ((options != NULL) &&
	    (nvlist_add_string(args, HPD_OPTIONS, options) != 0)) {
		nvlist_free(args);
		return (NULL);
	}

	/* Add state, but only for CHANGESTATE command */
	if ((cmd == HP_CMD_CHANGESTATE) &&
	    (nvlist_add_int32(args, HPD_STATE, state) != 0)) {
		nvlist_free(args);
		return (NULL);
	}

	return (args);
}

/*
 * i_hp_parse_results()
 *
 *	Parse out individual fields of an nvlist of results from
 *	a hotplugd door call.
 */
static int
i_hp_parse_results(nvlist_t *results, hp_node_t *rootp, char **optionsp)
{
	int	rv;

	/* Parse an information snapshot */
	if (rootp) {
		char	*buf = NULL;
		size_t	len = 0;

		*rootp = NULL;
		if (nvlist_lookup_byte_array(results, HPD_INFO,
		    (uchar_t **)&buf, (uint_t *)&len) == 0) {
			if ((rv = hp_unpack(buf, len, rootp)) != 0)
				return (rv);
		}
	}

	/* Parse a bus private option string */
	if (optionsp) {
		char	*str;

		*optionsp = NULL;
		if ((nvlist_lookup_string(results, HPD_OPTIONS, &str) == 0) &&
		    ((*optionsp = strdup(str)) == NULL)) {
			return (ENOMEM);
		}
	}

	/* Parse result code of the operation */
	if (nvlist_lookup_int32(results, HPD_STATUS, &rv) != 0) {
		i_hp_dprintf("i_hp_call_hotplugd: missing status.\n");
		return (EFAULT);
	}

	return (rv);
}
