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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <alloca.h>
#include <sys/stat.h>
#include <malloc.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <sys/mdesc.h>
#include <sys/mdesc_impl.h>
#include <libdevinfo.h>
#include "ldma.h"
#include "mdesc_mutable.h"


static int get_devinfo(uint8_t **mdpp, size_t *size);
static boolean_t is_root_complex(di_prom_handle_t ph, di_node_t di);
static md_node_t *link_device_node(mmd_t *mdp,
    di_prom_handle_t ph, di_node_t di, md_node_t *node, char *path);
static int create_children(mmd_t *mdp,
    di_prom_handle_t ph, md_node_t *node, di_node_t parent);
static int create_peers(mmd_t *mdp,
    di_prom_handle_t ph, md_node_t *node, di_node_t dev);
static int device_tree_to_md(mmd_t *mdp, md_node_t *top);


#define	PCIEX		"pciex"
#define	LDMA_MODULE	LDMA_NAME_DIO


/* System Info version supported (only version 1.0) */
static ds_ver_t ldma_dio_vers[] = { {1, 0} };

#define	LDMA_DIO_NVERS	(sizeof (ldma_dio_vers) / sizeof (ds_ver_t))
#define	LDMA_DIO_NHANDLERS  (sizeof (ldma_dio_handlers) /		\
    sizeof (ldma_msg_handler_t))

static ldm_msg_func_t ldma_dio_pcidev_info_handler;

static ldma_msg_handler_t ldma_dio_handlers[] = {
	{MSGDIO_PCIDEV_INFO, ldma_dio_pcidev_info_handler},
};

ldma_agent_info_t ldma_dio_info = {
	LDMA_NAME_DIO,
	ldma_dio_vers, LDMA_DIO_NVERS,
	ldma_dio_handlers, LDMA_DIO_NHANDLERS
};

/* ARGSUSED */
static ldma_request_status_t
ldma_dio_pcidev_info_handler(ds_ver_t *ver, ldma_message_header_t *request,
    size_t request_dlen, ldma_message_header_t **replyp, size_t *reply_dlenp)
{
	ldma_message_header_t *reply;
	char *data;
	uint8_t *md_bufp = NULL;
	size_t md_size;
	int rv;

	LDMA_DBG("%s: PCI device info request", __func__);
	rv  = get_devinfo(&md_bufp, &md_size);
	if (rv != 0) {
		LDMA_ERR("Failed to generate devinfo MD");
		return (LDMA_REQ_FAILED);
	}
	reply = ldma_alloc_result_msg(request, md_size);
	if (reply == NULL) {
		LDMA_ERR("Memory allocation failure");
		free(md_bufp);
		return (LDMA_REQ_FAILED);
	}

	reply->msg_info = md_size;
	data = LDMA_HDR2DATA(reply);
	(void) memcpy(data, md_bufp, md_size);
	*replyp = reply;
	*reply_dlenp = md_size;
	free(md_bufp);
	LDMA_DBG("%s: sending PCI device info", __func__);
	return (LDMA_REQ_COMPLETED);
}

static boolean_t
is_root_complex(di_prom_handle_t ph, di_node_t di)
{
	int	len;
	char	*type;

	len = di_prom_prop_lookup_strings(ph, di, "device_type", &type);
	if ((len == 0) || (type == NULL))
		return (B_FALSE);

	if (strcmp(type, PCIEX) != 0)
		return (B_FALSE);

	/*
	 * A root complex node is directly under the root node.  So, if
	 * 'di' is not the root node, and its parent has no parent,
	 * then 'di' represents a root complex node.
	 */
	return ((di_parent_node(di) != DI_NODE_NIL) &&
	    (di_parent_node(di_parent_node(di)) == DI_NODE_NIL));
}

/*
 * String properties in the prom can contain multiple null-terminated
 * strings which are concatenated together.  We must represent them in
 * an MD as a data property.  This function retrieves such a property
 * and adds it to the MD.  If the 'alt_name' PROM property exists then
 * the MD property is created with the value of the PROM 'alt_name'
 * property, otherwise it is created with the value of the PROM 'name'
 * property.
 */
static int
add_prom_string_prop(di_prom_handle_t ph,
    mmd_t *mdp, md_node_t *np, di_node_t di, char *name, char *alt_name)
{
	int		count;
	char		*pp_data = NULL;
	char		*str;
	int		rv = 0;

	if (alt_name != NULL) {
		count = di_prom_prop_lookup_strings(ph, di, alt_name, &pp_data);
	}
	if (pp_data == NULL) {
		count = di_prom_prop_lookup_strings(ph, di, name, &pp_data);
	}

	if (count > 0 && pp_data != NULL) {
		for (str = pp_data; count > 0; str += strlen(str) + 1)
			count--;
		rv = md_add_data_property(mdp,
		    np, name, str - pp_data, (uint8_t *)pp_data);
	}
	return (rv);
}

/*
 * Add an int property 'name' to an MD from an existing PROM property. If
 * the 'alt_name' PROM property exists then the MD property is created with
 * the value of the PROM 'alt_name' property, otherwise it is created with
 * the value of the PROM 'name' property.
 */
static int
add_prom_int_prop(di_prom_handle_t ph,
    mmd_t *mdp, md_node_t *np, di_node_t di, char *name, char *alt_name)
{
	int		count;
	int		rv = 0;
	int		*pp_data = NULL;

	if (alt_name != NULL) {
		count = di_prom_prop_lookup_ints(ph, di, alt_name, &pp_data);
	}
	if (pp_data == NULL) {
		count = di_prom_prop_lookup_ints(ph, di, name, &pp_data);
	}

	/*
	 * Note: We know that the properties of interest contain a
	 * a single int.
	 */
	if (count > 0 && pp_data != NULL) {
		ASSERT(count == 1);
		rv = md_add_value_property(mdp, np, name, *pp_data);
	}
	return (rv);
}

static md_node_t *
link_device_node(mmd_t *mdp,
    di_prom_handle_t ph, di_node_t di, md_node_t *node, char *path)
{
	md_node_t	*np;

	np = md_link_new_node(mdp, "iodevice", node, "fwd", "back");
	if (np == NULL)
		return (NULL);

	/* Add the properties from the devinfo node. */
	if (md_add_string_property(mdp, np, "dev_path", path) != 0)
		goto fail;

	/* Add the required properties for this node. */
	if (add_prom_string_prop(ph, mdp, np, di, "device_type", NULL) != 0)
		goto fail;

	if (add_prom_string_prop(ph, mdp, np, di, "compatible", NULL) != 0)
		goto fail;

	if (add_prom_int_prop(ph,
	    mdp, np, di, "device-id", "real-device-id") != 0)
		goto fail;

	if (add_prom_int_prop(ph,
	    mdp, np, di, "vendor-id", "real-vendor-id") != 0)
		goto fail;

	if (add_prom_int_prop(ph,
	    mdp, np, di, "class-code", "real-class-code") != 0)
		goto fail;

	return (np);

fail:
	md_free_node(mdp, np);
	return (NULL);
}

static int
create_children(mmd_t *mdp,
    di_prom_handle_t ph, md_node_t *md_parent, di_node_t di_parent)
{
	md_node_t	*md_node;
	md_node_t	*md_child;
	di_node_t	di_child;
	char		*path;
	int		rv;

	path = di_devfs_path(di_parent);
	if (path == NULL)
		return (EIO);

	md_node = link_device_node(mdp, ph, di_parent, md_parent, path);
	di_devfs_path_free(path);
	if (md_node == NULL) {
		return (ENOMEM);
	}

	while ((di_child = di_child_node(di_parent)) != DI_NODE_NIL) {
		path = di_devfs_path(di_child);
		if (path != NULL) {
			md_child = link_device_node(mdp,
			    ph, di_child, md_node, path);
			di_devfs_path_free(path);
			if (md_child == NULL) {
				return (ENOMEM);
			}
		}

		rv = create_peers(mdp, ph, md_node, di_child);
		if (rv != 0)
			return (rv);

		md_node = md_child;
		di_parent = di_child;
	}
	return (0);
}

static int
create_peers(mmd_t *mdp, di_prom_handle_t ph, md_node_t *node, di_node_t dev)
{
	di_node_t	di_peer;
	int		rv;

	while ((di_peer = di_sibling_node(dev)) != DI_NODE_NIL) {
		rv = create_children(mdp, ph, node, di_peer);
		if (rv != 0)
			return (rv);
		dev = di_peer;
	}
	return (0);
}

static int
device_tree_to_md(mmd_t *mdp, md_node_t *top)
{
	di_node_t		node;
	di_node_t		root;
	di_prom_handle_t	ph;
	int			rv = 0;

	root = di_init("/", DINFOSUBTREE | DINFOPROP);

	if (root == DI_NODE_NIL) {
		LDMA_ERR("di_init cannot find device tree root node.");
		return (errno);
	}

	ph = di_prom_init();
	if (ph == DI_PROM_HANDLE_NIL) {
		LDMA_ERR("di_prom_init failed.");
		di_fini(root);
		return (errno);
	}

	node = di_child_node(root);
	while (node != NULL) {
		if (is_root_complex(ph, node)) {
			rv = create_children(mdp, ph, top, node);
			if (rv != 0)
				break;
		}
		node = di_sibling_node(node);
	}

	di_prom_fini(ph);
	di_fini(root);
	return (rv);
}

static int
get_devinfo(uint8_t **mdpp, size_t *size)
{
	mmd_t		*mdp;
	md_node_t	*rootp;
	size_t		md_size;
	uint8_t		*md_bufp;

	mdp = md_new_md();
	if (mdp == NULL) {
		return (ENOMEM);
	}
	rootp = md_new_node(mdp, "root");
	if (rootp == NULL) {
		md_destroy(mdp);
		return (ENOMEM);
	}

	if (device_tree_to_md(mdp, rootp) != 0) {
		md_destroy(mdp);
		return (ENOMEM);
	}
	md_size = (int)md_gen_bin(mdp, &md_bufp);

	if (md_size == 0) {
		md_destroy(mdp);
		return (EIO);
	}
	*mdpp = md_bufp;
	*size = md_size;

	md_destroy(mdp);
	return (0);
}
