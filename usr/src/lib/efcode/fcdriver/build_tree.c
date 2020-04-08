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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <fcntl.h>

#include <fcode/private.h>
#include <fcode/log.h>

#include <fcdriver/fcdriver.h>

static fc_phandle_t
fc_nodeop(common_data_t *cdp, fc_phandle_t node, char *svc)
{
	fc_cell_t hcell;
	int error;

	error = fc_run_priv(cdp, svc, 1, 1, fc_phandle2cell(node), &hcell);
	if (error)
		return (0);
	return (fc_cell2phandle(hcell));
}

void
recurse_tree(fcode_env_t *env, device_t *d,
    void (*fn)(fcode_env_t *, device_t *))
{
	if (d != NULL) {
		device_t *p;

		fn(env, d);
		recurse_tree(env, d->child, fn);
		recurse_tree(env, d->peer, fn);
	}
}

static void
get_prom_nodeid(fcode_env_t *env, device_t *d)
{
	common_data_t *cdp = env->private;
	private_data_t *pd = d->private;
	char *name;
	int namelen;
	char *namebuf;

	if ((pd != NULL) && (pd->node)) {
		if (os_get_prop_common(cdp, pd->node, "name",
		    0, &namebuf, &namelen))
			namebuf = "<unknown>";
		debug_msg(DEBUG_UPLOAD, "Populated: %s = %p\n", namebuf,
		    pd->node);
		return;
	}

	name = get_package_name(env, d);
	debug_msg(DEBUG_UPLOAD, "Node %s: %p (%p)\n", name, d, pd);
	if (d->parent) {
		private_data_t *ppd = (private_data_t *)d->parent->private;
		fc_phandle_t thisnode;

		if (os_get_prop_common(cdp, ppd->node, "name",
		    0, &namebuf, &namelen))
			namebuf = "<unknown>";
		debug_msg(DEBUG_UPLOAD, "Parent: %p (%p) %s = %p\n", d->parent,
		    ppd, namebuf, ppd->node);
		for (thisnode = fc_nodeop(cdp, ppd->node, FC_CHILD_FCODE);
		    thisnode != 0;
		    thisnode = fc_nodeop(cdp, thisnode, FC_PEER_FCODE)) {
			int status;

			namebuf = "";
			namelen = 0;
			status = os_get_prop_common(cdp, thisnode, "name",
			    0, &namebuf, &namelen);
			debug_msg(DEBUG_UPLOAD, "Lookup: %p name '%s'\n"
			    " status: %d", thisnode, namebuf, status);
			if (status == 0 && strcmp(name, namebuf) == 0)
				break;
		}
		if (thisnode) {
			pd = MALLOC(sizeof (private_data_t));
			pd->common = cdp;
			pd->node = thisnode;
			pd->upload = 0;
			d->private = pd;
			add_my_handle(env, pd->node, d);
			install_property_vectors(env, d);
			debug_msg(DEBUG_UPLOAD, "Found: %p\n", thisnode);
		}
	}
}

static void
update_nodeids(fcode_env_t *env)
{
	/*
	 * We scan through the tree looking for nodes that don't have
	 * one of my structures attached, and for each of those nodes
	 * I attempt to match it with a real firmware node
	 */
	recurse_tree(env, env->root_node, get_prom_nodeid);
}

static void
build_nodes(fcode_env_t *env, common_data_t *cdp, fc_phandle_t h)
{
	char *name;
	int len;
	int n, allocd, depth;
	fc_phandle_t p;
	device_t *current, *attach;
	private_data_t *pd;
	private_data_t **node_array;

	/*
	 * This is not nice; new_device calls the allocate_phandle
	 * routine without exception, we need to disable the allocation
	 * while we are building the tree to the attachment point
	 * which is why the init_done variable exists.
	 */
	cdp->init_done = 0;
	node_array = NULL;
	depth = 0;
	allocd = sizeof (private_data_t *);
	do {
		node_array = REALLOC(node_array, allocd*(depth+1));
		pd = MALLOC(sizeof (private_data_t));
		pd->node = h;
		node_array[depth] = pd;
		name = NULL;
		(void) os_get_prop_common(cdp, pd->node, "name", 0, &name,
		    &len);
		if (name)
			debug_msg(DEBUG_UPLOAD, "Node: %p name: '%s'\n", h,
			    name);
		else
			log_message(MSG_ERROR, "Node: %p Unnamed node!!\n", h);
		depth++;
		h = fc_nodeop(cdp, h, FC_PARENT);
	} while (h);

	for (n = 0; n < (depth-1); n++) {
		new_device(env);
	}

	env->attachment_pt = current = attach = env->current_device;

	for (n = 0; n < depth; n++) {
		pd = node_array[n];
		pd->common = cdp;
		current->private = pd;
		add_my_handle(env, pd->node, current);
		install_property_vectors(env, current);
		current = current->parent;
	}

	for (current = attach; current != NULL; current = current->parent) {
		install_node_data(env, current);
		if (current->parent)
			finish_device(env);
	}

	FREE(node_array);
	cdp->init_done = 2;
	update_nodeids(env);
	cdp->init_done = 1;
	cdp->first_node = 1;
}

void
build_tree(fcode_env_t *env)
{
	common_data_t *cdp = env->private;
	instance_t *ih;

	root_node(env);
	ih = open_instance_chain(env, env->current_device, 0);
	MYSELF = ih;
	build_nodes(env, cdp, cdp->attach);
	close_instance_chain(env, ih, 0);
	MYSELF = 0;
	device_end(env);
}

/*
 * Installs /openprom and /packages nodes and sub-nodes.
 */
void
install_builtin_nodes(fcode_env_t *env)
{
	common_data_t *cdp = env->private;
	int saved_first_node;
	int saved_init_done;

	if (cdp) {
		saved_first_node = cdp->first_node;
		saved_init_done = cdp->init_done;
		cdp->first_node = 0;
		cdp->init_done = 2;
		install_openprom_nodes(env);
		install_package_nodes(env);
		cdp->first_node = saved_first_node;
		cdp->init_done = saved_init_done;
	}
}


#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

	FORTH(0,		"update-nodes",		update_nodeids);
	FORTH(0,		"build-tree",		build_tree);
}
