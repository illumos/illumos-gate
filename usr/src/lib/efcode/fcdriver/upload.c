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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

static void
create_node(fcode_env_t *env, device_t *d)
{
	int error;
	prop_t *p;
	instance_t *ih;
	char *service = FC_NEW_DEVICE;
	private_data_t *pd, *ppd;
	char *unit_str;

	pd = (private_data_t *)d->private;
	ppd = (private_data_t *)d->parent->private;

	ih = MYSELF;
	MYSELF = open_instance_chain(env, d, 0);
	p = lookup_package_property(env, "name", d);
	if (p == NULL) {
		forth_abort(env, "create_node: '%s' name prop not found\n",
		    get_path(env, d));
	}

	debug_msg(DEBUG_UPLOAD, "Create Node: %p\n", pd->node);
	debug_msg(DEBUG_UPLOAD, " Device Name: '%s'\n", p->data);
	debug_msg(DEBUG_UPLOAD, " Parent     : %p\n", ppd->node);

	my_unit(env);
	(void) call_my_parent(env, "encode-unit");
	unit_str = pop_a_duped_string(env, NULL);
	if (unit_str == NULL) {
		unit_str = STRDUP("");
	}

	debug_msg(DEBUG_UPLOAD, " Unit Addr  : '%s'\n", unit_str);

	error = fc_run_priv(pd->common, FC_NEW_DEVICE, 4, 0,
	    fc_phandle2cell(pd->node), fc_phandle2cell(ppd->node),
	    fc_ptr2cell(unit_str), fc_ptr2cell(p->data));

	FREE(unit_str);
	close_instance_chain(env, MYSELF, 0);
	MYSELF = ih;

	if (error)
		log_message(MSG_ERROR, "%s: parent: '%s' new: '%s'\n", service,
		    get_path(env, d->parent), p->data);
}

static void
finish_node(fcode_env_t *env, device_t *d)
{
	private_data_t *pd;
	int error;

	pd = (private_data_t *)d->private;

	debug_msg(DEBUG_UPLOAD, "Finish Node: %p\n", pd->node);

	error = fc_run_priv(pd->common, FC_FINISH_DEVICE, 1, 0,
	    fc_phandle2cell(pd->node));
	if (error)
		log_message(MSG_ERROR, "%s: failed\n", FC_FINISH_DEVICE);
}

static void
upload_properties(fcode_env_t *env, device_t *d)
{
	prop_t *p;
	private_data_t *pd;
	int error;

	pd = (private_data_t *)d->private;
	debug_msg(DEBUG_UPLOAD, "Upload Properties: node %p upload: %d\n",
	    pd->node, pd->upload);

	if (!pd->upload)
		return;

	for (p = d->properties; p; p = p->next) {
		DEBUGF(UPLOAD, print_property(env, p, " Upload: "));

		error = fc_run_priv(pd->common, FC_CREATE_PROPERTY, 4, 0,
		    fc_phandle2cell(pd->node), fc_int2cell(p->size),
		    fc_ptr2cell(p->data), fc_ptr2cell(p->name));

		if (error)
			log_message(MSG_ERROR, "%s: '%s' failed\n",
			    FC_CREATE_PROPERTY, p->name);
	}
}

static void
upload_node(fcode_env_t *env, device_t *d)
{
	private_data_t *pd = (private_data_t *)d->private;

	if (pd) {
		debug_msg(DEBUG_UPLOAD, "Upload Node: dev: %p node: %p"
		    " upload: %d\n", d, pd->node, pd->upload);
		if (pd->upload) {
			create_node(env, d);
			upload_properties(env, d);
			finish_node(env, d);
		}
	} else
		debug_msg(DEBUG_UPLOAD, "Upload Node: dev: %p NULL private\n",
		    d);
}

void
upload_nodes(fcode_env_t *env)
{
	debug_msg(DEBUG_UPLOAD, "Upload Nodes: Recursing Tree\n");
	recurse_tree(env, env->root_node, upload_node);
}

void
validate_nodes(fcode_env_t *env)
{
	int error;
	common_data_t *cdp = env->private;

	error = ioctl(cdp->fcode_fd, FC_VALIDATE);
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

	FORTH(0,	"upload-nodes",		upload_nodes);
	FORTH(0,	"validate-nodes",	validate_nodes);
}
