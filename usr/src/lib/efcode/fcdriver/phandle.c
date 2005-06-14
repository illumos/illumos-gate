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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <fcode/private.h>
#include <fcode/log.h>

#include <fcdriver/fcdriver.h>


static int use_os_handle = 1;

void
do_use_os_handles(fcode_env_t *env)
{
	use_os_handle = 1;
}

void
do_use_fake_handles(fcode_env_t *env)
{
	log_message(MSG_ERROR, "WARNING: using fake phandles, test only\n");
	use_os_handle = 0;
}

static int
match_nodeid(void *s, void *d)
{
	my_nodeid_t *src = s;
	my_nodeid_t *dest = d;
	return ((src->node) == (dest->node));
}

static int
match_handle(void *s, void *d)
{
	my_nodeid_t *src = s;
	my_nodeid_t *dest = d;
	return ((src->my_handle) == (dest->my_handle));
}

/*
 * Convert from an OS phandle to an interpreter phandle
 */
device_t *
convert_phandle(fcode_env_t *env, fstack_t d)
{
	fc_resource_t *t;
	common_data_t *cdp = env->private;
	device_t *r;

	if (use_os_handle) {
		my_nodeid_t nh;
		nh.my_handle = (fc_phandle_t) d;
		t = find_resource(&cdp->nodeids, &nh, match_handle);
		if (t == NULL) {
			r = 0;
		} else {
			my_nodeid_t *p = (my_nodeid_t *) t->data;
			r = (device_t *) p->node;
		}
	} else
		r = (device_t *)d;
	return (r);
}

/*
 * Interpreter phandle to OS phandle
 */
fstack_t
revert_phandle(fcode_env_t *env, device_t *d)
{
	fc_resource_t *t;
	common_data_t *cdp = env->private;
	fstack_t r;

	if (use_os_handle) {
		my_nodeid_t nh;
		nh.node = d;
		t = find_resource(&cdp->nodeids, &nh, match_nodeid);
		if (t == NULL) {
			r = 0;
		} else {
			my_nodeid_t *p = (my_nodeid_t *) t->data;
			r = (fstack_t) p->my_handle;
		}
	} else
		r = (fstack_t) d;
	return (r);
}

void
add_my_handle(fcode_env_t *env, fc_phandle_t mh, device_t *d)
{
	my_nodeid_t *nh;
	common_data_t *cdp = env->private;

	nh = MALLOC(sizeof (my_nodeid_t));
	nh->my_handle = mh;
	nh->node = d;
	if (add_resource(&cdp->nodeids, nh, match_handle) == NULL) {
		log_message(MSG_ERROR, "add_my_handle: add_resource failed\n");
	}
}

void
allocate_phandle(fcode_env_t *env)
{
	private_data_t *pd;
	common_data_t *cdp;
	int error;
	char *service;
	device_t *current;
	fc_cell_t hcell;

	if ((cdp = env->private) == NULL) {
		log_message(MSG_ERROR, "allocate_phandle: NULL common\n");
		return;
	}

	if (!cdp->init_done)
		return;

	current = MYSELF->device;
	ASSERT(current);

	if (cdp->first_node) {
		service = FC_CONFIG_CHILD;
		cdp->first_node = 0;
	} else {
		service = FC_ALLOC_PHANDLE;
	}

	pd = MALLOC(sizeof (private_data_t));
	pd->common = cdp;
	pd->parent = (fc_phandle_t) revert_phandle(env, current->parent);
	pd->upload = (cdp->init_done == 1);
	current->private = pd;

	error = fc_run_priv(cdp, service, 0, 1, &hcell);

	pd->node = fc_cell2phandle(hcell);

	add_my_handle(env, pd->node, current);
}

fc_phandle_t
fc_get_ap(common_data_t *cdp)
{
	fc_cell_t hcell;
	int error;

	error = fc_run_priv(cdp, FC_AP_PHANDLE, 0, 1, &hcell);

	if (error)
		exit(1);

	return (fc_cell2phandle(hcell));
}


#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

	env->convert_phandle = convert_phandle;
	env->revert_phandle = revert_phandle;
	env->allocate_phandle = allocate_phandle;
	FORTH(0,	"use-os-handles",	do_use_os_handles);
	FORTH(0,	"use-fake-handles",	do_use_fake_handles);
}
