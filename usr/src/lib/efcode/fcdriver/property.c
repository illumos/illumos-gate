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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>

#include <fcode/private.h>
#include <fcode/log.h>

#include <fcdriver/fcdriver.h>


static char *prop_buf;

static int
getproplen(common_data_t *cdp, fc_phandle_t node, char *propname, int inherit)
{
	fc_cell_t len;
	char *service;
	int error;

	service = inherit ? FC_GET_IN_PROPLEN : FC_GET_PKG_PROPLEN;

	error = fc_run_priv(cdp, service, 2, 1, fc_phandle2cell(node),
	    fc_ptr2cell(propname), &len);
	if (error)
		return (-1);

	return (fc_cell2int(len));
}

static int
getprop(common_data_t *cdp, fc_phandle_t node, char *propname, char *buf,
    int inherit)
{
	fc_cell_t len;
	char *service;
	int error;

	service = inherit ? FC_GET_IN_PROP : FC_GET_PKG_PROP;

	error = fc_run_priv(cdp, service, 3, 1, fc_phandle2cell(node),
	    fc_ptr2cell(buf), fc_ptr2cell(propname), &len);
	if (error)
		return (-1);

	return (fc_cell2int(len));
}

int
os_get_prop_common(common_data_t *cdp, fc_phandle_t node, char *name,
    int inherit, char **buf, int *len)
{
	int i, j;
	char *bp;

	i = getproplen(cdp, node, name, inherit);
	if (i <= 0) {
		/*
		 * OK for properties to be undefined, suppress error message
		 * unless some debug is on.
		 */
		if (get_interpreter_debug_level())
			log_message(MSG_ERROR, "os_get_prop_common:"
			    " getproplen(%s) returned %d\n", name, i);
		return (-1);
	}
	bp = MALLOC(i);

	j = getprop(cdp, node, name, bp, inherit);
	if (i != j) {
		/*
		 * It's an error if getproplen succeeded but getprop didn't
		 * return a matching length.
		 */
		log_message(MSG_ERROR, "os_get_prop_common: getprop(%s)"
		    " return %d, getproplen returned %d\n", name, j, i);
		FREE(bp);
		return (-2);
	}
	memcpy(prop_buf, bp, i);
	*buf = prop_buf;
	*len = i;
	FREE(bp);
	return (0);
}

static void
os_get_prop(fcode_env_t *env, int inherit, device_t *dev)
{
	fc_phandle_t node;
	char *name;
	char *prop;
	int len;
	private_data_t *pd;

	ASSERT(dev);

	pd = dev->private;
	ASSERT(pd);

	name = pop_a_string(env, &len);

	node = pd->node;
	if (node == 0) {
		log_message(MSG_ERROR, "os_get_prop: NULL node: %s\n",
		    get_path(env, dev));
		PUSH(DS, TRUE);
	} else if (os_get_prop_common(pd->common, node, name, inherit, &prop,
	    &len)) {
		PUSH(DS, TRUE);
	} else {
		PUSH(DS, (fstack_t)prop);
		PUSH(DS, len);
		PUSH(DS, FALSE);
	}
}

static void
os_get_package_prop(fcode_env_t *env)
{
	device_t *dev;

	CONVERT_PHANDLE(env, dev, POP(DS));
	os_get_prop(env, 0, dev);
}

static void
os_get_inherited_prop(fcode_env_t *env)
{
	os_get_prop(env, 1, env->attachment_pt);
}

void
install_property_vectors(fcode_env_t *env, device_t *d)
{
	d->vectors.get_package_prop = os_get_package_prop;
	d->vectors.get_inherited_prop = os_get_inherited_prop;
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

	prop_buf = MALLOC(4096);

}
