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
 * This module represents the expander on the disk backplane for the X4240 and
 * other Sun platforms.  Its purpose is to set a property indicating this is an
 * internal enclosure.
 */

#include <scsi/libses.h>
#include <scsi/libses_plugin.h>

/*ARGSUSED*/
static int
lsilogic_parse_node(ses_plugin_t *sp, ses_node_t *np)
{
	int nverr;
	nvlist_t *props;

	if (ses_node_type(np) != SES_NODE_ENCLOSURE)
		return (0);

	props = ses_node_props(np);

	SES_NV_ADD(boolean_value, nverr, props, LIBSES_EN_PROP_INTERNAL,
	    B_TRUE);

	return (0);
}

int
_ses_init(ses_plugin_t *sp)
{
	ses_plugin_config_t config = {
		.spc_node_parse = lsilogic_parse_node
	};

	return (ses_plugin_register(sp, LIBSES_PLUGIN_VERSION,
	    &config) != 0);
}
