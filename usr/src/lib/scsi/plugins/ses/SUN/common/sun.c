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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <alloca.h>
#include <libnvpair.h>

#include <scsi/libses.h>
#include <scsi/libses_plugin.h>
#include <scsi/plugins/ses/framework/libses.h>
#include <scsi/plugins/ses/vendor/sun.h>
#include <scsi/plugins/ses/vendor/sun_impl.h>

#include "../../../../../../lib/libfru/libnvfru/nvfru.h"

int
sun_fruid_parse_common(sun_fru_descr_impl_t *sfdip, nvlist_t *nvl)
{
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl,
	    LIBSES_PROP_FRU, sfdip-> sfdi_fru);
	SES_NV_ADD(uint64, nverr, nvl,
	    LIBSES_PROP_PHYS_PARENT, sfdip->sfdi_parent_element_index);

	return (0);
}

static int
sun_node_parse(ses_plugin_t *sp, ses_node_t *np)
{
	switch (ses_node_type(np)) {
	case SES_NODE_ENCLOSURE:
		return (sun_fill_enclosure_node(sp, np));

	case SES_NODE_AGGREGATE:
	case SES_NODE_ELEMENT:
		return (sun_fill_element_node(sp, np));

	default:
		return (0);
	}
}

int
_ses_init(ses_plugin_t *sp)
{
	ses_plugin_config_t config = {
		.spc_pages = sun_pages,
		.spc_node_parse = sun_node_parse
	};

	return (ses_plugin_register(sp, LIBSES_PLUGIN_VERSION,
	    &config) != 0);
}
