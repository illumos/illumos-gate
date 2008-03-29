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

#include <scsi/libses.h>
#include <scsi/libses_plugin.h>

#include "libses_impl.h"

/*ARGSUSED*/
static int
libses_parse_node(ses_plugin_t *sp, ses_node_t *np)
{
	nvlist_t *lid;
	nvlist_t *props;
	uint64_t id, type;
	char csn[17];
	const char *name;
	int nverr;

	props = ses_node_props(np);

	if (nvlist_lookup_uint64(props, SES_PROP_ELEMENT_TYPE,
	    &type) == 0 &&
	    (name = ses_element_type_name(type)) != NULL) {
		/*
		 * Add a standard human-readable name for the element type.
		 */
		SES_NV_ADD(string, nverr, props,
		    LIBSES_PROP_ELEMENT_TYPE_NAME, name);
	}

	if (ses_node_type(np) != SES_NODE_ENCLOSURE)
		return (0);

	/*
	 * The only thing we do for all targets is fill in the default chassis
	 * number from the enclosure logical ID.
	 */
	if (nvlist_lookup_nvlist(props, SES_EN_PROP_LID, &lid) != 0)
		return (0);

	VERIFY(nvlist_lookup_uint64(lid, SPC3_NAA_INT, &id) == 0);

	(void) snprintf(csn, sizeof (csn), "%llx", id);
	SES_NV_ADD(string, nverr, props, LIBSES_EN_PROP_CSN, csn);

	return (0);
}

int
_ses_init(ses_plugin_t *sp)
{
	ses_plugin_config_t config = {
		.spc_node_parse = libses_parse_node
	};

	return (ses_plugin_register(sp, LIBSES_PLUGIN_VERSION,
	    &config) != 0);
}

/*
 * libses must be loaded after ses2.
 */
int
_ses_priority(void)
{
	return (1);
}
