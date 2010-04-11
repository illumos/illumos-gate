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

#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <libnvpair.h>

#include <scsi/libses.h>
#include <scsi/libses_plugin.h>
#include <scsi/plugins/ses/vendor/sun.h>
#include <scsi/plugins/ses/vendor/sun_impl.h>

int
sun_fill_element_node(ses_plugin_t *sp, ses_node_t *np)
{
	ses_snap_t *snap = ses_node_snapshot(np);
	nvlist_t *props = ses_node_props(np);
	sun_fru_descr_impl_t *sfdip;
	size_t len;
	int err;

	if ((sfdip = ses_plugin_page_lookup(sp, snap,
	    SUN_DIAGPAGE_FRUID, np, &len)) != NULL) {
		if ((err = sun_fruid_parse_common(sfdip, props)) != 0)
			return (err);
	}

	return (0);
}
