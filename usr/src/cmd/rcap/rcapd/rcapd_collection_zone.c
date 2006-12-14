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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <procfs.h>
#include <project.h>
#include <stdlib.h>
#include <strings.h>
#include <zone.h>
#include <libzonecfg.h>
#include "rcapd.h"
#include "utils.h"

extern boolean_t gz_capped;

				/* round up to next y = 2^n */
#define	ROUNDUP(x, y)		(((x) + ((y) - 1)) & ~((y) - 1))

static void
update_zone(zone_entry_t *zent, void *walk_data)
{
	void(*update_notification_cb)(char *, char *, int, uint64_t, int) =
	    (void(*)(char *, char *, int, uint64_t, int))walk_data;
	int changes;
	int64_t max_rss;
	uint64_t mcap;
	lcollection_t *lcol;
	rcid_t colid;

	if (zone_getattr(zent->zid, ZONE_ATTR_PHYS_MCAP, &mcap,
	    sizeof (mcap)) != -1 && mcap != 0)
		max_rss = ROUNDUP(mcap, 1024) / 1024;
	else
		max_rss = 0;

	if (zent->zid == GLOBAL_ZONEID) {
		if (max_rss > 0)
			gz_capped = B_TRUE;
		else
			gz_capped = B_FALSE;
	}


	colid.rcid_type = RCIDT_ZONE;
	colid.rcid_val = zent->zid;

	lcol = lcollection_insert_update(&colid, max_rss, zent->zname,
	    &changes);
	if (update_notification_cb != NULL)
		update_notification_cb("zone", zent->zname, changes, max_rss,
		    (lcol != NULL) ? lcol->lcol_mark : 0);
}


/* ARGSUSED */
void
lcollection_update_zone(lcollection_update_type_t ut,
    void(*update_notification_cb)(char *, char *, int, uint64_t, int))
{
	int i;
	uint_t nzents;
	zone_entry_t *zents;

	/*
	 * Enumerate running zones.
	 */
	if (get_running_zones(&nzents, &zents) != 0)
		return;

	for (i = 0; i < nzents; i++) {
		update_zone(&zents[i], (void *)update_notification_cb);

	}

	free(zents);
}
