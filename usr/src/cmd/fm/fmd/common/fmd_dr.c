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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * FMD Dynamic Reconfiguration (DR) Event Handling
 *
 * Fault manager scheme plug-ins must track characteristics of individual
 * pieces of hardware.  As these components can be added or removed by a DR
 * operation, we need to provide a means by which plug-ins can determine when
 * they need to re-examine the current configuration.  We provide a simple
 * mechanism whereby this task can be implemented using lazy evaluation: a
 * simple 64-bit generation counter is maintained and incremented on *any* DR.
 * Schemes can store the generation number in scheme-specific data structures,
 * and then revalidate their contents if the current generation number has
 * changed since the resource information was cached.  This method saves time,
 * avoids the complexity of direct participation in DR, avoids the need for
 * resource-specific processing of DR events, and is relatively easy to port
 * to other systems that support dynamic reconfiguration.
 */

#include <sys/types.h>
#include <sys/sysevent/dr.h>
#include <sys/sysevent/eventdefs.h>

#include <stdio.h>
#include <libsysevent.h>

#undef MUTEX_HELD
#undef RW_READ_HELD
#undef RW_WRITE_HELD

#include <fmd_error.h>
#include <fmd_subr.h>
#include <fmd.h>

static void
fmd_dr_event(sysevent_t *sep)
{
	uint64_t gen;

	(void) pthread_mutex_lock(&fmd.d_stats_lock);
	gen = fmd.d_stats->ds_dr_gen.fmds_value.ui64++;
	(void) pthread_mutex_unlock(&fmd.d_stats_lock);

	TRACE((FMD_DBG_XPRT, "dr event %p, gen=%llu", (void *)sep, gen));
}

/*
 * Initialize DR event subscription.  Note: sysevent_bind_handle() calls
 * door_create() internally.  Door servers in fmd must be setup as fmd threads,
 * and fmd_transport_init() already calls door_server_create() for us.  We
 * therefore rely on fmd_transport_init() being called before fmd_dr_init().
 */
void
fmd_dr_init(void)
{
	const char *subclass = ESC_DR_AP_STATE_CHANGE;

	ASSERT(fmd.d_xprt_chan != NULL); /* fmd_transport_init() has happened */

	if ((fmd.d_dr_hdl = sysevent_bind_handle(fmd_dr_event)) == NULL)
		fmd_error(EFMD_EXIT, "failed to bind handle for DR sysevent");

	if (sysevent_subscribe_event(fmd.d_dr_hdl, EC_DR, &subclass, 1) == -1)
		fmd_error(EFMD_EXIT, "failed to subscribe for DR sysevent");
}

void
fmd_dr_fini(void)
{
	if (fmd.d_dr_hdl != NULL) {
		sysevent_unsubscribe_event(fmd.d_dr_hdl, EC_DR);
		sysevent_unbind_handle(fmd.d_dr_hdl);
	}
}
