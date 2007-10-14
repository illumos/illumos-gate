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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * AMD Athlon64/Opteron Model-Specific Poller Implementation
 */

#include <sys/types.h>

#include "ao.h"

/*
 * Decide whether the caller should poll the NB.  The decision is made
 * and any poll is performed under protection of the chip-wide mutex
 * enforced at the caller's level.  That mutex already ensures that all
 * pollers on a chip are serialized - the following is simply to
 * avoid the NB poll ping-ponging between different detectors.
 */
uint64_t
ao_ms_poll_ownermask(cmi_hdl_t hdl, hrtime_t pintvl)
{
	ao_ms_data_t *ao = cms_hdl_getcmsdata(hdl);
	hrtime_t now = gethrtime_waitfree();
	hrtime_t last = ao->ao_ms_shared->aos_nb_poll_timestamp;
	int dopoll = 0;

	if (now - last > 2 * pintvl || last == 0) {
		/*
		 * If no last value has been recorded assume ownership.
		 * Otherwise only take over if the current "owner" seems
		 * to be making little progress.
		 */
		ao->ao_ms_shared->aos_nb_poll_owner = hdl;
		dopoll = 1;
	} else if (ao->ao_ms_shared->aos_nb_poll_owner == hdl) {
		/*
		 * This is the current owner and it is making progress.
		 */
		dopoll = 1;
	}

	if (dopoll)
		ao->ao_ms_shared->aos_nb_poll_timestamp = now;

	return (dopoll ? -1ULL : ~(1 << AMD_MCA_BANK_NB));
}
