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

/*
 * Generic x86 CPU MCA poller - support functions for native and xpv pollers.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/sdt.h>
#include <sys/cmn_err.h>

#include "gcpu.h"

uint_t gcpu_poll_trace_nent = 100;

#ifdef DEBUG
int gcpu_poll_trace_always = 1;
#else
int gcpu_poll_trace_always = 0;
#endif

void
gcpu_poll_trace(gcpu_poll_trace_ctl_t *ptc, uint8_t what, uint8_t nerr)
{
	gcpu_poll_trace_t *pt;
	uint_t next;

	DTRACE_PROBE2(gcpu__mca__poll__trace, uint32_t, what, uint32_t, nerr);

	if (ptc->mptc_tbufs == NULL)
		return; /* poll trace buffer is disabled */

	next = (ptc->mptc_curtrace + 1) % gcpu_poll_trace_nent;
	pt = &ptc->mptc_tbufs[next];

	pt->mpt_when = 0;
	pt->mpt_what = what;

	pt->mpt_nerr = MIN(nerr, UINT8_MAX);

	pt->mpt_when = gethrtime_waitfree();
	ptc->mptc_curtrace = next;
}

void
gcpu_poll_trace_init(gcpu_poll_trace_ctl_t *ptc)
{
	gcpu_poll_trace_t *tbufs = NULL;

	if (gcpu_poll_trace_always) {
		tbufs = kmem_zalloc(sizeof (gcpu_poll_trace_t) *
		    gcpu_poll_trace_nent, KM_SLEEP);
	}

	ptc->mptc_tbufs = tbufs;
	ptc->mptc_curtrace = 0;
}
