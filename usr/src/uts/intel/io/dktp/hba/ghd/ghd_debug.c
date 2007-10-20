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

#include "ghd.h"
#include "ghd_debug.h"

#if !(defined(GHD_DEBUG) || defined(__lint))
ulong_t	ghd_debug_flags = 0;
#else
ulong_t	ghd_debug_flags = GDBG_FLAG_ERROR
		/*	| GDBG_FLAG_WAITQ	*/
		/*	| GDBG_FLAG_INTR	*/
		/*	| GDBG_FLAG_START	*/
		/*	| GDBG_FLAG_WARN	*/
		/*	| GDBG_FLAG_DMA		*/
		/*	| GDBG_FLAG_PEND_INTR	*/
		/*	| GDBG_FLAG_START	*/
		/*	| GDBG_FLAG_PKT		*/
		/*	| GDBG_FLAG_INIT	*/
			;
#endif

void
ghd_err(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vcmn_err(CE_CONT, fmt, ap);
	va_end(ap);
}

#if defined(GHD_DEBUG)
#include <sys/promif.h>
#define	PRF	prom_printf

static void
ghd_dump_ccc(ccc_t *P)
{
	PRF("nextp 0x%p tmrp 0x%p label 0x%p &mutex 0x%p\n",
	    P->ccc_nextp, P->ccc_tmrp, P->ccc_label, &P->ccc_activel_mutex);
	PRF("&activel 0x%p dip 0x%p iblock 0x%p\n",
	    &P->ccc_activel, P->ccc_hba_dip, P->ccc_iblock);
	PRF("softid 0x%p &hba_mutext 0x%p\n poll 0x%p\n",
	    P->ccc_soft_id, &P->ccc_hba_mutex, &P->ccc_hba_pollmode);
	PRF("&devs 0x%p &waitq_mutex 0x%p &waitq 0x%p\n",
	    &P->ccc_devs, &P->ccc_waitq_mutex, &P->ccc_waitq);
	PRF("waitq_freezetime 0x%p waitq_freezedelay %p\n",
	    &P->ccc_waitq_freezetime, &P->ccc_waitq_freezedelay);
	PRF("dq softid 0x%p &dq_mutex 0x%p &doneq 0x%p\n",
	    P->ccc_doneq_softid, &P->ccc_doneq_mutex, &P->ccc_doneq);
	PRF("handle 0x%p &ccballoc 0x%p\n",
	    P->ccc_hba_handle, &P->ccc_ccballoc);
	PRF("hba_reset_notify_callback 0x%p notify_list 0x%p mutex 0x%p\n",
	    P->ccc_hba_reset_notify_callback, &P->ccc_reset_notify_list,
	    &P->ccc_reset_notify_mutex);
}


static void
ghd_dump_gcmd(gcmd_t *P)
{
	PRF("cmd_q nextp 0x%p prevp 0x%p private 0x%p\n",
	    P->cmd_q.l2_nextp, P->cmd_q.l2_prevp, P->cmd_q.l2_private);
	PRF("state %ul wq lev %ld flags 0x%x\n",
	    P->cmd_state, P->cmd_waitq_level, P->cmd_flags);
	PRF("timer Q nextp 0x%p prevp 0x%p private 0x%p\n",
	    P->cmd_timer_link.l2_nextp, P->cmd_timer_link.l2_prevp,
	    P->cmd_timer_link.l2_private);

	PRF("start time 0x%lx timeout 0x%lx hba private 0x%p pktp 0x%p\n",
	    P->cmd_start_time, P->cmd_timeout, P->cmd_private, P->cmd_pktp);
	PRF("gtgtp 0x%p dma_flags 0x%x dma_handle 0x%p dmawin 0x%p "
	    "dmaseg 0x%p\n", P->cmd_gtgtp, P->cmd_dma_flags,
	    P->cmd_dma_handle, P->cmd_dmawin, P->cmd_dmaseg);
	PRF("wcount %d windex %d ccount %d cindex %d\n",
	    P->cmd_wcount, P->cmd_windex, P->cmd_ccount, P->cmd_cindex);
	PRF("totxfer %ld\n", P->cmd_totxfer);
}
#endif
