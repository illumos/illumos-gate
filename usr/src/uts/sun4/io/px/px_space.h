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

#ifndef	_SYS_PX_SPACE_H
#define	_SYS_PX_SPACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PX_SPURINTR_MSG_DEFAULT -1ull

extern char px_panic_hb_msg[];
extern char px_panic_rc_msg[];
extern char px_panic_rp_msg[];
extern char px_panic_fab_msg[];

extern uint_t px_max_errorq_size;
extern ushort_t px_command_default;
extern uint_t px_set_latency_timer_register;
extern uint64_t px_perr_fatal;
extern uint64_t px_serr_fatal;
extern hrtime_t px_intrpend_timeout;
extern uint_t px_unclaimed_intr_max;
extern uint_t px_unclaimed_intr_block;
extern uint32_t px_spurintr_duration;
extern uint64_t px_spurintr_msgs;
extern uint_t px_stream_buf_enable;
extern uint_t px_stream_buf_exists;
extern uint_t px_use_contexts;
extern uint_t px_ctx_no_active_flush;
extern uint_t px_context_minpages;

extern uint_t px_mmu_error_intr_enable;
extern uint_t px_rerun_disable;

extern uint_t px_error_intr_enable;
extern uint_t px_dwsync_disable;
extern uint_t px_intsync_disable;

extern uint_t px_intr_retry_intv;
extern uint8_t px_latency_timer;
extern uint_t px_panic_on_fatal_errors;
extern uint_t px_thermal_intr_fatal;
extern uint_t px_buserr_interrupt;

extern uint64_t px_errtrig_pa;

extern uint_t px_check_all_handlers;
extern uint_t px_lock_tlb;

extern uint64_t px_dvma_debug_on;
extern uint64_t px_dvma_debug_off;
extern uint32_t px_dvma_debug_rec;
extern uint_t px_dvma_page_cache_entries;
extern uint_t px_dvma_page_cache_clustsz;
extern int px_dvma_sync_before_unmap;
#ifdef	PX_DMA_PROF
extern uint_t px_dvmaft_npages;
extern uint_t px_dvmaft_limit;
extern uint_t px_dvmaft_free;
extern uint_t px_dvmaft_success;
extern uint_t px_dvmaft_exhaust;
extern uint_t px_dvma_vmem_alloc;
extern uint_t px_dvma_vmem_xalloc;
extern uint_t px_dvma_vmem_free;
extern uint_t px_dvma_vmem_xfree;
#endif	/* PX_DMA_PROF */
extern uint_t px_disable_fdvma;

extern uint_t px_iommu_ctx_lock_failure;
extern uintptr_t px_kmem_clid;

/* timeout length in micro seconds */
#define	PX_MSEC_TO_USEC	1000
#define	PX_PME_TO_ACK_TIMEOUT	(1000 * PX_MSEC_TO_USEC)
#define	PX_LUP_POLL_INTERVAL	(10 * PX_MSEC_TO_USEC)
#define	PX_LUP_POLL_TO		(10 * PX_LUP_POLL_INTERVAL)

#define	PX_PWR_PIL		1
#define	PX_MAX_L1_TRIES		5

extern uint64_t px_pme_to_ack_timeout;
extern uint64_t px_lup_poll_to;
extern uint64_t px_lup_poll_interval;
extern uint32_t	px_pwr_pil;
extern uint32_t px_max_l1_tries;

/* Print and Log tunables */
extern uint32_t px_log;
extern uint32_t px_die;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_SPACE_H */
