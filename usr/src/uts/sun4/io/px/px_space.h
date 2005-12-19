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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PX_SPACE_H
#define	_SYS_PX_SPACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PX_SPURINTR_MSG_DEFAULT -1ull

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
extern uint_t px_preserve_iommu_tsb;
extern uintptr_t px_kmem_clid;

#define	PX_ERR_EN_ALL			-1ull
#define	PX_ERR_MASK_NONE		0ull

extern uint64_t px_tlu_ue_intr_mask;
extern uint64_t px_tlu_ue_log_mask;
extern uint64_t px_tlu_ue_count_mask;

extern uint64_t px_tlu_ce_intr_mask;
extern uint64_t px_tlu_ce_log_mask;
extern uint64_t px_tlu_ce_count_mask;

extern uint64_t px_tlu_oe_intr_mask;
extern uint64_t px_tlu_oe_log_mask;
extern uint64_t px_tlu_oe_count_mask;

extern uint64_t px_mmu_intr_mask;
extern uint64_t px_mmu_log_mask;
extern uint64_t px_mmu_count_mask;

extern uint64_t px_imu_intr_mask;
extern uint64_t px_imu_log_mask;
extern uint64_t px_imu_count_mask;

#define	LPU_INTR_ENABLE 0ull
#define	LPU_INTR_DISABLE -1ull

extern uint64_t px_ilu_intr_mask;
extern uint64_t px_ilu_log_mask;
extern uint64_t px_ilu_count_mask;

extern uint64_t px_cb_intr_mask;
extern uint64_t px_cb_log_mask;
extern uint64_t px_cb_count_mask;

extern uint64_t px_lpul_intr_mask;
extern uint64_t px_lpul_log_mask;
extern uint64_t px_lpul_count_mask;

extern uint64_t px_lpup_intr_mask;
extern uint64_t px_lpup_log_mask;
extern uint64_t px_lpup_count_mask;

extern uint64_t px_lpur_intr_mask;
extern uint64_t px_lpur_log_mask;
extern uint64_t px_lpur_count_mask;

extern uint64_t px_lpux_intr_mask;
extern uint64_t px_lpux_log_mask;
extern uint64_t px_lpux_count_mask;

extern uint64_t px_lpus_intr_mask;
extern uint64_t px_lpus_log_mask;
extern uint64_t px_lpus_count_mask;

extern uint64_t px_lpug_intr_mask;
extern uint64_t px_lpug_log_mask;
extern uint64_t px_lpug_count_mask;

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

/* Fabric Error that should cause panics */
extern uint32_t px_fabric_die;
extern uint32_t px_fabric_die_rc_ce;
extern uint32_t px_fabric_die_rc_ue;
extern uint32_t px_fabric_die_rc_ce_gos;
extern uint32_t px_fabric_die_rc_ue_gos;
extern uint32_t px_fabric_die_ce;
extern uint32_t px_fabric_die_ue;
extern uint32_t px_fabric_die_ce_gos;
extern uint32_t px_fabric_die_ue_gos;
extern uint16_t px_fabric_die_bdg_sts;
extern uint16_t px_fabric_die_bdg_sts_gos;
extern uint16_t px_fabric_die_sw_sts;
extern uint16_t px_fabric_die_sw_sts_gos;
extern uint32_t px_fabric_die_sue;
extern uint32_t px_fabric_die_sue_gos;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_SPACE_H */
