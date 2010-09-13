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

#ifndef	_SYS_PCI_SPACE_H
#define	_SYS_PCI_SPACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PCI_SPURINTR_MSG_DEFAULT -1ull

extern uint_t tomatillo_disallow_bypass;

extern uint_t pci_interrupt_priorities_property;
extern uint_t pci_config_space_size_zero;
extern int pci_pbm_dma_sync_wait;
extern int pci_dvma_sync_before_unmap;
extern int pci_sync_lock;
extern int tomatillo_store_store_wrka;
extern uint_t tm_mtlb_maxpgs;
extern uint_t tm_mtlb_gc;
extern uint_t tm_mtlb_gc_manual;
extern uint32_t pci_spurintr_duration;
extern uint64_t pci_spurintr_msgs;


extern ushort_t pci_command_default;
extern uint_t pci_set_latency_timer_register;
extern uint_t pci_set_cache_line_size_register;

#ifdef DEBUG
extern uint64_t pci_debug_flags;
extern uint_t pci_warn_pp0;
#endif
extern uint_t pci_disable_pass1_workarounds;
extern uint_t pci_disable_pass2_workarounds;
extern uint_t pci_disable_pass3_workarounds;
extern uint_t pci_disable_plus_workarounds;
extern uint_t pci_disable_default_workarounds;
extern uint_t ecc_error_intr_enable;
extern uint_t pci_sbh_error_intr_enable;
extern uint_t pci_mmu_error_intr_enable;
extern uint_t pci_stream_buf_enable;
extern uint_t pci_stream_buf_exists;
extern uint_t pci_rerun_disable;
extern uint_t pci_enable_periodic_loopback_dma;
extern uint_t pci_enable_retry_arb;

extern uint_t pci_bus_parking_enable;
extern uint_t pci_error_intr_enable;
extern uint_t pci_retry_disable;
extern uint_t pci_retry_enable;
extern uint_t pci_dwsync_disable;
extern uint_t pci_intsync_disable;
extern uint_t pci_b_arb_enable;
extern uint_t pci_a_arb_enable;
extern uint_t pci_ecc_afsr_retries;

extern uint_t pci_intr_retry_intv;
extern uint8_t pci_latency_timer;
extern uint_t pci_panic_on_sbh_errors;
extern uint_t pci_panic_on_fatal_errors;
extern uint_t pci_thermal_intr_fatal;
extern uint_t pci_buserr_interrupt;
extern uint_t pci_set_dto_value;
extern uint_t pci_dto_value;
extern uint_t pci_lock_sbuf;
extern uint_t pci_use_contexts;
extern uint_t pci_sc_use_contexts;
extern uint_t pci_context_minpages;
extern uint_t pci_ctx_flush_warn;
extern uint_t pci_ctx_unsuccess_count;
extern uint_t pci_ctx_no_active_flush;
extern uint_t pci_ctx_no_compat;

extern uint_t pci_check_all_handlers;
extern uint_t pci_unclaimed_intr_max;
extern ulong_t pci_iommu_dvma_end;
extern uint_t pci_lock_tlb;

extern uint64_t pci_dvma_debug_on;
extern uint64_t pci_dvma_debug_off;
extern uint32_t pci_dvma_debug_rec;
extern uint_t pci_dvma_page_cache_entries;
extern uint_t pci_dvma_page_cache_clustsz;
#ifdef PCI_DMA_PROF
extern uint_t pci_dvmaft_npages;
extern uint_t pci_dvmaft_limit;
extern uint_t pci_dvmaft_free;
extern uint_t pci_dvmaft_success;
extern uint_t pci_dvmaft_exhaust;
extern uint_t pci_dvma_vmem_alloc;
extern uint_t pci_dvma_vmem_xalloc;
extern uint_t pci_dvma_vmem_free;
extern uint_t pci_dvma_vmem_xfree;
#endif
extern uint_t pci_disable_fdvma;

extern uint_t pci_iommu_ctx_lock_failure;
extern uint_t pci_preserve_iommu_tsb;

extern uint64_t pci_perr_enable;
extern uint64_t pci_serr_enable;
extern uint64_t pci_perr_fatal;
extern uint64_t pci_serr_fatal;
extern hrtime_t pci_intrpend_timeout;
extern hrtime_t pci_sync_buf_timeout;
extern hrtime_t pci_cdma_intr_timeout;
extern uint32_t pci_cdma_intr_count;

extern uint32_t pci_dto_fault_warn;
extern uint64_t pci_dto_intr_enable;
extern uint64_t pci_dto_count;
extern uint64_t pci_errtrig_pa;

extern uintptr_t pci_kmem_clid;
extern uint_t pci_intr_dma_sync;
extern uint_t pci_xmits_sc_max_prf;
extern uint64_t xmits_error_intr_enable;
extern uint_t xmits_perr_recov_int_enable;
extern uint_t xmits_max_transactions;
extern uint_t xmits_max_read_bytes;
extern uint_t xmits_upper_retry_counter;
extern uint_t xmits_pcix_diag_bugcntl_pcix;
extern uint_t xmits_pcix_diag_bugcntl_pci;

extern int pci_dvma_remap_enabled;
extern kthread_t *pci_reloc_thread;
extern kmutex_t pci_reloc_mutex;
extern kcondvar_t pci_reloc_cv;
extern int pci_reloc_presuspend;
extern int pci_reloc_suspend;
extern id_t pci_dvma_cbid;
extern id_t pci_fast_dvma_cbid;
extern int pci_dma_panic_on_leak;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_SPACE_H */
