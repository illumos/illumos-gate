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

/*
 * PCI nexus driver tunables
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/time.h>
#include <sys/thread.h>
#include <sys/ksynch.h>
#include <sys/pci.h>
#include <sys/pci/pci_space.h>


/*LINTLIBRARY*/

/*
 * Used to disallow bypass requests for tomatillos ver <= 2.3
 * 0 allow bypass, 1 disallow it. errata #75
 */
uint_t tomatillo_disallow_bypass = 0;

/*
 * The three variables below enable a workround for
 * tomatillo's micro TLB bug. errata #82
 */
uint_t tm_mtlb_maxpgs = 20;
uint_t tm_mtlb_gc = 0; /* for garbage collection */
uint_t tm_mtlb_gc_manual = 0; /* for manual tuning */

/*
 * By initializing pci_interrupt_priorities_property to 1, the priority
 * level of the interrupt handler for a PCI device can be defined via an
 * "interrupt-priorities" property.  This property is an array of integer
 * values that have a one to one mapping the the "interrupts" property.
 * For example, if a device's "interrupts" property was (1, 2) and its
 * "interrupt-priorities" value was (5, 12), the handler for the first
 * interrupt would run at cpu priority 5 and the second at priority 12.
 * This would override the drivers standard mechanism for assigning
 * priorities to interrupt handlers.
 */
uint_t pci_interrupt_priorities_property = 1;

/*
 * By initializing pci_config_space_size_zero to 1, the driver will
 * tolerate mapping requests for configuration space "reg" entries whose
 * size is not zero.
 */
uint_t pci_config_space_size_zero = 1;

int pci_dvma_sync_before_unmap = 0;
int pci_sync_lock = 0;

int tomatillo_store_store_wrka = 0;
uint32_t pci_spurintr_duration = 60000000; /* One minute */
uint64_t pci_spurintr_msgs = PCI_SPURINTR_MSG_DEFAULT;

/*
 * The variable controls the default setting of the command register
 * for pci devices.  See init_child() for details.
 *
 * This flags also controls the setting of bits in the bridge control
 * register pci to pci bridges.  See init_child() for details.
 */
ushort_t pci_command_default = PCI_COMM_SERR_ENABLE |
				PCI_COMM_WAIT_CYC_ENAB |
				PCI_COMM_PARITY_DETECT |
				PCI_COMM_ME |
				PCI_COMM_MAE |
				PCI_COMM_IO;
/*
 * The following variable enables a workaround for the following obp bug:
 *
 *	1234181 - obp should set latency timer registers in pci
 *		configuration header
 *
 * Until this bug gets fixed in the obp, the following workaround should
 * be enabled.
 */
uint_t pci_set_latency_timer_register = 1;

/*
 * The following variable enables a workaround for an obp bug to be
 * submitted.  A bug requesting a workaround fof this problem has
 * been filed:
 *
 *	1235094 - need workarounds on positron nexus drivers to set cache
 *		line size registers
 *
 * Until this bug gets fixed in the obp, the following workaround should
 * be enabled.
 */
uint_t pci_set_cache_line_size_register = 1;

/*
 * The following driver parameters are defined as variables to allow
 * patching for debugging and tuning.  Flags that can be set on a per
 * PBM basis are bit fields where the PBM device instance number maps
 * to the bit position.
 */
#ifdef DEBUG
uint64_t pci_debug_flags = 0;
uint_t pci_warn_pp0 = 0;
#endif
uint_t pci_disable_pass1_workarounds = 0;
uint_t pci_disable_pass2_workarounds = 0;
uint_t pci_disable_pass3_workarounds = 0;
uint_t pci_disable_plus_workarounds = 0;
uint_t pci_disable_default_workarounds = 0;
uint_t ecc_error_intr_enable = 1;
uint_t pci_sbh_error_intr_enable = (uint_t)-1;
uint_t pci_mmu_error_intr_enable = (uint_t)-1;
uint_t pci_stream_buf_enable = (uint_t)-1;
uint_t pci_stream_buf_exists = 1;
uint_t pci_rerun_disable = 0;

uint_t pci_enable_retry_arb = (uint_t)-1;

uint_t pci_bus_parking_enable = (uint_t)-1;
uint_t pci_error_intr_enable = (uint_t)-1;
uint_t pci_retry_disable = 0;
uint_t pci_retry_enable = 0;
uint_t pci_dwsync_disable = 0;
uint_t pci_intsync_disable = 0;
uint_t pci_b_arb_enable = 0xf;
uint_t pci_a_arb_enable = 0xf;
uint_t pci_ecc_afsr_retries = 100;	/* XXX - what's a good value? */

uint_t pci_intr_retry_intv = 5;		/* for interrupt retry reg */
uint8_t pci_latency_timer = 0x40;	/* for pci latency timer reg */
uint_t pci_panic_on_sbh_errors = 0;
uint_t pci_panic_on_fatal_errors = 1;	/* should be 1 at beta */
uint_t pci_thermal_intr_fatal = 1;	/* thermal interrupts fatal */
uint_t pci_buserr_interrupt = 1;	/* safari buserr interrupt */
uint_t pci_set_dto_value = 0;		/* overwrite the prom settings? */
uint_t pci_dto_value = 1;		/* schizo consistent buf timeout PTO */
uint_t pci_lock_sbuf = 0;

uint_t pci_use_contexts = 1;
uint_t pci_sc_use_contexts = 1;
uint_t pci_context_minpages = 2;
uint_t pci_ctx_flush_warn = CE_IGNORE;
uint_t pci_ctx_unsuccess_count = 0;	/* unsuccessful ctx flush count */
uint_t pci_ctx_no_active_flush = 0;	/* cannot handle active ctx flush */
uint_t pci_ctx_no_compat = 0;		/* maintain compatibility */

uint64_t pci_perr_enable = -1ull;
uint64_t pci_serr_enable = -1ull;
uint64_t pci_perr_fatal = -1ull;
uint64_t pci_serr_fatal = -1ull;
hrtime_t pci_intrpend_timeout = 5ll * NANOSEC;	/* 5 seconds in nanoseconds */
hrtime_t pci_sync_buf_timeout = 1ll * NANOSEC;	/* 1 second  in nanoseconds */
hrtime_t pci_cdma_intr_timeout = 1ll * NANOSEC; /* consistent sync trigger */
uint32_t pci_cdma_intr_count = 15; /* num of pci_cdma_intr_timeout cycles */

uint32_t pci_dto_fault_warn = CE_WARN; /* set to CE_IGNORE for no messages */
uint64_t pci_dto_intr_enable = 0;
uint64_t pci_dto_count = 0;
uint64_t pci_errtrig_pa = 0x0;

/*
 * The following flag controls behavior of the ino handler routine
 * when multiple interrupts are attached to a single ino.  Typically
 * this case would occur for the ino's assigned to the PCI bus slots
 * with multi-function devices or bus bridges.
 *
 * Setting the flag to zero causes the ino handler routine to return
 * after finding the first interrupt handler to claim the interrupt.
 *
 * Setting the flag to non-zero causes the ino handler routine to
 * return after making one complete pass through the interrupt
 * handlers.
 */
uint_t pci_check_all_handlers = 1;

/*
 * The following value is the number of consecutive unclaimed interrupts that
 * will be tolerated for a particular ino_p before the interrupt is deemed to
 * be jabbering and is blocked.
 */
uint_t pci_unclaimed_intr_max = 20;

ulong_t pci_iommu_dvma_end = 0xfffffffful;
uint_t pci_lock_tlb = 0;
uint64_t pci_dvma_debug_on = 0;
uint64_t pci_dvma_debug_off = 0;
uint32_t pci_dvma_debug_rec = 512;

/*
 * dvma address space allocation cache variables
 */
uint_t pci_dvma_page_cache_entries = 0x200;	/* # of chunks (1 << bits) */
uint_t pci_dvma_page_cache_clustsz = 0x8;	/* # of pages per chunk */
#ifdef PCI_DMA_PROF
uint_t pci_dvmaft_npages = 0;			/* FT fail due npages */
uint_t pci_dvmaft_limit = 0;			/* FT fail due limits */
uint_t pci_dvmaft_free = 0;			/* FT free */
uint_t pci_dvmaft_success = 0;			/* FT success */
uint_t pci_dvmaft_exhaust = 0;			/* FT vmem fallback */
uint_t pci_dvma_vmem_alloc = 0;			/* vmem alloc */
uint_t pci_dvma_vmem_xalloc = 0;		/* vmem xalloc */
uint_t pci_dvma_vmem_xfree = 0;			/* vmem xfree */
uint_t pci_dvma_vmem_free = 0;			/* vmem free */
#endif
uint_t pci_disable_fdvma = 0;

uint_t pci_iommu_ctx_lock_failure = 0;

/*
 * This flag preserves prom iommu settings by copying prom TSB entries
 * to corresponding kernel TSB entry locations. It should be removed
 * after the interface properties from obp have become default.
 */
uint_t pci_preserve_iommu_tsb = 1;

/*
 * memory callback list id callback list for kmem_alloc failure clients
 */
uintptr_t pci_kmem_clid = 0;

/*
 * Perform a consistent-mode sync/flush during interrupt.
 */
uint_t pci_intr_dma_sync = 0;

/*
 * This flag is used to enable max prefetch streaming cache mode
 * feature of XMITS.
 */
uint_t pci_xmits_sc_max_prf = 0;

/*
 * This flag is used to enable pcix error reporting in XMITS.
 */
uint64_t xmits_error_intr_enable = -1ull;

/*
 * Enable parity error recovery for xmits
 */
uint_t xmits_perr_recov_int_enable = 0;

/*
 * This flag controls whether or not DVMA remap support is
 * enabled (currently, Schizo/XMITS only).
 */
int pci_dvma_remap_enabled = 0;

/*
 * Serialize PCI relocations, since they are time critical.
 */
kthread_t *pci_reloc_thread = NULL;
kmutex_t pci_reloc_mutex;
kcondvar_t pci_reloc_cv;
int pci_reloc_presuspend = 0;
int pci_reloc_suspend = 0;
id_t pci_dvma_cbid;
id_t pci_fast_dvma_cbid;
int pci_dma_panic_on_leak = 0;

/*
 * Set Outstanding Maximum Split Transactions.  Legal settings are:
 * 0 = 1 Outstanding Transacation, 1 = 2, 2 = 3, 3 = 4, 4 = 8, 5 = 12,
 * 6 = 16, 7 = 32.
 */
uint_t xmits_max_transactions = 0;

/*
 * Set Max Memory Read Byte Count. Legal settings are:
 * 0 = 512 Max Memory Read Bytes, 1 = 1024, 2 = 2048, 3 = 4096.
 */
uint_t xmits_max_read_bytes = 0;

/*
 * Bits 15:0 increase the maximum PIO retries allowed by XMITS.
 */
uint_t xmits_upper_retry_counter = 0x3E8;

/*
 * default values for xmits pcix diag BUG_FIX_CNTL bits 47:32
 * depending on mode: pcix or pci.
 */
uint_t xmits_pcix_diag_bugcntl_pcix = 0xA0;
uint_t xmits_pcix_diag_bugcntl_pci =  0xFF;
