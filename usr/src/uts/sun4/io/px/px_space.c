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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * PCI Express nexus driver tunables
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/time.h>
#include <sys/pcie.h>
#include "px_obj.h"

/*LINTLIBRARY*/

uint32_t px_spurintr_duration = 60000000; /* One minute */
uint64_t px_spurintr_msgs = PX_SPURINTR_MSG_DEFAULT;

/*
 * The following variable enables a workaround for the following obp bug:
 *
 *	1234181 - obp should set latency timer registers in pci
 *		configuration header
 *
 * Until this bug gets fixed in the obp, the following workaround should
 * be enabled.
 */
uint_t px_set_latency_timer_register = 1;

/*
 * The following driver parameters are defined as variables to allow
 * patching for debugging and tuning.  Flags that can be set on a per
 * PBM basis are bit fields where the PBM device instance number maps
 * to the bit position.
 */
uint_t px_mmu_error_intr_enable = (uint_t)-1;
uint_t px_rerun_disable = 0;

uint_t px_error_intr_enable = (uint_t)-1;
uint_t px_dwsync_disable = 0;
uint_t px_intsync_disable = 0;

uint_t px_intr_retry_intv = 5;		/* for interrupt retry reg */
uint8_t px_latency_timer = 0x40;	/* for pci latency timer reg */
uint_t px_panic_on_fatal_errors = 1;	/* should be 1 at beta */
uint_t px_thermal_intr_fatal = 1;	/* thermal interrupts fatal */
uint_t px_buserr_interrupt = 1;	/* safari buserr interrupt */
uint_t px_ctx_no_active_flush = 0;	/* cannot handle active ctx flush */
uint_t px_use_contexts = 1;

hrtime_t px_intrpend_timeout = 5ull * NANOSEC;	/* 5 seconds in nanoseconds */

uint64_t px_perr_fatal = -1ull;
uint64_t px_serr_fatal = -1ull;
uint64_t px_errtrig_pa = 0x0;

char px_panic_hb_msg[] = " System bus";
char px_panic_rc_msg[] = " PCIe root complex";
char px_panic_rp_msg[] = " PCIe root port";
char px_panic_fab_msg[] = " PCIe fabric";

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
uint_t px_check_all_handlers = 1;

/*
 * The following value is the number of consecutive unclaimed interrupts that
 * will be tolerated for a particular ino_p before the interrupt is deemed to
 * be jabbering and is blocked.
 */
uint_t px_unclaimed_intr_max = 20;

/*
 * The following value will cause the nexus driver to block an ino after
 * px_unclaimed_intr_max unclaimed interrupts have been seen.  Setting this
 * value to 0 will cause interrupts to never be blocked, no matter how many
 * unclaimed interrupts are seen on a particular ino.
 */
uint_t px_unclaimed_intr_block = 1;

uint_t px_lock_tlb = 0;

uint64_t px_dvma_debug_on = 0;
uint64_t px_dvma_debug_off = 0;
uint32_t px_dvma_debug_rec = 512;

/*
 * dvma address space allocation cache variables
 */
uint_t px_dvma_page_cache_entries = 0x200;	/* # of chunks (1 << bits) */
uint_t px_dvma_page_cache_clustsz = 0x8;	/* # of pages per chunk */
#ifdef PX_DMA_PROF
uint_t px_dvmaft_npages = 0;			/* FT fail due npages */
uint_t px_dvmaft_limit = 0;			/* FT fail due limits */
uint_t px_dvmaft_free = 0;			/* FT free */
uint_t px_dvmaft_success = 0;			/* FT success */
uint_t px_dvmaft_exhaust = 0;			/* FT vmem fallback */
uint_t px_dvma_vmem_alloc = 0;			/* vmem alloc */
uint_t px_dvma_vmem_xalloc = 0;		/* vmem xalloc */
uint_t px_dvma_vmem_xfree = 0;			/* vmem xfree */
uint_t px_dvma_vmem_free = 0;			/* vmem free */
#endif
uint_t px_disable_fdvma = 0;
uint_t px_mmu_ctx_lock_failure = 0;

/*
 * memory callback list id callback list for kmem_alloc failure clients
 */
uintptr_t px_kmem_clid = 0;

/* timeout in micro seconds for receiving PME_To_ACK */
uint64_t px_pme_to_ack_timeout	= PX_PME_TO_ACK_TIMEOUT;

/* timeout in micro seconds for receiving link up interrupt */
uint64_t px_lup_poll_to = PX_LUP_POLL_TO;
uint64_t px_lup_poll_interval = PX_LUP_POLL_INTERVAL;

/* PIL at which PME_To_ACK message interrupt is handled */
uint32_t px_pwr_pil		= PX_PWR_PIL;

uint32_t px_max_l1_tries	= PX_MAX_L1_TRIES;

/* Print and Log tunables.  The following variables are booleans */
#ifdef DEBUG
uint32_t px_log = PX_PANIC | PX_NO_PANIC | PX_PROTECTED | PX_HW_RESET;
#else
uint32_t px_log = PX_PANIC;
#endif
uint32_t px_die = PX_PANIC | PX_PROTECTED | PX_HW_RESET;
