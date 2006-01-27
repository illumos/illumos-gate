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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/mutex.h>
#include <sys/kmem.h>
#include <sys/machparam.h>
#include <sys/machsystm.h>
#include <sys/machthread.h>
#include <sys/cpu.h>
#include <sys/cpuvar.h>
#include <vm/page.h>
#include <vm/hat.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <sys/vmsystm.h>
#include <sys/vmem.h>
#include <sys/mman.h>
#include <sys/cmn_err.h>
#include <sys/time.h>
#include <sys/async.h>
#include <sys/spl.h>
#include <sys/trap.h>
#include <sys/machtrap.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/debug.h>
#include <sys/x_call.h>
#include <sys/membar.h>
#include <sys/ivintr.h>
#include <sys/cred.h>
#include <sys/cpu_module.h>
#include <sys/ontrap.h>
#include <sys/sdt.h>
#include <sys/errorq.h>

#define	MAX_CE_FLTS	10
#define	MAX_ASYNC_FLTS	6

errorq_t *ue_queue;			/* queue of uncorrectable errors */
errorq_t *ce_queue;			/* queue of correctable errors */

/*
 * ce_verbose_memory - covers CEs in DIMMs
 * ce_verbose_other - covers "others" (ecache, IO, etc.)
 *
 * If the value is 0, nothing is logged.
 * If the value is 1, the error is logged to the log file, but not console.
 * If the value is 2, the error is logged to the log file and console.
 */
int	ce_verbose_memory = 1;
int	ce_verbose_other = 1;

int	ce_show_data = 0;
int	ce_debug = 0;
int	ue_debug = 0;
int	reset_debug = 0;

/*
 * Tunables for controlling the handling of asynchronous faults (AFTs). Setting
 * these to non-default values on a non-DEBUG kernel is NOT supported.
 */
int	aft_verbose = 0;	/* log AFT messages > 1 to log only */
int	aft_panic = 0;		/* panic (not reboot) on fatal usermode AFLT */
int	aft_testfatal = 0;	/* force all AFTs to panic immediately */

/*
 * Panic_* variables specific to the AFT code.  These are used to record
 * information that the platform-specific code will need once we panic.
 */
struct async_flt panic_aflt;

/*
 * Defined in bus_func.c but initialised in error_init
 */
extern kmutex_t bfd_lock;

/*
 * Common bus driver async error logging routine.  This routine can be shared
 * by all sun4u CPUs (unlike cpu_async_log_err) because we are assuming that
 * if an i/o bus error required a panic, the error interrupt handler will
 * enqueue the error and call panic itself.
 */
void
bus_async_log_err(struct async_flt *aflt)
{
	char unum[UNUM_NAMLEN];
	int len;

	/*
	 * Call back into the processor specific routine
	 * to check for cpu related errors that may
	 * have resulted in this error. (E.g. copyout trap)
	 */
	if (aflt->flt_in_memory)
		cpu_check_allcpus(aflt);

	/*
	 * Note that aflt->flt_stat is not the CPU afsr.
	 */
	(void) cpu_get_mem_unum_aflt(AFLT_STAT_INVALID, aflt,
		    unum, UNUM_NAMLEN, &len);
	aflt->flt_func(aflt, unum);
}

/*
 * ecc_cpu_call called from bus drain functions to run cpu
 * specific functions to check other cpus and get the unum.
 */
void
ecc_cpu_call(struct async_flt *ecc, char *unum, int err_type)
{
	int len;

	/*
	 * Call back into the processor
	 * specific routine to check for cpu related errors
	 * that may have resulted in this error.
	 * (E.g. copyout trap)
	 */
	if (ecc->flt_in_memory)
		cpu_check_allcpus(ecc);

	(void) cpu_get_mem_unum(AFLT_STAT_VALID, ecc->flt_synd,
					(uint64_t)-1, ecc->flt_addr,
					ecc->flt_bus_id, ecc->flt_in_memory,
					ecc->flt_status, unum,
					UNUM_NAMLEN, &len);

	if (err_type == ECC_IO_CE)
		cpu_ce_count_unum(ecc, len, unum);
}

/*
 * Handler to process a fatal error.  This routine can be called from a
 * softint, called from trap()'s AST handling, or called from the panic flow.
 */
/*ARGSUSED*/
static void
ue_drain(void *ignored, struct async_flt *aflt, errorq_elem_t *eqep)
{
	cpu_ue_log_err(aflt);
}

/*
 * Handler to process a correctable error.  This routine can be called from a
 * softint.  We just call the CPU module's logging routine.
 */
/*ARGSUSED*/
static void
ce_drain(void *ignored, struct async_flt *aflt, errorq_elem_t *eqep)
{
	cpu_ce_log_err(aflt, eqep);
}

/*
 * Scrub a non-fatal correctable ecc error.
 */
void
ce_scrub(struct async_flt *aflt)
{
	if (aflt->flt_in_memory)
		cpu_ce_scrub_mem_err(aflt, B_FALSE);
}

/*
 * Allocate error queue sizes based on max_ncpus.  max_ncpus is set just
 * after ncpunode has been determined.  ncpus is set in start_other_cpus
 * which is called after error_init() but may change dynamically.
 */
void
error_init(void)
{
	char tmp_name[MAXSYSNAME];
	pnode_t node;
	size_t size = cpu_aflt_size();

	/*
	 * Initialize the correctable and uncorrectable error queues.
	 */
	ue_queue = errorq_create("ue_queue", (errorq_func_t)ue_drain, NULL,
	    MAX_ASYNC_FLTS * (max_ncpus + 1), size, PIL_2, ERRORQ_VITAL);

	ce_queue = errorq_create("ce_queue", (errorq_func_t)ce_drain, NULL,
	    MAX_CE_FLTS * (max_ncpus + 1), size, PIL_1, 0);

	if (ue_queue == NULL || ce_queue == NULL)
		panic("failed to create required system error queue");

	/*
	 * Initialize the busfunc list mutex.  This must be a PIL_15 spin lock
	 * because we will need to acquire it from cpu_async_error().
	 */
	mutex_init(&bfd_lock, NULL, MUTEX_SPIN, (void *)PIL_15);

	node = prom_rootnode();
	if ((node == OBP_NONODE) || (node == OBP_BADNODE)) {
		cmn_err(CE_CONT, "error_init: node 0x%x\n", (uint_t)node);
		return;
	}

	if (((size = prom_getproplen(node, "reset-reason")) != -1) &&
	    (size <= MAXSYSNAME) &&
	    (prom_getprop(node, "reset-reason", tmp_name) != -1)) {
		if (reset_debug) {
			cmn_err(CE_CONT, "System booting after %s\n", tmp_name);
		} else if (strncmp(tmp_name, "FATAL", 5) == 0) {
			cmn_err(CE_CONT,
			    "System booting after fatal error %s\n", tmp_name);
		}
	}

	if (&cpu_error_init) {
		cpu_error_init((MAX_ASYNC_FLTS + MAX_CE_FLTS) *
		    (max_ncpus + 1));
	}
}

/*
 * Flags for ecc_page_zero DTrace probe since ecc_page_zero() is called
 * as a softint handler.
 */
#define	PAGE_ZERO_SUCCESS	0
#define	PAGE_ZERO_FAIL_NOLOCK	1
#define	PAGE_ZERO_FAIL_ONTRAP	2

void
ecc_page_zero(void *arg)
{
	uint64_t pa = (uint64_t)arg;
	int ret, success_flag;
	page_t *pp = page_numtopp_nolock(mmu_btop(pa));

	if (page_retire_check(pa, NULL) != 0)
		return;

	/*
	 * Must hold a lock on the page before calling pagezero()
	 *
	 * This will only fail if someone has or wants an exclusive lock on
	 * the page.  Since it's a retired page, this shouldn't happen.
	 */
	ret = page_lock_es(pp, SE_SHARED, (kmutex_t *)NULL,
	    P_NO_RECLAIM, SE_RETIRED);

	if (ret > 0) {
		on_trap_data_t otd;

		/*
		 * Protect pagezero() from async faults
		 */
		if (!on_trap(&otd, OT_DATA_EC)) {
			pagezero(pp, 0, PAGESIZE);
			success_flag = PAGE_ZERO_SUCCESS;
		} else {
			success_flag = PAGE_ZERO_FAIL_ONTRAP;
		}
		no_trap();
		page_unlock(pp);
	} else {
		success_flag = PAGE_ZERO_FAIL_NOLOCK;
	}
	DTRACE_PROBE2(page_zero_result, int, success_flag, uint64_t, pa);
}
