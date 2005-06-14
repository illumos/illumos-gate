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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/machsystm.h>
#include <sys/cpuvar.h>
#include <sys/async.h>
#include <sys/ontrap.h>
#include <sys/ddifm.h>
#include <sys/hypervisor_api.h>
#include <sys/errorq.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/x_call.h>
#include <sys/error.h>
#include <sys/fm/util.h>

#define	MAX_CE_FLTS		10
#define	MAX_ASYNC_FLTS		6

errorq_t *ue_queue;			/* queue of uncorrectable errors */
errorq_t *ce_queue;			/* queue of correctable errors */

/*
 * Being used by memory test driver.
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
 * Defined in bus_func.c but initialised in error_init
 */
extern kmutex_t bfd_lock;

static uint32_t rq_overflow_count = 0;		/* counter for rq overflow */

static void cpu_queue_one_event(errh_async_flt_t *);
static uint32_t count_entries_on_queue(uint64_t, uint64_t, uint32_t);
static void errh_page_settoxic(errh_async_flt_t *, uchar_t);
static void errh_page_retire(errh_async_flt_t *);
static int errh_error_protected(struct regs *, struct async_flt *, int *);
static void errh_rq_full(struct async_flt *);
static void ue_drain(void *, struct async_flt *, errorq_elem_t *);
static void ce_drain(void *, struct async_flt *, errorq_elem_t *);

/*ARGSUSED*/
void
process_resumable_error(struct regs *rp, uint32_t head_offset,
    uint32_t tail_offset)
{
	struct machcpu *mcpup;
	struct async_flt *aflt;
	errh_async_flt_t errh_flt;
	errh_er_t *head_va;

	mcpup = &(CPU->cpu_m);

	while (head_offset != tail_offset) {
		/* kernel buffer starts right after the resumable queue */
		head_va = (errh_er_t *)(mcpup->cpu_rq_va + head_offset +
		    CPU_RQ_SIZE);
		/* Copy the error report to local buffer */
		bzero(&errh_flt, sizeof (errh_async_flt_t));
		bcopy((char *)head_va, &(errh_flt.errh_er),
		    sizeof (errh_er_t));

		/* Increment the queue head */
		head_offset += Q_ENTRY_SIZE;
		/* Wrap around */
		head_offset &= (CPU_RQ_SIZE - 1);

		/* set error handle to zero so it can hold new error report */
		head_va->ehdl = 0;

		switch (errh_flt.errh_er.desc) {
		case ERRH_DESC_UCOR_RE:
			break;

		default:
			cmn_err(CE_WARN, "Error Descriptor 0x%llx "
			    " invalid in resumable error handler",
			    (long long) errh_flt.errh_er.desc);
			continue;
		}

		aflt = (struct async_flt *)&(errh_flt.cmn_asyncflt);
		aflt->flt_id = gethrtime();
		aflt->flt_bus_id = getprocessorid();
		aflt->flt_class = CPU_FAULT;
		aflt->flt_prot = AFLT_PROT_NONE;
		aflt->flt_priv = (((errh_flt.errh_er.attr & ERRH_MODE_MASK)
		    >> ERRH_MODE_SHIFT) == ERRH_MODE_PRIV);

		if (errh_flt.errh_er.attr & ERRH_ATTR_CPU)
			/* If it is an error on other cpu */
			aflt->flt_panic = 1;
		else
			aflt->flt_panic = 0;

		/*
		 * Handle resumable queue full case.
		 */
		if (errh_flt.errh_er.attr & ERRH_ATTR_RQF) {
			(void) errh_rq_full(aflt);
		}

		/*
		 * Queue the error on ce or ue queue depend on flt_panic.
		 * Even if flt_panic is set, the code still keep processing
		 * the rest element on rq until the panic starts.
		 */
		(void) cpu_queue_one_event(&errh_flt);

		/*
		 * Panic here if aflt->flt_panic has been set.
		 * Enqueued errors will be logged as part of the panic flow.
		 */
		if (aflt->flt_panic) {
			fm_panic("Unrecoverable error on another CPU");
		}
	}
}

void
process_nonresumable_error(struct regs *rp, uint64_t tl,
    uint32_t head_offset, uint32_t tail_offset)
{
	struct machcpu *mcpup;
	struct async_flt *aflt;
	errh_async_flt_t errh_flt;
	errh_er_t *head_va;
	int trampolined = 0;
	int expected = DDI_FM_ERR_UNEXPECTED;
	uint64_t exec_mode;

	mcpup = &(CPU->cpu_m);

	while (head_offset != tail_offset) {
		/* kernel buffer starts right after the nonresumable queue */
		head_va = (errh_er_t *)(mcpup->cpu_nrq_va + head_offset +
		    CPU_NRQ_SIZE);

		/* Copy the error report to local buffer */
		bzero(&errh_flt, sizeof (errh_async_flt_t));

		bcopy((char *)head_va, &(errh_flt.errh_er),
		    sizeof (errh_er_t));

		/* Increment the queue head */
		head_offset += Q_ENTRY_SIZE;
		/* Wrap around */
		head_offset &= (CPU_NRQ_SIZE - 1);

		/* set error handle to zero so it can hold new error report */
		head_va->ehdl = 0;

		aflt = (struct async_flt *)&(errh_flt.cmn_asyncflt);

		trampolined = 0;

		if (errh_flt.errh_er.attr & ERRH_ATTR_PIO)
			aflt->flt_class = BUS_FAULT;
		else
			aflt->flt_class = CPU_FAULT;

		aflt->flt_id = gethrtime();
		aflt->flt_bus_id = getprocessorid();
		aflt->flt_pc = (caddr_t)rp->r_pc;
		exec_mode = (errh_flt.errh_er.attr & ERRH_MODE_MASK)
		    >> ERRH_MODE_SHIFT;
		aflt->flt_priv = (exec_mode == ERRH_MODE_PRIV ||
		    exec_mode == ERRH_MODE_UNKNOWN);
		aflt->flt_tl = (uchar_t)tl;
		aflt->flt_prot = AFLT_PROT_NONE;
		aflt->flt_panic = ((aflt->flt_tl != 0) ||
		    (aft_testfatal != 0));

		switch (errh_flt.errh_er.desc) {
		case ERRH_DESC_PR_NRE:
			/*
			 * Fall through, precise fault also need to check
			 * to see if it was protected.
			 */

		case ERRH_DESC_DEF_NRE:
			/*
			 * If the trap occurred in privileged mode at TL=0,
			 * we need to check to see if we were executing
			 * in kernel under on_trap() or t_lofault
			 * protection. If so, modify the saved registers
			 * so that we return from the trap to the
			 * appropriate trampoline routine.
			 */
			if (aflt->flt_priv == 1 && aflt->flt_tl == 0)
				trampolined =
				    errh_error_protected(rp, aflt, &expected);

			if (!aflt->flt_priv || aflt->flt_prot ==
			    AFLT_PROT_COPY) {
				aflt->flt_panic |= aft_panic;
			} else if (!trampolined &&
			    aflt->flt_class != BUS_FAULT) {
				aflt->flt_panic = 1;
			}

			/*
			 * If PIO error, we need to query the bus nexus
			 * for fatal errors.
			 */
			if (aflt->flt_class == BUS_FAULT) {
				aflt->flt_addr = errh_flt.errh_er.ra;
				errh_cpu_run_bus_error_handlers(aflt,
				    expected);
			}

			break;

		default:
			cmn_err(CE_WARN, "Error Descriptor 0x%llx "
			    " invalid in nonresumable error handler",
			    (long long) errh_flt.errh_er.desc);
			continue;
		}

		/*
		 * Queue the error report for further processing. If
		 * flt_panic is set, code still process other errors
		 * in the queue until the panic routine stops the
		 * kernel.
		 */
		(void) cpu_queue_one_event(&errh_flt);

		/*
		 * Panic here if aflt->flt_panic has been set.
		 * Enqueued errors will be logged as part of the panic flow.
		 */
		if (aflt->flt_panic) {
			fm_panic("Unrecoverable hardware error");
		}

		/*
		 * If it is a memory error, we turn on the PAGE_IS_TOXIC
		 * flag. The page will be retired later and scrubbed when
		 * it is freed.
		 */
		if (errh_flt.errh_er.attr & ERRH_ATTR_MEM)
			(void) errh_page_settoxic(&errh_flt, PAGE_IS_TOXIC);

		/*
		 * If we queued an error and the it was in user mode or
		 * protected by t_lofault,
		 * set AST flag so the queue will be drained before
		 * returning to user mode.
		 */
		if (!aflt->flt_priv || aflt->flt_prot == AFLT_PROT_COPY) {
			int pcb_flag = 0;

			if (aflt->flt_class == CPU_FAULT)
				pcb_flag |= ASYNC_HWERR;
			else if (aflt->flt_class == BUS_FAULT)
				pcb_flag |= ASYNC_BERR;

			ttolwp(curthread)->lwp_pcb.pcb_flags |= pcb_flag;
			aston(curthread);
		}
	}
}

/*
 * For PIO errors, this routine calls nexus driver's error
 * callback routines. If the callback routine returns fatal, and
 * we are in kernel or unknow mode without any error protection,
 * we need to turn on the panic flag.
 */
void
errh_cpu_run_bus_error_handlers(struct async_flt *aflt, int expected)
{
	int status;
	ddi_fm_error_t de;

	bzero(&de, sizeof (ddi_fm_error_t));

	de.fme_version = DDI_FME_VERSION;
	de.fme_ena = fm_ena_generate(aflt->flt_id, FM_ENA_FMT1);
	de.fme_flag = expected;
	de.fme_bus_specific = (void *)aflt->flt_addr;
	status = ndi_fm_handler_dispatch(ddi_root_node(), NULL, &de);

	/*
	 * If error is protected, it will jump to proper routine
	 * to handle the handle; if it is in user level, we just
	 * kill the user process; if the driver thinks the error is
	 * not fatal, we can drive on. If none of above are true,
	 * we panic
	 */
	if ((aflt->flt_prot == AFLT_PROT_NONE) && (aflt->flt_priv == 1) &&
	    (status == DDI_FM_FATAL))
		aflt->flt_panic = 1;
}

/*
 * This routine checks to see if we are under any error protection when
 * the error happens. If we are under error protection, we unwind to
 * the protection and indicate fault.
 */
static int
errh_error_protected(struct regs *rp, struct async_flt *aflt, int *expected)
{
	int trampolined = 0;
	ddi_acc_hdl_t *hp;

	if (curthread->t_ontrap != NULL) {
		on_trap_data_t *otp = curthread->t_ontrap;

		if (otp->ot_prot & OT_DATA_EC) {
			aflt->flt_prot = AFLT_PROT_EC;
			otp->ot_trap |= OT_DATA_EC;
			rp->r_pc = otp->ot_trampoline;
			rp->r_npc = rp->r_pc +4;
			trampolined = 1;
		}

		if (otp->ot_prot & OT_DATA_ACCESS) {
			aflt->flt_prot = AFLT_PROT_ACCESS;
			otp->ot_trap |= OT_DATA_ACCESS;
			rp->r_pc = otp->ot_trampoline;
			rp->r_npc = rp->r_pc + 4;
			trampolined = 1;
			/*
			 * for peek and caut_gets
			 * errors are expected
			 */
			hp = (ddi_acc_hdl_t *)otp->ot_handle;
			if (!hp)
				*expected = DDI_FM_ERR_PEEK;
			else if (hp->ah_acc.devacc_attr_access ==
			    DDI_CAUTIOUS_ACC)
				*expected = DDI_FM_ERR_EXPECTED;
		}
	} else if (curthread->t_lofault) {
		aflt->flt_prot = AFLT_PROT_COPY;
		rp->r_g1 = EFAULT;
		rp->r_pc = curthread->t_lofault;
		rp->r_npc = rp->r_pc + 4;
		trampolined = 1;
	}

	return (trampolined);
}

/*
 * Queue one event.
 */
static void
cpu_queue_one_event(errh_async_flt_t *errh_fltp)
{
	struct async_flt *aflt = (struct async_flt *)errh_fltp;
	errorq_t *eqp;

	if (aflt->flt_panic)
		eqp = ue_queue;
	else
		eqp = ce_queue;

	errorq_dispatch(eqp, errh_fltp, sizeof (errh_async_flt_t),
	    aflt->flt_panic);
}

/*
 * The cpu_async_log_err() function is called by the ce/ue_drain() function to
 * handle logging for CPU events that are dequeued.  As such, it can be invoked
 * from softint context, from AST processing in the trap() flow, or from the
 * panic flow.  We decode the CPU-specific data, and log appropriate messages.
 */
void
cpu_async_log_err(void *flt)
{
	errh_async_flt_t *errh_fltp = (errh_async_flt_t *)flt;
	errh_er_t *errh_erp = (errh_er_t *)&errh_fltp->errh_er;

	switch (errh_erp->desc) {
	case ERRH_DESC_UCOR_RE:
		if (errh_erp->attr & ERRH_ATTR_MEM) {
			/*
			 * Turn on the PAGE_IS_TOXIC flag. The page will be
			 * scrubbed when it is freed.
			 */
			(void) errh_page_settoxic(errh_fltp, PAGE_IS_TOXIC);
		}

		break;

	case ERRH_DESC_PR_NRE:
	case ERRH_DESC_DEF_NRE:
		if (errh_erp->attr & ERRH_ATTR_MEM) {
			/*
			 * For non-resumable memory error, retire
			 * the page here.
			 */
			errh_page_retire(errh_fltp);
		}
		break;

	default:
		break;
	}
}

/*
 * Called from ce_drain().
 */
void
cpu_ce_log_err(struct async_flt *aflt)
{
	switch (aflt->flt_class) {
	case CPU_FAULT:
		cpu_async_log_err(aflt);
		break;

	case BUS_FAULT:
		cpu_async_log_err(aflt);
		break;

	default:
		break;
	}
}

/*
 * Called from ue_drain().
 */
void
cpu_ue_log_err(struct async_flt *aflt)
{
	switch (aflt->flt_class) {
	case CPU_FAULT:
		cpu_async_log_err(aflt);
		break;

	case BUS_FAULT:
		cpu_async_log_err(aflt);
		break;

	default:
		break;
	}
}

/*
 * Turn on flag on the error memory region.
 */
static void
errh_page_settoxic(errh_async_flt_t *errh_fltp, uchar_t flag)
{
	page_t *pp;
	uint64_t flt_real_addr_start = errh_fltp->errh_er.ra;
	uint64_t flt_real_addr_end = flt_real_addr_start +
	    errh_fltp->errh_er.sz - 1;
	int64_t current_addr;

	if (errh_fltp->errh_er.sz == 0)
		return;

	for (current_addr = flt_real_addr_start;
	    current_addr < flt_real_addr_end; current_addr += MMU_PAGESIZE) {
		pp = page_numtopp_nolock((pfn_t)
		    (current_addr >> MMU_PAGESHIFT));

		if (pp != NULL) {
			page_settoxic(pp, flag);
		}
	}
}

/*
 * Retire the page(s) indicated in the error report.
 */
static void
errh_page_retire(errh_async_flt_t *errh_fltp)
{
	page_t *pp;
	uint64_t flt_real_addr_start = errh_fltp->errh_er.ra;
	uint64_t flt_real_addr_end = flt_real_addr_start +
	    errh_fltp->errh_er.sz - 1;
	int64_t current_addr;

	if (errh_fltp->errh_er.sz == 0)
		return;

	for (current_addr = flt_real_addr_start;
	    current_addr < flt_real_addr_end; current_addr += MMU_PAGESIZE) {
		pp = page_numtopp_nolock((pfn_t)
		    (current_addr >> MMU_PAGESHIFT));

		if (pp != NULL) {
			(void) page_retire(pp, PAGE_IS_TOXIC);
		}
	}
}

void
mem_scrub(uint64_t paddr, uint64_t len)
{
	uint64_t pa, length, scrubbed_len;
	uint64_t ret = H_EOK;

	pa = paddr;
	length = len;
	scrubbed_len = 0;

	while (ret == H_EOK) {
		ret = hv_mem_scrub(pa, length, &scrubbed_len);

		if (ret == H_EOK || scrubbed_len >= length) {
			break;
		}

		pa += scrubbed_len;
		length -= scrubbed_len;
	}
}

void
mem_sync(caddr_t va, size_t len)
{
	uint64_t pa, length, flushed;
	uint64_t ret = H_EOK;

	pa = va_to_pa((caddr_t)va);

	if (pa == (uint64_t)-1)
		return;

	length = len;
	flushed = 0;

	while (ret == H_EOK) {
		ret = hv_mem_sync(pa, length, &flushed);

		if (ret == H_EOK || flushed >= length) {
			break;
		}

		pa += flushed;
		length -= flushed;
	}
}

/*
 * If resumable queue is full, we need to check if any cpu is in
 * error state. If not, we drive on. If yes, we need to panic. The
 * hypervisor call hv_cpu_state() is being used for checking the
 * cpu state.
 */
static void
errh_rq_full(struct async_flt *afltp)
{
	processorid_t who;
	uint64_t cpu_state;
	uint64_t retval;

	for (who = 0; who < NCPU; who++)
		if (CPU_IN_SET(cpu_ready_set, who)) {
			retval = hv_cpu_state(who, &cpu_state);
			if (retval != H_EOK || cpu_state == CPU_STATE_ERROR) {
				afltp->flt_panic = 1;
				break;
			}
		}
}

/*
 * Return processor specific async error structure
 * size used.
 */
int
cpu_aflt_size(void)
{
	return (sizeof (errh_async_flt_t));
}

#define	SZ_TO_ETRS_SHIFT	6

/*
 * Message print out when resumable queue is overflown
 */
/*ARGSUSED*/
void
rq_overflow(struct regs *rp, uint64_t head_offset,
    uint64_t tail_offset)
{
	rq_overflow_count++;
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
	cpu_ce_log_err(aflt);
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
	dnode_t node;
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
}
