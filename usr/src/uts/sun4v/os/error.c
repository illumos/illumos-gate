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

#include <sys/types.h>
#include <sys/machsystm.h>
#include <sys/sysmacros.h>
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
#include <sys/ivintr.h>
#include <sys/machasi.h>
#include <sys/mmu.h>
#include <sys/archsystm.h>

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
 * Used for vbsc hostshutdown (power-off button)
 */
int	err_shutdown_triggered = 0;	/* only once */
uint64_t err_shutdown_inum = 0;	/* used to pull the trigger */

/*
 * Used to print NRE/RE via system variable or kmdb
 */
int		printerrh = 0;		/* see /etc/system */
static void	errh_er_print(errh_er_t *, const char *);
kmutex_t	errh_print_lock;

/*
 * Defined in bus_func.c but initialised in error_init
 */
extern kmutex_t bfd_lock;

static uint32_t rq_overflow_count = 0;		/* counter for rq overflow */

static void cpu_queue_one_event(errh_async_flt_t *);
static uint32_t count_entries_on_queue(uint64_t, uint64_t, uint32_t);
static void errh_page_retire(errh_async_flt_t *, uchar_t);
static int errh_error_protected(struct regs *, struct async_flt *, int *);
static void errh_rq_full(struct async_flt *);
static void ue_drain(void *, struct async_flt *, errorq_elem_t *);
static void ce_drain(void *, struct async_flt *, errorq_elem_t *);
static void errh_handle_attr(errh_async_flt_t *);
static void errh_handle_asr(errh_async_flt_t *);

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

		mcpup->cpu_rq_lastre = head_va;
		if (printerrh)
			errh_er_print(&errh_flt.errh_er, "RQ");

		/* Increment the queue head */
		head_offset += Q_ENTRY_SIZE;
		/* Wrap around */
		head_offset &= (CPU_RQ_SIZE - 1);

		/* set error handle to zero so it can hold new error report */
		head_va->ehdl = 0;

		switch (errh_flt.errh_er.desc) {
		case ERRH_DESC_UCOR_RE:
			/*
			 * Check error attribute, handle individual error
			 * if it is needed.
			 */
			errh_handle_attr(&errh_flt);
			break;

		case ERRH_DESC_WARN_RE:
			/*
			 * Power-off requested, but handle it one time only.
			 */
			if (!err_shutdown_triggered) {
				setsoftint(err_shutdown_inum);
				++err_shutdown_triggered;
			}
			continue;

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
process_nonresumable_error(struct regs *rp, uint64_t flags,
    uint32_t head_offset, uint32_t tail_offset)
{
	struct machcpu *mcpup;
	struct async_flt *aflt;
	errh_async_flt_t errh_flt;
	errh_er_t *head_va;
	int trampolined = 0;
	int expected = DDI_FM_ERR_UNEXPECTED;
	uint64_t exec_mode;
	uint8_t u_spill_fill;
	int u_kill = 1;

	mcpup = &(CPU->cpu_m);

	while (head_offset != tail_offset) {
		/* kernel buffer starts right after the nonresumable queue */
		head_va = (errh_er_t *)(mcpup->cpu_nrq_va + head_offset +
		    CPU_NRQ_SIZE);

		/* Copy the error report to local buffer */
		bzero(&errh_flt, sizeof (errh_async_flt_t));

		bcopy((char *)head_va, &(errh_flt.errh_er),
		    sizeof (errh_er_t));

		mcpup->cpu_nrq_lastnre = head_va;
		if (printerrh)
			errh_er_print(&errh_flt.errh_er, "NRQ");

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
		aflt->flt_prot = AFLT_PROT_NONE;
		aflt->flt_tl = (uchar_t)(flags & ERRH_TL_MASK);
		aflt->flt_panic = ((aflt->flt_tl != 0) ||
		    (aft_testfatal != 0));

		/*
		 * For the first error packet on the queue, check if it
		 * happened in user fill/spill trap.
		 */
		if (flags & ERRH_U_SPILL_FILL) {
			u_spill_fill = 1;
			/* clear the user fill/spill flag in flags */
			flags = (uint64_t)aflt->flt_tl;
		} else
			u_spill_fill = 0;

		switch (errh_flt.errh_er.desc) {
		case ERRH_DESC_PR_NRE:
			if (u_spill_fill) {
				aflt->flt_panic = 0;
				break;
			}
			/*
			 * Context Register Parity - for reload of secondary
			 * context register, see nonresumable_error.  Note
			 * that 'size' for CRP denotes a sense of version,
			 * so if it's out of range, then just let it fall
			 * through and be processed later.
			 */
			if ((errh_flt.errh_er.attr & ERRH_ATTR_ASI) &&
			    (errh_flt.errh_er.asi == ASI_MMU_CTX) &&
			    (errh_flt.errh_er.addr >= MMU_PCONTEXT0) &&
			    (errh_flt.errh_er.addr + errh_flt.errh_er.sz <=
			    MMU_SCONTEXT1 + sizeof (uint64_t))) {

				if (aflt->flt_tl)	/* TL>0, so panic */
					break;

				u_kill = 0;		/* do not terminate */
				break;
			}
			/*
			 * All other PR_NRE fall through in order to
			 * check for protection.  The list can include
			 * ERRH_ATTR_FRF, ERRH_ATTR_IRF, ERRH_ATTR_MEM,
			 * and ERRH_ATTR_PIO.
			 */
			/*FALLTHRU*/

		case ERRH_DESC_DEF_NRE:
			/*
			 * If the trap occurred in privileged mode at TL=0,
			 * we need to check to see if we were executing
			 * in kernel under on_trap() or t_lofault
			 * protection. If so, and if it was a PIO or MEM
			 * error, then modify the saved registers so that
			 * we return from the trap to the appropriate
			 * trampoline routine.
			 */
			if (aflt->flt_priv == 1 && aflt->flt_tl == 0 &&
			    ((errh_flt.errh_er.attr & ERRH_ATTR_PIO) ||
			    (errh_flt.errh_er.attr & ERRH_ATTR_MEM))) {
				trampolined =
				    errh_error_protected(rp, aflt, &expected);
			}

			if (!aflt->flt_priv || aflt->flt_prot ==
			    AFLT_PROT_COPY) {
				aflt->flt_panic |= aft_panic;
			} else if (!trampolined &&
			    (aflt->flt_class != BUS_FAULT)) {
				aflt->flt_panic = 1;
			}

			/*
			 * Check error attribute, handle individual error
			 * if it is needed.
			 */
			errh_handle_attr(&errh_flt);

			/*
			 * If PIO error, we need to query the bus nexus
			 * for fatal errors.
			 */
			if (aflt->flt_class == BUS_FAULT) {
				aflt->flt_addr = errh_flt.errh_er.addr;
				errh_cpu_run_bus_error_handlers(aflt,
				    expected);
			}

			break;

		case ERRH_DESC_USER_DCORE:
			/*
			 * User generated panic. Call panic directly
			 * since there are no FMA e-reports to
			 * display.
			 */

			panic("Panic - Generated at user request");

			break;

		default:
			cmn_err(CE_WARN, "Panic - Error Descriptor 0x%llx "
			    " invalid in non-resumable error handler",
			    (long long) errh_flt.errh_er.desc);
			aflt->flt_panic = 1;
			break;
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
		 * Call page_retire() to handle memory errors.
		 */
		if (errh_flt.errh_er.attr & ERRH_ATTR_MEM)
			errh_page_retire(&errh_flt, PR_UE);

		/*
		 * If we queued an error for a thread that should terminate
		 * and it was in user mode or protected by t_lofault, set AST
		 * flag so the queue will be drained before returning to user
		 * mode.  Note that user threads can be killed via pcb_flags.
		 */
		if (u_kill && (!aflt->flt_priv ||
		    aflt->flt_prot == AFLT_PROT_COPY || u_spill_fill)) {
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
			 * Turn on the PR_UE flag. The page will be
			 * scrubbed when it is freed.
			 */
			errh_page_retire(errh_fltp, PR_UE);
		}

		break;

	case ERRH_DESC_PR_NRE:
	case ERRH_DESC_DEF_NRE:
		if (errh_erp->attr & ERRH_ATTR_MEM) {
			/*
			 * For non-resumable memory error, retire
			 * the page here.
			 */
			errh_page_retire(errh_fltp, PR_UE);

			/*
			 * If we are going to panic, scrub the page first
			 */
			if (errh_fltp->cmn_asyncflt.flt_panic)
				mem_scrub(errh_fltp->errh_er.addr,
				    errh_fltp->errh_er.sz);
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
errh_page_retire(errh_async_flt_t *errh_fltp, uchar_t flag)
{
	uint64_t flt_real_addr_start = errh_fltp->errh_er.addr;
	uint64_t flt_real_addr_end = flt_real_addr_start +
	    errh_fltp->errh_er.sz - 1;
	int64_t current_addr;

	if (errh_fltp->errh_er.sz == 0)
		return;

	for (current_addr = flt_real_addr_start;
	    current_addr < flt_real_addr_end; current_addr += MMU_PAGESIZE) {
		(void) page_retire(current_addr, flag);
	}
}

void
mem_scrub(uint64_t paddr, uint64_t len)
{
	uint64_t pa, length, scrubbed_len;

	pa = paddr;
	length = len;
	scrubbed_len = 0;

	while (length > 0) {
		if (hv_mem_scrub(pa, length, &scrubbed_len) != H_EOK)
			break;

		pa += scrubbed_len;
		length -= scrubbed_len;
	}
}

/*
 * Call hypervisor to flush the memory region.
 * Both va and len must be MMU_PAGESIZE aligned.
 * Returns the total number of bytes flushed.
 */
uint64_t
mem_sync(caddr_t orig_va, size_t orig_len)
{
	uint64_t pa, length, flushed;
	uint64_t chunk_len = MMU_PAGESIZE;
	uint64_t total_flushed = 0;
	uint64_t va, len;

	if (orig_len == 0)
		return (total_flushed);

	/* align va */
	va = P2ALIGN_TYPED(orig_va, MMU_PAGESIZE, uint64_t);
	/* round up len to MMU_PAGESIZE aligned */
	len = P2ROUNDUP_TYPED(orig_va + orig_len, MMU_PAGESIZE, uint64_t) - va;

	while (len > 0) {
		pa = va_to_pa((caddr_t)va);
		if (pa == (uint64_t)-1)
			return (total_flushed);

		length = chunk_len;
		flushed = 0;

		while (length > 0) {
			if (hv_mem_sync(pa, length, &flushed) != H_EOK)
				return (total_flushed);

			pa += flushed;
			length -= flushed;
			total_flushed += flushed;
		}

		va += chunk_len;
		len -= chunk_len;
	}

	return (total_flushed);
}

/*
 * If resumable queue is full, we need to check if any cpu is in
 * error state. If not, we drive on. If yes, we need to panic. The
 * hypervisor call hv_cpu_state() is being used for checking the
 * cpu state.  And reset %tick_compr in case tick-compare was lost.
 */
static void
errh_rq_full(struct async_flt *afltp)
{
	processorid_t who;
	uint64_t cpu_state;
	uint64_t retval;
	uint64_t current_tick;

	current_tick = (uint64_t)gettick();
	tickcmpr_set(current_tick);

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
 * Handler to process vbsc hostshutdown (power-off button).
 */
static int
err_shutdown_softintr()
{
	cmn_err(CE_WARN, "Power-off requested, system will now shutdown.");
	do_shutdown();

	/*
	 * just in case do_shutdown() fails
	 */
	(void) timeout((void(*)(void *))power_down, NULL, 100 * hz);
	return (DDI_INTR_CLAIMED);
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
	 * Setup interrupt handler for power-off button.
	 */
	err_shutdown_inum = add_softintr(PIL_9,
	    (softintrfunc)err_shutdown_softintr, NULL, SOFTINT_ST);

	/*
	 * Initialize the busfunc list mutex.  This must be a PIL_15 spin lock
	 * because we will need to acquire it from cpu_async_error().
	 */
	mutex_init(&bfd_lock, NULL, MUTEX_SPIN, (void *)PIL_15);

	/* Only allow one cpu at a time to dump errh errors. */
	mutex_init(&errh_print_lock, NULL, MUTEX_SPIN, (void *)PIL_15);

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

/*
 * Nonresumable queue is full, panic here
 */
/*ARGSUSED*/
void
nrq_overflow(struct regs *rp)
{
	fm_panic("Nonresumable queue full");
}

/*
 * This is the place for special error handling for individual errors.
 */
static void
errh_handle_attr(errh_async_flt_t *errh_fltp)
{
	switch (errh_fltp->errh_er.attr & ~ERRH_MODE_MASK) {
	case ERRH_ATTR_CPU:
	case ERRH_ATTR_MEM:
	case ERRH_ATTR_PIO:
	case ERRH_ATTR_IRF:
	case ERRH_ATTR_FRF:
	case ERRH_ATTR_SHUT:
		break;

	case ERRH_ATTR_ASR:
		errh_handle_asr(errh_fltp);
		break;

	case ERRH_ATTR_ASI:
	case ERRH_ATTR_PREG:
	case ERRH_ATTR_RQF:
		break;

	default:
		break;
	}
}

/*
 * Handle ASR bit set in ATTR
 */
static void
errh_handle_asr(errh_async_flt_t *errh_fltp)
{
	uint64_t current_tick;

	switch (errh_fltp->errh_er.reg) {
	case ASR_REG_VALID | ASR_REG_TICK:
		/*
		 * For Tick Compare Register error, it only happens when
		 * the register is being read or compared with the %tick
		 * register. Since we lost the contents of the register,
		 * we set the %tick_compr in the future. An interrupt will
		 * happen when %tick matches the value field of %tick_compr.
		 */
		current_tick = (uint64_t)gettick();
		tickcmpr_set(current_tick);
		/* Do not panic */
		errh_fltp->cmn_asyncflt.flt_panic = 0;
		break;

	default:
		break;
	}
}

/*
 * Dump the error packet
 */
/*ARGSUSED*/
static void
errh_er_print(errh_er_t *errh_erp, const char *queue)
{
	typedef union {
		uint64_t w;
		uint16_t s[4];
	} errhp_t;
	errhp_t *p = (errhp_t *)errh_erp;
	int i;

	mutex_enter(&errh_print_lock);
	switch (errh_erp->desc) {
	case ERRH_DESC_UCOR_RE:
		cmn_err(CE_CONT, "\nResumable Uncorrectable Error ");
		break;
	case ERRH_DESC_PR_NRE:
		cmn_err(CE_CONT, "\nNonresumable Precise Error ");
		break;
	case ERRH_DESC_DEF_NRE:
		cmn_err(CE_CONT, "\nNonresumable Deferred Error ");
		break;
	default:
		cmn_err(CE_CONT, "\nError packet ");
		break;
	}
	cmn_err(CE_CONT, "received on %s\n", queue);

	/*
	 * Print Q_ENTRY_SIZE bytes of epacket with 8 bytes per line
	 */
	for (i = Q_ENTRY_SIZE; i > 0; i -= 8, ++p) {
		cmn_err(CE_CONT, "%016lx: %04x %04x %04x %04x\n", (uint64_t)p,
		    p->s[0], p->s[1], p->s[2], p->s[3]);
	}
	mutex_exit(&errh_print_lock);
}
