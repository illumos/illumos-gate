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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2018 Joyent, Inc.
 */

#define	PSMI_1_7

#include <sys/mutex.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/clock.h>
#include <sys/machlock.h>
#include <sys/smp_impldefs.h>
#include <sys/uadmin.h>
#include <sys/promif.h>
#include <sys/psm.h>
#include <sys/psm_common.h>
#include <sys/atomic.h>
#include <sys/apic.h>
#include <sys/archsystm.h>
#include <sys/mach_intr.h>
#include <sys/hypervisor.h>
#include <sys/evtchn_impl.h>
#include <sys/modctl.h>
#include <sys/trap.h>
#include <sys/panic.h>
#include <sys/sysmacros.h>
#include <sys/pci_intr_lib.h>
#include <vm/hat_i86.h>

#include <xen/public/vcpu.h>
#include <xen/public/physdev.h>


/*
 * Global Data
 */

int xen_psm_verbose = 0;

/* As of now we don't support x2apic in xVM */
volatile uint32_t *apicadr = NULL;	/* dummy, so common code will link */
int apic_error = 0;
int apic_verbose = 0;
cpuset_t apic_cpumask;
int apic_forceload = 0;
uchar_t apic_vectortoipl[APIC_AVAIL_VECTOR / APIC_VECTOR_PER_IPL] = {
	3, 4, 5, 5, 6, 6, 9, 10, 11, 12, 13, 14, 15, 15
};
uchar_t apic_ipltopri[MAXIPL + 1];
uchar_t apic_ipls[APIC_AVAIL_VECTOR];
uint_t apic_picinit_called;
apic_cpus_info_t *apic_cpus;
int xen_psm_intr_policy = INTR_ROUND_ROBIN_WITH_AFFINITY;
/* use to make sure only one cpu handles the nmi */
static lock_t xen_psm_nmi_lock;
int xen_psm_kmdb_on_nmi = 0;		/* 0 - no, 1 - yes enter kmdb */
int xen_psm_panic_on_nmi = 0;
int xen_psm_num_nmis = 0;

cpuset_t xen_psm_cpus_online;	/* online cpus */
int xen_psm_ncpus = 1;		/* cpu count */
int xen_psm_next_bind_cpu;	/* next cpu to bind an interrupt to */

int xen_support_msi = 0;

static int xen_clock_irq = INVALID_IRQ;

/* flag definitions for xen_psm_verbose */
#define	XEN_PSM_VERBOSE_IRQ_FLAG		0x00000001
#define	XEN_PSM_VERBOSE_POWEROFF_FLAG		0x00000002
#define	XEN_PSM_VERBOSE_POWEROFF_PAUSE_FLAG	0x00000004

#define	XEN_PSM_VERBOSE_IRQ(fmt) \
	if (xen_psm_verbose & XEN_PSM_VERBOSE_IRQ_FLAG) \
		cmn_err fmt;

#define	XEN_PSM_VERBOSE_POWEROFF(fmt) \
	if (xen_psm_verbose & XEN_PSM_VERBOSE_POWEROFF_FLAG) \
		prom_printf fmt;

/*
 * Dummy apic array to point common routines at that want to do some apic
 * manipulation.  Xen doesn't allow guest apic access so we point at these
 * memory locations to fake out those who want to do apic fiddling.
 */
uint32_t xen_psm_dummy_apic[APIC_IRR_REG + 1];

static struct psm_info xen_psm_info;
static void xen_psm_setspl(int);

int
apic_alloc_msi_vectors(dev_info_t *dip, int inum, int count, int pri,
    int behavior);
int
apic_alloc_msix_vectors(dev_info_t *dip, int inum, int count, int pri,
    int behavior);

/*
 * Local support routines
 */

/*
 * Select vcpu to bind xen virtual device interrupt to.
 */
/*ARGSUSED*/
int
xen_psm_bind_intr(int irq)
{
	int bind_cpu;
	apic_irq_t *irqptr;

	bind_cpu = IRQ_UNBOUND;
	if (xen_psm_intr_policy == INTR_LOWEST_PRIORITY)
		return (bind_cpu);
	if (irq <= APIC_MAX_VECTOR)
		irqptr = apic_irq_table[irq];
	else
		irqptr = NULL;
	if (irqptr && (irqptr->airq_cpu != IRQ_UNBOUND))
		bind_cpu = irqptr->airq_cpu & ~IRQ_USER_BOUND;
	if (bind_cpu != IRQ_UNBOUND) {
		if (!CPU_IN_SET(xen_psm_cpus_online, bind_cpu))
			bind_cpu = 0;
		goto done;
	}
	if (xen_psm_intr_policy == INTR_ROUND_ROBIN_WITH_AFFINITY) {
		do {
			bind_cpu = xen_psm_next_bind_cpu++;
			if (xen_psm_next_bind_cpu >= xen_psm_ncpus)
				xen_psm_next_bind_cpu = 0;
		} while (!CPU_IN_SET(xen_psm_cpus_online, bind_cpu));
	} else {
		bind_cpu = 0;
	}
done:
	return (bind_cpu);
}

/*
 * Autoconfiguration Routines
 */

static int
xen_psm_probe(void)
{
	int ret = PSM_SUCCESS;

	if (DOMAIN_IS_INITDOMAIN(xen_info))
		ret = apic_probe_common(xen_psm_info.p_mach_idstring);
	return (ret);
}

static void
xen_psm_softinit(void)
{
	/* LINTED logical expression always true: op "||" */
	ASSERT((1 << EVTCHN_SHIFT) == NBBY * sizeof (ulong_t));
	CPUSET_ATOMIC_ADD(xen_psm_cpus_online, 0);
	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		apic_init_common();
	}
}

#define	XEN_NSEC_PER_TICK	10 /* XXX - assume we have a 100 Mhz clock */

/*ARGSUSED*/
static int
xen_psm_clkinit(int hertz)
{
	extern enum tod_fault_type tod_fault(enum tod_fault_type, int);
	extern int dosynctodr;

	/*
	 * domU cannot set the TOD hardware, fault the TOD clock now to
	 * indicate that and turn off attempts to sync TOD hardware
	 * with the hires timer.
	 */
	if (!DOMAIN_IS_INITDOMAIN(xen_info)) {
		mutex_enter(&tod_lock);
		(void) tod_fault(TOD_RDONLY, 0);
		dosynctodr = 0;
		mutex_exit(&tod_lock);
	}
	/*
	 * The hypervisor provides a timer based on the local APIC timer.
	 * The interface supports requests of nanosecond resolution.
	 * A common frequency of the apic clock is 100 Mhz which
	 * gives a resolution of 10 nsec per tick.  What we would really like
	 * is a way to get the ns per tick value from xen.
	 * XXPV - This is an assumption that needs checking and may change
	 */
	return (XEN_NSEC_PER_TICK);
}

static void
xen_psm_hrtimeinit(void)
{
	extern int gethrtime_hires;
	gethrtime_hires = 1;
}

/* xen_psm NMI handler */
/*ARGSUSED*/
static void
xen_psm_nmi_intr(caddr_t arg, struct regs *rp)
{
	xen_psm_num_nmis++;

	if (!lock_try(&xen_psm_nmi_lock))
		return;

	if (xen_psm_kmdb_on_nmi && psm_debugger()) {
		debug_enter("NMI received: entering kmdb\n");
	} else if (xen_psm_panic_on_nmi) {
		/* Keep panic from entering kmdb. */
		nopanicdebug = 1;
		panic("NMI received\n");
	} else {
		/*
		 * prom_printf is the best shot we have of something which is
		 * problem free from high level/NMI type of interrupts
		 */
		prom_printf("NMI received\n");
	}

	lock_clear(&xen_psm_nmi_lock);
}

static void
xen_psm_picinit()
{
	int cpu, irqno;
	cpuset_t cpus;

	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		/* set a flag so we know we have run xen_psm_picinit() */
		apic_picinit_called = 1;
		LOCK_INIT_CLEAR(&apic_ioapic_lock);

		/* XXPV - do we need to do this? */
		picsetup();	 /* initialise the 8259 */

		/* enable apic mode if imcr present */
		/* XXPV - do we need to do this either? */
		if (apic_imcrp) {
			outb(APIC_IMCR_P1, (uchar_t)APIC_IMCR_SELECT);
			outb(APIC_IMCR_P2, (uchar_t)APIC_IMCR_APIC);
		}

		ioapic_init_intr(IOAPIC_NOMASK);
		/*
		 * We never called xen_psm_addspl() when the SCI
		 * interrupt was added because that happened before the
		 * PSM module was loaded.  Fix that up here by doing
		 * any missed operations (e.g. bind to CPU)
		 */
		if ((irqno = apic_sci_vect) > 0) {
			if ((cpu = xen_psm_bind_intr(irqno)) == IRQ_UNBOUND) {
				CPUSET_ZERO(cpus);
				CPUSET_OR(cpus, xen_psm_cpus_online);
			} else {
				CPUSET_ONLY(cpus, cpu & ~IRQ_USER_BOUND);
			}
			ec_set_irq_affinity(irqno, cpus);
			apic_irq_table[irqno]->airq_temp_cpu =
			    (uchar_t)(cpu & ~IRQ_USER_BOUND);
			ec_enable_irq(irqno);
		}
	}

	/* add nmi handler - least priority nmi handler */
	LOCK_INIT_CLEAR(&xen_psm_nmi_lock);

	if (!psm_add_nmintr(0, (avfunc) xen_psm_nmi_intr,
	    "xVM_psm NMI handler", (caddr_t)NULL))
		cmn_err(CE_WARN, "xVM_psm: Unable to add nmi handler");
}


/*
 * generates an interprocessor interrupt to another CPU
 */
static void
xen_psm_send_ipi(int cpun, int ipl)
{
	ulong_t flag = intr_clear();

	ec_send_ipi(ipl, cpun);
	intr_restore(flag);
}

/*ARGSUSED*/
static int
xen_psm_addspl(int irqno, int ipl, int min_ipl, int max_ipl)
{
	int cpu, ret;
	cpuset_t cpus;

	/*
	 * We are called at splhi() so we can't call anything that might end
	 * up trying to context switch.
	 */
	if (irqno >= PIRQ_BASE && irqno < NR_PIRQS &&
	    DOMAIN_IS_INITDOMAIN(xen_info)) {
		/*
		 * Priority/affinity/enable for PIRQ's is set in ec_setup_pirq()
		 */
		ret = apic_addspl_common(irqno, ipl, min_ipl, max_ipl);
	} else {
		/*
		 * Set priority/affinity/enable for non PIRQs
		 */
		ret = ec_set_irq_priority(irqno, ipl);
		ASSERT(ret == 0);
		if ((cpu = xen_psm_bind_intr(irqno)) == IRQ_UNBOUND) {
			CPUSET_ZERO(cpus);
			CPUSET_OR(cpus, xen_psm_cpus_online);
		} else {
			CPUSET_ONLY(cpus, cpu & ~IRQ_USER_BOUND);
		}
		ec_set_irq_affinity(irqno, cpus);
		ec_enable_irq(irqno);
	}
	return (ret);
}

/*
 * Acquire ownership of this irq on this cpu
 */
void
xen_psm_acquire_irq(int irq)
{
	ulong_t flags;
	int cpuid;

	/*
	 * If the irq is currently being serviced by another cpu
	 * we busy-wait for the other cpu to finish.  Take any
	 * pending interrupts before retrying.
	 */
	do {
		flags = intr_clear();
		cpuid = ec_block_irq(irq);
		intr_restore(flags);
	} while (cpuid != CPU->cpu_id);
}

/*ARGSUSED*/
static int
xen_psm_delspl(int irqno, int ipl, int min_ipl, int max_ipl)
{
	apic_irq_t *irqptr;
	int err = PSM_SUCCESS;

	if (irqno >= PIRQ_BASE && irqno < NR_PIRQS &&
	    DOMAIN_IS_INITDOMAIN(xen_info)) {
		irqptr = apic_irq_table[irqno];
		/*
		 * unbind if no more sharers of this irq/evtchn
		 */
		if (irqptr->airq_share == 1) {
			xen_psm_acquire_irq(irqno);
			ec_unbind_irq(irqno);
		}
		err = apic_delspl_common(irqno, ipl, min_ipl, max_ipl);
		/*
		 * If still in use reset priority
		 */
		if (!err && irqptr->airq_share != 0) {
			err = ec_set_irq_priority(irqno, max_ipl);
			return (err);
		}
	} else {
		xen_psm_acquire_irq(irqno);
		ec_unbind_irq(irqno);
	}
	return (err);
}

static processorid_t
xen_psm_get_next_processorid(processorid_t id)
{
	if (id == -1)
		return (0);

	for (id++; id < NCPU; id++) {
		switch (-HYPERVISOR_vcpu_op(VCPUOP_is_up, id, NULL)) {
		case 0:		/* yeah, that one's there */
			return (id);
		default:
		case X_EINVAL:	/* out of range */
			return (-1);
		case X_ENOENT:	/* not present in the domain */
			/*
			 * It's not clear that we -need- to keep looking
			 * at this point, if, e.g., we can guarantee
			 * the hypervisor always keeps a contiguous range
			 * of vcpus around this is equivalent to "out of range".
			 *
			 * But it would be sad to miss a vcpu we're
			 * supposed to be using ..
			 */
			break;
		}
	}

	return (-1);
}

/*
 * XXPV - undo the start cpu op change; return to ignoring this value
 *	- also tweak error handling in main startup loop
 */
/*ARGSUSED*/
static int
xen_psm_cpu_start(processorid_t id, caddr_t arg)
{
	int ret;

	ASSERT(id > 0);
	CPUSET_ATOMIC_ADD(xen_psm_cpus_online, id);
	ec_bind_cpu_ipis(id);
	(void) ec_bind_virq_to_irq(VIRQ_TIMER, id);
	if ((ret = xen_vcpu_up(id)) == 0)
		xen_psm_ncpus++;
	else
		ret = EINVAL;
	return (ret);
}

/*
 * Allocate an irq for inter cpu signaling
 */
/*ARGSUSED*/
static int
xen_psm_get_ipivect(int ipl, int type)
{
	return (ec_bind_ipi_to_irq(ipl, 0));
}

/*ARGSUSED*/
static int
xen_psm_get_clockirq(int ipl)
{
	if (xen_clock_irq != INVALID_IRQ)
		return (xen_clock_irq);

	xen_clock_irq = ec_bind_virq_to_irq(VIRQ_TIMER, 0);
	return (xen_clock_irq);
}

/*ARGSUSED*/
static void
xen_psm_shutdown(int cmd, int fcn)
{
	XEN_PSM_VERBOSE_POWEROFF(("xen_psm_shutdown(%d,%d);\n", cmd, fcn));

	switch (cmd) {
	case A_SHUTDOWN:
		switch (fcn) {
		case AD_BOOT:
		case AD_IBOOT:
			(void) HYPERVISOR_shutdown(SHUTDOWN_reboot);
			break;
		case AD_POWEROFF:
			/* fall through if domU or if poweroff fails */
			if (DOMAIN_IS_INITDOMAIN(xen_info))
				if (apic_enable_acpi)
					(void) acpi_poweroff();
			/* FALLTHRU */
		case AD_HALT:
		default:
			(void) HYPERVISOR_shutdown(SHUTDOWN_poweroff);
			break;
		}
		break;
	case A_REBOOT:
		(void) HYPERVISOR_shutdown(SHUTDOWN_reboot);
		break;
	default:
		return;
	}
}


static int
xen_psm_translate_irq(dev_info_t *dip, int irqno)
{
	if (dip == NULL) {
		XEN_PSM_VERBOSE_IRQ((CE_CONT, "!xen_psm: irqno = %d"
		    " dip = NULL\n", irqno));
		return (irqno);
	}
	return (irqno);
}

/*
 * xen_psm_intr_enter() acks the event that triggered the interrupt and
 * returns the new priority level,
 */
/*ARGSUSED*/
static int
xen_psm_intr_enter(int ipl, int *vector)
{
	int newipl;
	uint_t intno;
	cpu_t *cpu = CPU;

	intno = (*vector);

	ASSERT(intno < NR_IRQS);
	ASSERT(cpu->cpu_m.mcpu_vcpu_info->evtchn_upcall_mask != 0);

	if (!ec_is_edge_pirq(intno))
		ec_clear_irq(intno);

	newipl = autovect[intno].avh_hi_pri;
	if (newipl == 0) {
		/*
		 * (newipl == 0) means we have no service routines for this
		 * vector.  We will treat this as a spurious interrupt.
		 * We have cleared the pending bit already, clear the event
		 * mask and return a spurious interrupt.  This case can happen
		 * when an interrupt delivery is racing with the removal of
		 * of the service routine for that interrupt.
		 */
		ec_unmask_irq(intno);
		newipl = -1;	/* flag spurious interrupt */
	} else if (newipl <= cpu->cpu_pri) {
		/*
		 * (newipl <= cpu->cpu_pri) means that we must be trying to
		 * service a vector that was shared with a higher priority
		 * isr.  The higher priority handler has been removed and
		 * we need to service this int.  We can't return a lower
		 * priority than current cpu priority.  Just synthesize a
		 * priority to return that should be acceptable.
		 * It should never happen that we synthesize a priority that
		 * moves us from low-priority to high-priority that would make
		 * a us incorrectly run on the high priority stack.
		 */
		newipl = cpu->cpu_pri + 1;	/* synthetic priority */
		ASSERT(newipl != LOCK_LEVEL + 1);
	}
	return (newipl);
}


/*
 * xen_psm_intr_exit() restores the old interrupt
 * priority level after processing an interrupt.
 * It is called with interrupts disabled, and does not enable interrupts.
 */
/* ARGSUSED */
static void
xen_psm_intr_exit(int ipl, int vector)
{
	ec_try_unmask_irq(vector);
	xen_psm_setspl(ipl);
}

intr_exit_fn_t
psm_intr_exit_fn(void)
{
	return (xen_psm_intr_exit);
}

/*
 * Check if new ipl level allows delivery of previously unserviced events
 */
static void
xen_psm_setspl(int ipl)
{
	struct cpu *cpu = CPU;
	volatile vcpu_info_t *vci = cpu->cpu_m.mcpu_vcpu_info;
	uint16_t pending;

	ASSERT(vci->evtchn_upcall_mask != 0);

	/*
	 * If new ipl level will enable any pending interrupts, setup so the
	 * upcoming sti will cause us to get an upcall.
	 */
	pending = cpu->cpu_m.mcpu_intr_pending & ~((1 << (ipl + 1)) - 1);
	if (pending) {
		int i;
		ulong_t pending_sels = 0;
		volatile ulong_t *selp;
		struct xen_evt_data *cpe = cpu->cpu_m.mcpu_evt_pend;

		for (i = bsrw_insn(pending); i > ipl; i--)
			pending_sels |= cpe->pending_sel[i];
		ASSERT(pending_sels);
		selp = (volatile ulong_t *)&vci->evtchn_pending_sel;
		atomic_or_ulong(selp, pending_sels);
		vci->evtchn_upcall_pending = 1;
	}
}

/*
 * This function provides external interface to the nexus for all
 * functionality related to the new DDI interrupt framework.
 *
 * Input:
 * dip     - pointer to the dev_info structure of the requested device
 * hdlp    - pointer to the internal interrupt handle structure for the
 *	     requested interrupt
 * intr_op - opcode for this call
 * result  - pointer to the integer that will hold the result to be
 *	     passed back if return value is PSM_SUCCESS
 *
 * Output:
 * return value is either PSM_SUCCESS or PSM_FAILURE
 */
int
xen_intr_ops(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp,
    psm_intr_op_t intr_op, int *result)
{
	int		cap;
	int		err;
	int		new_priority;
	apic_irq_t	*irqp;
	struct intrspec *ispec;

	DDI_INTR_IMPLDBG((CE_CONT, "xen_intr_ops: dip: %p hdlp: %p "
	    "intr_op: %x\n", (void *)dip, (void *)hdlp, intr_op));

	switch (intr_op) {
	case PSM_INTR_OP_CHECK_MSI:
		/*
		 * Till PCI passthru is supported, only dom0 has MSI/MSIX
		 */
		if (!DOMAIN_IS_INITDOMAIN(xen_info)) {
			*result = hdlp->ih_type & ~(DDI_INTR_TYPE_MSI |
			    DDI_INTR_TYPE_MSIX);
			break;
		}
		/*
		 * Check MSI/X is supported or not at APIC level and
		 * masked off the MSI/X bits in hdlp->ih_type if not
		 * supported before return.  If MSI/X is supported,
		 * leave the ih_type unchanged and return.
		 *
		 * hdlp->ih_type passed in from the nexus has all the
		 * interrupt types supported by the device.
		 */
		if (xen_support_msi == 0) {
			/*
			 * if xen_support_msi is not set, call
			 * apic_check_msi_support() to check whether msi
			 * is supported first
			 */
			if (apic_check_msi_support() == PSM_SUCCESS)
				xen_support_msi = 1;
			else
				xen_support_msi = -1;
		}
		if (xen_support_msi == 1)
			*result = hdlp->ih_type;
		else
			*result = hdlp->ih_type & ~(DDI_INTR_TYPE_MSI |
			    DDI_INTR_TYPE_MSIX);
		break;
	case PSM_INTR_OP_ALLOC_VECTORS:
		if (hdlp->ih_type == DDI_INTR_TYPE_MSI)
			*result = apic_alloc_msi_vectors(dip, hdlp->ih_inum,
			    hdlp->ih_scratch1, hdlp->ih_pri,
			    (int)(uintptr_t)hdlp->ih_scratch2);
		else
			*result = apic_alloc_msix_vectors(dip, hdlp->ih_inum,
			    hdlp->ih_scratch1, hdlp->ih_pri,
			    (int)(uintptr_t)hdlp->ih_scratch2);
		break;
	case PSM_INTR_OP_FREE_VECTORS:
		apic_free_vectors(dip, hdlp->ih_inum, hdlp->ih_scratch1,
		    hdlp->ih_pri, hdlp->ih_type);
		break;
	case PSM_INTR_OP_NAVAIL_VECTORS:
		/*
		 * XXPV - maybe we should make this be:
		 * min(APIC_VECTOR_PER_IPL, count of all avail vectors);
		 */
		if (DOMAIN_IS_INITDOMAIN(xen_info))
			*result = APIC_VECTOR_PER_IPL;
		else
			*result = 1;
		break;
	case PSM_INTR_OP_XLATE_VECTOR:
		ispec = ((ihdl_plat_t *)hdlp->ih_private)->ip_ispecp;
		if (ispec->intrspec_vec >= PIRQ_BASE &&
		    ispec->intrspec_vec < NR_PIRQS &&
		    DOMAIN_IS_INITDOMAIN(xen_info)) {
			*result = apic_introp_xlate(dip, ispec, hdlp->ih_type);
		} else {
			*result = ispec->intrspec_vec;
		}
		break;
	case PSM_INTR_OP_GET_PENDING:
		/* XXPV - is this enough for dom0 or do we need to ref ioapic */
		*result = ec_pending_irq(hdlp->ih_vector);
		break;
	case PSM_INTR_OP_CLEAR_MASK:
		/* XXPV - is this enough for dom0 or do we need to set ioapic */
		if (hdlp->ih_type != DDI_INTR_TYPE_FIXED)
			return (PSM_FAILURE);
		ec_enable_irq(hdlp->ih_vector);
		break;
	case PSM_INTR_OP_SET_MASK:
		/* XXPV - is this enough for dom0 or do we need to set ioapic */
		if (hdlp->ih_type != DDI_INTR_TYPE_FIXED)
			return (PSM_FAILURE);
		ec_disable_irq(hdlp->ih_vector);
		break;
	case PSM_INTR_OP_GET_CAP:
		cap = DDI_INTR_FLAG_PENDING | DDI_INTR_FLAG_EDGE;
		if (hdlp->ih_type == DDI_INTR_TYPE_FIXED)
			cap |= DDI_INTR_FLAG_MASKABLE;
		*result = cap;
		break;
	case PSM_INTR_OP_GET_SHARED:
		if (DOMAIN_IS_INITDOMAIN(xen_info)) {
			if (hdlp->ih_type != DDI_INTR_TYPE_FIXED)
				return (PSM_FAILURE);
			ispec = ((ihdl_plat_t *)hdlp->ih_private)->ip_ispecp;
			if ((irqp = apic_find_irq(dip, ispec, hdlp->ih_type))
			    == NULL)
				return (PSM_FAILURE);
			*result = (irqp->airq_share > 1) ? 1: 0;
		} else {
			return (PSM_FAILURE);
		}
		break;
	case PSM_INTR_OP_SET_PRI:
		new_priority = *(int *)result;
		err = ec_set_irq_priority(hdlp->ih_vector, new_priority);
		if (err != 0)
			return (PSM_FAILURE);
		break;
	case PSM_INTR_OP_GET_INTR:
		if (!DOMAIN_IS_INITDOMAIN(xen_info))
			return (PSM_FAILURE);
		/*
		 * The interrupt handle given here has been allocated
		 * specifically for this command, and ih_private carries
		 * a pointer to a apic_get_intr_t.
		 */
		if (apic_get_vector_intr_info(
		    hdlp->ih_vector, hdlp->ih_private) != PSM_SUCCESS)
			return (PSM_FAILURE);
		break;
	case PSM_INTR_OP_SET_CAP:
		/* FALLTHRU */
	default:
		return (PSM_FAILURE);
	}
	return (PSM_SUCCESS);
}

static void
xen_psm_rebind_irq(int irq)
{
	cpuset_t ncpu;
	processorid_t newcpu;
	apic_irq_t *irqptr;

	newcpu = xen_psm_bind_intr(irq);
	if (newcpu == IRQ_UNBOUND) {
		CPUSET_ZERO(ncpu);
		CPUSET_OR(ncpu, xen_psm_cpus_online);
	} else {
		CPUSET_ONLY(ncpu, newcpu & ~IRQ_USER_BOUND);
	}
	ec_set_irq_affinity(irq, ncpu);
	if (irq <= APIC_MAX_VECTOR) {
		irqptr = apic_irq_table[irq];
		ASSERT(irqptr != NULL);
		irqptr->airq_temp_cpu = (uchar_t)newcpu;
	}
}

/*
 * Disable all device interrupts for the given cpu.
 * High priority interrupts are not disabled and will still be serviced.
 */
static int
xen_psm_disable_intr(processorid_t cpun)
{
	int irq;

	/*
	 * Can't offline VCPU 0 on this hypervisor.  There's no reason
	 * anyone would want to given that the CPUs are virtual. Also note
	 * that the hypervisor requires suspend/resume to be on VCPU 0.
	 */
	if (cpun == 0)
		return (PSM_FAILURE);

	CPUSET_ATOMIC_DEL(xen_psm_cpus_online, cpun);
	for (irq = 0; irq < NR_IRQS; irq++) {
		if (!ec_irq_needs_rebind(irq, cpun))
			continue;
		xen_psm_rebind_irq(irq);
	}
	return (PSM_SUCCESS);
}

static void
xen_psm_enable_intr(processorid_t cpun)
{
	int irq;

	if (cpun == 0)
		return;

	CPUSET_ATOMIC_ADD(xen_psm_cpus_online, cpun);

	/*
	 * Rebalance device interrupts among online processors
	 */
	for (irq = 0; irq < NR_IRQS; irq++) {
		if (!ec_irq_rebindable(irq))
			continue;
		xen_psm_rebind_irq(irq);
	}

	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		apic_cpus[cpun].aci_status |= APIC_CPU_INTR_ENABLE;
	}
}

static int
xen_psm_post_cpu_start()
{
	processorid_t cpun;

	cpun = psm_get_cpu_id();
	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		/*
		 * Non-virtualized environments can call psm_post_cpu_start
		 * from Suspend/Resume with the APIC_CPU_INTR_ENABLE bit set.
		 * xen_psm_post_cpu_start() is only called from boot.
		 */
		apic_cpus[cpun].aci_status |= APIC_CPU_ONLINE;
	}
	return (PSM_SUCCESS);
}

/*
 * This function will reprogram the timer.
 *
 * When in oneshot mode the argument is the absolute time in future at which to
 * generate the interrupt.
 *
 * When in periodic mode, the argument is the interval at which the
 * interrupts should be generated. There is no need to support the periodic
 * mode timer change at this time.
 *
 * Note that we must be careful to convert from hrtime to Xen system time (see
 * xpv_timestamp.c).
 */
static void
xen_psm_timer_reprogram(hrtime_t timer_req)
{
	hrtime_t now, timer_new, time_delta, xen_time;
	ulong_t flags;

	flags = intr_clear();
	/*
	 * We should be called from high PIL context (CBE_HIGH_PIL),
	 * so kpreempt is disabled.
	 */

	now = xpv_gethrtime();
	xen_time = xpv_getsystime();
	if (timer_req <= now) {
		/*
		 * requested to generate an interrupt in the past
		 * generate an interrupt as soon as possible
		 */
		time_delta = XEN_NSEC_PER_TICK;
	} else
		time_delta = timer_req - now;

	timer_new = xen_time + time_delta;
	if (HYPERVISOR_set_timer_op(timer_new) != 0)
		panic("can't set hypervisor timer?");
	intr_restore(flags);
}

/*
 * This function will enable timer interrupts.
 */
static void
xen_psm_timer_enable(void)
{
	ec_unmask_irq(xen_clock_irq);
}

/*
 * This function will disable timer interrupts on the current cpu.
 */
static void
xen_psm_timer_disable(void)
{
	(void) ec_block_irq(xen_clock_irq);
	/*
	 * If the clock irq is pending on this cpu then we need to
	 * clear the pending interrupt.
	 */
	ec_unpend_irq(xen_clock_irq);
}

/*
 *
 * The following functions are in the platform specific file so that they
 * can be different functions depending on whether we are running on
 * bare metal or a hypervisor.
 */

/*
 * Allocate a free vector for irq at ipl.
 */
/* ARGSUSED */
uchar_t
apic_allocate_vector(int ipl, int irq, int pri)
{
	physdev_irq_t irq_op;
	uchar_t vector;
	int rc;

	irq_op.irq = irq;

	if ((rc = HYPERVISOR_physdev_op(PHYSDEVOP_alloc_irq_vector, &irq_op))
	    != 0)
		panic("Hypervisor alloc vector failed err: %d", -rc);
	vector = irq_op.vector;
	/*
	 * No need to worry about vector colliding with our reserved vectors
	 * e.g. T_FASTTRAP, xen can differentiate between hardware and software
	 * generated traps and handle them properly.
	 */
	apic_vector_to_irq[vector] = (uchar_t)irq;
	return (vector);
}

/* Mark vector as not being used by any irq */
void
apic_free_vector(uchar_t vector)
{
	apic_vector_to_irq[vector] = APIC_RESV_IRQ;
}

/*
 * This function returns the no. of vectors available for the pri.
 * dip is not used at this moment.  If we really don't need that,
 * it will be removed.  Since priority is not limited by hardware
 * when running on the hypervisor we simply return the maximum no.
 * of available contiguous vectors.
 */
/*ARGSUSED*/
int
apic_navail_vector(dev_info_t *dip, int pri)
{
	int	lowest, highest, i, navail, count;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_navail_vector: dip: %p, pri: %x\n",
	    (void *)dip, pri));

	highest = APIC_MAX_VECTOR;
	lowest = APIC_BASE_VECT;
	navail = count = 0;

	/* It has to be contiguous */
	for (i = lowest; i < highest; i++) {
		count = 0;
		while ((apic_vector_to_irq[i] == APIC_RESV_IRQ) &&
		    (i < highest)) {
			count++;
			i++;
		}
		if (count > navail)
			navail = count;
	}
	return (navail);
}

static physdev_manage_pci_t *managed_devlist;
static int mdev_cnt;
static int mdev_size = 128;
static uchar_t	msi_vector_to_pirq[APIC_MAX_VECTOR+1];

/*
 * Add devfn on given bus to devices managed by hypervisor
 */
static int
xen_manage_device(uint8_t bus, uint8_t devfn)
{
	physdev_manage_pci_t manage_pci, *newlist;
	int rc, i, oldsize;

	/*
	 * Check if bus/devfn already managed.  If so just return success.
	 */
	if (managed_devlist == NULL) {
		managed_devlist = kmem_alloc(sizeof (physdev_manage_pci_t) *
		    mdev_size, KM_NOSLEEP);
		if (managed_devlist == NULL) {
			cmn_err(CE_WARN,
			    "Can't alloc space for managed device list");
			return (0);
		}
	};
	for (i = 0; i < mdev_cnt; i++) {
		if (managed_devlist[i].bus == bus &&
		    managed_devlist[i].devfn == devfn)
			return (1); /* device already managed */
	}
	manage_pci.bus = bus;
	manage_pci.devfn = devfn;
	rc = HYPERVISOR_physdev_op(PHYSDEVOP_manage_pci_add, &manage_pci);
	if (rc < 0) {
		cmn_err(CE_WARN,
		    "hypervisor add pci device call failed bus:0x%x"
		    " devfn:0x%x", bus, devfn);
		return (0);
	}
	/*
	 * Add device to the managed device list
	 */
	if (i == mdev_size) {
		/*
		 * grow the managed device list
		 */
		oldsize = mdev_size * sizeof (physdev_manage_pci_t);
		mdev_size *= 2;
		newlist = kmem_alloc(sizeof (physdev_manage_pci_t) * mdev_size,
		    KM_NOSLEEP);
		if (newlist == NULL) {
			cmn_err(CE_WARN, "Can't grow managed device list");
			return (0);
		}
		bcopy(managed_devlist, newlist, oldsize);
		kmem_free(managed_devlist, oldsize);
		managed_devlist = newlist;
	}
	managed_devlist[i].bus = bus;
	managed_devlist[i].devfn = devfn;
	mdev_cnt++;
	return (1);
}

/*
 * allocate an apic irq struct for an MSI interrupt
 */
static int
msi_allocate_irq(int irq)
{
	apic_irq_t *irqptr = apic_irq_table[irq];

	if (irqptr == NULL) {
		irqptr = kmem_zalloc(sizeof (apic_irq_t), KM_NOSLEEP);
		if (irqptr == NULL) {
			cmn_err(CE_WARN, "xpv_psm: NO memory to allocate IRQ");
			return (-1);
		}
		apic_irq_table[irq] = irqptr;
	} else {
		if (irq == APIC_RESV_IRQ && irqptr->airq_mps_intr_index == 0)
			irqptr->airq_mps_intr_index = FREE_INDEX;
		if (irqptr->airq_mps_intr_index != FREE_INDEX) {
			cmn_err(CE_WARN, "xpv_psm: MSI IRQ already in use");
			return (-1);
		}
	}
	irqptr->airq_mps_intr_index = FREE_INDEX;
	return (irq);
}

/*
 * read MSI/MSIX vector out of config space
 */
static uchar_t
xpv_psm_get_msi_vector(dev_info_t *dip, int type, int entry)
{
	uint64_t		msi_data = 0;
	int			cap_ptr = i_ddi_get_msi_msix_cap_ptr(dip);
	ddi_acc_handle_t	handle = i_ddi_get_pci_config_handle(dip);
	ushort_t		msi_ctrl;
	uchar_t			vector;

	ASSERT((handle != NULL) && (cap_ptr != 0));
	if (type == DDI_INTR_TYPE_MSI) {
		msi_ctrl = pci_config_get16(handle, cap_ptr + PCI_MSI_CTRL);
		/*
		 * Get vector
		 */
		if (msi_ctrl &  PCI_MSI_64BIT_MASK) {
			msi_data = pci_config_get16(handle,
			    cap_ptr + PCI_MSI_64BIT_DATA);
		} else {
			msi_data = pci_config_get16(handle,
			    cap_ptr + PCI_MSI_32BIT_DATA);
		}
		vector = (msi_data & 0xff) + entry;
	} else if (type == DDI_INTR_TYPE_MSIX) {
		uintptr_t	off;
		ddi_intr_msix_t	*msix_p = i_ddi_get_msix(dip);

		/* Offset into the given entry in the MSI-X table */
		off = (uintptr_t)msix_p->msix_tbl_addr +
		    (entry  * PCI_MSIX_VECTOR_SIZE);

		msi_data = ddi_get32(msix_p->msix_tbl_hdl,
		    (uint32_t *)(off + PCI_MSIX_DATA_OFFSET));
		vector = msi_data & 0xff;
	}
	return (vector);
}


static void
get_busdevfn(dev_info_t *dip, int *busp, int *devfnp)
{
	pci_regspec_t *regspec;
	int reglen;

	/*
	 * Get device reg spec, first word has PCI bus and
	 * device/function info we need.
	 */
	if (ddi_getlongprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&regspec, &reglen) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "get_busdevfn() failed to get regspec.");
		return;
	}
	/*
	 * get PCI bus # from reg spec for device
	 */
	*busp = PCI_REG_BUS_G(regspec[0].pci_phys_hi);
	/*
	 * get combined device/function from reg spec for device.
	 */
	*devfnp = (regspec[0].pci_phys_hi & (PCI_REG_FUNC_M | PCI_REG_DEV_M)) >>
	    PCI_REG_FUNC_SHIFT;

	kmem_free(regspec, reglen);
}

/*
 * This function allocates "count" MSI vector(s) for the given "dip/pri/type"
 */
int
apic_alloc_msi_vectors(dev_info_t *dip, int inum, int count, int pri,
    int behavior)
{
	int	rcount, i, rc, irqno;
	uchar_t	vector, cpu;
	major_t	major;
	apic_irq_t	*irqptr;
	physdev_map_pirq_t map_irq;
	int busnum, devfn;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_alloc_msi_vectors: dip=0x%p "
	    "inum=0x%x  pri=0x%x count=0x%x behavior=%d\n",
	    (void *)dip, inum, pri, count, behavior));

	if (count > 1) {
		if (behavior == DDI_INTR_ALLOC_STRICT &&
		    apic_multi_msi_enable == 0)
			return (0);
		if (apic_multi_msi_enable == 0)
			count = 1;
	}

	if ((rcount = apic_navail_vector(dip, pri)) > count)
		rcount = count;
	else if (rcount == 0 || (rcount < count &&
	    behavior == DDI_INTR_ALLOC_STRICT))
		return (0);

	/* if not ISP2, then round it down */
	if (!ISP2(rcount))
		rcount = 1 << (highbit(rcount) - 1);

	/*
	 * get PCI bus #  and devfn from reg spec for device
	 */
	get_busdevfn(dip, &busnum, &devfn);

	/*
	 * Tell xen about this pci device
	 */
	if (!xen_manage_device(busnum, devfn))
		return (0);

	mutex_enter(&airq_mutex);

	major = (dip != NULL) ? ddi_name_to_major(ddi_get_name(dip)) : 0;
	for (i = 0; i < rcount; i++) {
		/*
		 * use PHYSDEVOP_map_pirq to have xen map MSI to a pirq
		 */
		map_irq.domid = DOMID_SELF;
		map_irq.type = MAP_PIRQ_TYPE_MSI;
		map_irq.index = -rcount; /* hypervisor auto allocates vectors */
		map_irq.pirq = -1;
		map_irq.bus = busnum;
		map_irq.devfn = devfn;
		map_irq.entry_nr = i;
		map_irq.table_base = 0;
		rc = HYPERVISOR_physdev_op(PHYSDEVOP_map_pirq, &map_irq);
		irqno = map_irq.pirq;
		if (rc < 0) {
			mutex_exit(&airq_mutex);
			cmn_err(CE_WARN, "map MSI irq failed err: %d", -rc);
			return (i);
		}
		if (irqno < 0) {
			mutex_exit(&airq_mutex);
			cmn_err(CE_NOTE,
			    "!hypervisor not configured for MSI support");
			xen_support_msi = -1;
			return (0);
		}

		/*
		 * Find out what vector the hypervisor assigned
		 */
		vector = xpv_psm_get_msi_vector(dip, DDI_INTR_TYPE_MSI, i);

		if (msi_allocate_irq(irqno) < 0) {
			mutex_exit(&airq_mutex);
			return (i);
		}
		apic_max_device_irq = max(irqno, apic_max_device_irq);
		apic_min_device_irq = min(irqno, apic_min_device_irq);
		irqptr = apic_irq_table[irqno];
		ASSERT(irqptr != NULL);
#ifdef	DEBUG
		if (apic_vector_to_irq[vector] != APIC_RESV_IRQ)
			DDI_INTR_IMPLDBG((CE_CONT, "apic_alloc_msi_vectors: "
			    "apic_vector_to_irq is not APIC_RESV_IRQ\n"));
#endif
		apic_vector_to_irq[vector] = (uchar_t)irqno;
		msi_vector_to_pirq[vector] = (uchar_t)irqno;

		irqptr->airq_vector = vector;
		irqptr->airq_ioapicindex = (uchar_t)inum;	/* start */
		irqptr->airq_intin_no = (uchar_t)rcount;
		irqptr->airq_ipl = pri;
		irqptr->airq_origirq = (uchar_t)(inum + i);
		irqptr->airq_share_id = 0;
		irqptr->airq_mps_intr_index = MSI_INDEX;
		irqptr->airq_dip = dip;
		irqptr->airq_major = major;
		if (i == 0) /* they all bind to the same cpu */
			cpu = irqptr->airq_cpu = xen_psm_bind_intr(irqno);
		else
			irqptr->airq_cpu = cpu;
		DDI_INTR_IMPLDBG((CE_CONT, "apic_alloc_msi_vectors: irq=0x%x "
		    "dip=0x%p vector=0x%x origirq=0x%x pri=0x%x\n", irqno,
		    (void *)irqptr->airq_dip, irqptr->airq_vector,
		    irqptr->airq_origirq, pri));
	}
	mutex_exit(&airq_mutex);
	return (rcount);
}

/*
 * This function allocates "count" MSI-X vector(s) for the given "dip/pri/type"
 */
int
apic_alloc_msix_vectors(dev_info_t *dip, int inum, int count, int pri,
    int behavior)
{
	int	rcount, i, rc;
	major_t	major;
	physdev_map_pirq_t map_irq;
	int busnum, devfn;
	ddi_intr_msix_t *msix_p = i_ddi_get_msix(dip);
	uint64_t table_base;
	pfn_t pfnum;

	if (msix_p == NULL) {
		msix_p = pci_msix_init(dip);
		if (msix_p != NULL) {
			i_ddi_set_msix(dip, msix_p);
		} else {
			cmn_err(CE_WARN, "apic_alloc_msix_vectors()"
			    " msix_init failed");
			return (0);
		}
	}
	/*
	 * Hypervisor wants PCI config space address of msix table base
	 */
	pfnum = hat_getpfnum(kas.a_hat, (caddr_t)msix_p->msix_tbl_addr) &
	    ~PFN_IS_FOREIGN_MFN;
	table_base = (uint64_t)((pfnum << PAGESHIFT) - msix_p->msix_tbl_offset |
	    ((uintptr_t)msix_p->msix_tbl_addr & PAGEOFFSET));
	/*
	 * get PCI bus #  and devfn from reg spec for device
	 */
	get_busdevfn(dip, &busnum, &devfn);

	/*
	 * Tell xen about this pci device
	 */
	if (!xen_manage_device(busnum, devfn))
		return (0);
	mutex_enter(&airq_mutex);

	if ((rcount = apic_navail_vector(dip, pri)) > count)
		rcount = count;
	else if (rcount == 0 || (rcount < count &&
	    behavior == DDI_INTR_ALLOC_STRICT)) {
		rcount = 0;
		goto out;
	}

	major = (dip != NULL) ? ddi_name_to_major(ddi_get_name(dip)) : 0;
	for (i = 0; i < rcount; i++) {
		int irqno;
		uchar_t	vector;
		apic_irq_t	*irqptr;

		/*
		 * use PHYSDEVOP_map_pirq to have xen map MSI-X to a pirq
		 */
		map_irq.domid = DOMID_SELF;
		map_irq.type = MAP_PIRQ_TYPE_MSI;
		map_irq.index = -1; /* hypervisor auto allocates vector */
		map_irq.pirq = -1;
		map_irq.bus = busnum;
		map_irq.devfn = devfn;
		map_irq.entry_nr = i;
		map_irq.table_base = table_base;
		rc = HYPERVISOR_physdev_op(PHYSDEVOP_map_pirq, &map_irq);
		irqno = map_irq.pirq;
		if (rc < 0) {
			mutex_exit(&airq_mutex);
			cmn_err(CE_WARN, "map MSI irq failed err: %d", -rc);
			return (i);
		}
		if (irqno < 0) {
			mutex_exit(&airq_mutex);
			cmn_err(CE_NOTE,
			    "!hypervisor not configured for MSI support");
			xen_support_msi = -1;
			return (0);
		}
		/*
		 * Find out what vector the hypervisor assigned
		 */
		vector = xpv_psm_get_msi_vector(dip, DDI_INTR_TYPE_MSIX, i);

		if (msi_allocate_irq(irqno) < 0) {
			mutex_exit(&airq_mutex);
			return (i);
		}
		apic_vector_to_irq[vector] = (uchar_t)irqno;
		msi_vector_to_pirq[vector] = (uchar_t)irqno;
		apic_max_device_irq = max(irqno, apic_max_device_irq);
		apic_min_device_irq = min(irqno, apic_min_device_irq);
		irqptr = apic_irq_table[irqno];
		ASSERT(irqptr != NULL);
		irqptr->airq_vector = (uchar_t)vector;
		irqptr->airq_ipl = pri;
		irqptr->airq_origirq = (uchar_t)(inum + i);
		irqptr->airq_share_id = 0;
		irqptr->airq_mps_intr_index = MSIX_INDEX;
		irqptr->airq_dip = dip;
		irqptr->airq_major = major;
		irqptr->airq_cpu = IRQ_UNBOUND; /* will be bound when addspl */
	}
out:
	mutex_exit(&airq_mutex);
	return (rcount);
}


/*
 * This finds the apic_irq_t associated with the dip, ispec and type.
 * The entry should have already been freed, but it can not have been
 * reused yet since the hypervisor can not have reassigned the pirq since
 * we have not freed that yet.
 */
static apic_irq_t *
msi_find_irq(dev_info_t *dip, struct intrspec *ispec)
{
	apic_irq_t	*irqp;
	int i;

	for (i = apic_min_device_irq; i <= apic_max_device_irq; i++) {
		if ((irqp = apic_irq_table[i]) == NULL)
			continue;
		if ((irqp->airq_dip == dip) &&
		    (irqp->airq_origirq == ispec->intrspec_vec) &&
		    (irqp->airq_ipl == ispec->intrspec_pri)) {
			return (irqp);
		}
	}
	return (NULL);
}

void
apic_free_vectors(dev_info_t *dip, int inum, int count, int pri, int type)
{
	int i, rc;
	physdev_unmap_pirq_t unmap_pirq;
	apic_irq_t *irqptr;
	struct intrspec ispec;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_free_vectors: dip: %p inum: %x "
	    "count: %x pri: %x type: %x\n",
	    (void *)dip, inum, count, pri, type));

	/* for MSI/X only */
	if (!DDI_INTR_IS_MSI_OR_MSIX(type))
		return;

	for (i = 0; i < count; i++) {
		DDI_INTR_IMPLDBG((CE_CONT, "apic_free_vectors: inum=0x%x "
		    "pri=0x%x count=0x%x\n", inum, pri, count));
		ispec.intrspec_vec = inum + i;
		ispec.intrspec_pri = pri;
		if ((irqptr = msi_find_irq(dip, &ispec)) == NULL) {
			cmn_err(CE_WARN,
			    "couldn't find irq %s,%s dip: 0x%p vec: %x pri: %x",
			    ddi_get_name(dip), ddi_get_name_addr(dip),
			    (void *)dip, inum + i, pri);
			continue;
		}
		/*
		 * use PHYSDEVOP_unmap_pirq to have xen unmap MSI from a pirq
		 */
		unmap_pirq.domid = DOMID_SELF;
		unmap_pirq.pirq = msi_vector_to_pirq[irqptr->airq_vector];
		rc = HYPERVISOR_physdev_op(PHYSDEVOP_unmap_pirq, &unmap_pirq);
		if (rc < 0) {
			cmn_err(CE_WARN, "unmap pirq failed");
			return;
		}
		irqptr->airq_mps_intr_index = FREE_INDEX;
		apic_vector_to_irq[irqptr->airq_vector] = APIC_RESV_IRQ;
	}
}

/*
 * The hypervisor doesn't permit access to local apics directly
 */
/* ARGSUSED */
uint32_t *
mapin_apic(uint32_t addr, size_t len, int flags)
{
	/*
	 * Return a pointer to a memory area to fake out the
	 * probe code that wants to read apic registers.
	 * The dummy values will end up being ignored by xen
	 * later on when they are used anyway.
	 */
	xen_psm_dummy_apic[APIC_VERS_REG] = APIC_INTEGRATED_VERS;
	return (xen_psm_dummy_apic);
}

/* ARGSUSED */
uint32_t *
mapin_ioapic(uint32_t addr, size_t len, int flags)
{
	/*
	 * Return non-null here to fake out configure code that calls this.
	 * The i86xpv platform will not reference through the returned value..
	 */
	return ((uint32_t *)0x1);
}

/* ARGSUSED */
void
mapout_apic(caddr_t addr, size_t len)
{
}

/* ARGSUSED */
void
mapout_ioapic(caddr_t addr, size_t len)
{
}

uint32_t
ioapic_read(int apic_ix, uint32_t reg)
{
	physdev_apic_t apic;

	apic.apic_physbase = (unsigned long)apic_physaddr[apic_ix];
	apic.reg = reg;
	if (HYPERVISOR_physdev_op(PHYSDEVOP_apic_read, &apic))
		panic("read ioapic %d reg %d failed", apic_ix, reg);
	return (apic.value);
}

void
ioapic_write(int apic_ix, uint32_t reg, uint32_t value)
{
	physdev_apic_t apic;

	apic.apic_physbase = (unsigned long)apic_physaddr[apic_ix];
	apic.reg = reg;
	apic.value = value;
	if (HYPERVISOR_physdev_op(PHYSDEVOP_apic_write, &apic))
		panic("write ioapic %d reg %d failed", apic_ix, reg);
}

/*
 * This function was added as part of x2APIC support in pcplusmp.
 */
void
ioapic_write_eoi(int apic_ix, uint32_t value)
{
	physdev_apic_t apic;

	apic.apic_physbase = (unsigned long)apic_physaddr[apic_ix];
	apic.reg = APIC_IO_EOI;
	apic.value = value;
	if (HYPERVISOR_physdev_op(PHYSDEVOP_apic_write, &apic))
		panic("write ioapic reg : APIC_IO_EOI %d failed", apic_ix);
}

/*
 * This function was added as part of x2APIC support in pcplusmp to resolve
 * undefined symbol in xpv_psm.
 */
void
x2apic_update_psm()
{
}

/*
 * This function was added as part of x2APIC support in pcplusmp to resolve
 * undefined symbol in xpv_psm.
 */
void
apic_ret()
{
}

/*
 * Call rebind to do the actual programming.
 */
int
apic_setup_io_intr(void *p, int irq, boolean_t deferred)
{
	apic_irq_t *irqptr;
	struct ioapic_reprogram_data *drep = NULL;
	int rv, cpu;
	cpuset_t cpus;

	if (deferred) {
		drep = (struct ioapic_reprogram_data *)p;
		ASSERT(drep != NULL);
		irqptr = drep->irqp;
	} else {
		irqptr = (apic_irq_t *)p;
	}
	ASSERT(irqptr != NULL);
	/*
	 * Set cpu based on xen idea of online cpu's not apic tables.
	 * Note that xen ignores/sets to it's own preferred value the
	 * target cpu field when programming ioapic anyway.
	 */
	if (irqptr->airq_mps_intr_index == MSI_INDEX)
		cpu = irqptr->airq_cpu; /* MSI cpus are already set */
	else {
		cpu = xen_psm_bind_intr(irq);
		irqptr->airq_cpu = cpu;
	}
	if (cpu == IRQ_UNBOUND) {
		CPUSET_ZERO(cpus);
		CPUSET_OR(cpus, xen_psm_cpus_online);
	} else {
		CPUSET_ONLY(cpus, cpu & ~IRQ_USER_BOUND);
	}
	rv = apic_rebind(irqptr, cpu, drep);
	if (rv) {
		/* CPU is not up or interrupt is disabled. Fall back to 0 */
		cpu = 0;
		irqptr->airq_cpu = cpu;
		rv = apic_rebind(irqptr, cpu, drep);
	}
	/*
	 * If rebind successful bind the irq to an event channel
	 */
	if (rv == 0) {
		ec_setup_pirq(irq, irqptr->airq_ipl, &cpus);
		CPUSET_FIND(cpus, cpu);
		apic_irq_table[irq]->airq_temp_cpu = cpu & ~IRQ_USER_BOUND;
	}
	return (rv);
}

/*
 * Allocate a new vector for the given irq
 */
/* ARGSUSED */
uchar_t
apic_modify_vector(uchar_t vector, int irq)
{
	return (apic_allocate_vector(0, irq, 0));
}

/*
 * The rest of the file is just generic psm module boilerplate
 */

static struct psm_ops xen_psm_ops = {
	xen_psm_probe,				/* psm_probe		*/

	xen_psm_softinit,			/* psm_init		*/
	xen_psm_picinit,			/* psm_picinit		*/
	xen_psm_intr_enter,			/* psm_intr_enter	*/
	xen_psm_intr_exit,			/* psm_intr_exit	*/
	xen_psm_setspl,				/* psm_setspl		*/
	xen_psm_addspl,				/* psm_addspl		*/
	xen_psm_delspl,				/* psm_delspl		*/
	xen_psm_disable_intr,			/* psm_disable_intr	*/
	xen_psm_enable_intr,			/* psm_enable_intr	*/
	(int (*)(int))NULL,			/* psm_softlvl_to_irq	*/
	(void (*)(int))NULL,			/* psm_set_softintr	*/
	(void (*)(processorid_t))NULL,		/* psm_set_idlecpu	*/
	(void (*)(processorid_t))NULL,		/* psm_unset_idlecpu	*/

	xen_psm_clkinit,			/* psm_clkinit		*/
	xen_psm_get_clockirq,			/* psm_get_clockirq	*/
	xen_psm_hrtimeinit,			/* psm_hrtimeinit	*/
	xpv_gethrtime,				/* psm_gethrtime	*/

	xen_psm_get_next_processorid,		/* psm_get_next_processorid */
	xen_psm_cpu_start,			/* psm_cpu_start	*/
	xen_psm_post_cpu_start,			/* psm_post_cpu_start	*/
	xen_psm_shutdown,			/* psm_shutdown		*/
	xen_psm_get_ipivect,			/* psm_get_ipivect	*/
	xen_psm_send_ipi,			/* psm_send_ipi		*/

	xen_psm_translate_irq,			/* psm_translate_irq	*/

	(void (*)(int, char *))NULL,		/* psm_notify_error	*/
	(void (*)(int msg))NULL,		/* psm_notify_func	*/
	xen_psm_timer_reprogram,		/* psm_timer_reprogram	*/
	xen_psm_timer_enable,			/* psm_timer_enable	*/
	xen_psm_timer_disable,			/* psm_timer_disable	*/
	(void (*)(void *arg))NULL,		/* psm_post_cyclic_setup */
	(void (*)(int, int))NULL,		/* psm_preshutdown	*/
	xen_intr_ops,			/* Advanced DDI Interrupt framework */
	(int (*)(psm_state_request_t *))NULL,	/* psm_state		*/
	(int (*)(psm_cpu_request_t *))NULL,	/* psm_cpu_ops		*/

	(int (*)(void))NULL,			/* psm_get_pir_ipivect	*/
	(void (*)(processorid_t))NULL,		/* psm_send_pir_ipi	*/
};

static struct psm_info xen_psm_info = {
	PSM_INFO_VER01_5,	/* version				*/
	PSM_OWN_EXCLUSIVE,	/* ownership				*/
	&xen_psm_ops,		/* operation				*/
	"xVM_psm",		/* machine name				*/
	"platform module"	/* machine descriptions			*/
};

static void *xen_psm_hdlp;

int
_init(void)
{
	return (psm_mod_init(&xen_psm_hdlp, &xen_psm_info));
}

int
_fini(void)
{
	return (psm_mod_fini(&xen_psm_hdlp, &xen_psm_info));
}

int
_info(struct modinfo *modinfop)
{
	return (psm_mod_info(&xen_psm_hdlp, &xen_psm_info, modinfop));
}
