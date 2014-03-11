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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */
/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

/*
 * To understand how the apix module interacts with the interrupt subsystem read
 * the theory statement in uts/i86pc/os/intr.c.
 */

/*
 * PSMI 1.1 extensions are supported only in 2.6 and later versions.
 * PSMI 1.2 extensions are supported only in 2.7 and later versions.
 * PSMI 1.3 and 1.4 extensions are supported in Solaris 10.
 * PSMI 1.5 extensions are supported in Solaris Nevada.
 * PSMI 1.6 extensions are supported in Solaris Nevada.
 * PSMI 1.7 extensions are supported in Solaris Nevada.
 */
#define	PSMI_1_7

#include <sys/processor.h>
#include <sys/time.h>
#include <sys/psm.h>
#include <sys/smp_impldefs.h>
#include <sys/cram.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/psm_common.h>
#include <sys/pit.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci.h>
#include <sys/promif.h>
#include <sys/x86_archext.h>
#include <sys/cpc_impl.h>
#include <sys/uadmin.h>
#include <sys/panic.h>
#include <sys/debug.h>
#include <sys/archsystm.h>
#include <sys/trap.h>
#include <sys/machsystm.h>
#include <sys/sysmacros.h>
#include <sys/cpuvar.h>
#include <sys/rm_platter.h>
#include <sys/privregs.h>
#include <sys/note.h>
#include <sys/pci_intr_lib.h>
#include <sys/spl.h>
#include <sys/clock.h>
#include <sys/cyclic.h>
#include <sys/dditypes.h>
#include <sys/sunddi.h>
#include <sys/x_call.h>
#include <sys/reboot.h>
#include <sys/mach_intr.h>
#include <sys/apix.h>
#include <sys/apix_irm_impl.h>

static int apix_probe();
static void apix_init();
static void apix_picinit(void);
static int apix_intr_enter(int, int *);
static void apix_intr_exit(int, int);
static void apix_setspl(int);
static int apix_disable_intr(processorid_t);
static void apix_enable_intr(processorid_t);
static int apix_get_clkvect(int);
static int apix_get_ipivect(int, int);
static void apix_post_cyclic_setup(void *);
static int apix_post_cpu_start();
static int apix_intr_ops(dev_info_t *, ddi_intr_handle_impl_t *,
    psm_intr_op_t, int *);

/*
 * Helper functions for apix_intr_ops()
 */
static void apix_redistribute_compute(void);
static int apix_get_pending(apix_vector_t *);
static apix_vector_t *apix_get_req_vector(ddi_intr_handle_impl_t *, ushort_t);
static int apix_get_intr_info(ddi_intr_handle_impl_t *, apic_get_intr_t *);
static char *apix_get_apic_type(void);
static int apix_intx_get_pending(int);
static void apix_intx_set_mask(int irqno);
static void apix_intx_clear_mask(int irqno);
static int apix_intx_get_shared(int irqno);
static void apix_intx_set_shared(int irqno, int delta);
static apix_vector_t *apix_intx_xlate_vector(dev_info_t *, int,
    struct intrspec *);
static int apix_intx_alloc_vector(dev_info_t *, int, struct intrspec *);

extern int apic_clkinit(int);

/* IRM initialization for APIX PSM module */
extern void apix_irm_init(void);

extern int irm_enable;

/*
 *	Local static data
 */
static struct	psm_ops apix_ops = {
	apix_probe,

	apix_init,
	apix_picinit,
	apix_intr_enter,
	apix_intr_exit,
	apix_setspl,
	apix_addspl,
	apix_delspl,
	apix_disable_intr,
	apix_enable_intr,
	NULL,			/* psm_softlvl_to_irq */
	NULL,			/* psm_set_softintr */

	apic_set_idlecpu,
	apic_unset_idlecpu,

	apic_clkinit,
	apix_get_clkvect,
	NULL,			/* psm_hrtimeinit */
	apic_gethrtime,

	apic_get_next_processorid,
	apic_cpu_start,
	apix_post_cpu_start,
	apic_shutdown,
	apix_get_ipivect,
	apic_send_ipi,

	NULL,			/* psm_translate_irq */
	NULL,			/* psm_notify_error */
	NULL,			/* psm_notify_func */
	apic_timer_reprogram,
	apic_timer_enable,
	apic_timer_disable,
	apix_post_cyclic_setup,
	apic_preshutdown,
	apix_intr_ops,		/* Advanced DDI Interrupt framework */
	apic_state,		/* save, restore apic state for S3 */
	apic_cpu_ops,		/* CPU control interface. */
};

struct psm_ops *psmops = &apix_ops;

static struct	psm_info apix_psm_info = {
	PSM_INFO_VER01_7,			/* version */
	PSM_OWN_EXCLUSIVE,			/* ownership */
	&apix_ops,				/* operation */
	APIX_NAME,				/* machine name */
	"apix MPv1.4 compatible",
};

static void *apix_hdlp;

static int apix_is_enabled = 0;

/*
 * Flag to indicate if APIX is to be enabled only for platforms
 * with specific hw feature(s).
 */
int apix_hw_chk_enable = 1;

/*
 * Hw features that are checked for enabling APIX support.
 */
#define	APIX_SUPPORT_X2APIC	0x00000001
uint_t apix_supported_hw = APIX_SUPPORT_X2APIC;

/*
 * apix_lock is used for cpu selection and vector re-binding
 */
lock_t apix_lock;
apix_impl_t *apixs[NCPU];
/*
 * Mapping between device interrupt and the allocated vector. Indexed
 * by major number.
 */
apix_dev_vector_t **apix_dev_vector;
/*
 * Mapping between device major number and cpu id. It gets used
 * when interrupt binding policy round robin with affinity is
 * applied. With that policy, devices with the same major number
 * will be bound to the same CPU.
 */
processorid_t *apix_major_to_cpu;	/* major to cpu mapping */
kmutex_t apix_mutex;	/* for apix_dev_vector & apix_major_to_cpu */

int apix_nipis = 16;	/* Maximum number of IPIs */
/*
 * Maximum number of vectors in a CPU that can be used for interrupt
 * allocation (including IPIs and the reserved vectors).
 */
int apix_cpu_nvectors = APIX_NVECTOR;

/* gcpu.h */

extern void apic_do_interrupt(struct regs *rp, trap_trace_rec_t *ttp);
extern void apic_change_eoi();

/*
 *	This is the loadable module wrapper
 */

int
_init(void)
{
	if (apic_coarse_hrtime)
		apix_ops.psm_gethrtime = &apic_gettime;
	return (psm_mod_init(&apix_hdlp, &apix_psm_info));
}

int
_fini(void)
{
	return (psm_mod_fini(&apix_hdlp, &apix_psm_info));
}

int
_info(struct modinfo *modinfop)
{
	return (psm_mod_info(&apix_hdlp, &apix_psm_info, modinfop));
}

static int
apix_probe()
{
	int rval;

	if (apix_enable == 0)
		return (PSM_FAILURE);

	/* check for hw features if specified  */
	if (apix_hw_chk_enable) {
		/* check if x2APIC mode is supported */
		if ((apix_supported_hw & APIX_SUPPORT_X2APIC) ==
		    APIX_SUPPORT_X2APIC) {
			if (!((apic_local_mode() == LOCAL_X2APIC) ||
			    apic_detect_x2apic())) {
				/* x2APIC mode is not supported in the hw */
				apix_enable = 0;
			}
		}
		if (apix_enable == 0)
			return (PSM_FAILURE);
	}

	rval = apic_probe_common(apix_psm_info.p_mach_idstring);
	if (rval == PSM_SUCCESS)
		apix_is_enabled = 1;
	else
		apix_is_enabled = 0;
	return (rval);
}

/*
 * Initialize the data structures needed by pcplusmpx module.
 * Specifically, the data structures used by addspl() and delspl()
 * routines.
 */
static void
apix_softinit()
{
	int i, *iptr;
	apix_impl_t *hdlp;
	int nproc;

	nproc = max(apic_nproc, apic_max_nproc);

	hdlp = kmem_zalloc(nproc * sizeof (apix_impl_t), KM_SLEEP);
	for (i = 0; i < nproc; i++) {
		apixs[i] = &hdlp[i];
		apixs[i]->x_cpuid = i;
		LOCK_INIT_CLEAR(&apixs[i]->x_lock);
	}

	/* cpu 0 is always up (for now) */
	apic_cpus[0].aci_status = APIC_CPU_ONLINE | APIC_CPU_INTR_ENABLE;

	iptr = (int *)&apic_irq_table[0];
	for (i = 0; i <= APIC_MAX_VECTOR; i++) {
		apic_level_intr[i] = 0;
		*iptr++ = NULL;
	}
	mutex_init(&airq_mutex, NULL, MUTEX_DEFAULT, NULL);

	apix_dev_vector = kmem_zalloc(sizeof (apix_dev_vector_t *) * devcnt,
	    KM_SLEEP);

	if (apic_intr_policy == INTR_ROUND_ROBIN_WITH_AFFINITY) {
		apix_major_to_cpu = kmem_zalloc(sizeof (int) * devcnt,
		    KM_SLEEP);
		for (i = 0; i < devcnt; i++)
			apix_major_to_cpu[i] = IRQ_UNINIT;
	}

	mutex_init(&apix_mutex, NULL, MUTEX_DEFAULT, NULL);
}

static int
apix_get_pending_spl(void)
{
	int cpuid = CPU->cpu_id;

	return (bsrw_insn(apixs[cpuid]->x_intr_pending));
}

static uintptr_t
apix_get_intr_handler(int cpu, short vec)
{
	apix_vector_t *apix_vector;

	ASSERT(cpu < apic_nproc && vec < APIX_NVECTOR);
	if (cpu >= apic_nproc)
		return (NULL);

	apix_vector = apixs[cpu]->x_vectbl[vec];

	return ((uintptr_t)(apix_vector->v_autovect));
}

static void
apix_init()
{
	extern void (*do_interrupt_common)(struct regs *, trap_trace_rec_t *);

	APIC_VERBOSE(INIT, (CE_CONT, "apix: psm_softinit\n"));

	do_interrupt_common = apix_do_interrupt;
	addintr = apix_add_avintr;
	remintr = apix_rem_avintr;
	get_pending_spl = apix_get_pending_spl;
	get_intr_handler = apix_get_intr_handler;
	psm_get_localapicid = apic_get_localapicid;
	psm_get_ioapicid = apic_get_ioapicid;

	apix_softinit();

#if !defined(__amd64)
	if (cpuid_have_cr8access(CPU))
		apic_have_32bit_cr8 = 1;
#endif

	/*
	 * Initialize IRM pool parameters
	 */
	if (irm_enable) {
		int	i;
		int	lowest_irq;
		int	highest_irq;

		/* number of CPUs present */
		apix_irminfo.apix_ncpus = apic_nproc;
		/* total number of entries in all of the IOAPICs present */
		lowest_irq = apic_io_vectbase[0];
		highest_irq = apic_io_vectend[0];
		for (i = 1; i < apic_io_max; i++) {
			if (apic_io_vectbase[i] < lowest_irq)
				lowest_irq = apic_io_vectbase[i];
			if (apic_io_vectend[i] > highest_irq)
				highest_irq = apic_io_vectend[i];
		}
		apix_irminfo.apix_ioapic_max_vectors =
		    highest_irq - lowest_irq + 1;
		/*
		 * Number of available per-CPU vectors excluding
		 * reserved vectors for Dtrace, int80, system-call,
		 * fast-trap, etc.
		 */
		apix_irminfo.apix_per_cpu_vectors = APIX_NAVINTR -
		    APIX_SW_RESERVED_VECTORS;

		/* Number of vectors (pre) allocated (SCI and HPET) */
		apix_irminfo.apix_vectors_allocated = 0;
		if (apic_hpet_vect != -1)
			apix_irminfo.apix_vectors_allocated++;
		if (apic_sci_vect != -1)
			apix_irminfo.apix_vectors_allocated++;
	}
}

static void
apix_init_intr()
{
	processorid_t	cpun = psm_get_cpu_id();
	uint_t nlvt;
	uint32_t svr = AV_UNIT_ENABLE | APIC_SPUR_INTR;
	extern void cmi_cmci_trap(void);

	apic_reg_ops->apic_write_task_reg(APIC_MASK_ALL);

	if (apic_mode == LOCAL_APIC) {
		/*
		 * We are running APIC in MMIO mode.
		 */
		if (apic_flat_model) {
			apic_reg_ops->apic_write(APIC_FORMAT_REG,
			    APIC_FLAT_MODEL);
		} else {
			apic_reg_ops->apic_write(APIC_FORMAT_REG,
			    APIC_CLUSTER_MODEL);
		}

		apic_reg_ops->apic_write(APIC_DEST_REG,
		    AV_HIGH_ORDER >> cpun);
	}

	if (apic_directed_EOI_supported()) {
		/*
		 * Setting the 12th bit in the Spurious Interrupt Vector
		 * Register suppresses broadcast EOIs generated by the local
		 * APIC. The suppression of broadcast EOIs happens only when
		 * interrupts are level-triggered.
		 */
		svr |= APIC_SVR_SUPPRESS_BROADCAST_EOI;
	}

	/* need to enable APIC before unmasking NMI */
	apic_reg_ops->apic_write(APIC_SPUR_INT_REG, svr);

	/*
	 * Presence of an invalid vector with delivery mode AV_FIXED can
	 * cause an error interrupt, even if the entry is masked...so
	 * write a valid vector to LVT entries along with the mask bit
	 */

	/* All APICs have timer and LINT0/1 */
	apic_reg_ops->apic_write(APIC_LOCAL_TIMER, AV_MASK|APIC_RESV_IRQ);
	apic_reg_ops->apic_write(APIC_INT_VECT0, AV_MASK|APIC_RESV_IRQ);
	apic_reg_ops->apic_write(APIC_INT_VECT1, AV_NMI);	/* enable NMI */

	/*
	 * On integrated APICs, the number of LVT entries is
	 * 'Max LVT entry' + 1; on 82489DX's (non-integrated
	 * APICs), nlvt is "3" (LINT0, LINT1, and timer)
	 */

	if (apic_cpus[cpun].aci_local_ver < APIC_INTEGRATED_VERS) {
		nlvt = 3;
	} else {
		nlvt = ((apic_reg_ops->apic_read(APIC_VERS_REG) >> 16) &
		    0xFF) + 1;
	}

	if (nlvt >= 5) {
		/* Enable performance counter overflow interrupt */

		if (!is_x86_feature(x86_featureset, X86FSET_MSR))
			apic_enable_cpcovf_intr = 0;
		if (apic_enable_cpcovf_intr) {
			if (apic_cpcovf_vect == 0) {
				int ipl = APIC_PCINT_IPL;

				apic_cpcovf_vect = apix_get_ipivect(ipl, -1);
				ASSERT(apic_cpcovf_vect);

				(void) add_avintr(NULL, ipl,
				    (avfunc)kcpc_hw_overflow_intr,
				    "apic pcint", apic_cpcovf_vect,
				    NULL, NULL, NULL, NULL);
				kcpc_hw_overflow_intr_installed = 1;
				kcpc_hw_enable_cpc_intr =
				    apic_cpcovf_mask_clear;
			}
			apic_reg_ops->apic_write(APIC_PCINT_VECT,
			    apic_cpcovf_vect);
		}
	}

	if (nlvt >= 6) {
		/* Only mask TM intr if the BIOS apparently doesn't use it */

		uint32_t lvtval;

		lvtval = apic_reg_ops->apic_read(APIC_THERM_VECT);
		if (((lvtval & AV_MASK) == AV_MASK) ||
		    ((lvtval & AV_DELIV_MODE) != AV_SMI)) {
			apic_reg_ops->apic_write(APIC_THERM_VECT,
			    AV_MASK|APIC_RESV_IRQ);
		}
	}

	/* Enable error interrupt */

	if (nlvt >= 4 && apic_enable_error_intr) {
		if (apic_errvect == 0) {
			int ipl = 0xf;	/* get highest priority intr */
			apic_errvect = apix_get_ipivect(ipl, -1);
			ASSERT(apic_errvect);
			/*
			 * Not PSMI compliant, but we are going to merge
			 * with ON anyway
			 */
			(void) add_avintr(NULL, ipl,
			    (avfunc)apic_error_intr, "apic error intr",
			    apic_errvect, NULL, NULL, NULL, NULL);
		}
		apic_reg_ops->apic_write(APIC_ERR_VECT, apic_errvect);
		apic_reg_ops->apic_write(APIC_ERROR_STATUS, 0);
		apic_reg_ops->apic_write(APIC_ERROR_STATUS, 0);
	}

	/* Enable CMCI interrupt */
	if (cmi_enable_cmci) {
		mutex_enter(&cmci_cpu_setup_lock);
		if (cmci_cpu_setup_registered == 0) {
			mutex_enter(&cpu_lock);
			register_cpu_setup_func(cmci_cpu_setup, NULL);
			mutex_exit(&cpu_lock);
			cmci_cpu_setup_registered = 1;
		}
		mutex_exit(&cmci_cpu_setup_lock);

		if (apic_cmci_vect == 0) {
			int ipl = 0x2;
			apic_cmci_vect = apix_get_ipivect(ipl, -1);
			ASSERT(apic_cmci_vect);

			(void) add_avintr(NULL, ipl,
			    (avfunc)cmi_cmci_trap, "apic cmci intr",
			    apic_cmci_vect, NULL, NULL, NULL, NULL);
		}
		apic_reg_ops->apic_write(APIC_CMCI_VECT, apic_cmci_vect);
	}

	apic_reg_ops->apic_write_task_reg(0);
}

static void
apix_picinit(void)
{
	int i, j;
	uint_t isr;

	APIC_VERBOSE(INIT, (CE_CONT, "apix: psm_picinit\n"));

	/*
	 * initialize interrupt remapping before apic
	 * hardware initialization
	 */
	apic_intrmap_init(apic_mode);
	if (apic_vt_ops == psm_vt_ops)
		apix_mul_ioapic_method = APIC_MUL_IOAPIC_IIR;

	/*
	 * On UniSys Model 6520, the BIOS leaves vector 0x20 isr
	 * bit on without clearing it with EOI.  Since softint
	 * uses vector 0x20 to interrupt itself, so softint will
	 * not work on this machine.  In order to fix this problem
	 * a check is made to verify all the isr bits are clear.
	 * If not, EOIs are issued to clear the bits.
	 */
	for (i = 7; i >= 1; i--) {
		isr = apic_reg_ops->apic_read(APIC_ISR_REG + (i * 4));
		if (isr != 0)
			for (j = 0; ((j < 32) && (isr != 0)); j++)
				if (isr & (1 << j)) {
					apic_reg_ops->apic_write(
					    APIC_EOI_REG, 0);
					isr &= ~(1 << j);
					apic_error |= APIC_ERR_BOOT_EOI;
				}
	}

	/* set a flag so we know we have run apic_picinit() */
	apic_picinit_called = 1;
	LOCK_INIT_CLEAR(&apic_gethrtime_lock);
	LOCK_INIT_CLEAR(&apic_ioapic_lock);
	LOCK_INIT_CLEAR(&apic_error_lock);
	LOCK_INIT_CLEAR(&apic_mode_switch_lock);

	picsetup();	 /* initialise the 8259 */

	/* add nmi handler - least priority nmi handler */
	LOCK_INIT_CLEAR(&apic_nmi_lock);

	if (!psm_add_nmintr(0, (avfunc) apic_nmi_intr,
	    "apix NMI handler", (caddr_t)NULL))
		cmn_err(CE_WARN, "apix: Unable to add nmi handler");

	apix_init_intr();

	/* enable apic mode if imcr present */
	if (apic_imcrp) {
		outb(APIC_IMCR_P1, (uchar_t)APIC_IMCR_SELECT);
		outb(APIC_IMCR_P2, (uchar_t)APIC_IMCR_APIC);
	}

	ioapix_init_intr(IOAPIC_MASK);

	/* setup global IRM pool if applicable */
	if (irm_enable)
		apix_irm_init();
}

static __inline__ void
apix_send_eoi(void)
{
	if (apic_mode == LOCAL_APIC)
		LOCAL_APIC_WRITE_REG(APIC_EOI_REG, 0);
	else
		X2APIC_WRITE(APIC_EOI_REG, 0);
}

/*
 * platform_intr_enter
 *
 *	Called at the beginning of the interrupt service routine, but unlike
 *	pcplusmp, does not mask interrupts. An EOI is given to the interrupt
 *	controller to enable other HW interrupts but interrupts are still
 * 	masked by the IF flag.
 *
 *	Return -1 for spurious interrupts
 *
 */
static int
apix_intr_enter(int ipl, int *vectorp)
{
	struct cpu *cpu = CPU;
	uint32_t cpuid = CPU->cpu_id;
	apic_cpus_info_t *cpu_infop;
	uchar_t vector;
	apix_vector_t *vecp;
	int nipl = -1;

	/*
	 * The real vector delivered is (*vectorp + 0x20), but our caller
	 * subtracts 0x20 from the vector before passing it to us.
	 * (That's why APIC_BASE_VECT is 0x20.)
	 */
	vector = *vectorp = (uchar_t)*vectorp + APIC_BASE_VECT;

	cpu_infop = &apic_cpus[cpuid];
	if (vector == APIC_SPUR_INTR) {
		cpu_infop->aci_spur_cnt++;
		return (APIC_INT_SPURIOUS);
	}

	vecp = xv_vector(cpuid, vector);
	if (vecp == NULL) {
		if (APIX_IS_FAKE_INTR(vector))
			nipl = apix_rebindinfo.i_pri;
		apix_send_eoi();
		return (nipl);
	}
	nipl = vecp->v_pri;

	/* if interrupted by the clock, increment apic_nsec_since_boot */
	if (vector == (apic_clkvect + APIC_BASE_VECT)) {
		if (!apic_oneshot) {
			/* NOTE: this is not MT aware */
			apic_hrtime_stamp++;
			apic_nsec_since_boot += apic_nsec_per_intr;
			apic_hrtime_stamp++;
			last_count_read = apic_hertz_count;
			apix_redistribute_compute();
		}

		apix_send_eoi();

		return (nipl);
	}

	ASSERT(vecp->v_state != APIX_STATE_OBSOLETED);

	/* pre-EOI handling for level-triggered interrupts */
	if (!APIX_IS_DIRECTED_EOI(apix_mul_ioapic_method) &&
	    (vecp->v_type & APIX_TYPE_FIXED) && apic_level_intr[vecp->v_inum])
		apix_level_intr_pre_eoi(vecp->v_inum);

	/* send back EOI */
	apix_send_eoi();

	cpu_infop->aci_current[nipl] = vector;
	if ((nipl > ipl) && (nipl > cpu->cpu_base_spl)) {
		cpu_infop->aci_curipl = (uchar_t)nipl;
		cpu_infop->aci_ISR_in_progress |= 1 << nipl;
	}

#ifdef	DEBUG
	if (vector >= APIX_IPI_MIN)
		return (nipl);	/* skip IPI */

	APIC_DEBUG_BUF_PUT(vector);
	APIC_DEBUG_BUF_PUT(vecp->v_inum);
	APIC_DEBUG_BUF_PUT(nipl);
	APIC_DEBUG_BUF_PUT(psm_get_cpu_id());
	if ((apic_stretch_interrupts) && (apic_stretch_ISR & (1 << nipl)))
		drv_usecwait(apic_stretch_interrupts);
#endif /* DEBUG */

	return (nipl);
}

/*
 * Any changes made to this function must also change X2APIC
 * version of intr_exit.
 */
static void
apix_intr_exit(int prev_ipl, int arg2)
{
	int cpuid = psm_get_cpu_id();
	apic_cpus_info_t *cpu_infop = &apic_cpus[cpuid];
	apix_impl_t *apixp = apixs[cpuid];

	UNREFERENCED_1PARAMETER(arg2);

	cpu_infop->aci_curipl = (uchar_t)prev_ipl;
	/* ISR above current pri could not be in progress */
	cpu_infop->aci_ISR_in_progress &= (2 << prev_ipl) - 1;

	if (apixp->x_obsoletes != NULL) {
		if (APIX_CPU_LOCK_HELD(cpuid))
			return;

		APIX_ENTER_CPU_LOCK(cpuid);
		(void) apix_obsolete_vector(apixp->x_obsoletes);
		APIX_LEAVE_CPU_LOCK(cpuid);
	}
}

/*
 * The pcplusmp setspl code uses the TPR to mask all interrupts at or below the
 * given ipl, but apix never uses the TPR and we never mask a subset of the
 * interrupts. They are either all blocked by the IF flag or all can come in.
 *
 * For setspl, we mask all interrupts for XC_HI_PIL (15), otherwise, interrupts
 * can come in if currently enabled by the IF flag. This table shows the state
 * of the IF flag when we leave this function.
 *
 *    curr IF |	ipl == 15	ipl != 15
 *    --------+---------------------------
 *       0    |    0		    0
 *       1    |    0		    1
 */
static void
apix_setspl(int ipl)
{
	/*
	 * Interrupts at ipl above this cannot be in progress, so the following
	 * mask is ok.
	 */
	apic_cpus[psm_get_cpu_id()].aci_ISR_in_progress &= (2 << ipl) - 1;

	if (ipl == XC_HI_PIL)
		cli();
}

int
apix_addspl(int virtvec, int ipl, int min_ipl, int max_ipl)
{
	uint32_t cpuid = APIX_VIRTVEC_CPU(virtvec);
	uchar_t vector = (uchar_t)APIX_VIRTVEC_VECTOR(virtvec);
	apix_vector_t *vecp = xv_vector(cpuid, vector);

	UNREFERENCED_3PARAMETER(ipl, min_ipl, max_ipl);
	ASSERT(vecp != NULL && LOCK_HELD(&apix_lock));

	if (vecp->v_type == APIX_TYPE_FIXED)
		apix_intx_set_shared(vecp->v_inum, 1);

	/* There are more interrupts, so it's already been enabled */
	if (vecp->v_share > 1)
		return (PSM_SUCCESS);

	/* return if it is not hardware interrupt */
	if (vecp->v_type == APIX_TYPE_IPI)
		return (PSM_SUCCESS);

	/*
	 * if apix_picinit() has not been called yet, just return.
	 * At the end of apic_picinit(), we will call setup_io_intr().
	 */
	if (!apic_picinit_called)
		return (PSM_SUCCESS);

	(void) apix_setup_io_intr(vecp);

	return (PSM_SUCCESS);
}

int
apix_delspl(int virtvec, int ipl, int min_ipl, int max_ipl)
{
	uint32_t cpuid = APIX_VIRTVEC_CPU(virtvec);
	uchar_t vector = (uchar_t)APIX_VIRTVEC_VECTOR(virtvec);
	apix_vector_t *vecp = xv_vector(cpuid, vector);

	UNREFERENCED_3PARAMETER(ipl, min_ipl, max_ipl);
	ASSERT(vecp != NULL && LOCK_HELD(&apix_lock));

	if (vecp->v_type == APIX_TYPE_FIXED)
		apix_intx_set_shared(vecp->v_inum, -1);

	/* There are more interrupts */
	if (vecp->v_share > 1)
		return (PSM_SUCCESS);

	/* return if it is not hardware interrupt */
	if (vecp->v_type == APIX_TYPE_IPI)
		return (PSM_SUCCESS);

	if (!apic_picinit_called) {
		cmn_err(CE_WARN, "apix: delete 0x%x before apic init",
		    virtvec);
		return (PSM_SUCCESS);
	}

	apix_disable_vector(vecp);

	return (PSM_SUCCESS);
}

/*
 * Try and disable all interrupts. We just assign interrupts to other
 * processors based on policy. If any were bound by user request, we
 * let them continue and return failure. We do not bother to check
 * for cache affinity while rebinding.
 */
static int
apix_disable_intr(processorid_t cpun)
{
	apix_impl_t *apixp = apixs[cpun];
	apix_vector_t *vecp, *newp;
	int bindcpu, i, hardbound = 0, errbound = 0, ret, loop, type;

	lock_set(&apix_lock);

	apic_cpus[cpun].aci_status &= ~APIC_CPU_INTR_ENABLE;
	apic_cpus[cpun].aci_curipl = 0;

	/* if this is for SUSPEND operation, skip rebinding */
	if (apic_cpus[cpun].aci_status & APIC_CPU_SUSPEND) {
		for (i = APIX_AVINTR_MIN; i <= APIX_AVINTR_MAX; i++) {
			vecp = apixp->x_vectbl[i];
			if (!IS_VECT_ENABLED(vecp))
				continue;

			apix_disable_vector(vecp);
		}
		lock_clear(&apix_lock);
		return (PSM_SUCCESS);
	}

	for (i = APIX_AVINTR_MIN; i <= APIX_AVINTR_MAX; i++) {
		vecp = apixp->x_vectbl[i];
		if (!IS_VECT_ENABLED(vecp))
			continue;

		if (vecp->v_flags & APIX_VECT_USER_BOUND) {
			hardbound++;
			continue;
		}
		type = vecp->v_type;

		/*
		 * If there are bound interrupts on this cpu, then
		 * rebind them to other processors.
		 */
		loop = 0;
		do {
			bindcpu = apic_find_cpu(APIC_CPU_INTR_ENABLE);

			if (type != APIX_TYPE_MSI)
				newp = apix_set_cpu(vecp, bindcpu, &ret);
			else
				newp = apix_grp_set_cpu(vecp, bindcpu, &ret);
		} while ((newp == NULL) && (loop++ < apic_nproc));

		if (loop >= apic_nproc) {
			errbound++;
			cmn_err(CE_WARN, "apix: failed to rebind vector %x/%x",
			    vecp->v_cpuid, vecp->v_vector);
		}
	}

	lock_clear(&apix_lock);

	if (hardbound || errbound) {
		cmn_err(CE_WARN, "Could not disable interrupts on %d"
		    "due to user bound interrupts or failed operation",
		    cpun);
		return (PSM_FAILURE);
	}

	return (PSM_SUCCESS);
}

/*
 * Bind interrupts to specified CPU
 */
static void
apix_enable_intr(processorid_t cpun)
{
	apix_vector_t *vecp;
	int i, ret;
	processorid_t n;

	lock_set(&apix_lock);

	apic_cpus[cpun].aci_status |= APIC_CPU_INTR_ENABLE;

	/* interrupt enabling for system resume */
	if (apic_cpus[cpun].aci_status & APIC_CPU_SUSPEND) {
		for (i = APIX_AVINTR_MIN; i <= APIX_AVINTR_MAX; i++) {
			vecp = xv_vector(cpun, i);
			if (!IS_VECT_ENABLED(vecp))
				continue;

			apix_enable_vector(vecp);
		}
		apic_cpus[cpun].aci_status &= ~APIC_CPU_SUSPEND;
	}

	for (n = 0; n < apic_nproc; n++) {
		if (!apic_cpu_in_range(n) || n == cpun ||
		    (apic_cpus[n].aci_status & APIC_CPU_INTR_ENABLE) == 0)
			continue;

		for (i = APIX_AVINTR_MIN; i <= APIX_AVINTR_MAX; i++) {
			vecp = xv_vector(n, i);
			if (!IS_VECT_ENABLED(vecp) ||
			    vecp->v_bound_cpuid != cpun)
				continue;

			if (vecp->v_type != APIX_TYPE_MSI)
				(void) apix_set_cpu(vecp, cpun, &ret);
			else
				(void) apix_grp_set_cpu(vecp, cpun, &ret);
		}
	}

	lock_clear(&apix_lock);
}

/*
 * Allocate vector for IPI
 * type == -1 indicates it is an internal request. Do not change
 * resv_vector for these requests.
 */
static int
apix_get_ipivect(int ipl, int type)
{
	uchar_t vector;

	if ((vector = apix_alloc_ipi(ipl)) > 0) {
		if (type != -1)
			apic_resv_vector[ipl] = vector;
		return (vector);
	}
	apic_error |= APIC_ERR_GET_IPIVECT_FAIL;
	return (-1);	/* shouldn't happen */
}

static int
apix_get_clkvect(int ipl)
{
	int vector;

	if ((vector = apix_get_ipivect(ipl, -1)) == -1)
		return (-1);

	apic_clkvect = vector - APIC_BASE_VECT;
	APIC_VERBOSE(IPI, (CE_CONT, "apix: clock vector = %x\n",
	    apic_clkvect));
	return (vector);
}

static int
apix_post_cpu_start()
{
	int cpun;
	static int cpus_started = 1;

	/* We know this CPU + BSP  started successfully. */
	cpus_started++;

	/*
	 * On BSP we would have enabled X2APIC, if supported by processor,
	 * in acpi_probe(), but on AP we do it here.
	 *
	 * We enable X2APIC mode only if BSP is running in X2APIC & the
	 * local APIC mode of the current CPU is MMIO (xAPIC).
	 */
	if (apic_mode == LOCAL_X2APIC && apic_detect_x2apic() &&
	    apic_local_mode() == LOCAL_APIC) {
		apic_enable_x2apic();
	}

	/*
	 * Switch back to x2apic IPI sending method for performance when target
	 * CPU has entered x2apic mode.
	 */
	if (apic_mode == LOCAL_X2APIC) {
		apic_switch_ipi_callback(B_FALSE);
	}

	splx(ipltospl(LOCK_LEVEL));
	apix_init_intr();

	/*
	 * since some systems don't enable the internal cache on the non-boot
	 * cpus, so we have to enable them here
	 */
	setcr0(getcr0() & ~(CR0_CD | CR0_NW));

#ifdef	DEBUG
	APIC_AV_PENDING_SET();
#else
	if (apic_mode == LOCAL_APIC)
		APIC_AV_PENDING_SET();
#endif	/* DEBUG */

	/*
	 * We may be booting, or resuming from suspend; aci_status will
	 * be APIC_CPU_INTR_ENABLE if coming from suspend, so we add the
	 * APIC_CPU_ONLINE flag here rather than setting aci_status completely.
	 */
	cpun = psm_get_cpu_id();
	apic_cpus[cpun].aci_status |= APIC_CPU_ONLINE;

	apic_reg_ops->apic_write(APIC_DIVIDE_REG, apic_divide_reg_init);

	return (PSM_SUCCESS);
}

/*
 * If this module needs a periodic handler for the interrupt distribution, it
 * can be added here. The argument to the periodic handler is not currently
 * used, but is reserved for future.
 */
static void
apix_post_cyclic_setup(void *arg)
{
	UNREFERENCED_1PARAMETER(arg);

	cyc_handler_t cyh;
	cyc_time_t cyt;

	/* cpu_lock is held */
	/* set up a periodic handler for intr redistribution */

	/*
	 * In peridoc mode intr redistribution processing is done in
	 * apic_intr_enter during clk intr processing
	 */
	if (!apic_oneshot)
		return;

	/*
	 * Register a periodical handler for the redistribution processing.
	 * Though we would generally prefer to use the DDI interface for
	 * periodic handler invocation, ddi_periodic_add(9F), we are
	 * unfortunately already holding cpu_lock, which ddi_periodic_add will
	 * attempt to take for us.  Thus, we add our own cyclic directly:
	 */
	cyh.cyh_func = (void (*)(void *))apix_redistribute_compute;
	cyh.cyh_arg = NULL;
	cyh.cyh_level = CY_LOW_LEVEL;

	cyt.cyt_when = 0;
	cyt.cyt_interval = apic_redistribute_sample_interval;

	apic_cyclic_id = cyclic_add(&cyh, &cyt);
}

/*
 * Called the first time we enable x2apic mode on this cpu.
 * Update some of the function pointers to use x2apic routines.
 */
void
x2apic_update_psm()
{
	struct psm_ops *pops = &apix_ops;

	ASSERT(pops != NULL);

	/*
	 * The pcplusmp module's version of x2apic_update_psm makes additional
	 * changes that we do not have to make here. It needs to make those
	 * changes because pcplusmp relies on the TPR register and the means of
	 * addressing that changes when using the local apic versus the x2apic.
	 * It's also worth noting that the apix driver specific function end up
	 * being apix_foo as opposed to apic_foo and x2apic_foo.
	 */
	pops->psm_send_ipi = x2apic_send_ipi;

	send_dirintf = pops->psm_send_ipi;

	apic_mode = LOCAL_X2APIC;
	apic_change_ops();
}

/*
 * This function provides external interface to the nexus for all
 * functionalities related to the new DDI interrupt framework.
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
static int
apix_intr_ops(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp,
    psm_intr_op_t intr_op, int *result)
{
	int		cap;
	apix_vector_t	*vecp, *newvecp;
	struct intrspec *ispec, intr_spec;
	processorid_t target;

	ispec = &intr_spec;
	ispec->intrspec_pri = hdlp->ih_pri;
	ispec->intrspec_vec = hdlp->ih_inum;
	ispec->intrspec_func = hdlp->ih_cb_func;

	switch (intr_op) {
	case PSM_INTR_OP_ALLOC_VECTORS:
		switch (hdlp->ih_type) {
		case DDI_INTR_TYPE_MSI:
			/* allocate MSI vectors */
			*result = apix_alloc_msi(dip, hdlp->ih_inum,
			    hdlp->ih_scratch1,
			    (int)(uintptr_t)hdlp->ih_scratch2);
			break;
		case DDI_INTR_TYPE_MSIX:
			/* allocate MSI-X vectors */
			*result = apix_alloc_msix(dip, hdlp->ih_inum,
			    hdlp->ih_scratch1,
			    (int)(uintptr_t)hdlp->ih_scratch2);
			break;
		case DDI_INTR_TYPE_FIXED:
			/* allocate or share vector for fixed */
			if ((ihdl_plat_t *)hdlp->ih_private == NULL) {
				return (PSM_FAILURE);
			}
			ispec = ((ihdl_plat_t *)hdlp->ih_private)->ip_ispecp;
			*result = apix_intx_alloc_vector(dip, hdlp->ih_inum,
			    ispec);
			break;
		default:
			return (PSM_FAILURE);
		}
		break;
	case PSM_INTR_OP_FREE_VECTORS:
		apix_free_vectors(dip, hdlp->ih_inum, hdlp->ih_scratch1,
		    hdlp->ih_type);
		break;
	case PSM_INTR_OP_XLATE_VECTOR:
		/*
		 * Vectors are allocated by ALLOC and freed by FREE.
		 * XLATE finds and returns APIX_VIRTVEC_VECTOR(cpu, vector).
		 */
		*result = APIX_INVALID_VECT;
		vecp = apix_get_dev_map(dip, hdlp->ih_inum, hdlp->ih_type);
		if (vecp != NULL) {
			*result = APIX_VIRTVECTOR(vecp->v_cpuid,
			    vecp->v_vector);
			break;
		}

		/*
		 * No vector to device mapping exists. If this is FIXED type
		 * then check if this IRQ is already mapped for another device
		 * then return the vector number for it (i.e. shared IRQ case).
		 * Otherwise, return PSM_FAILURE.
		 */
		if (hdlp->ih_type == DDI_INTR_TYPE_FIXED) {
			vecp = apix_intx_xlate_vector(dip, hdlp->ih_inum,
			    ispec);
			*result = (vecp == NULL) ? APIX_INVALID_VECT :
			    APIX_VIRTVECTOR(vecp->v_cpuid, vecp->v_vector);
		}
		if (*result == APIX_INVALID_VECT)
			return (PSM_FAILURE);
		break;
	case PSM_INTR_OP_GET_PENDING:
		vecp = apix_get_dev_map(dip, hdlp->ih_inum, hdlp->ih_type);
		if (vecp == NULL)
			return (PSM_FAILURE);

		*result = apix_get_pending(vecp);
		break;
	case PSM_INTR_OP_CLEAR_MASK:
		if (hdlp->ih_type != DDI_INTR_TYPE_FIXED)
			return (PSM_FAILURE);

		vecp = apix_get_dev_map(dip, hdlp->ih_inum, hdlp->ih_type);
		if (vecp == NULL)
			return (PSM_FAILURE);

		apix_intx_clear_mask(vecp->v_inum);
		break;
	case PSM_INTR_OP_SET_MASK:
		if (hdlp->ih_type != DDI_INTR_TYPE_FIXED)
			return (PSM_FAILURE);

		vecp = apix_get_dev_map(dip, hdlp->ih_inum, hdlp->ih_type);
		if (vecp == NULL)
			return (PSM_FAILURE);

		apix_intx_set_mask(vecp->v_inum);
		break;
	case PSM_INTR_OP_GET_SHARED:
		if (hdlp->ih_type != DDI_INTR_TYPE_FIXED)
			return (PSM_FAILURE);

		vecp = apix_get_dev_map(dip, hdlp->ih_inum, hdlp->ih_type);
		if (vecp == NULL)
			return (PSM_FAILURE);

		*result = apix_intx_get_shared(vecp->v_inum);
		break;
	case PSM_INTR_OP_SET_PRI:
		/*
		 * Called prior to adding the interrupt handler or when
		 * an interrupt handler is unassigned.
		 */
		if (hdlp->ih_type == DDI_INTR_TYPE_FIXED)
			return (PSM_SUCCESS);

		if (apix_get_dev_map(dip, hdlp->ih_inum, hdlp->ih_type) == NULL)
			return (PSM_FAILURE);

		break;
	case PSM_INTR_OP_SET_CPU:
	case PSM_INTR_OP_GRP_SET_CPU:
		/*
		 * The interrupt handle given here has been allocated
		 * specifically for this command, and ih_private carries
		 * a CPU value.
		 */
		*result = EINVAL;
		target = (int)(intptr_t)hdlp->ih_private;
		if (!apic_cpu_in_range(target)) {
			DDI_INTR_IMPLDBG((CE_WARN,
			    "[grp_]set_cpu: cpu out of range: %d\n", target));
			return (PSM_FAILURE);
		}

		lock_set(&apix_lock);

		vecp = apix_get_req_vector(hdlp, hdlp->ih_flags);
		if (!IS_VECT_ENABLED(vecp)) {
			DDI_INTR_IMPLDBG((CE_WARN,
			    "[grp]_set_cpu: invalid vector 0x%x\n",
			    hdlp->ih_vector));
			lock_clear(&apix_lock);
			return (PSM_FAILURE);
		}

		*result = 0;

		if (intr_op == PSM_INTR_OP_SET_CPU)
			newvecp = apix_set_cpu(vecp, target, result);
		else
			newvecp = apix_grp_set_cpu(vecp, target, result);

		lock_clear(&apix_lock);

		if (newvecp == NULL) {
			*result = EIO;
			return (PSM_FAILURE);
		}
		newvecp->v_bound_cpuid = target;
		hdlp->ih_vector = APIX_VIRTVECTOR(newvecp->v_cpuid,
		    newvecp->v_vector);
		break;

	case PSM_INTR_OP_GET_INTR:
		/*
		 * The interrupt handle given here has been allocated
		 * specifically for this command, and ih_private carries
		 * a pointer to a apic_get_intr_t.
		 */
		if (apix_get_intr_info(hdlp, hdlp->ih_private) != PSM_SUCCESS)
			return (PSM_FAILURE);
		break;

	case PSM_INTR_OP_CHECK_MSI:
		/*
		 * Check MSI/X is supported or not at APIC level and
		 * masked off the MSI/X bits in hdlp->ih_type if not
		 * supported before return.  If MSI/X is supported,
		 * leave the ih_type unchanged and return.
		 *
		 * hdlp->ih_type passed in from the nexus has all the
		 * interrupt types supported by the device.
		 */
		if (apic_support_msi == 0) {	/* uninitialized */
			/*
			 * if apic_support_msi is not set, call
			 * apic_check_msi_support() to check whether msi
			 * is supported first
			 */
			if (apic_check_msi_support() == PSM_SUCCESS)
				apic_support_msi = 1;	/* supported */
			else
				apic_support_msi = -1;	/* not-supported */
		}
		if (apic_support_msi == 1) {
			if (apic_msix_enable)
				*result = hdlp->ih_type;
			else
				*result = hdlp->ih_type & ~DDI_INTR_TYPE_MSIX;
		} else
			*result = hdlp->ih_type & ~(DDI_INTR_TYPE_MSI |
			    DDI_INTR_TYPE_MSIX);
		break;
	case PSM_INTR_OP_GET_CAP:
		cap = DDI_INTR_FLAG_PENDING;
		if (hdlp->ih_type == DDI_INTR_TYPE_FIXED)
			cap |= DDI_INTR_FLAG_MASKABLE;
		*result = cap;
		break;
	case PSM_INTR_OP_APIC_TYPE:
		((apic_get_type_t *)(hdlp->ih_private))->avgi_type =
		    apix_get_apic_type();
		((apic_get_type_t *)(hdlp->ih_private))->avgi_num_intr =
		    APIX_IPI_MIN;
		((apic_get_type_t *)(hdlp->ih_private))->avgi_num_cpu =
		    apic_nproc;
		hdlp->ih_ver = apic_get_apic_version();
		break;
	case PSM_INTR_OP_SET_CAP:
	default:
		return (PSM_FAILURE);
	}

	return (PSM_SUCCESS);
}

static void
apix_cleanup_busy(void)
{
	int i, j;
	apix_vector_t *vecp;

	for (i = 0; i < apic_nproc; i++) {
		if (!apic_cpu_in_range(i))
			continue;
		apic_cpus[i].aci_busy = 0;
		for (j = APIX_AVINTR_MIN; j < APIX_AVINTR_MAX; j++) {
			if ((vecp = xv_vector(i, j)) != NULL)
				vecp->v_busy = 0;
		}
	}
}

static void
apix_redistribute_compute(void)
{
	int	i, j, max_busy;

	if (!apic_enable_dynamic_migration)
		return;

	if (++apic_nticks == apic_sample_factor_redistribution) {
		/*
		 * Time to call apic_intr_redistribute().
		 * reset apic_nticks. This will cause max_busy
		 * to be calculated below and if it is more than
		 * apic_int_busy, we will do the whole thing
		 */
		apic_nticks = 0;
	}
	max_busy = 0;
	for (i = 0; i < apic_nproc; i++) {
		if (!apic_cpu_in_range(i))
			continue;
		/*
		 * Check if curipl is non zero & if ISR is in
		 * progress
		 */
		if (((j = apic_cpus[i].aci_curipl) != 0) &&
		    (apic_cpus[i].aci_ISR_in_progress & (1 << j))) {

			int	vect;
			apic_cpus[i].aci_busy++;
			vect = apic_cpus[i].aci_current[j];
			apixs[i]->x_vectbl[vect]->v_busy++;
		}

		if (!apic_nticks &&
		    (apic_cpus[i].aci_busy > max_busy))
			max_busy = apic_cpus[i].aci_busy;
	}
	if (!apic_nticks) {
		if (max_busy > apic_int_busy_mark) {
		/*
		 * We could make the following check be
		 * skipped > 1 in which case, we get a
		 * redistribution at half the busy mark (due to
		 * double interval). Need to be able to collect
		 * more empirical data to decide if that is a
		 * good strategy. Punt for now.
		 */
			apix_cleanup_busy();
			apic_skipped_redistribute = 0;
		} else
			apic_skipped_redistribute++;
	}
}

/*
 * intr_ops() service routines
 */

static int
apix_get_pending(apix_vector_t *vecp)
{
	int bit, index, irr, pending;

	/* need to get on the bound cpu */
	mutex_enter(&cpu_lock);
	affinity_set(vecp->v_cpuid);

	index = vecp->v_vector / 32;
	bit = vecp->v_vector % 32;
	irr = apic_reg_ops->apic_read(APIC_IRR_REG + index);

	affinity_clear();
	mutex_exit(&cpu_lock);

	pending = (irr & (1 << bit)) ? 1 : 0;
	if (!pending && vecp->v_type == APIX_TYPE_FIXED)
		pending = apix_intx_get_pending(vecp->v_inum);

	return (pending);
}

static apix_vector_t *
apix_get_req_vector(ddi_intr_handle_impl_t *hdlp, ushort_t flags)
{
	apix_vector_t *vecp;
	processorid_t cpuid;
	int32_t virt_vec = 0;

	switch (flags & PSMGI_INTRBY_FLAGS) {
	case PSMGI_INTRBY_IRQ:
		return (apix_intx_get_vector(hdlp->ih_vector));
	case PSMGI_INTRBY_VEC:
		virt_vec = (virt_vec == 0) ? hdlp->ih_vector : virt_vec;

		cpuid = APIX_VIRTVEC_CPU(virt_vec);
		if (!apic_cpu_in_range(cpuid))
			return (NULL);

		vecp = xv_vector(cpuid, APIX_VIRTVEC_VECTOR(virt_vec));
		break;
	case PSMGI_INTRBY_DEFAULT:
		vecp = apix_get_dev_map(hdlp->ih_dip, hdlp->ih_inum,
		    hdlp->ih_type);
		break;
	default:
		return (NULL);
	}

	return (vecp);
}

static int
apix_get_intr_info(ddi_intr_handle_impl_t *hdlp,
    apic_get_intr_t *intr_params_p)
{
	apix_vector_t *vecp;
	struct autovec *av_dev;
	int i;

	vecp = apix_get_req_vector(hdlp, intr_params_p->avgi_req_flags);
	if (IS_VECT_FREE(vecp)) {
		intr_params_p->avgi_num_devs = 0;
		intr_params_p->avgi_cpu_id = 0;
		intr_params_p->avgi_req_flags = 0;
		return (PSM_SUCCESS);
	}

	if (intr_params_p->avgi_req_flags & PSMGI_REQ_CPUID) {
		intr_params_p->avgi_cpu_id = vecp->v_cpuid;

		/* Return user bound info for intrd. */
		if (intr_params_p->avgi_cpu_id & IRQ_USER_BOUND) {
			intr_params_p->avgi_cpu_id &= ~IRQ_USER_BOUND;
			intr_params_p->avgi_cpu_id |= PSMGI_CPU_USER_BOUND;
		}
	}

	if (intr_params_p->avgi_req_flags & PSMGI_REQ_VECTOR)
		intr_params_p->avgi_vector = vecp->v_vector;

	if (intr_params_p->avgi_req_flags &
	    (PSMGI_REQ_NUM_DEVS | PSMGI_REQ_GET_DEVS))
		/* Get number of devices from apic_irq table shared field. */
		intr_params_p->avgi_num_devs = vecp->v_share;

	if (intr_params_p->avgi_req_flags &  PSMGI_REQ_GET_DEVS) {

		intr_params_p->avgi_req_flags  |= PSMGI_REQ_NUM_DEVS;

		/* Some devices have NULL dip.  Don't count these. */
		if (intr_params_p->avgi_num_devs > 0) {
			for (i = 0, av_dev = vecp->v_autovect; av_dev;
			    av_dev = av_dev->av_link) {
				if (av_dev->av_vector && av_dev->av_dip)
					i++;
			}
			intr_params_p->avgi_num_devs =
			    (uint8_t)MIN(intr_params_p->avgi_num_devs, i);
		}

		/* There are no viable dips to return. */
		if (intr_params_p->avgi_num_devs == 0) {
			intr_params_p->avgi_dip_list = NULL;

		} else {	/* Return list of dips */

			/* Allocate space in array for that number of devs. */
			intr_params_p->avgi_dip_list = kmem_zalloc(
			    intr_params_p->avgi_num_devs *
			    sizeof (dev_info_t *),
			    KM_NOSLEEP);
			if (intr_params_p->avgi_dip_list == NULL) {
				DDI_INTR_IMPLDBG((CE_WARN,
				    "apix_get_vector_intr_info: no memory"));
				return (PSM_FAILURE);
			}

			/*
			 * Loop through the device list of the autovec table
			 * filling in the dip array.
			 *
			 * Note that the autovect table may have some special
			 * entries which contain NULL dips.  These will be
			 * ignored.
			 */
			for (i = 0, av_dev = vecp->v_autovect; av_dev;
			    av_dev = av_dev->av_link) {
				if (av_dev->av_vector && av_dev->av_dip)
					intr_params_p->avgi_dip_list[i++] =
					    av_dev->av_dip;
			}
		}
	}

	return (PSM_SUCCESS);
}

static char *
apix_get_apic_type(void)
{
	return (apix_psm_info.p_mach_idstring);
}

apix_vector_t *
apix_set_cpu(apix_vector_t *vecp, int new_cpu, int *result)
{
	apix_vector_t *newp = NULL;
	dev_info_t *dip;
	int inum, cap_ptr;
	ddi_acc_handle_t handle;
	ddi_intr_msix_t *msix_p = NULL;
	ushort_t msix_ctrl;
	uintptr_t off;
	uint32_t mask;

	ASSERT(LOCK_HELD(&apix_lock));
	*result = ENXIO;

	/* Fail if this is an MSI intr and is part of a group. */
	if (vecp->v_type == APIX_TYPE_MSI) {
		if (i_ddi_intr_get_current_nintrs(APIX_GET_DIP(vecp)) > 1)
			return (NULL);
		else
			return (apix_grp_set_cpu(vecp, new_cpu, result));
	}

	/*
	 * Mask MSI-X. It's unmasked when MSI-X gets enabled.
	 */
	if (vecp->v_type == APIX_TYPE_MSIX && IS_VECT_ENABLED(vecp)) {
		if ((dip = APIX_GET_DIP(vecp)) == NULL)
			return (NULL);
		inum = vecp->v_devp->dv_inum;

		handle = i_ddi_get_pci_config_handle(dip);
		cap_ptr = i_ddi_get_msi_msix_cap_ptr(dip);
		msix_ctrl = pci_config_get16(handle, cap_ptr + PCI_MSIX_CTRL);
		if ((msix_ctrl & PCI_MSIX_FUNCTION_MASK) == 0) {
			/*
			 * Function is not masked, then mask "inum"th
			 * entry in the MSI-X table
			 */
			msix_p = i_ddi_get_msix(dip);
			off = (uintptr_t)msix_p->msix_tbl_addr + (inum *
			    PCI_MSIX_VECTOR_SIZE) + PCI_MSIX_VECTOR_CTRL_OFFSET;
			mask = ddi_get32(msix_p->msix_tbl_hdl, (uint32_t *)off);
			ddi_put32(msix_p->msix_tbl_hdl, (uint32_t *)off,
			    mask | 1);
		}
	}

	*result = 0;
	if ((newp = apix_rebind(vecp, new_cpu, 1)) == NULL)
		*result = EIO;

	/* Restore mask bit */
	if (msix_p != NULL)
		ddi_put32(msix_p->msix_tbl_hdl, (uint32_t *)off, mask);

	return (newp);
}

/*
 * Set cpu for MSIs
 */
apix_vector_t *
apix_grp_set_cpu(apix_vector_t *vecp, int new_cpu, int *result)
{
	apix_vector_t *newp, *vp;
	uint32_t orig_cpu = vecp->v_cpuid;
	int orig_vect = vecp->v_vector;
	int i, num_vectors, cap_ptr, msi_mask_off;
	uint32_t msi_pvm;
	ushort_t msi_ctrl;
	ddi_acc_handle_t handle;
	dev_info_t *dip;

	APIC_VERBOSE(INTR, (CE_CONT, "apix_grp_set_cpu: oldcpu: %x, vector: %x,"
	    " newcpu:%x\n", vecp->v_cpuid, vecp->v_vector, new_cpu));

	ASSERT(LOCK_HELD(&apix_lock));

	*result = ENXIO;

	if (vecp->v_type != APIX_TYPE_MSI) {
		DDI_INTR_IMPLDBG((CE_WARN, "set_grp: intr not MSI\n"));
		return (NULL);
	}

	if ((dip = APIX_GET_DIP(vecp)) == NULL)
		return (NULL);

	num_vectors = i_ddi_intr_get_current_nintrs(dip);
	if ((num_vectors < 1) || ((num_vectors - 1) & orig_vect)) {
		APIC_VERBOSE(INTR, (CE_WARN,
		    "set_grp: base vec not part of a grp or not aligned: "
		    "vec:0x%x, num_vec:0x%x\n", orig_vect, num_vectors));
		return (NULL);
	}

	if (vecp->v_inum != apix_get_min_dev_inum(dip, vecp->v_type))
		return (NULL);

	*result = EIO;
	for (i = 1; i < num_vectors; i++) {
		if ((vp = xv_vector(orig_cpu, orig_vect + i)) == NULL)
			return (NULL);
#ifdef DEBUG
		/*
		 * Sanity check: CPU and dip is the same for all entries.
		 * May be called when first msi to be enabled, at this time
		 * add_avintr() is not called for other msi
		 */
		if ((vp->v_share != 0) &&
		    ((APIX_GET_DIP(vp) != dip) ||
		    (vp->v_cpuid != vecp->v_cpuid))) {
			APIC_VERBOSE(INTR, (CE_WARN,
			    "set_grp: cpu or dip for vec 0x%x difft than for "
			    "vec 0x%x\n", orig_vect, orig_vect + i));
			APIC_VERBOSE(INTR, (CE_WARN,
			    "  cpu: %d vs %d, dip: 0x%p vs 0x%p\n", orig_cpu,
			    vp->v_cpuid, (void *)dip,
			    (void *)APIX_GET_DIP(vp)));
			return (NULL);
		}
#endif /* DEBUG */
	}

	cap_ptr = i_ddi_get_msi_msix_cap_ptr(dip);
	handle = i_ddi_get_pci_config_handle(dip);
	msi_ctrl = pci_config_get16(handle, cap_ptr + PCI_MSI_CTRL);

	/* MSI Per vector masking is supported. */
	if (msi_ctrl & PCI_MSI_PVM_MASK) {
		if (msi_ctrl &  PCI_MSI_64BIT_MASK)
			msi_mask_off = cap_ptr + PCI_MSI_64BIT_MASKBITS;
		else
			msi_mask_off = cap_ptr + PCI_MSI_32BIT_MASK;
		msi_pvm = pci_config_get32(handle, msi_mask_off);
		pci_config_put32(handle, msi_mask_off, (uint32_t)-1);
		APIC_VERBOSE(INTR, (CE_CONT,
		    "set_grp: pvm supported.  Mask set to 0x%x\n",
		    pci_config_get32(handle, msi_mask_off)));
	}

	if ((newp = apix_rebind(vecp, new_cpu, num_vectors)) != NULL)
		*result = 0;

	/* Reenable vectors if per vector masking is supported. */
	if (msi_ctrl & PCI_MSI_PVM_MASK) {
		pci_config_put32(handle, msi_mask_off, msi_pvm);
		APIC_VERBOSE(INTR, (CE_CONT,
		    "set_grp: pvm supported.  Mask restored to 0x%x\n",
		    pci_config_get32(handle, msi_mask_off)));
	}

	return (newp);
}

void
apix_intx_set_vector(int irqno, uint32_t cpuid, uchar_t vector)
{
	apic_irq_t *irqp;

	mutex_enter(&airq_mutex);
	irqp = apic_irq_table[irqno];
	irqp->airq_cpu = cpuid;
	irqp->airq_vector = vector;
	apic_record_rdt_entry(irqp, irqno);
	mutex_exit(&airq_mutex);
}

apix_vector_t *
apix_intx_get_vector(int irqno)
{
	apic_irq_t *irqp;
	uint32_t cpuid;
	uchar_t vector;

	mutex_enter(&airq_mutex);
	irqp = apic_irq_table[irqno & 0xff];
	if (IS_IRQ_FREE(irqp) || (irqp->airq_cpu == IRQ_UNINIT)) {
		mutex_exit(&airq_mutex);
		return (NULL);
	}
	cpuid = irqp->airq_cpu;
	vector = irqp->airq_vector;
	mutex_exit(&airq_mutex);

	return (xv_vector(cpuid, vector));
}

/*
 * Must called with interrupts disabled and apic_ioapic_lock held
 */
void
apix_intx_enable(int irqno)
{
	uchar_t ioapicindex, intin;
	apic_irq_t *irqp = apic_irq_table[irqno];
	ioapic_rdt_t irdt;
	apic_cpus_info_t *cpu_infop;
	apix_vector_t *vecp = xv_vector(irqp->airq_cpu, irqp->airq_vector);

	ASSERT(LOCK_HELD(&apic_ioapic_lock) && !IS_IRQ_FREE(irqp));

	ioapicindex = irqp->airq_ioapicindex;
	intin = irqp->airq_intin_no;
	cpu_infop =  &apic_cpus[irqp->airq_cpu];

	irdt.ir_lo = AV_PDEST | AV_FIXED | irqp->airq_rdt_entry;
	irdt.ir_hi = cpu_infop->aci_local_id;

	apic_vt_ops->apic_intrmap_alloc_entry(&vecp->v_intrmap_private, NULL,
	    vecp->v_type, 1, ioapicindex);
	apic_vt_ops->apic_intrmap_map_entry(vecp->v_intrmap_private,
	    (void *)&irdt, vecp->v_type, 1);
	apic_vt_ops->apic_intrmap_record_rdt(vecp->v_intrmap_private, &irdt);

	/* write RDT entry high dword - destination */
	WRITE_IOAPIC_RDT_ENTRY_HIGH_DWORD(ioapicindex, intin,
	    irdt.ir_hi);

	/* Write the vector, trigger, and polarity portion of the RDT */
	WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapicindex, intin, irdt.ir_lo);

	vecp->v_state = APIX_STATE_ENABLED;

	APIC_VERBOSE_IOAPIC((CE_CONT, "apix_intx_enable: ioapic 0x%x"
	    " intin 0x%x rdt_low 0x%x rdt_high 0x%x\n",
	    ioapicindex, intin, irdt.ir_lo, irdt.ir_hi));
}

/*
 * Must called with interrupts disabled and apic_ioapic_lock held
 */
void
apix_intx_disable(int irqno)
{
	apic_irq_t *irqp = apic_irq_table[irqno];
	int ioapicindex, intin;

	ASSERT(LOCK_HELD(&apic_ioapic_lock) && !IS_IRQ_FREE(irqp));
	/*
	 * The assumption here is that this is safe, even for
	 * systems with IOAPICs that suffer from the hardware
	 * erratum because all devices have been quiesced before
	 * they unregister their interrupt handlers.  If that
	 * assumption turns out to be false, this mask operation
	 * can induce the same erratum result we're trying to
	 * avoid.
	 */
	ioapicindex = irqp->airq_ioapicindex;
	intin = irqp->airq_intin_no;
	ioapic_write(ioapicindex, APIC_RDT_CMD + 2 * intin, AV_MASK);

	APIC_VERBOSE_IOAPIC((CE_CONT, "apix_intx_disable: ioapic 0x%x"
	    " intin 0x%x\n", ioapicindex, intin));
}

void
apix_intx_free(int irqno)
{
	apic_irq_t *irqp;

	mutex_enter(&airq_mutex);
	irqp = apic_irq_table[irqno];

	if (IS_IRQ_FREE(irqp)) {
		mutex_exit(&airq_mutex);
		return;
	}

	irqp->airq_mps_intr_index = FREE_INDEX;
	irqp->airq_cpu = IRQ_UNINIT;
	irqp->airq_vector = APIX_INVALID_VECT;
	mutex_exit(&airq_mutex);
}

#ifdef DEBUG
int apix_intr_deliver_timeouts = 0;
int apix_intr_rirr_timeouts = 0;
int apix_intr_rirr_reset_failure = 0;
#endif
int apix_max_reps_irr_pending = 10;

#define	GET_RDT_BITS(ioapic, intin, bits)	\
	(READ_IOAPIC_RDT_ENTRY_LOW_DWORD((ioapic), (intin)) & (bits))
#define	APIX_CHECK_IRR_DELAY	drv_usectohz(5000)

int
apix_intx_rebind(int irqno, processorid_t cpuid, uchar_t vector)
{
	apic_irq_t *irqp = apic_irq_table[irqno];
	ulong_t iflag;
	int waited, ioapic_ix, intin_no, level, repeats, rdt_entry, masked;

	ASSERT(irqp != NULL);

	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	ioapic_ix = irqp->airq_ioapicindex;
	intin_no = irqp->airq_intin_no;
	level = apic_level_intr[irqno];

	/*
	 * Wait for the delivery status bit to be cleared. This should
	 * be a very small amount of time.
	 */
	repeats = 0;
	do {
		repeats++;

		for (waited = 0; waited < apic_max_reps_clear_pending;
		    waited++) {
			if (GET_RDT_BITS(ioapic_ix, intin_no, AV_PENDING) == 0)
				break;
		}
		if (!level)
			break;

		/*
		 * Mask the RDT entry for level-triggered interrupts.
		 */
		irqp->airq_rdt_entry |= AV_MASK;
		rdt_entry = READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
		    intin_no);
		if ((masked = (rdt_entry & AV_MASK)) == 0) {
			/* Mask it */
			WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix, intin_no,
			    AV_MASK | rdt_entry);
		}

		/*
		 * If there was a race and an interrupt was injected
		 * just before we masked, check for that case here.
		 * Then, unmask the RDT entry and try again.  If we're
		 * on our last try, don't unmask (because we want the
		 * RDT entry to remain masked for the rest of the
		 * function).
		 */
		rdt_entry = READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
		    intin_no);
		if ((masked == 0) && ((rdt_entry & AV_PENDING) != 0) &&
		    (repeats < apic_max_reps_clear_pending)) {
			/* Unmask it */
			WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
			    intin_no, rdt_entry & ~AV_MASK);
			irqp->airq_rdt_entry &= ~AV_MASK;
		}
	} while ((rdt_entry & AV_PENDING) &&
	    (repeats < apic_max_reps_clear_pending));

#ifdef DEBUG
	if (GET_RDT_BITS(ioapic_ix, intin_no, AV_PENDING) != 0)
		apix_intr_deliver_timeouts++;
#endif

	if (!level || !APIX_IS_MASK_RDT(apix_mul_ioapic_method))
		goto done;

	/*
	 * wait for remote IRR to be cleared for level-triggered
	 * interrupts
	 */
	repeats = 0;
	do {
		repeats++;

		for (waited = 0; waited < apic_max_reps_clear_pending;
		    waited++) {
			if (GET_RDT_BITS(ioapic_ix, intin_no, AV_REMOTE_IRR)
			    == 0)
				break;
		}

		if (GET_RDT_BITS(ioapic_ix, intin_no, AV_REMOTE_IRR) != 0) {
			lock_clear(&apic_ioapic_lock);
			intr_restore(iflag);

			delay(APIX_CHECK_IRR_DELAY);

			iflag = intr_clear();
			lock_set(&apic_ioapic_lock);
		}
	} while (repeats < apix_max_reps_irr_pending);

	if (repeats >= apix_max_reps_irr_pending) {
#ifdef DEBUG
		apix_intr_rirr_timeouts++;
#endif

		/*
		 * If we waited and the Remote IRR bit is still not cleared,
		 * AND if we've invoked the timeout APIC_REPROGRAM_MAX_TIMEOUTS
		 * times for this interrupt, try the last-ditch workaround:
		 */
		if (GET_RDT_BITS(ioapic_ix, intin_no, AV_REMOTE_IRR) != 0) {
			/*
			 * Trying to clear the bit through normal
			 * channels has failed.  So as a last-ditch
			 * effort, try to set the trigger mode to
			 * edge, then to level.  This has been
			 * observed to work on many systems.
			 */
			WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
			    intin_no,
			    READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
			    intin_no) & ~AV_LEVEL);
			WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
			    intin_no,
			    READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
			    intin_no) | AV_LEVEL);
		}

		if (GET_RDT_BITS(ioapic_ix, intin_no, AV_REMOTE_IRR) != 0) {
#ifdef DEBUG
			apix_intr_rirr_reset_failure++;
#endif
			lock_clear(&apic_ioapic_lock);
			intr_restore(iflag);
			prom_printf("apix: Remote IRR still "
			    "not clear for IOAPIC %d intin %d.\n"
			    "\tInterrupts to this pin may cease "
			    "functioning.\n", ioapic_ix, intin_no);
			return (1);	/* return failure */
		}
	}

done:
	/* change apic_irq_table */
	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);
	apix_intx_set_vector(irqno, cpuid, vector);
	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	/* reprogramme IO-APIC RDT entry */
	apix_intx_enable(irqno);

	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);

	return (0);
}

static int
apix_intx_get_pending(int irqno)
{
	apic_irq_t *irqp;
	int intin, ioapicindex, pending;
	ulong_t iflag;

	mutex_enter(&airq_mutex);
	irqp = apic_irq_table[irqno];
	if (IS_IRQ_FREE(irqp)) {
		mutex_exit(&airq_mutex);
		return (0);
	}

	/* check IO-APIC delivery status */
	intin = irqp->airq_intin_no;
	ioapicindex = irqp->airq_ioapicindex;
	mutex_exit(&airq_mutex);

	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	pending = (READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapicindex, intin) &
	    AV_PENDING) ? 1 : 0;

	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);

	return (pending);
}

/*
 * This function will mask the interrupt on the I/O APIC
 */
static void
apix_intx_set_mask(int irqno)
{
	int intin, ioapixindex, rdt_entry;
	ulong_t iflag;
	apic_irq_t *irqp;

	mutex_enter(&airq_mutex);
	irqp = apic_irq_table[irqno];

	ASSERT(irqp->airq_mps_intr_index != FREE_INDEX);

	intin = irqp->airq_intin_no;
	ioapixindex = irqp->airq_ioapicindex;
	mutex_exit(&airq_mutex);

	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	rdt_entry = READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapixindex, intin);

	/* clear mask */
	WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapixindex, intin,
	    (AV_MASK | rdt_entry));

	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);
}

/*
 * This function will clear the mask for the interrupt on the I/O APIC
 */
static void
apix_intx_clear_mask(int irqno)
{
	int intin, ioapixindex, rdt_entry;
	ulong_t iflag;
	apic_irq_t *irqp;

	mutex_enter(&airq_mutex);
	irqp = apic_irq_table[irqno];

	ASSERT(irqp->airq_mps_intr_index != FREE_INDEX);

	intin = irqp->airq_intin_no;
	ioapixindex = irqp->airq_ioapicindex;
	mutex_exit(&airq_mutex);

	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	rdt_entry = READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapixindex, intin);

	/* clear mask */
	WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapixindex, intin,
	    ((~AV_MASK) & rdt_entry));

	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);
}

/*
 * For level-triggered interrupt, mask the IRQ line. Mask means
 * new interrupts will not be delivered. The interrupt already
 * accepted by a local APIC is not affected
 */
void
apix_level_intr_pre_eoi(int irq)
{
	apic_irq_t *irqp = apic_irq_table[irq];
	int apic_ix, intin_ix;

	if (irqp == NULL)
		return;

	ASSERT(apic_level_intr[irq] == TRIGGER_MODE_LEVEL);

	lock_set(&apic_ioapic_lock);

	intin_ix = irqp->airq_intin_no;
	apic_ix = irqp->airq_ioapicindex;

	if (irqp->airq_cpu != CPU->cpu_id) {
		if (!APIX_IS_MASK_RDT(apix_mul_ioapic_method))
			ioapic_write_eoi(apic_ix, irqp->airq_vector);
		lock_clear(&apic_ioapic_lock);
		return;
	}

	if (apix_mul_ioapic_method == APIC_MUL_IOAPIC_IOXAPIC) {
		/*
		 * This is a IOxAPIC and there is EOI register:
		 * 	Change the vector to reserved unused vector, so that
		 * 	the EOI	from Local APIC won't clear the Remote IRR for
		 * 	this level trigger interrupt. Instead, we'll manually
		 * 	clear it in apix_post_hardint() after ISR handling.
		 */
		WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(apic_ix, intin_ix,
		    (irqp->airq_rdt_entry & (~0xff)) | APIX_RESV_VECTOR);
	} else {
		WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(apic_ix, intin_ix,
		    AV_MASK | irqp->airq_rdt_entry);
	}

	lock_clear(&apic_ioapic_lock);
}

/*
 * For level-triggered interrupt, unmask the IRQ line
 * or restore the original vector number.
 */
void
apix_level_intr_post_dispatch(int irq)
{
	apic_irq_t *irqp = apic_irq_table[irq];
	int apic_ix, intin_ix;

	if (irqp == NULL)
		return;

	lock_set(&apic_ioapic_lock);

	intin_ix = irqp->airq_intin_no;
	apic_ix = irqp->airq_ioapicindex;

	if (APIX_IS_DIRECTED_EOI(apix_mul_ioapic_method)) {
		/*
		 * Already sent EOI back to Local APIC.
		 * Send EOI to IO-APIC
		 */
		ioapic_write_eoi(apic_ix, irqp->airq_vector);
	} else {
		/* clear the mask or restore the vector */
		WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(apic_ix, intin_ix,
		    irqp->airq_rdt_entry);

		/* send EOI to IOxAPIC */
		if (apix_mul_ioapic_method == APIC_MUL_IOAPIC_IOXAPIC)
			ioapic_write_eoi(apic_ix, irqp->airq_vector);
	}

	lock_clear(&apic_ioapic_lock);
}

static int
apix_intx_get_shared(int irqno)
{
	apic_irq_t *irqp;
	int share;

	mutex_enter(&airq_mutex);
	irqp = apic_irq_table[irqno];
	if (IS_IRQ_FREE(irqp) || (irqp->airq_cpu == IRQ_UNINIT)) {
		mutex_exit(&airq_mutex);
		return (0);
	}
	share = irqp->airq_share;
	mutex_exit(&airq_mutex);

	return (share);
}

static void
apix_intx_set_shared(int irqno, int delta)
{
	apic_irq_t *irqp;

	mutex_enter(&airq_mutex);
	irqp = apic_irq_table[irqno];
	if (IS_IRQ_FREE(irqp)) {
		mutex_exit(&airq_mutex);
		return;
	}
	irqp->airq_share += delta;
	mutex_exit(&airq_mutex);
}

/*
 * Setup IRQ table. Return IRQ no or -1 on failure
 */
static int
apix_intx_setup(dev_info_t *dip, int inum, int irqno,
    struct apic_io_intr *intrp, struct intrspec *ispec, iflag_t *iflagp)
{
	int origirq = ispec->intrspec_vec;
	int newirq;
	short intr_index;
	uchar_t ipin, ioapic, ioapicindex;
	apic_irq_t *irqp;

	UNREFERENCED_1PARAMETER(inum);

	if (intrp != NULL) {
		intr_index = (short)(intrp - apic_io_intrp);
		ioapic = intrp->intr_destid;
		ipin = intrp->intr_destintin;

		/* Find ioapicindex. If destid was ALL, we will exit with 0. */
		for (ioapicindex = apic_io_max - 1; ioapicindex; ioapicindex--)
			if (apic_io_id[ioapicindex] == ioapic)
				break;
		ASSERT((ioapic == apic_io_id[ioapicindex]) ||
		    (ioapic == INTR_ALL_APIC));

		/* check whether this intin# has been used by another irqno */
		if ((newirq = apic_find_intin(ioapicindex, ipin)) != -1)
			return (newirq);

	} else if (iflagp != NULL) {	/* ACPI */
		intr_index = ACPI_INDEX;
		ioapicindex = acpi_find_ioapic(irqno);
		ASSERT(ioapicindex != 0xFF);
		ioapic = apic_io_id[ioapicindex];
		ipin = irqno - apic_io_vectbase[ioapicindex];

		if (apic_irq_table[irqno] &&
		    apic_irq_table[irqno]->airq_mps_intr_index == ACPI_INDEX) {
			ASSERT(apic_irq_table[irqno]->airq_intin_no == ipin &&
			    apic_irq_table[irqno]->airq_ioapicindex ==
			    ioapicindex);
			return (irqno);
		}

	} else {	/* default configuration */
		intr_index = DEFAULT_INDEX;
		ioapicindex = 0;
		ioapic = apic_io_id[ioapicindex];
		ipin = (uchar_t)irqno;
	}

	/* allocate a new IRQ no */
	if ((irqp = apic_irq_table[irqno]) == NULL) {
		irqp = kmem_zalloc(sizeof (apic_irq_t), KM_SLEEP);
		apic_irq_table[irqno] = irqp;
	} else {
		if (irqp->airq_mps_intr_index != FREE_INDEX) {
			newirq = apic_allocate_irq(apic_first_avail_irq);
			if (newirq == -1) {
				return (-1);
			}
			irqno = newirq;
			irqp = apic_irq_table[irqno];
			ASSERT(irqp != NULL);
		}
	}
	apic_max_device_irq = max(irqno, apic_max_device_irq);
	apic_min_device_irq = min(irqno, apic_min_device_irq);

	irqp->airq_mps_intr_index = intr_index;
	irqp->airq_ioapicindex = ioapicindex;
	irqp->airq_intin_no = ipin;
	irqp->airq_dip = dip;
	irqp->airq_origirq = (uchar_t)origirq;
	if (iflagp != NULL)
		irqp->airq_iflag = *iflagp;
	irqp->airq_cpu = IRQ_UNINIT;
	irqp->airq_vector = 0;

	return (irqno);
}

/*
 * Setup IRQ table for non-pci devices. Return IRQ no or -1 on error
 */
static int
apix_intx_setup_nonpci(dev_info_t *dip, int inum, int bustype,
    struct intrspec *ispec)
{
	int irqno = ispec->intrspec_vec;
	int newirq, i;
	iflag_t intr_flag;
	ACPI_SUBTABLE_HEADER	*hp;
	ACPI_MADT_INTERRUPT_OVERRIDE *isop;
	struct apic_io_intr *intrp;

	if (!apic_enable_acpi || apic_use_acpi_madt_only) {
		int busid;

		if (bustype == 0)
			bustype = eisa_level_intr_mask ? BUS_EISA : BUS_ISA;

		/* loop checking BUS_ISA/BUS_EISA */
		for (i = 0; i < 2; i++) {
			if (((busid = apic_find_bus_id(bustype)) != -1) &&
			    ((intrp = apic_find_io_intr_w_busid(irqno, busid))
			    != NULL)) {
				return (apix_intx_setup(dip, inum, irqno,
				    intrp, ispec, NULL));
			}
			bustype = (bustype == BUS_EISA) ? BUS_ISA : BUS_EISA;
		}

		/* fall back to default configuration */
		return (-1);
	}

	/* search iso entries first */
	if (acpi_iso_cnt != 0) {
		hp = (ACPI_SUBTABLE_HEADER *)acpi_isop;
		i = 0;
		while (i < acpi_iso_cnt) {
			if (hp->Type == ACPI_MADT_TYPE_INTERRUPT_OVERRIDE) {
				isop = (ACPI_MADT_INTERRUPT_OVERRIDE *) hp;
				if (isop->Bus == 0 &&
				    isop->SourceIrq == irqno) {
					newirq = isop->GlobalIrq;
					intr_flag.intr_po = isop->IntiFlags &
					    ACPI_MADT_POLARITY_MASK;
					intr_flag.intr_el = (isop->IntiFlags &
					    ACPI_MADT_TRIGGER_MASK) >> 2;
					intr_flag.bustype = BUS_ISA;

					return (apix_intx_setup(dip, inum,
					    newirq, NULL, ispec, &intr_flag));
				}
				i++;
			}
			hp = (ACPI_SUBTABLE_HEADER *)(((char *)hp) +
			    hp->Length);
		}
	}
	intr_flag.intr_po = INTR_PO_ACTIVE_HIGH;
	intr_flag.intr_el = INTR_EL_EDGE;
	intr_flag.bustype = BUS_ISA;
	return (apix_intx_setup(dip, inum, irqno, NULL, ispec, &intr_flag));
}


/*
 * Setup IRQ table for pci devices. Return IRQ no or -1 on error
 */
static int
apix_intx_setup_pci(dev_info_t *dip, int inum, int bustype,
    struct intrspec *ispec)
{
	int busid, devid, pci_irq;
	ddi_acc_handle_t cfg_handle;
	uchar_t ipin;
	iflag_t intr_flag;
	struct apic_io_intr *intrp;

	if (acpica_get_bdf(dip, &busid, &devid, NULL) != 0)
		return (-1);

	if (busid == 0 && apic_pci_bus_total == 1)
		busid = (int)apic_single_pci_busid;

	if (pci_config_setup(dip, &cfg_handle) != DDI_SUCCESS)
		return (-1);
	ipin = pci_config_get8(cfg_handle, PCI_CONF_IPIN) - PCI_INTA;
	pci_config_teardown(&cfg_handle);

	if (apic_enable_acpi && !apic_use_acpi_madt_only) {	/* ACPI */
		if (apic_acpi_translate_pci_irq(dip, busid, devid,
		    ipin, &pci_irq, &intr_flag) != ACPI_PSM_SUCCESS)
			return (-1);

		intr_flag.bustype = (uchar_t)bustype;
		return (apix_intx_setup(dip, inum, pci_irq, NULL, ispec,
		    &intr_flag));
	}

	/* MP configuration table */
	pci_irq = ((devid & 0x1f) << 2) | (ipin & 0x3);
	if ((intrp = apic_find_io_intr_w_busid(pci_irq, busid)) == NULL) {
		pci_irq = apic_handle_pci_pci_bridge(dip, devid, ipin, &intrp);
		if (pci_irq == -1)
			return (-1);
	}

	return (apix_intx_setup(dip, inum, pci_irq, intrp, ispec, NULL));
}

/*
 * Translate and return IRQ no
 */
static int
apix_intx_xlate_irq(dev_info_t *dip, int inum, struct intrspec *ispec)
{
	int newirq, irqno = ispec->intrspec_vec;
	int parent_is_pci_or_pciex = 0, child_is_pciex = 0;
	int bustype = 0, dev_len;
	char dev_type[16];

	if (apic_defconf) {
		mutex_enter(&airq_mutex);
		goto defconf;
	}

	if ((dip == NULL) || (!apic_irq_translate && !apic_enable_acpi)) {
		mutex_enter(&airq_mutex);
		goto nonpci;
	}

	/*
	 * use ddi_getlongprop_buf() instead of ddi_prop_lookup_string()
	 * to avoid extra buffer allocation.
	 */
	dev_len = sizeof (dev_type);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, ddi_get_parent(dip),
	    DDI_PROP_DONTPASS, "device_type", (caddr_t)dev_type,
	    &dev_len) == DDI_PROP_SUCCESS) {
		if ((strcmp(dev_type, "pci") == 0) ||
		    (strcmp(dev_type, "pciex") == 0))
			parent_is_pci_or_pciex = 1;
	}

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "compatible", (caddr_t)dev_type,
	    &dev_len) == DDI_PROP_SUCCESS) {
		if (strstr(dev_type, "pciex"))
			child_is_pciex = 1;
	}

	mutex_enter(&airq_mutex);

	if (parent_is_pci_or_pciex) {
		bustype = child_is_pciex ? BUS_PCIE : BUS_PCI;
		newirq = apix_intx_setup_pci(dip, inum, bustype, ispec);
		if (newirq != -1)
			goto done;
		bustype = 0;
	} else if (strcmp(dev_type, "isa") == 0)
		bustype = BUS_ISA;
	else if (strcmp(dev_type, "eisa") == 0)
		bustype = BUS_EISA;

nonpci:
	newirq = apix_intx_setup_nonpci(dip, inum, bustype, ispec);
	if (newirq != -1)
		goto done;

defconf:
	newirq = apix_intx_setup(dip, inum, irqno, NULL, ispec, NULL);
	if (newirq == -1) {
		mutex_exit(&airq_mutex);
		return (-1);
	}
done:
	ASSERT(apic_irq_table[newirq]);
	mutex_exit(&airq_mutex);
	return (newirq);
}

static int
apix_intx_alloc_vector(dev_info_t *dip, int inum, struct intrspec *ispec)
{
	int irqno;
	apix_vector_t *vecp;

	if ((irqno = apix_intx_xlate_irq(dip, inum, ispec)) == -1)
		return (0);

	if ((vecp = apix_alloc_intx(dip, inum, irqno)) == NULL)
		return (0);

	DDI_INTR_IMPLDBG((CE_CONT, "apix_intx_alloc_vector: dip=0x%p name=%s "
	    "irqno=0x%x cpuid=%d vector=0x%x\n",
	    (void *)dip, ddi_driver_name(dip), irqno,
	    vecp->v_cpuid, vecp->v_vector));

	return (1);
}

/*
 * Return the vector number if the translated IRQ for this device
 * has a vector mapping setup. If no IRQ setup exists or no vector is
 * allocated to it then return 0.
 */
static apix_vector_t *
apix_intx_xlate_vector(dev_info_t *dip, int inum, struct intrspec *ispec)
{
	int irqno;
	apix_vector_t *vecp;

	/* get the IRQ number */
	if ((irqno = apix_intx_xlate_irq(dip, inum, ispec)) == -1)
		return (NULL);

	/* get the vector number if a vector is allocated to this irqno */
	vecp = apix_intx_get_vector(irqno);

	return (vecp);
}

/* stub function */
int
apix_loaded(void)
{
	return (apix_is_enabled);
}
