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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 * Copyright 2018 Joyent, Inc.
 */

/*
 * To understand how the pcplusmp module interacts with the interrupt subsystem
 * read the theory statement in uts/i86pc/os/intr.c.
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
#include <sys/apic.h>
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
#include <sys/hpet.h>
#include <sys/apic_common.h>
#include <sys/apic_timer.h>

/*
 *	Local Function Prototypes
 */
static void apic_init_intr(void);

/*
 *	standard MP entries
 */
static int	apic_probe(void);
static int	apic_getclkirq(int ipl);
static void	apic_init(void);
static void	apic_picinit(void);
static int	apic_post_cpu_start(void);
static int	apic_intr_enter(int ipl, int *vect);
static void	apic_setspl(int ipl);
static int	apic_addspl(int ipl, int vector, int min_ipl, int max_ipl);
static int	apic_delspl(int ipl, int vector, int min_ipl, int max_ipl);
static int	apic_disable_intr(processorid_t cpun);
static void	apic_enable_intr(processorid_t cpun);
static int		apic_get_ipivect(int ipl, int type);
static void	apic_post_cyclic_setup(void *arg);

#define	UCHAR_MAX	UINT8_MAX

/*
 * The following vector assignments influence the value of ipltopri and
 * vectortoipl. Note that vectors 0 - 0x1f are not used. We can program
 * idle to 0 and IPL 0 to 0xf to differentiate idle in case
 * we care to do so in future. Note some IPLs which are rarely used
 * will share the vector ranges and heavily used IPLs (5 and 6) have
 * a wide range.
 *
 * This array is used to initialize apic_ipls[] (in apic_init()).
 *
 *	IPL		Vector range.		as passed to intr_enter
 *	0		none.
 *	1,2,3		0x20-0x2f		0x0-0xf
 *	4		0x30-0x3f		0x10-0x1f
 *	5		0x40-0x5f		0x20-0x3f
 *	6		0x60-0x7f		0x40-0x5f
 *	7,8,9		0x80-0x8f		0x60-0x6f
 *	10		0x90-0x9f		0x70-0x7f
 *	11		0xa0-0xaf		0x80-0x8f
 *	...		...
 *	15		0xe0-0xef		0xc0-0xcf
 *	15		0xf0-0xff		0xd0-0xdf
 */
uchar_t apic_vectortoipl[APIC_AVAIL_VECTOR / APIC_VECTOR_PER_IPL] = {
	3, 4, 5, 5, 6, 6, 9, 10, 11, 12, 13, 14, 15, 15
};
	/*
	 * The ipl of an ISR at vector X is apic_vectortoipl[X>>4]
	 * NOTE that this is vector as passed into intr_enter which is
	 * programmed vector - 0x20 (APIC_BASE_VECT)
	 */

uchar_t	apic_ipltopri[MAXIPL + 1];	/* unix ipl to apic pri	*/
	/* The taskpri to be programmed into apic to mask given ipl */

/*
 * Correlation of the hardware vector to the IPL in use, initialized
 * from apic_vectortoipl[] in apic_init().  The final IPLs may not correlate
 * to the IPLs in apic_vectortoipl on some systems that share interrupt lines
 * connected to errata-stricken IOAPICs
 */
uchar_t apic_ipls[APIC_AVAIL_VECTOR];

/*
 * Patchable global variables.
 */
int	apic_enable_hwsoftint = 0;	/* 0 - disable, 1 - enable	*/
int	apic_enable_bind_log = 1;	/* 1 - display interrupt binding log */

/*
 *	Local static data
 */
static struct	psm_ops apic_ops = {
	apic_probe,

	apic_init,
	apic_picinit,
	apic_intr_enter,
	apic_intr_exit,
	apic_setspl,
	apic_addspl,
	apic_delspl,
	apic_disable_intr,
	apic_enable_intr,
	(int (*)(int))NULL,		/* psm_softlvl_to_irq */
	(void (*)(int))NULL,		/* psm_set_softintr */

	apic_set_idlecpu,
	apic_unset_idlecpu,

	apic_clkinit,
	apic_getclkirq,
	(void (*)(void))NULL,		/* psm_hrtimeinit */
	apic_gethrtime,

	apic_get_next_processorid,
	apic_cpu_start,
	apic_post_cpu_start,
	apic_shutdown,
	apic_get_ipivect,
	apic_send_ipi,

	(int (*)(dev_info_t *, int))NULL,	/* psm_translate_irq */
	(void (*)(int, char *))NULL,	/* psm_notify_error */
	(void (*)(int))NULL,		/* psm_notify_func */
	apic_timer_reprogram,
	apic_timer_enable,
	apic_timer_disable,
	apic_post_cyclic_setup,
	apic_preshutdown,
	apic_intr_ops,			/* Advanced DDI Interrupt framework */
	apic_state,			/* save, restore apic state for S3 */
	apic_cpu_ops,			/* CPU control interface. */

	apic_get_pir_ipivect,
	apic_send_pir_ipi,
};

struct psm_ops *psmops = &apic_ops;

static struct	psm_info apic_psm_info = {
	PSM_INFO_VER01_7,			/* version */
	PSM_OWN_EXCLUSIVE,			/* ownership */
	(struct psm_ops *)&apic_ops,		/* operation */
	APIC_PCPLUSMP_NAME,			/* machine name */
	"pcplusmp v1.4 compatible",
};

static void *apic_hdlp;

/* to gather intr data and redistribute */
static void apic_redistribute_compute(void);

/*
 *	This is the loadable module wrapper
 */

int
_init(void)
{
	if (apic_coarse_hrtime)
		apic_ops.psm_gethrtime = &apic_gettime;
	return (psm_mod_init(&apic_hdlp, &apic_psm_info));
}

int
_fini(void)
{
	return (psm_mod_fini(&apic_hdlp, &apic_psm_info));
}

int
_info(struct modinfo *modinfop)
{
	return (psm_mod_info(&apic_hdlp, &apic_psm_info, modinfop));
}

static int
apic_probe(void)
{
	/* check if apix is initialized */
	if (apix_enable && apix_loaded())
		return (PSM_FAILURE);

	/*
	 * Check whether x2APIC mode was activated by BIOS. We don't support
	 * that in pcplusmp as apix normally handles that.
	 */
	if (apic_local_mode() == LOCAL_X2APIC)
		return (PSM_FAILURE);

	/* continue using pcplusmp PSM */
	apix_enable = 0;

	return (apic_probe_common(apic_psm_info.p_mach_idstring));
}

static uchar_t
apic_xlate_vector_by_irq(uchar_t irq)
{
	if (apic_irq_table[irq] == NULL)
		return (0);

	return (apic_irq_table[irq]->airq_vector);
}

void
apic_init(void)
{
	int i;
	int	j = 1;

	psm_get_ioapicid = apic_get_ioapicid;
	psm_get_localapicid = apic_get_localapicid;
	psm_xlate_vector_by_irq = apic_xlate_vector_by_irq;

	apic_ipltopri[0] = APIC_VECTOR_PER_IPL; /* leave 0 for idle */
	for (i = 0; i < (APIC_AVAIL_VECTOR / APIC_VECTOR_PER_IPL); i++) {
		if ((i < ((APIC_AVAIL_VECTOR / APIC_VECTOR_PER_IPL) - 1)) &&
		    (apic_vectortoipl[i + 1] == apic_vectortoipl[i]))
			/* get to highest vector at the same ipl */
			continue;
		for (; j <= apic_vectortoipl[i]; j++) {
			apic_ipltopri[j] = (i << APIC_IPL_SHIFT) +
			    APIC_BASE_VECT;
		}
	}
	for (; j < MAXIPL + 1; j++)
		/* fill up any empty ipltopri slots */
		apic_ipltopri[j] = (i << APIC_IPL_SHIFT) + APIC_BASE_VECT;
	apic_init_common();

	apic_pir_vect = apic_get_ipivect(XC_CPUPOKE_PIL, -1);

#if !defined(__amd64)
	if (cpuid_have_cr8access(CPU))
		apic_have_32bit_cr8 = 1;
#endif
}

static void
apic_init_intr(void)
{
	processorid_t	cpun = psm_get_cpu_id();
	uint_t nlvt;
	uint32_t svr = AV_UNIT_ENABLE | APIC_SPUR_INTR;

	apic_reg_ops->apic_write_task_reg(APIC_MASK_ALL);

	ASSERT(apic_mode == LOCAL_APIC);

	/*
	 * We are running APIC in MMIO mode.
	 */
	if (apic_flat_model) {
		apic_reg_ops->apic_write(APIC_FORMAT_REG, APIC_FLAT_MODEL);
	} else {
		apic_reg_ops->apic_write(APIC_FORMAT_REG, APIC_CLUSTER_MODEL);
	}

	apic_reg_ops->apic_write(APIC_DEST_REG, AV_HIGH_ORDER >> cpun);

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
				int irq = apic_get_ipivect(ipl, -1);

				ASSERT(irq != -1);
				apic_cpcovf_vect =
				    apic_irq_table[irq]->airq_vector;
				ASSERT(apic_cpcovf_vect);
				(void) add_avintr(NULL, ipl,
				    (avfunc)kcpc_hw_overflow_intr,
				    "apic pcint", irq, NULL, NULL, NULL, NULL);
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
			int irq = apic_get_ipivect(ipl, -1);

			ASSERT(irq != -1);
			apic_errvect = apic_irq_table[irq]->airq_vector;
			ASSERT(apic_errvect);
			/*
			 * Not PSMI compliant, but we are going to merge
			 * with ON anyway
			 */
			(void) add_avintr((void *)NULL, ipl,
			    (avfunc)apic_error_intr, "apic error intr",
			    irq, NULL, NULL, NULL, NULL);
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
			int irq = apic_get_ipivect(ipl, -1);

			ASSERT(irq != -1);
			apic_cmci_vect = apic_irq_table[irq]->airq_vector;
			ASSERT(apic_cmci_vect);

			(void) add_avintr(NULL, ipl,
			    (avfunc)cmi_cmci_trap,
			    "apic cmci intr", irq, NULL, NULL, NULL, NULL);
		}
		apic_reg_ops->apic_write(APIC_CMCI_VECT, apic_cmci_vect);
	}
}

static void
apic_picinit(void)
{
	int i, j;
	uint_t isr;

	/*
	 * Initialize and enable interrupt remapping before apic
	 * hardware initialization
	 */
	apic_intrmap_init(apic_mode);

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
	    "pcplusmp NMI handler", (caddr_t)NULL))
		cmn_err(CE_WARN, "pcplusmp: Unable to add nmi handler");

	/*
	 * Check for directed-EOI capability in the local APIC.
	 */
	if (apic_directed_EOI_supported() == 1) {
		apic_set_directed_EOI_handler();
	}

	apic_init_intr();

	/* enable apic mode if imcr present */
	if (apic_imcrp) {
		outb(APIC_IMCR_P1, (uchar_t)APIC_IMCR_SELECT);
		outb(APIC_IMCR_P2, (uchar_t)APIC_IMCR_APIC);
	}

	ioapic_init_intr(IOAPIC_MASK);
}

#ifdef	DEBUG
void
apic_break(void)
{
}
#endif /* DEBUG */

/*
 * platform_intr_enter
 *
 *	Called at the beginning of the interrupt service routine to
 *	mask all level equal to and below the interrupt priority
 *	of the interrupting vector.  An EOI should be given to
 *	the interrupt controller to enable other HW interrupts.
 *
 *	Return -1 for spurious interrupts
 *
 */
/*ARGSUSED*/
static int
apic_intr_enter(int ipl, int *vectorp)
{
	uchar_t vector;
	int nipl;
	int irq;
	ulong_t iflag;
	apic_cpus_info_t *cpu_infop;

	/*
	 * The real vector delivered is (*vectorp + 0x20), but our caller
	 * subtracts 0x20 from the vector before passing it to us.
	 * (That's why APIC_BASE_VECT is 0x20.)
	 */
	vector = (uchar_t)*vectorp;

	/* if interrupted by the clock, increment apic_nsec_since_boot */
	if (vector == apic_clkvect) {
		if (!apic_oneshot) {
			/* NOTE: this is not MT aware */
			apic_hrtime_stamp++;
			apic_nsec_since_boot += apic_nsec_per_intr;
			apic_hrtime_stamp++;
			last_count_read = apic_hertz_count;
			apic_redistribute_compute();
		}

		/* We will avoid all the book keeping overhead for clock */
		nipl = apic_ipls[vector];

		*vectorp = apic_vector_to_irq[vector + APIC_BASE_VECT];

		apic_reg_ops->apic_write_task_reg(apic_ipltopri[nipl]);
		apic_reg_ops->apic_send_eoi(0);

		return (nipl);
	}

	cpu_infop = &apic_cpus[psm_get_cpu_id()];

	if (vector == (APIC_SPUR_INTR - APIC_BASE_VECT)) {
		cpu_infop->aci_spur_cnt++;
		return (APIC_INT_SPURIOUS);
	}

	/* Check if the vector we got is really what we need */
	if (apic_revector_pending) {
		/*
		 * Disable interrupts for the duration of
		 * the vector translation to prevent a self-race for
		 * the apic_revector_lock.  This cannot be done
		 * in apic_xlate_vector because it is recursive and
		 * we want the vector translation to be atomic with
		 * respect to other (higher-priority) interrupts.
		 */
		iflag = intr_clear();
		vector = apic_xlate_vector(vector + APIC_BASE_VECT) -
		    APIC_BASE_VECT;
		intr_restore(iflag);
	}

	nipl = apic_ipls[vector];
	*vectorp = irq = apic_vector_to_irq[vector + APIC_BASE_VECT];

	apic_reg_ops->apic_write_task_reg(apic_ipltopri[nipl]);

	cpu_infop->aci_current[nipl] = (uchar_t)irq;
	cpu_infop->aci_curipl = (uchar_t)nipl;
	cpu_infop->aci_ISR_in_progress |= 1 << nipl;

	/*
	 * apic_level_intr could have been assimilated into the irq struct.
	 * but, having it as a character array is more efficient in terms of
	 * cache usage. So, we leave it as is.
	 */
	if (!apic_level_intr[irq]) {
		apic_reg_ops->apic_send_eoi(0);
	}

#ifdef	DEBUG
	APIC_DEBUG_BUF_PUT(vector);
	APIC_DEBUG_BUF_PUT(irq);
	APIC_DEBUG_BUF_PUT(nipl);
	APIC_DEBUG_BUF_PUT(psm_get_cpu_id());
	if ((apic_stretch_interrupts) && (apic_stretch_ISR & (1 << nipl)))
		drv_usecwait(apic_stretch_interrupts);

	if (apic_break_on_cpu == psm_get_cpu_id())
		apic_break();
#endif /* DEBUG */
	return (nipl);
}

void
apic_intr_exit(int prev_ipl, int irq)
{
	apic_cpus_info_t *cpu_infop;

	apic_reg_ops->apic_write_task_reg(apic_ipltopri[prev_ipl]);

	cpu_infop = &apic_cpus[psm_get_cpu_id()];
	if (apic_level_intr[irq])
		apic_reg_ops->apic_send_eoi(irq);
	cpu_infop->aci_curipl = (uchar_t)prev_ipl;
	/* ISR above current pri could not be in progress */
	cpu_infop->aci_ISR_in_progress &= (2 << prev_ipl) - 1;
}

intr_exit_fn_t
psm_intr_exit_fn(void)
{
	return (apic_intr_exit);
}

/*
 * Mask all interrupts below or equal to the given IPL.
 */
static void
apic_setspl(int ipl)
{
	apic_reg_ops->apic_write_task_reg(apic_ipltopri[ipl]);

	/* interrupts at ipl above this cannot be in progress */
	apic_cpus[psm_get_cpu_id()].aci_ISR_in_progress &= (2 << ipl) - 1;
	/*
	 * this is a patch fix for the ALR QSMP P5 machine, so that interrupts
	 * have enough time to come in before the priority is raised again
	 * during the idle() loop.
	 */
	if (apic_setspl_delay)
		(void) apic_reg_ops->apic_get_pri();
}

/*ARGSUSED*/
static int
apic_addspl(int irqno, int ipl, int min_ipl, int max_ipl)
{
	return (apic_addspl_common(irqno, ipl, min_ipl, max_ipl));
}

static int
apic_delspl(int irqno, int ipl, int min_ipl, int max_ipl)
{
	return (apic_delspl_common(irqno, ipl, min_ipl,  max_ipl));
}

static int
apic_post_cpu_start(void)
{
	int cpun;
	static int cpus_started = 1;

	/* We know this CPU + BSP  started successfully. */
	cpus_started++;

	splx(ipltospl(LOCK_LEVEL));
	apic_init_intr();

	/*
	 * since some systems don't enable the internal cache on the non-boot
	 * cpus, so we have to enable them here
	 */
	setcr0(getcr0() & ~(CR0_CD | CR0_NW));

	APIC_AV_PENDING_SET();

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
 * type == -1 indicates it is an internal request. Do not change
 * resv_vector for these requests
 */
static int
apic_get_ipivect(int ipl, int type)
{
	uchar_t vector;
	int irq;

	if ((irq = apic_allocate_irq(APIC_VECTOR(ipl))) != -1) {
		if ((vector = apic_allocate_vector(ipl, irq, 1))) {
			apic_irq_table[irq]->airq_mps_intr_index =
			    RESERVE_INDEX;
			apic_irq_table[irq]->airq_vector = vector;
			if (type != -1) {
				apic_resv_vector[ipl] = vector;
			}
			return (irq);
		}
	}
	apic_error |= APIC_ERR_GET_IPIVECT_FAIL;
	return (-1);	/* shouldn't happen */
}

static int
apic_getclkirq(int ipl)
{
	int	irq;

	if ((irq = apic_get_ipivect(ipl, -1)) == -1)
		return (-1);
	/*
	 * Note the vector in apic_clkvect for per clock handling.
	 */
	apic_clkvect = apic_irq_table[irq]->airq_vector - APIC_BASE_VECT;
	APIC_VERBOSE_IOAPIC((CE_NOTE, "get_clkirq: vector = %x\n",
	    apic_clkvect));
	return (irq);
}

/*
 * Try and disable all interrupts. We just assign interrupts to other
 * processors based on policy. If any were bound by user request, we
 * let them continue and return failure. We do not bother to check
 * for cache affinity while rebinding.
 */

static int
apic_disable_intr(processorid_t cpun)
{
	int bind_cpu = 0, i, hardbound = 0;
	apic_irq_t *irq_ptr;
	ulong_t iflag;

	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	for (i = 0; i <= APIC_MAX_VECTOR; i++) {
		if (apic_reprogram_info[i].done == B_FALSE) {
			if (apic_reprogram_info[i].bindcpu == cpun) {
				/*
				 * CPU is busy -- it's the target of
				 * a pending reprogramming attempt
				 */
				lock_clear(&apic_ioapic_lock);
				intr_restore(iflag);
				return (PSM_FAILURE);
			}
		}
	}

	apic_cpus[cpun].aci_status &= ~APIC_CPU_INTR_ENABLE;

	apic_cpus[cpun].aci_curipl = 0;

	i = apic_min_device_irq;
	for (; i <= apic_max_device_irq; i++) {
		/*
		 * If there are bound interrupts on this cpu, then
		 * rebind them to other processors.
		 */
		if ((irq_ptr = apic_irq_table[i]) != NULL) {
			ASSERT((irq_ptr->airq_temp_cpu == IRQ_UNBOUND) ||
			    (irq_ptr->airq_temp_cpu == IRQ_UNINIT) ||
			    (apic_cpu_in_range(irq_ptr->airq_temp_cpu)));

			if (irq_ptr->airq_temp_cpu == (cpun | IRQ_USER_BOUND)) {
				hardbound = 1;
				continue;
			}

			if (irq_ptr->airq_temp_cpu == cpun) {
				do {
					bind_cpu =
					    apic_find_cpu(APIC_CPU_INTR_ENABLE);
				} while (apic_rebind_all(irq_ptr, bind_cpu));
			}
		}
	}

	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);

	if (hardbound) {
		cmn_err(CE_WARN, "Could not disable interrupts on %d"
		    "due to user bound interrupts", cpun);
		return (PSM_FAILURE);
	}
	else
		return (PSM_SUCCESS);
}

/*
 * Bind interrupts to the CPU's local APIC.
 * Interrupts should not be bound to a CPU's local APIC until the CPU
 * is ready to receive interrupts.
 */
static void
apic_enable_intr(processorid_t cpun)
{
	int	i;
	apic_irq_t *irq_ptr;
	ulong_t iflag;

	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	apic_cpus[cpun].aci_status |= APIC_CPU_INTR_ENABLE;

	i = apic_min_device_irq;
	for (i = apic_min_device_irq; i <= apic_max_device_irq; i++) {
		if ((irq_ptr = apic_irq_table[i]) != NULL) {
			if ((irq_ptr->airq_cpu & ~IRQ_USER_BOUND) == cpun) {
				(void) apic_rebind_all(irq_ptr,
				    irq_ptr->airq_cpu);
			}
		}
	}

	if (apic_cpus[cpun].aci_status & APIC_CPU_SUSPEND)
		apic_cpus[cpun].aci_status &= ~APIC_CPU_SUSPEND;

	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);
}

/*
 * If this module needs a periodic handler for the interrupt distribution, it
 * can be added here. The argument to the periodic handler is not currently
 * used, but is reserved for future.
 */
static void
apic_post_cyclic_setup(void *arg)
{
_NOTE(ARGUNUSED(arg))

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
	cyh.cyh_func = (void (*)(void *))apic_redistribute_compute;
	cyh.cyh_arg = NULL;
	cyh.cyh_level = CY_LOW_LEVEL;

	cyt.cyt_when = 0;
	cyt.cyt_interval = apic_redistribute_sample_interval;

	apic_cyclic_id = cyclic_add(&cyh, &cyt);
}

static void
apic_redistribute_compute(void)
{
	int	i, j, max_busy;

	if (apic_enable_dynamic_migration) {
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

				int	irq;
				apic_cpus[i].aci_busy++;
				irq = apic_cpus[i].aci_current[j];
				apic_irq_table[irq]->airq_busy++;
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
				if (apic_skipped_redistribute) {
					apic_cleanup_busy();
					apic_skipped_redistribute = 0;
				} else {
					apic_intr_redistribute();
				}
			} else
				apic_skipped_redistribute++;
		}
	}
}


/*
 * The following functions are in the platform specific file so that they
 * can be different functions depending on whether we are running on
 * bare metal or a hypervisor.
 */

/*
 * Check to make sure there are enough irq slots
 */
int
apic_check_free_irqs(int count)
{
	int i, avail;

	avail = 0;
	for (i = APIC_FIRST_FREE_IRQ; i < APIC_RESV_IRQ; i++) {
		if ((apic_irq_table[i] == NULL) ||
		    apic_irq_table[i]->airq_mps_intr_index == FREE_INDEX) {
			if (++avail >= count)
				return (PSM_SUCCESS);
		}
	}
	return (PSM_FAILURE);
}

/*
 * This function allocates "count" MSI vector(s) for the given "dip/pri/type"
 */
int
apic_alloc_msi_vectors(dev_info_t *dip, int inum, int count, int pri,
    int behavior)
{
	int	rcount, i;
	uchar_t	start, irqno;
	uint32_t cpu = 0;
	major_t	major;
	apic_irq_t	*irqptr;

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

	mutex_enter(&airq_mutex);

	for (start = 0; rcount > 0; rcount >>= 1) {
		if ((start = apic_find_multi_vectors(pri, rcount)) != 0 ||
		    behavior == DDI_INTR_ALLOC_STRICT)
			break;
	}

	if (start == 0) {
		/* no vector available */
		mutex_exit(&airq_mutex);
		return (0);
	}

	if (apic_check_free_irqs(rcount) == PSM_FAILURE) {
		/* not enough free irq slots available */
		mutex_exit(&airq_mutex);
		return (0);
	}

	major = (dip != NULL) ? ddi_driver_major(dip) : 0;
	for (i = 0; i < rcount; i++) {
		if ((irqno = apic_allocate_irq(apic_first_avail_irq)) ==
		    (uchar_t)-1) {
			/*
			 * shouldn't happen because of the
			 * apic_check_free_irqs() check earlier
			 */
			mutex_exit(&airq_mutex);
			DDI_INTR_IMPLDBG((CE_CONT, "apic_alloc_msi_vectors: "
			    "apic_allocate_irq failed\n"));
			return (i);
		}
		apic_max_device_irq = max(irqno, apic_max_device_irq);
		apic_min_device_irq = min(irqno, apic_min_device_irq);
		irqptr = apic_irq_table[irqno];
#ifdef	DEBUG
		if (apic_vector_to_irq[start + i] != APIC_RESV_IRQ)
			DDI_INTR_IMPLDBG((CE_CONT, "apic_alloc_msi_vectors: "
			    "apic_vector_to_irq is not APIC_RESV_IRQ\n"));
#endif
		apic_vector_to_irq[start + i] = (uchar_t)irqno;

		irqptr->airq_vector = (uchar_t)(start + i);
		irqptr->airq_ioapicindex = (uchar_t)inum;	/* start */
		irqptr->airq_intin_no = (uchar_t)rcount;
		ASSERT(pri >= 0 && pri <= UCHAR_MAX);
		irqptr->airq_ipl = (uchar_t)pri;
		irqptr->airq_vector = start + i;
		irqptr->airq_origirq = (uchar_t)(inum + i);
		irqptr->airq_share_id = 0;
		irqptr->airq_mps_intr_index = MSI_INDEX;
		irqptr->airq_dip = dip;
		irqptr->airq_major = major;
		if (i == 0) /* they all bound to the same cpu */
			cpu = irqptr->airq_cpu = apic_bind_intr(dip, irqno,
			    0xff, 0xff);
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
	int	rcount, i;
	major_t	major;

	mutex_enter(&airq_mutex);

	if ((rcount = apic_navail_vector(dip, pri)) > count)
		rcount = count;
	else if (rcount == 0 || (rcount < count &&
	    behavior == DDI_INTR_ALLOC_STRICT)) {
		rcount = 0;
		goto out;
	}

	if (apic_check_free_irqs(rcount) == PSM_FAILURE) {
		/* not enough free irq slots available */
		rcount = 0;
		goto out;
	}

	major = (dip != NULL) ? ddi_driver_major(dip) : 0;
	for (i = 0; i < rcount; i++) {
		uchar_t	vector, irqno;
		apic_irq_t	*irqptr;

		if ((irqno = apic_allocate_irq(apic_first_avail_irq)) ==
		    (uchar_t)-1) {
			/*
			 * shouldn't happen because of the
			 * apic_check_free_irqs() check earlier
			 */
			DDI_INTR_IMPLDBG((CE_CONT, "apic_alloc_msix_vectors: "
			    "apic_allocate_irq failed\n"));
			rcount = i;
			goto out;
		}
		if ((vector = apic_allocate_vector(pri, irqno, 1)) == 0) {
			/*
			 * shouldn't happen because of the
			 * apic_navail_vector() call earlier
			 */
			DDI_INTR_IMPLDBG((CE_CONT, "apic_alloc_msix_vectors: "
			    "apic_allocate_vector failed\n"));
			rcount = i;
			goto out;
		}
		apic_max_device_irq = max(irqno, apic_max_device_irq);
		apic_min_device_irq = min(irqno, apic_min_device_irq);
		irqptr = apic_irq_table[irqno];
		irqptr->airq_vector = (uchar_t)vector;
		ASSERT(pri >= 0 && pri <= UCHAR_MAX);
		irqptr->airq_ipl = (uchar_t)pri;
		irqptr->airq_origirq = (uchar_t)(inum + i);
		irqptr->airq_share_id = 0;
		irqptr->airq_mps_intr_index = MSIX_INDEX;
		irqptr->airq_dip = dip;
		irqptr->airq_major = major;
		irqptr->airq_cpu = apic_bind_intr(dip, irqno, 0xff, 0xff);
	}
out:
	mutex_exit(&airq_mutex);
	return (rcount);
}

/*
 * Allocate a free vector for irq at ipl. Takes care of merging of multiple
 * IPLs into a single APIC level as well as stretching some IPLs onto multiple
 * levels. APIC_HI_PRI_VECTS interrupts are reserved for high priority
 * requests and allocated only when pri is set.
 */
uchar_t
apic_allocate_vector(int ipl, int irq, int pri)
{
	int	lowest, highest, i;

	highest = apic_ipltopri[ipl] + APIC_VECTOR_MASK;
	lowest = apic_ipltopri[ipl - 1] + APIC_VECTOR_PER_IPL;

	if (highest < lowest) /* Both ipl and ipl - 1 map to same pri */
		lowest -= APIC_VECTOR_PER_IPL;

#ifdef	DEBUG
	if (apic_restrict_vector)	/* for testing shared interrupt logic */
		highest = lowest + apic_restrict_vector + APIC_HI_PRI_VECTS;
#endif /* DEBUG */
	if (pri == 0)
		highest -= APIC_HI_PRI_VECTS;

	for (i = lowest; i <= highest; i++) {
		if (APIC_CHECK_RESERVE_VECTORS(i))
			continue;
		if (apic_vector_to_irq[i] == APIC_RESV_IRQ) {
			apic_vector_to_irq[i] = (uchar_t)irq;
			ASSERT(i >= 0 && i <= UCHAR_MAX);
			return ((uchar_t)i);
		}
	}

	return (0);
}

/* Mark vector as not being used by any irq */
void
apic_free_vector(uchar_t vector)
{
	apic_vector_to_irq[vector] = APIC_RESV_IRQ;
}

/*
 * Call rebind to do the actual programming.
 * Must be called with interrupts disabled and apic_ioapic_lock held
 * 'p' is polymorphic -- if this function is called to process a deferred
 * reprogramming, p is of type 'struct ioapic_reprogram_data *', from which
 * the irq pointer is retrieved.  If not doing deferred reprogramming,
 * p is of the type 'apic_irq_t *'.
 *
 * apic_ioapic_lock must be held across this call, as it protects apic_rebind
 * and it protects apic_get_next_bind_cpu() from a race in which a CPU can be
 * taken offline after a cpu is selected, but before apic_rebind is called to
 * bind interrupts to it.
 */
int
apic_setup_io_intr(void *p, int irq, boolean_t deferred)
{
	apic_irq_t *irqptr;
	struct ioapic_reprogram_data *drep = NULL;
	int rv;

	if (deferred) {
		drep = (struct ioapic_reprogram_data *)p;
		ASSERT(drep != NULL);
		irqptr = drep->irqp;
	} else
		irqptr = (apic_irq_t *)p;

	ASSERT(irqptr != NULL);

	rv = apic_rebind(irqptr, apic_irq_table[irq]->airq_cpu, drep);
	if (rv) {
		/*
		 * CPU is not up or interrupts are disabled. Fall back to
		 * the first available CPU
		 */
		rv = apic_rebind(irqptr, apic_find_cpu(APIC_CPU_INTR_ENABLE),
		    drep);
	}

	return (rv);
}


uchar_t
apic_modify_vector(uchar_t vector, int irq)
{
	apic_vector_to_irq[vector] = (uchar_t)irq;
	return (vector);
}

char *
apic_get_apic_type(void)
{
	return (apic_psm_info.p_mach_idstring);
}

void
apic_switch_ipi_callback(boolean_t enter)
{
	ASSERT(enter == B_TRUE);
}

int
apic_detect_x2apic(void)
{
	return (0);
}

void
apic_enable_x2apic(void)
{
	cmn_err(CE_PANIC, "apic_enable_x2apic() called in pcplusmp");
}

void
x2apic_update_psm(void)
{
	cmn_err(CE_PANIC, "x2apic_update_psm() called in pcplusmp");
}
