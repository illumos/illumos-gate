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
#include <sys/inttypes.h>
#include <sys/cram.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/psm_common.h>
#include <sys/apic.h>
#include <sys/apic_common.h>
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
#include <sys/cpuvar.h>
#include <sys/rm_platter.h>
#include <sys/privregs.h>
#include <sys/cyclic.h>
#include <sys/note.h>
#include <sys/pci_intr_lib.h>
#include <sys/sunndi.h>
#include <sys/hpet.h>
#include <sys/clock.h>

/*
 * Part of mp_platfrom_common.c that's used only by pcplusmp & xpv_psm
 * but not apix.
 * These functions may be moved to xpv_psm later when apix and pcplusmp
 * are merged together
 */

/*
 *	Local Function Prototypes
 */
static void apic_mark_vector(uchar_t oldvector, uchar_t newvector);
static void apic_xlate_vector_free_timeout_handler(void *arg);
static int apic_check_stuck_interrupt(apic_irq_t *irq_ptr, int old_bind_cpu,
    int new_bind_cpu, int apicindex, int intin_no, int which_irq,
    struct ioapic_reprogram_data *drep);
static int apic_setup_irq_table(dev_info_t *dip, int irqno,
    struct apic_io_intr *intrp, struct intrspec *ispec, iflag_t *intr_flagp,
    int type);
static void apic_try_deferred_reprogram(int ipl, int vect);
static void delete_defer_repro_ent(int which_irq);
static void apic_ioapic_wait_pending_clear(int ioapicindex,
    int intin_no);

extern int apic_acpi_translate_pci_irq(dev_info_t *dip, int busid, int devid,
    int ipin, int *pci_irqp, iflag_t *intr_flagp);
extern int apic_handle_pci_pci_bridge(dev_info_t *idip, int child_devno,
    int child_ipin, struct apic_io_intr **intrp);
extern uchar_t acpi_find_ioapic(int irq);
extern struct apic_io_intr *apic_find_io_intr_w_busid(int irqno, int busid);
extern int apic_find_bus_id(int bustype);
extern int apic_find_intin(uchar_t ioapic, uchar_t intin);
extern void apic_record_rdt_entry(apic_irq_t *irqptr, int irq);

extern	int apic_sci_vect;
extern	iflag_t apic_sci_flags;
/* ACPI HPET interrupt configuration; -1 if HPET not used */
extern	int apic_hpet_vect;
extern	iflag_t apic_hpet_flags;
extern	int	apic_intr_policy;
extern	char *psm_name;

/*
 * number of bits per byte, from <sys/param.h>
 */
#define	UCHAR_MAX	UINT8_MAX

/* Max wait time (in repetitions) for flags to clear in an RDT entry. */
extern int apic_max_reps_clear_pending;

/* The irq # is implicit in the array index: */
struct ioapic_reprogram_data apic_reprogram_info[APIC_MAX_VECTOR+1];
/*
 * APIC_MAX_VECTOR + 1 is the maximum # of IRQs as well. ioapic_reprogram_info
 * is indexed by IRQ number, NOT by vector number.
 */

extern	int	apic_int_busy_mark;
extern	int	apic_int_free_mark;
extern	int	apic_diff_for_redistribution;
extern	int	apic_sample_factor_redistribution;
extern	int	apic_redist_cpu_skip;
extern	int	apic_num_imbalance;
extern	int	apic_num_rebind;

/* timeout for xlate_vector, mark_vector */
int	apic_revector_timeout = 16 * 10000; /* 160 millisec */

extern int	apic_defconf;
extern int	apic_irq_translate;

extern int	apic_use_acpi_madt_only;	/* 1=ONLY use MADT from ACPI */

extern	uchar_t	apic_io_vectbase[MAX_IO_APIC];

extern	boolean_t ioapic_mask_workaround[MAX_IO_APIC];

/*
 * First available slot to be used as IRQ index into the apic_irq_table
 * for those interrupts (like MSI/X) that don't have a physical IRQ.
 */
extern int apic_first_avail_irq;

/*
 * apic_defer_reprogram_lock ensures that only one processor is handling
 * deferred interrupt programming at *_intr_exit time.
 */
static	lock_t	apic_defer_reprogram_lock;

/*
 * The current number of deferred reprogrammings outstanding
 */
uint_t	apic_reprogram_outstanding = 0;

#ifdef DEBUG
/*
 * Counters that keep track of deferred reprogramming stats
 */
uint_t	apic_intr_deferrals = 0;
uint_t	apic_intr_deliver_timeouts = 0;
uint_t	apic_last_ditch_reprogram_failures = 0;
uint_t	apic_deferred_setup_failures = 0;
uint_t	apic_defer_repro_total_retries = 0;
uint_t	apic_defer_repro_successes = 0;
uint_t	apic_deferred_spurious_enters = 0;
#endif

extern	int	apic_io_max;
extern	struct apic_io_intr *apic_io_intrp;

uchar_t	apic_vector_to_irq[APIC_MAX_VECTOR+1];

extern	uint32_t	eisa_level_intr_mask;
	/* At least MSB will be set if EISA bus */

extern	int	apic_pci_bus_total;
extern	uchar_t	apic_single_pci_busid;

/*
 * Following declarations are for revectoring; used when ISRs at different
 * IPLs share an irq.
 */
static	lock_t	apic_revector_lock;
int	apic_revector_pending = 0;
static	uchar_t	*apic_oldvec_to_newvec;
static	uchar_t	*apic_newvec_to_oldvec;

/* ACPI Interrupt Source Override Structure ptr */
extern ACPI_MADT_INTERRUPT_OVERRIDE *acpi_isop;
extern int acpi_iso_cnt;

/*
 * Auto-configuration routines
 */

/*
 * Initialise vector->ipl and ipl->pri arrays. level_intr and irqtable
 * are also set to NULL. vector->irq is set to a value which cannot map
 * to a real irq to show that it is free.
 */
void
apic_init_common(void)
{
	int	i, j, indx;
	int	*iptr;

	/*
	 * Initialize apic_ipls from apic_vectortoipl.  This array is
	 * used in apic_intr_enter to determine the IPL to use for the
	 * corresponding vector.  On some systems, due to hardware errata
	 * and interrupt sharing, the IPL may not correspond to the IPL listed
	 * in apic_vectortoipl (see apic_addspl and apic_delspl).
	 */
	for (i = 0; i < (APIC_AVAIL_VECTOR / APIC_VECTOR_PER_IPL); i++) {
		indx = i * APIC_VECTOR_PER_IPL;

		for (j = 0; j < APIC_VECTOR_PER_IPL; j++, indx++)
			apic_ipls[indx] = apic_vectortoipl[i];
	}

	/* cpu 0 is always up (for now) */
	apic_cpus[0].aci_status = APIC_CPU_ONLINE | APIC_CPU_INTR_ENABLE;

	iptr = (int *)&apic_irq_table[0];
	for (i = 0; i <= APIC_MAX_VECTOR; i++) {
		apic_level_intr[i] = 0;
		*iptr++ = NULL;
		apic_vector_to_irq[i] = APIC_RESV_IRQ;

		/* These *must* be initted to B_TRUE! */
		apic_reprogram_info[i].done = B_TRUE;
		apic_reprogram_info[i].irqp = NULL;
		apic_reprogram_info[i].tries = 0;
		apic_reprogram_info[i].bindcpu = 0;
	}

	/*
	 * Allocate a dummy irq table entry for the reserved entry.
	 * This takes care of the race between removing an irq and
	 * clock detecting a CPU in that irq during interrupt load
	 * sampling.
	 */
	apic_irq_table[APIC_RESV_IRQ] =
	    kmem_zalloc(sizeof (apic_irq_t), KM_SLEEP);

	mutex_init(&airq_mutex, NULL, MUTEX_DEFAULT, NULL);
}

void
ioapic_init_intr(int mask_apic)
{
	int ioapic_ix;
	struct intrspec ispec;
	apic_irq_t *irqptr;
	int i, j;
	ulong_t iflag;

	LOCK_INIT_CLEAR(&apic_revector_lock);
	LOCK_INIT_CLEAR(&apic_defer_reprogram_lock);

	/* mask interrupt vectors */
	for (j = 0; j < apic_io_max && mask_apic; j++) {
		int intin_max;

		ioapic_ix = j;
		/* Bits 23-16 define the maximum redirection entries */
		intin_max = (ioapic_read(ioapic_ix, APIC_VERS_CMD) >> 16)
		    & 0xff;
		for (i = 0; i <= intin_max; i++)
			ioapic_write(ioapic_ix, APIC_RDT_CMD + 2 * i, AV_MASK);
	}

	/*
	 * Hack alert: deal with ACPI SCI interrupt chicken/egg here
	 */
	if (apic_sci_vect > 0) {
		/*
		 * acpica has already done add_avintr(); we just
		 * to finish the job by mimicing translate_irq()
		 *
		 * Fake up an intrspec and setup the tables
		 */
		ispec.intrspec_vec = apic_sci_vect;
		ispec.intrspec_pri = SCI_IPL;

		if (apic_setup_irq_table(NULL, apic_sci_vect, NULL,
		    &ispec, &apic_sci_flags, DDI_INTR_TYPE_FIXED) < 0) {
			cmn_err(CE_WARN, "!apic: SCI setup failed");
			return;
		}
		irqptr = apic_irq_table[apic_sci_vect];

		iflag = intr_clear();
		lock_set(&apic_ioapic_lock);

		/* Program I/O APIC */
		(void) apic_setup_io_intr(irqptr, apic_sci_vect, B_FALSE);

		lock_clear(&apic_ioapic_lock);
		intr_restore(iflag);

		irqptr->airq_share++;
	}

	/*
	 * Hack alert: deal with ACPI HPET interrupt chicken/egg here.
	 */
	if (apic_hpet_vect > 0) {
		/*
		 * hpet has already done add_avintr(); we just need
		 * to finish the job by mimicing translate_irq()
		 *
		 * Fake up an intrspec and setup the tables
		 */
		ispec.intrspec_vec = apic_hpet_vect;
		ispec.intrspec_pri = CBE_HIGH_PIL;

		if (apic_setup_irq_table(NULL, apic_hpet_vect, NULL,
		    &ispec, &apic_hpet_flags, DDI_INTR_TYPE_FIXED) < 0) {
			cmn_err(CE_WARN, "!apic: HPET setup failed");
			return;
		}
		irqptr = apic_irq_table[apic_hpet_vect];

		iflag = intr_clear();
		lock_set(&apic_ioapic_lock);

		/* Program I/O APIC */
		(void) apic_setup_io_intr(irqptr, apic_hpet_vect, B_FALSE);

		lock_clear(&apic_ioapic_lock);
		intr_restore(iflag);

		irqptr->airq_share++;
	}
}

/*
 * Add mask bits to disable interrupt vector from happening
 * at or above IPL. In addition, it should remove mask bits
 * to enable interrupt vectors below the given IPL.
 *
 * Both add and delspl are complicated by the fact that different interrupts
 * may share IRQs. This can happen in two ways.
 * 1. The same H/W line is shared by more than 1 device
 * 1a. with interrupts at different IPLs
 * 1b. with interrupts at same IPL
 * 2. We ran out of vectors at a given IPL and started sharing vectors.
 * 1b and 2 should be handled gracefully, except for the fact some ISRs
 * will get called often when no interrupt is pending for the device.
 * For 1a, we handle it at the higher IPL.
 */
/*ARGSUSED*/
int
apic_addspl_common(int irqno, int ipl, int min_ipl, int max_ipl)
{
	uchar_t vector;
	ulong_t iflag;
	apic_irq_t *irqptr, *irqheadptr;
	int irqindex;

	ASSERT(max_ipl <= UCHAR_MAX);
	irqindex = IRQINDEX(irqno);

	if ((irqindex == -1) || (!apic_irq_table[irqindex]))
		return (PSM_FAILURE);

	mutex_enter(&airq_mutex);
	irqptr = irqheadptr = apic_irq_table[irqindex];

	DDI_INTR_IMPLDBG((CE_CONT, "apic_addspl: dip=0x%p type=%d irqno=0x%x "
	    "vector=0x%x\n", (void *)irqptr->airq_dip,
	    irqptr->airq_mps_intr_index, irqno, irqptr->airq_vector));

	while (irqptr) {
		if (VIRTIRQ(irqindex, irqptr->airq_share_id) == irqno)
			break;
		irqptr = irqptr->airq_next;
	}
	irqptr->airq_share++;

	mutex_exit(&airq_mutex);

	/* return if it is not hardware interrupt */
	if (irqptr->airq_mps_intr_index == RESERVE_INDEX)
		return (PSM_SUCCESS);

	/* Or if there are more interupts at a higher IPL */
	if (ipl != max_ipl)
		return (PSM_SUCCESS);

	/*
	 * if apic_picinit() has not been called yet, just return.
	 * At the end of apic_picinit(), we will call setup_io_intr().
	 */

	if (!apic_picinit_called)
		return (PSM_SUCCESS);

	/*
	 * Upgrade vector if max_ipl is not earlier ipl. If we cannot allocate,
	 * return failure.
	 */
	if (irqptr->airq_ipl != max_ipl &&
	    !ioapic_mask_workaround[irqptr->airq_ioapicindex]) {

		vector = apic_allocate_vector(max_ipl, irqindex, 1);
		if (vector == 0) {
			irqptr->airq_share--;
			return (PSM_FAILURE);
		}
		irqptr = irqheadptr;
		apic_mark_vector(irqptr->airq_vector, vector);
		while (irqptr) {
			irqptr->airq_vector = vector;
			irqptr->airq_ipl = (uchar_t)max_ipl;
			/*
			 * reprogram irq being added and every one else
			 * who is not in the UNINIT state
			 */
			if ((VIRTIRQ(irqindex, irqptr->airq_share_id) ==
			    irqno) || (irqptr->airq_temp_cpu != IRQ_UNINIT)) {
				apic_record_rdt_entry(irqptr, irqindex);

				iflag = intr_clear();
				lock_set(&apic_ioapic_lock);

				(void) apic_setup_io_intr(irqptr, irqindex,
				    B_FALSE);

				lock_clear(&apic_ioapic_lock);
				intr_restore(iflag);
			}
			irqptr = irqptr->airq_next;
		}
		return (PSM_SUCCESS);

	} else if (irqptr->airq_ipl != max_ipl &&
	    ioapic_mask_workaround[irqptr->airq_ioapicindex]) {
		/*
		 * We cannot upgrade the vector, but we can change
		 * the IPL that this vector induces.
		 *
		 * Note that we subtract APIC_BASE_VECT from the vector
		 * here because this array is used in apic_intr_enter
		 * (no need to add APIC_BASE_VECT in that hot code
		 * path since we can do it in the rarely-executed path
		 * here).
		 */
		apic_ipls[irqptr->airq_vector - APIC_BASE_VECT] =
		    (uchar_t)max_ipl;

		irqptr = irqheadptr;
		while (irqptr) {
			irqptr->airq_ipl = (uchar_t)max_ipl;
			irqptr = irqptr->airq_next;
		}

		return (PSM_SUCCESS);
	}

	ASSERT(irqptr);

	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	(void) apic_setup_io_intr(irqptr, irqindex, B_FALSE);

	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);

	return (PSM_SUCCESS);
}

/*
 * Recompute mask bits for the given interrupt vector.
 * If there is no interrupt servicing routine for this
 * vector, this function should disable interrupt vector
 * from happening at all IPLs. If there are still
 * handlers using the given vector, this function should
 * disable the given vector from happening below the lowest
 * IPL of the remaining hadlers.
 */
/*ARGSUSED*/
int
apic_delspl_common(int irqno, int ipl, int min_ipl, int max_ipl)
{
	uchar_t vector;
	uint32_t bind_cpu;
	int intin, irqindex;
	int ioapic_ix;
	apic_irq_t	*irqptr, *preirqptr, *irqheadptr, *irqp;
	ulong_t iflag;

	mutex_enter(&airq_mutex);
	irqindex = IRQINDEX(irqno);
	irqptr = preirqptr = irqheadptr = apic_irq_table[irqindex];

	DDI_INTR_IMPLDBG((CE_CONT, "apic_delspl: dip=0x%p type=%d irqno=0x%x "
	    "vector=0x%x\n", (void *)irqptr->airq_dip,
	    irqptr->airq_mps_intr_index, irqno, irqptr->airq_vector));

	while (irqptr) {
		if (VIRTIRQ(irqindex, irqptr->airq_share_id) == irqno)
			break;
		preirqptr = irqptr;
		irqptr = irqptr->airq_next;
	}
	ASSERT(irqptr);

	irqptr->airq_share--;

	mutex_exit(&airq_mutex);

	/*
	 * If there are more interrupts at a higher IPL, we don't need
	 * to disable anything.
	 */
	if (ipl < max_ipl)
		return (PSM_SUCCESS);

	/* return if it is not hardware interrupt */
	if (irqptr->airq_mps_intr_index == RESERVE_INDEX)
		return (PSM_SUCCESS);

	if (!apic_picinit_called) {
		/*
		 * Clear irq_struct. If two devices shared an intpt
		 * line & 1 unloaded before picinit, we are hosed. But, then
		 * we hope the machine survive.
		 */
		irqptr->airq_mps_intr_index = FREE_INDEX;
		irqptr->airq_temp_cpu = IRQ_UNINIT;
		apic_free_vector(irqptr->airq_vector);
		return (PSM_SUCCESS);
	}
	/*
	 * Downgrade vector to new max_ipl if needed. If we cannot allocate,
	 * use old IPL. Not very elegant, but it should work.
	 */
	if ((irqptr->airq_ipl != max_ipl) && (max_ipl != PSM_INVALID_IPL) &&
	    !ioapic_mask_workaround[irqptr->airq_ioapicindex]) {
		apic_irq_t	*irqp;
		if ((vector = apic_allocate_vector(max_ipl, irqno, 1))) {
			apic_mark_vector(irqheadptr->airq_vector, vector);
			irqp = irqheadptr;
			while (irqp) {
				irqp->airq_vector = vector;
				irqp->airq_ipl = (uchar_t)max_ipl;
				if (irqp->airq_temp_cpu != IRQ_UNINIT) {
					apic_record_rdt_entry(irqp, irqindex);

					iflag = intr_clear();
					lock_set(&apic_ioapic_lock);

					(void) apic_setup_io_intr(irqp,
					    irqindex, B_FALSE);

					lock_clear(&apic_ioapic_lock);
					intr_restore(iflag);
				}
				irqp = irqp->airq_next;
			}
		}

	} else if (irqptr->airq_ipl != max_ipl &&
	    max_ipl != PSM_INVALID_IPL &&
	    ioapic_mask_workaround[irqptr->airq_ioapicindex]) {

	/*
	 * We cannot downgrade the IPL of the vector below the vector's
	 * hardware priority. If we did, it would be possible for a
	 * higher-priority hardware vector to interrupt a CPU running at an IPL
	 * lower than the hardware priority of the interrupting vector (but
	 * higher than the soft IPL of this IRQ). When this happens, we would
	 * then try to drop the IPL BELOW what it was (effectively dropping
	 * below base_spl) which would be potentially catastrophic.
	 *
	 * (e.g. Suppose the hardware vector associated with this IRQ is 0x40
	 * (hardware IPL of 4).  Further assume that the old IPL of this IRQ
	 * was 4, but the new IPL is 1.  If we forced vector 0x40 to result in
	 * an IPL of 1, it would be possible for the processor to be executing
	 * at IPL 3 and for an interrupt to come in on vector 0x40, interrupting
	 * the currently-executing ISR.  When apic_intr_enter consults
	 * apic_irqs[], it will return 1, bringing the IPL of the CPU down to 1
	 * so even though the processor was running at IPL 4, an IPL 1
	 * interrupt will have interrupted it, which must not happen)).
	 *
	 * Effectively, this means that the hardware priority corresponding to
	 * the IRQ's IPL (in apic_ipls[]) cannot be lower than the vector's
	 * hardware priority.
	 *
	 * (In the above example, then, after removal of the IPL 4 device's
	 * interrupt handler, the new IPL will continue to be 4 because the
	 * hardware priority that IPL 1 implies is lower than the hardware
	 * priority of the vector used.)
	 */
		/* apic_ipls is indexed by vector, starting at APIC_BASE_VECT */
		const int apic_ipls_index = irqptr->airq_vector -
		    APIC_BASE_VECT;
		const int vect_inherent_hwpri = irqptr->airq_vector >>
		    APIC_IPL_SHIFT;

		/*
		 * If there are still devices using this IRQ, determine the
		 * new ipl to use.
		 */
		if (irqptr->airq_share) {
			int vect_desired_hwpri, hwpri;

			ASSERT(max_ipl < MAXIPL);
			vect_desired_hwpri = apic_ipltopri[max_ipl] >>
			    APIC_IPL_SHIFT;

			/*
			 * If the desired IPL's hardware priority is lower
			 * than that of the vector, use the hardware priority
			 * of the vector to determine the new IPL.
			 */
			hwpri = (vect_desired_hwpri < vect_inherent_hwpri) ?
			    vect_inherent_hwpri : vect_desired_hwpri;

			/*
			 * Now, to get the right index for apic_vectortoipl,
			 * we need to subtract APIC_BASE_VECT from the
			 * hardware-vector-equivalent (in hwpri).  Since hwpri
			 * is already shifted, we shift APIC_BASE_VECT before
			 * doing the subtraction.
			 */
			hwpri -= (APIC_BASE_VECT >> APIC_IPL_SHIFT);

			ASSERT(hwpri >= 0);
			ASSERT(hwpri < MAXIPL);
			max_ipl = apic_vectortoipl[hwpri];
			apic_ipls[apic_ipls_index] = max_ipl;

			irqp = irqheadptr;
			while (irqp) {
				irqp->airq_ipl = (uchar_t)max_ipl;
				irqp = irqp->airq_next;
			}
		} else {
			/*
			 * No more devices on this IRQ, so reset this vector's
			 * element in apic_ipls to the original IPL for this
			 * vector
			 */
			apic_ipls[apic_ipls_index] =
			    apic_vectortoipl[vect_inherent_hwpri];
		}
	}

	/*
	 * If there are still active interrupts, we are done.
	 */
	if (irqptr->airq_share)
		return (PSM_SUCCESS);

	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	if (irqptr->airq_mps_intr_index == MSI_INDEX) {
		/*
		 * Disable the MSI vector
		 * Make sure we only disable on the last
		 * of the multi-MSI support
		 */
		if (i_ddi_intr_get_current_nenables(irqptr->airq_dip) == 1) {
			apic_pci_msi_disable_mode(irqptr->airq_dip,
			    DDI_INTR_TYPE_MSI);
		}
	} else if (irqptr->airq_mps_intr_index == MSIX_INDEX) {
		/*
		 * Disable the MSI-X vector
		 * needs to clear its mask and addr/data for each MSI-X
		 */
		apic_pci_msi_unconfigure(irqptr->airq_dip, DDI_INTR_TYPE_MSIX,
		    irqptr->airq_origirq);
		/*
		 * Make sure we only disable on the last MSI-X
		 */
		if (i_ddi_intr_get_current_nenables(irqptr->airq_dip) == 1) {
			apic_pci_msi_disable_mode(irqptr->airq_dip,
			    DDI_INTR_TYPE_MSIX);
		}
	} else {
		/*
		 * The assumption here is that this is safe, even for
		 * systems with IOAPICs that suffer from the hardware
		 * erratum because all devices have been quiesced before
		 * they unregister their interrupt handlers.  If that
		 * assumption turns out to be false, this mask operation
		 * can induce the same erratum result we're trying to
		 * avoid.
		 */
		ioapic_ix = irqptr->airq_ioapicindex;
		intin = irqptr->airq_intin_no;
		ioapic_write(ioapic_ix, APIC_RDT_CMD + 2 * intin, AV_MASK);
	}

	apic_vt_ops->apic_intrmap_free_entry(&irqptr->airq_intrmap_private);

	/*
	 * This irq entry is the only one in the chain.
	 */
	if (irqheadptr->airq_next == NULL) {
		ASSERT(irqheadptr == irqptr);
		bind_cpu = irqptr->airq_temp_cpu;
		if (((uint32_t)bind_cpu != IRQ_UNBOUND) &&
		    ((uint32_t)bind_cpu != IRQ_UNINIT)) {
			ASSERT(apic_cpu_in_range(bind_cpu));
			if (bind_cpu & IRQ_USER_BOUND) {
				/* If hardbound, temp_cpu == cpu */
				bind_cpu &= ~IRQ_USER_BOUND;
				apic_cpus[bind_cpu].aci_bound--;
			} else
				apic_cpus[bind_cpu].aci_temp_bound--;
		}
		irqptr->airq_temp_cpu = IRQ_UNINIT;
		irqptr->airq_mps_intr_index = FREE_INDEX;
		lock_clear(&apic_ioapic_lock);
		intr_restore(iflag);
		apic_free_vector(irqptr->airq_vector);
		return (PSM_SUCCESS);
	}

	/*
	 * If we get here, we are sharing the vector and there are more than
	 * one active irq entries in the chain.
	 */
	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);

	mutex_enter(&airq_mutex);
	/* Remove the irq entry from the chain */
	if (irqptr == irqheadptr) { /* The irq entry is at the head */
		apic_irq_table[irqindex] = irqptr->airq_next;
	} else {
		preirqptr->airq_next = irqptr->airq_next;
	}
	/* Free the irq entry */
	kmem_free(irqptr, sizeof (apic_irq_t));
	mutex_exit(&airq_mutex);

	return (PSM_SUCCESS);
}

/*
 * apic_introp_xlate() replaces apic_translate_irq() and is
 * called only from apic_intr_ops().  With the new ADII framework,
 * the priority can no longer be retrieved through i_ddi_get_intrspec().
 * It has to be passed in from the caller.
 *
 * Return value:
 *      Success: irqno for the given device
 *      Failure: -1
 */
int
apic_introp_xlate(dev_info_t *dip, struct intrspec *ispec, int type)
{
	char dev_type[16];
	int dev_len, pci_irq, newirq, bustype, devid, busid, i;
	int irqno = ispec->intrspec_vec;
	ddi_acc_handle_t cfg_handle;
	uchar_t ipin;
	struct apic_io_intr *intrp;
	iflag_t intr_flag;
	ACPI_SUBTABLE_HEADER	*hp;
	ACPI_MADT_INTERRUPT_OVERRIDE *isop;
	apic_irq_t *airqp;
	int parent_is_pci_or_pciex = 0;
	int child_is_pciex = 0;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_introp_xlate: dip=0x%p name=%s "
	    "type=%d irqno=0x%x\n", (void *)dip, ddi_get_name(dip), type,
	    irqno));

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

	if (DDI_INTR_IS_MSI_OR_MSIX(type)) {
		if ((airqp = apic_find_irq(dip, ispec, type)) != NULL) {
			airqp->airq_iflag.bustype =
			    child_is_pciex ? BUS_PCIE : BUS_PCI;
			return (apic_vector_to_irq[airqp->airq_vector]);
		}
		return (apic_setup_irq_table(dip, irqno, NULL, ispec,
		    NULL, type));
	}

	bustype = 0;

	/* check if we have already translated this irq */
	mutex_enter(&airq_mutex);
	newirq = apic_min_device_irq;
	for (; newirq <= apic_max_device_irq; newirq++) {
		airqp = apic_irq_table[newirq];
		while (airqp) {
			if ((airqp->airq_dip == dip) &&
			    (airqp->airq_origirq == irqno) &&
			    (airqp->airq_mps_intr_index != FREE_INDEX)) {

				mutex_exit(&airq_mutex);
				return (VIRTIRQ(newirq, airqp->airq_share_id));
			}
			airqp = airqp->airq_next;
		}
	}
	mutex_exit(&airq_mutex);

	if (apic_defconf)
		goto defconf;

	if ((dip == NULL) || (!apic_irq_translate && !apic_enable_acpi))
		goto nonpci;

	if (parent_is_pci_or_pciex) {
		/* pci device */
		if (acpica_get_bdf(dip, &busid, &devid, NULL) != 0)
			goto nonpci;
		if (busid == 0 && apic_pci_bus_total == 1)
			busid = (int)apic_single_pci_busid;

		if (pci_config_setup(dip, &cfg_handle) != DDI_SUCCESS)
			return (-1);
		ipin = pci_config_get8(cfg_handle, PCI_CONF_IPIN) - PCI_INTA;
		pci_config_teardown(&cfg_handle);
		if (apic_enable_acpi && !apic_use_acpi_madt_only) {
			if (apic_acpi_translate_pci_irq(dip, busid, devid,
			    ipin, &pci_irq, &intr_flag) != ACPI_PSM_SUCCESS)
				return (-1);

			intr_flag.bustype = child_is_pciex ? BUS_PCIE : BUS_PCI;
			return (apic_setup_irq_table(dip, pci_irq, NULL, ispec,
			    &intr_flag, type));
		} else {
			pci_irq = ((devid & 0x1f) << 2) | (ipin & 0x3);
			if ((intrp = apic_find_io_intr_w_busid(pci_irq, busid))
			    == NULL) {
				if ((pci_irq = apic_handle_pci_pci_bridge(dip,
				    devid, ipin, &intrp)) == -1)
					return (-1);
			}
			return (apic_setup_irq_table(dip, pci_irq, intrp, ispec,
			    NULL, type));
		}
	} else if (strcmp(dev_type, "isa") == 0)
		bustype = BUS_ISA;
	else if (strcmp(dev_type, "eisa") == 0)
		bustype = BUS_EISA;

nonpci:
	if (apic_enable_acpi && !apic_use_acpi_madt_only) {
		/* search iso entries first */
		if (acpi_iso_cnt != 0) {
			hp = (ACPI_SUBTABLE_HEADER *)acpi_isop;
			i = 0;
			while (i < acpi_iso_cnt) {
				if (hp->Type ==
				    ACPI_MADT_TYPE_INTERRUPT_OVERRIDE) {
					isop =
					    (ACPI_MADT_INTERRUPT_OVERRIDE *) hp;
					if (isop->Bus == 0 &&
					    isop->SourceIrq == irqno) {
						newirq = isop->GlobalIrq;
						intr_flag.intr_po =
						    isop->IntiFlags &
						    ACPI_MADT_POLARITY_MASK;
						intr_flag.intr_el =
						    (isop->IntiFlags &
						    ACPI_MADT_TRIGGER_MASK)
						    >> 2;
						intr_flag.bustype = BUS_ISA;

						return (apic_setup_irq_table(
						    dip, newirq, NULL, ispec,
						    &intr_flag, type));

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
		return (apic_setup_irq_table(dip, irqno, NULL, ispec,
		    &intr_flag, type));
	} else {
		if (bustype == 0)	/* not initialized */
			bustype = eisa_level_intr_mask ? BUS_EISA : BUS_ISA;
		for (i = 0; i < 2; i++) {
			if (((busid = apic_find_bus_id(bustype)) != -1) &&
			    ((intrp = apic_find_io_intr_w_busid(irqno, busid))
			    != NULL)) {
				if ((newirq = apic_setup_irq_table(dip, irqno,
				    intrp, ispec, NULL, type)) != -1) {
					return (newirq);
				}
				goto defconf;
			}
			bustype = (bustype == BUS_EISA) ? BUS_ISA : BUS_EISA;
		}
	}

/* MPS default configuration */
defconf:
	newirq = apic_setup_irq_table(dip, irqno, NULL, ispec, NULL, type);
	if (newirq == -1)
		return (-1);
	ASSERT(IRQINDEX(newirq) == irqno);
	ASSERT(apic_irq_table[irqno]);
	return (newirq);
}

/*
 * Attempt to share vector with someone else
 */
static int
apic_share_vector(int irqno, iflag_t *intr_flagp, short intr_index, int ipl,
	uchar_t ioapicindex, uchar_t ipin, apic_irq_t **irqptrp)
{
#ifdef DEBUG
	apic_irq_t *tmpirqp = NULL;
#endif /* DEBUG */
	apic_irq_t *irqptr, dummyirq;
	int	newirq, chosen_irq = -1, share = 127;
	int	lowest, highest, i;
	uchar_t	share_id;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_share_vector: irqno=0x%x "
	    "intr_index=0x%x ipl=0x%x\n", irqno, intr_index, ipl));

	highest = apic_ipltopri[ipl] + APIC_VECTOR_MASK;
	lowest = apic_ipltopri[ipl-1] + APIC_VECTOR_PER_IPL;

	if (highest < lowest) /* Both ipl and ipl-1 map to same pri */
		lowest -= APIC_VECTOR_PER_IPL;
	dummyirq.airq_mps_intr_index = intr_index;
	dummyirq.airq_ioapicindex = ioapicindex;
	dummyirq.airq_intin_no = ipin;
	if (intr_flagp)
		dummyirq.airq_iflag = *intr_flagp;
	apic_record_rdt_entry(&dummyirq, irqno);
	for (i = lowest; i <= highest; i++) {
		newirq = apic_vector_to_irq[i];
		if (newirq == APIC_RESV_IRQ)
			continue;
		irqptr = apic_irq_table[newirq];

		if ((dummyirq.airq_rdt_entry & 0xFF00) !=
		    (irqptr->airq_rdt_entry & 0xFF00))
			/* not compatible */
			continue;

		if (irqptr->airq_share < share) {
			share = irqptr->airq_share;
			chosen_irq = newirq;
		}
	}
	if (chosen_irq != -1) {
		/*
		 * Assign a share id which is free or which is larger
		 * than the largest one.
		 */
		share_id = 1;
		mutex_enter(&airq_mutex);
		irqptr = apic_irq_table[chosen_irq];
		while (irqptr) {
			if (irqptr->airq_mps_intr_index == FREE_INDEX) {
				share_id = irqptr->airq_share_id;
				break;
			}
			if (share_id <= irqptr->airq_share_id)
				share_id = irqptr->airq_share_id + 1;
#ifdef DEBUG
			tmpirqp = irqptr;
#endif /* DEBUG */
			irqptr = irqptr->airq_next;
		}
		if (!irqptr) {
			irqptr = kmem_zalloc(sizeof (apic_irq_t), KM_SLEEP);
			irqptr->airq_temp_cpu = IRQ_UNINIT;
			irqptr->airq_next =
			    apic_irq_table[chosen_irq]->airq_next;
			apic_irq_table[chosen_irq]->airq_next = irqptr;
#ifdef	DEBUG
			tmpirqp = apic_irq_table[chosen_irq];
#endif /* DEBUG */
		}
		irqptr->airq_mps_intr_index = intr_index;
		irqptr->airq_ioapicindex = ioapicindex;
		irqptr->airq_intin_no = ipin;
		if (intr_flagp)
			irqptr->airq_iflag = *intr_flagp;
		irqptr->airq_vector = apic_irq_table[chosen_irq]->airq_vector;
		irqptr->airq_share_id = share_id;
		apic_record_rdt_entry(irqptr, irqno);
		*irqptrp = irqptr;
#ifdef	DEBUG
		/* shuffle the pointers to test apic_delspl path */
		if (tmpirqp) {
			tmpirqp->airq_next = irqptr->airq_next;
			irqptr->airq_next = apic_irq_table[chosen_irq];
			apic_irq_table[chosen_irq] = irqptr;
		}
#endif /* DEBUG */
		mutex_exit(&airq_mutex);
		return (VIRTIRQ(chosen_irq, share_id));
	}
	return (-1);
}

/*
 * Allocate/Initialize the apic_irq_table[] entry for given irqno. If the entry
 * is used already, we will try to allocate a new irqno.
 *
 * Return value:
 *	Success: irqno
 *	Failure: -1
 */
static int
apic_setup_irq_table(dev_info_t *dip, int irqno, struct apic_io_intr *intrp,
    struct intrspec *ispec, iflag_t *intr_flagp, int type)
{
	int origirq = ispec->intrspec_vec;
	uchar_t ipl = ispec->intrspec_pri;
	int	newirq, intr_index;
	uchar_t	ipin, ioapic, ioapicindex, vector;
	apic_irq_t *irqptr;
	major_t	major;
	dev_info_t	*sdip;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_setup_irq_table: dip=0x%p type=%d "
	    "irqno=0x%x origirq=0x%x\n", (void *)dip, type, irqno, origirq));

	ASSERT(ispec != NULL);

	major =  (dip != NULL) ? ddi_driver_major(dip) : 0;

	if (DDI_INTR_IS_MSI_OR_MSIX(type)) {
		/* MSI/X doesn't need to setup ioapic stuffs */
		ioapicindex = 0xff;
		ioapic = 0xff;
		ipin = (uchar_t)0xff;
		intr_index = (type == DDI_INTR_TYPE_MSI) ? MSI_INDEX :
		    MSIX_INDEX;
		mutex_enter(&airq_mutex);
		if ((irqno = apic_allocate_irq(apic_first_avail_irq)) == -1) {
			mutex_exit(&airq_mutex);
			/* need an irq for MSI/X to index into autovect[] */
			cmn_err(CE_WARN, "No interrupt irq: %s instance %d",
			    ddi_get_name(dip), ddi_get_instance(dip));
			return (-1);
		}
		mutex_exit(&airq_mutex);

	} else if (intrp != NULL) {
		intr_index = (int)(intrp - apic_io_intrp);
		ioapic = intrp->intr_destid;
		ipin = intrp->intr_destintin;
		/* Find ioapicindex. If destid was ALL, we will exit with 0. */
		for (ioapicindex = apic_io_max - 1; ioapicindex; ioapicindex--)
			if (apic_io_id[ioapicindex] == ioapic)
				break;
		ASSERT((ioapic == apic_io_id[ioapicindex]) ||
		    (ioapic == INTR_ALL_APIC));

		/* check whether this intin# has been used by another irqno */
		if ((newirq = apic_find_intin(ioapicindex, ipin)) != -1) {
			return (newirq);
		}

	} else if (intr_flagp != NULL) {
		/* ACPI case */
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

	} else {
		/* default configuration */
		ioapicindex = 0;
		ioapic = apic_io_id[ioapicindex];
		ipin = (uchar_t)irqno;
		intr_index = DEFAULT_INDEX;
	}

	if (ispec == NULL) {
		APIC_VERBOSE_IOAPIC((CE_WARN, "No intrspec for irqno = %x\n",
		    irqno));
	} else if ((vector = apic_allocate_vector(ipl, irqno, 0)) == 0) {
		if ((newirq = apic_share_vector(irqno, intr_flagp, intr_index,
		    ipl, ioapicindex, ipin, &irqptr)) != -1) {
			irqptr->airq_ipl = ipl;
			irqptr->airq_origirq = (uchar_t)origirq;
			irqptr->airq_dip = dip;
			irqptr->airq_major = major;
			sdip = apic_irq_table[IRQINDEX(newirq)]->airq_dip;
			/* This is OK to do really */
			if (sdip == NULL) {
				cmn_err(CE_WARN, "Sharing vectors: %s"
				    " instance %d and SCI",
				    ddi_get_name(dip), ddi_get_instance(dip));
			} else {
				cmn_err(CE_WARN, "Sharing vectors: %s"
				    " instance %d and %s instance %d",
				    ddi_get_name(sdip), ddi_get_instance(sdip),
				    ddi_get_name(dip), ddi_get_instance(dip));
			}
			return (newirq);
		}
		/* try high priority allocation now  that share has failed */
		if ((vector = apic_allocate_vector(ipl, irqno, 1)) == 0) {
			cmn_err(CE_WARN, "No interrupt vector: %s instance %d",
			    ddi_get_name(dip), ddi_get_instance(dip));
			return (-1);
		}
	}

	mutex_enter(&airq_mutex);
	if (apic_irq_table[irqno] == NULL) {
		irqptr = kmem_zalloc(sizeof (apic_irq_t), KM_SLEEP);
		irqptr->airq_temp_cpu = IRQ_UNINIT;
		apic_irq_table[irqno] = irqptr;
	} else {
		irqptr = apic_irq_table[irqno];
		if (irqptr->airq_mps_intr_index != FREE_INDEX) {
			/*
			 * The slot is used by another irqno, so allocate
			 * a free irqno for this interrupt
			 */
			newirq = apic_allocate_irq(apic_first_avail_irq);
			if (newirq == -1) {
				mutex_exit(&airq_mutex);
				return (-1);
			}
			irqno = newirq;
			irqptr = apic_irq_table[irqno];
			if (irqptr == NULL) {
				irqptr = kmem_zalloc(sizeof (apic_irq_t),
				    KM_SLEEP);
				irqptr->airq_temp_cpu = IRQ_UNINIT;
				apic_irq_table[irqno] = irqptr;
			}
			vector = apic_modify_vector(vector, newirq);
		}
	}
	apic_max_device_irq = max(irqno, apic_max_device_irq);
	apic_min_device_irq = min(irqno, apic_min_device_irq);
	mutex_exit(&airq_mutex);
	irqptr->airq_ioapicindex = ioapicindex;
	irqptr->airq_intin_no = ipin;
	irqptr->airq_ipl = ipl;
	irqptr->airq_vector = vector;
	irqptr->airq_origirq = (uchar_t)origirq;
	irqptr->airq_share_id = 0;
	irqptr->airq_mps_intr_index = (short)intr_index;
	irqptr->airq_dip = dip;
	irqptr->airq_major = major;
	irqptr->airq_cpu = apic_bind_intr(dip, irqno, ioapic, ipin);
	if (intr_flagp)
		irqptr->airq_iflag = *intr_flagp;

	if (!DDI_INTR_IS_MSI_OR_MSIX(type)) {
		/* setup I/O APIC entry for non-MSI/X interrupts */
		apic_record_rdt_entry(irqptr, irqno);
	}
	return (irqno);
}

/*
 * return the cpu to which this intr should be bound.
 * Check properties or any other mechanism to see if user wants it
 * bound to a specific CPU. If so, return the cpu id with high bit set.
 * If not, use the policy to choose a cpu and return the id.
 */
uint32_t
apic_bind_intr(dev_info_t *dip, int irq, uchar_t ioapicid, uchar_t intin)
{
	int	instance, instno, prop_len, bind_cpu, count;
	uint_t	i, rc;
	uint32_t cpu;
	major_t	major;
	char	*name, *drv_name, *prop_val, *cptr;
	char	prop_name[32];
	ulong_t iflag;


	if (apic_intr_policy == INTR_LOWEST_PRIORITY)
		return (IRQ_UNBOUND);

	if (apic_nproc == 1)
		return (0);

	drv_name = NULL;
	rc = DDI_PROP_NOT_FOUND;
	major = (major_t)-1;
	if (dip != NULL) {
		name = ddi_get_name(dip);
		major = ddi_name_to_major(name);
		drv_name = ddi_major_to_name(major);
		instance = ddi_get_instance(dip);
		if (apic_intr_policy == INTR_ROUND_ROBIN_WITH_AFFINITY) {
			i = apic_min_device_irq;
			for (; i <= apic_max_device_irq; i++) {

				if ((i == irq) || (apic_irq_table[i] == NULL) ||
				    (apic_irq_table[i]->airq_mps_intr_index
				    == FREE_INDEX))
					continue;

				if ((apic_irq_table[i]->airq_major == major) &&
				    (!(apic_irq_table[i]->airq_cpu &
				    IRQ_USER_BOUND))) {

					cpu = apic_irq_table[i]->airq_cpu;

					cmn_err(CE_CONT,
					    "!%s: %s (%s) instance #%d "
					    "irq 0x%x vector 0x%x ioapic 0x%x "
					    "intin 0x%x is bound to cpu %d\n",
					    psm_name,
					    name, drv_name, instance, irq,
					    apic_irq_table[irq]->airq_vector,
					    ioapicid, intin, cpu);
					return (cpu);
				}
			}
		}
		/*
		 * search for "drvname"_intpt_bind_cpus property first, the
		 * syntax of the property should be "a[,b,c,...]" where
		 * instance 0 binds to cpu a, instance 1 binds to cpu b,
		 * instance 3 binds to cpu c...
		 * ddi_getlongprop() will search /option first, then /
		 * if "drvname"_intpt_bind_cpus doesn't exist, then find
		 * intpt_bind_cpus property.  The syntax is the same, and
		 * it applies to all the devices if its "drvname" specific
		 * property doesn't exist
		 */
		(void) strcpy(prop_name, drv_name);
		(void) strcat(prop_name, "_intpt_bind_cpus");
		rc = ddi_getlongprop(DDI_DEV_T_ANY, dip, 0, prop_name,
		    (caddr_t)&prop_val, &prop_len);
		if (rc != DDI_PROP_SUCCESS) {
			rc = ddi_getlongprop(DDI_DEV_T_ANY, dip, 0,
			    "intpt_bind_cpus", (caddr_t)&prop_val, &prop_len);
		}
	}
	if (rc == DDI_PROP_SUCCESS) {
		for (i = count = 0; i < (prop_len - 1); i++)
			if (prop_val[i] == ',')
				count++;
		if (prop_val[i-1] != ',')
			count++;
		/*
		 * if somehow the binding instances defined in the
		 * property are not enough for this instno., then
		 * reuse the pattern for the next instance until
		 * it reaches the requested instno
		 */
		instno = instance % count;
		i = 0;
		cptr = prop_val;
		while (i < instno)
			if (*cptr++ == ',')
				i++;
		bind_cpu = stoi(&cptr);
		kmem_free(prop_val, prop_len);
		/* if specific CPU is bogus, then default to next cpu */
		if (!apic_cpu_in_range(bind_cpu)) {
			cmn_err(CE_WARN, "%s: %s=%s: CPU %d not present",
			    psm_name, prop_name, prop_val, bind_cpu);
			rc = DDI_PROP_NOT_FOUND;
		} else {
			/* indicate that we are bound at user request */
			bind_cpu |= IRQ_USER_BOUND;
		}
		/*
		 * no need to check apic_cpus[].aci_status, if specific CPU is
		 * not up, then post_cpu_start will handle it.
		 */
	}
	if (rc != DDI_PROP_SUCCESS) {
		iflag = intr_clear();
		lock_set(&apic_ioapic_lock);
		bind_cpu = apic_get_next_bind_cpu();
		lock_clear(&apic_ioapic_lock);
		intr_restore(iflag);
	}

	if (drv_name != NULL)
		cmn_err(CE_CONT, "!%s: %s (%s) instance %d irq 0x%x "
		    "vector 0x%x ioapic 0x%x intin 0x%x is bound to cpu %d\n",
		    psm_name, name, drv_name, instance, irq,
		    apic_irq_table[irq]->airq_vector, ioapicid, intin,
		    bind_cpu & ~IRQ_USER_BOUND);
	else
		cmn_err(CE_CONT, "!%s: irq 0x%x "
		    "vector 0x%x ioapic 0x%x intin 0x%x is bound to cpu %d\n",
		    psm_name, irq, apic_irq_table[irq]->airq_vector, ioapicid,
		    intin, bind_cpu & ~IRQ_USER_BOUND);

	return ((uint32_t)bind_cpu);
}

/*
 * Mark vector as being in the process of being deleted. Interrupts
 * may still come in on some CPU. The moment an interrupt comes with
 * the new vector, we know we can free the old one. Called only from
 * addspl and delspl with interrupts disabled. Because an interrupt
 * can be shared, but no interrupt from either device may come in,
 * we also use a timeout mechanism, which we arbitrarily set to
 * apic_revector_timeout microseconds.
 */
static void
apic_mark_vector(uchar_t oldvector, uchar_t newvector)
{
	ulong_t iflag;

	iflag = intr_clear();
	lock_set(&apic_revector_lock);
	if (!apic_oldvec_to_newvec) {
		apic_oldvec_to_newvec =
		    kmem_zalloc(sizeof (newvector) * APIC_MAX_VECTOR * 2,
		    KM_NOSLEEP);

		if (!apic_oldvec_to_newvec) {
			/*
			 * This failure is not catastrophic.
			 * But, the oldvec will never be freed.
			 */
			apic_error |= APIC_ERR_MARK_VECTOR_FAIL;
			lock_clear(&apic_revector_lock);
			intr_restore(iflag);
			return;
		}
		apic_newvec_to_oldvec = &apic_oldvec_to_newvec[APIC_MAX_VECTOR];
	}

	/* See if we already did this for drivers which do double addintrs */
	if (apic_oldvec_to_newvec[oldvector] != newvector) {
		apic_oldvec_to_newvec[oldvector] = newvector;
		apic_newvec_to_oldvec[newvector] = oldvector;
		apic_revector_pending++;
	}
	lock_clear(&apic_revector_lock);
	intr_restore(iflag);
	(void) timeout(apic_xlate_vector_free_timeout_handler,
	    (void *)(uintptr_t)oldvector, drv_usectohz(apic_revector_timeout));
}

/*
 * xlate_vector is called from intr_enter if revector_pending is set.
 * It will xlate it if needed and mark the old vector as free.
 */
uchar_t
apic_xlate_vector(uchar_t vector)
{
	uchar_t	newvector, oldvector = 0;

	lock_set(&apic_revector_lock);
	/* Do we really need to do this ? */
	if (!apic_revector_pending) {
		lock_clear(&apic_revector_lock);
		return (vector);
	}
	if ((newvector = apic_oldvec_to_newvec[vector]) != 0)
		oldvector = vector;
	else {
		/*
		 * The incoming vector is new . See if a stale entry is
		 * remaining
		 */
		if ((oldvector = apic_newvec_to_oldvec[vector]) != 0)
			newvector = vector;
	}

	if (oldvector) {
		apic_revector_pending--;
		apic_oldvec_to_newvec[oldvector] = 0;
		apic_newvec_to_oldvec[newvector] = 0;
		apic_free_vector(oldvector);
		lock_clear(&apic_revector_lock);
		/* There could have been more than one reprogramming! */
		return (apic_xlate_vector(newvector));
	}
	lock_clear(&apic_revector_lock);
	return (vector);
}

void
apic_xlate_vector_free_timeout_handler(void *arg)
{
	ulong_t iflag;
	uchar_t oldvector, newvector;

	oldvector = (uchar_t)(uintptr_t)arg;
	iflag = intr_clear();
	lock_set(&apic_revector_lock);
	if ((newvector = apic_oldvec_to_newvec[oldvector]) != 0) {
		apic_free_vector(oldvector);
		apic_oldvec_to_newvec[oldvector] = 0;
		apic_newvec_to_oldvec[newvector] = 0;
		apic_revector_pending--;
	}

	lock_clear(&apic_revector_lock);
	intr_restore(iflag);
}

/*
 * Bind interrupt corresponding to irq_ptr to bind_cpu.
 * Must be called with interrupts disabled and apic_ioapic_lock held
 */
int
apic_rebind(apic_irq_t *irq_ptr, int bind_cpu,
    struct ioapic_reprogram_data *drep)
{
	int			ioapicindex, intin_no;
	uint32_t		airq_temp_cpu;
	apic_cpus_info_t	*cpu_infop;
	uint32_t		rdt_entry;
	int			which_irq;
	ioapic_rdt_t		irdt;

	which_irq = apic_vector_to_irq[irq_ptr->airq_vector];

	intin_no = irq_ptr->airq_intin_no;
	ioapicindex = irq_ptr->airq_ioapicindex;
	airq_temp_cpu = irq_ptr->airq_temp_cpu;
	if (airq_temp_cpu != IRQ_UNINIT && airq_temp_cpu != IRQ_UNBOUND) {
		if (airq_temp_cpu & IRQ_USER_BOUND)
			/* Mask off high bit so it can be used as array index */
			airq_temp_cpu &= ~IRQ_USER_BOUND;

		ASSERT(apic_cpu_in_range(airq_temp_cpu));
	}

	/*
	 * Can't bind to a CPU that's not accepting interrupts:
	 */
	cpu_infop = &apic_cpus[bind_cpu & ~IRQ_USER_BOUND];
	if (!(cpu_infop->aci_status & APIC_CPU_INTR_ENABLE))
		return (1);

	/*
	 * If we are about to change the interrupt vector for this interrupt,
	 * and this interrupt is level-triggered, attached to an IOAPIC,
	 * has been delivered to a CPU and that CPU has not handled it
	 * yet, we cannot reprogram the IOAPIC now.
	 */
	if (!APIC_IS_MSI_OR_MSIX_INDEX(irq_ptr->airq_mps_intr_index)) {

		rdt_entry = READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapicindex,
		    intin_no);

		if ((irq_ptr->airq_vector != RDT_VECTOR(rdt_entry)) &&
		    apic_check_stuck_interrupt(irq_ptr, airq_temp_cpu,
		    bind_cpu, ioapicindex, intin_no, which_irq, drep) != 0) {

			return (0);
		}

		/*
		 * NOTE: We do not unmask the RDT here, as an interrupt MAY
		 * still come in before we have a chance to reprogram it below.
		 * The reprogramming below will simultaneously change and
		 * unmask the RDT entry.
		 */

		if ((uint32_t)bind_cpu == IRQ_UNBOUND) {
			irdt.ir_lo =  AV_LDEST | AV_LOPRI |
			    irq_ptr->airq_rdt_entry;

			irdt.ir_hi = AV_TOALL >> APIC_ID_BIT_OFFSET;

			apic_vt_ops->apic_intrmap_alloc_entry(
			    &irq_ptr->airq_intrmap_private, NULL,
			    DDI_INTR_TYPE_FIXED, 1, ioapicindex);
			apic_vt_ops->apic_intrmap_map_entry(
			    irq_ptr->airq_intrmap_private, (void *)&irdt,
			    DDI_INTR_TYPE_FIXED, 1);
			apic_vt_ops->apic_intrmap_record_rdt(
			    irq_ptr->airq_intrmap_private, &irdt);

			/* Write the RDT entry -- no specific CPU binding */
			WRITE_IOAPIC_RDT_ENTRY_HIGH_DWORD(ioapicindex, intin_no,
			    irdt.ir_hi | AV_TOALL);

			if (airq_temp_cpu != IRQ_UNINIT && airq_temp_cpu !=
			    IRQ_UNBOUND)
				apic_cpus[airq_temp_cpu].aci_temp_bound--;

			/*
			 * Write the vector, trigger, and polarity portion of
			 * the RDT
			 */
			WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapicindex, intin_no,
			    irdt.ir_lo);

			irq_ptr->airq_temp_cpu = IRQ_UNBOUND;
			return (0);
		}
	}

	if (bind_cpu & IRQ_USER_BOUND) {
		cpu_infop->aci_bound++;
	} else {
		cpu_infop->aci_temp_bound++;
	}
	ASSERT(apic_cpu_in_range(bind_cpu));

	if ((airq_temp_cpu != IRQ_UNBOUND) && (airq_temp_cpu != IRQ_UNINIT)) {
		apic_cpus[airq_temp_cpu].aci_temp_bound--;
	}
	if (!APIC_IS_MSI_OR_MSIX_INDEX(irq_ptr->airq_mps_intr_index)) {

		irdt.ir_lo = AV_PDEST | AV_FIXED | irq_ptr->airq_rdt_entry;
		irdt.ir_hi = cpu_infop->aci_local_id;

		apic_vt_ops->apic_intrmap_alloc_entry(
		    &irq_ptr->airq_intrmap_private, NULL, DDI_INTR_TYPE_FIXED,
		    1, ioapicindex);
		apic_vt_ops->apic_intrmap_map_entry(
		    irq_ptr->airq_intrmap_private,
		    (void *)&irdt, DDI_INTR_TYPE_FIXED, 1);
		apic_vt_ops->apic_intrmap_record_rdt(
		    irq_ptr->airq_intrmap_private, &irdt);

		/* Write the RDT entry -- bind to a specific CPU: */
		WRITE_IOAPIC_RDT_ENTRY_HIGH_DWORD(ioapicindex, intin_no,
		    irdt.ir_hi);

		/* Write the vector, trigger, and polarity portion of the RDT */
		WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapicindex, intin_no,
		    irdt.ir_lo);

	} else {
		int type = (irq_ptr->airq_mps_intr_index == MSI_INDEX) ?
		    DDI_INTR_TYPE_MSI : DDI_INTR_TYPE_MSIX;
		if (type == DDI_INTR_TYPE_MSI) {
			if (irq_ptr->airq_ioapicindex ==
			    irq_ptr->airq_origirq) {
				/* first one */
				DDI_INTR_IMPLDBG((CE_CONT, "apic_rebind: call "
				    "apic_pci_msi_enable_vector\n"));
				apic_pci_msi_enable_vector(irq_ptr,
				    type, which_irq, irq_ptr->airq_vector,
				    irq_ptr->airq_intin_no,
				    cpu_infop->aci_local_id);
			}
			if ((irq_ptr->airq_ioapicindex +
			    irq_ptr->airq_intin_no - 1) ==
			    irq_ptr->airq_origirq) { /* last one */
				DDI_INTR_IMPLDBG((CE_CONT, "apic_rebind: call "
				    "apic_pci_msi_enable_mode\n"));
				apic_pci_msi_enable_mode(irq_ptr->airq_dip,
				    type, which_irq);
			}
		} else { /* MSI-X */
			apic_pci_msi_enable_vector(irq_ptr, type,
			    irq_ptr->airq_origirq, irq_ptr->airq_vector, 1,
			    cpu_infop->aci_local_id);
			apic_pci_msi_enable_mode(irq_ptr->airq_dip, type,
			    irq_ptr->airq_origirq);
		}
	}
	irq_ptr->airq_temp_cpu = (uint32_t)bind_cpu;
	apic_redist_cpu_skip &= ~(1 << (bind_cpu & ~IRQ_USER_BOUND));
	return (0);
}

static void
apic_last_ditch_clear_remote_irr(int ioapic_ix, int intin_no)
{
	if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix, intin_no)
	    & AV_REMOTE_IRR) != 0) {
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

		/*
		 * If the bit's STILL set, this interrupt may
		 * be hosed.
		 */
		if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
		    intin_no) & AV_REMOTE_IRR) != 0) {

			prom_printf("%s: Remote IRR still "
			    "not clear for IOAPIC %d intin %d.\n"
			    "\tInterrupts to this pin may cease "
			    "functioning.\n", psm_name, ioapic_ix,
			    intin_no);
#ifdef DEBUG
			apic_last_ditch_reprogram_failures++;
#endif
		}
	}
}

/*
 * This function is protected by apic_ioapic_lock coupled with the
 * fact that interrupts are disabled.
 */
static void
delete_defer_repro_ent(int which_irq)
{
	ASSERT(which_irq >= 0);
	ASSERT(which_irq <= 255);
	ASSERT(LOCK_HELD(&apic_ioapic_lock));

	if (apic_reprogram_info[which_irq].done)
		return;

	apic_reprogram_info[which_irq].done = B_TRUE;

#ifdef DEBUG
	apic_defer_repro_total_retries +=
	    apic_reprogram_info[which_irq].tries;

	apic_defer_repro_successes++;
#endif

	if (--apic_reprogram_outstanding == 0) {

		setlvlx = psm_intr_exit_fn();
	}
}


/*
 * Interrupts must be disabled during this function to prevent
 * self-deadlock.  Interrupts are disabled because this function
 * is called from apic_check_stuck_interrupt(), which is called
 * from apic_rebind(), which requires its caller to disable interrupts.
 */
static void
add_defer_repro_ent(apic_irq_t *irq_ptr, int which_irq, int new_bind_cpu)
{
	ASSERT(which_irq >= 0);
	ASSERT(which_irq <= 255);
	ASSERT(!interrupts_enabled());

	/*
	 * On the off-chance that there's already a deferred
	 * reprogramming on this irq, check, and if so, just update the
	 * CPU and irq pointer to which the interrupt is targeted, then return.
	 */
	if (!apic_reprogram_info[which_irq].done) {
		apic_reprogram_info[which_irq].bindcpu = new_bind_cpu;
		apic_reprogram_info[which_irq].irqp = irq_ptr;
		return;
	}

	apic_reprogram_info[which_irq].irqp = irq_ptr;
	apic_reprogram_info[which_irq].bindcpu = new_bind_cpu;
	apic_reprogram_info[which_irq].tries = 0;
	/*
	 * This must be the last thing set, since we're not
	 * grabbing any locks, apic_try_deferred_reprogram() will
	 * make its decision about using this entry iff done
	 * is false.
	 */
	apic_reprogram_info[which_irq].done = B_FALSE;

	/*
	 * If there were previously no deferred reprogrammings, change
	 * setlvlx to call apic_try_deferred_reprogram()
	 */
	if (++apic_reprogram_outstanding == 1) {

		setlvlx = apic_try_deferred_reprogram;
	}
}

static void
apic_try_deferred_reprogram(int prev_ipl, int irq)
{
	int reproirq;
	ulong_t iflag;
	struct ioapic_reprogram_data *drep;

	(*psm_intr_exit_fn())(prev_ipl, irq);

	if (!lock_try(&apic_defer_reprogram_lock)) {
		return;
	}

	/*
	 * Acquire the apic_ioapic_lock so that any other operations that
	 * may affect the apic_reprogram_info state are serialized.
	 * It's still possible for the last deferred reprogramming to clear
	 * between the time we entered this function and the time we get to
	 * the for loop below.  In that case, *setlvlx will have been set
	 * back to *_intr_exit and drep will be NULL. (There's no way to
	 * stop that from happening -- we would need to grab a lock before
	 * calling *setlvlx, which is neither realistic nor prudent).
	 */
	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	/*
	 * For each deferred RDT entry, try to reprogram it now.  Note that
	 * there is no lock acquisition to read apic_reprogram_info because
	 * '.done' is set only after the other fields in the structure are set.
	 */

	drep = NULL;
	for (reproirq = 0; reproirq <= APIC_MAX_VECTOR; reproirq++) {
		if (apic_reprogram_info[reproirq].done == B_FALSE) {
			drep = &apic_reprogram_info[reproirq];
			break;
		}
	}

	/*
	 * Either we found a deferred action to perform, or
	 * we entered this function spuriously, after *setlvlx
	 * was restored to point to *_intr_exit.  Any other
	 * permutation is invalid.
	 */
	ASSERT(drep != NULL || *setlvlx == psm_intr_exit_fn());

	/*
	 * Though we can't really do anything about errors
	 * at this point, keep track of them for reporting.
	 * Note that it is very possible for apic_setup_io_intr
	 * to re-register this very timeout if the Remote IRR bit
	 * has not yet cleared.
	 */

#ifdef DEBUG
	if (drep != NULL) {
		if (apic_setup_io_intr(drep, reproirq, B_TRUE) != 0) {
			apic_deferred_setup_failures++;
		}
	} else {
		apic_deferred_spurious_enters++;
	}
#else
	if (drep != NULL)
		(void) apic_setup_io_intr(drep, reproirq, B_TRUE);
#endif

	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);

	lock_clear(&apic_defer_reprogram_lock);
}

static void
apic_ioapic_wait_pending_clear(int ioapic_ix, int intin_no)
{
	int waited;

	/*
	 * Wait for the delivery pending bit to clear.
	 */
	if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix, intin_no) &
	    (AV_LEVEL|AV_PENDING)) == (AV_LEVEL|AV_PENDING)) {

		/*
		 * If we're still waiting on the delivery of this interrupt,
		 * continue to wait here until it is delivered (this should be
		 * a very small amount of time, but include a timeout just in
		 * case).
		 */
		for (waited = 0; waited < apic_max_reps_clear_pending;
		    waited++) {
			if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
			    intin_no) & AV_PENDING) == 0) {
				break;
			}
		}
	}
}


/*
 * Checks to see if the IOAPIC interrupt entry specified has its Remote IRR
 * bit set.  Calls functions that modify the function that setlvlx points to,
 * so that the reprogramming can be retried very shortly.
 *
 * This function will mask the RDT entry if the interrupt is level-triggered.
 * (The caller is responsible for unmasking the RDT entry.)
 *
 * Returns non-zero if the caller should defer IOAPIC reprogramming.
 */
static int
apic_check_stuck_interrupt(apic_irq_t *irq_ptr, int old_bind_cpu,
    int new_bind_cpu, int ioapic_ix, int intin_no, int which_irq,
    struct ioapic_reprogram_data *drep)
{
	int32_t			rdt_entry;
	int			waited;
	int			reps = 0;

	/*
	 * Wait for the delivery pending bit to clear.
	 */
	do {
		++reps;

		apic_ioapic_wait_pending_clear(ioapic_ix, intin_no);

		/*
		 * Mask the RDT entry, but only if it's a level-triggered
		 * interrupt
		 */
		rdt_entry = READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
		    intin_no);
		if ((rdt_entry & (AV_LEVEL|AV_MASK)) == AV_LEVEL) {

			/* Mask it */
			WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix, intin_no,
			    AV_MASK | rdt_entry);
		}

		if ((rdt_entry & AV_LEVEL) == AV_LEVEL) {
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
			if ((rdt_entry & AV_PENDING) &&
			    (reps < apic_max_reps_clear_pending)) {
				/* Unmask it */
				WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
				    intin_no, rdt_entry & ~AV_MASK);
			}
		}

	} while ((rdt_entry & AV_PENDING) &&
	    (reps < apic_max_reps_clear_pending));

#ifdef DEBUG
		if (rdt_entry & AV_PENDING)
			apic_intr_deliver_timeouts++;
#endif

	/*
	 * If the remote IRR bit is set, then the interrupt has been sent
	 * to a CPU for processing.  We have no choice but to wait for
	 * that CPU to process the interrupt, at which point the remote IRR
	 * bit will be cleared.
	 */
	if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix, intin_no) &
	    (AV_LEVEL|AV_REMOTE_IRR)) == (AV_LEVEL|AV_REMOTE_IRR)) {

		/*
		 * If the CPU that this RDT is bound to is NOT the current
		 * CPU, wait until that CPU handles the interrupt and ACKs
		 * it.  If this interrupt is not bound to any CPU (that is,
		 * if it's bound to the logical destination of "anyone"), it
		 * may have been delivered to the current CPU so handle that
		 * case by deferring the reprogramming (below).
		 */
		if ((old_bind_cpu != IRQ_UNBOUND) &&
		    (old_bind_cpu != IRQ_UNINIT) &&
		    (old_bind_cpu != psm_get_cpu_id())) {
			for (waited = 0; waited < apic_max_reps_clear_pending;
			    waited++) {
				if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
				    intin_no) & AV_REMOTE_IRR) == 0) {

					delete_defer_repro_ent(which_irq);

					/* Remote IRR has cleared! */
					return (0);
				}
			}
		}

		/*
		 * If we waited and the Remote IRR bit is still not cleared,
		 * AND if we've invoked the timeout APIC_REPROGRAM_MAX_TIMEOUTS
		 * times for this interrupt, try the last-ditch workaround:
		 */
		if (drep && drep->tries >= APIC_REPROGRAM_MAX_TRIES) {

			apic_last_ditch_clear_remote_irr(ioapic_ix, intin_no);

			/* Mark this one as reprogrammed: */
			delete_defer_repro_ent(which_irq);

			return (0);
		} else {
#ifdef DEBUG
			apic_intr_deferrals++;
#endif

			/*
			 * If waiting for the Remote IRR bit (above) didn't
			 * allow it to clear, defer the reprogramming.
			 * Add a new deferred-programming entry if the
			 * caller passed a NULL one (and update the existing one
			 * in case anything changed).
			 */
			add_defer_repro_ent(irq_ptr, which_irq, new_bind_cpu);
			if (drep)
				drep->tries++;

			/* Inform caller to defer IOAPIC programming: */
			return (1);
		}

	}

	/* Remote IRR is clear */
	delete_defer_repro_ent(which_irq);

	return (0);
}

/*
 * Called to migrate all interrupts at an irq to another cpu.
 * Must be called with interrupts disabled and apic_ioapic_lock held
 */
int
apic_rebind_all(apic_irq_t *irq_ptr, int bind_cpu)
{
	apic_irq_t	*irqptr = irq_ptr;
	int		retval = 0;

	while (irqptr) {
		if (irqptr->airq_temp_cpu != IRQ_UNINIT)
			retval |= apic_rebind(irqptr, bind_cpu, NULL);
		irqptr = irqptr->airq_next;
	}

	return (retval);
}

/*
 * apic_intr_redistribute does all the messy computations for identifying
 * which interrupt to move to which CPU. Currently we do just one interrupt
 * at a time. This reduces the time we spent doing all this within clock
 * interrupt. When it is done in idle, we could do more than 1.
 * First we find the most busy and the most free CPU (time in ISR only)
 * skipping those CPUs that has been identified as being ineligible (cpu_skip)
 * Then we look for IRQs which are closest to the difference between the
 * most busy CPU and the average ISR load. We try to find one whose load
 * is less than difference.If none exists, then we chose one larger than the
 * difference, provided it does not make the most idle CPU worse than the
 * most busy one. In the end, we clear all the busy fields for CPUs. For
 * IRQs, they are cleared as they are scanned.
 */
void
apic_intr_redistribute(void)
{
	int busiest_cpu, most_free_cpu;
	int cpu_free, cpu_busy, max_busy, min_busy;
	int min_free, diff;
	int average_busy, cpus_online;
	int i, busy;
	ulong_t iflag;
	apic_cpus_info_t *cpu_infop;
	apic_irq_t *min_busy_irq = NULL;
	apic_irq_t *max_busy_irq = NULL;

	busiest_cpu = most_free_cpu = -1;
	cpu_free = cpu_busy = max_busy = average_busy = 0;
	min_free = apic_sample_factor_redistribution;
	cpus_online = 0;
	/*
	 * Below we will check for CPU_INTR_ENABLE, bound, temp_bound, temp_cpu
	 * without ioapic_lock. That is OK as we are just doing statistical
	 * sampling anyway and any inaccuracy now will get corrected next time
	 * The call to rebind which actually changes things will make sure
	 * we are consistent.
	 */
	for (i = 0; i < apic_nproc; i++) {
		if (apic_cpu_in_range(i) &&
		    !(apic_redist_cpu_skip & (1 << i)) &&
		    (apic_cpus[i].aci_status & APIC_CPU_INTR_ENABLE)) {

			cpu_infop = &apic_cpus[i];
			/*
			 * If no unbound interrupts or only 1 total on this
			 * CPU, skip
			 */
			if (!cpu_infop->aci_temp_bound ||
			    (cpu_infop->aci_bound + cpu_infop->aci_temp_bound)
			    == 1) {
				apic_redist_cpu_skip |= 1 << i;
				continue;
			}

			busy = cpu_infop->aci_busy;
			average_busy += busy;
			cpus_online++;
			if (max_busy < busy) {
				max_busy = busy;
				busiest_cpu = i;
			}
			if (min_free > busy) {
				min_free = busy;
				most_free_cpu = i;
			}
			if (busy > apic_int_busy_mark) {
				cpu_busy |= 1 << i;
			} else {
				if (busy < apic_int_free_mark)
					cpu_free |= 1 << i;
			}
		}
	}
	if ((cpu_busy && cpu_free) ||
	    (max_busy >= (min_free + apic_diff_for_redistribution))) {

		apic_num_imbalance++;
#ifdef	DEBUG
		if (apic_verbose & APIC_VERBOSE_IOAPIC_FLAG) {
			prom_printf(
			    "redistribute busy=%x free=%x max=%x min=%x",
			    cpu_busy, cpu_free, max_busy, min_free);
		}
#endif /* DEBUG */


		average_busy /= cpus_online;

		diff = max_busy - average_busy;
		min_busy = max_busy; /* start with the max possible value */
		max_busy = 0;
		min_busy_irq = max_busy_irq = NULL;
		i = apic_min_device_irq;
		for (; i <= apic_max_device_irq; i++) {
			apic_irq_t *irq_ptr;
			/* Change to linked list per CPU ? */
			if ((irq_ptr = apic_irq_table[i]) == NULL)
				continue;
			/* Check for irq_busy & decide which one to move */
			/* Also zero them for next round */
			if ((irq_ptr->airq_temp_cpu == busiest_cpu) &&
			    irq_ptr->airq_busy) {
				if (irq_ptr->airq_busy < diff) {
					/*
					 * Check for least busy CPU,
					 * best fit or what ?
					 */
					if (max_busy < irq_ptr->airq_busy) {
						/*
						 * Most busy within the
						 * required differential
						 */
						max_busy = irq_ptr->airq_busy;
						max_busy_irq = irq_ptr;
					}
				} else {
					if (min_busy > irq_ptr->airq_busy) {
						/*
						 * least busy, but more than
						 * the reqd diff
						 */
						if (min_busy <
						    (diff + average_busy -
						    min_free)) {
							/*
							 * Making sure new cpu
							 * will not end up
							 * worse
							 */
							min_busy =
							    irq_ptr->airq_busy;

							min_busy_irq = irq_ptr;
						}
					}
				}
			}
			irq_ptr->airq_busy = 0;
		}

		if (max_busy_irq != NULL) {
#ifdef	DEBUG
			if (apic_verbose & APIC_VERBOSE_IOAPIC_FLAG) {
				prom_printf("rebinding %x to %x",
				    max_busy_irq->airq_vector, most_free_cpu);
			}
#endif /* DEBUG */
			iflag = intr_clear();
			if (lock_try(&apic_ioapic_lock)) {
				if (apic_rebind_all(max_busy_irq,
				    most_free_cpu) == 0) {
					/* Make change permenant */
					max_busy_irq->airq_cpu =
					    (uint32_t)most_free_cpu;
				}
				lock_clear(&apic_ioapic_lock);
			}
			intr_restore(iflag);

		} else if (min_busy_irq != NULL) {
#ifdef	DEBUG
			if (apic_verbose & APIC_VERBOSE_IOAPIC_FLAG) {
				prom_printf("rebinding %x to %x",
				    min_busy_irq->airq_vector, most_free_cpu);
			}
#endif /* DEBUG */

			iflag = intr_clear();
			if (lock_try(&apic_ioapic_lock)) {
				if (apic_rebind_all(min_busy_irq,
				    most_free_cpu) == 0) {
					/* Make change permenant */
					min_busy_irq->airq_cpu =
					    (uint32_t)most_free_cpu;
				}
				lock_clear(&apic_ioapic_lock);
			}
			intr_restore(iflag);

		} else {
			if (cpu_busy != (1 << busiest_cpu)) {
				apic_redist_cpu_skip |= 1 << busiest_cpu;
				/*
				 * We leave cpu_skip set so that next time we
				 * can choose another cpu
				 */
			}
		}
		apic_num_rebind++;
	} else {
		/*
		 * found nothing. Could be that we skipped over valid CPUs
		 * or we have balanced everything. If we had a variable
		 * ticks_for_redistribution, it could be increased here.
		 * apic_int_busy, int_free etc would also need to be
		 * changed.
		 */
		if (apic_redist_cpu_skip)
			apic_redist_cpu_skip = 0;
	}
	for (i = 0; i < apic_nproc; i++) {
		if (apic_cpu_in_range(i)) {
			apic_cpus[i].aci_busy = 0;
		}
	}
}

void
apic_cleanup_busy(void)
{
	int i;
	apic_irq_t *irq_ptr;

	for (i = 0; i < apic_nproc; i++) {
		if (apic_cpu_in_range(i)) {
			apic_cpus[i].aci_busy = 0;
		}
	}

	for (i = apic_min_device_irq; i <= apic_max_device_irq; i++) {
		if ((irq_ptr = apic_irq_table[i]) != NULL)
			irq_ptr->airq_busy = 0;
	}
}
