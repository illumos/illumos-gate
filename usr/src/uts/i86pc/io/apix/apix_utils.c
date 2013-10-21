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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2013 Pluribus Networks, Inc.
 */

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
#include <sys/dditypes.h>
#include <sys/sunddi.h>
#include <sys/x_call.h>
#include <sys/reboot.h>
#include <sys/apix.h>

static int apix_get_avail_vector_oncpu(uint32_t, int, int);
static apix_vector_t *apix_init_vector(processorid_t, uchar_t);
static void apix_cleanup_vector(apix_vector_t *);
static void apix_insert_av(apix_vector_t *, void *, avfunc, caddr_t, caddr_t,
    uint64_t *, int, dev_info_t *);
static void apix_remove_av(apix_vector_t *, struct autovec *);
static void apix_clear_dev_map(dev_info_t *, int, int);
static boolean_t apix_is_cpu_enabled(processorid_t);
static void apix_wait_till_seen(processorid_t, int);

#define	GET_INTR_INUM(ihdlp)		\
	(((ihdlp) != NULL) ? ((ddi_intr_handle_impl_t *)(ihdlp))->ih_inum : 0)

apix_rebind_info_t apix_rebindinfo = {0, 0, 0, NULL, 0, NULL};

/*
 * Allocate IPI
 *
 * Return vector number or 0 on error
 */
uchar_t
apix_alloc_ipi(int ipl)
{
	apix_vector_t *vecp;
	uchar_t vector;
	int cpun;
	int nproc;

	APIX_ENTER_CPU_LOCK(0);

	vector = apix_get_avail_vector_oncpu(0, APIX_IPI_MIN, APIX_IPI_MAX);
	if (vector == 0) {
		APIX_LEAVE_CPU_LOCK(0);
		cmn_err(CE_WARN, "apix: no available IPI\n");
		apic_error |= APIC_ERR_GET_IPIVECT_FAIL;
		return (0);
	}

	nproc = max(apic_nproc, apic_max_nproc);
	for (cpun = 0; cpun < nproc; cpun++) {
		vecp = xv_vector(cpun, vector);
		if (vecp == NULL) {
			vecp = kmem_zalloc(sizeof (apix_vector_t), KM_NOSLEEP);
			if (vecp == NULL) {
				cmn_err(CE_WARN, "apix: No memory for ipi");
				goto fail;
			}
			xv_vector(cpun, vector) = vecp;
		}
		vecp->v_state = APIX_STATE_ALLOCED;
		vecp->v_type = APIX_TYPE_IPI;
		vecp->v_cpuid = vecp->v_bound_cpuid = cpun;
		vecp->v_vector = vector;
		vecp->v_pri = ipl;
	}
	APIX_LEAVE_CPU_LOCK(0);
	return (vector);

fail:
	while (--cpun >= 0)
		apix_cleanup_vector(xv_vector(cpun, vector));
	APIX_LEAVE_CPU_LOCK(0);
	return (0);
}

/*
 * Add IPI service routine
 */
static int
apix_add_ipi(int ipl, avfunc xxintr, char *name, int vector,
    caddr_t arg1, caddr_t arg2)
{
	int cpun;
	apix_vector_t *vecp;
	int nproc;

	ASSERT(vector >= APIX_IPI_MIN && vector <= APIX_IPI_MAX);

	nproc = max(apic_nproc, apic_max_nproc);
	for (cpun = 0; cpun < nproc; cpun++) {
		APIX_ENTER_CPU_LOCK(cpun);
		vecp = xv_vector(cpun, vector);
		apix_insert_av(vecp, NULL, xxintr, arg1, arg2, NULL, ipl, NULL);
		vecp->v_state = APIX_STATE_ENABLED;
		APIX_LEAVE_CPU_LOCK(cpun);
	}

	APIC_VERBOSE(IPI, (CE_CONT, "apix: add ipi for %s, vector %x "
	    "ipl %x\n", name, vector, ipl));

	return (1);
}

/*
 * Find and return first free vector in range (start, end)
 */
static int
apix_get_avail_vector_oncpu(uint32_t cpuid, int start, int end)
{
	int i;
	apix_impl_t *apixp = apixs[cpuid];

	for (i = start; i <= end; i++) {
		if (APIC_CHECK_RESERVE_VECTORS(i))
			continue;
		if (IS_VECT_FREE(apixp->x_vectbl[i]))
			return (i);
	}

	return (0);
}

/*
 * Allocate a vector on specified cpu
 *
 * Return NULL on error
 */
static apix_vector_t *
apix_alloc_vector_oncpu(uint32_t cpuid, dev_info_t *dip, int inum, int type)
{
	processorid_t tocpu = cpuid & ~IRQ_USER_BOUND;
	apix_vector_t *vecp;
	int vector;

	ASSERT(APIX_CPU_LOCK_HELD(tocpu));

	/* find free vector */
	vector = apix_get_avail_vector_oncpu(tocpu, APIX_AVINTR_MIN,
	    APIX_AVINTR_MAX);
	if (vector == 0)
		return (NULL);

	vecp = apix_init_vector(tocpu, vector);
	vecp->v_type = (ushort_t)type;
	vecp->v_inum = inum;
	vecp->v_flags = (cpuid & IRQ_USER_BOUND) ? APIX_VECT_USER_BOUND : 0;

	if (dip != NULL)
		apix_set_dev_map(vecp, dip, inum);

	return (vecp);
}

/*
 * Allocates "count" contiguous MSI vectors starting at the proper alignment.
 * Caller needs to make sure that count has to be power of 2 and should not
 * be < 1.
 *
 * Return first vector number
 */
apix_vector_t *
apix_alloc_nvectors_oncpu(uint32_t cpuid, dev_info_t *dip, int inum,
    int count, int type)
{
	int i, msibits, start = 0, navail = 0;
	apix_vector_t *vecp, *startp = NULL;
	processorid_t tocpu = cpuid & ~IRQ_USER_BOUND;
	uint_t flags;

	ASSERT(APIX_CPU_LOCK_HELD(tocpu));

	/*
	 * msibits is the no. of lower order message data bits for the
	 * allocated MSI vectors and is used to calculate the aligned
	 * starting vector
	 */
	msibits = count - 1;

	/* It has to be contiguous */
	for (i = APIX_AVINTR_MIN; i <= APIX_AVINTR_MAX; i++) {
		if (!IS_VECT_FREE(xv_vector(tocpu, i)))
			continue;

		/*
		 * starting vector has to be aligned accordingly for
		 * multiple MSIs
		 */
		if (msibits)
			i = (i + msibits) & ~msibits;

		for (navail = 0, start = i; i <= APIX_AVINTR_MAX; i++) {
			if (!IS_VECT_FREE(xv_vector(tocpu, i)))
				break;
			if (APIC_CHECK_RESERVE_VECTORS(i))
				break;
			if (++navail == count)
				goto done;
		}
	}

	return (NULL);

done:
	flags = (cpuid & IRQ_USER_BOUND) ? APIX_VECT_USER_BOUND : 0;

	for (i = 0; i < count; i++) {
		if ((vecp = apix_init_vector(tocpu, start + i)) == NULL)
			goto fail;

		vecp->v_type = (ushort_t)type;
		vecp->v_inum = inum + i;
		vecp->v_flags = flags;

		if (dip != NULL)
			apix_set_dev_map(vecp, dip, inum + i);

		if (i == 0)
			startp = vecp;
	}

	return (startp);

fail:
	while (i-- > 0) {	/* Free allocated vectors */
		vecp = xv_vector(tocpu, start + i);
		apix_clear_dev_map(dip, inum + i, type);
		apix_cleanup_vector(vecp);
	}
	return (NULL);
}

#define	APIX_WRITE_MSI_DATA(_hdl, _cap, _ctrl, _v)\
do {\
	if ((_ctrl) & PCI_MSI_64BIT_MASK)\
		pci_config_put16((_hdl), (_cap) + PCI_MSI_64BIT_DATA, (_v));\
	else\
		pci_config_put16((_hdl), (_cap) + PCI_MSI_32BIT_DATA, (_v));\
_NOTE(CONSTCOND)} while (0)

static void
apix_pci_msi_enable_vector(apix_vector_t *vecp, dev_info_t *dip, int type,
    int inum, int count, uchar_t vector, int target_apic_id)
{
	uint64_t		msi_addr, msi_data;
	ushort_t		msi_ctrl;
	int			i, cap_ptr = i_ddi_get_msi_msix_cap_ptr(dip);
	ddi_acc_handle_t	handle = i_ddi_get_pci_config_handle(dip);
	msi_regs_t		msi_regs;
	void			*intrmap_tbl[PCI_MSI_MAX_INTRS];

	DDI_INTR_IMPLDBG((CE_CONT, "apix_pci_msi_enable_vector: dip=0x%p\n"
	    "\tdriver = %s, inum=0x%x vector=0x%x apicid=0x%x\n", (void *)dip,
	    ddi_driver_name(dip), inum, vector, target_apic_id));

	ASSERT((handle != NULL) && (cap_ptr != 0));

	msi_regs.mr_data = vector;
	msi_regs.mr_addr = target_apic_id;

	for (i = 0; i < count; i++)
		intrmap_tbl[i] = xv_intrmap_private(vecp->v_cpuid, vector + i);
	apic_vt_ops->apic_intrmap_alloc_entry(intrmap_tbl, dip, type,
	    count, 0xff);
	for (i = 0; i < count; i++)
		xv_intrmap_private(vecp->v_cpuid, vector + i) = intrmap_tbl[i];

	apic_vt_ops->apic_intrmap_map_entry(vecp->v_intrmap_private,
	    (void *)&msi_regs, type, count);
	apic_vt_ops->apic_intrmap_record_msi(vecp->v_intrmap_private,
	    &msi_regs);

	/* MSI Address */
	msi_addr = msi_regs.mr_addr;

	/* MSI Data: MSI is edge triggered according to spec */
	msi_data = msi_regs.mr_data;

	DDI_INTR_IMPLDBG((CE_CONT, "apix_pci_msi_enable_vector: addr=0x%lx "
	    "data=0x%lx\n", (long)msi_addr, (long)msi_data));

	if (type == APIX_TYPE_MSI) {
		msi_ctrl = pci_config_get16(handle, cap_ptr + PCI_MSI_CTRL);

		/* Set the bits to inform how many MSIs are enabled */
		msi_ctrl |= ((highbit(count) - 1) << PCI_MSI_MME_SHIFT);
		pci_config_put16(handle, cap_ptr + PCI_MSI_CTRL, msi_ctrl);

		if ((vecp->v_flags & APIX_VECT_MASKABLE) == 0)
			APIX_WRITE_MSI_DATA(handle, cap_ptr, msi_ctrl,
			    APIX_RESV_VECTOR);

		pci_config_put32(handle,
		    cap_ptr + PCI_MSI_ADDR_OFFSET, msi_addr);
		if (msi_ctrl &  PCI_MSI_64BIT_MASK)
			pci_config_put32(handle,
			    cap_ptr + PCI_MSI_ADDR_OFFSET + 4, msi_addr >> 32);

		APIX_WRITE_MSI_DATA(handle, cap_ptr, msi_ctrl, msi_data);
	} else if (type == APIX_TYPE_MSIX) {
		uintptr_t	off;
		ddi_intr_msix_t	*msix_p = i_ddi_get_msix(dip);

		/* Offset into the "inum"th entry in the MSI-X table */
		off = (uintptr_t)msix_p->msix_tbl_addr +
		    (inum * PCI_MSIX_VECTOR_SIZE);

		ddi_put32(msix_p->msix_tbl_hdl,
		    (uint32_t *)(off + PCI_MSIX_DATA_OFFSET), msi_data);
		ddi_put32(msix_p->msix_tbl_hdl,
		    (uint32_t *)(off + PCI_MSIX_LOWER_ADDR_OFFSET), msi_addr);
		ddi_put32(msix_p->msix_tbl_hdl,
		    (uint32_t *)(off + PCI_MSIX_UPPER_ADDR_OFFSET),
		    msi_addr >> 32);
	}
}

static void
apix_pci_msi_enable_mode(dev_info_t *dip, int type, int inum)
{
	ushort_t		msi_ctrl;
	int			cap_ptr = i_ddi_get_msi_msix_cap_ptr(dip);
	ddi_acc_handle_t	handle = i_ddi_get_pci_config_handle(dip);

	ASSERT((handle != NULL) && (cap_ptr != 0));

	if (type == APIX_TYPE_MSI) {
		msi_ctrl = pci_config_get16(handle, cap_ptr + PCI_MSI_CTRL);
		if ((msi_ctrl & PCI_MSI_ENABLE_BIT))
			return;

		msi_ctrl |= PCI_MSI_ENABLE_BIT;
		pci_config_put16(handle, cap_ptr + PCI_MSI_CTRL, msi_ctrl);

	} else if (type == DDI_INTR_TYPE_MSIX) {
		uintptr_t	off;
		uint32_t	mask;
		ddi_intr_msix_t	*msix_p;

		msix_p = i_ddi_get_msix(dip);

		/* Offset into "inum"th entry in the MSI-X table & clear mask */
		off = (uintptr_t)msix_p->msix_tbl_addr + (inum *
		    PCI_MSIX_VECTOR_SIZE) + PCI_MSIX_VECTOR_CTRL_OFFSET;

		mask = ddi_get32(msix_p->msix_tbl_hdl, (uint32_t *)off);

		ddi_put32(msix_p->msix_tbl_hdl, (uint32_t *)off, (mask & ~1));

		msi_ctrl = pci_config_get16(handle, cap_ptr + PCI_MSIX_CTRL);

		if (!(msi_ctrl & PCI_MSIX_ENABLE_BIT)) {
			msi_ctrl |= PCI_MSIX_ENABLE_BIT;
			pci_config_put16(handle, cap_ptr + PCI_MSIX_CTRL,
			    msi_ctrl);
		}
	}
}

/*
 * Setup interrupt, pogramming IO-APIC or MSI/X address/data.
 */
void
apix_enable_vector(apix_vector_t *vecp)
{
	int tocpu = vecp->v_cpuid, type = vecp->v_type;
	apic_cpus_info_t *cpu_infop;
	ulong_t iflag;

	ASSERT(tocpu < apic_nproc);

	cpu_infop = &apic_cpus[tocpu];
	if (vecp->v_flags & APIX_VECT_USER_BOUND)
		cpu_infop->aci_bound++;
	else
		cpu_infop->aci_temp_bound++;

	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	if (!DDI_INTR_IS_MSI_OR_MSIX(type)) {	/* fixed */
		apix_intx_enable(vecp->v_inum);
	} else {
		int inum = vecp->v_inum;
		dev_info_t *dip = APIX_GET_DIP(vecp);
		int count = i_ddi_intr_get_current_nintrs(dip);

		if (type == APIX_TYPE_MSI) {	/* MSI */
			if (inum == apix_get_max_dev_inum(dip, type)) {
				/* last one */
				uchar_t start_inum = inum + 1 - count;
				uchar_t start_vect = vecp->v_vector + 1 - count;
				apix_vector_t *start_vecp =
				    xv_vector(vecp->v_cpuid, start_vect);

				APIC_VERBOSE(INTR, (CE_CONT, "apix: call "
				    "apix_pci_msi_enable_vector\n"));
				apix_pci_msi_enable_vector(start_vecp, dip,
				    type, start_inum, count, start_vect,
				    cpu_infop->aci_local_id);

				APIC_VERBOSE(INTR, (CE_CONT, "apix: call "
				    "apix_pci_msi_enable_mode\n"));
				apix_pci_msi_enable_mode(dip, type, inum);
			}
		} else {				/* MSI-X */
			apix_pci_msi_enable_vector(vecp, dip,
			    type, inum, 1, vecp->v_vector,
			    cpu_infop->aci_local_id);
			apix_pci_msi_enable_mode(dip, type, inum);
		}
	}
	vecp->v_state = APIX_STATE_ENABLED;
	apic_redist_cpu_skip &= ~(1 << tocpu);

	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);
}

/*
 * Disable the interrupt
 */
void
apix_disable_vector(apix_vector_t *vecp)
{
	struct autovec *avp = vecp->v_autovect;
	ulong_t iflag;

	ASSERT(avp != NULL);

	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	switch (vecp->v_type) {
	case APIX_TYPE_MSI:
		ASSERT(avp->av_vector != NULL && avp->av_dip != NULL);
		/*
		 * Disable the MSI vector
		 * Make sure we only disable on the last
		 * of the multi-MSI support
		 */
		if (i_ddi_intr_get_current_nenables(avp->av_dip) == 1) {
			apic_pci_msi_disable_mode(avp->av_dip,
			    DDI_INTR_TYPE_MSI);
		}
		break;
	case APIX_TYPE_MSIX:
		ASSERT(avp->av_vector != NULL && avp->av_dip != NULL);
		/*
		 * Disable the MSI-X vector
		 * needs to clear its mask and addr/data for each MSI-X
		 */
		apic_pci_msi_unconfigure(avp->av_dip, DDI_INTR_TYPE_MSIX,
		    vecp->v_inum);
		/*
		 * Make sure we only disable on the last MSI-X
		 */
		if (i_ddi_intr_get_current_nenables(avp->av_dip) == 1) {
			apic_pci_msi_disable_mode(avp->av_dip,
			    DDI_INTR_TYPE_MSIX);
		}
		break;
	default:
		apix_intx_disable(vecp->v_inum);
		break;
	}

	if (!(apic_cpus[vecp->v_cpuid].aci_status & APIC_CPU_SUSPEND))
		vecp->v_state = APIX_STATE_DISABLED;
	apic_vt_ops->apic_intrmap_free_entry(&vecp->v_intrmap_private);
	vecp->v_intrmap_private = NULL;

	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);
}

/*
 * Mark vector as obsoleted or freed. The vector is marked
 * obsoleted if there are pending requests on it. Otherwise,
 * free the vector. The obsoleted vectors get freed after
 * being serviced.
 *
 * Return 1 on being obosoleted and 0 on being freed.
 */
#define	INTR_BUSY(_avp)\
	((((volatile ushort_t)(_avp)->av_flags) &\
	(AV_PENTRY_PEND | AV_PENTRY_ONPROC)) != 0)
#define	LOCAL_WITH_INTR_DISABLED(_cpuid)\
	((_cpuid) == psm_get_cpu_id() && !interrupts_enabled())
static uint64_t dummy_tick;

int
apix_obsolete_vector(apix_vector_t *vecp)
{
	struct autovec *avp = vecp->v_autovect;
	int repeats, tries, ipl, busy = 0, cpuid = vecp->v_cpuid;
	apix_impl_t *apixp = apixs[cpuid];

	ASSERT(APIX_CPU_LOCK_HELD(cpuid));

	for (avp = vecp->v_autovect; avp != NULL; avp = avp->av_link) {
		if (avp->av_vector == NULL)
			continue;

		if (LOCAL_WITH_INTR_DISABLED(cpuid)) {
			int bit, index, irr;

			if (INTR_BUSY(avp)) {
				busy++;
				continue;
			}

			/* check IRR for pending interrupts */
			index = vecp->v_vector / 32;
			bit = vecp->v_vector % 32;
			irr = apic_reg_ops->apic_read(APIC_IRR_REG + index);
			if ((irr & (1 << bit)) != 0)
				busy++;

			if (!busy)
				apix_remove_av(vecp, avp);

			continue;
		}

		repeats = 0;
		do {
			repeats++;
			for (tries = 0; tries < apic_max_reps_clear_pending;
			    tries++)
				if (!INTR_BUSY(avp))
					break;
		} while (INTR_BUSY(avp) &&
		    (repeats < apic_max_reps_clear_pending));

		if (INTR_BUSY(avp))
			busy++;
		else {
			/*
			 * Interrupt is not in pending list or being serviced.
			 * However it might be cached in Local APIC's IRR
			 * register. It's impossible to check another CPU's
			 * IRR register. Then wait till lower levels finish
			 * running.
			 */
			for (ipl = 1; ipl < MIN(LOCK_LEVEL, vecp->v_pri); ipl++)
				apix_wait_till_seen(cpuid, ipl);
			if (INTR_BUSY(avp))
				busy++;
		}

		if (!busy)
			apix_remove_av(vecp, avp);
	}

	if (busy) {
		apix_vector_t *tp = apixp->x_obsoletes;

		if (vecp->v_state == APIX_STATE_OBSOLETED)
			return (1);

		vecp->v_state = APIX_STATE_OBSOLETED;
		vecp->v_next = NULL;
		if (tp == NULL)
			apixp->x_obsoletes = vecp;
		else {
			while (tp->v_next != NULL)
				tp = tp->v_next;
			tp->v_next = vecp;
		}
		return (1);
	}

	/* interrupt is not busy */
	if (vecp->v_state == APIX_STATE_OBSOLETED) {
		/* remove from obsoleted list */
		apixp->x_obsoletes = vecp->v_next;
		vecp->v_next = NULL;
	}
	apix_cleanup_vector(vecp);
	return (0);
}

/*
 * Duplicate number of continuous vectors to specified target vectors.
 */
static void
apix_dup_vectors(apix_vector_t *oldp, apix_vector_t *newp, int count)
{
	struct autovec *avp;
	apix_vector_t *fromp, *top;
	processorid_t oldcpu = oldp->v_cpuid, newcpu = newp->v_cpuid;
	uchar_t oldvec = oldp->v_vector, newvec = newp->v_vector;
	int i, inum;

	ASSERT(oldp->v_type != APIX_TYPE_IPI);

	for (i = 0; i < count; i++) {
		fromp = xv_vector(oldcpu, oldvec + i);
		top = xv_vector(newcpu, newvec + i);
		ASSERT(fromp != NULL && top != NULL);

		/* copy over original one */
		top->v_state = fromp->v_state;
		top->v_type = fromp->v_type;
		top->v_bound_cpuid = fromp->v_bound_cpuid;
		top->v_inum = fromp->v_inum;
		top->v_flags = fromp->v_flags;
		top->v_intrmap_private = fromp->v_intrmap_private;

		for (avp = fromp->v_autovect; avp != NULL; avp = avp->av_link) {
			if (avp->av_vector == NULL)
				continue;

			apix_insert_av(top, avp->av_intr_id, avp->av_vector,
			    avp->av_intarg1, avp->av_intarg2, avp->av_ticksp,
			    avp->av_prilevel, avp->av_dip);

			if (fromp->v_type == APIX_TYPE_FIXED &&
			    avp->av_dip != NULL) {
				inum = GET_INTR_INUM(avp->av_intr_id);
				apix_set_dev_map(top, avp->av_dip, inum);
			}
		}

		if (DDI_INTR_IS_MSI_OR_MSIX(fromp->v_type) &&
		    fromp->v_devp != NULL)
			apix_set_dev_map(top, fromp->v_devp->dv_dip,
			    fromp->v_devp->dv_inum);
	}
}

static apix_vector_t *
apix_init_vector(processorid_t cpuid, uchar_t vector)
{
	apix_impl_t *apixp = apixs[cpuid];
	apix_vector_t *vecp = apixp->x_vectbl[vector];

	ASSERT(IS_VECT_FREE(vecp));

	if (vecp == NULL) {
		vecp = kmem_zalloc(sizeof (apix_vector_t), KM_NOSLEEP);
		if (vecp == NULL) {
			cmn_err(CE_WARN, "apix: no memory to allocate vector");
			return (NULL);
		}
		apixp->x_vectbl[vector] = vecp;
	}
	vecp->v_state = APIX_STATE_ALLOCED;
	vecp->v_cpuid = vecp->v_bound_cpuid = cpuid;
	vecp->v_vector = vector;

	return (vecp);
}

static void
apix_cleanup_vector(apix_vector_t *vecp)
{
	ASSERT(vecp->v_share == 0);
	vecp->v_bound_cpuid = IRQ_UNINIT;
	vecp->v_state = APIX_STATE_FREED;
	vecp->v_type = 0;
	vecp->v_flags = 0;
	vecp->v_busy = 0;
	vecp->v_intrmap_private = NULL;
}

static void
apix_dprint_vector(apix_vector_t *vecp, dev_info_t *dip, int count)
{
#ifdef DEBUG
	major_t major;
	char *name, *drv_name;
	int instance, len, t_len;
	char mesg[1024] = "apix: ";

	t_len = sizeof (mesg);
	len = strlen(mesg);
	if (dip != NULL) {
		name = ddi_get_name(dip);
		major = ddi_name_to_major(name);
		drv_name = ddi_major_to_name(major);
		instance = ddi_get_instance(dip);
		(void) snprintf(mesg + len, t_len - len, "%s (%s) instance %d ",
		    name, drv_name, instance);
	}
	len = strlen(mesg);

	switch (vecp->v_type) {
	case APIX_TYPE_FIXED:
		(void) snprintf(mesg + len, t_len - len, "irqno %d",
		    vecp->v_inum);
		break;
	case APIX_TYPE_MSI:
		(void) snprintf(mesg + len, t_len - len,
		    "msi inum %d (count %d)", vecp->v_inum, count);
		break;
	case APIX_TYPE_MSIX:
		(void) snprintf(mesg + len, t_len - len, "msi-x inum %d",
		    vecp->v_inum);
		break;
	default:
		break;

	}

	APIC_VERBOSE(ALLOC, (CE_CONT, "%s allocated with vector 0x%x on "
	    "cpu %d\n", mesg, vecp->v_vector, vecp->v_cpuid));
#endif	/* DEBUG */
}

/*
 * Operations on avintr
 */

#define	INIT_AUTOVEC(p, intr_id, f, arg1, arg2, ticksp, ipl, dip)	\
do { \
	(p)->av_intr_id = intr_id;	\
	(p)->av_vector = f;		\
	(p)->av_intarg1 = arg1;		\
	(p)->av_intarg2 = arg2;		\
	(p)->av_ticksp = ticksp;	\
	(p)->av_prilevel = ipl;		\
	(p)->av_dip = dip;		\
	(p)->av_flags = 0;		\
_NOTE(CONSTCOND)} while (0)

/*
 * Insert an interrupt service routine into chain by its priority from
 * high to low
 */
static void
apix_insert_av(apix_vector_t *vecp, void *intr_id, avfunc f, caddr_t arg1,
    caddr_t arg2, uint64_t *ticksp, int ipl, dev_info_t *dip)
{
	struct autovec *p, *prep, *mem;

	APIC_VERBOSE(INTR, (CE_CONT, "apix_insert_av: dip %p, vector 0x%x, "
	    "cpu %d\n", (void *)dip, vecp->v_vector, vecp->v_cpuid));

	mem = kmem_zalloc(sizeof (struct autovec), KM_SLEEP);
	INIT_AUTOVEC(mem, intr_id, f, arg1, arg2, ticksp, ipl, dip);
	if (vecp->v_type == APIX_TYPE_FIXED && apic_level_intr[vecp->v_inum])
		mem->av_flags |= AV_PENTRY_LEVEL;

	vecp->v_share++;
	vecp->v_pri = (ipl > vecp->v_pri) ? ipl : vecp->v_pri;
	if (vecp->v_autovect == NULL) {	/* Nothing on list - put it at head */
		vecp->v_autovect = mem;
		return;
	}

	if (DDI_INTR_IS_MSI_OR_MSIX(vecp->v_type)) {	/* MSI/X */
		ASSERT(vecp->v_share == 1);	/* No sharing for MSI/X */

		INIT_AUTOVEC(vecp->v_autovect, intr_id, f, arg1, arg2, ticksp,
		    ipl, dip);
		prep = vecp->v_autovect->av_link;
		vecp->v_autovect->av_link = NULL;

		/* Free the following autovect chain */
		while (prep != NULL) {
			ASSERT(prep->av_vector == NULL);

			p = prep;
			prep = prep->av_link;
			kmem_free(p, sizeof (struct autovec));
		}

		kmem_free(mem, sizeof (struct autovec));
		return;
	}

	/* find where it goes in list */
	prep = NULL;
	for (p = vecp->v_autovect; p != NULL; p = p->av_link) {
		if (p->av_vector && p->av_prilevel <= ipl)
			break;
		prep = p;
	}
	if (prep != NULL) {
		if (prep->av_vector == NULL) {	/* freed struct available */
			INIT_AUTOVEC(prep, intr_id, f, arg1, arg2,
			    ticksp, ipl, dip);
			prep->av_flags = mem->av_flags;
			kmem_free(mem, sizeof (struct autovec));
			return;
		}

		mem->av_link = prep->av_link;
		prep->av_link = mem;
	} else {
		/* insert new intpt at beginning of chain */
		mem->av_link = vecp->v_autovect;
		vecp->v_autovect = mem;
	}
}

/*
 * After having made a change to an autovector list, wait until we have
 * seen specified cpu not executing an interrupt at that level--so we
 * know our change has taken effect completely (no old state in registers,
 * etc).
 */
#define	APIX_CPU_ENABLED(_cp) \
	(quiesce_active == 0 && \
	(((_cp)->cpu_flags & (CPU_QUIESCED|CPU_OFFLINE)) == 0))

static void
apix_wait_till_seen(processorid_t cpuid, int ipl)
{
	struct cpu *cp = cpu[cpuid];

	if (cp == NULL || LOCAL_WITH_INTR_DISABLED(cpuid))
		return;

	/*
	 * Don't wait if the CPU is quiesced or offlined. This can happen
	 * when a CPU is running pause thread but hardware triggered an
	 * interrupt and the interrupt gets queued.
	 */
	for (;;) {
		if (!INTR_ACTIVE((volatile struct cpu *)cpu[cpuid], ipl) &&
		    (!APIX_CPU_ENABLED(cp) ||
		    !INTR_PENDING((volatile apix_impl_t *)apixs[cpuid], ipl)))
			return;
	}
}

static void
apix_remove_av(apix_vector_t *vecp, struct autovec *target)
{
	int hi_pri = 0;
	struct autovec *p;

	if (target == NULL)
		return;

	APIC_VERBOSE(INTR, (CE_CONT, "apix_remove_av: dip %p, vector 0x%x, "
	    "cpu %d\n", (void *)target->av_dip, vecp->v_vector, vecp->v_cpuid));

	for (p = vecp->v_autovect; p; p = p->av_link) {
		if (p == target || p->av_vector == NULL)
			continue;
		hi_pri = (p->av_prilevel > hi_pri) ? p->av_prilevel : hi_pri;
	}

	vecp->v_share--;
	vecp->v_pri = hi_pri;

	/*
	 * This drops the handler from the chain, it can no longer be called.
	 * However, there is no guarantee that the handler is not currently
	 * still executing.
	 */
	target->av_vector = NULL;
	/*
	 * There is a race where we could be just about to pick up the ticksp
	 * pointer to increment it after returning from the service routine
	 * in av_dispatch_autovect.  Rather than NULL it out let's just point
	 * it off to something safe so that any final tick update attempt
	 * won't fault.
	 */
	target->av_ticksp = &dummy_tick;
	apix_wait_till_seen(vecp->v_cpuid, target->av_prilevel);
}

static struct autovec *
apix_find_av(apix_vector_t *vecp, void *intr_id, avfunc f)
{
	struct autovec *p;

	for (p = vecp->v_autovect; p; p = p->av_link) {
		if ((p->av_vector == f) && (p->av_intr_id == intr_id)) {
			/* found the handler */
			return (p);
		}
	}

	return (NULL);
}

static apix_vector_t *
apix_find_vector_by_avintr(void *intr_id, avfunc f)
{
	apix_vector_t *vecp;
	processorid_t n;
	uchar_t v;

	for (n = 0; n < apic_nproc; n++) {
		if (!apix_is_cpu_enabled(n))
			continue;

		for (v = APIX_AVINTR_MIN; v <= APIX_AVINTR_MIN; v++) {
			vecp = xv_vector(n, v);
			if (vecp == NULL ||
			    vecp->v_state <= APIX_STATE_OBSOLETED)
				continue;

			if (apix_find_av(vecp, intr_id, f) != NULL)
				return (vecp);
		}
	}

	return (NULL);
}

/*
 * Add interrupt service routine.
 *
 * For legacy interrupts (HPET timer, ACPI SCI), the vector is actually
 * IRQ no. A vector is then allocated. Otherwise, the vector is already
 * allocated. The input argument virt_vect is virtual vector of format
 * APIX_VIRTVEC_VECTOR(cpuid, vector).
 *
 * Return 1 on success, 0 on failure.
 */
int
apix_add_avintr(void *intr_id, int ipl, avfunc xxintr, char *name,
    int virt_vect, caddr_t arg1, caddr_t arg2, uint64_t *ticksp,
    dev_info_t *dip)
{
	int cpuid;
	uchar_t v = (uchar_t)APIX_VIRTVEC_VECTOR(virt_vect);
	apix_vector_t *vecp;

	if (xxintr == NULL) {
		cmn_err(CE_WARN, "Attempt to add null for %s "
		    "on vector 0x%x,0x%x", name,
		    APIX_VIRTVEC_CPU(virt_vect),
		    APIX_VIRTVEC_VECTOR(virt_vect));
		return (0);
	}

	if (v >= APIX_IPI_MIN)	/* IPIs */
		return (apix_add_ipi(ipl, xxintr, name, v, arg1, arg2));

	if (!APIX_IS_VIRTVEC(virt_vect)) {	/* got irq */
		int irqno = virt_vect;
		int inum = GET_INTR_INUM(intr_id);

		/*
		 * Senarios include:
		 * a. add_avintr() is called before irqp initialized (legacy)
		 * b. irqp is initialized, vector is not allocated (fixed)
		 * c. irqp is initialized, vector is allocated (fixed & shared)
		 */
		if ((vecp = apix_alloc_intx(dip, inum, irqno)) == NULL)
			return (0);

		cpuid = vecp->v_cpuid;
		v = vecp->v_vector;
		virt_vect = APIX_VIRTVECTOR(cpuid, v);
	} else {	/* got virtual vector */
		cpuid = APIX_VIRTVEC_CPU(virt_vect);
		vecp = xv_vector(cpuid, v);
		ASSERT(vecp != NULL);
	}

	lock_set(&apix_lock);
	if (vecp->v_state <= APIX_STATE_OBSOLETED) {
		vecp = NULL;

		/*
		 * Basically the allocated but not enabled interrupts
		 * will not get re-targeted. But MSIs in allocated state
		 * could be re-targeted due to group re-targeting.
		 */
		if (intr_id != NULL && dip != NULL) {
			ddi_intr_handle_impl_t *hdlp = intr_id;
			vecp = apix_get_dev_map(dip, hdlp->ih_inum,
			    hdlp->ih_type);
			ASSERT(vecp->v_state == APIX_STATE_ALLOCED);
		}
		if (vecp == NULL) {
			lock_clear(&apix_lock);
			cmn_err(CE_WARN, "Invalid interrupt 0x%x,0x%x "
			    " for %p to add", cpuid, v, intr_id);
			return (0);
		}
		cpuid = vecp->v_cpuid;
		virt_vect = APIX_VIRTVECTOR(cpuid, vecp->v_vector);
	}

	APIX_ENTER_CPU_LOCK(cpuid);
	apix_insert_av(vecp, intr_id, xxintr, arg1, arg2, ticksp, ipl, dip);
	APIX_LEAVE_CPU_LOCK(cpuid);

	(void) apix_addspl(virt_vect, ipl, 0, 0);

	lock_clear(&apix_lock);

	return (1);
}

/*
 * Remove avintr
 *
 * For fixed, if it's the last one of shared interrupts, free the vector.
 * For msi/x, only disable the interrupt but not free the vector, which
 * is freed by PSM_XXX_FREE_XXX.
 */
void
apix_rem_avintr(void *intr_id, int ipl, avfunc xxintr, int virt_vect)
{
	avfunc f;
	apix_vector_t *vecp;
	struct autovec *avp;
	processorid_t cpuid;

	if ((f = xxintr) == NULL)
		return;

	lock_set(&apix_lock);

	if (!APIX_IS_VIRTVEC(virt_vect)) {	/* got irq */
		vecp = apix_intx_get_vector(virt_vect);
		virt_vect = APIX_VIRTVECTOR(vecp->v_cpuid, vecp->v_vector);
	} else	/* got virtual vector */
		vecp = xv_vector(APIX_VIRTVEC_CPU(virt_vect),
		    APIX_VIRTVEC_VECTOR(virt_vect));

	if (vecp == NULL) {
		lock_clear(&apix_lock);
		cmn_err(CE_CONT, "Invalid interrupt 0x%x,0x%x to remove",
		    APIX_VIRTVEC_CPU(virt_vect),
		    APIX_VIRTVEC_VECTOR(virt_vect));
		return;
	}

	if (vecp->v_state <= APIX_STATE_OBSOLETED ||
	    ((avp = apix_find_av(vecp, intr_id, f)) == NULL)) {
		/*
		 * It's possible that the interrupt is rebound to a
		 * different cpu before rem_avintr() is called. Search
		 * through all vectors once it happens.
		 */
		if ((vecp = apix_find_vector_by_avintr(intr_id, f))
		    == NULL) {
			lock_clear(&apix_lock);
			cmn_err(CE_CONT, "Unknown interrupt 0x%x,0x%x "
			    "for %p to remove", APIX_VIRTVEC_CPU(virt_vect),
			    APIX_VIRTVEC_VECTOR(virt_vect), intr_id);
			return;
		}
		virt_vect = APIX_VIRTVECTOR(vecp->v_cpuid, vecp->v_vector);
		avp = apix_find_av(vecp, intr_id, f);
	}
	cpuid = vecp->v_cpuid;

	/* disable interrupt */
	(void) apix_delspl(virt_vect, ipl, 0, 0);

	/* remove ISR entry */
	APIX_ENTER_CPU_LOCK(cpuid);
	apix_remove_av(vecp, avp);
	APIX_LEAVE_CPU_LOCK(cpuid);

	lock_clear(&apix_lock);
}

/*
 * Device to vector mapping table
 */

static void
apix_clear_dev_map(dev_info_t *dip, int inum, int type)
{
	char *name;
	major_t major;
	apix_dev_vector_t *dvp, *prev = NULL;
	int found = 0;

	name = ddi_get_name(dip);
	major = ddi_name_to_major(name);

	mutex_enter(&apix_mutex);

	for (dvp = apix_dev_vector[major]; dvp != NULL;
	    prev = dvp, dvp = dvp->dv_next) {
		if (dvp->dv_dip == dip && dvp->dv_inum == inum &&
		    dvp->dv_type == type) {
			found++;
			break;
		}
	}

	if (!found) {
		mutex_exit(&apix_mutex);
		return;
	}

	if (prev != NULL)
		prev->dv_next = dvp->dv_next;

	if (apix_dev_vector[major] == dvp)
		apix_dev_vector[major] = dvp->dv_next;

	dvp->dv_vector->v_devp = NULL;

	mutex_exit(&apix_mutex);

	kmem_free(dvp, sizeof (apix_dev_vector_t));
}

void
apix_set_dev_map(apix_vector_t *vecp, dev_info_t *dip, int inum)
{
	apix_dev_vector_t *dvp;
	char *name;
	major_t major;
	uint32_t found = 0;

	ASSERT(dip != NULL);
	name = ddi_get_name(dip);
	major = ddi_name_to_major(name);

	mutex_enter(&apix_mutex);

	for (dvp = apix_dev_vector[major]; dvp != NULL;
	    dvp = dvp->dv_next) {
		if (dvp->dv_dip == dip && dvp->dv_inum == inum &&
		    dvp->dv_type == vecp->v_type) {
			found++;
			break;
		}
	}

	if (found == 0) {	/* not found */
		dvp = kmem_zalloc(sizeof (apix_dev_vector_t), KM_SLEEP);
		dvp->dv_dip = dip;
		dvp->dv_inum = inum;
		dvp->dv_type = vecp->v_type;

		dvp->dv_next = apix_dev_vector[major];
		apix_dev_vector[major] = dvp;
	}
	dvp->dv_vector = vecp;
	vecp->v_devp = dvp;

	mutex_exit(&apix_mutex);

	DDI_INTR_IMPLDBG((CE_CONT, "apix_set_dev_map: dip=0x%p "
	    "inum=0x%x  vector=0x%x/0x%x\n",
	    (void *)dip, inum, vecp->v_cpuid, vecp->v_vector));
}

apix_vector_t *
apix_get_dev_map(dev_info_t *dip, int inum, int type)
{
	char *name;
	major_t major;
	apix_dev_vector_t *dvp;
	apix_vector_t *vecp;

	name = ddi_get_name(dip);
	if ((major = ddi_name_to_major(name)) == DDI_MAJOR_T_NONE)
		return (NULL);

	mutex_enter(&apix_mutex);
	for (dvp = apix_dev_vector[major]; dvp != NULL;
	    dvp = dvp->dv_next) {
		if (dvp->dv_dip == dip && dvp->dv_inum == inum &&
		    dvp->dv_type == type) {
			vecp = dvp->dv_vector;
			mutex_exit(&apix_mutex);
			return (vecp);
		}
	}
	mutex_exit(&apix_mutex);

	return (NULL);
}

/*
 * Get minimum inum for specified device, used for MSI
 */
int
apix_get_min_dev_inum(dev_info_t *dip, int type)
{
	char *name;
	major_t major;
	apix_dev_vector_t *dvp;
	int inum = -1;

	name = ddi_get_name(dip);
	major = ddi_name_to_major(name);

	mutex_enter(&apix_mutex);
	for (dvp = apix_dev_vector[major]; dvp != NULL;
	    dvp = dvp->dv_next) {
		if (dvp->dv_dip == dip && dvp->dv_type == type) {
			if (inum == -1)
				inum = dvp->dv_inum;
			else
				inum = (dvp->dv_inum < inum) ?
				    dvp->dv_inum : inum;
		}
	}
	mutex_exit(&apix_mutex);

	return (inum);
}

int
apix_get_max_dev_inum(dev_info_t *dip, int type)
{
	char *name;
	major_t major;
	apix_dev_vector_t *dvp;
	int inum = -1;

	name = ddi_get_name(dip);
	major = ddi_name_to_major(name);

	mutex_enter(&apix_mutex);
	for (dvp = apix_dev_vector[major]; dvp != NULL;
	    dvp = dvp->dv_next) {
		if (dvp->dv_dip == dip && dvp->dv_type == type) {
			if (inum == -1)
				inum = dvp->dv_inum;
			else
				inum = (dvp->dv_inum > inum) ?
				    dvp->dv_inum : inum;
		}
	}
	mutex_exit(&apix_mutex);

	return (inum);
}

/*
 * Major to cpu binding, for INTR_ROUND_ROBIN_WITH_AFFINITY cpu
 * binding policy
 */

static uint32_t
apix_get_dev_binding(dev_info_t *dip)
{
	major_t major;
	char *name;
	uint32_t cpu = IRQ_UNINIT;

	name = ddi_get_name(dip);
	major = ddi_name_to_major(name);
	if (major < devcnt) {
		mutex_enter(&apix_mutex);
		cpu = apix_major_to_cpu[major];
		mutex_exit(&apix_mutex);
	}

	return (cpu);
}

static void
apix_set_dev_binding(dev_info_t *dip, uint32_t cpu)
{
	major_t major;
	char *name;

	/* setup major to cpu mapping */
	name = ddi_get_name(dip);
	major = ddi_name_to_major(name);
	if (apix_major_to_cpu[major] == IRQ_UNINIT) {
		mutex_enter(&apix_mutex);
		apix_major_to_cpu[major] = cpu;
		mutex_exit(&apix_mutex);
	}
}

/*
 * return the cpu to which this intr should be bound.
 * Check properties or any other mechanism to see if user wants it
 * bound to a specific CPU. If so, return the cpu id with high bit set.
 * If not, use the policy to choose a cpu and return the id.
 */
uint32_t
apix_bind_cpu(dev_info_t *dip)
{
	int	instance, instno, prop_len, bind_cpu, count;
	uint_t	i, rc;
	major_t	major;
	char	*name, *drv_name, *prop_val, *cptr;
	char	prop_name[32];

	lock_set(&apix_lock);

	if (apic_intr_policy == INTR_LOWEST_PRIORITY) {
		cmn_err(CE_WARN, "apix: unsupported interrupt binding policy "
		    "LOWEST PRIORITY, use ROUND ROBIN instead");
		apic_intr_policy = INTR_ROUND_ROBIN;
	}

	if (apic_nproc == 1) {
		lock_clear(&apix_lock);
		return (0);
	}

	drv_name = NULL;
	rc = DDI_PROP_NOT_FOUND;
	major = (major_t)-1;
	if (dip != NULL) {
		name = ddi_get_name(dip);
		major = ddi_name_to_major(name);
		drv_name = ddi_major_to_name(major);
		instance = ddi_get_instance(dip);
		if (apic_intr_policy == INTR_ROUND_ROBIN_WITH_AFFINITY) {
			bind_cpu = apix_get_dev_binding(dip);
			if (bind_cpu != IRQ_UNINIT) {
				lock_clear(&apix_lock);
				return (bind_cpu);
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
		/* if specific cpu is bogus, then default to cpu 0 */
		if (bind_cpu >= apic_nproc) {
			cmn_err(CE_WARN, "apix: %s=%s: CPU %d not present",
			    prop_name, prop_val, bind_cpu);
			bind_cpu = 0;
		} else {
			/* indicate that we are bound at user request */
			bind_cpu |= IRQ_USER_BOUND;
		}
		/*
		 * no need to check apic_cpus[].aci_status, if specific cpu is
		 * not up, then post_cpu_start will handle it.
		 */
	} else {
		bind_cpu = apic_get_next_bind_cpu();
	}

	lock_clear(&apix_lock);

	return ((uint32_t)bind_cpu);
}

static boolean_t
apix_is_cpu_enabled(processorid_t cpuid)
{
	apic_cpus_info_t *cpu_infop;

	cpu_infop = &apic_cpus[cpuid];

	if ((cpu_infop->aci_status & APIC_CPU_INTR_ENABLE) == 0)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Must be called with apix_lock held. This function can be
 * called from above lock level by apix_intr_redistribute().
 *
 * Arguments:
 *    vecp  : Vector to be rebound
 *    tocpu : Target cpu. IRQ_UNINIT means target is vecp->v_cpuid.
 *    count : Number of continuous vectors
 *
 * Return new vector being bound to
 */
apix_vector_t *
apix_rebind(apix_vector_t *vecp, processorid_t newcpu, int count)
{
	apix_vector_t *newp, *oldp;
	processorid_t oldcpu = vecp->v_cpuid;
	uchar_t newvec, oldvec = vecp->v_vector;
	int i;

	ASSERT(LOCK_HELD(&apix_lock) && count > 0);

	if (!apix_is_cpu_enabled(newcpu))
		return (NULL);

	if (vecp->v_cpuid == newcpu) 	/* rebind to the same cpu */
		return (vecp);

	APIX_ENTER_CPU_LOCK(oldcpu);
	APIX_ENTER_CPU_LOCK(newcpu);

	/* allocate vector */
	if (count == 1)
		newp = apix_alloc_vector_oncpu(newcpu, NULL, 0, vecp->v_type);
	else {
		ASSERT(vecp->v_type == APIX_TYPE_MSI);
		newp = apix_alloc_nvectors_oncpu(newcpu, NULL, 0, count,
		    vecp->v_type);
	}
	if (newp == NULL) {
		APIX_LEAVE_CPU_LOCK(newcpu);
		APIX_LEAVE_CPU_LOCK(oldcpu);
		return (NULL);
	}

	newvec = newp->v_vector;
	apix_dup_vectors(vecp, newp, count);

	APIX_LEAVE_CPU_LOCK(newcpu);
	APIX_LEAVE_CPU_LOCK(oldcpu);

	if (!DDI_INTR_IS_MSI_OR_MSIX(vecp->v_type)) {
		ASSERT(count == 1);
		if (apix_intx_rebind(vecp->v_inum, newcpu, newvec) != 0) {
			struct autovec *avp;
			int inum;

			/* undo duplication */
			APIX_ENTER_CPU_LOCK(oldcpu);
			APIX_ENTER_CPU_LOCK(newcpu);
			for (avp = newp->v_autovect; avp != NULL;
			    avp = avp->av_link) {
				if (avp->av_dip != NULL) {
					inum = GET_INTR_INUM(avp->av_intr_id);
					apix_set_dev_map(vecp, avp->av_dip,
					    inum);
				}
				apix_remove_av(newp, avp);
			}
			apix_cleanup_vector(newp);
			APIX_LEAVE_CPU_LOCK(newcpu);
			APIX_LEAVE_CPU_LOCK(oldcpu);
			APIC_VERBOSE(REBIND, (CE_CONT, "apix: rebind fixed "
			    "interrupt 0x%x to cpu %d failed\n",
			    vecp->v_inum, newcpu));
			return (NULL);
		}

		APIX_ENTER_CPU_LOCK(oldcpu);
		(void) apix_obsolete_vector(vecp);
		APIX_LEAVE_CPU_LOCK(oldcpu);
		APIC_VERBOSE(REBIND, (CE_CONT, "apix: rebind fixed interrupt"
		    " 0x%x/0x%x to 0x%x/0x%x\n",
		    oldcpu, oldvec, newcpu, newvec));
		return (newp);
	}

	for (i = 0; i < count; i++) {
		oldp = xv_vector(oldcpu, oldvec + i);
		newp = xv_vector(newcpu, newvec + i);

		if (newp->v_share > 0) {
			APIX_SET_REBIND_INFO(oldp, newp);

			apix_enable_vector(newp);

			APIX_CLR_REBIND_INFO();
		}

		APIX_ENTER_CPU_LOCK(oldcpu);
		(void) apix_obsolete_vector(oldp);
		APIX_LEAVE_CPU_LOCK(oldcpu);
	}
	APIC_VERBOSE(REBIND, (CE_CONT, "apix: rebind vector 0x%x/0x%x "
	    "to 0x%x/0x%x, count=%d\n",
	    oldcpu, oldvec, newcpu, newvec, count));

	return (xv_vector(newcpu, newvec));
}

/*
 * Senarios include:
 * a. add_avintr() is called before irqp initialized (legacy)
 * b. irqp is initialized, vector is not allocated (fixed interrupts)
 * c. irqp is initialized, vector is allocated (shared interrupts)
 */
apix_vector_t *
apix_alloc_intx(dev_info_t *dip, int inum, int irqno)
{
	apic_irq_t *irqp;
	apix_vector_t *vecp;

	/*
	 * Allocate IRQ. Caller is later responsible for the
	 * initialization
	 */
	mutex_enter(&airq_mutex);
	if ((irqp = apic_irq_table[irqno]) == NULL) {
		/* allocate irq */
		irqp = kmem_zalloc(sizeof (apic_irq_t), KM_SLEEP);
		irqp->airq_mps_intr_index = FREE_INDEX;
		apic_irq_table[irqno] = irqp;
	}
	if (irqp->airq_mps_intr_index == FREE_INDEX) {
		irqp->airq_mps_intr_index = DEFAULT_INDEX;
		irqp->airq_cpu = IRQ_UNINIT;
		irqp->airq_origirq = (uchar_t)irqno;
	}

	mutex_exit(&airq_mutex);

	/*
	 * allocate vector
	 */
	if (irqp->airq_cpu == IRQ_UNINIT) {
		uint32_t bindcpu, cpuid;

		/* select cpu by system policy */
		bindcpu = apix_bind_cpu(dip);
		cpuid = bindcpu & ~IRQ_USER_BOUND;

		/* allocate vector */
		APIX_ENTER_CPU_LOCK(cpuid);

		if ((vecp = apix_alloc_vector_oncpu(bindcpu, dip, inum,
		    APIX_TYPE_FIXED)) == NULL) {
			cmn_err(CE_WARN, "No interrupt vector for irq %x",
			    irqno);
			APIX_LEAVE_CPU_LOCK(cpuid);
			return (NULL);
		}
		vecp->v_inum = irqno;
		vecp->v_flags |= APIX_VECT_MASKABLE;

		apix_intx_set_vector(irqno, vecp->v_cpuid, vecp->v_vector);

		APIX_LEAVE_CPU_LOCK(cpuid);
	} else {
		vecp = xv_vector(irqp->airq_cpu, irqp->airq_vector);
		ASSERT(!IS_VECT_FREE(vecp));

		if (dip != NULL)
			apix_set_dev_map(vecp, dip, inum);
	}

	if ((dip != NULL) &&
	    (apic_intr_policy == INTR_ROUND_ROBIN_WITH_AFFINITY) &&
	    ((vecp->v_flags & APIX_VECT_USER_BOUND) == 0))
		apix_set_dev_binding(dip, vecp->v_cpuid);

	apix_dprint_vector(vecp, dip, 1);

	return (vecp);
}

int
apix_alloc_msi(dev_info_t *dip, int inum, int count, int behavior)
{
	int i, cap_ptr, rcount = count;
	apix_vector_t *vecp;
	processorid_t bindcpu, cpuid;
	ushort_t msi_ctrl;
	ddi_acc_handle_t handle;

	DDI_INTR_IMPLDBG((CE_CONT, "apix_alloc_msi_vectors: dip=0x%p "
	    "inum=0x%x  count=0x%x behavior=%d\n",
	    (void *)dip, inum, count, behavior));

	if (count > 1) {
		if (behavior == DDI_INTR_ALLOC_STRICT &&
		    apic_multi_msi_enable == 0)
			return (0);
		if (apic_multi_msi_enable == 0)
			count = 1;
	}

	/* Check whether it supports per-vector masking */
	cap_ptr = i_ddi_get_msi_msix_cap_ptr(dip);
	handle = i_ddi_get_pci_config_handle(dip);
	msi_ctrl = pci_config_get16(handle, cap_ptr + PCI_MSI_CTRL);

	/* bind to cpu */
	bindcpu = apix_bind_cpu(dip);
	cpuid = bindcpu & ~IRQ_USER_BOUND;

	/* if not ISP2, then round it down */
	if (!ISP2(rcount))
		rcount = 1 << (highbit(rcount) - 1);

	APIX_ENTER_CPU_LOCK(cpuid);
	for (vecp = NULL; rcount > 0; rcount >>= 1) {
		vecp = apix_alloc_nvectors_oncpu(bindcpu, dip, inum, rcount,
		    APIX_TYPE_MSI);
		if (vecp != NULL || behavior == DDI_INTR_ALLOC_STRICT)
			break;
	}
	for (i = 0; vecp && i < rcount; i++)
		xv_vector(vecp->v_cpuid, vecp->v_vector + i)->v_flags |=
		    (msi_ctrl & PCI_MSI_PVM_MASK) ? APIX_VECT_MASKABLE : 0;
	APIX_LEAVE_CPU_LOCK(cpuid);
	if (vecp == NULL) {
		APIC_VERBOSE(INTR, (CE_CONT,
		    "apix_alloc_msi: no %d cont vectors found on cpu 0x%x\n",
		    count, bindcpu));
		return (0);
	}

	/* major to cpu binding */
	if ((apic_intr_policy == INTR_ROUND_ROBIN_WITH_AFFINITY) &&
	    ((vecp->v_flags & APIX_VECT_USER_BOUND) == 0))
		apix_set_dev_binding(dip, vecp->v_cpuid);

	apix_dprint_vector(vecp, dip, rcount);

	return (rcount);
}

int
apix_alloc_msix(dev_info_t *dip, int inum, int count, int behavior)
{
	apix_vector_t *vecp;
	processorid_t bindcpu, cpuid;
	int i;

	for (i = 0; i < count; i++) {
		/* select cpu by system policy */
		bindcpu = apix_bind_cpu(dip);
		cpuid = bindcpu & ~IRQ_USER_BOUND;

		/* allocate vector */
		APIX_ENTER_CPU_LOCK(cpuid);
		if ((vecp = apix_alloc_vector_oncpu(bindcpu, dip, inum + i,
		    APIX_TYPE_MSIX)) == NULL) {
			APIX_LEAVE_CPU_LOCK(cpuid);
			APIC_VERBOSE(INTR, (CE_CONT, "apix_alloc_msix: "
			    "allocate msix for device dip=%p, inum=%d on"
			    " cpu %d failed", (void *)dip, inum + i, bindcpu));
			break;
		}
		vecp->v_flags |= APIX_VECT_MASKABLE;
		APIX_LEAVE_CPU_LOCK(cpuid);

		/* major to cpu mapping */
		if ((i == 0) &&
		    (apic_intr_policy == INTR_ROUND_ROBIN_WITH_AFFINITY) &&
		    ((vecp->v_flags & APIX_VECT_USER_BOUND) == 0))
			apix_set_dev_binding(dip, vecp->v_cpuid);

		apix_dprint_vector(vecp, dip, 1);
	}

	if (i < count && behavior == DDI_INTR_ALLOC_STRICT) {
		APIC_VERBOSE(INTR, (CE_WARN, "apix_alloc_msix: "
		    "strictly allocate %d vectors failed, got %d\n",
		    count, i));
		apix_free_vectors(dip, inum, i, APIX_TYPE_MSIX);
		i = 0;
	}

	return (i);
}

/*
 * A rollback free for vectors allocated by apix_alloc_xxx().
 */
void
apix_free_vectors(dev_info_t *dip, int inum, int count, int type)
{
	int i, cpuid;
	apix_vector_t *vecp;

	DDI_INTR_IMPLDBG((CE_CONT, "apix_free_vectors: dip: %p inum: %x "
	    "count: %x type: %x\n",
	    (void *)dip, inum, count, type));

	lock_set(&apix_lock);

	for (i = 0; i < count; i++, inum++) {
		if ((vecp = apix_get_dev_map(dip, inum, type)) == NULL) {
			lock_clear(&apix_lock);
			DDI_INTR_IMPLDBG((CE_CONT, "apix_free_vectors: "
			    "dip=0x%p inum=0x%x type=0x%x apix_find_intr() "
			    "failed\n", (void *)dip, inum, type));
			continue;
		}

		APIX_ENTER_CPU_LOCK(vecp->v_cpuid);
		cpuid = vecp->v_cpuid;

		DDI_INTR_IMPLDBG((CE_CONT, "apix_free_vectors: "
		    "dip=0x%p inum=0x%x type=0x%x vector 0x%x (share %d)\n",
		    (void *)dip, inum, type, vecp->v_vector, vecp->v_share));

		/* tear down device interrupt to vector mapping */
		apix_clear_dev_map(dip, inum, type);

		if (vecp->v_type == APIX_TYPE_FIXED) {
			if (vecp->v_share > 0) {	/* share IRQ line */
				APIX_LEAVE_CPU_LOCK(cpuid);
				continue;
			}

			/* Free apic_irq_table entry */
			apix_intx_free(vecp->v_inum);
		}

		/* free vector */
		apix_cleanup_vector(vecp);

		APIX_LEAVE_CPU_LOCK(cpuid);
	}

	lock_clear(&apix_lock);
}

/*
 * Must be called with apix_lock held
 */
apix_vector_t *
apix_setup_io_intr(apix_vector_t *vecp)
{
	processorid_t bindcpu;
	int ret;

	ASSERT(LOCK_HELD(&apix_lock));

	/*
	 * Interrupts are enabled on the CPU, programme IOAPIC RDT
	 * entry or MSI/X address/data to enable the interrupt.
	 */
	if (apix_is_cpu_enabled(vecp->v_cpuid)) {
		apix_enable_vector(vecp);
		return (vecp);
	}

	/*
	 * CPU is not up or interrupts are disabled. Fall back to the
	 * first avialable CPU.
	 */
	bindcpu = apic_find_cpu(APIC_CPU_INTR_ENABLE);

	if (vecp->v_type == APIX_TYPE_MSI)
		return (apix_grp_set_cpu(vecp, bindcpu, &ret));

	return (apix_set_cpu(vecp, bindcpu, &ret));
}

/*
 * For interrupts which call add_avintr() before apic is initialized.
 * ioapix_setup_intr() will
 *   - allocate vector
 *   - copy over ISR
 */
static void
ioapix_setup_intr(int irqno, iflag_t *flagp)
{
	extern struct av_head autovect[];
	apix_vector_t *vecp;
	apic_irq_t *irqp;
	uchar_t ioapicindex, ipin;
	ulong_t iflag;
	struct autovec *avp;

	ioapicindex = acpi_find_ioapic(irqno);
	ASSERT(ioapicindex != 0xFF);
	ipin = irqno - apic_io_vectbase[ioapicindex];

	mutex_enter(&airq_mutex);
	irqp = apic_irq_table[irqno];

	/*
	 * The irq table entry shouldn't exist unless the interrupts are shared.
	 * In that case, make sure it matches what we would initialize it to.
	 */
	if (irqp != NULL) {
		ASSERT(irqp->airq_mps_intr_index == ACPI_INDEX);
		ASSERT(irqp->airq_intin_no == ipin &&
		    irqp->airq_ioapicindex == ioapicindex);
		vecp = xv_vector(irqp->airq_cpu, irqp->airq_vector);
		ASSERT(!IS_VECT_FREE(vecp));
		mutex_exit(&airq_mutex);
	} else {
		irqp = kmem_zalloc(sizeof (apic_irq_t), KM_SLEEP);

		irqp->airq_cpu = IRQ_UNINIT;
		irqp->airq_origirq = (uchar_t)irqno;
		irqp->airq_mps_intr_index = ACPI_INDEX;
		irqp->airq_ioapicindex = ioapicindex;
		irqp->airq_intin_no = ipin;
		irqp->airq_iflag = *flagp;
		irqp->airq_share++;

		apic_irq_table[irqno] = irqp;
		mutex_exit(&airq_mutex);

		vecp = apix_alloc_intx(NULL, 0, irqno);
	}

	/* copy over autovect */
	for (avp = autovect[irqno].avh_link; avp; avp = avp->av_link)
		apix_insert_av(vecp, avp->av_intr_id, avp->av_vector,
		    avp->av_intarg1, avp->av_intarg2, avp->av_ticksp,
		    avp->av_prilevel, avp->av_dip);

	/* Program I/O APIC */
	iflag = intr_clear();
	lock_set(&apix_lock);

	(void) apix_setup_io_intr(vecp);

	lock_clear(&apix_lock);
	intr_restore(iflag);

	APIC_VERBOSE_IOAPIC((CE_CONT, "apix: setup ioapic, irqno %x "
	    "(ioapic %x, ipin %x) is bound to cpu %x, vector %x\n",
	    irqno, ioapicindex, ipin, irqp->airq_cpu, irqp->airq_vector));
}

void
ioapix_init_intr(int mask_apic)
{
	int ioapicindex;
	int i, j;

	/* mask interrupt vectors */
	for (j = 0; j < apic_io_max && mask_apic; j++) {
		int intin_max;

		ioapicindex = j;
		/* Bits 23-16 define the maximum redirection entries */
		intin_max = (ioapic_read(ioapicindex, APIC_VERS_CMD) >> 16)
		    & 0xff;
		for (i = 0; i <= intin_max; i++)
			ioapic_write(ioapicindex, APIC_RDT_CMD + 2 * i,
			    AV_MASK);
	}

	/*
	 * Hack alert: deal with ACPI SCI interrupt chicken/egg here
	 */
	if (apic_sci_vect > 0)
		ioapix_setup_intr(apic_sci_vect, &apic_sci_flags);

	/*
	 * Hack alert: deal with ACPI HPET interrupt chicken/egg here.
	 */
	if (apic_hpet_vect > 0)
		ioapix_setup_intr(apic_hpet_vect, &apic_hpet_flags);
}
