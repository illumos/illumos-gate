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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Pluribus Networks, Inc.
 */

/*
 * apic_introp.c:
 *	Has code for Advanced DDI interrupt framework support.
 */

#include <sys/cpuvar.h>
#include <sys/psm.h>
#include <sys/archsystm.h>
#include <sys/apic.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/mach_intr.h>
#include <sys/sysmacros.h>
#include <sys/trap.h>
#include <sys/pci.h>
#include <sys/pci_intr_lib.h>
#include <sys/apic_common.h>

extern struct av_head autovect[];

/*
 *	Local Function Prototypes
 */
apic_irq_t	*apic_find_irq(dev_info_t *, struct intrspec *, int);

/*
 * apic_pci_msi_enable_vector:
 *	Set the address/data fields in the MSI/X capability structure
 *	XXX: MSI-X support
 */
/* ARGSUSED */
void
apic_pci_msi_enable_vector(apic_irq_t *irq_ptr, int type, int inum, int vector,
    int count, int target_apic_id)
{
	uint64_t		msi_addr, msi_data;
	ushort_t		msi_ctrl;
	dev_info_t		*dip = irq_ptr->airq_dip;
	int			cap_ptr = i_ddi_get_msi_msix_cap_ptr(dip);
	ddi_acc_handle_t	handle = i_ddi_get_pci_config_handle(dip);
	msi_regs_t		msi_regs;
	int			irqno, i;
	void			*intrmap_tbl[PCI_MSI_MAX_INTRS];

	DDI_INTR_IMPLDBG((CE_CONT, "apic_pci_msi_enable_vector: dip=0x%p\n"
	    "\tdriver = %s, inum=0x%x vector=0x%x apicid=0x%x\n", (void *)dip,
	    ddi_driver_name(dip), inum, vector, target_apic_id));

	ASSERT((handle != NULL) && (cap_ptr != 0));

	msi_regs.mr_data = vector;
	msi_regs.mr_addr = target_apic_id;

	for (i = 0; i < count; i++) {
		irqno = apic_vector_to_irq[vector + i];
		intrmap_tbl[i] = apic_irq_table[irqno]->airq_intrmap_private;
	}
	apic_vt_ops->apic_intrmap_alloc_entry(intrmap_tbl, dip, type,
	    count, 0xff);
	for (i = 0; i < count; i++) {
		irqno = apic_vector_to_irq[vector + i];
		apic_irq_table[irqno]->airq_intrmap_private =
		    intrmap_tbl[i];
	}

	apic_vt_ops->apic_intrmap_map_entry(irq_ptr->airq_intrmap_private,
	    (void *)&msi_regs, type, count);
	apic_vt_ops->apic_intrmap_record_msi(irq_ptr->airq_intrmap_private,
	    &msi_regs);

	/* MSI Address */
	msi_addr = msi_regs.mr_addr;

	/* MSI Data: MSI is edge triggered according to spec */
	msi_data = msi_regs.mr_data;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_pci_msi_enable_vector: addr=0x%lx "
	    "data=0x%lx\n", (long)msi_addr, (long)msi_data));

	if (type == DDI_INTR_TYPE_MSI) {
		msi_ctrl = pci_config_get16(handle, cap_ptr + PCI_MSI_CTRL);

		/* Set the bits to inform how many MSIs are enabled */
		msi_ctrl |= ((highbit(count) -1) << PCI_MSI_MME_SHIFT);
		pci_config_put16(handle, cap_ptr + PCI_MSI_CTRL, msi_ctrl);

		/*
		 * Only set vector if not on hypervisor
		 */
		pci_config_put32(handle,
		    cap_ptr + PCI_MSI_ADDR_OFFSET, msi_addr);

		if (msi_ctrl &  PCI_MSI_64BIT_MASK) {
			pci_config_put32(handle,
			    cap_ptr + PCI_MSI_ADDR_OFFSET + 4, msi_addr >> 32);
			pci_config_put16(handle,
			    cap_ptr + PCI_MSI_64BIT_DATA, msi_data);
		} else {
			pci_config_put16(handle,
			    cap_ptr + PCI_MSI_32BIT_DATA, msi_data);
		}

	} else if (type == DDI_INTR_TYPE_MSIX) {
		uintptr_t	off;
		ddi_intr_msix_t	*msix_p = i_ddi_get_msix(dip);

		ASSERT(msix_p != NULL);

		/* Offset into the "inum"th entry in the MSI-X table */
		off = (uintptr_t)msix_p->msix_tbl_addr +
		    (inum  * PCI_MSIX_VECTOR_SIZE);

		ddi_put32(msix_p->msix_tbl_hdl,
		    (uint32_t *)(off + PCI_MSIX_DATA_OFFSET), msi_data);
		ddi_put32(msix_p->msix_tbl_hdl,
		    (uint32_t *)(off + PCI_MSIX_LOWER_ADDR_OFFSET), msi_addr);
		ddi_put32(msix_p->msix_tbl_hdl,
		    (uint32_t *)(off + PCI_MSIX_UPPER_ADDR_OFFSET),
		    msi_addr >> 32);
	}
}

/*
 * This function returns the no. of vectors available for the pri.
 * dip is not used at this moment.  If we really don't need that,
 * it will be removed.
 */
/*ARGSUSED*/
int
apic_navail_vector(dev_info_t *dip, int pri)
{
	int	lowest, highest, i, navail, count;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_navail_vector: dip: %p, pri: %x\n",
	    (void *)dip, pri));

	highest = apic_ipltopri[pri] + APIC_VECTOR_MASK;
	lowest = apic_ipltopri[pri - 1] + APIC_VECTOR_PER_IPL;
	navail = count = 0;

	if (highest < lowest) /* Both ipl and ipl - 1 map to same pri */
		lowest -= APIC_VECTOR_PER_IPL;

	/* It has to be contiguous */
	for (i = lowest; i <= highest; i++) {
		count = 0;
		while ((apic_vector_to_irq[i] == APIC_RESV_IRQ) &&
		    (i <= highest)) {
			if (APIC_CHECK_RESERVE_VECTORS(i))
				break;
			count++;
			i++;
		}
		if (count > navail)
			navail = count;
	}
	return (navail);
}

/*
 * Finds "count" contiguous MSI vectors starting at the proper alignment
 * at "pri".
 * Caller needs to make sure that count has to be power of 2 and should not
 * be < 1.
 */
uchar_t
apic_find_multi_vectors(int pri, int count)
{
	int	lowest, highest, i, navail, start, msibits;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_find_mult: pri: %x, count: %x\n",
	    pri, count));

	highest = apic_ipltopri[pri] + APIC_VECTOR_MASK;
	lowest = apic_ipltopri[pri - 1] + APIC_VECTOR_PER_IPL;
	navail = 0;

	if (highest < lowest) /* Both ipl and ipl - 1 map to same pri */
		lowest -= APIC_VECTOR_PER_IPL;

	/*
	 * msibits is the no. of lower order message data bits for the
	 * allocated MSI vectors and is used to calculate the aligned
	 * starting vector
	 */
	msibits = count - 1;

	/* It has to be contiguous */
	for (i = lowest; i <= highest; i++) {
		navail = 0;

		/*
		 * starting vector has to be aligned accordingly for
		 * multiple MSIs
		 */
		if (msibits)
			i = (i + msibits) & ~msibits;
		start = i;
		while ((apic_vector_to_irq[i] == APIC_RESV_IRQ) &&
		    (i <= highest)) {
			if (APIC_CHECK_RESERVE_VECTORS(i))
				break;
			navail++;
			if (navail >= count)
				return (start);
			i++;
		}
	}
	return (0);
}


/*
 * It finds the apic_irq_t associates with the dip, ispec and type.
 */
apic_irq_t *
apic_find_irq(dev_info_t *dip, struct intrspec *ispec, int type)
{
	apic_irq_t	*irqp;
	int i;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_find_irq: dip=0x%p vec=0x%x "
	    "ipl=0x%x type=0x%x\n", (void *)dip, ispec->intrspec_vec,
	    ispec->intrspec_pri, type));

	for (i = apic_min_device_irq; i <= apic_max_device_irq; i++) {
		for (irqp = apic_irq_table[i]; irqp; irqp = irqp->airq_next) {
			if ((irqp->airq_dip == dip) &&
			    (irqp->airq_origirq == ispec->intrspec_vec) &&
			    (irqp->airq_ipl == ispec->intrspec_pri)) {
				if (type == DDI_INTR_TYPE_MSI) {
					if (irqp->airq_mps_intr_index ==
					    MSI_INDEX)
						return (irqp);
				} else if (type == DDI_INTR_TYPE_MSIX) {
					if (irqp->airq_mps_intr_index ==
					    MSIX_INDEX)
						return (irqp);
				} else
					return (irqp);
			}
		}
	}
	DDI_INTR_IMPLDBG((CE_CONT, "apic_find_irq: return NULL\n"));
	return (NULL);
}

/*
 * This function will return the pending bit of the irqp.
 * It either comes from the IRR register of the APIC or the RDT
 * entry of the I/O APIC.
 * For the IRR to work, it needs to be to its binding CPU
 */
static int
apic_get_pending(apic_irq_t *irqp, int type)
{
	int			bit, index, irr, pending;
	int			intin_no;
	int			apic_ix;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_get_pending: irqp: %p, cpuid: %x "
	    "type: %x\n", (void *)irqp, irqp->airq_cpu & ~IRQ_USER_BOUND,
	    type));

	/* need to get on the bound cpu */
	mutex_enter(&cpu_lock);
	affinity_set(irqp->airq_cpu & ~IRQ_USER_BOUND);

	index = irqp->airq_vector / 32;
	bit = irqp->airq_vector % 32;
	irr = apic_reg_ops->apic_read(APIC_IRR_REG + index);

	affinity_clear();
	mutex_exit(&cpu_lock);

	pending = (irr & (1 << bit)) ? 1 : 0;
	if (!pending && (type == DDI_INTR_TYPE_FIXED)) {
		/* check I/O APIC for fixed interrupt */
		intin_no = irqp->airq_intin_no;
		apic_ix = irqp->airq_ioapicindex;
		pending = (READ_IOAPIC_RDT_ENTRY_LOW_DWORD(apic_ix, intin_no) &
		    AV_PENDING) ? 1 : 0;
	}
	return (pending);
}


/*
 * This function will clear the mask for the interrupt on the I/O APIC
 */
static void
apic_clear_mask(apic_irq_t *irqp)
{
	int			intin_no;
	ulong_t			iflag;
	int32_t			rdt_entry;
	int 			apic_ix;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_clear_mask: irqp: %p\n",
	    (void *)irqp));

	intin_no = irqp->airq_intin_no;
	apic_ix = irqp->airq_ioapicindex;

	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	rdt_entry = READ_IOAPIC_RDT_ENTRY_LOW_DWORD(apic_ix, intin_no);

	/* clear mask */
	WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(apic_ix, intin_no,
	    ((~AV_MASK) & rdt_entry));

	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);
}


/*
 * This function will mask the interrupt on the I/O APIC
 */
static void
apic_set_mask(apic_irq_t *irqp)
{
	int			intin_no;
	int 			apic_ix;
	ulong_t			iflag;
	int32_t			rdt_entry;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_set_mask: irqp: %p\n", (void *)irqp));

	intin_no = irqp->airq_intin_no;
	apic_ix = irqp->airq_ioapicindex;

	iflag = intr_clear();

	lock_set(&apic_ioapic_lock);

	rdt_entry = READ_IOAPIC_RDT_ENTRY_LOW_DWORD(apic_ix, intin_no);

	/* mask it */
	WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(apic_ix, intin_no,
	    (AV_MASK | rdt_entry));

	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);
}


void
apic_free_vectors(dev_info_t *dip, int inum, int count, int pri, int type)
{
	int i;
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
		if ((irqptr = apic_find_irq(dip, &ispec, type)) == NULL) {
			DDI_INTR_IMPLDBG((CE_CONT, "apic_free_vectors: "
			    "dip=0x%p inum=0x%x pri=0x%x apic_find_irq() "
			    "failed\n", (void *)dip, inum, pri));
			continue;
		}
		irqptr->airq_mps_intr_index = FREE_INDEX;
		apic_vector_to_irq[irqptr->airq_vector] = APIC_RESV_IRQ;
	}
}

/*
 * apic_pci_msi_enable_mode:
 */
void
apic_pci_msi_enable_mode(dev_info_t *rdip, int type, int inum)
{
	ushort_t		msi_ctrl;
	int			cap_ptr = i_ddi_get_msi_msix_cap_ptr(rdip);
	ddi_acc_handle_t	handle = i_ddi_get_pci_config_handle(rdip);

	ASSERT((handle != NULL) && (cap_ptr != 0));

	if (type == DDI_INTR_TYPE_MSI) {
		msi_ctrl = pci_config_get16(handle, cap_ptr + PCI_MSI_CTRL);
		if ((msi_ctrl & PCI_MSI_ENABLE_BIT))
			return;

		msi_ctrl |= PCI_MSI_ENABLE_BIT;
		pci_config_put16(handle, cap_ptr + PCI_MSI_CTRL, msi_ctrl);

	} else if (type == DDI_INTR_TYPE_MSIX) {
		uintptr_t	off;
		uint32_t	mask;
		ddi_intr_msix_t	*msix_p;

		msix_p = i_ddi_get_msix(rdip);

		ASSERT(msix_p != NULL);

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

static int
apic_set_cpu(int irqno, int cpu, int *result)
{
	apic_irq_t *irqp;
	ulong_t iflag;
	int ret;

	DDI_INTR_IMPLDBG((CE_CONT, "APIC_SET_CPU\n"));

	mutex_enter(&airq_mutex);
	irqp = apic_irq_table[irqno];
	mutex_exit(&airq_mutex);

	if (irqp == NULL) {
		*result = ENXIO;
		return (PSM_FAILURE);
	}

	/* Fail if this is an MSI intr and is part of a group. */
	if ((irqp->airq_mps_intr_index == MSI_INDEX) &&
	    (irqp->airq_intin_no > 1)) {
		*result = ENXIO;
		return (PSM_FAILURE);
	}

	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	ret = apic_rebind_all(irqp, cpu);

	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);

	if (ret) {
		*result = EIO;
		return (PSM_FAILURE);
	}
	/*
	 * keep tracking the default interrupt cpu binding
	 */
	irqp->airq_cpu = cpu;

	*result = 0;
	return (PSM_SUCCESS);
}

static int
apic_grp_set_cpu(int irqno, int new_cpu, int *result)
{
	dev_info_t *orig_dip;
	uint32_t orig_cpu;
	ulong_t iflag;
	apic_irq_t *irqps[PCI_MSI_MAX_INTRS];
	int i;
	int cap_ptr;
	int msi_mask_off;
	ushort_t msi_ctrl;
	uint32_t msi_pvm;
	ddi_acc_handle_t handle;
	int num_vectors = 0;
	uint32_t vector;

	DDI_INTR_IMPLDBG((CE_CONT, "APIC_GRP_SET_CPU\n"));

	/*
	 * Take mutex to insure that table doesn't change out from underneath
	 * us while we're playing with it.
	 */
	mutex_enter(&airq_mutex);
	irqps[0] = apic_irq_table[irqno];
	orig_cpu = irqps[0]->airq_temp_cpu;
	orig_dip = irqps[0]->airq_dip;
	num_vectors = irqps[0]->airq_intin_no;
	vector = irqps[0]->airq_vector;

	/* A "group" of 1 */
	if (num_vectors == 1) {
		mutex_exit(&airq_mutex);
		return (apic_set_cpu(irqno, new_cpu, result));
	}

	*result = ENXIO;

	if (irqps[0]->airq_mps_intr_index != MSI_INDEX) {
		mutex_exit(&airq_mutex);
		DDI_INTR_IMPLDBG((CE_CONT, "set_grp: intr not MSI\n"));
		goto set_grp_intr_done;
	}
	if ((num_vectors < 1) || ((num_vectors - 1) & vector)) {
		mutex_exit(&airq_mutex);
		DDI_INTR_IMPLDBG((CE_CONT,
		    "set_grp: base vec not part of a grp or not aligned: "
		    "vec:0x%x, num_vec:0x%x\n", vector, num_vectors));
		goto set_grp_intr_done;
	}
	DDI_INTR_IMPLDBG((CE_CONT, "set_grp: num intrs in grp: %d\n",
	    num_vectors));

	ASSERT((num_vectors + vector) < APIC_MAX_VECTOR);

	*result = EIO;

	/*
	 * All IRQ entries in the table for the given device will be not
	 * shared.  Since they are not shared, the dip in the table will
	 * be true to the device of interest.
	 */
	for (i = 1; i < num_vectors; i++) {
		irqps[i] = apic_irq_table[apic_vector_to_irq[vector + i]];
		if (irqps[i] == NULL) {
			mutex_exit(&airq_mutex);
			goto set_grp_intr_done;
		}
#ifdef DEBUG
		/* Sanity check: CPU and dip is the same for all entries. */
		if ((irqps[i]->airq_dip != orig_dip) ||
		    (irqps[i]->airq_temp_cpu != orig_cpu)) {
			mutex_exit(&airq_mutex);
			DDI_INTR_IMPLDBG((CE_CONT,
			    "set_grp: cpu or dip for vec 0x%x difft than for "
			    "vec 0x%x\n", vector, vector + i));
			DDI_INTR_IMPLDBG((CE_CONT,
			    "  cpu: %d vs %d, dip: 0x%p vs 0x%p\n", orig_cpu,
			    irqps[i]->airq_temp_cpu, (void *)orig_dip,
			    (void *)irqps[i]->airq_dip));
			goto set_grp_intr_done;
		}
#endif /* DEBUG */
	}
	mutex_exit(&airq_mutex);

	cap_ptr = i_ddi_get_msi_msix_cap_ptr(orig_dip);
	handle = i_ddi_get_pci_config_handle(orig_dip);
	msi_ctrl = pci_config_get16(handle, cap_ptr + PCI_MSI_CTRL);

	/* MSI Per vector masking is supported. */
	if (msi_ctrl & PCI_MSI_PVM_MASK) {
		if (msi_ctrl &  PCI_MSI_64BIT_MASK)
			msi_mask_off = cap_ptr + PCI_MSI_64BIT_MASKBITS;
		else
			msi_mask_off = cap_ptr + PCI_MSI_32BIT_MASK;
		msi_pvm = pci_config_get32(handle, msi_mask_off);
		pci_config_put32(handle, msi_mask_off, (uint32_t)-1);
		DDI_INTR_IMPLDBG((CE_CONT,
		    "set_grp: pvm supported.  Mask set to 0x%x\n",
		    pci_config_get32(handle, msi_mask_off)));
	}

	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	/*
	 * Do the first rebind and check for errors.  Apic_rebind_all returns
	 * an error if the CPU is not accepting interrupts.  If the first one
	 * succeeds they all will.
	 */
	if (apic_rebind_all(irqps[0], new_cpu))
		(void) apic_rebind_all(irqps[0], orig_cpu);
	else {
		irqps[0]->airq_cpu = new_cpu;

		for (i = 1; i < num_vectors; i++) {
			(void) apic_rebind_all(irqps[i], new_cpu);
			irqps[i]->airq_cpu = new_cpu;
		}
		*result = 0;	/* SUCCESS */
	}

	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);

	/* Reenable vectors if per vector masking is supported. */
	if (msi_ctrl & PCI_MSI_PVM_MASK) {
		pci_config_put32(handle, msi_mask_off, msi_pvm);
		DDI_INTR_IMPLDBG((CE_CONT,
		    "set_grp: pvm supported.  Mask restored to 0x%x\n",
		    pci_config_get32(handle, msi_mask_off)));
	}

set_grp_intr_done:
	if (*result != 0)
		return (PSM_FAILURE);

	return (PSM_SUCCESS);
}

int
apic_get_vector_intr_info(int vecirq, apic_get_intr_t *intr_params_p)
{
	struct autovec *av_dev;
	uchar_t irqno;
	int i;
	apic_irq_t *irq_p;

	/* Sanity check the vector/irq argument. */
	ASSERT((vecirq >= 0) || (vecirq <= APIC_MAX_VECTOR));

	mutex_enter(&airq_mutex);

	/*
	 * Convert the vecirq arg to an irq using vector_to_irq table
	 * if the arg is a vector.  Pass thru if already an irq.
	 */
	if ((intr_params_p->avgi_req_flags & PSMGI_INTRBY_FLAGS) ==
	    PSMGI_INTRBY_VEC)
		irqno = apic_vector_to_irq[vecirq];
	else
		irqno = vecirq;

	irq_p = apic_irq_table[irqno];

	if ((irq_p == NULL) ||
	    ((irq_p->airq_mps_intr_index != RESERVE_INDEX) &&
	    ((irq_p->airq_temp_cpu == IRQ_UNBOUND) ||
	    (irq_p->airq_temp_cpu == IRQ_UNINIT)))) {
		mutex_exit(&airq_mutex);
		return (PSM_FAILURE);
	}

	if (intr_params_p->avgi_req_flags & PSMGI_REQ_CPUID) {

		/* Get the (temp) cpu from apic_irq table, indexed by irq. */
		intr_params_p->avgi_cpu_id = irq_p->airq_temp_cpu;

		/* Return user bound info for intrd. */
		if (intr_params_p->avgi_cpu_id & IRQ_USER_BOUND) {
			intr_params_p->avgi_cpu_id &= ~IRQ_USER_BOUND;
			intr_params_p->avgi_cpu_id |= PSMGI_CPU_USER_BOUND;
		}
	}

	if (intr_params_p->avgi_req_flags & PSMGI_REQ_VECTOR)
		intr_params_p->avgi_vector = irq_p->airq_vector;

	if (intr_params_p->avgi_req_flags &
	    (PSMGI_REQ_NUM_DEVS | PSMGI_REQ_GET_DEVS))
		/* Get number of devices from apic_irq table shared field. */
		intr_params_p->avgi_num_devs = irq_p->airq_share;

	if (intr_params_p->avgi_req_flags &  PSMGI_REQ_GET_DEVS) {

		intr_params_p->avgi_req_flags  |= PSMGI_REQ_NUM_DEVS;

		/* Some devices have NULL dip.  Don't count these. */
		if (intr_params_p->avgi_num_devs > 0) {
			for (i = 0, av_dev = autovect[irqno].avh_link;
			    av_dev; av_dev = av_dev->av_link)
				if (av_dev->av_vector && av_dev->av_dip)
					i++;
			intr_params_p->avgi_num_devs =
			    MIN(intr_params_p->avgi_num_devs, i);
		}

		/* There are no viable dips to return. */
		if (intr_params_p->avgi_num_devs == 0)
			intr_params_p->avgi_dip_list = NULL;

		else {	/* Return list of dips */

			/* Allocate space in array for that number of devs. */
			intr_params_p->avgi_dip_list = kmem_zalloc(
			    intr_params_p->avgi_num_devs *
			    sizeof (dev_info_t *),
			    KM_SLEEP);

			/*
			 * Loop through the device list of the autovec table
			 * filling in the dip array.
			 *
			 * Note that the autovect table may have some special
			 * entries which contain NULL dips.  These will be
			 * ignored.
			 */
			for (i = 0, av_dev = autovect[irqno].avh_link;
			    av_dev; av_dev = av_dev->av_link)
				if (av_dev->av_vector && av_dev->av_dip)
					intr_params_p->avgi_dip_list[i++] =
					    av_dev->av_dip;
		}
	}

	mutex_exit(&airq_mutex);

	return (PSM_SUCCESS);
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
int
apic_intr_ops(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp,
    psm_intr_op_t intr_op, int *result)
{
	int		cap;
	int		count_vec;
	int		old_priority;
	int		new_priority;
	int		new_cpu;
	apic_irq_t	*irqp;
	struct intrspec *ispec, intr_spec;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_intr_ops: dip: %p hdlp: %p "
	    "intr_op: %x\n", (void *)dip, (void *)hdlp, intr_op));

	ispec = &intr_spec;
	ispec->intrspec_pri = hdlp->ih_pri;
	ispec->intrspec_vec = hdlp->ih_inum;
	ispec->intrspec_func = hdlp->ih_cb_func;

	switch (intr_op) {
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
		if (apic_support_msi == 0) {
			/*
			 * if apic_support_msi is not set, call
			 * apic_check_msi_support() to check whether msi
			 * is supported first
			 */
			if (apic_check_msi_support() == PSM_SUCCESS)
				apic_support_msi = 1;
			else
				apic_support_msi = -1;
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
		*result = apic_navail_vector(dip, hdlp->ih_pri);
		break;
	case PSM_INTR_OP_XLATE_VECTOR:
		ispec = ((ihdl_plat_t *)hdlp->ih_private)->ip_ispecp;
		*result = apic_introp_xlate(dip, ispec, hdlp->ih_type);
		if (*result == -1)
			return (PSM_FAILURE);
		break;
	case PSM_INTR_OP_GET_PENDING:
		if ((irqp = apic_find_irq(dip, ispec, hdlp->ih_type)) == NULL)
			return (PSM_FAILURE);
		*result = apic_get_pending(irqp, hdlp->ih_type);
		break;
	case PSM_INTR_OP_CLEAR_MASK:
		if (hdlp->ih_type != DDI_INTR_TYPE_FIXED)
			return (PSM_FAILURE);
		irqp = apic_find_irq(dip, ispec, hdlp->ih_type);
		if (irqp == NULL)
			return (PSM_FAILURE);
		apic_clear_mask(irqp);
		break;
	case PSM_INTR_OP_SET_MASK:
		if (hdlp->ih_type != DDI_INTR_TYPE_FIXED)
			return (PSM_FAILURE);
		if ((irqp = apic_find_irq(dip, ispec, hdlp->ih_type)) == NULL)
			return (PSM_FAILURE);
		apic_set_mask(irqp);
		break;
	case PSM_INTR_OP_GET_CAP:
		cap = DDI_INTR_FLAG_PENDING;
		if (hdlp->ih_type == DDI_INTR_TYPE_FIXED)
			cap |= DDI_INTR_FLAG_MASKABLE;
		*result = cap;
		break;
	case PSM_INTR_OP_GET_SHARED:
		if (hdlp->ih_type != DDI_INTR_TYPE_FIXED)
			return (PSM_FAILURE);
		ispec = ((ihdl_plat_t *)hdlp->ih_private)->ip_ispecp;
		if ((irqp = apic_find_irq(dip, ispec, hdlp->ih_type)) == NULL)
			return (PSM_FAILURE);
		*result = (irqp->airq_share > 1) ? 1: 0;
		break;
	case PSM_INTR_OP_SET_PRI:
		old_priority = hdlp->ih_pri;	/* save old value */
		new_priority = *(int *)result;	/* try the new value */

		if (hdlp->ih_type == DDI_INTR_TYPE_FIXED) {
			return (PSM_SUCCESS);
		}

		/* Now allocate the vectors */
		if (hdlp->ih_type == DDI_INTR_TYPE_MSI) {
			/* SET_PRI does not support the case of multiple MSI */
			if (i_ddi_intr_get_current_nintrs(hdlp->ih_dip) > 1)
				return (PSM_FAILURE);

			count_vec = apic_alloc_msi_vectors(dip, hdlp->ih_inum,
			    1, new_priority,
			    DDI_INTR_ALLOC_STRICT);
		} else {
			count_vec = apic_alloc_msix_vectors(dip, hdlp->ih_inum,
			    1, new_priority,
			    DDI_INTR_ALLOC_STRICT);
		}

		/* Did we get new vectors? */
		if (!count_vec)
			return (PSM_FAILURE);

		/* Finally, free the previously allocated vectors */
		apic_free_vectors(dip, hdlp->ih_inum, count_vec,
		    old_priority, hdlp->ih_type);
		break;
	case PSM_INTR_OP_SET_CPU:
	case PSM_INTR_OP_GRP_SET_CPU:
		/*
		 * The interrupt handle given here has been allocated
		 * specifically for this command, and ih_private carries
		 * a CPU value.
		 */
		new_cpu = (int)(intptr_t)hdlp->ih_private;
		if (!apic_cpu_in_range(new_cpu)) {
			DDI_INTR_IMPLDBG((CE_CONT,
			    "[grp_]set_cpu: cpu out of range: %d\n", new_cpu));
			*result = EINVAL;
			return (PSM_FAILURE);
		}
		if (hdlp->ih_vector > APIC_MAX_VECTOR) {
			DDI_INTR_IMPLDBG((CE_CONT,
			    "[grp_]set_cpu: vector out of range: %d\n",
			    hdlp->ih_vector));
			*result = EINVAL;
			return (PSM_FAILURE);
		}
		if ((hdlp->ih_flags & PSMGI_INTRBY_FLAGS) == PSMGI_INTRBY_VEC)
			hdlp->ih_vector = apic_vector_to_irq[hdlp->ih_vector];
		if (intr_op == PSM_INTR_OP_SET_CPU) {
			if (apic_set_cpu(hdlp->ih_vector, new_cpu, result) !=
			    PSM_SUCCESS)
				return (PSM_FAILURE);
		} else {
			if (apic_grp_set_cpu(hdlp->ih_vector, new_cpu,
			    result) != PSM_SUCCESS)
				return (PSM_FAILURE);
		}
		break;
	case PSM_INTR_OP_GET_INTR:
		/*
		 * The interrupt handle given here has been allocated
		 * specifically for this command, and ih_private carries
		 * a pointer to a apic_get_intr_t.
		 */
		if (apic_get_vector_intr_info(
		    hdlp->ih_vector, hdlp->ih_private) != PSM_SUCCESS)
			return (PSM_FAILURE);
		break;
	case PSM_INTR_OP_APIC_TYPE:
		((apic_get_type_t *)(hdlp->ih_private))->avgi_type =
		    apic_get_apic_type();
		((apic_get_type_t *)(hdlp->ih_private))->avgi_num_intr =
		    APIC_MAX_VECTOR;
		((apic_get_type_t *)(hdlp->ih_private))->avgi_num_cpu =
		    boot_ncpus;
		hdlp->ih_ver = apic_get_apic_version();
		break;
	case PSM_INTR_OP_SET_CAP:
	default:
		return (PSM_FAILURE);
	}
	return (PSM_SUCCESS);
}
