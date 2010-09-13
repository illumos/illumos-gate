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
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/pci_intr_lib.h>


/* Multiple vector support for MSI */
int	apic_multi_msi_enable = 1;

/* Multiple vector support for MSI-X */
int	apic_msix_enable = 1;

/*
 * check whether the system supports MSI
 *
 * If PCI-E capability is found, then this must be a PCI-E system.
 * Since MSI is required for PCI-E system, it returns PSM_SUCCESS
 * to indicate this system supports MSI.
 */
int
apic_check_msi_support()
{
	dev_info_t *cdip;
	char dev_type[16];
	int dev_len;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_check_msi_support:\n"));

	/*
	 * check whether the first level children of root_node have
	 * PCI-E capability
	 */
	for (cdip = ddi_get_child(ddi_root_node()); cdip != NULL;
	    cdip = ddi_get_next_sibling(cdip)) {

		DDI_INTR_IMPLDBG((CE_CONT, "apic_check_msi_support: cdip: 0x%p,"
		    " driver: %s, binding: %s, nodename: %s\n", (void *)cdip,
		    ddi_driver_name(cdip), ddi_binding_name(cdip),
		    ddi_node_name(cdip)));
		dev_len = sizeof (dev_type);
		if (ddi_getlongprop_buf(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
		    "device_type", (caddr_t)dev_type, &dev_len)
		    != DDI_PROP_SUCCESS)
			continue;
		if (strcmp(dev_type, "pciex") == 0)
			return (PSM_SUCCESS);
	}

	/* MSI is not supported on this system */
	DDI_INTR_IMPLDBG((CE_CONT, "apic_check_msi_support: no 'pciex' "
	    "device_type found\n"));
	return (PSM_FAILURE);
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

	DDI_INTR_IMPLDBG((CE_CONT, "apic_pci_msi_enable_vector: dip=0x%p\n"
	    "\tdriver = %s, inum=0x%x vector=0x%x apicid=0x%x\n", (void *)dip,
	    ddi_driver_name(dip), inum, vector, target_apic_id));

	ASSERT((handle != NULL) && (cap_ptr != 0));

	/* MSI Address */
	msi_addr = (MSI_ADDR_HDR |
	    (target_apic_id << MSI_ADDR_DEST_SHIFT));
	msi_addr |= ((MSI_ADDR_RH_FIXED << MSI_ADDR_RH_SHIFT) |
	    (MSI_ADDR_DM_PHYSICAL << MSI_ADDR_DM_SHIFT));

	/* MSI Data: MSI is edge triggered according to spec */
	msi_data = ((MSI_DATA_TM_EDGE << MSI_DATA_TM_SHIFT) | vector);

	DDI_INTR_IMPLDBG((CE_CONT, "apic_pci_msi_enable_vector: addr=0x%lx "
	    "data=0x%lx\n", (long)msi_addr, (long)msi_data));

	if (type == DDI_INTR_TYPE_MSI) {
		msi_ctrl = pci_config_get16(handle, cap_ptr + PCI_MSI_CTRL);

		/* Set the bits to inform how many MSIs are enabled */
		msi_ctrl |= ((highbit(count) -1) << PCI_MSI_MME_SHIFT);
		pci_config_put16(handle, cap_ptr + PCI_MSI_CTRL, msi_ctrl);
	}
}


/*
 * apic_pci_msi_disable_mode:
 */
void
apic_pci_msi_disable_mode(dev_info_t *rdip, int type)
{
	ushort_t		msi_ctrl;
	int			cap_ptr = i_ddi_get_msi_msix_cap_ptr(rdip);
	ddi_acc_handle_t	handle = i_ddi_get_pci_config_handle(rdip);

	ASSERT((handle != NULL) && (cap_ptr != 0));

	if (type == DDI_INTR_TYPE_MSI) {
		msi_ctrl = pci_config_get16(handle, cap_ptr + PCI_MSI_CTRL);
		if (!(msi_ctrl & PCI_MSI_ENABLE_BIT))
			return;

		msi_ctrl &= ~PCI_MSI_ENABLE_BIT;	/* MSI disable */
		pci_config_put16(handle, cap_ptr + PCI_MSI_CTRL, msi_ctrl);

	} else if (type == DDI_INTR_TYPE_MSIX) {
		msi_ctrl = pci_config_get16(handle, cap_ptr + PCI_MSIX_CTRL);
		if (msi_ctrl & PCI_MSIX_ENABLE_BIT) {
			msi_ctrl &= ~PCI_MSIX_ENABLE_BIT;
			pci_config_put16(handle, cap_ptr + PCI_MSIX_CTRL,
			    msi_ctrl);
		}
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


/*
 * We let the hypervisor deal with msi configutation
 * so just stub this out.
 */

/* ARGSUSED */
void
apic_pci_msi_unconfigure(dev_info_t *rdip, int type, int inum)
{
}
