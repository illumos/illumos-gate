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

/*
 * apic_introp.c:
 *	Has code for Advanced DDI interrupt framework support.
 */

#include <sys/cpuvar.h>
#include <sys/psm.h>
#include "apic.h"
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/mach_intr.h>
#include <sys/sysmacros.h>
#include <sys/trap.h>
#include <sys/pci.h>
#include <sys/pci_intr_lib.h>

extern struct av_head autovect[];

/*
 *	Local Function Prototypes
 */
int		apic_pci_msi_enable_vector(dev_info_t *, int, int,
		    int, int, int);
apic_irq_t	*apic_find_irq(dev_info_t *, struct intrspec *, int);
static int	apic_get_pending(apic_irq_t *, int);
static void	apic_clear_mask(apic_irq_t *);
static void	apic_set_mask(apic_irq_t *);
static uchar_t	apic_find_multi_vectors(int, int);
int		apic_navail_vector(dev_info_t *, int);
int		apic_alloc_vectors(dev_info_t *, int, int, int, int);
void		apic_free_vectors(dev_info_t *, int, int, int, int);
int		apic_intr_ops(dev_info_t *, ddi_intr_handle_impl_t *,
		    psm_intr_op_t, int *);

extern int	intr_clear(void);
extern void	intr_restore(uint_t);
extern uchar_t	apic_bind_intr(dev_info_t *, int, uchar_t, uchar_t);
extern int	apic_allocate_irq(int);
extern int	apic_introp_xlate(dev_info_t *, struct intrspec *, int);
extern int	apic_rebind_all(apic_irq_t *irq_ptr, int bind_cpu, int safe);
extern boolean_t apic_cpu_in_range(int cpu);

/*
 * MSI support flag:
 * reflects whether MSI is supported at APIC level
 * it can also be patched through /etc/system
 *
 *  0 = default value - don't know and need to call apic_check_msi_support()
 *      to find out then set it accordingly
 *  1 = supported
 * -1 = not supported
 */
int	apic_support_msi = 0;

/* Multiple vector support for MSI */
int	apic_multi_msi_enable = 1;
int	apic_multi_msi_max = 2;

extern uchar_t		apic_ipltopri[MAXIPL+1];
extern uchar_t		apic_vector_to_irq[APIC_MAX_VECTOR+1];
extern int		apic_max_device_irq;
extern int		apic_min_device_irq;
extern apic_irq_t	*apic_irq_table[APIC_MAX_VECTOR+1];
extern volatile uint32_t *apicadr; /* virtual addr of local APIC */
extern volatile int32_t	*apicioadr[MAX_IO_APIC];
extern lock_t		apic_ioapic_lock;
extern kmutex_t		airq_mutex;
extern apic_cpus_info_t	*apic_cpus;
extern int apic_first_avail_irq;


/*
 * apic_pci_msi_enable_vector:
 *	Set the address/data fields in the MSI/X capability structure
 *	XXX: MSI-X support
 */
/* ARGSUSED */
int
apic_pci_msi_enable_vector(dev_info_t *dip, int type, int inum, int vector,
    int count, int target_apic_id)
{
	uint64_t	msi_addr, msi_data;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_pci_msi_enable_vector: dip=0x%p\n"
	    "\tdriver = %s, inum=0x%x vector=0x%x apicid=0x%x\n", (void *)dip,
	    ddi_driver_name(dip), inum, vector, target_apic_id));

	/* MSI Address */
	msi_addr = (MSI_ADDR_HDR | (target_apic_id << MSI_ADDR_DEST_SHIFT));
	msi_addr |= ((MSI_ADDR_RH_FIXED << MSI_ADDR_RH_SHIFT) |
		    (MSI_ADDR_DM_PHYSICAL << MSI_ADDR_DM_SHIFT));

	/* MSI Data: MSI is edge triggered according to spec */
	msi_data = ((MSI_DATA_TM_EDGE << MSI_DATA_TM_SHIFT) | vector);

	DDI_INTR_IMPLDBG((CE_CONT, "apic_pci_msi_enable_vector: addr=0x%lx "
	    "data=0x%lx\n", (long)msi_addr, (long)msi_data));

	if (pci_msi_configure(dip, type, count, inum, msi_addr, msi_data) !=
	    DDI_SUCCESS) {
		DDI_INTR_IMPLDBG((CE_CONT, "apic_pci_msi_enable_vector: "
		    "pci_msi_configure failed\n"));
		return (PSM_FAILURE);
	}

	return (PSM_SUCCESS);
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

	/* It has to be contiguous */
	for (i = lowest; i < highest; i++) {
		count = 0;
		while ((apic_vector_to_irq[i] == APIC_RESV_IRQ) &&
			(i < highest)) {
			if ((i == T_FASTTRAP) || (i == APIC_SPUR_INTR))
				break;
			count++;
			i++;
		}
		if (count > navail)
			navail = count;
	}
	return (navail);
}

static uchar_t
apic_find_multi_vectors(int pri, int count)
{
	int	lowest, highest, i, navail, start;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_find_mult: pri: %x, count: %x\n",
	    pri, count));

	highest = apic_ipltopri[pri] + APIC_VECTOR_MASK;
	lowest = apic_ipltopri[pri - 1] + APIC_VECTOR_PER_IPL;
	navail = 0;

	/* It has to be contiguous */
	for (i = lowest; i < highest; i++) {
		navail = 0;
		start = i;
		while ((apic_vector_to_irq[i] == APIC_RESV_IRQ) &&
			(i < highest)) {
			if ((i == T_FASTTRAP) || (i == APIC_SPUR_INTR))
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
		if ((irqp = apic_irq_table[i]) == NULL)
			continue;
		if ((irqp->airq_dip == dip) &&
		    (irqp->airq_origirq == ispec->intrspec_vec) &&
		    (irqp->airq_ipl == ispec->intrspec_pri)) {
			if (DDI_INTR_IS_MSI_OR_MSIX(type)) {
				if (APIC_IS_MSI_OR_MSIX_INDEX(irqp->
				    airq_mps_intr_index))
					return (irqp);
			} else
				return (irqp);
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
	volatile int32_t 	*ioapic;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_get_pending: irqp: %p, cpuid: %x "
	    "type: %x\n", (void *)irqp, irqp->airq_cpu & ~IRQ_USER_BOUND,
	    type));

	/* need to get on the bound cpu */
	mutex_enter(&cpu_lock);
	affinity_set(irqp->airq_cpu & ~IRQ_USER_BOUND);

	index = irqp->airq_vector / 32;
	bit = irqp->airq_vector % 32;
	irr = apicadr[APIC_IRR_REG + index];

	affinity_clear();
	mutex_exit(&cpu_lock);

	pending = (irr & (1 << bit)) ? 1 : 0;
	if (!pending && (type == DDI_INTR_TYPE_FIXED)) {
		/* check I/O APIC for fixed interrupt */
		intin_no = irqp->airq_intin_no;
		ioapic = apicioadr[irqp->airq_ioapicindex];
		pending = (READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic, intin_no) &
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
	int			iflag;
	int32_t			rdt_entry;
	volatile int32_t 	*ioapic;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_clear_mask: irqp: %p\n",
	    (void *)irqp));

	intin_no = irqp->airq_intin_no;
	ioapic = apicioadr[irqp->airq_ioapicindex];

	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	rdt_entry = READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic, intin_no);

	/* clear mask */
	WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic, intin_no,
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
	volatile int32_t 	*ioapic;
	int			iflag;
	int32_t			rdt_entry;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_set_mask: irqp: %p\n", (void *)irqp));

	intin_no = irqp->airq_intin_no;
	ioapic = apicioadr[irqp->airq_ioapicindex];

	iflag = intr_clear();

	lock_set(&apic_ioapic_lock);

	rdt_entry = READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic, intin_no);

	/* mask it */
	WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic, intin_no,
	    (AV_MASK | rdt_entry));

	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);
}


/*
 * This function allocate "count" vector(s) for the given "dip/pri/type"
 */
int
apic_alloc_vectors(dev_info_t *dip, int inum, int count, int pri, int type)
{
	int	rcount, i;
	uchar_t	start, irqno, cpu;
	short	idx;
	major_t	major;
	apic_irq_t	*irqptr;

	/* for MSI/X only */
	if (!DDI_INTR_IS_MSI_OR_MSIX(type))
		return (0);

	DDI_INTR_IMPLDBG((CE_CONT, "apic_alloc_vectors: dip=0x%p type=%d "
	    "inum=0x%x  pri=0x%x count=0x%x\n",
	    (void *)dip, type, inum, pri, count));

	if (count > 1) {
		if (apic_multi_msi_enable == 0)
			count = 1;
		else if (count > apic_multi_msi_max)
			count = apic_multi_msi_max;
	}

	if ((rcount = apic_navail_vector(dip, pri)) > count)
		rcount = count;

	mutex_enter(&airq_mutex);

	for (start = 0; rcount > 0; rcount--) {
		if ((start = apic_find_multi_vectors(pri, rcount)) != 0)
			break;
	}

	if (start == 0) {
		/* no vector available */
		mutex_exit(&airq_mutex);
		return (0);
	}

	idx = (short)((type == DDI_INTR_TYPE_MSI) ? MSI_INDEX : MSIX_INDEX);
	major = (dip != NULL) ? ddi_name_to_major(ddi_get_name(dip)) : 0;
	for (i = 0; i < rcount; i++) {
		if ((irqno = apic_allocate_irq(apic_first_avail_irq)) ==
		    (uchar_t)-1) {
			mutex_exit(&airq_mutex);
			DDI_INTR_IMPLDBG((CE_CONT, "apic_alloc_vectors: "
			    "apic_allocate_irq failed\n"));
			return (i);
		}
		apic_max_device_irq = max(irqno, apic_max_device_irq);
		apic_min_device_irq = min(irqno, apic_min_device_irq);
		irqptr = apic_irq_table[irqno];
#ifdef	DEBUG
		if (apic_vector_to_irq[start + i] != APIC_RESV_IRQ)
			DDI_INTR_IMPLDBG((CE_CONT, "apic_alloc_vectors: "
			    "apic_vector_to_irq is not APIC_RESV_IRQ\n"));
#endif
		apic_vector_to_irq[start + i] = (uchar_t)irqno;

		irqptr->airq_vector = (uchar_t)(start + i);
		irqptr->airq_ioapicindex = (uchar_t)inum;	/* start */
		irqptr->airq_intin_no = (uchar_t)rcount;
		irqptr->airq_ipl = pri;
		irqptr->airq_vector = start + i;
		irqptr->airq_origirq = (uchar_t)(inum + i);
		irqptr->airq_share_id = 0;
		irqptr->airq_mps_intr_index = idx;
		irqptr->airq_dip = dip;
		irqptr->airq_major = major;
		if (i == 0) /* they all bound to the same cpu */
			cpu = irqptr->airq_cpu = apic_bind_intr(dip, irqno,
				0xff, 0xff);
		else
			irqptr->airq_cpu = cpu;
		DDI_INTR_IMPLDBG((CE_CONT, "apic_alloc_vectors: irq=0x%x "
		    "dip=0x%p vector=0x%x origirq=0x%x pri=0x%x\n", irqno,
		    (void *)irqptr->airq_dip, irqptr->airq_vector,
		    irqptr->airq_origirq, pri));
	}
	mutex_exit(&airq_mutex);
	return (rcount);
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
 * check whether the system supports MSI
 *
 * If PCI-E capability is found, then this must be a PCI-E system.
 * Since MSI is required for PCI-E system, it returns PSM_SUCCESS
 * to indicate this system supports MSI.
 */
int
apic_check_msi_support(dev_info_t *dip)
{

	dev_info_t *rootdip;
	char dev_type[16];
	int dev_len;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_check_msi_support: dip: 0x%p\n",
	    (void *)dip));

	/* check whether the device or its ancestors have PCI-E capability */
	for (rootdip = ddi_root_node(); dip != rootdip;
	    dip = ddi_get_parent(dip)) {

		DDI_INTR_IMPLDBG((CE_CONT, "apic_check_msi_support: dip: 0x%p,"
		    " driver: %s, binding: %s, nodename: %s\n", (void *)dip,
		    ddi_driver_name(dip), ddi_binding_name(dip),
		    ddi_node_name(dip)));
		dev_len = sizeof (dev_type);
		if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
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

int
apic_get_vector_intr_info(int vecirq, apic_get_intr_t *intr_params_p)
{
	struct autovec *av_dev;
	uchar_t irq;
	int i;

	/* Sanity check the vector/irq argument. */
	ASSERT((vecirq >= 0) || (vecirq <= APIC_MAX_VECTOR));

	mutex_enter(&airq_mutex);

	/*
	 * Convert the vecirq arg to an irq using vector_to_irq table
	 * if the arg is a vector.  Pass thru if already an irq.
	 */
	if ((intr_params_p->avgi_req_flags & PSMGI_INTRBY_FLAGS) ==
	    PSMGI_INTRBY_VEC)
		irq = apic_vector_to_irq[vecirq];
	else
		irq = vecirq;

	if (intr_params_p->avgi_req_flags & PSMGI_REQ_CPUID) {

		/* Get the (temp) cpu from apic_irq table, indexed by irq. */
		intr_params_p->avgi_cpu_id = apic_irq_table[irq]->airq_temp_cpu;

		/* Return user bound info for intrd. */
		if (intr_params_p->avgi_cpu_id & IRQ_USER_BOUND) {
			intr_params_p->avgi_cpu_id &= ~IRQ_USER_BOUND;
			intr_params_p->avgi_cpu_id |= PSMGI_CPU_USER_BOUND;
		}
	}

	if (intr_params_p->avgi_req_flags & PSMGI_REQ_VECTOR) {
		intr_params_p->avgi_vector = apic_irq_table[irq]->airq_vector;
	}

	if (intr_params_p->avgi_req_flags &
	    (PSMGI_REQ_NUM_DEVS | PSMGI_REQ_GET_DEVS)) {
		/* Get number of devices from apic_irq table shared field. */
		intr_params_p->avgi_num_devs = apic_irq_table[irq]->airq_share;
	}

	if (intr_params_p->avgi_req_flags &  PSMGI_REQ_GET_DEVS) {

		intr_params_p->avgi_req_flags  |= PSMGI_REQ_NUM_DEVS;

		/* Some devices have NULL dip.  Don't count these. */
		if (intr_params_p->avgi_num_devs > 0) {
			for (i = 0, av_dev = autovect[irq].avh_link;
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
			for (i = 0, av_dev = autovect[irq].avh_link;
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
	int		cap, ret;
	int		count_vec;
	int		cpu;
	int		old_priority;
	int		new_priority;
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
			if (apic_check_msi_support(dip) == PSM_SUCCESS)
				apic_support_msi = 1;
			else
				apic_support_msi = -1;
		}
		if (apic_support_msi == 1)
			*result = hdlp->ih_type;
		else
			*result = hdlp->ih_type & ~(DDI_INTR_TYPE_MSI |
			    DDI_INTR_TYPE_MSIX);
		break;
	case PSM_INTR_OP_ALLOC_VECTORS:
		*result = apic_alloc_vectors(dip, hdlp->ih_inum,
		    hdlp->ih_scratch1, hdlp->ih_pri, hdlp->ih_type);
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
		if ((irqp = apic_find_irq(dip, ispec, hdlp->ih_type)) == NULL)
			return (PSM_FAILURE);
		*result = irqp->airq_share ? 1: 0;
		break;
	case PSM_INTR_OP_SET_PRI:
		old_priority = hdlp->ih_pri;	/* save old value */
		new_priority = *(int *)result;	/* try the new value */

		/* First, check if "hdlp->ih_scratch1" vectors exist? */
		if (apic_navail_vector(dip, new_priority) < hdlp->ih_scratch1)
			return (PSM_FAILURE);

		/* Now allocate the vectors */
		count_vec = apic_alloc_vectors(dip, hdlp->ih_inum,
		    hdlp->ih_scratch1, new_priority, hdlp->ih_type);

		/* Did we get fewer vectors? */
		if (count_vec != hdlp->ih_scratch1) {
			apic_free_vectors(dip, hdlp->ih_inum, count_vec,
			    new_priority, hdlp->ih_type);
			return (PSM_FAILURE);
		}

		/* Finally, free the previously allocated vectors */
		apic_free_vectors(dip, hdlp->ih_inum, count_vec,
		    old_priority, hdlp->ih_type);
		hdlp->ih_pri = new_priority; /* set the new value */
		break;
	case PSM_INTR_OP_SET_CPU:
		/*
		 * The interrupt handle given here has been allocated
		 * specifically for this command, and ih_private carries
		 * a CPU value.
		 */
		cpu = (int)(intptr_t)hdlp->ih_private;

		if (!apic_cpu_in_range(cpu)) {
			*result = EINVAL;
			return (PSM_FAILURE);
		}

		mutex_enter(&airq_mutex);

		/* Convert the vector to the irq using vector_to_irq table. */
		irqp = apic_irq_table[apic_vector_to_irq[hdlp->ih_vector]];
		if (irqp == NULL) {
			mutex_exit(&airq_mutex);
			*result = ENXIO;
			return (PSM_FAILURE);
		}
		ret = apic_rebind_all(irqp, cpu, 1);
		mutex_exit(&airq_mutex);
		if (ret) {
			*result = EIO;
			return (PSM_FAILURE);
		}
		*result = 0;
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
	case PSM_INTR_OP_SET_CAP:
	default:
		return (PSM_FAILURE);
	}
	return (PSM_SUCCESS);
}
