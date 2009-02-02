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
 * Portions Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2008, Intel Corporation.
 * All rights reserved.
 */

/*
 * Intel IOMMU implementaion
 */
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/ddidmareq.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddifm.h>
#include <sys/sunndi.h>
#include <sys/debug.h>
#include <sys/fm/protocol.h>
#include <sys/note.h>
#include <sys/apic.h>
#include <vm/hat_i86.h>
#include <sys/smp_impldefs.h>
#include <sys/spl.h>
#include <sys/archsystm.h>
#include <sys/x86_archext.h>
#include <sys/rootnex.h>
#include <sys/avl.h>
#include <sys/bootconf.h>
#include <sys/bootinfo.h>
#include <sys/intel_iommu.h>
#include <sys/atomic.h>
#include <sys/iommulib.h>

/*
 * internal variables
 *   iommu_state	- the list of iommu structures
 *   reserve_memory	- the list of reserved regions
 *   page_num		- the count of pages for iommu page tables
 */
static list_t iommu_states;
static list_t reserve_memory;
static uint_t page_num;

/*
 * record some frequently used dips
 */
static dev_info_t *pci_top_devinfo = NULL;
static dev_info_t *isa_top_devinfo = NULL;
static dev_info_t *lpc_devinfo = NULL;

/*
 * dvma cache related variables
 */
static uint_t dvma_cache_high = 64;
static dvma_cookie_head_t cookie_cache[MAX_COOKIE_CACHE_SIZE];

/* ioapic info for interrupt remapping */
static ioapic_iommu_info_t *ioapic_iommu_infos[MAX_IO_APIC];

/*
 * switch to turn on/off the gfx dma remapping unit,
 * this is used when there is a dedicated drhd for the
 * gfx
 */
int gfx_drhd_disable = 0;
static dev_info_t *gfx_devinfo = NULL;

/*
 * switch to disable dmar remapping unit, even the initiation work has
 * been finished
 */
int dmar_drhd_disable = 0;

static char *dmar_fault_reason[] = {
	"Reserved",
	"The present field in root-entry is Clear",
	"The present field in context-entry is Clear",
	"Hardware detected invalid programming of a context-entry",
	"The DMA request attempted to access an address beyond max support",
	"The Write field in a page-table entry is Clear when DMA write",
	"The Read field in a page-table entry is Clear when DMA read",
	"Access the next level page table resulted in error",
	"Access the root-entry table resulted in error",
	"Access the context-entry table resulted in error",
	"Reserved field not initialized to zero in a present root-entry",
	"Reserved field not initialized to zero in a present context-entry",
	"Reserved field not initialized to zero in a present page-table entry",
	"DMA blocked due to the Translation Type field in context-entry",
	"Incorrect fault event reason number"
};

#define	DMAR_MAX_REASON_NUMBER	(14)

#define	IOMMU_ALLOC_RESOURCE_DELAY	drv_usectohz(5000)

/*
 * QS field of Invalidation Queue Address Register
 * the size of invalidation queue is 1 << (qinv_iqa_qs + 8)
 */
static uint_t qinv_iqa_qs = 6;

/*
 * the invalidate desctiptor type of queued invalidation interface
 */
static char *qinv_dsc_type[] = {
	"Reserved",
	"Context Cache Invalidate Descriptor",
	"IOTLB Invalidate Descriptor",
	"Device-IOTLB Invalidate Descriptor",
	"Interrupt Entry Cache Invalidate Descriptor",
	"Invalidation Wait Descriptor",
	"Incorrect queue invalidation type"
};

#define	QINV_MAX_DSC_TYPE	(6)

/*
 * S field of the Interrupt Remapping Table Address Register
 * the size of the interrupt remapping table is 1 << (intrr_irta_s + 1)
 */
static uint_t intrr_irta_s = INTRR_MAX_IRTA_SIZE;

/*
 * whether disable interrupt remapping in LOCAL_APIC mode
 */
static int intrr_only_for_x2apic = 1;

/*
 * whether verify the source id of interrupt request
 */
static int intrr_enable_sid_verify = 0;

/* the fault reason for interrupt remapping */
static char *intrr_fault_reason[] = {
	"reserved field set in IRTE",
	"interrupt_index exceed the intr-remap table size",
	"present field in IRTE is clear",
	"hardware access intr-remap table address resulted in error",
	"reserved field set in IRTE, inlcude various conditional",
	"hardware blocked an interrupt request in Compatibility format",
	"remappable interrupt request blocked due to verification failure"
};

#define	INTRR_MAX_REASON_NUMBER	(6)

/*
 * the queued invalidation interface functions
 */
static int iommu_qinv_init(intel_iommu_state_t *iommu);
static void iommu_qinv_fini(intel_iommu_state_t *iommu);
static void iommu_qinv_enable(intel_iommu_state_t *iommu);
static void qinv_submit_inv_dsc(intel_iommu_state_t *iommu, inv_dsc_t *dsc);
static void qinv_cc_common(intel_iommu_state_t *iommu, uint8_t function_mask,
    uint16_t source_id, uint_t domain_id, ctt_inv_g_t type);
static void qinv_iotlb_common(intel_iommu_state_t *iommu, uint_t domain_id,
    uint64_t addr, uint_t am, uint_t hint, tlb_inv_g_t type);
static void qinv_iec_common(intel_iommu_state_t *iommu, uint_t iidx,
    uint_t im, uint_t g);
static void qinv_iec_global(intel_iommu_state_t *iommu);
static void qinv_iec_single(intel_iommu_state_t *iommu, uint_t iidx);
static void qinv_iec(intel_iommu_state_t *iommu, uint_t iidx, uint_t cnt);
static uint_t qinv_alloc_sync_mem_entry(intel_iommu_state_t *iommu);
static void qinv_wait_async_unfence(intel_iommu_state_t *iommu,
    iotlb_pend_node_t *node);
static void qinv_wait_sync(intel_iommu_state_t *iommu);
static int qinv_wait_async_finish(intel_iommu_state_t *iommu, int *count);
static void qinv_cc_fsi(intel_iommu_state_t *iommu, uint8_t function_mask,
    uint16_t source_id, uint_t domain_id);
static void qinv_cc_dsi(intel_iommu_state_t *iommu, uint_t domain_id);
static void qinv_cc_gbl(intel_iommu_state_t *iommu);
static void qinv_iotlb_psi(intel_iommu_state_t *iommu, uint_t domain_id,
    uint64_t dvma, uint_t count, uint_t hint);
static void qinv_iotlb_dsi(intel_iommu_state_t *iommu, uint_t domain_id);
static void qinv_iotlb_gbl(intel_iommu_state_t *iommu);
static void qinv_plant_wait(intel_iommu_state_t *iommu,
    iommu_dvma_cookie_t *dcookies, uint_t count, uint_t array_size);
static void qinv_reap_wait(intel_iommu_state_t *iommu);

/*LINTED*/
static void qinv_wait_async_fence(intel_iommu_state_t *iommu);
/*LINTED*/
static void qinv_dev_iotlb_common(intel_iommu_state_t *iommu, uint16_t sid,
    uint64_t addr, uint_t size, uint_t max_invs_pd);

/* interrupt remapping related functions */
static int intr_remap_init_unit(intel_iommu_state_t *iommu);
static void intr_remap_fini_unit(intel_iommu_state_t *iommu);
static void intr_remap_enable_unit(intel_iommu_state_t *iommu);
static uint_t bitset_find_free(bitset_t *, uint_t);
static uint_t bitset_find_multi_free(bitset_t *, uint_t, uint_t);
static int intrr_tbl_alloc_entry(intr_remap_tbl_state_t *);
static int intrr_tbl_alloc_multi_entries(intr_remap_tbl_state_t *, uint_t);
static void get_ioapic_iommu_info(void);
static void intr_remap_get_iommu(apic_irq_t *);
static void intr_remap_get_sid(apic_irq_t *);

static int intr_remap_init(int);
static void intr_remap_enable(void);
static void intr_remap_alloc_entry(apic_irq_t *);
static void intr_remap_map_entry(apic_irq_t *, void *);
static void intr_remap_free_entry(apic_irq_t *);
static void intr_remap_record_rdt(apic_irq_t *, ioapic_rdt_t *);
static void intr_remap_record_msi(apic_irq_t *, msi_regs_t *);

static struct apic_intrr_ops intr_remap_ops = {
	intr_remap_init,
	intr_remap_enable,
	intr_remap_alloc_entry,
	intr_remap_map_entry,
	intr_remap_free_entry,
	intr_remap_record_rdt,
	intr_remap_record_msi,
};

/* apic mode, APIC/X2APIC */
static int intrr_apic_mode = LOCAL_APIC;

/*
 * cpu_clflush()
 *   flush the cpu cache line
 */
static void
cpu_clflush(caddr_t addr, uint_t size)
{
	uint_t i;

	for (i = 0; i < size; i += x86_clflush_size) {
		clflush_insn(addr+i);
	}

	mfence_insn();
}

/*
 * iommu_page_init()
 *   do some init work for the iommu page allocator
 */
static void
iommu_page_init(void)
{
	page_num = 0;
}

/*
 * iommu_get_page()
 *   get a 4k iommu page, and zero out it
 */
static paddr_t
iommu_get_page(intel_iommu_state_t *iommu, int kmflag)
{
	paddr_t paddr;
	caddr_t vaddr;

	paddr = iommu_page_alloc(kmflag);
	vaddr = iommu_page_map(paddr);
	bzero(vaddr, IOMMU_PAGE_SIZE);
	iommu->iu_dmar_ops->do_clflush(vaddr, IOMMU_PAGE_SIZE);
	iommu_page_unmap(vaddr);

	page_num++;

	return (paddr);
}

/*
 * iommu_free_page()
 *   free the iommu page allocated with iommu_get_page
 */
static void
iommu_free_page(paddr_t paddr)
{
	iommu_page_free(paddr);
	page_num--;
}

#define	iommu_get_reg32(iommu, offset)	ddi_get32((iommu)->iu_reg_handle, \
		(uint32_t *)(iommu->iu_reg_address + (offset)))
#define	iommu_get_reg64(iommu, offset)	ddi_get64((iommu)->iu_reg_handle, \
		(uint64_t *)(iommu->iu_reg_address + (offset)))
#define	iommu_put_reg32(iommu, offset, val)	ddi_put32\
		((iommu)->iu_reg_handle, \
		(uint32_t *)(iommu->iu_reg_address + (offset)), val)
#define	iommu_put_reg64(iommu, offset, val)	ddi_put64\
		((iommu)->iu_reg_handle, \
		(uint64_t *)(iommu->iu_reg_address + (offset)), val)

/*
 * calculate_agaw()
 *   calculate agaw from gaw
 */
static int
calculate_agaw(int gaw)
{
	int r, agaw;

	r = (gaw - 12) % 9;

	if (r == 0)
		agaw = gaw;
	else
		agaw = gaw + 9 - r;

	if (agaw > 64)
		agaw = 64;

	return (agaw);
}

/*
 * destroy_iommu_state()
 *   destory an iommu state
 */
static void
destroy_iommu_state(intel_iommu_state_t *iommu)
{
	iommu_free_page(iommu->iu_root_entry_paddr);
	iommu_rscs_fini(&(iommu->iu_domain_id_hdl));
	mutex_destroy(&(iommu->iu_reg_lock));
	mutex_destroy(&(iommu->iu_root_context_lock));
	ddi_regs_map_free(&(iommu->iu_reg_handle));
	kmem_free(iommu->iu_dmar_ops, sizeof (struct dmar_ops));

	if (iommu->iu_inv_queue) {
		iommu_qinv_fini(iommu);
	}

	if (iommu->iu_intr_remap_tbl) {
		intr_remap_fini_unit(iommu);
	}

	kmem_free(iommu, sizeof (intel_iommu_state_t));
}

/*
 * iommu_update_stats - update iommu private kstat counters
 *
 * This routine will dump and reset the iommu's internal
 * statistics counters. The current stats dump values will
 * be sent to the kernel status area.
 */
static int
iommu_update_stats(kstat_t *ksp, int rw)
{
	intel_iommu_state_t *iommu;
	iommu_kstat_t *iommu_ksp;
	const char *state;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	iommu = (intel_iommu_state_t *)ksp->ks_private;
	ASSERT(iommu != NULL);
	iommu_ksp = (iommu_kstat_t *)ksp->ks_data;
	ASSERT(iommu_ksp != NULL);

	state = (iommu->iu_enabled & DMAR_ENABLE) ? "enabled" : "disabled";
	(void) strcpy(iommu_ksp->is_dmar_enabled.value.c, state);
	state = (iommu->iu_enabled & QINV_ENABLE) ? "enabled" : "disabled";
	(void) strcpy(iommu_ksp->is_qinv_enabled.value.c, state);
	state = (iommu->iu_enabled & INTRR_ENABLE) ?
	    "enabled" : "disabled";
	(void) strcpy(iommu_ksp->is_intrr_enabled.value.c, state);
	iommu_ksp->is_iotlb_psi.value.ui64 =
	    iommu->iu_statistics.st_iotlb_psi;
	iommu_ksp->is_iotlb_domain.value.ui64 =
	    iommu->iu_statistics.st_iotlb_domain;
	iommu_ksp->is_iotlb_global.value.ui64 =
	    iommu->iu_statistics.st_iotlb_global;
	iommu_ksp->is_write_buffer.value.ui64 =
	    iommu->iu_statistics.st_write_buffer;
	iommu_ksp->is_context_cache.value.ui64 =
	    iommu->iu_statistics.st_context_cache;
	iommu_ksp->is_wait_complete_us.value.ui64 =
	    drv_hztousec(iommu->iu_statistics.st_wait_complete_us);
	iommu_ksp->is_domain_alloc.value.ui64 =
	    iommu->iu_statistics.st_domain_alloc;
	iommu_ksp->is_page_used.value.ui64 = page_num;

	return (0);
}

/*
 * iommu_init_stats - initialize kstat data structures
 *
 * This routine will create and initialize the iommu private
 * statistics counters.
 */
int
iommu_init_stats(intel_iommu_state_t *iommu)
{
	kstat_t *ksp;
	iommu_kstat_t *iommu_ksp;

	/*
	 * Create and init kstat
	 */
	ksp = kstat_create("rootnex", 0,
	    ddi_node_name(iommu->iu_drhd->di_dip),
	    "misc", KSTAT_TYPE_NAMED,
	    sizeof (iommu_kstat_t) / sizeof (kstat_named_t), 0);

	if (ksp == NULL) {
		cmn_err(CE_WARN,
		    "Could not create kernel statistics for %s",
		    ddi_node_name(iommu->iu_drhd->di_dip));
		return (DDI_FAILURE);
	}

	iommu->iu_kstat = ksp;
	iommu_ksp = (iommu_kstat_t *)ksp->ks_data;

	/*
	 * Initialize all the statistics
	 */
	kstat_named_init(&(iommu_ksp->is_dmar_enabled), "dmar_enable",
	    KSTAT_DATA_CHAR);
	kstat_named_init(&(iommu_ksp->is_qinv_enabled), "qinv_enable",
	    KSTAT_DATA_CHAR);
	kstat_named_init(&(iommu_ksp->is_intrr_enabled), "intrr_enable",
	    KSTAT_DATA_CHAR);
	kstat_named_init(&(iommu_ksp->is_iotlb_psi), "iotlb_psi",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&(iommu_ksp->is_iotlb_domain), "iotlb_domain",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&(iommu_ksp->is_iotlb_global), "iotlb_global",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&(iommu_ksp->is_write_buffer), "write_buffer",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&(iommu_ksp->is_context_cache), "context_cache",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&(iommu_ksp->is_wait_complete_us), "wait_complete_us",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&(iommu_ksp->is_page_used), "physical_page_used",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&(iommu_ksp->is_domain_alloc), "domain_allocated",
	    KSTAT_DATA_UINT64);

	/*
	 * Function to provide kernel stat update on demand
	 */
	ksp->ks_update = iommu_update_stats;

	/*
	 * Pointer into provider's raw statistics
	 */
	ksp->ks_private = (void *)iommu;

	/*
	 * Add kstat to systems kstat chain
	 */
	kstat_install(ksp);

	return (DDI_SUCCESS);
}

/*
 * iommu_intr_handler()
 *   the fault event handler for a single drhd
 */
static int
iommu_intr_handler(intel_iommu_state_t *iommu)
{
	uint32_t status;
	int index, fault_reg_offset;
	int max_fault_index;

	mutex_enter(&(iommu->iu_reg_lock));

	/* read the fault status */
	status = iommu_get_reg32(iommu, IOMMU_REG_FAULT_STS);

	/* check if we have a pending fault for this IOMMU */
	if (!(status & IOMMU_FAULT_STS_PPF)) {
		goto no_primary_faults;
	}

	/*
	 * handle all primary pending faults
	 */
	index = IOMMU_FAULT_GET_INDEX(status);
	max_fault_index =  IOMMU_CAP_GET_NFR(iommu->iu_capability) - 1;
	fault_reg_offset = IOMMU_CAP_GET_FRO(iommu->iu_capability);

	_NOTE(CONSTCOND)
	while (1) {
		uint64_t val;
		uint8_t fault_reason;
		uint8_t fault_type;
		uint16_t sid;
		uint64_t pg_addr;
		uint64_t iidx;

		/* read the higher 64bits */
		val = iommu_get_reg64(iommu,
		    fault_reg_offset + index * 16 + 8);

		/* check if pending fault */
		if (!IOMMU_FRR_GET_F(val))
			break;

		/* get the fault reason, fault type and sid */
		fault_reason = IOMMU_FRR_GET_FR(val);
		fault_type = IOMMU_FRR_GET_FT(val);
		sid = IOMMU_FRR_GET_SID(val);

		/* read the first 64bits */
		val = iommu_get_reg64(iommu,
		    fault_reg_offset + index * 16);
		pg_addr = val & IOMMU_PAGE_MASK;
		iidx = val >> 48;

		/* clear the fault */
		iommu_put_reg32(iommu, fault_reg_offset + index * 16 + 12,
		    (((uint32_t)1) << 31));

		/* report the fault info */
		if (fault_reason < 0x20) {
			/* dmar-remapping fault */
			cmn_err(CE_WARN,
			    "%s generated a fault event when translating "
			    "DMA %s\n"
			    "\t on address 0x%" PRIx64 " for PCI(%d, %d, %d), "
			    "the reason is:\n\t %s",
			    ddi_node_name(iommu->iu_drhd->di_dip),
			    fault_type ? "read" : "write", pg_addr,
			    (sid >> 8) & 0xff, (sid >> 3) & 0x1f, sid & 0x7,
			    dmar_fault_reason[MIN(fault_reason,
			    DMAR_MAX_REASON_NUMBER)]);
		} else if (fault_reason < 0x27) {
			/* intr-remapping fault */
			cmn_err(CE_WARN,
			    "%s generated a fault event when translating "
			    "interrupt request\n"
			    "\t on index 0x%" PRIx64 " for PCI(%d, %d, %d), "
			    "the reason is:\n\t %s",
			    ddi_node_name(iommu->iu_drhd->di_dip),
			    iidx,
			    (sid >> 8) & 0xff, (sid >> 3) & 0x1f, sid & 0x7,
			    intrr_fault_reason[MIN((fault_reason - 0x20),
			    INTRR_MAX_REASON_NUMBER)]);
		}

		index++;
		if (index > max_fault_index)
			index = 0;
	}

no_primary_faults:

	/*
	 * handle queued invalidation interface errors
	 */
	if (status & IOMMU_FAULT_STS_IQE) {
		uint64_t	head;
		inv_dsc_t	*dsc;

		head = QINV_IQA_HEAD(
		    iommu_get_reg64(iommu, IOMMU_REG_INVAL_QH));
		dsc = (inv_dsc_t *)(iommu->iu_inv_queue->iq_table.vaddr
		    + (head * QINV_ENTRY_SIZE));

		/* report the error */
		cmn_err(CE_WARN,
		    "%s generated a fault when fetching a descriptor from the\n"
		    "\tinvalidation queue, or detects that the fetched\n"
		    "\tdescriptor is invalid. The head register is "
		    "0x%" PRIx64 ",\n"
		    "\tthe type is %s\n",
		    ddi_node_name(iommu->iu_drhd->di_dip), head,
		    qinv_dsc_type[MIN(INV_DSC_TYPE(dsc),
		    QINV_MAX_DSC_TYPE)]);
	}

	/*
	 * Hardware received an unexpected or invalid Device-IOTLB
	 * invalidation completion
	 */
	if (status & IOMMU_FAULT_STS_ICE) {
		cmn_err(CE_WARN,
		    "Hardware received an unexpected or invalid "
		    "Device-IOTLB invalidation completion.\n");
	}

	/*
	 * Hardware detected a Device-IOTLB invalidation
	 * completion time-out
	 */
	if (status & IOMMU_FAULT_STS_ITE) {
		cmn_err(CE_WARN,
		    "Hardware detected a Device-IOTLB invalidation "
		    "completion time-out.\n");
	}

	/* clear the fault */
	iommu_put_reg32(iommu, IOMMU_REG_FAULT_STS, 1);

	mutex_exit(&(iommu->iu_reg_lock));

	return (1);
}

/*
 * intel_iommu_intr_handler()
 *   call iommu_intr_handler for each iommu
 */
static uint_t
intel_iommu_intr_handler(caddr_t arg)
{
	int claimed = 0;
	intel_iommu_state_t *iommu;
	list_t *lp = (list_t *)arg;

	for_each_in_list(lp, iommu) {
		claimed |= iommu_intr_handler(iommu);
	}

	return (claimed ? DDI_INTR_CLAIMED : DDI_INTR_UNCLAIMED);
}

/*
 * intel_iommu_add_intr()
 *   the interface to hook dmar interrupt handler
 */
static void
intel_iommu_add_intr(void)
{
	int ipl, irq, vect;
	intel_iommu_state_t *iommu;
	uint32_t msi_addr, msi_data;
	ipl = IOMMU_INTR_IPL;

	irq = psm_get_ipivect(ipl, -1);
	vect = apic_irq_table[irq]->airq_vector;
	(void) add_avintr((void *)NULL, ipl, (avfunc)(intel_iommu_intr_handler),
	    "iommu intr", irq, (caddr_t)&iommu_states, NULL, NULL, NULL);

	msi_addr = (MSI_ADDR_HDR |
	    (MSI_ADDR_RH_FIXED << MSI_ADDR_RH_SHIFT) |
	    (MSI_ADDR_DM_PHYSICAL << MSI_ADDR_DM_SHIFT) |
	    (apic_cpus[0].aci_local_id & 0xFF));
	msi_data = ((MSI_DATA_TM_EDGE << MSI_DATA_TM_SHIFT) | vect);

	for_each_in_list(&iommu_states, iommu) {
		(void) iommu_intr_handler(iommu);
		mutex_enter(&(iommu->iu_reg_lock));
		iommu_put_reg32(iommu, IOMMU_REG_FEVNT_ADDR, msi_addr);
		if (intrr_apic_mode == LOCAL_X2APIC) {
			iommu_put_reg32(iommu, IOMMU_REG_FEVNT_UADDR,
			    apic_cpus[0].aci_local_id & 0xFFFFFF00);
		} else {
			iommu_put_reg32(iommu, IOMMU_REG_FEVNT_UADDR, 0);
		}
		iommu_put_reg32(iommu, IOMMU_REG_FEVNT_DATA, msi_data);
		iommu_put_reg32(iommu, IOMMU_REG_FEVNT_CON, 0);
		mutex_exit(&(iommu->iu_reg_lock));
	}
}

/*
 * wait max 60s for the hardware completion
 */
#define	IOMMU_WAIT_TIME		60000000
#define	iommu_wait_completion(iommu, offset, getf, completion, status) \
{ \
	clock_t stick = ddi_get_lbolt(); \
	clock_t ntick; \
	_NOTE(CONSTCOND) \
	while (1) { \
		status = getf(iommu, offset); \
		ntick = ddi_get_lbolt(); \
		if (completion) {\
			atomic_add_64\
			    (&(iommu->iu_statistics.st_wait_complete_us),\
			    ntick - stick);\
			break; \
		} \
		if (ntick - stick >= drv_usectohz(IOMMU_WAIT_TIME)) { \
			cmn_err(CE_PANIC, \
			    "iommu wait completion time out\n"); \
		} else { \
			iommu_cpu_nop();\
		}\
	}\
}

/*
 * dmar_flush_write_buffer()
 *   flush the write buffer
 */
static void
dmar_flush_write_buffer(intel_iommu_state_t *iommu)
{
	uint32_t status;

	mutex_enter(&(iommu->iu_reg_lock));
	iommu_put_reg32(iommu, IOMMU_REG_GLOBAL_CMD,
	    iommu->iu_global_cmd_reg | IOMMU_GCMD_WBF);
	iommu_wait_completion(iommu, IOMMU_REG_GLOBAL_STS,
	    iommu_get_reg32, !(status & IOMMU_GSTS_WBFS), status);
	mutex_exit(&(iommu->iu_reg_lock));

	/* record the statistics */
	atomic_inc_64(&(iommu->iu_statistics.st_write_buffer));
}

/*
 * dmar_flush_iotlb_common()
 *   flush the iotlb cache
 */
static void
dmar_flush_iotlb_common(intel_iommu_state_t *iommu, uint_t domain_id,
    uint64_t addr, uint_t am, uint_t hint, tlb_inv_g_t type)
{
	uint64_t command = 0, iva = 0, status;
	uint_t iva_offset, iotlb_offset;

	iva_offset = IOMMU_ECAP_GET_IRO(iommu->iu_excapability);
	iotlb_offset = iva_offset + 8;

	/*
	 * prepare drain read/write command
	 */
	if (IOMMU_CAP_GET_DWD(iommu->iu_capability)) {
		command |= TLB_INV_DRAIN_WRITE;
	}

	if (IOMMU_CAP_GET_DRD(iommu->iu_capability)) {
		command |= TLB_INV_DRAIN_READ;
	}

	/*
	 * if the hardward doesn't support page selective invalidation, we
	 * will use domain type. Otherwise, use global type
	 */
	switch (type) {
	case TLB_INV_G_PAGE:
		if (!IOMMU_CAP_GET_PSI(iommu->iu_capability) ||
		    am > IOMMU_CAP_GET_MAMV(iommu->iu_capability) ||
		    addr & IOMMU_PAGE_OFFSET) {
			goto ignore_psi;
		}
		command |= TLB_INV_PAGE | TLB_INV_IVT |
		    TLB_INV_DID(domain_id);
		iva = addr | am | TLB_IVA_HINT(hint);
		break;
ignore_psi:
	case TLB_INV_G_DOMAIN:
		command |= TLB_INV_DOMAIN | TLB_INV_IVT |
		    TLB_INV_DID(domain_id);
		break;
	case TLB_INV_G_GLOBAL:
		command |= TLB_INV_GLOBAL | TLB_INV_IVT;
		break;
	default:
		cmn_err(CE_WARN, "incorrect iotlb flush type");
		return;
	}

	/*
	 * do the actual flush
	 */
	mutex_enter(&(iommu->iu_reg_lock));
	/* verify there is no pending command */
	iommu_wait_completion(iommu, iotlb_offset, iommu_get_reg64,
	    !(status & TLB_INV_IVT), status);
	if (iva)
		iommu_put_reg64(iommu, iva_offset, iva);
	iommu_put_reg64(iommu, iotlb_offset, command);
	iommu_wait_completion(iommu, iotlb_offset, iommu_get_reg64,
	    !(status & TLB_INV_IVT), status);
	mutex_exit(&(iommu->iu_reg_lock));

	/*
	 * check the result and record the statistics
	 */
	switch (TLB_INV_GET_IAIG(status)) {
	/* global */
	case 1:
		atomic_inc_64(&(iommu->iu_statistics.st_iotlb_global));
		break;
	/* domain */
	case 2:
		atomic_inc_64(&(iommu->iu_statistics.st_iotlb_domain));
		break;
	/* psi */
	case 3:
		atomic_inc_64(&(iommu->iu_statistics.st_iotlb_psi));
		break;
	default:
		break;
	}
}

/*
 * dmar_flush_iotlb_psi()
 *   register based iotlb psi invalidation
 */
static void
dmar_flush_iotlb_psi(intel_iommu_state_t *iommu, uint_t domain_id,
    uint64_t dvma, uint_t count, uint_t hint)
{
	uint_t am = 0;
	uint_t max_am = 0;
	uint64_t align = 0;
	uint64_t dvma_pg = 0;
	uint_t used_count = 0;

	/* choose page specified invalidation */
	if (IOMMU_CAP_GET_PSI(iommu->iu_capability)) {
		/* MAMV is valid only if PSI is set */
		max_am = IOMMU_CAP_GET_MAMV(iommu->iu_capability);
		while (count != 0) {
			/* First calculate alignment of DVMA */
			dvma_pg = IOMMU_BTOP(dvma);
			ASSERT(dvma_pg != NULL);
			ASSERT(count >= 1);
			for (align = 1; (dvma_pg & align) == 0; align <<= 1)
				;
			/* truncate count to the nearest power of 2 */
			for (used_count = 1, am = 0; count >> used_count != 0;
			    used_count <<= 1, am++)
				;
			if (am > max_am) {
				am = max_am;
				used_count = 1 << am;
			}
			if (align >= used_count) {
				dmar_flush_iotlb_common(iommu, domain_id,
				    dvma, am, hint, TLB_INV_G_PAGE);
			} else {
				/* align < used_count */
				used_count = align;
				for (am = 0; (1 << am) != used_count; am++)
					;
				dmar_flush_iotlb_common(iommu, domain_id,
				    dvma, am, hint, TLB_INV_G_PAGE);
			}
			count -= used_count;
			dvma = (dvma_pg + used_count) << IOMMU_PAGE_SHIFT;
		}
	/* choose domain invalidation */
	} else {
		dmar_flush_iotlb_common(iommu, domain_id, dvma,
		    0, 0, TLB_INV_G_DOMAIN);
	}
}

/*
 * dmar_flush_iotlb_dsi()
 *   flush dsi iotlb
 */
static void
dmar_flush_iotlb_dsi(intel_iommu_state_t *iommu, uint_t domain_id)
{
	dmar_flush_iotlb_common(iommu, domain_id, 0, 0, 0, TLB_INV_G_DOMAIN);
}

/*
 * dmar_flush_iotlb_glb()
 *   flush global iotbl
 */
static void
dmar_flush_iotlb_glb(intel_iommu_state_t *iommu)
{
	dmar_flush_iotlb_common(iommu, 0, 0, 0, 0, TLB_INV_G_GLOBAL);
}


/*
 * dmar_flush_context_cache()
 *   flush the context cache
 */
static void
dmar_flush_context_cache(intel_iommu_state_t *iommu, uint8_t function_mask,
    uint16_t source_id, uint_t domain_id, ctt_inv_g_t type)
{
	uint64_t command = 0, status;

	/*
	 * define the command
	 */
	switch (type) {
	case CTT_INV_G_DEVICE:
		command |= CCMD_INV_ICC | CCMD_INV_DEVICE
		    | CCMD_INV_DID(domain_id)
		    | CCMD_INV_SID(source_id) | CCMD_INV_FM(function_mask);
		break;
	case CTT_INV_G_DOMAIN:
		command |= CCMD_INV_ICC | CCMD_INV_DOMAIN
		    | CCMD_INV_DID(domain_id);
		break;
	case CTT_INV_G_GLOBAL:
		command |= CCMD_INV_ICC | CCMD_INV_GLOBAL;
		break;
	default:
		cmn_err(CE_WARN, "incorrect context cache flush type");
		return;
	}

	mutex_enter(&(iommu->iu_reg_lock));
	/* verify there is no pending command */
	iommu_wait_completion(iommu, IOMMU_REG_CONTEXT_CMD, iommu_get_reg64,
	    !(status & CCMD_INV_ICC), status);
	iommu_put_reg64(iommu, IOMMU_REG_CONTEXT_CMD, command);
	iommu_wait_completion(iommu, IOMMU_REG_CONTEXT_CMD, iommu_get_reg64,
	    !(status & CCMD_INV_ICC), status);
	mutex_exit(&(iommu->iu_reg_lock));

	/* record the context cache statistics */
	atomic_inc_64(&(iommu->iu_statistics.st_context_cache));
}

/*
 * dmar_flush_context_fsi()
 *   function based context cache flush
 */
static void
dmar_flush_context_fsi(intel_iommu_state_t *iommu, uint8_t function_mask,
    uint16_t source_id, uint_t domain_id)
{
	dmar_flush_context_cache(iommu, function_mask, source_id,
	    domain_id, CTT_INV_G_DEVICE);
}

/*
 * dmar_flush_context_dsi()
 *   domain based context cache flush
 */
static void
dmar_flush_context_dsi(intel_iommu_state_t *iommu, uint_t domain_id)
{
	dmar_flush_context_cache(iommu, 0, 0, domain_id, CTT_INV_G_DOMAIN);
}

/*
 * dmar_flush_context_gbl()
 *   flush global context cache
 */
static void
dmar_flush_context_gbl(intel_iommu_state_t *iommu)
{
	dmar_flush_context_cache(iommu, 0, 0, 0, CTT_INV_G_GLOBAL);
}

/*
 * dmar_set_root_entry_table()
 *   set root entry table
 */
static void
dmar_set_root_table(intel_iommu_state_t *iommu)
{
	uint32_t status;

	mutex_enter(&(iommu->iu_reg_lock));
	iommu_put_reg64(iommu, IOMMU_REG_ROOTENTRY,
	    iommu->iu_root_entry_paddr);
	iommu_put_reg32(iommu, IOMMU_REG_GLOBAL_CMD,
	    iommu->iu_global_cmd_reg | IOMMU_GCMD_SRTP);
	iommu_wait_completion(iommu, IOMMU_REG_GLOBAL_STS,
	    iommu_get_reg32, (status & IOMMU_GSTS_RTPS), status);
	mutex_exit(&(iommu->iu_reg_lock));
}

/*
 * dmar_enable_unit()
 *   enable the dmar unit
 */
static void
dmar_enable_unit(intel_iommu_state_t *iommu)
{
	uint32_t status;

	mutex_enter(&(iommu->iu_reg_lock));
	iommu_put_reg32(iommu, IOMMU_REG_GLOBAL_CMD,
	    IOMMU_GCMD_TE);
	iommu_wait_completion(iommu, IOMMU_REG_GLOBAL_STS,
	    iommu_get_reg32, (status & IOMMU_GSTS_TES), status);
	mutex_exit(&(iommu->iu_reg_lock));
	iommu->iu_global_cmd_reg |= IOMMU_GCMD_TE;
	iommu->iu_enabled |= DMAR_ENABLE;
	cmn_err(CE_CONT, "?\t%s enabled\n",
	    ddi_node_name(iommu->iu_drhd->di_dip));
}

/*
 * iommu_bringup_unit()
 *   the processes to bring up a dmar unit
 */
static void
iommu_bringup_unit(intel_iommu_state_t *iommu)
{
	/*
	 * flush the iommu write buffer
	 */
	iommu->iu_dmar_ops->do_flwb(iommu);

	/*
	 * set root entry table
	 */
	iommu->iu_dmar_ops->do_set_root_table(iommu);

	/*
	 * flush the context cache
	 */
	iommu->iu_dmar_ops->do_context_gbl(iommu);

	/*
	 * flush the iotlb cache
	 */
	iommu->iu_dmar_ops->do_iotlb_gbl(iommu);

	/*
	 * at last enable the unit
	 */
	iommu->iu_dmar_ops->do_enable(iommu);

	/* enable queued invalidation */
	if (iommu->iu_inv_queue)
		iommu_qinv_enable(iommu);
}

/*
 * iommu_dvma_cache_get()
 *   get a dvma from the cache
 */
static uint64_t
iommu_dvma_cache_get(dmar_domain_state_t *domain,
    size_t size, size_t align, size_t nocross)
{
	dvma_cache_node_t *cache_node = NULL;
	dvma_cache_head_t *cache_head;
	uint_t index = IOMMU_BTOP(size) - 1;
	uint64_t ioaddr;

	if (index >= DVMA_CACHE_HEAD_CNT)
		return (0);

	cache_head = &(domain->dm_dvma_cache[index]);
	mutex_enter(&(cache_head->dch_free_lock));
	for_each_in_list(&(cache_head->dch_free_list), cache_node) {
		if ((cache_node->dcn_align >= align) &&
		    ((nocross == 0) ||
		    ((cache_node->dcn_dvma ^ (cache_node->dcn_dvma + size - 1))
		    < (nocross - 1)))) {
			list_remove(&(cache_head->dch_free_list),
			    cache_node);
			cache_head->dch_free_count--;
			break;
		}
	}
	mutex_exit(&(cache_head->dch_free_lock));

	if (cache_node) {
		ioaddr = cache_node->dcn_dvma;
		mutex_enter(&(cache_head->dch_mem_lock));
		list_insert_head(&(cache_head->dch_mem_list), cache_node);
		mutex_exit(&(cache_head->dch_mem_lock));
		return (ioaddr);
	}

	return (0);
}

/*
 * iommu_dvma_cache_put()
 *   put a dvma to the cache after use
 */
static void
iommu_dvma_cache_put(dmar_domain_state_t *domain, uint64_t dvma,
    size_t size, size_t align)
{
	dvma_cache_node_t *cache_node = NULL;
	dvma_cache_head_t *cache_head;
	uint_t index = IOMMU_BTOP(size) - 1;
	boolean_t shrink = B_FALSE;

	/* out of cache range */
	if (index >= DVMA_CACHE_HEAD_CNT) {
		vmem_xfree(domain->dm_dvma_map,
		    (void *)(intptr_t)dvma, size);
		return;
	}

	cache_head = &(domain->dm_dvma_cache[index]);

	/* get a node block */
	mutex_enter(&(cache_head->dch_mem_lock));
	cache_node = list_head(&(cache_head->dch_mem_list));
	if (cache_node) {
		list_remove(&(cache_head->dch_mem_list), cache_node);
	}
	mutex_exit(&(cache_head->dch_mem_lock));

	/* no cache, alloc one */
	if (cache_node == NULL) {
		cache_node = kmem_alloc(sizeof (dvma_cache_node_t), KM_SLEEP);
	}

	/* initialize this node */
	cache_node->dcn_align = align;
	cache_node->dcn_dvma = dvma;

	/* insert into the free list */
	mutex_enter(&(cache_head->dch_free_lock));
	list_insert_head(&(cache_head->dch_free_list), cache_node);

	/* shrink the cache list */
	if (cache_head->dch_free_count++ > dvma_cache_high) {
		cache_node = list_tail(&(cache_head->dch_free_list));
		list_remove(&(cache_head->dch_free_list), cache_node);
		shrink = B_TRUE;
		cache_head->dch_free_count--;
	}
	mutex_exit(&(cache_head->dch_free_lock));

	if (shrink) {
		ASSERT(cache_node);
		vmem_xfree(domain->dm_dvma_map,
		    (void *)(intptr_t)(cache_node->dcn_dvma), size);
		kmem_free(cache_node, sizeof (dvma_cache_node_t));
	}
}

/*
 * iommu_dvma_cache_flush()
 *   flush the dvma caches when vmem_xalloc() failed
 */
static void
iommu_dvma_cache_flush(dmar_domain_state_t *domain, dev_info_t *dip)
{
	dvma_cache_node_t *cache_node;
	dvma_cache_head_t *cache_head;
	uint_t index;

	cmn_err(CE_NOTE, "domain dvma cache for %s flushed",
	    ddi_node_name(dip));

	for (index = 0; index < DVMA_CACHE_HEAD_CNT; index++) {
		cache_head = &(domain->dm_dvma_cache[index]);
		mutex_enter(&(cache_head->dch_free_lock));
		cache_node = list_head(&(cache_head->dch_free_list));
		while (cache_node) {
			list_remove(&(cache_head->dch_free_list), cache_node);
			vmem_xfree(domain->dm_dvma_map,
			    (void *)(intptr_t)(cache_node->dcn_dvma),
			    IOMMU_PTOB(index + 1));
			kmem_free(cache_node, sizeof (dvma_cache_node_t));
			cache_head->dch_free_count--;
			cache_node = list_head(&(cache_head->dch_free_list));
		}
		ASSERT(cache_head->dch_free_count == 0);
		mutex_exit(&(cache_head->dch_free_lock));
	}
}

/*
 * get_dvma_cookie_array()
 *   get a dvma cookie array from the cache or allocate
 */
static iommu_dvma_cookie_t *
get_dvma_cookie_array(uint_t array_size)
{
	dvma_cookie_head_t *cache_head;
	iommu_dvma_cookie_t *cookie = NULL;

	if (array_size > MAX_COOKIE_CACHE_SIZE) {
		return (kmem_alloc(sizeof (iommu_dvma_cookie_t) * array_size,
		    KM_SLEEP));
	}

	cache_head = &(cookie_cache[array_size - 1]);
	mutex_enter(&(cache_head->dch_lock));
	/* LINTED E_EQUALITY_NOT_ASSIGNMENT */
	if (cookie = cache_head->dch_next) {
		cache_head->dch_next = cookie->dc_next;
		cache_head->dch_count--;
	}
	mutex_exit(&(cache_head->dch_lock));

	if (cookie) {
		return (cookie);
	} else {
		return (kmem_alloc(sizeof (iommu_dvma_cookie_t) * array_size,
		    KM_SLEEP));
	}
}

/*
 * put_dvma_cookie_array()
 *   put a dvma cookie array to the cache or free
 */
static void
put_dvma_cookie_array(iommu_dvma_cookie_t *dcookies, uint_t array_size)
{
	dvma_cookie_head_t *cache_head;

	if (array_size > MAX_COOKIE_CACHE_SIZE) {
		kmem_free(dcookies, sizeof (iommu_dvma_cookie_t) * array_size);
		return;
	}

	cache_head = &(cookie_cache[array_size - 1]);
	mutex_enter(&(cache_head->dch_lock));
	dcookies->dc_next = cache_head->dch_next;
	cache_head->dch_next = dcookies;
	cache_head->dch_count++;
	mutex_exit(&(cache_head->dch_lock));
}

/*
 * dmar_reg_plant_wait()
 *   the plant wait operation for register based cache invalidation
 */
static void
dmar_reg_plant_wait(intel_iommu_state_t *iommu, iommu_dvma_cookie_t *dcookies,
    uint_t count, uint_t array_size)
{
	iotlb_pend_node_t *node = NULL;
	iotlb_pend_head_t *head;

	head = &(iommu->iu_pend_head);

	/* get a node */
	mutex_enter(&(head->ich_mem_lock));
	node = list_head(&(head->ich_mem_list));
	if (node) {
		list_remove(&(head->ich_mem_list), node);
	}
	mutex_exit(&(head->ich_mem_lock));

	/* no cache, alloc one */
	if (node == NULL) {
		node = kmem_alloc(sizeof (iotlb_pend_node_t), KM_SLEEP);
	}

	/* initialize this node */
	node->icn_dcookies = dcookies;
	node->icn_count = count;
	node->icn_array_size = array_size;

	/* insert into the pend list */
	mutex_enter(&(head->ich_pend_lock));
	list_insert_tail(&(head->ich_pend_list), node);
	head->ich_pend_count++;
	mutex_exit(&(head->ich_pend_lock));
}

/*
 * dmar_release_dvma_cookie()
 *   release the dvma cookie
 */
static void
dmar_release_dvma_cookie(iommu_dvma_cookie_t *dcookies,
    uint_t count, uint_t array_size)
{
	uint_t i;

	/* free dvma */
	for (i = 0; i < count; i++) {
		iommu_dvma_cache_put(dcookies[i].dc_domain,
		    dcookies[i].dc_addr, dcookies[i].dc_size,
		    dcookies[i].dc_align);
	}

	/* free the cookie array */
	put_dvma_cookie_array(dcookies, array_size);
}

/*
 * dmar_reg_reap_wait()
 *   the reap wait operation for register based cache invalidation
 */
static void
dmar_reg_reap_wait(intel_iommu_state_t *iommu)
{
	iotlb_pend_node_t *node;
	iotlb_pend_head_t *head;

	head = &(iommu->iu_pend_head);
	mutex_enter(&(head->ich_pend_lock));
	node = list_head(&(head->ich_pend_list));
	if (node) {
		list_remove(&(head->ich_pend_list), node);
		head->ich_pend_count--;
	}
	mutex_exit(&(head->ich_pend_lock));

	if (node) {
		dmar_release_dvma_cookie(node->icn_dcookies,
		    node->icn_count, node->icn_array_size);
		/* put the node into the node cache */
		mutex_enter(&(head->ich_mem_lock));
		list_insert_head(&(head->ich_mem_list), node);
		mutex_exit(&(head->ich_mem_lock));
	}
}

/*
 * dmar_init_ops()
 *   init dmar ops
 */
static void
dmar_init_ops(intel_iommu_state_t *iommu)
{
	struct dmar_ops *ops;

	ASSERT(iommu);
	ops = kmem_alloc(sizeof (struct dmar_ops), KM_SLEEP);

	/* initialize the dmar operations */
	ops->do_enable = dmar_enable_unit;
	ops->do_fault = iommu_intr_handler;

	/* cpu clflush */
	if (iommu->iu_coherency) {
		ops->do_clflush = (void (*)(caddr_t, uint_t))return_instr;
	} else {
		ASSERT(x86_feature & X86_CLFSH);
		ops->do_clflush = cpu_clflush;
	}

	/* write buffer */
	if (IOMMU_CAP_GET_RWBF(iommu->iu_capability)) {
		ops->do_flwb = dmar_flush_write_buffer;
	} else {
		ops->do_flwb = (void (*)(intel_iommu_state_t *))return_instr;
	}

	/* cache related functions */
	ops->do_iotlb_psi = dmar_flush_iotlb_psi;
	ops->do_iotlb_dsi = dmar_flush_iotlb_dsi;
	ops->do_iotlb_gbl = dmar_flush_iotlb_glb;
	ops->do_context_fsi = dmar_flush_context_fsi;
	ops->do_context_dsi = dmar_flush_context_dsi;
	ops->do_context_gbl = dmar_flush_context_gbl;
	ops->do_plant_wait = dmar_reg_plant_wait;
	ops->do_reap_wait = dmar_reg_reap_wait;

	ops->do_set_root_table = dmar_set_root_table;

	iommu->iu_dmar_ops = ops;
}

/*
 * create_iommu_state()
 *   alloc and setup the iommu state
 */
static int
create_iommu_state(drhd_info_t *drhd)
{
	intel_iommu_state_t *iommu;
	int mgaw, sagaw, agaw;
	int bitnum;
	int ret;

	static ddi_device_acc_attr_t ioattr = {
		DDI_DEVICE_ATTR_V0,
		DDI_NEVERSWAP_ACC,
		DDI_STRICTORDER_ACC,
	};

	iommu = kmem_alloc(sizeof (intel_iommu_state_t), KM_SLEEP);
	drhd->di_iommu = (void *)iommu;
	iommu->iu_drhd = drhd;

	/*
	 * map the register address space
	 */
	ret = ddi_regs_map_setup(iommu->iu_drhd->di_dip, 0,
	    (caddr_t *)&(iommu->iu_reg_address), (offset_t)0,
	    (offset_t)IOMMU_REG_SIZE, &ioattr,
	    &(iommu->iu_reg_handle));

	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iommu register map failed: %d", ret);
		kmem_free(iommu, sizeof (intel_iommu_state_t));
		return (DDI_FAILURE);
	}

	mutex_init(&(iommu->iu_reg_lock), NULL, MUTEX_DRIVER,
	    (void *)ipltospl(IOMMU_INTR_IPL));
	mutex_init(&(iommu->iu_root_context_lock), NULL, MUTEX_DRIVER, NULL);

	/*
	 * get the register value
	 */
	iommu->iu_capability = iommu_get_reg64(iommu, IOMMU_REG_CAP);
	iommu->iu_excapability = iommu_get_reg64(iommu, IOMMU_REG_EXCAP);

	/*
	 * if the hardware access is non-coherent, we need clflush
	 */
	if (IOMMU_ECAP_GET_C(iommu->iu_excapability)) {
		iommu->iu_coherency = B_TRUE;
	} else {
		iommu->iu_coherency = B_FALSE;
		if (!(x86_feature & X86_CLFSH)) {
			cmn_err(CE_WARN, "drhd can't be enabled due to "
			    "missing clflush functionality");
			ddi_regs_map_free(&(iommu->iu_reg_handle));
			kmem_free(iommu, sizeof (intel_iommu_state_t));
			return (DDI_FAILURE);
		}
	}

	/*
	 * retrieve the maximum number of domains
	 */
	iommu->iu_max_domain = IOMMU_CAP_ND(iommu->iu_capability);

	/*
	 * setup the domain id allocator
	 *  domain id 0 is reserved by the architecture
	 */
	iommu_rscs_init(1, iommu->iu_max_domain, &(iommu->iu_domain_id_hdl));

	/*
	 * calculate the agaw
	 */
	mgaw = IOMMU_CAP_MGAW(iommu->iu_capability);
	sagaw = IOMMU_CAP_SAGAW(iommu->iu_capability);
	iommu->iu_gaw = mgaw;
	agaw = calculate_agaw(iommu->iu_gaw);
	bitnum = (agaw - 30) / 9;

	while (bitnum < 5) {
		if (sagaw & (1 << bitnum))
			break;
		else
			bitnum++;
	}

	if (bitnum >= 5) {
		cmn_err(CE_PANIC, "can't determine agaw");
		/*NOTREACHED*/
		return (DDI_FAILURE);
	} else {
		iommu->iu_agaw = 30 + bitnum * 9;
		if (iommu->iu_agaw > 64)
			iommu->iu_agaw = 64;
		iommu->iu_level = bitnum + 2;
	}

	/*
	 * the iommu is orginally disabled
	 */
	iommu->iu_enabled = 0;
	iommu->iu_global_cmd_reg = 0;

	/*
	 * init kstat
	 */
	(void) iommu_init_stats(iommu);
	bzero(&(iommu->iu_statistics), sizeof (iommu_stat_t));

	/*
	 * init dmar ops
	 */
	dmar_init_ops(iommu);

	/*
	 * alloc root entry table, this should put after init ops
	 */
	iommu->iu_root_entry_paddr = iommu_get_page(iommu, KM_SLEEP);

	/*
	 * init queued invalidation interface
	 */
	iommu->iu_inv_queue = NULL;
	if (IOMMU_ECAP_GET_QI(iommu->iu_excapability)) {
		if (iommu_qinv_init(iommu) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "%s init queued invalidation interface failed\n",
			    ddi_node_name(iommu->iu_drhd->di_dip));
		}
	}

	/*
	 * init intr remapping table state pointer
	 */
	iommu->iu_intr_remap_tbl = NULL;

	/*
	 * initialize the iotlb pending list and cache
	 */
	mutex_init(&(iommu->iu_pend_head.ich_pend_lock), NULL,
	    MUTEX_DRIVER, NULL);
	list_create(&(iommu->iu_pend_head.ich_pend_list),
	    sizeof (iotlb_pend_node_t),
	    offsetof(iotlb_pend_node_t, node));
	iommu->iu_pend_head.ich_pend_count = 0;

	mutex_init(&(iommu->iu_pend_head.ich_mem_lock), NULL,
	    MUTEX_DRIVER, NULL);
	list_create(&(iommu->iu_pend_head.ich_mem_list),
	    sizeof (iotlb_pend_node_t),
	    offsetof(iotlb_pend_node_t, node));

	/*
	 * insert this iommu into the list
	 */
	list_insert_tail(&iommu_states, iommu);

	/*
	 * report this unit
	 */
	cmn_err(CE_CONT, "?\t%s state structure created\n",
	    ddi_node_name(iommu->iu_drhd->di_dip));

	return (DDI_SUCCESS);
}

#define	IS_OVERLAP(new, old)	(((new)->rm_pfn_start <= (old)->rm_pfn_end) && \
				((new)->rm_pfn_end >= (old)->rm_pfn_start))

/*
 * memory_region_overlap()
 *   handle the pci mmio pages overlap condition
 */
static boolean_t
memory_region_overlap(dmar_reserve_pages_t *rmem)
{
	dmar_reserve_pages_t *temp;

	for_each_in_list(&reserve_memory, temp) {
		if (IS_OVERLAP(rmem, temp)) {
			temp->rm_pfn_start = MIN(temp->rm_pfn_start,
			    rmem->rm_pfn_start);
			temp->rm_pfn_end = MAX(temp->rm_pfn_end,
			    rmem->rm_pfn_end);
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * collect_pci_mmio_walk
 *   reserve a single dev mmio resources
 */
static int
collect_pci_mmio_walk(dev_info_t *dip, void *arg)
{
	_NOTE(ARGUNUSED(arg))

	int i, length, account;
	pci_regspec_t *assigned;
	uint64_t mmio_hi, mmio_lo, mmio_size;
	dmar_reserve_pages_t *rmem;

	/*
	 * ingore the devices which have no assigned-address
	 * properties
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "assigned-addresses", (caddr_t)&assigned,
	    &length) != DDI_PROP_SUCCESS)
		return (DDI_WALK_CONTINUE);

	account = length / sizeof (pci_regspec_t);

	for (i = 0; i < account; i++) {

		/*
		 * check the memory io assigned-addresses
		 * refer to pci.h for bits defination of
		 * pci_phys_hi
		 */
		if (((assigned[i].pci_phys_hi & PCI_ADDR_MASK)
		    == PCI_ADDR_MEM32) ||
		    ((assigned[i].pci_phys_hi & PCI_ADDR_MASK)
		    == PCI_ADDR_MEM64)) {
			mmio_lo = (((uint64_t)assigned[i].pci_phys_mid) << 32) |
			    (uint64_t)assigned[i].pci_phys_low;
			mmio_size =
			    (((uint64_t)assigned[i].pci_size_hi) << 32) |
			    (uint64_t)assigned[i].pci_size_low;
			mmio_hi = mmio_lo + mmio_size - 1;

			rmem = kmem_alloc(sizeof (dmar_reserve_pages_t),
			    KM_SLEEP);
			rmem->rm_pfn_start = IOMMU_BTOP(mmio_lo);
			rmem->rm_pfn_end = IOMMU_BTOP(mmio_hi);
			if (!memory_region_overlap(rmem)) {
				list_insert_tail(&reserve_memory, rmem);
			}
		}
	}

	kmem_free(assigned, length);

	return (DDI_WALK_CONTINUE);
}

/*
 * collect_pci_mmio()
 *   walk through the pci device tree, and collect the mmio resources
 */
static int
collect_pci_mmio(dev_info_t *pdip)
{
	int count;
	ASSERT(pdip);

	/*
	 * walk through the device tree under pdip
	 * normally, pdip should be the pci root nexus
	 */
	ndi_devi_enter(pdip, &count);
	ddi_walk_devs(ddi_get_child(pdip),
	    collect_pci_mmio_walk, NULL);
	ndi_devi_exit(pdip, count);

	return (DDI_SUCCESS);
}

/*
 * iommu_collect_reserve_memory()
 *   collect the reserved memory region
 */
static void
iommu_collect_reserve_memory(void)
{
	dmar_reserve_pages_t *rmem;

	/*
	 * reserve pages for pci memory mapped io
	 */
	(void) collect_pci_mmio(pci_top_devinfo);

	/*
	 * reserve pages for ioapic
	 */
	rmem = kmem_alloc(sizeof (dmar_reserve_pages_t), KM_SLEEP);
	rmem->rm_pfn_start = IOMMU_BTOP(IOAPIC_REGION_START);
	rmem->rm_pfn_end = IOMMU_BTOP(IOAPIC_REGION_END);
	list_insert_tail(&reserve_memory, rmem);
}

/*
 * match_dip_sbdf()
 *   walk function for get_dip_from_info()
 */
static int
match_dip_sbdf(dev_info_t *dip, void *arg)
{
	iommu_private_t *private = DEVI(dip)->devi_iommu_private;
	pci_dev_info_t *info = arg;

	if (private &&
	    (info->pdi_seg == private->idp_seg) &&
	    (info->pdi_bus == private->idp_bus) &&
	    (info->pdi_devfn == private->idp_devfn)) {
		info->pdi_dip = dip;
		return (DDI_WALK_TERMINATE);
	}
	return (DDI_WALK_CONTINUE);
}

/*
 * get_dip_from_info()
 *   get the dev_info structure by pass a bus/dev/func
 */
static int
get_dip_from_info(pci_dev_info_t *info)
{
	int count;
	info->pdi_dip = NULL;

	ndi_devi_enter(pci_top_devinfo, &count);
	ddi_walk_devs(ddi_get_child(pci_top_devinfo),
	    match_dip_sbdf, info);
	ndi_devi_exit(pci_top_devinfo, count);

	if (info->pdi_dip)
		return (DDI_SUCCESS);
	else
		return (DDI_FAILURE);
}

/*
 * get_pci_top_bridge()
 *   get the top level bridge for a pci device
 */
static dev_info_t *
get_pci_top_bridge(dev_info_t *dip)
{
	iommu_private_t *private;
	dev_info_t *tmp, *pdip;

	tmp = NULL;
	pdip = ddi_get_parent(dip);
	while (pdip != pci_top_devinfo) {
		private = DEVI(pdip)->devi_iommu_private;
		if ((private->idp_bbp_type == IOMMU_PPB_PCIE_PCI) ||
		    (private->idp_bbp_type == IOMMU_PPB_PCI_PCI))
			tmp = pdip;
		pdip = ddi_get_parent(pdip);
	}

	return (tmp);
}

/*
 * domain_vmem_init_reserve()
 *   dish out the reserved pages
 */
static void
domain_vmem_init_reserve(dmar_domain_state_t *domain)
{
	dmar_reserve_pages_t *rmem;
	uint64_t lo, hi;
	size_t size;

	for_each_in_list(&reserve_memory, rmem) {
		lo = IOMMU_PTOB(rmem->rm_pfn_start);
		hi = IOMMU_PTOB(rmem->rm_pfn_end + 1);
		size = hi - lo;

		if (vmem_xalloc(domain->dm_dvma_map,
		    size,		/* size */
		    IOMMU_PAGE_SIZE,	/* align/quantum */
		    0,			/* phase */
		    0,			/* nocross */
		    (void *)(uintptr_t)lo,	/* minaddr */
		    (void *)(uintptr_t)hi,	/* maxaddr */
		    VM_NOSLEEP) == NULL) {
			cmn_err(CE_WARN,
			    "region [%" PRIx64 ",%" PRIx64 ") not reserved",
			    lo, hi);
		}
	}
}

/*
 * domain_vmem_init()
 *   initiate the domain vmem
 */
static void
domain_vmem_init(dmar_domain_state_t *domain)
{
	char vmem_name[64];
	uint64_t base, size;
	static uint_t vmem_instance = 0;

	/*
	 * create the whole available virtual address and
	 * dish out the reserved memory regions with xalloc
	 */
	(void) snprintf(vmem_name, sizeof (vmem_name),
	    "domain_vmem_%d", vmem_instance++);
	base = IOMMU_PAGE_SIZE;
	size = IOMMU_SIZE_4G - base;

	domain->dm_dvma_map = vmem_create(vmem_name,
	    (void *)(uintptr_t)base,	/* base */
	    size,			/* size */
	    IOMMU_PAGE_SIZE,		/* quantum */
	    NULL,			/* afunc */
	    NULL,			/* ffunc */
	    NULL,			/* source */
	    0,				/* qcache_max */
	    VM_SLEEP);

	/*
	 * dish out the reserved pages
	 */
	domain_vmem_init_reserve(domain);
}

/*
 * iommu_domain_init()
 *   initiate a domain
 */
static int
iommu_domain_init(dmar_domain_state_t *domain)
{
	uint_t i;

	/*
	 * allocate the domain id
	 */
	if (iommu_rscs_alloc(domain->dm_iommu->iu_domain_id_hdl,
	    &(domain->dm_domain_id)) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "domain id exhausted %p, assign 1",
		    (void *)domain->dm_iommu);
		domain->dm_domain_id = 1;
	}

	/*
	 * record the domain statistics
	 */
	atomic_inc_64(&(domain->dm_iommu->iu_statistics.st_domain_alloc));

	/*
	 * create vmem map
	 */
	domain_vmem_init(domain);

	/*
	 * create the first level page table
	 */
	domain->dm_page_table_paddr =
	    iommu_get_page(domain->dm_iommu, KM_SLEEP);

	/*
	 * init the CPU available page tables
	 */
	domain->dm_pt_tree.vp = kmem_zalloc(IOMMU_PAGE_SIZE << 1, KM_SLEEP);
	domain->dm_pt_tree.pp = iommu_page_map(domain->dm_page_table_paddr);
	domain->dm_identity = B_FALSE;

	/*
	 * init the dvma cache
	 */
	for (i = 0; i < DVMA_CACHE_HEAD_CNT; i++) {
		/* init the free list */
		mutex_init(&(domain->dm_dvma_cache[i].dch_free_lock),
		    NULL, MUTEX_DRIVER, NULL);
		list_create(&(domain->dm_dvma_cache[i].dch_free_list),
		    sizeof (dvma_cache_node_t),
		    offsetof(dvma_cache_node_t, node));
		domain->dm_dvma_cache[i].dch_free_count = 0;

		/* init the memory cache list */
		mutex_init(&(domain->dm_dvma_cache[i].dch_mem_lock),
		    NULL, MUTEX_DRIVER, NULL);
		list_create(&(domain->dm_dvma_cache[i].dch_mem_list),
		    sizeof (dvma_cache_node_t),
		    offsetof(dvma_cache_node_t, node));
	}

	return (DDI_SUCCESS);
}

/*
 * dmar_check_sub()
 *   check to see if the device is under scope of a p2p bridge
 */
static boolean_t
dmar_check_sub(dev_info_t *dip, pci_dev_scope_t *devs)
{
	dev_info_t *pdip, *pci_root;
	iommu_private_t *private;
	int bus = devs->pds_bus;
	int devfn = ((devs->pds_dev << 3) | devs->pds_func);

	pdip = ddi_get_parent(dip);
	pci_root = pci_top_devinfo;
	while (pdip != pci_root) {
		private = DEVI(pdip)->devi_iommu_private;
		if (private && (private->idp_bus == bus) &&
		    (private->idp_devfn == devfn))
			return (B_TRUE);
		pdip = ddi_get_parent(pdip);
	}

	return (B_FALSE);
}

/*
 * iommu_get_dmar()
 *   get the iommu structure for a device
 */
static intel_iommu_state_t *
iommu_get_dmar(dev_info_t *dip)
{
	iommu_private_t *private =
	    DEVI(dip)->devi_iommu_private;
	int seg = private->idp_seg;
	int bus = private->idp_bus;
	int dev = private->idp_devfn >> 3;
	int func = private->idp_devfn & 7;
	pci_dev_scope_t *devs;
	drhd_info_t *drhd;

	/*
	 * walk the drhd list for a match
	 */
	for_each_in_list(&(dmar_info->dmari_drhd[seg]), drhd) {

		/*
		 * match the include all
		 */
		if (drhd->di_include_all)
			return ((intel_iommu_state_t *)
			    drhd->di_iommu);

		/*
		 * try to match the device scope
		 */
		for_each_in_list(&(drhd->di_dev_list), devs) {

			/*
			 * get a perfect match
			 */
			if (devs->pds_bus == bus &&
			    devs->pds_dev == dev &&
			    devs->pds_func == func) {
				return ((intel_iommu_state_t *)
				    (drhd->di_iommu));
			}

			/*
			 * maybe under a scope of a p2p
			 */
			if (devs->pds_type == 0x2 &&
			    dmar_check_sub(dip, devs))
				return ((intel_iommu_state_t *)
				    (drhd->di_iommu));
		}
	}

	/*
	 * shouldn't get here
	 */
	cmn_err(CE_PANIC, "can't match iommu for %s\n",
	    ddi_node_name(dip));

	return (NULL);
}

/*
 * domain_set_root_context
 *   set root context for a single device
 */
static void
domain_set_root_context(dmar_domain_state_t *domain,
    pci_dev_info_t *info, uint_t agaw)
{
	caddr_t root, context;
	paddr_t paddr;
	iorce_t rce;
	uint_t bus, devfn;
	intel_iommu_state_t *iommu;
	uint_t aw_code;

	ASSERT(domain);
	iommu = domain->dm_iommu;
	ASSERT(iommu);
	bus = info->pdi_bus;
	devfn = info->pdi_devfn;
	aw_code = (agaw - 30) / 9;

	/*
	 * set root entry
	 */
	root = iommu_page_map(iommu->iu_root_entry_paddr);
	rce = (iorce_t)root + bus;
	mutex_enter(&(iommu->iu_root_context_lock));
	if (!ROOT_ENTRY_GET_P(rce)) {
		paddr = iommu_get_page(iommu, KM_SLEEP);
		ROOT_ENTRY_SET_P(rce);
		ROOT_ENTRY_SET_CTP(rce, paddr);
		iommu->iu_dmar_ops->do_clflush((caddr_t)rce, sizeof (*rce));
		context = iommu_page_map(paddr);
	} else {
		paddr = ROOT_ENTRY_GET_CTP(rce);
		context = iommu_page_map(paddr);
	}

	/* set context entry */
	rce = (iorce_t)context + devfn;
	if (!CONT_ENTRY_GET_P(rce)) {
		paddr = domain->dm_page_table_paddr;
		CONT_ENTRY_SET_P(rce);
		CONT_ENTRY_SET_ASR(rce, paddr);
		CONT_ENTRY_SET_AW(rce, aw_code);
		CONT_ENTRY_SET_DID(rce, domain->dm_domain_id);
		iommu->iu_dmar_ops->do_clflush((caddr_t)rce, sizeof (*rce));
	} else if (CONT_ENTRY_GET_ASR(rce) !=
	    domain->dm_page_table_paddr) {
		cmn_err(CE_WARN, "root context entries for"
		    " %d, %d, %d has been set", bus,
		    devfn >>3, devfn & 0x7);
	}

	mutex_exit(&(iommu->iu_root_context_lock));
	iommu_page_unmap(root);
	iommu_page_unmap(context);

	/* cache mode set, flush context cache */
	if (IOMMU_CAP_GET_CM(iommu->iu_capability)) {
		iommu->iu_dmar_ops->do_context_fsi(iommu, 0,
		    (bus << 8) | devfn, domain->dm_domain_id);
		iommu->iu_dmar_ops->do_iotlb_dsi(iommu, domain->dm_domain_id);
	/* cache mode not set, flush write buffer */
	} else {
		iommu->iu_dmar_ops->do_flwb(iommu);
	}
}

/*
 * setup_single_context()
 *   setup the root context entry
 */
static void
setup_single_context(dmar_domain_state_t *domain,
    int seg, int bus, int devfn)
{
	pci_dev_info_t info;

	info.pdi_seg = seg;
	info.pdi_bus = bus;
	info.pdi_devfn = devfn;

	domain_set_root_context(domain, &info,
	    domain->dm_iommu->iu_agaw);
}

/*
 * setup_context_walk()
 *   the walk function to set up the possible context entries
 */
static int
setup_context_walk(dev_info_t *dip, void *arg)
{
	dmar_domain_state_t *domain = arg;
	iommu_private_t *private;

	private = DEVI(dip)->devi_iommu_private;
	ASSERT(private);

	setup_single_context(domain, private->idp_seg,
	    private->idp_bus, private->idp_devfn);
	return (DDI_WALK_PRUNECHILD);
}

/*
 * setup_possible_contexts()
 *   set up all the possible context entries for a device under ppb
 */
static void
setup_possible_contexts(dmar_domain_state_t *domain, dev_info_t *dip)
{
	int count;
	iommu_private_t *private;
	private = DEVI(dip)->devi_iommu_private;

	/* for pci-pci bridge */
	if (private->idp_bbp_type == IOMMU_PPB_PCI_PCI) {
		setup_single_context(domain, private->idp_seg,
		    private->idp_bus, private->idp_devfn);
		return;
	}

	/* for pcie-pci bridge */
	setup_single_context(domain, private->idp_seg,
	    private->idp_bus, private->idp_devfn);
	setup_single_context(domain, private->idp_seg,
	    private->idp_sec, 0);

	/* for functions under pcie-pci bridge */
	ndi_devi_enter(dip, &count);
	ddi_walk_devs(ddi_get_child(dip), setup_context_walk, domain);
	ndi_devi_exit(dip, count);
}

/*
 * iommu_alloc_domain()
 *   allocate a domain for device, the result is returned in domain parameter
 */
static int
iommu_alloc_domain(dev_info_t *dip, dmar_domain_state_t **domain)
{
	iommu_private_t *private, *b_private;
	dmar_domain_state_t *new;
	pci_dev_info_t info;
	dev_info_t *bdip = NULL;
	uint_t need_to_set_parent;
	int count, pcount;

	need_to_set_parent = 0;
	private = DEVI(dip)->devi_iommu_private;
	if (private == NULL) {
		cmn_err(CE_PANIC, "iommu private is NULL (%s)\n",
		    ddi_node_name(dip));
	}

	/*
	 * check if the domain has already allocated
	 */
	if (private->idp_intel_domain) {
		*domain = INTEL_IOMMU_PRIVATE(private->idp_intel_domain);
		return (DDI_SUCCESS);
	}

	/*
	 * we have to assign a domain for this device,
	 */

	ndi_hold_devi(dip);
	bdip = get_pci_top_bridge(dip);
	if (bdip != NULL) {
		ndi_devi_enter(ddi_get_parent(bdip), &pcount);
	}

	/*
	 * hold the parent for modifying its children
	 */
	ndi_devi_enter(ddi_get_parent(dip), &count);

	/*
	 * check to see if it is under a pci bridge
	 */
	if (bdip != NULL) {
		b_private = DEVI(bdip)->devi_iommu_private;
		if (b_private->idp_intel_domain) {
			new = INTEL_IOMMU_PRIVATE(b_private->idp_intel_domain);
			goto get_domain_finish;
		} else {
			need_to_set_parent = 1;
		}
	}

get_domain_alloc:
	/*
	 * OK, we have to allocate a new domain
	 */
	new = kmem_alloc(sizeof (dmar_domain_state_t), KM_SLEEP);
	new->dm_iommu = iommu_get_dmar(dip);

	/*
	 * setup the domain
	 */
	if (iommu_domain_init(new) != DDI_SUCCESS) {
		ndi_devi_exit(ddi_get_parent(dip), count);
		if (need_to_set_parent)
			ndi_devi_exit(ddi_get_parent(bdip), pcount);
		return (DDI_FAILURE);
	}

get_domain_finish:
	/*
	 * add the device to the domain's device list
	 */
	private->idp_intel_domain = (void *)new;
	ndi_devi_exit(ddi_get_parent(dip), count);

	if (need_to_set_parent) {
		b_private->idp_intel_domain = (void *)new;
		ndi_devi_exit(ddi_get_parent(bdip), pcount);
		setup_possible_contexts(new, bdip);
	} else if (bdip == NULL) {
		info.pdi_seg = private->idp_seg;
		info.pdi_bus = private->idp_bus;
		info.pdi_devfn = private->idp_devfn;
		domain_set_root_context(new, &info,
		    new->dm_iommu->iu_agaw);
	} else {
		ndi_devi_exit(ddi_get_parent(bdip), pcount);
	}

	/*
	 * return new domain
	 */
	*domain = new;
	return (DDI_SUCCESS);
}

/*
 * iommu_get_domain()
 *   get a iommu domain for dip, and the result is returned in domain
 */
static int
iommu_get_domain(dev_info_t *dip, dmar_domain_state_t **domain)
{
	iommu_private_t *private;
	dev_info_t *pdip;
	private = DEVI(dip)->devi_iommu_private;

	ASSERT(domain);

	/*
	 * for isa devices attached under lpc
	 */
	if (ddi_get_parent(dip) == isa_top_devinfo) {
		if (lpc_devinfo) {
			return (iommu_alloc_domain(lpc_devinfo, domain));
		} else {
			*domain = NULL;
			return (DDI_FAILURE);
		}
	}

	/*
	 * for gart, use the real graphic devinfo
	 */
	if (strcmp(ddi_node_name(dip), "agpgart") == 0) {
		if (gfx_devinfo) {
			return (iommu_alloc_domain(gfx_devinfo, domain));
		} else {
			*domain = NULL;
			return (DDI_FAILURE);
		}
	}

	/*
	 * if iommu private is NULL, we share
	 * the domain with the parent
	 */
	if (private == NULL) {
		pdip = ddi_get_parent(dip);
		return (iommu_alloc_domain(pdip, domain));
	}

	/*
	 * check if the domain has already allocated
	 */
	if (private->idp_intel_domain) {
		*domain = INTEL_IOMMU_PRIVATE(private->idp_intel_domain);
		return (DDI_SUCCESS);
	}

	/*
	 * allocate a domain for this device
	 */
	return (iommu_alloc_domain(dip, domain));
}

/*
 * helper functions to manipulate iommu pte
 */
static inline void
set_pte(iopte_t pte, uint_t rw, paddr_t addr)
{
	*pte |= (rw & 0x3);
	*pte |= (addr & IOMMU_PAGE_MASK);
}

static inline paddr_t
pte_get_paddr(iopte_t pte)
{
	return (*pte & IOMMU_PAGE_MASK);
}

/*
 * dvma_level_offset()
 *   get the page table offset by specifying a dvma and level
 */
static inline uint_t
dvma_level_offset(uint64_t dvma_pn, uint_t level)
{
	uint_t start_bit, offset;

	start_bit = (level - 1) * IOMMU_LEVEL_STRIDE;
	offset = (dvma_pn >> start_bit) & IOMMU_LEVEL_OFFSET;

	return (offset);
}

/*
 * iommu_setup_level_table()
 *   setup the page table for a level
 */
static iovpte_t
iommu_setup_level_table(dmar_domain_state_t *domain,
    iovpte_t pvpte, uint_t offset)
{
	iopte_t pte;
	iovpte_t vpte;
	paddr_t child;

	vpte = (iovpte_t)(pvpte->vp) + offset;
	pte = (iopte_t)(pvpte->pp) + offset;

	/*
	 * the pte is nonpresent, alloc new page
	 */
	if (*pte == NULL) {
		child = iommu_get_page(domain->dm_iommu, KM_SLEEP);
		set_pte(pte, IOMMU_PAGE_PROP_RW, child);
		domain->dm_iommu->iu_dmar_ops->do_clflush((caddr_t)pte,
		    sizeof (*pte));
		vpte->vp = kmem_zalloc(IOMMU_PAGE_SIZE << 1, KM_SLEEP);
		vpte->pp = iommu_page_map(child);
	}

	return (vpte);
}

/*
 * iommu_setup_page_table()
 *   setup the page table for a dvma
 */
static caddr_t
iommu_setup_page_table(dmar_domain_state_t *domain, uint64_t dvma)
{
	iovpte_t vpte;
	uint_t level;
	uint_t offset;
	int i;

	level = domain->dm_iommu->iu_level;
	vpte = &(domain->dm_pt_tree);

	for (i = level; i > 1; i--) {
		offset = dvma_level_offset(IOMMU_BTOP(dvma), i);
		vpte = iommu_setup_level_table(domain, vpte, offset);
	}

	return (vpte->pp);
}

/*
 * iommu_map_page_range()
 *   map a range of pages for iommu translation
 *
 * domain: the device domain
 * dvma: the start dvma for mapping
 * start: the start physcial address
 * end: the end physical address
 * flags: misc flag
 */
static int
iommu_map_page_range(dmar_domain_state_t *domain, uint64_t dvma,
    uint64_t start, uint64_t end, int flags)
{
	uint_t offset;
	iopte_t pte;
	caddr_t vaddr, dirt;
	uint64_t paddr = start & IOMMU_PAGE_MASK;
	uint64_t epaddr = end & IOMMU_PAGE_MASK;
	uint64_t ioaddr = dvma & IOMMU_PAGE_MASK;
	uint_t count;

	while (paddr <= epaddr) {
		vaddr = iommu_setup_page_table(domain, ioaddr);
		offset = dvma_level_offset(IOMMU_BTOP(ioaddr), 1);

		count = 0;
		dirt = (caddr_t)((iopte_t)vaddr + offset);
		while ((paddr <= epaddr) && (offset < IOMMU_PTE_MAX)) {
			pte = (iopte_t)vaddr + offset;
			if (*pte != NULL) {
				if (pte_get_paddr(pte) != paddr) {
					cmn_err(CE_WARN, "try to set "
					    "non-NULL pte");
				}
			} else {
				set_pte(pte, IOMMU_PAGE_PROP_RW, paddr);
			}
			paddr += IOMMU_PAGE_SIZE;
			offset++;
			count++;
		}

		/* flush cpu and iotlb cache */
		domain->dm_iommu->iu_dmar_ops->do_clflush(dirt,
		    count * sizeof (uint64_t));

		if (!(flags & IOMMU_PAGE_PROP_NOSYNC)) {
			/* cache mode set, flush iotlb */
			if (IOMMU_CAP_GET_CM(domain->dm_iommu->iu_capability)) {
				domain->dm_iommu->iu_dmar_ops->
				    do_iotlb_psi(domain->dm_iommu,
				    0, ioaddr, count, TLB_IVA_WHOLE);
			/* cache mode not set, flush write buffer */
			} else {
				domain->dm_iommu->iu_dmar_ops->
				    do_flwb(domain->dm_iommu);
			}
		}

		ioaddr += IOMMU_PTOB(count);
	}

	return (DDI_SUCCESS);
}

/*
 * build_single_rmrr_identity_map()
 *   build identity map for a single rmrr unit
 */
static void
build_single_rmrr_identity_map(rmrr_info_t *rmrr)
{
	pci_dev_scope_t *devs;
	pci_dev_info_t info;
	uint64_t start, end, size;
	dmar_domain_state_t *domain;

	info.pdi_seg = rmrr->ri_segment;
	for_each_in_list(&(rmrr->ri_dev_list), devs) {
		info.pdi_bus = devs->pds_bus;
		info.pdi_devfn = (devs->pds_dev << 3) |
		    devs->pds_func;

		if (get_dip_from_info(&info) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "rmrr: get dip for %d,%d failed",
			    info.pdi_bus, info.pdi_devfn);
			continue;
		}

		if (iommu_get_domain(info.pdi_dip, &domain) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "rmrr: get domain for %s failed",
			    ddi_node_name(info.pdi_dip));
			continue;
		}

		start = rmrr->ri_baseaddr;
		end = rmrr->ri_limiaddr;
		size = end - start + 1;

		/*
		 * setup the page tables
		 */
		if ((vmem_xalloc(domain->dm_dvma_map,
		    size,		/* size */
		    IOMMU_PAGE_SIZE,	/* align/quantum */
		    0,			/* phase */
		    0,			/* nocross */
		    (void *)(uintptr_t)start,		/* minaddr */
		    (void *)(uintptr_t)(end + 1),	/* maxaddr */
		    VM_NOSLEEP) != NULL)) {
			(void) iommu_map_page_range(domain,
			    start, start, end,
			    DDI_DMA_READ | DDI_DMA_WRITE |
			    IOMMU_PAGE_PROP_NOSYNC);
		} else {
			cmn_err(CE_WARN, "Can't reserve 0x%" PRIx64
			    " ~ 0x%" PRIx64 " for %s", start, end,
			    ddi_node_name(info.pdi_dip));
		}
	}
}

/*
 * build_rmrr_identity_map()
 *   build identity mapping for devices under rmrr scopes
 */
static void
build_rmrr_identity_map(void)
{
	rmrr_info_t *rmrr;
	int i;

	for (i = 0; i < DMAR_MAX_SEGMENT; i++) {
		if (list_is_empty(&(dmar_info->dmari_rmrr[i])))
			break;
		for_each_in_list(&(dmar_info->dmari_rmrr[i]), rmrr) {
			build_single_rmrr_identity_map(rmrr);
		}
	}
}

/*
 * drhd_only_for_gfx()
 *   return TRUE, if the drhd is only for gfx
 */
static boolean_t
drhd_only_for_gfx(intel_iommu_state_t *iommu)
{
	drhd_info_t *drhd = iommu->iu_drhd;
	pci_dev_scope_t *devs;
	pci_dev_info_t info;
	int dev_num;

	if (drhd->di_include_all)
		return (B_FALSE);

	/* get the device number attached to this drhd */
	dev_num = 0;
	for_each_in_list(&(drhd->di_dev_list), devs) {
		dev_num++;
	}

	if (dev_num == 1) {
		iommu_private_t *private;
		devs = list_head(&(drhd->di_dev_list));
		info.pdi_seg = drhd->di_segment;
		info.pdi_bus = devs->pds_bus;
		info.pdi_devfn = (devs->pds_dev << 3) +
		    (devs->pds_func & 0x7);

		if (get_dip_from_info(&info) != DDI_SUCCESS) {
			return (B_FALSE);
		}

		private = DEVI(info.pdi_dip)->devi_iommu_private;
		if (private->idp_is_display)
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * build_dev_identity_map()
 *   build identity map for a device
 */
static void
build_dev_identity_map(dev_info_t *dip)
{
	struct memlist *mp;
	dmar_domain_state_t *domain;

	if (iommu_get_domain(dip, &domain) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "build identity map for %s failed,"
		    "this device may not be functional",
		    ddi_node_name(dip));
		return;
	}

	ASSERT(bootops != NULL);
	ASSERT(!modrootloaded);
	mp = bootops->boot_mem->physinstalled;
	while (mp != 0) {
		(void) iommu_map_page_range(domain,
		    mp->address & IOMMU_PAGE_MASK,
		    mp->address & IOMMU_PAGE_MASK,
		    (mp->address + mp->size - 1) & IOMMU_PAGE_MASK,
		    DDI_DMA_READ | DDI_DMA_WRITE |
		    IOMMU_PAGE_PROP_NOSYNC);
		mp = mp->next;
	}

	/*
	 * record the identity map for domain, any device
	 * which uses this domain will needn't any further
	 * map
	 */
	domain->dm_identity = B_TRUE;
}

/*
 * build_isa_gfx_identity_walk()
 *   the walk function for build_isa_gfx_identity_map()
 */
static int
build_isa_gfx_identity_walk(dev_info_t *dip, void *arg)
{
	_NOTE(ARGUNUSED(arg))

	iommu_private_t *private;
	private = DEVI(dip)->devi_iommu_private;

	/* ignore the NULL private device */
	if (!private)
		return (DDI_WALK_CONTINUE);

	/* fix the gfx and fd */
	if (private->idp_is_display) {
		gfx_devinfo = dip;
		build_dev_identity_map(dip);
	} else if (private->idp_is_lpc) {
		lpc_devinfo = dip;
	}

	/* workaround for pci8086,10bc pci8086,11bc */
	if ((strcmp(ddi_node_name(dip), "pci8086,10bc") == 0) ||
	    (strcmp(ddi_node_name(dip), "pci8086,11bc") == 0)) {
		cmn_err(CE_CONT, "?Workaround for PRO/1000 PT Quad"
		    " Port LP Server Adapter applied\n");
		build_dev_identity_map(dip);
	}

	return (DDI_WALK_CONTINUE);
}

/*
 * build_isa_gfx_identity_map()
 *   build identity map for isa and gfx devices
 */
static void
build_isa_gfx_identity_map(void)
{
	int count;

	/*
	 * walk through the device tree from pdip
	 * normally, pdip should be the pci root
	 */
	ndi_devi_enter(pci_top_devinfo, &count);
	ddi_walk_devs(ddi_get_child(pci_top_devinfo),
	    build_isa_gfx_identity_walk, NULL);
	ndi_devi_exit(pci_top_devinfo, count);
}

/*
 * dmar_check_boot_option()
 *   check the intel iommu boot option
 */
static void
dmar_check_boot_option(char *opt, int *var)
{
	int len;
	char *boot_option;

	*var = 0;

	if ((len = do_bsys_getproplen(NULL, opt)) > 0) {
		boot_option = kmem_alloc(len, KM_SLEEP);
		(void) do_bsys_getprop(NULL, opt, boot_option);
		if (strcmp(boot_option, "yes") == 0 ||
		    strcmp(boot_option, "true") == 0) {
			cmn_err(CE_CONT, "\"%s=true\" was set\n",
			    opt);
			*var = 1;
		} else if (strcmp(boot_option, "no") == 0 ||
		    strcmp(boot_option, "false") == 0) {
			cmn_err(CE_CONT, "\"%s=false\" was set\n",
			    opt);
			*var = 0;
		}
		kmem_free(boot_option, len);
	}
}

extern void (*rootnex_iommu_add_intr)(void);

/*
 * intel_iommu_attach_dmar_nodes()
 *   attach intel iommu nodes
 */
int
intel_iommu_attach_dmar_nodes(void)
{
	drhd_info_t *drhd;
	intel_iommu_state_t *iommu;
	dmar_reserve_pages_t *rmem;
	int i;

	/*
	 * retrieve the dmar boot options
	 */
	cmn_err(CE_CONT, "?Start to check dmar related boot options\n");
	dmar_check_boot_option("dmar-gfx-disable", &gfx_drhd_disable);
	dmar_check_boot_option("dmar-drhd-disable", &dmar_drhd_disable);

	/*
	 * init the lists
	 */
	list_create(&iommu_states, sizeof (intel_iommu_state_t),
	    offsetof(intel_iommu_state_t, node));
	list_create(&reserve_memory, sizeof (dmar_reserve_pages_t),
	    offsetof(dmar_reserve_pages_t, node));

	pci_top_devinfo = ddi_find_devinfo("pci", -1, 0);
	isa_top_devinfo = ddi_find_devinfo("isa", -1, 0);
	if (pci_top_devinfo == NULL) {
		cmn_err(CE_WARN, "can't get pci top devinfo");
		return (DDI_FAILURE);
	}

	iommu_page_init();

	/*
	 * initiate each iommu unit
	 */
	cmn_err(CE_CONT, "?Start to create iommu state structures\n");
	for (i = 0; i < DMAR_MAX_SEGMENT; i++) {
		for_each_in_list(&(dmar_info->dmari_drhd[i]), drhd) {
			if (create_iommu_state(drhd) != DDI_SUCCESS)
				goto iommu_init_fail;
		}
	}

	/*
	 * register interrupt remap ops
	 */
	if (dmar_info->dmari_intr_remap == B_TRUE) {
		psm_vt_ops = &intr_remap_ops;
	}

	/*
	 * collect the reserved memory pages
	 */
	cmn_err(CE_CONT, "?Start to collect the reserved memory\n");
	iommu_collect_reserve_memory();

	/*
	 * build identity map for devices in the rmrr scope
	 */
	cmn_err(CE_CONT, "?Start to prepare identity map for rmrr\n");
	build_rmrr_identity_map();

	/*
	 * build identity map for isa and gfx devices
	 */
	cmn_err(CE_CONT, "?Start to prepare identity map for gfx\n");
	build_isa_gfx_identity_map();

	/*
	 * initialize the dvma cookie cache
	 */
	for (i = 0; i < MAX_COOKIE_CACHE_SIZE; i++) {
		mutex_init(&(cookie_cache[i].dch_lock), NULL,
		    MUTEX_DRIVER, NULL);
		cookie_cache[i].dch_count = 0;
		cookie_cache[i].dch_next = NULL;
	}

	/*
	 * regist the intr add function
	 */
	rootnex_iommu_add_intr = intel_iommu_add_intr;

	/*
	 * enable dma remapping
	 */
	cmn_err(CE_CONT, "?Start to enable the dmar units\n");
	if (!dmar_drhd_disable) {
		for_each_in_list(&iommu_states, iommu) {
			if (gfx_drhd_disable &&
			    drhd_only_for_gfx(iommu))
				continue;
			iommu_bringup_unit(iommu);
		}
	}

	return (DDI_SUCCESS);

iommu_init_fail:
	/*
	 * free the reserve memory list
	 */
	while (rmem = list_head(&reserve_memory)) {
		list_remove(&reserve_memory, rmem);
		kmem_free(rmem, sizeof (dmar_reserve_pages_t));
	}
	list_destroy(&reserve_memory);

	/*
	 * free iommu state structure
	 */
	while (iommu = list_head(&iommu_states)) {
		list_remove(&iommu_states, iommu);
		destroy_iommu_state(iommu);
	}
	list_destroy(&iommu_states);

	return (DDI_FAILURE);
}

/*
 * get_level_table()
 *   get level n page table, NULL is returned if
 *   failure encountered
 */
static caddr_t
get_level_table(dmar_domain_state_t *domain,
    uint64_t dvma_pn, uint_t n)
{
	iovpte_t vpte;
	uint_t level;
	uint_t i, offset;

	level = domain->dm_iommu->iu_level;
	ASSERT(level >= n);
	vpte = &(domain->dm_pt_tree);

	/* walk to the level n page table */
	for (i = level; i > n; i--) {
		offset = dvma_level_offset(dvma_pn, i);
		vpte = (iovpte_t)(vpte->vp) + offset;
	}

	return (vpte->pp);
}

/*
 * iommu_alloc_cookie_array()
 *   allocate the cookie array which is needed by map sgl
 */
static int
iommu_alloc_cookie_array(rootnex_dma_t *dma,
    struct ddi_dma_req *dmareq, uint_t prealloc)
{
	int kmflag;
	rootnex_sglinfo_t *sinfo = &(dma->dp_sglinfo);

	/* figure out the rough estimate of array size */
	sinfo->si_max_pages =
	    (dmareq->dmar_object.dmao_size + IOMMU_PAGE_OFFSET) /
	    sinfo->si_max_cookie_size + 1;

	/* the preallocated buffer fit this size */
	if (sinfo->si_max_pages <= prealloc) {
		dma->dp_cookies = (ddi_dma_cookie_t *)dma->dp_prealloc_buffer;
		dma->dp_need_to_free_cookie = B_FALSE;
	/* we need to allocate new array */
	} else {
		/* convert the sleep flags */
		if (dmareq->dmar_fp == DDI_DMA_SLEEP) {
			kmflag =  KM_SLEEP;
		} else {
			kmflag =  KM_NOSLEEP;
		}

		dma->dp_cookie_size = sinfo->si_max_pages *
		    sizeof (ddi_dma_cookie_t);
		dma->dp_cookies = kmem_alloc(dma->dp_cookie_size, kmflag);
		if (dma->dp_cookies == NULL) {
			return (IOMMU_SGL_NORESOURCES);
		}
		dma->dp_need_to_free_cookie = B_TRUE;
	}

	/* allocate the dvma cookie array */
	dma->dp_dvma_cookies = get_dvma_cookie_array(sinfo->si_max_pages);

	return (IOMMU_SGL_SUCCESS);
}

/*
 * iommu_alloc_dvma()
 *   alloc a dvma range for the caller
 */
static int
iommu_alloc_dvma(dmar_domain_state_t *domain, uint_t size,
    ddi_dma_impl_t *hp, uint64_t *dvma, uint_t cnt)
{
	rootnex_dma_t *dma;
	ddi_dma_attr_t *dma_attr;
	iommu_dvma_cookie_t *dcookie;
	uint64_t ioaddr;
	size_t xsize, align, nocross;
	uint64_t minaddr, maxaddr;

	/* shotcuts */
	dma = (rootnex_dma_t *)hp->dmai_private;
	dma_attr = &(hp->dmai_attr);
	dcookie = dma->dp_dvma_cookies;

	/* parameters */
	xsize = (size + IOMMU_PAGE_OFFSET) & IOMMU_PAGE_MASK;
	align = MAX((size_t)(dma_attr->dma_attr_align), IOMMU_PAGE_SIZE);
	nocross = (size_t)(dma_attr->dma_attr_seg + 1);
	minaddr = dma_attr->dma_attr_addr_lo;
	maxaddr = dma_attr->dma_attr_addr_hi + 1;

	/* handle the rollover cases */
	if (maxaddr < dma_attr->dma_attr_addr_hi) {
		maxaddr = dma_attr->dma_attr_addr_hi;
	}

	/* get from cache first */
	ioaddr = iommu_dvma_cache_get(domain, xsize, align, nocross);

	if (ioaddr == NULL) {
		/* allocate from vmem arena */
		ioaddr = (uint64_t)(uintptr_t)vmem_xalloc(domain->dm_dvma_map,
		    xsize, align, 0, nocross,
		    (void *)(uintptr_t)minaddr,
		    (void *)(uintptr_t)maxaddr,
		    VM_NOSLEEP);

		/* if xalloc failed, we have to flush the cache and retry */
		if (ioaddr == NULL) {
			iommu_dvma_cache_flush(domain, dma->dp_dip);
			ioaddr = (uint64_t)(uintptr_t)vmem_xalloc(
			    domain->dm_dvma_map,
			    xsize, align, 0, nocross,
			    (void *)(uintptr_t)minaddr,
			    (void *)(uintptr_t)maxaddr,
			    VM_NOSLEEP);
			ASSERT(ioaddr);
		}
	}

	ASSERT(ioaddr >= minaddr);
	ASSERT(ioaddr + size - 1 < maxaddr);

	*dvma = ioaddr;

	/*
	 * save the dvma range in the device dvma cookie
	 */
	dcookie[cnt].dc_addr = ioaddr;
	dcookie[cnt].dc_size = xsize;
	dcookie[cnt].dc_domain = domain;
	dcookie[cnt].dc_align = align;

	return (DDI_SUCCESS);
}

/*
 * iommu_map_dvma()
 *   map dvma to the physical addresses, the actual
 *   mapped dvma page number is returned
 */
static int
iommu_map_dvma(dmar_domain_state_t *domain, uint64_t dvma,
    uint64_t paddr, uint_t psize, struct ddi_dma_req *dmareq)
{
	uint64_t start, end;
	int flags;

	start = paddr & IOMMU_PAGE_MASK;
	end = (paddr + psize - 1) & IOMMU_PAGE_MASK;
	flags = dmareq->dmar_flags & DDI_DMA_RDWR;

	/* map each physical address */
	(void) iommu_map_page_range(domain, dvma, start, end, flags);
	return (IOMMU_BTOP(end - start) + 1);
}

/*
 * intel_iommu_map_sgl()
 *   called from rootnex_dma_bindhdl(), to build dma
 *   cookies when iommu is enabled
 */
int
intel_iommu_map_sgl(ddi_dma_handle_t handle,
    struct ddi_dma_req *dmareq, uint_t prealloc)
{
	ddi_dma_atyp_t buftype;
	uint64_t offset;
	page_t **pparray;
	uint64_t paddr;
	uint64_t dvma;
	uint_t psize;
	uint_t size;
	uint64_t maxseg;
	caddr_t vaddr;
	uint_t pcnt, cnt;
	page_t *page;
	ddi_dma_cookie_t *sgl;
	rootnex_sglinfo_t *sglinfo;
	ddi_dma_obj_t *dmar_object;
	ddi_dma_impl_t *hp;
	rootnex_dma_t *dma;
	dmar_domain_state_t *domain;
	int e;

	hp = (ddi_dma_impl_t *)handle;
	dma = (rootnex_dma_t *)hp->dmai_private;
	sglinfo = &(dma->dp_sglinfo);
	dmar_object = &(dmareq->dmar_object);
	maxseg = sglinfo->si_max_cookie_size;
	pparray = dmar_object->dmao_obj.virt_obj.v_priv;
	vaddr = dmar_object->dmao_obj.virt_obj.v_addr;
	buftype = dmar_object->dmao_type;
	size = dmar_object->dmao_size;

	/* get domain for the dma request */
	if (iommu_get_domain(dma->dp_dip, &domain) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "get domain for %s failed",
		    ddi_node_name(dma->dp_dip));
		return (IOMMU_SGL_NORESOURCES);
	}

	/* direct return if drhd is disabled */
	if (!(domain->dm_iommu->iu_enabled & DMAR_ENABLE) ||
	    domain->dm_identity)
		return (IOMMU_SGL_DISABLE);

	/*
	 * allocate the cookies arrays, if the pre-allocated
	 * space is not enough, we should reallocate it
	 */
	if (iommu_alloc_cookie_array(dma, dmareq, prealloc)
	    != IOMMU_SGL_SUCCESS)
		return (IOMMU_SGL_NORESOURCES);
	hp->dmai_cookie = dma->dp_cookies;
	sgl = dma->dp_cookies;

	pcnt = 0;
	cnt = 0;

	/* retrieve paddr, psize, offset from dmareq */
	if (buftype == DMA_OTYP_PAGES) {
		page = dmar_object->dmao_obj.pp_obj.pp_pp;
		ASSERT(!PP_ISFREE(page) && PAGE_LOCKED(page));
		offset =  dmar_object->dmao_obj.pp_obj.pp_offset &
		    MMU_PAGEOFFSET;
		paddr = pfn_to_pa(page->p_pagenum) + offset;
		psize = MIN((MMU_PAGESIZE - offset), size);
		sglinfo->si_asp = NULL;
		page = page->p_next;
	} else {
		ASSERT((buftype == DMA_OTYP_VADDR) ||
		    (buftype == DMA_OTYP_BUFVADDR));
		sglinfo->si_asp = dmar_object->dmao_obj.virt_obj.v_as;
		if (sglinfo->si_asp == NULL) {
			sglinfo->si_asp = &kas;
		}
		offset = (uintptr_t)vaddr & MMU_PAGEOFFSET;

		if (pparray != NULL) {
			ASSERT(!PP_ISFREE(pparray[pcnt]));
			paddr = pfn_to_pa(pparray[pcnt]->p_pagenum) + offset;
			psize = MIN((MMU_PAGESIZE - offset), size);
			pcnt++;
		} else {
			paddr = pfn_to_pa(hat_getpfnum(sglinfo->si_asp->a_hat,
			    vaddr)) + offset;
			psize = MIN(size, (MMU_PAGESIZE - offset));
			vaddr += psize;
		}
	}

	/* save the iommu page offset */
	sglinfo->si_buf_offset = offset & IOMMU_PAGE_OFFSET;

	/*
	 * allocate the dvma and map [paddr, paddr+psize)
	 */
	e = iommu_alloc_dvma(domain, MIN(size + sglinfo->si_buf_offset,
	    maxseg), hp, &dvma, cnt);
	if (e != DDI_SUCCESS)
		return (IOMMU_SGL_NORESOURCES);
	e  = iommu_map_dvma(domain, dvma, paddr, psize, dmareq);

	/*
	 * setup the first cookie with the dvma of the page
	 * and the its size, we don't take account in the
	 * offset into the first page now
	 */
	sgl[cnt].dmac_laddress = dvma;
	sgl[cnt].dmac_size = psize + sglinfo->si_buf_offset;
	sgl[cnt].dmac_type = 0;
	dvma += IOMMU_PTOB(e);

	size -= psize;
	while (size > 0) {
		/* get the size for this page (i.e. partial or full page) */
		psize = MIN(size, MMU_PAGESIZE);
		if (buftype == DMA_OTYP_PAGES) {
			/* get the paddr from the page_t */
			ASSERT(!PP_ISFREE(page) && PAGE_LOCKED(page));
			paddr = pfn_to_pa(page->p_pagenum);
			page = page->p_next;
		} else if (pparray != NULL) {
			/* index into the array of page_t's to get the paddr */
			ASSERT(!PP_ISFREE(pparray[pcnt]));
			paddr = pfn_to_pa(pparray[pcnt]->p_pagenum);
			pcnt++;
		} else {
			/* call into the VM to get the paddr */
			paddr = pfn_to_pa(hat_getpfnum
			    (sglinfo->si_asp->a_hat, vaddr));
			vaddr += psize;
		}

		/*
		 * check to see if this page would put us
		 * over the max cookie size
		 */
		if ((sgl[cnt].dmac_size + psize) > maxseg) {
			/* use the next cookie */
			cnt++;

			/* allocate the dvma and map [paddr, paddr+psize) */
			e = iommu_alloc_dvma(domain, MIN(size, maxseg),
			    hp, &dvma, cnt);
			if (e != DDI_SUCCESS)
				return (IOMMU_SGL_NORESOURCES);
			e  = iommu_map_dvma(domain, dvma, paddr, psize, dmareq);

			/* save the cookie information */
			sgl[cnt].dmac_laddress = dvma;
			sgl[cnt].dmac_size = psize;
			sgl[cnt].dmac_type = 0;
			dvma += IOMMU_PTOB(e);

		/*
		 * we can add this page in the current cookie
		 */
		} else {
			e  = iommu_map_dvma(domain, dvma, paddr, psize, dmareq);
			sgl[cnt].dmac_size += psize;
			dvma += IOMMU_PTOB(e);
		}

		size -= psize;
	}

	/* take account in the offset into the first page */
	sgl[0].dmac_laddress += sglinfo->si_buf_offset;
	sgl[0].dmac_size -= sglinfo->si_buf_offset;

	/* save away how many cookies we have */
	sglinfo->si_sgl_size = cnt + 1;

	return (IOMMU_SGL_SUCCESS);
}

/*
 * iommu_clear_leaf_pte()
 *   clear a single leaf pte
 */
static void
iommu_clear_leaf_pte(dmar_domain_state_t *domain, uint64_t dvma, uint64_t size)
{
	iopte_t pte;
	uint_t offset;
	caddr_t leaf_table, dirt;
	uint64_t csize = 0;
	uint64_t cdvma = dvma & IOMMU_PAGE_MASK;
	int count;

	while (csize < size) {

		/* retrieve the leaf page table */
		leaf_table = get_level_table(domain, IOMMU_BTOP(cdvma), 1);
		if (!leaf_table) {
			cmn_err(CE_WARN, "get level 1 table for 0x%"
			    PRIx64 "failed", cdvma);
			return;
		}

		/* map the leaf page and walk to the pte */
		offset = dvma_level_offset(IOMMU_BTOP(cdvma), 1);

		/* clear the ptes */
		count = 0;
		dirt = (caddr_t)((iopte_t)leaf_table + offset);
		while ((csize < size) &&
		    (offset < IOMMU_PTE_MAX)) {
			pte = (iopte_t)leaf_table + offset;
			if (!*pte) {
				cmn_err(CE_WARN, "try to clear NULL pte");
			} else {
				*pte = 0;
			}
			csize += IOMMU_PAGE_SIZE;
			offset++;
			count++;
		}

		/* flush cpu and iotlb cache */
		domain->dm_iommu->iu_dmar_ops->do_clflush(dirt,
		    count * sizeof (uint64_t));
		domain->dm_iommu->iu_dmar_ops->do_iotlb_psi(domain->dm_iommu,
		    domain->dm_domain_id, cdvma, count, TLB_IVA_LEAF);

		/* unmap the leaf page */
		cdvma += IOMMU_PTOB(count);
	}
}

/*
 * intel_iommu_unmap_sgl()
 *   called from rootnex_dma_unbindhdl(), to unbind dma
 *   cookies when iommu is enabled
 */
void
intel_iommu_unmap_sgl(ddi_dma_handle_t handle)
{
	ddi_dma_impl_t *hp;
	rootnex_dma_t *dma;
	dmar_domain_state_t *domain;
	iommu_dvma_cookie_t *dcookies;
	rootnex_sglinfo_t *sinfo;
	uint64_t i;

	hp = (ddi_dma_impl_t *)handle;
	dma = (rootnex_dma_t *)hp->dmai_private;
	dcookies = dma->dp_dvma_cookies;
	sinfo = &(dma->dp_sglinfo);

	/* get the device domain, no return check needed here */
	(void) iommu_get_domain(dma->dp_dip, &domain);

	/* if the drhd is disabled, nothing will be done */
	if (!(domain->dm_iommu->iu_enabled & DMAR_ENABLE) ||
	    domain->dm_identity)
		return;

	/* the drhd is enabled */
	for (i = 0; i < sinfo->si_sgl_size; i++) {
		/* clear leaf ptes */
		iommu_clear_leaf_pte(domain, dcookies[i].dc_addr,
		    dcookies[i].dc_size);
	}

	domain->dm_iommu->iu_dmar_ops->do_reap_wait(domain->dm_iommu);
	domain->dm_iommu->iu_dmar_ops->do_plant_wait(domain->dm_iommu,
	    dcookies, sinfo->si_sgl_size, sinfo->si_max_pages);
}

/*
 * initialize invalidation request queue structure.
 * call ddi_dma_mem_alloc to allocate physical contigous
 * pages for invalidation queue table
 */
static int
iommu_qinv_init(intel_iommu_state_t *iommu)
{
	inv_queue_state_t *inv_queue;
	size_t size;

	ddi_dma_attr_t inv_queue_dma_attr = {
		DMA_ATTR_V0,
		0U,
		0xffffffffU,
		0xffffffffU,
		MMU_PAGESIZE, /* page aligned */
		0x1,
		0x1,
		0xffffffffU,
		0xffffffffU,
		1,
		4,
		0
	};

	ddi_device_acc_attr_t inv_queue_acc_attr = {
		DDI_DEVICE_ATTR_V0,
		DDI_NEVERSWAP_ACC,
		DDI_STRICTORDER_ACC
	};

	if (qinv_iqa_qs > QINV_MAX_QUEUE_SIZE)
		qinv_iqa_qs = QINV_MAX_QUEUE_SIZE;

	inv_queue = (inv_queue_state_t *)
	    kmem_zalloc(sizeof (inv_queue_state_t), KM_SLEEP);

	/* set devi_ops in dev info structure for ddi_dma_mem_alloc */
	DEVI(iommu->iu_drhd->di_dip)->devi_ops =
	    DEVI(ddi_root_node())->devi_ops;

	/*
	 * set devi_bus_dma_allochdl in dev info structure for
	 * ddi_dma_free_handle
	 */
	DEVI(iommu->iu_drhd->di_dip)->devi_bus_dma_allochdl =
	    DEVI(ddi_root_node());

	if (ddi_dma_alloc_handle(iommu->iu_drhd->di_dip,
	    &inv_queue_dma_attr,
	    DDI_DMA_SLEEP,
	    NULL,
	    &(inv_queue->iq_table.dma_hdl)) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "alloc invalidation queue table handler failed\n");
		goto queue_table_handle_failed;
	}

	if (ddi_dma_alloc_handle(iommu->iu_drhd->di_dip,
	    &inv_queue_dma_attr,
	    DDI_DMA_SLEEP,
	    NULL,
	    &(inv_queue->iq_sync.dma_hdl)) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "alloc invalidation queue sync mem handler failed\n");
		goto sync_table_handle_failed;
	}

	inv_queue->iq_table.size = (1 << (qinv_iqa_qs + 8));
	size = inv_queue->iq_table.size * QINV_ENTRY_SIZE;

	/* alloc physical contiguous pages for invalidation queue */
	if (ddi_dma_mem_alloc(inv_queue->iq_table.dma_hdl,
	    size,
	    &inv_queue_acc_attr,
	    DDI_DMA_CONSISTENT | IOMEM_DATA_UNCACHED,
	    DDI_DMA_SLEEP,
	    NULL,
	    &(inv_queue->iq_table.vaddr),
	    &size,
	    &(inv_queue->iq_table.acc_hdl)) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "alloc invalidation queue table failed\n");
		goto queue_table_mem_failed;
	}

	ASSERT(!((uintptr_t)inv_queue->iq_table.vaddr & MMU_PAGEOFFSET));
	bzero(inv_queue->iq_table.vaddr, size);

	/* get the base physical address of invalidation request queue */
	inv_queue->iq_table.paddr = pfn_to_pa(
	    hat_getpfnum(kas.a_hat, inv_queue->iq_table.vaddr));

	inv_queue->iq_table.head = inv_queue->iq_table.tail = 0;

	inv_queue->iq_sync.size = inv_queue->iq_table.size;
	size = inv_queue->iq_sync.size * QINV_SYNC_DATA_SIZE;

	/* alloc status memory for invalidation wait descriptor */
	if (ddi_dma_mem_alloc(inv_queue->iq_sync.dma_hdl,
	    size,
	    &inv_queue_acc_attr,
	    DDI_DMA_CONSISTENT | IOMEM_DATA_UNCACHED,
	    DDI_DMA_SLEEP,
	    NULL,
	    &(inv_queue->iq_sync.vaddr),
	    &size,
	    &(inv_queue->iq_sync.acc_hdl)) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "alloc invalidation queue sync mem failed\n");
		goto sync_table_mem_failed;
	}

	ASSERT(!((uintptr_t)inv_queue->iq_sync.vaddr & MMU_PAGEOFFSET));
	bzero(inv_queue->iq_sync.vaddr, size);
	inv_queue->iq_sync.paddr = pfn_to_pa(
	    hat_getpfnum(kas.a_hat, inv_queue->iq_sync.vaddr));

	inv_queue->iq_sync.head = inv_queue->iq_sync.tail = 0;

	mutex_init(&(inv_queue->iq_table.lock), NULL, MUTEX_DRIVER, NULL);
	mutex_init(&(inv_queue->iq_sync.lock), NULL, MUTEX_DRIVER, NULL);

	/*
	 * init iotlb pend node for submitting invalidation iotlb
	 * queue request
	 */
	inv_queue->iotlb_pend_node = (iotlb_pend_node_t **)
	    kmem_zalloc(inv_queue->iq_sync.size
	    * sizeof (iotlb_pend_node_t *), KM_SLEEP);

	/* set invalidation queue structure */
	iommu->iu_inv_queue = inv_queue;

	return (DDI_SUCCESS);

sync_table_mem_failed:
	ddi_dma_mem_free(&(inv_queue->iq_table.acc_hdl));

queue_table_mem_failed:
	ddi_dma_free_handle(&(inv_queue->iq_sync.dma_hdl));

sync_table_handle_failed:
	ddi_dma_free_handle(&(inv_queue->iq_table.dma_hdl));

queue_table_handle_failed:
	kmem_free(inv_queue, sizeof (inv_queue_state_t));

	return (ENOMEM);
}

/* destroy invalidation queue structure */
static void
iommu_qinv_fini(intel_iommu_state_t *iommu)
{
	inv_queue_state_t *inv_queue;

	inv_queue = iommu->iu_inv_queue;
	kmem_free(inv_queue->iotlb_pend_node,
	    inv_queue->iq_sync.size
	    * sizeof (iotlb_pend_node_t *));
	ddi_dma_mem_free(&(inv_queue->iq_sync.acc_hdl));
	ddi_dma_mem_free(&(inv_queue->iq_table.acc_hdl));
	ddi_dma_free_handle(&(inv_queue->iq_sync.dma_hdl));
	ddi_dma_free_handle(&(inv_queue->iq_table.dma_hdl));
	mutex_destroy(&(inv_queue->iq_table.lock));
	mutex_destroy(&(inv_queue->iq_sync.lock));
	kmem_free(inv_queue, sizeof (inv_queue_state_t));
}

/* enable queued invalidation interface */
static void
iommu_qinv_enable(intel_iommu_state_t *iommu)
{
	inv_queue_state_t *inv_queue;
	uint64_t iqa_reg_value;
	uint32_t status;

	struct dmar_ops *dmar_ops;

	inv_queue = iommu->iu_inv_queue;

	iqa_reg_value = inv_queue->iq_table.paddr | qinv_iqa_qs;

	mutex_enter(&iommu->iu_reg_lock);
	/* Initialize the Invalidation Queue Tail register to zero */
	iommu_put_reg64(iommu, IOMMU_REG_INVAL_QT, 0);

	/* set invalidation queue base address register */
	iommu_put_reg64(iommu, IOMMU_REG_INVAL_QAR, iqa_reg_value);

	/* enable queued invalidation interface */
	iommu_put_reg32(iommu, IOMMU_REG_GLOBAL_CMD,
	    iommu->iu_global_cmd_reg | IOMMU_GCMD_QIE);
	iommu_wait_completion(iommu, IOMMU_REG_GLOBAL_STS,
	    iommu_get_reg32, (status & IOMMU_GSTS_QIES), status);
	mutex_exit(&iommu->iu_reg_lock);

	iommu->iu_global_cmd_reg |= IOMMU_GCMD_QIE;
	iommu->iu_enabled |= QINV_ENABLE;

	/* set new queued invalidation interface */
	dmar_ops = iommu->iu_dmar_ops;

	dmar_ops->do_context_fsi = qinv_cc_fsi;
	dmar_ops->do_context_dsi = qinv_cc_dsi;
	dmar_ops->do_context_gbl = qinv_cc_gbl;
	dmar_ops->do_iotlb_psi = qinv_iotlb_psi;
	dmar_ops->do_iotlb_dsi = qinv_iotlb_dsi;
	dmar_ops->do_iotlb_gbl = qinv_iotlb_gbl;
	dmar_ops->do_plant_wait = qinv_plant_wait;
	dmar_ops->do_reap_wait = qinv_reap_wait;
}

/* submit invalidation request descriptor to invalidation queue */
static void
qinv_submit_inv_dsc(intel_iommu_state_t *iommu, inv_dsc_t *dsc)
{
	inv_queue_state_t *inv_queue;
	inv_queue_mem_t *iq_table;
	uint_t tail;
	uint_t old_tail;

	inv_queue = iommu->iu_inv_queue;
	iq_table = &(inv_queue->iq_table);

	mutex_enter(&iq_table->lock);
	tail = iq_table->tail;
	iq_table->tail++;

	if (iq_table->tail == iq_table->size)
		iq_table->tail = 0;

	while (iq_table->head == iq_table->tail) {
		/*
		 * inv queue table exhausted, wait hardware to fetch
		 * next decscritor
		 */
		iq_table->head = QINV_IQA_HEAD(
		    iommu_get_reg64(iommu, IOMMU_REG_INVAL_QH));
	}
	old_tail = iq_table->tail;
	mutex_exit(&iq_table->lock);

	bcopy(dsc, iq_table->vaddr + tail * QINV_ENTRY_SIZE,
	    QINV_ENTRY_SIZE);

	mutex_enter(&iq_table->lock);
	if (old_tail == iq_table->tail)
		iommu_put_reg64(iommu, IOMMU_REG_INVAL_QT,
		    iq_table->tail << QINV_IQA_TAIL_SHIFT);
	mutex_exit(&iq_table->lock);
}

/* queued invalidation interface -- invalidate context cache */
static void
qinv_cc_common(intel_iommu_state_t *iommu, uint8_t function_mask,
    uint16_t source_id, uint_t domain_id, ctt_inv_g_t type)
{
	inv_dsc_t dsc;

	dsc.lo = CC_INV_DSC_LOW(function_mask, source_id, domain_id, type);
	dsc.hi = CC_INV_DSC_HIGH;

	qinv_submit_inv_dsc(iommu, &dsc);

	/* record the context cache statistics */
	atomic_inc_64(&(iommu->iu_statistics.st_context_cache));
}

/* queued invalidation interface -- invalidate iotlb */
static void
qinv_iotlb_common(intel_iommu_state_t *iommu, uint_t domain_id,
    uint64_t addr, uint_t am, uint_t hint, tlb_inv_g_t type)
{
	inv_dsc_t dsc;
	uint8_t dr = 0;
	uint8_t dw = 0;

	if (IOMMU_CAP_GET_DRD(iommu->iu_capability))
		dr = 1;
	if (IOMMU_CAP_GET_DWD(iommu->iu_capability))
		dw = 1;

	switch (type) {
	case TLB_INV_G_PAGE:
		if (!IOMMU_CAP_GET_PSI(iommu->iu_capability) ||
		    am > IOMMU_CAP_GET_MAMV(iommu->iu_capability) ||
		    addr & IOMMU_PAGE_OFFSET) {
			type = TLB_INV_G_DOMAIN;
			goto qinv_ignore_psi;
		}
		dsc.lo = IOTLB_INV_DSC_LOW(domain_id, dr, dw, type);
		dsc.hi = IOTLB_INV_DSC_HIGH(addr, hint, am);
		break;

	qinv_ignore_psi:
	case TLB_INV_G_DOMAIN:
		dsc.lo = IOTLB_INV_DSC_LOW(domain_id, dr, dw, type);
		dsc.hi = 0;
		break;

	case TLB_INV_G_GLOBAL:
		dsc.lo = IOTLB_INV_DSC_LOW(0, dr, dw, type);
		dsc.hi = 0;
		break;
	default:
		cmn_err(CE_WARN, "incorrect iotlb flush type");
		return;
	}

	qinv_submit_inv_dsc(iommu, &dsc);

	/*
	 * check the result and record the statistics
	 */
	switch (type) {
	/* global */
	case TLB_INV_G_GLOBAL:
		atomic_inc_64(&(iommu->iu_statistics.st_iotlb_global));
		break;
	/* domain */
	case TLB_INV_G_DOMAIN:
		atomic_inc_64(&(iommu->iu_statistics.st_iotlb_domain));
		break;
	/* psi */
	case TLB_INV_G_PAGE:
		atomic_inc_64(&(iommu->iu_statistics.st_iotlb_psi));
		break;
	default:
		break;
	}
}

/* queued invalidation interface -- invalidate dev_iotlb */
static void
qinv_dev_iotlb_common(intel_iommu_state_t *iommu, uint16_t sid,
    uint64_t addr, uint_t size, uint_t max_invs_pd)
{
	inv_dsc_t dsc;

	dsc.lo = DEV_IOTLB_INV_DSC_LOW(sid, max_invs_pd);
	dsc.hi = DEV_IOTLB_INV_DSC_HIGH(addr, size);

	qinv_submit_inv_dsc(iommu, &dsc);
}

/* queued invalidation interface -- invalidate interrupt entry cache */
static void
qinv_iec_common(intel_iommu_state_t *iommu, uint_t iidx, uint_t im, uint_t g)
{
	inv_dsc_t dsc;

	dsc.lo = IEC_INV_DSC_LOW(iidx, im, g);
	dsc.hi = IEC_INV_DSC_HIGH;

	qinv_submit_inv_dsc(iommu, &dsc);
}

/* queued invalidation interface -- global invalidate interrupt entry cache */
static void
qinv_iec_global(intel_iommu_state_t *iommu)
{
	qinv_iec_common(iommu, 0, 0, IEC_INV_GLOBAL);
	qinv_wait_sync(iommu);
}

/* queued invalidation interface -- invalidate single interrupt entry cache */
static void
qinv_iec_single(intel_iommu_state_t *iommu, uint_t iidx)
{
	qinv_iec_common(iommu, iidx, 0, IEC_INV_INDEX);
	qinv_wait_sync(iommu);
}

/* queued invalidation interface -- invalidate interrupt entry caches */
static void
qinv_iec(intel_iommu_state_t *iommu, uint_t iidx, uint_t cnt)
{
	uint_t	i, mask = 0;

	ASSERT(cnt != 0);

	/* requested interrupt count is not a power of 2 */
	if (!ISP2(cnt)) {
		for (i = 0; i < cnt; i++) {
			qinv_iec_common(iommu, iidx + cnt, 0, IEC_INV_INDEX);
		}
		qinv_wait_sync(iommu);
		return;
	}

	while ((2 << mask) < cnt) {
		mask++;
	}

	if (mask > IOMMU_ECAP_GET_MHMV(iommu->iu_excapability)) {
		for (i = 0; i < cnt; i++) {
			qinv_iec_common(iommu, iidx + cnt, 0, IEC_INV_INDEX);
		}
		qinv_wait_sync(iommu);
		return;
	}

	qinv_iec_common(iommu, iidx, mask, IEC_INV_INDEX);

	qinv_wait_sync(iommu);
}

/*
 * alloc free entry from sync status table
 */
static uint_t
qinv_alloc_sync_mem_entry(intel_iommu_state_t *iommu)
{
	inv_queue_mem_t *sync_mem;
	uint_t tail;

	sync_mem = &iommu->iu_inv_queue->iq_sync;

sync_mem_exhausted:
	mutex_enter(&sync_mem->lock);
	tail = sync_mem->tail;
	sync_mem->tail++;
	if (sync_mem->tail == sync_mem->size)
		sync_mem->tail = 0;

	if (sync_mem->head == sync_mem->tail) {
		/* should never happen */
		cmn_err(CE_WARN, "sync mem exhausted\n");
		sync_mem->tail = tail;
		mutex_exit(&sync_mem->lock);
		delay(IOMMU_ALLOC_RESOURCE_DELAY);
		goto sync_mem_exhausted;
	}
	mutex_exit(&sync_mem->lock);

	return (tail);
}

/*
 * queued invalidation interface -- invalidation wait descriptor
 *   fence flag not set, need status data to indicate the invalidation
 *   wait descriptor completion
 */
static void
qinv_wait_async_unfence(intel_iommu_state_t *iommu, iotlb_pend_node_t *node)
{
	inv_dsc_t dsc;
	inv_queue_mem_t *sync_mem;
	uint64_t saddr;
	uint_t tail;

	sync_mem = &iommu->iu_inv_queue->iq_sync;
	tail = qinv_alloc_sync_mem_entry(iommu);

	/* plant an iotlb pending node */
	iommu->iu_inv_queue->iotlb_pend_node[tail] = node;

	saddr = sync_mem->paddr + tail * QINV_SYNC_DATA_SIZE;

	/*
	 * sdata = QINV_SYNC_DATA_UNFENCE, fence = 0, sw = 1, if = 0
	 * indicate the invalidation wait descriptor completion by
	 * performing a coherent DWORD write to the status address,
	 * not by generating an invalidation completion event
	 */
	dsc.lo = INV_WAIT_DSC_LOW(QINV_SYNC_DATA_UNFENCE, 0, 1, 0);
	dsc.hi = INV_WAIT_DSC_HIGH(saddr);

	qinv_submit_inv_dsc(iommu, &dsc);
}

/*
 * queued invalidation interface -- invalidation wait descriptor
 *   fence flag set, indicate descriptors following the invalidation
 *   wait descriptor must be processed by hardware only after the
 *   invalidation wait descriptor completes.
 */
static void
qinv_wait_async_fence(intel_iommu_state_t *iommu)
{
	inv_dsc_t dsc;

	/* sw = 0, fence = 1, iflag = 0 */
	dsc.lo = INV_WAIT_DSC_LOW(0, 1, 0, 0);
	dsc.hi = 0;
	qinv_submit_inv_dsc(iommu, &dsc);
}

/*
 * queued invalidation interface -- invalidation wait descriptor
 *   wait until the invalidation request finished
 */
static void
qinv_wait_sync(intel_iommu_state_t *iommu)
{
	inv_dsc_t dsc;
	inv_queue_mem_t *sync_mem;
	uint64_t saddr;
	uint_t tail;
	volatile uint32_t *status;

	sync_mem = &iommu->iu_inv_queue->iq_sync;
	tail = qinv_alloc_sync_mem_entry(iommu);
	saddr = sync_mem->paddr + tail * QINV_SYNC_DATA_SIZE;
	status = (uint32_t *)(sync_mem->vaddr + tail * QINV_SYNC_DATA_SIZE);

	/*
	 * sdata = QINV_SYNC_DATA_FENCE, fence = 1, sw = 1, if = 0
	 * indicate the invalidation wait descriptor completion by
	 * performing a coherent DWORD write to the status address,
	 * not by generating an invalidation completion event
	 */
	dsc.lo = INV_WAIT_DSC_LOW(QINV_SYNC_DATA_FENCE, 1, 1, 0);
	dsc.hi = INV_WAIT_DSC_HIGH(saddr);

	qinv_submit_inv_dsc(iommu, &dsc);

	while ((*status) != QINV_SYNC_DATA_FENCE)
		iommu_cpu_nop();
	*status = QINV_SYNC_DATA_UNFENCE;
}

/* get already completed invalidation wait requests */
static int
qinv_wait_async_finish(intel_iommu_state_t *iommu, int *cnt)
{
	inv_queue_mem_t *sync_mem;
	int index;
	volatile uint32_t *value;

	ASSERT((*cnt) == 0);

	sync_mem = &iommu->iu_inv_queue->iq_sync;

	mutex_enter(&sync_mem->lock);
	index = sync_mem->head;
	value = (uint32_t *)(sync_mem->vaddr + index
	    * QINV_SYNC_DATA_SIZE);
	while (*value == QINV_SYNC_DATA_UNFENCE) {
		*value = 0;
		(*cnt)++;
		sync_mem->head++;
		if (sync_mem->head == sync_mem->size) {
			sync_mem->head = 0;
			value = (uint32_t *)(sync_mem->vaddr);
		} else
			value = (uint32_t *)((char *)value +
			    QINV_SYNC_DATA_SIZE);
	}

	mutex_exit(&sync_mem->lock);
	if ((*cnt) > 0)
		return (index);
	else
		return (-1);
}

/*
 * queued invalidation interface
 *   function based context cache invalidation
 */
static void
qinv_cc_fsi(intel_iommu_state_t *iommu, uint8_t function_mask,
    uint16_t source_id, uint_t domain_id)
{
	qinv_cc_common(iommu, function_mask, source_id,
	    domain_id, CTT_INV_G_DEVICE);
	qinv_wait_sync(iommu);
}

/*
 * queued invalidation interface
 *   domain based context cache invalidation
 */
static void
qinv_cc_dsi(intel_iommu_state_t *iommu, uint_t domain_id)
{
	qinv_cc_common(iommu, 0, 0, domain_id, CTT_INV_G_DOMAIN);
	qinv_wait_sync(iommu);
}

/*
 * queued invalidation interface
 *   invalidation global context cache
 */
static void
qinv_cc_gbl(intel_iommu_state_t *iommu)
{
	qinv_cc_common(iommu, 0, 0, 0, CTT_INV_G_GLOBAL);
	qinv_wait_sync(iommu);
}

/*
 * queued invalidation interface
 *   paged based iotlb invalidation
 */
static void
qinv_iotlb_psi(intel_iommu_state_t *iommu, uint_t domain_id,
	uint64_t dvma, uint_t count, uint_t hint)
{
	uint_t am = 0;
	uint_t max_am;

	max_am = IOMMU_CAP_GET_MAMV(iommu->iu_capability);

	/* choose page specified invalidation */
	if (IOMMU_CAP_GET_PSI(iommu->iu_capability)) {
		while (am <= max_am) {
			if ((ADDR_AM_OFFSET(IOMMU_BTOP(dvma), am) + count)
			    <= ADDR_AM_MAX(am)) {
				qinv_iotlb_common(iommu, domain_id,
				    dvma, am, hint, TLB_INV_G_PAGE);
				break;
			}
			am++;
		}
		if (am > max_am) {
			qinv_iotlb_common(iommu, domain_id,
			    dvma, 0, hint, TLB_INV_G_DOMAIN);
		}

	/* choose domain invalidation */
	} else {
		qinv_iotlb_common(iommu, domain_id, dvma,
		    0, hint, TLB_INV_G_DOMAIN);
	}
}

/*
 * queued invalidation interface
 *   domain based iotlb invalidation
 */
static void
qinv_iotlb_dsi(intel_iommu_state_t *iommu, uint_t domain_id)
{
	qinv_iotlb_common(iommu, domain_id, 0, 0, 0, TLB_INV_G_DOMAIN);
	qinv_wait_sync(iommu);
}

/*
 * queued invalidation interface
 *    global iotlb invalidation
 */
static void
qinv_iotlb_gbl(intel_iommu_state_t *iommu)
{
	qinv_iotlb_common(iommu, 0, 0, 0, 0, TLB_INV_G_GLOBAL);
	qinv_wait_sync(iommu);
}

/*
 * the plant wait operation for queued invalidation interface
 */
static void
qinv_plant_wait(intel_iommu_state_t *iommu, iommu_dvma_cookie_t *dcookies,
		uint_t count, uint_t array_size)
{
	iotlb_pend_node_t *node = NULL;
	iotlb_pend_head_t *head;

	head = &(iommu->iu_pend_head);
	mutex_enter(&(head->ich_mem_lock));
	node = list_head(&(head->ich_mem_list));
	if (node) {
		list_remove(&(head->ich_mem_list), node);
	}
	mutex_exit(&(head->ich_mem_lock));

	/* no cache, alloc one */
	if (node == NULL) {
		node = kmem_zalloc(sizeof (iotlb_pend_node_t), KM_SLEEP);
	}
	node->icn_dcookies = dcookies;
	node->icn_count = count;
	node->icn_array_size = array_size;

	/* plant an invalidation wait descriptor, not wait its completion */
	qinv_wait_async_unfence(iommu, node);
}

/*
 * the reap wait operation for queued invalidation interface
 */
static void
qinv_reap_wait(intel_iommu_state_t *iommu)
{
	int index, cnt = 0;
	iotlb_pend_node_t *node;
	iotlb_pend_head_t *head;

	head = &(iommu->iu_pend_head);

	index = qinv_wait_async_finish(iommu, &cnt);

	while (cnt--) {
		node = iommu->iu_inv_queue->iotlb_pend_node[index];
		if (node == NULL)
			continue;
		dmar_release_dvma_cookie(node->icn_dcookies,
		    node->icn_count, node->icn_array_size);

		mutex_enter(&(head->ich_mem_lock));
		list_insert_head(&(head->ich_mem_list), node);
		mutex_exit(&(head->ich_mem_lock));
		iommu->iu_inv_queue->iotlb_pend_node[index] = NULL;
		index++;
		if (index == iommu->iu_inv_queue->iq_sync.size)
			index = 0;
	}
}

/* init interrupt remapping table */
static int
intr_remap_init_unit(intel_iommu_state_t *iommu)
{
	intr_remap_tbl_state_t *intr_remap_tbl;
	size_t size;

	ddi_dma_attr_t intrr_dma_attr = {
		DMA_ATTR_V0,
		0U,
		0xffffffffU,
		0xffffffffU,
		MMU_PAGESIZE,	/* page aligned */
		0x1,
		0x1,
		0xffffffffU,
		0xffffffffU,
		1,
		4,
		0
	};

	ddi_device_acc_attr_t intrr_acc_attr = {
		DDI_DEVICE_ATTR_V0,
		DDI_NEVERSWAP_ACC,
		DDI_STRICTORDER_ACC
	};

	if (intrr_apic_mode == LOCAL_X2APIC) {
		if (!IOMMU_ECAP_GET_EIM(iommu->iu_excapability)) {
			return (DDI_FAILURE);
		}
	}

	if (intrr_irta_s > INTRR_MAX_IRTA_SIZE) {
		intrr_irta_s = INTRR_MAX_IRTA_SIZE;
	}

	intr_remap_tbl = (intr_remap_tbl_state_t *)
	    kmem_zalloc(sizeof (intr_remap_tbl_state_t), KM_SLEEP);

	if (ddi_dma_alloc_handle(iommu->iu_drhd->di_dip,
	    &intrr_dma_attr,
	    DDI_DMA_SLEEP,
	    NULL,
	    &(intr_remap_tbl->dma_hdl)) != DDI_SUCCESS) {
		goto intrr_tbl_handle_failed;
	}

	intr_remap_tbl->size = 1 << (intrr_irta_s + 1);
	size = intr_remap_tbl->size * INTRR_RTE_SIZE;
	if (ddi_dma_mem_alloc(intr_remap_tbl->dma_hdl,
	    size,
	    &intrr_acc_attr,
	    DDI_DMA_CONSISTENT | IOMEM_DATA_UNCACHED,
	    DDI_DMA_SLEEP,
	    NULL,
	    &(intr_remap_tbl->vaddr),
	    &size,
	    &(intr_remap_tbl->acc_hdl)) != DDI_SUCCESS) {
		goto intrr_tbl_mem_failed;

	}

	ASSERT(!((uintptr_t)intr_remap_tbl->vaddr & MMU_PAGEOFFSET));
	bzero(intr_remap_tbl->vaddr, size);
	intr_remap_tbl->paddr = pfn_to_pa(
	    hat_getpfnum(kas.a_hat, intr_remap_tbl->vaddr));

	mutex_init(&(intr_remap_tbl->lock), NULL, MUTEX_DRIVER, NULL);
	bitset_init(&intr_remap_tbl->map);
	bitset_resize(&intr_remap_tbl->map, intr_remap_tbl->size);
	intr_remap_tbl->free = 0;

	iommu->iu_intr_remap_tbl = intr_remap_tbl;

	return (DDI_SUCCESS);

intrr_tbl_mem_failed:
	ddi_dma_free_handle(&(intr_remap_tbl->dma_hdl));

intrr_tbl_handle_failed:
	kmem_free(intr_remap_tbl, sizeof (intr_remap_tbl_state_t));

	return (ENOMEM);
}

/* destroy interrupt remapping table */
static void
intr_remap_fini_unit(intel_iommu_state_t *iommu)
{
	intr_remap_tbl_state_t *intr_remap_tbl;

	intr_remap_tbl = iommu->iu_intr_remap_tbl;
	bitset_fini(&intr_remap_tbl->map);
	ddi_dma_mem_free(&(intr_remap_tbl->acc_hdl));
	ddi_dma_free_handle(&(intr_remap_tbl->dma_hdl));
	kmem_free(intr_remap_tbl, sizeof (intr_remap_tbl_state_t));
}

/* enable interrupt remapping hardware unit */
static void
intr_remap_enable_unit(intel_iommu_state_t *iommu)
{
	uint32_t status;
	uint64_t irta_reg;
	intr_remap_tbl_state_t *intr_remap_tbl;

	intr_remap_tbl = iommu->iu_intr_remap_tbl;

	irta_reg = intr_remap_tbl->paddr | intrr_irta_s;

	if (intrr_apic_mode == LOCAL_X2APIC)
		irta_reg |= (0x1 << 11);

	/* set interrupt remap table pointer */
	mutex_enter(&(iommu->iu_reg_lock));
	iommu_put_reg64(iommu, IOMMU_REG_IRTAR,	irta_reg);
	iommu_put_reg32(iommu, IOMMU_REG_GLOBAL_CMD,
	    iommu->iu_global_cmd_reg | IOMMU_GCMD_SIRTP);
	iommu_wait_completion(iommu, IOMMU_REG_GLOBAL_STS,
	    iommu_get_reg32, (status & IOMMU_GSTS_IRTPS), status);
	mutex_exit(&(iommu->iu_reg_lock));

	/* global flush intr entry cache */
	qinv_iec_global(iommu);

	/* enable interrupt remapping */
	mutex_enter(&(iommu->iu_reg_lock));
	iommu_put_reg32(iommu, IOMMU_REG_GLOBAL_CMD,
	    iommu->iu_global_cmd_reg | IOMMU_GCMD_IRE);
	iommu_wait_completion(iommu, IOMMU_REG_GLOBAL_STS,
	    iommu_get_reg32, (status & IOMMU_GSTS_IRES),
	    status);
	iommu->iu_global_cmd_reg |= IOMMU_GCMD_IRE;

	/* set compatible mode */
	iommu_put_reg32(iommu, IOMMU_REG_GLOBAL_CMD,
	    iommu->iu_global_cmd_reg | IOMMU_GCMD_CFI);
	iommu_wait_completion(iommu, IOMMU_REG_GLOBAL_STS,
	    iommu_get_reg32, (status & IOMMU_GSTS_CFIS),
	    status);
	iommu->iu_global_cmd_reg |= IOMMU_GCMD_CFI;
	mutex_exit(&(iommu->iu_reg_lock));

	iommu->iu_enabled |= INTRR_ENABLE;
}

/*
 * helper function to find the free interrupt remapping
 * table entry
 */
static uint_t
bitset_find_free(bitset_t *b, uint_t post)
{
	uint_t	i;
	uint_t	cap = bitset_capacity(b);

	if (post == cap)
		post = 0;

	ASSERT(post < cap);

	for (i = post; i < cap; i++) {
		if (!bitset_in_set(b, i))
			return (i);
	}

	for (i = 0; i < post; i++) {
		if (!bitset_in_set(b, i))
			return (i);
	}

	return (INTRR_IIDX_FULL);	/* no free index */
}

/*
 * helper function to find 'count' contigous free
 * interrupt remapping table entries
 */
static uint_t
bitset_find_multi_free(bitset_t *b, uint_t post, uint_t count)
{
	uint_t  i, j;
	uint_t	cap = bitset_capacity(b);

	if (post == INTRR_IIDX_FULL) {
		return (INTRR_IIDX_FULL);
	}

	if (count > cap)
		return (INTRR_IIDX_FULL);

	ASSERT(post < cap);

	for (i = post; (i + count) <= cap; i++) {
		for (j = 0; j < count; j++) {
			if (bitset_in_set(b, (i + j))) {
				i = i + j;
				break;
			}
			if (j == count - 1)
				return (i);
		}
	}

	for (i = 0; (i < post) && ((i + count) <= cap); i++) {
		for (j = 0; j < count; j++) {
			if (bitset_in_set(b, (i + j))) {
				i = i + j;
				break;
			}
			if (j == count - 1)
				return (i);
		}
	}

	return (INTRR_IIDX_FULL);  		/* no free index */
}

/* alloc one interrupt remapping table entry */
static int
intrr_tbl_alloc_entry(intr_remap_tbl_state_t *intr_remap_tbl)
{
	uint32_t iidx;

retry_alloc_iidx:
	mutex_enter(&intr_remap_tbl->lock);
	iidx = intr_remap_tbl->free;
	if (iidx == INTRR_IIDX_FULL) {
		/* no free intr entry, use compatible format intr */
		mutex_exit(&intr_remap_tbl->lock);
		if (intrr_apic_mode == LOCAL_X2APIC) {
			/*
			 * x2apic mode not allowed compatible
			 * interrupt
			 */
			delay(IOMMU_ALLOC_RESOURCE_DELAY);
			goto retry_alloc_iidx;
		}
	} else {
		bitset_add(&intr_remap_tbl->map, iidx);
		intr_remap_tbl->free = bitset_find_free(&intr_remap_tbl->map,
		    iidx + 1);
		mutex_exit(&intr_remap_tbl->lock);
	}

	return (iidx);
}

/* alloc 'cnt' contigous interrupt remapping table entries */
static int
intrr_tbl_alloc_multi_entries(intr_remap_tbl_state_t *intr_remap_tbl,
    uint_t cnt)
{
	uint_t iidx, pos, i;

retry_alloc_iidxs:
	mutex_enter(&intr_remap_tbl->lock);
	pos = intr_remap_tbl->free;
	iidx = bitset_find_multi_free(&intr_remap_tbl->map, pos, cnt);
	if (iidx != INTRR_IIDX_FULL) {
		if (iidx <= pos && pos < (iidx + cnt)) {
			intr_remap_tbl->free = bitset_find_free(
			    &intr_remap_tbl->map, iidx + cnt);
		}
		for (i = 0; i < cnt; i++) {
			bitset_add(&intr_remap_tbl->map, iidx + i);
		}
		mutex_exit(&intr_remap_tbl->lock);
	} else {
		mutex_exit(&intr_remap_tbl->lock);
		if (intrr_apic_mode == LOCAL_X2APIC) {
			/* x2apic mode not allowed comapitible interrupt */
			delay(IOMMU_ALLOC_RESOURCE_DELAY);
			goto retry_alloc_iidxs;
		}
	}

	return (iidx);
}

/* get ioapic source id and iommu structure for ioapics */
static void
get_ioapic_iommu_info(void)
{
	ioapic_drhd_info_t *ioapic_dinfo;
	uint_t i;

	for_each_in_list(&ioapic_drhd_infos, ioapic_dinfo) {
		for (i = 0; i < MAX_IO_APIC; i++) {
			if (ioapic_dinfo->ioapic_id == apic_io_id[i]) {
				ioapic_iommu_infos[i] = kmem_zalloc(
				    sizeof (ioapic_iommu_info_t), KM_SLEEP);
				ioapic_iommu_infos[i]->sid = ioapic_dinfo->sid;
				ioapic_iommu_infos[i]->iommu =
				    (intel_iommu_state_t *)
				    ioapic_dinfo->drhd->di_iommu;
				break;
			}
		}
	}
}

/* initialize interrupt remapping */
static int
intr_remap_init(int apic_mode)
{
	intel_iommu_state_t *iommu;
	int intrr_all_disable = 1;

	intrr_apic_mode = apic_mode;

	if ((intrr_apic_mode != LOCAL_X2APIC) && intrr_only_for_x2apic) {
		/*
		 * interrupt remapping is not a must in apic mode
		 */
		return (DDI_FAILURE);
	}

	for_each_in_list(&iommu_states, iommu) {
		if ((iommu->iu_enabled & QINV_ENABLE) &&
		    IOMMU_ECAP_GET_IR(iommu->iu_excapability)) {
			if (intr_remap_init_unit(iommu) == DDI_SUCCESS) {
				intrr_all_disable = 0;
			}
		}
	}

	if (intrr_all_disable) {
		/*
		 * if all drhd unit disabled intr remapping,
		 * return FAILURE
		 */
		return (DDI_FAILURE);
	} else {
		return (DDI_SUCCESS);
	}
}

/* enable interrupt remapping */
static void
intr_remap_enable(void)
{
	intel_iommu_state_t *iommu;

	for_each_in_list(&iommu_states, iommu) {
		if (iommu->iu_intr_remap_tbl)
			intr_remap_enable_unit(iommu);
	}

	/* get iommu structure and interrupt source id for ioapic */
	get_ioapic_iommu_info();
}

/* alloc remapping entry for the interrupt */
static void
intr_remap_alloc_entry(apic_irq_t *irq_ptr)
{
	intel_iommu_state_t	*iommu;
	intr_remap_tbl_state_t *intr_remap_tbl;
	uint32_t		iidx, cnt, i;
	uint_t			vector, irqno;
	uint32_t		sid_svt_sq;

	if (AIRQ_PRIVATE(irq_ptr) == INTRR_DISABLE ||
	    AIRQ_PRIVATE(irq_ptr) != NULL) {
		return;
	}

	AIRQ_PRIVATE(irq_ptr) =
	    kmem_zalloc(sizeof (intr_remap_private_t), KM_SLEEP);

	intr_remap_get_iommu(irq_ptr);

	iommu = INTRR_PRIVATE(irq_ptr)->ir_iommu;
	if (iommu == NULL) {
		goto intr_remap_disable;
	}

	intr_remap_tbl = iommu->iu_intr_remap_tbl;

	if (irq_ptr->airq_mps_intr_index == MSI_INDEX) {
		cnt = irq_ptr->airq_intin_no;
	} else {
		cnt = 1;
	}

	if (cnt == 1) {
		iidx = intrr_tbl_alloc_entry(intr_remap_tbl);
	} else {
		iidx = intrr_tbl_alloc_multi_entries(intr_remap_tbl, cnt);
	}

	if (iidx == INTRR_IIDX_FULL) {
		goto intr_remap_disable;
	}

	INTRR_PRIVATE(irq_ptr)->ir_iidx = iidx;

	intr_remap_get_sid(irq_ptr);

	if (cnt == 1) {
		if (IOMMU_CAP_GET_CM(iommu->iu_capability)) {
			qinv_iec_single(iommu, iidx);
		} else {
			iommu->iu_dmar_ops->do_flwb(iommu);
		}
		return;
	}

	sid_svt_sq = INTRR_PRIVATE(irq_ptr)->ir_sid_svt_sq;

	vector = irq_ptr->airq_vector;

	for (i = 1; i < cnt; i++) {
		irqno = apic_vector_to_irq[vector + i];
		irq_ptr = apic_irq_table[irqno];

		ASSERT(irq_ptr);

		AIRQ_PRIVATE(irq_ptr) =
		    kmem_zalloc(sizeof (intr_remap_private_t), KM_SLEEP);

		INTRR_PRIVATE(irq_ptr)->ir_iommu = iommu;
		INTRR_PRIVATE(irq_ptr)->ir_sid_svt_sq = sid_svt_sq;
		INTRR_PRIVATE(irq_ptr)->ir_iidx = iidx + i;
	}

	if (IOMMU_CAP_GET_CM(iommu->iu_capability)) {
		qinv_iec(iommu, iidx, cnt);
	} else {
		iommu->iu_dmar_ops->do_flwb(iommu);
	}

	return;

intr_remap_disable:
	kmem_free(AIRQ_PRIVATE(irq_ptr), sizeof (intr_remap_private_t));
	AIRQ_PRIVATE(irq_ptr) = INTRR_DISABLE;
}

/* helper function to get iommu structure */
static void intr_remap_get_iommu(apic_irq_t *irq_ptr)
{
	intel_iommu_state_t	*iommu = NULL;

	ASSERT(INTRR_PRIVATE(irq_ptr)->ir_iommu == NULL);

	if (!APIC_IS_MSI_OR_MSIX_INDEX(irq_ptr->airq_mps_intr_index)) {
		/* for fixed interrupt */
		uint_t ioapic_index = irq_ptr->airq_ioapicindex;
		if (ioapic_iommu_infos[ioapic_index])
			iommu = ioapic_iommu_infos[ioapic_index]->iommu;
	} else {
		if (irq_ptr->airq_dip != NULL) {
			iommu = iommu_get_dmar(irq_ptr->airq_dip);
		}
	}

	if ((iommu != NULL) && (iommu->iu_enabled & INTRR_ENABLE)) {
		INTRR_PRIVATE(irq_ptr)->ir_iommu = iommu;
	}
}

/* helper function to get interrupt request source id */
static void
intr_remap_get_sid(apic_irq_t *irq_ptr)
{
	dev_info_t	*dip, *pdip;
	iommu_private_t	*private;
	uint16_t	sid;
	uchar_t		svt, sq;

	if (!intrr_enable_sid_verify) {
		return;
	}

	if (!APIC_IS_MSI_OR_MSIX_INDEX(irq_ptr->airq_mps_intr_index)) {
		/* for interrupt through I/O APIC */
		uint_t ioapic_index = irq_ptr->airq_ioapicindex;

		sid = ioapic_iommu_infos[ioapic_index]->sid;

		svt = SVT_ALL_VERIFY;
		sq = SQ_VERIFY_ALL;
	} else {
		/* MSI/MSI-X interrupt */
		dip = irq_ptr->airq_dip;
		ASSERT(dip);
		pdip = get_pci_top_bridge(dip);
		if (pdip == NULL) {
			/* pcie device */
			private = DEVI(dip)->devi_iommu_private;
			ASSERT(private);
			sid = (private->idp_bus << 8) | private->idp_devfn;
			svt = SVT_ALL_VERIFY;
			sq = SQ_VERIFY_ALL;
		} else {
			private = DEVI(pdip)->devi_iommu_private;
			ASSERT(private);

			if (private->idp_bbp_type == IOMMU_PPB_PCIE_PCI) {
				/* device behind pcie to pci bridge */
				sid = (private->idp_bus << 8) | \
				    private->idp_sec;
				svt = SVT_BUS_VERIFY;
				sq = SQ_VERIFY_ALL;
			} else {
				/* device behind pci to pci bridge */
				sid = (private->idp_bus << 8) | \
				    private->idp_devfn;
				svt = SVT_ALL_VERIFY;
				sq = SQ_VERIFY_ALL;
			}
		}
	}

	INTRR_PRIVATE(irq_ptr)->ir_sid_svt_sq = sid | (svt << 18) | (sq << 16);
}

/* remapping the interrupt */
static void
intr_remap_map_entry(apic_irq_t *irq_ptr, void *intr_data)
{
	intel_iommu_state_t	*iommu;
	intr_remap_tbl_state_t	*intr_remap_tbl;
	ioapic_rdt_t	*irdt = (ioapic_rdt_t *)intr_data;
	msi_regs_t	*mregs = (msi_regs_t *)intr_data;
	intr_rte_t	irte;
	uint_t		iidx, i, cnt;
	uint32_t	dst, sid_svt_sq;
	uchar_t		vector, dlm, tm, rh, dm;

	if (AIRQ_PRIVATE(irq_ptr) == INTRR_DISABLE) {
		return;
	}

	if (irq_ptr->airq_mps_intr_index == MSI_INDEX) {
		cnt = irq_ptr->airq_intin_no;
	} else {
		cnt = 1;
	}

	iidx = INTRR_PRIVATE(irq_ptr)->ir_iidx;
	iommu = INTRR_PRIVATE(irq_ptr)->ir_iommu;
	intr_remap_tbl = iommu->iu_intr_remap_tbl;
	sid_svt_sq = INTRR_PRIVATE(irq_ptr)->ir_sid_svt_sq;
	vector = irq_ptr->airq_vector;

	if (!APIC_IS_MSI_OR_MSIX_INDEX(irq_ptr->airq_mps_intr_index)) {
		dm = RDT_DM(irdt->ir_lo);
		rh = 0;
		tm = RDT_TM(irdt->ir_lo);
		dlm = RDT_DLM(irdt->ir_lo);
		dst = irdt->ir_hi;
	} else {
		dm = MSI_ADDR_DM_PHYSICAL;
		rh = MSI_ADDR_RH_FIXED;
		tm = MSI_DATA_TM_EDGE;
		dlm = 0;
		dst = mregs->mr_addr;
	}

	if (intrr_apic_mode == LOCAL_APIC)
		dst = (dst & 0xFF) << 8;

	if (cnt == 1) {
		irte.lo = IRTE_LOW(dst, vector, dlm, tm, rh, dm, 0, 1);
		irte.hi = IRTE_HIGH(sid_svt_sq);

		/* set interrupt remapping table entry */
		bcopy(&irte, intr_remap_tbl->vaddr +
		    iidx * INTRR_RTE_SIZE,
		    INTRR_RTE_SIZE);

		qinv_iec_single(iommu, iidx);

	} else {
		vector = irq_ptr->airq_vector;
		for (i = 0; i < cnt; i++) {
			irte.lo = IRTE_LOW(dst, vector, dlm, tm, rh, dm, 0, 1);
			irte.hi = IRTE_HIGH(sid_svt_sq);

			/* set interrupt remapping table entry */
			bcopy(&irte, intr_remap_tbl->vaddr +
			    iidx * INTRR_RTE_SIZE,
			    INTRR_RTE_SIZE);
			vector++;
			iidx++;
		}

		qinv_iec(iommu, iidx, cnt);
	}
}

/* free the remapping entry */
static void
intr_remap_free_entry(apic_irq_t *irq_ptr)
{
	intel_iommu_state_t *iommu;
	intr_remap_tbl_state_t *intr_remap_tbl;
	uint32_t iidx;

	if (AIRQ_PRIVATE(irq_ptr) == INTRR_DISABLE) {
		AIRQ_PRIVATE(irq_ptr) = NULL;
		return;
	}

	iommu = INTRR_PRIVATE(irq_ptr)->ir_iommu;
	intr_remap_tbl = iommu->iu_intr_remap_tbl;
	iidx = INTRR_PRIVATE(irq_ptr)->ir_iidx;

	bzero(intr_remap_tbl->vaddr + iidx * INTRR_RTE_SIZE,
	    INTRR_RTE_SIZE);

	qinv_iec_single(iommu, iidx);

	mutex_enter(&intr_remap_tbl->lock);
	bitset_del(&intr_remap_tbl->map, iidx);
	if (intr_remap_tbl->free == INTRR_IIDX_FULL) {
		intr_remap_tbl->free = iidx;
	}
	mutex_exit(&intr_remap_tbl->lock);

	kmem_free(AIRQ_PRIVATE(irq_ptr), sizeof (intr_remap_private_t));
	AIRQ_PRIVATE(irq_ptr) = NULL;
}

/* record the ioapic rdt entry */
static void
intr_remap_record_rdt(apic_irq_t *irq_ptr, ioapic_rdt_t *irdt)
{
	uint32_t rdt_entry, tm, pol, iidx, vector;

	rdt_entry = irdt->ir_lo;

	if (INTRR_PRIVATE(irq_ptr) != NULL) {
		iidx = INTRR_PRIVATE(irq_ptr)->ir_iidx;
		tm = RDT_TM(rdt_entry);
		pol = RDT_POL(rdt_entry);
		vector = irq_ptr->airq_vector;
		irdt->ir_lo = (tm << INTRR_IOAPIC_TM_SHIFT) |
		    (pol << INTRR_IOAPIC_POL_SHIFT) |
		    ((iidx >> 15) << INTRR_IOAPIC_IIDX15_SHIFT) |
		    vector;
		irdt->ir_hi = (iidx << INTRR_IOAPIC_IIDX_SHIFT) |
		    (1 << INTRR_IOAPIC_FORMAT_SHIFT);
	} else {
		irdt->ir_hi <<= APIC_ID_BIT_OFFSET;
	}
}

/* record the msi interrupt structure */
/*ARGSUSED*/
static void
intr_remap_record_msi(apic_irq_t *irq_ptr, msi_regs_t *mregs)
{
	uint_t	iidx;

	if (INTRR_PRIVATE(irq_ptr) != NULL) {
		iidx = INTRR_PRIVATE(irq_ptr)->ir_iidx;

		mregs->mr_data = 0;
		mregs->mr_addr = MSI_ADDR_HDR |
		    ((iidx & 0x7fff) << INTRR_MSI_IIDX_SHIFT) |
		    (1 << INTRR_MSI_FORMAT_SHIFT) | (1 << INTRR_MSI_SHV_SHIFT) |
		    ((iidx >> 15) << INTRR_MSI_IIDX15_SHIFT);
	} else {
		mregs->mr_addr = MSI_ADDR_HDR |
		    (MSI_ADDR_RH_FIXED << MSI_ADDR_RH_SHIFT) |
		    (MSI_ADDR_DM_PHYSICAL << MSI_ADDR_DM_SHIFT) |
		    (mregs->mr_addr << MSI_ADDR_DEST_SHIFT);
		mregs->mr_data = (MSI_DATA_TM_EDGE << MSI_DATA_TM_SHIFT) |
		    mregs->mr_data;
	}
}
