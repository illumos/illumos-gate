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
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */


#include <sys/apic.h>
#include <vm/hat_i86.h>
#include <sys/sysmacros.h>
#include <sys/smp_impldefs.h>
#include <sys/immu.h>


typedef struct intrmap_private {
	immu_t		*ir_immu;
	immu_inv_wait_t	ir_inv_wait;
	uint16_t	ir_idx;
	uint32_t	ir_sid_svt_sq;
} intrmap_private_t;

#define	INTRMAP_PRIVATE(intrmap) ((intrmap_private_t *)intrmap)

/* interrupt remapping table entry */
typedef struct intrmap_rte {
	uint64_t	lo;
	uint64_t	hi;
} intrmap_rte_t;

#define	IRTE_HIGH(sid_svt_sq) (sid_svt_sq)
#define	IRTE_LOW(dst, vector, dlm, tm, rh, dm, fpd, p)	\
	    (((uint64_t)(dst) << 32) |  \
	    ((uint64_t)(vector) << 16) | \
	    ((uint64_t)(dlm) << 5) | \
	    ((uint64_t)(tm) << 4) | \
	    ((uint64_t)(rh) << 3) | \
	    ((uint64_t)(dm) << 2) | \
	    ((uint64_t)(fpd) << 1) | \
	    (p))

typedef enum {
	SVT_NO_VERIFY = 0,	/* no verification */
	SVT_ALL_VERIFY,		/* using sid and sq to verify */
	SVT_BUS_VERIFY,		/* verify #startbus and #endbus */
	SVT_RSVD
} intrmap_svt_t;

typedef enum {
	SQ_VERIFY_ALL = 0,	/* verify all 16 bits */
	SQ_VERIFY_IGR_1,	/* ignore bit 3 */
	SQ_VERIFY_IGR_2,	/* ignore bit 2-3 */
	SQ_VERIFY_IGR_3		/* ignore bit 1-3 */
} intrmap_sq_t;

/*
 * S field of the Interrupt Remapping Table Address Register
 * the size of the interrupt remapping table is 1 << (immu_intrmap_irta_s + 1)
 */
static uint_t intrmap_irta_s = INTRMAP_MAX_IRTA_SIZE;

/*
 * If true, arrange to suppress broadcast EOI by setting edge-triggered mode
 * even for level-triggered interrupts in the interrupt-remapping engine.
 * If false, broadcast EOI can still be suppressed if the CPU supports the
 * APIC_SVR_SUPPRESS_BROADCAST_EOI bit.  In both cases, the IOAPIC is still
 * programmed with the correct trigger mode, and pcplusmp must send an EOI
 * to the IOAPIC by writing to the IOAPIC's EOI register to make up for the
 * missing broadcast EOI.
 */
static int intrmap_suppress_brdcst_eoi = 0;

/*
 * whether verify the source id of interrupt request
 */
static int intrmap_enable_sid_verify = 0;

/* fault types for DVMA remapping */
static char *immu_dvma_faults[] = {
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
	"Incorrect fault event reason number",
};
#define	DVMA_MAX_FAULTS (sizeof (immu_dvma_faults)/(sizeof (char *))) - 1

/* fault types for interrupt remapping */
static char *immu_intrmap_faults[] = {
	"reserved field set in IRTE",
	"interrupt_index exceed the intr-remap table size",
	"present field in IRTE is clear",
	"hardware access intr-remap table address resulted in error",
	"reserved field set in IRTE, include various conditional",
	"hardware blocked an interrupt request in Compatibility format",
	"remappable interrupt request blocked due to verification failure"
};
#define	INTRMAP_MAX_FAULTS \
	(sizeof (immu_intrmap_faults) / (sizeof (char *))) - 1

/* Function prototypes */
static int immu_intrmap_init(int apic_mode);
static void immu_intrmap_switchon(int suppress_brdcst_eoi);
static void immu_intrmap_alloc(void **intrmap_private_tbl, dev_info_t *dip,
    uint16_t type, int count, uchar_t ioapic_index);
static void immu_intrmap_map(void *intrmap_private, void *intrmap_data,
    uint16_t type, int count);
static void immu_intrmap_free(void **intrmap_privatep);
static void immu_intrmap_rdt(void *intrmap_private, ioapic_rdt_t *irdt);
static void immu_intrmap_msi(void *intrmap_private, msi_regs_t *mregs);

static struct apic_intrmap_ops intrmap_ops = {
	immu_intrmap_init,
	immu_intrmap_switchon,
	immu_intrmap_alloc,
	immu_intrmap_map,
	immu_intrmap_free,
	immu_intrmap_rdt,
	immu_intrmap_msi,
};

/* apic mode, APIC/X2APIC */
static int intrmap_apic_mode = LOCAL_APIC;


/*
 * helper functions
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

	return (INTRMAP_IDX_FULL);	/* no free index */
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

	if (post == INTRMAP_IDX_FULL) {
		return (INTRMAP_IDX_FULL);
	}

	if (count > cap)
		return (INTRMAP_IDX_FULL);

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

	return (INTRMAP_IDX_FULL);		/* no free index */
}

/* alloc one interrupt remapping table entry */
static int
alloc_tbl_entry(intrmap_t *intrmap)
{
	uint32_t idx;

	for (;;) {
		mutex_enter(&intrmap->intrmap_lock);
		idx = intrmap->intrmap_free;
		if (idx != INTRMAP_IDX_FULL) {
			bitset_add(&intrmap->intrmap_map, idx);
			intrmap->intrmap_free =
			    bitset_find_free(&intrmap->intrmap_map, idx + 1);
			mutex_exit(&intrmap->intrmap_lock);
			break;
		}

		/* no free intr entry, use compatible format intr */
		mutex_exit(&intrmap->intrmap_lock);

		if (intrmap_apic_mode != LOCAL_X2APIC) {
			break;
		}

		/*
		 * x2apic mode not allowed compatible
		 * interrupt
		 */
		delay(IMMU_ALLOC_RESOURCE_DELAY);
	}

	return (idx);
}

/* alloc 'cnt' contigous interrupt remapping table entries */
static int
alloc_tbl_multi_entries(intrmap_t *intrmap, uint_t cnt)
{
	uint_t idx, pos, i;

	for (; ; ) {
		mutex_enter(&intrmap->intrmap_lock);
		pos = intrmap->intrmap_free;
		idx = bitset_find_multi_free(&intrmap->intrmap_map, pos, cnt);

		if (idx != INTRMAP_IDX_FULL) {
			if (idx <= pos && pos < (idx + cnt)) {
				intrmap->intrmap_free = bitset_find_free(
				    &intrmap->intrmap_map, idx + cnt);
			}
			for (i = 0; i < cnt; i++) {
				bitset_add(&intrmap->intrmap_map, idx + i);
			}
			mutex_exit(&intrmap->intrmap_lock);
			break;
		}

		mutex_exit(&intrmap->intrmap_lock);

		if (intrmap_apic_mode != LOCAL_X2APIC) {
			break;
		}

		/* x2apic mode not allowed comapitible interrupt */
		delay(IMMU_ALLOC_RESOURCE_DELAY);
	}

	return (idx);
}

/* init interrupt remapping table */
static int
init_unit(immu_t *immu)
{
	intrmap_t *intrmap;
	size_t size;

	ddi_dma_attr_t intrmap_dma_attr = {
		DMA_ATTR_V0,
		0U,
		0xffffffffffffffffULL,
		0xffffffffU,
		MMU_PAGESIZE,	/* page aligned */
		0x1,
		0x1,
		0xffffffffU,
		0xffffffffffffffffULL,
		1,
		4,
		0
	};

	ddi_device_acc_attr_t intrmap_acc_attr = {
		DDI_DEVICE_ATTR_V0,
		DDI_NEVERSWAP_ACC,
		DDI_STRICTORDER_ACC
	};

	/*
	 * Using interrupt remapping implies using the queue
	 * invalidation interface. According to Intel,
	 * hardware that supports interrupt remapping should
	 * also support QI.
	 */
	ASSERT(IMMU_ECAP_GET_QI(immu->immu_regs_excap));

	if (intrmap_apic_mode == LOCAL_X2APIC) {
		if (!IMMU_ECAP_GET_EIM(immu->immu_regs_excap)) {
			return (DDI_FAILURE);
		}
	}

	if (intrmap_irta_s > INTRMAP_MAX_IRTA_SIZE) {
		intrmap_irta_s = INTRMAP_MAX_IRTA_SIZE;
	}

	intrmap =  kmem_zalloc(sizeof (intrmap_t), KM_SLEEP);

	if (ddi_dma_alloc_handle(immu->immu_dip,
	    &intrmap_dma_attr,
	    DDI_DMA_SLEEP,
	    NULL,
	    &(intrmap->intrmap_dma_hdl)) != DDI_SUCCESS) {
		kmem_free(intrmap, sizeof (intrmap_t));
		return (DDI_FAILURE);
	}

	intrmap->intrmap_size = 1 << (intrmap_irta_s + 1);
	size = intrmap->intrmap_size * INTRMAP_RTE_SIZE;
	if (ddi_dma_mem_alloc(intrmap->intrmap_dma_hdl,
	    size,
	    &intrmap_acc_attr,
	    DDI_DMA_CONSISTENT | IOMEM_DATA_UNCACHED,
	    DDI_DMA_SLEEP,
	    NULL,
	    &(intrmap->intrmap_vaddr),
	    &size,
	    &(intrmap->intrmap_acc_hdl)) != DDI_SUCCESS) {
		ddi_dma_free_handle(&(intrmap->intrmap_dma_hdl));
		kmem_free(intrmap, sizeof (intrmap_t));
		return (DDI_FAILURE);
	}

	ASSERT(!((uintptr_t)intrmap->intrmap_vaddr & MMU_PAGEOFFSET));
	bzero(intrmap->intrmap_vaddr, size);
	intrmap->intrmap_paddr = pfn_to_pa(
	    hat_getpfnum(kas.a_hat, intrmap->intrmap_vaddr));

	mutex_init(&(intrmap->intrmap_lock), NULL, MUTEX_DRIVER, NULL);
	bitset_init(&intrmap->intrmap_map);
	bitset_resize(&intrmap->intrmap_map, intrmap->intrmap_size);
	intrmap->intrmap_free = 0;

	immu->immu_intrmap = intrmap;

	return (DDI_SUCCESS);
}

static immu_t *
get_immu(dev_info_t *dip, uint16_t type, uchar_t ioapic_index)
{
	immu_t	*immu = NULL;

	if (!DDI_INTR_IS_MSI_OR_MSIX(type)) {
		immu = immu_dmar_ioapic_immu(ioapic_index);
	} else {
		if (dip != NULL)
			immu = immu_dmar_get_immu(dip);
	}

	return (immu);
}

static int
get_top_pcibridge(dev_info_t *dip, void *arg)
{
	dev_info_t **topdipp = arg;
	immu_devi_t *immu_devi;

	mutex_enter(&(DEVI(dip)->devi_lock));
	immu_devi = DEVI(dip)->devi_iommu;
	mutex_exit(&(DEVI(dip)->devi_lock));

	if (immu_devi == NULL || immu_devi->imd_pcib_type == IMMU_PCIB_BAD ||
	    immu_devi->imd_pcib_type == IMMU_PCIB_ENDPOINT) {
		return (DDI_WALK_CONTINUE);
	}

	*topdipp = dip;

	return (DDI_WALK_CONTINUE);
}

static dev_info_t *
intrmap_top_pcibridge(dev_info_t *rdip)
{
	dev_info_t *top_pcibridge = NULL;

	if (immu_walk_ancestor(rdip, NULL, get_top_pcibridge,
	    &top_pcibridge, NULL, 0) != DDI_SUCCESS) {
		return (NULL);
	}

	return (top_pcibridge);
}

/* function to get interrupt request source id */
static uint32_t
get_sid(dev_info_t *dip, uint16_t type, uchar_t ioapic_index)
{
	dev_info_t	*pdip;
	immu_devi_t	*immu_devi;
	uint16_t	sid;
	uchar_t		svt, sq;

	if (!intrmap_enable_sid_verify) {
		return (0);
	}

	if (!DDI_INTR_IS_MSI_OR_MSIX(type)) {
		/* for interrupt through I/O APIC */
		sid = immu_dmar_ioapic_sid(ioapic_index);
		svt = SVT_ALL_VERIFY;
		sq = SQ_VERIFY_ALL;
	} else {
		/* MSI/MSI-X interrupt */
		ASSERT(dip);
		pdip = intrmap_top_pcibridge(dip);
		ASSERT(pdip);
		immu_devi = DEVI(pdip)->devi_iommu;
		ASSERT(immu_devi);
		if (immu_devi->imd_pcib_type == IMMU_PCIB_PCIE_PCI) {
			/* device behind pcie to pci bridge */
			sid = (immu_devi->imd_bus << 8) | immu_devi->imd_sec;
			svt = SVT_BUS_VERIFY;
			sq = SQ_VERIFY_ALL;
		} else {
			/* pcie device or device behind pci to pci bridge */
			sid = (immu_devi->imd_bus << 8) |
			    immu_devi->imd_devfunc;
			svt = SVT_ALL_VERIFY;
			sq = SQ_VERIFY_ALL;
		}
	}

	return (sid | (svt << 18) | (sq << 16));
}

static void
intrmap_enable(immu_t *immu)
{
	intrmap_t *intrmap;
	uint64_t irta_reg;

	intrmap = immu->immu_intrmap;

	irta_reg = intrmap->intrmap_paddr | intrmap_irta_s;
	if (intrmap_apic_mode == LOCAL_X2APIC) {
		irta_reg |= (0x1 << 11);
	}

	immu_regs_intrmap_enable(immu, irta_reg);
}

/* ####################################################################### */

/*
 * immu_intr_handler()
 *	the fault event handler for a single immu unit
 */
uint_t
immu_intr_handler(caddr_t arg, caddr_t arg1 __unused)
{
	immu_t *immu = (immu_t *)arg;
	uint32_t status;
	int index, fault_reg_offset;
	int max_fault_index;
	boolean_t found_fault;
	dev_info_t *idip;

	mutex_enter(&(immu->immu_intr_lock));
	mutex_enter(&(immu->immu_regs_lock));

	/* read the fault status */
	status = immu_regs_get32(immu, IMMU_REG_FAULT_STS);

	idip = immu->immu_dip;
	ASSERT(idip);

	/* check if we have a pending fault for this immu unit */
	if ((status & IMMU_FAULT_STS_PPF) == 0) {
		mutex_exit(&(immu->immu_regs_lock));
		mutex_exit(&(immu->immu_intr_lock));
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * handle all primary pending faults
	 */
	index = IMMU_FAULT_GET_INDEX(status);
	max_fault_index =  IMMU_CAP_GET_NFR(immu->immu_regs_cap) - 1;
	fault_reg_offset = IMMU_CAP_GET_FRO(immu->immu_regs_cap);

	found_fault = B_FALSE;
	_NOTE(CONSTCOND)
	while (1) {
		uint64_t val;
		uint8_t fault_reason;
		uint8_t fault_type;
		uint16_t sid;
		uint64_t pg_addr;
		uint64_t idx;

		/* read the higher 64bits */
		val = immu_regs_get64(immu, fault_reg_offset + index * 16 + 8);

		/* check if this fault register has pending fault */
		if (!IMMU_FRR_GET_F(val)) {
			break;
		}

		found_fault = B_TRUE;

		/* get the fault reason, fault type and sid */
		fault_reason = IMMU_FRR_GET_FR(val);
		fault_type = IMMU_FRR_GET_FT(val);
		sid = IMMU_FRR_GET_SID(val);

		/* read the first 64bits */
		val = immu_regs_get64(immu, fault_reg_offset + index * 16);
		pg_addr = val & IMMU_PAGEMASK;
		idx = val >> 48;

		/* clear the fault */
		immu_regs_put32(immu, fault_reg_offset + index * 16 + 12,
		    (((uint32_t)1) << 31));

		/* report the fault info */
		if (fault_reason < 0x20) {
			/* immu-remapping fault */
			ddi_err(DER_WARN, idip,
			    "generated a fault event when translating DMA %s\n"
			    "\t on address 0x%" PRIx64 " for PCI(%d, %d, %d), "
			    "the reason is:\n\t %s",
			    fault_type ? "read" : "write", pg_addr,
			    (sid >> 8) & 0xff, (sid >> 3) & 0x1f, sid & 0x7,
			    immu_dvma_faults[MIN(fault_reason,
			    DVMA_MAX_FAULTS)]);
			immu_print_fault_info(sid, pg_addr);
		} else if (fault_reason < 0x27) {
			/* intr-remapping fault */
			ddi_err(DER_WARN, idip,
			    "generated a fault event when translating "
			    "interrupt request\n"
			    "\t on index 0x%" PRIx64 " for PCI(%d, %d, %d), "
			    "the reason is:\n\t %s",
			    idx,
			    (sid >> 8) & 0xff, (sid >> 3) & 0x1f, sid & 0x7,
			    immu_intrmap_faults[MIN((fault_reason - 0x20),
			    INTRMAP_MAX_FAULTS)]);
		} else {
			ddi_err(DER_WARN, idip, "Unknown fault reason: 0x%x",
			    fault_reason);
		}

		index++;
		if (index > max_fault_index)
			index = 0;
	}

	/* Clear the fault */
	if (!found_fault) {
		ddi_err(DER_MODE, idip,
		    "Fault register set but no fault present");
	}
	immu_regs_put32(immu, IMMU_REG_FAULT_STS, 1);
	mutex_exit(&(immu->immu_regs_lock));
	mutex_exit(&(immu->immu_intr_lock));
	return (DDI_INTR_CLAIMED);
}
/* ######################################################################### */

/*
 * Interrupt remap entry points
 */

/* initialize interrupt remapping */
static int
immu_intrmap_init(int apic_mode)
{
	immu_t *immu;
	int error = DDI_FAILURE;

	if (immu_intrmap_enable == B_FALSE) {
		return (DDI_SUCCESS);
	}

	intrmap_apic_mode = apic_mode;

	immu = list_head(&immu_list);
	for (; immu; immu = list_next(&immu_list, immu)) {
		if ((immu->immu_intrmap_running == B_TRUE) &&
		    IMMU_ECAP_GET_IR(immu->immu_regs_excap)) {
			if (init_unit(immu) == DDI_SUCCESS) {
				error = DDI_SUCCESS;
			}
		}
	}

	/*
	 * if all IOMMU units disable intr remapping,
	 * return FAILURE
	 */
	return (error);
}



/* enable interrupt remapping */
static void
immu_intrmap_switchon(int suppress_brdcst_eoi)
{
	immu_t *immu;


	intrmap_suppress_brdcst_eoi = suppress_brdcst_eoi;

	immu = list_head(&immu_list);
	for (; immu; immu = list_next(&immu_list, immu)) {
		if (immu->immu_intrmap_setup == B_TRUE) {
			intrmap_enable(immu);
		}
	}
}

/* alloc remapping entry for the interrupt */
static void
immu_intrmap_alloc(void **intrmap_private_tbl, dev_info_t *dip,
    uint16_t type, int count, uchar_t ioapic_index)
{
	immu_t	*immu;
	intrmap_t *intrmap;
	immu_inv_wait_t *iwp;
	uint32_t		idx, i;
	uint32_t		sid_svt_sq;
	intrmap_private_t	*intrmap_private;

	if (intrmap_private_tbl[0] == INTRMAP_DISABLE ||
	    intrmap_private_tbl[0] != NULL) {
		return;
	}

	intrmap_private_tbl[0] =
	    kmem_zalloc(sizeof (intrmap_private_t), KM_SLEEP);
	intrmap_private = INTRMAP_PRIVATE(intrmap_private_tbl[0]);

	immu = get_immu(dip, type, ioapic_index);
	if ((immu != NULL) && (immu->immu_intrmap_running == B_TRUE)) {
		intrmap_private->ir_immu = immu;
	} else {
		goto intrmap_disable;
	}

	intrmap = immu->immu_intrmap;

	if (count == 1) {
		idx = alloc_tbl_entry(intrmap);
	} else {
		idx = alloc_tbl_multi_entries(intrmap, count);
	}

	if (idx == INTRMAP_IDX_FULL) {
		goto intrmap_disable;
	}

	intrmap_private->ir_idx = idx;

	sid_svt_sq = intrmap_private->ir_sid_svt_sq =
	    get_sid(dip, type, ioapic_index);
	iwp = &intrmap_private->ir_inv_wait;
	immu_init_inv_wait(iwp, "intrmaplocal", B_TRUE);

	if (count == 1) {
		if (IMMU_CAP_GET_CM(immu->immu_regs_cap)) {
			immu_qinv_intr_one_cache(immu, idx, iwp);
		} else {
			immu_regs_wbf_flush(immu);
		}
		return;
	}

	for (i = 1; i < count; i++) {
		intrmap_private_tbl[i] =
		    kmem_zalloc(sizeof (intrmap_private_t), KM_SLEEP);

		INTRMAP_PRIVATE(intrmap_private_tbl[i])->ir_immu = immu;
		INTRMAP_PRIVATE(intrmap_private_tbl[i])->ir_sid_svt_sq =
		    sid_svt_sq;
		INTRMAP_PRIVATE(intrmap_private_tbl[i])->ir_idx = idx + i;
	}

	if (IMMU_CAP_GET_CM(immu->immu_regs_cap)) {
		immu_qinv_intr_caches(immu, idx, count, iwp);
	} else {
		immu_regs_wbf_flush(immu);
	}

	return;

intrmap_disable:
	kmem_free(intrmap_private_tbl[0], sizeof (intrmap_private_t));
	intrmap_private_tbl[0] = INTRMAP_DISABLE;
}


/* remapping the interrupt */
static void
immu_intrmap_map(void *intrmap_private, void *intrmap_data, uint16_t type,
    int count)
{
	immu_t	*immu;
	immu_inv_wait_t	*iwp;
	intrmap_t	*intrmap;
	ioapic_rdt_t	*irdt = (ioapic_rdt_t *)intrmap_data;
	msi_regs_t	*mregs = (msi_regs_t *)intrmap_data;
	intrmap_rte_t	irte;
	uint_t		idx, i;
	uint32_t	dst, sid_svt_sq;
	uchar_t		vector, dlm, tm, rh, dm;

	if (intrmap_private == INTRMAP_DISABLE)
		return;

	idx = INTRMAP_PRIVATE(intrmap_private)->ir_idx;
	immu = INTRMAP_PRIVATE(intrmap_private)->ir_immu;
	iwp = &INTRMAP_PRIVATE(intrmap_private)->ir_inv_wait;
	intrmap = immu->immu_intrmap;
	sid_svt_sq = INTRMAP_PRIVATE(intrmap_private)->ir_sid_svt_sq;

	if (!DDI_INTR_IS_MSI_OR_MSIX(type)) {
		dm = RDT_DM(irdt->ir_lo);
		rh = 0;
		tm = RDT_TM(irdt->ir_lo);
		dlm = RDT_DLM(irdt->ir_lo);
		dst = irdt->ir_hi;

		/*
		 * Mark the IRTE's TM as Edge to suppress broadcast EOI.
		 */
		if (intrmap_suppress_brdcst_eoi) {
			tm = TRIGGER_MODE_EDGE;
		}

		vector = RDT_VECTOR(irdt->ir_lo);
	} else {
		dm = MSI_ADDR_DM_PHYSICAL;
		rh = MSI_ADDR_RH_FIXED;
		tm = TRIGGER_MODE_EDGE;
		dlm = 0;
		dst = mregs->mr_addr;

		vector = mregs->mr_data & 0xff;
	}

	if (intrmap_apic_mode == LOCAL_APIC)
		dst = (dst & 0xFF) << 8;

	if (count == 1) {
		irte.lo = IRTE_LOW(dst, vector, dlm, tm, rh, dm, 0, 1);
		irte.hi = IRTE_HIGH(sid_svt_sq);

		/* set interrupt remapping table entry */
		bcopy(&irte, intrmap->intrmap_vaddr +
		    idx * INTRMAP_RTE_SIZE,
		    INTRMAP_RTE_SIZE);

		immu_qinv_intr_one_cache(immu, idx, iwp);

	} else {
		for (i = 0; i < count; i++) {
			irte.lo = IRTE_LOW(dst, vector, dlm, tm, rh, dm, 0, 1);
			irte.hi = IRTE_HIGH(sid_svt_sq);

			/* set interrupt remapping table entry */
			bcopy(&irte, intrmap->intrmap_vaddr +
			    idx * INTRMAP_RTE_SIZE,
			    INTRMAP_RTE_SIZE);
			vector++;
			idx++;
		}

		immu_qinv_intr_caches(immu, idx, count, iwp);
	}
}

/* free the remapping entry */
static void
immu_intrmap_free(void **intrmap_privatep)
{
	immu_t *immu;
	immu_inv_wait_t *iwp;
	intrmap_t *intrmap;
	uint32_t idx;

	if (*intrmap_privatep == INTRMAP_DISABLE || *intrmap_privatep == NULL) {
		*intrmap_privatep = NULL;
		return;
	}

	immu = INTRMAP_PRIVATE(*intrmap_privatep)->ir_immu;
	iwp = &INTRMAP_PRIVATE(*intrmap_privatep)->ir_inv_wait;
	intrmap = immu->immu_intrmap;
	idx = INTRMAP_PRIVATE(*intrmap_privatep)->ir_idx;

	bzero(intrmap->intrmap_vaddr + idx * INTRMAP_RTE_SIZE,
	    INTRMAP_RTE_SIZE);

	immu_qinv_intr_one_cache(immu, idx, iwp);

	mutex_enter(&intrmap->intrmap_lock);
	bitset_del(&intrmap->intrmap_map, idx);
	if (intrmap->intrmap_free == INTRMAP_IDX_FULL) {
		intrmap->intrmap_free = idx;
	}
	mutex_exit(&intrmap->intrmap_lock);

	kmem_free(*intrmap_privatep, sizeof (intrmap_private_t));
	*intrmap_privatep = NULL;
}

/* record the ioapic rdt entry */
static void
immu_intrmap_rdt(void *intrmap_private, ioapic_rdt_t *irdt)
{
	uint32_t rdt_entry, tm, pol, idx, vector;

	rdt_entry = irdt->ir_lo;

	if (intrmap_private != INTRMAP_DISABLE && intrmap_private != NULL) {
		idx = INTRMAP_PRIVATE(intrmap_private)->ir_idx;
		tm = RDT_TM(rdt_entry);
		pol = RDT_POL(rdt_entry);
		vector = RDT_VECTOR(rdt_entry);
		irdt->ir_lo = (tm << INTRMAP_IOAPIC_TM_SHIFT) |
		    (pol << INTRMAP_IOAPIC_POL_SHIFT) |
		    ((idx >> 15) << INTRMAP_IOAPIC_IDX15_SHIFT) |
		    vector;
		irdt->ir_hi = (idx << INTRMAP_IOAPIC_IDX_SHIFT) |
		    (1 << INTRMAP_IOAPIC_FORMAT_SHIFT);
	} else {
		irdt->ir_hi <<= APIC_ID_BIT_OFFSET;
	}
}

/* record the msi interrupt structure */
/*ARGSUSED*/
static void
immu_intrmap_msi(void *intrmap_private, msi_regs_t *mregs)
{
	uint_t	idx;

	if (intrmap_private != INTRMAP_DISABLE && intrmap_private != NULL) {
		idx = INTRMAP_PRIVATE(intrmap_private)->ir_idx;

		mregs->mr_data = 0;
		mregs->mr_addr = MSI_ADDR_HDR |
		    ((idx & 0x7fff) << INTRMAP_MSI_IDX_SHIFT) |
		    (1 << INTRMAP_MSI_FORMAT_SHIFT) |
		    (1 << INTRMAP_MSI_SHV_SHIFT) |
		    ((idx >> 15) << INTRMAP_MSI_IDX15_SHIFT);
	} else {
		mregs->mr_addr = MSI_ADDR_HDR |
		    (MSI_ADDR_RH_FIXED << MSI_ADDR_RH_SHIFT) |
		    (MSI_ADDR_DM_PHYSICAL << MSI_ADDR_DM_SHIFT) |
		    (mregs->mr_addr << MSI_ADDR_DEST_SHIFT);
		mregs->mr_data = (MSI_DATA_TM_EDGE << MSI_DATA_TM_SHIFT) |
		    mregs->mr_data;
	}
}

/* ######################################################################### */
/*
 * Functions exported by immu_intr.c
 */
void
immu_intrmap_setup(list_t *listp)
{
	immu_t *immu;

	/*
	 * Check if ACPI DMAR tables say that
	 * interrupt remapping is supported
	 */
	if (immu_dmar_intrmap_supported() == B_FALSE) {
		return;
	}

	/*
	 * Check if interrupt remapping is disabled.
	 */
	if (immu_intrmap_enable == B_FALSE) {
		return;
	}

	psm_vt_ops = &intrmap_ops;

	immu = list_head(listp);
	for (; immu; immu = list_next(listp, immu)) {
		mutex_init(&(immu->immu_intrmap_lock), NULL,
		    MUTEX_DEFAULT, NULL);
		mutex_enter(&(immu->immu_intrmap_lock));
		immu_init_inv_wait(&immu->immu_intrmap_inv_wait,
		    "intrmapglobal", B_TRUE);
		immu->immu_intrmap_setup = B_TRUE;
		mutex_exit(&(immu->immu_intrmap_lock));
	}
}

void
immu_intrmap_startup(immu_t *immu)
{
	/* do nothing */
	mutex_enter(&(immu->immu_intrmap_lock));
	if (immu->immu_intrmap_setup == B_TRUE) {
		immu->immu_intrmap_running = B_TRUE;
	}
	mutex_exit(&(immu->immu_intrmap_lock));
}

/*
 * Register a Intel IOMMU unit (i.e. DMAR unit's)
 * interrupt handler
 */
void
immu_intr_register(immu_t *immu)
{
	int irq, vect;
	char intr_handler_name[IMMU_MAXNAMELEN];
	uint32_t msi_data;
	uint32_t uaddr;
	uint32_t msi_addr;
	uint32_t localapic_id = 0;

	if (psm_get_localapicid)
		localapic_id = psm_get_localapicid(0);

	msi_addr = (MSI_ADDR_HDR |
	    ((localapic_id & 0xFF) << MSI_ADDR_DEST_SHIFT) |
	    (MSI_ADDR_RH_FIXED << MSI_ADDR_RH_SHIFT) |
	    (MSI_ADDR_DM_PHYSICAL << MSI_ADDR_DM_SHIFT));

	if (intrmap_apic_mode == LOCAL_X2APIC) {
		uaddr = localapic_id & 0xFFFFFF00;
	} else {
		uaddr = 0;
	}

	/* Dont need to hold immu_intr_lock since we are in boot */
	irq = vect = psm_get_ipivect(IMMU_INTR_IPL, -1);
	if (psm_xlate_vector_by_irq != NULL)
		vect = psm_xlate_vector_by_irq(irq);

	msi_data = ((MSI_DATA_DELIVERY_FIXED <<
	    MSI_DATA_DELIVERY_SHIFT) | vect);

	(void) snprintf(intr_handler_name, sizeof (intr_handler_name),
	    "%s-intr-handler", immu->immu_name);

	(void) add_avintr((void *)NULL, IMMU_INTR_IPL,
	    immu_intr_handler, intr_handler_name, irq,
	    (caddr_t)immu, NULL, NULL, NULL);

	immu_regs_intr_enable(immu, msi_addr, msi_data, uaddr);

	(void) immu_intr_handler((caddr_t)immu, NULL);
}
