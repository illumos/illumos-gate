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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/amd_iommu.h>

#include "amd_iommu_impl.h"
#include "amd_iommu_page_tables.h"

ddi_dma_attr_t amd_iommu_pgtable_dma_attr = {
	DMA_ATTR_V0,
	0U,				/* dma_attr_addr_lo */
	0xffffffffffffffffULL,		/* dma_attr_addr_hi */
	0xffffffffU,			/* dma_attr_count_max */
	(uint64_t)4096,			/* dma_attr_align */
	1,				/* dma_attr_burstsizes */
	64,				/* dma_attr_minxfer */
	0xffffffffU,			/* dma_attr_maxxfer */
	0xffffffffU,			/* dma_attr_seg */
	1,				/* dma_attr_sgllen, variable */
	64,				/* dma_attr_granular */
	0				/* dma_attr_flags */
};

/*ARGSUSED*/
static int
amd_iommu_get_src_bdf(amd_iommu_t *iommu, uint16_t bdf, uint16_t *src_bdfp)
{
	return (amd_iommu_lookup_src_bdf(bdf, src_bdfp));
}

static dev_info_t *
amd_iommu_pci_dip(dev_info_t *rdip)
{
	dev_info_t *pdip;
	const char *driver = ddi_driver_name(rdip);
	int instance = ddi_get_instance(rdip);
	const char *f = "amd_iommu_pci_dip";

	/* Hold rdip so it and its parents don't go away */
	ndi_hold_devi(rdip);

	if (ddi_is_pci_dip(rdip))
		return (rdip);

	pdip = rdip;
	while (pdip = ddi_get_parent(pdip)) {
		if (ddi_is_pci_dip(pdip)) {
			ndi_hold_devi(pdip);
			ndi_rele_devi(rdip);
			return (pdip);
		}
	}

	cmn_err(CE_WARN, "%s: %s%d dip = %p has no PCI parent",
	    f, driver, instance, (void *)rdip);

	ndi_rele_devi(rdip);

	return (NULL);
}

static int
amd_iommu_get_devtbl_entry(amd_iommu_t *iommu, dev_info_t *rdip,
    uint16_t *deviceidp, uint64_t **devtbl_entry)
{
	int bus = -1;
	int device = -1;
	int func = -1;
	uint16_t bdf;
	uint16_t src_bdf;
	uint16_t deviceid;
	dev_info_t *idip = iommu->aiomt_dip;
	const char *driver = ddi_driver_name(idip);
	int instance = ddi_get_instance(idip);
	dev_info_t *pci_dip;
	const char *f = "amd_iommu_get_devtbl_entry";

	*deviceidp = 0;
	*devtbl_entry = NULL;

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_DEVTBL) {
		char buf[MAXPATHLEN];
		cmn_err(CE_WARN, "%s: attempting to get devtbl entry for %s",
		    f, ddi_pathname(rdip, buf));
	}

	pci_dip = amd_iommu_pci_dip(rdip);
	if (pci_dip == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: failed to get PCI dip. idx=%d",
		    f, driver, instance, iommu->aiomt_idx);
		return (DDI_FAILURE);
	}

	if (acpica_get_bdf(pci_dip, &bus, &device, &func) == DDI_FAILURE) {
		ndi_rele_devi(pci_dip);
		cmn_err(CE_WARN, "%s: %s%d: failed to get BDF for PCI dip "
		    "(%p). idx=%d", f, driver, instance, (void *)pci_dip,
		    iommu->aiomt_idx);
		return (DDI_FAILURE);
	}

	ndi_rele_devi(pci_dip);

	if (bus > UINT8_MAX || bus < 0 ||
	    device > UINT8_MAX || device < 0 ||
	    func > UINT8_MAX || func < 0) {
		cmn_err(CE_WARN, "%s: %s%d: invalid BDF(%d,%d,%d) for PCI dip "
		    "(%p). idx=%d", f, driver, instance, bus, device, func,
		    (void *)pci_dip, iommu->aiomt_idx);
		return (DDI_FAILURE);
	}

	bdf = ((uint8_t)bus << 8) | ((uint8_t)device << 3) | (uint8_t)func;

	if (amd_iommu_get_src_bdf(iommu, bdf, &src_bdf)
	    == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s: %s%d: failed to get SRC BDF for PCI "
		    "dip (%p). idx=%d", f, driver, instance, (void *)pci_dip,
		    iommu->aiomt_idx);
		return (DDI_FAILURE);
	}

	deviceid = src_bdf;

	if ((deviceid + 1) * AMD_IOMMU_DEVTBL_ENTRY_SZ >
	    iommu->aiomt_devtbl_sz) {
		cmn_err(CE_WARN, "%s: %s%d: deviceid (%u) for PCI dip (%p) "
		    "exceeds device table size (%u). IOMMU idx=%d", f, driver,
		    instance, deviceid, (void *)pci_dip, iommu->aiomt_devtbl_sz,
		    iommu->aiomt_idx);
		return (DDI_FAILURE);
	}

	*deviceidp = deviceid;
	/*LINTED*/
	*devtbl_entry = (uint64_t *)(&iommu->aiomt_devtbl
	    [deviceid * AMD_IOMMU_DEVTBL_ENTRY_SZ]);

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_DEVTBL) {
		char buf[MAXPATHLEN];
		cmn_err(CE_WARN, "%s: got deviceid=%u devtbl entry (%p) for %s",
		    f, *deviceidp, (void *)(uintptr_t)(*devtbl_entry),
		    ddi_pathname(rdip, buf));
	}
	return (DDI_SUCCESS);
}

int
amd_iommu_rm_devtab(amd_iommu_t *iommu, dev_info_t *rdip)
{
	int invalidate;
	uint64_t *devtbl_entry;
	uint16_t deviceid;
	int error = DDI_SUCCESS;
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	const char *f = "amd_iommu_rm_devtab";

	if (amd_iommu_get_devtbl_entry(iommu, rdip, &deviceid, &devtbl_entry)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d: rdip=%p. Failed to "
		    "get device table entry.", f, driver, instance,
		    iommu->aiomt_idx, (void *)rdip);
		return (DDI_FAILURE);
	}

	SYNC_FORKERN(iommu->aiomt_dmahdl);
	invalidate = AMD_IOMMU_REG_GET(devtbl_entry[0], AMD_IOMMU_DEVTBL_V);

	AMD_IOMMU_REG_SET(devtbl_entry[0], AMD_IOMMU_DEVTBL_V, 0);
	SYNC_FORDEV(iommu->aiomt_dmahdl);

	if (invalidate) {
		amd_iommu_cmdargs_t cmdargs = {0};
		cmdargs.ca_deviceid = deviceid;
		error = amd_iommu_cmd(iommu, AMD_IOMMU_CMD_INVAL_DEVTAB_ENTRY,
		    &cmdargs, AMD_IOMMU_CMD_FLAGS_COMPL_WAIT, 0);
	}

	return (error);
}

int
amd_iommu_page_table_hash_init(amd_iommu_page_table_hash_t *ampt)
{
	ampt->ampt_hash = kmem_zalloc(sizeof (amd_iommu_page_table_t *) *
	    AMD_IOMMU_PGTABLE_HASH_SZ, KM_SLEEP);
	return (DDI_SUCCESS);
}

void
amd_iommu_page_table_hash_fini(amd_iommu_page_table_hash_t *ampt)
{
	kmem_free(ampt->ampt_hash,
	    sizeof (amd_iommu_page_table_t *) * AMD_IOMMU_PGTABLE_HASH_SZ);
	ampt->ampt_hash = NULL;
}

static uint32_t
pt_hashfn(uint64_t pa_4K)
{
	return (pa_4K % AMD_IOMMU_PGTABLE_HASH_SZ);
}

static void
amd_iommu_insert_pgtable_hash(amd_iommu_page_table_t *pt)
{
	uint64_t pa_4K = ((uint64_t)pt->pt_cookie.dmac_cookie_addr) >> 12;
	uint32_t idx = pt_hashfn(pa_4K);

	mutex_enter(&amd_iommu_page_table_hash.ampt_lock);

	pt->pt_next = amd_iommu_page_table_hash.ampt_hash[idx];
	pt->pt_prev = NULL;
	amd_iommu_page_table_hash.ampt_hash[idx] = pt;
	if (pt->pt_next)
		pt->pt_next->pt_prev = pt;

	mutex_exit(&amd_iommu_page_table_hash.ampt_lock);
}

static void
amd_iommu_remove_pgtable_hash(amd_iommu_page_table_t *pt)
{

	uint64_t pa_4K = (pt->pt_cookie.dmac_cookie_addr >> 12);
	uint32_t idx = pt_hashfn(pa_4K);

	mutex_enter(&amd_iommu_page_table_hash.ampt_lock);

	if (pt->pt_next)
		pt->pt_next->pt_prev = pt->pt_prev;

	if (pt->pt_prev)
		pt->pt_prev->pt_next = pt->pt_next;
	else
		amd_iommu_page_table_hash.ampt_hash[idx] = pt->pt_next;

	pt->pt_next = NULL;
	pt->pt_prev = NULL;

	mutex_exit(&amd_iommu_page_table_hash.ampt_lock);
}

static amd_iommu_page_table_t *
amd_iommu_lookup_pgtable_hash(uint64_t pgtable_pa_4K)
{
	amd_iommu_page_table_t *pt;
	uint32_t idx = pt_hashfn(pgtable_pa_4K);

	mutex_enter(&amd_iommu_page_table_hash.ampt_lock);
	pt = amd_iommu_page_table_hash.ampt_hash[idx];
	for (; pt; pt = pt->pt_next) {
		if (pt->pt_cookie.dmac_cookie_addr == (pgtable_pa_4K << 12))
			break;
	}
	mutex_exit(&amd_iommu_page_table_hash.ampt_lock);

	return (pt);
}

/*ARGSUSED*/
static amd_iommu_page_table_t *
amd_iommu_lookup_pgtable(amd_iommu_t *iommu, amd_iommu_page_table_t *ppt,
    int level, uint16_t index)
{
	uint64_t *devtbl_entry;
	uint64_t pdte;
	uint64_t pgtable_pa_4K;
	uint8_t TV;
	uint8_t V;

	ASSERT(level > 0 && level <= AMD_IOMMU_PGTABLE_MAXLEVEL);

	if (level == AMD_IOMMU_PGTABLE_MAXLEVEL) {
		devtbl_entry = (uint64_t *)ppt;
		SYNC_FORKERN(iommu->aiomt_dmahdl);
		TV = AMD_IOMMU_REG_GET(devtbl_entry[0], AMD_IOMMU_DEVTBL_TV);
		V = AMD_IOMMU_REG_GET(devtbl_entry[0], AMD_IOMMU_DEVTBL_V);
		if (V != 1 || TV != 1) {
			return (NULL);
		}
		pgtable_pa_4K = AMD_IOMMU_REG_GET(devtbl_entry[0],
		    AMD_IOMMU_DEVTBL_ROOT_PGTBL);
	} else {
		pdte = ppt->pt_pgtblva[index];
		SYNC_FORKERN(ppt->pt_dma_hdl);
		if (AMD_IOMMU_REG_GET(pdte, AMD_IOMMU_PTDE_PR) == 0) {
			if (amd_iommu_debug & AMD_IOMMU_DEBUG_PAGE_TABLES) {
				cmn_err(CE_NOTE, "Skipping PR=0 pdte: %p",
				    (void *)(uintptr_t)pdte);
			}
			return (NULL);
		}
		pgtable_pa_4K = AMD_IOMMU_REG_GET(pdte, AMD_IOMMU_PTDE_ADDR);
	}

	return (amd_iommu_lookup_pgtable_hash(pgtable_pa_4K));
}

static int
amd_iommu_alloc_pgtable(amd_iommu_t *iommu, uint16_t domainid,
    amd_iommu_page_table_t **ptp)
{
	int err;
	uint_t ncookies;
	amd_iommu_page_table_t *pt;
	dev_info_t *idip = iommu->aiomt_dip;
	const char *driver = ddi_driver_name(idip);
	int instance = ddi_get_instance(idip);
	const char *f = "amd_iommu_alloc_pgtable";

	*ptp = NULL;

	pt = kmem_zalloc(sizeof (amd_iommu_page_table_t), KM_SLEEP);

	/*
	 * Each page table is 4K in size
	 */
	pt->pt_mem_reqsz = AMD_IOMMU_PGTABLE_SZ;

	/*
	 * Alloc a DMA handle. Use the IOMMU dip as we want this DMA
	 * to *not* enter the IOMMU - no recursive entrance.
	 */
	err = ddi_dma_alloc_handle(idip, &amd_iommu_pgtable_dma_attr,
	    DDI_DMA_SLEEP, NULL, &pt->pt_dma_hdl);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: domainid = %d. Cannot alloc "
		    "DMA handle for IO Page Table", f, driver, instance,
		    domainid);
		kmem_free(pt, sizeof (amd_iommu_page_table_t));
		return (DDI_FAILURE);
	}

	/*
	 * Alloc memory for IO Page Table.
	 */
	err = ddi_dma_mem_alloc(pt->pt_dma_hdl, pt->pt_mem_reqsz,
	    &amd_iommu_devacc, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
	    NULL, (caddr_t *)&pt->pt_pgtblva, (size_t *)&pt->pt_mem_realsz,
	    &pt->pt_mem_hdl);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: domainid=%d. Cannot allocate "
		    "DMA memory for IO Page table",
		    f, driver, instance, domainid);
		ddi_dma_free_handle(&pt->pt_dma_hdl);
		kmem_free(pt, sizeof (amd_iommu_page_table_t));
		return (DDI_FAILURE);
	}

	/*
	 * The Page table DMA VA must be 4K aligned and
	 * size >= than requested memory.
	 *
	 */
	ASSERT(((uint64_t)(uintptr_t)pt->pt_pgtblva & AMD_IOMMU_PGTABLE_ALIGN)
	    == 0);
	ASSERT(pt->pt_mem_realsz >= pt->pt_mem_reqsz);

	/*
	 * Now bind the handle
	 */
	err = ddi_dma_addr_bind_handle(pt->pt_dma_hdl, NULL,
	    (caddr_t)pt->pt_pgtblva, pt->pt_mem_realsz,
	    DDI_DMA_READ | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
	    NULL, &pt->pt_cookie, &ncookies);
	if (err != DDI_DMA_MAPPED) {
		cmn_err(CE_WARN, "%s: %s%d: domainid=%d. Cannot bind memory "
		    "for DMA to IO Page Tables. bufrealsz=%p",
		    f, driver, instance, domainid,
		    (void *)(uintptr_t)pt->pt_mem_realsz);
		ddi_dma_mem_free(&pt->pt_mem_hdl);
		ddi_dma_free_handle(&pt->pt_dma_hdl);
		kmem_free(pt, sizeof (amd_iommu_page_table_t));
		return (DDI_FAILURE);
	}

	/*
	 * We assume the DMA engine on the IOMMU is capable of handling the
	 * whole page table in a single cookie. If not and multiple cookies
	 * are needed we fail.
	 */
	if (ncookies != 1) {
		cmn_err(CE_WARN, "%s: %s%d: Cannot handle multiple "
		    "cookies for DMA to IO page Table #cookies=%u",
		    f, driver, instance, ncookies);
		(void) ddi_dma_unbind_handle(pt->pt_dma_hdl);
		ddi_dma_mem_free(&pt->pt_mem_hdl);
		ddi_dma_free_handle(&pt->pt_dma_hdl);
		kmem_free(pt, sizeof (amd_iommu_page_table_t));
		return (DDI_FAILURE);
	}

	/*
	 * The address in the cookie must be 4K aligned and >= table size
	 */
	ASSERT(pt->pt_cookie.dmac_cookie_addr != NULL);
	ASSERT((pt->pt_cookie.dmac_cookie_addr & AMD_IOMMU_PGTABLE_ALIGN) == 0);
	ASSERT(pt->pt_cookie.dmac_size >= pt->pt_mem_realsz);
	ASSERT(pt->pt_cookie.dmac_size >= pt->pt_mem_reqsz);
	ASSERT(pt->pt_mem_reqsz >= AMD_IOMMU_PGTABLE_SIZE);
	ASSERT(pt->pt_mem_realsz >= pt->pt_mem_reqsz);
	ASSERT(pt->pt_pgtblva);
	ASSERT(pt->pt_index == 0);

	bzero(pt->pt_pgtblva, pt->pt_mem_realsz);
	SYNC_FORDEV(pt->pt_dma_hdl);

	amd_iommu_insert_pgtable_hash(pt);

	*ptp = pt;

	return (DDI_SUCCESS);
}

static void
amd_iommu_free_pgtable(amd_iommu_t *iommu, amd_iommu_page_table_t *pt)
{
	int i;
	uint64_t *pte_array;
	dev_info_t *dip = iommu->aiomt_dip;
	int instance = ddi_get_instance(dip);
	const char *driver = ddi_driver_name(dip);
	const char *f = "amd_iommu_free_pgtable";

	amd_iommu_remove_pgtable_hash(pt);

	SYNC_FORKERN(pt->pt_dma_hdl);
	pte_array = pt->pt_pgtblva;
	for (i = 0; i < AMD_IOMMU_PGTABLE_SZ / (sizeof (*pte_array)); i++) {
		ASSERT(AMD_IOMMU_REG_GET(pte_array[i],
		    AMD_IOMMU_PTDE_PR)  == 0);
	}

	/* Unbind the handle */
	if (ddi_dma_unbind_handle(pt->pt_dma_hdl) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d, domainid=%u. "
		    "Failed to unbind handle: %p for IOMMU Page Table",
		    f, driver, instance, iommu->aiomt_idx, pt->pt_domainid,
		    (void *)pt->pt_dma_hdl);
	}
	/* Free the table memory allocated for DMA */
	ddi_dma_mem_free(&pt->pt_mem_hdl);

	/* Free the DMA handle */
	ddi_dma_free_handle(&pt->pt_dma_hdl);

	kmem_free(pt, sizeof (amd_iommu_page_table_t));
}

static int
init_pde(amd_iommu_page_table_t *ppt, amd_iommu_page_table_t *pt)
{
	uint64_t *pdep = &ppt->pt_pgtblva[pt->pt_index];
	uint64_t next_pgtable_pa_4K = (pt->pt_cookie.dmac_cookie_addr) >> 12;

	/* nothing to set. PDE is already set */
	if (AMD_IOMMU_REG_GET(REGVAL64(pdep), AMD_IOMMU_PTDE_PR) == 1) {
		ASSERT(PT_REF_VALID(ppt));
		ASSERT(PT_REF_VALID(pt));
		ppt->pt_ptde_ref[pt->pt_index]++;
		ASSERT(AMD_IOMMU_REG_GET(REGVAL64(pdep), AMD_IOMMU_PTDE_ADDR)
		    == next_pgtable_pa_4K);
		return (DDI_SUCCESS);
	}

	ppt->pt_ref++;
	ASSERT(PT_REF_VALID(ppt));

	AMD_IOMMU_REG_SET(REGVAL64(pdep), AMD_IOMMU_PTDE_IW, 1);
	AMD_IOMMU_REG_SET(REGVAL64(pdep), AMD_IOMMU_PTDE_IR, 1);
	AMD_IOMMU_REG_SET(REGVAL64(pdep), AMD_IOMMU_PTDE_ADDR,
	    next_pgtable_pa_4K);
	pt->pt_parent = ppt;
	AMD_IOMMU_REG_SET(REGVAL64(pdep), AMD_IOMMU_PTDE_NXT_LVL,
	    pt->pt_level);
	ppt->pt_ptde_ref[pt->pt_index] = 1;
	AMD_IOMMU_REG_SET(REGVAL64(pdep), AMD_IOMMU_PTDE_PR, 1);
	SYNC_FORDEV(ppt->pt_dma_hdl);
	ASSERT(AMD_IOMMU_REG_GET(REGVAL64(pdep), AMD_IOMMU_PTDE_PR) == 1);

	return (DDI_SUCCESS);
}

static int
init_pte(amd_iommu_page_table_t *pt, uint64_t pa, uint16_t index)
{
	uint64_t *ptep = &pt->pt_pgtblva[index];
	uint64_t pa_4K = pa >> 12;

	/* nothing to set if PTE is already set */
	if (AMD_IOMMU_REG_GET(REGVAL64(ptep), AMD_IOMMU_PTDE_PR) == 1) {
		ASSERT(PT_REF_VALID(pt));
		pt->pt_ptde_ref[index]++;
		ASSERT(AMD_IOMMU_REG_GET(REGVAL64(ptep), AMD_IOMMU_PTDE_ADDR)
		    == pa_4K);
		return (DDI_SUCCESS);
	}

	pt->pt_ref++;
	ASSERT(PT_REF_VALID(pt));

	AMD_IOMMU_REG_SET(REGVAL64(ptep), AMD_IOMMU_PTDE_IW, 1);
	AMD_IOMMU_REG_SET(REGVAL64(ptep), AMD_IOMMU_PTDE_IR, 1);
	AMD_IOMMU_REG_SET(REGVAL64(ptep), AMD_IOMMU_PTE_FC, 0);
	AMD_IOMMU_REG_SET(REGVAL64(ptep), AMD_IOMMU_PTE_U, 0);
	AMD_IOMMU_REG_SET(REGVAL64(ptep), AMD_IOMMU_PTDE_ADDR, pa_4K);
	AMD_IOMMU_REG_SET(REGVAL64(ptep), AMD_IOMMU_PTDE_NXT_LVL, 0);
	pt->pt_ptde_ref[index] = 1;
	AMD_IOMMU_REG_SET(REGVAL64(ptep), AMD_IOMMU_PTDE_PR, 1);
	SYNC_FORDEV(pt->pt_dma_hdl);
	ASSERT(AMD_IOMMU_REG_GET(REGVAL64(ptep), AMD_IOMMU_PTDE_PR) == 1);

	if (pa_4K == 0xcfff0)
		debug_enter("init_pte");

	return (DDI_SUCCESS);
}

int
init_devtbl(amd_iommu_t *iommu, int16_t deviceid, uint64_t *devtbl_entry,
    amd_iommu_page_table_t *pt, uint64_t *new_devtblp)
{
	uint64_t entry[4] = {0};
	int invalidate;
	int i;
	uint64_t root_pgtable_pa_4K = (pt->pt_cookie.dmac_cookie_addr) >> 12;
	int error = DDI_SUCCESS;

	*new_devtblp = 0;

	SYNC_FORKERN(iommu->aiomt_dmahdl);

	if (AMD_IOMMU_REG_GET(devtbl_entry[0], AMD_IOMMU_DEVTBL_V) == 1 &&
	    AMD_IOMMU_REG_GET(devtbl_entry[0], AMD_IOMMU_DEVTBL_TV) == 1) {
		iommu->aiomt_devtbl_ent_ref[deviceid]++;
		*new_devtblp = 0;
		return (DDI_SUCCESS);
	}

	invalidate = AMD_IOMMU_REG_GET(devtbl_entry[0], AMD_IOMMU_DEVTBL_V);

	entry[3] = 0;
	entry[2] = 0;
	AMD_IOMMU_REG_SET(entry[1], AMD_IOMMU_DEVTBL_SYSMGT, 0);
	AMD_IOMMU_REG_SET(entry[1], AMD_IOMMU_DEVTBL_EX, 0);
	AMD_IOMMU_REG_SET(entry[1], AMD_IOMMU_DEVTBL_SD, 0);
	AMD_IOMMU_REG_SET(entry[1], AMD_IOMMU_DEVTBL_CACHE, 0);
	AMD_IOMMU_REG_SET(entry[1], AMD_IOMMU_DEVTBL_IOCTL, 0);
	AMD_IOMMU_REG_SET(entry[1], AMD_IOMMU_DEVTBL_SA, 0);
	AMD_IOMMU_REG_SET(entry[1], AMD_IOMMU_DEVTBL_SE, 0);
	AMD_IOMMU_REG_SET(entry[1], AMD_IOMMU_DEVTBL_IOTLB, 1);
	AMD_IOMMU_REG_SET(entry[1], AMD_IOMMU_DEVTBL_DOMAINID, pt->pt_domainid);
	AMD_IOMMU_REG_SET(entry[0], AMD_IOMMU_DEVTBL_IW, 1);
	AMD_IOMMU_REG_SET(entry[0], AMD_IOMMU_DEVTBL_IR, 1);
	AMD_IOMMU_REG_SET(entry[0], AMD_IOMMU_DEVTBL_ROOT_PGTBL,
	    root_pgtable_pa_4K);
	AMD_IOMMU_REG_SET(entry[0], AMD_IOMMU_DEVTBL_PG_MODE,
	    AMD_IOMMU_PGTABLE_MAXLEVEL);
	AMD_IOMMU_REG_SET(entry[0], AMD_IOMMU_DEVTBL_TV, 1);
	AMD_IOMMU_REG_SET(entry[0], AMD_IOMMU_DEVTBL_V, 1);
	iommu->aiomt_devtbl_ent_ref[deviceid] = 1;

	for (i = 1; i < 4; i++) {
		devtbl_entry[i] = entry[i];
	}
	*new_devtblp = entry[0];

	pt->pt_parent = (amd_iommu_page_table_t *)devtbl_entry;

	if (invalidate) {
		amd_iommu_cmdargs_t cmdargs = {0};
		cmdargs.ca_deviceid = deviceid;
		error = amd_iommu_cmd(iommu, AMD_IOMMU_CMD_INVAL_DEVTAB_ENTRY,
		    &cmdargs, AMD_IOMMU_CMD_FLAGS_COMPL_WAIT, 0);
	}

	return (error);
}

static int
amd_iommu_setup_1_pgtable(amd_iommu_t *iommu, dev_info_t *rdip,
    uint16_t deviceid, amd_iommu_page_table_t *ppt, uint16_t index,
    int level, uint64_t va, uint64_t pa, amd_iommu_page_table_t **ptp,
    uint16_t *next_idxp, uint64_t *new_devtblp)
{
	int error;
	uint16_t domainid;
	uint64_t *devtbl_entry;
	amd_iommu_page_table_t *pt;
	const char *driver = ddi_driver_name(rdip);
	int instance = ddi_get_instance(rdip);
	const char *f = "amd_iommu_setup_1_pgtable";

	*ptp = NULL;
	*next_idxp = 0;
	error = DDI_SUCCESS;

	ASSERT(level > 0 && level <= AMD_IOMMU_PGTABLE_MAXLEVEL);

	domainid = (level == AMD_IOMMU_PGTABLE_MAXLEVEL) ? index :
	    ppt->pt_domainid;

	/* Check if page table is already allocated */
	if (pt = amd_iommu_lookup_pgtable(iommu, ppt, level, index)) {
		ASSERT(pt->pt_domainid == domainid);
		ASSERT(pt->pt_level == level);
		ASSERT(pt->pt_index == index);
		goto out;
	}

	if (amd_iommu_alloc_pgtable(iommu, domainid, &pt)
	    != DDI_SUCCESS) {
		ASSERT(0);
		cmn_err(CE_WARN, "%s: %s%d: idx = %u, domainid = %u, va = %p ",
		    f, driver, instance, iommu->aiomt_idx, domainid,
		    (void *)(uintptr_t)va);
		return (DDI_FAILURE);
	}

	pt->pt_domainid = domainid;
	pt->pt_level = level;
	pt->pt_index = index;

	if (level == AMD_IOMMU_PGTABLE_MAXLEVEL) {
		devtbl_entry = (uint64_t *)ppt;
		error = init_devtbl(iommu, deviceid, devtbl_entry, pt,
		    new_devtblp);
	} else {
		if (pa >> 12 == 0xcfff0) {
			cmn_err(CE_WARN, "level = %d", level);
			debug_enter("init-pde");
		}
		error = init_pde(ppt, pt);
	}

out:
	if (level == 1) {
		ASSERT(error == DDI_SUCCESS);
		error = init_pte(pt, pa, AMD_IOMMU_VA_BITS(va, level));
	} else {
		*next_idxp = AMD_IOMMU_VA_BITS(va, level);
		*ptp = pt;
	}

	return (error);
}

static int
amd_iommu_teardown_pdte(amd_iommu_t *iommu, amd_iommu_page_table_t *pt,
    int index)
{
	uint64_t *ptdep = &pt->pt_pgtblva[index];

	if (AMD_IOMMU_REG_GET(REGVAL64(ptdep), AMD_IOMMU_PTDE_PR) == 1) {
		AMD_IOMMU_REG_SET(REGVAL64(ptdep), AMD_IOMMU_PTDE_PR, 0);
		SYNC_FORDEV(pt->pt_dma_hdl);
		ASSERT(AMD_IOMMU_REG_GET(REGVAL64(ptdep),
		    AMD_IOMMU_PTDE_PR) == 0);
		pt->pt_ref--;
		ASSERT(PT_REF_VALID(pt));
	}

	if (pt->pt_ref == 0) {
		amd_iommu_free_pgtable(iommu, pt);
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

static void
amd_iommu_invalidate_devtbl_tv(uint64_t *devtbl_entry)
{
	AMD_IOMMU_REG_SET(REGVAL64(&devtbl_entry[0]), AMD_IOMMU_DEVTBL_TV, 0);
	ASSERT(AMD_IOMMU_REG_GET(devtbl_entry[0], AMD_IOMMU_DEVTBL_TV) == 0);
}

static int
amd_iommu_create_pgtables(amd_iommu_t *iommu, uint16_t domainid,
    dev_info_t *rdip, uint64_t va, uint64_t pa)
{
	int level;
	uint16_t index;
	uint16_t next_idx;
	uint16_t deviceid;
	uint64_t *devtbl_entry;
	uint64_t new_devtbl;
	amd_iommu_page_table_t *pt;
	amd_iommu_page_table_t *ppt;
	const char *driver = ddi_driver_name(rdip);
	int instance = ddi_get_instance(rdip);
	const char *f = "amd_iommu_create_pgtables";

	devtbl_entry = NULL;
	new_devtbl = 0;
	if (amd_iommu_get_devtbl_entry(iommu, rdip, &deviceid, &devtbl_entry)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d: rdip=%p. Failed to "
		    "get device table entry.", f, driver, instance,
		    iommu->aiomt_idx, (void *)rdip);
		return (DDI_FAILURE);
	}

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_PAGE_TABLES) {
		cmn_err(CE_NOTE, "%s: %s%d: idx = %u, domainid = %u, "
		    "va = %p, pa = %p",
		    f, driver, instance,
		    iommu->aiomt_idx, domainid,
		    (void *)(uintptr_t)va,
		    (void *)(uintptr_t)pa);
	}

	/*
	 * Parent page table for level 6 page table is the device table entry
	 * Index in parent table for level 6 page table is the domainid
	 */
	ppt = (amd_iommu_page_table_t *)devtbl_entry;
	index = domainid;

	for (level = AMD_IOMMU_PGTABLE_MAXLEVEL; level > 0; level--) {
		pt = NULL;
		next_idx = 0;
		if (amd_iommu_setup_1_pgtable(iommu, rdip, deviceid,
		    ppt, index, level, va, pa, &pt, &next_idx, &new_devtbl)
		    != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s: %s%d: idx=%d: domainid=%u, va=%p"
			    " Failed to setup page table(s).",
			    f, driver, instance, iommu->aiomt_idx,
			    domainid, (void *)(uintptr_t)va);

			return (DDI_FAILURE);
		}

		if (level > 1) {
			ASSERT(pt);
			ASSERT(pt->pt_domainid == domainid);
			ppt = pt;
			index = next_idx;
		} else {
			ASSERT(level == 1);
			ASSERT(pt == NULL);
			ppt = NULL;
			ASSERT(next_idx == 0);
		}
	}

	if (new_devtbl != 0)
		devtbl_entry[0] = new_devtbl;

	SYNC_FORDEV(iommu->aiomt_dmahdl);

	return (DDI_SUCCESS);
}

static int
amd_iommu_destroy_pgtables(amd_iommu_t *iommu, uint16_t domainid,
    dev_info_t *rdip, uint64_t pageva)
{
	int level;
	uint16_t index;
	uint16_t prev_index;
	uint16_t deviceid;
	uint64_t *devtbl_entry;
	amd_iommu_page_table_t *pt;
	amd_iommu_page_table_t *ppt;
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	const char *f = "amd_iommu_destroy_pgtables";

	devtbl_entry = NULL;
	deviceid = 0;
	if (amd_iommu_get_devtbl_entry(iommu, rdip, &deviceid, &devtbl_entry)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d: rdip=%p. Failed to "
		    "get device table entry.", f, driver, instance,
		    iommu->aiomt_idx, (void *)rdip);
		return (DDI_FAILURE);
	}

	/*
	 * Parent page table for level 6 page table is the device table entry
	 * Index in parent table for level 6 page table is the domainid
	 */
	ppt = (amd_iommu_page_table_t *)devtbl_entry;
	index = domainid;
	for (level = AMD_IOMMU_PGTABLE_MAXLEVEL; level > 0; level--) {
		if (pt = amd_iommu_lookup_pgtable(iommu, ppt, level, index)) {
			ppt = pt;
			index = AMD_IOMMU_VA_BITS(pageva, level);
			continue;
		}
		break;
	}

	if (level == 0) {
		uint64_t pte = pt->pt_pgtblva[index];
		uint64_t pa_4K;
		pa_4K = AMD_IOMMU_REG_GET(pte, AMD_IOMMU_PTDE_ADDR);
		ASSERT(pageva == pa_4K << 12);
	}

	pt = ppt;
	for (++level; level <= AMD_IOMMU_PGTABLE_MAXLEVEL; level++) {
		prev_index = pt->pt_index;
		ppt = pt->pt_parent;
		if (amd_iommu_teardown_pdte(iommu, pt, index) != DDI_SUCCESS) {
			break;
		}
		index = prev_index;
		pt = ppt;
	}

	if (level > AMD_IOMMU_PGTABLE_MAXLEVEL) {
		amd_iommu_invalidate_devtbl_tv(devtbl_entry);
	}

	return (DDI_SUCCESS);
}

int
amd_iommu_walk_va2pa(amd_iommu_t *iommu, uint16_t domainid, dev_info_t *rdip,
    uint64_t va, uint64_t *pap)
{
	int level;
	uint64_t *devtbl_entry;
	uint64_t pte;
	uint64_t pa_4K;
	uint16_t deviceid;
	uint16_t index;
	amd_iommu_page_table_t *ppt;
	const char *driver = ddi_driver_name(rdip);
	int instance = ddi_get_instance(rdip);
	const char *f = "amd_iommu_walk_va2pa";

	*pap = 0;
	devtbl_entry = NULL;
	if (amd_iommu_get_devtbl_entry(iommu, rdip, &deviceid, &devtbl_entry)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d: rdip=%p. Failed to "
		    "get device table entry.", f, driver, instance,
		    iommu->aiomt_idx, (void *)rdip);
		return (DDI_FAILURE);
	}

	ppt = (amd_iommu_page_table_t *)devtbl_entry;
	index = domainid;
	for (level = AMD_IOMMU_PGTABLE_MAXLEVEL; level > 0; level--) {
		if (ppt = amd_iommu_lookup_pgtable(iommu, ppt, level, index)) {
			index = AMD_IOMMU_VA_BITS(va, level);
			continue;
		}
		break;
	}

	if (level != 0) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d: rdip=%p. Failed to "
		    "translate va to pa. Failed at level=%d for va=%p",
		    f, driver, instance, iommu->aiomt_idx, (void *)rdip, level,
		    (void *)(uintptr_t)va);
		return (DDI_FAILURE);
	}

	pte = ppt->pt_pgtblva[index];
	ASSERT(AMD_IOMMU_REG_GET(pte, AMD_IOMMU_PTDE_PR) == 1);
	pa_4K = AMD_IOMMU_REG_GET(pte, AMD_IOMMU_PTDE_ADDR);
	*pap = pa_4K << 12;

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_PAGE_TABLES) {
		cmn_err(CE_NOTE, "%s: %s%d: idx=%d: rdip = %p. Found pa=%p "
		    "for va=%p at level %d",
		    f, driver, instance, iommu->aiomt_idx, (void *)rdip,
		    (void *)(uintptr_t)*pap, (void *)(uintptr_t)va, level);
	}

	return (DDI_SUCCESS);
}

int
amd_iommu_map_pa2va(amd_iommu_t *iommu, uint16_t domainid, dev_info_t *rdip,
    uint64_t start_pa, uint64_t pa_sz)
{
	pfn_t pfn_start;
	pfn_t pfn_end;
	pfn_t pfn;
#ifdef DEBUG
	uint64_t pa = 0;
#endif
	uint64_t end_pa;
	const char *f = "amd_iommu_map_pa2va";

	pfn_start = (start_pa & MMU_PAGEMASK) >> MMU_PAGESHIFT;

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_PAGE_TABLES) {
		cmn_err(CE_NOTE, "pa = %p, pfn_new = %p, pfn_start = %p, "
		    "pgshift = %d",
		    (void *)(uintptr_t)start_pa,
		    (void *)(uintptr_t)(start_pa >> MMU_PAGESHIFT),
		    (void *)(uintptr_t)pfn_start, MMU_PAGESHIFT);
	}

	end_pa = start_pa + pa_sz - 1;
	pfn_end = (end_pa & MMU_PAGEMASK) >> MMU_PAGESHIFT;

	for (pfn = pfn_start; pfn <= pfn_end; pfn++) {
		if (amd_iommu_debug & AMD_IOMMU_DEBUG_PAGE_TABLES) {
			char buf[MAXPATHLEN];
			cmn_err(CE_WARN, "%s: attempting to create page tables "
			    "for pfn = %p, pfn_end = %p, path = %s",
			    f, (void *)(uintptr_t)pfn,
			    (void *)(uintptr_t)pfn_end,
			    ddi_pathname(rdip, buf));

		}
		if (amd_iommu_create_pgtables(iommu, domainid, rdip,
		    pfn << MMU_PAGESHIFT, pfn << MMU_PAGESHIFT)
		    != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to create_pgtables");
			return (DDI_FAILURE);
		}

#ifdef	DEBUG
		ASSERT(amd_iommu_walk_va2pa(iommu, domainid, rdip,
		    pfn << MMU_PAGESHIFT, &pa) == DDI_SUCCESS);
		ASSERT(pa == pfn << MMU_PAGESHIFT);
#endif

		if (amd_iommu_debug & AMD_IOMMU_DEBUG_PAGE_TABLES) {
			char buf[MAXPATHLEN];
			cmn_err(CE_WARN, "%s: successfully created page tables "
			    "for pfn = %p, pfn_end = %p, path = %s",
			    f, (void *)(uintptr_t)pfn,
			    (void *)(uintptr_t)pfn_end,
			    ddi_pathname(rdip, buf));
		}
	}

	return (DDI_SUCCESS);
}

int
amd_iommu_unmap_va(amd_iommu_t *iommu, uint16_t domainid, dev_info_t *rdip,
    uint64_t va, uint64_t va_sz)
{
	uint64_t page_start;
	uint64_t page_end;
	uint64_t end_va;
	uint64_t page;

	page_start = (va & PAGEMASK) >> PAGESHIFT;

	end_va = va + va_sz - 1;
	page_end = (end_va & PAGEMASK) >> PAGESHIFT;

	for (page = page_start; page <= page_end; page++) {
		if (amd_iommu_destroy_pgtables(iommu, domainid, rdip,
		    page << PAGESHIFT) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}
