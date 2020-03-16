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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/amd_iommu.h>
#include <sys/bootconf.h>
#include <sys/sysmacros.h>
#include <sys/ddidmareq.h>

#include "amd_iommu_impl.h"
#include "amd_iommu_acpi.h"
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

static amd_iommu_domain_t **amd_iommu_domain_table;

static struct {
	int f_count;
	amd_iommu_page_table_t *f_list;
} amd_iommu_pgtable_freelist;
int amd_iommu_no_pgtable_freelist;

/*ARGSUSED*/
static int
amd_iommu_get_src_bdf(amd_iommu_t *iommu, int32_t bdf, int32_t *src_bdfp)
{
	amd_iommu_acpi_ivhd_t *hinfop;

	hinfop = amd_iommu_lookup_ivhd(bdf);
	if (hinfop == NULL) {
		if (bdf == -1) {
			*src_bdfp = bdf;
		} else {
			cmn_err(CE_WARN, "No IVHD entry for 0x%x", bdf);
			return (DDI_FAILURE);
		}
	} else if (hinfop->ach_src_deviceid == -1) {
		*src_bdfp = bdf;
	} else {
		*src_bdfp = hinfop->ach_src_deviceid;
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
amd_iommu_get_domain(amd_iommu_t *iommu, dev_info_t *rdip, int alias,
    uint16_t deviceid, domain_id_t *domainid, const char *path)
{
	const char *f = "amd_iommu_get_domain";

	*domainid = AMD_IOMMU_INVALID_DOMAIN;

	ASSERT(strcmp(ddi_driver_name(rdip), "agpgart") != 0);

	switch (deviceid) {
		case AMD_IOMMU_INVALID_DOMAIN:
		case AMD_IOMMU_IDENTITY_DOMAIN:
		case AMD_IOMMU_PASSTHRU_DOMAIN:
		case AMD_IOMMU_SYS_DOMAIN:
			*domainid = AMD_IOMMU_SYS_DOMAIN;
			break;
		default:
			*domainid = deviceid;
			break;
	}

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_DEVTBL) {
		cmn_err(CE_NOTE, "%s: domainid for %s = %d",
		    f, path, *domainid);
	}

	return (DDI_SUCCESS);
}

static uint16_t
hash_domain(domain_id_t domainid)
{
	return (domainid % AMD_IOMMU_DOMAIN_HASH_SZ);
}

/*ARGSUSED*/
void
amd_iommu_init_page_tables(amd_iommu_t *iommu)
{
	amd_iommu_domain_table = kmem_zalloc(
	    sizeof (amd_iommu_domain_t *) * AMD_IOMMU_DOMAIN_HASH_SZ, KM_SLEEP);
}

/*ARGSUSED*/
void
amd_iommu_fini_page_tables(amd_iommu_t *iommu)
{
	if (amd_iommu_domain_table) {
		kmem_free(amd_iommu_domain_table,
		    sizeof (amd_iommu_domain_t *) * AMD_IOMMU_DOMAIN_HASH_SZ);
		amd_iommu_domain_table = NULL;
	}
}

static amd_iommu_domain_t *
amd_iommu_lookup_domain(amd_iommu_t *iommu, domain_id_t domainid,
    map_type_t type, int km_flags)
{
	uint16_t idx;
	amd_iommu_domain_t *dp;
	char name[AMD_IOMMU_VMEM_NAMELEN+1];

	ASSERT(amd_iommu_domain_table);

	idx = hash_domain(domainid);

	for (dp = amd_iommu_domain_table[idx]; dp; dp = dp->d_next) {
		if (dp->d_domainid == domainid)
			return (dp);
	}

	ASSERT(type != AMD_IOMMU_INVALID_MAP);

	dp = kmem_zalloc(sizeof (*dp), km_flags);
	if (dp == NULL)
		return (NULL);
	dp->d_domainid = domainid;
	dp->d_pgtable_root_4K = 0;	/* make this explicit */

	if (type == AMD_IOMMU_VMEM_MAP) {
		uint64_t base;
		uint64_t size;
		(void) snprintf(name, sizeof (name), "dvma_idx%d_domain%d",
		    iommu->aiomt_idx, domainid);
		base = MMU_PAGESIZE;
		size = AMD_IOMMU_SIZE_4G - MMU_PAGESIZE;
		dp->d_vmem = vmem_create(name, (void *)(uintptr_t)base, size,
		    MMU_PAGESIZE, NULL, NULL, NULL, 0,
		    km_flags == KM_SLEEP ? VM_SLEEP : VM_NOSLEEP);
		if (dp->d_vmem == NULL) {
			kmem_free(dp, sizeof (*dp));
			return (NULL);
		}
	} else {
		dp->d_vmem = NULL;
	}

	dp->d_next = amd_iommu_domain_table[idx];
	dp->d_prev = NULL;
	amd_iommu_domain_table[idx] = dp;
	if (dp->d_next)
		dp->d_next->d_prev = dp;
	dp->d_ref = 0;


	return (dp);
}

static void
amd_iommu_teardown_domain(amd_iommu_t *iommu, amd_iommu_domain_t *dp)
{
	uint16_t idx;
	int flags;
	amd_iommu_cmdargs_t cmdargs = {0};
	domain_id_t domainid = dp->d_domainid;
	const char *f = "amd_iommu_teardown_domain";

	ASSERT(dp->d_ref == 0);

	idx = hash_domain(dp->d_domainid);

	if (dp->d_prev == NULL)
		amd_iommu_domain_table[idx] = dp->d_next;
	else
		dp->d_prev->d_next = dp->d_next;

	if (dp->d_next)
		dp->d_next->d_prev = dp->d_prev;

	if (dp->d_vmem != NULL) {
		vmem_destroy(dp->d_vmem);
		dp->d_vmem = NULL;
	}

	kmem_free(dp, sizeof (*dp));

	cmdargs.ca_domainid = (uint16_t)domainid;
	cmdargs.ca_addr = (uintptr_t)0x7FFFFFFFFFFFF000;
	flags = AMD_IOMMU_CMD_FLAGS_PAGE_PDE_INVAL |
	    AMD_IOMMU_CMD_FLAGS_PAGE_INVAL_S;

	if (amd_iommu_cmd(iommu, AMD_IOMMU_CMD_INVAL_IOMMU_PAGES,
	    &cmdargs, flags, 0) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: idx=%d: domainid=%d"
		    "Failed to invalidate domain in IOMMU HW cache",
		    f, iommu->aiomt_idx, cmdargs.ca_domainid);
	}
}

static int
amd_iommu_get_deviceid(amd_iommu_t *iommu, dev_info_t *rdip, int32_t *deviceid,
    int *aliasp, const char *path)
{
	int bus = -1;
	int device = -1;
	int func = -1;
	uint16_t bdf;
	int32_t src_bdf;
	dev_info_t *idip = iommu->aiomt_dip;
	const char *driver = ddi_driver_name(idip);
	int instance = ddi_get_instance(idip);
	dev_info_t *pci_dip;
	const char *f = "amd_iommu_get_deviceid";

	/* be conservative. Always assume an alias */
	*aliasp = 1;
	*deviceid = 0;

	/* Check for special special devices (rdip == NULL) */
	if (rdip == NULL) {
		if (amd_iommu_get_src_bdf(iommu, -1, &src_bdf) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "%s: %s%d: idx=%d, failed to get SRC BDF "
			    "for special-device",
			    f, driver, instance, iommu->aiomt_idx);
			return (DDI_DMA_NOMAPPING);
		}
		*deviceid = src_bdf;
		*aliasp = 1;
		return (DDI_SUCCESS);
	}

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_DEVTBL) {
		cmn_err(CE_NOTE, "%s: attempting to get deviceid for %s",
		    f, path);
	}

	pci_dip = amd_iommu_pci_dip(rdip, path);
	if (pci_dip == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: idx = %d, failed to get PCI dip "
		    "for rdip=%p, path = %s",
		    f, driver, instance, iommu->aiomt_idx, (void *)rdip,
		    path);
		return (DDI_DMA_NOMAPPING);
	}

	if (acpica_get_bdf(pci_dip, &bus, &device, &func) != DDI_SUCCESS) {
		ndi_rele_devi(pci_dip);
		cmn_err(CE_WARN, "%s: %s%d: idx=%d, failed to get BDF for "
		    "PCI dip (%p). rdip path = %s",
		    f, driver, instance, iommu->aiomt_idx,
		    (void *)pci_dip, path);
		return (DDI_DMA_NOMAPPING);
	}

	ndi_rele_devi(pci_dip);

	if (bus > UINT8_MAX || bus < 0 ||
	    device > UINT8_MAX || device < 0 ||
	    func > UINT8_MAX || func < 0) {
		cmn_err(CE_WARN, "%s: %s%d:  idx=%d, invalid BDF(%d,%d,%d) "
		    "for PCI dip (%p). rdip path = %s", f, driver, instance,
		    iommu->aiomt_idx,
		    bus, device, func,
		    (void *)pci_dip, path);
		return (DDI_DMA_NOMAPPING);
	}

	bdf = ((uint8_t)bus << 8) | ((uint8_t)device << 3) | (uint8_t)func;

	if (amd_iommu_get_src_bdf(iommu, bdf, &src_bdf) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d, failed to get SRC BDF "
		    "for PCI dip (%p) rdip path = %s.",
		    f, driver, instance, iommu->aiomt_idx, (void *)pci_dip,
		    path);
		return (DDI_DMA_NOMAPPING);
	}

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_DEVTBL) {
		cmn_err(CE_NOTE, "%s: Deviceid = %u for path = %s",
		    f, src_bdf, path);
	}

	*deviceid = src_bdf;
	*aliasp = (src_bdf != bdf);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
init_devtbl(amd_iommu_t *iommu, uint64_t *devtbl_entry, domain_id_t domainid,
    amd_iommu_domain_t *dp)
{
	uint64_t entry[4] = {0};
	int i;

	/* If already passthru, don't touch */
	if (AMD_IOMMU_REG_GET64(&(devtbl_entry[0]), AMD_IOMMU_DEVTBL_V) == 0 &&
	    AMD_IOMMU_REG_GET64(&(devtbl_entry[0]), AMD_IOMMU_DEVTBL_TV) == 0) {
		return (0);
	}

	if (AMD_IOMMU_REG_GET64(&(devtbl_entry[0]), AMD_IOMMU_DEVTBL_V) == 1 &&
	    AMD_IOMMU_REG_GET64(&(devtbl_entry[0]), AMD_IOMMU_DEVTBL_TV) == 1) {

		ASSERT(dp->d_pgtable_root_4K ==
		    AMD_IOMMU_REG_GET64(&(devtbl_entry[0]),
		    AMD_IOMMU_DEVTBL_ROOT_PGTBL));

		ASSERT(dp->d_domainid == AMD_IOMMU_REG_GET64(&(devtbl_entry[1]),
		    AMD_IOMMU_DEVTBL_DOMAINID));

		return (0);
	}

	/* New devtbl entry for this domain. Bump up the domain ref-count */
	dp->d_ref++;

	entry[3] = 0;
	entry[2] = 0;
	AMD_IOMMU_REG_SET64(&(entry[1]), AMD_IOMMU_DEVTBL_EX, 1);
	AMD_IOMMU_REG_SET64(&(entry[1]), AMD_IOMMU_DEVTBL_SD, 0);
	AMD_IOMMU_REG_SET64(&(entry[1]), AMD_IOMMU_DEVTBL_CACHE, 0);
	AMD_IOMMU_REG_SET64(&(entry[1]), AMD_IOMMU_DEVTBL_IOCTL, 1);
	AMD_IOMMU_REG_SET64(&(entry[1]), AMD_IOMMU_DEVTBL_SA, 0);
	AMD_IOMMU_REG_SET64(&(entry[1]), AMD_IOMMU_DEVTBL_SE, 1);
	AMD_IOMMU_REG_SET64(&(entry[1]), AMD_IOMMU_DEVTBL_DOMAINID,
	    (uint16_t)domainid);
	AMD_IOMMU_REG_SET64(&(entry[0]), AMD_IOMMU_DEVTBL_IW, 1);
	AMD_IOMMU_REG_SET64(&(entry[0]), AMD_IOMMU_DEVTBL_IR, 1);
	AMD_IOMMU_REG_SET64(&(entry[0]), AMD_IOMMU_DEVTBL_ROOT_PGTBL,
	    dp->d_pgtable_root_4K);
	AMD_IOMMU_REG_SET64(&(entry[0]), AMD_IOMMU_DEVTBL_PG_MODE,
	    AMD_IOMMU_PGTABLE_MAXLEVEL);
	AMD_IOMMU_REG_SET64(&(entry[0]), AMD_IOMMU_DEVTBL_TV,
	    domainid == AMD_IOMMU_PASSTHRU_DOMAIN ? 0 : 1);
	AMD_IOMMU_REG_SET64(&(entry[0]), AMD_IOMMU_DEVTBL_V,
	    domainid == AMD_IOMMU_PASSTHRU_DOMAIN ? 0 : 1);

	for (i = 1; i < 4; i++) {
		devtbl_entry[i] = entry[i];
	}
	devtbl_entry[0] = entry[0];

	/* we did an actual init */
	return (1);
}

void
amd_iommu_set_passthru(amd_iommu_t *iommu, dev_info_t *rdip)
{
	int32_t deviceid;
	int alias;
	uint64_t *devtbl_entry;
	amd_iommu_cmdargs_t cmdargs = {0};
	char *path;
	int pathfree;
	int V;
	int TV;
	int instance;
	const char *driver;
	const char *f = "amd_iommu_set_passthru";

	if (rdip) {
		driver = ddi_driver_name(rdip);
		instance = ddi_get_instance(rdip);
	} else {
		driver = "special-device";
		instance = 0;
	}

	path = kmem_alloc(MAXPATHLEN, KM_NOSLEEP);
	if (path) {
		if (rdip)
			(void) ddi_pathname(rdip, path);
		else
			(void) strcpy(path, "special-device");
		pathfree = 1;
	} else {
		pathfree = 0;
		path = "<path-mem-alloc-failed>";
	}

	if (amd_iommu_get_deviceid(iommu, rdip, &deviceid, &alias, path)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d: rdip=%p. "
		    "Failed to get device ID for device %s.", f, driver,
		    instance,
		    iommu->aiomt_idx, (void *)rdip, path);
		goto out;
	}

	/* No deviceid */
	if (deviceid == -1) {
		goto out;
	}

	if ((deviceid + 1) * AMD_IOMMU_DEVTBL_ENTRY_SZ >
	    iommu->aiomt_devtbl_sz) {
		cmn_err(CE_WARN, "%s: %s%d: IOMMU idx=%d, deviceid (%u) "
		    "for rdip (%p) exceeds device table size (%u), path=%s",
		    f, driver,
		    instance, iommu->aiomt_idx, deviceid, (void *)rdip,
		    iommu->aiomt_devtbl_sz, path);
		goto out;
	}

	/*LINTED*/
	devtbl_entry = (uint64_t *)&iommu->aiomt_devtbl
	    [deviceid * AMD_IOMMU_DEVTBL_ENTRY_SZ];

	V = AMD_IOMMU_REG_GET64(&(devtbl_entry[0]), AMD_IOMMU_DEVTBL_V);
	TV = AMD_IOMMU_REG_GET64(&(devtbl_entry[0]), AMD_IOMMU_DEVTBL_TV);

	/* Already passthru */
	if (V == 0 && TV == 0) {
		goto out;
	}

	/* Existing translations */
	if (V == 1 && TV == 1) {
		goto out;
	}

	/* Invalid setting */
	if (V == 0 && TV == 1) {
		goto out;
	}

	AMD_IOMMU_REG_SET64(&(devtbl_entry[0]), AMD_IOMMU_DEVTBL_V, 0);

	cmdargs.ca_deviceid = (uint16_t)deviceid;
	(void) amd_iommu_cmd(iommu, AMD_IOMMU_CMD_INVAL_DEVTAB_ENTRY,
	    &cmdargs, 0, 0);

out:
	if (pathfree)
		kmem_free(path, MAXPATHLEN);
}

static int
amd_iommu_set_devtbl_entry(amd_iommu_t *iommu, dev_info_t *rdip,
    domain_id_t domainid, uint16_t deviceid, amd_iommu_domain_t *dp,
    const char *path)
{
	uint64_t *devtbl_entry;
	amd_iommu_cmdargs_t cmdargs = {0};
	int error, flags;
	dev_info_t *idip = iommu->aiomt_dip;
	const char *driver = ddi_driver_name(idip);
	int instance = ddi_get_instance(idip);
	const char *f = "amd_iommu_set_devtbl_entry";

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_DEVTBL) {
		cmn_err(CE_NOTE, "%s: attempting to set devtbl entry for %s",
		    f, path);
	}

	if ((deviceid + 1) * AMD_IOMMU_DEVTBL_ENTRY_SZ >
	    iommu->aiomt_devtbl_sz) {
		cmn_err(CE_WARN, "%s: %s%d: IOMMU idx=%d, deviceid (%u) "
		    "for rdip (%p) exceeds device table size (%u), path=%s",
		    f, driver,
		    instance, iommu->aiomt_idx, deviceid, (void *)rdip,
		    iommu->aiomt_devtbl_sz, path);
		return (DDI_DMA_NOMAPPING);
	}

	/*LINTED*/
	devtbl_entry = (uint64_t *)&iommu->aiomt_devtbl
	    [deviceid * AMD_IOMMU_DEVTBL_ENTRY_SZ];

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_DEVTBL) {
		cmn_err(CE_NOTE, "%s: deviceid=%u devtbl entry (%p) for %s",
		    f, deviceid, (void *)(uintptr_t)(*devtbl_entry), path);
	}

	/*
	 * Flush internal caches, need to do this if we came up from
	 * fast boot
	 */
	cmdargs.ca_deviceid = deviceid;
	error = amd_iommu_cmd(iommu, AMD_IOMMU_CMD_INVAL_DEVTAB_ENTRY,
	    &cmdargs, 0, 0);
	if (error != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: idx=%d: deviceid=%d"
		    "Failed to invalidate domain in IOMMU HW cache",
		    f, iommu->aiomt_idx, deviceid);
		return (error);
	}

	cmdargs.ca_domainid = (uint16_t)domainid;
	cmdargs.ca_addr = (uintptr_t)0x7FFFFFFFFFFFF000;
	flags = AMD_IOMMU_CMD_FLAGS_PAGE_PDE_INVAL |
	    AMD_IOMMU_CMD_FLAGS_PAGE_INVAL_S;

	error = amd_iommu_cmd(iommu, AMD_IOMMU_CMD_INVAL_IOMMU_PAGES,
	    &cmdargs, flags, 0);
	if (error != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: idx=%d: domainid=%d"
		    "Failed to invalidate translations in IOMMU HW cache",
		    f, iommu->aiomt_idx, cmdargs.ca_domainid);
		return (error);
	}

	/* Initialize device table entry */
	if (init_devtbl(iommu, devtbl_entry, domainid, dp)) {
		cmdargs.ca_deviceid = deviceid;
		error = amd_iommu_cmd(iommu, AMD_IOMMU_CMD_INVAL_DEVTAB_ENTRY,
		    &cmdargs, 0, 0);
	}

	return (error);
}

int
amd_iommu_clear_devtbl_entry(amd_iommu_t *iommu, dev_info_t *rdip,
    domain_id_t domainid, uint16_t deviceid, amd_iommu_domain_t *dp,
    int *domain_freed, char *path)
{
	uint64_t *devtbl_entry;
	int error = DDI_SUCCESS;
	amd_iommu_cmdargs_t cmdargs = {0};
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	const char *f = "amd_iommu_clear_devtbl_entry";

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_DEVTBL) {
		cmn_err(CE_NOTE, "%s: attempting to clear devtbl entry for "
		    "domainid = %d, deviceid = %u, path = %s",
		    f, domainid, deviceid, path);
	}

	if ((deviceid + 1) * AMD_IOMMU_DEVTBL_ENTRY_SZ >
	    iommu->aiomt_devtbl_sz) {
		cmn_err(CE_WARN, "%s: %s%d: IOMMU idx=%d, deviceid (%u) "
		    "for rdip (%p) exceeds device table size (%u), path = %s",
		    f, driver, instance,
		    iommu->aiomt_idx, deviceid, (void *)rdip,
		    iommu->aiomt_devtbl_sz, path);
		return (DDI_FAILURE);
	}

	/*LINTED*/
	devtbl_entry = (uint64_t *)&iommu->aiomt_devtbl
	    [deviceid * AMD_IOMMU_DEVTBL_ENTRY_SZ];

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_DEVTBL) {
		cmn_err(CE_NOTE, "%s: deviceid=%u devtbl entry (%p) for %s",
		    f, deviceid, (void *)(uintptr_t)(*devtbl_entry), path);
	}

	if (AMD_IOMMU_REG_GET64(&(devtbl_entry[0]), AMD_IOMMU_DEVTBL_TV) == 0) {
		/* Nothing to do */
		return (DDI_SUCCESS);
	}

	ASSERT(dp->d_pgtable_root_4K == AMD_IOMMU_REG_GET64(&(devtbl_entry[0]),
	    AMD_IOMMU_DEVTBL_ROOT_PGTBL));

	ASSERT(domainid == AMD_IOMMU_REG_GET64(&(devtbl_entry[1]),
	    AMD_IOMMU_DEVTBL_DOMAINID));

	AMD_IOMMU_REG_SET64(&(devtbl_entry[0]), AMD_IOMMU_DEVTBL_TV, 0);
	AMD_IOMMU_REG_SET64(&(devtbl_entry[0]), AMD_IOMMU_DEVTBL_ROOT_PGTBL, 0);
	AMD_IOMMU_REG_SET64(&(devtbl_entry[0]), AMD_IOMMU_DEVTBL_V, 1);

	SYNC_FORDEV(iommu->aiomt_dmahdl);

	dp->d_ref--;
	ASSERT(dp->d_ref >= 0);

	if (dp->d_ref == 0) {
		*domain_freed = 1;
	}

	cmdargs.ca_deviceid = deviceid;
	error = amd_iommu_cmd(iommu, AMD_IOMMU_CMD_INVAL_DEVTAB_ENTRY,
	    &cmdargs, 0, 0);
	if (error != DDI_SUCCESS)
		error = DDI_FAILURE;

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

	ASSERT((pt->pt_cookie.dmac_cookie_addr & AMD_IOMMU_PGTABLE_ALIGN) == 0);

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

	ASSERT((pt->pt_cookie.dmac_cookie_addr & AMD_IOMMU_PGTABLE_ALIGN) == 0);

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
amd_iommu_lookup_pgtable_hash(domain_id_t domainid, uint64_t pgtable_pa_4K)
{
	amd_iommu_page_table_t *pt;
	uint32_t idx = pt_hashfn(pgtable_pa_4K);

	mutex_enter(&amd_iommu_page_table_hash.ampt_lock);
	pt = amd_iommu_page_table_hash.ampt_hash[idx];
	for (; pt; pt = pt->pt_next) {
		if (domainid != pt->pt_domainid)
			continue;
		ASSERT((pt->pt_cookie.dmac_cookie_addr &
		    AMD_IOMMU_PGTABLE_ALIGN) == 0);
		if ((pt->pt_cookie.dmac_cookie_addr >> 12) == pgtable_pa_4K) {
			break;
		}
	}
	mutex_exit(&amd_iommu_page_table_hash.ampt_lock);

	return (pt);
}

/*ARGSUSED*/
static amd_iommu_page_table_t *
amd_iommu_lookup_pgtable(amd_iommu_t *iommu, amd_iommu_page_table_t *ppt,
    amd_iommu_domain_t *dp, int level, uint16_t index)
{
	uint64_t *pdtep;
	uint64_t pgtable_pa_4K;

	ASSERT(level > 0 && level <= AMD_IOMMU_PGTABLE_MAXLEVEL);
	ASSERT(dp);

	if (level == AMD_IOMMU_PGTABLE_MAXLEVEL) {
		ASSERT(ppt == NULL);
		ASSERT(index == 0);
		pgtable_pa_4K = dp->d_pgtable_root_4K;
	} else {
		ASSERT(ppt);
		pdtep = &(ppt->pt_pgtblva[index]);
		if (AMD_IOMMU_REG_GET64(pdtep, AMD_IOMMU_PTDE_PR) == 0) {
			if (amd_iommu_debug & AMD_IOMMU_DEBUG_PAGE_TABLES) {
				cmn_err(CE_NOTE, "Skipping PR=0 pdte: 0x%"
				    PRIx64, *pdtep);
			}
			return (NULL);
		}
		pgtable_pa_4K = AMD_IOMMU_REG_GET64(pdtep, AMD_IOMMU_PTDE_ADDR);
	}

	return (amd_iommu_lookup_pgtable_hash(dp->d_domainid, pgtable_pa_4K));
}

static amd_iommu_page_table_t *
amd_iommu_alloc_from_freelist(void)
{
	int i;
	uint64_t *pte_array;
	amd_iommu_page_table_t *pt;

	if (amd_iommu_no_pgtable_freelist == 1)
		return (NULL);

	if (amd_iommu_pgtable_freelist.f_count == 0)
		return (NULL);

	pt = amd_iommu_pgtable_freelist.f_list;
	amd_iommu_pgtable_freelist.f_list = pt->pt_next;
	amd_iommu_pgtable_freelist.f_count--;

	pte_array = pt->pt_pgtblva;
	for (i = 0; i < AMD_IOMMU_PGTABLE_SZ / (sizeof (*pte_array)); i++) {
		ASSERT(pt->pt_pte_ref[i] == 0);
		ASSERT(AMD_IOMMU_REG_GET64(&(pte_array[i]),
		    AMD_IOMMU_PTDE_PR)  == 0);
	}

	return (pt);
}

static int
amd_iommu_alloc_pgtable(amd_iommu_t *iommu, domain_id_t domainid,
    const char *path, amd_iommu_page_table_t **ptp, int km_flags)
{
	int err;
	uint_t ncookies;
	amd_iommu_page_table_t *pt;
	dev_info_t *idip = iommu->aiomt_dip;
	const char *driver = ddi_driver_name(idip);
	int instance = ddi_get_instance(idip);
	const char *f = "amd_iommu_alloc_pgtable";

	*ptp = NULL;

	pt = amd_iommu_alloc_from_freelist();
	if (pt)
		goto init_pgtable;

	pt = kmem_zalloc(sizeof (amd_iommu_page_table_t), km_flags);
	if (pt == NULL)
		return (DDI_DMA_NORESOURCES);

	/*
	 * Each page table is 4K in size
	 */
	pt->pt_mem_reqsz = AMD_IOMMU_PGTABLE_SZ;

	/*
	 * Alloc a DMA handle. Use the IOMMU dip as we want this DMA
	 * to *not* enter the IOMMU - no recursive entrance.
	 */
	err = ddi_dma_alloc_handle(idip, &amd_iommu_pgtable_dma_attr,
	    km_flags == KM_SLEEP ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT,
	    NULL, &pt->pt_dma_hdl);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: domainid = %d, path = %s. "
		    "Cannot alloc DMA handle for IO Page Table",
		    f, driver, instance, domainid, path);
		kmem_free(pt, sizeof (amd_iommu_page_table_t));
		return (err == DDI_DMA_NORESOURCES ? err : DDI_DMA_NOMAPPING);
	}

	/*
	 * Alloc memory for IO Page Table.
	 * XXX remove size_t cast kludge
	 */
	err = ddi_dma_mem_alloc(pt->pt_dma_hdl, pt->pt_mem_reqsz,
	    &amd_iommu_devacc, DDI_DMA_CONSISTENT|IOMEM_DATA_UNCACHED,
	    km_flags == KM_SLEEP ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT,
	    NULL, (caddr_t *)&pt->pt_pgtblva,
	    (size_t *)&pt->pt_mem_realsz, &pt->pt_mem_hdl);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: domainid=%d, path = %s. "
		    "Cannot allocate DMA memory for IO Page table",
		    f, driver, instance, domainid, path);
		ddi_dma_free_handle(&pt->pt_dma_hdl);
		kmem_free(pt, sizeof (amd_iommu_page_table_t));
		return (DDI_DMA_NORESOURCES);
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
	    DDI_DMA_READ | DDI_DMA_CONSISTENT,
	    km_flags == KM_SLEEP ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT,
	    NULL, &pt->pt_cookie, &ncookies);
	if (err != DDI_DMA_MAPPED) {
		cmn_err(CE_WARN, "%s: %s%d: domainid=%d, path = %s. "
		    "Cannot bind memory for DMA to IO Page Tables. "
		    "bufrealsz=%p",
		    f, driver, instance, domainid, path,
		    (void *)(uintptr_t)pt->pt_mem_realsz);
		ddi_dma_mem_free(&pt->pt_mem_hdl);
		ddi_dma_free_handle(&pt->pt_dma_hdl);
		kmem_free(pt, sizeof (amd_iommu_page_table_t));
		return (err == DDI_DMA_PARTIAL_MAP ? DDI_DMA_NOMAPPING :
		    err);
	}

	/*
	 * We assume the DMA engine on the IOMMU is capable of handling the
	 * whole page table in a single cookie. If not and multiple cookies
	 * are needed we fail.
	 */
	if (ncookies != 1) {
		cmn_err(CE_WARN, "%s: %s%d: domainid = %d, path=%s "
		    "Cannot handle multiple "
		    "cookies for DMA to IO page Table, #cookies=%u",
		    f, driver, instance, domainid, path, ncookies);
		(void) ddi_dma_unbind_handle(pt->pt_dma_hdl);
		ddi_dma_mem_free(&pt->pt_mem_hdl);
		ddi_dma_free_handle(&pt->pt_dma_hdl);
		kmem_free(pt, sizeof (amd_iommu_page_table_t));
		return (DDI_DMA_NOMAPPING);
	}

init_pgtable:
	/*
	 * The address in the cookie must be 4K aligned and >= table size
	 */
	ASSERT(pt->pt_cookie.dmac_cookie_addr != (uintptr_t)NULL);
	ASSERT((pt->pt_cookie.dmac_cookie_addr & AMD_IOMMU_PGTABLE_ALIGN) == 0);
	ASSERT(pt->pt_cookie.dmac_size >= pt->pt_mem_realsz);
	ASSERT(pt->pt_cookie.dmac_size >= pt->pt_mem_reqsz);
	ASSERT(pt->pt_mem_reqsz >= AMD_IOMMU_PGTABLE_SIZE);
	ASSERT(pt->pt_mem_realsz >= pt->pt_mem_reqsz);
	ASSERT(pt->pt_pgtblva);

	pt->pt_domainid = AMD_IOMMU_INVALID_DOMAIN;
	pt->pt_level = 0x7;
	pt->pt_index = 0;
	pt->pt_ref = 0;
	pt->pt_next = NULL;
	pt->pt_prev = NULL;
	pt->pt_parent = NULL;

	bzero(pt->pt_pgtblva, pt->pt_mem_realsz);
	SYNC_FORDEV(pt->pt_dma_hdl);

	amd_iommu_insert_pgtable_hash(pt);

	*ptp = pt;

	return (DDI_SUCCESS);
}

static int
amd_iommu_move_to_freelist(amd_iommu_page_table_t *pt)
{
	if (amd_iommu_no_pgtable_freelist == 1)
		return (DDI_FAILURE);

	if (amd_iommu_pgtable_freelist.f_count ==
	    AMD_IOMMU_PGTABLE_FREELIST_MAX)
		return (DDI_FAILURE);

	pt->pt_next = amd_iommu_pgtable_freelist.f_list;
	amd_iommu_pgtable_freelist.f_list = pt;
	amd_iommu_pgtable_freelist.f_count++;

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

	ASSERT(pt->pt_ref == 0);

	amd_iommu_remove_pgtable_hash(pt);

	pte_array = pt->pt_pgtblva;
	for (i = 0; i < AMD_IOMMU_PGTABLE_SZ / (sizeof (*pte_array)); i++) {
		ASSERT(pt->pt_pte_ref[i] == 0);
		ASSERT(AMD_IOMMU_REG_GET64(&(pte_array[i]),
		    AMD_IOMMU_PTDE_PR)  == 0);
	}

	if (amd_iommu_move_to_freelist(pt) == DDI_SUCCESS)
		return;

	/* Unbind the handle */
	if (ddi_dma_unbind_handle(pt->pt_dma_hdl) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d, domainid=%d. "
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
	uint64_t *pdep = &(ppt->pt_pgtblva[pt->pt_index]);
	uint64_t next_pgtable_pa_4K = (pt->pt_cookie.dmac_cookie_addr) >> 12;

	/* nothing to set. PDE is already set */
	if (AMD_IOMMU_REG_GET64(pdep, AMD_IOMMU_PTDE_PR) == 1) {
		ASSERT(PT_REF_VALID(ppt));
		ASSERT(PT_REF_VALID(pt));
		ASSERT(ppt->pt_pte_ref[pt->pt_index] == 0);
		ASSERT(AMD_IOMMU_REG_GET64(pdep, AMD_IOMMU_PTDE_ADDR)
		    == next_pgtable_pa_4K);
		return (DDI_SUCCESS);
	}

	ppt->pt_ref++;
	ASSERT(PT_REF_VALID(ppt));

	/* Page Directories are always RW */
	AMD_IOMMU_REG_SET64(pdep, AMD_IOMMU_PTDE_IW, 1);
	AMD_IOMMU_REG_SET64(pdep, AMD_IOMMU_PTDE_IR, 1);
	AMD_IOMMU_REG_SET64(pdep, AMD_IOMMU_PTDE_ADDR,
	    next_pgtable_pa_4K);
	pt->pt_parent = ppt;
	AMD_IOMMU_REG_SET64(pdep, AMD_IOMMU_PTDE_NXT_LVL,
	    pt->pt_level);
	ppt->pt_pte_ref[pt->pt_index] = 0;
	AMD_IOMMU_REG_SET64(pdep, AMD_IOMMU_PTDE_PR, 1);
	SYNC_FORDEV(ppt->pt_dma_hdl);
	ASSERT(AMD_IOMMU_REG_GET64(pdep, AMD_IOMMU_PTDE_PR) == 1);

	return (DDI_SUCCESS);
}

static int
init_pte(amd_iommu_page_table_t *pt, uint64_t pa, uint16_t index,
    struct ddi_dma_req *dmareq)
{
	uint64_t *ptep = &(pt->pt_pgtblva[index]);
	uint64_t pa_4K = pa >> 12;
	int R;
	int W;

	/* nothing to set if PTE is already set */
	if (AMD_IOMMU_REG_GET64(ptep, AMD_IOMMU_PTDE_PR) == 1) {
		/*
		 * Adjust current permissions
		 * DDI_DMA_WRITE means direction of DMA is MEM -> I/O
		 * so that requires Memory READ permissions i.e. sense
		 * is inverted.
		 * Note: either or both of DD_DMA_READ/WRITE may be set
		 */
		if (amd_iommu_no_RW_perms == 0) {
			R = AMD_IOMMU_REG_GET64(ptep, AMD_IOMMU_PTDE_IR);
			W = AMD_IOMMU_REG_GET64(ptep, AMD_IOMMU_PTDE_IW);
			if (R == 0 && ((dmareq->dmar_flags & DDI_DMA_WRITE) ||
			    (dmareq->dmar_flags & DDI_DMA_RDWR))) {
				AMD_IOMMU_REG_SET64(ptep, AMD_IOMMU_PTDE_IR, 1);
			}
			if (W  == 0 && ((dmareq->dmar_flags & DDI_DMA_READ) ||
			    (dmareq->dmar_flags & DDI_DMA_RDWR))) {
				AMD_IOMMU_REG_SET64(ptep, AMD_IOMMU_PTDE_IW, 1);
			}
		}
		ASSERT(PT_REF_VALID(pt));
		pt->pt_pte_ref[index]++;
		ASSERT(AMD_IOMMU_REG_GET64(ptep, AMD_IOMMU_PTDE_ADDR)
		    == pa_4K);
		return (DDI_SUCCESS);
	}

	pt->pt_ref++;
	ASSERT(PT_REF_VALID(pt));

	/* see comment above about inverting sense of RD/WR */
	if (amd_iommu_no_RW_perms == 0) {
		AMD_IOMMU_REG_SET64(ptep, AMD_IOMMU_PTDE_IR, 0);
		AMD_IOMMU_REG_SET64(ptep, AMD_IOMMU_PTDE_IW, 0);
		if (dmareq->dmar_flags & DDI_DMA_RDWR) {
			AMD_IOMMU_REG_SET64(ptep, AMD_IOMMU_PTDE_IW, 1);
			AMD_IOMMU_REG_SET64(ptep, AMD_IOMMU_PTDE_IR, 1);
		} else {
			if (dmareq->dmar_flags & DDI_DMA_WRITE) {
				AMD_IOMMU_REG_SET64(ptep, AMD_IOMMU_PTDE_IR, 1);
			}
			if (dmareq->dmar_flags & DDI_DMA_READ) {
				AMD_IOMMU_REG_SET64(ptep, AMD_IOMMU_PTDE_IW, 1);
			}
		}
	} else {
		AMD_IOMMU_REG_SET64(ptep, AMD_IOMMU_PTDE_IR, 1);
		AMD_IOMMU_REG_SET64(ptep, AMD_IOMMU_PTDE_IW, 1);
	}

	/* TODO what is correct for FC and U */
	AMD_IOMMU_REG_SET64(ptep, AMD_IOMMU_PTE_FC, 0);
	AMD_IOMMU_REG_SET64(ptep, AMD_IOMMU_PTE_U, 0);
	AMD_IOMMU_REG_SET64(ptep, AMD_IOMMU_PTDE_ADDR, pa_4K);
	AMD_IOMMU_REG_SET64(ptep, AMD_IOMMU_PTDE_NXT_LVL, 0);
	ASSERT(pt->pt_pte_ref[index] == 0);
	pt->pt_pte_ref[index] = 1;
	AMD_IOMMU_REG_SET64(ptep, AMD_IOMMU_PTDE_PR, 1);
	SYNC_FORDEV(pt->pt_dma_hdl);
	ASSERT(AMD_IOMMU_REG_GET64(ptep, AMD_IOMMU_PTDE_PR) == 1);

	return (DDI_SUCCESS);
}


static void
init_pt(amd_iommu_page_table_t *pt, amd_iommu_domain_t *dp,
    int level, uint16_t index)
{
	ASSERT(dp);

	if (level == AMD_IOMMU_PGTABLE_MAXLEVEL) {
		dp->d_pgtable_root_4K = (pt->pt_cookie.dmac_cookie_addr) >> 12;
	} else {
		ASSERT(level >= 1 && level < AMD_IOMMU_PGTABLE_MAXLEVEL);
	}

	pt->pt_domainid = dp->d_domainid;
	pt->pt_level = level;
	pt->pt_index = index;
}

static int
amd_iommu_setup_1_pgtable(amd_iommu_t *iommu, dev_info_t *rdip,
    struct ddi_dma_req *dmareq,
    domain_id_t domainid, amd_iommu_domain_t *dp,
    amd_iommu_page_table_t *ppt,
    uint16_t index, int level, uint64_t va, uint64_t pa,
    amd_iommu_page_table_t **ptp,  uint16_t *next_idxp, const char *path,
    int km_flags)
{
	int error;
	amd_iommu_page_table_t *pt;
	const char *driver = ddi_driver_name(rdip);
	int instance = ddi_get_instance(rdip);
	const char *f = "amd_iommu_setup_1_pgtable";

	*ptp = NULL;
	*next_idxp = 0;
	error = DDI_SUCCESS;

	ASSERT(level > 0 && level <= AMD_IOMMU_PGTABLE_MAXLEVEL);

	ASSERT(dp);
	if (level == AMD_IOMMU_PGTABLE_MAXLEVEL) {
		ASSERT(ppt == NULL);
		ASSERT(index == 0);
	} else {
		ASSERT(ppt);
	}

	/* Check if page table is already allocated */
	if (pt = amd_iommu_lookup_pgtable(iommu, ppt, dp, level, index)) {
		ASSERT(pt->pt_domainid == domainid);
		ASSERT(pt->pt_level == level);
		ASSERT(pt->pt_index == index);
		goto out;
	}

	if ((error = amd_iommu_alloc_pgtable(iommu, domainid, path, &pt,
	    km_flags)) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: idx = %u, domainid = %d, va = %p "
		    "path = %s", f, driver, instance, iommu->aiomt_idx,
		    domainid, (void *)(uintptr_t)va, path);
		return (error);
	}

	ASSERT(dp->d_domainid == domainid);

	init_pt(pt, dp, level, index);

out:
	if (level != AMD_IOMMU_PGTABLE_MAXLEVEL) {
		error = init_pde(ppt, pt);
	}

	if (level == 1) {
		ASSERT(error == DDI_SUCCESS);
		error = init_pte(pt, pa, AMD_IOMMU_VA_BITS(va, level), dmareq);
	} else {
		*next_idxp = AMD_IOMMU_VA_BITS(va, level);
		*ptp = pt;
	}

	return (error);
}

typedef enum {
	PDTE_NOT_TORN = 0x1,
	PDTE_TORN_DOWN = 0x2,
	PGTABLE_TORN_DOWN = 0x4
} pdte_tear_t;

static pdte_tear_t
amd_iommu_teardown_pdte(amd_iommu_t *iommu,
    amd_iommu_page_table_t *pt, int index)
{
	uint8_t next_level;
	pdte_tear_t retval;
	uint64_t *ptdep = &(pt->pt_pgtblva[index]);

	next_level = AMD_IOMMU_REG_GET64(ptdep,
	    AMD_IOMMU_PTDE_NXT_LVL);

	if (AMD_IOMMU_REG_GET64(ptdep, AMD_IOMMU_PTDE_PR) == 1) {
		if (pt->pt_level == 1) {
			ASSERT(next_level == 0);
			/* PTE */
			pt->pt_pte_ref[index]--;
			if (pt->pt_pte_ref[index] != 0) {
				return (PDTE_NOT_TORN);
			}
		} else {
			ASSERT(next_level != 0 && next_level != 7);
		}
		ASSERT(pt->pt_pte_ref[index] == 0);
		ASSERT(PT_REF_VALID(pt));

		AMD_IOMMU_REG_SET64(ptdep, AMD_IOMMU_PTDE_PR, 0);
		SYNC_FORDEV(pt->pt_dma_hdl);
		ASSERT(AMD_IOMMU_REG_GET64(ptdep,
		    AMD_IOMMU_PTDE_PR) == 0);
		pt->pt_ref--;
		ASSERT(PT_REF_VALID(pt));
		retval = PDTE_TORN_DOWN;
	} else {
		ASSERT(0);
		ASSERT(pt->pt_pte_ref[index] == 0);
		ASSERT(PT_REF_VALID(pt));
		retval = PDTE_NOT_TORN;
	}

	if (pt->pt_ref == 0) {
		amd_iommu_free_pgtable(iommu, pt);
		return (PGTABLE_TORN_DOWN);
	}

	return (retval);
}

static int
amd_iommu_create_pgtables(amd_iommu_t *iommu, dev_info_t *rdip,
    struct ddi_dma_req *dmareq, uint64_t va,
    uint64_t pa, uint16_t deviceid, domain_id_t domainid,
    amd_iommu_domain_t *dp, const char *path, int km_flags)
{
	int level;
	uint16_t index;
	uint16_t next_idx;
	amd_iommu_page_table_t *pt;
	amd_iommu_page_table_t *ppt;
	int error;
	const char *driver = ddi_driver_name(rdip);
	int instance = ddi_get_instance(rdip);
	const char *f = "amd_iommu_create_pgtables";

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_PAGE_TABLES) {
		cmn_err(CE_NOTE, "%s: %s%d: idx = %u, domainid = %d, "
		    "deviceid = %u, va = %p, pa = %p, path = %s",
		    f, driver, instance,
		    iommu->aiomt_idx, domainid, deviceid,
		    (void *)(uintptr_t)va,
		    (void *)(uintptr_t)pa, path);
	}

	if (domainid == AMD_IOMMU_PASSTHRU_DOMAIN) {
		/* No need for pagetables. Just set up device table entry */
		goto passthru;
	}

	index = 0;
	ppt = NULL;
	for (level = AMD_IOMMU_PGTABLE_MAXLEVEL; level > 0;
	    level--, pt = NULL, next_idx = 0) {
		if ((error = amd_iommu_setup_1_pgtable(iommu, rdip, dmareq,
		    domainid, dp, ppt, index, level, va, pa, &pt,
		    &next_idx, path, km_flags)) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s: %s%d: idx=%d: domainid=%d, "
			    "deviceid=%u, va= %p, pa = %p, Failed to setup "
			    "page table(s) at level = %d, path = %s.",
			    f, driver, instance, iommu->aiomt_idx,
			    domainid, deviceid, (void *)(uintptr_t)va,
			    (void *)(uintptr_t)pa, level, path);
			return (error);
		}

		if (level > 1) {
			ASSERT(pt);
			ASSERT(pt->pt_domainid == domainid);
			ppt = pt;
			index = next_idx;
		} else {
			ASSERT(level == 1);
			ASSERT(pt == NULL);
			ASSERT(next_idx == 0);
			ppt = NULL;
			index = 0;
		}
	}

passthru:
	if ((error = amd_iommu_set_devtbl_entry(iommu, rdip, domainid, deviceid,
	    dp, path)) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d: rdip=%p, deviceid=%u, "
		    "domainid=%d."
		    "Failed to set device table entry for path %s.",
		    f, driver, instance,
		    iommu->aiomt_idx, (void *)rdip, deviceid, domainid, path);
		return (error);
	}

	SYNC_FORDEV(iommu->aiomt_dmahdl);

	return (DDI_SUCCESS);
}

static int
amd_iommu_destroy_pgtables(amd_iommu_t *iommu, dev_info_t *rdip,
    uint64_t pageva, uint16_t deviceid, domain_id_t domainid,
    amd_iommu_domain_t *dp, map_type_t type, int *domain_freed, char *path)
{
	int level;
	int flags;
	amd_iommu_cmdargs_t cmdargs = {0};
	uint16_t index;
	uint16_t prev_index;
	amd_iommu_page_table_t *pt;
	amd_iommu_page_table_t *ppt;
	pdte_tear_t retval;
	int tear_level;
	int invalidate_pte;
	int invalidate_pde;
	int error = DDI_FAILURE;
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	const char *f = "amd_iommu_destroy_pgtables";

	tear_level = -1;
	if (amd_iommu_debug & AMD_IOMMU_DEBUG_PAGE_TABLES) {
		cmn_err(CE_NOTE, "%s: %s%d: idx = %u, domainid = %d, "
		    "deviceid = %u, va = %p, path = %s",
		    f, driver, instance,
		    iommu->aiomt_idx, domainid, deviceid,
		    (void *)(uintptr_t)pageva, path);
	}

	if (domainid == AMD_IOMMU_PASSTHRU_DOMAIN) {
		/*
		 * there are no pagetables for the passthru domain.
		 * Just the device table entry
		 */
		error = DDI_SUCCESS;
		goto passthru;
	}

	ppt = NULL;
	index = 0;
	for (level = AMD_IOMMU_PGTABLE_MAXLEVEL; level > 0; level--) {
		pt = amd_iommu_lookup_pgtable(iommu, ppt, dp, level, index);
		if (pt) {
			ppt = pt;
			index = AMD_IOMMU_VA_BITS(pageva, level);
			continue;
		}
		break;
	}

	if (level == 0) {
		uint64_t *ptep;
		uint64_t pa_4K;

		ASSERT(pt);
		ASSERT(pt == ppt);
		ASSERT(pt->pt_domainid == dp->d_domainid);

		ptep = &(pt->pt_pgtblva[index]);

		pa_4K = AMD_IOMMU_REG_GET64(ptep, AMD_IOMMU_PTDE_ADDR);
		if (amd_iommu_unity_map || type == AMD_IOMMU_UNITY_MAP) {
			ASSERT(pageva == (pa_4K << MMU_PAGESHIFT));
		}
	}

	invalidate_pde = 0;
	invalidate_pte = 0;
	for (++level; level <= AMD_IOMMU_PGTABLE_MAXLEVEL; level++) {
		prev_index = pt->pt_index;
		ppt = pt->pt_parent;
		retval = amd_iommu_teardown_pdte(iommu, pt, index);
		switch (retval) {
			case PDTE_NOT_TORN:
				goto invalidate;
			case PDTE_TORN_DOWN:
				invalidate_pte = 1;
				goto invalidate;
			case PGTABLE_TORN_DOWN:
				invalidate_pte = 1;
				invalidate_pde = 1;
				tear_level = level;
				break;
		}
		index = prev_index;
		pt = ppt;
	}

invalidate:
	/*
	 * Now teardown the IOMMU HW caches if applicable
	 */
	if (invalidate_pte) {
		cmdargs.ca_domainid = (uint16_t)domainid;
		if (amd_iommu_pageva_inval_all) {
			cmdargs.ca_addr = (uintptr_t)0x7FFFFFFFFFFFF000;
			flags = AMD_IOMMU_CMD_FLAGS_PAGE_PDE_INVAL |
			    AMD_IOMMU_CMD_FLAGS_PAGE_INVAL_S;
		} else if (invalidate_pde) {
			cmdargs.ca_addr =
			    (uintptr_t)AMD_IOMMU_VA_INVAL(pageva, tear_level);
			flags = AMD_IOMMU_CMD_FLAGS_PAGE_PDE_INVAL |
			    AMD_IOMMU_CMD_FLAGS_PAGE_INVAL_S;
		} else {
			cmdargs.ca_addr = (uintptr_t)pageva;
			flags = 0;
		}
		if (amd_iommu_cmd(iommu, AMD_IOMMU_CMD_INVAL_IOMMU_PAGES,
		    &cmdargs, flags, 0) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s: %s%d: idx=%d: domainid=%d, "
			    "rdip=%p. Failed to invalidate IOMMU HW cache "
			    "for %s", f, driver, instance,
			    iommu->aiomt_idx, domainid, (void *)rdip, path);
			error = DDI_FAILURE;
			goto out;
		}
	}

passthru:
	if (tear_level == AMD_IOMMU_PGTABLE_MAXLEVEL) {
		error = amd_iommu_clear_devtbl_entry(iommu, rdip, domainid,
		    deviceid, dp, domain_freed, path);
	} else {
		error = DDI_SUCCESS;
	}

out:
	SYNC_FORDEV(iommu->aiomt_dmahdl);

	return (error);
}

static int
cvt_bind_error(int error)
{
	switch (error) {
	case DDI_DMA_MAPPED:
	case DDI_DMA_PARTIAL_MAP:
	case DDI_DMA_NORESOURCES:
	case DDI_DMA_NOMAPPING:
		break;
	default:
		cmn_err(CE_PANIC, "Unsupported error code: %d", error);
		/*NOTREACHED*/
	}
	return (error);
}

int
amd_iommu_map_pa2va(amd_iommu_t *iommu, dev_info_t *rdip, ddi_dma_attr_t *attrp,
    struct ddi_dma_req *dmareq, uint64_t start_pa, uint64_t pa_sz,
    map_type_t type, uint64_t *start_vap, int km_flags)
{
	pfn_t pfn_start;
	pfn_t pfn_end;
	pfn_t pfn;
	int alias;
	int32_t deviceid;
	domain_id_t domainid;
	amd_iommu_domain_t *dp;
	uint64_t end_pa;
	uint64_t start_va;
	uint64_t end_va;
	uint64_t pg_start;
	uint64_t pg_end;
	uint64_t pg;
	uint64_t va_sz;
	char *path;
	int error = DDI_DMA_NOMAPPING;
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	const char *f = "amd_iommu_map_pa2va";

	ASSERT(pa_sz != 0);

	*start_vap = 0;

	ASSERT(rdip);

	path = kmem_alloc(MAXPATHLEN, km_flags);
	if (path == NULL) {
		error = DDI_DMA_NORESOURCES;
		goto out;
	}
	(void) ddi_pathname(rdip, path);

	/*
	 * First get deviceid
	 */
	if (amd_iommu_get_deviceid(iommu, rdip, &deviceid, &alias, path)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d: rdip=%p. "
		    "Failed to get device ID for %s.", f, driver, instance,
		    iommu->aiomt_idx, (void *)rdip, path);
		error = DDI_DMA_NOMAPPING;
		goto out;
	}

	/*
	 * Next get the domain for this rdip
	 */
	if (amd_iommu_get_domain(iommu, rdip, alias, deviceid, &domainid, path)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d: rdip=%p, path=%s. "
		    "Failed to get domain.", f, driver, instance,
		    iommu->aiomt_idx, (void *)rdip, path);
		error = DDI_DMA_NOMAPPING;
		goto out;
	}

	dp = amd_iommu_lookup_domain(iommu, domainid, type, km_flags);
	if (dp == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d: domainid=%d, rdip=%p. "
		    "Failed to get device ID for %s.", f, driver, instance,
		    iommu->aiomt_idx, domainid, (void *)rdip, path);
		error = DDI_DMA_NORESOURCES;
		goto out;
	}

	ASSERT(dp->d_domainid == domainid);

	pfn_start = start_pa >> MMU_PAGESHIFT;

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_PAGE_TABLES) {
		cmn_err(CE_NOTE, "pa = %p, pfn_new = %p, pfn_start = %p, "
		    "pgshift = %d",
		    (void *)(uintptr_t)start_pa,
		    (void *)(uintptr_t)(start_pa >> MMU_PAGESHIFT),
		    (void *)(uintptr_t)pfn_start, MMU_PAGESHIFT);
	}

	end_pa = start_pa + pa_sz - 1;
	pfn_end = end_pa >> MMU_PAGESHIFT;

	if (amd_iommu_unity_map || type == AMD_IOMMU_UNITY_MAP) {
		start_va = start_pa;
		end_va = end_pa;
		va_sz = pa_sz;
		*start_vap = start_va;
	} else {
		va_sz = mmu_ptob(pfn_end - pfn_start + 1);
		start_va = (uintptr_t)vmem_xalloc(dp->d_vmem, va_sz,
		    MAX(attrp->dma_attr_align, MMU_PAGESIZE),
		    0,
		    attrp->dma_attr_seg + 1,
		    (void *)(uintptr_t)attrp->dma_attr_addr_lo,
		    (void *)(uintptr_t)MIN((attrp->dma_attr_addr_hi + 1),
		    AMD_IOMMU_SIZE_4G),	/* XXX rollover */
		    km_flags == KM_SLEEP ? VM_SLEEP : VM_NOSLEEP);
		if (start_va == 0) {
			cmn_err(CE_WARN, "%s: No VA resources",
			    amd_iommu_modname);
			error = DDI_DMA_NORESOURCES;
			goto out;
		}
		ASSERT((start_va & MMU_PAGEOFFSET) == 0);
		end_va = start_va + va_sz - 1;
		*start_vap = start_va + (start_pa & MMU_PAGEOFFSET);
	}

	pg_start = start_va >> MMU_PAGESHIFT;
	pg_end = end_va >> MMU_PAGESHIFT;

	pg = pg_start;
	for (pfn = pfn_start; pfn <= pfn_end; pfn++, pg++) {

		if (amd_iommu_debug & AMD_IOMMU_DEBUG_PAGE_TABLES) {
			cmn_err(CE_NOTE, "%s: attempting to create page tables "
			    "for pfn = %p, va = %p, path = %s",
			    f, (void *)(uintptr_t)(pfn << MMU_PAGESHIFT),
			    (void *)(uintptr_t)(pg << MMU_PAGESHIFT), path);

		}

		if (amd_iommu_unity_map || type == AMD_IOMMU_UNITY_MAP) {
			ASSERT(pfn == pg);
		}

		if ((error = amd_iommu_create_pgtables(iommu, rdip, dmareq,
		    pg << MMU_PAGESHIFT,
		    pfn << MMU_PAGESHIFT, deviceid, domainid, dp, path,
		    km_flags)) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to create_pgtables");
			goto out;
		}

		if (amd_iommu_debug & AMD_IOMMU_DEBUG_PAGE_TABLES) {
			cmn_err(CE_NOTE, "%s: successfully created page tables "
			    "for pfn = %p, vapg = %p, path = %s",
			    f, (void *)(uintptr_t)pfn,
			    (void *)(uintptr_t)pg, path);
		}

	}
	ASSERT(pg == pg_end + 1);


	if (amd_iommu_debug & AMD_IOMMU_DEBUG_PA2VA) {
		cmn_err(CE_NOTE, "pa=%p, va=%p",
		    (void *)(uintptr_t)start_pa,
		    (void *)(uintptr_t)(*start_vap));
	}
	error = DDI_DMA_MAPPED;

out:
	kmem_free(path, MAXPATHLEN);
	return (cvt_bind_error(error));
}

int
amd_iommu_unmap_va(amd_iommu_t *iommu, dev_info_t *rdip, uint64_t start_va,
    uint64_t va_sz, map_type_t type)
{
	uint64_t end_va;
	uint64_t pg_start;
	uint64_t pg_end;
	uint64_t pg;
	uint64_t actual_sz;
	char *path;
	int pathfree;
	int alias;
	int32_t deviceid;
	domain_id_t domainid;
	amd_iommu_domain_t *dp;
	int error;
	int domain_freed;
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	const char *f = "amd_iommu_unmap_va";

	if (amd_iommu_no_unmap)
		return (DDI_SUCCESS);

	path = kmem_alloc(MAXPATHLEN, KM_NOSLEEP);
	if (path) {
		(void) ddi_pathname(rdip, path);
		pathfree = 1;
	} else {
		pathfree = 0;
		path = "<path-mem-alloc-failed>";
	}

	/*
	 * First get deviceid
	 */
	if (amd_iommu_get_deviceid(iommu, rdip, &deviceid, &alias, path)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d: rdip=%p. "
		    "Failed to get device ID for %s.", f, driver, instance,
		    iommu->aiomt_idx, (void *)rdip, path);
		error = DDI_FAILURE;
		goto out;
	}

	/*
	 * Next get the domain for this rdip
	 */
	if (amd_iommu_get_domain(iommu, rdip, alias, deviceid, &domainid, path)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d: rdip=%p, path=%s. "
		    "Failed to get domain.", f, driver, instance,
		    iommu->aiomt_idx, (void *)rdip, path);
		error = DDI_FAILURE;
		goto out;
	}

	/* should never result in domain allocation/vmem_create */
	dp = amd_iommu_lookup_domain(iommu, domainid, AMD_IOMMU_INVALID_MAP,
	    KM_NOSLEEP);
	if (dp == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d: domainid=%d, rdip=%p. "
		    "Failed to get device ID for %s.", f, driver, instance,
		    iommu->aiomt_idx, domainid, (void *)rdip, path);
		error = DDI_FAILURE;
		goto out;
	}

	ASSERT(dp->d_domainid == domainid);

	pg_start = start_va >> MMU_PAGESHIFT;
	end_va = start_va + va_sz - 1;
	pg_end = end_va >> MMU_PAGESHIFT;
	actual_sz = (pg_end - pg_start + 1) << MMU_PAGESHIFT;

	domain_freed = 0;
	for (pg = pg_start; pg <= pg_end; pg++) {
		domain_freed = 0;
		if (amd_iommu_destroy_pgtables(iommu, rdip,
		    pg << MMU_PAGESHIFT, deviceid, domainid, dp, type,
		    &domain_freed, path) != DDI_SUCCESS) {
			error = DDI_FAILURE;
			goto out;
		}
		if (domain_freed) {
			ASSERT(pg == pg_end);
			break;
		}
	}

	/*
	 * vmem_xalloc() must be paired with vmem_xfree
	 */
	if (type == AMD_IOMMU_VMEM_MAP && !amd_iommu_unity_map) {
		vmem_xfree(dp->d_vmem,
		    (void *)(uintptr_t)(pg_start << MMU_PAGESHIFT), actual_sz);
	}

	if (domain_freed)
		amd_iommu_teardown_domain(iommu, dp);

	error = DDI_SUCCESS;
out:
	if (pathfree)
		kmem_free(path, MAXPATHLEN);
	return (error);
}
