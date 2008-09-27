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

#pragma ident	"@(#)iommulib.c	1.6	08/09/07 SMI"

#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/iommulib.h>

/* ******** Type definitions private to this file  ********************** */

/* 1 per IOMMU unit. There may be more than one per dip */
typedef struct iommulib_unit {
	kmutex_t ilu_lock;
	uint64_t ilu_ref;
	uint32_t ilu_unitid;
	dev_info_t *ilu_dip;
	iommulib_ops_t *ilu_ops;
	void* ilu_data;
	struct iommulib_unit *ilu_next;
	struct iommulib_unit *ilu_prev;
} iommulib_unit_t;

typedef struct iommulib_cache {
	dev_info_t *cache_rdip;
	iommulib_unit_t *cache_unit;
	struct iommulib_cache *cache_next;
	struct iommulib_cache *cache_prev;
} iommulib_cache_t;

typedef struct iommulib_nex {
	dev_info_t *nex_dip;
	iommulib_nexops_t nex_ops;
	struct iommulib_nex *nex_next;
	struct iommulib_nex *nex_prev;
} iommulib_nex_t;

/* ********* Function prototypes ********************* */
static int lookup_cache(dev_info_t *rdip, iommulib_unit_t **unitpp);
static void insert_cache(dev_info_t *rdip, iommulib_unit_t *unitp);


/* *********  Globals ************************ */

/* IOMMU side: Following data protected by lock */
static kmutex_t iommulib_lock;
static iommulib_unit_t   *iommulib_list;
static uint64_t iommulib_unit_ids = 0;
static uint64_t iommulib_num_units = 0;

/* rootnex side data */

static kmutex_t iommulib_nexus_lock;
static iommulib_nex_t *iommulib_nexus_list;

#define	IOMMULIB_CACHE_SIZE 256
static kmutex_t iommulib_cache_lock;
static iommulib_cache_t **iommulib_cache;

/* tunable via /etc/system */
static uint_t iommulib_cache_size = IOMMULIB_CACHE_SIZE;

/* can be set atomically without lock */
static volatile uint32_t iommulib_fini;

/* debug flag */
static int iommulib_debug;

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops, "IOMMU library module"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	/*
	 * static mutexes automagically initialized
	 * by being allocated in zeroed memory
	 */
	mutex_enter(&iommulib_cache_lock);
	iommulib_cache = kmem_zalloc(
	    sizeof (iommulib_cache_t *) * iommulib_cache_size, KM_SLEEP);
	mutex_exit(&iommulib_cache_lock);

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	mutex_enter(&iommulib_lock);
	if (iommulib_list != NULL || iommulib_nexus_list != NULL) {
		mutex_exit(&iommulib_lock);
		return (EBUSY);
	}
	iommulib_fini = 1;

	mutex_enter(&iommulib_cache_lock);
	kmem_free(iommulib_cache,
	    sizeof (iommulib_cache_t *) * iommulib_cache_size);
	iommulib_cache = NULL;
	mutex_exit(&iommulib_cache_lock);

	mutex_exit(&iommulib_lock);
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Routines with iommulib_iommu_* are invoked from the
 * IOMMU driver.
 * Routines with iommulib_nex* are invoked from the
 * nexus driver (typically rootnex)
 */

int
iommulib_nexus_register(dev_info_t *dip, iommulib_nexops_t *nexops,
    iommulib_nexhandle_t *handle)
{
	iommulib_nex_t *nexp;
	int instance = ddi_get_instance(dip);
	const char *driver = ddi_driver_name(dip);
	dev_info_t *pdip = ddi_get_parent(dip);
	const char *f = "iommulib_nexus_register";

	ASSERT(nexops);
	ASSERT(handle);

	*handle = NULL;

	/*
	 * Root node is never busy held
	 */
	if (dip != ddi_root_node() && (i_ddi_node_state(dip) < DS_PROBED ||
	    !DEVI_BUSY_OWNED(pdip))) {
		cmn_err(CE_WARN, "%s: NEXUS devinfo node not in DS_PROBED "
		    "or busy held for nexops vector (%p). Failing registration",
		    f, (void *)nexops);
		return (DDI_FAILURE);
	}

	if (nexops->nops_vers != IOMMU_NEXOPS_VERSION) {
		cmn_err(CE_WARN, "%s: %s%d: Invalid IOMMULIB nexops version "
		    "in nexops vector (%p). Failing NEXUS registration",
		    f, driver, instance, (void *)nexops);
		return (DDI_FAILURE);
	}

	ASSERT(nexops->nops_data == NULL);

	if (nexops->nops_id == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL ID field. "
		    "Failing registration for nexops vector: %p",
		    f, driver, instance, (void *)nexops);
		return (DDI_FAILURE);
	}

	if (nexops->nops_dma_allochdl == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL nops_dma_allochdl op. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)nexops);
		return (DDI_FAILURE);
	}

	if (nexops->nops_dma_freehdl == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL nops_dma_freehdl op. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)nexops);
		return (DDI_FAILURE);
	}

	if (nexops->nops_dma_bindhdl == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL nops_dma_bindhdl op. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)nexops);
		return (DDI_FAILURE);
	}

	if (nexops->nops_dma_sync == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL nops_dma_sync op. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)nexops);
		return (DDI_FAILURE);
	}


	if (nexops->nops_dma_reset_cookies == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL nops_dma_reset_cookies op. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)nexops);
		return (DDI_FAILURE);
	}

	if (nexops->nops_dma_get_cookies == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL nops_dma_get_cookies op. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)nexops);
		return (DDI_FAILURE);
	}

	if (nexops->nops_dma_win == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL nops_dma_win op. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)nexops);
		return (DDI_FAILURE);
	}

	/* Check for legacy ops */
	if (nexops->nops_dma_map == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL legacy nops_dma_map op. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)nexops);
		return (DDI_FAILURE);
	}

	if (nexops->nops_dma_mctl == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL legacy nops_dma_mctl op. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)nexops);
		return (DDI_FAILURE);
	}

	nexp = kmem_zalloc(sizeof (iommulib_nex_t), KM_SLEEP);

	mutex_enter(&iommulib_lock);
	if (iommulib_fini == 1) {
		mutex_exit(&iommulib_lock);
		cmn_err(CE_WARN, "%s: IOMMULIB unloading. "
		    "Failing NEXUS register.", f);
		kmem_free(nexp, sizeof (iommulib_nex_t));
		return (DDI_FAILURE);
	}

	/*
	 * fini/register race conditions have been handled. Now create the
	 * nexus struct
	 */
	ndi_hold_devi(dip);
	nexp->nex_dip = dip;
	nexp->nex_ops = *nexops;

	mutex_enter(&iommulib_nexus_lock);
	nexp->nex_next = iommulib_nexus_list;
	iommulib_nexus_list = nexp;
	nexp->nex_prev = NULL;

	if (nexp->nex_next != NULL)
		nexp->nex_next->nex_prev = nexp;

	mutex_exit(&iommulib_nexus_lock);
	mutex_exit(&iommulib_lock);

	cmn_err(CE_NOTE, "!%s: %s%d: Succesfully registered NEXUS %s "
	    "nexops=%p", f, driver, instance, ddi_node_name(dip),
	    (void *)nexops);

	*handle = nexp;

	return (DDI_SUCCESS);
}

int
iommulib_nexus_unregister(iommulib_nexhandle_t handle)
{
	dev_info_t *dip;
	int instance;
	const char *driver;
	iommulib_nex_t *nexp = (iommulib_nex_t *)handle;
	const char *f = "iommulib_nexus_unregister";

	ASSERT(nexp);

	mutex_enter(&iommulib_nexus_lock);

	dip = nexp->nex_dip;
	driver = ddi_driver_name(dip);
	instance = ddi_get_instance(dip);

	/* A future enhancement would be to add ref-counts */

	if (nexp->nex_prev == NULL) {
		iommulib_nexus_list = nexp->nex_next;
	} else {
		nexp->nex_prev->nex_next = nexp->nex_next;
	}

	if (nexp->nex_next != NULL)
		nexp->nex_next->nex_prev = nexp->nex_prev;

	mutex_exit(&iommulib_nexus_lock);

	kmem_free(nexp, sizeof (iommulib_nex_t));

	cmn_err(CE_WARN, "%s: %s%d: NEXUS (%s) handle successfully "
	    "unregistered from IOMMULIB", f, driver, instance,
	    ddi_node_name(dip));

	ndi_rele_devi(dip);

	return (DDI_SUCCESS);
}

static iommulib_nexops_t *
lookup_nexops(dev_info_t *dip)
{
	iommulib_nex_t  *nexp;

	mutex_enter(&iommulib_nexus_lock);
	nexp = iommulib_nexus_list;
	while (nexp) {
		if (nexp->nex_dip == dip)
			break;
		nexp = nexp->nex_next;
	}
	mutex_exit(&iommulib_nexus_lock);

	return (nexp ? &nexp->nex_ops : NULL);
}

int
iommulib_iommu_register(dev_info_t *dip, iommulib_ops_t *ops,
    iommulib_handle_t *handle)
{
	const char *vendor;
	iommulib_unit_t *unitp;
	int instance = ddi_get_instance(dip);
	const char *driver = ddi_driver_name(dip);
	dev_info_t *pdip = ddi_get_parent(dip);
	const char *f = "iommulib_register";

	ASSERT(ops);
	ASSERT(handle);

	if (i_ddi_node_state(dip) < DS_PROBED || !DEVI_BUSY_OWNED(pdip)) {
		cmn_err(CE_WARN, "%s: devinfo node not in DS_PROBED or "
		    "busy held for ops vector (%p). Failing registration",
		    f, (void *)ops);
		return (DDI_FAILURE);
	}


	if (ops->ilops_vers != IOMMU_OPS_VERSION) {
		cmn_err(CE_WARN, "%s: %s%d: Invalid IOMMULIB ops version "
		    "in ops vector (%p). Failing registration", f, driver,
		    instance, (void *)ops);
		return (DDI_FAILURE);
	}

	switch (ops->ilops_vendor) {
	case AMD_IOMMU:
		vendor = "AMD";
		break;
	case INTEL_IOMMU:
		vendor = "Intel";
		break;
	case INVALID_VENDOR:
		cmn_err(CE_WARN, "%s: %s%d: vendor field (%x) not initialized. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, ops->ilops_vendor, (void *)ops);
		return (DDI_FAILURE);
	default:
		cmn_err(CE_WARN, "%s: %s%d: Invalid vendor field (%x). "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, ops->ilops_vendor, (void *)ops);
		return (DDI_FAILURE);
	}

	cmn_err(CE_NOTE, "%s: %s%d: Detected IOMMU registration from vendor %s",
	    f, driver, instance, vendor);

	if (ops->ilops_data == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL IOMMU data field. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)ops);
		return (DDI_FAILURE);
	}

	if (ops->ilops_id == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL ID field. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)ops);
		return (DDI_FAILURE);
	}

	if (ops->ilops_probe == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL probe op. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)ops);
		return (DDI_FAILURE);
	}

	if (ops->ilops_dma_allochdl == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL dma_allochdl op. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)ops);
		return (DDI_FAILURE);
	}

	if (ops->ilops_dma_freehdl == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL dma_freehdl op. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)ops);
		return (DDI_FAILURE);
	}

	if (ops->ilops_dma_bindhdl == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL dma_bindhdl op. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)ops);
		return (DDI_FAILURE);
	}

	if (ops->ilops_dma_sync == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL dma_sync op. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)ops);
		return (DDI_FAILURE);
	}

	if (ops->ilops_dma_win == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL dma_win op. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)ops);
		return (DDI_FAILURE);
	}

	/* Check for legacy ops */
	if (ops->ilops_dma_map == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL legacy dma_map op. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)ops);
		return (DDI_FAILURE);
	}

	if (ops->ilops_dma_mctl == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: NULL legacy dma_mctl op. "
		    "Failing registration for ops vector: %p", f,
		    driver, instance, (void *)ops);
		return (DDI_FAILURE);
	}

	unitp = kmem_zalloc(sizeof (iommulib_unit_t), KM_SLEEP);
	mutex_enter(&iommulib_lock);
	if (iommulib_fini == 1) {
		mutex_exit(&iommulib_lock);
		cmn_err(CE_WARN, "%s: IOMMULIB unloading. Failing register.",
		    f);
		kmem_free(unitp, sizeof (iommulib_unit_t));
		return (DDI_FAILURE);
	}

	/*
	 * fini/register race conditions have been handled. Now create the
	 * IOMMU unit
	 */
	mutex_init(&unitp->ilu_lock, NULL, MUTEX_DEFAULT, NULL);

	mutex_enter(&unitp->ilu_lock);
	unitp->ilu_unitid = ++iommulib_unit_ids;
	unitp->ilu_ref = 0;
	ndi_hold_devi(dip);
	unitp->ilu_dip = dip;
	unitp->ilu_ops = ops;
	unitp->ilu_data = ops->ilops_data;

	unitp->ilu_next = iommulib_list;
	unitp->ilu_prev = NULL;
	iommulib_list->ilu_prev = unitp;
	iommulib_list = unitp;

	mutex_exit(&unitp->ilu_lock);

	iommulib_num_units++;

	*handle = unitp;

	mutex_exit(&iommulib_lock);

	cmn_err(CE_NOTE, "%s: %s%d: Succesfully registered IOMMU unit "
	    "from vendor=%s, ops=%p, data=%p, IOMMULIB unitid=%u",
	    f, driver, instance, vendor, (void *)ops, (void *)unitp->ilu_data,
	    unitp->ilu_unitid);

	return (DDI_SUCCESS);
}

int
iommulib_iommu_unregister(iommulib_handle_t handle)
{
	uint32_t unitid;
	dev_info_t *dip;
	int instance;
	const char *driver;
	iommulib_unit_t *unitp = (iommulib_unit_t *)handle;
	const char *f = "iommulib_unregister";

	ASSERT(unitp);

	mutex_enter(&iommulib_lock);
	mutex_enter(&unitp->ilu_lock);

	unitid = unitp->ilu_unitid;
	dip = unitp->ilu_dip;
	driver = ddi_driver_name(dip);
	instance = ddi_get_instance(dip);

	if (unitp->ilu_ref != 0) {
		mutex_exit(&unitp->ilu_lock);
		mutex_exit(&iommulib_lock);
		cmn_err(CE_WARN, "%s: %s%d: IOMMULIB handle is busy. Cannot "
		    "unregister IOMMULIB unitid %u",
		    f, driver, instance, unitid);
		return (DDI_FAILURE);
	}
	unitp->ilu_unitid = 0;
	ASSERT(unitp->ilu_ref == 0);

	if (unitp->ilu_prev == NULL) {
		iommulib_list = unitp->ilu_next;
		unitp->ilu_next->ilu_prev = NULL;
	} else {
		unitp->ilu_prev->ilu_next = unitp->ilu_next;
		unitp->ilu_next->ilu_prev = unitp->ilu_prev;
	}

	iommulib_num_units--;

	mutex_exit(&unitp->ilu_lock);

	mutex_destroy(&unitp->ilu_lock);
	kmem_free(unitp, sizeof (iommulib_unit_t));

	mutex_exit(&iommulib_lock);

	cmn_err(CE_WARN, "%s: %s%d: IOMMULIB handle (unitid=%u) successfully "
	    "unregistered", f, driver, instance, unitid);

	ndi_rele_devi(dip);

	return (DDI_SUCCESS);
}

int
iommulib_nex_open(dev_info_t *rdip, uint_t *errorp)
{
	iommulib_unit_t *unitp;
	int instance = ddi_get_instance(rdip);
	const char *driver = ddi_driver_name(rdip);
	const char *f = "iommulib_nex_open";

	*errorp = 0;
	DEVI(rdip)->devi_iommulib_handle = NULL;

	/* prevent use of IOMMU for AMD IOMMU's DMA */
	if (strcmp(driver, "amd_iommu") == 0) {
		*errorp = ENOTSUP;
		return (DDI_FAILURE);
	}

	if (lookup_cache(rdip, &unitp) == DDI_SUCCESS) {
		DEVI(rdip)->devi_iommulib_handle =
		    (iommulib_handle_t)unitp;
		return (DDI_SUCCESS);
	}


	/*
	 * Ok this dip is not in the cache. Use the probe entry point
	 * to determine in a hardware specific manner whether this
	 * dip is controlled by an IOMMU. If yes, insert it into the
	 * cache and return the handle corresponding to the IOMMU unit.
	 */

	mutex_enter(&iommulib_lock);
	for (unitp = iommulib_list; unitp; unitp = unitp->ilu_next) {
		if (unitp->ilu_ops->ilops_probe(rdip) == DDI_SUCCESS)
			break;
	}

	if (unitp == NULL) {
		mutex_exit(&iommulib_lock);
		if (iommulib_debug) {
			char *buf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
			cmn_err(CE_WARN, "%s: %s%d: devinfo node (%p): is not "
			    "controlled by an IOMMU: path=%s", f, driver,
			    instance, (void *)rdip, ddi_pathname(rdip, buf));
			kmem_free(buf, MAXPATHLEN);
		}
		*errorp = ENOTSUP;
		return (DDI_FAILURE);
	}

	mutex_enter(&unitp->ilu_lock);
	unitp->ilu_ref++;
	mutex_exit(&unitp->ilu_lock);
	mutex_exit(&iommulib_lock);

	insert_cache(rdip, unitp);

	DEVI(rdip)->devi_iommulib_handle = unitp;

	return (DDI_SUCCESS);
}

void
iommulib_nex_close(dev_info_t *rdip)
{
	iommulib_unit_t *unitp;
	const char *driver;
	int instance;
	uint32_t unitid;
	const char *f = "iommulib_nex_close";

	unitp = (iommulib_unit_t *)DEVI(rdip)->devi_iommulib_handle;
	if (unitp == NULL)
		return;

	DEVI(rdip)->devi_iommulib_handle = NULL;

	/*
	 * Assume we don't support DR of IOMMUs. The mapping of
	 * dips to IOMMU units should not change. Let the mapping
	 * persist in the cache.
	 */

	mutex_enter(&iommulib_lock);
	mutex_enter(&unitp->ilu_lock);
	unitid = unitp->ilu_unitid;
	driver = ddi_driver_name(unitp->ilu_dip);
	instance = ddi_get_instance(unitp->ilu_dip);
	unitp->ilu_ref--;
	mutex_exit(&unitp->ilu_lock);
	mutex_exit(&iommulib_lock);

	if (iommulib_debug) {
		char *buf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		(void) ddi_pathname(rdip, buf);
		cmn_err(CE_NOTE, "%s: %s%d: closing IOMMU for dip (%p), "
		    "unitid=%u rdip path = %s", f, driver, instance,
		    (void *)rdip, unitid, buf);
		kmem_free(buf, MAXPATHLEN);
	}
}

int
iommulib_nexdma_allochdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_attr_t *attr, int (*waitfp)(caddr_t),
    caddr_t arg, ddi_dma_handle_t *dma_handlep)
{
	iommulib_handle_t handle = DEVI(rdip)->devi_iommulib_handle;
	iommulib_unit_t *unitp = (iommulib_unit_t *)handle;

	ASSERT(unitp);

	/* No need to grab lock - the handle is reference counted */
	return (unitp->ilu_ops->ilops_dma_allochdl(handle, dip, rdip,
	    attr, waitfp, arg, dma_handlep));
}

int
iommulib_nexdma_freehdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t dma_handle)
{
	int error;
	iommulib_handle_t handle = DEVI(rdip)->devi_iommulib_handle;
	iommulib_unit_t *unitp = (iommulib_unit_t *)handle;

	ASSERT(unitp);

	/* No need to grab lock - the handle is reference counted */
	error = unitp->ilu_ops->ilops_dma_freehdl(handle, dip,
	    rdip, dma_handle);

	iommulib_nex_close(rdip);

	return (error);
}

int
iommulib_nexdma_bindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t dma_handle, struct ddi_dma_req *dmareq,
    ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	iommulib_handle_t handle = DEVI(rdip)->devi_iommulib_handle;
	iommulib_unit_t *unitp = (iommulib_unit_t *)handle;

	ASSERT(unitp);

	/* No need to grab lock - the handle is reference counted */
	return (unitp->ilu_ops->ilops_dma_bindhdl(handle, dip, rdip, dma_handle,
	    dmareq, cookiep, ccountp));
}

int
iommulib_nexdma_unbindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t dma_handle)
{
	iommulib_handle_t handle = DEVI(rdip)->devi_iommulib_handle;
	iommulib_unit_t *unitp = (iommulib_unit_t *)handle;

	ASSERT(unitp);

	/* No need to grab lock - the handle is reference counted */
	return (unitp->ilu_ops->ilops_dma_unbindhdl(handle, dip, rdip,
	    dma_handle));
}

int
iommulib_nexdma_sync(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t dma_handle, off_t off, size_t len,
    uint_t cache_flags)
{
	iommulib_handle_t handle = DEVI(rdip)->devi_iommulib_handle;
	iommulib_unit_t *unitp = (iommulib_unit_t *)handle;

	ASSERT(unitp);

	/* No need to grab lock - the handle is reference counted */
	return (unitp->ilu_ops->ilops_dma_sync(handle, dip, rdip, dma_handle,
	    off, len, cache_flags));
}

int
iommulib_nexdma_win(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t dma_handle, uint_t win, off_t *offp, size_t *lenp,
    ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	iommulib_handle_t handle = DEVI(rdip)->devi_iommulib_handle;
	iommulib_unit_t *unitp = (iommulib_unit_t *)handle;

	ASSERT(unitp);

	/* No need to grab lock - the handle is reference counted */
	return (unitp->ilu_ops->ilops_dma_win(handle, dip, rdip, dma_handle,
	    win, offp, lenp, cookiep, ccountp));
}

/* Obsolete DMA routines */

int
iommulib_nexdma_map(dev_info_t *dip, dev_info_t *rdip,
    struct ddi_dma_req *dmareq, ddi_dma_handle_t *dma_handle)
{
	iommulib_handle_t handle = DEVI(rdip)->devi_iommulib_handle;
	iommulib_unit_t *unitp = handle;

	ASSERT(unitp);

	/* No need to grab lock - the handle is reference counted */
	return (unitp->ilu_ops->ilops_dma_map(handle, dip, rdip, dmareq,
	    dma_handle));
}

int
iommulib_nexdma_mctl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t dma_handle, enum ddi_dma_ctlops request,
    off_t *offp, size_t *lenp, caddr_t *objpp, uint_t cache_flags)
{
	iommulib_handle_t handle = DEVI(rdip)->devi_iommulib_handle;
	iommulib_unit_t *unitp = (iommulib_unit_t *)handle;

	ASSERT(unitp);

	/* No need to grab lock - the handle is reference counted */
	return (unitp->ilu_ops->ilops_dma_mctl(handle, dip, rdip, dma_handle,
	    request, offp, lenp, objpp, cache_flags));
}

/* Utility routines invoked by IOMMU drivers */
int
iommulib_iommu_dma_allochdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_attr_t *attr, int (*waitfp)(caddr_t), caddr_t arg,
    ddi_dma_handle_t *handlep)
{
	iommulib_nexops_t *nexops = lookup_nexops(dip);
	if (nexops == NULL)
		return (DDI_FAILURE);
	return (nexops->nops_dma_allochdl(dip, rdip, attr, waitfp, arg,
	    handlep));
}

int
iommulib_iommu_dma_freehdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle)
{
	iommulib_nexops_t *nexops = lookup_nexops(dip);
	if (nexops == NULL)
		return (DDI_FAILURE);
	return (nexops->nops_dma_freehdl(dip, rdip, handle));
}

int
iommulib_iommu_dma_bindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, struct ddi_dma_req *dmareq,
    ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	iommulib_nexops_t *nexops = lookup_nexops(dip);
	if (nexops == NULL)
		return (DDI_FAILURE);
	return (nexops->nops_dma_bindhdl(dip, rdip, handle, dmareq,
	    cookiep, ccountp));
}

int
iommulib_iommu_dma_unbindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle)
{
	iommulib_nexops_t *nexops = lookup_nexops(dip);
	if (nexops == NULL)
		return (DDI_FAILURE);
	return (nexops->nops_dma_unbindhdl(dip, rdip, handle));
}

void
iommulib_iommu_dma_reset_cookies(dev_info_t *dip, ddi_dma_handle_t handle)
{
	iommulib_nexops_t *nexops = lookup_nexops(dip);
	nexops->nops_dma_reset_cookies(dip, handle);
}

int
iommulib_iommu_dma_get_cookies(dev_info_t *dip, ddi_dma_handle_t handle,
    ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	iommulib_nexops_t *nexops = lookup_nexops(dip);
	if (nexops == NULL)
		return (DDI_FAILURE);
	return (nexops->nops_dma_get_cookies(dip, handle, cookiep, ccountp));
}

int
iommulib_iommu_dma_sync(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, off_t off, size_t len, uint_t cache_flags)
{
	iommulib_nexops_t *nexops = lookup_nexops(dip);
	if (nexops == NULL)
		return (DDI_FAILURE);
	return (nexops->nops_dma_sync(dip, rdip, handle, off, len,
	    cache_flags));
}

int
iommulib_iommu_dma_win(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, uint_t win, off_t *offp, size_t *lenp,
    ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	iommulib_nexops_t *nexops = lookup_nexops(dip);
	if (nexops == NULL)
		return (DDI_FAILURE);
	return (nexops->nops_dma_win(dip, rdip, handle, win, offp, lenp,
	    cookiep, ccountp));
}

int
iommulib_iommu_dma_map(dev_info_t *dip, dev_info_t *rdip,
    struct ddi_dma_req *dmareq, ddi_dma_handle_t *handlep)
{
	iommulib_nexops_t *nexops = lookup_nexops(dip);
	if (nexops == NULL)
		return (DDI_FAILURE);
	return (nexops->nops_dma_map(dip, rdip, dmareq, handlep));
}

int
iommulib_iommu_dma_mctl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, enum ddi_dma_ctlops request, off_t *offp,
    size_t *lenp, caddr_t *objpp, uint_t cache_flags)
{
	iommulib_nexops_t *nexops = lookup_nexops(dip);
	if (nexops == NULL)
		return (DDI_FAILURE);
	return (nexops->nops_dma_mctl(dip, rdip, handle, request, offp, lenp,
	    objpp, cache_flags));
}

int
iommulib_iommu_getunitid(iommulib_handle_t handle, uint64_t *unitidp)
{
	iommulib_unit_t *unitp;
	uint64_t unitid;

	unitp = (iommulib_unit_t *)handle;

	ASSERT(unitp);
	ASSERT(unitidp);

	mutex_enter(&unitp->ilu_lock);
	unitid = unitp->ilu_unitid;
	mutex_exit(&unitp->ilu_lock);

	ASSERT(unitid > 0);
	*unitidp = (uint64_t)unitid;

	return (DDI_SUCCESS);
}

dev_info_t *
iommulib_iommu_getdip(iommulib_handle_t handle)
{
	iommulib_unit_t *unitp;
	dev_info_t *dip;

	unitp = (iommulib_unit_t *)handle;

	ASSERT(unitp);

	mutex_enter(&unitp->ilu_lock);
	dip = unitp->ilu_dip;
	ASSERT(dip);
	ndi_hold_devi(dip);
	mutex_exit(&unitp->ilu_lock);

	return (dip);
}

iommulib_ops_t *
iommulib_iommu_getops(iommulib_handle_t handle)
{
	iommulib_unit_t *unitp;
	iommulib_ops_t *ops;

	unitp = (iommulib_unit_t *)handle;

	ASSERT(unitp);

	mutex_enter(&unitp->ilu_lock);
	ops = unitp->ilu_ops;
	mutex_exit(&unitp->ilu_lock);

	ASSERT(ops);

	return (ops);
}

void *
iommulib_iommu_getdata(iommulib_handle_t handle)
{
	iommulib_unit_t *unitp;
	void *data;

	unitp = (iommulib_unit_t *)handle;

	ASSERT(unitp);

	mutex_enter(&unitp->ilu_lock);
	data = unitp->ilu_data;
	mutex_exit(&unitp->ilu_lock);

	ASSERT(data);

	return (data);
}

/*
 * Internal routines
 */

static uint32_t
hashfn(uint64_t ptr)
{
	return (ptr % iommulib_cache_size);
}

static int
lookup_cache(dev_info_t *rdip, iommulib_unit_t **unitpp)
{
	uint64_t idx;
	iommulib_cache_t *cachep;
	iommulib_unit_t *unitp;
	int retval = DDI_FAILURE;

	*unitpp = NULL;

	mutex_enter(&iommulib_lock);
	mutex_enter(&iommulib_cache_lock);

	ASSERT(iommulib_cache);

	idx = hashfn((uint64_t)(uintptr_t)rdip);

	ASSERT(idx < iommulib_cache_size);

	for (cachep = iommulib_cache[idx]; cachep;
	    cachep = cachep->cache_next) {
		if (cachep->cache_rdip == rdip)
			break;
	}

	if (cachep != NULL) {
		unitp = cachep->cache_unit;
		mutex_enter(&unitp->ilu_lock);
		unitp->ilu_ref++;
		mutex_exit(&unitp->ilu_lock);
		*unitpp = unitp;
		retval = DDI_SUCCESS;
	}

	mutex_exit(&iommulib_cache_lock);
	mutex_exit(&iommulib_lock);
	return (retval);
}

static void
insert_cache(dev_info_t *rdip, iommulib_unit_t *unitp)
{
	uint32_t idx;
	iommulib_cache_t *cachep;

	mutex_enter(&iommulib_lock);
	mutex_enter(&iommulib_cache_lock);

	ASSERT(iommulib_cache);

	idx = hashfn((uint64_t)(uintptr_t)rdip);

	ASSERT(idx < iommulib_cache_size);

	for (cachep = iommulib_cache[idx]; cachep;
	    cachep = cachep->cache_next) {
		if (cachep->cache_rdip == rdip)
			break;
	}

	if (cachep == NULL) {
		cachep = kmem_zalloc(sizeof (iommulib_cache_t), KM_SLEEP);
		cachep->cache_rdip = rdip;
		cachep->cache_unit = unitp;	/* ref-count set by caller */
		cachep->cache_prev = NULL;
		cachep->cache_next = iommulib_cache[idx];
		if (cachep->cache_next)
			cachep->cache_next->cache_prev = cachep;
		iommulib_cache[idx] = cachep;
	}

	mutex_exit(&iommulib_cache_lock);
	mutex_exit(&iommulib_lock);
}
