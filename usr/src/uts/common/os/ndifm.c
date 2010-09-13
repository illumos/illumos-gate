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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Fault Management for Nexus Device Drivers
 *
 * In addition to implementing and supporting Fault Management for Device
 * Drivers (ddifm.c), nexus drivers must support their children by
 * reporting FM capabilities, intializing interrupt block cookies
 * for error handling callbacks and caching mapped resources for lookup
 * during the detection of an IO transaction error.
 *
 * It is typically the nexus driver that receives an error indication
 * for a fault that may have occurred in the data path of an IO transaction.
 * Errors may be detected or received via an interrupt, a callback from
 * another subsystem (e.g. a cpu trap) or examination of control data.
 *
 * Upon detection of an error, the nexus has a responsibility to alert
 * its children of the error and the transaction associated with that
 * error.  The actual implementation may vary depending upon the capabilities
 * of the nexus, its underlying hardware and its children.  In this file,
 * we provide support for typical nexus driver fault management tasks.
 *
 * Fault Management Initialization
 *
 *      Nexus drivers must implement two new busops, bus_fm_init() and
 *      bus_fm_fini().  bus_fm_init() is called from a child nexus or device
 *      driver and is expected to initialize any per-child state and return
 *      the FM and error interrupt priority levels of the nexus driver.
 *      Similarly, bus_fm_fini() is called by child drivers and should
 *      clean-up any resources allocated during bus_fm_init().
 *      These functions are called from passive kernel context, typically from
 *      driver attach(9F) and detach(9F) entry points.
 *
 * Error Handler Dispatching
 *
 *      Nexus drivers implemented to support error handler capabilities
 *	should invoke registered error handler callbacks for child drivers
 *	thought to be involved in the error.
 *	ndi_fm_handler_dispatch() is used to invoke
 *      all error handlers and returns one of the following status
 *      indications:
 *
 *      DDI_FM_OK - No errors found by any child
 *      DDI_FM_FATAL - one or more children have detected a fatal error
 *      DDI_FM_NONFATAL - no fatal errors, but one or more children have
 *                            detected a non-fatal error
 *
 *      ndi_fm_handler_dispatch() may be called in any context
 *      subject to the constraints specified by the interrupt iblock cookie
 *      returned during initialization.
 *
 * Protected Accesses
 *
 *      When an access handle is mapped or a DMA handle is bound via the
 *      standard busops, bus_map() or bus_dma_bindhdl(), a child driver
 *      implemented to support DDI_FM_ACCCHK_CAPABLE or
 *	DDI_FM_DMACHK_CAPABLE capabilites
 *	expects the nexus to flag any errors detected for transactions
 *	associated with the mapped or bound handles.
 *
 *      Children nexus or device drivers will set the following flags
 *      in their ddi_device_access or dma_attr_flags when requesting
 *      the an access or DMA handle mapping:
 *
 *      DDI_DMA_FLAGERR - nexus should set error status for any errors
 *                              detected for a failed DMA transaction.
 *      DDI_ACC_FLAGERR - nexus should set error status for any errors
 *                              detected for a failed PIO transaction.
 *
 *      A nexus is expected to provide additional error detection and
 *      handling for handles with these flags set.
 *
 * Exclusive Bus Access
 *
 *      In cases where a driver requires a high level of fault tolerance
 *      for a programmed IO transaction, it is neccessary to grant exclusive
 *      access to the bus resource.  Exclusivity guarantees that a fault
 *      resulting from a transaction on the bus can be easily traced and
 *      reported to the driver requesting the transaction.
 *
 *      Nexus drivers must implement two new busops to support exclusive
 *      access, bus_fm_access_enter() and bus_fm_access_exit().  The IO
 *      framework will use these functions when it must set-up access
 *      handles that set devacc_attr_access to DDI_ACC_CAUTIOUS in
 *      their ddi_device_acc_attr_t request.
 *
 *      Upon receipt of a bus_fm_access_enter() request, the nexus must prevent
 *      all other access requests until it receives bus_fm_access_exit()
 *      for the requested bus instance. bus_fm_access_enter() and
 *	bus_fm_access_exit() may be called from user, kernel or kernel
 *	interrupt context.
 *
 * Access and DMA Handle Caching
 *
 *      To aid a nexus driver in associating access or DMA handles with
 *      a detected error, the nexus should cache all handles that are
 *      associated with DDI_ACC_FLAGERR, DDI_ACC_CAUTIOUS_ACC or
 *	DDI_DMA_FLAGERR requests from its children.  ndi_fmc_insert() is
 *	called by a nexus to cache handles with the above protection flags
 *	and ndi_fmc_remove() is called when that handle is unmapped or
 *	unbound by the requesting child.  ndi_fmc_insert() and
 *	ndi_fmc_remove() may be called from any user or kernel context.
 *
 *	FM cache element is implemented by kmem_cache. The elements are
 *	stored in a doubly-linked searchable list.  When a handle is created,
 *	ndi_fm_insert() allocates an entry from the kmem_cache and inserts
 *	the entry to the head of the list.  When a handle is unmapped
 *	or unbound, ndi_fm_remove() removes its associated cache entry from
 *	the list.
 *
 *      Upon detection of an error, the nexus may invoke ndi_fmc_error() to
 *      iterate over the handle cache of one or more of its FM compliant
 *      children.  A comparison callback function is provided upon each
 *      invocation of ndi_fmc_error() to tell the IO framework if a
 *      handle is associated with an error.  If so, the framework will
 *      set the error status for that handle before returning from
 *      ndi_fmc_error().
 *
 *      ndi_fmc_error() may be called in any context
 *      subject to the constraints specified by the interrupt iblock cookie
 *      returned during initialization of the nexus and its children.
 *
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/debug.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi.h>
#include <sys/ndi_impldefs.h>
#include <sys/devctl.h>
#include <sys/nvpair.h>
#include <sys/ddifm.h>
#include <sys/ndifm.h>
#include <sys/spl.h>
#include <sys/sysmacros.h>
#include <sys/devops.h>
#include <sys/atomic.h>
#include <sys/kmem.h>
#include <sys/fm/io/ddi.h>

kmem_cache_t *ndi_fm_entry_cache;

void
ndi_fm_init(void)
{
	ndi_fm_entry_cache = kmem_cache_create("ndi_fm_entry_cache",
	    sizeof (ndi_fmcentry_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
}

/*
 * Allocate and initialize a fault management resource cache
 * A fault management cache consists of a set of cache elements that
 * are allocated from "ndi_fm_entry_cache".
 */
/* ARGSUSED */
void
i_ndi_fmc_create(ndi_fmc_t **fcpp, int qlen, ddi_iblock_cookie_t ibc)
{
	ndi_fmc_t *fcp;

	fcp = kmem_zalloc(sizeof (ndi_fmc_t), KM_SLEEP);
	mutex_init(&fcp->fc_lock, NULL, MUTEX_DRIVER, ibc);

	*fcpp = fcp;
}

/*
 * Destroy and resources associated with the given fault management cache.
 */
void
i_ndi_fmc_destroy(ndi_fmc_t *fcp)
{
	ndi_fmcentry_t *fep, *pp;

	if (fcp == NULL)
		return;

	/* Free all the cached entries, this should not happen though */
	mutex_enter(&fcp->fc_lock);
	for (fep = fcp->fc_head; fep != NULL; fep = pp) {
		pp = fep->fce_next;
		kmem_cache_free(ndi_fm_entry_cache, fep);
	}
	mutex_exit(&fcp->fc_lock);
	mutex_destroy(&fcp->fc_lock);
	kmem_free(fcp, sizeof (ndi_fmc_t));
}

/*
 * ndi_fmc_insert -
 * 	Add a new entry to the specified cache.
 *
 * 	This function must be called at or below LOCK_LEVEL
 */
void
ndi_fmc_insert(dev_info_t *dip, int flag, void *resource, void *bus_specific)
{
	struct dev_info *devi = DEVI(dip);
	ndi_fmc_t *fcp;
	ndi_fmcentry_t *fep, **fpp;
	struct i_ddi_fmhdl *fmhdl;

	ASSERT(devi);
	ASSERT(flag == DMA_HANDLE || flag == ACC_HANDLE);

	fmhdl = devi->devi_fmhdl;
	if (fmhdl == NULL) {
		return;
	}

	if (flag == DMA_HANDLE) {
		if (!DDI_FM_DMA_ERR_CAP(fmhdl->fh_cap)) {
			return;
		}
		fcp = fmhdl->fh_dma_cache;
		fpp = &((ddi_dma_impl_t *)resource)->dmai_error.err_fep;
	} else if (flag == ACC_HANDLE) {
		if (!DDI_FM_ACC_ERR_CAP(fmhdl->fh_cap)) {
			i_ddi_drv_ereport_post(dip, DVR_EFMCAP, NULL,
			    DDI_NOSLEEP);
			return;
		}
		fcp = fmhdl->fh_acc_cache;
		fpp = &((ddi_acc_impl_t *)resource)->ahi_err->err_fep;
	}

	fep = kmem_cache_alloc(ndi_fm_entry_cache, KM_NOSLEEP);
	if (fep == NULL) {
		atomic_inc_64(&fmhdl->fh_kstat.fek_fmc_full.value.ui64);
		return;
	}

	/*
	 * Set-up the handle resource and bus_specific information.
	 * Also remember the pointer back to the cache for quick removal.
	 */
	fep->fce_bus_specific = bus_specific;
	fep->fce_resource = resource;
	fep->fce_next = NULL;

	/* Add entry to the end of the active list */
	mutex_enter(&fcp->fc_lock);
	ASSERT(*fpp == NULL);
	*fpp = fep;
	fep->fce_prev = fcp->fc_tail;
	if (fcp->fc_tail != NULL)
		fcp->fc_tail->fce_next = fep;
	else
		fcp->fc_head = fep;
	fcp->fc_tail = fep;
	mutex_exit(&fcp->fc_lock);
}

/*
 * 	Remove an entry from the specified cache of access or dma mappings
 *
 * 	This function must be called at or below LOCK_LEVEL.
 */
void
ndi_fmc_remove(dev_info_t *dip, int flag, const void *resource)
{
	ndi_fmc_t *fcp;
	ndi_fmcentry_t *fep;
	struct dev_info *devi = DEVI(dip);
	struct i_ddi_fmhdl *fmhdl;

	ASSERT(devi);
	ASSERT(flag == DMA_HANDLE || flag == ACC_HANDLE);

	fmhdl = devi->devi_fmhdl;
	if (fmhdl == NULL) {
		return;
	}

	/* Find cache entry pointer for this resource */
	if (flag == DMA_HANDLE) {
		if (!DDI_FM_DMA_ERR_CAP(fmhdl->fh_cap)) {
			return;
		}
		fcp = fmhdl->fh_dma_cache;

		ASSERT(fcp);

		mutex_enter(&fcp->fc_lock);
		fep = ((ddi_dma_impl_t *)resource)->dmai_error.err_fep;
		((ddi_dma_impl_t *)resource)->dmai_error.err_fep = NULL;
	} else if (flag == ACC_HANDLE) {
		if (!DDI_FM_ACC_ERR_CAP(fmhdl->fh_cap)) {
			i_ddi_drv_ereport_post(dip, DVR_EFMCAP, NULL,
			    DDI_NOSLEEP);
			return;
		}
		fcp = fmhdl->fh_acc_cache;

		ASSERT(fcp);

		mutex_enter(&fcp->fc_lock);
		fep = ((ddi_acc_impl_t *)resource)->ahi_err->err_fep;
		((ddi_acc_impl_t *)resource)->ahi_err->err_fep = NULL;
	} else {
		return;
	}

	/*
	 * Resource not in cache, return
	 */
	if (fep == NULL) {
		mutex_exit(&fcp->fc_lock);
		atomic_inc_64(&fmhdl->fh_kstat.fek_fmc_miss.value.ui64);
		return;
	}

	/*
	 * Updates to FM cache pointers require us to grab fmc_lock
	 * to synchronize access to the cache for ndi_fmc_insert()
	 * and ndi_fmc_error()
	 */
	if (fep == fcp->fc_head)
		fcp->fc_head = fep->fce_next;
	else
		fep->fce_prev->fce_next = fep->fce_next;
	if (fep == fcp->fc_tail)
		fcp->fc_tail = fep->fce_prev;
	else
		fep->fce_next->fce_prev = fep->fce_prev;
	mutex_exit(&fcp->fc_lock);

	kmem_cache_free(ndi_fm_entry_cache, fep);
}

int
ndi_fmc_entry_error(dev_info_t *dip, int flag, ddi_fm_error_t *derr,
    const void *bus_err_state)
{
	int status, fatal = 0, nonfatal = 0;
	ndi_fmc_t *fcp = NULL;
	ndi_fmcentry_t *fep;
	struct i_ddi_fmhdl *fmhdl;

	ASSERT(flag == DMA_HANDLE || flag == ACC_HANDLE);

	fmhdl = DEVI(dip)->devi_fmhdl;
	ASSERT(fmhdl);
	status = DDI_FM_UNKNOWN;

	if (flag == DMA_HANDLE && DDI_FM_DMA_ERR_CAP(fmhdl->fh_cap)) {
		fcp = fmhdl->fh_dma_cache;
		ASSERT(fcp);
	} else if (flag == ACC_HANDLE && DDI_FM_ACC_ERR_CAP(fmhdl->fh_cap)) {
		fcp = fmhdl->fh_acc_cache;
		ASSERT(fcp);
	}

	if (fcp != NULL) {

		/*
		 * Check active resource entries
		 */
		mutex_enter(&fcp->fc_lock);
		for (fep = fcp->fc_head; fep != NULL; fep = fep->fce_next) {
			ddi_fmcompare_t compare_func;

			/*
			 * Compare captured error state with handle
			 * resources.  During the comparison and
			 * subsequent error handling, we block
			 * attempts to free the cache entry.
			 */
			compare_func = (flag == ACC_HANDLE) ?
			    i_ddi_fm_acc_err_cf_get((ddi_acc_handle_t)
			    fep->fce_resource) :
			    i_ddi_fm_dma_err_cf_get((ddi_dma_handle_t)
			    fep->fce_resource);

			if (compare_func == NULL) /* unbound or not FLAGERR */
				continue;

			status = compare_func(dip, fep->fce_resource,
			    bus_err_state, fep->fce_bus_specific);
			if (status == DDI_FM_UNKNOWN || status == DDI_FM_OK)
				continue;

			if (status == DDI_FM_FATAL)
				++fatal;
			else if (status == DDI_FM_NONFATAL)
				++nonfatal;

			/* Set the error for this resource handle */
			if (flag == ACC_HANDLE) {
				ddi_acc_handle_t ap = fep->fce_resource;

				i_ddi_fm_acc_err_set(ap, derr->fme_ena, status,
				    DDI_FM_ERR_UNEXPECTED);
				ddi_fm_acc_err_get(ap, derr, DDI_FME_VERSION);
				derr->fme_acc_handle = ap;
			} else {
				ddi_dma_handle_t dp = fep->fce_resource;

				i_ddi_fm_dma_err_set(dp, derr->fme_ena, status,
				    DDI_FM_ERR_UNEXPECTED);
				ddi_fm_dma_err_get(dp, derr, DDI_FME_VERSION);
				derr->fme_dma_handle = dp;
			}
		}
		mutex_exit(&fcp->fc_lock);
	}
	return (fatal ? DDI_FM_FATAL : nonfatal ? DDI_FM_NONFATAL :
	    DDI_FM_UNKNOWN);
}

/*
 * Check error state against the handle resource stored in the specified
 * FM cache.  If tdip != NULL, we check only the cache entries for tdip.
 * The caller must ensure that tdip is valid throughout the call and
 * all FM data structures can be safely accesses.
 *
 * If tdip == NULL, we check all children that have registered their
 * FM_DMA_CHK or FM_ACC_CHK capabilities.
 *
 * The following status values may be returned:
 *
 *	DDI_FM_FATAL - if at least one cache entry comparison yields a
 *			fatal error.
 *
 *	DDI_FM_NONFATAL - if at least one cache entry comparison yields a
 *			non-fatal error and no comparison yields a fatal error.
 *
 *	DDI_FM_UNKNOWN - cache entry comparisons did not yield fatal or
 *			non-fatal errors.
 *
 */
int
ndi_fmc_error(dev_info_t *dip, dev_info_t *tdip, int flag, uint64_t ena,
    const void *bus_err_state)
{
	int status, fatal = 0, nonfatal = 0;
	ddi_fm_error_t derr;
	struct i_ddi_fmhdl *fmhdl;
	struct i_ddi_fmtgt *tgt;

	ASSERT(flag == DMA_HANDLE || flag == ACC_HANDLE);

	i_ddi_fm_handler_enter(dip);
	fmhdl = DEVI(dip)->devi_fmhdl;
	ASSERT(fmhdl);

	bzero(&derr, sizeof (ddi_fm_error_t));
	derr.fme_version = DDI_FME_VERSION;
	derr.fme_flag = DDI_FM_ERR_UNEXPECTED;
	derr.fme_ena = ena;

	for (tgt = fmhdl->fh_tgts; tgt != NULL; tgt = tgt->ft_next) {

		if (tdip != NULL && tdip != tgt->ft_dip)
			continue;

		/*
		 * Attempt to find the entry in this childs handle cache
		 */
		status = ndi_fmc_entry_error(tgt->ft_dip, flag, &derr,
		    bus_err_state);

		if (status == DDI_FM_FATAL)
			++fatal;
		else if (status == DDI_FM_NONFATAL)
			++nonfatal;
		else
			continue;

		/*
		 * Call our child to process this error.
		 */
		status = tgt->ft_errhdl->eh_func(tgt->ft_dip, &derr,
		    tgt->ft_errhdl->eh_impl);

		if (status == DDI_FM_FATAL)
			++fatal;
		else if (status == DDI_FM_NONFATAL)
			++nonfatal;
	}

	i_ddi_fm_handler_exit(dip);

	if (fatal)
		return (DDI_FM_FATAL);
	else if (nonfatal)
		return (DDI_FM_NONFATAL);

	return (DDI_FM_UNKNOWN);
}

int
ndi_fmc_entry_error_all(dev_info_t *dip, int flag, ddi_fm_error_t *derr)
{
	ndi_fmc_t *fcp = NULL;
	ndi_fmcentry_t *fep;
	struct i_ddi_fmhdl *fmhdl;
	int nonfatal = 0;

	ASSERT(flag == DMA_HANDLE || flag == ACC_HANDLE);

	fmhdl = DEVI(dip)->devi_fmhdl;
	ASSERT(fmhdl);

	if (flag == DMA_HANDLE && DDI_FM_DMA_ERR_CAP(fmhdl->fh_cap)) {
		fcp = fmhdl->fh_dma_cache;
		ASSERT(fcp);
	} else if (flag == ACC_HANDLE && DDI_FM_ACC_ERR_CAP(fmhdl->fh_cap)) {
		fcp = fmhdl->fh_acc_cache;
		ASSERT(fcp);
	}

	if (fcp != NULL) {
		/*
		 * Check active resource entries
		 */
		mutex_enter(&fcp->fc_lock);
		for (fep = fcp->fc_head; fep != NULL; fep = fep->fce_next) {
			ddi_fmcompare_t compare_func;

			compare_func = (flag == ACC_HANDLE) ?
			    i_ddi_fm_acc_err_cf_get((ddi_acc_handle_t)
			    fep->fce_resource) :
			    i_ddi_fm_dma_err_cf_get((ddi_dma_handle_t)
			    fep->fce_resource);

			if (compare_func == NULL) /* unbound or not FLAGERR */
				continue;

			/* Set the error for this resource handle */
			nonfatal++;

			if (flag == ACC_HANDLE) {
				ddi_acc_handle_t ap = fep->fce_resource;

				i_ddi_fm_acc_err_set(ap, derr->fme_ena,
				    DDI_FM_NONFATAL, DDI_FM_ERR_UNEXPECTED);
				ddi_fm_acc_err_get(ap, derr, DDI_FME_VERSION);
				derr->fme_acc_handle = ap;
			} else {
				ddi_dma_handle_t dp = fep->fce_resource;

				i_ddi_fm_dma_err_set(dp, derr->fme_ena,
				    DDI_FM_NONFATAL, DDI_FM_ERR_UNEXPECTED);
				ddi_fm_dma_err_get(dp, derr, DDI_FME_VERSION);
				derr->fme_dma_handle = dp;
			}
		}
		mutex_exit(&fcp->fc_lock);
	}
	return (nonfatal ? DDI_FM_NONFATAL : DDI_FM_UNKNOWN);
}

/*
 * Dispatch registered error handlers for dip.  If tdip != NULL, only
 * the error handler (if available) for tdip is invoked.  Otherwise,
 * all registered error handlers are invoked.
 *
 * The following status values may be returned:
 *
 *	DDI_FM_FATAL - if at least one error handler returns a
 *			fatal error.
 *
 *	DDI_FM_NONFATAL - if at least one error handler returns a
 *			non-fatal error and none returned a fatal error.
 *
 *	DDI_FM_UNKNOWN - if at least one error handler returns
 *			unknown status and none return fatal or non-fatal.
 *
 *	DDI_FM_OK - if all error handlers return DDI_FM_OK
 */
int
ndi_fm_handler_dispatch(dev_info_t *dip, dev_info_t *tdip,
    const ddi_fm_error_t *nerr)
{
	int status;
	int unknown = 0, fatal = 0, nonfatal = 0;
	struct i_ddi_fmhdl *hdl;
	struct i_ddi_fmtgt *tgt;

	status = DDI_FM_UNKNOWN;

	i_ddi_fm_handler_enter(dip);
	hdl = DEVI(dip)->devi_fmhdl;
	tgt = hdl->fh_tgts;
	while (tgt != NULL) {
		if (tdip == NULL || tdip == tgt->ft_dip) {
			struct i_ddi_errhdl *errhdl;

			errhdl = tgt->ft_errhdl;
			status = errhdl->eh_func(tgt->ft_dip, nerr,
			    errhdl->eh_impl);

			if (status == DDI_FM_FATAL)
				++fatal;
			else if (status == DDI_FM_NONFATAL)
				++nonfatal;
			else if (status == DDI_FM_UNKNOWN)
				++unknown;

			/* Only interested in one target */
			if (tdip != NULL)
				break;
		}
		tgt = tgt->ft_next;
	}
	i_ddi_fm_handler_exit(dip);

	if (fatal)
		return (DDI_FM_FATAL);
	else if (nonfatal)
		return (DDI_FM_NONFATAL);
	else if (unknown)
		return (DDI_FM_UNKNOWN);
	else
		return (DDI_FM_OK);
}

/*
 * Set error status for specified access or DMA handle
 *
 * May be called in any context but caller must insure validity of
 * handle.
 */
void
ndi_fm_acc_err_set(ddi_acc_handle_t handle, ddi_fm_error_t *dfe)
{
	i_ddi_fm_acc_err_set(handle, dfe->fme_ena, dfe->fme_status,
	    dfe->fme_flag);
}

void
ndi_fm_dma_err_set(ddi_dma_handle_t handle, ddi_fm_error_t *dfe)
{
	i_ddi_fm_dma_err_set(handle, dfe->fme_ena, dfe->fme_status,
	    dfe->fme_flag);
}

/*
 * Call parent busop fm initialization routine.
 *
 * Called during driver attach(1M)
 */
int
i_ndi_busop_fm_init(dev_info_t *dip, int tcap, ddi_iblock_cookie_t *ibc)
{
	int pcap;
	dev_info_t *pdip = (dev_info_t *)DEVI(dip)->devi_parent;

	if (dip == ddi_root_node())
		return (ddi_system_fmcap | DDI_FM_EREPORT_CAPABLE);

	/* Valid operation for BUSO_REV_6 and above */
	if (DEVI(pdip)->devi_ops->devo_bus_ops->busops_rev < BUSO_REV_6)
		return (DDI_FM_NOT_CAPABLE);

	if (DEVI(pdip)->devi_ops->devo_bus_ops->bus_fm_init == NULL)
		return (DDI_FM_NOT_CAPABLE);

	pcap = (*DEVI(pdip)->devi_ops->devo_bus_ops->bus_fm_init)
	    (pdip, dip, tcap, ibc);

	return (pcap);
}

/*
 * Call parent busop fm clean-up routine.
 *
 * Called during driver detach(1M)
 */
void
i_ndi_busop_fm_fini(dev_info_t *dip)
{
	dev_info_t *pdip = (dev_info_t *)DEVI(dip)->devi_parent;

	if (dip == ddi_root_node())
		return;

	/* Valid operation for BUSO_REV_6 and above */
	if (DEVI(pdip)->devi_ops->devo_bus_ops->busops_rev < BUSO_REV_6)
		return;

	if (DEVI(pdip)->devi_ops->devo_bus_ops->bus_fm_fini == NULL)
		return;

	(*DEVI(pdip)->devi_ops->devo_bus_ops->bus_fm_fini)(pdip, dip);
}

/*
 * The following routines provide exclusive access to a nexus resource
 *
 * These busops may be called in user or kernel driver context.
 */
void
i_ndi_busop_access_enter(dev_info_t *dip, ddi_acc_handle_t handle)
{
	dev_info_t *pdip = (dev_info_t *)DEVI(dip)->devi_parent;

	/* Valid operation for BUSO_REV_6 and above */
	if (DEVI(pdip)->devi_ops->devo_bus_ops->busops_rev < BUSO_REV_6)
		return;

	if (DEVI(pdip)->devi_ops->devo_bus_ops->bus_fm_access_enter == NULL)
		return;

	(*DEVI(pdip)->devi_ops->devo_bus_ops->bus_fm_access_enter)
	    (pdip, handle);
}

void
i_ndi_busop_access_exit(dev_info_t *dip, ddi_acc_handle_t handle)
{
	dev_info_t *pdip = (dev_info_t *)DEVI(dip)->devi_parent;

	/* Valid operation for BUSO_REV_6 and above */
	if (DEVI(pdip)->devi_ops->devo_bus_ops->busops_rev < BUSO_REV_6)
		return;

	if (DEVI(pdip)->devi_ops->devo_bus_ops->bus_fm_access_exit == NULL)
		return;

	(*DEVI(pdip)->devi_ops->devo_bus_ops->bus_fm_access_exit)(pdip, handle);
}
