/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2020, the University of Queensland
 * Copyright 2020 RackTop Systems, Inc.
 */

/*
 * Mellanox Connect-X 4/5/6 driver.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/sysmacros.h>
#include <sys/disp.h>
#include <sys/sdt.h>

#include <sys/mac_provider.h>

#include <mlxcx.h>

/*
 * CTASSERT(s) to cover bad values which would induce bugs.
 */
CTASSERT(MLXCX_CQ_LWM_GAP >= MLXCX_CQ_HWM_GAP);

/*
 * Disable interrupts.
 * The act of calling ddi_intr_disable() does not guarantee an interrupt
 * routine is not running, so flag the vector as quiescing and wait
 * for anything active to finish.
 */
void
mlxcx_intr_disable(mlxcx_t *mlxp)
{
	int i;

	mlxcx_cmd_eq_disable(mlxp);

	for (i = 0; i < mlxp->mlx_intr_count; ++i) {
		mlxcx_event_queue_t *mleq = &mlxp->mlx_eqs[i];

		mutex_enter(&mleq->mleq_mtx);

		if ((mleq->mleq_state & MLXCX_EQ_INTR_ENABLED) == 0) {
			mutex_exit(&mleq->mleq_mtx);
			continue;
		}

		(void) ddi_intr_disable(mlxp->mlx_intr_handles[i]);

		mleq->mleq_state |= MLXCX_EQ_INTR_QUIESCE;
		while ((mleq->mleq_state & MLXCX_EQ_INTR_ACTIVE) != 0)
			cv_wait(&mleq->mleq_cv, &mleq->mleq_mtx);

		mleq->mleq_state &= ~MLXCX_EQ_INTR_ENABLED;

		mutex_exit(&mleq->mleq_mtx);
	}
}

void
mlxcx_intr_teardown(mlxcx_t *mlxp)
{
	int i;
	int ret;

	for (i = 0; i < mlxp->mlx_intr_count; ++i) {
		mlxcx_event_queue_t *mleq = &mlxp->mlx_eqs[i];

		mutex_enter(&mleq->mleq_mtx);
		VERIFY0(mleq->mleq_state & MLXCX_EQ_ALLOC);
		if (mleq->mleq_state & MLXCX_EQ_CREATED)
			VERIFY(mleq->mleq_state & MLXCX_EQ_DESTROYED);
		if (i >= mlxp->mlx_intr_cq0) {
			VERIFY(avl_is_empty(&mleq->mleq_cqs));
			avl_destroy(&mleq->mleq_cqs);
		}
		mutex_exit(&mleq->mleq_mtx);
		(void) ddi_intr_remove_handler(mlxp->mlx_intr_handles[i]);
		ret = ddi_intr_free(mlxp->mlx_intr_handles[i]);
		if (ret != DDI_SUCCESS) {
			mlxcx_warn(mlxp, "failed to free interrupt %d: %d",
			    i, ret);
		}
		mutex_destroy(&mleq->mleq_mtx);
		cv_destroy(&mleq->mleq_cv);
	}
	kmem_free(mlxp->mlx_intr_handles, mlxp->mlx_intr_size);
	kmem_free(mlxp->mlx_eqs, mlxp->mlx_eqs_size);
	mlxp->mlx_intr_handles = NULL;
	mlxp->mlx_eqs = NULL;
}

/*
 * Get the next SW-owned entry on the event queue, or NULL if we reach the end.
 */
static mlxcx_eventq_ent_t *
mlxcx_eq_next(mlxcx_event_queue_t *mleq)
{
	mlxcx_eventq_ent_t *ent;
	ddi_fm_error_t err;
	uint_t ci;
	const uint_t swowner = ((mleq->mleq_cc >> mleq->mleq_entshift) & 1);

	/*
	 * This should only be called from interrupt context to ensure
	 * correctness of mleq_cc.
	 */
	ASSERT(servicing_interrupt());
	ASSERT(mleq->mleq_state & MLXCX_EQ_CREATED);
	ASSERT0(mleq->mleq_state & MLXCX_EQ_DESTROYED);

	/* mleq_nents is always a power of 2 */
	ci = mleq->mleq_cc & (mleq->mleq_nents - 1);

	ent = &mleq->mleq_ent[ci];
	VERIFY0(ddi_dma_sync(mleq->mleq_dma.mxdb_dma_handle,
	    (uintptr_t)ent - (uintptr_t)mleq->mleq_ent,
	    sizeof (mlxcx_eventq_ent_t), DDI_DMA_SYNC_FORCPU));
	ddi_fm_dma_err_get(mleq->mleq_dma.mxdb_dma_handle, &err,
	    DDI_FME_VERSION);
	if (err.fme_status == DDI_FM_OK && (ent->mleqe_owner & 1) == swowner) {
		/* The PRM says we have to membar here, so we're doing it */
		membar_consumer();
		++mleq->mleq_cc;
		return (ent);
	}
	/*
	 * In the case of a DMA error, we should re-arm this EQ and then come
	 * back and try again when the device wakes us back up.
	 *
	 * Hopefully the fault will be gone by then.
	 */
	ddi_fm_dma_err_clear(mleq->mleq_dma.mxdb_dma_handle, DDI_FME_VERSION);

	return (NULL);
}

void
mlxcx_arm_eq(mlxcx_t *mlxp, mlxcx_event_queue_t *mleq)
{
	uint_t try = 0;
	ddi_fm_error_t err;
	bits32_t v = new_bits32();

	/*
	 * This is only called during initialization when the EQ is
	 * armed for the first time, and when re-armed at the end of
	 * interrupt processing.
	 */
	ASSERT(mutex_owned(&mleq->mleq_mtx) || servicing_interrupt());
	ASSERT(mleq->mleq_state & MLXCX_EQ_CREATED);
	ASSERT0(mleq->mleq_state & MLXCX_EQ_DESTROYED);
	ASSERT0(mleq->mleq_state & MLXCX_EQ_ARMED);
	ASSERT0(mleq->mleq_state & MLXCX_EQ_POLLING);

	mleq->mleq_state |= MLXCX_EQ_ARMED;
	mleq->mleq_cc_armed = mleq->mleq_cc;

	set_bits32(&v, MLXCX_EQ_ARM_EQN, mleq->mleq_num);
	set_bits32(&v, MLXCX_EQ_ARM_CI, mleq->mleq_cc);

retry:
	mlxcx_uar_put32(mlxp, mleq->mleq_uar, MLXCX_UAR_EQ_ARM,
	    from_bits32(v));
	ddi_fm_acc_err_get(mlxp->mlx_regs_handle, &err,
	    DDI_FME_VERSION);
	if (err.fme_status == DDI_FM_OK)
		return;
	if (try++ < mlxcx_doorbell_tries) {
		ddi_fm_acc_err_clear(mlxp->mlx_regs_handle, DDI_FME_VERSION);
		goto retry;
	}
	ddi_fm_service_impact(mlxp->mlx_dip, DDI_SERVICE_LOST);
}

static void
mlxcx_update_eq(mlxcx_t *mlxp, mlxcx_event_queue_t *mleq)
{
	bits32_t v = new_bits32();
	ddi_fm_error_t err;

	/*
	 * This should only be called from interrupt context to ensure
	 * correctness of mleq_cc.
	 */
	ASSERT(servicing_interrupt());
	ASSERT(mleq->mleq_state & MLXCX_EQ_CREATED);
	ASSERT0(mleq->mleq_state & MLXCX_EQ_DESTROYED);
	ASSERT0(mleq->mleq_state & MLXCX_EQ_ARMED);

	set_bits32(&v, MLXCX_EQ_ARM_EQN, mleq->mleq_num);
	set_bits32(&v, MLXCX_EQ_ARM_CI, mleq->mleq_cc);

	mlxcx_uar_put32(mlxp, mleq->mleq_uar, MLXCX_UAR_EQ_NOARM,
	    from_bits32(v));
	ddi_fm_acc_err_get(mlxp->mlx_regs_handle, &err,
	    DDI_FME_VERSION);
	ddi_fm_acc_err_clear(mlxp->mlx_regs_handle, DDI_FME_VERSION);
	/*
	 * Ignore the error, if it's still happening when we try to re-arm the
	 * EQ, we will note the impact then.
	 */
}

static mlxcx_completionq_ent_t *
mlxcx_cq_next(mlxcx_completion_queue_t *mlcq)
{
	mlxcx_completionq_ent_t *ent;
	ddi_fm_error_t err;
	uint_t ci;
	const uint_t swowner = ((mlcq->mlcq_cc >> mlcq->mlcq_entshift) & 1);

	ASSERT(mutex_owned(&mlcq->mlcq_mtx));
	ASSERT(mlcq->mlcq_state & MLXCX_CQ_CREATED);
	ASSERT0(mlcq->mlcq_state & MLXCX_CQ_DESTROYED);

	/* mlcq_nents is always a power of 2 */
	ci = mlcq->mlcq_cc & (mlcq->mlcq_nents - 1);

	ent = &mlcq->mlcq_ent[ci];
	VERIFY0(ddi_dma_sync(mlcq->mlcq_dma.mxdb_dma_handle,
	    (uintptr_t)ent - (uintptr_t)mlcq->mlcq_ent,
	    sizeof (mlxcx_completionq_ent_t), DDI_DMA_SYNC_FORCPU));
	ddi_fm_dma_err_get(mlcq->mlcq_dma.mxdb_dma_handle, &err,
	    DDI_FME_VERSION);
	if (err.fme_status == DDI_FM_OK && (ent->mlcqe_owner & 1) == swowner) {
		/* The PRM says we have to membar here, so we're doing it */
		membar_consumer();
		++mlcq->mlcq_cc;
		return (ent);
	}
	ddi_fm_dma_err_clear(mlcq->mlcq_dma.mxdb_dma_handle, DDI_FME_VERSION);

	return (NULL);
}

void
mlxcx_update_cqci(mlxcx_t *mlxp, mlxcx_completion_queue_t *mlcq)
{
	ddi_fm_error_t err;
	uint_t try = 0;

	mlcq->mlcq_doorbell->mlcqd_update_ci = to_be24(mlcq->mlcq_cc);

retry:
	MLXCX_DMA_SYNC(mlcq->mlcq_doorbell_dma, DDI_DMA_SYNC_FORDEV);
	ddi_fm_dma_err_get(mlcq->mlcq_doorbell_dma.mxdb_dma_handle, &err,
	    DDI_FME_VERSION);
	if (err.fme_status != DDI_FM_OK) {
		if (try++ < mlxcx_doorbell_tries) {
			ddi_fm_dma_err_clear(
			    mlcq->mlcq_doorbell_dma.mxdb_dma_handle,
			    DDI_FME_VERSION);
			goto retry;
		} else {
			ddi_fm_service_impact(mlxp->mlx_dip, DDI_SERVICE_LOST);
			return;
		}
	}
}

void
mlxcx_arm_cq(mlxcx_t *mlxp, mlxcx_completion_queue_t *mlcq)
{
	bits32_t dbval = new_bits32();
	uint64_t udbval;
	ddi_fm_error_t err;
	uint_t try = 0;

	ASSERT(mutex_owned(&mlcq->mlcq_arm_mtx));
	ASSERT(mutex_owned(&mlcq->mlcq_mtx));
	ASSERT(mlcq->mlcq_state & MLXCX_CQ_CREATED);
	ASSERT0(mlcq->mlcq_state & MLXCX_CQ_DESTROYED);

	if (mlcq->mlcq_state & MLXCX_CQ_ARMED) {
		ASSERT3U(mlcq->mlcq_ec, >, mlcq->mlcq_ec_armed);
	}

	if (mlcq->mlcq_state & MLXCX_CQ_TEARDOWN)
		return;

	atomic_or_uint(&mlcq->mlcq_state, MLXCX_CQ_ARMED);
	mlcq->mlcq_cc_armed = mlcq->mlcq_cc;
	mlcq->mlcq_ec_armed = mlcq->mlcq_ec;

	set_bits32(&dbval, MLXCX_CQ_ARM_SEQ, mlcq->mlcq_ec);
	set_bits32(&dbval, MLXCX_CQ_ARM_CI, mlcq->mlcq_cc);

	udbval = (uint64_t)from_bits32(dbval) << 32;
	udbval |= mlcq->mlcq_num & 0xffffff;

	mlcq->mlcq_doorbell->mlcqd_update_ci = to_be24(mlcq->mlcq_cc);
	mlcq->mlcq_doorbell->mlcqd_arm_ci = dbval;

retry:
	MLXCX_DMA_SYNC(mlcq->mlcq_doorbell_dma, DDI_DMA_SYNC_FORDEV);
	ddi_fm_dma_err_get(mlcq->mlcq_doorbell_dma.mxdb_dma_handle, &err,
	    DDI_FME_VERSION);
	if (err.fme_status != DDI_FM_OK) {
		if (try++ < mlxcx_doorbell_tries) {
			ddi_fm_dma_err_clear(
			    mlcq->mlcq_doorbell_dma.mxdb_dma_handle,
			    DDI_FME_VERSION);
			goto retry;
		} else {
			goto err;
		}
	}

	mlxcx_uar_put64(mlxp, mlcq->mlcq_uar, MLXCX_UAR_CQ_ARM, udbval);
	ddi_fm_acc_err_get(mlxp->mlx_regs_handle, &err,
	    DDI_FME_VERSION);
	if (err.fme_status == DDI_FM_OK)
		return;
	if (try++ < mlxcx_doorbell_tries) {
		ddi_fm_acc_err_clear(mlxp->mlx_regs_handle, DDI_FME_VERSION);
		goto retry;
	}

err:
	ddi_fm_service_impact(mlxp->mlx_dip, DDI_SERVICE_LOST);
}

const char *
mlxcx_event_name(mlxcx_event_t evt)
{
	switch (evt) {
	case MLXCX_EVENT_COMPLETION:
		return ("COMPLETION");
	case MLXCX_EVENT_PATH_MIGRATED:
		return ("PATH_MIGRATED");
	case MLXCX_EVENT_COMM_ESTABLISH:
		return ("COMM_ESTABLISH");
	case MLXCX_EVENT_SENDQ_DRAIN:
		return ("SENDQ_DRAIN");
	case MLXCX_EVENT_LAST_WQE:
		return ("LAST_WQE");
	case MLXCX_EVENT_SRQ_LIMIT:
		return ("SRQ_LIMIT");
	case MLXCX_EVENT_DCT_ALL_CLOSED:
		return ("DCT_ALL_CLOSED");
	case MLXCX_EVENT_DCT_ACCKEY_VIOL:
		return ("DCT_ACCKEY_VIOL");
	case MLXCX_EVENT_CQ_ERROR:
		return ("CQ_ERROR");
	case MLXCX_EVENT_WQ_CATASTROPHE:
		return ("WQ_CATASTROPHE");
	case MLXCX_EVENT_PATH_MIGRATE_FAIL:
		return ("PATH_MIGRATE_FAIL");
	case MLXCX_EVENT_PAGE_FAULT:
		return ("PAGE_FAULT");
	case MLXCX_EVENT_WQ_INVALID_REQ:
		return ("WQ_INVALID_REQ");
	case MLXCX_EVENT_WQ_ACCESS_VIOL:
		return ("WQ_ACCESS_VIOL");
	case MLXCX_EVENT_SRQ_CATASTROPHE:
		return ("SRQ_CATASTROPHE");
	case MLXCX_EVENT_INTERNAL_ERROR:
		return ("INTERNAL_ERROR");
	case MLXCX_EVENT_PORT_STATE:
		return ("PORT_STATE");
	case MLXCX_EVENT_GPIO:
		return ("GPIO");
	case MLXCX_EVENT_PORT_MODULE:
		return ("PORT_MODULE");
	case MLXCX_EVENT_TEMP_WARNING:
		return ("TEMP_WARNING");
	case MLXCX_EVENT_REMOTE_CONFIG:
		return ("REMOTE_CONFIG");
	case MLXCX_EVENT_DCBX_CHANGE:
		return ("DCBX_CHANGE");
	case MLXCX_EVENT_DOORBELL_CONGEST:
		return ("DOORBELL_CONGEST");
	case MLXCX_EVENT_STALL_VL:
		return ("STALL_VL");
	case MLXCX_EVENT_CMD_COMPLETION:
		return ("CMD_COMPLETION");
	case MLXCX_EVENT_PAGE_REQUEST:
		return ("PAGE_REQUEST");
	case MLXCX_EVENT_NIC_VPORT:
		return ("NIC_VPORT");
	case MLXCX_EVENT_EC_PARAMS_CHANGE:
		return ("EC_PARAMS_CHANGE");
	case MLXCX_EVENT_XRQ_ERROR:
		return ("XRQ_ERROR");
	}
	return ("UNKNOWN");
}

/* Should be called only when link state has changed. */
void
mlxcx_update_link_state(mlxcx_t *mlxp, mlxcx_port_t *port)
{
	link_state_t ls;

	mutex_enter(&port->mlp_mtx);
	(void) mlxcx_cmd_query_port_status(mlxp, port);
	(void) mlxcx_cmd_query_port_speed(mlxp, port);
	(void) mlxcx_cmd_query_port_fec(mlxp, port);

	switch (port->mlp_oper_status) {
	case MLXCX_PORT_STATUS_UP:
	case MLXCX_PORT_STATUS_UP_ONCE:
		ls = LINK_STATE_UP;
		break;
	case MLXCX_PORT_STATUS_DOWN:
		ls = LINK_STATE_DOWN;
		break;
	default:
		ls = LINK_STATE_UNKNOWN;
	}
	mac_link_update(mlxp->mlx_mac_hdl, ls);

	mutex_exit(&port->mlp_mtx);
}

CTASSERT(MLXCX_MANAGE_PAGES_MAX_PAGES < UINT_MAX);

static void
mlxcx_give_pages_once(mlxcx_t *mlxp, size_t npages)
{
	ddi_device_acc_attr_t acc;
	ddi_dma_attr_t attr;
	mlxcx_dev_page_t *mdp;
	mlxcx_dev_page_t **pages;
	size_t i;
	const ddi_dma_cookie_t *ck;

	/*
	 * If this isn't enough, the HCA will ask for more
	 */
	npages = MIN(npages, MLXCX_MANAGE_PAGES_MAX_PAGES);

	pages = kmem_zalloc(sizeof (*pages) * npages, KM_SLEEP);

	for (i = 0; i < npages; i++) {
		mdp = kmem_zalloc(sizeof (mlxcx_dev_page_t), KM_SLEEP);
		mlxcx_dma_acc_attr(mlxp, &acc);
		mlxcx_dma_page_attr(mlxp, &attr);
		if (!mlxcx_dma_alloc(mlxp, &mdp->mxdp_dma, &attr, &acc,
		    B_TRUE, MLXCX_HW_PAGE_SIZE, B_TRUE)) {
			mlxcx_warn(mlxp, "failed to allocate 4k page %u/%lu", i,
			    npages);
			kmem_free(mdp, sizeof (mlxcx_dev_page_t));
			goto cleanup_npages;
		}
		ck = mlxcx_dma_cookie_one(&mdp->mxdp_dma);
		mdp->mxdp_pa = ck->dmac_laddress;
		pages[i] = mdp;
	}

	mutex_enter(&mlxp->mlx_pagemtx);

	if (!mlxcx_cmd_give_pages(mlxp,
	    MLXCX_MANAGE_PAGES_OPMOD_GIVE_PAGES, npages, pages)) {
		mlxcx_warn(mlxp, "!hardware refused our gift of %lu "
		    "pages!", npages);
		mutex_exit(&mlxp->mlx_pagemtx);
		goto cleanup_npages;
	}

	for (i = 0; i < npages; i++) {
		avl_add(&mlxp->mlx_pages, pages[i]);
	}
	mlxp->mlx_npages += npages;
	mutex_exit(&mlxp->mlx_pagemtx);

	kmem_free(pages, sizeof (*pages) * npages);

	return;

cleanup_npages:
	for (i = 0; i < npages; i++) {
		if ((mdp = pages[i]) == NULL)
			break;

		mlxcx_dma_free(&mdp->mxdp_dma);
		kmem_free(mdp, sizeof (mlxcx_dev_page_t));
	}
	/* Tell the hardware we had an allocation failure. */
	(void) mlxcx_cmd_give_pages(mlxp, MLXCX_MANAGE_PAGES_OPMOD_ALLOC_FAIL,
	    0, NULL);
	mutex_exit(&mlxp->mlx_pagemtx);

	kmem_free(pages, sizeof (*pages) * npages);
}

static void
mlxcx_take_pages_once(mlxcx_t *mlxp, size_t npages)
{
	uint_t i;
	int32_t ret;
	uint64_t *pas;
	mlxcx_dev_page_t *mdp, probe;

	pas = kmem_alloc(sizeof (*pas) * npages, KM_SLEEP);

	if (!mlxcx_cmd_return_pages(mlxp, npages, pas, &ret)) {
		kmem_free(pas, sizeof (*pas) * npages);
		return;
	}

	mutex_enter(&mlxp->mlx_pagemtx);

	ASSERT0(avl_is_empty(&mlxp->mlx_pages));

	for (i = 0; i < ret; i++) {
		bzero(&probe, sizeof (probe));
		probe.mxdp_pa = pas[i];

		mdp = avl_find(&mlxp->mlx_pages, &probe, NULL);

		if (mdp != NULL) {
			avl_remove(&mlxp->mlx_pages, mdp);
			mlxp->mlx_npages--;
			mlxcx_dma_free(&mdp->mxdp_dma);
			kmem_free(mdp, sizeof (mlxcx_dev_page_t));
		} else {
			mlxcx_warn(mlxp, "hardware returned a page "
			    "with PA 0x%" PRIx64 " but we have no "
			    "record of giving out such a page", pas[i]);
		}
	}

	mutex_exit(&mlxp->mlx_pagemtx);

	kmem_free(pas, sizeof (*pas) * npages);
}

static void
mlxcx_pages_task(void *arg)
{
	mlxcx_async_param_t *param = arg;
	mlxcx_t *mlxp = param->mla_mlx;
	int32_t npages;

	/*
	 * We can drop the pending status now, as we've extracted what
	 * is needed to process the pages request.
	 *
	 * Even though we should never get another pages request until
	 * we have responded to this, along with the guard in mlxcx_sync_intr,
	 * this safely allows the reuse of mlxcx_async_param_t.
	 */
	mutex_enter(&param->mla_mtx);
	npages = param->mla_pages.mlp_npages;
	param->mla_pending = B_FALSE;
	bzero(&param->mla_pages, sizeof (param->mla_pages));
	mutex_exit(&param->mla_mtx);

	/*
	 * The PRM describes npages as: "Number of missing / unneeded pages
	 * (signed number, msb indicate sign)". The implication is that
	 * it will not be zero. We are expected to use this to give or
	 * take back pages (based on the sign) using the MANAGE_PAGES
	 * command but we can't determine whether to give or take
	 * when npages is zero. So we do nothing.
	 */
	if (npages > 0) {
		mlxcx_give_pages_once(mlxp, npages);
	} else if (npages < 0) {
		mlxcx_take_pages_once(mlxp, -1 * npages);
	}
}

static void
mlxcx_link_state_task(void *arg)
{
	mlxcx_async_param_t *param = arg;
	mlxcx_port_t *port;
	mlxcx_t *mlxp;

	/*
	 * Gather the argruments from the parameters and clear the
	 * pending status.
	 *
	 * The pending status must be cleared *before* we update the
	 * link state. This is both safe and required to ensure we always
	 * have the correct link state. It is safe because taskq_ents are
	 * reusable (by the caller of taskq_dispatch_ent()) once the
	 * task function has started executing. It is necessarily before
	 * updating the link state to guarantee further link state change
	 * events are not missed and we always have the current link state.
	 */
	mutex_enter(&param->mla_mtx);
	mlxp = param->mla_mlx;
	port = param->mla_port;
	param->mla_pending = B_FALSE;
	mutex_exit(&param->mla_mtx);

	mlxcx_update_link_state(mlxp, port);
}

static const char *
mlxcx_module_error_string(mlxcx_module_error_type_t err)
{
	switch (err) {
	case MLXCX_MODULE_ERR_POWER_BUDGET:
		return ("POWER_BUDGET");
	case MLXCX_MODULE_ERR_LONG_RANGE:
		return ("LONG_RANGE");
	case MLXCX_MODULE_ERR_BUS_STUCK:
		return ("BUS_STUCK");
	case MLXCX_MODULE_ERR_NO_EEPROM:
		return ("NO_EEPROM");
	case MLXCX_MODULE_ERR_ENFORCEMENT:
		return ("ENFORCEMENT");
	case MLXCX_MODULE_ERR_UNKNOWN_IDENT:
		return ("UNKNOWN_IDENT");
	case MLXCX_MODULE_ERR_HIGH_TEMP:
		return ("HIGH_TEMP");
	case MLXCX_MODULE_ERR_CABLE_SHORTED:
		return ("CABLE_SHORTED");
	default:
		return ("UNKNOWN");
	}
}

static void
mlxcx_report_module_error(mlxcx_t *mlxp, mlxcx_evdata_port_mod_t *evd)
{
	uint64_t ena;
	char buf[FM_MAX_CLASS];
	const char *lename;
	const char *ename;
	const char *stname;
	uint_t eno = 0;
	mlxcx_module_status_t state = evd->mled_port_mod_module_status;

	switch (state) {
	case MLXCX_MODULE_ERROR:
		stname = "error";
		eno = evd->mled_port_mod_error_type;
		lename = mlxcx_module_error_string(eno);
		switch (eno) {
		case MLXCX_MODULE_ERR_ENFORCEMENT:
			ename = DDI_FM_TXR_ERROR_WHITELIST;
			break;
		case MLXCX_MODULE_ERR_UNKNOWN_IDENT:
		case MLXCX_MODULE_ERR_NO_EEPROM:
			ename = DDI_FM_TXR_ERROR_NOTSUPP;
			break;
		case MLXCX_MODULE_ERR_HIGH_TEMP:
			ename = DDI_FM_TXR_ERROR_OVERTEMP;
			break;
		case MLXCX_MODULE_ERR_POWER_BUDGET:
		case MLXCX_MODULE_ERR_LONG_RANGE:
		case MLXCX_MODULE_ERR_CABLE_SHORTED:
			ename = DDI_FM_TXR_ERROR_HWFAIL;
			break;
		case MLXCX_MODULE_ERR_BUS_STUCK:
		default:
			ename = DDI_FM_TXR_ERROR_UNKNOWN;
		}
		break;
	default:
		return;
	}

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
	    DDI_FM_NIC, DDI_FM_TXR_ERROR);
	ena = fm_ena_generate(0, FM_ENA_FMT1);
	if (!DDI_FM_EREPORT_CAP(mlxp->mlx_fm_caps))
		return;

	ddi_fm_ereport_post(mlxp->mlx_dip, buf, ena, DDI_NOSLEEP,
	    /* compulsory FM props */
	    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
	    /* generic NIC txr error event props */
	    "error", DATA_TYPE_STRING, ename,
	    "port_index", DATA_TYPE_UINT8, 0,
	    "txr_index", DATA_TYPE_UINT8, evd->mled_port_mod_module,
	    /* local props */
	    "mlxcx_state", DATA_TYPE_STRING, stname,
	    "mlxcx_error", DATA_TYPE_STRING, lename,
	    "mlxcx_error_num", DATA_TYPE_UINT8, eno,
	    NULL);
	ddi_fm_service_impact(mlxp->mlx_dip, DDI_SERVICE_LOST);
}

/*
 * Common beginning of interrupt processing.
 * Confirm interrupt hasn't been disabled, verify its state and
 * mark the vector as active.
 */
static boolean_t
mlxcx_intr_ini(mlxcx_t *mlxp, mlxcx_event_queue_t *mleq)
{
	mutex_enter(&mleq->mleq_mtx);

	if ((mleq->mleq_state & MLXCX_EQ_INTR_ENABLED) == 0) {
		mutex_exit(&mleq->mleq_mtx);
		return (B_FALSE);
	}

	if (!(mleq->mleq_state & MLXCX_EQ_ALLOC) ||
	    !(mleq->mleq_state & MLXCX_EQ_CREATED) ||
	    (mleq->mleq_state & MLXCX_EQ_DESTROYED)) {
		mlxcx_warn(mlxp, "intr %d in bad eq state",
		    mleq->mleq_intr_index);
		mutex_exit(&mleq->mleq_mtx);
		return (B_FALSE);
	}

	mleq->mleq_state |= MLXCX_EQ_INTR_ACTIVE;
	mutex_exit(&mleq->mleq_mtx);

	return (B_TRUE);
}

/*
 * End of interrupt processing.
 * Mark vector as no longer active and if shutdown is blocked on this vector,
 * wake it up.
 */
static void
mlxcx_intr_fini(mlxcx_event_queue_t *mleq)
{
	mutex_enter(&mleq->mleq_mtx);
	if ((mleq->mleq_state & MLXCX_EQ_INTR_QUIESCE) != 0)
		cv_signal(&mleq->mleq_cv);

	mleq->mleq_state &= ~MLXCX_EQ_INTR_ACTIVE;
	mutex_exit(&mleq->mleq_mtx);
}

static uint_t
mlxcx_intr_async(caddr_t arg, caddr_t arg2)
{
	mlxcx_t *mlxp = (mlxcx_t *)arg;
	mlxcx_event_queue_t *mleq = (mlxcx_event_queue_t *)arg2;
	mlxcx_eventq_ent_t *ent;
	mlxcx_async_param_t *param;
	uint_t portn;
	uint16_t func;

	if (!mlxcx_intr_ini(mlxp, mleq))
		return (DDI_INTR_CLAIMED);

	ent = mlxcx_eq_next(mleq);
	if (ent == NULL) {
		goto done;
	}

	ASSERT(mleq->mleq_state & MLXCX_EQ_ARMED);
	mleq->mleq_state &= ~MLXCX_EQ_ARMED;

	for (; ent != NULL; ent = mlxcx_eq_next(mleq)) {
		DTRACE_PROBE2(event, mlxcx_t *, mlxp, mlxcx_eventq_ent_t *,
		    ent);

		switch (ent->mleqe_event_type) {
		case MLXCX_EVENT_CMD_COMPLETION:
			mlxcx_cmd_completion(mlxp, ent);
			break;
		case MLXCX_EVENT_PAGE_REQUEST:
			func = from_be16(ent->mleqe_page_request.
			    mled_page_request_function_id);
			VERIFY3U(func, <=, MLXCX_FUNC_ID_MAX);

			param = &mlxp->mlx_npages_req[func];
			mutex_enter(&param->mla_mtx);
			if (param->mla_pending) {
				/*
				 * The PRM states we will not get another
				 * page request event until any pending have
				 * been posted as complete to the HCA.
				 * This will guard against this anyway.
				 */
				mutex_exit(&param->mla_mtx);
				mlxcx_warn(mlxp, "Unexpected page request "
				    "whilst another is pending");
				break;
			}
			param->mla_pages.mlp_npages =
			    (int32_t)from_be32(ent->mleqe_page_request.
			    mled_page_request_num_pages);
			param->mla_pages.mlp_func = func;
			param->mla_pending = B_TRUE;
			ASSERT3P(param->mla_mlx, ==, mlxp);
			mutex_exit(&param->mla_mtx);

			taskq_dispatch_ent(mlxp->mlx_async_tq, mlxcx_pages_task,
			    param, 0, &param->mla_tqe);
			break;
		case MLXCX_EVENT_PORT_STATE:
			portn = get_bits8(
			    ent->mleqe_port_state.mled_port_state_port_num,
			    MLXCX_EVENT_PORT_NUM) - 1;
			if (portn >= mlxp->mlx_nports)
				break;

			param = &mlxp->mlx_ports[portn].mlx_port_event;
			mutex_enter(&param->mla_mtx);
			if (param->mla_pending) {
				/*
				 * There is a link state event pending
				 * processing. When that event is handled
				 * it will get the current link state.
				 */
				mutex_exit(&param->mla_mtx);
				break;
			}

			ASSERT3P(param->mla_mlx, ==, mlxp);
			ASSERT3P(param->mla_port, ==, &mlxp->mlx_ports[portn]);

			param->mla_pending = B_TRUE;
			mutex_exit(&param->mla_mtx);

			taskq_dispatch_ent(mlxp->mlx_async_tq,
			    mlxcx_link_state_task, param, 0, &param->mla_tqe);
			break;
		case MLXCX_EVENT_PORT_MODULE:
			mlxcx_report_module_error(mlxp, &ent->mleqe_port_mod);
			break;
		default:
			mlxcx_warn(mlxp, "unhandled event 0x%x on intr %d",
			    ent->mleqe_event_type, mleq->mleq_intr_index);
		}
	}

	mlxcx_arm_eq(mlxp, mleq);

done:
	mlxcx_intr_fini(mleq);
	return (DDI_INTR_CLAIMED);
}

static boolean_t
mlxcx_process_cq(mlxcx_t *mlxp, mlxcx_completion_queue_t *mlcq, mblk_t **mpp,
    size_t bytelim)
{
	mlxcx_work_queue_t *wq = mlcq->mlcq_wq;
	mlxcx_completionq_ent_t *cent;
	mblk_t *mp, *cmp, *nmp;
	mlxcx_buffer_t *buf;
	boolean_t found, added;
	size_t bytes = 0;
	uint_t rx_frames = 0;
	uint_t comp_cnt = 0;
	int64_t wqebbs, bufcnt;

	*mpp = NULL;

	if (!(mlcq->mlcq_state & MLXCX_CQ_ALLOC) ||
	    !(mlcq->mlcq_state & MLXCX_CQ_CREATED) ||
	    (mlcq->mlcq_state & MLXCX_CQ_DESTROYED) ||
	    (mlcq->mlcq_state & MLXCX_CQ_TEARDOWN)) {
		return (B_FALSE);
	}

	nmp = cmp = mp = NULL;

	wqebbs = 0;
	bufcnt = 0;
	for (cent = mlxcx_cq_next(mlcq); cent != NULL;
	    cent = mlxcx_cq_next(mlcq)) {
		/*
		 * Teardown and ring stop can atomic_or this flag
		 * into our state if they want us to stop early.
		 */
		if (mlcq->mlcq_state & MLXCX_CQ_TEARDOWN)
			return (B_FALSE);

		comp_cnt++;
		if (cent->mlcqe_opcode == MLXCX_CQE_OP_REQ &&
		    cent->mlcqe_send_wqe_opcode == MLXCX_WQE_OP_NOP) {
			/* NOP */
			atomic_dec_64(&wq->mlwq_wqebb_used);
			goto nextcq;
		}

lookagain:
		/*
		 * Generally the buffer we're looking for will be
		 * at the front of the list, so this loop won't
		 * need to look far.
		 */
		buf = list_head(&mlcq->mlcq_buffers);
		found = B_FALSE;
		while (buf != NULL) {
			if ((buf->mlb_wqe_index & UINT16_MAX) ==
			    from_be16(cent->mlcqe_wqe_counter)) {
				found = B_TRUE;
				break;
			}
			buf = list_next(&mlcq->mlcq_buffers, buf);
		}

		if (!found) {
			/*
			 * If there's any buffers waiting on the
			 * buffers_b list, then merge those into
			 * the main list and have another look.
			 *
			 * The wq enqueue routines push new buffers
			 * into buffers_b so that they can avoid
			 * taking the mlcq_mtx and blocking us for
			 * every single packet.
			 */
			added = B_FALSE;
			mutex_enter(&mlcq->mlcq_bufbmtx);
			if (!list_is_empty(&mlcq->mlcq_buffers_b)) {
				list_move_tail(&mlcq->mlcq_buffers,
				    &mlcq->mlcq_buffers_b);
				added = B_TRUE;
			}
			mutex_exit(&mlcq->mlcq_bufbmtx);
			if (added)
				goto lookagain;

			buf = list_head(&mlcq->mlcq_buffers);
			mlxcx_warn(mlxp, "got completion on CQ %x but "
			    "no buffer matching wqe found: %x (first "
			    "buffer counter = %x)", mlcq->mlcq_num,
			    from_be16(cent->mlcqe_wqe_counter),
			    buf == NULL ? UINT32_MAX :
			    buf->mlb_wqe_index);
			mlxcx_fm_ereport(mlxp, DDI_FM_DEVICE_INVAL_STATE);
			goto nextcq;
		}

		/*
		 * The buf is likely to be freed below, count this now.
		 */
		wqebbs += buf->mlb_wqebbs;

		list_remove(&mlcq->mlcq_buffers, buf);
		bufcnt++;

		switch (mlcq->mlcq_wq->mlwq_type) {
		case MLXCX_WQ_TYPE_SENDQ:
			mlxcx_tx_completion(mlxp, mlcq, cent, buf);
			break;
		case MLXCX_WQ_TYPE_RECVQ:
			nmp = mlxcx_rx_completion(mlxp, mlcq, cent, buf);
			bytes += from_be32(cent->mlcqe_byte_cnt);
			if (nmp != NULL) {
				if (cmp != NULL) {
					cmp->b_next = nmp;
					cmp = nmp;
				} else {
					mp = cmp = nmp;
				}

				rx_frames++;
			}
			break;
		}

		/*
		 * Update the consumer index with what has been processed,
		 * followed by driver counters. It is important to tell the
		 * hardware first, otherwise when we throw more packets at
		 * it, it may get an overflow error.
		 * We do this whenever we've processed enough to bridge the
		 * high->low water mark.
		 */
		if (bufcnt > (MLXCX_CQ_LWM_GAP - MLXCX_CQ_HWM_GAP)) {
			mlxcx_update_cqci(mlxp, mlcq);
			/*
			 * Both these variables are incremented using
			 * atomics as they are modified in other code paths
			 * (Eg during tx) which hold different locks.
			 */
			atomic_add_64(&mlcq->mlcq_bufcnt, -bufcnt);
			atomic_add_64(&wq->mlwq_wqebb_used, -wqebbs);
			wqebbs = 0;
			bufcnt = 0;
			comp_cnt = 0;
		}
nextcq:
		if (rx_frames > mlxp->mlx_props.mldp_rx_per_cq ||
		    (bytelim != 0 && bytes > bytelim))
			break;
	}

	if (comp_cnt > 0) {
		mlxcx_update_cqci(mlxp, mlcq);
		atomic_add_64(&mlcq->mlcq_bufcnt, -bufcnt);
		atomic_add_64(&wq->mlwq_wqebb_used, -wqebbs);
	}

	*mpp = mp;
	return (B_TRUE);
}


mblk_t *
mlxcx_rx_poll(mlxcx_t *mlxp, mlxcx_completion_queue_t *mlcq, size_t bytelim)
{
	mblk_t *mp = NULL;

	ASSERT(mutex_owned(&mlcq->mlcq_mtx));

	ASSERT(mlcq->mlcq_wq != NULL);
	ASSERT3U(mlcq->mlcq_wq->mlwq_type, ==, MLXCX_WQ_TYPE_RECVQ);

	(void) mlxcx_process_cq(mlxp, mlcq, &mp, bytelim);

	return (mp);
}

static uint_t
mlxcx_intr_n(caddr_t arg, caddr_t arg2)
{
	mlxcx_t *mlxp = (mlxcx_t *)arg;
	mlxcx_event_queue_t *mleq = (mlxcx_event_queue_t *)arg2;
	mlxcx_eventq_ent_t *ent;
	mlxcx_completion_queue_t *mlcq, probe;
	mlxcx_work_queue_t *mlwq;
	mblk_t *mp = NULL;
	boolean_t tellmac = B_FALSE;

	if (!mlxcx_intr_ini(mlxp, mleq))
		return (DDI_INTR_CLAIMED);

	ent = mlxcx_eq_next(mleq);
	if (ent == NULL) {
		if (++mleq->mleq_badintrs > mlxcx_stuck_intr_count) {
			mlxcx_fm_ereport(mlxp, DDI_FM_DEVICE_BADINT_LIMIT);
			ddi_fm_service_impact(mlxp->mlx_dip, DDI_SERVICE_LOST);
			(void) ddi_intr_disable(mlxp->mlx_intr_handles[
			    mleq->mleq_intr_index]);
		}
		goto done;
	}
	mleq->mleq_badintrs = 0;

	ASSERT(mleq->mleq_state & MLXCX_EQ_ARMED);
	mleq->mleq_state &= ~MLXCX_EQ_ARMED;

	for (; ent != NULL; ent = mlxcx_eq_next(mleq)) {
		if (ent->mleqe_event_type != MLXCX_EVENT_COMPLETION) {
			mlxcx_fm_ereport(mlxp, DDI_FM_DEVICE_INVAL_STATE);
			ddi_fm_service_impact(mlxp->mlx_dip, DDI_SERVICE_LOST);
			(void) ddi_intr_disable(mlxp->mlx_intr_handles[
			    mleq->mleq_intr_index]);
			goto done;
		}
		ASSERT3U(ent->mleqe_event_type, ==, MLXCX_EVENT_COMPLETION);

		probe.mlcq_num =
		    from_be24(ent->mleqe_completion.mled_completion_cqn);
		mutex_enter(&mleq->mleq_mtx);
		mlcq = avl_find(&mleq->mleq_cqs, &probe, NULL);
		mutex_exit(&mleq->mleq_mtx);

		if (mlcq == NULL)
			continue;

		mlwq = mlcq->mlcq_wq;

		/*
		 * mlcq_arm_mtx is used to avoid race conditions between
		 * this interrupt routine and the transition from polling
		 * back to interrupt mode. When exiting poll mode the
		 * CQ is likely to be un-armed, which means there will
		 * be no events for the CQ coming though here,
		 * consequently very low contention on mlcq_arm_mtx.
		 *
		 * mlcq_arm_mtx must be released before calls into mac
		 * layer in order to avoid deadlocks.
		 */
		mutex_enter(&mlcq->mlcq_arm_mtx);
		mlcq->mlcq_ec++;
		atomic_and_uint(&mlcq->mlcq_state, ~MLXCX_CQ_ARMED);

		if (mutex_tryenter(&mlcq->mlcq_mtx) == 0) {
			/*
			 * If we failed to take the mutex because the
			 * polling function has it, just move on.
			 * We don't want to block other CQs behind
			 * this one.
			 */
			if ((mlcq->mlcq_state & MLXCX_CQ_POLLING) != 0) {
				mutex_exit(&mlcq->mlcq_arm_mtx);
				goto update_eq;
			}

			/* Otherwise we will wait. */
			mutex_enter(&mlcq->mlcq_mtx);
		}

		if ((mlcq->mlcq_state & MLXCX_CQ_POLLING) == 0 &&
		    mlxcx_process_cq(mlxp, mlcq, &mp, 0)) {
			/*
			 * The ring is not in polling mode and we processed
			 * some completion queue entries.
			 */
			if ((mlcq->mlcq_state & MLXCX_CQ_BLOCKED_MAC) != 0 &&
			    mlcq->mlcq_bufcnt < mlcq->mlcq_buflwm) {
				atomic_and_uint(&mlcq->mlcq_state,
				    ~MLXCX_CQ_BLOCKED_MAC);
				tellmac = B_TRUE;
			}

			if ((mlwq->mlwq_state & MLXCX_WQ_BLOCKED_MAC) != 0 &&
			    mlwq->mlwq_wqebb_used < mlwq->mlwq_buflwm) {
				atomic_and_uint(&mlwq->mlwq_state,
				    ~MLXCX_WQ_BLOCKED_MAC);
				tellmac = B_TRUE;
			}

			mlxcx_arm_cq(mlxp, mlcq);

			mutex_exit(&mlcq->mlcq_mtx);
			mutex_exit(&mlcq->mlcq_arm_mtx);

			if (tellmac) {
				mac_tx_ring_update(mlxp->mlx_mac_hdl,
				    mlcq->mlcq_mac_hdl);
				tellmac = B_FALSE;
			}

			if (mp != NULL) {
				mac_rx_ring(mlxp->mlx_mac_hdl,
				    mlcq->mlcq_mac_hdl, mp, mlcq->mlcq_mac_gen);
			}
		} else {
			mutex_exit(&mlcq->mlcq_mtx);
			mutex_exit(&mlcq->mlcq_arm_mtx);
		}

update_eq:
		/*
		 * Updating the consumer counter for an EQ requires a write
		 * to the UAR, which is possibly expensive.
		 *
		 * Try to do it only often enough to stop us wrapping around.
		 */
		if ((mleq->mleq_cc & 0x7) == 0)
			mlxcx_update_eq(mlxp, mleq);
	}

	mlxcx_arm_eq(mlxp, mleq);

done:
	mlxcx_intr_fini(mleq);
	return (DDI_INTR_CLAIMED);
}

boolean_t
mlxcx_intr_setup(mlxcx_t *mlxp)
{
	dev_info_t *dip = mlxp->mlx_dip;
	int ret;
	int nintrs = 0;
	int navail = 0;
	int types, i;
	mlxcx_eventq_type_t eqt = MLXCX_EQ_TYPE_ANY;

	ret = ddi_intr_get_supported_types(dip, &types);
	if (ret != DDI_SUCCESS) {
		return (B_FALSE);
	}

	if (!(types & DDI_INTR_TYPE_MSIX)) {
		mlxcx_warn(mlxp, "MSI-X interrupts not available, but mlxcx "
		    "requires MSI-X");
		return (B_FALSE);
	}

	ret = ddi_intr_get_nintrs(dip, DDI_INTR_TYPE_MSIX, &nintrs);
	if (ret != DDI_SUCCESS) {
		return (B_FALSE);
	}
	if (nintrs < 2) {
		mlxcx_warn(mlxp, "%d MSI-X interrupts available, but mlxcx "
		    "requires 2", nintrs);
		return (B_FALSE);
	}

	ret = ddi_intr_get_navail(dip, DDI_INTR_TYPE_MSIX, &navail);
	if (navail < 2) {
		mlxcx_warn(mlxp, "%d MSI-X interrupts available, but mlxcx "
		    "requires 2", navail);
		return (B_FALSE);
	}

	mlxp->mlx_intr_size = navail * sizeof (ddi_intr_handle_t);
	mlxp->mlx_intr_handles = kmem_alloc(mlxp->mlx_intr_size, KM_SLEEP);
	/*
	 * Interrupts for Completion Queues events start from vector 1
	 * up to available vectors. Vector 0 is used for asynchronous
	 * events.
	 */
	mlxp->mlx_intr_cq0 = 1;

	ret = ddi_intr_alloc(dip, mlxp->mlx_intr_handles, DDI_INTR_TYPE_MSIX,
	    0, navail, &mlxp->mlx_intr_count, DDI_INTR_ALLOC_NORMAL);
	if (ret != DDI_SUCCESS) {
		mlxcx_intr_teardown(mlxp);
		return (B_FALSE);
	}
	if (mlxp->mlx_intr_count < mlxp->mlx_intr_cq0 + 1) {
		mlxcx_intr_teardown(mlxp);
		return (B_FALSE);
	}
	mlxp->mlx_intr_type = DDI_INTR_TYPE_MSIX;

	ret = ddi_intr_get_pri(mlxp->mlx_intr_handles[0], &mlxp->mlx_intr_pri);
	if (ret != DDI_SUCCESS) {
		mlxcx_intr_teardown(mlxp);
		return (B_FALSE);
	}

	mlxp->mlx_eqs_size = mlxp->mlx_intr_count *
	    sizeof (mlxcx_event_queue_t);
	mlxp->mlx_eqs = kmem_zalloc(mlxp->mlx_eqs_size, KM_SLEEP);

	/*
	 * In the failure path, mlxcx_intr_teardown() expects this
	 * mutex and avl tree to be init'ed - so do it now.
	 */
	for (i = 0; i < mlxp->mlx_intr_count; ++i) {
		mutex_init(&mlxp->mlx_eqs[i].mleq_mtx, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(mlxp->mlx_intr_pri));
		cv_init(&mlxp->mlx_eqs[i].mleq_cv, NULL, CV_DRIVER, NULL);

		if (i < mlxp->mlx_intr_cq0)
			continue;

		avl_create(&mlxp->mlx_eqs[i].mleq_cqs, mlxcx_cq_compare,
		    sizeof (mlxcx_completion_queue_t),
		    offsetof(mlxcx_completion_queue_t, mlcq_eq_entry));
	}

	ret = ddi_intr_add_handler(mlxp->mlx_intr_handles[0], mlxcx_intr_async,
	    (caddr_t)mlxp, (caddr_t)&mlxp->mlx_eqs[0]);
	if (ret != DDI_SUCCESS) {
		mlxcx_intr_teardown(mlxp);
		return (B_FALSE);
	}

	/*
	 * If we have enough interrupts, set their "type" fields so that we
	 * avoid mixing RX and TX queues on the same EQs.
	 */
	if (mlxp->mlx_intr_count >= 8) {
		eqt = MLXCX_EQ_TYPE_RX;
	}

	for (i = mlxp->mlx_intr_cq0; i < mlxp->mlx_intr_count; ++i) {
		mlxp->mlx_eqs[i].mleq_intr_index = i;

		mlxp->mlx_eqs[i].mleq_type = eqt;
		/*
		 * If eqt is still ANY, just leave it set to that
		 * (no else here).
		 */
		if (eqt == MLXCX_EQ_TYPE_RX) {
			eqt = MLXCX_EQ_TYPE_TX;
		} else if (eqt == MLXCX_EQ_TYPE_TX) {
			eqt = MLXCX_EQ_TYPE_RX;
		}

		ret = ddi_intr_add_handler(mlxp->mlx_intr_handles[i],
		    mlxcx_intr_n, (caddr_t)mlxp, (caddr_t)&mlxp->mlx_eqs[i]);
		if (ret != DDI_SUCCESS) {
			mlxcx_intr_teardown(mlxp);
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}
