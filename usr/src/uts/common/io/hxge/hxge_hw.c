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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <hxge_impl.h>

lb_property_t lb_normal = {normal, "normal", hxge_lb_normal};
lb_property_t lb_mac10g = {internal, "mac10g", hxge_lb_mac10g};

uint32_t hxge_lb_dbg = 1;

extern uint32_t hxge_jumbo_frame_size;

static void hxge_rtrace_ioctl(p_hxge_t, queue_t *, mblk_t *, struct iocblk *);

void
hxge_global_reset(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_global_reset"));

	(void) hxge_intr_hw_disable(hxgep);

	if (hxgep->suspended)
		(void) hxge_link_init(hxgep);

	(void) hxge_vmac_init(hxgep);

	(void) hxge_intr_hw_enable(hxgep);

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_global_reset"));
}


void
hxge_hw_id_init(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_hw_id_init"));

	/*
	 * Initialize the frame size to either standard "1500 + 38" or
	 * jumbo. The user may tune the frame size through the "mtu" parameter
	 * using "dladm set-linkprop"
	 */
	hxgep->vmac.minframesize = MIN_FRAME_SIZE;
	hxgep->vmac.maxframesize = HXGE_DEFAULT_MTU + MTU_TO_FRAME_SIZE;
	if (hxgep->param_arr[param_accept_jumbo].value)
		hxgep->vmac.maxframesize = (uint16_t)hxge_jumbo_frame_size;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_hw_id_init: maxframesize %d",
	    hxgep->vmac.maxframesize));
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_hw_id_init"));
}

void
hxge_hw_init_niu_common(p_hxge_t hxgep)
{
	p_hxge_hw_list_t hw_p;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_hw_init_niu_common"));

	if ((hw_p = hxgep->hxge_hw_p) == NULL) {
		return;
	}

	MUTEX_ENTER(&hw_p->hxge_cfg_lock);
	if (hw_p->flags & COMMON_INIT_DONE) {
		HXGE_DEBUG_MSG((hxgep, MOD_CTL, "hxge_hw_init_niu_common"
		    " already done for dip $%p exiting", hw_p->parent_devp));
		MUTEX_EXIT(&hw_p->hxge_cfg_lock);
		return;
	}

	hw_p->flags = COMMON_INIT_START;
	HXGE_DEBUG_MSG((hxgep, MOD_CTL,
	    "hxge_hw_init_niu_common Started for device id %x",
	    hw_p->parent_devp));

	(void) hxge_pfc_hw_reset(hxgep);
	hw_p->flags = COMMON_INIT_DONE;
	MUTEX_EXIT(&hw_p->hxge_cfg_lock);

	HXGE_DEBUG_MSG((hxgep, MOD_CTL,
	    "hxge_hw_init_niu_common Done for device id %x",
	    hw_p->parent_devp));
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_hw_init_niu_common"));
}

uint_t
hxge_intr(caddr_t arg1, caddr_t arg2)
{
	p_hxge_ldv_t		ldvp = (p_hxge_ldv_t)arg1;
	p_hxge_t		hxgep = (p_hxge_t)arg2;
	uint8_t			ldv;
	hpi_handle_t		handle;
	p_hxge_ldgv_t		ldgvp;
	p_hxge_ldg_t		ldgp, t_ldgp;
	p_hxge_ldv_t		t_ldvp;
	uint32_t		vector0 = 0, vector1 = 0;
	int			j, nldvs;
	hpi_status_t		rs = HPI_SUCCESS;

	/*
	 * DDI interface returns second arg as NULL
	 */
	if ((arg2 == NULL) || ((void *) ldvp->hxgep != arg2)) {
		hxgep = ldvp->hxgep;
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_intr"));

	if (hxgep->hxge_mac_state != HXGE_MAC_STARTED) {
		HXGE_ERROR_MSG((hxgep, INT_CTL,
		    "<== hxge_intr: not initialized"));
		return (DDI_INTR_UNCLAIMED);
	}

	ldgvp = hxgep->ldgvp;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_intr: ldgvp $%p", ldgvp));

	if (ldvp == NULL && ldgvp)
		t_ldvp = ldvp = ldgvp->ldvp;
	if (ldvp)
		ldgp = t_ldgp = ldvp->ldgp;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_intr: "
	    "ldgvp $%p ldvp $%p ldgp $%p", ldgvp, ldvp, ldgp));

	if (ldgvp == NULL || ldvp == NULL || ldgp == NULL) {
		HXGE_ERROR_MSG((hxgep, INT_CTL, "==> hxge_intr: "
		    "ldgvp $%p ldvp $%p ldgp $%p", ldgvp, ldvp, ldgp));
		HXGE_ERROR_MSG((hxgep, INT_CTL, "<== hxge_intr: not ready"));
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * This interrupt handler will have to go through
	 * all the logical devices to find out which
	 * logical device interrupts us and then call
	 * its handler to process the events.
	 */
	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	t_ldgp = ldgp;
	t_ldvp = ldgp->ldvp;
	nldvs = ldgp->nldvs;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_intr: #ldvs %d #intrs %d",
	    nldvs, ldgvp->ldg_intrs));
	HXGE_DEBUG_MSG((hxgep, INT_CTL,
	    "==> hxge_intr(%d): #ldvs %d", i, nldvs));

	/*
	 * Get this group's flag bits.
	 */
	t_ldgp->interrupted = B_FALSE;
	rs = hpi_ldsv_ldfs_get(handle, t_ldgp->ldg, &vector0, &vector1);
	if (rs != HPI_SUCCESS)
		return (DDI_INTR_UNCLAIMED);

	if (!vector0 && !vector1) {
		HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_intr: "
		    "no interrupts on group %d", t_ldgp->ldg));
		return (DDI_INTR_UNCLAIMED);
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_intr: "
	    "vector0 0x%llx vector1 0x%llx", vector0, vector1));

	t_ldgp->interrupted = B_TRUE;
	nldvs = t_ldgp->nldvs;

	/*
	 * Process all devices that share this group.
	 */
	for (j = 0; j < nldvs; j++, t_ldvp++) {
		/*
		 * Call device's handler if flag bits are on.
		 */
		ldv = t_ldvp->ldv;
		if ((LDV_ON(ldv, vector0) | (LDV_ON(ldv, vector1)))) {
			HXGE_DEBUG_MSG((hxgep, INT_CTL,
			    "==> hxge_intr: calling device %d"
			    " #ldvs %d #intrs %d", j, nldvs, nintrs));
			(void) (t_ldvp->ldv_intr_handler)(
			    (caddr_t)t_ldvp, arg2);
		}
	}

	/*
	 * Re-arm group interrupts
	 */
	if (t_ldgp->interrupted) {
		HXGE_DEBUG_MSG((hxgep, INT_CTL,
		    "==> hxge_intr: arm group %d", t_ldgp->ldg));
		(void) hpi_intr_ldg_mgmt_set(handle, t_ldgp->ldg,
		    t_ldgp->arm, t_ldgp->ldg_timer);
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_intr"));
	return (DDI_INTR_CLAIMED);
}

hxge_status_t
hxge_peu_handle_sys_errors(p_hxge_t hxgep)
{
	hpi_handle_t		handle;
	p_hxge_peu_sys_stats_t	statsp;
	peu_intr_stat_t		stat;

	handle = hxgep->hpi_handle;
	statsp = (p_hxge_peu_sys_stats_t)&hxgep->statsp->peu_sys_stats;

	HXGE_REG_RD32(handle, PEU_INTR_STAT, &stat.value);

	/*
	 * The PCIE errors are unrecoverrable and cannot be cleared.
	 * The only thing we can do here is to mask them off to prevent
	 * continued interrupts.
	 */
	HXGE_REG_WR32(handle, PEU_INTR_MASK, 0xffffffff);

	if (stat.bits.spc_acc_err) {
		statsp->spc_acc_err++;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_peu_handle_sys_errors: spc_acc_err"));
	}

	if (stat.bits.tdc_pioacc_err) {
		statsp->tdc_pioacc_err++;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_peu_handle_sys_errors: tdc_pioacc_err"));
	}

	if (stat.bits.rdc_pioacc_err) {
		statsp->rdc_pioacc_err++;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_peu_handle_sys_errors: rdc_pioacc_err"));
	}

	if (stat.bits.pfc_pioacc_err) {
		statsp->pfc_pioacc_err++;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_peu_handle_sys_errors: pfc_pioacc_err"));
	}

	if (stat.bits.vmac_pioacc_err) {
		statsp->vmac_pioacc_err++;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_peu_handle_sys_errors: vmac_pioacc_err"));
	}

	if (stat.bits.cpl_hdrq_parerr) {
		statsp->cpl_hdrq_parerr++;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_peu_handle_sys_errors: cpl_hdrq_parerr"));
	}

	if (stat.bits.cpl_dataq_parerr) {
		statsp->cpl_dataq_parerr++;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_peu_handle_sys_errors: cpl_dataq_parerr"));
	}

	if (stat.bits.retryram_xdlh_parerr) {
		statsp->retryram_xdlh_parerr++;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_peu_handle_sys_errors: retryram_xdlh_parerr"));
	}

	if (stat.bits.retrysotram_xdlh_parerr) {
		statsp->retrysotram_xdlh_parerr++;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_peu_handle_sys_errors: retrysotram_xdlh_parerr"));
	}

	if (stat.bits.p_hdrq_parerr) {
		statsp->p_hdrq_parerr++;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_peu_handle_sys_errors: p_hdrq_parerr"));
	}

	if (stat.bits.p_dataq_parerr) {
		statsp->p_dataq_parerr++;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_peu_handle_sys_errors: p_dataq_parerr"));
	}

	if (stat.bits.np_hdrq_parerr) {
		statsp->np_hdrq_parerr++;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_peu_handle_sys_errors: np_hdrq_parerr"));
	}

	if (stat.bits.np_dataq_parerr) {
		statsp->np_dataq_parerr++;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_peu_handle_sys_errors: np_dataq_parerr"));
	}

	if (stat.bits.eic_msix_parerr) {
		statsp->eic_msix_parerr++;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_peu_handle_sys_errors: eic_msix_parerr"));
	}

	if (stat.bits.hcr_parerr) {
		statsp->hcr_parerr++;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_peu_handle_sys_errors: hcr_parerr"));
	}

	HXGE_FM_REPORT_ERROR(hxgep, NULL, HXGE_FM_EREPORT_PEU_ERR);
	return (HXGE_OK);
}

/*ARGSUSED*/
uint_t
hxge_syserr_intr(caddr_t arg1, caddr_t arg2)
{
	p_hxge_ldv_t	ldvp = (p_hxge_ldv_t)arg1;
	p_hxge_t	hxgep = (p_hxge_t)arg2;
	p_hxge_ldg_t	ldgp = NULL;
	hpi_handle_t	handle;
	dev_err_stat_t	estat;

	if ((arg1 == NULL) && (arg2 == NULL)) {
		return (DDI_INTR_UNCLAIMED);
	}

	if ((arg2 == NULL) ||
	    ((ldvp != NULL) && ((void *)ldvp->hxgep != arg2))) {
		if (ldvp != NULL) {
			hxgep = ldvp->hxgep;
		}
	}

	HXGE_DEBUG_MSG((hxgep, SYSERR_CTL,
	    "==> hxge_syserr_intr: arg2 $%p arg1 $%p", hxgep, ldvp));

	if (ldvp != NULL && ldvp->use_timer == B_FALSE) {
		ldgp = ldvp->ldgp;
		if (ldgp == NULL) {
			HXGE_ERROR_MSG((hxgep, SYSERR_CTL,
			    "<== hxge_syserrintr(no logical group): "
			    "arg2 $%p arg1 $%p", hxgep, ldvp));
			return (DDI_INTR_UNCLAIMED);
		}
	}

	/*
	 * This interrupt handler is for system error interrupts.
	 */
	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	estat.value = 0;
	(void) hpi_fzc_sys_err_stat_get(handle, &estat);
	HXGE_DEBUG_MSG((hxgep, SYSERR_CTL,
	    "==> hxge_syserr_intr: device error 0x%016llx", estat.value));

	if (estat.bits.tdc_err0 || estat.bits.tdc_err1) {
		/* TDMC */
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_syserr_intr: device error - TDMC"));
		(void) hxge_txdma_handle_sys_errors(hxgep);
	} else if (estat.bits.rdc_err0 || estat.bits.rdc_err1) {
		/* RDMC */
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_syserr_intr: device error - RDMC"));
		(void) hxge_rxdma_handle_sys_errors(hxgep);
	} else if (estat.bits.vnm_pio_err1 || estat.bits.peu_err1) {
		/* PCI-E */
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_syserr_intr: device error - PCI-E"));

		/* kstats are updated here */
		(void) hxge_peu_handle_sys_errors(hxgep);

		if (estat.bits.peu_err1)
			HXGE_FM_REPORT_ERROR(hxgep, NULL,
			    HXGE_FM_EREPORT_PEU_ERR);

		if (estat.bits.vnm_pio_err1)
			HXGE_FM_REPORT_ERROR(hxgep, NULL,
			    HXGE_FM_EREPORT_PEU_VNM_PIO_ERR);
	} else if (estat.value != 0) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_syserr_intr: device error - unknown"));
	}

	if ((ldgp != NULL) && (ldvp != NULL) &&
	    (ldgp->nldvs == 1) && !ldvp->use_timer) {
		(void) hpi_intr_ldg_mgmt_set(handle, ldgp->ldg,
		    B_TRUE, ldgp->ldg_timer);
	}

	HXGE_DEBUG_MSG((hxgep, SYSERR_CTL, "<== hxge_syserr_intr"));
	return (DDI_INTR_CLAIMED);
}

void
hxge_intr_hw_enable(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_intr_hw_enable"));

	(void) hxge_intr_mask_mgmt_set(hxgep, B_TRUE);

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_intr_hw_enable"));
}

void
hxge_intr_hw_disable(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_intr_hw_disable"));

	(void) hxge_intr_mask_mgmt_set(hxgep, B_FALSE);

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_intr_hw_disable"));
}

/*ARGSUSED*/
void
hxge_rx_hw_blank(void *arg, time_t ticks, uint_t count)
{
	p_hxge_t	hxgep = (p_hxge_t)arg;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_rx_hw_blank"));

	/*
	 * Replace current ticks and counts for later
	 * processing by the receive packet interrupt routines.
	 */
	hxgep->intr_timeout = (uint16_t)ticks;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_rx_hw_blank"));
}

void
hxge_hw_stop(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_hw_stop"));

	(void) hxge_tx_vmac_disable(hxgep);
	(void) hxge_rx_vmac_disable(hxgep);
	(void) hxge_txdma_hw_mode(hxgep, HXGE_DMA_STOP);
	(void) hxge_rxdma_hw_mode(hxgep, HXGE_DMA_STOP);

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_hw_stop"));
}

void
hxge_hw_ioctl(p_hxge_t hxgep, queue_t *wq, mblk_t *mp, struct iocblk *iocp)
{
	int cmd;

	HXGE_DEBUG_MSG((hxgep, IOC_CTL, "==> hxge_hw_ioctl"));

	if (hxgep == NULL) {
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	iocp->ioc_error = 0;
	cmd = iocp->ioc_cmd;

	switch (cmd) {
	default:
		miocnak(wq, mp, 0, EINVAL);
		return;

	case HXGE_PUT_TCAM:
		hxge_put_tcam(hxgep, mp->b_cont);
		miocack(wq, mp, 0, 0);
		break;

	case HXGE_GET_TCAM:
		hxge_get_tcam(hxgep, mp->b_cont);
		miocack(wq, mp, 0, 0);
		break;

	case HXGE_RTRACE:
		hxge_rtrace_ioctl(hxgep, wq, mp, iocp);
		break;
	}
}

/*
 * 10G is the only loopback mode for Hydra.
 */
void
hxge_loopback_ioctl(p_hxge_t hxgep, queue_t *wq, mblk_t *mp,
    struct iocblk *iocp)
{
	p_lb_property_t lb_props;
	size_t		size;
	int		i;

	if (mp->b_cont == NULL) {
		miocnak(wq, mp, 0, EINVAL);
	}

	switch (iocp->ioc_cmd) {
	case LB_GET_MODE:
		HXGE_DEBUG_MSG((hxgep, IOC_CTL, "HXGE_GET_LB_MODE command"));
		if (hxgep != NULL) {
			*(lb_info_sz_t *)mp->b_cont->b_rptr =
			    hxgep->statsp->port_stats.lb_mode;
			miocack(wq, mp, sizeof (hxge_lb_t), 0);
		} else
			miocnak(wq, mp, 0, EINVAL);
		break;

	case LB_SET_MODE:
		HXGE_DEBUG_MSG((hxgep, IOC_CTL, "HXGE_SET_LB_MODE command"));
		if (iocp->ioc_count != sizeof (uint32_t)) {
			miocack(wq, mp, 0, 0);
			break;
		}
		if ((hxgep != NULL) && hxge_set_lb(hxgep, wq, mp->b_cont)) {
			miocack(wq, mp, 0, 0);
		} else {
			miocnak(wq, mp, 0, EPROTO);
		}
		break;

	case LB_GET_INFO_SIZE:
		HXGE_DEBUG_MSG((hxgep, IOC_CTL, "LB_GET_INFO_SIZE command"));
		if (hxgep != NULL) {
			size = sizeof (lb_normal) + sizeof (lb_mac10g);

			*(lb_info_sz_t *)mp->b_cont->b_rptr = size;

			HXGE_DEBUG_MSG((hxgep, IOC_CTL,
			    "HXGE_GET_LB_INFO command: size %d", size));
			miocack(wq, mp, sizeof (lb_info_sz_t), 0);
		} else
			miocnak(wq, mp, 0, EINVAL);
		break;

	case LB_GET_INFO:
		HXGE_DEBUG_MSG((hxgep, IOC_CTL, "HXGE_GET_LB_INFO command"));
		if (hxgep != NULL) {
			size = sizeof (lb_normal) + sizeof (lb_mac10g);
			HXGE_DEBUG_MSG((hxgep, IOC_CTL,
			    "HXGE_GET_LB_INFO command: size %d", size));
			if (size == iocp->ioc_count) {
				i = 0;
				lb_props = (p_lb_property_t)mp->b_cont->b_rptr;
				lb_props[i++] = lb_normal;
				lb_props[i++] = lb_mac10g;

				miocack(wq, mp, size, 0);
			} else
				miocnak(wq, mp, 0, EINVAL);
		} else {
			miocnak(wq, mp, 0, EINVAL);
			cmn_err(CE_NOTE, "hxge_hw_ioctl: invalid command 0x%x",
			    iocp->ioc_cmd);
		}

		break;
	}
}

/*ARGSUSED*/
boolean_t
hxge_set_lb(p_hxge_t hxgep, queue_t *wq, p_mblk_t mp)
{
	boolean_t	status = B_TRUE;
	uint32_t	lb_mode;
	lb_property_t	*lb_info;

	HXGE_DEBUG_MSG((hxgep, IOC_CTL, "<== hxge_set_lb"));
	lb_mode = hxgep->statsp->port_stats.lb_mode;
	if (lb_mode == *(uint32_t *)mp->b_rptr) {
		cmn_err(CE_NOTE,
		    "hxge%d: Loopback mode already set (lb_mode %d).\n",
		    hxgep->instance, lb_mode);
		status = B_FALSE;
		goto hxge_set_lb_exit;
	}

	lb_mode = *(uint32_t *)mp->b_rptr;
	lb_info = NULL;

	/* 10G is the only loopback mode for Hydra */
	if (lb_mode == lb_normal.value)
		lb_info = &lb_normal;
	else if (lb_mode == lb_mac10g.value)
		lb_info = &lb_mac10g;
	else {
		cmn_err(CE_NOTE,
		    "hxge%d: Loopback mode not supported(mode %d).\n",
		    hxgep->instance, lb_mode);
		status = B_FALSE;
		goto hxge_set_lb_exit;
	}

	if (lb_mode == hxge_lb_normal) {
		if (hxge_lb_dbg) {
			cmn_err(CE_NOTE,
			    "!hxge%d: Returning to normal operation",
			    hxgep->instance);
		}

		hxgep->statsp->port_stats.lb_mode = hxge_lb_normal;
		hxge_global_reset(hxgep);

		goto hxge_set_lb_exit;
	}

	hxgep->statsp->port_stats.lb_mode = lb_mode;

	if (hxge_lb_dbg)
		cmn_err(CE_NOTE, "!hxge%d: Adapter now in %s loopback mode",
		    hxgep->instance, lb_info->key);

	if (lb_info->lb_type == internal) {
		if ((hxgep->statsp->port_stats.lb_mode == hxge_lb_mac10g))
			hxgep->statsp->mac_stats.link_speed = 10000;
		else {
			cmn_err(CE_NOTE,
			    "hxge%d: Loopback mode not supported(mode %d).\n",
			    hxgep->instance, lb_mode);
			status = B_FALSE;
			goto hxge_set_lb_exit;
		}
		hxgep->statsp->mac_stats.link_duplex = 2;
		hxgep->statsp->mac_stats.link_up = 1;
	}

	hxge_global_reset(hxgep);

hxge_set_lb_exit:
	HXGE_DEBUG_MSG((hxgep, DDI_CTL,
	    "<== hxge_set_lb status = 0x%08x", status));

	return (status);
}

void
hxge_check_hw_state(p_hxge_t hxgep)
{
	p_hxge_ldgv_t		ldgvp;
	p_hxge_ldv_t		t_ldvp;

	HXGE_DEBUG_MSG((hxgep, SYSERR_CTL, "==> hxge_check_hw_state"));

	MUTEX_ENTER(hxgep->genlock);

	hxgep->hxge_timerid = 0;
	if (!(hxgep->drv_state & STATE_HW_INITIALIZED)) {
		goto hxge_check_hw_state_exit;
	}

	hxge_check_tx_hang(hxgep);

	ldgvp = hxgep->ldgvp;
	if (ldgvp == NULL || (ldgvp->ldvp_syserr == NULL)) {
		HXGE_ERROR_MSG((hxgep, SYSERR_CTL, "<== hxge_check_hw_state: "
		    "NULL ldgvp (interrupt not ready)."));
		goto hxge_check_hw_state_exit;
	}

	t_ldvp = ldgvp->ldvp_syserr;
	if (!t_ldvp->use_timer) {
		HXGE_DEBUG_MSG((hxgep, SYSERR_CTL, "<== hxge_check_hw_state: "
		    "ldgvp $%p t_ldvp $%p use_timer flag %d",
		    ldgvp, t_ldvp, t_ldvp->use_timer));
		goto hxge_check_hw_state_exit;
	}

	if (fm_check_acc_handle(hxgep->dev_regs->hxge_regh) != DDI_FM_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "Bad register acc handle"));
	}

	(void) hxge_syserr_intr((caddr_t)t_ldvp, (caddr_t)hxgep);

	hxgep->hxge_timerid = hxge_start_timer(hxgep, hxge_check_hw_state,
	    HXGE_CHECK_TIMER);

hxge_check_hw_state_exit:
	MUTEX_EXIT(hxgep->genlock);

	HXGE_DEBUG_MSG((hxgep, SYSERR_CTL, "<== hxge_check_hw_state"));
}

/*ARGSUSED*/
static void
hxge_rtrace_ioctl(p_hxge_t hxgep, queue_t *wq, mblk_t *mp,
    struct iocblk *iocp)
{
	ssize_t		size;
	rtrace_t	*rtp;
	mblk_t		*nmp;
	uint32_t	i, j;
	uint32_t	start_blk;
	uint32_t	base_entry;
	uint32_t	num_entries;

	HXGE_DEBUG_MSG((hxgep, STR_CTL, "==> hxge_rtrace_ioctl"));

	size = 1024;
	if (mp->b_cont == NULL || MBLKL(mp->b_cont) < size) {
		HXGE_DEBUG_MSG((hxgep, STR_CTL,
		    "malformed M_IOCTL MBLKL = %d size = %d",
		    MBLKL(mp->b_cont), size));
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	nmp = mp->b_cont;
	rtp = (rtrace_t *)nmp->b_rptr;
	start_blk = rtp->next_idx;
	num_entries = rtp->last_idx;
	base_entry = start_blk * MAX_RTRACE_IOC_ENTRIES;

	HXGE_DEBUG_MSG((hxgep, STR_CTL, "start_blk = %d\n", start_blk));
	HXGE_DEBUG_MSG((hxgep, STR_CTL, "num_entries = %d\n", num_entries));
	HXGE_DEBUG_MSG((hxgep, STR_CTL, "base_entry = %d\n", base_entry));

	rtp->next_idx = hpi_rtracebuf.next_idx;
	rtp->last_idx = hpi_rtracebuf.last_idx;
	rtp->wrapped = hpi_rtracebuf.wrapped;
	for (i = 0, j = base_entry; i < num_entries; i++, j++) {
		rtp->buf[i].ctl_addr = hpi_rtracebuf.buf[j].ctl_addr;
		rtp->buf[i].val_l32 = hpi_rtracebuf.buf[j].val_l32;
		rtp->buf[i].val_h32 = hpi_rtracebuf.buf[j].val_h32;
	}

	nmp->b_wptr = nmp->b_rptr + size;
	HXGE_DEBUG_MSG((hxgep, STR_CTL, "<== hxge_rtrace_ioctl"));
	miocack(wq, mp, (int)size, 0);
}
