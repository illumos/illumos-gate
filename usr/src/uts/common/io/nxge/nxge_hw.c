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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/nxge/nxge_impl.h>

/*
 * Tunable Receive Completion Ring Configuration B parameters.
 */
uint16_t nxge_rx_pkt_thres;	/* 16 bits */
uint8_t nxge_rx_pkt_timeout;	/* 6 bits based on DMA clock divider */

lb_property_t lb_normal = {normal, "normal", nxge_lb_normal};
lb_property_t lb_external10g = {external, "external10g", nxge_lb_ext10g};
lb_property_t lb_external1000 = {external, "external1000", nxge_lb_ext1000};
lb_property_t lb_external100 = {external, "external100", nxge_lb_ext100};
lb_property_t lb_external10 = {external, "external10", nxge_lb_ext10};
lb_property_t lb_phy10g = {internal, "phy10g", nxge_lb_phy10g};
lb_property_t lb_phy1000 = {internal, "phy1000", nxge_lb_phy1000};
lb_property_t lb_phy = {internal, "phy", nxge_lb_phy};
lb_property_t lb_serdes10g = {internal, "serdes10g", nxge_lb_serdes10g};
lb_property_t lb_serdes1000 = {internal, "serdes", nxge_lb_serdes1000};
lb_property_t lb_mac10g = {internal, "mac10g", nxge_lb_mac10g};
lb_property_t lb_mac1000 = {internal, "mac1000", nxge_lb_mac1000};
lb_property_t lb_mac = {internal, "mac10/100", nxge_lb_mac};

uint32_t nxge_lb_dbg = 1;
void nxge_get_mii(p_nxge_t nxgep, p_mblk_t mp);
void nxge_put_mii(p_nxge_t nxgep, p_mblk_t mp);
static nxge_status_t nxge_check_xaui_xfp(p_nxge_t nxgep);

extern uint32_t nxge_rx_mode;
extern uint32_t nxge_jumbo_mtu;
extern uint16_t	nxge_rdc_buf_offset;

static void
nxge_rtrace_ioctl(p_nxge_t, queue_t *, mblk_t *, struct iocblk *);

/* ARGSUSED */
nxge_status_t
nxge_global_reset(p_nxge_t nxgep)
{
	nxge_status_t	status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_global_reset"));

	if ((status = nxge_link_monitor(nxgep, LINK_MONITOR_STOP)) != NXGE_OK)
		return (status);
	(void) nxge_intr_hw_disable(nxgep);

	if ((nxgep->suspended) ||
	    ((nxgep->statsp->port_stats.lb_mode ==
	    nxge_lb_phy1000) ||
	    (nxgep->statsp->port_stats.lb_mode ==
	    nxge_lb_phy10g) ||
	    (nxgep->statsp->port_stats.lb_mode ==
	    nxge_lb_serdes1000) ||
	    (nxgep->statsp->port_stats.lb_mode ==
	    nxge_lb_serdes10g))) {
		if ((status = nxge_link_init(nxgep)) != NXGE_OK)
			return (status);
	}

	if ((status = nxge_link_monitor(nxgep, LINK_MONITOR_START)) != NXGE_OK)
		return (status);
	if ((status = nxge_mac_init(nxgep)) != NXGE_OK)
		return (status);
	(void) nxge_intr_hw_enable(nxgep);

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_global_reset"));
	return (status);
}

/* ARGSUSED */
void
nxge_hw_id_init(p_nxge_t nxgep)
{
	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_hw_id_init"));

	/*
	 * Set up initial hardware parameters required such as mac mtu size.
	 */
	nxgep->mac.is_jumbo = B_FALSE;

	/*
	 * Set the maxframe size to 1522 (1518 + 4) to account for
	 * VLAN tagged packets.
	 */
	nxgep->mac.minframesize = NXGE_MIN_MAC_FRAMESIZE;	/* 64 */
	nxgep->mac.maxframesize = NXGE_MAX_MAC_FRAMESIZE;	/* 1522 */

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_hw_id_init: maxframesize %d",
	    nxgep->mac.maxframesize));
	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_hw_id_init"));
}

/* ARGSUSED */
void
nxge_hw_init_niu_common(p_nxge_t nxgep)
{
	p_nxge_hw_list_t hw_p;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_hw_init_niu_common"));

	if ((hw_p = nxgep->nxge_hw_p) == NULL) {
		return;
	}
	MUTEX_ENTER(&hw_p->nxge_cfg_lock);
	if (hw_p->flags & COMMON_INIT_DONE) {
		NXGE_DEBUG_MSG((nxgep, MOD_CTL,
		    "nxge_hw_init_niu_common"
		    " already done for dip $%p function %d exiting",
		    hw_p->parent_devp, nxgep->function_num));
		MUTEX_EXIT(&hw_p->nxge_cfg_lock);
		return;
	}

	hw_p->flags = COMMON_INIT_START;
	NXGE_DEBUG_MSG((nxgep, MOD_CTL, "nxge_hw_init_niu_common"
	    " Started for device id %x with function %d",
	    hw_p->parent_devp, nxgep->function_num));

	/* per neptune common block init */
	(void) nxge_fflp_hw_reset(nxgep);

	if (nxgep->niu_hw_type != NIU_HW_TYPE_RF) {
		switch (nxge_rdc_buf_offset) {
		case SW_OFFSET_NO_OFFSET:
		case SW_OFFSET_64:
		case SW_OFFSET_128:
			break;
		default:
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_hw_init_niu_common: Unsupported RDC buffer"
			    " offset code %d, setting to %d",
			    nxge_rdc_buf_offset, SW_OFFSET_NO_OFFSET));
			nxge_rdc_buf_offset = SW_OFFSET_NO_OFFSET;
			break;
		}
	} else {
		switch (nxge_rdc_buf_offset) {
		case SW_OFFSET_NO_OFFSET:
		case SW_OFFSET_64:
		case SW_OFFSET_128:
		case SW_OFFSET_192:
		case SW_OFFSET_256:
		case SW_OFFSET_320:
		case SW_OFFSET_384:
		case SW_OFFSET_448:
			break;
		default:
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_hw_init_niu_common: Unsupported RDC buffer"
			    " offset code %d, setting to %d",
			    nxge_rdc_buf_offset, SW_OFFSET_NO_OFFSET));
			nxge_rdc_buf_offset = SW_OFFSET_NO_OFFSET;
			break;
		}
	}

	hw_p->flags = COMMON_INIT_DONE;
	MUTEX_EXIT(&hw_p->nxge_cfg_lock);

	NXGE_DEBUG_MSG((nxgep, MOD_CTL, "nxge_hw_init_niu_common"
	    " Done for device id %x with function %d",
	    hw_p->parent_devp, nxgep->function_num));
	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_hw_init_niu_common"));
}

/* ARGSUSED */
uint_t
nxge_intr(void *arg1, void *arg2)
{
	p_nxge_ldv_t ldvp = (p_nxge_ldv_t)arg1;
	p_nxge_t nxgep = (p_nxge_t)arg2;
	uint_t serviced = DDI_INTR_UNCLAIMED;
	uint8_t ldv;
	npi_handle_t handle;
	p_nxge_ldgv_t ldgvp;
	p_nxge_ldg_t ldgp, t_ldgp;
	p_nxge_ldv_t t_ldvp;
	uint64_t vector0 = 0, vector1 = 0, vector2 = 0;
	int i, j, nldvs, nintrs = 1;
	npi_status_t rs = NPI_SUCCESS;

	/* DDI interface returns second arg as NULL (n2 niumx driver) !!! */
	if (arg2 == NULL || (void *) ldvp->nxgep != arg2) {
		nxgep = ldvp->nxgep;
	}
	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_intr"));

	if (!(nxgep->drv_state & STATE_HW_INITIALIZED)) {
		NXGE_ERROR_MSG((nxgep, INT_CTL,
		    "<== nxge_intr: not initialized 0x%x", serviced));
		return (serviced);
	}

	ldgvp = nxgep->ldgvp;
	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_intr: ldgvp $%p", ldgvp));
	if (ldvp == NULL && ldgvp) {
		t_ldvp = ldvp = ldgvp->ldvp;
	}
	if (ldvp) {
		ldgp = t_ldgp = ldvp->ldgp;
	}
	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_intr: "
	    "ldgvp $%p ldvp $%p ldgp $%p", ldgvp, ldvp, ldgp));
	if (ldgvp == NULL || ldvp == NULL || ldgp == NULL) {
		NXGE_ERROR_MSG((nxgep, INT_CTL, "==> nxge_intr: "
		    "ldgvp $%p ldvp $%p ldgp $%p", ldgvp, ldvp, ldgp));
		NXGE_ERROR_MSG((nxgep, INT_CTL, "<== nxge_intr: not ready"));
		return (DDI_INTR_UNCLAIMED);
	}
	/*
	 * This interrupt handler will have to go through all the logical
	 * devices to find out which logical device interrupts us and then call
	 * its handler to process the events.
	 */
	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	t_ldgp = ldgp;
	t_ldvp = ldgp->ldvp;

	nldvs = ldgp->nldvs;

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_intr: #ldvs %d #intrs %d",
	    nldvs, ldgvp->ldg_intrs));

	serviced = DDI_INTR_CLAIMED;
	for (i = 0; i < nintrs; i++, t_ldgp++) {
		NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_intr(%d): #ldvs %d "
		    " #intrs %d", i, nldvs, nintrs));
		/* Get this group's flag bits.  */
		rs = npi_ldsv_ldfs_get(handle, t_ldgp->ldg,
		    &vector0, &vector1, &vector2);
		if (rs) {
			continue;
		}
		if (!vector0 && !vector1 && !vector2) {
			NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_intr: "
			    "no interrupts on group %d", t_ldgp->ldg));
			continue;
		}
		NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_intr: "
		    "vector0 0x%llx vector1 0x%llx vector2 0x%llx",
		    vector0, vector1, vector2));
		nldvs = t_ldgp->nldvs;
		for (j = 0; j < nldvs; j++, t_ldvp++) {
			/*
			 * Call device's handler if flag bits are on.
			 */
			ldv = t_ldvp->ldv;
			if (((ldv < NXGE_MAC_LD_START) &&
			    (LDV_ON(ldv, vector0) |
			    (LDV_ON(ldv, vector1)))) ||
			    (ldv >= NXGE_MAC_LD_START &&
			    ((LDV2_ON_1(ldv, vector2)) ||
			    (LDV2_ON_2(ldv, vector2))))) {
				(void) (t_ldvp->ldv_intr_handler)(
				    (caddr_t)t_ldvp, arg2);
				NXGE_DEBUG_MSG((nxgep, INT_CTL,
				    "==> nxge_intr: "
				    "calling device %d #ldvs %d #intrs %d",
				    j, nldvs, nintrs));
			}
		}
	}

	t_ldgp = ldgp;
	for (i = 0; i < nintrs; i++, t_ldgp++) {
		/* rearm group interrupts */
		NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_intr: arm "
		    "group %d", t_ldgp->ldg));
		(void) npi_intr_ldg_mgmt_set(handle, t_ldgp->ldg,
		    t_ldgp->arm, t_ldgp->ldg_timer);
	}

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_intr: serviced 0x%x",
	    serviced));
	return (serviced);
}


/*
 * XFP Related Status Register Values Under 3 Different Conditions
 *
 * -------------+-------------------------+-------------------------
 * 		|   Intel XFP and Avago   |	 Picolight XFP
 * -------------+---------+---------------+---------+---------------
 *		| STATUS0 | TX_ALARM_STAT | STATUS0 | TX_ALARM_STAT
 * -------------+---------+---------------+---------+---------------
 *	No XFP  | 0x639C  |      0x40     | 0x639C  |      0x40
 * -------------+---------+---------------+---------+---------------
 * XFP,linkdown | 0x43BC  |      0x40     | 0x639C  |      0x40
 * -------------+---------+---------------+---------+---------------
 * XFP,linkup   | 0x03FC  |      0x0      | 0x03FC  |      0x0
 * -------------+---------+---------------+---------+---------------
 * Note:
 *      STATUS0         = BCM8704_USER_ANALOG_STATUS0_REG
 *      TX_ALARM_STAT   = BCM8704_USER_TX_ALARM_STATUS_REG
 */
/* ARGSUSED */
static nxge_status_t
nxge_check_xaui_xfp(p_nxge_t nxgep)
{
	nxge_status_t	status = NXGE_OK;
	uint8_t		phy_port_addr;
	uint16_t	val;
	uint16_t	val1;
	uint8_t		portn;

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_check_xaui_xfp"));

	portn = nxgep->mac.portnum;
	phy_port_addr = nxgep->statsp->mac_stats.xcvr_portn;

	/*
	 * Keep the val1 code even though it is not used. Could be
	 * used to differenciate the "No XFP" case and "XFP,linkdown"
	 * case when a Intel XFP is used.
	 */
	if ((status = nxge_mdio_read(nxgep, phy_port_addr,
	    BCM8704_USER_DEV3_ADDR,
	    BCM8704_USER_ANALOG_STATUS0_REG, &val)) == NXGE_OK) {
		status = nxge_mdio_read(nxgep, phy_port_addr,
		    BCM8704_USER_DEV3_ADDR,
		    BCM8704_USER_TX_ALARM_STATUS_REG, &val1);
	}

	if (status != NXGE_OK) {
		NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
		    NXGE_FM_EREPORT_XAUI_ERR);
		if (DDI_FM_EREPORT_CAP(nxgep->fm_capabilities)) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "XAUI is bad or absent on port<%d>\n", portn));
		}
#ifdef NXGE_DEBUG
	/*
	 * As a workaround for CR6693529, do not execute this block of
	 * code for non-debug driver. When a Picolight XFP transceiver
	 * is used, register BCM8704_USER_ANALOG_STATUS0_REG returns
	 * the same 0x639C value in normal link down case, which causes
	 * false FMA messages and link reconnection problem.
	 */
	} else if (nxgep->mac.portmode == PORT_10G_FIBER) {
		/*
		 * 0x03FC = 0000 0011 1111 1100 (XFP is normal)
		 * 0x639C = 0110 0011 1001 1100 (XFP has problem)
		 * bit14 = 1: PDM loss-of-light indicator
		 * bit13 = 1: PDM Rx loss-of-signal
		 * bit6  = 0: Light is NOT ok
		 * bit5  = 0: PMD Rx signal is NOT ok
		 */
		if (val == 0x639C) {
			NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
			    NXGE_FM_EREPORT_XFP_ERR);
			if (DDI_FM_EREPORT_CAP(nxgep->fm_capabilities)) {
				NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				    "XFP is bad or absent on port<%d>\n",
				    portn));
			}
			status = NXGE_ERROR;
		}
#endif
	}
	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_check_xaui_xfp"));
	return (status);
}


/* ARGSUSED */
uint_t
nxge_syserr_intr(void *arg1, void *arg2)
{
	p_nxge_ldv_t ldvp = (p_nxge_ldv_t)arg1;
	p_nxge_t nxgep = (p_nxge_t)arg2;
	p_nxge_ldg_t ldgp = NULL;
	npi_handle_t handle;
	sys_err_stat_t estat;
	uint_t serviced = DDI_INTR_UNCLAIMED;

	if (arg1 == NULL && arg2 == NULL) {
		return (serviced);
	}
	if (arg2 == NULL || ((ldvp != NULL && (void *) ldvp->nxgep != arg2))) {
		if (ldvp != NULL) {
			nxgep = ldvp->nxgep;
		}
	}
	NXGE_DEBUG_MSG((nxgep, SYSERR_CTL,
	    "==> nxge_syserr_intr: arg2 $%p arg1 $%p", nxgep, ldvp));
	if (ldvp != NULL && ldvp->use_timer == B_FALSE) {
		ldgp = ldvp->ldgp;
		if (ldgp == NULL) {
			NXGE_ERROR_MSG((nxgep, SYSERR_CTL,
			    "<== nxge_syserrintr(no logical group): "
			    "arg2 $%p arg1 $%p", nxgep, ldvp));
			return (DDI_INTR_UNCLAIMED);
		}
		/*
		 * Get the logical device state if the function uses interrupt.
		 */
	}

	/* This interrupt handler is for system error interrupts.  */
	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	estat.value = 0;
	(void) npi_fzc_sys_err_stat_get(handle, &estat);
	NXGE_DEBUG_MSG((nxgep, SYSERR_CTL,
	    "==> nxge_syserr_intr: device error 0x%016llx", estat.value));

	if (estat.bits.ldw.smx) {
		/* SMX */
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "==> nxge_syserr_intr: device error - SMX"));
	} else if (estat.bits.ldw.mac) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "==> nxge_syserr_intr: device error - MAC"));
		/*
		 * There is nothing to be done here. All MAC errors go to per
		 * MAC port interrupt. MIF interrupt is the only MAC sub-block
		 * that can generate status here. MIF status reported will be
		 * ignored here. It is checked by per port timer instead.
		 */
	} else if (estat.bits.ldw.ipp) {
		NXGE_DEBUG_MSG((nxgep, NXGE_ERR_CTL,
		    "==> nxge_syserr_intr: device error - IPP"));
		(void) nxge_ipp_handle_sys_errors(nxgep);
	} else if (estat.bits.ldw.zcp) {
		/* ZCP */
		NXGE_DEBUG_MSG((nxgep, NXGE_ERR_CTL,
		    "==> nxge_syserr_intr: device error - ZCP"));
		(void) nxge_zcp_handle_sys_errors(nxgep);
	} else if (estat.bits.ldw.tdmc) {
		/* TDMC */
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "==> nxge_syserr_intr: device error - TDMC"));
		/*
		 * There is no TDMC system errors defined in the PRM. All TDMC
		 * channel specific errors are reported on a per channel basis.
		 */
	} else if (estat.bits.ldw.rdmc) {
		/* RDMC */
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "==> nxge_syserr_intr: device error - RDMC"));
		(void) nxge_rxdma_handle_sys_errors(nxgep);
	} else if (estat.bits.ldw.txc) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "==> nxge_syserr_intr: device error - TXC"));
		(void) nxge_txc_handle_sys_errors(nxgep);
	} else if ((nxgep->niu_type != N2_NIU) && estat.bits.ldw.peu) {
		/* PCI-E */
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "==> nxge_syserr_intr: device error - PCI-E"));
	} else if (estat.bits.ldw.meta1) {
		/* META1 */
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "==> nxge_syserr_intr: device error - META1"));
	} else if (estat.bits.ldw.meta2) {
		/* META2 */
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "==> nxge_syserr_intr: device error - META2"));
	} else if (estat.bits.ldw.fflp) {
		/* FFLP */
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "==> nxge_syserr_intr: device error - FFLP"));
		(void) nxge_fflp_handle_sys_errors(nxgep);
	}

	/*
	 * nxge_check_xaui_xfg checks XAUI for all of the following
	 * portmodes, but checks XFP only if portmode == PORT_10G_FIBER.
	 */
	if (nxgep->mac.portmode == PORT_10G_FIBER ||
	    nxgep->mac.portmode == PORT_10G_COPPER ||
	    nxgep->mac.portmode == PORT_10G_TN1010 ||
	    nxgep->mac.portmode == PORT_1G_TN1010) {
		if (nxge_check_xaui_xfp(nxgep) != NXGE_OK) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "==> nxge_syserr_intr: device error - XAUI"));
		}
	}

	serviced = DDI_INTR_CLAIMED;

	if (ldgp != NULL && ldvp != NULL && ldgp->nldvs == 1 &&
	    !ldvp->use_timer) {
		(void) npi_intr_ldg_mgmt_set(handle, ldgp->ldg,
		    B_TRUE, ldgp->ldg_timer);
	}
	NXGE_DEBUG_MSG((nxgep, SYSERR_CTL, "<== nxge_syserr_intr"));
	return (serviced);
}

/* ARGSUSED */
void
nxge_intr_hw_enable(p_nxge_t nxgep)
{
	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_intr_hw_enable"));
	(void) nxge_intr_mask_mgmt_set(nxgep, B_TRUE);
	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_intr_hw_enable"));
}

/* ARGSUSED */
void
nxge_intr_hw_disable(p_nxge_t nxgep)
{
	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_intr_hw_disable"));
	(void) nxge_intr_mask_mgmt_set(nxgep, B_FALSE);
	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_intr_hw_disable"));
}

/* ARGSUSED */
void
nxge_rx_hw_blank(void *arg, time_t ticks, uint_t count)
{
	p_nxge_t nxgep = (p_nxge_t)arg;
	uint8_t channel;
	npi_handle_t handle;
	p_nxge_ldgv_t ldgvp;
	p_nxge_ldv_t ldvp;
	int i;

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_rx_hw_blank"));
	handle = NXGE_DEV_NPI_HANDLE(nxgep);

	if ((ldgvp = nxgep->ldgvp) == NULL) {
		NXGE_ERROR_MSG((nxgep, INT_CTL,
		    "<== nxge_rx_hw_blank (not enabled)"));
		return;
	}
	ldvp = nxgep->ldgvp->ldvp;
	if (ldvp == NULL) {
		return;
	}
	for (i = 0; i < ldgvp->nldvs; i++, ldvp++) {
		if (ldvp->is_rxdma) {
			channel = ldvp->channel;
			(void) npi_rxdma_cfg_rdc_rcr_threshold(handle,
			    channel, count);
			(void) npi_rxdma_cfg_rdc_rcr_timeout(handle,
			    channel, ticks);
		}
	}

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_rx_hw_blank"));
}

/* ARGSUSED */
void
nxge_hw_stop(p_nxge_t nxgep)
{
	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_hw_stop"));

	(void) nxge_tx_mac_disable(nxgep);
	(void) nxge_rx_mac_disable(nxgep);
	(void) nxge_txdma_hw_mode(nxgep, NXGE_DMA_STOP);
	(void) nxge_rxdma_hw_mode(nxgep, NXGE_DMA_STOP);

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_hw_stop"));
}

/* ARGSUSED */
void
nxge_hw_ioctl(p_nxge_t nxgep, queue_t *wq, mblk_t *mp, struct iocblk *iocp)
{
	int cmd;

	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "==> nxge_hw_ioctl"));

	if (nxgep == NULL) {
		miocnak(wq, mp, 0, EINVAL);
		return;
	}
	iocp->ioc_error = 0;
	cmd = iocp->ioc_cmd;

	switch (cmd) {
	default:
		miocnak(wq, mp, 0, EINVAL);
		return;

	case NXGE_GET_MII:
		nxge_get_mii(nxgep, mp->b_cont);
		miocack(wq, mp, sizeof (uint16_t), 0);
		break;

	case NXGE_PUT_MII:
		nxge_put_mii(nxgep, mp->b_cont);
		miocack(wq, mp, 0, 0);
		break;

	case NXGE_GET64:
		nxge_get64(nxgep, mp->b_cont);
		miocack(wq, mp, sizeof (uint32_t), 0);
		break;

	case NXGE_PUT64:
		nxge_put64(nxgep, mp->b_cont);
		miocack(wq, mp, 0, 0);
		break;

	case NXGE_PUT_TCAM:
		nxge_put_tcam(nxgep, mp->b_cont);
		miocack(wq, mp, 0, 0);
		break;

	case NXGE_GET_TCAM:
		nxge_get_tcam(nxgep, mp->b_cont);
		miocack(wq, mp, 0, 0);
		break;

	case NXGE_TX_REGS_DUMP:
		nxge_txdma_regs_dump_channels(nxgep);
		miocack(wq, mp, 0, 0);
		break;
	case NXGE_RX_REGS_DUMP:
		nxge_rxdma_regs_dump_channels(nxgep);
		miocack(wq, mp, 0, 0);
		break;
	case NXGE_VIR_INT_REGS_DUMP:
	case NXGE_INT_REGS_DUMP:
		nxge_virint_regs_dump(nxgep);
		miocack(wq, mp, 0, 0);
		break;
	case NXGE_RTRACE:
		nxge_rtrace_ioctl(nxgep, wq, mp, iocp);
		break;
	}
}

/* ARGSUSED */
void
nxge_loopback_ioctl(p_nxge_t nxgep, queue_t *wq, mblk_t *mp,
	struct iocblk *iocp)
{
	p_lb_property_t lb_props;

	size_t size;
	int i;

	if (mp->b_cont == NULL) {
		miocnak(wq, mp, 0, EINVAL);
	}
	switch (iocp->ioc_cmd) {
	case LB_GET_MODE:
		NXGE_DEBUG_MSG((nxgep, IOC_CTL, "NXGE_GET_LB_MODE command"));
		if (nxgep != NULL) {
			*(lb_info_sz_t *)mp->b_cont->b_rptr =
			    nxgep->statsp->port_stats.lb_mode;
			miocack(wq, mp, sizeof (nxge_lb_t), 0);
		} else {
			miocnak(wq, mp, 0, EINVAL);
		}
		break;
	case LB_SET_MODE:
		NXGE_DEBUG_MSG((nxgep, IOC_CTL, "NXGE_SET_LB_MODE command"));
		if (iocp->ioc_count != sizeof (uint32_t)) {
			miocack(wq, mp, 0, 0);
			break;
		}
		if ((nxgep != NULL) && nxge_set_lb(nxgep, wq, mp->b_cont)) {
			miocack(wq, mp, 0, 0);
		} else {
			miocnak(wq, mp, 0, EPROTO);
		}
		break;
	case LB_GET_INFO_SIZE:
		NXGE_DEBUG_MSG((nxgep, IOC_CTL, "LB_GET_INFO_SIZE command"));
		if (nxgep != NULL) {
			size = sizeof (lb_normal);
			if (nxgep->statsp->mac_stats.cap_10gfdx) {
				/* TN1010 does not support external loopback */
				if (nxgep->mac.portmode != PORT_1G_TN1010 &&
				    nxgep->mac.portmode != PORT_10G_TN1010) {
					size += sizeof (lb_external10g);
				}
				size += sizeof (lb_mac10g);
				/* Publish PHY loopback if PHY is present */
				if (nxgep->mac.portmode == PORT_10G_COPPER ||
				    nxgep->mac.portmode == PORT_10G_TN1010 ||
				    nxgep->mac.portmode == PORT_10G_FIBER)
					size += sizeof (lb_phy10g);
			}

			/*
			 * Even if cap_10gfdx is false, we still do 10G
			 * serdes loopback as a part of SunVTS xnetlbtest
			 * internal loopback test.
			 */
			if (nxgep->mac.portmode == PORT_10G_FIBER ||
			    nxgep->mac.portmode == PORT_10G_COPPER ||
			    nxgep->mac.portmode == PORT_10G_TN1010 ||
			    nxgep->mac.portmode == PORT_10G_SERDES)
				size += sizeof (lb_serdes10g);

			if (nxgep->statsp->mac_stats.cap_1000fdx) {
				/* TN1010 does not support external loopback */
				if (nxgep->mac.portmode != PORT_1G_TN1010 &&
				    nxgep->mac.portmode != PORT_10G_TN1010) {
					size += sizeof (lb_external1000);
				}
				size += sizeof (lb_mac1000);
				if (nxgep->mac.portmode == PORT_1G_COPPER ||
				    nxgep->mac.portmode == PORT_1G_TN1010 ||
				    nxgep->mac.portmode ==
				    PORT_1G_RGMII_FIBER)
					size += sizeof (lb_phy1000);
			}
			if (nxgep->statsp->mac_stats.cap_100fdx)
				size += sizeof (lb_external100);
			if (nxgep->statsp->mac_stats.cap_10fdx)
				size += sizeof (lb_external10);
			if (nxgep->mac.portmode == PORT_1G_FIBER ||
			    nxgep->mac.portmode == PORT_1G_TN1010 ||
			    nxgep->mac.portmode == PORT_1G_SERDES)
				size += sizeof (lb_serdes1000);

			*(lb_info_sz_t *)mp->b_cont->b_rptr = size;

			NXGE_DEBUG_MSG((nxgep, IOC_CTL,
			    "NXGE_GET_LB_INFO command: size %d", size));
			miocack(wq, mp, sizeof (lb_info_sz_t), 0);
		} else
			miocnak(wq, mp, 0, EINVAL);
		break;

	case LB_GET_INFO:
		NXGE_DEBUG_MSG((nxgep, IOC_CTL, "NXGE_GET_LB_INFO command"));
		if (nxgep != NULL) {
			size = sizeof (lb_normal);
			if (nxgep->statsp->mac_stats.cap_10gfdx) {
				/* TN1010 does not support external loopback */
				if (nxgep->mac.portmode != PORT_1G_TN1010 &&
				    nxgep->mac.portmode != PORT_10G_TN1010) {
					size += sizeof (lb_external10g);
				}
				size += sizeof (lb_mac10g);
				/* Publish PHY loopback if PHY is present */
				if (nxgep->mac.portmode == PORT_10G_COPPER ||
				    nxgep->mac.portmode == PORT_10G_TN1010 ||
				    nxgep->mac.portmode == PORT_10G_FIBER)
					size += sizeof (lb_phy10g);
			}
			if (nxgep->mac.portmode == PORT_10G_FIBER ||
			    nxgep->mac.portmode == PORT_10G_COPPER ||
			    nxgep->mac.portmode == PORT_10G_TN1010 ||
			    nxgep->mac.portmode == PORT_10G_SERDES)
				size += sizeof (lb_serdes10g);

			if (nxgep->statsp->mac_stats.cap_1000fdx) {
				/* TN1010 does not support external loopback */
				if (nxgep->mac.portmode != PORT_1G_TN1010 &&
				    nxgep->mac.portmode != PORT_10G_TN1010) {
					size += sizeof (lb_external1000);
				}
				size += sizeof (lb_mac1000);
				if (nxgep->mac.portmode == PORT_1G_COPPER ||
				    nxgep->mac.portmode == PORT_1G_TN1010 ||
				    nxgep->mac.portmode ==
				    PORT_1G_RGMII_FIBER)
					size += sizeof (lb_phy1000);
			}
			if (nxgep->statsp->mac_stats.cap_100fdx)
				size += sizeof (lb_external100);

			if (nxgep->statsp->mac_stats.cap_10fdx)
				size += sizeof (lb_external10);

			if (nxgep->mac.portmode == PORT_1G_FIBER ||
			    nxgep->mac.portmode == PORT_1G_TN1010 ||
			    nxgep->mac.portmode == PORT_1G_SERDES)
				size += sizeof (lb_serdes1000);

			NXGE_DEBUG_MSG((nxgep, IOC_CTL,
			    "NXGE_GET_LB_INFO command: size %d", size));
			if (size == iocp->ioc_count) {
				i = 0;
				lb_props = (p_lb_property_t)mp->b_cont->b_rptr;
				lb_props[i++] = lb_normal;

				if (nxgep->statsp->mac_stats.cap_10gfdx) {
					lb_props[i++] = lb_mac10g;
					if (nxgep->mac.portmode ==
					    PORT_10G_COPPER ||
					    nxgep->mac.portmode ==
					    PORT_10G_TN1010 ||
					    nxgep->mac.portmode ==
					    PORT_10G_FIBER) {
						lb_props[i++] = lb_phy10g;
					}
					/* TN1010 does not support ext lb */
					if (nxgep->mac.portmode !=
					    PORT_10G_TN1010 &&
					    nxgep->mac.portmode !=
					    PORT_1G_TN1010) {
						lb_props[i++] = lb_external10g;
					}
				}

				if (nxgep->mac.portmode == PORT_10G_FIBER ||
				    nxgep->mac.portmode == PORT_10G_COPPER ||
				    nxgep->mac.portmode == PORT_10G_TN1010 ||
				    nxgep->mac.portmode == PORT_10G_SERDES)
					lb_props[i++] = lb_serdes10g;

				if (nxgep->statsp->mac_stats.cap_1000fdx) {
					/* TN1010 does not support ext lb */
					if (nxgep->mac.portmode !=
					    PORT_10G_TN1010 &&
					    nxgep->mac.portmode !=
					    PORT_1G_TN1010) {
						lb_props[i++] = lb_external1000;
					}
				}

				if (nxgep->statsp->mac_stats.cap_100fdx)
					lb_props[i++] = lb_external100;

				if (nxgep->statsp->mac_stats.cap_10fdx)
					lb_props[i++] = lb_external10;

				if (nxgep->statsp->mac_stats.cap_1000fdx)
					lb_props[i++] = lb_mac1000;

				if (nxgep->mac.portmode == PORT_1G_COPPER ||
				    nxgep->mac.portmode == PORT_1G_TN1010 ||
				    nxgep->mac.portmode ==
				    PORT_1G_RGMII_FIBER) {
					if (nxgep->statsp->mac_stats.
					    cap_1000fdx)
						lb_props[i++] = lb_phy1000;
				} else if (nxgep->mac.portmode ==
				    PORT_1G_FIBER ||
				    nxgep->mac.portmode == PORT_1G_TN1010 ||
				    nxgep->mac.portmode == PORT_1G_SERDES) {
					lb_props[i++] = lb_serdes1000;
				}
				miocack(wq, mp, size, 0);
			} else
				miocnak(wq, mp, 0, EINVAL);
		} else {
			miocnak(wq, mp, 0, EINVAL);
			cmn_err(CE_NOTE, "!nxge_hw_ioctl: invalid command 0x%x",
			    iocp->ioc_cmd);
		}
		break;
	}
}

/*
 * DMA channel interfaces to access various channel specific
 * hardware functions.
 */
/* ARGSUSED */
void
nxge_rxdma_channel_put64(nxge_os_acc_handle_t handle, void *reg_addrp,
	uint32_t reg_base, uint16_t channel, uint64_t reg_data)
{
	uint64_t reg_offset;

	NXGE_DEBUG_MSG((NULL, DMA_CTL, "<== nxge_rxdma_channel_put64"));

	/*
	 * Channel is assumed to be from 0 to the maximum DMA channel #. If we
	 * use the virtual DMA CSR address space from the config space (in PCI
	 * case), then the following code need to be use different offset
	 * computation macro.
	 */
	reg_offset = reg_base + DMC_OFFSET(channel);
	NXGE_PIO_WRITE64(handle, reg_addrp, reg_offset, reg_data);

	NXGE_DEBUG_MSG((NULL, DMA_CTL, "<== nxge_rxdma_channel_put64"));
}

/* ARGSUSED */
uint64_t
nxge_rxdma_channel_get64(nxge_os_acc_handle_t handle, void *reg_addrp,
	uint32_t reg_base, uint16_t channel)
{
	uint64_t reg_offset;

	NXGE_DEBUG_MSG((NULL, DMA_CTL, "<== nxge_rxdma_channel_get64"));

	/*
	 * Channel is assumed to be from 0 to the maximum DMA channel #. If we
	 * use the virtual DMA CSR address space from the config space (in PCI
	 * case), then the following code need to be use different offset
	 * computation macro.
	 */
	reg_offset = reg_base + DMC_OFFSET(channel);

	NXGE_DEBUG_MSG((NULL, DMA_CTL, "<== nxge_rxdma_channel_get64"));

	return (NXGE_PIO_READ64(handle, reg_addrp, reg_offset));
}

/* ARGSUSED */
void
nxge_get32(p_nxge_t nxgep, p_mblk_t mp)
{
	nxge_os_acc_handle_t nxge_regh;

	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "nxge_get32"));
	nxge_regh = nxgep->dev_regs->nxge_regh;

	*(uint32_t *)mp->b_rptr = NXGE_PIO_READ32(nxge_regh,
	    nxgep->dev_regs->nxge_regp, *(uint32_t *)mp->b_rptr);

	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "value = 0x%08X",
	    *(uint32_t *)mp->b_rptr));
	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "nxge_get32"));
}

/* ARGSUSED */
void
nxge_put32(p_nxge_t nxgep, p_mblk_t mp)
{
	nxge_os_acc_handle_t nxge_regh;
	uint32_t *buf;
	uint8_t *reg;

	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "nxge_put32"));
	nxge_regh = nxgep->dev_regs->nxge_regh;

	buf = (uint32_t *)mp->b_rptr;
	reg = (uint8_t *)(nxgep->dev_regs->nxge_regp) + buf[0];
	NXGE_DEBUG_MSG((nxgep, IOC_CTL,
	    "reg = 0x%016llX index = 0x%08X value = 0x%08X",
	    reg, buf[0], buf[1]));
	NXGE_PIO_WRITE32(nxge_regh, (uint32_t *)reg, 0, buf[1]);
	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "nxge_put32"));
}

/*ARGSUSED*/
boolean_t
nxge_set_lb(p_nxge_t nxgep, queue_t *wq, p_mblk_t mp)
{
	boolean_t status = B_TRUE;
	uint32_t lb_mode;
	lb_property_t *lb_info;

	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "<== nxge_set_lb"));
	lb_mode = nxgep->statsp->port_stats.lb_mode;
	if (lb_mode == *(uint32_t *)mp->b_rptr) {
		cmn_err(CE_NOTE,
		    "!nxge%d: Loopback mode already set (lb_mode %d).\n",
		    nxgep->instance, lb_mode);
		status = B_FALSE;
		goto nxge_set_lb_exit;
	}
	lb_mode = *(uint32_t *)mp->b_rptr;
	lb_info = NULL;
	if (lb_mode == lb_normal.value)
		lb_info = &lb_normal;
	else if ((lb_mode == lb_external10g.value) &&
	    (nxgep->statsp->mac_stats.cap_10gfdx))
		lb_info = &lb_external10g;
	else if ((lb_mode == lb_external1000.value) &&
	    (nxgep->statsp->mac_stats.cap_1000fdx))
		lb_info = &lb_external1000;
	else if ((lb_mode == lb_external100.value) &&
	    (nxgep->statsp->mac_stats.cap_100fdx))
		lb_info = &lb_external100;
	else if ((lb_mode == lb_external10.value) &&
	    (nxgep->statsp->mac_stats.cap_10fdx))
		lb_info = &lb_external10;
	else if ((lb_mode == lb_phy10g.value) &&
	    (nxgep->mac.portmode == PORT_10G_COPPER ||
	    nxgep->mac.portmode == PORT_10G_TN1010 ||
	    nxgep->mac.portmode == PORT_10G_FIBER))
		lb_info = &lb_phy10g;
	else if ((lb_mode == lb_phy1000.value) &&
	    (nxgep->mac.portmode == PORT_1G_COPPER ||
	    nxgep->mac.portmode == PORT_1G_TN1010 ||
	    nxgep->mac.portmode == PORT_1G_RGMII_FIBER))
		lb_info = &lb_phy1000;
	else if ((lb_mode == lb_phy.value) &&
	    (nxgep->mac.portmode == PORT_1G_COPPER))
		lb_info = &lb_phy;
	else if ((lb_mode == lb_serdes10g.value) &&
	    (nxgep->mac.portmode == PORT_10G_FIBER ||
	    nxgep->mac.portmode == PORT_10G_COPPER ||
	    nxgep->mac.portmode == PORT_10G_TN1010 ||
	    nxgep->mac.portmode == PORT_10G_SERDES))
		lb_info = &lb_serdes10g;
	else if ((lb_mode == lb_serdes1000.value) &&
	    (nxgep->mac.portmode == PORT_1G_FIBER ||
	    nxgep->mac.portmode == PORT_1G_TN1010 ||
	    nxgep->mac.portmode == PORT_1G_SERDES))
		lb_info = &lb_serdes1000;
	else if (lb_mode == lb_mac10g.value)
		lb_info = &lb_mac10g;
	else if (lb_mode == lb_mac1000.value)
		lb_info = &lb_mac1000;
	else if (lb_mode == lb_mac.value)
		lb_info = &lb_mac;
	else {
		cmn_err(CE_NOTE,
		    "!nxge%d: Loopback mode not supported(mode %d).\n",
		    nxgep->instance, lb_mode);
		status = B_FALSE;
		goto nxge_set_lb_exit;
	}

	if (lb_mode == nxge_lb_normal) {
		if (nxge_lb_dbg) {
			cmn_err(CE_NOTE,
			    "!nxge%d: Returning to normal operation",
			    nxgep->instance);
		}
		if (nxge_set_lb_normal(nxgep) != NXGE_OK) {
			status = B_FALSE;
			cmn_err(CE_NOTE,
			    "!nxge%d: Failed to return to normal operation",
			    nxgep->instance);
		}
		goto nxge_set_lb_exit;
	}
	nxgep->statsp->port_stats.lb_mode = lb_mode;

	if (nxge_lb_dbg)
		cmn_err(CE_NOTE,
		    "!nxge%d: Adapter now in %s loopback mode",
		    nxgep->instance, lb_info->key);
	nxgep->param_arr[param_autoneg].value = 0;
	nxgep->param_arr[param_anar_10gfdx].value =
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_ext10g) ||
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_mac10g) ||
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_phy10g) ||
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_serdes10g);
	nxgep->param_arr[param_anar_10ghdx].value = 0;
	nxgep->param_arr[param_anar_1000fdx].value =
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_ext1000) ||
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_mac1000) ||
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_phy1000) ||
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_serdes1000);
	nxgep->param_arr[param_anar_1000hdx].value = 0;
	nxgep->param_arr[param_anar_100fdx].value =
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_phy) ||
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_mac) ||
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_ext100);
	nxgep->param_arr[param_anar_100hdx].value = 0;
	nxgep->param_arr[param_anar_10fdx].value =
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_mac) ||
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_ext10);
	if (nxgep->statsp->port_stats.lb_mode == nxge_lb_ext1000) {
		nxgep->param_arr[param_master_cfg_enable].value = 1;
		nxgep->param_arr[param_master_cfg_value].value = 1;
	}
	if ((nxgep->statsp->port_stats.lb_mode == nxge_lb_ext10g) ||
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_ext1000) ||
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_ext100) ||
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_ext10) ||
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_phy10g) ||
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_phy1000) ||
	    (nxgep->statsp->port_stats.lb_mode == nxge_lb_phy)) {

		if (nxge_link_monitor(nxgep, LINK_MONITOR_STOP) != NXGE_OK)
			goto nxge_set_lb_err;
		if (nxge_xcvr_find(nxgep) != NXGE_OK)
			goto nxge_set_lb_err;
		if (nxge_link_init(nxgep) != NXGE_OK)
			goto nxge_set_lb_err;
		if (nxge_link_monitor(nxgep, LINK_MONITOR_START) != NXGE_OK)
			goto nxge_set_lb_err;
	}
	if (lb_info->lb_type == internal) {
		if ((nxgep->statsp->port_stats.lb_mode == nxge_lb_mac10g) ||
		    (nxgep->statsp->port_stats.lb_mode ==
		    nxge_lb_phy10g) ||
		    (nxgep->statsp->port_stats.lb_mode ==
		    nxge_lb_serdes10g)) {
			nxgep->statsp->mac_stats.link_speed = 10000;
		} else if ((nxgep->statsp->port_stats.lb_mode
		    == nxge_lb_mac1000) ||
		    (nxgep->statsp->port_stats.lb_mode ==
		    nxge_lb_phy1000) ||
		    (nxgep->statsp->port_stats.lb_mode ==
		    nxge_lb_serdes1000)) {
			nxgep->statsp->mac_stats.link_speed = 1000;
		} else {
			nxgep->statsp->mac_stats.link_speed = 100;
		}
		nxgep->statsp->mac_stats.link_duplex = 2;
		nxgep->statsp->mac_stats.link_up = 1;
	}
	if (nxge_global_reset(nxgep) != NXGE_OK)
		goto nxge_set_lb_err;

nxge_set_lb_exit:
	NXGE_DEBUG_MSG((nxgep, DDI_CTL,
	    "<== nxge_set_lb status = 0x%08x", status));
	return (status);
nxge_set_lb_err:
	status = B_FALSE;
	cmn_err(CE_NOTE,
	    "!nxge%d: Failed to put adapter in %s loopback mode",
	    nxgep->instance, lb_info->key);
	return (status);
}

/* Return to normal (no loopback) mode */
/* ARGSUSED */
nxge_status_t
nxge_set_lb_normal(p_nxge_t nxgep)
{
	nxge_status_t	status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_set_lb_normal"));

	nxgep->statsp->port_stats.lb_mode = nxge_lb_normal;
	nxgep->param_arr[param_autoneg].value =
	    nxgep->param_arr[param_autoneg].old_value;
	nxgep->param_arr[param_anar_1000fdx].value =
	    nxgep->param_arr[param_anar_1000fdx].old_value;
	nxgep->param_arr[param_anar_1000hdx].value =
	    nxgep->param_arr[param_anar_1000hdx].old_value;
	nxgep->param_arr[param_anar_100fdx].value =
	    nxgep->param_arr[param_anar_100fdx].old_value;
	nxgep->param_arr[param_anar_100hdx].value =
	    nxgep->param_arr[param_anar_100hdx].old_value;
	nxgep->param_arr[param_anar_10fdx].value =
	    nxgep->param_arr[param_anar_10fdx].old_value;
	nxgep->param_arr[param_master_cfg_enable].value =
	    nxgep->param_arr[param_master_cfg_enable].old_value;
	nxgep->param_arr[param_master_cfg_value].value =
	    nxgep->param_arr[param_master_cfg_value].old_value;

	if ((status = nxge_global_reset(nxgep)) != NXGE_OK)
		return (status);

	if ((status = nxge_link_monitor(nxgep, LINK_MONITOR_STOP)) != NXGE_OK)
		return (status);
	if ((status = nxge_xcvr_find(nxgep)) != NXGE_OK)
		return (status);
	if ((status = nxge_link_init(nxgep)) != NXGE_OK)
		return (status);
	status = nxge_link_monitor(nxgep, LINK_MONITOR_START);

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_set_lb_normal"));

	return (status);
}

/* ARGSUSED */
void
nxge_get_mii(p_nxge_t nxgep, p_mblk_t mp)
{
	uint16_t reg;

	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "==> nxge_get_mii"));

	reg = *(uint16_t *)mp->b_rptr;
	(void) nxge_mii_read(nxgep, nxgep->statsp->mac_stats.xcvr_portn, reg,
	    (uint16_t *)mp->b_rptr);
	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "reg = 0x%08X value = 0x%04X",
	    reg, *(uint16_t *)mp->b_rptr));
	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "<== nxge_get_mii"));
}

/* ARGSUSED */
void
nxge_put_mii(p_nxge_t nxgep, p_mblk_t mp)
{
	uint16_t *buf;
	uint8_t reg;

	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "==> nxge_put_mii"));
	buf = (uint16_t *)mp->b_rptr;
	reg = (uint8_t)buf[0];
	NXGE_DEBUG_MSG((nxgep, IOC_CTL,
	    "reg = 0x%08X index = 0x%08X value = 0x%08X",
	    reg, buf[0], buf[1]));
	(void) nxge_mii_write(nxgep, nxgep->statsp->mac_stats.xcvr_portn,
	    reg, buf[1]);
	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "<== nxge_put_mii"));
}

/* ARGSUSED */
void
nxge_check_hw_state(p_nxge_t nxgep)
{
	p_nxge_ldgv_t ldgvp;
	p_nxge_ldv_t t_ldvp;

	NXGE_DEBUG_MSG((nxgep, SYSERR_CTL, "==> nxge_check_hw_state"));

	MUTEX_ENTER(nxgep->genlock);
	nxgep->nxge_timerid = 0;
	if (!(nxgep->drv_state & STATE_HW_INITIALIZED)) {
		goto nxge_check_hw_state_exit;
	}
	nxge_check_tx_hang(nxgep);

	ldgvp = nxgep->ldgvp;
	if (ldgvp == NULL || (ldgvp->ldvp_syserr == NULL)) {
		NXGE_ERROR_MSG((nxgep, SYSERR_CTL, "<== nxge_check_hw_state: "
		    "NULL ldgvp (interrupt not ready)."));
		goto nxge_check_hw_state_exit;
	}
	t_ldvp = ldgvp->ldvp_syserr;
	if (!t_ldvp->use_timer) {
		NXGE_DEBUG_MSG((nxgep, SYSERR_CTL, "<== nxge_check_hw_state: "
		    "ldgvp $%p t_ldvp $%p use_timer flag %d",
		    ldgvp, t_ldvp, t_ldvp->use_timer));
		goto nxge_check_hw_state_exit;
	}
	if (fm_check_acc_handle(nxgep->dev_regs->nxge_regh) != DDI_FM_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "port%d Bad register acc handle", nxgep->mac.portnum));
	}
	(void) nxge_syserr_intr((void *) t_ldvp, (void *) nxgep);

	nxgep->nxge_timerid = nxge_start_timer(nxgep, nxge_check_hw_state,
	    NXGE_CHECK_TIMER);

nxge_check_hw_state_exit:
	MUTEX_EXIT(nxgep->genlock);
	NXGE_DEBUG_MSG((nxgep, SYSERR_CTL, "<== nxge_check_hw_state"));
}

/*ARGSUSED*/
static void
nxge_rtrace_ioctl(p_nxge_t nxgep, queue_t *wq, mblk_t *mp,
	struct iocblk *iocp)
{
	ssize_t size;
	rtrace_t *rtp;
	mblk_t *nmp;
	uint32_t i, j;
	uint32_t start_blk;
	uint32_t base_entry;
	uint32_t num_entries;

	NXGE_DEBUG_MSG((nxgep, STR_CTL, "==> nxge_rtrace_ioctl"));

	size = 1024;
	if (mp->b_cont == NULL || MBLKL(mp->b_cont) < size) {
		NXGE_DEBUG_MSG((nxgep, STR_CTL,
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

	NXGE_DEBUG_MSG((nxgep, STR_CTL, "start_blk = %d\n", start_blk));
	NXGE_DEBUG_MSG((nxgep, STR_CTL, "num_entries = %d\n", num_entries));
	NXGE_DEBUG_MSG((nxgep, STR_CTL, "base_entry = %d\n", base_entry));

	rtp->next_idx = npi_rtracebuf.next_idx;
	rtp->last_idx = npi_rtracebuf.last_idx;
	rtp->wrapped = npi_rtracebuf.wrapped;
	for (i = 0, j = base_entry; i < num_entries; i++, j++) {
		rtp->buf[i].ctl_addr = npi_rtracebuf.buf[j].ctl_addr;
		rtp->buf[i].val_l32 = npi_rtracebuf.buf[j].val_l32;
		rtp->buf[i].val_h32 = npi_rtracebuf.buf[j].val_h32;
	}

	nmp->b_wptr = nmp->b_rptr + size;
	NXGE_DEBUG_MSG((nxgep, STR_CTL, "<== nxge_rtrace_ioctl"));
	miocack(wq, mp, (int)size, 0);
}
