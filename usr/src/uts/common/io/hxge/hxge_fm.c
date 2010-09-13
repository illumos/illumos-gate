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
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>

static hxge_fm_ereport_attr_t
*hxge_fm_get_ereport_attr(hxge_fm_ereport_id_t ereport_id);

static int
hxge_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data);

hxge_fm_ereport_attr_t hxge_fm_ereport_vmac[] = {
	{HXGE_FM_EREPORT_VMAC_LINK_DOWN,	"10g_link_down",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_LOST}
};

hxge_fm_ereport_attr_t hxge_fm_ereport_pfc[] = {
	/*
	 * The following are part of LDF 0, non-fatal
	 */
	{HXGE_FM_EREPORT_PFC_TCAM_PAR_ERR,	"classifier_tcam_par_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{HXGE_FM_EREPORT_PFC_VLAN_PAR_ERR,	"classifier_vlan_par_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{HXGE_FM_EREPORT_PFC_PKT_DROP,		"classifier_pkt_drop_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED}
};

hxge_fm_ereport_attr_t hxge_fm_ereport_rdmc[] = {
	/*
	 * The following are part of LDF1, fatal
	 */
	{HXGE_FM_EREPORT_RDMC_RBR_CPL_TO,	"rxdma_rbr_cpl_to",
						DDI_FM_DEVICE_NO_RESPONSE,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_RDMC_PEU_RESP_ERR,	"rxdma_peu_resp_err",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_RDMC_RCR_SHA_PAR,	"rxdma_rcr_sha_par_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_RDMC_RBR_PRE_PAR,	"rxdma_rbr_pre_par_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_RDMC_RBR_PRE_EMPTY,	"rxdma_rbr_pre_empty_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_RDMC_RCR_SHA_FULL,	"rxdma_rcr_sha_full",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_RDMC_RCRFULL,		"rxdma_rcr_full",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_RDMC_RBR_EMPTY,	"rxdma_rbr_empty",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_RDMC_RBRFULL,		"rxdma_rbr_full",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_RDMC_RCR_ERR,		"rxdma_completion_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_DEGRADED},
	/*
	 * Control/Data ram received a ecc double bit error.
	 * Fatal error. Part of Device Error 1
	 */
	{HXGE_FM_EREPORT_RDMC_CTRL_FIFO_DED,	"rxdma_ctrl_fifo_ded",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_RDMC_DATA_FIFO_DED,	"rxdma_data_fifo_ded",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_DEGRADED},
	/*
	 * Control/Data ram received a ecc single bit error.
	 * Non-Fatal error. Part of Device Error 0
	 */
	{HXGE_FM_EREPORT_RDMC_CTRL_FIFO_SEC,	"rxdma_ctrl_fifo_sec",
						DDI_FM_DEVICE_INTERN_CORR,
						DDI_SERVICE_UNAFFECTED},
	{HXGE_FM_EREPORT_RDMC_DATA_FIFO_SEC,	"rxdma_data_fifo_sec",
						DDI_FM_DEVICE_INTERN_CORR,
						DDI_SERVICE_UNAFFECTED}
};

hxge_fm_ereport_attr_t hxge_fm_ereport_tdmc[] = {
	{HXGE_FM_EREPORT_TDMC_PEU_RESP_ERR,	"txdma_peu_resp_err",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_TDMC_PKT_SIZE_HDR_ERR,	"txdma_pkt_size_hdr_err",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_TDMC_RUNT_PKT_DROP_ERR, "txdma_runt_pkt_drop_err",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_TDMC_PKT_SIZE_ERR,	"txdma_pkt_size_err",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_TDMC_TX_RNG_OFLOW,	"txdma_tx_rng_oflow",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_TDMC_PREF_PAR_ERR,	"txdma_pref_par_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_TDMC_TDR_PREF_CPL_TO,	"txdma_tdr_pref_cpl_to",
						DDI_FM_DEVICE_NO_RESPONSE,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_TDMC_PKT_CPL_TO,	"txdma_pkt_cpl_to",
						DDI_FM_DEVICE_NO_RESPONSE,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_TDMC_INVALID_SOP,	"txdma_invalid_sop",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_TDMC_UNEXPECTED_SOP,	"txdma_unexpected_sop",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_TDMC_REORD_TBL_PAR,	"txdma_reord_tbl_par_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_DEGRADED},
	{HXGE_FM_EREPORT_TDMC_REORD_BUF_DED,	"txdma_reord_buf_ded_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_DEGRADED}
};

hxge_fm_ereport_attr_t hxge_fm_ereport_peu[] = {
	{HXGE_FM_EREPORT_PEU_ERR,		"peu_peu_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_LOST},
	{HXGE_FM_EREPORT_PEU_VNM_PIO_ERR,	"peu_vnm_pio_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_LOST}
};

hxge_fm_ereport_attr_t hxge_fm_ereport_sw[] = {
	{HXGE_FM_EREPORT_SW_INVALID_CHAN_NUM,	"invalid_chan_num",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_LOST},
	{HXGE_FM_EREPORT_SW_INVALID_PARAM,	"invalid_param",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_LOST}
};

void
hxge_fm_init(p_hxge_t hxgep, ddi_device_acc_attr_t *reg_attr,
	ddi_device_acc_attr_t *desc_attr, ddi_dma_attr_t *dma_attr)
{
	ddi_iblock_cookie_t iblk;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_fm_init"));

	/* fm-capable in hxge.conf can be used to set fm_capabilities. */
	hxgep->fm_capabilities = ddi_prop_get_int(DDI_DEV_T_ANY, hxgep->dip,
	    DDI_PROP_DONTPASS, "fm-capable",
	    DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE);

	HXGE_DEBUG_MSG((hxgep, DDI_CTL,
	    "FM capable = %d\n", hxgep->fm_capabilities));

	/*
	 * Register capabilities with IO Fault Services. The capabilities
	 * set above may not be supported by the parent nexus, in that case
	 * some capability bits may be cleared.
	 */
	if (hxgep->fm_capabilities)
		ddi_fm_init(hxgep->dip, &hxgep->fm_capabilities, &iblk);

	/*
	 * Initialize pci ereport capabilities if ereport capable
	 */
	if (DDI_FM_EREPORT_CAP(hxgep->fm_capabilities) ||
	    DDI_FM_ERRCB_CAP(hxgep->fm_capabilities)) {
		pci_ereport_setup(hxgep->dip);
	}

	/* Register error callback if error callback capable */
	if (DDI_FM_ERRCB_CAP(hxgep->fm_capabilities)) {
		ddi_fm_handler_register(hxgep->dip,
		    hxge_fm_error_cb, (void *) hxgep);
	}

	/*
	 * DDI_FLGERR_ACC indicates:
	 * o Driver will check its access handle(s) for faults on
	 *   a regular basis by calling ddi_fm_acc_err_get
	 * o Driver is able to cope with incorrect results of I/O
	 *   operations resulted from an I/O fault
	 */
	if (DDI_FM_ACC_ERR_CAP(hxgep->fm_capabilities)) {
		reg_attr->devacc_attr_access  = DDI_FLAGERR_ACC;
		desc_attr->devacc_attr_access = DDI_FLAGERR_ACC;
	} else {
		reg_attr->devacc_attr_access  = DDI_DEFAULT_ACC;
		desc_attr->devacc_attr_access = DDI_DEFAULT_ACC;
	}

	/*
	 * DDI_DMA_FLAGERR indicates:
	 * o Driver will check its DMA handle(s) for faults on a
	 *   regular basis using ddi_fm_dma_err_get
	 * o Driver is able to cope with incorrect results of DMA
	 *   operations resulted from an I/O fault
	 */
	if (DDI_FM_DMA_ERR_CAP(hxgep->fm_capabilities))
		dma_attr->dma_attr_flags |= DDI_DMA_FLAGERR;
	else
		dma_attr->dma_attr_flags &= ~DDI_DMA_FLAGERR;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_fm_init"));
}

void
hxge_fm_fini(p_hxge_t hxgep)
{
	/* Only unregister FMA capabilities if we registered some */
	if (hxgep->fm_capabilities) {
		/*
		 * Release any resources allocated by pci_ereport_setup()
		 */
		if (DDI_FM_EREPORT_CAP(hxgep->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(hxgep->fm_capabilities))
			pci_ereport_teardown(hxgep->dip);

		/*
		 * Un-register error callback if error callback capable
		 */
		if (DDI_FM_ERRCB_CAP(hxgep->fm_capabilities))
			ddi_fm_handler_unregister(hxgep->dip);

		/* Unregister from IO Fault Services */
		ddi_fm_fini(hxgep->dip);
	}
}


/*
 * Simply call pci_ereport_post which generates ereports for errors
 * that occur in the PCI local bus configuration status registers.
 */
/*ARGSUSED*/
static int
hxge_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err,
	const void *impl_data)
{
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);
}


static hxge_fm_ereport_attr_t *
hxge_fm_get_ereport_attr(hxge_fm_ereport_id_t ereport_id)
{
	hxge_fm_ereport_attr_t	*attr;
	uint8_t			blk_id;
	uint8_t			index;

	/* Extract the block id and the index within the block */
	blk_id = ((ereport_id >> EREPORT_FM_ID_SHIFT) & EREPORT_FM_ID_MASK);
	index = (ereport_id & EREPORT_INDEX_MASK);

	/* Return the appropriate structure of type hxge_fm_ereport_attr_t */
	switch (blk_id) {
	case FM_SW_ID:
		attr = &hxge_fm_ereport_sw[index];
		break;
	case FM_VMAC_ID:
		attr = &hxge_fm_ereport_vmac[index];
		break;
	case FM_PFC_ID:
		attr = &hxge_fm_ereport_pfc[index];
		break;
	case FM_RXDMA_ID:
		attr = &hxge_fm_ereport_rdmc[index];
		break;
	case FM_TXDMA_ID:
		attr = &hxge_fm_ereport_tdmc[index];
		break;
	case FM_PEU_ID:
		attr = &hxge_fm_ereport_peu[index];
		break;
	default:
		attr = NULL;
	}

	return (attr);
}

static void
hxge_fm_ereport(p_hxge_t hxgep, uint8_t err_chan,
	hxge_fm_ereport_attr_t *ereport)
{
	uint64_t		ena;
	char			eclass[FM_MAX_CLASS];
	char			*err_str;
	p_hxge_stats_t		statsp;

	(void) snprintf(eclass, FM_MAX_CLASS, "%s.%s", DDI_FM_DEVICE,
	    ereport->eclass);

	err_str = ereport->str;
	ena = fm_ena_generate(0, FM_ENA_FMT1);
	statsp = hxgep->statsp;

	switch (ereport->index) {
	case HXGE_FM_EREPORT_VMAC_LINK_DOWN:
		ddi_fm_ereport_post(hxgep->dip, eclass, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
		    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
		    NULL);
		break;
	case HXGE_FM_EREPORT_PFC_TCAM_PAR_ERR:
		ddi_fm_ereport_post(hxgep->dip, eclass, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
		    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
		    ERNAME_PFC_TCAM_ERR, DATA_TYPE_UINT32,
		    statsp->pfc_stats.tcam_parity_err,
		    NULL);
		break;
	case HXGE_FM_EREPORT_PFC_VLAN_PAR_ERR:
		ddi_fm_ereport_post(hxgep->dip, eclass, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
		    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
		    ERNAME_PFC_VLAN_ERR, DATA_TYPE_UINT32,
		    statsp->pfc_stats.vlan_parity_err,
		    NULL);
		break;
	case HXGE_FM_EREPORT_PFC_PKT_DROP:
		ddi_fm_ereport_post(hxgep->dip, eclass, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
		    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
		    ERNAME_PFC_PKT_DROP, DATA_TYPE_UINT32,
		    statsp->pfc_stats.pkt_drop,
		    NULL);
		break;
	case HXGE_FM_EREPORT_RDMC_RBR_CPL_TO:
	case HXGE_FM_EREPORT_RDMC_PEU_RESP_ERR:
	case HXGE_FM_EREPORT_RDMC_RCRFULL:
	case HXGE_FM_EREPORT_RDMC_RBR_EMPTY:
	case HXGE_FM_EREPORT_RDMC_RBRFULL:
	case HXGE_FM_EREPORT_RDMC_RBR_PRE_EMPTY:
	case HXGE_FM_EREPORT_RDMC_RCR_SHA_FULL:
		ddi_fm_ereport_post(hxgep->dip, eclass, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
		    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
		    ERNAME_ERR_DCHAN, DATA_TYPE_UINT8, err_chan,
		    NULL);
		break;
	case HXGE_FM_EREPORT_RDMC_RBR_PRE_PAR:
	case HXGE_FM_EREPORT_RDMC_RCR_SHA_PAR: {
		uint32_t err_log;
		hxge_rx_ring_stats_t *rdc_statsp;

		rdc_statsp = &statsp->rdc_stats[err_chan];
		if (ereport->index == HXGE_FM_EREPORT_RDMC_RBR_PRE_PAR)
			err_log = (uint32_t)
			    rdc_statsp->errlog.pre_par.value;
		else
			err_log = (uint32_t)
			    rdc_statsp->errlog.sha_par.value;
		ddi_fm_ereport_post(hxgep->dip, eclass, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
		    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
		    ERNAME_ERR_DCHAN, DATA_TYPE_UINT8, err_chan,
		    ERNAME_RDMC_PAR_ERR_LOG, DATA_TYPE_UINT8, err_log,
		    NULL);
		}
		break;
	case HXGE_FM_EREPORT_RDMC_RCR_ERR: {
		uint8_t err_type;
		err_type = statsp->rdc_stats[err_chan].errlog.compl_err_type;
		ddi_fm_ereport_post(hxgep->dip, eclass, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
		    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
		    ERNAME_ERR_DCHAN, DATA_TYPE_UINT8, err_chan,
		    ERNAME_RDC_ERR_TYPE, DATA_TYPE_UINT8, err_type,
		    NULL);
		}
		break;
	case HXGE_FM_EREPORT_RDMC_CTRL_FIFO_SEC:
	case HXGE_FM_EREPORT_RDMC_CTRL_FIFO_DED:
	case HXGE_FM_EREPORT_RDMC_DATA_FIFO_SEC:
	case HXGE_FM_EREPORT_RDMC_DATA_FIFO_DED:
		ddi_fm_ereport_post(hxgep->dip, eclass, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
		    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
		    NULL);
		break;

	case HXGE_FM_EREPORT_TDMC_PEU_RESP_ERR:
	case HXGE_FM_EREPORT_TDMC_TX_RNG_OFLOW:
	case HXGE_FM_EREPORT_TDMC_PKT_SIZE_HDR_ERR:
	case HXGE_FM_EREPORT_TDMC_RUNT_PKT_DROP_ERR:
	case HXGE_FM_EREPORT_TDMC_PKT_SIZE_ERR:
	case HXGE_FM_EREPORT_TDMC_TDR_PREF_CPL_TO:
	case HXGE_FM_EREPORT_TDMC_PKT_CPL_TO:
	case HXGE_FM_EREPORT_TDMC_INVALID_SOP:
	case HXGE_FM_EREPORT_TDMC_UNEXPECTED_SOP:
		ddi_fm_ereport_post(hxgep->dip, eclass, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
		    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
		    ERNAME_ERR_DCHAN, DATA_TYPE_UINT8, err_chan,
		    NULL);
		break;

	case HXGE_FM_EREPORT_TDMC_PREF_PAR_ERR:
		ddi_fm_ereport_post(hxgep->dip, eclass, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
		    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
		    ERNAME_ERR_DCHAN, DATA_TYPE_UINT8, err_chan,
		    ERNAME_TDC_PREF_PAR_LOG, DATA_TYPE_UINT32,
		    statsp->tdc_stats[err_chan].errlog.value, NULL);
		break;
	case HXGE_FM_EREPORT_TDMC_REORD_TBL_PAR:
	case HXGE_FM_EREPORT_TDMC_REORD_BUF_DED:
		ddi_fm_ereport_post(hxgep->dip, eclass, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
		    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
		    NULL);
		break;

	case HXGE_FM_EREPORT_PEU_ERR:
	case HXGE_FM_EREPORT_PEU_VNM_PIO_ERR:
		ddi_fm_ereport_post(hxgep->dip, eclass, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
		    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
		    NULL);
		break;

	case HXGE_FM_EREPORT_SW_INVALID_CHAN_NUM:
	case HXGE_FM_EREPORT_SW_INVALID_PARAM:
		ddi_fm_ereport_post(hxgep->dip, eclass, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
		    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
		    NULL);
		break;
	}
}

void
hxge_fm_report_error(p_hxge_t hxgep, uint8_t err_chan,
	hxge_fm_ereport_id_t fm_ereport_id)
{
	hxge_fm_ereport_attr_t	*fm_ereport_attr;

	fm_ereport_attr = hxge_fm_get_ereport_attr(fm_ereport_id);

	if (fm_ereport_attr != NULL &&
	    (DDI_FM_EREPORT_CAP(hxgep->fm_capabilities))) {
		hxge_fm_ereport(hxgep, err_chan, fm_ereport_attr);
		ddi_fm_service_impact(hxgep->dip, fm_ereport_attr->impact);
	}
}

int
fm_check_acc_handle(ddi_acc_handle_t handle)
{
	ddi_fm_error_t err;

	ddi_fm_acc_err_get(handle, &err, DDI_FME_VERSION);
	ddi_fm_acc_err_clear(handle, DDI_FME_VERSION);

	return (err.fme_status);
}

int
fm_check_dma_handle(ddi_dma_handle_t handle)
{
	ddi_fm_error_t err;

	ddi_fm_dma_err_get(handle, &err, DDI_FME_VERSION);
	return (err.fme_status);
}
