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
 * ***********************************************************************
 * *                                                                    **
 * *                            NOTICE                                  **
 * *            COPYRIGHT (C) 1996-2015 QLOGIC CORPORATION              **
 * *                    ALL RIGHTS RESERVED                             **
 * *                                                                    **
 * ***********************************************************************
 *
 */

#include <ql_apps.h>
#include <ql_api.h>
#include <ql_fm.h>

/* Define default impact code */
qlc_fm_ereport_t qlc_fm_ereport_tbl[] = {

	{QL_FM_EREPORT_DMA_ERR,
	"A DMA direction error",
	QL_FM_DEVICE_DMA_ERR,
	DDI_FM_DEVICE_INTERN_CORR,
	DDI_SERVICE_UNAFFECTED},

	{QL_FM_EREPORT_BAD_PAYLOAD,
	"A bad payload detected",
	QL_FM_DEVICE_BAD_PAYLOAD,
	DDI_FM_DEVICE_INTERN_CORR,
	DDI_SERVICE_UNAFFECTED},

	{QL_FM_EREPORT_CMD_FAILED,
	"A command failed",
	QL_FM_DEVICE_CMD_FAILED,
	DDI_FM_DEVICE_INTERN_CORR,
	DDI_SERVICE_UNAFFECTED},

	{QL_FM_EREPORT_CHIP_HANG,
	"fw is not responding",
	QL_FM_DEVICE_CHIP_HANG,
	DDI_FM_DEVICE_INTERN_CORR,
	DDI_SERVICE_UNAFFECTED},

	{QL_FM_EREPORT_UNKNOWN,
	"Unknown error reported",
	QL_FM_DEVICE_UNKNOWN,
	DDI_FM_DEVICE_INTERN_CORR,
	DDI_SERVICE_UNAFFECTED},

	{QL_FM_EREPORT_MBA_REQ_TRANSFER_ERR,
	"Async event request transfer error",
	QL_FM_DEVICE_MBA_REQ_TRANSFER_ERR,
	DDI_FM_DEVICE_INVAL_STATE,
	DDI_SERVICE_LOST},

	{QL_FM_EREPORT_MBA_RSP_TRANSFER_ERR,
	"Async event response transfer error",
	QL_FM_DEVICE_MBA_RSP_TRANSFER_ERR,
	DDI_FM_DEVICE_INVAL_STATE,
	DDI_SERVICE_LOST},

	{QL_FM_EREPORT_ACC_HANDLE_CHECK,
	"ACC handle check return failed",
	QL_FM_DEVICE_ACC_HANDLE_ERR,
	DDI_FM_DEVICE_INTERN_UNCORR,
	DDI_SERVICE_LOST},

	{QL_FM_EREPORT_DMA_HANDLE_CHECK,
	"DMA handle check return failed",
	QL_FM_DEVICE_DMA_HANDLE_ERR,
	DDI_FM_DEVICE_INTERN_CORR,
	DDI_SERVICE_UNAFFECTED},

	/* Reporting Standard I/O controller Errors */

	/* End of table */
	{0, NULL, NULL, NULL, 0},
};


int
qlc_fm_check_acc_handle(ql_adapter_state_t *ha, ddi_acc_handle_t handle)
{

	ddi_fm_error_t err;

	if (!DDI_FM_ACC_ERR_CAP(ha->fm_capabilities)) {
		return (DDI_FM_OK);
	}
	err.fme_status = DDI_FM_OK;

	ddi_fm_acc_err_get(handle, &err, DDI_FME_VERSION);

	(void) ddi_fm_acc_err_clear(handle, DDI_FME_VERSION);

	return (err.fme_status);
}

/*ARGSUSED*/
int
qlc_fm_check_dma_handle(ql_adapter_state_t *ha, ddi_dma_handle_t handle)
{
	ddi_fm_error_t err;

	if (!DDI_FM_DMA_ERR_CAP(ha->fm_capabilities)) {
		return (DDI_FM_OK);
	}

	err.fme_status = DDI_FM_OK;

	ddi_fm_dma_err_get(handle, &err, DDI_FME_VERSION);

	return (err.fme_status);

}


void
qlc_fm_check_pkt_dma_handle(ql_adapter_state_t *ha, ql_srb_t *sb)
{
	fc_packet_t	*pkt = sb->pkt;
	int		rval = DDI_FM_OK;


	if (!DDI_FM_DMA_ERR_CAP(ha->fm_capabilities)) {
		return;
	}

	if (pkt->pkt_cmd_acc != NULL && pkt->pkt_cmdlen) {
		rval = qlc_fm_check_dma_handle(ha, pkt->pkt_cmd_dma);
	}

	if (pkt->pkt_resp_acc != NULL && rval == DDI_FM_OK &&
	    pkt->pkt_rsplen != 0) {
		rval = qlc_fm_check_dma_handle(ha, pkt->pkt_resp_dma);
	}

	if (((pkt->pkt_data_acc != NULL) & (rval == DDI_FM_OK) &
	    (pkt->pkt_datalen != 0)) != 0) {
		rval = qlc_fm_check_dma_handle(ha, pkt->pkt_data_dma);
	}

	if (rval != DDI_FM_OK) {
		pkt->pkt_state = FC_PKT_TRAN_ERROR;
		pkt->pkt_reason = FC_REASON_DMA_ERROR;
		pkt->pkt_expln = FC_EXPLN_NONE;
		pkt->pkt_action = FC_ACTION_RETRYABLE;

		(void) qlc_fm_report_err_impact(ha,
		    QL_FM_EREPORT_DMA_HANDLE_CHECK);
	}

}

/*
 * The IO fault service error handling callback function
 */

/*ARGSUSED*/
int
qlc_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data)
{
	pci_ereport_post(dip, err, NULL);

	return (err->fme_status);

}

/*ARGSUSED*/
void
qlc_fm_service_impact(ql_adapter_state_t *ha, int impact)
{
	if (!DDI_FM_EREPORT_CAP(ha->fm_capabilities)) {
		return;
	}

	ddi_fm_service_impact(ha->dip, impact);
}


/*ARGSUSED*/
void
qlc_fm_init(ql_adapter_state_t *ha)
{
	ddi_iblock_cookie_t iblk;

	if (ha->fm_capabilities == DDI_FM_NOT_CAPABLE) {
		return;
	}

	/*
	 * Register capabilities with IO Fault Services.
	 */
	if (ha->fm_capabilities) {
		ddi_fm_init(ha->dip, (int *)&ha->fm_capabilities, &iblk);
	}

	/*
	 * Initialize pci ereport capabilities if ereport capable
	 * PCI-related errors are automatically detected and reported
	 */
	if (DDI_FM_EREPORT_CAP(ha->fm_capabilities) ||
	    DDI_FM_ERRCB_CAP(ha->fm_capabilities)) {
		pci_ereport_setup(ha->dip);
	}

	/*
	 * Register error callback if error callback capable.
	 */
	if (DDI_FM_ERRCB_CAP(ha->fm_capabilities)) {
		ddi_fm_handler_register(ha->dip,
		    qlc_fm_error_cb, (void*)ha);
	}

	/*
	 * DDI_FLAGERR_ACC indicates:
	 * 1. Driver will check its access handle(s) for faults on
	 *    a regular basis by calling ddi_fm_acc_err_get
	 * 2. Driver is able to cope with incorrect results of I/O
	 *    operations resulted from an I/O fault.
	 */
	if (DDI_FM_ACC_ERR_CAP(ha->fm_capabilities)) {
		ql_dev_acc_attr.devacc_attr_access = DDI_FLAGERR_ACC;
	} else {
		ql_dev_acc_attr.devacc_attr_access = DDI_DEFAULT_ACC;
	}

	/*
	 * per instance based setup only
	 */
	if (DDI_FM_DMA_ERR_CAP(ha->fm_capabilities)) {
		ha->bit32_io_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;
		ha->bit64_io_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;

	} else {
		ha->bit32_io_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
		ha->bit64_io_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
	}

}


void
qlc_fm_fini(ql_adapter_state_t *ha)
{
	if (ha->fm_capabilities) {
		/*
		 * Release any resources allocated by pci_ereport_setup()
		 */
		if (DDI_FM_EREPORT_CAP(ha->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(ha->fm_capabilities)) {
			pci_ereport_teardown(ha->dip);
		}

		if (DDI_FM_ERRCB_CAP(ha->fm_capabilities)) {
			ddi_fm_handler_unregister(ha->dip);
		}

		/* Unregister from IO Fault Services */
		ddi_fm_fini(ha->dip);
	}

}


void
qlc_fm_report_err_impact(ql_adapter_state_t *ha, uint32_t fid)
{
	uint64_t ena;
	char eclass[QL_FM_MAX_CLASS];
	qlc_fm_ereport_t *ereport = NULL;

	if (!DDI_FM_EREPORT_CAP(ha->fm_capabilities)) {
		return;
	}

	if (fid > QL_FM_EREPORT_NONE) {
		cmn_err(CE_NOTE, "Not reported yet");
		return;
	}

	ereport = &qlc_fm_ereport_tbl[fid];

	/* We already have everything we need in ereport */
	(void) snprintf(eclass, QL_FM_MAX_CLASS, "%s.%s",
	    DDI_FM_DEVICE,
	    ereport->gen_eclass);

	ena = fm_ena_generate(0, FM_ENA_FMT1);

	switch (ereport->fid) {
	case QL_FM_EREPORT_DMA_ERR:
	case QL_FM_EREPORT_BAD_PAYLOAD:
	case QL_FM_EREPORT_CMD_FAILED:
	case QL_FM_EREPORT_CHIP_HANG:
	case QL_FM_EREPORT_UNKNOWN:
	case QL_FM_EREPORT_MBA_REQ_TRANSFER_ERR:
	case QL_FM_EREPORT_MBA_RSP_TRANSFER_ERR:

		ddi_fm_ereport_post(ha->dip, eclass, ena,
		    DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
		    "Detailed error desc", DATA_TYPE_STRING, ereport->desc,
		    "Instance number", DATA_TYPE_UINT8, ha->instance,
		    NULL);

		break;

	case QL_FM_EREPORT_ACC_HANDLE_CHECK:
	case QL_FM_EREPORT_DMA_HANDLE_CHECK:
	/*
	 * Adjust the impact code based on the state
	 * of the device: For example, if check failed
	 * during attach, then impact is DDI_SERVICE_LOST.
	 *
	 * driver's callback qlc_fm_error_cb() registerd will report error.
	 * We only need to report service impact here.
	 */
		ddi_fm_ereport_post(ha->dip, eclass, ena,
		    DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
		    "Detailed error desc", DATA_TYPE_STRING, ereport->desc,
		    "Instance number", DATA_TYPE_UINT8, ha->instance,
		    NULL);

		break;

	default:
		ddi_fm_ereport_post(ha->dip, eclass, ena,
		    DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0, NULL);

		break;
	}

	qlc_fm_service_impact(ha, ereport->impact_code);
}
