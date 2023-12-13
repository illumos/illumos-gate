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

/* Copyright 2015 QLogic Corporation */

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

#ifndef	_QL_FM_H
#define	_QL_FM_H

#ifdef __cplusplus
extern "C" {
#endif


/* standard I/O controller eclass already defined in sys/fm/ddi.h */
/* DDI_FM_DEVICE_INVAL_STATE "inval_state" etc */

/* qlc HBA specific ereport definitions */
#define	QL_FM_DEVICE			"qlc"

/* qlc HBA specific event defs */
#define	QL_FM_DEVICE_DMA_ERR		"qlc.dma_err"
#define	QL_FM_DEVICE_BAD_PAYLOAD	"qlc.bad_payload"
#define	QL_FM_DEVICE_CMD_FAILED		"qlc.cmd_failed"
#define	QL_FM_DEVICE_CHIP_HANG		"qlc.chip_hang"
#define	QL_FM_DEVICE_UNKNOWN		"qlc.unknown"
#define	QL_FM_DEVICE_MBA_REQ_TRANSFER_ERR	"qlc.asyn_mbx_req_err"
#define	QL_FM_DEVICE_MBA_RSP_TRANSFER_ERR	"qlc.asyn_mbx_rsp_err"
#define	QL_FM_DEVICE_ACC_HANDLE_ERR	"qlc.acc_hdl_err"
#define	QL_FM_DEVICE_DMA_HANDLE_ERR	"qlc.dma_hdl_err"

#define	QL_FM_MAX_CLASS			256


typedef struct qlc_fm_ereport {
	uint32_t		fid;		/* Fault Id */
	char			*desc;
	char			*eclass;	/* Error class */
	char			*gen_eclass;	/* Standard error class */
	ddi_fault_impact_t	impact_code;
} qlc_fm_ereport_t;


/* define fid */

typedef enum {
	QL_FM_EREPORT_DMA_ERR = 0,
	QL_FM_EREPORT_BAD_PAYLOAD,
	QL_FM_EREPORT_CMD_FAILED,
	QL_FM_EREPORT_CHIP_HANG,
	QL_FM_EREPORT_UNKNOWN,
	QL_FM_EREPORT_MBA_REQ_TRANSFER_ERR,
	QL_FM_EREPORT_MBA_RSP_TRANSFER_ERR,
	QL_FM_EREPORT_ACC_HANDLE_CHECK,
	QL_FM_EREPORT_DMA_HANDLE_CHECK,
	QL_FM_EREPORT_NONE
} qlc_fm_ereport_fid_t;

extern ddi_device_acc_attr_t ql_dev_acc_attr;
extern ddi_dma_attr_t ql_64bit_io_dma_attr;
extern ddi_dma_attr_t ql_32bit_io_dma_attr;

int qlc_fm_check_acc_handle(ql_adapter_state_t *, ddi_acc_handle_t);
int qlc_fm_check_dma_handle(ql_adapter_state_t *, ddi_dma_handle_t);
int qlc_fm_error_cb(dev_info_t *, ddi_fm_error_t *,
	const void *);
void qlc_fm_init(ql_adapter_state_t *);
void qlc_fm_fini(ql_adapter_state_t *);
void qlc_fm_report_err_impact(ql_adapter_state_t *, uint32_t);
void qlc_fm_service_impact(ql_adapter_state_t *, int);
void qlc_fm_check_pkt_dma_handle(ql_adapter_state_t *, ql_srb_t *);


#ifdef __cplusplus
}
#endif

#endif	/* _QL_FM_H */
