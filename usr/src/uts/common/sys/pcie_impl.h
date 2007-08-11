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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PCIE_IMPL_H
#define	_SYS_PCIE_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/pcie.h>

/* PCI-E config space data for error handling and ereport */
typedef struct pf_data {
	dev_info_t	*dip;
	pcie_req_id_t	bdf;
	pcie_req_id_t	rp_bdf;
	uint32_t	severity_flags;
	int		parent_index;
	pcie_req_id_t	fault_bdf;
	uint32_t	fault_addr;
	int		send_erpt;

	/* 0-3Fh.  PCI */
	uint16_t	vendor_id;
	uint16_t	device_id;
	uint8_t		hdr_type;
	uint16_t	command;		/* command */
	uint16_t	status;			/* status */
	uint8_t		rev_id;
	uint16_t	s_status;		/* Bridge secondary status */
	pcie_req_id_t	bdg_secbus;		/* Bridge secondary bus num */

	/* 40h-FFh. PCI-X Capability */
	uint16_t	pcix_s_status;		/* PCI-X Secondary status */
	uint32_t	pcix_bdg_status;	/* PCI-X Bridge status */

	/* 40h-FFh. PCI-E Capability */
	uint16_t	pcie_off;		/* PCI-E capability offset */
	uint8_t		dev_type;		/* device/port type */
	uint16_t	dev_status;		/* device status */

	/* 100h-FFFh. Extended PCI-E */
	uint16_t	aer_off;		/* AER offset */

	uint32_t	aer_ce_status;		/* AER Correctable Errors */

	uint32_t	aer_ue_status;		/* AER Uncorrectable Errors */
	uint32_t	aer_severity;
	uint32_t	aer_control;
	uint32_t	aer_h0;
	uint32_t	aer_h1;
	uint32_t	aer_h2;
	uint32_t	aer_h3;

	uint32_t	s_aer_ue_status;	/* Secondary AER UEs */
	uint32_t	s_aer_control;
	uint32_t	s_aer_severity;
	uint32_t	s_aer_h0;
	uint32_t	s_aer_h1;
	uint32_t	s_aer_h2;
	uint32_t	s_aer_h3;
} pf_data_t;

/* Information used while handling errors in the fabric. */
typedef struct pf_impl {
	dev_info_t	*pf_rpdip;
	pcie_req_id_t	pf_fbdf;	/* captured fault bdf to scan */
	uint32_t	pf_faddr;	/* captured fault addr to scan */
	ddi_fm_error_t	*pf_derr;
	pf_data_t	*pf_dq_p;	/* ptr to pcie fault data queue */
	int		*pf_dq_tail_p;	/* last valid index of fault data q */
} pf_impl_t;

/* Parent Private data of PCI/PCIe devices in a PCIe system */
typedef struct pcie_ppd {
	dev_info_t	*ppd_dip;
	ddi_acc_handle_t ppd_cfg_hdl;		/* error handling acc handle */
	kmutex_t	ppd_fm_lock;		/* error handling lock */
	uint_t		ppd_fm_flags;

	/* Static PCI/PCIe information */
	pcie_req_id_t	ppd_bdf;
	uint32_t	ppd_dev_ven_id;		/* device/vendor ID */
	uint8_t		ppd_hdr_type;		/* pci header type, see pci.h */
	uint8_t		ppd_dev_type;		/* PCI-E dev type, see pcie.h */
	uint8_t		ppd_bdg_secbus;		/* Bridge secondary bus num */
	pcie_req_id_t	ppd_pcie2pci_secbus;	/* PCIe2PCI Bridge secbus num */
	uint16_t	ppd_pcie_off;		/* PCIe Capability Offset */
	uint16_t	ppd_aer_off;		/* PCIe Advanced Error Offset */
	uint16_t	ppd_pcix_off;		/* PCIx Capability Offset */
	pci_bus_range_t	ppd_bus_range;		/* pci bus-range property */
	ppb_ranges_t	*ppd_addr_ranges;	/* pci range property */
	int		ppd_addr_entries;	/* number of range prop */
	pci_regspec_t	*ppd_assigned_addr;	/* "assigned-address" prop */
	int		ppd_assigned_entries;	/* number of prop entries */
} pcie_ppd_t;

#define	PCI_GET_BDF(dip)	\
	((pcie_ppd_t *)pcie_get_ppd(dip))->ppd_bdf
#define	PCI_GET_BDG_SECBUS(dip)	\
	((pcie_ppd_t *)pcie_get_ppd(dip))->ppd_bdg_secbus
#define	PCI_GET_PCIE2PCI_SECBUS(dip)	\
	((pcie_ppd_t *)pcie_get_ppd(dip))->ppd_pcie2pci_secbus

/*
 * The following flag is used for Broadcom 5714/5715 bridge prefetch issue.
 * This flag will be used both by px and px_pci nexus drivers.
 */
#define	PX_DMAI_FLAGS_MAP_BUFZONE	0x40000

/* ppd_fm_flags field */
#define	PF_FM_READY		(1 << 0)	/* ppd_fm_lock initialized */
#define	PF_IS_NH		(1 << 1)	/* known as non-hardened */

/* PCIe fabric error handling return codes */
#define	PF_NO_ERROR		(1 << 0)	/* No error seen */
#define	PF_CE			(1 << 1)	/* Correctable Error */
#define	PF_NO_PANIC		(1 << 2)	/* Error should not panic sys */
#define	PF_MATCHED_DEVICE	(1 << 3)	/* Error Handled By Device */
#define	PF_MATCHED_RC		(1 << 4)	/* Error Handled By RC */
#define	PF_MATCHED_PARENT	(1 << 5)	/* Error Handled By Parent */
#define	PF_PANIC		(1 << 6)	/* Error should panic system */

/* PCIe fabric handle lookup return codes */
#define	PF_HDL_FOUND		0
#define	PF_HDL_NOTFOUND		1

/* PCIe fabric handle lookup address flags */
#define	PF_DMA_ADDR		(1 << 0)
#define	PF_PIO_ADDR		(1 << 1)
#define	PF_CFG_ADDR		(1 << 2)
#define	PF_IO_ADDR		(1 << 3)

#define	PF_SEND_ERPT_YES	1
#define	PF_SEND_ERPT_UNKNOWN	0
#define	PF_SEND_ERPT_NO		-1

#define	PF_SUCCESS		(1 << 0)
#define	PF_FAILURE		(1 << 1)
#define	PF_DO_NOT_SCAN		(1 << 2)

/* PCIe helper functions */
extern pcie_ppd_t *pcie_get_ppd(dev_info_t *dip);

/* PCIe Friendly Functions */
extern int pcie_initchild(dev_info_t *dip);
extern void pcie_uninitchild(dev_info_t *dip);
extern void pcie_clear_errors(dev_info_t *dip, ddi_acc_handle_t cfg_hdl);
extern int pcie_postattach_child(dev_info_t *dip);
extern void pcie_enable_errors(dev_info_t *dip, ddi_acc_handle_t cfg_hdl);
extern void pcie_disable_errors(dev_info_t *dip, ddi_acc_handle_t cfg_hdl);
extern int pcie_enable_ce(dev_info_t *dip, ddi_acc_handle_t cfg_hdl);
extern dev_info_t *pcie_get_my_childs_dip(dev_info_t *dip, dev_info_t *rdip);
extern uint32_t pcie_get_bdf_for_dma_xfer(dev_info_t *dip, dev_info_t *rdip);

extern pcie_ppd_t *pcie_init_ppd(dev_info_t *cdip);
extern void pcie_uninit_ppd(dev_info_t *cdip);
extern boolean_t pcie_is_child(dev_info_t *dip, dev_info_t *rdip);
extern int pcie_get_bdf_from_dip(dev_info_t *dip, pcie_req_id_t *bdf);

/* PCIe error handling functions */
extern int pf_en_dq(pf_data_t *pf_data_p, pf_data_t *dq_p, int *dq_tail_p,
    pcie_req_id_t pbdf);
extern int pf_get_dq_size(void);
extern int pf_tlp_decode(dev_info_t *rpdip, pf_data_t *pf_data_p,
    pcie_req_id_t *bdf, uint32_t *addr, uint32_t *trans_type);
extern int pf_tlp_hdl_lookup(dev_info_t *rpdip, ddi_fm_error_t *derr,
    pf_data_t *pf_data_p);
extern int pf_hdl_lookup(dev_info_t *rpdip, uint64_t ena,
    uint32_t flag, uint32_t addr, pcie_req_id_t bdf);
extern int pf_scan_fabric(dev_info_t *rpdip, ddi_fm_error_t *derr,
    pf_data_t *dq_p, int *dq_tail_p);
extern void pf_init(dev_info_t *dip, ddi_iblock_cookie_t ibc,
    ddi_attach_cmd_t cmd);
extern void pf_fini(dev_info_t *dip, ddi_detach_cmd_t cmd);
extern boolean_t pf_ready(dev_info_t *dip);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCIE_IMPL_H */
