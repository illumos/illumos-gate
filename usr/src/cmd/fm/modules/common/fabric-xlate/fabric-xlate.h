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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 */

#ifndef _FABRIC_XLATE_H
#define	_FABRIC_XLATE_H

#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/nvpair.h>
#include <sys/types.h>
#include <sys/pcie.h>
#include <sys/fm/io/pci.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	STRCMP(s1, s2) (strcmp((const char *)s1, (const char *)s2) == 0)
/*
 * These values are used for the xxx_tgt_trans value in fab_data_t.  They are
 * originally set in pcie_fault.c and originally defined in pcie_impl.h.
 */
#define	PF_ADDR_DMA		(1 << 0)
#define	PF_ADDR_PIO		(1 << 1)
#define	PF_ADDR_CFG		(1 << 2)


/*
 * The fabric ereport preparation functions (fab_prep_*) in fab_erpt_tbl_t
 * structures may return an error if the ereport could not be set up properly.
 * Typically, these errors are errnos. It is possible that based on incoming
 * ereport payload data, we might not want to generate an ereport at all: In
 * this case, the preparation functions may instead return PF_EREPORT_IGNORE,
 * which is set at a high value so as not to collide with the errnos.
 */
#define	PF_EREPORT_IGNORE	INT_MAX

extern fmd_xprt_t *fab_fmd_xprt;	/* FMD transport layer handle */
extern char fab_buf[];

/* PCI-E config space data for error handling and fabric ereports */
typedef struct fab_data {
	/* Original ereport NVL */
	nvlist_t	*nvl;

	/* Device Information */
	uint16_t bdf;
	uint16_t device_id;
	uint16_t vendor_id;
	uint8_t rev_id;
	uint16_t dev_type;
	uint16_t pcie_off;
	uint16_t pcix_off;
	uint16_t aer_off;
	uint16_t ecc_ver;

	/* Ereport Information */
	uint32_t remainder;
	uint32_t severity;

	/* Error Registers */
	uint16_t pci_err_status;	/* pci status register */
	uint16_t pci_cfg_comm;		/* pci command register */

	uint16_t pci_bdg_sec_stat;	/* PCI secondary status reg */
	uint16_t pci_bdg_ctrl;		/* PCI bridge control reg */

	uint16_t pcix_command;		/* pcix command register */
	uint32_t pcix_status;		/* pcix status register */

	uint16_t pcix_bdg_sec_stat;	/* pcix bridge secondary status reg */
	uint32_t pcix_bdg_stat;		/* pcix bridge status reg */

	uint16_t pcix_ecc_control_0;	/* pcix ecc control status reg */
	uint16_t pcix_ecc_status_0;	/* pcix ecc control status reg */
	uint32_t pcix_ecc_fst_addr_0;	/* pcix ecc first address reg */
	uint32_t pcix_ecc_sec_addr_0;	/* pcix ecc second address reg */
	uint32_t pcix_ecc_attr_0;	/* pcix ecc attributes reg */
	uint16_t pcix_ecc_control_1;	/* pcix ecc control status reg */
	uint16_t pcix_ecc_status_1;	/* pcix ecc control status reg */
	uint32_t pcix_ecc_fst_addr_1;	/* pcix ecc first address reg */
	uint32_t pcix_ecc_sec_addr_1;	/* pcix ecc second address reg */
	uint32_t pcix_ecc_attr_1;	/* pcix ecc attributes reg */

	uint16_t pcie_err_status;	/* pcie device status register */
	uint16_t pcie_err_ctl;		/* pcie error control register */
	uint32_t pcie_dev_cap;		/* pcie device capabilities register */

	uint32_t pcie_adv_ctl;		/* pcie advanced control reg */
	uint32_t pcie_ue_status;	/* pcie ue error status reg */
	uint32_t pcie_ue_mask;		/* pcie ue error mask reg */
	uint32_t pcie_ue_sev;		/* pcie ue error severity reg */
	uint32_t pcie_ue_hdr[4];	/* pcie ue header log */
	uint32_t pcie_ce_status;	/* pcie ce error status reg */
	uint32_t pcie_ce_mask;		/* pcie ce error mask reg */
	uint32_t pcie_ue_tgt_trans;	/* Fault trans type from AER Logs */
	uint64_t pcie_ue_tgt_addr;	/* Fault addr from AER Logs */
	pcie_req_id_t pcie_ue_tgt_bdf;	/* Fault bdf from SAER Logs */
	boolean_t pcie_ue_no_tgt_erpt;  /* Don't send target ereports */

	uint32_t pcie_sue_ctl;		/* pcie bridge secondary ue control */
	uint32_t pcie_sue_status;	/* pcie bridge secondary ue status */
	uint32_t pcie_sue_mask;		/* pcie bridge secondary ue mask */
	uint32_t pcie_sue_sev;		/* pcie bridge secondary ue severity */
	uint32_t pcie_sue_hdr[4];	/* pcie bridge secondary ue hdr log */
	uint32_t pcie_sue_tgt_trans;	/* Fault trans type from AER Logs */
	uint64_t pcie_sue_tgt_addr;	/* Fault addr from AER Logs */
	pcie_req_id_t pcie_sue_tgt_bdf;	/* Fault bdf from SAER Logs */

	uint32_t pcie_rp_status;	/* root complex status register */
	uint16_t pcie_rp_ctl;		/* root complex control register */
	uint32_t pcie_rp_err_status;	/* pcie root complex error status reg */
	uint32_t pcie_rp_err_cmd;	/* pcie root complex error cmd reg */
	uint16_t pcie_rp_ce_src_id;	/* pcie root complex ce source id */
	uint16_t pcie_rp_ue_src_id;	/* pcie root complex ue source id */

	/*
	 * The slot register values refer to the registers of the component's
	 * parent slot, not the component itself.
	 *
	 * You should only use the register values -- i.e.,
	 * pcie_slot_{cap,control,status} -- if pcie_slot_data_valid is set to
	 * true.
	 */
	boolean_t pcie_slot_data_valid; /* true if slot data is valid */
	uint32_t pcie_slot_cap;		/* pcie slot capabilities */
	uint16_t pcie_slot_control;	/* pcie slot control */
	uint16_t pcie_slot_status;	/* pcie slot status */

	/* Flags */
	boolean_t pcie_rp_send_all;	/* need to send ereports on all rps */
} fab_data_t;

typedef struct fab_erpt_tbl {
	const char	*err_class;	/* Final Ereport Class */
	uint32_t	reg_bit;	/* Error Bit Mask */
	const char	*tgt_class;	/* Target Ereport Class */
} fab_erpt_tbl_t;

typedef struct fab_err_tbl {
	fab_erpt_tbl_t	*erpt_tbl;	/* ereport table */
	uint32_t	reg_offset;	/* sts reg for ereport table offset */
	uint32_t	reg_size;	/* size of the status register */
	/* Pointer to function that prepares the ereport body */
	int		(*fab_prep)(fmd_hdl_t *, fab_data_t *, nvlist_t *,
	    fab_erpt_tbl_t *);
} fab_err_tbl_t;

extern void fab_setup_master_table();

/* Main functions for converting "fabric" ereports */
extern void fab_xlate_pcie_erpts(fmd_hdl_t *, fab_data_t *);
extern void fab_xlate_fabric_erpts(fmd_hdl_t *, nvlist_t *, const char *);
extern void fab_xlate_fire_erpts(fmd_hdl_t *, nvlist_t *, const char *);
extern void fab_xlate_epkt_erpts(fmd_hdl_t *, nvlist_t *, const char *);

/* Common functions for sending translated ereports */
extern int fab_prep_basic_erpt(fmd_hdl_t *, nvlist_t *, nvlist_t *, boolean_t);
extern void fab_send_tgt_erpt(fmd_hdl_t *, fab_data_t *, const char *,
    boolean_t);
extern void fab_send_erpt(fmd_hdl_t *hdl, fab_data_t *data, fab_err_tbl_t *tbl);

/* Misc Functions */
extern void fab_pr(fmd_hdl_t *, fmd_event_t *, nvlist_t *);
extern boolean_t fab_get_hcpath(fmd_hdl_t *, nvlist_t *, char **, size_t *);
extern boolean_t fab_get_rcpath(fmd_hdl_t *, nvlist_t *, char *);
extern char *fab_find_rppath_by_df(fmd_hdl_t *, nvlist_t *, uint8_t);
extern char *fab_find_rppath_by_devbdf(fmd_hdl_t *, nvlist_t *, pcie_req_id_t);
extern char *fab_find_rppath_by_devpath(fmd_hdl_t *, const char *);
extern char *fab_find_addr(fmd_hdl_t *hdl, nvlist_t *nvl, uint64_t addr);
extern char *fab_find_bdf(fmd_hdl_t *hdl, nvlist_t *nvl, pcie_req_id_t bdf);
extern boolean_t fab_hc2dev(fmd_hdl_t *, const char *, char **);
extern boolean_t fab_hc2dev_nvl(fmd_hdl_t *, nvlist_t *, char **);
extern char *fab_get_rpdev(fmd_hdl_t *);
extern void fab_set_fake_rp(fmd_hdl_t *);
extern void fab_send_erpt_all_rps(fmd_hdl_t *, nvlist_t *);

#ifdef __cplusplus
}
#endif

#endif /* _FABRIC_XLATE_H */
