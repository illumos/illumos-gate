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

#ifndef	_SYS_PCIFM_H
#define	_SYS_PCIFM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dditypes.h>		/* for ddi_acc_handle_t */

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * PCI device type defines.
 */
#define	PCI_BRIDGE_DEV			0x02
#define	PCIX_DEV			0x04
#define	PCIEX_DEV			0x08
#define	PCIEX_ADV_DEV			0x10
#define	PCIEX_RC_DEV			0x20
#define	PCIEX_2PCI_DEV			0x40
#define	PCIEX_SWITCH_DEV		0x80

/*
 * PCI and PCI-X valid flags
 */
#define	PCI_ERR_STATUS_VALID		0x1
#define	PCI_BDG_SEC_STAT_VALID		0x2
#define	PCI_BDG_CTRL_VALID		0x4
#define	PCIX_ERR_STATUS_VALID		0x8
#define	PCIX_ERR_ECC_STS_VALID		0x10
#define	PCIX_ERR_S_ECC_STS_VALID	0x20
#define	PCIX_BDG_STATUS_VALID		0x40
#define	PCIX_BDG_SEC_STATUS_VALID	0x80

/*
 * PCI Express valid flags
 */
#define	PCIE_ERR_STATUS_VALID		0x1
#define	PCIE_CE_STATUS_VALID		0x2
#define	PCIE_UE_STATUS_VALID		0x4
#define	PCIE_RC_ERR_STATUS_VALID	0x8
#define	PCIE_SUE_STATUS_VALID		0x10
#define	PCIE_SUE_HDR_VALID		0x20
#define	PCIE_UE_HDR_VALID		0x40
#define	PCIE_SRC_ID_VALID		0x80

/*
 * PCI(-X) structures used (by pci_ereport_setup, pci_ereport_post, and
 * pci_ereport_teardown) to gather and report errors detected by PCI(-X)
 * compliant devices.
 */
typedef struct pci_bdg_error_regs {
	uint16_t pci_bdg_vflags;	/* status valid bits */
	uint16_t pci_bdg_sec_stat;	/* PCI secondary status reg */
	uint16_t pci_bdg_ctrl;		/* PCI bridge control reg */
} pci_bdg_error_regs_t;

typedef struct pci_error_regs {
	uint16_t pci_vflags;		/* status valid bits */
	uint8_t pci_cap_ptr;		/* PCI Capability pointer */
	uint16_t pci_err_status;	/* pci status register */
	uint16_t pci_cfg_comm;		/* pci command register */
	pci_bdg_error_regs_t *pci_bdg_regs;
} pci_error_regs_t;

typedef struct pci_erpt {
	ddi_acc_handle_t pe_hdl;	/* Config space access handle */
	uint64_t pe_dflags;		/* Device type flags */
	uint16_t pe_bdf;		/* bus/device/function of device */
	pci_error_regs_t *pe_pci_regs;	/* PCI generic error registers */
	void *pe_regs;			/* Pointer to extended error regs */
} pci_erpt_t;

typedef struct pcix_ecc_regs {
	uint16_t pcix_ecc_vflags;	/* pcix ecc valid flags */
	uint16_t pcix_ecc_bdf;		/* pcix ecc bdf */
	uint32_t pcix_ecc_ctlstat;	/* pcix ecc control status reg */
	uint32_t pcix_ecc_fstaddr;	/* pcix ecc first address reg */
	uint32_t pcix_ecc_secaddr;	/* pcix ecc second address reg */
	uint32_t pcix_ecc_attr;		/* pcix ecc attributes reg */
} pcix_ecc_regs_t;

typedef struct pcix_error_regs {
	uint16_t pcix_vflags;		/* pcix valid flags */
	uint8_t pcix_cap_ptr;		/* pcix capability pointer */
	uint16_t pcix_ver;		/* pcix version */
	uint16_t pcix_command;		/* pcix command register */
	uint32_t pcix_status;		/* pcix status register */
	pcix_ecc_regs_t *pcix_ecc_regs;	/* pcix ecc registers */
} pcix_error_regs_t;

typedef struct pcix_bdg_error_regs {
	uint16_t pcix_bdg_vflags;	/* pcix valid flags */
	uint8_t pcix_bdg_cap_ptr;	/* pcix bridge capability pointer */
	uint16_t pcix_bdg_ver;		/* pcix version */
	uint16_t pcix_bdg_sec_stat;	/* pcix bridge secondary status reg */
	uint32_t pcix_bdg_stat;		/* pcix bridge status reg */
	pcix_ecc_regs_t *pcix_bdg_ecc_regs[2];	/* pcix ecc registers */
} pcix_bdg_error_regs_t;

/*
 * PCI Express error register structures used (by pci_ereport_setup,
 * pci_ereport_post, and pci_ereport_teardown) to gather and report errors
 * detected by PCI Express compliant devices.
 */
typedef struct pcie_adv_bdg_error_regs {
	uint32_t pcie_sue_status;	/* pcie bridge secondary ue status */
	uint32_t pcie_sue_mask;		/* pcie bridge secondary ue mask */
	uint32_t pcie_sue_sev;		/* pcie bridge secondary ue severity */
	uint32_t pcie_sue_hdr0;		/* pcie bridge secondary ue hdr log */
	uint32_t pcie_sue_hdr[3];	/* pcie bridge secondary ue hdr log */
} pcie_adv_bdg_error_regs_t;

typedef struct pcie_adv_rc_error_regs {
	uint32_t pcie_rc_err_status;	/* pcie root complex error status reg */
	uint32_t pcie_rc_err_cmd;	/* pcie root complex error cmd reg */
	uint16_t pcie_rc_ce_src_id;	/* pcie root complex ce source id */
	uint16_t pcie_rc_ue_src_id;	/* pcie root complex ue source id */
} pcie_adv_rc_error_regs_t;

typedef struct pcie_adv_error_regs {
	uint16_t pcie_adv_vflags;	/* pcie advanced error valid flags */
	uint16_t pcie_adv_cap_ptr;	/* pcie advanced capability pointer */
	uint16_t pcie_adv_bdf;		/* pcie bdf */
	uint32_t pcie_adv_ctl;		/* pcie advanced control reg */
	uint32_t pcie_ce_status;	/* pcie ce error status reg */
	uint32_t pcie_ce_mask;		/* pcie ce error mask reg */
	uint32_t pcie_ue_status;	/* pcie ue error status reg */
	uint32_t pcie_ue_mask;		/* pcie ue error mask reg */
	uint32_t pcie_ue_sev;		/* pcie ue error severity reg */
	uint32_t pcie_ue_hdr0;		/* pcie ue header log */
	uint32_t pcie_ue_hdr[3];	/* pcie ue header log */
	pcie_adv_bdg_error_regs_t *pcie_adv_bdg_regs;	/* pcie bridge regs */
	pcie_adv_rc_error_regs_t *pcie_adv_rc_regs;	/* pcie rc regs */
} pcie_adv_error_regs_t;

typedef struct pcie_rc_error_regs {
	uint32_t pcie_rc_status;	/* root complex status register */
	uint16_t pcie_rc_ctl;		/* root complex control register */
} pcie_rc_error_regs_t;

typedef struct pcie_error_regs {
	uint16_t pcie_vflags;		/* pcie valid flags */
	uint8_t pcie_cap_ptr;		/* PCI Express capability pointer */
	uint16_t pcie_cap;		/* PCI Express capability register */
	uint16_t pcie_err_status;	/* pcie device status register */
	uint16_t pcie_err_ctl;		/* pcie error control register */
	uint16_t pcie_dev_cap;		/* pcie device capabilities register */
	pcix_bdg_error_regs_t *pcix_bdg_regs;	/* pcix bridge regs */
	pcie_rc_error_regs_t *pcie_rc_regs;	/* pcie root complex regs */
	pcie_adv_error_regs_t *pcie_adv_regs;	/* pcie advanced err regs */
} pcie_error_regs_t;

/*
 * pcie bus specific structure
 */

typedef struct pci_fme_bus_specific {
	int pci_bs_type;
	uint64_t pci_bs_addr;
	uint16_t pci_bs_bdf;
	int pci_bs_flags;
} pci_fme_bus_specific_t;

#define	PCI_BS_ADDR_VALID		1
#define	PCI_BS_BDF_VALID		2

/*
 * target error queue defines
 */
#define	TARGET_MAX_ERRS			6
#define	TGT_PCI_SPACE_UNKNOWN		4

typedef struct pci_target_err {
	uint64_t tgt_err_addr;
	uint64_t tgt_err_ena;
	uint64_t tgt_pci_addr;
	uint32_t tgt_pci_space;
	dev_info_t *tgt_dip;
	char *tgt_err_class;
	char *tgt_bridge_type;
} pci_target_err_t;

#define	PCI_FM_SEV_INC(x)	((x) == DDI_FM_FATAL) ? fatal++ :\
				(((x) == DDI_FM_NONFATAL) ? nonfatal++ :\
				(((x) == DDI_FM_UNKNOWN) ? unknown++ : ok++));

#define	PCIEX_TYPE_CE			0x0
#define	PCIEX_TYPE_UE			0x1
#define	PCIEX_TYPE_GEN			0x2
#define	PCIEX_TYPE_RC_UE_MSG		0x3
#define	PCIEX_TYPE_RC_CE_MSG		0x4
#define	PCIEX_TYPE_RC_MULT_MSG		0x5

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCIFM_H */
