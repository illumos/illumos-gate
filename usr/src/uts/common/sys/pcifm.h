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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PCIFM_H
#define	_SYS_PCIFM_H

#include <sys/dditypes.h>		/* for ddi_acc_handle_t */

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * PCI device type defines.
 */
#define	PCI_BRIDGE_DEV			0x02
#define	PCIX_DEV			0x04

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

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCIFM_H */
