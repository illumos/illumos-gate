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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PCI_FM_H
#define	_PCI_FM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ddifm.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#define	PBM_PRIMARY		1
#define	PBM_SECONDARY		0
#define	PBM_NONFATAL		0
#define	PBM_FATAL		1
#define	CB_NONFATAL		0
#define	CB_FATAL		1
#define	FM_LOG_PCI		0
#define	FM_LOG_PBM		1
#define	PCI_SIDEA		0
#define	PCI_SIDEB		1
#define	ECC_MAX_ERRS		6

/*
 * Since pci_pbm_err_handler() is called by various interrupt/trap/callback
 * handlers, it is necessary for it to know where it is being called from.
 * Below are the flags passed to pci_pbm_err_handler() to give it knowledge
 * of it's caller.
 */
#define	PCI_TRAP_CALL		0x0
#define	PCI_CB_CALL		0x1
#define	PCI_INTR_CALL		0x2
#define	PCI_BUS_EXIT_CALL	0x3
#define	PCI_ECC_CALL		0x4

#define	PCIX_ERROR_SUBCLASS	"pcix"
#define	PCIX_SECONDARY		"s-"
#define	PCIX_STAT		"pcix-stat"
#define	PCIX_PFAR		"pcix-pfar"

extern errorq_t *pci_ecc_queue;		/* per-system ecc handling queue */

/*
 * region where schizo pio ecc error was detected
 */
typedef enum {
	SCH_REG_UPA,
	SCH_REG_PCIA_REG,
	SCH_REG_PCIA_MEM,
	SCH_REG_PCIA_CFGIO,
	SCH_REG_PCIB_REG,
	SCH_REG_PCIB_MEM,
	SCH_REG_PCIB_CFGIO,
	SCH_REG_SAFARI_REGS
} ecc_region_t;

typedef struct pbm_fm_err {
	char *pbm_err_class;
	uint64_t pbm_reg_bit;
	int pbm_pri;
	int pbm_flag;
	char *pbm_terr_class;
} pbm_fm_err_t;

typedef struct ecc_format {
	ecc_region_t ecc_region;
	uint64_t ecc_space;
	int ecc_side;
} ecc_format_t;

typedef struct cb_fm_err {
	char *cb_err_class;
	uint64_t cb_reg_bit;
	int cb_fatal;
} cb_fm_err_t;

typedef struct ecc_fm_err {
	char *ecc_err_class;
	uint64_t ecc_reg_bit;
	int ecc_type;
	int ecc_pri;
	uint64_t ecc_region_bits;
	int ecc_region;
	int ecc_flag;
} ecc_fm_err_t;

/*
 * iommu errstate used to store iommu specific registers
 */
struct iommu_errstate {
	uint64_t iommu_stat;
	uint64_t iommu_tfar;
};

struct pci_errstate {
	char *pci_err_class;
	uint16_t pci_cfg_stat;
	uint16_t pci_cfg_comm;
	uint64_t pci_pa;
};

/*
 * pbm errstate use to encompass the state for all errors
 * detected by the pci block
 */
struct pbm_errstate {
	char *pbm_err_class;
	int pbm_pri;
	int pbm_log;
	uint32_t pbm_err;
	uint32_t pbm_multi;
	char *pbm_bridge_type;
	uint64_t pbm_ctl_stat;
	uint64_t pbm_afsr;
	uint64_t pbm_afar;
	uint64_t pbm_va_log;
	uint64_t pbm_err_sl;
	iommu_errstate_t pbm_iommu;
	uint64_t pbm_pcix_stat;
	uint32_t pbm_pcix_pfar;
	pci_errstate_t pbm_pci;
	char *pbm_terr_class;
};

/*
 * ecc errstate used to store all state captured,
 * upon detection of an ecc error.
 */
struct ecc_errstate {
	char *ecc_bridge_type;
	ecc_t *ecc_p;
	uint64_t ecc_afsr;
	uint64_t ecc_afar;
	uint64_t ecc_offset;
	uint64_t ecc_dev_id;
	uint64_t ecc_dw_offset;
	struct async_flt ecc_aflt;
	ecc_intr_info_t ecc_ii_p;
	uint64_t ecc_ctrl;
	int ecc_pri;
	ecc_region_t ecc_region;
	uint64_t ecc_ena;
	uint64_t ecc_err_addr;
	char *ecc_err_type;
	int ecc_pg_ret;
	int ecc_caller;
	nvlist_t *ecc_fmri;
	uint64_t ecc_dimm_offset;
	char ecc_unum[UNUM_NAMLEN];
	char ecc_dimm_sid[DIMM_SERIAL_ID_LEN];
};

/*
 * control block error state
 */
struct cb_errstate {
	char *cb_err_class;
	char *cb_bridge_type;
	uint64_t cb_csr;
	uint64_t cb_err;
	uint64_t cb_intr;
	uint64_t cb_elog;
	uint64_t cb_ecc;
	uint64_t cb_pcr;
	uint64_t cb_ue_afsr;
	uint64_t cb_ue_afar;
	uint64_t cb_ce_afsr;
	uint64_t cb_ce_afar;
	uint64_t cb_first_elog;
	uint64_t cb_first_eaddr;
	uint64_t cb_leaf_status;
	pbm_errstate_t cb_pbm[2];
};

extern int pci_fm_init_child(dev_info_t *dip, dev_info_t *tdip, int cap,
		ddi_iblock_cookie_t *ibc);
extern void pci_bus_enter(dev_info_t *dip, ddi_acc_handle_t handle);
extern void pci_bus_exit(dev_info_t *dip, ddi_acc_handle_t handle);
extern void pbm_ereport_post(dev_info_t *dip, uint64_t ena,
		pbm_errstate_t *pbm_err);
extern void pci_fm_acc_setup(ddi_map_req_t *mp, dev_info_t *rdip);
extern void pci_fmri_create(dev_info_t *dip, pci_common_t *cmn_p);
extern void pci_fm_create(pci_t *pci_p);
extern void pci_fm_destroy(pci_t *pci_p);
extern int pci_err_callback(dev_info_t *dip, ddi_fm_error_t *derr,
		const void *impl_data);
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _PCI_FM_H */
