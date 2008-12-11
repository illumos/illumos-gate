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
#include <assert.h>
#include <stddef.h>
#include <errno.h>
#include <strings.h>
#include <fm/fmd_api.h>
#include <fm/libtopo.h>
#include <sys/fm/util.h>
#include <sys/fm/protocol.h>
#include <sys/fm/io/pci.h>
#include <sys/fm/io/sun4_fire.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <sys/nvpair.h>
#include <sys/nvpair_impl.h>

#include <libxml/xpath.h>
#include <libxml/parser.h>
#include <libxml/xpathInternals.h>
#include <libxml/tree.h>

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
	uint16_t pcie_rp_ce_src_id;	/* pcie root complex ce sourpe id */
	uint16_t pcie_rp_ue_src_id;	/* pcie root complex ue sourpe id */
} fab_data_t;

/*
 * These values are used for the xxx_tgt_trans value in fab_data_t.  They are
 * originally set in pcie_fault.c and originally defined in pcie_impl.h.
 */
#define	PF_ADDR_DMA		(1 << 0)
#define	PF_ADDR_PIO		(1 << 1)
#define	PF_ADDR_CFG		(1 << 2)

typedef struct fab_erpt_tbl {
	const char	*err_class;	/* Final Ereport Class */
	uint32_t	reg_bit;	/* Error Bit Mask */
	/* Pointer to function that prepares the ereport body */
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

typedef struct fab_fire_tbl {
	const char	*err_class;
	uint32_t	fire_bit;	/* Fire error bit */
	uint16_t	pci_err_sts;	/* Equivalent PCI Error Status */
	uint16_t	pci_bdg_sts;	/* Equivalent PCI Bridge Status */
} fab_fire_tbl_t;

/* Static FM Topo XML Format and XML XPath Context  */
static xmlDocPtr		fab_doc = NULL;
static xmlXPathContextPtr	fab_xpathCtx = NULL;
static int			fab_valid_topo = 0;
#define	XMLTOPOFILE "/tmp/fab-xlate-topo.xml"

/* Functions that convert ereports to a common C data structure */
static void fab_pci_fabric_to_data(fmd_hdl_t *hdl, nvlist_t *nvl,
    fab_data_t *data);
static void fab_fire_to_data(fmd_hdl_t *hdl, nvlist_t *nvl, fab_data_t *data);

/* Common functions for sending translated ereports */
static int fab_prep_basic_erpt(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *erpt,
    boolean_t isRC);
static boolean_t fab_get_rcpath(fmd_hdl_t *hdl, nvlist_t *nvl, char *rcpath);
static char *fab_find_addr(fmd_hdl_t *hdl, nvlist_t *nvl, uint64_t addr);
static char *fab_find_bdf(fmd_hdl_t *hdl, nvlist_t *nvl, pcie_req_id_t bdf);
static void fab_send_tgt_erpt(fmd_hdl_t *hdl, fab_data_t *data,
    const char *class, boolean_t isPrimary);
static void fab_send_erpt(fmd_hdl_t *hdl, fab_data_t *data, fab_err_tbl_t *tbl);

/*
 * Common functions for converting  pci.fabric classes of
 * ereports
 */
static int fab_prep_pci_erpt(fmd_hdl_t *hdl, fab_data_t *data,
    nvlist_t *erpt, fab_erpt_tbl_t *table);
static int fab_prep_pci_bdg_erpt(fmd_hdl_t *hdl, fab_data_t *data,
    nvlist_t *erpt, fab_erpt_tbl_t *table);
static int fab_prep_pci_bdg_ctl_erpt(fmd_hdl_t *hdl, fab_data_t *data,
    nvlist_t *erpt, fab_erpt_tbl_t *table);
static int fab_prep_pcie_ce_erpt(fmd_hdl_t *hdl, fab_data_t *data,
    nvlist_t *erpt, fab_erpt_tbl_t *table);
static int fab_prep_pcie_ue_erpt(fmd_hdl_t *hdl, fab_data_t *data,
    nvlist_t *erpt, fab_erpt_tbl_t *table);
static int fab_prep_pcie_sue_erpt(fmd_hdl_t *hdl, fab_data_t *data,
    nvlist_t *erpt, fab_erpt_tbl_t *table);
static int fab_prep_pcie_nadv_erpt(fmd_hdl_t *hdl, fab_data_t *data,
    nvlist_t *erpt, fab_erpt_tbl_t *table);
static int fab_prep_pcix_erpt(fmd_hdl_t *hdl, fab_data_t *data,
    nvlist_t *erpt, fab_erpt_tbl_t *table);
static void fab_send_pcix_ecc_erpt(fmd_hdl_t *hdl, fab_data_t *data);
static int fab_prep_pcix_bdg_erpt(fmd_hdl_t *hdl, fab_data_t *data,
    nvlist_t *erpt, fab_erpt_tbl_t *table);
static void fab_send_pcix_bdg_ecc_erpt(fmd_hdl_t *hdl, fab_data_t *data);
static int fab_prep_pcie_rc_erpt(fmd_hdl_t *hdl, fab_data_t *data,
    nvlist_t *erpt, fab_erpt_tbl_t *table);
static int fab_prep_pcie_fake_rc_erpt(fmd_hdl_t *hdl, fab_data_t *data,
    nvlist_t *erpt, fab_erpt_tbl_t *table);

/* Functions for converting fire specific error registers */
static int fab_xlate_fire_ce(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    const char *class);
static int fab_xlate_fire_ue(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    const char *class);
static int fab_xlate_fire_oe(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    const char *class);
static int fab_xlate_fire_dmc(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    const char *class);

/* Main functions for converting "fabric" ereports */
static void fab_xlate_pcie_erpts(fmd_hdl_t *hdl, fab_data_t *data);
static void fab_xlate_fire_erpts(fmd_hdl_t *hdl, fab_data_t *data,
    nvlist_t *nvl, const char *class);

/*
 * Translation tables for converting "fabric" error bits into "pci" ereports.
 * <Ereport Class Name>, <Error Bit Mask>, <Preparation Function>
 */

/* MACRO for table entries with no TGT ereports */
#define	NT(class, bit, prep) class, bit, prep, NULL
/* Translate Fabric ereports to ereport.io.pci.* */
static fab_erpt_tbl_t fab_pci_erpt_tbl[] = {
	PCI_DET_PERR,		PCI_STAT_PERROR,	NULL,
	PCI_MDPE,		PCI_STAT_S_PERROR,	NULL,
	PCI_SIG_SERR,		PCI_STAT_S_SYSERR,	NULL,
	PCI_MA,			PCI_STAT_R_MAST_AB,	NULL,
	PCI_REC_TA,		PCI_STAT_R_TARG_AB,	NULL,
	PCI_SIG_TA,		PCI_STAT_S_TARG_AB,	NULL,
	NULL, NULL, NULL
};

/* Translate Fabric ereports to ereport.io.pci.sec-* */
static fab_erpt_tbl_t fab_pci_bdg_erpt_tbl[] = {
	PCI_DET_PERR,		PCI_STAT_PERROR,	NULL,
	PCI_MDPE,		PCI_STAT_S_PERROR,	NULL,
	PCI_REC_SERR,		PCI_STAT_S_SYSERR,	NULL,
#ifdef sparc
	PCI_MA,			PCI_STAT_R_MAST_AB,	NULL,
#endif
	PCI_REC_TA,		PCI_STAT_R_TARG_AB,	NULL,
	PCI_SIG_TA,		PCI_STAT_S_TARG_AB,	NULL,
	NULL, NULL, NULL, NULL,
};


/* Translate Fabric ereports to ereport.io.pci.dto */
static fab_erpt_tbl_t fab_pci_bdg_ctl_erpt_tbl[] = {
	PCI_DTO,	PCI_BCNF_BCNTRL_DTO_STAT,	NULL,
	NULL, NULL, NULL
};

/* Translate Fabric ereports to ereport.io.pciex.* */
static fab_erpt_tbl_t fab_pcie_ce_erpt_tbl[] = {
	PCIEX_RE,	PCIE_AER_CE_RECEIVER_ERR,	NULL,
	PCIEX_RNR,	PCIE_AER_CE_REPLAY_ROLLOVER,	NULL,
	PCIEX_RTO,	PCIE_AER_CE_REPLAY_TO,		NULL,
	PCIEX_BDP,	PCIE_AER_CE_BAD_DLLP,		NULL,
	PCIEX_BTP,	PCIE_AER_CE_BAD_TLP,		NULL,
	PCIEX_ANFE,	PCIE_AER_CE_AD_NFE,		NULL,
	NULL, NULL, NULL
};

/* Translate Fabric ereports to ereport.io.pciex.* */
static fab_erpt_tbl_t fab_pcie_ue_erpt_tbl[] = {
	PCIEX_TE,	PCIE_AER_UCE_TRAINING,		NULL,
	PCIEX_DLP,	PCIE_AER_UCE_DLP,		NULL,
	PCIEX_SD,	PCIE_AER_UCE_SD,		NULL,
	PCIEX_ROF,	PCIE_AER_UCE_RO,		NULL,
	PCIEX_FCP,	PCIE_AER_UCE_FCP,		NULL,
	PCIEX_MFP,	PCIE_AER_UCE_MTLP,		NULL,
	PCIEX_CTO,	PCIE_AER_UCE_TO,		PCI_TARG_MA,
	PCIEX_UC,	PCIE_AER_UCE_UC,		NULL,
	PCIEX_ECRC,	PCIE_AER_UCE_ECRC,		NULL,
	PCIEX_CA,	PCIE_AER_UCE_CA,		PCI_TARG_REC_TA,
#ifdef sparc
	PCIEX_UR,	PCIE_AER_UCE_UR,		PCI_TARG_MA,
#endif
	PCIEX_POIS,	PCIE_AER_UCE_PTLP,		PCI_TARG_MDPE,
	NULL, NULL, NULL
};

/* Translate Fabric ereports to ereport.io.pciex.* */
static fab_erpt_tbl_t fab_pcie_sue_erpt_tbl[] = {
	PCIEX_S_TA_SC,	PCIE_AER_SUCE_TA_ON_SC,		PCI_TARG_REC_TA,
	PCIEX_S_MA_SC,	PCIE_AER_SUCE_MA_ON_SC,		PCI_TARG_MA,
	PCIEX_S_RTA,	PCIE_AER_SUCE_RCVD_TA,		PCI_TARG_REC_TA,
#ifdef sparc
	PCIEX_S_RMA,	PCIE_AER_SUCE_RCVD_MA,		PCI_TARG_MA,
#endif
	PCIEX_S_USC,	PCIE_AER_SUCE_USC_ERR,		NULL,
	PCIEX_S_USCMD,	PCIE_AER_SUCE_USC_MSG_DATA_ERR,	PCI_TARG_REC_TA,
	PCIEX_S_UDE,	PCIE_AER_SUCE_UC_DATA_ERR,	PCI_TARG_MDPE,
	PCIEX_S_UAT,	PCIE_AER_SUCE_UC_ATTR_ERR,	PCI_TARG_MDPE,
	PCIEX_S_UADR,	PCIE_AER_SUCE_UC_ADDR_ERR,	PCI_TARG_MDPE,
	PCIEX_S_TEX,	PCIE_AER_SUCE_TIMER_EXPIRED,	NULL,
	PCIEX_S_PERR,	PCIE_AER_SUCE_PERR_ASSERT,	PCI_TARG_MDPE,
	PCIEX_S_SERR,	PCIE_AER_SUCE_SERR_ASSERT,	NULL,
	PCIEX_INTERR,	PCIE_AER_SUCE_INTERNAL_ERR,	NULL,
	NULL, NULL, NULL
};

/* Translate Fabric ereports to ereport.io.pcix.* */
static fab_erpt_tbl_t fab_pcix_erpt_tbl[] = {
	PCIX_SPL_DIS,		PCI_PCIX_SPL_DSCD,	NULL,
	PCIX_UNEX_SPL,		PCI_PCIX_UNEX_SPL,	NULL,
	PCIX_RX_SPL_MSG,	PCI_PCIX_RX_SPL_MSG,	NULL,
	NULL, NULL, NULL
};
static fab_erpt_tbl_t *fab_pcix_bdg_erpt_tbl = fab_pcix_erpt_tbl;

/* Translate Fabric ereports to ereport.io.pcix.sec-* */
static fab_erpt_tbl_t fab_pcix_bdg_sec_erpt_tbl[] = {
	PCIX_SPL_DIS,		PCI_PCIX_BSS_SPL_DSCD,	NULL,
	PCIX_UNEX_SPL,		PCI_PCIX_BSS_UNEX_SPL,	NULL,
	PCIX_BSS_SPL_OR,	PCI_PCIX_BSS_SPL_OR,	NULL,
	PCIX_BSS_SPL_DLY,	PCI_PCIX_BSS_SPL_DLY,	NULL,
	NULL, NULL, NULL
};

/* Translate Fabric ereports to ereport.io.pciex.* */
static fab_erpt_tbl_t fab_pcie_nadv_erpt_tbl[] = {
#ifdef sparc
	PCIEX_UR,		PCIE_DEVSTS_UR_DETECTED,	NULL,
#endif
	PCIEX_FAT,		PCIE_DEVSTS_FE_DETECTED,	NULL,
	PCIEX_NONFAT,		PCIE_DEVSTS_NFE_DETECTED,	NULL,
	PCIEX_CORR,		PCIE_DEVSTS_CE_DETECTED,	NULL,
	NULL, NULL, NULL
};

/* Translate Fabric ereports to ereport.io.pciex.* */
static fab_erpt_tbl_t fab_pcie_rc_erpt_tbl[] = {
	PCIEX_RC_FE_MSG,	PCIE_AER_RE_STS_FE_MSGS_RCVD,	NULL,
	PCIEX_RC_NFE_MSG,	PCIE_AER_RE_STS_NFE_MSGS_RCVD,	NULL,
	PCIEX_RC_CE_MSG,	PCIE_AER_RE_STS_CE_RCVD,	NULL,
	PCIEX_RC_MCE_MSG,	PCIE_AER_RE_STS_MUL_CE_RCVD,	NULL,
	PCIEX_RC_MUE_MSG,	PCIE_AER_RE_STS_MUL_FE_NFE_RCVD, NULL,
	NULL, NULL, NULL
};

/*
 * Translate Fabric ereports to pseudo ereport.io.pciex.* RC Fabric Messages.
 * If the RP is not a PCIe compliant RP or does not support AER, rely on the
 * leaf fabric ereport to help create a xxx_MSG ereport coming from the RC.
 */
static fab_erpt_tbl_t fab_pcie_fake_rc_erpt_tbl[] = {
	PCIEX_RC_FE_MSG,	PCIE_DEVSTS_FE_DETECTED,	NULL,
	PCIEX_RC_NFE_MSG,	PCIE_DEVSTS_NFE_DETECTED,	NULL,
	PCIEX_RC_CE_MSG,	PCIE_DEVSTS_CE_DETECTED,	NULL,
	NULL, NULL, NULL,
};

static fab_err_tbl_t *fab_master_err_tbl;

/*
 * Translation tables for converting fire error bits into "pci" ereports.
 * <Fire Bit>
 * <pci ereport Class>
 * <pci error status reg>
 * <pci bridge status reg>
 * <pci target class>
 */
#define	FAB_FIRE_PEC_BIT(fb) "ereport.io." PCIEX_FIRE "." FIRE_PEC_ ## fb
#define	FAB_FIRE_DMC_BIT(fb) "ereport.io." PCIEX_FIRE "." FIRE_DMC_ ## fb
#define	FAB_N2_DMU_BIT(fb) "ereport.io.n2.dmu." fb
#define	FAB_OB_PEC_BIT(fb) "ereport.io." PCIEX_OBERON "." FIRE_PEC_ ## fb

#define	FAB_FIRE_UE(fb, bit, sts, bdg) \
	FAB_FIRE_PEC_BIT(fb), PCIE_AER_UCE_ ## bit, sts, bdg
#define	FAB_OB_UE(fb, bit, sts, bdg) \
	FAB_OB_PEC_BIT(fb), PCIE_AER_UCE_ ## bit, sts, bdg
static fab_fire_tbl_t fab_fire_pec_ue_tbl[] = {
	FAB_FIRE_UE(UR,	 UR,	   PCI_STAT_S_SYSERR,	0),
	FAB_FIRE_UE(UC,	 UC,	   PCI_STAT_S_SYSERR,	0),
	FAB_OB_UE(ECRC,	 ECRC,	   PCI_STAT_S_SYSERR,	0),
	FAB_FIRE_UE(CTO, TO,	   PCI_STAT_S_SYSERR,	0),
	FAB_FIRE_UE(ROF, RO,	   PCI_STAT_S_SYSERR,	0),
	FAB_FIRE_UE(MFP, MTLP,	   PCI_STAT_S_SYSERR,	0),
	FAB_FIRE_UE(PP,	 PTLP,	   PCI_STAT_S_PERROR,
	    (PCI_STAT_S_SYSERR | PCI_STAT_PERROR)),
	FAB_FIRE_UE(FCP, FCP,	   PCI_STAT_S_SYSERR,	0),
	FAB_FIRE_UE(DLP, DLP,	   PCI_STAT_S_SYSERR,	0),
	FAB_FIRE_UE(TE,	 TRAINING, PCI_STAT_S_SYSERR,	0),
	FAB_FIRE_UE(CA,	 CA,	   PCI_STAT_S_TARG_AB,
	    PCI_STAT_S_TARG_AB),
	NULL, NULL, NULL,
};

#define	FAB_FIRE_CE(fb, bit) \
	FAB_FIRE_PEC_BIT(fb), PCIE_AER_CE_ ## bit, 0, 0
static fab_fire_tbl_t fab_fire_pec_ce_tbl[] = {
	FAB_FIRE_CE(RTO,	REPLAY_TO),
	FAB_FIRE_CE(RNR,	REPLAY_ROLLOVER),
	FAB_FIRE_CE(BDP,	BAD_DLLP),
	FAB_FIRE_CE(BTP,	BAD_TLP),
	FAB_FIRE_CE(RE,		RECEIVER_ERR),
	NULL, NULL, NULL,
};

/*
 * WUC/RUC will need to be special cased for the target ereports, because you
 * need to decode the tlp log.
 */
#define	FAB_FIRE_WUCRUC(fb) \
	FAB_FIRE_PEC_BIT(fb), 0, 0, (PCI_STAT_R_MAST_AB | PCI_STAT_S_SYSERR)
#define	FAB_FIRE_OE(fb, bit) \
	FAB_FIRE_PEC_BIT(fb), PCIE_AER_UCE_ ## bit, PCI_STAT_S_SYSERR, 0
#define	FAB_OB_OE(fb, bit) \
	FAB_FIRE_PEC_BIT(fb), PCIE_AER_UCE_ ## bit, PCI_STAT_S_SYSERR, 0
static fab_fire_tbl_t fab_fire_pec_oe_tbl[] = {
	FAB_FIRE_WUCRUC(WUC),
	FAB_FIRE_WUCRUC(RUC),
	FAB_FIRE_OE(ERU, DLP),
	FAB_FIRE_OE(ERO, DLP),
	FAB_FIRE_OE(EMP, DLP),
	FAB_FIRE_OE(EPE, DLP),
	NULL, NULL, NULL,
};

#define	FAB_FIRE_DMC(fb) \
	FAB_FIRE_DMC_BIT(fb), PCIE_AER_UCE_CA, 0, PCI_STAT_S_TARG_AB
#define	FAB_N2_DMU(fb) \
	FAB_N2_DMU_BIT(fb), PCIE_AER_UCE_CA, 0, PCI_STAT_S_TARG_AB
static fab_fire_tbl_t fab_fire_dmc_tbl[] = {
	FAB_FIRE_DMC(BYP_ERR),
	FAB_FIRE_DMC(BYP_OOR),
	FAB_FIRE_DMC(TRN_OOR),
	FAB_FIRE_DMC(TTE_INV),
	FAB_FIRE_DMC(TTE_PRT),
	FAB_N2_DMU("iotsbdesc_inv"),
	FAB_N2_DMU("sun4v_adj_va_uf"),
	FAB_N2_DMU("sun4v_inv_pg_sz"),
	FAB_N2_DMU("sun4v_key_err"),
	FAB_N2_DMU("sun4v_va_oor"),
	NULL, NULL, NULL
};

static fmd_xprt_t *fab_fmd_xprt = NULL;	/* FMD transport layer handle */
static char fab_buf[FM_MAX_CLASS];
static boolean_t fab_xlate_fake_rp = B_TRUE;

#define	HAS_PROP(node, name) xmlHasProp(node, (const xmlChar *)name)
#define	GET_PROP(node, name) ((char *)xmlGetProp(node, (const xmlChar *)name))
#define	STRCMP(s1, s2) (strcmp((const char *)s1, (const char *)s2) == 0)

#define	FAB_LOOKUP(sz, name, field) \
	(void) nvlist_lookup_uint ## sz(nvl, name, field)
/* ARGSUSED */
static void
fab_pci_fabric_to_data(fmd_hdl_t *hdl, nvlist_t *nvl, fab_data_t *data) {
	data->nvl = nvl;

	/* Generic PCI device information */
	FAB_LOOKUP(16,	"bdf",			&data->bdf);
	FAB_LOOKUP(16,	"device_id",		&data->device_id);
	FAB_LOOKUP(16,	"vendor_id",		&data->vendor_id);
	FAB_LOOKUP(8,	"rev_id",		&data->rev_id);
	FAB_LOOKUP(16,	"dev_type",		&data->dev_type);
	FAB_LOOKUP(16,	"pcie_off",		&data->pcie_off);
	FAB_LOOKUP(16,	"pcix_off",		&data->pcix_off);
	FAB_LOOKUP(16,	"aer_off",		&data->aer_off);
	FAB_LOOKUP(16,	"ecc_ver",		&data->ecc_ver);

	/* Misc ereport information */
	FAB_LOOKUP(32,	"remainder",		&data->remainder);
	FAB_LOOKUP(32,	"severity",		&data->severity);

	/* PCI registers */
	FAB_LOOKUP(16,	"pci_status",		&data->pci_err_status);
	FAB_LOOKUP(16,	"pci_command",		&data->pci_cfg_comm);

	/* PCI bridge registers */
	FAB_LOOKUP(16,	"pci_bdg_sec_status",	&data->pci_bdg_sec_stat);
	FAB_LOOKUP(16,	"pci_bdg_ctrl",		&data->pci_bdg_ctrl);

	/* PCIx registers */
	FAB_LOOKUP(32,	"pcix_status",		&data->pcix_status);
	FAB_LOOKUP(16,	"pcix_command",		&data->pcix_command);

	/* PCIx ECC Registers */
	FAB_LOOKUP(16,	"pcix_ecc_control_0",	&data->pcix_ecc_control_0);
	FAB_LOOKUP(16,	"pcix_ecc_status_0",	&data->pcix_ecc_status_0);
	FAB_LOOKUP(32,	"pcix_ecc_fst_addr_0",	&data->pcix_ecc_fst_addr_0);
	FAB_LOOKUP(32,	"pcix_ecc_sec_addr_0",	&data->pcix_ecc_sec_addr_0);
	FAB_LOOKUP(32,	"pcix_ecc_attr_0",	&data->pcix_ecc_attr_0);

	/* PCIx ECC Bridge Registers */
	FAB_LOOKUP(16,	"pcix_ecc_control_1",	&data->pcix_ecc_control_1);
	FAB_LOOKUP(16,	"pcix_ecc_status_1",	&data->pcix_ecc_status_1);
	FAB_LOOKUP(32,	"pcix_ecc_fst_addr_1",	&data->pcix_ecc_fst_addr_1);
	FAB_LOOKUP(32,	"pcix_ecc_sec_addr_1",	&data->pcix_ecc_sec_addr_1);
	FAB_LOOKUP(32,	"pcix_ecc_attr_1",	&data->pcix_ecc_attr_1);

	/* PCIx Bridge */
	FAB_LOOKUP(32,	"pcix_bdg_status",	&data->pcix_bdg_stat);
	FAB_LOOKUP(16,	"pcix_bdg_sec_status",	&data->pcix_bdg_sec_stat);

	/* PCIe registers */
	FAB_LOOKUP(16,	"pcie_status",		&data->pcie_err_status);
	FAB_LOOKUP(16,	"pcie_command",		&data->pcie_err_ctl);
	FAB_LOOKUP(32,	"pcie_dev_cap",		&data->pcie_dev_cap);

	/* PCIe AER registers */
	FAB_LOOKUP(32,	"pcie_adv_ctl",		&data->pcie_adv_ctl);
	FAB_LOOKUP(32,	"pcie_ue_status",	&data->pcie_ue_status);
	FAB_LOOKUP(32,	"pcie_ue_mask",		&data->pcie_ue_mask);
	FAB_LOOKUP(32,	"pcie_ue_sev",		&data->pcie_ue_sev);
	FAB_LOOKUP(32,	"pcie_ue_hdr0",		&data->pcie_ue_hdr[0]);
	FAB_LOOKUP(32,	"pcie_ue_hdr1",		&data->pcie_ue_hdr[1]);
	FAB_LOOKUP(32,	"pcie_ue_hdr2",		&data->pcie_ue_hdr[2]);
	FAB_LOOKUP(32,	"pcie_ue_hdr3",		&data->pcie_ue_hdr[3]);
	FAB_LOOKUP(32,	"pcie_ce_status",	&data->pcie_ce_status);
	FAB_LOOKUP(32,	"pcie_ce_mask",		&data->pcie_ce_mask);
	FAB_LOOKUP(32,	"pcie_ue_tgt_trans",	&data->pcie_ue_tgt_trans);
	FAB_LOOKUP(64,	"pcie_ue_tgt_addr",	&data->pcie_ue_tgt_addr);
	FAB_LOOKUP(16,	"pcie_ue_tgt_bdf",	&data->pcie_ue_tgt_bdf);

	/* PCIe BDG AER registers */
	FAB_LOOKUP(32,	"pcie_sue_adv_ctl",	&data->pcie_sue_ctl);
	FAB_LOOKUP(32,	"pcie_sue_status",	&data->pcie_sue_status);
	FAB_LOOKUP(32,	"pcie_sue_mask",	&data->pcie_sue_mask);
	FAB_LOOKUP(32,	"pcie_sue_sev",		&data->pcie_sue_sev);
	FAB_LOOKUP(32,	"pcie_sue_hdr0",	&data->pcie_sue_hdr[0]);
	FAB_LOOKUP(32,	"pcie_sue_hdr1",	&data->pcie_sue_hdr[1]);
	FAB_LOOKUP(32,	"pcie_sue_hdr2",	&data->pcie_sue_hdr[2]);
	FAB_LOOKUP(32,	"pcie_sue_hdr3",	&data->pcie_sue_hdr[3]);
	FAB_LOOKUP(32,	"pcie_sue_tgt_trans",	&data->pcie_sue_tgt_trans);
	FAB_LOOKUP(64,	"pcie_sue_tgt_addr",	&data->pcie_sue_tgt_addr);
	FAB_LOOKUP(16,	"pcie_sue_tgt_bdf",	&data->pcie_sue_tgt_bdf);

	/* PCIe RP registers */
	FAB_LOOKUP(32,	"pcie_rp_status",	&data->pcie_rp_status);
	FAB_LOOKUP(16,	"pcie_rp_control",	&data->pcie_rp_ctl);

	/* PCIe RP AER registers */
	FAB_LOOKUP(32,	"pcie_adv_rp_status",	&data->pcie_rp_err_status);
	FAB_LOOKUP(32,	"pcie_adv_rp_command",	&data->pcie_rp_err_cmd);
	FAB_LOOKUP(16,	"pcie_adv_rp_ce_src_id", &data->pcie_rp_ce_src_id);
	FAB_LOOKUP(16,	"pcie_adv_rp_ue_src_id", &data->pcie_rp_ue_src_id);

	/*
	 * If the system has a PCIe complaint RP with AER, turn off translating
	 * fake RP ereports.
	 */
	if (fab_xlate_fake_rp &&
	    (data->dev_type == PCIE_PCIECAP_DEV_TYPE_ROOT) &&
	    data->aer_off)
		fab_xlate_fake_rp = B_FALSE;
}

/* ARGSUSED */
static void
fab_fire_to_data(fmd_hdl_t *hdl, nvlist_t *nvl, fab_data_t *data) {
	data->nvl = nvl;

	/* Always Root Complex */
	data->dev_type = PCIE_PCIECAP_DEV_TYPE_ROOT;

	data->pcie_ue_sev = (PCIE_AER_UCE_DLP | PCIE_AER_UCE_SD |
	    PCIE_AER_UCE_FCP | PCIE_AER_UCE_RO | PCIE_AER_UCE_MTLP);
}

/* ARGSUSED */
static int
fab_prep_basic_erpt(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *erpt,
    boolean_t isRC) {
	uint64_t	*now;
	uint64_t	ena;
	uint_t		nelem;
	nvlist_t	*detector, *new_detector;
	char		rcpath[255];
	int		err = 0;

	/* Grab the tod, ena and detector(FMRI) */
	err |= nvlist_lookup_uint64_array(nvl, "__tod", &now, &nelem);
	err |= nvlist_lookup_uint64(nvl, "ena", &ena);
	err |= nvlist_lookup_nvlist(nvl, FM_EREPORT_DETECTOR, &detector);
	if (err)
		return (err);

	/* Make a copy of the detector */
	err = nvlist_dup(detector, &new_detector, NV_UNIQUE_NAME);
	if (err)
		return (err);

	/* Copy the tod and ena to erpt */
	(void) nvlist_add_uint64(erpt, FM_EREPORT_ENA, ena);
	(void) nvlist_add_uint64_array(erpt, "__tod", now, nelem);

	/*
	 * Create the correct ROOT FMRI from PCIe leaf fabric ereports.	 Used
	 * only by fab_prep_fake_rc_erpt.  See the fab_pciex_fake_rc_erpt_tbl
	 * comments for more information.
	 */
	if (isRC && fab_get_rcpath(hdl, nvl, rcpath)) {
		/* Create the correct PCIe RC new_detector aka FMRI */
		(void) nvlist_remove(new_detector, FM_FMRI_DEV_PATH,
		    DATA_TYPE_STRING);
		(void) nvlist_add_string(new_detector, FM_FMRI_DEV_PATH,
		    rcpath);
	}

	/* Copy the FMRI to erpt */
	(void) nvlist_add_nvlist(erpt, FM_EREPORT_DETECTOR, new_detector);

	nvlist_free(new_detector);
	return (err);
}

static void
fab_send_tgt_erpt(fmd_hdl_t *hdl, fab_data_t *data, const char *class,
    boolean_t isPrimary)
{
	nvlist_t	*nvl = data->nvl;
	nvlist_t	*erpt;
	char		*fmri = NULL;
	uint32_t	tgt_trans;
	uint64_t	tgt_addr;
	uint16_t	tgt_bdf;

	if (isPrimary) {
		tgt_trans = data->pcie_ue_tgt_trans;
		tgt_addr = data->pcie_ue_tgt_addr;
		tgt_bdf = data->pcie_ue_tgt_bdf;
	} else {
		tgt_trans = data->pcie_sue_tgt_trans;
		tgt_addr = data->pcie_sue_tgt_addr;
		tgt_bdf = data->pcie_sue_tgt_bdf;
	}

	fmd_hdl_debug(hdl, "Sending Target Ereport: "
	    "type 0x%x addr 0x%llx fltbdf 0x%x\n",
	    tgt_trans, tgt_addr, tgt_bdf);

	if (!tgt_trans)
		return;

	if ((tgt_trans == PF_ADDR_PIO) && tgt_addr)
		fmri = fab_find_addr(hdl, nvl, tgt_addr);
	else if ((tgt_trans == PF_ADDR_CFG) && tgt_bdf)
		fmri = fab_find_bdf(hdl, nvl, tgt_bdf);

	if (fmri) {
		uint64_t	*now;
		uint64_t	ena;
		uint_t		nelem;
		nvlist_t	*detector;
		int		err = 0;

		/* Allocate space for new erpt */
		if (nvlist_alloc(&erpt, NV_UNIQUE_NAME, 0) != 0)
			goto done;

		/* Generate the target ereport class */
		(void) snprintf(fab_buf, FM_MAX_CLASS, "ereport.io.%s.%s",
		    PCI_ERROR_SUBCLASS, class);
		(void) nvlist_add_string(erpt, FM_CLASS, fab_buf);

		/* Grab the tod, ena and detector(FMRI) */
		err |= nvlist_lookup_uint64_array(nvl, "__tod", &now, &nelem);
		err |= nvlist_lookup_uint64(nvl, "ena", &ena);

		/* Copy the tod and ena to erpt */
		(void) nvlist_add_uint64(erpt, FM_EREPORT_ENA, ena);
		(void) nvlist_add_uint64_array(erpt, "__tod", now, nelem);

		/* Create the correct FMRI */
		if (nvlist_alloc(&detector, NV_UNIQUE_NAME, 0) != 0) {
			nvlist_free(erpt);
			goto done;
		}
		(void) nvlist_add_string(detector, FM_VERSION,
		    FM_DEV_SCHEME_VERSION);
		(void) nvlist_add_string(detector, FM_FMRI_SCHEME,
		    FM_FMRI_SCHEME_DEV);
		(void) nvlist_add_string(detector, FM_FMRI_DEV_PATH, fmri);
		(void) nvlist_add_nvlist(erpt, FM_EREPORT_DETECTOR, detector);

		/* Add the address payload */
		(void) nvlist_add_uint64(erpt, PCI_PA, tgt_addr);

		fmd_hdl_debug(hdl, "Sending target ereport: %s 0x%x\n",
		    fab_buf, tgt_addr);
		fmd_xprt_post(hdl, fab_fmd_xprt, erpt, 0);
		if (fmd_xprt_error(hdl, fab_fmd_xprt))
			goto done;
	} else {
		fmd_hdl_debug(hdl, "Cannot find Target FMRI addr:0x%llx",
		    tgt_addr);
	}

	return;
done:
	fmd_hdl_debug(hdl, "Failed to send Target PCI ereport\n");
}

static void
fab_send_erpt(fmd_hdl_t *hdl, fab_data_t *data, fab_err_tbl_t *tbl)
{
	fab_erpt_tbl_t	*erpt_tbl, *entry;
	nvlist_t	*erpt;
	uint32_t	reg;

	erpt_tbl = tbl->erpt_tbl;
	if (tbl->reg_size == 16) {
		reg = (uint32_t)*((uint16_t *)
		    ((uint32_t)data + tbl->reg_offset));
	} else {
		reg = *((uint32_t *)((uint32_t)data + tbl->reg_offset));
	}

	for (entry = erpt_tbl; entry->err_class; entry++) {
		if (!(reg & entry->reg_bit))
			continue;

		if (nvlist_alloc(&erpt, NV_UNIQUE_NAME, 0) != 0)
			goto done;
		if (tbl->fab_prep(hdl, data, erpt, entry) != 0) {
			fmd_hdl_debug(hdl, "Prepping ereport failed\n");
			nvlist_free(erpt);
			continue;
		}

		fmd_hdl_debug(hdl, "Sending ereport: %s 0x%x\n", fab_buf, reg);
		fmd_xprt_post(hdl, fab_fmd_xprt, erpt, 0);
		if (fmd_xprt_error(hdl, fab_fmd_xprt)) {
			fmd_hdl_debug(hdl, "Failed to send PCI ereport\n");
			return;
		}
	}

	return;
done:
	fmd_hdl_debug(hdl, "Failed  to send PCI ereport\n");
}

static int
fab_prep_pci_erpt(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    fab_erpt_tbl_t *tbl)
{
	const char *class = tbl->err_class;
	int err = fab_prep_basic_erpt(hdl, data->nvl, erpt, B_FALSE);

	/* Generate an ereport for this error bit. */
	(void) snprintf(fab_buf, FM_MAX_CLASS, "ereport.io.%s.%s",
	    PCI_ERROR_SUBCLASS, class);
	(void) nvlist_add_string(erpt, FM_CLASS, fab_buf);

	(void) nvlist_add_uint16(erpt, PCI_CONFIG_STATUS, data->pci_err_status);
	(void) nvlist_add_uint16(erpt, PCI_CONFIG_COMMAND, data->pci_cfg_comm);

	return (err);
}

static int
fab_prep_pci_bdg_erpt(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    fab_erpt_tbl_t *tbl)
{
	const char *class = tbl->err_class;
	int err = fab_prep_basic_erpt(hdl, data->nvl, erpt, B_FALSE);

	/* Generate an ereport for this error bit. */
	(void) snprintf(fab_buf, FM_MAX_CLASS, "ereport.io.%s.%s-%s",
	    PCI_ERROR_SUBCLASS, PCI_SEC_ERROR_SUBCLASS, class);
	(void) nvlist_add_string(erpt, FM_CLASS, fab_buf);

	(void) nvlist_add_uint16(erpt, PCI_SEC_CONFIG_STATUS,
	    data->pci_bdg_sec_stat);
	(void) nvlist_add_uint16(erpt, PCI_BCNTRL, data->pci_bdg_ctrl);

	return (err);
}

static int
fab_prep_pci_bdg_ctl_erpt(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    fab_erpt_tbl_t *tbl)
{
	const char *class = tbl->err_class;
	int err = fab_prep_basic_erpt(hdl, data->nvl, erpt, B_FALSE);

	/* Generate an ereport for this error bit. */
	(void) snprintf(fab_buf, FM_MAX_CLASS, "ereport.io.%s.%s",
	    PCI_ERROR_SUBCLASS, class);
	(void) nvlist_add_string(erpt, FM_CLASS, fab_buf);

	(void) nvlist_add_uint16(erpt, PCI_SEC_CONFIG_STATUS,
	    data->pci_bdg_sec_stat);
	(void) nvlist_add_uint16(erpt, PCI_BCNTRL, data->pci_bdg_ctrl);

	return (err);
}


static int
fab_prep_pcie_ce_erpt(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    fab_erpt_tbl_t *tbl)
{
	const char *class = tbl->err_class;
	int err = fab_prep_basic_erpt(hdl, data->nvl, erpt, B_FALSE);

	/* Generate an ereport for this error bit. */
	(void) snprintf(fab_buf, FM_MAX_CLASS, "ereport.io.%s.%s",
	    PCIEX_ERROR_SUBCLASS, class);
	(void) nvlist_add_string(erpt, FM_CLASS, fab_buf);

	(void) nvlist_add_uint16(erpt, PCIEX_DEVSTS_REG, data->pcie_err_status);
	(void) nvlist_add_uint32(erpt, PCIEX_CE_STATUS_REG,
	    data->pcie_ce_status);

	return (err);
}

static int
fab_prep_pcie_ue_erpt(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    fab_erpt_tbl_t *tbl)
{
	const char *class = tbl->err_class;
	uint32_t first_err = 1 << (data->pcie_adv_ctl &
	    PCIE_AER_CTL_FST_ERR_PTR_MASK);
	int err = fab_prep_basic_erpt(hdl, data->nvl, erpt, B_FALSE);

	/* Generate an ereport for this error bit. */
	(void) snprintf(fab_buf, FM_MAX_CLASS, "ereport.io.%s.%s",
	    PCIEX_ERROR_SUBCLASS, class);
	(void) nvlist_add_string(erpt, FM_CLASS, fab_buf);

	(void) nvlist_add_uint16(erpt, PCIEX_DEVSTS_REG, data->pcie_err_status);
	(void) nvlist_add_uint32(erpt, PCIEX_UE_STATUS_REG,
	    data->pcie_ue_status);
	(void) nvlist_add_uint32(erpt, PCIEX_UE_SEV_REG, data->pcie_ue_sev);
	(void) nvlist_add_uint32(erpt, PCIEX_ADV_CTL, data->pcie_adv_ctl);

	fmd_hdl_debug(hdl, "Bit 0x%x First Err 0x%x", tbl->reg_bit, first_err);

	if ((tbl->reg_bit == first_err) && data->pcie_ue_tgt_bdf) {
		(void) nvlist_add_uint16(erpt, PCIEX_SRC_ID,
		    data->pcie_ue_tgt_bdf);
		(void) nvlist_add_boolean_value(erpt, PCIEX_SRC_VALID, B_TRUE);
	} else {
		(void) nvlist_add_uint16(erpt, PCIEX_SRC_ID, 0);
		(void) nvlist_add_boolean_value(erpt, PCIEX_SRC_VALID, B_FALSE);
	}

	if ((tbl->reg_bit == first_err) && data->pcie_ue_tgt_trans) {
		if (tbl->tgt_class)
			fab_send_tgt_erpt(hdl, data, tbl->tgt_class, B_TRUE);
	}

	return (err);
}

static int
fab_prep_pcie_sue_erpt(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    fab_erpt_tbl_t *tbl)
{
	const char *class = tbl->err_class;
	uint32_t first_err = 1 << (data->pcie_sue_ctl &
	    PCIE_AER_SCTL_FST_ERR_PTR_MASK);
	int err = fab_prep_basic_erpt(hdl, data->nvl, erpt, B_FALSE);

	/* Generate an ereport for this error bit. */
	(void) snprintf(fab_buf, FM_MAX_CLASS, "ereport.io.%s.%s",
	    PCIEX_ERROR_SUBCLASS, class);
	(void) nvlist_add_string(erpt, FM_CLASS, fab_buf);

	(void) nvlist_add_uint32(erpt, PCIEX_SEC_UE_STATUS,
	    data->pcie_sue_status);

	fmd_hdl_debug(hdl, "Bit 0x%x First Err 0x%x", tbl->reg_bit, first_err);

	if ((tbl->reg_bit == first_err) && data->pcie_sue_tgt_bdf) {
		(void) nvlist_add_uint16(erpt, PCIEX_SRC_ID,
		    data->pcie_sue_tgt_bdf);
		(void) nvlist_add_boolean_value(erpt, PCIEX_SRC_VALID, B_TRUE);
	} else {
		(void) nvlist_add_uint16(erpt, PCIEX_SRC_ID, 0);
		(void) nvlist_add_boolean_value(erpt, PCIEX_SRC_VALID, B_FALSE);
	}

	if ((tbl->reg_bit == first_err) && data->pcie_sue_tgt_trans) {
		if (tbl->tgt_class)
			fab_send_tgt_erpt(hdl, data, tbl->tgt_class, B_FALSE);
	}

	return (err);
}

static int
fab_prep_pcix_erpt(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    fab_erpt_tbl_t *tbl)
{
	const char *class = tbl->err_class;
	int err = 0;

	/* Only send if this is not a bridge */
	if (!data->pcix_status || data->pcix_bdg_sec_stat)
		return (1);

	err = fab_prep_basic_erpt(hdl, data->nvl, erpt, B_FALSE);

	/* Generate an ereport for this error bit. */
	(void) snprintf(fab_buf, FM_MAX_CLASS, "ereport.io.%s.%s",
	    PCIX_ERROR_SUBCLASS, class);
	(void) nvlist_add_string(erpt, FM_CLASS, fab_buf);

	(void) nvlist_add_uint8(erpt, PCIX_COMMAND, data->pcix_command);
	(void) nvlist_add_uint32(erpt, PCIX_STATUS, data->pcix_status);

	return (err);
}

static void
fab_send_pcix_ecc_erpt(fmd_hdl_t *hdl, fab_data_t *data)
{
	nvlist_t *erpt;
	int ecc_phase = (data->pcix_ecc_status_0 & PCI_PCIX_ECC_PHASE) >> 0x4;
	int ecc_corr = data->pcix_ecc_status_0 & PCI_PCIX_ECC_CORR;
	int sec_ue = data->pcix_ecc_status_0 & PCI_PCIX_ECC_S_UE;
	int sec_ce = data->pcix_ecc_status_0 & PCI_PCIX_ECC_S_CE;
	uint32_t ctlstat = (data->pcix_ecc_control_0 << 16) |
	    data->pcix_ecc_status_0;

	switch (ecc_phase) {
	case PCI_PCIX_ECC_PHASE_NOERR:
		break;
	case PCI_PCIX_ECC_PHASE_FADDR:
	case PCI_PCIX_ECC_PHASE_SADDR:
		(void) snprintf(fab_buf, FM_MAX_CLASS,
		    "%s.%s", PCIX_ERROR_SUBCLASS,
		    ecc_corr ? PCIX_ECC_CE_ADDR : PCIX_ECC_UE_ADDR);
		break;
	case PCI_PCIX_ECC_PHASE_ATTR:
		(void) snprintf(fab_buf, FM_MAX_CLASS,
		    "%s.%s", PCIX_ERROR_SUBCLASS,
		    ecc_corr ? PCIX_ECC_CE_ATTR : PCIX_ECC_UE_ATTR);
		break;
	case PCI_PCIX_ECC_PHASE_DATA32:
	case PCI_PCIX_ECC_PHASE_DATA64:
		(void) snprintf(fab_buf, FM_MAX_CLASS,
		    "%s.%s", PCIX_ERROR_SUBCLASS,
		    ecc_corr ? PCIX_ECC_CE_DATA : PCIX_ECC_UE_DATA);
		break;
	}

	if (ecc_phase) {
		if (nvlist_alloc(&erpt, NV_UNIQUE_NAME, 0) != 0)
			goto done;
		(void) fab_prep_basic_erpt(hdl, data->nvl, erpt, B_FALSE);
		(void) nvlist_add_string(erpt, FM_CLASS, fab_buf);
		(void) nvlist_add_uint16(erpt, PCIX_COMMAND,
		    data->pcix_command);
		(void) nvlist_add_uint32(erpt, PCIX_STATUS, data->pcix_status);
		(void) nvlist_add_uint32(erpt, PCIX_ECC_CTLSTAT, ctlstat);
		(void) nvlist_add_uint32(erpt, PCIX_ECC_ATTR,
		    data->pcix_ecc_attr_0);
		fmd_hdl_debug(hdl, "Sending ecc ereport: %s\n", fab_buf);
		fmd_xprt_post(hdl, fab_fmd_xprt, erpt, 0);
		if (fmd_xprt_error(hdl, fab_fmd_xprt))
			fmd_hdl_debug(hdl, "Failed to send ECC ereport\n");
	}

	if (sec_ce || sec_ue) {
		(void) snprintf(fab_buf, FM_MAX_CLASS,
		    "%s.%s", PCIX_ERROR_SUBCLASS,
		    sec_ce ? PCIX_ECC_S_CE : PCIX_ECC_S_UE);
		if (nvlist_alloc(&erpt, NV_UNIQUE_NAME, 0) != 0)
			goto done;
		(void) fab_prep_basic_erpt(hdl, data->nvl, erpt, B_FALSE);
		(void) nvlist_add_string(erpt, FM_CLASS, fab_buf);
		(void) nvlist_add_uint16(erpt, PCIX_COMMAND,
		    data->pcix_command);
		(void) nvlist_add_uint32(erpt, PCIX_STATUS, data->pcix_status);
		(void) nvlist_add_uint32(erpt, PCIX_ECC_CTLSTAT, ctlstat);
		(void) nvlist_add_uint32(erpt, PCIX_ECC_ATTR,
		    data->pcix_ecc_attr_0);
		fmd_hdl_debug(hdl, "Sending ecc ereport: %s\n", fab_buf);
		fmd_xprt_post(hdl, fab_fmd_xprt, erpt, 0);
		if (fmd_xprt_error(hdl, fab_fmd_xprt))
			fmd_hdl_debug(hdl, "Failed to send ECC ereport\n");
	}

	return;
done:
	fmd_hdl_debug(hdl, "Failed to send ECC ereport\n");
}

static int
fab_prep_pcix_bdg_sec_erpt(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    fab_erpt_tbl_t *tbl)
{
	const char *class = tbl->err_class;
	int err = fab_prep_basic_erpt(hdl, data->nvl, erpt, B_FALSE);

	/* Generate an ereport for this error bit. */
	(void) snprintf(fab_buf, FM_MAX_CLASS, "ereport.io.%s.%s%s",
	    PCIX_ERROR_SUBCLASS, PCIX_SEC_ERROR_SUBCLASS, class);
	(void) nvlist_add_string(erpt, FM_CLASS, fab_buf);

	(void) nvlist_add_uint16(erpt, PCIX_SEC_STATUS,
	    data->pcix_bdg_sec_stat);
	(void) nvlist_add_uint32(erpt, PCIX_BDG_STAT, data->pcix_bdg_stat);

	return (err);
}

static int
fab_prep_pcix_bdg_erpt(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    fab_erpt_tbl_t *tbl)
{
	const char *class = tbl->err_class;
	int err = fab_prep_basic_erpt(hdl, data->nvl, erpt, B_FALSE);

	/* Generate an ereport for this error bit. */
	(void) snprintf(fab_buf, FM_MAX_CLASS, "ereport.io.%s.%s",
	    PCIX_ERROR_SUBCLASS, class);
	(void) nvlist_add_string(erpt, FM_CLASS, fab_buf);

	(void) nvlist_add_uint16(erpt, PCIX_SEC_STATUS,
	    data->pcix_bdg_sec_stat);
	(void) nvlist_add_uint32(erpt, PCIX_BDG_STAT, data->pcix_bdg_stat);

	return (err);
}

static void
fab_send_pcix_bdg_ecc_erpt(fmd_hdl_t *hdl, fab_data_t *data)
{
	nvlist_t *erpt;
	int ecc_phase = (data->pcix_ecc_status_1 & PCI_PCIX_ECC_PHASE) >> 0x4;
	int ecc_corr = data->pcix_ecc_status_1 & PCI_PCIX_ECC_CORR;
	int sec_ue = data->pcix_ecc_status_1 & PCI_PCIX_ECC_S_UE;
	int sec_ce = data->pcix_ecc_status_1 & PCI_PCIX_ECC_S_CE;
	uint32_t ctlstat = (data->pcix_ecc_control_1 << 16) |
	    data->pcix_ecc_status_1;

	switch (ecc_phase) {
	case PCI_PCIX_ECC_PHASE_NOERR:
		break;
	case PCI_PCIX_ECC_PHASE_FADDR:
	case PCI_PCIX_ECC_PHASE_SADDR:
		(void) snprintf(fab_buf, FM_MAX_CLASS,
		    "%s.%s%s", PCIX_ERROR_SUBCLASS, PCIX_SEC_ERROR_SUBCLASS,
		    ecc_corr ? PCIX_ECC_CE_ADDR : PCIX_ECC_UE_ADDR);
		break;
	case PCI_PCIX_ECC_PHASE_ATTR:
		(void) snprintf(fab_buf, FM_MAX_CLASS,
		    "%s.%s%s", PCIX_ERROR_SUBCLASS, PCIX_SEC_ERROR_SUBCLASS,
		    ecc_corr ? PCIX_ECC_CE_ATTR : PCIX_ECC_UE_ATTR);
		break;
	case PCI_PCIX_ECC_PHASE_DATA32:
	case PCI_PCIX_ECC_PHASE_DATA64:
		(void) snprintf(fab_buf, FM_MAX_CLASS,
		    "%s.%s%s", PCIX_ERROR_SUBCLASS, PCIX_SEC_ERROR_SUBCLASS,
		    ecc_corr ? PCIX_ECC_CE_DATA : PCIX_ECC_UE_DATA);
		break;
	}
	if (ecc_phase) {
		if (nvlist_alloc(&erpt, NV_UNIQUE_NAME, 0) != 0)
			goto done;
		(void) fab_prep_basic_erpt(hdl, data->nvl, erpt, B_FALSE);
		(void) nvlist_add_string(erpt, FM_CLASS, fab_buf);
		(void) nvlist_add_uint16(erpt, PCIX_SEC_STATUS,
		    data->pcix_bdg_sec_stat);
		(void) nvlist_add_uint32(erpt, PCIX_BDG_STAT,
		    data->pcix_bdg_stat);
		(void) nvlist_add_uint32(erpt, PCIX_ECC_CTLSTAT, ctlstat);
		(void) nvlist_add_uint32(erpt, PCIX_ECC_ATTR,
		    data->pcix_ecc_attr_1);
		fmd_hdl_debug(hdl, "Sending ecc ereport: %s\n", fab_buf);
		fmd_xprt_post(hdl, fab_fmd_xprt, erpt, 0);
		if (fmd_xprt_error(hdl, fab_fmd_xprt))
			fmd_hdl_debug(hdl, "Failed to send ECC ereport\n");
	}

	if (sec_ce || sec_ue) {
		(void) snprintf(fab_buf, FM_MAX_CLASS,
		    "%s.%s%s", PCIX_ERROR_SUBCLASS, PCIX_SEC_ERROR_SUBCLASS,
		    sec_ce ? PCIX_ECC_S_CE : PCIX_ECC_S_UE);
		if (nvlist_alloc(&erpt, NV_UNIQUE_NAME, 0) != 0)
			goto done;
		(void) fab_prep_basic_erpt(hdl, data->nvl, erpt, B_FALSE);
		(void) nvlist_add_string(erpt, FM_CLASS, fab_buf);
		(void) nvlist_add_uint16(erpt, PCIX_SEC_STATUS,
		    data->pcix_bdg_sec_stat);
		(void) nvlist_add_uint32(erpt, PCIX_BDG_STAT,
		    data->pcix_bdg_stat);
		(void) nvlist_add_uint32(erpt, PCIX_ECC_CTLSTAT, ctlstat);
		(void) nvlist_add_uint32(erpt, PCIX_ECC_ATTR,
		    data->pcix_ecc_attr_1);
		fmd_hdl_debug(hdl, "Sending ecc ereport: %s\n", fab_buf);
		fmd_xprt_post(hdl, fab_fmd_xprt, erpt, 0);
		if (fmd_xprt_error(hdl, fab_fmd_xprt))
			fmd_hdl_debug(hdl, "Failed to send ECC ereport\n");
	}
	return;
done:
	fmd_hdl_debug(hdl, "Failed to send ECC ereport\n");
}

static int
fab_prep_pcie_nadv_erpt(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    fab_erpt_tbl_t *tbl)
{
	const char *class = tbl->err_class;
	int err = 0;

	/* Don't send this for PCI device, Root Ports, or PCIe with AER */
	if ((data->dev_type == PCIE_PCIECAP_DEV_TYPE_PCI_DEV) ||
	    (data->dev_type == PCIE_PCIECAP_DEV_TYPE_ROOT) ||
	    data->aer_off)
		return (1);

	err = fab_prep_basic_erpt(hdl, data->nvl, erpt, B_FALSE);

	/* Generate an ereport for this error bit. */
	(void) snprintf(fab_buf, FM_MAX_CLASS, "ereport.io.%s.%s",
	    PCIEX_ERROR_SUBCLASS, class);
	(void) nvlist_add_string(erpt, FM_CLASS, fab_buf);

	(void) nvlist_add_uint16(erpt, PCIEX_DEVSTS_REG, data->pcie_err_status);

	return (err);
}

static int
fab_prep_pcie_rc_erpt(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    fab_erpt_tbl_t *tbl)
{
	const char *class = tbl->err_class;
	uint32_t status = data->pcie_rp_err_status;
	int err = 0;
	int isFE = 0, isNFE = 0;

	fmd_hdl_debug(hdl, "XLATE RP Error Class %s", class);

	if (!data->aer_off)
		return (-1);

	/* Only send a FE Msg if the 1st UE error is FE */
	if (STRCMP(class, PCIEX_RC_FE_MSG))
		if (!(status & PCIE_AER_RE_STS_FIRST_UC_FATAL))
			return (-1);
		else
			isFE = 1;

	/* Only send a NFE Msg is the 1st UE error is NFE */
	if (STRCMP(class, PCIEX_RC_NFE_MSG))
		if (status & PCIE_AER_RE_STS_FIRST_UC_FATAL)
			return (-1);
		else
			isNFE = 1;

	fmd_hdl_debug(hdl, "XLATE RP Error");

	err |= fab_prep_basic_erpt(hdl, data->nvl, erpt, B_FALSE);

	/* Generate an ereport for this error bit. */
	(void) snprintf(fab_buf, FM_MAX_CLASS, "ereport.io.%s.%s",
	    PCIEX_ERROR_SUBCLASS, class);
	(void) nvlist_add_string(erpt, FM_CLASS, fab_buf);

	(void) nvlist_add_uint32(erpt, PCIEX_ROOT_ERRSTS_REG, status);
	if ((isFE || isNFE) && data->pcie_rp_ue_src_id) {
		(void) nvlist_add_uint16(erpt, PCIEX_SRC_ID,
		    data->pcie_rp_ue_src_id);
		(void) nvlist_add_boolean_value(erpt, PCIEX_SRC_VALID, B_TRUE);
	}
	if (STRCMP(class, PCIEX_RC_CE_MSG) && data->pcie_rp_ce_src_id) {
		(void) nvlist_add_uint16(erpt, PCIEX_SRC_ID,
		    data->pcie_rp_ce_src_id);
		(void) nvlist_add_boolean_value(erpt, PCIEX_SRC_VALID, B_TRUE);
	}

	return (err);
}

static int
fab_prep_pcie_fake_rc_erpt(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    fab_erpt_tbl_t *tbl)
{
	const char *class = tbl->err_class;
	uint32_t rc_err_sts = 0;
	int err = 0;

	/*
	 * Don't send this for PCI device or Root Ports.  Only send it on
	 * systems with non-compliant RPs.
	 */
	if ((data->dev_type == PCIE_PCIECAP_DEV_TYPE_PCI_DEV) ||
	    (data->dev_type == PCIE_PCIECAP_DEV_TYPE_ROOT) ||
	    (!fab_xlate_fake_rp))
		return (-1);

	err = fab_prep_basic_erpt(hdl, data->nvl, erpt, B_TRUE);

	/* Generate an ereport for this error bit. */
	(void) snprintf(fab_buf, FM_MAX_CLASS, "ereport.io.%s.%s",
	    PCIEX_ERROR_SUBCLASS, class);
	(void) nvlist_add_string(erpt, FM_CLASS, fab_buf);

	/* Send PCIe RC Ereports */
	if (data->pcie_err_status & PCIE_DEVSTS_CE_DETECTED) {
		rc_err_sts |= PCIE_AER_RE_STS_CE_RCVD;
	}

	/* NFE/FE src id takes precedence over CE src id */
	if (data->pcie_err_status & PCIE_DEVSTS_NFE_DETECTED) {
		rc_err_sts |= PCIE_AER_RE_STS_NFE_MSGS_RCVD;
		rc_err_sts |= PCIE_AER_RE_STS_FE_NFE_RCVD;
	}
	if (data->pcie_err_status & PCIE_DEVSTS_FE_DETECTED) {
		rc_err_sts |= PCIE_AER_RE_STS_FE_MSGS_RCVD;
		rc_err_sts |= PCIE_AER_RE_STS_FE_NFE_RCVD;
	}
	if ((data->pcie_err_status & PCIE_DEVSTS_NFE_DETECTED) &&
	    (data->pcie_err_status & PCIE_DEVSTS_FE_DETECTED)) {
		rc_err_sts |= PCIE_AER_RE_STS_FIRST_UC_FATAL;
		rc_err_sts |= PCIE_AER_RE_STS_MUL_FE_NFE_RCVD;
	}

	(void) nvlist_add_uint32(erpt, PCIEX_ROOT_ERRSTS_REG, rc_err_sts);

	if (!(rc_err_sts & PCIE_AER_RE_STS_MUL_FE_NFE_RCVD)) {
		(void) nvlist_add_uint16(erpt, PCIEX_SRC_ID, data->bdf);
		(void) nvlist_add_boolean_value(erpt, PCIEX_SRC_VALID, B_TRUE);
	}

	return (err);
}

static int
fab_xlate_fire_ce(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    const char *class)
{
	fab_fire_tbl_t	*entry;
	uint64_t	reg;

	for (entry = fab_fire_pec_ce_tbl; entry->err_class; entry++) {
		if (STRCMP(class, entry->err_class))
			goto send;
	}

	return (0);

send:
	fmd_hdl_debug(hdl, "Translate Fire CE %s\n", class);

	/* Fill in the device status register */
	data->pcie_err_status = PCIE_DEVSTS_CE_DETECTED;

	/* Fill in the AER CE register */
	if (nvlist_lookup_uint64(erpt, "tlu-cess", &reg) == 0) {
		data->pcie_ce_status = (uint32_t)reg | (uint32_t)(reg >> 32);
	}

	return (1);
}

static int
fab_xlate_fire_ue(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    const char *class)
{
	fab_fire_tbl_t	*entry;
	uint64_t	reg;
	uint32_t	temp;
	pcie_tlp_hdr_t	*hdr;

	for (entry = fab_fire_pec_ue_tbl; entry->err_class; entry++) {
		if (STRCMP(class, entry->err_class))
			goto send;
	}

	return (0);

send:
	fmd_hdl_debug(hdl, "Translate Fire UE %s\n", class);

	/* Fill in PCI Status Register */
	data->pci_err_status = entry->pci_err_sts;
	data->pci_bdg_sec_stat = entry->pci_bdg_sts;

	/* Fill in the device status register */
	if (entry->fire_bit & data->pcie_ue_sev)
		data->pcie_err_status = PCIE_DEVSTS_FE_DETECTED;
	else
		data->pcie_err_status = PCIE_DEVSTS_NFE_DETECTED;

	if (entry->fire_bit == PCIE_AER_UCE_UR)
		data->pcie_err_status |= PCIE_DEVSTS_UR_DETECTED;

	/* Fill in the AER UE register */
	if (nvlist_lookup_uint64(erpt, "tlu-uess", &reg) == 0) {
		data->pcie_ue_status = (uint32_t)reg | (uint32_t)(reg >> 32);
	}

	/* Fill in the AER Control register */
	if ((reg & (uint64_t)entry->fire_bit) &&
	    nvlist_lookup_boolean(erpt, "primary")) {
		temp = entry->fire_bit;
		for (data->pcie_adv_ctl = (uint32_t)-1; temp;
		    data->pcie_adv_ctl++)
			temp = temp >> 1;
	}

	/* If CTO create target information */
	if (entry->fire_bit == PCIE_AER_UCE_TO &&
	    nvlist_lookup_boolean(erpt, "primary")) {
		if (nvlist_lookup_uint64(erpt, "tlu-tueh1l", &reg) == 0) {
			data->pcie_ue_hdr[0] = (uint32_t)(reg >> 32);
			data->pcie_ue_hdr[1] = (uint32_t)(reg);
		}
		if (nvlist_lookup_uint64(erpt, "tlu-tueh2l", &reg) == 0) {
			data->pcie_ue_hdr[2] = (uint32_t)(reg >> 32);
			data->pcie_ue_hdr[3] = (uint32_t)(reg);
		}

		hdr = (pcie_tlp_hdr_t *)(&data->pcie_ue_hdr[0]);
		switch (hdr->type) {
		case PCIE_TLP_TYPE_IO:
		case PCIE_TLP_TYPE_MEM:
		case PCIE_TLP_TYPE_MEMLK:
			data->pcie_ue_tgt_trans = PF_ADDR_PIO;
			if (hdr->fmt & 0x1) {
				data->pcie_ue_tgt_addr = reg;
			} else {
				data->pcie_ue_tgt_addr = data->pcie_ue_hdr[2];
			}
			break;
		case PCIE_TLP_TYPE_CFG0:
		case PCIE_TLP_TYPE_CFG1:
			data->pcie_ue_tgt_trans = PF_ADDR_CFG;
			data->pcie_ue_tgt_bdf = data->pcie_ue_hdr[2] >> 16;
			break;
		}
	}

	/* Fill in the AER Header registers */
	if (nvlist_lookup_uint64(erpt, "tlu-rueh1l", &reg) == 0) {
		data->pcie_ue_hdr[0] = (uint32_t)(reg >> 32);
		data->pcie_ue_hdr[1] = (uint32_t)(reg);
	}
	if (nvlist_lookup_uint64(erpt, "tlu-rueh2l", &reg) == 0) {
		data->pcie_ue_hdr[2] = (uint32_t)(reg >> 32);
		data->pcie_ue_hdr[3] = (uint32_t)(reg);
	}

	return (1);
}

static int
fab_xlate_fire_oe(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    const char *class)
{
	fab_fire_tbl_t	*entry;
	uint64_t	reg;

	for (entry = fab_fire_pec_oe_tbl; entry->err_class; entry++) {
		if (STRCMP(class, entry->err_class))
			goto send;
	}

	return (0);

send:
	fmd_hdl_debug(hdl, "Translate Fire OE %s\n", class);

	/* Fill in PCI Status Register */
	if (entry->fire_bit) {
		data->pci_err_status = entry->pci_err_sts;
		data->pci_bdg_sec_stat = entry->pci_bdg_sts;
	} else {
		if (nvlist_lookup_uint64(erpt, "tlu-roeeh1l", &reg) == 0) {
			data->pcie_ue_hdr[0] = (uint32_t)(reg >> 32);
			data->pcie_ue_hdr[1] = (uint32_t)(reg);
		}
		if (nvlist_lookup_uint64(erpt, "tlu-roeeh2l", &reg) == 0) {
			data->pcie_ue_hdr[2] = (uint32_t)(reg >> 32);
			data->pcie_ue_hdr[3] = (uint32_t)(reg);
		}

		if (((pcie_tlp_hdr_t *)(&data->pcie_ue_hdr[0]))->type ==
		    PCIE_TLP_TYPE_CPL) {
			pcie_cpl_t *cpl = (pcie_cpl_t *)&data->pcie_ue_hdr[1];
			switch (cpl->status) {
			case PCIE_CPL_STS_UR:
				data->pci_err_status = 0;
				data->pci_bdg_sec_stat = PCI_STAT_R_MAST_AB |
				    PCI_STAT_S_SYSERR;
				break;
			case PCIE_CPL_STS_CA:
				data->pci_err_status = 0;
				data->pci_bdg_sec_stat = PCI_STAT_R_TARG_AB |
				    PCI_STAT_S_SYSERR;
				break;
			}
		}
	}

	/* Fill in the device status register */
	if (entry->fire_bit & data->pcie_ue_sev)
		data->pcie_err_status = PCIE_DEVSTS_FE_DETECTED;
	else
		data->pcie_err_status = PCIE_DEVSTS_NFE_DETECTED;

	/* Fill in the AER UE register */
	data->pcie_ue_status = entry->fire_bit;

	return (1);
}

static int
fab_xlate_fire_dmc(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *erpt,
    const char *class)
{
	fab_fire_tbl_t	*entry;
	uint64_t	reg;
	uint32_t	temp;

	for (entry = fab_fire_dmc_tbl; entry->err_class; entry++) {
		fmd_hdl_debug(hdl, "Matching %s\n", entry->err_class);
		if (STRCMP(class, entry->err_class) &&
		    nvlist_lookup_boolean(erpt, "primary"))
				goto send;
	}

	return (0);

send:
	fmd_hdl_debug(hdl, "Translate Fire DMC %s\n", class);

	/* Fill in PCI Status Register */
	data->pci_err_status = entry->pci_err_sts;
	data->pci_bdg_sec_stat = entry->pci_bdg_sts;

	/* Fill in the device status register */
	data->pcie_err_status = PCIE_DEVSTS_NFE_DETECTED;

	/* Fill in the AER UE register */
	data->pcie_ue_status = entry->fire_bit;

	/* Fill in the AER Control register */
	temp = entry->fire_bit;
	for (data->pcie_adv_ctl = (uint32_t)-1; temp; data->pcie_adv_ctl++)
		temp = temp >> 1;

	/* Fill in the AER Header registers */
	if (nvlist_lookup_uint64(erpt, "mmu-tfsr", &reg) == 0) {
		fmd_hdl_debug(hdl, "tfsr 0x%llx\n", reg);
		/* Get the trans type */
		temp = (reg & 0x3F0000) >> 16;
		data->pcie_ue_hdr[0] = (uint32_t)(temp << 24);
		data->pcie_ue_tgt_trans = PF_ADDR_DMA;
		/* Get the req id */
		temp = (reg & 0xFFFF);
		data->pcie_ue_hdr[1] = (uint32_t)(temp << 16);
		data->pcie_ue_tgt_bdf = temp;
	}

	if (nvlist_lookup_uint64(erpt, "mmu-tfar", &reg) == 0) {
		fmd_hdl_debug(hdl, "tfar 0x%llx\n", reg);
		/* Get the address */
		data->pcie_ue_hdr[2] = reg;
		data->pcie_ue_hdr[3] = 0;
		data->pcie_ue_tgt_addr = reg;
	}

	fmd_hdl_debug(hdl, "HEADER 0 0x%x\n", data->pcie_ue_hdr[0]);
	fmd_hdl_debug(hdl, "HEADER 1 0x%x\n", data->pcie_ue_hdr[1]);
	fmd_hdl_debug(hdl, "HEADER 2 0x%x\n", data->pcie_ue_hdr[2]);
	fmd_hdl_debug(hdl, "HEADER 3 0x%x\n", data->pcie_ue_hdr[3]);

	return (1);
}

static void
fab_xlate_pcie_erpts(fmd_hdl_t *hdl, fab_data_t *data)
{
	fab_err_tbl_t *tbl;

	fmd_hdl_debug(hdl, "Sending Ereports Now");

	/* Go through the error logs and send the relavant reports */
	for (tbl = fab_master_err_tbl; tbl->erpt_tbl; tbl++) {
		fab_send_erpt(hdl, data, tbl);
	}

	/* Send PCI-X ECC Ereports */
	fab_send_pcix_ecc_erpt(hdl, data);
	fab_send_pcix_bdg_ecc_erpt(hdl, data);
}

static void
fab_xlate_fire_erpts(fmd_hdl_t *hdl, fab_data_t *data, nvlist_t *nvl,
    const char *class)
{
	if (fmd_nvl_class_match(hdl, nvl, "ereport.io.fire.pec.*")) {
		if (fab_xlate_fire_ce(hdl, data, nvl, class))
			return;

		if (fab_xlate_fire_ue(hdl, data, nvl, class))
			return;

		if (fab_xlate_fire_oe(hdl, data, nvl, class))
			return;
	} else if (fmd_nvl_class_match(hdl, nvl, "ereport.io.fire.dmc.*") ||
	    fmd_nvl_class_match(hdl, nvl, "ereport.io.n2.dmu.*")) {
		if (fab_xlate_fire_dmc(hdl, data, nvl, class))
			return;
	}
}

static void
fab_update_topo(fmd_hdl_t *hdl)
{
	topo_hdl_t	*thp = NULL;
	FILE		*fp;
	int		err = 0;

	if ((thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION)) == NULL) {
		fmd_hdl_debug(hdl, "Failed to hold topo\n");
	}

	fp = fopen(XMLTOPOFILE, "w");

	if (topo_xml_print(thp, fp, FM_FMRI_SCHEME_HC, &err) < 0) {
		fmd_hdl_debug(hdl, "Failed to get XML topo\n");
	}

	(void) fclose(fp);

	fmd_hdl_topo_rele(hdl, thp);

	if (fab_xpathCtx)
		xmlXPathFreeContext(fab_xpathCtx);
	if (fab_doc)
		xmlFreeDoc(fab_doc);

	/* Load xml document */
	fab_doc = xmlParseFile(XMLTOPOFILE);

	/* Init xpath */
	fab_xpathCtx = xmlXPathNewContext(fab_doc);

	fab_valid_topo = 1;
}

#define	FAB_HC2DEV_QUERY_SIZE_MIN 160
#define	FAB_HC2DEV_QUERY_SIZE(sz) \
	((sz + FAB_HC2DEV_QUERY_SIZE_MIN) * sizeof (char))

static boolean_t
fab_hc2dev(fmd_hdl_t *hdl, nvlist_t *detector, char **dev_path,
    uint_t *dev_path_size) {
	xmlXPathObjectPtr xpathObj;
	xmlNodeSetPtr	nodes;
	char 		*query, *query_end, *temp;
	uint_t 		i, size;
	size_t		query_size = 0;
	nvlist_t	**hcl;

	if (nvlist_lookup_nvlist_array(detector, FM_FMRI_HC_LIST, &hcl,
		&size) != 0)
		goto fail;

	for (i = 0; i < size; i++) {
		if (nvlist_lookup_string(hcl[i], FM_FMRI_HC_NAME, &temp) != 0)
			goto fail;
		query_size += strlen(temp);
		if (nvlist_lookup_string(hcl[i], FM_FMRI_HC_ID, &temp) != 0)
			goto fail;
		query_size += strlen(temp);
		/* Adjust for '=' and '/' later */
		query_size += 2;
	}

	query = fmd_hdl_alloc(hdl, FAB_HC2DEV_QUERY_SIZE(query_size),
	    FMD_SLEEP);
	(void) sprintf(query, "//propval[@name='resource' and "
	    "contains(substring(@value, string-length(@value) - %d), '",
	    query_size);

	query_end = query;
	query_end += strlen(query);

	for (i = 0; i < size; i++) {
		(void) nvlist_lookup_string(hcl[i], FM_FMRI_HC_NAME, &temp);
		(void) snprintf(query_end, query_size, "%s=", temp);
		query_end += strlen(temp) + 1;
		(void) nvlist_lookup_string(hcl[i], FM_FMRI_HC_ID, &temp);
		(void) snprintf(query_end, query_size, "%s", temp);
		query_end += strlen(temp);
		if (i != (size - 1)) {
			(void) sprintf(query_end++, "/");
		}
	}

	(void) sprintf(query_end, "')]/parent::*/following-sibling::*/"
	    "propval[@name='dev']/@value");

	fmd_hdl_debug(hdl, "xpathObj query %s\n", query);

	xpathObj = xmlXPathEvalExpression((const xmlChar *)query,
	    fab_xpathCtx);
	fmd_hdl_free(hdl, query, FAB_HC2DEV_QUERY_SIZE(query_size));

	fmd_hdl_debug(hdl, "xpathObj 0x%p type %d\n", xpathObj,
	    xpathObj->type);
	nodes = xpathObj->nodesetval;

	if (nodes) {
		temp = (char *)xmlNodeGetContent(nodes->nodeTab[0]);
		fmd_hdl_debug(hdl, "HC Dev Path: %s\n", temp);
		*dev_path_size = strlen(temp) + 1;
		*dev_path = fmd_hdl_alloc(hdl, *dev_path_size, FMD_SLEEP);
		(void) strcpy(*dev_path,
		    (char *)xmlNodeGetContent(nodes->nodeTab[0]));
		return (B_TRUE);
	}
fail:
	return (B_FALSE);
}

/* ARGSUSED */
static boolean_t
fab_get_rcpath(fmd_hdl_t *hdl, nvlist_t *nvl, char *rcpath) {
	nvlist_t	*detector;
	char		*path, *scheme;
	uint_t		size;

	if (nvlist_lookup_nvlist(nvl, FM_EREPORT_DETECTOR, &detector) != 0)
		goto fail;
	if (nvlist_lookup_string(detector, FM_FMRI_SCHEME, &scheme) != 0)
		goto fail;

	if (STRCMP(scheme, FM_FMRI_SCHEME_DEV)) {
		if (nvlist_lookup_string(detector, FM_FMRI_DEV_PATH,
			&path) != 0)
			goto fail;
		(void) strncpy(rcpath, path, FM_MAX_CLASS);
	} else if (STRCMP(scheme, FM_FMRI_SCHEME_HC)) {
		/*
		 * This should only occur for ereports that come from the RC
		 * itself.  In this case convert HC scheme to dev path.
		 */
		if (fab_hc2dev(hdl, detector, &path, &size)) {
			(void) strncpy(rcpath, path, FM_MAX_CLASS);
			fmd_hdl_free(hdl, path, size);
		} else {
			goto fail;
		}
	} else {
		return (B_FALSE);
	}

	/*
	 * Extract the RC path by taking the first device in the dev path
	 *
	 * /pci@0,0/pci8086,3605@2/pci8086,3500@0/pci8086,3514@1/pci8086,105e@0
	 * - to -
	 * /pci@0,0
	 */
	path = strchr(rcpath + 1, '/');
	if (path)
		path[0] = '\0';

	return (B_TRUE);
fail:
	return (B_FALSE);
}

static char *
fab_find_bdf(fmd_hdl_t *hdl, nvlist_t *nvl, pcie_req_id_t bdf) {
	xmlXPathObjectPtr xpathObj;
	xmlNodeSetPtr	nodes;
	char		query[500];
	int		bus, dev, fn;
	char		rcpath[255];

	if (bdf != (uint16_t)-1) {
		bus = (bdf & PCIE_REQ_ID_BUS_MASK) >> PCIE_REQ_ID_BUS_SHIFT;
		dev = (bdf & PCIE_REQ_ID_DEV_MASK) >> PCIE_REQ_ID_DEV_SHIFT;
		fn = (bdf & PCIE_REQ_ID_FUNC_MASK) >> PCIE_REQ_ID_FUNC_SHIFT;
	}

	if (!fab_get_rcpath(hdl, nvl, rcpath))
		goto fail;

	/*
	 * Explanation of the XSL XPATH Query
	 * Line 1: Look at all nodes with the node name "propval"
	 * Line 2-3: See if the "value" of the node ends with correct PCIEx BDF
	 * Line 4-5: See if the "value" of the node ends with correct PCI BDF
	 * Line 6: Go up one level to the parent of the current node
	 * Line 7: See if child node contains "ASRU" with the same PCIe Root
	 * Line 8: Traverse up the parent and the other siblings and look for
	 *	   the io "propgroup" and get the value of the dev "propval"
	 */
	(void) snprintf(query, sizeof (query), "//propval["
	    "contains(substring(@value, string-length(@value) - 34), "
	    "'pciexbus=%d/pciexdev=%d/pciexfn=%d') or "
	    "contains(substring(@value, string-length(@value) - 28), "
	    "'pcibus=%d/pcidev=%d/pcifn=%d')"
	    "]/parent::"
	    "*/propval[@name='ASRU' and contains(@value, '%s')]"
	    "/parent::*/following-sibling::*[@name='io']/propval[@name='dev']/"
	    "@value", bus, dev, fn, bus, dev, fn, rcpath);

	fmd_hdl_debug(hdl, "xpathObj query %s\n", query);

	xpathObj = xmlXPathEvalExpression((const xmlChar *)query, fab_xpathCtx);

	fmd_hdl_debug(hdl, "xpathObj 0x%p type %d\n", xpathObj, xpathObj->type);

	nodes = xpathObj->nodesetval;
	if (nodes) {
		fmd_hdl_debug(hdl, "BDF Dev Path: %s\n",
		    xmlNodeGetContent(nodes->nodeTab[0]));
		return ((char *)xmlNodeGetContent(nodes->nodeTab[0]));
	}
fail:
	return (NULL);
}

static char *
fab_find_addr(fmd_hdl_t *hdl, nvlist_t *nvl, uint64_t addr) {
	xmlXPathObjectPtr xpathObj;
	xmlNodeSetPtr nodes;
	xmlNodePtr devNode;
	char query[500];
	int size, i, j;
	uint32_t prop[50];
	char *token;
	pci_regspec_t *assign_p;
	uint64_t low, hi;
	char rcpath[255];

	if (!fab_get_rcpath(hdl, nvl, rcpath))
		goto fail;

	(void) snprintf(query, sizeof (query), "//propval["
	    "@name='ASRU' and contains(@value, '%s')]/"
	    "parent::*/following-sibling::*[@name='pci']/"
	    "propval[@name='assigned-addresses']", rcpath);

	fmd_hdl_debug(hdl, "xpathObj query %s\n", query);

	xpathObj = xmlXPathEvalExpression((const xmlChar *)query, fab_xpathCtx);

	fmd_hdl_debug(hdl, "xpathObj 0x%p type %d\n", xpathObj, xpathObj->type);

	nodes = xpathObj->nodesetval;
	size = (nodes) ? nodes->nodeNr : 0;

	/* Decode the list of assigned addresses xml nodes for each device */
	for (i = 0; i < size; i++) {
		devNode = nodes->nodeTab[i];
		if (!HAS_PROP(devNode, "value"))
			continue;

		/* Convert "string" assigned-addresses to pci_regspec_t */
		j = 0;
		for (token = strtok(GET_PROP(devNode, "value"), " "); token;
		    token = strtok(NULL, " ")) {
			prop[j++] = strtoul(token, (char **)NULL, 16);
		}
		prop[j] = (uint32_t)-1;

		/* Check if address belongs to this device */
		for (assign_p = (pci_regspec_t *)prop;
		    assign_p->pci_phys_hi != (uint_t)-1; assign_p++) {
			low = assign_p->pci_phys_low;
			hi = low + assign_p->pci_size_low;
			if ((addr < hi) && (addr >= low)) {
				fmd_hdl_debug(hdl, "Found Address\n");
				goto found;
			}
		}
	}
	goto fail;

found:
	/* Traverse up the xml tree and back down to find the right propgroup */
	for (devNode = devNode->parent->parent->children;
	    devNode; devNode = devNode->next) {
		if (STRCMP(devNode->name, "propgroup") &&
		    STRCMP(GET_PROP(devNode, "name"), "io"))
			goto propgroup;
	}
	goto fail;

propgroup:
	/* Retrive the "dev" propval and return */
	for (devNode = devNode->children; devNode; devNode = devNode->next) {
		if (STRCMP(devNode->name, "propval") &&
		    STRCMP(GET_PROP(devNode, "name"), "dev")) {
			fmd_hdl_debug(hdl, "Addr Dev Path: %s\n",
			    GET_PROP(devNode, "value"));
			return (GET_PROP(devNode, "value"));
		}
	}
fail:
	return (NULL);
}

static void
fab_pr(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl) {
	nvpair_t *nvp;

	for (nvp = nvlist_next_nvpair(nvl, NULL);
	    nvp != NULL;
	    nvp = nvlist_next_nvpair(nvl, nvp)) {

		data_type_t type = nvpair_type(nvp);
		const char *name = nvpair_name(nvp);

		boolean_t b;
		uint8_t i8;
		uint16_t i16;
		uint32_t i32;
		uint64_t i64;
		char *str;
		nvlist_t *cnv;

		nvlist_t **nvlarr;
		uint_t arrsize;
		int arri;


		if (STRCMP(name, FM_CLASS))
			continue; /* already printed by caller */

		fmd_hdl_debug(hdl, " %s=", name);

		switch (type) {
		case DATA_TYPE_BOOLEAN:
			fmd_hdl_debug(hdl, "DATA_TYPE_BOOLEAN 1");
			break;

		case DATA_TYPE_BOOLEAN_VALUE:
			(void) nvpair_value_boolean_value(nvp, &b);
			fmd_hdl_debug(hdl, "DATA_TYPE_BOOLEAN_VALUE %d",
			    b ? "1" : "0");
			break;

		case DATA_TYPE_BYTE:
			(void) nvpair_value_byte(nvp, &i8);
			fmd_hdl_debug(hdl, "DATA_TYPE_BYTE 0x%x", i8);
			break;

		case DATA_TYPE_INT8:
			(void) nvpair_value_int8(nvp, (void *)&i8);
			fmd_hdl_debug(hdl, "DATA_TYPE_INT8 0x%x", i8);
			break;

		case DATA_TYPE_UINT8:
			(void) nvpair_value_uint8(nvp, &i8);
			fmd_hdl_debug(hdl, "DATA_TYPE_UINT8 0x%x", i8);
			break;

		case DATA_TYPE_INT16:
			(void) nvpair_value_int16(nvp, (void *)&i16);
			fmd_hdl_debug(hdl, "DATA_TYPE_INT16 0x%x", i16);
			break;

		case DATA_TYPE_UINT16:
			(void) nvpair_value_uint16(nvp, &i16);
			fmd_hdl_debug(hdl, "DATA_TYPE_UINT16 0x%x", i16);
			break;

		case DATA_TYPE_INT32:
			(void) nvpair_value_int32(nvp, (void *)&i32);
			fmd_hdl_debug(hdl, "DATA_TYPE_INT32 0x%x", i32);
			break;

		case DATA_TYPE_UINT32:
			(void) nvpair_value_uint32(nvp, &i32);
			fmd_hdl_debug(hdl, "DATA_TYPE_UINT32 0x%x", i32);
			break;

		case DATA_TYPE_INT64:
			(void) nvpair_value_int64(nvp, (void *)&i64);
			fmd_hdl_debug(hdl, "DATA_TYPE_INT64 0x%llx",
			    (u_longlong_t)i64);
			break;

		case DATA_TYPE_UINT64:
			(void) nvpair_value_uint64(nvp, &i64);
			fmd_hdl_debug(hdl, "DATA_TYPE_UINT64 0x%llx",
			    (u_longlong_t)i64);
			break;

		case DATA_TYPE_HRTIME:
			(void) nvpair_value_hrtime(nvp, (void *)&i64);
			fmd_hdl_debug(hdl, "DATA_TYPE_HRTIME 0x%llx",
			    (u_longlong_t)i64);
			break;

		case DATA_TYPE_STRING:
			(void) nvpair_value_string(nvp, &str);
			fmd_hdl_debug(hdl, "DATA_TYPE_STRING \"%s\"",
			    str ? str : "<NULL>");
			break;

		case DATA_TYPE_NVLIST:
			fmd_hdl_debug(hdl, "[");
			(void) nvpair_value_nvlist(nvp, &cnv);
			fab_pr(hdl, NULL, cnv);
			fmd_hdl_debug(hdl, " ]");
			break;

		case DATA_TYPE_BOOLEAN_ARRAY:
		case DATA_TYPE_BYTE_ARRAY:
		case DATA_TYPE_INT8_ARRAY:
		case DATA_TYPE_UINT8_ARRAY:
		case DATA_TYPE_INT16_ARRAY:
		case DATA_TYPE_UINT16_ARRAY:
		case DATA_TYPE_INT32_ARRAY:
		case DATA_TYPE_UINT32_ARRAY:
		case DATA_TYPE_INT64_ARRAY:
		case DATA_TYPE_UINT64_ARRAY:
		case DATA_TYPE_STRING_ARRAY:
			fmd_hdl_debug(hdl, "[...]");
			break;
		case DATA_TYPE_NVLIST_ARRAY:
			arrsize = 0;
			(void) nvpair_value_nvlist_array(nvp, &nvlarr,
			    &arrsize);

			for (arri = 0; arri < arrsize; arri++) {
				fab_pr(hdl, ep, nvlarr[arri]);
			}

			break;
		case DATA_TYPE_UNKNOWN:
			fmd_hdl_debug(hdl, "<unknown>");
			break;
		}
	}
}

/*ARGSUSED*/
static void
fab_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	fab_data_t fab_data = {0};

	if (!fab_valid_topo)
		fab_update_topo(hdl);

	if (fmd_nvl_class_match(hdl, nvl, "ereport.io.pci.fabric")) {
		fmd_hdl_debug(hdl, "PCI ereport received: %s\n", class);
		fab_pci_fabric_to_data(hdl, nvl, &fab_data);
		fab_xlate_pcie_erpts(hdl, &fab_data);
	} else {
		fab_pr(hdl, ep, nvl);
		fmd_hdl_debug(hdl, "Fire RC ereport received: %s\n", class);
		fab_fire_to_data(hdl, nvl, &fab_data);
		fab_xlate_fire_erpts(hdl, &fab_data, nvl, class);
		fab_xlate_pcie_erpts(hdl, &fab_data);
	}
}

/* ARGSUSED */
static void
fab_topo(fmd_hdl_t *hdl, topo_hdl_t *topo)
{
	fab_valid_topo = 0;
}

static const fmd_hdl_ops_t fmd_ops = {
	fab_recv,	/* fmdo_recv */
	NULL,		/* fmdo_timeout */
	NULL,		/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL,		/* fmdo_gc */
	NULL,		/* fmdo_send */
	fab_topo,	/* fmdo_topo */
};

static const fmd_hdl_info_t fmd_info = {
	"Fabric Ereport Translater", "1.0", &fmd_ops, NULL
};

#define	REG_OFF(reg) ((uint32_t)(uint32_t)&fab_data.reg - (uint32_t)&fab_data)
#define	SET_TBL(n, err, reg, sz) \
	fab_master_err_tbl[n].erpt_tbl = fab_ ## err ## _erpt_tbl; \
	fab_master_err_tbl[n].reg_offset = REG_OFF(reg); \
	fab_master_err_tbl[n].reg_size = sz; \
	fab_master_err_tbl[n].fab_prep = fab_prep_ ## err ## _erpt;

void
_fmd_init(fmd_hdl_t *hdl)
{
	fab_data_t fab_data;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return;

	/* Init libxml */
	xmlInitParser();

	fab_fmd_xprt = fmd_xprt_open(hdl, FMD_XPRT_RDONLY, NULL, NULL);
	fmd_hdl_debug(hdl, "Fabric Translater Started\n");

	/* Setup the master error table */
	fab_master_err_tbl = (fab_err_tbl_t *)calloc(13,
	    sizeof (fab_err_tbl_t));

	SET_TBL(0, pci,			pci_err_status,	    16);
	SET_TBL(1, pci_bdg,		pci_bdg_sec_stat,   16);
	SET_TBL(2, pci_bdg_ctl,		pci_bdg_ctrl,	    16);
	SET_TBL(3, pcie_ce,		pcie_ce_status,	    32);
	SET_TBL(4, pcie_ue,		pcie_ue_status,	    32);
	SET_TBL(5, pcie_sue,		pcie_sue_status,    32);
	SET_TBL(6, pcix,		pcix_status,	    32);
	SET_TBL(7, pcix_bdg_sec,	pcix_bdg_sec_stat,  16);
	SET_TBL(8, pcix_bdg,		pcix_bdg_stat,	    32);
	SET_TBL(9, pcie_nadv,		pcie_err_status,    16);
	SET_TBL(10, pcie_rc,		pcie_rp_err_status, 32);
	SET_TBL(11, pcie_fake_rc,	pcie_err_status,    16);
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	/* Fini xpath */
	if (fab_xpathCtx)
		xmlXPathFreeContext(fab_xpathCtx);
	/* Free xml document */
	if (fab_doc)
		xmlFreeDoc(fab_doc);
	/* Fini libxml */
	xmlCleanupParser();

	fmd_xprt_close(hdl, fab_fmd_xprt);
}
