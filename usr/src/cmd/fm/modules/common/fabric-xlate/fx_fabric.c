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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#include <stddef.h>
#include <strings.h>
#include <sys/fm/util.h>

#include "fabric-xlate.h"

#define	FAB_LOOKUP(sz, name, field) \
	(void) nvlist_lookup_uint ## sz(nvl, name, field)

static boolean_t fab_xlate_fake_rp = B_TRUE;
static fab_err_tbl_t *fab_master_err_tbl;

/*
 * Translation tables for converting "fabric" error bits into "pci" ereports.
 * <Ereport Class Name>, <Error Bit Mask>, <Preparation Function>
 */

/* MACRO for table entries with no TGT ereports */
#define	NT(class, bit, prep) class, bit, prep, NULL
/* Translate Fabric ereports to ereport.io.pci.* */
fab_erpt_tbl_t fab_pci_erpt_tbl[] = {
	PCI_DET_PERR,		PCI_STAT_PERROR,	NULL,
	PCI_MDPE,		PCI_STAT_S_PERROR,	NULL,
	PCI_SIG_SERR,		PCI_STAT_S_SYSERR,	NULL,
	PCI_MA,			PCI_STAT_R_MAST_AB,	NULL,
	PCI_REC_TA,		PCI_STAT_R_TARG_AB,	NULL,
	PCI_SIG_TA,		PCI_STAT_S_TARG_AB,	NULL,
	NULL, 0, NULL
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
	NULL, 0, NULL,
};


/* Translate Fabric ereports to ereport.io.pci.dto */
static fab_erpt_tbl_t fab_pci_bdg_ctl_erpt_tbl[] = {
	PCI_DTO,	PCI_BCNF_BCNTRL_DTO_STAT,	NULL,
	NULL, 0, NULL
};

/* Translate Fabric ereports to ereport.io.pciex.* */
static fab_erpt_tbl_t fab_pcie_ce_erpt_tbl[] = {
	PCIEX_RE,	PCIE_AER_CE_RECEIVER_ERR,	NULL,
	PCIEX_RNR,	PCIE_AER_CE_REPLAY_ROLLOVER,	NULL,
	PCIEX_RTO,	PCIE_AER_CE_REPLAY_TO,		NULL,
	PCIEX_BDP,	PCIE_AER_CE_BAD_DLLP,		NULL,
	PCIEX_BTP,	PCIE_AER_CE_BAD_TLP,		NULL,
	PCIEX_ANFE,	PCIE_AER_CE_AD_NFE,		NULL,
	NULL, 0, NULL
};

/*
 * Translate Fabric ereports to ereport.io.pciex.*
 * The Target Ereports for this section is only used on leaf devices, with the
 * exception of TO
 */
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
	NULL, 0, NULL
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
	NULL, 0, NULL
};

/* Translate Fabric ereports to ereport.io.pcix.* */
static fab_erpt_tbl_t fab_pcix_erpt_tbl[] = {
	PCIX_SPL_DIS,		PCI_PCIX_SPL_DSCD,	NULL,
	PCIX_UNEX_SPL,		PCI_PCIX_UNEX_SPL,	NULL,
	PCIX_RX_SPL_MSG,	PCI_PCIX_RX_SPL_MSG,	NULL,
	NULL, 0, NULL
};
static fab_erpt_tbl_t *fab_pcix_bdg_erpt_tbl = fab_pcix_erpt_tbl;

/* Translate Fabric ereports to ereport.io.pcix.sec-* */
static fab_erpt_tbl_t fab_pcix_bdg_sec_erpt_tbl[] = {
	PCIX_SPL_DIS,		PCI_PCIX_BSS_SPL_DSCD,	NULL,
	PCIX_UNEX_SPL,		PCI_PCIX_BSS_UNEX_SPL,	NULL,
	PCIX_BSS_SPL_OR,	PCI_PCIX_BSS_SPL_OR,	NULL,
	PCIX_BSS_SPL_DLY,	PCI_PCIX_BSS_SPL_DLY,	NULL,
	NULL, 0, NULL
};

/* Translate Fabric ereports to ereport.io.pciex.* */
static fab_erpt_tbl_t fab_pcie_nadv_erpt_tbl[] = {
#ifdef sparc
	PCIEX_UR,		PCIE_DEVSTS_UR_DETECTED,	NULL,
#endif
	PCIEX_FAT,		PCIE_DEVSTS_FE_DETECTED,	NULL,
	PCIEX_NONFAT,		PCIE_DEVSTS_NFE_DETECTED,	NULL,
	PCIEX_CORR,		PCIE_DEVSTS_CE_DETECTED,	NULL,
	NULL, 0, NULL
};

/* Translate Fabric ereports to ereport.io.pciex.* */
static fab_erpt_tbl_t fab_pcie_rc_erpt_tbl[] = {
	PCIEX_RC_FE_MSG,	PCIE_AER_RE_STS_FE_MSGS_RCVD,	NULL,
	PCIEX_RC_NFE_MSG,	PCIE_AER_RE_STS_NFE_MSGS_RCVD,	NULL,
	PCIEX_RC_CE_MSG,	PCIE_AER_RE_STS_CE_RCVD,	NULL,
	PCIEX_RC_MCE_MSG,	PCIE_AER_RE_STS_MUL_CE_RCVD,	NULL,
	PCIEX_RC_MUE_MSG,	PCIE_AER_RE_STS_MUL_FE_NFE_RCVD, NULL,
	NULL, 0, NULL
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
	NULL, 0, NULL,
};

/* ARGSUSED */
void
fab_pci_fabric_to_data(fmd_hdl_t *hdl, nvlist_t *nvl, fab_data_t *data)
{
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

	if ((tbl->reg_bit == first_err) && !data->pcie_ue_no_tgt_erpt &&
	    data->pcie_ue_tgt_trans) {
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

	if ((tbl->reg_bit == first_err) && !data->pcie_ue_no_tgt_erpt &&
	    data->pcie_sue_tgt_trans) {
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

void
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

void
fab_xlate_fabric_erpts(fmd_hdl_t *hdl, nvlist_t *nvl, const char *class)
{
	fab_data_t data = {0};

	fmd_hdl_debug(hdl, "fabric ereport received: %s\n", class);

	fab_pci_fabric_to_data(hdl, nvl, &data);
	fab_xlate_pcie_erpts(hdl, &data);
}

void
fab_set_fake_rp(fmd_hdl_t *hdl)
{
	char *rppath = fab_get_rpdev(hdl), *str = NULL;
	int count = 0;

	if (!rppath) {
		fmd_hdl_debug(hdl, "Can't find root port dev path");
		return;
	}

	/*
	 * For the path '/pci@xxx' is fake root port,
	 * and  '/pci@xxx/pci@y' is real root port.
	 */
	str = rppath;
	while (*str) {
		if (*str == '/')
			count++;
		str++;
	}

	if (count == 1)
		fab_xlate_fake_rp = B_TRUE;
	else
		/*
		 * If count is 0, then it should still be B_FALSE
		 */
		fab_xlate_fake_rp = B_FALSE;

	fmd_hdl_strfree(hdl, rppath);
}

#define	SET_TBL(n, err, reg, sz) \
	fab_master_err_tbl[n].erpt_tbl = fab_ ## err ## _erpt_tbl; \
	fab_master_err_tbl[n].reg_offset = offsetof(fab_data_t, reg); \
	fab_master_err_tbl[n].reg_size = sz; \
	fab_master_err_tbl[n].fab_prep = fab_prep_ ## err ## _erpt;

void
fab_setup_master_table()
{
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
