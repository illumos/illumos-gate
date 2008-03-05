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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sunndi.h>
#include <sys/sysmacros.h>
#include <sys/ddifm_impl.h>
#include <sys/fm/util.h>
#include <sys/fm/protocol.h>
#include <sys/fm/io/pci.h>
#include <sys/fm/io/ddi.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <sys/pci_impl.h>
#include <sys/epm.h>
#include <sys/pcifm.h>

#define	PCIX_ECC_VER_CHECK(x)	(((x) == PCI_PCIX_VER_1) ||\
				((x) == PCI_PCIX_VER_2))

/*
 * Expected PCI Express error mask values
 */
uint32_t pcie_expected_ce_mask = 0x0;
uint32_t pcie_expected_ue_mask = PCIE_AER_UCE_UC;
#if defined(__sparc)
uint32_t pcie_expected_sue_mask = 0x0;
#else
uint32_t pcie_expected_sue_mask = PCIE_AER_SUCE_RCVD_MA;
#endif
uint32_t pcie_aer_uce_log_bits = PCIE_AER_UCE_LOG_BITS;
#if defined(__sparc)
uint32_t pcie_aer_suce_log_bits = PCIE_AER_SUCE_LOG_BITS;
#else
uint32_t pcie_aer_suce_log_bits = \
	    PCIE_AER_SUCE_LOG_BITS & ~PCIE_AER_SUCE_RCVD_MA;
#endif

errorq_t *pci_target_queue = NULL;

pci_fm_err_t pci_err_tbl[] = {
	PCI_DET_PERR,	PCI_STAT_PERROR,	NULL,		DDI_FM_UNKNOWN,
	PCI_MDPE,	PCI_STAT_S_PERROR,	PCI_TARG_MDPE,	DDI_FM_UNKNOWN,
	PCI_SIG_SERR,	PCI_STAT_S_SYSERR,	NULL,		DDI_FM_FATAL,
	PCI_MA,		PCI_STAT_R_MAST_AB,	PCI_TARG_MA,	DDI_FM_UNKNOWN,
	PCI_REC_TA,	PCI_STAT_R_TARG_AB,	PCI_TARG_REC_TA, DDI_FM_UNKNOWN,
	PCI_SIG_TA,	PCI_STAT_S_TARG_AB,	NULL,		DDI_FM_UNKNOWN,
	NULL, NULL, NULL, NULL,
};

pci_fm_err_t pci_bdg_err_tbl[] = {
	PCI_DET_PERR,	PCI_STAT_PERROR,	NULL,		DDI_FM_UNKNOWN,
	PCI_MDPE,	PCI_STAT_S_PERROR,	PCI_TARG_MDPE,	DDI_FM_UNKNOWN,
	PCI_REC_SERR,	PCI_STAT_S_SYSERR,	NULL,		DDI_FM_UNKNOWN,
#if defined(__sparc)
	PCI_MA,		PCI_STAT_R_MAST_AB,	PCI_TARG_MA,	DDI_FM_UNKNOWN,
#endif
	PCI_REC_TA,	PCI_STAT_R_TARG_AB,	PCI_TARG_REC_TA, DDI_FM_UNKNOWN,
	PCI_SIG_TA,	PCI_STAT_S_TARG_AB,	NULL,		DDI_FM_UNKNOWN,
	NULL, NULL, NULL, NULL,
};

static pci_fm_err_t pciex_ce_err_tbl[] = {
	PCIEX_RE,	PCIE_AER_CE_RECEIVER_ERR,	NULL,	DDI_FM_OK,
	PCIEX_RNR,	PCIE_AER_CE_REPLAY_ROLLOVER,	NULL,	DDI_FM_OK,
	PCIEX_RTO,	PCIE_AER_CE_REPLAY_TO,		NULL,	DDI_FM_OK,
	PCIEX_BDP,	PCIE_AER_CE_BAD_DLLP,		NULL,	DDI_FM_OK,
	PCIEX_BTP,	PCIE_AER_CE_BAD_TLP,		NULL,	DDI_FM_OK,
	PCIEX_ANFE,	PCIE_AER_CE_AD_NFE,		NULL,	DDI_FM_OK,
	NULL, NULL, NULL, NULL,
};

static pci_fm_err_t pciex_ue_err_tbl[] = {
	PCIEX_TE,	PCIE_AER_UCE_TRAINING,		NULL,	DDI_FM_FATAL,
	PCIEX_DLP,	PCIE_AER_UCE_DLP,		NULL,	DDI_FM_FATAL,
	PCIEX_SD,	PCIE_AER_UCE_SD,		NULL,   DDI_FM_FATAL,
	PCIEX_ROF,	PCIE_AER_UCE_RO,		NULL,	DDI_FM_FATAL,
	PCIEX_FCP,	PCIE_AER_UCE_FCP,		NULL,	DDI_FM_FATAL,
	PCIEX_MFP,	PCIE_AER_UCE_MTLP,		NULL,	DDI_FM_FATAL,
	PCIEX_CTO,	PCIE_AER_UCE_TO,		NULL,	DDI_FM_UNKNOWN,
	PCIEX_UC,	PCIE_AER_UCE_UC,		NULL,	DDI_FM_OK,
	PCIEX_ECRC,	PCIE_AER_UCE_ECRC,		NULL,	DDI_FM_UNKNOWN,
	PCIEX_CA,	PCIE_AER_UCE_CA,		NULL,	DDI_FM_UNKNOWN,
	PCIEX_UR,	PCIE_AER_UCE_UR,		NULL,	DDI_FM_UNKNOWN,
	PCIEX_POIS,	PCIE_AER_UCE_PTLP,		NULL,	DDI_FM_UNKNOWN,
	NULL, NULL, NULL, NULL,
};

static pci_fm_err_t pcie_sue_err_tbl[] = {
	PCIEX_S_TA_SC,	PCIE_AER_SUCE_TA_ON_SC,		NULL,	DDI_FM_UNKNOWN,
	PCIEX_S_MA_SC,	PCIE_AER_SUCE_MA_ON_SC,		NULL,	DDI_FM_UNKNOWN,
	PCIEX_S_RTA,	PCIE_AER_SUCE_RCVD_TA,		NULL,	DDI_FM_UNKNOWN,
#if defined(__sparc)
	PCIEX_S_RMA,	PCIE_AER_SUCE_RCVD_MA,		NULL,	DDI_FM_UNKNOWN,
#endif
	PCIEX_S_USC,	PCIE_AER_SUCE_USC_ERR,		NULL,	DDI_FM_UNKNOWN,
	PCIEX_S_USCMD,	PCIE_AER_SUCE_USC_MSG_DATA_ERR,	NULL,	DDI_FM_FATAL,
	PCIEX_S_UDE,	PCIE_AER_SUCE_UC_DATA_ERR,	NULL,	DDI_FM_UNKNOWN,
	PCIEX_S_UAT,	PCIE_AER_SUCE_UC_ATTR_ERR,	NULL,	DDI_FM_FATAL,
	PCIEX_S_UADR,	PCIE_AER_SUCE_UC_ADDR_ERR,	NULL,	DDI_FM_FATAL,
	PCIEX_S_TEX,	PCIE_AER_SUCE_TIMER_EXPIRED,	NULL,	DDI_FM_FATAL,
	PCIEX_S_PERR,	PCIE_AER_SUCE_PERR_ASSERT,	NULL,	DDI_FM_UNKNOWN,
	PCIEX_S_SERR,	PCIE_AER_SUCE_SERR_ASSERT,	NULL,	DDI_FM_FATAL,
	PCIEX_INTERR,	PCIE_AER_SUCE_INTERNAL_ERR,	NULL,	DDI_FM_FATAL,
	NULL, NULL, NULL, NULL,
};

static pci_fm_err_t pcix_err_tbl[] = {
	PCIX_SPL_DIS,		PCI_PCIX_SPL_DSCD,	NULL,	DDI_FM_UNKNOWN,
	PCIX_UNEX_SPL,		PCI_PCIX_UNEX_SPL,	NULL,	DDI_FM_UNKNOWN,
	PCIX_RX_SPL_MSG,	PCI_PCIX_RX_SPL_MSG,	NULL,   DDI_FM_UNKNOWN,
	NULL, NULL, NULL, NULL,
};

static pci_fm_err_t pcix_sec_err_tbl[] = {
	PCIX_SPL_DIS,		PCI_PCIX_BSS_SPL_DSCD,	NULL,	DDI_FM_UNKNOWN,
	PCIX_UNEX_SPL,		PCI_PCIX_BSS_UNEX_SPL,	NULL,	DDI_FM_UNKNOWN,
	PCIX_BSS_SPL_OR,	PCI_PCIX_BSS_SPL_OR,	NULL,	DDI_FM_OK,
	PCIX_BSS_SPL_DLY,	PCI_PCIX_BSS_SPL_DLY,	NULL,	DDI_FM_OK,
	NULL, NULL, NULL, NULL,
};

static pci_fm_err_t pciex_nadv_err_tbl[] = {
	PCIEX_UR,	PCIE_DEVSTS_UR_DETECTED,	NULL,	DDI_FM_UNKNOWN,
	PCIEX_FAT,	PCIE_DEVSTS_FE_DETECTED,	NULL,	DDI_FM_FATAL,
	PCIEX_NONFAT,	PCIE_DEVSTS_NFE_DETECTED,	NULL,	DDI_FM_UNKNOWN,
	PCIEX_CORR,	PCIE_DEVSTS_CE_DETECTED,	NULL,	DDI_FM_OK,
	NULL, NULL, NULL, NULL,
};

static int
pci_config_check(ddi_acc_handle_t handle, int fme_flag)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);
	ddi_fm_error_t de;

	if (!(DDI_FM_ACC_ERR_CAP(ddi_fm_capable(hp->ah_dip))))
		return (DDI_FM_OK);

	de.fme_version = DDI_FME_VERSION;

	ddi_fm_acc_err_get(handle, &de, de.fme_version);
	if (de.fme_status != DDI_FM_OK) {
		if (fme_flag == DDI_FM_ERR_UNEXPECTED) {
			char buf[FM_MAX_CLASS];

			(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
			    PCI_ERROR_SUBCLASS, PCI_NR);
			ddi_fm_ereport_post(hp->ah_dip, buf, de.fme_ena,
			    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0, NULL);
		}
		ddi_fm_acc_err_clear(handle, de.fme_version);
	}
	return (de.fme_status);
}

static void
pcix_ecc_regs_gather(pci_erpt_t *erpt_p, pcix_ecc_regs_t *pcix_ecc_regs,
    uint8_t pcix_cap_ptr, int fme_flag)
{
	int bdg = erpt_p->pe_dflags & PCI_BRIDGE_DEV;

	pcix_ecc_regs->pcix_ecc_ctlstat = pci_config_get32(erpt_p->pe_hdl,
	    (pcix_cap_ptr + (bdg ? PCI_PCIX_BDG_ECC_STATUS :
	    PCI_PCIX_ECC_STATUS)));
	if (pci_config_check(erpt_p->pe_hdl, fme_flag) == DDI_FM_OK)
		pcix_ecc_regs->pcix_ecc_vflags |= PCIX_ERR_ECC_STS_VALID;
	else
		return;
	pcix_ecc_regs->pcix_ecc_fstaddr = pci_config_get32(erpt_p->pe_hdl,
	    (pcix_cap_ptr + (bdg ? PCI_PCIX_BDG_ECC_FST_AD :
	    PCI_PCIX_ECC_FST_AD)));
	pcix_ecc_regs->pcix_ecc_secaddr = pci_config_get32(erpt_p->pe_hdl,
	    (pcix_cap_ptr + (bdg ? PCI_PCIX_BDG_ECC_SEC_AD :
	    PCI_PCIX_ECC_SEC_AD)));
	pcix_ecc_regs->pcix_ecc_attr = pci_config_get32((
	    ddi_acc_handle_t)erpt_p->pe_hdl,
	    (pcix_cap_ptr + (bdg ? PCI_PCIX_BDG_ECC_ATTR : PCI_PCIX_ECC_ATTR)));
}

static void
pcix_regs_gather(pci_erpt_t *erpt_p, void *pe_regs, int fme_flag)
{
	if (erpt_p->pe_dflags & PCI_BRIDGE_DEV) {
		pcix_bdg_error_regs_t *pcix_bdg_regs =
		    (pcix_bdg_error_regs_t *)pe_regs;
		uint8_t pcix_bdg_cap_ptr;
		int i;

		pcix_bdg_cap_ptr = pcix_bdg_regs->pcix_bdg_cap_ptr;
		pcix_bdg_regs->pcix_bdg_sec_stat = pci_config_get16(
		    erpt_p->pe_hdl, (pcix_bdg_cap_ptr + PCI_PCIX_SEC_STATUS));
		if (pci_config_check(erpt_p->pe_hdl, fme_flag) == DDI_FM_OK)
			pcix_bdg_regs->pcix_bdg_vflags |=
			    PCIX_BDG_SEC_STATUS_VALID;
		else
			return;
		pcix_bdg_regs->pcix_bdg_stat = pci_config_get32(erpt_p->pe_hdl,
		    (pcix_bdg_cap_ptr + PCI_PCIX_BDG_STATUS));
		if (pci_config_check(erpt_p->pe_hdl, fme_flag) == DDI_FM_OK)
			pcix_bdg_regs->pcix_bdg_vflags |= PCIX_BDG_STATUS_VALID;
		else
			return;
		if (PCIX_ECC_VER_CHECK(pcix_bdg_regs->pcix_bdg_ver)) {
			pcix_ecc_regs_t *pcix_bdg_ecc_regs;
			/*
			 * PCI Express to PCI-X bridges only implement the
			 * secondary side of the PCI-X ECC registers, bit one is
			 * read-only so we make sure we do not write to it.
			 */
			if (erpt_p->pe_dflags & PCIEX_2PCI_DEV) {
				pcix_bdg_ecc_regs =
				    pcix_bdg_regs->pcix_bdg_ecc_regs[1];
				pcix_ecc_regs_gather(erpt_p, pcix_bdg_ecc_regs,
				    pcix_bdg_cap_ptr, fme_flag);
			} else {
				for (i = 0; i < 2; i++) {
					pcix_bdg_ecc_regs =
					    pcix_bdg_regs->pcix_bdg_ecc_regs[i];
					pci_config_put32(erpt_p->pe_hdl,
					    (pcix_bdg_cap_ptr +
					    PCI_PCIX_BDG_ECC_STATUS), i);
					pcix_ecc_regs_gather(erpt_p,
					    pcix_bdg_ecc_regs,
					    pcix_bdg_cap_ptr, fme_flag);
				}
			}
		}
	} else {
		pcix_error_regs_t *pcix_regs = (pcix_error_regs_t *)pe_regs;
		uint8_t pcix_cap_ptr;

		pcix_cap_ptr = pcix_regs->pcix_cap_ptr;

		pcix_regs->pcix_command = pci_config_get16(erpt_p->pe_hdl,
		    (pcix_cap_ptr + PCI_PCIX_COMMAND));
		pcix_regs->pcix_status = pci_config_get32(erpt_p->pe_hdl,
		    (pcix_cap_ptr + PCI_PCIX_STATUS));
		if (pci_config_check(erpt_p->pe_hdl, fme_flag) == DDI_FM_OK)
			pcix_regs->pcix_vflags |= PCIX_ERR_STATUS_VALID;
		else
			return;
		if (PCIX_ECC_VER_CHECK(pcix_regs->pcix_ver)) {
			pcix_ecc_regs_t *pcix_ecc_regs =
			    pcix_regs->pcix_ecc_regs;

			pcix_ecc_regs_gather(erpt_p, pcix_ecc_regs,
			    pcix_cap_ptr, fme_flag);
		}
	}
}

static void
pcie_regs_gather(pci_erpt_t *erpt_p, int fme_flag)
{
	pcie_error_regs_t *pcie_regs = (pcie_error_regs_t *)erpt_p->pe_regs;
	uint8_t pcie_cap_ptr;
	pcie_adv_error_regs_t *pcie_adv_regs;
	uint16_t pcie_ecap_ptr;

	pcie_cap_ptr = pcie_regs->pcie_cap_ptr;

	pcie_regs->pcie_err_status = pci_config_get16(erpt_p->pe_hdl,
	    pcie_cap_ptr + PCIE_DEVSTS);
	if (pci_config_check(erpt_p->pe_hdl, fme_flag) == DDI_FM_OK)
		pcie_regs->pcie_vflags |= PCIE_ERR_STATUS_VALID;
	else
		return;

	pcie_regs->pcie_err_ctl = pci_config_get16(erpt_p->pe_hdl,
	    (pcie_cap_ptr + PCIE_DEVCTL));
	pcie_regs->pcie_dev_cap = pci_config_get16(erpt_p->pe_hdl,
	    (pcie_cap_ptr + PCIE_DEVCAP));

	if ((erpt_p->pe_dflags & PCI_BRIDGE_DEV) && (erpt_p->pe_dflags &
	    PCIX_DEV))
		pcix_regs_gather(erpt_p, pcie_regs->pcix_bdg_regs, fme_flag);

	if (erpt_p->pe_dflags & PCIEX_RC_DEV) {
		pcie_rc_error_regs_t *pcie_rc_regs = pcie_regs->pcie_rc_regs;

		pcie_rc_regs->pcie_rc_status = pci_config_get32(erpt_p->pe_hdl,
		    (pcie_cap_ptr + PCIE_ROOTSTS));
		pcie_rc_regs->pcie_rc_ctl = pci_config_get16(erpt_p->pe_hdl,
		    (pcie_cap_ptr + PCIE_ROOTCTL));
	}

	if (!(erpt_p->pe_dflags & PCIEX_ADV_DEV))
		return;

	pcie_adv_regs = pcie_regs->pcie_adv_regs;

	pcie_ecap_ptr = pcie_adv_regs->pcie_adv_cap_ptr;

	pcie_adv_regs->pcie_ue_status = pci_config_get32(erpt_p->pe_hdl,
	    pcie_ecap_ptr + PCIE_AER_UCE_STS);
	if (pci_config_check(erpt_p->pe_hdl, fme_flag) == DDI_FM_OK)
		pcie_adv_regs->pcie_adv_vflags |= PCIE_UE_STATUS_VALID;

	pcie_adv_regs->pcie_ue_mask = pci_config_get32(erpt_p->pe_hdl,
	    pcie_ecap_ptr + PCIE_AER_UCE_MASK);
	pcie_adv_regs->pcie_ue_sev = pci_config_get32(erpt_p->pe_hdl,
	    pcie_ecap_ptr + PCIE_AER_UCE_SERV);
	pcie_adv_regs->pcie_adv_ctl = pci_config_get32(erpt_p->pe_hdl,
	    pcie_ecap_ptr + PCIE_AER_CTL);
	pcie_adv_regs->pcie_ue_hdr0 = pci_config_get32(erpt_p->pe_hdl,
	    pcie_ecap_ptr + PCIE_AER_HDR_LOG);
	if (pci_config_check(erpt_p->pe_hdl, fme_flag) == DDI_FM_OK) {
		int i;
		pcie_adv_regs->pcie_adv_vflags |= PCIE_UE_HDR_VALID;

		for (i = 0; i < 3; i++) {
			pcie_adv_regs->pcie_ue_hdr[i] = pci_config_get32(
			    erpt_p->pe_hdl, pcie_ecap_ptr + PCIE_AER_HDR_LOG +
			    (4 * (i + 1)));
		}
	}

	pcie_adv_regs->pcie_ce_status = pci_config_get32(erpt_p->pe_hdl,
	    pcie_ecap_ptr + PCIE_AER_CE_STS);
	if (pci_config_check(erpt_p->pe_hdl, fme_flag) == DDI_FM_OK)
		pcie_adv_regs->pcie_adv_vflags |= PCIE_CE_STATUS_VALID;

	pcie_adv_regs->pcie_ce_mask = pci_config_get32(erpt_p->pe_hdl,
	    pcie_ecap_ptr + PCIE_AER_CE_MASK);

	/*
	 * If pci express to pci bridge then grab the bridge
	 * error registers.
	 */
	if (erpt_p->pe_dflags & PCIEX_2PCI_DEV) {
		pcie_adv_bdg_error_regs_t *pcie_bdg_regs =
		    pcie_adv_regs->pcie_adv_bdg_regs;

		pcie_bdg_regs->pcie_sue_status =
		    pci_config_get32(erpt_p->pe_hdl,
		    pcie_ecap_ptr + PCIE_AER_SUCE_STS);
		pcie_bdg_regs->pcie_sue_mask =
		    pci_config_get32(erpt_p->pe_hdl,
		    pcie_ecap_ptr + PCIE_AER_SUCE_MASK);
		if (pci_config_check(erpt_p->pe_hdl, fme_flag) == DDI_FM_OK)
			pcie_adv_regs->pcie_adv_vflags |= PCIE_SUE_STATUS_VALID;
		pcie_bdg_regs->pcie_sue_hdr0 = pci_config_get32(erpt_p->pe_hdl,
		    (pcie_ecap_ptr + PCIE_AER_SHDR_LOG));

		if (pci_config_check(erpt_p->pe_hdl, fme_flag) == DDI_FM_OK) {
			int i;

			pcie_adv_regs->pcie_adv_vflags |= PCIE_SUE_HDR_VALID;

			for (i = 0; i < 3; i++) {
				pcie_bdg_regs->pcie_sue_hdr[i] =
				    pci_config_get32(erpt_p->pe_hdl,
				    pcie_ecap_ptr + PCIE_AER_SHDR_LOG +
				    (4 * (i + 1)));
			}
		}
	}
	/*
	 * If PCI Express root complex then grab the root complex
	 * error registers.
	 */
	if (erpt_p->pe_dflags & PCIEX_RC_DEV) {
		pcie_adv_rc_error_regs_t *pcie_rc_regs =
		    pcie_adv_regs->pcie_adv_rc_regs;

		pcie_rc_regs->pcie_rc_err_cmd = pci_config_get32(erpt_p->pe_hdl,
		    (pcie_ecap_ptr + PCIE_AER_RE_CMD));
		pcie_rc_regs->pcie_rc_err_status =
		    pci_config_get32(erpt_p->pe_hdl,
		    (pcie_ecap_ptr + PCIE_AER_RE_STS));
		if (pci_config_check(erpt_p->pe_hdl, fme_flag) == DDI_FM_OK)
			pcie_adv_regs->pcie_adv_vflags |=
			    PCIE_RC_ERR_STATUS_VALID;
		pcie_rc_regs->pcie_rc_ce_src_id =
		    pci_config_get16(erpt_p->pe_hdl,
		    (pcie_ecap_ptr + PCIE_AER_CE_SRC_ID));
		pcie_rc_regs->pcie_rc_ue_src_id =
		    pci_config_get16(erpt_p->pe_hdl,
		    (pcie_ecap_ptr + PCIE_AER_ERR_SRC_ID));
		if (pci_config_check(erpt_p->pe_hdl, fme_flag) == DDI_FM_OK)
			pcie_adv_regs->pcie_adv_vflags |= PCIE_SRC_ID_VALID;
	}
}

/*ARGSUSED*/
static void
pci_regs_gather(dev_info_t *dip, pci_erpt_t *erpt_p, int fme_flag)
{
	pci_error_regs_t *pci_regs = erpt_p->pe_pci_regs;

	/*
	 * Start by reading all the error registers that are available for
	 * pci and pci express and for leaf devices and bridges/switches
	 */
	pci_regs->pci_err_status = pci_config_get16(erpt_p->pe_hdl,
	    PCI_CONF_STAT);
	if (pci_config_check(erpt_p->pe_hdl, fme_flag) != DDI_FM_OK)
		return;
	pci_regs->pci_vflags |= PCI_ERR_STATUS_VALID;
	pci_regs->pci_cfg_comm = pci_config_get16(erpt_p->pe_hdl,
	    PCI_CONF_COMM);
	if (pci_config_check(erpt_p->pe_hdl, fme_flag) != DDI_FM_OK)
		return;

	/*
	 * If pci-pci bridge grab PCI bridge specific error registers.
	 */
	if (erpt_p->pe_dflags & PCI_BRIDGE_DEV) {
		pci_regs->pci_bdg_regs->pci_bdg_sec_stat =
		    pci_config_get16(erpt_p->pe_hdl, PCI_BCNF_SEC_STATUS);
		if (pci_config_check(erpt_p->pe_hdl, fme_flag) == DDI_FM_OK)
			pci_regs->pci_bdg_regs->pci_bdg_vflags |=
			    PCI_BDG_SEC_STAT_VALID;
		pci_regs->pci_bdg_regs->pci_bdg_ctrl =
		    pci_config_get16(erpt_p->pe_hdl, PCI_BCNF_BCNTRL);
		if (pci_config_check(erpt_p->pe_hdl, fme_flag) == DDI_FM_OK)
			pci_regs->pci_bdg_regs->pci_bdg_vflags |=
			    PCI_BDG_CTRL_VALID;
	}

	/*
	 * If pci express device grab pci express error registers and
	 * check for advanced error reporting features and grab them if
	 * available.
	 */
	if (erpt_p->pe_dflags & PCIEX_DEV)
		pcie_regs_gather(erpt_p, fme_flag);
	else if (erpt_p->pe_dflags & PCIX_DEV)
		pcix_regs_gather(erpt_p, erpt_p->pe_regs, fme_flag);

}

static void
pcix_regs_clear(pci_erpt_t *erpt_p, void *pe_regs)
{
	if (erpt_p->pe_dflags & PCI_BRIDGE_DEV) {
		pcix_bdg_error_regs_t *pcix_bdg_regs =
		    (pcix_bdg_error_regs_t *)pe_regs;
		uint8_t pcix_bdg_cap_ptr;
		int i;

		pcix_bdg_cap_ptr = pcix_bdg_regs->pcix_bdg_cap_ptr;

		if (pcix_bdg_regs->pcix_bdg_vflags & PCIX_BDG_SEC_STATUS_VALID)
			pci_config_put16(erpt_p->pe_hdl,
			    (pcix_bdg_cap_ptr + PCI_PCIX_SEC_STATUS),
			    pcix_bdg_regs->pcix_bdg_sec_stat);

		if (pcix_bdg_regs->pcix_bdg_vflags & PCIX_BDG_STATUS_VALID)
			pci_config_put32(erpt_p->pe_hdl,
			    (pcix_bdg_cap_ptr + PCI_PCIX_BDG_STATUS),
			    pcix_bdg_regs->pcix_bdg_stat);

		pcix_bdg_regs->pcix_bdg_vflags = 0x0;

		if (PCIX_ECC_VER_CHECK(pcix_bdg_regs->pcix_bdg_ver)) {
			pcix_ecc_regs_t *pcix_bdg_ecc_regs;
			/*
			 * PCI Express to PCI-X bridges only implement the
			 * secondary side of the PCI-X ECC registers, bit one is
			 * read-only so we make sure we do not write to it.
			 */
			if (erpt_p->pe_dflags & PCIEX_2PCI_DEV) {
				pcix_bdg_ecc_regs =
				    pcix_bdg_regs->pcix_bdg_ecc_regs[1];

				if (pcix_bdg_ecc_regs->pcix_ecc_vflags &
				    PCIX_ERR_ECC_STS_VALID) {

					pci_config_put32(erpt_p->pe_hdl,
					    (pcix_bdg_cap_ptr +
					    PCI_PCIX_BDG_ECC_STATUS),
					    pcix_bdg_ecc_regs->
					    pcix_ecc_ctlstat);
				}
				pcix_bdg_ecc_regs->pcix_ecc_vflags = 0x0;
			} else {
				for (i = 0; i < 2; i++) {
					pcix_bdg_ecc_regs =
					    pcix_bdg_regs->pcix_bdg_ecc_regs[i];


					if (pcix_bdg_ecc_regs->pcix_ecc_vflags &
					    PCIX_ERR_ECC_STS_VALID) {
						pci_config_put32(erpt_p->pe_hdl,
						    (pcix_bdg_cap_ptr +
						    PCI_PCIX_BDG_ECC_STATUS),
						    i);

						pci_config_put32(erpt_p->pe_hdl,
						    (pcix_bdg_cap_ptr +
						    PCI_PCIX_BDG_ECC_STATUS),
						    pcix_bdg_ecc_regs->
						    pcix_ecc_ctlstat);
					}
					pcix_bdg_ecc_regs->pcix_ecc_vflags =
					    0x0;
				}
			}
		}
	} else {
		pcix_error_regs_t *pcix_regs = (pcix_error_regs_t *)pe_regs;
		uint8_t pcix_cap_ptr;

		pcix_cap_ptr = pcix_regs->pcix_cap_ptr;

		if (pcix_regs->pcix_vflags & PCIX_ERR_STATUS_VALID)
			pci_config_put32(erpt_p->pe_hdl,
			    (pcix_cap_ptr + PCI_PCIX_STATUS),
			    pcix_regs->pcix_status);

		pcix_regs->pcix_vflags = 0x0;

		if (PCIX_ECC_VER_CHECK(pcix_regs->pcix_ver)) {
			pcix_ecc_regs_t *pcix_ecc_regs =
			    pcix_regs->pcix_ecc_regs;

			if (pcix_ecc_regs->pcix_ecc_vflags &
			    PCIX_ERR_ECC_STS_VALID)
				pci_config_put32(erpt_p->pe_hdl,
				    (pcix_cap_ptr + PCI_PCIX_ECC_STATUS),
				    pcix_ecc_regs->pcix_ecc_ctlstat);

			pcix_ecc_regs->pcix_ecc_vflags = 0x0;
		}
	}
}

static void
pcie_regs_clear(pci_erpt_t *erpt_p)
{
	pcie_error_regs_t *pcie_regs = (pcie_error_regs_t *)erpt_p->pe_regs;
	uint8_t pcie_cap_ptr;
	pcie_adv_error_regs_t *pcie_adv_regs;
	uint16_t pcie_ecap_ptr;

	pcie_cap_ptr = pcie_regs->pcie_cap_ptr;

	if (pcie_regs->pcie_vflags & PCIE_ERR_STATUS_VALID)
		pci_config_put16(erpt_p->pe_hdl, pcie_cap_ptr + PCIE_DEVSTS,
		    pcie_regs->pcie_err_status);

	pcie_regs->pcie_vflags = 0x0;

	if ((erpt_p->pe_dflags & PCI_BRIDGE_DEV) &&
	    (erpt_p->pe_dflags & PCIX_DEV))
		pcix_regs_clear(erpt_p, pcie_regs->pcix_bdg_regs);

	if (!(erpt_p->pe_dflags & PCIEX_ADV_DEV))
		return;

	pcie_adv_regs = pcie_regs->pcie_adv_regs;

	pcie_ecap_ptr = pcie_adv_regs->pcie_adv_cap_ptr;

	if (pcie_adv_regs->pcie_adv_vflags & PCIE_UE_STATUS_VALID)
		pci_config_put32(erpt_p->pe_hdl,
		    pcie_ecap_ptr + PCIE_AER_UCE_STS,
		    pcie_adv_regs->pcie_ue_status);

	if (pcie_adv_regs->pcie_adv_vflags & PCIE_CE_STATUS_VALID)
		pci_config_put32(erpt_p->pe_hdl,
		    pcie_ecap_ptr + PCIE_AER_CE_STS,
		    pcie_adv_regs->pcie_ce_status);


	if (erpt_p->pe_dflags & PCIEX_2PCI_DEV) {
		pcie_adv_bdg_error_regs_t *pcie_bdg_regs =
		    pcie_adv_regs->pcie_adv_bdg_regs;


		if (pcie_adv_regs->pcie_adv_vflags & PCIE_SUE_STATUS_VALID)
			pci_config_put32(erpt_p->pe_hdl,
			    pcie_ecap_ptr + PCIE_AER_SUCE_STS,
			    pcie_bdg_regs->pcie_sue_status);
	}
	/*
	 * If PCI Express root complex then clear the root complex
	 * error registers.
	 */
	if (erpt_p->pe_dflags & PCIEX_RC_DEV) {
		pcie_adv_rc_error_regs_t *pcie_rc_regs =
		    pcie_adv_regs->pcie_adv_rc_regs;


		if (pcie_adv_regs->pcie_adv_vflags & PCIE_RC_ERR_STATUS_VALID)
			pci_config_put32(erpt_p->pe_hdl,
			    (pcie_ecap_ptr + PCIE_AER_RE_STS),
			    pcie_rc_regs->pcie_rc_err_status);
	}
	pcie_adv_regs->pcie_adv_vflags = 0x0;
}

static void
pci_regs_clear(pci_erpt_t *erpt_p)
{
	/*
	 * Finally clear the error bits
	 */
	if (erpt_p->pe_dflags & PCIEX_DEV)
		pcie_regs_clear(erpt_p);
	else if (erpt_p->pe_dflags & PCIX_DEV)
		pcix_regs_clear(erpt_p, erpt_p->pe_regs);

	if (erpt_p->pe_pci_regs->pci_vflags & PCI_ERR_STATUS_VALID)
		pci_config_put16(erpt_p->pe_hdl, PCI_CONF_STAT,
		    erpt_p->pe_pci_regs->pci_err_status);

	erpt_p->pe_pci_regs->pci_vflags = 0x0;

	if (erpt_p->pe_dflags & PCI_BRIDGE_DEV) {
		if (erpt_p->pe_pci_regs->pci_bdg_regs->pci_bdg_vflags &
		    PCI_BDG_SEC_STAT_VALID)
			pci_config_put16(erpt_p->pe_hdl, PCI_BCNF_SEC_STATUS,
			    erpt_p->pe_pci_regs->pci_bdg_regs->
			    pci_bdg_sec_stat);
		if (erpt_p->pe_pci_regs->pci_bdg_regs->pci_bdg_vflags &
		    PCI_BDG_CTRL_VALID)
			pci_config_put16(erpt_p->pe_hdl, PCI_BCNF_BCNTRL,
			    erpt_p->pe_pci_regs->pci_bdg_regs->pci_bdg_ctrl);

		erpt_p->pe_pci_regs->pci_bdg_regs->pci_bdg_vflags = 0x0;
	}
}

/*
 * pcix_ereport_setup: Allocate structures for PCI-X error handling and ereport
 * generation.
 */
/* ARGSUSED */
static void
pcix_ereport_setup(dev_info_t *dip, pci_erpt_t *erpt_p)
{
	uint8_t pcix_cap_ptr;
	int i;

	pcix_cap_ptr = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "pcix-capid-pointer", PCI_CAP_NEXT_PTR_NULL);

	if (pcix_cap_ptr != PCI_CAP_NEXT_PTR_NULL)
		erpt_p->pe_dflags |= PCIX_DEV;
	else
		return;

	if (erpt_p->pe_dflags & PCI_BRIDGE_DEV) {
		pcix_bdg_error_regs_t *pcix_bdg_regs;

		erpt_p->pe_regs = kmem_zalloc(sizeof (pcix_bdg_error_regs_t),
		    KM_SLEEP);
		pcix_bdg_regs = (pcix_bdg_error_regs_t *)erpt_p->pe_regs;
		pcix_bdg_regs->pcix_bdg_cap_ptr = pcix_cap_ptr;
		pcix_bdg_regs->pcix_bdg_ver = pci_config_get16(erpt_p->pe_hdl,
		    pcix_cap_ptr + PCI_PCIX_SEC_STATUS) & PCI_PCIX_VER_MASK;
		if (PCIX_ECC_VER_CHECK(pcix_bdg_regs->pcix_bdg_ver)) {
			for (i = 0; i < 2; i++) {
				pcix_bdg_regs->pcix_bdg_ecc_regs[i] =
				    kmem_zalloc(sizeof (pcix_ecc_regs_t),
				    KM_SLEEP);
			}
		}
	} else {
		pcix_error_regs_t *pcix_regs;

		erpt_p->pe_regs = kmem_zalloc(sizeof (pcix_error_regs_t),
		    KM_SLEEP);
		pcix_regs = (pcix_error_regs_t *)erpt_p->pe_regs;
		pcix_regs->pcix_cap_ptr = pcix_cap_ptr;
		pcix_regs->pcix_ver = pci_config_get16(erpt_p->pe_hdl,
		    pcix_cap_ptr + PCI_PCIX_COMMAND) & PCI_PCIX_VER_MASK;
		if (PCIX_ECC_VER_CHECK(pcix_regs->pcix_ver)) {
			pcix_regs->pcix_ecc_regs = kmem_zalloc(
			    sizeof (pcix_ecc_regs_t), KM_SLEEP);
		}
	}
}

static void
pcie_ereport_setup(dev_info_t *dip, pci_erpt_t *erpt_p)
{
	pcie_error_regs_t *pcie_regs;
	pcie_adv_error_regs_t *pcie_adv_regs;
	uint8_t pcix_cap_ptr;
	uint8_t pcie_cap_ptr;
	uint16_t pcie_ecap_ptr;
	uint16_t dev_type = 0;
	uint32_t mask = pcie_expected_ue_mask;

	/*
	 * The following sparc specific code should be removed once the pci_cap
	 * interfaces create the necessary properties for us.
	 */
#if defined(__sparc)
	ushort_t status;
	uint32_t slot_cap;
	uint8_t cap_ptr = 0;
	uint8_t cap_id = 0;
	uint32_t hdr, hdr_next_ptr, hdr_cap_id;
	uint16_t offset = P2ALIGN(PCIE_EXT_CAP, 4);
	uint16_t aer_ptr = 0;

	cap_ptr = pci_config_get8(erpt_p->pe_hdl, PCI_CONF_CAP_PTR);
	if (pci_config_check(erpt_p->pe_hdl, DDI_FM_ERR_UNEXPECTED) ==
	    DDI_FM_OK) {
		while ((cap_id = pci_config_get8(erpt_p->pe_hdl, cap_ptr)) !=
		    0xff) {
			if (cap_id == PCI_CAP_ID_PCIX) {
				(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
				    "pcix-capid-pointer", cap_ptr);
			}
		if (cap_id == PCI_CAP_ID_PCI_E) {
			status = pci_config_get16(erpt_p->pe_hdl, cap_ptr + 2);
			if (status & PCIE_PCIECAP_SLOT_IMPL) {
				/* offset 14h is Slot Cap Register */
				slot_cap = pci_config_get32(erpt_p->pe_hdl,
				    cap_ptr + PCIE_SLOTCAP);
				(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
				    "pcie-slotcap-reg", slot_cap);
			}
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
			    "pcie-capid-reg", pci_config_get16(erpt_p->pe_hdl,
			    cap_ptr + PCIE_PCIECAP));
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
			    "pcie-capid-pointer", cap_ptr);

		}
			if ((cap_ptr = pci_config_get8(erpt_p->pe_hdl,
			    cap_ptr + 1)) == 0xff || cap_ptr == 0 ||
			    (pci_config_check(erpt_p->pe_hdl,
			    DDI_FM_ERR_UNEXPECTED) != DDI_FM_OK))
				break;
		}
	}

#endif

	pcix_cap_ptr = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "pcix-capid-pointer", PCI_CAP_NEXT_PTR_NULL);

	if (pcix_cap_ptr != PCI_CAP_NEXT_PTR_NULL)
		erpt_p->pe_dflags |= PCIX_DEV;

	pcie_cap_ptr = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "pcie-capid-pointer", PCI_CAP_NEXT_PTR_NULL);

	if (pcie_cap_ptr != PCI_CAP_NEXT_PTR_NULL) {
		erpt_p->pe_dflags |= PCIEX_DEV;
		erpt_p->pe_regs = kmem_zalloc(sizeof (pcie_error_regs_t),
		    KM_SLEEP);
		pcie_regs = (pcie_error_regs_t *)erpt_p->pe_regs;
		pcie_regs->pcie_cap_ptr = pcie_cap_ptr;
	}

	if (!(erpt_p->pe_dflags & PCIEX_DEV))
		return;

	/*
	 * Don't currently need to check for version here because we are
	 * compliant with PCIE 1.0a which is version 0 and is guaranteed
	 * software compatibility with future versions.  We will need to
	 * add errors for new detectors/features which are added in newer
	 * revisions [sec 7.8.2].
	 */
	pcie_regs->pcie_cap = pci_config_get16(erpt_p->pe_hdl,
	    pcie_regs->pcie_cap_ptr + PCIE_PCIECAP);

	dev_type = pcie_regs->pcie_cap & PCIE_PCIECAP_DEV_TYPE_MASK;

	if ((erpt_p->pe_dflags & PCI_BRIDGE_DEV) &&
	    (erpt_p->pe_dflags & PCIX_DEV)) {
		int i;

		pcie_regs->pcix_bdg_regs =
		    kmem_zalloc(sizeof (pcix_bdg_error_regs_t), KM_SLEEP);

		pcie_regs->pcix_bdg_regs->pcix_bdg_cap_ptr = pcix_cap_ptr;
		pcie_regs->pcix_bdg_regs->pcix_bdg_ver =
		    pci_config_get16(erpt_p->pe_hdl,
		    pcix_cap_ptr + PCI_PCIX_SEC_STATUS) & PCI_PCIX_VER_MASK;

		if (PCIX_ECC_VER_CHECK(pcie_regs->pcix_bdg_regs->pcix_bdg_ver))
			for (i = 0; i < 2; i++)
				pcie_regs->pcix_bdg_regs->pcix_bdg_ecc_regs[i] =
				    kmem_zalloc(sizeof (pcix_ecc_regs_t),
				    KM_SLEEP);
	}

	if (dev_type == PCIE_PCIECAP_DEV_TYPE_ROOT) {
		erpt_p->pe_dflags |= PCIEX_RC_DEV;
		pcie_regs->pcie_rc_regs = kmem_zalloc(
		    sizeof (pcie_rc_error_regs_t), KM_SLEEP);
	}
	/*
	 * The following sparc specific code should be removed once the pci_cap
	 * interfaces create the necessary properties for us.
	 */
#if defined(__sparc)

	hdr = pci_config_get32(erpt_p->pe_hdl, offset);
	hdr_next_ptr = (hdr >> PCIE_EXT_CAP_NEXT_PTR_SHIFT) &
	    PCIE_EXT_CAP_NEXT_PTR_MASK;
	hdr_cap_id = (hdr >> PCIE_EXT_CAP_ID_SHIFT) & PCIE_EXT_CAP_ID_MASK;

	while ((hdr_next_ptr != PCIE_EXT_CAP_NEXT_PTR_NULL) &&
	    (hdr_cap_id != PCIE_EXT_CAP_ID_AER)) {
		offset = P2ALIGN(hdr_next_ptr, 4);
		hdr = pci_config_get32(erpt_p->pe_hdl, offset);
		hdr_next_ptr = (hdr >> PCIE_EXT_CAP_NEXT_PTR_SHIFT) &
		    PCIE_EXT_CAP_NEXT_PTR_MASK;
		hdr_cap_id = (hdr >> PCIE_EXT_CAP_ID_SHIFT) &
		    PCIE_EXT_CAP_ID_MASK;
	}

	if (hdr_cap_id == PCIE_EXT_CAP_ID_AER)
		aer_ptr = P2ALIGN(offset, 4);
	if (aer_ptr != PCI_CAP_NEXT_PTR_NULL)
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "pcie-aer-pointer", aer_ptr);
#endif

	/*
	 * Find and store if this device is capable of pci express
	 * advanced errors, if not report an error against the device.
	 */
	pcie_ecap_ptr = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "pcie-aer-pointer", PCI_CAP_NEXT_PTR_NULL);
	if (pcie_ecap_ptr != PCI_CAP_NEXT_PTR_NULL) {
		erpt_p->pe_dflags |= PCIEX_ADV_DEV;
		pcie_regs->pcie_adv_regs = kmem_zalloc(
		    sizeof (pcie_adv_error_regs_t), KM_SLEEP);
		pcie_regs->pcie_adv_regs->pcie_adv_cap_ptr = pcie_ecap_ptr;
	}

	if (!(erpt_p->pe_dflags & PCIEX_ADV_DEV)) {
		return;
	}

	pcie_adv_regs = pcie_regs->pcie_adv_regs;

	if (pcie_adv_regs == NULL)
		return;
	/*
	 * Initialize structures for advanced PCI Express devices.
	 */

	/*
	 * Advanced error registers exist for PCI Express to PCI(X) Bridges and
	 * may also exist for PCI(X) to PCI Express Bridges, the latter is not
	 * well explained in the PCI Express to PCI/PCI-X Bridge Specification
	 * 1.0 and will be left out of the current gathering of these registers.
	 */
	if (dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) {
		erpt_p->pe_dflags |= PCIEX_2PCI_DEV;
		pcie_adv_regs->pcie_adv_bdg_regs = kmem_zalloc(
		    sizeof (pcie_adv_bdg_error_regs_t), KM_SLEEP);
	}

	if (erpt_p->pe_dflags & PCIEX_RC_DEV)
		pcie_adv_regs->pcie_adv_rc_regs = kmem_zalloc(
		    sizeof (pcie_adv_rc_error_regs_t), KM_SLEEP);

	/*
	 * Check that mask values are as expected, if not
	 * change them to what we desire.
	 */
	pci_regs_gather(dip, erpt_p, DDI_FM_ERR_UNEXPECTED);
	pcie_regs = (pcie_error_regs_t *)erpt_p->pe_regs;
	if (pcie_regs->pcie_adv_regs->pcie_ce_mask != pcie_expected_ce_mask) {
		pci_config_put32(erpt_p->pe_hdl,
		    pcie_ecap_ptr + PCIE_AER_CE_MASK, pcie_expected_ce_mask);
	}

	/* Disable PTLP/ECRC (or mask these two) for Switches */
	if (dev_type == PCIE_PCIECAP_DEV_TYPE_UP ||
	    dev_type == PCIE_PCIECAP_DEV_TYPE_DOWN) {
		erpt_p->pe_dflags |= PCIEX_SWITCH_DEV;
		mask |= PCIE_AER_UCE_PTLP | PCIE_AER_UCE_ECRC;
	}

	if (pcie_regs->pcie_adv_regs->pcie_ue_mask != mask) {
		pci_config_put32(erpt_p->pe_hdl,
		    pcie_ecap_ptr + PCIE_AER_UCE_MASK, mask);
	}
	if (erpt_p->pe_dflags & PCIEX_2PCI_DEV) {
		if (pcie_regs->pcie_adv_regs->pcie_adv_bdg_regs->pcie_sue_mask
		    != pcie_expected_sue_mask) {
			pci_config_put32(erpt_p->pe_hdl,
			    pcie_ecap_ptr + PCIE_AER_SUCE_MASK,
			    pcie_expected_sue_mask);
		}
	}
}

/*
 * pci_ereport_setup: Detect PCI device type and initialize structures to be
 * used to generate ereports based on detected generic device errors.
 */
void
pci_ereport_setup(dev_info_t *dip)
{
	struct dev_info *devi = DEVI(dip);
	struct i_ddi_fmhdl *fmhdl = devi->devi_fmhdl;
	pci_erpt_t *erpt_p;
	uint8_t pci_hdr_type;
	uint16_t pci_status;
	pci_regspec_t *pci_rp;
	int32_t len;
	uint32_t phys_hi;

	/*
	 * If device is not ereport capbable then report an error against the
	 * driver for using this interface,
	 */
	if (!DDI_FM_EREPORT_CAP(ddi_fm_capable(dip)) &&
	    !DDI_FM_ERRCB_CAP(ddi_fm_capable(dip))) {
		i_ddi_drv_ereport_post(dip, DVR_EFMCAP, NULL, DDI_SLEEP);
		return;
	}

	/*
	 * ASSERT fmhdl exists and fh_bus_specific is NULL.
	 */
	ASSERT(fmhdl && (fmhdl->fh_bus_specific == NULL));

	erpt_p = kmem_zalloc(sizeof (pci_erpt_t), KM_SLEEP);

	if (pci_config_setup(dip, &erpt_p->pe_hdl) != DDI_SUCCESS)
		goto error;

	erpt_p->pe_pci_regs = kmem_zalloc(sizeof (pci_error_regs_t), KM_SLEEP);

	pci_status = pci_config_get16(erpt_p->pe_hdl, PCI_CONF_STAT);
	if (pci_config_check(erpt_p->pe_hdl, DDI_FM_ERR_UNEXPECTED) !=
	    DDI_FM_OK)
		goto error;

	/*
	 * Get header type and record if device is a bridge.
	 */
	pci_hdr_type = pci_config_get8(erpt_p->pe_hdl, PCI_CONF_HEADER);
	if (pci_config_check(erpt_p->pe_hdl, DDI_FM_ERR_UNEXPECTED) !=
	    DDI_FM_OK)
		goto error;

	/*
	 * Check to see if PCI device is a bridge, if so allocate pci bridge
	 * error register structure.
	 */
	if ((pci_hdr_type & PCI_HEADER_TYPE_M) == PCI_HEADER_PPB) {
		erpt_p->pe_dflags |= PCI_BRIDGE_DEV;
		erpt_p->pe_pci_regs->pci_bdg_regs = kmem_zalloc(
		    sizeof (pci_bdg_error_regs_t), KM_SLEEP);
	}

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&pci_rp, &len) == DDI_SUCCESS) {
		phys_hi = pci_rp->pci_phys_hi;
		kmem_free(pci_rp, len);

		erpt_p->pe_bdf = (uint16_t)(PCI_REG_BDFR_G(phys_hi) >>
		    PCI_REG_FUNC_SHIFT);
	}


	if (!(pci_status & PCI_STAT_CAP)) {
		goto done;
	}

	/*
	 * Initialize structures for PCI Express and PCI-X devices.
	 * Order matters below and pcie_ereport_setup should preceed
	 * pcix_ereport_setup.
	 */
	pcie_ereport_setup(dip, erpt_p);

	if (!(erpt_p->pe_dflags & PCIEX_DEV)) {
		pcix_ereport_setup(dip, erpt_p);
	}

done:
	pci_regs_gather(dip, erpt_p, DDI_FM_ERR_UNEXPECTED);
	pci_regs_clear(erpt_p);

	/*
	 * Before returning set fh_bus_specific to completed pci_erpt_t
	 * structure
	 */
	fmhdl->fh_bus_specific = (void *)erpt_p;

	return;
error:
	if (erpt_p->pe_pci_regs)
		kmem_free(erpt_p->pe_pci_regs, sizeof (pci_error_regs_t));
	kmem_free(erpt_p, sizeof (pci_erpt_t));
	erpt_p = NULL;
}

static void
pcix_ereport_teardown(pci_erpt_t *erpt_p)
{
	if (erpt_p->pe_dflags & PCI_BRIDGE_DEV) {
		pcix_bdg_error_regs_t *pcix_bdg_regs;
		uint16_t pcix_ver;

		pcix_bdg_regs = (pcix_bdg_error_regs_t *)erpt_p->pe_regs;
		pcix_ver = pcix_bdg_regs->pcix_bdg_ver;
		if (PCIX_ECC_VER_CHECK(pcix_ver)) {
			int i;
			for (i = 0; i < 2; i++)
				kmem_free(pcix_bdg_regs->pcix_bdg_ecc_regs[i],
				    sizeof (pcix_ecc_regs_t));
		}
		kmem_free(erpt_p->pe_regs, sizeof (pcix_bdg_error_regs_t));
	} else {
		pcix_error_regs_t *pcix_regs;
		uint16_t pcix_ver;

		pcix_regs = (pcix_error_regs_t *)erpt_p->pe_regs;
		pcix_ver = pcix_regs->pcix_ver;
		if (PCIX_ECC_VER_CHECK(pcix_ver)) {
			kmem_free(pcix_regs->pcix_ecc_regs,
			    sizeof (pcix_ecc_regs_t));
		}
		kmem_free(erpt_p->pe_regs, sizeof (pcix_error_regs_t));
	}
}

static void
pcie_ereport_teardown(pci_erpt_t *erpt_p)
{
	pcie_error_regs_t *pcie_regs = (pcie_error_regs_t *)erpt_p->pe_regs;

	if (erpt_p->pe_dflags & PCIEX_ADV_DEV) {
		pcie_adv_error_regs_t *pcie_adv = pcie_regs->pcie_adv_regs;

		if (erpt_p->pe_dflags & PCIEX_2PCI_DEV)
			kmem_free(pcie_adv->pcie_adv_bdg_regs,
			    sizeof (pcie_adv_bdg_error_regs_t));
		if (erpt_p->pe_dflags & PCIEX_RC_DEV)
			kmem_free(pcie_adv->pcie_adv_rc_regs,
			    sizeof (pcie_adv_rc_error_regs_t));
		kmem_free(pcie_adv, sizeof (pcie_adv_error_regs_t));
	}

	if (erpt_p->pe_dflags & PCIEX_RC_DEV)
		kmem_free(pcie_regs->pcie_rc_regs,
		    sizeof (pcie_rc_error_regs_t));

	if (erpt_p->pe_dflags & PCI_BRIDGE_DEV) {
		if (erpt_p->pe_dflags & PCIX_DEV) {
			uint16_t pcix_ver = pcie_regs->pcix_bdg_regs->
			    pcix_bdg_ver;

			if (PCIX_ECC_VER_CHECK(pcix_ver)) {
				int i;
				for (i = 0; i < 2; i++)
					kmem_free(pcie_regs->pcix_bdg_regs->
					    pcix_bdg_ecc_regs[i],
					    sizeof (pcix_ecc_regs_t));
			}
			kmem_free(pcie_regs->pcix_bdg_regs,
			    sizeof (pcix_bdg_error_regs_t));
		}
	}
	kmem_free(erpt_p->pe_regs, sizeof (pcie_error_regs_t));
}

void
pci_ereport_teardown(dev_info_t *dip)
{
	struct i_ddi_fmhdl *fmhdl = DEVI(dip)->devi_fmhdl;
	pci_erpt_t *erpt_p;

	if (!DDI_FM_EREPORT_CAP(ddi_fm_capable(dip)) &&
	    !DDI_FM_ERRCB_CAP(ddi_fm_capable(dip))) {
		i_ddi_drv_ereport_post(dip, DVR_EFMCAP, NULL, DDI_SLEEP);
	}

	ASSERT(fmhdl);

	erpt_p = (pci_erpt_t *)fmhdl->fh_bus_specific;
	if (erpt_p == NULL)
		return;

	if (erpt_p->pe_dflags & PCIEX_DEV)
		pcie_ereport_teardown(erpt_p);
	else if (erpt_p->pe_dflags & PCIX_DEV)
		pcix_ereport_teardown(erpt_p);
	pci_config_teardown((ddi_acc_handle_t *)&erpt_p->pe_hdl);
	if (erpt_p->pe_dflags & PCI_BRIDGE_DEV)
		kmem_free(erpt_p->pe_pci_regs->pci_bdg_regs,
		    sizeof (pci_bdg_error_regs_t));
	kmem_free(erpt_p->pe_pci_regs, sizeof (pci_error_regs_t));
	kmem_free(erpt_p, sizeof (pci_erpt_t));
	fmhdl->fh_bus_specific = NULL;
	/*
	 * The following sparc specific code should be removed once the pci_cap
	 * interfaces create the necessary properties for us.
	 */
#if defined(__sparc)
	(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, "pcix-capid-pointer");
	(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, "pcie-slotcap-reg");
	(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, "pcie-capid-reg");
	(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, "pcie-capid-pointer");
	(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, "pcie-aer-pointer");
#endif
}

static void
pcie_ereport_post(dev_info_t *dip, ddi_fm_error_t *derr, pci_erpt_t *erpt_p,
    char *buf, int errtype)
{
	pcie_error_regs_t *pcie_regs = (pcie_error_regs_t *)erpt_p->pe_regs;
	pcie_adv_error_regs_t *pcie_adv_regs = pcie_regs->pcie_adv_regs;
	pcie_adv_rc_error_regs_t *pcie_adv_rc_regs;

	switch (errtype) {
	case PCIEX_TYPE_CE:
		ddi_fm_ereport_post(dip, buf, derr->fme_ena,
		    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
		    PCIEX_DEVSTS_REG, DATA_TYPE_UINT16,
		    pcie_regs->pcie_err_status,
		    PCIEX_CE_STATUS_REG, DATA_TYPE_UINT32,
		    pcie_adv_regs->pcie_ce_status, NULL);
		break;
	case PCIEX_TYPE_UE:
		ddi_fm_ereport_post(dip, buf, derr->fme_ena,
		    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
		    PCIEX_DEVSTS_REG, DATA_TYPE_UINT16,
		    pcie_regs->pcie_err_status,
		    PCIEX_UE_STATUS_REG, DATA_TYPE_UINT32,
		    pcie_adv_regs->pcie_ue_status, PCIEX_UE_SEV_REG,
		    DATA_TYPE_UINT32, pcie_adv_regs->pcie_ue_sev,
		    PCIEX_ADV_CTL, DATA_TYPE_UINT32,
		    pcie_adv_regs->pcie_adv_ctl,
		    PCIEX_SRC_ID, DATA_TYPE_UINT16,
		    pcie_adv_regs->pcie_adv_bdf,
		    PCIEX_SRC_VALID, DATA_TYPE_BOOLEAN_VALUE,
		    (pcie_adv_regs->pcie_adv_bdf != NULL) ?
		    1 : NULL,
#ifdef DEBUG
		    PCIEX_UE_HDR0, DATA_TYPE_UINT32,
		    pcie_adv_regs->pcie_ue_hdr0,
		    PCIEX_UE_HDR1, DATA_TYPE_UINT32,
		    pcie_adv_regs->pcie_ue_hdr[0],
		    PCIEX_UE_HDR2, DATA_TYPE_UINT32,
		    pcie_adv_regs->pcie_ue_hdr[1],
		    PCIEX_UE_HDR3, DATA_TYPE_UINT32,
		    pcie_adv_regs->pcie_ue_hdr[2],
#endif
		    NULL);
		break;
	case PCIEX_TYPE_GEN:
		ddi_fm_ereport_post(dip, buf, derr->fme_ena,
		    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8,
		    0, PCIEX_DEVSTS_REG, DATA_TYPE_UINT16,
		    pcie_regs->pcie_err_status, NULL);
		break;
	case PCIEX_TYPE_RC_UE_MSG:
	case PCIEX_TYPE_RC_CE_MSG:
		pcie_adv_rc_regs = pcie_adv_regs->pcie_adv_rc_regs;

		ddi_fm_ereport_post(dip, buf, derr->fme_ena,
		    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
		    PCIEX_ROOT_ERRSTS_REG, DATA_TYPE_UINT32,
		    pcie_adv_rc_regs->pcie_rc_err_status,
		    PCIEX_SRC_ID, DATA_TYPE_UINT16,
		    (errtype == PCIEX_TYPE_RC_UE_MSG) ?
		    pcie_adv_rc_regs->pcie_rc_ue_src_id :
		    pcie_adv_rc_regs->pcie_rc_ce_src_id,
		    PCIEX_SRC_VALID, DATA_TYPE_BOOLEAN_VALUE,
		    (errtype == PCIEX_TYPE_RC_UE_MSG) ?
		    (pcie_adv_regs->pcie_adv_vflags & PCIE_SRC_ID_VALID &&
		    pcie_adv_rc_regs->pcie_rc_ue_src_id != 0) :
		    (pcie_adv_regs->pcie_adv_vflags & PCIE_SRC_ID_VALID &&
		    pcie_adv_rc_regs->pcie_rc_ce_src_id != 0), NULL);
		break;
	case PCIEX_TYPE_RC_MULT_MSG:
		pcie_adv_rc_regs = pcie_adv_regs->pcie_adv_rc_regs;

		ddi_fm_ereport_post(dip, buf, derr->fme_ena,
		    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
		    PCIEX_ROOT_ERRSTS_REG, DATA_TYPE_UINT32,
		    pcie_adv_rc_regs->pcie_rc_err_status, NULL);
		break;
	default:
		break;
	}
}

/*ARGSUSED*/
static void
pcie_check_addr(dev_info_t *dip, ddi_fm_error_t *derr, pci_erpt_t *erpt_p)
{
	pcie_error_regs_t *pcie_regs = (pcie_error_regs_t *)erpt_p->pe_regs;
	pcie_adv_error_regs_t *pcie_adv_regs = pcie_regs->pcie_adv_regs;
	pcie_tlp_hdr_t *ue_hdr0;
	uint32_t *ue_hdr;
	uint64_t addr = NULL;
	int upstream = 0;
	pci_fme_bus_specific_t *pci_fme_bsp =
	    (pci_fme_bus_specific_t *)derr->fme_bus_specific;

	if (!(pcie_adv_regs->pcie_adv_vflags & PCIE_UE_HDR_VALID))
		return;

	ue_hdr0 = (pcie_tlp_hdr_t *)&pcie_adv_regs->pcie_ue_hdr0;
	ue_hdr = pcie_adv_regs->pcie_ue_hdr;

	if ((pcie_regs->pcie_cap & PCIE_PCIECAP_DEV_TYPE_MASK) ==
	    PCIE_PCIECAP_DEV_TYPE_ROOT ||
	    (pcie_regs->pcie_cap & PCIE_PCIECAP_DEV_TYPE_MASK) ==
	    PCIE_PCIECAP_DEV_TYPE_DOWN)
		upstream = 1;

	switch (ue_hdr0->type) {
	case PCIE_TLP_TYPE_MEM:
	case PCIE_TLP_TYPE_MEMLK:
		if ((ue_hdr0->fmt & 0x1) == 0x1) {
			pcie_mem64_t *mem64_tlp = (pcie_mem64_t *)ue_hdr;

			addr = (uint64_t)mem64_tlp->addr1 << 32 |
			    (uint32_t)mem64_tlp->addr0 << 2;
			pcie_adv_regs->pcie_adv_bdf = mem64_tlp->rid;
		} else {
			pcie_memio32_t *memio32_tlp = (pcie_memio32_t *)ue_hdr;

			addr = (uint32_t)memio32_tlp->addr0 << 2;
			pcie_adv_regs->pcie_adv_bdf = memio32_tlp->rid;
		}
		if (upstream) {
			pci_fme_bsp->pci_bs_bdf = pcie_adv_regs->pcie_adv_bdf;
			pci_fme_bsp->pci_bs_flags |= PCI_BS_BDF_VALID;
		} else if ((pcie_regs->pcie_cap & PCIE_PCIECAP_DEV_TYPE_MASK) ==
		    PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) {
			pci_fme_bsp->pci_bs_bdf = erpt_p->pe_bdf;
			pci_fme_bsp->pci_bs_flags |= PCI_BS_BDF_VALID;
		}
		pci_fme_bsp->pci_bs_addr = addr;
		pci_fme_bsp->pci_bs_flags |= PCI_BS_ADDR_VALID;
		pci_fme_bsp->pci_bs_type = upstream ? DMA_HANDLE : ACC_HANDLE;
		break;

	case PCIE_TLP_TYPE_IO:
		{
			pcie_memio32_t *memio32_tlp = (pcie_memio32_t *)ue_hdr;

			addr = (uint32_t)memio32_tlp->addr0 << 2;
			pcie_adv_regs->pcie_adv_bdf = memio32_tlp->rid;
			if ((pcie_regs->pcie_cap &
			    PCIE_PCIECAP_DEV_TYPE_MASK) ==
			    PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) {
				pci_fme_bsp->pci_bs_bdf = erpt_p->pe_bdf;
				pci_fme_bsp->pci_bs_flags |= PCI_BS_BDF_VALID;
			}
			pci_fme_bsp->pci_bs_addr = addr;
			pci_fme_bsp->pci_bs_flags |= PCI_BS_ADDR_VALID;
			pci_fme_bsp->pci_bs_type = ACC_HANDLE;
			break;
		}
	case PCIE_TLP_TYPE_CFG0:
	case PCIE_TLP_TYPE_CFG1:
		{
			pcie_cfg_t *cfg_tlp = (pcie_cfg_t *)ue_hdr;

			pcie_adv_regs->pcie_adv_bdf = cfg_tlp->rid;
			pci_fme_bsp->pci_bs_bdf = (uint16_t)cfg_tlp->bus << 8 |
			    (uint16_t)cfg_tlp->dev << 3 | cfg_tlp->func;
			pci_fme_bsp->pci_bs_flags |= PCI_BS_BDF_VALID;
			pci_fme_bsp->pci_bs_type = ACC_HANDLE;
			break;
		}
	case PCIE_TLP_TYPE_MSG:
		{
			pcie_msg_t *msg_tlp = (pcie_msg_t *)ue_hdr;

			pcie_adv_regs->pcie_adv_bdf = msg_tlp->rid;
			break;
		}
	case PCIE_TLP_TYPE_CPL:
	case PCIE_TLP_TYPE_CPLLK:
		{
			pcie_cpl_t *cpl_tlp = (pcie_cpl_t *)ue_hdr;

			pcie_adv_regs->pcie_adv_bdf = cpl_tlp->cid;
			pci_fme_bsp->pci_bs_flags |= PCI_BS_BDF_VALID;
			if (upstream) {
				pci_fme_bsp->pci_bs_bdf = cpl_tlp->cid;
				pci_fme_bsp->pci_bs_type = ACC_HANDLE;
			} else {
				pci_fme_bsp->pci_bs_bdf = cpl_tlp->rid;
				pci_fme_bsp->pci_bs_type = DMA_HANDLE;
			}
			break;
		}
	case PCIE_TLP_TYPE_MSI:
	default:
		break;
	}
}

/*ARGSUSED*/
static void
pcie_pci_check_addr(dev_info_t *dip, ddi_fm_error_t *derr, pci_erpt_t *erpt_p,
    int type)
{
	pcie_error_regs_t *pcie_regs = (pcie_error_regs_t *)erpt_p->pe_regs;
	pcie_adv_error_regs_t *pcie_adv_regs = pcie_regs->pcie_adv_regs;
	pcie_adv_bdg_error_regs_t *pcie_bdg_regs =
	    pcie_adv_regs->pcie_adv_bdg_regs;
	uint64_t addr = NULL;
	pcix_attr_t *pcie_pci_sue_attr;
	int cmd;
	int dual_addr = 0;
	pci_fme_bus_specific_t *pci_fme_bsp =
	    (pci_fme_bus_specific_t *)derr->fme_bus_specific;

	if (!(pcie_adv_regs->pcie_adv_vflags & PCIE_SUE_HDR_VALID))
		return;

	pcie_pci_sue_attr = (pcix_attr_t *)&pcie_bdg_regs->pcie_sue_hdr0;
	cmd = (pcie_bdg_regs->pcie_sue_hdr[0] >>
	    PCIE_AER_SUCE_HDR_CMD_LWR_SHIFT) & PCIE_AER_SUCE_HDR_CMD_LWR_MASK;

cmd_switch:
	addr = pcie_bdg_regs->pcie_sue_hdr[2];
	addr = (addr << PCIE_AER_SUCE_HDR_ADDR_SHIFT) |
	    pcie_bdg_regs->pcie_sue_hdr[1];
	switch (cmd) {
	case PCI_PCIX_CMD_IORD:
	case PCI_PCIX_CMD_IOWR:
		pcie_adv_regs->pcie_adv_bdf = pcie_pci_sue_attr->rid;
		if (addr) {
			pci_fme_bsp->pci_bs_addr = addr;
			pci_fme_bsp->pci_bs_flags |= PCI_BS_ADDR_VALID;
			pci_fme_bsp->pci_bs_type = ACC_HANDLE;
		}
		break;
	case PCI_PCIX_CMD_MEMRD_DW:
	case PCI_PCIX_CMD_MEMWR:
	case PCI_PCIX_CMD_MEMRD_BL:
	case PCI_PCIX_CMD_MEMWR_BL:
	case PCI_PCIX_CMD_MEMRDBL:
	case PCI_PCIX_CMD_MEMWRBL:
		pcie_adv_regs->pcie_adv_bdf = pcie_pci_sue_attr->rid;
		if (addr) {
			pci_fme_bsp->pci_bs_addr = addr;
			pci_fme_bsp->pci_bs_flags |= PCI_BS_ADDR_VALID;
			pci_fme_bsp->pci_bs_type = type;
		}
		break;
	case PCI_PCIX_CMD_CFRD:
	case PCI_PCIX_CMD_CFWR:
		pcie_adv_regs->pcie_adv_bdf = pcie_pci_sue_attr->rid;
		/*
		 * for type 1 config transaction we can find bdf from address
		 */
		if ((addr & 3) == 1) {
			pci_fme_bsp->pci_bs_bdf = (addr >> 8) & 0xffffffff;
			pci_fme_bsp->pci_bs_flags |= PCI_BS_BDF_VALID;
			pci_fme_bsp->pci_bs_type = ACC_HANDLE;
		}
		break;
	case PCI_PCIX_CMD_SPL:
		pcie_adv_regs->pcie_adv_bdf = pcie_pci_sue_attr->rid;
		if (type == ACC_HANDLE) {
			pci_fme_bsp->pci_bs_bdf = pcie_adv_regs->pcie_adv_bdf;
			pci_fme_bsp->pci_bs_flags |= PCI_BS_BDF_VALID;
			pci_fme_bsp->pci_bs_type = type;
		}
		break;
	case PCI_PCIX_CMD_DADR:
		cmd = (pcie_bdg_regs->pcie_sue_hdr[0] >>
		    PCIE_AER_SUCE_HDR_CMD_UP_SHIFT) &
		    PCIE_AER_SUCE_HDR_CMD_UP_MASK;
		if (dual_addr)
			break;
		++dual_addr;
		goto cmd_switch;
	default:
		break;
	}
}

/*ARGSUSED*/
static int
pcix_check_addr(dev_info_t *dip, ddi_fm_error_t *derr,
    pcix_ecc_regs_t *pcix_ecc_regs, int type)
{
	int cmd = (pcix_ecc_regs->pcix_ecc_ctlstat >> 16) & 0xf;
	uint64_t addr;
	pci_fme_bus_specific_t *pci_fme_bsp =
	    (pci_fme_bus_specific_t *)derr->fme_bus_specific;

	addr = pcix_ecc_regs->pcix_ecc_secaddr;
	addr = addr << 32;
	addr |= pcix_ecc_regs->pcix_ecc_fstaddr;

	switch (cmd) {
	case PCI_PCIX_CMD_INTR:
	case PCI_PCIX_CMD_SPEC:
		return (DDI_FM_FATAL);
	case PCI_PCIX_CMD_IORD:
	case PCI_PCIX_CMD_IOWR:
		pci_fme_bsp->pci_bs_addr = addr;
		pci_fme_bsp->pci_bs_flags |= PCI_BS_ADDR_VALID;
		pci_fme_bsp->pci_bs_type = type;
		return (DDI_FM_UNKNOWN);
	case PCI_PCIX_CMD_DEVID:
		return (DDI_FM_FATAL);
	case PCI_PCIX_CMD_MEMRD_DW:
	case PCI_PCIX_CMD_MEMWR:
	case PCI_PCIX_CMD_MEMRD_BL:
	case PCI_PCIX_CMD_MEMWR_BL:
		pci_fme_bsp->pci_bs_addr = addr;
		pci_fme_bsp->pci_bs_flags |= PCI_BS_ADDR_VALID;
		pci_fme_bsp->pci_bs_type = type;
		return (DDI_FM_UNKNOWN);
	case PCI_PCIX_CMD_CFRD:
	case PCI_PCIX_CMD_CFWR:
		/*
		 * for type 1 config transaction we can find bdf from address
		 */
		if ((addr & 3) == 1) {
			pci_fme_bsp->pci_bs_bdf = (addr >> 8) & 0xffffffff;
			pci_fme_bsp->pci_bs_flags |= PCI_BS_BDF_VALID;
			pci_fme_bsp->pci_bs_type = type;
		}
		return (DDI_FM_UNKNOWN);
	case PCI_PCIX_CMD_SPL:
	case PCI_PCIX_CMD_DADR:
		return (DDI_FM_UNKNOWN);
	case PCI_PCIX_CMD_MEMRDBL:
	case PCI_PCIX_CMD_MEMWRBL:
		pci_fme_bsp->pci_bs_addr = addr;
		pci_fme_bsp->pci_bs_flags |= PCI_BS_ADDR_VALID;
		pci_fme_bsp->pci_bs_type = type;
		return (DDI_FM_UNKNOWN);
	default:
		return (DDI_FM_FATAL);
	}
}

/*ARGSUSED*/
static int
pci_bdg_error_report(dev_info_t *dip, ddi_fm_error_t *derr, pci_erpt_t *erpt_p)
{
	pci_bdg_error_regs_t *pci_bdg_regs = erpt_p->pe_pci_regs->pci_bdg_regs;
	int fatal = 0;
	int nonfatal = 0;
	int unknown = 0;
	int ok = 0;
	int ret = DDI_FM_OK;
	char buf[FM_MAX_CLASS];
	int i;
	pci_fme_bus_specific_t *pci_fme_bsp =
	    (pci_fme_bus_specific_t *)derr->fme_bus_specific;

	if (derr->fme_flag != DDI_FM_ERR_UNEXPECTED)
		goto done;

	if ((pci_bdg_regs->pci_bdg_vflags & PCI_BDG_CTRL_VALID) &&
	    (pci_bdg_regs->pci_bdg_ctrl & PCI_BCNF_BCNTRL_DTO_STAT)) {
		(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
		    PCI_ERROR_SUBCLASS, PCI_DTO);
		ddi_fm_ereport_post(dip, buf, derr->fme_ena,
		    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
		    PCI_SEC_CONFIG_STATUS, DATA_TYPE_UINT16,
		    pci_bdg_regs->pci_bdg_sec_stat, PCI_BCNTRL,
		    DATA_TYPE_UINT16, pci_bdg_regs->pci_bdg_ctrl, NULL);
		unknown++;
	}

	if (pci_bdg_regs->pci_bdg_vflags & PCI_BDG_SEC_STAT_VALID) {
		for (i = 0; pci_bdg_err_tbl[i].err_class != NULL; i++) {
			if (pci_bdg_regs->pci_bdg_sec_stat &
			    pci_bdg_err_tbl[i].reg_bit) {
				(void) snprintf(buf, FM_MAX_CLASS, "%s.%s-%s",
				    PCI_ERROR_SUBCLASS, PCI_SEC_ERROR_SUBCLASS,
				    pci_bdg_err_tbl[i].err_class);
				ddi_fm_ereport_post(dip, buf, derr->fme_ena,
				    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
				    PCI_SEC_CONFIG_STATUS, DATA_TYPE_UINT16,
				    pci_bdg_regs->pci_bdg_sec_stat, PCI_BCNTRL,
				    DATA_TYPE_UINT16,
				    pci_bdg_regs->pci_bdg_ctrl, NULL);
				PCI_FM_SEV_INC(pci_bdg_err_tbl[i].flags);
				if (pci_fme_bsp && (pci_fme_bsp->pci_bs_flags &
				    PCI_BS_ADDR_VALID) &&
				    pci_fme_bsp->pci_bs_type == ACC_HANDLE &&
				    pci_bdg_err_tbl[i].terr_class)
					pci_target_enqueue(derr->fme_ena,
					    pci_bdg_err_tbl[i].terr_class,
					    PCI_ERROR_SUBCLASS,
					    pci_fme_bsp->pci_bs_addr);
			}
		}
#if !defined(__sparc)
		/*
		 * For x86, many drivers and even user-level code currently get
		 * away with accessing bad addresses, getting a UR and getting
		 * -1 returned. Unfortunately, we have no control over this, so
		 * we will have to treat all URs as nonfatal. Moreover, if the
		 * leaf driver is non-hardened, then we don't actually see the
		 * UR directly. All we see is a secondary bus master abort at
		 * the root complex - so it's this condition that we actually
		 * need to treat as nonfatal (providing no other unrelated nfe
		 * conditions have also been seen by the root complex).
		 */
		if ((erpt_p->pe_dflags & PCIEX_RC_DEV) &&
		    (pci_bdg_regs->pci_bdg_sec_stat & PCI_STAT_R_MAST_AB) &&
		    !(pci_bdg_regs->pci_bdg_sec_stat & PCI_STAT_S_PERROR)) {
			pcie_error_regs_t *pcie_regs =
			    (pcie_error_regs_t *)erpt_p->pe_regs;
			if ((pcie_regs->pcie_vflags & PCIE_ERR_STATUS_VALID) &&
			    !(pcie_regs->pcie_err_status &
			    PCIE_DEVSTS_NFE_DETECTED))
				nonfatal++;
			if (erpt_p->pe_dflags & PCIEX_ADV_DEV) {
				pcie_adv_error_regs_t *pcie_adv_regs =
				    pcie_regs->pcie_adv_regs;
				pcie_adv_rc_error_regs_t *pcie_rc_regs =
				    pcie_adv_regs->pcie_adv_rc_regs;
				if ((pcie_adv_regs->pcie_adv_vflags &
				    PCIE_RC_ERR_STATUS_VALID) &&
				    (pcie_rc_regs->pcie_rc_err_status &
				    PCIE_AER_RE_STS_NFE_MSGS_RCVD)) {
					(void) snprintf(buf, FM_MAX_CLASS,
					    "%s.%s-%s", PCI_ERROR_SUBCLASS,
					    PCI_SEC_ERROR_SUBCLASS, PCI_MA);
					ddi_fm_ereport_post(dip, buf,
					    derr->fme_ena, DDI_NOSLEEP,
					    FM_VERSION, DATA_TYPE_UINT8, 0,
					    PCI_SEC_CONFIG_STATUS,
					    DATA_TYPE_UINT16,
					    pci_bdg_regs->pci_bdg_sec_stat,
					    PCI_BCNTRL, DATA_TYPE_UINT16,
					    pci_bdg_regs->pci_bdg_ctrl, NULL);
				}
			}
		}
#endif
	}

done:
	/*
	 * Need to check for poke and cautious put. We already know peek
	 * and cautious get errors occurred (as we got a trap) and we know
	 * they are nonfatal.
	 */
	if (derr->fme_flag == DDI_FM_ERR_EXPECTED) {
		/*
		 * for cautious puts we treat all errors as nonfatal. Actually
		 * we set nonfatal for cautious gets as well - doesn't do any
		 * harm
		 */
		if (pci_bdg_regs->pci_bdg_sec_stat & (PCI_STAT_R_TARG_AB |
		    PCI_STAT_R_MAST_AB | PCI_STAT_S_PERROR | PCI_STAT_S_SYSERR))
			nonfatal++;
	}
	if (derr->fme_flag == DDI_FM_ERR_POKE) {
		/*
		 * special case for pokes - we only consider master abort
		 * and target abort as nonfatal. Sserr with no master abort is
		 * fatal, but master/target abort can come in on separate
		 * instance, so return unknown and parent will determine if
		 * nonfatal (if another child returned nonfatal - ie master
		 * or target abort) or fatal otherwise
		 */
		if (pci_bdg_regs->pci_bdg_sec_stat & (PCI_STAT_R_TARG_AB |
		    PCI_STAT_R_MAST_AB))
			nonfatal++;
		if (erpt_p->pe_pci_regs->pci_err_status & PCI_STAT_S_SYSERR)
			unknown++;
	}

	/*
	 * now check children below the bridge
	 */
	ret = ndi_fm_handler_dispatch(dip, NULL, derr);
	PCI_FM_SEV_INC(ret);
	return (fatal ? DDI_FM_FATAL : (nonfatal ? DDI_FM_NONFATAL :
	    (unknown ? DDI_FM_UNKNOWN : DDI_FM_OK)));
}

static int
pcix_ecc_error_report(dev_info_t *dip, ddi_fm_error_t *derr, pci_erpt_t *erpt_p,
    void *pe_regs)
{
	pcix_error_regs_t *pcix_regs;
	pcix_bdg_error_regs_t *pcix_bdg_regs;
	pcix_ecc_regs_t *pcix_ecc_regs;
	int bridge;
	int i;
	int ecc_phase;
	int ecc_corr;
	int sec_ue;
	int sec_ce;
	int fatal = 0;
	int nonfatal = 0;
	int unknown = 0;
	int ok = 0;
	char buf[FM_MAX_CLASS];

	if (erpt_p->pe_dflags & PCI_BRIDGE_DEV) {
		pcix_bdg_regs = (pcix_bdg_error_regs_t *)pe_regs;
		bridge = 1;
	} else {
		pcix_regs = (pcix_error_regs_t *)pe_regs;
		bridge = 0;
	}

	for (i = 0; i < (bridge ? 2 : 1); i++) {
		int ret = DDI_FM_OK;
		pcix_ecc_regs = bridge ? pcix_bdg_regs->pcix_bdg_ecc_regs[i] :
		    pcix_regs->pcix_ecc_regs;
		if (pcix_ecc_regs->pcix_ecc_vflags & PCIX_ERR_ECC_STS_VALID) {
			ecc_phase = (pcix_ecc_regs->pcix_ecc_ctlstat &
			    PCI_PCIX_ECC_PHASE) >> 0x4;
			ecc_corr = (pcix_ecc_regs->pcix_ecc_ctlstat &
			    PCI_PCIX_ECC_CORR);
			sec_ue = (pcix_ecc_regs->pcix_ecc_ctlstat &
			    PCI_PCIX_ECC_S_UE);
			sec_ce = (pcix_ecc_regs->pcix_ecc_ctlstat &
			    PCI_PCIX_ECC_S_CE);

			switch (ecc_phase) {
			case PCI_PCIX_ECC_PHASE_NOERR:
				break;
			case PCI_PCIX_ECC_PHASE_FADDR:
			case PCI_PCIX_ECC_PHASE_SADDR:
				PCI_FM_SEV_INC(ecc_corr ?  DDI_FM_OK :
				    DDI_FM_FATAL);
				(void) snprintf(buf, FM_MAX_CLASS,
				    "%s.%s%s", PCIX_ERROR_SUBCLASS,
				    i ? PCIX_SEC_ERROR_SUBCLASS : "",
				    ecc_corr ? PCIX_ECC_CE_ADDR :
				    PCIX_ECC_UE_ADDR);
				break;
			case PCI_PCIX_ECC_PHASE_ATTR:
				PCI_FM_SEV_INC(ecc_corr ?
				    DDI_FM_OK : DDI_FM_FATAL);
				(void) snprintf(buf, FM_MAX_CLASS,
				    "%s.%s%s", PCIX_ERROR_SUBCLASS,
				    i ? PCIX_SEC_ERROR_SUBCLASS : "",
				    ecc_corr ? PCIX_ECC_CE_ATTR :
				    PCIX_ECC_UE_ATTR);
				break;
			case PCI_PCIX_ECC_PHASE_DATA32:
			case PCI_PCIX_ECC_PHASE_DATA64:
				if (ecc_corr)
					ret = DDI_FM_OK;
				else {
					int type;
					pci_error_regs_t *pci_regs =
					    erpt_p->pe_pci_regs;

					if (i) {
						if (pci_regs->pci_bdg_regs->
						    pci_bdg_sec_stat &
						    PCI_STAT_S_PERROR)
							type = ACC_HANDLE;
						else
							type = DMA_HANDLE;
					} else {
						if (pci_regs->pci_err_status &
						    PCI_STAT_S_PERROR)
							type = DMA_HANDLE;
						else
							type = ACC_HANDLE;
					}
					ret = pcix_check_addr(dip, derr,
					    pcix_ecc_regs, type);
				}
				PCI_FM_SEV_INC(ret);

				(void) snprintf(buf, FM_MAX_CLASS,
				    "%s.%s%s", PCIX_ERROR_SUBCLASS,
				    i ? PCIX_SEC_ERROR_SUBCLASS : "",
				    ecc_corr ? PCIX_ECC_CE_DATA :
				    PCIX_ECC_UE_DATA);
				break;
			}
			if (ecc_phase)
				if (bridge)
					ddi_fm_ereport_post(dip, buf,
					    derr->fme_ena,
					    DDI_NOSLEEP, FM_VERSION,
					    DATA_TYPE_UINT8, 0,
					    PCIX_SEC_STATUS, DATA_TYPE_UINT16,
					    pcix_bdg_regs->pcix_bdg_sec_stat,
					    PCIX_BDG_STAT, DATA_TYPE_UINT32,
					    pcix_bdg_regs->pcix_bdg_stat,
					    PCIX_ECC_CTLSTAT, DATA_TYPE_UINT32,
					    pcix_ecc_regs->pcix_ecc_ctlstat,
					    PCIX_ECC_ATTR, DATA_TYPE_UINT32,
					    pcix_ecc_regs->pcix_ecc_attr, NULL);
				else
					ddi_fm_ereport_post(dip, buf,
					    derr->fme_ena,
					    DDI_NOSLEEP, FM_VERSION,
					    DATA_TYPE_UINT8, 0,
					    PCIX_COMMAND, DATA_TYPE_UINT16,
					    pcix_regs->pcix_command,
					    PCIX_STATUS, DATA_TYPE_UINT32,
					    pcix_regs->pcix_status,
					    PCIX_ECC_CTLSTAT, DATA_TYPE_UINT32,
					    pcix_ecc_regs->pcix_ecc_ctlstat,
					    PCIX_ECC_ATTR, DATA_TYPE_UINT32,
					    pcix_ecc_regs->pcix_ecc_attr, NULL);
			if (sec_ce || sec_ue) {
				(void) snprintf(buf, FM_MAX_CLASS,
				    "%s.%s%s", PCIX_ERROR_SUBCLASS,
				    i ? PCIX_SEC_ERROR_SUBCLASS : "",
				    sec_ce ? PCIX_ECC_S_CE : PCIX_ECC_S_UE);
				if (bridge)
					ddi_fm_ereport_post(dip, buf,
					    derr->fme_ena,
					    DDI_NOSLEEP, FM_VERSION,
					    DATA_TYPE_UINT8, 0,
					    PCIX_SEC_STATUS, DATA_TYPE_UINT16,
					    pcix_bdg_regs->pcix_bdg_sec_stat,
					    PCIX_BDG_STAT, DATA_TYPE_UINT32,
					    pcix_bdg_regs->pcix_bdg_stat,
					    PCIX_ECC_CTLSTAT, DATA_TYPE_UINT32,
					    pcix_ecc_regs->pcix_ecc_ctlstat,
					    PCIX_ECC_ATTR, DATA_TYPE_UINT32,
					    pcix_ecc_regs->pcix_ecc_attr, NULL);
				else
					ddi_fm_ereport_post(dip, buf,
					    derr->fme_ena,
					    DDI_NOSLEEP, FM_VERSION,
					    DATA_TYPE_UINT8, 0,
					    PCIX_COMMAND, DATA_TYPE_UINT16,
					    pcix_regs->pcix_command,
					    PCIX_STATUS, DATA_TYPE_UINT32,
					    pcix_regs->pcix_status,
					    PCIX_ECC_CTLSTAT, DATA_TYPE_UINT32,
					    pcix_ecc_regs->pcix_ecc_ctlstat,
					    PCIX_ECC_ATTR, DATA_TYPE_UINT32,
					    pcix_ecc_regs->pcix_ecc_attr, NULL);
				PCI_FM_SEV_INC(sec_ue ? DDI_FM_FATAL :
				    DDI_FM_OK);
			}
		}
	}
	return (fatal ? DDI_FM_FATAL : (nonfatal ? DDI_FM_NONFATAL :
	    (unknown ? DDI_FM_UNKNOWN : DDI_FM_OK)));
}

static int
pcix_bdg_error_report(dev_info_t *dip, ddi_fm_error_t *derr, pci_erpt_t *erpt_p,
    void *pe_regs)
{
	pcix_bdg_error_regs_t *pcix_bdg_regs = (pcix_bdg_error_regs_t *)pe_regs;
	int fatal = 0;
	int nonfatal = 0;
	int unknown = 0;
	int ok = 0;
	char buf[FM_MAX_CLASS];
	int i;

	if (pcix_bdg_regs->pcix_bdg_vflags & PCIX_BDG_STATUS_VALID) {
		for (i = 0; pcix_err_tbl[i].err_class != NULL; i++) {
			if ((pcix_bdg_regs->pcix_bdg_stat &
			    pcix_err_tbl[i].reg_bit)) {
				(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
				    PCIX_ERROR_SUBCLASS,
				    pcix_err_tbl[i].err_class);
				ddi_fm_ereport_post(dip, buf, derr->fme_ena,
				    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
				    PCIX_SEC_STATUS, DATA_TYPE_UINT16,
				    pcix_bdg_regs->pcix_bdg_sec_stat,
				    PCIX_BDG_STAT, DATA_TYPE_UINT32,
				    pcix_bdg_regs->pcix_bdg_stat, NULL);
				PCI_FM_SEV_INC(pcix_err_tbl[i].flags);
			}
		}
	}

	if (pcix_bdg_regs->pcix_bdg_vflags & PCIX_BDG_SEC_STATUS_VALID) {
		for (i = 0; pcix_sec_err_tbl[i].err_class != NULL; i++) {
			if ((pcix_bdg_regs->pcix_bdg_sec_stat &
			    pcix_sec_err_tbl[i].reg_bit)) {
				(void) snprintf(buf, FM_MAX_CLASS, "%s.%s%s",
				    PCIX_ERROR_SUBCLASS,
				    PCIX_SEC_ERROR_SUBCLASS,
				    pcix_sec_err_tbl[i].err_class);
				ddi_fm_ereport_post(dip, buf, derr->fme_ena,
				    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
				    PCIX_SEC_STATUS, DATA_TYPE_UINT16,
				    pcix_bdg_regs->pcix_bdg_sec_stat,
				    PCIX_BDG_STAT, DATA_TYPE_UINT32,
				    pcix_bdg_regs->pcix_bdg_stat, NULL);
				PCI_FM_SEV_INC(pcix_sec_err_tbl[i].flags);
			}
		}
	}

	/* Log/Handle ECC errors */
	if (PCIX_ECC_VER_CHECK(pcix_bdg_regs->pcix_bdg_ver)) {
		int ret;

		ret = pcix_ecc_error_report(dip, derr, erpt_p,
		    (void *)pcix_bdg_regs);
		PCI_FM_SEV_INC(ret);
	}
	return (fatal ? DDI_FM_FATAL : (nonfatal ? DDI_FM_NONFATAL :
	    (unknown ? DDI_FM_UNKNOWN : DDI_FM_OK)));
}

static int
pcix_error_report(dev_info_t *dip, ddi_fm_error_t *derr, pci_erpt_t *erpt_p)
{
	pcix_error_regs_t *pcix_regs = (pcix_error_regs_t *)erpt_p->pe_regs;
	int fatal = 0;
	int nonfatal = 0;
	int unknown = 0;
	int ok = 0;
	char buf[FM_MAX_CLASS];
	int i;

	if (pcix_regs->pcix_vflags & PCIX_ERR_STATUS_VALID) {
		for (i = 0; pcix_err_tbl[i].err_class != NULL; i++) {
			if (!(pcix_regs->pcix_status & pcix_err_tbl[i].reg_bit))
				continue;

			(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
			    PCIX_ERROR_SUBCLASS, pcix_err_tbl[i].err_class);
			ddi_fm_ereport_post(dip, buf, derr->fme_ena,
			    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
			    PCIX_COMMAND, DATA_TYPE_UINT16,
			    pcix_regs->pcix_command, PCIX_STATUS,
			    DATA_TYPE_UINT32, pcix_regs->pcix_status,
			    NULL);
			PCI_FM_SEV_INC(pcix_err_tbl[i].flags);
		}
	}
	/* Log/Handle ECC errors */
	if (PCIX_ECC_VER_CHECK(pcix_regs->pcix_ver)) {
		int ret = pcix_ecc_error_report(dip, derr, erpt_p,
		    (void *)pcix_regs);
		PCI_FM_SEV_INC(ret);
	}

	return (fatal ? DDI_FM_FATAL : (nonfatal ? DDI_FM_NONFATAL :
	    (unknown ? DDI_FM_UNKNOWN : DDI_FM_OK)));
}

static int
pcie_rc_error_report(dev_info_t *dip, ddi_fm_error_t *derr, pci_erpt_t *erpt_p,
    void *pe_regs)
{
	pcie_adv_error_regs_t *pcie_adv_regs = (pcie_adv_error_regs_t *)pe_regs;
	int fatal = 0;
	int nonfatal = 0;
	int unknown = 0;
	char buf[FM_MAX_CLASS];

	if (pcie_adv_regs->pcie_adv_vflags & PCIE_RC_ERR_STATUS_VALID) {
		pcie_adv_rc_error_regs_t *pcie_rc_regs =
		    pcie_adv_regs->pcie_adv_rc_regs;
		int ce, ue, mult_ce, mult_ue, first_ue_fatal, nfe, fe;

		ce = pcie_rc_regs->pcie_rc_err_status &
		    PCIE_AER_RE_STS_CE_RCVD;
		ue = pcie_rc_regs->pcie_rc_err_status &
		    PCIE_AER_RE_STS_FE_NFE_RCVD;
		mult_ce = pcie_rc_regs->pcie_rc_err_status &
		    PCIE_AER_RE_STS_MUL_CE_RCVD;
		mult_ue = pcie_rc_regs->pcie_rc_err_status &
		    PCIE_AER_RE_STS_MUL_FE_NFE_RCVD;
		first_ue_fatal = pcie_rc_regs->pcie_rc_err_status &
		    PCIE_AER_RE_STS_FIRST_UC_FATAL;
		nfe = pcie_rc_regs->pcie_rc_err_status &
		    PCIE_AER_RE_STS_NFE_MSGS_RCVD;
		fe = pcie_rc_regs->pcie_rc_err_status &
		    PCIE_AER_RE_STS_FE_MSGS_RCVD;
		/*
		 * log fatal/nonfatal/corrected messages
		 * recieved by root complex
		 */
		if (ue && fe)
			fatal++;

		if (fe && first_ue_fatal) {
			(void) snprintf(buf, FM_MAX_CLASS,
			    "%s.%s", PCIEX_ERROR_SUBCLASS, PCIEX_RC_FE_MSG);
			pcie_ereport_post(dip, derr, erpt_p, buf,
			    PCIEX_TYPE_RC_UE_MSG);
		}
		if (nfe && !first_ue_fatal) {
			(void) snprintf(buf, FM_MAX_CLASS,
			    "%s.%s", PCIEX_ERROR_SUBCLASS, PCIEX_RC_NFE_MSG);
			pcie_ereport_post(dip, derr, erpt_p, buf,
			    PCIEX_TYPE_RC_UE_MSG);
		}
		if (ce) {
			(void) snprintf(buf, FM_MAX_CLASS,
			    "%s.%s", PCIEX_ERROR_SUBCLASS, PCIEX_RC_CE_MSG);
			pcie_ereport_post(dip, derr, erpt_p, buf,
			    PCIEX_TYPE_RC_CE_MSG);
		}
		if (mult_ce) {
			(void) snprintf(buf, FM_MAX_CLASS,
			    "%s.%s", PCIEX_ERROR_SUBCLASS, PCIEX_RC_MCE_MSG);
			pcie_ereport_post(dip, derr, erpt_p, buf,
			    PCIEX_TYPE_RC_MULT_MSG);
		}
		if (mult_ue) {
			(void) snprintf(buf, FM_MAX_CLASS,
			    "%s.%s", PCIEX_ERROR_SUBCLASS, PCIEX_RC_MUE_MSG);
			pcie_ereport_post(dip, derr, erpt_p, buf,
			    PCIEX_TYPE_RC_MULT_MSG);
		}
	}
	return (fatal ? DDI_FM_FATAL : (nonfatal ? DDI_FM_NONFATAL :
	    (unknown ? DDI_FM_UNKNOWN : DDI_FM_OK)));
}

static int
pcie_error_report(dev_info_t *dip, ddi_fm_error_t *derr, pci_erpt_t *erpt_p)
{
	int fatal = 0;
	int nonfatal = 0;
	int unknown = 0;
	int ok = 0;
	int type;
	char buf[FM_MAX_CLASS];
	int i;
	pcie_error_regs_t *pcie_regs = (pcie_error_regs_t *)erpt_p->pe_regs;
	pcie_adv_error_regs_t *pcie_adv_regs;
	pcie_adv_bdg_error_regs_t *pcie_bdg_regs;

	if ((erpt_p->pe_dflags & PCI_BRIDGE_DEV) &&
	    (erpt_p->pe_dflags & PCIX_DEV)) {
		int ret = pcix_bdg_error_report(dip, derr, erpt_p,
		    (void *)pcie_regs->pcix_bdg_regs);
		PCI_FM_SEV_INC(ret);
	}

	if (!(erpt_p->pe_dflags & PCIEX_ADV_DEV)) {
		if (!(pcie_regs->pcie_vflags & PCIE_ERR_STATUS_VALID))
			goto done;
#if !defined(__sparc)
		/*
		 * On x86 ignore UR on non-RBER leaf devices, pciex-pci
		 * bridges and switches.
		 */
		if ((pcie_regs->pcie_err_status & PCIE_DEVSTS_UR_DETECTED) &&
		    !(pcie_regs->pcie_err_status & PCIE_DEVSTS_FE_DETECTED) &&
		    ((erpt_p->pe_dflags & (PCIEX_2PCI_DEV|PCIEX_SWITCH_DEV)) ||
		    !(erpt_p->pe_dflags & PCI_BRIDGE_DEV)) &&
		    !(pcie_regs->pcie_dev_cap & PCIE_DEVCAP_ROLE_BASED_ERR_REP))
			goto done;
#endif
		for (i = 0; pciex_nadv_err_tbl[i].err_class != NULL; i++) {
			if (!(pcie_regs->pcie_err_status &
			    pciex_nadv_err_tbl[i].reg_bit))
				continue;

			(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
			    PCIEX_ERROR_SUBCLASS,
			    pciex_nadv_err_tbl[i].err_class);
			pcie_ereport_post(dip, derr, erpt_p, buf,
			    PCIEX_TYPE_GEN);
			PCI_FM_SEV_INC(pciex_nadv_err_tbl[i].flags);
		}
		goto done;
	}

	pcie_adv_regs = pcie_regs->pcie_adv_regs;

	/*
	 * Log PCI Express uncorrectable errors
	 */
	if (pcie_adv_regs->pcie_adv_vflags & PCIE_UE_STATUS_VALID) {
		for (i = 0; pciex_ue_err_tbl[i].err_class != NULL; i++) {
			if (!(pcie_adv_regs->pcie_ue_status &
			    pciex_ue_err_tbl[i].reg_bit))
				continue;

			(void) snprintf(buf, FM_MAX_CLASS,
			    "%s.%s", PCIEX_ERROR_SUBCLASS,
			    pciex_ue_err_tbl[i].err_class);

			/*
			 * First check for advisary nonfatal conditions
			 * - hardware endpoint successfully retrying a cto
			 * - hardware endpoint receiving poisoned tlp and
			 *   dealing with it itself (but not if root complex)
			 * If the device has declared these as correctable
			 * errors then treat them as such.
			 */
			if ((pciex_ue_err_tbl[i].reg_bit == PCIE_AER_UCE_TO ||
			    (pciex_ue_err_tbl[i].reg_bit == PCIE_AER_UCE_PTLP &&
			    !(erpt_p->pe_dflags & PCIEX_RC_DEV))) &&
			    (pcie_regs->pcie_err_status &
			    PCIE_DEVSTS_CE_DETECTED) &&
			    !(pcie_regs->pcie_err_status &
			    PCIE_DEVSTS_NFE_DETECTED)) {
				pcie_ereport_post(dip, derr, erpt_p, buf,
				    PCIEX_TYPE_UE);
				continue;
			}

#if !defined(__sparc)
			/*
			 * On x86 for leaf devices and pciex-pci bridges,
			 * ignore UR on non-RBER devices or on RBER devices when
			 * advisory nonfatal.
			 */
			if (pciex_ue_err_tbl[i].reg_bit == PCIE_AER_UCE_UR &&
			    ((erpt_p->pe_dflags &
			    (PCIEX_2PCI_DEV|PCIEX_SWITCH_DEV)) ||
			    !(erpt_p->pe_dflags & PCI_BRIDGE_DEV))) {
				if (!(pcie_regs->pcie_dev_cap &
				    PCIE_DEVCAP_ROLE_BASED_ERR_REP))
					continue;
				if (!(pcie_regs->pcie_err_status &
				    PCIE_DEVSTS_NFE_DETECTED))
					continue;
			}
#endif
			pcie_adv_regs->pcie_adv_bdf = 0;
			/*
			 * Now try and look up handle if
			 * - error bit is among PCIE_AER_UCE_LOG_BITS, and
			 * - no other PCIE_AER_UCE_LOG_BITS are set, and
			 * - error bit is not masked, and
			 * - flag is DDI_FM_UNKNOWN
			 */
			if ((pcie_adv_regs->pcie_ue_status &
			    pcie_aer_uce_log_bits) ==
			    pciex_ue_err_tbl[i].reg_bit &&
			    !(pciex_ue_err_tbl[i].reg_bit &
			    pcie_adv_regs->pcie_ue_mask) &&
			    pciex_ue_err_tbl[i].flags == DDI_FM_UNKNOWN)
				pcie_check_addr(dip, derr, erpt_p);

			PCI_FM_SEV_INC(pciex_ue_err_tbl[i].flags);
			pcie_ereport_post(dip, derr, erpt_p, buf,
			    PCIEX_TYPE_UE);
		}
	}

	/*
	 * Log PCI Express correctable errors
	 */
	if (pcie_adv_regs->pcie_adv_vflags & PCIE_CE_STATUS_VALID) {
		for (i = 0; pciex_ce_err_tbl[i].err_class != NULL; i++) {
			if (!(pcie_adv_regs->pcie_ce_status &
			    pciex_ce_err_tbl[i].reg_bit))
				continue;

			(void) snprintf(buf, FM_MAX_CLASS,
			    "%s.%s", PCIEX_ERROR_SUBCLASS,
			    pciex_ce_err_tbl[i].err_class);
			pcie_ereport_post(dip, derr, erpt_p, buf,
			    PCIEX_TYPE_CE);
		}
	}

	if (!(erpt_p->pe_dflags & PCI_BRIDGE_DEV))
		goto done;

	if (erpt_p->pe_dflags & PCIEX_RC_DEV) {
		int ret = pcie_rc_error_report(dip, derr, erpt_p,
		    (void *)pcie_adv_regs);
		PCI_FM_SEV_INC(ret);
	}

	if (!((erpt_p->pe_dflags & PCIEX_2PCI_DEV) &&
	    (pcie_adv_regs->pcie_adv_vflags & PCIE_SUE_STATUS_VALID)))
		goto done;

	pcie_bdg_regs = pcie_adv_regs->pcie_adv_bdg_regs;

	for (i = 0; pcie_sue_err_tbl[i].err_class != NULL; i++) {
		if ((pcie_bdg_regs->pcie_sue_status &
		    pcie_sue_err_tbl[i].reg_bit)) {
			(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
			    PCIEX_ERROR_SUBCLASS,
			    pcie_sue_err_tbl[i].err_class);

			if ((pcie_bdg_regs->pcie_sue_status &
			    pcie_aer_suce_log_bits) !=
			    pcie_sue_err_tbl[i].reg_bit ||
			    pcie_sue_err_tbl[i].flags != DDI_FM_UNKNOWN) {
				ddi_fm_ereport_post(dip, buf, derr->fme_ena,
				    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
				    PCIEX_SEC_UE_STATUS, DATA_TYPE_UINT32,
				    pcie_bdg_regs->pcie_sue_status,
#ifdef DEBUG
				    PCIEX_SUE_HDR0, DATA_TYPE_UINT32,
				    pcie_bdg_regs->pcie_sue_hdr0,
				    PCIEX_SUE_HDR1, DATA_TYPE_UINT32,
				    pcie_bdg_regs->pcie_sue_hdr[0],
				    PCIEX_SUE_HDR2, DATA_TYPE_UINT32,
				    pcie_bdg_regs->pcie_sue_hdr[1],
				    PCIEX_SUE_HDR3, DATA_TYPE_UINT32,
				    pcie_bdg_regs->pcie_sue_hdr[2],
#endif
				    NULL);
			} else {
				pcie_adv_regs->pcie_adv_bdf = 0;
				switch (pcie_sue_err_tbl[i].reg_bit) {
				case PCIE_AER_SUCE_RCVD_TA:
				case PCIE_AER_SUCE_RCVD_MA:
				case PCIE_AER_SUCE_USC_ERR:
					type = ACC_HANDLE;
					break;
				case PCIE_AER_SUCE_TA_ON_SC:
				case PCIE_AER_SUCE_MA_ON_SC:
					type = DMA_HANDLE;
					break;
				case PCIE_AER_SUCE_UC_DATA_ERR:
				case PCIE_AER_SUCE_PERR_ASSERT:
					if (erpt_p->pe_pci_regs->pci_bdg_regs->
					    pci_bdg_sec_stat &
					    PCI_STAT_S_PERROR)
						type = ACC_HANDLE;
					else
						type = DMA_HANDLE;
					break;
				}
				pcie_pci_check_addr(dip, derr, erpt_p, type);
				ddi_fm_ereport_post(dip, buf, derr->fme_ena,
				    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
				    PCIEX_SEC_UE_STATUS, DATA_TYPE_UINT32,
				    pcie_bdg_regs->pcie_sue_status,
				    PCIEX_SRC_ID, DATA_TYPE_UINT16,
				    pcie_adv_regs->pcie_adv_bdf,
				    PCIEX_SRC_VALID, DATA_TYPE_BOOLEAN_VALUE,
				    (pcie_adv_regs->pcie_adv_bdf != NULL) ?
				    1 : NULL,
#ifdef DEBUG
				    PCIEX_SUE_HDR0, DATA_TYPE_UINT32,
				    pcie_bdg_regs->pcie_sue_hdr0,
				    PCIEX_SUE_HDR1, DATA_TYPE_UINT32,
				    pcie_bdg_regs->pcie_sue_hdr[0],
				    PCIEX_SUE_HDR2, DATA_TYPE_UINT32,
				    pcie_bdg_regs->pcie_sue_hdr[1],
				    PCIEX_SUE_HDR3, DATA_TYPE_UINT32,
				    pcie_bdg_regs->pcie_sue_hdr[2],
#endif
				    NULL);
			}
			PCI_FM_SEV_INC(pcie_sue_err_tbl[i].flags);
		}
	}
done:
	return (fatal ? DDI_FM_FATAL : (nonfatal ? DDI_FM_NONFATAL :
	    (unknown ? DDI_FM_UNKNOWN : DDI_FM_OK)));
}

static void
pci_error_report(dev_info_t *dip, ddi_fm_error_t *derr, pci_erpt_t *erpt_p)
{
	int fatal = 0;
	int nonfatal = 0;
	int unknown = 0;
	int ok = 0;
	char buf[FM_MAX_CLASS];
	int i;

	if (derr->fme_flag == DDI_FM_ERR_UNEXPECTED) {
		/*
		 * Log generic PCI errors.
		 */
		for (i = 0; pci_err_tbl[i].err_class != NULL; i++) {
			if (!(erpt_p->pe_pci_regs->pci_err_status &
			    pci_err_tbl[i].reg_bit) ||
			    !(erpt_p->pe_pci_regs->pci_vflags &
			    PCI_ERR_STATUS_VALID))
				continue;
			/*
			 * Generate an ereport for this error bit.
			 */
			(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
			    PCI_ERROR_SUBCLASS, pci_err_tbl[i].err_class);
			ddi_fm_ereport_post(dip, buf, derr->fme_ena,
			    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
			    PCI_CONFIG_STATUS, DATA_TYPE_UINT16,
			    erpt_p->pe_pci_regs->pci_err_status,
			    PCI_CONFIG_COMMAND, DATA_TYPE_UINT16,
			    erpt_p->pe_pci_regs->pci_cfg_comm, NULL);

			/*
			 * The meaning of SERR is different for PCIEX (just
			 * implies a message has been sent) so we don't want to
			 * treat that one as fatal.
			 */
			if ((erpt_p->pe_dflags & PCIEX_DEV) &&
			    pci_err_tbl[i].reg_bit == PCI_STAT_S_SYSERR) {
				unknown++;
			} else {
				PCI_FM_SEV_INC(pci_err_tbl[i].flags);
			}
		}
		if (erpt_p->pe_dflags & PCIEX_DEV) {
			int ret = pcie_error_report(dip, derr, erpt_p);
			PCI_FM_SEV_INC(ret);
		} else if (erpt_p->pe_dflags & PCIX_DEV) {
			if (erpt_p->pe_dflags & PCI_BRIDGE_DEV) {
				int ret = pcix_bdg_error_report(dip, derr,
				    erpt_p, erpt_p->pe_regs);
				PCI_FM_SEV_INC(ret);
			} else {
				int ret = pcix_error_report(dip, derr, erpt_p);
				PCI_FM_SEV_INC(ret);
			}
		}
	}

	if ((erpt_p->pe_dflags & PCI_BRIDGE_DEV)) {
		int ret = pci_bdg_error_report(dip, derr, erpt_p);
		PCI_FM_SEV_INC(ret);
	}

	if (derr->fme_flag == DDI_FM_ERR_UNEXPECTED) {
		pci_fme_bus_specific_t *pci_fme_bsp;
		int ret = DDI_FM_UNKNOWN;

		pci_fme_bsp = (pci_fme_bus_specific_t *)derr->fme_bus_specific;
		if (pci_fme_bsp->pci_bs_flags & PCI_BS_ADDR_VALID) {
			ret = ndi_fmc_entry_error(dip,
			    pci_fme_bsp->pci_bs_type, derr,
			    (void *)&pci_fme_bsp->pci_bs_addr);
			PCI_FM_SEV_INC(ret);
		}
		/*
		 * If we didn't find the handle using an addr, try using bdf.
		 * Note we don't do this where the bdf is for a
		 * device behind a pciex/pci bridge as the bridge may have
		 * fabricated the bdf.
		 */
		if (ret == DDI_FM_UNKNOWN &&
		    (pci_fme_bsp->pci_bs_flags & PCI_BS_BDF_VALID) &&
		    pci_fme_bsp->pci_bs_bdf == erpt_p->pe_bdf &&
		    (erpt_p->pe_dflags & PCIEX_DEV) &&
		    !(erpt_p->pe_dflags & PCIEX_2PCI_DEV)) {
			ret = ndi_fmc_entry_error_all(dip,
			    pci_fme_bsp->pci_bs_type, derr);
			PCI_FM_SEV_INC(ret);
		}
	}

	derr->fme_status = (fatal ? DDI_FM_FATAL : (nonfatal ? DDI_FM_NONFATAL :
	    (unknown ? DDI_FM_UNKNOWN : DDI_FM_OK)));
}

void
pci_ereport_post(dev_info_t *dip, ddi_fm_error_t *derr, uint16_t *xx_status)
{
	struct i_ddi_fmhdl *fmhdl;
	pci_erpt_t *erpt_p;
	ddi_fm_error_t de;
	pci_fme_bus_specific_t pci_fme_bs;

	fmhdl = DEVI(dip)->devi_fmhdl;
	if (!DDI_FM_EREPORT_CAP(ddi_fm_capable(dip)) &&
	    !DDI_FM_ERRCB_CAP(ddi_fm_capable(dip))) {
		i_ddi_drv_ereport_post(dip, DVR_EFMCAP, NULL, DDI_NOSLEEP);
		return;
	}

	/*
	 * copy in the ddi_fm_error_t structure in case it's VER0
	 */
	de.fme_version = derr->fme_version;
	de.fme_status = derr->fme_status;
	de.fme_flag = derr->fme_flag;
	de.fme_ena = derr->fme_ena;
	de.fme_acc_handle = derr->fme_acc_handle;
	de.fme_dma_handle = derr->fme_dma_handle;
	de.fme_bus_specific = derr->fme_bus_specific;
	if (derr->fme_version >= DDI_FME_VER1)
		de.fme_bus_type = derr->fme_bus_type;
	else
		de.fme_bus_type = DDI_FME_BUS_TYPE_DFLT;
	if (de.fme_bus_type == DDI_FME_BUS_TYPE_DFLT) {
		/*
		 * if this is the first pci device we've found convert
		 * fme_bus_specific to DDI_FME_BUS_TYPE_PCI
		 */
		bzero(&pci_fme_bs, sizeof (pci_fme_bs));
		if (de.fme_bus_specific) {
			/*
			 * the cpu passed us an addr - this can be used to look
			 * up an access handle
			 */
			pci_fme_bs.pci_bs_addr = (uintptr_t)de.fme_bus_specific;
			pci_fme_bs.pci_bs_type = ACC_HANDLE;
			pci_fme_bs.pci_bs_flags |= PCI_BS_ADDR_VALID;
		}
		de.fme_bus_specific = (void *)&pci_fme_bs;
		de.fme_bus_type = DDI_FME_BUS_TYPE_PCI;
	}

	ASSERT(fmhdl);

	if (de.fme_ena == NULL)
		de.fme_ena = fm_ena_generate(0, FM_ENA_FMT1);

	erpt_p = (pci_erpt_t *)fmhdl->fh_bus_specific;
	if (erpt_p == NULL)
		return;

	pci_regs_gather(dip, erpt_p, de.fme_flag);
	pci_error_report(dip, &de, erpt_p);
	pci_regs_clear(erpt_p);

	derr->fme_status = de.fme_status;
	derr->fme_ena = de.fme_ena;
	derr->fme_acc_handle = de.fme_acc_handle;
	derr->fme_dma_handle = de.fme_dma_handle;
	if (xx_status != NULL)
		*xx_status = erpt_p->pe_pci_regs->pci_err_status;
}

/*
 * private version of walk_devs() that can be used during panic. No
 * sleeping or locking required.
 */
static int
pci_fm_walk_devs(dev_info_t *dip, int (*f)(dev_info_t *, void *), void *arg)
{
	while (dip) {
		switch ((*f)(dip, arg)) {
		case DDI_WALK_TERMINATE:
			return (DDI_WALK_TERMINATE);
		case DDI_WALK_CONTINUE:
			if (pci_fm_walk_devs(ddi_get_child(dip), f,
			    arg) == DDI_WALK_TERMINATE)
				return (DDI_WALK_TERMINATE);
			break;
		case DDI_WALK_PRUNECHILD:
			break;
		}
		dip = ddi_get_next_sibling(dip);
	}
	return (DDI_WALK_CONTINUE);
}

/*
 * need special version of ddi_fm_ereport_post() as the leaf driver may
 * not be hardened.
 */
static void
pci_fm_ereport_post(dev_info_t *dip, const char *error_class, uint64_t ena,
    uint8_t version, ...)
{
	char *name;
	char device_path[MAXPATHLEN];
	char ddi_error_class[FM_MAX_CLASS];
	nvlist_t *ereport, *detector;
	nv_alloc_t *nva;
	errorq_elem_t *eqep;
	va_list ap;

	if (panicstr) {
		eqep = errorq_reserve(ereport_errorq);
		if (eqep == NULL)
			return;
		ereport = errorq_elem_nvl(ereport_errorq, eqep);
		nva = errorq_elem_nva(ereport_errorq, eqep);
		detector = fm_nvlist_create(nva);
	} else {
		ereport = fm_nvlist_create(NULL);
		detector = fm_nvlist_create(NULL);
	}

	(void) ddi_pathname(dip, device_path);
	fm_fmri_dev_set(detector, FM_DEV_SCHEME_VERSION, NULL,
	    device_path, NULL);
	(void) snprintf(ddi_error_class, FM_MAX_CLASS, "%s.%s",
	    DDI_IO_CLASS, error_class);
	fm_ereport_set(ereport, version, ddi_error_class, ena, detector, NULL);

	va_start(ap, version);
	name = va_arg(ap, char *);
	(void) i_fm_payload_set(ereport, name, ap);
	va_end(ap);

	if (panicstr) {
		errorq_commit(ereport_errorq, eqep, ERRORQ_SYNC);
	} else {
		(void) fm_ereport_post(ereport, EVCH_TRYHARD);
		fm_nvlist_destroy(ereport, FM_NVA_FREE);
		fm_nvlist_destroy(detector, FM_NVA_FREE);
	}
}

static int
pci_check_regs(dev_info_t *dip, void *arg)
{
	int reglen;
	int rn;
	int totreg;
	pci_regspec_t *drv_regp;
	pci_target_err_t *tgt_err = (pci_target_err_t *)arg;

	if (tgt_err->tgt_pci_space == PCI_REG_ADDR_G(PCI_ADDR_CONFIG)) {
		/*
		 * for config space, we need to check if the given address
		 * is a valid config space address for this device - based
		 * on pci_phys_hi of the config space entry in reg property.
		 */
		if (ddi_getlongprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
		    "reg", (caddr_t)&drv_regp, &reglen) != DDI_SUCCESS)
			return (DDI_WALK_CONTINUE);

		totreg = reglen / sizeof (pci_regspec_t);
		for (rn = 0; rn < totreg; rn++) {
			if (tgt_err->tgt_pci_space ==
			    PCI_REG_ADDR_G(drv_regp[rn].pci_phys_hi) &&
			    (tgt_err->tgt_pci_addr & (PCI_REG_BUS_M |
			    PCI_REG_DEV_M | PCI_REG_FUNC_M)) ==
			    (drv_regp[rn].pci_phys_hi & (PCI_REG_BUS_M |
			    PCI_REG_DEV_M | PCI_REG_FUNC_M))) {
				tgt_err->tgt_dip = dip;
				kmem_free(drv_regp, reglen);
				return (DDI_WALK_TERMINATE);
			}
		}
		kmem_free(drv_regp, reglen);
	} else {
		/*
		 * for non config space, need to check reg to look
		 * for any non-relocable mapping, otherwise check
		 * assigned-addresses.
		 */
		if (ddi_getlongprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
		    "reg", (caddr_t)&drv_regp, &reglen) != DDI_SUCCESS)
			return (DDI_WALK_CONTINUE);

		totreg = reglen / sizeof (pci_regspec_t);
		for (rn = 0; rn < totreg; rn++) {
			if ((drv_regp[rn].pci_phys_hi & PCI_RELOCAT_B) &&
			    (tgt_err->tgt_pci_space == TGT_PCI_SPACE_UNKNOWN ||
			    tgt_err->tgt_pci_space ==
			    PCI_REG_ADDR_G(drv_regp[rn].pci_phys_hi)) &&
			    (tgt_err->tgt_pci_addr >=
			    (uint64_t)drv_regp[rn].pci_phys_low +
			    ((uint64_t)drv_regp[rn].pci_phys_mid << 32)) &&
			    (tgt_err->tgt_pci_addr <
			    (uint64_t)drv_regp[rn].pci_phys_low +
			    ((uint64_t)drv_regp[rn].pci_phys_mid << 32) +
			    (uint64_t)drv_regp[rn].pci_size_low +
			    ((uint64_t)drv_regp[rn].pci_size_hi << 32))) {
				tgt_err->tgt_dip = dip;
				kmem_free(drv_regp, reglen);
				return (DDI_WALK_TERMINATE);
			}
		}
		kmem_free(drv_regp, reglen);

		if (ddi_getlongprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
		    "assigned-addresses", (caddr_t)&drv_regp, &reglen) !=
		    DDI_SUCCESS)
			return (DDI_WALK_CONTINUE);

		totreg = reglen / sizeof (pci_regspec_t);
		for (rn = 0; rn < totreg; rn++) {
			if ((tgt_err->tgt_pci_space == TGT_PCI_SPACE_UNKNOWN ||
			    tgt_err->tgt_pci_space ==
			    PCI_REG_ADDR_G(drv_regp[rn].pci_phys_hi)) &&
			    (tgt_err->tgt_pci_addr >=
			    (uint64_t)drv_regp[rn].pci_phys_low +
			    ((uint64_t)drv_regp[rn].pci_phys_mid << 32)) &&
			    (tgt_err->tgt_pci_addr <
			    (uint64_t)drv_regp[rn].pci_phys_low +
			    ((uint64_t)drv_regp[rn].pci_phys_mid << 32) +
			    (uint64_t)drv_regp[rn].pci_size_low +
			    ((uint64_t)drv_regp[rn].pci_size_hi << 32))) {
				tgt_err->tgt_dip = dip;
				kmem_free(drv_regp, reglen);
				return (DDI_WALK_TERMINATE);
			}
		}
		kmem_free(drv_regp, reglen);
	}
	return (DDI_WALK_CONTINUE);
}

/*
 * impl_fix_ranges - fixes the config space entry of the "ranges"
 * property on psycho+ platforms.  (if changing this function please make sure
 * to change the pci_fix_ranges function in pcipsy.c)
 */
/*ARGSUSED*/
static void
pci_fix_ranges(dev_info_t *dip, pci_ranges_t *pci_ranges, int nrange)
{
#if defined(__sparc)
	char *name = ddi_binding_name(dip);

	if ((strcmp(name, "pci108e,8000") == 0) ||
	    (strcmp(name, "pci108e,a000") == 0) ||
	    (strcmp(name, "pci108e,a001") == 0)) {
		int i;
		for (i = 0; i < nrange; i++, pci_ranges++)
			if ((pci_ranges->child_high & PCI_REG_ADDR_M) ==
			    PCI_ADDR_CONFIG)
				pci_ranges->parent_low |=
				    pci_ranges->child_high;
	}
#endif
}

static int
pci_check_ranges(dev_info_t *dip, void *arg)
{
	uint64_t range_parent_begin;
	uint64_t range_parent_size;
	uint64_t range_parent_end;
	uint32_t space_type;
	uint32_t bus_num;
	uint32_t range_offset;
	pci_ranges_t *pci_ranges, *rangep;
	pci_bus_range_t *pci_bus_rangep;
	int pci_ranges_length;
	int nrange;
	pci_target_err_t *tgt_err = (pci_target_err_t *)arg;
	int i, size;
	if (strcmp(ddi_node_name(dip), "pci") != 0 &&
	    strcmp(ddi_node_name(dip), "pciex") != 0)
		return (DDI_WALK_CONTINUE);

	/*
	 * Get the ranges property. Note we only look at the top level pci
	 * node (hostbridge) which has a ranges property of type pci_ranges_t
	 * not at pci-pci bridges.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "ranges",
	    (caddr_t)&pci_ranges, &pci_ranges_length) != DDI_SUCCESS) {
		/*
		 * no ranges property - no translation needed
		 */
		tgt_err->tgt_pci_addr = tgt_err->tgt_err_addr;
		tgt_err->tgt_pci_space = TGT_PCI_SPACE_UNKNOWN;
		if (panicstr)
			(void) pci_fm_walk_devs(ddi_get_child(dip),
			    pci_check_regs, (void *)tgt_err);
		else {
			int circ = 0;
			ndi_devi_enter(dip, &circ);
			ddi_walk_devs(ddi_get_child(dip), pci_check_regs,
			    (void *)tgt_err);
			ndi_devi_exit(dip, circ);
		}
		if (tgt_err->tgt_dip != NULL)
			return (DDI_WALK_TERMINATE);
		return (DDI_WALK_PRUNECHILD);
	}
	nrange = pci_ranges_length / sizeof (pci_ranges_t);
	rangep = pci_ranges;

	/* Need to fix the pci ranges property for psycho based systems */
	pci_fix_ranges(dip, pci_ranges, nrange);

	for (i = 0; i < nrange; i++, rangep++) {
		range_parent_begin = ((uint64_t)rangep->parent_high << 32) +
		    rangep->parent_low;
		range_parent_size = ((uint64_t)rangep->size_high << 32) +
		    rangep->size_low;
		range_parent_end = range_parent_begin + range_parent_size - 1;

		if ((tgt_err->tgt_err_addr < range_parent_begin) ||
		    (tgt_err->tgt_err_addr > range_parent_end)) {
			/* Not in range */
			continue;
		}
		space_type = PCI_REG_ADDR_G(rangep->child_high);
		if (space_type == PCI_REG_ADDR_G(PCI_ADDR_CONFIG)) {
			/* Config space address - check bus range */
			range_offset = tgt_err->tgt_err_addr -
			    range_parent_begin;
			bus_num = PCI_REG_BUS_G(range_offset);
			if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
			    DDI_PROP_DONTPASS, "bus-range",
			    (caddr_t)&pci_bus_rangep, &size) != DDI_SUCCESS) {
				continue;
			}
			if ((bus_num < pci_bus_rangep->lo) ||
			    (bus_num > pci_bus_rangep->hi)) {
				/*
				 * Bus number not appropriate for this
				 * pci nexus.
				 */
				kmem_free(pci_bus_rangep, size);
				continue;
			}
			kmem_free(pci_bus_rangep, size);
		}

		/* We have a match if we get here - compute pci address */
		tgt_err->tgt_pci_addr = tgt_err->tgt_err_addr -
		    range_parent_begin;
		tgt_err->tgt_pci_addr += (((uint64_t)rangep->child_mid << 32) +
		    rangep->child_low);
		tgt_err->tgt_pci_space = space_type;
		if (panicstr)
			(void) pci_fm_walk_devs(ddi_get_child(dip),
			    pci_check_regs, (void *)tgt_err);
		else {
			int circ = 0;
			ndi_devi_enter(dip, &circ);
			ddi_walk_devs(ddi_get_child(dip), pci_check_regs,
			    (void *)tgt_err);
			ndi_devi_exit(dip, circ);
		}
		if (tgt_err->tgt_dip != NULL) {
			kmem_free(pci_ranges, pci_ranges_length);
			return (DDI_WALK_TERMINATE);
		}
	}
	kmem_free(pci_ranges, pci_ranges_length);
	return (DDI_WALK_PRUNECHILD);
}

/*
 * Function used to drain pci_target_queue, either during panic or after softint
 * is generated, to generate target device ereports based on captured physical
 * addresses
 */
/*ARGSUSED*/
static void
pci_target_drain(void *private_p, pci_target_err_t *tgt_err)
{
	char buf[FM_MAX_CLASS];

	/*
	 * The following assumes that all pci_pci bridge devices
	 * are configured as transparant. Find the top-level pci
	 * nexus which has tgt_err_addr in one of its ranges, converting this
	 * to a pci address in the process. Then starting at this node do
	 * another tree walk to find a device with the pci address we've
	 * found within range of one of it's assigned-addresses properties.
	 */
	tgt_err->tgt_dip = NULL;
	if (panicstr)
		(void) pci_fm_walk_devs(ddi_root_node(), pci_check_ranges,
		    (void *)tgt_err);
	else
		ddi_walk_devs(ddi_root_node(), pci_check_ranges,
		    (void *)tgt_err);
	if (tgt_err->tgt_dip == NULL)
		return;

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", tgt_err->tgt_bridge_type,
	    tgt_err->tgt_err_class);
	pci_fm_ereport_post(tgt_err->tgt_dip, buf, tgt_err->tgt_err_ena, 0,
	    PCI_PA, DATA_TYPE_UINT64, tgt_err->tgt_err_addr, NULL);
}

void
pci_target_enqueue(uint64_t ena, char *class, char *bridge_type, uint64_t addr)
{
	pci_target_err_t tgt_err;

	tgt_err.tgt_err_ena = ena;
	tgt_err.tgt_err_class = class;
	tgt_err.tgt_bridge_type = bridge_type;
	tgt_err.tgt_err_addr = addr;
	errorq_dispatch(pci_target_queue, (void *)&tgt_err,
	    sizeof (pci_target_err_t), ERRORQ_ASYNC);
}

void
pci_targetq_init(void)
{
	/*
	 * PCI target errorq, to schedule async handling of generation of
	 * target device ereports based on captured physical address.
	 * The errorq is created here but destroyed when _fini is called
	 * for the pci module.
	 */
	if (pci_target_queue == NULL) {
		pci_target_queue = errorq_create("pci_target_queue",
		    (errorq_func_t)pci_target_drain, (void *)NULL,
		    TARGET_MAX_ERRS, sizeof (pci_target_err_t), FM_ERR_PIL,
		    ERRORQ_VITAL);
		if (pci_target_queue == NULL)
			panic("failed to create required system error queue");
	}
}
