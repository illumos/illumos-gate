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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#include <strings.h>
#include <sys/fm/io/sun4_fire.h>

#include "fabric-xlate.h"

typedef struct fab_fire_tbl {
	const char	*err_class;
	uint32_t	fire_bit;	/* Fire error bit */
	uint16_t	pci_err_sts;	/* Equivalent PCI Error Status */
	uint16_t	pci_bdg_sts;	/* Equivalent PCI Bridge Status */
} fab_fire_tbl_t;

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
	NULL, 0, 0,
};

#define	FAB_FIRE_CE(fb, bit) \
	FAB_FIRE_PEC_BIT(fb), PCIE_AER_CE_ ## bit, 0, 0
static fab_fire_tbl_t fab_fire_pec_ce_tbl[] = {
	FAB_FIRE_CE(RTO,	REPLAY_TO),
	FAB_FIRE_CE(RNR,	REPLAY_ROLLOVER),
	FAB_FIRE_CE(BDP,	BAD_DLLP),
	FAB_FIRE_CE(BTP,	BAD_TLP),
	FAB_FIRE_CE(RE,		RECEIVER_ERR),
	NULL, 0, 0,
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
	NULL, 0, 0,
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
	NULL, 0, 0
};

/* ARGSUSED */
static void
fab_fire_to_data(fmd_hdl_t *hdl, nvlist_t *nvl, fab_data_t *data)
{
	data->nvl = nvl;

	/* Always Root Complex */
	data->dev_type = PCIE_PCIECAP_DEV_TYPE_ROOT;

	data->pcie_ue_sev = (PCIE_AER_UCE_DLP | PCIE_AER_UCE_SD |
	    PCIE_AER_UCE_FCP | PCIE_AER_UCE_RO | PCIE_AER_UCE_MTLP);
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

void
fab_xlate_fire_erpts(fmd_hdl_t *hdl, nvlist_t *nvl, const char *class)
{
	fab_data_t data = {0};

	fmd_hdl_debug(hdl, "Fire RC ereport received: %s\n", class);

	fab_fire_to_data(hdl, nvl, &data);

	if (fmd_nvl_class_match(hdl, nvl, "ereport.io.fire.pec.*")) {
		if (! fab_xlate_fire_ce(hdl, &data, nvl, class) &&
		    ! fab_xlate_fire_ue(hdl, &data, nvl, class))
			(void) fab_xlate_fire_oe(hdl, &data, nvl, class);
	} else if (fmd_nvl_class_match(hdl, nvl, "ereport.io.fire.dmc.*") ||
	    fmd_nvl_class_match(hdl, nvl, "ereport.io.n2.dmu.*"))
		(void) fab_xlate_fire_dmc(hdl, &data, nvl, class);

	fab_xlate_pcie_erpts(hdl, &data);
}
