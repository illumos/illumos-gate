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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/sunndi.h>
#include <sys/sysmacros.h>
#include <sys/ddifm_impl.h>
#include <sys/fm/util.h>
#include <sys/fm/protocol.h>
#include <sys/fm/io/pci.h>
#include <sys/fm/io/ddi.h>
#include <sys/pci.h>
#include <sys/pci_cap.h>
#include <sys/pci_impl.h>
#include <sys/epm.h>
#include <sys/pcifm.h>

#define	PCIX_ECC_VER_CHECK(x)	(((x) == PCI_PCIX_VER_1) ||\
				((x) == PCI_PCIX_VER_2))

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

	/* If pci-x device grab error registers */
	if (erpt_p->pe_dflags & PCIX_DEV)
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
pci_regs_clear(pci_erpt_t *erpt_p)
{
	/*
	 * Finally clear the error bits
	 */
	if (erpt_p->pe_dflags & PCIX_DEV)
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
	uint16_t pcix_cap_ptr = PCI_CAP_NEXT_PTR_NULL;
	ddi_acc_handle_t eh;
	int i;

	if (pci_config_setup(dip, &eh) == DDI_SUCCESS) {
		(void) PCI_CAP_LOCATE(eh, PCI_CAP_ID_PCIX, &pcix_cap_ptr);
		pci_config_teardown(&eh);
	}

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

	/* Initialize structures for PCI-X devices. */
	pcix_ereport_setup(dip, erpt_p);

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

	if (erpt_p->pe_dflags & PCIX_DEV)
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

			PCI_FM_SEV_INC(pci_err_tbl[i].flags);
		}
		if (erpt_p->pe_dflags & PCIX_DEV) {
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
		    pci_fme_bsp->pci_bs_bdf == erpt_p->pe_bdf) {
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

	/*
	 * On PCI Express systems, all error handling and ereport are done via
	 * the PCIe misc module.  This function is a no-op for PCIe Systems.  In
	 * order to tell if a system is a PCI or PCIe system, check that the
	 * bus_private_data exists.  If it exists, this is a PCIe system.
	 */
	if (ndi_get_bus_private(dip, B_TRUE)) {
		derr->fme_status = DDI_FM_OK;
		if (xx_status != NULL)
			*xx_status = 0x0;

		return;
	}

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
	    device_path, NULL, NULL);
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
