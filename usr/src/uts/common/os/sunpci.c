/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sunndi.h>
#include <sys/ddifm_impl.h>
#include <sys/fm/util.h>
#include <sys/fm/protocol.h>
#include <sys/fm/io/pci.h>
#include <sys/fm/io/ddi.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <sys/pci_impl.h>
#include <sys/epm.h>


int
pci_config_setup(dev_info_t *dip, ddi_acc_handle_t *handle)
{
	caddr_t	cfgaddr;
	ddi_device_acc_attr_t attr;

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/* Check for fault management capabilities */
	if (DDI_FM_ACC_ERR_CAP(ddi_fm_capable(dip)))
		attr.devacc_attr_access = DDI_FLAGERR_ACC;

	return (ddi_regs_map_setup(dip, 0, &cfgaddr, 0, 0, &attr, handle));
}

void
pci_config_teardown(ddi_acc_handle_t *handle)
{
	ddi_regs_map_free(handle);
}

/*
 * pci_ereport_setup, pci_ereport_teardown, pci_ereport_post:
 * Interfaces to be used by ereport capable PCI device drivers to setup,
 * teardown, and post generic PCI error reports. This is to guarantee a
 * consistant error report model for all PCI devices. Please see
 * PSARC/2004/391.
 */

typedef struct pci_erpt {
	caddr_t pci_cfg_addr;		/* Config space address */
	ddi_acc_handle_t pci_cfg_hdl;	/* Config space access handle */
} pci_erpt_t;

pci_fm_err_t pci_err_tbl[] = {
	PCI_DET_PERR,	PCI_STAT_PERROR,	NULL,
	PCI_MDPE,	PCI_STAT_S_PERROR,	PCI_TARG_MDPE,
	PCI_SIG_SERR,	PCI_STAT_S_SYSERR,	NULL,
	PCI_MA,		PCI_STAT_R_MAST_AB,	PCI_TARG_MA,
	PCI_REC_TA,	PCI_STAT_R_TARG_AB,	PCI_TARG_REC_TA,
	PCI_SIG_TA,	PCI_STAT_S_TARG_AB,	NULL,
	NULL, NULL,
};

pci_fm_err_t pci_bdg_err_tbl[] = {
	PCI_DET_PERR,	PCI_STAT_PERROR,	NULL,
	PCI_MDPE,	PCI_STAT_S_PERROR,	NULL,
	PCI_REC_SERR,	PCI_STAT_S_SYSERR,	NULL,
	PCI_MA,		PCI_STAT_R_MAST_AB,	NULL,
	PCI_REC_TA,	PCI_STAT_R_TARG_AB,	NULL,
	PCI_SIG_TA,	PCI_STAT_S_TARG_AB,	NULL,
	NULL, NULL,
};

void
pci_ereport_setup(dev_info_t *dip)
{
	struct dev_info *devi = DEVI(dip);
	struct i_ddi_fmhdl *fmhdl = devi->devi_fmhdl;
	pci_erpt_t *erpt_p;
	ddi_acc_hdl_t *hp;
	uint16_t pci_devstat = 0;
	uint16_t pcie_cap = 0;
	uint8_t ecap_ptr = 0;
	uint8_t cap_ptr = 0;
	uint8_t cap_id = 0;
	int have_pciex;

	if (!DDI_FM_EREPORT_CAP(ddi_fm_capable(dip))) {
		i_ddi_drv_ereport_post(dip, DVR_EFMCAP, NULL, DDI_SLEEP);
		return;
	}

	ASSERT(fmhdl);
	ASSERT(fmhdl->fh_bus_specific == NULL);

	if ((erpt_p = kmem_zalloc(sizeof (pci_erpt_t), KM_SLEEP)) == NULL)
		return;

	/*
	 * Setup config space and store config address
	 * in pci_erpt struct.
	 */
	if (pci_config_setup(dip, &erpt_p->pci_cfg_hdl) == DDI_SUCCESS) {
		hp = impl_acc_hdl_get(erpt_p->pci_cfg_hdl);
		erpt_p->pci_cfg_addr = (caddr_t)hp->ah_addr;
		fmhdl->fh_bus_specific = (void *)erpt_p;
	} else {
		return;
	}

	/*
	 * Determine if this device supports a capabilities list.  We
	 * do so by looking at a bit in the status register. If we are
	 * unable to retrieve the status register, something is horribly
	 * wrong and we should just bail.
	 */
	if ((pci_devstat = ddi_get16(erpt_p->pci_cfg_hdl,
	    (uint16_t *)(erpt_p->pci_cfg_addr + PCI_CONF_STAT))) == 0xff)
		return;
	if ((pci_devstat & PCI_STAT_CAP) == 0)
		return;

	/*
	 * Determine if we are on a machine with pci express.  We do so
	 * by looping through the capabilities of the device and looking
	 * to see if one of those capabilities is support of PCI
	 * express.
	 */
	have_pciex = 0;
	if ((cap_ptr = ddi_get8(erpt_p->pci_cfg_hdl,
	    (uint8_t *)(erpt_p->pci_cfg_addr + PCI_CONF_CAP_PTR))) !=
	    0xff) {
		while ((cap_id = ddi_get8(erpt_p->pci_cfg_hdl,
		    (uint8_t *)(erpt_p->pci_cfg_addr + cap_ptr))) !=
		    0xff) {
			if (cap_id == PCI_CAP_ID_PCI_E) {
				ecap_ptr = cap_ptr;
				have_pciex = 1;
				break;
			}
			if ((cap_ptr = ddi_get8(erpt_p->pci_cfg_hdl,
			    (uint8_t *)(erpt_p->pci_cfg_addr +
			    cap_ptr + 1))) == 0xff || cap_ptr == 0)
				break;
		}
	}

	/*
	 * If not pci express, we're done
	 */
	if (have_pciex == 0)
		return;

	/*
	 * Save and export the pci express capabilities reg.
	 */
	pcie_cap = ddi_get16(erpt_p->pci_cfg_hdl,
	    (uint16_t *)(erpt_p->pci_cfg_addr + ecap_ptr + PCIE_PCIECAP));
	(void) ndi_prop_update_int(DDI_DEV_T_NONE,
	    dip, SAVED_PCIEX_CAP_REG, pcie_cap);

	/*
	 * Find and export any slot capabilities register
	 */
	if (pcie_cap & PCIE_PCIECAP_SLOT_IMPL) {
		int sltcap = ddi_get32(erpt_p->pci_cfg_hdl,
		    (uint32_t *)
		    (erpt_p->pci_cfg_addr + ecap_ptr + PCIE_SLOTCAP));
		(void) ndi_prop_update_int(DDI_DEV_T_NONE,
		    dip, SAVED_PCIEX_SLOTCAP_REG, sltcap);
	}
}

void
pci_ereport_teardown(dev_info_t *dip)
{
	struct i_ddi_fmhdl *fmhdl = DEVI(dip)->devi_fmhdl;
	pci_erpt_t *erpt_p;

	if (!DDI_FM_EREPORT_CAP(ddi_fm_capable(dip))) {
		i_ddi_drv_ereport_post(dip, DVR_EFMCAP, NULL, DDI_SLEEP);
	}

	ASSERT(fmhdl);

	erpt_p = (pci_erpt_t *)fmhdl->fh_bus_specific;
	if (erpt_p == NULL)
		return;

	(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, SAVED_PCIEX_CAP_REG);
	(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, SAVED_PCIEX_SLOTCAP_REG);
	pci_config_teardown(&erpt_p->pci_cfg_hdl);
	kmem_free(erpt_p, sizeof (pci_erpt_t));
	fmhdl->fh_bus_specific = NULL;
}

void
pci_ereport_post(dev_info_t *dip, ddi_fm_error_t *derr, uint16_t *status)
{
	struct i_ddi_fmhdl *fmhdl;
	pci_erpt_t *erpt_p;
	char buf[FM_MAX_CLASS];
	uint16_t cfg_comm = 0xffff;
	uint16_t cfg_stat = 0xffff;
	int i;
	fmhdl = DEVI(dip)->devi_fmhdl;

	if (!DDI_FM_EREPORT_CAP(ddi_fm_capable(dip))) {
		i_ddi_drv_ereport_post(dip, DVR_EFMCAP, NULL, DDI_NOSLEEP);
		return;
	}

	ASSERT(fmhdl);

	derr->fme_ena = derr->fme_ena ? derr->fme_ena : fm_ena_generate(0,
	    FM_ENA_FMT1);

	erpt_p = (pci_erpt_t *)fmhdl->fh_bus_specific;
	if (erpt_p == NULL) {
		i_ddi_drv_ereport_post(dip, DVR_EFMCAP, NULL, DDI_NOSLEEP);
		return;
	}

	if ((cfg_stat = ddi_get16(erpt_p->pci_cfg_hdl,
	    (uint16_t *)(erpt_p->pci_cfg_addr + PCI_CONF_STAT))) == 0xffff) {
		(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
		    PCI_ERROR_SUBCLASS, PCI_NR);
		ddi_fm_ereport_post(dip, buf, derr->fme_ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, 0, NULL);
		goto done;
	}
	if ((cfg_comm = ddi_get16(erpt_p->pci_cfg_hdl,
	    (uint16_t *)(erpt_p->pci_cfg_addr + PCI_CONF_COMM))) == 0xffff) {
		(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
		    PCI_ERROR_SUBCLASS, PCI_NR);
		ddi_fm_ereport_post(dip, buf, derr->fme_ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, 0, NULL);
		goto done;
	}

	if (derr->fme_flag == DDI_FM_ERR_UNEXPECTED) {
		for (i = 0; pci_err_tbl[i].err_class != NULL; i++) {
			if (cfg_stat & pci_err_tbl[i].reg_bit) {

				/*
				 * Generate an ereport for this error bit.
				 */
				(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
				    PCI_ERROR_SUBCLASS,
				    pci_err_tbl[i].err_class);
				ddi_fm_ereport_post(dip, buf, derr->fme_ena,
				    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
				    PCI_CONFIG_STATUS, DATA_TYPE_UINT16,
				    cfg_stat, PCI_CONFIG_COMMAND,
				    DATA_TYPE_UINT16, cfg_comm, NULL);

				/*
				 * Generate a corresponding ereport on behalf
				 * of the target (the parent dip) of the
				 * transaction.
				 */
				if (pci_err_tbl[i].terr_class != NULL &&
				    DDI_FM_EREPORT_CAP(ddi_fm_capable(
				    (dev_info_t *)DEVI(dip)->devi_parent))) {
					(void) snprintf(buf, FM_MAX_CLASS,
					    "%s.%s", PCI_ERROR_SUBCLASS,
					    pci_err_tbl[i].terr_class);
					ddi_fm_ereport_post((dev_info_t *)
					    DEVI(dip)->devi_parent, buf,
					    derr->fme_ena, DDI_NOSLEEP,
					    FM_VERSION, DATA_TYPE_UINT8, 0,
					    NULL);
				}
			}
		}
	}

	/*
	 * Clear error bits
	 */
	ddi_put16(erpt_p->pci_cfg_hdl,
	    (uint16_t *)(erpt_p->pci_cfg_addr + PCI_CONF_STAT),
	    (uint16_t)cfg_stat);
done:
	if (status != NULL)
		*status = cfg_stat;
}

/*
 * Generic pci-pci bridge error report function
 */
void
pci_bdg_ereport_post(dev_info_t *dip, ddi_fm_error_t *derr, uint16_t *status)
{
	struct i_ddi_fmhdl *fmhdl;
	pci_erpt_t *erpt_p;
	char buf[FM_MAX_CLASS];
	uint16_t bdg_ctrl = 0xffff;
	uint16_t cfg_sec_stat = 0xffff;
	int i;

	if (!DDI_FM_EREPORT_CAP(ddi_fm_capable(dip))) {
		i_ddi_drv_ereport_post(dip, DVR_EFMCAP, NULL, DDI_NOSLEEP);
		return;
	}

	fmhdl = DEVI(dip)->devi_fmhdl;

	ASSERT(fmhdl);

	derr->fme_ena = derr->fme_ena ? derr->fme_ena : fm_ena_generate(0,
	    FM_ENA_FMT1);

	erpt_p = (pci_erpt_t *)fmhdl->fh_bus_specific;
	if (erpt_p == NULL) {
		i_ddi_drv_ereport_post(dip, DVR_EFMCAP, NULL, DDI_NOSLEEP);
		return;
	}

	if ((cfg_sec_stat = ddi_get16(erpt_p->pci_cfg_hdl,
	    (uint16_t *)(erpt_p->pci_cfg_addr + PCI_BCNF_SEC_STATUS)))
	    == 0xffff) {
		(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", PCI_ERROR_SUBCLASS,
		    PCI_NR);
		ddi_fm_ereport_post(dip, buf, derr->fme_ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, 0, NULL);
		goto done;
	}

	if ((bdg_ctrl = ddi_get16(erpt_p->pci_cfg_hdl,
	    (uint16_t *)(erpt_p->pci_cfg_addr + PCI_BCNF_BCNTRL))) == 0xffff) {
		(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", PCI_ERROR_SUBCLASS,
		    PCI_NR);
		ddi_fm_ereport_post(dip, buf, derr->fme_ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, 0, NULL);
		goto done;
	}

	if (derr->fme_flag == DDI_FM_ERR_UNEXPECTED) {
		if (bdg_ctrl & PCI_BCNF_BCNTRL_DTO_STAT) {
			(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
			    PCI_ERROR_SUBCLASS, PCI_DTO);
			ddi_fm_ereport_post(dip, buf, derr->fme_ena,
			    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
			    PCI_SEC_CONFIG_STATUS, DATA_TYPE_UINT16,
			    cfg_sec_stat, PCI_BCNTRL, DATA_TYPE_UINT16,
			    bdg_ctrl, NULL);
		}

		for (i = 0; pci_bdg_err_tbl[i].err_class != NULL; i++) {
			if (cfg_sec_stat & pci_bdg_err_tbl[i].reg_bit) {
				(void) snprintf(buf, FM_MAX_CLASS, "%s.%s-%s",
				    PCI_ERROR_SUBCLASS, PCI_SEC_ERROR_SUBCLASS,
				    pci_bdg_err_tbl[i].err_class);
				ddi_fm_ereport_post(dip, buf, derr->fme_ena,
				    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
				    PCI_SEC_CONFIG_STATUS, DATA_TYPE_UINT16,
				    cfg_sec_stat, PCI_BCNTRL, DATA_TYPE_UINT16,
				    bdg_ctrl, NULL);
			}
		}
	}

	/*
	 * Clear error bits
	 */
	ddi_put16(erpt_p->pci_cfg_hdl, (uint16_t *)
	    (erpt_p->pci_cfg_addr + PCI_BCNF_SEC_STATUS),
	    (uint16_t)cfg_sec_stat);
	ddi_put16(erpt_p->pci_cfg_hdl, (uint16_t *)
	    (erpt_p->pci_cfg_addr + PCI_BCNF_BCNTRL),
	    (uint16_t)bdg_ctrl);

done:
	if (status != NULL)
		*status = cfg_sec_stat;
}

/*
 * Generic pci-pci bridge error analysis function
 */
int
pci_bdg_check_status(dev_info_t *dip, ddi_fm_error_t *derr,
    uint16_t pci_cfg_stat, uint16_t pci_cfg_sec_stat)
{
	int ret;
	int fatal = 0;
	int nonfatal = 0;
	int unknown = 0;

	if (derr->fme_flag == DDI_FM_ERR_POKE) {
		/*
		 * special case for pokes - we only consider master abort
		 * and target abort as nonfatal. Sserr with no master abort is
		 * fatal, but master/target abort can come in on separate
		 * instance, so return unknown and parent will determine if
		 * nonfatal (if another child returned nonfatal - ie master
		 * or target abort) or fatal otherwise
		 */
		if (pci_cfg_sec_stat & (PCI_STAT_R_TARG_AB |
		    PCI_STAT_R_MAST_AB))
			nonfatal++;
		if (pci_cfg_stat & PCI_STAT_S_SYSERR)
			unknown++;
	} else if (derr->fme_flag == DDI_FM_ERR_UNEXPECTED) {
		/*
		 * Only sserr on primary bus is considered fatal.
		 * In all other conditions, the bridge has been able to notify
		 * the initiator of the error condition, so let the initiator
		 * (be it the host for PIO or the leaf device for DMA) handle it
		 */
		if (pci_cfg_stat & PCI_STAT_S_SYSERR)
			fatal++;
		if (pci_cfg_stat & (PCI_STAT_PERROR |
		    PCI_STAT_R_MAST_AB | PCI_STAT_S_PERROR |
		    PCI_STAT_R_TARG_AB | PCI_STAT_S_TARG_AB))
			nonfatal++;
		if (pci_cfg_sec_stat & (PCI_STAT_R_TARG_AB |
		    PCI_STAT_S_SYSERR | PCI_STAT_R_MAST_AB | PCI_STAT_S_PERROR |
		    PCI_STAT_PERROR | PCI_STAT_S_TARG_AB))
			nonfatal++;
	}

	/*
	 * now check children below the bridge
	 */
	ret = ndi_fm_handler_dispatch(dip, NULL, derr);
	if (ret == DDI_FM_FATAL)
		fatal++;
	else if (ret == DDI_FM_NONFATAL)
		nonfatal++;
	else if (ret == DDI_FM_UNKNOWN)
		unknown++;

	return (fatal ? DDI_FM_FATAL : (nonfatal ? DDI_FM_NONFATAL :
	    (unknown ? DDI_FM_UNKNOWN : DDI_FM_OK)));
}

#ifdef _LP64
uint8_t
pci_config_get8(ddi_acc_handle_t handle, off_t offset)
#else /* _ILP32 */
uint8_t
pci_config_getb(ddi_acc_handle_t handle, off_t offset)
#endif
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	return (ddi_get8(handle, (uint8_t *)cfgaddr));
}

#ifdef _LP64
uint16_t
pci_config_get16(ddi_acc_handle_t handle, off_t offset)
#else /* _ILP32 */
uint16_t
pci_config_getw(ddi_acc_handle_t handle, off_t offset)
#endif
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	return (ddi_get16(handle, (uint16_t *)cfgaddr));
}

#ifdef _LP64
uint32_t
pci_config_get32(ddi_acc_handle_t handle, off_t offset)
#else /* _ILP32 */
uint32_t
pci_config_getl(ddi_acc_handle_t handle, off_t offset)
#endif
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	return (ddi_get32(handle, (uint32_t *)cfgaddr));
}

#ifdef _LP64
uint64_t
pci_config_get64(ddi_acc_handle_t handle, off_t offset)
#else /* _ILP32 */
uint64_t
pci_config_getll(ddi_acc_handle_t handle, off_t offset)
#endif
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	return (ddi_get64(handle, (uint64_t *)cfgaddr));
}

#ifdef _LP64
void
pci_config_put8(ddi_acc_handle_t handle, off_t offset, uint8_t value)
#else /* _ILP32 */
void
pci_config_putb(ddi_acc_handle_t handle, off_t offset, uint8_t value)
#endif
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	ddi_put8(handle, (uint8_t *)cfgaddr, value);
}

#ifdef _LP64
void
pci_config_put16(ddi_acc_handle_t handle, off_t offset, uint16_t value)
#else /* _ILP32 */
void
pci_config_putw(ddi_acc_handle_t handle, off_t offset, uint16_t value)
#endif
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	ddi_put16(handle, (uint16_t *)cfgaddr, value);
}

#ifdef _LP64
void
pci_config_put32(ddi_acc_handle_t handle, off_t offset, uint32_t value)
#else /* _ILP32 */
void
pci_config_putl(ddi_acc_handle_t handle, off_t offset, uint32_t value)
#endif
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	ddi_put32(handle, (uint32_t *)cfgaddr, value);
}

#ifdef _LP64
void
pci_config_put64(ddi_acc_handle_t handle, off_t offset, uint64_t value)
#else /* _ILP32 */
void
pci_config_putll(ddi_acc_handle_t handle, off_t offset, uint64_t value)
#endif
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	ddi_put64(handle, (uint64_t *)cfgaddr, value);
}

/*ARGSUSED*/
int
pci_report_pmcap(dev_info_t *dip, int cap, void *arg)
{
	return (DDI_SUCCESS);
}

/*
 * Note about saving and restoring config space.
 * PCI devices have only upto 256 bytes of config space while PCI Express
 * devices can have upto 4k config space. In case of PCI Express device,
 * we save all 4k config space and restore it even if it doesn't make use
 * of all 4k. But some devices don't respond to reads to non-existent
 * registers within the config space. To avoid any panics, we use ddi_peek
 * to do the reads. A bit mask is used to indicate which words of the
 * config space are accessible. While restoring the config space, only those
 * readable words are restored. We do all this in 32 bit size words.
 */
#define	INDEX_SHIFT		3
#define	BITMASK			0x7

static uint32_t pci_save_caps(ddi_acc_handle_t confhdl, uint32_t *regbuf,
    pci_cap_save_desc_t *cap_descp, uint32_t *ncapsp);
static void pci_restore_caps(ddi_acc_handle_t confhdl, uint32_t *regbuf,
    pci_cap_save_desc_t *cap_descp, uint32_t elements);
static uint32_t pci_generic_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr,
    uint32_t *regbuf, uint32_t nwords);
static uint32_t pci_msi_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr,
    uint32_t *regbuf, uint32_t notused);
static uint32_t pci_pcix_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr,
    uint32_t *regbuf, uint32_t notused);
static uint32_t pci_pcie_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr,
    uint32_t *regbuf, uint32_t notused);
static void pci_fill_buf(ddi_acc_handle_t confhdl, uint16_t cap_ptr,
    uint32_t *regbuf, uint32_t nwords);
static uint32_t cap_walk_and_save(ddi_acc_handle_t confhdl, uint32_t *regbuf,
    pci_cap_save_desc_t *cap_descp, uint32_t *ncapsp, int xspace);
static void pci_pmcap_check(ddi_acc_handle_t confhdl, uint32_t *regbuf,
    uint16_t pmcap_offset);

/*
 * Table below specifies the number of registers to be saved for each PCI
 * capability. pci_generic_save saves the number of words specified in the
 * table. Any special considerations will be taken care by the capability
 * specific save function e.g. use pci_msi_save to save registers associated
 * with MSI capability. PCI_UNKNOWN_SIZE indicates that number of registers
 * to be saved is variable and will be determined by the specific save function.
 * Currently we save/restore all the registers associated with the capability
 * including read only registers. Regsiters are saved and restored in 32 bit
 * size words.
 */
static pci_cap_entry_t pci_cap_table[] = {
	{PCI_CAP_ID_PM, PCI_PMCAP_NDWORDS, pci_generic_save},
	{PCI_CAP_ID_AGP, PCI_AGP_NDWORDS, pci_generic_save},
	{PCI_CAP_ID_SLOT_ID, PCI_SLOTID_NDWORDS, pci_generic_save},
	{PCI_CAP_ID_MSI_X, PCI_MSIX_NDWORDS, pci_generic_save},
	{PCI_CAP_ID_MSI, PCI_CAP_SZUNKNOWN, pci_msi_save},
	{PCI_CAP_ID_PCIX, PCI_CAP_SZUNKNOWN, pci_pcix_save},
	{PCI_CAP_ID_PCI_E, PCI_CAP_SZUNKNOWN, pci_pcie_save},
	/*
	 * {PCI_CAP_ID_cPCI_CRC, 0, NULL},
	 * {PCI_CAP_ID_VPD, 0, NULL},
	 * {PCI_CAP_ID_cPCI_HS, 0, NULL},
	 * {PCI_CAP_ID_PCI_HOTPLUG, 0, NULL},
	 * {PCI_CAP_ID_AGP_8X, 0, NULL},
	 * {PCI_CAP_ID_SECURE_DEV, 0, NULL},
	 */
	{PCI_CAP_NEXT_PTR_NULL, 0, NULL}
};

/*
 * Save the configuration registers for cdip as a property
 * so that it persists after detach/uninitchild.
 */
int
pci_save_config_regs(dev_info_t *dip)
{
	ddi_acc_handle_t confhdl;
	pci_config_header_state_t *chsp;
	pci_cap_save_desc_t *pci_cap_descp;
	int ret;
	uint32_t i, ncaps, nwords;
	uint32_t *regbuf, *p;
	uint8_t *maskbuf;
	size_t maskbufsz, regbufsz, capbufsz;
	ddi_acc_hdl_t *hp;
	off_t offset = 0;
	uint8_t cap_ptr, cap_id;
	int pcie = 0;

	if (pci_config_setup(dip, &confhdl) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d can't get config handle",
			ddi_driver_name(dip), ddi_get_instance(dip));

		return (DDI_FAILURE);
	}
	/*
	 * Determine if it is a pci express device. If it is, save entire
	 * 4k config space treating it as a array of 32 bit integers.
	 * If it is not, do it in a usual PCI way.
	 */
	cap_ptr = pci_config_get8(confhdl, PCI_BCNF_CAP_PTR);
	/*
	 * Walk the capabilities searching for pci express capability
	 */
	while (cap_ptr != PCI_CAP_NEXT_PTR_NULL) {
		cap_id = pci_config_get8(confhdl,
		    cap_ptr + PCI_CAP_ID);
		if (cap_id == PCI_CAP_ID_PCI_E) {
			pcie = 1;
			break;
		}
		cap_ptr = pci_config_get8(confhdl,
		    cap_ptr + PCI_CAP_NEXT_PTR);
	}

	if (pcie) {
		/* PCI express device. Can have data in all 4k space */
		regbuf = (uint32_t *)kmem_zalloc((size_t)PCIE_CONF_HDR_SIZE,
			    KM_SLEEP);
		p = regbuf;
		/*
		 * Allocate space for mask.
		 * mask size is 128 bytes (4096 / 4 / 8 )
		 */
		maskbufsz = (size_t)((PCIE_CONF_HDR_SIZE/ sizeof (uint32_t)) >>
		    INDEX_SHIFT);
		maskbuf = (uint8_t *)kmem_zalloc(maskbufsz, KM_SLEEP);
		hp = impl_acc_hdl_get(confhdl);
		for (i = 0; i < (PCIE_CONF_HDR_SIZE / sizeof (uint32_t)); i++) {
			if (ddi_peek32(dip, (int32_t *)(hp->ah_addr + offset),
			    (int32_t *)p) == DDI_SUCCESS) {
				/* it is readable register. set the bit */
				maskbuf[i >> INDEX_SHIFT] |=
				    (uint8_t)(1 << (i & BITMASK));
			}
			p++;
			offset += sizeof (uint32_t);
		}

		if ((ret = ndi_prop_update_byte_array(DDI_DEV_T_NONE, dip,
		    SAVED_CONFIG_REGS_MASK, (uchar_t *)maskbuf,
		    maskbufsz)) != DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "couldn't create %s property while"
			    "saving config space for %s@%d\n",
			    SAVED_CONFIG_REGS_MASK, ddi_driver_name(dip),
			    ddi_get_instance(dip));
		} else if ((ret = ndi_prop_update_byte_array(DDI_DEV_T_NONE,
		    dip, SAVED_CONFIG_REGS, (uchar_t *)regbuf,
		    (size_t)PCIE_CONF_HDR_SIZE)) != DDI_PROP_SUCCESS) {
			(void) ddi_prop_remove(DDI_DEV_T_NONE, dip,
			    SAVED_CONFIG_REGS_MASK);
			cmn_err(CE_WARN, "%s%d can't update prop %s",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    SAVED_CONFIG_REGS);
		}

		kmem_free(maskbuf, (size_t)maskbufsz);
		kmem_free(regbuf, (size_t)PCIE_CONF_HDR_SIZE);
	} else {
		regbuf = (uint32_t *)kmem_zalloc((size_t)PCI_CONF_HDR_SIZE,
			    KM_SLEEP);
		chsp = (pci_config_header_state_t *)regbuf;

		chsp->chs_command = pci_config_get16(confhdl, PCI_CONF_COMM);
		chsp->chs_header_type =	pci_config_get8(confhdl,
			    PCI_CONF_HEADER);
		if ((chsp->chs_header_type & PCI_HEADER_TYPE_M) ==
		    PCI_HEADER_ONE)
			chsp->chs_bridge_control =
			    pci_config_get16(confhdl, PCI_BCNF_BCNTRL);
		chsp->chs_cache_line_size = pci_config_get8(confhdl,
		    PCI_CONF_CACHE_LINESZ);
		chsp->chs_latency_timer = pci_config_get8(confhdl,
		    PCI_CONF_LATENCY_TIMER);
		if ((chsp->chs_header_type & PCI_HEADER_TYPE_M) ==
		    PCI_HEADER_ONE) {
			chsp->chs_sec_latency_timer =
			    pci_config_get8(confhdl, PCI_BCNF_LATENCY_TIMER);
		}

		chsp->chs_base0 = pci_config_get32(confhdl, PCI_CONF_BASE0);
		chsp->chs_base1 = pci_config_get32(confhdl, PCI_CONF_BASE1);
		chsp->chs_base2 = pci_config_get32(confhdl, PCI_CONF_BASE2);
		chsp->chs_base3 = pci_config_get32(confhdl, PCI_CONF_BASE3);
		chsp->chs_base4 = pci_config_get32(confhdl, PCI_CONF_BASE4);
		chsp->chs_base5 = pci_config_get32(confhdl, PCI_CONF_BASE5);

		/*
		 * Allocate maximum space required for capability descriptions.
		 * The maximum number of capabilties saved is the number of
		 * capabilities listed in the pci_cap_table.
		 */
		ncaps = (sizeof (pci_cap_table) / sizeof (pci_cap_entry_t));
		capbufsz = ncaps * sizeof (pci_cap_save_desc_t);
		pci_cap_descp = (pci_cap_save_desc_t *)kmem_zalloc(
		    capbufsz, KM_SLEEP);
		p = (uint32_t *)((caddr_t)regbuf +
		    sizeof (pci_config_header_state_t));
		nwords = pci_save_caps(confhdl, p, pci_cap_descp, &ncaps);
		regbufsz = sizeof (pci_config_header_state_t) +
		    nwords * sizeof (uint32_t);

		if ((ret = ndi_prop_update_byte_array(DDI_DEV_T_NONE, dip,
		    SAVED_CONFIG_REGS, (uchar_t *)regbuf, regbufsz)) !=
		    DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "%s%d can't update prop %s",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    SAVED_CONFIG_REGS);
		} else if (ncaps) {
			ret = ndi_prop_update_byte_array(DDI_DEV_T_NONE, dip,
			    SAVED_CONFIG_REGS_CAPINFO, (uchar_t *)pci_cap_descp,
			    ncaps * sizeof (pci_cap_save_desc_t));
			if (ret != DDI_PROP_SUCCESS)
				(void) ddi_prop_remove(DDI_DEV_T_NONE, dip,
				    SAVED_CONFIG_REGS);
		}
		kmem_free(regbuf, (size_t)PCI_CONF_HDR_SIZE);
		kmem_free(pci_cap_descp, capbufsz);
	}
	pci_config_teardown(&confhdl);

	if (ret != DDI_PROP_SUCCESS)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

/*
 * Saves registers associated with PCI capabilities.
 * Returns number of 32 bit words saved.
 * Number of capabilities saved is returned in ncapsp.
 */
static uint32_t
pci_save_caps(ddi_acc_handle_t confhdl, uint32_t *regbuf,
    pci_cap_save_desc_t *cap_descp, uint32_t *ncapsp)
{
	return (cap_walk_and_save(confhdl, regbuf, cap_descp, ncapsp, 0));
}

static uint32_t
cap_walk_and_save(ddi_acc_handle_t confhdl, uint32_t *regbuf,
    pci_cap_save_desc_t *cap_descp, uint32_t *ncapsp, int xspace)
{
	pci_cap_entry_t *pci_cap_entp;
	uint16_t cap_id, offset;
	uint32_t words_saved = 0, nwords = 0;
	uint16_t cap_ptr = PCI_CAP_NEXT_PTR_NULL;

	*ncapsp = 0;
	if (!xspace)
		cap_ptr = pci_config_get8(confhdl, PCI_BCNF_CAP_PTR);
	/*
	 * Walk the capabilities
	 */
	while (cap_ptr != PCI_CAP_NEXT_PTR_NULL) {
		cap_id = CAP_ID(confhdl, cap_ptr, xspace);
		/* Search for this cap id in our table */
		if (!xspace)
			pci_cap_entp = pci_cap_table;
		while (pci_cap_entp->cap_id != PCI_CAP_NEXT_PTR_NULL &&
		    pci_cap_entp->cap_id != cap_id)
			pci_cap_entp++;

		offset = cap_ptr;
		cap_ptr = NEXT_CAP(confhdl, cap_ptr, xspace);
		/*
		 * If this cap id is not found in the table, there is nothing
		 * to save.
		 */
		if (pci_cap_entp->cap_id == PCI_CAP_NEXT_PTR_NULL)
			continue;
		if (pci_cap_entp->cap_save_func) {
			if ((nwords = pci_cap_entp->cap_save_func(confhdl,
			    offset, regbuf, pci_cap_entp->cap_ndwords))) {
				cap_descp->cap_nregs = nwords;
				cap_descp->cap_offset = offset;
				cap_descp->cap_id = cap_id;
				regbuf += nwords;
				cap_descp++;
				words_saved += nwords;
				(*ncapsp)++;
			}
		}

	}
	return (words_saved);
}

static void
pci_fill_buf(ddi_acc_handle_t confhdl, uint16_t cap_ptr,
    uint32_t *regbuf, uint32_t nwords)
{
	int i;

	for (i = 0; i < nwords; i++) {
		*regbuf = pci_config_get32(confhdl, cap_ptr);
		regbuf++;
		cap_ptr += 4;
	}
}

static uint32_t
pci_generic_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr, uint32_t *regbuf,
    uint32_t nwords)
{
	pci_fill_buf(confhdl, cap_ptr, regbuf, nwords);
	return (nwords);
}

/*ARGSUSED*/
static uint32_t
pci_msi_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr, uint32_t *regbuf,
    uint32_t notused)
{
	uint32_t nwords = PCI_MSI_MIN_WORDS;
	uint16_t msi_ctrl;

	/* Figure out how many registers to be saved */
	msi_ctrl = pci_config_get16(confhdl, cap_ptr + PCI_MSI_CTRL);
	/* If 64 bit address capable add one word */
	if (msi_ctrl & PCI_MSI_64BIT_MASK)
		nwords++;
	/* If per vector masking capable, add two more words */
	if (msi_ctrl & PCI_MSI_PVM_MASK)
		nwords += 2;
	pci_fill_buf(confhdl, cap_ptr, regbuf, nwords);

	return (nwords);
}

/*ARGSUSED*/
static uint32_t
pci_pcix_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr, uint32_t *regbuf,
    uint32_t notused)
{
	uint32_t nwords = PCI_PCIX_MIN_WORDS;
	uint16_t pcix_command;

	/* Figure out how many registers to be saved */
	pcix_command = pci_config_get16(confhdl, cap_ptr + PCI_PCIX_COMMAND);
	/* If it is version 1 or version 2, add 4 words */
	if (((pcix_command & PCI_PCIX_VER_MASK) == PCI_PCIX_VER_1) ||
	    ((pcix_command & PCI_PCIX_VER_MASK) == PCI_PCIX_VER_2))
		nwords += 4;
	pci_fill_buf(confhdl, cap_ptr, regbuf, nwords);

	return (nwords);
}

/*ARGSUSED*/
static uint32_t
pci_pcie_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr, uint32_t *regbuf,
    uint32_t notused)
{
	return (0);
}

static void
pci_pmcap_check(ddi_acc_handle_t confhdl, uint32_t *regbuf,
    uint16_t pmcap_offset)
{
	uint16_t pmcsr;
	uint16_t pmcsr_offset = pmcap_offset + PCI_PMCSR;
	uint32_t *saved_pmcsrp = (uint32_t *)((caddr_t)regbuf + PCI_PMCSR);

	/*
	 * Copy the power state bits from the PMCSR to our saved copy.
	 * This is to make sure that we don't change the D state when
	 * we restore config space of the device.
	 */
	pmcsr = pci_config_get16(confhdl, pmcsr_offset);
	(*saved_pmcsrp) &= ~PCI_PMCSR_STATE_MASK;
	(*saved_pmcsrp) |= (pmcsr & PCI_PMCSR_STATE_MASK);
}

static void
pci_restore_caps(ddi_acc_handle_t confhdl, uint32_t *regbuf,
    pci_cap_save_desc_t *cap_descp, uint32_t elements)
{
	int i, j;
	uint16_t offset;

	for (i = 0; i < (elements / sizeof (pci_cap_save_desc_t)); i++) {
		offset = cap_descp->cap_offset;
		if (cap_descp->cap_id == PCI_CAP_ID_PM)
			pci_pmcap_check(confhdl, regbuf, offset);
		for (j = 0; j < cap_descp->cap_nregs; j++) {
			pci_config_put32(confhdl, offset, *regbuf);
			regbuf++;
			offset += 4;
		}
		cap_descp++;
	}
}

/*
 * Restore config_regs from a single devinfo node.
 */
int
pci_restore_config_regs(dev_info_t *dip)
{
	ddi_acc_handle_t confhdl;
	pci_config_header_state_t *chs_p;
	pci_cap_save_desc_t *cap_descp;
	uint32_t elements, i;
	uint8_t *maskbuf;
	uint32_t *regbuf, *p;
	off_t offset = 0;

	if (pci_config_setup(dip, &confhdl) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d can't get config handle",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, SAVED_CONFIG_REGS_MASK,
	    (uchar_t **)&maskbuf, &elements) == DDI_PROP_SUCCESS) {

		if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, SAVED_CONFIG_REGS,
		    (uchar_t **)&regbuf, &elements) != DDI_PROP_SUCCESS) {
			goto restoreconfig_err;
		}
		ASSERT(elements == PCIE_CONF_HDR_SIZE);
		/* pcie device and has 4k config space saved */
		p = regbuf;
		for (i = 0; i < PCIE_CONF_HDR_SIZE / sizeof (uint32_t); i++) {
			/* If the word is readable then restore it */
			if (maskbuf[i >> INDEX_SHIFT] &
			    (uint8_t)(1 << (i & BITMASK)))
				pci_config_put32(confhdl, offset, *p);
			p++;
			offset += sizeof (uint32_t);
		}
		ddi_prop_free(regbuf);
		ddi_prop_free(maskbuf);
		if (ndi_prop_remove(DDI_DEV_T_NONE, dip,
		    SAVED_CONFIG_REGS_MASK) != DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "%s%d can't remove prop %s",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    SAVED_CONFIG_REGS_MASK);
		}
	} else {
		if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, SAVED_CONFIG_REGS,
		    (uchar_t **)&regbuf, &elements) != DDI_PROP_SUCCESS) {

			pci_config_teardown(&confhdl);
			return (DDI_FAILURE);
		}

		chs_p = (pci_config_header_state_t *)regbuf;
		pci_config_put16(confhdl, PCI_CONF_COMM,
		    chs_p->chs_command);
		if ((chs_p->chs_header_type & PCI_HEADER_TYPE_M) ==
		    PCI_HEADER_ONE) {
			pci_config_put16(confhdl, PCI_BCNF_BCNTRL,
			    chs_p->chs_bridge_control);
		}
		pci_config_put8(confhdl, PCI_CONF_CACHE_LINESZ,
		    chs_p->chs_cache_line_size);
		pci_config_put8(confhdl, PCI_CONF_LATENCY_TIMER,
		    chs_p->chs_latency_timer);
		if ((chs_p->chs_header_type & PCI_HEADER_TYPE_M) ==
		    PCI_HEADER_ONE)
			pci_config_put8(confhdl, PCI_BCNF_LATENCY_TIMER,
			    chs_p->chs_sec_latency_timer);

		pci_config_put32(confhdl, PCI_CONF_BASE0, chs_p->chs_base0);
		pci_config_put32(confhdl, PCI_CONF_BASE1, chs_p->chs_base1);
		pci_config_put32(confhdl, PCI_CONF_BASE2, chs_p->chs_base2);
		pci_config_put32(confhdl, PCI_CONF_BASE3, chs_p->chs_base3);
		pci_config_put32(confhdl, PCI_CONF_BASE4, chs_p->chs_base4);
		pci_config_put32(confhdl, PCI_CONF_BASE5, chs_p->chs_base5);

		if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
		    SAVED_CONFIG_REGS_CAPINFO,
		    (uchar_t **)&cap_descp, &elements) == DDI_PROP_SUCCESS) {
			/*
			 * PCI capability related regsiters are saved.
			 * Restore them based on the description.
			 */
			p = (uint32_t *)((caddr_t)regbuf +
			    sizeof (pci_config_header_state_t));
			pci_restore_caps(confhdl, p, cap_descp, elements);
			ddi_prop_free(cap_descp);
		}

		ddi_prop_free(regbuf);
	}

	/*
	 * Make sure registers are flushed
	 */
	(void) pci_config_get32(confhdl, PCI_CONF_BASE5);


	if (ndi_prop_remove(DDI_DEV_T_NONE, dip, SAVED_CONFIG_REGS) !=
	    DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "%s%d can't remove prop %s",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    SAVED_CONFIG_REGS);
	}

	pci_config_teardown(&confhdl);

	return (DDI_SUCCESS);

restoreconfig_err:
	ddi_prop_free(maskbuf);
	if (ndi_prop_remove(DDI_DEV_T_NONE, dip, SAVED_CONFIG_REGS_MASK) !=
	    DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "%s%d can't remove prop %s",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    SAVED_CONFIG_REGS_MASK);
	}
	pci_config_teardown(&confhdl);
	return (DDI_FAILURE);
}
