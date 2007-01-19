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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Misc module for AGP master device support
 */

#include <sys/modctl.h>
#include <sys/pci.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/sunddi.h>
#include <sys/agpgart.h>
#include <sys/agp/agpdefs.h>
#include <sys/agp/agpmaster_io.h>

#define	I8XX_MMIO_REGSET	2
#define	I8XX_FB_REGSET		1
#define	I8XX_PTE_OFFSET		0x10000
#define	I8XX_PGTBL_CTL		0x2020
#define	I915_GTTADDR_BAR	4
#define	I915_FB_REGSET		3

#ifdef DEBUG
#define	CONFIRM(value) ASSERT(value)
#else
#define	CONFIRM(value) if (!(value)) return (EINVAL)
#endif

int agpm_debug = 0;
#define	AGPM_DEBUG(args)	if (agpm_debug >= 1) cmn_err args

/*
 * Whether it is a Intel integrated graphics card
 */
#define	IS_IGD(agpmaster) ((agpmaster->agpm_dev_type == DEVICE_IS_I810) || \
		    (agpmaster->agpm_dev_type == DEVICE_IS_I830))


#define	IS_INTEL_9XX(agpmaster) ((agpmaster->agpm_id == INTEL_IGD_910) || \
		    (agpmaster->agpm_id == INTEL_IGD_910M) || \
		    (agpmaster->agpm_id == INTEL_IGD_945))

static struct modlmisc modlmisc = {
	&mod_miscops, "AGP master interfaces v%I%"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

static ddi_device_acc_attr_t i8xx_dev_access = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

static off_t agpmaster_cap_find(ddi_acc_handle_t);
static int detect_i8xx_device(agp_master_softc_t *);
static int detect_agp_devcice(agp_master_softc_t *, ddi_acc_handle_t);
static int i8xx_add_to_gtt(gtt_impl_t *, igd_gtt_seg_t);
static void i8xx_remove_from_gtt(gtt_impl_t *, igd_gtt_seg_t);

int
_init(void)
{
	int	err;

	if ((err = mod_install(&modlinkage)) != 0)
		return (err);

	return (0);
}

int
_fini(void)
{
	int	err;

	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Minor node is not removed here, since the caller (xx_attach) is
 * responsible for removing all nodes.
 */
void
agpmaster_detach(agp_master_softc_t **master_softcp)
{
	agp_master_softc_t *master_softc;

	ASSERT(master_softcp);
	master_softc = *master_softcp;

	/* intel integrated device */
	if (IS_IGD(master_softc)) {
		if (master_softc->agpm_data.agpm_gtt.gtt_mmio_handle != NULL) {
			ddi_regs_map_free(
			    &master_softc->agpm_data.agpm_gtt.gtt_mmio_handle);
		}
	}

	kmem_free(master_softc, sizeof (agp_master_softc_t));
	master_softc = NULL;

	return;

}

/*
 * Try to initialize agp master.
 * 0 is returned if the device is successfully initialized. AGP master soft
 * state is returned in master_softcp if needed.
 * Otherwise -1 is returned and *master_softcp is set to NULL.
 */
int
agpmaster_attach(dev_info_t *devi, agp_master_softc_t **master_softcp,
    ddi_acc_handle_t pci_acc_hdl, minor_t minor)
{
	int instance;
	int status;
	agp_master_softc_t *agpmaster;
	uint32_t value;
	off_t reg_size;
	char buf[80];


	ASSERT(pci_acc_hdl);
	*master_softcp = NULL;
	agpmaster = (agp_master_softc_t *)
	    kmem_zalloc(sizeof (agp_master_softc_t), KM_SLEEP);

	agpmaster->agpm_id =
	    pci_config_get32(pci_acc_hdl, PCI_CONF_VENID);
	agpmaster->agpm_acc_hdl = pci_acc_hdl;

	if (!detect_i8xx_device(agpmaster)) {
		/* map mmio register set */
		if (IS_INTEL_9XX(agpmaster)) {
			status = ddi_regs_map_setup(devi, I915_GTTADDR_BAR,
			    &agpmaster->agpm_data.agpm_gtt.gtt_mmio_base,
			    0, 0, &i8xx_dev_access,
			    &agpmaster->agpm_data.agpm_gtt.gtt_mmio_handle);
		} else {
			status = ddi_regs_map_setup(devi, I8XX_MMIO_REGSET,
			    &agpmaster->agpm_data.agpm_gtt.gtt_mmio_base,
			    0, 0, &i8xx_dev_access,
			    &agpmaster->agpm_data.agpm_gtt.gtt_mmio_handle);
		}

		if (status != DDI_SUCCESS) {
			AGPM_DEBUG((CE_WARN,
			    "agpmaster_attach: ddi_regs_map_setup failed"));
			goto fail;
		}
		/* get GTT range base offset */
		if (IS_INTEL_9XX(agpmaster)) {
			agpmaster->agpm_data.agpm_gtt.gtt_addr =
			    agpmaster->agpm_data.agpm_gtt.gtt_mmio_base;
		} else
			agpmaster->agpm_data.agpm_gtt.gtt_addr =
			agpmaster->agpm_data.agpm_gtt.gtt_mmio_base +
			I8XX_PTE_OFFSET;

		/* get graphics memory size */
		if (IS_INTEL_9XX(agpmaster)) {
			status = ddi_dev_regsize(devi, I915_FB_REGSET,
			    &reg_size);
		} else
			status = ddi_dev_regsize(devi, I8XX_FB_REGSET,
			    &reg_size);
		/*
		 * if memory size is smaller than a certain value, it means
		 * the register set number for graphics memory range might
		 * be wrong
		 */
		if (status != DDI_SUCCESS || reg_size < 0x400000) {
			AGPM_DEBUG((CE_WARN,
			    "agpmaster_attach: ddi_dev_regsize error"));
			goto fail;
		}

		agpmaster->agpm_data.agpm_gtt.gtt_info.igd_apersize =
		    BYTES2MB(reg_size);
		if (IS_INTEL_9XX(agpmaster)) {
			value = pci_config_get32(pci_acc_hdl,
			    I915_CONF_GMADR);
		} else
			value = pci_config_get32(pci_acc_hdl,
			    I8XX_CONF_GMADR);

		agpmaster->agpm_data.agpm_gtt.gtt_info.igd_aperbase =
		    value & GTT_BASE_MASK;
		agpmaster->agpm_data.agpm_gtt.gtt_info.igd_devid =
		    agpmaster->agpm_id;
	} else if (detect_agp_devcice(agpmaster, pci_acc_hdl)) {
		/*
		 * non IGD or AGP devices, AMD64 gart
		 */
		AGPM_DEBUG((CE_WARN,
		    "agpmaster_attach: neither IGD or AGP devices exists"));
		agpmaster_detach(&agpmaster);
		return (0);
	}

	/* create minor node for IGD or AGP device */
	instance = ddi_get_instance(devi);

	(void) sprintf(buf, "%s%d", AGPMASTER_NAME, instance);
	status = ddi_create_minor_node(devi, buf, S_IFCHR, minor,
	    DDI_NT_AGP_MASTER, 0);

	if (status != DDI_SUCCESS) {
		AGPM_DEBUG((CE_WARN,
		    "agpmaster_attach: create agpmaster node failed"));
		goto fail;
	}

	*master_softcp = agpmaster;
	return (0);
fail:
	agpmaster_detach(&agpmaster);
	return (-1);
}

/*
 * Currently, it handles ioctl requests related with agp master device for
 * layered driver (agpgart) only.
 */
/*ARGSUSED*/
int
agpmaster_ioctl(dev_t dev, int cmd, intptr_t data, int mode, cred_t *cred,
    int *rval, agp_master_softc_t *softc)
{
	uint32_t base;
	uint32_t addr;
	igd_gtt_seg_t seg;
	agp_info_t info;
	uint32_t value;
	off_t cap;
	uint32_t command;
	static char kernel_only[] =
	    "agpmaster_ioctl: %s is a kernel only ioctl";

	CONFIRM(softc);

	switch (cmd) {
	case DEVICE_DETECT:
		if (!(mode & FKIOCTL)) {
			AGPM_DEBUG((CE_CONT, kernel_only, "DEVICE_DETECT"));
			return (ENXIO);
		}

		if (ddi_copyout(&softc->agpm_dev_type,
		    (void *)data, sizeof (int), mode))
			return (EFAULT);
		break;
	case AGP_MASTER_SETCMD:
		if (!(mode & FKIOCTL)) {
			AGPM_DEBUG((CE_CONT, kernel_only, "AGP_MASTER_SETCMD"));
			return (ENXIO);
		}

		CONFIRM(softc->agpm_dev_type == DEVICE_IS_AGP);
		CONFIRM(softc->agpm_data.agpm_acaptr);

		if (ddi_copyin((void *)data, &command,
		    sizeof (uint32_t), mode))
			return (EFAULT);

		pci_config_put32(softc->agpm_acc_hdl,
		    softc->agpm_data.agpm_acaptr + AGP_CONF_COMMAND,
		    command);
		break;
	case AGP_MASTER_GETINFO:
		if (!(mode & FKIOCTL)) {
			AGPM_DEBUG((CE_CONT, kernel_only,
			    "AGP_MASTER_GETINFO"));
			return (ENXIO);
		}

		CONFIRM(softc->agpm_dev_type == DEVICE_IS_AGP);
		CONFIRM(softc->agpm_data.agpm_acaptr);

		cap = softc->agpm_data.agpm_acaptr;
		value = pci_config_get32(softc->agpm_acc_hdl, cap);
		info.agpi_version.agpv_major = (uint16_t)((value >> 20) & 0xf);
		info.agpi_version.agpv_minor = (uint16_t)((value >> 16) & 0xf);
		info.agpi_devid = softc->agpm_id;
		info.agpi_mode = pci_config_get32(
		    softc->agpm_acc_hdl, cap + AGP_CONF_STATUS);

		if (ddi_copyout(&info, (void *)data,
		    sizeof (agp_info_t), mode))
			return (EFAULT);
		break;
	case I810_SET_GTT_BASE:
		if (!(mode & FKIOCTL)) {
			AGPM_DEBUG((CE_CONT, kernel_only, "I810_SET_GTT_ADDR"));
			return (ENXIO);
		}

		CONFIRM(softc->agpm_dev_type == DEVICE_IS_I810);

		if (ddi_copyin((void *)data, &base, sizeof (uint32_t), mode))
			return (EFAULT);

		/* enables page table */
		addr = (base & GTT_BASE_MASK) | GTT_TABLE_VALID;

		ddi_put32(softc->agpm_data.agpm_gtt.gtt_mmio_handle,
		    (uint32_t *)(softc->agpm_data.agpm_gtt.gtt_mmio_base +
			I8XX_PGTBL_CTL),
		    addr);
		break;
	case I8XX_GET_INFO:
		if (!(mode & FKIOCTL)) {
			AGPM_DEBUG((CE_CONT, kernel_only, "I8XX_GET_INFO"));
			return (ENXIO);
		}

		CONFIRM(IS_IGD(softc));

		if (ddi_copyout(&softc->agpm_data.agpm_gtt.gtt_info,
		    (void *)data, sizeof (igd_info_t), mode))
			return (EFAULT);
		break;
	case I8XX_ADD2GTT:
		if (!(mode & FKIOCTL)) {
			AGPM_DEBUG((CE_CONT, kernel_only, "I8XX_ADD2GTT"));
			return (ENXIO);
		}

		CONFIRM(IS_IGD(softc));

		if (ddi_copyin((void *)data, &seg,
		    sizeof (igd_gtt_seg_t), mode))
			return (EFAULT);

		if (i8xx_add_to_gtt(&softc->agpm_data.agpm_gtt, seg))
			return (EINVAL);
		break;
	case I8XX_REM_GTT:
		if (!(mode & FKIOCTL)) {
			AGPM_DEBUG((CE_CONT, kernel_only, "I8XX_REM_GTT"));
			return (ENXIO);
		}

		CONFIRM(IS_IGD(softc));

		if (ddi_copyin((void *)data, &seg,
		    sizeof (igd_gtt_seg_t), mode))
			return (EFAULT);

		i8xx_remove_from_gtt(&softc->agpm_data.agpm_gtt, seg);
		break;
	case I8XX_UNCONFIG:
		if (!(mode & FKIOCTL)) {
			AGPM_DEBUG((CE_CONT, kernel_only, "I8XX_UNCONFIG"));
			return (ENXIO);
		}

		CONFIRM(IS_IGD(softc));

		if (softc->agpm_dev_type == DEVICE_IS_I810)
			ddi_put32(softc->agpm_data.agpm_gtt.gtt_mmio_handle,
			    (uint32_t *)
			    (softc->agpm_data.agpm_gtt.gtt_mmio_base +
				I8XX_PGTBL_CTL), 0);
		/*
		 * may need to clear all gtt entries here for i830 series,
		 * but may not be necessary
		 */
		break;
	}
	return (0);
}

/*
 * If AGP cap pointer is successfully found, none-zero value is returned.
 * Otherwise 0 is returned.
 */
static off_t
agpmaster_cap_find(ddi_acc_handle_t acc_handle)
{
	off_t		nextcap;
	uint32_t	ncapid;
	uint8_t		value;

	/* check if this device supports capibility pointer */
	value = (uint8_t)(pci_config_get16(acc_handle, PCI_CONF_STAT)
			    & PCI_CONF_CAP_MASK);

	if (!value)
		return (0);
	/* get the offset of the first capability pointer from CAPPTR */
	nextcap = (off_t)(pci_config_get8(acc_handle, AGP_CONF_CAPPTR));

	/* check AGP capability from the first capability pointer */
	while (nextcap) {
		ncapid = pci_config_get32(acc_handle, nextcap);
		if ((ncapid & PCI_CONF_CAPID_MASK)
		    == AGP_CAP_ID) /* find AGP cap */
			break;

		nextcap = (off_t)((ncapid & PCI_CONF_NCAPID_MASK) >> 8);
	}

	return (nextcap);

}

/*
 * If i8xx device is successfully detected, 0 is returned.
 * Otherwise -1 is returned.
 */
static int
detect_i8xx_device(agp_master_softc_t *master_softc)
{

	switch (master_softc->agpm_id) {
	case INTEL_IGD_810:
	case INTEL_IGD_810DC:
	case INTEL_IGD_810E:
	case INTEL_IGD_815:
		master_softc->agpm_dev_type = DEVICE_IS_I810;
		break;
	case INTEL_IGD_830M:
	case INTEL_IGD_845G:
	case INTEL_IGD_855GM:
	case INTEL_IGD_865G:
	case INTEL_IGD_910:
	case INTEL_IGD_910M:
	case INTEL_IGD_945:
		master_softc->agpm_dev_type = DEVICE_IS_I830;
		break;
	default:		/* unknown id */
		return (-1);
	}

	return (0);
}

/*
 * If agp master is succssfully detected, 0 is returned.
 * Otherwise -1 is returned.
 */
static int
detect_agp_devcice(agp_master_softc_t *master_softc,
    ddi_acc_handle_t acc_handle)
{
	off_t cap;

	cap = agpmaster_cap_find(acc_handle);
	if (cap) {
		master_softc->agpm_dev_type = DEVICE_IS_AGP;
		master_softc->agpm_data.agpm_acaptr = cap;
		return (0);
	} else {
		return (-1);
	}

}

/*
 * Please refer to GART and GTT entry format table in agpdefs.h for
 * intel GTT entry format.
 */
static int
phys2entry(uint32_t type, uint32_t physaddr, uint32_t *entry)
{
	uint32_t value;

	switch (type) {
	case AGP_PHYSICAL:
	case AGP_NORMAL:
		value = (physaddr & GTT_PTE_MASK) | GTT_PTE_VALID;
		break;
	default:
		return (-1);
	}

	*entry = value;

	return (0);
}

static int
i8xx_add_to_gtt(gtt_impl_t *gtt, igd_gtt_seg_t seg)
{
	int i;
	uint32_t *paddr;
	uint32_t entry;
	uint32_t maxpages;

	maxpages = gtt->gtt_info.igd_apersize;
	maxpages = GTT_MB_TO_PAGES(maxpages);

	paddr = seg.igs_phyaddr;

	/* check if gtt max page number is reached */
	if ((seg.igs_pgstart + seg.igs_npage) > maxpages)
		return (-1);

	paddr = seg.igs_phyaddr;
	for (i = seg.igs_pgstart; i < (seg.igs_pgstart + seg.igs_npage);
	    i++, paddr++) {
		if (phys2entry(seg.igs_type, *paddr, &entry))
			return (-1);
		ddi_put32(gtt->gtt_mmio_handle,
		    (uint32_t *)(gtt->gtt_addr + i * sizeof (uint32_t)),
		    entry);
	}

	return (0);
}

static void
i8xx_remove_from_gtt(gtt_impl_t *gtt, igd_gtt_seg_t seg)
{
	int i;
	uint32_t maxpages;

	maxpages = gtt->gtt_info.igd_apersize;
	maxpages = GTT_MB_TO_PAGES(maxpages);

	/* check if gtt max page number is reached */
	if ((seg.igs_pgstart + seg.igs_npage) > maxpages)
		return;

	for (i = seg.igs_pgstart; i < (seg.igs_pgstart + seg.igs_npage); i++) {
		ddi_put32(gtt->gtt_mmio_handle,
		    (uint32_t *)(gtt->gtt_addr +
		    i * sizeof (uint32_t)),
		    0);
	}
}
