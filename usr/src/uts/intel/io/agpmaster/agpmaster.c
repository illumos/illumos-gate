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
 * Copyright (c) 2009, Intel Corporation.
 * All Rights Reserved.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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

#define	PGTBL_CTL	0x2020	/* Page table control register */
#define	I8XX_FB_BAR	1
#define	I8XX_MMIO_BAR	2
#define	I8XX_PTE_OFFSET	0x10000
#define	I915_MMADR	1	/* mem-mapped registers BAR */
#define	I915_GMADR	3	/* graphics mem BAR */
#define	I915_GTTADDR	4	/* GTT BAR */
#define	I965_GTTMMADR	1	/* mem-mapped registers BAR + GTT */
/* In 965 1MB GTTMMADR, GTT reside in the latter 512KB */
#define	I965_GTT_OFFSET	0x80000
#define	GM45_GTT_OFFSET	0x200000
#define	GTT_SIZE_MASK	0xe
#define	GTT_512KB	(0 << 1)
#define	GTT_256KB	(1 << 1)
#define	GTT_128KB	(2 << 1)
#define	GTT_1MB		(3 << 1)
#define	GTT_2MB		(4 << 1)
#define	GTT_1_5MB	(5 << 1)

#define	MMIO_BASE(x)	(x)->agpm_data.agpm_gtt.gtt_mmio_base
#define	MMIO_HANDLE(x)	(x)->agpm_data.agpm_gtt.gtt_mmio_handle
#define	GTT_HANDLE(x)	(x)->agpm_data.agpm_gtt.gtt_handle
/* Base address of GTT */
#define	GTT_ADDR(x)	(x)->agpm_data.agpm_gtt.gtt_addr
/* Graphics memory base address */
#define	APER_BASE(x)	(x)->agpm_data.agpm_gtt.gtt_info.igd_aperbase

#define	AGPM_WRITE(x, off, val) \
    ddi_put32(MMIO_HANDLE(x), (uint32_t *)(MMIO_BASE(x) + (off)), (val));

#define	AGPM_READ(x, off) \
    ddi_get32(MMIO_HANDLE(x), (uint32_t *)(MMIO_BASE(x) + (off)));

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

static struct modlmisc modlmisc = {
	&mod_miscops, "AGP master interfaces"
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
	if (IS_IGD(master_softc) &&
	    ((MMIO_HANDLE(master_softc) != NULL) ||
	    (GTT_HANDLE(master_softc) != NULL))) {
		/*
		 * for some chipsets, mmap handle is shared between both mmio
		 * and GTT table.
		 */
		if ((GTT_HANDLE(master_softc) != MMIO_HANDLE(master_softc)) &&
		    (GTT_HANDLE(master_softc) != NULL))
			ddi_regs_map_free(&GTT_HANDLE(master_softc));
		if (MMIO_HANDLE(master_softc) != NULL)
			ddi_regs_map_free(&MMIO_HANDLE(master_softc));
	}

	kmem_free(master_softc, sizeof (agp_master_softc_t));
	master_softc = NULL;

	return;

}

/*
 * 965 has a fixed GTT table size (512KB), so check to see the actual aperture
 * size. Aperture size = GTT table size * 1024.
 */
static off_t
i965_apersize(agp_master_softc_t *agpmaster)
{
	off_t apersize;

	apersize = AGPM_READ(agpmaster, PGTBL_CTL);
	AGPM_DEBUG((CE_NOTE, "i965_apersize: PGTBL_CTL = %lx", apersize));
	switch (apersize & GTT_SIZE_MASK) {
	case GTT_2MB:
		apersize = 2048;
		break;
	case GTT_1_5MB:
		apersize = 1536;
		break;
	case GTT_1MB:
		apersize = 1024;
		break;
	case GTT_512KB:
		apersize = 512;
		break;
	case GTT_256KB:
		apersize = 256;
		break;
	case GTT_128KB:
		apersize = 128;
		break;
	default:
		apersize = 0;
		AGPM_DEBUG((CE_WARN,
		    "i965_apersize: invalid GTT size in PGTBL_CTL"));
	}
	return (apersize);
}

/*
 * For Intel 3 series, we need to get GTT size from the GGMS field in GMCH
 * Graphics Control Register. Return aperture size in MB.
 */
static off_t
i3XX_apersize(ddi_acc_handle_t pci_acc_hdl)
{
	uint16_t value;
	off_t apersize;

	/*
	 * Get the value of configuration register MGGC "Mirror of Dev0 GMCH
	 * Graphics Control" from Internal Graphics #2 (Device2:Function0).
	 */
	value = pci_config_get16(pci_acc_hdl, I8XX_CONF_GC);
	AGPM_DEBUG((CE_NOTE, "i3XX_apersize: MGGC = 0x%x", value));
	/* computing aperture size using the pre-allocated GTT size */
	switch (value & IX33_GGMS_MASK) {
	case IX33_GGMS_1M:
		apersize = 1024;
		break;
	case IX33_GGMS_2M:
		apersize = 2048;
		break;
	default:
		apersize = 0;	/* no memory pre-allocated */
		AGPM_DEBUG((CE_WARN,
		    "i3XX_apersize: no memory allocated for GTT"));
	}
	AGPM_DEBUG((CE_NOTE, "i3xx_apersize: apersize = %ldM", apersize));
	return (apersize);
}

#define	CHECK_STATUS(status)	\
    if (status != DDI_SUCCESS) { \
	    AGPM_DEBUG((CE_WARN, \
		"set_gtt_mmio: regs_map_setup error")); \
	    return (-1); \
}
/*
 * Set gtt_addr, gtt_mmio_base, igd_apersize, igd_aperbase and igd_devid
 * according to chipset.
 */
static int
set_gtt_mmio(dev_info_t *devi, agp_master_softc_t *agpmaster,
    ddi_acc_handle_t pci_acc_hdl)
{
	off_t apersize;  /* size of graphics mem (MB) == GTT size (KB) */
	uint32_t value;
	off_t gmadr_off;  /* GMADR offset in PCI config space */
	int status;

	if (IS_INTEL_X33(agpmaster->agpm_id)) {
		/* Intel 3 series are similar with 915/945 series */
		status = ddi_regs_map_setup(devi, I915_GTTADDR,
		    &GTT_ADDR(agpmaster), 0, 0, &i8xx_dev_access,
		    &GTT_HANDLE(agpmaster));
		CHECK_STATUS(status);

		status = ddi_regs_map_setup(devi, I915_MMADR,
		    &MMIO_BASE(agpmaster), 0, 0, &i8xx_dev_access,
		    &MMIO_HANDLE(agpmaster));
		CHECK_STATUS(status);

		gmadr_off = I915_CONF_GMADR;
		/* Different computing method used in getting aperture size. */
		apersize = i3XX_apersize(pci_acc_hdl);
	} else if (IS_INTEL_965(agpmaster->agpm_id)) {
		status = ddi_regs_map_setup(devi, I965_GTTMMADR,
		    &MMIO_BASE(agpmaster), 0, 0, &i8xx_dev_access,
		    &MMIO_HANDLE(agpmaster));
		CHECK_STATUS(status);
		if ((agpmaster->agpm_id == INTEL_IGD_GM45) ||
		    IS_INTEL_G4X(agpmaster->agpm_id))
			GTT_ADDR(agpmaster) =
			    MMIO_BASE(agpmaster) + GM45_GTT_OFFSET;
		else
			GTT_ADDR(agpmaster) =
			    MMIO_BASE(agpmaster) + I965_GTT_OFFSET;
		GTT_HANDLE(agpmaster) = MMIO_HANDLE(agpmaster);

		gmadr_off = I915_CONF_GMADR;
		apersize = i965_apersize(agpmaster);
	} else if (IS_INTEL_915(agpmaster->agpm_id)) {
		/* I915/945 series */
		status = ddi_regs_map_setup(devi, I915_GTTADDR,
		    &GTT_ADDR(agpmaster), 0, 0, &i8xx_dev_access,
		    &GTT_HANDLE(agpmaster));
		CHECK_STATUS(status);

		status = ddi_regs_map_setup(devi, I915_MMADR,
		    &MMIO_BASE(agpmaster), 0, 0, &i8xx_dev_access,
		    &MMIO_HANDLE(agpmaster));
		CHECK_STATUS(status);

		gmadr_off = I915_CONF_GMADR;
		status = ddi_dev_regsize(devi, I915_GMADR, &apersize);
		apersize = BYTES2MB(apersize);
	} else {
		/* I8XX series */
		status = ddi_regs_map_setup(devi, I8XX_MMIO_BAR,
		    &MMIO_BASE(agpmaster), 0, 0, &i8xx_dev_access,
		    &MMIO_HANDLE(agpmaster));
		CHECK_STATUS(status);

		GTT_ADDR(agpmaster) = MMIO_BASE(agpmaster) + I8XX_PTE_OFFSET;
		GTT_HANDLE(agpmaster) = MMIO_HANDLE(agpmaster);
		gmadr_off = I8XX_CONF_GMADR;
		status = ddi_dev_regsize(devi, I8XX_FB_BAR, &apersize);
		apersize = BYTES2MB(apersize);
		CHECK_STATUS(status);
	}

	/*
	 * If memory size is smaller than a certain value, it means
	 * the register set number for graphics memory range might
	 * be wrong
	 */
	if (status != DDI_SUCCESS || apersize < 4) {
		AGPM_DEBUG((CE_WARN,
		    "set_gtt_mmio: error in getting graphics memory"));
		return (-1);
	}

	agpmaster->agpm_data.agpm_gtt.gtt_info.igd_apersize = apersize;

	/* get graphics memory base address from GMADR */
	value = pci_config_get32(pci_acc_hdl, gmadr_off);
	APER_BASE(agpmaster) = value & GTT_BASE_MASK;
	AGPM_DEBUG((CE_NOTE, "set_gtt_mmio: aperbase = 0x%x, apersize = %ldM, "
	    "gtt_addr = %p, mmio_base = %p", APER_BASE(agpmaster), apersize,
	    (void *)GTT_ADDR(agpmaster), (void *)MMIO_BASE(agpmaster)));
	return (0);
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
	char buf[80];


	ASSERT(pci_acc_hdl);
	*master_softcp = NULL;
	agpmaster = (agp_master_softc_t *)
	    kmem_zalloc(sizeof (agp_master_softc_t), KM_SLEEP);

	agpmaster->agpm_id =
	    pci_config_get32(pci_acc_hdl, PCI_CONF_VENID);
	agpmaster->agpm_acc_hdl = pci_acc_hdl;

	if (!detect_i8xx_device(agpmaster)) {
		/* Intel 8XX, 915, 945 and 965 series */
		if (set_gtt_mmio(devi, agpmaster, pci_acc_hdl) != 0)
			goto fail;
	} else if (detect_agp_devcice(agpmaster, pci_acc_hdl)) {
		/* non IGD or AGP devices, AMD64 gart */
		AGPM_DEBUG((CE_WARN,
		    "agpmaster_attach: neither IGD or AGP devices exists"));
		agpmaster_detach(&agpmaster);
		return (0);
	}

	agpmaster->agpm_data.agpm_gtt.gtt_info.igd_devid =
	    agpmaster->agpm_id;

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

		AGPM_WRITE(softc, PGTBL_CTL, addr);
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
			AGPM_WRITE(softc, PGTBL_CTL, 0);
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
	case INTEL_IGD_915:
	case INTEL_IGD_915GM:
	case INTEL_IGD_945:
	case INTEL_IGD_945GM:
	case INTEL_IGD_945GME:
	case INTEL_IGD_946GZ:
	case INTEL_IGD_965G1:
	case INTEL_IGD_965G2:
	case INTEL_IGD_965GM:
	case INTEL_IGD_965GME:
	case INTEL_IGD_965Q:
	case INTEL_IGD_Q35:
	case INTEL_IGD_G33:
	case INTEL_IGD_Q33:
	case INTEL_IGD_GM45:
	case INTEL_IGD_EL:
	case INTEL_IGD_Q45:
	case INTEL_IGD_G45:
	case INTEL_IGD_G41:
	case INTEL_IGD_IGDNG_D:
	case INTEL_IGD_IGDNG_M:
	case INTEL_IGD_B43:
		master_softc->agpm_dev_type = DEVICE_IS_I830;
		break;
	default:		/* unknown id */
		return (-1);
	}

	return (0);
}

/*
 * If agp master is successfully detected, 0 is returned.
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
		ddi_put32(gtt->gtt_handle,
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
		ddi_put32(gtt->gtt_handle,
		    (uint32_t *)(gtt->gtt_addr + i * sizeof (uint32_t)), 0);
	}
}
