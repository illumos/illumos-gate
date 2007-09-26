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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/sunldi.h>
#include <sys/pci.h>
#include <sys/agpgart.h>
#include <sys/agp/agpdefs.h>
#include <sys/agp/agptarget_io.h>

int agptarget_debug_var = 0;
#define	TARGETDB_PRINT2(fmt)	if (agptarget_debug_var >= 1) cmn_err fmt
#define	INST2NODENUM(inst)	(inst)
#define	DEV2INST(dev)		(getminor(dev))

typedef struct agp_target_softstate {
	dev_info_t		*tsoft_dip;
	ddi_acc_handle_t	tsoft_pcihdl;
	uint32_t		tsoft_devid;
	/* The offset of the ACAPID register */
	off_t			tsoft_acaptr;
	kmutex_t		tsoft_lock;
}agp_target_softstate_t;

/*
 * To get the pre-allocated graphics mem size using Graphics Mode Select
 * (GMS) value.
 */
typedef struct gms_mode {
	uint32_t	gm_devid;	/* bridge vendor + device id */
	off_t		gm_regoff;	/* mode selection register offset */
	uint32_t	gm_mask;	/* GMS mask */
	uint32_t	gm_num;		/* number of modes in gm_vec */
	int 		*gm_vec;	/* modes array */
} gms_mode_t;

static void *agptarget_glob_soft_handle;

#define	GETSOFTC(instance)	((agp_target_softstate_t *)	\
    ddi_get_soft_state(agptarget_glob_soft_handle, instance));

/*
 * The AMD8151 bridge is the only supported 64 bit hardware
 */
static int
is_64bit_aper(agp_target_softstate_t *softstate)
{
	return (softstate->tsoft_devid == AMD_BR_8151);
}
/*
 * Check if it is an intel bridge
 */
static int
is_intel_br(agp_target_softstate_t *softstate)
{
	return ((softstate->tsoft_devid & VENDOR_ID_MASK) ==
	    INTEL_VENDOR_ID);
}

/*
 * agp_target_cap_find()
 *
 * Description:
 * 	This function searches the linked capability list to find the offset
 * 	of the AGP capability register. When it was not found, return 0.
 * 	This works for standard AGP chipsets, but not for some Intel chipsets,
 * 	like the I830M/I830MP/I852PM/I852GME/I855GME. It will return 0 for
 * 	these chipsets even if AGP is supported. So the offset of acapid
 * 	should be set manually in thoses cases.
 *
 * Arguments:
 * 	pci_handle		ddi acc handle of pci config
 *
 * Returns:
 * 	0			No capability pointer register found
 * 	nexcap			The AGP capability pointer register offset
 */
static off_t
agp_target_cap_find(ddi_acc_handle_t pci_handle)
{
	off_t		nextcap = 0;
	uint32_t	ncapid = 0;
	uint8_t		value = 0;

	/* Check if this device supports the capability pointer */
	value = (uint8_t)(pci_config_get16(pci_handle, PCI_CONF_STAT)
	    & PCI_CONF_CAP_MASK);

	if (!value)
		return (0);
	/* Get the offset of the first capability pointer from CAPPTR */
	nextcap = (off_t)(pci_config_get8(pci_handle, AGP_CONF_CAPPTR));

	/* Check the AGP capability from the first capability pointer */
	while (nextcap) {
		ncapid = pci_config_get32(pci_handle, nextcap);
		/*
		 * AGP3.0 rev1.0 127  the capid was assigned by the PCI SIG,
		 * 845 data sheet page 69
		 */
		if ((ncapid & PCI_CONF_CAPID_MASK) ==
		    AGP_CAP_ID) /* The AGP cap was found */
			break;

		nextcap = (off_t)((ncapid & PCI_CONF_NCAPID_MASK) >> 8);
	}

	return (nextcap);

}

/*
 * agp_target_get_aperbase()
 *
 * Description:
 * 	This function gets the AGP aperture base address from the AGP target
 *	register, the AGP aperture base register was programmed by the BIOS.
 *
 * Arguments:
 * 	softstate		driver soft state pointer
 *
 * Returns:
 * 	aper_base 		AGP aperture base address
 *
 * Notes:
 * 	If a 64bit bridge device is available, the AGP aperture base address
 * 	can be 64 bit.
 */
static uint64_t
agp_target_get_apbase(agp_target_softstate_t *softstate)
{
	uint64_t aper_base;

	if (is_intel_br(softstate)) {
		aper_base = pci_config_get32(softstate->tsoft_pcihdl,
		    AGP_CONF_APERBASE) & AGP_32_APERBASE_MASK;
	} else if (is_64bit_aper(softstate)) {
		aper_base = pci_config_get64(softstate->tsoft_pcihdl,
		    AGP_CONF_APERBASE);
		/* 32-bit or 64-bit aperbase base pointer */
		if ((aper_base & AGP_APER_TYPE_MASK) == 0)
			aper_base &= AGP_32_APERBASE_MASK;
		else
			aper_base &= AGP_64_APERBASE_MASK;
	}

	return (aper_base);
}

/*
 * agp_target_get_apsize()
 *
 * Description:
 * 	This function gets the AGP aperture size by reading the AGP aperture
 * 	size register.
 * Arguments:
 * 	softstate		driver soft state pointer
 *
 * Return:
 * 	size		The AGP aperture size in megabytes
 * 	0		an unexpected error
 */
static size_t
agp_target_get_apsize(agp_target_softstate_t *softstate)
{
	off_t cap;
	uint16_t value;
	size_t size, regsize;

	ASSERT(softstate->tsoft_acaptr);
	cap = softstate->tsoft_acaptr;

	if (is_intel_br(softstate)) {
		/* extend this value to 16 bit for later tests */
		value = (uint16_t)pci_config_get8(softstate->tsoft_pcihdl,
		    cap + AGP_CONF_APERSIZE) | AGP_APER_SIZE_MASK;
	} else if (is_64bit_aper(softstate)) {
		value = pci_config_get16(softstate->tsoft_pcihdl,
		    cap + AGP_CONF_APERSIZE);
	}

	if (value & AGP_APER_128M_MASK) {
		switch (value & AGP_APER_128M_MASK) {
			case AGP_APER_4M:
				size = 4; /* 4M */
				break;
			case AGP_APER_8M:
				size = 8; /* 8M */
				break;
			case AGP_APER_16M:
				size = 16; /* 16M */
				break;
			case AGP_APER_32M:
				size = 32; /* 32M */
				break;
			case AGP_APER_64M:
				size = 64; /* 64M */
				break;
			case AGP_APER_128M:
				size = 128; /* 128M */
				break;
			default:
				size = 0; /* not true */
		}
	} else {
		switch (value & AGP_APER_4G_MASK) {
			case AGP_APER_256M:
				size = 256; /* 256 M */
				break;
			case AGP_APER_512M:
				size = 512; /* 512 M */
				break;
			case AGP_APER_1024M:
				size = 1024; /* 1024 M */
				break;
			case AGP_APER_2048M:
				size = 2048; /* 2048 M */
				break;
			case AGP_APER_4G:
				size = 4096; /* 4096 M */
				break;
			default:
				size = 0; /* not true */
		}
	}
	/*
	 * In some cases, there is no APSIZE register, so the size value
	 * of 256M could be wrong. Check the value by reading the size of
	 * the first register which was set in the PCI configuration space.
	 */
	if (size == 256) {
		if (ddi_dev_regsize(softstate->tsoft_dip,
		    AGP_TARGET_BAR1, (off_t *)&regsize) == DDI_FAILURE)
			return (0);

		if (MB2BYTES(size) != regsize) {
			TARGETDB_PRINT2((CE_WARN,
			    "APSIZE 256M doesn't match regsize %lx",
			    regsize));
			TARGETDB_PRINT2((CE_WARN, "Use regsize instead"));
			size = BYTES2MB(regsize);
		}
	}

	return (size);
}

static void
agp_target_set_gartaddr(agp_target_softstate_t *softstate, uint32_t gartaddr)
{
	ASSERT(softstate->tsoft_acaptr);

	/* Disable the GTLB for Intel chipsets */
	pci_config_put16(softstate->tsoft_pcihdl,
	    softstate->tsoft_acaptr + AGP_CONF_CONTROL, 0x0000);

	pci_config_put32(softstate->tsoft_pcihdl,
	    softstate->tsoft_acaptr + AGP_CONF_ATTBASE,
	    gartaddr & AGP_ATTBASE_MASK);
}

/*
 * Pre-allocated graphics memory for every type of Intel north bridge, mem size
 * are specified in kbytes.
 */
#define	GMS_MB(n) 	((n) * 1024)
#define	GMS_SHIFT 	4
#define	GMS_SIZE(a)	(sizeof (a) / sizeof (int))

/*
 * Since value zero always means "No memory pre-allocated", value of (GMS - 1)
 * is used to index these arrays, i.e. gms_xxx[1] contains the mem size (in kb)
 * that GMS value 0x1 corresponding to.
 *
 * Assuming all "reserved" GMS value as zero bytes of pre-allocated graphics
 * memory, unless some special BIOS settings exist.
 */
static int gms_810[12] = {0, 0, 0, 0, 0, 0, 0, 512, 0, 0, 0, GMS_MB(1)};
static int gms_830_845[4] = {0, 512, GMS_MB(1), GMS_MB(8)};
static int gms_855GM[5] = {GMS_MB(1), GMS_MB(4), GMS_MB(8), GMS_MB(16),
	GMS_MB(32)};
/* There is no modes for 16M in datasheet, but some BIOS add it. */
static int gms_865_915GM[4] = {GMS_MB(1), 0, GMS_MB(8), GMS_MB(16)};
static int gms_915_945_965[3] = {GMS_MB(1), 0, GMS_MB(8)};
static int gms_965GM[7] = {GMS_MB(1), GMS_MB(4), GMS_MB(8), GMS_MB(16),
	GMS_MB(32), GMS_MB(48), GMS_MB(64)};
static int gms_X33[9] = {GMS_MB(1), GMS_MB(4), GMS_MB(8), GMS_MB(16),
	GMS_MB(32), GMS_MB(48), GMS_MB(64), GMS_MB(128), GMS_MB(256)};

static gms_mode_t gms_modes[] = {
	{INTEL_BR_810, I810_CONF_SMRAM, I810_GMS_MASK,
		GMS_SIZE(gms_810), gms_810},
	{INTEL_BR_810DC, I810_CONF_SMRAM, I810_GMS_MASK,
		GMS_SIZE(gms_810), gms_810},
	{INTEL_BR_810E, I810_CONF_SMRAM, I810_GMS_MASK,
		GMS_SIZE(gms_810), gms_810},
	{INTEL_BR_830M, I8XX_CONF_GC, I8XX_GC_MODE_MASK,
		GMS_SIZE(gms_830_845), gms_830_845},
	{INTEL_BR_845, I8XX_CONF_GC, I8XX_GC_MODE_MASK,
		GMS_SIZE(gms_830_845), gms_830_845},
	{INTEL_BR_855GM, I8XX_CONF_GC, I8XX_GC_MODE_MASK,
		GMS_SIZE(gms_855GM), gms_855GM},
	{INTEL_BR_865, I8XX_CONF_GC, I8XX_GC_MODE_MASK,
		GMS_SIZE(gms_865_915GM), gms_865_915GM},
	{INTEL_BR_915GM, I8XX_CONF_GC, I8XX_GC_MODE_MASK,
		GMS_SIZE(gms_865_915GM), gms_865_915GM},
	{INTEL_BR_915, I8XX_CONF_GC, I8XX_GC_MODE_MASK,
		GMS_SIZE(gms_915_945_965), gms_915_945_965},
	{INTEL_BR_945, I8XX_CONF_GC, I8XX_GC_MODE_MASK,
		GMS_SIZE(gms_915_945_965), gms_915_945_965},
	{INTEL_BR_945GM, I8XX_CONF_GC, I8XX_GC_MODE_MASK,
		GMS_SIZE(gms_915_945_965), gms_915_945_965},
	{INTEL_BR_946GZ, I8XX_CONF_GC, I8XX_GC_MODE_MASK,
		GMS_SIZE(gms_915_945_965), gms_915_945_965},
	{INTEL_BR_965G1, I8XX_CONF_GC, I8XX_GC_MODE_MASK,
		GMS_SIZE(gms_915_945_965), gms_915_945_965},
	{INTEL_BR_965G2, I8XX_CONF_GC, I8XX_GC_MODE_MASK,
		GMS_SIZE(gms_915_945_965), gms_915_945_965},
	{INTEL_BR_965Q, I8XX_CONF_GC, I8XX_GC_MODE_MASK,
		GMS_SIZE(gms_915_945_965), gms_915_945_965},
	{INTEL_BR_965GM, I8XX_CONF_GC, I8XX_GC_MODE_MASK,
		GMS_SIZE(gms_965GM), gms_965GM},
	{INTEL_BR_965GME, I8XX_CONF_GC, I8XX_GC_MODE_MASK,
		GMS_SIZE(gms_965GM), gms_965GM},
	{INTEL_BR_Q35, I8XX_CONF_GC, IX33_GC_MODE_MASK,
		GMS_SIZE(gms_X33), gms_X33},
	{INTEL_BR_G33, I8XX_CONF_GC, IX33_GC_MODE_MASK,
		GMS_SIZE(gms_X33), gms_X33},
	{INTEL_BR_Q33, I8XX_CONF_GC, IX33_GC_MODE_MASK,
		GMS_SIZE(gms_X33), gms_X33}
};

/* Returns the size (kbytes) of pre-allocated graphics memory */
static size_t
i8xx_biosmem_detect(agp_target_softstate_t *softstate)
{
	uint8_t memval;
	size_t kbytes;
	int i;
	int num_modes;

	kbytes = 0;
	/* get GMS modes list entry */
	num_modes = (sizeof (gms_modes) / sizeof (gms_mode_t));
	for (i = 0; i < num_modes; i++) {
		if (gms_modes[i].gm_devid == softstate->tsoft_devid)
			break;
	}
	if (i ==  num_modes)
		goto done;
	/* fetch the GMS value from DRAM controller */
	memval = pci_config_get8(softstate->tsoft_pcihdl,
	    gms_modes[i].gm_regoff);
	TARGETDB_PRINT2((CE_NOTE, "i8xx_biosmem_detect: memval = %x", memval));
	memval = (memval & gms_modes[i].gm_mask) >> GMS_SHIFT;
	/* assuming zero byte for 0 or "reserved" GMS values */
	if (memval == 0 || memval > gms_modes[i].gm_num) {
		TARGETDB_PRINT2((CE_WARN, "i8xx_biosmem_detect: "
		    "devid = %x, GMS = %x. assuming zero byte of "
		    "pre-allocated memory", gms_modes[i].gm_devid, memval));
		goto done;
	}
	memval--;	/* use (GMS_value - 1) as index */
	kbytes = (gms_modes[i].gm_vec)[memval];

done:
	TARGETDB_PRINT2((CE_NOTE,
	    "i8xx_biosmem_detect: %ldKB BIOS pre-allocated memory detected",
	    kbytes));
	return (kbytes);
}

/*ARGSUSED*/
static int agptarget_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,
    void *arg, void **resultp)
{
	agp_target_softstate_t *st;
	int instance, rval = DDI_FAILURE;
	dev_t dev;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		instance = DEV2INST(dev);
		st = ddi_get_soft_state(agptarget_glob_soft_handle, instance);
		if (st != NULL) {
			mutex_enter(&st->tsoft_lock);
			*resultp = st->tsoft_dip;
			mutex_exit(&st->tsoft_lock);
			rval = DDI_SUCCESS;
		} else
			*resultp = NULL;

		break;
	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = DEV2INST(dev);
		*resultp = (void *)(uintptr_t)instance;
		rval = DDI_SUCCESS;
	default:
		break;
	}

	return (rval);
}

static int
agp_target_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	agp_target_softstate_t *softstate;
	int instance;
	int status;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(agptarget_glob_soft_handle, instance) !=
	    DDI_SUCCESS)
		return (DDI_FAILURE);

	softstate = ddi_get_soft_state(agptarget_glob_soft_handle, instance);
	mutex_init(&softstate->tsoft_lock, NULL, MUTEX_DRIVER, NULL);
	softstate->tsoft_dip = dip;
	status = pci_config_setup(dip, &softstate->tsoft_pcihdl);
	if (status != DDI_SUCCESS) {
		ddi_soft_state_free(agptarget_glob_soft_handle, instance);
		return (DDI_FAILURE);
	}

	softstate->tsoft_devid = pci_config_get32(softstate->tsoft_pcihdl,
	    PCI_CONF_VENID);
	softstate->tsoft_acaptr = agp_target_cap_find(softstate->tsoft_pcihdl);
	if (softstate->tsoft_acaptr == 0) {
		/* Make a correction for some Intel chipsets */
		if (is_intel_br(softstate))
			softstate->tsoft_acaptr = AGP_CAP_OFF_DEF;
		else
			return (DDI_FAILURE);
	}

	status = ddi_create_minor_node(dip, AGPTARGET_NAME, S_IFCHR,
	    INST2NODENUM(instance), DDI_NT_AGP_TARGET, 0);

	if (status != DDI_SUCCESS) {
		pci_config_teardown(&softstate->tsoft_pcihdl);
		ddi_soft_state_free(agptarget_glob_soft_handle, instance);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
agp_target_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	agp_target_softstate_t *softstate;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);

	softstate = ddi_get_soft_state(agptarget_glob_soft_handle, instance);

	ddi_remove_minor_node(dip, AGPTARGET_NAME);
	pci_config_teardown(&softstate->tsoft_pcihdl);
	mutex_destroy(&softstate->tsoft_lock);
	ddi_soft_state_free(agptarget_glob_soft_handle, instance);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
agp_target_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *cred, int *rval)
{
	int instance = DEV2INST(dev);
	agp_target_softstate_t *st;
	static char kernel_only[] =
	    "amd64_gart_ioctl: is a kernel only ioctl";

	if (!(mode & FKIOCTL)) {
		TARGETDB_PRINT2((CE_CONT, kernel_only));
		return (ENXIO);
	}
	st = GETSOFTC(instance);

	if (st == NULL)
		return (ENXIO);

	mutex_enter(&st->tsoft_lock);

	switch (cmd) {
	case CHIP_DETECT:
	{
		int type = 0;

		if (is_intel_br(st))
			type = CHIP_IS_INTEL;
		else if (is_64bit_aper(st))
			type = CHIP_IS_AMD;
		else {
			type = 0;
			TARGETDB_PRINT2((CE_WARN, "Unknown bridge!"));
		}

		if (ddi_copyout(&type, (void *)data, sizeof (int), mode)) {
			mutex_exit(&st->tsoft_lock);
			return (EFAULT);
		}

		break;
	}
	case I8XX_GET_PREALLOC_SIZE:
	{
		size_t prealloc_size;

		if (!is_intel_br(st)) {
			mutex_exit(&st->tsoft_lock);
			return (EINVAL);
		}

		prealloc_size = i8xx_biosmem_detect(st);
		if (ddi_copyout(&prealloc_size, (void *)data,
		    sizeof (size_t), mode)) {
			mutex_exit(&st->tsoft_lock);
			return (EFAULT);
		}

		break;
	}
	case AGP_TARGET_GETINFO:
	{
		i_agp_info_t info;
		uint32_t value;
		off_t cap;

		ASSERT(st->tsoft_acaptr);

		cap = st->tsoft_acaptr;
		value = pci_config_get32(st->tsoft_pcihdl, cap);
		info.iagp_ver.agpv_major = (uint16_t)((value >> 20) & 0xf);
		info.iagp_ver.agpv_minor = (uint16_t)((value >> 16) & 0xf);
		info.iagp_devid = st->tsoft_devid;
		info.iagp_mode = pci_config_get32(st->tsoft_pcihdl,
		    cap + AGP_CONF_STATUS);
		info.iagp_aperbase = agp_target_get_apbase(st);
		info.iagp_apersize = agp_target_get_apsize(st);

		if (ddi_copyout(&info, (void *)data,
		    sizeof (i_agp_info_t), mode)) {
			mutex_exit(&st->tsoft_lock);
			return (EFAULT);
		}
		break;

	}
	/*
	 * This ioctl is only for Intel AGP chipsets.
	 * It is not necessary for the AMD8151 AGP bridge, because
	 * this register in the AMD8151 does not control any hardware.
	 * It is only provided for compatibility with an Intel AGP bridge.
	 * Please refer to the <<AMD8151 data sheet>> page 24,
	 * AGP device GART pointer.
	 */
	case AGP_TARGET_SET_GATTADDR:
	{
		uint32_t gartaddr;

		if (ddi_copyin((void *)data, &gartaddr,
		    sizeof (uint32_t), mode)) {
			mutex_exit(&st->tsoft_lock);
			return (EFAULT);
		}

		agp_target_set_gartaddr(st, gartaddr);
		break;
	}
	case AGP_TARGET_SETCMD:
	{
		uint32_t command;

		if (ddi_copyin((void *)data, &command,
		    sizeof (uint32_t), mode)) {
			mutex_exit(&st->tsoft_lock);
			return (EFAULT);
		}

		ASSERT(st->tsoft_acaptr);

		pci_config_put32(st->tsoft_pcihdl,
		    st->tsoft_acaptr + AGP_CONF_COMMAND,
		    command);
		break;

	}
	case AGP_TARGET_FLUSH_GTLB:
	{
		uint16_t value;

		ASSERT(st->tsoft_acaptr);

		value = pci_config_get16(st->tsoft_pcihdl,
		    st->tsoft_acaptr + AGP_CONF_CONTROL);
		value &= ~AGPCTRL_GTLBEN;
		pci_config_put16(st->tsoft_pcihdl,
		    st->tsoft_acaptr + AGP_CONF_CONTROL, value);
		value |= AGPCTRL_GTLBEN;
		pci_config_put16(st->tsoft_pcihdl,
		    st->tsoft_acaptr + AGP_CONF_CONTROL, value);

		break;
	}
	case AGP_TARGET_CONFIGURE:
	{
		uint8_t value;

		ASSERT(st->tsoft_acaptr);

		/*
		 * In Intel agp bridges, agp misc register offset
		 * is indexed from 0 instead of capability register.
		 * AMD agp bridges have no such misc register
		 * to control the aperture access, and they have
		 * similar regsiters in CPU gart devices instead.
		 */

		if (is_intel_br(st)) {
			value = pci_config_get8(st->tsoft_pcihdl,
			    st->tsoft_acaptr + AGP_CONF_MISC);
			value |= AGP_MISC_APEN;
			pci_config_put8(st->tsoft_pcihdl,
			    st->tsoft_acaptr + AGP_CONF_MISC, value);
		}
		break;

	}
	case AGP_TARGET_UNCONFIG:
	{
		uint32_t value1;
		uint8_t value2;

		ASSERT(st->tsoft_acaptr);

		pci_config_put16(st->tsoft_pcihdl,
		    st->tsoft_acaptr + AGP_CONF_CONTROL, 0x0);

		if (is_intel_br(st)) {
			value2 = pci_config_get8(st->tsoft_pcihdl,
			    st->tsoft_acaptr + AGP_CONF_MISC);
			value2 &= ~AGP_MISC_APEN;
			pci_config_put8(st->tsoft_pcihdl,
			    st->tsoft_acaptr + AGP_CONF_MISC, value2);
		}

		value1 = pci_config_get32(st->tsoft_pcihdl,
		    st->tsoft_acaptr + AGP_CONF_COMMAND);
		value1 &= ~AGPCMD_AGPEN;
		pci_config_put32(st->tsoft_pcihdl,
		    st->tsoft_acaptr + AGP_CONF_COMMAND,
		    value1);

		pci_config_put32(st->tsoft_pcihdl,
		    st->tsoft_acaptr + AGP_CONF_ATTBASE, 0x0);

		break;
	}

	default:
		mutex_exit(&st->tsoft_lock);
		return (ENXIO);
	} /* end switch */

	mutex_exit(&st->tsoft_lock);

	return (0);
}

/*ARGSUSED*/
static int
agp_target_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
	int instance = DEV2INST(*devp);
	agp_target_softstate_t *st;

	if (!(flag & FKLYR))
		return (ENXIO);

	st = GETSOFTC(instance);

	if (st == NULL)
		return (ENXIO);

	return (0);
}

/*ARGSUSED*/
static int
agp_target_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	int instance = DEV2INST(dev);
	agp_target_softstate_t *st;

	st = GETSOFTC(instance);

	if (st == NULL)
		return (ENXIO);

	return (0);
}

static  struct  cb_ops  agp_target_cb_ops = {
	agp_target_open,		/* cb_open */
	agp_target_close,		/* cb_close */
	nodev,				/* cb_strategy */
	nodev,				/* cb_print */
	nodev,				/* cb_dump */
	nodev,				/* cb_read() */
	nodev,				/* cb_write() */
	agp_target_ioctl,		/* cb_ioctl */
	nodev,				/* cb_devmap */
	nodev,				/* cb_mmap */
	nodev,				/* cb_segmap */
	nochpoll,			/* cb_chpoll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* cb_stream */
	D_NEW | D_MP, 			/* cb_flag */
	CB_REV,				/* cb_ops version? */
	nodev,				/* cb_aread() */
	nodev,				/* cb_awrite() */
};

/* device operations */
static struct dev_ops agp_target_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	agptarget_getinfo, 	/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	agp_target_attach,	/* devo_attach */
	agp_target_detach,	/* devo_detach */
	nodev,			/* devo_reset */
	&agp_target_cb_ops,	/* devo_cb_ops */
	0,			/* devo_bus_ops */
	0,			/* devo_power */
};

static  struct modldrv modldrv = {
	&mod_driverops,
	"AGP target driver v%I%",
	&agp_target_ops,
};

static  struct modlinkage modlinkage = {
	MODREV_1,		/* MODREV_1 is indicated by manual */
	{&modldrv, NULL, NULL, NULL}
};

int
_init(void)
{
	int ret;

	ret = ddi_soft_state_init(&agptarget_glob_soft_handle,
	    sizeof (agp_target_softstate_t), 1);

	if (ret)
		goto err1;

	if ((ret = mod_install(&modlinkage)) != 0) {
		goto err2;
	}

	return (DDI_SUCCESS);
err2:
	ddi_soft_state_fini(&agptarget_glob_soft_handle);
err1:
	return (ret);
}

int
_info(struct  modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int	ret;

	if ((ret = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&agptarget_glob_soft_handle);
	}
	return (ret);
}
