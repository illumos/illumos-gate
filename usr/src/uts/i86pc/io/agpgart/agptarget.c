/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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
	off_t			tsoft_acaptr;	/* offset of ACAPID register */
	kmutex_t		tsoft_lock;
}agp_target_softstate_t;

static void *agptarget_glob_soft_handle;

#define	GETSOFTC(instance)	((agp_target_softstate_t *)	\
    ddi_get_soft_state(agptarget_glob_soft_handle, instance));

/*
 * AMD8151 bridge is the only 64 bit hardware supported
 */
static int
is_64bit_aper(agp_target_softstate_t *softstate)
{
	return (softstate->tsoft_devid == AMD_BR_8151);
}

/*
 * agp_target_cap_find()
 *
 * Description:
 * 	This function seach the linked capability list to find the
 * 	offset of AGP capability register. When not found, return 0.
 * 	This works for standard AGP chipsets, but not for some Intel chipsets,
 * 	like I830M/I830MP/I852PM/I852GME/I855GME. It will return 0 for
 * 	these chipsets even if AGP is supported. So the offset of acapid
 * 	should be set manually in thoses cases.
 *
 * Arguments:
 * 	pci_handle		ddi acc handle of pci config
 *
 * Returns:
 * 	0			No capability pointer register found
 * 	nexcap			AGP capability pointer register offset
 */
static off_t
agp_target_cap_find(ddi_acc_handle_t pci_handle)
{
	off_t		nextcap = 0;
	uint32_t	ncapid = 0;
	uint8_t		value = 0;

	/* Check if this device supports capibility pointer */
	value = (uint8_t)(pci_config_get16(pci_handle, PCI_CONF_STAT)
	    & PCI_CONF_CAP_MASK);

	if (!value)
		return (0);
	/* Get the offset of the first capability pointer from CAPPTR */
	nextcap = (off_t)(pci_config_get8(pci_handle, AGP_CONF_CAPPTR));

	/* Check AGP capability from the first capability pointer */
	while (nextcap) {
		ncapid = pci_config_get32(pci_handle, nextcap);
		/*
		 * AGP3.0 rev1.0 127  capid assigned by PCI SIG,
		 * 845 data sheet page 69
		 */
		if ((ncapid & PCI_CONF_CAPID_MASK) ==
		    AGP_CAP_ID) /* AGP cap found */
			break;

		nextcap = (off_t)((ncapid & PCI_CONF_NCAPID_MASK) >> 8);
	}

	return (nextcap);

}

/*
 * agp_target_get_aperbase()
 *
 * Description:
 * 	This function get the AGP aperture base address from agp target
 *	register, the AGP aperture base register programmed by BIOS.
 *
 * Arguments:
 * 	softstate		driver soft state pointer
 *
 * Returns:
 * 	aper_base 		AGP aperture base address
 *
 * Notes:
 * 	If 64bit bridge deice available, the agp aperture base address
 * 	can be 64 bit
 */
static uint64_t
agp_target_get_apbase(agp_target_softstate_t *softstate)
{
	uint64_t aper_base;

	if (!is_64bit_aper(softstate)) {
		aper_base = pci_config_get32(softstate->tsoft_pcihdl,
		    AGP_CONF_APERBASE) & AGP_32_APERBASE_MASK;
	} else {
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
 * 	This function get the agp aperture size by read the agp aperture
 * 	size register.
 * Arguments:
 * 	softstate		driver soft state pointer
 *
 * Return:
 * 	size		agp aperture size in megabytes
 * 	0		unexpected error
 */
static size_t
agp_target_get_apsize(agp_target_softstate_t *softstate)
{
	off_t cap;
	uint16_t value;
	size_t size, regsize;

	ASSERT(softstate->tsoft_acaptr);
	cap = softstate->tsoft_acaptr;

	if ((softstate->tsoft_devid & VENDOR_ID_MASK) == INTEL_VENDOR_ID) {
		/* extend this value to 16 bit for later test */
		value = (uint16_t)pci_config_get8(softstate->tsoft_pcihdl,
		    cap + AGP_CONF_APERSIZE) | AGP_APER_SIZE_MASK;
	} else {
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
	 * of 256M could be wrong. Check the value by reading
	 * the size of the first register set in PCI configuration space.
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

	/* Disable GTLB for Intel chipsets */
	pci_config_put16(softstate->tsoft_pcihdl,
	    softstate->tsoft_acaptr + AGP_CONF_CONTROL, 0x0000);

	pci_config_put32(softstate->tsoft_pcihdl,
	    softstate->tsoft_acaptr + AGP_CONF_ATTBASE,
	    gartaddr & AGP_ATTBASE_MASK);
}

static size_t
i8xx_biosmem_detect(agp_target_softstate_t *softstate)
{
	uint8_t memval;
	size_t kbytes;

	switch (softstate->tsoft_devid) {
	case INTEL_BR_810:
	case INTEL_BR_810DC:
	case INTEL_BR_810E:
		memval = pci_config_get8(softstate->tsoft_pcihdl,
		    I810_CONF_SMRAM);
		switch (memval & I810_GMS_MASK) {
		case 0x80:
			kbytes = 512; /* 512K preallocated memory */
			break;
		case 0xc0:
			kbytes = 1024; /* 1024K preallocated memory */
			break;
		default:
			kbytes = 0; /* unexpected case */
		}
		break;
	case INTEL_BR_830M:
	case INTEL_BR_845:
		memval = pci_config_get8(softstate->tsoft_pcihdl, I8XX_CONF_GC);
		switch (memval & I8XX_GC_MODE_MASK) {
		case I8XX_GC_MODE2:
			kbytes = 512; /* 512K preallocated memory */
			break;
		case I8XX_GC_MODE3:
			kbytes = 1024; /* 1M preallocated memory */
			break;
		case I8XX_GC_MODE4:
			kbytes = 8 * 1024; /* 8M preallocated memory */
			break;
		default:
			kbytes = 0; /* unexpected case */
		}
		break;
	case INTEL_BR_855GM:
		memval = pci_config_get8(softstate->tsoft_pcihdl, I8XX_CONF_GC);
		switch (memval & I8XX_GC_MODE_MASK) {
		case I8XX_GC_MODE1:
			kbytes = 1024; /* 1M preallocated memory */
			break;
		case I8XX_GC_MODE2:
			kbytes = 4 * 1024; /* 4M preallocated memory */
			break;
		case I8XX_GC_MODE3:
			kbytes = 8 * 1024; /* 8M preallocated memory */
			break;
		case I8XX_GC_MODE4:
			kbytes = 16 * 1024; /* 16M preallocated memory */
			break;
		case I8XX_GC_MODE5:
			kbytes = 32 * 1024; /* 32M preallocated memory */
			break;
		default:
			kbytes = 0; /* unexpected case */
		}
		break;
	case INTEL_BR_865:
		memval = pci_config_get8(softstate->tsoft_pcihdl, I8XX_CONF_GC);
		switch (memval & I8XX_GC_MODE_MASK) {
		case I8XX_GC_MODE1:
			kbytes = 1024; /* 1M preallocated memory */
			break;
		case I8XX_GC_MODE3:
			kbytes = 8 * 1024; /* 8M preallocated memory */
			break;
		case I8XX_GC_MODE4:
			kbytes = 16 * 1024; /* 16M preallocated memory */
			break;
		default:
			kbytes = 0; /* unexpected case */
		}
		break;
	default:
		kbytes = 0;
	}

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
		/* Make correction for some Intel chipsets */
		if ((softstate->tsoft_devid & VENDOR_ID_MASK) ==
		    INTEL_VENDOR_ID)
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
		int type;
		switch (st->tsoft_devid & VENDOR_ID_MASK) {
		case INTEL_VENDOR_ID:
			type = CHIP_IS_INTEL;
			break;
		case AMD_VENDOR_ID:
			type = CHIP_IS_AMD;
			break;
		default:
			type = 0;
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

		if ((st->tsoft_devid & VENDOR_ID_MASK) !=
		    INTEL_VENDOR_ID) {
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
	 * This ioctl is only for intel agp chipsets.
	 * It is not nessary for AMD8151 AGP bridge, because
	 * this register in AMD8151 does not control any hadware.
	 * It is  only provided for compatible with intel agp bridge
	 * Please refer to <<AMD8151 data sheet>> page 24,
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

		value = pci_config_get8(st->tsoft_pcihdl,
		    st->tsoft_acaptr + AGP_CONF_MISC);
		value |= AGP_MISC_APEN;
		pci_config_put8(st->tsoft_pcihdl,
		    st->tsoft_acaptr + AGP_CONF_MISC, value);
		break;

	}
	case AGP_TARGET_UNCONFIG:
	{
		uint32_t value1;
		uint8_t value2;

		ASSERT(st->tsoft_acaptr);

		pci_config_put16(st->tsoft_pcihdl,
		    st->tsoft_acaptr + AGP_CONF_CONTROL, 0x0);

		value2 = pci_config_get8(st->tsoft_pcihdl,
		    st->tsoft_acaptr + AGP_CONF_MISC);
		value2 &= ~AGP_MISC_APEN;
		pci_config_put8(st->tsoft_pcihdl,
		    st->tsoft_acaptr + AGP_CONF_MISC, value2);

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
