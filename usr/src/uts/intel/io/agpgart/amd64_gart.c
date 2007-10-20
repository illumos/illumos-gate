/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/sunldi.h>
#include <sys/file.h>
#include <sys/agpgart.h>
#include <sys/agp/agpdefs.h>
#include <sys/agp/agpamd64gart_io.h>

#define	MAX_GART_INSTS		8
#define	GETSOFTC(instance)	((amd64_gart_softstate_t *)	\
    ddi_get_soft_state(amd64_gart_glob_soft_handle, (instance)));
#define	DEV2INST(dev)		(getminor(dev))
#define	INST2NODENUM(inst)	(inst)

int amd64_debug_var = 0;
#define	AMD64DB_PRINT1(fmt)	if (amd64_debug_var == 1) cmn_err fmt
#define	AMD64DB_PRINT2(fmt)	if (amd64_debug_var >= 1) cmn_err fmt

typedef struct amd64_gart_softstate {
	dev_info_t		*gsoft_dip;
	ddi_acc_handle_t	gsoft_pcihdl;
	kmutex_t		gsoft_lock;
}amd64_gart_softstate_t;

static void *amd64_gart_glob_soft_handle;

static uint64_t
amd64_get_aperbase(amd64_gart_softstate_t *sc)
{
	uint32_t	value;
	uint64_t	aper_base;

	/* amd64 aperture base support 40 bits and 32M aligned */
	value = pci_config_get32(sc->gsoft_pcihdl,
	    AMD64_APERTURE_BASE) & AMD64_APERBASE_MASK;
	aper_base = (uint64_t)value << AMD64_APERBASE_SHIFT;
	return (aper_base);
}

static size_t
amd64_get_apersize(amd64_gart_softstate_t *sc)
{
	uint32_t	value;
	size_t		size;

	value = pci_config_get32(sc->gsoft_pcihdl, AMD64_APERTURE_CONTROL);

	value = (value & AMD64_APERSIZE_MASK) >> 1;

	/* aper size = 2^value x 32 */
	switch (value) {
		case  0x0:
			size = 32;
			break;
		case  0x1:
			size = 64;
			break;
		case  0x2:
			size = 128;
			break;
		case  0x3:
			size = 256;
			break;
		case  0x4:
			size = 512;
			break;
		case  0x5:
			size = 1024;
			break;
		case  0x6:
			size = 2048;
			break;
		default:		/* reserved */
			size = 0;
	};

	return (size);
}

static void
amd64_invalidate_gtlb(amd64_gart_softstate_t *sc)
{
	uint32_t value;

	value = pci_config_get32(sc->gsoft_pcihdl, AMD64_GART_CACHE_CTL);
	value |= AMD64_INVALID_CACHE;

	pci_config_put32(sc->gsoft_pcihdl, AMD64_GART_CACHE_CTL, value);
}

static void
amd64_enable_gart(amd64_gart_softstate_t *sc, int enable)
{
	uint32_t aper_ctl;
	uint32_t aper_base;
	uint32_t gart_ctl;
	uint32_t gart_base;

	aper_ctl = pci_config_get32(sc->gsoft_pcihdl, AMD64_APERTURE_CONTROL);
	AMD64DB_PRINT1((CE_NOTE, "before: aper_ctl = %x", aper_ctl));
	aper_base = pci_config_get32(sc->gsoft_pcihdl, AMD64_APERTURE_BASE);
	gart_ctl = pci_config_get32(sc->gsoft_pcihdl, AMD64_GART_CACHE_CTL);
	gart_base = pci_config_get32(sc->gsoft_pcihdl, AMD64_GART_BASE);
#ifdef lint
	aper_base = aper_base;
	gart_ctl = gart_ctl;
	gart_base = gart_base;
#endif /* lint */
	AMD64DB_PRINT1((CE_NOTE, "before: aper_base = %x", aper_base));
	AMD64DB_PRINT1((CE_NOTE, "before: gart_ctl = %x", gart_ctl));
	AMD64DB_PRINT1((CE_NOTE, "before: gart_base = %x", gart_base));
	if (enable) {
		aper_ctl |= AMD64_GARTEN;
		aper_ctl &= ~(AMD64_DISGARTCPU | AMD64_DISGARTIO);
	} else
		aper_ctl &= (~AMD64_GARTEN);

	pci_config_put32(sc->gsoft_pcihdl, AMD64_APERTURE_CONTROL, aper_ctl);
}

/*ARGSUSED*/
static int
amd64_gart_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,
    void *arg, void **resultp)
{
	amd64_gart_softstate_t *st;
	int instance, rval = DDI_FAILURE;
	dev_t dev;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		instance = DEV2INST(dev);
		st = ddi_get_soft_state(amd64_gart_glob_soft_handle, instance);
		if (st != NULL) {
			mutex_enter(&st->gsoft_lock);
			*resultp = st->gsoft_dip;
			mutex_exit(&st->gsoft_lock);
			rval = DDI_SUCCESS;
		} else {
			*resultp = NULL;
		}

		break;
	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = DEV2INST(dev);
		*resultp = (void *)(uintptr_t)instance;
		rval = DDI_SUCCESS;
		break;
	default:
		break;
	}

	return (rval);
}

static int
amd64_gart_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance;
	amd64_gart_softstate_t	*sc;
	int			status;
	char			buf[80];

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_RESUME:
		/* Nothing special is needed for resume. */
		return (DDI_SUCCESS);

	case DDI_ATTACH:
		break;
	}

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(amd64_gart_glob_soft_handle, instance) !=
	    DDI_SUCCESS)
		return (DDI_FAILURE);

	sc = ddi_get_soft_state(amd64_gart_glob_soft_handle, instance);
	mutex_init(&sc->gsoft_lock, NULL, MUTEX_DRIVER, NULL);
	sc->gsoft_dip = dip;
	status = pci_config_setup(dip, &sc->gsoft_pcihdl);
	if (status != DDI_SUCCESS) {
		ddi_soft_state_free(amd64_gart_glob_soft_handle, instance);
		return (DDI_FAILURE);
	}
	(void) sprintf(buf, "%s-%d", AMD64GART_NAME, instance);
	status = ddi_create_minor_node(dip, buf, S_IFCHR,
	    INST2NODENUM(instance), DDI_NT_AGP_CPUGART, 0);
	if (status != DDI_SUCCESS) {
		pci_config_teardown(&sc->gsoft_pcihdl);
		ddi_soft_state_free(amd64_gart_glob_soft_handle, instance);
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
amd64_gart_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int			instance;
	amd64_gart_softstate_t	*sc;
	char			buf[80];

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_SUSPEND:
		/* Nothing special is needed for suspend */
		return (DDI_SUCCESS);

	case DDI_DETACH:
		break;
	}

	instance = ddi_get_instance(dip);
	sc = ddi_get_soft_state(amd64_gart_glob_soft_handle, instance);

	(void) sprintf(buf, "%s-%d", AMD64GART_NAME, instance);
	ddi_remove_minor_node(dip, buf);
	pci_config_teardown(&sc->gsoft_pcihdl);
	mutex_destroy(&sc->gsoft_lock);
	ddi_soft_state_free(amd64_gart_glob_soft_handle, instance);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
amd64_gart_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *cred, int *rval)
{
	int instance;
	amd64_gart_softstate_t *sc;
	static char kernel_only[] =
	    "amd64_gart_ioctl: is a kernel only ioctl";

	if (!(mode & FKIOCTL)) {
		AMD64DB_PRINT2((CE_CONT, kernel_only));
		return (ENXIO);
	}
	instance = DEV2INST(dev);
	sc = GETSOFTC(instance);

	if (sc == NULL)
		return (ENXIO);
	mutex_enter(&sc->gsoft_lock);

	switch (cmd) {
	case AMD64_GET_INFO:
	{
		amdgart_info_t info;

		info.cgart_aperbase = amd64_get_aperbase(sc);
		info.cgart_apersize = amd64_get_apersize(sc);

		if (ddi_copyout(&info, (void *)data,
		    sizeof (amdgart_info_t), mode)) {
			mutex_exit(&sc->gsoft_lock);
			return (EFAULT);
		}
		break;
	}
	case AMD64_SET_GART_ADDR:
	{
		uint32_t addr;

		if (ddi_copyin((void *)data, &addr, sizeof (uint32_t), mode)) {
			mutex_exit(&sc->gsoft_lock);
			return (EFAULT);
		}

		pci_config_put32(sc->gsoft_pcihdl, AMD64_GART_BASE, addr);
		amd64_enable_gart(sc, 1);

		break;
	}
	case AMD64_FLUSH_GTLB:
	{
		amd64_invalidate_gtlb(sc);

		break;
	}
	case AMD64_CONFIGURE:
	{
		/* reserved */
		break;
	}
	case AMD64_UNCONFIG:
	{
		amd64_enable_gart(sc, 0);
		pci_config_put32(sc->gsoft_pcihdl, AMD64_GART_BASE, 0x00000000);

		break;
	}
	default:
		mutex_exit(&sc->gsoft_lock);
		return (ENXIO);

	}

	mutex_exit(&sc->gsoft_lock);

	return (0);
}

/*ARGSUSED*/
static int
amd64_gart_open(dev_t *dev, int flag, int otyp, cred_t *cred)
{
	int			instance;
	amd64_gart_softstate_t	*sc;

	if (!(flag & FKLYR))
		return (ENXIO);

	instance = DEV2INST(*dev);
	sc = GETSOFTC(instance);

	if (sc == NULL)
		return (ENXIO);

	return (0);
}

/*ARGSUSED*/
static int
amd64_gart_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	int			instance;
	amd64_gart_softstate_t	*sc;

	instance = DEV2INST(dev);
	sc = GETSOFTC(instance);

	if (sc == NULL)
		return (ENXIO);

	return (0);
}

static  struct  cb_ops  amd64_gart_cb_ops = {
	amd64_gart_open,	/* cb_open() */
	amd64_gart_close,	/* cb_close() */
	nodev,			/* cb_strategy() */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read() */
	nodev,			/* cb_write() */
	amd64_gart_ioctl,	/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* cb_stream */
	D_NEW | D_MP,		/* cb_flag */
	CB_REV,			/* cb_ops version? */
	nodev,			/* cb_aread() */
	nodev,			/* cb_awrite() */
};

/* device operations */
static struct dev_ops amd64_gart_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	amd64_gart_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	amd64_gart_attach,	/* devo_attach */
	amd64_gart_detach,	/* devo_detach */
	nodev,			/* devo_reset */
	&amd64_gart_cb_ops,	/* devo_cb_ops */
	0,			/* devo_bus_ops */
	0,			/* devo_power */
};

static  struct modldrv modldrv = {
	&mod_driverops,
	"AGP AMD gart driver v%I%",
	&amd64_gart_ops,
};

static  struct modlinkage modlinkage = {
	MODREV_1,		/* MODREV_1 is indicated by manual */
	&modldrv,
	NULL
};


int
_init(void)
{
	int ret = DDI_SUCCESS;

	ret = ddi_soft_state_init(&amd64_gart_glob_soft_handle,
	    sizeof (amd64_gart_softstate_t),
	    MAX_GART_INSTS);

	if (ret)
		return (ret);
	if ((ret = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&amd64_gart_glob_soft_handle);
		return (ret);
	}
	return (DDI_SUCCESS);
}

int
_info(struct  modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;
	if ((ret = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&amd64_gart_glob_soft_handle);
	}
	return (ret);
}
