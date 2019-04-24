/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Intel Platform Controller Hub (PCH) Thermal Sensor Driver
 *
 * The Intel PCH is a chip that was introduced around the Nehalem generation
 * that provides many services for the broader system on a discrete chip from
 * the CPU. While it existed prior to the Nehalem generation, it was previously
 * two discrete chips called the Northbridge and Southbridge. Sometimes this
 * device is also called a 'chipset'.
 *
 * The PCH contains everything from a USB controller, to an AHCI controller, to
 * clocks, the Intel Management Engine, and more. Relevant to this driver is its
 * thermal sensor which gives us the ability to read the temperature sensor that
 * is embedded in the PCH.
 *
 * The format of this sensor varies based on the generation of the chipset. The
 * current driver supports the following chipsets organized by datasheet, which
 * corresponds with a change in format that was introduced in the Haswell
 * generation:
 *
 *  - Intel 8 Series PCH
 *  - Intel 9 Series PCH
 *  - Intel C610 Series and X99 PCH
 *  - Intel C620 Series PCH
 *  - Intel 100 Series PCH
 *  - Intel 200 Series and Z730 PCH
 *  - Intel Sunrise Point-LP (Kaby Lake-U) PCH
 *  - Intel 300 Series and C240 Chipset
 *
 * The following chipsets use a different format and are not currently
 * supported:
 *
 *  - Intel 5 Series and Xeon 3400 PCH
 *  - Intel 6 Series PCH
 *  - Intel 7 Series PCH
 *  - Intel C600 Series and X79 PCH
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/sensors.h>

/*
 * In all cases the data we care about is in the first PCI bar, bar 0. Per
 * pci(4)/pcie(4), this is always going to be register number 1.
 */
#define	PCHTEMP_RNUMBER	1

/*
 * The PCH Temperature Sensor has a resolution of 1/2 a degree. This is a
 * resolution of 2 in our parlance. The register reads 50 C higher than it is.
 * Therefore our offset is 50 shifted over by one.
 */
#define	PCHTEMP_TEMP_RESOLUTION	2
#define	PCHTEMP_TEMP_OFFSET	(50 << 1)

/*
 * This register offset has the temperature that we want to read in the lower
 * 8-bits. The resolution and offset are described above.
 */
#define	PCHTEMP_REG_TEMP	0x00
#define	PCHTEMP_REG_TEMP_TSR	0x00ff

/*
 * Thermal Sensor Enable and Lock (TSEL) register. This register is a byte wide
 * and has two bits that we care about. The ETS bit, enable thermal sensor,
 * indicates whether or not the sensor is enabled. The control for this can be
 * locked which is the PLDB, Policy Lock-Down Bit, bit. Which restricts
 * additional control of this register.
 */
#define	PCHTEMP_REG_TSEL	0x08
#define	PCHTEMP_REG_TSEL_ETS	0x01
#define	PCHTEMP_REG_TSEL_PLDB	0x80

/*
 * Threshold registers for the thermal sensors. These indicate the catastrophic,
 * the high alert threshold, and the low alert threshold respectively.
 */
#define	PCHTEMP_REG_CTT		0x10
#define	PCHTEMP_REG_TAHV	0x14
#define	PCHTEMP_REG_TALV	0x18

typedef struct pchtemp {
	dev_info_t		*pcht_dip;
	int			pcht_fm_caps;
	caddr_t			pcht_base;
	ddi_acc_handle_t	pcht_handle;
	kmutex_t		pcht_mutex;	/* Protects members below */
	uint16_t		pcht_temp_raw;
	uint8_t			pcht_tsel_raw;
	uint16_t		pcht_ctt_raw;
	uint16_t		pcht_tahv_raw;
	uint16_t		pcht_talv_raw;
	int64_t			pcht_temp;
} pchtemp_t;

void *pchtemp_state;

static pchtemp_t *
pchtemp_find_by_dev(dev_t dev)
{
	return (ddi_get_soft_state(pchtemp_state, getminor(dev)));
}

static int
pchtemp_read_check(pchtemp_t *pch)
{
	ddi_fm_error_t de;

	if (!DDI_FM_ACC_ERR_CAP(pch->pcht_fm_caps)) {
		return (DDI_FM_OK);
	}

	ddi_fm_acc_err_get(pch->pcht_handle, &de, DDI_FME_VERSION);
	ddi_fm_acc_err_clear(pch->pcht_handle, DDI_FME_VERSION);
	return (de.fme_status);
}

static int
pchtemp_read(pchtemp_t *pch)
{
	uint16_t temp, ctt, tahv, talv;
	uint8_t tsel;

	ASSERT(MUTEX_HELD(&pch->pcht_mutex));

	temp = ddi_get16(pch->pcht_handle,
	    (uint16_t *)((uintptr_t)pch->pcht_base + PCHTEMP_REG_TEMP));
	tsel = ddi_get8(pch->pcht_handle,
	    (uint8_t *)((uintptr_t)pch->pcht_base + PCHTEMP_REG_TSEL));
	ctt = ddi_get16(pch->pcht_handle,
	    (uint16_t *)((uintptr_t)pch->pcht_base + PCHTEMP_REG_CTT));
	tahv = ddi_get16(pch->pcht_handle,
	    (uint16_t *)((uintptr_t)pch->pcht_base + PCHTEMP_REG_TAHV));
	talv = ddi_get16(pch->pcht_handle,
	    (uint16_t *)((uintptr_t)pch->pcht_base + PCHTEMP_REG_TALV));

	if (pchtemp_read_check(pch) != DDI_FM_OK) {
		dev_err(pch->pcht_dip, CE_WARN, "failed to read temperature "
		    "data due to FM device error");
		return (EIO);
	}

	pch->pcht_temp_raw = temp;
	pch->pcht_tsel_raw = tsel;
	pch->pcht_ctt_raw = ctt;
	pch->pcht_tahv_raw = tahv;
	pch->pcht_talv_raw = talv;

	if ((tsel & PCHTEMP_REG_TSEL_ETS) == 0) {
		return (ENXIO);
	}

	pch->pcht_temp = (temp & PCHTEMP_REG_TEMP_TSR) - PCHTEMP_TEMP_OFFSET;

	return (0);
}

static int
pchtemp_open(dev_t *devp, int flags, int otype, cred_t *credp)
{
	pchtemp_t *pch;

	if (crgetzoneid(credp) != GLOBAL_ZONEID || drv_priv(credp)) {
		return (EPERM);
	}

	if ((flags & (FEXCL | FNDELAY | FWRITE)) != 0) {
		return (EINVAL);
	}

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	pch = pchtemp_find_by_dev(*devp);
	if (pch == NULL) {
		return (ENXIO);
	}

	return (0);
}

static int
pchtemp_ioctl_kind(intptr_t arg, int mode)
{
	sensor_ioctl_kind_t kind;

	bzero(&kind, sizeof (sensor_ioctl_kind_t));
	kind.sik_kind = SENSOR_KIND_TEMPERATURE;

	if (ddi_copyout((void *)&kind, (void *)arg, sizeof (kind),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
pchtemp_ioctl_temp(pchtemp_t *pch, intptr_t arg, int mode)
{
	int ret;
	sensor_ioctl_temperature_t temp;

	bzero(&temp, sizeof (temp));

	mutex_enter(&pch->pcht_mutex);
	if ((ret = pchtemp_read(pch)) != 0) {
		mutex_exit(&pch->pcht_mutex);
		return (ret);
	}

	temp.sit_unit = SENSOR_UNIT_CELSIUS;
	temp.sit_gran = PCHTEMP_TEMP_RESOLUTION;
	temp.sit_temp = pch->pcht_temp;
	mutex_exit(&pch->pcht_mutex);

	if (ddi_copyout(&temp, (void *)arg, sizeof (temp),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
pchtemp_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	pchtemp_t *pch;

	pch = pchtemp_find_by_dev(dev);
	if (pch == NULL) {
		return (ENXIO);
	}

	if ((mode & FREAD) == 0) {
		return (EINVAL);
	}

	switch (cmd) {
	case SENSOR_IOCTL_TYPE:
		return (pchtemp_ioctl_kind(arg, mode));
	case SENSOR_IOCTL_TEMPERATURE:
		return (pchtemp_ioctl_temp(pch, arg, mode));
	default:
		return (ENOTTY);
	}
}

static int
pchtemp_close(dev_t dev, int flags, int otype, cred_t *credp)
{
	return (0);
}

static void
pchtemp_cleanup(pchtemp_t *pch)
{
	int inst;

	ASSERT3P(pch->pcht_dip, !=, NULL);
	inst = ddi_get_instance(pch->pcht_dip);

	ddi_remove_minor_node(pch->pcht_dip, NULL);

	if (pch->pcht_handle != NULL) {
		ddi_regs_map_free(&pch->pcht_handle);
	}

	if (pch->pcht_fm_caps != DDI_FM_NOT_CAPABLE) {
		ddi_fm_fini(pch->pcht_dip);
	}

	mutex_destroy(&pch->pcht_mutex);
	ddi_soft_state_free(pchtemp_state, inst);
}

static int
pchtemp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int inst, ret;
	pchtemp_t *pch;
	off_t memsize;
	ddi_device_acc_attr_t da;
	ddi_iblock_cookie_t iblk;
	char name[1024];

	switch (cmd) {
	case DDI_RESUME:
		return (DDI_SUCCESS);
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	inst = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(pchtemp_state, inst) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to allocate soft state entry %d",
		    inst);
		return (DDI_FAILURE);
	}

	pch = ddi_get_soft_state(pchtemp_state, inst);
	if (pch == NULL) {
		dev_err(dip, CE_WARN, "failed to retrieve soft state entry %d",
		    inst);
		return (DDI_FAILURE);
	}
	pch->pcht_dip = dip;

	pch->pcht_fm_caps = DDI_FM_ACCCHK_CAPABLE;
	ddi_fm_init(dip, &pch->pcht_fm_caps, &iblk);

	mutex_init(&pch->pcht_mutex, NULL, MUTEX_DRIVER, NULL);

	if (ddi_dev_regsize(dip, PCHTEMP_RNUMBER, &memsize) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to obtain register size for "
		    "register set %d", PCHTEMP_RNUMBER);
		goto err;
	}

	bzero(&da, sizeof (ddi_device_acc_attr_t));
	da.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	da.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	da.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (DDI_FM_ACC_ERR_CAP(pch->pcht_fm_caps)) {
		da.devacc_attr_access = DDI_FLAGERR_ACC;
	} else {
		da.devacc_attr_access = DDI_DEFAULT_ACC;
	}

	if ((ret = ddi_regs_map_setup(dip, PCHTEMP_RNUMBER, &pch->pcht_base,
	    0, memsize, &da, &pch->pcht_handle)) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to map register set %d: %d",
		    PCHTEMP_RNUMBER, ret);
		goto err;
	}

	if (snprintf(name, sizeof (name), "ts.%d", inst) >= sizeof (name)) {
		dev_err(dip, CE_WARN, "failed to construct minor node name, "
		    "name too long");
		goto err;
	}

	if (ddi_create_minor_node(pch->pcht_dip, name, S_IFCHR, (minor_t)inst,
	    DDI_NT_SENSOR_TEMP_PCH, 0) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to create minor node %s", name);
		goto err;
	}

	/*
	 * Attempt a single read to lock in the temperature. We don't mind if
	 * this fails for some reason.
	 */
	mutex_enter(&pch->pcht_mutex);
	(void) pchtemp_read(pch);
	mutex_exit(&pch->pcht_mutex);

	return (DDI_SUCCESS);

err:
	pchtemp_cleanup(pch);
	return (DDI_FAILURE);
}

static int
pchtemp_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **resultp)
{
	pchtemp_t *pch;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		pch = pchtemp_find_by_dev((dev_t)arg);
		if (pch == NULL) {
			return (DDI_FAILURE);
		}

		*resultp = pch->pcht_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(uintptr_t)getminor((dev_t)arg);
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
pchtemp_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int inst;
	pchtemp_t *pch;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	inst = ddi_get_instance(dip);
	pch = ddi_get_soft_state(pchtemp_state, inst);
	if (pch == NULL) {
		dev_err(dip, CE_WARN, "asked to detached instance %d, but "
		    "it does not exist in soft state", inst);
		return (DDI_FAILURE);
	}

	pchtemp_cleanup(pch);
	return (DDI_SUCCESS);
}

static struct cb_ops pchtemp_cb_ops = {
	.cb_open = pchtemp_open,
	.cb_close = pchtemp_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = pchtemp_ioctl,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_flag = D_MP,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev
};

static struct dev_ops pchtemp_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = pchtemp_getinfo,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = pchtemp_attach,
	.devo_detach = pchtemp_detach,
	.devo_reset = nodev,
	.devo_power = ddi_power,
	.devo_quiesce = ddi_quiesce_not_needed,
	.devo_cb_ops = &pchtemp_cb_ops
};

static struct modldrv pchtemp_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Intel PCH Thermal Sensor",
	.drv_dev_ops = &pchtemp_dev_ops
};

static struct modlinkage pchtemp_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &pchtemp_modldrv, NULL }
};

int
_init(void)
{
	int ret;

	if (ddi_soft_state_init(&pchtemp_state, sizeof (pchtemp_t), 1) !=
	    DDI_SUCCESS) {
		return (ENOMEM);
	}

	if ((ret = mod_install(&pchtemp_modlinkage)) != 0) {
		ddi_soft_state_fini(&pchtemp_state);
		return (ret);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&pchtemp_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&pchtemp_modlinkage)) != 0) {
		return (ret);
	}

	ddi_soft_state_fini(&pchtemp_state);
	return (ret);
}
