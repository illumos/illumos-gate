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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * DDR5 SPD5118 Hub Driver.
 *
 * The Hub has an integrated temperature sensor and a 1024 KiB EEPROM. This is
 * based on JESD300-5B.01, Version 1.5.1, May 2023. The device uses the lower
 * 7-bits of registers to retrieve access to the current page. The upper 7-bits
 * is used to get access to the current page of NVM data. The current page is
 * controlled through one of the volatile registers. There is also a second mode
 * that allows the device to be put into a 2-byte mode where you can access all
 * of the memory, but we just opt for the traditional paged mode.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/bitext.h>
#include <sys/sysmacros.h>
#include <sys/i2c/client.h>
#include <eedev.h>

/*
 * Hub Device Registers. This is a subset of the registers that are useful for
 * us. Note, this uses the same thermal readout mechanism as the spd5118 driver.
 * See that driver for more information on the temperature logic.
 */
#define	HUB_R_TYPE_MSB		0x00
#define	HUB_R_TYPE_LSB		0x01
#define	HUB_R_REV		0x02
#define	HUB_R_VID0		0x03
#define	HUB_R_VID1		0x04
#define	HUB_R_CAP		0x05
#define	HUB_R_CAP_GET_TS_SUP(r)		bitx8(r, 1, 1)
#define	HUB_R_CAP_GET_HUB(r)		bitx8(r, 0, 0)
#define	HUB_R_I2C_CFG		0x0b
#define	HUB_R_I2C_CFG_GET_MODE(r)	bitx8(r, 3, 3)
#define	HUB_R_I2C_CFG_GET_PAGE(r)	bitx8(r, 2, 0)
#define	HUB_R_I2C_CFG_SET_PAGE(r, v)	bitset8(r, 2, 0, v)
#define	HUB_R_TEMP_LSB		0x31
#define	HUB_R_TEMP_LSB_GET_TEMP(v)	bitx8(v, 7, 2)
#define	HUB_R_TEMP_MSB		0x32
#define	HUB_R_TEMP_MSB_GET_TEMP(v)	bitx8(v, 3, 0)
#define	HUB_R_TEMP_MSB_GET_SIGN(v)	bitx8(v, 4, 4)
#define	HUB_R_TEMP_MSB_SHIFT	6
#define	HUB_R_NVM_BASE		0x80
#define	HUB_R_REG_MAX		UINT8_MAX

/*
 * The temperature is measured in units of 0.25 degrees.
 */
#define	HUB_TEMP_RES	4

/*
 * Attributes of the device's size.
 */
#define	HUB_NVM_NPAGES		8
#define	HUB_NVM_PAGE_SIZE	128

typedef struct spd5118 {
	dev_info_t *spd_dip;
	i2c_client_t *spd_client;
	i2c_reg_hdl_t *spd_regs;
	uint8_t spd_vid[2];
	uint8_t spd_rev;
	uint8_t spd_cap;
	eedev_hdl_t *spd_eehdl;
	id_t spd_ksensor;
	kmutex_t spd_mutex;
	uint8_t spd_buf[I2C_REQ_MAX];
	uint8_t spd_raw[2];
	int64_t spd_temp;
} spd5118_t;

static const i2c_reg_acc_attr_t spd5118_reg_attr = {
	.i2cacc_version = I2C_REG_ACC_ATTR_V0,
	.i2cacc_addr_len = 1,
	.i2cacc_reg_len = 1,
	.i2cacc_addr_max = HUB_R_REG_MAX
};

static bool
spd5118_page_change(i2c_txn_t *txn, spd5118_t *spd, uint32_t page)
{
	uint8_t cfg;
	i2c_error_t err;

	VERIFY(MUTEX_HELD(&spd->spd_mutex));

	if (!i2c_reg_get(txn, spd->spd_regs, HUB_R_I2C_CFG, &cfg, sizeof (cfg),
	    &err)) {
		dev_err(spd->spd_dip, CE_WARN, "!failed to read cap register: "
		    "0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (false);
	}

	if (HUB_R_I2C_CFG_GET_PAGE(cfg) != page) {
		cfg = HUB_R_I2C_CFG_SET_PAGE(cfg, page);
		if (!i2c_reg_put(txn, spd->spd_regs, HUB_R_I2C_CFG, &cfg,
		    sizeof (cfg), &err)) {
			dev_err(spd->spd_dip, CE_WARN, "!failed to write cap "
			    "register: 0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
			return (false);
		}
	}

	return (true);
}

static int
spd5118_temp_read(void *arg, sensor_ioctl_scalar_t *scalar)
{
	int ret;
	uint8_t val[2];
	i2c_txn_t *txn;
	i2c_error_t err;
	spd5118_t *spd = arg;

	mutex_enter(&spd->spd_mutex);
	if (i2c_bus_lock(spd->spd_client, 0, &txn) != I2C_CORE_E_OK) {
		mutex_exit(&spd->spd_mutex);
		return (EINTR);
	}

	/*
	 * The hub specification is a bit unclear. It seems to suggest that that
	 * you shouldn't access other registers when you're not on page 0. As
	 * such, we always change back to page 0 out of an abundance of caution.
	 */
	if (!spd5118_page_change(txn, spd, 0)) {
		ret = EIO;
		goto done;
	}

	if (!i2c_reg_get(txn, spd->spd_regs, HUB_R_TEMP_LSB, val, sizeof (val),
	    &err)) {
		dev_err(spd->spd_dip, CE_WARN, "!failed to read temp "
		    "registers: 0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (EIO);
	}

	bcopy(val, spd->spd_raw, sizeof (val));
	uint64_t u64 = HUB_R_TEMP_LSB_GET_TEMP(spd->spd_raw[0]) |
	    (HUB_R_TEMP_MSB_GET_TEMP(spd->spd_raw[1]) << HUB_R_TEMP_MSB_SHIFT);
	if (HUB_R_TEMP_MSB_GET_SIGN(spd->spd_raw[1]) == 1) {
		u64 |= UINT64_MAX & ~((1 << 10) - 1);
	}
	spd->spd_temp = (int64_t)u64;
	scalar->sis_value = spd->spd_temp;

	/*
	 * The sensor is in units 0.25 Degrees C. According to the Table 65
	 * Temperature Sensor Performance, there are there accuracy ranges:
	 *
	 *  TYP 0.5, MAX 1.0	 75 <= T~A~ <= 95
	 *  TYP 1.0, MAX 2.0	 40 <= T~A~ <= 125
	 *  TYP 2.0, MAX 3.0	-40 <= T~A~ <= 125
	 */
	scalar->sis_unit = SENSOR_UNIT_CELSIUS;
	scalar->sis_gran = HUB_TEMP_RES;
	int64_t prec_temp = scalar->sis_value / HUB_TEMP_RES;
	if (75 <= prec_temp && prec_temp <= 95) {
		scalar->sis_prec = 1 * scalar->sis_gran;
	} else if (40 <= prec_temp && prec_temp <= 125) {
		scalar->sis_prec = 2 * scalar->sis_gran;
	} else {
		scalar->sis_prec = 3 * scalar->sis_gran;
	}
	ret = 0;

done:
	i2c_bus_unlock(txn);
	mutex_exit(&spd->spd_mutex);
	return (ret);
}

static const ksensor_ops_t spd5118_temp_ops = {
	.kso_kind = ksensor_kind_temperature,
	.kso_scalar = spd5118_temp_read
};

static int
spd5118_read(void *arg, struct uio *uio, uint32_t page, uint32_t pageoff,
    uint32_t nbytes)
{
	int ret;
	i2c_txn_t *txn;
	i2c_error_t err;
	spd5118_t *spd = arg;

	VERIFY3U(page, <, HUB_NVM_NPAGES);
	VERIFY3U(pageoff, <, HUB_NVM_PAGE_SIZE);

	mutex_enter(&spd->spd_mutex);
	if (i2c_bus_lock(spd->spd_client, 0, &txn) != I2C_CORE_E_OK) {
		mutex_exit(&spd->spd_mutex);
		return (EINTR);
	}

	if (!spd5118_page_change(txn, spd, page)) {
		ret = EIO;
		goto done;
	}

	/*
	 * We need to adjust the page offset to get us into the correct part of
	 * the register space.
	 */
	pageoff += HUB_R_NVM_BASE;
	if (i2c_reg_get(txn, spd->spd_regs, pageoff, spd->spd_buf, nbytes,
	    &err)) {
		ret = uiomove(spd->spd_buf, nbytes, UIO_READ, uio);
	} else {
		dev_err(spd->spd_dip, CE_WARN, "!failed to read %u bytes of "
		    "NVM at 0x%x on page %u: 0x%x/0x%x", nbytes, pageoff, page,
		    err.i2c_error, err.i2c_ctrl);
		ret = EIO;
	}

done:
	i2c_bus_unlock(txn);
	mutex_exit(&spd->spd_mutex);
	return (ret);
}

static const eedev_ops_t spd5118_eedev_ops = {
	.eo_read = spd5118_read
};

static bool
spd5118_i2c_init(spd5118_t *spd)
{
	i2c_errno_t err;

	if ((err = i2c_client_init(spd->spd_dip, 0, &spd->spd_client)) !=
	    I2C_CORE_E_OK) {
		dev_err(spd->spd_dip, CE_WARN, "failed to create i2c client: "
		    "0x%x", err);
		return (false);
	}

	if ((err = i2c_reg_handle_init(spd->spd_client, &spd5118_reg_attr,
	    &spd->spd_regs)) != I2C_CORE_E_OK) {
		dev_err(spd->spd_dip, CE_WARN, "failed to create register "
		    "handle: %s (0x%x)", i2c_client_errtostr(spd->spd_client,
		    err), err);
		return (false);
	}

	return (true);
}

/*
 * Read the MSB device type register to make sure that this is an SPD5118
 * device.
 */
static bool
spd5118_ident(spd5118_t *spd)
{
	uint8_t type[2];
	i2c_error_t err;

	if (!i2c_reg_get(NULL, spd->spd_regs, HUB_R_TYPE_MSB, type,
	    sizeof (type), &err)) {
		dev_err(spd->spd_dip, CE_WARN, "!failed to read type "
		    "registers: 0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (false);
	}

	/*
	 * The hub specification is a bit unclear. It seems to suggest that that
	 * you shouldn't access other registers when you're not on page 0. This
	 * may mean that we can't get the device ID. So if we read a zero ID,
	 * set the page to page 0 and try to read again.
	 */
	if (type[0] == 0 && type[1] == 0) {
		mutex_enter(&spd->spd_mutex);
		if (!spd5118_page_change(NULL, spd, 0)) {
			mutex_exit(&spd->spd_mutex);
			return (false);
		}
		mutex_exit(&spd->spd_mutex);

		if (!i2c_reg_get(NULL, spd->spd_regs, HUB_R_TYPE_MSB, type,
		    sizeof (type), &err)) {
			dev_err(spd->spd_dip, CE_WARN, "!failed to read type "
			    "registers: 0x%x/0x%x", err.i2c_error,
			    err.i2c_ctrl);
			return (false);
		}
	}

	if (type[0] != 0x51 || type[1] != 0x18) {
		dev_err(spd->spd_dip, CE_WARN, "encountered unsupported device "
		    "type: 0x%x/0x%x", type[0], type[1]);
		return (false);
	}

	if (!i2c_reg_get(NULL, spd->spd_regs, HUB_R_VID0, spd->spd_vid,
	    sizeof (spd->spd_vid), &err)) {
		dev_err(spd->spd_dip, CE_WARN, "!failed to read vid registers: "
		    "0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (false);
	}

	if (!i2c_reg_get(NULL, spd->spd_regs, HUB_R_REV, &spd->spd_rev,
	    sizeof (spd->spd_rev), &err)) {
		dev_err(spd->spd_dip, CE_WARN, "!failed to read rev register: "
		    "0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (false);
	}

	if (!i2c_reg_get(NULL, spd->spd_regs, HUB_R_CAP, &spd->spd_cap,
	    sizeof (spd->spd_cap), &err)) {
		dev_err(spd->spd_dip, CE_WARN, "!failed to read cap register: "
		    "0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (false);
	}

	return (true);
}

static bool
spd5118_eedev_init(spd5118_t *spd)
{
	int ret;
	eedev_reg_t reg;

	bzero(&reg, sizeof (reg));
	reg.ereg_vers = EEDEV_REG_VERS;
	reg.ereg_size = HUB_NVM_NPAGES * HUB_NVM_PAGE_SIZE;
	reg.ereg_seg = HUB_NVM_PAGE_SIZE;
	reg.ereg_read_gran = 1;
	reg.ereg_ro = true;
	reg.ereg_dip = spd->spd_dip;
	reg.ereg_driver = spd;
	reg.ereg_name = NULL;
	reg.ereg_ops = &spd5118_eedev_ops;
	reg.ereg_max_read = MIN(i2c_reg_max_read(spd->spd_regs),
	    I2C_REQ_MAX / 2);

	if ((ret = eedev_create(&reg, &spd->spd_eehdl)) != 0) {
		dev_err(spd->spd_dip, CE_WARN, "failed to create eedev device: "
		    "%d", ret);
		return (false);
	}

	return (true);
}

static void
spd5118_cleanup(spd5118_t *spd)
{
	(void) ksensor_remove(spd->spd_dip, KSENSOR_ALL_IDS);
	eedev_fini(spd->spd_eehdl);
	i2c_reg_handle_destroy(spd->spd_regs);
	i2c_client_destroy(spd->spd_client);
	mutex_destroy(&spd->spd_mutex);
	ddi_set_driver_private(spd->spd_dip, NULL);
	spd->spd_dip = NULL;
	kmem_free(spd, sizeof (spd5118_t));
}

static int
spd5118_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret;
	spd5118_t *spd;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	spd = kmem_zalloc(sizeof (spd5118_t), KM_SLEEP);
	spd->spd_dip = dip;
	ddi_set_driver_private(dip, spd);
	mutex_init(&spd->spd_mutex, NULL, MUTEX_DRIVER, NULL);

	if (!spd5118_i2c_init(spd))
		goto cleanup;

	if (!spd5118_ident(spd))
		goto cleanup;

	if (!spd5118_eedev_init(spd))
		goto cleanup;

	if ((ret = i2c_client_ksensor_create_scalar(spd->spd_client,
	    SENSOR_KIND_TEMPERATURE, &spd5118_temp_ops, spd, "temp",
	    &spd->spd_ksensor)) != 0) {
		dev_err(spd->spd_dip, CE_WARN, "failed to create ksensor: %d",
		    ret);
		goto cleanup;
	}

	return (DDI_SUCCESS);

cleanup:
	spd5118_cleanup(spd);
	return (DDI_FAILURE);
}

static int
spd5118_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	spd5118_t *spd;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	spd = ddi_get_driver_private(dip);
	if (spd == NULL) {
		dev_err(dip, CE_WARN, "asked to detach, but missing private "
		    "data");
		return (DDI_FAILURE);
	}
	VERIFY3P(spd->spd_dip, ==, dip);

	spd5118_cleanup(spd);
	return (DDI_SUCCESS);
}

static struct dev_ops spd5118_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = spd5118_attach,
	.devo_detach = spd5118_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed
};

static struct modldrv spd5118_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "SPD5118 driver",
	.drv_dev_ops = &spd5118_dev_ops
};

static struct modlinkage spd5118_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &spd5118_modldrv, NULL }
};


int
_init(void)
{
	return (mod_install(&spd5118_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&spd5118_modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&spd5118_modlinkage));
}
