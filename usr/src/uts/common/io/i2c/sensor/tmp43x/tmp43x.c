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
 * TI TMP401, TMP411, TMP431, TMP432, and TMP435 driver.
 *
 * This driver supports a variety of TI TMP4xx devices that have relatively
 * similar programming semantics and register layouts. They all share one
 * critical piece, that the various devices can be identified by a combination
 * of the manufacturer and device id registers in 0xfe and 0xff respectively.
 *
 * The temperature data is stored as a 12-bit unsigned value that is offset from
 * one of two modes depending on the device temperature range and measure in
 * units of 0.0625 C. The temperature registers are split between a high and a
 * low byte. The hardware allows you to either perform a two byte read of the
 * high byte to get a coherent read or otherwise it will latch the low byte on
 * the read of a high byte. The temperature data comes in two forms, a standard
 * form in the range 0 to 127 C. However, the extended range operates from -55
 * to 150 C. The main difference is that in extended mode, there is a -64 C
 * offset applied to the read value.
 *
 * We use our normal register interface to take care of the 2-byte endian reads.
 * The rest use a normal SMBus register interface. Like other devices, this
 * hardware has a shutdown mode that we will take the device out of if we find
 * it in it.
 *
 * Here are the major differences between device generations:
 *
 * DEV     LOCAL  REMOTE  NFACTOR   BETA    MIN/MAX  LRES
 * TMP401  1      1       No        No      No       YES
 * TMP411  1      1       Yes       No      Yes      YES
 * TMP431  1      1       Yes       Yes     No       No
 * TMP432  1      2       Yes       Yes     No       No
 * TMP435  1      1       Yes       Yes     No       No
 *
 * These devices have evolved a bit over time. The TMP401 does not have n-factor
 * correction or beta compensation support. n-factor supported was added in the
 * TMP411 devices and BETA compensation TMP43x devices. The TMP401 and TMP411
 * have a programmable resolution for the local measurement. TMP411 is the only
 * device with a maximum and minimum register values. Those are not plumbed
 * through in the driver right now.
 *
 * These devices also support programmable alert thresholds, which are not
 * exposed in the sensor framework today.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/bitext.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/i2c/client.h>
#include <sys/sensors.h>


/*
 * The device registers across these families are a bit of a mess. Some
 * registers, but not all have different addresses for read and for write. These
 * are all in slightly different places. All devices support a manufacturer and
 * device ID in the same spot here. We use logical registers to identify things
 * here and then use device-specific information to know how to dispatch it.
 * Only a subset of the registers that we use are listed here. While we don't
 * use them today, the registers related to device-tree based configuration, the
 * n-factor and beta compensation are also included here. They are only
 * supported by the TMP43x devices.
 */
typedef enum {
	TMP43X_R_TEMP_LOCAL	= 0,
	TMP43X_R_TEMP_REM1,
	TMP43X_R_TEMP_REM2,
	TMP43X_R_CFG1,
	TMP43X_R_NFACTOR1,
	TMP43X_R_NFACTOR2,
	TMP43X_R_BETA1,
	TMP43X_R_BETA2,
	TMP43X_R_RES
} tmp43x_reg_t;

#define	TMP43X_NSESNORS	3

typedef enum {
	TMP43X_REG_TYPE_TEMP,
	TMP43X_REG_TYPE_1B
} tmp43x_reg_type_t;

typedef struct tmp43x_reg_info {
	tmp43x_reg_t tri_reg;
	bool tri_ro;
	uint8_t tri_read;
	uint8_t tri_write;
} tmp43x_reg_info_t;

static const tmp43x_reg_info_t tmp43x_regs_401[] = {
	{ TMP43X_R_TEMP_LOCAL, true, 0x0, 0x0 },
	{ TMP43X_R_TEMP_REM1, true, 0x1, 0x1 },
	{ TMP43X_R_CFG1, false, 0x3, 0x9 },
	{ TMP43X_R_RES, false, 0x1a, 0x1a }
};

static const tmp43x_reg_info_t tmp43x_regs_411[] = {
	{ TMP43X_R_TEMP_LOCAL, true, 0x0, 0x0 },
	{ TMP43X_R_TEMP_REM1, true, 0x1, 0x1 },
	{ TMP43X_R_CFG1, false, 0x3, 0x9 },
	{ TMP43X_R_RES, false, 0x1a, 0x1a },
	{ TMP43X_R_NFACTOR1, false, 0x18, 0x18 }
};

static const tmp43x_reg_info_t tmp43x_regs_431_435[] = {
	{ TMP43X_R_TEMP_LOCAL, true, 0x0, 0x0 },
	{ TMP43X_R_TEMP_REM1, true, 0x1, 0x1 },
	{ TMP43X_R_CFG1, false, 0x3, 0x9 },
	{ TMP43X_R_NFACTOR1, false, 0x18, 0x18 },
	{ TMP43X_R_BETA1, false, 0x25, 0x25 },
};

static const tmp43x_reg_info_t tmp43x_regs_432[] = {
	{ TMP43X_R_TEMP_LOCAL, true, 0x0, 0x0 },
	{ TMP43X_R_TEMP_REM1, true, 0x1, 0x1 },
	{ TMP43X_R_TEMP_REM2, true, 0x23, 0x23 },
	{ TMP43X_R_CFG1, false, 0x3, 0x9 },
	{ TMP43X_R_NFACTOR1, false, 0x27, 0x27 },
	{ TMP43X_R_NFACTOR2, false, 0x28, 0x28 },
	{ TMP43X_R_BETA1, false, 0x25, 0x25 },
	{ TMP43X_R_BETA2, false, 0x26, 0x26 },
};

/*
 * Fixed location registers that each device doesn't have to define. These
 * define the vendor and device IDs.
 */
#define	TMP43X_R_MFGID	0xfe
#define	TMP43X_MFG_TI	0x55
#define	TMP43X_R_DEVID	0xff

typedef enum {
	TMP43X_DEV_401	= 0x11,
	/* The 411E/411DE use the same code */
	TMP43X_DEV_411A	= 0x12,
	TMP43X_DEV_411B	= 0x13,
	TMP43X_DEV_411C	= 0x10,
	TMP43X_DEV_431	= 0x31,
	TMP43X_DEV_432	= 0x32,
	TMP43X_DEV_435	= 0x35
} tmp43x_dev_t;

/*
 * The temperature is a 12 bit value in temp[15, 4]. The granularity is 16 as we
 * have 4 bits of data here.
 */
#define	TMP43X_TEMP_GRAN	16
#define	TMP43X_TEMP_GET_VAL(r)	bitx16(r, 15, 4)
#define	TMP43X_TEMP_EXTD_ADJ	(-65 * TMP43X_TEMP_GRAN)
#define	TMP43X_TEMP_PREC	(TMP43X_TEMP_GRAN * 1)

/*
 * Common configuration register bits.
 */
#define	TMP43X_CFG1_GET_SD(r)		bitx8(r, 6, 6)
#define	TMP43X_CFG1_SET_SD(r, v)	bitset8(r, 6, 6, v)
#define	TMP43X_CFG1_SD_RUN	0
#define	TMP43X_CFG1_SD_STOP	1
#define	TMP43X_CFG1_GET_RANGE(r)	bitx8(r, 2, 2)
#define	TMP43X_CFG1_RANGE_STD	0
#define	TMP43X_CFG1_RANGE_EXT	1

/*
 * Resolution register.
 */
#define	TMP43X_RES_SET_RES(r, v)	bitset8(r, 1, 0, v)
#define	TMP43X_RES_RES_9B	0
#define	TMP43X_RES_RES_10B	1
#define	TMP43X_RES_RES_11B	2
#define	TMP43X_RES_RES_12B	3

/*
 * BETA register controls.
 */
#define	TMP43X_BETA_GET_RANGE(r)	bitx8(r, 3, 0)
#define	TMP43X_BETA_SET_RANGE(r, v)	bitset8(r, 3, 0, v)

/*
 * Flags used to indicate which device-specific behaviors needs to be set.
 */
typedef enum {
	TMP43X_F_NFACTOR	= 1 << 0,
	TMP43X_F_BETA		= 1 << 1,
	TMP43X_F_LRES		= 1 << 2,
	TMP43X_F_MINMAX		= 1 << 3,
	TMP43X_F_REM2		= 1 << 4,
	/*
	 * This is a run-time flag to indicate if extended measurements are in
	 * effect.
	 */
	TMP43X_F_EXT_TEMP	= 1 << 5
} tmp43x_flags_t;

typedef struct tmp43x {
	dev_info_t *tmp_dip;
	i2c_client_t *tmp_client;
	i2c_reg_hdl_t *tmp_regs;
	tmp43x_dev_t tmp_dev;
	tmp43x_flags_t tmp_flags;
	uint8_t tmp_nrem;
	const tmp43x_reg_info_t *tmp_rinfo;
	size_t tmp_nrinfo;
	id_t tmp_ksensor[TMP43X_NSESNORS];
	kmutex_t tmp_mutex;
	uint16_t tmp_raw[TMP43X_NSESNORS];
	int64_t tmp_temp[TMP43X_NSESNORS];
} tmp43x_t;

static tmp43x_reg_type_t
tmp43x_reg_type(tmp43x_reg_t reg)
{
	switch (reg) {
	case TMP43X_R_TEMP_LOCAL:
	case TMP43X_R_TEMP_REM1:
	case TMP43X_R_TEMP_REM2:
		return (TMP43X_REG_TYPE_TEMP);
	case TMP43X_R_CFG1:
	case TMP43X_R_NFACTOR1:
	case TMP43X_R_NFACTOR2:
	case TMP43X_R_BETA1:
	case TMP43X_R_BETA2:
	case TMP43X_R_RES:
		return (TMP43X_REG_TYPE_1B);
	default:
		panic("tmp43x programmer error: unknown register 0x%x", reg);
	}
}

static bool
tmp43x_write_ctl(tmp43x_t *tmp, tmp43x_reg_t reg, uint8_t val)
{
	const tmp43x_reg_info_t *info = NULL;
	i2c_error_t err;

	for (size_t i = 0; i < tmp->tmp_nrinfo; i++) {
		if (tmp->tmp_rinfo[i].tri_reg == reg) {
			info = &tmp->tmp_rinfo[i];
			break;
		}
	}

	VERIFY3P(info, !=, NULL);
	VERIFY3B(info->tri_ro, ==, false);
	VERIFY3U(tmp43x_reg_type(reg), ==, TMP43X_REG_TYPE_1B);

	if (!smbus_client_write_u8(NULL, tmp->tmp_client, info->tri_write, val,
	    &err)) {
		dev_err(tmp->tmp_dip, CE_WARN, "!failed to write register "
		    "0x%x: 0x%x/0x%x", info->tri_read, err.i2c_error,
		    err.i2c_ctrl);
		return (false);
	}

	return (true);
}

static bool
tmp43x_read_ctl(tmp43x_t *tmp, tmp43x_reg_t reg, uint8_t *valp)
{
	const tmp43x_reg_info_t *info = NULL;
	i2c_error_t err;

	for (size_t i = 0; i < tmp->tmp_nrinfo; i++) {
		if (tmp->tmp_rinfo[i].tri_reg == reg) {
			info = &tmp->tmp_rinfo[i];
			break;
		}
	}

	VERIFY3P(info, !=, NULL);
	VERIFY3U(tmp43x_reg_type(reg), ==, TMP43X_REG_TYPE_1B);

	if (!smbus_client_read_u8(NULL, tmp->tmp_client, info->tri_read, valp,
	    &err)) {
		dev_err(tmp->tmp_dip, CE_WARN, "!failed to read register 0x%x: "
		    "0x%x/0x%x", info->tri_read, err.i2c_error, err.i2c_ctrl);
		return (false);
	}

	return (true);
}

static int
tmp43x_temp_read(tmp43x_t *tmp, tmp43x_reg_t reg, sensor_ioctl_scalar_t *scalar)
{
	const tmp43x_reg_info_t *info = NULL;
	i2c_error_t err;
	uint16_t val;

	for (size_t i = 0; i < tmp->tmp_nrinfo; i++) {
		if (tmp->tmp_rinfo[i].tri_reg == reg) {
			info = &tmp->tmp_rinfo[i];
			break;
		}
	}

	VERIFY3P(info, !=, NULL);
	VERIFY3U(tmp43x_reg_type(reg), ==, TMP43X_REG_TYPE_TEMP);

	mutex_enter(&tmp->tmp_mutex);
	if (!i2c_reg_get(NULL, tmp->tmp_regs, info->tri_read, &val,
	    sizeof (val), &err)) {
		dev_err(tmp->tmp_dip, CE_WARN, "!failed to read temperature "
		    "register 0x%x: 0x%x/0x%x", info->tri_read, err.i2c_error,
		    err.i2c_ctrl);
		mutex_exit(&tmp->tmp_mutex);
		return (EIO);
	}

	tmp->tmp_raw[reg] = val;
	int64_t temp = TMP43X_TEMP_GET_VAL(val);
	if ((tmp->tmp_flags & TMP43X_F_EXT_TEMP) != 0) {
		temp += TMP43X_TEMP_EXTD_ADJ;
	}
	tmp->tmp_temp[reg] = temp;

	scalar->sis_value = temp;
	scalar->sis_gran = TMP43X_TEMP_GRAN;
	scalar->sis_prec = TMP43X_TEMP_PREC;
	scalar->sis_unit = SENSOR_UNIT_CELSIUS;
	mutex_exit(&tmp->tmp_mutex);

	return (0);
}

static int
tmp43x_temp_read_local(void *arg, sensor_ioctl_scalar_t *scalar)
{
	tmp43x_t *tmp = arg;

	return (tmp43x_temp_read(tmp, TMP43X_R_TEMP_LOCAL, scalar));
}

static int
tmp43x_temp_read_rem1(void *arg, sensor_ioctl_scalar_t *scalar)
{
	tmp43x_t *tmp = arg;

	return (tmp43x_temp_read(tmp, TMP43X_R_TEMP_REM1, scalar));
}

static int
tmp43x_temp_read_rem2(void *arg, sensor_ioctl_scalar_t *scalar)
{
	tmp43x_t *tmp = arg;

	return (tmp43x_temp_read(tmp, TMP43X_R_TEMP_REM2, scalar));
}

static const ksensor_ops_t tmp43x_local_temp_ops = {
	.kso_kind = ksensor_kind_temperature,
	.kso_scalar = tmp43x_temp_read_local
};

static const ksensor_ops_t tmp43x_rem1_temp_ops = {
	.kso_kind = ksensor_kind_temperature,
	.kso_scalar = tmp43x_temp_read_rem1
};

static const ksensor_ops_t tmp43x_rem2_temp_ops = {
	.kso_kind = ksensor_kind_temperature,
	.kso_scalar = tmp43x_temp_read_rem2
};


static const i2c_reg_acc_attr_t tmp43x_reg_attr = {
	.i2cacc_version = I2C_REG_ACC_ATTR_V0,
	.i2cacc_addr_len = 1,
	.i2cacc_reg_len = 2,
	.i2cacc_reg_endian = DDI_STRUCTURE_BE_ACC,
	.i2cacc_addr_max = UINT8_MAX
};

static bool
tmp43x_i2c_init(tmp43x_t *tmp)
{
	i2c_errno_t err;

	if ((err = i2c_client_init(tmp->tmp_dip, 0, &tmp->tmp_client)) !=
	    I2C_CORE_E_OK) {
		dev_err(tmp->tmp_dip, CE_WARN, "failed to create i2c client: "
		    "0x%x", err);
		return (false);
	}

	if ((err = i2c_reg_handle_init(tmp->tmp_client, &tmp43x_reg_attr,
	    &tmp->tmp_regs)) != I2C_CORE_E_OK) {
		dev_err(tmp->tmp_dip, CE_WARN, "failed to create register "
		    "handle: %s (0x%x)", i2c_client_errtostr(tmp->tmp_client,
		    err), err);
		return (false);
	}

	return (true);
}

static bool
tmp43x_ident(tmp43x_t *tmp)
{
	uint8_t val;
	i2c_error_t err;

	if (!smbus_client_read_u8(NULL, tmp->tmp_client, TMP43X_R_MFGID, &val,
	    &err)) {
		dev_err(tmp->tmp_dip, CE_WARN, "!failed to read mfg register: "
		    "0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (false);
	}

	if (val != TMP43X_MFG_TI) {
		dev_err(tmp->tmp_dip, CE_WARN, "encountered unsupported vendor "
		    "id: 0x%x", val);
		return (false);
	}

	if (!smbus_client_read_u8(NULL, tmp->tmp_client, TMP43X_R_DEVID, &val,
	    &err)) {
		dev_err(tmp->tmp_dip, CE_WARN, "!failed to read device "
		    "id register: 0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (false);
	}

	switch (val) {
	case TMP43X_DEV_401:
		tmp->tmp_flags = TMP43X_F_LRES;
		tmp->tmp_rinfo = tmp43x_regs_401;
		tmp->tmp_nrinfo = ARRAY_SIZE(tmp43x_regs_401);
		break;
	case TMP43X_DEV_411A:
	case TMP43X_DEV_411B:
	case TMP43X_DEV_411C:
		tmp->tmp_flags = TMP43X_F_LRES | TMP43X_F_MINMAX |
		    TMP43X_F_NFACTOR;
		tmp->tmp_rinfo = tmp43x_regs_411;
		tmp->tmp_nrinfo = ARRAY_SIZE(tmp43x_regs_411);
		break;
	case TMP43X_DEV_431:
	case TMP43X_DEV_435:
		tmp->tmp_flags = TMP43X_F_NFACTOR | TMP43X_F_BETA;
		tmp->tmp_rinfo = tmp43x_regs_431_435;
		tmp->tmp_nrinfo = ARRAY_SIZE(tmp43x_regs_431_435);
		break;
	case TMP43X_DEV_432:
		tmp->tmp_flags = TMP43X_F_NFACTOR | TMP43X_F_BETA |
		    TMP43X_F_REM2;
		tmp->tmp_rinfo = tmp43x_regs_432;
		tmp->tmp_nrinfo = ARRAY_SIZE(tmp43x_regs_432);
		break;
	default:
		dev_err(tmp->tmp_dip, CE_WARN, "encountered unsupported device "
		    "id: 0x%x", val);
		return (false);
	}

	tmp->tmp_dev = val;
	return (true);
}

/*
 * Start the device by determining the following:
 *
 *  - Which range has been configured on the device.
 *  - Taking the device out of a shutdown state if its in it.
 *  - Changing the local resolution for relevant devices.
 */
static bool
tmp43x_start(tmp43x_t *tmp)
{
	uint8_t cfg1;

	if (!tmp43x_read_ctl(tmp, TMP43X_R_CFG1, &cfg1)) {
		return (false);
	}

	if (TMP43X_CFG1_GET_RANGE(cfg1) == TMP43X_CFG1_RANGE_EXT) {
		tmp->tmp_flags |= TMP43X_F_EXT_TEMP;
	}

	if (TMP43X_CFG1_GET_SD(cfg1) == TMP43X_CFG1_SD_STOP) {
		cfg1 = TMP43X_CFG1_SET_SD(cfg1, TMP43X_CFG1_SD_RUN);
		if (!tmp43x_write_ctl(tmp, TMP43X_R_CFG1, cfg1)) {
			return (false);
		}
	}

	/*
	 * Attempt to set the local resolution on hardware that requires it. We
	 * always set the device to 12-bit resolution for consistency. On the
	 * newer TMP411 parts it is the same cost regardless. On older TMP401 /
	 * TMP411 this is a bit more expensive. If this becomes a problem we can
	 * add a device property to stop it from occurring.
	 */
	if ((tmp->tmp_flags & TMP43X_F_LRES) != 0) {
		uint8_t res, nres;

		if (!tmp43x_read_ctl(tmp, TMP43X_R_RES, &res)) {
			return (false);
		}

		nres = TMP43X_RES_SET_RES(res, TMP43X_RES_RES_12B);
		if (res != nres && !tmp43x_write_ctl(tmp, TMP43X_R_RES, nres)) {
			return (false);
		}
	}

	return (true);
}

static bool
tmp43x_ksensor_init(tmp43x_t *tmp)
{
	int ret;

	if ((ret = i2c_client_ksensor_create_scalar(tmp->tmp_client,
	    SENSOR_KIND_TEMPERATURE, &tmp43x_local_temp_ops, tmp, "local",
	    &tmp->tmp_ksensor[0])) != 0) {
		dev_err(tmp->tmp_dip, CE_WARN, "failed to create ksensor: %d",
		    ret);
		return (false);
	}

	if ((ret = i2c_client_ksensor_create_scalar(tmp->tmp_client,
	    SENSOR_KIND_TEMPERATURE, &tmp43x_rem1_temp_ops, tmp, "remote1",
	    &tmp->tmp_ksensor[1])) != 0) {
		dev_err(tmp->tmp_dip, CE_WARN, "failed to create ksensor: %d",
		    ret);
		return (false);
	}

	if ((tmp->tmp_flags & TMP43X_F_REM2) == 0)
		return (true);

	if ((ret = i2c_client_ksensor_create_scalar(tmp->tmp_client,
	    SENSOR_KIND_TEMPERATURE, &tmp43x_rem2_temp_ops, tmp, "remote2",
	    &tmp->tmp_ksensor[2])) != 0) {
		dev_err(tmp->tmp_dip, CE_WARN, "failed to create ksensor: %d",
		    ret);
		return (false);
	}
	return (true);
}

static void
tmp43x_cleanup(tmp43x_t *tmp)
{
	(void) ksensor_remove(tmp->tmp_dip, KSENSOR_ALL_IDS);
	i2c_reg_handle_destroy(tmp->tmp_regs);
	i2c_client_destroy(tmp->tmp_client);
	mutex_destroy(&tmp->tmp_mutex);
	ddi_set_driver_private(tmp->tmp_dip, NULL);
	tmp->tmp_dip = NULL;
	kmem_free(tmp, sizeof (tmp43x_t));
}

static int
tmp43x_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	tmp43x_t *tmp;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	tmp = kmem_zalloc(sizeof (tmp43x_t), KM_SLEEP);
	tmp->tmp_dip = dip;
	ddi_set_driver_private(dip, tmp);
	mutex_init(&tmp->tmp_mutex, NULL, MUTEX_DRIVER, NULL);

	if (!tmp43x_i2c_init(tmp))
		goto cleanup;

	if (!tmp43x_ident(tmp))
		goto cleanup;

	if (!tmp43x_start(tmp))
		goto cleanup;

	if (!tmp43x_ksensor_init(tmp))
		goto cleanup;

	return (DDI_SUCCESS);

cleanup:
	tmp43x_cleanup(tmp);
	return (DDI_FAILURE);
}

static int
tmp43x_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	tmp43x_t *tmp;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	tmp = ddi_get_driver_private(dip);
	if (tmp == NULL) {
		dev_err(dip, CE_WARN, "asked to detach, but missing private "
		    "data");
		return (DDI_FAILURE);
	}
	VERIFY3P(tmp->tmp_dip, ==, dip);

	tmp43x_cleanup(tmp);
	return (DDI_SUCCESS);
}

static struct dev_ops tmp43x_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = tmp43x_attach,
	.devo_detach = tmp43x_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed
};

static struct modldrv tmp43x_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "TMP43X driver",
	.drv_dev_ops = &tmp43x_dev_ops
};

static struct modlinkage tmp43x_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &tmp43x_modldrv, NULL }
};

int
_init(void)
{
	return (mod_install(&tmp43x_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&tmp43x_modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&tmp43x_modlinkage));
}
