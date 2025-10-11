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
 * LM75, LM76, LM77, and derivatives temperature sensor driver.
 *
 * The LM75-77 are a series of temperature sensors that were originally produced
 * by National Semiconductor and since then, many different compatible devices
 * have been created. These devices all have two-byte registers that we think of
 * as big endian; however, the configuration register is only a single byte. We
 * use a register handle for everything other than that. TI also has a series of
 * TMP7[5-7] devices that this can handle.
 *
 * Each device has slightly different temperature register semantics:
 *
 *  - The LM75 has a 9-bit signed integer with a resolution of 0.5 C. Data bits
 *    are found in temp[14:7]. The sign bit is temp[15]. It has a +/-2 C
 *    accuracy in the range -25 <= T~A~ <= 100 C and +/-3 C otherwise.
 *
 *  - Some versions of the LM75A and LM75B support an 11-bit signed integer
 *    temperature with a resolution of 0.125. These are basically the same as
 *    the LM75 otherwise. temp[15] is the sign bit, temp[14:5]. Unfortunately
 *    not all versions of the LM75[AB] agree here. The TI datasheets often claim
 *    to still be 9-bit. The NXP ones, 11-bit. As a result we're currently going
 *    to treat all lm75 class variants the same here.
 *
 *  - The LM76 has a 12-bit signed integer with a resolution of 0.0625 C. Data
 *    bits are found in temp[14:3]. The sign bit is temp[15]. temp[2:0] are used
 *    for status bits. The accuracy varies, so we generally use +/-1 C.
 *
 *  - The LM77 has a 9-bit signed integer with a resolution of 0.5 C. Data bits
 *    are found temp[11:3]. The sign bit is replicated in bits[15:12]. temp[2:0]
 *    are used as status bits like the LM76. This family has three accuracy
 *    ranges: +/-1.5 for -10 <= T~A~ <= 65. +/-2 2.0 for -25 <= T~A~ <= 100. And
 *    +/- 3 for the rest.
 *
 *  - TI has the TMP75, TMP175, and TMP275 which use a slightly different 12-bit
 *    scheme from the LM76, that is intended to be compatible with the LM75.
 *    The sign bit is temp[15], while the data is temp[14:4]. This makes it more
 *    LM75 compatible. It has a +/-1 C accuracy and the resolution is 0.0625.
 *    These devices have programmable resolutions. For now, we don't have
 *    support for this and some of the other clones out there.
 *
 * All of these parts can be sent into a shutdown state where they no longer
 * actively process the temperature. This is controlled by the configuration
 * register. One thing of note is that there are different compatible versions
 * of this device due to different ones made by national, TI, etc.
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
 * Device registers.
 */
#define	LM7X_R_TEMP	0
#define	LM7X_R_CONF	1
#define	LM7X_R_CONF_GET_SHUT(r)		bitx8(r, 0, 0)
#define	LM7X_R_CONF_SET_SHUT(r, v)	bitset8(r, 0, 0, v)
#define	LM7X_R_THYST	2

/*
 * LM75 specific registers.
 */
#define	LM75_R_TOS	3

/*
 * LM76/77 specific registers.
 */
#define	LM76_R_TCRIT	4
#define	LM76_R_TLOW	5
#define	LM76_R_THIGH	6

/*
 * This represents a single precision range. Something that matches between the
 * min and maximum will be used. These values in degrees C. The dc and pdc are
 * how many degrees and partial degrees C are required. The degrees are a normal
 * unit. The pdc is basically the divisor that should be applied to a single
 * degree of precision. So +/- 1.5 would be dc = 1, pdc = 2.
 */
typedef struct {
	int64_t lpi_min;
	int64_t lpi_max;
	uint8_t lpi_dc;
	uint8_t lpi_pdc;
} lm_prec_info_t;

typedef struct lm_hw_info {
	uint32_t lhi_gran;
	uint_t lhi_hi;
	uint_t lhi_lo;
	const lm_prec_info_t *lhi_prec;
	size_t lhi_nprec;
	uint32_t lhi_max_reg;
} lm_hw_info_t;

typedef struct lm7x_ident {
	char *li_name;
	char *li_compat;
	const lm_hw_info_t *li_dev;
} lm7x_ident_t;

typedef struct lm7x {
	dev_info_t *lm_dip;
	i2c_client_t *lm_client;
	i2c_reg_hdl_t *lm_regs;
	const lm7x_ident_t *lm_ident;
	id_t lm_ksensor;
	kmutex_t lm_mutex;
	uint16_t lm_raw;
	int64_t lm_temp;
} lm7x_t;

/*
 * Hardware Temperature Granularities
 */
#define	LM_GRAN_0P5	2
#define	LM_GRAN_0P0625	4

static const lm_prec_info_t lm75_prec[] = {
	{ -25, 100, 2, 0 },
	{ INT64_MIN, INT64_MAX, 3, 0 }
};

static const lm_prec_info_t lm76_prec[] = {
	{ INT64_MIN, INT64_MAX, 1, 0 }
};

static const lm_prec_info_t lm77_prec[] = {
	{ -10, 65, 1, 2 },
	{ -25, 100, 2, 0 },
	{ INT64_MIN, INT64_MAX, 3, 0 }
};

static const lm_hw_info_t lm75_info = {
	.lhi_gran = LM_GRAN_0P5,
	.lhi_hi = 14,
	.lhi_lo = 7,
	.lhi_prec = lm75_prec,
	.lhi_nprec = ARRAY_SIZE(lm75_prec),
	.lhi_max_reg = LM75_R_TOS
};

static const lm_hw_info_t lm76_info = {
	.lhi_gran = LM_GRAN_0P0625,
	.lhi_hi = 14,
	.lhi_lo = 3,
	.lhi_prec = lm76_prec,
	.lhi_nprec = ARRAY_SIZE(lm76_prec),
	.lhi_max_reg = LM76_R_THIGH
};

static const lm_hw_info_t lm77_info = {
	.lhi_gran = LM_GRAN_0P5,
	.lhi_hi = 11,
	.lhi_lo = 3,
	.lhi_prec = lm77_prec,
	.lhi_nprec = ARRAY_SIZE(lm77_prec),
	.lhi_max_reg = LM76_R_THIGH
};

static const lm7x_ident_t lm7x_idents[] = {
	{ "lm75", "national,lm75", &lm75_info },
	{ "lm75a", "national,lm75a", &lm75_info },
	{ "lm75b", "national,lm75b", &lm75_info },
	{ "lm76", "national,lm76", &lm76_info },
	{ "lm77", "national,lm77", &lm77_info }
};

static uint32_t
lm7x_precision(const lm_hw_info_t *info, int64_t val)
{
	val /= info->lhi_gran;

	for (size_t i = 0; i < info->lhi_nprec; i++) {
		const lm_prec_info_t *prec = &info->lhi_prec[i];

		if (val < prec->lpi_min || val > prec->lpi_max)
			continue;

		uint32_t ret = info->lhi_gran * prec->lpi_dc;
		if (prec->lpi_pdc > 0) {
			ret += info->lhi_gran / prec->lpi_pdc;
		}

		return (ret);
	}

	return (0);
}

static int
lm7x_temp_read(void *arg, sensor_ioctl_scalar_t *scalar)
{
	lm7x_t *lm = arg;
	const lm_hw_info_t *info = lm->lm_ident->li_dev;
	uint16_t val;
	i2c_error_t err;

	if (!i2c_reg_get(NULL, lm->lm_regs, LM7X_R_TEMP, &val, sizeof (val),
	    &err)) {
		dev_err(lm->lm_dip, CE_WARN, "!failed to read temp register: "
		    "0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (EIO);
	}

	mutex_enter(&lm->lm_mutex);
	lm->lm_raw = val;

	uint64_t u64 = bitx16(val, info->lhi_hi, info->lhi_lo);
	if ((u64 & (1 << info->lhi_hi)) != 0) {
		u64 |= UINT64_MAX & ~((1 << (info->lhi_hi + 1)) - 1);
	}
	lm->lm_temp = (int64_t)u64;

	scalar->sis_value = lm->lm_temp;
	scalar->sis_gran = info->lhi_gran;
	scalar->sis_prec = lm7x_precision(info, lm->lm_temp);
	scalar->sis_unit = SENSOR_UNIT_CELSIUS;
	mutex_exit(&lm->lm_mutex);

	return (0);
}

static const ksensor_ops_t lm7x_temp_ops = {
	.kso_kind = ksensor_kind_temperature,
	.kso_scalar = lm7x_temp_read
};

static bool
lm7x_ident(lm7x_t *lm)
{
	const char *bind = ddi_binding_name(lm->lm_dip);
	const char *name = ddi_node_name(lm->lm_dip);

	for (size_t i = 0; i < ARRAY_SIZE(lm7x_idents); i++) {
		if (strcmp(bind, lm7x_idents[i].li_name) == 0 ||
		    strcmp(bind, lm7x_idents[i].li_compat) == 0 ||
		    strcmp(name, lm7x_idents[i].li_name) == 0 ||
		    strcmp(name, lm7x_idents[i].li_compat) == 0) {
			lm->lm_ident = &lm7x_idents[i];
			return (true);
		}

	}

	dev_err(lm->lm_dip, CE_WARN, "failed to match against node name %s "
	    "and binding name %s", name, bind);
	return (false);
}

static bool
lm7x_i2c_init(lm7x_t *lm)
{
	i2c_errno_t err;
	i2c_reg_acc_attr_t attr;

	if ((err = i2c_client_init(lm->lm_dip, 0, &lm->lm_client)) !=
	    I2C_CORE_E_OK) {
		dev_err(lm->lm_dip, CE_WARN, "failed to create i2c client: "
		    "0x%x", err);
		return (false);
	}

	bzero(&attr, sizeof (attr));
	attr.i2cacc_version = I2C_REG_ACC_ATTR_V0;
	attr.i2cacc_addr_len = 1;
	attr.i2cacc_reg_len = 2;
	attr.i2cacc_reg_endian = DDI_STRUCTURE_BE_ACC;
	attr.i2cacc_addr_max = lm->lm_ident->li_dev->lhi_max_reg;

	if ((err = i2c_reg_handle_init(lm->lm_client, &attr, &lm->lm_regs)) !=
	    I2C_CORE_E_OK) {
		dev_err(lm->lm_dip, CE_WARN, "failed to create register "
		    "handle: %s (0x%x)", i2c_client_errtostr(lm->lm_client,
		    err), err);
		return (false);
	}

	return (true);
}

/*
 * We need to check if this device has been shut down. If it has, wake it up.
 * This is the one register that is special and is a 1 byte register so we don't
 * use the normal register handle.
 */
static bool
lm7x_start(lm7x_t *lm)
{
	uint8_t conf, nconf;
	i2c_error_t err;

	if (!smbus_client_read_u8(NULL, lm->lm_client, LM7X_R_CONF, &conf,
	    &err)) {
		dev_err(lm->lm_dip, CE_WARN, "!failed to read conf register: "
		    "0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (false);
	}

	nconf = LM7X_R_CONF_SET_SHUT(conf, 0);
	if (conf != nconf && !smbus_client_write_u8(NULL, lm->lm_client,
	    LM7X_R_CONF, conf, &err)) {
		dev_err(lm->lm_dip, CE_WARN, "!failed to write conf register: "
		    "0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (false);
	}

	return (true);
}

static void
lm7x_cleanup(lm7x_t *lm)
{
	(void) ksensor_remove(lm->lm_dip, KSENSOR_ALL_IDS);
	i2c_reg_handle_destroy(lm->lm_regs);
	i2c_client_destroy(lm->lm_client);
	mutex_destroy(&lm->lm_mutex);
	ddi_set_driver_private(lm->lm_dip, NULL);
	lm->lm_dip = NULL;
	kmem_free(lm, sizeof (lm7x_t));
}

static int
lm7x_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret;
	lm7x_t *lm;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	lm = kmem_zalloc(sizeof (lm7x_t), KM_SLEEP);
	lm->lm_dip = dip;
	ddi_set_driver_private(dip, lm);
	mutex_init(&lm->lm_mutex, NULL, MUTEX_DRIVER, NULL);

	if (!lm7x_ident(lm))
		goto cleanup;

	if (!lm7x_i2c_init(lm))
		goto cleanup;

	if (!lm7x_start(lm))
		goto cleanup;

	if ((ret = i2c_client_ksensor_create_scalar(lm->lm_client,
	    SENSOR_KIND_TEMPERATURE, &lm7x_temp_ops, lm, "temp",
	    &lm->lm_ksensor)) != 0) {
		dev_err(lm->lm_dip, CE_WARN, "failed to create ksensor: %d",
		    ret);
		goto cleanup;
	}

	return (DDI_SUCCESS);

cleanup:
	lm7x_cleanup(lm);
	return (DDI_FAILURE);
}

static int
lm7x_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	lm7x_t *lm;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	lm = ddi_get_driver_private(dip);
	if (lm == NULL) {
		dev_err(dip, CE_WARN, "asked to detach, but missing private "
		    "data");
		return (DDI_FAILURE);
	}
	VERIFY3P(lm->lm_dip, ==, dip);

	lm7x_cleanup(lm);
	return (DDI_SUCCESS);
}

static struct dev_ops lm7x_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = lm7x_attach,
	.devo_detach = lm7x_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed
};

static struct modldrv lm7x_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "LM7x driver",
	.drv_dev_ops = &lm7x_dev_ops
};

static struct modlinkage lm7x_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &lm7x_modldrv, NULL }
};

int
_init(void)
{
	return (mod_install(&lm7x_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&lm7x_modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&lm7x_modlinkage));
}
