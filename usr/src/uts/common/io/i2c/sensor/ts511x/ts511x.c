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
 * JEDEC DDR5 TS511x and TS521x temperature sensor driver.
 *
 * DDR5 DIMMs may have some number of temperature sensor drivers present, which
 * generally implement the TS511x or TS521x specification. This driver is based
 * on JESD302-1A, revision 2.0 (August 2023).
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/bitext.h>
#include <sys/debug.h>
#include <sys/i2c/client.h>
#include <sys/sensors.h>

/*
 * The following are a subset of the device registers.
 */
#define	TS_R_TYPE_MSB	0
#define	TS_R_TYPE_511X	0x51
#define	TS_R_TYPE_521X	0x52
#define	TS_R_TYPE_LSB	1
#define	TS_R_TYPE_LSB_GRADE_A	0x11
#define	TS_R_TYPE_LSB_GRADE_B	0x10
#define	TS_R_REV	2
#define	TS_R_REV_GET_MAJ(v)	bitx8(v, 5, 4)
#define	TS_R_REV_GET_MIN(v)	bitx8(v, 3, 1)
#define	TS_R_VID0	3
#define	TS_R_VID1	4

/*
 * All two byte thermal registers are in units of 0.25 C. These are signed
 * values. The low bit currently has bits [1:0] as reserved. Similarly the high
 * register has bits [7:5] reserved and [4] is the sign bit. The macros for
 * getting these values are defined in the temp register.
 */
#define	TS_R_HIGH_LIMIT_LSB	0x1c
#define	TS_R_HIGH_LIMIT_MSB	0x1d
#define	TS_R_LOW_LIMIT_LSB	0x1e
#define	TS_R_LOW_LIMIT_MSB	0x1f
#define	TS_R_HIGH_CRIT_LSB	0x20
#define	TS_R_HIGH_CRIT_MSB	0x21
#define	TS_R_LOW_CRIT_LSB	0x22
#define	TS_R_LOW_CRIT_MSB	0x23
#define	TS_R_TEMP_LSB		0x31
#define	TS_R_TEMP_LSB_GET_TEMP(v)	bitx8(v, 7, 2)
#define	TS_R_TEMP_MSB		0x32
#define	TS_R_TEMP_MSB_GET_TEMP(v)	bitx8(v, 3, 0)
#define	TS_R_TEMP_MSB_GET_SIGN(v)	bitx8(v, 4, 4)
#define	TS_R_TEMP_MSB_SHIFT	6
/*
 * The serial number is only present on TS521x devices.
 */
#define	TS_R_SN0	0x50
#define	TS_R_SN1	0x51
#define	TS_R_SN2	0x52
#define	TS_R_SN3	0x53
#define	TS_R_SN4	0x54
#define	TS_R_MAX	0xFF

/*
 * The temperature is measured in units of 0.25 degrees.
 */
#define	TS_TEMP_RES	4

typedef enum ts511x_type {
	TS_TYPE_511X,
	TS_TYPE_521X
} ts511x_type_t;

typedef struct ts511x {
	dev_info_t *ts_dip;
	i2c_client_t *ts_client;
	i2c_reg_hdl_t *ts_regs;
	ts511x_type_t ts_type;
	id_t ts_ksensor;
	uint8_t ts_vid[2];
	uint8_t ts_rev;
	uint8_t ts_sn[5];
	kmutex_t ts_mutex;
	uint8_t ts_raw[2];
	int64_t ts_temp;
} ts511x_t;

static const i2c_reg_acc_attr_t ts511x_reg_attr = {
	.i2cacc_version = I2C_REG_ACC_ATTR_V0,
	.i2cacc_addr_len = 1,
	.i2cacc_reg_len = 1,
	.i2cacc_addr_max = TS_R_MAX
};

static int
ts511x_temp_read(void *arg, sensor_ioctl_scalar_t *scalar)
{
	ts511x_t *ts = arg;
	uint8_t val[2];
	i2c_error_t err;

	if (!i2c_reg_get(NULL, ts->ts_regs, TS_R_TEMP_LSB, val, sizeof (val),
	    &err)) {
		dev_err(ts->ts_dip, CE_WARN, "!failed to read temp registers: "
		    "0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (EIO);
	}

	mutex_enter(&ts->ts_mutex);
	bcopy(val, ts->ts_raw, sizeof (val));
	uint64_t u64 = TS_R_TEMP_LSB_GET_TEMP(ts->ts_raw[0]) |
	    (TS_R_TEMP_MSB_GET_TEMP(ts->ts_raw[1]) << TS_R_TEMP_MSB_SHIFT);
	if (TS_R_TEMP_MSB_GET_SIGN(ts->ts_raw[1]) == 1) {
		u64 |= UINT64_MAX & ~((1 << 10) - 1);
	}
	ts->ts_temp = (int64_t)u64;
	scalar->sis_value = ts->ts_temp;

	/*
	 * The sensor is in units 0.25 Degrees C. According to the Table 65
	 * Temperature Sensor Performance, there are three accuracy ranges:
	 *
	 *  TYP 0.5, MAX 1.0	 75 <= T~A~ <= 95
	 *  TYP 1.0, MAX 2.0	 40 <= T~A~ <= 125
	 *  TYP 2.0, MAX 3.0	-40 <= T~A~ <= 125
	 */
	scalar->sis_unit = SENSOR_UNIT_CELSIUS;
	scalar->sis_gran = TS_TEMP_RES;
	int64_t prec_temp = scalar->sis_value / TS_TEMP_RES;
	if (75 <= prec_temp && prec_temp <= 95) {
		scalar->sis_prec = 1 * scalar->sis_gran;
	} else if (40 <= prec_temp && prec_temp <= 125) {
		scalar->sis_prec = 2 * scalar->sis_gran;
	} else {
		scalar->sis_prec = 3 * scalar->sis_gran;
	}
	mutex_exit(&ts->ts_mutex);

	return (0);
}

static const ksensor_ops_t ts511x_temp_ops = {
	.kso_kind = ksensor_kind_temperature,
	.kso_scalar = ts511x_temp_read
};

static bool
ts511x_i2c_init(ts511x_t *ts)
{
	i2c_errno_t err;

	if ((err = i2c_client_init(ts->ts_dip, 0, &ts->ts_client)) !=
	    I2C_CORE_E_OK) {
		dev_err(ts->ts_dip, CE_WARN, "failed to create i2c client: "
		    "0x%x", err);
		return (false);
	}

	if ((err = i2c_reg_handle_init(ts->ts_client, &ts511x_reg_attr,
	    &ts->ts_regs)) != I2C_CORE_E_OK) {
		dev_err(ts->ts_dip, CE_WARN, "failed to create register "
		    "handle: %s (0x%x)", i2c_client_errtostr(ts->ts_client,
		    err), err);
		return (false);
	}

	return (true);
}

/*
 * Read the MSB device type register to make sure we know what kind of device
 * this is. Once we do, snapshot a bit of additional information about the
 * device such as the revision, JEDEC ID, and serial number if it has one.
 */
static bool
ts511x_ident(ts511x_t *ts)
{
	uint8_t type;
	i2c_error_t err;

	if (!i2c_reg_get(NULL, ts->ts_regs, TS_R_TYPE_MSB, &type, sizeof (type),
	    &err)) {
		dev_err(ts->ts_dip, CE_WARN, "!failed to read type register: "
		    "0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (false);
	}

	switch (type) {
	case TS_R_TYPE_511X:
		ts->ts_type = TS_TYPE_511X;
		break;
	case TS_R_TYPE_521X:
		ts->ts_type = TS_TYPE_521X;
		break;
	default:
		dev_err(ts->ts_dip, CE_WARN, "encountered unsupported device "
		    "type: 0x%x", type);
		return (false);
	}

	if (!i2c_reg_get(NULL, ts->ts_regs, TS_R_VID0, ts->ts_vid,
	    sizeof (ts->ts_vid), &err)) {
		dev_err(ts->ts_dip, CE_WARN, "!failed to read vid registers: "
		    "0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (false);
	}

	if (!i2c_reg_get(NULL, ts->ts_regs, TS_R_REV, &ts->ts_rev,
	    sizeof (ts->ts_rev), &err)) {
		dev_err(ts->ts_dip, CE_WARN, "!failed to read rev register: "
		    "0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (false);
	}

	if (ts->ts_type != TS_TYPE_521X) {
		return (true);
	}

	if (!i2c_reg_get(NULL, ts->ts_regs, TS_R_REV, ts->ts_sn,
	    sizeof (ts->ts_sn), &err)) {
		dev_err(ts->ts_dip, CE_WARN, "!failed to read sn registers: "
		    "0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (false);
	}

	return (true);
}

static void
ts511x_cleanup(ts511x_t *ts)
{
	(void) ksensor_remove(ts->ts_dip, KSENSOR_ALL_IDS);
	i2c_reg_handle_destroy(ts->ts_regs);
	i2c_client_destroy(ts->ts_client);
	mutex_destroy(&ts->ts_mutex);
	ddi_set_driver_private(ts->ts_dip, NULL);
	ts->ts_dip = NULL;
	kmem_free(ts, sizeof (ts511x_t));
}

static int
ts511x_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret;
	ts511x_t *ts;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	ts = kmem_zalloc(sizeof (ts511x_t), KM_SLEEP);
	ts->ts_dip = dip;
	ddi_set_driver_private(dip, ts);
	mutex_init(&ts->ts_mutex, NULL, MUTEX_DRIVER, NULL);

	if (!ts511x_i2c_init(ts))
		goto cleanup;

	if (!ts511x_ident(ts))
		goto cleanup;

	if ((ret = i2c_client_ksensor_create_scalar(ts->ts_client,
	    SENSOR_KIND_TEMPERATURE, &ts511x_temp_ops, ts, "temp",
	    &ts->ts_ksensor)) != 0) {
		dev_err(ts->ts_dip, CE_WARN, "failed to create ksensor: %d",
		    ret);
		goto cleanup;
	}

	return (DDI_SUCCESS);

cleanup:
	ts511x_cleanup(ts);
	return (DDI_FAILURE);
}

static int
ts511x_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ts511x_t *ts;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	ts = ddi_get_driver_private(dip);
	if (ts == NULL) {
		dev_err(dip, CE_WARN, "asked to detach, but missing private "
		    "data");
		return (DDI_FAILURE);
	}
	VERIFY3P(ts->ts_dip, ==, dip);

	ts511x_cleanup(ts);
	return (DDI_SUCCESS);
}

static struct dev_ops ts511x_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = ts511x_attach,
	.devo_detach = ts511x_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed
};

static struct modldrv ts511x_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "TS511X/TS521X driver",
	.drv_dev_ops = &ts511x_dev_ops
};

static struct modlinkage ts511x_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &ts511x_modldrv, NULL }
};


int
_init(void)
{
	return (mod_install(&ts511x_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ts511x_modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&ts511x_modlinkage));
}
