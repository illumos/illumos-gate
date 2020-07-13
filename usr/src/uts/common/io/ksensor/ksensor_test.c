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
 * Copyright 2020 Oxide Computer Company
 */

/*
 * This driver is used to implement parts of the ksensor test suite.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/zone.h>
#include <sys/sensors.h>

typedef struct ksensor_test {
	dev_info_t *kt_dip;
	id_t kt_sensor1;
	id_t kt_sensor2;
	id_t kt_sensor3;
	id_t kt_sensor4;
	id_t kt_sensor5;
} ksensor_test_t;

static int
ksensor_test_temperature(void *arg, sensor_ioctl_temperature_t *temp)
{
	temp->sit_unit = SENSOR_UNIT_CELSIUS;
	temp->sit_gran = 4;
	temp->sit_prec = -2;
	temp->sit_temp = 23;
	return (0);
}

static const ksensor_ops_t ksensor_test_temp_ops = {
	ksensor_kind_temperature,
	ksensor_test_temperature
};

static int
ksensor_test_kind_eio(void *arg, sensor_ioctl_kind_t *kindp)
{
	return (EIO);
}

static int
ksensor_test_temp_eio(void *arg, sensor_ioctl_temperature_t *tempp)
{
	return (EIO);
}

static const ksensor_ops_t ksensor_test_eio_ops = {
	ksensor_test_kind_eio,
	ksensor_test_temp_eio
};

static int
ksensor_test_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret;
	char buf[128];
	ksensor_test_t *kt;

	switch (cmd) {
	case DDI_RESUME:
		return (DDI_SUCCESS);
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	kt = kmem_zalloc(sizeof (ksensor_test_t), KM_SLEEP);
	kt->kt_dip = dip;

	(void) snprintf(buf, sizeof (buf), "test.temp.%d.1",
	    ddi_get_instance(dip));
	if ((ret = ksensor_create(dip, &ksensor_test_temp_ops, NULL, buf,
	    "ddi_sensor:test", &kt->kt_sensor1)) != 0) {
		dev_err(dip, CE_WARN, "failed to attatch sensor %s: %d", buf,
		    ret);
		goto err;
	}

	(void) snprintf(buf, sizeof (buf), "test.temp.%d.2",
	    ddi_get_instance(dip));
	if ((ret = ksensor_create(dip, &ksensor_test_temp_ops, NULL, buf,
	    "ddi_sensor:test", &kt->kt_sensor2)) != 0) {
		dev_err(dip, CE_WARN, "failed to attatch sensor %s: %d", buf,
		    ret);
		goto err;
	}

	(void) snprintf(buf, sizeof (buf), "test.temp.%d.3",
	    ddi_get_instance(dip));
	if ((ret = ksensor_create(dip, &ksensor_test_temp_ops, NULL, buf,
	    "ddi_sensor:test", &kt->kt_sensor3)) != 0) {
		dev_err(dip, CE_WARN, "failed to attatch sensor %s: %d", buf,
		    ret);
		goto err;
	}

	(void) snprintf(buf, sizeof (buf), "test.temp.%d.4",
	    ddi_get_instance(dip));
	if ((ret = ksensor_create(dip, &ksensor_test_temp_ops, NULL, buf,
	    "ddi_sensor:test", &kt->kt_sensor4)) != 0) {
		dev_err(dip, CE_WARN, "failed to attatch sensor %s: %d", buf,
		    ret);
		goto err;
	}

	(void) snprintf(buf, sizeof (buf), "test.eio.%d",
	    ddi_get_instance(dip));
	if ((ret = ksensor_create(dip, &ksensor_test_eio_ops, NULL, buf,
	    "ddi_sensor:test", &kt->kt_sensor5)) != 0) {
		dev_err(dip, CE_WARN, "failed to attatch sensor %s: %d", buf,
		    ret);
		goto err;
	}

	ddi_set_driver_private(dip, kt);

	return (DDI_SUCCESS);
err:
	(void) ksensor_remove(dip, KSENSOR_ALL_IDS);
	kmem_free(kt, sizeof (ksensor_test_t));
	return (DDI_FAILURE);
}

static int
ksensor_test_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ksensor_test_t *kt;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	kt = ddi_get_driver_private(dip);
	if (kt == NULL) {
		dev_err(dip, CE_WARN, "failed to find ksensor_test_t");
		return (DDI_FAILURE);
	}

	if (kt->kt_sensor3 != 0 &&
	    ksensor_remove(dip, kt->kt_sensor3) != 0) {
		dev_err(dip, CE_WARN, "failed to remove sensor 3");
		return (DDI_FAILURE);
	}
	kt->kt_sensor3 = 0;
	if (ksensor_remove(dip, KSENSOR_ALL_IDS) != 0) {
		dev_err(dip, CE_WARN, "failed to remove sensors");
		return (DDI_FAILURE);
	}
	kmem_free(kt, sizeof (*kt));
	ddi_set_driver_private(dip, NULL);
	return (DDI_SUCCESS);
}

static struct dev_ops ksensor_test_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = nodev,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = ksensor_test_attach,
	.devo_detach = ksensor_test_detach,
	.devo_reset = nodev,
	.devo_power = ddi_power,
	.devo_quiesce = ddi_quiesce_not_needed,
};

static struct modldrv ksensor_test_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Kernel Sensor test driver",
	.drv_dev_ops = &ksensor_test_dev_ops
};

static struct modlinkage ksensor_test_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &ksensor_test_modldrv, NULL }
};

int
_init(void)
{
	return (mod_install(&ksensor_test_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ksensor_test_modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&ksensor_test_modlinkage));
}
