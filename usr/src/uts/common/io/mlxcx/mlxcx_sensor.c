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

#include <mlxcx.h>
#include <sys/sensors.h>

/*
 * The PRM indicates that the temperature is measured in 1/8th degrees.
 */
#define	MLXCX_TEMP_GRAN	8

/*
 * Read a single temperature sensor entry. The ksensor framework guarantees that
 * it will only call this once for a given sensor at any time, though multiple
 * sensors can be in parallel.
 */
static int
mlxcx_temperature_read(void *arg, sensor_ioctl_scalar_t *scalar)
{
	boolean_t ok;
	uint16_t tmp;
	mlxcx_register_data_t data;
	mlxcx_temp_sensor_t *sensor = arg;
	mlxcx_t *mlxp = sensor->mlts_mlx;

	bzero(&data, sizeof (data));
	data.mlrd_mtmp.mlrd_mtmp_sensor_index = to_be16(sensor->mlts_index);
	ok = mlxcx_cmd_access_register(mlxp, MLXCX_CMD_ACCESS_REGISTER_READ,
	    MLXCX_REG_MTMP, &data);
	if (!ok) {
		return (EIO);
	}

	tmp = from_be16(data.mlrd_mtmp.mlrd_mtmp_temperature);
	sensor->mlts_value = (int16_t)tmp;
	tmp = from_be16(data.mlrd_mtmp.mlrd_mtmp_max_temperature);
	sensor->mlts_max_value = (int16_t)tmp;
	bcopy(data.mlrd_mtmp.mlrd_mtmp_name, sensor->mlts_name,
	    sizeof (sensor->mlts_name));

	scalar->sis_unit = SENSOR_UNIT_CELSIUS;
	scalar->sis_gran = MLXCX_TEMP_GRAN;
	scalar->sis_prec = 0;
	scalar->sis_value = (int64_t)sensor->mlts_value;

	return (0);
}

static const ksensor_ops_t mlxcx_temp_ops = {
	.kso_kind = ksensor_kind_temperature,
	.kso_scalar = mlxcx_temperature_read
};

void
mlxcx_teardown_sensors(mlxcx_t *mlxp)
{
	if (mlxp->mlx_temp_nsensors == 0)
		return;
	(void) ksensor_remove(mlxp->mlx_dip, KSENSOR_ALL_IDS);
	kmem_free(mlxp->mlx_temp_sensors, sizeof (mlxcx_temp_sensor_t) *
	    mlxp->mlx_temp_nsensors);
}

boolean_t
mlxcx_setup_sensors(mlxcx_t *mlxp)
{
	mlxcx_register_data_t data;
	boolean_t ok;

	mlxp->mlx_temp_nsensors = 0;
	bzero(&data, sizeof (data));
	ok = mlxcx_cmd_access_register(mlxp, MLXCX_CMD_ACCESS_REGISTER_READ,
	    MLXCX_REG_MTCAP, &data);
	if (!ok) {
		return (B_FALSE);
	}

	if (data.mlrd_mtcap.mlrd_mtcap_sensor_count == 0) {
		return (B_TRUE);
	}

	mlxp->mlx_temp_nsensors = data.mlrd_mtcap.mlrd_mtcap_sensor_count;
	mlxp->mlx_temp_sensors = kmem_zalloc(sizeof (mlxcx_temp_sensor_t) *
	    mlxp->mlx_temp_nsensors, KM_SLEEP);

	for (uint8_t i = 0; i < mlxp->mlx_temp_nsensors; i++) {
		char buf[32];
		int ret;

		if (snprintf(buf, sizeof (buf), "temp%u", i) >= sizeof (buf)) {
			mlxcx_warn(mlxp, "sensor name %u would overflow "
			    "internal buffer");
			goto err;
		}

		mlxp->mlx_temp_sensors[i].mlts_mlx = mlxp;
		mlxp->mlx_temp_sensors[i].mlts_index = i;

		ret = ksensor_create_scalar_pcidev(mlxp->mlx_dip,
		    SENSOR_KIND_TEMPERATURE, &mlxcx_temp_ops,
		    &mlxp->mlx_temp_sensors[i], buf,
		    &mlxp->mlx_temp_sensors[i].mlts_ksensor);
		if (ret != 0) {
			mlxcx_warn(mlxp, "failed to create temp sensor %s: %d",
			    buf, ret);
			goto err;
		}
	}

	return (B_TRUE);
err:
	mlxcx_teardown_sensors(mlxp);
	return (B_FALSE);
}
