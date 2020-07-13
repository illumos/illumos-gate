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
 * Handle and report sensors found on some igb parts.
 *
 * The Intel I350 has a built-in thermal sensor diode and an optional External
 * Thermal Sensor configuration. This external configuration is provided through
 * an optional space in the NVM and allows for up to 4 external sensors to be
 * defined. Currently, the only defined external thermal sensor is the Microchip
 * EMC 1413. As of this time, we haven't encountered a device that uses the EMC
 * 1413 in the wild, so while the definitions here are present, that is stubbed
 * out for the time.
 *
 * When accessing the internal sensor, the I350 Datasheet requires that we take
 * software/firmware semaphore before proceeding.
 */

#include "igb_sw.h"
#include <sys/sensors.h>
#include <sys/bitmap.h>

/*
 * Thermal register values.
 */
#define	E1000_THMJT_TEMP(x)	BITX(x, 8, 0)
#define	E1000_THMJT_VALID(x)	BITX(x, 31, 31)
#define	E1000_THMJT_RESOLUTION	1
#define	E1000_THMJT_PRECISION	5

/*
 * Misc. definitions required for accessing the NVM space.
 */
#define	IGB_NVM_ETS_CFG	0x3e
#define	IGB_NVM_ETS_CFG_NSENSORS(x)	BITX(x, 2, 0)
#define	IGB_NVM_ETS_CFG_TYPE(x)		BITX(x, 5, 3)
#define	IGB_NVM_ETS_CFG_TYPE_EMC1413	0

#define	IGB_NVM_ETS_SENSOR_LOC(x)	BITX(x, 13, 10)
#define	IGB_NVM_ETS_SENSOR_INDEX(x)	BITX(x, 9, 8)
#define	IGB_NVM_ETS_SENSOR_THRESH(x)	BITX(x, 7, 0)

#define	IGB_ETS_I2C_ADDRESS	0xf8

/*
 * These definitions come from the Microchip datasheet for the thermal diode
 * sensor defined by the external spec. These parts have an accuracy of 1 degree
 * and a granularity of 1/8th of a degree.
 */
#define	EMC1413_REG_CFG			0x03
#define	EMC1413_REG_CFG_RANGE		(1 << 2)
#define	EMC1413_RANGE_ADJ		(-64)
#define	EMC1413_REG_INT_DIODE_HI	0x00
#define	EMC1413_REG_INT_DIODE_LO	0x29
#define	EMC1413_REG_EXT1_DIODE_HI	0x01
#define	EMC1413_REG_EXT1_DIODE_LO	0x10
#define	EMC1413_REG_EXT2_DIODE_HI	0x23
#define	EMC1413_REG_EXT2_DIODE_LO	0x24
#define	EMC1413_REG_EXT3_DIODE_HI	0x2a
#define	EMC1413_REG_EXT3_DIODE_LO	0x2b

static int
igb_sensor_reg_temp(void *arg, sensor_ioctl_temperature_t *temp)
{
	igb_t *igb = arg;
	uint32_t reg;

	if (igb->hw.mac.ops.acquire_swfw_sync(&igb->hw, E1000_SWFW_PWRTS_SM) !=
	    E1000_SUCCESS) {
		return (EIO);
	}
	reg = E1000_READ_REG(&igb->hw, E1000_THMJT);
	igb->hw.mac.ops.release_swfw_sync(&igb->hw, E1000_SWFW_PWRTS_SM);
	if (E1000_THMJT_VALID(reg) == 0) {
		return (EIO);
	}

	temp->sit_unit = SENSOR_UNIT_CELSIUS;
	temp->sit_gran = E1000_THMJT_RESOLUTION;
	temp->sit_prec = E1000_THMJT_PRECISION;
	temp->sit_temp = E1000_THMJT_TEMP(reg);

	return (0);
}

static const ksensor_ops_t igb_sensor_reg_ops = {
	.kso_kind = ksensor_kind_temperature,
	.kso_temp = igb_sensor_reg_temp
};

static boolean_t
igb_sensors_create_minors(igb_t *igb)
{
	int ret;
	igb_sensors_t *sp = &igb->igb_sensors;

	if ((ret = ksensor_create_temp_pcidev(igb->dip, &igb_sensor_reg_ops,
	    igb, "builtin", &sp->isn_reg_ksensor)) != 0) {
		igb_log(igb, IGB_LOG_ERROR, "failed to create main sensor: %d",
		    ret);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
igb_sensors_init_ets(igb_t *igb, uint_t ets_off, uint_t index)
{
	uint16_t val;
	int ret;
	igb_sensors_t *sensors = &igb->igb_sensors;
	igb_ets_t *etsp = &sensors->isn_ets[sensors->isn_nents];
	igb_ets_loc_t loc;

	if ((ret = e1000_read_nvm(&igb->hw, ets_off, 1, &val)) !=
	    E1000_SUCCESS) {
		igb_log(igb, IGB_LOG_ERROR, "failed to read ETS word "
		    "at offset 0x%x: error %d", ets_off, ret);
		return (B_FALSE);
	}

	/*
	 * The data sheet says that if the location is listed as N/A, then we
	 * should not display this sensor. In this case, we just skip it.
	 */
	loc = IGB_NVM_ETS_SENSOR_LOC(val);
	if (loc == IGB_ETS_LOC_NA) {
		return (B_TRUE);
	}

	etsp->iet_loc = loc;
	etsp->iet_index = IGB_NVM_ETS_SENSOR_INDEX(val);
	etsp->iet_thresh = IGB_NVM_ETS_SENSOR_THRESH(val);
	sensors->isn_nents++;

	return (B_TRUE);
}

void
igb_init_sensors(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;
	uint16_t ets_off;

	/*
	 * Only the I350 supports the thermal temperature sensor values. This is
	 * device-wide, so only enumerate on bus zero.
	 */
	hw = &igb->hw;
	if (hw->mac.type != e1000_i350 || hw->bus.func != 0) {
		return;
	}

	ets_off = 0xffff;
	(void) e1000_read_nvm(hw, IGB_NVM_ETS_CFG, 1, &ets_off);
	if (ets_off != 0 && ets_off != 0xffff) {
		int ret;
		uint_t nents, i;
		uint16_t val;

		/*
		 * Swallow the fact that we can't read the ETS config.
		 */
		if ((ret = e1000_read_nvm(hw, ets_off, 1, &val)) !=
		    E1000_SUCCESS) {
			igb_log(igb, IGB_LOG_ERROR, "failed to read ETS word "
			    "at offset 0x%x: error %d", ets_off, ret);
			return;
		}

		/*
		 * If we don't find this, assume we can't use the external
		 * sensor either.
		 */
		if (IGB_NVM_ETS_CFG_TYPE(val) != IGB_NVM_ETS_CFG_TYPE_EMC1413) {
			return;
		}

		nents = IGB_NVM_ETS_CFG_NSENSORS(val);
		if (nents > IGB_ETS_MAX) {
			igb_log(igb, IGB_LOG_ERROR, "firmware NVM ETS "
			    "configuration has more entries (%d) than allowed",
			    nents);
			nents = IGB_ETS_MAX;
		}

		for (i = 0; i < nents; i++) {
			if (!igb_sensors_init_ets(igb, ets_off, i)) {
				return;
			}
		}
	}

	if (!igb_sensors_create_minors(igb)) {
		(void) ksensor_remove(igb->dip, KSENSOR_ALL_IDS);
		return;
	}

	igb->igb_sensors.isn_valid = B_TRUE;
}

void
igb_fini_sensors(igb_t *igb)
{
	if (igb->igb_sensors.isn_valid) {
		(void) ksensor_remove(igb->dip, KSENSOR_ALL_IDS);
		igb->igb_sensors.isn_valid = B_FALSE;
	}
}
