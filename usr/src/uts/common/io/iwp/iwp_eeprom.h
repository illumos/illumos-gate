/*
 * Sun elects to have this file available under and governed by the BSD license
 * (see below for full license text).  However, the following notice
 * accompanied the original version of this file:
 */

/*
 * Copyright (c) 2009, Intel Corporation
 * All rights reserved.
 */

/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2005 - 2009 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
 * USA
 *
 * The full GNU General Public License is included in this distribution
 * in the file called LICENSE.GPL.
 *
 * Contact Information:
 * James P. Ketrenos <ipw2100-admin@linux.intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 * BSD LICENSE
 *
 * Copyright(c) 2005 - 2009 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _IWP_EEPROM_H_
#define	_IWP_EEPROM_H_

/*
 * This file defines EEPROM related constants, enums, and inline functions.
 */

/*
 * EEPROM field values
 */
#define	ANTENNA_SWITCH_NORMAL		0
#define	ANTENNA_SWITCH_INVERSE		1

enum {
	EEPROM_CHANNEL_VALID = (1 << 0),	/* usable for this SKU/geo */
	EEPROM_CHANNEL_IBSS = (1 << 1),	/* usable as an IBSS channel */
	/* Bit 2 Reserved */
	EEPROM_CHANNEL_ACTIVE = (1 << 3),	/* active scanning allowed */
	EEPROM_CHANNEL_RADAR = (1 << 4),	/* radar detection required */
	EEPROM_CHANNEL_WIDE = (1 << 5),
	EEPROM_CHANNEL_NARROW = (1 << 6),
	EEPROM_CHANNEL_DFS = (1 << 7),	/* dynamic freq selection candidate */
};

/*
 * EEPROM field lengths
 */
#define	EEPROM_BOARD_PBA_NUMBER_LENGTH		11

/*
 * EEPROM field lengths
 */
#define	EEPROM_BOARD_PBA_NUMBER_LENGTH		11
#define	EEPROM_REGULATORY_SKU_ID_LENGTH		4
#define	EEPROM_REGULATORY_BAND1_CHANNELS_LENGTH	14
#define	EEPROM_REGULATORY_BAND2_CHANNELS_LENGTH	13
#define	EEPROM_REGULATORY_BAND3_CHANNELS_LENGTH	12
#define	EEPROM_REGULATORY_BAND4_CHANNELS_LENGTH	11
#define	EEPROM_REGULATORY_BAND5_CHANNELS_LENGTH	6


#define	EEPROM_REGULATORY_NUMBER_OF_BANDS	5

/*
 * SKU Capabilities
 */
#define	EEPROM_SKU_CAP_SW_RF_KILL_ENABLE	(1 << 0)
#define	EEPROM_SKU_CAP_HW_RF_KILL_ENABLE	(1 << 1)
#define	EEPROM_SKU_CAP_OP_MODE_MRC		(1 << 7)

/*
 * *regulatory* channel data from eeprom, one for each channel
 */
struct iwl_eeprom_channel {
	uint8_t flags;		/* flags copied from EEPROM */
	int8_t max_power_avg;	/* max power (dBm) on this chnl, limit 31 */
};

/*
 * Mapping of a Tx power level, at factory calibration temperature,
 *   to a radio/DSP gain table index.
 * One for each of 5 "sample" power levels in each band.
 * v_det is measured at the factory, using the 3945's built-in power amplifier
 *   (PA) output voltage detector.  This same detector is used during Tx of
 *   long packets in normal operation to provide feedback as to proper output
 *   level.
 * Data copied from EEPROM.
 */
struct iwl_eeprom_txpower_sample {
	uint8_t gain_index;	/* index into power (gain) setup table ... */
	int8_t power;		/* ... for this pwr level for this chnl group */
	uint16_t v_det;		/* PA output voltage */
};

/*
 * Mappings of Tx power levels -> nominal radio/DSP gain table indexes.
 * One for each channel group (a.k.a. "band") (1 for BG, 4 for A).
 * Tx power setup code interpolates between the 5 "sample" power levels
 *    to determine the nominal setup for a requested power level.
 * Data copied from EEPROM.
 * DO NOT ALTER THIS STRUCTURE!!!
 */
struct iwl_eeprom_txpower_group {
	/* 5 power levels */
	struct iwl_eeprom_txpower_sample samples[5];
	/* coefficients for voltage->power formula (signed) */
	uint32_t a, b, c, d, e;
	/* these modify coeffs based on frequency (signed) */
	uint32_t Fa, Fb, Fc, Fd, Fe;
	/* highest power possible by h/w in this * band */
	int8_t saturation_power;
	/* "representative" channel # in this band */
	uint8_t group_channel;
	/* h/w temperature at factory calib this band (signed) */
	uint16_t temperature;
};

/*
 * Temperature-based Tx-power compensation data, not band-specific.
 * These coefficients are use to modify a/b/c/d/e coeffs based on
 *   difference between current temperature and factory calib temperature.
 * Data copied from EEPROM.
 */
struct iwl_eeprom_temperature_corr {
	uint32_t Ta;
	uint32_t Tb;
	uint32_t Tc;
	uint32_t Td;
	uint32_t Te;
};


/*
 * eeprom map
 */
#define	EEP_MAC_ADDRESS	42	/* chipset's MAC address 6 bytes */
#define	EEP_VERSION	136	/* eeprom version 2 bytes */
#define	EEP_SP_RADIO_CONFIGURATION	144	/* SP's radio configuration */



#define	CSR_EEPROM_REG			(CSR_BASE+0x02c)
#define	CSR_EEPROM_GP			(CSR_BASE+0x030)
#define	CSR_EEPROM_GP_VALID_MSK		0x00000007
#define	CSR_EEPROM_GP_BAD_SIGNATURE	0x00000000
#define	IWP_SP_EEPROM_SIZE	2048

#define	IWP_READ_EEP_SHORT(sc, addr)	((((uint16_t)sc->sc_eep_map[addr + 1])\
					    << 8) |\
					    ((uint16_t)sc->sc_eep_map[addr]))

#define	SP_RADIO_TYPE_3x3	(0)
#define	SP_RADIO_TYPE_2x2	(1)
#define	SP_RADIO_TYPE_1x2	(2)
#define	SP_RADIO_TYPE_MAX	(3)

#define	SP_RADIO_TYPE_MSK(x)	(x & 3)
#define	SP_RADIO_STEP_MSK(x)	((x>>2) & 3)
#define	SP_RADIO_DASH_MSK(x)	((x>>4) & 3)
#define	SP_RADIO_PNUM_MSK(x)	((x>>6) & 3)
#define	SP_RADIO_TX_CHAIN_MSK(x)	((x>>8) & 0xf)
#define	SP_RADIO_RX_CHAIN_MSK(x)	((x>>12) & 0xf)

#define	ADDRESS_MSK		0x0000ffff
#define	INDIRECT_TYPE_MSK	0x000f0000
#define	INDIRECT_HOST		0x00010000
#define	INDIRECT_GENERAL	0x00020000
#define	INDIRECT_REGULATORY	0x00030000
#define	INDIRECT_CALIBRATION	0x00040000
#define	INDIRECT_PROCESS_ADJST	0x00050000
#define	INDIRECT_OTHERS		0x00060000
#define	INDIRECT_ADDRESS	0x00100000

#define	EEP_LINK_HOST		(200)
#define	EEP_LINK_GENERAL	(202)
#define	EEP_LINK_REGULATORY	(204)
#define	EEP_LINK_CALIBRATION	(206)
#define	EEP_LINK_PROCESS_ADJST	(208)
#define	EEP_LINK_OTHERS		(210)

#define	EEP_CALIBRATION		((0x00) | INDIRECT_ADDRESS |\
				    INDIRECT_CALIBRATION)

#define	EEP_TX_POWER_TX_CHAINS	(3)
#define	EEP_RXIQ_CAL_CHANNELS	(7)
#define	EEP_CAL_CHANNEL_GROUP	(7)
#define	EEP_RXIQ_DRIVER_MODES	(12)



#endif /* _IWP_EEPROM_H_ */
