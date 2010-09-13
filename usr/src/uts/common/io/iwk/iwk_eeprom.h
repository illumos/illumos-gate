/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2007, Intel Corporation
 * All rights reserved.
 */

/*
 * Sun elects to use this software under the BSD license.
 */

/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2005 - 2007 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU Geeral Public License as
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
 * Copyright(c) 2005 - 2007 Intel Corporation. All rights reserved.
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

#ifndef _IWK_EEPROM_H_
#define	_IWK_EEPROM_H_

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

#define	EEP_TX_POWER_TX_CHAINS		(2)
#define	EEP_TX_POWER_BANDS		(8)
#define	EEP_TX_POWER_MEASUREMENTS	(3)
#define	EEP_TX_POWER_VERSION		(2)
#define	EEP_TX_POWER_VERSION_NEW	(5)

struct iwk_eep_calib_measure {
	uint8_t temperature;
	uint8_t gain_idx;
	uint8_t actual_pow;
	int8_t pa_det;
};

struct iwk_eep_calib_channel_info {
	uint8_t ch_num;
	struct iwk_eep_calib_measure
	    measure[EEP_TX_POWER_TX_CHAINS][EEP_TX_POWER_MEASUREMENTS];
};

struct iwk_eep_calib_subband_info {
	uint8_t ch_from;
	uint8_t ch_to;
	struct iwk_eep_calib_channel_info ch1;
	struct iwk_eep_calib_channel_info ch2;
};

struct iwk_eep_calib_info {
	uint8_t saturation_power24;
	uint8_t saturation_power52;
	uint16_t voltage;
	struct iwk_eep_calib_subband_info band_info_tbl[EEP_TX_POWER_BANDS];
};

struct iwk_eep_channel {
	uint8_t flags;
	int8_t max_power_avg; /* each channel's maximum power, 31 as limit */
};

/*
 * eeprom map
 */
struct iwk_eep {
	uint8_t reser0[16];
	uint16_t device_id;
	uint8_t reser1[2];
	uint16_t pmc;
	uint8_t reser2[20];
	uint8_t mac_address[6];
	uint8_t reser3[58];
	uint16_t board_revision;
	uint8_t reser4[11];
	uint8_t board_pba_number[9];
	uint8_t reser5[8];
	uint16_t version;
	uint8_t sku_cap;
	uint8_t leds_mode;
	uint16_t oem_mode;
	uint16_t wowlan_mode;
	uint16_t leds_times_interval;
	uint8_t leds_off_time;
	uint8_t leds_on_time;
	uint8_t almgor_m_version;
	uint8_t antenna_switch_type;
	uint8_t reser6[8];
	uint16_t board_revision_4965;
	uint8_t reser7[13];
	uint8_t board_pba_number_4965[9];
	uint8_t reser8[10];
	uint8_t sku_id[4];
	uint16_t band_1_count;
	struct iwk_eep_channel  band_1_channels[14];
	uint16_t band_2_count;
	struct iwk_eep_channel  band_2_channels[13];
	uint16_t band_3_count;
	struct iwk_eep_channel  band_3_channels[12];
	uint16_t band_4_count;
	struct iwk_eep_channel  band_4_channels[11];
	uint16_t band_5_count;
	struct iwk_eep_channel  band_5_channels[6];
	uint8_t reser10[2];
	struct iwk_eep_channel  band_24_channels[7];
	uint8_t reser11[2];
	struct iwk_eep_channel  band_52_channels[11];
	uint8_t reser12[6];
	uint16_t calib_version;
	uint8_t reser13[2];
	uint16_t satruation_power;
	uint8_t reser14[94];
	struct iwk_eep_calib_info calib_info;
	uint8_t reser15[140];
};

#define	CSR_EEPROM_REG			(CSR_BASE+0x02c)
#define	CSR_EEPROM_GP			(CSR_BASE+0x030)
#define	CSR_EEPROM_GP_VALID_MSK		0x00000007
#define	CSR_EEPROM_GP_BAD_SIGNATURE	0x00000000



#endif /* _IWK_EEPROM_H_ */
