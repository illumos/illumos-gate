/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2008, Intel Corporation
 * All rights reserved.
 */

/*
 * Sun elects to have this file available under and governed by the BSD
 * license (see below for full license text). However, the following
 * notice accompanied the original version of this file:
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


#ifndef _IWK_CALIBRATION_H_
#define	_IWK_CALIBRATION_H_

/*
 * Most Tx and Rx calibration is done by uCode during the initialization
 * phase of uCode boot. Driver must calibrate only:
 *
 * 1)  Tx power (depends on temperature)
 * 2)  Receiver gain balance (and detect disconnected antennas)
 * 3)  Receiver sensitivity (to optimize signal detection)
 */

/* START TEMPERATURE */

/*
 * 4965 temperature calculation.
 *
 * The driver must calculate the device temperature before calculating
 * a txpower setting (amplifier gain is temperature dependent).  The
 * calculation uses 4 measurements, 3 of which (R1, R2, R3) are calibration
 * values used for the life of the driver, and one of which (R4) is the
 * real-time temperature indicator.
 *
 * uCode provides all 4 values to the driver via the "initialize alive"
 * notification (see struct iwk_init_alive_resp).  After the runtime uCode
 * image loads, uCode updates the R4 value via statistics notifications
 * (see STATISTICS_NOTIFICATION), which occur after each received beacon
 * when associated, or can be requested via REPLY_STATISTICS_CMD.
 *
 * NOTE:  uCode provides the R4 value as a 23-bit signed value.  Driver
 *        must sign-extend to 32 bits before applying formula below.
 *
 * Formula:
 *
 * degrees Kelvin = ((97 * 259 * (R4 - R2) / (R3 - R1)) / 100) + 8
 *
 * NOTE:  The basic formula is 259 * (R4-R2) / (R3-R1).  The 97/100 is
 * an additional correction, which should be centered around 0 degrees
 * Celsius (273 degrees Kelvin).  The 8 (3 percent of 273) compensates for
 * centering the 97/100 correction around 0 degrees K.
 *
 * Add 273 to Kelvin value to find degrees Celsius, for comparing current
 * temperature with factory-measured temperatures when calculating txpower
 * settings.
 */

/* END TEMPERATURE */

/* START TXPOWER */

/*
 * 4965 txpower calculations rely on information from three sources:
 *
 *     1) EEPROM
 *     2) "initialize" alive notification
 *     3) statistics notifications
 *
 * EEPROM data consists of:
 *
 * 1)  Regulatory information (max txpower and channel usage flags) is provided
 *     separately for each channel that can possibly supported by 4965.
 *     40 MHz wide (.11n fat) channels are listed separately from 20 MHz
 *     (legacy) channels.
 *
 *     See struct iwk_eep_channel for format, and struct iwk_eep for
 *     locations in EEPROM.
 *
 * 2)  Factory txpower calibration information is provided separately for
 *     sub-bands of contiguous channels.  2.4GHz has just one sub-band,
 *     but 5 GHz has several sub-bands.
 *
 *     In addition, per-band (2.4 and 5 Ghz) saturation txpowers are provided.
 *
 *     See struct iwk_eep_calib_info (and the tree of structures contained
 *     within it) for format, and struct iwk_eep for locations in EEPROM.
 *
 * "Initialization alive" notification (see struct iwk_init_alive_resp)
 * consists of:
 *
 * 1)  Temperature calculation parameters.
 *
 * 2)  Power supply voltage measurement.
 *
 * 3)  Tx gain compensation to balance 2 transmitters for MIMO use.
 *
 * Statistics notifications deliver:
 *
 * 1)  Current values for temperature param R4.
 */

/*
 * To calculate a txpower setting for a given desired target txpower, channel,
 * modulation bit rate, and transmitter chain (4965 has 2 transmitters to
 * support MIMO and transmit diversity), driver must do the following:
 *
 * 1)  Compare desired txpower vs. (EEPROM) regulatory limit for this channel.
 *     Do not exceed regulatory limit; reduce target txpower if necessary.
 *
 *     If setting up txpowers for MIMO rates (rate indexes 8-15, 24-31),
 *     2 transmitters will be used simultaneously; driver must reduce the
 *     regulatory limit by 3 dB (half-power) for each transmitter, so the
 *     combined total output of the 2 transmitters is within regulatory limits.
 *
 *
 * 2)  Compare target txpower vs. (EEPROM) saturation txpower *reduced by
 *     backoff for this bit rate*.  Do not exceed (saturation - backoff[rate]);
 *     reduce target txpower if necessary.
 *
 *     Backoff values below are in 1/2 dB units (equivalent to steps in
 *     txpower gain tables):
 *
 *     OFDM 6 - 36 MBit:  10 steps (5 dB)
 *     OFDM 48 MBit:      15 steps (7.5 dB)
 *     OFDM 54 MBit:      17 steps (8.5 dB)
 *     OFDM 60 MBit:      20 steps (10 dB)
 *     CCK all rates:     10 steps (5 dB)
 *
 *     Backoff values apply to saturation txpower on a per-transmitter basis;
 *     when using MIMO (2 transmitters), each transmitter uses the same
 *     saturation level provided in EEPROM, and the same backoff values;
 *     no reduction (such as with regulatory txpower limits) is required.
 *
 *     Saturation and Backoff values apply equally to 20 Mhz (legacy) channel
 *     widths and 40 Mhz (.11n fat) channel widths; there is no separate
 *     factory measurement for fat channels.
 *
 *     The result of this step is the final target txpower.  The rest of
 *     the steps figure out the proper settings for the device.
 *
 *
 * 3)  Determine (EEPROM) calibration subband for the target channel, by
 *     comparing against first and last channels in each subband
 *     (see struct iwk_eep_calib_subband_info).
 *
 *
 * 4)  Linearly interpolate (EEPROM) factory calibration measurement sets,
 *     referencing the 2 factory-measured (sample) channels within the subband.
 *
 *     Interpolation is based on difference between target channel's frequency
 *     and the sample channels' frequencies.  Since channel numbers are based
 *     on frequency (5 MHz between each channel number), this is equivalent
 *     to interpolating based on channel number differences.
 *
 *     Note that the sample channels may or may not be the channels at the
 *     edges of the subband.  The target channel may be "outside" of the
 *     span of the sampled channels.
 *
 *     Driver may choose the pair (for 2 Tx chains) of measurements (see
 *     struct iwk_eep_calib_channel_info) for which the actual measured
 *     txpower comes closest to the desired txpower.  Usually, though,
 *     the middle set of measurements is closest to the regulatory limits,
 *     and is therefore a good choice for all txpower calculations.
 *
 *     Driver should interpolate both members of the chosen measurement pair,
 *     i.e. for both Tx chains (radio transmitters), unless the driver knows
 *     that only one of the chains will be used (e.g. only one tx antenna
 *     connected, but this should be unusual).
 *
 *     Driver should interpolate factory values for temperature, gain table
 *     index, and actual power.  The power amplifier detector values are
 *     not used by the driver.
 *
 *     If the target channel happens to be one of the sample channels, the
 *     results should agree with the sample channel's measurements!
 *
 *
 * 5)  Find difference between desired txpower and (interpolated)
 *     factory-measured txpower.  Using (interpolated) factory gain table index
 *     as a starting point, adjust this index lower to increase txpower,
 *     or higher to decrease txpower, until the target txpower is reached.
 *     Each step in the gain table is 1/2 dB.
 *
 *     For example, if factory measured txpower is 16 dBm, and target txpower
 *     is 13 dBm, add 6 steps to the factory gain index to reduce txpower
 *     by 3 dB.
 *
 *
 * 6)  Find difference between current device temperature and (interpolated)
 *     factory-measured temperature for sub-band.  Factory values are in
 *     degrees Celsius.  To calculate current temperature, see comments for
 *     "4965 temperature calculation".
 *
 *     If current temperature is higher than factory temperature, driver must
 *     increase gain (lower gain table index), and vice versa.
 *
 *     Temperature affects gain differently for different channels:
 *
 *     2.4 GHz all channels:  3.5 degrees per half-dB step
 *     5 GHz channels 34-43:  4.5 degrees per half-dB step
 *     5 GHz channels >= 44:  4.0 degrees per half-dB step
 *
 *     NOTE:  Temperature can increase rapidly when transmitting, especially
 *            with heavy traffic at high txpowers.  Driver should update
 *            temperature calculations often under these conditions to
 *            maintain strong txpower in the face of rising temperature.
 *
 *
 * 7)  Find difference between current power supply voltage indicator
 *     (from "initialize alive") and factory-measured power supply voltage
 *     indicator (EEPROM).
 *
 *     If the current voltage is higher (indicator is lower) than factory
 *     voltage, gain should be reduced (gain table index increased) by:
 *
 *     (eeprom - current) / 7
 *
 *     If the current voltage is lower (indicator is higher) than factory
 *     voltage, gain should be increased (gain table index decreased) by:
 *
 *     2 * (current - eeprom) / 7
 *
 *     If number of index steps in either direction turns out to be > 2,
 *     something is wrong ... just use 0.
 *
 *     NOTE:  Voltage compensation is independent of band/channel.
 *
 *     NOTE:  "Initialize" uCode measures current voltage, which is assumed
 *            to be constant after this initial measurement.  Voltage
 *            compensation for txpower (number of steps in gain table)
 *            may be calculated once and used until the next uCode bootload.
 *
 *
 * 8)  If setting up txpowers for MIMO rates (rate indexes 8-15, 24-31),
 *     adjust txpower for each transmitter chain, so txpower is balanced
 *     between the two chains.  There are 5 pairs of tx_atten[group][chain]
 *     values in "initialize alive", one pair for each of 5 channel ranges:
 *
 *     Group 0:  5 GHz channel 34-43
 *     Group 1:  5 GHz channel 44-70
 *     Group 2:  5 GHz channel 71-124
 *     Group 3:  5 GHz channel 125-200
 *     Group 4:  2.4 GHz all channels
 *
 *     Add the tx_atten[group][chain] value to the index for the target chain.
 *     The values are signed, but are in pairs of 0 and a non-negative number,
 *     so as to reduce gain (if necessary) of the "hotter" channel.  This
 *     avoids any need to double-check for regulatory compliance after
 *     this step.
 *
 *
 * 9)  If setting up for a CCK rate, lower the gain by adding a CCK compensation
 *     value to the index:
 *
 *     Hardware rev B:  9 steps (4.5 dB)
 *     Hardware rev C:  5 steps (2.5 dB)
 *
 *     Hardware rev for 4965 can be determined by reading CSR_HW_REV_WA_REG,
 *     bits [3:2], 1 = B, 2 = C.
 *
 *     NOTE:  This compensation is in addition to any saturation backoff that
 *            might have been applied in an earlier step.
 *
 *
 * 10) Select the gain table, based on band (2.4 vs 5 GHz).
 *
 *     Limit the adjusted index to stay within the table!
 *
 *
 * 11) Read gain table entries for DSP and radio gain, place into appropriate
 *     location(s) in command.
 */

/* Temperature calibration offset is 3% 0C in Kelvin */
#define	TEMPERATURE_CALIB_KELVIN_OFFSET 8
#define	TEMPERATURE_CALIB_A_VAL 259

#define	KELVIN_TO_CELSIUS(x) ((x)-273)
#define	CELSIUS_TO_KELVIN(x) ((x)+273)

/* First and last channels of all groups */
#define	CALIB_IWK_TX_ATTEN_GR1_FCH 34
#define	CALIB_IWK_TX_ATTEN_GR1_LCH 43
#define	CALIB_IWK_TX_ATTEN_GR2_FCH 44
#define	CALIB_IWK_TX_ATTEN_GR2_LCH 70
#define	CALIB_IWK_TX_ATTEN_GR3_FCH 71
#define	CALIB_IWK_TX_ATTEN_GR3_LCH 124
#define	CALIB_IWK_TX_ATTEN_GR4_FCH 125
#define	CALIB_IWK_TX_ATTEN_GR4_LCH 200
#define	CALIB_IWK_TX_ATTEN_GR5_FCH 1
#define	CALIB_IWK_TX_ATTEN_GR5_LCH 20

/* Limit range of txpower output target to be between these values */
#define	IWK_TX_POWER_TARGET_POWER_MIN  (0)   /* 0 dBm = 1 milliwatt */
#define	IWK_TX_POWER_TARGET_POWER_MAX  (16)  /* 16 dBm */

#define	TX_POWER_IWK_ILLEGAL_VOLTAGE  (-10000)

/*
 * 4965 power supply voltage compensation
 */
#define	TX_POWER_IWK_VOLTAGE_CODES_PER_03V  (7)

/* Limit range of calculated temperature to be between these Kelvin values */
#define	IWK_TX_POWER_TEMPERATURE_MIN  (263)
#define	IWK_TX_POWER_TEMPERATURE_MAX  (410)

union iwk_tx_power_dual_stream {
	struct {
		uint8_t radio_tx_gain[2];
		uint8_t dsp_predis_atten[2];
	} s;
	uint32_t dw;
};

#define	POWER_TABLE_NUM_ENTRIES	(33)
#define	POWER_TABLE_CCK_ENTRY	(32)

/*
 * When MIMO is used (2 transmitters operating simultaneously), driver should
 * limit each transmitter to deliver a max of 3 dB below the regulatory limit
 * for the device.  That is, half power for each transmitter, so total power
 * is within regulatory limits.
 *
 * The value "6" represents number of steps in gain table to reduce power.
 * Each step is 1/2 dB.
 */
#define	IWK_TX_POWER_MIMO_REGULATORY_COMPENSATION	(6)

/*
 * CCK gain compensation.
 *
 * When calculating txpowers for CCK, after making sure that the target power
 * is within regulatory and saturation limits, driver must additionally
 * back off gain by adding these values to the gain table index.
 */
#define	IWK_TX_POWER_CCK_COMPENSATION_C_STEP	(5)

/*
 * Gain tables.
 *
 * The following tables contain pair of values for setting txpower, i.e.
 * gain settings for the output of the device's digital signal processor (DSP),
 * and for the analog gain structure of the transmitter.
 *
 * Each entry in the gain tables represents a step of 1/2 dB.  Note that these
 * are *relative* steps, not indications of absolute output power.  Output
 * power varies with temperature, voltage, and channel frequency, and also
 * requires consideration of average power (to satisfy regulatory constraints),
 * and peak power (to avoid distortion of the output signal).
 *
 * Each entry contains two values:
 * 1)  DSP gain (or sometimes called DSP attenuation).  This is a fine-grained
 *     linear value that multiplies the output of the digital signal processor,
 *     before being sent to the analog radio.
 * 2)  Radio gain.  This sets the analog gain of the radio Tx path.
 *     It is a coarser setting, and behaves in a logarithmic (dB) fashion.
 *
 * EEPROM contains factory calibration data for txpower.  This maps actual
 * measured txpower levels to gain settings in the "well known" tables
 * below ("well-known" means here that both factory calibration *and* the
 * driver work with the same table).
 *
 * There are separate tables for 2.4 GHz and 5 GHz bands.  The 5 GHz table
 * has an extension (into negative indexes), in case the driver needs to
 * boost power setting for high device temperatures (higher than would be
 * present during factory calibration).  A 5 Ghz EEPROM index of "40"
 * corresponds to the 49th entry in the table used by the driver.
 */
#define	MIN_TX_GAIN_INDEX	(0) /* highest gain, lowest idx, 2.4 */
#define	MIN_TX_GAIN_INDEX_52GHZ_EXT	(-9) /* highest gain, lowest idx, 5 */

struct gain_entry {
	uint8_t	dsp;
	uint8_t	radio;
};

static const struct gain_entry gains_table[2][108] = {
	/* 5.2GHz power gain index table */
	{
		{123, 0x3F},	/* highest txpower */
		{117, 0x3F},
		{110, 0x3F},
		{104, 0x3F},
		{98, 0x3F},
		{110, 0x3E},
		{104, 0x3E},
		{98, 0x3E},
		{110, 0x3D},
		{104, 0x3D},
		{98, 0x3D},
		{110, 0x3C},
		{104, 0x3C},
		{98, 0x3C},
		{110, 0x3B},
		{104, 0x3B},
		{98, 0x3B},
		{110, 0x3A},
		{104, 0x3A},
		{98, 0x3A},
		{110, 0x39},
		{104, 0x39},
		{98, 0x39},
		{110, 0x38},
		{104, 0x38},
		{98, 0x38},
		{110, 0x37},
		{104, 0x37},
		{98, 0x37},
		{110, 0x36},
		{104, 0x36},
		{98, 0x36},
		{110, 0x35},
		{104, 0x35},
		{98, 0x35},
		{110, 0x34},
		{104, 0x34},
		{98, 0x34},
		{110, 0x33},
		{104, 0x33},
		{98, 0x33},
		{110, 0x32},
		{104, 0x32},
		{98, 0x32},
		{110, 0x31},
		{104, 0x31},
		{98, 0x31},
		{110, 0x30},
		{104, 0x30},
		{98, 0x30},
		{110, 0x25},
		{104, 0x25},
		{98, 0x25},
		{110, 0x24},
		{104, 0x24},
		{98, 0x24},
		{110, 0x23},
		{104, 0x23},
		{98, 0x23},
		{110, 0x22},
		{104, 0x18},
		{98, 0x18},
		{110, 0x17},
		{104, 0x17},
		{98, 0x17},
		{110, 0x16},
		{104, 0x16},
		{98, 0x16},
		{110, 0x15},
		{104, 0x15},
		{98, 0x15},
		{110, 0x14},
		{104, 0x14},
		{98, 0x14},
		{110, 0x13},
		{104, 0x13},
		{98, 0x13},
		{110, 0x12},
		{104, 0x08},
		{98, 0x08},
		{110, 0x07},
		{104, 0x07},
		{98, 0x07},
		{110, 0x06},
		{104, 0x06},
		{98, 0x06},
		{110, 0x05},
		{104, 0x05},
		{98, 0x05},
		{110, 0x04},
		{104, 0x04},
		{98, 0x04},
		{110, 0x03},
		{104, 0x03},
		{98, 0x03},
		{110, 0x02},
		{104, 0x02},
		{98, 0x02},
		{110, 0x01},
		{104, 0x01},
		{98, 0x01},
		{110, 0x00},
		{104, 0x00},
		{98, 0x00},
		{93, 0x00},
		{88, 0x00},
		{83, 0x00},
		{78, 0x00},
	},
	/* 2.4GHz power gain index table */
	{
		{110, 0x3f},	/* highest txpower */
		{104, 0x3f},
		{98, 0x3f},
		{110, 0x3e},
		{104, 0x3e},
		{98, 0x3e},
		{110, 0x3d},
		{104, 0x3d},
		{98, 0x3d},
		{110, 0x3c},
		{104, 0x3c},
		{98, 0x3c},
		{110, 0x3b},
		{104, 0x3b},
		{98, 0x3b},
		{110, 0x3a},
		{104, 0x3a},
		{98, 0x3a},
		{110, 0x39},
		{104, 0x39},
		{98, 0x39},
		{110, 0x38},
		{104, 0x38},
		{98, 0x38},
		{110, 0x37},
		{104, 0x37},
		{98, 0x37},
		{110, 0x36},
		{104, 0x36},
		{98, 0x36},
		{110, 0x35},
		{104, 0x35},
		{98, 0x35},
		{110, 0x34},
		{104, 0x34},
		{98, 0x34},
		{110, 0x33},
		{104, 0x33},
		{98, 0x33},
		{110, 0x32},
		{104, 0x32},
		{98, 0x32},
		{110, 0x31},
		{104, 0x31},
		{98, 0x31},
		{110, 0x30},
		{104, 0x30},
		{98, 0x30},
		{110, 0x6},
		{104, 0x6},
		{98, 0x6},
		{110, 0x5},
		{104, 0x5},
		{98, 0x5},
		{110, 0x4},
		{104, 0x4},
		{98, 0x4},
		{110, 0x3},
		{104, 0x3},
		{98, 0x3},
		{110, 0x2},
		{104, 0x2},
		{98, 0x2},
		{110, 0x1},
		{104, 0x1},
		{98, 0x1},
		{110, 0x0},
		{104, 0x0},
		{98, 0x0},
		{97, 0},
		{96, 0},
		{95, 0},
		{94, 0},
		{93, 0},
		{92, 0},
		{91, 0},
		{90, 0},
		{89, 0},
		{88, 0},
		{87, 0},
		{86, 0},
		{85, 0},
		{84, 0},
		{83, 0},
		{82, 0},
		{81, 0},
		{80, 0},
		{79, 0},
		{78, 0},
		{77, 0},
		{76, 0},
		{75, 0},
		{74, 0},
		{73, 0},
		{72, 0},
		{71, 0},
		{70, 0},
		{69, 0},
		{68, 0},
		{67, 0},
		{66, 0},
		{65, 0},
		{64, 0},
		{63, 0},
		{62, 0},
		{61, 0},
		{60, 0},
		{59, 0},
	}
};

/* END TXPOWER */

struct statistics_div {
	uint32_t tx_on_a;
	uint32_t tx_on_b;
	uint32_t exec_time;
	uint32_t probe_time;
	uint32_t reserved1;
	uint32_t reserved2;
};

struct statistics_dbg {
	uint32_t burst_check;
	uint32_t burst_count;
	uint32_t reserved[4];
};


struct statistics_general {
	uint32_t temperature;
	uint32_t temperature_m;
	struct statistics_dbg dbg;
	uint32_t sleep_time;
	uint32_t slots_out;
	uint32_t slots_idle;
	uint32_t ttl_timestamp;
	struct statistics_div div;
	uint32_t rx_enable_counter;
	uint32_t reserved1;
	uint32_t reserved2;
	uint32_t reserved3;
};


struct statistics_tx_non_phy_agg {
	uint32_t ba_timeout;
	uint32_t ba_reschedule_frames;
	uint32_t scd_query_agg_frame_cnt;
	uint32_t scd_query_no_agg;
	uint32_t scd_query_agg;
	uint32_t scd_query_mismatch;
	uint32_t frame_not_ready;
	uint32_t underrun;
	uint32_t bt_prio_kill;
	uint32_t rx_ba_rsp_cnt;
	uint32_t reserved2;
	uint32_t reserved3;
};


struct statistics_tx {
	uint32_t preamble_cnt;
	uint32_t rx_detected_cnt;
	uint32_t bt_prio_defer_cnt;
	uint32_t bt_prio_kill_cnt;
	uint32_t few_bytes_cnt;
	uint32_t cts_timeout;
	uint32_t ack_timeout;
	uint32_t expected_ack_cnt;
	uint32_t actual_ack_cnt;
	uint32_t dump_msdu_cnt;
	uint32_t burst_abort_next_frame_mismatch_cnt;
	uint32_t burst_abort_missing_next_frame_cnt;
	uint32_t cts_timeout_collision;
	uint32_t ack_or_ba_timeout_collision;
	struct statistics_tx_non_phy_agg agg;
};


struct statistics_rx_ht_phy {
	uint32_t plcp_err;
	uint32_t overrun_err;
	uint32_t early_overrun_err;
	uint32_t crc32_good;
	uint32_t crc32_err;
	uint32_t mh_format_err;
	uint32_t agg_crc32_good;
	uint32_t agg_mpdu_cnt;
	uint32_t agg_cnt;
	uint32_t reserved2;
};

struct statistics_rx_non_phy {
	uint32_t bogus_cts; /* CTS received when not expecting CTS */
	uint32_t bogus_ack; /* ACK received when not expecting ACK */
	uint32_t non_bssid_frames; /* number of frames with BSSID that */
					/* doesn't belong to the STA BSSID */
	uint32_t filtered_frames; /* count frames that were dumped in the */
					/* filtering process */
	uint32_t non_channel_beacons; /* beacons with our bss id but not on */
					/* our serving channel */
	uint32_t channel_beacons; /* beacons with our bss id and in our */
					/* serving channel */
	uint32_t num_missed_bcon; /* number of missed beacons */
	uint32_t adc_rx_saturation_time; /* count in 0.8us units the time */
					/* the ADC was in saturation */
	uint32_t ina_detection_search_time; /* total time (in 0.8us) */
						/* searched for INA */
	uint32_t beacon_silence_rssi_a; /* RSSI silence after beacon frame */
	uint32_t beacon_silence_rssi_b; /* RSSI silence after beacon frame */
	uint32_t beacon_silence_rssi_c; /* RSSI silence after beacon frame */
	uint32_t interference_data_flag; /* flag for interference data */
					/* availability. 1 when data is */
					/* available. */
	uint32_t channel_load; /* counts RX Enable time */
	uint32_t dsp_false_alarms; /* DSP false alarm (both OFDM */
					/* and CCK) counter */
	uint32_t beacon_rssi_a;
	uint32_t beacon_rssi_b;
	uint32_t beacon_rssi_c;
	uint32_t beacon_energy_a;
	uint32_t beacon_energy_b;
	uint32_t beacon_energy_c;
};

struct statistics_rx_phy {
	uint32_t ina_cnt;
	uint32_t fina_cnt;
	uint32_t plcp_err;
	uint32_t crc32_err;
	uint32_t overrun_err;
	uint32_t early_overrun_err;
	uint32_t crc32_good;
	uint32_t false_alarm_cnt;
	uint32_t fina_sync_err_cnt;
	uint32_t sfd_timeout;
	uint32_t fina_timeout;
	uint32_t unresponded_rts;
	uint32_t rxe_frame_limit_overrun;
	uint32_t sent_ack_cnt;
	uint32_t sent_cts_cnt;
	uint32_t sent_ba_rsp_cnt;
	uint32_t dsp_self_kill;
	uint32_t mh_format_err;
	uint32_t re_acq_main_rssi_sum;
	uint32_t reserved3;
};

struct statistics_rx {
	struct statistics_rx_phy ofdm;
	struct statistics_rx_phy cck;
	struct statistics_rx_non_phy general;
	struct statistics_rx_ht_phy ofdm_ht;
};

struct iwk_notif_statistics {
	uint32_t flag;
	struct statistics_rx rx;
	struct statistics_tx tx;
	struct statistics_general general;
};

/* START Receiver gain balance */

/*
 * REPLY_PHY_CALIBRATION_CMD = 0xb0 (command, has simple generic response)
 *
 * This command sets the relative gains of 4965's 3 radio receiver chains.
 *
 * After the first association, driver should accumulate signal and noise
 * statistics from the STATISTICS_NOTIFICATIONs that follow the first 20
 * beacons from the associated network (don't collect statistics that come
 * in from scanning, or any other non-network source).
 *
 * DISCONNECTED ANTENNA:
 *
 * Driver should determine which antennas are actually connected, by comparing
 * average beacon signal levels for the 3 Rx chains.  Accumulate (add) the
 * following values over 20 beacons, one accumulator for each of the chains
 * a/b/c, from struct statistics_rx_non_phy:
 *
 * beacon_rssi_[abc] & 0x0FF (unsigned, units in dB)
 *
 * Find the strongest signal from among a/b/c.  Compare the other two to the
 * strongest.  If any signal is more than 15 dB (times 20, unless you
 * divide the accumulated values by 20) below the strongest, the driver
 * considers that antenna to be disconnected, and should not try to use that
 * antenna/chain for Rx or Tx.  If both A and B seem to be disconnected,
 * driver should declare the stronger one as connected, and attempt to use it
 * (A and B are the only 2 Tx chains!).
 *
 *
 * RX BALANCE:
 *
 * Driver should balance the 3 receivers (but just the ones that are connected
 * to antennas, see above) for gain, by comparing the average signal levels
 * detected during the silence after each beacon (background noise).
 * Accumulate (add) the following values over 20 beacons, one accumulator for
 * each of the chains a/b/c, from struct statistics_rx_non_phy:
 *
 * beacon_silence_rssi_[abc] & 0x0FF (unsigned, units in dB)
 *
 * Find the weakest background noise level from among a/b/c.  This Rx chain
 * will be the reference, with 0 gain adjustment.  Attenuate other channels by
 * finding noise difference:
 *
 * (accum_noise[i] - accum_noise[reference]) / 30
 *
 * The "30" adjusts the dB in the 20 accumulated samples to units of 1.5 dB.
 * For use in diff_gain_[abc] fields of struct iwk_calibration_cmd, the
 * driver should limit the difference results to a range of 0-3 (0-4.5 dB),
 * and set bit 2 to indicate "reduce gain".  The value for the reference
 * (weakest) chain should be "0".
 *
 * diff_gain_[abc] bit fields:
 *   2: (1) reduce gain, (0) increase gain
 * 1-0: amount of gain, units of 1.5 dB
 */

#define	RX_CHAINS_NUM  (3)
#define	CHAIN_GAIN_DIFF_INIT_VAL  (4)

#define	IWK_GAIN_DIFF_ALIVE (0)
#define	IWK_GAIN_DIFF_ACCUMULATE (1)
#define	IWK_GAIN_DIFF_CALIBRATED (2)

#define	INTERFERENCE_DATA_AVAILABLE  (1)
#define	BEACON_NUM_20  (20)
#define	MAX_ALLOWED_DIFF  (15)

struct iwk_rx_gain_diff {
	uint8_t		state;
	uint16_t	beacon_count;
	uint8_t		gain_diff_send;
	uint32_t	beacon_stren_a;
	uint32_t	beacon_stren_b;
	uint32_t	beacon_stren_c;
	uint32_t	noise_stren_a;
	uint32_t	noise_stren_b;
	uint32_t	noise_stren_c;
	uint8_t		disconnect_chain[RX_CHAINS_NUM];
	uint8_t		connected_chains;
	uint8_t		gain_diff_chain[RX_CHAINS_NUM];
};

/* END Receiver gain balance */

/* START Receiver sensitivity */

/*
 * SENSITIVITY_CMD = 0xa8
 *
 * This command sets up the Rx signal detector for a sensitivity level that
 * is high enough to lock onto all signals within the associated network,
 * but low enough to ignore signals that are below a certain threshold, so as
 * not to have too many "false alarms".  False alarms are signals that the
 * Rx DSP tries to lock onto, but then discards after determining that they
 * are noise.
 *
 * The optimum number of false alarms is between 5 and 50 per 200 TUs
 * (200 * 1024 uSecs, i.e. 204.8 milliseconds) of actual Rx time (i.e.
 * time listening, not transmitting).  Driver must adjust sensitivity so that
 * the ratio of actual false alarms to actual Rx time falls within this range.
 *
 * While associated, uCode delivers STATISTICS_NOTIFICATIONs after each
 * received beacon.  These provide information to the driver to analyze the
 * sensitivity.  Don't analyze statistics that come in from scanning, or any
 * other non-associated-network source.  Pertinent statistics include:
 *
 * From "general" statistics (struct statistics_rx_non_phy):
 *
 * (beacon_energy_[abc] & 0x0FF00) >> 8 (unsigned, higher value is lower level)
 *   Measure of energy of desired signal.  Used for establishing a level
 *   below which the device does not detect signals.
 *
 * (beacon_silence_rssi_[abc] & 0x0FF00) >> 8 (unsigned, units in dB)
 *   Measure of background noise in silent period after beacon.
 *
 * channel_load
 *   uSecs of actual Rx time during beacon period (varies according to
 *   how much time was spent transmitting).
 *
 * From "cck" and "ofdm" statistics (struct statistics_rx_phy), separately:
 *
 * false_alarm_cnt
 *   Signal locks abandoned early (before phy-level header).
 *
 * plcp_err
 *   Signal locks abandoned late (during phy-level header).
 *
 * NOTE:  Both false_alarm_cnt and plcp_err increment monotonically from
 *        beacon to beacon, i.e. each value is an accumulation of all errors
 *        before and including the latest beacon.  Values will wrap around to 0
 *        after counting up to 2^32 - 1.  Driver must differentiate vs.
 *        previous beacon's values to determine # false alarms in the current
 *        beacon period.
 *
 * Total number of false alarms = false_alarms + plcp_errs
 *
 * For OFDM, adjust the following table entries in struct iwk_rx_sensitivity_cmd
 * (notice that the start points for OFDM are at or close to settings for
 * maximum sensitivity):
 *
 *                                             START  /  MIN  /  MAX
 *   HD_AUTO_CORR32_X1_TH_ADD_MIN_INDEX          90   /   85  /  120
 *   HD_AUTO_CORR32_X1_TH_ADD_MIN_MRC_INDEX     170   /  170  /  210
 *   HD_AUTO_CORR32_X4_TH_ADD_MIN_INDEX         105   /  105  /  140
 *   HD_AUTO_CORR32_X4_TH_ADD_MIN_MRC_INDEX     220   /  220  /  270
 *
 *   If actual rate of OFDM false alarms (+ plcp_errors) is too high
 *   (greater than 50 for each 204.8 msecs listening), reduce sensitivity
 *   by *adding* 1 to all 4 of the table entries above, up to the max for
 *   each entry.  Conversely, if false alarm rate is too low (less than 5
 *   for each 204.8 msecs listening), *subtract* 1 from each entry to
 *   increase sensitivity.
 *
 * For CCK sensitivity, keep track of the following:
 *
 *   1).  20-beacon history of maximum background noise, indicated by
 *        (beacon_silence_rssi_[abc] & 0x0FF00), units in dB, across the
 *        3 receivers.  For any given beacon, the "silence reference" is
 *        the maximum of last 60 samples (20 beacons * 3 receivers).
 *
 *   2).  10-beacon history of strongest signal level, as indicated
 *        by (beacon_energy_[abc] & 0x0FF00) >> 8, across the 3 receivers,
 *        i.e. the strength of the signal through the best receiver at the
 *        moment.  These measurements are "upside down", with lower values
 *        for stronger signals, so max energy will be *minimum* value.
 *
 *        Then for any given beacon, the driver must determine the *weakest*
 *        of the strongest signals; this is the minimum level that needs to be
 *        successfully detected, when using the best receiver at the moment.
 *        "Max cck energy" is the maximum (higher value means lower energy!)
 *        of the last 10 minima.  Once this is determined, driver must add
 *        a little margin by adding "6" to it.
 *
 *   3).  Number of consecutive beacon periods with too few false alarms.
 *        Reset this to 0 at the first beacon period that falls within the
 *        "good" range (5 to 50 false alarms per 204.8 milliseconds rx).
 *
 * Then, adjust the following CCK table entries in struct iwk_rx_sensitivity_cmd
 * (notice that the start points for CCK are at maximum sensitivity):
 *
 *                                             START  /  MIN  /  MAX
 *   HD_AUTO_CORR40_X4_TH_ADD_MIN_INDEX         125   /  125  /  200
 *   HD_AUTO_CORR40_X4_TH_ADD_MIN_MRC_INDEX     200   /  200  /  400
 *   HD_MIN_ENERGY_CCK_DET_INDEX                100   /    0  /  100
 *
 *   If actual rate of CCK false alarms (+ plcp_errors) is too high
 *   (greater than 50 for each 204.8 msecs listening), method for reducing
 *   sensitivity is:
 *
 *   1)  *Add* 3 to value in HD_AUTO_CORR40_X4_TH_ADD_MIN_MRC_INDEX,
 *       up to max 400.
 *
 *   2)  If current value in HD_AUTO_CORR40_X4_TH_ADD_MIN_INDEX is < 160,
 *       sensitivity has been reduced a significant amount; bring it up to
 *       a moderate 161.  Otherwise, *add* 3, up to max 200.
 *
 *   3)  a)  If current value in HD_AUTO_CORR40_X4_TH_ADD_MIN_INDEX is > 160,
 *       sensitivity has been reduced only a moderate or small amount;
 *       *subtract* 2 from value in HD_MIN_ENERGY_CCK_DET_INDEX,
 *       down to min 0.  Otherwise (if gain has been significantly reduced),
 *       don't change the HD_MIN_ENERGY_CCK_DET_INDEX value.
 *
 *       b)  Save a snapshot of the "silence reference".
 *
 *   If actual rate of CCK false alarms (+ plcp_errors) is too low
 *   (less than 5 for each 204.8 msecs listening), method for increasing
 *   sensitivity is used only if:
 *
 *   1a)  Previous beacon did not have too many false alarms
 *   1b)  AND difference between previous "silence reference" and current
 *        "silence reference" (prev - current) is 2 or more,
 *   OR 2)  100 or more consecutive beacon periods have had rate of
 *          less than 5 false alarms per 204.8 milliseconds rx time.
 *
 *   Method for increasing sensitivity:
 *
 *   1)  *Subtract* 3 from value in HD_AUTO_CORR40_X4_TH_ADD_MIN_INDEX,
 *       down to min 125.
 *
 *   2)  *Subtract* 3 from value in HD_AUTO_CORR40_X4_TH_ADD_MIN_MRC_INDEX,
 *       down to min 200.
 *
 *   3)  *Add* 2 to value in HD_MIN_ENERGY_CCK_DET_INDEX, up to max 100.
 *
 *   If actual rate of CCK false alarms (+ plcp_errors) is within good range
 *   (between 5 and 50 for each 204.8 msecs listening):
 *
 *   1)  Save a snapshot of the silence reference.
 *
 *   2)  If previous beacon had too many CCK false alarms (+ plcp_errors),
 *       give some extra margin to energy threshold by *subtracting* 8
 *       from value in HD_MIN_ENERGY_CCK_DET_INDEX.
 *
 *   For all cases (too few, too many, good range), make sure that the CCK
 *   detection threshold (energy) is below the energy level for robust
 *   detection over the past 10 beacon periods, the "Max cck energy".
 *   Lower values mean higher energy; this means making sure that the value
 *   in HD_MIN_ENERGY_CCK_DET_INDEX is at or *above* "Max cck energy".
 *
 * Driver should set the following entries to fixed values:
 *
 *   HD_MIN_ENERGY_OFDM_DET_INDEX               100
 *   HD_BARKER_CORR_TH_ADD_MIN_INDEX            190
 *   HD_BARKER_CORR_TH_ADD_MIN_MRC_INDEX        390
 *   HD_OFDM_ENERGY_TH_IN_INDEX                  62
 */

#define	IWK_SENSITIVITY_CALIB_ALLOW_MSK  (1 << 0)
#define	IWK_SENSITIVITY_OFDM_UPDATE_MSK  (1 << 1)
#define	IWK_SENSITIVITY_CCK_UPDATE_MSK   (1 << 2)

#define	MIN_ENERGY_CCK_DET_IDX			(0)
#define	MIN_ENERGY_OFDM_DET_IDX			(1)
#define	AUTO_CORR32_X1_TH_ADD_MIN_IDX		(2)
#define	AUTO_CORR32_X1_TH_ADD_MIN_MRC_IDX	(3)
#define	AUTO_CORR40_X4_TH_ADD_MIN_MRC_IDX	(4)
#define	AUTO_CORR32_X4_TH_ADD_MIN_IDX		(5)
#define	AUTO_CORR32_X4_TH_ADD_MIN_MRC_IDX	(6)
#define	BARKER_CORR_TH_ADD_MIN_IDX		(7)
#define	BARKER_CORR_TH_ADD_MIN_MRC_IDX		(8)
#define	AUTO_CORR40_X4_TH_ADD_MIN_IDX		(9)
#define	PTAM_ENERGY_TH_IDX			(10)

#define	IWK_GOOD_RANGE_FALSE_ALARM	(0)
#define	IWK_TOO_MANY_FALSE_ALARM	(1)
#define	IWK_TOO_FEW_FALSE_ALARM		(2)

#define	IWK_SENSITIVITY_CONTROL_DEFAULT_TABLE	(0)
#define	IWK_SENSITIVITY_CONTROL_WORK_TABLE	(1)

struct iwk_rx_sensitivity_cmd {
	uint16_t  control;
	uint16_t  table[11];
};

struct iwk_rx_sensitivity {
	uint16_t  auto_corr_ofdm_x4;
	uint16_t  auto_corr_mrc_ofdm_x4;
	uint16_t  auto_corr_ofdm_x1;
	uint16_t  auto_corr_mrc_ofdm_x1;

	uint16_t  auto_corr_cck_x4;
	uint16_t  auto_corr_mrc_cck_x4;
	uint16_t  min_energy_det_cck;

	uint16_t  flags;

	uint32_t  last_bad_plcp_cnt_ofdm;
	uint32_t  last_false_alarm_cnt_ofdm;
	uint32_t  last_bad_plcp_cnt_cck;
	uint32_t  last_false_alarm_cnt_cck;

	uint32_t  cck_curr_state;
	uint32_t  cck_prev_state;
	uint32_t  cck_beacon_min[10];
	uint32_t  cck_beacon_idx;
	uint8_t   cck_noise_max[20];
	uint32_t  cck_noise_ref;
	uint32_t  cck_noise_idx;
	int32_t   cck_noise_diff;
	uint32_t  cck_no_false_alarm_num;
};

/* END Receiver sensitivity */

#endif /* _IWK_CALIBRATION_H_ */
