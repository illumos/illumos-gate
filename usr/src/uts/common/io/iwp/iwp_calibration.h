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


#ifndef _IWP_CALIBRATION_H
#define	_IWP_CALIBRATION_H

#define	EEP_TX_POWER_TX_CHAINS	(3)
#define	EEP_RXIQ_CAL_CHANNELS	(7)
#define	EEP_CAL_CHANNEL_GROUP	(7)
#define	EEP_RXIQ_DRIVER_MODES	(12)

struct	tx_pow_calib_hdr {
	uint8_t		calib_version;
	uint8_t		pa_type;
	uint16_t	voltage_reading;
};

struct	iwp_eep_txpower_sample {
	uint8_t	gain_index;	/* index to power setup table */
	int8_t	power;		/* power level for this channel group */
	uint8_t	v_det;		/* PA output voltage */
	uint8_t	temp_reading;
};

struct	iwp_eep_txpower_cal {
	struct	iwp_eep_txpower_sample	samples[6];	/* 6 power level */
	/* highest power possible by hardware in this band */
	uint8_t	saturation_power;
	/* "representative" channel number in this band */
	uint8_t	group_channel;
	int8_t	t_pa_det;
	int8_t	t_actual_power;
};

struct	rx_iq_cal {
	int16_t	ars;
	int16_t	arc;
};

struct	iwp_eep_calibration {
	struct	tx_pow_calib_hdr tx_pow_calib_hdr;
	struct	iwp_eep_txpower_cal txpow_group
		[EEP_TX_POWER_TX_CHAINS][EEP_CAL_CHANNEL_GROUP];
	uint16_t	xtal_calib[2];
	int16_t		temp_calib_temp;
	int16_t		temp_calib_volt;
	uint8_t		rx_iBB_filter;
	uint8_t		reserved;
	struct	rx_iq_cal rx_iq_cal
		[EEP_RXIQ_CAL_CHANNELS][EEP_RXIQ_DRIVER_MODES];
};

#endif /* _IWP_CALIBRATION_H */
