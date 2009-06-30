/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2004 Video54 Technologies, Inc.
 * Copyright (c) 2004-2008 Atheros Communications, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ddi.h>

#include "arn_core.h"

static struct ath_rate_table ar5416_11na_ratetable = {
	42,
	{0},
	{
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 6000, /* 6 Mb */
			5400, 0x0b, 0x00, 12,
			0, 2, 1, 0, 0, 0, 0, 0 },
		{ VALID,	VALID, WLAN_RC_PHY_OFDM, 9000, /* 9 Mb */
			7800,  0x0f, 0x00, 18,
			0, 3, 1, 1, 1, 1, 1, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 12000, /* 12 Mb */
			10000, 0x0a, 0x00, 24,
			2, 4, 2, 2, 2, 2, 2, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 18000, /* 18 Mb */
			13900, 0x0e, 0x00, 36,
			2, 6,  2, 3, 3, 3, 3, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 24000, /* 24 Mb */
			17300, 0x09, 0x00, 48,
			4, 10, 3, 4, 4, 4, 4, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 36000, /* 36 Mb */
			23000, 0x0d, 0x00, 72,
			4, 14, 3, 5, 5, 5, 5, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 48000, /* 48 Mb */
			27400, 0x08, 0x00, 96,
			4, 20, 3, 6, 6, 6, 6, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 54000, /* 54 Mb */
			29300, 0x0c, 0x00, 108,
			4, 23, 3, 7, 7, 7, 7, 0 },
		{ VALID_20, VALID_20, WLAN_RC_PHY_HT_20_SS, 6500, /* 6.5 Mb */
			6400, 0x80, 0x00, 0,
			0, 2, 3, 8, 24, 8, 24, 3216 },
		{ VALID_20, VALID_20, WLAN_RC_PHY_HT_20_SS, 13000, /* 13 Mb */
			12700, 0x81, 0x00, 1,
			2, 4, 3, 9, 25, 9, 25, 6434 },
		{ VALID_20, VALID_20, WLAN_RC_PHY_HT_20_SS, 19500, /* 19.5 Mb */
			18800, 0x82, 0x00, 2,
			2, 6, 3, 10, 26, 10, 26, 9650 },
		{ VALID_20, VALID_20, WLAN_RC_PHY_HT_20_SS, 26000, /* 26 Mb */
			25000, 0x83, 0x00, 3,
			4, 10, 3, 11, 27, 11, 27, 12868 },
		{ VALID_20, VALID_20, WLAN_RC_PHY_HT_20_SS, 39000, /* 39 Mb */
			36700, 0x84, 0x00, 4,
			4, 14, 3, 12, 28, 12, 28, 19304 },
		{ INVALID, VALID_20, WLAN_RC_PHY_HT_20_SS, 52000, /* 52 Mb */
			48100, 0x85, 0x00, 5,
			4, 20, 3, 13, 29, 13, 29, 25740 },
		{ INVALID, VALID_20, WLAN_RC_PHY_HT_20_SS, 58500, /* 58.5 Mb */
			53500, 0x86, 0x00, 6,
			4, 23, 3, 14, 30, 14, 30,  28956 },
		{ INVALID, VALID_20, WLAN_RC_PHY_HT_20_SS, 65000, /* 65 Mb */
			59000, 0x87, 0x00, 7,
			4, 25, 3, 15, 31, 15, 32, 32180 },
		{ INVALID, INVALID, WLAN_RC_PHY_HT_20_DS, 13000, /* 13 Mb */
			12700, 0x88, 0x00,
			8, 0, 2, 3, 16, 33, 16, 33, 6430 },
		{ INVALID, INVALID, WLAN_RC_PHY_HT_20_DS, 26000, /* 26 Mb */
			24800, 0x89, 0x00, 9,
			2, 4, 3, 17, 34, 17, 34, 12860 },
		{ INVALID, INVALID, WLAN_RC_PHY_HT_20_DS, 39000, /* 39 Mb */
			36600, 0x8a, 0x00, 10,
			2, 6, 3, 18, 35, 18, 35, 19300 },
		{ VALID_20, INVALID, WLAN_RC_PHY_HT_20_DS, 52000, /* 52 Mb */
			48100, 0x8b, 0x00, 11,
			4, 10, 3, 19, 36, 19, 36, 25736 },
		{ VALID_20, INVALID, WLAN_RC_PHY_HT_20_DS, 78000, /* 78 Mb */
			69500, 0x8c, 0x00, 12,
			4, 14, 3, 20, 37, 20, 37, 38600 },
		{ VALID_20, INVALID, WLAN_RC_PHY_HT_20_DS, 104000, /* 104 Mb */
			89500, 0x8d, 0x00, 13,
			4, 20, 3, 21, 38, 21, 38, 51472 },
		{ VALID_20, INVALID, WLAN_RC_PHY_HT_20_DS, 117000, /* 117 Mb */
			98900, 0x8e, 0x00, 14,
			4, 23, 3, 22, 39, 22, 39, 57890 },
		{ VALID_20, INVALID, WLAN_RC_PHY_HT_20_DS, 130000, /* 130 Mb */
			108300, 0x8f, 0x00, 15,
			4, 25, 3, 23, 40, 23, 41, 64320 },
		{ VALID_40, VALID_40, WLAN_RC_PHY_HT_40_SS, 13500, /* 13.5 Mb */
			13200, 0x80, 0x00, 0,
			0, 2, 3, 8, 24, 24, 24, 6684 },
		{ VALID_40, VALID_40, WLAN_RC_PHY_HT_40_SS, 27500, /* 27.0 Mb */
			25900, 0x81, 0x00, 1,
			2, 4, 3, 9, 25, 25, 25, 13368 },
		{ VALID_40, VALID_40, WLAN_RC_PHY_HT_40_SS, 40500, /* 40.5 Mb */
			38600, 0x82, 0x00, 2,
			2, 6, 3, 10, 26, 26, 26, 20052 },
		{ VALID_40, VALID_40, WLAN_RC_PHY_HT_40_SS, 54000, /* 54 Mb */
			49800, 0x83, 0x00, 3,
			4, 10, 3, 11, 27, 27, 27, 26738 },
		{ VALID_40, VALID_40, WLAN_RC_PHY_HT_40_SS, 81500, /* 81 Mb */
			72200, 0x84, 0x00, 4,
			4, 14, 3, 12, 28, 28, 28, 40104 },
		{ INVALID, VALID_40, WLAN_RC_PHY_HT_40_SS, 108000, /* 108 Mb */
			92900, 0x85, 0x00, 5,
			4, 20, 3, 13, 29, 29, 29, 53476 },
		{ INVALID, VALID_40, WLAN_RC_PHY_HT_40_SS, 121500, /* 121.5Mb */
			102700, 0x86, 0x00, 6,
			4, 23, 3, 14, 30, 30, 30, 60156 },
		{ INVALID, VALID_40, WLAN_RC_PHY_HT_40_SS, 135000, /* 135 Mb */
			112000, 0x87, 0x00, 7,
			4, 25, 3, 15, 31, 32, 32, 66840 },
		{ INVALID, VALID_40, WLAN_RC_PHY_HT_40_SS_HGI,
			150000, /* 150Mb */
			122000, 0x87, 0x00, 7,
			4, 25, 3, 15, 31, 32, 32, 74200 },
		{ INVALID, INVALID, WLAN_RC_PHY_HT_40_DS, 27000, /* 27 Mb */
			25800, 0x88, 0x00, 8,
			0, 2, 3, 16, 33, 33, 33, 13360 },
		{ INVALID, INVALID, WLAN_RC_PHY_HT_40_DS, 54000, /* 54 Mb */
			49800, 0x89, 0x00, 9,
			2, 4, 3, 17, 34, 34, 34, 26720 },
		{ INVALID, INVALID, WLAN_RC_PHY_HT_40_DS, 81000, /* 81 Mb */
			71900, 0x8a, 0x00, 10,
			2, 6, 3, 18, 35, 35, 35, 40080 },
		{ VALID_40, INVALID, WLAN_RC_PHY_HT_40_DS, 108000, /* 108 Mb */
			92500, 0x8b, 0x00, 11,
			4, 10, 3, 19, 36, 36, 36, 53440 },
		{ VALID_40, INVALID, WLAN_RC_PHY_HT_40_DS, 162000, /* 162 Mb */
			130300, 0x8c, 0x00, 12,
			4, 14, 3, 20, 37, 37, 37, 80160 },
		{ VALID_40, INVALID, WLAN_RC_PHY_HT_40_DS, 216000, /* 216 Mb */
			162800, 0x8d, 0x00, 13,
			4, 20, 3, 21, 38, 38, 38, 106880 },
		{ VALID_40, INVALID, WLAN_RC_PHY_HT_40_DS, 243000, /* 243 Mb */
			178200, 0x8e, 0x00, 14,
			4, 23, 3, 22, 39, 39, 39, 120240 },
		{ VALID_40, INVALID, WLAN_RC_PHY_HT_40_DS, 270000, /* 270 Mb */
			192100, 0x8f, 0x00, 15,
			4, 25, 3, 23, 40, 41, 41, 133600 },
		{ VALID_40, INVALID, WLAN_RC_PHY_HT_40_DS_HGI,
			300000, /* 300 Mb */
			207000, 0x8f, 0x00, 15,
			4, 25, 3, 23, 40, 41, 41, 148400 },
	},
	50,  /* probe interval */
	50,  /* rssi reduce interval */
	WLAN_RC_HT_FLAG,  /* Phy rates allowed initially */
};

/*
 * 4ms frame limit not used for NG mode.  The values filled
 * for HT are the 64K max aggregate limit
 */

static struct ath_rate_table ar5416_11ng_ratetable = {
	46,
	{0},
	{
		{ VALID_ALL, VALID_ALL, WLAN_RC_PHY_CCK, 1000, /* 1 Mb */
			900, 0x1b, 0x00, 2,
			0, 0, 1, 0, 0, 0, 0, 0 },
		{ VALID_ALL, VALID_ALL, WLAN_RC_PHY_CCK, 2000, /* 2 Mb */
			1900, 0x1a, 0x04, 4,
			1, 1, 1, 1, 1, 1, 1, 0 },
		{ VALID_ALL, VALID_ALL, WLAN_RC_PHY_CCK, 5500, /* 5.5 Mb */
			4900, 0x19, 0x04, 11,
			2, 2, 2, 2, 2, 2, 2, 0 },
		{ VALID_ALL, VALID_ALL, WLAN_RC_PHY_CCK, 11000, /* 11 Mb */
			8100, 0x18, 0x04, 22,
			3, 3, 2, 3, 3, 3, 3, 0 },
		{ INVALID, INVALID, WLAN_RC_PHY_OFDM, 6000, /* 6 Mb */
			5400, 0x0b, 0x00, 12,
			4, 2, 1, 4, 4, 4, 4, 0 },
		{ INVALID, INVALID, WLAN_RC_PHY_OFDM, 9000, /* 9 Mb */
			7800, 0x0f, 0x00, 18,
			4, 3, 1, 5, 5, 5, 5, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 12000, /* 12 Mb */
			10100, 0x0a, 0x00, 24,
			6, 4, 1, 6, 6, 6, 6, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 18000, /* 18 Mb */
			14100,  0x0e, 0x00, 36,
			6, 6, 2, 7, 7, 7, 7, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 24000, /* 24 Mb */
			17700, 0x09, 0x00, 48,
			8, 10, 3, 8, 8, 8, 8, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 36000, /* 36 Mb */
			23700, 0x0d, 0x00, 72,
			8, 14, 3, 9, 9, 9, 9, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 48000, /* 48 Mb */
			27400, 0x08, 0x00, 96,
			8, 20, 3, 10, 10, 10, 10, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 54000, /* 54 Mb */
			30900, 0x0c, 0x00, 108,
			8, 23, 3, 11, 11, 11, 11, 0 },
		{ INVALID, INVALID, WLAN_RC_PHY_HT_20_SS, 6500, /* 6.5 Mb */
			6400, 0x80, 0x00, 0,
			4, 2, 3, 12, 28, 12, 28, 3216 },
		{ VALID_20, VALID_20, WLAN_RC_PHY_HT_20_SS, 13000, /* 13 Mb */
			12700, 0x81, 0x00, 1,
			6, 4, 3, 13, 29, 13, 29, 6434 },
		{ VALID_20, VALID_20, WLAN_RC_PHY_HT_20_SS, 19500, /* 19.5 Mb */
			18800, 0x82, 0x00, 2,
			6, 6, 3, 14, 30, 14, 30, 9650 },
		{ VALID_20, VALID_20, WLAN_RC_PHY_HT_20_SS, 26000, /* 26 Mb */
			25000, 0x83, 0x00, 3,
			8, 10, 3, 15, 31, 15, 31, 12868 },
		{ VALID_20, VALID_20, WLAN_RC_PHY_HT_20_SS, 39000, /* 39 Mb */
			36700, 0x84, 0x00, 4,
			8, 14, 3, 16, 32, 16, 32, 19304 },
		{ INVALID, VALID_20, WLAN_RC_PHY_HT_20_SS, 52000, /* 52 Mb */
			48100, 0x85, 0x00, 5,
			8, 20, 3, 17, 33, 17, 33, 25740 },
		{ INVALID,  VALID_20, WLAN_RC_PHY_HT_20_SS, 58500, /* 58.5 Mb */
			53500, 0x86, 0x00, 6,
			8, 23, 3, 18, 34, 18, 34, 28956 },
		{ INVALID, VALID_20, WLAN_RC_PHY_HT_20_SS, 65000, /* 65 Mb */
			59000, 0x87, 0x00, 7,
			8, 25, 3, 19, 35, 19, 36, 32180 },
		{ INVALID, INVALID, WLAN_RC_PHY_HT_20_DS, 13000, /* 13 Mb */
			12700, 0x88, 0x00, 8,
			4, 2, 3, 20, 37, 20, 37, 6430 },
		{ INVALID, INVALID, WLAN_RC_PHY_HT_20_DS, 26000, /* 26 Mb */
			24800, 0x89, 0x00, 9,
			6, 4, 3, 21, 38, 21, 38, 12860 },
		{ INVALID, INVALID, WLAN_RC_PHY_HT_20_DS, 39000, /* 39 Mb */
			36600, 0x8a, 0x00, 10,
			6, 6, 3, 22, 39, 22, 39, 19300 },
		{ VALID_20, INVALID, WLAN_RC_PHY_HT_20_DS, 52000, /* 52 Mb */
			48100, 0x8b, 0x00, 11,
			8, 10, 3, 23, 40, 23, 40, 25736 },
		{ VALID_20, INVALID, WLAN_RC_PHY_HT_20_DS, 78000, /* 78 Mb */
			69500, 0x8c, 0x00, 12,
			8, 14, 3, 24, 41, 24, 41, 38600 },
		{ VALID_20, INVALID, WLAN_RC_PHY_HT_20_DS, 104000, /* 104 Mb */
			89500, 0x8d, 0x00, 13,
			8, 20, 3, 25, 42, 25, 42, 51472 },
		{ VALID_20, INVALID, WLAN_RC_PHY_HT_20_DS, 117000, /* 117 Mb */
			98900, 0x8e, 0x00, 14,
			8, 23, 3, 26, 43, 26, 44, 57890 },
		{ VALID_20, INVALID, WLAN_RC_PHY_HT_20_DS, 130000, /* 130 Mb */
			108300, 0x8f, 0x00, 15,
			8, 25, 3, 27, 44, 27, 45, 64320 },
		{ VALID_40, VALID_40, WLAN_RC_PHY_HT_40_SS, 13500, /* 13.5 Mb */
			13200, 0x80, 0x00, 0,
			8, 2, 3, 12, 28, 28, 28, 6684 },
		{ VALID_40, VALID_40, WLAN_RC_PHY_HT_40_SS, 27500, /* 27.0 Mb */
			25900, 0x81, 0x00, 1,
			8, 4, 3, 13, 29, 29, 29, 13368 },
		{ VALID_40, VALID_40, WLAN_RC_PHY_HT_40_SS, 40500, /* 40.5 Mb */
			38600, 0x82, 0x00, 2,
			8, 6, 3, 14, 30, 30, 30, 20052 },
		{ VALID_40, VALID_40, WLAN_RC_PHY_HT_40_SS, 54000, /* 54 Mb */
			49800, 0x83, 0x00, 3,
			8, 10, 3, 15, 31, 31, 31, 26738 },
		{ VALID_40, VALID_40, WLAN_RC_PHY_HT_40_SS, 81500, /* 81 Mb */
			72200, 0x84, 0x00, 4,
			8, 14, 3, 16, 32, 32, 32, 40104 },
		{ INVALID, VALID_40, WLAN_RC_PHY_HT_40_SS, 108000, /* 108 Mb */
			92900, 0x85, 0x00, 5,
			8, 20, 3, 17, 33, 33, 33, 53476 },
		{ INVALID,  VALID_40, WLAN_RC_PHY_HT_40_SS,
			121500, /* 121.5 Mb */
			102700, 0x86, 0x00, 6,
			8, 23, 3, 18, 34, 34, 34, 60156 },
		{ INVALID, VALID_40, WLAN_RC_PHY_HT_40_SS, 135000, /* 135 Mb */
			112000, 0x87, 0x00, 7,
			8, 23, 3, 19, 35, 36, 36, 66840 },
		{ INVALID, VALID_40, WLAN_RC_PHY_HT_40_SS_HGI,
			150000, /* 150 Mb */
			122000, 0x87, 0x00, 7,
			8, 25, 3, 19, 35, 36, 36, 74200 },
		{ INVALID, INVALID, WLAN_RC_PHY_HT_40_DS, 27000, /* 27 Mb */
			25800, 0x88, 0x00, 8,
			8, 2, 3, 20, 37, 37, 37, 13360 },
		{ INVALID, INVALID, WLAN_RC_PHY_HT_40_DS, 54000, /* 54 Mb */
			49800, 0x89, 0x00, 9,
			8, 4, 3, 21, 38, 38, 38, 26720 },
		{ INVALID, INVALID, WLAN_RC_PHY_HT_40_DS, 81000, /* 81 Mb */
			71900, 0x8a, 0x00, 10,
			8, 6, 3, 22, 39, 39, 39, 40080 },
		{ VALID_40, INVALID, WLAN_RC_PHY_HT_40_DS, 108000, /* 108 Mb */
			92500, 0x8b, 0x00, 11,
			8, 10, 3, 23, 40, 40, 40, 53440 },
		{ VALID_40, INVALID, WLAN_RC_PHY_HT_40_DS, 162000, /* 162 Mb */
			130300, 0x8c, 0x00, 12,
			8, 14, 3, 24, 41, 41, 41, 80160 },
		{ VALID_40, INVALID, WLAN_RC_PHY_HT_40_DS, 216000, /* 216 Mb */
			162800, 0x8d, 0x00, 13,
			8, 20, 3, 25, 42, 42, 42, 106880 },
		{ VALID_40, INVALID, WLAN_RC_PHY_HT_40_DS, 243000, /* 243 Mb */
			178200, 0x8e, 0x00, 14,
			8, 23, 3, 26, 43, 43, 43, 120240 },
		{ VALID_40, INVALID, WLAN_RC_PHY_HT_40_DS, 270000, /* 270 Mb */
			192100, 0x8f, 0x00, 15,
			8, 23, 3, 27, 44, 45, 45, 133600 },
		{ VALID_40, INVALID, WLAN_RC_PHY_HT_40_DS_HGI,
			300000, /* 300 Mb */
			207000, 0x8f, 0x00, 15,
			8, 25, 3, 27, 44, 45, 45, 148400 },
		},
	50,  /* probe interval */
	50,  /* rssi reduce interval */
	WLAN_RC_HT_FLAG,  /* Phy rates allowed initially */
};

static struct ath_rate_table ar5416_11a_ratetable = {
	8,
	{0},
	{
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 6000, /* 6 Mb */
			5400, 0x0b, 0x00, (0x80|12),
			0, 2, 1, 0, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 9000, /* 9 Mb */
			7800, 0x0f, 0x00, 18,
			0, 3, 1, 1, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 12000, /* 12 Mb */
			10000, 0x0a, 0x00, (0x80|24),
			2, 4, 2, 2, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 18000, /* 18 Mb */
			13900, 0x0e, 0x00, 36,
			2, 6, 2, 3, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 24000, /* 24 Mb */
			17300, 0x09, 0x00, (0x80|48),
			4, 10, 3, 4, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 36000, /* 36 Mb */
			23000, 0x0d, 0x00, 72,
			4, 14, 3, 5, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 48000, /* 48 Mb */
			27400, 0x08, 0x00, 96,
			4, 19, 3, 6, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 54000, /* 54 Mb */
			29300, 0x0c, 0x00, 108,
			4, 23, 3, 7, 0 },
	},
	50,  /* probe interval */
	50,  /* rssi reduce interval */
	0,   /* Phy rates allowed initially */
};

static struct ath_rate_table ar5416_11g_ratetable = {
	12,
	{0},
	{
		{ VALID, VALID, WLAN_RC_PHY_CCK, 1000, /* 1 Mb */
			900, 0x1b, 0x00, 2,
			0, 0, 1, 0, 0 },
		{ VALID, VALID, WLAN_RC_PHY_CCK, 2000, /* 2 Mb */
			1900, 0x1a, 0x04, 4,
			1, 1, 1, 1, 0 },
		{ VALID, VALID, WLAN_RC_PHY_CCK, 5500, /* 5.5 Mb */
			4900, 0x19, 0x04, 11,
			2, 2, 2, 2, 0 },
		{ VALID, VALID, WLAN_RC_PHY_CCK, 11000, /* 11 Mb */
			8100, 0x18, 0x04, 22,
			3, 3, 2, 3, 0 },
		{ INVALID, INVALID, WLAN_RC_PHY_OFDM, 6000, /* 6 Mb */
			5400, 0x0b, 0x00, 12,
			4, 2, 1, 4, 0 },
		{ INVALID, INVALID, WLAN_RC_PHY_OFDM, 9000, /* 9 Mb */
			7800, 0x0f, 0x00, 18,
			4, 3, 1, 5, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 12000, /* 12 Mb */
			10000, 0x0a, 0x00, 24,
			6, 4, 1, 6, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 18000, /* 18 Mb */
			13900, 0x0e, 0x00, 36,
			6, 6, 2, 7, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 24000, /* 24 Mb */
			17300, 0x09, 0x00, 48,
			8, 10, 3, 8, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 36000, /* 36 Mb */
			23000, 0x0d, 0x00, 72,
			8, 14, 3, 9, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 48000, /* 48 Mb */
			27400, 0x08, 0x00, 96,
			8, 19, 3, 10, 0 },
		{ VALID, VALID, WLAN_RC_PHY_OFDM, 54000, /* 54 Mb */
			29300, 0x0c, 0x00, 108,
			8, 23, 3, 11, 0 },
	},
	50,  /* probe interval */
	50,  /* rssi reduce interval */
	0,   /* Phy rates allowed initially */
};

static struct ath_rate_table ar5416_11b_ratetable = {
	4,
	{0},
	{
		{ VALID, VALID, WLAN_RC_PHY_CCK, 1000, /* 1 Mb */
			900, 0x1b,  0x00, (0x80|2),
			0, 0, 1, 0, 0 },
		{ VALID, VALID, WLAN_RC_PHY_CCK, 2000, /* 2 Mb */
			1800, 0x1a, 0x04, (0x80|4),
			1, 1, 1, 1, 0 },
		{ VALID, VALID, WLAN_RC_PHY_CCK, 5500, /* 5.5 Mb */
			4300, 0x19, 0x04, (0x80|11),
			1, 2, 2, 2, 0 },
		{ VALID, VALID, WLAN_RC_PHY_CCK, 11000, /* 11 Mb */
			7100, 0x18, 0x04, (0x80|22),
			1, 4, 100, 3, 0 },
	},
	100, /* probe interval */
	100, /* rssi reduce interval */
	0,   /* Phy rates allowed initially */
};

static void
arn_setup_rate_table(struct arn_softc *sc,
    struct ath_rate_table *rate_table)
{
	int i;

	for (i = 0; i < 256; i++)
		rate_table->rateCodeToIndex[i] = (uint8_t)-1;

	for (i = 0; i < rate_table->rate_cnt; i++) {
		uint8_t code = rate_table->info[i].ratecode;
		uint8_t cix = rate_table->info[i].ctrl_rate;
		uint8_t sh = rate_table->info[i].short_preamble;

		rate_table->rateCodeToIndex[code] = (int)i;
		rate_table->rateCodeToIndex[code | sh] = (int)i;

		rate_table->info[i].lpAckDuration =
		    ath9k_hw_computetxtime(sc->sc_ah, rate_table,
		    WLAN_CTRL_FRAME_SIZE,
		    cix,
		    B_FALSE);
		rate_table->info[i].spAckDuration =
		    ath9k_hw_computetxtime(sc->sc_ah, rate_table,
		    WLAN_CTRL_FRAME_SIZE,
		    cix,
		    B_TRUE);
	}
}

void
arn_rate_attach(struct arn_softc *sc)
{
	sc->hw_rate_table[ATH9K_MODE_11B] =
	    &ar5416_11b_ratetable;
	sc->hw_rate_table[ATH9K_MODE_11A] =
	    &ar5416_11a_ratetable;
	sc->hw_rate_table[ATH9K_MODE_11G] =
	    &ar5416_11g_ratetable;
	sc->hw_rate_table[ATH9K_MODE_11NA_HT20] =
	    &ar5416_11na_ratetable;
	sc->hw_rate_table[ATH9K_MODE_11NG_HT20] =
	    &ar5416_11ng_ratetable;
	sc->hw_rate_table[ATH9K_MODE_11NA_HT40PLUS] =
	    &ar5416_11na_ratetable;
	sc->hw_rate_table[ATH9K_MODE_11NA_HT40MINUS] =
	    &ar5416_11na_ratetable;
	sc->hw_rate_table[ATH9K_MODE_11NG_HT40PLUS] =
	    &ar5416_11ng_ratetable;
	sc->hw_rate_table[ATH9K_MODE_11NG_HT40MINUS] =
	    &ar5416_11ng_ratetable;

	arn_setup_rate_table(sc, &ar5416_11b_ratetable);
	arn_setup_rate_table(sc, &ar5416_11a_ratetable);
	arn_setup_rate_table(sc, &ar5416_11g_ratetable);
	arn_setup_rate_table(sc, &ar5416_11na_ratetable);
	arn_setup_rate_table(sc, &ar5416_11ng_ratetable);
}

void
arn_rate_update(struct arn_softc *sc, struct ieee80211_node *in, int32_t rate)
{
	struct ath_node *an = ATH_NODE(in);
	const struct ath_rate_table *rt = sc->sc_currates;
	uint8_t rix;

	ASSERT(rt != NULL);

	in->in_txrate = rate;

	/* management/control frames always go at the lowest speed */
	an->an_tx_mgtrate = rt->info[0].ratecode;
	an->an_tx_mgtratesp = an->an_tx_mgtrate | rt->info[0].short_preamble;

	ARN_DBG((ARN_DBG_RATE, "arn: arn_rate_update(): "
	    "mgtrate=%d mgtratesp=%d\n",
	    an->an_tx_mgtrate, an->an_tx_mgtratesp));

	/*
	 * Before associating a node has no rate set setup
	 * so we can't calculate any transmit codes to use.
	 * This is ok since we should never be sending anything
	 * but management frames and those always go at the
	 * lowest hardware rate.
	 */
	if (in->in_rates.ir_nrates == 0)
		goto done;
	an->an_tx_rix0 = sc->asc_rixmap[
	    in->in_rates.ir_rates[rate] & IEEE80211_RATE_VAL];
	an->an_tx_rate0 = rt->info[an->an_tx_rix0].ratecode;
	an->an_tx_rate0sp = an->an_tx_rate0 |
	    rt->info[an->an_tx_rix0].short_preamble;
	if (sc->sc_mrretry) {
		/*
		 * Hardware supports multi-rate retry; setup two
		 * step-down retry rates and make the lowest rate
		 * be the ``last chance''.  We use 4, 2, 2, 2 tries
		 * respectively (4 is set here, the rest are fixed
		 * in the xmit routine).
		 */
		an->an_tx_try0 = 1 + 3;		/* 4 tries at rate 0 */
		if (--rate >= 0) {
			rix = sc->asc_rixmap[
			    in->in_rates.ir_rates[rate]&IEEE80211_RATE_VAL];
			an->an_tx_rate1 = rt->info[rix].ratecode;
			an->an_tx_rate1sp = an->an_tx_rate1 |
			    rt->info[rix].short_preamble;
		} else {
			an->an_tx_rate1 = an->an_tx_rate1sp = 0;
		}
		if (--rate >= 0) {
			rix = sc->asc_rixmap[
			    in->in_rates.ir_rates[rate]&IEEE80211_RATE_VAL];
			an->an_tx_rate2 = rt->info[rix].ratecode;
			an->an_tx_rate2sp = an->an_tx_rate2 |
			    rt->info[rix].short_preamble;
		} else {
			an->an_tx_rate2 = an->an_tx_rate2sp = 0;
		}
		if (rate > 0) {
			an->an_tx_rate3 = rt->info[0].ratecode;
			an->an_tx_rate3sp =
			    an->an_tx_mgtrate | rt->info[0].short_preamble;
		} else {
			an->an_tx_rate3 = an->an_tx_rate3sp = 0;
		}
	} else {
		an->an_tx_try0 = ATH_TXMAXTRY;  /* max tries at rate 0 */
		an->an_tx_rate1 = an->an_tx_rate1sp = 0;
		an->an_tx_rate2 = an->an_tx_rate2sp = 0;
		an->an_tx_rate3 = an->an_tx_rate3sp = 0;
	}
done:
	an->an_tx_ok = an->an_tx_err = an->an_tx_retr = an->an_tx_upper = 0;
}

/*
 * Set the starting transmit rate for a node.
 */
void
arn_rate_ctl_start(struct arn_softc *sc, struct ieee80211_node *in)
{
	ieee80211com_t *ic = (ieee80211com_t *)sc;
	int32_t srate;

	if (ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) {
		/*
		 * No fixed rate is requested. For 11b start with
		 * the highest negotiated rate; otherwise, for 11g
		 * and 11a, we start "in the middle" at 24Mb or 36Mb.
		 */
		srate = in->in_rates.ir_nrates - 1;
		if (sc->sc_curmode != IEEE80211_MODE_11B) {
			/*
			 * Scan the negotiated rate set to find the
			 * closest rate.
			 */
			/* NB: the rate set is assumed sorted */
			for (; srate >= 0 && IEEE80211_RATE(srate) > 72;
			    srate--) {}
		}
	} else {
		/*
		 * A fixed rate is to be used; We know the rate is
		 * there because the rate set is checked when the
		 * station associates.
		 */
		/* NB: the rate set is assumed sorted */
		srate = in->in_rates.ir_nrates - 1;
		for (; srate >= 0 && IEEE80211_RATE(srate) != ic->ic_fixed_rate;
		    srate--) {}
	}

	ARN_DBG((ARN_DBG_RATE, "arn: arn_rate_ctl_start(): "
	    "srate=%d rate=%d\n", srate, IEEE80211_RATE(srate)));

	arn_rate_update(sc, in, srate);
}

void
arn_rate_cb(void *arg, struct ieee80211_node *in)
{
	arn_rate_update((struct arn_softc *)arg, in, 0);
}

/*
 * Reset the rate control state for each 802.11 state transition.
 */
void
arn_rate_ctl_reset(struct arn_softc *sc, enum ieee80211_state state)
{
	ieee80211com_t *ic = (ieee80211com_t *)sc;
	struct ieee80211_node *in;

	if (ic->ic_opmode == IEEE80211_M_STA) {
		/*
		 * Reset local xmit state; this is really only
		 * meaningful when operating in station mode.
		 */
		in = (struct ieee80211_node *)ic->ic_bss;
		if (state == IEEE80211_S_RUN) {
			arn_rate_ctl_start(sc, in);
		} else {
			arn_rate_update(sc, in, 0);
		}
	} else {
		/*
		 * When operating as a station the node table holds
		 * the AP's that were discovered during scanning.
		 * For any other operating mode we want to reset the
		 * tx rate state of each node.
		 */
		ieee80211_iterate_nodes(&ic->ic_sta, arn_rate_cb, sc);
		arn_rate_update(sc, ic->ic_bss, 0);
	}
}

/*
 * Examine and potentially adjust the transmit rate.
 */
void
arn_rate_ctl(void *arg, struct ieee80211_node *in)
{
	struct arn_softc *sc = arg;
	struct ath_node *an = ATH_NODE(in);
	struct ieee80211_rateset *rs = &in->in_rates;
	int32_t mod = 0, nrate, enough;

	/*
	 * Rate control(very primitive version).
	 */
	sc->sc_stats.ast_rate_calls++;

	enough = (an->an_tx_ok + an->an_tx_err >= 10);

	/* no packet reached -> down */
	if (an->an_tx_err > 0 && an->an_tx_ok == 0)
		mod = -1;

	/* all packets needs retry in average -> down */
	if (enough && an->an_tx_ok < an->an_tx_retr)
		mod = -1;

	/* no error and less than 10% of packets needs retry -> up */
	if (enough && an->an_tx_err == 0 && an->an_tx_ok > an->an_tx_retr * 10)
		mod = 1;

	nrate = in->in_txrate;
	switch (mod) {
	case 0:
		if (enough && an->an_tx_upper > 0)
			an->an_tx_upper--;
		break;
	case -1:
		if (nrate > 0) {
			nrate--;
			sc->sc_stats.ast_rate_drop++;
		}
		an->an_tx_upper = 0;
		break;
	case 1:
		if (++an->an_tx_upper < 10)
			break;
		an->an_tx_upper = 0;
		if (nrate + 1 < rs->ir_nrates) {
			nrate++;
			sc->sc_stats.ast_rate_raise++;
		}
		break;
	}

	if (nrate != in->in_txrate) {
		ARN_DBG((ARN_DBG_RATE, "arn: arn_rate_ctl(): %dM -> %dM "
		    "(%d ok, %d err, %d retr)\n",
		    (rs->ir_rates[in->in_txrate] & IEEE80211_RATE_VAL) / 2,
		    (rs->ir_rates[nrate] & IEEE80211_RATE_VAL) / 2,
		    an->an_tx_ok, an->an_tx_err, an->an_tx_retr));
		arn_rate_update(sc, in, nrate);
	} else if (enough)
		an->an_tx_ok = an->an_tx_err = an->an_tx_retr = 0;
}
