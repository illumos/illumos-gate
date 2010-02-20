/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/net80211_ht.h>

#include "arn_core.h"
#include "arn_hw.h"
#include "arn_reg.h"

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

static inline int8_t
median(int8_t a, int8_t b, int8_t c)
{
	if (a >= b) {
		if (b >= c)
			return (b);
		else if (a > c)
			return (c);
		else
			return (a);
	} else {
		if (a >= c)
			return (a);
		else if (b >= c)
			return (c);
		else
			return (b);
	}
}

static void
arn_rc_sort_validrates(struct ath_rate_table *rate_table,
    struct ath_rate_priv *ath_rc_priv)
{
	uint8_t i, j, idx, idx_next;

	for (i = ath_rc_priv->max_valid_rate - 1; i > 0; i--) {
		for (j = 0; j <= i-1; j++) {
			idx = ath_rc_priv->valid_rate_index[j];
			idx_next = ath_rc_priv->valid_rate_index[j+1];

			if (rate_table->info[idx].ratekbps >
			    rate_table->info[idx_next].ratekbps) {
				ath_rc_priv->valid_rate_index[j] = idx_next;
				ath_rc_priv->valid_rate_index[j+1] = idx;
			}
		}
	}
}

static void
arn_rc_init_valid_txmask(struct ath_rate_priv *ath_rc_priv)
{
	uint8_t i;

	for (i = 0; i < ath_rc_priv->rate_table_size; i++)
		ath_rc_priv->valid_rate_index[i] = 0;
}

static inline void
arn_rc_set_valid_txmask(struct ath_rate_priv *ath_rc_priv,
    uint8_t index, int valid_tx_rate)
{
	ASSERT(index <= ath_rc_priv->rate_table_size);
	ath_rc_priv->valid_rate_index[index] = valid_tx_rate ? 1 : 0;
}

static inline int
/* LINTED E_STATIC_UNUSED */
arn_rc_isvalid_txmask(struct ath_rate_priv *ath_rc_priv, uint8_t index)
{
	ASSERT(index <= ath_rc_priv->rate_table_size);
	return (ath_rc_priv->valid_rate_index[index]);
}

/* ARGSUSED */
static inline int
arn_rc_get_nextvalid_txrate(struct ath_rate_table *rate_table,
    struct ath_rate_priv *ath_rc_priv,
    uint8_t cur_valid_txrate,
    uint8_t *next_idx)
{
	uint8_t i;

	for (i = 0; i < ath_rc_priv->max_valid_rate - 1; i++) {
		if (ath_rc_priv->valid_rate_index[i] == cur_valid_txrate) {
			*next_idx = ath_rc_priv->valid_rate_index[i+1];
			return (1);
		}
	}

	/* No more valid rates */
	*next_idx = 0;

	return (0);
}

/* Return true only for single stream */
static int
arn_rc_valid_phyrate(uint32_t phy, uint32_t capflag, int ignore_cw)
{
	if (WLAN_RC_PHY_HT(phy) && !(capflag & WLAN_RC_HT_FLAG))
		return (0);
	if (WLAN_RC_PHY_DS(phy) && !(capflag & WLAN_RC_DS_FLAG))
		return (0);
	if (WLAN_RC_PHY_SGI(phy) && !(capflag & WLAN_RC_SGI_FLAG))
		return (0);
	if (!ignore_cw && WLAN_RC_PHY_HT(phy))
		if (WLAN_RC_PHY_40(phy) && !(capflag & WLAN_RC_40_FLAG))
			return (0);
		if (!WLAN_RC_PHY_40(phy) && (capflag & WLAN_RC_40_FLAG))
			return (0);

	return (1);
}

/* ARGSUSED */
static inline int
arn_rc_get_nextlowervalid_txrate(struct ath_rate_table *rate_table,
    struct ath_rate_priv *ath_rc_priv,
    uint8_t cur_valid_txrate, uint8_t *next_idx)
{
	int8_t i;

	for (i = 1; i < ath_rc_priv->max_valid_rate; i++) {
		if (ath_rc_priv->valid_rate_index[i] == cur_valid_txrate) {
			*next_idx = ath_rc_priv->valid_rate_index[i-1];
			return (1);
		}
	}

	return (0);
}

static uint8_t
arn_rc_init_validrates(struct ath_rate_priv *ath_rc_priv,
    struct ath_rate_table *rate_table, uint32_t capflag)
{
	uint8_t i, hi = 0;
	uint32_t valid;

	for (i = 0; i < rate_table->rate_cnt; i++) {
		valid = (ath_rc_priv->single_stream ?
		    rate_table->info[i].valid_single_stream :
		    rate_table->info[i].valid);
		if (valid == 1) {
			uint32_t phy = rate_table->info[i].phy;
			uint8_t valid_rate_count = 0;

			if (!arn_rc_valid_phyrate(phy, capflag, 0))
				continue;

			valid_rate_count = ath_rc_priv->valid_phy_ratecnt[phy];

			ath_rc_priv->
			    valid_phy_rateidx[phy][valid_rate_count] = i;
			ath_rc_priv->valid_phy_ratecnt[phy] += 1;
			arn_rc_set_valid_txmask(ath_rc_priv, i, 1);
			hi = A_MAX(hi, i);
		}
	}

	return (hi);
}

static uint8_t
arn_rc_setvalid_rates(struct ath_rate_priv *ath_rc_priv,
    struct ath_rate_table *rate_table,
    struct ath_rateset *rateset,
    uint32_t capflag)
{
	uint8_t i, j, hi = 0;

	/* Use intersection of working rates and valid rates */
	for (i = 0; i < rateset->rs_nrates; i++) {
		for (j = 0; j < rate_table->rate_cnt; j++) {
			uint32_t phy = rate_table->info[j].phy;
			uint32_t valid = (ath_rc_priv->single_stream ?
			    rate_table->info[j].valid_single_stream :
			    rate_table->info[j].valid);
			uint8_t rate = rateset->rs_rates[i];
			uint8_t dot11rate = rate_table->info[j].dot11rate;

			/*
			 * We allow a rate only if its valid and the
			 * capflag matches one of the validity
			 * (VALID/VALID_20/VALID_40) flags
			 */
			if (((rate & 0x7F) == (dot11rate & 0x7F)) &&
			    ((valid & WLAN_RC_CAP_MODE(capflag)) ==
			    WLAN_RC_CAP_MODE(capflag)) &&
			    !WLAN_RC_PHY_HT(phy)) {
				uint8_t valid_rate_count = 0;

				if (!arn_rc_valid_phyrate(phy, capflag, 0))
					continue;

				valid_rate_count =
				    ath_rc_priv->valid_phy_ratecnt[phy];

				ath_rc_priv->valid_phy_rateidx[phy]
				    [valid_rate_count] = j;
				ath_rc_priv->valid_phy_ratecnt[phy] += 1;
				arn_rc_set_valid_txmask(ath_rc_priv, j, 1);
				hi = A_MAX(hi, j);
			}
		}
	}

	return (hi);
}

static uint8_t
arn_rc_setvalid_htrates(struct ath_rate_priv *ath_rc_priv,
    struct ath_rate_table *rate_table,
    uint8_t *mcs_set, uint32_t capflag)
{
	struct ath_rateset *rateset = (struct ath_rateset *)mcs_set;

	uint8_t i, j, hi = 0;

	/* Use intersection of working rates and valid rates */
	for (i = 0; i < rateset->rs_nrates; i++) {
		for (j = 0; j < rate_table->rate_cnt; j++) {
			uint32_t phy = rate_table->info[j].phy;
			uint32_t valid = (ath_rc_priv->single_stream ?
			    rate_table->info[j].valid_single_stream :
			    rate_table->info[j].valid);
			uint8_t rate = rateset->rs_rates[i];
			uint8_t dot11rate = rate_table->info[j].dot11rate;

			if (((rate & 0x7F) != (dot11rate & 0x7F)) ||
			    !WLAN_RC_PHY_HT(phy) ||
			    !WLAN_RC_PHY_HT_VALID(valid, capflag))
				continue;

			if (!arn_rc_valid_phyrate(phy, capflag, 0))
				continue;

			ath_rc_priv->valid_phy_rateidx[phy]
			    [ath_rc_priv->valid_phy_ratecnt[phy]] = j;
			ath_rc_priv->valid_phy_ratecnt[phy] += 1;
			arn_rc_set_valid_txmask(ath_rc_priv, j, 1);
			hi = A_MAX(hi, j);
		}
	}

	return (hi);
}

/* ARGSUSED */
static uint8_t
arn_rc_ratefind_ht(struct arn_softc *sc,
    struct ath_rate_priv *ath_rc_priv,
    struct ath_rate_table *rate_table,
    int probe_allowed, int *is_probing,
    int is_retry)
{
	uint32_t dt, best_thruput, this_thruput, now_msec;
	uint8_t rate, next_rate, best_rate, maxindex, minindex;
	int8_t  rssi_last, rssi_reduce = 0, index = 0;

	*is_probing = 0;

	rssi_last = median(ath_rc_priv->rssi_last,
	    ath_rc_priv->rssi_last_prev,
	    ath_rc_priv->rssi_last_prev2);

	/*
	 * Age (reduce) last ack rssi based on how old it is.
	 * The bizarre numbers are so the delta is 160msec,
	 * meaning we divide by 16.
	 * 0msec   <= dt <= 25msec: don't derate
	 * 25msec  <= dt <= 185msec: derate linearly from 0 to 10dB
	 * 185msec <= dt: derate by 10dB
	 */

	/* now_msec = jiffies_to_msecs(jiffies); */
	now_msec = drv_hztousec(ddi_get_lbolt())/1000; /* mescs ? */
	dt = now_msec - ath_rc_priv->rssi_time;

	if (dt >= 185)
		rssi_reduce = 10;
	else if (dt >= 25)
		rssi_reduce = (uint8_t)((dt - 25) >> 4);

	/* Now reduce rssi_last by rssi_reduce */
	if (rssi_last < rssi_reduce)
		rssi_last = 0;
	else
		rssi_last -= rssi_reduce;

	/*
	 * Now look up the rate in the rssi table and return it.
	 * If no rates match then we return 0 (lowest rate)
	 */

	best_thruput = 0;
	maxindex = ath_rc_priv->max_valid_rate-1;

	minindex = 0;
	best_rate = minindex;

	/*
	 * Try the higher rate first. It will reduce memory moving time
	 * if we have very good channel characteristics.
	 */
	for (index = maxindex; index >= minindex; index--) {
		uint8_t per_thres;

		rate = ath_rc_priv->valid_rate_index[index];
		if (rate > ath_rc_priv->rate_max_phy)
			continue;

		/*
		 * For TCP the average collision rate is around 11%,
		 * so we ignore PERs less than this.  This is to
		 * prevent the rate we are currently using (whose
		 * PER might be in the 10-15 range because of TCP
		 * collisions) looking worse than the next lower
		 * rate whose PER has decayed close to 0.  If we
		 * used to next lower rate, its PER would grow to
		 * 10-15 and we would be worse off then staying
		 * at the current rate.
		 */
		per_thres = ath_rc_priv->state[rate].per;
		if (per_thres < 12)
			per_thres = 12;

		this_thruput = rate_table->info[rate].user_ratekbps *
		    (100 - per_thres);

		if (best_thruput <= this_thruput) {
			best_thruput = this_thruput;
			best_rate    = rate;
		}
	}

	rate = best_rate;

	/*
	 * if we are retrying for more than half the number
	 * of max retries, use the min rate for the next retry
	 */
	if (is_retry)
		rate = ath_rc_priv->valid_rate_index[minindex];

	ath_rc_priv->rssi_last_lookup = rssi_last;

	/*
	 * Must check the actual rate (ratekbps) to account for
	 * non-monoticity of 11g's rate table
	 */

	if (rate >= ath_rc_priv->rate_max_phy && probe_allowed) {
		rate = ath_rc_priv->rate_max_phy;

		/* Probe the next allowed phy state */
		/* FIXME:XXXX Check to make sure ratMax is checked properly */
		if (arn_rc_get_nextvalid_txrate(rate_table,
		    ath_rc_priv, rate, &next_rate) &&
		    (now_msec - ath_rc_priv->probe_time >
		    rate_table->probe_interval) &&
		    (ath_rc_priv->hw_maxretry_pktcnt >= 1)) {
			rate = next_rate;
			ath_rc_priv->probe_rate = rate;
			ath_rc_priv->probe_time = now_msec;
			ath_rc_priv->hw_maxretry_pktcnt = 0;
			*is_probing = 1;
		}
	}

	if (rate > (ath_rc_priv->rate_table_size - 1))
		rate = ath_rc_priv->rate_table_size - 1;

	ASSERT((rate_table->info[rate].valid && !ath_rc_priv->single_stream) ||
	    (rate_table->info[rate].valid_single_stream &&
	    ath_rc_priv->single_stream));

	return (rate);
}

static void
arn_rc_rate_set_series(struct ath_rate_table *rate_table,
    struct ath9k_tx_rate *rate,
    uint8_t tries,
    uint8_t rix,
    int rtsctsenable)
{
#if 0
	struct ieee80211_node *in;
	ieee80211com_t *ic = (ieee80211com_t *)sc;
#endif
	rate->count = tries;
	rate->idx = rix;

	if (rtsctsenable)
		rate->flags |= ATH9K_TX_RC_USE_RTS_CTS;
#if 0
	if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
	    (in->in_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE)) {
		rate->flags |= ATH9K_TX_RC_USE_SHORT_PREAMBLE;
	}
#endif
	if (WLAN_RC_PHY_40(rate_table->info[rix].phy))
		rate->flags |= ATH9K_TX_RC_40_MHZ_WIDTH;
	if (WLAN_RC_PHY_SGI(rate_table->info[rix].phy))
		rate->flags |= ATH9K_TX_RC_SHORT_GI;
	if (WLAN_RC_PHY_HT(rate_table->info[rix].phy))
		rate->flags |= ATH9K_TX_RC_MCS;
}

/* ARGSUSED */
static uint8_t
arn_rc_rate_getidx(struct arn_softc *sc,
    struct ath_rate_priv *ath_rc_priv,
    struct ath_rate_table *rate_table,
    uint8_t rix, uint16_t stepdown,
    uint16_t min_rate)
{
	uint32_t j;
	uint8_t nextindex;

	if (min_rate) {
		for (j = RATE_TABLE_SIZE; j > 0; j--) {
			if (arn_rc_get_nextlowervalid_txrate(rate_table,
			    ath_rc_priv, rix, &nextindex))
				rix = nextindex;
			else
				break;
		}
	} else {
		for (j = stepdown; j > 0; j--) {
			if (arn_rc_get_nextlowervalid_txrate(rate_table,
			    ath_rc_priv, rix, &nextindex))
				rix = nextindex;
			else
				break;
		}
	}
	return (rix);
}

static void
arn_rc_ratefind(struct arn_softc *sc, struct ath_rate_priv *ath_rc_priv,
    struct ath_buf *bf, int num_tries, int num_rates, int *is_probe,
    boolean_t is_retry)
{
	uint8_t try_per_rate = 0, i = 0, rix, nrix;
	struct ath_rate_table *rate_table;
	struct ath9k_tx_rate *rates = bf->rates;
	ieee80211com_t *ic = (ieee80211com_t *)sc;

	rate_table = sc->sc_currates;
	rix = arn_rc_ratefind_ht(sc, ath_rc_priv, rate_table, 1,
	    is_probe, is_retry);
	nrix = rix;

	if (*is_probe) {
		/*
		 * set one try for probe rates. For the
		 * probes don't enable rts
		 */
		arn_rc_rate_set_series(rate_table,
		    &rates[i++], 1, nrix, 0);

		try_per_rate = (num_tries/num_rates);
		/*
		 * Get the next tried/allowed rate. No RTS for the next series
		 * after the probe rate
		 */
		nrix = arn_rc_rate_getidx(sc,
		    ath_rc_priv, rate_table, nrix, 1, 0);
		arn_rc_rate_set_series(rate_table,
		    &rates[i++], try_per_rate, nrix, 0);
	} else {
		try_per_rate = (num_tries/num_rates);
		/* Set the choosen rate. No RTS for first series entry. */
		arn_rc_rate_set_series(rate_table,
		    &rates[i++], try_per_rate, nrix, 0);
	}

	/* Fill in the other rates for multirate retry */
	for (; i < num_rates; i++) {
		uint8_t try_num;
		uint8_t min_rate;

		try_num = ((i + 1) == num_rates) ?
		    num_tries - (try_per_rate * i) : try_per_rate;
		/* LINTED E_FALSE_LOGICAL_EXPR */
		min_rate = (((i + 1) == num_rates) && 0);

		nrix = arn_rc_rate_getidx(sc, ath_rc_priv,
		    rate_table, nrix, 1, min_rate);
		/* All other rates in the series have RTS enabled */
		arn_rc_rate_set_series(rate_table, &rates[i], try_num, nrix, 1);
	}

	/*
	 * NB:Change rate series to enable aggregation when operating
	 * at lower MCS rates. When first rate in series is MCS2
	 * in HT40 @ 2.4GHz, series should look like:
	 *
	 * {MCS2, MCS1, MCS0, MCS0}.
	 *
	 * When first rate in series is MCS3 in HT20 @ 2.4GHz, series should
	 * look like:
	 *
	 * {MCS3, MCS2, MCS1, MCS1}
	 *
	 * So, set fourth rate in series to be same as third one for
	 * above conditions.
	 */

	if (IEEE80211_IS_CHAN_HTG(ic->ic_curchan)) {
		uint8_t dot11rate = rate_table->info[rix].dot11rate;
		uint8_t phy = rate_table->info[rix].phy;
		if (i == 4 &&
		    ((dot11rate == 2 && phy == WLAN_RC_PHY_HT_40_SS) ||
		    (dot11rate == 3 && phy == WLAN_RC_PHY_HT_20_SS))) {
			rates[3].idx = rates[2].idx;
			rates[3].flags = rates[2].flags;
		}
	}
}

/* ARGSUSED */
static boolean_t
arn_rc_update_per(struct arn_softc *sc,
    struct ath_rate_table *rate_table,
    struct ath_rate_priv *ath_rc_priv,
    struct ath_tx_info_priv *tx_info_priv,
    int tx_rate, int xretries, int retries,
	uint32_t now_msec)
{
	boolean_t state_change = B_FALSE;
	int count;
	uint8_t last_per;
	static uint32_t nretry_to_per_lookup[10] = {
		100 * 0 / 1,
		100 * 1 / 4,
		100 * 1 / 2,
		100 * 3 / 4,
		100 * 4 / 5,
		100 * 5 / 6,
		100 * 6 / 7,
		100 * 7 / 8,
		100 * 8 / 9,
		100 * 9 / 10
	};

	last_per = ath_rc_priv->state[tx_rate].per;

	if (xretries) {
		if (xretries == 1) {
			ath_rc_priv->state[tx_rate].per += 30;
			if (ath_rc_priv->state[tx_rate].per > 100)
				ath_rc_priv->state[tx_rate].per = 100;
		} else {
			/* xretries == 2 */
			count = ARRAY_SIZE(nretry_to_per_lookup);
			if (retries >= count)
				retries = count - 1;

			/* new_PER = 7/8*old_PER + 1/8*(currentPER) */
			ath_rc_priv->state[tx_rate].per =
			    (uint8_t)(last_per - (last_per >> 3) + (100 >> 3));
		}

		/* xretries == 1 or 2 */

		if (ath_rc_priv->probe_rate == tx_rate)
			ath_rc_priv->probe_rate = 0;

	} else { /* xretries == 0 */
		count = ARRAY_SIZE(nretry_to_per_lookup);
		if (retries >= count)
			retries = count - 1;

		if (tx_info_priv->n_bad_frames) {
			/*
			 * new_PER = 7/8*old_PER + 1/8*(currentPER)
			 * Assuming that n_frames is not 0.  The current PER
			 * from the retries is 100 * retries / (retries+1),
			 * since the first retries attempts failed, and the
			 * next one worked.  For the one that worked,
			 * n_bad_frames subframes out of n_frames wored,
			 * so the PER for that part is
			 * 100 * n_bad_frames / n_frames, and it contributes
			 * 100 * n_bad_frames / (n_frames * (retries+1)) to
			 * the above PER.  The expression below is a
			 * simplified version of the sum of these two terms.
			 */
			if (tx_info_priv->n_frames > 0) {
				int n_frames, n_bad_frames;
				uint8_t cur_per, new_per;

				n_bad_frames = retries *
				    tx_info_priv->n_frames +
				    tx_info_priv->n_bad_frames;
				n_frames =
				    tx_info_priv->n_frames * (retries + 1);
				cur_per =
				    (100 * n_bad_frames / n_frames) >> 3;
				new_per = (uint8_t)
				    (last_per - (last_per >> 3) + cur_per);
				ath_rc_priv->state[tx_rate].per = new_per;
			}
		} else {
			ath_rc_priv->state[tx_rate].per =
			    (uint8_t)(last_per - (last_per >> 3) +
			    (nretry_to_per_lookup[retries] >> 3));
		}

		ath_rc_priv->rssi_last_prev2 = ath_rc_priv->rssi_last_prev;
		ath_rc_priv->rssi_last_prev  = ath_rc_priv->rssi_last;
		ath_rc_priv->rssi_last = tx_info_priv->tx.ts_rssi;
		ath_rc_priv->rssi_time = now_msec;

		/*
		 * If we got at most one retry then increase the max rate if
		 * this was a probe.  Otherwise, ignore the probe.
		 */
		if (ath_rc_priv->probe_rate &&
		    ath_rc_priv->probe_rate == tx_rate) {
			if (retries > 0 || 2 * tx_info_priv->n_bad_frames >
			    tx_info_priv->n_frames) {
				/*
				 * Since we probed with just a single attempt,
				 * any retries means the probe failed.  Also,
				 * if the attempt worked, but more than half
				 * the subframes were bad then also consider
				 * the probe a failure.
				 */
				ath_rc_priv->probe_rate = 0;
			} else {
				uint8_t probe_rate = 0;

				ath_rc_priv->rate_max_phy =
				    ath_rc_priv->probe_rate;
				probe_rate = ath_rc_priv->probe_rate;

				if (ath_rc_priv->state[probe_rate].per > 30)
					ath_rc_priv->state[probe_rate].per = 20;

				ath_rc_priv->probe_rate = 0;

				/*
				 * Since this probe succeeded, we allow the next
				 * probe twice as soon.  This allows the maxRate
				 * to move up faster if the probes are
				 * succesful.
				 */
				ath_rc_priv->probe_time =
				    now_msec - rate_table->probe_interval / 2;
			}
		}

		if (retries > 0) {
			/*
			 * Don't update anything.  We don't know if
			 * this was because of collisions or poor signal.
			 *
			 * Later: if rssi_ack is close to
			 * ath_rc_priv->state[txRate].rssi_thres and we see lots
			 * of retries, then we could increase
			 * ath_rc_priv->state[txRate].rssi_thres.
			 */
			ath_rc_priv->hw_maxretry_pktcnt = 0;
		} else {
			int32_t rssi_ackAvg;
			int8_t rssi_thres;
			int8_t rssi_ack_vmin;

			/*
			 * It worked with no retries. First ignore bogus (small)
			 * rssi_ack values.
			 */
			if (tx_rate == ath_rc_priv->rate_max_phy &&
			    ath_rc_priv->hw_maxretry_pktcnt < 255) {
				ath_rc_priv->hw_maxretry_pktcnt++;
			}

			if (tx_info_priv->tx.ts_rssi <
			    rate_table->info[tx_rate].rssi_ack_validmin)
				goto exit;

			/* Average the rssi */
			if (tx_rate != ath_rc_priv->rssi_sum_rate) {
				ath_rc_priv->rssi_sum_rate = tx_rate;
				ath_rc_priv->rssi_sum =
				    ath_rc_priv->rssi_sum_cnt = 0;
			}

			ath_rc_priv->rssi_sum += tx_info_priv->tx.ts_rssi;
			ath_rc_priv->rssi_sum_cnt++;

			if (ath_rc_priv->rssi_sum_cnt < 4)
				goto exit;

			rssi_ackAvg =
			    (ath_rc_priv->rssi_sum + 2) / 4;
			rssi_thres =
			    ath_rc_priv->state[tx_rate].rssi_thres;
			rssi_ack_vmin =
			    rate_table->info[tx_rate].rssi_ack_validmin;

			ath_rc_priv->rssi_sum =
			    ath_rc_priv->rssi_sum_cnt = 0;

			/* Now reduce the current rssi threshold */
			if ((rssi_ackAvg < rssi_thres + 2) &&
			    (rssi_thres > rssi_ack_vmin)) {
				ath_rc_priv->state[tx_rate].rssi_thres--;
			}

			state_change = B_TRUE;
		}
	}
exit:
	return (state_change);
}

/*
 * Update PER, RSSI and whatever else that the code thinks
 * it is doing. If you can make sense of all this, you really
 * need to go out more.
 */
static void
arn_rc_update_ht(struct arn_softc *sc,
    struct ath_rate_priv *ath_rc_priv,
    struct ath_tx_info_priv *tx_info_priv,
    int tx_rate, int xretries, int retries)
{
#define	CHK_RSSI(rate)					\
	((ath_rc_priv->state[(rate)].rssi_thres +	\
	    rate_table->info[(rate)].rssi_ack_deltamin) > \
	    ath_rc_priv->state[(rate)+1].rssi_thres)

	/* u32 now_msec = jiffies_to_msecs(jiffies); */
	uint32_t now_msec = drv_hztousec(ddi_get_lbolt())/1000; /* mescs ? */
	int rate;
	uint8_t last_per;
	boolean_t state_change = B_FALSE;
	struct ath_rate_table *rate_table = sc->sc_currates;
	int size = ath_rc_priv->rate_table_size;

	if ((tx_rate < 0) || (tx_rate > rate_table->rate_cnt))
		return;

	/* To compensate for some imbalance between ctrl and ext. channel */

	if (WLAN_RC_PHY_40(rate_table->info[tx_rate].phy))
		tx_info_priv->tx.ts_rssi =
		    tx_info_priv->tx.ts_rssi < 3 ? 0 :
		    tx_info_priv->tx.ts_rssi - 3;

	last_per = ath_rc_priv->state[tx_rate].per;

	/* Update PER first */
	state_change = arn_rc_update_per(sc, rate_table, ath_rc_priv,
	    tx_info_priv, tx_rate, xretries,
	    retries, now_msec);

	/*
	 * If this rate looks bad (high PER) then stop using it for
	 * a while (except if we are probing).
	 */
	if (ath_rc_priv->state[tx_rate].per >= 55 && tx_rate > 0 &&
	    rate_table->info[tx_rate].ratekbps <=
	    rate_table->info[ath_rc_priv->rate_max_phy].ratekbps) {
		(void) arn_rc_get_nextlowervalid_txrate(rate_table,
		    ath_rc_priv,
		    (uint8_t)tx_rate,
		    &ath_rc_priv->rate_max_phy);

		/* Don't probe for a little while. */
		ath_rc_priv->probe_time = now_msec;
	}

	if (state_change) {
		/*
		 * Make sure the rates above this have higher rssi thresholds.
		 * (Note:  Monotonicity is kept within the OFDM rates and
		 * within the CCK rates. However, no adjustment is
		 * made to keep the rssi thresholds monotonically
		 * increasing between the CCK and OFDM rates.)
		 */
		for (rate = tx_rate; rate < size - 1; rate++) {
			if (rate_table->info[rate+1].phy !=
			    rate_table->info[tx_rate].phy)
				break;

			if (CHK_RSSI(rate)) {
				ath_rc_priv->state[rate+1].rssi_thres =
				    ath_rc_priv->state[rate].rssi_thres +
				    rate_table->info[rate].rssi_ack_deltamin;
			}
		}

		/* Make sure the rates below this have lower rssi thresholds. */
		for (rate = tx_rate - 1; rate >= 0; rate--) {
			if (rate_table->info[rate].phy !=
			    rate_table->info[tx_rate].phy)
				break;

			if (CHK_RSSI(rate)) {
				if (ath_rc_priv->state[rate+1].rssi_thres <
				    rate_table->info[rate].rssi_ack_deltamin)
					ath_rc_priv->state[rate].rssi_thres = 0;
				else {
					ath_rc_priv->state[rate].rssi_thres =
					    ath_rc_priv->state[rate+1].
					    rssi_thres -
					    rate_table->info[rate].
					    rssi_ack_deltamin;
				}

				if (ath_rc_priv->state[rate].rssi_thres <
				    rate_table->info[rate].rssi_ack_validmin) {
					ath_rc_priv->state[rate].rssi_thres =
					    rate_table->info[rate].
					    rssi_ack_validmin;
				}
			}
		}
	}

	/* Make sure the rates below this have lower PER */
	/* Monotonicity is kept only for rates below the current rate. */
	if (ath_rc_priv->state[tx_rate].per < last_per) {
		for (rate = tx_rate - 1; rate >= 0; rate--) {
			if (rate_table->info[rate].phy !=
			    rate_table->info[tx_rate].phy)
				break;

			if (ath_rc_priv->state[rate].per >
			    ath_rc_priv->state[rate+1].per) {
				ath_rc_priv->state[rate].per =
				    ath_rc_priv->state[rate+1].per;
			}
		}
	}

	/* Maintain monotonicity for rates above the current rate */
	for (rate = tx_rate; rate < size - 1; rate++) {
		if (ath_rc_priv->state[rate+1].per <
		    ath_rc_priv->state[rate].per)
			ath_rc_priv->state[rate+1].per =
			    ath_rc_priv->state[rate].per;
	}

	/*
	 * Every so often, we reduce the thresholds and
	 * PER (different for CCK and OFDM).
	 */
	if (now_msec - ath_rc_priv->rssi_down_time >=
	    rate_table->rssi_reduce_interval) {

		for (rate = 0; rate < size; rate++) {
			if (ath_rc_priv->state[rate].rssi_thres >
			    rate_table->info[rate].rssi_ack_validmin)
				ath_rc_priv->state[rate].rssi_thres -= 1;
		}
		ath_rc_priv->rssi_down_time = now_msec;
	}

	/*
	 * Every so often, we reduce the thresholds
	 * and PER (different for CCK and OFDM).
	 */
	if (now_msec - ath_rc_priv->per_down_time >=
	    rate_table->rssi_reduce_interval) {
		for (rate = 0; rate < size; rate++) {
			ath_rc_priv->state[rate].per =
			    7 * ath_rc_priv->state[rate].per / 8;
		}

		ath_rc_priv->per_down_time = now_msec;
	}

#undef CHK_RSSI
}

static int
ath_rc_get_rateindex(struct ath_rate_table *rate_table,
    struct ath9k_tx_rate *rate)
{
	int rix;

	if ((rate->flags & ATH9K_TX_RC_40_MHZ_WIDTH) &&
	    (rate->flags & ATH9K_TX_RC_SHORT_GI))
		rix = rate_table->info[rate->idx].ht_index;
	else if (rate->flags & ATH9K_TX_RC_SHORT_GI)
		rix = rate_table->info[rate->idx].sgi_index;
	else if (rate->flags & ATH9K_TX_RC_40_MHZ_WIDTH)
		rix = rate_table->info[rate->idx].cw40index;
	else
		rix = rate_table->info[rate->idx].base_index;

	return (rix);
}

static void
ath_rc_tx_status(struct arn_softc *sc, struct ath_rate_priv *ath_rc_priv,
    struct ath_buf *bf, int final_ts_idx, int xretries, int long_retry)
{
	struct ath_tx_info_priv *tx_info_priv =
	    (struct ath_tx_info_priv *)&bf->tx_info_priv;
	struct ath9k_tx_rate *rates = bf->rates;
	struct ath_rate_table *rate_table;
	uint32_t i = 0, rix;
	uint8_t flags;

	rate_table = sc->sc_currates;

	/*
	 * If the first rate is not the final index, there
	 * are intermediate rate failures to be processed.
	 */
	if (final_ts_idx != 0) {
		/* Process intermediate rates that failed. */
		for (i = 0; i < final_ts_idx; i++) {
			if (rates[i].count != 0 && (rates[i].idx >= 0)) {
				flags = rates[i].flags;

				/*
				 * If HT40 and we have switched mode from
				 * 40 to 20 => don't update
				 */

				if ((flags & ATH9K_TX_RC_40_MHZ_WIDTH) &&
				    (ath_rc_priv->rc_phy_mode !=
				    WLAN_RC_40_FLAG))
					return;

				rix =
				    ath_rc_get_rateindex(rate_table, &rates[i]);
				arn_rc_update_ht(sc, ath_rc_priv,
				    tx_info_priv, rix,
				    xretries ? 1 : 2,
				    rates[i].count);
			}
		}
	} else {
		/*
		 * Handle the special case of MIMO PS burst, where the second
		 * aggregate is sent out with only one rate and one try.
		 * Treating it as an excessive retry penalizes the rate
		 * inordinately.
		 */
		if (rates[0].count == 1 && xretries == 1)
			xretries = 2;
	}

	flags = rates[i].flags;

	/* If HT40 and we have switched mode from 40 to 20 => don't update */
	if ((flags & ATH9K_TX_RC_40_MHZ_WIDTH) &&
	    (ath_rc_priv->rc_phy_mode != WLAN_RC_40_FLAG)) {
		return;
	}

	rix = ath_rc_get_rateindex(rate_table, &rates[i]);
	arn_rc_update_ht(sc, ath_rc_priv, tx_info_priv, rix,
	    xretries, long_retry);
}

static struct ath_rate_table *
arn_choose_rate_table(struct arn_softc *sc, uint32_t cur_mode,
    boolean_t is_ht, boolean_t is_cw_40)
{
	int ath9k_mode;
	switch (cur_mode) {
	case IEEE80211_MODE_11A:
	case IEEE80211_MODE_11NA:
		ath9k_mode = ATH9K_MODE_11A;
		if (is_ht)
			ath9k_mode = ATH9K_MODE_11NA_HT20;
		if (is_cw_40)
			ath9k_mode = ATH9K_MODE_11NA_HT40PLUS;
		break;
	case IEEE80211_MODE_11B:
		ath9k_mode = ATH9K_MODE_11B;
		break;
	case IEEE80211_MODE_11G:
	case IEEE80211_MODE_11NG:
		ath9k_mode = ATH9K_MODE_11G;
		if (is_ht)
			ath9k_mode = ATH9K_MODE_11NG_HT20;
		if (is_cw_40)
			ath9k_mode = ATH9K_MODE_11NG_HT40PLUS;
		break;
	default:
		ARN_DBG((ARN_DBG_RATE, "Invalid band\n"));
		return (NULL);
	}

	switch (ath9k_mode) {
	case ATH9K_MODE_11A:
		ARN_DBG((ARN_DBG_RATE, "choose rate table:ATH9K_MODE_11A\n"));
		break;
	case ATH9K_MODE_11B:
		ARN_DBG((ARN_DBG_RATE, "choose rate table:ATH9K_MODE_11B\n"));
		break;
	case ATH9K_MODE_11G:
		ARN_DBG((ARN_DBG_RATE, "choose rate table:ATH9K_MODE_11G\n"));
		break;
	case ATH9K_MODE_11NA_HT20:
		ARN_DBG((ARN_DBG_RATE,
		    "choose rate table:ATH9K_MODE_11NA_HT20\n"));
		break;
	case ATH9K_MODE_11NA_HT40PLUS:
		ARN_DBG((ARN_DBG_RATE,
		    "choose rate table:ATH9K_MODE_11NA_HT40PLUS\n"));
		break;
	case ATH9K_MODE_11NG_HT20:
		ARN_DBG((ARN_DBG_RATE,
		    "choose rate table:ATH9K_MODE_11NG_HT20\n"));
		break;
	case ATH9K_MODE_11NG_HT40PLUS:
		ARN_DBG((ARN_DBG_RATE,
		    "choose rate table:ATH9K_MODE_11NG_HT40PLUS\n"));
		break;
	default:
		arn_problem("Invalid band\n");
		break;
	}

	ARN_DBG((ARN_DBG_RATE, "Choosing rate table for mode: %d\n",
	    ath9k_mode));
	return (sc->hw_rate_table[ath9k_mode]);
}

/* Private rate contral initialization */
static void
arn_rc_init(struct arn_softc *sc,
    struct ath_rate_priv *ath_rc_priv,
    struct ieee80211_node *in)
{
	struct ath_rate_table *rate_table = NULL;
	struct ath_rateset *rateset = &ath_rc_priv->neg_rates;
	ieee80211com_t *ic = (ieee80211com_t *)sc;
	uint32_t cur_mode = ic->ic_curmode;
	uint8_t *ht_mcs = (uint8_t *)&ath_rc_priv->neg_ht_rates;
	uint8_t i, j, k, hi = 0, hthi = 0;
	boolean_t is_rc_ds;

	/* FIXME: Adhoc */
	if ((sc->sc_ah->ah_opmode == ATH9K_M_STA) ||
	    (sc->sc_ah->ah_opmode == ATH9K_M_IBSS)) {
		boolean_t is_ht = in->in_flags & IEEE80211_NODE_HT;
		/* 20/40 support */
		boolean_t is_cw_40 =
		    in->in_htcap & IEEE80211_HTCAP_CHWIDTH40;
		rate_table =
		    arn_choose_rate_table(sc, cur_mode, is_ht, is_cw_40);
	} else if (sc->sc_ah->ah_opmode == ATH9K_M_HOSTAP) {
		/* cur_rate_table would be set on init */
		rate_table = sc->sc_currates;
	}

	if (!rate_table) {
		ARN_DBG((ARN_DBG_FATAL, "Rate table not initialized\n"));
		return;
	}

	if (in->in_flags & IEEE80211_NODE_HT) {
		/* 2.6.30 */
		ath_rc_priv->ht_cap = WLAN_RC_HT_FLAG;
		is_rc_ds = (AR_SREV_9280_20_OR_LATER(sc->sc_ah) &&
		    (ath9k_hw_get_eeprom(sc->sc_ah, EEP_RC_CHAIN_MASK) == 1)) ?
		    B_FALSE: B_TRUE;
		if (sc->sc_ah->ah_caps.tx_chainmask != 1 && is_rc_ds) {
			if (sc->sc_ht_conf.rx_mcs_mask[1]) {
				ath_rc_priv->ht_cap |= WLAN_RC_DS_FLAG;
			}
		}

		if (in->in_htcap & IEEE80211_HTCAP_CHWIDTH40)
			ath_rc_priv->ht_cap |= WLAN_RC_40_FLAG;
		if (in->in_htcap & IEEE80211_HTCAP_SHORTGI40)
			ath_rc_priv->ht_cap |= WLAN_RC_SGI_FLAG;
	}

	/*
	 * Initial rate table size. Will change depending
	 * on the working rate set
	 */
	ath_rc_priv->rate_table_size = RATE_TABLE_SIZE;

	/* Initialize thresholds according to the global rate table */
	for (i = 0; i < ath_rc_priv->rate_table_size; i++) {
		ath_rc_priv->state[i].rssi_thres =
		    rate_table->info[i].rssi_ack_validmin;
		ath_rc_priv->state[i].per = 0;
	}

	/* Determine the valid rates */
	arn_rc_init_valid_txmask(ath_rc_priv);

	for (i = 0; i < WLAN_RC_PHY_MAX; i++) {
		for (j = 0; j < MAX_TX_RATE_PHY; j++)
			ath_rc_priv->valid_phy_rateidx[i][j] = 0;
		ath_rc_priv->valid_phy_ratecnt[i] = 0;
	}
	ath_rc_priv->rc_phy_mode = (ath_rc_priv->ht_cap & WLAN_RC_40_FLAG);

	/* Set stream capability */
	ath_rc_priv->single_stream =
	    (ath_rc_priv->ht_cap & WLAN_RC_DS_FLAG) ? 0 : 1;

	if (!rateset->rs_nrates) {
		/* No working rate, just initialize valid rates */
		hi = arn_rc_init_validrates(ath_rc_priv, rate_table,
		    ath_rc_priv->ht_cap);
	} else {
		/* Use intersection of working rates and valid rates */
		hi = arn_rc_setvalid_rates(ath_rc_priv, rate_table,
		    rateset, ath_rc_priv->ht_cap);
		if (ath_rc_priv->ht_cap & WLAN_RC_HT_FLAG) {
			hthi = arn_rc_setvalid_htrates(ath_rc_priv,
			    rate_table,
			    ht_mcs,
			    ath_rc_priv->ht_cap);
		}
		hi = A_MAX(hi, hthi);
	}

	ath_rc_priv->rate_table_size = hi + 1;
	ath_rc_priv->rate_max_phy = 0;
	ASSERT(ath_rc_priv->rate_table_size <= RATE_TABLE_SIZE);

	for (i = 0, k = 0; i < WLAN_RC_PHY_MAX; i++) {
		for (j = 0; j < ath_rc_priv->valid_phy_ratecnt[i]; j++) {
			ath_rc_priv->valid_rate_index[k++] =
			    ath_rc_priv->valid_phy_rateidx[i][j];
		}

		if (!arn_rc_valid_phyrate(i, rate_table->initial_ratemax, 1) ||
		    !ath_rc_priv->valid_phy_ratecnt[i])
			continue;

		ath_rc_priv->rate_max_phy =
		    ath_rc_priv->valid_phy_rateidx[i][j-1];
	}
	ASSERT(ath_rc_priv->rate_table_size <= RATE_TABLE_SIZE);
	ASSERT(k <= RATE_TABLE_SIZE);

	ath_rc_priv->max_valid_rate = k;
	arn_rc_sort_validrates(rate_table, ath_rc_priv);
	ath_rc_priv->rate_max_phy = ath_rc_priv->valid_rate_index[k-4];
	sc->sc_currates = rate_table;
}

void
arn_tx_status(struct arn_softc *sc, struct ath_buf *bf, boolean_t is_data)
{
	struct ieee80211_node *in = (struct ieee80211_node *)(bf->bf_in);
	struct ath_node *an = ATH_NODE(in);
	struct ath_rate_priv *ath_rc_priv =
	    (struct ath_rate_priv *)&an->rate_priv;
	struct ath_tx_info_priv *tx_info_priv =
	    (struct ath_tx_info_priv *)&bf->tx_info_priv;
	int final_ts_idx, tx_status = 0, is_underrun = 0;

	final_ts_idx = tx_info_priv->tx.ts_rateindex;

	if (!is_data || !tx_info_priv->update_rc)
		return;

	if (tx_info_priv->tx.ts_status & ATH9K_TXERR_FILT)
		return;

	/*
	 * If underrun error is seen assume it as an excessive retry only
	 * if prefetch trigger level have reached the max (0x3f for 5416)
	 * Adjust the long retry as if the frame was tried ATH_11N_TXMAXTRY
	 * times. This affects how ratectrl updates PER for the failed rate.
	 */
	if (tx_info_priv->tx.ts_flags &
	    (ATH9K_TX_DATA_UNDERRUN | ATH9K_TX_DELIM_UNDERRUN) &&
	    ((sc->sc_ah->ah_txTrigLevel) >= ath_rc_priv->tx_triglevel_max)) {
		tx_status = 1;
		is_underrun = 1;
	}

	if ((tx_info_priv->tx.ts_status & ATH9K_TXERR_XRETRY) ||
	    (tx_info_priv->tx.ts_status & ATH9K_TXERR_FIFO))
		tx_status = 1;

	ath_rc_tx_status(sc,
	    ath_rc_priv,
	    bf,
	    final_ts_idx,
	    tx_status,
	    (is_underrun) ? ATH_11N_TXMAXTRY : tx_info_priv->tx.ts_longretry);
}

void
arn_get_rate(struct arn_softc *sc, struct ath_buf *bf,
    struct ieee80211_frame *wh)
{
	struct ieee80211_node *in = (struct ieee80211_node *)(bf->bf_in);
	struct ath_node *an = ATH_NODE(in);
	struct ath_rate_priv *ath_rc_priv =
	    (struct ath_rate_priv *)&an->rate_priv;
	struct ath_rate_table *rt = sc->sc_currates;
	ieee80211com_t *ic = (ieee80211com_t *)sc;
	int is_probe = 0;
	uint8_t i;

	/* lowest rate for management and multicast/broadcast frames */
	if (!IEEE80211_IS_DATA(wh) || IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		bf->rates[0].idx = 0; /* xxx Fix me */
		bf->rates[0].count =
		    IEEE80211_IS_MULTICAST(wh->i_addr1) ?
		    1 : ATH_MGT_TXMAXTRY;
		return;
	}

	/* Find tx rate for unicast frames */
	arn_rc_ratefind(sc, ath_rc_priv, bf, ATH_11N_TXMAXTRY, 4,
	    &is_probe, B_FALSE);

	/* Temporary workaround for 'dladm show-wifi' */
	for (i = 0; i < in->in_rates.ir_nrates; i++) {
		ARN_DBG((ARN_DBG_RATE, "arn: arn_get_rate(): "
		    "in->in_rates.ir_rates[%d] = %d,"
		    "bf->rates[0].idx = %d,"
		    "rt->info[bf->rates[0].idx].dot11rate = %d\n",
		    i,
		    in->in_rates.ir_rates[i],
		    bf->rates[0].idx,
		    rt->info[bf->rates[0].idx].dot11rate));
		if (rt->info[bf->rates[0].idx].dot11rate ==
		    in->in_rates.ir_rates[i])
			break;
	}
	in->in_txrate = i;
	if (ic->ic_curmode == IEEE80211_MODE_11NA ||
	    ic->ic_curmode == IEEE80211_MODE_11NG)
		in->in_txrate = in->in_rates.ir_nrates - 1;

	/* Check if aggregation has to be enabled for this tid */
#ifdef ARN_TX_AGGREGATION
	/* should check if enabled, not supported */
	if (sc->sc_ht_conf.ht_supported) {
		if (ieee80211_is_data_qos(wh)) {
			uint8_t *qc, tid;
			struct ath_node *an;
			struct ieee80211_qosframe *qwh = NULL;

			qwh = (struct ieee80211_qosframe *)wh;
			tid = qc[0] & 0xf;
			an = (struct ath_node *)sta->drv_priv;

			if (arn_tx_aggr_check(sc, an, tid))
				/* to do */
		}
	}
#endif /* ARN_TX_AGGREGATION */
}

void
arn_rate_init(struct arn_softc *sc, struct ieee80211_node *in)
{
	int i;
	struct ath_node *an = ATH_NODE(in);
	struct ath_rate_priv *ath_rc_priv =
	    (struct ath_rate_priv *)&an->rate_priv;

	/* should be moved to arn_node_init later */
	ath_rc_priv->rssi_down_time =
	    drv_hztousec(ddi_get_lbolt())/1000; /* mesc */
	ath_rc_priv->tx_triglevel_max =
	    sc->sc_ah->ah_caps.tx_triglevel_max;

	for (i = 0; i < in->in_rates.ir_nrates; i++) {
		ath_rc_priv->neg_rates.rs_rates[i] = in->in_rates.ir_rates[i];
		ARN_DBG((ARN_DBG_RATE, "arn:arn_rate_init()"
		    "ath_rc_priv->neg_rates.rs_rates[%d] = %d\n",
		    i, ath_rc_priv->neg_rates.rs_rates[i]));
	}
	ath_rc_priv->neg_rates.rs_nrates = in->in_rates.ir_nrates;

	/* negotiated ht rate set ??? */
	if (in->in_flags & IEEE80211_NODE_HT) {
		for (i = 0; i < in->in_htrates.rs_nrates; i++) {
			ath_rc_priv->neg_ht_rates.rs_rates[i] =
			    in->in_htrates.rs_rates[i];
			ARN_DBG((ARN_DBG_RATE, "arn:arn_rate_init()"
			    "ath_rc_priv->neg_ht_rates.rs_rates[%d] = %d\n",
			    i, ath_rc_priv->neg_ht_rates.rs_rates[i]));
		}
		ath_rc_priv->neg_ht_rates.rs_nrates = in->in_htrates.rs_nrates;

		/* arn_update_chainmask(sc); */
	}

#ifdef ARN_TX_AGGREGATION
	/* Temply put the following ht info init here */
	uint8_t ampdu_factor, ampdu_density;
	if (sc->sc_ht_conf.ht_support &&
	    (in->in_htcap_ie != NULL) &&
	    (in->in_htcap != 0) &&
	    (in->in_htparam != 0)) {
		ampdu_factor = in->in_htparam & HT_RX_AMPDU_FACTOR_MSK;
		ampdu_density = (in->in_htparam & HT_MPDU_DENSITY_MSK) >>
		    HT_MPDU_DENSITY_POS;
		an->maxampdu =
		    1 << (IEEE80211_HTCAP_MAXRXAMPDU_FACTOR + ampdu_factor);
		an->mpdudensity = parse_mpdudensity(ampdu_density);
	}
	/* end */
#endif /* ARN_TX_AGGREGATION */

	arn_rc_init(sc, ath_rc_priv, in);
}

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

#ifdef ARN_LEGACY_RC
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
#endif /* ARN_LEGACY_RC */
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

#ifdef ARN_LEGACY_RC
		if (state == IEEE80211_S_RUN) {
			arn_rate_ctl_start(sc, in);
		} else {
			arn_rate_update(sc, in, 0);
		}
#else
		if (state == IEEE80211_S_RUN)
			arn_rate_init(sc, in);
#endif
	/* LINTED E_NOP_ELSE_STMT */
	} else {
		/*
		 * When operating as a station the node table holds
		 * the AP's that were discovered during scanning.
		 * For any other operating mode we want to reset the
		 * tx rate state of each node.
		 */
#ifdef ARN_LEGACY_RC
		ieee80211_iterate_nodes(&ic->ic_sta, arn_rate_cb, sc);
#endif
	}
}

#ifdef ARN_LEGACY_RC
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
#endif /* ARN_LEGACY_RC */
