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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * DDR3-specific SPD processing logic. For an overview of the processing design
 * please see libjedec_spd.c.
 */

#include <sys/sysmacros.h>
#include <sys/debug.h>
#include "libjedec_spd.h"

static const spd_value_map_t spd_ddr3_nbytes_used_map[] = {
	{ SPD_DDR3_NBYTES_USED_UNDEF, 0, true },
	{ SPD_DDR3_NBYTES_USED_128, 128, false },
	{ SPD_DDR3_NBYTES_USED_176, 176, false },
	{ SPD_DDR3_NBYTES_USED_256, 256, false },
};

static const spd_value_map_t spd_ddr3_nbytes_total_map[] = {
	{ SPD_DDR3_NBYTES_TOTAL_UNDEF, 0, true },
	{ SPD_DDR3_NBYTES_TOTAL_256, 256, false }
};

/*
 * The macro values represent the last byte covered therefore the number of
 * bytes is that plus one.
 */
static const spd_value_map_t spd_ddr3_crc_map[] = {
	{ SPD_DDR3_NBYTES_CRC_125, 126, false },
	{ SPD_DDR3_NBYTES_CRC_116, 117, false }
};

static void
spd_parse_ddr3_nbytes(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t used = SPD_DDR3_NBYTES_USED(data);
	const uint8_t total = SPD_DDR3_NBYTES_TOTAL(data);
	const uint8_t crc = SPD_DDR3_NBYTES_CRC(data);

	spd_insert_map(si, SPD_KEY_NBYTES_USED, used, spd_ddr3_nbytes_used_map,
	    ARRAY_SIZE(spd_ddr3_nbytes_used_map));
	spd_insert_map(si, SPD_KEY_NBYTES_TOTAL, total,
	    spd_ddr3_nbytes_total_map, ARRAY_SIZE(spd_ddr3_nbytes_total_map));

	/*
	 * Unlike DDR5, there is no specific definition to indicate that the SPD
	 * is present or what type of device it is. There is only one standard
	 * DDR3 EEPROM, EE1002, so we note that it's here when we process this.
	 */
	spd_upsert_flag(si, SPD_KEY_DEVS, SPD_DEVICE_SPD);
	spd_nvl_insert_u32(si, SPD_KEY_DEV_SPD_TYPE, SPD_SPD_T_EE1002);

	spd_insert_map(si, SPD_KEY_CRC_DDR3_LEN, crc, spd_ddr3_crc_map,
	    ARRAY_SIZE(spd_ddr3_crc_map));
}

static const spd_value_map_t spd_ddr3_mod_type_map[] = {
	{ SPD_DDR3_MOD_TYPE_TYPE_UNDEF, UINT32_MAX, true },
	{ SPD_DDR3_MOD_TYPE_TYPE_RDIMM, SPD_MOD_TYPE_RDIMM, false },
	{ SPD_DDR3_MOD_TYPE_TYPE_UDIMM, SPD_MOD_TYPE_UDIMM, false },
	{ SPD_DDR3_MOD_TYPE_TYPE_SODIMM, SPD_MOD_TYPE_SODIMM, false },
	{ SPD_DDR3_MOD_TYPE_TYPE_MICRO_DIMM, SPD_MOD_TYPE_MICRO_DIMM, false },
	{ SPD_DDR3_MOD_TYPE_TYPE_MINI_RDIMM, SPD_MOD_TYPE_MINI_RDIMM, false },
	{ SPD_DDR3_MOD_TYPE_TYPE_MINI_UDIMM, SPD_MOD_TYPE_MINI_UDIMM, false },
	{ SPD_DDR3_MOD_TYPE_TYPE_MINI_CDIMM, SPD_MOD_TYPE_MINI_CDIMM, false },
	{ SPD_DDR3_MOD_TYPE_TYPE_72b_SORDIMM, SPD_MOD_TYPE_72b_SO_RDIMM,
	    false },
	{ SPD_DDR3_MOD_TYPE_TYPE_72b_SOUDIMM, SPD_MOD_TYPE_72b_SO_UDIMM,
	    false },
	{ SPD_DDR3_MOD_TYPE_TYPE_72b_SOCDIMM, SPD_MOD_TYPE_72b_SO_CDIMM,
	    false },
	{ SPD_DDR3_MOD_TYPE_TYPE_LRDIMM, SPD_MOD_TYPE_LRDIMM, false },
	{ SPD_DDR3_MOD_TYPE_TYPE_16b_SODIMM, SPD_MOD_TYPE_16b_SO_DIMM, false },
	{ SPD_DDR3_MOD_TYPE_TYPE_32b_SODIMM, SPD_MOD_TYPE_32b_SO_DIMM, false },
};

static void
spd_parse_ddr3_mod_type(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t type = SPD_DDR3_MOD_TYPE_TYPE(data);

	spd_insert_map(si, SPD_KEY_MOD_TYPE, type, spd_ddr3_mod_type_map,
	    ARRAY_SIZE(spd_ddr3_mod_type_map));
}

static const spd_value_range_t spd_ddr3_nba_range = {
	.svr_max = SPD_DDR3_DENSITY_NBA_BITS_MAX,
	.svr_base = SPD_DDR3_DENSITY_NBA_BITS_BASE
};

static const spd_value_map64_t spd_ddr3_density_map[] = {
	{SPD_DDR3_DENSITY_DENSITY_256Mb, 256ULL * 1024ULL * 1024ULL, false },
	{SPD_DDR3_DENSITY_DENSITY_512Mb, 512ULL * 1024ULL * 1024ULL, false },
	{SPD_DDR3_DENSITY_DENSITY_1Gb, 1ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{SPD_DDR3_DENSITY_DENSITY_2Gb, 2ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{SPD_DDR3_DENSITY_DENSITY_4Gb, 4ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{SPD_DDR3_DENSITY_DENSITY_8Gb, 8ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{SPD_DDR3_DENSITY_DENSITY_16Gb, 16ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{SPD_DDR3_DENSITY_DENSITY_32Gb, 32ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{SPD_DDR3_DENSITY_DENSITY_12Gb, 12ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{SPD_DDR3_DENSITY_DENSITY_24Gb, 24ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
};

/*
 * DDR3 does not define bank groups, hence when we insert the bank address bits
 * we come back and set bank group bits to 0.
 */
static void
spd_parse_ddr3_density(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t dens = SPD_DDR3_DENSITY_DENSITY(data);
	const uint8_t nba = SPD_DDR3_DENSITY_NBA_BITS(data);

	spd_insert_range(si, SPD_KEY_NBANK_BITS, nba, &spd_ddr3_nba_range);
	spd_nvl_insert_u32(si, SPD_KEY_NBGRP_BITS, 0);
	spd_insert_map64(si, SPD_KEY_DIE_SIZE, dens, spd_ddr3_density_map,
	    ARRAY_SIZE(spd_ddr3_density_map));
}

static const spd_value_range_t spd_ddr3_nrow_range = {
	.svr_max = SPD_DDR3_ADDR_NROWS_MAX,
	.svr_base = SPD_DDR3_ADDR_NROWS_BASE
};

static const spd_value_range_t spd_ddr3_ncol_range = {
	.svr_max = SPD_DDR3_ADDR_NCOLS_MAX,
	.svr_base = SPD_DDR3_ADDR_NCOLS_BASE
};

static void
spd_parse_ddr3_addr(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t nrows = SPD_DDR3_ADDR_NROWS(data);
	const uint8_t ncols = SPD_DDR3_ADDR_NCOLS(data);

	spd_insert_range(si, SPD_KEY_NROW_BITS, nrows, &spd_ddr3_nrow_range);
	spd_insert_range(si, SPD_KEY_NCOL_BITS, ncols, &spd_ddr3_ncol_range);
}

static void
spd_parse_ddr3_volt(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	uint32_t volts[3];
	uint_t nvolt = 0;

	/*
	 * DDR3 came out with 1.5V support initially meaning a value of zero
	 * indicates that 1.5V is supported. Affirmative values came later.
	 */
	if (SPD_DDR3_VOLT_V1P5_OPER(data) == 0) {
		volts[nvolt] = 1500;
		nvolt++;
	}

	if (SPD_DDR3_VOLT_V1P35_OPER(data) != 0) {
		volts[nvolt] = 1350;
		nvolt++;
	}

	if (SPD_DDR3_VOLT_V1P25_OPER(data) != 0) {
		volts[nvolt] = 1250;
		nvolt++;
	}

	if (nvolt > 0) {
		spd_nvl_insert_u32_array(si, key, volts, nvolt);
	}
}

static const spd_value_range_t spd_ddr3_width_range = {
	.svr_base = SPD_DDR3_MOD_ORG_WIDTH_BASE,
	.svr_max = SPD_DDR3_MOD_ORG_WIDTH_MAX,
	.svr_exp = true
};

static const spd_value_map_t spd_ddr3_nranks[] = {
	{ SPD_DDR3_MOD_ORG_NRANKS_1, 1, false },
	{ SPD_DDR3_MOD_ORG_NRANKS_2, 2, false },
	{ SPD_DDR3_MOD_ORG_NRANKS_3, 3, false },
	{ SPD_DDR3_MOD_ORG_NRANKS_4, 4, false },
	{ SPD_DDR3_MOD_ORG_NRANKS_8, 8, false }
};

static void
spd_parse_ddr3_mod_org(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t nranks = SPD_DDR4_MOD_ORG_NPKG_RANK(data);
	const uint8_t width = SPD_DDR4_MOD_ORG_WIDTH(data);

	spd_insert_range(si, SPD_KEY_DRAM_WIDTH, width, &spd_ddr3_width_range);
	spd_insert_map(si, SPD_KEY_NRANKS, nranks, spd_ddr3_nranks,
	    ARRAY_SIZE(spd_ddr3_nranks));
}

static const spd_value_map_t spd_ddr3_ext_width[] = {
	{ SPD_DDR4_MOD_BUS_WIDTH_EXT_NONE, 0, false },
	{ SPD_DDR4_MOD_BUS_WIDTH_EXT_8b, 8, false }
};

static const spd_value_range_t spd_ddr3_pri_range = {
	.svr_base = SPD_DDR3_BUS_WIDTH_PRI_BASE,
	.svr_max = SPD_DDR3_BUS_WIDTH_PRI_MAX,
	.svr_exp = true
};

static void
spd_parse_ddr3_bus_width(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t ext = SPD_DDR3_BUS_WIDTH_EXT(data);
	const uint8_t pri = SPD_DDR3_BUS_WIDTH_PRI(data);

	/*
	 * DDR3 only has a single channel and subchanne. Record that reality
	 * here.
	 */
	spd_nvl_insert_u32(si, SPD_KEY_NSUBCHAN, 1);
	spd_nvl_insert_u32(si, SPD_KEY_DRAM_NCHAN, 1);
	spd_insert_range(si, SPD_KEY_DATA_WIDTH, pri, &spd_ddr3_pri_range);
	spd_insert_map(si, SPD_KEY_ECC_WIDTH, ext, spd_ddr3_ext_width,
	    ARRAY_SIZE(spd_ddr3_ext_width));
}

/*
 * We only currently support a 1 ps FTB. The DDR3 spec has examples of 2.5ps and
 * 5ps versions. 1p was the magic number required for DDR4 and LPDDR3-5. For now
 * we admit we don't support processing it and will cross the bridge when it
 * becomes important for consumers.
 */
static void
spd_parse_ddr3_ftb(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];

	if (SPD_DDR3_FTB_DIVIDEND(data) != 1 ||
	    SPD_DDR3_FTB_DIVISOR(data) != 1) {
		spd_nvl_err(si, key, SPD_ERROR_NO_XLATE, "library cannot "
		    "handle FTB value that's not 1ps, found divisor and "
		    "dividend %u/%u", SPD_DDR3_FTB_DIVISOR(data),
		    SPD_DDR3_FTB_DIVIDEND(data));
		return;
	}

	spd_nvl_insert_u32(si, key, SPD_DDR3_FTB_PS);
}

/*
 * There are two bytes that represent the divisor and dividend; however, only a
 * value that results in 125ps is supported by the spec.
 */
static void
spd_parse_ddr3_mtb(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t dividend = si->si_data[off];
	const uint8_t divisor = si->si_data[off + 1];

	if (dividend != SPD_DDR3_MTB_125PS_DIVIDEND ||
	    divisor != SPD_DDR3_MTB_125PS_DIVISOR) {
		spd_nvl_err(si, key, SPD_ERROR_NO_XLATE, "library encountered "
		    "undefined MTB value (not 125ps): found divisor and "
		    "dividend %u/%u", divisor, dividend);
		return;
	}

	spd_nvl_insert_u32(si, key, SPD_DDR3_MTB_PS);
}

static void
spd_parse_ddr3_cas(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	uint32_t cas[16] = { 0 };
	uint_t ncas = 0;

	ASSERT3U(len, ==, 2);
	for (uint32_t byte = 0; byte < len; byte++) {
		const uint32_t data = si->si_data[off + byte];
		uint32_t nbits = NBBY;

		/*
		 * The last byte reserves the last bit.
		 */
		if (byte == len - 1)
			nbits--;

		for (uint32_t i = 0; i < nbits; i++) {
			if (bitx8(data, i, i) == 1) {
				cas[ncas] = SPD_DDR3_CAS_BASE + i + NBBY * byte;
				ncas++;
			}
		}
	}

	spd_nvl_insert_u32_array(si, key, cas, ncas);
}

/*
 * Parse a time value that is a single number of MTB units.
 */
static void
spd_parse_ddr3_mtb_time(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint64_t ps = (uint64_t)si->si_data[off] * SPD_DDR3_MTB_PS;

	if (ps == 0) {
		spd_nvl_err(si, key, SPD_ERROR_NO_XLATE,
		    "encountered unexpected zero time value");
		return;
	}
	spd_nvl_insert_u64(si, key, ps);
}

/*
 *
 * t~RAS~ consists of the upper nibble at off and the MTB at off + 1.
 */
static void
spd_parse_ddr3_tras(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t ras_nib = SPD_DDR3_RAS_RC_UPPER_RAS(si->si_data[off]);
	ASSERT3U(len, ==, 2);

	return (spd_parse_ddr_time(si, key, ras_nib, si->si_data[off + 1], 0));
}

/*
 * t~RC~ consists of an upper 4-bit nibble at off. Its MTB is at off + 2. The
 * FTB is at off + len - 1.
 */
static void
spd_parse_ddr3_trc(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t rc_nib = SPD_DDR3_RAS_RC_UPPER_RC(si->si_data[off]);

	return (spd_parse_ddr_time(si, key, rc_nib, si->si_data[off + 2],
	    si->si_data[off + len - 1]));
}

static void
spd_parse_ddr3_tfaw(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t nib = SPD_DDR3_TFAB_NIB_UPPER_TFAW(si->si_data[off]);
	ASSERT3U(len, ==, 2);

	return (spd_parse_ddr_time(si, key, nib, si->si_data[off + 1], 0));
}

static void
spd_parse_ddr3_opt_feat(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	spd_ddr3_feat_t flags = 0;

	if (SPD_DDR3_OPT_FEAT_RZQ6(data) != 0)
		flags |= SPD_DDR3_FEAT_RZQ_6;
	if (SPD_DDR3_OPT_FEAT_RZQ7(data) != 0)
		flags |= SPD_DDR3_FEAT_RZQ_7;
	if (SPD_DDR3_OPT_FEAT_DLLO(data) != 0)
		flags |= SPD_DDR3_FEAT_DLL_OFF;

	if (flags != 0) {
		spd_upsert_flag(si, SPD_KEY_DDR3_FEAT, flags);
	}
}

static const spd_value_map_t spd_ddr3_temp[] = {
	{ SPD_DDR3_REFRESH_ETR_TEMP_85C, JEDEC_TEMP_CASE_NT, false },
	{ SPD_DDR3_REFRESH_ETR_TEMP_95C, JEDEC_TEMP_CASE_XT, false },
};

static const spd_value_map_t spd_ddr3_xtrr[] = {
	{ SPD_DDR3_REFRESH_ETR_REF_2X, 2, false },
	{ SPD_DDR3_REFRESH_ETR_REF_1X, 1, false },
};

/*
 * While this defines an ODTS bit it was pending a ballot and it's not clear to
 * us that this ballot has ever passed. If it has, then we will denote
 * something there.
 */
static void
spd_parse_ddr3_refresh(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t etr = SPD_DDR3_REFRESH_ETR_TEMP(data);
	const uint8_t rr = SPD_DDR3_REFRESH_ETR_REF(data);

	spd_insert_map(si, SPD_KEY_MOD_OPER_TEMP, etr,
	    spd_ddr3_temp, ARRAY_SIZE(spd_ddr3_temp));
	spd_insert_map(si, SPD_KEY_DDR3_XTRR, rr,
	    spd_ddr3_xtrr, ARRAY_SIZE(spd_ddr3_xtrr));
	if (SPD_DDR3_REFRESH_ASR_SUP(data) != 0) {
		spd_upsert_flag(si, SPD_KEY_DDR3_FEAT, SPD_DDR3_FEAT_ASR);
	}

	if (SPD_DDR3_REFRESH_PASR_SUP(data) != 0) {
		spd_nvl_insert_key(si, SPD_KEY_DDR_PASR);
	}
}

static void
spd_parse_ddr3_ts(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];

	if (SPD_DDR3_MOD_THERM_PRES(data)) {
		spd_upsert_flag(si, SPD_KEY_DEVS, SPD_DEVICE_TEMP_1);
		spd_nvl_insert_u32(si, SPD_KEY_DEV_TEMP_TYPE,
		    SPD_TEMP_T_TSE2002);
	}
}

static const spd_value_map_t spd_ddr3_sl_map[] = {
	{ SPD_DDR3_PKG_SIG_LOAD_UNSPEC, SPD_SL_UNSPECIFIED, false },
	{ SPD_DDR3_PKG_SIG_LOAD_MULTI, SPD_SL_MUTLI_STACK, false },
	{ SPD_DDR3_PKG_SIG_LOAD_SINGLE, SPD_SL_3DS, false }
};

static const spd_value_range_t spd_ddr3_ndie_range = {
	.svr_min = SPD_DDR3_PKG_DIE_CNT_MIN,
	.svr_max = SPD_DDR3_PKG_DIE_CNT_MAX,
	.svr_exp = true
};

static void
spd_parse_ddr3_type(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t ndie = SPD_DDR3_PKG_DIE_CNT(data);
	const uint8_t sl = SPD_DDR3_PKG_SIG_LOAD(data);

	if (SPD_DDR3_PKG_TYPE(data) == SPD_DDR3_PKG_TYPE_NOT) {
		spd_nvl_insert_key(si, SPD_KEY_PKG_NOT_MONO);
	}

	/*
	 * A value of zero here is considered unspecified.
	 */
	if (SPD_DDR3_PKG_DIE_CNT(data) != 0) {
		spd_insert_range(si, SPD_KEY_PKG_NDIE, ndie,
		    &spd_ddr3_ndie_range);
	}

	spd_insert_map(si, SPD_KEY_PKG_SL, sl, spd_ddr3_sl_map,
	    ARRAY_SIZE(spd_ddr3_sl_map));
}

static const spd_value_map_t spd_ddr3_maw_map[] = {
	{ SPD_DDR3_MAC_MAW_8192X, 8192, false },
	{ SPD_DDR3_MAC_MAW_4096X, 4096, false },
	{ SPD_DDR3_MAC_MAW_2048X, 2048, false }
};

static const spd_value_map_t spd_ddr3_mac_map[] = {
	{ SPD_DDR3_MAC_MAC_UNTESTED, 0, true},
	{ SPD_DDR3_MAC_MAC_700K, 700000, false },
	{ SPD_DDR3_MAC_MAC_600K, 600000, false },
	{ SPD_DDR3_MAC_MAC_500K, 500000, false },
	{ SPD_DDR3_MAC_MAC_400K, 400000, false },
	{ SPD_DDR3_MAC_MAC_300K, 300000, false },
	{ SPD_DDR3_MAC_MAC_200K, 200000, false },
	{ SPD_DDR3_MAC_MAC_UNLIMITED, SPD_KEY_MAC_UNLIMITED, false }
};

static void
spd_parse_ddr3_mac(spd_info_t *si, uint32_t off, uint32_t len, const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t maw = SPD_DDR3_MAC_MAW(data);
	const uint8_t mac = SPD_DDR3_MAC_MAC(data);

	spd_insert_map(si, SPD_KEY_MAW, maw, spd_ddr3_maw_map,
	    ARRAY_SIZE(spd_ddr3_maw_map));
	spd_insert_map(si, SPD_KEY_MAC, mac, spd_ddr3_mac_map,
	    ARRAY_SIZE(spd_ddr3_mac_map));
}

/*
 * The DDR3 CRC comes in two different lengths as the DDR3 CRC may optionally
 * cover the manufacturing information or stop short at byte 116. Which length
 * this is is defined in byte 0.
 */
static void
spd_parse_ddr3_crc(spd_info_t *si, uint32_t off, uint32_t len, const char *key)
{
	const uint16_t expect = si->si_data[off + len - 2] |
	    (si->si_data[off + len - 1] << 8);
	const uint8_t crc = SPD_DDR3_NBYTES_CRC(si->si_data[SPD_DDR3_NBYTES]);
	const uint32_t crc_len = crc == SPD_DDR3_NBYTES_CRC_125 ? 127 : 117;

	spd_parse_crc_expect(si, off, crc_len, expect, key);
}

static const spd_parse_t spd_ddr3_common[] = {
	{ .sp_off = SPD_DDR3_NBYTES, .sp_parse = spd_parse_ddr3_nbytes },
	{ .sp_off = SPD_DDR3_SPD_REV, .sp_parse = spd_parse_rev },
	/*
	 * We have previously validated that the DRAM type is something that we
	 * understand. We pass through the raw enum to users here.
	 */
	{ .sp_off = SPD_DDR3_DRAM_TYPE, .sp_key = SPD_KEY_DRAM_TYPE,
	    .sp_parse = spd_parse_raw_u8 },
	{ .sp_off = SPD_DDR3_MOD_TYPE, .sp_parse = spd_parse_ddr3_mod_type },
	{ .sp_off = SPD_DDR3_DENSITY, .sp_parse = spd_parse_ddr3_density },
	{ .sp_off = SPD_DDR3_ADDR, .sp_parse = spd_parse_ddr3_addr },
	{ .sp_off = SPD_DDR3_VOLT, .sp_key = SPD_KEY_NOM_VDD,
	    .sp_parse = spd_parse_ddr3_volt },
	{ .sp_off = SPD_DDR3_MOD_ORG, .sp_parse = spd_parse_ddr3_mod_org },
	{ .sp_off = SPD_DDR3_BUS_WIDTH, .sp_parse = spd_parse_ddr3_bus_width },
	{ .sp_off = SPD_DDR3_FTB, .sp_key = SPD_KEY_FTB,
	    .sp_parse = spd_parse_ddr3_ftb },
	{ .sp_off = SPD_DDR3_MTB_DIVIDEND, .sp_key = SPD_KEY_MTB, .sp_len = 2,
	    .sp_parse = spd_parse_ddr3_mtb },
	{ .sp_off = SPD_DDR3_TCK_MIN, .sp_key = SPD_KEY_TCKAVG_MIN,
	    .sp_len = SPD_DDR3_TCK_MIN_FINE - SPD_DDR3_TCK_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_DDR3_CAS_SUP0, .sp_key = SPD_KEY_CAS, .sp_len = 2,
	    .sp_parse = spd_parse_ddr3_cas },
	{ .sp_off = SPD_DDR3_TAA_MIN, .sp_key = SPD_KEY_TAA_MIN,
	    .sp_len = SPD_DDR3_TAA_MIN_FINE - SPD_DDR3_TAA_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_DDR3_TWR_MIN, .sp_key = SPD_KEY_TWR_MIN,
	    .sp_parse = spd_parse_ddr3_mtb_time },
	{ .sp_off = SPD_DDR3_TRCD_MIN, .sp_key = SPD_KEY_TRCD_MIN,
	    .sp_len = SPD_DDR3_TRCD_MIN_FINE - SPD_DDR3_TRCD_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	/*
	 * DDR3 defines only a single tRRD value. There are no bank groups in
	 * DDR3 therefore we translate that to tRRD_L, as we consider everything
	 * to be in a single bank group.
	 */
	{ .sp_off = SPD_DDR3_TRRD_MIN, .sp_key = SPD_KEY_TRRD_L_MIN,
	    .sp_parse = spd_parse_ddr3_mtb_time },
	{ .sp_off = SPD_DDR3_TRP_MIN, .sp_key = SPD_KEY_TRP_MIN,
	    .sp_len = SPD_DDR3_TRP_MIN_FINE - SPD_DDR3_TRP_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_DDR3_RAS_RC_UPPER, .sp_len = 2,
	    .sp_key = SPD_KEY_TRAS_MIN, .sp_parse = spd_parse_ddr3_tras },
	{ .sp_off = SPD_DDR3_RAS_RC_UPPER, .sp_key = SPD_KEY_TRC_MIN,
	    .sp_len = SPD_DDR3_TRC_MIN_FINE - SPD_DDR3_RAS_RC_UPPER + 1,
	    .sp_parse = spd_parse_ddr3_trc },
	/*
	 * Our rough understanding is that the DDR3 tRFC is a 1x rate.
	 */
	{ .sp_off = SPD_DDR3_TRFC_MIN_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TRFC1_MIN, .sp_parse = spd_parse_mtb_pair },
	/*
	 * tWTR is like tRRD and it gets mapped to the same bank group case.
	 */
	{ .sp_off = SPD_DDR3_TWTR_MIN, .sp_key = SPD_KEY_TWTRS_MIN,
	    .sp_parse = spd_parse_ddr3_mtb_time },
	{ .sp_off = SPD_DDR3_TRTP_MIN, .sp_key = SPD_KEY_TRTP,
	    .sp_parse = spd_parse_ddr3_mtb_time },
	{ .sp_off = SPD_DDR3_TFAW_NIB, .sp_len = 2,
	    .sp_key = SPD_KEY_TFAW, .sp_parse = spd_parse_ddr3_tfaw },
	{ .sp_off = SPD_DDR3_OPT_FEAT, .sp_parse = spd_parse_ddr3_opt_feat },
	{ .sp_off = SPD_DDR3_REFRESH, .sp_parse = spd_parse_ddr3_refresh },
	{ .sp_off = SPD_DDR3_MOD_THERM, .sp_parse = spd_parse_ddr3_ts },
	{ .sp_off = SPD_DDR3_TYPE, .sp_parse = spd_parse_ddr3_type },
	{ .sp_off = SPD_DDR3_MAC, .sp_parse = spd_parse_ddr3_mac},
	/*
	 * As the CRC is part of all module types we just stick in with the
	 * general processing.
	 */
	{ .sp_len = SPD_DDR3_CRC_MSB + 1, .sp_key = SPD_KEY_CRC_DDR3,
	    .sp_parse = spd_parse_ddr3_crc },
};

static const spd_parse_t spd_ddr3_mfg[] = {
	{ .sp_off = SPD_DDR3_MFG_MOD_ID0, .sp_len = 2,
	    .sp_key = SPD_KEY_MFG_MOD_MFG_ID,
	    .sp_parse = spd_parse_jedec_id },
	{ .sp_off = SPD_DDR3_MFG_MOD_ID0, .sp_len = 2,
	    .sp_key = SPD_KEY_MFG_MOD_MFG_NAME,
	    .sp_parse = spd_parse_jedec_id_str },
	{ .sp_off = SPD_DDR3_MFG_LOC, .sp_key = SPD_KEY_MFG_MOD_LOC_ID,
	    .sp_parse = spd_parse_raw_u8 },
	{ .sp_off = SPD_DDR3_MFG_YEAR, .sp_key = SPD_KEY_MFG_MOD_YEAR,
	    .sp_parse = spd_parse_hex_string },
	{ .sp_off = SPD_DDR3_MFG_WEEK, .sp_key = SPD_KEY_MFG_MOD_WEEK,
	    .sp_parse = spd_parse_hex_string },
	{ .sp_off = SPD_DDR3_MOD_SN, .sp_len = SPD_DDR3_MOD_SN_LEN,
	    .sp_key = SPD_KEY_MFG_MOD_SN, .sp_parse = spd_parse_hex_string },
	{ .sp_off = SPD_DDR3_MOD_PN, .sp_len = SPD_DDR3_MOD_PN_LEN,
	    .sp_key = SPD_KEY_MFG_MOD_PN, .sp_parse = spd_parse_string },
	/*
	 * In DDR3 the module revision is a two byte value that is up to the
	 * vendor to define. While we've seen one instance where this was split
	 * into a DDR4 style module and DRAM revision, we just blindly turn it
	 * into a hex string just because that is not a guarantee.
	 */
	{ .sp_off = SPD_DDR3_MOD_REV, .sp_len = SPD_DDR3_MOD_REV_LEN,
	    .sp_key = SPD_KEY_MFG_MOD_REV, .sp_parse = spd_parse_hex_string },
	{ .sp_off = SPD_DDR3_MFG_DRAM_ID0, .sp_len = 2,
	    .sp_key = SPD_KEY_MFG_DRAM_MFG_ID,
	    .sp_parse = spd_parse_jedec_id },
	{ .sp_off = SPD_DDR3_MFG_DRAM_ID0, .sp_len = 2,
	    .sp_key = SPD_KEY_MFG_DRAM_MFG_NAME,
	    .sp_parse = spd_parse_jedec_id_str },
};

static void
spd_parse_ddr3_design(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(off, >=, SPD_DDR3_RDIMM_HEIGHT);
	return (spd_parse_design(si, off, SPD_DDR3_UDIMM_HEIGHT));
}

static void
spd_parse_ddr3_edge(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];

	if (SPD_DDR3_UDIMM_MAP_R1(data) == SPD_DDR3_UDIMM_MAP_R1_MIRROR)
		spd_nvl_insert_key(si, SPD_KEY_MOD_EDGE_MIRROR);
}

static const spd_parse_t spd_ddr3_udimm[] = {
	{ .sp_off = SPD_DDR3_UDIMM_HEIGHT, .sp_key = SPD_KEY_MOD_HEIGHT,
	    .sp_parse = spd_parse_height },
	{ .sp_off = SPD_DDR3_UDIMM_THICK, .sp_parse = spd_parse_thickness },
	{ .sp_off = SPD_DDR3_UDIMM_REF, .sp_parse = spd_parse_ddr3_design },
	{ .sp_off = SPD_DDR3_UDIMM_MAP, .sp_parse = spd_parse_ddr3_edge }
};

/*
 * This mapping is true for both the number of rows and registers.
 */
static const spd_value_map_t spd_ddr3_rdimm_nrows_map[] = {
	{ 0, 0, true },
	{ 1, 1, false },
	{ 2, 2, false },
	{ 3, 4, false }
};

static void
spd_parse_ddr3_rdimm_attr(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t nregs = SPD_DDR3_RDIMM_ATTR_NREGS(data);
	const uint8_t nrows = SPD_DDR3_RDIMM_ATTR_NROWS(data);

	spd_insert_map(si, SPD_KEY_MOD_NROWS, nrows, spd_ddr3_rdimm_nrows_map,
	    ARRAY_SIZE(spd_ddr3_rdimm_nrows_map));
	spd_insert_map(si, SPD_KEY_MOD_NREGS, nregs, spd_ddr3_rdimm_nrows_map,
	    ARRAY_SIZE(spd_ddr3_rdimm_nrows_map));
}

static void
spd_parse_ddr3_rdimm_hs(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];

	if (SPD_DDR3_RDIMM_THERM_IMPL(data) != 0)
		spd_upsert_flag(si, SPD_KEY_DEVS, SPD_DEVICE_HS);
}

static void
spd_parse_ddr3_rdimm_type(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t type = SPD_DDR3_RDIMM_RTYPE_TYPE(data);

	if (type != SPD_DDR3_RDIMM_RTYPE_TYPE_SSTE32882) {
		spd_nvl_err(si, SPD_KEY_DEV_RCD_TYPE, SPD_ERROR_NO_XLATE,
		    "encountered unknown register type value: 0x%x", type);
		return;
	}

	spd_upsert_flag(si, SPD_KEY_DEVS, SPD_DEVICE_RCD);
	spd_nvl_insert_u32(si, SPD_KEY_DEV_RCD_TYPE, SPD_RCD_T_SSTE32882);
}

/*
 * There are different variants of these maps that RDIMMs and LRDIMMs share
 * which are used depending on the specific register value and what it actually
 * supports.
 */
static const spd_value_map_t spd_ddr3_rdimm_lmsv_ds_map[] = {
	{ SPD_DDR3_RDIMM_DS_LIGHT, SPD_DRIVE_LIGHT, false },
	{ SPD_DDR3_RDIMM_DS_MODERATE, SPD_DRIVE_MODERATE, false },
	{ SPD_DDR3_RDIMM_DS_STRONG, SPD_DRIVE_STRONG, false },
	{ SPD_DDR3_RDIMM_DS_VERY_STRONG, SPD_DRIVE_VERY_STRONG, false },
};

static const spd_value_map_t spd_ddr3_rdimm_lms_ds_map[] = {
	{ SPD_DDR3_RDIMM_DS_LIGHT, SPD_DRIVE_LIGHT, false },
	{ SPD_DDR3_RDIMM_DS_MODERATE, SPD_DRIVE_MODERATE, false },
	{ SPD_DDR3_RDIMM_DS_STRONG, SPD_DRIVE_STRONG, false },
};

static const spd_value_map_t spd_ddr3_rdimm_lm_ds_map[] = {
	{ SPD_DDR3_RDIMM_DS_LIGHT, SPD_DRIVE_LIGHT, false },
	{ SPD_DDR3_RDIMM_DS_MODERATE, SPD_DRIVE_MODERATE, false },
};

static void
spd_parse_ddr3_rdimm_cads(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t caa = SPD_DDR3_RDIMM_CADS_CAA(data);
	const uint8_t cab = SPD_DDR3_RDIMM_CADS_CAB(data);

	spd_insert_map(si, SPD_KEY_DDR3_RCD_DS_CAA, caa,
	    spd_ddr3_rdimm_lms_ds_map, ARRAY_SIZE(spd_ddr3_rdimm_lms_ds_map));
	spd_insert_map(si, SPD_KEY_DDR3_RCD_DS_CAB, cab,
	    spd_ddr3_rdimm_lms_ds_map, ARRAY_SIZE(spd_ddr3_rdimm_lms_ds_map));
}

static void
spd_parse_ddr3_rdimm_ccds(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t ctla = SPD_DDR3_RDIMM_CCDS_CTLA(data);
	const uint8_t ctlb = SPD_DDR3_RDIMM_CCDS_CTLB(data);
	const uint8_t y1 = SPD_DDR3_RDIMM_CCDS_CLK1(data);
	const uint8_t y0 = SPD_DDR3_RDIMM_CCDS_CLK0(data);


	spd_insert_map(si, SPD_KEY_DDR3_RCD_DS_CTLA, ctla,
	    spd_ddr3_rdimm_lm_ds_map, ARRAY_SIZE(spd_ddr3_rdimm_lm_ds_map));
	spd_insert_map(si, SPD_KEY_DDR3_RCD_DS_CTLB, ctlb,
	    spd_ddr3_rdimm_lm_ds_map, ARRAY_SIZE(spd_ddr3_rdimm_lm_ds_map));
	spd_insert_map(si, SPD_KEY_DDR3_RCD_DS_Y0, y0,
	    spd_ddr3_rdimm_lms_ds_map, ARRAY_SIZE(spd_ddr3_rdimm_lms_ds_map));
	spd_insert_map(si, SPD_KEY_DDR3_RCD_DS_Y1, y1,
	    spd_ddr3_rdimm_lms_ds_map, ARRAY_SIZE(spd_ddr3_rdimm_lms_ds_map));
}

static const spd_parse_t spd_ddr3_rdimm[] = {
	{ .sp_off = SPD_DDR3_RDIMM_HEIGHT, .sp_key = SPD_KEY_MOD_HEIGHT,
	    .sp_parse = spd_parse_height },
	{ .sp_off = SPD_DDR3_RDIMM_THICK, .sp_parse = spd_parse_thickness },
	{ .sp_off = SPD_DDR3_RDIMM_REF, .sp_parse = spd_parse_ddr3_design },
	{ .sp_off = SPD_DDR3_RDIMM_ATTR,
	    .sp_parse = spd_parse_ddr3_rdimm_attr },
	{ .sp_off = SPD_DDR3_RDIMM_THERM, .sp_parse = spd_parse_ddr3_rdimm_hs },
	{ .sp_off = SPD_DDR3_RDIMM_REG_MFG_ID0, .sp_len = 2,
	    .sp_key = SPD_KEY_DEV_RCD_MFG,
	    .sp_parse = spd_parse_jedec_id },
	{ .sp_off = SPD_DDR3_RDIMM_REG_MFG_ID0, .sp_len = 2,
	    .sp_key = SPD_KEY_DEV_RCD_MFG_NAME,
	    .sp_parse = spd_parse_jedec_id_str },
	{ .sp_off = SPD_DDR3_RDIMM_REV, .sp_key = SPD_KEY_DEV_RCD_REV,
	    .sp_parse = spd_parse_dram_step },
	{ .sp_off = SPD_DDR3_RDIMM_RTYPE,
	    .sp_parse = spd_parse_ddr3_rdimm_type },
	{ .sp_off = SPD_DDR3_RDIMM_CADS,
	    .sp_parse = spd_parse_ddr3_rdimm_cads },
	{ .sp_off = SPD_DDR3_RDIMM_CCDS,
	    .sp_parse = spd_parse_ddr3_rdimm_ccds },
};

static const spd_parse_t spd_ddr3_cdimm[] = {
	{ .sp_off = SPD_DDR3_CDIMM_HEIGHT, .sp_key = SPD_KEY_MOD_HEIGHT,
	    .sp_parse = spd_parse_height },
	{ .sp_off = SPD_DDR3_CDIMM_THICK, .sp_parse = spd_parse_thickness },
	{ .sp_off = SPD_DDR3_CDIMM_REF, .sp_parse = spd_parse_ddr3_design },
};

static const spd_value_map_t spd_ddr3_lrdimm_nrows_map[] = {
	{ 0, 0, true },
	{ 1, 1, false },
	{ 2, 2, false },
};

static const spd_value_map_t spd_ddr3_lrdimm_orient_map[] = {
	{ SPD_DDR3_LRDIMM_ATTR_ORIENT_VERT, SPD_ORNT_VERTICAL, false },
	{ SPD_DDR3_LRDIMM_ATTR_ORIENT_HORIZ, SPD_ORNT_HORIZONTAL, false }
};

static void
spd_parse_ddr3_lrdimm_attr(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t mirror = SPD_DDR3_LRDIMM_ATTR_MIR(data);
	const uint8_t nrows = SPD_DDR3_LRDIMM_ATTR_NROWS(data);
	const uint8_t orient = SPD_DDR3_LRDIMM_ATTR_ORIENT(data);

	if (mirror == SPD_DDR3_LRDIMM_ATTR_MIR_ODD_ARE)
		spd_nvl_insert_key(si, SPD_KEY_MOD_EDGE_MIRROR);

	spd_insert_map(si, SPD_KEY_MOD_NROWS, nrows, spd_ddr3_lrdimm_nrows_map,
	    ARRAY_SIZE(spd_ddr3_lrdimm_nrows_map));
	spd_insert_map(si, SPD_KEY_DDR3_MB_ORIENT, orient,
	    spd_ddr3_lrdimm_orient_map, ARRAY_SIZE(spd_ddr3_lrdimm_orient_map));

	if (SPD_DDR3_LRDIMM_ATTR_HS(data) != 0)
		spd_upsert_flag(si, SPD_KEY_DEVS, SPD_DEVICE_HS);
}

static void
spd_parse_ddr3_lrdimm_mb(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 2);

	/*
	 * Use this chance to set the DDR3 MB device as present and its type.
	 */
	spd_upsert_flag(si, SPD_KEY_DEVS, SPD_DEVICE_DB);
	spd_nvl_insert_u32(si, SPD_KEY_DEV_DB_TYPE, SPD_DB_T_DDR3MB);
	spd_parse_jedec_id(si, off, 2, SPD_KEY_DEV_DB_MFG);
	spd_parse_jedec_id_str(si, off, 2, SPD_KEY_DEV_DB_MFG_NAME);
}

static void
spd_parse_ddr3_lrdimm_tcds(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t ca = SPD_DDR3_LRDIMM_TCDS_AC(data);
	const uint8_t cs = SPD_DDR3_LRDIMM_TCDS_QxCS(data);

	spd_insert_map(si, SPD_KEY_DDR3_MB_DS_CA, ca,
	    spd_ddr3_rdimm_lmsv_ds_map, ARRAY_SIZE(spd_ddr3_rdimm_lmsv_ds_map));
	spd_insert_map(si, SPD_KEY_DDR3_MB_DS_CS, cs,
	    spd_ddr3_rdimm_lms_ds_map, ARRAY_SIZE(spd_ddr3_rdimm_lms_ds_map));
}

static void
spd_parse_ddr3_lrdimm_ckds(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t odt = SPD_DDR3_LRDIMM_CKDS_ODT(data);
	const uint8_t cke = SPD_DDR3_LRDIMM_CKDS_CKE(data);
	const uint8_t y1 = SPD_DDR3_LRDIMM_CKDS_Y1Y3(data);
	const uint8_t y0 = SPD_DDR3_LRDIMM_CKDS_Y0Y2(data);

	spd_insert_map(si, SPD_KEY_DDR3_MB_DS_ODT, odt,
	    spd_ddr3_rdimm_lms_ds_map, ARRAY_SIZE(spd_ddr3_rdimm_lms_ds_map));
	spd_insert_map(si, SPD_KEY_DDR3_MB_DS_CKE, cke,
	    spd_ddr3_rdimm_lms_ds_map, ARRAY_SIZE(spd_ddr3_rdimm_lms_ds_map));
	spd_insert_map(si, SPD_KEY_DDR3_MB_DS_Y1, y1,
	    spd_ddr3_rdimm_lms_ds_map, ARRAY_SIZE(spd_ddr3_rdimm_lms_ds_map));
	spd_insert_map(si, SPD_KEY_DDR3_MB_DS_Y0, y0,
	    spd_ddr3_rdimm_lms_ds_map, ARRAY_SIZE(spd_ddr3_rdimm_lms_ds_map));
}

static void
spd_parse_ddr3_lrdimm_ext_delay(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t y = SPD_DDR3_LRDIMM_EXTD_Y(data);
	const uint8_t cs = SPD_DDR3_LRDIMM_EXTD_CS(data);
	const uint8_t odt = SPD_DDR3_LRDIMM_EXTD_ODT(data);
	const uint8_t cke = SPD_DDR3_LRDIMM_EXTD_CKE(data);

	/*
	 * A value of 0 is equal to no delay, otherwise these are a measure of
	 * x/128 * tCK values and we store x in the nvlist.
	 */
	if (y != 0)
		spd_nvl_insert_u32(si, SPD_KEY_DDR3_MB_EXTD_Y, y);
	if (cs != 0)
		spd_nvl_insert_u32(si, SPD_KEY_DDR3_MB_EXTD_CS, cs);
	if (odt != 0)
		spd_nvl_insert_u32(si, SPD_KEY_DDR3_MB_EXTD_ODT, odt);
	if (cke != 0)
		spd_nvl_insert_u32(si, SPD_KEY_DDR3_MB_EXTD_CKE, cke);
}

/*
 * Each additive delay nibble contains an enable bit. However, the enable bit
 * for Y clocks is actually bit 0 in SPD_DDR3_LRDIMM_TCDS.
 */
static void
spd_parse_ddr3_lrdimm_add_delay_csy(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t y = SPD_DDR3_LRDIMM_ADDD_CSY_Y(data);
	const uint8_t cs = SPD_DDR3_LRDIMM_ADDD_CSY_CS(data);
	ASSERT3U(off, >, SPD_DDR3_LRDIMM_TCDS);
	const uint8_t yen = si->si_data[SPD_DDR3_LRDIMM_TCDS];

	if (SPD_DDR3_LRDIMM_TCDS_ACPL(yen) != SPD_DDR3_LRDIMM_TCDS_ACPL_STD) {
		const uint8_t val = SPD_DDR3_LRDIMM_ADD_BASE - y;
		spd_nvl_insert_u32(si, SPD_KEY_DDR3_MB_ADDD_Y, val);
	}

	if (SPD_DDR3_LRDIMM_ADDD_CSY_CS_EN(data) != 0) {
		const uint8_t val = SPD_DDR3_LRDIMM_ADD_BASE - cs;
		spd_nvl_insert_u32(si, SPD_KEY_DDR3_MB_ADDD_CS, val);
	}
}

static void
spd_parse_ddr3_lrdimm_add_delay_odt(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t cke = SPD_DDR3_LRDIMM_ADDD_ODT_CKE(data);
	const uint8_t odt = SPD_DDR3_LRDIMM_ADDD_ODT_ODT(data);

	if (SPD_DDR3_LRDIMM_ADDD_ODT_CKE_EN(data) != 0) {
		const uint8_t val = SPD_DDR3_LRDIMM_ADD_BASE - cke;
		spd_nvl_insert_u32(si, SPD_KEY_DDR3_MB_ADDD_CKE, val);
	}

	if (SPD_DDR3_LRDIMM_ADDD_ODT_ODT_EN(data) != 0) {
		const uint8_t val = SPD_DDR3_LRDIMM_ADD_BASE - odt;
		spd_nvl_insert_u32(si, SPD_KEY_DDR3_MB_ADDD_ODT, val);
	}
}

static const spd_value_map_t spd_ddr3_mdq_ds_map[] = {
	{ SPD_DDR3_LRDIMM_MDQ_DS_40R, 40, false },
	{ SPD_DDR3_LRDIMM_MDQ_DS_34R, 34, false },
	{ SPD_DDR3_LRDIMM_MDQ_DS_48R, 48, false },
	{ SPD_DDR3_LRDIMM_MDQ_DS_27R, 27, false },
	{ SPD_DDR3_LRDIMM_MDQ_DS_20R, 20, false }
};

static const spd_value_map_t spd_ddr3_odt_map[] = {
	{ SPD_DDR3_LRDIMM_MDQ_ODT_DIS, SPD_TERM_DISABLED, false },
	{ SPD_DDR3_LRDIMM_MDQ_ODT_60R, 60, false },
	{ SPD_DDR3_LRDIMM_MDQ_ODT_120R, 120, false },
	{ SPD_DDR3_LRDIMM_MDQ_ODT_40R, 40, false },
	{ SPD_DDR3_LRDIMM_MDQ_ODT_30R, 30, false },
	{ SPD_DDR3_LRDIMM_MDQ_ODT_240R, 240, false },
	{ SPD_DDR3_LRDIMM_MDQ_ODT_80R, 80, false },
};

static void
spd_parse_ddr3_lrdimm_mdq(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t d800 = si->si_data[off];
	const uint8_t d1333 = si->si_data[off + SPD_DDR3_LRDIMM_STRIDE];
	const uint8_t d1866 = si->si_data[off + SPD_DDR3_LRDIMM_STRIDE * 2];
	const uint8_t odt[3] = { SPD_DDR3_LRDIMM_MDQ_ODT(d800),
	    SPD_DDR3_LRDIMM_MDQ_ODT(d1333), SPD_DDR3_LRDIMM_MDQ_ODT(d1866) };
	const uint8_t ds[3] = { SPD_DDR3_LRDIMM_MDQ_DS(d800),
	    SPD_DDR3_LRDIMM_MDQ_DS(d1333), SPD_DDR3_LRDIMM_MDQ_DS(d1866) };

	spd_insert_map_array(si, SPD_KEY_DDR3_MDQ_ODT, odt, ARRAY_SIZE(odt),
	    spd_ddr3_odt_map, ARRAY_SIZE(spd_ddr3_odt_map));
	spd_insert_map_array(si, SPD_KEY_DDR3_MDQ_DS, ds, ARRAY_SIZE(ds),
	    spd_ddr3_mdq_ds_map, ARRAY_SIZE(spd_ddr3_mdq_ds_map));
}

static void
spd_parse_ddr3_lrdimm_odt_common(spd_info_t *si, uint32_t off,
    const char *r0_odt0_rd_key, const char *r0_odt1_rd_key,
    const char *r1_odt0_rd_key, const char *r1_odt1_rd_key,
    const char *r0_odt0_wr_key, const char *r0_odt1_wr_key,
    const char *r1_odt0_wr_key, const char *r1_odt1_wr_key)
{
	const uint8_t d800 = si->si_data[off];
	const uint8_t d1333 = si->si_data[off + SPD_DDR3_LRDIMM_STRIDE];
	const uint8_t d1866 = si->si_data[off + SPD_DDR3_LRDIMM_STRIDE * 2];
	boolean_t r0_odt0_rd[3] = { SPD_DDR3_LRDIMM_ODT_R0_ODT0_RD(d800),
	    SPD_DDR3_LRDIMM_ODT_R0_ODT0_RD(d1333),
	    SPD_DDR3_LRDIMM_ODT_R0_ODT0_RD(d1866) };
	boolean_t r0_odt1_rd[3] = { SPD_DDR3_LRDIMM_ODT_R0_ODT1_RD(d800),
	    SPD_DDR3_LRDIMM_ODT_R0_ODT1_RD(d1333),
	    SPD_DDR3_LRDIMM_ODT_R0_ODT1_RD(d1866) };
	boolean_t r1_odt0_rd[3] = { SPD_DDR3_LRDIMM_ODT_R1_ODT0_RD(d800),
	    SPD_DDR3_LRDIMM_ODT_R1_ODT0_RD(d1333),
	    SPD_DDR3_LRDIMM_ODT_R1_ODT0_RD(d1866) };
	boolean_t r1_odt1_rd[3] = { SPD_DDR3_LRDIMM_ODT_R1_ODT1_RD(d800),
	    SPD_DDR3_LRDIMM_ODT_R1_ODT1_RD(d1333),
	    SPD_DDR3_LRDIMM_ODT_R1_ODT1_RD(d1866) };
	boolean_t r0_odt0_wr[3] = { SPD_DDR3_LRDIMM_ODT_R0_ODT0_WR(d800),
	    SPD_DDR3_LRDIMM_ODT_R0_ODT0_WR(d1333),
	    SPD_DDR3_LRDIMM_ODT_R0_ODT0_WR(d1866) };
	boolean_t r0_odt1_wr[3] = { SPD_DDR3_LRDIMM_ODT_R0_ODT1_WR(d800),
	    SPD_DDR3_LRDIMM_ODT_R0_ODT1_WR(d1333),
	    SPD_DDR3_LRDIMM_ODT_R0_ODT1_WR(d1866) };
	boolean_t r1_odt0_wr[3] = { SPD_DDR3_LRDIMM_ODT_R1_ODT0_WR(d800),
	    SPD_DDR3_LRDIMM_ODT_R1_ODT0_WR(d1333),
	    SPD_DDR3_LRDIMM_ODT_R1_ODT0_WR(d1866) };
	boolean_t r1_odt1_wr[3] = { SPD_DDR3_LRDIMM_ODT_R1_ODT1_WR(d800),
	    SPD_DDR3_LRDIMM_ODT_R1_ODT1_WR(d1333),
	    SPD_DDR3_LRDIMM_ODT_R1_ODT1_WR(d1866) };

	spd_nvl_insert_boolean_array(si, r0_odt0_rd_key, r0_odt0_rd,
	    ARRAY_SIZE(r0_odt0_rd));
	spd_nvl_insert_boolean_array(si, r0_odt1_rd_key, r0_odt1_rd,
	    ARRAY_SIZE(r0_odt1_rd));
	spd_nvl_insert_boolean_array(si, r1_odt0_rd_key, r1_odt0_rd,
	    ARRAY_SIZE(r1_odt0_rd));
	spd_nvl_insert_boolean_array(si, r1_odt1_rd_key, r1_odt1_rd,
	    ARRAY_SIZE(r1_odt1_rd));
	spd_nvl_insert_boolean_array(si, r0_odt0_wr_key, r0_odt0_wr,
	    ARRAY_SIZE(r0_odt0_wr));
	spd_nvl_insert_boolean_array(si, r0_odt1_wr_key, r0_odt1_wr,
	    ARRAY_SIZE(r0_odt1_wr));
	spd_nvl_insert_boolean_array(si, r1_odt0_wr_key, r1_odt0_wr,
	    ARRAY_SIZE(r1_odt0_wr));
	spd_nvl_insert_boolean_array(si, r1_odt1_wr_key, r1_odt1_wr,
	    ARRAY_SIZE(r1_odt1_wr));
}

static void
spd_parse_ddr3_lrdimm_odt_r0(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	spd_parse_ddr3_lrdimm_odt_common(si, off,
	    SPD_KEY_DDR3_MB_R0_ODT0_RD, SPD_KEY_DDR3_MB_R0_ODT1_RD,
	    SPD_KEY_DDR3_MB_R1_ODT0_RD, SPD_KEY_DDR3_MB_R1_ODT1_RD,
	    SPD_KEY_DDR3_MB_R0_ODT0_WR, SPD_KEY_DDR3_MB_R0_ODT1_WR,
	    SPD_KEY_DDR3_MB_R1_ODT0_WR, SPD_KEY_DDR3_MB_R1_ODT1_WR);
}

static void
spd_parse_ddr3_lrdimm_odt_r2(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	spd_parse_ddr3_lrdimm_odt_common(si, off,
	    SPD_KEY_DDR3_MB_R2_ODT0_RD, SPD_KEY_DDR3_MB_R2_ODT1_RD,
	    SPD_KEY_DDR3_MB_R3_ODT0_RD, SPD_KEY_DDR3_MB_R3_ODT1_RD,
	    SPD_KEY_DDR3_MB_R2_ODT0_WR, SPD_KEY_DDR3_MB_R2_ODT1_WR,
	    SPD_KEY_DDR3_MB_R3_ODT0_WR, SPD_KEY_DDR3_MB_R3_ODT1_WR);

}

static void
spd_parse_ddr3_lrdimm_odt_r4(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	spd_parse_ddr3_lrdimm_odt_common(si, off,
	    SPD_KEY_DDR3_MB_R4_ODT0_RD, SPD_KEY_DDR3_MB_R4_ODT1_RD,
	    SPD_KEY_DDR3_MB_R5_ODT0_RD, SPD_KEY_DDR3_MB_R5_ODT1_RD,
	    SPD_KEY_DDR3_MB_R4_ODT0_WR, SPD_KEY_DDR3_MB_R4_ODT1_WR,
	    SPD_KEY_DDR3_MB_R5_ODT0_WR, SPD_KEY_DDR3_MB_R5_ODT1_WR);

}

static void
spd_parse_ddr3_lrdimm_odt_r6(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	spd_parse_ddr3_lrdimm_odt_common(si, off,
	    SPD_KEY_DDR3_MB_R6_ODT0_RD, SPD_KEY_DDR3_MB_R6_ODT1_RD,
	    SPD_KEY_DDR3_MB_R7_ODT0_RD, SPD_KEY_DDR3_MB_R7_ODT1_RD,
	    SPD_KEY_DDR3_MB_R6_ODT0_WR, SPD_KEY_DDR3_MB_R6_ODT1_WR,
	    SPD_KEY_DDR3_MB_R7_ODT0_WR, SPD_KEY_DDR3_MB_R7_ODT1_WR);
}

static const spd_value_map_t spd_ddr3_rtt_wr_map[] = {
	{ SPD_DDR3_LRDIMM_RTT_WR_DIS, SPD_TERM_DISABLED, false },
	{ SPD_DDR3_LRDIMM_RTT_WR_60R, 60, false },
	{ SPD_DDR3_LRDIMM_RTT_WR_120R, 120, false },
};

static const spd_value_map_t spd_ddr3_rtt_nom_map[] = {
	{ SPD_DDR3_LRDIMM_RTT_NOM_DIS, SPD_TERM_DISABLED, false },
	{ SPD_DDR3_LRDIMM_RTT_NOM_60R, 60, false },
	{ SPD_DDR3_LRDIMM_RTT_NOM_120R, 120, false },
	{ SPD_DDR3_LRDIMM_RTT_NOM_40R, 40, false },
	{ SPD_DDR3_LRDIMM_RTT_NOM_20R, 20, false },
	{ SPD_DDR3_LRDIMM_RTT_NOM_30R, 30, false },
};

static const spd_value_map_t spd_ddr3_dram_imp_map[] = {
	{ SPD_DDR3_LRDIMM_RTT_IMP_40R, 40, false },
	{ SPD_DDR3_LRDIMM_RTT_IMP_34R, 34, false }
};

static void
spd_parse_ddr3_lrdimm_rtt(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t d800 = si->si_data[off];
	const uint8_t d1333 = si->si_data[off + SPD_DDR3_LRDIMM_STRIDE];
	const uint8_t d1866 = si->si_data[off + SPD_DDR3_LRDIMM_STRIDE * 2];
	const uint8_t imp[3] = { SPD_DDR3_LRDIMM_RTT_IMP(d800),
	    SPD_DDR3_LRDIMM_RTT_IMP(d1333), SPD_DDR3_LRDIMM_RTT_IMP(d1866) };
	const uint8_t nom[3] = { SPD_DDR3_LRDIMM_RTT_NOM(d800),
	    SPD_DDR3_LRDIMM_RTT_NOM(d1333), SPD_DDR3_LRDIMM_RTT_NOM(d1866) };
	const uint8_t wr[3] = { SPD_DDR3_LRDIMM_RTT_WR(d800),
	    SPD_DDR3_LRDIMM_RTT_WR(d1333), SPD_DDR3_LRDIMM_RTT_WR(d1866) };

	spd_insert_map_array(si, SPD_KEY_DDR3_DRAM_DS, imp, ARRAY_SIZE(imp),
	    spd_ddr3_dram_imp_map, ARRAY_SIZE(spd_ddr3_dram_imp_map));
	spd_insert_map_array(si, SPD_KEY_DDR3_RTT_NOM, nom, ARRAY_SIZE(nom),
	    spd_ddr3_rtt_nom_map, ARRAY_SIZE(spd_ddr3_rtt_nom_map));
	spd_insert_map_array(si, SPD_KEY_DDR3_RTT_WRT, wr, ARRAY_SIZE(wr),
	    spd_ddr3_rtt_wr_map, ARRAY_SIZE(spd_ddr3_rtt_wr_map));
}

/*
 * Parse the delay that is spread out amongst three registers, each of which are
 * two apart. These are for 1.5V, 1.35, and 1.25V each.
 */
static void
spd_parse_ddr3_lrdimm_mod_delay(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t d1v5 = si->si_data[off];
	const uint8_t d1v35 = si->si_data[off + 2];
	const uint8_t d1v25 = si->si_data[off + 4];
	uint64_t delay[3] = { d1v25 * SPD_DDR3_MTB_PS, d1v35 * SPD_DDR3_MTB_PS,
	    d1v5 * SPD_DDR3_MTB_PS };

	spd_nvl_insert_u64_array(si, key, delay, ARRAY_SIZE(delay));
}

static const spd_parse_t spd_ddr3_lrdimm[] = {
	{ .sp_off = SPD_DDR3_LRDIMM_HEIGHT, .sp_key = SPD_KEY_MOD_HEIGHT,
	    .sp_parse = spd_parse_height },
	{ .sp_off = SPD_DDR3_LRDIMM_THICK, .sp_parse = spd_parse_thickness },
	{ .sp_off = SPD_DDR3_LRDIMM_REF, .sp_parse = spd_parse_ddr3_design },
	{ .sp_off = SPD_DDR3_LRDIMM_ATTR,
	    .sp_parse = spd_parse_ddr3_lrdimm_attr },
	{ .sp_off = SPD_DDR3_LRDIMM_MB_REV, .sp_key = SPD_KEY_DEV_DB_REV,
	    .sp_parse = spd_parse_dram_step },
	{ .sp_off = SPD_DDR3_LRDIMM_MB_MFG_ID0, .sp_len = 2,
	    .sp_parse = spd_parse_ddr3_lrdimm_mb },
	{ .sp_off = SPD_DDR3_LRDIMM_TCDS,
	    .sp_parse = spd_parse_ddr3_lrdimm_tcds },
	{ .sp_off = SPD_DDR3_LRDIMM_CKDS,
	    .sp_parse = spd_parse_ddr3_lrdimm_ckds },
	{ .sp_off = SPD_DDR3_LRDIMM_EXTD,
	    .sp_parse = spd_parse_ddr3_lrdimm_ext_delay },
	{ .sp_off = SPD_DDR3_LRDIMM_ADDD_CSY,
	    .sp_parse = spd_parse_ddr3_lrdimm_add_delay_csy },
	{ .sp_off = SPD_DDR3_LRDIMM_ADDD_ODT,
	    .sp_parse = spd_parse_ddr3_lrdimm_add_delay_odt },
	{ .sp_off = SPD_DDR3_LRDIMM_MDQ_800,
	    .sp_len = SPD_DDR3_LRDIMM_MDQ_1866 - SPD_DDR3_LRDIMM_MDQ_800 + 1,
	    .sp_parse = spd_parse_ddr3_lrdimm_mdq },
	{ .sp_off = SPD_DDR3_LRDIMM_ODT_R0_800,
	    .sp_len = SPD_DDR3_LRDIMM_ODT_R0_1866 -
	    SPD_DDR3_LRDIMM_ODT_R0_800 + 1,
	    .sp_parse = spd_parse_ddr3_lrdimm_odt_r0 },
	{ .sp_off = SPD_DDR3_LRDIMM_ODT_R2_800,
	    .sp_len = SPD_DDR3_LRDIMM_ODT_R2_1866 -
	    SPD_DDR3_LRDIMM_ODT_R2_800 + 1,
	    .sp_parse = spd_parse_ddr3_lrdimm_odt_r2 },
	{ .sp_off = SPD_DDR3_LRDIMM_ODT_R4_800,
	    .sp_len = SPD_DDR3_LRDIMM_ODT_R4_1866 -
	    SPD_DDR3_LRDIMM_ODT_R4_800 + 1,
	    .sp_parse = spd_parse_ddr3_lrdimm_odt_r4 },
	{ .sp_off = SPD_DDR3_LRDIMM_ODT_R6_800,
	    .sp_len = SPD_DDR3_LRDIMM_ODT_R6_1866 -
	    SPD_DDR3_LRDIMM_ODT_R6_800 + 1,
	    .sp_parse = spd_parse_ddr3_lrdimm_odt_r6 },
	{ .sp_off = SPD_DDR3_LRDIMM_RTT_800,
	    .sp_len = SPD_DDR3_LRDIMM_RTT_1866 - SPD_DDR3_LRDIMM_RTT_800 + 1,
	    .sp_parse = spd_parse_ddr3_lrdimm_rtt },
	{ .sp_off = SPD_DDR3_LRDIMM_MIN_DELAY_1V5,
	    .sp_key = SPD_KEY_DDR3_MOD_MIN_DELAY,
	    .sp_len = SPD_DDR3_LRDIMM_MIN_DELAY_1V25 -
	    SPD_DDR3_LRDIMM_MIN_DELAY_1V5 + 1,
	    .sp_parse = spd_parse_ddr3_lrdimm_mod_delay },
	{ .sp_off = SPD_DDR3_LRDIMM_MAX_DELAY_1V5,
	    .sp_key = SPD_KEY_DDR3_MOD_MAX_DELAY,
	    .sp_len = SPD_DDR3_LRDIMM_MAX_DELAY_1V25 -
	    SPD_DDR3_LRDIMM_MAX_DELAY_1V5 + 1,
	    .sp_parse = spd_parse_ddr3_lrdimm_mod_delay },
	{ .sp_off = SPD_DDR3_LRDIMM_PERS, .sp_key = SPD_KEY_DDR3_MB_PERS,
	    .sp_len = SPD_DDR3_LRDIMM_PERS_NBYTES,
	    .sp_parse = spd_parse_u8_array }
};

static void
spd_parse_ddr3_mod_specific(spd_info_t *si)
{
	uint32_t type;

	if (nvlist_lookup_uint32(si->si_nvl, SPD_KEY_MOD_TYPE, &type) != 0)
		return;

	switch (type) {
	case SPD_MOD_TYPE_UDIMM:
	case SPD_MOD_TYPE_SODIMM:
	case SPD_MOD_TYPE_MICRO_DIMM:
	case SPD_MOD_TYPE_MINI_UDIMM:
	case SPD_MOD_TYPE_16b_SO_DIMM:
	case SPD_MOD_TYPE_32b_SO_DIMM:
	case SPD_MOD_TYPE_72b_SO_UDIMM:
		spd_parse(si, spd_ddr3_udimm, ARRAY_SIZE(spd_ddr3_udimm));
		break;
	case SPD_MOD_TYPE_RDIMM:
	case SPD_MOD_TYPE_MINI_RDIMM:
	case SPD_MOD_TYPE_72b_SO_RDIMM:
		spd_parse(si, spd_ddr3_rdimm, ARRAY_SIZE(spd_ddr3_rdimm));
		break;
	case SPD_MOD_TYPE_72b_SO_CDIMM:
	case SPD_MOD_TYPE_MINI_CDIMM:
		spd_parse(si, spd_ddr3_cdimm, ARRAY_SIZE(spd_ddr3_cdimm));
		break;
	case SPD_MOD_TYPE_LRDIMM:
		spd_parse(si, spd_ddr3_lrdimm, ARRAY_SIZE(spd_ddr3_lrdimm));
		break;
	default:
		break;
	}
}

void
spd_parse_ddr3(spd_info_t *si)
{
	if (SPD_DDR3_SPD_REV_ENC(si->si_data[SPD_DDR3_SPD_REV]) !=
	    SPD_DDR3_SPD_REV_V1) {
		si->si_error = LIBJEDEC_SPD_UNSUP_REV;
		return;
	}

	spd_parse(si, spd_ddr3_common, ARRAY_SIZE(spd_ddr3_common));
	spd_parse_ddr3_mod_specific(si);
	spd_parse(si, spd_ddr3_mfg, ARRAY_SIZE(spd_ddr3_mfg));
}
