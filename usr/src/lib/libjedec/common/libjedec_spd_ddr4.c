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
 * DDR4-specific SPD processing logic. For an overview of the processing design
 * please see libjedec_spd.c. Note, this currently does not handle NVDIMMs.
 */

#include <sys/sysmacros.h>
#include <sys/debug.h>
#include "libjedec_spd.h"

static const spd_value_map_t spd_ddr4_nbytes_used_map[] = {
	{ SPD_DDR4_NBYTES_USED_UNDEF, 0, true },
	{ SPD_DDR4_NBYTES_USED_128, 128, false },
	{ SPD_DDR4_NBYTES_USED_256, 256, false },
	{ SPD_DDR4_NBYTES_USED_384, 384, false },
	{ SPD_DDR4_NBYTES_USED_512, 512, false }
};

static const spd_value_map_t spd_ddr4_nbytes_total_map[] = {
	{ SPD_DDR4_NBYTES_TOTAL_UNDEF, 0, true },
	{ SPD_DDR4_NBYTES_TOTAL_256, 256, false },
	{ SPD_DDR4_NBYTES_TOTAL_512, 512, false }
};

static void
spd_parse_ddr4_nbytes(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t used = SPD_DDR4_NBYTES_USED(data);
	const uint8_t total = SPD_DDR4_NBYTES_TOTAL(data);

	spd_insert_map(si, SPD_KEY_NBYTES_USED, used, spd_ddr4_nbytes_used_map,
	    ARRAY_SIZE(spd_ddr4_nbytes_used_map));
	spd_insert_map(si, SPD_KEY_NBYTES_TOTAL, total,
	    spd_ddr4_nbytes_total_map, ARRAY_SIZE(spd_ddr4_nbytes_total_map));

	/*
	 * Unlike DDR5, there is no specific definition to indicate that the SPD
	 * is present or what type of device it is. There is only one standard
	 * DDR4 EEPROM, EE1004, so we note that it's here when we process this.
	 */
	spd_upsert_flag(si, SPD_KEY_DEVS, SPD_DEVICE_SPD);
	spd_nvl_insert_u32(si, SPD_KEY_DEV_SPD_TYPE, SPD_SPD_T_EE1004);
}

/*
 * DDR4 has a type value that we leave out: SPD_DDR4_MOD_TYPE_TYPE_EXT. The
 * external type says to look in another register; however, all types in that
 * register are reserved. So we just let it be flagged as an unknown value right
 * now. Which is mostly kind of right.
 */
static const spd_value_map_t spd_ddr4_mod_type_map[] = {
	{ SPD_DDR4_MOD_TYPE_TYPE_RDIMM, SPD_MOD_TYPE_RDIMM, false },
	{ SPD_DDR4_MOD_TYPE_TYPE_UDIMM, SPD_MOD_TYPE_UDIMM, false },
	{ SPD_DDR4_MOD_TYPE_TYPE_SODIMM, SPD_MOD_TYPE_SODIMM, false },
	{ SPD_DDR4_MOD_TYPE_TYPE_LRDIMM, SPD_MOD_TYPE_LRDIMM, false },
	{ SPD_DDR4_MOD_TYPE_TYPE_MINI_RDIMM, SPD_MOD_TYPE_MINI_RDIMM, false },
	{ SPD_DDR4_MOD_TYPE_TYPE_MINI_UDIMM, SPD_MOD_TYPE_MINI_UDIMM, false },
	{ SPD_DDR4_MOD_TYPE_TYPE_72b_SORDIMM, SPD_MOD_TYPE_72b_SO_RDIMM,
	    false },
	{ SPD_DDR4_MOD_TYPE_TYPE_72b_SOUDIMM, SPD_MOD_TYPE_72b_SO_UDIMM,
	    false },
	{ SPD_DDR4_MOD_TYPE_TYPE_16b_SODIMM, SPD_MOD_TYPE_16b_SO_DIMM, false },
	{ SPD_DDR4_MOD_TYPE_TYPE_32b_SODIMM, SPD_MOD_TYPE_32b_SO_DIMM, false }
};

static const spd_value_map_t spd_ddr4_mod_is_hybrid_map[] = {
	{ 0, SPD_MOD_NOT_HYBRID, false },
	{ 1, SPD_MOD_HYBRID_NVDIMMM, false }
};

static const spd_value_map_t spd_ddr4_mod_hybrid_map[] = {
	{ SPD_DDR4_MOD_TYPE_HYBRID_NVDIMM_NF, SPD_MOD_TYPE_NVDIMM_N, false },
	{ SPD_DDR4_MOD_TYPE_HYBRID_NVDIMM_P, SPD_MOD_TYPE_NVDIMM_P, false },
	{ SPD_DDR4_MOD_TYPE_HYBRID_NVDIMM_H, SPD_MOD_TYPE_NVDIMM_H, false }
};

static void
spd_parse_ddr4_mod_type(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t type = SPD_DDR4_MOD_TYPE_TYPE(data);
	const uint8_t is_hyb = SPD_DDR4_MOD_TYPE_ISHYBRID(data);
	const uint8_t hybrid = SPD_DDR4_MOD_TYPE_HYBRID(data);

	spd_insert_map(si, SPD_KEY_MOD_HYBRID_TYPE, is_hyb,
	    spd_ddr4_mod_is_hybrid_map, ARRAY_SIZE(spd_ddr4_mod_is_hybrid_map));

	if (is_hyb != 0) {
		spd_insert_map(si, SPD_KEY_MOD_NVDIMM_TYPE, hybrid,
		    spd_ddr4_mod_hybrid_map,
		    ARRAY_SIZE(spd_ddr4_mod_hybrid_map));
	}

	spd_insert_map(si, SPD_KEY_MOD_TYPE, type, spd_ddr4_mod_type_map,
	    ARRAY_SIZE(spd_ddr4_mod_type_map));
}

static const spd_value_map64_t spd_ddr4_density_map[] = {
	{ SPD_DDR4_DENSITY_DENSITY_256Mb, 256ULL * 1024ULL * 1024ULL, false },
	{ SPD_DDR4_DENSITY_DENSITY_512Mb, 512ULL * 1024ULL * 1024ULL, false },
	{ SPD_DDR4_DENSITY_DENSITY_1Gb, 1024ULL * 1024ULL * 1024ULL, false },
	{ SPD_DDR4_DENSITY_DENSITY_2Gb, 2ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_DDR4_DENSITY_DENSITY_4Gb, 4ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_DDR4_DENSITY_DENSITY_8Gb, 8ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_DDR4_DENSITY_DENSITY_16Gb, 16ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_DDR4_DENSITY_DENSITY_32Gb, 32ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_DDR4_DENSITY_DENSITY_12Gb, 12ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_DDR4_DENSITY_DENSITY_24Gb, 24ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
};

static const spd_value_range_t spd_ddr4_nbgrp_range = {
	.svr_max = SPD_DDR4_DENSITY_NBG_BITS_MAX
};

static const spd_value_range_t spd_ddr4_nba_range = {
	.svr_max = SPD_DDR4_DENSITY_NBA_BITS_MAX,
	.svr_base = SPD_DDR4_DENSITY_NBA_BITS_BASE
};

static void
spd_parse_ddr4_density(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t nbg = SPD_DDR4_DENSITY_NBG_BITS(data);
	const uint8_t nbank = SPD_DDR4_DENSITY_NBA_BITS(data);
	const uint8_t dens = SPD_DDR4_DENSITY_DENSITY(data);

	spd_insert_range(si, SPD_KEY_NBGRP_BITS, nbg, &spd_ddr4_nbgrp_range);
	spd_insert_range(si, SPD_KEY_NBANK_BITS, nbank, &spd_ddr4_nba_range);
	spd_insert_map64(si, SPD_KEY_DIE_SIZE, dens, spd_ddr4_density_map,
	    ARRAY_SIZE(spd_ddr4_density_map));
}

static const spd_value_range_t spd_ddr4_nrow_range = {
	.svr_max = SPD_DDR4_ADDR_NROWS_MAX,
	.svr_base = SPD_DDR4_ADDR_NROWS_BASE
};

static const spd_value_range_t spd_ddr4_ncol_range = {
	.svr_max = SPD_DDR4_ADDR_NCOLS_MAX,
	.svr_base = SPD_DDR4_ADDR_NCOLS_BASE
};

static void
spd_parse_ddr4_addr(spd_info_t *si, uint32_t off, uint32_t len, const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t nrows = SPD_DDR4_ADDR_NROWS(data);
	const uint8_t ncols = SPD_DDR4_ADDR_NCOLS(data);

	spd_insert_range(si, SPD_KEY_NROW_BITS, nrows, &spd_ddr4_nrow_range);
	spd_insert_range(si, SPD_KEY_NCOL_BITS, ncols, &spd_ddr4_ncol_range);
}

static const spd_value_map_t spd_ddr4_sl_map[] = {
	{ SPD_DDR4_PKG_SIG_LOAD_UNSPEC, SPD_SL_UNSPECIFIED, false },
	{ SPD_DDR4_PKG_SIG_LOAD_MULTI, SPD_SL_MUTLI_STACK, false },
	{ SPD_DDR4_PKG_SIG_LOAD_SINGLE, SPD_SL_3DS, false }
};

static void
spd_parse_ddr4_pkg_common(spd_info_t *si, uint8_t data, const char *die_key,
    const char *sl_key)
{
	const uint8_t ndie = SPD_DDR4_PKG_DIE_CNT(data) +
	    SPD_DDR4_PKG_DIE_CNT_BASE;
	const uint8_t sl = SPD_DDR4_PKG_SIG_LOAD(data);

	spd_nvl_insert_u32(si, die_key, ndie);
	spd_insert_map(si, sl_key, sl, spd_ddr4_sl_map,
	    ARRAY_SIZE(spd_ddr4_sl_map));
}

static void
spd_parse_ddr4_pri_pkg(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];

	if (SPD_DDR4_PKG_TYPE(data) == SPD_DDR4_PKG_TYPE_NOT) {
		spd_nvl_insert_key(si, SPD_KEY_PKG_NOT_MONO);
	}

	return (spd_parse_ddr4_pkg_common(si, si->si_data[off],
	    SPD_KEY_PKG_NDIE, SPD_KEY_PKG_SL));
}

static void
spd_parse_ddr4_sec_pkg(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(off, >=, SPD_DDR4_PRI_PKG);

	if (SPD_DDR4_PKG_TYPE(si->si_data[SPD_DDR4_PRI_PKG]) ==
	    SPD_DDR4_PKG_TYPE_MONO) {
		return;
	}

	return (spd_parse_ddr4_pkg_common(si, si->si_data[off],
	    SPD_KEY_SEC_PKG_NDIE, SPD_KEY_SEC_PKG_SL));
}

static const spd_value_map_t spd_ddr4_maw_map[] = {
	{ SPD_DDR4_OPT_FEAT_MAW_8192X, 8192, false },
	{ SPD_DDR4_OPT_FEAT_MAW_4096X, 4096, false },
	{ SPD_DDR4_OPT_FEAT_MAW_2048X, 2048, false }
};

static const spd_value_map_t spd_ddr4_mac_map[] = {
	{ SPD_DDR4_OPT_FEAT_MAC_UNTESTED, 0, true},
	{ SPD_DDR4_OPT_FEAT_MAC_700K, 700000, false },
	{ SPD_DDR4_OPT_FEAT_MAC_600K, 600000, false },
	{ SPD_DDR4_OPT_FEAT_MAC_500K, 500000, false },
	{ SPD_DDR4_OPT_FEAT_MAC_400K, 400000, false },
	{ SPD_DDR4_OPT_FEAT_MAC_300K, 300000, false },
	{ SPD_DDR4_OPT_FEAT_MAC_200K, 200000, false },
	{ SPD_DDR4_OPT_FEAT_MAC_UNLIMITED, SPD_KEY_MAC_UNLIMITED, false }
};

static void
spd_parse_ddr4_feat(spd_info_t *si, uint32_t off, uint32_t len, const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t maw = SPD_DDR4_OPT_FEAT_MAW(data);
	const uint8_t mac = SPD_DDR4_OPT_FEAT_MAC(data);

	spd_insert_map(si, SPD_KEY_MAW, maw, spd_ddr4_maw_map,
	    ARRAY_SIZE(spd_ddr4_maw_map));
	spd_insert_map(si, SPD_KEY_MAC, mac, spd_ddr4_mac_map,
	    ARRAY_SIZE(spd_ddr4_mac_map));
}

static void
spd_parse_ddr4_feat2(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t ppr_sup = SPD_DDR4_OPT_FEAT2_PPR(data);
	spd_ppr_flags_t flags = 0;

	switch (ppr_sup) {
	case SPD_DDR4_OPT_FEAT2_PPR_1RPBG:
		spd_nvl_insert_u32(si, SPD_KEY_PPR_GRAN,
		    SPD_PPR_GRAN_BANK_GROUP);
		flags |= SPD_PPR_F_HARD_PPR;
		break;
	case SPD_DDR4_OPT_FEAT2_PPR_NOTSUP:
		/*
		 * No PPR, nothing to do.
		 */
		return;
	default:
		/*
		 * Unknown PPR value.
		 */
		spd_nvl_err(si, SPD_KEY_PPR, SPD_ERROR_NO_XLATE,
		    "encountered unknown value: 0x%x", ppr_sup);
		return;
	}

	if (SPD_DDR4_OPT_FEAT2_SOFT_PPR(data))
		flags |= SPD_PPR_F_SOFT_PPR;
	if (SPD_DDR4_OPT_FEAT2_MBIST_PPR(data))
		flags |= SPD_PPR_F_MBIST_PPR;
	spd_nvl_insert_u32(si, SPD_KEY_PPR, flags);
}

static void
spd_parse_ddr4_volt(spd_info_t *si, uint32_t off, uint32_t len, const char *key)
{
	const uint8_t data = si->si_data[off];
	uint32_t volts[] = { 1200 };

	if (SPD_DDR4_VOLT_V1P2_OPER(data) == 0)
		return;
	spd_nvl_insert_u32_array(si, key, volts, ARRAY_SIZE(volts));
}

static const spd_value_map_t spd_ddr4_dram_width[] = {
	{ SPD_DDR4_MOD_ORG_WIDTH_4b, 4, false },
	{ SPD_DDR4_MOD_ORG_WIDTH_8b, 8, false },
	{ SPD_DDR4_MOD_ORG_WIDTH_16b, 16, false },
	{ SPD_DDR4_MOD_ORG_WIDTH_32b, 32, false }
};

static const spd_value_range_t spd_ddr4_nrank_range = {
	.svr_base = SPD_DDR4_MOD_ORG_NPKG_RANK_BASE
};

static void
spd_parse_ddr4_mod_org(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t mix = SPD_DDR4_MOD_ORG_RANK_MIX(data);
	const uint8_t nranks = SPD_DDR4_MOD_ORG_NPKG_RANK(data);
	const uint8_t width = SPD_DDR4_MOD_ORG_WIDTH(data);

	if (mix == SPD_DDR4_MOD_ORG_RANK_MIX_ASYM)
		spd_nvl_insert_key(si, SPD_KEY_RANK_ASYM);
	spd_insert_range(si, SPD_KEY_NRANKS, nranks, &spd_ddr4_nrank_range);
	spd_insert_map(si, SPD_KEY_DRAM_WIDTH, width, spd_ddr4_dram_width,
	    ARRAY_SIZE(spd_ddr4_dram_width));
}

static const spd_value_map_t spd_ddr4_ext_width[] = {
	{ SPD_DDR4_MOD_BUS_WIDTH_EXT_NONE, 0, false },
	{ SPD_DDR4_MOD_BUS_WIDTH_EXT_8b, 8, false }
};

static const spd_value_map_t spd_ddr4_pri_width[] = {
	{ SPD_DDR4_MOD_BUS_WIDTH_PRI_8b, 8, false },
	{ SPD_DDR4_MOD_BUS_WIDTH_PRI_16b, 16, false },
	{ SPD_DDR4_MOD_BUS_WIDTH_PRI_32b, 32, false },
	{ SPD_DDR4_MOD_BUS_WIDTH_PRI_64b, 64, false },
};

static void
spd_parse_ddr4_bus_width(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t ext = SPD_DDR4_MOD_BUS_WIDTH_EXT(data);
	const uint8_t pri = SPD_DDR4_MOD_BUS_WIDTH_PRI(data);

	/*
	 * DDR4 is simpler than LPDDRx and DDR5. It only has a single channel
	 * and each DRAM is only connected to one channel.
	 */
	spd_nvl_insert_u32(si, SPD_KEY_NSUBCHAN, 1);
	spd_nvl_insert_u32(si, SPD_KEY_DRAM_NCHAN, 1);
	spd_insert_map(si, SPD_KEY_DATA_WIDTH, pri, spd_ddr4_pri_width,
	    ARRAY_SIZE(spd_ddr4_pri_width));
	spd_insert_map(si, SPD_KEY_ECC_WIDTH, ext, spd_ddr4_ext_width,
	    ARRAY_SIZE(spd_ddr4_ext_width));
}

static void
spd_parse_ddr4_therm(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];

	/*
	 * In DDR4, there is only a single standard temperature device. It is
	 * often integrated into the EEPROM, but from a JEDEC perspective these
	 * each have their own device type.
	 */
	if (SPD_DDR4_MOD_THERM_PRES(data) != 0) {
		spd_upsert_flag(si, key, SPD_DEVICE_TEMP_1);
		spd_nvl_insert_u32(si, SPD_KEY_DEV_TEMP_TYPE,
		    SPD_TEMP_T_TSE2004av);
	}
}

static const spd_value_map_t spd_ddr4_ts_mtb[] = {
	{ SPD_DDR4_TIMEBASE_MTB_125ps, SPD_DDR4_MTB_PS, false }
};

static const spd_value_map_t spd_ddr4_ts_ftb[] = {
	{ SPD_DDR4_TIMEBASE_FTB_1ps, SPD_DDR4_FTB_PS, false }
};

static void
spd_parse_ddr4_ts(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t mtb = SPD_DDR4_TIMEBASE_MTB(data);
	const uint8_t ftb = SPD_DDR4_TIMEBASE_FTB(data);


	spd_insert_map(si, SPD_KEY_MTB, mtb, spd_ddr4_ts_mtb,
	    ARRAY_SIZE(spd_ddr4_ts_mtb));
	spd_insert_map(si, SPD_KEY_FTB, ftb, spd_ddr4_ts_ftb,
	    ARRAY_SIZE(spd_ddr4_ts_ftb));
}

/*
 * t~RAS~ consists of the upper nibble at off and the MTB at off + 1.
 */
static void
spd_parse_ddr4_tras(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t ras_nib = SPD_DDR4_RAS_RC_UPPER_RAS(si->si_data[off]);
	ASSERT3U(len, ==, 2);

	return (spd_parse_ddr_time(si, key, ras_nib, si->si_data[off + 1], 0));
}

/*
 * t~RC~ consists of an upper 4-bit nibble at off. Its MTB is at off + 2. The
 * FTB is at off + len - 1.
 */
static void
spd_parse_ddr4_trc(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t rc_nib = SPD_DDR4_RAS_RC_UPPER_RC(si->si_data[off]);

	return (spd_parse_ddr_time(si, key, rc_nib, si->si_data[off + 2],
	    si->si_data[off + len - 1]));
}

/*
 * Upper nibble in off, MTB in off + 1, no FTB.
 */
static void
spd_parse_ddr4_tfaw(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t faw_nib = SPD_DDR4_TFAW_UPPER_FAW(si->si_data[off]);
	return (spd_parse_ddr_time(si, key, faw_nib, si->si_data[off + 1], 0));
}

static void
spd_parse_ddr4_twr(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t twr_nib = SPD_DDR4_TWR_MIN_UPPER_TWR(si->si_data[off]);
	return (spd_parse_ddr_time(si, key, twr_nib, si->si_data[off + 1], 0));
}

static void
spd_parse_ddr4_twtrs(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t twtrs_nib = SPD_DDR4_TWRT_UPPER_TWRS(si->si_data[off]);
	return (spd_parse_ddr_time(si, key, twtrs_nib, si->si_data[off + 1],
	    0));
}

static void
spd_parse_ddr4_twtrl(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t twtrl_nib = SPD_DDR4_TWRT_UPPER_TWRL(si->si_data[off]);
	return (spd_parse_ddr_time(si, key, twtrl_nib, si->si_data[off + 2],
	    0));
}

static void
spd_parse_ddr4_cas(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	uint32_t cas[32] = { 0 };
	uint_t ncas = 0;
	uint32_t cas_base;

	ASSERT3U(len, ==, 4);
	if (SPD_DDR4_CAS_SUP3_RANGE(si->si_data[off + 3]) ==
	    SPD_DDR4_CAS_SUP3_RANGE_7) {
		cas_base = 7;
	} else {
		cas_base = 23;
	}

	for (uint32_t byte = 0; byte < len; byte++) {
		uint32_t data = si->si_data[off + byte];
		uint32_t nbits = NBBY;

		/*
		 * The last byte reserves the last two bits.
		 */
		if (byte == len - 1)
			nbits -= 2;

		for (uint32_t i = 0; i < nbits; i++) {
			if (bitx8(data, i, i) == 1) {
				cas[ncas] = cas_base + i + NBBY * byte;
				ncas++;
			}
		}
	}

	spd_nvl_insert_u32_array(si, key, cas, ncas);
}

static const uint32_t spd_ddr4_nib_map[0x18][0x4] = {
	{ 0, 1, 2, 3 },
	{ 0, 1, 3, 2 },
	{ 0, 2, 1, 3 },
	{ 0, 2, 3, 1 },
	{ 0, 3, 1, 2 },
	{ 0, 3, 2, 1 },
	{ 1, 0, 2, 3 },
	{ 1, 0, 3, 2 },
	{ 1, 2, 0, 3 },
	{ 1, 2, 3, 0 },
	{ 1, 3, 0, 2 },
	{ 1, 3, 2, 0 },
	{ 2, 0, 1, 3 },
	{ 2, 0, 3, 1 },
	{ 2, 1, 0, 3 },
	{ 2, 1, 3, 0 },
	{ 2, 3, 0, 1 },
	{ 2, 3, 1, 0 },
	{ 3, 0, 1, 2 },
	{ 3, 0, 2, 1 },
	{ 3, 1, 0, 2 },
	{ 3, 1, 2, 0 },
	{ 3, 2, 0, 1 },
	{ 3, 2, 1, 0 }
};

/*
 * This function is shared between LPDDR3/4 and DDR4. They have the same values.
 */
void
spd_parse_ddr4_nib_map(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t pkg = SPD_DDR4_MAP_PKG(data);
	const uint8_t nib = SPD_DDR4_MAP_NIBBLE(data);
	uint8_t idx = SPD_DDR4_MAP_IDX(data);
	uint32_t bits[4];

	/*
	 * Because there is only a single legal value we don't make a specific
	 * nvlist key for it; however, if it is incorrect we will complain about
	 * it!
	 */
	if (pkg != SPD_DDR4_MAP_PKG_FLIP) {
		spd_nvl_err(si, key, SPD_ERROR_NO_XLATE,
		    "encountered bad package value: 0x%x", pkg);
	}

	if (idx == SPD_DDR4_MAP_IDX_UNSPEC)
		return;
	idx--;

	if (idx >= ARRAY_SIZE(spd_ddr4_nib_map)) {
		spd_nvl_err(si, key, SPD_ERROR_NO_XLATE,
		    "encountered bad nibble mapping value: 0x%x", idx);
		return;
	}

	if (nib == 1) {
		bits[0] = spd_ddr4_nib_map[idx][0] + 4;
		bits[1] = spd_ddr4_nib_map[idx][1] + 4;
		bits[2] = spd_ddr4_nib_map[idx][2] + 4;
		bits[3] = spd_ddr4_nib_map[idx][3] + 4;
	} else {
		bits[0] = spd_ddr4_nib_map[idx][0];
		bits[1] = spd_ddr4_nib_map[idx][1];
		bits[2] = spd_ddr4_nib_map[idx][2];
		bits[3] = spd_ddr4_nib_map[idx][3];
	};

	spd_nvl_insert_u32_array(si, key, bits, ARRAY_SIZE(bits));
}

static const spd_parse_t spd_ddr4_common[] = {
	{ .sp_off = SPD_DDR4_NBYTES, .sp_parse = spd_parse_ddr4_nbytes },
	{ .sp_off = SPD_DDR4_SPD_REV, .sp_parse = spd_parse_rev },
	/*
	 * We have previously validated that the DRAM type is something that we
	 * understand. We pass through the raw enum to users here.
	 */
	{ .sp_off = SPD_DDR4_DRAM_TYPE, .sp_key = SPD_KEY_DRAM_TYPE,
	    .sp_parse = spd_parse_raw_u8 },
	{ .sp_off = SPD_DDR4_MOD_TYPE, .sp_parse = spd_parse_ddr4_mod_type },
	{ .sp_off = SPD_DDR4_DENSITY, .sp_parse = spd_parse_ddr4_density },
	{ .sp_off = SPD_DDR4_ADDR, .sp_parse = spd_parse_ddr4_addr },
	{ .sp_off = SPD_DDR4_PRI_PKG, .sp_parse = spd_parse_ddr4_pri_pkg },
	{ .sp_off = SPD_DDR4_SEC_PKG, .sp_parse = spd_parse_ddr4_sec_pkg },
	{ .sp_off = SPD_DDR4_OPT_FEAT, .sp_parse = spd_parse_ddr4_feat },
	{ .sp_off = SPD_DDR4_OPT_FEAT2, .sp_parse = spd_parse_ddr4_feat2 },
	{ .sp_off = SPD_DDR4_VOLT, .sp_key = SPD_KEY_NOM_VDD,
	    .sp_parse = spd_parse_ddr4_volt },
	{ .sp_off = SPD_DDR4_MOD_ORG, .sp_parse = spd_parse_ddr4_mod_org },
	{ .sp_off = SPD_DDR4_MOD_BUS_WIDTH,
	    .sp_parse = spd_parse_ddr4_bus_width },
	{ .sp_off = SPD_DDR4_MOD_THERM, .sp_key = SPD_KEY_DEVS,
	    .sp_parse = spd_parse_ddr4_therm },
	/*
	 * Because there is only one set of valid time bases, we assume that
	 * as part of the rest of the time construction.
	 */
	{ .sp_off = SPD_DDR4_TIMEBASE, .sp_parse = spd_parse_ddr4_ts },
	{ .sp_off = SPD_DDR4_TCKAVG_MIN, .sp_key = SPD_KEY_TCKAVG_MIN,
	    .sp_len = SPD_DDR4_TCKAVG_MIN_FINE - SPD_DDR4_TCKAVG_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_DDR4_TCKAVG_MAX, .sp_key = SPD_KEY_TCKAVG_MAX,
	    .sp_len = SPD_DDR4_TCKAVG_MAX_FINE - SPD_DDR4_TCKAVG_MAX + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_DDR4_CAS_SUP0, .sp_key = SPD_KEY_CAS,
	    .sp_len = SPD_DDR4_CAS_SUP3 - SPD_DDR4_CAS_SUP0 + 1,
	    .sp_parse = spd_parse_ddr4_cas },
	{ .sp_off = SPD_DDR4_TAA_MIN, .sp_key = SPD_KEY_TAA_MIN,
	    .sp_len = SPD_DDR4_TAA_MIN_FINE - SPD_DDR4_TAA_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_DDR4_TRCD_MIN, .sp_key = SPD_KEY_TRCD_MIN,
	    .sp_len = SPD_DDR4_TRCD_MIN_FINE - SPD_DDR4_TRCD_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_DDR4_TRP_MIN, .sp_key = SPD_KEY_TRP_MIN,
	    .sp_len = SPD_DDR4_TRP_MIN_FINE - SPD_DDR4_TRP_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_DDR4_RAS_RC_UPPER, .sp_len = 2,
	    .sp_key = SPD_KEY_TRAS_MIN, .sp_parse = spd_parse_ddr4_tras },
	{ .sp_off = SPD_DDR4_RAS_RC_UPPER, .sp_key = SPD_KEY_TRC_MIN,
	    .sp_len = SPD_DDR4_TRC_MIN_FINE - SPD_DDR4_RAS_RC_UPPER + 1,
	    .sp_parse = spd_parse_ddr4_trc },
	{ .sp_off = SPD_DDR4_TRFC1_MIN_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TRFC1_MIN, .sp_parse = spd_parse_mtb_pair },
	{ .sp_off = SPD_DDR4_TRFC2_MIN_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TRFC2_MIN, .sp_parse = spd_parse_mtb_pair },
	{ .sp_off = SPD_DDR4_TRFC4_MIN_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TRFC4_MIN, .sp_parse = spd_parse_mtb_pair },
	{ .sp_off = SPD_DDR4_TFAW_UPPER, .sp_len = 2, .sp_key = SPD_KEY_TFAW,
	    .sp_parse = spd_parse_ddr4_tfaw },
	{ .sp_off = SPD_DDR4_TRRDS_MIN, .sp_key = SPD_KEY_TRRD_S_MIN,
	    .sp_len = SPD_DDR4_TRRDS_MIN_FINE - SPD_DDR4_TRRDS_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_DDR4_TRRDL_MIN, .sp_key = SPD_KEY_TRRD_L_MIN,
	    .sp_len = SPD_DDR4_TRRDL_MIN_FINE - SPD_DDR4_TRRDL_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_DDR4_TCCDL_MIN, .sp_key = SPD_KEY_TCCD_L_MIN,
	    .sp_len = SPD_DDR4_TCCDL_MIN_FINE - SPD_DDR4_TCCDL_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_DDR4_TWR_MIN_UPPER, .sp_len = 2,
	    .sp_key = SPD_KEY_TWR_MIN, .sp_parse = spd_parse_ddr4_twr },
	{ .sp_off = SPD_DDR4_TWRT_UPPER, .sp_len = 2,
	    .sp_key = SPD_KEY_TWTRS_MIN, .sp_parse = spd_parse_ddr4_twtrs },
	{ .sp_off = SPD_DDR4_TWRT_UPPER, .sp_len = 3,
	    .sp_key = SPD_KEY_TWTRL_MIN, .sp_parse = spd_parse_ddr4_twtrl },
	{ .sp_off = SPD_DDR4_MAP_DQ0, .sp_key = SPD_KEY_DDR4_MAP_DQ0,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_DDR4_MAP_DQ4, .sp_key = SPD_KEY_DDR4_MAP_DQ4,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_DDR4_MAP_DQ8, .sp_key = SPD_KEY_DDR4_MAP_DQ8,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_DDR4_MAP_DQ12, .sp_key = SPD_KEY_DDR4_MAP_DQ12,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_DDR4_MAP_DQ16, .sp_key = SPD_KEY_DDR4_MAP_DQ16,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_DDR4_MAP_DQ20, .sp_key = SPD_KEY_DDR4_MAP_DQ20,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_DDR4_MAP_DQ24, .sp_key = SPD_KEY_DDR4_MAP_DQ24,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_DDR4_MAP_DQ28, .sp_key = SPD_KEY_DDR4_MAP_DQ28,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_DDR4_MAP_CB0, .sp_key = SPD_KEY_DDR4_MAP_CB0,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_DDR4_MAP_CB4, .sp_key = SPD_KEY_DDR4_MAP_CB4,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_DDR4_MAP_DQ32, .sp_key = SPD_KEY_DDR4_MAP_DQ32,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_DDR4_MAP_DQ36, .sp_key = SPD_KEY_DDR4_MAP_DQ36,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_DDR4_MAP_DQ40, .sp_key = SPD_KEY_DDR4_MAP_DQ40,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_DDR4_MAP_DQ44, .sp_key = SPD_KEY_DDR4_MAP_DQ44,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_DDR4_MAP_DQ48, .sp_key = SPD_KEY_DDR4_MAP_DQ48,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_DDR4_MAP_DQ52, .sp_key = SPD_KEY_DDR4_MAP_DQ52,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_DDR4_MAP_DQ56, .sp_key = SPD_KEY_DDR4_MAP_DQ56,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_DDR4_MAP_DQ60, .sp_key = SPD_KEY_DDR4_MAP_DQ60,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_len = SPD_DDR4_CRC_MSB + 1, .sp_key = SPD_KEY_CRC_DDR4_BASE,
	    .sp_parse = spd_parse_crc },
};

static const spd_parse_t spd_ddr4_mfg[] = {
	{ .sp_off = SPD_DDR4_MOD_MFG_ID0, .sp_len = 2,
	    .sp_key = SPD_KEY_MFG_MOD_MFG_ID,
	    .sp_parse = spd_parse_jedec_id },
	{ .sp_off = SPD_DDR4_MOD_MFG_ID0, .sp_len = 2,
	    .sp_key = SPD_KEY_MFG_MOD_MFG_NAME,
	    .sp_parse = spd_parse_jedec_id_str },
	{ .sp_off = SPD_DDR4_DRAM_MFG_ID0, .sp_len = 2,
	    .sp_key = SPD_KEY_MFG_DRAM_MFG_ID,
	    .sp_parse = spd_parse_jedec_id },
	{ .sp_off = SPD_DDR4_DRAM_MFG_ID0, .sp_len = 2,
	    .sp_key = SPD_KEY_MFG_DRAM_MFG_NAME,
	    .sp_parse = spd_parse_jedec_id_str },
	{ .sp_off = SPD_DDR4_MOD_MFG_LOC, .sp_key = SPD_KEY_MFG_MOD_LOC_ID,
	    .sp_parse = spd_parse_raw_u8 },
	{ .sp_off = SPD_DDR4_MOD_MFG_YEAR, .sp_key = SPD_KEY_MFG_MOD_YEAR,
	    .sp_parse = spd_parse_hex_string },
	{ .sp_off = SPD_DDR4_MOD_MFG_WEEK, .sp_key = SPD_KEY_MFG_MOD_WEEK,
	    .sp_parse = spd_parse_hex_string },
	{ .sp_off = SPD_DDR4_MOD_SN, .sp_len = SPD_DDR4_MOD_SN_LEN,
	    .sp_key = SPD_KEY_MFG_MOD_SN, .sp_parse = spd_parse_hex_string },
	{ .sp_off = SPD_DDR4_MOD_PN, .sp_len = SPD_DDR4_MOD_PN_LEN,
	    .sp_key = SPD_KEY_MFG_MOD_PN, .sp_parse = spd_parse_string },
	{ .sp_off = SPD_DDR4_MOD_REV, .sp_key = SPD_KEY_MFG_MOD_REV,
	    .sp_parse = spd_parse_dram_step },
	{ .sp_off = SPD_DDR4_DRAM_STEP, .sp_key = SPD_KEY_MFG_DRAM_STEP,
	    .sp_parse = spd_parse_dram_step },
};

/*
 * The offsets and values for design information are identical across DDR4 and
 * the LPDDR3/4/4X SPD data.
 */
void
spd_parse_ddr4_design(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(off, >=, SPD_DDR4_RDIMM_HEIGHT);
	return (spd_parse_design(si, off, SPD_DDR4_RDIMM_HEIGHT));
}

static void
spd_parse_ddr4_edge(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];

	if (SPD_DDR4_RDIMM_MAP_R1(data) != 0)
		spd_nvl_insert_key(si, SPD_KEY_MOD_EDGE_MIRROR);
}

/*
 * DDR4 UDIMM specific processing.
 */
static const spd_parse_t spd_ddr4_udimm[] = {
	{ .sp_off = SPD_DDR4_UDIMM_HEIGHT, .sp_key = SPD_KEY_MOD_HEIGHT,
	    .sp_parse = spd_parse_height },
	{ .sp_off = SPD_DDR4_UDIMM_THICK, .sp_parse = spd_parse_thickness },
	{ .sp_off = SPD_DDR4_UDIMM_REF, .sp_parse = spd_parse_ddr4_design },
	{ .sp_off = SPD_DDR4_UDIMM_MAP, .sp_parse = spd_parse_ddr4_edge },
	{ .sp_off = SPD_DDR4_BLK1_CRC_START, .sp_len = SPD_DDR4_BLK1_CRC_MSB +
	    1 - SPD_DDR4_BLK1_CRC_START, .sp_key = SPD_KEY_CRC_DDR4_BLK1,
	    .sp_parse = spd_parse_crc }
};

/*
 * DDR4 RDIMM specific processing.
 */
static const spd_value_map_t spd_ddr4_rcd_type_map[] = {
	{ SPD_DDR4_RDIMM_ATTR_TYPE_RCD01, SPD_RCD_T_DDR4RCD01, false },
	{ SPD_DDR4_RDIMM_ATTR_TYPE_RCD02, SPD_RCD_T_DDR4RCD02, false },
};

static void
spd_parse_ddr4_rdimm_attr(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t rcd = SPD_DDR4_RDIMM_ATTR_TYPE(data);
	const uint8_t nrow = 1 << (SPD_DDR4_RDIMM_ATTR_NROWS(data) - 1);
	const uint8_t nreg = 1 << (SPD_DDR4_RDIMM_ATTR_NREGS(data) - 1);

	spd_upsert_flag(si, SPD_KEY_DEVS, SPD_DEVICE_RCD);
	spd_insert_map(si, SPD_KEY_DEV_RCD_TYPE, rcd,
	    spd_ddr4_rcd_type_map, ARRAY_SIZE(spd_ddr4_rcd_type_map));
	if (nrow != 0)
		spd_nvl_insert_u32(si, SPD_KEY_MOD_NROWS, nrow);
	if (nreg != 0)
		spd_nvl_insert_u32(si, SPD_KEY_MOD_NREGS, nreg);
}

static void
spd_parse_ddr4_rdimm_therm(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];

	if (SPD_DDR4_RDIMM_THERM_IMPL(data) != 0)
		spd_upsert_flag(si, SPD_KEY_DEVS, SPD_DEVICE_HS);
}

static void
spd_parse_ddr4_rdimm_rcd_mfg(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 2);

	spd_parse_jedec_id(si, off, 2, SPD_KEY_DEV_RCD_MFG);
	spd_parse_jedec_id_str(si, off, 2, SPD_KEY_DEV_RCD_MFG_NAME);
}

static const spd_value_map_t spd_ddr4_rdimm_ods_map[] = {
	{ SPD_DDR4_RDIMM_ODS0_LIGHT, SPD_DRIVE_LIGHT, false },
	{ SPD_DDR4_RDIMM_ODS0_MODERATE, SPD_DRIVE_MODERATE, false },
	{ SPD_DDR4_RDIMM_ODS0_STRONG, SPD_DRIVE_STRONG, false },
	{ SPD_DDR4_RDIMM_ODS0_VERY_STRONG, SPD_DRIVE_VERY_STRONG, false },
};

static void
spd_parse_ddr4_rdimm_ods(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t ods0 = si->si_data[off];
	const uint8_t ods1 = si->si_data[off + 1];
	const uint8_t cs = SPD_DDR4_RDIMM_ODS0_CS(ods0);
	const uint8_t ca = SPD_DDR4_RDIMM_ODS0_CA(ods0);
	const uint8_t odt = SPD_DDR4_RDIMM_ODS0_ODT(ods0);
	const uint8_t cke = SPD_DDR4_RDIMM_ODS0_CKE(ods0);
	const uint8_t y1 = SPD_DDR4_RDIMM_ODS1_Y1(ods1);
	const uint8_t y0 = SPD_DDR4_RDIMM_ODS1_Y0(ods1);

	spd_insert_map(si, SPD_KEY_DDR4_RCD_DS_CKE, cke, spd_ddr4_rdimm_ods_map,
	    ARRAY_SIZE(spd_ddr4_rdimm_ods_map));
	spd_insert_map(si, SPD_KEY_DDR4_RCD_DS_ODT, odt, spd_ddr4_rdimm_ods_map,
	    ARRAY_SIZE(spd_ddr4_rdimm_ods_map));
	spd_insert_map(si, SPD_KEY_DDR4_RCD_DS_CA, ca, spd_ddr4_rdimm_ods_map,
	    ARRAY_SIZE(spd_ddr4_rdimm_ods_map));
	spd_insert_map(si, SPD_KEY_DDR4_RCD_DS_CS, cs, spd_ddr4_rdimm_ods_map,
	    ARRAY_SIZE(spd_ddr4_rdimm_ods_map));
	spd_insert_map(si, SPD_KEY_DDR4_RCD_DS_Y0, y0, spd_ddr4_rdimm_ods_map,
	    ARRAY_SIZE(spd_ddr4_rdimm_ods_map));
	spd_insert_map(si, SPD_KEY_DDR4_RCD_DS_Y1, y1, spd_ddr4_rdimm_ods_map,
	    ARRAY_SIZE(spd_ddr4_rdimm_ods_map));

	if (SPD_DDR4_RDIMM_ODS1_SLEW_SUP(ods1) != 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR4_RCD_SLEW);
}

static const spd_parse_t spd_ddr4_rdimm[] = {
	{ .sp_off = SPD_DDR4_RDIMM_HEIGHT, .sp_key = SPD_KEY_MOD_HEIGHT,
	    .sp_parse = spd_parse_height },
	{ .sp_off = SPD_DDR4_RDIMM_THICK, .sp_parse = spd_parse_thickness },
	{ .sp_off = SPD_DDR4_RDIMM_REF, .sp_parse = spd_parse_ddr4_design },
	{ .sp_off = SPD_DDR4_RDIMM_ATTR,
	    .sp_parse = spd_parse_ddr4_rdimm_attr },
	{ .sp_off = SPD_DDR4_RDIMM_THERM,
	    .sp_parse = spd_parse_ddr4_rdimm_therm },
	{ .sp_off = SPD_DDR4_RDIMM_REG_MFG_ID0, .sp_len = 2,
	    .sp_parse = spd_parse_ddr4_rdimm_rcd_mfg },
	{ .sp_off = SPD_DDR4_RDIMM_REV, .sp_key = SPD_KEY_DEV_RCD_REV,
	    .sp_parse = spd_parse_dram_step },
	{ .sp_off = SPD_DDR4_RDIMM_MAP, .sp_parse = spd_parse_ddr4_edge },
	{ .sp_off = SPD_DDR4_RDIMM_ODS0, .sp_len = 2,
	    .sp_parse = spd_parse_ddr4_rdimm_ods },
	{ .sp_off = SPD_DDR4_BLK1_CRC_START, .sp_len = SPD_DDR4_BLK1_CRC_MSB +
	    1 - SPD_DDR4_BLK1_CRC_START, .sp_key = SPD_KEY_CRC_DDR4_BLK1,
	    .sp_parse = spd_parse_crc }
};

/*
 * DDR4 LRDIMM specific processing.
 */
static const spd_value_map_t spd_ddr4_db_type_map[] = {
	{ SPD_DDR4_LRDIMM_ATTR_TYPE_RCD01_DB01, SPD_RCD_T_DDR4RCD01, false },
	{ SPD_DDR4_LRDIMM_ATTR_TYPE_RCD02_DB02, SPD_RCD_T_DDR4RCD02, false },
};

/*
 * We use value maps for these LRDIMM properties because they're a bit
 * inconsistent and this gets us out of a lot of if statements. The RDIMM code
 * doesn't have this problem because all of the values are valid.
 */
static const spd_value_map_t spd_ddr4_lrdimm_nrows_map[] = {
	{ 0, 0, true },
	{ 1, 1, false },
	{ 2, 2, false }
};

static const spd_value_map_t spd_ddr4_lrdimm_nregs_map[] = {
	{ 0, 0, true },
	{ 1, 1, false }
};

static void
spd_parse_ddr4_lrdimm_attr(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t rcd = SPD_DDR4_LRDIMM_ATTR_TYPE(data);
	const uint8_t nrow = SPD_DDR4_LRDIMM_ATTR_NROWS(data);
	const uint8_t nreg = SPD_DDR4_LRDIMM_ATTR_NREGS(data);

	/*
	 * The type defines both the RCD and the DB. The RCD types overlap with
	 * RDIMMs.
	 */
	spd_upsert_flag(si, SPD_KEY_DEVS, SPD_DEVICE_RCD | SPD_DEVICE_DB);
	spd_insert_map(si, SPD_KEY_DEV_RCD_TYPE, rcd,
	    spd_ddr4_rcd_type_map, ARRAY_SIZE(spd_ddr4_rcd_type_map));
	spd_insert_map(si, SPD_KEY_DEV_DB_TYPE, rcd,
	    spd_ddr4_db_type_map, ARRAY_SIZE(spd_ddr4_db_type_map));
	spd_insert_map(si, SPD_KEY_MOD_NROWS, nrow, spd_ddr4_lrdimm_nrows_map,
	    ARRAY_SIZE(spd_ddr4_lrdimm_nrows_map));
	spd_insert_map(si, SPD_KEY_MOD_NREGS, nreg, spd_ddr4_lrdimm_nregs_map,
	    ARRAY_SIZE(spd_ddr4_lrdimm_nregs_map));
}

/*
 * The LRDIMM manufacturer here covers both the register and the data buffer, so
 * we end up setting the same values for both.
 */
static void
spd_parse_ddr4_lrdimm_rcd_mfg(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 2);

	spd_parse_jedec_id(si, off, 2, SPD_KEY_DEV_RCD_MFG);
	spd_parse_jedec_id_str(si, off, 2, SPD_KEY_DEV_RCD_MFG_NAME);
	spd_parse_jedec_id(si, off, 2, SPD_KEY_DEV_DB_MFG);
	spd_parse_jedec_id_str(si, off, 2, SPD_KEY_DEV_DB_MFG_NAME);
}

static const spd_value_map_t spd_ddr4_lrdimm_ods_map[] = {
	{ SPD_DDR4_LRDIMM_ODS1_MODERATE, SPD_DRIVE_MODERATE, false },
	{ SPD_DDR4_LRDIMM_ODS1_STRONG, SPD_DRIVE_STRONG, false }
};

static void
spd_parse_ddr4_lrdimm_ods(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t bck = SPD_DDR4_LRDIMM_ODS1_BCK(data);
	const uint8_t bcom = SPD_DDR4_LRDIMM_ODS1_BCOM(data);

	spd_insert_map(si, SPD_KEY_DDR4_RCD_DS_BCOM, bcom,
	    spd_ddr4_lrdimm_ods_map, ARRAY_SIZE(spd_ddr4_lrdimm_ods_map));
	spd_insert_map(si, SPD_KEY_DDR4_RCD_DS_BCK, bck,
	    spd_ddr4_lrdimm_ods_map, ARRAY_SIZE(spd_ddr4_lrdimm_ods_map));
}

/*
 * There are two VrefDQ ranges in the DDR4 specs. These all increase at 0.65%
 * increments, hence our mult as 65.
 */
static const spd_value_range_t spd_ddr4_vrefdq1_range = {
	.svr_base = 6000,
	.svr_mult = 65,
	.svr_max = 9250
};

static const spd_value_range_t spd_ddr4_vrefdq2_range = {
	.svr_base = 4500,
	.svr_mult = 65,
	.svr_max = 7750
};

static void
spd_parse_ddr4_vrefdq_common(spd_info_t *si, uint8_t range, uint8_t val,
    const char *key)
{
	if (range == SPD_DDR4_LRDIMM_VERFDQ_RNG_1) {
		spd_insert_range(si, key, val, &spd_ddr4_vrefdq1_range);
	} else {
		ASSERT3U(range, ==, SPD_DDR4_LRDIMM_VERFDQ_RNG_2);
		spd_insert_range(si, key, val, &spd_ddr4_vrefdq2_range);
	}
}

static void
spd_parse_ddr4_lrdimm_vrefdq_r0(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t volt = SPD_DDR4_LRDIMM_VREFDQ_V(data);
	const uint8_t range = si->si_data[off + len - 1];

	spd_parse_ddr4_vrefdq_common(si, SPD_DDR4_LRDIMM_VREFDQ_RNG_R0(range),
	    volt, key);
}

static void
spd_parse_ddr4_lrdimm_vrefdq_r1(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t volt = SPD_DDR4_LRDIMM_VREFDQ_V(data);
	const uint8_t range = si->si_data[off + len];

	spd_parse_ddr4_vrefdq_common(si, SPD_DDR4_LRDIMM_VREFDQ_RNG_R1(range),
	    volt, key);
}

static void
spd_parse_ddr4_lrdimm_vrefdq_r2(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t volt = SPD_DDR4_LRDIMM_VREFDQ_V(data);
	const uint8_t range = si->si_data[off + len];

	spd_parse_ddr4_vrefdq_common(si, SPD_DDR4_LRDIMM_VREFDQ_RNG_R2(range),
	    volt, key);
}

static void
spd_parse_ddr4_lrdimm_vrefdq_r3(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t volt = SPD_DDR4_LRDIMM_VREFDQ_V(data);
	const uint8_t range = si->si_data[off + len];

	spd_parse_ddr4_vrefdq_common(si, SPD_DDR4_LRDIMM_VREFDQ_RNG_R3(range),
	    volt, key);
}

static void
spd_parse_ddr4_lrdimm_vrefdq_db(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t range = si->si_data[off + len];

	spd_parse_ddr4_vrefdq_common(si, SPD_DDR4_LRDIMM_VREFDQ_RNG_DB(range),
	    data, key);
}

static const spd_value_map_t spd_ddr4_mdq_ds_map[] = {
	{ SPD_DDR4_LRDIMM_MDQ_DS_40R, 40, false },
	{ SPD_DDR4_LRDIMM_MDQ_DS_34R, 34, false },
	{ SPD_DDR4_LRDIMM_MDQ_DS_48R, 48, false },
	{ SPD_DDR4_LRDIMM_MDQ_DS_60R, 60, false }
};

static const spd_value_map_t spd_ddr4_rtt_map[] = {
	{ SPD_DDR4_LRDIMM_MDQ_RTT_DIS, SPD_TERM_DISABLED, false },
	{ SPD_DDR4_LRDIMM_MDQ_RTT_60R, 60, false },
	{ SPD_DDR4_LRDIMM_MDQ_RTT_120R, 120, false },
	{ SPD_DDR4_LRDIMM_MDQ_RTT_40R, 40, false },
	{ SPD_DDR4_LRDIMM_MDQ_RTT_240R, 240, false },
	{ SPD_DDR4_LRDIMM_MDQ_RTT_48R, 48, false },
	{ SPD_DDR4_LRDIMM_MDQ_RTT_80R, 80, false },
	{ SPD_DDR4_LRDIMM_MDQ_RTT_34R, 34, false },
};

static void
spd_parse_ddr4_lrdimm_mdq(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t d1866 = si->si_data[off];
	const uint8_t d2400 = si->si_data[off + 1];
	const uint8_t d3200 = si->si_data[off + 2];
	const uint8_t rtt[3] = { SPD_DDR4_LRDIMM_MDQ_RTT(d1866),
	    SPD_DDR4_LRDIMM_MDQ_RTT(d2400), SPD_DDR4_LRDIMM_MDQ_RTT(d3200) };
	const uint8_t ds[3] = { SPD_DDR4_LRDIMM_MDQ_DS(d1866),
	    SPD_DDR4_LRDIMM_MDQ_DS(d2400), SPD_DDR4_LRDIMM_MDQ_DS(d3200) };

	spd_insert_map_array(si, SPD_KEY_DDR4_MDQ_RTT, rtt, ARRAY_SIZE(rtt),
	    spd_ddr4_rtt_map, ARRAY_SIZE(spd_ddr4_rtt_map));
	spd_insert_map_array(si, SPD_KEY_DDR4_MDQ_DS, ds, ARRAY_SIZE(ds),
	    spd_ddr4_mdq_ds_map, ARRAY_SIZE(spd_ddr4_mdq_ds_map));
}

static const spd_value_map_t spd_ddr4_dram_ds_map[] = {
	{ SPD_DDR4_LRDIMM_DRAM_DS_34R, 34, false },
	{ SPD_DDR4_LRDIMM_DRAM_DS_48R, 48, false }
};

static void
spd_parse_ddr4_lrdimm_dram(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t ds[3] = {
		SPD_DDR4_LRDIMM_DRAM_DS_1866(data),
		SPD_DDR4_LRDIMM_DRAM_DS_2400(data),
		SPD_DDR4_LRDIMM_DRAM_DS_3200(data)
	};

	spd_insert_map_array(si, SPD_KEY_DDR4_DRAM_DS, ds, ARRAY_SIZE(ds),
	    spd_ddr4_dram_ds_map, ARRAY_SIZE(spd_ddr4_dram_ds_map));
}

static const spd_value_map_t spd_ddr4_rtt_wr_map[] = {
	{ SPD_DDR4_LRDIMM_ODT_WR_DYN_OFF, SPD_TERM_DISABLED, false },
	{ SPD_DDR4_LRDIMM_ODT_WR_120R, 120, false },
	{ SPD_DDR4_LRDIMM_ODT_WR_240R, 240, false },
	{ SPD_DDR4_LRDIMM_ODT_WR_HIZ, SPD_TERM_HIZ, false },
	{ SPD_DDR4_LRDIMM_ODT_WR_80R, 80, false },
};

static void
spd_parse_ddr4_lrdimm_odt(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t d1866 = si->si_data[off];
	const uint8_t d2400 = si->si_data[off + 1];
	const uint8_t d3200 = si->si_data[off + 2];
	const uint8_t nom[3] = { SPD_DDR4_LRDIMM_ODT_NOM(d1866),
	    SPD_DDR4_LRDIMM_ODT_NOM(d2400), SPD_DDR4_LRDIMM_ODT_NOM(d3200) };
	const uint8_t wr[3] = { SPD_DDR4_LRDIMM_ODT_WR(d1866),
	    SPD_DDR4_LRDIMM_ODT_WR(d2400), SPD_DDR4_LRDIMM_ODT_WR(d3200) };

	spd_insert_map_array(si, SPD_KEY_DDR4_RTT_NOM, nom, ARRAY_SIZE(nom),
	    spd_ddr4_rtt_map, ARRAY_SIZE(spd_ddr4_rtt_map));
	spd_insert_map_array(si, SPD_KEY_DDR4_RTT_WR, wr, ARRAY_SIZE(wr),
	    spd_ddr4_rtt_wr_map, ARRAY_SIZE(spd_ddr4_rtt_wr_map));
}

static void
spd_parse_ddr4_lrdimm_park(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t d1866 = si->si_data[off];
	const uint8_t d2400 = si->si_data[off + 1];
	const uint8_t d3200 = si->si_data[off + 2];
	const uint8_t r01[3] = { SPD_DDR4_LRDIMM_PARK_R01(d1866),
	    SPD_DDR4_LRDIMM_PARK_R01(d2400), SPD_DDR4_LRDIMM_PARK_R01(d3200) };
	const uint8_t r23[3] = { SPD_DDR4_LRDIMM_PARK_R23(d1866),
	    SPD_DDR4_LRDIMM_PARK_R23(d2400), SPD_DDR4_LRDIMM_PARK_R23(d3200) };

	spd_insert_map_array(si, SPD_KEY_DDR4_RTT_PARK_R0, r01, ARRAY_SIZE(r01),
	    spd_ddr4_rtt_map, ARRAY_SIZE(spd_ddr4_rtt_map));
	spd_insert_map_array(si, SPD_KEY_DDR4_RTT_PARK_R2, r23, ARRAY_SIZE(r23),
	    spd_ddr4_rtt_map, ARRAY_SIZE(spd_ddr4_rtt_map));
}

static void
spd_parse_ddr4_lrdimm_dfe(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];

	if (SPD_DDR4_LRDIMM_EQ_DFE_SUP(data) != 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR4_DB_DFE);
	if (SPD_DDR4_LRDIMM_EQ_GA_SUP(data) != 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR4_DB_GAIN);
}

static const spd_parse_t spd_ddr4_lrdimm[] = {
	{ .sp_off = SPD_DDR4_LRDIMM_HEIGHT, .sp_key = SPD_KEY_MOD_HEIGHT,
	    .sp_parse = spd_parse_height },
	{ .sp_off = SPD_DDR4_LRDIMM_THICK, .sp_parse = spd_parse_thickness },
	{ .sp_off = SPD_DDR4_LRDIMM_REF, .sp_parse = spd_parse_ddr4_design },
	{ .sp_off = SPD_DDR4_LRDIMM_ATTR,
	    .sp_parse = spd_parse_ddr4_lrdimm_attr },
	{ .sp_off = SPD_DDR4_LRDIMM_THERM,
	    .sp_parse = spd_parse_ddr4_rdimm_therm },
	{ .sp_off = SPD_DDR4_LRDIMM_REG_MFG_ID0, .sp_len = 2,
	    .sp_parse = spd_parse_ddr4_lrdimm_rcd_mfg },
	{ .sp_off = SPD_DDR4_LRDIMM_REV, .sp_key = SPD_KEY_DEV_RCD_REV,
	    .sp_parse = spd_parse_dram_step },
	{ .sp_off = SPD_DDR4_LRDIMM_MAP, .sp_parse = spd_parse_ddr4_edge },
	/*
	 * The LRDIMM output drive strength is equivalent to the RDIMM, so we
	 * use that. For ODS1, we fire it a second-time to get just the
	 * LRDIMM-specific fields.
	 */
	{ .sp_off = SPD_DDR4_LRDIMM_ODS0, .sp_len = 2,
	    .sp_parse = spd_parse_ddr4_rdimm_ods },
	{ .sp_off = SPD_DDR4_LRDIMM_ODS1,
	    .sp_parse = spd_parse_ddr4_lrdimm_ods },
	{ .sp_off = SPD_DDR4_LRDIMM_DB_REV,  .sp_key = SPD_KEY_DEV_DB_REV,
	    .sp_parse = spd_parse_dram_step },
	/*
	 * The five VrefDQ values (four ranks and data buffer) require the range
	 * byte to determine which base set of values to use. This is why they
	 * all have the long length to ensure we account for that.
	 */
	{ .sp_off = SPD_DDR4_LRDIMM_VREFDQ0, .sp_key = SPD_KEY_DDR4_VREFDQ_R0,
	    .sp_len = SPD_DDR4_LRDIMM_VREFDQ_RNG - SPD_DDR4_LRDIMM_VREFDQ0 + 1,
	    .sp_parse = spd_parse_ddr4_lrdimm_vrefdq_r0 },
	{ .sp_off = SPD_DDR4_LRDIMM_VREFDQ1, .sp_key = SPD_KEY_DDR4_VREFDQ_R1,
	    .sp_len = SPD_DDR4_LRDIMM_VREFDQ_RNG - SPD_DDR4_LRDIMM_VREFDQ1 + 1,
	    .sp_parse = spd_parse_ddr4_lrdimm_vrefdq_r1 },

	{ .sp_off = SPD_DDR4_LRDIMM_VREFDQ2, .sp_key = SPD_KEY_DDR4_VREFDQ_R2,
	    .sp_len = SPD_DDR4_LRDIMM_VREFDQ_RNG - SPD_DDR4_LRDIMM_VREFDQ2 + 1,
	    .sp_parse = spd_parse_ddr4_lrdimm_vrefdq_r2 },

	{ .sp_off = SPD_DDR4_LRDIMM_VREFDQ3, .sp_key = SPD_KEY_DDR4_VREFDQ_R3,
	    .sp_len = SPD_DDR4_LRDIMM_VREFDQ_RNG - SPD_DDR4_LRDIMM_VREFDQ3 + 1,
	    .sp_parse = spd_parse_ddr4_lrdimm_vrefdq_r3 },

	{ .sp_off = SPD_DDR4_LRDIMM_VREFDQ_DB, .sp_key = SPD_KEY_DDR4_VREFDQ_DB,
	    .sp_len = SPD_DDR4_LRDIMM_VREFDQ_RNG - SPD_DDR4_LRDIMM_VREFDQ_DB +
	    1, .sp_parse = spd_parse_ddr4_lrdimm_vrefdq_db },
	{ .sp_off = SPD_DDR4_LRDIMM_MDQ_1866, .sp_len = 3,
	    .sp_parse = spd_parse_ddr4_lrdimm_mdq },
	{ .sp_off = SPD_DDR4_LRDIMM_DRAM_DS,
	    .sp_parse = spd_parse_ddr4_lrdimm_dram },
	{ .sp_off = SPD_DDR4_LRDIMM_ODT_1866, .sp_len = 3,
	    .sp_parse = spd_parse_ddr4_lrdimm_odt },
	{ .sp_off = SPD_DDR4_LRDIMM_PARK_1866, .sp_len = 3,
	    .sp_parse = spd_parse_ddr4_lrdimm_park },
	{ .sp_off = SPD_DDR4_LRDIMM_EQ, .sp_parse = spd_parse_ddr4_lrdimm_dfe },
	{ .sp_off = SPD_DDR4_BLK1_CRC_START, .sp_len = SPD_DDR4_BLK1_CRC_MSB +
	    1 - SPD_DDR4_BLK1_CRC_START, .sp_key = SPD_KEY_CRC_DDR4_BLK1,
	    .sp_parse = spd_parse_crc }
};

static void
spd_parse_ddr4_mod_specific(spd_info_t *si)
{
	uint32_t type;

	if (nvlist_lookup_uint32(si->si_nvl, SPD_KEY_MOD_TYPE, &type) != 0)
		return;

	switch (type) {
	case SPD_MOD_TYPE_RDIMM:
	case SPD_MOD_TYPE_MINI_RDIMM:
	case SPD_MOD_TYPE_72b_SO_RDIMM:
		spd_parse(si, spd_ddr4_rdimm, ARRAY_SIZE(spd_ddr4_rdimm));
		break;
	case SPD_MOD_TYPE_LRDIMM:
		spd_parse(si, spd_ddr4_lrdimm, ARRAY_SIZE(spd_ddr4_lrdimm));
		break;
	case SPD_MOD_TYPE_UDIMM:
	case SPD_MOD_TYPE_SODIMM:
	case SPD_MOD_TYPE_MINI_UDIMM:
	case SPD_MOD_TYPE_72b_SO_UDIMM:
	case SPD_MOD_TYPE_16b_SO_DIMM:
	case SPD_MOD_TYPE_32b_SO_DIMM:
		spd_parse(si, spd_ddr4_udimm, ARRAY_SIZE(spd_ddr4_udimm));
		break;
	default:
		break;
	}
}

void
spd_parse_ddr4_mfg(spd_info_t *si)
{
	spd_parse(si, spd_ddr4_mfg, ARRAY_SIZE(spd_ddr4_mfg));
}

/*
 * DDR4 processing.
 *
 *  1. Check that we know the encoding revision of the SPD.
 *  2. Capture the SPD module type information as we already have the dram type
 *     information.
 *  3. Attempt to parse everything. Note that we don't really use the device's
 *     notion of how much data should be present and only will attempt to parse
 *     regions if we have enough data from the user.
 */
void
spd_parse_ddr4(spd_info_t *si)
{
	if (SPD_DDR4_SPD_REV_ENC(si->si_data[SPD_DDR4_SPD_REV]) !=
	    SPD_DDR4_SPD_REV_V1) {
		si->si_error = LIBJEDEC_SPD_UNSUP_REV;
		return;
	}

	/*
	 * Parse DDR4 common attributes. Some overlay information. Then go
	 * through and do the manufacturing info.
	 */
	spd_parse(si, spd_ddr4_common, ARRAY_SIZE(spd_ddr4_common));
	spd_parse_ddr4_mod_specific(si);
	spd_parse_ddr4_mfg(si);
}
