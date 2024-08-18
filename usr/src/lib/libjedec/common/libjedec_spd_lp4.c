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
 * LPDDR4, LPDDR4X, and LPDDR3 SPD processing logic. For an overview of the
 * processing design please see libjedec_spd.c. These have a similar design to
 * DDR4 and leverages the existing manufacturing logic there.
 */

#include <sys/sysmacros.h>
#include <sys/debug.h>
#include "libjedec_spd.h"

static const spd_value_map_t spd_lp4_nbytes_used_map[] = {
	{ SPD_LP4_NBYTES_USED_UNDEF, 0, true },
	{ SPD_LP4_NBYTES_USED_128, 128, false },
	{ SPD_LP4_NBYTES_USED_256, 256, false },
	{ SPD_LP4_NBYTES_USED_384, 384, false },
	{ SPD_LP4_NBYTES_USED_512, 512, false }
};

static const spd_value_map_t spd_lp4_nbytes_total_map[] = {
	{ SPD_LP4_NBYTES_TOTAL_UNDEF, 0, true },
	{ SPD_LP4_NBYTES_TOTAL_256, 256, false },
	{ SPD_LP4_NBYTES_TOTAL_512, 512, false }
};

static void
spd_parse_lp4_nbytes(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t used = SPD_LP4_NBYTES_USED(data);
	const uint8_t total = SPD_LP4_NBYTES_TOTAL(data);

	spd_insert_map(si, SPD_KEY_NBYTES_USED, used, spd_lp4_nbytes_used_map,
	    ARRAY_SIZE(spd_lp4_nbytes_used_map));
	spd_insert_map(si, SPD_KEY_NBYTES_TOTAL, total,
	    spd_lp4_nbytes_total_map, ARRAY_SIZE(spd_lp4_nbytes_total_map));

	/*
	 * Like with DDR4 there is no specific way to determine the type. We
	 * take our best guess based upon the size. A 256 byte EEPROM is most
	 * likely the EE1002 spec and the 512 byte EEPROM is the EE1004 as those
	 * are the defended sized.
	 */
	spd_upsert_flag(si, SPD_KEY_DEVS, SPD_DEVICE_SPD);
	if (total == SPD_LP4_NBYTES_TOTAL_256) {
		spd_nvl_insert_u32(si, SPD_KEY_DEV_SPD_TYPE, SPD_SPD_T_EE1002);
	} else if (total == SPD_LP4_NBYTES_TOTAL_512) {
		spd_nvl_insert_u32(si, SPD_KEY_DEV_SPD_TYPE, SPD_SPD_T_EE1004);
	}
}

/*
 * Like DDR4 the value of zero is defined for extensions; however, there are no
 * defined type extensions. As such we don't check for it.
 */
static const spd_value_map_t spd_lp4_mod_type_map[] = {
	{ SPD_LP4_MOD_TYPE_TYPE_LPDIMM, SPD_MOD_TYPE_LPDIMM, false },
	{ SPD_LP4_MOD_TYPE_TYPE_SOLDER, SPD_MOD_TYPE_SOLDER, false }
};

static const spd_value_map_t spd_lp4_mod_is_hybrid_map[] = {
	{ 0, SPD_MOD_NOT_HYBRID, false },
	{ 1, SPD_MOD_HYBRID_NVDIMMM, false }
};

static void
spd_parse_lp4_mod_type(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t type = SPD_LP4_MOD_TYPE_TYPE(data);
	const uint8_t is_hyb = SPD_LP4_MOD_TYPE_ISHYBRID(data);

	spd_insert_map(si, SPD_KEY_MOD_HYBRID_TYPE, is_hyb,
	    spd_lp4_mod_is_hybrid_map, ARRAY_SIZE(spd_lp4_mod_is_hybrid_map));

	spd_insert_map(si, SPD_KEY_MOD_TYPE, type, spd_lp4_mod_type_map,
	    ARRAY_SIZE(spd_lp4_mod_type_map));
}

static const spd_value_map64_t spd_lp4_density_map[] = {
	{ SPD_LP4_DENSITY_DENSITY_1Gb, 1ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP4_DENSITY_DENSITY_2Gb, 2ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP4_DENSITY_DENSITY_4Gb, 4ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP4_DENSITY_DENSITY_8Gb, 8ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP4_DENSITY_DENSITY_16Gb, 16ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP4_DENSITY_DENSITY_32Gb, 32ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP4_DENSITY_DENSITY_12Gb, 12ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP4_DENSITY_DENSITY_24Gb, 24ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP4_DENSITY_DENSITY_3Gb, 3ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP4_DENSITY_DENSITY_6Gb, 64ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP4_DENSITY_DENSITY_18Gb, 18ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
};

static const spd_value_range_t spd_lp4_nbgrp_range = {
	.svr_max = SPD_LP4_DENSITY_NBG_BITS_MAX
};

static const spd_value_range_t spd_lp4_nba_range = {
	.svr_max = SPD_LP4_DENSITY_NBA_BITS_MAX,
	.svr_base = SPD_LP4_DENSITY_NBA_BITS_BASE
};

static void
spd_parse_lp4_density(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t nbg = SPD_LP4_DENSITY_NBG_BITS(data);
	const uint8_t nbank = SPD_LP4_DENSITY_NBA_BITS(data);
	const uint8_t dens = SPD_LP4_DENSITY_DENSITY(data);

	spd_insert_range(si, SPD_KEY_NBGRP_BITS, nbg, &spd_lp4_nbgrp_range);
	spd_insert_range(si, SPD_KEY_NBANK_BITS, nbank, &spd_lp4_nba_range);
	spd_insert_map64(si, SPD_KEY_DIE_SIZE, dens, spd_lp4_density_map,
	    ARRAY_SIZE(spd_lp4_density_map));
}

static const spd_value_range_t spd_lp4_nrow_range = {
	.svr_max = SPD_LP4_ADDR_NROWS_MAX,
	.svr_base = SPD_LP4_ADDR_NROWS_BASE
};

static const spd_value_range_t spd_lp4_ncol_range = {
	.svr_max = SPD_LP4_ADDR_NCOLS_MAX,
	.svr_base = SPD_LP4_ADDR_NCOLS_BASE
};

static void
spd_parse_lp4_addr(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t nrows = SPD_LP4_ADDR_NROWS(data);
	const uint8_t ncols = SPD_LP4_ADDR_NCOLS(data);

	spd_insert_range(si, SPD_KEY_NROW_BITS, nrows, &spd_lp4_nrow_range);
	spd_insert_range(si, SPD_KEY_NCOL_BITS, ncols, &spd_lp4_ncol_range);
}

static const spd_value_range_t spd_lp4_ndie_range = {
	.svr_base = SPD_LP4_PKG_DIE_CNT_BASE
};

static const spd_value_range_t spd_lp4_nchan_range = {
	.svr_max = SPD_LP4_PKG_NCHAN_MAX,
	.svr_exp = true
};

static void
spd_parse_lp4_pkg(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t ndie = SPD_LP4_PKG_DIE_CNT(data);
	const uint8_t nchan = SPD_LP4_PKG_NCHAN(data);


	if (SPD_LP4_PKG_TYPE(data) == SPD_LP4_PKG_TYPE_NOT) {
		spd_nvl_insert_key(si, SPD_KEY_PKG_NOT_MONO);
	}

	spd_insert_range(si, SPD_KEY_PKG_NDIE, ndie, &spd_lp4_ndie_range);
	spd_insert_range(si, SPD_KEY_DRAM_NCHAN, nchan, &spd_lp4_nchan_range);
}

static const spd_value_map_t spd_lp4_maw_map[] = {
	{ SPD_LP4_OPT_FEAT_MAW_8192X, 8192, false },
	{ SPD_LP4_OPT_FEAT_MAW_4096X, 4096, false },
	{ SPD_LP4_OPT_FEAT_MAW_2048X, 2048, false }
};

static const spd_value_map_t spd_lp4_mac_map[] = {
	{ SPD_LP4_OPT_FEAT_MAC_UNTESTED, 0, true},
	{ SPD_LP4_OPT_FEAT_MAC_700K, 700000, false },
	{ SPD_LP4_OPT_FEAT_MAC_600K, 600000, false },
	{ SPD_LP4_OPT_FEAT_MAC_500K, 500000, false },
	{ SPD_LP4_OPT_FEAT_MAC_400K, 400000, false },
	{ SPD_LP4_OPT_FEAT_MAC_300K, 300000, false },
	{ SPD_LP4_OPT_FEAT_MAC_200K, 200000, false },
	{ SPD_LP4_OPT_FEAT_MAC_UNLIMITED, SPD_KEY_MAC_UNLIMITED, false }
};

static void
spd_parse_lp4_feat(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t maw = SPD_DDR4_OPT_FEAT_MAW(data);
	const uint8_t mac = SPD_DDR4_OPT_FEAT_MAC(data);

	spd_insert_map(si, SPD_KEY_MAW, maw, spd_lp4_maw_map,
	    ARRAY_SIZE(spd_lp4_maw_map));
	spd_insert_map(si, SPD_KEY_MAC, mac, spd_lp4_mac_map,
	    ARRAY_SIZE(spd_lp4_mac_map));
}

static void
spd_parse_lp4_feat2(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t ppr_sup = SPD_DDR4_OPT_FEAT2_PPR(data);
	spd_ppr_flags_t flags = 0;

	switch (ppr_sup) {
	case SPD_LP4_OPT_FEAT2_PPR_1RPBG:
		spd_nvl_insert_u32(si, SPD_KEY_PPR_GRAN,
		    SPD_PPR_GRAN_BANK_GROUP);
		flags |= SPD_PPR_F_HARD_PPR;
		break;
	case SPD_LP4_OPT_FEAT2_PPR_NOTSUP:
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

	if (SPD_LP4_OPT_FEAT2_SOFT_PPR(data))
		flags |= SPD_PPR_F_SOFT_PPR;
	spd_nvl_insert_u32(si, SPD_KEY_PPR, flags);
}

static const spd_value_range_t spd_lp4_nrank_range = {
	.svr_max = SPD_LP4_MOD_ORG_NPKG_RANK_MAX,
	.svr_base = SPD_LP4_MOD_ORG_NPKG_RANK_BASE
};

static const spd_value_range_t spd_lp4_width_range = {
	.svr_max = SPD_LP4_MOD_ORG_WIDTH_MAX,
	.svr_base = SPD_LP4_MOD_ORG_WIDTH_BASE,
	.svr_exp = true
};

static void
spd_parse_lp4_mod_org(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t byte = SPD_LP4_MOD_ORG_IDENT(data);
	const uint8_t nrank = SPD_LP4_MOD_ORG_NPKG_RANK(data);
	const uint8_t width = SPD_LP4_MOD_ORG_WIDTH(data);

	if (byte == SPD_LP4_MOD_ORG_IDENT_BYTE) {
		spd_nvl_insert_key(si, SPD_KEY_LP_BYTE_MODE);
	}

	spd_insert_range(si, SPD_KEY_NRANKS, nrank, &spd_lp4_nrank_range);
	spd_insert_range(si, SPD_KEY_DRAM_WIDTH, width, &spd_lp4_width_range);

}

static const spd_value_map_t spd_lp4_chan_map[] = {
	{ SPD_LP4_BUS_WIDTH_NCHAN_1ch, 1, false },
	{ SPD_LP4_BUS_WIDTH_NCHAN_2ch, 2, false },
	{ SPD_LP4_BUS_WIDTH_NCHAN_3ch, 3, false },
	{ SPD_LP4_BUS_WIDTH_NCHAN_4ch, 4, false },
	{ SPD_LP4_BUS_WIDTH_NCHAN_8ch, 8, false }
};

static const spd_value_range_t spd_lp4_chan_width_range = {
	.svr_base = SPD_LP4_BUS_WIDTH_PRI_BASE,
	.svr_max = SPD_LP4_BUS_WIDTH_PRI_MAX,
	.svr_exp = true
};

static void
spd_parse_lp4_bus_width(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t nchan = SPD_LP4_BUS_WIDTH_NCHAN(data);
	const uint8_t ext = SPD_LP4_BUS_WIDTH_EXT(data);
	const uint8_t width = SPD_LP4_BUS_WIDTH_PRI(data);

	spd_insert_map(si, SPD_KEY_NSUBCHAN, nchan, spd_lp4_chan_map,
	    ARRAY_SIZE(spd_lp4_chan_map));

	if (ext != SPD_LP4_BUS_WIDTH_EXT_NONE) {
		spd_nvl_err(si, SPD_KEY_ECC_WIDTH, SPD_ERROR_NO_XLATE,
		    "encountered invalid bus width extension: 0x%x", ext);
	} else {
		spd_nvl_insert_u32(si, SPD_KEY_ECC_WIDTH, 0);
	}

	spd_insert_range(si, SPD_KEY_DATA_WIDTH, width,
	    &spd_lp4_chan_width_range);
}

static void
spd_parse_lp4_therm(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];

	if (SPD_LP4_MOD_THERM_PRES(data) != 0)
		spd_upsert_flag(si, key, SPD_DEVICE_TEMP_1);
	/*
	 * Like DDR4, LPDDR3/4 only define that this must be TSE2004av
	 * compliant.
	 */
	spd_nvl_insert_u32(si, SPD_KEY_DEV_TEMP_TYPE, SPD_TEMP_T_TSE2004av);
}

static const spd_value_range_t spd_lp4_dsm_range = {
	.svr_max = SPD_LP4_SIGLOAD1_DSM_LOAD_MAX,
	.svr_exp = true
};

static const spd_value_range_t spd_lp4_cac_range = {
	.svr_max = SPD_LP4_SIGLOAD1_CAC_LOAD_MAX,
	.svr_exp = true
};

static const spd_value_range_t spd_lp4_cs_range = {
	.svr_max = SPD_LP4_SIGLOAD1_CS_LOAD_MAX,
	.svr_exp = true
};

static void
spd_parse_lp4_sigload(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t dsm = SPD_LP5_SIGLOAD1_DSM_LOAD(data);
	const uint8_t cac = SPD_LP5_SIGLOAD1_CAC_LOAD(data);
	const uint8_t cs = SPD_LP5_SIGLOAD1_CS_LOAD(data);

	spd_insert_range(si, SPD_KEY_LP_LOAD_DSM, dsm, &spd_lp4_dsm_range);
	spd_insert_range(si, SPD_KEY_LP_LOAD_CAC, cac, &spd_lp4_cac_range);
	spd_insert_range(si, SPD_KEY_LP_LOAD_CS, cs, &spd_lp4_cs_range);
}

static const spd_value_map_t spd_lp4_ts_mtb[] = {
	{ SPD_LP4_TIMEBASE_MTB_125ps, SPD_LP4_MTB_PS, false }
};

static const spd_value_map_t spd_lp4_ts_ftb[] = {
	{ SPD_LP4_TIMEBASE_FTB_1ps, SPD_LP4_FTB_PS, false }
};

static void
spd_parse_lp4_timebase(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t mtb = SPD_LP4_TIMEBASE_MTB(data);
	const uint8_t ftb = SPD_LP4_TIMEBASE_FTB(data);

	spd_insert_map(si, SPD_KEY_MTB, mtb, spd_lp4_ts_mtb,
	    ARRAY_SIZE(spd_lp4_ts_mtb));
	spd_insert_map(si, SPD_KEY_FTB, ftb, spd_lp4_ts_ftb,
	    ARRAY_SIZE(spd_lp4_ts_ftb));
}

/*
 * The first byte of CAS values is non-uniform. The second byte onwards begins
 * at CL=16 and each bit indicates a CL two apart. We use this array of all CAS
 * values as most of them aren't actually defined by the spec.
 */
static const uint32_t spd_lp4_cas_map[32] = {
	[0] = 3,
	[1] = 6,
	[2] = 8,
	[3] = 9,
	[4] = 10,
	[5] = 11,
	[6] = 12,
	[7] = 14,
	[8] = 16,
	[9] = 18,
	[10] = 20,
	[11] = 22,
	[12] = 24,
	[13] = 26,
	[14] = 28,
	[15] = 30,
	[16] = 32,
	[18] = 36,
	[20] = 40,
	[22] = 44
};

static void
spd_parse_lp4_cas(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	uint32_t cas[32] = { 0 };
	uint_t ncas = 0;

	ASSERT3U(len, ==, 4);
	for (uint32_t byte = 0; byte < MIN(len, 4); byte++) {
		uint32_t data = si->si_data[off + byte];
		uint32_t nbits = NBBY;

		for (uint32_t i = 0; i < nbits; i++) {
			if (bitx8(data, i, i) == 1) {
				uint8_t pos = i + byte * NBBY;
				if (spd_lp4_cas_map[pos] != 0) {
					cas[ncas] = spd_lp4_cas_map[pos];
					ncas++;
				} else {
					spd_nvl_err(si, key, SPD_ERROR_BAD_DATA,
					    "invalid CAS byte %u/bit %u found",
					    byte, i);
					return;
				}
			}
		}
	}

	spd_nvl_insert_u32_array(si, key, cas, ncas);
}

static void
spd_parse_lp4_rwlat(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t wr = SPD_LP4_RWLAT_WRITE(data);
	const uint8_t rd = SPD_LP4_RWLAT_READ(data);
	spd_lp_rwlat_t rwlat = 0;

	switch (wr) {
	case SPD_LP4_RWLAT_WRITE_A:
		rwlat |= SPD_LP_RWLAT_WRITE_A;
		break;
	case SPD_LP4_RWLAT_WRITE_B:
		rwlat |= SPD_LP_RWLAT_WRITE_B;
		break;
	default:
		spd_nvl_err(si, key, SPD_ERROR_NO_XLATE, "unknown write "
		    "latency set value: 0x%x", wr);
		return;
	}

	switch (rd) {
	case SPD_LP4_RWLAT_DBIRD_DIS:
		break;
	case SPD_LP4_RWLAT_DBIRD_EN:
		rwlat |= SPD_LP_RWLAT_DBIRD_EN;
		break;
	default:
		spd_nvl_err(si, key, SPD_ERROR_NO_XLATE, "unknown read "
		    "latency mode value: 0x%x", rd);
		return;
	}

	spd_nvl_insert_u32(si, key, rwlat);
}

static const spd_parse_t spd_lp4_base[] = {
	{ .sp_off = SPD_LP4_NBYTES, .sp_parse = spd_parse_lp4_nbytes },
	{ .sp_off = SPD_LP4_SPD_REV, .sp_parse = spd_parse_rev },
	/*
	 * We have previously validated that the DRAM type is something that we
	 * understand. We pass through the raw enum to users here.
	 */
	{ .sp_off = SPD_LP4_DRAM_TYPE, .sp_key = SPD_KEY_DRAM_TYPE,
	    .sp_parse = spd_parse_raw_u8 },

	{ .sp_off = SPD_LP4_MOD_TYPE, .sp_parse = spd_parse_lp4_mod_type },
	{ .sp_off = SPD_LP4_DENSITY, .sp_parse = spd_parse_lp4_density },
	{ .sp_off = SPD_LP4_ADDR, .sp_parse = spd_parse_lp4_addr },
	{ .sp_off = SPD_LP4_PKG, .sp_parse = spd_parse_lp4_pkg },
	{ .sp_off = SPD_LP4_OPT_FEAT, .sp_parse = spd_parse_lp4_feat },
	{ .sp_off = SPD_LP4_OPT_FEAT2, .sp_parse = spd_parse_lp4_feat2 },
	{ .sp_off = SPD_LP4_MOD_ORG, .sp_parse = spd_parse_lp4_mod_org },
	{ .sp_off = SPD_LP4_BUS_WIDTH, .sp_parse = spd_parse_lp4_bus_width },
	{ .sp_off = SPD_LP4_MOD_THERM, .sp_parse = spd_parse_lp4_therm },
	{ .sp_off = SPD_LP4_SIGLOAD, .sp_parse = spd_parse_lp4_sigload },
	{ .sp_off = SPD_LP4_TIMEBASE, .sp_parse = spd_parse_lp4_timebase },
	{ .sp_off = SPD_LP4_TCKAVG_MIN, .sp_key = SPD_KEY_TCKAVG_MIN,
	    .sp_len = SPD_LP4_TCKAVG_MIN_FINE - SPD_LP4_TCKAVG_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_LP4_TCKAVG_MAX, .sp_key = SPD_KEY_TCKAVG_MAX,
	    .sp_len = SPD_LP4_TCKAVG_MAX_FINE - SPD_LP4_TCKAVG_MAX + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_LP4_CAS_SUP0, .sp_key = SPD_KEY_CAS,
	    .sp_len = SPD_LP4_CAS_SUP3 - SPD_LP4_CAS_SUP0 + 1,
	    .sp_parse = spd_parse_lp4_cas },
	{ .sp_off = SPD_LP5_TAA_MIN, .sp_key = SPD_KEY_TAA_MIN,
	    .sp_len = SPD_LP5_TAA_MIN_FINE - SPD_LP5_TAA_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_LP4_RWLAT, .sp_key = SPD_KEY_LP_RWLAT,
	    .sp_parse = spd_parse_lp4_rwlat },
	{ .sp_off = SPD_LP5_TRCD_MIN, .sp_key = SPD_KEY_TRCD_MIN,
	    .sp_len = SPD_LP5_TRCD_MIN_FINE - SPD_LP5_TRCD_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_LP5_TRPAB_MIN, .sp_key = SPD_KEY_TRPAB_MIN,
	    .sp_len = SPD_LP5_TRPAB_MIN_FINE - SPD_LP5_TRPAB_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_LP5_TRPPB_MIN, .sp_key = SPD_KEY_TRPPB_MIN,
	    .sp_len = SPD_LP5_TRPPB_MIN_FINE - SPD_LP5_TRPPB_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_LP5_TRPPB_MIN, .sp_key = SPD_KEY_TRPPB_MIN,
	    .sp_len = SPD_LP5_TRPPB_MIN_FINE - SPD_LP5_TRPPB_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_LP4_TRFCAB_MIN_LO, .sp_key = SPD_KEY_TRFCAB_MIN,
	    .sp_len = 2, .sp_parse = spd_parse_mtb_pair },
	{ .sp_off = SPD_LP4_TRFCPB_MIN_LO, .sp_key = SPD_KEY_TRFCPB_MIN,
	    .sp_len = 2, .sp_parse = spd_parse_mtb_pair },
	{ .sp_off = SPD_LP4_MAP_DQ0, .sp_key = SPD_KEY_DDR4_MAP_DQ0,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_LP4_MAP_DQ4, .sp_key = SPD_KEY_DDR4_MAP_DQ4,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_LP4_MAP_DQ8, .sp_key = SPD_KEY_DDR4_MAP_DQ8,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_LP4_MAP_DQ12, .sp_key = SPD_KEY_DDR4_MAP_DQ12,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_LP4_MAP_DQ16, .sp_key = SPD_KEY_DDR4_MAP_DQ16,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_LP4_MAP_DQ20, .sp_key = SPD_KEY_DDR4_MAP_DQ20,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_LP4_MAP_DQ24, .sp_key = SPD_KEY_DDR4_MAP_DQ24,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_LP4_MAP_DQ28, .sp_key = SPD_KEY_DDR4_MAP_DQ28,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_LP4_MAP_CB0, .sp_key = SPD_KEY_DDR4_MAP_CB0,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_LP4_MAP_CB4, .sp_key = SPD_KEY_DDR4_MAP_CB4,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_LP4_MAP_DQ32, .sp_key = SPD_KEY_DDR4_MAP_DQ32,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_LP4_MAP_DQ36, .sp_key = SPD_KEY_DDR4_MAP_DQ36,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_LP4_MAP_DQ40, .sp_key = SPD_KEY_DDR4_MAP_DQ40,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_LP4_MAP_DQ44, .sp_key = SPD_KEY_DDR4_MAP_DQ44,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_LP4_MAP_DQ48, .sp_key = SPD_KEY_DDR4_MAP_DQ48,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_LP4_MAP_DQ52, .sp_key = SPD_KEY_DDR4_MAP_DQ52,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_LP4_MAP_DQ56, .sp_key = SPD_KEY_DDR4_MAP_DQ56,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_off = SPD_LP4_MAP_DQ60, .sp_key = SPD_KEY_DDR4_MAP_DQ60,
	    .sp_parse = spd_parse_ddr4_nib_map },
	{ .sp_len = SPD_DDR4_CRC_MSB + 1, .sp_key = SPD_KEY_CRC_DDR4_BASE,
	    .sp_parse = spd_parse_crc },
	{ .sp_len = SPD_LP4_CRC_MSB + 1, .sp_key = SPD_KEY_CRC_DDR4_BASE,
	    .sp_parse = spd_parse_crc },
};

static const spd_parse_t spd_lp4_lpdimm[] = {
	{ .sp_off = SPD_LP4_LPDIMM_HEIGHT, .sp_key = SPD_KEY_MOD_HEIGHT,
	    .sp_parse = spd_parse_height },
	{ .sp_off = SPD_LP4_LPDIMM_THICK, .sp_parse = spd_parse_thickness },
	{ .sp_off = SPD_LP4_LPDIMM_REF, .sp_parse = spd_parse_ddr4_design },
	{ .sp_off = SPD_LP4_BLK1_CRC_START, .sp_len = SPD_LP4_BLK1_CRC_MSB +
	    1 - SPD_LP4_BLK1_CRC_START, .sp_key = SPD_KEY_CRC_DDR4_BLK1,
	    .sp_parse = spd_parse_crc }
};

static void
spd_parse_lp4_mod_specific(spd_info_t *si)
{
	uint32_t type;

	if (nvlist_lookup_uint32(si->si_nvl, SPD_KEY_MOD_TYPE, &type) != 0)
		return;

	switch (type) {
	case SPD_MOD_TYPE_LPDIMM:
		spd_parse(si, spd_lp4_lpdimm, ARRAY_SIZE(spd_lp4_lpdimm));
		break;
	default:
		break;
	}
}

void
spd_parse_lp4(spd_info_t *si)
{
	if (SPD_LP4_SPD_REV_ENC(si->si_data[SPD_LP4_SPD_REV]) !=
	    SPD_LP4_SPD_REV_V1) {
		si->si_error = LIBJEDEC_SPD_UNSUP_REV;
		return;
	}

	spd_parse(si, spd_lp4_base, ARRAY_SIZE(spd_lp4_base));
	spd_parse_lp4_mod_specific(si);
	spd_parse_ddr4_mfg(si);
}
