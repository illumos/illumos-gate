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
 * LPDDR5/x-specific SPD processing logic. For an overview of the processing
 * design please see libjedec_spd.c. LPDDR5 has a similar design to DDR5 and
 * even uses the same common module, manufacturing, and module-specific data.
 */

#include <sys/sysmacros.h>
#include <sys/debug.h>
#include "libjedec_spd.h"

static const spd_value_map_t spd_lp5_nbytes_total_map[] = {
	{ SPD_DDR5_NBYTES_TOTAL_UNDEF, 0, true },
	{ SPD_DDR5_NBYTES_TOTAL_256, 256, false },
	{ SPD_DDR5_NBYTES_TOTAL_512, 512, false },
	{ SPD_DDR5_NBYTES_TOTAL_1024, 1024, false },
	{ SPD_DDR5_NBYTES_TOTAL_2048, 2048, false }
};

static void
spd_parse_lp5_nbytes(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t total = SPD_LP5_NBYTES_TOTAL(data);
	uint8_t beta = SPD_LP5_NBYTES_BETA(data);
	beta = bitset8(beta, 4, 4, SPD_LP5_NBYTES_BETAHI(data));

	spd_nvl_insert_u32(si, SPD_KEY_BETA, beta);
	spd_insert_map(si, SPD_KEY_NBYTES_TOTAL, total,
	    spd_lp5_nbytes_total_map, ARRAY_SIZE(spd_lp5_nbytes_total_map));
}

static const spd_value_map64_t spd_lp5_density_map[] = {
	{ SPD_LP5_DENSITY_DENSITY_1Gb, 1ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP5_DENSITY_DENSITY_2Gb, 2ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP5_DENSITY_DENSITY_4Gb, 4ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP5_DENSITY_DENSITY_8Gb, 8ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP5_DENSITY_DENSITY_16Gb, 16ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP5_DENSITY_DENSITY_32Gb, 32ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP5_DENSITY_DENSITY_12Gb, 12ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP5_DENSITY_DENSITY_24Gb, 24ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP5_DENSITY_DENSITY_3Gb, 3ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_LP5_DENSITY_DENSITY_6Gb, 6ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
};

static const spd_value_range_t spd_lp5_nbg_range = {
	.svr_max = SPD_LP5_DENSITY_NBG_BITS_MAX
};

static const spd_value_range_t spd_lp5_nba_range = {
	.svr_max = SPD_LP5_DENSITY_NBA_BITS_MAX,
	.svr_base = SPD_LP5_DENSITY_NBA_BITS_BASE
};

static void
spd_parse_lp5_density(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t nbg = SPD_LP5_DENSITY_NBG_BITS(data);
	const uint8_t nba = SPD_LP5_DENSITY_NBA_BITS(data);
	const uint8_t dens = SPD_LP5_DENSITY_DENSITY(data);

	spd_insert_range(si, SPD_KEY_NBGRP_BITS, nbg, &spd_lp5_nbg_range);
	spd_insert_range(si, SPD_KEY_NBANK_BITS, nba, &spd_lp5_nba_range);
	spd_insert_map64(si, SPD_KEY_DIE_SIZE, dens, spd_lp5_density_map,
	    ARRAY_SIZE(spd_lp5_density_map));
}

static const spd_value_map_t spd_lp5_ncol_map[] = {
	{ SPD_LP5_ADDRESS_BCOL_3BA6C, 6, false },
	{ SPD_LP5_ADDRESS_BCOL_4BA6C, 6, false }
};

static const spd_value_range_t spd_lp5_nrow_range = {
	.svr_max = SPD_LP5_ADDRESS_NROW_MAX,
	.svr_base = SPD_LP5_ADDRESS_NROW_BASE
};

static void
spd_parse_lp5_address(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t nrow = SPD_LP5_ADDRESS_NROWS(data);
	const uint8_t bcol = SPD_LP5_ADDRESS_BCOL(data);

	spd_insert_range(si, SPD_KEY_NROW_BITS, nrow, &spd_lp5_nrow_range);
	spd_insert_map(si, SPD_KEY_NCOL_BITS, bcol, spd_lp5_ncol_map,
	    ARRAY_SIZE(spd_lp5_ncol_map));
}

static const spd_value_map_t spd_lp5_ndie_map[] = {
	{ SPD_LP5_DIE_CNT_1, 1, false },
	{ SPD_LP5_DIE_CNT_2, 2, false },
	{ SPD_LP5_DIE_CNT_3, 3, false },
	{ SPD_LP5_DIE_CNT_4, 4, false },
	{ SPD_LP5_DIE_CNT_5, 5, false },
	{ SPD_LP5_DIE_CNT_6, 6, false },
	{ SPD_LP5_DIE_CNT_16, 16, false },
	{ SPD_LP5_DIE_CNT_8, 8, false }
};

/*
 * To insert the total number of DQs we need the die width which comes later.
 * Similarly, the signal loading index comes into play for a later word. As such
 * we process that later as well and therefore the only thing we process here
 * are the total number of dies.
 */
static void
spd_parse_lp5_pkg(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t ndie = SPD_LP5_PKG_DIE_CNT(data);

	if (SPD_LP5_PKG_TYPE(data) == SPD_LP5_PKG_TYPE_NOT) {
		spd_nvl_insert_key(si, SPD_KEY_PKG_NOT_MONO);
	}

	spd_insert_map(si, SPD_KEY_PKG_NDIE, ndie, spd_lp5_ndie_map,
	    ARRAY_SIZE(spd_lp5_ndie_map));
}

static void
spd_parse_lp5_opt_feat(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t ppr_sup = SPD_LP5_OPT_FEAT_PPR(data);
	spd_ppr_flags_t flags = 0;

	switch (ppr_sup) {
	case SPD_LP5_OPT_FEAT_PPR_SUP:
		flags |= SPD_PPR_F_HARD_PPR;
		break;
	case SPD_LP5_OPT_FEAT_PPR_NOTSUP:
		break;
	default:
		spd_nvl_err(si, key, SPD_ERROR_NO_XLATE,
		    "encountered unknown value: 0x%x", ppr_sup);
		return;
	}

	if (SPD_LP5_OPT_FEAT_SOFT_PPR(data) != 0) {
		flags |= SPD_PPR_F_SOFT_PPR;
	}

	if (flags != 0) {
		spd_nvl_insert_u32(si, key, flags);
	}
}

static const spd_value_range_t spd_lp5_nrank_range = {
	.svr_max = SPD_LP5_MOD_ORG_RANK_MAX,
	.svr_base = SPD_LP5_MOD_ORG_RANK_BASE
};

static const spd_value_range_t spd_lp5_width_range = {
	.svr_max = SPD_LP5_MOD_ORG_WIDTH_MAX,
	.svr_base = SPD_LP5_MOD_ORG_WIDTH_BASE,
	.svr_exp = true
};

static void
spd_parse_lp5_mod_org(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t byte = SPD_LP5_MOD_ORG_IDENT(data);
	const uint8_t nrank = SPD_LP5_MOD_ORG_RANK(data);
	const uint8_t width = SPD_LP5_MOD_ORG_WIDTH(data);

	if (byte == SPD_LP5_MOD_ORG_IDENT_BYTE) {
		spd_nvl_insert_key(si, SPD_KEY_LP_BYTE_MODE);
	}

	spd_insert_range(si, SPD_KEY_NRANKS, nrank, &spd_lp5_nrank_range);
	spd_insert_range(si, SPD_KEY_DRAM_WIDTH, width, &spd_lp5_width_range);
}

static const spd_value_map_t spd_lp5_subchan_width[] = {
	{ SP5_LP5_WIDTH_SUBCHAN_16b, 16, false },
	{ SP5_LP5_WIDTH_SUBCHAN_32b, 16, false }
};

/*
 * While this is nominally duplicative of the common memory channel
 * organization, we implement it here anyways just in case.
 */
static void
spd_parse_lp5_width(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t scw = SPD_LP5_WIDTH_SUBCHAN(data);

	spd_insert_map(si, key, scw, spd_lp5_subchan_width,
	    ARRAY_SIZE(spd_lp5_subchan_width));
}

static const spd_value_range_t spd_lp5_dsm_range = {
	.svr_max = SPD_LP5_SIGLOAD1_DSM_LOAD_MAX,
	.svr_exp = true
};

static const spd_value_range_t spd_lp5_cac_range = {
	.svr_max = SPD_LP5_SIGLOAD1_CAC_LOAD_MAX,
	.svr_exp = true
};

static const spd_value_range_t spd_lp5_cs_range = {
	.svr_max = SPD_LP5_SIGLOAD1_CS_LOAD_MAX,
	.svr_exp = true
};

static void
spd_parse_lp5_sigload(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t dsm = SPD_LP5_SIGLOAD1_DSM_LOAD(data);
	const uint8_t cac = SPD_LP5_SIGLOAD1_CAC_LOAD(data);
	const uint8_t cs = SPD_LP5_SIGLOAD1_CS_LOAD(data);

	spd_insert_range(si, SPD_KEY_LP_LOAD_DSM, dsm, &spd_lp5_dsm_range);
	spd_insert_range(si, SPD_KEY_LP_LOAD_CAC, cac, &spd_lp5_cac_range);
	spd_insert_range(si, SPD_KEY_LP_LOAD_CS, cs, &spd_lp5_cs_range);
}

static const spd_value_map_t spd_lp5_ts_mtb[] = {
	{ SPD_LP5_TIMEBASE_MTB_125ps, SPD_LP5_MTB_PS, false }
};

static const spd_value_map_t spd_lp5_ts_ftb[] = {
	{ SPD_LP5_TIMEBASE_FTB_1ps, SPD_LP5_FTB_PS, false }
};

static void
spd_parse_lp5_timebase(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t mtb = SPD_LP5_TIMEBASE_MTB(data);
	const uint8_t ftb = SPD_LP5_TIMEBASE_FTB(data);

	spd_insert_map(si, SPD_KEY_MTB, mtb, spd_lp5_ts_mtb,
	    ARRAY_SIZE(spd_lp5_ts_mtb));
	spd_insert_map(si, SPD_KEY_FTB, ftb, spd_lp5_ts_ftb,
	    ARRAY_SIZE(spd_lp5_ts_ftb));
}

static const spd_parse_t spd_lp5_base[] = {
	{ .sp_off = SPD_LP5_NBYTES, .sp_parse = spd_parse_lp5_nbytes },
	{ .sp_off = SPD_LP5_SPD_REV, .sp_parse = spd_parse_rev },
	/*
	 * We have previously validated that the DRAM type is something that we
	 * understand. We pass through the raw enum to users here.
	 */
	{ .sp_off = SPD_LP5_DRAM_TYPE, .sp_key = SPD_KEY_DRAM_TYPE,
	    .sp_parse = spd_parse_raw_u8 },
	/*
	 * DDR5 and LPDDR5 use the same values here, so we reuse the logic.
	 */
	{ .sp_off = SPD_LP5_MOD_TYPE, .sp_parse = spd_parse_ddr5_mod_type },
	{ .sp_off = SPD_LP5_DENSITY, .sp_parse = spd_parse_lp5_density },
	{ .sp_off = SPD_LP5_ADDRESS, .sp_parse = spd_parse_lp5_address },
	{ .sp_off = SPD_LP5_PKG, .sp_parse = spd_parse_lp5_pkg},
	{ .sp_off = SPD_LP5_OPT_FEAT, .sp_key = SPD_KEY_PPR,
	    .sp_parse = spd_parse_lp5_opt_feat },
	{ .sp_off = SPD_LP5_MOD_ORG, .sp_parse = spd_parse_lp5_mod_org },
	{ .sp_off = SPD_LP5_WIDTH, .sp_key = SPD_KEY_DATA_WIDTH,
	    .sp_parse = spd_parse_lp5_width },
	{ .sp_off = SPD_LP5_WIDTH, .sp_parse = spd_parse_lp5_sigload },
	{ .sp_off = SPD_LP5_TIMEBASE, .sp_parse = spd_parse_lp5_timebase },
	{ .sp_off = SPD_LP5_TCKAVG_MIN, .sp_key = SPD_KEY_TCKAVG_MIN,
	    .sp_len = SPD_LP5_TCKAVG_MIN_FINE - SPD_LP5_TCKAVG_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_LP5_TCKAVG_MAX, .sp_key = SPD_KEY_TCKAVG_MAX,
	    .sp_len = SPD_LP5_TCKAVG_MAX_FINE - SPD_LP5_TCKAVG_MAX + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
	{ .sp_off = SPD_LP5_TAA_MIN, .sp_key = SPD_KEY_TAA_MIN,
	    .sp_len = SPD_LP5_TAA_MIN_FINE - SPD_LP5_TAA_MIN + 1,
	    .sp_parse = spd_parse_mtb_ftb_time_pair },
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
	{ .sp_off = SPD_LP5_TRFCAB_MIN_LO, .sp_key = SPD_KEY_TRFCAB_MIN,
	    .sp_len = 2, .sp_parse = spd_parse_mtb_pair },
	{ .sp_off = SPD_LP5_TRFCPB_MIN_LO, .sp_key = SPD_KEY_TRFCPB_MIN,
	    .sp_len = 2, .sp_parse = spd_parse_mtb_pair },
};

void
spd_parse_lp5(spd_info_t *si)
{
	if (SPD_LP5_SPD_REV_ENC(si->si_data[SPD_LP5_SPD_REV]) !=
	    SPD_LP5_SPD_REV_V1) {
		si->si_error = LIBJEDEC_SPD_UNSUP_REV;
		return;
	}

	spd_parse(si, spd_lp5_base, ARRAY_SIZE(spd_lp5_base));
	spd_parse_ddr5_common(si);
}
