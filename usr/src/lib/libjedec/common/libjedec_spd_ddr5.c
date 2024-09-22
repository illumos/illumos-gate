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
 * DDR5-specific SPD processing logic. For an overview of the processing design
 * please see libjedec_spd.c. Note, this currently does not handle NVDIMMs.
 */

#include <sys/sysmacros.h>
#include <sys/debug.h>
#include "libjedec_spd.h"

static const spd_value_map_t spd_ddr5_nbytes_total_map[] = {
	{ SPD_DDR5_NBYTES_TOTAL_UNDEF, 0, true },
	{ SPD_DDR5_NBYTES_TOTAL_256, 256, false },
	{ SPD_DDR5_NBYTES_TOTAL_512, 512, false },
	{ SPD_DDR5_NBYTES_TOTAL_1024, 1024, false },
	{ SPD_DDR5_NBYTES_TOTAL_2048, 2048, false }
};

static void
spd_parse_ddr5_nbytes(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t total = SPD_DDR5_NBYTES_TOTAL(data);
	uint8_t beta = SPD_DDR5_NBYTES_BETA(data);
	beta = bitset8(beta, 4, 4, SPD_DDR5_NBYTES_BETAHI(data));

	spd_nvl_insert_u32(si, SPD_KEY_BETA, beta);
	spd_insert_map(si, SPD_KEY_NBYTES_TOTAL, total,
	    spd_ddr5_nbytes_total_map, ARRAY_SIZE(spd_ddr5_nbytes_total_map));
}

static const spd_value_map_t spd_ddr5_mod_type_map[] = {
	{ SPD_DDR5_MOD_TYPE_TYPE_RDIMM, SPD_MOD_TYPE_RDIMM, false },
	{ SPD_DDR5_MOD_TYPE_TYPE_UDIMM, SPD_MOD_TYPE_UDIMM, false },
	{ SPD_DDR5_MOD_TYPE_TYPE_SODIMM, SPD_MOD_TYPE_SODIMM, false },
	{ SPD_DDR5_MOD_TYPE_TYPE_LRDIMM, SPD_MOD_TYPE_LRDIMM, false },
	{ SPD_DDR5_MOD_TYPE_TYPE_CUDIMM, SPD_MOD_TYPE_CUDIMM, false },
	{ SPD_DDR5_MOD_TYPE_TYPE_CSODIMM, SPD_MOD_TYPE_CSODIMM, false },
	{ SPD_DDR5_MOD_TYPE_TYPE_MRDIMM, SPD_MOD_TYPE_MRDIMM, false },
	{ SPD_DDR5_MOD_TYPE_TYPE_CAMM2, SPD_MOD_TYPE_CAMM2, false },
	{ SPD_DDR5_MOD_TYPE_TYPE_DDIMM, SPD_MOD_TYPE_DDIMM, false },
	{ SPD_DDR5_MOD_TYPE_TYPE_SOLDER, SPD_MOD_TYPE_SOLDER, false }
};

static const spd_value_map_t spd_ddr5_mod_is_hybrid_map[] = {
	{ 0, SPD_MOD_NOT_HYBRID, false },
	{ 1, SPD_MOD_HYBRID_NVDIMMM, false }
};

static const spd_value_map_t spd_ddr5_mod_hybrid_map[] = {
	{ SPD_DDR5_MOD_TYPE_HYBRID_NVDIMM_N, SPD_MOD_TYPE_NVDIMM_N, false },
	{ SPD_DDR5_MOD_TYPE_HYBRID_NVDIMM_P, SPD_MOD_TYPE_NVDIMM_P, false }
};

/*
 * This is shared between DDR5 and LPDDR5 as they end up using the same
 * definitions for module types.
 */
void
spd_parse_ddr5_mod_type(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t type = SPD_DDR5_MOD_TYPE_TYPE(data);
	const uint8_t is_hyb = SPD_DDR5_MOD_TYPE_ISHYBRID(data);
	const uint8_t hybrid = SPD_DDR5_MOD_TYPE_HYBRID(data);

	spd_insert_map(si, SPD_KEY_MOD_HYBRID_TYPE, is_hyb,
	    spd_ddr5_mod_is_hybrid_map, ARRAY_SIZE(spd_ddr5_mod_is_hybrid_map));

	if (is_hyb != 0) {
		spd_insert_map(si, SPD_KEY_MOD_NVDIMM_TYPE, hybrid,
		    spd_ddr5_mod_hybrid_map,
		    ARRAY_SIZE(spd_ddr5_mod_hybrid_map));
	}

	spd_insert_map(si, SPD_KEY_MOD_TYPE, type, spd_ddr5_mod_type_map,
	    ARRAY_SIZE(spd_ddr5_mod_type_map));
}

static bool
spd_parse_ddr5_isassym(spd_info_t *si)
{
	ASSERT3U(si->si_size, >, SPD_DDR5_COM_ORG);
	const uint8_t data = si->si_data[SPD_DDR5_COM_ORG];
	const uint8_t is_asym = SPD_DDR5_COM_ORG_MIX(data);

	return (is_asym == SPD_DDR5_COM_ORG_MIX_ASYM);
}

static const spd_value_map64_t spd_ddr5_density_map[] = {
	{ SPD_DDR5_DENPKG_DPD_4Gb, 4ULL * 1024ULL * 1024ULL * 1024ULL, false },
	{ SPD_DDR5_DENPKG_DPD_8Gb, 8ULL * 1024ULL * 1024ULL * 1024ULL, false },
	{ SPD_DDR5_DENPKG_DPD_12Gb, 12ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_DDR5_DENPKG_DPD_16Gb, 16ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_DDR5_DENPKG_DPD_24Gb, 24ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_DDR5_DENPKG_DPD_32Gb, 32ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_DDR5_DENPKG_DPD_48Gb, 48ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
	{ SPD_DDR5_DENPKG_DPD_64Gb, 64ULL * 1024ULL * 1024ULL * 1024ULL,
	    false },
};

static const spd_value_map_t spd_ddr5_ndies_map[] = {
	{ SPD_DDR5_DENPKG_DPP_MONO, 1, false },
	{ SPD_DDR5_DENPKG_DPP_DDP, 2, false },
	{ SPD_DDR5_DENPKG_DPP_2H3DS, 2, false },
	{ SPD_DDR5_DENPKG_DPP_4H3DS, 4, false },
	{ SPD_DDR5_DENPKG_DPP_8H3DS, 8, false },
	{ SPD_DDR5_DENPKG_DPP_16H3DS, 16, false },
};

static const spd_value_map_t spd_ddr5_sl_map[] = {
	{ SPD_DDR5_DENPKG_DPP_MONO, SPD_SL_UNSPECIFIED, false },
	{ SPD_DDR5_DENPKG_DPP_DDP, SPD_SL_UNSPECIFIED, false },
	{ SPD_DDR5_DENPKG_DPP_2H3DS, SPD_SL_3DS, false },
	{ SPD_DDR5_DENPKG_DPP_4H3DS, SPD_SL_3DS, false },
	{ SPD_DDR5_DENPKG_DPP_8H3DS, SPD_SL_3DS, false },
	{ SPD_DDR5_DENPKG_DPP_16H3DS, SPD_SL_3DS, false },
};

static void
spd_parse_ddr5_denpkg(spd_info_t *si, uint8_t data, const char *ndie_key,
    const char *den_key, const char *sl_key)
{
	const uint8_t ndie = SPD_DDR5_DENPKG_DPP(data);
	const uint8_t dens = SPD_DDR5_DENPKG_DPD(data);

	spd_insert_map(si, ndie_key, ndie, spd_ddr5_ndies_map,
	    ARRAY_SIZE(spd_ddr5_ndies_map));
	spd_insert_map(si, sl_key, ndie, spd_ddr5_sl_map,
	    ARRAY_SIZE(spd_ddr5_sl_map));
	spd_insert_map64(si, den_key, dens, spd_ddr5_density_map,
	    ARRAY_SIZE(spd_ddr5_density_map));
}

static void
spd_parse_ddr5_denpkg_pri(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	spd_parse_ddr5_denpkg(si, si->si_data[off], SPD_KEY_PKG_NDIE,
	    SPD_KEY_DIE_SIZE, SPD_KEY_PKG_SL);
}

static void
spd_parse_ddr5_denpkg_sec(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	if (!spd_parse_ddr5_isassym(si))
		return;

	spd_parse_ddr5_denpkg(si, si->si_data[off], SPD_KEY_SEC_PKG_NDIE,
	    SPD_KEY_SEC_DIE_SIZE, SPD_KEY_SEC_PKG_SL);
}

static const spd_value_range_t spd_ddr5_nrow_range = {
	.svr_max = SPD_DDR5_ADDR_NROWS_MAX,
	.svr_base = SPD_DDR5_ADDR_NROWS_BASE
};

static const spd_value_range_t spd_ddr5_ncol_range = {
	.svr_max = SPD_DDR5_ADDR_NCOLS_MAX,
	.svr_base = SPD_DDR5_ADDR_NCOLS_BASE
};

static void
spd_parse_ddr5_addr(spd_info_t *si, uint8_t data, const char *row_key,
    const char *col_key)
{
	const uint8_t ncols = SPD_DDR5_ADDR_NCOLS(data);
	const uint8_t nrows = SPD_DDR5_ADDR_NROWS(data);

	spd_insert_range(si, col_key, ncols, &spd_ddr5_ncol_range);
	spd_insert_range(si, row_key, nrows, &spd_ddr5_nrow_range);
}

static void
spd_parse_ddr5_addr_pri(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	spd_parse_ddr5_addr(si, si->si_data[off], SPD_KEY_NROW_BITS,
	    SPD_KEY_NCOL_BITS);
}

static void
spd_parse_ddr5_addr_sec(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	if (!spd_parse_ddr5_isassym(si))
		return;

	spd_parse_ddr5_addr(si, si->si_data[off], SPD_KEY_SEC_NROW_BITS,
	    SPD_KEY_SEC_NCOL_BITS);
}

static const spd_value_map_t spd_ddr5_width_map[] = {
	{ SPD_DDR5_WIDTH_X4, 4, false },
	{ SPD_DDR5_WIDTH_X8, 8, false },
	{ SPD_DDR5_WIDTH_X16, 16, false },
	{ SPD_DDR5_WIDTH_X32, 32, false }
};

static void
spd_parse_ddr5_width(spd_info_t *si, uint8_t data, const char *key)
{
	const uint8_t width = SPD_DDR5_WIDTH_WIDTH(data);

	spd_insert_map(si, key, width, spd_ddr5_width_map,
	    ARRAY_SIZE(spd_ddr5_width_map));
}

static void
spd_parse_ddr5_width_pri(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	spd_parse_ddr5_width(si, si->si_data[off], SPD_KEY_DRAM_WIDTH);
}

static void
spd_parse_ddr5_width_sec(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	if (!spd_parse_ddr5_isassym(si))
		return;

	spd_parse_ddr5_width(si, si->si_data[off], SPD_KEY_SEC_DRAM_WIDTH);
}

static const spd_value_range_t spd_ddr5_nbg_range = {
	.svr_max = SPD_DDR5_BANKS_NBG_BITS_MAX
};

static const spd_value_range_t spd_ddr5_nba_range = {
	.svr_max = SPD_DDR5_BANKS_NBA_BITS_MAX
};

static void
spd_parse_ddr5_banks(spd_info_t *si, uint8_t data, const char *bg_key,
    const char *ba_key)
{
	const uint8_t nbg = SPD_DDR5_BANKS_NBG_BITS(data);
	const uint8_t nba = SPD_DDR5_BANKS_NBA_BITS(data);

	spd_insert_range(si, bg_key, nbg, &spd_ddr5_nbg_range);
	spd_insert_range(si, ba_key, nba, &spd_ddr5_nba_range);
}

static void
spd_parse_ddr5_banks_pri(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	spd_parse_ddr5_banks(si, si->si_data[off], SPD_KEY_NBGRP_BITS,
	    SPD_KEY_NBANK_BITS);
}

static void
spd_parse_ddr5_banks_sec(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	if (!spd_parse_ddr5_isassym(si))
		return;

	spd_parse_ddr5_banks(si, si->si_data[off], SPD_KEY_SEC_NBGRP_BITS,
	    SPD_KEY_SEC_NBANK_BITS);
}

static void
spd_parse_ddr5_ppr(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	spd_ppr_flags_t flags = SPD_PPR_F_HARD_PPR | SPD_PPR_F_SOFT_PPR;

	if (SPD_DDR5_PPR_GRAN(data) == SPD_DDR5_PPR_GRAN_BGRP) {
		spd_nvl_insert_u32(si, SPD_KEY_PPR_GRAN,
		    SPD_PPR_GRAN_BANK_GROUP);
	} else {
		spd_nvl_insert_u32(si, SPD_KEY_PPR_GRAN,
		    SPD_PPR_GRAN_BANK);
	}

	if (SPD_DDR5_PPR_LOCK_SUP(data) != 0)
		flags |= SPD_PPR_F_PPR_UNDO;
	if (SPD_DDR5_PPR_MPPR_SUP(data) != 0)
		flags |= SPD_PPR_F_MBIST_PPR;
	spd_nvl_insert_u32(si, SPD_KEY_PPR, flags);

	if (SPD_DDR5_PPR_BL32_SUP(data) != 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_BL32);
}

static const spd_value_map_t spd_ddr5_dca_map[] = {
	{ SPD_DDR5_SPD_DCA_TYPE_UNSUP, SPD_DCA_UNSPPORTED, false },
	{ SPD_DDR5_SPD_DCA_TYPE_1_2P, SPD_DCA_1_OR_2_PHASE, false },
	{ SPD_DDR5_SPD_DCA_TYPE_4P, SPD_DCA_4_PHASE, false }
};

static void
spd_parse_ddr5_dca(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t dca = SPD_DDR5_SPD_DCA_TYPE(data);

	if (SPD_DDR5_SPD_DCA_PASR(data) != 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR_PASR);

	spd_insert_map(si, SPD_KEY_DDR5_DCA, dca, spd_ddr5_dca_map,
	    ARRAY_SIZE(spd_ddr5_dca_map));
}

static void
spd_parse_ddr5_flt(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	spd_fault_t flt = 0;

	if (SPD_DDR5_FLT_WIDE_TS(data) != 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_WIDE_TS);

	if (SPD_DDR5_FLT_WBSUPR_SUP(data) != 0) {
		if (SPD_DDR5_FLT_WBSUPR_SEL(data) ==
		    SPD_DDR5_FLT_WBSUPR_SEL_MR15) {
			flt |= SPD_FLT_WRSUP_MR15;
		} else {
			flt |= SPD_FLT_WRSUP_MR9;
		}
	}

	if (SPD_DDR5_FLT_BFLT(data))
		flt |= SPD_FLT_BOUNDED;
	if (flt != 0)
		spd_nvl_insert_u32(si, SPD_KEY_DDR5_FLT, flt);
}

/*
 * Voltages support describing the nominal, operational, and endurant ranges.
 * Currently we only encode the nominal values.
 */
static void
spd_parse_ddr5_voltage(spd_info_t *si, uint8_t data, const char *key,
    uint32_t *mv, uint32_t nmv)
{
	const uint8_t nom_idx = SPD_DDR5_DRAM_VOLT_NOM(data);

	if (nom_idx >= nmv) {
		spd_nvl_err(si, key, SPD_ERROR_NO_XLATE,
		    "encountered unknown value: 0x%x", nom_idx);
	} else {
		spd_nvl_insert_u32_array(si, key, &mv[nom_idx], 1);
	}
}

static void
spd_parse_ddr5_vdd(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	uint32_t volts[] = { 1100 };
	return (spd_parse_ddr5_voltage(si, si->si_data[off], key, volts,
	    ARRAY_SIZE(volts)));
}

static void
spd_parse_ddr5_vddq(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	uint32_t volts[] = { 1100 };
	return (spd_parse_ddr5_voltage(si, si->si_data[off], key, volts,
	    ARRAY_SIZE(volts)));
}

static void
spd_parse_ddr5_vpp(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	uint32_t volts[] = { 1800 };
	return (spd_parse_ddr5_voltage(si, si->si_data[off], key, volts,
	    ARRAY_SIZE(volts)));
}

static void
spd_parse_ddr5_time(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];

	if (SPD_DDR5_TIME_STD(data) == SPD_DDR5_TIME_STD_NON)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_NONSTD_TIME);
}

/*
 * Time in picoseconds. The LSB is at off. The MSB is at off + 1.
 */
static void
spd_parse_ddr5_ps(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	uint64_t ps;

	ASSERT3U(len, ==, 2);
	ps = (uint64_t)si->si_data[off];
	ps |= (uint64_t)si->si_data[off + 1] << 8;

	if (ps == 0) {
		spd_nvl_err(si, key, SPD_ERROR_NO_XLATE,
		    "encountered unexpected zero time value");
		return;
	}

	spd_nvl_insert_u64(si, key, ps);
}

/*
 * Time in nanoseconds. The LSB is at off. The MSB is at off + 1. We normalize
 * all times to ps.
 */
static void
spd_parse_ddr5_ns(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	uint64_t ns, ps;

	ASSERT3U(len, ==, 2);
	ns = (uint64_t)si->si_data[off];
	ns |= (uint64_t)si->si_data[off + 1] << 8;

	if (ns == 0) {
		spd_nvl_err(si, key, SPD_ERROR_NO_XLATE,
		    "encountered unexpected zero time value");
		return;
	}

	ps = ns * 1000;
	spd_nvl_insert_u64(si, key, ps);
}

/*
 * Several DDR5 timing properties are only valid for 3DS type DIMMs. So we
 * double check the actual DIMM type before we proceed to parse this.
 */
static void
spd_parse_ddr5_3ds_ns(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(off, >=, SPD_DDR5_DENPKG1);
	uint32_t val;

	if (nvlist_lookup_uint32(si->si_nvl, SPD_KEY_PKG_SL, &val) != 0 ||
	    val != SPD_SL_3DS) {
		return;
	}

	spd_parse_ddr5_ns(si, off, len, key);
}

static void
spd_parse_ddr5_nck(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];

	if (data == 0) {
		spd_nvl_err(si, key, SPD_ERROR_NO_XLATE,
		    "encountered unexpected zero clock value");
		return;
	}

	spd_nvl_insert_u32(si, key, data);
}

static void
spd_parse_ddr5_cas(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	uint32_t cas[40] = { 0 };
	uint_t ncas = 0;
	uint32_t cas_base = 20;

	ASSERT3U(len, ==, 5);

	for (uint32_t byte = 0; byte < len; byte++) {
		uint32_t data = si->si_data[off + byte];

		for (uint32_t i = 0; i < NBBY; i++) {
			if (bitx8(data, i, i) == 1) {
				cas[ncas] = cas_base + 2 * (i + NBBY * byte);
				ncas++;
			}
		}
	}

	spd_nvl_insert_u32_array(si, key, cas, ncas);
}

static const spd_value_range_t spd_ddr5_raammt_norm_range = {
	.svr_min = SPD_DDR5_RFM0_RAAMMT_NORM_MIN,
	.svr_max = SPD_DDR5_RFM0_RAAMMT_NORM_MAX,
	.svr_mult = SPD_DDR5_RFM0_RAAMMT_NORM_MULT
};

static const spd_value_range_t spd_ddr5_raammt_fgr_range = {
	.svr_min = SPD_DDR5_RFM0_RAAMMT_FGR_MIN,
	.svr_max = SPD_DDR5_RFM0_RAAMMT_FGR_MAX,
	.svr_mult = SPD_DDR5_RFM0_RAAMMT_FGR_MULT
};

static const spd_value_range_t spd_ddr5_raaimt_norm_range = {
	.svr_min = SPD_DDR5_RFM0_RAAIMT_NORM_MIN,
	.svr_max = SPD_DDR5_RFM0_RAAIMT_NORM_MAX,
	.svr_mult = SPD_DDR5_RFM0_RAAIMT_NORM_MULT
};

static const spd_value_range_t spd_ddr5_raaimt_fgr_range = {
	.svr_min = SPD_DDR5_RFM0_RAAIMT_FGR_MIN,
	.svr_max = SPD_DDR5_RFM0_RAAIMT_FGR_MAX,
	.svr_mult = SPD_DDR5_RFM0_RAAIMT_FGR_MULT
};

static const spd_value_range_t spd_ddr5_brc_cfg_range = {
	.svr_max = SPD_DDR5_RFM1_BRC_CFG_MAX,
	.svr_base = SPD_DDR5_RFM1_BRC_CFG_BASE
};

static const spd_value_map_t spd_ddr5_raa_ctr_map[] = {
	{ SPD_DDR5_RFM1_CTR_1X, 1, false },
	{ SPD_DDR5_RFM1_CTR_2X, 2, false }
};

static void
spd_parse_ddr5_rfm_flags(spd_info_t *si, uint8_t rfm0, uint8_t rfm1,
    const char *key)
{
	spd_rfm_flags_t flags = 0;

	if (SPD_DDR5_RFM0_RFM_REQ(rfm0) != 0)
		flags |= SPD_RFM_F_REQUIRED;
	if (SPD_DDR5_RFM1_DRFM_SUP(rfm1) != 0)
		flags |= SPD_RFM_F_DRFM_SUP;

	spd_nvl_insert_u32(si, key, flags);
}

static void
spd_parse_ddr5_arfm_flags(spd_info_t *si, uint8_t rfm1, const char *key)
{
	spd_rfm_flags_t flags = 0;

	if (SPD_DDR5_RFM1_DRFM_SUP(rfm1) != 0)
		flags |= SPD_RFM_F_DRFM_SUP;

	spd_nvl_insert_u32(si, key, flags);
}

static void
spd_parse_ddr5_rfm_common(spd_info_t *si, uint8_t rfm0, uint8_t rfm1,
    const char *raaimt_key, const char *raaimt_fgr_key, const char *raammt_key,
    const char *raammt_fgr_key, const char *brc_cfg_key,
    const char *brc_sup_key, const char *raa_ctr_key)
{
	const uint8_t raammt = SPD_DDR5_RFM0_RAAMMT_NORM(rfm0);
	const uint8_t raammt_fgr = SPD_DDR5_RFM0_RAAMMT_FGR(rfm0);
	const uint8_t raaimt = SPD_DDR5_RFM0_RAAIMT_NORM(rfm0);
	const uint8_t raaimt_fgr = SPD_DDR5_RFM0_RAAIMT_FGR(rfm0);
	const uint8_t brc_cfg = SPD_DDR5_RFM1_BRC_CFG(rfm1);
	const uint8_t brc_sup = SPD_DDR5_RFM1_BRC_SUP(rfm1);
	const uint8_t raa_ctr = SPD_DDR5_RFM1_CTR(rfm1);
	spd_brc_flags_t brc_flags = SPD_BRC_F_LVL_2;

	if (brc_sup == SPD_DDR5_RFM1_BRC_SUP_234)
		brc_flags |= SPD_BRC_F_LVL_3 | SPD_BRC_F_LVL_4;

	if (SPD_DDR5_RFM0_RFM_REQ(rfm0) != 0) {
		spd_insert_range(si, raaimt_key, raaimt,
		    &spd_ddr5_raaimt_norm_range);
		spd_insert_range(si, raaimt_fgr_key, raaimt_fgr,
		    &spd_ddr5_raaimt_fgr_range);
		spd_insert_range(si, raammt_key, raammt,
		    &spd_ddr5_raammt_norm_range);
		spd_insert_range(si, raammt_fgr_key, raammt_fgr,
		    &spd_ddr5_raammt_fgr_range);
		spd_insert_map(si, raa_ctr_key, raa_ctr, spd_ddr5_raa_ctr_map,
		    ARRAY_SIZE(spd_ddr5_raa_ctr_map));
	}

	if (SPD_DDR5_RFM1_DRFM_SUP(rfm1) != 0) {
		spd_insert_range(si, brc_cfg_key, brc_cfg,
		    &spd_ddr5_brc_cfg_range);
		spd_nvl_insert_u32(si, brc_sup_key, brc_flags);
	}
}

static void
spd_parse_ddr5_rfm_pri(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 2);

	spd_parse_ddr5_rfm_flags(si, si->si_data[off], si->si_data[off + 1],
	    SPD_KEY_DDR5_RFM_FLAGS_PRI);
	spd_parse_ddr5_rfm_common(si, si->si_data[off], si->si_data[off + 1],
	    SPD_KEY_DDR5_RFM_RAAIMT_PRI, SPD_KEY_DDR5_RFM_RAAIMT_FGR_PRI,
	    SPD_KEY_DDR5_RFM_RAAMMT_PRI, SPD_KEY_DDR5_RFM_RAAMMT_FGR_PRI,
	    SPD_KEY_DDR5_RFM_BRC_CFG_PRI, SPD_KEY_DDR5_RFM_BRC_SUP_PRI,
	    SPD_KEY_DDR5_RFM_RAA_DEC_PRI);
}

static void
spd_parse_ddr5_rfm_sec(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	if (!spd_parse_ddr5_isassym(si))
		return;

	spd_parse_ddr5_rfm_flags(si, si->si_data[off], si->si_data[off + 1],
	    SPD_KEY_DDR5_RFM_FLAGS_SEC);
	spd_parse_ddr5_rfm_common(si, si->si_data[off], si->si_data[off + 1],
	    SPD_KEY_DDR5_RFM_RAAIMT_SEC, SPD_KEY_DDR5_RFM_RAAIMT_FGR_SEC,
	    SPD_KEY_DDR5_RFM_RAAMMT_SEC, SPD_KEY_DDR5_RFM_RAAMMT_FGR_SEC,
	    SPD_KEY_DDR5_RFM_BRC_CFG_SEC, SPD_KEY_DDR5_RFM_BRC_SUP_SEC,
	    SPD_KEY_DDR5_RFM_RAA_DEC_SEC);
}

static void
spd_parse_ddr5_arfma_pri(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 2);

	if (SPD_DDR5_ARFM_SUP(si->si_data[off]) == 0)
		return;

	spd_parse_ddr5_arfm_flags(si, si->si_data[off + 1],
	    SPD_KEY_DDR5_ARFMA_FLAGS_PRI);
	spd_parse_ddr5_rfm_common(si, si->si_data[off], si->si_data[off + 1],
	    SPD_KEY_DDR5_ARFMA_RAAIMT_PRI, SPD_KEY_DDR5_ARFMA_RAAIMT_FGR_PRI,
	    SPD_KEY_DDR5_ARFMA_RAAMMT_PRI, SPD_KEY_DDR5_ARFMA_RAAMMT_FGR_PRI,
	    SPD_KEY_DDR5_ARFMA_BRC_CFG_PRI, SPD_KEY_DDR5_ARFMA_BRC_SUP_PRI,
	    SPD_KEY_DDR5_ARFMA_RAA_DEC_PRI);
}

static void
spd_parse_ddr5_arfma_sec(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	if (!spd_parse_ddr5_isassym(si))
		return;

	if (SPD_DDR5_ARFM_SUP(si->si_data[off]) == 0)
		return;

	spd_parse_ddr5_arfm_flags(si, si->si_data[off + 1],
	    SPD_KEY_DDR5_ARFMA_FLAGS_SEC);
	spd_parse_ddr5_rfm_common(si, si->si_data[off], si->si_data[off + 1],
	    SPD_KEY_DDR5_ARFMA_RAAIMT_SEC, SPD_KEY_DDR5_ARFMA_RAAIMT_FGR_SEC,
	    SPD_KEY_DDR5_ARFMA_RAAMMT_SEC, SPD_KEY_DDR5_ARFMA_RAAMMT_FGR_SEC,
	    SPD_KEY_DDR5_ARFMA_BRC_CFG_SEC, SPD_KEY_DDR5_ARFMA_BRC_SUP_SEC,
	    SPD_KEY_DDR5_ARFMA_RAA_DEC_SEC);
}

static void
spd_parse_ddr5_arfmb_pri(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 2);

	if (SPD_DDR5_ARFM_SUP(si->si_data[off]) == 0)
		return;

	spd_parse_ddr5_arfm_flags(si, si->si_data[off + 1],
	    SPD_KEY_DDR5_ARFMB_FLAGS_PRI);
	spd_parse_ddr5_rfm_common(si, si->si_data[off], si->si_data[off + 1],
	    SPD_KEY_DDR5_ARFMB_RAAIMT_PRI, SPD_KEY_DDR5_ARFMB_RAAIMT_FGR_PRI,
	    SPD_KEY_DDR5_ARFMB_RAAMMT_PRI, SPD_KEY_DDR5_ARFMB_RAAMMT_FGR_PRI,
	    SPD_KEY_DDR5_ARFMB_BRC_CFG_PRI, SPD_KEY_DDR5_ARFMB_BRC_SUP_PRI,
	    SPD_KEY_DDR5_ARFMB_RAA_DEC_PRI);
}

static void
spd_parse_ddr5_arfmb_sec(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	if (!spd_parse_ddr5_isassym(si))
		return;

	if (SPD_DDR5_ARFM_SUP(si->si_data[off]) == 0)
		return;

	spd_parse_ddr5_arfm_flags(si, si->si_data[off + 1],
	    SPD_KEY_DDR5_ARFMB_FLAGS_SEC);
	spd_parse_ddr5_rfm_common(si, si->si_data[off], si->si_data[off + 1],
	    SPD_KEY_DDR5_ARFMB_RAAIMT_SEC, SPD_KEY_DDR5_ARFMB_RAAIMT_FGR_SEC,
	    SPD_KEY_DDR5_ARFMB_RAAMMT_SEC, SPD_KEY_DDR5_ARFMB_RAAMMT_FGR_SEC,
	    SPD_KEY_DDR5_ARFMB_BRC_CFG_SEC, SPD_KEY_DDR5_ARFMB_BRC_SUP_SEC,
	    SPD_KEY_DDR5_ARFMB_RAA_DEC_SEC);
}

static void
spd_parse_ddr5_arfmc_pri(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 2);

	if (SPD_DDR5_ARFM_SUP(si->si_data[off]) == 0)
		return;

	spd_parse_ddr5_arfm_flags(si, si->si_data[off + 1],
	    SPD_KEY_DDR5_ARFMC_FLAGS_PRI);
	spd_parse_ddr5_rfm_common(si, si->si_data[off], si->si_data[off + 1],
	    SPD_KEY_DDR5_ARFMC_RAAIMT_PRI, SPD_KEY_DDR5_ARFMC_RAAIMT_FGR_PRI,
	    SPD_KEY_DDR5_ARFMC_RAAMMT_PRI, SPD_KEY_DDR5_ARFMC_RAAMMT_FGR_PRI,
	    SPD_KEY_DDR5_ARFMC_BRC_CFG_PRI, SPD_KEY_DDR5_ARFMC_BRC_SUP_PRI,
	    SPD_KEY_DDR5_ARFMC_RAA_DEC_PRI);
}

static void
spd_parse_ddr5_arfmc_sec(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	if (!spd_parse_ddr5_isassym(si))
		return;

	if (SPD_DDR5_ARFM_SUP(si->si_data[off]) == 0)
		return;

	spd_parse_ddr5_arfm_flags(si, si->si_data[off + 1],
	    SPD_KEY_DDR5_ARFMC_FLAGS_SEC);
	spd_parse_ddr5_rfm_common(si, si->si_data[off], si->si_data[off + 1],
	    SPD_KEY_DDR5_ARFMC_RAAIMT_SEC, SPD_KEY_DDR5_ARFMC_RAAIMT_FGR_SEC,
	    SPD_KEY_DDR5_ARFMC_RAAMMT_SEC, SPD_KEY_DDR5_ARFMC_RAAMMT_FGR_SEC,
	    SPD_KEY_DDR5_ARFMC_BRC_CFG_SEC, SPD_KEY_DDR5_ARFMC_BRC_SUP_SEC,
	    SPD_KEY_DDR5_ARFMC_RAA_DEC_SEC);
}

static const spd_parse_t spd_ddr5_base[] = {
	{ .sp_off = SPD_DDR5_NBYTES, .sp_parse = spd_parse_ddr5_nbytes },
	{ .sp_off = SPD_DDR5_SPD_REV, .sp_parse = spd_parse_rev },
	/*
	 * We have previously validated that the DRAM type is something that we
	 * understand. We pass through the raw enum to users here.
	 */
	{ .sp_off = SPD_DDR5_DRAM_TYPE, .sp_key = SPD_KEY_DRAM_TYPE,
	    .sp_parse = spd_parse_raw_u8 },
	{ .sp_off = SPD_DDR5_MOD_TYPE, .sp_parse = spd_parse_ddr5_mod_type },
	/*
	 * All secondary values must check whether an asymmetrical module is
	 * present in Byte 234. As such, for the secondary versions we set LEN
	 * to include that value. They then move to a common function.
	 */
	{ .sp_off = SPD_DDR5_DENPKG1, .sp_parse = spd_parse_ddr5_denpkg_pri },
	{ .sp_off = SPD_DDR5_DENPKG2, .sp_parse = spd_parse_ddr5_denpkg_sec,
	    .sp_len = SPD_DDR5_COM_ORG - SPD_DDR5_DENPKG2 + 1 },
	{ .sp_off = SPD_DDR5_ADDR1, .sp_parse = spd_parse_ddr5_addr_pri },
	{ .sp_off = SPD_DDR5_ADDR2, .sp_parse = spd_parse_ddr5_addr_sec,
	    .sp_len = SPD_DDR5_COM_ORG - SPD_DDR5_ADDR2 + 1 },
	{ .sp_off = SPD_DDR5_WIDTH1, .sp_parse = spd_parse_ddr5_width_pri },
	{ .sp_off = SPD_DDR5_WIDTH2, .sp_parse = spd_parse_ddr5_width_sec,
	    .sp_len = SPD_DDR5_COM_ORG - SPD_DDR5_WIDTH2 + 1 },
	{ .sp_off = SPD_DDR5_BANKS1, .sp_parse = spd_parse_ddr5_banks_pri },
	{ .sp_off = SPD_DDR5_BANKS2, .sp_parse = spd_parse_ddr5_banks_sec,
	    .sp_len = SPD_DDR5_COM_ORG - SPD_DDR5_BANKS2 + 1 },
	{ .sp_off = SPD_DDR5_PPR, .sp_parse = spd_parse_ddr5_ppr },
	{ .sp_off = SPD_DDR5_SDA, .sp_parse = spd_parse_ddr5_dca },
	{ .sp_off = SPD_DDR5_FLT, .sp_parse = spd_parse_ddr5_flt },
	{ .sp_off = SPD_DDR5_DRAM_VDD, .sp_key = SPD_KEY_NOM_VDD,
	    .sp_parse = spd_parse_ddr5_vdd },
	{ .sp_off = SPD_DDR5_DRAM_VDDQ, .sp_key = SPD_KEY_NOM_VDDQ,
	    .sp_parse = spd_parse_ddr5_vddq },
	{ .sp_off = SPD_DDR5_DRAM_VPP, .sp_key = SPD_KEY_NOM_VPP,
	    .sp_parse = spd_parse_ddr5_vpp },
	{ .sp_off = SPD_DDR5_TIME, .sp_parse = spd_parse_ddr5_time },
	{ .sp_off = SPD_DDR5_TCKAVG_MIN_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TCKAVG_MIN, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_TCKAVG_MAX_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TCKAVG_MAX, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_CAS_SUP0, .sp_len = 5, .sp_key = SPD_KEY_CAS,
	    .sp_parse = spd_parse_ddr5_cas },
	{ .sp_off = SPD_DDR5_TAA_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TAA_MIN, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_TRCD_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TRCD_MIN, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_TRP_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TRP_MIN, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_TRAS_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TRAS_MIN, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_TRC_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TRC_MIN, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_TWR_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TWR_MIN, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_TRFC1_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TRFC1_MIN, .sp_parse = spd_parse_ddr5_ns },
	{ .sp_off = SPD_DDR5_TRFC2_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TRFC2_MIN, .sp_parse = spd_parse_ddr5_ns },
	{ .sp_off = SPD_DDR5_TRFCSB_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TRFCSB, .sp_parse = spd_parse_ddr5_ns },
	{ .sp_off = SPD_DDR5_3DS_TRFC1_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TRFC1_DLR, .sp_parse = spd_parse_ddr5_3ds_ns },
	{ .sp_off = SPD_DDR5_3DS_TRFC2_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TRFC2_DLR, .sp_parse = spd_parse_ddr5_3ds_ns },
	{ .sp_off = SPD_DDR5_3DS_TRFCSB_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TRFCSB_DLR, .sp_parse = spd_parse_ddr5_3ds_ns },
	{ .sp_off = SPD_DDR5_RFM0_SDRAM0, .sp_len = 2,
	    .sp_parse = spd_parse_ddr5_rfm_pri },
	{ .sp_off = SPD_DDR5_RFM0_SDRAM1, .sp_parse = spd_parse_ddr5_rfm_sec,
	    .sp_len = SPD_DDR5_COM_ORG - SPD_DDR5_RFM0_SDRAM1 + 1 },
	{ .sp_off = SPD_DDR5_ARFM0_A_SDRAM0, .sp_len = 2,
	    .sp_parse = spd_parse_ddr5_arfma_pri },
	{ .sp_off = SPD_DDR5_ARFM0_A_SDRAM1,
	    .sp_len = SPD_DDR5_COM_ORG - SPD_DDR5_ARFM0_A_SDRAM1 + 1,
	    .sp_parse = spd_parse_ddr5_arfma_sec },
	{ .sp_off = SPD_DDR5_ARFM0_B_SDRAM0, .sp_len = 2,
	    .sp_parse = spd_parse_ddr5_arfmb_pri },
	{ .sp_off = SPD_DDR5_ARFM0_B_SDRAM1,
	    .sp_len = SPD_DDR5_COM_ORG - SPD_DDR5_ARFM0_B_SDRAM1 + 1,
	    .sp_parse = spd_parse_ddr5_arfmb_sec },
	{ .sp_off = SPD_DDR5_ARFM0_C_SDRAM0, .sp_len = 2,
	    .sp_parse = spd_parse_ddr5_arfmc_pri },
	{ .sp_off = SPD_DDR5_ARFM0_C_SDRAM1,
	    .sp_len = SPD_DDR5_COM_ORG - SPD_DDR5_ARFM0_C_SDRAM1 + 1,
	    .sp_parse = spd_parse_ddr5_arfmc_sec },
	{ .sp_off = SPD_DDR5_TRRD_L_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TRRD_L_MIN, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_TRRD_L_NCK, .sp_key = SPD_KEY_TRRD_L_NCK,
	    .sp_parse = spd_parse_ddr5_nck },
	{ .sp_off = SPD_DDR5_TCCD_L_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TCCD_L_MIN, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_TCCD_L_NCK, .sp_key = SPD_KEY_TCCD_L_NCK,
	    .sp_parse = spd_parse_ddr5_nck },
	{ .sp_off = SPD_DDR5_TCCD_L_WR_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TCCDLWR, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_TCCD_L_WR_NCK, .sp_key = SPD_KEY_TCCDLWR_NCK,
	    .sp_parse = spd_parse_ddr5_nck },
	{ .sp_off = SPD_DDR5_TCCD_L_WR2_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TCCDLWR2, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_TCCD_L_WR2_NCK, .sp_key = SPD_KEY_TCCDLWR2_NCK,
	    .sp_parse = spd_parse_ddr5_nck },
	{ .sp_off = SPD_DDR5_TFAW_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TFAW, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_TFAW_NCK, .sp_key = SPD_KEY_TFAW_NCK,
	    .sp_parse = spd_parse_ddr5_nck },
	{ .sp_off = SPD_DDR5_TCCD_L_WTR_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TCCDLWTR, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_TCCD_L_WTR_NCK, .sp_key = SPD_KEY_TCCDLWTR_NCK,
	    .sp_parse = spd_parse_ddr5_nck },
	{ .sp_off = SPD_DDR5_TCCD_S_WTR_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TCCDSWTR, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_TCCD_S_WTR_NCK, .sp_key = SPD_KEY_TCCDSWTR_NCK,
	    .sp_parse = spd_parse_ddr5_nck },
	{ .sp_off = SPD_DDR5_TRTP_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TRTP, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_TRTP_NCK, .sp_key = SPD_KEY_TRTP_NCK,
	    .sp_parse = spd_parse_ddr5_nck }
};

/*
 * These are additional fields that were added in v1.2 of the SPD data.
 */
static const spd_parse_t spd_ddr5_base_1v2[] = {
	{ .sp_off = SPD_DDR5_TCCD_M_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TCCDM, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_TCCD_M_NCK, .sp_key = SPD_KEY_TCCDM_NCK,
	    .sp_parse = spd_parse_ddr5_nck },
	{ .sp_off = SPD_DDR5_TCCD_M_WR_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TCCDMWR, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_TCCD_M_WR_NCK, .sp_key = SPD_KEY_TCCDMWR_NCK,
	    .sp_parse = spd_parse_ddr5_nck },
	{ .sp_off = SPD_DDR5_TCCD_M_WTR_LSB, .sp_len = 2,
	    .sp_key = SPD_KEY_TCCDMWTR, .sp_parse = spd_parse_ddr5_ps },
	{ .sp_off = SPD_DDR5_TCCD_M_WTR_NCK, .sp_key = SPD_KEY_TCCDMWTR_NCK,
	    .sp_parse = spd_parse_ddr5_nck }

};

static void
spd_parse_ddr5_mod_rev(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t enc = SPD_DDR5_SPD_REV_ENC(data);
	const uint8_t add = SPD_DDR5_SPD_REV_ADD(data);

	spd_nvl_insert_u32(si, SPD_KEY_MOD_REV_ENC, enc);
	spd_nvl_insert_u32(si, SPD_KEY_MOD_REV_ADD, add);
}

static const spd_value_map_t spd_ddr5_hash_map[] = {
	{ SPD_DDR5_COM_HASH_NONE, 0, true },
	{ SPD_DDR5_COM_HASH_ALG1, SPD_HASH_SEQ_ALG_1, false }
};

static void
spd_parse_ddr5_hash_seq(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t alg = SPD_DDR5_COM_HASH_HASH(data);

	spd_insert_map(si, key, alg, spd_ddr5_hash_map,
	    ARRAY_SIZE(spd_ddr5_hash_map));
}

static void
spd_parse_ddr5_dev_common(spd_info_t *si, uint32_t off, spd_device_t flags,
    const char *id_key, const char *id_str_key, const char *rev_key,
    const char *type_key, const spd_value_map_t *type_map, size_t ntypes)
{
	const uint8_t type = SPD_DDR5_COM_INFO_TYPE(si->si_data[off + 2]);

	spd_parse_jedec_id(si, off, 2, id_key);
	spd_parse_jedec_id_str(si, off, 2, id_str_key);
	spd_parse_hex_vers(si, off + 3, 1, rev_key);
	spd_upsert_flag(si, SPD_KEY_DEVS, flags);
	spd_insert_map(si, type_key, type, type_map, ntypes);
}

static const spd_value_map_t spd_ddr5_spd_type_map[] = {
	{ SPD_DDR5_COM_INFO_TYPE_SPD5118, SPD_SPD_T_SPD5118, false },
	{ SPD_DDR5_COM_INFO_TYPE_ESPD5216, SPD_SPD_T_ESPD5216, false }
};

static void
spd_parse_ddr5_spd(spd_info_t *si, uint32_t off, uint32_t len, const char *key)
{
	ASSERT3U(len, ==, 4);
	const uint8_t type = si->si_data[off + 2];
	if (SPD_DDR5_COM_INFO_PRES(type) == 0)
		return;

	spd_parse_ddr5_dev_common(si, off, SPD_DEVICE_SPD, SPD_KEY_DEV_SPD_MFG,
	    SPD_KEY_DEV_SPD_MFG_NAME, SPD_KEY_DEV_SPD_REV, SPD_KEY_DEV_SPD_TYPE,
	    spd_ddr5_spd_type_map, ARRAY_SIZE(spd_ddr5_spd_type_map));
}

static const spd_value_map_t spd_ddr5_pmic_type_map[] = {
	{ SPD_DDR5_COM_INFO_TYPE_PMIC5000, SPD_PMIC_T_PMIC5000, false },
	{ SPD_DDR5_COM_INFO_TYPE_PMIC5010, SPD_PMIC_T_PMIC5010, false },
	{ SPD_DDR5_COM_INFO_TYPE_PMIC5100, SPD_PMIC_T_PMIC5100, false },
	{ SPD_DDR5_COM_INFO_TYPE_PMIC5020, SPD_PMIC_T_PMIC5020, false },
	{ SPD_DDR5_COM_INFO_TYPE_PMIC5120, SPD_PMIC_T_PMIC5120, false },
	{ SPD_DDR5_COM_INFO_TYPE_PMIC5200, SPD_PMIC_T_PMIC5200, false },
	{ SPD_DDR5_COM_INFO_TYPE_PMIC5030, SPD_PMIC_T_PMIC5030, false },
};

static void
spd_parse_ddr5_pmic0(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 4);
	const uint8_t type = si->si_data[off + 2];
	if (SPD_DDR5_COM_INFO_PRES(type) == 0)
		return;

	spd_parse_ddr5_dev_common(si, off, SPD_DEVICE_PMIC_0,
	    SPD_KEY_DEV_PMIC0_MFG, SPD_KEY_DEV_PMIC0_MFG_NAME,
	    SPD_KEY_DEV_PMIC0_REV, SPD_KEY_DEV_PMIC0_TYPE,
	    spd_ddr5_pmic_type_map, ARRAY_SIZE(spd_ddr5_pmic_type_map));
}

static void
spd_parse_ddr5_pmic1(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 4);
	const uint8_t type = si->si_data[off + 2];
	if (SPD_DDR5_COM_INFO_PRES(type) == 0)
		return;

	spd_parse_ddr5_dev_common(si, off, SPD_DEVICE_PMIC_1,
	    SPD_KEY_DEV_PMIC1_MFG, SPD_KEY_DEV_PMIC1_MFG_NAME,
	    SPD_KEY_DEV_PMIC1_REV, SPD_KEY_DEV_PMIC1_TYPE,
	    spd_ddr5_pmic_type_map, ARRAY_SIZE(spd_ddr5_pmic_type_map));
}

static void
spd_parse_ddr5_pmic2(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 4);
	const uint8_t type = si->si_data[off + 2];
	if (SPD_DDR5_COM_INFO_PRES(type) == 0)
		return;

	spd_parse_ddr5_dev_common(si, off, SPD_DEVICE_PMIC_2,
	    SPD_KEY_DEV_PMIC2_MFG, SPD_KEY_DEV_PMIC2_MFG_NAME,
	    SPD_KEY_DEV_PMIC2_REV, SPD_KEY_DEV_PMIC2_TYPE,
	    spd_ddr5_pmic_type_map, ARRAY_SIZE(spd_ddr5_pmic_type_map));
}

static const spd_value_map_t spd_ddr5_temp_type_map[] = {
	{ SPD_DDR5_COM_INFO_TYPE_TS5111, SPD_TEMP_T_TS5111, false },
	{ SPD_DDR5_COM_INFO_TYPE_TS5110, SPD_TEMP_T_TS5110, false },
	{ SPD_DDR5_COM_INFO_TYPE_TS5211, SPD_TEMP_T_TS5211, false },
	{ SPD_DDR5_COM_INFO_TYPE_TS5210, SPD_TEMP_T_TS5210, false }
};

static void
spd_parse_ddr5_ts(spd_info_t *si, uint32_t off, uint32_t len, const char *key)
{
	ASSERT3U(len, ==, 4);
	const uint8_t type = si->si_data[off + 2];
	spd_device_t flags = 0;
	if (SPD_DDR5_COM_INFO_PRES(type) != 0)
		flags |= SPD_DEVICE_TEMP_1;
	if (SPD_DDR5_COM_INFO_TS1_PRES(type) != 0)
		flags |= SPD_DEVICE_TEMP_2;
	if (flags == 0)
		return;

	spd_parse_ddr5_dev_common(si, off, flags, SPD_KEY_DEV_TEMP_MFG,
	    SPD_KEY_DEV_TEMP_MFG_NAME, SPD_KEY_DEV_TEMP_REV,
	    SPD_KEY_DEV_TEMP_TYPE, spd_ddr5_temp_type_map,
	    ARRAY_SIZE(spd_ddr5_temp_type_map));
}

/*
 * While DDR5 uses similar constants as earlier DDR standards, less values have
 * been officially defined yet so we use a different table from the others.
 */
static const spd_str_map_t spd_ddr5_design_map[] = {
	{ 0, "A", false },
	{ 1, "B", false },
	{ 2, "C", false },
	{ 3, "D", false },
	{ 4, "E", false },
	{ 5, "F", false },
	{ 6, "G", false },
	{ 7, "H", false },
	{ 8, "J", false },
	{ 9, "K", false },
	{ 10, "L", false },
	{ 11, "M", false },
	{ 12, "N", false },
	{ 13, "P", false },
	{ 14, "R", false },
	{ 15, "T", false },
	{ 16, "U", false },
	{ 17, "V", false },
	{ 18, "W", false },
	{ 19, "Y", false },
	{ 20, "AA", false },
	{ 21, "AB", false },
	{ 22, "AC", false },
	{ 23, "AD", false },
	{ 24, "AE", false },
	{ 25, "AF", false },
	{ 26, "AG", false },
	{ 27, "AH", false },
	{ 28, "AJ", false },
	{ 29, "AK", false },
	{ 31, "ZZ", false }
};

static const spd_value_range_t spd_ddr5_design_rev_range = {
	.svr_max = SPD_DDR5_COM_REF_REV_MAX
};

static void
spd_parse_ddr5_design(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t rev = SPD_DDR5_COM_REF_REV(data);
	const uint8_t card = SPD_DDR5_COM_REF_CARD(data);

	spd_insert_str_map(si, SPD_KEY_MOD_REF_DESIGN, card,
	    spd_ddr5_design_map, ARRAY_SIZE(spd_ddr5_design_map));
	spd_insert_range(si, SPD_KEY_MOD_DESIGN_REV, rev,
	    &spd_ddr5_design_rev_range);
}

static const spd_value_map_t spd_ddr5_attr_nrows_map[] = {
	{ SPD_DDR5_COM_ATTR_NROWS_UNDEF, 0, true },
	{ SPD_DDR5_COM_ATTR_NROWS_1, 1, false },
	{ SPD_DDR5_COM_ATTR_NROWS_2, 2, false }
};

static const spd_value_map_t spd_ddr5_attr_otr_map[] = {
	{ SPD_DDR5_COM_ATTR_OTR_A1T, JEDEC_TEMP_CASE_A1T, false },
	{ SPD_DDR5_COM_ATTR_OTR_A2T, JEDEC_TEMP_CASE_A2T, false },
	{ SPD_DDR5_COM_ATTR_OTR_A3T, JEDEC_TEMP_CASE_A3T, false },
	{ SPD_DDR5_COM_ATTR_OTR_IT, JEDEC_TEMP_CASE_IT, false },
	{ SPD_DDR5_COM_ATTR_OTR_ST, JEDEC_TEMP_CASE_ST, false },
	{ SPD_DDR5_COM_ATTR_OTR_ET, JEDEC_TEMP_CASE_ET, false },
	{ SPD_DDR5_COM_ATTR_OTR_RT, JEDEC_TEMP_CASE_RT, false },
	{ SPD_DDR5_COM_ATTR_OTR_NT, JEDEC_TEMP_CASE_NT, false },
	{ SPD_DDR5_COM_ATTR_OTR_XT, JEDEC_TEMP_CASE_XT, false }
};

static void
spd_parse_ddr5_attr(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t otr = SPD_DDR5_COM_ATTR_OTR(data);
	const uint8_t nrows = SPD_DDR5_COM_ATTR_NROWS(data);

	if (SPD_DDR5_COM_ATTR_SPREAD(data) != 0)
		spd_upsert_flag(si, SPD_KEY_DEVS, SPD_DEVICE_HS);
	spd_insert_map(si, SPD_KEY_MOD_NROWS, nrows,
	    spd_ddr5_attr_nrows_map, ARRAY_SIZE(spd_ddr5_attr_nrows_map));
	spd_insert_map(si, SPD_KEY_MOD_OPER_TEMP, otr,
	    spd_ddr5_attr_otr_map, ARRAY_SIZE(spd_ddr5_attr_otr_map));
}

static const spd_value_range_t spd_ddr5_nrank_range = {
	.svr_base = SPD_DDR5_COM_ORG_NRANK_BASE
};

static void
spd_parse_ddr5_mod_org(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t nranks = SPD_DDR4_MOD_ORG_NPKG_RANK(data);

	if (SPD_DDR5_COM_ORG_MIX(data) == SPD_DDR5_COM_ORG_MIX_ASYM)
		spd_nvl_insert_key(si, SPD_KEY_RANK_ASYM);
	spd_insert_range(si, SPD_KEY_NRANKS, nranks, &spd_ddr5_nrank_range);
}

static const spd_value_map_t spd_ddr5_ext_width[] = {
	{ SPD_DDR5_COM_BUS_WIDTH_EXT_NONE, 0, false },
	{ SPD_DDR5_COM_BUS_WIDTH_EXT_4b, 4, false },
	{ SPD_DDR5_COM_BUS_WIDTH_EXT_8b, 8, false }
};

static const spd_value_map_t spd_ddr5_pri_width[] = {
	{ SPD_DDR5_COM_BUS_WIDTH_PRI_8b, 8, false },
	{ SPD_DDR5_COM_BUS_WIDTH_PRI_16b, 16, false },
	{ SPD_DDR5_COM_BUS_WIDTH_PRI_32b, 32, false },
	{ SPD_DDR5_COM_BUS_WIDTH_PRI_64b, 64, false },
};

static const spd_value_range_t spd_ddr5_nsc_range = {
	.svr_max = SPD_DDR5_COM_BUS_WIDTH_NSC_MAX,
	.svr_exp = true
};

static void
spd_parse_ddr5_bus_width(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t nsc = SPD_DDR5_COM_BUS_WIDTH_NSC(data);
	const uint8_t ext = SPD_DDR5_COM_BUS_WIDTH_EXT(data);
	const uint8_t pri = SPD_DDR5_COM_BUS_WIDTH_PRI(data);

	spd_insert_range(si, SPD_KEY_NSUBCHAN, nsc, &spd_ddr5_nsc_range);
	spd_nvl_insert_u32(si, SPD_KEY_DRAM_NCHAN, 1);
	spd_insert_map(si, SPD_KEY_ECC_WIDTH, ext, spd_ddr5_ext_width,
	    ARRAY_SIZE(spd_ddr5_ext_width));
	spd_insert_map(si, SPD_KEY_DATA_WIDTH, pri, spd_ddr5_pri_width,
	    ARRAY_SIZE(spd_ddr5_pri_width));
}

static const spd_parse_t spd_ddr5_module[] = {
	{ .sp_off = SPD_DDR5_COM_REV, .sp_parse = spd_parse_ddr5_mod_rev },
	{ .sp_off = SPD_DDR5_COM_HASH, .sp_parse = spd_parse_ddr5_hash_seq,
	    .sp_key = SPD_KEY_HASH_SEQ },
	{ .sp_off = SPD_DDR5_COM_MFG_ID0_SPD, .sp_len = 4,
	    .sp_parse = spd_parse_ddr5_spd },
	{ .sp_off = SPD_DDR5_COM_MFG_ID0_PMIC0, .sp_len = 4,
	    .sp_parse = spd_parse_ddr5_pmic0 },
	{ .sp_off = SPD_DDR5_COM_MFG_ID0_PMIC1, .sp_len = 4,
	    .sp_parse = spd_parse_ddr5_pmic1 },
	{ .sp_off = SPD_DDR5_COM_MFG_ID0_PMIC2, .sp_len = 4,
	    .sp_parse = spd_parse_ddr5_pmic2 },
	{ .sp_off = SPD_DDR5_COM_MFG_ID0_TS, .sp_len = 4,
	    .sp_parse = spd_parse_ddr5_ts },
	{ .sp_off = SPD_DDR5_COM_HEIGHT, .sp_key = SPD_KEY_MOD_HEIGHT,
	    .sp_parse = spd_parse_height },
	{ .sp_off = SPD_DDR5_COM_THICK, .sp_parse = spd_parse_thickness },
	{ .sp_off = SPD_DDR5_COM_REF, .sp_parse = spd_parse_ddr5_design },
	{ .sp_off = SPD_DDR5_COM_ATTR, .sp_parse = spd_parse_ddr5_attr },
	{ .sp_off = SPD_DDR5_COM_ORG, .sp_parse = spd_parse_ddr5_mod_org },
	{ .sp_off = SPD_DDR5_COM_BUS_WIDTH,
	    .sp_parse = spd_parse_ddr5_bus_width },
	/* We include the DDR5 CRC in this group as it's considered common */
	{ .sp_len = SPD_DDR5_CRC_MSB + 1, .sp_key = SPD_KEY_CRC_DDR5,
	    .sp_parse = spd_parse_crc },
};

static const spd_parse_t spd_ddr5_mfg[] = {
	{ .sp_off = SPD_DDR5_MOD_MFG_ID0, .sp_len = 2,
	    .sp_key = SPD_KEY_MFG_MOD_MFG_ID, .sp_parse = spd_parse_jedec_id },
	{ .sp_off = SPD_DDR5_MOD_MFG_ID0, .sp_len = 2,
	    .sp_key = SPD_KEY_MFG_MOD_MFG_NAME,
	    .sp_parse = spd_parse_jedec_id_str },
	{ .sp_off = SPD_DDR5_DRAM_MFG_ID0, .sp_len = 2,
	    .sp_key = SPD_KEY_MFG_DRAM_MFG_ID, .sp_parse = spd_parse_jedec_id },
	{ .sp_off = SPD_DDR5_DRAM_MFG_ID0, .sp_len = 2,
	    .sp_key = SPD_KEY_MFG_DRAM_MFG_NAME,
	    .sp_parse = spd_parse_jedec_id_str },
	{ .sp_off = SPD_DDR5_MOD_MFG_LOC, .sp_key = SPD_KEY_MFG_MOD_LOC_ID,
	    .sp_parse = spd_parse_raw_u8 },
	{ .sp_off = SPD_DDR5_MOD_MFG_YEAR, .sp_key = SPD_KEY_MFG_MOD_YEAR,
	    .sp_parse = spd_parse_hex_string },
	{ .sp_off = SPD_DDR5_MOD_MFG_WEEK, .sp_key = SPD_KEY_MFG_MOD_WEEK,
	    .sp_parse = spd_parse_hex_string },
	{ .sp_off = SPD_DDR5_MOD_SN, .sp_len = SPD_DDR5_MOD_SN_LEN,
	    .sp_key = SPD_KEY_MFG_MOD_SN, .sp_parse = spd_parse_hex_string },
	{ .sp_off = SPD_DDR5_MOD_PN, .sp_len = SPD_DDR5_MOD_PN_LEN,
	    .sp_key = SPD_KEY_MFG_MOD_PN, .sp_parse = spd_parse_string },
	{ .sp_off = SPD_DDR5_MOD_REV, .sp_key = SPD_KEY_MFG_MOD_REV,
	    .sp_parse = spd_parse_dram_step },
	{ .sp_off = SPD_DDR5_DRAM_STEP, .sp_key = SPD_KEY_MFG_DRAM_STEP,
	    .sp_parse = spd_parse_dram_step }
};

/*
 * Annex A.2 UDIMM and SODIMM specific processing.
 */

static const spd_value_map_t spd_ddr5_cd_type_map[] = {
	{ SPD_DDR5_UDIMM_INFO_TYPE_DDR5CK01, SPD_CD_T_DDR5CK01, false }
};

static void
spd_parse_ddr5_udimm_cd(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 4);
	const uint8_t type = si->si_data[off + 2];
	if (SPD_DDR5_COM_INFO_PRES(type) == 0)
		return;

	spd_parse_ddr5_dev_common(si, off, SPD_DEVICE_CD_0,
	    SPD_KEY_DEV_CD0_MFG, SPD_KEY_DEV_CD0_MFG_NAME,
	    SPD_KEY_DEV_CD0_REV, SPD_KEY_DEV_CD0_TYPE,
	    spd_ddr5_cd_type_map, ARRAY_SIZE(spd_ddr5_cd_type_map));
}

static void
spd_parse_ddr5_udimm_ckd_cfg(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];

	if (SPD_DDR5_UDIMM_CKD_CFG_CHAQCK0(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_CKD_CHAQCK0_EN);
	if (SPD_DDR5_UDIMM_CKD_CFG_CHAQCK1(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_CKD_CHAQCK1_EN);
	if (SPD_DDR5_UDIMM_CKD_CFG_CHBQCK0(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_CKD_CHBQCK0_EN);
	if (SPD_DDR5_UDIMM_CKD_CFG_CHBQCK1(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_CKD_CHBQCK1_EN);
}

static const spd_value_map_t spd_ddr5_ckd_ds_map[] = {
	{ SPD_DDR5_UDIMM_CKD_DRV_LIGHT, SPD_DRIVE_LIGHT, false },
	{ SPD_DDR5_UDIMM_CKD_DRV_MODERATE, SPD_DRIVE_MODERATE, false },
	{ SPD_DDR5_UDIMM_CKD_DRV_STRONG, SPD_DRIVE_STRONG, false },
	{ SPD_DDR5_UDIMM_CKD_DRV_WEAK, SPD_DRIVE_WEAK, false }
};

static void
spd_parse_ddr5_udimm_ckd_drv(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t qck0a = SPD_DDR5_UDIMM_CKD_DRV_CHAQCK0_DRIVE(data);
	const uint8_t qck1a = SPD_DDR5_UDIMM_CKD_DRV_CHAQCK1_DRIVE(data);
	const uint8_t qck0b = SPD_DDR5_UDIMM_CKD_DRV_CHBQCK0_DRIVE(data);
	const uint8_t qck1b = SPD_DDR5_UDIMM_CKD_DRV_CHBQCK1_DRIVE(data);


	spd_insert_map(si, SPD_KEY_DDR5_CKD_CHAQCK0_DS, qck0a,
	    spd_ddr5_ckd_ds_map, ARRAY_SIZE(spd_ddr5_ckd_ds_map));
	spd_insert_map(si, SPD_KEY_DDR5_CKD_CHAQCK1_DS, qck1a,
	    spd_ddr5_ckd_ds_map, ARRAY_SIZE(spd_ddr5_ckd_ds_map));
	spd_insert_map(si, SPD_KEY_DDR5_CKD_CHBQCK0_DS, qck0b,
	    spd_ddr5_ckd_ds_map, ARRAY_SIZE(spd_ddr5_ckd_ds_map));
	spd_insert_map(si, SPD_KEY_DDR5_CKD_CHBQCK1_DS, qck1b,
	    spd_ddr5_ckd_ds_map, ARRAY_SIZE(spd_ddr5_ckd_ds_map));
}

static const spd_value_map_t spd_ddr5_ckd_slew_map[] = {
	{ SPD_DDR5_UDIMM_CKD_SLEW_SLEW_MODERATE, SPD_SLEW_MODERATE, false },
	{ SPD_DDR5_UDIMM_CKD_SLEW_SLEW_FAST, SPD_SLEW_FAST, false }
};

static void
spd_parse_ddr5_udimm_ckd_slew(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t qcka = SPD_DDR5_UDIMM_CKD_SLEW_CHAQCK_SLEW(data);
	const uint8_t qckb = SPD_DDR5_UDIMM_CKD_SLEW_CHBQCK_SLEW(data);

	spd_insert_map(si, SPD_KEY_DDR5_CKD_CHAQCK_SLEW, qcka,
	    spd_ddr5_ckd_slew_map, ARRAY_SIZE(spd_ddr5_ckd_slew_map));
	spd_insert_map(si, SPD_KEY_DDR5_CKD_CHBQCK_SLEW, qckb,
	    spd_ddr5_ckd_slew_map, ARRAY_SIZE(spd_ddr5_ckd_slew_map));
}

static const spd_parse_t spd_ddr5_udimm[] = {
	{ .sp_off = SPD_DDR5_COM_MFG_ID0_TS, .sp_len = 4,
	    .sp_parse = spd_parse_ddr5_udimm_cd }
};

static const spd_parse_t spd_ddr5_udimm_1v1[] = {
	{ .sp_off = SPD_DDR5_UDIMM_CKD_CFG,
	    .sp_parse = spd_parse_ddr5_udimm_ckd_cfg },
	{ .sp_off = SPD_DDR5_UDIMM_CKD_DRV,
	    .sp_parse = spd_parse_ddr5_udimm_ckd_drv },
	{ .sp_off = SPD_DDR5_UDIMM_CKD_SLEW,
	    .sp_parse = spd_parse_ddr5_udimm_ckd_slew }
};

/*
 * Annex A.3 RDIMM and LRDIMM specific processing. Because certain fields are
 * LRDIMM-only, we use two different top-level tables to drive them; however,
 * they generally overlap otherwise. Items that are LRDIMM only will contain
 * lrdimm in the name. All items named rdimm are shared between both the LRDIMM
 * and RDIMM processing.
 */
static const spd_value_map_t spd_ddr5_rcd_type_map[] = {
	{ SPD_DDR5_RDIMM_INFO_TYPE_RCD01, SPD_RCD_T_DDR5RCD01, false },
	{ SPD_DDR5_RDIMM_INFO_TYPE_RCD02, SPD_RCD_T_DDR5RCD02, false },
	{ SPD_DDR5_RDIMM_INFO_TYPE_RCD03, SPD_RCD_T_DDR5RCD03, false },
	{ SPD_DDR5_RDIMM_INFO_TYPE_RCD04, SPD_RCD_T_DDR5RCD04, false },
	{ SPD_DDR5_RDIMM_INFO_TYPE_RCD05, SPD_RCD_T_DDR5RCD05, false }
};

static const spd_value_map_t spd_ddr5_db_type_map[] = {
	{ SPD_DDR5_RDIMM_INFO_TYPE_DB01, SPD_DB_T_DDR5DB01, false },
	{ SPD_DDR5_RDIMM_INFO_TYPE_DB02, SPD_DB_T_DDR5DB02, false }
};

static void
spd_parse_ddr5_rdimm_rcd(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 4);
	const uint8_t type = si->si_data[off + 2];
	if (SPD_DDR5_COM_INFO_PRES(type) == 0)
		return;

	spd_parse_ddr5_dev_common(si, off, SPD_DEVICE_RCD,
	    SPD_KEY_DEV_RCD_MFG, SPD_KEY_DEV_RCD_MFG_NAME,
	    SPD_KEY_DEV_RCD_REV, SPD_KEY_DEV_RCD_TYPE,
	    spd_ddr5_rcd_type_map, ARRAY_SIZE(spd_ddr5_rcd_type_map));
}

static void
spd_parse_ddr5_lrdimm_db(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 4);
	const uint8_t type = si->si_data[off + 2];
	if (SPD_DDR5_COM_INFO_PRES(type) == 0)
		return;

	spd_parse_ddr5_dev_common(si, off, SPD_DEVICE_DB,
	    SPD_KEY_DEV_DB_MFG, SPD_KEY_DEV_DB_MFG_NAME,
	    SPD_KEY_DEV_DB_REV, SPD_KEY_DEV_DB_TYPE,
	    spd_ddr5_db_type_map, ARRAY_SIZE(spd_ddr5_db_type_map));
}

static void
spd_parse_ddr5_rdimm_clken(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];

	if (SPD_DDR5_RDIMM_CLKEN_QACK(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_RCD_QACK_EN);
	if (SPD_DDR5_RDIMM_CLKEN_QBCK(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_RCD_QBCK_EN);
	if (SPD_DDR5_RDIMM_CLKEN_QCCK(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_RCD_QCCK_EN);
	if (SPD_DDR5_RDIMM_CLKEN_QDCK(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_RCD_QDCK_EN);
	if (SPD_DDR5_RDIMM_CLKEN_BCK(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_RCD_BCK_EN);
}

static void
spd_parse_ddr5_rdimm_rwen(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];

	if (SPD_DDR5_RDIMM_RW09_QBCS(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_RCD_QBCS_EN);
	if (SPD_DDR5_RDIMM_RW09_QACS(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_RCD_QACS_EN);
	if (SPD_DDR5_RDIMM_RW09_QXCA13(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_RCD_QxCA13_EN);
	if (SPD_DDR5_RDIMM_RW09_BCS(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_RCD_BCS_EN);
	if (SPD_DDR5_RDIMM_RW09_DCS(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_RCD_QxCS_EN);
	if (SPD_DDR5_RDIMM_RW09_QBCA(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_RCD_QBCA_EN);
	if (SPD_DDR5_RDIMM_RW09_QACA(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_RCD_QACA_EN);
}

static const spd_value_map_t spd_ddr5_ds_map[] = {
	{ SPD_DDR5_RDIMM_DRV_LIGHT, SPD_DRIVE_LIGHT, false },
	{ SPD_DDR5_RDIMM_DRV_MODERATE, SPD_DRIVE_MODERATE, false },
	{ SPD_DDR5_RDIMM_DRV_STRONG, SPD_DRIVE_STRONG, false }
};

static void
spd_parse_ddr5_rdimm_clkimp(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t qack = SPD_DDR5_RDIMM_QCK_DRV_QACK(data);
	const uint8_t qbck = SPD_DDR5_RDIMM_QCK_DRV_QBCK(data);
	const uint8_t qcck = SPD_DDR5_RDIMM_QCK_DRV_QCCK(data);
	const uint8_t qdck = SPD_DDR5_RDIMM_QCK_DRV_QDCK(data);

	spd_insert_map(si, SPD_KEY_DDR5_RCD_QACK_DS, qack, spd_ddr5_ds_map,
	    ARRAY_SIZE(spd_ddr5_ds_map));
	spd_insert_map(si, SPD_KEY_DDR5_RCD_QBCK_DS, qbck, spd_ddr5_ds_map,
	    ARRAY_SIZE(spd_ddr5_ds_map));
	spd_insert_map(si, SPD_KEY_DDR5_RCD_QCCK_DS, qcck, spd_ddr5_ds_map,
	    ARRAY_SIZE(spd_ddr5_ds_map));
	spd_insert_map(si, SPD_KEY_DDR5_RCD_QDCK_DS, qdck, spd_ddr5_ds_map,
	    ARRAY_SIZE(spd_ddr5_ds_map));
}

static void
spd_parse_ddr5_rdimm_casimp(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t cs = SPD_DDR5_RDIMM_QCA_DRV_CS(data);
	const uint8_t ca = SPD_DDR5_RDIMM_QCA_DRV_CA(data);

	spd_insert_map(si, SPD_KEY_DDR5_RCD_QxCS_DS, cs, spd_ddr5_ds_map,
	    ARRAY_SIZE(spd_ddr5_ds_map));
	spd_insert_map(si, SPD_KEY_DDR5_RCD_CA_DS, ca, spd_ddr5_ds_map,
	    ARRAY_SIZE(spd_ddr5_ds_map));
}

static void
spd_parse_ddr5_lrdimm_dbimp(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t bck = SPD_DDR5_LRDIMM_DB_DRV_BCK(data);
	const uint8_t bcom = SPD_DDR5_LRDIMM_DB_DRV_BCOM(data);

	spd_insert_map(si, SPD_KEY_DDR5_RCD_BCK_DS, bck, spd_ddr5_ds_map,
	    ARRAY_SIZE(spd_ddr5_ds_map));
	spd_insert_map(si, SPD_KEY_DDR5_RCD_BCOM_DS, bcom, spd_ddr5_ds_map,
	    ARRAY_SIZE(spd_ddr5_ds_map));
}

static const spd_value_map_t spd_ddr5_rcd_slew_map[] = {
	{ SPD_DDR5_RDIMM_SLEW_MODERTE, SPD_SLEW_MODERATE, false },
	{ SPD_DDR5_RDIMM_SLEW_FAST, SPD_SLEW_FAST, false },
	{ SPD_DDR5_RDIMM_SLEW_SLOW, SPD_SLEW_SLOW, false }
};

static void
spd_parse_ddr5_rdimm_qslew(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t qcs = SPD_DDR5_RDIMM_QXX_SLEW_QCS(data);
	const uint8_t qca = SPD_DDR5_RDIMM_QXX_SLEW_QCA(data);
	const uint8_t qck = SPD_DDR5_RDIMM_QXX_SLEW_QCK(data);

	spd_insert_map(si, SPD_KEY_DDR5_RCD_QCK_SLEW, qck,
	    spd_ddr5_rcd_slew_map, ARRAY_SIZE(spd_ddr5_rcd_slew_map));
	spd_insert_map(si, SPD_KEY_DDR5_RCD_QCA_SLEW, qca,
	    spd_ddr5_rcd_slew_map, ARRAY_SIZE(spd_ddr5_rcd_slew_map));
	spd_insert_map(si, SPD_KEY_DDR5_RCD_QCS_SLEW, qcs,
	    spd_ddr5_rcd_slew_map, ARRAY_SIZE(spd_ddr5_rcd_slew_map));
}

static void
spd_parse_ddr5_lrdimm_bslew(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t bck = SPD_DDR5_LRDIMM_BXX_SLEW_BCK(data);
	const uint8_t bcom = SPD_DDR5_LRDIMM_BXX_SLEW_BCOM(data);

	spd_insert_map(si, SPD_KEY_DDR5_RCD_BCK_SLEW, bck,
	    spd_ddr5_rcd_slew_map, ARRAY_SIZE(spd_ddr5_rcd_slew_map));
	spd_insert_map(si, SPD_KEY_DDR5_RCD_BCOM_SLEW, bcom,
	    spd_ddr5_rcd_slew_map, ARRAY_SIZE(spd_ddr5_rcd_slew_map));
}

static const spd_value_map_t spd_ddr5_rtt_term_map[] = {
	{ SPD_DDR5_LDRIMM_PARK_OFF, 0, true },
	{ SPD_DDR5_LDRIMM_PARK_240R, 240, false },
	{ SPD_DDR5_LDRIMM_PARK_120R, 120, false },
	{ SPD_DDR5_LDRIMM_PARK_80R, 80, false },
	{ SPD_DDR5_LDRIMM_PARK_60R, 60, false },
	{ SPD_DDR5_LDRIMM_PARK_48R, 48, false },
	{ SPD_DDR5_LDRIMM_PARK_40R, 40, false },
	{ SPD_DDR5_LDRIMM_PARK_34R, 34, false }
};

static void
spd_parse_ddr5_lrdimm_rtt(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t rtt = SPD_DDR5_LRDIMM_PARK_TERM(data);

	spd_insert_map(si, SPD_KEY_DDR5_RCD_RTT_TERM, rtt,
	    spd_ddr5_rtt_term_map, ARRAY_SIZE(spd_ddr5_rtt_term_map));
}

static const spd_parse_t spd_ddr5_rdimm[] = {
	{ .sp_off = SPD_DDR5_RDIMM_MFG_ID0_RCD, .sp_len = 4,
	    .sp_parse = spd_parse_ddr5_rdimm_rcd },
	{ .sp_off = SPD_DDR5_RDIMM_CLKEN,
	    .sp_parse = spd_parse_ddr5_rdimm_clken },
	{ .sp_off = SPD_DDR5_RDIMM_RW09,
	    .sp_parse = spd_parse_ddr5_rdimm_rwen },
	{ .sp_off = SPD_DDR5_RDIMM_QCK_DRV,
	    .sp_parse = spd_parse_ddr5_rdimm_clkimp },
	{ .sp_off = SPD_DDR5_RDIMM_QCA_DRV,
	    .sp_parse = spd_parse_ddr5_rdimm_casimp },
	{ .sp_off = SPD_DDR5_RDIMM_QXX_SLEW,
	    .sp_parse = spd_parse_ddr5_rdimm_qslew }
};

static const spd_parse_t spd_ddr5_lrdimm[] = {
	{ .sp_off = SPD_DDR5_RDIMM_MFG_ID0_RCD, .sp_len = 4,
	    .sp_parse = spd_parse_ddr5_rdimm_rcd },
	{ .sp_off = SPD_DDR5_RDIMM_MFG_ID0_DB, .sp_len = 4,
	    .sp_parse = spd_parse_ddr5_lrdimm_db },
	{ .sp_off = SPD_DDR5_RDIMM_CLKEN,
	    .sp_parse = spd_parse_ddr5_rdimm_clken },
	{ .sp_off = SPD_DDR5_RDIMM_RW09,
	    .sp_parse = spd_parse_ddr5_rdimm_rwen },
	{ .sp_off = SPD_DDR5_RDIMM_QCK_DRV,
	    .sp_parse = spd_parse_ddr5_rdimm_clkimp },
	{ .sp_off = SPD_DDR5_RDIMM_QCA_DRV,
	    .sp_parse = spd_parse_ddr5_rdimm_casimp },
	{ .sp_off = SPD_DDR5_LRDIMM_DB_DRV,
	    .sp_parse = spd_parse_ddr5_lrdimm_dbimp },
	{ .sp_off = SPD_DDR5_RDIMM_QXX_SLEW,
	    .sp_parse = spd_parse_ddr5_rdimm_qslew },
	{ .sp_off = SPD_DDR5_LRDIMM_BXX_SLEW,
	    .sp_parse = spd_parse_ddr5_lrdimm_bslew },
	{ .sp_off = SPD_DDR5_LRDIMM_PARK,
	    .sp_parse = spd_parse_ddr5_lrdimm_rtt },
};

/*
 * Annex A.4 MRDIMM specific processing.
 */
static const spd_value_map_t spd_ddr5_mrcd_type_map[] = {
	{ SPD_DDR5_MRDIMM_INFO_TYPE_MRCD01, SPD_MRCD_T_DDR5MRCD01, false },
	{ SPD_DDR5_MRDIMM_INFO_TYPE_MRCD02, SPD_MRCD_T_DDR5MRCD02, false }
};

static const spd_value_map_t spd_ddr5_mdb_type_map[] = {
	{ SPD_DDR5_MRDIMM_INFO_TYPE_MDB01, SPD_MDB_T_DDR5MDB01, false },
	{ SPD_DDR5_MRDIMM_INFO_TYPE_MDB02, SPD_MDB_T_DDR5MDB02, false }
};

static void
spd_parse_ddr5_mrdimm_mrcd(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 4);
	const uint8_t type = si->si_data[off + 2];
	if (SPD_DDR5_COM_INFO_PRES(type) == 0)
		return;

	spd_parse_ddr5_dev_common(si, off, SPD_DEVICE_MRCD,
	    SPD_KEY_DEV_MRCD_MFG, SPD_KEY_DEV_MRCD_MFG_NAME,
	    SPD_KEY_DEV_MRCD_REV, SPD_KEY_DEV_MRCD_TYPE,
	    spd_ddr5_mrcd_type_map, ARRAY_SIZE(spd_ddr5_mrcd_type_map));
}

static void
spd_parse_ddr5_mrdimm_mdb(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 4);
	const uint8_t type = si->si_data[off + 2];
	if (SPD_DDR5_COM_INFO_PRES(type) == 0)
		return;

	spd_parse_ddr5_dev_common(si, off, SPD_DEVICE_MDB,
	    SPD_KEY_DEV_MDB_MFG, SPD_KEY_DEV_MDB_MFG_NAME,
	    SPD_KEY_DEV_MDB_REV, SPD_KEY_DEV_MDB_TYPE,
	    spd_ddr5_mdb_type_map, ARRAY_SIZE(spd_ddr5_mdb_type_map));
}

static const spd_parse_t spd_ddr5_mrdimm[] = {
	{ .sp_off = SPD_DDR5_MRDIMM_MFG_ID0_MRCD, .sp_len = 4,
	    .sp_parse = spd_parse_ddr5_mrdimm_mrcd },
	{ .sp_off = SPD_DDR5_MRDIMM_MFG_ID0_MDB, .sp_len = 4,
	    .sp_parse = spd_parse_ddr5_mrdimm_mdb }
};

static void
spd_parse_ddr5_mrdimm_cden(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];

	if (SPD_DDR5_MRDIMM_CDEN_QACK(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_MRCD_QACK_EN);
	if (SPD_DDR5_MRDIMM_CDEN_QBCK(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_MRCD_QBCK_EN);
	if (SPD_DDR5_MRDIMM_CDEN_QCCK(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_MRCD_QCCK_EN);
	if (SPD_DDR5_MRDIMM_CDEN_QDCK(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_MRCD_QDCK_EN);
	if (SPD_DDR5_MRDIMM_CDEN_BCK(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_MRCD_BCK_EN);
}

static void
spd_parse_ddr5_mrdimm_oacen(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];

	if (SPD_DDR5_MRDIMM_CDEN_QACA(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_MRCD_QACA_EN);
	if (SPD_DDR5_MRDIMM_CDEN_QBCA(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_MRCD_QBCA_EN);
	if (SPD_DDR5_MRDIMM_CDEN_QxCS1(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_MRCD_QxCS_EN);
	if (SPD_DDR5_MRDIMM_CDEN_BCS(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_MRCD_BCS_EN);
	if (SPD_DDR5_MRDIMM_CDEN_QCA13(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_MRCD_QxCA13_EN);
	if (SPD_DDR5_MRDIMM_CDEN_QACS(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_MRCD_QACS_EN);
	if (SPD_DDR5_MRDIMM_CDEN_QBCS(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_MRCD_QBCS_EN);
	if (SPD_DDR5_MRDIMM_CDEN_DCS1(data) == 0)
		spd_nvl_insert_key(si, SPD_KEY_DDR5_MRCD_DCS1_EN);
}

static const spd_value_map_t spd_ddr5_mrcd_ds_map[] = {
	{ SPD_DDR5_MRDIMM_DRV_LIGHT, SPD_DRIVE_LIGHT, false },
	{ SPD_DDR5_MRDIMM_DRV_MODERATE, SPD_DRIVE_MODERATE, false },
	{ SPD_DDR5_MRDIMM_DRV_STRONG, SPD_DRIVE_STRONG, false }
};

static void
spd_parse_ddr5_mrdimm_qck_drv(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t qack = SPD_DDR5_MRDIMM_QCK_DRV_QACK(data);
	const uint8_t qbck = SPD_DDR5_MRDIMM_QCK_DRV_QBCK(data);
	const uint8_t qcck = SPD_DDR5_MRDIMM_QCK_DRV_QCCK(data);
	const uint8_t qdck = SPD_DDR5_MRDIMM_QCK_DRV_QDCK(data);

	spd_insert_map(si, SPD_KEY_DDR5_RCD_QACK_DS, qack, spd_ddr5_mrcd_ds_map,
	    ARRAY_SIZE(spd_ddr5_mrcd_ds_map));
	spd_insert_map(si, SPD_KEY_DDR5_RCD_QBCK_DS, qbck, spd_ddr5_mrcd_ds_map,
	    ARRAY_SIZE(spd_ddr5_mrcd_ds_map));
	spd_insert_map(si, SPD_KEY_DDR5_RCD_QCCK_DS, qcck, spd_ddr5_mrcd_ds_map,
	    ARRAY_SIZE(spd_ddr5_mrcd_ds_map));
	spd_insert_map(si, SPD_KEY_DDR5_RCD_QDCK_DS, qdck, spd_ddr5_mrcd_ds_map,
	    ARRAY_SIZE(spd_ddr5_mrcd_ds_map));

}

static const spd_value_map_t spd_ddr5_mrcd_out[] = {
	{ SPD_DDR5_MRDIMM_QCA_DRV_QCS1_OUT_NORM, SPD_MRCD_OUT_NORMAL, false },
	{ SPD_DDR5_MRDIMM_QCA_DRV_QCS1_OUT_DIS, SPD_MRCD_OUT_DISABLED, false },
	{ SPD_DDR5_MRDIMM_QCA_DRV_QCS1_OUT_LOW, SPD_MRCD_OUT_LOW, false }
};

static void
spd_parse_ddr5_mrdimm_qca_drv(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t cs = SPD_DDR5_MRDIMM_QCA_DRV_CS(data);
	const uint8_t ca = SPD_DDR5_MRDIMM_QCA_DRV_CA(data);
	const uint8_t out = SPD_DDR5_MRDIMM_QCA_DRV_QCS1_OUT(data);

	spd_insert_map(si, SPD_KEY_DDR5_MRCD_QxCS_DS, cs, spd_ddr5_mrcd_ds_map,
	    ARRAY_SIZE(spd_ddr5_mrcd_ds_map));
	spd_insert_map(si, SPD_KEY_DDR5_MRCD_CA_DS, ca, spd_ddr5_mrcd_ds_map,
	    ARRAY_SIZE(spd_ddr5_mrcd_ds_map));
	spd_insert_map(si, SPD_KEY_DDR5_MRCD_QxCS_OUT, out, spd_ddr5_mrcd_out,
	    ARRAY_SIZE(spd_ddr5_mrcd_out));
}

static void
spd_parse_ddr5_mrdimm_db_drv(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t bck = SPD_DDR5_MRDIMM_DB_DRV_BCK(data);
	const uint8_t bcom = SPD_DDR5_MRDIMM_DB_DRV_BCOM(data);

	spd_insert_map(si, SPD_KEY_DDR5_MRCD_BCK_DS, bck, spd_ddr5_mrcd_ds_map,
	    ARRAY_SIZE(spd_ddr5_mrcd_ds_map));
	spd_insert_map(si, SPD_KEY_DDR5_MRCD_BCOM_DS, bcom,
	    spd_ddr5_mrcd_ds_map, ARRAY_SIZE(spd_ddr5_mrcd_ds_map));
}

static const spd_value_map_t spd_ddr5_mrcd_slew_map[] = {
	{ SPD_DDR5_MRDIMM_SLEW_MODERTE, SPD_SLEW_MODERATE, false },
	{ SPD_DDR5_MRDIMM_SLEW_FAST, SPD_SLEW_FAST, false },
	{ SPD_DDR5_MRDIMM_SLEW_SLOW, SPD_SLEW_SLOW, false }
};

static void
spd_parse_ddr5_mrdimm_qxx_slew(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t qcs = SPD_DDR5_MRDIMM_QXX_SLEW_QCS(data);
	const uint8_t qca = SPD_DDR5_MRDIMM_QXX_SLEW_QCA(data);
	const uint8_t qck = SPD_DDR5_MRDIMM_QXX_SLEW_QCK(data);

	spd_insert_map(si, SPD_KEY_DDR5_MRCD_QCK_SLEW, qck,
	    spd_ddr5_mrcd_slew_map, ARRAY_SIZE(spd_ddr5_mrcd_slew_map));
	spd_insert_map(si, SPD_KEY_DDR5_MRCD_QCA_SLEW, qca,
	    spd_ddr5_mrcd_slew_map, ARRAY_SIZE(spd_ddr5_mrcd_slew_map));
	spd_insert_map(si, SPD_KEY_DDR5_MRCD_QCS_SLEW, qcs,
	    spd_ddr5_mrcd_slew_map, ARRAY_SIZE(spd_ddr5_mrcd_slew_map));
}

static void
spd_parse_ddr5_mrdimm_bxx_slew(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t bck = SPD_DDR5_MRDIMM_BXX_SLEW_BCK(data);
	const uint8_t bcom = SPD_DDR5_MRDIMM_BXX_SLEW_BCOM(data);

	spd_insert_map(si, SPD_KEY_DDR5_MRCD_BCK_SLEW, bck,
	    spd_ddr5_mrcd_slew_map, ARRAY_SIZE(spd_ddr5_mrcd_slew_map));
	spd_insert_map(si, SPD_KEY_DDR5_MRCD_BCOM_SLEW, bcom,
	    spd_ddr5_mrcd_slew_map, ARRAY_SIZE(spd_ddr5_mrcd_slew_map));

}

static const spd_value_map_t spd_ddr5_mrcd_dca_map[] = {
	{ 0, SPD_MRCD_DCA_CFG_0, false },
	{ 1, SPD_MRCD_DCA_CFG_1, false }
};

static void
spd_parse_ddr5_mrdimm_dca_cfg(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t cfg = SPD_DDR5_MRDIMM_DCA_CFG_CFG(data);

	spd_insert_map(si, SPD_KEY_DDR5_MRCD_DCA_CFG, cfg,
	    spd_ddr5_mrcd_dca_map, ARRAY_SIZE(spd_ddr5_mrcd_dca_map));
}

static const spd_value_map_t spd_ddr5_mrdimm_irxt_map[] = {
	{ SPD_DDR5_MRDIMM_IRXTYPE_TYPE_UNMATCHED, SPD_MRDIMM_IRXT_UNMATCHED,
	    false },
	{ SPD_DDR5_MRDIMM_IRXTYPE_TYPE_MATCHED, SPD_MRDIMM_IRXT_MATCHED,
	    false }
};

static void
spd_parse_ddr5_mrdimm_irxtype(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t irxt = SPD_DDR5_MRDIMM_IRXTYPE_TYPE(data);

	spd_insert_map(si, SPD_KEY_DDR5_MRDIMM_IRXT, irxt,
	    spd_ddr5_mrdimm_irxt_map, ARRAY_SIZE(spd_ddr5_mrdimm_irxt_map));
}

static const spd_parse_t spd_ddr5_mrdimm_1v1[] = {
	{ .sp_off = SPD_DDR5_MRDIMM_CDEN,
	    .sp_parse = spd_parse_ddr5_mrdimm_cden },
	{ .sp_off = SPD_DDR5_MRDIMM_OACEN,
	    .sp_parse = spd_parse_ddr5_mrdimm_oacen },
	{ .sp_off = SPD_DDR5_MRDIMM_QCK_DRV,
	    .sp_parse = spd_parse_ddr5_mrdimm_qck_drv },
	{ .sp_off = SPD_DDR5_MRDIMM_QCA_DRV,
	    .sp_parse = spd_parse_ddr5_mrdimm_qca_drv },
	{ .sp_off = SPD_DDR5_MRDIMM_DB_DRV,
	    .sp_parse = spd_parse_ddr5_mrdimm_db_drv },
	{ .sp_off = SPD_DDR5_MRDIMM_QXX_SLEW,
	    .sp_parse = spd_parse_ddr5_mrdimm_qxx_slew },
	{ .sp_off = SPD_DDR5_MRDIMM_BXX_SLEW,
	    .sp_parse = spd_parse_ddr5_mrdimm_bxx_slew },
	{ .sp_off = SPD_DDR5_MRDIMM_DCA_CFG,
	    .sp_parse = spd_parse_ddr5_mrdimm_dca_cfg },
	{ .sp_off = SPD_DDR5_MRDIMM_IRXTYPE,
	    .sp_parse = spd_parse_ddr5_mrdimm_irxtype }
};

/*
 * Annex A.5 DDIMM specific processing.
 */
static const spd_value_map_t spd_ddr5_dmb_type_map[] = {
	{ SPD_DDR5_DDIMM_INFO_TYPE_DMB501, SPD_DMB_T_DMB5011, false }
};

static void
spd_parse_ddr5_ddimm_dmb(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 4);
	const uint8_t type = si->si_data[off + 2];
	if (SPD_DDR5_COM_INFO_PRES(type) == 0)
		return;

	spd_parse_ddr5_dev_common(si, off, SPD_DEVICE_DMB,
	    SPD_KEY_DEV_DMB_MFG, SPD_KEY_DEV_DMB_MFG_NAME,
	    SPD_KEY_DEV_DMB_REV, SPD_KEY_DEV_DMB_TYPE,
	    spd_ddr5_dmb_type_map, ARRAY_SIZE(spd_ddr5_dmb_type_map));
}

static const spd_parse_t spd_ddr5_ddimm[] = {
	{ .sp_off = SPD_DDR5_DDIMM_MFG_ID0_DMB, .sp_len = 4,
	    .sp_parse = spd_parse_ddr5_ddimm_dmb },
};

/*
 * Annex A.8 CAMM2 specific processing.
 */
static void
spd_parse_ddr5_camm2_ckd0(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 4);
	const uint8_t type = si->si_data[off + 2];
	if (SPD_DDR5_COM_INFO_PRES(type) == 0)
		return;

	spd_parse_ddr5_dev_common(si, off, SPD_DEVICE_CD_0,
	    SPD_KEY_DEV_CD0_MFG, SPD_KEY_DEV_CD0_MFG_NAME,
	    SPD_KEY_DEV_CD0_REV, SPD_KEY_DEV_CD0_TYPE,
	    spd_ddr5_cd_type_map, ARRAY_SIZE(spd_ddr5_cd_type_map));
}

static void
spd_parse_ddr5_camm2_ckd1(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 4);
	const uint8_t type = si->si_data[off + 2];
	if (SPD_DDR5_COM_INFO_PRES(type) == 0)
		return;

	spd_parse_ddr5_dev_common(si, off, SPD_DEVICE_CD_1,
	    SPD_KEY_DEV_CD1_MFG, SPD_KEY_DEV_CD1_MFG_NAME,
	    SPD_KEY_DEV_CD1_REV, SPD_KEY_DEV_CD1_TYPE,
	    spd_ddr5_cd_type_map, ARRAY_SIZE(spd_ddr5_cd_type_map));
}

static const spd_parse_t spd_ddr5_camm2[] = {
	{ .sp_off = SPD_DDR5_CAMM2_MFG_ID0_CKD0, .sp_len = 4,
	    .sp_parse = spd_parse_ddr5_camm2_ckd0 },
	{ .sp_off = SPD_DDR5_CAMM2_MFG_ID0_CKD1, .sp_len = 4,
	    .sp_parse = spd_parse_ddr5_camm2_ckd1 },
};

static void
spd_parse_ddr5_mod_specific(spd_info_t *si)
{
	uint32_t type;

	if (nvlist_lookup_uint32(si->si_nvl, SPD_KEY_MOD_TYPE, &type) != 0)
		return;

	switch (type) {
	case SPD_MOD_TYPE_RDIMM:
		spd_parse(si, spd_ddr5_rdimm, ARRAY_SIZE(spd_ddr5_rdimm));
		break;
	case SPD_MOD_TYPE_LRDIMM:
		spd_parse(si, spd_ddr5_lrdimm, ARRAY_SIZE(spd_ddr5_lrdimm));
		break;
	case SPD_MOD_TYPE_UDIMM:
	case SPD_MOD_TYPE_SODIMM:
	case SPD_MOD_TYPE_CUDIMM:
	case SPD_MOD_TYPE_CSODIMM:
		spd_parse(si, spd_ddr5_udimm, ARRAY_SIZE(spd_ddr5_udimm));
		if (SPD_DDR5_SPD_REV_ADD(si->si_data[SPD_DDR5_COM_REV]) >= 1) {
			spd_parse(si, spd_ddr5_udimm_1v1,
			    ARRAY_SIZE(spd_ddr5_udimm_1v1));
		}
		break;
	case SPD_MOD_TYPE_MRDIMM:
		spd_parse(si, spd_ddr5_mrdimm, ARRAY_SIZE(spd_ddr5_mrdimm));
		if (SPD_DDR5_SPD_REV_ADD(si->si_data[SPD_DDR5_COM_REV]) >= 1) {
			spd_parse(si, spd_ddr5_mrdimm_1v1,
			    ARRAY_SIZE(spd_ddr5_mrdimm_1v1));
		}
		break;
	case SPD_MOD_TYPE_DDIMM:
		spd_parse(si, spd_ddr5_ddimm, ARRAY_SIZE(spd_ddr5_ddimm));
		break;
	case SPD_MOD_TYPE_CAMM2:
		spd_parse(si, spd_ddr5_camm2, ARRAY_SIZE(spd_ddr5_camm2));
		break;
	/*
	 * Soldered DIMMs don't have any data.
	 */
	case SPD_MOD_TYPE_SOLDER:
	default:
		break;
	}
}

/*
 * This is a common entry point for all of the common pieces of DDR5 and LPDDR5.
 * They use the same offsets and meanings and therefore this is called by both.
 * While strictly speaking LPDDR5 doesn't support all of the different types of
 * module types that DDR5 does, we will parse whatever is claimed.
 */
void
spd_parse_ddr5_common(spd_info_t *si)
{
	spd_parse(si, spd_ddr5_module, ARRAY_SIZE(spd_ddr5_module));
	spd_parse(si, spd_ddr5_mfg, ARRAY_SIZE(spd_ddr5_mfg));
	spd_parse_ddr5_mod_specific(si);
}

/*
 * DDR5 has two different revisions. One that is present in the base region and
 * one that is present in the common module region that covers the
 * module-related pieces. We check that both are present and go from there. We
 * may want to relax this in the future so that it's easier to just decode a
 * subset of this, but for the time being, we require both.
 */
void
spd_parse_ddr5(spd_info_t *si)
{
	if (SPD_DDR5_SPD_REV_ENC(si->si_data[SPD_DDR5_SPD_REV]) !=
	    SPD_DDR5_SPD_REV_V1) {
		si->si_error = LIBJEDEC_SPD_UNSUP_REV;
		return;
	}

	if (si->si_nbytes <= SPD_DDR5_COM_REV) {
		si->si_error = LIBJEDEC_SPD_TOOSHORT;
		return;
	}

	if (SPD_DDR5_SPD_REV_ENC(si->si_data[SPD_DDR5_COM_REV]) !=
	    SPD_DDR5_SPD_REV_V1) {
		si->si_error = LIBJEDEC_SPD_UNSUP_REV;
		return;
	}

	spd_parse(si, spd_ddr5_base, ARRAY_SIZE(spd_ddr5_base));
	if (SPD_DDR5_SPD_REV_ADD(si->si_data[SPD_DDR5_COM_REV]) >= 2)
		spd_parse(si, spd_ddr5_base_1v2, ARRAY_SIZE(spd_ddr5_base_1v2));
	spd_parse_ddr5_common(si);
}
