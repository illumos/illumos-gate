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
 * This implements common DIMM creation for the hc tree. Currently this is based
 * primarily on providing SPD data.
 */

#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <libjedec.h>
#include <string.h>
#include <stdbool.h>

#include "topo_dimm.h"

typedef struct {
	uint32_t sc_dram_type;
	uint32_t sc_mod_type;
	const char *sc_dram_str;
	const char *sc_mod_str;
	bool sc_asym;
	uint32_t sc_nranks;
	uint32_t sc_even_ranks;
	uint32_t sc_odd_ranks;
	uint32_t sc_data_bits;
	uint32_t sc_ecc_bits;
	uint32_t sc_nsubchan;
	uint32_t sc_pkg_sl[2];
	uint32_t sc_pkg_ndie[2];
	uint64_t sc_die_size[2];
	uint32_t sc_dram_width[2];
	uint32_t sc_nrows[2];
	uint32_t sc_ncols[2];
	uint32_t sc_nbank_bits[2];
	uint32_t sc_nbgrp_bits[2];
	uint32_t sc_vdd;
	uint32_t sc_devices;
} spd_cache_t;

static const topo_pgroup_info_t topo_dimm_pgroup = {
	TOPO_PGROUP_DIMM_PROPS,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t topo_dimm_comps_pgroup = {
	TOPO_PGROUP_DIMM_COMPONENTS,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

/*
 * Translate a subset of the DDR types that we're likely to support into the
 * corresponding current DDR information. We only really support taking these
 * apart, so that's OK.
 */
static const char *
topo_dimm_dram_type2str(spd_dram_type_t type)
{
	switch (type) {
	case SPD_DT_DDR4_SDRAM:
		return (TOPO_DIMM_TYPE_DDR4);
	case SPD_DT_LPDDR4_SDRAM:
		return (TOPO_DIMM_TYPE_LPDDR4);
	case SPD_DT_DDR5_SDRAM:
		return (TOPO_DIMM_TYPE_DDR5);
	case SPD_DT_LPDDR5_SDRAM:
		return (TOPO_DIMM_TYPE_LPDDR5);
	default:
		return (NULL);
	}

}

/*
 * Various string functions for different component types.
 */
static const char *
topo_dimm_temp2str(uint32_t val)
{
	switch (val) {
	case SPD_TEMP_T_TSE2002:
		return ("TSE2002");
	case SPD_TEMP_T_TSE2004av:
		return ("TSE2004av");
	case SPD_TEMP_T_TS5111:
		return ("TS5111");
	case SPD_TEMP_T_TS5110:
		return ("TS5110");
	case SPD_TEMP_T_TS5210:
		return ("TS5210");
	case SPD_TEMP_T_TS5211:
		return ("TS5211");
	default:
		return ("unknown");
	}
}

static const char *
topo_dimm_pmic2str(uint32_t val)
{
	switch (val) {
	case SPD_PMIC_T_PMIC5000:
		return ("PMIC5000");
	case SPD_PMIC_T_PMIC5010:
		return ("PMIC5010");
	case SPD_PMIC_T_PMIC5100:
		return ("PMIC5100");
	case SPD_PMIC_T_PMIC5020:
		return ("PMIC5020");
	case SPD_PMIC_T_PMIC5120:
		return ("PMIC5120");
	case SPD_PMIC_T_PMIC5200:
		return ("PMIC5200");
	case SPD_PMIC_T_PMIC5030:
		return ("PMIC5030");
	default:
		return ("unknown");
	}
}

static const char *
topo_dimm_cd2str(uint32_t val)
{
	switch (val) {
	case SPD_CD_T_DDR5CK01:
		return ("DDR5CK01");
	default:
		return ("unknown");
	}
}

static const char *
topo_dimm_rcd2str(uint32_t val)
{
	switch (val) {
	case SPD_RCD_T_SSTE32882:
		return ("SSTE32882");
	case SPD_RCD_T_DDR4RCD01:
		return ("DDR4RCD01");
	case SPD_RCD_T_DDR4RCD02:
		return ("DDR4RCD02");
	case SPD_RCD_T_DDR5RCD01:
		return ("DDR5RCD01");
	case SPD_RCD_T_DDR5RCD02:
		return ("DDR5RCD02");
	case SPD_RCD_T_DDR5RCD03:
		return ("DDR5RCD03");
	case SPD_RCD_T_DDR5RCD04:
		return ("DDR5RCD04");
	case SPD_RCD_T_DDR5RCD05:
		return ("DDR5RCD05");
	default:
		return ("unknown");
	}
}

static const char *
topo_dimm_db2str(uint32_t val)
{
	switch (val) {
	case SPD_DB_T_DDR4DB01:
		return ("DDR4DB01");
	case SPD_DB_T_DDR4DB02:
		return ("DDR4DB02");
	case SPD_DB_T_DDR5DB01:
		return ("DDR5DB01");
	case SPD_DB_T_DDR5DB02:
		return ("DDR5DB02");
	case SPD_DB_T_DDR3MB:
		return ("DDR3MB");
	default:
		return ("unknown");
	}
}

static const char *
topo_dimm_mrcd2str(uint32_t val)
{
	switch (val) {
	case SPD_MRCD_T_DDR5MRCD01:
		return ("DDR5MRCD01");
	case SPD_MRCD_T_DDR5MRCD02:
		return ("DDR5MRCD02");
	default:
		return ("unknown");
	}
}

static const char *
topo_dimm_mdb2str(uint32_t val)
{
	switch (val) {
	case SPD_MDB_T_DDR5MDB01:
		return ("DDR5MDB01");
	case SPD_MDB_T_DDR5MDB02:
		return ("DDR5MDB02");
	default:
		return ("unknown");
	}
}

static const char *
topo_dimm_dmb2str(uint32_t val)
{
	switch (val) {
	case SPD_DMB_T_DMB5011:
		return ("DMB5011");
	default:
		return ("unknown");
	}
}

static const char *
topo_dimm_spd2str(uint32_t val)
{
	switch (val) {
	case SPD_SPD_T_EE1002:
		return ("EE1002");
	case SPD_SPD_T_EE1004:
		return ("EE1004");
	case SPD_SPD_T_SPD5118:
		return ("SPD5118");
	case SPD_SPD_T_ESPD5216:
		return ("ESPD5216");
	default:
		return ("unknown");
	}
}

/*
 * DDR4 and DDR5 have a fixed voltage. DDR3 had a range of voltages that could
 * be selected. In addition, LPDDR4 and LPDDR5 depend on the specifics of the
 * memory controller as they allow for variable options here.
 */
static uint32_t
topo_dimm_mod_vdd(spd_dram_type_t type)
{
	switch (type) {
	case SPD_DT_DDR4_SDRAM:
		return (1200);
	case SPD_DT_DDR5_SDRAM:
		return (1100);
	default:
		return (0);
	}
}

static const char *
topo_dimm_mod_type2str(spd_module_type_t type)
{
	switch (type) {
	case SPD_MOD_TYPE_RDIMM:
		return ("RDIMM");
	case SPD_MOD_TYPE_UDIMM:
		return ("UDIMM");
	case SPD_MOD_TYPE_SODIMM:
		return ("SO-DIMM");
	case SPD_MOD_TYPE_LRDIMM:
		return ("LRDIMM");
	case SPD_MOD_TYPE_MRDIMM:
		return ("MRDIMM");
	case SPD_MOD_TYPE_DDIMM:
		return ("DDIMM");
	case SPD_MOD_TYPE_SOLDER:
		return ("solder-down");
	case SPD_MOD_TYPE_MINI_RDIMM:
		return ("Mini-RDIMM");
	case SPD_MOD_TYPE_MINI_UDIMM:
		return ("Mini-UDIMM");
	case SPD_MOD_TYPE_MINI_CDIMM:
		return ("Mini-CDIMM");
	case SPD_MOD_TYPE_72b_SO_RDIMM:
		return ("72b-SO-RDIMM");
	case SPD_MOD_TYPE_72b_SO_UDIMM:
		return ("72b-SO-UDIMM");
	case SPD_MOD_TYPE_72b_SO_CDIMM:
		return ("72b-SO-CDIMM");
	case SPD_MOD_TYPE_16b_SO_DIMM:
		return ("16b-SO-DIMM");
	case SPD_MOD_TYPE_32b_SO_DIMM:
		return ("32b-SO-DIMM");
	case SPD_MOD_TYPE_CUDIMM:
		return ("CUDIMM");
	case SPD_MOD_TYPE_CSODIMM:
		return ("CSODIMM");
	case SPD_MOD_TYPE_CAMM2:
		return ("CAMM2");
	case SPD_MOD_TYPE_LPDIMM:
		return ("LP-DIMM");
	case SPD_MOD_TYPE_MICRO_DIMM:
		return ("Micro-DIMM");
	default:
		return (NULL);
	}
}

/*
 * Go through and cache common properties that we would look up in the NVL into
 * a structure. We do this once and then reuse this for common settings. We
 * don't generally include PN/SN/Rev information in here since not having that
 * is OK and we can still create nodes and due to the fact that we generally
 * only use it once.
 */
static bool
topo_dimm_cache_spd(topo_mod_t *mod, nvlist_t *spd, spd_cache_t *cache)
{
	/*
	 * First go through and look up values that we expect to always be
	 * present.
	 */
	if (nvlist_lookup_pairs(spd, 0,
	    SPD_KEY_MOD_TYPE, DATA_TYPE_UINT32, &cache->sc_mod_type,
	    SPD_KEY_NRANKS, DATA_TYPE_UINT32, &cache->sc_nranks,
	    SPD_KEY_NSUBCHAN, DATA_TYPE_UINT32, &cache->sc_nsubchan,
	    SPD_KEY_DATA_WIDTH, DATA_TYPE_UINT32, &cache->sc_data_bits,
	    SPD_KEY_ECC_WIDTH, DATA_TYPE_UINT32, &cache->sc_ecc_bits,
	    SPD_KEY_NBANK_BITS, DATA_TYPE_UINT32, &cache->sc_nbank_bits[0],
	    SPD_KEY_NBGRP_BITS, DATA_TYPE_UINT32, &cache->sc_nbgrp_bits[0],
	    SPD_KEY_NROW_BITS, DATA_TYPE_UINT32, &cache->sc_nrows[0],
	    SPD_KEY_NCOL_BITS, DATA_TYPE_UINT32, &cache->sc_ncols[0],

	    SPD_KEY_PKG_SL, DATA_TYPE_UINT32, &cache->sc_pkg_sl[0],
	    SPD_KEY_PKG_NDIE, DATA_TYPE_UINT32, &cache->sc_pkg_ndie[0],
	    SPD_KEY_DRAM_WIDTH, DATA_TYPE_UINT32, &cache->sc_dram_width[0],
	    SPD_KEY_DIE_SIZE, DATA_TYPE_UINT64, &cache->sc_die_size[0],
	    SPD_KEY_DEVS, DATA_TYPE_UINT32, &cache->sc_devices,
	    NULL) != 0) {
		topo_mod_dprintf(mod, "failed to find expected primary SPD "
		    "keys");
		return (false);
	}

	/*
	 * Set information that should be valid based on the types that we
	 * support right now.
	 */
	cache->sc_dram_str = topo_dimm_dram_type2str(cache->sc_dram_type);
	cache->sc_mod_str = topo_dimm_mod_type2str(cache->sc_mod_type);
	cache->sc_vdd = topo_dimm_mod_vdd(cache->sc_dram_type);

	/*
	 * Next we have keys that may or may not be present.
	 */
	cache->sc_asym = nvlist_lookup_boolean(spd, SPD_KEY_RANK_ASYM) == 0;

	if (!cache->sc_asym)
		return (true);

	cache->sc_even_ranks = cache->sc_odd_ranks = cache->sc_nranks / 2;
	if (cache->sc_nranks % 2 == 1)
		cache->sc_even_ranks++;

	/*
	 * Now go through and look up keys that we believe should always be
	 * present given that we have an asymmetric configuration.
	 */
	if (nvlist_lookup_pairs(spd, 0,
	    SPD_KEY_SEC_NBANK_BITS, DATA_TYPE_UINT32, &cache->sc_nbank_bits[1],
	    SPD_KEY_SEC_NBGRP_BITS, DATA_TYPE_UINT32, &cache->sc_nbgrp_bits[1],
	    SPD_KEY_SEC_NROW_BITS, DATA_TYPE_UINT32, &cache->sc_nrows[1],
	    SPD_KEY_SEC_NCOL_BITS, DATA_TYPE_UINT32, &cache->sc_ncols[1],
	    SPD_KEY_SEC_PKG_SL, DATA_TYPE_UINT32, &cache->sc_pkg_sl[1],
	    SPD_KEY_SEC_PKG_NDIE, DATA_TYPE_UINT32, &cache->sc_pkg_ndie[1],
	    SPD_KEY_SEC_DRAM_WIDTH, DATA_TYPE_UINT32, &cache->sc_dram_width[1],
	    SPD_KEY_SEC_DIE_SIZE, DATA_TYPE_UINT32, &cache->sc_die_size[1],
	    NULL) != 0) {
		topo_mod_dprintf(mod, "failed to get secondary keys for SPD "
		    "size calculation");
		return (false);
	}

	return (true);
}

/*
 * Calculating the size here is a little nuanced. The rough formula is provided
 * by JEDEC in the various SPD Annexes. The rough formula is:
 *
 * (SDRAM Capacity / 8) * (Bus width / SDRAM width) * Logical ranks
 *
 * Phrased in terms of SPD macros this is really:
 *
 * SPD_KEY_DIE_SIZE / 8 * (SPD_KEY_DATA_WIDTH / SPD_KEY_DRAM_WIDTH) * Logical
 * Ranks
 *
 * The DIMM operates in chunks that are equal to its data width multiplied by
 * the number of sub-channels. In general for DDR4/5 this is always going to be
 * 64-bits or 8 bytes. The ECC is not included in this. The SDRAM width is
 * fairly straightforward. The logical ranks depends on the die type and the
 * number of actual ranks present. This is basically SPD_KEY_PKG_NDIE *
 * SPD_KEY_NRANKS.
 *
 * However, there are two small wrinkles: the calculation of logical ranks and
 * asymmetrical modules. With asymmetrical modules the data width doesn't
 * change, the capacity and SDRAM width may change. In addition, calculating
 * logical ranks is a bit nuanced here. First, each module declares the number
 * of ranks that exist in the package. This has to then be transformed into
 * logical ranks, which happens if we're using 3DS based DIMMs, which is
 * determined based on the SPD_KEY_PKG_SL key. When using 3DS we need to
 * multiple the number of dies by the number of ranks, otherwise it stays at
 * 1x.
 *
 * When we're using asymmetrical DIMMs, the primary fields nominally apply to
 * the even ranks and the secondary fields to the odd ranks. This is explicitly
 * the case in DDR5. It is less explicit in DDR4, but we treat it the same way.
 */
static bool
topo_dimm_calc_size(topo_mod_t *mod, const spd_cache_t *cache, uint64_t *sizep)
{
	uint32_t pndie = cache->sc_pkg_ndie[0];
	uint32_t width = cache->sc_data_bits * cache->sc_nsubchan /
	    cache->sc_dram_width[0];

	*sizep = 0;
	if (cache->sc_pkg_sl[0] != SPD_SL_3DS)
		pndie = 1;

	if (!cache->sc_asym) {
		*sizep = pndie * width * cache->sc_nranks *
		    cache->sc_die_size[0] / 8;
		return (true);
	}

	if (cache->sc_nranks < 2) {
		topo_mod_dprintf(mod, "encountered asymmetrical module but it "
		    "only has %u ranks", cache->sc_nranks);
		return (false);
	}

	*sizep = pndie * width * cache->sc_even_ranks *
	    cache->sc_die_size[0] / 8;

	pndie = cache->sc_pkg_ndie[1];
	if (cache->sc_pkg_sl[1] != SPD_SL_3DS)
		pndie = 1;

	*sizep += pndie * width * cache->sc_odd_ranks *
	    cache->sc_die_size[1] / 8;
	return (true);
}

/*
 * Add basic information to the DIMM. Some information like the current memory
 * speed or LPDDR voltage can only be derived from the memory controller or
 * systems firmware (i.e. SMBIOS).
 */
static bool
topo_dimm_add_props(topo_mod_t *mod, tnode_t *dimm, const spd_cache_t *cache)
{
	uint32_t nbanks[2], nbgrps[2], nbpbg[2];
	uint_t arr_len = 1;
	uint64_t size;

	nbgrps[0] = 1 << cache->sc_nbgrp_bits[0];
	nbpbg[0] = 1 << cache->sc_nbank_bits[0];
	nbanks[0] = nbgrps[0] * nbpbg[0];

	if (!topo_dimm_calc_size(mod, cache, &size)) {
		return (false);
	}

	/*
	 * This indicates that we have an asymmetrical DIMM configuration. This
	 * implies that the number of banks and bank groups actually vary based
	 * on whether it's an odd/even rank.
	 */
	if (cache->sc_asym) {
		arr_len = 2;
		nbgrps[1] = 1 << cache->sc_nbgrp_bits[1];
		nbpbg[1] = 1 << cache->sc_nbank_bits[1];
		nbanks[1] = nbgrps[1] * nbpbg[1];
	}

	if (topo_create_props(mod, dimm, TOPO_PROP_IMMUTABLE, &topo_dimm_pgroup,
	    TOPO_PROP_DIMM_RANKS, TOPO_TYPE_UINT32, cache->sc_nranks,
	    TOPO_PROP_DIMM_BANKS, TOPO_TYPE_UINT32_ARRAY, nbanks, arr_len,
	    TOPO_PROP_DIMM_BANK_GROUPS, TOPO_TYPE_UINT32_ARRAY, nbgrps, arr_len,
	    TOPO_PROP_DIMM_BANKS_PER_GROUP, TOPO_TYPE_UINT32_ARRAY, nbpbg,
	    arr_len,
	    TOPO_PROP_DIMM_SUBCHANNELS, TOPO_TYPE_UINT32, cache->sc_nsubchan,
	    TOPO_PROP_DIMM_DATA_WIDTH, TOPO_TYPE_UINT32, cache->sc_data_bits,
	    TOPO_PROP_DIMM_ECC_WIDTH, TOPO_TYPE_UINT32, cache->sc_ecc_bits,
	    TOPO_PROP_DIMM_VDD, TOPO_TYPE_UINT32, cache->sc_vdd,
	    TOPO_PROP_DIMM_SIZE, TOPO_TYPE_UINT64, size,
	    TOPO_PROP_DIMM_TYPE, TOPO_TYPE_STRING, cache->sc_dram_str,
	    TOPO_PROP_DIMM_MODULE_TYPE, TOPO_TYPE_STRING, cache->sc_mod_str,
	    NULL) != 0) {
		topo_mod_dprintf(mod, "failed to set basic DIMM properties: %s",
		    topo_mod_errmsg(mod));
		return (false);
	}

	return (true);
}

static int
topo_dimm_create_tn(topo_mod_t *mod, tnode_t *pn, tnode_t **tnp,
    const char *name, topo_instance_t inst, const char *part, const char *rev,
    const char *serial)
{
	int ret;
	nvlist_t *auth = NULL;
	nvlist_t *fmri = NULL;
	tnode_t *tn;

	if ((auth = topo_mod_auth(mod, pn)) == NULL) {
		topo_mod_dprintf(mod, "failed to get auth data: %s",
		    topo_mod_errmsg(mod));
		ret = -1;
		goto out;
	}

	if ((fmri = topo_mod_hcfmri(mod, pn, FM_HC_SCHEME_VERSION, name,
	    inst, NULL, auth, part, rev, serial)) == NULL) {
		topo_mod_dprintf(mod, "failed to create fmri for %s[%" PRIu64
		    "]: %s\n", name, inst, topo_mod_errmsg(mod));
		ret = -1;
		goto out;
	}

	if ((tn = topo_node_bind(mod, pn, name, inst, fmri)) == NULL) {
		topo_mod_dprintf(mod, "failed to bind fmri for %s[%" PRIu64
		    "]: %s\n", name, inst, topo_mod_errmsg(mod));
		ret = -1;
		goto out;
	}

	topo_pgroup_hcset(tn, auth);
	if (topo_node_fru_set(tn, fmri, 0, &ret) != 0) {
		topo_mod_dprintf(mod, "failed to set FRU: %s\n",
		    topo_strerror(ret));
		ret = topo_mod_seterrno(mod, ret);
		goto out;
	}

	*tnp = tn;
	ret = 0;
out:
	nvlist_free(auth);
	nvlist_free(fmri);
	return (ret);
}

static bool
topo_dimm_crc_ok(topo_mod_t *mod, nvlist_t *nvl, spd_dram_type_t type)
{
	nvlist_t *errs;
	const char *crc_keys[2] = { NULL };

	/*
	 * Note: Because this function determines which forms of SPD we support,
	 * if you end up adding something to the list you should update
	 * topo_dimm_add_props() to make sure that any additional variants have
	 * been added there or that we have information from their corresponding
	 * memory controllers.
	 */
	switch (type) {
	case SPD_DT_DDR4_SDRAM:
		crc_keys[0] = SPD_KEY_CRC_DDR4_BASE;
		crc_keys[1] = SPD_KEY_CRC_DDR4_BLK1;
		break;
	case SPD_DT_DDR5_SDRAM:
		crc_keys[0] = SPD_KEY_CRC_DDR5;
		break;
	default:
		topo_mod_dprintf(mod, "unsupported DRAM type: 0x%x", type);
		return (false);
	}

	/*
	 * If there are no errors then we're likely OK and we can continue.
	 */
	if (nvlist_lookup_nvlist(nvl, SPD_KEY_ERRS, &errs) != 0) {
		return (true);
	}

	for (size_t i = 0; i < ARRAY_SIZE(crc_keys); i++) {
		nvlist_t *key;

		if (crc_keys[i] == NULL)
			continue;

		if (nvlist_lookup_nvlist(errs, crc_keys[i], &key) == 0) {
			return (false);
		}
	}

	return (true);
}

typedef struct dimm_comp {
	const char *dc_comp;
	spd_device_t dc_mask;
	bool dc_always;
	uint32_t (*dc_count)(const struct dimm_comp *, const spd_cache_t *,
	    nvlist_t *);
	/* XXX determine if cache is needed */
	bool (*dc_mfg)(topo_mod_t *, tnode_t *, const struct dimm_comp *,
	    const spd_cache_t *, nvlist_t *, void *);
	const char *(*dc_type2str)(uint32_t);
	void *dc_mfg_arg;
} dimm_comp_t;

static uint32_t
dimm_comp_count_solo(const dimm_comp_t *comp, const spd_cache_t *cache,
    nvlist_t *spd)
{
	return (1);
}

/*
 * We'd like to determine the number of dies that are actually present. One
 * way to calculate this is to look at the data bits and ecc bits that are
 * required and divide that by the DRAM width. There should be one set of such
 * dies for each primary rank. In DDR4/5 these contain the banks/groups.
 *
 * In a physical sense, even when using DDP or 3DS stacked modules, then there
 * is still only a single refdes basically on the board so we create it that
 * way. In the DDR4/5 world when there are more than two ranks, they are stacked
 * or using the older DDP technology. So basically we assume there are only up
 * to two ranks worth of dies at most.
 */
static uint32_t
dimm_comp_count_dies(const dimm_comp_t *comp, const spd_cache_t *cache,
    nvlist_t *spd)
{
	uint32_t chan_width = (cache->sc_ecc_bits + cache->sc_data_bits) *
	    cache->sc_nsubchan;
	uint32_t ndies_rank[2] = { 0, 0 };

	ndies_rank[0] = chan_width / cache->sc_dram_width[0];
	if (cache->sc_asym) {
		ndies_rank[1] = chan_width / cache->sc_dram_width[1];
	} else if (cache->sc_nranks >= 2) {
		ndies_rank[1] = ndies_rank[0];
	}

	return (ndies_rank[0] + ndies_rank[1]);
}

static uint32_t
dimm_comp_count_mask(const dimm_comp_t *comp, const spd_cache_t *cache,
    nvlist_t *spd)
{
	uint32_t ret = 0;
	uint32_t combo_mask = cache->sc_devices & comp->dc_mask;

	for (uint32_t i = 0; i < sizeof (uint32_t) * NBBY; i++) {
		if (((1 << i) & combo_mask) != 0)
			ret++;
	}

	return (ret);
}

/*
 * In the DDR4 SPD information, there is an explicit key for the number of
 * registers that actually exist in the system. If the key exists then we return
 * that, otherwise we don't do anything.
 */
static uint32_t
dimm_comp_count_regs(const dimm_comp_t *comp, const spd_cache_t *cache,
    nvlist_t *spd)
{
	uint32_t ret;

	if (nvlist_lookup_uint32(spd, SPD_KEY_MOD_NREGS, &ret) != 0)
		return (0);
	return (ret);
}

/*
 * This enum indicates the possible state for all the keys of a given type.
 * Basically we need to make sure that for the given range of keys they are
 * generally consistent.
 */
typedef enum {
	DIMM_COMP_K_VALID,
	DIMM_COMP_K_ERR,
	DIMM_COMP_K_ENOENT
} dimm_comp_key_state_t;

static dimm_comp_key_state_t
dimm_comp_keys_exist(nvlist_t *spd, const char *const *keys, uint_t nents,
    bool partial_enoent)
{
	dimm_comp_key_state_t ret;

	if (nents == 0) {
		return (DIMM_COMP_K_ERR);
	}

	if (keys == NULL) {
		return (DIMM_COMP_K_ENOENT);
	}

	for (uint_t i = 0; i < nents; i++) {
		dimm_comp_key_state_t cur;

		cur = nvlist_exists(spd, keys[i]) ? DIMM_COMP_K_VALID :
		    DIMM_COMP_K_ENOENT;
		if (i == 0) {
			ret = cur;
			continue;
		}

		/*
		 * If we have changed disposition that is a problem. However, we
		 * will allow a partial ENOENT to exist if we've been given the
		 * flag to cover for the case where we don't have a translation
		 * for a given manufacturer's JEDEC ID name.
		 */
		if (ret != cur) {
			if (partial_enoent) {
				ret = DIMM_COMP_K_VALID;
			} else {
				return (DIMM_COMP_K_ERR);
			}
		}
	}

	return (ret);
}

/*
 * The JEDEC IDs are a pair of two digits. Because we don't really have arrays
 * of arrays in topo, we instead convert this into a string of the form
 * 0x%x:0x%x with the continuation first and then the specific value.
 */
static bool
dimm_comp_mfg_common_ids(topo_mod_t *mod, tnode_t *dimm, nvlist_t *spd,
    const char *prop, const char *const *keys, uint_t nents)
{
	char **strs = NULL;
	bool ret = false;
	int err;

	if ((strs = topo_mod_zalloc(mod, sizeof (char *) * nents)) == NULL) {
		topo_mod_dprintf(mod, "failed to allocate memory for %s string "
		    "array: %s", prop, topo_strerror(EMOD_NOMEM));
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		return (false);
	}

	for (size_t i = 0; i < nents; i++) {
		uint32_t *data;
		uint_t nvals;
		int nret = nvlist_lookup_uint32_array(spd, keys[i], &data,
		    &nvals);

		if (nret != 0) {
			topo_mod_dprintf(mod, "failed to look up %s: %s",
			    keys[i], strerror(nret));
			(void) topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
			goto out;
		}

		if (nvals != 2) {
			topo_mod_dprintf(mod, "key %s has wrong number of "
			    "array entries: found %u, expected %u", keys[i],
			    nvals, 2);
			(void) topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
			goto out;
		}

		if (topo_mod_asprintf(mod, &strs[i], "0x%x:0x%x", data[0],
		    data[1]) == -1) {
			topo_mod_dprintf(mod, "failed to construct ID string "
			    "for %s: %s\n", keys[i], strerror(errno));
			(void) topo_mod_seterrno(mod, EMOD_NOMEM);
			goto out;
		}
	}

	if (topo_prop_set_string_array(dimm, TOPO_PGROUP_DIMM_COMPONENTS, prop,
	    TOPO_PROP_IMMUTABLE, (const char **)strs, nents, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set property %s: %s", prop,
		    topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		goto out;
	}

	ret = true;
out:
	for (uint_t i = 0; i < nents; i++) {
		topo_mod_strfree(mod, strs[i]);
	}
	topo_mod_free(mod, strs, sizeof (char *) * nents);
	return (ret);
}

static bool
dimm_comp_mfg_common_strings(topo_mod_t *mod, tnode_t *dimm, nvlist_t *spd,
    const char *prop, const char *const *keys, uint_t nents, bool allow_enoent)
{
	char **strs = NULL;
	int err;
	bool ret = false;

	if ((strs = topo_mod_zalloc(mod, sizeof (char *) * nents)) == NULL) {
		topo_mod_dprintf(mod, "failed to allocate memory for %s string "
		    "array: %s", prop, topo_strerror(EMOD_NOMEM));
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		return (false);
	}

	for (size_t i = 0; i < nents; i++) {
		int nret = nvlist_lookup_string(spd, keys[i], &strs[i]);
		if (nret != 0 && !(allow_enoent && nret == ENOENT)) {
			topo_mod_dprintf(mod, "failed to look up %s: %s",
			    keys[i], strerror(nret));
			(void) topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
			goto out;
		}
	}

	if (topo_prop_set_string_array(dimm, TOPO_PGROUP_DIMM_COMPONENTS, prop,
	    TOPO_PROP_IMMUTABLE, (const char **)strs, nents, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set property %s: %s", prop,
		    topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		goto out;
	}

	ret = true;
out:
	topo_mod_free(mod, strs, sizeof (char *) * nents);
	return (ret);
}

/*
 * The type of a part is encoded as a uint32_t and has a corresponding enum. We
 * want to translate that into a string. The table for that is stored in the
 * dimm_comp_t.
 */
static bool
dimm_comp_mfg_common_type(topo_mod_t *mod, tnode_t *dimm, nvlist_t *spd,
    const dimm_comp_t *comp, const char *const *keys, uint_t nents)
{
	const char **strs = NULL;
	int err;
	bool ret = false;
	char prop[64];

	if (comp->dc_type2str == NULL) {
		(void) topo_mod_dprintf(mod, "missing type2str function for "
		    "component type %s", comp->dc_comp);
		(void) topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
		return (false);
	}

	(void) snprintf(prop, sizeof (prop), "%s-type", comp->dc_comp);
	if ((strs = topo_mod_zalloc(mod, sizeof (char *) * nents)) == NULL) {
		topo_mod_dprintf(mod, "failed to allocate memory for %s string "
		    "array: %s", prop, topo_strerror(EMOD_NOMEM));
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		return (false);
	}

	for (size_t i = 0; i < nents; i++) {
		uint32_t raw;

		int nret = nvlist_lookup_uint32(spd, keys[i], &raw);
		if (nret != 0) {
			topo_mod_dprintf(mod, "failed to look up %s: %s",
			    keys[i], strerror(nret));
			(void) topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
			goto out;
		}

		strs[i] = comp->dc_type2str(raw);
	}

	if (topo_prop_set_string_array(dimm, TOPO_PGROUP_DIMM_COMPONENTS, prop,
	    TOPO_PROP_IMMUTABLE, strs, nents, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set property %s: %s", prop,
		    topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		goto out;
	}

	ret = true;
out:
	topo_mod_free(mod, strs, sizeof (char *) * nents);
	return (ret);
}


/*
 * Given a number of keys to check for each item type, attempt to look up each
 * item and add a property based on it. Prior to DDR5, we generally won't have
 * information for the manufacturers or revisions. As such, when we fail to get
 * any keys of a given type, that's fine. However, we do want to make sure that
 * we are always adding things consistently, that is if we are told we have
 * three keys for something and sometimes only look up two, that's an error.
 */
static bool
dimm_comp_mfg_common(topo_mod_t *mod, tnode_t *dimm, const dimm_comp_t *comp,
    nvlist_t *spd, const char *const *mfg_id_key,
    const char *const *mfg_name_key, const char *const *type_key,
    const char *const *rev_key, uint_t nents)
{
	dimm_comp_key_state_t mfg_id_valid, mfg_name_valid, type_valid;
	dimm_comp_key_state_t rev_valid;

	if (nents == 0) {
		return (true);
	}

	mfg_id_valid = dimm_comp_keys_exist(spd, mfg_id_key, nents, false);
	mfg_name_valid = dimm_comp_keys_exist(spd, mfg_name_key, nents, true);
	type_valid = dimm_comp_keys_exist(spd, type_key, nents, false);
	rev_valid = dimm_comp_keys_exist(spd, rev_key, nents, false);

	if (mfg_name_valid == DIMM_COMP_K_ERR || rev_valid == DIMM_COMP_K_ERR ||
	    mfg_id_valid == DIMM_COMP_K_ERR || type_valid == DIMM_COMP_K_ERR) {
		topo_mod_dprintf(mod, "encountered erroneous keys: 0x%x 0x%x "
		    "0x%x 0x%x", mfg_name_valid, rev_valid, mfg_id_valid,
		    type_valid);
		(void) topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
		return (false);
	}

	if (mfg_id_valid == DIMM_COMP_K_VALID) {
		char key[64];

		(void) snprintf(key, sizeof (key), "%s-id",
		    comp->dc_comp);
		if (!dimm_comp_mfg_common_ids(mod, dimm, spd, key,
		    mfg_id_key, nents)) {
			return (false);
		}
	}

	if (mfg_name_valid == DIMM_COMP_K_VALID) {
		char key[64];

		(void) snprintf(key, sizeof (key), "%s-mfg-name",
		    comp->dc_comp);
		if (!dimm_comp_mfg_common_strings(mod, dimm, spd, key,
		    mfg_name_key, nents, true)) {
			return (false);
		}
	}

	if (rev_valid == DIMM_COMP_K_VALID) {
		char key[64];

		(void) snprintf(key, sizeof (key), "%s-revision",
		    comp->dc_comp);
		if (!dimm_comp_mfg_common_strings(mod, dimm, spd, key, rev_key,
		    nents, false)) {
			return (false);
		}
	}

	if (type_valid == DIMM_COMP_K_VALID) {
		if (!dimm_comp_mfg_common_type(mod, dimm, spd, comp, type_key,
		    nents)) {
			return (false);
		}
	}

	return (true);
}

static bool
dimm_comp_mfg_die(topo_mod_t *mod, tnode_t *dimm, const dimm_comp_t *comp,
    const spd_cache_t *cache, nvlist_t *spd, void *arg)
{
	const char *mfg_id = SPD_KEY_MFG_DRAM_MFG_ID;
	const char *mfg_name = SPD_KEY_MFG_DRAM_MFG_NAME;
	const char *rev = SPD_KEY_MFG_DRAM_STEP;

	return (dimm_comp_mfg_common(mod, dimm, comp, spd, &mfg_id, &mfg_name,
	    NULL, &rev, 1));
}

static bool
dimm_comp_mfg_single(topo_mod_t *mod, tnode_t *dimm, const dimm_comp_t *comp,
    const spd_cache_t *cache, nvlist_t *spd, void *arg)
{
	char *mfg_key = NULL, *mfg_str_key = NULL, *type_key = NULL;
	char *rev_key = NULL;
	const char *name = arg;
	bool ret;

	if (name == NULL) {
		name = comp->dc_comp;
	}

	if (topo_mod_asprintf(mod, &mfg_key, "module.%s.mfg-id", name) == -1 ||
	    topo_mod_asprintf(mod, &mfg_str_key, "module.%s.mfg-name",
	    name) == -1 ||
	    topo_mod_asprintf(mod, &type_key, "module.%s.type", name) == -1 ||
	    topo_mod_asprintf(mod, &rev_key, "module.%s.revision", name) ==
	    -1) {
		ret = false;
		goto done;
	}

	ret = dimm_comp_mfg_common(mod, dimm, comp, spd,
	    (const char **)&mfg_key, (const char **)&mfg_str_key,
	    (const char **)&type_key, (const char **)&rev_key, 1);

done:
	topo_mod_strfree(mod, mfg_key);
	topo_mod_strfree(mod, mfg_str_key);
	topo_mod_strfree(mod, type_key);
	topo_mod_strfree(mod, rev_key);
	return (ret);
}

static bool
dimm_comp_mfg_pmic(topo_mod_t *mod, tnode_t *dimm, const dimm_comp_t *comp,
    const spd_cache_t *cache, nvlist_t *spd, void *arg)
{
	const char **mfg_keys = NULL, **mfg_str_keys = NULL, **type_keys = NULL;
	const char **rev_keys = NULL;
	bool ret = false;
	uint32_t nents = 0, curent = 0;
	size_t alen;

	if ((cache->sc_devices & SPD_DEVICE_PMIC_0) != 0)
		nents++;
	if ((cache->sc_devices & SPD_DEVICE_PMIC_1) != 0)
		nents++;
	if ((cache->sc_devices & SPD_DEVICE_PMIC_2) != 0)
		nents++;

	if (nents == 0) {
		return (true);
	}

	alen = sizeof (char *) * nents;

	if ((mfg_keys = topo_mod_zalloc(mod, alen)) == NULL ||
	    (mfg_str_keys = topo_mod_zalloc(mod, alen)) == NULL ||
	    (type_keys = topo_mod_zalloc(mod, alen)) == NULL ||
	    (rev_keys = topo_mod_zalloc(mod, alen)) == NULL) {
		goto done;
	}

	if ((cache->sc_devices & SPD_DEVICE_PMIC_0) != 0) {
		mfg_keys[curent] = SPD_KEY_DEV_PMIC0_MFG;
		mfg_str_keys[curent] = SPD_KEY_DEV_PMIC0_MFG_NAME;
		type_keys[curent] = SPD_KEY_DEV_PMIC0_TYPE;
		rev_keys[curent] = SPD_KEY_DEV_PMIC0_REV;
		curent++;
	}

	if ((cache->sc_devices & SPD_DEVICE_PMIC_1) != 0) {
		mfg_keys[curent] = SPD_KEY_DEV_PMIC1_MFG;
		mfg_str_keys[curent] = SPD_KEY_DEV_PMIC1_MFG_NAME;
		type_keys[curent] = SPD_KEY_DEV_PMIC1_TYPE;
		rev_keys[curent] = SPD_KEY_DEV_PMIC1_REV;
		curent++;
	}

	if ((cache->sc_devices & SPD_DEVICE_PMIC_2) != 0) {
		mfg_keys[curent] = SPD_KEY_DEV_PMIC2_MFG;
		mfg_str_keys[curent] = SPD_KEY_DEV_PMIC2_MFG_NAME;
		type_keys[curent] = SPD_KEY_DEV_PMIC2_TYPE;
		rev_keys[curent] = SPD_KEY_DEV_PMIC2_REV;
		curent++;
	}

	ret = dimm_comp_mfg_common(mod, dimm, comp, spd, mfg_keys,
	    mfg_str_keys, type_keys, rev_keys, nents);

done:
	topo_mod_free(mod, mfg_keys, alen);
	topo_mod_free(mod, mfg_str_keys, alen);
	topo_mod_free(mod, type_keys, alen);
	topo_mod_free(mod, rev_keys, alen);
	return (ret);
}

static bool
dimm_comp_mfg_cd(topo_mod_t *mod, tnode_t *dimm, const dimm_comp_t *comp,
    const spd_cache_t *cache, nvlist_t *spd, void *arg)
{
	const char **mfg_keys = NULL, **mfg_str_keys = NULL, **type_keys = NULL;
	const char **rev_keys = NULL;
	bool ret = false;
	uint32_t nents = 0, curent = 0;
	size_t alen;

	if ((cache->sc_devices & SPD_DEVICE_CD_0) != 0)
		nents++;
	if ((cache->sc_devices & SPD_DEVICE_CD_1) != 0)
		nents++;

	if (nents == 0) {
		return (true);
	}

	alen = sizeof (char *) * nents;

	if ((mfg_keys = topo_mod_zalloc(mod, alen)) == NULL ||
	    (mfg_str_keys = topo_mod_zalloc(mod, alen)) == NULL ||
	    (type_keys = topo_mod_zalloc(mod, alen)) == NULL ||
	    (rev_keys = topo_mod_zalloc(mod, alen)) == NULL) {
		goto done;
	}

	if ((cache->sc_devices & SPD_DEVICE_CD_0) != 0) {
		mfg_keys[curent] = SPD_KEY_DEV_CD0_MFG;
		mfg_str_keys[curent] = SPD_KEY_DEV_CD0_MFG_NAME;
		type_keys[curent] = SPD_KEY_DEV_CD0_TYPE;
		rev_keys[curent] = SPD_KEY_DEV_CD0_REV;
		curent++;
	}

	if ((cache->sc_devices & SPD_DEVICE_CD_1) != 0) {
		mfg_keys[curent] = SPD_KEY_DEV_CD1_MFG;
		mfg_str_keys[curent] = SPD_KEY_DEV_CD1_MFG_NAME;
		type_keys[curent] = SPD_KEY_DEV_CD1_TYPE;
		rev_keys[curent] = SPD_KEY_DEV_CD1_REV;
		curent++;
	}

	ret = dimm_comp_mfg_common(mod, dimm, comp, spd, mfg_keys,
	    mfg_str_keys, type_keys, rev_keys, nents);

done:
	topo_mod_free(mod, mfg_keys, alen);
	topo_mod_free(mod, mfg_str_keys, alen);
	topo_mod_free(mod, type_keys, alen);
	topo_mod_free(mod, rev_keys, alen);
	return (ret);
}

static const dimm_comp_t dimm_comps[] = {
	{ .dc_comp = TOPO_PROP_DIMM_COMP_DIE, .dc_always = true,
	    .dc_count = dimm_comp_count_dies, .dc_mfg = dimm_comp_mfg_die },
	{ .dc_comp = TOPO_PROP_DIMM_COMP_SPD, .dc_mask = SPD_DEVICE_SPD,
	    .dc_count = dimm_comp_count_solo, .dc_mfg = dimm_comp_mfg_single,
	    .dc_type2str = topo_dimm_spd2str },
	{ .dc_comp = TOPO_PROP_DIMM_COMP_TS, .dc_mask = SPD_DEVICE_TEMP_1 |
	    SPD_DEVICE_TEMP_2, .dc_count = dimm_comp_count_mask,
	    .dc_mfg = dimm_comp_mfg_single, .dc_mfg_arg = "temp",
	    .dc_type2str = topo_dimm_temp2str },
	{ .dc_comp = TOPO_PROP_DIMM_COMP_HS, .dc_mask = SPD_DEVICE_HS },
	{ .dc_comp = TOPO_PROP_DIMM_COMP_PMIC, .dc_mask = SPD_DEVICE_PMIC_0 |
	    SPD_DEVICE_PMIC_1 | SPD_DEVICE_PMIC_2, .dc_mfg = dimm_comp_mfg_pmic,
	    .dc_type2str = topo_dimm_pmic2str  },
	{ .dc_comp = TOPO_PROP_DIMM_COMP_CD, .dc_mask = SPD_DEVICE_CD_0 |
	    SPD_DEVICE_CD_1, .dc_mfg = dimm_comp_mfg_cd,
	    .dc_type2str = topo_dimm_cd2str },
	{ .dc_comp = TOPO_PROP_DIMM_COMP_RCD, .dc_mask = SPD_DEVICE_RCD,
	    .dc_count = dimm_comp_count_regs, .dc_mfg = dimm_comp_mfg_single,
	    .dc_type2str = topo_dimm_rcd2str },
	{ .dc_comp = TOPO_PROP_DIMM_COMP_DB, .dc_mask = SPD_DEVICE_DB,
	    .dc_mfg = dimm_comp_mfg_single, .dc_type2str = topo_dimm_db2str },
	{ .dc_comp = TOPO_PROP_DIMM_COMP_MRCD, .dc_mask = SPD_DEVICE_MRCD,
	    .dc_mfg = dimm_comp_mfg_single, .dc_type2str = topo_dimm_mrcd2str },
	{ .dc_comp = TOPO_PROP_DIMM_COMP_MDB, .dc_mask = SPD_DEVICE_MDB,
	    .dc_mfg = dimm_comp_mfg_single, .dc_type2str = topo_dimm_mdb2str },
	{ .dc_comp = TOPO_PROP_DIMM_COMP_DMB, .dc_mask = SPD_DEVICE_DMB,
	    .dc_mfg = dimm_comp_mfg_single, .dc_type2str = topo_dimm_dmb2str }
};

/*
 * Go through and add the different information that exists for each type of
 * component that we might have. For most items on here, we can know they are
 * present, but we may not be able to get the count and much more than a
 * revision string or type. See additional discussion at the definition of
 * TOPO_PGROUP_DIMM_COMPONENTS for this property group and a bit of the design.
 */
static bool
topo_dimm_add_comps(topo_mod_t *mod, tnode_t *dimm, nvlist_t *spd,
    const spd_cache_t *cache)
{
	int ret;
	const char *devs[ARRAY_SIZE(dimm_comps)];
	uint_t ndevs = 0;
	const char *pg = topo_dimm_comps_pgroup.tpi_name;

	/*
	 * Always create the pgroup, as we'll at least have information about
	 * the DRAM dies to add.
	 */
	if (topo_pgroup_create(dimm, &topo_dimm_comps_pgroup, &ret) != 0) {
		topo_mod_dprintf(mod, "failed to create property group %s: %s",
		    pg, topo_strerror(ret));
		(void) topo_mod_seterrno(mod, ret);
		return (false);
	}

	for (size_t i = 0; i < ARRAY_SIZE(dimm_comps); i++) {
		const dimm_comp_t *c = &dimm_comps[i];
		char prop[64];
		bool pres = false;

		if (c->dc_always || (cache->sc_devices & c->dc_mask) != 0) {
			pres = true;
			devs[ndevs] = dimm_comps[i].dc_comp;
			ndevs++;
		}

		if (pres && c->dc_count != NULL) {
			uint32_t count = c->dc_count(c, cache, spd);
			(void) snprintf(prop, sizeof (prop), "%s-count",
			    c->dc_comp);
			if (count != 0 && topo_prop_set_uint32(dimm, pg, prop,
			    TOPO_PROP_IMMUTABLE, count, &ret) != 0) {
				topo_mod_dprintf(mod, "failed to set property "
				    "%s: %s", prop, topo_strerror(ret));
				(void) topo_mod_seterrno(mod, ret);
				return (false);
			}
		}

		if (pres && c->dc_mfg != NULL && !c->dc_mfg(mod, dimm, c, cache,
		    spd, c->dc_mfg_arg)) {
			return (false);
		}
	}

	if (topo_prop_set_string_array(dimm, pg, TOPO_PROP_DIMM_COMP,
	    TOPO_PROP_IMMUTABLE, devs, ndevs, &ret) != 0) {
		topo_mod_dprintf(mod, "failed to create components array: %s",
		    topo_strerror(ret));
		(void) topo_mod_seterrno(mod, ret);
		return (false);
	}

	return (true);
}

static int
topo_dimm_enum(topo_mod_t *mod, tnode_t *pn, const char *name,
    topo_instance_t min, topo_instance_t max, void *modarg, void *data)
{
	int ret;
	const topo_dimm_t *dimm;
	spd_error_t spd_err;
	nvlist_t *spd_nvl = NULL;
	uint32_t dram_type;
	char *mod_pn = NULL, *mod_sn = NULL, *mod_rev = NULL;
	char *mod_c_pn = NULL, *mod_c_sn = NULL, *mod_c_rev = NULL;
	tnode_t *dimm_tn;
	spd_cache_t spd_cache;

	topo_mod_dprintf(mod, "asked to enum %s [%" PRIu64 ", %" PRIu64 "] on "
	    "%s%" PRIu64 "\n", name, min, max, topo_node_name(pn),
	    topo_node_instance(pn));

	if (strcmp(name, DIMM) != 0) {
		topo_mod_dprintf(mod, "cannot enumerate %s: unknown type\n",
		    name);
		ret = -1;
		goto out;
	}

	if (data == NULL) {
		topo_mod_dprintf(mod, "cannot enumerate %s: missing required "
		    "data\n", name);
		ret = topo_mod_seterrno(mod, EMOD_METHOD_INVAL);
		goto out;
	}

	if (min != max) {
		topo_mod_dprintf(mod, "cannot enumerate %s: multiple instances "
		    "requested\n", name);
		ret = topo_mod_seterrno(mod, EMOD_METHOD_INVAL);
		goto out;
	}

	dimm = data;
	if (dimm->td_nspd == 0 || dimm->td_spd == NULL) {
		topo_mod_dprintf(mod, "cannot enumerate %s: no valid DIMM "
		    "data provided", name);
		ret = topo_mod_seterrno(mod, EMOD_METHOD_INVAL);
		goto out;
	}

	spd_nvl = libjedec_spd(dimm->td_spd, dimm->td_nspd, &spd_err);
	if (spd_nvl == NULL) {
		topo_mod_dprintf(mod, "failed to parse SPD information: got "
		    "error 0x%x", spd_err);
		ret = topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
	}

	if ((ret = nvlist_lookup_uint32(spd_nvl, SPD_KEY_DRAM_TYPE,
	    &dram_type)) != 0) {
		topo_mod_dprintf(mod, "failed to get SPD key %s: %s",
		    SPD_KEY_DRAM_TYPE, strerror(ret));
		ret = topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
		goto out;
	}

	if (!topo_dimm_crc_ok(mod, spd_nvl, dram_type)) {
		ret = topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
		goto out;
	}

	/*
	 * If we have SPD data, we'd expect all of the basic part, serial, and
	 * revision information to be available for the module. However, if
	 * there was bad data for some reason, we allow ourselves to not be able
	 * to look it up.
	 */
	if (nvlist_lookup_pairs(spd_nvl, NV_FLAG_NOENTOK,
	    SPD_KEY_MFG_MOD_PN, DATA_TYPE_STRING, &mod_pn,
	    SPD_KEY_MFG_MOD_SN, DATA_TYPE_STRING, &mod_sn,
	    SPD_KEY_MFG_MOD_REV, DATA_TYPE_STRING, &mod_rev, NULL) != 0) {
		topo_mod_dprintf(mod, "failed to look up basic DIMM FMRI "
		    "information");
		ret = topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
		goto out;
	}

	mod_c_pn = topo_mod_clean_str(mod, mod_pn);
	mod_c_sn = topo_mod_clean_str(mod, mod_sn);
	mod_c_rev = topo_mod_clean_str(mod, mod_rev);

	if ((ret = topo_node_range_create(mod, pn, DIMM, 0, 0)) != 0) {
		topo_mod_dprintf(mod, "failed to create DIMM range: %s",
		    topo_mod_errmsg(mod));
		goto out;
	}

	if ((ret = topo_dimm_create_tn(mod, pn, &dimm_tn, DIMM, 0, mod_c_pn,
	    mod_c_rev, mod_c_sn)) != 0) {
		goto out;
	}

	if (topo_node_label_set(dimm_tn, NULL, &ret) != 0) {
		topo_mod_dprintf(mod, "failed to set label on DIMM: %s",
		    topo_mod_errmsg(mod));
		ret = topo_mod_seterrno(mod, ret);
		goto out;
	}

	(void) memset(&spd_cache, 0, sizeof (spd_cache));
	spd_cache.sc_dram_type = dram_type;
	if (!topo_dimm_cache_spd(mod, spd_nvl, &spd_cache))
		goto out;

	if (!topo_dimm_add_props(mod, dimm_tn, &spd_cache))
		goto out;

	if (!topo_dimm_add_comps(mod, dimm_tn, spd_nvl, &spd_cache))
		goto out;

	ret = 0;
out:
	topo_mod_strfree(mod, mod_c_sn);
	topo_mod_strfree(mod, mod_c_pn);
	topo_mod_strfree(mod, mod_c_rev);
	nvlist_free(spd_nvl);
	return (ret);
}

static const topo_modops_t topo_dimm_ops = {
	topo_dimm_enum, NULL
};

static topo_modinfo_t topo_dimm_mod = {
	"Common DIMM Enumerator", FM_FMRI_SCHEME_HC, TOPO_MOD_DIMM_VERS,
	    &topo_dimm_ops
};

int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	if (getenv("TOPODIMMDEBUG") != NULL) {
		topo_mod_setdebug(mod);
	}
	topo_mod_dprintf(mod, "module initializing\n");

	return (topo_mod_register(mod, &topo_dimm_mod, TOPO_VERSION));
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}
