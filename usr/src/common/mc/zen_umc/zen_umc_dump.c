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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * Dump and restore logic for external processing. Dump generally runs in kernel
 * context from a well formed structure created by the driver. Restore is used
 * in userland as part of testing and related.
 *
 * Note, there are a lot of fields in these structures that are not serialized
 * because they are not used as part of the decoder (e.g. the various raw values
 * which are captured to aid future debugging).
 */

#include "zen_umc.h"
#ifndef _KERNEL
#include <string.h>
#include <strings.h>
#include <libnvpair.h>
#endif

static nvlist_t *
zen_umc_dump_dram_rule(df_dram_rule_t *rule)
{
	nvlist_t *nvl;

	nvl = fnvlist_alloc();
	fnvlist_add_uint32(nvl, "ddr_flags", rule->ddr_flags);
	fnvlist_add_uint64(nvl, "ddr_base", rule->ddr_base);
	fnvlist_add_uint64(nvl, "ddr_limit", rule->ddr_limit);
	fnvlist_add_uint16(nvl, "ddr_dest_fabid", rule->ddr_dest_fabid);
	fnvlist_add_uint8(nvl, "ddr_sock_ileave_bits",
	    rule->ddr_sock_ileave_bits);
	fnvlist_add_uint8(nvl, "ddr_die_ileave_bits",
	    rule->ddr_die_ileave_bits);
	fnvlist_add_uint8(nvl, "ddr_addr_start", rule->ddr_addr_start);
	fnvlist_add_uint8(nvl, "ddr_remap_ent", rule->ddr_remap_ent);
	fnvlist_add_uint32(nvl, "ddr_chan_ileave", rule->ddr_chan_ileave);

	return (nvl);
}

static nvlist_t *
zen_umc_dump_cs(umc_cs_t *cs)
{
	nvlist_t *nvl = fnvlist_alloc();
	nvlist_t *base = fnvlist_alloc();
	nvlist_t *sec = fnvlist_alloc();

	fnvlist_add_uint64(base, "udb_base", cs->ucs_base.udb_base);
	fnvlist_add_uint8(base, "udb_valid", cs->ucs_base.udb_valid);
	fnvlist_add_nvlist(nvl, "ucs_base", base);
	nvlist_free(base);
	fnvlist_add_uint64(sec, "udb_base", cs->ucs_sec.udb_base);
	fnvlist_add_uint8(sec, "udb_valid", cs->ucs_sec.udb_valid);
	fnvlist_add_nvlist(nvl, "ucs_sec", sec);
	nvlist_free(sec);
	fnvlist_add_uint64(nvl, "ucs_base_mask", cs->ucs_base_mask);
	fnvlist_add_uint64(nvl, "ucs_sec_mask", cs->ucs_sec_mask);
	fnvlist_add_uint8(nvl, "ucs_nrow_lo", cs->ucs_nrow_lo);
	fnvlist_add_uint8(nvl, "ucs_nrow_hi", cs->ucs_nrow_hi);
	fnvlist_add_uint8(nvl, "ucs_nbank_groups", cs->ucs_nbank_groups);
	fnvlist_add_uint8(nvl, "ucs_cs_xor", cs->ucs_cs_xor);
	fnvlist_add_uint8(nvl, "ucs_row_hi_bit", cs->ucs_row_hi_bit);
	fnvlist_add_uint8(nvl, "ucs_row_low_bit", cs->ucs_row_low_bit);
	fnvlist_add_uint8_array(nvl, "ucs_bank_bits", cs->ucs_bank_bits,
	    cs->ucs_nbanks);
	fnvlist_add_uint8_array(nvl, "ucs_col_bits", cs->ucs_col_bits,
	    cs->ucs_ncol);
	fnvlist_add_uint8(nvl, "ucs_inv_msbs", cs->ucs_inv_msbs);
	fnvlist_add_uint8_array(nvl, "ucs_rm_bits", cs->ucs_rm_bits,
	    cs->ucs_nrm);
	fnvlist_add_uint8(nvl, "ucs_inv_msbs_sec", cs->ucs_inv_msbs_sec);
	fnvlist_add_uint8_array(nvl, "ucs_rm_bits_sec", cs->ucs_rm_bits_sec,
	    cs->ucs_nrm);
	fnvlist_add_uint8(nvl, "ucs_subchan", cs->ucs_subchan);

	return (nvl);
}

static nvlist_t *
zen_umc_dump_dimm(umc_dimm_t *dimm)
{
	nvlist_t *nvl = fnvlist_alloc();
	nvlist_t *cs[ZEN_UMC_MAX_CS_PER_DIMM];

	fnvlist_add_uint32(nvl, "ud_flags", dimm->ud_flags);
	fnvlist_add_uint32(nvl, "ud_width", dimm->ud_width);
	fnvlist_add_uint32(nvl, "ud_kind", dimm->ud_kind);
	fnvlist_add_uint32(nvl, "ud_dimmno", dimm->ud_dimmno);

	for (uint_t i = 0; i < ZEN_UMC_MAX_CS_PER_DIMM; i++) {
		cs[i] = zen_umc_dump_cs(&dimm->ud_cs[i]);
	}
	fnvlist_add_nvlist_array(nvl, "ud_cs", cs, ZEN_UMC_MAX_CS_PER_DIMM);
	for (uint_t i = 0; i < ZEN_UMC_MAX_CS_PER_DIMM; i++) {
		nvlist_free(cs[i]);
	}

	return (nvl);
}

static nvlist_t *
zen_umc_dump_chan_hash(umc_chan_hash_t *hash)
{
	nvlist_t *nvl = fnvlist_alloc();

	fnvlist_add_uint32(nvl, "uch_flags", hash->uch_flags);

	if (hash->uch_flags & UMC_CHAN_HASH_F_BANK) {
		nvlist_t *banks[ZEN_UMC_MAX_CHAN_BANK_HASH];
		for (uint_t i = 0; i < ZEN_UMC_MAX_CHAN_BANK_HASH; i++) {
			banks[i] = fnvlist_alloc();

			fnvlist_add_uint32(banks[i], "ubh_row_xor",
			    hash->uch_bank_hashes[i].ubh_row_xor);
			fnvlist_add_uint32(banks[i], "ubh_col_xor",
			    hash->uch_bank_hashes[i].ubh_col_xor);
			fnvlist_add_boolean_value(banks[i], "ubh_en",
			    hash->uch_bank_hashes[i].ubh_en);
		}
		fnvlist_add_nvlist_array(nvl, "uch_bank_hashes", banks,
		    ZEN_UMC_MAX_CHAN_BANK_HASH);

		for (uint_t i = 0; i < ZEN_UMC_MAX_CHAN_BANK_HASH; i++) {
			nvlist_free(banks[i]);
		}
	}

	if (hash->uch_flags & UMC_CHAN_HASH_F_RM) {
		nvlist_t *rm[ZEN_UMC_MAX_CHAN_RM_HASH];
		for (uint_t i = 0; i < ZEN_UMC_MAX_CHAN_RM_HASH; i++) {
			rm[i] = fnvlist_alloc();

			fnvlist_add_uint64(rm[i], "uah_addr_xor",
			    hash->uch_rm_hashes[i].uah_addr_xor);
			fnvlist_add_boolean_value(rm[i], "uah_en",
			    hash->uch_rm_hashes[i].uah_en);
		}
		fnvlist_add_nvlist_array(nvl, "uch_rm_hashes", rm,
		    ZEN_UMC_MAX_CHAN_RM_HASH);

		for (uint_t i = 0; i < ZEN_UMC_MAX_CHAN_RM_HASH; i++) {
			nvlist_free(rm[i]);
		}
	}

	if (hash->uch_flags & UMC_CHAN_HASH_F_CS) {
		nvlist_t *cs[ZEN_UMC_MAX_CHAN_CS_HASH];
		for (uint_t i = 0; i < ZEN_UMC_MAX_CHAN_CS_HASH; i++) {
			cs[i] = fnvlist_alloc();

			fnvlist_add_uint64(cs[i], "uah_addr_xor",
			    hash->uch_rm_hashes[i].uah_addr_xor);
			fnvlist_add_boolean_value(cs[i], "uah_en",
			    hash->uch_rm_hashes[i].uah_en);
		}
		fnvlist_add_nvlist_array(nvl, "uch_cs_hashes", cs,
		    ZEN_UMC_MAX_CHAN_CS_HASH);

		for (uint_t i = 0; i < ZEN_UMC_MAX_CHAN_CS_HASH; i++) {
			nvlist_free(cs[i]);
		}
	}

	if (hash->uch_flags & UMC_CHAN_HASH_F_PC) {
		nvlist_t *pc = fnvlist_alloc();

		fnvlist_add_uint32(pc, "uph_row_xor",
		    hash->uch_pc_hash.uph_row_xor);
		fnvlist_add_uint32(pc, "uph_col_xor",
		    hash->uch_pc_hash.uph_col_xor);
		fnvlist_add_uint8(pc, "uph_bank_xor",
		    hash->uch_pc_hash.uph_bank_xor);
		fnvlist_add_boolean_value(pc, "uph_en",
		    hash->uch_pc_hash.uph_en);

		fnvlist_add_nvlist(nvl, "uch_pch_hash", pc);
		fnvlist_free(pc);

	}

	return (nvl);
}

static nvlist_t *
zen_umc_dump_chan(zen_umc_chan_t *chan)
{
	nvlist_t *nvl, *hash;
	nvlist_t *rules[ZEN_UMC_MAX_CS_RULES];
	nvlist_t *offsets[ZEN_UMC_MAX_DRAM_OFFSET];
	nvlist_t *dimms[ZEN_UMC_MAX_DIMMS];

	nvl = fnvlist_alloc();
	fnvlist_add_uint32(nvl, "chan_flags", chan->chan_flags);
	fnvlist_add_uint32(nvl, "chan_fabid", chan->chan_fabid);
	fnvlist_add_uint32(nvl, "chan_instid", chan->chan_instid);
	fnvlist_add_uint32(nvl, "chan_logid", chan->chan_logid);
	fnvlist_add_uint32(nvl, "chan_np2_space0", chan->chan_np2_space0);
	fnvlist_add_uint32(nvl, "chan_type", chan->chan_type);

	for (uint_t i = 0; i < chan->chan_nrules; i++) {
		rules[i] = zen_umc_dump_dram_rule(&chan->chan_rules[i]);
	}

	for (uint_t i = 0; i < chan->chan_nrules - 1; i++) {
		offsets[i] = fnvlist_alloc();
		fnvlist_add_boolean_value(offsets[i], "cho_valid",
		    chan->chan_offsets[i].cho_valid);
		fnvlist_add_uint64(offsets[i], "cho_offset",
		    chan->chan_offsets[i].cho_offset);
	}

	for (uint_t i = 0; i < ZEN_UMC_MAX_DIMMS; i++) {
		dimms[i] = zen_umc_dump_dimm(&chan->chan_dimms[i]);
	}

	fnvlist_add_nvlist_array(nvl, "chan_rules", rules, chan->chan_nrules);
	fnvlist_add_nvlist_array(nvl, "chan_offsets", offsets,
	    chan->chan_nrules - 1);
	fnvlist_add_nvlist_array(nvl, "chan_dimms", dimms, ZEN_UMC_MAX_DIMMS);
	hash = zen_umc_dump_chan_hash(&chan->chan_hash);
	fnvlist_add_nvlist(nvl, "chan_hash", hash);

	for (uint_t i = 0; i < chan->chan_nrules; i++) {
		nvlist_free(rules[i]);
	}

	for (uint_t i = 0; i < chan->chan_nrules - 1; i++) {
		nvlist_free(offsets[i]);
	}

	for (uint_t i = 0; i < ZEN_UMC_MAX_DIMMS; i++) {
		nvlist_free(dimms[i]);
	}

	nvlist_free(hash);

	return (nvl);
}

static nvlist_t *
zen_umc_dump_df(zen_umc_df_t *df)
{
	nvlist_t *nvl;
	nvlist_t *rules[ZEN_UMC_MAX_DRAM_RULES];
	nvlist_t *remap[ZEN_UMC_MAX_CS_REMAPS];
	nvlist_t *chan[ZEN_UMC_MAX_UMCS];

	nvl = fnvlist_alloc();
	fnvlist_add_uint32(nvl, "zud_flags", df->zud_flags);
	fnvlist_add_uint32(nvl, "zud_dfno", df->zud_dfno);
	fnvlist_add_uint32(nvl, "zud_ccm_inst", df->zud_ccm_inst);
	fnvlist_add_uint64(nvl, "zud_hole_base", df->zud_hole_base);

	for (uint_t i = 0; i < df->zud_dram_nrules; i++) {
		rules[i] = zen_umc_dump_dram_rule(&df->zud_rules[i]);
	}

	for (uint_t i = 0; i < df->zud_cs_nremap; i++) {
		remap[i] = fnvlist_alloc();
		fnvlist_add_uint16_array(remap[i], "csr_remaps",
		    df->zud_remap[i].csr_remaps, df->zud_remap[i].csr_nremaps);
	}

	for (uint_t i = 0; i < df->zud_nchan; i++) {
		chan[i] = zen_umc_dump_chan(&df->zud_chan[i]);
	}

	fnvlist_add_nvlist_array(nvl, "zud_rules", rules, df->zud_dram_nrules);
	fnvlist_add_nvlist_array(nvl, "zud_remap", remap, df->zud_cs_nremap);
	fnvlist_add_nvlist_array(nvl, "zud_chan", chan, df->zud_nchan);

	for (uint_t i = 0; i < df->zud_dram_nrules; i++) {
		nvlist_free(rules[i]);
	}

	for (uint_t i = 0; i < df->zud_cs_nremap; i++) {
		nvlist_free(remap[i]);
	}

	for (uint_t i = 0; i < df->zud_nchan; i++) {
		nvlist_free(chan[i]);
	}

	return (nvl);
}

nvlist_t *
zen_umc_dump_decoder(zen_umc_t *umc)
{
	nvlist_t *nvl, *umc_nvl, *decomp;
	nvlist_t *dfs[ZEN_UMC_MAX_DFS];

	nvl = fnvlist_alloc();
	fnvlist_add_uint32(nvl, "mc_dump_version", 0);
	fnvlist_add_string(nvl, "mc_dump_driver", "zen_umc");

	umc_nvl = fnvlist_alloc();
	fnvlist_add_uint64(umc_nvl, "umc_tom", umc->umc_tom);
	fnvlist_add_uint64(umc_nvl, "umc_tom2", umc->umc_tom2);
	fnvlist_add_uint32(umc_nvl, "umc_family", umc->umc_family);
	fnvlist_add_uint32(umc_nvl, "umc_df_rev", umc->umc_df_rev);

	decomp = fnvlist_alloc();
	fnvlist_add_uint32(decomp, "dfd_sock_mask",
	    umc->umc_decomp.dfd_sock_mask);
	fnvlist_add_uint32(decomp, "dfd_die_mask",
	    umc->umc_decomp.dfd_die_mask);
	fnvlist_add_uint32(decomp, "dfd_node_mask",
	    umc->umc_decomp.dfd_node_mask);
	fnvlist_add_uint32(decomp, "dfd_comp_mask",
	    umc->umc_decomp.dfd_comp_mask);
	fnvlist_add_uint8(decomp, "dfd_sock_shift",
	    umc->umc_decomp.dfd_sock_shift);
	fnvlist_add_uint8(decomp, "dfd_die_shift",
	    umc->umc_decomp.dfd_die_shift);
	fnvlist_add_uint8(decomp, "dfd_node_shift",
	    umc->umc_decomp.dfd_node_shift);
	fnvlist_add_uint8(decomp, "dfd_comp_shift",
	    umc->umc_decomp.dfd_comp_shift);
	fnvlist_add_nvlist(umc_nvl, "umc_decomp", decomp);
	nvlist_free(decomp);

	for (uint_t i = 0; i < umc->umc_ndfs; i++) {
		dfs[i] = zen_umc_dump_df(&umc->umc_dfs[i]);
	}

	fnvlist_add_nvlist_array(umc_nvl, "umc_dfs", dfs, umc->umc_ndfs);
	fnvlist_add_nvlist(nvl, "zen_umc", umc_nvl);
	for (uint_t i = 0; i < umc->umc_ndfs; i++) {
		nvlist_free(dfs[i]);
	}

	return (nvl);
}

static boolean_t
zen_umc_restore_dram_rule(nvlist_t *nvl, df_dram_rule_t *rule)
{
	return (nvlist_lookup_pairs(nvl, 0,
	    "ddr_flags", DATA_TYPE_UINT32, &rule->ddr_flags,
	    "ddr_base", DATA_TYPE_UINT64, &rule->ddr_base,
	    "ddr_limit", DATA_TYPE_UINT64, &rule->ddr_limit,
	    "ddr_dest_fabid", DATA_TYPE_UINT16, &rule->ddr_dest_fabid,
	    "ddr_sock_ileave_bits", DATA_TYPE_UINT8,
	    &rule->ddr_sock_ileave_bits,
	    "ddr_die_ileave_bits", DATA_TYPE_UINT8, &rule->ddr_die_ileave_bits,
	    "ddr_addr_start", DATA_TYPE_UINT8, &rule->ddr_addr_start,
	    "ddr_remap_ent", DATA_TYPE_UINT8, &rule->ddr_remap_ent,
	    "ddr_chan_ileave", DATA_TYPE_UINT32, &rule->ddr_chan_ileave,
	    NULL) == 0);
}

static boolean_t
zen_umc_restore_cs(nvlist_t *nvl, umc_cs_t *cs)
{
	nvlist_t *base, *sec;
	uint8_t *bank_bits, *col_bits, *rm_bits, *rm_bits_sec;
	uint_t nbanks, ncols, nrm, nrm_sec;

	if (nvlist_lookup_pairs(nvl, 0,
	    "ucs_base", DATA_TYPE_NVLIST, &base,
	    "ucs_sec", DATA_TYPE_NVLIST, &sec,
	    "ucs_base_mask", DATA_TYPE_UINT64, &cs->ucs_base_mask,
	    "ucs_sec_mask", DATA_TYPE_UINT64, &cs->ucs_sec_mask,
	    "ucs_nrow_lo", DATA_TYPE_UINT8, &cs->ucs_nrow_lo,
	    "ucs_nrow_hi", DATA_TYPE_UINT8, &cs->ucs_nrow_hi,
	    "ucs_nbank_groups", DATA_TYPE_UINT8, &cs->ucs_nbank_groups,
	    "ucs_cs_xor", DATA_TYPE_UINT8, &cs->ucs_cs_xor,
	    "ucs_row_hi_bit", DATA_TYPE_UINT8, &cs->ucs_row_hi_bit,
	    "ucs_row_low_bit", DATA_TYPE_UINT8, &cs->ucs_row_low_bit,
	    "ucs_bank_bits", DATA_TYPE_UINT8_ARRAY, &bank_bits, &nbanks,
	    "ucs_col_bits", DATA_TYPE_UINT8_ARRAY, &col_bits, &ncols,
	    "ucs_inv_msbs", DATA_TYPE_UINT8, &cs->ucs_inv_msbs,
	    "ucs_rm_bits", DATA_TYPE_UINT8_ARRAY, &rm_bits, &nrm,
	    "ucs_inv_msbs_sec", DATA_TYPE_UINT8, &cs->ucs_inv_msbs_sec,
	    "ucs_rm_bits_sec", DATA_TYPE_UINT8_ARRAY, &rm_bits_sec, &nrm_sec,
	    "ucs_subchan", DATA_TYPE_UINT8, &cs->ucs_subchan,
	    NULL) != 0) {
		return (B_FALSE);
	}

	if (nbanks > ZEN_UMC_MAX_BANK_BITS ||
	    ncols > ZEN_UMC_MAX_COL_BITS ||
	    nrm > ZEN_UMC_MAX_RM_BITS ||
	    nrm != nrm_sec) {
		return (B_FALSE);
	}

	cs->ucs_nbanks = nbanks;
	cs->ucs_ncol = ncols;
	cs->ucs_nrm = nrm;

	bcopy(bank_bits, cs->ucs_bank_bits, cs->ucs_nbanks *
	    sizeof (uint8_t));
	bcopy(col_bits, cs->ucs_col_bits, cs->ucs_ncol * sizeof (uint8_t));
	bcopy(rm_bits, cs->ucs_rm_bits, cs->ucs_nrm * sizeof (uint8_t));
	bcopy(rm_bits_sec, cs->ucs_rm_bits_sec, cs->ucs_nrm *
	    sizeof (uint8_t));

	if (nvlist_lookup_pairs(base, 0,
	    "udb_base", DATA_TYPE_UINT64, &cs->ucs_base.udb_base,
	    "udb_valid", DATA_TYPE_UINT8, &cs->ucs_base.udb_valid,
	    NULL) != 0) {
		return (B_FALSE);
	}

	if (nvlist_lookup_pairs(sec, 0,
	    "udb_base", DATA_TYPE_UINT64, &cs->ucs_sec.udb_base,
	    "udb_valid", DATA_TYPE_UINT8, &cs->ucs_sec.udb_valid,
	    NULL) != 0) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
zen_umc_restore_dimm(nvlist_t *nvl, umc_dimm_t *dimm)
{
	nvlist_t **cs;
	uint_t ncs;

	if (nvlist_lookup_pairs(nvl, 0,
	    "ud_flags", DATA_TYPE_UINT32, &dimm->ud_flags,
	    "ud_width", DATA_TYPE_UINT32, &dimm->ud_width,
	    "ud_kind", DATA_TYPE_UINT32, &dimm->ud_kind,
	    "ud_dimmno", DATA_TYPE_UINT32, &dimm->ud_dimmno,
	    "ud_cs", DATA_TYPE_NVLIST_ARRAY, &cs, &ncs,
	    NULL) != 0) {
		return (B_FALSE);
	}

	if (ncs != ZEN_UMC_MAX_CS_PER_DIMM) {
		return (B_FALSE);
	}

	for (uint_t i = 0; i < ZEN_UMC_MAX_CS_PER_DIMM; i++) {
		if (!zen_umc_restore_cs(cs[i], &dimm->ud_cs[i])) {
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static boolean_t
zen_umc_restore_hash(nvlist_t *nvl, umc_chan_hash_t *hash)
{
	if (nvlist_lookup_uint32(nvl, "uch_flags", &hash->uch_flags) != 0) {
		return (B_FALSE);
	}

	if (hash->uch_flags & UMC_CHAN_HASH_F_BANK) {
		nvlist_t **banks;
		uint_t nbanks;

		if (nvlist_lookup_nvlist_array(nvl, "uch_bank_hashes", &banks,
		    &nbanks) != 0) {
			return (B_FALSE);
		}

		if (nbanks != ZEN_UMC_MAX_CHAN_BANK_HASH) {
			return (B_FALSE);
		}

		for (uint_t i = 0; i < nbanks; i++) {
			if (nvlist_lookup_pairs(banks[i], 0,
			    "ubh_row_xor", DATA_TYPE_UINT32,
			    &hash->uch_bank_hashes[i].ubh_row_xor,
			    "ubh_col_xor", DATA_TYPE_UINT32,
			    &hash->uch_bank_hashes[i].ubh_col_xor,
			    "ubh_en", DATA_TYPE_BOOLEAN_VALUE,
			    &hash->uch_bank_hashes[i].ubh_en,
			    NULL) != 0) {
				return (B_FALSE);
			}
		}
	}

	if (hash->uch_flags & UMC_CHAN_HASH_F_RM) {
		nvlist_t **rm;
		uint_t nrm;

		if (nvlist_lookup_nvlist_array(nvl, "uch_rm_hashes", &rm,
		    &nrm) != 0) {
			return (B_FALSE);
		}

		if (nrm != ZEN_UMC_MAX_CHAN_RM_HASH) {
			return (B_FALSE);
		}

		for (uint_t i = 0; i < nrm; i++) {
			if (nvlist_lookup_pairs(rm[i], 0,
			    "uah_addr_xor", DATA_TYPE_UINT64,
			    &hash->uch_rm_hashes[i].uah_addr_xor,
			    "uah_en", DATA_TYPE_BOOLEAN_VALUE,
			    &hash->uch_rm_hashes[i].uah_en,
			    NULL) != 0) {
				return (B_FALSE);
			}
		}
	}

	if (hash->uch_flags & UMC_CHAN_HASH_F_CS) {
		nvlist_t **cs;
		uint_t ncs;

		if (nvlist_lookup_nvlist_array(nvl, "uch_cs_hashes", &cs,
		    &ncs) != 0) {
			return (B_FALSE);
		}

		if (ncs != ZEN_UMC_MAX_CHAN_CS_HASH) {
			return (B_FALSE);
		}

		for (uint_t i = 0; i < ncs; i++) {
			if (nvlist_lookup_pairs(cs[i], 0,
			    "uah_addr_xor", DATA_TYPE_UINT64,
			    &hash->uch_cs_hashes[i].uah_addr_xor,
			    "uah_en", DATA_TYPE_BOOLEAN_VALUE,
			    &hash->uch_cs_hashes[i].uah_en,
			    NULL) != 0) {
				return (B_FALSE);
			}
		}
	}

	if (hash->uch_flags & UMC_CHAN_HASH_F_PC) {
		nvlist_t *pc;

		if (nvlist_lookup_nvlist(nvl, "uch_pch_hash", &pc) != 0) {
			return (B_FALSE);
		}

		if (nvlist_lookup_pairs(pc, 0,
		    "uph_row_xor", DATA_TYPE_UINT32,
		    &hash->uch_pc_hash.uph_row_xor,
		    "uph_col_xor", DATA_TYPE_UINT32,
		    &hash->uch_pc_hash.uph_col_xor,
		    "uph_bank_xor", DATA_TYPE_UINT32,
		    &hash->uch_pc_hash.uph_bank_xor,
		    "uph_en", DATA_TYPE_BOOLEAN_VALUE,
		    &hash->uch_pc_hash.uph_en,
		    NULL) != 0) {
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

static boolean_t
zen_umc_restore_chan(nvlist_t *nvl, zen_umc_chan_t *chan)
{
	uint_t noffsets, ndimms;
	nvlist_t **rules, **offsets, **dimms, *hash;

	if (nvlist_lookup_pairs(nvl, 0,
	    "chan_flags", DATA_TYPE_UINT32, &chan->chan_flags,
	    "chan_fabid", DATA_TYPE_UINT32, &chan->chan_fabid,
	    "chan_instid", DATA_TYPE_UINT32, &chan->chan_instid,
	    "chan_logid", DATA_TYPE_UINT32, &chan->chan_logid,
	    "chan_rules", DATA_TYPE_NVLIST_ARRAY, &rules, &chan->chan_nrules,
	    "chan_np2_space0", DATA_TYPE_UINT32, &chan->chan_np2_space0,
	    "chan_type", DATA_TYPE_UINT32, &chan->chan_np2_space0,
	    "chan_offsets", DATA_TYPE_NVLIST_ARRAY, &offsets, &noffsets,
	    "chan_dimms", DATA_TYPE_NVLIST_ARRAY, &dimms, &ndimms,
	    "chan_hash", DATA_TYPE_NVLIST, &hash,
	    NULL) != 0) {
		return (B_FALSE);
	}

	if (chan->chan_nrules > ZEN_UMC_MAX_CS_RULES ||
	    noffsets != chan->chan_nrules - 1 || ndimms != ZEN_UMC_MAX_DIMMS) {
		return (B_FALSE);
	}

	for (uint_t i = 0; i < chan->chan_nrules; i++) {
		if (!zen_umc_restore_dram_rule(rules[i],
		    &chan->chan_rules[i])) {
			return (B_FALSE);
		}
	}

	for (uint_t i = 0; i < chan->chan_nrules - 1; i++) {
		chan_offset_t *coff = &chan->chan_offsets[i];

		if (nvlist_lookup_pairs(offsets[i], 0,
		    "cho_valid", DATA_TYPE_BOOLEAN_VALUE, &coff->cho_valid,
		    "cho_offset", DATA_TYPE_UINT64, &coff->cho_offset,
		    NULL) != 0) {
			return (B_FALSE);
		}
	}

	for (uint_t i = 0; i < ZEN_UMC_MAX_DIMMS; i++) {
		if (!zen_umc_restore_dimm(dimms[i], &chan->chan_dimms[i])) {
			return (B_FALSE);
		}
	}

	if (!zen_umc_restore_hash(hash, &chan->chan_hash)) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
zen_umc_restore_df(nvlist_t *nvl, zen_umc_df_t *df)
{
	nvlist_t **rules, **chan, **remap;

	if (nvlist_lookup_pairs(nvl, 0,
	    "zud_flags", DATA_TYPE_UINT32, &df->zud_flags,
	    "zud_dfno", DATA_TYPE_UINT32, &df->zud_dfno,
	    "zud_ccm_inst", DATA_TYPE_UINT32, &df->zud_ccm_inst,
	    "zud_hole_base", DATA_TYPE_UINT64, &df->zud_hole_base,
	    "zud_rules", DATA_TYPE_NVLIST_ARRAY, &rules, &df->zud_dram_nrules,
	    "zud_remap", DATA_TYPE_NVLIST_ARRAY, &remap, &df->zud_cs_nremap,
	    "zud_chan", DATA_TYPE_NVLIST_ARRAY, &chan, &df->zud_nchan,
	    NULL != 0) ||
	    df->zud_dram_nrules > ZEN_UMC_MAX_DRAM_RULES ||
	    df->zud_cs_nremap > ZEN_UMC_MAX_CS_REMAPS ||
	    df->zud_nchan > ZEN_UMC_MAX_UMCS) {
		return (B_FALSE);
	}

	for (uint_t i = 0; i < df->zud_dram_nrules; i++) {
		if (!zen_umc_restore_dram_rule(rules[i], &df->zud_rules[i])) {
			return (B_FALSE);
		}
	}

	for (uint_t i = 0; i < df->zud_cs_nremap; i++) {
		uint16_t *u16p;
		if (nvlist_lookup_uint16_array(remap[i], "csr_remaps", &u16p,
		    &df->zud_remap[i].csr_nremaps) != 0 ||
		    df->zud_remap[i].csr_nremaps > ZEN_UMC_MAX_REMAP_ENTS) {
			return (B_FALSE);
		}
		bcopy(u16p, df->zud_remap[i].csr_remaps,
		    df->zud_remap[i].csr_nremaps);
	}

	for (uint_t i = 0; i < df->zud_nchan; i++) {
		if (!zen_umc_restore_chan(chan[i], &df->zud_chan[i])) {
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

boolean_t
zen_umc_restore_decoder(nvlist_t *nvl, zen_umc_t *umc)
{
	uint32_t vers;
	char *driver;
	nvlist_t *umc_nvl, *decomp, **dfs;
	bzero(umc, sizeof (zen_umc_t));

	if (nvlist_lookup_pairs(nvl, 0,
	    "mc_dump_version", DATA_TYPE_UINT32, &vers,
	    "mc_dump_driver", DATA_TYPE_STRING, &driver,
	    NULL) != 0 || vers != 0 || strcmp(driver, "zen_umc") != 0 ||
	    nvlist_lookup_nvlist(nvl, "zen_umc", &umc_nvl) != 0) {
		return (B_FALSE);
	}

	if (nvlist_lookup_pairs(umc_nvl, 0,
	    "umc_tom", DATA_TYPE_UINT64, &umc->umc_tom,
	    "umc_tom2", DATA_TYPE_UINT64, &umc->umc_tom2,
	    "umc_family", DATA_TYPE_UINT32, &umc->umc_family,
	    "umc_df_rev", DATA_TYPE_UINT32, &umc->umc_df_rev,
	    "umc_decomp", DATA_TYPE_NVLIST, &decomp,
	    "umc_dfs", DATA_TYPE_NVLIST_ARRAY, &dfs, &umc->umc_ndfs,
	    NULL) != 0 || umc->umc_ndfs > ZEN_UMC_MAX_DFS) {
		return (B_FALSE);
	}


	if (nvlist_lookup_pairs(decomp, 0,
	    "dfd_sock_mask", DATA_TYPE_UINT32, &umc->umc_decomp.dfd_sock_mask,
	    "dfd_die_mask", DATA_TYPE_UINT32, &umc->umc_decomp.dfd_die_mask,
	    "dfd_node_mask", DATA_TYPE_UINT32, &umc->umc_decomp.dfd_node_mask,
	    "dfd_comp_mask", DATA_TYPE_UINT32, &umc->umc_decomp.dfd_comp_mask,
	    "dfd_sock_shift", DATA_TYPE_UINT8, &umc->umc_decomp.dfd_sock_shift,
	    "dfd_die_shift", DATA_TYPE_UINT8, &umc->umc_decomp.dfd_die_shift,
	    "dfd_node_shift", DATA_TYPE_UINT8, &umc->umc_decomp.dfd_node_shift,
	    "dfd_comp_shift", DATA_TYPE_UINT8, &umc->umc_decomp.dfd_comp_shift,
	    NULL) != 0) {
		return (B_FALSE);
	}

	for (uint_t i = 0; i < umc->umc_ndfs; i++) {
		if (!zen_umc_restore_df(dfs[i], &umc->umc_dfs[i])) {
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}
