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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Zen UMC Decoding logic. See zen_umc.c for an overview of everything. This
 * implements shared userland/kernel decoding.
 */

#include "zen_umc.h"

#ifndef _KERNEL
#include <strings.h>
#endif

/*
 * Address constants.
 */
#define	ZEN_UMC_TOM2_START	0x100000000ULL
#define	ZEN_UMC_TOM2_RSVD_BEGIN	0xfd00000000ULL
#define	ZEN_UMC_TOM2_RSVD_END	0x10000000000ULL

/*
 * COD based hashing constants.
 */
#define	ZEN_UMC_COD_NBITS	3
#define	ZEN_UMC_NPS_MOD_NBITS	3

/*
 * Enumeration that represents which parts of the NPS 1K/2K non-power of 2 hash
 * we should use. These are ordered such their indexes correspond with the
 * 'hashes' array indexes used in zen_umc_decode_ileave_nps_k_mod().
 */
typedef enum {
	ZEN_UMC_NP2_K_HASH_8 = 0,
	ZEN_UMC_NP2_K_HASH_9,
	ZEN_UMC_NP2_K_HASH_12,
	ZEN_UMC_NP2_K_HASH_13
} zen_umc_np2_k_hash_t;

typedef struct {
	/*
	 * Indicates what the type of this rule is.
	 */
	df_chan_ileave_t zukr_type;
	/*
	 * This is the modulus that this rule uses.
	 */
	uint32_t zukr_mod;
	/*
	 * Indicates that this rule requires socket interleaving. Otherwise we
	 * expect no socket interleaving to be enabled.
	 */
	boolean_t zukr_sock;
	/*
	 * This is the 'high' portion of the original address that is used as
	 * part of the division and modulus logic when we take it. This bit is
	 * inclusive, e.g. a value of 12 indicates we want addr[64:12].
	 */
	uint32_t zukr_high;
	/*
	 * This indicates at what point in the modulus address the high bits
	 * should arrive at.
	 */
	uint32_t zukr_mod_shift;
	/*
	 * This indicates how we should fill the remaining bits in the modulus
	 * address. This is either zero filled or an original address bit. Only
	 * address bits 8 or 9 are ever used so we cheat and treat a zero here
	 * as zero filled. Only the first zukr_mod_shift bits will be
	 * considered. This and zukr_mod_shit are used prior to the modulus
	 * calculation.
	 */
	uint32_t zukr_mod_fill[5];
	/*
	 * The next series of values defines how to construct the channel. The
	 * channel is always made up of some number of bits from the modulus
	 * value and then optionally some of the hash bits. The first value
	 * indicates how many bits to shift the resulting modulus value by. Any
	 * bit that it is shifted over by must be filled by a hashed value. The
	 * indication of which hash bit is indicated by its starting address
	 * number.
	 */
	uint32_t zukr_chan_mod_shift;
	zen_umc_np2_k_hash_t zukr_chan_fill[2];
	/*
	 * Next, it's time to describe how to construct the normalized address.
	 * There is a portion of it which is divided by the modulus. This is
	 * always going to be the high bits, but sometimes includes additional
	 * lower parts of the physical address ORed in. The first value
	 * indicates how many consecutive address bits should be included. The
	 * second indicates the starting address.
	 */
	uint32_t zukr_div_addr;
	uint32_t zukr_div_naddr;
	/*
	 * Finally the middle portion of the normalized address.
	 */
	uint32_t zukr_norm_addr;
	uint32_t zukr_norm_naddr;
} zen_umc_np2_k_rule_t;

const zen_umc_np2_k_rule_t zen_umc_np2_k_rules[] = { {
	.zukr_type = DF_CHAN_ILEAVE_NPS4_3CH_1K,
	.zukr_mod = 3,
	.zukr_high = 12,
	.zukr_mod_shift = 2,
	.zukr_mod_fill = { 8, 9 },
	.zukr_chan_mod_shift = 0,
	.zukr_div_addr = 8,
	.zukr_div_naddr = 2,
	.zukr_norm_addr = 10,
	.zukr_norm_naddr = 2
}, {
	.zukr_type = DF_CHAN_ILEAVE_NPS4_3CH_2K,
	.zukr_mod = 3,
	.zukr_high = 12,
	.zukr_mod_shift = 2,
	.zukr_mod_fill = { 0, 8 },
	.zukr_chan_mod_shift = 0,
	.zukr_div_addr = 8,
	.zukr_div_naddr = 1,
	.zukr_norm_addr = 9,
	.zukr_norm_naddr = 3
}, {
	.zukr_type = DF_CHAN_ILEAVE_NPS2_6CH_1K,
	.zukr_mod = 3,
	.zukr_high = 12,
	.zukr_mod_shift = 2,
	.zukr_mod_fill = { 0, 9 },
	.zukr_chan_mod_shift = 1,
	.zukr_chan_fill = { ZEN_UMC_NP2_K_HASH_8 },
	.zukr_div_addr = 9,
	.zukr_div_naddr = 1,
	.zukr_norm_addr = 10,
	.zukr_norm_naddr = 2
}, {
	.zukr_type = DF_CHAN_ILEAVE_NPS2_6CH_2K,
	.zukr_mod = 3,
	.zukr_high = 12,
	.zukr_mod_shift = 2,
	.zukr_mod_fill = { 0, 0 },
	.zukr_chan_mod_shift = 1,
	.zukr_chan_fill = { ZEN_UMC_NP2_K_HASH_8 },
	.zukr_div_naddr = 0,
	.zukr_norm_addr = 9,
	.zukr_norm_naddr = 3
}, {
	.zukr_type = DF_CHAN_ILEAVE_NPS1_12CH_1K,
	.zukr_mod = 3,
	.zukr_high = 12,
	.zukr_mod_shift = 2,
	.zukr_mod_fill = { 0, 0 },
	.zukr_chan_mod_shift = 2,
	.zukr_chan_fill = { ZEN_UMC_NP2_K_HASH_8, ZEN_UMC_NP2_K_HASH_9 },
	.zukr_div_naddr = 0,
	.zukr_norm_addr = 10,
	.zukr_norm_naddr = 2
}, {
	.zukr_type = DF_CHAN_ILEAVE_NPS1_12CH_1K,
	.zukr_mod = 3,
	.zukr_high = 12,
	.zukr_mod_shift = 2,
	.zukr_mod_fill = { 0, 0 },
	.zukr_chan_mod_shift = 2,
	.zukr_chan_fill = { ZEN_UMC_NP2_K_HASH_8, ZEN_UMC_NP2_K_HASH_9 },
	.zukr_div_naddr = 0,
	.zukr_norm_addr = 10,
	.zukr_norm_naddr = 2
}, {
	.zukr_type = DF_CHAN_ILEAVE_NPS1_12CH_2K,
	.zukr_mod = 3,
	.zukr_high = 13,
	.zukr_mod_shift = 3,
	.zukr_mod_fill = { 0, 0, 0 },
	.zukr_chan_mod_shift = 2,
	.zukr_chan_fill = { ZEN_UMC_NP2_K_HASH_8, ZEN_UMC_NP2_K_HASH_12 },
	.zukr_div_naddr = 0,
	.zukr_norm_addr = 9,
	.zukr_norm_naddr = 3
}, {
	.zukr_type = DF_CHAN_ILEAVE_NPS0_24CH_1K,
	.zukr_mod = 3,
	.zukr_sock = B_TRUE,
	.zukr_high = 13,
	.zukr_mod_shift = 3,
	.zukr_mod_fill = { 0, 0, 0 },
	.zukr_chan_mod_shift = 2,
	.zukr_chan_fill = { ZEN_UMC_NP2_K_HASH_9, ZEN_UMC_NP2_K_HASH_12 },
	.zukr_div_naddr = 0,
	.zukr_norm_addr = 10,
	.zukr_norm_naddr = 2
}, {
	.zukr_type = DF_CHAN_ILEAVE_NPS0_24CH_2K,
	.zukr_mod = 3,
	.zukr_sock = B_TRUE,
	.zukr_high = 14,
	.zukr_mod_shift = 4,
	.zukr_mod_fill = { 0, 0, 0, 0 },
	.zukr_chan_mod_shift = 2,
	.zukr_chan_fill = { ZEN_UMC_NP2_K_HASH_12, ZEN_UMC_NP2_K_HASH_13 },
	.zukr_div_naddr = 0,
	.zukr_norm_addr = 9,
	.zukr_norm_naddr = 3
}, {
	.zukr_type = DF_CHAN_ILEAVE_NPS2_5CH_1K,
	.zukr_mod = 5,
	.zukr_high = 12,
	.zukr_mod_shift = 2,
	.zukr_mod_fill = { 8, 9 },
	.zukr_chan_mod_shift = 0,
	.zukr_div_addr = 8,
	.zukr_div_naddr = 2,
	.zukr_norm_addr = 10,
	.zukr_norm_naddr = 2
}, {
	.zukr_type = DF_CHAN_ILEAVE_NPS2_5CH_2K,
	.zukr_mod = 5,
	.zukr_high = 12,
	.zukr_mod_shift = 2,
	.zukr_mod_fill = { 0, 8 },
	.zukr_chan_mod_shift = 0,
	.zukr_div_addr = 8,
	.zukr_div_naddr = 1,
	.zukr_norm_addr = 9,
	.zukr_norm_naddr = 3
}, {
	.zukr_type = DF_CHAN_ILEAVE_NPS1_10CH_1K,
	.zukr_mod = 5,
	.zukr_high = 12,
	.zukr_mod_shift = 2,
	.zukr_mod_fill = { 0, 9 },
	.zukr_chan_mod_shift = 1,
	.zukr_chan_fill = { ZEN_UMC_NP2_K_HASH_8 },
	.zukr_div_addr = 9,
	.zukr_div_naddr = 1,
	.zukr_norm_addr = 10,
	.zukr_norm_naddr = 2
}, {
	.zukr_type = DF_CHAN_ILEAVE_NPS1_10CH_2K,
	.zukr_mod = 5,
	.zukr_high = 12,
	.zukr_mod_shift = 2,
	.zukr_mod_fill = { 0, 0 },
	.zukr_chan_mod_shift = 1,
	.zukr_chan_fill = { ZEN_UMC_NP2_K_HASH_8 },
	.zukr_div_naddr = 0,
	.zukr_norm_addr = 9,
	.zukr_norm_naddr = 3
} };

/*
 * We want to apply some initial heuristics to determine if a physical address
 * is DRAM before we proceed because of the MMIO hole and related. The DRAM
 * ranges can overlap with these system reserved ranges so we have to manually
 * check these.  Effectively this means that we have a few valid ranges:
 *
 *  o [ 0, TOM )
 *  o [ 4 GiB, TOM2 )
 *
 * However, the above 4 GiB runs into trouble depending on size. There is a 12
 * GiB system reserved address region right below 1 TiB. So it really turns
 * into the following when we have more than 1 TiB of DRAM:
 *
 *  o [ 0, TOM )
 *  o [ 4 GiB, 1 TiB - 12 GiB )
 *  o [ 1 TiB, TOM2 )
 *
 * Note, this does not currently scan MTRRs or MMIO rules for what might be
 * redirected to MMIO.
 */
static boolean_t
zen_umc_decode_is_dram(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	if (dec->dec_pa < umc->umc_tom) {
		return (B_TRUE);
	}

	if (dec->dec_pa >= umc->umc_tom2) {
		dec->dec_fail = ZEN_UMC_DECODE_F_OUTSIDE_DRAM;
		return (B_FALSE);
	}

	/*
	 * If the address is in the reserved hole around 1 TiB, do not proceed.
	 */
	if (dec->dec_pa >= ZEN_UMC_TOM2_RSVD_BEGIN &&
	    dec->dec_pa < ZEN_UMC_TOM2_RSVD_END) {
		dec->dec_fail = ZEN_UMC_DECODE_F_OUTSIDE_DRAM;
		return (B_FALSE);
	}

	/*
	 * Now that we've validated we're not in the hole, check to see if we're
	 * actually in a valid region for TOM2.
	 */
	if (dec->dec_pa >= ZEN_UMC_TOM2_START &&
	    dec->dec_pa < umc->umc_tom2) {
		return (B_TRUE);
	}

	/*
	 * At this point we have eliminated all known DRAM regions described by
	 * TOM and TOM2, so we have to conclude that whatever we're looking at
	 * is now not part of DRAM.
	 */
	dec->dec_fail = ZEN_UMC_DECODE_F_OUTSIDE_DRAM;
	return (B_FALSE);
}

/*
 * In our first stop on decoding, we need to go through and take a physical
 * address and figure out what the corresponding initial DF rule that applies
 * is. This rule will then be used to figure out which target on the data fabric
 * we should be going to and what interleaving rules apply.
 *
 * Our DRAM rule may reflect that the DRAM hole is active. In this case the
 * specified range in the rule will be larger than the actual amount of DRAM
 * present. MMIO accesses take priority over DRAM accesses in the core and
 * therefore the MMIO portion of the rule is not actually decoded. When trying
 * to match a rule we do not need to worry about that and can just look whether
 * our physical address matches a rule. We will take into account whether
 * hoisting should adjust the address when we translate from a system address to
 * a normal address (e.g. an address in the channel) which will be done in a
 * subsequent step. If an address is in the hole, that has already been
 * accounted for.
 *
 * While gathering information, we have all the DRAM rules for a given CCM that
 * corresponds to a CPU core. This allows us to review all DRAM rules in one
 * place rather than walking through what's been assigned to each UMC instance,
 * which only has the rules that are directed towards that particular channel
 * and matter for determining channel offsets.
 */
static boolean_t
zen_umc_decode_find_df_rule(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	const zen_umc_df_t *df = &umc->umc_dfs[0];

	for (uint_t i = 0; i < df->zud_dram_nrules; i++) {
		const df_dram_rule_t *rule = &df->zud_rules[i];

		/*
		 * If this rule is not enabled, skip it.
		 */
		if ((rule->ddr_flags & DF_DRAM_F_VALID) == 0)
			continue;

		if (dec->dec_pa >= rule->ddr_base &&
		    dec->dec_pa < rule->ddr_limit) {
			dec->dec_df_ruleno = i;
			dec->dec_df_rule = rule;
			dec->dec_df_rulesrc = df;
			return (B_TRUE);
		}
	}

	dec->dec_fail = ZEN_UMC_DECODE_F_NO_DF_RULE;
	return (B_FALSE);
}

/*
 * This function takes care of the common logic of adjusting an address by the
 * base value in the rule and determining if we need to apply the DRAM hole or
 * not. This function is used in two different places:
 *
 *   o As part of adjusting the system address to construct the interleave
 *     address for DFv4 and Zen 3 based 6-channel hashing (see
 *     zen_umc_determine_ileave_addr() below).
 *   o As part of adjusting the system address at the beginning of normalization
 *     to a channel address.
 *
 * One thing to highlight is that the same adjustment we make in the first case
 * applies to a subset of things for interleaving; however, it applies to
 * everything when normalizing.
 */
static boolean_t
zen_umc_adjust_dram_addr(const zen_umc_t *umc, zen_umc_decoder_t *dec,
    uint64_t *addrp, zen_umc_decode_failure_t errno)
{
	const uint64_t init_addr = *addrp;
	const df_dram_rule_t *rule = dec->dec_df_rule;
	const zen_umc_df_t *df = dec->dec_df_rulesrc;
	uint64_t mod_addr = init_addr;

	ASSERT3U(init_addr, >=, rule->ddr_base);
	ASSERT3U(init_addr, <, rule->ddr_limit);
	mod_addr -= rule->ddr_base;

	/*
	 * Determine if the hole applies to this rule.
	 */
	if ((rule->ddr_flags & DF_DRAM_F_HOLE) != 0 &&
	    (df->zud_flags & ZEN_UMC_DF_F_HOLE_VALID) != 0 &&
	    init_addr >= ZEN_UMC_TOM2_START) {
		uint64_t hole_size;
		hole_size = ZEN_UMC_TOM2_START -
		    umc->umc_dfs[0].zud_hole_base;
		if (mod_addr < hole_size) {
			dec->dec_fail = errno;
			dec->dec_fail_data = dec->dec_df_ruleno;
			return (B_FALSE);
		}

		mod_addr -= hole_size;
	}

	*addrp = mod_addr;
	return (B_TRUE);
}

/*
 * Take care of constructing the address we need to use for determining the
 * interleaving target fabric id. See the big theory statement in zen_umc.c for
 * more on this.
 */
static boolean_t
zen_umc_determine_ileave_addr(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	const df_dram_rule_t *rule = dec->dec_df_rule;

	if ((umc->umc_df_rev <= DF_REV_3 &&
	    rule->ddr_chan_ileave != DF_CHAN_ILEAVE_6CH) ||
	    umc->umc_df_rev >= DF_REV_4D2) {
		dec->dec_ilv_pa = dec->dec_pa;
		return (B_TRUE);
	}

	dec->dec_ilv_pa = dec->dec_pa;
	if (!zen_umc_adjust_dram_addr(umc, dec, &dec->dec_ilv_pa,
	    ZEN_UMC_DECODE_F_ILEAVE_UNDERFLOW)) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * This is a simple interleaving case where we simply extract bits. No hashing
 * required! Per zen_umc.c, from lowest to highest, we have channel, die, and
 * then socket bits.
 */
static boolean_t
zen_umc_decode_ileave_nohash(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint32_t nchan_bit, ndie_bit, nsock_bit, addr_bit;
	const df_dram_rule_t *rule = dec->dec_df_rule;

	nsock_bit = rule->ddr_sock_ileave_bits;
	ndie_bit = rule->ddr_die_ileave_bits;
	switch (rule->ddr_chan_ileave) {
	case DF_CHAN_ILEAVE_1CH:
		nchan_bit = 0;
		break;
	case DF_CHAN_ILEAVE_2CH:
		nchan_bit = 1;
		break;
	case DF_CHAN_ILEAVE_4CH:
		nchan_bit = 2;
		break;
	case DF_CHAN_ILEAVE_8CH:
		nchan_bit = 3;
		break;
	case DF_CHAN_ILEAVE_16CH:
		nchan_bit = 4;
		break;
	case DF_CHAN_ILEAVE_32CH:
		nchan_bit = 5;
		break;
	default:
		dec->dec_fail = ZEN_UMC_DECODE_F_CHAN_ILEAVE_NOTSUP;
		dec->dec_fail_data = rule->ddr_chan_ileave;
		return (B_FALSE);
	}

	/*
	 * Zero all of these out in case no bits are dedicated to this purpose.
	 * In those cases, then the value for this is always zero.
	 */
	dec->dec_ilv_sock = dec->dec_ilv_die = dec->dec_ilv_chan = 0;
	addr_bit = rule->ddr_addr_start;
	if (nchan_bit > 0) {
		dec->dec_ilv_chan = bitx64(dec->dec_ilv_pa,
		    addr_bit + nchan_bit - 1, addr_bit);
		addr_bit += nchan_bit;
	}

	if (ndie_bit > 0) {
		dec->dec_ilv_die = bitx64(dec->dec_ilv_pa,
		    addr_bit + ndie_bit - 1, addr_bit);
		addr_bit += ndie_bit;
	}

	if (nsock_bit > 0) {
		dec->dec_ilv_sock = bitx64(dec->dec_ilv_pa,
		    addr_bit + nsock_bit - 1, addr_bit);
		addr_bit += nsock_bit;
	}

	return (B_TRUE);
}

/*
 * Perform the Zen 2/Zen 3 "COD" based hashing. See the zen_umc.c interleaving
 * section of the big theory statement for an overview of how this works.
 */
static boolean_t
zen_umc_decode_ileave_cod(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint32_t nchan_bit;
	const df_dram_rule_t *rule = dec->dec_df_rule;
	/*
	 * The order of bits here is defined by AMD. Yes, we do use the rule's
	 * address bit first and then skip to bit 12 for the second hash bit.
	 */
	const uint32_t addr_bits[3] = { rule->ddr_addr_start, 12, 13 };

	if (rule->ddr_sock_ileave_bits != 0 || rule->ddr_die_ileave_bits != 0) {
		dec->dec_fail = ZEN_UMC_DECODE_F_COD_BAD_ILEAVE;
		dec->dec_fail_data = dec->dec_df_ruleno;
		return (B_FALSE);
	}

	switch (rule->ddr_chan_ileave) {
	case DF_CHAN_ILEAVE_COD4_2CH:
		nchan_bit = 1;
		break;
	case DF_CHAN_ILEAVE_COD2_4CH:
		nchan_bit = 2;
		break;
	case DF_CHAN_ILEAVE_COD1_8CH:
		nchan_bit = 3;
		break;
	default:
		dec->dec_fail = ZEN_UMC_DECODE_F_CHAN_ILEAVE_NOTSUP;
		dec->dec_fail_data = rule->ddr_chan_ileave;
		return (B_FALSE);
	}

	dec->dec_ilv_sock = dec->dec_ilv_die = dec->dec_ilv_chan = 0;

	/*
	 * Proceed to calculate the address hash based on the number of bits
	 * that we have been told to use based on the DF rule. Use the flags in
	 * the rule to determine which additional address ranges to hash in.
	 */
	for (uint_t i = 0; i < nchan_bit; i++) {
		uint8_t hash = 0;

		hash = bitx64(dec->dec_ilv_pa, addr_bits[i], addr_bits[i]);
		if ((rule->ddr_flags & DF_DRAM_F_HASH_16_18) != 0) {
			uint8_t val = bitx64(dec->dec_ilv_pa, 16 + i, 16 + i);
			hash ^= val;
		}

		if ((rule->ddr_flags & DF_DRAM_F_HASH_21_23) != 0) {
			uint8_t val = bitx64(dec->dec_ilv_pa, 21 + i, 21 + i);
			hash ^= val;
		}

		if ((rule->ddr_flags & DF_DRAM_F_HASH_30_32) != 0) {
			uint8_t val = bitx64(dec->dec_ilv_pa, 30 + i, 30 + i);
			hash ^= val;
		}

		dec->dec_ilv_chan |= hash << i;
	}

	return (B_TRUE);
}

/*
 * Common logic to perform hashing across the NPS, NPS 1K, and NPS 2K variants.
 */
static void
zen_umc_decode_ileave_nps_common(zen_umc_decoder_t *dec,
    const uint32_t *addr_bits, const uint32_t *adj, uint32_t nsock_bits,
    uint32_t nchan_bits, boolean_t df4p0)
{
	const df_dram_rule_t *rule = dec->dec_df_rule;

	for (uint32_t i = 0; i < nchan_bits + nsock_bits; i++) {
		uint8_t hash = 0;

		hash = bitx64(dec->dec_ilv_pa, addr_bits[i], addr_bits[i]);
		if ((rule->ddr_flags & DF_DRAM_F_HASH_16_18) != 0) {
			uint8_t val = bitx64(dec->dec_ilv_pa, 16 + adj[i],
			    16 + adj[i]);
			hash ^= val;
		}

		if ((rule->ddr_flags & DF_DRAM_F_HASH_21_23) != 0) {
			uint8_t val = bitx64(dec->dec_ilv_pa, 21 + adj[i],
			    21 + adj[i]);
			hash ^= val;
		}

		if ((rule->ddr_flags & DF_DRAM_F_HASH_30_32) != 0) {
			uint8_t val = bitx64(dec->dec_ilv_pa, 30 + adj[i], 30 +
			    adj[i]);
			hash ^= val;
		}

		/*
		 * While 1T is only supported in the NPS 1K/2K variant, rule
		 * normalization means this won't be set in the plain NPS case.
		 */
		if ((rule->ddr_flags & DF_DRAM_F_HASH_40_42) != 0) {
			uint8_t val = bitx64(dec->dec_ilv_pa, 40 + adj[i],
			    40 + adj[i]);
			hash ^= val;
		}

		/*
		 * If this is the first bit and we're not doing socket
		 * interleaving, then we need to add bit 14 to the running hash.
		 * This is only true for a strict DF v4.0 NPS style hash. We
		 * don't perform this for the 1K/2K variant.
		 */
		if (i == 0 && nsock_bits == 0 && df4p0) {
			uint8_t val = bitx64(dec->dec_ilv_pa, 14, 14);
			hash ^= val;
		}

		/*
		 * If socket interleaving is going on we need to store the first
		 * bit as the socket hash and then redirect the remaining bits
		 * to the channel, taking into account that the shift will be
		 * adjusted as a result.
		 */
		if (nsock_bits > 0) {
			if (i == 0) {
				dec->dec_ilv_sock = hash;
			} else {
				dec->dec_ilv_chan |= hash << (i - 1);
			}
		} else {
			dec->dec_ilv_chan |= hash << i;
		}
	}
}


/*
 * This implements the standard NPS hash for power of 2 based channel
 * configurations that is found in DFv4. For more information, please see the
 * interleaving portion of the zen_umc.c big theory statement.
 */
static boolean_t
zen_umc_decode_ileave_nps(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint32_t nchan_bit, nsock_bit;
	const df_dram_rule_t *rule = dec->dec_df_rule;
	/*
	 * The order of bits here is defined by AMD. Yes, this is start with the
	 * defined address bit and then skip to bit 12.
	 */
	const uint32_t addr_bits[4] = { rule->ddr_addr_start, 12, 13, 14 };
	const uint32_t adj[4] = { 0, 1, 2, 3 };

	if (rule->ddr_die_ileave_bits != 0) {
		dec->dec_fail = ZEN_UMC_DECODE_F_NPS_BAD_ILEAVE;
		dec->dec_fail_data = dec->dec_df_ruleno;
		return (B_FALSE);
	}

	nsock_bit = rule->ddr_sock_ileave_bits;
	switch (rule->ddr_chan_ileave) {
	case DF_CHAN_ILEAVE_NPS4_2CH:
		nchan_bit = 1;
		break;
	case DF_CHAN_ILEAVE_NPS2_4CH:
		nchan_bit = 2;
		break;
	case DF_CHAN_ILEAVE_NPS1_8CH:
		nchan_bit = 3;
		break;
	default:
		dec->dec_fail = ZEN_UMC_DECODE_F_CHAN_ILEAVE_NOTSUP;
		dec->dec_fail_data = rule->ddr_chan_ileave;
		return (B_FALSE);
	}

	ASSERT3U(nchan_bit + nsock_bit, <=, 4);
	dec->dec_ilv_sock = dec->dec_ilv_die = dec->dec_ilv_chan = 0;

	zen_umc_decode_ileave_nps_common(dec, addr_bits, adj, nsock_bit,
	    nchan_bit, B_TRUE);
	return (B_TRUE);
}

/*
 * This implements the Zen 5 (really DF 4D2) NPS variants that work on both 1K
 * and 2K hashing.
 */
static boolean_t
zen_umc_decode_ileave_nps_k(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint32_t nchan_bit, nsock_bit;
	const df_dram_rule_t *rule = dec->dec_df_rule;
	const uint32_t addr_bits_1k[5] = { rule->ddr_addr_start, 9, 12, 13,
	    14 };
	const uint32_t addr_bits_2k[4] = { rule->ddr_addr_start, 12, 13, 14 };
	const uint32_t adj_1k[5] = { 0, 1, 2, 3, 4 };
	const uint32_t adj_2k[4] = { 0, 2, 3, 4 };
	const uint32_t *addr_bits;
	const uint32_t *adj;

	if (rule->ddr_die_ileave_bits != 0 || rule->ddr_addr_start != 8) {
		dec->dec_fail = ZEN_UMC_DECODE_F_NPS_BAD_ILEAVE;
		dec->dec_fail_data = dec->dec_df_ruleno;
		return (B_FALSE);
	}

	nsock_bit = rule->ddr_sock_ileave_bits;
	switch (rule->ddr_chan_ileave) {
	case DF_CHAN_ILEAVE_NPS4_2CH_1K:
	case DF_CHAN_ILEAVE_NPS4_2CH_2K:
		nchan_bit = 1;
		break;
	case DF_CHAN_ILEAVE_NPS2_4CH_1K:
	case DF_CHAN_ILEAVE_NPS2_4CH_2K:
		nchan_bit = 2;
		break;
	case DF_CHAN_ILEAVE_NPS1_8CH_1K:
	case DF_CHAN_ILEAVE_NPS1_8CH_2K:
		nchan_bit = 3;
		break;
	case DF_CHAN_ILEAVE_NPS1_16CH_1K:
	case DF_CHAN_ILEAVE_NPS1_16CH_2K:
		nchan_bit = 4;
		break;
	default:
		dec->dec_fail = ZEN_UMC_DECODE_F_CHAN_ILEAVE_NOTSUP;
		dec->dec_fail_data = rule->ddr_chan_ileave;
		return (B_FALSE);
	}

	switch (rule->ddr_chan_ileave) {
	case DF_CHAN_ILEAVE_NPS4_2CH_1K:
	case DF_CHAN_ILEAVE_NPS2_4CH_1K:
	case DF_CHAN_ILEAVE_NPS1_8CH_1K:
	case DF_CHAN_ILEAVE_NPS1_16CH_1K:
		ASSERT3U(nchan_bit + nsock_bit, <=, 5);
		addr_bits = addr_bits_1k;
		adj = adj_1k;
		break;
	case DF_CHAN_ILEAVE_NPS4_2CH_2K:
	case DF_CHAN_ILEAVE_NPS2_4CH_2K:
	case DF_CHAN_ILEAVE_NPS1_8CH_2K:
	case DF_CHAN_ILEAVE_NPS1_16CH_2K:
		ASSERT3U(nchan_bit + nsock_bit, <=, 4);
		addr_bits = addr_bits_2k;
		adj = adj_2k;
		break;
	default:
		dec->dec_fail = ZEN_UMC_DECODE_F_CHAN_ILEAVE_NOTSUP;
		dec->dec_fail_data = rule->ddr_chan_ileave;
		return (B_FALSE);
	}

	dec->dec_ilv_sock = dec->dec_ilv_die = dec->dec_ilv_chan = 0;
	zen_umc_decode_ileave_nps_common(dec, addr_bits, adj, nsock_bit,
	    nchan_bit, B_FALSE);
	return (B_TRUE);
}

/*
 * This implements the logic to perform the Zen 3 6ch special hash. It's worth
 * calling out that unlike all other hash functions, this does not support the
 * use of the DF_DRAM_F_HASH_16_18 flag.
 */
static void
zen_umc_decode_hash_zen3_6ch(const df_dram_rule_t *rule, uint64_t pa,
    uint8_t hashes[3])
{
	uint32_t addr_bit = rule->ddr_addr_start;
	/*
	 * Yes, we use these in a weird order. No, there is no 64K.
	 */
	const uint32_t bits_2M[3] = { 23, 21, 22 };
	const uint32_t bits_1G[3] = { 32, 30, 31 };

	hashes[0] = hashes[1] = hashes[2] = 0;
	for (uint_t i = 0; i < ZEN_UMC_COD_NBITS; i++) {
		hashes[i] = bitx64(pa, addr_bit + i, addr_bit + i);
		if (i == 0) {
			uint8_t val = bitx64(pa, addr_bit + 3, addr_bit + 3);
			hashes[i] ^= val;
		}

		if ((rule->ddr_flags & DF_DRAM_F_HASH_21_23) != 0) {
			uint8_t val = bitx64(pa, bits_2M[i], bits_2M[i]);
			hashes[i] ^= val;
		}

		if ((rule->ddr_flags & DF_DRAM_F_HASH_30_32) != 0) {
			uint8_t val = bitx64(pa, bits_1G[i], bits_1G[i]);
			hashes[i] ^= val;
		}
	}
}

/*
 * Perform Zen 3 6-channel hashing. This is pretty weird compared to others. See
 * the zen_umc.c big theory statement for the thorny details.
 */
static boolean_t
zen_umc_decode_ileave_zen3_6ch(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint8_t hashes[3] = { 0 };
	const df_dram_rule_t *rule = dec->dec_df_rule;
	uint32_t addr_bit = rule->ddr_addr_start;

	if (rule->ddr_sock_ileave_bits != 0 || rule->ddr_die_ileave_bits != 0) {
		dec->dec_fail = ZEN_UMC_DECODE_F_COD_BAD_ILEAVE;
		dec->dec_fail_data = dec->dec_df_ruleno;
		return (B_FALSE);
	}

	zen_umc_decode_hash_zen3_6ch(rule, dec->dec_ilv_pa, hashes);
	dec->dec_ilv_sock = dec->dec_ilv_die = dec->dec_ilv_chan = 0;
	dec->dec_ilv_chan = hashes[0];
	if (hashes[1] == 1 && hashes[2] == 1) {
		uint64_t mod_addr = dec->dec_ilv_pa >> (addr_bit + 3);
		dec->dec_ilv_chan |= (mod_addr % 3) << 1;
	} else {
		dec->dec_ilv_chan |= hashes[1] << 1;
		dec->dec_ilv_chan |= hashes[2] << 2;
	}

	return (B_TRUE);
}

/*
 * This is the standard hash function for the non-power of two based NPS hashes.
 * See the big theory statement for more information. Unlike the normal NPS hash
 * which uses bit 14 conditionally based on socket interleaving, here it is
 * always used.
 */
static void
zen_umc_decode_hash_nps_mod(const df_dram_rule_t *rule, uint64_t pa,
    uint8_t hashes[3])
{
	const uint32_t addr_bits[3] = { rule->ddr_addr_start, 12, 13 };

	for (uint_t i = 0; i < ZEN_UMC_NPS_MOD_NBITS; i++) {
		hashes[i] = bitx64(pa, addr_bits[i], addr_bits[i]);
		if (i == 0) {
			uint8_t val = bitx64(pa, 14, 14);
			hashes[i] ^= val;
		}

		if ((rule->ddr_flags & DF_DRAM_F_HASH_16_18) != 0) {
			uint8_t val = bitx64(pa, 16 + i, 16 + i);
			hashes[i] ^= val;
		}

		if ((rule->ddr_flags & DF_DRAM_F_HASH_21_23) != 0) {
			uint8_t val = bitx64(pa, 21 + i, 21 + i);
			hashes[i] ^= val;
		}

		if ((rule->ddr_flags & DF_DRAM_F_HASH_30_32) != 0) {
			uint8_t val = bitx64(pa, 30 + i, 30 + i);
			hashes[i] ^= val;
		}
	}
}

static void
zen_umc_decode_hash_nps_k_mod(const df_dram_rule_t *rule, uint64_t pa,
    uint8_t hashes[4])
{
	const uint32_t addr_bits[4] = { rule->ddr_addr_start, 9, 12, 13 };

	for (size_t i = 0; i < ARRAY_SIZE(addr_bits); i++) {
		hashes[i] = bitx64(pa, addr_bits[i], addr_bits[i]);
		if (i == 0) {
			uint8_t val = bitx64(pa, 14, 14);
			hashes[i] ^= val;
		}

		if ((rule->ddr_flags & DF_DRAM_F_HASH_16_18) != 0) {
			uint8_t val = bitx64(pa, 16 + i, 16 + i);
			hashes[i] ^= val;
		}

		if ((rule->ddr_flags & DF_DRAM_F_HASH_21_23) != 0) {
			uint8_t val = bitx64(pa, 21 + i, 21 + i);
			hashes[i] ^= val;
		}

		if ((rule->ddr_flags & DF_DRAM_F_HASH_30_32) != 0) {
			uint8_t val = bitx64(pa, 30 + i, 30 + i);
			hashes[i] ^= val;
		}

		if ((rule->ddr_flags & DF_DRAM_F_HASH_40_42) != 0) {
			uint8_t val = bitx64(pa, 40 + i, 40 + i);
			hashes[i] ^= val;
		}
	}
}

/*
 * See the big theory statement in zen_umc.c which describes the rules for this
 * computation. This is a little less weird than the Zen 3 one, but still,
 * unique.
 */
static boolean_t
zen_umc_decode_ileave_nps_mod(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint8_t hashes[3] = { 0 };
	uint32_t nsock_bit, chan_mod;
	const df_dram_rule_t *rule = dec->dec_df_rule;

	if (rule->ddr_die_ileave_bits != 0) {
		dec->dec_fail = ZEN_UMC_DECODE_F_NPS_BAD_ILEAVE;
		dec->dec_fail_data = dec->dec_df_ruleno;
		return (B_FALSE);
	}

	nsock_bit = rule->ddr_sock_ileave_bits;
	switch (rule->ddr_chan_ileave) {
	case DF_CHAN_ILEAVE_NPS4_3CH:
	case DF_CHAN_ILEAVE_NPS2_6CH:
	case DF_CHAN_ILEAVE_NPS1_12CH:
		chan_mod = 3;
		break;
	case DF_CHAN_ILEAVE_NPS2_5CH:
	case DF_CHAN_ILEAVE_NPS1_10CH:
		chan_mod = 5;
		break;
	default:
		dec->dec_fail = ZEN_UMC_DECODE_F_CHAN_ILEAVE_NOTSUP;
		dec->dec_fail_data = rule->ddr_chan_ileave;
		return (B_FALSE);
	}

	dec->dec_ilv_sock = dec->dec_ilv_die = dec->dec_ilv_chan = 0;
	zen_umc_decode_hash_nps_mod(rule, dec->dec_ilv_pa, hashes);

	if (nsock_bit > 0) {
		ASSERT3U(nsock_bit, ==, 1);
		dec->dec_ilv_sock = hashes[0];
	}

	dec->dec_ilv_chan = bitx64(dec->dec_ilv_pa, 63, 14) % chan_mod;
	if (hashes[0] == 1) {
		dec->dec_ilv_chan = (dec->dec_ilv_chan + 1) % chan_mod;
	}

	/*
	 * Use the remaining hash bits based on the number of channels. There is
	 * nothing else to do for 3/5 channel configs.
	 */
	switch (rule->ddr_chan_ileave) {
	case DF_CHAN_ILEAVE_NPS4_3CH:
	case DF_CHAN_ILEAVE_NPS2_5CH:
		break;
	case DF_CHAN_ILEAVE_NPS2_6CH:
	case DF_CHAN_ILEAVE_NPS1_10CH:
		dec->dec_ilv_chan += hashes[2] * chan_mod;
		break;
	case DF_CHAN_ILEAVE_NPS1_12CH:
		dec->dec_ilv_chan += ((hashes[2] << 1) | hashes[1]) * chan_mod;
		break;
	default:
		dec->dec_fail = ZEN_UMC_DECODE_F_CHAN_ILEAVE_NOTSUP;
		dec->dec_fail_data = rule->ddr_chan_ileave;
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Determine the interleave address for the NPS 1K/2K non-power of 2 based
 * values. Each of these uses a similar style of calculation with rather
 * different values and as such we use a data table for each of these that maps
 * to a given rule.
 */
static boolean_t
zen_umc_decode_ileave_nps_k_mod(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint8_t hashes[4] = { 0 };
	uint32_t chan, mod_val;
	uint64_t mod_addr;
	const df_dram_rule_t *rule = dec->dec_df_rule;
	const zen_umc_np2_k_rule_t *np2 = NULL;

	for (size_t i = 0; i < ARRAY_SIZE(zen_umc_np2_k_rules); i++) {
		if (rule->ddr_chan_ileave == zen_umc_np2_k_rules[i].zukr_type) {
			np2 = &zen_umc_np2_k_rules[i];
			break;
		}
	}

	if (np2 == NULL) {
		dec->dec_fail = ZEN_UMC_DECODE_F_CHAN_ILEAVE_NOTSUP;
		dec->dec_fail_data = rule->ddr_chan_ileave;
		return (B_FALSE);
	}

	if (rule->ddr_die_ileave_bits != 0 || rule->ddr_addr_start != 8) {
		dec->dec_fail = ZEN_UMC_DECODE_F_NPS_BAD_ILEAVE;
		dec->dec_fail_data = dec->dec_df_ruleno;
		return (B_FALSE);
	}

	/*
	 * These rules either require that socket interleaving is enabled or
	 * not. Make sure that this matches before we proceed.
	 */
	if (np2->zukr_sock != (rule->ddr_sock_ileave_bits == 1)) {
		dec->dec_fail = ZEN_UMC_DECODE_F_NPS_BAD_ILEAVE;
		dec->dec_fail_data = dec->dec_df_ruleno;
		return (B_FALSE);
	}

	dec->dec_ilv_sock = dec->dec_ilv_die = dec->dec_ilv_chan = 0;
	zen_umc_decode_hash_nps_k_mod(rule, dec->dec_ilv_pa, hashes);
	if (rule->ddr_sock_ileave_bits > 0) {
		ASSERT3U(rule->ddr_sock_ileave_bits, ==, 1);
		dec->dec_ilv_sock = hashes[0];
	}

	mod_addr = bitx64(dec->dec_ilv_pa, 63, np2->zukr_high);
	mod_addr = mod_addr << np2->zukr_mod_shift;
	for (uint32_t i = 0; i < np2->zukr_mod_shift; i++) {
		uint32_t bit = np2->zukr_mod_fill[i];
		if (bit != 0) {
			uint64_t val = bitx64(dec->dec_ilv_pa, bit, bit);
			mod_addr = bitset64(mod_addr, i, i, val);
		}
	}

	mod_val = (uint32_t)(mod_addr % np2->zukr_mod);
	chan = mod_val << np2->zukr_chan_mod_shift;
	for (uint32_t i = 0; i < np2->zukr_chan_mod_shift; i++) {
		VERIFY3U(np2->zukr_chan_fill[i], <, ARRAY_SIZE(hashes));
		uint32_t bit = np2->zukr_chan_fill[i];
		uint32_t val = hashes[np2->zukr_chan_fill[i]];
		chan = bitset32(chan, bit, bit, val);
	}

	dec->dec_ilv_chan = chan;
	return (B_TRUE);
}

/*
 * Our next task is to attempt to translate the PA and the DF rule from a system
 * address into a normalized address and a particular DRAM channel that it's
 * targeting. There are several things that we need to take into account here
 * when performing interleaving and translation:
 *
 *  o The DRAM Hole modifying our base address
 *  o The various interleave bits
 *  o Potentially hashing based on channel and global settings
 *  o Potential CS re-targeting registers (only on some systems)
 *  o Finally, the question of how to adjust for the DRAM hole and the base
 *    address changes based on the DF generation and channel configuration. This
 *    influences what address we start interleaving with.
 *
 * Note, this phase does not actually construct the normalized (e.g. channel)
 * address. That's done in a subsequent step. For more background, please see
 * the 'Data Fabric Interleaving' section of the zen_umc.c big theory statement.
 */
static boolean_t
zen_umc_decode_sysaddr_to_csid(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint32_t sock, die, chan, remap_ruleset;
	const df_dram_rule_t *rule = dec->dec_df_rule;
	const zen_umc_cs_remap_t *remap;

	/*
	 * First, we must determine what the actual address used for
	 * interleaving is. This varies based on the interleaving and DF
	 * generation.
	 */
	if (!zen_umc_determine_ileave_addr(umc, dec)) {
		return (B_FALSE);
	}

	switch (rule->ddr_chan_ileave) {
	case DF_CHAN_ILEAVE_1CH:
	case DF_CHAN_ILEAVE_2CH:
	case DF_CHAN_ILEAVE_4CH:
	case DF_CHAN_ILEAVE_8CH:
	case DF_CHAN_ILEAVE_16CH:
	case DF_CHAN_ILEAVE_32CH:
		if (!zen_umc_decode_ileave_nohash(umc, dec)) {
			return (B_FALSE);
		}
		break;
	case DF_CHAN_ILEAVE_COD4_2CH:
	case DF_CHAN_ILEAVE_COD2_4CH:
	case DF_CHAN_ILEAVE_COD1_8CH:
		if (!zen_umc_decode_ileave_cod(umc, dec)) {
			return (B_FALSE);
		}
		break;
	case DF_CHAN_ILEAVE_NPS4_2CH:
	case DF_CHAN_ILEAVE_NPS2_4CH:
	case DF_CHAN_ILEAVE_NPS1_8CH:
		if (!zen_umc_decode_ileave_nps(umc, dec)) {
			return (B_FALSE);
		}
		break;
	case DF_CHAN_ILEAVE_6CH:
		if (!zen_umc_decode_ileave_zen3_6ch(umc, dec)) {
			return (B_FALSE);
		}
		break;
	case DF_CHAN_ILEAVE_NPS4_3CH:
	case DF_CHAN_ILEAVE_NPS2_6CH:
	case DF_CHAN_ILEAVE_NPS1_12CH:
	case DF_CHAN_ILEAVE_NPS2_5CH:
	case DF_CHAN_ILEAVE_NPS1_10CH:
		if (!zen_umc_decode_ileave_nps_mod(umc, dec)) {
			return (B_FALSE);
		}
		break;
	case DF_CHAN_ILEAVE_NPS4_2CH_1K:
	case DF_CHAN_ILEAVE_NPS2_4CH_1K:
	case DF_CHAN_ILEAVE_NPS1_8CH_1K:
	case DF_CHAN_ILEAVE_NPS1_16CH_1K:
	case DF_CHAN_ILEAVE_NPS4_2CH_2K:
	case DF_CHAN_ILEAVE_NPS2_4CH_2K:
	case DF_CHAN_ILEAVE_NPS1_8CH_2K:
	case DF_CHAN_ILEAVE_NPS1_16CH_2K:
		if (!zen_umc_decode_ileave_nps_k(umc, dec)) {
			return (B_FALSE);
		}
		break;
	case DF_CHAN_ILEAVE_NPS4_3CH_1K:
	case DF_CHAN_ILEAVE_NPS2_6CH_1K:
	case DF_CHAN_ILEAVE_NPS1_12CH_1K:
	case DF_CHAN_ILEAVE_NPS0_24CH_1K:
	case DF_CHAN_ILEAVE_NPS2_5CH_1K:
	case DF_CHAN_ILEAVE_NPS1_10CH_1K:
	case DF_CHAN_ILEAVE_NPS4_3CH_2K:
	case DF_CHAN_ILEAVE_NPS2_6CH_2K:
	case DF_CHAN_ILEAVE_NPS1_12CH_2K:
	case DF_CHAN_ILEAVE_NPS0_24CH_2K:
	case DF_CHAN_ILEAVE_NPS2_5CH_2K:
	case DF_CHAN_ILEAVE_NPS1_10CH_2K:
		if (!zen_umc_decode_ileave_nps_k_mod(umc, dec)) {
			return (B_FALSE);
		}
		break;
	case DF_CHAN_ILEAVE_MI3H_8CH:
	case DF_CHAN_ILEAVE_MI3H_16CH:
	case DF_CHAN_ILEAVE_MI3H_32CH:
	default:
		dec->dec_fail = ZEN_UMC_DECODE_F_CHAN_ILEAVE_NOTSUP;
		dec->dec_fail_data = rule->ddr_chan_ileave;
		return (B_FALSE);
	}

	/*
	 * At this point we have dealt with decoding the interleave into the
	 * logical elements that it contains. We need to transform that back
	 * into a fabric ID, so we can add it to the base fabric ID in our rule.
	 * After that, we need to see if there is any CS remapping going on. If
	 * there is, we will replace the component part of the decomposed fabric
	 * ID. With that done, we can then transform the components back into
	 * our target fabric ID, which indicates which UMC we're after.
	 */
	zen_fabric_id_compose(&umc->umc_decomp, dec->dec_ilv_sock,
	    dec->dec_ilv_die, dec->dec_ilv_chan, &dec->dec_ilv_fabid);
	dec->dec_log_fabid = dec->dec_ilv_fabid + rule->ddr_dest_fabid;

	/*
	 * If there's no remapping to do, then we're done. Simply assign the
	 * logical ID as our target.
	 */
	zen_fabric_id_decompose(&umc->umc_decomp, dec->dec_log_fabid, &sock,
	    &die, &chan);
	if ((rule->ddr_flags & DF_DRAM_F_REMAP_EN) == 0) {
		dec->dec_targ_fabid = dec->dec_log_fabid;
		return (B_TRUE);
	}

	/*
	 * The DF contains multiple remapping tables. We must figure out which
	 * of these to actually use. There are two different ways that this can
	 * work. The first way is the one added in DFv4 and is used since then.
	 * In that case, the DRAM rule includes both that remapping was enabled
	 * and which of the multiple mapping tables to use.
	 *
	 * This feature also exists prior to DFv4, but only in Milan. In that
	 * world, indicated by the DF_DRAM_F_REMAP_SOCK flag, there is one table
	 * in each DF per-socket. Based on the destination socket from the data
	 * fabric ID, you pick the actual table to use.
	 *
	 * Once the table has been selected, we maintain the socket and die
	 * portions of the fabric ID as constants and replace the component with
	 * the one the remapping table indicates.
	 *
	 * Technically each DF has its own copy of the remapping tables. To make
	 * this work we rely on the following assumption: a given DF node has to
	 * be able to fully route all DRAM rules to a target. That is, a given
	 * DF node doesn't really forward a system address to the remote die for
	 * further interleave processing and therefore we must have enough
	 * information here to map it totally from the same DF that we got the
	 * CCM rules from in the first place, DF 0.
	 */
	if ((rule->ddr_flags & DF_DRAM_F_REMAP_SOCK) != 0) {
		remap_ruleset = sock;
	} else {
		remap_ruleset = rule->ddr_remap_ent;
	}

	if (remap_ruleset >= dec->dec_df_rulesrc->zud_cs_nremap) {
		dec->dec_fail = ZEN_UMC_DECODE_F_BAD_REMAP_SET;
		dec->dec_fail_data = remap_ruleset;
		return (B_FALSE);
	}

	remap = &dec->dec_df_rulesrc->zud_remap[remap_ruleset];
	if (chan >= remap->csr_nremaps) {
		dec->dec_fail = ZEN_UMC_DECODE_F_BAD_REMAP_ENTRY;
		dec->dec_fail_data = chan;
		return (B_FALSE);
	}

	dec->dec_remap_comp = remap->csr_remaps[chan];
	if ((dec->dec_remap_comp & ~umc->umc_decomp.dfd_comp_mask) != 0) {
		dec->dec_fail = ZEN_UMC_DECODE_F_REMAP_HAS_BAD_COMP;
		dec->dec_fail_data = dec->dec_remap_comp;
		return (B_FALSE);
	}

	zen_fabric_id_compose(&umc->umc_decomp, sock, die, dec->dec_remap_comp,
	    &dec->dec_targ_fabid);

	return (B_TRUE);
}

/*
 * Our next step here is to actually take our target ID and find the
 * corresponding DF, UMC, and actual rule that was used. Note, we don't
 * decompose the ID and look things up that way for a few reasons. While each
 * UMC should map linearly to its instance/component ID, there are suggestions
 * that they can be renumbered. This makes it simplest to just walk over
 * everything (and there aren't that many things to walk over either).
 */
static boolean_t
zen_umc_decode_find_umc_rule(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	for (uint_t dfno = 0; dfno < umc->umc_ndfs; dfno++) {
		const zen_umc_df_t *df = &umc->umc_dfs[dfno];
		for (uint_t umcno = 0; umcno < df->zud_nchan; umcno++) {
			const zen_umc_chan_t *chan = &df->zud_chan[umcno];

			if (chan->chan_fabid != dec->dec_targ_fabid) {
				continue;
			}

			/*
			 * At this point we have found the UMC that we were
			 * looking for. Snapshot that and then figure out which
			 * rule index of it corresponds to our mapping so we can
			 * properly determine an offset. We will still use the
			 * primary CCM rule for all other calculations.
			 */
			dec->dec_umc_chan = chan;
			for (uint32_t ruleno = 0; ruleno < chan->chan_nrules;
			    ruleno++) {
				const df_dram_rule_t *rule =
				    &chan->chan_rules[ruleno];
				if ((rule->ddr_flags & DF_DRAM_F_VALID) == 0) {
					continue;
				}

				if (dec->dec_pa >= rule->ddr_base &&
				    dec->dec_pa < rule->ddr_limit) {
					dec->dec_umc_ruleno = ruleno;
					return (B_TRUE);
				}
			}

			dec->dec_fail = ZEN_UMC_DECODE_F_UMC_DOESNT_HAVE_PA;
			return (B_FALSE);
		}
	}

	dec->dec_fail = ZEN_UMC_DECODE_F_CANNOT_MAP_FABID;
	return (B_FALSE);
}

/*
 * Non-hashing interleave modes system address normalization logic. See the
 * zen_umc.c big theory statement for more information.
 */
static boolean_t
zen_umc_decode_normalize_nohash(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint_t nbits = 0;
	const df_dram_rule_t *rule = dec->dec_df_rule;

	nbits += rule->ddr_sock_ileave_bits;
	nbits += rule->ddr_die_ileave_bits;
	switch (rule->ddr_chan_ileave) {
	case DF_CHAN_ILEAVE_1CH:
		break;
	case DF_CHAN_ILEAVE_2CH:
		nbits += 1;
		break;
	case DF_CHAN_ILEAVE_4CH:
		nbits += 2;
		break;
	case DF_CHAN_ILEAVE_8CH:
		nbits += 3;
		break;
	case DF_CHAN_ILEAVE_16CH:
		nbits += 4;
		break;
	case DF_CHAN_ILEAVE_32CH:
		nbits += 5;
		break;
	default:
		dec->dec_fail = ZEN_UMC_DECODE_F_CHAN_ILEAVE_NOTSUP;
		dec->dec_fail_data = rule->ddr_chan_ileave;
		return (B_FALSE);
	}

	/*
	 * If we have a really simple configuration (e.g. no interleaving at
	 * all), then make sure that we do not actually do anything here.
	 */
	if (nbits > 0) {
		dec->dec_norm_addr = bitdel64(dec->dec_norm_addr,
		    rule->ddr_addr_start + nbits - 1, rule->ddr_addr_start);
	}

	return (B_TRUE);
}

/*
 * COD/NPS system address normalization logic. See the zen_umc.c big theory
 * statement for more information.
 */
static boolean_t
zen_umc_decode_normalize_hash(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint_t nbits = 0, nstart = 0;
	const df_dram_rule_t *rule = dec->dec_df_rule;

	/*
	 * NPS 1K hashes remove bits 8 and 9 first. Determine how many bits to
	 * remove from the starting location. This will later be reduced based
	 * upon how many address bits there actually are.
	 */
	switch (rule->ddr_chan_ileave) {
	case DF_CHAN_ILEAVE_NPS4_2CH_1K:
	case DF_CHAN_ILEAVE_NPS2_4CH_1K:
	case DF_CHAN_ILEAVE_NPS1_8CH_1K:
	case DF_CHAN_ILEAVE_NPS1_16CH_1K:
		nstart = 2;
		break;
	default:
		nstart = 1;
		break;
	}

	/*
	 * NPS hashes allow for socket interleaving, COD hashes do not. Add
	 * socket interleaving, skip die.
	 */
	nbits += rule->ddr_sock_ileave_bits;
	switch (rule->ddr_chan_ileave) {
	case DF_CHAN_ILEAVE_COD4_2CH:
	case DF_CHAN_ILEAVE_NPS4_2CH:
	case DF_CHAN_ILEAVE_NPS4_2CH_1K:
	case DF_CHAN_ILEAVE_NPS4_2CH_2K:
		nbits += 1;
		break;
	case DF_CHAN_ILEAVE_COD2_4CH:
	case DF_CHAN_ILEAVE_NPS2_4CH:
	case DF_CHAN_ILEAVE_NPS2_4CH_1K:
	case DF_CHAN_ILEAVE_NPS2_4CH_2K:
		nbits += 2;
		break;
	case DF_CHAN_ILEAVE_COD1_8CH:
	case DF_CHAN_ILEAVE_NPS1_8CH:
	case DF_CHAN_ILEAVE_NPS1_8CH_1K:
	case DF_CHAN_ILEAVE_NPS1_8CH_2K:
		nbits += 3;
		break;
	case DF_CHAN_ILEAVE_NPS1_16CH_1K:
	case DF_CHAN_ILEAVE_NPS1_16CH_2K:
		nbits += 4;
		break;
	default:
		dec->dec_fail = ZEN_UMC_DECODE_F_CHAN_ILEAVE_NOTSUP;
		dec->dec_fail_data = rule->ddr_chan_ileave;
	}

	/*
	 * Don't remove more bits from the start than exist.
	 */
	if (nstart > nbits) {
		nstart = nbits;
	}

	/*
	 * Always remove high order bits before low order bits so we don't have
	 * to adjust the bits we need to remove.
	 */
	if (nbits > nstart) {
		uint_t start = 12;
		uint_t end = start + (nbits - nstart - 1);
		dec->dec_norm_addr = bitdel64(dec->dec_norm_addr, end, start);
	}

	dec->dec_norm_addr = bitdel64(dec->dec_norm_addr,
	    rule->ddr_addr_start + nstart - 1, rule->ddr_addr_start);
	return (B_TRUE);
}

/*
 * Now it's time to perform normalization of our favorite interleaving type.
 * Please see the comments in zen_umc.c on this to understand what we're doing
 * here and why.
 */
static boolean_t
zen_umc_decode_normalize_zen3_6ch(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint8_t hashes[3] = { 0 };
	uint_t start, end;
	const df_dram_rule_t *rule = dec->dec_df_rule;

	/*
	 * As per the theory statement, we always remove the hash bits here from
	 * the starting address. Because this is a 6-channel config, that turns
	 * into 3. Perform the hash again first.
	 */
	zen_umc_decode_hash_zen3_6ch(rule, dec->dec_norm_addr, hashes);
	start = rule->ddr_addr_start;
	end = rule->ddr_addr_start + ZEN_UMC_COD_NBITS - 1;
	dec->dec_norm_addr = bitdel64(dec->dec_norm_addr, end, start);

	/*
	 * This is the case the theory statement warned about. This gets
	 * normalized to the top of the DIMM's range (its two upper most bits
	 * are set).
	 */
	if (hashes[1] == 1 && hashes[2] == 1) {
		uint_t start = 14 - ZEN_UMC_COD_NBITS +
		    dec->dec_umc_chan->chan_np2_space0;
		dec->dec_norm_addr = bitset64(dec->dec_norm_addr, start + 1,
		    start, 0x3);
	}

	return (B_TRUE);
}

/*
 * Based on the algorithm of sorts described in zen_umc.c, we have a few
 * different phases of extraction and combination. This isn't quite like the
 * others where we simply delete bits.
 */
static boolean_t
zen_umc_decode_normalize_nps_mod(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint64_t low, high, mid;
	uint_t nbits, chan_mod, sock_bits, nmid_bits;
	uint_t mid_start, mid_end;
	uint8_t hashes[3] = { 0 };
	const df_dram_rule_t *rule = dec->dec_df_rule;

	sock_bits = rule->ddr_sock_ileave_bits;
	switch (rule->ddr_chan_ileave) {
	case DF_CHAN_ILEAVE_NPS4_3CH:
		chan_mod = 3;
		nbits = 1;
		break;
	case DF_CHAN_ILEAVE_NPS2_5CH:
		chan_mod = 5;
		nbits = 1;
		break;
	case DF_CHAN_ILEAVE_NPS2_6CH:
		chan_mod = 3;
		nbits = 2;
		break;
	case DF_CHAN_ILEAVE_NPS1_10CH:
		chan_mod = 5;
		nbits = 2;
		break;
	case DF_CHAN_ILEAVE_NPS1_12CH:
		chan_mod = 3;
		nbits = 3;
		break;
	default:
		dec->dec_fail = ZEN_UMC_DECODE_F_CHAN_ILEAVE_NOTSUP;
		dec->dec_fail_data = rule->ddr_chan_ileave;
		return (B_FALSE);
	}

	/*
	 * First extract the low bit range that we're using which is everything
	 * below the starting interleave address. We also always extract the
	 * high bits, which are always [63:14] and divide it by the modulus.
	 * Note, we apply the hash after any such division if needed. It becomes
	 * the new least significant bit.
	 */
	low = bitx64(dec->dec_norm_addr, rule->ddr_addr_start - 1, 0);
	high = bitx64(dec->dec_norm_addr, 63, 14) / chan_mod;
	zen_umc_decode_hash_nps_mod(rule, dec->dec_norm_addr, hashes);
	if (sock_bits == 0) {
		high = (high << 1) | hashes[0];
	}

	/*
	 * Now for the weirdest bit here, extracting the middle bits. Recall
	 * this hash uses bit 8, then 13, then 12 (the hash order is still 8,
	 * 12, 13, but it uses the hashes[2] before hashes[1] in
	 * zen_umc_decode_ileave_nps_mod()). So if we're only using 1 interleave
	 * bit, we just remove bit 8 (assuming that is our starting address) and
	 * our range is [13:9]. If we're using two, our range becomes [12:9],
	 * and if three, [11:9]. The 6 - nbits below comes from the fact that in
	 * a 1 bit interleave we have 5 bits. Because our mid_start/mid_end
	 * range is inclusive, we subtract one at the end from mid_end.
	 */
	nmid_bits = 6 - nbits;
	mid_start = rule->ddr_addr_start + 1;
	mid_end = mid_start + nmid_bits - 1;
	mid = bitx64(dec->dec_norm_addr, mid_end, mid_start);

	/*
	 * Because we've been removing bits, we don't use any of the start and
	 * ending ranges we calculated above for shifts, as that was what we
	 * needed from the original address.
	 */
	dec->dec_norm_addr = low | (mid << rule->ddr_addr_start) | (high <<
	    (rule->ddr_addr_start + nmid_bits));

	return (B_TRUE);
}

/*
 * Construct the normalized address for the NPS 1K/2K non-power of 2 instances.
 * See the theory statement for the rough formula used here. While each variant
 * uses slightly different values, that has been abstracted based on our data
 * table.
 */
static boolean_t
zen_umc_decode_normalize_nps_k_mod(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint64_t high, mid, low;
	uint_t mid_end;
	const df_dram_rule_t *rule = dec->dec_df_rule;
	const zen_umc_np2_k_rule_t *np2 = NULL;

	for (size_t i = 0; i < ARRAY_SIZE(zen_umc_np2_k_rules); i++) {
		if (rule->ddr_chan_ileave == zen_umc_np2_k_rules[i].zukr_type) {
			np2 = &zen_umc_np2_k_rules[i];
			break;
		}
	}

	if (np2 == NULL) {
		dec->dec_fail = ZEN_UMC_DECODE_F_CHAN_ILEAVE_NOTSUP;
		dec->dec_fail_data = rule->ddr_chan_ileave;
		return (B_FALSE);
	}

	low = bitx64(dec->dec_norm_addr, rule->ddr_addr_start - 1, 0);
	mid_end = np2->zukr_norm_addr + np2->zukr_norm_naddr - 1;
	VERIFY3U(mid_end, >=, rule->ddr_addr_start);
	mid = bitx64(dec->dec_norm_addr, mid_end, np2->zukr_norm_addr);

	high = bitx64(dec->dec_norm_addr, 63, np2->zukr_high);
	if (np2->zukr_div_naddr > 0) {
		uint_t ins_end = np2->zukr_div_addr + np2->zukr_div_naddr - 1;
		uint64_t insert = bitx64(dec->dec_norm_addr, ins_end,
		    np2->zukr_div_addr);

		high = high << np2->zukr_div_naddr;
		high = bitset64(high, np2->zukr_div_naddr - 1, 0, insert);
	}
	high = high / np2->zukr_mod;

	dec->dec_norm_addr = low | (mid << rule->ddr_addr_start) | (high <<
	    (rule->ddr_addr_start + np2->zukr_norm_naddr));
	return (B_TRUE);
}

/*
 * Now we need to go through and try to construct a normalized address using all
 * the information that we've gathered to date. To do this we need to take into
 * account all of the following transformations on the address that need to
 * occur. We apply modifications to the address in the following order:
 *
 *   o The base address of the rule
 *   o DRAM hole changes
 *   o Normalization of the address due to interleaving (more fun)
 *   o The DRAM offset register of the rule
 */
static boolean_t
zen_umc_decode_sysaddr_to_norm(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	const zen_umc_chan_t *chan = dec->dec_umc_chan;
	const df_dram_rule_t *rule = dec->dec_df_rule;

	dec->dec_norm_addr = dec->dec_pa;
	if (!zen_umc_adjust_dram_addr(umc, dec, &dec->dec_norm_addr,
	    ZEN_UMC_DECODE_F_CALC_NORM_UNDERFLOW)) {
		return (B_FALSE);
	}

	/*
	 * Now for the most annoying part of this whole thing, normalizing based
	 * on our actual interleave format. The reason for this is that when
	 * interleaving is going on, it actually is removing bits that are just
	 * being used to direct it somewhere; however, it's actually generally
	 * speaking the same value in each location. See the big theory
	 * statement in zen_umc.c for more information.
	 */
	switch (rule->ddr_chan_ileave) {
	case DF_CHAN_ILEAVE_1CH:
	case DF_CHAN_ILEAVE_2CH:
	case DF_CHAN_ILEAVE_4CH:
	case DF_CHAN_ILEAVE_8CH:
	case DF_CHAN_ILEAVE_16CH:
	case DF_CHAN_ILEAVE_32CH:
		if (!zen_umc_decode_normalize_nohash(umc, dec)) {
			return (B_FALSE);
		}
		break;
	case DF_CHAN_ILEAVE_COD4_2CH:
	case DF_CHAN_ILEAVE_COD2_4CH:
	case DF_CHAN_ILEAVE_COD1_8CH:
	case DF_CHAN_ILEAVE_NPS4_2CH:
	case DF_CHAN_ILEAVE_NPS2_4CH:
	case DF_CHAN_ILEAVE_NPS1_8CH:
	case DF_CHAN_ILEAVE_NPS4_2CH_1K:
	case DF_CHAN_ILEAVE_NPS2_4CH_1K:
	case DF_CHAN_ILEAVE_NPS1_8CH_1K:
	case DF_CHAN_ILEAVE_NPS1_16CH_1K:
	case DF_CHAN_ILEAVE_NPS4_2CH_2K:
	case DF_CHAN_ILEAVE_NPS2_4CH_2K:
	case DF_CHAN_ILEAVE_NPS1_8CH_2K:
	case DF_CHAN_ILEAVE_NPS1_16CH_2K:
		if (!zen_umc_decode_normalize_hash(umc, dec)) {
			return (B_FALSE);
		}
		break;
	case DF_CHAN_ILEAVE_6CH:
		if (!zen_umc_decode_normalize_zen3_6ch(umc, dec)) {
			return (B_FALSE);
		}
		break;
	case DF_CHAN_ILEAVE_NPS4_3CH:
	case DF_CHAN_ILEAVE_NPS2_6CH:
	case DF_CHAN_ILEAVE_NPS1_12CH:
	case DF_CHAN_ILEAVE_NPS2_5CH:
	case DF_CHAN_ILEAVE_NPS1_10CH:
		if (!zen_umc_decode_normalize_nps_mod(umc, dec)) {
			return (B_FALSE);
		}
		break;
	case DF_CHAN_ILEAVE_NPS4_3CH_1K:
	case DF_CHAN_ILEAVE_NPS2_6CH_1K:
	case DF_CHAN_ILEAVE_NPS1_12CH_1K:
	case DF_CHAN_ILEAVE_NPS0_24CH_1K:
	case DF_CHAN_ILEAVE_NPS2_5CH_1K:
	case DF_CHAN_ILEAVE_NPS1_10CH_1K:
	case DF_CHAN_ILEAVE_NPS4_3CH_2K:
	case DF_CHAN_ILEAVE_NPS2_6CH_2K:
	case DF_CHAN_ILEAVE_NPS1_12CH_2K:
	case DF_CHAN_ILEAVE_NPS0_24CH_2K:
	case DF_CHAN_ILEAVE_NPS2_5CH_2K:
	case DF_CHAN_ILEAVE_NPS1_10CH_2K:
		if (!zen_umc_decode_normalize_nps_k_mod(umc, dec)) {
			return (B_FALSE);
		}
		break;
	case DF_CHAN_ILEAVE_MI3H_8CH:
	case DF_CHAN_ILEAVE_MI3H_16CH:
	case DF_CHAN_ILEAVE_MI3H_32CH:
	default:
		dec->dec_fail = ZEN_UMC_DECODE_F_CHAN_ILEAVE_NOTSUP;
		dec->dec_fail_data = rule->ddr_chan_ileave;
		return (B_FALSE);
	}

	/*
	 * Determine if this rule has an offset to apply. Note, there is never
	 * an offset for rule 0, hence the index into this is one less than the
	 * actual rule number. Unlike other transformations these offsets
	 * describe the start of a normalized range. Therefore we need to
	 * actually add this value instead of subtract.
	 */
	if (dec->dec_umc_ruleno > 0) {
		uint32_t offno = dec->dec_umc_ruleno - 1;
		const chan_offset_t *offset = &chan->chan_offsets[offno];

		if (offset->cho_valid) {
			dec->dec_norm_addr += offset->cho_offset;
		}
	}

	return (B_TRUE);
}

/*
 * This applies the formula that determines a chip-select actually matches which
 * is defined as (address & ~mask) == (base & ~mask) in the PPR. There is both a
 * primary and secondary mask here. We need to pay attention to which is used
 * (if any) for later on.
 */
static boolean_t
zen_umc_decoder_cs_matches(const umc_cs_t *cs, const uint64_t norm,
    boolean_t *matched_sec)
{
	if ((cs->ucs_flags & UMC_CS_F_DECODE_EN) == 0) {
		return (B_FALSE);
	}

	if (cs->ucs_base.udb_valid != 0) {
		uint64_t imask = ~cs->ucs_base_mask;
		if ((norm & imask) == (cs->ucs_base.udb_base & imask)) {
			*matched_sec = B_FALSE;
			return (B_TRUE);
		}
	}

	if (cs->ucs_sec.udb_valid != 0) {
		uint64_t imask = ~cs->ucs_sec_mask;
		if ((norm & imask) == (cs->ucs_sec.udb_base & imask)) {
			*matched_sec = B_TRUE;
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * Go through with our normalized address and map it to a given chip-select.
 * This as a side effect indicates which DIMM we're going out on as well. Note,
 * the final DIMM can change due to chip-select hashing; however, we use this
 * DIMM for determining all of the actual address translations.
 */
static boolean_t
zen_umc_decode_find_cs(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	const zen_umc_chan_t *chan = dec->dec_umc_chan;

	for (uint_t dimmno = 0; dimmno < ZEN_UMC_MAX_DIMMS; dimmno++) {
		const umc_dimm_t *dimm = &chan->chan_dimms[dimmno];

		if ((dimm->ud_flags & UMC_DIMM_F_VALID) == 0)
			continue;

		for (uint_t csno = 0; csno < ZEN_UMC_MAX_CS_PER_DIMM; csno++) {
			const umc_cs_t *cs = &dimm->ud_cs[csno];
			boolean_t is_sec = B_FALSE;

			if (zen_umc_decoder_cs_matches(cs, dec->dec_norm_addr,
			    &is_sec)) {
				dec->dec_dimm = dimm;
				dec->dec_cs = cs;
				dec->dec_log_csno = dimmno * ZEN_UMC_MAX_DIMMS +
				    csno;
				dec->dec_cs_sec = is_sec;
				return (B_TRUE);
			}
		}
	}

	dec->dec_fail = ZEN_UMC_DECODE_F_NO_CS_BASE_MATCH;
	return (B_FALSE);
}

/*
 * Extract the column from the address. For once, something that is almost
 * straightforward.
 */
static boolean_t
zen_umc_decode_cols(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint32_t cols = 0;
	const umc_cs_t *cs = dec->dec_cs;

	for (uint_t i = 0; i < cs->ucs_ncol; i++) {
		uint32_t index;

		index = cs->ucs_col_bits[i];
		cols |= bitx64(dec->dec_norm_addr, index, index) << i;
	}

	dec->dec_dimm_col = cols;
	return (B_TRUE);
}

/*
 * The row is split into two different regions. There's a low and high value,
 * though the high value is only present in DDR4. Unlike the column, where each
 * bit is spelled out, each set of row bits are contiguous (low and high are
 * independent).
 */
static boolean_t
zen_umc_decode_rows(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint32_t row = 0;
	uint8_t inv;
	const umc_cs_t *cs = dec->dec_cs;
	const uint_t total_bits = cs->ucs_nrow_lo + cs->ucs_nrow_hi;
	const uint_t lo_end = cs->ucs_nrow_lo + cs->ucs_row_low_bit - 1;

	row = bitx64(dec->dec_norm_addr, lo_end, cs->ucs_row_low_bit);
	if (cs->ucs_nrow_hi > 0) {
		const uint_t hi_end = cs->ucs_nrow_hi + cs->ucs_row_hi_bit - 1;
		const uint32_t hi = bitx64(dec->dec_norm_addr, hi_end,
		    cs->ucs_row_hi_bit);

		row |= hi << cs->ucs_nrow_lo;
	}

	if (dec->dec_cs_sec) {
		inv = cs->ucs_inv_msbs_sec;
	} else {
		inv = cs->ucs_inv_msbs;
	}

	/*
	 * We need to potentially invert the top two bits of the row address
	 * based on the low two bits of the inverted register below. Note, inv
	 * only has two valid bits below. So we shift them into place to perform
	 * the XOR. See the big theory statement in zen_umc.c for more on why
	 * this works.
	 */
	inv = inv << (total_bits - 2);
	row = row ^ inv;

	dec->dec_dimm_row = row;
	return (B_TRUE);
}

/*
 * Several of the hash schemes ask us to go through and xor all the bits that
 * are in an address to transform it into a single bit. This implements that for
 * a uint32_t. This is basically a bitwise XOR reduce.
 */
static uint8_t
zen_umc_running_xor32(const uint32_t in)
{
	uint8_t run = 0;

	for (uint_t i = 0; i < sizeof (in) * NBBY; i++) {
		run ^= bitx32(in, i, i);
	}

	return (run);
}

static uint8_t
zen_umc_running_xor64(const uint64_t in)
{
	uint8_t run = 0;

	for (uint_t i = 0; i < sizeof (in) * NBBY; i++) {
		run ^= bitx64(in, i, i);
	}

	return (run);
}

/*
 * Our goal here is to extract the number of banks and bank groups that are
 * used, if any.
 */
static boolean_t
zen_umc_decode_banks(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint8_t bank = 0;
	const umc_cs_t *cs = dec->dec_cs;
	const umc_chan_hash_t *hash = &dec->dec_umc_chan->chan_hash;

	/*
	 * Get an initial bank address bit and then perform any hashing if
	 * bank hashing is enabled. Note, the memory controller's nbanks is the
	 * total number of bank and bank group bits, hence why it's used for
	 * the loop counter.
	 */
	for (uint_t i = 0; i < cs->ucs_nbanks; i++) {
		uint32_t row_hash, col_hash;
		uint8_t row_xor, col_xor;
		uint_t targ = cs->ucs_bank_bits[i];
		uint8_t val = bitx64(dec->dec_norm_addr, targ, targ);
		const umc_bank_hash_t *bank_hash = &hash->uch_bank_hashes[i];

		if ((hash->uch_flags & UMC_CHAN_HASH_F_BANK) == 0 ||
		    !hash->uch_bank_hashes[i].ubh_en) {
			bank |= val << i;
			continue;
		}

		/*
		 * See the big theory statement for more on this. Short form,
		 * bit-wise AND the row and column, then XOR shenanigans.
		 */
		row_hash = dec->dec_dimm_row & bank_hash->ubh_row_xor;
		col_hash = dec->dec_dimm_col & bank_hash->ubh_col_xor;
		row_xor = zen_umc_running_xor32(row_hash);
		col_xor = zen_umc_running_xor32(col_hash);
		bank |= (row_xor ^ col_xor ^ val) << i;
	}

	/*
	 * The bank and bank group are conjoined in the register and bit
	 * definitions. Once we've calculated that, extract it.
	 */
	dec->dec_dimm_bank_group = bitx8(bank, cs->ucs_nbank_groups - 1, 0);
	dec->dec_dimm_bank = bitx8(bank, cs->ucs_nbanks, cs->ucs_nbank_groups);
	return (B_TRUE);
}

/*
 * Extract the sub-channel. If not a DDR5 based device, simply set it to zero
 * and return. We can't forget to hash this if required.
 */
static boolean_t
zen_umc_decode_subchan(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint8_t subchan;
	uint32_t row_hash, col_hash, bank_hash;
	uint8_t row_xor, col_xor, bank_xor;
	const umc_cs_t *cs = dec->dec_cs;
	const umc_chan_hash_t *hash = &dec->dec_umc_chan->chan_hash;

	switch (dec->dec_umc_chan->chan_type) {
	case UMC_DIMM_T_DDR5:
	case UMC_DIMM_T_LPDDR5:
		break;
	default:
		dec->dec_dimm_subchan = 0;
		return (B_TRUE);
	}

	subchan = bitx64(dec->dec_norm_addr, cs->ucs_subchan, cs->ucs_subchan);
	if ((hash->uch_flags & UMC_CHAN_HASH_F_PC) == 0 ||
	    !hash->uch_pc_hash.uph_en) {
		dec->dec_dimm_subchan = subchan;
		return (B_TRUE);
	}

	row_hash = dec->dec_dimm_row & hash->uch_pc_hash.uph_row_xor;
	col_hash = dec->dec_dimm_col & hash->uch_pc_hash.uph_col_xor;
	bank_hash = dec->dec_dimm_bank & hash->uch_pc_hash.uph_bank_xor;
	row_xor = zen_umc_running_xor32(row_hash);
	col_xor = zen_umc_running_xor32(col_hash);
	bank_xor = zen_umc_running_xor32(bank_hash);

	dec->dec_dimm_subchan = subchan ^ row_xor ^ col_xor ^ bank_xor;
	return (B_TRUE);
}

/*
 * Note that we have normalized the RM bits between the primary and secondary
 * base/mask registers so that way even though the DDR5 controller always uses
 * the same RM selection bits, it works in a uniform way for both DDR4 and DDR5.
 */
static boolean_t
zen_umc_decode_rank_mul(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint8_t rm = 0;
	const umc_cs_t *cs = dec->dec_cs;
	const umc_chan_hash_t *hash = &dec->dec_umc_chan->chan_hash;

	for (uint_t i = 0; i < cs->ucs_nrm; i++) {
		uint8_t index = cs->ucs_rm_bits[i];
		uint8_t bit = bitx64(dec->dec_norm_addr, index, index);

		if ((hash->uch_flags & UMC_CHAN_HASH_F_RM) != 0 &&
		    hash->uch_rm_hashes[i].uah_en) {
			uint64_t norm_mask = dec->dec_norm_addr &
			    hash->uch_rm_hashes[i].uah_addr_xor;
			uint8_t norm_hash = zen_umc_running_xor64(norm_mask);
			bit = bit ^ norm_hash;
		}

		rm |= bit << i;
	}

	dec->dec_dimm_rm = rm;
	return (B_TRUE);
}

/*
 * Go through and determine the actual chip-select activated. This is subject to
 * hashing. Note, we first constructed a logical chip-select value based on
 * which of the four base/mask registers in the UMC we activated for the
 * channel. That basically seeded the two bit value we start with.
 */
static boolean_t
zen_umc_decode_chipsel(const zen_umc_t *umc, zen_umc_decoder_t *dec)
{
	uint8_t csno = 0;
	const umc_cs_t *cs = dec->dec_cs;
	const umc_chan_hash_t *hash = &dec->dec_umc_chan->chan_hash;

	for (uint_t i = 0; i < ZEN_UMC_MAX_CS_BITS; i++) {
		uint8_t bit = bitx8(dec->dec_log_csno, i, i);
		if ((hash->uch_flags & UMC_CHAN_HASH_F_CS) != 0 &&
		    hash->uch_cs_hashes[i].uah_en) {
			uint64_t mask = dec->dec_norm_addr &
			    hash->uch_cs_hashes[i].uah_addr_xor;
			uint8_t rxor = zen_umc_running_xor64(mask);
			bit = bit ^ rxor;
		}
		csno |= bit << i;
	}

	/*
	 * It is not entirely clear what the circumstances are that we need to
	 * apply the chip-select xor. Right now we always apply it. This only
	 * exists on a few DDR5 SoCs, it seems, and we zero out other cases to
	 * try and have a uniform and reasonable path. This tells us what the
	 * absolute chip-select is in the channel. We record this for debugging
	 * purposes and to derive the DIMM and CS.
	 */
	dec->dec_chan_csno = (csno ^ cs->ucs_cs_xor) & 0x3;

	/*
	 * Now that we actually know which chip-select we're targeting, go back
	 * and actual indicate which DIMM we'll go out to and what chip-select
	 * it is relative to the DIMM. This may have changed out due to CS
	 * hashing. As such we have to now snapshot our final DIMM and
	 * chip-select.
	 */
	dec->dec_dimm_no = dec->dec_chan_csno >> 1;
	dec->dec_dimm_csno = dec->dec_chan_csno % 2;
	return (B_TRUE);
}

/*
 * Initialize the decoder state. We do this by first zeroing it all and then
 * setting various result addresses to the UINTXX_MAX that is appropriate. These
 * work as better sentinel values than zero; however, we always zero the
 * structure to be defensive, cover pointers, etc.
 */
static void
zen_umc_decoder_init(zen_umc_decoder_t *dec)
{
	bzero(dec, sizeof (*dec));

	dec->dec_pa = dec->dec_ilv_pa = UINT64_MAX;
	dec->dec_df_ruleno = UINT32_MAX;
	dec->dec_ilv_sock = dec->dec_ilv_die = dec->dec_ilv_chan =
	    dec->dec_ilv_fabid = dec->dec_log_fabid = dec->dec_remap_comp =
	    dec->dec_targ_fabid = UINT32_MAX;
	dec->dec_umc_ruleno = UINT32_MAX;
	dec->dec_norm_addr = UINT64_MAX;
	dec->dec_dimm_col = dec->dec_dimm_row = UINT32_MAX;
	dec->dec_log_csno = dec->dec_dimm_bank = dec->dec_dimm_bank_group =
	    dec->dec_dimm_subchan = dec->dec_dimm_rm = dec->dec_chan_csno =
	    dec->dec_dimm_no = dec->dec_dimm_csno = UINT8_MAX;
}

boolean_t
zen_umc_decode_pa(const zen_umc_t *umc, const uint64_t pa,
    zen_umc_decoder_t *dec)
{
	zen_umc_decoder_init(dec);
	dec->dec_pa = pa;

	/*
	 * Before we proceed through decoding, the first thing we should try to
	 * do is verify that this is even something that could be DRAM.
	 */
	if (!zen_umc_decode_is_dram(umc, dec)) {
		ASSERT3U(dec->dec_fail, !=, ZEN_UMC_DECODE_F_NONE);
		return (B_FALSE);
	}

	/*
	 * The very first thing that we need to do is find a data fabric rule
	 * that corresponds to this memory address. This will be used to
	 * determine which set of rules for interleave and related we actually
	 * should then use.
	 */
	if (!zen_umc_decode_find_df_rule(umc, dec)) {
		ASSERT3U(dec->dec_fail, !=, ZEN_UMC_DECODE_F_NONE);
		return (B_FALSE);
	}

	/*
	 * Now that we have a DF rule, we must take a more involved step of
	 * mapping to a given CS, e.g. a specific UMC channel. This will tell us
	 * the socket and die as well. This takes care of all the interleaving
	 * and remapping and produces a target fabric ID.
	 */
	if (!zen_umc_decode_sysaddr_to_csid(umc, dec)) {
		ASSERT3U(dec->dec_fail, !=, ZEN_UMC_DECODE_F_NONE);
		return (B_FALSE);
	}

	/*
	 * With that target ID known, now actually map this to a corresponding
	 * UMC.
	 */
	if (!zen_umc_decode_find_umc_rule(umc, dec)) {
		ASSERT3U(dec->dec_fail, !=, ZEN_UMC_DECODE_F_NONE);
		return (B_FALSE);
	}

	/*
	 * With the target and corresponding rules and offset information,
	 * actually perform normalization.
	 */
	if (!zen_umc_decode_sysaddr_to_norm(umc, dec)) {
		ASSERT3U(dec->dec_fail, !=, ZEN_UMC_DECODE_F_NONE);
		return (B_FALSE);
	}

	/*
	 * Finally, we somehow managed to actually construct a normalized
	 * address. Now we must begin the act of transforming this channel
	 * address into something that makes sense to address a DIMM. To start
	 * with determine which logical chip-select, which determines where we
	 * source all our data to use.
	 */
	if (!zen_umc_decode_find_cs(umc, dec)) {
		ASSERT3U(dec->dec_fail, !=, ZEN_UMC_DECODE_F_NONE);
		return (B_FALSE);
	}

	/*
	 * Now that we have the logical chip-select matched that we're sourcing
	 * our data from, the next this is a bit more involved: we need to
	 * extract the row, column, rank/rank multiplication, bank, and bank
	 * group out of all this, while taking into account all of our hashes.
	 *
	 * To do this, we begin by first calculating the row and column as those
	 * will be needed to determine some of our other values here.
	 */
	if (!zen_umc_decode_rows(umc, dec)) {
		ASSERT3U(dec->dec_fail, !=, ZEN_UMC_DECODE_F_NONE);
		return (B_FALSE);
	}

	if (!zen_umc_decode_cols(umc, dec)) {
		ASSERT3U(dec->dec_fail, !=, ZEN_UMC_DECODE_F_NONE);
		return (B_FALSE);
	}

	/*
	 * Now that we have the rows and columns we can go through and determine
	 * the bank and bank group. This depends on the above.
	 */
	if (!zen_umc_decode_banks(umc, dec)) {
		ASSERT3U(dec->dec_fail, !=, ZEN_UMC_DECODE_F_NONE);
		return (B_FALSE);
	}

	/*
	 * If we have a DDR5 generation DIMM then we need to consider the
	 * subchannel. This doesn't exist in DDR4 systems (the function handles
	 * this reality). Because of potential hashing, this needs to come after
	 * the row, column, and bank have all been determined.
	 */
	if (!zen_umc_decode_subchan(umc, dec)) {
		ASSERT3U(dec->dec_fail, !=, ZEN_UMC_DECODE_F_NONE);
		return (B_FALSE);
	}

	/*
	 * Time for the last two pieces here: the actual chip select used and
	 * then figuring out which rank, taking into account rank
	 * multiplication. Don't worry, these both have hashing opportunities.
	 */
	if (!zen_umc_decode_rank_mul(umc, dec)) {
		ASSERT3U(dec->dec_fail, !=, ZEN_UMC_DECODE_F_NONE);
		return (B_FALSE);
	}

	if (!zen_umc_decode_chipsel(umc, dec)) {
		ASSERT3U(dec->dec_fail, !=, ZEN_UMC_DECODE_F_NONE);
		return (B_FALSE);
	}

	/*
	 * Somehow, that's it.
	 */
	return (B_TRUE);
}
