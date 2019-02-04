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
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Memory decoding logic.
 *
 * This file is part of the 'imc' driver on x86. It supports taking a physical
 * address and determining what the corresponding DIMM is. This is shared
 * between the kernel and userland for easier testing.
 *
 * For more information about the different parts of the decoding process,
 * please see the file 'uts/i86pc/io/imc/imc.c'.
 */

#include <sys/sysmacros.h>

#ifndef _KERNEL
#include <stdint.h>
#include <strings.h>
#define	BITX(u, h, l)	(((u) >> (l)) & ((1LU << ((h) - (l) + 1LU)) - 1LU))
#endif	/* !_KERNEL */

#include "imc.h"

/*
 * Address ranges for decoding system addresses. There are three ranges that
 * exist on x86, traditional DOS memory (hi 640 KiB), low memory, and high
 * memory. Low memory always starts at 1 MiB and high memory always starts at 4
 * GiB. The upper bounds of these ranges is based on registers on the system.
 */
#define	IMC_DECODE_CONV_BASE	0UL
#define	IMC_DECODE_CONV_MAX	0x00009ffffULL	/* 640 KiB - 1 */
#define	IMC_DECODE_LOW_BASE	0x000100000ULL	/* 1 M */
#define	IMC_DECODE_HIGH_BASE	0x100000000ULL /* 4 GiB */

typedef struct imc_legacy_range {
	uint64_t	ilr_base;
	size_t		ilr_len;
	const char	*ilr_desc;
} imc_legacy_range_t;

/*
 * These represent regions of memory that are reserved for use and will not be
 * decoded by DRAM.
 */
static imc_legacy_range_t imc_legacy_ranges[] = {
	{ 0x00000A0000ULL,	128 * 1024,	"VGA" },
	{ 0x00000C0000ULL,	256 * 1024,	"PAM" },
	{ 0x0000F00000ULL,	1024 * 1024,	"Reserved" },
	{ 0x00FE000000ULL,	32 * 1024 * 1024, "Unknown" },
	{ 0x00FF000000ULL,	16 * 1024 * 1024, "Firmware" },
	{ 0x00FED20000ULL,	384 * 1024,	"TXT" },
	{ 0x00FED00000ULL,	1024 * 1024,	"PCH" },
	{ 0x00FEC00000ULL,	1024 * 1024,	"IOAPIC" },
	{ 0x00FEB80000ULL,	512 * 1024,	"Reserved" },
	{ 0x00FEB00000ULL,	64 * 1024,	"Reserved" }
};

/*
 * Determine whether or not this address is in one of the reserved regions or if
 * it falls outside of the explicit DRAM ranges.
 */
static boolean_t
imc_decode_addr_resvd(const imc_t *imc, imc_decode_state_t *dec)
{
	uint_t i;
	const imc_sad_t *sad;

	for (i = 0; i < ARRAY_SIZE(imc_legacy_ranges); i++) {
		uint64_t end = imc_legacy_ranges[i].ilr_base +
		    imc_legacy_ranges[i].ilr_len;

		if (dec->ids_pa >= imc_legacy_ranges[i].ilr_base &&
		    dec->ids_pa < end) {
			dec->ids_fail = IMC_DECODE_F_LEGACY_RANGE;
			dec->ids_fail_data = i;
			return (B_TRUE);
		}
	}

	/*
	 * For checking and determining whether or not we fit in DRAM, we need
	 * to check against the top of low memory and the top of high memory.
	 * While we technically have this information on a per-socket basis, we
	 * have to rely on the fact that both processors have the same
	 * information. A requirement which if not true, would lead to chaos
	 * depending on what socket we're running on.
	 */
	sad = &imc->imc_sockets[0].isock_sad;
	if (sad->isad_valid != IMC_SAD_V_VALID) {
		dec->ids_fail = IMC_DECODE_F_BAD_SAD;
		return (B_TRUE);
	}

	/*
	 * An address may fall into three ranges. It may fall into conventional
	 * memory. It may fall into low memory. It may fall into high memory.
	 * The conventional memory range is inclusive at the top. The others
	 * have been translated such that they are uniformly exclusive at the
	 * top. Because the bottom of conventional memory is at zero, the
	 * compiler will be angry if we compare against IMC_DECODE_CONV_BASE as
	 * it is always true.
	 */
	if (dec->ids_pa <= IMC_DECODE_CONV_MAX) {
		return (B_FALSE);
	}

	if (dec->ids_pa >= IMC_DECODE_LOW_BASE &&
	    dec->ids_pa < sad->isad_tolm) {
		return (B_FALSE);
	}

	if (dec->ids_pa >= IMC_DECODE_HIGH_BASE &&
	    dec->ids_pa < sad->isad_tohm) {
		return (B_FALSE);
	}

	/*
	 * Memory fell outside of the valid range. It's not for us.
	 */
	dec->ids_fail = IMC_DECODE_F_OUTSIDE_DRAM;
	return (B_TRUE);
}

static uint_t
imc_decode_sad_interleave(const imc_sad_rule_t *rule, uint64_t pa)
{
	uint_t itgt = 0;

	switch (rule->isr_imode) {
	case IMC_SAD_IMODE_8t6:
		if (rule->isr_a7mode) {
			itgt = BITX(pa, 9, 9);
			itgt |= (BITX(pa, 8, 7) << 1);
		} else {
			itgt = BITX(pa, 8, 6);
		}
		break;
	case IMC_SAD_IMODE_8t6XOR:
		if (rule->isr_a7mode) {
			itgt = BITX(pa, 9, 9);
			itgt |= (BITX(pa, 8, 7) << 1);
		} else {
			itgt = BITX(pa, 8, 6);
		}
		itgt ^= BITX(pa, 18, 16);
		break;
	case IMC_SAD_IMODE_10t8:
		itgt = BITX(pa, 10, 8);
		break;
	case IMC_SAD_IMODE_14t12:
		itgt = BITX(pa, 14, 12);
		break;
	case IMC_SAD_IMODE_32t30:
		itgt = BITX(pa, 32, 30);
		break;
	}

	return (itgt);
}

/*
 * Use the system address decoder to try and find a valid SAD entry for this
 * address. We always use socket zero's SAD as the SAD rules should be the same
 * between the different sockets.
 */
static boolean_t
imc_decode_sad(const imc_t *imc, imc_decode_state_t *dec)
{
	uint_t i, ileaveidx;
	uint8_t ileavetgt;
	uint32_t nodeid, tadid, channelid;
	uint64_t base;
	const imc_socket_t *socket = &imc->imc_sockets[0];
	const imc_sad_t *sad = &socket->isock_sad;
	const imc_sad_rule_t *rule;
	boolean_t loop = B_FALSE;

	/*
	 * Note, all SAD rules have been adjusted so that they are uniformly
	 * exclusive.
	 */
start:
	for (rule = NULL, i = 0, base = 0; i < sad->isad_nrules; i++) {
		rule = &sad->isad_rules[i];

		if (rule->isr_enable && dec->ids_pa >= base &&
		    dec->ids_pa < rule->isr_limit) {
			break;
		}

		base = rule->isr_limit;
	}

	if (rule == NULL || i == sad->isad_nrules) {
		dec->ids_fail = IMC_DECODE_F_NO_SAD_RULE;
		return (B_FALSE);
	}

	/*
	 * Store the SAD rule in the decode information for debugging's sake.
	 */
	dec->ids_sad = sad;
	dec->ids_sad_rule = rule;

	/*
	 * We have found a SAD rule. We now need to transform that into the
	 * corresponding target based on its mode, etc. The way we do this
	 * varies based on the generation.
	 *
	 * The first thing we need to do is to figure out the target in the
	 * interleave list.
	 */
	ileaveidx = imc_decode_sad_interleave(rule, dec->ids_pa);
	if (ileaveidx >= rule->isr_ntargets) {
		dec->ids_fail = IMC_DECODE_F_BAD_SAD_INTERLEAVE;
		dec->ids_fail_data = ileaveidx;
		return (B_FALSE);
	}
	ileavetgt = rule->isr_targets[ileaveidx];
	if (imc->imc_gen >= IMC_GEN_SKYLAKE &&
	    IMC_SAD_ILEAVE_SKX_LOCAL(ileavetgt) == 0) {
		/*
		 * If we're in this case, the interleave rule said we had a
		 * remote target. That means we need to find the correct SAD
		 * based on the Node ID and then do all of this over again.
		 */
		nodeid = IMC_SAD_ILEAVE_SKX_TARGET(ileavetgt);

		if (loop) {
			dec->ids_fail = IMC_DECODE_F_SAD_SEARCH_LOOP;
			return (B_FALSE);
		}

		for (i = 0; i < imc->imc_nsockets; i++) {
			if (imc->imc_sockets[i].isock_valid ==
			    IMC_SOCKET_V_VALID &&
			    imc->imc_sockets[i].isock_nodeid == nodeid) {
				socket = &imc->imc_sockets[i];
				sad = &imc->imc_sockets[i].isock_sad;
				loop = B_TRUE;
				goto start;
			}
		}

		dec->ids_fail = IMC_DECODE_F_BAD_REMOTE_MC_ROUTE;
		dec->ids_fail_data = nodeid;
		return (B_FALSE);
	}

	/*
	 * On some platforms we need to derive the target channel based on the
	 * physical address and additional rules in the SAD. If we do, do that
	 * here. The idea is that this may overrule the memory channel route
	 * table target that was determined from the SAD rule.
	 */
	if (rule->isr_need_mod3) {
		uint64_t addr;
		uint8_t channel;

		switch (rule->isr_mod_mode) {
		case IMC_SAD_MOD_MODE_45t6:
			addr = dec->ids_pa >> 6;
			break;
		case IMC_SAD_MOD_MODE_45t8:
			addr = dec->ids_pa >> 8;
			break;
		case IMC_SAD_MOD_MODE_45t12:
			addr = dec->ids_pa >> 12;
			break;
		default:
			dec->ids_fail = IMC_DECODE_F_SAD_BAD_MOD;
			return (B_FALSE);
		}

		switch (rule->isr_mod_type) {
		case IMC_SAD_MOD_TYPE_MOD3:
			channel = (addr % 3) << 1;
			channel |= ileavetgt & 1;
			break;
		case IMC_SAD_MOD_TYPE_MOD2_01:
			channel = (addr % 2) << 1;
			channel |= ileavetgt & 1;
			break;
		case IMC_SAD_MOD_TYPE_MOD2_12:
			channel = (addr % 2) << 2;
			channel |= (~addr % 2) << 1;
			channel |= ileavetgt & 1;
			break;
		case IMC_SAD_MOD_TYPE_MOD2_02:
			channel = (addr % 2) << 2;
			channel |= ileavetgt & 1;
			break;
		default:
			dec->ids_fail = IMC_DECODE_F_SAD_BAD_MOD;
			return (B_FALSE);
		}

		ileavetgt = channel;
	}

	switch (imc->imc_gen) {
	case IMC_GEN_SANDY:
		/*
		 * Sandy Bridge systems only have a single home agent, so the
		 * interleave target is always the node id.
		 */
		nodeid = ileavetgt;
		tadid = 0;
		channelid = UINT32_MAX;
		break;
	case IMC_GEN_IVY:
	case IMC_GEN_HASWELL:
	case IMC_GEN_BROADWELL:
		/*
		 * On these generations, the interleave NodeID in the SAD
		 * encodes both the nodeid and the home agent ID that we care
		 * about.
		 */
		nodeid = IMC_NODEID_IVY_BRD_UPPER(ileavetgt) |
		    IMC_NODEID_IVY_BRD_LOWER(ileavetgt);
		tadid = IMC_NODEID_IVY_BRD_HA(ileavetgt);
		channelid = UINT32_MAX;
		break;
	case IMC_GEN_SKYLAKE:
		/*
		 * On Skylake generation systems we take the interleave target
		 * and use that to look up both the memory controller and the
		 * physical channel in the route table. The nodeid is already
		 * known because its SAD rules redirect us.
		 */
		nodeid = socket->isock_nodeid;
		if (ileavetgt > IMC_SAD_ILEAVE_SKX_MAX) {
			dec->ids_fail = IMC_DECODE_F_BAD_SAD_INTERLEAVE;
			dec->ids_fail_data = ileavetgt;
			return (B_FALSE);
		}
		ileavetgt = IMC_SAD_ILEAVE_SKX_TARGET(ileavetgt);
		if (ileavetgt > sad->isad_mcroute.ismc_nroutes) {
			dec->ids_fail = IMC_DECODE_F_BAD_SAD_INTERLEAVE;
			dec->ids_fail_data = ileavetgt;
			return (B_FALSE);
		}
		tadid = sad->isad_mcroute.ismc_mcroutes[ileavetgt].ismce_imc;
		channelid =
		    sad->isad_mcroute.ismc_mcroutes[ileavetgt].ismce_pchannel;
		break;
	default:
		nodeid = tadid = channelid = UINT32_MAX;
		break;
	}

	/*
	 * Map to the correct socket based on the nodeid. Make sure that we have
	 * a valid TAD.
	 */
	dec->ids_socket = NULL;
	for (i = 0; i < imc->imc_nsockets; i++) {
		if (imc->imc_sockets[i].isock_nodeid == nodeid) {
			dec->ids_socket = &imc->imc_sockets[i];
			break;
		}
	}
	if (dec->ids_socket == NULL) {
		dec->ids_fail = IMC_DECODE_F_SAD_BAD_SOCKET;
		dec->ids_fail_data = nodeid;
		return (B_FALSE);
	}

	if (tadid >= dec->ids_socket->isock_ntad) {
		dec->ids_fail = IMC_DECODE_F_SAD_BAD_TAD;
		dec->ids_fail_data = tadid;
		return (B_FALSE);
	}

	dec->ids_nodeid = nodeid;
	dec->ids_tadid = tadid;
	dec->ids_channelid = channelid;
	dec->ids_tad = &dec->ids_socket->isock_tad[tadid];
	dec->ids_mc = &dec->ids_socket->isock_imcs[tadid];

	return (B_TRUE);
}

/*
 * For Sandy Bridge through Broadwell we need to decode the memory channel that
 * we're targeting. This is determined based on the number of ways that the
 * socket and channel are supposed to be interleaved. The TAD has a target
 * channel list sitting with the TAD rule. To figure out the appropriate index,
 * the algorithm is roughly:
 *
 *    idx = [(dec->ids_pa >> 6) / socket-ways] % channel-ways
 *
 * The shift by six, comes from taking the number of bits that are in theory in
 * the cache line size. Of course, if things were this simple, that'd be great.
 * The first complication is a7mode / MCChanShiftUpEnable. When this is enabled,
 * more cache lines are used for this. The next complication comes when the
 * feature MCChanHashEn is enabled. This means that we have to hash the
 * resulting address before we do the modulus based on the number of channel
 * ways.
 *
 * The last, and most complicated problem is when the number of channel ways is
 * set to three. When this is the case, the base address of the range may not
 * actually start at index zero. The nominal solution is to use the offset
 * that's programmed on a per-channel basis to offset the system address.
 * However, to get that information we would have to know what channel we're on,
 * which is what we're trying to figure out. Regretfully, proclaim that we can't
 * in this case.
 */
static boolean_t
imc_decode_tad_channel(const imc_t *imc, imc_decode_state_t *dec)
{
	uint64_t index;
	const imc_tad_rule_t *rule = dec->ids_tad_rule;

	index = dec->ids_pa >> 6;
	if ((dec->ids_tad->itad_flags & IMC_TAD_FLAG_CHANSHIFT) != 0) {
		index = index >> 1;
	}

	/*
	 * When performing a socket way equals three comparison, this would not
	 * work.
	 */
	index = index / rule->itr_sock_way;

	if ((dec->ids_tad->itad_flags & IMC_TAD_FLAG_CHANHASH) != 0) {
		uint_t i;
		for (i = 12; i < 28; i += 2) {
			uint64_t shift = (dec->ids_pa >> i) & 0x3;
			index ^= shift;
		}
	}

	index %= rule->itr_chan_way;
	if (index >= rule->itr_ntargets) {
		dec->ids_fail = IMC_DECODE_F_TAD_BAD_TARGET_INDEX;
		dec->ids_fail_data = index;
		return (B_FALSE);
	}

	dec->ids_channelid = rule->itr_targets[index];
	return (B_TRUE);
}

static uint_t
imc_tad_gran_to_shift(const imc_tad_t *tad, imc_tad_gran_t gran)
{
	uint_t shift = 0;

	switch (gran) {
	case IMC_TAD_GRAN_64B:
		shift = 6;
		if ((tad->itad_flags & IMC_TAD_FLAG_CHANSHIFT) != 0) {
			shift++;
		}
		break;
	case IMC_TAD_GRAN_256B:
		shift = 8;
		break;
	case IMC_TAD_GRAN_4KB:
		shift = 12;
		break;
	case IMC_TAD_GRAN_1GB:
		shift = 30;
		break;
	}

	return (shift);
}

static boolean_t
imc_decode_tad(const imc_t *imc, imc_decode_state_t *dec)
{
	uint_t i, tadruleno;
	uint_t sockshift, chanshift, sockmask, chanmask;
	uint64_t off, chanaddr;
	const imc_tad_t *tad = dec->ids_tad;
	const imc_mc_t *mc = dec->ids_mc;
	const imc_tad_rule_t *rule = NULL;
	const imc_channel_t *chan;

	/*
	 * The first step in all of this is to determine which TAD rule applies
	 * for this address.
	 */
	for (i = 0; i < tad->itad_nrules; i++) {
		rule = &tad->itad_rules[i];

		if (dec->ids_pa >= rule->itr_base &&
		    dec->ids_pa < rule->itr_limit) {
			break;
		}
	}

	if (rule == NULL || i == tad->itad_nrules) {
		dec->ids_fail = IMC_DECODE_F_NO_TAD_RULE;
		return (B_FALSE);
	}
	tadruleno = i;
	dec->ids_tad_rule = rule;

	/*
	 * Check if our TAD rule requires 3-way interleaving on the channel. We
	 * basically can't do that right now. For more information, see the
	 * comment above imc_decode_tad_channel().
	 */
	if (rule->itr_chan_way == 3) {
		dec->ids_fail = IMC_DECODE_F_TAD_3_ILEAVE;
		return (B_FALSE);
	}

	/*
	 * On some platforms, we need to now calculate the channel index from
	 * this. The way that we calculate this is nominally straightforward,
	 * but complicated by a number of different issues.
	 */
	switch (imc->imc_gen) {
	case IMC_GEN_SANDY:
	case IMC_GEN_IVY:
	case IMC_GEN_HASWELL:
	case IMC_GEN_BROADWELL:
		if (!imc_decode_tad_channel(imc, dec)) {
			return (B_FALSE);
		}
		break;
	default:
		/*
		 * On Skylake and newer platforms we should have already decoded
		 * the target channel based on using the memory controller route
		 * table above.
		 */
		break;
	}

	/*
	 * We initialize ids_channelid to UINT32_MAX, so this should make sure
	 * that we catch an incorrect channel as well.
	 */
	if (dec->ids_channelid >= mc->icn_nchannels) {
		dec->ids_fail = IMC_DECODE_F_BAD_CHANNEL_ID;
		dec->ids_fail_data = dec->ids_channelid;
		return (B_FALSE);
	}
	chan = &mc->icn_channels[dec->ids_channelid];
	dec->ids_chan = chan;

	if (tadruleno >= chan->ich_ntad_offsets) {
		dec->ids_fail = IMC_DECODE_F_BAD_CHANNEL_TAD_OFFSET;
		dec->ids_fail_data = tadruleno;
		return (B_FALSE);
	}

	/*
	 * Now we can go ahead and calculate the channel address, which is
	 * roughly equal to:
	 *
	 * chan_addr = (sys_addr - off) / (chan way * sock way).
	 *
	 * The catch is that we want to preserve the low bits where possible.
	 * The number of bits is based on the interleaving granularities, the
	 * way that's calculated is based on information in the TAD rule.
	 * However, if a7mode is enabled on Ivy Bridge through Broadwell, then
	 * we need to add one to that. So we will save the smallest number of
	 * bits that are left after interleaving.
	 *
	 * Because the interleaving occurs at different granularities, we need
	 * to break this into two discrete steps, one where we apply the socket
	 * interleaving and one where we apply the channel interleaving,
	 * shifting and dividing at each step.
	 */
	off = chan->ich_tad_offsets[tadruleno];
	if (off > dec->ids_pa) {
		dec->ids_fail = IMC_DECODE_F_CHANOFF_UNDERFLOW;
		return (B_FALSE);
	}
	chanshift = imc_tad_gran_to_shift(tad, rule->itr_chan_gran);
	sockshift = imc_tad_gran_to_shift(tad, rule->itr_sock_gran);
	chanmask = (1 << chanshift) - 1;
	sockmask = (1 << sockshift) - 1;

	chanaddr = dec->ids_pa - off;
	chanaddr >>= sockshift;
	chanaddr /= rule->itr_sock_way;
	chanaddr <<= sockshift;
	chanaddr |= dec->ids_pa & sockmask;
	chanaddr >>= chanshift;
	chanaddr /= rule->itr_chan_way;
	chanaddr <<= chanshift;
	chanaddr |= dec->ids_pa & chanmask;

	dec->ids_chanaddr = chanaddr;

	return (B_TRUE);
}

static boolean_t
imc_decode_rir(const imc_t *imc, imc_decode_state_t *dec)
{
	const imc_mc_t *mc = dec->ids_mc;
	const imc_channel_t *chan = dec->ids_chan;
	const imc_rank_ileave_t *rir = NULL;
	const imc_rank_ileave_entry_t *rirtarg;
	const imc_dimm_t *dimm;
	uint32_t shift, index;
	uint_t i, dimmid, rankid;
	uint64_t mask, base, rankaddr;

	if (mc->icn_closed) {
		shift = IMC_PAGE_BITS_CLOSED;
	} else {
		shift = IMC_PAGE_BITS_OPEN;
	}
	mask = (1UL << shift) - 1;

	for (i = 0, base = 0; i < chan->ich_nrankileaves; i++) {
		rir = &chan->ich_rankileaves[i];
		if (rir->irle_enabled && dec->ids_chanaddr >= base &&
		    dec->ids_chanaddr < rir->irle_limit) {
			break;
		}

		base = rir->irle_limit;
	}

	if (rir == NULL || i == chan->ich_nrankileaves) {
		dec->ids_fail = IMC_DECODE_F_NO_RIR_RULE;
		return (B_FALSE);
	}
	dec->ids_rir = rir;

	/*
	 * Determine the index of the rule that we care about. This is done by
	 * shifting the address based on the open and closed page bits and then
	 * just modding it by the number of ways in question.
	 */
	index = (dec->ids_chanaddr >> shift) % rir->irle_nways;
	if (index >= rir->irle_nentries) {
		dec->ids_fail = IMC_DECODE_F_BAD_RIR_ILEAVE_TARGET;
		dec->ids_fail_data = index;
		return (B_FALSE);
	}
	rirtarg = &rir->irle_entries[index];

	/*
	 * The rank interleaving register has information about a physical rank
	 * target. This is within the notion of the physical chip selects that
	 * exist. While the memory controller only has eight actual chip
	 * selects, the physical values that are programmed depend a bit on the
	 * underlying hardware. Effectively, in this ID space, each DIMM has
	 * four ranks associated with it. Even when we only have two ranks with
	 * each physical channel, they'll be programmed so we can simply do the
	 * following match:
	 *
	 * DIMM = rank id / 4
	 * RANK = rank id % 4
	 */
	dec->ids_physrankid = rirtarg->irle_target;
	dimmid = dec->ids_physrankid / 4;
	rankid = dec->ids_physrankid % 4;

	if (dimmid >= chan->ich_ndimms) {
		dec->ids_fail = IMC_DECODE_F_BAD_DIMM_INDEX;
		dec->ids_fail_data = dimmid;
		return (B_FALSE);
	}

	dimm = &chan->ich_dimms[dimmid];
	if (!dimm->idimm_present) {
		dec->ids_fail = IMC_DECODE_F_DIMM_NOT_PRESENT;
		return (B_FALSE);
	}
	dec->ids_dimmid = dimmid;
	dec->ids_dimm = dimm;

	if (rankid >= dimm->idimm_nranks) {
		dec->ids_fail = IMC_DECODE_F_BAD_DIMM_RANK;
		dec->ids_fail_data = rankid;
		return (B_FALSE);
	}
	dec->ids_rankid = rankid;

	/*
	 * Calculate the rank address. We need to divide the address by the
	 * number of rank ways and then or in the lower bits.
	 */
	rankaddr = dec->ids_chanaddr;
	rankaddr >>= shift;
	rankaddr /= rir->irle_nways;
	rankaddr <<= shift;
	rankaddr |= dec->ids_chanaddr & mask;

	if (rirtarg->irle_offset > rankaddr) {
		dec->ids_fail = IMC_DECODE_F_RANKOFF_UNDERFLOW;
		return (B_FALSE);
	}
	rankaddr -= rirtarg->irle_offset;
	dec->ids_rankaddr = rankaddr;

	return (B_TRUE);
}

boolean_t
imc_decode_pa(const imc_t *imc, uint64_t pa, imc_decode_state_t *dec)
{
	bzero(dec, sizeof (*dec));
	dec->ids_pa = pa;
	dec->ids_nodeid = dec->ids_tadid = dec->ids_channelid = UINT32_MAX;

	/*
	 * We need to rely on socket zero's information. Make sure that it both
	 * exists and is considered valid.
	 */
	if (imc->imc_nsockets < 1 ||
	    imc->imc_sockets[0].isock_valid != IMC_SOCKET_V_VALID) {
		dec->ids_fail = IMC_DECODE_F_BAD_SOCKET;
		dec->ids_fail_data = 0;
		return (B_FALSE);
	}

	/*
	 * First, we need to make sure that the PA we've been given actually is
	 * meant to target a DRAM address. This address may fall to MMIO, MMCFG,
	 * be an address that's outside of DRAM, or belong to a legacy address
	 * range that is interposed.
	 */
	if (imc_decode_addr_resvd(imc, dec)) {
		return (B_FALSE);
	}

	/*
	 * Now that we have this data, we want to go through and look at the
	 * SAD. The SAD will point us to a specific socket and an IMC / home
	 * agent on that socket which will tell us which TAD we need to use.
	 */
	if (!imc_decode_sad(imc, dec)) {
		return (B_FALSE);
	}

	/*
	 * The decoded SAD information has pointed us a TAD. We need to use this
	 * to point us to the corresponding memory channel and the corresponding
	 * address on the channel.
	 */
	if (!imc_decode_tad(imc, dec)) {
		return (B_FALSE);
	}

	/*
	 * Use the rank interleaving data to determine which DIMM this is, the
	 * relevant rank, and the rank address.
	 */
	if (!imc_decode_rir(imc, dec)) {
		return (B_FALSE);
	}

	return (B_TRUE);
}
