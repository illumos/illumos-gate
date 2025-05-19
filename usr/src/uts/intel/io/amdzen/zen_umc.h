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

#ifndef _ZEN_UMC_H
#define	_ZEN_UMC_H

/*
 * This file contains definitions that are used to manage and decode the Zen UMC
 * state.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/stdint.h>
#include <sys/sunddi.h>
#include <sys/nvpair.h>
#include <sys/x86_archext.h>
#include <amdzen_client.h>

/*
 * This is the maximum number of DRAM rules that we expect any supported device
 * to have here. The actual number may be less. These are rules that come from a
 * DF CCM.
 */
#define	ZEN_UMC_MAX_DRAM_RULES	20

/*
 * This is the maximum number of rules that we expect any system to actually
 * have for each UMC.
 */
#define	ZEN_UMC_MAX_CS_RULES	4

/*
 * This is the maximum number of DFs that we expect to encounter in a given
 * platform. This number comes from the Naples generation, where there were up
 * to 4 per socket, 2 sockets per machine, so 8 total. In subsequent generations
 * there is only a single 1 per socket.
 */
#define	ZEN_UMC_MAX_DFS	8

/*
 * This indicates the maximum number of UMC DF nodes that we expect to
 * encounter.
 */
#define	ZEN_UMC_MAX_UMCS	12

/*
 * This indicates the maximum number of DRAM offset rules that can exist in a
 * platform. Note, this is directly tied to the maximum number of CS rules.
 */
#define	ZEN_UMC_MAX_DRAM_OFFSET	(ZEN_UMC_MAX_CS_RULES - 1)

/*
 * This indicates the maximum number of remap rule sets and corresponding
 * entries that can exist. Milan's max is smaller than the current overall DFv4
 * maximum.
 */
#define	ZEN_UMC_MAX_CS_REMAPS		4
#define	ZEN_UMC_MAX_REMAP_ENTS		16
#define	ZEN_UMC_MILAN_CS_NREMAPS	2
#define	ZEN_UMC_MILAN_REMAP_ENTS	12
#define	ZEN_UMC_REMAP_PER_REG		8
#define	ZEN_UMC_REMAP_PER_REG_4D2	6

/*
 * DRAM Channel related maximums.
 */
#define	ZEN_UMC_MAX_DIMMS		2
#define	ZEN_UMC_MAX_CS_PER_DIMM		2
#define	ZEN_UMC_MAX_CS_BITS		2
#define	ZEN_UMC_MAX_CHAN_BASE		2
#define	ZEN_UMC_MAX_CHAN_MASK		2
#define	ZEN_UMC_MAX_BANK_BITS		5
#define	ZEN_UMC_MAX_COL_BITS		16
#define	ZEN_UMC_MAX_RM_BITS		4
#define	ZEN_UMC_MAX_COLSEL_PER_REG	8

#define	ZEN_UMC_DDR4_CHAN_NMASKS	1

/*
 * DRAM Channel hash maximums. Surprisingly enough, the DDR4 and DDR5 maximums
 * are the same; however, in exchange what hashes are actually implemented
 * varies.
 */
#define	ZEN_UMC_MAX_CHAN_BANK_HASH	5
#define	ZEN_UMC_MAX_CHAN_RM_HASH	3
#define	ZEN_UMC_MAX_CHAN_CS_HASH	2

/*
 * A sentinel to indicate we were unable to determine a frequency or transfer
 * rate.
 */
#define	ZEN_UMC_UNKNOWN_FREQ	0

/*
 * This is the number of memory P-states that the UMC supports. This appears to
 * be the same across all Zen Family processors. While there are ways to see the
 * current P-state, it is hard to really know when these transitions occur. We
 * simply grab all of the speed and configuration information with them when we
 * discover it.
 */
#define	ZEN_UMC_NMEM_PSTATES	4

/*
 * This is the logical set of different channel interleaving rules that we
 * support today in the driver. The actual values of the enumeration do not
 * overlap at all with hardware. Do not use these to try and marry up against
 * values from the DF itself.
 *
 * Note, these values are also encoded in the private mc decoder dumps that we
 * can produce. If these values change, please take care of ensuring
 * compatibility for others who may be consuming this. Appending to this list
 * should be OK.
 */
typedef enum df_chan_ileave {
	DF_CHAN_ILEAVE_1CH	= 0,
	DF_CHAN_ILEAVE_2CH,
	DF_CHAN_ILEAVE_4CH,
	DF_CHAN_ILEAVE_6CH,
	DF_CHAN_ILEAVE_8CH,
	DF_CHAN_ILEAVE_16CH,
	DF_CHAN_ILEAVE_32CH,
	DF_CHAN_ILEAVE_COD4_2CH,
	DF_CHAN_ILEAVE_COD2_4CH,
	DF_CHAN_ILEAVE_COD1_8CH,
	/*
	 * The primary NPS hashes were added in Zen 4 / DF 4.0.
	 */
	DF_CHAN_ILEAVE_NPS4_2CH,
	DF_CHAN_ILEAVE_NPS2_4CH,
	DF_CHAN_ILEAVE_NPS1_8CH,
	DF_CHAN_ILEAVE_NPS4_3CH,
	DF_CHAN_ILEAVE_NPS2_6CH,
	DF_CHAN_ILEAVE_NPS1_12CH,
	DF_CHAN_ILEAVE_NPS2_5CH,
	DF_CHAN_ILEAVE_NPS1_10CH,
	/*
	 * The 1K/2K split was primarily introduced in Zen 5. There are no DF
	 * 4.0 style NPS values in the enumeration.
	 */
	DF_CHAN_ILEAVE_NPS4_2CH_1K,
	DF_CHAN_ILEAVE_NPS2_4CH_1K,
	DF_CHAN_ILEAVE_NPS1_8CH_1K,
	DF_CHAN_ILEAVE_NPS1_16CH_1K,
	DF_CHAN_ILEAVE_NPS4_3CH_1K,
	DF_CHAN_ILEAVE_NPS2_6CH_1K,
	DF_CHAN_ILEAVE_NPS1_12CH_1K,
	DF_CHAN_ILEAVE_NPS0_24CH_1K,
	DF_CHAN_ILEAVE_NPS2_5CH_1K,
	DF_CHAN_ILEAVE_NPS1_10CH_1K,
	DF_CHAN_ILEAVE_NPS4_2CH_2K,
	DF_CHAN_ILEAVE_NPS2_4CH_2K,
	DF_CHAN_ILEAVE_NPS1_8CH_2K,
	DF_CHAN_ILEAVE_NPS1_16CH_2K,
	DF_CHAN_ILEAVE_NPS4_3CH_2K,
	DF_CHAN_ILEAVE_NPS2_6CH_2K,
	DF_CHAN_ILEAVE_NPS1_12CH_2K,
	DF_CHAN_ILEAVE_NPS0_24CH_2K,
	DF_CHAN_ILEAVE_NPS2_5CH_2K,
	DF_CHAN_ILEAVE_NPS1_10CH_2K,
	/*
	 * MI300 style hash variants. Internally referred to as "MI3H".
	 */
	DF_CHAN_ILEAVE_MI3H_8CH,
	DF_CHAN_ILEAVE_MI3H_16CH,
	DF_CHAN_ILEAVE_MI3H_32CH
} df_chan_ileave_t;

/*
 * This is a collection of logical flags that we use to cover attributes of a
 * DRAM rule.
 */
typedef enum df_dram_flags {
	/*
	 * Used to indicate that the contents of the rule are actually valid and
	 * should be considered. Many rules can be unused in hardware.
	 */
	DF_DRAM_F_VALID		= 1 << 0,
	/*
	 * Indicates that the DRAM hole is active for this particular rule. If
	 * this flag is set and the hole is valid in the DF, then we need to
	 * take the actual DRAM hole into account.
	 */
	DF_DRAM_F_HOLE		= 1 << 1,
	/*
	 * These next five are used to indicate when hashing is going on, which
	 * bits to use. These are for 4K, 64K, 2M, 1G, and 1T parts of addresses
	 * respectively. The 4K and 1T were added starting with DF 4D2. The 4K
	 * hashing is only currently known to be consumed as part of the MI3H
	 * series hashed interleaving.
	 */
	DF_DRAM_F_HASH_12_14	= 1 << 2,
	DF_DRAM_F_HASH_16_18	= 1 << 3,
	DF_DRAM_F_HASH_21_23	= 1 << 4,
	DF_DRAM_F_HASH_30_32	= 1 << 5,
	DF_DRAM_F_HASH_40_42	= 1 << 6,
	/*
	 * Indicates that this rule should have remap processing and the remap
	 * target is valid. If the DF_DRAM_F_REMAP_SOCK flag is set, this
	 * indicates that the processing is based on socket versus a particular
	 * entry.
	 */
	DF_DRAM_F_REMAP_EN	= 1 << 7,
	DF_DRAM_F_REMAP_SOCK	= 1 << 8,
	/*
	 * Indicates that this region is backed by "storage class memory".
	 * Maintained for debugging information.
	 */
	DF_DRAM_F_SCM		= 1 << 9
} df_dram_flags_t;

/*
 * This represents a single offset value for a channel. This is used when
 * applying normalization.
 */
typedef struct chan_offset {
	uint32_t	cho_raw;
	boolean_t	cho_valid;
	uint64_t	cho_offset;
} chan_offset_t;

/*
 * This structure represents a single DRAM rule, no matter where it shows up.
 * This smooths over the differences between generations.
 */
typedef struct df_dram_rule {
	uint32_t		ddr_raw_base;
	uint32_t		ddr_raw_limit;
	uint32_t		ddr_raw_ctrl;
	uint32_t		ddr_raw_ileave;
	df_dram_flags_t		ddr_flags;
	uint64_t		ddr_base;
	uint64_t		ddr_limit;
	uint16_t		ddr_dest_fabid;
	uint8_t			ddr_sock_ileave_bits;
	uint8_t			ddr_die_ileave_bits;
	uint8_t			ddr_addr_start;
	uint8_t			ddr_remap_ent;
	df_chan_ileave_t	ddr_chan_ileave;
} df_dram_rule_t;

typedef struct umc_dimm_base {
	uint64_t	udb_base;
	boolean_t	udb_valid;
} umc_dimm_base_t;

typedef enum umc_dimm_type {
	UMC_DIMM_T_UNKNOWN,
	UMC_DIMM_T_DDR4,
	UMC_DIMM_T_LPDDR4,
	UMC_DIMM_T_DDR5,
	UMC_DIMM_T_LPDDR5
} umc_dimm_type_t;

typedef enum umc_dimm_width {
	UMC_DIMM_W_X4,
	UMC_DIMM_W_X8,
	UMC_DIMM_W_X16,
} umc_dimm_width_t;

typedef enum umc_dimm_kind {
	UMC_DIMM_K_UDIMM,
	UMC_DIMM_K_RDIMM,
	UMC_DIMM_K_LRDIMM,
	UMC_DIMM_K_3DS_RDIMM
} umc_dimm_kind_t;

typedef enum umc_dimm_flags {
	/*
	 * This flag indicates that this DIMM should be used for decoding
	 * purposes. It basically means that there is at least one chip-select
	 * decoding register that has been enabled. Unfortunately, we don't have
	 * a good way right now of distinguishing between a DIMM being present
	 * and being usable. This likely needs to be re-evaluated when we
	 * consider how we present things to topo. We may be able to pull this
	 * out of the clock disable logic.
	 */
	UMC_DIMM_F_VALID	= 1 << 0,
} umc_dimm_flags_t;

typedef enum umc_cs_flags {
	/*
	 * This flag indicates that at least one of the base or secondary
	 * chip-select decoding register is enabled.
	 */
	UMC_CS_F_DECODE_EN	= 1 << 0,
} umc_cs_flags_t;

/*
 * A DIMM may have one or more ranks, which is an independent logical item that
 * is activated by a 'chip-select' signal on a DIMM (e.g. CS_L[1:0]). In a given
 * channel, AMD always has two instances of a 'chip-select' data structure.
 * While these have a 1:1 correspondence in the case of single and dual rank
 * DIMMs, in the case where there are more, then rank multiplication rules are
 * used to determine which of the additional chip and chip-select signals to
 * actually drive on the bus. But still, there are only up to two of these
 * structures. To match AMD terminology we call these a 'chip-select' or
 * 'umc_cs_t'.
 *
 * The amount of information that exists on a per-chip-select and per-DIMM basis
 * varies between the different memory controller generations. As such, we
 * normalize things such that a given chip-select always has all of the
 * information related to it, duplicating it in the DDR4 case.
 *
 * While DDR5 adds the notion of sub-channels, a single chip-select is used to
 * cover both sub-channels and instead a bit in the normalized address (and
 * hashing) is used to determine which sub-channel to active. So while hardware
 * actually has different chip-select lines for each sub-channel they are not
 * represented that way in the UMC.
 */
typedef struct umc_cs {
	umc_cs_flags_t		ucs_flags;
	umc_dimm_base_t		ucs_base;
	umc_dimm_base_t		ucs_sec;
	uint64_t		ucs_base_mask;
	uint64_t		ucs_sec_mask;
	uint8_t			ucs_nbanks;
	uint8_t			ucs_ncol;
	uint8_t			ucs_nrow_lo;
	uint8_t			ucs_nrow_hi;
	uint8_t			ucs_nrm;
	uint8_t			ucs_nbank_groups;
	uint8_t			ucs_cs_xor;
	uint8_t			ucs_row_hi_bit;
	uint8_t			ucs_row_low_bit;
	uint8_t			ucs_bank_bits[ZEN_UMC_MAX_BANK_BITS];
	uint8_t			ucs_col_bits[ZEN_UMC_MAX_COL_BITS];
	uint8_t			ucs_inv_msbs;
	uint8_t			ucs_rm_bits[ZEN_UMC_MAX_RM_BITS];
	uint8_t			ucs_inv_msbs_sec;
	uint8_t			ucs_rm_bits_sec[ZEN_UMC_MAX_RM_BITS];
	uint8_t			ucs_subchan;
} umc_cs_t;

/*
 * This structure represents information about a DIMM. Most of the interesting
 * stuff is on the umc_cs_t up above, which is the logical 'chip-select' that
 * AMD implements in the UMC.
 *
 * When we come back and add topo glue for the driver, we should consider adding
 * the following information here and in the channel:
 *
 *  o Channel capable speed
 *  o A way to map this DIMM to an SMBIOS / SPD style entry
 */
typedef struct umc_dimm {
	umc_dimm_flags_t	ud_flags;
	umc_dimm_width_t	ud_width;
	umc_dimm_kind_t		ud_kind;
	uint32_t		ud_dimmno;
	uint32_t		ud_dimmcfg_raw;
	uint64_t		ud_dimm_size;
	umc_cs_t		ud_cs[ZEN_UMC_MAX_CS_PER_DIMM];
} umc_dimm_t;

typedef enum umc_chan_flags {
	/*
	 * Indicates that the channel has enabled ECC logic.
	 */
	UMC_CHAN_F_ECC_EN	= 1 << 0,
	/*
	 * We believe that this indicates some amount of the AMD SEV encryption
	 * is ongoing, leveraging some of the page-table control.
	 */
	UMC_CHAN_F_ENCR_EN	= 1 << 1,
	/*
	 * Indicates that the channel is employing data scrambling. This is
	 * basically what folks have called Transparent Shared Memory
	 * Encryption.
	 */
	UMC_CHAN_F_SCRAMBLE_EN	= 1 << 2
} umc_chan_flags_t;

typedef struct umc_bank_hash {
	uint32_t	ubh_row_xor;
	uint32_t	ubh_col_xor;
	boolean_t	ubh_en;
} umc_bank_hash_t;

typedef struct umc_addr_hash {
	uint64_t	uah_addr_xor;
	boolean_t	uah_en;
} umc_addr_hash_t;

typedef struct umc_pc_hash {
	uint32_t	uph_row_xor;
	uint32_t	uph_col_xor;
	uint8_t		uph_bank_xor;
	boolean_t	uph_en;
} umc_pc_hash_t;

typedef enum umc_chan_hash_flags {
	UMC_CHAN_HASH_F_BANK	= 1 << 0,
	UMC_CHAN_HASH_F_RM	= 1 << 1,
	UMC_CHAN_HASH_F_PC	= 1 << 2,
	UMC_CHAN_HASH_F_CS	= 1 << 3,
} umc_chan_hash_flags_t;

typedef struct umc_chan_hash {
	umc_chan_hash_flags_t	uch_flags;
	umc_bank_hash_t		uch_bank_hashes[ZEN_UMC_MAX_CHAN_BANK_HASH];
	umc_addr_hash_t		uch_rm_hashes[ZEN_UMC_MAX_CHAN_RM_HASH];
	umc_addr_hash_t		uch_cs_hashes[ZEN_UMC_MAX_CHAN_CS_HASH];
	umc_pc_hash_t		uch_pc_hash;
} umc_chan_hash_t;

/*
 * This structure represents the overall memory channel. There is a 1:1
 * relationship between these structures and discover UMC hardware entities on
 * the data fabric. Note, these always exist regardless of whether the channels
 * are actually implemented on a PCB or not.
 */
typedef struct zen_umc_chan {
	umc_chan_flags_t	chan_flags;
	uint32_t		chan_fabid;
	uint32_t		chan_instid;
	uint32_t		chan_logid;
	uint32_t		chan_nrules;
	uint32_t		chan_umccfg_raw;
	uint32_t		chan_datactl_raw;
	uint32_t		chan_eccctl_raw;
	uint32_t		chan_umccap_raw;
	uint32_t		chan_umccap_hi_raw;
	uint32_t		chan_np2_raw;
	uint32_t		chan_np2_space0;
	/*
	 * These have the clock and speed of the channel in MHz and MT/s
	 * respectively. These are not always a 1:2 ratio. See the definition
	 * and discussion around D_UMC_DRAMCFG. Note, the channel's speed may
	 * not be the maximum supported speed of a DIMM itself. That requires
	 * going into the SPD data on Zen, the UMC doesn't track it because it
	 * doesn't matter to it. There is one of these for each memory P-state.
	 */
	uint32_t		chan_dramcfg_raw[ZEN_UMC_NMEM_PSTATES];
	uint32_t		chan_clock[ZEN_UMC_NMEM_PSTATES];
	uint32_t		chan_speed[ZEN_UMC_NMEM_PSTATES];
	umc_dimm_type_t		chan_type;
	df_dram_rule_t		chan_rules[ZEN_UMC_MAX_CS_RULES];
	chan_offset_t		chan_offsets[ZEN_UMC_MAX_DRAM_OFFSET];
	umc_dimm_t		chan_dimms[ZEN_UMC_MAX_DIMMS];
	umc_chan_hash_t		chan_hash;
} zen_umc_chan_t;

typedef struct zen_umc_cs_remap {
	uint_t		csr_nremaps;
	uint16_t	csr_remaps[ZEN_UMC_MAX_REMAP_ENTS];
} zen_umc_cs_remap_t;

typedef enum zen_umc_df_flags {
	/*
	 * Indicates that the DRAM Hole is valid and in use.
	 */
	ZEN_UMC_DF_F_HOLE_VALID	= 1 << 0,
	/*
	 * These next three are used to indicate when hashing is going on, which
	 * bits to use. These are for 64K, 2M, and 1G parts of addresses
	 * respectively.
	 */
	ZEN_UMC_DF_F_HASH_16_18	= 1 << 1,
	ZEN_UMC_DF_F_HASH_21_23	= 1 << 2,
	ZEN_UMC_DF_F_HASH_30_32	= 1 << 3
} zen_umc_df_flags_t;

typedef struct zen_umc_df {
	zen_umc_df_flags_t	zud_flags;
	uint_t			zud_dfno;
	uint_t			zud_ccm_inst;
	uint_t			zud_dram_nrules;
	uint_t			zud_nchan;
	uint_t			zud_cs_nremap;
	uint32_t		zud_capab;
	uint32_t		zud_hole_raw;
	uint32_t		zud_glob_ctl_raw;
	uint64_t		zud_hole_base;
	df_dram_rule_t		zud_rules[ZEN_UMC_MAX_DRAM_RULES];
	zen_umc_cs_remap_t	zud_remap[ZEN_UMC_MAX_CS_REMAPS];
	zen_umc_chan_t		zud_chan[ZEN_UMC_MAX_UMCS];
} zen_umc_df_t;

typedef enum zen_umc_umc_style {
	/*
	 * These are UMCs that generally implement the basic DDR4 UMC found in
	 * Zen 1-3 systems. The APU variant does not support multiple banks.
	 */
	ZEN_UMC_UMC_S_DDR4,
	ZEN_UMC_UMC_S_DDR4_APU,
	/*
	 * This represents a slightly different UMC design that exists in Van
	 * Gogh and Mendocino. In particular, it primarily supports LPDDR5 but
	 * is an extension of the DDR4 UMC in some respects such as the
	 * DramConfiguration register, but otherwise looks more like the DDR5
	 * case.
	 */
	ZEN_UMC_UMC_S_HYBRID_LPDDR5,
	/*
	 * These are UMCs that generally implement the basic DDR5 UMC found in
	 * Zen 4+ (and other) systems. The APU variant does not support multiple
	 * banks.
	 */
	ZEN_UMC_UMC_S_DDR5,
	ZEN_UMC_UMC_S_DDR5_APU
} zen_umc_umc_style_t;

typedef enum zen_umc_fam_flags {
	/*
	 * Indicates that there's an indirection table for the destinations of
	 * target rules. This is only required to be set explicitly for systems
	 * prior to the DF 4D2 variant as after that remapping support is
	 * indicated in the DF::DfCapability register.
	 */
	ZEN_UMC_FAM_F_TARG_REMAP	= 1 << 0,
	/*
	 * Indicates that non-power of two interleave rules are supported and
	 * that we need additional register configuration.
	 */
	ZEN_UMC_FAM_F_NP2		= 1 << 1,
	/*
	 * Indicates that the DF hashing rules to configure COD hashes need to
	 * be checked.
	 */
	ZEN_UMC_FAM_F_NORM_HASH		= 1 << 2,
	/*
	 * In DDR4 this indicates presence of the HashRM and in DDR5 the
	 * AddrHash.
	 */
	ZEN_UMC_FAM_F_UMC_HASH		= 1 << 3,
	/*
	 * Indicates support for extended UMC registers for larger addresses.
	 * Generally on Server parts. This should only be set if there are
	 * non-reserved bits in the register.
	 */
	ZEN_UMC_FAM_F_UMC_EADDR		= 1 << 4,
	/*
	 * Indicates that CS decoder supports an XOR function.
	 */
	ZEN_UMC_FAM_F_CS_XOR		= 1 << 5
} zen_umc_fam_flags_t;

/*
 * This structure is meant to contain per SoC family (not CPUID family)
 * information. This is stuff that we basically need to encode about the
 * processor itself and relates to its limits, the style it operates in, the
 * way it works, etc.
 */
typedef struct zen_umc_fam_data {
	x86_processor_family_t	zufd_family;
	zen_umc_fam_flags_t	zufd_flags;
	uint8_t			zufd_dram_nrules;
	uint8_t			zufd_cs_nrules;
	zen_umc_umc_style_t	zufd_umc_style;
	umc_chan_hash_flags_t	zufd_chan_hash;
	uint32_t		zufd_base_instid;
} zen_umc_fam_data_t;

/*
 * The top-level data structure for the system. This is a single structure that
 * represents everything that could possibly exist and is filled in with what we
 * actually discover.
 */
typedef struct zen_umc {
	uint64_t umc_tom;
	uint64_t umc_tom2;
	dev_info_t *umc_dip;
	x86_processor_family_t umc_family;
	df_rev_t umc_df_rev;
	const zen_umc_fam_data_t *umc_fdata;
	df_fabric_decomp_t umc_decomp;
	uint_t umc_ndfs;
	zen_umc_df_t umc_dfs[ZEN_UMC_MAX_DFS];
	/*
	 * This lock protects the data underneath here.
	 */
	kmutex_t umc_nvl_lock;
	nvlist_t *umc_decoder_nvl;
	char *umc_decoder_buf;
	size_t umc_decoder_len;
} zen_umc_t;

typedef enum zen_umc_decode_failure {
	ZEN_UMC_DECODE_F_NONE = 0,
	/*
	 * Indicates that the address was not contained within the TOM and TOM2
	 * regions that indicate DRAM (or was in a reserved hole).
	 */
	ZEN_UMC_DECODE_F_OUTSIDE_DRAM,
	/*
	 * Indicates that we could not find a DF rule in the CCM rule that
	 * claims to honor this address.
	 */
	ZEN_UMC_DECODE_F_NO_DF_RULE,
	/*
	 * Indicates that trying to construct the interleave address to use
	 * would have led to an underflow somehow.
	 */
	ZEN_UMC_DECODE_F_ILEAVE_UNDERFLOW,
	/*
	 * Indicates that we do not currently support decoding the indicated
	 * channel interleave type.
	 */
	ZEN_UMC_DECODE_F_CHAN_ILEAVE_NOTSUP,
	/*
	 * Indicates that we found a COD hash rule that had a non-zero socket or
	 * die interleave, which isn't supported and we don't know how to
	 * decode.
	 */
	ZEN_UMC_DECODE_F_COD_BAD_ILEAVE,
	/*
	 * This is similar to the above, but indicates that we hit a bad NPS
	 * interleave rule instead of a COD.
	 */
	ZEN_UMC_DECODE_F_NPS_BAD_ILEAVE,
	/*
	 * Indicates that somehow we thought we should use a remap rule set that
	 * was beyond our capabilities.
	 */
	ZEN_UMC_DECODE_F_BAD_REMAP_SET,
	/*
	 * Indicates that we tried to find an index for the remap rules;
	 * however, the logical component ID was outside the range of the number
	 * of entries that we have.
	 */
	ZEN_UMC_DECODE_F_BAD_REMAP_ENTRY,
	/*
	 * Indicates that the remap rule had an invalid component bit set in its
	 * mask.
	 */
	ZEN_UMC_DECODE_F_REMAP_HAS_BAD_COMP,
	/*
	 * Indicates that we could not find a UMC with the fabric ID we thought
	 * we should have.
	 */
	ZEN_UMC_DECODE_F_CANNOT_MAP_FABID,
	/*
	 * Indicates that somehow the UMC we found did not actually contain a
	 * DRAM rule that covered our original PA.
	 */
	ZEN_UMC_DECODE_F_UMC_DOESNT_HAVE_PA,
	/*
	 * Indicates that we would have somehow underflowed the address
	 * calculations normalizing the system address.
	 */
	ZEN_UMC_DECODE_F_CALC_NORM_UNDERFLOW,
	/*
	 * Indicates that none of the UMC's chip-selects actually matched a base
	 * or secondary.
	 */
	ZEN_UMC_DECODE_F_NO_CS_BASE_MATCH,
} zen_umc_decode_failure_t;

/*
 * This struct accumulates all of our decoding logic and states and we use it so
 * it's easier for us to look at what's going on and the decisions that we made
 * along the way.
 */
typedef struct zen_umc_decoder {
	zen_umc_decode_failure_t	dec_fail;
	uint64_t			dec_fail_data;
	uint64_t			dec_pa;
	const zen_umc_df_t		*dec_df_rulesrc;
	uint32_t			dec_df_ruleno;
	const df_dram_rule_t		*dec_df_rule;
	uint64_t			dec_ilv_pa;
	/*
	 * These three values represent the IDs that we extract from the
	 * interleave address.
	 */
	uint32_t			dec_ilv_sock;
	uint32_t			dec_ilv_die;
	uint32_t			dec_ilv_chan;
	uint32_t			dec_ilv_fabid;
	uint32_t			dec_log_fabid;
	uint32_t			dec_remap_comp;
	uint32_t			dec_targ_fabid;
	const zen_umc_chan_t		*dec_umc_chan;
	uint32_t			dec_umc_ruleno;
	uint64_t			dec_norm_addr;
	const umc_dimm_t		*dec_dimm;
	const umc_cs_t			*dec_cs;
	boolean_t			dec_cs_sec;
	uint32_t			dec_dimm_col;
	uint32_t			dec_dimm_row;
	uint8_t				dec_log_csno;
	uint8_t				dec_dimm_bank;
	uint8_t				dec_dimm_bank_group;
	uint8_t				dec_dimm_subchan;
	uint8_t				dec_dimm_rm;
	uint8_t				dec_chan_csno;
	uint8_t				dec_dimm_no;
	uint8_t				dec_dimm_csno;
} zen_umc_decoder_t;

/*
 * Decoding and normalization routines.
 */
extern boolean_t zen_umc_decode_pa(const zen_umc_t *, const uint64_t,
    zen_umc_decoder_t *);

/*
 * Encoding and decoding
 */
extern nvlist_t *zen_umc_dump_decoder(zen_umc_t *);
extern boolean_t zen_umc_restore_decoder(nvlist_t *, zen_umc_t *);

#ifdef __cplusplus
}
#endif

#endif /* _ZEN_UMC_H */
