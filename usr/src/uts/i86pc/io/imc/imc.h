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

#ifndef _INTEL_IMC_H
#define	_INTEL_IMC_H

#include <sys/types.h>
#include <sys/bitmap.h>
#include <sys/list.h>
#include <sys/sunddi.h>

/*
 * This header file contains the definitions used for the various generations of
 * the Intel IMC driver.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The maximum number of sockets that the IMC driver supports. This is currently
 * determined by the Purley platforms (Skylake) which support up to 8 CPUs.
 */
#define	IMC_MAX_SOCKETS		8

/*
 * The maximum number of memory controllers that exist per socket. Currently all
 * supported platforms (Sandy Bridge -> Skylake) support at most two.
 */
#define	IMC_MAX_IMCPERSOCK	2

/*
 * The maximum number of channels that exist per IMC. Currently Skylake supports
 * 3 per IMC. On certain configurations of Haswell/Broadwell, there is only a
 * single IMC which supports all 4 channels.
 */
#define	IMC_MAX_CHANPERMC	4

/*
 * The maximum number of DIMMs that exist per channel. On Skylake this is two
 * DIMMs. However, Sandy Bridge through Broadwell support three.
 */
#define	IMC_MAX_DIMMPERCHAN	3

/*
 * The maximum number of rank disable bits per DIMM. This is currently
 * consistent across all generations that have these bits.
 */
#define	IMC_MAX_RANK_DISABLE	4

/*
 * The number of different PCI buses that we need to record for a given
 * platform. Pre-Skylake there are only two that are required, one for the IIO
 * and one for the non-IIO. On Skylake, more PCI buses are used.
 */
#define	IMC_MAX_PCIBUSES	3

/*
 * Macros to take apart the node id for a given processor. These assume that
 * we're reading the nodeid from the UBox and not from the SAD control.
 */
#define	IMC_NODEID_UBOX_MASK(x)		((x) & 0x7)

/*
 * On Ivy Bridge through Broadwell, the node id that is found in the SAD targets
 * has the HA indicator as NodeID[2]. This means that the actual target node of
 * the socket is NodeID[3] | NodeID[1:0].
 */
#define	IMC_NODEID_IVY_BRD_UPPER(x)	BITX(x, 3, 3)
#define	IMC_NODEID_IVY_BRD_LOWER(x)	BITX(x, 1, 0)
#define	IMC_NODEID_IVY_BRD_HA(x)	BITX(x, 2, 2)

/*
 * Macros to take apart the MCMTR register bits that we care about.
 */
#define	IMC_MCMTR_CLOSED_PAGE(x)	BITX(x, 0, 0)
#define	IMC_MCMTR_LOCKSTEP(x)		BITX(x, 1, 1)
#define	IMC_MCMTR_ECC_ENABLED(x)	BITX(x, 2, 2)

#define	IMC_MCMTR_DDR4_HAS_BRD(x)	BITX(x, 14, 14)

/*
 * Macros to take apart the dimmmtr_* registers in different generations. While
 * there are similarities, these often end up different between generations and
 * chips. These macros use a range of CPUs that they're valid for in the name.
 * Macros with no suffix are valid for all currently supported CPUs.
 */

#define	IMC_REG_MC_MTR0		0x80
#define	IMC_REG_MC_MTR1		0x84
#define	IMC_REG_MC_MTR2		0x88

#define	IMC_MTR_CA_WIDTH(x)	BITX(x, 1, 0)
#define	IMC_MTR_CA_BASE		10
#define	IMC_MTR_CA_MIN		10
#define	IMC_MTR_CA_MAX		12

#define	IMC_MTR_RA_WIDTH(x)	BITX(x, 4, 2)
#define	IMC_MTR_RA_BASE		12
#define	IMC_MTR_RA_MIN		13
#define	IMC_MTR_RA_MAX		18

#define	IMC_MTR_DENSITY_IVY_BRD(x)	BITX(x, 6, 5)
#define	IMC_MTR_DENSITY_SKX(x)		BITX(x, 7, 5)

#define	IMC_MTR_WIDTH_IVB_HAS(x)	BITX(x, 8, 7)
#define	IMC_MTR_WIDTH_BRD_SKX(x)	BITX(x, 9, 8)

#define	IMC_MTR_DDR_RANKS(x)		BITX(x, 13, 12)
#define	IMC_MTR_DDR_RANKS_MAX		4
#define	IMC_MTR_DDR_RANKS_MAX_HAS_SKX	8

#define	IMC_MTR_PRESENT_SNB_BRD(x)	BITX(x, 14, 14)
#define	IMC_MTR_PRESENT_SKYLAKE(x)	BITX(x, 15, 15)

#define	IMC_MTR_RANK_DISABLE(x)		BITX(x, 19, 16)

#define	IMC_MTR_DDR4_ENABLE_HAS_BRD(x)	BITX(x, 20, 20)
#define	IMC_MTR_HDRL_HAS_SKX(x)		BITX(x, 21, 21)
#define	IMC_MTR_HDRL_PARITY_HAS_SKX(x)	BITX(x, 22, 22)
#define	IMC_MTR_3DSRANKS_HAS_SKX(x)	BITX(x, 24, 23)

/*
 * Data for the RASENABLES register.
 */
#define	IMC_MC_MIRROR_SNB_BRD(x)	BITX(x, 0, 0)

/*
 * The maximum number of SAD rules that exist on all supported platforms.
 */
#define	IMC_MAX_SAD_RULES	24

/*
 * The maximum number of targets that can be interleaved in a sad rule.
 */
#define	IMC_MAX_SAD_INTERLEAVE	8

/*
 * The maximum number of route entries that exist in SAD. This is only used on
 * SKX.
 */
#define	IMC_MAX_SAD_MCROUTES	6

/*
 * Definitions used to decode the MC Route table. Note that at this time this is
 * very Skylake specific (as it's the only platform it's supported on).
 */
#define	IMC_REG_SKX_SAD_MC_ROUTE_TABLE	0xb4
#define	IMC_MC_ROUTE_RING_BITS		3
#define	IMC_MC_ROUTE_RING_MASK		0x7
#define	IMC_MC_ROUTE_CHAN_BITS		2
#define	IMC_MC_ROUTE_CHAN_MASK		0x3
#define	IMC_MC_ROUTE_CHAN_OFFSET	18

/*
 * Definitions to help decode TOLM (top of low memory) and TOHM (top of high
 * memory). The way this is done varies based on generation. These regions are
 * currently always 64-MByte aligned
 *
 * On Sandy Bridge and Ivy Bridge the low four bits of TOLM are bits 31:28. TOHM
 * is a single register. Bits 20:0 map to bits 45:25. Both registers represent
 * the upper limit (as in one higher than the max DRAM value).
 *
 * On Haswell through Skylake, TOLM is represented as a 32-bit quantity. No
 * shifting is required. However, only bits 31:26 are present. TOHM is spread
 * out among two registers. The lower 32-bits is masked in a similar fashion. In
 * both cases, these registers represent an inclusive range where we don't care
 * about other bits. To deal with this we'll increment the lowest bit we care
 * about to make it an exclusive range.
 *
 * Based on the above, we have opted to make both ranges in the IMC driver
 * normalized to an _exclusive_ value.
 *
 * Ivy Bridge has the values in both the CBo SAD and a VT-d section; however, we
 * use the CBo SAD which is why it looks like Sandy Bridge and not Haswell.
 */

#define	IMC_TOLM_SNB_IVY_MASK		0xf
#define	IMC_TOLM_SNB_IVY_SHIFT		28
#define	IMC_TOHM_SNB_IVY_MASK		0x1fffff
#define	IMC_TOHM_SNB_IVY_SHIFT		25

#define	IMC_TOLM_HAS_SKX_MASK		0xfc000000
#define	IMC_TOLM_HAS_SKY_EXCL		(1 << 26)
#define	IMC_TOHM_LOW_HAS_SKX_MASK	0xfc000000
#define	IMC_TOHM_HAS_SKY_EXCL		(1 << 26)

/*
 * Definitions to decode SAD values. These are sometimes subtlety different
 * across generations.
 */
#define	IMC_SAD_DRAM_RULE_ENABLE(x)		BITX(x, 0, 0)

#define	IMC_SAD_DRAM_INTERLEAVE_SNB_BRD(x)	BITX(x, 1, 1)
#define	IMC_SAD_DRAM_INTERLEAVE_SNB_BRD_8t6XOR	0
#define	IMC_SAD_DRAM_INTERLEAVE_SNB_BRD_8t6	1

#define	IMC_SAD_DRAM_INTERLEAVE_SKX(x)		BITX(x, 2, 1)
#define	IMC_SAD_DRAM_INTERLEAVE_SKX_8t6		0
#define	IMC_SAD_DRAM_INTERLEAVE_SKX_10t8	1
#define	IMC_SAD_DRAM_INTERLEAVE_SKX_14t12	2
#define	IMC_SAD_DRAM_INTERLEAVE_SKX_32t30	3

#define	IMC_SAD_DRAM_ATTR_SNB_BRD(x)		BITX(x, 3, 2)
#define	IMC_SAD_DRAM_ATTR_SKX(x)		BITX(x, 4, 3)
#define	IMC_SAD_DRAM_ATTR_DRAM			0
#define	IMC_SAD_DRAM_ATTR_MMCFG			1
#define	IMC_SAD_DRAM_ATTR_NXM			2

#define	IMC_SAD_DRAM_MOD23_SKX(x)		BITX(x, 6, 5)
#define	IMC_SAD_DRAM_MOD23_MOD3			0
#define	IMC_SAD_DRAM_MOD23_MOD2_C01		1
#define	IMC_SAD_DRAM_MOD23_MOD2_C12		2
#define	IMC_SAD_DRAM_MOD23_MOD2_C02		3

#define	IMC_SAD_DRAM_LIMIT_SNB_BRD(x)		BITX(x, 25, 6)
#define	IMC_SAD_DRAM_LIMIT_SKX(x)		BITX(x, 26, 7)
#define	IMC_SAD_DRAM_LIMIT_SHIFT		26
#define	IMC_SAD_DRAM_LIMIT_EXCLUSIVE		(1 << IMC_SAD_DRAM_LIMIT_SHIFT)

#define	IMC_SAD_DRAM_A7_IVB_BRD(x)		BITX(x, 26, 26)
#define	IMC_SAD_DRAM_MOD3_SKX(x)		BITX(x, 27, 27)
#define	IMC_SAD_DRAM_MOD3_MODE_SKX(x)		BITX(x, 31, 30)
#define	IMC_SAD_DRAM_MOD3_MODE_45t6		0
#define	IMC_SAD_DRAM_MOD3_MODE_45t8		1
#define	IMC_SAD_DRAM_MOD3_MODE_45t12		2

#define	IMC_SAD_ILEAVE_SNB_MASK			0x7
#define	IMC_SAD_ILEAVE_SNB_LEN			3
#define	IMC_SAD_ILEAVE_IVB_SKX_MASK		0xf
#define	IMC_SAD_ILEAVE_IVB_SKX_LEN		4

/*
 * The interleave targets on Skylake use the upper bit to indicate whether it is
 * referring to a local memory controller or if it actually refers to another
 * node that is far away. The maximum value includes the upper bit which is used
 * to indicate whether it is remote or far.
 */
#define	IMC_SAD_ILEAVE_SKX_LOCAL(x)		BITX(x, 3, 3)
#define	IMC_SAD_ILEAVE_SKX_TARGET(x)		BITX(x, 2, 0)
#define	IMC_SAD_ILEAVE_SKX_MAX			0xf

/*
 * Maximum number of TAD tables that we need to consider. On Sandy Bridge
 * through Broadwell this is based on the number of home agents that are present
 * in the system. On Sandy Bridge there is one, on others, there are up to two.
 * On Skylake, there is one TAD per IMC.
 */
#define	IMC_MAX_TAD	2

/*
 * Maximum number of TAD rules on any of the supported processors.
 */
#define	IMC_MAX_TAD_RULES	12

/*
 * Maximum number of interleave targets. Note, this only applies to Sandy Bridge
 * through Broadwell. Skylake gets this information in another form.
 */
#define	IMC_MAX_TAD_TARGETS	4

/*
 * Offset between the base TAD rule and the corresponding wayness rule on
 * Skylake.
 */
#define	IMC_SKX_WAYNESS_OFFSET	0x30

/*
 * Various macros to decode the TAD rules.
 */
#define	IMC_TAD_LIMIT(x)		BITX(x, 31, 12)
#define	IMC_TAD_LIMIT_SHIFT		26
#define	IMC_TAD_LIMIT_EXCLUSIVE		(1 << IMC_TAD_LIMIT_SHIFT)

#define	IMC_TAD_SOCK_WAY(x)		BITX(x, 11, 10)
#define	IMC_TAD_SOCK_WAY_1		0
#define	IMC_TAD_SOCK_WAY_2		1
#define	IMC_TAD_SOCK_WAY_4		2
#define	IMC_TAD_SOCK_WAY_8		3
#define	IMC_TAD_CHAN_WAY(x)		BITX(x, 9, 8)
#define	IMC_TAD_TARG3(x)		BITX(x, 7, 6)
#define	IMC_TAD_TARG2(x)		BITX(x, 5, 4)
#define	IMC_TAD_TARG1(x)		BITX(x, 3, 2)
#define	IMC_TAD_TARG0(x)		BITX(x, 1, 0)

#define	IMC_TAD_SNB_BRD_NTARGETS	4

/*
 * These are registers specific to the Skylake and newer TAD BASE registers.
 */
#define	IMC_TAD_BASE_BASE(x)		BITX(x, 31, 12)
#define	IMC_TAD_BASE_SHIFT		26

#define	IMC_TAD_BASE_CHAN_GRAN(x)	BITX(x, 7, 6)
#define	IMC_TAD_BASE_CHAN_GRAN_64B	0
#define	IMC_TAD_BASE_CHAN_GRAN_256B	1
#define	IMC_TAD_BASE_CHAN_GRAN_4KB	2

#define	IMC_TAD_BASE_SOCK_GRAN(x)	BITX(x, 5, 4)
#define	IMC_TAD_BASE_SOCK_GRAN_64B	0
#define	IMC_TAD_BASE_SOCK_GRAN_256B	1
#define	IMC_TAD_BASE_SOCK_GRAN_4KB	2
#define	IMC_TAD_BASE_SOCK_GRAN_1GB	3

#define	IMC_TADCHAN_OFFSET_SNB_BRD(x)	BITX(x, 25, 6)
#define	IMC_TADCHAN_OFFSET_SKX(x)	BITX(x, 23, 4)
#define	IMC_TADCHAN_OFFSET_SHIFT	26

/*
 * Macros to get at various TAD features.
 */
#define	IMC_TAD_SYSDEF_LOCKSTEP(x)	BITX(x, 7, 7)
#define	IMC_TAD_SYSDEF2_SHIFTUP(x)	BITX(x, 22, 22)
#define	IMC_TAD_SYSDEF2_CHANHASH(x)	BITX(x, 21, 21)

/*
 * Maximum number of different wayness entries that exist across the various IMC
 * generations. Each wayness then has a maximum number of target entries.
 */
#define	IMC_MAX_RANK_WAYS		5
#define	IMC_MAX_RANK_INTERLEAVES	8

/*
 * Macros to take apart the rank interleave wayness and offset registers.
 */
#define	IMC_RIR_WAYNESS_ENABLED(x)	BITX(x, 31, 31)
#define	IMC_RIR_WAYNESS_WAY(x)		BITX(x, 29, 28)
#define	IMC_RIR_LIMIT_HAS_SKX(x)	BITX(x, 11, 1)
#define	IMC_RIR_LIMIT_SNB_IVB(x)	BITX(x, 10, 1)
#define	IMC_RIR_LIMIT_SHIFT		29
#define	IMC_RIR_LIMIT_EXCLUSIVE		(1 << IMC_RIR_LIMIT_SHIFT)

/*
 * Currently, everything other than Broadwell has the same value for the target
 * offset.
 */
#define	IMC_RIR_OFFSET_TARGET_BRD(x)		BITX(x, 23, 20)
#define	IMC_RIR_OFFSET_TARGET(x)		BITX(x, 19, 16)
#define	IMC_RIR_OFFSET_OFFSET_HAS_SKX(x)	BITX(x, 15, 2)
#define	IMC_RIR_OFFSET_OFFSET_SNB_IVB(x)	BITX(x, 14, 2)
#define	IMC_RIR_OFFSET_SHIFT			29

/*
 * Definitions to cover manipulations of open and closed pages.
 */
#define	IMC_PAGE_BITS_CLOSED	6
#define	IMC_PAGE_BITS_OPEN	13

/*
 * Macros to decode and understand the CPUBUSNO registers in the UBOX_DECS.
 */
#define	IMC_UBOX_CPUBUSNO_0(x)			BITX(x, 7, 0)
#define	IMC_UBOX_CPUBUSNO_1(x)			BITX(x, 15, 8)
#define	IMC_UBOX_CPUBUSNO_2(x)			BITX(x, 23, 16)

/*
 * Hardware generations supported by the IMC driver.
 */
typedef enum {
	IMC_GEN_UNKNOWN = 0,
	IMC_GEN_SANDY,
	IMC_GEN_IVY,
	IMC_GEN_HASWELL,
	IMC_GEN_BROADWELL,
	/*
	 * IMC_GEN_SKYLAKE also covers Cascade Lake. The two are similar to the
	 * point of even having the same PCI IDs for all of the devices. The
	 * only difference in the cpuid signature between them is the stepping,
	 * hence we do not have a separate Cascade Lake target here, as it's
	 * really the same as Skylake.
	 */
	IMC_GEN_SKYLAKE
} imc_gen_t;

/*
 * Generation specific limits.
 */
typedef struct imc_gen_data {
	uint_t	igd_max_sockets;
	uint_t	igd_max_imcs;
	uint_t	igd_max_channels;
	uint_t	igd_max_dimms;
	uint_t	igd_max_ranks;
	uint_t	igd_mtr_offsets[IMC_MAX_DIMMPERCHAN];
	uint_t	igd_mcmtr_offset;
	uint_t	igd_topo_offset;
	uint_t	igd_num_mcroutes;
	uint_t	igd_tolm_offset;
	uint_t	igd_tohm_low_offset;
	uint_t	igd_tohm_hi_offset;
	uint_t	igd_sad_dram_offset;
	uint_t	igd_sad_ndram_rules;
	uint_t	igd_sad_nodeid_offset;
	uint_t	igd_tad_nrules;
	uint_t	igd_tad_rule_offset;
	uint_t	igd_tad_chan_offset;
	uint_t	igd_tad_sysdef;
	uint_t	igd_tad_sysdef2;
	uint_t	igd_mc_mirror;
	uint_t	igd_rir_nways;
	uint_t	igd_rir_way_offset;
	uint_t	igd_rir_nileaves;
	uint_t	igd_rir_ileave_offset;
	uint_t	igd_ubox_cpubusno_offset;
} imc_gen_data_t;

/*
 * Different types of PCI devices that show up on the core that we may need to
 * attach to.
 */
typedef enum {
	IMC_TYPE_UNKNOWN = 0,
	IMC_TYPE_MC0_M2M,	/* SKX Only */
	IMC_TYPE_MC1_M2M,	/* SKX Only */
	IMC_TYPE_MC0_MAIN0,
	IMC_TYPE_MC0_MAIN1,
	IMC_TYPE_MC1_MAIN0,
	IMC_TYPE_MC1_MAIN1,
	IMC_TYPE_MC0_CHANNEL0,
	IMC_TYPE_MC0_CHANNEL1,
	IMC_TYPE_MC0_CHANNEL2,
	IMC_TYPE_MC0_CHANNEL3,
	IMC_TYPE_MC1_CHANNEL0,
	IMC_TYPE_MC1_CHANNEL1,
	IMC_TYPE_MC1_CHANNEL2,
	IMC_TYPE_MC1_CHANNEL3,
	IMC_TYPE_SAD_DRAM,
	IMC_TYPE_SAD_MMIO,
	/*
	 * We want to note which device has the TOLM and TOHM registers.
	 * Unfortunately this is a rather complicated affair. On Sandy Bridge
	 * they are a part of the IMC_TYPE_SAD_MMIO. On Ivy Bridge, it's on its
	 * own dedicated device on the CBo.
	 *
	 * On Haswell onward, these move to the VT-D misc. registers. On Haswell
	 * and Broadwell, only one of these exist in the system. However, on
	 * Skylake these exist per socket.
	 */
	IMC_TYPE_SAD_MISC,
	IMC_TYPE_VTD_MISC,
	/*
	 * On SKX this exists on a per-core basis. It contains the memory
	 * controller routing table.
	 */
	IMC_TYPE_SAD_MCROUTE,
	IMC_TYPE_UBOX,
	IMC_TYPE_UBOX_CPUBUSNO,
	IMC_TYPE_HA0,
	IMC_TYPE_HA1,
} imc_type_t;

/*
 * Each entry in the stub table represents a device that we might attach to in a
 * given generation. This is only defined in the kernel to make it easier to
 * build the imc decoder in userland for testing.
 */
#ifdef	_KERNEL
typedef struct imc_stub_table {
	imc_gen_t	imcs_gen;
	imc_type_t	imcs_type;
	uint16_t	imcs_devid;
	uint16_t	imcs_pcidev;
	uint16_t	imcs_pcifunc;
	const char	*imcs_desc;
} imc_stub_table_t;

typedef struct imc_stub {
	avl_node_t		istub_link;
	dev_info_t		*istub_dip;
	uint16_t		istub_vid;
	uint16_t		istub_did;
	uint16_t		istub_bus;
	uint16_t		istub_dev;
	uint16_t		istub_func;
	ddi_acc_handle_t	istub_cfgspace;
	const imc_stub_table_t	*istub_table;
} imc_stub_t;
#else
typedef struct imc_stub {
	void	*istub_unused;
} imc_stub_t;
#endif	/* _KERNEL */

typedef enum {
	IMC_F_UNSUP_PLATFORM	= (1 << 0),
	IMC_F_SCAN_DISPATCHED	= (1 << 1),
	IMC_F_SCAN_COMPLETE	= (1 << 2),
	IMC_F_ATTACH_DISPATCHED	= (1 << 3),
	IMC_F_ATTACH_COMPLETE	= (1 << 4),
	IMC_F_MCREG_FAILED	= (1 << 5)
} imc_flags_t;

#define	IMC_F_ALL_FLAGS	(IMC_F_UNSUP_PLATFORM | IMC_F_SCAN_DISPATCHED | \
    IMC_F_SCAN_COMPLETE | IMC_F_ATTACH_DISPATCHED | IMC_F_ATTACH_COMPLETE | \
    IMC_F_MCREG_FAILED)

typedef enum imc_dimm_type {
	IMC_DIMM_UNKNOWN,
	IMC_DIMM_DDR3,
	IMC_DIMM_DDR4,
	IMC_DIMM_NVDIMM
} imc_dimm_type_t;

typedef enum imc_dimm_valid {
	IMC_DIMM_V_VALID	= 0,
	IMC_DIMM_V_BAD_PCI_READ	= (1 << 0),
	IMC_DIMM_V_BAD_ROWS	= (1 << 1),
	IMC_DIMM_V_BAD_COLUMNS	= (1 << 2),
	IMC_DIMM_V_BAD_DENSITY	= (1 <<	3),
	IMC_DIMM_V_BAD_WIDTH	= (1 << 4),
	IMC_DIMM_V_BAD_RANKS	= (1 << 5)
} imc_dimm_valid_t;

typedef struct imc_dimm {
	imc_dimm_valid_t	idimm_valid;
	boolean_t	idimm_present;
	uint8_t		idimm_3dsranks;
	boolean_t	idimm_hdrl_parity;
	boolean_t	idimm_hdrl;
	boolean_t	idimm_ranks_disabled[IMC_MAX_RANK_DISABLE];
	uint8_t		idimm_nbanks;
	uint8_t		idimm_nranks;
	uint8_t		idimm_width;
	uint8_t		idimm_density; /* In GiB */
	uint8_t		idimm_nrows;
	uint8_t		idimm_ncolumns;
	/* Synthesized */
	uint64_t	idimm_size;
	/* Raw data */
	uint32_t	idimm_mtr;
} imc_dimm_t;

typedef struct imc_rank_ileave_entry {
	uint8_t		irle_target;
	uint64_t	irle_offset;
} imc_rank_ileave_entry_t;

typedef struct imc_rank_ileave {
	boolean_t		irle_enabled;
	uint32_t		irle_raw;
	uint8_t			irle_nways;
	uint8_t			irle_nwaysbits;
	uint64_t		irle_limit;
	uint_t			irle_nentries;
	imc_rank_ileave_entry_t	irle_entries[IMC_MAX_RANK_INTERLEAVES];
} imc_rank_ileave_t;

typedef enum imc_channel_valid {
	IMC_CHANNEL_V_VALID		= 0,
	IMC_CHANNEL_V_BAD_PCI_READ	= 1 << 0,
} imc_channel_valid_t;

typedef struct imc_channel {
	imc_channel_valid_t	ich_valid;
	imc_stub_t		*ich_desc;
	uint_t			ich_ndimms;
	imc_dimm_t		ich_dimms[IMC_MAX_DIMMPERCHAN];
	uint_t			ich_ntad_offsets;
	uint32_t		ich_tad_offsets_raw[IMC_MAX_TAD_RULES];
	uint64_t		ich_tad_offsets[IMC_MAX_TAD_RULES];
	uint_t			ich_nrankileaves;
	imc_rank_ileave_t	ich_rankileaves[IMC_MAX_RANK_WAYS];
} imc_channel_t;

typedef struct imc_controller {
	imc_stub_t	*icn_main0;
	imc_stub_t	*icn_main1;
	imc_stub_t	*icn_m2m;
	boolean_t	icn_invalid;
	imc_dimm_type_t	icn_dimm_type;
	boolean_t	icn_ecc;
	boolean_t	icn_lockstep;
	boolean_t	icn_closed;
	uint32_t	icn_topo;
	uint_t		icn_nchannels;
	imc_channel_t	icn_channels[IMC_MAX_CHANPERMC];
} imc_mc_t;

typedef enum imc_sad_rule_type {
	IMC_SAD_TYPE_DRAM,
	IMC_SAD_TYPE_MMCFG,
	IMC_SAD_TYPE_NXM
} imc_sad_rule_type_t;

typedef enum imc_sad_rule_imode {
	IMC_SAD_IMODE_8t6,
	IMC_SAD_IMODE_8t6XOR,
	IMC_SAD_IMODE_10t8,
	IMC_SAD_IMODE_14t12,
	IMC_SAD_IMODE_32t30
} imc_sad_rule_imode_t;

typedef enum imc_sad_rule_mod_mode {
	IMC_SAD_MOD_MODE_NONE,
	IMC_SAD_MOD_MODE_45t6,
	IMC_SAD_MOD_MODE_45t8,
	IMC_SAD_MOD_MODE_45t12
} imc_sad_rule_mod_mode_t;

typedef enum imc_sad_rule_mod_type {
	IMC_SAD_MOD_TYPE_NONE,
	IMC_SAD_MOD_TYPE_MOD3,
	IMC_SAD_MOD_TYPE_MOD2_01,
	IMC_SAD_MOD_TYPE_MOD2_12,
	IMC_SAD_MOD_TYPE_MOD2_02
} imc_sad_rule_mod_type_t;

typedef struct imc_sad_mcroute_entry {
	uint8_t	ismce_imc;		/* ID of the target IMC */
	uint8_t	ismce_pchannel;		/* ID of the target physical channel */
} imc_sad_mcroute_entry_t;

typedef struct imc_sad_mcroute_table {
	uint32_t		ismc_raw_mcroute;
	uint_t			ismc_nroutes;
	imc_sad_mcroute_entry_t	ismc_mcroutes[IMC_MAX_SAD_MCROUTES];
} imc_sad_mcroute_table_t;

/*
 * This rule represents a single SAD entry.
 */
typedef struct imc_sad_rule {
	uint32_t		isr_raw_dram;
	uint32_t		isr_raw_interleave;
	boolean_t		isr_enable;
	boolean_t		isr_a7mode;
	boolean_t		isr_need_mod3;
	uint64_t		isr_limit;
	imc_sad_rule_type_t	isr_type;
	imc_sad_rule_imode_t	isr_imode;
	imc_sad_rule_mod_mode_t	isr_mod_mode;
	imc_sad_rule_mod_type_t	isr_mod_type;
	uint_t			isr_ntargets;
	uint8_t			isr_targets[IMC_MAX_SAD_INTERLEAVE];
} imc_sad_rule_t;

typedef enum imc_sad_flags {
	IMC_SAD_MCROUTE_VALID	= 1 << 0,
} imc_sad_flags_t;

typedef enum imc_sad_valid {
	IMC_SAD_V_VALID		= 0,
	IMC_SAD_V_BAD_PCI_READ	= 1 << 0,
	IMC_SAD_V_BAD_MCROUTE	= 1 << 1,
	IMC_SAD_V_BAD_DRAM_ATTR	= 1 << 2,
	IMC_SAD_V_BAD_MOD3	= 1 << 3,
} imc_sad_valid_t;

typedef struct imc_sad {
	imc_sad_flags_t	isad_flags;
	imc_sad_valid_t	isad_valid;
	imc_stub_t	*isad_dram;
	imc_stub_t	*isad_mmio;
	imc_stub_t	*isad_tolh;
	uint64_t	isad_tolm;
	uint64_t	isad_tohm;
	uint_t		isad_nrules;
	imc_sad_rule_t	isad_rules[IMC_MAX_SAD_RULES];
	imc_sad_mcroute_table_t isad_mcroute;
} imc_sad_t;

typedef enum imc_tad_gran {
	IMC_TAD_GRAN_64B = 0,
	IMC_TAD_GRAN_256B,
	IMC_TAD_GRAN_4KB,
	IMC_TAD_GRAN_1GB
} imc_tad_gran_t;

typedef struct imc_tad_rule {
	uint64_t	itr_base;
	uint64_t	itr_limit;
	uint32_t	itr_raw;
	uint32_t	itr_raw_gran;
	uint8_t		itr_sock_way;
	uint8_t		itr_chan_way;
	imc_tad_gran_t	itr_sock_gran;
	imc_tad_gran_t	itr_chan_gran;
	uint_t		itr_ntargets;
	uint8_t		itr_targets[IMC_MAX_TAD_TARGETS];
} imc_tad_rule_t;

typedef enum imc_tad_valid {
	IMC_TAD_V_VALID		= 1 << 0,
	IMC_TAD_V_BAD_PCI_READ	= 1 << 1,
	IMC_TAD_V_BAD_CHAN_GRAN	= 1 << 2
} imc_tad_valid_t;

typedef enum imc_tad_flags {
	IMC_TAD_FLAG_CHANSHIFT	= 1 << 0,
	IMC_TAD_FLAG_CHANHASH	= 1 << 1,
	IMC_TAD_FLAG_MIRROR	= 1 << 2,
	IMC_TAD_FLAG_LOCKSTEP	= 1 << 3
} imc_tad_flags_t;

typedef struct imc_tad {
	imc_tad_valid_t	itad_valid;
	imc_stub_t	*itad_stub;
	imc_tad_flags_t	itad_flags;
	uint_t		itad_nrules;
	imc_tad_rule_t	itad_rules[IMC_MAX_TAD_RULES];
} imc_tad_t;

typedef enum imc_socket_valid {
	IMC_SOCKET_V_VALID	= 0,
	IMC_SOCKET_V_BAD_NODEID	= 1 << 0
} imc_socket_valid_t;

typedef struct imc_socket {
	imc_socket_valid_t	isock_valid;
	uint_t			isock_bus[IMC_MAX_PCIBUSES];
	uint_t			isock_nbus;
	uint_t			isock_gen;
	nvlist_t		*isock_nvl;
	char			*isock_buf;
	size_t			isock_buflen;
	imc_sad_t		isock_sad;
	uint_t			isock_ntad;
	imc_tad_t		isock_tad[IMC_MAX_TAD];
	imc_stub_t		*isock_ubox;
	imc_stub_t		*isock_cpubusno;
	uint32_t		isock_nodeid;
	uint_t			isock_nimc;
	imc_mc_t		isock_imcs[IMC_MAX_IMCPERSOCK];
} imc_socket_t;

typedef struct imc {
	/*
	 * The initial members here are only used in the kernel. This is done to
	 * make it easier for us to be able to define a version of this to use
	 * in testing.
	 */
#ifdef	_KERNEL
	dev_info_t	*imc_dip;
	kmutex_t	imc_lock;
	imc_flags_t	imc_flags;
	const imc_gen_data_t	*imc_gen_data;
	ddi_taskq_t	*imc_taskq;
	uint_t		imc_nscanned;
	avl_tree_t	imc_stubs;
	nvlist_t	*imc_decoder_dump;
	char		*imc_decoder_buf;
	size_t		imc_decoder_len;
#endif	/* _KERNEL */
	imc_gen_t	imc_gen;

	/*
	 * Data about the memory in the system
	 */
	uint_t		imc_nsockets;
	imc_socket_t	imc_sockets[IMC_MAX_SOCKETS];

#ifdef _KERNEL
	/*
	 * The imc_sockets[] array is organized based on increasing PCI Bus ID.
	 * This array maps the socket id that user land thinks of back to the
	 * actual underlying socket in case hardware does not put them in order.
	 */
	imc_socket_t	*imc_spointers[IMC_MAX_SOCKETS];

	/*
	 * Store the IIO global VT-D misc. device. While there are sometimes
	 * multiple on the system, we only keep a single one around.
	 */
	imc_stub_t	*imc_gvtd_misc;
#endif
} imc_t;


/*
 * Decoder failure reasons
 */
typedef enum imc_decode_failure {
	IMC_DECODE_F_NONE = 0,
	/*
	 * Indicates that the memory address fell into a reserved legacy range.
	 * The legacy range index is stored in the failure data.
	 */
	IMC_DECODE_F_LEGACY_RANGE,
	/*
	 * Indicates that we had bad socket data. The socket in question is
	 * noted in the failure data.
	 */
	IMC_DECODE_F_BAD_SOCKET,
	/*
	 * Indicates that we had bad SAD data. The socket the SAD is associated
	 * with is noted in the failure data.
	 */
	IMC_DECODE_F_BAD_SAD,
	/*
	 * Indicates that the address was not contained in conventional, low,
	 * or high memory.
	 */
	IMC_DECODE_F_OUTSIDE_DRAM,
	/*
	 * Indicates that no valid SAD rule was found for the address.
	 */
	IMC_DECODE_F_NO_SAD_RULE,
	/*
	 * Indicates that the SAD interleave target was beyond the valid index.
	 */
	IMC_DECODE_F_BAD_SAD_INTERLEAVE,
	/*
	 * Indicates that the route suggested a remote processor we can't find.
	 */
	IMC_DECODE_F_BAD_REMOTE_MC_ROUTE,
	/*
	 * Indicates that we ended up in a loop trying to find the right socket
	 * to use.
	 */
	IMC_DECODE_F_SAD_SEARCH_LOOP,
	/*
	 * Indicates that we encountered a SAD rule that asked for inconsistent
	 * mod rules.
	 */
	IMC_DECODE_F_SAD_BAD_MOD,
	/*
	 * Indicates that the socket or tad rule we found doesn't actually point
	 * to something that we know about.
	 */
	IMC_DECODE_F_SAD_BAD_SOCKET,
	IMC_DECODE_F_SAD_BAD_TAD,
	/*
	 * Indicates that we could not find a matching tad rule.
	 */
	IMC_DECODE_F_NO_TAD_RULE,
	/*
	 * Indicates that we encountered the TAD channel 3-way interleave that
	 * we don't support.
	 */
	IMC_DECODE_F_TAD_3_ILEAVE,
	/*
	 * Indicates that we had a bad target index.
	 */
	IMC_DECODE_F_TAD_BAD_TARGET_INDEX,
	/*
	 * Indicates that we have a bad channel ID.
	 */
	IMC_DECODE_F_BAD_CHANNEL_ID,
	/*
	 * Indicates that the TAD rule offset in the channel interleave was
	 * incorrect.
	 */
	IMC_DECODE_F_BAD_CHANNEL_TAD_OFFSET,
	/*
	 * We couldn't find a valid rank interleave rule.
	 */
	IMC_DECODE_F_NO_RIR_RULE,
	/*
	 * Indicates that the index of the rank interleaving target was bad.
	 */
	IMC_DECODE_F_BAD_RIR_ILEAVE_TARGET,
	/*
	 * Indicates that the calculated DIMM represents an invalid DIMM that is
	 * beyond the number of supported DIMMS per channel on the platform.
	 */
	IMC_DECODE_F_BAD_DIMM_INDEX,
	/*
	 * Indicates that the specified DIMM is not preset; however, it is a
	 * valid DIMM number.
	 */
	IMC_DECODE_F_DIMM_NOT_PRESENT,
	/*
	 * Indicates that the specified rank on the DIMM is more than the number
	 * of ranks that the DIMM has.
	 */
	IMC_DECODE_F_BAD_DIMM_RANK,
	/*
	 * Indicates that the channel offset is larger than the system address,
	 * meaning that we would end up with an underflow if we continued. The
	 * equivalent is true for the rank address.
	 */
	IMC_DECODE_F_CHANOFF_UNDERFLOW,
	IMC_DECODE_F_RANKOFF_UNDERFLOW,
} imc_decode_failure_t;

/*
 * Decoder state tracking
 */
typedef struct imc_decode_state {
	imc_decode_failure_t	ids_fail;
	uint64_t		ids_fail_data;
	uint64_t		ids_pa;
	uint64_t		ids_chanaddr;
	uint64_t		ids_rankaddr;
	uint32_t		ids_nodeid;
	uint32_t		ids_tadid;
	uint32_t		ids_channelid;
	uint32_t		ids_physrankid;
	uint32_t		ids_dimmid;
	uint32_t		ids_rankid;
	const imc_socket_t	*ids_socket;
	const imc_sad_t		*ids_sad;
	const imc_sad_rule_t	*ids_sad_rule;
	const imc_tad_t		*ids_tad;
	const imc_tad_rule_t	*ids_tad_rule;
	const imc_mc_t		*ids_mc;
	const imc_channel_t	*ids_chan;
	const imc_rank_ileave_t	*ids_rir;
	const imc_dimm_t	*ids_dimm;
} imc_decode_state_t;

#ifdef	_KERNEL

/*
 * Functions needed for the stub drivers.
 */
extern int imc_attach_stub(dev_info_t *, ddi_attach_cmd_t);
extern int imc_detach_stub(dev_info_t *, ddi_detach_cmd_t);

/*
 * Decoder related functions
 */
extern void imc_decoder_init(imc_t *);

extern nvlist_t *imc_dump_decoder(imc_t *);
#else	/* !_KERNEL */
extern boolean_t imc_restore_decoder(nvlist_t *, imc_t *);
#endif	/* _KERNEL */

extern boolean_t imc_decode_pa(const imc_t *, uint64_t, imc_decode_state_t *);


#ifdef __cplusplus
}
#endif

#endif /* _INTEL_IMC_H */
