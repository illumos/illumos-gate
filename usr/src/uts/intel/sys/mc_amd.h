/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MC_AMD_H
#define	_MC_AMD_H

#include <sys/mc.h>
#include <sys/isa_defs.h>
#include <sys/x86_archext.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Definitions, register offsets, register structure etc pertaining to
 * the memory controller on AMD64 systems.  These are used by both the
 * AMD cpu module and the mc-amd driver.
 */

/*
 * The mc-amd driver exports an nvlist to userland, where the primary
 * consumer is the "chip" topology enumerator for this platform type which
 * builds a full topology subtree from this information.  Others can use
 * it, too, but don't depend on it not changing without an ARC contract
 * (and the contract should probably concern the topology, not this nvlist).
 *
 * In the initial mc-amd implementation this nvlist was not versioned;
 * we'll think of that as version 0 and it may be recognised by the absence
 * of a "mcamd-nvlist-version member.
 *
 * Version 1 is defined as follows.  A name in square brackets indicates
 * that member is optional (only present if the actual value is valid).
 *
 * Name			Type		Description
 * -------------------- --------------- ---------------------------------------
 * mcamd-nvlist-version	uint8		Exported nvlist version number
 * num			uint64		Chip id of this memory controller
 * revision		uint64		cpuid_getchiprev() result
 * revname		string		cpuid_getchiprevstr() result
 * socket		string		"Socket 755|939|940|AM2|F(1207)|S1g1"
 * ecc-type		string		"ChipKill 128/16" or "Normal 64/8"
 * base-addr		uint64		Node base address
 * lim-addr		uint64		Node limit address
 * node-ilen		uint64		0|1|3|7 for 0/2/4/8 way node interleave
 * node-ilsel		uint64		Node interleave position of this node
 * cs-intlv-factor	uint64		chip-select interleave: 1/2/4/8
 * dram-hole-size	uint64		size in bytes from dram hole addr reg
 * access-width		uint64		MC mode, 64 or 128 bit
 * bank-mapping		uint64		Raw DRAM Bank Address Mapping Register
 * bankswizzle		uint64		1 if bank swizzling enabled; else 0
 * mismatched-dimm-support uint64	1 if active; else 0
 * [spare-csnum]	uint64		Chip-select pair number of any spare
 * [bad-csnum]		uint64		Chip-select pair number of swapped cs
 * cslist		nvlist array	See below; may have 0 members
 * dimmlist		nvlist array	See below; may have 0 members
 *
 * cslist is an array of nvlist, each as follows:
 *
 * Name			Type		Description
 * -------------------- --------------- ---------------------------------------
 * num			uint64		Chip-select base/mask pair number
 * base-addr		uint64		Chip-select base address (rel to node)
 * mask			uint64		Chip-select mask
 * size			uint64		Chip-select size in bytes
 * dimm1-num		uint64		First dimm (lodimm if a pair)
 * dimm1-csname		string		Socket cs# line name for 1st dimm rank
 * [dimm2-num]		uint64		Second dimm if applicable (updimm)
 * [dimm2-csname]	string		Socket cs# line name for 2nd dimm rank
 *
 * dimmlist is an array of nvlist, each as follows:
 *
 * Name			Type		Description
 * -------------------- --------------- ---------------------------------------
 * num			uint64		DIMM instance number
 * size			uint64		DIMM size in bytes
 * csnums		uint64 array	CS base/mask pair(s) on this DIMM
 * csnames		string array	Socket cs# line name(s) on this DIMM
 *
 *	The n'th csnums entry corresponds to the n'th csnames entry
 */
#define	MC_NVLIST_VERSTR	"mcamd-nvlist-version"
#define	MC_NVLIST_VERS0		0
#define	MC_NVLIST_VERS1		1
#define	MC_NVLIST_VERS		MC_NVLIST_VERS1

/*
 * Constants and feature/revision test macros that are not expected to vary
 * among different AMD family 0xf processor revisions.
 */

/*
 * Configuration constants
 */
#define	MC_CHIP_MAXNODES	8	/* max number of MCs in system */
#define	MC_CHIP_NDIMM		8	/* max dimms per MC */
#define	MC_CHIP_NCS		8	/* number of chip-selects per MC */
#define	MC_CHIP_NDRAMCHAN	2	/* maximum number of dram channels */
#define	MC_CHIP_DIMMRANKMAX	4	/* largest number of ranks per dimm */
#define	MC_CHIP_DIMMPERCS	2	/* max number of dimms per cs */
#define	MC_CHIP_DIMMPAIR(csnum)	(csnum / MC_CHIP_DIMMPERCS)

/*
 * Memory controller registers are read via PCI config space accesses on
 * bus 0, device 0x18 + NodeId, and function as follows:
 *
 * Function 0: HyperTransport Technology Configuration
 * Function 1: Address Map
 * Function 2: DRAM Controller & HyperTransport Technology Trace Mode
 * Function 3: Miscellaneous Control
 */

#define	MC_AMD_DEV_OFFSET	0x18	/* node ID + offset == PCI dev num */

enum mc_funcnum {
	MC_FUNC_HTCONFIG = 0,
	MC_FUNC_ADDRMAP	= 1,
	MC_FUNC_DRAMCTL = 2,
	MC_FUNC_MISCCTL = 3
};

/*
 * For a given (bus, device, function) a particular offset selects the
 * desired register.  All registers are 32-bits wide.
 *
 * Different family 0xf processor revisions vary slightly in the content
 * of these configuration registers.  The biggest change is with rev F
 * where DDR2 support has been introduced along with some hardware-controlled
 * correctable memory error thresholding.  Fortunately most of the config info
 * required by the mc-amd driver is similar across revisions.
 *
 * We will try to insulate most of the driver code from config register
 * details by reading all memory-controller PCI config registers that we
 * will need at driver attach time for each of functions 0 through 3, and
 * storing them in a "cooked" form as memory controller properties.
 * These are to be accessed directly where we have an mc_t to hand, otherwise
 * through mcamd_get_numprop.  As such we expect most/all use of the
 * structures and macros defined below to be in those attach codepaths.
 */

/*
 * Function 0 (HT Config) offsets
 */
#define	MC_HT_REG_RTBL_NODE_0	0x40
#define	MC_HT_REG_RTBL_INCR	4
#define	MC_HT_REG_NODEID	0x60
#define	MC_HT_REG_UNITID	0x64

/*
 * Function 1 (address map) offsets for DRAM base, DRAM limit, DRAM hole
 * registers.
 */
#define	MC_AM_REG_DRAMBASE_0	0x40	/* Offset for DRAM Base 0 */
#define	MC_AM_REG_DRAMLIM_0	0x44	/* Offset for DRAM Limit 0 */
#define	MC_AM_REG_DRAM_INCR	8	/* incr between base/limit pairs */
#define	MC_AM_REG_HOLEADDR	0xf0	/* DRAM Hole Address Register */

/*
 * Function 2 (dram controller) offsets for chip-select base, chip-select mask,
 * DRAM bank address mapping, DRAM configuration registers.
 */
#define	MC_DC_REG_CS_INCR	4	/* incr for CS base and mask */
#define	MC_DC_REG_CSBASE_0	0x40	/* 0x40 - 0x5c */
#define	MC_DC_REG_CSMASK_0	0x60	/* 0x60 - 0x7c */
#define	MC_DC_REG_BANKADDRMAP	0x80	/* DRAM Bank Address Mapping */
#define	MC_DC_REG_DRAMCFGLO	0x90	/* DRAM Configuration Low */
#define	MC_DC_REG_DRAMCFGHI	0x94	/* DRAM Configuration High */
#define	MC_DC_REG_DRAMMISC	0xa0	/* DRAM Miscellaneous */

/*
 * Function 3 (misc control) offset for NB MCA config, scrubber control,
 * online spare control and NB capabilities.
 */
#define	MC_CTL_REG_NBCFG	0x44	/* MCA NB configuration register */
#define	MC_CTL_REG_SCRUBCTL	0x58	/* Scrub control register */
#define	MC_CTL_REG_SCRUBADDR_LO	0x5c	/* DRAM Scrub Address Low */
#define	MC_CTL_REG_SCRUBADDR_HI	0x60	/* DRAM Scrub Address High */
#define	MC_CTL_REG_SPARECTL	0xb0	/* On-line spare control register */
#define	MC_CTL_REG_NBCAP	0xe8	/* NB Capabilities */
#define	MC_CTL_REG_EXTNBCFG	0x180	/* Ext. MCA NB configuration register */

#define	MC_NBCAP_L3CAPABLE	(1U << 25)
#define	MC_NBCAP_MULTINODECPU	(1U << 29)
#define	MC_EXTNBCFG_ECCSYMSZ	(1U << 25)

/*
 * MC4_MISC MSR and MC4_MISCj MSRs
 */
#define	MC_MSR_NB_MISC0		0x413
#define	MC_MSR_NB_MISC1		0xc0000408
#define	MC_MSR_NB_MISC2		0xc0000409
#define	MC_MSR_NB_MISC3		0xc000040a
#define	MC_MSR_NB_MISC(j) \
	((j) == 0 ? MC_MSR_NB_MISC0 : MC_MSR_NB_MISC1 + (j) - 1)

/*
 * PCI registers will be represented as unions, with one fixed-width unsigned
 * integer member providing access to the raw register value and one or more
 * structs breaking the register out into bitfields (more than one struct if
 * the register definitions varies across processor revisions).
 *
 * The "raw" union member will always be '_val32'.  Use MCREG_VAL32 to
 * access this member.
 *
 * The bitfield structs are all named _fmt_xxx where xxx identifies the
 * processor revision to which it applies.  At this point the only xxx
 * values in use are:
 *			'cmn' - applies to all revisions
 *			'f_preF' - applies to revisions E and earlier
 *			'f_revFG' - applies to revisions F and G
 *
 * Variants such as 'preD', 'revDE', 'postCG' etc should be introduced
 * as requirements arise.  The MC_REV_* and MC_REV_MATCH etc macros
 * will also need to grow to match.  Use MCREG_FIELD_* to access the
 * individual bitfields of a register, perhaps using MC_REV_* and MC_REV_MATCH
 * to decide which revision suffix to provide.  Where a bitfield appears
 * in different revisions but has the same use it should be named identically
 * (even if the BKDG varies a little) so that the MC_REG_FIELD_* macros
 * can lookup that member based on revision only.
 */

#define	MC_REV_UNKNOWN	X86_CHIPREV_UNKNOWN

#define	MC_F_REV_B	X86_CHIPREV_AMD_F_REV_B
#define	MC_F_REV_C	(X86_CHIPREV_AMD_F_REV_C0 | X86_CHIPREV_AMD_F_REV_CG)
#define	MC_F_REV_D	X86_CHIPREV_AMD_F_REV_D
#define	MC_F_REV_E	X86_CHIPREV_AMD_F_REV_E
#define	MC_F_REV_F	X86_CHIPREV_AMD_F_REV_F
#define	MC_F_REV_G	X86_CHIPREV_AMD_F_REV_G

#define	MC_10_REV_A	X86_CHIPREV_AMD_10_REV_A
#define	MC_10_REV_B	X86_CHIPREV_AMD_10_REV_B

/*
 * The most common groupings for memory controller features.
 */
#define	MC_F_REVS_BC	(MC_F_REV_B | MC_F_REV_C)
#define	MC_F_REVS_DE	(MC_F_REV_D | MC_F_REV_E)
#define	MC_F_REVS_BCDE	(MC_F_REVS_BC | MC_F_REVS_DE)
#define	MC_F_REVS_FG	(MC_F_REV_F | MC_F_REV_G)

#define	MC_10_REVS_AB	(MC_10_REV_A | MC_10_REV_B)

/*
 * Is 'rev' included in the 'revmask' bitmask?
 */
#define	MC_REV_MATCH(rev, revmask)	X86_CHIPREV_MATCH(rev, revmask)

/*
 * Is 'rev' at least revision 'revmin' or greater
 */
#define	MC_REV_ATLEAST(rev, minrev)	X86_CHIPREV_ATLEAST(rev, minrev)

#define	_MCREG_FIELD(up, revsuffix, field) ((up)->_fmt_##revsuffix.field)

#define	MCREG_VAL32(up) ((up)->_val32)

/*
 * Access a field that has the same structure in all families and revisions
 */
#define	MCREG_FIELD_CMN(up, field)	_MCREG_FIELD(up, cmn, field)

/*
 * Access a field as defined for family 0xf prior to revision F
 */
#define	MCREG_FIELD_F_preF(up, field)	_MCREG_FIELD(up, f_preF, field)

/*
 * Access a field as defined for family 0xf revisions F and G
 */
#define	MCREG_FIELD_F_revFG(up, field)	_MCREG_FIELD(up, f_revFG, field)

/*
 * Access a field as defined for family 0x10 revisions A and
 */
#define	MCREG_FIELD_10_revAB(up, field)	_MCREG_FIELD(up, 10_revAB, field)

/*
 * We will only define the register bitfields for little-endian order
 */
#ifdef	_BIT_FIELDS_LTOH

/*
 * Function 0 - HT Configuration: Routing Table Node Register
 */
union mcreg_htroute {
	uint32_t	_val32;
	struct {
		uint32_t	RQRte:4;	/*  3:0 */
		uint32_t	reserved1:4;	/*  7:4 */
		uint32_t	RPRte:4;	/* 11:8 */
		uint32_t	reserved2:4;	/* 15:12 */
		uint32_t	BCRte:4;	/* 19:16 */
		uint32_t	reserved3:12;	/* 31:20 */
	} _fmt_cmn;
};

/*
 * Function 0 - HT Configuration: Node ID Register
 */
union mcreg_nodeid {
	uint32_t	_val32;
	struct {
		uint32_t	NodeId:3;	/*  2:0 */
		uint32_t	reserved1:1;	/*  3:3 */
		uint32_t	NodeCnt:3;	/*  6:4 */
		uint32_t	reserved2:1;	/*  7:7 */
		uint32_t	SbNode:3;	/* 10:8 */
		uint32_t	reserved3:1;	/* 11:11 */
		uint32_t	LkNode:3;	/* 14:12 */
		uint32_t	reserved4:1;	/* 15:15 */
		uint32_t	CpuCnt:4;	/* 19:16 */
		uint32_t	reserved:12;	/* 31:20 */
	} _fmt_cmn;
};

#define	HT_COHERENTNODES(up)	(MCREG_FIELD_CMN(up, NodeCnt) + 1)
#define	HT_SYSTEMCORECOUNT(up)	(MCREG_FIELD_CMN(up, CpuCnt) + 1)

/*
 * Function 0 - HT Configuration: Unit ID Register
 */
union mcreg_unitid {
	uint32_t	_val32;
	struct {
		uint32_t	C0Unit:2;	/*  1:0 */
		uint32_t	C1Unit:2;	/*  3:2 */
		uint32_t	McUnit:2;	/*  5:4 */
		uint32_t	HbUnit:2;	/*  7:6 */
		uint32_t	SbLink:2;	/*  9:8 */
		uint32_t	reserved:22;	/* 31:10 */
	} _fmt_cmn;
};

/*
 * Function 1 - DRAM Address Map: DRAM Base i Registers
 *
 */

union mcreg_drambase {
	uint32_t	_val32;
	struct {
		uint32_t	RE:1;		/*  0:0  - Read Enable */
		uint32_t	WE:1;		/*  1:1  - Write Enable */
		uint32_t	reserved1:6;	/*  7:2 */
		uint32_t	IntlvEn:3;	/* 10:8  - Interleave Enable */
		uint32_t	reserved2:5;	/* 15:11 */
		uint32_t	DRAMBasei:16;	/* 31:16 - Base Addr 39:24 */
	} _fmt_cmn;
};

#define	MC_DRAMBASE(up)	((uint64_t)MCREG_FIELD_CMN(up, DRAMBasei) << 24)

/*
 * Function 1 - DRAM Address Map: DRAM Limit i Registers
 *
 */

union mcreg_dramlimit {
	uint32_t	_val32;
	struct {
		uint32_t	DstNode:3;	/*  2:0  - Destination Node */
		uint32_t	reserved1:5;	/*  7:3 */
		uint32_t	IntlvSel:3;	/* 10:8  - Interleave Select */
		uint32_t	reserved2:5;	/* 15:11 */
		uint32_t	DRAMLimiti:16;	/* 31:16 - Limit Addr 39:24 */
	} _fmt_cmn;
};

#define	MC_DRAMLIM(up) \
	((uint64_t)MCREG_FIELD_CMN(up, DRAMLimiti) << 24 |		\
	(MCREG_FIELD_CMN(up, DRAMLimiti) ?  ((1 << 24) - 1) : 0))

/*
 * Function 1 - DRAM Address Map: DRAM Hole Address Register
 */

union mcreg_dramhole {
	uint32_t	_val32;
	struct {
		uint32_t	DramHoleValid:1;	/*  0:0 */
		uint32_t	reserved1:7;		/*  7:1 */
		uint32_t	DramHoleOffset:8;	/* 15:8 */
		uint32_t	reserved2:8;		/* 23:16 */
		uint32_t	DramHoleBase:8;		/* 31:24 */
	} _fmt_cmn;
};

#define	MC_DRAMHOLE_SIZE(up) (MCREG_FIELD_CMN(up, DramHoleOffset) << 24)

/*
 * Function 2 - DRAM Controller: DRAM CS Base Address Registers
 */

union mcreg_csbase {
	uint32_t	_val32;
	/*
	 * Register format in family 0xf revisions E and earlier
	 */
	struct {
		uint32_t	CSEnable:1;	/*  0:0  - CS Bank Enable */
		uint32_t	reserved1:8;	/*  8:1 */
		uint32_t	BaseAddrLo:7;	/* 15:9  - Base Addr 19:13 */
		uint32_t	reserved2:5;	/* 20:16 */
		uint32_t	BaseAddrHi:11;	/* 31:21 - Base Addr 35:25 */
	} _fmt_f_preF;
	/*
	 * Register format in family 0xf revisions F and G
	 */
	struct {
		uint32_t	CSEnable:1;	/*  0:0  - CS Bank Enable */
		uint32_t	Spare:1;	/*  1:1  - Spare Rank */
		uint32_t	TestFail:1;	/*  2:2  - Memory Test Failed */
		uint32_t	reserved1:2;	/*  4:3 */
		uint32_t	BaseAddrLo:9;	/* 13:5  - Base Addr 21:13 */
		uint32_t	reserved2:5;	/* 18:14 */
		uint32_t	BaseAddrHi:10;	/* 28:19 - Base Addr 36:27 */
		uint32_t	reserved3:3;	/* 31:39 */
	} _fmt_f_revFG;
};

#define	MC_CSBASE(up, rev) (MC_REV_MATCH(rev, MC_F_REVS_FG) ?	\
	(uint64_t)MCREG_FIELD_F_revFG(up, BaseAddrHi) << 27 |		\
	(uint64_t)MCREG_FIELD_F_revFG(up, BaseAddrLo) << 13 :		\
	(uint64_t)MCREG_FIELD_F_preF(up, BaseAddrHi) << 25 |		\
	(uint64_t)MCREG_FIELD_F_preF(up, BaseAddrLo) << 13)

/*
 * Function 2 - DRAM Controller: DRAM CS Mask Registers
 */

union mcreg_csmask {
	uint32_t	_val32;
	/*
	 * Register format in family 0xf revisions E and earlier
	 */
	struct {
		uint32_t	reserved1:9;	/*  8:0 */
		uint32_t	AddrMaskLo:7;	/* 15:9  - Addr Mask 19:13 */
		uint32_t	reserved2:5;	/* 20:16 */
		uint32_t	AddrMaskHi:9;	/* 29:21 - Addr Mask 33:25 */
		uint32_t	reserved3:2;	/* 31:30 */
	} _fmt_f_preF;
	/*
	 * Register format in family 0xf revisions F and G
	 */
	struct {
		uint32_t	reserved1:5;	/*  4:0 */
		uint32_t	AddrMaskLo:9;	/* 13:5  - Addr Mask 21:13 */
		uint32_t	reserved2:5;	/* 18:14 */
		uint32_t	AddrMaskHi:10;	/* 28:19 - Addr Mask 36:27 */
		uint32_t	reserved3:3;	/* 31:29 */
	} _fmt_f_revFG;
};

#define	MC_CSMASKLO_LOBIT(rev) (MC_REV_MATCH(rev, MC_F_REVS_FG) ? 13 : 13)
#define	MC_CSMASKLO_HIBIT(rev) (MC_REV_MATCH(rev, MC_F_REVS_FG) ? 21 : 19)

#define	MC_CSMASKHI_LOBIT(rev) (MC_REV_MATCH(rev, MC_F_REVS_FG) ? 27 : 25)
#define	MC_CSMASKHI_HIBIT(rev) (MC_REV_MATCH(rev, MC_F_REVS_FG) ? 36 : 33)

#define	MC_CSMASK_UNMASKABLE(rev) (MC_REV_MATCH(rev, MC_F_REVS_FG) ? 0 : 2)

#define	MC_CSMASK(up, rev) (MC_REV_MATCH(rev, MC_F_REVS_FG) ? \
	(uint64_t)MCREG_FIELD_F_revFG(up, AddrMaskHi) << 27 | \
	(uint64_t)MCREG_FIELD_F_revFG(up, AddrMaskLo) << 13 | 0x7c01fff : \
	(uint64_t)MCREG_FIELD_F_preF(up, AddrMaskHi) << 25 | \
	(uint64_t)MCREG_FIELD_F_preF(up, AddrMaskLo) << 13 | 0x1f01fff)

/*
 * Function 2 - DRAM Controller: DRAM Bank Address Mapping Registers
 */

union mcreg_bankaddrmap {
	uint32_t	_val32;
	/*
	 * Register format in family 0xf revisions E and earlier
	 */
	struct {
		uint32_t	cs10:4;			/*  3:0  - CS1/0 */
		uint32_t	cs32:4;			/*  7:4  - CS3/2 */
		uint32_t	cs54:4;			/* 11:8  - CS5/4 */
		uint32_t	cs76:4;			/* 15:12 - CS7/6 */
		uint32_t	reserved1:14;		/* 29:16 */
		uint32_t	BankSwizzleMode:1;	/* 30:30 */
		uint32_t	reserved2:1;		/* 31:31 */
	} _fmt_f_preF;
	/*
	 * Register format in family 0xf revisions F and G
	 */
	struct {
		uint32_t	cs10:4;			/*  3:0  - CS1/0 */
		uint32_t	cs32:4;			/*  7:4  - CS3/2 */
		uint32_t	cs54:4;			/* 11:8  - CS5/4 */
		uint32_t	cs76:4;			/* 15:12 - CS7/6 */
		uint32_t	reserved1:16;		/* 31:16 */
	} _fmt_f_revFG;
	/*
	 * Accessing all mode encodings as one uint16
	 */
	struct {
		uint32_t	allcsmodes:16;		/* 15:0 */
		uint32_t	pad:16;			/* 31:16 */
	} _fmt_bankmodes;
};

#define	MC_DC_BAM_CSBANK_MASK	0x0000000f
#define	MC_DC_BAM_CSBANK_SHIFT	4

#define	MC_CSBANKMODE(up, csnum) ((up)->_fmt_bankmodes.allcsmodes >>	\
    MC_DC_BAM_CSBANK_SHIFT * MC_CHIP_DIMMPAIR(csnum) & MC_DC_BAM_CSBANK_MASK)

/*
 * Function 2 - DRAM Controller: DRAM Configuration Low and High
 */

union mcreg_dramcfg_lo {
	uint32_t _val32;
	/*
	 * Register format in family 0xf revisions E and earlier.
	 * Bit 7 is a BIOS ScratchBit in revs D and earlier,
	 * PwrDwnTriEn in revision E;  we don't use it so
	 * we'll call it ambig1.
	 */
	struct {
		uint32_t	DLL_Dis:1;	/* 0 */
		uint32_t	D_DRV:1;	/* 1 */
		uint32_t	QFC_EN:1;	/* 2 */
		uint32_t	DisDqsHys:1;	/* 3 */
		uint32_t	reserved1:1;	/* 4 */
		uint32_t	Burst2Opt:1;	/* 5 */
		uint32_t	Mod64BitMux:1;	/* 6 */
		uint32_t	ambig1:1;	/* 7 */
		uint32_t	DramInit:1;	/* 8 */
		uint32_t	DualDimmEn:1;	/* 9 */
		uint32_t	DramEnable:1;	/* 10 */
		uint32_t	MemClrStatus:1;	/* 11 */
		uint32_t	ESR:1;		/* 12 */
		uint32_t	SR_S:1;		/* 13 */
		uint32_t	RdWrQByp:2;	/* 15:14 */
		uint32_t	Width128:1;	/* 16 */
		uint32_t	DimmEcEn:1;	/* 17 */
		uint32_t	UnBufDimm:1;	/* 18 */
		uint32_t	ByteEn32:1;	/* 19 */
		uint32_t	x4DIMMs:4;	/* 23:20 */
		uint32_t	DisInRcvrs:1;	/* 24 */
		uint32_t	BypMax:3;	/* 27:25 */
		uint32_t	En2T:1;		/* 28 */
		uint32_t	UpperCSMap:1;	/* 29 */
		uint32_t	PwrDownCtl:2;	/* 31:30 */
	} _fmt_f_preF;
	/*
	 * Register format in family 0xf revisions F and G
	 */
	struct {
		uint32_t	InitDram:1;		/* 0 */
		uint32_t	ExitSelfRef:1;		/* 1 */
		uint32_t	reserved1:2;		/* 3:2 */
		uint32_t	DramTerm:2;		/* 5:4 */
		uint32_t	reserved2:1;		/* 6 */
		uint32_t	DramDrvWeak:1;		/* 7 */
		uint32_t	ParEn:1;		/* 8 */
		uint32_t	SelRefRateEn:1;		/* 9 */
		uint32_t	BurstLength32:1;	/* 10 */
		uint32_t	Width128:1;		/* 11 */
		uint32_t	x4DIMMs:4;		/* 15:12 */
		uint32_t	UnBuffDimm:1;		/* 16 */
		uint32_t	reserved3:2;		/* 18:17 */
		uint32_t	DimmEccEn:1;		/* 19 */
		uint32_t	reserved4:12;		/* 31:20 */
	} _fmt_f_revFG;
};

/*
 * Function 2 - DRAM Controller: DRAM Controller Miscellaneous Data
 */

union mcreg_drammisc {
	uint32_t _val32;
	/*
	 * Register format in family 0xf revisions F and G
	 */
	struct {
		uint32_t	reserved2:1;		/* 0 */
		uint32_t	DisableJitter:1;	/* 1 */
		uint32_t	RdWrQByp:2;		/* 3:2 */
		uint32_t	Mod64Mux:1;		/* 4 */
		uint32_t	DCC_EN:1;		/* 5 */
		uint32_t	ILD_lmt:3;		/* 8:6 */
		uint32_t	DramEnabled:1;		/* 9 */
		uint32_t	PwrSavingsEn:1;		/* 10 */
		uint32_t	reserved1:13;		/* 23:11 */
		uint32_t	MemClkDis:8;		/* 31:24 */
	} _fmt_f_revFG;
};

union mcreg_dramcfg_hi {
	uint32_t _val32;
	/*
	 * Register format in family 0xf revisions E and earlier.
	 */
	struct {
		uint32_t	AsyncLat:4;		/* 3:0 */
		uint32_t	reserved1:4;		/* 7:4 */
		uint32_t	RdPreamble:4;		/* 11:8 */
		uint32_t	reserved2:1;		/* 12 */
		uint32_t	MemDQDrvStren:2;	/* 14:13 */
		uint32_t	DisableJitter:1;	/* 15 */
		uint32_t	ILD_lmt:3;		/* 18:16 */
		uint32_t	DCC_EN:1;		/* 19 */
		uint32_t	MemClk:3;		/* 22:20 */
		uint32_t	reserved3:2;		/* 24:23 */
		uint32_t	MCR:1;			/* 25 */
		uint32_t	MC0_EN:1;		/* 26 */
		uint32_t	MC1_EN:1;		/* 27 */
		uint32_t	MC2_EN:1;		/* 28 */
		uint32_t	MC3_EN:1;		/* 29 */
		uint32_t	reserved4:1;		/* 30 */
		uint32_t	OddDivisorCorrect:1;	/* 31 */
	} _fmt_f_preF;
	/*
	 * Register format in family 0xf revisions F and G
	 */
	struct {
		uint32_t	MemClkFreq:3;		/* 2:0 */
		uint32_t	MemClkFreqVal:1;	/* 3 */
		uint32_t	MaxAsyncLat:4;		/* 7:4 */
		uint32_t	reserved1:4;		/* 11:8 */
		uint32_t	RDqsEn:1;		/* 12 */
		uint32_t	reserved2:1;		/* 13 */
		uint32_t	DisDramInterface:1;	/* 14 */
		uint32_t	PowerDownEn:1;		/* 15 */
		uint32_t	PowerDownMode:1;	/* 16 */
		uint32_t	FourRankSODimm:1;	/* 17 */
		uint32_t	FourRankRDimm:1;	/* 18 */
		uint32_t	reserved3:1;		/* 19 */
		uint32_t	SlowAccessMode:1;	/* 20 */
		uint32_t	reserved4:1;		/* 21 */
		uint32_t	BankSwizzleMode:1;	/* 22 */
		uint32_t	undocumented1:1;	/* 23 */
		uint32_t	DcqBypassMax:4;		/* 27:24 */
		uint32_t	FourActWindow:4;	/* 31:28 */
	} _fmt_f_revFG;
};

/*
 * Function 3 - Miscellaneous Control: Scrub Control Register
 */

union mcreg_scrubctl {
	uint32_t _val32;
	struct {
		uint32_t	DramScrub:5;		/* 4:0 */
		uint32_t	reserved3:3;		/* 7:5 */
		uint32_t	L2Scrub:5;		/* 12:8 */
		uint32_t	reserved2:3;		/* 15:13 */
		uint32_t	DcacheScrub:5;		/* 20:16 */
		uint32_t	reserved1:11;		/* 31:21 */
	} _fmt_cmn;
};

union mcreg_dramscrublo {
	uint32_t _val32;
	struct {
		uint32_t	ScrubReDirEn:1;		/* 0 */
		uint32_t	reserved:5;		/* 5:1 */
		uint32_t	ScrubAddrLo:26;		/* 31:6 */
	} _fmt_cmn;
};

union mcreg_dramscrubhi {
	uint32_t _val32;
	struct {
		uint32_t	ScrubAddrHi:8;		/* 7:0 */
		uint32_t	reserved:24;		/* 31:8 */
	} _fmt_cmn;
};

/*
 * Function 3 - Miscellaneous Control: On-Line Spare Control Register
 */

union mcreg_nbcfg {
	uint32_t _val32;
	/*
	 * Register format in family 0xf revisions E and earlier.
	 */
	struct {
		uint32_t	CpuEccErrEn:1;			/* 0 */
		uint32_t	CpuRdDatErrEn:1;		/* 1 */
		uint32_t	SyncOnUcEccEn:1;		/* 2 */
		uint32_t	SyncPktGenDis:1;		/* 3 */
		uint32_t	SyncPktPropDis:1;		/* 4 */
		uint32_t	IoMstAbortDis:1;		/* 5 */
		uint32_t	CpuErrDis:1;			/* 6 */
		uint32_t	IoErrDis:1;			/* 7 */
		uint32_t	WdogTmrDis:1;			/* 8 */
		uint32_t	WdogTmrCntSel:3;		/* 11:9 */
		uint32_t	WdogTmrBaseSel:2;		/* 13:12 */
		uint32_t	LdtLinkSel:2;			/* 15:14 */
		uint32_t	GenCrcErrByte0:1;		/* 16 */
		uint32_t	GenCrcErrByte1:1;		/* 17 */
		uint32_t	reserved1:2;			/* 19:18 */
		uint32_t	SyncOnWdogEn:1;			/* 20 */
		uint32_t	SyncOnAnyErrEn:1;		/* 21 */
		uint32_t	EccEn:1;			/* 22 */
		uint32_t	ChipKillEccEn:1;		/* 23 */
		uint32_t	IoRdDatErrEn:1;			/* 24 */
		uint32_t	DisPciCfgCpuErrRsp:1;		/* 25 */
		uint32_t	reserved2:1;			/* 26 */
		uint32_t	NbMcaToMstCpuEn:1;		/* 27 */
		uint32_t	reserved3:4;			/* 31:28 */
	} _fmt_f_preF;
	/*
	 * Register format in family 0xf revisions F and G
	 */
	struct {
		uint32_t	CpuEccErrEn:1;			/* 0 */
		uint32_t	CpuRdDatErrEn:1;		/* 1 */
		uint32_t	SyncOnUcEccEn:1;		/* 2 */
		uint32_t	SyncPktGenDis:1;		/* 3 */
		uint32_t	SyncPktPropDis:1;		/* 4 */
		uint32_t	IoMstAbortDis:1;		/* 5 */
		uint32_t	CpuErrDis:1;			/* 6 */
		uint32_t	IoErrDis:1;			/* 7 */
		uint32_t	WdogTmrDis:1;			/* 8 */
		uint32_t	WdogTmrCntSel:3;		/* 11:9 */
		uint32_t	WdogTmrBaseSel:2;		/* 13:12 */
		uint32_t	LdtLinkSel:2;			/* 15:14 */
		uint32_t	GenCrcErrByte0:1;		/* 16 */
		uint32_t	GenCrcErrByte1:1;		/* 17 */
		uint32_t	reserved1:2;			/* 19:18 */
		uint32_t	SyncOnWdogEn:1;			/* 20 */
		uint32_t	SyncOnAnyErrEn:1;		/* 21 */
		uint32_t	EccEn:1;			/* 22 */
		uint32_t	ChipKillEccEn:1;		/* 23 */
		uint32_t	IoRdDatErrEn:1;			/* 24 */
		uint32_t	DisPciCfgCpuErrRsp:1;		/* 25 */
		uint32_t	reserved2:1;			/* 26 */
		uint32_t	NbMcaToMstCpuEn:1;		/* 27 */
		uint32_t	DisTgtAbtCpuErrRsp:1;		/* 28 */
		uint32_t	DisMstAbtCpuErrRsp:1;		/* 29 */
		uint32_t	SyncOnDramAdrParErrEn:1;	/* 30 */
		uint32_t	reserved3:1;			/* 31 */

	} _fmt_f_revFG;
};

/*
 * Function 3 - Miscellaneous Control: On-Line Spare Control Register
 */

union mcreg_sparectl {
	uint32_t _val32;
	/*
	 * Register format in family 0xf revisions F and G
	 */
	struct {
		uint32_t	SwapEn:1;		/* 0 */
		uint32_t	SwapDone:1;		/* 1 */
		uint32_t	reserved1:2;		/* 3:2 */
		uint32_t	BadDramCs:3;		/* 6:4 */
		uint32_t	reserved2:5;		/* 11:7 */
		uint32_t	SwapDoneInt:2;		/* 13:12 */
		uint32_t	EccErrInt:2;		/* 15:14 */
		uint32_t	EccErrCntDramCs:3;	/* 18:16 */
		uint32_t	reserved3:1;		/* 19 */
		uint32_t	EccErrCntDramChan:1;	/* 20 */
		uint32_t	reserved4:2;		/* 22:21 */
		uint32_t	EccErrCntWrEn:1;	/* 23 */
		uint32_t	EccErrCnt:4;		/* 27:24 */
		uint32_t	reserved5:4;		/* 31:28 */
	} _fmt_f_revFG;
	/*
	 * Regiser format in family 0x10 revisions A and B
	 */
	struct {
		uint32_t	SwapEn0:1;		/* 0 */
		uint32_t	SwapDone0:1;		/* 1 */
		uint32_t	SwapEn1:1;		/* 2 */
		uint32_t	SwapDone1:1;		/* 3 */
		uint32_t	BadDramCs0:3;		/* 6:4 */
		uint32_t	reserved1:1;		/* 7 */
		uint32_t	BadDramCs1:3;		/* 10:8 */
		uint32_t	reserved2:1;		/* 11 */
		uint32_t	SwapDoneInt:2;		/* 13:12 */
		uint32_t	EccErrInt:2;		/* 15:14 */
		uint32_t	EccErrCntDramCs:4;	/* 19:16 */
		uint32_t	EccErrCntDramChan:2;	/* 21:20 */
		uint32_t	reserved4:1;		/* 22 */
		uint32_t	EccErrCntWrEn:1;	/* 23 */
		uint32_t	EccErrCnt:4;		/* 27:24 */
		uint32_t	LvtOffset:4;		/* 31:28 */
	} _fmt_10_revAB;
};

/*
 * Since the NB is on-chip some registers are also accessible as MSRs.
 * We will represent such registers as bitfields as in the 32-bit PCI
 * registers above, with the restriction that we must compile for 32-bit
 * kernels and so 64-bit bitfields cannot be used.
 */

#define	_MCMSR_FIELD(up, revsuffix, field) ((up)->_fmt_##revsuffix.field)

#define	MCMSR_VAL(up) ((up)->_val64)

#define	MCMSR_FIELD_CMN(up, field)	_MCMSR_FIELD(up, cmn, field)
#define	MCMSR_FIELD_F_preF(up, field)	_MCMSR_FIELD(up, f_preF, field)
#define	MCMSR_FIELD_F_revFG(up, field)	_MCMSR_FIELD(up, f_revFG, field)
#define	MCMSR_FIELD_10_revAB(up, field)	_MCMSR_FIELD(up, 10_revAB, field)

/*
 * The NB MISC registers.  On family 0xf rev F this was introduced with
 * a 12-bit ECC error count of all ECC errors observed on this memory-
 * controller (regardless of channel or chip-select) and the ability to
 * raise an interrupt or SMI on overflow.  In family 0x10 it has a similar
 * purpose, but the register is is split into 4 misc registers
 * MC4_MISC{0,1,2,3} accessible via both MSRs and PCI config space;
 * they perform thresholding for dram, l3, HT errors.
 */

union mcmsr_nbmisc {
	uint64_t _val64;
	/*
	 * MSR format in family 0xf revision F and later
	 */
	struct {
		/*
		 * Lower 32 bits
		 */
		struct {
			uint32_t _reserved;			/* 31:0 */
		} _mcimisc_lo;
		/*
		 * Upper 32 bits
		 */
		struct {
			uint32_t _ErrCount:12;			/* 43:32 */
			uint32_t _reserved1:4;			/* 47:44 */
			uint32_t _Ovrflw:1;			/* 48 */
			uint32_t _IntType:2;			/* 50:49 */
			uint32_t _CntEn:1;			/* 51 */
			uint32_t _LvtOff:4;			/* 55:52 */
			uint32_t _reserved2:5;			/* 60:56 */
			uint32_t _Locked:1;			/* 61 */
			uint32_t _CntP:1;			/* 62 */
			uint32_t _Valid:1;			/* 63 */
		} _mcimisc_hi;
	} _fmt_f_revFG;
	/*
	 * MSR format in family 0x10 revisions A and B
	 */
	struct {
		/*
		 * Lower 32 bits
		 */
		struct {
			uint32_t _reserved:24;			/* 23:0 */
			uint32_t _BlkPtr:8;			/* 31:24 */
		} _mcimisc_lo;
		/*
		 * Upper 32 bits
		 */
		struct {
			uint32_t _ErrCnt:12;			/* 43:32 */
			uint32_t _reserved1:4;			/* 47:44 */
			uint32_t _Ovrflw:1;			/* 48 */
			uint32_t _IntType:2;			/* 50:49 */
			uint32_t _CntEn:1;			/* 51 */
			uint32_t _LvtOff:4;			/* 55:52 */
			uint32_t _reserved2:5;			/* 60:56 */
			uint32_t _Locked:1;			/* 61 */
			uint32_t _CntP:1;			/* 62 */
			uint32_t _Valid:1;			/* 63 */

		} _mcimisc_hi;
	} _fmt_10_revAB;
};

#define	mcmisc_BlkPtr	_mcimisc_lo._BlkPtr
#define	mcmisc_ErrCount	_mcimisc_hi._ErrCount
#define	mcmisc_Ovrflw	_mcimisc_hi._Ovrflw
#define	mcmisc_IntType	_mcimisc_hi._IntType
#define	mcmisc_CntEn	_mcimisc_hi._CntEn
#define	mcmisc_LvtOff	_mcimisc_hi._LvtOff
#define	mcmisc_Locked	_mcimisc_hi._Locked
#define	mcmisc_CntP	_mcimisc_hi._CntP
#define	mcmisc_Valid	_mcimisc_hi._Valid

#endif /* _BIT_FIELDS_LTOH */

#ifdef __cplusplus
}
#endif

#endif /* _MC_AMD_H */
