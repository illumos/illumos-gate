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

#ifndef _SYS_AMDZEN_DF_H
#define	_SYS_AMDZEN_DF_H

/*
 * This file contains definitions for the registers that appears in the AMD Zen
 * Data Fabric. The data fabric is the main component which routes transactions
 * between entities (e.g. CPUS, DRAM, PCIe, etc.) in the system. The data fabric
 * itself is made up of up to 8 PCI functions. There can be multiple instances
 * of the data fabric. There is one instance per die. In most AMD processors
 * after Zen 1, there is only a single die per socket, for more background see
 * the uts/i86pc/os/cpuid.c big theory statement. All data fabric instances
 * appear on PCI bus 0. The first instance shows up on device 0x18. Subsequent
 * instances simply increment that number by one.
 *
 * There are currently four major revisions of the data fabric that are
 * supported here, which are v2 (Zen 1), v3 (Zen 2/3), v3.5 (Zen 2/3 with DDR5),
 * and v4 (Zen 4). In many cases, while the same logical thing exists in
 * different generations, they often have different shapes and sometimes things
 * with the same shape show up in different locations. As DFv4 has been extended
 * across several different lines, things haven't been quite as smooth as we'd
 * like in terms of DF representation. Certain things end up moving around much
 * more liberally while revving the minor version of the DF, though at least we
 * can still identify it as such.
 *
 * The major (relevant to us) distinction that we have found so far is that
 * starting in DF 4v2 and greater, the way that DRAM was structured and the
 * corresponding DRAM channel remap settings were moved. Because the DRAM base
 * address registers were moved to 0x200, we call this DF_REV_4D2. If this
 * gets much more nuanced, we should likely figure out if we want to encode
 * minor versions in these constants and offer function pointers to get common
 * things rather than forcing it onto clients. Note that this is very much a
 * rough approximation and not really great. There are many places where the
 * width of fields has changed slightly between minor revs, but are eating up
 * more reserved bits, or not using quite as many.
 *
 * To make things a little easier for clients, each register definition encodes
 * enough information to also include which hardware generations it supports,
 * the actual PCI function it appears upon, and the register offset. This is to
 * make sure that consumers don't have to guess some of this information in the
 * latter cases and we can try to guarantee we're not accessing an incorrect
 * register for our platform (unfortunately at runtime).
 *
 * Register definitions have the following form:
 *
 * DF_<reg name>_<vers>
 *
 * Here <reg name> is something that describes the register. This may not be the
 * exact same as the PPR (processor programming reference); however, the PPR
 * name for the register will be included above it in a comment (though these
 * have sometimes changed from time to time). For example, DF_DRAM_HOLE. If a
 * given register is the same in all currently supported versions, then there is
 * no version suffix appended. Otherwise, the first version it is supported in
 * is appended. For example, DF_DRAM_BASE_V2, DF_DRAM_BASE_V3, DF_DRAM_BASE_V4,
 * etc. or DF_FIDMASK0_V3P5, etc. If the register offset is the same in multiple
 * versions, then there they share the earliest version.
 *
 * For fields there are currently macros to extract these or chain them together
 * leveraging bitx32() and bitset32(). Fields have the forms:
 *
 * DF_<reg name>_<vers>_GET_<field>
 * DF_<reg name>_<vers>_SET_<field>
 *
 * Like in the above, if there are cases where a single field is the same across
 * all versions, then the <vers> portion will be elided. There are many cases
 * where the register definition does not change, but the fields themselves do
 * change with each version because each hardware rev opts to be slightly
 * different.
 *
 * When adding support for a new chip, please look carefully through the
 * requisite documentation to ensure that they match what we see here. There are
 * often cases where there may be a subtle thing or you hit a case like V3P5
 * that until you dig deeper just seem to be weird.
 */

#include <sys/bitext.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum df_rev {
	DF_REV_UNKNOWN	= 0,
	DF_REV_2	= 1 << 0,
	DF_REV_3	= 1 << 1,
	DF_REV_3P5	= 1 << 2,
	DF_REV_4	= 1 << 3,
	/*
	 * This is a synthetic revision we make up per the theory statement that
	 * covers devices that have an updated DRAM layout.
	 */
	DF_REV_4D2	= 1 << 4
} df_rev_t;

#define	DF_REV_ALL_3	(DF_REV_3 | DF_REV_3P5)
#define	DF_REV_ALL_23	(DF_REV_2 | DF_REV_ALL_3)
#define	DF_REV_ALL_4	(DF_REV_4 | DF_REV_4D2)
#define	DF_REV_ALL	(DF_REV_ALL_23 | DF_REV_ALL_4)

typedef struct df_reg_def {
	df_rev_t	drd_gens;
	uint8_t		drd_func;
	uint16_t	drd_reg;
} df_reg_def_t;

/*
 * This set of registers provides us access to the count of instances in the
 * data fabric and then a number of different pieces of information about them
 * like their type. Note, these registers require indirect access because the
 * information cannot be broadcast.
 */

/*
 * DF::FabricBlockInstanceCount -- Describes the number of instances in the data
 * fabric. With v4, also includes versioning information.
 */
/*CSTYLED*/
#define	DF_FBICNT		(df_reg_def_t){ .drd_gens = DF_REV_ALL, \
				    .drd_func = 0, .drd_reg = 0x40 }
#define	DF_FBICNT_V4_GET_MAJOR(r)	bitx32(r, 27, 24)
#define	DF_FBICNT_V4_GET_MINOR(r)	bitx32(r, 23, 16)
#define	DF_FBICNT_GET_COUNT(r)		bitx32(r, 7, 0)

/*
 * DF::FabricBlockInstanceInformation0 -- get basic information about a fabric
 * instance.
 */
/*CSTYLED*/
#define	DF_FBIINFO0		(df_reg_def_t){ .drd_gens = DF_REV_ALL, \
				    .drd_func = 0, .drd_reg = 0x44 }
#define	DF_FBIINFO0_GET_SUBTYPE(r)	bitx32(r, 26, 24)
#define	DF_SUBTYPE_NONE	0
typedef enum {
	DF_CAKE_SUBTYPE_GMI = 1,
	DF_CAKE_SUBTYPE_xGMI = 2
} df_cake_subtype_t;

typedef enum {
	DF_IOM_SUBTYPE_IOHUB = 1,
} df_iom_subtype_t;

typedef enum {
	DF_CS_SUBTYPE_UMC = 1,
	/*
	 * The subtype changed beginning in DFv4. Prior to DFv4, the secondary
	 * type was CCIX. Starting with DFv4, this is now CMP. It is unclear if
	 * these are the same thing or not.
	 */
	DF_CS_SUBTYPE_CCIX = 2,
	DF_CS_SUBTYPE_CMP = 2
} df_cs_subtype_t;

/*
 * Starting in DFv4 they introduced a CCM subtype; however, kept the CPU
 * compatible with prior DF revisions in v4.0. Starting with v4.1, they moved
 * this to a value of one and the less asked about the ACM the better.
 * Unfortunately this doesn't fit nicely with the major DF revisions which we
 * use for register access.
 */
typedef enum {
	DF_CCM_SUBTYPE_CPU_V2 = 0,
	DF_CCM_SUBTYPE_ACM_V4 = 1,
	DF_CCM_SUBTYPE_CPU_V4P1 = 1
} df_ccm_subtype_v4_t;

typedef enum {
	DF_NCM_SUBTYPE_MMHUB = 1,
	DF_NCM_SUBTYPE_DCE = 2,
	DF_NCM_SUBTYPE_IOMMU = 4
} df_ncm_subtype_t;


#define	DF_FBIINFO0_GET_HAS_MCA(r)	bitx32(r, 23, 23)
#define	DF_FBIINFO0_GET_FTI_DCNT(r)	bitx32(r, 21, 20)
#define	DF_FBIINFO0_GET_FTI_PCNT(r)	bitx32(r, 18, 16)
#define	DF_FBIINFO0_GET_SDP_RESPCNT(r)	bitx32(r, 14, 14)
#define	DF_FBIINFO0_GET_SDP_PCNT(r)	bitx32(r, 13, 12)
#define	DF_FBIINFO0_GET_FTI_WIDTH(r)	bitx32(r, 9, 8)
typedef enum {
	DF_FTI_W_64 = 0,
	DF_FTI_W_128,
	DF_FTI_W_256,
	DF_FTI_W_512
} df_fti_width_t;
#define	DF_FBIINFO0_V3_GET_ENABLED(r)	bitx32(r, 6, 6)
#define	DF_FBIINFO0_GET_SDP_WIDTH(r)	bitx32(r, 5, 4)
typedef enum {
	DF_SDP_W_64 = 0,
	DF_SDP_W_128,
	DF_SDP_W_256,
	DF_SDP_W_512
} df_sdp_width_t;
#define	DF_FBIINFO0_GET_TYPE(r)		bitx32(r, 3, 0)
typedef enum {
	DF_TYPE_CCM = 0,
	DF_TYPE_GCM,
	DF_TYPE_NCM,
	DF_TYPE_IOMS,
	DF_TYPE_CS,
	DF_TYPE_NCS,
	DF_TYPE_TCDX,
	DF_TYPE_PIE,
	DF_TYPE_SPF,
	DF_TYPE_LLC,
	DF_TYPE_CAKE,
	DF_TYPE_ICNG,
	DF_TYPE_PFX,
	DF_TYPE_CNLI
} df_type_t;

/*
 * DF::FabricBlockInstanceInformation1 -- get basic information about a fabric
 * instance. This appears to have been dropped starting in DF 4D2.
 */
/*CSTYLED*/
#define	DF_FBIINFO1		(df_reg_def_t){ .drd_gens = DF_REV_ALL_23 | \
				    DF_REV_4, .drd_func = 0, .drd_reg = 0x48 }
#define	DF_FBINFO1_GET_FTI3_NINSTID(r)		bitx32(r, 31, 24)
#define	DF_FBINFO1_GET_FTI2_NINSTID(r)		bitx32(r, 23, 16)
#define	DF_FBINFO1_GET_FTI1_NINSTID(r)		bitx32(r, 15, 8)
#define	DF_FBINFO1_GET_FTI0_NINSTID(r)		bitx32(r, 7, 0)

/*
 * DF::FabricBlockInstanceInformation2 -- get basic information about a fabric
 * instance. This appears to have been dropped starting in DF 4D2.
 */
/*CSTYLED*/
#define	DF_FBIINFO2		(df_reg_def_t){ .drd_gens = DF_REV_ALL_23 | \
				    DF_REV_4, .drd_func = 0, .drd_reg = 0x4c }
#define	DF_FBINFO2_GET_FTI5_NINSTID(r)		bitx32(r, 15, 8)
#define	DF_FBINFO2_GET_FTI4_NINSTID(r)		bitx32(r, 7, 0)

/*
 * DF::FabricBlockInstanceInformation3 -- obtain the basic IDs for a given
 * instance.
 */
/*CSTYLED*/
#define	DF_FBIINFO3		(df_reg_def_t){ .drd_gens = DF_REV_ALL, \
				    .drd_func = 0, .drd_reg = 0x50 }
#define	DF_FBIINFO3_V2_GET_BLOCKID(r)	bitx32(r, 15, 8)
#define	DF_FBIINFO3_V3_GET_BLOCKID(r)	bitx32(r, 13, 8)
#define	DF_FBIINFO3_V3P5_GET_BLOCKID(r)	bitx32(r, 11, 8)
#define	DF_FBIINFO3_V4_GET_BLOCKID(r)	bitx32(r, 19, 8)
#define	DF_FBIINFO3_GET_INSTID(r)	bitx32(r, 7, 0)

/*
 * DF::DfCapability -- Describes the capabilities that the DF has.
 */
/*CSTYLED*/
#define	DF_CAPAB		(df_reg_def_t){ .drd_gens = DF_REV_ALL, \
				    .drd_func = 0, .drd_reg = 0x90 }
#define	DF_CAPAB_GET_EXTCSREMAP(r)	bitx32(r, 2, 2);
#define	DF_CAPAB_GET_SPF(r)		bitx32(r, 1, 1);
#define	DF_CAPAB_GET_POISON(r)		bitx32(r, 0, 0);

/*
 * DF::Skt0CsTargetRemap0, DF::Skt0CsTargetRemap1, DF::Skt1CsTargetRemap0,
 * DF::Skt1CsTargetRemap1 -- The next set of registers provide access to
 * chip-select remapping. Caution, while these have a documented DF generation
 * that they are specific to, it seems they still aren't always implemented and
 * are specific to Milan (v3) and Genoa (v4). The actual remap extraction is the
 * same between both.
 */
#define	DF_CS_REMAP_GET_CSX(r, x)	bitx32(r, (3 + (4 * (x))), (4 * ((x))))
/*CSTYLED*/
#define	DF_SKT0_CS_REMAP0_V3	(df_reg_def_t){ .drd_gens = DF_REV_3, \
				    .drd_func = 0, .drd_reg = 0x60 }
/*CSTYLED*/
#define	DF_SKT1_CS_REMAP0_V3	(df_reg_def_t){ .drd_gens = DF_REV_3, \
				    .drd_func = 0, .drd_reg = 0x68 }
/*CSTYLED*/
#define	DF_SKT0_CS_REMAP1_V3	(df_reg_def_t){ .drd_gens = DF_REV_3, \
				    .drd_func = 0, .drd_reg = 0x64 }
/*CSTYLED*/
#define	DF_SKT1_CS_REMAP1_V3	(df_reg_def_t){ .drd_gens = DF_REV_3, \
				    .drd_func = 0, .drd_reg = 0x6c }
/*
 * DF::CsTargetRemap0A, DF::CsTargetRemap0B, etc. -- These registers contain the
 * remap engines in DFv4. Note, that while v3 used 0/1 as REMAP[01], as
 * referring to the same logical set of things, here [0-3] is used for different
 * things and A/B distinguish the different actual CS values. This was redone to
 * allow for a wider channel selection in the 4D2 parts, see the subsequent
 * section.
 */
/*CSTYLED*/
#define	DF_CS_REMAP0A_V4	(df_reg_def_t){ .drd_gens = DF_REV_4, \
				    .drd_func = 7, .drd_reg = 0x180 }
/*CSTYLED*/
#define	DF_CS_REMAP0B_V4	(df_reg_def_t){ .drd_gens = DF_REV_4, \
				    .drd_func = 7, .drd_reg = 0x184 }
/*CSTYLED*/
#define	DF_CS_REMAP1A_V4	(df_reg_def_t){ .drd_gens = DF_REV_4, \
				    .drd_func = 7, .drd_reg = 0x188 }
/*CSTYLED*/
#define	DF_CS_REMAP1B_V4	(df_reg_def_t){ .drd_gens = DF_REV_4, \
				    .drd_func = 7, .drd_reg = 0x18c }
/*CSTYLED*/
#define	DF_CS_REMAP2A_V4	(df_reg_def_t){ .drd_gens = DF_REV_4, \
				    .drd_func = 7, .drd_reg = 0x190 }
/*CSTYLED*/
#define	DF_CS_REMAP2B_V4	(df_reg_def_t){ .drd_gens = DF_REV_4, \
				    .drd_func = 7, .drd_reg = 0x194 }
/*CSTYLED*/
#define	DF_CS_REMAP3A_V4	(df_reg_def_t){ .drd_gens = DF_REV_4, \
				    .drd_func = 7, .drd_reg = 0x198 }
/*CSTYLED*/
#define	DF_CS_REMAP3B_V4	(df_reg_def_t){ .drd_gens = DF_REV_4, \
				    .drd_func = 7, .drd_reg = 0x19c }

/*
 * DF::CsTargetRemap0A, DF::CsTargetRemap0B, etc. -- D42 edition. This has
 * changed the actual size of the remap values so that they are now 5 bits wide,
 * allowing for up to 32 channels. This is indicated by bit 2 (EXTCSREMAP) in
 * DF::DfCapability. As a result, there are now only 6 remaps per register, so
 * there are now 3 registers [ABC] per remap target [0123].
 * changing around where the registers actually are.
 */
#define	DF_CS_REMAP_GET_CSX_V4B(r, x)	bitx32(r, (4 + (5 * (x))), (5 * ((x))))
/*CSTYLED*/
#define	DF_CS_REMAP0A_V4D2	(df_reg_def_t){ .drd_gens = DF_REV_4D2, \
				    .drd_func = 7, .drd_reg = 0x180 }
/*CSTYLED*/
#define	DF_CS_REMAP0B_V4D2	(df_reg_def_t){ .drd_gens = DF_REV_4D2, \
				    .drd_func = 7, .drd_reg = 0x184 }
/*CSTYLED*/
#define	DF_CS_REMAP0C_V4D2	(df_reg_def_t){ .drd_gens = DF_REV_4D2, \
				    .drd_func = 7, .drd_reg = 0x188 }
/*CSTYLED*/
#define	DF_CS_REMAP1A_V4D2	(df_reg_def_t){ .drd_gens = DF_REV_4D2, \
				    .drd_func = 7, .drd_reg = 0x198 }
/*CSTYLED*/
#define	DF_CS_REMAP1B_V4D2	(df_reg_def_t){ .drd_gens = DF_REV_4D2, \
				    .drd_func = 7, .drd_reg = 0x19c }
/*CSTYLED*/
#define	DF_CS_REMAP1C_V4D2	(df_reg_def_t){ .drd_gens = DF_REV_4D2, \
				    .drd_func = 7, .drd_reg = 0x1a0 }
/*CSTYLED*/
#define	DF_CS_REMAP2A_V4D2	(df_reg_def_t){ .drd_gens = DF_REV_4D2, \
				    .drd_func = 7, .drd_reg = 0x1b0 }
/*CSTYLED*/
#define	DF_CS_REMAP2B_V4D2	(df_reg_def_t){ .drd_gens = DF_REV_4D2, \
				    .drd_func = 7, .drd_reg = 0x1b4 }
/*CSTYLED*/
#define	DF_CS_REMAP2C_V4D2	(df_reg_def_t){ .drd_gens = DF_REV_4D2, \
				    .drd_func = 7, .drd_reg = 0x1b8 }
/*CSTYLED*/
#define	DF_CS_REMAP3A_V4D2	(df_reg_def_t){ .drd_gens = DF_REV_4D2, \
				    .drd_func = 7, .drd_reg = 0x1c8 }
/*CSTYLED*/
#define	DF_CS_REMAP3B_V4D2	(df_reg_def_t){ .drd_gens = DF_REV_4D2, \
				    .drd_func = 7, .drd_reg = 0x1cc }
/*CSTYLED*/
#define	DF_CS_REMAP3C_V4D2	(df_reg_def_t){ .drd_gens = DF_REV_4D2, \
				    .drd_func = 7, .drd_reg = 0x1d0 }

/*
 * DF::CfgAddressCntl -- This register contains the information about the
 * configuration of PCIe buses.  We care about finding which one has our BUS A,
 * which is required to map it to the in-package northbridge instance.
 */
/*CSTYLED*/
#define	DF_CFG_ADDR_CTL_V2	(df_reg_def_t){ .drd_gens = DF_REV_ALL_23, \
				.drd_func = 0, \
				.drd_reg = 0x84 }
/*CSTYLED*/
#define	DF_CFG_ADDR_CTL_V4	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 0, \
				.drd_reg = 0xc04 }
#define	DF_CFG_ADDR_CTL_GET_BUS_NUM(r)	bitx32(r, 7, 0)

/*
 * DF::CfgAddressMap -- This next set of registers covers PCI Bus configuration
 * address maps. The layout here changes at v4. This routes a given PCI bus to a
 * device.
 */
/*CSTYLED*/
#define	DF_CFGMAP_V2(x)		(df_reg_def_t){ .drd_gens = DF_REV_ALL_23, \
				.drd_func = 0, \
				.drd_reg = 0xa0 + ((x) * 4) }
#define	DF_MAX_CFGMAP		8
#define	DF_MAX_CFGMAP_TURIN	16
#define	DF_CFGMAP_V2_GET_BUS_LIMIT(r)		bitx32(r, 31, 24)
#define	DF_CFGMAP_V2_GET_BUS_BASE(r)		bitx32(r, 23, 16)
#define	DF_CFGMAP_V2_GET_DEST_ID(r)		bitx32(r, 11, 4)
#define	DF_CFGMAP_V3_GET_DEST_ID(r)		bitx32(r, 13, 4)
#define	DF_CFGMAP_V3P5_GET_DEST_ID(r)		bitx32(r, 7, 4)
#define	DF_CFGMAP_V2_GET_WE(r)			bitx32(r, 1, 1)
#define	DF_CFGMAP_V2_GET_RE(r)			bitx32(r, 0, 0)

/*
 * DF::CfgBaseAddress, DF::CfgLimitAddress -- DFv4 variants of the above now in
 * two registers and more possible entries!
 */
/*CSTYLED*/
#define	DF_CFGMAP_BASE_V4(x)	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 0, \
				.drd_reg = 0xc80 + ((x) * 8) }
/*CSTYLED*/
#define	DF_CFGMAP_LIMIT_V4(x)	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 0, \
				.drd_reg = 0xc84 + ((x) * 8) }
#define	DF_CFGMAP_BASE_V4_GET_BASE(r)	bitx32(r, 23, 16)
#define	DF_CFGMAP_BASE_V4_GET_SEG(r)	bitx32(r, 15, 8)
#define	DF_CFGMAP_BASE_V4_GET_WE(r)	bitx32(r, 1, 1)
#define	DF_CFGMAP_BASE_V4_GET_RE(r)	bitx32(r, 0, 0)
#define	DF_CFGMAP_LIMIT_V4_GET_LIMIT(r)		bitx32(r, 23, 16)
#define	DF_CFGMAP_LIMIT_V4_GET_DEST_ID(r)	bitx32(r, 11, 0)
#define	DF_CFGMAP_LIMIT_V4D2_GET_DEST_ID(r)	bitx32(r, 7, 0)

/*
 * DF::X86IOBaseAddress, DF::X86IOLimitAddress -- Base and limit registers for
 * routing I/O space. These are fairly similar prior to DFv4. The number of
 * these was increased in Turin. We expect this'll hold true for future server
 * parts.
 */
/*CSTYLED*/
#define	DF_IO_BASE_V2(x)	(df_reg_def_t){ .drd_gens = DF_REV_ALL_23, \
				.drd_func = 0, \
				.drd_reg = 0xc0 + ((x) * 8) }
/*CSTYLED*/
#define	DF_IO_BASE_V4(x)	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 0, \
				.drd_reg = 0xd00 + ((x) * 8) }
#define	DF_MAX_IO_RULES		8
#define	DF_MAX_IO_RULES_TURIN	16
#define	DF_IO_BASE_SHIFT	12
#define	DF_IO_BASE_V2_GET_BASE(r)	bitx32(r, 24, 12)
#define	DF_IO_BASE_V2_GET_IE(r)		bitx32(r, 5, 5)
#define	DF_IO_BASE_V2_GET_WE(r)		bitx32(r, 1, 1)
#define	DF_IO_BASE_V2_GET_RE(r)		bitx32(r, 0, 0)
#define	DF_IO_BASE_V2_SET_BASE(r, v)	bitset32(r, 24, 12, v)
#define	DF_IO_BASE_V2_SET_IE(r, v)	bitset32(r, 5, 5, v)
#define	DF_IO_BASE_V2_SET_WE(r, v)	bitset32(r, 1, 1, v)
#define	DF_IO_BASE_V2_SET_RE(r, v)	bitset32(r, 0, 0, v)

#define	DF_IO_BASE_V4_GET_BASE(r)	bitx32(r, 28, 16)
#define	DF_IO_BASE_V4_GET_IE(r)		bitx32(r, 5, 5)
#define	DF_IO_BASE_V4_GET_WE(r)		bitx32(r, 1, 1)
#define	DF_IO_BASE_V4_GET_RE(r)		bitx32(r, 0, 0)
#define	DF_IO_BASE_V4_SET_BASE(r, v)	bitset32(r, 28, 16, v)
#define	DF_IO_BASE_V4_SET_IE(r, v)	bitset32(r, 5, 5, v)
#define	DF_IO_BASE_V4_SET_WE(r, v)	bitset32(r, 1, 1, v)
#define	DF_IO_BASE_V4_SET_RE(r, v)	bitset32(r, 0, 0, v)

/*CSTYLED*/
#define	DF_IO_LIMIT_V2(x)	(df_reg_def_t){ .drd_gens = DF_REV_ALL_23, \
				.drd_func = 0, \
				.drd_reg = 0xc4 + ((x) * 8) }
/*CSTYLED*/
#define	DF_IO_LIMIT_V4(x)	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 0, \
				.drd_reg = 0xd04 + ((x) * 8) }
#define	DF_MAX_IO_LIMIT		((1 << 24) - 1)
#define	DF_IO_LIMIT_SHIFT	12
#define	DF_IO_LIMIT_EXCL	(1 << DF_IO_LIMIT_SHIFT)
#define	DF_IO_LIMIT_V2_GET_LIMIT(r)	bitx32(r, 24, 12)
#define	DF_IO_LIMIT_V2_GET_DEST_ID(r)	bitx32(r, 7, 0)
#define	DF_IO_LIMIT_V3_GET_DEST_ID(r)	bitx32(r, 9, 0)
#define	DF_IO_LIMIT_V3P5_GET_DEST_ID(r)	bitx32(r, 3, 0)
#define	DF_IO_LIMIT_V2_SET_LIMIT(r, v)		bitset32(r, 24, 12, v)
#define	DF_IO_LIMIT_V2_SET_DEST_ID(r, v)	bitset32(r, 7, 0, v)
#define	DF_IO_LIMIT_V3_SET_DEST_ID(r, v)	bitset32(r, 9, 0, v)
#define	DF_IO_LIMIT_V3P5_SET_DEST_ID(r, v)	bitset32(r, 3, 0, v)

#define	DF_IO_LIMIT_V4_GET_LIMIT(r)	bitx32(r, 28, 16)
#define	DF_IO_LIMIT_V4_GET_DEST_ID(r)	bitx32(r, 11, 0)
#define	DF_IO_LIMIT_V4D2_GET_DEST_ID(r)	bitx32(r, 7, 0)
#define	DF_IO_LIMIT_V4_SET_LIMIT(r, v)		bitset32(r, 28, 16, v)
#define	DF_IO_LIMIT_V4_SET_DEST_ID(r, v)	bitset32(r, 11, 0, v)
#define	DF_IO_LIMIT_V4D2_SET_DEST_ID(r, v)	bitset32(r, 7, 0, v)

/*
 * DF::DramHoleControl -- This controls MMIO below 4 GiB. Note, both this and
 * the Top of Memory (TOM) need to be set consistently.
 */
/*CSTYLED*/
#define	DF_DRAM_HOLE_V2		(df_reg_def_t){ .drd_gens = DF_REV_ALL_23, \
				.drd_func = 0, \
				.drd_reg = 0x104 }
/*CSTYLED*/
#define	DF_DRAM_HOLE_V4		(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 7, \
				.drd_reg = 0x104 }
#define	DF_DRAM_HOLE_GET_BASE(r)	bitx32(r, 31, 24)
#define	DF_DRAM_HOLE_BASE_SHIFT		24
#define	DF_DRAM_HOLE_GET_VALID(r)	bitx32(r, 0, 0)

/*
 * DF::DramBaseAddress, DF::DramLimitAddress -- DRAM rules, these are split into
 * a base and limit. While DFv2, 3, and 3.5 all have the same addresses, they
 * have different bit patterns entirely. DFv4 is in a different location and
 * further splits this into four registers. We do all of the pre-DFv4 stuff and
 * follow with DFv4. In DFv2-3.5 the actual values of the bits (e.g. the meaning
 * of the channel interleave value) are the same, even though where those bits
 * are in the register changes.
 *
 * In DF v2, v3, and v3.5 the set of constants for interleave values are the
 * same, so we define them once at the v2 version.
 */
/*CSTYLED*/
#define	DF_DRAM_BASE_V2(r)	(df_reg_def_t){ .drd_gens = DF_REV_ALL_23, \
				.drd_func = 0, \
				.drd_reg = 0x110 + ((r) * 8) }
#define	DF_DRAM_BASE_V2_GET_BASE(r)		bitx32(r, 31, 12)
#define	DF_DRAM_BASE_V2_BASE_SHIFT		28
#define	DF_DRAM_BASE_V2_GET_ILV_ADDR(r)		bitx32(r, 10, 8)
#define	DF_DRAM_BASE_V2_GET_ILV_CHAN(r)		bitx32(r, 7, 4)
#define	DF_DRAM_BASE_V2_ILV_CHAN_1		0x0
#define	DF_DRAM_BASE_V2_ILV_CHAN_2		0x1
#define	DF_DRAM_BASE_V2_ILV_CHAN_4		0x3
#define	DF_DRAM_BASE_V2_ILV_CHAN_8		0x5
#define	DF_DRAM_BASE_V2_ILV_CHAN_6		0x6
#define	DF_DRAM_BASE_V2_ILV_CHAN_COD4_2		0xc
#define	DF_DRAM_BASE_V2_ILV_CHAN_COD2_4		0xd
#define	DF_DRAM_BASE_V2_ILV_CHAN_COD1_8		0xe
#define	DF_DRAM_BASE_V2_GET_HOLE_EN(r)		bitx32(r, 1, 1)
#define	DF_DRAM_BASE_V2_GET_VALID(r)		bitx32(r, 0, 0)

#define	DF_DRAM_BASE_V3_GET_ILV_ADDR(r)		bitx32(r, 11, 9)
#define	DF_DRAM_BASE_V3_GET_ILV_SOCK(r)		bitx32(r, 8, 8)
#define	DF_DRAM_BASE_V3_GET_ILV_DIE(r)		bitx32(r, 7, 6)
#define	DF_DRAM_BASE_V3_GET_ILV_CHAN(r)		bitx32(r, 5, 2)

#define	DF_DRAM_BASE_V3P5_GET_ILV_ADDR(r)	bitx32(r, 11, 9)
#define	DF_DRAM_BASE_V3P5_GET_ILV_SOCK(r)	bitx32(r, 8, 8)
#define	DF_DRAM_BASE_V3P5_GET_ILV_DIE(r)	bitx32(r, 7, 7)
#define	DF_DRAM_BASE_V3P5_GET_ILV_CHAN(r)	bitx32(r, 6, 2)

/*
 * Shared definitions for the DF DRAM interleaving address start bits. While the
 * bitfield / register definition is different between DFv2/3/3.5 and DFv4, the
 * actual contents of the base address register and the base are shared.
 */
#define	DF_DRAM_ILV_ADDR_8		0
#define	DF_DRAM_ILV_ADDR_9		1
#define	DF_DRAM_ILV_ADDR_10		2
#define	DF_DRAM_ILV_ADDR_11		3
#define	DF_DRAM_ILV_ADDR_12		4
#define	DF_DRAM_ILV_ADDR_BASE		8

/*CSTYLED*/
#define	DF_DRAM_LIMIT_V2(r)	(df_reg_def_t){ .drd_gens = DF_REV_ALL_23, \
				.drd_func = 0, \
				.drd_reg = 0x114 + ((r) * 8) }
#define	DF_DRAM_LIMIT_V2_GET_LIMIT(r)		bitx32(r, 31, 12)
#define	DF_DRAM_LIMIT_V2_LIMIT_SHIFT		28
#define	DF_DRAM_LIMIT_V2_LIMIT_EXCL		(1 << 28)
/* These are in the base register for v3, v3.5 */
#define	DF_DRAM_LIMIT_V2_GET_ILV_DIE(r)		bitx32(r, 11, 10)
#define	DF_DRAM_LIMIT_V2_GET_ILV_SOCK(r)	bitx32(r, 8, 8)
#define	DF_DRAM_LIMIT_V2_GET_DEST_ID(r)		bitx32(r, 7, 0)

#define	DF_DRAM_LIMIT_V3_GET_BUS_BREAK(r)	bitx32(r, 10, 10)
#define	DF_DRAM_LIMIT_V3_GET_DEST_ID(r)		bitx32(r, 9, 0)

#define	DF_DRAM_LIMIT_V3P5_GET_DEST_ID(r)	bitx32(r, 3, 0)

/*
 * DF::DramBaseAddress, DF::DramLimitAddress, DF::DramAddressCtl,
 * DF::DramAddressIntlv  -- DFv4 edition. Here all the controls around the
 * target, interleaving, hashing, and more is split out from the base and limit
 * registers and put into dedicated control and interleave registers.
 *
 * In the 4D2 variant, the base and limit are the same, just at different
 * addresses. The control register is subtly different with additional
 * interleave options.
 */
/*CSTYLED*/
#define	DF_DRAM_BASE_V4(x)	(df_reg_def_t){ .drd_gens = DF_REV_4, \
				.drd_func = 7, \
				.drd_reg = 0xe00 + ((x) * 0x10) }
/*CSTYLED*/
#define	DF_DRAM_BASE_V4D2(x)	(df_reg_def_t){ .drd_gens = DF_REV_4D2, \
				.drd_func = 7, \
				.drd_reg = 0x200 + ((x) * 0x10) }
#define	DF_DRAM_BASE_V4_GET_ADDR(r)		bitx32(r, 27, 0)
#define	DF_DRAM_BASE_V4_BASE_SHIFT		28
/*CSTYLED*/
#define	DF_DRAM_LIMIT_V4(x)	(df_reg_def_t){ .drd_gens = DF_REV_4, \
				.drd_func = 7, \
				.drd_reg = 0xe04 + ((x) * 0x10) }
/*CSTYLED*/
#define	DF_DRAM_LIMIT_V4D2(x)	(df_reg_def_t){ .drd_gens = DF_REV_4D2, \
				.drd_func = 7, \
				.drd_reg = 0x204 + ((x) * 0x10) }
#define	DF_DRAM_LIMIT_V4_GET_ADDR(r)		bitx32(r, 27, 0)
#define	DF_DRAM_LIMIT_V4_LIMIT_SHIFT		28
#define	DF_DRAM_LIMIT_V4_LIMIT_EXCL		(1 << 28)

/*CSTYLED*/
#define	DF_DRAM_CTL_V4(x)	(df_reg_def_t){ .drd_gens = DF_REV_4, \
				.drd_func = 7, \
				.drd_reg = 0xe08 + ((x) * 0x10) }
/*CSTYLED*/
#define	DF_DRAM_CTL_V4D2(x)	(df_reg_def_t){ .drd_gens = DF_REV_4D2, \
				.drd_func = 7, \
				.drd_reg = 0x208 + ((x) * 0x10) }
#define	DF_DRAM_CTL_V4_GET_DEST_ID(r)		bitx32(r, 27, 16)
#define	DF_DRAM_CTL_V4D2_GET_DEST_ID(r)		bitx32(r, 23, 16)
#define	DF_DRAM_CTL_V4D2_GET_HASH_1T(r)		bitx32(r, 15, 15)
/*
 * It seems that this was added in DF V4.1 (no relation to 4D2). It was reserved
 * prior to this, so we leave it without a version suffix for now.
 */
#define	DF_DRAM_CTL_V4_GET_COL_SWIZ(r)		bitx32(r, 11, 11)
#define	DF_DRAM_CTL_V4_GET_HASH_1G(r)		bitx32(r, 10, 10)
#define	DF_DRAM_CTL_V4_GET_HASH_2M(r)		bitx32(r, 9, 9)
#define	DF_DRAM_CTL_V4_GET_HASH_64K(r)		bitx32(r, 8, 8)
#define	DF_DRAM_CTL_V4D2_GET_HASH_4K(r)		bitx32(r, 7, 7)
#define	DF_DRAM_CTL_V4_GET_REMAP_SEL(r)		bitx32(r, 7, 5)
#define	DF_DRAM_CTL_V4D2_GET_REMAP_SEL(r)	bitx32(r, 6, 5)
#define	DF_DRAM_CTL_V4_GET_REMAP_EN(r)		bitx32(r, 4, 4)
#define	DF_DRAM_CTL_V4_GET_SCM(r)		bitx32(r, 2, 2)
#define	DF_DRAM_CTL_V4_GET_HOLE_EN(r)		bitx32(r, 1, 1)
#define	DF_DRAM_CTL_V4_GET_VALID(r)		bitx32(r, 0, 0)

/*CSTYLED*/
#define	DF_DRAM_ILV_V4(x)	(df_reg_def_t){ .drd_gens = DF_REV_4, \
				.drd_func = 7, \
				.drd_reg = 0xe0c + ((x) * 0x10) }
/*CSTYLED*/
#define	DF_DRAM_ILV_V4D2(x)	(df_reg_def_t){ .drd_gens = DF_REV_4D2, \
				.drd_func = 7, \
				.drd_reg = 0x20c + ((x) * 0x10) }
#define	DF_DRAM_ILV_V4_GET_SOCK(r)		bitx32(r, 18, 18)
#define	DF_DRAM_ILV_V4_GET_DIE(r)		bitx32(r, 13, 12)
/*
 * We're cheating a bit here. We combine the various different non-overlapping
 * values in the 4D2 variants. In particular, most client parts stick to the
 * first few values while the rest are sometimes used in the moniker "DF 4.5".
 */
#define	DF_DRAM_ILV_V4D2_GET_CHAN(r)		bitx32(r, 9, 4)
#define	DF_DRAM_ILV_V4D2_CHAN_1			0x0
#define	DF_DRAM_ILV_V4D2_CHAN_2			0x1
#define	DF_DRAM_ILV_V4D2_CHAN_4			0x3
#define	DF_DRAM_ILV_V4D2_CHAN_NPS1_16S8CH_1K	0xc
#define	DF_DRAM_ILV_V4D2_CHAN_NPS0_24CH_1K	0xe
#define	DF_DRAM_ILV_V4D2_CHAN_NPS4_2CH_1K	0x10
#define	DF_DRAM_ILV_V4D2_CHAN_NPS2_4CH_1K	0x11
#define	DF_DRAM_ILV_V4D2_CHAN_NPS1_8S4CH_1K	0x12
#define	DF_DRAM_ILV_V4D2_CHAN_NPS4_3CH_1K	0x13
#define	DF_DRAM_ILV_V4D2_CHAN_NPS2_6CH_1K	0x14
#define	DF_DRAM_ILV_V4D2_CHAN_NPS1_12CH_1K	0x15
#define	DF_DRAM_ILV_V4D2_CHAN_NPS2_5CH_1K	0x16
#define	DF_DRAM_ILV_V4D2_CHAN_NPS1_10CH_1K	0x17
#define	DF_DRAM_ILV_V4D2_CHAN_NPS4_2CH_2K	0x20
#define	DF_DRAM_ILV_V4D2_CHAN_NPS2_4CH_2K	0x21
#define	DF_DRAM_ILV_V4D2_CHAN_NPS1_8S4CH_2K	0x22
#define	DF_DRAM_ILV_V4D2_CHAN_NPS1_16S8CH_2K	0x23
#define	DF_DRAM_ILV_V4D2_CHAN_NPS4_3CH_2K	0x24
#define	DF_DRAM_ILV_V4D2_CHAN_NPS2_6CH_2K	0x25
#define	DF_DRAM_ILV_V4D2_CHAN_NPS1_12CH_2K	0x26
#define	DF_DRAM_ILV_V4D2_CHAN_NPS0_24CH_2K	0x27
#define	DF_DRAM_ILV_V4D2_CHAN_NPS2_5CH_2K	0x28
#define	DF_DRAM_ILV_V4D2_CHAN_NPS2_10CH_2K	0x29
#define	DF_DRAM_ILV_V4_GET_CHAN(r)		bitx32(r, 8, 4)
#define	DF_DRAM_ILV_V4_CHAN_1			0x0
#define	DF_DRAM_ILV_V4_CHAN_2			0x1
#define	DF_DRAM_ILV_V4_CHAN_4			0x3
#define	DF_DRAM_ILV_V4_CHAN_8			0x5
#define	DF_DRAM_ILV_V4_CHAN_16			0x7
#define	DF_DRAM_ILV_V4_CHAN_32			0x8
#define	DF_DRAM_ILV_V4_CHAN_NPS4_2CH		0x10
#define	DF_DRAM_ILV_V4_CHAN_NPS2_4CH		0x11
#define	DF_DRAM_ILV_V4_CHAN_NPS1_8CH		0x12
#define	DF_DRAM_ILV_V4_CHAN_NPS4_3CH		0x13
#define	DF_DRAM_ILV_V4_CHAN_NPS2_6CH		0x14
#define	DF_DRAM_ILV_V4_CHAN_NPS1_12CH		0x15
#define	DF_DRAM_ILV_V4_CHAN_NPS2_5CH		0x16
#define	DF_DRAM_ILV_V4_CHAN_NPS1_10CH		0x17
#define	DF_DRAM_ILV_V4_GET_ADDR(r)		bitx32(r, 2, 0)

/*
 * DF::DramOffset --  These exist only for CS entries, e.g. a UMC. There is
 * generally only one of these in Zen 1-3. This register changes in Zen 4 and
 * there are up to 3 instances there. This register corresponds to each DRAM
 * rule that the UMC has starting at the second one. This is because the first
 * DRAM rule in a channel always is defined to start at offset 0, so there is no
 * entry here.
 */
/*CSTYLED*/
#define	DF_DRAM_OFFSET_V2	(df_reg_def_t){ .drd_gens = DF_REV_ALL_23, \
				.drd_func = 0, \
				.drd_reg = 0x1b4 }
/*CSTYLED*/
#define	DF_DRAM_OFFSET_V4(r)	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 7, \
				.drd_reg = 0x140 + ((r) * 4) }
#define	DF_DRAM_OFFSET_V2_GET_OFFSET(r)		bitx32(r, 31, 20)
#define	DF_DRAM_OFFSET_V3_GET_OFFSET(r)		bitx32(r, 31, 12)
#define	DF_DRAM_OFFSET_V4_GET_OFFSET(r)		bitx32(r, 24, 1)
#define	DF_DRAM_OFFSET_SHIFT			28
#define	DF_DRAM_OFFSET_GET_EN(r)		bitx32(r, 0, 0)

/*
 * DF::VGAEn -- This controls whether or not the historical x86 VGA
 * compatibility region is enabled or not.
 */
/*CSTYLED*/
#define	DF_VGA_EN_V2		(df_reg_def_t){ .drd_gens = DF_REV_ALL_23, \
				.drd_func = 0, \
				.drd_reg = 0x80 }
/*CSTYLED*/
#define	DF_VGA_EN_V4		(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 0, \
				.drd_reg = 0xc08 }

#define	DF_VGA_EN_GET_FABID(r)		bitx32(r, 15, 4)
#define	DF_VGA_EN_GET_CPUDIS(r)		bitx32(r, 2, 2)
#define	DF_VGA_EN_GET_NP(r)		bitx32(r, 1, 1)
#define	DF_VGA_EN_GET_EN(r)		bitx32(r, 0, 0)

/*
 * DF::MmioPciCfgBaseAddr, DF::MmioPciCfgBaseAddrExt, DF::MmioPciCfgLimitAddr,
 * DF::MmioPciCfgLimitAddrExt -- These are DFv4 additions that control where PCI
 * extended configuration space is and whether or not the DF honors this. This
 * must match the values programmed into the CPU. Prior to DFv4, there was not a
 * DF setting for this. The encoded values of the base and limit are the same.
 */
/*CSTYLED*/
#define	DF_ECAM_BASE_V4		(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 0, \
				.drd_reg = 0xc10 }
/*CSTYLED*/
#define	DF_ECAM_BASE_EXT_V4	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 0, \
				.drd_reg = 0xc14 }
/*CSTYLED*/
#define	DF_ECAM_LIMIT_V4		(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 0, \
				.drd_reg = 0xc18 }
/*CSTYLED*/
#define	DF_ECAM_LIMIT_EXT_V4	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 0, \
				.drd_reg = 0xc1c }
#define	DF_ECAM_V4_GET_ADDR(r)		bitx32(r, 31, 20)
#define	DF_ECAM_V4_ADDR_SHIFT		20
#define	DF_ECAM_LIMIT_EXCL		(1 << DF_ECAM_V4_ADDR_SHIFT)
#define	DF_ECAM_BASE_V4_GET_EN(r)	bitx32(r, 0, 0)
#define	DF_ECAM_EXT_V4_GET_ADDR(r)	bitx32(r, 23, 0)
#define	DF_ECAM_EXT_V4_ADDR_SHIFT	32

/*
 * DF::MmioBaseAddress, DF::MmioLimitAddress, DF::MmioAddressControl -- These
 * control the various MMIO rules for a given system.
 */
/*CSTYLED*/
#define	DF_MMIO_BASE_V2(x)	(df_reg_def_t){ .drd_gens = DF_REV_ALL_23, \
				.drd_func = 0, \
				.drd_reg = 0x200 + ((x) * 0x10) }
/*CSTYLED*/
#define	DF_MMIO_LIMIT_V2(x)	(df_reg_def_t){ .drd_gens = DF_REV_ALL_23, \
				.drd_func = 0, \
				.drd_reg = 0x204 + ((x) * 0x10) }
/*CSTYLED*/
#define	DF_MMIO_BASE_V4(x)	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 0, \
				.drd_reg = 0xd80 + ((x) * 0x10) }
/*CSTYLED*/
#define	DF_MMIO_LIMIT_V4(x)	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 0, \
				.drd_reg = 0xd84 + ((x) * 0x10) }
#define	DF_MMIO_SHIFT		16
#define	DF_MMIO_LIMIT_EXCL	(1 << DF_MMIO_SHIFT)
#define	DF_MAX_MMIO_RULES	16
#define	DF_MAX_MMIO_RULES_TURIN	32
/*CSTYLED*/
#define	DF_MMIO_CTL_V2(x)	(df_reg_def_t){ .drd_gens = DF_REV_ALL_23, \
				.drd_func = 0, \
				.drd_reg = 0x208 + ((x) * 0x10) }
/*CSTYLED*/
#define	DF_MMIO_CTL_V4(x)	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 0, \
				.drd_reg = 0xd88 + ((x) * 0x10) }
#define	DF_MMIO_CTL_V2_GET_NP(r)	bitx32(r, 12, 12)
#define	DF_MMIO_CTL_V2_GET_DEST_ID(r)	bitx32(r, 11, 4)
#define	DF_MMIO_CTL_V2_SET_NP(r, v)		bitset32(r, 12, 12, v)
#define	DF_MMIO_CTL_V2_SET_DEST_ID(r, v)	bitset32(r, 11, 4, v)

#define	DF_MMIO_CTL_V3_GET_NP(r)	bitx32(r, 16, 16)
#define	DF_MMIO_CTL_V3_GET_DEST_ID(r)	bitx32(r, 13, 4)
#define	DF_MMIO_CTL_V3P5_GET_DEST_ID(r)	bitx32(r, 7, 4)
#define	DF_MMIO_CTL_V3_SET_NP(r, v)		bitset32(r, 16, 16, v)
#define	DF_MMIO_CTL_V3_SET_DEST_ID(r, v)	bitset32(r, 13, 4, v)
#define	DF_MMIO_CTL_V3P5_SET_DEST_ID(r, v)	bitset32(r, 7, 4, v)

#define	DF_MMIO_CTL_V4_GET_DEST_ID(r)	bitx32(r, 27, 16)
#define	DF_MMIO_CTL_V4D2_GET_DEST_ID(r)	bitx32(r, 23, 16)
#define	DF_MMIO_CTL_V4_GET_NP(r)	bitx32(r, 3, 3)
#define	DF_MMIO_CTL_V4_SET_DEST_ID(r, v)	bitset32(r, 27, 16, v)
#define	DF_MMIO_CTL_V4D2_SET_DEST_ID(r, v)	bitset32(r, 23, 16, v)
#define	DF_MMIO_CTL_V4_SET_NP(r, v)		bitset32(r, 3, 3, v)

#define	DF_MMIO_CTL_GET_CPU_DIS(r)	bitx32(r, 2, 2)
#define	DF_MMIO_CTL_GET_WE(r)		bitx32(r, 1, 1)
#define	DF_MMIO_CTL_GET_RE(r)		bitx32(r, 0, 0)
#define	DF_MMIO_CTL_SET_CPU_DIS(r, v)		bitset32(r, 2, 2, v)
#define	DF_MMIO_CTL_SET_WE(r, v)		bitset32(r, 1, 1, v)
#define	DF_MMIO_CTL_SET_RE(r, v)		bitset32(r, 0, 0, v)

/*
 * DF::MmioExtAddress -- New in DFv4, this allows extending the number of bits
 * used for MMIO.
 */
/*CSTYLED*/
#define	DF_MMIO_EXT_V4(x)	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 0, \
				.drd_reg = 0xd8c + ((x) * 0x10) }
#define	DF_MMIO_EXT_V4_GET_LIMIT(r)	bitx32(r, 23, 16)
#define	DF_MMIO_EXT_V4_GET_BASE(r)	bitx32(r, 7, 0)
#define	DF_MMIO_EXT_V4_SET_LIMIT(r)	bitset32(r, 23, 16)
#define	DF_MMIO_EXT_V4_SET_BASE(r)	bitset32(r, 7, 0)
#define	DF_MMIO_EXT_SHIFT		48

/*
 * DF::DfGlobalCtrl -- This register we generally only care about in the
 * DFv3/3.5 timeframe when it has the actual hash controls, hence its current
 * definition. It technically exists in DFv2/v4, but is not relevant.
 */
/*CSTYLED*/
#define	DF_GLOB_CTL_V3		(df_reg_def_t){ .drd_gens = DF_REV_ALL_3, \
				.drd_func = 0, \
				.drd_reg = 0x3F8 }
#define	DF_GLOB_CTL_V3_GET_HASH_1G(r)	bitx32(r, 22, 22)
#define	DF_GLOB_CTL_V3_GET_HASH_2M(r)	bitx32(r, 21, 21)
#define	DF_GLOB_CTL_V3_GET_HASH_64K(r)	bitx32(r, 20, 20)

/*
 * DF::SystemCfg -- This register describes the basic information about the data
 * fabric that we're talking to. Don't worry, this is different in every
 * generation, even when the address is the same. Somehow despite all these
 * differences the actual things like defined types are somehow the same.
 */
typedef enum {
	DF_DIE_TYPE_CPU	= 0,
	DF_DIE_TYPE_APU,
	DF_DIE_TYPE_dGPU
} df_die_type_t;

/*CSTYLED*/
#define	DF_SYSCFG_V2		(df_reg_def_t){ .drd_gens = DF_REV_2, \
				.drd_func = 1, \
				.drd_reg = 0x200 }
#define	DF_SYSCFG_V2_GET_SOCK_ID(r)	bitx32(r, 27, 27)
#define	DF_SYSCFG_V2_GET_DIE_ID(r)	bitx32(r, 25, 24)
#define	DF_SYSCFG_V2_GET_MY_TYPE(r)	bitx32(r, 22, 21)
#define	DF_SYSCFG_V2_GET_LOCAL_IS_ME(r)	bitx32(r, 19, 16)
#define	DF_SYSCFG_V2_GET_LOCAL_TYPE3(r)	bitx32(r, 13, 12)
#define	DF_SYSCFG_V2_GET_LOCAL_TYPE2(r)	bitx32(r, 11, 10)
#define	DF_SYSCFG_V2_GET_LOCAL_TYPE1(r)	bitx32(r, 9, 8)
#define	DF_SYSCFG_V2_GET_LOCAL_TYPE0(r)	bitx32(r, 7, 6)
#define	DF_SYSCFG_V2_GET_OTHER_SOCK(r)	bitx32(r, 5, 5)
#define	DF_SYSCFG_V2_GET_DIE_PRESENT(r)	bitx32(r, 4, 0)
#define	DF_SYSCFG_V2_DIE_PRESENT(x)	bitx32(r, 3, 0)

/*CSTYLED*/
#define	DF_SYSCFG_V3		(df_reg_def_t){ .drd_gens = DF_REV_3, \
				.drd_func = 1, \
				.drd_reg = 0x200 }
#define	DF_SYSCFG_V3_GET_NODE_ID(r)	bitx32(r, 30, 28)
#define	DF_SYSCFG_V3_GET_OTHER_SOCK(r)	bitx32(r, 27, 27)
#define	DF_SYSCFG_V3_GET_OTHER_TYPE(r)	bitx32(r, 26, 25)
#define	DF_SYSCFG_V3_GET_MY_TYPE(r)	bitx32(r, 24, 23)
#define	DF_SYSCFG_V3_GET_DIE_TYPE(r)	bitx32(r, 18, 11)
#define	DF_SYSCFG_V3_GET_DIE_PRESENT(r)	bitx32(r, 7, 0)

/*CSTYLED*/
#define	DF_SYSCFG_V3P5		(df_reg_def_t){ .drd_gens = DF_REV_3P5, \
				.drd_func = 1, \
				.drd_reg = 0x140 }
#define	DF_SYSCFG_V3P5_GET_NODE_ID(r)		bitx32(r, 19, 16)
#define	DF_SYSCFG_V3P5_GET_OTHER_SOCK(r)	bitx32(r, 8, 8)
#define	DF_SYSCFG_V3P5_GET_NODE_MAP(r)		bitx32(r, 4, 4)
#define	DF_SYSCFG_V3P5_GET_OTHER_TYPE(r)	bitx32(r, 3, 2)
#define	DF_SYSCFG_V3P5_GET_MY_TYPE(r)		bitx32(r, 1, 0)

/*CSTYLED*/
#define	DF_SYSCFG_V4		(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 4, \
				.drd_reg = 0x180 }
#define	DF_SYSCFG_V4_GET_NODE_ID(r)	bitx32(r, 27, 16)
#define	DF_SYSCFG_V4_GET_OTHER_SOCK(r)	bitx32(r, 8, 8)
#define	DF_SYSCFG_V4_GET_NODE_MAP(r)	bitx32(r, 4, 4)
#define	DF_SYSCFG_V4_GET_OTHER_TYPE(r)	bitx32(r, 3, 2)
#define	DF_SYSCFG_V4_GET_MY_TYPE(r)	bitx32(r, 1, 0)

/*
 * DF::SystemComponentCnt -- Has a count of how many things are here. However,
 * this does not seem defined for DFv3.5
 */
/*CSTYLED*/
#define	DF_COMPCNT_V2		(df_reg_def_t){ .drd_gens = DF_REV_ALL_23, \
				.drd_func = 1, \
				.drd_reg = 0x204 }
#define	DF_COMPCNT_V2_GET_IOMS(r)	bitx32(r, 23, 16)
#define	DF_COMPCNT_V2_GET_GCM(r)	bitx32(r, 15, 8)
#define	DF_COMPCNT_V2_GET_PIE(r)	bitx32(r, 7, 0)

/*CSTYLED*/
#define	DF_COMPCNT_V4		(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 4, \
				.drd_reg = 0x184 }
#define	DF_COMPCNT_V4_GET_IOS(r)	bitx32(r, 31, 26)
#define	DF_COMPCNT_V4_GET_GCM(r)	bitx32(r, 25, 16)
#define	DF_COMPCNT_V4_GET_IOM(r)	bitx32(r, 15, 8)
#define	DF_COMPCNT_V4_GET_PIE(r)	bitx32(r, 7, 0)

/*
 * This next section contains a bunch of register definitions for how to take
 * apart ID masks. The register names and sets have changed across every DF
 * revision. This will be done in chunks that define all DFv2, then v3, etc.
 */

/*
 * DF::SystemFabricIdMask -- DFv2 style breakdowns of IDs. Note, unlike others
 * the socket and die shifts are not relative to a node mask, but are global.
 */
/*CSTYLED*/
#define	DF_FIDMASK_V2		(df_reg_def_t){ .drd_gens = DF_REV_2, \
				.drd_func = 1, \
				.drd_reg = 0x208 }
#define	DF_FIDMASK_V2_GET_SOCK_SHIFT(r)		bitx32(r, 31, 28)
#define	DF_FIDMASK_V2_GET_DIE_SHIFT(r)		bitx32(r, 27, 24)
#define	DF_FIDMASK_V2_GET_SOCK_MASK(r)		bitx32(r, 23, 16)
#define	DF_FIDMASK_V2_GET_DIE_MASK(r)		bitx32(r, 15, 8)

/*
 * DF::SystemFabricIdMask0, DF::SystemFabricIdMask1 -- The DFv3 variant of
 * breaking down an ID into bits and shifts. Unlike in DFv2, the socket and die
 * are relative to a node ID. For more, see amdzen_determine_fabric_decomp() in
 * uts/intel/io/amdzen/amdzen.c.
 */
/*CSTYLED*/
#define	DF_FIDMASK0_V3		(df_reg_def_t){ .drd_gens = DF_REV_3, \
				.drd_func = 1, \
				.drd_reg = 0x208 }
#define	DF_FIDMASK0_V3_GET_NODE_MASK(r)		bitx32(r, 25, 16)
#define	DF_FIDMASK0_V3_GET_COMP_MASK(r)		bitx32(r, 9, 0)
/*CSTYLED*/
#define	DF_FIDMASK1_V3		(df_reg_def_t){ .drd_gens = DF_REV_3, \
				.drd_func = 1, \
				.drd_reg = 0x20c }
#define	DF_FIDMASK1_V3_GET_SOCK_MASK(r)		bitx32(r, 26, 24)
#define	DF_FIDMASK1_V3_GET_DIE_MASK(r)		bitx32(r, 18, 16)
#define	DF_FIDMASK1_V3_GET_SOCK_SHIFT(r)	bitx32(r, 9, 8)
#define	DF_FIDMASK1_V3_GET_NODE_SHIFT(r)	bitx32(r, 3, 0)

/*
 * DF::SystemFabricIdMask0, DF::SystemFabricIdMask1, DF::SystemFabricIdMask2 --
 * DFv3.5 and DFv4 have the same format here, but in different registers.
 */
/*CSTYLED*/
#define	DF_FIDMASK0_V3P5	(df_reg_def_t){ .drd_gens = DF_REV_3P5, \
				.drd_func = 1, \
				.drd_reg = 0x150 }
/*CSTYLED*/
#define	DF_FIDMASK0_V4		(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 4, \
				.drd_reg = 0x1b0 }
#define	DF_FIDMASK0_V3P5_GET_NODE_MASK(r)	bitx32(r, 31, 16)
#define	DF_FIDMASK0_V3P5_GET_COMP_MASK(r)	bitx32(r, 15, 0)
/*CSTYLED*/
#define	DF_FIDMASK1_V3P5	(df_reg_def_t){ .drd_gens = DF_REV_3P5, \
				.drd_func = 1, \
				.drd_reg = 0x154 }
/*CSTYLED*/
#define	DF_FIDMASK1_V4		(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 4, \
				.drd_reg = 0x1b4 }
#define	DF_FIDMASK1_V3P5_GET_SOCK_SHIFT(r)	bitx32(r, 11, 8)
#define	DF_FIDMASK1_V3P5_GET_NODE_SHIFT(r)	bitx32(r, 3, 0)
/*CSTYLED*/
#define	DF_FIDMASK2_V3P5	(df_reg_def_t){ .drd_gens = DF_REV_3P5, \
				.drd_func = 1, \
				.drd_reg = 0x158 }
/*CSTYLED*/
#define	DF_FIDMASK2_V4		(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 4, \
				.drd_reg = 0x1b8 }
#define	DF_FIDMASK2_V3P5_GET_SOCK_MASK(r)	bitx32(r, 31, 16)
#define	DF_FIDMASK2_V3P5_GET_DIE_MASK(r)	bitx32(r, 15, 0)

/*
 * DF::DieFabricIdMask -- This is a Zeppelin, DFv2 special. There are a couple
 * instances of this for different types of devices; however, this is where the
 * component mask is actually stored. This is replicated for a CPU, APU, and
 * dGPU, each with slightly different values. We need to look at DF_SYSCFG_V2 to
 * determine which type of die we have and use the appropriate one when looking
 * at this. This makes the Zen 1 CPUs and APUs have explicitly different set up
 * here. Look, it got better in DFv3.
 */
/*CSTYLED*/
#define	DF_DIEMASK_CPU_V2	(df_reg_def_t){ .drd_gens = DF_REV_2, \
				.drd_func = 1, \
				.drd_reg = 0x22c }
/*CSTYLED*/
#define	DF_DIEMASK_APU_V2	(df_reg_def_t){ .drd_gens = DF_REV_2, \
				.drd_func = 1, \
				.drd_reg = 0x24c }
#define	DF_DIEMASK_V2_GET_SOCK_SHIFT(r)		bitx32(r, 31, 28)
#define	DF_DIEMASK_V2_GET_DIE_SHIFT(r)		bitx32(r, 27, 24)
#define	DF_DIEMASK_V2_GET_SOCK_MASK(r)		bitx32(r, 23, 16)
#define	DF_DIEMASK_V2_GET_DIE_MASK(r)		bitx32(r, 15, 8)
#define	DF_DIEMASK_V2_GET_COMP_MASK(r)		bitx32(r, 7, 0)

/*
 * DF::CCDEnable -- This register is present for CCMs and ACMs. Despite its
 * name, the interpretation is not quite straightforward. That is, it only
 * indirectly tells us about whether or not there are two CCDs or not. A CCM
 * port can be in wide mode where its two SDPs (Scalable Data Ports) are in fact
 * instead connected to a single CCD. If wide mode is enabled in DF::CCMConfig4,
 * then a value of 0x3 just indicates that both SDP ports are connected to a
 * single CCD.
 *
 * The CCX related fields are only valid when the dense mode is enabled in the
 * global DF controls. If a CPU doesn't support that, then that field is
 * reserved. We don't generally recommend this as a way of determining if
 * multiple CCX units are present on the CCD because it is tied to DFv4.
 */
#define	DF_MAX_CCDS_PER_CCM	2
/*CSTYLED*/
#define	DF_CCD_EN_V4		(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 1, \
				.drd_reg = 0x104 }
#define	DF_CCD_EN_V4_GET_CCX_EN(r)	bitx32(r, 17, 16)
#define	DF_CCD_EN_V4_GET_CCD_EN(r)	bitx32(r, 1, 0)


/*
 * DF::PhysicalCoreEnable0, etc. -- These registers can be used to tell us which
 * cores are actually enabled. This appears to have been introduced in DFv3.
 * DFv4 expanded this from two registers to several more. The number that are
 * valid vary based upon the CPU family.
 */
/*CSTYLED*/
#define	DF_PHYS_CORE_EN0_V3	(df_reg_def_t){ .drd_gens = DF_REV_ALL_3, \
				.drd_func = 1, \
				.drd_reg = 0x300 }
/*CSTYLED*/
#define	DF_PHYS_CORE_EN1_V3	(df_reg_def_t){ .drd_gens = DF_REV_ALL_3, \
				.drd_func = 1, \
				.drd_reg = 0x304 }
/*CSTYLED*/
#define	DF_PHYS_CORE_EN0_V4	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 1, \
				.drd_reg = 0x140 }
/*CSTYLED*/
#define	DF_PHYS_CORE_EN1_V4	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 1, \
				.drd_reg = 0x144 }
/*CSTYLED*/
#define	DF_PHYS_CORE_EN2_V4	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 1, \
				.drd_reg = 0x148 }
/*CSTYLED*/
#define	DF_PHYS_CORE_EN3_V4	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 1, \
				.drd_reg = 0x14c }
/*CSTYLED*/
#define	DF_PHYS_CORE_EN4_V4	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 1, \
				.drd_reg = 0x150 }
/*CSTYLED*/
#define	DF_PHYS_CORE_EN5_V4	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 1, \
				.drd_reg = 0x154 }

/*
 * DF::Np2ChannelConfig -- This is used in Milan to contain information about
 * how non-power of 2 based channel configuration works. Note, we only know that
 * this exists in Milan (and its ThreadRipper equivalent). We don't believe it
 * is in other DFv3 products like Rome, Matisse, Vermeer, or the APUs.
 */
/*CSTYLED*/
#define	DF_NP2_CONFIG_V3	(df_reg_def_t){ .drd_gens = DF_REV_3, \
				.drd_func = 2, \
				.drd_reg = 0x90 }
#define	DF_NP2_CONFIG_V3_GET_SPACE1(r)		bitx32(r, 13, 8)
#define	DF_NP2_CONFIG_V3_GET_SPACE0(r)		bitx32(r, 5, 0)

/*
 * DF::CCMConfig4 -- This is one of several CCM configuration related registers.
 * This varies in each DF revision. That is, while we've found it does exist in
 * DFv3, it is at a different address and the bits have rather different
 * meanings. A subset of the bits are defined below based upon our needs.
 */
/*CSTYLED*/
#define	DF_CCMCFG4_V4		(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 3, \
				.drd_reg = 0x510 }
#define	DF_CCMCFG4_V4_GET_WIDE_EN(r)		bitx32(r, 26, 26)

/*
 * DF::FabricIndirectConfigAccessAddress, DF::FabricIndirectConfigAccessDataLo,
 * DF::FabricIndirectConfigAccessDataHi --  These registers are used to define
 * Indirect Access, commonly known as FICAA and FICAD for the system. While
 * there are multiple copies of the indirect access registers in device 4, we're
 * only allowed access to one set of those (which are the ones present here).
 * Specifically the OS is given access to set 3.
 */
/*CSTYLED*/
#define	DF_FICAA_V2		(df_reg_def_t){ .drd_gens = DF_REV_ALL_23, \
				.drd_func = 4, \
				.drd_reg = 0x5c }
/*CSTYLED*/
#define	DF_FICAA_V4		(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 4, \
				.drd_reg = 0x8c }
#define	DF_FICAA_V2_SET_INST(r, v)		bitset32(r, 23, 16, v)
#define	DF_FICAA_V2_SET_64B(r, v)		bitset32(r, 14, 14, v)
#define	DF_FICAA_V2_SET_FUNC(r, v)		bitset32(r, 13, 11, v)
#define	DF_FICAA_V2_SET_REG(r, v)		bitset32(r, 10, 2, v)
#define	DF_FICAA_V2_SET_TARG_INST(r, v)		bitset32(r, 0, 0, v)

#define	DF_FICAA_V4_SET_REG(r, v)		bitset32(r, 10, 1, v)

/*CSTYLED*/
#define	DF_FICAD_LO_V2		(df_reg_def_t){ .drd_gens = DF_REV_ALL_23, \
				.drd_func = 4, \
				.drd_reg = 0x98}
/*CSTYLED*/
#define	DF_FICAD_HI_V2		(df_reg_def_t){ .drd_gens = DF_REV_ALL_23, \
				.drd_func = 4, \
				.drd_reg = 0x9c}
/*CSTYLED*/
#define	DF_FICAD_LO_V4		(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 4, \
				.drd_reg = 0xb8}
/*CSTYLED*/
#define	DF_FICAD_HI_V4		(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 4, \
				.drd_reg = 0xbc}

/*
 * DF::SpecialSysFunctionFabricID1, DF::SpecialSysFunctionFabricID2 -- These
 * registers are used to look up the FabricID of various functional groups.
 * These exist in DFv3 and DFv4 at different addresses with slightly different
 * field widths.
 */
/*CSTYLED*/
#define	DF_SYS_FUN_FID1_V3	(df_reg_def_t){ .drd_gens = DF_REV_ALL_3, \
				.drd_func = 1, \
				.drd_reg = 0x60 }
#define	DF_SYS_FUN_FID1_V3_GET_MSTR_PIE_FID(r)		bitx32(r, 21, 16)
#define	DF_SYS_FUN_FID1_V3_GET_LCL_PIE_FID(r)		bitx32(r, 5, 0)

/*CSTYLED*/
#define	DF_SYS_FUN_FID1_V4	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 4, \
				.drd_reg = 0x190 }
#define	DF_SYS_FUN_FID1_V4_GET_MSTR_PIE_FID(r)		bitx32(r, 27, 16)
#define	DF_SYS_FUN_FID1_V4D2_GET_MSTR_PIE_FID(r)	bitx32(r, 23, 16)
#define	DF_SYS_FUN_FID1_V4_GET_LCL_PIE_FID(r)		bitx32(r, 11, 0)
#define	DF_SYS_FUN_FID1_V4D2_GET_LCL_PIE_FID(r)		bitx32(r, 7, 0)

/*CSTYLED*/
#define	DF_SYS_FUN_FID2_V3	(df_reg_def_t){ .drd_gens = DF_REV_ALL_3, \
				.drd_func = 1, \
				.drd_reg = 0x64 }
#define	DF_SYS_FUN_FID2_V3_GET_FCH_IOMS_FID(r)		bitx32(r, 21, 16)
#define	DF_SYS_FUN_FID2_V3_GET_LCL_IOMS_FID(r)		bitx32(r, 5, 0)

/*CSTYLED*/
#define	DF_SYS_FUN_FID2_V4	(df_reg_def_t){ .drd_gens = DF_REV_ALL_4, \
				.drd_func = 4, \
				.drd_reg = 0x194 }
#define	DF_SYS_FUN_FID2_V4_GET_FCH_IOS_FID(r)		bitx32(r, 27, 16)
#define	DF_SYS_FUN_FID2_V4D2_GET_FCH_IOS_FID(r)		bitx32(r, 23, 16)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_AMDZEN_DF_H */
