/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 */
/*
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SCAT_DCD_H
#define	_SCAT_DCD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains definitions of the structures gdcd_t and ldcd_t,
 * Global and Local Domain Configuration Descriptors and the various
 * substructures they contain.
 * The gdcd is the information handed off to OBP and the OS by POST
 * in the "golden" I/O SRAM of a domain in Sun Fire 15000 systems.
 * The ldcd contains information about the two ports local to each
 * sram, kept in that local sram, to support DR operations.
 */

#include <sys/types.h>

#include <post/scat_const.h>
#include <post/scat_asicbrd_types.h>


#ifdef __cplusplus
extern "C" {
#endif

#define	DCD_VERSION 4


#define	GDCD_MAGIC (('G'<< 24) | ('D'<< 16) | ('C'<< 8) | 'D')
#define	LDCD_MAGIC (('L'<< 24) | ('D'<< 16) | ('C'<< 8) | 'D')


#define	PMBANKS_PER_PORT	2
#define	LMBANKS_PER_PMBANK	2
#define	IOBUS_PER_PORT		2
#define	IOCARD_PER_BUS		4	/* 1 currently, but could change */
#define	LINKS_PER_PORT		5	/* 3 in current hardware */
#define	DIMMS_PER_PORT		8
#define	DIMMS_PER_PMBANK	4
#define	ECDIMMS_PER_PORT	2

	/*
	 * This is intended to handle Jubatus8X - up to 8 CPU cores
	 * within one Safari port.
	 */
#define	SAF_AGENT_PER_PORT	8

	/*
	 * The most significant element of the otherwise unused
	 * prd_t.prd_wic_links[LINKS_PER_PORT] in processor ports is
	 * reserved for use by DR to save the prd_prsv of the port
	 * while that is temporarily marked RSV_UNCONFIG when the
	 * processor is borrowed for I/O cage testing for DR.
	 * It is expected that .prd_wic_links[PRD_LINK_IX_HOLD_CPUPORT_PRSV]
	 * will be restored to RSV_UNDEFINED when the prd_prsv is
	 * restored to its original value. It would be a Good Thing to
	 * check that prd_prsv is not ever being set to RSV_UNDEFINED;
	 * it's probably wrong to restore it to other than RSV_GOOD().
	 */
#define	PRD_LINK_IX_HOLD_CPUPORT_PRSV	(LINKS_PER_PORT - 1)

	/*
	 * There are four Address Decode Registers, 0 - 3, one for each
	 * logical bank. ADR 0 and 2 control the logical banks in
	 * physical bank 0; ADR 1 and 3 control the logical banks in
	 * physical bank 1.
	 */
#define	ADR2PBANK(adr)			((adr) & 1)
#define	ADR2LBANK(adr)			(((adr) >> 1) & 1)
#define	PLBANK2ADR(pbank, lbank)	((((lbank) & 1) << 1) | ((pbank) & 1))


	/* ======================================================== */
	/*
	 * RSV stands for Resource Status Value.
	 * These are the values used in all cases where the status of
	 * a resource is maintained in a byte element of a structure.
	 * These are ordered in terms of preserving interesting information
	 * in POST displays where all configurations are displayed in a
	 * single value. The highest value for a resource over all
	 * configurations is shown.
	 * Of course, this is just for help to engineers/technicians in
	 * understanding what happened; for the most part, everything
	 * except "GOOD" is just different flavors of "BAD".
	 * This is not an enum because they need to fit in a byte.
	 */

typedef uint8_t	prdrsv_t;

#define	RSV_UNKNOWN	0x0		/* No status yet */
#define	RSV_PRESENT	0x1		/* Presence detected */
#define	RSV_CRUNCH	0x2		/* Unusable by implication */
#define	RSV_UNDEFINED	0x3		/* Architecturally Missing */
#define	RSV_MISS	0x4		/* Missing */
#define	RSV_MISCONFIG	0x5		/* Misconfigured, e.g., mixed dimms */
#define	RSV_FAIL_OBP	0x6		/* Failed by OBP */
#define	RSV_FAIL	0x7		/* Tested and failed */
#define	RSV_BLACK	0x8		/* Blacklisted */
#define	RSV_RED		0x9		/* Redlisted */
#define	RSV_EXCLUDED	0xA		/* Not in this domain */
#define	RSV_UNCONFIG	0xB		/* Good, but not in config. */
#define	RSV_PASS	0xC		/* Passed some sort of test; */
					/* Always subject to more... */
	/*
	 * Odd proc of a good Lockstep pair. Valid only for prd_prsv for
	 * processor ports.
	 */
#define	RSV_LOCKSTEP	0xD

	/*
	 * This will be used instead of RSV_MISS when an hsPCI
	 * cassette is present but it contains no PCI adapter.
	 * Intended to be used only for prd_t.prd_iocard_rsv[][]
	 */
#define	RSV_EMPTY_CASSETTE	0xF	/* An hsPCI cassette, no adapter */

	/*
	 * This definition of Good depends on context.
	 * Some customers of this status may want to use only PASS.
	 */
#define	RSV_GOOD(rsv) \
	(RSV_PASS == (rsv) || RSV_UNKNOWN == (rsv) || RSV_PRESENT == (rsv))

#define	RSV_NOTOUCH(rsv) (RSV_EXCLUDED == (rsv) || RSV_RED == (rsv))

	/* ============================================================ */
	/*		Port Resource Descriptor - PRD			*/

typedef struct {
	uint64_t	prd_ver_reg;	/* port version register */
		/*
		 * For ports with memory, the address decode register
		 * for each bank, and the address control register.
		 */
	uint64_t	prd_madr[PMBANKS_PER_PORT][LMBANKS_PER_PMBANK];
	uint64_t	prd_macr;
	/* DOUBLEWORD */

	uint16_t	prd_rfreq;		/* rated frequency Mhz */
	uint16_t	prd_afreq_ratio;	/* ratio of actual frequency */
						/* to interconnect speed */

	prdrsv_t	prd_prsv;	/* status of entire port. */
	uint8_t		prd_ptype;	/* port type. See SAFPTYPE_ below */

		/* memory configuration state */
	uint8_t		prd_mem_config_state;

	uint8_t		prd_fill1;
	/* DOUBLEWORD */

		/*
		 * This is intended to handle Jubatus2X - 8X.
		 * For all other cases, expect that prd_agent[0] = prd_prsv,
		 * and prd_agent[7:1] = RSV_UNDEFINED.
		 * For JubatusnX, it conveys the status of the
		 * n core processors.
		 */
	prdrsv_t	prd_agent[SAF_AGENT_PER_PORT];
	/* DOUBLEWORD */

		/* for ports that have memory */
	prdrsv_t	prd_bank_rsv[PMBANKS_PER_PORT][LMBANKS_PER_PMBANK];
								/* bank rsv */
	uint16_t	prd_log_bank_size[PMBANKS_PER_PORT];	/* bank size */
				/*
				 * If a physical bank has two logical
				 * banks, they are always the same size.
				 */
	/* DOUBLEWORD */

		/* for ports with IO buses */
	prdrsv_t	prd_iocard_rsv[IOBUS_PER_PORT][IOCARD_PER_BUS];
		/*
		 * Currently, only 1 adapter is on each bus and index
		 * zero is used for that. Index 1 is reserved.
		 * The remaining 2 are used to support in-kernel-probing,
		 * to avoid board specific hooks.
		 * They only exist on bus 1 of Schizo 0 on the board.
		 */
#define	IOBOARD_BBCRIO_PORT		0
#define	IOBOARD_BBCRIO_BUS		1
#define	IOCARD_RSV_SBBC_INDEX		2
#define	IOCARD_RSV_RIO_INDEX		3

	/* DOUBLEWORD */

	prdrsv_t	prd_iobus_rsv[IOBUS_PER_PORT];

		/* For ports with WCI links, status of each link */
	prdrsv_t	prd_wic_links[LINKS_PER_PORT];

	uint8_t		fill2;
	/* DOUBLEWORD */


	prdrsv_t	prd_dimm[PMBANKS_PER_PORT][DIMMS_PER_PMBANK];
			/*
			 * Status for dimms [1:0][3:0].
			 * This contains at most only probing information.
			 * Testing is done on logical banks, so results are
			 * not representable at the dimm level, since each
			 * dimm contains part of two logical banks.
			 *
			 * Also, probing is expensive in time, so it is
			 * skipped if the results would not affect available
			 * resources.
			 * Example: if dimm 0 of a pbank is missing, the other
			 * three dimms are ignored and will be RSV_UNKNOWN.
			 */

	/* DOUBLEWORD */
	uint8_t		prd_cache;	/* external cache size (MByte) */
	prdrsv_t	prd_ecdimm[ECDIMMS_PER_PORT];
		/* status for ecache dimms 0..1 */


	uint8_t		prd_sparebyte[5];
	/* DOUBLEWORD */
	uint32_t	prd_spare[4];
	/* DOUBLEWORD */

} prd_t;

	/* prd_mem_config_state manifest constants */
#define	PRD_MCS_BANKS			((uint8_t)1 << 0)
#define	PRD_MCS_SLICE			((uint8_t)1 << 1)
#define	PRD_MCS_IMODE(mode)		(((uint8_t)(mode) & 0x3) << 2)
#define	PRD_MCS_GET_IMODE(mcs)		(((uint8_t)(mcs) & 0xC) >> 2)
#define	PRD_MCS_FAILD			((uint8_t)1 << 6)
#define	PRD_MCS_VALID			((uint8_t)1 << 7)


	/* Types of Safari ports. Not an enum so it fits in a byte. */
#define	SAFPTYPE_NULL	0
#define	SAFPTYPE_CPU	1
#define	SAFPTYPE_sPCI	2
#define	SAFPTYPE_cPCI	3
#define	SAFPTYPE_WCI	4
#define	SAFPTYPE_PCIX	5
#define	SAFPTYPE_MAX	SAFPTYPE_PCIX

#define	SAFTYPE_PCI(type) \
	((SAFPTYPE_sPCI == (type)) || (SAFPTYPE_cPCI == (type)))


	/* ======================================================== */
	/* Local and Global Domain Configuration Descriptors LDCD & GDCD */

	/* Enumeration of process types for xdcd.h.dcd_lmod_type */
typedef enum {
	DCDLMT_OTHER,		/* Something not otherwise in this enum */
	DCDLMT_POST_BOOT,	/* POST at initial domain creation */
	DCDLMT_POST_DR,		/* POST for some sort of DR case */
	DCDLMT_OBP,		/* Domain Open Boot */
	DCDLMT_OS,		/* Domain Solaris */
	DCDLMT_DR_SMS,		/* DR process running on SSC */
	DCDLMT_DR_DOMAIN,	/* DR process running on domain */
	DCDLMT_OTHER_SMS,	/* Non-DR process running on SSC */
	DCDLMT_COUNT		/* Array size for strings, etc. */
} dcd_lmod_type_t;


	/* dcd substructure for status of L1 boards in each slot */
typedef struct {
	xcl1bt_t	l1ss_type;	/* enum in scat_asicbrd_types.h */
	prdrsv_t	l1ss_rsv;	/* Status. */
					/*
					 * The cdc information is rightfully
					 * only relevant to the EXB and the
					 * slot 0 board of that EXB. But it
					 * needs to stay with that slot 0
					 * board over DR operations, so
					 * it goes here.
					 * It should be ignored for slot 1
					 * boards.
					 */
	prdrsv_t	l1ss_cdc_rsv;
	uint8_t		l1ss_cdc_dimm_size;	/* MBytes */
	uint8_t		l1ss_fill1;		/* Explicit alignment */
	/* DOUBLEWORD */
					/*
					 * So Starcat software that doesn't
					 * have knowledge of the CPU sram
					 * TOC format can find the LDCD in
					 * CPU srams.
					 */
	uint16_t	l1ss_cpu_ldcd_xwd_offset;	/* Byte offset >> 3 */
	uint16_t	l1ss_cpu_drblock_xwd_offset;	/* Byte offset >> 3 */
	uint8_t		l1ss_flags;			/* See below */
	uint8_t		l1ss_sparebyte[3];
	uint32_t	l1ss_spare[2];
	/* DOUBLEWORD */
} l1_slot_stat_t;

	/*
	 * When this flag is set, all CPUs on this L1 board should be
	 * configured with a NULL Local Physical Address (LPA) range in
	 * their Safari Config Registers.
	 * This flag can be ignored for boards with no processors.
	 */
#define	L1SSFLG_THIS_L1_NULL_PROC_LPA		(1 << 0)


	/* dcd substructure for memory chunk list. */
typedef struct {
	uint64_t	mc_base_pa;	/* Base Physical Address */
	uint64_t	mc_mbytes;	/* Size of Chunk in MBytes */
} mem_chunk_t;

#define	MAX_DOM_MEM_CHUNKS (EXP_COUNT * S0_LPORT_COUNT * \
			    PMBANKS_PER_PORT * LMBANKS_PER_PMBANK)
typedef struct {
	uint64_t	dcl_chunks;	/* number of chunks */
	mem_chunk_t	dcl_chunk[MAX_DOM_MEM_CHUNKS];
} domain_chunk_list_t;

#define	MAX_EXP_MEM_CHUNKS (S0_LPORT_COUNT * \
			    PMBANKS_PER_PORT * LMBANKS_PER_PMBANK)
typedef struct {
	uint64_t	ecl_chunks;	/* number of chunks */
	mem_chunk_t	ecl_chunk[MAX_EXP_MEM_CHUNKS];
} exp_chunk_list_t;

typedef struct {
	uint32_t	dcd_magic;	/* GDCD_MAGIC or LDCD_MAGIC */
	uint32_t	dcd_version;	/* structure version: DCD_VERSION */
	uint32_t	dcd_csum;	/* So sum((uint[]) xdcd) == 0. */
	uint32_t	dcd_post_pid;	/* Process ID of the SSC hpost that */
					/* originally created this domain */
					/* or POSTed this board. */
	/* DOUBLEWORD */

	uint64_t	dcd_boot_time;	/* Time of creation of the domain */
					/* by POST. To be backward compatible */
					/* in ILD32, uint64_t is used instead */
					/* of time_t. */

	uint64_t	dcd_lmod_time;	/* Time of last modification of */
					/* this structure. */

	uint32_t	dcd_lmod_pid;	/* Process ID of the last modifier */
					/* of this structure. If the last */
					/* modifier has no PID, set to 0. */

	dcd_lmod_type_t dcd_lmod_type;	/* Type of process that last modified */
					/* this structure. See above. */
	/* DOUBLEWORD */

	uint32_t	dcd_mod_count;	/* Count of the number of times */
					/* this structure has been modified. */
					/* Set to 0 by original POST. */

	uint32_t	dcd_post_level;	/* Level at which POST executed */
					/* for most recent boot or test. */
	/* DOUBLEWORD */

	uint32_t	dcd_post_private;	/* Private word for POST */
	uint32_t	dcd_flags;		/* See DCDFLAG_xxx */
	uint32_t	dcd_spare[8];		/* Minimize future problems */
	/* DOUBLEWORD */
} dcd_header_t;


	/*
	 * This flag is only for use in LDCDs. It is set when this
	 * board is part of a domain and the local DCD is considered
	 * only a secondary copy of the information in the GDCD.
	 * We do not keep the GDCD location here, since that would
	 * impose extra work on DR when the golden IOSRAM board detaches.
	 * POST will set this in all LDCDs in a newly booted domain.
	 */
#define	DCDFLAG_IN_DOMAIN		(1u << 0)

	/*
	 * This flag is only for use in LDCDs. It is set when this
	 * board was called for hpost -H (h.dcd_lmod_type is DCDLMT_POST_DR)
	 * and no testing was required. All that was done was clearing.
	 */
#define	DCDFLAG_CLEARED_ONLY		(1u << 1)

	/* POST inititalizes dcd_testcage_mbyte_PA to this value */
#define	DCD_TESTCAGE_MBYTE_PA_INIT	((uint32_t)-1)
	/*
	 * zero (0) in dcd_testcage_log2_mbytes has the special meaning
	 * that no testcage memory is to be allocated.
	 * zero (0) in dcd_testcage_log2_mbytes_align is a real
	 * alignment of 1MB.
	 */
#define	DCD_DR_TESTCAGE_DISABLED	(0)	/* zero size cage */
#define	DCD_DR_TESTCAGE_LOG2_1MB_ALIGN	(0)	/* 2^0 = 1 for */
	/*
	 * The remainder of these constants can be used for
	 * either dcd_testcage_* variable and indicate the
	 * value shown.
	 */
#define	DCD_DR_TESTCAGE_LOG2_2MB	(1)	/* 2^1 =  2 */
#define	DCD_DR_TESTCAGE_LOG2_4MB	(2)	/* 2^2 =  4 */
#define	DCD_DR_TESTCAGE_LOG2_8MB	(3)	/* 2^3 =  8 */
#define	DCD_DR_TESTCAGE_LOG2_16MB	(4)	/* 2^4 =  16 */
#define	DCD_DR_TESTCAGE_LOG2_32MB	(5)	/* 2^5 =  32 */
#define	DCD_DR_TESTCAGE_LOG2_64MB	(6)	/* 2^6 =  64 */
#define	DCD_DR_TESTCAGE_LOG2_128MB	(7)	/* 2^7 =  128 */
#define	DCD_DR_TESTCAGE_LOG2_256MB	(8)	/* 2^8 =  256 */
#define	DCD_DR_TESTCAGE_LOG2_512MB	(9)	/* 2^9 =  512 */
#define	DCD_DR_TESTCAGE_LOG2_1024MB	(10)	/* 2^10 = 1024 */

	/* Global DCD - exists only in golden I/O sram */
typedef struct {
	dcd_header_t	h;
	/* DOUBLEWORD */

	uint32_t	dcd_intercon_freq;	/* In Hertz */
	uint8_t		dcd_abus_mask;		/* Address bus config [1:0] */
	uint8_t		dcd_dbus_mask;		/* Data bus config [1:0] */
	uint8_t		dcd_rbus_mask;		/* Response bus config [1:0] */
	uint8_t		dcd_stick_ratio;	/* Ratio of intercon:STICK */
	/* DOUBLEWORD */

	uint8_t		dcd_domain;		/* 0-17 or other if unknown */
		/*
		 * Specification of the required size and alignment of
		 * the DR testcage memory used during POST -H testcage runs.
		 * The formula is bytes = (1 << (log2_value + 20)).
		 */
	uint8_t		dcd_testcage_log2_mbytes_size;
	uint8_t 	dcd_testcage_log2_mbytes_align;
	uint8_t		dcd_fill[5];
	/* DOUBLEWORD */
		/*
		 * Specification of the DR testcage memory base physical addr.
		 * This is initialized to DCD_TESTCAGE_PA_INIT by POST
		 * and set by setkeyswitch when it determines the location of
		 * the testcage.  The formula is PA = (mbyte_PA << 20).
		 */
	uint32_t	dcd_testcage_mbyte_PA;
	uint32_t	dcd_spare[3];		/* Avoid future problems */
	/* DOUBLEWORD */

		/* Information on the L1 boards in each slot: */
	l1_slot_stat_t	dcd_slot[EXP_COUNT][SLOT_COUNT];
	/* DOUBLEWORD */

		/*
		 * Information on 108 Safari ports.
		 * See scat_const.h for macros that will help in computing
		 * indexes into this array, particularly "PWE" and "PFP".
		 */
	prd_t		dcd_prd[EXP_COUNT][PORT_PER_EXP];
	/* DOUBLEWORD */

		/*
		 * memory chunk list for the domain; max 288 chunks.
		 * This is the worst case scenario where there is no
		 * interleaving and no re-configuration of the memory address
		 * decode registers to make board memory contiguous.
		 * This uses 288 * 16bytes = 4608KB.
		 */
	domain_chunk_list_t dcd_chunk_list;
} gdcd_t;

	/* Local DCD - exists in every I/O, CPU, and WCI sram */
typedef struct {
	dcd_header_t	h;
	/* DOUBLEWORD */

		/* Information on the L1 board in this slot: */
	l1_slot_stat_t	dcd_slot;
	/* DOUBLEWORD */

		/* Information on 2 Safari ports: */
	prd_t		dcd_prd[2];
	/* DOUBLEWORD */

		/* memory chunk list for this exp; max 16 chunks */
	exp_chunk_list_t dcd_chunk_list;
} ldcd_t;

#ifdef __cplusplus
}
#endif

#endif	/* !_SCAT_DCD_H */
