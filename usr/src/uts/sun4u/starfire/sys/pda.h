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
 * Copyright 1998-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_PDA_H
#define	_SYS_PDA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * Contains definitions used for PDA (Post Descriptor Array) [post2obp]
 * support.
 *
 * XXX - These data structures is defined in SSP-land in:
 *	 src/post/export/xf_postif.h.  It is not anticipated
 *	 that any future changes will be made to this data
 *	 structure so we'll allow this hack on this go around.
 */

#define	MAX_ABUSES		4	/* Address buses */
#define	MAX_DBUSES		2	/* Data buses */

#define	MAX_SYSBDS		16	/* no more than 16 system boards */
#define	MAX_PROCMODS		4	/* Per system board */
#define	MAX_PC			3	/* Per system board */
#define	MAX_XDB			4	/* Per system board */
#define	MAX_CIC			4	/* Per system board */
#define	MAX_MGROUPS		4	/* Per MC and system board */
#define	MAX_IOCS		2	/* Per system board */
#define	MAX_SLOTS_PER_IOC	4	/* Per ioc */

typedef struct {
	ushort_t	bda_board;		/* BDAN 0|Anyred|mem|Board */
	ushort_t	bda_proc;		/* BDAN Processor 3:0	*/
	ushort_t	bda_pc;			/* BDAN PC asic 2:0	*/
	ushort_t	bda_xdb;		/* BDAN XDB asic 3:0	*/
	ushort_t	bda_cic;		/* BDAN CIC asic 3:0	*/
	ushort_t	bda_ldpath;		/* BDAN 0|0| ldpath [dbus] */
	ushort_t	bda_ioc;		/* BDAN 0|0| ioc 1:0	*/
	ushort_t	bda_ios[MAX_IOCS];	/* BDAN Scard 3:0	*/
	ushort_t	bda_mgroup;		/* BDAN memory group 3:0 */
} board_desc_t;

typedef struct {
	ushort_t	bada_proc [MAX_PROCMODS];  /* Extra status on procs */
	uchar_t		bada_iom_type;		/* I/O module type. */
	uchar_t		bada_fill[3];
	ushort_t	bada_ioc[MAX_IOCS];	/* Extra status on iocs	*/
} board_auxdesc_t;

/*
 * The three lsb of bada_proc holds the ecache size of that proc
 * module, as (log-base-2 - 19), so 1/2 MB is 0, 1 MB is 1, ...
 * 32 MB is 6. 7 is a bogus value.
 */
#define	BADA_PROC_GET_ECL2M19(bada_proc)	((bada_proc) & 0x7)

typedef struct {
	uint32_t	bmda_adr;		/* MC ADR */
	uint32_t	bmda_gab_bank_sel;	/* MC gab bank sel reg */
	ushort_t	bmda_bank_setup;	/* MC gab bank setup reg */
	ushort_t	bmda_filler;
	int32_t		bmda_badpage[MAX_MGROUPS];
						/*
						 * One bad page offset per
						 * mgroup is allowed. No
						 * bad page if < 0.
						 */
} board_mdesc_t;

/*
 * BDA nibble status definitions:
 * These are ordered in terms of preserving interesting information
 * in POST displays where all configurations are displayed in a
 * single value. The highest value for a resource over all
 * configurations is shown.
 * Of course, this is just for help to engineers/technicians in
 * understanding what happened; for the most part, everything
 * except "GOOD" is just different flavors of "BAD".
 * Note the special macro SET_BDA_NBL_CRUNCH below which requires
 * that BDAN_CRUNCH be 0.
 */
#define	BDAN_CRUNCH	0x0		/* Unusable by implication */
#define	BDAN_UNDEFINED	0x1		/* Architecturally Missing */
#define	BDAN_MISS	0x2		/* Missing */
#define	BDAN_FAIL	0x3		/* Tested and failed */
#define	BDAN_BLACK	0x4		/* Blacklisted */
#define	BDAN_RED	0x5		/* Redlisted */
#define	BDAN_EXCLUDED	0x6		/* Board is not in this domain */
#define	BDAN_UNCONFIG	0x7		/* Good, but not in config. */
#define	BDAN_GOOD	0x8		/* Like it says. */
#define	BDAN_MASK	0xF


/* Macros for accessing BDA nibbles */
#define	BDA_NBL(shrt, nibix) \
		(((shrt) >> ((nibix) << 2)) & BDAN_MASK)
#define	SET_BDA_NBL(shrt, nibix, val) \
{ \
	shrt &= ~(BDAN_MASK << ((nibix) << 2)); \
	shrt |= (val) << ((nibix) << 2); \
}

/*
 * This exists to keep lint from complaining about statements with
 * null efect when we OR in a constant 0 in SET_BDA_NBL. It's a pain,
 * but it does save the code optimizer some work. ;-{
 */
#define	SET_BDA_NBL_CRUNCH(shrt, nibix) \
		(shrt &= ~(BDAN_MASK << ((nibix) << 2)))

/* Definitions for nibbles in the bda_board element: */
#define	BDA_GEN_NBL	0	/* Overall state of the board */
#define	BDA_MC_NBL	1	/* State of the memory. */
/*
 * BDAN_RED if anything red on board, or board is BDAN_EXCLUDED;
 * otherwise BDAN_GOOD
 */
#define	BDA_ANYRED_NBL	2
/*
 * Macro BDA_PAGESHIFT hides Solaris page size to Starfire POST, as POST
 * assumes Solaris basic page size as 8K.
 * Note: Only BDA_PAGESHIFT is used, BDA_PAGESIZE is added for readability.
 */
#define	BDA_PAGESHIFT	13
#define	BDA_PAGESIZE	(1<<BDA_PAGESHIFT)

typedef struct {			/* Memory Total Descriptor */
	int32_t	Memt_NumPages;		/* 8 KB each */
	int32_t	Memt_NumChunks;
} MemoryTotal_t;

typedef struct {				/* Chunk Descriptor */
	uint32_t	Memc_StartAddress;	/* In 8 KB pages */
	int32_t		Memc_Size;		/* In 8 KB pages */
} MemChunk_t;


#define	P2OBP_MAGIC	"XFPOST_2OBP"
#define	VAR_ARRAY_LEN	1

typedef struct {
	char		p2o_magic[12];		/* magic cookie = P2OBP_MAGIC */
	int32_t		p2o_struct_version;	/* equal to P2OBP_VERSION */
	uint32_t	p2o_csum;		/* sum(uint[]) */
	uint32_t	p2o_post_time;		/* creation time */
	uint32_t	p2o_post_pid;		/* pid of sequencer on SSP */
	uint32_t	p2o_post_level;		/* level at which hpost ran */
	short		p2o_abus_mask;		/* [3:0] = Valid PA buses */
						/* [5:4] = bus shuffle mode */
	short		p2o_dbus_mask;		/* Valid physdata buses */
	uint32_t	p2o_intercon_freq;	/* hz */
	uint32_t	p2o_procssor_freq;	/* hz */
	int32_t		p2o_post_private;
	uint32_t	p2o_flags;		/* See P2OFLAG_XXX */
	uchar_t		p2o_procint_intx_freq_ratio;	/* 0 if not known */
	uchar_t		p2o_fill_byte[3];
	uint_t		p2o_filler[6];		/* for expansion */
	board_desc_t	p2o_bdinfo[MAX_SYSBDS];
	board_mdesc_t	p2o_bdminfo[MAX_SYSBDS];
	board_auxdesc_t	p2o_auxinfo[MAX_SYSBDS];
	MemoryTotal_t	p2o_memtotal;
	/*
	 * Array of descriptors of existing memory.
	 * Number of descriptors is given in memtotal.NumChunks.
	 */
	MemChunk_t	p2o_mchunks[VAR_ARRAY_LEN];
} post2obp_info_t;

#ifdef _KERNEL
/*
 * Following definitions in support of DR.
 */
typedef void		*pda_handle_t;

extern pda_handle_t	pda_open();
extern void		pda_close(pda_handle_t ph);
extern int		pda_board_present(pda_handle_t ph, int boardnum);
extern void		*pda_get_board_info(pda_handle_t ph, int boardnum);
extern uint_t		pda_get_mem_size(pda_handle_t ph, int boardnum);
extern void		pda_mem_add_span(pda_handle_t ph,
						uint64_t basepa,
						uint64_t nbytes);
extern void		pda_mem_del_span(pda_handle_t ph,
						uint64_t basepa,
						uint64_t nbytes);
extern void		pda_mem_sync(pda_handle_t ph, int board, int unit);
extern void		pda_get_busmask(pda_handle_t ph,
						short *amask, short *dmask);
extern int		pda_is_valid(pda_handle_t ph);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_PDA_H */
