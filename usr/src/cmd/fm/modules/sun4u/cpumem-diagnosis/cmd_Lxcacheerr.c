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
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Support routines for managing per-Lxcache state.
 */

#include <sys/types.h>
#include <errno.h>
#include <strings.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/fm/cpu/UltraSPARC-III.h>
#include <sys/cpuvar.h>
#include <cmd_Lxcache.h>
#include <cmd_mem.h>
#include <cmd_cpu.h>
#include <cmd_state.h>
#include <cmd.h>
#define	_KERNEL
#include <sys/cheetahregs.h>
#include <sys/mem_cache.h>
#undef _KERNEL
#include <sys/errclassify.h>
#include <sys/fm/io/sun4upci.h>

#include <fmd_adm.h>
#include <fmd_adm_impl.h>
#include <fmd_rpc_adm.h>

#define	PN_CACHE_ERRORS (CMD_ERRCL_UCC | CMD_ERRCL_WDC | \
			    CMD_ERRCL_CPC | CMD_ERRCL_EDC | \
			    CMD_ERRCL_L3_UCC | CMD_ERRCL_L3_CPC |\
			    CMD_ERRCL_L3_WDC | CMD_ERRCL_L3_EDC)

/* Note that these are the same for panther L2 and L3 (see prm) */

#define	LX_INDEX_MASK		PN_L2_INDEX_MASK
#define	LX_INDEX_SHIFT		6
#define	PN_ECSTATE_NA	5
#define	PN_ECSTATE_INV	0

#define	PN_L3_INDEX_MASK	PN_L3_TAG_RD_MASK

static const errdata_t l3errdata =
	{ &cmd.cmd_l3data_serd, "l3cachedata", CMD_PTR_LxCACHE_CASE };
static const errdata_t l2errdata =
	{ &cmd.cmd_l2data_serd, "l2cachedata", CMD_PTR_LxCACHE_CASE };

/* Macro for putting 64-bit onto stack as two 32-bit ints */
#define	PRTF_64_TO_32(x)	(uint32_t)((x)>>32), (uint32_t)(x)

#define	LX_PA_MASK2_32BIT_CORRECT	16
#define	LX_PA_MASK3_32BIT_CORRECT	24
#define	LX_PA_MASK2 0x7fffff8
#define	LX_PA_MASK3 0x7ffff8


#define	MAX_RETRIES_FOR_ECC_MATCH	3
#define	PN_TAG_ECC_MASK 0x7fc0
#define	PN_L2_PTAG_SHIFT	19
#define	PN_L3_PTAG_SHIFT	24
#define	L2_PTAG_MASK		0xffffff
#define	L3_PTAG_MASK		0xfffff
#define	BIT_MASK		0x7f
#define	MSB_BIT			0x8000
#define	SET_MSB_BIT		0x8000
#define	CLEAR_MSB_BIT		0x7fff
#define	PN_LX_TAG_ECC_START_BIT	6
#define	PN_LX_TAG_ECC_END_BIT	14
#define	PN_LX_STATE_END_BIT	2
#define	PN_LX_NUM_OF_BITS_IN_ECC	9

#define	LX_NWAYS		4

int test_mode = 0;	/* should be 0 in production version. */
#define	FM_EREPORT_RECHECK_OF_TAGS "recheck_tags"
#define	RETRIES_TO_BE_DONE_WHEN_SYND_IS_ZERO	3
uint32_t cmd_Lxcache_recheck_tags_delay
	[RETRIES_TO_BE_DONE_WHEN_SYND_IS_ZERO + 1] = {0, 1, 2, 4};

/*
 * e (for ecctable) maps single bit positions (0-127, or 0-0x7F) to the
 * corresponding ECC syndromes for an error in that position.
 */
int e[] = {
	/* From Table P-4, JPS1 US-III Supplement */
		/* 0	1	2	3	4	5	6	7 */
/* 00 */	0x03B,	0x127,	0x067,	0x097,	0x10F,	0x08F,	0x04F,	0x02C,
/* 08 */	0x147,	0x0C7,	0x02F,	0x01C,	0x117,	0x032,	0x08A,	0x04A,
/* 10 */	0x01F,	0x086,	0x046,	0x026,	0x09B,	0x08C,	0x0C1,	0x0A1,
/* 18 */	0x01A,	0x016,	0x061,	0x091,	0x052,	0x00E,	0x109,	0x029,
/* 20 */	0x02A,	0x019,	0x105,	0x085,	0x045,	0x025,	0x015,	0x103,
/* 28 */	0x031,	0x00D,	0x083,	0x043,	0x051,	0x089,	0x023,	0x007,
/* 30 */	0x0B9,	0x049,	0x013,	0x0A7,	0x057,	0x00B,	0x07A,	0x187,
/* 38 */	0x0F8,	0x11B,	0x079,	0x034,	0x178,	0x1D8,	0x05B,	0x04C,
/* 40 */	0x064,	0x1B4,	0x037,	0x03D,	0x058,	0x13C,	0x1B1,	0x03E,
/* 48 */	0x1C3,	0x0BC,	0x1A0,	0x1D4,	0x1CA,	0x190,	0x124,	0x13A,
/* 50 */	0x1C0,	0x188,	0x122,	0x114,	0x184,	0x182,	0x160,	0x118,
/* 58 */	0x181,	0x150,	0x148,	0x144,	0x142,	0x141,	0x130,	0x0A8,
/* 60 */	0x128,	0x121,	0x0E0,	0x094,	0x112,	0x10C,	0x0D0,	0x0B0,
/* 68 */	0x10A,	0x106,	0x062,	0x1B2,	0x0C8,	0x0C4,	0x0C2,	0x1F0,
/* 70 */	0x0A4,	0x0A2,	0x098,	0x1D1,	0x070,	0x1E8,	0x1C6,	0x1C5,
/* 78 */	0x068,	0x1E4,	0x1E2,	0x1E1,	0x1D2,	0x1CC,	0x1C9,	0x1B8,
	/* Now we have the check bits */
	/* C0	C1	C2	C3	C4	C5	C6	C7	C8 */
	0x001,	0x002,	0x004,	0x008,	0x010,	0x020,	0x040,	0x080,	0x100,
};

#define	NBITS (sizeof (e)/sizeof (e[0]))
#define	NDATABITS (128)
/*
 * This table is used to determine which bit(s) is(are) bad when an ECC
 * error occurs.  The array is indexed by an 9-bit syndrome.  The entries
 * of this array have the following semantics:
 *
 *      00-127  The number of the bad bit, when only one bit is bad.
 *      128     ECC bit C0 is bad.
 *      129     ECC bit C1 is bad.
 *      130     ECC bit C2 is bad.
 *      131     ECC bit C3 is bad.
 *      132     ECC bit C4 is bad.
 *      133     ECC bit C5 is bad.
 *      134     ECC bit C6 is bad.
 *      135     ECC bit C7 is bad.
 *      136     ECC bit C8 is bad.
 *	137-143 reserved for Mtag Data and ECC.
 *      144(M2) Two bits are bad within a nibble.
 *      145(M3) Three bits are bad within a nibble.
 *      146(M3) Four bits are bad within a nibble.
 *      147(M)  Multiple bits (5 or more) are bad.
 *      148     NO bits are bad.
 * Based on "Cheetah Programmer's Reference Manual" rev 1.1, Tables 11-4,11-5.
 */

#define	C0	128
#define	C1	129
#define	C2	130
#define	C3	131
#define	C4	132
#define	C5	133
#define	C6	134
#define	C7	135
#define	C8	136
#define	MT0	137	/* Mtag Data bit 0 */
#define	MT1	138
#define	MT2	139
#define	MTC0	140	/* Mtag Check bit 0 */
#define	MTC1	141
#define	MTC2	142
#define	MTC3	143
#define	M2	144
#define	M3	145
#define	M4	146
#define	M	147
#define	NA	148
#if defined(JALAPENO) || defined(SERRANO)
#define	S003	149	/* Syndrome 0x003 => likely from CPU/EDU:ST/FRU/BP */
#define	S003MEM	150	/* Syndrome 0x003 => likely from WDU/WBP */
#define	SLAST	S003MEM	/* last special syndrome */
#else /* JALAPENO || SERRANO */
#define	S003	149	/* Syndrome 0x003 => likely from EDU:ST */
#define	S071	150	/* Syndrome 0x071 => likely from WDU/CPU */
#define	S11C	151	/* Syndrome 0x11c => likely from BERR/DBERR */
#define	SLAST	S11C	/* last special syndrome */
#endif /* JALAPENO || SERRANO */
#if defined(JALAPENO) || defined(SERRANO)
#define	BPAR0	152	/* syndrom 152 through 167 for bus parity */
#define	BPAR15	167
#endif	/* JALAPENO || SERRANO */

static uint8_t ecc_syndrome_tab[] =
{
NA,  C0,  C1, S003, C2,  M2,  M3,  47,  C3,  M2,  M2,  53,  M2,  41,  29,   M,
C4,   M,   M,  50,  M2,  38,  25,  M2,  M2,  33,  24,  M2,  11,   M,  M2,  16,
C5,   M,   M,  46,  M2,  37,  19,  M2,   M,  31,  32,   M,   7,  M2,  M2,  10,
M2,  40,  13,  M2,  59,   M,  M2,  66,   M,  M2,  M2,   0,  M2,  67,  71,   M,
C6,   M,   M,  43,   M,  36,  18,   M,  M2,  49,  15,   M,  63,  M2,  M2,   6,
M2,  44,  28,  M2,   M,  M2,  M2,  52,  68,  M2,  M2,  62,  M2,  M3,  M3,  M4,
M2,  26, 106,  M2,  64,   M,  M2,   2, 120,   M,  M2,  M3,   M,  M3,  M3,  M4,
#if defined(JALAPENO) || defined(SERRANO)
116, M2,  M2,  M3,  M2,  M3,   M,  M4,  M2,  58,  54,  M2,   M,  M4,  M4,  M3,
#else	/* JALAPENO || SERRANO */
116, S071, M2,  M3,  M2,  M3,   M,  M4,  M2,  58,  54,  M2,   M,  M4,  M4,  M3,
#endif	/* JALAPENO || SERRANO */
C7,  M2,   M,  42,   M,  35,  17,  M2,   M,  45,  14,  M2,  21,  M2,  M2,   5,
M,   27,   M,   M,  99,   M,   M,   3, 114,  M2,  M2,  20,  M2,  M3,  M3,   M,
M2,  23, 113,  M2, 112,  M2,   M,  51,  95,   M,  M2,  M3,  M2,  M3,  M3,  M2,
103,  M,  M2,  M3,  M2,  M3,  M3,  M4,  M2,  48,   M,   M,  73,  M2,   M,  M3,
M2,  22, 110,  M2, 109,  M2,   M,   9, 108,  M2,   M,  M3,  M2,  M3,  M3,   M,
102, M2,   M,   M,  M2,  M3,  M3,   M,  M2,  M3,  M3,  M2,   M,  M4,   M,  M3,
98,   M,  M2,  M3,  M2,   M,  M3,  M4,  M2,  M3,  M3,  M4,  M3,   M,   M,   M,
M2,  M3,  M3,   M,  M3,   M,   M,   M,  56,  M4,   M,  M3,  M4,   M,   M,   M,
C8,   M,  M2,  39,   M,  34, 105,  M2,   M,  30, 104,   M, 101,   M,   M,   4,
#if defined(JALAPENO) || defined(SERRANO)
M,    M, 100,   M,  83,   M,  M2,  12,  87,   M,   M,  57,  M2,   M,  M3,   M,
#else	/* JALAPENO || SERRANO */
M,    M, 100,   M,  83,   M,  M2,  12,  87,   M,   M,  57, S11C,  M,  M3,   M,
#endif	/* JALAPENO || SERRANO */
M2,  97,  82,  M2,  78,  M2,  M2,   1,  96,   M,   M,   M,   M,   M,  M3,  M2,
94,   M,  M2,  M3,  M2,   M,  M3,   M,  M2,   M,  79,   M,  69,   M,  M4,   M,
M2,  93,  92,   M,  91,   M,  M2,   8,  90,  M2,  M2,   M,   M,   M,   M,  M4,
89,   M,   M,  M3,  M2,  M3,  M3,   M,   M,   M,  M3,  M2,  M3,  M2,   M,  M3,
86,   M,  M2,  M3,  M2,   M,  M3,   M,  M2,   M,  M3,   M,  M3,   M,   M,  M3,
M,    M,  M3,  M2,  M3,  M2,  M4,   M,  60,   M,  M2,  M3,  M4,   M,   M,  M2,
M2,  88,  85,  M2,  84,   M,  M2,  55,  81,  M2,  M2,  M3,  M2,  M3,  M3,  M4,
77,   M,   M,   M,  M2,  M3,   M,   M,  M2,  M3,  M3,  M4,  M3,  M2,   M,   M,
74,   M,  M2,  M3,   M,   M,  M3,   M,   M,   M,  M3,   M,  M3,   M,  M4,  M3,
M2,  70, 107,  M4,  65,  M2,  M2,   M, 127,   M,   M,   M,  M2,  M3,  M3,   M,
80,  M2,  M2,  72,   M, 119, 118,   M,  M2, 126,  76,   M, 125,   M,  M4,  M3,
M2, 115, 124,   M,  75,   M,   M,  M3,  61,   M,  M4,   M,  M4,   M,   M,   M,
M,  123, 122,  M4, 121,  M4,   M,  M3, 117,  M2,  M2,  M3,  M4,  M3,   M,   M,
111,  M,   M,   M,  M4,  M3,  M3,   M,   M,   M,  M3,   M,  M3,  M2,   M,   M
};

#define	ESYND_TBL_SIZE	(sizeof (ecc_syndrome_tab) / sizeof (uint8_t))

int8_t L2TAG_bit_to_way_map[128] = {
/*	1   2   3   4   5   6   7   8   9   10  11  12  13  14  15  16 */
/* 1 */ 0,  0,  0,  1,  1,  1,  2,  2,  2,  3,  3,  3,  0,  0,  0,  0,
/* 2 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* 3 */ 0,  0,  0,  0,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
/* 4 */ 2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2, -1, -1, -1, -1,
/* 5 */-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  1,  1,  1,  1,
/* 6 */ 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
/* 7 */ 1,  1,  1,  1,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,
/* 8 */ 3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3, -1, -1, -1, -1,
};

uint8_t L2TAG_bit_to_way_bit[128] = {
/*	1   2   3   4   5   6   7   8   9   10  11  12  13  14  15  16 */
/* 1 */ 0,  1,  2,  0,  1,  2,  0,  1,  2,  0,  1,  2,  19, 20, 21, 22,
/* 2 */23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
/* 3 */39, 40, 41, 42, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
/* 4 */31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, C0, C0, C0, C0,
/* 5 */C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, 19, 20, 21, 22,
/* 6 */23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
/* 7 */39, 40, 41, 42, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
/* 8 */31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, C0, C0, C0, C0,
};

int8_t L3TAG_bit_to_way_map[128] = {
/*	1   2   3   4   5   6   7   8   9   10  11  12  13  14  15  16 */
/* 1 */ 1,  3,  1,  3,  1,  3,  1,  3,  1,  3,  1,  3,  1,  3,  1,  3,
/* 2 */ 1,  3,  1,  3,  1,  3,  1,  3,  1,  3,  1,  3,  1,  3,  1,  3,
/* 3 */ 1,  3,  1,  3,  1,  3,  1,  3,  1,  3,  1,  3,  1,  3, -1, -1,
/* 4 */-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
/* 5 */ 0,  2,  0,  2,  0,  2,  0,  2,  0,  2,  0,  2,  0,  2,  0,  2,
/* 6 */ 0,  2,  0,  2,  0,  2,  0,  2,  0,  2,  0,  2,  0,  2,  0,  2,
/* 7 */ 0,  2,  0,  2,  0,  2,  0,  2,  0,  2,  0,  2,  0,  2, -1, -1,
/* 8 */-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

uint8_t L3TAG_bit_to_way_bit[128] = {
/*	1   2   3   4   5   6   7   8   9   10  11  12  13  14  15  16 */
/* 1 */ 0,  0,  1,  1,  2,  2, 24, 24, 25, 25, 26, 26, 27, 27, 28, 28,
/* 2 */29, 29, 30, 30, 31, 31, 32, 32, 33, 33, 34, 34, 35, 35, 36, 36,
/* 3 */37, 37, 38, 38, 39, 39, 40, 40, 41, 41, 42, 42, 43, 43, C0, C0,
/* 4 */C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0,
/* 5 */ 0,  0,  1,  1,  2,  2, 24, 24, 25, 25, 26, 26, 27, 27, 28, 28,
/* 6 */29, 29, 30, 30, 31, 31, 32, 32, 33, 33, 34, 34, 35, 35, 36, 36,
/* 7 */37, 37, 38, 38, 39, 39, 40, 40, 41, 41, 42, 42, 43, 43, C0, C0,
/* 8 */C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0,
};

uint16_t
calcecc(uint64_t chi, uint64_t clo)
{
	int i;
	uint64_t syndrome = 0;

	for (i = 0; i < (NDATABITS/2); i++) {
		syndrome ^= ((chi & 1) ? e[(NDATABITS/2) + i] : 0) ^
		    ((clo & 1) ? e[i] : 0);
		chi >>= 1;
		clo >>= 1;
	}
	return (uint16_t)(syndrome);
}

uint64_t
calcsynd(uint64_t chi, uint64_t clo, uint64_t ecc)
{
	return (calcecc(chi, clo) ^ ecc);
}

static uint8_t
tag_bit_to_way_bit(cmd_ptrsubtype_t pstype, int16_t tag_bit)
{
	uint8_t way_bit = C0;

	switch (pstype) {
		case CMD_PTR_CPU_L2TAG:
			way_bit = L2TAG_bit_to_way_bit[tag_bit];
			break;
		case CMD_PTR_CPU_L3TAG:
			way_bit = L3TAG_bit_to_way_bit[tag_bit];
			break;
	}
	return (way_bit);
}

static int8_t
bit_to_way(cmd_ptrsubtype_t pstype, uint32_t bit)
{
	int8_t way = -1;

	switch (pstype) {
		case CMD_PTR_CPU_L2TAG:
			way = L2TAG_bit_to_way_map[bit & BIT_MASK];
			break;
		case CMD_PTR_CPU_L3TAG:
			way = L3TAG_bit_to_way_map[bit & BIT_MASK];
			break;
	}
	return (way);
}

static int32_t
get_index(cmd_ptrsubtype_t pstype, uint64_t tag_afar)
{
	int32_t	index = -1;

	switch (pstype) {
		case CMD_PTR_CPU_L2TAG:
			index = (int32_t)((tag_afar & PN_L2_INDEX_MASK)
			    >> PN_CACHE_LINE_SHIFT);
			break;
		case CMD_PTR_CPU_L3TAG:
			index = (int32_t)((tag_afar & PN_L3_TAG_RD_MASK)
			    >> PN_CACHE_LINE_SHIFT);
			break;
	}
	return (index);
}

static int
get_retired_ways(uint64_t *tag_data)
{
	int		i, retired_ways;

	retired_ways = 0;
	for (i = 0; i < PN_CACHE_NWAYS; i++) {
		if ((tag_data[i] & CH_ECSTATE_MASK) ==
		    PN_ECSTATE_NA)
			retired_ways++;
	}
	return (retired_ways);
}

static cmd_evdisp_t
extract_data_from_ereport_payload(fmd_hdl_t *hdl, nvlist_t *nvl,
				    cmd_cpu_t *cpu,
				    cmd_ptrsubtype_t pstype,
				    uint64_t *afarp, uint64_t *tag_data,
				    const char *fltnm)
{
	ch_ec_data_t	*ec_data;
	char		*payload_namep;
	int		tag_afar_status;
	uint64_t	tag_afar;
	int		i;
	uint_t		sz;
	int32_t	index;
	int32_t		recheck_of_tags;

	tag_afar_status = cmd_afar_valid(hdl, nvl, 0, &tag_afar);
	if (tag_afar_status == -1) {
		fmd_hdl_debug(hdl,
		    "\n%s:cpu_id = %d Invalid afar status in nvlist\n",
		    fltnm, cpu->cpu_cpuid);
		return (CMD_EVD_BAD);
	}
	*afarp = tag_afar;
	index = get_index(pstype, tag_afar);
	switch (pstype) {
		case CMD_PTR_CPU_L2TAG:
			payload_namep = FM_EREPORT_PAYLOAD_NAME_L2_DATA;
			break;
		case CMD_PTR_CPU_L3TAG:
			payload_namep = FM_EREPORT_PAYLOAD_NAME_L3_DATA;
			break;
		default:
			return (CMD_EVD_BAD);
	}
	if (nvlist_lookup_int32(nvl, FM_EREPORT_RECHECK_OF_TAGS,
	    &recheck_of_tags) != 0)
		recheck_of_tags = 0;
	if ((recheck_of_tags) || (test_mode))
		return (get_tagdata(cpu, pstype, index, tag_data));
	if (nvlist_lookup_uint64_array(nvl, payload_namep,
	    (uint64_t **)&ec_data, &sz) != 0) {
		fmd_hdl_debug(hdl,
		    "\n%s: cpu_id = %d index = %d could not find %s"
		    " in nvlist\n",
		    fltnm, cpu->cpu_cpuid, index, payload_namep);
		fmd_hdl_debug(hdl,
		    "\n%s: cpu_id = %d Reading tag data through"
		    " mem_cache driver.\n",
		    fltnm, cpu->cpu_cpuid);
		return (get_tagdata(cpu, pstype, index,
		    tag_data));
	}
	for (i = 0; i < PN_CACHE_NWAYS; i++) {
		tag_data[i] = ec_data[i].ec_tag;
	}
	return (CMD_EVD_OK);
}

static void
print_ecc(fmd_hdl_t *hdl, cmd_cpu_t *cpu, const char *fltnm, uint64_t *tag_data)
{
	int	i;
	uint16_t	tag_ecc[PN_CACHE_NWAYS];

	for (i = 0; i < PN_CACHE_NWAYS; i++) {
		tag_ecc[i] =
		    ((tag_data[i] & PN_TAG_ECC_MASK)
		    >> PN_LX_TAG_ECC_START_BIT);
	}
	fmd_hdl_debug(hdl,
	    "\n%s: cpu_id = %d ecc[0] = 0x%03x ecc[1] = 0x%03x"
	    " ecc[2] = 0x%03x ecc[3] = 0x%03x\n",
	    fltnm, cpu->cpu_cpuid, tag_ecc[0], tag_ecc[1], tag_ecc[2],
	    tag_ecc[3]);

}

static int
matching_ecc(uint64_t *tag_data)
{
	int	i;
	uint16_t	tag_ecc[PN_CACHE_NWAYS];

	for (i = 0; i < PN_CACHE_NWAYS; i++) {
		tag_ecc[i] =
		    ((tag_data[i] & PN_TAG_ECC_MASK)
		    >> PN_LX_TAG_ECC_START_BIT);
		if (tag_ecc[i] != tag_ecc[0]) {
			return (1);
		}
	}
	return (0);
}

static void
gen_data_for_ecc(uint64_t *tag_data, uint64_t *data_for_ecc_gen,
		    cmd_ptrsubtype_t pstype)
{
	uint64_t	ptag[PN_CACHE_NWAYS];
	uint8_t		state[PN_CACHE_NWAYS];
	int		i;
	uint16_t	tag_ecc[PN_CACHE_NWAYS];
	uint8_t		bit_position;

	for (i = 0; i < PN_CACHE_NWAYS; i++) {
		state[i] = tag_data[i] & CH_ECSTATE_MASK;
		tag_ecc[i] =
		    ((tag_data[i] & PN_TAG_ECC_MASK)
		    >> PN_LX_TAG_ECC_START_BIT);
		switch (pstype) {
			case CMD_PTR_CPU_L2TAG:
				ptag[i] = (tag_data[i] >> PN_L2_PTAG_SHIFT) &
				    L2_PTAG_MASK;
				break;
			case CMD_PTR_CPU_L3TAG:
				ptag[i] = (tag_data[i] >> PN_L3_PTAG_SHIFT) &
				    L3_PTAG_MASK;
				break;
		}
	}
	/*
	 * We now assemble the 128 bit data swizzling the Physical tags
	 * and states we obtained for all the 4 ways.
	 */
	data_for_ecc_gen[0] = 0;	/* high order 64 bits */
	data_for_ecc_gen[1] = 0;	/* low order 64 bits */
	switch (pstype) {
		case CMD_PTR_CPU_L2TAG:
			data_for_ecc_gen[1] = state[0];	/* way 0 state */
			data_for_ecc_gen[1] |=
			    (state[1] << 3); /* way 1 state */
			data_for_ecc_gen[1] |=
			    (state[2] << 6); /* way 2 state */
			data_for_ecc_gen[1] |=
			    (state[3] << 9); /* way 3 state */
			data_for_ecc_gen[1] |= (ptag[0] << 12); /* way 0 ptag */
			data_for_ecc_gen[1] |= (ptag[2] << 36); /* way 2 ptag */
			/* bits 63:60 of low order 64 bits are 0s */

			/*
			 * We now start with hig order 64 bits.
			 * the low 12 bits are 0s
			 */
			data_for_ecc_gen[0] |= (ptag[1] << 12); /* way 1 ptag */
			data_for_ecc_gen[0] |= (ptag[3] << 36); /* way 3 ptag */
			break;
		case CMD_PTR_CPU_L3TAG:
			bit_position = 0;
			/*
			 * Swizzle state bits for way 1 and way 3
			 */
			for (i = 0; i < 3; i++) {
				data_for_ecc_gen[1] |=
				    (((state[1] >> i) & 1) << bit_position);
				bit_position++;
				data_for_ecc_gen[1] |=
				    (((state[3] >> i) & 1) << bit_position);
				bit_position++;
			}
			/*
			 * Swizzle physical tag bits for way 1 and way 3
			 */
			for (i = 0; i < 20; i++) {
				data_for_ecc_gen[1] |=
				    (((ptag[1] >> i) & 1) << bit_position);
				bit_position++;
				data_for_ecc_gen[1] |=
				    (((ptag[3] >> i) & 1) << bit_position);
				bit_position++;
			}
			/*
			 * start the high order 64 bits.
			 */
			bit_position = 0;
			/*
			 * Swizzle state bits for way 0 and way 2
			 */
			for (i = 0; i < 3; i++) {
				data_for_ecc_gen[0] |=
				    (((state[0] >> i) & 1) << bit_position);
				bit_position++;
				data_for_ecc_gen[0] |=
				    (((state[2] >> i) & 1) << bit_position);
				bit_position++;
			}
			/*
			 * Swizzle physical tag bits for way 0 and way 2
			 */
			for (i = 0; i < 20; i++) {
				data_for_ecc_gen[0] |=
				    (((ptag[0] >> i) & 1) << bit_position);
				bit_position++;
				data_for_ecc_gen[0] |=
				    (((ptag[2] >> i) & 1) << bit_position);
				bit_position++;
			}
			break;
	}
}

static uint16_t
compute_syndrome(uint64_t *tag_data, cmd_ptrsubtype_t pstype)
{
	uint64_t	tag_synd;
	uint64_t	data_for_ecc_gen[2];
	uint16_t	tag_ecc;

	gen_data_for_ecc(tag_data, data_for_ecc_gen, pstype);
	tag_ecc = ((tag_data[0] & PN_TAG_ECC_MASK) >> PN_LX_TAG_ECC_START_BIT);
	tag_synd = calcsynd(data_for_ecc_gen[0], data_for_ecc_gen[1],
	    (uint64_t)tag_ecc);
	return (tag_synd);
}

static int16_t
find_bit_stickiness(uint64_t *tag_data, int8_t way, int16_t bit)
{
	int16_t	sticky_bit;

	sticky_bit = bit;
	if ((tag_data[way] & ((uint64_t)1 << bit)) != 0)
		sticky_bit |= MSB_BIT;
	return (sticky_bit);
}

static cmd_Lxcache_t *
cmd_create_and_destroy_Lxcache(fmd_hdl_t *hdl, cmd_cpu_t *cpu,
	cmd_Lxcache_t *Lxcache)
{
	const char		*fltnm;
	cmd_Lxcache_t	*new_Lxcache;

	fltnm = cmd_type_to_str(Lxcache->Lxcache_type);

	/*
	 * We first create a new Lxcache and add the event ep
	 * that is in Lxcache to the new case we create.
	 * we then destroy the Lxcache that has the event ep in its SERD engine.
	 */
	new_Lxcache = cmd_Lxcache_create(hdl, Lxcache->xr, cpu,
	    cpu->cpu_asru_nvl,
	    Lxcache->Lxcache_type,
	    Lxcache->Lxcache_index, Lxcache->Lxcache_way, Lxcache->Lxcache_bit);
	if (new_Lxcache == NULL) {
		fmd_hdl_debug(hdl,
		    "\n%s:cpu_id %d:Failed to create a Lxcache for"
		    " index %d way %d bit %d\n",
		    fltnm, cpu->cpu_cpuid, Lxcache->Lxcache_index,
		    Lxcache->Lxcache_way, Lxcache->Lxcache_bit);
		return (NULL);
	}
	(void) cmd_create_case_for_Lxcache(hdl, cpu, new_Lxcache);
	cmd_Lxcache_destroy(hdl, cpu, Lxcache);
	return (new_Lxcache);
}

int
cmd_Lxcache_retire_as_reason(fmd_hdl_t *hdl, cmd_cpu_t *cpu,
    cmd_Lxcache_t *Lxcache, const char *fltnm, int32_t reason)
{
	boolean_t	ret;
	uint_t		certainty;

	if (reason == CMD_LXSUSPECT_0_TAG) {
		/*
		 * clear MSB bit to retire as SUSPECT_0_TAG
		 * We need to update the Lxcache asru to reflect
		 * the change in bit value.
		 */
		Lxcache->Lxcache_bit &= CLEAR_MSB_BIT;
		errno = nvlist_add_uint16(
		    Lxcache->Lxcache_asru_nvl,
		    FM_FMRI_CPU_CACHE_BIT,
		    Lxcache->Lxcache_bit);
		if (errno) {
			fmd_hdl_debug(hdl,
			    "\n%s:cpu_id %d: failed to update",
			    " CACHE_BIT in asru.\n",
			    fltnm, cpu->cpu_cpuid);
			return (CMD_EVD_BAD);
		}
	}
	if (reason == CMD_LXCONVICTED)
		certainty = HUNDRED_PERCENT;
	else
		certainty = SUSPECT_PERCENT;
	ret = cmd_Lxcache_retire(hdl, cpu, Lxcache, fltnm, certainty);
	if (reason == CMD_LXSUSPECT_0_TAG)
		Lxcache->Lxcache_bit |= SET_MSB_BIT;
	if (ret == B_FALSE)
		return (CMD_EVD_BAD);
	Lxcache->Lxcache_reason = reason;
	/*
	 * Update the persistence storage of
	 * Lxcache.
	 */
	fmd_hdl_debug(hdl,
	    "\n%s:cpu_id %d:reason = %s flags = %s\n",
	    fltnm, cpu->cpu_cpuid,
	    cmd_reason_to_str(Lxcache->Lxcache_reason),
	    cmd_flags_to_str(Lxcache->Lxcache_flags));
	cmd_Lxcache_write(hdl, Lxcache);
	return (CMD_EVD_OK);
}

int
retire_lowest_retirable_way_as_suspect(fmd_hdl_t *hdl, cmd_cpu_t *cpu,
    cmd_Lxcache_t *anonymous_Lxcache, const char *fltnm)
{
	/*
	 * This routine is called only when handling anonymous TAG or DATA
	 * errors. When we exit this routine we would have destroyed the
	 * anonymous_Lxcache structure that was passed to us and created
	 * a new Lxcache if we were successful in determining a way to retire.
	 */
	int8_t	lowest_retirable_way, ways_retired;
	int32_t	reason;
	cmd_ptrsubtype_t type;
	cmd_Lxcache_t *new_Lxcache;

	ways_retired = get_index_retired_ways(cpu,
	    anonymous_Lxcache->Lxcache_type,
	    anonymous_Lxcache->Lxcache_index);
	if (ways_retired == -1) {
		/*
		 * Couldn't determine how many ways have been retired at this
		 * index. Destroy the anonymous_Lxcache and return failure.
		 */
		cmd_Lxcache_destroy(hdl, cpu, anonymous_Lxcache);
		return (CMD_EVD_BAD);
	}
	/*
	 * Before retiring a way check if we have already
	 * retired 3 ways for this index.
	 * For TAG errors we will not perform this check because
	 * we could reretire cachlines retired for DATA errors.
	 * The get_lowest_retirable_way() will ensure that we do
	 * not end up retiring all 4 ways.
	 */
	if (!IS_TAG(anonymous_Lxcache->Lxcache_type)) {
		if (ways_retired >= 3) {
			fmd_hdl_debug(hdl,
			    "\n%s: cpu %d: num of ways retired for index %d"
			    " is %d will fault the CPU\n",
			    fltnm, cpu->cpu_cpuid,
			    anonymous_Lxcache->Lxcache_index, ways_retired);
			type = anonymous_Lxcache->Lxcache_type;
			/*
			 * destroy the anonymous_Lxcache
			 */
			cmd_Lxcache_destroy(hdl, cpu, anonymous_Lxcache);
			cmd_fault_the_cpu(hdl, cpu, type, fltnm);
			return (CMD_EVD_OK);
		}
	}
	/*
	 * No ways have been retired as "SUSPECT" for this bit.
	 * We need to retire the lowest unretired way as suspect.
	 */
	fmd_hdl_debug(hdl,
	    "\n%s: cpu_id %d Checking for the lowest retirable"
	    " way at index %d\n",
	    fltnm, cpu->cpu_cpuid, anonymous_Lxcache->Lxcache_index);
	lowest_retirable_way = cmd_Lxcache_get_lowest_retirable_way(cpu,
	    anonymous_Lxcache->Lxcache_index, anonymous_Lxcache->Lxcache_type);
	if (lowest_retirable_way != -1) {
		fmd_hdl_debug(hdl,
		    "\n%s: cpu_id %d lowest retirable way is %d\n",
		    fltnm, cpu->cpu_cpuid, lowest_retirable_way);
		anonymous_Lxcache->Lxcache_way = lowest_retirable_way;
		new_Lxcache = cmd_create_and_destroy_Lxcache(hdl, cpu,
		    anonymous_Lxcache);
		if ((new_Lxcache == NULL) ||
		    (new_Lxcache->Lxcache_case.cc_cp == NULL)) {
			return (CMD_EVD_BAD);
		}
		if (IS_TAG(new_Lxcache->Lxcache_type))
			reason = CMD_LXSUSPECT_0_TAG;
		else
			reason = CMD_LXSUSPECT_DATA;
		return (cmd_Lxcache_retire_as_reason(hdl, cpu, new_Lxcache,
		    fltnm, reason));
	} else {
		fmd_hdl_debug(hdl,
		    "\n%s:cpu_id %d we are unable to determine which"
		    " way is faulty at cache index %d."
		    " Will retire the CPU.\nRecommended-Action:"
		    " Service action required\n",
		    fltnm, cpu->cpu_cpuid, anonymous_Lxcache->Lxcache_index);
		type = anonymous_Lxcache->Lxcache_type;
		/*
		 * destroy the anonymous_Lxcache
		 */
		cmd_Lxcache_destroy(hdl, cpu, anonymous_Lxcache);
		cmd_fault_the_cpu(hdl, cpu, type, fltnm);
		return (CMD_EVD_OK);
	}
}

int
unretire_suspect_and_retire_next_retirable_way(fmd_hdl_t *hdl, cmd_cpu_t *cpu,
    cmd_Lxcache_t *suspect_Lxcache, cmd_Lxcache_t *anonymous_Lxcache,
    const char *fltnm)
{
	int8_t	retired_way, next_retirable_way;
	int32_t	retired_index;
	cmd_ptrsubtype_t retired_type;
	int32_t	reason;
	cmd_Lxcache_t *new_Lxcache;

	/*
	 * This routine is called only when handling anonymous TAG or DATA
	 * errors. When we exit this routine we would have destroyed the
	 * anonymous_Lxcache structure that was passed to us.
	 */
	fmd_hdl_debug(hdl,
	    "\n%s:cpu_id %d found index %d way %d"
	    " bit %d retired as %s. Will unretire this now.\n",
	    fltnm, cpu->cpu_cpuid, suspect_Lxcache->Lxcache_index,
	    suspect_Lxcache->Lxcache_way, suspect_Lxcache->Lxcache_bit,
	    cmd_reason_to_str(suspect_Lxcache->Lxcache_reason));
	/*
	 * Save the way because we will destroy the
	 * suspect_Lxcache after we successfully unretire it.
	 */
	retired_way = suspect_Lxcache->Lxcache_way;
	retired_index = suspect_Lxcache->Lxcache_index;
	retired_type = suspect_Lxcache->Lxcache_type;
	/*
	 * unretire the retired_way.
	 */
	if (cmd_Lxcache_unretire(hdl, cpu, suspect_Lxcache,
	    fltnm)
	    == B_TRUE) {
		suspect_Lxcache->Lxcache_reason =
		    CMD_LXFUNCTIONING;
		fmd_hdl_debug(hdl,
		    "\n%s:cpu_id %d index %d way %d"
		    " successfully unretired. Will"
		    " destroy this Lxcache now.\n",
		    fltnm, cpu->cpu_cpuid, suspect_Lxcache->Lxcache_index,
		    suspect_Lxcache->Lxcache_way);
		cmd_Lxcache_destroy(hdl, cpu, suspect_Lxcache);
	} else {
		/*
		 * destroy the anonymous_Lxcache
		 */
		cmd_Lxcache_destroy(hdl, cpu, anonymous_Lxcache);
		return (CMD_EVD_BAD);
	}
	/*
	 * retire the next retirable way
	 */
	next_retirable_way = cmd_Lxcache_get_next_retirable_way(cpu,
	    retired_index,
	    retired_type, retired_way);
	if (next_retirable_way == -1) {
		/*
		 * There is no retirable way that is next to the
		 * one we just retired. We need to offline the
		 * CPU since we are unable to determine which
		 * way is reporting the errors.
		 */
		fmd_hdl_debug(hdl,
		    "\n%s:cpu_id %d we are unable to determine"
		    " which way is faulty at cache index %d."
		    " It is likely that we have a leaky bit"
		    " that gets corrected.\n Will retire"
		    " the CPU.\nRecommended-Action: Service"
		    " action required\n",
		    fltnm, cpu->cpu_cpuid, retired_index);
		/*
		 * destroy the anonymous_Lxcache
		 */
		cmd_Lxcache_destroy(hdl, cpu, anonymous_Lxcache);
		cmd_fault_the_cpu(hdl, cpu, retired_type, fltnm);
		return (CMD_EVD_OK);
	} else {
		fmd_hdl_debug(hdl,
		    "\n%s:cpu_id %d found way %d at index %d to"
		    " retire as SUSPECT_0/SUSPECT_DATA\n",
		    fltnm, cpu->cpu_cpuid, next_retirable_way, retired_index);
		/*
		 * We need to create a new Lxcache struture.
		 * The existing Lxcache is for anonymous way.
		 */
		anonymous_Lxcache->Lxcache_way = next_retirable_way;
		new_Lxcache = cmd_create_and_destroy_Lxcache(hdl,
		    cpu, anonymous_Lxcache);
		if ((new_Lxcache == NULL) ||
		    (new_Lxcache->Lxcache_case.cc_cp == NULL)) {
			return (CMD_EVD_BAD);
		}
		if (IS_TAG(new_Lxcache->Lxcache_type))
			reason = CMD_LXSUSPECT_0_TAG;
		else
			reason = CMD_LXSUSPECT_DATA;
		return (cmd_Lxcache_retire_as_reason(hdl, cpu, new_Lxcache,
		    fltnm, reason));
	}
}

void
find_and_destroy_anonymous_Lxcache(fmd_hdl_t *hdl, cmd_cpu_t *cpu,
    cmd_ptrsubtype_t pstype, int32_t index)
{
	cmd_Lxcache_t *anonymous_Lxcache;
	const char	*fltnm;

	fltnm = cmd_type_to_str(pstype);
	anonymous_Lxcache =
	    cmd_Lxcache_lookup_by_type_index_way_bit(cpu,
	    pstype, index, -1, -1);
	if (anonymous_Lxcache != NULL) {
		fmd_hdl_debug(hdl,
		    "\n%s:cpu_id = %d index = %d We are destroying the"
		    " anonymous Lxcache now.\n",
		    fltnm, cpu->cpu_cpuid, index);
		/*
		 * Free the resources allocated to handle
		 * recheck_of_tags. Delete the Lxcache.
		 */
		cmd_Lxcache_destroy(hdl, cpu,
		    anonymous_Lxcache);
	}
}

void
cmd_Lxcache_anonymous_tag_error_timeout(fmd_hdl_t *hdl, id_t id)
{
	cmd_Lxcache_t	*Lxcache;
	const char	*class;


	/*
	 * We search thru the entire Lxcache structures to find
	 * a matching id.
	 */
	Lxcache = cmd_Lxcache_lookup_by_timeout_id(id);
	if (Lxcache == NULL) {
		fmd_hdl_debug(hdl,
		    "Could not find Lxcache for timeout_id 0x%x\n", id);
		return;
	}
	fmd_hdl_debug(hdl,
	    "\n%s:anonymous_tag_error_timeout:index = %d\n",
	    cmd_type_to_str(Lxcache->Lxcache_type),
	    Lxcache->Lxcache_index);
	/*
	 * Set timeout_id to -1 to indicate that we have processed the
	 * timeout.
	 */
	Lxcache->Lxcache_timeout_id = -1;
	switch (Lxcache->Lxcache_type) {
		case CMD_PTR_CPU_L2TAG:
			class = "ereport.cpu.ultraSPARC-IVplus.thce";
			(void) cmd_txce(hdl, Lxcache->Lxcache_ep,
			    Lxcache->Lxcache_nvl,
			    class, Lxcache->Lxcache_clcode);
			break;
		case CMD_PTR_CPU_L3TAG:
			class = "ereport.cpu.ultraSPARC-IVplus.l3-thce";
			(void) cmd_l3_thce(hdl, Lxcache->Lxcache_ep,
			    Lxcache->Lxcache_nvl,
			    class, Lxcache->Lxcache_clcode);
			break;
		default:
			fmd_hdl_debug(hdl,
			    "Unexpected pstype 0x%x found in"
			    " anonymous_tag_error_timeout: index = %d\n",
			    Lxcache->Lxcache_type,
			    Lxcache->Lxcache_index);
			return;
	}
}

cmd_evdisp_t
cmd_us4plus_tag_err(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
		cmd_cpu_t *cpu, cmd_ptrsubtype_t pstype,
		const char *serdn, const char *serdt,
		const char *fltnm, cmd_errcl_t clcode)
{
	uint64_t	tag_afar;
	int32_t	index;
	int8_t		way;
	int16_t		tag_bit, bit, sticky_bit;
	cmd_Lxcache_t	*Lxcache, *suspect_Lxcache, *retired_Lxcache;
	cmd_Lxcache_t	*anonymous_Lxcache;
	uint64_t	tag_synd;
	uint64_t	tag_data[PN_CACHE_NWAYS];
	uint8_t		state;
	int		ways_retired, ret;
	int		retries_for_ecc_match;
	int32_t		recheck_of_tags;
	int		way_already_retired = 0;

	/*
	 * We now extract physical tags and states
	 * and also look for matching ECC on all 4 ways.
	 */
	ret = extract_data_from_ereport_payload(hdl, nvl, cpu, pstype,
	    &tag_afar, tag_data, fltnm);
	if (ret != 0)
		return (ret);
	index = get_index(pstype, tag_afar);
	retries_for_ecc_match = 0;
	while (matching_ecc(tag_data) != 0) {
		if (retries_for_ecc_match >= MAX_RETRIES_FOR_ECC_MATCH)
			return (CMD_EVD_BAD);
		print_ecc(hdl, cpu, fltnm, tag_data);
		fmd_hdl_debug(hdl,
		    "\n%s:cpu_id = %d index = %d ECCs don't match.\n"
		    "Reading tag info again.\n",
		    fltnm, cpu->cpu_cpuid, index);
		(void) get_tagdata(cpu, pstype, index, tag_data);
		retries_for_ecc_match++;
	}
	ways_retired = get_retired_ways(tag_data);
	fmd_hdl_debug(hdl,
	    "\n%s:cpu_id %d: found %d ways retired at the index %d\n",
	    fltnm, cpu->cpu_cpuid, ways_retired, index);
	tag_synd = compute_syndrome(tag_data, pstype);
	ret = nvlist_lookup_int32(nvl, FM_EREPORT_RECHECK_OF_TAGS,
	    &recheck_of_tags);
	if (ret != CMD_EVD_OK) {
		fmd_hdl_debug(hdl,
		    "ret value = %d for nvlist_lookup of recheck_of_tags\n",
		    ret);
		recheck_of_tags = 0;
	}
	if (tag_synd == 0) {
		/*
		 * The bit has been corrected by writeback, we will
		 * first check if we are processing the re-check of tags
		 * that we scheduled thru the timeout call.
		 * if so we will exit if we reached the max retries.
		 * Else we start a timeout and exit.
		 * We will create a Lxcache structure for this index with way
		 * as -1 and bit as -1. We will also keep a count of
		 * attempts we made to check the tag data at this index.
		 *
		 */
		way = -1;
		bit = -1;
		Lxcache = cmd_Lxcache_lookup_by_type_index_way_bit(cpu, pstype,
		    index, way, bit);
		if (recheck_of_tags) {
			/*
			 * We are processing the re-read of tags scheduled by
			 * timeout. Exit if retry limit has been
			 * reached. Else start another timeout.
			 */
			if (Lxcache == NULL) {
				/*
				 * This shouldn't happen.
				 */
				fmd_hdl_debug(hdl,
				    "\n%s: cpu_id = %d failed to lookup"
				    " index = %d way %d bit %d\n",
				    fltnm, cpu->cpu_cpuid, index, way, bit);
				return (CMD_EVD_BAD);
			}
			fmd_hdl_debug(hdl,
			    "\n%s: cpu_id = %d index = %d syndrome"
			    " computed is 0 in attempt #%d.\n",
			    fltnm, cpu->cpu_cpuid, index,
			    Lxcache->Lxcache_retry_count);
			if (Lxcache->Lxcache_retry_count >=
			    RETRIES_TO_BE_DONE_WHEN_SYND_IS_ZERO) {
				/*
				 * We free only the nvl list here.
				 * anonymous SERD engine will be freed
				 * when the Lxcache gets destroyed.
				 * We need the anonymous SERD engine still
				 * because it has the event ep.
				 * reset or destroy of SERD engine frees the
				 * event ep.
				 */
				if (Lxcache->Lxcache_nvl != NULL) {
					nvlist_free(Lxcache->Lxcache_nvl);
					Lxcache->Lxcache_nvl = NULL;
				}
				fmd_hdl_debug(hdl,
		    "\n%s:cpu_id %d Max retry count reached. Giving up.\n",
				    fltnm, cpu->cpu_cpuid);
				Lxcache->Lxcache_timeout_id = -1;
				Lxcache->Lxcache_retry_count = 0;
				goto process_after_finding_way_bit;
			} else {
				Lxcache->Lxcache_retry_count++;
				Lxcache->Lxcache_timeout_id =
				    fmd_timer_install(hdl,
				    (void *)CMD_TIMERTYPE_ANONYMOUS_TAG_ERROR,
				    NULL,
				    (cmd_Lxcache_recheck_tags_delay[
				    Lxcache->Lxcache_retry_count] * NANOSEC));
				return (CMD_EVD_OK);
			}
		}
		/*
		 * Check if we already have a Lxcache structure
		 * with anonymous way and bit created.
		 */
		if (Lxcache == NULL) {
			Lxcache = cmd_Lxcache_create(hdl, 0, cpu,
			    cpu->cpu_asru_nvl, pstype, index, way, bit);
			if (Lxcache == NULL) {
				fmd_hdl_debug(hdl,
				    "\n%s:cpu_id %d Failed to create Lxcache"
				    " for index=%d\n",
				    fltnm, cpu->cpu_cpuid, index);
				return (CMD_EVD_BAD);
			}
		}
		if (Lxcache->Lxcache_timeout_id != -1) {
			/*
			 * We have another syndrome = 0 condition while we are
			 * still in the process of retrying for the previous
			 * condition.
			 */
			fmd_hdl_debug(hdl,
			    "\n%s: cpu_id = %d index = %d We have another"
			    " syndrome = 0 condition while we have already"
			    " scheduled a timeout. We will ignore this"
			    " event.\n",
			    fltnm, cpu->cpu_cpuid, index);
			return (CMD_EVD_OK);
		}
		fmd_hdl_debug(hdl,
		    "\n%s: cpu_id = %d index = %d syndrome computed is 0."
		    "Looks like the bit got corrected."
		    " Will check later to see if it is OK.\n",
		    fltnm, cpu->cpu_cpuid, index);
		/*
		 * We need to store the following arguments passed to
		 * this function(tag_error_handler) so that we can
		 * invoke this function from timeout routine.
		 *
		 * nvl, ep, clcode
		 */
		if (Lxcache->Lxcache_nvl == NULL) {
			if (nvlist_dup(nvl, &Lxcache->Lxcache_nvl, 0) != 0) {
				fmd_hdl_debug(hdl,
				    "\n%s:cpu_id %d Failed to duplicate nvl"
				    " for index=%d\n",
				    fltnm, cpu->cpu_cpuid, index);
				return (CMD_EVD_BAD);
			}
			if (nvlist_add_int32(Lxcache->Lxcache_nvl,
			    FM_EREPORT_RECHECK_OF_TAGS, 1) != 0) {
				fmd_hdl_debug(hdl,
				    "\n%s:cpu_id %d Failed to add"
				    " RECHECK_OF_TAGS in nvl for index=%d\n",
				    fltnm, cpu->cpu_cpuid, index);
				return (CMD_EVD_BAD);
			}
		}
		/*
		 * We are called with CMP_CPU_LEVEL_CORE masked out
		 * from cmd_txce(), cmd_l3_thce() routines.
		 * We need to set CMD_CPU_LEVEL_CORE because we want to handle
		 * both the cores on the Chip as one single cpu_id.
		 */
		Lxcache->Lxcache_clcode = (clcode | CMD_CPU_LEVEL_CORE);
		if (Lxcache->Lxcache_ep == NULL) {
			Lxcache->Lxcache_ep = ep;
			/*
			 * we need to preserve the event ep so that it does
			 * not get destroyed when we return from this call.
			 * We do that by adding the event ep to the SERD engine.
			 * The SERD engine we create is different from the one
			 * we create when we handle the actual event at label
			 * process_after_finding_way_bit.
			 */
			Lxcache->Lxcache_serdnm =
			    cmd_Lxcache_anonymous_serdnm_create(hdl,
			    cpu->cpu_cpuid, pstype, index,
			    way, bit);
			if (!fmd_serd_exists(hdl, Lxcache->Lxcache_serdnm)) {
				fmd_serd_create(hdl, Lxcache->Lxcache_serdnm,
				    fmd_prop_get_int32(hdl, serdn),
				    fmd_prop_get_int64(hdl, serdt));
				fmd_hdl_debug(hdl,
				    "\n%s: cpu_id %d: created a SERD engine"
				    " %s\n",
				    fltnm, cpu->cpu_cpuid,
				    Lxcache->Lxcache_serdnm);
			}
			(void) fmd_serd_record(hdl,
			    Lxcache->Lxcache_serdnm,
			    ep);
		}
		Lxcache->Lxcache_retry_count++;
		Lxcache->Lxcache_timeout_id =
		    fmd_timer_install(hdl,
		    (void *)CMD_TIMERTYPE_ANONYMOUS_TAG_ERROR, NULL,
		    (cmd_Lxcache_recheck_tags_delay[
		    Lxcache->Lxcache_retry_count] * NANOSEC));
		return (CMD_EVD_OK);

	} else {
		/*
		 * tag_synd != 0
		 * determine way and bit
		 */
		tag_bit = ecc_syndrome_tab[tag_synd & 0x1ff];
		fmd_hdl_debug(hdl,
		    "\n%s: cpu_id = %d index = %d tag_bit %03d is faulty.\n",
		    fltnm, cpu->cpu_cpuid, index, tag_bit);
		if ((tag_bit > C8)) {
			fmd_hdl_debug(hdl, "%s: cpu_id = %d"
			    " Unexpected MTAG or Multiple bit error detected\n",
			    fltnm, cpu->cpu_cpuid);
			find_and_destroy_anonymous_Lxcache(hdl, cpu, pstype,
			    index);
			return (CMD_EVD_BAD);
		}
		if ((tag_bit >= C0) && (tag_bit <= C8)) {
			/*
			 * ECC bit is corrupted.
			 * Need to offline the CPU
			 */
			bit = (tag_bit - C0) + PN_LX_TAG_ECC_START_BIT;
			way = 0;
			fmd_hdl_debug(hdl,
			    "\n%s: cpu_id = %d ECC bit is faulty.\n",
			    fltnm, cpu->cpu_cpuid);
		} else {
			bit = tag_bit_to_way_bit(pstype, tag_bit);
			way = bit_to_way(pstype, tag_bit);
			if (way < 0) {
				fmd_hdl_debug(hdl,
				    "\n%s: cpu_id = %d %d bit indicted is a"
				    " meta bit  !!\n",
				    fltnm, cpu->cpu_cpuid, bit);
				find_and_destroy_anonymous_Lxcache(hdl, cpu,
				    pstype,
				    index);
				return (CMD_EVD_BAD);
			}
		}
	}	/* end of tag_synd != 0 */
process_after_finding_way_bit:
	if ((Lxcache = cmd_Lxcache_lookup_by_type_index_way_bit(cpu, pstype,
	    index, way,
	    bit)) != NULL &&
	    Lxcache->Lxcache_case.cc_cp != NULL &&
	    fmd_case_solved(hdl, Lxcache->Lxcache_case.cc_cp)) {
		fmd_hdl_debug(hdl,
		    "\n%s:cpu %d: the case for %s is already solved.\n",
		    fltnm, cpu->cpu_cpuid, Lxcache->Lxcache_bufname);
		find_and_destroy_anonymous_Lxcache(hdl, cpu, pstype, index);
		return (CMD_EVD_REDUND);
	}

	if (Lxcache == NULL)
		Lxcache = cmd_Lxcache_create(hdl, 0, cpu, cpu->cpu_asru_nvl,
		    pstype, index, way, bit);
	if (Lxcache == NULL) {
		fmd_hdl_debug(hdl,
		    "\n%s:cpu %d: Failed to create Lxcache for index %d",
		    " way %d bit %d\n",
		    fltnm, cpu->cpu_cpuid, index, way, bit);
		find_and_destroy_anonymous_Lxcache(hdl, cpu, pstype, index);
		return (CMD_EVD_BAD);
	}
	if (cmd_create_case_for_Lxcache(hdl, cpu, Lxcache) == B_FALSE) {
		find_and_destroy_anonymous_Lxcache(hdl, cpu, pstype, index);
		return (CMD_EVD_BAD);
	}
	if (Lxcache->Lxcache_case.cc_serdnm == NULL) {
		Lxcache->Lxcache_case.cc_serdnm = cmd_Lxcache_serdnm_create(hdl,
		    cpu->cpu_cpuid, pstype, index,
		    way, bit);
		if (!fmd_serd_exists(hdl, Lxcache->Lxcache_case.cc_serdnm)) {
			fmd_serd_create(hdl, Lxcache->Lxcache_case.cc_serdnm,
			    fmd_prop_get_int32(hdl, serdn),
			    fmd_prop_get_int64(hdl, serdt));
			fmd_hdl_debug(hdl,
			    "\n%s: cpu_id %d: created a SERD engine %s\n",
			    fltnm, cpu->cpu_cpuid,
			    Lxcache->Lxcache_case.cc_serdnm);
		}
	}
	fmd_hdl_debug(hdl,
	    "\n%s:cpu_id %d: Checking if the SERD engine %s has fired.\n",
	    fltnm, cpu->cpu_cpuid, Lxcache->Lxcache_case.cc_serdnm);

	(void) fmd_serd_record(hdl, Lxcache->Lxcache_case.cc_serdnm, ep);
	if (way >= 0) {
		/*
		 * Now that we have recorded the event ep we can do the
		 * necessary cleanup of resources allocated for recheck of tags.
		 */
		find_and_destroy_anonymous_Lxcache(hdl, cpu, pstype, index);
	}
	if (fmd_serd_fired(hdl, Lxcache->Lxcache_case.cc_serdnm) ==
	    FMD_B_FALSE)
		return (CMD_EVD_OK);

	fmd_hdl_debug(hdl, "\n%s: cpu_id = %d creating fault %s\n",
	    fltnm, cpu->cpu_cpuid, Lxcache->Lxcache_case.cc_serdnm);
	fmd_case_add_serd(hdl, Lxcache->Lxcache_case.cc_cp,
	    Lxcache->Lxcache_case.cc_serdnm);
	fmd_serd_reset(hdl, Lxcache->Lxcache_case.cc_serdnm);
	if (way == -1) {
		/*
		 * The assignment below is to make the code easier to maintain.
		 * We need to destroy the anonymous_Lxcache after we have
		 * identifed a way to retire. If we cannot detrmine a way to
		 * retire we will destrory the anonymous_Lxcache and fault the
		 * cpu.
		 */
		anonymous_Lxcache = Lxcache;
		/*
		 * Anonymous TAG way retirement.
		 * - if a way at this index has already been retired as
		 *   "suspect-1", unretire that way, and retire the next
		 *   unretired way as "suspect-0", using a pattern of all zeros
		 *   for the PA bits.
		 * - if a way at this index has already been retired as
		 *   "suspect-0", re-retire that way as "suspect-1", using a
		 *   pattern of all ones for the PA bits.
		 * - if no ways have been retired as "suspect" for this index,
		 *   retire the lowest unretired way as "suspect-0" for this
		 *   bit, using a pattern of all zeros for the PA bits.
		 * - if there is no next retirable way, fault the CPU.
		 */
		suspect_Lxcache = cmd_Lxcache_lookup_by_type_index_bit_reason(
		    cpu, pstype, index, bit, CMD_LXSUSPECT_1_TAG);
		anonymous_Lxcache->Lxcache_ep = ep;
		if (suspect_Lxcache) {
			ret = unretire_suspect_and_retire_next_retirable_way(
			    hdl, cpu, suspect_Lxcache, anonymous_Lxcache,
			    fltnm);
			return (ret);
		}	/* end SUSPECT_1_TAG */
		suspect_Lxcache = cmd_Lxcache_lookup_by_type_index_bit_reason(
		    cpu, pstype, index, bit, CMD_LXSUSPECT_0_TAG);
		if (suspect_Lxcache) {
			fmd_hdl_debug(hdl,
			    "\n%s:cpu_id %d found index %d way %d"
			    " bit %d retired as SUSPECT_0_TAG. Will"
			    " re-retire this now as SUSPECT_1_TAG.\n",
			    fltnm, cpu->cpu_cpuid, index,
			    suspect_Lxcache->Lxcache_way, bit);
			/*
			 * destroy the anonymous_Lxcache
			 */
			cmd_Lxcache_destroy(hdl, cpu, anonymous_Lxcache);
			suspect_Lxcache->Lxcache_ep = ep;
			/*
			 * We need to update the FM_FMRI_CPU_CACHE_BIT entry
			 * in the Lxcache_asru_nvl. This entry was last updated
			 * when the cacheline was retired as SUSPECT_0.
			 * Therefore the MSB of FM_FMRI_CPU_CACHE_BIT entry
			 * value will be reset. To retire cacheline as
			 * SUSPECT_1 the MSB has to be set.
			 */
			errno = nvlist_add_uint16(
			    suspect_Lxcache->Lxcache_asru_nvl,
			    FM_FMRI_CPU_CACHE_BIT,
			    suspect_Lxcache->Lxcache_bit);
			if (errno) {
				fmd_hdl_debug(hdl,
				    "\n%s:cpu_id %d: failed to update",
				    " CACHE_BIT in asru.\n",
				    fltnm, cpu->cpu_cpuid);
			}
			return (cmd_Lxcache_retire_as_reason(hdl, cpu,
			    suspect_Lxcache, fltnm, CMD_LXSUSPECT_1_TAG));
		}	/* end of SUSPECT_0_TAG */
		/*
		 * No ways have been retired as "SUSPECT_x" for this bit.
		 * We need to retire the lowest unretired way as suspect.
		 */
		ret = retire_lowest_retirable_way_as_suspect(hdl, cpu,
		    anonymous_Lxcache,
		    fltnm);
		return (ret);
	}	/* End of Anonymous TAG retirement */
	/*
	 * Identified bit and way has fired.
	 * - Destroy any anonymous SERD engine at that index.
	 * - If the bad bit is an ECC bit, fault the CPU.
	 * - If the way was already convicted due to tag errors, fault the CPU.
	 * - If the bad bit is a state bit, then:
	 * - if the stable value of the bad bit will hold the NA encoding,
	 *   retire the containing way as "convicted".
	 * - if the stable value of the bad bit will not hold the NA
	 *   encoding, fault the CPU.
	 */
	cmd_Lxcache_destroy_anonymous_serd_engines(hdl, cpu, pstype, index, -1);
	sticky_bit = find_bit_stickiness(tag_data, way, bit);
	if ((bit >= PN_LX_TAG_ECC_START_BIT) &&
	    (bit <= PN_LX_TAG_ECC_END_BIT)) {
		fmd_hdl_debug(hdl,
		    "\n%s:cpu_id %d Bad ECC bit %d at cache index %d way %d"
		    " detected. Will offline the CPU.\n",
		    fltnm, cpu->cpu_cpuid, bit, index, way);
		cmd_fault_the_cpu(hdl, cpu, pstype, fltnm);
		return (CMD_EVD_OK);
	}
	/*
	 * Check if a STATE bit is faulty.
	 * If so we need to ensure that we will be able to
	 * make the way NA, else fault the CPU.
	 */
	if (bit <= PN_LX_STATE_END_BIT) {
		fmd_hdl_debug(hdl,
		    "%s cpu_id = %d: STATE bit %d is faulty.\n",
		    fltnm, cpu->cpu_cpuid, bit);
		/*
		 * If the stable value of bit will hold the NA encoding
		 * retire the containing way Else fault the cpu.
		 */
		state = tag_data[way] & CH_ECSTATE_MASK;
		if ((state & (1 << bit)) != (PN_ECSTATE_NA & (1 << bit))) {
			/*
			 * The stable value of the bad bit will not hold the
			 * NA encoding. will fault the CPU.
			 */
			fmd_hdl_debug(hdl,
			    "\n%s:cpu_id %d STATE bit %d is faulty at"
			    " cache index %d way %d. STATE = 0x%x\n"
			    " The bad bit will not hold the encoding we need"
			    " to mark the cacheline as retired, so will offline"
			    " the CPU.\n",
			    fltnm, cpu->cpu_cpuid, bit, index, way, state);
			cmd_fault_the_cpu(hdl, cpu, pstype, fltnm);
			return (CMD_EVD_OK);
		}
	}
	/*
	 * Check if we are getting fault on a way that is already retired.
	 * if the way was already convicted due to tag errors, fault the CPU.
	 * Note that the way could have previously been retired due to
	 * data errors.  This is okay; we just re-retire it due to tag errors,
	 * so that we can write the offending tag bit to a stable value.
	 */
	if ((tag_data[way] & CH_ECSTATE_MASK) == PN_ECSTATE_NA) {
		/*
		 * Looking for CONVICTED TAG fault first.
		 * If found retire the CPU.
		 */
		retired_Lxcache = cmd_Lxcache_lookup_by_type_index_way_reason(
		    cpu, pstype, index, way, CMD_LXCONVICTED);
		if (retired_Lxcache) {
			fmd_hdl_debug(hdl,
			    "\n%s: cpu %d: The cache index %d way %d previously"
			    " retired for %s fault at bit %d is reporting"
			    " fault. Will fault the CPU\n",
			    fltnm, cpu->cpu_cpuid, index, way,
			    cmd_type_to_str(
			    retired_Lxcache->Lxcache_type),
			    retired_Lxcache->Lxcache_bit);
			cmd_fault_the_cpu(hdl, cpu, pstype, fltnm);
			return (CMD_EVD_OK);
		}
		way_already_retired = 1;
	}
	/*
	 * If any way(Including the current way) at this index is retired as
	 * "suspect" due to tag errors, unretire it.  (If that suspect way
	 * really was bad, it will start producing errors again and will
	 * eventually be retired again.)
	 */
	suspect_Lxcache = cmd_Lxcache_lookup_by_type_index_bit_reason(
	    cpu, pstype, index,  -1,
	    (CMD_LXSUSPECT_0_TAG | CMD_LXSUSPECT_1_TAG));
	if (suspect_Lxcache) {
		fmd_hdl_debug(hdl,
		    "\n%s:cpu_id %d found index %d way %d"
		    " bit %d retired as SUSPECT_x. Will"
		    "  unretire this now.\n",
		    fltnm, cpu->cpu_cpuid, index,
		    suspect_Lxcache->Lxcache_way, -1);
		/*
		 * unretire the suspect_x retired_way.
		 */
		if (cmd_Lxcache_unretire(hdl, cpu, suspect_Lxcache, fltnm)
		    == B_TRUE) {
			suspect_Lxcache->Lxcache_reason =
			    CMD_LXFUNCTIONING;
			fmd_hdl_debug(hdl,
			    "\n%s:cpu_id %d index %d way %d"
			    " successfully unretired. Will"
			    " destroy this Lxcache now.\n",
			    fltnm, cpu->cpu_cpuid, index,
			    suspect_Lxcache->Lxcache_way);
			cmd_Lxcache_destroy(hdl, cpu, suspect_Lxcache);
		} else {
			/*
			 * We are unable to unretire the previously retired
			 * SUSPECT way at the fault index.
			 * If the previously retired way is same as the way
			 * we are attempting to retire then return failure.
			 */
			if (suspect_Lxcache->Lxcache_way ==
			    Lxcache->Lxcache_way)
				return (CMD_EVD_BAD);
		}
	}
	ways_retired = get_index_retired_ways(cpu, pstype, index);
	if (ways_retired == -1)
		return (CMD_EVD_BAD);
	/*
	 * Before retiring a way check if we have already
	 * retired 3 ways for this index.
	 * If the way was already retired due to DATA error or
	 * SUSPECT_X TAG error then we skip the check.
	 */
	if (!way_already_retired) {
		if (ways_retired >= 3) {
			fmd_hdl_debug(hdl,
			    "\n%s: cpu %d: num of ways retired for index %d"
			    " is %d will fault the CPU\n",
			    fltnm, cpu->cpu_cpuid, index, ways_retired);
			cmd_fault_the_cpu(hdl, cpu, pstype, fltnm);
			return (CMD_EVD_OK);
		}
	}
	fmd_hdl_debug(hdl,
	    "\n%s: cpu %d: num of ways retired for index %d is %d\n",
	    fltnm, cpu->cpu_cpuid, index, ways_retired);
	if ((errno = nvlist_add_uint16(Lxcache->Lxcache_asru_nvl,
	    FM_FMRI_CPU_CACHE_BIT,
	    sticky_bit)) != 0 ||
	    (errno = fmd_nvl_fmri_expand(hdl, Lxcache->Lxcache_asru_nvl)) != 0)
		fmd_hdl_abort(hdl, "failed to build Lxcache fmri");
	Lxcache->Lxcache_ep = ep;
	return (cmd_Lxcache_retire_as_reason(hdl, cpu, Lxcache, fltnm,
	    CMD_LXCONVICTED));
}

static boolean_t
pn_there_is_a_matching_synd(fmd_hdl_t *hdl, cmd_xr_t *xr)
{
	int ec_data_idx, i;
	int8_t	way;
	uint64_t ec_tag, data_hi, data_lo;
	int ecc, calc_synd;
	ec_data_elm_t *ecdptr = NULL;
	uint8_t state;
	ch_ec_data_t	*ecp;

	ecp = (ch_ec_data_t *)(xr->xr_cache_data);
	for (way = 0; way < xr->xr_num_ways; way++, ecp++) {
		ec_tag = ecp->ec_tag;
		/*
		 * skip Retired and Invalid ways
		 */
		state = ec_tag & CH_ECSTATE_MASK;
		if ((state == PN_ECSTATE_NA) ||
		    (state == CH_ECSTATE_INV))
			continue;
		/*
		 * Each 16 bytes of data are protected by 9-bit ECC field.
		 */

		for (i = 0; i < (CH_ECACHE_SUBBLK_SIZE/16); i++) {
			ec_data_idx = (i/2);

			ecdptr = &ecp->ec_data[ec_data_idx];
			if ((i & 1) == 0) {
				ecc = (ecdptr->ec_eccd >> 9) & 0x1ff;
				data_hi = ecdptr->ec_d8[0];
				data_lo = ecdptr->ec_d8[1];
			} else {
				ecc = ecdptr->ec_eccd & 0x1ff;
				data_hi = ecdptr->ec_d8[2];
				data_lo = ecdptr->ec_d8[3];
			}

			calc_synd = calcsynd(data_hi, data_lo, ecc);
			if ((calc_synd != 0) &&
			    (xr->xr_synd == calc_synd)) {
				if (xr->xr_num_ways == 1) {
					fmd_hdl_debug(hdl,
			"\ncomputed syndrome matches with the reported syndrome"
			" 0x%x index = %d way = %d\n",
					    xr->xr_synd, xr->xr_error_index,
					    xr->xr_error_way);
				} else {
					fmd_hdl_debug(hdl,
					    "\ncomputed syndrome matches with"
					    " the reported syndrome"
					    " 0x%x index = %d way = %d\n",
					    xr->xr_synd, xr->xr_error_index,
					    way);
					xr->xr_error_way = way;
				}
				return (B_TRUE);
			}
		}
	}
	return (B_FALSE);
}

/* add to cheetahregs.h */
#define	CH_ECSTATE_NA 	5

static int32_t
pn_extract_index(int32_t type, uint64_t afar)
{
	int32_t index = -1;

	switch (type) {
		case CMD_PTR_CPU_L2DATA:
			index = (int32_t)((afar & PN_L2_INDEX_MASK)
			    >> PN_CACHE_LINE_SHIFT);
			break;
		case CMD_PTR_CPU_L3DATA:
			index = (int32_t)((afar & PN_L3_INDEX_MASK)
			    >> PN_CACHE_LINE_SHIFT);
			break;
	}
	return (index);
}

/*
 *	cmd_cache_ce_panther
 *
 *	This routine handles L2 and L3 cachedata errors for the Panther.
 *	It's called when the train processing for L2 and L3 correctable
 *	data errors are about to issue a fault.
 *
 *	This routine retrieves payload information gathered during the XR
 *	processing and generates a unique SERD engine and cache data
 *	associated with the CPU if one does not exist.
 *	If the SERD fires for the given engine it will initiate a cache
 *	line fault if the way is not anonomyous.
 *	If the way is anonomyous, it will attempt to choose a way for the
 *	given index to fault. If the maximum for the index has not been
 *	reached, it will attempt to unretire a different way previously retired
 * 	under suspicion for the index prior to faulting
 *	the selected way.
 *	The routine will also fault the CPU if the maximum number of
 *	retired ways for the CPU has been exceeded based on the category.
 */
/*ARGSUSED*/
int
cmd_cache_ce_panther(fmd_hdl_t *hdl, fmd_event_t *ep, cmd_xr_t *xr)
{
	cmd_Lxcache_t *suspect_Lxcache, *Lxcache, *anonymous_Lxcache;
	cmd_cpu_t *cpu = xr->xr_cpu;
	cmd_case_t *cpu_cc;
	cmd_ptrsubtype_t type;
	const errdata_t *cache_ed;
	uint16_t offset;
	int16_t bit;
	int	ways_retired;
	int	ret;

	/*
	 * The caller of this routine cmd_xxc_hdlr() expects us to
	 * return CMD_EVD_OK for success and CMD_EVD_BAD for failures.
	 * If this is not a Panther or one of the Panther specific
	 * errors that we handle here, then exit
	 */

	if (cpu->cpu_pers.cpup_type != CPU_ULTRASPARC_IVplus)
		return (CMD_EVD_BAD);

	if (!(xr->xr_clcode & (int)PN_CACHE_ERRORS))
		return (CMD_EVD_BAD);


	/* Set up Cache specific structs */

	if (CMD_ERRCL_ISL2XXCU(xr->xr_clcode)) {
		type = CMD_PTR_CPU_L2DATA;
		cpu_cc = &cpu->cpu_l2data;
		cache_ed = &l2errdata;
	} else {
		type = CMD_PTR_CPU_L3DATA;
		cpu_cc = &cpu->cpu_l3data;
		cache_ed = &l3errdata;
	}

	/* Ensure that our case is not solved */

	if (cpu->cpu_faulting || (cpu_cc->cc_cp != NULL &&
	    fmd_case_solved(hdl, cpu_cc->cc_cp)))
			return (CMD_EVD_OK);

	fmd_hdl_debug(hdl, "Processing Panther %s Error\n",
	    cache_ed->ed_fltnm);

	/* L3 errors arrive as mem scheme errors - convert to CPU */
	if (type == CMD_PTR_CPU_L3DATA) {
		cmd_fmri_init(hdl, &xr->xr_rsrc,
		    xr->xr_detector_nvlist, "%s_rsrc",
		    fmd_case_uuid(hdl, xr->xr_case));
	}
	bit = (uint8_t)ecc_syndrome_tab[xr->xr_synd];
	offset = (uint16_t)xr->xr_afar & 0x3f;
	if (bit > C8) {
		fmd_hdl_debug(hdl, "xxC/LDxC dropped due to syndrome\n");
		return (CMD_EVD_BAD);
	}
	if (bit < C0) {
		/*
		 * Data bit. Set bit in the range 0-511
		 */
		bit += ((3 - (offset/16)) * 128);
	} else {
		/*
		 * ECC bit. Set bit in the range 512-547
		 */
		bit -= C0;
		bit += 512 + ((3 - (offset/16)) * PN_LX_NUM_OF_BITS_IN_ECC);
	}
	xr->xr_error_index = pn_extract_index(type, xr->xr_afar);
	if (xr->xr_error_index == 0xffffffff) {
		fmd_hdl_debug(hdl, "xxC/LDxC dropped due to index\n");
		return (CMD_EVD_BAD);
	}
	fmd_hdl_debug(hdl, "cpu_id: %d, syndrome: 0x%x, afar: 0x%llx\n",
	    xr->xr_cpuid, xr->xr_synd, xr->xr_afar);
	fmd_hdl_debug(hdl, "index: 0x%x(%d) bit: %d\n",
	    xr->xr_error_index, xr->xr_error_index, bit);
	/*
	 * The payload information for the DATA errors are assembled
	 * after first looking for a valid line that matches the fault AFAR.
	 * If no match is found all 4 ways are logged and xr_num_ways
	 * will be 4. If a matching way is found only that entry is logged
	 * and xr_num_ways is set as 1.
	 * The xr_error_way is set as -1 when xr_num_ways is 4, else
	 * xr_error_way is set to the matching way.
	 * what we do below is to force the xr_error_way to -1 for WDC/CPC
	 * errors.
	 * For UCC and EDC errors the xr_error_way will be set correctly.
	 */

	switch (xr->xr_clcode) {
		case CMD_ERRCL_WDC:
		case CMD_ERRCL_L3_WDC:
			/*
			 * WDC is a disrupting trap, and invalidates and
			 * overwrites the problematic way.  Any match is due to
			 * a refetch of the AFAR, which could have been to any
			 * way. So these are treated as "anonymous".
			 */
			fmd_hdl_debug(hdl, "WDC fault detected\n");
			xr->xr_error_way = (uint32_t)CMD_ANON_WAY;
			break;
		case CMD_ERRCL_CPC:
		case CMD_ERRCL_L3_CPC:
			/*
			 * CPC is a disrupting trap, but since it happens due to
			 * a snoop, the problematic way could become invalid,
			 * overwritten by a different cache line, and then the
			 * AFAR accessed and pulled into a different way,
			 * causing a false positive match.  So it's best to not
			 * look for a matching way and just ascribe these to
			 *  the "anonymous" way.
			 */
			fmd_hdl_debug(hdl, "CPC fault detected\n");
			xr->xr_error_way = (uint32_t)CMD_ANON_WAY;
			break;
		case CMD_ERRCL_UCC:
		case CMD_ERRCL_L3_UCC:
			/*
			 * UCC is a precise trap, so, absent activity from the
			 * other core, the tag address values read by the TL=1
			 * trap handler are likely to be the same as those at
			 * the time of the trap.
			 * (A snoop from another CPU might cause a change in
			 * state from valid to invalid, but the  tag address
			 * won't change.) If we find a matching valid tag,
			 * that identifies the way.
			 */
			fmd_hdl_debug(hdl, "UCC fault detected\n");
			fmd_hdl_debug(hdl, "# of ways collected are %d\n",
			    xr->xr_num_ways);
			fmd_hdl_debug(hdl,
			    "\n%s:cpu_id %d: error way = %d\n",
			    cache_ed->ed_fltnm, cpu->cpu_cpuid,
			    xr->xr_error_way);
			break;
		case CMD_ERRCL_EDC:
		case CMD_ERRCL_L3_EDC:
			/*
			 * EDC is a disrupting trap, but again if a matching
			 * valid way is found, it is likely to be the correct
			 * way.
			 */
			fmd_hdl_debug(hdl, "EDC fault detected\n");
			fmd_hdl_debug(hdl, "# of ways collected are %d\n",
			    xr->xr_num_ways);
			fmd_hdl_debug(hdl,
			    "\n%s:cpu_id %d: error way = %d\n",
			    cache_ed->ed_fltnm, cpu->cpu_cpuid,
			    xr->xr_error_way);
			break;
		default:
			fmd_hdl_debug(hdl, "Unexpected fault detected\n");
			xr->xr_error_way = (uint32_t)CMD_ANON_WAY;
	}
	if ((type == CMD_PTR_CPU_L2DATA) &&
	    (xr->xr_cache_data != NULL) &&
	    (!pn_there_is_a_matching_synd(hdl, xr))) {
		fmd_hdl_debug(hdl, "No matching syndrome\n");
	}
	Lxcache = cmd_Lxcache_lookup_by_type_index_way_bit(xr->xr_cpu, type,
	    xr->xr_error_index, xr->xr_error_way, bit);

	if (Lxcache == NULL) {
		fmd_hdl_debug(hdl,
		    "\n%s: cpu %d: creating a case for index %d way %d"
		    " bit %d\n",
		    cache_ed->ed_fltnm, xr->xr_cpuid,
		    xr->xr_error_index, xr->xr_error_way, bit);
		Lxcache = cmd_Lxcache_create(hdl, xr, xr->xr_cpu,
		    xr->xr_cpu->cpu_asru_nvl,
		    type, xr->xr_error_index,
		    xr->xr_error_way, bit);
		if (Lxcache == NULL) {
			fmd_hdl_debug(hdl,
			    "\n%s:cpu_id %d:Failed to create a Lxcache for"
			    " index %d way %d bit %d\n",
			    cache_ed->ed_fltnm, cpu->cpu_cpuid,
			    Lxcache->Lxcache_index,
			    Lxcache->Lxcache_way, Lxcache->Lxcache_bit);
			return (CMD_EVD_BAD);
		}
	}
	if (cmd_create_case_for_Lxcache(hdl, cpu, Lxcache) == B_FALSE)
		return (CMD_EVD_BAD);
	if (Lxcache->Lxcache_case.cc_serdnm == NULL) {
		Lxcache->Lxcache_case.cc_serdnm =
		    cmd_Lxcache_serdnm_create(hdl, xr->xr_cpuid,
		    type, xr->xr_error_index, xr->xr_error_way, bit);

		if (!fmd_serd_exists(hdl,
		    Lxcache->Lxcache_case.cc_serdnm)) {
			fmd_serd_create(hdl,
			    Lxcache->Lxcache_case.cc_serdnm,
			    cache_ed->ed_serd->cs_n,
			    cache_ed->ed_serd->cs_t);
			fmd_hdl_debug(hdl,
			    "\n%s: cpu_id %d: created a SERD engine %s\n",
			    cache_ed->ed_fltnm, cpu->cpu_cpuid,
			    Lxcache->Lxcache_case.cc_serdnm);
		}
	}
	/* Ensure that our case is not solved */
	if ((Lxcache->Lxcache_case.cc_cp != NULL) &&
	    fmd_case_solved(hdl, Lxcache->Lxcache_case.cc_cp)) {
		fmd_hdl_debug(hdl,
		    "\n%s:cpu %d: the case for %s is already solved.\n",
		    cache_ed->ed_fltnm, cpu->cpu_cpuid,
		    Lxcache->Lxcache_bufname);
		return (CMD_EVD_REDUND);
	}

	fmd_hdl_debug(hdl,
	    "\n%s:cpu_id %d: checking if SERD engine %s has fired.\n",
	    cache_ed->ed_fltnm, xr->xr_cpuid, Lxcache->Lxcache_case.cc_serdnm);

	if (fmd_serd_record(hdl, Lxcache->Lxcache_case.cc_serdnm, ep)
	    == FMD_B_FALSE)
		return (CMD_EVD_OK); /* serd engine hasn't fired yet */

	fmd_hdl_debug(hdl, "\n%s: cpu_id = %d creating fault %s\n",
	    cache_ed->ed_fltnm, cpu->cpu_cpuid,
	    Lxcache->Lxcache_case.cc_serdnm);
	fmd_case_add_serd(hdl, Lxcache->Lxcache_case.cc_cp,
	    Lxcache->Lxcache_case.cc_serdnm);
	fmd_serd_reset(hdl, Lxcache->Lxcache_case.cc_serdnm);
	/*
	 * Find out if there is a way at the fault index/bit that was retired
	 * as suspect. We need this information for both anonymous way and
	 * identified way handling. We store this info in suspect_Lxcache.
	 */
	fmd_hdl_debug(hdl,
	    "\n%s:cpu_id %d checking if there is a way at"
	    " index %d retired as suspect due to bit %d\n",
	    cache_ed->ed_fltnm, cpu->cpu_cpuid,
	    Lxcache->Lxcache_index, Lxcache->Lxcache_bit);
	suspect_Lxcache = cmd_Lxcache_lookup_by_type_index_bit_reason(
	    cpu, type, Lxcache->Lxcache_index, Lxcache->Lxcache_bit,
	    CMD_LXSUSPECT_DATA);
	if (xr->xr_error_way != (uint32_t)CMD_ANON_WAY) {
		/*
		 * IDENTIFIED WAY DATA error handling.
		 *
		 * If there is a way at that index retired as suspect due
		 * to that bit, unretire it.
		 * retire the identified way, and mark the way as "convicted"
		 * for this bit. Destroy any anonymous SERD engine named by
		 * that index and bit.
		 */
		if (suspect_Lxcache != NULL) {
			fmd_hdl_debug(hdl,
			    "\n%s:cpu_id %d found index %d way %d"
			    " bit %d retired on suspicion. Will"
			    "  unretire this now.\n",
			    cache_ed->ed_fltnm, cpu->cpu_cpuid,
			    suspect_Lxcache->Lxcache_index,
			    suspect_Lxcache->Lxcache_way,
			    suspect_Lxcache->Lxcache_bit);
			/*
			 * unretire the retired_way.
			 */
			if (cmd_Lxcache_unretire(hdl, cpu, suspect_Lxcache,
			    cache_ed->ed_fltnm) == B_TRUE) {
				suspect_Lxcache->Lxcache_reason =
				    CMD_LXFUNCTIONING;
				cmd_Lxcache_destroy(hdl, cpu, suspect_Lxcache);
			}
			/*
			 * We proceed to retire the identified way even if
			 * we are unable to unretire the suspect way.
			 * We will not end up retiring all 4 ways because
			 * we check the actual number of ways retired
			 * at this index by reading the info from processor
			 * directly. The call to get_index_retired_ways() does
			 * that.
			 */
		}
		/*
		 * Before retiring a way check if we have already
		 * retired 3 ways for this index.
		 */
		ways_retired = get_index_retired_ways(cpu, type,
		    Lxcache->Lxcache_index);
		if (ways_retired == -1) {
			fmd_hdl_debug(hdl,
			    "\n%s: cpu %d: We are unable to determine how many"
			    " ways are retired at this index. We will not be"
			    " retiring the identified cacheline at index %d"
			    " way %d\n",
			    cache_ed->ed_fltnm, cpu->cpu_cpuid,
			    Lxcache->Lxcache_index, Lxcache->Lxcache_way);
			return (CMD_EVD_BAD);
		}
		if (ways_retired >= 3) {
			fmd_hdl_debug(hdl,
			    "\n%s: cpu %d: num of ways retired for index %d"
			    " is %d. Will fault the CPU\n",
			    cache_ed->ed_fltnm, cpu->cpu_cpuid,
			    Lxcache->Lxcache_index, ways_retired);
			cmd_fault_the_cpu(hdl, cpu, type, cache_ed->ed_fltnm);
			return (CMD_EVD_OK);
		}
		/*
		 * retire the cache line
		 */
		ret = cmd_Lxcache_retire_as_reason(hdl, cpu, Lxcache,
		    cache_ed->ed_fltnm, CMD_LXCONVICTED);
		if (ret != CMD_EVD_OK)
			return (ret);
		/*
		 * anonymous serd engines for DATA faults will have valid bit
		 * but way as -1.
		 */
		cmd_Lxcache_destroy_anonymous_serd_engines(hdl, cpu, type,
		    Lxcache->Lxcache_index,
		    bit);
		return (CMD_EVD_OK);
	}	/* end of IDENTIFIED WAY error handling */
	/*
	 * ANONYMOUS WAY DATA error handling.
	 *
	 * - if a way at this index has already been retired as "suspect"
	 * for this bit, unretire that way, and retire the next retirable
	 * way as "suspect" for this bit.
	 * - if no ways have been retired as "suspect" for this bit,
	 * retire the lowest unretired way as "suspect" for this bit.
	 * - if there is no next retirable way, fault the CPU.
	 */
	/*
	 * The assignment below is to make the code easier to maintain.
	 * We need to destroy the anonymous_Lxcache after we have
	 * identifed a way to retire. If we cannot detrmine a way to
	 * retire we will destrory the anonymous_Lxcache and fault the cpu.
	 */
	anonymous_Lxcache = Lxcache;
	anonymous_Lxcache->Lxcache_ep = ep;
	if (suspect_Lxcache != NULL) {
		ret = unretire_suspect_and_retire_next_retirable_way(hdl,
		    cpu, suspect_Lxcache, anonymous_Lxcache,
		    cache_ed->ed_fltnm);
	} else {
		ret = retire_lowest_retirable_way_as_suspect(hdl, cpu,
		    anonymous_Lxcache, cache_ed->ed_fltnm);
	}
	return (ret);
}

/* ARGSUSED */
int
cmd_xr_pn_cache_fill(fmd_hdl_t *hdl, nvlist_t *nvl, cmd_xr_t *xr,
    cmd_cpu_t *cpu, cmd_errcl_t clcode)
{
	struct ch_ec_data *data_ptr;
	uint64_t *cache_data = NULL;
	uint_t sz;

	if (cpu->cpu_pers.cpup_type != CPU_ULTRASPARC_IVplus)
		return (0);

	if (nvlist_lookup_nvlist(nvl, FM_EREPORT_DETECTOR,
	    &xr->xr_detector_nvlist) != 0) {
		fmd_hdl_debug(hdl, "look up for FM_EREPORT_DETECTOR failed\n");
		return (-1);
	}
	if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_NAME_AFSR,
	    &xr->xr_afsr) != 0) {
		fmd_hdl_debug(hdl,
		    "look up for FM_EREPORT_PAYLOAD_NAME_AFSR failed\n");
		return (-1);
	}

	/* check clcode for l2/l3 first */
	if (CMD_ERRCL_ISL3XXCU(clcode)) {
		if (nvlist_lookup_uint8(nvl, FM_EREPORT_PAYLOAD_NAME_L3_WAYS,
		    &xr->xr_num_ways) != 0) {
			fmd_hdl_debug(hdl,
		    "look up for FM_EREPORT_PAYLOAD_NAME_L3_WAYS failed\n");
			return (-1);
		}

		if (nvlist_lookup_uint64_array(nvl,
		    FM_EREPORT_PAYLOAD_NAME_L3_DATA, (uint64_t **)&cache_data,
		    &sz) != 0) {
			fmd_hdl_debug(hdl,
		    "look up for FM_EREPORT_PAYLOAD_NAME_L3_DATA failed\n");
		}
	} else {
		if (nvlist_lookup_uint8(nvl, FM_EREPORT_PAYLOAD_NAME_L2_WAYS,
		    &xr->xr_num_ways) != 0) {
			fmd_hdl_debug(hdl,
		    "look up for FM_EREPORT_PAYLOAD_NAME_L2_WAYS failed\n");
			return (-1);
		}

		if (nvlist_lookup_uint64_array(nvl,
		    FM_EREPORT_PAYLOAD_NAME_L2_DATA, (uint64_t **)&cache_data,
		    &sz) != 0) {
			fmd_hdl_debug(hdl,
		    "look up for FM_EREPORT_PAYLOAD_NAME_L2_DATA failed\n");
		}
	}
	if (xr->xr_num_ways > PN_CACHE_NWAYS) {
		fmd_hdl_debug(hdl,
		    "xr_num_ways > PN_CACHE_WAYS\n");
		return (-1);
	}

	xr->xr_cache_data = cache_data;
	data_ptr = (struct ch_ec_data *)cache_data;
	if (cache_data == NULL) {
		xr->xr_error_way = (uint32_t)CMD_ANON_WAY;
		return (0);
	}

	/*
	 * Our error handler checks for a matching valid way
	 * If there is a match, there is only 1 data set, the set
	 * associated with the cache-line/way that was "valid"
	 * Otherwise, it stores all of the ways
	 */
	xr->xr_error_tag = data_ptr[0].ec_tag;
	xr->xr_error_way = (uint32_t)data_ptr[0].ec_way;

	/* If there is more than 1 way structure, set way to Anonymous */
	if (xr->xr_num_ways > 1)
		xr->xr_error_way = (uint32_t)CMD_ANON_WAY;

	return (0);
}
