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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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


static const errdata_t clr_l3errdata =
	{ &cmd.cmd_l3data_serd, "l3cachedata", CMD_PTR_LxCACHE_CASE };
static const errdata_t clr_l2errdata =
	{ &cmd.cmd_l2data_serd, "l2cachedata", CMD_PTR_LxCACHE_CASE };


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

#define	LX_NWAYS		4

int test_mode = 0;	/* should be 0 in production version. */

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

uint8_t L2TAG_bit_to_way_map[128] = {
/*	1   2   3   4   5   6   7   8   9   10  11  12  13  14  15  16 */
/* 1 */ 0,  0,  0,  1,  1,  1,  2,  2,  2,  3,  3,  3,  0,  0,  0,  0,
/* 2 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* 3 */ 0,  0,  0,  0,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
/* 4 */ 2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2, C0, C0, C0, C0,
/* 5 */C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0,  1,  1,  1,  1,
/* 6 */ 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
/* 7 */ 1,  1,  1,  1,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,
/* 8 */ 3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3, C0, C0, C0, C0,
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

uint8_t L3TAG_bit_to_way_map[128] = {
/*	1   2   3   4   5   6   7   8   9   10  11  12  13  14  15  16 */
/* 1 */ 1,  3,  1,  3,  1,  3,  1,  3,  1,  3,  1,  3,  1,  3,  1,  3,
/* 2 */ 1,  3,  1,  3,  1,  3,  1,  3,  1,  3,  1,  3,  1,  3,  1,  3,
/* 3 */ 1,  3,  1,  3,  1,  3,  1,  3,  1,  3,  1,  3,  1,  3, C0, C0,
/* 4 */C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0,
/* 5 */ 0,  2,  0,  2,  0,  2,  0,  2,  0,  2,  0,  2,  0,  2,  0,  2,
/* 6 */ 0,  2,  0,  2,  0,  2,  0,  2,  0,  2,  0,  2,  0,  2,  0,  2,
/* 7 */ 0,  2,  0,  2,  0,  2,  0,  2,  0,  2,  0,  2,  0,  2, C0, C0,
/* 8 */C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0, C0,
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

uint64_t
calcsynd(uint64_t chi, uint64_t clo, uint64_t ecc)
{
	int i;
	uint64_t syndrome = 0;

	for (i = 0; i < (NDATABITS/2); i++) {
		syndrome ^= ((chi & 1) ? e[(NDATABITS/2) + i] : 0) ^
		    ((clo & 1) ? e[i] : 0);
		chi >>= 1;
		clo >>= 1;
	}
	return (syndrome ^ ecc);
}

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

static uint8_t
tag_bit_to_way_bit(cmd_ptrsubtype_t pstype, uint16_t tag_bit)
{
	uint8_t way_bit;

	switch (pstype) {
		case CMD_PTR_CPU_L2TAG:
			way_bit = L2TAG_bit_to_way_bit[tag_bit];
			return (way_bit);
			break;
		case CMD_PTR_CPU_L3TAG:
			way_bit = L3TAG_bit_to_way_bit[tag_bit];
			return (way_bit);
			break;
	}
	way_bit = C0;
	return (way_bit);
}

static uint8_t
bit_to_way(cmd_ptrsubtype_t pstype, uint32_t bit)
{
	uint8_t way;

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

static uint32_t
get_index(cmd_ptrsubtype_t pstype, uint64_t tag_afar)
{
	uint32_t	index;

	switch (pstype) {
		case CMD_PTR_CPU_L2TAG:
			index = (uint32_t)((tag_afar & PN_L2_INDEX_MASK)
			    >> PN_CACHE_LINE_SHIFT);
			break;
		case CMD_PTR_CPU_L3TAG:
			index = (uint32_t)((tag_afar & PN_L3_TAG_RD_MASK)
			    >> PN_CACHE_LINE_SHIFT);
			break;
	}
	return (index);
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
	uint8_t		tag_afar_status;
	uint64_t	tag_afar;
	int		i;
	uint_t		sz;
	uint32_t	index;

	if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_NAME_AFAR,
	    &tag_afar) != 0) {
		fmd_hdl_debug(hdl,
		    "%s:cpu_id = %d could not find AFAR in nvlist\n",
		    fltnm, cpu->cpu_cpuid);
		return (CMD_EVD_BAD);
	}
	*afarp = tag_afar;
	index = get_index(pstype, tag_afar);
	if (nvlist_lookup_uint8(nvl, FM_EREPORT_PAYLOAD_NAME_AFAR_STATUS,
	    &tag_afar_status) != 0) {
		fmd_hdl_debug(hdl,
		    "%s: cpu_id = %d index = %d could not find AFAR_STATUS"
		    " in nvlist\n",
		    fltnm, cpu->cpu_cpuid, index);
		return (CMD_EVD_BAD);
	}
	switch (pstype) {
		case CMD_PTR_CPU_L2TAG:
			payload_namep = FM_EREPORT_PAYLOAD_NAME_L2_DATA;
			break;
		case CMD_PTR_CPU_L3TAG:
			payload_namep = FM_EREPORT_PAYLOAD_NAME_L3_DATA;
			break;
	}
	if (test_mode) {
		return (get_tagdata(cpu, pstype, index,
		    tag_data));
	} else {
		if (nvlist_lookup_uint64_array(nvl, payload_namep,
		    (uint64_t **)&ec_data, &sz) != 0) {
			fmd_hdl_debug(hdl,
			    "%s: cpu_id = %d index = %d could not find %s"
			    " in nvlist\n",
			    fltnm, cpu->cpu_cpuid, index, payload_namep);
			fmd_hdl_debug(hdl,
			    "%s: cpu_id = %d Reading tag data through"
			    " mem_cache driver.\n",
			    fltnm, cpu->cpu_cpuid);
			return (get_tagdata(cpu, pstype, index,
			    tag_data));
		}
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
		tag_ecc[i] = ((tag_data[i] & PN_TAG_ECC_MASK) >> 6);
	}
	fmd_hdl_debug(hdl,
	    "%s: cpu_id = %d ecc[0] = 0x%03x, ecc[1] = 0x%03x, ecc[2] = 0x%03x,"
	    " ecc[3] = 0x%03x\n",
	    fltnm, cpu->cpu_cpuid, tag_ecc[0], tag_ecc[1], tag_ecc[2],
	    tag_ecc[3]);

}

static int
matching_ecc(uint64_t *tag_data)
{
	int	i;
	uint16_t	tag_ecc[PN_CACHE_NWAYS];

	for (i = 0; i < PN_CACHE_NWAYS; i++) {
		tag_ecc[i] = ((tag_data[i] & PN_TAG_ECC_MASK) >> 6);
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
		tag_ecc[i] = ((tag_data[i] & PN_TAG_ECC_MASK) >> 6);
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
	tag_ecc = ((tag_data[0] & PN_TAG_ECC_MASK) >> 6);
	tag_synd = calcsynd(data_for_ecc_gen[0], data_for_ecc_gen[1],
	    (uint64_t)tag_ecc);
	return (tag_synd);
}

static uint16_t
find_bit_stickiness(uint64_t *tag_data, uint32_t way, uint16_t bit)
{
	uint16_t	sticky_bit;

	if ((tag_data[way] & ((uint64_t)1 << bit)) != 0) {
		sticky_bit = (bit | MSB_BIT);
		return (sticky_bit);
	}
	return (bit);
}

cmd_evdisp_t
cmd_us4plus_tag_err(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
		const char *class, cmd_cpu_t *cpu, cmd_ptrsubtype_t pstype,
		const char *serdnm, const char *serdn, const char *serdt,
		const char *fltnm)
{
	uint64_t	tag_afar;
	uint32_t	index, way;
	uint16_t	tag_bit, bit, sticky_bit;
	cmd_Lxcache_t	*Lxcache;
	const char	*uuid;
	uint64_t	tag_synd;
	uint64_t	tag_data[PN_CACHE_NWAYS];
	uint8_t		state[PN_CACHE_NWAYS];
	int		ways_retired, ret;
	int		cpu_fault, retries_for_ecc_match;

#if defined(lint)
	serdnm = serdnm;
	class = class;
#endif
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
		    "%s:cpu_id = %d index = %d ECCs don't match.\n"
		    "Reading tag info again.\n",
		    fltnm, cpu->cpu_cpuid, index);
		(void) get_tagdata(cpu, pstype, index, tag_data);
		retries_for_ecc_match++;
		continue;
	}
	tag_synd = compute_syndrome(tag_data, pstype);
	if (tag_synd == 0) {
		/*
		 * The bit has been corrected by writeback, we will
		 * check this later to see if the bit becomes sticky again
		 */
		fmd_hdl_debug(hdl,
		    "%s: cpu_id = %d index = %d syndrome computed is 0."
		    "Looks like the bit got corrected."
		    " Will check later to see if it is OK.\n",
		    fltnm, cpu->cpu_cpuid, index);
		return (CMD_EVD_OK);
	}
	tag_bit = ecc_syndrome_tab[tag_synd & 0x1ff];
	fmd_hdl_debug(hdl,
	    "%s: cpu_id = %d index = %d tag_bit %03d is faulty.\n",
	    fltnm, cpu->cpu_cpuid, index, tag_bit);
	if ((tag_bit > C8)) {
		fmd_hdl_debug(hdl, "%s: cpu_id = %d"
		    " Unexpected MTAG or Multiple bit error detected\n",
		    fltnm, cpu->cpu_cpuid);
		return (CMD_EVD_BAD);
	}
	if ((tag_bit >= C0) && (tag_bit <= C8)) {
		/*
		 * ECC bit is corrupted.
		 * Need to offline the CPU
		 */
		bit = (tag_bit - C0) + 6;
		way = 0;
		fmd_hdl_debug(hdl, "%s: cpu_id = %d ECC bit is faulty.\n",
		    fltnm, cpu->cpu_cpuid);
	} else {
		bit = tag_bit_to_way_bit(pstype, tag_bit);
		way = bit_to_way(pstype, tag_bit);
		if (way == C0) {
			fmd_hdl_debug(hdl,
			"%s: cpu_id = %d %d bit indicted is a meta bit  !!\n",
			    fltnm, cpu->cpu_cpuid, bit);
			return (CMD_EVD_BAD);
		}

	}
	if ((Lxcache = cmd_Lxcache_lookup(cpu, pstype, index, way,
	    bit)) != NULL &&
	    Lxcache->Lxcache_case.cc_cp != NULL &&
	    fmd_case_solved(hdl, Lxcache->Lxcache_case.cc_cp)) {
		fmd_hdl_debug(hdl,
		    "%s:cpu %d: the case for %s is already solved.\n",
		    fltnm, cpu->cpu_cpuid, Lxcache->Lxcache_bufname);
		return (CMD_EVD_REDUND);
	}


	if (Lxcache == NULL)
		Lxcache = cmd_Lxcache_create(hdl, 0, cpu, cpu->cpu_asru_nvl,
		    pstype, index, way, bit);

	if (Lxcache->Lxcache_case.cc_cp == NULL) {
		Lxcache->Lxcache_case.cc_cp = cmd_case_create(hdl,
		    &Lxcache->Lxcache_header, CMD_PTR_LxCACHE_CASE,
		    &uuid);
		fmd_hdl_debug(hdl,
		    "%s:cpu_id %d:created a case for index %d way %d bit %d\n",
		    fltnm, cpu->cpu_cpuid, index, way, bit);
	}
	if (Lxcache->Lxcache_case.cc_serdnm == NULL) {
		Lxcache->Lxcache_case.cc_serdnm = cmd_Lxcache_serdnm_create(hdl,
		    cpu->cpu_cpuid, pstype, index,
		    way, bit);
		fmd_serd_create(hdl, Lxcache->Lxcache_case.cc_serdnm,
		    fmd_prop_get_int32(hdl, serdn),
		    fmd_prop_get_int64(hdl, serdt));
		fmd_hdl_debug(hdl,
		    "%s: cpu_id %d: created a SERD engine %s\n",
		    fltnm, cpu->cpu_cpuid, Lxcache->Lxcache_case.cc_serdnm);
	}
	fmd_hdl_debug(hdl,
	    "%s:cpu_id %d: Checking if the SERD engine %s has fired.\n",
	    fltnm, cpu->cpu_cpuid, Lxcache->Lxcache_case.cc_serdnm);

	if (fmd_serd_record(hdl, Lxcache->Lxcache_case.cc_serdnm, ep) ==
	    FMD_B_FALSE)
		return (CMD_EVD_OK); /* engine hasn't fired */

	fmd_hdl_debug(hdl, "%s: cpu_id = %d creating fault %s\n",
	    fltnm, cpu->cpu_cpuid, Lxcache->Lxcache_case.cc_serdnm);
	fmd_case_add_serd(hdl, Lxcache->Lxcache_case.cc_cp,
	    Lxcache->Lxcache_case.cc_serdnm);
	fmd_serd_reset(hdl, Lxcache->Lxcache_case.cc_serdnm);
	sticky_bit = find_bit_stickiness(tag_data, way, bit);
	if ((bit >= 6) && (bit <= 14)) {
		cmd_fault_the_cpu(hdl, cpu, pstype, fltnm);
		return (CMD_EVD_OK);
	}
	/*
	 * Check if a STATE bit is faulty.
	 * If so we need to ensure that we will be able to
	 * make the way NA, else fault the CPU.
	 */
	if (bit <= 2) {
		fmd_hdl_debug(hdl,
		    "%s cpu_id = %d: STATE bit %d is faulty.\n",
		    fltnm, cpu->cpu_cpuid, bit);
		/*
		 * If the stable value of bit will hold the NA encoding
		 * retire the containing way Else fault the cpu.
		 */
		cpu_fault = 0;
		state[way] = tag_data[way] & CH_ECSTATE_MASK;
		if (bit == 1) {
			/*
			 * The stable value should be 0.
			 */
			if (state[way] & 0x2)
				cpu_fault = 1;
		} else {
			/*
			 * The stable value should be 1.
			 */
			if ((state[way] & 0x5) == 0)
				cpu_fault = 1;
		}
		fmd_hdl_debug(hdl,
		    "%s cpu_id = %d: STATE bit %d is faulty."
		    "cpu_fault = %d STATE = 0x%x\n",
		    fltnm, cpu->cpu_cpuid, bit,
		    cpu_fault, state[way]);
		if (cpu_fault) {
			cmd_fault_the_cpu(hdl, cpu, pstype, fltnm);
			return (CMD_EVD_OK);
		}
	}
	/*
	 * Before retiring a way check if we have already
	 * retired 3 ways for this index.
	 */
	ways_retired = get_index_retired_ways(cpu, pstype, index);
	if (ways_retired == -1)
			return (CMD_EVD_BAD);
	if (ways_retired >= 3) {
		fmd_hdl_debug(hdl,
		    "%s: cpu %d: num of ways retired for index %d is %d"
		    " will fault the CPU\n",
		    fltnm, cpu->cpu_cpuid, index, ways_retired);
		cmd_fault_the_cpu(hdl, cpu, pstype, fltnm);
		return (CMD_EVD_OK);
	}
	/*
	 * Check if we getting fault on a way that is already retired.
	 * If so we need to retire the CPU.
	 */
	if (is_index_way_retired(cpu, pstype, index, way) == 1) {
		fmd_hdl_debug(hdl,
		    "%s: cpu %d: An already retired index %d way %d is"
		    " reporting fault. will fault the CPU\n",
		    fltnm, cpu->cpu_cpuid, index, way);
		cmd_fault_the_cpu(hdl, cpu, pstype, fltnm);
		return (CMD_EVD_OK);
	}

	fmd_hdl_debug(hdl,
	    "%s: cpu %d: num of ways retired for index %d is %d\n",
	    fltnm, cpu->cpu_cpuid, index, ways_retired);
	if ((errno = nvlist_add_uint16(Lxcache->Lxcache_asru_nvl,
	    FM_FMRI_CPU_CACHE_BIT,
	    sticky_bit)) != 0 ||
	    (errno = fmd_nvl_fmri_expand(hdl, Lxcache->Lxcache_asru_nvl)) != 0)
		fmd_hdl_abort(hdl, "failed to build Lxcache fmri");
	Lxcache->Lxcache_reason = CMD_LXCONVICTED;
	cmd_Lxcache_fault(hdl, cpu, Lxcache, fltnm, NULL, 100);
	return (CMD_EVD_OK);
}

static int
cmd_cache_valid_way_check(fmd_hdl_t *hdl, uint64_t ec_tag, uint64_t afar,
    cmd_ptrsubtype_t type)
{
	int ret_val = 0;	 /* 0 = failure */

	if (type == CMD_PTR_CPU_L2DATA) {
		if ((ec_tag >> LX_PA_MASK2_32BIT_CORRECT & LX_PA_MASK2) ==
		    (afar >> LX_PA_MASK2_32BIT_CORRECT & LX_PA_MASK2)) {
			ret_val = 1;
			fmd_hdl_debug(hdl, "L2 AFAR/TAG match\n");
		}
	} else {
		if ((ec_tag >> LX_PA_MASK3_32BIT_CORRECT &  LX_PA_MASK3) ==
		    (afar >> LX_PA_MASK3_32BIT_CORRECT  & LX_PA_MASK3)) {
			ret_val = 1;
			fmd_hdl_debug(hdl, "L3 AFAR/TAG match\n");
		}
	}

	ec_tag &= (uint64_t)CH_ECSTATE_MASK;
	if ((ec_tag ==  CH_ECSTATE_INV) ||
	    (ec_tag ==  CH_ECSTATE_OWN) ||
	    (ec_tag ==  CH_ECSTATE_MOD)) {
		ret_val = 0;
		fmd_hdl_debug(hdl, "state not proper for match: %llx\n",
		    ec_tag);
	}
	return (ret_val);
}

/* Find the lowest way SERD engine not faulted for the given index */

uint32_t
cmd_Lx_lookup_lowest_way(cmd_Lxcache_t **other_cache, cmd_cpu_t *cpu,
    uint32_t index,  cmd_ptrsubtype_t pstype)
{
	cmd_Lxcache_t *cache = NULL;
	uint32_t way, way1;

	*other_cache = NULL;
	for (way = 0; way < LX_NWAYS - 1; way++) {
		cache = cmd_Lxcache_lookup_by_index_way(cpu, pstype,
		    index, way);
			if (cache == NULL ||
			    (cache->Lxcache_reason == CMD_LXFUNCTIONING)) {
				*other_cache = cache;
				way1 = way;
				break;
			}
	}
	if (pstype == CMD_PTR_CPU_L2DATA) {
		pstype = CMD_PTR_CPU_L2TAG;
	} else {
		pstype = CMD_PTR_CPU_L3TAG;
	}
	for (way = 0; way < LX_NWAYS - 1; way++) {
		cache = cmd_Lxcache_lookup_by_index_way(cpu, pstype,
		    index, way);
			if (cache == NULL ||
			    (cache->Lxcache_reason == CMD_LXFUNCTIONING)) {
				/* return this way if larger */
				if (way > way1) {
					*other_cache = cache;
					return (way);
				} else {
					return (way1);
				}
		}
	}
	return ((uint32_t)-1);  /* This shouldn't happen! */
}

/*
 * Find the lowest way SERD engine faulted but not convicted for the
 * given index
 */

uint32_t
cmd_Lx_lookup_lowest_suspicous_way(cmd_Lxcache_t **other_cache, cmd_cpu_t *cpu,
    int32_t index, cmd_ptrsubtype_t pstype)
{
	cmd_Lxcache_t *cache = NULL;
	int32_t way, way1 = -1;

	*other_cache = NULL;
	for (way = 0; way < LX_NWAYS; way++) {
		cache = cmd_Lxcache_lookup_by_index_way(cpu, pstype,
		    index, way);
			if (cache != NULL &&
			    (cache->Lxcache_reason == CMD_LXSUSPICOUS)) {
				*other_cache = cache;
				way1 = way;
				break;
		}
	}
	if (pstype == CMD_PTR_CPU_L2DATA) {
		pstype = CMD_PTR_CPU_L2TAG;
	} else  {
		pstype = CMD_PTR_CPU_L3TAG;
	}
	for (way = 0; way < LX_NWAYS; way++) {
		cache = cmd_Lxcache_lookup_by_index_way(cpu, pstype,
		    index, way);
			if (cache != NULL &&
			    (cache->Lxcache_reason == CMD_LXSUSPICOUS)) {
				if (way1 == -1)
					return (way);
				/* Return the smaller of the two */
				if (way < way1) {
					*other_cache = cache;
					return (way);
				} else {
					return (way1);
				}
		}
	}
	/* if there are no suspicious tag ways, we fall through */
	return (way1);
}
/* Count the number of ways convicted for a given index */

uint32_t
cmd_Lx_index_count_ways(cmd_cpu_t *cpu, uint32_t index,
    cmd_ptrsubtype_t pstype)
{
	cmd_Lxcache_t *cache = NULL;
	uint32_t way, way_count = 0;

	for (way = 0; way < LX_NWAYS - 1; way++) {
		cache = cmd_Lxcache_lookup_by_index_way(cpu, pstype,
		    index, way);
			if ((cache != NULL) &&
			    (cache->Lxcache_reason == CMD_LXCONVICTED)) {
				way_count++;
			}
	}
	return (way_count);
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
	cmd_xxcu_trw_t *trw;
	cmd_Lxcache_t *anon_cache, *cache, *other_cache;
	cmd_cpu_t *cpu = xr->xr_cpu;
	cmd_case_t *cpu_cc;
	struct ch_ec_data *data_ptr;
	cmd_ptrsubtype_t type;
	nvlist_t *rsrc_nvl = NULL;
	nvlist_t *repair_nvl = NULL;
	uint32_t new_way, way_count, unretire_way;
	const char *uuid;
	const errdata_t *cache_ed;
	int i, bit, offset;

	/*
	 * If this is not a Panther or one of the Panther specific
	 * errors that we handle here, then exit
	 */

	if (xr->xr_cpu->cpu_pers.cpup_type != CPU_ULTRASPARC_IVplus)
		return ((int)~CPU_ULTRASPARC_IVplus);

	if (!(xr->xr_clcode & (int)PN_CACHE_ERRORS))
		return (-1);

	if ((trw = cmd_trw_lookup(xr->xr_ena,
	    xr->xr_afar_status, xr->xr_afar)) == NULL) {
		fmd_hdl_debug(hdl, "cmd_trw_lookup: Not found\n");
	} else
		/*  Account for trw deref if necessary */
		if (trw->trw_ref > 1)
			cmd_trw_deref(hdl, trw);

	/* Set up Cache specific structs */

	if (CMD_ERRCL_ISL2XXCU(xr->xr_clcode)) {
		type = CMD_PTR_CPU_L2DATA;
		cpu_cc = &cpu->cpu_l2data;
		cache_ed = &clr_l2errdata;
	} else {
		type = CMD_PTR_CPU_L3DATA;
		cpu_cc = &cpu->cpu_l3data;
		cache_ed = &clr_l3errdata;
	}

	/* Ensure that our case is not solved */

	if (cpu->cpu_faulting || (cpu_cc->cc_cp != NULL &&
	    fmd_case_solved(hdl, cpu_cc->cc_cp)))
			return (0);

	fmd_hdl_debug(hdl, "Processing Panther Cache %s Error\n",
	    cache_ed->ed_fltnm);

	/* L3 errors arrive as mem scheme errors - convert to CPU */
	if (type == CMD_PTR_CPU_L3DATA) {
		cmd_fmri_init(hdl, &xr->xr_rsrc,
		    xr->xr_detector_nvlist, "%s_rsrc",
		    fmd_case_uuid(hdl, xr->xr_case));
	}

	/* Check for valid syndrome */
	if (cmd_cpu_synd_check(xr->xr_synd, xr->xr_clcode) < 0) {
		fmd_hdl_debug(hdl,
		    "xxC/LDxC dropped due to syndrome\n");
		return (0);
	}

	/* Retrieve pointer to our payload data */
	data_ptr = (struct ch_ec_data *)xr->xr_cache_data;
	offset = 0;
	for (i = 0; i < 4; i++) {
		if (data_ptr[0].ec_data[0].ec_d8[i]
		    != data_ptr[0].ec_data[0].ec_d8[i+1]) {
			if ((i < 3) &&
			    (data_ptr[0].ec_data[0].ec_d8[i+1] !=
			    data_ptr[0].ec_data[0].ec_d8[i+2])) {
				offset = (7 - (i + 1));
				break;
			} else {
				offset = (7 - i);
				break;
			}
		}
		if (data_ptr[0].ec_data[1].ec_d8[i]
		    != data_ptr[0].ec_data[1].ec_d8[i+1]) {
			if ((i < 3) &&
			    (data_ptr[0].ec_data[1].ec_d8[i+1] !=
			    data_ptr[0].ec_data[1].ec_d8[i+2])) {
				offset = (3 - (i + 1));
				break;
			} else {
				offset = (3 - i);
				break;
			}
		}
	}

	fmd_hdl_debug(hdl, "offset is %d\n", offset);
	bit = cmd_synd2upos(xr->xr_synd) + (offset/2 * 128);

	if (cmd_cache_valid_way_check(hdl, xr->xr_error_tag,
	    xr->xr_afar, type))
		fmd_hdl_debug(hdl, "matching valid way found");
	else {
		fmd_hdl_debug(hdl, "no matching valid way found");
		xr->xr_error_way = (uint32_t)CMD_ANON_WAY;
	}

	fmd_hdl_debug(hdl, "payload num_ways is %x", xr->xr_num_ways);
	fmd_hdl_debug(hdl, "payload afar is %llx\n", xr->xr_afar);
	fmd_hdl_debug(hdl, "payload ec_tag is %llx\n",
	    xr->xr_error_tag);
	fmd_hdl_debug(hdl, "payload index is %lx\n",
	    xr->xr_error_index);
	fmd_hdl_debug(hdl, "payload way is %lx\n",
	    xr->xr_error_way);
	fmd_hdl_debug(hdl, "payload afsr is %llx\n", xr->xr_afsr);
	fmd_hdl_debug(hdl, "xr_synd is %llx\n", xr->xr_synd);
	fmd_hdl_debug(hdl, "Syndrome lookup is %x\n",
	    cmd_synd2upos(xr->xr_synd));

	/* First, register cache error */

	cache = cmd_Lxcache_lookup(xr->xr_cpu, type,
	    xr->xr_error_index, xr->xr_error_way, bit);

	if (cache == NULL) {
		fmd_hdl_debug(hdl,
		    "%s: cpu %d: creating a case for index %d way %d"
		    " bit %x\n",
		    cache_ed->ed_fltnm, xr->xr_cpuid,
		    xr->xr_error_index, xr->xr_error_way, bit);
		cache = cmd_Lxcache_create(hdl, xr, xr->xr_cpu,
		    xr->xr_cpu->cpu_asru_nvl,
		    type, xr->xr_error_index,
		    xr->xr_error_way, bit);

		cache->Lxcache_case.cc_cp = cmd_case_create(hdl,
		    &cache->Lxcache_header, cache_ed->ed_pst, &uuid);

		cache->Lxcache_case.cc_serdnm =
		    cmd_Lxcache_serdnm_create(hdl, xr->xr_cpuid,
		    type, xr->xr_error_index, xr->xr_error_way, bit);

		if (!fmd_serd_exists(hdl,
		    cache->Lxcache_case.cc_serdnm)) {
			fmd_serd_create(hdl,
			    cache->Lxcache_case.cc_serdnm,
			    cache_ed->ed_serd->cs_n,
			    cache_ed->ed_serd->cs_t);
		}
	} else {
		if ((cache->Lxcache_reason == CMD_LXCONVICTED) ||
		    (cache->Lxcache_reason == CMD_LXSUSPICOUS)) {
			fmd_hdl_debug(hdl, "cache line previously"
			    "retired -- ignoring\n");
			return (0);
		}
	}
	/* Ensure that our case is not solved */
	if (cache->Lxcache_flags == CMD_LxCACHE_F_FAULTING ||
	    (cache->Lxcache_case.cc_cp != NULL &&
	    fmd_case_solved(hdl, cache->Lxcache_case.cc_cp)))
			return (0);

	fmd_hdl_debug(hdl, "%s: cpu %d: checking if SERD engine %s has"
	    " fired.\n",
	    cache_ed->ed_fltnm, xr->xr_cpuid, cache->Lxcache_case.cc_serdnm);

	if (fmd_serd_record(hdl, cache->Lxcache_case.cc_serdnm,
	    ep) == FMD_B_FALSE)
		return (0); /* serd engine hasn't fired yet */

	if (xr->xr_rsrc_nvl != NULL && nvlist_dup(xr->xr_rsrc_nvl,
	    &rsrc_nvl, 0) != 0) {
		fmd_hdl_abort(hdl, "failed to duplicate resource FMRI for "
		    "%s fault", cache_ed->ed_fltnm);
	}

	/* This cache line's SERD Engine has fired. Prepare to convict it */
	cache->Lxcache_reason = CMD_LXCONVICTED;

	/* Get the number of ways convicted for this index */

	way_count = cmd_Lx_index_count_ways(xr->xr_cpu,
	    xr->xr_error_index, type);

	/* Tally apprpropiate ways convinced due to Tag faults */
	if (type == CMD_PTR_CPU_L2DATA) {
		way_count += cmd_Lx_index_count_ways(xr->xr_cpu,
		    xr->xr_error_index, CMD_PTR_CPU_L2TAG);
	} else  {
		way_count += cmd_Lx_index_count_ways(xr->xr_cpu,
		    xr->xr_error_index, CMD_PTR_CPU_L3TAG);
	}

	fmd_hdl_debug(hdl, "index = %d: number of ways now retired %d",
	    xr->xr_error_index, way_count);

	if ((xr->xr_error_way == (uint32_t)CMD_ANON_WAY) || (way_count == 4)) {
		/* If there are none left fault the CPU */
		if (way_count == 4)	{
			fmd_hdl_debug(hdl,
			    "Already 3 ways are retired for this line."
			    "Retiring the CPU because all ways are faulty.\n");
			cmd_fault_the_cpu(hdl, xr->xr_cpu, type,
			    cache_ed->ed_fltnm);
			return (CMD_EVD_OK);
		} else {
			/* Find the lowest way not faulted */
			new_way = cmd_Lx_lookup_lowest_way(&other_cache,
			    xr->xr_cpu, xr->xr_error_index, type);

			if (new_way == (uint32_t)-1) {
				fmd_hdl_debug(hdl, "Lookup returned -1"
				    "setting to 0\n");
				new_way = 0;
			}
			/*
			 * If a previous case for this way exists,
			 * destroy it as we are replacing it with the
			 * triggered Anonymous Way SERD case
			 */
			other_cache = cmd_Lxcache_lookup_by_index_way(
			    xr->xr_cpu,
			    type, xr->xr_error_index, new_way);
			if (other_cache != NULL) {
				fmd_hdl_debug(hdl, "closing serd: %s\n",
				    other_cache->Lxcache_case.cc_serdnm);
				cmd_Lxcache_destroy(hdl, xr->xr_cpu,
				    other_cache);
			}

			/* Change the way for this case */
			fmd_hdl_debug(hdl, "Changing way for case %s "
			    "from %d to %d\n", uuid,
			    cache->Lxcache_way, new_way);

			(void) nvlist_add_uint32(cache->Lxcache_asru_nvl,
			    FM_FMRI_CPU_CACHE_WAY, new_way);

			/* Remove the ANON way SERD Engine */
			fmd_serd_destroy(hdl, cache->Lxcache_case.cc_serdnm);
			fmd_hdl_strfree(hdl, cache->Lxcache_case.cc_serdnm);

			cache->Lxcache_way = new_way;
			cache->Lxcache_case.cc_serdnm =
			    cmd_Lxcache_serdnm_create(hdl, xr->xr_cpuid,
			    type, xr->xr_error_index,
			    new_way, bit);

			/* Now replace it with the new_way SERD */
			fmd_serd_create(hdl,
			    cache->Lxcache_case.cc_serdnm,
			    cache_ed->ed_serd->cs_n,
			    cache_ed->ed_serd->cs_t);
			/*
			 * If we have retired a previous way in this
			 * cache line under suspicion, unretire it
			 */
			unretire_way =
			    cmd_Lx_lookup_lowest_suspicous_way(&other_cache,
			    xr->xr_cpu, xr->xr_error_index, type);

			if ((new_way != 0) && (unretire_way != (uint32_t)-1)) {
				fmd_hdl_debug(hdl, "Unretire way %d\n",
				    unretire_way);
				if (cpu->cpu_asru_nvl != NULL &&
				    nvlist_dup(cpu->cpu_asru_nvl,
				    &repair_nvl, 0) != 0) {
					fmd_hdl_abort(hdl, "failed to"
					    "duplicate resource FMRI for "
					    "repair");
					}

				cmd_Lxcache_destroy(hdl, xr->xr_cpu,
				    other_cache);
				/*
				 * Unretire the cacheline from DE.
				 */
				if (cmd_Lxcache_unretire(hdl, cpu,
				    other_cache,
				    cache_ed->ed_fltnm) == B_FALSE)
					return (CMD_EVD_BAD);
			}
			/* Indicate our reason for retiring */
			cache->Lxcache_reason = CMD_LXSUSPICOUS;

			/* Fall through and fault the index/way */
		}
	}

	/*
	 * if this SERD engine specifies a way, then destroy any
	 * other anonomymous engine associated with the index/way
	 */

	anon_cache = cmd_Lxcache_lookup(xr->xr_cpu,
	    type, xr->xr_error_index, CMD_ANON_WAY, bit);

	if ((anon_cache != NULL) && (anon_cache != cache)) {
		fmd_hdl_debug(hdl, "closing serd: %s\n",
		    anon_cache->Lxcache_case.cc_serdnm);
		cmd_Lxcache_destroy(hdl, xr->xr_cpu, anon_cache);
	}

	fmd_case_add_serd(hdl, cache->Lxcache_case.cc_cp,
	    cache->Lxcache_case.cc_serdnm);

	fmd_hdl_debug(hdl, "creating fault %s\n",
	    cache->Lxcache_case.cc_serdnm);

	cmd_Lxcache_fault(hdl, xr->xr_cpu, cache, cache_ed->ed_fltnm,
	    xr->xr_cpu->cpu_fru_nvl, 100);

	nvlist_free(rsrc_nvl);
	return (0);
}

/* ARGSUSED */
int
cmd_xr_pn_cache_fill(fmd_hdl_t *hdl, nvlist_t *nvl, cmd_xr_t *xr,
    cmd_cpu_t *cpu, cmd_errcl_t clcode)
{
	struct ch_ec_data *data_ptr;
	uint64_t *cache_data;
	uint_t sz;
	int i;

	if (cpu->cpu_pers.cpup_type != CPU_ULTRASPARC_IVplus)
		return (0);

	if (nvlist_lookup_nvlist(nvl, FM_EREPORT_DETECTOR,
	    &xr->xr_detector_nvlist) != 0)
		return (-1);
	if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_NAME_AFSR,
	    &xr->xr_afsr) != 0)
		return (-1);

	/* check clcode for l2/l3 first */
	if (CMD_ERRCL_ISL3XXCU(clcode)) {
		if (nvlist_lookup_uint8(nvl, FM_EREPORT_PAYLOAD_NAME_L3_WAYS,
		    &xr->xr_num_ways) != 0)
			return (-1);

		if (nvlist_lookup_uint64_array(nvl,
		    FM_EREPORT_PAYLOAD_NAME_L3_DATA, (uint64_t **)&cache_data,
		    &sz) != 0)
			return (-1);
	} else {
		if (nvlist_lookup_uint8(nvl, FM_EREPORT_PAYLOAD_NAME_L2_WAYS,
		    &xr->xr_num_ways) != 0)
			return (-1);

		if (nvlist_lookup_uint64_array(nvl,
		    FM_EREPORT_PAYLOAD_NAME_L2_DATA, (uint64_t **)&cache_data,
		    &sz) != 0)
			return (-1);
	}
	if (xr->xr_num_ways > PN_CACHE_NWAYS)
		return (-1);

	xr->xr_cache_data = cache_data;
	data_ptr = (struct ch_ec_data *)cache_data;
	for (i = 0; i < xr->xr_num_ways; i++) {
		xr->xr_error_index =
		    (uint32_t)((data_ptr[i].ec_idx & LX_INDEX_MASK) >>
		    LX_INDEX_SHIFT);
		xr->xr_error_tag = data_ptr[i].ec_tag;
		xr->xr_error_way = (uint32_t)data_ptr[i].ec_way;
	}
	/* If there is more than 1 way structure, set way to Anonymous */
	if (xr->xr_num_ways > 1)
		xr->xr_error_way = (uint32_t)CMD_ANON_WAY;

	return (0);
}
