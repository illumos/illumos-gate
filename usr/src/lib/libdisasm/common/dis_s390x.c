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
 * Copyright 2015 Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
 */

#include <stdio.h>
#include <libdisasm.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/byteorder.h>

#include "libdisasm_impl.h"

#define	ILC2LEN(ilc)	(2 * ((ilc) >= 2 ? (ilc) : (ilc) + 1))

/*
 * Throughout this file, the instruction format names based on:
 *   SA22-7832-09  z/Architecture Principles of Operation
 *
 * System/370, ESA/390, and earlier z/Architecture POP use slightly
 * different names for the formats (the variant names are numeric).  For the
 * sake of simplicity, we use the most detailed definitions - z/Architecture.
 *
 * For ESA/390 we map the formats:
 *   E   -> E
 *   I   -> I
 *   RR  -> RR
 *   RRE -> RRE
 *   RRF -> RRD & RRFa-e
 *   RX  -> RXa-b
 *   RXE -> RXE
 *   RXF -> RXF
 *   RS  -> RSa-b
 *   RSE -> RSYa-b
 *   RSL -> RSLa
 *   RSI -> RSI
 *   RI  -> RIa-c
 *   RIL -> RILa-c
 *   SI  -> SI
 *   S   -> S
 *   SS  -> SSa-b & SSd-e
 *   SSE -> SSE
 *
 * For System/370 we map the formats:
 *   RR -> RR
 *   RX -> RXa-b
 *   RS -> RSa-b
 *   SI -> SI
 *   S  -> S
 *   SS -> SSa-c
 *
 * Disassembly begins in tbl_xx.  The first byte of the instruction is used
 * as the index.  This yields either an instruction or a sub-table.
 *
 * If an instruction is encountered, its format field is used to format the
 * instruction.
 *
 * There are two types of sub-tables: extended opcode tables (indicated with
 * IF_TBL) or a multiple mnemonics tables (indicated with IF_MULTI).
 *
 * Extended opcode tables indicade which additional bits of the instruction
 * should be inspected.  These bits are used as an index into the sub table.
 *
 * Multiple mnemonic tables are used to print different mnemonics depending
 * on the architecture.  Over the years, certain instructions got a new
 * preferred mnemonic.  For example, 0xa70 is test-under-mask-high (tmh) on
 * System/390.  On z/Architecture systems, the instruction behaves
 * identically (and the assembler hapilly accepts tmh), but the preferred
 * mnemonic is tmlh (test-under-mask-low-high) because z/Architecture
 * extended the general purpose registers from 32 bits to 64 bits.  The
 * current architecture flag (e.g., F_390) is used to index into the
 * sub-table.
 *
 * Regardless of which sub-table is encountered, the selected entry in the
 * sub-table is interpreted using the same rules as the contents of tbl_xx.
 *
 * Finally, we use the extended opcode sub-table mechanism to pretty print
 * the branching instructions.  All branches are conditional based on a
 * 4-bit mask indicating which value of the condition code will result in a
 * taken branch.  In order to produce a more human friendly output, we use
 * the 4-bit mask as an extended opcode to break up the branching
 * instruction into 16 different ones.  For example, instead of printing:
 *
 *    bc   7,0x123(%r1,%r2)
 *
 * we print:
 *
 *    bne  0x123(%r1,%r2)
 *
 * Note that we are using designated initializers via the INSTR/TABLE/MULTI
 * macros and therefore the below tables can be sparse.  We rely on unset
 * entries having zero format fields (aka. IF_INVAL) per C99.
 */

/* BEGIN CSTYLED */
enum ifmt {
	/* invalid */
	IF_INVAL = 0,

	/* indirection */
	IF_TBL,
	IF_MULTI,

	/* 2-byte */
	IF_ZERO,		/* 370, 390, z */
	IF_E,			/*      390, z */
	IF_I,			/*      390, z */
	IF_RR,			/* 370, 390, z */

	/* 4-byte */
	IF_DIAG,		/* 370, 390, z */
	IF_IE,			/*           z */
	IF_RIa,			/*      390, z */
	IF_RIb,			/*      390, z */
	IF_RIc,			/*      390, z */
	IF_RRD,			/*      390, z */ /* on 390 these are RRF */
	IF_RRE,			/*      390, z */
	IF_RRFa,		/*      390, z */
	IF_RRFb,		/*      390, z */
	IF_RRFc,		/*      390, z */
	IF_RRFd,		/*      390, z */
	IF_RRFe,		/*      390, z */
	IF_RSa,			/* 370, 390, z */
	IF_RSb,			/* 370, 390, z */
	IF_RSI,			/*      390, z */
	IF_RXa,			/* 370, 390, z */
	IF_RXb,			/* 370, 390, z */
	IF_S,			/* 370, 390, z */
	IF_SI,			/* 370, 390, z */

	/* 6-byte */
	IF_MII,			/*           z */
	IF_RIEa,		/*           z */
	IF_RIEb,		/*           z */
	IF_RIEc,		/*           z */
	IF_RIEd,		/*           z */
	IF_RIEe,		/*           z */
	IF_RIEf,		/*           z */
	IF_RILa,		/*      390, z */
	IF_RILb,		/*      390, z */
	IF_RILc,		/*      390, z */
	IF_RIS,			/*           z */
	IF_RRS,			/*           z */
	IF_RSLa,		/*      390, z */
	IF_RSLb,		/*           z */
	IF_RSYa,		/*           z */
	IF_RSYb,		/*           z */
	IF_RXE,			/*      390, z */
	IF_RXF,			/*      390, z */
	IF_RXYa,		/*           z */
	IF_RXYb,		/*           z */
	IF_SIL,			/*           z */
	IF_SIY,			/*           z */
	IF_SMI,			/*           z */
	IF_SSa,			/* 370, 390, z */
	IF_SSb,			/* 370, 390, z */
	IF_SSc,			/* 370, 390, z */
	IF_SSd,			/*      390, z */
	IF_SSe,			/*      390, z */
	IF_SSf,			/*      390, z */
	IF_SSE,			/*      390, z */
	IF_SSF,			/*           z */
};

#define	IF_NFMTS		(IF_SSF + 1)

#define	F_370			0x0001			/* 370         */
#define	F_390			0x0002			/*      390    */
#define	F_Z			0x0004			/*           z */
#define	F_SIGNED_IMM		0x0010			/* 370, 390, z */
#define	F_CTL_REG		0x0020			/* 370, 390, z */
#define	F_HIDE_MASK		0x0040			/* 370, 390, z */
#define	F_R1_IS_MASK		0x0080			/* 370, 390, z */
/* END CSTYLED */

struct inst_table {
	union {
		struct {
			const char *it_name;
			unsigned it_flags;
		} it_inst;
		struct {
			const struct inst_table *it_ptr;
			uint8_t it_off:4;
			uint8_t it_shift:4;
			uint8_t it_mask;
		} it_table;
		struct {
			const struct inst_table *it_ptr;
		} it_multi;
	} it_u;
	enum ifmt it_fmt;
};

#define	BITFLD(a, b)		DECL_BITFIELD2(b:4, a:4)

union inst {
	uint8_t raw[6];
	struct {
		uint8_t op;
		uint8_t par1;
		uint16_t par2;
	} diag;
	struct {
		uint8_t op;
		uint8_t i;
	} i;
	struct {
		uint16_t op;
		uint8_t pad;
		BITFLD(i1, i2);
	} ie;
	struct {
		uint8_t op;
		BITFLD(m1, ri2h);
		uint8_t ri2l;
		uint8_t ri3h;
		uint16_t ri3l;
	} mii;
	struct {
		uint8_t op;
		BITFLD(r1, r2);
	} rr;
	struct {
		uint16_t op;
		BITFLD(r1, pad);
		BITFLD(r3, r2);
	} rrd;
	struct {
		uint16_t op;
		uint8_t pad;
		BITFLD(r1, r2);
	} rre;
	struct {
		uint16_t op;
		BITFLD(r1, m4);
		BITFLD(r3, r2);
	} rrf_ab;
	struct {
		uint16_t op;
		BITFLD(m3, m4);
		BITFLD(r1, r2);
	} rrf_cde;
	struct {
		uint8_t op1;
		BITFLD(r1, r2);
		BITFLD(b4, d4h);
		uint8_t d4l;
		BITFLD(m3, pad);
		uint8_t op2;
	} rrs;
	struct {
		uint8_t op;
		BITFLD(r1, x2);
		BITFLD(b2, d2h);
		uint8_t d2l;
	} rx_a;
	struct {
		uint8_t op;
		BITFLD(m1, x2);
		BITFLD(b2, d2h);
		uint8_t d2l;
	} rx_b;
	struct {
		uint8_t op1;
		BITFLD(r1, x2);
		BITFLD(b2, d2h);
		uint8_t d2l;
		uint8_t pad;
		uint8_t op2;
	} rxe;
	struct {
		uint8_t op1;
		BITFLD(r3, x2);
		BITFLD(b2, d2h);
		uint8_t d2l;
		BITFLD(r1, pad);
		uint8_t op2;
	} rxf;
	struct {
		uint8_t op1;
		BITFLD(r1, x2);
		BITFLD(b2, dl2h);
		uint8_t dl2l;
		uint8_t dh2;
		uint8_t op2;
	} rxy_a;
	struct {
		uint8_t op1;
		BITFLD(m1, x2);
		BITFLD(b2, dl2h);
		uint8_t dl2l;
		uint8_t dh2;
		uint8_t op2;
	} rxy_b;
	struct {
		uint8_t op;
		BITFLD(r1, r3);
		BITFLD(b2, d2h);
		uint8_t d2l;
	} rs_a;
	struct {
		uint8_t op;
		BITFLD(r1, m3);
		BITFLD(b2, d2h);
		uint8_t d2l;
	} rs_b;
	struct {
		uint8_t op1;
		BITFLD(l1, pad1);
		BITFLD(b1, d1h);
		uint8_t d1l;
		uint8_t pad2;
		uint8_t op2;
	} rsl_a;
	struct {
		uint8_t op1;
		uint8_t l2;
		BITFLD(b2, d2h);
		uint8_t d2l;
		BITFLD(r1, m3);
		uint8_t op2;
	} rsl_b;
	struct {
		uint8_t op;
		BITFLD(r1, r3);
		uint16_t ri2;
	} rsi;
	struct {
		uint8_t op1;
		BITFLD(r1, r3);
		BITFLD(b2, dl2h);
		uint8_t dl2l;
		uint8_t dh2;
		uint8_t op2;
	} rsy_a;
	struct {
		uint8_t op1;
		BITFLD(r1, m3);
		BITFLD(b2, dl2h);
		uint8_t dl2l;
		uint8_t dh2;
		uint8_t op2;
	} rsy_b;
	struct {
		uint8_t op1;
		BITFLD(r1, op2);
		uint16_t i2;
	} ri_a;
	struct {
		uint8_t op1;
		BITFLD(r1, op2);
		uint16_t ri2;
	} ri_b;
	struct {
		uint8_t op1;
		BITFLD(m1, op2);
		uint16_t ri2;
	} ri_c;
	struct {
		uint8_t op1;
		BITFLD(r1, _pad0);
		uint16_t i2;
		BITFLD(m3, _pad1);
		uint8_t op2;
	} rie_a;
	struct {
		uint8_t op1;
		BITFLD(r1, r2);
		uint16_t ri4;
		BITFLD(m3, _pad);
		uint8_t op2;
	} rie_b;
	struct {
		uint8_t op1;
		BITFLD(r1, m3);
		uint16_t ri4;
		uint8_t i2;
		uint8_t op2;
	} rie_c;
	struct {
		uint8_t op1;
		BITFLD(r1, r3);
		uint16_t i2;
		uint8_t _pad;
		uint8_t op2;
	} rie_d;
	struct {
		uint8_t op1;
		BITFLD(r1, r3);
		uint16_t ri2;
		uint8_t _pad;
		uint8_t op2;
	} rie_e;
	struct {
		uint8_t op1;
		BITFLD(r1, r2);
		uint8_t i3;
		uint8_t i4;
		uint8_t i5;
		uint8_t op2;
	} rie_f;
	struct {
		uint8_t op1;
		BITFLD(r1, op2);
		uint16_t i2h;
		uint16_t i2l;
	} ril_a;
	struct {
		uint8_t op1;
		BITFLD(r1, op2);
		uint16_t ri2h;
		uint16_t ri2l;
	} ril_b;
	struct {
		uint8_t op1;
		BITFLD(m1, op2);
		uint16_t ri2h;
		uint16_t ri2l;
	} ril_c;
	struct {
		uint8_t op1;
		BITFLD(r1, m3);
		BITFLD(b4, d4h);
		uint8_t d4l;
		uint8_t i2;
		uint8_t op2;
	} ris;
	struct {
		uint8_t op;
		uint8_t i2;
		BITFLD(b1, d1h);
		uint8_t d1l;
	} si;
	struct {
		uint16_t op;
		BITFLD(b1, d1h);
		uint8_t d1l;
		uint16_t i2;
	} sil;
	struct {
		uint8_t op1;
		uint8_t i2;
		BITFLD(b1, dl1h);
		uint8_t dl1l;
		uint8_t dh1;
		uint8_t op2;
	} siy;
	struct {
		uint8_t op;
		BITFLD(m1, pad);
		BITFLD(b3, d3h);
		uint8_t d3l;
		uint16_t ri2;
	} smi;
	struct {
		uint8_t op1;
		uint8_t op2;
		BITFLD(b2, d2h);
		uint8_t d2l;
	} s;
	struct {
		uint8_t op;
		uint8_t l;
		BITFLD(b1, d1h);
		uint8_t d1l;
		BITFLD(b2, d2h);
		uint8_t d2l;
	} ss_a;
	struct {
		uint8_t op;
		BITFLD(l1, l2);
		BITFLD(b1, d1h);
		uint8_t d1l;
		BITFLD(b2, d2h);
		uint8_t d2l;
	} ss_b;
	struct {
		uint8_t op;
		BITFLD(l1, i3);
		BITFLD(b1, d1h);
		uint8_t d1l;
		BITFLD(b2, d2h);
		uint8_t d2l;
	} ss_c;
	struct {
		uint8_t op;
		BITFLD(r1, r3);
		BITFLD(b1, d1h);
		uint8_t d1l;
		BITFLD(b2, d2h);
		uint8_t d2l;
	} ss_d;
	struct {
		uint8_t op;
		BITFLD(r1, r3);
		BITFLD(b2, d2h);
		uint8_t d2l;
		BITFLD(b4, d4h);
		uint8_t d4l;
	} ss_e;
	struct {
		uint8_t op;
		uint8_t l2;
		BITFLD(b1, d1h);
		uint8_t d1l;
		BITFLD(b2, d2h);
		uint8_t d2l;
	} ss_f;
	struct {
		uint16_t op;
		BITFLD(b1, d1h);
		uint8_t d1l;
		BITFLD(b2, d2h);
		uint8_t d2l;
	} sse;
	struct {
		uint8_t op1;
		BITFLD(r3, op2);
		BITFLD(b1, d1h);
		uint8_t d1l;
		BITFLD(b2, d2h);
		uint8_t d2l;
	} ssf;
};

#define	INSTR(op, m, fm, fl)	[op] = { \
					.it_u.it_inst = { \
						.it_name = (m), \
						.it_flags = (fl), \
					}, \
					.it_fmt = (fm), \
				}
#define	TABLE(op, tbl, o, s, m)	[op] = { \
					.it_u.it_table = { \
						.it_ptr = (tbl), \
						.it_off = (o), \
						.it_shift = (s), \
						.it_mask = (m), \
					}, \
					.it_fmt = IF_TBL, \
				}
#define	MULTI(op, tbl)		[op] = { \
					.it_u.it_multi.it_ptr = (tbl), \
					.it_fmt = IF_MULTI, \
				}

/*
 * Instruction tables based on:
 *   GA22-7000-4   System/370 Principles of Operation
 *   SA22-7201-08  ESA/390 Principles of Operation
 *   SA22-7832-09  z/Architecture Principles of Operation
 */

/* BEGIN CSTYLED */
static const struct inst_table tbl_01xx[256] = {
	INSTR(0x01, "pr",    IF_E, F_390 | F_Z),
	INSTR(0x02, "upt",   IF_E, F_390 | F_Z),
	INSTR(0x04, "ptff",  IF_E, F_Z),
	INSTR(0x07, "sckpf", IF_E, F_390 | F_Z),
	INSTR(0x0a, "pfpo",  IF_E, F_Z),
	INSTR(0x0b, "tam",   IF_E, F_390 | F_Z),
	INSTR(0x0c, "sam24", IF_E, F_390 | F_Z),
	INSTR(0x0d, "sam31", IF_E, F_390 | F_Z),
	INSTR(0x0e, "sam64", IF_E, F_Z),
	INSTR(0xff, "trap2", IF_E, F_390 | F_Z),
};

static const struct inst_table tbl_07[] = {
	INSTR(0x0, "nopr",  IF_RR, F_370 | F_390 | F_Z | F_HIDE_MASK),
	INSTR(0x1, "bor",   IF_RR, F_370 | F_390 | F_Z | F_HIDE_MASK),
	INSTR(0x2, "bhr",   IF_RR, F_370 | F_390 | F_Z | F_HIDE_MASK),
	INSTR(0x3, "bcr",   IF_RR, F_370 | F_390 | F_Z | F_R1_IS_MASK),
	INSTR(0x4, "blr",   IF_RR, F_370 | F_390 | F_Z | F_HIDE_MASK),
	INSTR(0x5, "bcr",   IF_RR, F_370 | F_390 | F_Z | F_R1_IS_MASK),
	INSTR(0x6, "bcr",   IF_RR, F_370 | F_390 | F_Z | F_R1_IS_MASK),
	INSTR(0x7, "bnzr",  IF_RR, F_370 | F_390 | F_Z | F_HIDE_MASK),
	INSTR(0x8, "ber",   IF_RR, F_370 | F_390 | F_Z | F_HIDE_MASK),
	INSTR(0x9, "bcr",   IF_RR, F_370 | F_390 | F_Z | F_R1_IS_MASK),
	INSTR(0xa, "bcr",   IF_RR, F_370 | F_390 | F_Z | F_R1_IS_MASK),
	INSTR(0xb, "bner",  IF_RR, F_370 | F_390 | F_Z | F_HIDE_MASK),
	INSTR(0xc, "bcr",   IF_RR, F_370 | F_390 | F_Z | F_R1_IS_MASK),
	INSTR(0xd, "bnhr",  IF_RR, F_370 | F_390 | F_Z | F_HIDE_MASK),
	INSTR(0xe, "bnor",  IF_RR, F_370 | F_390 | F_Z | F_HIDE_MASK),
	INSTR(0xf, "br",    IF_RR, F_370 | F_390 | F_Z | F_HIDE_MASK),
};

static const struct inst_table tbl_47[] = {
	INSTR(0x0, "nop",   IF_RXb, F_370 | F_390 | F_Z | F_HIDE_MASK),
	INSTR(0x1, "bo",    IF_RXb, F_370 | F_390 | F_Z | F_HIDE_MASK),
	INSTR(0x2, "bh",    IF_RXb, F_370 | F_390 | F_Z | F_HIDE_MASK),
	INSTR(0x3, "bc",    IF_RXb, F_370 | F_390 | F_Z),
	INSTR(0x4, "bl",    IF_RXb, F_370 | F_390 | F_Z | F_HIDE_MASK),
	INSTR(0x5, "bc",    IF_RXb, F_370 | F_390 | F_Z),
	INSTR(0x6, "bc",    IF_RXb, F_370 | F_390 | F_Z),
	INSTR(0x7, "bne",   IF_RXb, F_370 | F_390 | F_Z | F_HIDE_MASK),
	INSTR(0x8, "be",    IF_RXb, F_370 | F_390 | F_Z | F_HIDE_MASK),
	INSTR(0x9, "bc",    IF_RXb, F_370 | F_390 | F_Z),
	INSTR(0xa, "bc",    IF_RXb, F_370 | F_390 | F_Z),
	INSTR(0xb, "bnl",   IF_RXb, F_370 | F_390 | F_Z | F_HIDE_MASK),
	INSTR(0xc, "bc",    IF_RXb, F_370 | F_390 | F_Z),
	INSTR(0xd, "bnh",   IF_RXb, F_370 | F_390 | F_Z | F_HIDE_MASK),
	INSTR(0xe, "bno",   IF_RXb, F_370 | F_390 | F_Z | F_HIDE_MASK),
	INSTR(0xf, "b",     IF_RXb, F_370 | F_390 | F_Z | F_HIDE_MASK),
};

/* the preferred mnemonic changed over time */
static const struct inst_table tbl_25[] = {
	INSTR(F_370, "lrdr",  IF_RR,   F_370),
	INSTR(F_390, "ldxr",  IF_RR,   F_390),
	INSTR(F_Z,   "ldxr",  IF_RR,   F_Z),
};

/* the preferred mnemonic changed over time */
static const struct inst_table tbl_35[] = {
	INSTR(F_370, "lrer",  IF_RR,   F_370),
	INSTR(F_390, "ledr",  IF_RR,   F_390),
	INSTR(F_Z,   "ledr",  IF_RR,   F_Z),
};

/* the preferred mnemonic changed over time */
static const struct inst_table tbl_3c[] = {
	INSTR(F_370, "mer",   IF_RR,   F_370),
	INSTR(F_390, "mder",  IF_RR,   F_390),
	INSTR(F_Z,   "mder",  IF_RR,   F_Z),
};

/* the preferred mnemonic changed over time */
static const struct inst_table tbl_7c[] = {
	INSTR(F_370, "me",    IF_RXa,  F_370),
	INSTR(F_390, "mde",   IF_RXa,  F_390),
	INSTR(F_Z,   "mde",   IF_RXa,  F_Z),
};

/* the meaning of this instruction changed over time */
static const struct inst_table tbl_84[] = {
	INSTR(F_370, "wrd",   IF_SI,   F_370),
	INSTR(F_390, "brxh",  IF_RSI,  F_390),
	INSTR(F_Z,   "brxh",  IF_RSI,  F_Z),
};

/* the meaning of this instruction changed over time */
static const struct inst_table tbl_85[] = {
	INSTR(F_370, "rdd",   IF_SI,   F_370),
	INSTR(F_390, "brxle", IF_RSI,  F_390),
	INSTR(F_Z,   "brxle", IF_RSI,  F_Z),
};

static const struct inst_table tbl_a5x[16] = {
	INSTR(0x0,  "iihh",  IF_RIa, F_Z),
	INSTR(0x1,  "iihl",  IF_RIa, F_Z),
	INSTR(0x2,  "iilh",  IF_RIa, F_Z),
	INSTR(0x3,  "iill",  IF_RIa, F_Z),
	INSTR(0x4,  "nihh",  IF_RIa, F_Z),
	INSTR(0x5,  "nihl",  IF_RIa, F_Z),
	INSTR(0x6,  "nilh",  IF_RIa, F_Z),
	INSTR(0x7,  "nill",  IF_RIa, F_Z),
	INSTR(0x8,  "oihh",  IF_RIa, F_Z),
	INSTR(0x9,  "oihl",  IF_RIa, F_Z),
	INSTR(0xa,  "oilh",  IF_RIa, F_Z),
	INSTR(0xb,  "oill",  IF_RIa, F_Z),
	INSTR(0xc,  "llihh", IF_RIa, F_Z),
	INSTR(0xd,  "llihl", IF_RIa, F_Z),
	INSTR(0xe,  "llilh", IF_RIa, F_Z),
	INSTR(0xf,  "llill", IF_RIa, F_Z),
};

/* the preferred mnemonic changed over time */
static const struct inst_table tbl_a70[] = {
	INSTR(F_390, "tmh",    IF_RIa, F_390),
	INSTR(F_Z,   "tmlh",   IF_RIa, F_Z),
};

/* the preferred mnemonic changed over time */
static const struct inst_table tbl_a71[] = {
	INSTR(F_390, "tml",    IF_RIa, F_390),
	INSTR(F_Z,   "tmll",   IF_RIa, F_Z),
};

static const struct inst_table tbl_a74[16] = {
	INSTR(0x0, "jnop", IF_RIc, F_390 | F_Z | F_HIDE_MASK),
	INSTR(0x1, "jo",   IF_RIc, F_390 | F_Z | F_HIDE_MASK),
	INSTR(0x2, "jh",   IF_RIc, F_390 | F_Z | F_HIDE_MASK),
	INSTR(0x3, "brc",  IF_RIc, F_390 | F_Z),
	INSTR(0x4, "jl",   IF_RIc, F_390 | F_Z | F_HIDE_MASK),
	INSTR(0x5, "brc",  IF_RIc, F_390 | F_Z),
	INSTR(0x6, "brc",  IF_RIc, F_390 | F_Z),
	INSTR(0x7, "jne",  IF_RIc, F_390 | F_Z | F_HIDE_MASK),
	INSTR(0x8, "je",   IF_RIc, F_390 | F_Z | F_HIDE_MASK),
	INSTR(0x9, "brc",  IF_RIc, F_390 | F_Z),
	INSTR(0xa, "brc",  IF_RIc, F_390 | F_Z),
	INSTR(0xb, "jnl",  IF_RIc, F_390 | F_Z | F_HIDE_MASK),
	INSTR(0xc, "brc",  IF_RIc, F_390 | F_Z),
	INSTR(0xd, "jnh",  IF_RIc, F_390 | F_Z | F_HIDE_MASK),
	INSTR(0xe, "jno",  IF_RIc, F_390 | F_Z | F_HIDE_MASK),
	INSTR(0xf, "j",    IF_RIc, F_390 | F_Z | F_HIDE_MASK),
};

static const struct inst_table tbl_a7x[16] = {
	MULTI(0x0, tbl_a70),
	MULTI(0x1, tbl_a71),
	INSTR(0x2, "tmhh",   IF_RIa, F_Z),
	INSTR(0x3, "tmhl",   IF_RIa, F_Z),
	TABLE(0x4, tbl_a74, 1, 4, 0x0f),
	INSTR(0x5, "bras",   IF_RIb, F_390 | F_Z),
	INSTR(0x6, "brct",   IF_RIb, F_390 | F_Z),
	INSTR(0x7, "brctg",  IF_RIb, F_Z),
	INSTR(0x8, "lhi",    IF_RIa, F_390 | F_Z),
	INSTR(0x9, "lghi",   IF_RIa, F_Z),
	INSTR(0xa, "ahi",    IF_RIa, F_390 | F_Z | F_SIGNED_IMM),
	INSTR(0xb, "aghi",   IF_RIa, F_Z | F_SIGNED_IMM),
	INSTR(0xc, "mhi",    IF_RIa, F_390 | F_Z),
	INSTR(0xd, "mghi",   IF_RIa, F_Z),
	INSTR(0xe, "chi",    IF_RIa, F_390 | F_Z | F_SIGNED_IMM),
	INSTR(0xf, "cghi",   IF_RIa, F_Z | F_SIGNED_IMM),
};

static const struct inst_table tbl_b2a6[] = {
	INSTR(F_390, "cuutf", IF_RRFc, F_390),
	INSTR(F_Z,   "c21",   IF_RRFc, F_Z),
};

static const struct inst_table tbl_b2a7[] = {
	INSTR(F_390, "cutfu",  IF_RRFc, F_390),
	INSTR(F_Z,   "cu12",   IF_RRFc, F_Z),
};

static const struct inst_table tbl_b2xx[256] = {
	INSTR(0x02, "stidp",  IF_S,    F_370 | F_390 | F_Z),
	INSTR(0x04, "sck",    IF_S,    F_370 | F_390 | F_Z),
	INSTR(0x05, "stck",   IF_S,    F_370 | F_390 | F_Z),
	INSTR(0x06, "sckc",   IF_S,    F_370 | F_390 | F_Z),
	INSTR(0x07, "stckc",  IF_S,    F_370 | F_390 | F_Z),
	INSTR(0x08, "spt",    IF_S,    F_370 | F_390 | F_Z),
	INSTR(0x09, "stpt",   IF_S,    F_370 | F_390 | F_Z),
	INSTR(0x0a, "spka",   IF_S,    F_370 | F_390 | F_Z),
	INSTR(0x0b, "ipk",    IF_S,    F_370 | F_390 | F_Z),
	INSTR(0x0d, "ptlb",   IF_S,    F_370 | F_390 | F_Z),
	INSTR(0x10, "spx",    IF_S,    F_370 | F_390 | F_Z),
	INSTR(0x11, "stpx",   IF_S,    F_370 | F_390 | F_Z),
	INSTR(0x12, "stap",   IF_S,    F_370 | F_390 | F_Z),
	INSTR(0x13, "rrb",    IF_S,    F_370),
	INSTR(0x14, "sie",    IF_S,    F_390 | F_Z),
	INSTR(0x18, "pc",     IF_S,    F_390 | F_Z),
	INSTR(0x19, "sac",    IF_S,    F_390 | F_Z),
	INSTR(0x1a, "cfc",    IF_S,    F_390 | F_Z),
	INSTR(0x21, "ipte",   IF_RRE,  F_390 | F_Z),
	INSTR(0x22, "ipm",    IF_RRE,  F_390 | F_Z),
	INSTR(0x23, "ivsk",   IF_RRE,  F_390 | F_Z),
	INSTR(0x24, "iac",    IF_RRE,  F_390 | F_Z),
	INSTR(0x25, "ssar",   IF_RRE,  F_390 | F_Z),
	INSTR(0x26, "epar",   IF_RRE,  F_390 | F_Z),
	INSTR(0x27, "esar",   IF_RRE,  F_390 | F_Z),
	INSTR(0x28, "pt",     IF_RRE,  F_390 | F_Z),
	INSTR(0x29, "iske",   IF_RRE,  F_390 | F_Z),
	INSTR(0x2a, "rrbe",   IF_RRE,  F_390 | F_Z),
	INSTR(0x2b, "sske",   IF_RRFc, F_390 | F_Z),
	INSTR(0x2c, "tb",     IF_RRE,  F_390 | F_Z),
	INSTR(0x2d, "dxr",    IF_RRE,  F_390 | F_Z),
	INSTR(0x2e, "pgin",   IF_RRE,  F_390 | F_Z),
	INSTR(0x2f, "pgout",  IF_RRE,  F_390 | F_Z),
	INSTR(0x30, "csch",   IF_S,    F_Z),
	INSTR(0x31, "hsch",   IF_S,    F_Z),
	INSTR(0x32, "msch",   IF_S,    F_Z),
	INSTR(0x33, "ssch",   IF_S,    F_Z),
	INSTR(0x34, "stsch",  IF_S,    F_Z),
	INSTR(0x35, "tsch",   IF_S,    F_Z),
	INSTR(0x36, "tpi",    IF_S,    F_Z),
	INSTR(0x37, "sal",    IF_S,    F_Z),
	INSTR(0x38, "rsch",   IF_S,    F_Z),
	INSTR(0x39, "stcrw",  IF_S,    F_Z),
	INSTR(0x3a, "stcps",  IF_S,    F_Z),
	INSTR(0x3b, "rchp",   IF_S,    F_Z),
	INSTR(0x3d, "schm",   IF_S,    F_Z),
	INSTR(0x40, "bakr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x41, "cksm",   IF_RRE,  F_390 | F_Z),
	INSTR(0x44, "sqdr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x45, "sqer",   IF_RRE,  F_390 | F_Z),
	INSTR(0x46, "stura",  IF_RRE,  F_390 | F_Z),
	INSTR(0x47, "msta",   IF_RRE,  F_390 | F_Z),
	INSTR(0x48, "palb",   IF_RRE,  F_390 | F_Z),
	INSTR(0x49, "ereg",   IF_RRE,  F_390 | F_Z),
	INSTR(0x4a, "esta",   IF_RRE,  F_390 | F_Z),
	INSTR(0x4b, "lura",   IF_RRE,  F_390 | F_Z),
	INSTR(0x4c, "tar",    IF_RRE,  F_390 | F_Z),
	INSTR(0x4d, "cpya",   IF_RRE,  F_390 | F_Z),
	INSTR(0x4e, "sar",    IF_RRE,  F_390 | F_Z),
	INSTR(0x4f, "ear",    IF_RRE,  F_390 | F_Z),
	INSTR(0x50, "csp",    IF_RRE,  F_390 | F_Z),
	INSTR(0x52, "msr",    IF_RRE,  F_390 | F_Z),
	INSTR(0x54, "mvpg",   IF_RRE,  F_390 | F_Z),
	INSTR(0x55, "mvst",   IF_RRE,  F_390 | F_Z),
	INSTR(0x57, "cuse",   IF_RRE,  F_390 | F_Z),
	INSTR(0x58, "bsg",    IF_RRE,  F_390 | F_Z),
	INSTR(0x5a, "bsa",    IF_RRE,  F_390 | F_Z),
	INSTR(0x5d, "clst",   IF_RRE,  F_390 | F_Z),
	INSTR(0x5e, "srst",   IF_RRE,  F_390 | F_Z),
	INSTR(0x63, "cmpsc",  IF_RRE,  F_Z),
	INSTR(0x76, "xsch",   IF_S,    F_Z),
	INSTR(0x77, "rp",     IF_S,    F_390 | F_Z),
	INSTR(0x78, "stcke",  IF_S,    F_390 | F_Z),
	INSTR(0x79, "sacf",   IF_S,    F_390 | F_Z),
	INSTR(0x7c, "stckf",  IF_S,    F_Z),
	INSTR(0x7d, "stsi",   IF_S,    F_390 | F_Z),
	INSTR(0x99, "srnm",   IF_S,    F_390 | F_Z),
	INSTR(0x9c, "stfpc",  IF_S,    F_390 | F_Z),
	INSTR(0x9d, "lfpc",   IF_S,    F_390 | F_Z),
	INSTR(0xa5, "tre",    IF_RRE,  F_390 | F_Z),
	MULTI(0xa6, tbl_b2a6),
	MULTI(0xa7, tbl_b2a7),
	INSTR(0xb0, "stfle",  IF_S,    F_Z),
	INSTR(0xb1, "stfl",   IF_S,    F_390 | F_Z),
	INSTR(0xb2, "lpswe",  IF_S,    F_Z),
	INSTR(0xb8, "srnmb",  IF_S,    F_Z),
	INSTR(0xb9, "srnmt",  IF_S,    F_Z),
	INSTR(0xbd, "lfas",   IF_S,    F_Z),
	INSTR(0xe8, "ppa",    IF_RRFc, F_Z),
	INSTR(0xec, "etnd",   IF_RRE,  F_Z),
	INSTR(0xf8, "tend",   IF_S,    F_Z),
	INSTR(0xfa, "niai",   IF_IE,   F_Z),
	INSTR(0xfc, "tabort", IF_S,    F_Z),
	INSTR(0xff, "trap4",  IF_S,    F_390 | F_Z),
};

static const struct inst_table tbl_b344[] = {
	INSTR(F_390, "ledbr",  IF_RRE,  F_390),
	INSTR(F_Z,   "ledbra", IF_RRFe, F_Z),
};

static const struct inst_table tbl_b345[] = {
	INSTR(F_390, "ldxbr",  IF_RRE,  F_390),
	INSTR(F_Z,   "ldxbra", IF_RRFe, F_Z),
};

static const struct inst_table tbl_b346[] = {
	INSTR(F_390, "lexbr",  IF_RRE,  F_390),
	INSTR(F_Z,   "lexbra", IF_RRFe, F_Z),
};

static const struct inst_table tbl_b347[] = {
	INSTR(F_390, "fixbr",  IF_RRFe, F_390),
	INSTR(F_Z,   "fixbra", IF_RRFe, F_Z),
};

static const struct inst_table tbl_b357[] = {
	INSTR(F_390, "fiebr",  IF_RRFe, F_390),
	INSTR(F_Z,   "fiebre", IF_RRFe, F_Z),
};

static const struct inst_table tbl_b35f[] = {
	INSTR(F_390, "fidbr",  IF_RRFe, F_390),
	INSTR(F_Z,   "fidbra", IF_RRFe, F_Z),
};

static const struct inst_table tbl_b394[] = {
	INSTR(F_390, "cefbr",  IF_RRE,  F_390),
	INSTR(F_Z,   "cefbra", IF_RRFe, F_Z),
};

static const struct inst_table tbl_b395[] = {
	INSTR(F_390, "cdfbr",  IF_RRE,  F_390),
	INSTR(F_Z,   "cdfbra", IF_RRFe, F_Z),
};

static const struct inst_table tbl_b396[] = {
	INSTR(F_390, "cxfbr",  IF_RRE,  F_390),
	INSTR(F_Z,   "cxfbra", IF_RRFe, F_Z),
};

static const struct inst_table tbl_b398[] = {
	INSTR(F_390, "cfebr",  IF_RRFe, F_390),
	INSTR(F_Z,   "cfebra", IF_RRFe, F_Z),
};

static const struct inst_table tbl_b399[] = {
	INSTR(F_390, "cfdbr",  IF_RRFe, F_390),
	INSTR(F_Z,   "cfdbra", IF_RRFe, F_Z),
};

static const struct inst_table tbl_b39a[] = {
	INSTR(F_390, "cfxbr",  IF_RRFe, F_390),
	INSTR(F_Z,   "cfxbra", IF_RRFe, F_Z),
};

static const struct inst_table tbl_b3xx[256] = {
	INSTR(0x00, "lpebr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x01, "lnebr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x02, "ltebr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x03, "lcebr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x04, "ldebr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x05, "lxdbr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x06, "lxebr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x07, "mxdbr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x08, "kebr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x09, "cebr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x0a, "aebr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x0b, "sebr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x0c, "mdebr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x0d, "debr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x0e, "maebr",  IF_RRD,  F_390 | F_Z),
	INSTR(0x0f, "msebr",  IF_RRD,  F_390 | F_Z),
	INSTR(0x10, "lpdbr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x11, "lndbr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x12, "ltdbr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x13, "lcdbr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x14, "sqebr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x15, "sqdbr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x16, "sqxbr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x17, "meebr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x18, "kdbr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x19, "cdbr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x1a, "adbr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x1b, "sdbr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x1c, "mdbr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x1d, "ddbr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x1e, "madbr",  IF_RRD,  F_390 | F_Z),
	INSTR(0x1f, "msdbr",  IF_RRD,  F_390 | F_Z),
	INSTR(0x24, "lder",   IF_RRE,  F_390 | F_Z),
	INSTR(0x25, "lxdr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x26, "lxer",   IF_RRE,  F_390 | F_Z),
	INSTR(0x2e, "maer",   IF_RRD,  F_390 | F_Z),
	INSTR(0x2f, "mser",   IF_RRD,  F_390 | F_Z),
	INSTR(0x36, "sqxr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x37, "meer",   IF_RRE,  F_390 | F_Z),
	INSTR(0x38, "maylr",  IF_RRD,  F_Z),
	INSTR(0x39, "mylr",   IF_RRD,  F_Z),
	INSTR(0x3a, "mayr",   IF_RRD,  F_Z),
	INSTR(0x3b, "myr",    IF_RRD,  F_Z),
	INSTR(0x3c, "mayhr",  IF_RRD,  F_Z),
	INSTR(0x3d, "myhr",   IF_RRD,  F_Z),
	INSTR(0x3e, "madr",   IF_RRD,  F_390 | F_Z),
	INSTR(0x3f, "msdr",   IF_RRD,  F_390 | F_Z),
	INSTR(0x40, "lpxbr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x41, "lnxbr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x42, "ltxbr",  IF_RRE,  F_390 | F_Z),
	INSTR(0x43, "lcxbr",  IF_RRE,  F_390 | F_Z),
	MULTI(0x44, tbl_b344),
	MULTI(0x45, tbl_b345),
	MULTI(0x46, tbl_b346),
	MULTI(0x47, tbl_b347),
	INSTR(0x48, "kxbr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x49, "cxbr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x4a, "axbr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x4b, "sxbr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x4c, "mxbr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x4d, "dxbr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x50, "tbedr",  IF_RRFe, F_390 | F_Z),
	INSTR(0x51, "tbdr",   IF_RRFe, F_390 | F_Z),
	INSTR(0x53, "diebr",  IF_RRFb, F_390 | F_Z),
	MULTI(0x57, tbl_b357),
	INSTR(0x58, "thder",  IF_RRE,  F_390 | F_Z),
	INSTR(0x59, "thdr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x5b, "didbr",  IF_RRFe, F_390 | F_Z),
	MULTI(0x5f, tbl_b35f),
	INSTR(0x60, "lpxr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x61, "lnxr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x62, "ltxr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x63, "lcxr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x65, "lxr",    IF_RRE,  F_390 | F_Z),
	INSTR(0x66, "lexr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x67, "fixr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x69, "cxr",    IF_RRE,  F_390 | F_Z),
	INSTR(0x70, "lpdfr",  IF_RRE,  F_Z),
	INSTR(0x71, "lndfr",  IF_RRE,  F_Z),
	INSTR(0x72, "cpsdr",  IF_RRFe, F_Z),
	INSTR(0x73, "lcdfr",  IF_RRE,  F_Z),
	INSTR(0x74, "lzer",   IF_RRE,  F_390 | F_Z),
	INSTR(0x75, "lzdr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x76, "lzxr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x77, "fier",   IF_RRE,  F_390 | F_Z),
	INSTR(0x7f, "fidr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x84, "sfpc",   IF_RRE,  F_390 | F_Z),
	INSTR(0x85, "sfasr",  IF_RRE,  F_Z),
	INSTR(0x8c, "efpc",   IF_RRE,  F_390 | F_Z),
	INSTR(0x90, "celfbr", IF_RRFe, F_Z),
	INSTR(0x91, "cdlfbr", IF_RRFe, F_Z),
	INSTR(0x92, "cxlfbr", IF_RRFe, F_Z),
	MULTI(0x94, tbl_b394),
	MULTI(0x95, tbl_b395),
	MULTI(0x96, tbl_b396),
	MULTI(0x98, tbl_b398),
	MULTI(0x99, tbl_b399),
	MULTI(0x9a, tbl_b39a),
	INSTR(0x9c, "clfebr", IF_RRFe, F_Z),
	INSTR(0x9d, "clfdbr", IF_RRFe, F_Z),
	INSTR(0x9e, "clfxbr", IF_RRFe, F_Z),
	INSTR(0xa0, "celgbr", IF_RRFe, F_Z),
	INSTR(0xa1, "cdlgbr", IF_RRFe, F_Z),
	INSTR(0xa2, "cxlgbr", IF_RRFe, F_Z),
	INSTR(0xa4, "cegbra", IF_RRFe, F_Z),
	INSTR(0xa5, "cdgbra", IF_RRFe, F_Z),
	INSTR(0xa6, "cxgbra", IF_RRFe, F_Z),
	INSTR(0xa8, "cgebra", IF_RRFe, F_Z),
	INSTR(0xa9, "cgdbra", IF_RRFe, F_Z),
	INSTR(0xaa, "cgxbra", IF_RRFe, F_Z),
	INSTR(0xac, "clgebr", IF_RRFe, F_Z),
	INSTR(0xad, "clgdbr", IF_RRFe, F_Z),
	INSTR(0xae, "clgxbr", IF_RRFe, F_Z),
	INSTR(0xb4, "cefr",   IF_RRE,  F_390 | F_Z),
	INSTR(0xb5, "cdfr",   IF_RRE,  F_390 | F_Z),
	INSTR(0xb6, "cxfr",   IF_RRE,  F_390 | F_Z),
	INSTR(0xb8, "cfer",   IF_RRFe, F_390 | F_Z),
	INSTR(0xb9, "cfdr",   IF_RRFe, F_390 | F_Z),
	INSTR(0xba, "cfxr",   IF_RRFe, F_390 | F_Z),
	INSTR(0xc1, "ldgr",   IF_RRE,  F_Z),
	INSTR(0xc4, "cegr",   IF_RRE,  F_Z),
	INSTR(0xc5, "cdgr",   IF_RRE,  F_Z),
	INSTR(0xc6, "cxgr",   IF_RRE,  F_Z),
	INSTR(0xc8, "cger",   IF_RRFe, F_Z),
	INSTR(0xc9, "cgdr",   IF_RRFe, F_Z),
	INSTR(0xca, "cgxr",   IF_RRFe, F_Z),
	INSTR(0xcd, "lgdr",   IF_RRE,  F_Z),
	INSTR(0xd0, "mdtra",  IF_RRFa, F_Z),
	INSTR(0xd1, "ddtra",  IF_RRFa, F_Z),
	INSTR(0xd2, "adtra",  IF_RRFa, F_Z),
	INSTR(0xd3, "sdtra",  IF_RRFa, F_Z),
	INSTR(0xd4, "ldetr",  IF_RRFd, F_Z),
	INSTR(0xd5, "ledtr",  IF_RRFe, F_Z),
	INSTR(0xd6, "ltdtr",  IF_RRE,  F_Z),
	INSTR(0xd7, "fidtr",  IF_RRFe, F_Z),
	INSTR(0xd8, "mxtra",  IF_RRFa, F_Z),
	INSTR(0xd9, "dxtra",  IF_RRFa, F_Z),
	INSTR(0xda, "axtra",  IF_RRFa, F_Z),
	INSTR(0xdb, "sxtra",  IF_RRFa, F_Z),
	INSTR(0xdc, "lxdtr",  IF_RRFd, F_Z),
	INSTR(0xdd, "ldxtr",  IF_RRFe, F_Z),
	INSTR(0xde, "ltxtr",  IF_RRE,  F_Z),
	INSTR(0xdf, "fixtr",  IF_RRFe, F_Z),
	INSTR(0xe0, "kdtr",   IF_RRE,  F_Z),
	INSTR(0xe1, "cgdtra", IF_RRFe, F_Z),
	INSTR(0xe2, "cudtr",  IF_RRE,  F_Z),
	INSTR(0xe3, "csdtr",  IF_RRFd, F_Z),
	INSTR(0xe4, "cdtr",   IF_RRE,  F_Z),
	INSTR(0xe5, "eedtr",  IF_RRE,  F_Z),
	INSTR(0xe7, "esdtr",  IF_RRE,  F_Z),
	INSTR(0xe8, "kxtr",   IF_RRE,  F_Z),
	INSTR(0xe9, "cgxtra", IF_RRFe, F_Z),
	INSTR(0xea, "cuxtr",  IF_RRE,  F_Z),
	INSTR(0xeb, "csxtr",  IF_RRFd, F_Z),
	INSTR(0xec, "cxtr",   IF_RRE,  F_Z),
	INSTR(0xed, "eextr",  IF_RRE,  F_Z),
	INSTR(0xef, "esxtr",  IF_RRE,  F_Z),
	INSTR(0xf1, "cdgtra", IF_RRE,  F_Z),
	INSTR(0xf2, "cdutr",  IF_RRE,  F_Z),
	INSTR(0xf3, "cdstr",  IF_RRE,  F_Z),
	INSTR(0xf4, "cedtr",  IF_RRE,  F_Z),
	INSTR(0xf5, "qadtr",  IF_RRFb, F_Z),
	INSTR(0xf6, "iedtr",  IF_RRFb, F_Z),
	INSTR(0xf7, "rrdtr",  IF_RRFb, F_Z),
	INSTR(0xf9, "cxgtra", IF_RRE,  F_Z),
	INSTR(0xfa, "cxutr",  IF_RRE,  F_Z),
	INSTR(0xfb, "cxstr",  IF_RRE,  F_Z),
	INSTR(0xfc, "cextr",  IF_RRE,  F_Z),
	INSTR(0xfd, "qaxtr",  IF_RRFb, F_Z),
	INSTR(0xfe, "iextr",  IF_RRFb, F_Z),
	INSTR(0xff, "rrxtr",  IF_RRFb, F_Z),
};

static const struct inst_table tbl_b9xx[256] = {
	INSTR(0x00, "lpgr",   IF_RRE,  F_Z),
	INSTR(0x01, "lngr",   IF_RRE,  F_Z),
	INSTR(0x02, "ltgr",   IF_RRE,  F_Z),
	INSTR(0x03, "lcgr",   IF_RRE,  F_Z),
	INSTR(0x04, "lgr",    IF_RRE,  F_Z),
	INSTR(0x05, "lurag",  IF_RRE,  F_Z),
	INSTR(0x06, "lgbr",   IF_RRE,  F_Z),
	INSTR(0x07, "lghr",   IF_RRE,  F_Z),
	INSTR(0x08, "agr",    IF_RRE,  F_Z),
	INSTR(0x09, "sgr",    IF_RRE,  F_Z),
	INSTR(0x0a, "algr",   IF_RRE,  F_Z),
	INSTR(0x0b, "slgr",   IF_RRE,  F_Z),
	INSTR(0x0c, "msgr",   IF_RRE,  F_Z),
	INSTR(0x0d, "dsgr",   IF_RRE,  F_Z),
	INSTR(0x0e, "eregg",  IF_RRE,  F_Z),
	INSTR(0x0f, "lrvgr",  IF_RRE,  F_Z),
	INSTR(0x10, "lpgfr",  IF_RRE,  F_Z),
	INSTR(0x11, "lngfr",  IF_RRE,  F_Z),
	INSTR(0x12, "ltgfr",  IF_RRE,  F_Z),
	INSTR(0x13, "lcgfr",  IF_RRE,  F_Z),
	INSTR(0x14, "lgfr",   IF_RRE,  F_Z),
	INSTR(0x16, "llgfr",  IF_RRE,  F_Z),
	INSTR(0x17, "llgtr",  IF_RRE,  F_Z),
	INSTR(0x18, "agfr",   IF_RRE,  F_Z),
	INSTR(0x19, "sgfr",   IF_RRE,  F_Z),
	INSTR(0x1a, "algfr",  IF_RRE,  F_Z),
	INSTR(0x1b, "slgfr",  IF_RRE,  F_Z),
	INSTR(0x1c, "msgfr",  IF_RRE,  F_Z),
	INSTR(0x1d, "dsgfr",  IF_RRE,  F_Z),
	INSTR(0x1e, "kmac",   IF_RRE,  F_390 | F_Z),
	INSTR(0x1f, "lrvr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x20, "cgr",    IF_RRE,  F_Z),
	INSTR(0x21, "clgr",   IF_RRE,  F_Z),
	INSTR(0x25, "sturg",  IF_RRE,  F_Z),
	INSTR(0x26, "lbr",    IF_RRE,  F_Z),
	INSTR(0x27, "lhr",    IF_RRE,  F_Z),
	INSTR(0x28, "pckmo",  IF_RRE,  F_Z),
	INSTR(0x2a, "kmf",    IF_RRE,  F_Z),
	INSTR(0x2b, "kmo",    IF_RRE,  F_Z),
	INSTR(0x2c, "pcc",    IF_RRE,  F_Z),
	INSTR(0x2d, "kmctr",  IF_RRFd, F_Z),
	INSTR(0x2e, "km",     IF_RRE,  F_390 | F_Z),
	INSTR(0x2f, "kmc",    IF_RRE,  F_390 | F_Z),
	INSTR(0x30, "cgfr",   IF_RRE,  F_Z),
	INSTR(0x31, "clgfr",  IF_RRE,  F_Z),
	INSTR(0x3e, "kimd",   IF_RRE,  F_390 | F_Z),
	INSTR(0x3f, "klmd",   IF_RRE,  F_390 | F_Z),
	INSTR(0x41, "cfdtr",  IF_RRFe, F_Z),
	INSTR(0x42, "clgdtr", IF_RRFe, F_Z),
	INSTR(0x43, "clfdtr", IF_RRFe, F_Z),
	INSTR(0x46, "bctgr",  IF_RRE,  F_Z),
	INSTR(0x49, "cfxtr",  IF_RRFe, F_Z),
	INSTR(0x4a, "clgxtr", IF_RRFe, F_Z),
	INSTR(0x4b, "clfxtr", IF_RRFe, F_Z),
	INSTR(0x51, "cdftr",  IF_RRE,  F_Z),
	INSTR(0x52, "cdlgtr", IF_RRFe, F_Z),
	INSTR(0x53, "cdlftr", IF_RRFe, F_Z),
	INSTR(0x59, "cxftr",  IF_RRE,  F_Z),
	INSTR(0x5a, "cxlgtr", IF_RRFe, F_Z),
	INSTR(0x5b, "cxlftr", IF_RRFe, F_Z),
	INSTR(0x60, "cgrt",   IF_RRFc, F_Z),
	INSTR(0x61, "clgrt",  IF_RRFc, F_Z),
	INSTR(0x72, "crt",    IF_RRFc, F_Z),
	INSTR(0x73, "clrt",   IF_RRFc, F_Z),
	INSTR(0x80, "ngr",    IF_RRE,  F_Z),
	INSTR(0x81, "ogr",    IF_RRE,  F_Z),
	INSTR(0x82, "xgr",    IF_RRE,  F_Z),
	INSTR(0x83, "flogr",  IF_RRE,  F_Z),
	INSTR(0x84, "llgcr",  IF_RRE,  F_Z),
	INSTR(0x85, "llghr",  IF_RRE,  F_Z),
	INSTR(0x86, "mlgr",   IF_RRE,  F_Z),
	INSTR(0x87, "dlgr",   IF_RRE,  F_Z),
	INSTR(0x88, "alcgr",  IF_RRE,  F_Z),
	INSTR(0x89, "slbgr",  IF_RRE,  F_Z),
	INSTR(0x8a, "cspg",   IF_RRE,  F_Z),
	INSTR(0x8d, "epsw",   IF_RRE,  F_390 | F_Z),
	INSTR(0x8e, "idte",   IF_RRFb, F_Z),
	INSTR(0x8f, "crdte",  IF_RRFb, F_Z),
	INSTR(0x90, "trtt",   IF_RRFc, F_390 | F_Z),
	INSTR(0x91, "trto",   IF_RRFc, F_390 | F_Z),
	INSTR(0x92, "trot",   IF_RRFc, F_390 | F_Z),
	INSTR(0x93, "troo",   IF_RRFc, F_390 | F_Z),
	INSTR(0x94, "llcr",   IF_RRE,  F_Z),
	INSTR(0x95, "llhr",   IF_RRE,  F_Z),
	INSTR(0x96, "mlr",    IF_RRE,  F_390 | F_Z),
	INSTR(0x97, "dlr",    IF_RRE,  F_390 | F_Z),
	INSTR(0x98, "alcr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x99, "slbr",   IF_RRE,  F_390 | F_Z),
	INSTR(0x9a, "epair",  IF_RRE,  F_Z),
	INSTR(0x9b, "esair",  IF_RRE,  F_Z),
	INSTR(0x9d, "esea",   IF_RRE,  F_Z),
	INSTR(0x9e, "pti",    IF_RRE,  F_Z),
	INSTR(0x9f, "ssair",  IF_RRE,  F_Z),
	INSTR(0xa2, "ptf",    IF_RRE,  F_Z),
	INSTR(0xaa, "lptea",  IF_RRFb, F_Z),
	INSTR(0xae, "rrbm",   IF_RRE,  F_Z),
	INSTR(0xaf, "pfmf",   IF_RRE,  F_Z),
	INSTR(0xb0, "cu14",   IF_RRFc, F_Z),
	INSTR(0xb1, "cu24",   IF_RRFc, F_Z),
	INSTR(0xb2, "cu41",   IF_RRE,  F_Z),
	INSTR(0xb3, "cu42",   IF_RRE,  F_Z),
	INSTR(0xbd, "trtre",  IF_RRFc, F_Z),
	INSTR(0xbe, "srstu",  IF_RRE,  F_Z),
	INSTR(0xbf, "trte",   IF_RRFc, F_Z),
	INSTR(0xc8, "ahhhr",  IF_RRFa, F_Z),
	INSTR(0xc9, "shhhr",  IF_RRFa, F_Z),
	INSTR(0xca, "alhhhr", IF_RRFa, F_Z),
	INSTR(0xcb, "slhhhr", IF_RRFa, F_Z),
	INSTR(0xcd, "chhr",   IF_RRE,  F_Z),
	INSTR(0xcf, "clhhr",  IF_RRE,  F_Z),
	INSTR(0xd8, "ahhlr",  IF_RRFa, F_Z),
	INSTR(0xd9, "shhlr",  IF_RRFa, F_Z),
	INSTR(0xda, "alhhlr", IF_RRFa, F_Z),
	INSTR(0xdb, "slhhlr", IF_RRFa, F_Z),
	INSTR(0xdd, "chlr",   IF_RRE,  F_Z),
	INSTR(0xdf, "clhlr",  IF_RRE,  F_Z),
	INSTR(0xe1, "popcnt", IF_RRE,  F_Z),
	INSTR(0xe2, "locgr",  IF_RRFc, F_Z),
	INSTR(0xe4, "ngrk",   IF_RRFa, F_Z),
	INSTR(0xe6, "ogrk",   IF_RRFa, F_Z),
	INSTR(0xe7, "xgrk",   IF_RRFa, F_Z),
	INSTR(0xe8, "agrk",   IF_RRFa, F_Z),
	INSTR(0xe9, "sgrk",   IF_RRFa, F_Z),
	INSTR(0xea, "algrk",  IF_RRFa, F_Z),
	INSTR(0xeb, "slgrk",  IF_RRFa, F_Z),
	INSTR(0xf2, "locgr",  IF_RRFc, F_Z),
	INSTR(0xf4, "nrk",    IF_RRFa, F_Z),
	INSTR(0xf6, "ork",    IF_RRFa, F_Z),
	INSTR(0xf7, "xrk",    IF_RRFa, F_Z),
	INSTR(0xf8, "ark",    IF_RRFa, F_Z),
	INSTR(0xf9, "srk",    IF_RRFa, F_Z),
	INSTR(0xfa, "alrk",   IF_RRFa, F_Z),
	INSTR(0xfb, "slrk",   IF_RRFa, F_Z),
};

static const struct inst_table tbl_c0x[16] = {
	INSTR(0x0, "larl",   IF_RILb, F_390 | F_Z),
	INSTR(0x1, "lgfi",   IF_RILa, F_Z),
	INSTR(0x4, "brcl",   IF_RILc, F_390 | F_Z),
	INSTR(0x5, "brasl",  IF_RILb, F_390 | F_Z),
	INSTR(0x6, "xihf",   IF_RILa, F_Z),
	INSTR(0x7, "xilf",   IF_RILa, F_Z),
	INSTR(0x8, "iihf",   IF_RILa, F_Z),
	INSTR(0x9, "iilf",   IF_RILa, F_Z),
	INSTR(0xa, "nihf",   IF_RILa, F_Z),
	INSTR(0xb, "nilf",   IF_RILa, F_Z),
	INSTR(0xc, "oihf",   IF_RILa, F_Z),
	INSTR(0xd, "oilf",   IF_RILa, F_Z),
	INSTR(0xe, "llihf",  IF_RILa, F_Z),
	INSTR(0xf, "llilf",  IF_RILa, F_Z),
};

static const struct inst_table tbl_c2x[16] = {
	INSTR(0x0, "msgfi",  IF_RILa, F_Z),
	INSTR(0x1, "msfi",   IF_RILa, F_Z),
	INSTR(0x4, "slgfi",  IF_RILa, F_Z),
	INSTR(0x5, "slfi",   IF_RILa, F_Z),
	INSTR(0x8, "agfi",   IF_RILa, F_Z),
	INSTR(0x9, "afi",    IF_RILa, F_Z),
	INSTR(0xa, "algfi",  IF_RILa, F_Z),
	INSTR(0xb, "alfi",   IF_RILa, F_Z),
	INSTR(0xc, "cgfi",   IF_RILa, F_Z),
	INSTR(0xd, "cfi",    IF_RILa, F_Z),
	INSTR(0xe, "clgfi",  IF_RILa, F_Z),
	INSTR(0xf, "clfi",   IF_RILa, F_Z),
};

static const struct inst_table tbl_c4x[16] = {
	INSTR(0x2, "llhrl",  IF_RILb, F_Z),
	INSTR(0x4, "lghrl",  IF_RILb, F_Z),
	INSTR(0x5, "lhrl",   IF_RILb, F_Z),
	INSTR(0x6, "llghrl", IF_RILb, F_Z),
	INSTR(0x7, "sthrl",  IF_RILb, F_Z),
	INSTR(0x8, "lgrl",   IF_RILb, F_Z),
	INSTR(0xb, "stgrl",  IF_RILb, F_Z),
	INSTR(0xc, "lgfrl",  IF_RILb, F_Z),
	INSTR(0xd, "lrl",    IF_RILb, F_Z),
	INSTR(0xe, "llgfrl", IF_RILb, F_Z),
	INSTR(0xf, "strl",   IF_RILb, F_Z),
};

static const struct inst_table tbl_c6x[16] = {
	INSTR(0x0, "exrl",   IF_RILb, F_Z),
	INSTR(0x2, "pfdrl",  IF_RILc, F_Z),
	INSTR(0x4, "cghrl",  IF_RILb, F_Z),
	INSTR(0x5, "chrl",   IF_RILb, F_Z),
	INSTR(0x6, "clghrl", IF_RILb, F_Z),
	INSTR(0x7, "clhrl",  IF_RILb, F_Z),
	INSTR(0x8, "cgrl",   IF_RILb, F_Z),
	INSTR(0xa, "clgrl",  IF_RILb, F_Z),
	INSTR(0xc, "cgfrl",  IF_RILb, F_Z),
	INSTR(0xd, "crl",    IF_RILb, F_Z),
	INSTR(0xe, "clgfrl", IF_RILb, F_Z),
	INSTR(0xf, "clrl",   IF_RILb, F_Z),
};

static const struct inst_table tbl_c8x[16] = {
	INSTR(0x0, "mvcos",  IF_SSF, F_Z),
	INSTR(0x1, "ectg",   IF_SSF, F_Z),
	INSTR(0x2, "csst",   IF_SSF, F_Z),
	INSTR(0x4, "lpd",    IF_SSF, F_Z),
	INSTR(0x5, "lpdg",   IF_SSF, F_Z),
};

static const struct inst_table tbl_ccx[16] = {
	INSTR(0x6, "brcth",  IF_RILb, F_Z),
	INSTR(0x8, "aih",    IF_RILa, F_Z),
	INSTR(0xa, "alsih",  IF_RILa, F_Z),
	INSTR(0xb, "alsihn", IF_RILa, F_Z),
	INSTR(0xd, "cih",    IF_RILa, F_Z),
	INSTR(0xf, "clih",   IF_RILa, F_Z),
};

static const struct inst_table tbl_e3xx[256] = {
	INSTR(0x02, "ltg",    IF_RXYa, F_Z),
	INSTR(0x03, "lrag",   IF_RXYa, F_Z),
	INSTR(0x04, "lg",     IF_RXYa, F_Z),
	INSTR(0x06, "cvby",   IF_RXYa, F_Z),
	INSTR(0x08, "ag",     IF_RXYa, F_Z),
	INSTR(0x09, "sg",     IF_RXYa, F_Z),
	INSTR(0x0a, "alg",    IF_RXYa, F_Z),
	INSTR(0x0b, "slg",    IF_RXYa, F_Z),
	INSTR(0x0c, "msg",    IF_RXYa, F_Z),
	INSTR(0x0d, "dsg",    IF_RXYa, F_Z),
	INSTR(0x0e, "cvbg",   IF_RXYa, F_Z),
	INSTR(0x0f, "lrvg",   IF_RXYa, F_Z),
	INSTR(0x12, "lt",     IF_RXYa, F_Z),
	INSTR(0x13, "lray",   IF_RXYa, F_Z),
	INSTR(0x14, "lgf",    IF_RXYa, F_Z),
	INSTR(0x15, "lgh",    IF_RXYa, F_Z),
	INSTR(0x16, "llgf",   IF_RXYa, F_Z),
	INSTR(0x17, "llgt",   IF_RXYa, F_Z),
	INSTR(0x18, "agf",    IF_RXYa, F_Z),
	INSTR(0x19, "sgf",    IF_RXYa, F_Z),
	INSTR(0x1a, "algf",   IF_RXYa, F_Z),
	INSTR(0x1b, "slgf",   IF_RXYa, F_Z),
	INSTR(0x1c, "msgf",   IF_RXYa, F_Z),
	INSTR(0x1d, "dsgf",   IF_RXYa, F_Z),
	INSTR(0x1e, "lrv",    IF_RXYa, F_390 | F_Z),
	INSTR(0x1f, "lrvh",   IF_RXYa, F_390 | F_Z),
	INSTR(0x20, "cg",     IF_RXYa, F_Z),
	INSTR(0x21, "clg",    IF_RXYa, F_Z),
	INSTR(0x24, "stg",    IF_RXYa, F_Z),
	INSTR(0x25, "ntstg",  IF_RXYa, F_Z),
	INSTR(0x26, "cvdy",   IF_RXYa, F_Z),
	INSTR(0x2e, "cvdg",   IF_RXYa, F_Z),
	INSTR(0x2f, "strvg",  IF_RXYa, F_Z),
	INSTR(0x30, "cgf",    IF_RXYa, F_Z),
	INSTR(0x31, "clgf",   IF_RXYa, F_Z),
	INSTR(0x32, "ltgf",   IF_RXYa, F_Z),
	INSTR(0x34, "cgh",    IF_RXYa, F_Z),
	INSTR(0x36, "pfd",    IF_RXYb, F_Z),
	INSTR(0x3e, "strv",   IF_RXYa, F_390 | F_Z),
	INSTR(0x3f, "strvh",  IF_RXYa, F_390 | F_Z),
	INSTR(0x46, "bctg",   IF_RXYa, F_Z),
	INSTR(0x50, "sty",    IF_RXYa, F_Z),
	INSTR(0x51, "msy",    IF_RXYa, F_Z),
	INSTR(0x54, "ny",     IF_RXYa, F_Z),
	INSTR(0x55, "cly",    IF_RXYa, F_Z),
	INSTR(0x56, "oy",     IF_RXYa, F_Z),
	INSTR(0x57, "xy",     IF_RXYa, F_Z),
	INSTR(0x58, "ly",     IF_RXYa, F_Z),
	INSTR(0x59, "cy",     IF_RXYa, F_Z),
	INSTR(0x5a, "ay",     IF_RXYa, F_Z),
	INSTR(0x5b, "sy",     IF_RXYa, F_Z),
	INSTR(0x5c, "mfy",    IF_RXYa, F_Z),
	INSTR(0x5e, "aly",    IF_RXYa, F_Z),
	INSTR(0x5f, "sly",    IF_RXYa, F_Z),
	INSTR(0x70, "sthy",   IF_RXYa, F_Z),
	INSTR(0x71, "lay",    IF_RXYa, F_Z),
	INSTR(0x72, "stcy",   IF_RXYa, F_Z),
	INSTR(0x73, "icy",    IF_RXYa, F_Z),
	INSTR(0x75, "laey",   IF_RXYa, F_Z),
	INSTR(0x76, "lb",     IF_RXYa, F_Z),
	INSTR(0x77, "lgb",    IF_RXYa, F_Z),
	INSTR(0x78, "lhy",    IF_RXYa, F_Z),
	INSTR(0x79, "chy",    IF_RXYa, F_Z),
	INSTR(0x7a, "ahy",    IF_RXYa, F_Z),
	INSTR(0x7b, "shy",    IF_RXYa, F_Z),
	INSTR(0x7c, "mhy",    IF_RXYa, F_Z),
	INSTR(0x80, "ng",     IF_RXYa, F_Z),
	INSTR(0x81, "og",     IF_RXYa, F_Z),
	INSTR(0x82, "xg",     IF_RXYa, F_Z),
	INSTR(0x85, "lgat",   IF_RXYa, F_Z),
	INSTR(0x86, "mlg",    IF_RXYa, F_Z),
	INSTR(0x87, "dlg",    IF_RXYa, F_Z),
	INSTR(0x88, "alcg",   IF_RXYa, F_Z),
	INSTR(0x89, "slbg",   IF_RXYa, F_Z),
	INSTR(0x8e, "stpq",   IF_RXYa, F_Z),
	INSTR(0x8f, "lpq",    IF_RXYa, F_Z),
	INSTR(0x90, "llgc",   IF_RXYa, F_Z),
	INSTR(0x91, "llgh",   IF_RXYa, F_Z),
	INSTR(0x94, "llc",    IF_RXYa, F_Z),
	INSTR(0x95, "llh",    IF_RXYa, F_Z),
	INSTR(0x96, "ml",     IF_RXYa, F_390 | F_Z),
	INSTR(0x97, "dl",     IF_RXYa, F_390 | F_Z),
	INSTR(0x98, "alc",    IF_RXYa, F_390 | F_Z),
	INSTR(0x99, "slb",    IF_RXYa, F_390 | F_Z),
	INSTR(0x9c, "llgtat", IF_RXYa, F_Z),
	INSTR(0x9d, "llgfat", IF_RXYa, F_Z),
	INSTR(0x9f, "lat",    IF_RXYa, F_Z),
	INSTR(0xc0, "lbh",    IF_RXYa, F_Z),
	INSTR(0xc2, "llch",   IF_RXYa, F_Z),
	INSTR(0xc3, "stch",   IF_RXYa, F_Z),
	INSTR(0xc4, "lhh",    IF_RXYa, F_Z),
	INSTR(0xc6, "llhh",   IF_RXYa, F_Z),
	INSTR(0xc7, "sthh",   IF_RXYa, F_Z),
	INSTR(0xc8, "lfhat",  IF_RXYa, F_Z),
	INSTR(0xca, "lfh",    IF_RXYa, F_Z),
	INSTR(0xcb, "stfh",   IF_RXYa, F_Z),
	INSTR(0xcd, "chf",    IF_RXYa, F_Z),
	INSTR(0xcf, "clhf",   IF_RXYa, F_Z),
};

static const struct inst_table tbl_e5xx[256] = {
	INSTR(0x00, "lasp",    IF_SSE, F_390 | F_Z),
	INSTR(0x01, "tprot",   IF_SSE, F_390 | F_Z),
	INSTR(0x02, "strag",   IF_SSE, F_Z),
	INSTR(0x0e, "mvcsk",   IF_SSE, F_390 | F_Z),
	INSTR(0x0f, "mvcdk",   IF_SSE, F_390 | F_Z),
	INSTR(0x44, "mvhhi",   IF_SIL, F_Z),
	INSTR(0x48, "mvghi",   IF_SIL, F_Z),
	INSTR(0x4c, "mvhi",    IF_SIL, F_Z),
	INSTR(0x54, "chhsi",   IF_SIL, F_Z),
	INSTR(0x55, "clhhsi",  IF_SIL, F_Z),
	INSTR(0x58, "cghsi",   IF_SIL, F_Z),
	INSTR(0x59, "clghsi",  IF_SIL, F_Z),
	INSTR(0x5c, "chsi",    IF_SIL, F_Z),
	INSTR(0x5d, "clfhsi",  IF_SIL, F_Z),
	INSTR(0x60, "tbegin",  IF_SIL, F_Z),
	INSTR(0x61, "tbeginc", IF_SIL, F_Z),
};

static const struct inst_table tbl_ebxx[256] = {
	INSTR(0x04, "lmg",   IF_RSYa, F_Z),
	INSTR(0x0a, "srag",  IF_RSYa, F_Z),
	INSTR(0x0b, "slag",  IF_RSYa, F_Z),
	INSTR(0x0c, "srlg",  IF_RSYa, F_Z),
	INSTR(0x0d, "sllg",  IF_RSYa, F_Z),
	INSTR(0x0f, "tracg", IF_RSYa, F_Z),
	INSTR(0x14, "csy",   IF_RSYa, F_Z),
	INSTR(0x1c, "rllg",  IF_RSYa, F_Z),
	INSTR(0x1d, "rll",   IF_RSYa, F_390 | F_Z),
	INSTR(0x20, "clmh",  IF_RSYb, F_Z),
	INSTR(0x21, "clmy",  IF_RSYb, F_Z),
	INSTR(0x23, "clt",   IF_RSYb, F_Z),
	INSTR(0x24, "stmg",  IF_RSYa, F_Z),
	INSTR(0x25, "stctg", IF_RSYa, F_Z | F_CTL_REG),
	INSTR(0x26, "stmh",  IF_RSYa, F_Z),
	INSTR(0x2b, "clgt",  IF_RSYb, F_Z),
	INSTR(0x2c, "stcmh", IF_RSYb, F_Z),
	INSTR(0x2d, "stcmy", IF_RSYb, F_Z),
	INSTR(0x2f, "lctlg", IF_RSYa, F_Z | F_CTL_REG),
	INSTR(0x30, "csg",   IF_RSYa, F_Z),
	INSTR(0x31, "cdsy",  IF_RSYa, F_Z),
	INSTR(0x3e, "cdsg",  IF_RSYa, F_Z),
	INSTR(0x44, "bxhg",  IF_RSYa, F_Z),
	INSTR(0x45, "bxleg", IF_RSYa, F_Z),
	INSTR(0x4c, "ecag",  IF_RSYa, F_Z),
	INSTR(0x51, "tmy",   IF_SIY,  F_Z),
	INSTR(0x52, "mviy",  IF_SIY,  F_Z),
	INSTR(0x54, "niy",   IF_SIY,  F_Z),
	INSTR(0x55, "cliy",  IF_SIY,  F_Z),
	INSTR(0x56, "oiy",   IF_SIY,  F_Z),
	INSTR(0x57, "xiy",   IF_SIY,  F_Z),
	INSTR(0x6a, "asi",   IF_SIY,  F_Z),
	INSTR(0x6e, "alsi",  IF_SIY,  F_Z),
	INSTR(0x80, "icmh",  IF_RSYb, F_Z),
	INSTR(0x81, "icmy",  IF_RSYb, F_Z),
	INSTR(0x8e, "mvclu", IF_RSYa, F_390 | F_Z),
	INSTR(0x8f, "clclu", IF_RSYa, F_390 | F_Z),
	INSTR(0x90, "stmy",  IF_RSYa, F_Z),
	INSTR(0x96, "lmh",   IF_RSYa, F_Z),
	INSTR(0x98, "lmy",   IF_RSYa, F_Z),
	INSTR(0x9a, "lamy",  IF_RSYa, F_Z),
	INSTR(0x9b, "stamy", IF_RSYa, F_Z),
	INSTR(0xc0, "tp",    IF_RSLa, F_390 | F_Z),
	INSTR(0xdc, "srak",  IF_RSYa, F_Z),
	INSTR(0xdd, "slak",  IF_RSYa, F_Z),
	INSTR(0xde, "srlk",  IF_RSYa, F_Z),
	INSTR(0xdf, "sllk",  IF_RSYa, F_Z),
	INSTR(0xe2, "locg",  IF_RSYb, F_Z),
	INSTR(0xe3, "stocg", IF_RSYb, F_Z),
	INSTR(0xe4, "lang",  IF_RSYa, F_Z),
	INSTR(0xe6, "laog",  IF_RSYa, F_Z),
	INSTR(0xe7, "laxg",  IF_RSYa, F_Z),
	INSTR(0xe8, "laag",  IF_RSYa, F_Z),
	INSTR(0xea, "laalg", IF_RSYa, F_Z),
	INSTR(0xf2, "loc",   IF_RSYb, F_Z),
	INSTR(0xf3, "stoc",  IF_RSYb, F_Z),
	INSTR(0xf4, "lan",   IF_RSYa, F_Z),
	INSTR(0xf6, "lao",   IF_RSYa, F_Z),
	INSTR(0xf7, "lax",   IF_RSYa, F_Z),
	INSTR(0xf8, "laa",   IF_RSYa, F_Z),
	INSTR(0xfa, "laal",  IF_RSYa, F_Z),
};

static const struct inst_table tbl_ecxx[256] = {
	INSTR(0x44, "brxhg",   IF_RIEe, F_Z),
	INSTR(0x45, "brxlg",   IF_RIEe, F_Z),
	INSTR(0x51, "risblg",  IF_RIEf, F_Z),
	INSTR(0x54, "rnsbg",   IF_RIEf, F_Z),
	INSTR(0x55, "risbg",   IF_RIEf, F_Z),
	INSTR(0x56, "rosbg",   IF_RIEf, F_Z),
	INSTR(0x57, "rxsbg",   IF_RIEf, F_Z),
	INSTR(0x59, "risbgn",  IF_RIEf, F_Z),
	INSTR(0x5d, "risbhg",  IF_RIEf, F_Z),
	INSTR(0x64, "cgrj",    IF_RIEb, F_Z),
	INSTR(0x65, "clgrj",   IF_RIEb, F_Z),
	INSTR(0x70, "cgit",    IF_RIEa, F_Z),
	INSTR(0x71, "clgit",   IF_RIEa, F_Z),
	INSTR(0x72, "cit",     IF_RIEa, F_Z),
	INSTR(0x73, "clfit",   IF_RIEa, F_Z),
	INSTR(0x76, "crj",     IF_RIEb, F_Z),
	INSTR(0x77, "clrj",    IF_RIEb, F_Z),
	INSTR(0x7c, "cgij",    IF_RIEc, F_Z),
	INSTR(0x7d, "clgij",   IF_RIEc, F_Z),
	INSTR(0x7e, "cij",     IF_RIEc, F_Z),
	INSTR(0x7f, "clij",    IF_RIEc, F_Z),
	INSTR(0xd8, "ahik",    IF_RIEd, F_Z),
	INSTR(0xd9, "aghik",   IF_RIEd, F_Z),
	INSTR(0xda, "alhsik",  IF_RIEd, F_Z),
	INSTR(0xdb, "alghsik", IF_RIEd, F_Z),
	INSTR(0xe4, "cgrb",    IF_RRS,  F_Z),
	INSTR(0xe5, "clgrb",   IF_RRS,  F_Z),
	INSTR(0xf6, "crb",     IF_RRS,  F_Z),
	INSTR(0xf7, "clrb",    IF_RRS,  F_Z),
	INSTR(0xfc, "cgib",    IF_RIS,  F_Z),
	INSTR(0xfd, "clgib",   IF_RIS,  F_Z),
	INSTR(0xfe, "cib",     IF_RIS,  F_Z),
	INSTR(0xff, "clib",    IF_RIS,  F_Z),
};

static const struct inst_table tbl_edxx[256] = {
	INSTR(0x04, "ldeb",   IF_RXE,  F_390 | F_Z),
	INSTR(0x05, "lxdb",   IF_RXE,  F_390 | F_Z),
	INSTR(0x06, "lxeb",   IF_RXE,  F_390 | F_Z),
	INSTR(0x07, "mxdb",   IF_RXE,  F_390 | F_Z),
	INSTR(0x08, "keb",    IF_RXE,  F_390 | F_Z),
	INSTR(0x09, "ceb",    IF_RXE,  F_390 | F_Z),
	INSTR(0x0a, "aeb",    IF_RXE,  F_390 | F_Z),
	INSTR(0x0b, "seb",    IF_RXE,  F_390 | F_Z),
	INSTR(0x0c, "mdeb",   IF_RXE,  F_390 | F_Z),
	INSTR(0x0d, "deb",    IF_RXE,  F_390 | F_Z),
	INSTR(0x0e, "maeb",   IF_RXF,  F_390 | F_Z),
	INSTR(0x0f, "mseb",   IF_RXF,  F_390 | F_Z),
	INSTR(0x10, "tceb",   IF_RXE,  F_390 | F_Z),
	INSTR(0x11, "tcdb",   IF_RXE,  F_390 | F_Z),
	INSTR(0x12, "tcxb",   IF_RXE,  F_390 | F_Z),
	INSTR(0x14, "sqeb",   IF_RXE,  F_390 | F_Z),
	INSTR(0x15, "sqdb",   IF_RXE,  F_390 | F_Z),
	INSTR(0x17, "meeb",   IF_RXE,  F_390 | F_Z),
	INSTR(0x18, "kdb",    IF_RXE,  F_390 | F_Z),
	INSTR(0x19, "cdb",    IF_RXE,  F_390 | F_Z),
	INSTR(0x1a, "adb",    IF_RXE,  F_390 | F_Z),
	INSTR(0x1b, "sdb",    IF_RXE,  F_390 | F_Z),
	INSTR(0x1c, "mdb",    IF_RXE,  F_390 | F_Z),
	INSTR(0x1d, "ddb",    IF_RXE,  F_390 | F_Z),
	INSTR(0x1e, "madb",   IF_RXF,  F_390 | F_Z),
	INSTR(0x1f, "msdb",   IF_RXF,  F_390 | F_Z),
	INSTR(0x24, "lde",    IF_RXE,  F_390 | F_Z),
	INSTR(0x25, "lxd",    IF_RXE,  F_390 | F_Z),
	INSTR(0x26, "lxe",    IF_RXE,  F_390 | F_Z),
	INSTR(0x2e, "mae",    IF_RXF,  F_390 | F_Z),
	INSTR(0x2f, "mse",    IF_RXF,  F_390 | F_Z),
	INSTR(0x34, "sqe",    IF_RXE,  F_390 | F_Z),
	INSTR(0x35, "sqd",    IF_RXE,  F_390 | F_Z),
	INSTR(0x37, "mee",    IF_RXE,  F_390 | F_Z),
	INSTR(0x38, "mayl",   IF_RXF,  F_Z),
	INSTR(0x39, "myl",    IF_RXF,  F_Z),
	INSTR(0x3a, "may",    IF_RXF,  F_Z),
	INSTR(0x3b, "my",     IF_RXF,  F_Z),
	INSTR(0x3c, "mayh",   IF_RXF,  F_Z),
	INSTR(0x3d, "myh",    IF_RXF,  F_Z),
	INSTR(0x3e, "mad",    IF_RXF,  F_390 | F_Z),
	INSTR(0x3f, "msd",    IF_RXF,  F_390 | F_Z),
	INSTR(0x40, "sldt",   IF_RXF,  F_Z),
	INSTR(0x41, "srdt",   IF_RXF,  F_Z),
	INSTR(0x48, "slxt",   IF_RXF,  F_Z),
	INSTR(0x49, "srxt",   IF_RXF,  F_Z),
	INSTR(0x50, "tdcet",  IF_RXE,  F_Z),
	INSTR(0x51, "tdget",  IF_RXE,  F_Z),
	INSTR(0x54, "tdcdt",  IF_RXE,  F_Z),
	INSTR(0x55, "tdgdt",  IF_RXE,  F_Z),
	INSTR(0x58, "tdcxt",  IF_RXE,  F_Z),
	INSTR(0x59, "tdgxt",  IF_RXE,  F_Z),
	INSTR(0x64, "ley",    IF_RXYa, F_Z),
	INSTR(0x65, "ldy",    IF_RXYa, F_Z),
	INSTR(0x66, "stey",   IF_RXYa, F_Z),
	INSTR(0x67, "stdy",   IF_RXYa, F_Z),
	INSTR(0xa8, "czdt",   IF_RSLb, F_Z),
	INSTR(0xa9, "czxt",   IF_RSLb, F_Z),
	INSTR(0xaa, "cdzt",   IF_RSLb, F_Z),
	INSTR(0xab, "cxzt",   IF_RSLb, F_Z),
};

static const struct inst_table tbl_xx[256] = {
	INSTR(0x00, ".byte", IF_ZERO, F_370 | F_390 | F_Z),
	TABLE(0x01, tbl_01xx, 1, 0, 0xff),
	INSTR(0x04, "spm",   IF_RR,   F_370 | F_Z),
	INSTR(0x05, "balr",  IF_RR,   F_370 | F_Z),
	INSTR(0x06, "bctr",  IF_RR,   F_370 | F_Z),
	TABLE(0x07, tbl_07, 1, 4, 0x0f),
	INSTR(0x08, "ssk",   IF_RR,   F_370),
	INSTR(0x09, "isk",   IF_RR,   F_370),
	INSTR(0x0a, "svc",   IF_I,    F_370 | F_390 | F_Z),
	INSTR(0x0b, "bsm",   IF_RR,   F_390 | F_Z),
	INSTR(0x0c, "bassm", IF_RR,   F_390 | F_Z),
	INSTR(0x0d, "basr",  IF_RR,   F_390 | F_Z),
	INSTR(0x0e, "mvcl",  IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x0f, "clcl",  IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x10, "lpr",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x11, "lnr",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x12, "ltr",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x13, "lcr",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x14, "nr",    IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x15, "clr",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x16, "or",    IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x17, "xr",    IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x18, "lr",    IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x19, "cr",    IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x1a, "ar",    IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x1b, "sr",    IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x1c, "mr",    IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x1d, "dr",    IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x1e, "alr",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x1f, "slr",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x20, "lpdr",  IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x21, "lndr",  IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x22, "ltdr",  IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x23, "lcdr",  IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x24, "hdr",   IF_RR,   F_370 | F_390 | F_Z),
	MULTI(0x25, tbl_25),
	INSTR(0x26, "mxr",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x27, "mxdr",  IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x28, "ldr",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x29, "cdr",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x2a, "adr",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x2b, "sdr",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x2c, "mdr",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x2d, "ddr",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x2e, "awr",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x2f, "swr",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x30, "lper",  IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x31, "lner",  IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x32, "lter",  IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x33, "lcer",  IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x34, "her",   IF_RR,   F_370 | F_390 | F_Z),
	MULTI(0x35, tbl_35),
	INSTR(0x36, "axr",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x37, "sxr",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x38, "ler",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x39, "cer",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x3a, "aer",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x3b, "ser",   IF_RR,   F_370 | F_390 | F_Z),
	MULTI(0x3c, tbl_3c),
	INSTR(0x3d, "der",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x3e, "aur",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x3f, "sur",   IF_RR,   F_370 | F_390 | F_Z),
	INSTR(0x40, "sth",   IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x41, "la",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x42, "stc",   IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x43, "ic",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x44, "ex",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x45, "bal",   IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x46, "bct",   IF_RXa,  F_370 | F_390 | F_Z),
	TABLE(0x47, tbl_47, 1, 4, 0x0f),
	INSTR(0x48, "lh",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x49, "ch",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x4a, "ah",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x4b, "sh",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x4c, "mh",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x4d, "bas",   IF_RXa,  F_390 | F_Z),
	INSTR(0x4e, "cvd",   IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x4f, "cvb",   IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x50, "st",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x51, "lae",   IF_RXa,  F_390 | F_Z),
	INSTR(0x54, "n",     IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x55, "cl",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x56, "o",     IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x57, "x",     IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x58, "l",     IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x59, "c",     IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x5a, "a",     IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x5b, "s",     IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x5c, "m",     IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x5d, "d",     IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x5e, "al",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x5f, "sl",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x60, "std",   IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x67, "mxd",   IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x68, "ld",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x69, "cd",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x6a, "ad",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x6b, "sd",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x6c, "md",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x6d, "dd",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x6e, "aw",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x6f, "sw",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x70, "ste",   IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x71, "ms",    IF_RXa,  F_390 | F_Z),
	INSTR(0x78, "le",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x79, "ce",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x7a, "ae",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x7b, "se",    IF_RXa,  F_370 | F_390 | F_Z),
	MULTI(0x7c, tbl_7c),
	INSTR(0x7d, "de",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x7e, "au",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x7f, "su",    IF_RXa,  F_370 | F_390 | F_Z),
	INSTR(0x80, "ssm",   IF_S,    F_370 | F_390 | F_Z),
	INSTR(0x82, "lpsw",  IF_S,    F_370 | F_390 | F_Z),
	INSTR(0x83, "diag",  IF_DIAG, F_370 | F_390 | F_Z),
	MULTI(0x84, tbl_84),
	MULTI(0x85, tbl_85),
	INSTR(0x86, "bxh",   IF_RSa,  F_370 | F_390 | F_Z),
	INSTR(0x87, "bxle",  IF_RSa,  F_370 | F_390 | F_Z),
	INSTR(0x88, "srl",   IF_RSa,  F_370 | F_390 | F_Z),
	INSTR(0x89, "sll",   IF_RSa,  F_370 | F_390 | F_Z),
	INSTR(0x8a, "sra",   IF_RSa,  F_370 | F_390 | F_Z),
	INSTR(0x8b, "sla",   IF_RSa,  F_370 | F_390 | F_Z),
	INSTR(0x8c, "srdl",  IF_RSa,  F_370 | F_390 | F_Z),
	INSTR(0x8d, "sldl",  IF_RSa,  F_370 | F_390 | F_Z),
	INSTR(0x8e, "srda",  IF_RSa,  F_370 | F_390 | F_Z),
	INSTR(0x8f, "slda",  IF_RSa,  F_370 | F_390 | F_Z),
	INSTR(0x90, "stm",   IF_RSa,  F_370 | F_390 | F_Z),
	INSTR(0x91, "tm",    IF_SI,   F_370 | F_390 | F_Z),
	INSTR(0x92, "mvi",   IF_SI,   F_370 | F_390 | F_Z),
	INSTR(0x93, "ts",    IF_S,    F_370 | F_390 | F_Z),
	INSTR(0x94, "ni",    IF_SI,   F_370 | F_390 | F_Z),
	INSTR(0x95, "cli",   IF_SI,   F_370 | F_390 | F_Z),
	INSTR(0x96, "oi",    IF_SI,   F_370 | F_390 | F_Z),
	INSTR(0x97, "xi",    IF_SI,   F_370 | F_390 | F_Z),
	INSTR(0x98, "lm",    IF_RSa,  F_370 | F_390 | F_Z),
	INSTR(0x99, "trace", IF_RSa,  F_390 | F_Z),
	INSTR(0x9a, "lam",   IF_RSa,  F_390 | F_Z),
	INSTR(0x9b, "stam",  IF_RSa,  F_390 | F_Z),
	TABLE(0xa5, tbl_a5x, 1, 0, 0x0f),
	TABLE(0xa7, tbl_a7x, 1, 0, 0x0f),
	INSTR(0xa8, "mvcle", IF_RSa,  F_390 | F_Z),
	INSTR(0xa9, "clcle", IF_RSa,  F_390 | F_Z),
	INSTR(0xac, "stnsm", IF_SI,   F_370 | F_390 | F_Z),
	INSTR(0xad, "stosm", IF_SI,   F_370 | F_390 | F_Z),
	INSTR(0xae, "sigp",  IF_RSa,  F_370 | F_390 | F_Z),
	INSTR(0xaf, "mc",    IF_SI,   F_370 | F_390 | F_Z),
	INSTR(0xb1, "lra",   IF_RXa,  F_370 | F_390 | F_Z),
	TABLE(0xb2, tbl_b2xx, 1, 0, 0xff),
	TABLE(0xb3, tbl_b3xx, 1, 0, 0xff),
	INSTR(0xb6, "stctl", IF_RSa,  F_370 | F_390 | F_Z | F_CTL_REG),
	INSTR(0xb7, "lctl",  IF_RSa,  F_370 | F_390 | F_Z | F_CTL_REG),
	TABLE(0xb9, tbl_b9xx, 1, 0, 0xff),
	INSTR(0xba, "cs",    IF_RSa,  F_370 | F_390 | F_Z),
	INSTR(0xbb, "cds",   IF_RSa,  F_370 | F_390 | F_Z),
	INSTR(0xbd, "clm",   IF_RSb,  F_370 | F_390 | F_Z),
	INSTR(0xbe, "stcm",  IF_RSb,  F_370 | F_390 | F_Z),
	INSTR(0xbf, "icm",   IF_RSb,  F_370 | F_390 | F_Z),
	TABLE(0xc0, tbl_c0x, 1, 0, 0x0f),
	TABLE(0xc2, tbl_c2x, 1, 0, 0x0f),
	TABLE(0xc4, tbl_c4x, 1, 0, 0x0f),
	INSTR(0xc5, "bprp",  IF_MII,  F_Z),
	TABLE(0xc6, tbl_c6x, 1, 0, 0x0f),
	INSTR(0xc7, "bpp",   IF_SMI,  F_Z),
	TABLE(0xc8, tbl_c8x, 1, 0, 0x0f),
	TABLE(0xcc, tbl_ccx, 1, 0, 0x0f),
	INSTR(0xd0, "trtr",  IF_SSa,  F_Z),
	INSTR(0xd1, "mvn",   IF_SSa,  F_370 | F_390 | F_Z),
	INSTR(0xd2, "mvc",   IF_SSa,  F_370 | F_390 | F_Z),
	INSTR(0xd3, "mvz",   IF_SSa,  F_370 | F_390 | F_Z),
	INSTR(0xd4, "nc",    IF_SSa,  F_370 | F_390 | F_Z),
	INSTR(0xd5, "clc",   IF_SSa,  F_370 | F_390 | F_Z),
	INSTR(0xd6, "oc",    IF_SSa,  F_370 | F_390 | F_Z),
	INSTR(0xd7, "xc",    IF_SSa,  F_370 | F_390 | F_Z),
	INSTR(0xd9, "mvck",  IF_SSd,  F_390 | F_Z),
	INSTR(0xda, "mvcp",  IF_SSd,  F_390 | F_Z),
	INSTR(0xdb, "mvcs",  IF_SSd,  F_390 | F_Z),
	INSTR(0xdc, "tr",    IF_SSa,  F_370 | F_390 | F_Z),
	INSTR(0xdd, "trt",   IF_SSa,  F_370 | F_390 | F_Z),
	INSTR(0xde, "ed",    IF_SSa,  F_370 | F_390 | F_Z),
	INSTR(0xdf, "edmk",  IF_SSa,  F_370 | F_390 | F_Z),
	INSTR(0xe1, "pku",   IF_SSf,  F_390 | F_Z),
	INSTR(0xe2, "unpku", IF_SSa,  F_390 | F_Z),
	TABLE(0xe3, tbl_e3xx, 5, 0, 0xff),
	TABLE(0xe5, tbl_e5xx, 1, 0, 0xff),
	INSTR(0xe8, "mvcin", IF_SSa,  F_390 | F_Z),
	INSTR(0xe9, "pka",   IF_SSf,  F_390 | F_Z),
	INSTR(0xea, "unpka", IF_SSa,  F_390 | F_Z),
	TABLE(0xeb, tbl_ebxx, 5, 0, 0xff),
	TABLE(0xec, tbl_ecxx, 5, 0, 0xff),
	TABLE(0xed, tbl_edxx, 5, 0, 0xff),
	INSTR(0xee, "plo",   IF_SSe,  F_390 | F_Z),
	INSTR(0xef, "lmd",   IF_SSe,  F_Z),
	INSTR(0xf0, "srp",   IF_SSc,  F_370 | F_390 | F_Z),
	INSTR(0xf1, "mvo",   IF_SSb,  F_370 | F_390 | F_Z),
	INSTR(0xf2, "pack",  IF_SSb,  F_370 | F_390 | F_Z),
	INSTR(0xf3, "unpk",  IF_SSb,  F_370 | F_390 | F_Z),
	INSTR(0xf8, "zap",   IF_SSb,  F_370 | F_390 | F_Z),
	INSTR(0xf9, "cp",    IF_SSb,  F_370 | F_390 | F_Z),
	INSTR(0xfa, "ap",    IF_SSb,  F_370 | F_390 | F_Z),
	INSTR(0xfb, "sp",    IF_SSb,  F_370 | F_390 | F_Z),
	INSTR(0xfc, "mp",    IF_SSb,  F_370 | F_390 | F_Z),
	INSTR(0xfd, "dp",    IF_SSb,  F_370 | F_390 | F_Z),
};
/* END CSTYLED */

/* how masks are printed */
static const char *M[16] = {
	"0",  "1",  "2",  "3",  "4",  "5",  "6",  "7",
	"8",  "9", "10", "11", "12", "13", "14", "15",
};

/* how general purpose regs are printed */
static const char *R[16] = {
	"%r0",  "%r1",  "%r2",  "%r3",  "%r4",  "%r5",  "%r6",  "%r7",
	"%r8",  "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15",
};

/* how control regs are printed */
static const char *C[16] = {
	"%c0",  "%c1",  "%c2",  "%c3",  "%c4",  "%c5",  "%c6",  "%c7",
	"%c8",  "%c9", "%c10", "%c11", "%c12", "%c13", "%c14", "%c15",
};

/* B and X registers are still registers - print them the same way */
#define	B	R
#define	X	R

static inline uint32_t
val_8_4_8(uint32_t hi, uint32_t mid, uint32_t lo)
{
	ASSERT0(hi & ~0xff);
	ASSERT0(mid & ~0xf);
	ASSERT0(lo & ~0xff);
	return ((hi << 12) | (mid << 8) | lo);
}

static inline uint32_t
val_16_16(uint32_t hi, uint32_t lo)
{
	ASSERT0(hi & ~0xffff);
	ASSERT0(lo & ~0xffff);
	return ((BE_16(hi) << 16) | BE_16(lo));
}

static inline int32_t
sval_16_16(uint32_t hi, uint32_t lo)
{
	return (val_16_16(hi, lo));
}

static inline uint32_t
val_8_16(uint32_t hi, uint32_t lo)
{
	ASSERT0(hi & ~0xff);
	ASSERT0(lo & ~0xffff);
	return ((hi << 16) | BE_16(lo));
}

static inline int32_t
sval_8_16(uint32_t hi, uint32_t lo)
{
	int32_t tmp = val_8_16(hi, lo);

	/* sign extend */
	if (tmp & 0x00800000)
		return (0xff000000 | tmp);
	return (tmp);
}

static inline uint32_t
val_4_8(uint32_t hi, uint32_t lo)
{
	ASSERT0(hi & ~0xf);
	ASSERT0(lo & ~0xff);
	return ((hi << 8) | lo);
}

static inline int32_t
sval_4_8(uint32_t hi, uint32_t lo)
{
	uint32_t tmp = val_4_8(hi, lo);

	/* sign extend */
	if (tmp & 0x800)
		return (0xfffff000 | tmp);
	return (tmp);
}

/* ARGSUSED */
static void
fmt_zero(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "0x00, 0x00");
}

/* ARGSUSED */
static void
fmt_diag(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%#x",
	    val_8_16(inst->diag.par1, inst->diag.par2));
}

/* ARGSUSED */
static void
fmt_e(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	/* nothing to do */
}

/* ARGSUSED */
static void
fmt_i(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%#x", inst->i.i);
}

/* ARGSUSED */
static void
fmt_ie(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%u,%u", inst->ie.i1, inst->ie.i2);
}

/* ARGSUSED */
static void
fmt_mii(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint64_t ri2 = addr + 2 * sval_4_8(inst->mii.ri2h, inst->mii.ri2l);
	uint64_t ri3 = addr + 2 * sval_8_16(inst->mii.ri3h, inst->mii.ri3l);

	(void) snprintf(buf, buflen, "%s,%#x,%#x", M[inst->mii.m1], ri2, ri3);
}

/* ARGSUSED */
static void
fmt_ril_a(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%s,%u", R[inst->ril_a.r1],
	    val_16_16(inst->ril_a.i2h, inst->ril_a.i2l));
}

/* ARGSUSED */
static void
fmt_ril_b(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint64_t ri2 = addr + 2 *
	    sval_16_16(inst->ril_b.ri2h, inst->ril_b.ri2l);

	(void) snprintf(buf, buflen, "%s,%#x", R[inst->ril_b.r1], ri2);
}

/* ARGSUSED */
static void
fmt_ril_c(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint64_t ri2 = addr + 2 *
	    sval_16_16(inst->ril_c.ri2h, inst->ril_c.ri2l);

	(void) snprintf(buf, buflen, "%s,%#x", M[inst->ril_c.m1], ri2);
}

/* ARGSUSED */
static void
fmt_ris(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint32_t d4 = val_4_8(inst->ris.d4h, inst->ris.d4l);

	(void) snprintf(buf, buflen, "%s,%u,%s,%u(%s)",
	    R[inst->ris.r1], inst->ris.i2, M[inst->ris.m3], d4,
	    B[inst->ris.b4]);
}

/* ARGSUSED */
static void
fmt_ri_a(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint16_t i2 = BE_16(inst->ri_a.i2);

	if (flags & F_SIGNED_IMM)
		(void) snprintf(buf, buflen, "%s,%d", R[inst->ri_a.r1],
		    (int16_t)i2);
	else
		(void) snprintf(buf, buflen, "%s,%u", R[inst->ri_a.r1],
		    i2);
}

/* ARGSUSED */
static void
fmt_ri_b(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint64_t ri2 = addr + 2 * (int16_t)BE_16(inst->ri_b.ri2);

	(void) snprintf(buf, buflen, "%s,%#x", R[inst->ri_b.r1], ri2);
}

static void
fmt_ri_c(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint64_t ri2 = addr + 2 * (int16_t)BE_16(inst->ri_c.ri2);

	if (flags & F_HIDE_MASK)
		(void) snprintf(buf, buflen, "%#x", ri2);
	else
		(void) snprintf(buf, buflen, "%s,%#x", M[inst->ri_c.m1], ri2);
}

/* ARGSUSED */
static void
fmt_rie_a(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%s,%u,%s", R[inst->rie_a.r1],
	    BE_16(inst->rie_a.i2), M[inst->rie_a.m3]);
}

/* ARGSUSED */
static void
fmt_rie_b(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint64_t ri4 = addr + 2 * (int16_t)BE_16(inst->rie_b.ri4);

	(void) snprintf(buf, buflen, "%s,%s,%s,%#x", R[inst->rie_b.r1],
	    R[inst->rie_b.r2], M[inst->rie_b.m3], ri4);
}

/* ARGSUSED */
static void
fmt_rie_c(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint64_t ri4 = addr + 2 * (int16_t)BE_16(inst->rie_c.ri4);

	(void) snprintf(buf, buflen, "%s,%u,%s,%#x", R[inst->rie_c.r1],
	    inst->rie_c.i2, M[inst->rie_c.m3], ri4);
}

/* ARGSUSED */
static void
fmt_rie_d(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%s,%s,%u", R[inst->rie_d.r1],
	    R[inst->rie_d.r3], BE_16(inst->rie_d.i2));
}

/* ARGSUSED */
static void
fmt_rie_e(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint64_t ri2 = addr + 2 * (int16_t)BE_16(inst->rie_e.ri2);

	(void) snprintf(buf, buflen, "%s,%s,%#x", R[inst->rie_e.r1],
	    R[inst->rie_e.r3], ri2);
}

/* ARGSUSED */
static void
fmt_rie_f(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%s,%s,%u,%u,%u", R[inst->rie_f.r1],
	    R[inst->rie_f.r2], inst->rie_f.i3, inst->rie_f.i4,
	    inst->rie_f.i5);
}

/* ARGSUSED */
static void
fmt_rre(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%s,%s", R[inst->rre.r1], R[inst->rre.r2]);
}

/* ARGSUSED */
static void
fmt_rrf_a(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%s,%s,%s",
	    R[inst->rrf_ab.r1], R[inst->rrf_ab.r2], R[inst->rrf_ab.r3]);
}

/* ARGSUSED */
static void
fmt_rrf_b(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%s,%s,%s",
	    R[inst->rrf_ab.r1], R[inst->rrf_ab.r3], R[inst->rrf_ab.r2]);
}

/* ARGSUSED */
static void
fmt_rrf_c(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%s,%s,%s",
	    R[inst->rrf_cde.r1], R[inst->rrf_cde.r2], M[inst->rrf_cde.m3]);
}

/* ARGSUSED */
static void
fmt_rrf_d(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%s,%s,%s",
	    R[inst->rrf_cde.r1], R[inst->rrf_cde.r2], M[inst->rrf_cde.m4]);
}

/* ARGSUSED */
static void
fmt_rrf_e(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%s,%s,%s,%s",
	    R[inst->rrf_cde.r1], M[inst->rrf_cde.m3],
	    R[inst->rrf_cde.r2], M[inst->rrf_cde.m4]);
}

/* ARGSUSED */
static void
fmt_rrs(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%s,%s,%s,%u(%s)", R[inst->rrs.r1],
	    R[inst->rrs.r2], M[inst->rrs.m3],
	    val_4_8(inst->rrs.d4h, inst->rrs.d4l), B[inst->rrs.b4]);
}

/* ARGSUSED */
static void
fmt_rr(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	/* a branch uses r1 as a mask */
	if (flags & F_HIDE_MASK)
		(void) snprintf(buf, buflen, "%s", R[inst->rr.r2]);
	else if (flags & F_R1_IS_MASK)
		(void) snprintf(buf, buflen, "%s,%s", M[inst->rr.r1],
		    R[inst->rr.r2]);
	else
		(void) snprintf(buf, buflen, "%s,%s", R[inst->rr.r1],
		    R[inst->rr.r2]);
}

/* ARGSUSED */
static void
fmt_rrd(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%s,%s,%s", R[inst->rrd.r1],
	    R[inst->rrd.r3], R[inst->rrd.r2]);
}

/* ARGSUSED */
static void
fmt_rx_a(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint32_t d2 = val_4_8(inst->rx_a.d2h, inst->rx_b.d2l);

	(void) snprintf(buf, buflen, "%s,%u(%s,%s)", R[inst->rx_a.r1],
	    d2, X[inst->rx_a.x2], B[inst->rx_a.b2]);
}

/* ARGSUSED */
static void
fmt_rx_b(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint32_t d2 = val_4_8(inst->rx_b.d2h, inst->rx_b.d2l);

	if (flags & F_HIDE_MASK)
		(void) snprintf(buf, buflen, "%u(%s,%s)",
		    d2, X[inst->rx_b.x2], B[inst->rx_b.b2]);
	else
		(void) snprintf(buf, buflen, "%s,%u(%s,%s)", M[inst->rx_b.m1],
		    d2, X[inst->rx_b.x2], B[inst->rx_b.b2]);
}

/* ARGSUSED */
static void
fmt_rxe(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint32_t d2 = val_4_8(inst->rxe.d2h, inst->rxe.d2l);

	(void) snprintf(buf, buflen, "%s,%u(%s,%s)",
	    R[inst->rxe.r1], d2, X[inst->rxe.x2], B[inst->rxe.b2]);
}

/* ARGSUSED */
static void
fmt_rxf(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint32_t d2 = val_4_8(inst->rxf.d2h, inst->rxf.d2l);

	(void) snprintf(buf, buflen, "%s,%s,%u(%s,%s)",
	    R[inst->rxf.r1], R[inst->rxf.r3], d2, X[inst->rxf.x2],
	    B[inst->rxf.b2]);
}

/* ARGSUSED */
static void
fmt_rxy_a(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint32_t d2;

	d2 = val_8_4_8(inst->rxy_a.dh2, inst->rxy_a.dl2h, inst->rxy_a.dl2l);

	(void) snprintf(buf, buflen, "%s,%u(%s,%s)",
	    R[inst->rxy_a.r1], d2, X[inst->rxy_a.x2], B[inst->rxy_a.b2]);
}

/* ARGSUSED */
static void
fmt_rxy_b(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint32_t d2;

	d2 = val_8_4_8(inst->rxy_b.dh2, inst->rxy_b.dl2h, inst->rxy_b.dl2l);

	(void) snprintf(buf, buflen, "%s,%u(%s,%s)",
	    M[inst->rxy_b.m1], d2, X[inst->rxy_b.x2], B[inst->rxy_b.b2]);
}

/* ARGSUSED */
static void
fmt_rs_a(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	const char *r1, *r3;

	if (flags & F_CTL_REG) {
		r1 = C[inst->rs_a.r1];
		r3 = C[inst->rs_a.r3];
	} else {
		r1 = R[inst->rs_a.r1];
		r3 = R[inst->rs_a.r3];
	}

	(void) snprintf(buf, buflen, "%s,%s,%u(%s)", r1, r3,
	    val_4_8(inst->rs_a.d2h, inst->rs_a.d2l), B[inst->rs_a.b2]);
}

/* ARGSUSED */
static void
fmt_rs_b(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%s,%s,%u(%s)", R[inst->rs_b.r1],
	    M[inst->rs_b.m3], val_4_8(inst->rs_b.d2h, inst->rs_b.d2l),
	    B[inst->rs_b.b2]);
}

/* ARGSUSED */
static void
fmt_rsl_a(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%u(%u,%s)",
	    val_4_8(inst->rsl_a.d1h, inst->rsl_a.d1l), inst->rsl_a.l1,
	    B[inst->rsl_a.b1]);
}

/* ARGSUSED */
static void
fmt_rsl_b(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%s,%u(%u,%s),%s",
	    R[inst->rsl_b.r1],
	    val_4_8(inst->rsl_b.d2h, inst->rsl_b.d2l), inst->rsl_b.l2,
	    B[inst->rsl_b.b2], M[inst->rsl_b.m3]);
}

/* ARGSUSED */
static void
fmt_rsy_a(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	const char *r1, *r3;
	uint32_t d2;

	d2 = val_8_4_8(inst->rsy_a.dh2, inst->rsy_a.dl2h, inst->rsy_a.dl2l);

	if (flags & F_CTL_REG) {
		r1 = C[inst->rsy_a.r1];
		r3 = C[inst->rsy_a.r3];
	} else {
		r1 = R[inst->rsy_a.r1];
		r3 = R[inst->rsy_a.r3];
	}

	(void) snprintf(buf, buflen, "%s,%s,%u(%s)", r1, r3, d2,
	    B[inst->rsy_a.b2]);
}

/* ARGSUSED */
static void
fmt_rsy_b(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint32_t d2;

	d2 = val_8_4_8(inst->rsy_b.dh2, inst->rsy_b.dl2h, inst->rsy_b.dl2l);

	(void) snprintf(buf, buflen, "%s,%s,%u(%s)",
	    R[inst->rsy_b.r1], M[inst->rsy_b.m3],
	    d2, B[inst->rsy_b.b2]);
}

/* ARGSUSED */
static void
fmt_rsi(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint64_t ri2 = addr + 2 * (int16_t)BE_16(inst->rsi.ri2);

	(void) snprintf(buf, buflen, "%s,%s,%#x", R[inst->rsi.r1],
	    R[inst->rsi.r3], ri2);
}

/* ARGSUSED */
static void
fmt_si(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint32_t d1 = val_4_8(inst->si.d1h, inst->si.d1l);

	(void) snprintf(buf, buflen, "%u(%s),%u", d1, B[inst->si.b1],
	    inst->si.i2);
}

/* ARGSUSED */
static void
fmt_sil(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%u(%s),%u",
	    val_4_8(inst->sil.d1h, inst->sil.d1l), B[inst->sil.b1],
	    BE_16(inst->sil.i2));
}

/* ARGSUSED */
static void
fmt_siy(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	(void) snprintf(buf, buflen, "%u(%s),%u",
	    val_8_4_8(inst->siy.dh1, inst->siy.dl1h, inst->siy.dl1l),
	    B[inst->siy.b1], inst->siy.i2);
}

/* ARGSUSED */
static void
fmt_smi(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint64_t ri2 = addr + 2 * (int16_t)BE_16(inst->smi.ri2);

	(void) snprintf(buf, buflen, "%s,%#x,%u(%s)", M[inst->smi.m1], ri2,
	    val_4_8(inst->smi.d3h, inst->smi.d3l), B[inst->smi.b3]);
}

/* ARGSUSED */
static void
fmt_s(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint32_t d = val_4_8(inst->s.d2h, inst->s.d2l);

	(void) snprintf(buf, buflen, "%u(%s)", d, B[inst->s.b2]);
}

/* ARGSUSED */
static void
fmt_ss_a(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint32_t d1, d2;

	d1 = val_4_8(inst->ss_a.d1h, inst->ss_a.d1l);
	d2 = val_4_8(inst->ss_a.d2h, inst->ss_a.d2l);

	(void) snprintf(buf, buflen, "%u(%u,%s),%u(%s)",
	    d1, inst->ss_a.l + 1, B[inst->ss_a.b1],
	    d2, B[inst->ss_a.b2]);
}

/* ARGSUSED */
static void
fmt_ss_b(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint32_t d1, d2;

	d1 = val_4_8(inst->ss_b.d1h, inst->ss_b.d1l);
	d2 = val_4_8(inst->ss_b.d2h, inst->ss_b.d2l);

	(void) snprintf(buf, buflen, "%u(%u,%s),%u(%u,%s)",
	    d1, inst->ss_b.l1 + 1, B[inst->ss_b.b1],
	    d2, inst->ss_b.l2 + 1, B[inst->ss_b.b2]);
}

/* ARGSUSED */
static void
fmt_ss_c(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint32_t d1, d2;

	d1 = val_4_8(inst->ss_c.d1h, inst->ss_c.d1l);
	d2 = val_4_8(inst->ss_c.d2h, inst->ss_c.d2l);

	(void) snprintf(buf, buflen, "%u(%u,%s),%u(%s),%u",
	    d1, inst->ss_c.l1, B[inst->ss_c.b1],
	    d2, B[inst->ss_c.b2], inst->ss_c.i3);
}

/* ARGSUSED */
static void
fmt_ss_d(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint32_t d1, d2;

	d1 = val_4_8(inst->ss_d.d1h, inst->ss_d.d1l);
	d2 = val_4_8(inst->ss_d.d2h, inst->ss_d.d2l);

	(void) snprintf(buf, buflen, "%u(%s,%s),%u(%s),%s",
	    d1, R[inst->ss_d.r1], B[inst->ss_d.b1],
	    d2, B[inst->ss_d.b2], R[inst->ss_d.r3]);
}

/* ARGSUSED */
static void
fmt_ss_e(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint32_t d2, d4;

	d2 = val_4_8(inst->ss_e.d2h, inst->ss_e.d2l);
	d4 = val_4_8(inst->ss_e.d4h, inst->ss_e.d4l);

	(void) snprintf(buf, buflen, "%s,%u(%s),%s,%u(%s)",
	    R[inst->ss_e.r1], d2, B[inst->ss_e.b2],
	    R[inst->ss_e.r3], d4, B[inst->ss_e.b4]);
}

/* ARGSUSED */
static void
fmt_ss_f(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint32_t d1, d2;

	d1 = val_4_8(inst->ss_f.d1h, inst->ss_f.d1l);
	d2 = val_4_8(inst->ss_f.d2h, inst->ss_f.d2l);

	(void) snprintf(buf, buflen, "%u(%s),%u(%u,%s)",
	    d1, B[inst->ss_f.b1], d2, inst->ss_f.l2,
	    B[inst->ss_f.b2]);
}

/* ARGSUSED */
static void
fmt_sse(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint32_t d1 = val_4_8(inst->sse.d1h, inst->sse.d1l);
	uint32_t d2 = val_4_8(inst->sse.d2h, inst->sse.d2l);

	(void) snprintf(buf, buflen, "%u(%s),%u(%s)",
	    d1, B[inst->sse.b1], d2, B[inst->sse.b2]);
}

/* ARGSUSED */
static void
fmt_ssf(uint64_t addr, union inst *inst, char *buf, size_t buflen, int flags)
{
	uint32_t d1 = val_4_8(inst->ssf.d1h, inst->ssf.d1l);
	uint32_t d2 = val_4_8(inst->ssf.d2h, inst->ssf.d2l);

	(void) snprintf(buf, buflen, "%u(%s),%u(%s),%s",
	    d1, B[inst->ssf.b1],
	    d2, B[inst->ssf.b2], R[inst->ssf.r3]);
}

static void (*fmt_fxns[IF_NFMTS])(uint64_t, union inst *, char *, size_t,
    int) = {
	[IF_ZERO]	= fmt_zero,
	[IF_DIAG]	= fmt_diag,
	[IF_E]		= fmt_e,
	[IF_I]		= fmt_i,
	[IF_IE]		= fmt_ie,
	[IF_MII]	= fmt_mii,
	[IF_RIa]	= fmt_ri_a,
	[IF_RIb]	= fmt_ri_b,
	[IF_RIc]	= fmt_ri_c,
	[IF_RIEa]	= fmt_rie_a,
	[IF_RIEb]	= fmt_rie_b,
	[IF_RIEc]	= fmt_rie_c,
	[IF_RIEd]	= fmt_rie_d,
	[IF_RIEe]	= fmt_rie_e,
	[IF_RIEf]	= fmt_rie_f,
	[IF_RILa]	= fmt_ril_a,
	[IF_RILb]	= fmt_ril_b,
	[IF_RILc]	= fmt_ril_c,
	[IF_RIS]	= fmt_ris,
	[IF_RR]		= fmt_rr,
	[IF_RRD]	= fmt_rrd,
	[IF_RRE]	= fmt_rre,
	[IF_RRFa]	= fmt_rrf_a,
	[IF_RRFb]	= fmt_rrf_b,
	[IF_RRFc]	= fmt_rrf_c,
	[IF_RRFd]	= fmt_rrf_d,
	[IF_RRFe]	= fmt_rrf_e,
	[IF_RRS]	= fmt_rrs,
	[IF_RSa]	= fmt_rs_a,
	[IF_RSb]	= fmt_rs_b,
	[IF_RSI]	= fmt_rsi,
	[IF_RSLa]	= fmt_rsl_a,
	[IF_RSLb]	= fmt_rsl_b,
	[IF_RSYa]	= fmt_rsy_a,
	[IF_RSYb]	= fmt_rsy_b,
	[IF_RXa]	= fmt_rx_a,
	[IF_RXb]	= fmt_rx_b,
	[IF_RXE]	= fmt_rxe,
	[IF_RXF]	= fmt_rxf,
	[IF_RXYa]	= fmt_rxy_a,
	[IF_RXYb]	= fmt_rxy_b,
	[IF_S]		= fmt_s,
	[IF_SI]		= fmt_si,
	[IF_SIL]	= fmt_sil,
	[IF_SIY]	= fmt_siy,
	[IF_SMI]	= fmt_smi,
	[IF_SSa]	= fmt_ss_a,
	[IF_SSb]	= fmt_ss_b,
	[IF_SSc]	= fmt_ss_c,
	[IF_SSd]	= fmt_ss_d,
	[IF_SSe]	= fmt_ss_e,
	[IF_SSf]	= fmt_ss_f,
	[IF_SSE]	= fmt_sse,
	[IF_SSF]	= fmt_ssf,
};

/*
 * Even if we don't know how to disassemble the instruction, we know how long
 * it is, so we always succeed.  That is why we can get away with returning
 * void.
 */
static void
dis_s390(uint64_t addr, union inst *inst, char *buf, size_t buflen, int mach)
{
	const struct inst_table *tbl = &tbl_xx[inst->raw[0]];
	int tmp;

	/* nothing to do */
	if (buflen == 0)
		return;

	while (tbl->it_fmt == IF_TBL || tbl->it_fmt == IF_MULTI) {
		if (tbl->it_fmt == IF_TBL) {
			int idx;

			idx   = inst->raw[tbl->it_u.it_table.it_off];
			idx >>= tbl->it_u.it_table.it_shift;
			idx  &= tbl->it_u.it_table.it_mask;

			tbl = &tbl->it_u.it_table.it_ptr[idx];
		} else if (tbl->it_fmt == IF_MULTI) {
			tbl = &tbl->it_u.it_multi.it_ptr[mach];
		}
	}

	if (tbl->it_fmt == IF_INVAL)
		goto inval;

	if ((tbl->it_u.it_inst.it_flags & mach) == 0)
		goto inval;

	tmp = snprintf(buf, buflen, "%-7s ", tbl->it_u.it_inst.it_name);
	if (tmp < 0)
		return;

	fmt_fxns[tbl->it_fmt](addr, inst, buf + tmp, buflen - tmp,
	    tbl->it_u.it_inst.it_flags);

	return;

inval:
	(void) snprintf(buf, buflen, "??");
}

static int
dis_s390_supports_flags(int flags)
{
	int archflags = flags & DIS_ARCH_MASK;

	if (archflags == DIS_S370 || archflags == DIS_S390_31 ||
	    archflags == DIS_S390_64)
		return (1);

	return (0);
}

static int
dis_s390_disassemble(dis_handle_t *dhp, uint64_t addr, char *buf,
    size_t buflen)
{
	union inst inst;
	int mach;
	int len;

	if (dhp->dh_read(dhp->dh_data, addr, &inst.raw[0], 2) != 2)
		return (-1);

	len = ILC2LEN(inst.raw[0] >> 6) - 2;

	if (len > 0 &&
	    dhp->dh_read(dhp->dh_data, addr + 2, &inst.raw[2], len) != len)
			return (-1);

	switch (dhp->dh_flags & (DIS_S370 | DIS_S390_31 | DIS_S390_64)) {
		case DIS_S370:
			mach = F_370;
			break;
		case DIS_S390_31:
			mach = F_390;
			break;
		case DIS_S390_64:
			mach = F_Z;
			break;
	}

	dis_s390(addr, &inst, buf, buflen, mach);

	return (0);
}

/* ARGSUSED */
static int
dis_s390_min_instrlen(dis_handle_t *dhp)
{
	return (2);
}

/* ARGSUSED */
static int
dis_s390_max_instrlen(dis_handle_t *dhp)
{
	return (6);
}

dis_arch_t dis_arch_s390 = {
	.da_supports_flags	= dis_s390_supports_flags,
	.da_disassemble		= dis_s390_disassemble,
	.da_min_instrlen	= dis_s390_min_instrlen,
	.da_max_instrlen	= dis_s390_max_instrlen,
};
