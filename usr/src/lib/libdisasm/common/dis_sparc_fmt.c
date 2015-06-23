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
 * Copyright 2009 Jason King.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Joshua M. Clulow <josh@sysmgr.org>
 */


#include <sys/byteorder.h>
#include <stdarg.h>

#if !defined(DIS_STANDALONE)
#include <stdio.h>
#endif /* DIS_STANDALONE */

#include "libdisasm.h"
#include "libdisasm_impl.h"
#include "dis_sparc.h"
#include "dis_sparc_fmt.h"

extern char *strncpy(char *, const char *, size_t);
extern size_t strlen(const char *);
extern int strcmp(const char *, const char *);
extern int strncmp(const char *, const char *, size_t);
extern size_t strlcat(char *, const char *, size_t);
extern size_t strlcpy(char *, const char *, size_t);

/*
 * This file has the functions that do all the dirty work of outputting the
 * disassembled instruction
 *
 * All the non-static functions follow the format_fcn (in dis_sparc.h):
 * Input:
 *	disassembler handle/context
 *	instruction to disassemble
 *	instruction definition pointer (inst_t *)
 *	index in the table of the instruction
 * Return:
 *	0 Success
 *    !0 Invalid instruction
 *
 * Generally, instructions found in the same table use the same output format
 * or have a few minor differences (which are described in the 'flags' field
 * of the instruction definition. In some cases, certain instructions differ
 * radically enough from those in the same table, that their own format
 * function is used.
 *
 * Typically each table has a unique format function defined in this file.  In
 * some cases (such as branches) a common one for all the tables is used.
 *
 * When adding support for new instructions, it is largely a judgement call
 * as to when a new format function is defined.
 */

/* The various instruction formats of a sparc instruction */

#if defined(_BIT_FIELDS_HTOL)
typedef struct format1 {
	uint32_t op:2;
	uint32_t disp30:30;
} format1_t;
#elif defined(_BIT_FIELDS_LTOH)
typedef struct format1 {
	uint32_t disp30:30;
	uint32_t op:2;
} format1_t;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

#if defined(_BIT_FIELDS_HTOL)
typedef struct format2 {
	uint32_t op:2;
	uint32_t rd:5;
	uint32_t op2:3;
	uint32_t imm22:22;
} format2_t;
#elif defined(_BIT_FIELDS_LTOH)
typedef struct format2 {
	uint32_t imm22:22;
	uint32_t op2:3;
	uint32_t rd:5;
	uint32_t op:2;
} format2_t;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

#if defined(_BIT_FIELDS_HTOL)
typedef struct format2a {
	uint32_t op:2;
	uint32_t a:1;
	uint32_t cond:4;
	uint32_t op2:3;
	uint32_t disp22:22;
} format2a_t;
#elif defined(_BIT_FIELDS_LTOH)
typedef struct format2a {
	uint32_t disp22:22;
	uint32_t op2:3;
	uint32_t cond:4;
	uint32_t a:1;
	uint32_t op:2;
} format2a_t;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

#if defined(_BIT_FIELDS_HTOL)
typedef struct format2b {
	uint32_t op:2;
	uint32_t a:1;
	uint32_t cond:4;
	uint32_t op2:3;
	uint32_t cc:2;
	uint32_t p:1;
	uint32_t disp19:19;
} format2b_t;
#elif defined(_BIT_FIELDS_LTOH)
typedef struct format2b {
	uint32_t disp19:19;
	uint32_t p:1;
	uint32_t cc:2;
	uint32_t op2:3;
	uint32_t cond:4;
	uint32_t a:1;
	uint32_t op:2;
} format2b_t;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

#if defined(_BIT_FIELDS_HTOL)
typedef struct format2c {
	uint32_t op:2;
	uint32_t a:1;
	uint32_t cond:4;
	uint32_t op2:3;
	uint32_t d16hi:2;
	uint32_t p:1;
	uint32_t rs1:5;
	uint32_t d16lo:14;
} format2c_t;
#elif defined(_BIT_FIELDS_LTOH)
typedef struct format2c {
	uint32_t d16lo:14;
	uint32_t rs1:5;
	uint32_t p:1;
	uint32_t d16hi:2;
	uint32_t op2:3;
	uint32_t cond:4;
	uint32_t a:1;
	uint32_t op:2;
} format2c_t;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

#if defined(_BIT_FIELDS_HTOL)
typedef struct format3 {
	uint32_t op:2;
	uint32_t rd:5;
	uint32_t op3:6;
	uint32_t rs1:5;
	uint32_t i:1;
	uint32_t asi:8;
	uint32_t rs2:5;
} format3_t;
#elif defined(_BIT_FIELDS_LTOH)
typedef struct format3 {
	uint32_t rs2:5;
	uint32_t asi:8;
	uint32_t i:1;
	uint32_t rs1:5;
	uint32_t op3:6;
	uint32_t rd:5;
	uint32_t op:2;
} format3_t;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

#if defined(_BIT_FIELDS_HTOL)
typedef struct format3a {
	uint32_t op:2;
	uint32_t rd:5;
	uint32_t op3:6;
	uint32_t rs1:5;
	uint32_t i:1;
	uint32_t simm13:13;
} format3a_t;
#elif defined(_BIT_FIELDS_LTOH)
typedef struct format3a {
	uint32_t simm13:13;
	uint32_t i:1;
	uint32_t rs1:5;
	uint32_t op3:6;
	uint32_t rd:5;
	uint32_t op:2;
} format3a_t;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

#if defined(_BIT_FIELDS_HTOL)
typedef struct format3b {
	uint32_t op:2;
	uint32_t rd:5;
	uint32_t op3:6;
	uint32_t rs1:5;
	uint32_t i:1;
	uint32_t x:1;
	uint32_t undef:6;
	uint32_t shcnt:6;
} format3b_t;
#elif defined(_BIT_FIELDS_LTOH)
typedef struct format3b {
	uint32_t shcnt:6;
	uint32_t undef:6;
	uint32_t x:1;
	uint32_t i:1;
	uint32_t rs1:5;
	uint32_t op3:6;
	uint32_t rd:5;
	uint32_t op:2;
} format3b_t;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

#if defined(_BIT_FIELDS_HTOL)
typedef struct format3c {
	uint32_t op:2;
	uint32_t rd:5;
	uint32_t op3:6;
	uint32_t cc2:1;
	uint32_t cond:4;
	uint32_t i:1;
	uint32_t cc:2;
	uint32_t simm11:11;
} format3c_t;
#elif defined(_BIT_FIELDS_LTOH)
typedef struct format3c {
	uint32_t simm11:11;
	uint32_t cc:2;
	uint32_t i:1;
	uint32_t cond:4;
	uint32_t cc2:1;
	uint32_t op3:6;
	uint32_t rd:5;
	uint32_t op:2;
} format3c_t;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

#if defined(_BIT_FIELDS_HTOL)
typedef struct format3d {
	uint32_t op:2;
	uint32_t rd:5;
	uint32_t op3:6;
	uint32_t rs1:5;
	uint32_t i:1;
	uint32_t rcond:3;
	uint32_t simm10:10;
} format3d_t;
#elif defined(_BIT_FIELDS_LTOH)
typedef struct format3d {
	uint32_t simm10:10;
	uint32_t rcond:3;
	uint32_t i:1;
	uint32_t rs1:5;
	uint32_t op3:6;
	uint32_t rd:5;
	uint32_t op:2;
} format3d_t;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

#if defined(_BIT_FIELDS_HTOL)
typedef struct formatcp {
	uint32_t op:2;
	uint32_t rd:5;
	uint32_t op3:6;
	uint32_t rs1:5;
	uint32_t opc:9;
	uint32_t rs2:5;
} formatcp_t;
#elif defined(_BIT_FIELDS_LTOH)
typedef struct formatcp {
	uint32_t rs2:5;
	uint32_t opc:9;
	uint32_t rs1:5;
	uint32_t op3:6;
	uint32_t rd:5;
	uint32_t op:2;
} formatcp_t;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

#if defined(_BIT_FIELDS_HTOL)
typedef struct formattcc {
	uint32_t op:2;
	uint32_t undef:1;
	uint32_t cond:4;
	uint32_t op3:6;
	uint32_t rs1:5;
	uint32_t i:1;
	uint32_t cc:2;
	uint32_t undef2:3;
	uint32_t immtrap:8;
} formattcc_t;
#elif defined(_BIT_FIELDS_LTOH)
typedef struct formattcc {
	uint32_t immtrap:8;
	uint32_t undef2:3;
	uint32_t cc:2;
	uint32_t i:1;
	uint32_t rs1:5;
	uint32_t op3:6;
	uint32_t cond:4;
	uint32_t undef:1;
	uint32_t op:2;
} formattcc_t;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

#if defined(_BIT_FIELDS_HTOL)
typedef struct formattcc2 {
	uint32_t op:2;
	uint32_t undef:1;
	uint32_t cond:4;
	uint32_t op3:6;
	uint32_t rs1:5;
	uint32_t i:1;
	uint32_t cc:2;
	uint32_t undef2:6;
	uint32_t rs2:5;
} formattcc2_t;
#elif defined(_BIT_FIELDS_LTOH)
typedef struct formattcc2 {
	uint32_t rs2:5;
	uint32_t undef2:6;
	uint32_t cc:2;
	uint32_t i:1;
	uint32_t rs1:5;
	uint32_t op3:6;
	uint32_t cond:4;
	uint32_t undef:1;
	uint32_t op:2;
} formattcc2_t;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

#if defined(_BIT_FIELDS_HTOL)
typedef struct formatmbr {
	uint32_t op:2;
	uint32_t rd:5;
	uint32_t op3:6;
	uint32_t rs1:5;
	uint32_t i:1;
	uint32_t undef:6;
	uint32_t cmask:3;
	uint32_t mmask:4;
} formatmbr_t;
#elif defined(_BIT_FIELDS_LTOH)
typedef struct formatmbr {
	uint32_t mmask:4;
	uint32_t cmask:3;
	uint32_t undef:6;
	uint32_t i:1;
	uint32_t rs1:5;
	uint32_t op3:6;
	uint32_t rd:5;
	uint32_t op:2;
} formatmbr_t;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

#if defined(_BIT_FIELDS_HTOL)
typedef struct formatfcmp {
	uint32_t op:2;
	uint32_t undef:3;
	uint32_t cc:2;
	uint32_t op3:6;
	uint32_t rs1:5;
	uint32_t opf:9;
	uint32_t rs2:5;
} formatfcmp_t;
#elif defined(_BIT_FIELDS_LTOH)
typedef struct formatfcmp {
	uint32_t rs2:5;
	uint32_t opf:9;
	uint32_t rs1:5;
	uint32_t op3:6;
	uint32_t cc:2;
	uint32_t undef:3;
	uint32_t op:2;
} formatfcmp_t;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

#if defined(_BIT_FIELDS_HTOL)
typedef struct formatfmov {
	uint32_t op:2;
	uint32_t rd:5;
	uint32_t op3:6;
	uint32_t undef:1;
	uint32_t cond:4;
	uint32_t cc:3;
	uint32_t opf:6;
	uint32_t rs2:5;
} formatfmov_t;
#elif defined(_BIT_FIELDS_LTOH)
typedef struct formatfmov {
	uint32_t rs2:5;
	uint32_t opf:6;
	uint32_t cc:3;
	uint32_t cond:4;
	uint32_t undef:1;
	uint32_t op3:6;
	uint32_t rd:5;
	uint32_t op:2;
} formatfmov_t;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

#if defined(_BIT_FIELDS_HTOL)
typedef struct formatfused {
	uint32_t op:2;
	uint32_t rd:5;
	uint32_t op3:6;
	uint32_t rs1:5;
	uint32_t rs3:5;
	uint32_t op5:4;
	uint32_t rs2:5;
} formatfused_t;
#elif defined(_BIT_FIELDS_LTOH)
typedef struct formatfused {
	uint32_t rs2:5;
	uint32_t op5:4;
	uint32_t rs3:5;
	uint32_t rs1:5;
	uint32_t op3:6;
	uint32_t rd:5;
	uint32_t op:2;
} formatfused_t;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

typedef union ifmt {
	uint32_t	i;
	format1_t	f1;
	format2_t	f2;
	format2a_t	f2a;
	format2b_t	f2b;
	format2c_t	f2c;
	format3_t	f3;
	format3a_t	f3a;
	format3b_t	f3b;
	format3c_t	f3c;
	format3d_t	f3d;
	formatcp_t	fcp;
	formattcc_t	ftcc;
	formattcc2_t	ftcc2;
	formatfcmp_t	fcmp;
	formatmbr_t	fmb;
	formatfmov_t	fmv;
	formatfused_t	fused;
} ifmt_t;

/* integer register names */
static const char *reg_names[32] = {
	"%g0", "%g1", "%g2", "%g3", "%g4", "%g5", "%g6", "%g7",
	"%o0", "%o1", "%o2", "%o3", "%o4", "%o5", "%sp", "%o7",
	"%l0", "%l1", "%l2", "%l3", "%l4", "%l5", "%l6", "%l7",
	"%i0", "%i1", "%i2", "%i3", "%i4", "%i5", "%fp", "%i7"
};

/* floating point register names */
static const char *freg_names[32] = {
	"%f0",  "%f1",  "%f2",  "%f3",  "%f4",  "%f5",  "%f6",  "%f7",
	"%f8",  "%f9",  "%f10", "%f11", "%f12", "%f13", "%f14", "%f15",
	"%f16", "%f17", "%f18", "%f19", "%f20", "%f21", "%f22", "%f23",
	"%f24", "%f25", "%f26", "%f27", "%f28", "%f29", "%f30", "%f31"
};

/* double precision register names */
static const char *fdreg_names[32] = {
	"%d0",  "%d32", "%d2",  "%d34", "%d4",  "%d36", "%d6",  "%d38",
	"%d8",  "%d40", "%d10", "%d42", "%d12", "%d44", "%d14", "%d46",
	"%d16", "%d48", "%d18", "%d50", "%d20", "%d52", "%d22", "%d54",
	"%d24", "%d56", "%d26", "%d58", "%d28", "%d60", "%d30", "%d62"
};

static const char *compat_fdreg_names[32] = {
	"%f0",  "%f32", "%f2",  "%f34", "%f4",  "%f36", "%f6",  "%f38",
	"%f8",  "%f40", "%f10", "%f42", "%f12", "%f44", "%f14", "%f46",
	"%f16", "%f48", "%f18", "%f50", "%f20", "%f52", "%f22", "%f54",
	"%f24", "%f56", "%f26", "%f58", "%f28", "%f60", "%f30", "%f62"
};


static const char *fqreg_names[32] = {
	"%q0",  "%q32", "%f2",  "%f3",  "%f4",  "%q4",  "%q36", "%f6",
	"%f7",  "%q8",  "%q40", "%f10", "%f11", "%q12", "%q44", "%f14",
	"%f15", "%q16", "%q48", "%f18", "%f19", "%q20", "%q52", "%f22",
	"%f23", "%q24", "%q56", "%f26", "%f27", "%q28", "%q60", "%f30",
};


/* coprocessor register names -- sparcv8 only */
static const char *cpreg_names[32] = {
	"%c0",  "%c1",  "%c2",  "%c3",  "%c4",  "%c5",  "%c6",  "%c7",
	"%c8",  "%c9",  "%c10", "%c11", "%c12", "%c13", "%c14", "%c15",
	"%c16", "%c17", "%c18", "%c19", "%c20", "%c21", "%c22", "%c23",
	"%c24", "%c25", "%c26", "%c27", "%c28", "%c29", "%c30", "%c31",
};

/* floating point condition code names */
static const char *fcc_names[4] = {
	"%fcc0", "%fcc1", "%fcc2", "%fcc3"
};

/* condition code names */
static const char *icc_names[4] = {
	"%icc", NULL, "%xcc", NULL
};

/* bitmask values for membar */
static const char *membar_mmask[4] = {
	"#LoadLoad", "#StoreLoad", "#LoadStore", "#StoreStore"
};

static const char *membar_cmask[3] = {
	"#Lookaside", "#MemIssue", "#Sync"
};

/* v8 ancillary state register names */
static const char *asr_names[32] = {
	"%y",	"%asr1",  "%asr2",  "%asr3",
	"%asr4",  "%asr5",  "%asr6",  "%asr7",
	"%asr8",  "%asr9",  "%asr10", "%asr11",
	"%asr12", "%asr13", "%asr14", "%asr15",
	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL
};
static const uint32_t asr_rdmask = 0x0000ffffL;
static const uint32_t asr_wrmask = 0x0000ffffL;

static const char *v9_asr_names[32] = {
	"%y",		NULL,		"%ccr",	"%asi",
	"%tick",	"%pc",		"%fprs",	NULL,
	NULL,		NULL,		NULL,	NULL,
	NULL,		NULL,		NULL,	NULL,
	"%pcr",		"%pic",		"%dcr",	"%gsr",
	"%softint_set",	"%softint_clr",	"%softint",	"%tick_cmpr",
	"%stick",	"%stick_cmpr",	NULL,	NULL,
	NULL,		NULL,		NULL,	NULL
};
/*
 * on v9, only certain registers are valid for read or writing
 * these are bitmasks corresponding to which registers are valid in which
 * case. Any access to %dcr is illegal.
 */
static const uint32_t v9_asr_rdmask = 0x03cb007d;
static const uint32_t v9_asr_wrmask = 0x03fb004d;

/* privledged register names on v9 */
/* TODO: compat - NULL to %priv_nn */
static const char *v9_privreg_names[32] = {
	"%tpc",	 "%tnpc",	"%tstate",  "%tt",
	"%tick",	"%tba",	 "%pstate",  "%tl",
	"%pil",	 "%cwp",	 "%cansave", "%canrestore",
	"%cleanwin", "%otherwin", "%wstate",  "%fq",
	"%gl",	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	"%ver"
};

/* hyper privileged register names on v9 */
static const char *v9_hprivreg_names[32] = {
	"%hpstate",	 "%htstate",	NULL,  "%hintp",
	NULL,	"%htba",	 "%hver",  NULL,
	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	NULL,
	NULL,	NULL,	NULL,	"%hstick_cmpr"
};

static const uint32_t v9_pr_rdmask = 0x80017fff;
static const uint32_t v9_pr_wrmask = 0x00017fff;
static const uint32_t v9_hpr_rdmask = 0x8000006b;
static const uint32_t v9_hpr_wrmask = 0x8000006b;

static const char *prefetch_str[32] = {
	"#n_reads", "#one_read",
	"#n_writes", "#one_write",
	"#page",    NULL, NULL, NULL,
	NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL,
	NULL, "#unified", NULL, NULL,
	"#n_reads_strong", "#one_read_strong",
	"#n_writes_strong", "#one_write_strong",
	NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL
};

static void prt_field(const char *, uint32_t, int);

static const char *get_regname(dis_handle_t *, int, uint32_t);
static int32_t sign_extend(int32_t, int32_t);

static void prt_name(dis_handle_t *, const char *, int);

#define	IMM_SIGNED 0x01  /* Is immediate value signed		*/
#define	IMM_ADDR   0x02  /* Is immediate value part of an address */
static void prt_imm(dis_handle_t *, uint32_t, int);

static void prt_asi(dis_handle_t *, uint32_t);
static const char *get_asi_name(uint8_t);
static void prt_address(dis_handle_t *, uint32_t, int);
static void prt_aluargs(dis_handle_t *, uint32_t, uint32_t);
static void bprintf(dis_handle_t *, const char *, ...);

/*
 * print out val (which is 'bitlen' bits long) in binary
 */
#if defined(DIS_STANDALONE)
/* ARGSUSED */
void
prt_binary(uint32_t val, int bitlen)
{

}

#else

void
prt_binary(uint32_t val, int bitlen)
{
	int i;

	for (i = bitlen - 1; i >= 0; --i) {
		(void) fprintf(stderr, ((val & (1L << i)) != 0) ? "1" : "0");

		if (i % 4 == 0 && i != 0)
			(void) fprintf(stderr, " ");
	}
}
#endif /* DIS_STANDALONE */


/*
 * print out a call instruction
 * format: call address  <name>
 */
/* ARGSUSED1 */
int
fmt_call(dis_handle_t *dhp, uint32_t instr, const inst_t *inp, int idx)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	ifmt_t *f = (ifmt_t *)&instr;

	int32_t disp;
	size_t curlen;

	int octal = ((dhp->dh_flags & DIS_OCTAL) != 0);

	if ((dhx->dhx_debug & DIS_DEBUG_PRTFMT) != 0) {
		prt_field("op", f->f1.op, 2);
		prt_field("disp30", f->f1.disp30, 30);
	}

	disp = sign_extend(f->f1.disp30, 30) * 4;

	prt_name(dhp, inp->in_data.in_def.in_name, 1);

	bprintf(dhp, (octal != 0) ? "%s0%-11lo" : "%s0x%-10lx",
	    (disp < 0) ? "-" : "+",
	    (disp < 0) ? (-disp) : disp);

	(void) strlcat(dhx->dhx_buf, " <", dhx->dhx_buflen);

	curlen = strlen(dhx->dhx_buf);
	dhp->dh_lookup(dhp->dh_data, dhp->dh_addr + (int64_t)disp,
	    dhx->dhx_buf + curlen, dhx->dhx_buflen - curlen - 1, NULL,
	    NULL);
	(void) strlcat(dhx->dhx_buf, ">", dhx->dhx_buflen);


	return (0);
}

int
fmt_sethi(dis_handle_t *dhp, uint32_t instr, const inst_t *inp, int idx)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	ifmt_t *f = (ifmt_t *)&instr;

	if ((dhx->dhx_debug & DIS_DEBUG_PRTFMT) != 0) {
		prt_field("op", f->f2.op, 2);
		prt_field("op2", f->f2.op2, 3);
		prt_field("rd", f->f2.rd, 5);
		prt_field("imm22", f->f2.imm22, 22);
	}

	if (idx == 0) {
		/* unimp / illtrap */
		prt_name(dhp, inp->in_data.in_def.in_name, 1);
		prt_imm(dhp, f->f2.imm22, 0);
		return (0);
	}

	if (f->f2.imm22 == 0 && f->f2.rd == 0) {
		prt_name(dhp, "nop", 0);
		return (0);
	}

	/* ?? Should we return -1 if rd == 0 && disp != 0 */

	prt_name(dhp, inp->in_data.in_def.in_name, 1);

	bprintf(dhp,
	    ((dhp->dh_flags & DIS_OCTAL) != 0) ?
	    "%%hi(0%lo), %s" : "%%hi(0x%lx), %s",
	    f->f2.imm22 << 10,
	    reg_names[f->f2.rd]);

	return (0);
}

/* ARGSUSED3 */
int
fmt_branch(dis_handle_t *dhp, uint32_t instr, const inst_t *inp, int idx)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	const char *name = inp->in_data.in_def.in_name;
	const char *r = NULL;
	const char *annul = "";
	const char *pred  = "";

	char buf[15];

	ifmt_t *f = (ifmt_t *)&instr;

	size_t curlen;
	int32_t disp;
	uint32_t flags = inp->in_data.in_def.in_flags;
	int octal = ((dhp->dh_flags & DIS_OCTAL) != 0);

	if ((dhx->dhx_debug & DIS_DEBUG_PRTFMT) != 0) {
		prt_field("op", f->f2.op, 2);
		prt_field("op2", f->f2.op2, 3);

		switch (FLG_DISP_VAL(flags)) {
		case DISP22:
			prt_field("cond", f->f2a.cond, 4);
			prt_field("a", f->f2a.a, 1);
			prt_field("disp22", f->f2a.disp22, 22);
			break;

		case DISP19:
			prt_field("cond", f->f2a.cond, 4);
			prt_field("a", f->f2a.a, 1);
			prt_field("p", f->f2b.p, 1);
			prt_field("cc", f->f2b.cc, 2);
			prt_field("disp19", f->f2b.disp19, 19);
			break;

		case DISP16:
			prt_field("bit 28", ((instr & (1L << 28)) >> 28), 1);
			prt_field("rcond", f->f2c.cond, 3);
			prt_field("p", f->f2c.p, 1);
			prt_field("rs1", f->f2c.rs1, 5);
			prt_field("d16hi", f->f2c.d16hi, 2);
			prt_field("d16lo", f->f2c.d16lo, 14);
			break;
		}
	}

	if (f->f2b.op2 == 0x01 && idx == 0x00 && f->f2b.p == 1 &&
	    f->f2b.cc == 0x02 && ((dhx->dhx_debug & DIS_DEBUG_SYN_ALL) != 0)) {
		name = "iprefetch";
		flags = FLG_RS1(REG_NONE)|FLG_DISP(DISP19);
	}


	switch (FLG_DISP_VAL(flags)) {
	case DISP22:
		disp = sign_extend(f->f2a.disp22, 22);
		break;

	case DISP19:
		disp = sign_extend(f->f2b.disp19, 19);
		break;

	case DISP16:
		disp = sign_extend((f->f2c.d16hi << 14)|f->f2c.d16lo, 16);
		break;

	}

	disp *= 4;

	if ((FLG_RS1_VAL(flags) == REG_ICC) || (FLG_RS1_VAL(flags) == REG_FCC))
		r = get_regname(dhp, FLG_RS1_VAL(flags), f->f2b.cc);
	else
		r = get_regname(dhp, FLG_RS1_VAL(flags), f->f2c.rs1);

	if (r == NULL)
		return (-1);

	if (f->f2a.a == 1)
		annul = ",a";

	if ((flags & FLG_PRED) != 0) {
		if (f->f2b.p == 0) {
			pred = ",pn";
		} else {
			if ((dhx->dhx_debug & DIS_DEBUG_COMPAT) != 0)
				pred = ",pt";
		}
	}

	(void) dis_snprintf(buf, sizeof (buf), "%s%s%s", name, annul, pred);
	prt_name(dhp, buf, 1);


	switch (FLG_DISP_VAL(flags)) {
	case DISP22:
		bprintf(dhp,
		    (octal != 0) ? "%s0%-11lo <" : "%s0x%-10lx <",
		    (disp < 0) ? "-" : "+",
		    (disp < 0) ? (-disp) : disp);
		break;

	case DISP19:
		bprintf(dhp,
		    (octal != 0) ? "%s, %s0%-5lo <" :
		    "%s, %s0x%-04lx <", r,
		    (disp < 0) ? "-" : "+",
		    (disp < 0) ? (-disp) : disp);
		break;

	case DISP16:
		bprintf(dhp,
		    (octal != 0) ? "%s, %s0%-6lo <" : "%s, %s0x%-5lx <",
		    r,
		    (disp < 0) ? "-" : "+",
		    (disp < 0) ? (-disp) : disp);
		break;
	}

	curlen = strlen(dhx->dhx_buf);
	dhp->dh_lookup(dhp->dh_data, dhp->dh_addr + (int64_t)disp,
	    dhx->dhx_buf + curlen, dhx->dhx_buflen - curlen - 1, NULL, NULL);

	(void) strlcat(dhx->dhx_buf, ">", dhx->dhx_buflen);

	return (0);
}



/*
 * print out the compare and swap instructions (casa/casxa)
 * format: casa/casxa [%rs1] imm_asi, %rs2, %rd
 *	    casa/casxa [%rs1] %asi, %rs2, %rd
 *
 * If DIS_DEBUG_SYN_ALL is set, synthetic instructions are emitted
 * when an immediate ASI value is given as follows:
 *
 * casa  [%rs1]#ASI_P, %rs2, %rd    -> cas   [%rs1], %rs2, %rd
 * casa  [%rs1]#ASI_P_L, %rs2, %rd  -> casl  [%rs1], %rs2, %rd
 * casxa [%rs1]#ASI_P, %rs2, %rd    -> casx  [%rs1], %rs2, %rd
 * casxa [%rs1]#ASI_P_L, %rs2, %rd  -> casxl [%rs1], %rs2, %rd
 */
static int
fmt_cas(dis_handle_t *dhp, uint32_t instr, const char *name)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	ifmt_t *f = (ifmt_t *)&instr;
	const char *asistr = NULL;
	int noasi = 0;

	asistr = get_asi_name(f->f3.asi);

	if ((dhx->dhx_debug & (DIS_DEBUG_SYN_ALL|DIS_DEBUG_COMPAT)) != 0) {
		if (f->f3.op3 == 0x3c && f->f3.i == 0) {
			if (f->f3.asi == 0x80) {
				noasi = 1;
				name = "cas";
			}

			if (f->f3.asi == 0x88) {
				noasi = 1;
				name = "casl";
			}
		}

		if (f->f3.op3 == 0x3e && f->f3.i == 0) {
			if (f->f3.asi == 0x80) {
				noasi = 1;
				name = "casx";
			}

			if (f->f3.asi == 0x88) {
				noasi = 1;
				name = "casxl";
			}
		}
	}

	prt_name(dhp, name, 1);

	bprintf(dhp, "[%s]", reg_names[f->f3.rs1]);

	if (noasi == 0) {
		(void) strlcat(dhx->dhx_buf, " ", dhx->dhx_buflen);
		prt_asi(dhp, instr);
	}

	bprintf(dhp, ", %s, %s", reg_names[f->f3.rs2], reg_names[f->f3.rd]);

	if (noasi == 0 && asistr != NULL)
		bprintf(dhp, "\t<%s>", asistr);

	return (0);
}

/*
 * format a load/store instruction
 * format: ldXX [%rs1 + %rs2], %rd	  load, i==0
 *	    ldXX [%rs1 +/- nn], %rd	  load, i==1
 *	    ldXX [%rs1 + %rs2] #XX, %rd   load w/ imm_asi, i==0
 *	    ldXX [%rs1 +/- nn] %asi, %rd  load from asi[%asi], i==1
 *
 *	    stXX %rd, [%rs1 + %rs2]	  store, i==0
 *	    stXX %rd, [%rs1 +/- nn]	  store, i==1
 *	    stXX %rd, [%rs1 + %rs1] #XX   store to imm_asi, i==0
 *	    stXX %rd, [%rs1 +/-nn] %asi   store to asi[%asi], i==1
 *
 * The register sets used for %rd are set in the instructions flags field
 * The asi variants are used if FLG_ASI is set in the instructions flags field
 *
 * If DIS_DEBUG_SYNTH_ALL or DIS_DEBUG_COMPAT are set,
 * When %rs1, %rs2 or nn are 0, they are not printed, i.e.
 * [ %rs1 + 0x0 ], %rd -> [%rs1], %rd for example
 *
 * The following synthetic instructions are also implemented:
 *
 * stb %g0, [addr] -> clrb [addr]    DIS_DEBUG_SYNTH_ALL
 * sth %g0, [addr] -> crlh [addr]    DIS_DEBUG_SYNTH_ALL
 * stw %g0, [addr] -> clr  [addr]    DIS_DEBUG_SYNTH_ALL|DIS_DEBUG_COMPAT
 * stx %g0, [addr] -> clrx [addr]    DIS_DEBUG_SYNTH_ALL
 *
 * If DIS_DEBUG_COMPAT is set, the following substitutions also take place
 *	lduw -> ld
 *	ldtw -> ld
 *	stuw -> st
 *	sttw -> st
 */
int
fmt_ls(dis_handle_t *dhp, uint32_t instr, const inst_t *inp, int idx)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	ifmt_t *f = (ifmt_t *)&instr;
	const char *regstr = NULL;
	const char *asistr = NULL;

	const char *iname = inp->in_data.in_def.in_name;
	uint32_t flags = inp->in_data.in_def.in_flags;

	if ((dhx->dhx_debug & DIS_DEBUG_PRTFMT) != 0) {
		prt_field("op", f->f3.op, 2);
		prt_field("op3", f->f3.op3, 6);
		prt_field("rs1", f->f3.rs1, 5);
		prt_field("i", f->f3.i, 1);
		if (f->f3.i != 0) {
			prt_field("simm13", f->f3a.simm13, 13);
		} else {
			if ((flags & FLG_ASI) != 0)
				prt_field("imm_asi", f->f3.asi, 8);
			prt_field("rs2", f->f3.rs2, 5);
		}
		prt_field("rd", f->f3.rd, 5);
	}

	if (idx == 0x2d || idx == 0x3d) {
		/* prefetch / prefetcha */

		prt_name(dhp, iname, 1);

		prt_address(dhp, instr, 0);

		if (idx == 0x3d) {
			(void) strlcat(dhx->dhx_buf, " ", dhx->dhx_buflen);
			prt_asi(dhp, instr);
		}

		(void) strlcat(dhx->dhx_buf, ", ", dhx->dhx_buflen);

		/* fcn field is the same as rd */
		if (prefetch_str[f->f3.rd] != NULL)
			(void) strlcat(dhx->dhx_buf, prefetch_str[f->f3.rd],
			    dhx->dhx_buflen);
		else
			prt_imm(dhp, f->f3.rd, 0);

		if (idx == 0x3d && f->f3.i == 0) {
			asistr = get_asi_name(f->f3.asi);
			if (asistr != NULL)
				bprintf(dhp, "\t<%s>", asistr);
		}

		return (0);
	}

	/* casa / casxa */
	if (idx == 0x3c || idx == 0x3e)
		return (fmt_cas(dhp, instr, iname));

	/* synthetic instructions & special cases */
	switch (idx) {
	case 0x00:
		/* ld */
		if ((dhx->dhx_debug & DIS_DEBUG_COMPAT) == 0)
			iname = "lduw";
		break;

	case 0x03:
		if ((dhx->dhx_debug & DIS_DEBUG_COMPAT) == 0)
			iname = "ldtw";
		break;

	case 0x04:
		/* stw */
		if ((dhx->dhx_debug & DIS_DEBUG_COMPAT) == 0)
			iname = "stuw";

		if ((dhp->dh_flags & (DIS_DEBUG_COMPAT|DIS_DEBUG_SYN_ALL))
		    == 0)
			break;

		if (f->f3.rd == 0) {
			iname = "clr";
			flags = FLG_RD(REG_NONE);
		}
		break;

	case 0x05:
		/* stb */
		if ((dhp->dh_flags & (DIS_DEBUG_COMPAT|DIS_DEBUG_SYN_ALL))
		    == 0)
			break;

		if (f->f3.rd == 0) {
			iname = "clrb";
			flags = FLG_RD(REG_NONE);
		}
		break;

	case 0x06:
		/* sth */
		if ((dhp->dh_flags & (DIS_DEBUG_COMPAT|DIS_DEBUG_SYN_ALL))
		    == 0)
			break;

		if (f->f3.rd == 0) {
			iname = "clrh";
			flags = FLG_RD(REG_NONE);
		}
		break;

	case 0x07:
		if ((dhx->dhx_debug & DIS_DEBUG_COMPAT) == 0)
			iname = "sttw";
		break;

	case 0x0e:
		/* stx */

		if ((dhp->dh_flags & (DIS_DEBUG_COMPAT|DIS_DEBUG_SYN_ALL))
		    == 0)
			break;

		if (f->f3.rd == 0) {
			iname = "clrx";
			flags = FLG_RD(REG_NONE);
		}
		break;

	case 0x13:
		/* ldtwa */
		if (((dhx->dhx_debug & DIS_DEBUG_COMPAT) == 0) &&
		    ((dhp->dh_flags & (DIS_SPARC_V9|DIS_SPARC_V9_SGI)) != 0))
			iname = "ldtwa";
		break;

	case 0x17:
		/* sttwa */
		if (((dhx->dhx_debug & DIS_DEBUG_COMPAT) == 0) &&
		    ((dhp->dh_flags & (DIS_SPARC_V9|DIS_SPARC_V9_SGI)) != 0))
			iname = "sttwa";
		break;

	case 0x21:
	case 0x25:
		/*
		 * on sparcv8 it merely says that rd != 1 should generate an
		 * exception, on v9, it is illegal
		 */
		if ((dhp->dh_flags & (DIS_SPARC_V9|DIS_SPARC_V9_SGI)) == 0)
			break;

		iname = (idx == 0x21) ? "ldx" : "stx";

		if (f->f3.rd > 1)
			return (-1);

		break;

	case 0x31:
		/* stda */
		switch (f->f3.asi) {
			case 0xc0:
			case 0xc1:
			case 0xc8:
			case 0xc9:
			case 0xc2:
			case 0xc3:
			case 0xca:
			case 0xcb:
			case 0xc4:
			case 0xc5:
			case 0xcc:
			case 0xcd:
				/*
				 * store partial floating point, only valid w/
				 * vis
				 *
				 * Somewhat confusingly, it uses the same op
				 * code as 'stda' -- store double to alternate
				 * space.  It is distinguised by specific
				 * imm_asi values (as seen above), and
				 * has a slightly different output syntax
				 */

				if ((dhp->dh_flags & DIS_SPARC_V9_SGI) == 0)
					break;
				if (f->f3.i != 0)
					break;
				prt_name(dhp, iname, 1);
				bprintf(dhp, "%s, %s, [%s] ",
				    get_regname(dhp, REG_FPD, f->f3.rd),
				    get_regname(dhp, REG_FPD, f->f3.rs2),
				    get_regname(dhp, REG_FPD, f->f3.rs1));
				prt_asi(dhp, instr);
				asistr = get_asi_name(f->f3.asi);
				if (asistr != NULL)
					bprintf(dhp, "\t<%s>", asistr);

				return (0);

			default:
				break;
		}

	}

	regstr = get_regname(dhp, FLG_RD_VAL(flags), f->f3.rd);

	if (f->f3.i == 0)
		asistr = get_asi_name(f->f3.asi);

	prt_name(dhp, iname, 1);

	if ((flags & FLG_STORE) != 0) {
		if (regstr[0] != '\0') {
			(void) strlcat(dhx->dhx_buf, regstr, dhx->dhx_buflen);
			(void) strlcat(dhx->dhx_buf, ", ", dhx->dhx_buflen);
		}

		prt_address(dhp, instr, 0);
		if ((flags & FLG_ASI) != 0) {
			(void) strlcat(dhx->dhx_buf, " ", dhx->dhx_buflen);
			prt_asi(dhp, instr);
		}
	} else {
		prt_address(dhp, instr, 0);
		if ((flags & FLG_ASI) != 0) {
			(void) strlcat(dhx->dhx_buf, " ", dhx->dhx_buflen);
			prt_asi(dhp, instr);
		}

		if (regstr[0] != '\0') {
			(void) strlcat(dhx->dhx_buf, ", ", dhx->dhx_buflen);
			(void) strlcat(dhx->dhx_buf, regstr, dhx->dhx_buflen);
		}
	}

	if ((flags & FLG_ASI) != 0 && asistr != NULL)
		bprintf(dhp, "\t<%s>", asistr);

	return (0);
}

static int
fmt_cpop(dis_handle_t *dhp, uint32_t instr, const inst_t *inp)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	ifmt_t *f = (ifmt_t *)&instr;
	int flags = FLG_P1(REG_CP)|FLG_P2(REG_CP)|FLG_NOIMM|FLG_P3(REG_CP);

	if ((dhx->dhx_debug & DIS_DEBUG_PRTFMT) != 0) {
		prt_field("op", f->fcp.op, 2);
		prt_field("op3", f->fcp.op3, 6);
		prt_field("opc", f->fcp.opc, 9);
		prt_field("rs1", f->fcp.rs1, 5);
		prt_field("rs2", f->fcp.rs2, 5);
		prt_field("rd", f->fcp.rd, 5);
	}

	prt_name(dhp, inp->in_data.in_def.in_name, 1);
	prt_imm(dhp, f->fcp.opc, 0);

	(void) strlcat(dhx->dhx_buf, ", ", dhx->dhx_buflen);
	(void) prt_aluargs(dhp, instr, flags);

	return (0);
}

static int
dis_fmt_rdwr(dis_handle_t *dhp, uint32_t instr, const inst_t *inp, int idx)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	const char *psr_str = "%psr";
	const char *wim_str = "%wim";
	const char *tbr_str = "%tbr";

	const char *name = inp->in_data.in_def.in_name;
	const char *regstr = NULL;

	ifmt_t *f = (ifmt_t *)&instr;

	int rd = (idx < 0x30);
	int v9 = (dhp->dh_flags & (DIS_SPARC_V9|DIS_SPARC_V9_SGI));
	int ridx = f->f3.rs1;
	int i, first;
	int pr_rs1 = 1;
	int pr_rs2 = 1;

	int use_mask = 1;
	uint32_t mask;

	if (rd == 0)
		ridx = f->f3.rd;

	switch (idx) {
	case 0x28:
		/* rd */

		/* stbar */
		if ((f->f3.rd == 0) && (f->f3.rs1 == 15) && (f->f3.i == 0)) {
			prt_name(dhp, "stbar", 0);
			return (0);
		}

		/* membar */
		if ((v9 != 0) && (f->f3.rd == 0) && (f->f3.rs1 == 15) &&
		    (f->f3.i == 1) && ((f->i & (1L << 12)) == 0)) {

			prt_name(dhp, "membar",
			    ((f->fmb.cmask != 0) || (f->fmb.mmask != 0)));

			first = 0;

			for (i = 0; i < 4; ++i) {
				if ((f->fmb.cmask & (1L << i)) != 0) {
					bprintf(dhp, "%s%s",
					    (first != 0) ? "|" : "",
					    membar_cmask[i]);
					first = 1;
				}
			}

			for (i = 0; i < 5; ++i) {
				if ((f->fmb.mmask & (1L << i)) != 0) {
					bprintf(dhp, "%s%s",
					    (first != 0) ? "|" : "",
					    membar_mmask[i]);
					first = 1;
				}
			}

			return (0);
		}

		if (v9 != 0) {
			regstr = v9_asr_names[ridx];
			mask = v9_asr_rdmask;
		} else {
			regstr = asr_names[ridx];
			mask = asr_rdmask;
		}
		break;

	case 0x29:
		if (v9 != 0) {
			regstr = v9_hprivreg_names[ridx];
			mask = v9_hpr_rdmask;
		} else {
			regstr = psr_str;
			use_mask = 0;
		}
		break;

	case 0x2a:
		if (v9 != 0) {
			regstr = v9_privreg_names[ridx];
			mask = v9_pr_rdmask;
		} else {
			regstr = wim_str;
			use_mask = 0;
		}
		break;

	case 0x2b:
		if (v9 != 0) {
			/* flushw */
			prt_name(dhp, name, 0);
			return (0);
		}

		regstr = tbr_str;
		use_mask = 0;
		break;

	case 0x30:
		if (v9 != 0) {
			regstr = v9_asr_names[ridx];
			mask = v9_asr_wrmask;
		} else {
			regstr = asr_names[ridx];
			mask = asr_wrmask;
		}

		/*
		 * sir is shoehorned in here, per Ultrasparc 2007
		 * hyperprivileged edition, section 7.88, all of
		 * these must be true to distinguish from WRasr
		 */
		if (v9 != 0 && f->f3.rd == 15 && f->f3.rs1 == 0 &&
		    f->f3.i == 1) {
			prt_name(dhp, "sir", 1);
			prt_imm(dhp, sign_extend(f->f3a.simm13, 13),
			    IMM_SIGNED);
			return (0);
		}

		/* synth: mov */
		if ((dhx->dhx_debug & (DIS_DEBUG_COMPAT|DIS_DEBUG_SYN_ALL))
		    == 0)
			break;

		if (v9 == 0) {
			if (f->f3.rs1 == 0) {
				name = "mov";
				pr_rs1 = 0;
			}

			if ((f->f3.i == 0 && f->f3.rs2 == 0) ||
			    (f->f3.i == 1 && f->f3a.simm13 == 0)) {
				name = "mov";
				pr_rs2 = 0;
			}
		}

		if (pr_rs1 == 0)
			pr_rs2 = 1;

		break;

	case 0x31:
		/*
		 * NOTE: due to the presence of an overlay entry for another
		 * table, this case only happens when doing v8 instructions
		 * only
		 */
		regstr = psr_str;
		use_mask = 0;
		break;

	case 0x32:
		if (v9 != 0) {
			regstr = v9_privreg_names[ridx];
			mask = v9_pr_wrmask;
		} else {
			regstr = wim_str;
			use_mask = 0;
		}
		break;

	case 0x33:
		if (v9 != 0) {
			regstr = v9_hprivreg_names[ridx];
			mask = v9_hpr_wrmask;
		} else {
			regstr = tbr_str;
			use_mask = 0;
		}
		break;
	}

	if (regstr == NULL)
		return (-1);

	if (use_mask != 0 && ((1L << ridx) & mask) == 0)
		return (-1);

	prt_name(dhp, name, 1);

	if (rd != 0) {
		bprintf(dhp, "%s, %s", regstr, reg_names[f->f3.rd]);
	} else {
		if (pr_rs1 == 1)
			bprintf(dhp, "%s, ", reg_names[f->f3.rs1]);

		if (pr_rs2 != 0) {
			if (f->f3.i == 1)
				prt_imm(dhp, sign_extend(f->f3a.simm13, 13),
				    IMM_SIGNED);
			else
				(void) strlcat(dhx->dhx_buf,
				    reg_names[f->f3.rs2], dhx->dhx_buflen);
			(void) strlcat(dhx->dhx_buf, ", ", dhx->dhx_buflen);
		}

		(void) strlcat(dhx->dhx_buf, regstr, dhx->dhx_buflen);
	}

	return (0);
}

/* ARGSUSED3 */
int
fmt_trap(dis_handle_t *dhp, uint32_t instr, const inst_t *inp, int idx)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	ifmt_t *f = (ifmt_t *)&instr;

	int v9 = ((dhp->dh_flags & (DIS_SPARC_V9|DIS_SPARC_V9_SGI)) != 0);
	int p_rs1, p_t;

	if (f->ftcc.undef != 0)
		return (-1);

	if (icc_names[f->ftcc.cc] == NULL)
		return (-1);

	if (f->ftcc.i == 1 && f->ftcc.undef2 != 0)
		return (-1);

	if (f->ftcc2.i == 0 && f->ftcc2.undef2 != 0)
		return (-1);

	p_rs1 = ((f->ftcc.rs1 != 0) ||
	    ((dhx->dhx_debug & (DIS_DEBUG_COMPAT|DIS_DEBUG_SYN_ALL)) == 0));

	if (f->ftcc.i == 0) {
		p_t = (f->f3.rs2 != 0 || p_rs1 == 0);

		bprintf(dhp, "%-9s %s%s%s%s%s", inp->in_data.in_def.in_name,
		    (v9 != 0) ? icc_names[f->ftcc2.cc] : "",
		    (v9 != 0) ? ", " : "",
		    (p_rs1 != 0) ? reg_names[f->ftcc2.rs1] : "",
		    (p_rs1 != 0) ? " + " : "",
		    (p_t != 0) ? reg_names[f->f3.rs2] : "");
	} else {
		bprintf(dhp, "%-9s %s%s%s%s0x%x", inp->in_data.in_def.in_name,
		    (v9 != 0) ? icc_names[f->ftcc2.cc] : "",
		    (v9 != 0) ? ", " : "",
		    (p_rs1 != 0) ? reg_names[f->ftcc2.rs1] : "",
		    (p_rs1 != 0) ? " + " : "",
		    f->ftcc.immtrap);
	}
	return (0);
}

static int
prt_shift(dis_handle_t *dhp, uint32_t instr, const inst_t *inp)
{
	char name[5];
	uint32_t cnt;

	ifmt_t *f = (ifmt_t *)&instr;
	int octal = ((dhp->dh_flags & DIS_OCTAL) != 0);

	name[0] = '\0';
	(void) strlcat(name, inp->in_data.in_def.in_name, sizeof (name));

	if (f->f3b.i == 1)
		cnt = f->f3.rs2;

	if (f->f3b.x == 1 && ((dhp->dh_flags & DIS_SPARC_V8) == 0)) {
		cnt = f->f3b.shcnt;
		(void) strlcat(name, "x", sizeof (name));
	}

	prt_name(dhp, name, 1);

	if (f->f3b.i == 1)
		bprintf(dhp, (octal != 0) ? "%s, 0%lo, %s" : "%s, 0x%lx, %s",
		    reg_names[f->f3.rs1], cnt, reg_names[f->f3.rd]);
	else
		bprintf(dhp, "%s, %s, %s", reg_names[f->f3.rs1],
		    reg_names[f->f3.rs2], reg_names[f->f3.rd]);

	return (0);
}

/* ARGSUSED3 */
static int
prt_jmpl(dis_handle_t *dhp, uint32_t instr, const inst_t *inp, int idx)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	const char *name = inp->in_data.in_def.in_name;
	ifmt_t *f = (ifmt_t *)&instr;

	if (f->f3.rd == 15 && ((dhx->dhx_debug & DIS_DEBUG_COMPAT) == 0))
		name = "call";

	if (f->f3.rd == 0) {
		if (f->f3.i == 1 && f->f3a.simm13 == 8) {
			if (f->f3.rs1 == 15) {
				prt_name(dhp, "retl", 0);
				return (0);
			}

			if (f->f3.rs1 == 31) {
				prt_name(dhp, "ret", 0);
				return (0);
			}
		}

		name = "jmp";
	}

	prt_name(dhp, name, 1);
	prt_address(dhp, instr, 1);

	if (f->f3.rd == 0)
		return (0);

	if (f->f3.rd == 15 && ((dhx->dhx_debug & DIS_DEBUG_COMPAT) == 0))
		return (0);

	bprintf(dhp, ", %s", reg_names[f->f3.rd]);

	return (0);
}

int
fmt_alu(dis_handle_t *dhp, uint32_t instr, const inst_t *inp, int idx)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	ifmt_t *f = (ifmt_t *)&instr;

	const char *name = inp->in_data.in_def.in_name;
	int flags = inp->in_data.in_def.in_flags;
	int arg = 0;

	if ((dhx->dhx_debug & DIS_DEBUG_PRTFMT) != 0) {
		prt_field("op", f->f3.op, 2);
		prt_field("op3", f->f3.op3, 6);
		prt_field("rs1", f->f3.rs1, 5);

		switch (idx) {
			/* TODO: more formats */

		default:
			if (f->f3.i == 0)
				prt_field("rs2", f->f3.rs2, 5);
			else
				prt_field("simm13", f->f3a.simm13, 13);

			prt_field("rd", f->f3.rd, 5);
		}

	}

	switch (idx) {
	case 0x00:
		/* add */

		if ((dhx->dhx_debug & DIS_DEBUG_SYN_ALL) == 0)
			break;

		if (f->f3.rs1 == f->f3.rd && f->f3.i == 1 &&
		    f->f3a.simm13 == 1) {
			name = "inc";
			flags = FLG_P1(REG_NONE)|FLG_P2(REG_NONE)|FLG_NOIMM;
			break;
		}

		if (f->f3.rs1 == f->f3.rd && f->f3.i == 1 &&
		    f->f3a.simm13 != 1) {
			name = "inc";
			flags = FLG_P1(REG_NONE);
			break;
		}
		break;

	case 0x02:
		/* or */

		if ((dhx->dhx_debug & (DIS_DEBUG_SYN_ALL|DIS_DEBUG_COMPAT))
		    == 0)
			break;

		if ((dhx->dhx_debug & DIS_DEBUG_SYN_ALL) != 0) {
			if (f->f3.rs1 == f->f3.rd) {
				name = "bset";
				flags = FLG_P1(REG_NONE);
				break;
			}
		}

		if (((f->f3.i == 0 && f->f3.rs2 == 0) ||
		    (f->f3.i == 1 && f->f3a.simm13 == 0)) &&
		    (f->f3.rs1 == 0)) {
			name = "clr";
			flags = FLG_P1(REG_NONE)|FLG_P2(REG_NONE)|FLG_NOIMM;
			break;
		}

		if (f->f3.rs1 == 0) {
			name = "mov";
			flags = FLG_P1(REG_NONE);
			break;
		}
		break;

	case 0x04:
		/* sub */

		if ((dhx->dhx_debug & (DIS_DEBUG_SYN_ALL|DIS_DEBUG_COMPAT))
		    == 0)
			break;

		if (f->f3.rs1 == 0 && f->f3.i == 0 && f->f3.rs2 == f->f3.rd) {
			name = "neg";
			flags = FLG_P1(REG_NONE)|FLG_P2(REG_NONE);
			break;
		}

		if (f->f3.rs1 == 0 && f->f3.i == 0 && f->f3.rs2 != f->f3.rd) {
			name = "neg";
			flags = FLG_P1(REG_NONE);
			break;
		}

		if ((dhx->dhx_debug & DIS_DEBUG_SYN_ALL) == 0)
			break;

		if (f->f3.rs1 == f->f3.rd && f->f3.i == 1 &&
		    f->f3a.simm13 == 1) {
			name = "dec";
			flags = FLG_P1(REG_NONE)|FLG_P2(REG_NONE)|FLG_NOIMM;
			break;
		}

		if (f->f3.rs1 == f->f3.rd && f->f3.i == 1 &&
		    f->f3a.simm13 != 1) {
			name = "dec";
			flags = FLG_P1(REG_NONE);
			break;
		}
		break;

	case 0x07:
		/* xnor */

		if ((dhx->dhx_debug & (DIS_DEBUG_SYN_ALL|DIS_DEBUG_COMPAT))
		    == 0)
			break;

		/*
		 * xnor -> not when you have:
		 *	 xnor %rs1, 0x0 or %g0, %rd
		 */
		if ((f->f3.i == 0 && f->f3.rs2 != 0) ||
		    (f->f3.i == 1 && f->f3a.simm13 != 0))
			break;

		name = "not";

		if (f->f3.rs1 == f->f3.rd)
			flags = FLG_P1(REG_NONE)|FLG_P2(REG_NONE)|FLG_NOIMM|
			    FLG_P3(REG_INT);
		else
			flags = FLG_P1(REG_INT)|FLG_P2(REG_NONE)|FLG_NOIMM|
			    FLG_P3(REG_INT);

		break;

	case 0x10:
		/* addcc */

		if ((dhx->dhx_debug & DIS_DEBUG_SYN_ALL) == 0)
			break;

		if (f->f3.rs1 == f->f3.rd && f->f3.i == 1 &&
		    f->f3a.simm13 == 1) {
			name = "inccc";
			flags = FLG_P1(REG_NONE)|FLG_P2(REG_NONE)|FLG_NOIMM;
			break;
		}

		if (f->f3.rs1 == f->f3.rd && f->f3.i == 1 &&
		    f->f3a.simm13 != 1) {
			name = "inccc";
			flags = FLG_P1(REG_NONE);
			break;
		}
		break;

	case 0x11:
		/* andcc */

		if (f->f3.rd != 0)
			break;

		if ((dhx->dhx_debug & (DIS_DEBUG_COMPAT|DIS_DEBUG_SYN_ALL))
		    == 0)
			break;

		if (((dhx->dhx_debug & DIS_DEBUG_COMPAT) != 0) &&
		    ((dhp->dh_flags & (DIS_SPARC_V9|DIS_SPARC_V9_SGI)) == 0))
			break;

		name = "btst";
		flags = FLG_P1(REG_NONE);
		f->f3.rd = f->f3.rs1;
		break;

	case 0x12:
		/* orcc */

		if ((dhx->dhx_debug & (DIS_DEBUG_SYN_ALL|DIS_DEBUG_COMPAT))
		    == 0)
			break;

		if (f->f3.rs1 == 0 && f->f3.rd == 0 && f->f3.i == 0) {
			name = "tst";
			flags = FLG_P1(REG_NONE)|FLG_P3(REG_NONE);
			break;
		}

		if (f->f3.rs2 == 0 && f->f3.rd == 0 && f->f3.i == 0) {
			name = "tst";
			flags = FLG_P2(REG_NONE)|FLG_P3(REG_NONE);
			break;
		}

		break;

	case 0x14:
		/* subcc */

		if ((dhx->dhx_debug & (DIS_DEBUG_SYN_ALL|DIS_DEBUG_COMPAT))
		    == 0)
			break;

		if (f->f3.rd == 0) {
			name = "cmp";
			flags = FLG_P3(REG_NONE);
			break;
		}

		if ((dhx->dhx_debug & DIS_DEBUG_COMPAT) != 0)
			break;

		if (f->f3.rs1 == f->f3.rd && f->f3.i == 1 &&
		    f->f3a.simm13 == 1) {
			name = "deccc";
			flags = FLG_P1(REG_NONE)|FLG_P2(REG_NONE)|FLG_NOIMM;
			break;
		}

		if (f->f3.rs1 == f->f3.rd && f->f3.i == 1 &&
		    f->f3a.simm13 != 1) {
			name = "deccc";
			flags = FLG_P1(REG_NONE);
			break;
		}

		break;

	case 0x25:
	case 0x26:
	case 0x27:
		return (prt_shift(dhp, instr, inp));

	case 0x28:
	case 0x29:
	case 0x2a:
	case 0x2b:
	case 0x30:
	case 0x31:
	case 0x32:
	case 0x33:
		return (dis_fmt_rdwr(dhp, instr, inp, idx));

	case 0x36:
	case 0x37:
		/* NOTE: overlayed on v9 */
		if ((dhp->dh_flags & DIS_SPARC_V8) != 0)
			return (fmt_cpop(dhp, instr, inp));
		break;

	case 0x38:
		/* jmpl */
		return (prt_jmpl(dhp, instr, inp, idx));

	case 0x39:
		/* rett / return */
		prt_name(dhp, name, 1);
		prt_address(dhp, instr, 1);
		return (0);

	case 0x3b:
		/* flush */
		prt_name(dhp, name, 1);
		prt_address(dhp, instr, 0);
		return (0);

	case 0x3c:
	case 0x3d:
		/* save / restore */
		if ((dhx->dhx_debug & (DIS_DEBUG_SYN_ALL|DIS_DEBUG_COMPAT))
		    == 0)
			break;

		if (f->f3.rs1 != 0 || f->f3.rs2 != 0 || f->f3.rd != 0)
			break;

		if (f->f3.i != 0 && ((dhx->dhx_debug & DIS_DEBUG_COMPAT) != 0))
			break;

		prt_name(dhp, name, 0);
		return (0);
	}

	if (FLG_P1_VAL(flags) != REG_NONE || FLG_P2_VAL(flags) != REG_NONE ||
	    FLG_P3_VAL(flags) != REG_NONE)
		arg = 1;

	prt_name(dhp, name, (arg != 0));
	prt_aluargs(dhp, instr, flags);

	return (0);
}

/* ARGSUSED1 */
int
fmt_regwin(dis_handle_t *dhp, uint32_t instr, const inst_t *inp, int idx)
{
	prt_name(dhp, inp->in_data.in_def.in_name, 0);
	return (0);
}

/* ARGSUSED1 */
int
fmt_trap_ret(dis_handle_t *dhp, uint32_t instr, const inst_t *inp, int idx)
{
	ifmt_t *f = (ifmt_t *)&instr;
	prt_name(dhp, inp->in_data.in_def.in_name, 1);

	if (f->f3.rd == 0xf) {
		/* jpriv */
		prt_address(dhp, instr, 1);
	}

	return (0);
}

/* ARGSUSED3 */
int
fmt_movcc(dis_handle_t *dhp, uint32_t instr, const inst_t *inp, int idx)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	ifmt_t *f = (ifmt_t *)&instr;
	const char **regs = NULL;

	if ((dhx->dhx_debug & DIS_DEBUG_PRTFMT) != 0) {
		prt_field("op", f->f3c.op, 2);
		prt_field("op3", f->f3c.op3, 6);
		prt_field("cond", f->f3c.cond, 4);
		prt_field("cc2", f->f3c.cc2, 1);
		prt_field("cc", f->f3c.cc, 2);
		prt_field("i", f->f3c.i, 1);

		if (f->f3c.i == 0)
			prt_field("rs2", f->f3.rs2, 5);
		else
			prt_field("simm11", f->f3c.simm11, 11);

		prt_field("rd", f->f3.rd, 5);
	}

	if (f->f3c.cc2 == 0) {
		regs = fcc_names;
	} else {
		regs = icc_names;
		if (regs[f->f3c.cc] == NULL)
			return (-1);
	}

	prt_name(dhp, inp->in_data.in_def.in_name, 1);

	bprintf(dhp, "%s, ", regs[f->f3c.cc]);

	if (f->f3c.i == 1)
		prt_imm(dhp, sign_extend(f->f3c.simm11, 11), IMM_SIGNED);
	else
		(void) strlcat(dhx->dhx_buf, reg_names[f->f3.rs2],
		    dhx->dhx_buflen);

	bprintf(dhp, ", %s", reg_names[f->f3.rd]);

	return (0);
}

/* ARGSUSED3 */
int
fmt_movr(dis_handle_t *dhp, uint32_t instr, const inst_t *inp, int idx)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	ifmt_t *f = (ifmt_t *)&instr;

	prt_name(dhp, inp->in_data.in_def.in_name, 1);

	bprintf(dhp, "%s, ", reg_names[f->f3d.rs1]);

	if (f->f3d.i == 1)
		prt_imm(dhp, sign_extend(f->f3d.simm10, 10), IMM_SIGNED);
	else
		(void) strlcat(dhx->dhx_buf, reg_names[f->f3.rs2],
		    dhx->dhx_buflen);

	bprintf(dhp, ", %s", reg_names[f->f3.rd]);

	return (0);
}

/* ARGSUSED3 */
int
fmt_fpop1(dis_handle_t *dhp, uint32_t instr, const inst_t *inp, int idx)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	ifmt_t *f = (ifmt_t *)&instr;
	int flags = inp->in_data.in_def.in_flags;

	flags |= FLG_NOIMM;

	if ((dhx->dhx_debug & DIS_DEBUG_PRTFMT) != 0) {
		prt_field("op", f->f3.op, 2);
		prt_field("op3", f->f3.op3, 6);
		prt_field("opf", f->fcmp.opf, 9);
		prt_field("rs1", f->f3.rs1, 5);
		prt_field("rs2", f->f3.rs2, 5);
		prt_field("rd", f->f3.rd, 5);
	}

	prt_name(dhp, inp->in_data.in_def.in_name, 1);
	prt_aluargs(dhp, instr, flags);

	return (0);
}

int
fmt_fpop2(dis_handle_t *dhp, uint32_t instr, const inst_t *inp, int idx)
{
	static const char *condstr_icc[16] = {
		"n", "e",  "le", "l",  "leu", "lu",  "neg", "vs",
		"a", "nz", "g",  "ge", "gu",  "geu", "pos", "vc"
	};

	static const char *condstr_fcc[16] = {
		"n", "nz", "lg", "ul", "l",   "ug", "g",   "u",
		"a", "e",  "ue", "ge", "uge", "le", "ule", "o"
	};

	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	ifmt_t *f = (ifmt_t *)&instr;
	const char *ccstr = "";
	char name[15];

	int flags = inp->in_data.in_def.in_flags;
	int is_cmp = (idx == 0x51 || idx == 0x52 || idx == 0x53 ||
	    idx == 0x55 || idx == 0x56 || idx == 0x57);
	int is_fmov = (idx & 0x3f);
	int is_v9 = ((dhp->dh_flags & (DIS_SPARC_V9|DIS_SPARC_V9_SGI)) != 0);
	int is_compat = ((dhx->dhx_debug & DIS_DEBUG_COMPAT) != 0);

	int p_cc = 0;

	is_fmov = (is_fmov == 0x1 || is_fmov == 0x2 || is_fmov == 0x3);

	if ((dhx->dhx_debug & DIS_DEBUG_PRTFMT) != 0) {
		prt_field("op", f->f3.op, 2);
		prt_field("op3", f->f3.op3, 6);
		prt_field("opf", f->fcmp.opf, 9);

		switch (idx & 0x3f) {
		case 0x51:
		case 0x52:
		case 0x53:
		case 0x55:
		case 0x56:
		case 0x57:
			prt_field("cc", f->fcmp.cc, 2);
			prt_field("rs1", f->f3.rs1, 5);
			prt_field("rs2", f->f3.rs2, 5);
			break;

		case 0x01:
		case 0x02:
		case 0x03:
			prt_field("opf_low", f->fmv.opf, 6);
			prt_field("cond", f->fmv.cond, 4);
			prt_field("opf_cc", f->fmv.cc, 3);
			prt_field("rs2", f->fmv.rs2, 5);
			break;

		default:
			prt_field("rs1", f->f3.rs1, 5);
			prt_field("rs2", f->f3.rs2, 5);
			prt_field("rd", f->f3.rd, 5);
		}
	}

	name[0] = '\0';
	(void) strlcat(name, inp->in_data.in_def.in_name, sizeof (name));

	if (is_fmov != 0) {
		(void) strlcat(name,
		    (f->fmv.cc < 4) ? condstr_fcc[f->fmv.cond]
		    : condstr_icc[f->fmv.cond],
		    sizeof (name));
	}

	prt_name(dhp, name, 1);

	if (is_cmp != 0)
		ccstr = fcc_names[f->fcmp.cc];

	if (is_fmov != 0)
		ccstr = (f->fmv.cc < 4) ? fcc_names[f->fmv.cc & 0x3]
		    : icc_names[f->fmv.cc & 0x3];

	if (ccstr == NULL)
		return (-1);

	p_cc = (is_compat == 0 || is_v9 != 0 ||
	    (is_cmp != 0 && f->fcmp.cc != 0) ||
	    (is_fmov != 0 && f->fmv.cc != 0));

	if (p_cc != 0)
		bprintf(dhp, "%s, ", ccstr);

	prt_aluargs(dhp, instr, flags);

	return (0);
}

int
fmt_vis(dis_handle_t *dhp, uint32_t instr, const inst_t *inp, int idx)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	ifmt_t *f = (ifmt_t *)&instr;
	int flags = inp->in_data.in_def.in_flags;

	if ((dhx->dhx_debug & DIS_DEBUG_PRTFMT) != 0) {
		prt_field("op", f->f3.op, 2);
		prt_field("op3", f->f3.op3, 6);
		prt_field("opf", f->fcmp.opf, 9);

		if (idx == 0x081) {
			prt_field("mode", instr & 02L, 2);
		} else {
			prt_field("rs1", f->f3.rs1, 5);
			prt_field("rs2", f->f3.rs2, 5);
			prt_field("rd", f->f3.rd, 5);
		}
	}

	prt_name(dhp, inp->in_data.in_def.in_name, 1);

	if (idx == 0x081) {
		/* siam */
		bprintf(dhp, "%d", instr & 0x7L);
		return (0);
	}

	prt_aluargs(dhp, instr, flags);

	return (0);
}

/* ARGSUSED3 */
int
fmt_fused(dis_handle_t *dhp, uint32_t instr, const inst_t *inp, int idx)
{
	ifmt_t *f = (ifmt_t *)&instr;
	int flags = inp->in_data.in_def.in_flags;

	prt_name(dhp, inp->in_data.in_def.in_name, 1);
	bprintf(dhp, "%s, %s, %s, %s",
	    get_regname(dhp, FLG_P1_VAL(flags), f->fused.rs1),
	    get_regname(dhp, FLG_P1_VAL(flags), f->fused.rs2),
	    get_regname(dhp, FLG_P1_VAL(flags), f->fused.rs3),
	    get_regname(dhp, FLG_P1_VAL(flags), f->fused.rd));

	return (0);
}
/*
 * put name into the output buffer
 * if add_space !=0, append a space after it
 */
static void
prt_name(dis_handle_t *dhp, const char *name, int add_space)
{
	bprintf(dhp, (add_space == 0) ? "%s" : "%-9s ", name);
}

/*
 * For debugging, print out a field of the instruction
 * field is the name of the field
 * val is the value of the field
 * len is the length of the field (in bits)
 */
#if defined(DIS_STANDALONE)
/* ARGSUSED */
static void
prt_field(const char *field, uint32_t val, int len)
{

}

#else
static void
prt_field(const char *field, uint32_t val, int len)
{
	(void) fprintf(stderr, "DISASM: %8s = 0x%-8x (", field, val);
	prt_binary(val, len);
	(void) fprintf(stderr, ")\n");
}
#endif /* DIS_STANDALONE */

/*
 * sign extend a val (that is 'bits' bits in length) to a 32-bit signed
 * integer
 */
static int32_t
sign_extend(int32_t val, int32_t bits)
{
	if ((val & (1L << (bits - 1))) == 0)
		return (val);

	return ((-1L << bits) | val);
}

/*
 * print out an immediate (i.e. constant) value
 * val is the value
 * format indicates if it is:
 * 0		 Unsigned
 * IMM_SIGNED  A signed value (prepend +/- to the value)
 * IMM_ADDR    Part of an address expression (prepend +/- but with a space
 *		   between the sign and the value for things like [%i1 + 0x55]
 */
static void
prt_imm(dis_handle_t *dhp, uint32_t val, int format)
{
	const char *fmtstr = NULL;
	int32_t sv = (int32_t)val;
	int octal = dhp->dh_flags & DIS_OCTAL;

	switch (format) {
	case IMM_ADDR:
		if (sv < 0) {
			sv = -sv;
			fmtstr = (octal != 0) ? "- 0%lo" : "- 0x%lx";
		} else {
			fmtstr = (octal != 0) ? "+ 0%lo" : "+ 0x%lx";
		}
		break;

	case IMM_SIGNED:
		if (sv < 0) {
			sv = -sv;
			fmtstr = (octal != 0) ? "-0%lo" : "-0x%lx";
			break;
		}
		/* fall through */

	default:
		fmtstr = (octal != 0) ? "0%lo" : "0x%lx";
	}

	bprintf(dhp, fmtstr, sv);
}

/*
 * return the symbolic name of a register
 * regset is one of the REG_* values indicating which type of register it is
 * such as integer, floating point, etc.
 * idx is the numeric value of the register
 *
 * If regset is REG_NONE, an empty, but non-NULL string is returned
 * NULL may be returned if the index indicates an invalid register value
 * such as with the %icc/%xcc sets
 */
static const char *
get_regname(dis_handle_t *dhp, int regset, uint32_t idx)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	const char *regname = NULL;

	switch (regset) {
	case REG_INT:
		regname = reg_names[idx];
		break;

	case REG_FP:
		regname = freg_names[idx];
		break;

	case REG_FPD:
		if (((dhx->dhx_debug & DIS_DEBUG_COMPAT) == 0) ||
		    ((dhp->dh_flags & (DIS_SPARC_V9|DIS_SPARC_V9_SGI)) != 0))
			regname = fdreg_names[idx];
		else
			regname = compat_fdreg_names[idx];

		break;

	case REG_FPQ:
		if ((dhx->dhx_debug & DIS_DEBUG_COMPAT) == 0)
			regname = fqreg_names[idx];
		else
			regname = freg_names[idx];

		break;

	case REG_CP:
		regname = cpreg_names[idx];
		break;

	case REG_ICC:
		regname = icc_names[idx];
		break;

	case REG_FCC:
		regname = fcc_names[idx];
		break;

	case REG_FSR:
		regname = "%fsr";
		break;

	case REG_CSR:
		regname = "%csr";
		break;

	case REG_CQ:
		regname = "%cq";
		break;

	case REG_NONE:
		regname = "";
		break;
	}

	return (regname);
}

/*
 * output the asi value from the instruction
 *
 * TODO: investigate if this should perhaps have a mask -- are undefined ASI
 *	  values for an instruction still disassembled??
 */
static void
prt_asi(dis_handle_t *dhp, uint32_t instr)
{
	ifmt_t *f = (ifmt_t *)&instr;
	int octal = ((dhp->dh_flags & DIS_OCTAL) != 0);

	if (f->f3.i != 0)
		bprintf(dhp, "%%asi");
	else
		bprintf(dhp, (octal != 0) ? "0%03o" : "0x%02x", f->f3.asi);

}

/*
 * put an address expression into the output buffer
 *
 * instr is the instruction to use
 * if nobrackets != 0, [] are not added around the instruction
 *
 * Currently this option is set when printing out the address portion
 * of a jmpl instruction, but otherwise 0 for load/stores
 *
 * If no debug flags are set, the full expression is output, even when
 * %g0 or 0x0 appears in the address
 *
 * If DIS_DEBUG_SYN_ALL or DIS_DEBUG_COMPAT are set, when %g0 or 0x0
 * appear in the address, they are not output.  If the wierd (and probably
 * shouldn't happen) address of [%g0 + %g0] or [%g0 + 0x0] is encountered,
 * [%g0] is output
 */
static void
prt_address(dis_handle_t *dhp, uint32_t instr, int nobrackets)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	ifmt_t *f = (ifmt_t *)&instr;
	int32_t simm13;
	int octal = ((dhp->dh_flags & DIS_OCTAL) != 0);
	int p1 = ((dhx->dhx_debug & (DIS_DEBUG_COMPAT|DIS_DEBUG_SYN_ALL)) == 0);
	int p2 = ((dhx->dhx_debug & (DIS_DEBUG_COMPAT|DIS_DEBUG_SYN_ALL)) == 0);

	if (f->f3a.i == 0) {
		p1 |= ((f->f3a.rs1 != 0) || f->f3.rs2 == 0);
		p2 |= (f->f3.rs2 != 0);

		bprintf(dhp, "%s%s%s%s%s",
		    (nobrackets == 0) ? "[" : "",
		    (p1 != 0) ? reg_names[f->f3a.rs1] : "",
		    (p1 != 0 && p2 != 0) ? " + " : "",
		    (p2 != 0) ? reg_names[f->f3.rs2] : "",
		    (nobrackets == 0) ? "]" : "");
	} else {
		const char *sign;

		simm13 = sign_extend(f->f3a.simm13, 13);
		sign = (simm13 < 0) ? "-" : "+";

		p1 |= (f->f3a.rs1 != 0);
		p2 |= (p1 == 0 || simm13 != 0);

		if (p1 == 0 && simm13 == 0)
			p2 = 1;

		if (p1 == 0 && simm13 >= 0)
			sign = "";

		if (p2 != 0)
			bprintf(dhp,
			    (octal != 0) ? "%s%s%s%s%s0%lo%s" :
			    "%s%s%s%s%s0x%lx%s",
			    (nobrackets == 0) ? "[" : "",
			    (p1 != 0) ? reg_names[f->f3a.rs1] : "",
			    (p1 != 0) ? " " : "",
			    sign,
			    (p1 != 0) ? " " : "",
			    (simm13 < 0) ? -(simm13) : simm13,
			    (nobrackets == 0) ? "]" : "");
		else
			bprintf(dhp, "%s%s%s",
			    (nobrackets == 0) ? "[" : "",
			    reg_names[f->f3a.rs1],
			    (nobrackets == 0) ? "]" : "");
	}
}

/*
 * print out the arguments to an alu operation (add, sub, etc.)
 * conatined in 'instr'
 *
 * alu instructions have the following format:
 *	 %rs1, %rs2, %rd    (i == 0)
 *	 %rs1, 0xnnn, %rd   (i == 1)
 *	   ^	^	^
 *	   |	|	|
 *	  p1    p2	p3
 *
 * flags indicates the register set to use for each position (p1, p2, p3)
 * as well as if immediate values (i == 1) are allowed
 *
 * if flags indicates a specific position has REG_NONE set as it's register
 * set, it is omitted from the output.  This is primarly used for certain
 * floating point operations
 */
static void
prt_aluargs(dis_handle_t *dhp, uint32_t instr, uint32_t flags)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	ifmt_t *f = (ifmt_t *)&instr;
	const char *r1, *r2, *r3;
	int p1, p2, p3;
	unsigned int opf = 0;

	r1 = get_regname(dhp, FLG_P1_VAL(flags), f->f3.rs1);
	r2 = get_regname(dhp, FLG_P2_VAL(flags), f->f3.rs2);
	r3 = get_regname(dhp, FLG_P3_VAL(flags), f->f3.rd);

	p1 = (FLG_P1_VAL(flags) != REG_NONE);
	p2 = (((flags & FLG_NOIMM) == 0) || (FLG_P2_VAL(flags) != REG_NONE));
	p3 = (FLG_RD_VAL(flags) != REG_NONE);

	if (r1 == NULL || r1[0] == '\0')
		p1 = 0;

	if (f->f3a.i == 0 && (r2 == NULL || r2[0] == '\0'))
		p2 = 0;

	if (r3 == NULL || r3[0] == '\0')
		p3 = 0;

	if ((f->fcmp.op == 2) && (f->fcmp.op3 == 0x36) && (f->fcmp.cc != 0))
		opf = f->fcmp.opf;

	if ((opf == 0x151) || (opf == 0x152)) {
		(void) strlcat(dhx->dhx_buf, r3, dhx->dhx_buflen);
		(void) strlcat(dhx->dhx_buf, ", ", dhx->dhx_buflen);
		p3 = 0;
	}

	if (p1 != 0) {
		(void) strlcat(dhx->dhx_buf, r1, dhx->dhx_buflen);
		if (p2 != 0 || p3 != 0)
			(void) strlcat(dhx->dhx_buf, ", ", dhx->dhx_buflen);
	}

	if (p2 != 0) {
		if (f->f3.i == 0 || ((flags & FLG_NOIMM) != 0))
			(void) strlcat(dhx->dhx_buf, r2, dhx->dhx_buflen);
		else
			prt_imm(dhp, sign_extend(f->f3a.simm13, 13),
			    IMM_SIGNED);

		if (p3 != 0)
			(void) strlcat(dhx->dhx_buf, ", ", dhx->dhx_buflen);
	}

	if (p3 != 0)
		(void) strlcat(dhx->dhx_buf, r3, dhx->dhx_buflen);
}

static const char *
get_asi_name(uint8_t asi)
{
	switch (asi) {
		case 0x04:
			return ("ASI_N");

		case 0x0c:
			return ("ASI_NL");

		case 0x10:
			return ("ASI_AIUP");

		case 0x11:
			return ("ASI_AIUS");

		case 0x14:
			return ("ASI_REAL");

		case 0x15:
			return ("ASI_REAL_IO");

		case 0x16:
			return ("ASI_BLK_AIUP");

		case 0x17:
			return ("ASI_BLK_AIUS");

		case 0x18:
			return ("ASI_AIUPL");

		case 0x19:
			return ("ASI_AIUSL");

		case 0x1c:
			return ("ASI_REAL_L");

		case 0x1d:
			return ("ASI_REAL_IO_L");

		case 0x1e:
			return ("ASI_BLK_AIUPL");

		case 0x1f:
			return ("ASI_BLK_AIUS_L");

		case 0x20:
			return ("ASI_SCRATCHPAD");

		case 0x21:
			return ("ASI_MMU_CONTEXTID");

		case 0x22:
			return ("ASI_TWINX_AIUP");

		case 0x23:
			return ("ASI_TWINX_AIUS");

		case 0x25:
			return ("ASI_QUEUE");

		case 0x26:
			return ("ASI_TWINX_R");

		case 0x27:
			return ("ASI_TWINX_N");

		case 0x2a:
			return ("ASI_LDTX_AIUPL");

		case 0x2b:
			return ("ASI_TWINX_AIUS_L");

		case 0x2e:
			return ("ASI_TWINX_REAL_L");

		case 0x2f:
			return ("ASI_TWINX_NL");

		case 0x30:
			return ("ASI_AIPP");

		case 0x31:
			return ("ASI_AIPS");

		case 0x36:
			return ("ASI_AIPN");

		case 0x38:
			return ("ASI_AIPP_L");

		case 0x39:
			return ("ASI_AIPS_L");

		case 0x3e:
			return ("ASI_AIPN_L");

		case 0x41:
			return ("ASI_CMT_SHARED");

		case 0x4f:
			return ("ASI_HYP_SCRATCHPAD");

		case 0x50:
			return ("ASI_IMMU");

		case 0x52:
			return ("ASI_MMU_REAL");

		case 0x54:
			return ("ASI_MMU");

		case 0x55:
			return ("ASI_ITLB_DATA_ACCESS_REG");

		case 0x56:
			return ("ASI_ITLB_TAG_READ_REG");

		case 0x57:
			return ("ASI_IMMU_DEMAP");

		case 0x58:
			return ("ASI_DMMU / ASI_UMMU");

		case 0x5c:
			return ("ASI_DTLB_DATA_IN_REG");

		case 0x5d:
			return ("ASI_DTLB_DATA_ACCESS_REG");

		case 0x5e:
			return ("ASI_DTLB_TAG_READ_REG");

		case 0x5f:
			return ("ASI_DMMU_DEMAP");

		case 0x63:
			return ("ASI_CMT_PER_STRAND / ASI_CMT_PER_CORE");

		case 0x80:
			return ("ASI_P");

		case 0x81:
			return ("ASI_S");

		case 0x82:
			return ("ASI_PNF");

		case 0x83:
			return ("ASI_SNF");

		case 0x88:
			return ("ASI_PL");

		case 0x89:
			return ("ASI_SL");

		case 0x8a:
			return ("ASI_PNFL");

		case 0x8b:
			return ("ASI_SNFL");

		case 0xc0:
			return ("ASI_PST8_P");

		case 0xc1:
			return ("ASI_PST8_S");

		case 0xc2:
			return ("ASI_PST16_P");

		case 0xc3:
			return ("ASI_PST16_S");

		case 0xc4:
			return ("ASI_PST32_P");

		case 0xc5:
			return ("ASI_PST32_S");

		case 0xc8:
			return ("ASI_PST8_PL");

		case 0xc9:
			return ("ASI_PST8_SL");

		case 0xca:
			return ("ASI_PST16_PL");

		case 0xcb:
			return ("ASI_PST16_SL");

		case 0xcc:
			return ("ASI_PST32_PL");

		case 0xcd:
			return ("ASI_PST32_SL");

		case 0xd0:
			return ("ASI_FL8_P");

		case 0xd1:
			return ("ASI_FL8_S");

		case 0xd2:
			return ("ASI_FL16_P");

		case 0xd3:
			return ("ASI_FL16_S");

		case 0xd8:
			return ("ASI_FL8_PL");

		case 0xd9:
			return ("ASI_FL8_SL");

		case 0xda:
			return ("ASI_FL16_PL");

		case 0xdb:
			return ("ASI_FL16_SL");

		case 0xe0:
			return ("ASI_BLK_COMMIT_P");

		case 0xe1:
			return ("ASI_BLK_SOMMIT_S");

		case 0xe2:
			return ("ASI_TWINX_P");

		case 0xe3:
			return ("ASI_TWINX_S");

		case 0xea:
			return ("ASI_TWINX_PL");

		case 0xeb:
			return ("ASI_TWINX_SL");

		case 0xf0:
			return ("ASI_BLK_P");

		case 0xf1:
			return ("ASI_BLK_S");

		case 0xf8:
			return ("ASI_BLK_PL");

		case 0xf9:
			return ("ASI_BLK_SL");

		default:
			return (NULL);
	}
}

/*
 * just a handy function that takes care of managing the buffer length
 * w/ printf
 */

/*
 * PRINTF LIKE 1
 */
static void
bprintf(dis_handle_t *dhp, const char *fmt, ...)
{
	dis_handle_sparc_t *dhx = dhp->dh_arch_private;
	size_t curlen;
	va_list ap;

	curlen = strlen(dhx->dhx_buf);

	va_start(ap, fmt);
	(void) dis_vsnprintf(dhx->dhx_buf + curlen, dhx->dhx_buflen -
	    curlen, fmt, ap);
	va_end(ap);
}
