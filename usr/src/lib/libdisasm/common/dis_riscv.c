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
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * RISC-V Instruction set decoder
 */

#include <libdisasm.h>
#include <sys/byteorder.h>
#include <sys/debug.h>

#include "libdisasm_impl.h"

#include <stdio.h>

extern int strcmp(const char *, const char *);

/*
 * Register names based on their ABI name.
 */
static const char *dis_riscv_regs[32] = {
	"x0", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
	"s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
	"a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
	"s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
};

static const char *dis_riscv_fpregs[32] = {
	"ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7",
	"fs0", "fs1", "fa0", "fa1", "fa2", "fa3", "fa4", "fa5",
	"fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7",
	"fs8", "fs9", "fs10", "fs11", "ft8", "ft9", "ft10", "ft11",
};

static const char *dis_riscv_c_regs[8] = {
	"s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5"
};

static const char *dis_riscv_c_fpregs[8] = {
	"fs0", "fs1", "fa0", "fa1", "fa2", "fa3", "fa4", "fa5"
};

/*
 * RM names have the leading comma in them because the last value represents
 * that the hardware register decides the rounding mode and therefore nothing
 * should be appended to the instruction.
 */
static const char *dis_riscv_rm[8] = {
	",rne", ",rtz", ",rdn", ",rup", ",rmm", ",???", ",???", ""
};

typedef struct dis_riscv_csr {
	uint_t		drc_val;
	const char	*drc_name;
} dis_riscv_csr_t;

/*
 * The current set of CSR names as per Table 2.2-2.5 from RISC-V Privileged
 * Architectures V1.10. These include all of the ones in the User-Level ISA.
 * These are ordered per the doc.
 */
static dis_riscv_csr_t dis_riscv_csr_map[] = {
	/* User Trap */
	{ 0x000, "ustatus" },	{ 0x004, "uie" },	{ 0x005, "utvec" },
	/* User Trap Handling */
	{ 0x040, "uscratch" },	{ 0x041, "uepc" },	{ 0x042, "ucause" },
	{ 0x043, "utval" },	{ 0x044, "uip" },
	/* User Floating-Point CSRs */
	{ 0x001, "fflags" },	{ 0x002, "frm" },	{ 0x003, "fcsr" },
	/* User Counters/Timers */
	{ 0xc00, "cycle" },	{ 0xc01, "time" },	{ 0xc02, "instret" },
	{ 0xc03, "hpmcounter3" },	{ 0xc04, "hpmcounter4" },
	{ 0xc05, "hpmcounter5" },	{ 0xc06, "hpmcounter6" },
	{ 0xc07, "hpmcounter7" },	{ 0xc08, "hpmcounter8" },
	{ 0xc09, "hpmcounter9" },	{ 0xc0a, "hpmcounter10" },
	{ 0xc0b, "hpmcounter11" },	{ 0xc0c, "hpmcounter12" },
	{ 0xc0d, "hpmcounter13" },	{ 0xc0e, "hpmcounter14" },
	{ 0xc0f, "hpmcounter15" },	{ 0xc10, "hpmcounter16" },
	{ 0xc11, "hpmcounter17" },	{ 0xc12, "hpmcounter18" },
	{ 0xc13, "hpmcounter19" },	{ 0xc14, "hpmcounter20" },
	{ 0xc15, "hpmcounter21" },	{ 0xc16, "hpmcounter22" },
	{ 0xc17, "hpmcounter23" },	{ 0xc18, "hpmcounter24" },
	{ 0xc19, "hpmcounter25" },	{ 0xc1a, "hpmcounter26" },
	{ 0xc1b, "hpmcounter27" },	{ 0xc1c, "hpmcounter28" },
	{ 0xc1d, "hpmcounter29" },	{ 0xc1e, "hpmcounter30" },
	{ 0xc1f, "hpmcounter31" },
	{ 0xc80, "cycleh" },	{ 0xc81, "timeh" },	{ 0xc82, "instreth" },
	{ 0xc83, "hpmcounter3h" },	{ 0xc84, "hpmcounter4h" },
	{ 0xc85, "hpmcounter5h" },	{ 0xc86, "hpmcounter6h" },
	{ 0xc87, "hpmcounter7h" },	{ 0xc88, "hpmcounter8h" },
	{ 0xc89, "hpmcounter9h" },	{ 0xc8a, "hpmcounter10h" },
	{ 0xc8b, "hpmcounter11h" },	{ 0xc8c, "hpmcounter12h" },
	{ 0xc8d, "hpmcounter13h" },	{ 0xc8e, "hpmcounter14h" },
	{ 0xc8f, "hpmcounter15h" },	{ 0xc90, "hpmcounter16h" },
	{ 0xc91, "hpmcounter17h" },	{ 0xc92, "hpmcounter18h" },
	{ 0xc93, "hpmcounter19h" },	{ 0xc94, "hpmcounter20h" },
	{ 0xc95, "hpmcounter21h" },	{ 0xc96, "hpmcounter22h" },
	{ 0xc97, "hpmcounter23h" },	{ 0xc98, "hpmcounter24h" },
	{ 0xc99, "hpmcounter25h" },	{ 0xc9a, "hpmcounter26h" },
	{ 0xc9b, "hpmcounter27h" },	{ 0xc9c, "hpmcounter28h" },
	{ 0xc9d, "hpmcounter29h" },	{ 0xc9e, "hpmcounter30h" },
	{ 0xc9f, "hpmcounter31h" },
	/* Supervisor Trap Status */
	{ 0x100, "sstatus" },	{ 0x102, "sedeleg" },	{ 0x103, "sideleg" },
	{ 0x104, "sie" },	{ 0x105, "stvec" },	{ 0x106, "scounteren" },
	/* Supervisor Trap Handling */
	{ 0x140, "sscratch" },	{ 0x141, "sepc" },	{ 0x142, "scause" },
	{ 0x143, "stval" },	{ 0x144, "sip" },
	/* Supervisor Protection and Translation */
	{ 0x180, "satp" },
	/* Machine Information Registers */
	{ 0xf11, "mvendorid" },	{ 0xf12, "marchid" },
	{ 0xf13, "mimpid" },	{ 0xf14, "mhartid" },
	/* Machine Trap Setup */
	{ 0x300, "mstatus" },	{ 0x301, "misa" },	{ 0x302, "medeleg" },
	{ 0x303, "mideleg" },	{ 0x304, "mie" },	{ 0x305, "mtvec" },
	{ 0x306, "mcounteren" },
	/* Machine Trap Handling */
	{ 0x340, "mscratch" },	{ 0x341, "mepc" },	{ 0x342, "mcause" },
	{ 0x343, "mtval" },	{ 0x344, "mip" },
	/* Machine Protection and Translation */
	{ 0x3a0, "pmpcfg0" },	{ 0x3a1, "pmpcfg1" },
	{ 0x3a2, "pmpcfg2" },	{ 0x3a3, "pmpcfg3" },
	{ 0x3b0, "pmpaddr0" },	{ 0x3b1, "pmpaddr1" },
	{ 0x3b2, "pmpaddr2" },	{ 0x3b3, "pmpaddr3" },
	{ 0x3b4, "pmpaddr4" },	{ 0x3b5, "pmpaddr5" },
	{ 0x3b6, "pmpaddr6" },	{ 0x3b7, "pmpaddr7" },
	{ 0x3b8, "pmpaddr8" },	{ 0x3b9, "pmpaddr9" },
	{ 0x3ba, "pmpaddr10" },	{ 0x3bb, "pmpaddr11" },
	{ 0x3bc, "pmpaddr12" },	{ 0x3bd, "pmpaddr13" },
	{ 0x3be, "pmpaddr14" },	{ 0x3bf, "pmpaddr15" }
};

typedef enum dis_riscv_csr_alias_type {
	DIS_RISCV_CSR_READ,
	DIS_RISCV_CSR_READ_GEN,
	DIS_RISCV_CSR_SWAP,
	DIS_RISCV_CSR_SWAP_IMM,
	DIS_RISCV_CSR_WRITE,
	DIS_RISCV_CSR_WRITE_GEN,
	DIS_RISCV_CSR_WRITE_IMM,
	DIS_RISCV_CSR_WRITE_IMM_GEN
} dis_riscv_csr_alias_type_t;

typedef struct dis_riscv_csr_alias {
	const char *drca_alias;
	dis_riscv_csr_alias_type_t drca_type;
	const char *drca_base;
	const char *drca_csr;
	int drca_rd;
	int drca_rs;
} dis_riscv_csr_alias_t;

/*
 * Table of aliases. A NULL or -1 indicates a don't care.
 */
static dis_riscv_csr_alias_t dis_riscv_csr_alias[] = {
	{ "rdinstret", DIS_RISCV_CSR_READ, "csrrs", "instret", -1, 0 },
	{ "rdinstreth", DIS_RISCV_CSR_READ, "csrrs", "instreth", -1, 0 },
	{ "rdcycle", DIS_RISCV_CSR_READ, "csrrs", "cycle", -1, 0 },
	{ "rdcycleh", DIS_RISCV_CSR_READ, "csrrs", "cycleh", -1, 0 },
	{ "rdtime", DIS_RISCV_CSR_READ, "csrrs", "time", -1, 0 },
	{ "rdtimeh", DIS_RISCV_CSR_READ, "csrrs", "timeh", -1, 0 },
	{ "frcsr", DIS_RISCV_CSR_READ, "csrrs", "fcsr", -1, 0 },
	{ "fscsr", DIS_RISCV_CSR_WRITE, "csrrw", "fcsr", 0, -1 },
	{ "fscsr", DIS_RISCV_CSR_SWAP, "csrrw", "fcsr", -1, -1 },
	{ "frrm", DIS_RISCV_CSR_READ, "csrrs", "frm", -1, 0 },
	{ "fsrm", DIS_RISCV_CSR_WRITE, "csrrw", "frm", 0, -1 },
	{ "fsrm", DIS_RISCV_CSR_SWAP, "csrrw", "frm", -1, -1 },
	{ "fsrmi", DIS_RISCV_CSR_WRITE_IMM, "csrrwi", "frm", 0, -1 },
	{ "fsrmi", DIS_RISCV_CSR_SWAP_IMM, "csrrwi", "frm", -1, -1 },
	{ "frflags", DIS_RISCV_CSR_READ, "csrrs", "fflags", -1, 0 },
	{ "fsflags", DIS_RISCV_CSR_WRITE, "csrrw", "fflags", 0, -1 },
	{ "fsflags", DIS_RISCV_CSR_SWAP, "csrrw", "fflags", -1, -1 },
	{ "fsflagsi", DIS_RISCV_CSR_WRITE_IMM, "csrrwi", "fflags", 0, -1 },
	{ "fsflagsi", DIS_RISCV_CSR_SWAP_IMM, "csrrwi", "fflags", -1, -1 },
	/*
	 * These are the generic aliases that aren't based on the CSR. Keep
	 * them last.
	 */
	{ "csrr", DIS_RISCV_CSR_READ_GEN, "csrrs", NULL, -1, 0 },
	{ "csrw", DIS_RISCV_CSR_WRITE_GEN, "csrrw", NULL, 0, -1 },
	{ "csrs", DIS_RISCV_CSR_WRITE_GEN, "csrrs", NULL, 0, -1 },
	{ "csrc", DIS_RISCV_CSR_WRITE_GEN, "csrrc", NULL, 0, -1 },
	{ "csrwi", DIS_RISCV_CSR_WRITE_IMM_GEN, "csrrwi", NULL, 0, -1 },
	{ "csrsi", DIS_RISCV_CSR_WRITE_IMM_GEN, "csrrsi", NULL, 0, -1 },
	{ "csrci", DIS_RISCV_CSR_WRITE_IMM_GEN, "csrrci", NULL, 0, -1 },
};

/*
 * Take an n-bit value whose sign bit is indicated by the big sign and convert
 * to a signed type.
 */
static uint_t
dis_riscv_sign_extend(uint_t val, uint_t sbit, const char **sign)
{
	VERIFY3U(sbit, <=, 31);

	if (val >= 1 << sbit) {
		*sign = "-";
		return ((1 << (sbit + 1)) - val);
	} else {
		*sign = "";
		return (val);
	}
}

/*
 * Four byte decode tables. This is derived from the RV32/64G Instruction Set
 * Listings. We describe a table entry based on the opcode and optional opcodes
 * based on the type of instruction that it is and its encoding format. Most
 * sets of instructions have one of several uniform encoding types.
 *
 *  31             25 24     20 19  15 14    12  11        7  6      0
 * |    funct7       |   r2    |  rs1 | funct3 | rd          | opcode | R-type
 * |    imm[11:0]              |  rs1 | funct3 | rd          | opcode | I-type
 * |    imm[11:5]    |   r2    |  rs1 | funct3 | imm[4:0]    | opcode | S-type
 * |    imm[12|10:5] |   r2    |  rs1 | funct3 | imm[4:1|11] | opcode | B-type
 * |    imm[31:12]                             | rd          | opcode | U-type
 * |    imm[10|10:1|11|19:12]                  | rd          | opcode | J-type
 */
typedef enum dis_riscv_itype {
	DIS_RISCV_I_R_TYPE,
	DIS_RISCV_I_I_TYPE,
	DIS_RISCV_I_S_TYPE,
	DIS_RISCV_I_B_TYPE,
	DIS_RISCV_I_U_TYPE,
	DIS_RISCV_I_J_TYPE,
	DIS_RISCV_I_R4_TYPE,
	/*
	 * This is a variant of the standard R type where the first bit of
	 * funct7 is actually used for this shift.
	 */
	DIS_RISCV_I_SHIFT64_TYPE,
	/*
	 * This type isn't explicitly defined in the ISA doc; however, it is a
	 * standard format that is for all of the Atomic class instructions.
	 * This is treated like an R-type, except the funct7 is really a funct5.
	 * The load variant is similar; however, rs2 must be zero.
	 */
	DIS_RISCV_I_RV32A_TYPE,
	DIS_RISCV_I_RV32A_LOAD_TYPE,
	/*
	 * This is a custom type we've defined where the first value is the
	 * instruction mask and the second value is the value of the bits in it.
	 * This is used for a few irregular instructions ala FENCE and ECALL.
	 */
	DIS_RISCV_I_MASK_TYPE,
	/*
	 * This type is used for FP arguments that use rs2 as an opcode.
	 */
	DIS_RISCV_I_FP_RS2OP_TYPE,
	/*
	 * This type uses the opcode and funct7 and uses funct3 as a rounding
	 * mode argument.
	 */
	DIS_RISCV_I_FP_RM_TYPE,
	/*
	 * This fp type uses the opcode, funct7, funct3, and rs2 as an op type.
	 */
	DIS_RISCV_I_FP_R_RS2_TYPE,
} dis_riscv_itype_t;

#define	DIS_RISCV_OPCODE(x)	((x) & 0x7f)
#define	DIS_RISCV_FUNCT3(x)	(((x) >> 12) & 0x7)
#define	DIS_RISCV_FUNCT7(x)	(((x) >> 25) & 0x7f)
#define	DIS_RISCV_RD(x)		(((x) >> 7) & 0x1f)
#define	DIS_RISCV_RS1(x)	(((x) >> 15) & 0x1f)
#define	DIS_RISCV_RS2(x)	(((x) >> 20) & 0x1f)
#define	DIS_RISCV_FP_RS3(x)	(((x) >> 27) & 0x1f)
#define	DIS_RISCV_FUNCT2(x)	(((x) >> 25) & 0x03)

/*
 * SHIFT funct7 variant.
 */
#define	DIS_RISCV_SFUNCT7(x)	(((x) >> 26) & 0x3f)

#define	DIS_RISCV_UIMM(x)	(((x) >> 12) & 0xfffff)

#define	DIS_RISCV_IIMM(x)	(((x) >> 20) & 0xfff)

#define	DIS_RISCV_BIMM_12(x)	(((x) >> 19) & 0x1000)
#define	DIS_RISCV_BIMM_11(x)	(((x) & 0x80) << 4)
#define	DIS_RISCV_BIMM_10_5(x)	(((x) >> 20) & 0x7e0)
#define	DIS_RISCV_BIMM_4_1(x)	(((x) >> 7) & 0x1e)

#define	DIS_RISCV_SIMM_UP(x)	((((x) >> 25) & 0x7f) << 5)
#define	DIS_RISCV_SIMM_LOW(x)	(((x) >> 7) & 0x1f)

#define	DIS_RISCV_JIMM_20(x)	(((x) & 0x80000000) >> 11)
#define	DIS_RISCV_JIMM_19_12(x)	((x) & 0xff000)
#define	DIS_RISCV_JIMM_11(x)	(((x) & 100000) >> 9)
#define	DIS_RISCV_JIMM_10_1(x)	(((x) & 0x7fe00000) >> 20)

#define	DIS_RISCV_RVA_FUNCT5(x)	(((x) >> 27) & 0x1f)
#define	DIS_RISCV_RVA_AQ(x)	(((x) >> 26) & 0x1)
#define	DIS_RISCV_RVA_RL(x)	(((x) >> 25) & 0x1)

struct dis_riscv_instr;
typedef void (*dis_riscv_func_t)(dis_handle_t *, uint32_t,
    struct dis_riscv_instr *, char *, size_t);

typedef struct dis_riscv_instr {
	const char 		*drv_name;
	dis_riscv_itype_t	drv_type;
	dis_riscv_func_t	drv_print;
	uint_t			drv_opcode;
	uint_t			drv_funct3;
	uint_t			drv_funct7;
	uint_t			drv_funct2;
} dis_riscv_instr_t;

/*ARGSUSED*/
static void
dis_riscv_rtype_32(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	(void) dis_snprintf(buf, buflen, "%s %s,%s,%s", table->drv_name,
	    dis_riscv_regs[DIS_RISCV_RD(instr)],
	    dis_riscv_regs[DIS_RISCV_RS1(instr)],
	    dis_riscv_regs[DIS_RISCV_RS2(instr)]);
}

static void
dis_riscv_itype_32(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	const char *s;
	uint_t imm = dis_riscv_sign_extend(DIS_RISCV_IIMM(instr), 11, &s);

	if ((dhp->dh_flags & DIS_OCTAL) != 0) {
		(void) dis_snprintf(buf, buflen, "%s %s,%s,%s0%o",
		    table->drv_name, dis_riscv_regs[DIS_RISCV_RD(instr)],
		    dis_riscv_regs[DIS_RISCV_RS1(instr)], s, imm);
	} else {
		(void) dis_snprintf(buf, buflen, "%s %s,%s,%s0x%x",
		    table->drv_name, dis_riscv_regs[DIS_RISCV_RD(instr)],
		    dis_riscv_regs[DIS_RISCV_RS1(instr)], s, imm);
	}
}

static void
dis_riscv_btype_32(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	const char *s;
	uint_t bimm = DIS_RISCV_BIMM_12(instr) | DIS_RISCV_BIMM_11(instr) |
	    DIS_RISCV_BIMM_10_5(instr) | DIS_RISCV_BIMM_4_1(instr);
	uint_t imm = dis_riscv_sign_extend(bimm, 12, &s);

	if ((dhp->dh_flags & DIS_OCTAL) != 0) {
		(void) dis_snprintf(buf, buflen, "%s %s,%s,%s0%o",
		    table->drv_name, dis_riscv_regs[DIS_RISCV_RD(instr)],
		    dis_riscv_regs[DIS_RISCV_RS1(instr)], s, imm);
	} else {
		(void) dis_snprintf(buf, buflen, "%s %s,%s,%s0x%x",
		    table->drv_name, dis_riscv_regs[DIS_RISCV_RD(instr)],
		    dis_riscv_regs[DIS_RISCV_RS1(instr)], s, imm);
	}
}

static void
dis_riscv_load(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	const char *s;
	uint_t imm = dis_riscv_sign_extend(DIS_RISCV_IIMM(instr), 11, &s);

	if ((dhp->dh_flags & DIS_OCTAL) != 0) {
		(void) dis_snprintf(buf, buflen, "%s %s,%s0%o(%s)",
		    table->drv_name, dis_riscv_regs[DIS_RISCV_RD(instr)],
		    s, imm, dis_riscv_regs[DIS_RISCV_RS1(instr)]);
	} else {
		(void) dis_snprintf(buf, buflen, "%s %s,%s0x%x(%s)",
		    table->drv_name, dis_riscv_regs[DIS_RISCV_RD(instr)],
		    s, imm, dis_riscv_regs[DIS_RISCV_RS1(instr)]);
	}
}

static void
dis_riscv_stype_32(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	const char *s;
	uint_t simm = DIS_RISCV_SIMM_UP(instr) | DIS_RISCV_SIMM_LOW(instr);
	uint_t val = dis_riscv_sign_extend(simm, 11, &s);

	if ((dhp->dh_flags & DIS_OCTAL) != 0) {
		(void) dis_snprintf(buf, buflen, "%s %s,%s0%o(%s)",
		    table->drv_name, dis_riscv_regs[DIS_RISCV_RS2(instr)],
		    s, val, dis_riscv_regs[DIS_RISCV_RS1(instr)]);
	} else {
		(void) dis_snprintf(buf, buflen, "%s %s,%s0x%x(%s)",
		    table->drv_name, dis_riscv_regs[DIS_RISCV_RS2(instr)],
		    s, val, dis_riscv_regs[DIS_RISCV_RS1(instr)]);
	}
}

/*ARGSUSED*/
static void
dis_riscv_utype_32(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	(void) dis_snprintf(buf, buflen, "%s %s,0x%x", table->drv_name,
	    dis_riscv_regs[DIS_RISCV_RD(instr)], DIS_RISCV_UIMM(instr));
}

static void
dis_riscv_jtype_32(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	const char *s;
	uint_t jimm = DIS_RISCV_JIMM_20(instr) | DIS_RISCV_JIMM_19_12(instr) |
	    DIS_RISCV_JIMM_11(instr) | DIS_RISCV_JIMM_10_1(instr);
	uint_t imm = dis_riscv_sign_extend(jimm, 20, &s);

	if ((dhp->dh_flags & DIS_OCTAL) != 0) {
		(void) dis_snprintf(buf, buflen, "%s %s,%s0%o",
		    table->drv_name, dis_riscv_regs[DIS_RISCV_RD(instr)],
		    s, imm);
	} else {
		(void) dis_snprintf(buf, buflen, "%s %s,%s0x%x",
		    table->drv_name, dis_riscv_regs[DIS_RISCV_RD(instr)],
		    s, imm);
	}
}

/*
 * The shift instructions are a variant on the R-type instructions where RS2 is
 * an immediate to perform the shift by as opposed to a register.
 */
static void
dis_riscv_shift_32(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	if ((dhp->dh_flags & DIS_OCTAL) != 0) {
		(void) dis_snprintf(buf, buflen, "%s %s,%s,0%o",
		    table->drv_name, dis_riscv_regs[DIS_RISCV_RD(instr)],
		    dis_riscv_regs[DIS_RISCV_RS1(instr)], DIS_RISCV_RS2(instr));
	} else {
		(void) dis_snprintf(buf, buflen, "%s %s,%s,0x%x",
		    table->drv_name, dis_riscv_regs[DIS_RISCV_RD(instr)],
		    dis_riscv_regs[DIS_RISCV_RS1(instr)], DIS_RISCV_RS2(instr));
	}
}

/*
 * The 64-bit version of shift instructions steals an extra bit from funct7 to
 * construct the shift amount.
 */
static void
dis_riscv_shift_64(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	uint_t shift = DIS_RISCV_RS2(instr) | ((instr & (1UL << 25)) >> 20);
	if ((dhp->dh_flags & DIS_OCTAL) != 0) {
		(void) dis_snprintf(buf, buflen, "%s %s,%s,0%o",
		    table->drv_name, dis_riscv_regs[DIS_RISCV_RD(instr)],
		    dis_riscv_regs[DIS_RISCV_RS1(instr)], shift);
	} else {
		(void) dis_snprintf(buf, buflen, "%s %s,%s,0x%x",
		    table->drv_name, dis_riscv_regs[DIS_RISCV_RD(instr)],
		    dis_riscv_regs[DIS_RISCV_RS1(instr)], shift);
	}
}

/*ARGSUSED*/
static void
dis_riscv_csr(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	uint_t rd, csr, rs, i;
	const char *csrstr = NULL;
	char csrval[32];
	dis_riscv_csr_alias_t *alias = NULL;

	rd = DIS_RISCV_RD(instr);
	rs = DIS_RISCV_RS1(instr);
	csr = DIS_RISCV_IIMM(instr);

	for (i = 0; i < ARRAY_SIZE(dis_riscv_csr_map); i++) {
		if (csr == dis_riscv_csr_map[i].drc_val) {
			csrstr = dis_riscv_csr_map[i].drc_name;
			break;
		}
	}

	if (csrstr == NULL) {
		(void) dis_snprintf(csrval, sizeof (csrval), "0x%x", csr);
		csrstr = csrval;
	}

	for (i = 0; i < ARRAY_SIZE(dis_riscv_csr_alias); i++) {
		dis_riscv_csr_alias_t *a = &dis_riscv_csr_alias[i];
		if (strcmp(a->drca_base, table->drv_name) != 0)
			continue;
		if (a->drca_csr != NULL && strcmp(a->drca_csr, csrstr) != 0)
			continue;
		if (a->drca_rd != -1 && a->drca_rd != rd)
			continue;
		if (a->drca_rs != -1 && a->drca_rs != rs)
			continue;
		alias = a;
		break;
	}

	if (alias == NULL) {
		(void) dis_snprintf(buf, buflen, "%s %s,%s,%s", table->drv_name,
		    dis_riscv_regs[rd], csrstr, dis_riscv_regs[rs]);
		return;
	}

	switch (alias->drca_type) {
	case DIS_RISCV_CSR_READ:
		(void) dis_snprintf(buf, buflen, "%s %s", alias->drca_alias,
		    dis_riscv_regs[rd]);
		break;
	case DIS_RISCV_CSR_READ_GEN:
		(void) dis_snprintf(buf, buflen, "%s %s,%s", alias->drca_alias,
		    dis_riscv_regs[rd], csrstr);
		break;
	case DIS_RISCV_CSR_SWAP:
		(void) dis_snprintf(buf, buflen, "%s %s,%s", alias->drca_alias,
		    dis_riscv_regs[rd], dis_riscv_regs[rs]);
		break;
	case DIS_RISCV_CSR_WRITE:
		(void) dis_snprintf(buf, buflen, "%s %s", alias->drca_alias,
		    dis_riscv_regs[rs]);
		break;
	case DIS_RISCV_CSR_WRITE_GEN:
		(void) dis_snprintf(buf, buflen, "%s %s,%s", alias->drca_alias,
		    csrstr, dis_riscv_regs[rs]);
		break;
	default:
		(void) dis_snprintf(buf, buflen, "<unknown>");
		break;
	}
}

static void
dis_riscv_csri(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	uint_t rd, csr, imm, i;
	const char *csrstr = NULL;
	char csrval[32];
	dis_riscv_csr_alias_t *alias = NULL;

	rd = DIS_RISCV_RD(instr);
	imm = DIS_RISCV_RS1(instr);
	csr = DIS_RISCV_IIMM(instr);

	for (i = 0; i < ARRAY_SIZE(dis_riscv_csr_map); i++) {
		if (csr == dis_riscv_csr_map[i].drc_val) {
			csrstr = dis_riscv_csr_map[i].drc_name;
			break;
		}
	}

	if (csrstr == NULL) {
		(void) dis_snprintf(csrval, sizeof (csrval), "0x%x", csr);
		csrstr = csrval;
	}

	for (i = 0; i < ARRAY_SIZE(dis_riscv_csr_alias); i++) {
		dis_riscv_csr_alias_t *a = &dis_riscv_csr_alias[i];
		if (strcmp(a->drca_base, table->drv_name) != 0)
			continue;
		if (a->drca_csr != NULL && strcmp(a->drca_csr, csrstr) != 0)
			continue;
		if (a->drca_rd != -1 && a->drca_rd != rd)
			continue;
		if (a->drca_rs != -1)
			continue;
		alias = a;
		break;
	}

	if (alias == NULL) {
		if ((dhp->dh_flags & DIS_OCTAL) != 0) {
			(void) dis_snprintf(buf, buflen, "%s %s,%s,0%o",
			    table->drv_name, dis_riscv_regs[rd], csrstr, imm);
		} else {
			(void) dis_snprintf(buf, buflen, "%s %s,%s,0x%x",
			    table->drv_name, dis_riscv_regs[rd], csrstr, imm);
		}
		return;
	}

	switch (alias->drca_type) {
	case DIS_RISCV_CSR_SWAP_IMM:
		if ((dhp->dh_flags & DIS_OCTAL) != 0) {
			(void) dis_snprintf(buf, buflen, "%s %s,0%o",
			    alias->drca_alias, dis_riscv_regs[rd], imm);
		} else {
			(void) dis_snprintf(buf, buflen, "%s %s,0x%x",
			    alias->drca_alias, dis_riscv_regs[rd], imm);
		}
		break;
	case DIS_RISCV_CSR_WRITE_IMM:
		if ((dhp->dh_flags & DIS_OCTAL) != 0) {
			(void) dis_snprintf(buf, buflen, "%s 0%o",
			    alias->drca_alias, imm);
		} else {
			(void) dis_snprintf(buf, buflen, "%s 0x%x",
			    alias->drca_alias, imm);
		}
		break;
	case DIS_RISCV_CSR_WRITE_IMM_GEN:
		if ((dhp->dh_flags & DIS_OCTAL) != 0) {
			(void) dis_snprintf(buf, buflen, "%s %s,0%o",
			    alias->drca_alias, csrstr, imm);
		} else {
			(void) dis_snprintf(buf, buflen, "%s %s,0x%x",
			    alias->drca_alias, csrstr, imm);
		}
		break;
	default:
		(void) dis_snprintf(buf, buflen, "<unknown>");
		break;
	}
}

#define	DIS_RISCV_FENCE_PRED(x)	(((x) >> 24) & 0xf)
#define	DIS_RISCV_FENCE_SUCC(x)	(((x) >> 20) & 0xf)
#define	DIS_RISCV_FENCE_I	0x8
#define	DIS_RISCV_FENCE_O	0x4
#define	DIS_RISCV_FENCE_R	0x2
#define	DIS_RISCV_FENCE_W	0x1
#define	DIS_RISCV_FENCE_IORW	0xf

/*ARGSUSED*/
static void
dis_riscv_fence(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	uint_t pred, succ;

	pred = DIS_RISCV_FENCE_PRED(instr);
	succ = DIS_RISCV_FENCE_SUCC(instr);

	/*
	 * If both halves are iorw that is aliased to just an empty fence
	 * instruction per Chapter 20 - RISC-V Assembly Programmer's Handbook in
	 * the RISC-V user spec.
	 */
	if (pred == DIS_RISCV_FENCE_IORW && succ == DIS_RISCV_FENCE_IORW) {
		(void) dis_snprintf(buf, buflen, "%s", table->drv_name);
		return;
	}

	(void) dis_snprintf(buf, buflen, "%s %s%s%s%s, %s%s%s%s",
	    table->drv_name,
	    pred & DIS_RISCV_FENCE_I ? "i" : "",
	    pred & DIS_RISCV_FENCE_O ? "o" : "",
	    pred & DIS_RISCV_FENCE_R ? "r" : "",
	    pred & DIS_RISCV_FENCE_W ? "w" : "",
	    succ & DIS_RISCV_FENCE_I ? "i" : "",
	    succ & DIS_RISCV_FENCE_O ? "o" : "",
	    succ & DIS_RISCV_FENCE_R ? "r" : "",
	    succ & DIS_RISCV_FENCE_W ? "w" : "");
}

/*ARGSUSED*/
static void
dis_riscv_name(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	(void) dis_snprintf(buf, buflen, "%s", table->drv_name);
}

/*ARGSUSED*/
static void
dis_riscv_rs1_rs2(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	(void) dis_snprintf(buf, buflen, "%s %s,%s", table->drv_name,
	    dis_riscv_regs[DIS_RISCV_RS1(instr)],
	    dis_riscv_regs[DIS_RISCV_RS2(instr)]);
}

/*ARGSUSED*/
static void
dis_riscv_rv32a_load(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_instr_t *table, char *buf, size_t buflen)
{
	const char *suffix = "";

	if (DIS_RISCV_RVA_AQ(instr) && DIS_RISCV_RVA_RL(instr)) {
		suffix = ".aqrl";
	} else if (DIS_RISCV_RVA_AQ(instr)) {
		suffix = ".aq";
	} else if (DIS_RISCV_RVA_RL(instr)) {
		suffix = ".rl";
	}

	(void) dis_snprintf(buf, buflen, "%s%s %s,(%s)", table->drv_name,
	    suffix, dis_riscv_regs[DIS_RISCV_RD(instr)],
	    dis_riscv_regs[DIS_RISCV_RS1(instr)]);
}

/*ARGSUSED*/
static void
dis_riscv_rv32a(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	const char *suffix = "";

	if (DIS_RISCV_RVA_AQ(instr) && DIS_RISCV_RVA_RL(instr)) {
		suffix = ".aqrl";
	} else if (DIS_RISCV_RVA_AQ(instr)) {
		suffix = ".aq";
	} else if (DIS_RISCV_RVA_RL(instr)) {
		suffix = ".rl";
	}

	(void) dis_snprintf(buf, buflen, "%s%s %s,%s,(%s)", table->drv_name,
	    suffix, dis_riscv_regs[DIS_RISCV_RD(instr)],
	    dis_riscv_regs[DIS_RISCV_RS2(instr)],
	    dis_riscv_regs[DIS_RISCV_RS1(instr)]);
}

static void
dis_riscv_fp_load(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	const char *s;
	uint_t imm = dis_riscv_sign_extend(DIS_RISCV_IIMM(instr), 11, &s);

	if ((dhp->dh_flags & DIS_OCTAL) != 0) {
		(void) dis_snprintf(buf, buflen, "%s %s,%s0%o(%s)",
		    table->drv_name, dis_riscv_fpregs[DIS_RISCV_RD(instr)],
		    s, imm, dis_riscv_regs[DIS_RISCV_RS1(instr)]);
	} else {
		(void) dis_snprintf(buf, buflen, "%s %s,%s0x%x(%s)",
		    table->drv_name, dis_riscv_fpregs[DIS_RISCV_RD(instr)],
		    s, imm, dis_riscv_regs[DIS_RISCV_RS1(instr)]);
	}
}

static void
dis_riscv_fp_store(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	const char *s;
	uint_t simm = DIS_RISCV_SIMM_UP(instr) | DIS_RISCV_SIMM_LOW(instr);
	uint_t val = dis_riscv_sign_extend(simm, 11, &s);

	if ((dhp->dh_flags & DIS_OCTAL) != 0) {
		(void) dis_snprintf(buf, buflen, "%s %s,%s0%o(%s)",
		    table->drv_name, dis_riscv_fpregs[DIS_RISCV_RS2(instr)],
		    s, val, dis_riscv_regs[DIS_RISCV_RS1(instr)]);
	} else {
		(void) dis_snprintf(buf, buflen, "%s %s,%s0x%x(%s)",
		    table->drv_name, dis_riscv_fpregs[DIS_RISCV_RS2(instr)],
		    s, val, dis_riscv_regs[DIS_RISCV_RS1(instr)]);
	}
}

/*ARGSUSED*/
static void
dis_riscv_fp_r(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	(void) dis_snprintf(buf, buflen, "%s %s,%s,%s", table->drv_name,
	    dis_riscv_fpregs[DIS_RISCV_RD(instr)],
	    dis_riscv_fpregs[DIS_RISCV_RS1(instr)],
	    dis_riscv_fpregs[DIS_RISCV_RS2(instr)]);
}

/*
 * Variant of fp_r type that goes to integer destination registers.
 */
/*ARGSUSED*/
static void
dis_riscv_fp_r_fpi(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	(void) dis_snprintf(buf, buflen, "%s %s,%s,%s", table->drv_name,
	    dis_riscv_regs[DIS_RISCV_RD(instr)],
	    dis_riscv_fpregs[DIS_RISCV_RS1(instr)],
	    dis_riscv_fpregs[DIS_RISCV_RS2(instr)]);
}

/*ARGSUSED*/
static void
dis_riscv_fp_r4(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	(void) dis_snprintf(buf, buflen, "%s %s,%s,%s,%s%s", table->drv_name,
	    dis_riscv_fpregs[DIS_RISCV_RD(instr)],
	    dis_riscv_fpregs[DIS_RISCV_RS1(instr)],
	    dis_riscv_fpregs[DIS_RISCV_RS2(instr)],
	    dis_riscv_fpregs[DIS_RISCV_FP_RS3(instr)],
	    dis_riscv_rm[DIS_RISCV_FUNCT3(instr)]);
}

/*ARGSUSED*/
static void
dis_riscv_fp_rs2_fp(dis_handle_t *dhp, uint32_t instr, dis_riscv_instr_t *table,
    char *buf, size_t buflen)
{
	(void) dis_snprintf(buf, buflen, "%s %s,%s%s", table->drv_name,
	    dis_riscv_fpregs[DIS_RISCV_RD(instr)],
	    dis_riscv_fpregs[DIS_RISCV_RS1(instr)],
	    dis_riscv_rm[DIS_RISCV_FUNCT3(instr)]);
}

/*ARGSUSED*/
static void
dis_riscv_fp_rs2_fp_nr(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_instr_t *table, char *buf, size_t buflen)
{
	(void) dis_snprintf(buf, buflen, "%s %s,%s", table->drv_name,
	    dis_riscv_fpregs[DIS_RISCV_RD(instr)],
	    dis_riscv_fpregs[DIS_RISCV_RS1(instr)]);
}

/*ARGSUSED*/
static void
dis_riscv_fp_rs2_fpi(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_instr_t *table, char *buf, size_t buflen)
{
	(void) dis_snprintf(buf, buflen, "%s %s,%s%s", table->drv_name,
	    dis_riscv_regs[DIS_RISCV_RD(instr)],
	    dis_riscv_fpregs[DIS_RISCV_RS1(instr)],
	    dis_riscv_rm[DIS_RISCV_FUNCT3(instr)]);
}

/*ARGSUSED*/
static void
dis_riscv_fp_rs2_ifp(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_instr_t *table, char *buf, size_t buflen)
{
	(void) dis_snprintf(buf, buflen, "%s %s,%s%s", table->drv_name,
	    dis_riscv_fpregs[DIS_RISCV_RD(instr)],
	    dis_riscv_regs[DIS_RISCV_RS1(instr)],
	    dis_riscv_rm[DIS_RISCV_FUNCT3(instr)]);
}

/*ARGSUSED*/
static void
dis_riscv_fp_rs2_fpi_nr(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_instr_t *table, char *buf, size_t buflen)
{
	(void) dis_snprintf(buf, buflen, "%s %s,%s", table->drv_name,
	    dis_riscv_regs[DIS_RISCV_RD(instr)],
	    dis_riscv_fpregs[DIS_RISCV_RS1(instr)]);
}

/*ARGSUSED*/
static void
dis_riscv_fp_rs2_ifp_nr(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_instr_t *table, char *buf, size_t buflen)
{
	(void) dis_snprintf(buf, buflen, "%s %s,%s", table->drv_name,
	    dis_riscv_fpregs[DIS_RISCV_RD(instr)],
	    dis_riscv_regs[DIS_RISCV_RS1(instr)]);
}


/*ARGSUSED*/
static void
dis_riscv_fp_rm(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_instr_t *table, char *buf, size_t buflen)
{
	(void) dis_snprintf(buf, buflen, "%s %s,%s,%s%s", table->drv_name,
	    dis_riscv_fpregs[DIS_RISCV_RD(instr)],
	    dis_riscv_fpregs[DIS_RISCV_RS1(instr)],
	    dis_riscv_fpregs[DIS_RISCV_RS2(instr)],
	    dis_riscv_rm[DIS_RISCV_FUNCT3(instr)]);
}

#define	DIS_RISCV_R32(str, op, f3, f7)	\
	{ str, DIS_RISCV_I_R_TYPE, dis_riscv_rtype_32, op, f3, f7 }
#define	DIS_RISCV_I32(str, op, f3)	\
	{ str, DIS_RISCV_I_I_TYPE, dis_riscv_itype_32, op, f3 }
#define	DIS_RISCV_S32(str, op, f3)	\
	{ str, DIS_RISCV_I_S_TYPE, dis_riscv_stype_32, op, f3 }
#define	DIS_RISCV_B32(str, op, f3)	\
	{ str, DIS_RISCV_I_B_TYPE, dis_riscv_btype_32, op, f3 }
#define	DIS_RISCV_U32(str, op)		\
	{ str, DIS_RISCV_I_U_TYPE, dis_riscv_utype_32, op }
#define	DIS_RISCV_J32(str, op)		\
	{ str, DIS_RISCV_I_J_TYPE, dis_riscv_jtype_32, op }

/*
 * These are non-standard types that we've defined because they require
 * different handling.
 */
#define	DIS_RISCV_SHIFT32(str, op, f3, f7)	\
	{ str, DIS_RISCV_I_R_TYPE, dis_riscv_shift_32, op, f3, f7 }
#define	DIS_RISCV_SHIFT64(str, op, f3, f7)	\
	{ str, DIS_RISCV_I_SHIFT64_TYPE, dis_riscv_shift_64, op, f3, f7 }
#define	DIS_RISCV_CSR(str, op, f3)		\
	{ str, DIS_RISCV_I_I_TYPE, dis_riscv_csr, op, f3 }
#define	DIS_RISCV_CSRI(str, op, f3)		\
	{ str, DIS_RISCV_I_I_TYPE, dis_riscv_csri, op, f3 }
#define	DIS_RISCV_LOAD(str, op, f3)		\
	{ str, DIS_RISCV_I_I_TYPE, dis_riscv_load, op, f3 }

#define	DIS_RISCV_MASK(str, mask, val, func)	\
	{ str, DIS_RISCV_I_MASK_TYPE, func, mask, val }


/*
 * Atomic-extension specific entries
 */
#define	DIS_RISCV_A32(str, op, f3, f5)		\
	{ str, DIS_RISCV_I_RV32A_TYPE, dis_riscv_rv32a, op, f3, f5 }
#define	DIS_RISCV_A32LOAD(str, op, f3, f5, f2)	\
	{ str, DIS_RISCV_I_RV32A_LOAD_TYPE, dis_riscv_rv32a_load, op, f3, \
	    f5, f2 }

/*
 * Floating-point specific entries
 */
#define	DIS_RISCV_FP_LOAD(str, op, f3)				\
	{ str, DIS_RISCV_I_I_TYPE, dis_riscv_fp_load, op, f3 }
#define	DIS_RISCV_FP_STORE(str, op, f3)				\
	{ str, DIS_RISCV_I_S_TYPE, dis_riscv_fp_store, op, f3 }
#define	DIS_RISCV_FP_R(str, op, f3, f7)				\
	{ str, DIS_RISCV_I_R_TYPE, dis_riscv_fp_r, op, f3, f7 }
#define	DIS_RISCV_FP_R4(str, op, f2)				\
	{ str, DIS_RISCV_I_R4_TYPE, dis_riscv_fp_r4, op, 0, 0, f2 }
#define	DIS_RISCV_FP_RS2_FP(str, op, rs2, f7)			\
	{ str, DIS_RISCV_I_FP_RS2OP_TYPE, dis_riscv_fp_rs2_fp, op, rs2, f7 }
#define	DIS_RISCV_FP_RS2_FP_NR(str, op, rs2, f7)		\
	{ str, DIS_RISCV_I_FP_RS2OP_TYPE, dis_riscv_fp_rs2_fp_nr, op, rs2, f7 }
#define	DIS_RISCV_FP_RS2_FPI(str, op, rs2, f7)			\
	{ str, DIS_RISCV_I_FP_RS2OP_TYPE, dis_riscv_fp_rs2_fpi, op, rs2, f7 }
#define	DIS_RISCV_FP_RS2_IFP(str, op, rs2, f7)			\
	{ str, DIS_RISCV_I_FP_RS2OP_TYPE, dis_riscv_fp_rs2_ifp, op, rs2, f7 }
#define	DIS_RISCV_FP_RS2_IFP_NR(str, op, rs2, f7)		\
	{ str, DIS_RISCV_I_FP_RS2OP_TYPE, dis_riscv_fp_rs2_ifp_nr, op, rs2, f7 }
#define	DIS_RISCV_FP_RM(str, op, f7)				\
	{ str, DIS_RISCV_I_FP_RM_TYPE, dis_riscv_fp_rm, op, 0, f7 }
#define	DIS_RISCV_FP_R_RS2_FPI(str, op, f3, rs2, f7)		\
	{ str, DIS_RISCV_I_FP_R_RS2_TYPE, dis_riscv_fp_rs2_fpi, op, f3, f7, \
	    rs2 }
#define	DIS_RISCV_FP_R_RS2_IFP(str, op, f3, rs2, f7)		\
	{ str, DIS_RISCV_I_FP_R_RS2_TYPE, dis_riscv_fp_rs2_ifp, op, f3, f7, \
	    rs2 }
#define	DIS_RISCV_FP_R_RS2_FPI_NR(str, op, f3, rs2, f7)		\
	{ str, DIS_RISCV_I_FP_R_RS2_TYPE, dis_riscv_fp_rs2_fpi_nr, op, f3, \
	    f7, rs2 }
#define	DIS_RISCV_FP_R_RS2_IFP_NR(str, op, f3, rs2, f7)		\
	{ str, DIS_RISCV_I_FP_R_RS2_TYPE, dis_riscv_fp_rs2_ifp_nr, op, f3, \
	    f7, rs2 }
#define	DIS_RISCV_FP_RI(str, op, f3, f7) 			\
	{ str, DIS_RISCV_I_R_TYPE, dis_riscv_fp_r_fpi, op, f3, f7 }

/*
 * This table is ordered such that it follows the ordering in the RISC-V ISA
 * Manual.
 */
static dis_riscv_instr_t dis_riscv_4byte[] = {
	/*
	 * RV32I
	 */
	DIS_RISCV_U32("lui", 0x37),
	DIS_RISCV_U32("auipc", 0x17),
	DIS_RISCV_J32("jal", 0x6f),
	/* ret is a special case of jalr */
	DIS_RISCV_MASK("ret", 0xffffffff, 0x00008067, dis_riscv_name),
	DIS_RISCV_I32("jalr", 0x67, 0x0),
	DIS_RISCV_B32("beq", 0x63, 0x0),
	DIS_RISCV_B32("bne", 0x63, 0x1),
	DIS_RISCV_B32("blt", 0x63, 0x4),
	DIS_RISCV_B32("bge", 0x63, 0x5),
	DIS_RISCV_B32("bltu", 0x63, 0x6),
	DIS_RISCV_B32("bgeu", 0x63, 0x7),
	DIS_RISCV_LOAD("lb", 0x03, 0x0),
	DIS_RISCV_LOAD("lh", 0x03, 0x1),
	DIS_RISCV_LOAD("lw", 0x03, 0x2),
	DIS_RISCV_LOAD("lbu", 0x03, 0x4),
	DIS_RISCV_LOAD("lhu", 0x03, 0x5),
	DIS_RISCV_S32("sb", 0x23, 0x0),
	DIS_RISCV_S32("sh", 0x23, 0x1),
	DIS_RISCV_S32("sw", 0x23, 0x2),
	/* nop is addi x0, x0, 0 */
	DIS_RISCV_MASK("nop", 0xffffffff, 0x00000013, dis_riscv_name),
	DIS_RISCV_I32("addi", 0x13, 0x0),
	DIS_RISCV_I32("slti", 0x13, 0x2),
	DIS_RISCV_I32("sltiu", 0x13, 0x3),
	DIS_RISCV_I32("xori", 0x13, 0x4),
	DIS_RISCV_I32("ori", 0x13, 0x6),
	DIS_RISCV_I32("andi", 0x13, 0x7),
	DIS_RISCV_SHIFT32("slli", 0x13, 0x1, 0x00),
	DIS_RISCV_SHIFT32("srli", 0x13, 0x5, 0x00),
	DIS_RISCV_SHIFT32("srai", 0x13, 0x5, 0x20),
	DIS_RISCV_R32("add", 0x33, 0x0, 0x00),
	DIS_RISCV_R32("sub", 0x33, 0x0, 0x20),
	DIS_RISCV_R32("sll", 0x33, 0x1, 0x00),
	DIS_RISCV_R32("slt", 0x33, 0x2, 0x00),
	DIS_RISCV_R32("sltu", 0x33, 0x3, 0x00),
	DIS_RISCV_R32("xor", 0x33, 0x4, 0x00),
	DIS_RISCV_R32("srl", 0x33, 0x5, 0x00),
	DIS_RISCV_R32("sra", 0x33, 0x5, 0x20),
	DIS_RISCV_R32("or", 0x33, 0x6, 0x00),
	DIS_RISCV_R32("and", 0x33, 0x7, 0x00),
	DIS_RISCV_MASK("fence", 0xf00fffff, 0xf, dis_riscv_fence),
	DIS_RISCV_MASK("fence.i", 0xfffff00f, 0x100f, dis_riscv_name),
	DIS_RISCV_MASK("ecall", 0xffffffff, 0x73, dis_riscv_name),
	DIS_RISCV_MASK("ebreak", 0xffffffff, 0x100073, dis_riscv_name),
	DIS_RISCV_CSR("csrrw", 0x73, 0x1),
	DIS_RISCV_CSR("csrrs", 0x73, 0x2),
	DIS_RISCV_CSR("csrrc", 0x73, 0x3),
	DIS_RISCV_CSRI("csrrwi", 0x73, 0x5),
	DIS_RISCV_CSRI("csrrsi", 0x73, 0x6),
	DIS_RISCV_CSRI("csrrci", 0x73, 0x7),
	/*
	 * RV64I
	 */
	DIS_RISCV_LOAD("lwu", 0x03, 0x6),
	DIS_RISCV_LOAD("ld", 0x03, 0x3),
	DIS_RISCV_S32("sd", 0x23, 0x3),
	DIS_RISCV_SHIFT64("slli", 0x13, 0x1, 0x0),
	DIS_RISCV_SHIFT64("srli", 0x13, 0x5, 0x0),
	DIS_RISCV_SHIFT64("srai", 0x13, 0x5, 0x10),
	DIS_RISCV_I32("addiw", 0x1b, 0x0),
	DIS_RISCV_SHIFT32("slliw", 0x1b, 0x1, 0x0),
	DIS_RISCV_SHIFT32("srliw", 0x1b, 0x5, 0x0),
	DIS_RISCV_SHIFT32("sraiw", 0x1b, 0x5, 0x20),
	DIS_RISCV_R32("addw", 0x3b, 0x0, 0x00),
	DIS_RISCV_R32("subw", 0x3b, 0x0, 0x20),
	DIS_RISCV_R32("sllw", 0x3b, 0x1, 0x00),
	DIS_RISCV_R32("srlw", 0x3b, 0x5, 0x00),
	DIS_RISCV_R32("sraw", 0x3b, 0x5, 0x20),
	/*
	 * RV32M
	 */
	DIS_RISCV_R32("mul", 0x33, 0x0, 0x01),
	DIS_RISCV_R32("mulh", 0x33, 0x1, 0x01),
	DIS_RISCV_R32("mulhsu", 0x33, 0x2, 0x01),
	DIS_RISCV_R32("mulhu", 0x33, 0x3, 0x01),
	DIS_RISCV_R32("div", 0x33, 0x4, 0x01),
	DIS_RISCV_R32("divu", 0x33, 0x5, 0x01),
	DIS_RISCV_R32("rem", 0x33, 0x6, 0x01),
	DIS_RISCV_R32("remu", 0x33, 0x7, 0x01),
	/*
	 * RV64M
	 */
	DIS_RISCV_R32("mulw", 0x3b, 0x0, 0x01),
	DIS_RISCV_R32("divw", 0x3b, 0x4, 0x01),
	DIS_RISCV_R32("divuw", 0x3b, 0x5, 0x01),
	DIS_RISCV_R32("remw", 0x3b, 0x6, 0x01),
	DIS_RISCV_R32("remuw", 0x3b, 0x7, 0x01),
	/*
	 * RV32A
	 */
	DIS_RISCV_A32LOAD("lr.w", 0x2f, 0x2, 0x02, 0x0),
	DIS_RISCV_A32("sc.w", 0x2f, 0x2, 0x03),
	DIS_RISCV_A32("amoswap.w", 0x2f, 0x2, 0x01),
	DIS_RISCV_A32("amoadd.w", 0x2f, 0x2, 0x00),
	DIS_RISCV_A32("amoxor.w", 0x2f, 0x2, 0x04),
	DIS_RISCV_A32("amoand.w", 0x2f, 0x2, 0x0c),
	DIS_RISCV_A32("amoor.w", 0x2f, 0x2, 0x08),
	DIS_RISCV_A32("amomin.w", 0x2f, 0x2, 0x10),
	DIS_RISCV_A32("amomax.w", 0x2f, 0x2, 0x14),
	DIS_RISCV_A32("amominu.w", 0x2f, 0x2, 0x18),
	DIS_RISCV_A32("amomaxu.w", 0x2f, 0x2, 0x1c),
	/*
	 * RV64A
	 */
	DIS_RISCV_A32LOAD("lr.d", 0x2f, 0x3, 0x02, 0x0),
	DIS_RISCV_A32("sc.d", 0x2f, 0x3, 0x03),
	DIS_RISCV_A32("amoswap.d", 0x2f, 0x3, 0x01),
	DIS_RISCV_A32("amoadd.d", 0x2f, 0x3, 0x00),
	DIS_RISCV_A32("amoxor.d", 0x2f, 0x3, 0x04),
	DIS_RISCV_A32("amoand.d", 0x2f, 0x3, 0x0c),
	DIS_RISCV_A32("amoor.d", 0x2f, 0x3, 0x08),
	DIS_RISCV_A32("amomin.d", 0x2f, 0x3, 0x10),
	DIS_RISCV_A32("amomax.d", 0x2f, 0x3, 0x14),
	DIS_RISCV_A32("amominu.d", 0x2f, 0x3, 0x18),
	DIS_RISCV_A32("amomaxu.d", 0x2f, 0x3, 0x1c),
	/*
	 * RV32F
	 */
	DIS_RISCV_FP_LOAD("flw", 0x07, 0x2),
	DIS_RISCV_FP_STORE("fsw", 0x27, 0x2),
	DIS_RISCV_FP_R4("fmadd.s", 0x43, 0x0),
	DIS_RISCV_FP_R4("fmsub.s", 0x47, 0x0),
	DIS_RISCV_FP_R4("fnmsub.s", 0x4b, 0x0),
	DIS_RISCV_FP_R4("fnmadd.s", 0x4f, 0x0),
	DIS_RISCV_FP_RM("fadd.s", 0x53, 0x00),
	DIS_RISCV_FP_RM("fsub.s", 0x53, 0x04),
	DIS_RISCV_FP_RM("fmul.s", 0x53, 0x08),
	DIS_RISCV_FP_RM("fdiv.s", 0x53, 0xc),
	DIS_RISCV_FP_RS2_FP("fsqrt.s", 0x53, 0x00, 0x2c),
	DIS_RISCV_FP_R("fsgnj.s", 0x53, 0x0, 0x10),
	DIS_RISCV_FP_R("fsgnjn.s", 0x53, 0x1, 0x10),
	DIS_RISCV_FP_R("fsgnjx.s", 0x53, 0x2, 0x10),
	DIS_RISCV_FP_R("fmin.s", 0x53, 0x0, 0x14),
	DIS_RISCV_FP_R("fmax.s", 0x53, 0x1, 0x14),
	DIS_RISCV_FP_RS2_FPI("fcvt.w.s", 0x53, 0x00, 0x60),
	DIS_RISCV_FP_RS2_FPI("fcvt.wu.s", 0x53, 0x01, 0x60),
	DIS_RISCV_FP_R_RS2_FPI_NR("fmv.x.w", 0x53, 0x00, 0x00, 0x70),
	DIS_RISCV_FP_RI("feq.s", 0x53, 0x2, 0x50),
	DIS_RISCV_FP_RI("flt.s", 0x53, 0x1, 0x50),
	DIS_RISCV_FP_RI("fle.s", 0x53, 0x0, 0x50),
	DIS_RISCV_FP_R_RS2_FPI_NR("fclass.s", 0x53, 0x1, 0x00, 0x70),
	DIS_RISCV_FP_RS2_IFP("fcvt.s.w", 0x53, 0x00, 0x68),
	DIS_RISCV_FP_RS2_IFP("fcvt.s.wu", 0x53, 0x01, 0x68),
	DIS_RISCV_FP_R_RS2_IFP_NR("fmv.w.x", 0x53, 0x0, 0x00, 0x78),
	/*
	 * RV64F
	 */
	DIS_RISCV_FP_RS2_FPI("fcvt.l.s", 0x53, 0x02, 0x60),
	DIS_RISCV_FP_RS2_FPI("fcvt.lu.s", 0x53, 0x03, 0x60),
	DIS_RISCV_FP_RS2_IFP("fcvt.s.l", 0x53, 0x02, 0x68),
	DIS_RISCV_FP_RS2_IFP("fcvt.s.lu", 0x53, 0x03, 0x68),
	/*
	 * RV32D
	 */
	DIS_RISCV_FP_LOAD("fld", 0x07, 0x3),
	DIS_RISCV_FP_STORE("fsd", 0x27, 0x3),
	DIS_RISCV_FP_R4("fmadd.d", 0x43, 0x1),
	DIS_RISCV_FP_R4("fmsub.d", 0x47, 0x1),
	DIS_RISCV_FP_R4("fnmsub.d", 0x4b, 0x1),
	DIS_RISCV_FP_R4("fnmadd.d", 0x4f, 0x1),
	DIS_RISCV_FP_RM("fadd.d", 0x53, 0x01),
	DIS_RISCV_FP_RM("fsub.d", 0x53, 0x05),
	DIS_RISCV_FP_RM("fmul.d", 0x53, 0x09),
	DIS_RISCV_FP_RM("fdiv.d", 0x53, 0xd),
	DIS_RISCV_FP_RS2_FP("fsqrt.d", 0x53, 0x00, 0x2d),
	DIS_RISCV_FP_R("fsgnj.d", 0x53, 0x0, 0x11),
	DIS_RISCV_FP_R("fsgnjn.d", 0x53, 0x1, 0x11),
	DIS_RISCV_FP_R("fsgnjx.d", 0x53, 0x2, 0x11),
	DIS_RISCV_FP_R("fmin.d", 0x53, 0x0, 0x15),
	DIS_RISCV_FP_R("fmax.d", 0x53, 0x1, 0x15),
	DIS_RISCV_FP_RS2_FP("fcvt.s.d", 0x53, 0x01, 0x20),
	DIS_RISCV_FP_RS2_FP_NR("fcvt.d.s", 0x53, 0x00, 0x21),
	DIS_RISCV_FP_RI("feq.d", 0x53, 0x2, 0x51),
	DIS_RISCV_FP_RI("flt.d", 0x53, 0x1, 0x51),
	DIS_RISCV_FP_RI("fle.d", 0x53, 0x0, 0x51),
	DIS_RISCV_FP_R_RS2_FPI_NR("fclass.d", 0x53, 0x1, 0x00, 0x71),
	DIS_RISCV_FP_RS2_FPI("fcvt.w.d", 0x53, 0x00, 0x61),
	DIS_RISCV_FP_RS2_FPI("fcvt.wu.d", 0x53, 0x01, 0x61),
	DIS_RISCV_FP_RS2_IFP_NR("fcvt.d.w", 0x53, 0x00, 0x69),
	DIS_RISCV_FP_RS2_IFP_NR("fcvt.d.wu", 0x53, 0x01, 0x69),
	/*
	 * RV64D
	 */
	DIS_RISCV_FP_RS2_FPI("fcvt.l.d", 0x53, 0x02, 0x61),
	DIS_RISCV_FP_RS2_FPI("fcvt.lu.d", 0x53, 0x03, 0x61),
	DIS_RISCV_FP_R_RS2_FPI_NR("fmv.x.d", 0x53, 0x0, 0x00, 0x71),
	DIS_RISCV_FP_RS2_IFP("fcvt.d.l", 0x53, 0x02, 0x69),
	DIS_RISCV_FP_RS2_IFP("fcvt.d.lu", 0x53, 0x03, 0x69),
	DIS_RISCV_FP_R_RS2_IFP_NR("fmv.d.x", 0x53, 0x0, 0x00, 0x79),
	/*
	 * Privileged Instructions from RISC-V Privileged Architectures V1.10.
	 */
	DIS_RISCV_MASK("uret", 0xffffffff, 0x00200073, dis_riscv_name),
	DIS_RISCV_MASK("sret", 0xffffffff, 0x10200073, dis_riscv_name),
	DIS_RISCV_MASK("mret", 0xffffffff, 0x30200073, dis_riscv_name),
	DIS_RISCV_MASK("wfi", 0xffffffff, 0x10500073, dis_riscv_name),
	DIS_RISCV_MASK("sfence.vma", 0xfe007fff, 0x12000073, dis_riscv_rs1_rs2)
};

static void
dis_riscv_decode_4byte(dis_handle_t *dhp, uint32_t instr, char *buf,
    size_t buflen)
{
	uint_t i;

	for (i = 0; i < ARRAY_SIZE(dis_riscv_4byte); i++) {
		dis_riscv_instr_t *t = &dis_riscv_4byte[i];
		switch (t->drv_type) {
		case DIS_RISCV_I_R_TYPE:
			if (DIS_RISCV_OPCODE(instr) == t->drv_opcode &&
			    DIS_RISCV_FUNCT3(instr) == t->drv_funct3 &&
			    DIS_RISCV_FUNCT7(instr) == t->drv_funct7) {
				break;
			}
			continue;
		case DIS_RISCV_I_I_TYPE:
		case DIS_RISCV_I_S_TYPE:
		case DIS_RISCV_I_B_TYPE:
			if (DIS_RISCV_OPCODE(instr) == t->drv_opcode &&
			    DIS_RISCV_FUNCT3(instr) == t->drv_funct3) {
				break;
			}
			continue;
		case DIS_RISCV_I_U_TYPE:
		case DIS_RISCV_I_J_TYPE:
			if (DIS_RISCV_OPCODE(instr) == t->drv_opcode) {
				break;
			}
			continue;
		case DIS_RISCV_I_R4_TYPE:
			if (DIS_RISCV_OPCODE(instr) == t->drv_opcode &&
			    DIS_RISCV_FUNCT2(instr) == t->drv_funct2) {
				break;
			}
			continue;
		case DIS_RISCV_I_MASK_TYPE:
			if ((instr & t->drv_opcode) == t->drv_funct3) {
				break;
			}
			continue;
		case DIS_RISCV_I_SHIFT64_TYPE:
			if (DIS_RISCV_OPCODE(instr) == t->drv_opcode &&
			    DIS_RISCV_FUNCT3(instr) == t->drv_funct3 &&
			    DIS_RISCV_SFUNCT7(instr) == t->drv_funct7) {
				break;
			}
			continue;

		case DIS_RISCV_I_RV32A_LOAD_TYPE:
			if (DIS_RISCV_OPCODE(instr) == t->drv_opcode &&
			    DIS_RISCV_FUNCT3(instr) == t->drv_funct3 &&
			    DIS_RISCV_RVA_FUNCT5(instr) == t->drv_funct7 &&
			    DIS_RISCV_RS2(instr) == t->drv_funct2) {
				break;
			}
			continue;
		case DIS_RISCV_I_RV32A_TYPE:
			if (DIS_RISCV_OPCODE(instr) == t->drv_opcode &&
			    DIS_RISCV_FUNCT3(instr) == t->drv_funct3 &&
			    DIS_RISCV_RVA_FUNCT5(instr) == t->drv_funct7) {
				break;
			}
			continue;
		case DIS_RISCV_I_FP_RS2OP_TYPE:
			if (DIS_RISCV_OPCODE(instr) == t->drv_opcode &&
			    DIS_RISCV_RS2(instr) == t->drv_funct3 &&
			    DIS_RISCV_FUNCT7(instr) == t->drv_funct7) {
				break;
			}
			continue;
		case DIS_RISCV_I_FP_RM_TYPE:
			if (DIS_RISCV_OPCODE(instr) == t->drv_opcode &&
			    DIS_RISCV_FUNCT7(instr) == t->drv_funct7) {
				break;
			}
			continue;
		case DIS_RISCV_I_FP_R_RS2_TYPE:
			if (DIS_RISCV_OPCODE(instr) == t->drv_opcode &&
			    DIS_RISCV_FUNCT3(instr) == t->drv_funct3 &&
			    DIS_RISCV_RS2(instr) == t->drv_funct2 &&
			    DIS_RISCV_FUNCT7(instr) == t->drv_funct7) {
				break;
			}
			continue;
		default:
			continue;
		}

		t->drv_print(dhp, instr, t, buf, buflen);
		return;
	}

	(void) dis_snprintf(buf, buflen, "<unknown>");
}

/*
 * Two byte decode table types.
 */
typedef enum dis_riscv_ctype {
	/*
	 * Indicates that we should match based on the opcode and funct3.
	 */
	DIS_RISCV_C_FUNCT3,
	/*
	 * Indicates that we should match the instruction based on a mask.
	 */
	DIS_RISCV_C_MATCH
} dis_riscv_ctype_t;

/*
 * The compact forms are depending on the elf class. This is used to keep track
 * of the class and match it.
 */
typedef enum dis_riscv_c_class {
	DIS_RISCV_CL_ALL,
	DIS_RISCV_CL_32,
	DIS_RISCV_CL_64,
	DIS_RISCV_CL_32_64,
	DIS_RISCV_CL_64_128
} dis_riscv_c_class_t;

struct dis_riscv_c_instr;
typedef void (*dis_riscv_c_func_t)(dis_handle_t *, uint32_t,
    struct dis_riscv_c_instr *, char *, size_t);

typedef struct dis_riscv_c_instr {
	const char		*drv_c_name;
	dis_riscv_ctype_t	drv_c_type;
	dis_riscv_c_func_t	drv_c_print;
	dis_riscv_c_class_t 	drv_c_class;
	uint_t			drv_c_opcode;
	uint_t			drv_c_funct;
	uint_t			drv_c_mask;
	uint_t			drv_c_match;
} dis_riscv_c_instr_t;

#define	DIS_RISCV_C_OPCODE(x)	((x) & 0x03)
#define	DIS_RISCV_C_FUNCT3(x)	(((x) & 0xe000) >> 13)

#define	DIS_RISCV_C_RS1(x)	(((x) & 0x0f80) >> 7)
#define	DIS_RISCV_C_RS2(x)	(((x) & 0x007c) >> 2)
#define	DIS_RISCV_C_RD(x)	DIS_RISCV_C_RS1(x)

#define	DIS_RISCV_C_RS1P(x)	(((x) & 0x0380) >> 7)
#define	DIS_RISCV_C_RS2P(x)	DIS_RISCV_C_RDP(x)
#define	DIS_RISCV_C_RDP(x)	(((x) & 0x001c) >> 2)

/*
 * CJ format immediate extractor
 */
#define	DIS_RISCV_C_J_11(x)	(((x) & 0x1000) >> 1)
#define	DIS_RISCV_C_J_4(x)	(((x) & 0x0800) >> 7)
#define	DIS_RISCV_C_J_9_8(x)	(((x) & 0x0600) >> 1)
#define	DIS_RISCV_C_J_10(x)	(((x) & 0x0100) << 2)
#define	DIS_RISCV_C_J_6(x)	(((x) & 0x0080) >> 1)
#define	DIS_RISCV_C_J_7(x)	(((x) & 0x0040) << 1)
#define	DIS_RISCV_C_J_3_1(x)	(((x) & 0x0038) >> 3)
#define	DIS_RISCV_C_J_5(x)	(((x) & 0x0004) << 3)

/*
 * Compact Branch extractor
 */
#define	DIS_RISCV_C_B_8(x)	(((x) & 0x1000) >> 4)
#define	DIS_RISCV_C_B_4_3(x)	(((x) & 0x0c00) >> 7)
#define	DIS_RISCV_C_B_7_6(x)	(((x) & 0x0060) << 1)
#define	DIS_RISCV_C_B_2_1(x)	(((x) & 0x0018) >> 2)
#define	DIS_RISCV_C_B_5(x)	(((x) & 0x0004) << 3)

/*
 * c.addi16spn extractor
 */
#define	DIS_RISCV_C_A16_9(x)	(((x) & 0x1000) >> 3)
#define	DIS_RISCV_C_A16_4(x)	(((x) & 0x0040) >> 2)
#define	DIS_RISCV_C_A16_6(x)	(((x) & 0x0020) << 1)
#define	DIS_RISCV_C_A16_8_7(x)	(((x) & 0x0018) << 4)
#define	DIS_RISCV_C_A16_5(x)	(((x) & 0x0004) << 3)

/*
 * c.addi4spn extractor
 */
#define	DIS_RISCV_C_A4_5_4(x)	(((x) & 0x1800) >> 7)
#define	DIS_RISCV_C_A4_9_6(x)	(((x) & 0x0700) >> 2)
#define	DIS_RISCV_C_A4_2(x)	(((x) & 0x0040) >> 4)
#define	DIS_RISCV_C_A4_3(x)	(((x) & 0x0020) >> 2)

/*ARGSUSED*/
static void
dis_riscv_c_name(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	(void) dis_snprintf(buf, buflen, "%s", table->drv_c_name);
}

static void
dis_riscv_c_loadstore(dis_handle_t *dhp, const char *name, const char *dreg,
    const char *sreg, uint32_t off, char *buf, size_t buflen)
{

	if ((dhp->dh_flags & DIS_OCTAL) != 0) {
		(void) dis_snprintf(buf, buflen, "%s %s,0%o(%s)", name, dreg,
		    off, sreg);
	} else {
		(void) dis_snprintf(buf, buflen, "%s %s,0x%x(%s)", name, dreg,
		    off, sreg);
	}
}

static void
dis_riscv_c_lwsp(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	uint32_t imm = ((instr & 0x000c) << 4) |
	    ((instr & 0x1000) >> 7) | ((instr & 0x0070) >> 2);

	dis_riscv_c_loadstore(dhp, table->drv_c_name,
	    dis_riscv_regs[DIS_RISCV_C_RD(instr)], dis_riscv_regs[2], imm, buf,
	    buflen);
}

static void
dis_riscv_c_ldsp(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	uint32_t imm = ((instr & 0x001c) << 4) |
	    ((instr & 0x1000) >> 7) | ((instr & 0x0060) >> 2);

	dis_riscv_c_loadstore(dhp, table->drv_c_name,
	    dis_riscv_regs[DIS_RISCV_C_RD(instr)], dis_riscv_regs[2],
	    imm, buf, buflen);
}

static void
dis_riscv_c_flwsp(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	uint32_t imm = ((instr & 0x000c) << 4) |
	    ((instr & 0x1000) >> 7) | ((instr & 0x0070) >> 2);

	dis_riscv_c_loadstore(dhp, table->drv_c_name,
	    dis_riscv_fpregs[DIS_RISCV_C_RD(instr)], dis_riscv_regs[2],
	    imm, buf, buflen);
}

static void
dis_riscv_c_fldsp(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	uint32_t imm = ((instr & 0x001c) << 4) |
	    ((instr & 0x1000) >> 7) | ((instr & 0x0060) >> 2);

	dis_riscv_c_loadstore(dhp, table->drv_c_name,
	    dis_riscv_fpregs[DIS_RISCV_C_RD(instr)], dis_riscv_regs[2],
	    imm, buf, buflen);
}

static void
dis_riscv_c_swsp(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	uint32_t imm = ((instr & 0x0180) >> 1) | ((instr & 0x1e00) >> 7);

	dis_riscv_c_loadstore(dhp, table->drv_c_name,
	    dis_riscv_regs[DIS_RISCV_C_RS2(instr)], dis_riscv_regs[2], imm,
	    buf, buflen);
}

static void
dis_riscv_c_sdsp(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	uint32_t imm = ((instr & 0x0380) >> 1) | ((instr & 0x1c00) >> 7);

	dis_riscv_c_loadstore(dhp, table->drv_c_name,
	    dis_riscv_regs[DIS_RISCV_C_RS2(instr)], dis_riscv_regs[2], imm,
	    buf, buflen);
}

static void
dis_riscv_c_fswsp(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	uint32_t imm = ((instr & 0x0180) >> 1) | ((instr & 0x1e00) >> 7);

	dis_riscv_c_loadstore(dhp, table->drv_c_name,
	    dis_riscv_fpregs[DIS_RISCV_C_RS2(instr)], dis_riscv_regs[2], imm,
	    buf, buflen);
}

static void
dis_riscv_c_fsdsp(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	uint32_t imm = ((instr & 0x0380) >> 1) | ((instr & 0x1c00) >> 7);

	dis_riscv_c_loadstore(dhp, table->drv_c_name,
	    dis_riscv_fpregs[DIS_RISCV_C_RS2(instr)], dis_riscv_regs[2], imm,
	    buf, buflen);
}

static void
dis_riscv_c_lw(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	uint32_t imm = ((instr & 0x0020) << 1) | ((instr & 0x1c) >> 7) |
	    ((instr & 0x0040) >> 3);

	dis_riscv_c_loadstore(dhp, table->drv_c_name,
	    dis_riscv_c_regs[DIS_RISCV_C_RDP(instr)],
	    dis_riscv_c_regs[DIS_RISCV_C_RS1P(instr)],
	    imm, buf, buflen);
}

static void
dis_riscv_c_ld(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	uint32_t imm = ((instr & 0x0060) << 1) | ((instr & 0x1c) >> 7);

	dis_riscv_c_loadstore(dhp, table->drv_c_name,
	    dis_riscv_c_regs[DIS_RISCV_C_RDP(instr)],
	    dis_riscv_c_regs[DIS_RISCV_C_RS1P(instr)],
	    imm, buf, buflen);
}

static void
dis_riscv_c_flw(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	uint32_t imm = ((instr & 0x0020) << 1) | ((instr & 0x1c) >> 7) |
	    ((instr & 0x0040) >> 3);

	dis_riscv_c_loadstore(dhp, table->drv_c_name,
	    dis_riscv_c_fpregs[DIS_RISCV_C_RDP(instr)],
	    dis_riscv_c_regs[DIS_RISCV_C_RS1P(instr)],
	    imm, buf, buflen);
}

static void
dis_riscv_c_fld(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	uint32_t imm = ((instr & 0x0060) << 1) | ((instr & 0x1c) >> 7);

	dis_riscv_c_loadstore(dhp, table->drv_c_name,
	    dis_riscv_c_fpregs[DIS_RISCV_C_RDP(instr)],
	    dis_riscv_c_regs[DIS_RISCV_C_RS1P(instr)],
	    imm, buf, buflen);
}

/*
 * The J type has the 11 bit immediate arranged as:
 *
 *  offset[11|4|9:8|10|6|7|3:1|5] going from bits 2 to 12.
 */
static void
dis_riscv_c_j(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	const char *s;
	uint_t jimm = DIS_RISCV_C_J_11(instr) | DIS_RISCV_C_J_10(instr) |
	    DIS_RISCV_C_J_9_8(instr) | DIS_RISCV_C_J_7(instr) |
	    DIS_RISCV_C_J_6(instr) | DIS_RISCV_C_J_5(instr) |
	    DIS_RISCV_C_J_4(instr) | DIS_RISCV_C_J_3_1(instr);
	uint_t imm = dis_riscv_sign_extend(jimm, 11, &s);

	if ((dhp->dh_flags & DIS_OCTAL) != 0) {
		(void) dis_snprintf(buf, buflen, "%s %s0%o", table->drv_c_name,
		    s, imm);
	} else {
		(void) dis_snprintf(buf, buflen, "%s %s0x%x", table->drv_c_name,
		    s, imm);
	}
}

/*ARGSUSED*/
static void
dis_riscv_c_jr(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	(void) dis_snprintf(buf, buflen, "%s %s", table->drv_c_name,
	    dis_riscv_regs[DIS_RISCV_C_RS1(instr)]);
}

static void
dis_riscv_c_regimm(dis_handle_t *dhp, const char *instr, const char *dreg,
    const char *sign, uint_t imm, char *buf, size_t buflen)
{
	if ((dhp->dh_flags & DIS_OCTAL) != 0) {
		(void) dis_snprintf(buf, buflen, "%s %s,%s0%o", instr, dreg,
		    sign, imm);
	} else {
		(void) dis_snprintf(buf, buflen, "%s %s,%s0x%x", instr, dreg,
		    sign, imm);
	}
}

static void
dis_riscv_c_branch(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	const char *s;
	uint_t bimm = DIS_RISCV_C_B_8(instr) | DIS_RISCV_C_B_7_6(instr) |
	    DIS_RISCV_C_B_5(instr) | DIS_RISCV_C_B_4_3(instr) |
	    DIS_RISCV_C_B_2_1(instr);
	uint_t imm = dis_riscv_sign_extend(bimm, 8, &s);

	dis_riscv_c_regimm(dhp, table->drv_c_name,
	    dis_riscv_c_regs[DIS_RISCV_C_RS1P(instr)], s, imm, buf, buflen);
}

static void
dis_riscv_c_bigimmint(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	const char *s;
	uint_t limm = ((instr & 0x1000) >> 7) | ((instr & 0x007c) >> 2);
	uint_t imm = dis_riscv_sign_extend(limm, 5, &s);

	dis_riscv_c_regimm(dhp, table->drv_c_name,
	    dis_riscv_regs[DIS_RISCV_C_RD(instr)], s, imm, buf, buflen);
}

static void
dis_riscv_c_zext_bigimmint(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	uint_t imm = ((instr & 0x1000) >> 7) | ((instr & 0x007c) >> 2);

	dis_riscv_c_regimm(dhp, table->drv_c_name,
	    dis_riscv_regs[DIS_RISCV_C_RD(instr)], "", imm, buf, buflen);
}

static void
dis_riscv_c_addi16sp(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	const char *s;
	uint_t aimm = DIS_RISCV_C_A16_9(instr) | DIS_RISCV_C_A16_8_7(instr) |
	    DIS_RISCV_C_A16_6(instr) | DIS_RISCV_C_A16_5(instr) |
	    DIS_RISCV_C_A16_4(instr);
	int imm = dis_riscv_sign_extend(aimm, 9, &s);

	dis_riscv_c_regimm(dhp, table->drv_c_name,
	    dis_riscv_regs[DIS_RISCV_C_RD(instr)], s, imm, buf, buflen);
}

static void
dis_riscv_c_addi4spn(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	uint_t imm = DIS_RISCV_C_A4_9_6(instr) | DIS_RISCV_C_A4_5_4(instr) |
	    DIS_RISCV_C_A4_3(instr) | DIS_RISCV_C_A4_2(instr);

	if ((dhp->dh_flags & DIS_OCTAL) != 0) {
		(void) dis_snprintf(buf, buflen, "%s %s,sp,0%o",
		    table->drv_c_name, dis_riscv_c_regs[DIS_RISCV_C_RDP(instr)],
		    imm);
	} else {
		(void) dis_snprintf(buf, buflen, "%s %s,sp,0x%x",
		    table->drv_c_name, dis_riscv_c_regs[DIS_RISCV_C_RDP(instr)],
		    imm);
	}
}

static void
dis_riscv_c_immint(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	const char *s;
	uint_t limm = ((instr & 0x1000) >> 7) | ((instr & 0x007c) >> 2);
	uint_t imm = dis_riscv_sign_extend(limm, 5, &s);

	dis_riscv_c_regimm(dhp, table->drv_c_name,
	    dis_riscv_c_regs[DIS_RISCV_C_RS1P(instr)], s, imm, buf, buflen);
}

static void
dis_riscv_c_zext_immint(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	uint_t imm = ((instr & 0x1000) >> 7) | ((instr & 0x007c) >> 2);

	dis_riscv_c_regimm(dhp, table->drv_c_name,
	    dis_riscv_c_regs[DIS_RISCV_C_RS1P(instr)], "", imm, buf, buflen);
}

/*ARGSUSED*/
static void
dis_riscv_c_bigint(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	(void) dis_snprintf(buf, buflen, "%s %s,%s", table->drv_c_name,
	    dis_riscv_regs[DIS_RISCV_C_RD(instr)],
	    dis_riscv_regs[DIS_RISCV_C_RS2(instr)]);
}


/*ARGSUSED*/
static void
dis_riscv_c_int(dis_handle_t *dhp, uint32_t instr,
    dis_riscv_c_instr_t *table, char *buf, size_t buflen)
{
	(void) dis_snprintf(buf, buflen, "%s %s,%s", table->drv_c_name,
	    dis_riscv_c_regs[DIS_RISCV_C_RS1P(instr)],
	    dis_riscv_c_regs[DIS_RISCV_C_RS2P(instr)]);
}

#define	DIS_RISCV_CFUNCT3(name, class, op, funct, print)		\
	{ name, DIS_RISCV_C_FUNCT3, print, class, op, funct, 0, 0 }
#define	DIS_RISCV_CMATCH(name, class, op, funct, mask, match, print) 	\
	{ name, DIS_RISCV_C_MATCH, print, class, op, funct, mask, match }

static dis_riscv_c_instr_t dis_riscv_2byte[] = {
	/* Quadrant 0 */
	DIS_RISCV_CFUNCT3("c.addi4spn", DIS_RISCV_CL_32_64, 0x0, 0x0,
	    dis_riscv_c_addi4spn),
	DIS_RISCV_CFUNCT3("c.fld", DIS_RISCV_CL_32_64, 0x0, 0x01,
	    dis_riscv_c_fld),
	DIS_RISCV_CFUNCT3("c.lw", DIS_RISCV_CL_ALL, 0x0, 0x2,
	    dis_riscv_c_lw),
	DIS_RISCV_CFUNCT3("c.flw", DIS_RISCV_CL_32, 0x0, 0x3,
	    dis_riscv_c_flw),
	DIS_RISCV_CFUNCT3("f.ld", DIS_RISCV_CL_64_128, 0x0, 0x3,
	    dis_riscv_c_ld),
	DIS_RISCV_CFUNCT3("c.fsd", DIS_RISCV_CL_32_64, 0x0, 0x5,
	    dis_riscv_c_fld),
	DIS_RISCV_CFUNCT3("c.sw", DIS_RISCV_CL_ALL, 0x0, 0x6,
	    dis_riscv_c_lw),
	DIS_RISCV_CFUNCT3("c.fsw", DIS_RISCV_CL_32, 0x0, 0x7,
	    dis_riscv_c_flw),
	DIS_RISCV_CFUNCT3("c.sd", DIS_RISCV_CL_64_128, 0x0, 0x7,
	    dis_riscv_c_ld),
	/* Quadrant 1 */
	DIS_RISCV_CMATCH("c.nop", DIS_RISCV_CL_ALL, 0x01, 0x00, 0x1ffc, 0x0,
	    dis_riscv_c_name),
	DIS_RISCV_CFUNCT3("c.addi", DIS_RISCV_CL_ALL, 0x01, 0x00,
	    dis_riscv_c_bigimmint),
	DIS_RISCV_CFUNCT3("c.jal", DIS_RISCV_CL_32, 0x01, 0x01,
	    dis_riscv_c_j),
	DIS_RISCV_CFUNCT3("c.addiw", DIS_RISCV_CL_64_128, 0x01, 0x01,
	    dis_riscv_c_bigimmint),
	DIS_RISCV_CFUNCT3("c.li", DIS_RISCV_CL_ALL, 0x01, 0x02,
	    dis_riscv_c_bigimmint),
	DIS_RISCV_CMATCH("c.addi16sp", DIS_RISCV_CL_ALL, 0x01, 0x03, 0x0f80,
	    0x0100, dis_riscv_c_addi16sp),
	DIS_RISCV_CFUNCT3("c.lui", DIS_RISCV_CL_ALL, 0x01, 0x03,
	    dis_riscv_c_zext_bigimmint),
	DIS_RISCV_CMATCH("c.srli", DIS_RISCV_CL_ALL, 0x1, 0x4, 0x0c00, 0x0000,
	    dis_riscv_c_zext_immint),
	DIS_RISCV_CMATCH("c.srai", DIS_RISCV_CL_ALL, 0x1, 0x4, 0x0c00, 0x0400,
	    dis_riscv_c_zext_immint),
	DIS_RISCV_CMATCH("c.andi", DIS_RISCV_CL_ALL, 0x1, 0x4, 0x0c00, 0x0800,
	    dis_riscv_c_immint),
	DIS_RISCV_CMATCH("c.sub", DIS_RISCV_CL_ALL, 0x1, 0x4, 0x1c60, 0x0c00,
	    dis_riscv_c_int),
	DIS_RISCV_CMATCH("c.xor", DIS_RISCV_CL_ALL, 0x1, 0x4, 0x1c60, 0x0c20,
	    dis_riscv_c_int),
	DIS_RISCV_CMATCH("c.or", DIS_RISCV_CL_ALL, 0x1, 0x4, 0x1c60, 0x0c40,
	    dis_riscv_c_int),
	DIS_RISCV_CMATCH("c.and", DIS_RISCV_CL_ALL, 0x1, 0x4, 0x1c60, 0x0c60,
	    dis_riscv_c_int),
	DIS_RISCV_CMATCH("c.subw", DIS_RISCV_CL_64_128, 0x1, 0x4, 0x1c60,
	    0x1c00, dis_riscv_c_int),
	DIS_RISCV_CMATCH("c.addw", DIS_RISCV_CL_64_128, 0x1, 0x4, 0x1c60,
	    0x1c20, dis_riscv_c_int),
	DIS_RISCV_CFUNCT3("c.j", DIS_RISCV_CL_ALL, 0x1, 0x5,
	    dis_riscv_c_j),
	DIS_RISCV_CFUNCT3("c.beqz", DIS_RISCV_CL_ALL, 0x1, 0x6,
	    dis_riscv_c_branch),
	DIS_RISCV_CFUNCT3("c.bnez", DIS_RISCV_CL_ALL, 0x1, 0x7,
	    dis_riscv_c_branch),
	/* Quadrant 2 */
	DIS_RISCV_CFUNCT3("c.slli", DIS_RISCV_CL_ALL, 0x2, 0x0,
	    dis_riscv_c_zext_bigimmint),
	DIS_RISCV_CFUNCT3("c.fldsp", DIS_RISCV_CL_32_64, 0x2, 0x1,
	    dis_riscv_c_fldsp),
	DIS_RISCV_CFUNCT3("c.lwsp", DIS_RISCV_CL_ALL, 0x2, 0x2,
	    dis_riscv_c_lwsp),
	DIS_RISCV_CFUNCT3("c.flwsp", DIS_RISCV_CL_32, 0x2, 0x3,
	    dis_riscv_c_flwsp),
	DIS_RISCV_CFUNCT3("c.ldsp", DIS_RISCV_CL_64_128, 0x2, 0x3,
	    dis_riscv_c_ldsp),
	DIS_RISCV_CMATCH("c.jr", DIS_RISCV_CL_ALL, 0x2, 0x4, 0x107c, 0x0,
	    dis_riscv_c_jr),
	DIS_RISCV_CMATCH("c.mv", DIS_RISCV_CL_ALL, 0x2, 0x4, 0x1000, 0x0,
	    dis_riscv_c_bigint),
	DIS_RISCV_CMATCH("c.ebreak", DIS_RISCV_CL_ALL, 0x2, 0x4, 0x1ffc, 0x1000,
	    dis_riscv_c_name),
	DIS_RISCV_CMATCH("c.jalr", DIS_RISCV_CL_ALL, 0x2, 0x4, 0x107c, 0x1000,
	    dis_riscv_c_jr),
	DIS_RISCV_CMATCH("c.add", DIS_RISCV_CL_ALL, 0x2, 0x4, 0x1000, 0x1000,
	    dis_riscv_c_bigint),
	DIS_RISCV_CFUNCT3("c.fsdsp", DIS_RISCV_CL_32_64, 0x2, 0x5,
	    dis_riscv_c_fsdsp),
	DIS_RISCV_CFUNCT3("c.swsp", DIS_RISCV_CL_ALL, 0x2, 0x6,
	    dis_riscv_c_swsp),
	DIS_RISCV_CFUNCT3("c.fswsp", DIS_RISCV_CL_32, 0x2, 0x7,
	    dis_riscv_c_fswsp),
	DIS_RISCV_CFUNCT3("c.sdsp", DIS_RISCV_CL_64_128, 0x2, 0x7,
	    dis_riscv_c_sdsp),
};

static void
dis_riscv_decode_2byte(dis_handle_t *dhp, uint32_t instr, char *buf,
    size_t buflen)
{
	uint_t i;

	for (i = 0; i < ARRAY_SIZE(dis_riscv_2byte); i++) {
		dis_riscv_c_instr_t *t = &dis_riscv_2byte[i];
		switch (t->drv_c_class) {
		case DIS_RISCV_CL_ALL:
			break;
		case DIS_RISCV_CL_32:
			if ((dhp->dh_flags & DIS_RISCV_32) == 0)
				continue;
			break;
		case DIS_RISCV_CL_64:
			if ((dhp->dh_flags & DIS_RISCV_64) == 0)
				continue;
			break;
		case DIS_RISCV_CL_32_64:
			if ((dhp->dh_flags &
			    (DIS_RISCV_32 | DIS_RISCV_64)) == 0) {
				continue;
			}
			break;
		case DIS_RISCV_CL_64_128:
			if ((dhp->dh_flags & DIS_RISCV_64) == 0)
				continue;
			break;
		}

		switch (t->drv_c_type) {
		case DIS_RISCV_C_FUNCT3:
			if (DIS_RISCV_C_OPCODE(instr) == t->drv_c_opcode &&
			    DIS_RISCV_C_FUNCT3(instr) == t->drv_c_funct) {
				break;
			}
			continue;
		case DIS_RISCV_C_MATCH:
			if (DIS_RISCV_C_OPCODE(instr) == t->drv_c_opcode &&
			    DIS_RISCV_C_FUNCT3(instr) == t->drv_c_funct &&
			    ((instr & t->drv_c_mask) == t->drv_c_match)) {
				break;
			}
			continue;
		default:
			continue;
		}

		t->drv_c_print(dhp, instr, t, buf, buflen);
		return;
	}

	(void) dis_snprintf(buf, buflen, "<unknown>");
}


/*
 * RISC-V instructions always come in parcels of two bytes. Read the next two
 * byte parcel and advance the address in the handle. Also, take care of endian
 * issues if required.
 */
static int
dis_riscv_read_parcel(dis_handle_t *dhp, uint16_t *valp)
{
	if ((dhp->dh_addr % 2) != 0)
		return (-1);

	if (dhp->dh_read(dhp->dh_data, dhp->dh_addr, valp, sizeof (*valp)) !=
	    sizeof (*valp))
		return (-1);

	*valp = LE_16(*valp);

	dhp->dh_addr += 2;

	return (0);
}

/*
 * The first 'parcel' (uint16_t) of any instruction can be used to determine the
 * instruction length. This is derived from Section 1.2 Instruction Length
 * Encoding of Volume I: RISC-V User-Level ISA V2.2.
 *
 *  | xxxxxxxxxxxxxxaa | 16-bit iff aa != 11
 *  | xxxxxxxxxxxbbb11 | 32-bit iff bbb != 111
 *  | xxxxxxxxxx011111 | 48-bit iff bbb != 111
 *  | xxxxxxxxx0111111 | 64-bit iff bbb != 111
 *  | xnnnxxxxx1111111 | (80 + 16*nnn)-bit iff nnn != 111
 */
#define	RISCV_LEN_16_MASK	0x0003
#define	RISCV_LEN_32_MASK	0x001c
#define	RISCV_LEN_48_MASK	0x0020
#define	RISCV_LEN_64_MASK	0x0040
#define	RISCV_LEN_80_MASK	0x7000
#define	RISCV_LEN_80_SHIFT	12

static int
dis_riscv_decode_len(uint16_t instr)
{
	if ((instr & RISCV_LEN_16_MASK) != RISCV_LEN_16_MASK)
		return (2);

	if ((instr & RISCV_LEN_32_MASK) != RISCV_LEN_32_MASK)
		return (4);

	if ((instr & RISCV_LEN_48_MASK) != RISCV_LEN_48_MASK)
		return (6);

	if ((instr & RISCV_LEN_64_MASK) != RISCV_LEN_64_MASK)
		return (8);

	if ((instr & RISCV_LEN_80_MASK) != RISCV_LEN_80_MASK) {
		uint_t factor = (instr & RISCV_LEN_80_MASK) >>
		    RISCV_LEN_80_SHIFT;
		return ((10 + 2 * factor));
	}

	return (-1);
}

static int
dis_riscv_supports_flags(int flags)
{
	int archflags = flags & DIS_ARCH_MASK;

	return (archflags == DIS_RISCV_32 || archflags == DIS_RISCV_64);
}

static int
dis_riscv_disassemble(dis_handle_t *dhp, uint64_t addr, char *buf,
    size_t buflen)
{
	int len;
	uint16_t parcel;
	uint32_t instr;


	dhp->dh_addr = addr;

	/*
	 * All instructions have to be 2-byte aligned. Most have to be four byte
	 * aligned, but we determine that after we decode the instruction size.
	 * The 2-byte alignment check is done when we read the parcel.
	 */
	if (dis_riscv_read_parcel(dhp, &parcel) != 0)
		return (-1);

	len = dis_riscv_decode_len(parcel);
	if (len < 2 || (len % 2) != 0)
		return (-1);
	switch (len) {
	case 2:
		instr = parcel;
		dis_riscv_decode_2byte(dhp, instr, buf, buflen);
		break;
	case 4:
		instr = parcel;
		if (dis_riscv_read_parcel(dhp, &parcel) != 0)
			return (-1);
		instr |= parcel << 16;
		dis_riscv_decode_4byte(dhp, instr, buf, buflen);
		break;
	default:
		/*
		 * This case represents a valid instruction length, but
		 * something we don't understand. Treat this as an unknown
		 * instruction. However, read the rest of the length of the
		 * instruction to make sure that we read things correctly.
		 */
		(void) dis_snprintf(buf, buflen, "<unknown>");
		for (; len > 0; len -= 2) {
			if (dis_riscv_read_parcel(dhp, &parcel) != 0) {
				return (-1);
			}
		}
		break;
	}

	return (0);
}

/*ARGSUSED*/
static int
dis_riscv_min_instrlen(dis_handle_t *dhp)
{
	return (2);
}

/*ARGSUSED*/
static int
dis_riscv_max_instrlen(dis_handle_t *dhp)
{
	return (22);
}

static int
dis_riscv_instrlen(dis_handle_t *dhp, uint64_t addr)
{
	int ret;
	uint16_t parcel;

	dhp->dh_addr = addr;

	if (dis_riscv_read_parcel(dhp, &parcel) != 0)
		return (-1);

	/*
	 * Get length based on this parcel. Check for required alignment. 2-byte
	 * alignment was already taken care of when we read the parcel.
	 */
	ret = dis_riscv_decode_len(parcel);
	if (ret >= 4 && (addr % 4) != 0)
		return (-1);

	return (ret);
}

dis_arch_t dis_arch_riscv = {
	.da_supports_flags = dis_riscv_supports_flags,
	.da_disassemble = dis_riscv_disassemble,
	.da_min_instrlen = dis_riscv_min_instrlen,
	.da_max_instrlen = dis_riscv_max_instrlen,
	.da_instrlen = dis_riscv_instrlen
};
