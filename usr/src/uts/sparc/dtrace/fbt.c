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


#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cpuvar.h>
#include <sys/kmem.h>
#include <sys/strsubr.h>
#include <sys/dtrace.h>
#include <sys/kobj.h>
#include <sys/modctl.h>
#include <sys/atomic.h>
#include <vm/seg_kmem.h>
#include <sys/stack.h>
#include <sys/ctf_api.h>
#include <sys/sysmacros.h>

static dev_info_t		*fbt_devi;
static dtrace_provider_id_t	fbt_id;
static uintptr_t		fbt_trampoline;
static caddr_t			fbt_trampoline_window;
static size_t			fbt_trampoline_size;
static int			fbt_verbose = 0;

/*
 * Various interesting bean counters.
 */
static int			fbt_entry;
static int			fbt_ret;
static int			fbt_retl;
static int			fbt_retl_jmptab;
static int			fbt_retl_twoinstr;
static int			fbt_retl_tailcall;
static int			fbt_retl_tailjmpl;
static int			fbt_leaf_functions;

extern char			stubs_base[];
extern char			stubs_end[];

#define	FBT_REG_G0		0
#define	FBT_REG_G1		1
#define	FBT_REG_O0		8
#define	FBT_REG_O1		9
#define	FBT_REG_O2		10
#define	FBT_REG_O3		11
#define	FBT_REG_O4		12
#define	FBT_REG_O5		13
#define	FBT_REG_O6		14
#define	FBT_REG_O7		15
#define	FBT_REG_I0		24
#define	FBT_REG_I1		25
#define	FBT_REG_I2		26
#define	FBT_REG_I3		27
#define	FBT_REG_I4		28
#define	FBT_REG_I7		31
#define	FBT_REG_L0		16
#define	FBT_REG_L1		17
#define	FBT_REG_L2		18
#define	FBT_REG_L3		19
#define	FBT_REG_PC		5

#define	FBT_REG_ISGLOBAL(r)	((r) < 8)
#define	FBT_REG_ISOUTPUT(r)	((r) >= 8 && (r) < 16)
#define	FBT_REG_ISLOCAL(r)	((r) >= 16 && (r) < 24)
#define	FBT_REG_ISVOLATILE(r)	\
	((FBT_REG_ISGLOBAL(r) || FBT_REG_ISOUTPUT(r)) && (r) != FBT_REG_G0)
#define	FBT_REG_NLOCALS		8

#define	FBT_REG_MARKLOCAL(locals, r)	\
	if (FBT_REG_ISLOCAL(r)) \
		(locals)[(r) - FBT_REG_L0] = 1;

#define	FBT_REG_INITLOCALS(local, locals)	\
	for ((local) = 0; (local) < FBT_REG_NLOCALS; (local)++)  \
		(locals)[(local)] = 0; \
	(local) = FBT_REG_L0

#define	FBT_REG_ALLOCLOCAL(local, locals)	\
	while ((locals)[(local) - FBT_REG_L0]) \
		(local)++; \
	(locals)[(local) - FBT_REG_L0] = 1;

#define	FBT_OP_MASK		0xc0000000
#define	FBT_OP_SHIFT		30
#define	FBT_OP(val)		((val) & FBT_FMT1_MASK)

#define	FBT_SIMM13_MASK		0x1fff
#define	FBT_SIMM13_MAX		((int32_t)0xfff)
#define	FBT_IMM22_MASK		0x3fffff
#define	FBT_IMM22_SHIFT		10
#define	FBT_IMM10_MASK		0x3ff

#define	FBT_DISP30_MASK		0x3fffffff
#define	FBT_DISP30(from, to)	\
	(((uintptr_t)(to) - (uintptr_t)(from) >> 2) & FBT_DISP30_MASK)

#define	FBT_DISP22_MASK		0x3fffff
#define	FBT_DISP22(from, to)	\
	(((uintptr_t)(to) - (uintptr_t)(from) >> 2) & FBT_DISP22_MASK)

#define	FBT_DISP19_MASK		0x7ffff
#define	FBT_DISP19(from, to)	\
	(((uintptr_t)(to) - (uintptr_t)(from) >> 2) & FBT_DISP19_MASK)

#define	FBT_DISP16_HISHIFT	20
#define	FBT_DISP16_HIMASK	(0x3 << FBT_DISP16_HISHIFT)
#define	FBT_DISP16_LOMASK	(0x3fff)
#define	FBT_DISP16_MASK		(FBT_DISP16_HIMASK | FBT_DISP16_LOMASK)
#define	FBT_DISP16(val)	\
	((((val) & FBT_DISP16_HIMASK) >> 6) | ((val) & FBT_DISP16_LOMASK))

#define	FBT_DISP14_MASK		0x3fff
#define	FBT_DISP14(from, to)	\
	(((uintptr_t)(to) - (uintptr_t)(from) >> 2) & FBT_DISP14_MASK)

#define	FBT_OP0			(((uint32_t)0) << FBT_OP_SHIFT)
#define	FBT_OP1			(((uint32_t)1) << FBT_OP_SHIFT)
#define	FBT_OP2			(((uint32_t)2) << FBT_OP_SHIFT)
#define	FBT_ILLTRAP		0

#define	FBT_ANNUL_SHIFT		29
#define	FBT_ANNUL		(1 << FBT_ANNUL_SHIFT)

#define	FBT_FMT3_OP3_SHIFT	19
#define	FBT_FMT3_OP_MASK	0xc1f80000
#define	FBT_FMT3_OP(val)	((val) & FBT_FMT3_OP_MASK)

#define	FBT_FMT3_RD_SHIFT	25
#define	FBT_FMT3_RD_MASK	(0x1f << FBT_FMT3_RD_SHIFT)
#define	FBT_FMT3_RD(val)	\
	(((val) & FBT_FMT3_RD_MASK) >> FBT_FMT3_RD_SHIFT)

#define	FBT_FMT3_RS1_SHIFT	14
#define	FBT_FMT3_RS1_MASK	(0x1f << FBT_FMT3_RS1_SHIFT)
#define	FBT_FMT3_RS1(val)	\
	(((val) & FBT_FMT3_RS1_MASK) >> FBT_FMT3_RS1_SHIFT)
#define	FBT_FMT3_RS1_SET(val, rs1) \
	(val) = ((val) & ~FBT_FMT3_RS1_MASK) | ((rs1) << FBT_FMT3_RS1_SHIFT)

#define	FBT_FMT3_RS2_SHIFT	0
#define	FBT_FMT3_RS2_MASK	(0x1f << FBT_FMT3_RS2_SHIFT)
#define	FBT_FMT3_RS2(val)	\
	(((val) & FBT_FMT3_RS2_MASK) >> FBT_FMT3_RS2_SHIFT)
#define	FBT_FMT3_RS2_SET(val, rs2) \
	(val) = ((val) & ~FBT_FMT3_RS2_MASK) | ((rs2) << FBT_FMT3_RS2_SHIFT)

#define	FBT_FMT3_IMM_SHIFT	13
#define	FBT_FMT3_IMM		(1 << FBT_FMT3_IMM_SHIFT)
#define	FBT_FMT3_SIMM13_MASK	FBT_SIMM13_MASK

#define	FBT_FMT3_ISIMM(val)	((val) & FBT_FMT3_IMM)
#define	FBT_FMT3_SIMM13(val)	((val) & FBT_FMT3_SIMM13_MASK)

#define	FBT_FMT2_OP2_SHIFT	22
#define	FBT_FMT2_OP2_MASK	(0x7 << FBT_FMT2_OP2_SHIFT)
#define	FBT_FMT2_RD_SHIFT	25

#define	FBT_FMT1_OP(val)	((val) & FBT_OP_MASK)
#define	FBT_FMT1_DISP30(val)	((val) & FBT_DISP30_MASK)

#define	FBT_FMT2_OP2_BPCC	(0x01 << FBT_FMT2_OP2_SHIFT)
#define	FBT_FMT2_OP2_BCC	(0x02 << FBT_FMT2_OP2_SHIFT)
#define	FBT_FMT2_OP2_BPR	(0x03 << FBT_FMT2_OP2_SHIFT)
#define	FBT_FMT2_OP2_SETHI	(0x04 << FBT_FMT2_OP2_SHIFT)

#define	FBT_FMT2_COND_SHIFT	25
#define	FBT_FMT2_COND_BA	(0x8 << FBT_FMT2_COND_SHIFT)
#define	FBT_FMT2_COND_BL	(0x3 << FBT_FMT2_COND_SHIFT)
#define	FBT_FMT2_COND_BGE	(0xb << FBT_FMT2_COND_SHIFT)

#define	FBT_OP_RESTORE		(FBT_OP2 | (0x3d << FBT_FMT3_OP3_SHIFT))
#define	FBT_OP_SAVE		(FBT_OP2 | (0x3c << FBT_FMT3_OP3_SHIFT))
#define	FBT_OP_JMPL		(FBT_OP2 | (0x38 << FBT_FMT3_OP3_SHIFT))
#define	FBT_OP_RETURN		(FBT_OP2 | (0x39 << FBT_FMT3_OP3_SHIFT))
#define	FBT_OP_CALL		FBT_OP1
#define	FBT_OP_SETHI		(FBT_OP0 | FBT_FMT2_OP2_SETHI)
#define	FBT_OP_ADD		(FBT_OP2 | (0x00 << FBT_FMT3_OP3_SHIFT))
#define	FBT_OP_OR		(FBT_OP2 | (0x02 << FBT_FMT3_OP3_SHIFT))
#define	FBT_OP_SUB		(FBT_OP2 | (0x04 << FBT_FMT3_OP3_SHIFT))
#define	FBT_OP_CC		(FBT_OP2 | (0x10 << FBT_FMT3_OP3_SHIFT))
#define	FBT_OP_BA		(FBT_OP0 | FBT_FMT2_OP2_BCC | FBT_FMT2_COND_BA)
#define	FBT_OP_BL		(FBT_OP0 | FBT_FMT2_OP2_BCC | FBT_FMT2_COND_BL)
#define	FBT_OP_BGE		(FBT_OP0 | FBT_FMT2_OP2_BCC | FBT_FMT2_COND_BGE)
#define	FBT_OP_BAPCC		(FBT_OP0 | FBT_FMT2_OP2_BPCC | FBT_FMT2_COND_BA)
#define	FBT_OP_RD		(FBT_OP2 | (0x28 << FBT_FMT3_OP3_SHIFT))

#define	FBT_ORLO(rs, val, rd) \
	(FBT_OP_OR | ((rs) << FBT_FMT3_RS1_SHIFT) | \
	((rd) << FBT_FMT3_RD_SHIFT) | FBT_FMT3_IMM | ((val) & FBT_IMM10_MASK))

#define	FBT_ORSIMM13(rs, val, rd) \
	(FBT_OP_OR | ((rs) << FBT_FMT3_RS1_SHIFT) | \
	((rd) << FBT_FMT3_RD_SHIFT) | FBT_FMT3_IMM | ((val) & FBT_SIMM13_MASK))

#define	FBT_ADDSIMM13(rs, val, rd) \
	(FBT_OP_ADD | ((rs) << FBT_FMT3_RS1_SHIFT) | \
	((rd) << FBT_FMT3_RD_SHIFT) | FBT_FMT3_IMM | ((val) & FBT_SIMM13_MASK))

#define	FBT_ADD(rs1, rs2, rd) \
	(FBT_OP_ADD | ((rs1) << FBT_FMT3_RS1_SHIFT) | \
	((rs2) << FBT_FMT3_RS2_SHIFT) | ((rd) << FBT_FMT3_RD_SHIFT))

#define	FBT_CMP(rs1, rs2) \
	(FBT_OP_SUB | FBT_OP_CC | ((rs1) << FBT_FMT3_RS1_SHIFT) | \
	((rs2) << FBT_FMT3_RS2_SHIFT) | (FBT_REG_G0 << FBT_FMT3_RD_SHIFT))

#define	FBT_MOV(rs, rd) \
	(FBT_OP_OR | (FBT_REG_G0 << FBT_FMT3_RS1_SHIFT) | \
	((rs) << FBT_FMT3_RS2_SHIFT) | ((rd) << FBT_FMT3_RD_SHIFT))

#define	FBT_SETHI(val, reg)	\
	(FBT_OP_SETHI | (reg << FBT_FMT2_RD_SHIFT) | \
	((val >> FBT_IMM22_SHIFT) & FBT_IMM22_MASK))

#define	FBT_CALL(orig, dest)	(FBT_OP_CALL | FBT_DISP30(orig, dest))

#define	FBT_RET \
	(FBT_OP_JMPL | (FBT_REG_I7 << FBT_FMT3_RS1_SHIFT) | \
	(FBT_REG_G0 << FBT_FMT3_RD_SHIFT) | FBT_FMT3_IMM | (sizeof (pc_t) << 1))

#define	FBT_SAVEIMM(rd, val, rs1)	\
	(FBT_OP_SAVE | ((rs1) << FBT_FMT3_RS1_SHIFT) | \
	((rd) << FBT_FMT3_RD_SHIFT) | FBT_FMT3_IMM | ((val) & FBT_SIMM13_MASK))

#define	FBT_RESTORE(rd, rs1, rs2)	\
	(FBT_OP_RESTORE | ((rs1) << FBT_FMT3_RS1_SHIFT) | \
	((rd) << FBT_FMT3_RD_SHIFT) | ((rs2) << FBT_FMT3_RS2_SHIFT))

#define	FBT_RETURN(rs1, val)		\
	(FBT_OP_RETURN | ((rs1) << FBT_FMT3_RS1_SHIFT) | \
	FBT_FMT3_IMM | ((val) & FBT_SIMM13_MASK))

#define	FBT_BA(orig, dest)	(FBT_OP_BA | FBT_DISP22(orig, dest))
#define	FBT_BAA(orig, dest)	(FBT_BA(orig, dest) | FBT_ANNUL)
#define	FBT_BL(orig, dest)	(FBT_OP_BL | FBT_DISP22(orig, dest))
#define	FBT_BGE(orig, dest)	(FBT_OP_BGE | FBT_DISP22(orig, dest))
#define	FBT_BDEST(va, instr)	((uintptr_t)(va) + \
	(((int32_t)(((instr) & FBT_DISP22_MASK) << 10)) >> 8))
#define	FBT_BPCCDEST(va, instr)	((uintptr_t)(va) + \
	(((int32_t)(((instr) & FBT_DISP19_MASK) << 13)) >> 11))
#define	FBT_BPRDEST(va, instr)	((uintptr_t)(va) + \
	(((int32_t)((FBT_DISP16(instr)) << 16)) >> 14))

/*
 * We're only going to treat a save as safe if (a) both rs1 and rd are
 * %sp and (b) if the instruction has a simm, the value isn't 0.
 */
#define	FBT_IS_SAVE(instr)	\
	(FBT_FMT3_OP(instr) == FBT_OP_SAVE && \
	FBT_FMT3_RD(instr) == FBT_REG_O6 && \
	FBT_FMT3_RS1(instr) == FBT_REG_O6 && \
	!(FBT_FMT3_ISIMM(instr) && FBT_FMT3_SIMM13(instr) == 0))

#define	FBT_IS_BA(instr)	(((instr) & ~FBT_DISP22_MASK) == FBT_OP_BA)
#define	FBT_IS_BAPCC(instr)	(((instr) & ~FBT_DISP22_MASK) == FBT_OP_BAPCC)

#define	FBT_IS_RDPC(instr)	((FBT_FMT3_OP(instr) == FBT_OP_RD) && \
	(FBT_FMT3_RD(instr) == FBT_REG_PC))

#define	FBT_IS_PCRELATIVE(instr)	\
	((((instr) & FBT_OP_MASK) == FBT_OP0 && \
	((instr) & FBT_FMT2_OP2_MASK) != FBT_FMT2_OP2_SETHI) || \
	((instr) & FBT_OP_MASK) == FBT_OP1 || \
	FBT_IS_RDPC(instr))

#define	FBT_IS_CTI(instr)	\
	((((instr) & FBT_OP_MASK) == FBT_OP0 && \
	((instr) & FBT_FMT2_OP2_MASK) != FBT_FMT2_OP2_SETHI) || \
	((instr) & FBT_OP_MASK) == FBT_OP1 || \
	(FBT_FMT3_OP(instr) == FBT_OP_JMPL) || \
	(FBT_FMT3_OP(instr) == FBT_OP_RETURN))

#define	FBT_PROBENAME_ENTRY	"entry"
#define	FBT_PROBENAME_RETURN	"return"
#define	FBT_ESTIMATE_ID		(UINT32_MAX)
#define	FBT_COUNTER(id, count)	if ((id) != FBT_ESTIMATE_ID) (count)++

#define	FBT_ENTENT_MAXSIZE	(16 * sizeof (uint32_t))
#define	FBT_RETENT_MAXSIZE	(11 * sizeof (uint32_t))
#define	FBT_RETLENT_MAXSIZE	(23 * sizeof (uint32_t))
#define	FBT_ENT_MAXSIZE		\
	MAX(MAX(FBT_ENTENT_MAXSIZE, FBT_RETENT_MAXSIZE), FBT_RETLENT_MAXSIZE)

typedef struct fbt_probe {
	char		*fbtp_name;
	dtrace_id_t	fbtp_id;
	uintptr_t	fbtp_addr;
	struct modctl	*fbtp_ctl;
	int		fbtp_loadcnt;
	int		fbtp_symndx;
	int		fbtp_primary;
	int		fbtp_return;
	uint32_t	*fbtp_patchpoint;
	uint32_t	fbtp_patchval;
	uint32_t	fbtp_savedval;
	struct fbt_probe *fbtp_next;
} fbt_probe_t;

typedef struct fbt_trampoline {
	uintptr_t	fbtt_va;
	uintptr_t	fbtt_limit;
	uintptr_t	fbtt_next;
} fbt_trampoline_t;

static caddr_t
fbt_trampoline_map(uintptr_t tramp, size_t size)
{
	uintptr_t offs;
	page_t **ppl;

	ASSERT(fbt_trampoline_window == NULL);
	ASSERT(fbt_trampoline_size == 0);
	ASSERT(fbt_trampoline == NULL);

	size += tramp & PAGEOFFSET;
	fbt_trampoline = tramp & PAGEMASK;
	fbt_trampoline_size = (size + PAGESIZE - 1) & PAGEMASK;
	fbt_trampoline_window =
	    vmem_alloc(heap_arena, fbt_trampoline_size, VM_SLEEP);

	(void) as_pagelock(&kas, &ppl, (caddr_t)fbt_trampoline,
	    fbt_trampoline_size, S_WRITE);

	for (offs = 0; offs < fbt_trampoline_size; offs += PAGESIZE) {
		hat_devload(kas.a_hat, fbt_trampoline_window + offs, PAGESIZE,
		    hat_getpfnum(kas.a_hat, (caddr_t)fbt_trampoline + offs),
		    PROT_READ | PROT_WRITE,
		    HAT_LOAD_LOCK | HAT_LOAD_NOCONSIST);
	}

	as_pageunlock(&kas, ppl, (caddr_t)fbt_trampoline, fbt_trampoline_size,
	    S_WRITE);

	return (fbt_trampoline_window + (tramp & PAGEOFFSET));
}

static void
fbt_trampoline_unmap()
{
	ASSERT(fbt_trampoline_window != NULL);
	ASSERT(fbt_trampoline_size != 0);
	ASSERT(fbt_trampoline != NULL);

	membar_enter();
	sync_icache((caddr_t)fbt_trampoline, fbt_trampoline_size);
	sync_icache(fbt_trampoline_window, fbt_trampoline_size);

	hat_unload(kas.a_hat, fbt_trampoline_window, fbt_trampoline_size,
	    HAT_UNLOAD_UNLOCK);

	vmem_free(heap_arena, fbt_trampoline_window, fbt_trampoline_size);

	fbt_trampoline_window = NULL;
	fbt_trampoline = 0;
	fbt_trampoline_size = 0;
}

static uintptr_t
fbt_patch_entry(uint32_t *instr, uint32_t id, fbt_trampoline_t *tramp,
    int nargs)
{
	uint32_t *tinstr = (uint32_t *)tramp->fbtt_next;
	uint32_t first = *instr;
	uintptr_t va = tramp->fbtt_va;
	uintptr_t base = tramp->fbtt_next;

	if (tramp->fbtt_next + FBT_ENTENT_MAXSIZE > tramp->fbtt_limit) {
		/*
		 * There isn't sufficient room for this entry; return failure.
		 */
		return (0);
	}

	FBT_COUNTER(id, fbt_entry);

	if (FBT_IS_SAVE(first)) {
		*tinstr++ = first;
	} else {
		*tinstr++ = FBT_SAVEIMM(FBT_REG_O6, -SA(MINFRAME), FBT_REG_O6);
	}

	if (id > (uint32_t)FBT_SIMM13_MAX) {
		*tinstr++ = FBT_SETHI(id, FBT_REG_O0);
		*tinstr++ = FBT_ORLO(FBT_REG_O0, id, FBT_REG_O0);
	} else {
		*tinstr++ = FBT_ORSIMM13(FBT_REG_G0, id, FBT_REG_O0);
	}

	if (nargs >= 1)
		*tinstr++ = FBT_MOV(FBT_REG_I0, FBT_REG_O1);

	if (nargs >= 2)
		*tinstr++ = FBT_MOV(FBT_REG_I1, FBT_REG_O2);

	if (nargs >= 3)
		*tinstr++ = FBT_MOV(FBT_REG_I2, FBT_REG_O3);

	if (nargs >= 4)
		*tinstr++ = FBT_MOV(FBT_REG_I3, FBT_REG_O4);

	if (nargs >= 5)
		*tinstr++ = FBT_MOV(FBT_REG_I4, FBT_REG_O5);

	if (FBT_IS_SAVE(first)) {
		uintptr_t ret = (uintptr_t)instr - sizeof (uint32_t);

		*tinstr++ = FBT_SETHI(ret, FBT_REG_G1);
		*tinstr = FBT_CALL((uintptr_t)tinstr - base + va, dtrace_probe);
		tinstr++;
		*tinstr++ = FBT_ORLO(FBT_REG_G1, ret, FBT_REG_O7);
	} else {
		uintptr_t slot = *--tinstr;
		uintptr_t ret = (uintptr_t)instr + sizeof (uint32_t);
		uint32_t delay = first;

		*tinstr = FBT_CALL((uintptr_t)tinstr - base + va, dtrace_probe);
		tinstr++;
		*tinstr++ = slot;
		*tinstr++ = FBT_RESTORE(FBT_REG_G0, FBT_REG_G0, FBT_REG_G0);

		if (FBT_IS_BA(first) || FBT_IS_BAPCC(first)) {
			/*
			 * This is a special case:  we are instrumenting a
			 * a non-annulled branch-always (or variant).  We'll
			 * return directly to the destination of the branch,
			 * copying the instruction in the delay slot here,
			 * and then executing it in the slot of a ba.
			 */
			if (FBT_IS_BA(first)) {
				ret = FBT_BDEST(instr, *instr);
			} else {
				ret = FBT_BPCCDEST(instr, *instr);
			}

			delay = *(instr + 1);
		}

		if ((first & FBT_OP_MASK) != FBT_OP0 ||
		    (first & FBT_FMT2_OP2_MASK) != FBT_FMT2_OP2_BPR) {
			*tinstr = FBT_BA((uintptr_t)tinstr - base + va, ret);
			tinstr++;
			*tinstr++ = delay;
		} else {
			/*
			 * If this is a branch-on-register, we have a little
			 * more work to do:  because the displacement is only
			 * sixteen bits, we're going to thunk the branch into
			 * the trampoline, and then ba,a to the appropriate
			 * destination in the branch targets.  That is, we're
			 * constructing this sequence in the trampoline:
			 *
			 *		br[cc]	%[rs], 1f
			 *		<delay-instruction>
			 *		ba,a	<not-taken-destination>
			 *	1:	ba,a	<taken-destination>
			 *
			 */
			uintptr_t targ = FBT_BPRDEST(instr, first);

			*tinstr = first & ~(FBT_DISP16_MASK);
			*tinstr |= FBT_DISP14(tinstr, &tinstr[3]);
			tinstr++;
			*tinstr++ = *(instr + 1);
			*tinstr = FBT_BAA((uintptr_t)tinstr - base + va,
			    ret + sizeof (uint32_t));
			tinstr++;
			*tinstr = FBT_BAA((uintptr_t)tinstr - base + va, targ);
			tinstr++;
		}
	}

	tramp->fbtt_va += (uintptr_t)tinstr - tramp->fbtt_next;
	tramp->fbtt_next = (uintptr_t)tinstr;

	return (1);
}

/*
 * We are patching control-transfer/restore couplets.  There are three
 * variants of couplet:
 *
 * (a)	return		rs1 + imm
 *	delay
 *
 * (b)	jmpl		rs1 + (rs2 | offset), rd
 *	restore		rs1, rs2 | imm, rd
 *
 * (c)	call		displacement
 *	restore		rs1, rs2 | imm, rd
 *
 * If rs1 in (a) is anything other than %i7, or imm is anything other than 8,
 * or delay is a DCTI, we fail.  If rd from the jmpl in (b) is something other
 * than %g0 (a ret or a tail-call through a function pointer) or %o7 (a call
 * through a register), we fail.
 *
 * Note that rs1 and rs2 in the restore instructions in (b) and (c) are
 * potentially outputs and/or globals.  Because these registers cannot be
 * relied upon across the call to dtrace_probe(), we move rs1 into an unused
 * local, ls0, and rs2 into an unused local, ls1, and restructure the restore
 * to be:
 *
 *	restore		ls0, ls1, rd
 *
 * Likewise, rs1 and rs2 in the jmpl of case (b) may be outputs and/or globals.
 * If the jmpl uses outputs or globals, we restructure it to be:
 *
 *	jmpl		ls2 + (ls3 | offset), (%g0 | %o7)
 *
 */
/*ARGSUSED*/
static int
fbt_canpatch_return(uint32_t *instr, int offset, const char *name)
{
	int rd;

	if (FBT_FMT3_OP(*instr) == FBT_OP_RETURN) {
		uint32_t delay = *(instr + 1);

		if (*instr != FBT_RETURN(FBT_REG_I7, 8)) {
			/*
			 * It's unclear if we should warn about this or not.
			 * We really wouldn't expect the compiler to generate
			 * return instructions with something other than %i7
			 * as rs1 and 8 as the simm13 -- it would just be
			 * mean-spirited.  That said, such a construct isn't
			 * necessarily incorrect.  Sill, we err on the side of
			 * caution and warn about it...
			 */
			cmn_err(CE_NOTE, "cannot instrument return of %s at "
			    "%p: non-canonical return instruction", name,
			    (void *)instr);
			return (0);
		}

		if (FBT_IS_CTI(delay)) {
			/*
			 * This is even weirder -- a DCTI coupled with a
			 * return instruction.  Similar constructs are used to
			 * return from utraps, but these typically have the
			 * return in the slot -- and we wouldn't expect to see
			 * it in the kernel regardless.  At any rate, we don't
			 * want to try to instrument this construct, whatever
			 * it may be.
			 */
			cmn_err(CE_NOTE, "cannot instrument return of %s at "
			    "%p: CTI in delay slot of return instruction",
			    name, (void *)instr);
			return (0);
		}

		if (FBT_IS_PCRELATIVE(delay)) {
			/*
			 * This is also very weird, but might be correct code
			 * if the function is (for example) returning the
			 * address of the delay instruction of the return as
			 * its return value (e.g. "rd %pc, %o0" in the slot).
			 * Perhaps correct, but still too weird to not warn
			 * about it...
			 */
			cmn_err(CE_NOTE, "cannot instrument return of %s at "
			    "%p: PC-relative instruction in delay slot of "
			    "return instruction", name, (void *)instr);
			return (0);
		}

		return (1);
	}

	if (FBT_FMT3_OP(*(instr + 1)) != FBT_OP_RESTORE)
		return (0);

	if (FBT_FMT1_OP(*instr) == FBT_OP_CALL)
		return (1);

	if (FBT_FMT3_OP(*instr) != FBT_OP_JMPL)
		return (0);

	rd = FBT_FMT3_RD(*instr);

	if (rd == FBT_REG_I7 || rd == FBT_REG_O7 || rd == FBT_REG_G0)
		return (1);

	/*
	 * We have encountered a jmpl that is storing the calling %pc in
	 * some register besides %i7, %o7 or %g0.  This is strange; emit
	 * a warning and fail.
	 */
	cmn_err(CE_NOTE, "cannot instrument return of %s at %p: unexpected "
	    "jmpl destination register", name, (void *)instr);
	return (0);
}

static int
fbt_canpatch_retl(uint32_t *instr, int offset, const char *name)
{
	if (FBT_FMT1_OP(*instr) == FBT_OP_CALL ||
	    (FBT_FMT3_OP(*instr) == FBT_OP_JMPL &&
	    FBT_FMT3_RD(*instr) == FBT_REG_O7)) {
		/*
		 * If this is a call (or a jmpl that links into %o7), we can
		 * patch it iff the next instruction uses %o7 as a destination
		 * register.  Because there is an ABI responsibility to
		 * restore %o7 to the value before the call/jmpl, we don't
		 * particularly care how this routine is managing to restore
		 * it (mov, add, ld or divx for all we care).  If it doesn't
		 * seem to be restoring it at all, however, we'll refuse
		 * to patch it.
		 */
		uint32_t delay = *(instr + 1);
		uint32_t op, rd;

		op = FBT_FMT1_OP(delay);
		rd = FBT_FMT3_RD(delay);

		if (op != FBT_OP2 || rd != FBT_REG_O7) {
			/*
			 * This is odd.  Before we assume that we're looking
			 * at something bizarre (and warn accordingly), we'll
			 * check to see if it's obviously a jump table entry.
			 */
			if (*instr < (uintptr_t)instr &&
			    *instr >= (uintptr_t)instr - offset)
				return (0);

			cmn_err(CE_NOTE, "cannot instrument return of %s at "
			    "%p: leaf jmpl/call delay isn't restoring %%o7",
			    name, (void *)instr);
			return (0);
		}

		return (1);
	}

	if (offset == sizeof (uint32_t)) {
		/*
		 * If this is the second instruction in the function, we're
		 * going to allow it to be patched if the first instruction
		 * is a patchable return-from-leaf instruction.
		 */
		if (fbt_canpatch_retl(instr - 1, 0, name))
			return (1);
	}

	if (FBT_FMT3_OP(*instr) != FBT_OP_JMPL)
		return (0);

	if (FBT_FMT3_RD(*instr) != FBT_REG_G0)
		return (0);

	return (1);
}

/*ARGSUSED*/
static uint32_t
fbt_patch_return(uint32_t *instr, uint32_t *funcbase, uint32_t *funclim,
    int offset, uint32_t id, fbt_trampoline_t *tramp, const char *name)
{
	uint32_t *tinstr = (uint32_t *)tramp->fbtt_next;
	uint32_t cti = *instr, restore = *(instr + 1), rs1, dest;
	uintptr_t va = tramp->fbtt_va;
	uintptr_t base = tramp->fbtt_next;
	uint32_t locals[FBT_REG_NLOCALS], local;

	if (tramp->fbtt_next + FBT_RETENT_MAXSIZE > tramp->fbtt_limit) {
		/*
		 * There isn't sufficient room for this entry; return failure.
		 */
		return (FBT_ILLTRAP);
	}

	FBT_COUNTER(id, fbt_ret);

	if (FBT_FMT3_OP(*instr) == FBT_OP_RETURN) {
		/*
		 * To handle the case of the return instruction, we'll emit a
		 * restore, followed by the instruction in the slot (which
		 * we'll transplant here), and then another save.  While it
		 * may seem intellectually unsatisfying to emit the additional
		 * restore/save couplet, one can take solace in the fact that
		 * we don't do this if the instruction in the return delay
		 * slot is a nop -- which it is nearly 90% of the time with
		 * gcc.  (And besides, this couplet can't induce unnecessary
		 * spill/fill traps; rewriting the delay instruction to be
		 * in terms of the current window hardly seems worth the
		 * trouble -- let alone the risk.)
		 */
		uint32_t delay = *(instr + 1);
		ASSERT(*instr == FBT_RETURN(FBT_REG_I7, 8));

		cti = FBT_RET;
		restore = FBT_RESTORE(FBT_REG_G0, FBT_REG_G0, FBT_REG_G0);

		if (delay != FBT_SETHI(0, FBT_REG_G0)) {
			*tinstr++ = restore;
			*tinstr++ = delay;
			*tinstr++ = FBT_SAVEIMM(FBT_REG_O6,
			    -SA(MINFRAME), FBT_REG_O6);
		}
	}

	FBT_REG_INITLOCALS(local, locals);

	/*
	 * Mark the locals used in the jmpl.
	 */
	if (FBT_FMT3_OP(cti) == FBT_OP_JMPL) {
		uint32_t rs1 = FBT_FMT3_RS1(cti);
		FBT_REG_MARKLOCAL(locals, rs1);

		if (!FBT_FMT3_ISIMM(cti)) {
			uint32_t rs2 = FBT_FMT3_RS2(cti);
			FBT_REG_MARKLOCAL(locals, rs2);
		}
	}

	/*
	 * And mark the locals used in the restore.
	 */
	rs1 = FBT_FMT3_RS1(restore);
	FBT_REG_MARKLOCAL(locals, rs1);

	if (!FBT_FMT3_ISIMM(restore)) {
		uint32_t rs2 = FBT_FMT3_RS2(restore);
		FBT_REG_MARKLOCAL(locals, rs2);
	}

	if (FBT_FMT3_OP(cti) == FBT_OP_JMPL) {
		uint32_t rs1 = FBT_FMT3_RS1(cti);

		if (FBT_REG_ISVOLATILE(rs1)) {
			FBT_REG_ALLOCLOCAL(local, locals);
			FBT_FMT3_RS1_SET(cti, local);
			*tinstr++ = FBT_MOV(rs1, local);
		}

		if (!FBT_FMT3_ISIMM(cti)) {
			uint32_t rs2 = FBT_FMT3_RS2(cti);

			if (FBT_REG_ISVOLATILE(rs2)) {
				FBT_REG_ALLOCLOCAL(local, locals);
				FBT_FMT3_RS2_SET(cti, local);
				*tinstr++ = FBT_MOV(rs2, local);
			}
		}
	}

	rs1 = FBT_FMT3_RS1(restore);

	if (FBT_REG_ISVOLATILE(rs1)) {
		FBT_REG_ALLOCLOCAL(local, locals);
		FBT_FMT3_RS1_SET(restore, local);
		*tinstr++ = FBT_MOV(rs1, local);
	}

	if (!FBT_FMT3_ISIMM(restore)) {
		uint32_t rs2 = FBT_FMT3_RS2(restore);

		if (FBT_REG_ISVOLATILE(rs2)) {
			FBT_REG_ALLOCLOCAL(local, locals);
			FBT_FMT3_RS2_SET(restore, local);
			*tinstr++ = FBT_MOV(rs2, local);
		}
	}

	if (id > (uint32_t)FBT_SIMM13_MAX) {
		*tinstr++ = FBT_SETHI(id, FBT_REG_O0);
		*tinstr++ = FBT_ORLO(FBT_REG_O0, id, FBT_REG_O0);
	} else {
		*tinstr++ = FBT_ORSIMM13(FBT_REG_G0, id, FBT_REG_O0);
	}

	if (offset > (uint32_t)FBT_SIMM13_MAX) {
		*tinstr++ = FBT_SETHI(offset, FBT_REG_O1);
		*tinstr++ = FBT_ORLO(FBT_REG_O1, offset, FBT_REG_O1);
	} else {
		*tinstr++ = FBT_ORSIMM13(FBT_REG_G0, offset, FBT_REG_O1);
	}

	*tinstr = FBT_CALL((uintptr_t)tinstr - base + va, dtrace_probe);
	tinstr++;

	if (FBT_FMT3_RD(restore) == FBT_REG_O0) {
		/*
		 * If the destination register of the restore is %o0, we
		 * need to perform the implied calculation to derive the
		 * return value.
		 */
		uint32_t add = (restore & ~FBT_FMT3_OP_MASK) | FBT_OP_ADD;
		add &= ~FBT_FMT3_RD_MASK;
		*tinstr++ = add | (FBT_REG_O2 << FBT_FMT3_RD_SHIFT);
	} else {
		*tinstr++ = FBT_MOV(FBT_REG_I0, FBT_REG_O2);
	}

	/*
	 * If the control transfer instruction is %pc-relative (i.e. a
	 * call), we need to reset it appropriately.
	 */
	if (FBT_FMT1_OP(cti) == FBT_OP_CALL) {
		dest = (uintptr_t)instr + (FBT_FMT1_DISP30(cti) << 2);
		*tinstr = FBT_CALL((uintptr_t)tinstr - base + va, dest);
		tinstr++;
	} else {
		*tinstr++ = cti;
	}

	*tinstr++ = restore;
	tramp->fbtt_va += (uintptr_t)tinstr - tramp->fbtt_next;
	tramp->fbtt_next = (uintptr_t)tinstr;

	return (FBT_BAA(instr, va));
}

static uint32_t
fbt_patch_retl(uint32_t *instr, uint32_t *funcbase, uint32_t *funclim,
    int offset, uint32_t id, fbt_trampoline_t *tramp, const char *name)
{
	uint32_t *tinstr = (uint32_t *)tramp->fbtt_next;
	uintptr_t va = tramp->fbtt_va;
	uintptr_t base = tramp->fbtt_next;
	uint32_t cti = *instr, dest;
	int annul = 0;

	FBT_COUNTER(id, fbt_retl);

	if (tramp->fbtt_next + FBT_RETLENT_MAXSIZE > tramp->fbtt_limit) {
		/*
		 * There isn't sufficient room for this entry; return failure.
		 */
		return (FBT_ILLTRAP);
	}

	if (offset == sizeof (uint32_t) &&
	    fbt_canpatch_retl(instr - 1, 0, name)) {
		*tinstr++ = *instr;
		annul = 1;
		FBT_COUNTER(id, fbt_retl_twoinstr);
	} else {
		if (FBT_FMT3_OP(cti) == FBT_OP_JMPL &&
		    FBT_FMT3_RD(cti) != FBT_REG_O7 &&
		    FBT_FMT3_RS1(cti) != FBT_REG_O7) {
			annul = 1;
			*tinstr++ = *(instr + 1);
		}
	}

	*tinstr++ = FBT_SAVEIMM(FBT_REG_O6, -SA(MINFRAME), FBT_REG_O6);

	if (FBT_FMT3_OP(cti) == FBT_OP_JMPL) {
		uint32_t rs1, rs2, o2i = FBT_REG_I0 - FBT_REG_O0;

		/*
		 * If we have a jmpl and it's in terms of output registers, we
		 * need to rewrite it to be in terms of the corresponding input
		 * registers.  If it's in terms of the globals, we'll rewrite
		 * it to be in terms of locals.
		 */
		rs1 = FBT_FMT3_RS1(cti);

		if (FBT_REG_ISOUTPUT(rs1))
			rs1 += o2i;

		if (FBT_REG_ISGLOBAL(rs1)) {
			*tinstr++ = FBT_MOV(rs1, FBT_REG_L0);
			rs1 = FBT_REG_L0;
		}

		FBT_FMT3_RS1_SET(cti, rs1);

		if (!FBT_FMT3_ISIMM(cti)) {
			rs2 = FBT_FMT3_RS2(cti);

			if (FBT_REG_ISOUTPUT(rs2))
				rs2 += o2i;

			if (FBT_REG_ISGLOBAL(rs2)) {
				*tinstr++ = FBT_MOV(rs2, FBT_REG_L1);
				rs2 = FBT_REG_L1;
			}

			FBT_FMT3_RS2_SET(cti, rs2);
		}

		/*
		 * Now we need to check the rd and source register for the jmpl;
		 * If neither rd nor the source register is %o7, then we might
		 * have a jmp that is actually part of a jump table.  We need
		 * to generate the code to compare it to the base and limit of
		 * the function.
		 */
		if (FBT_FMT3_RD(cti) != FBT_REG_O7 && rs1 != FBT_REG_I7) {
			uintptr_t base = (uintptr_t)funcbase;
			uintptr_t limit = (uintptr_t)funclim;

			FBT_COUNTER(id, fbt_retl_jmptab);

			if (FBT_FMT3_ISIMM(cti)) {
				*tinstr++ = FBT_ADDSIMM13(rs1,
				    FBT_FMT3_SIMM13(cti), FBT_REG_L2);
			} else {
				*tinstr++ = FBT_ADD(rs1, rs2, FBT_REG_L2);
			}

			*tinstr++ = FBT_SETHI(base, FBT_REG_L3);
			*tinstr++ = FBT_ORLO(FBT_REG_L3, base, FBT_REG_L3);
			*tinstr++ = FBT_CMP(FBT_REG_L2, FBT_REG_L3);
			*tinstr++ = FBT_BL(0, 8 * sizeof (uint32_t));
			*tinstr++ = FBT_SETHI(limit, FBT_REG_L3);
			*tinstr++ = FBT_ORLO(FBT_REG_L3, limit, FBT_REG_L3);
			*tinstr++ = FBT_CMP(FBT_REG_L2, FBT_REG_L3);
			*tinstr++ = FBT_BGE(0, 4 * sizeof (uint32_t));
			*tinstr++ = FBT_SETHI(0, FBT_REG_G0);
			*tinstr++ = cti;
			*tinstr++ = FBT_RESTORE(FBT_REG_G0,
			    FBT_REG_G0, FBT_REG_G0);
		}
	}

	if (id > (uint32_t)FBT_SIMM13_MAX) {
		*tinstr++ = FBT_SETHI(id, FBT_REG_O0);
		*tinstr++ = FBT_ORLO(FBT_REG_O0, id, FBT_REG_O0);
	} else {
		*tinstr++ = FBT_ORSIMM13(FBT_REG_G0, id, FBT_REG_O0);
	}

	if (offset > (uint32_t)FBT_SIMM13_MAX) {
		*tinstr++ = FBT_SETHI(offset, FBT_REG_O1);
		*tinstr++ = FBT_ORLO(FBT_REG_O1, offset, FBT_REG_O1);
	} else {
		*tinstr++ = FBT_ORSIMM13(FBT_REG_G0, offset, FBT_REG_O1);
	}

	*tinstr = FBT_CALL((uintptr_t)tinstr - base + va, dtrace_probe);
	tinstr++;
	*tinstr++ = FBT_MOV(FBT_REG_I0, FBT_REG_O2);

	/*
	 * If the control transfer instruction is %pc-relative (i.e. a
	 * call), we need to reset it appropriately.
	 */
	if (FBT_FMT1_OP(cti) == FBT_OP_CALL) {
		FBT_COUNTER(id, fbt_retl_tailcall);
		dest = (uintptr_t)instr + (FBT_FMT1_DISP30(cti) << 2);
		*tinstr = FBT_CALL((uintptr_t)tinstr - base + va, dest);
		tinstr++;
		annul = 1;
	} else {
		if (FBT_FMT3_OP(cti) == FBT_OP_JMPL) {
			*tinstr++ = cti;

			if (FBT_FMT3_RD(cti) == FBT_REG_O7) {
				FBT_COUNTER(id, fbt_retl_tailjmpl);
				annul = 1;
			}
		} else {
			*tinstr++ = FBT_RET;
		}
	}

	*tinstr++ = FBT_RESTORE(FBT_REG_G0, FBT_REG_G0, FBT_REG_G0);

	tramp->fbtt_va += (uintptr_t)tinstr - tramp->fbtt_next;
	tramp->fbtt_next = (uintptr_t)tinstr;

	return (annul ? FBT_BAA(instr, va) : FBT_BA(instr, va));
}

/*ARGSUSED*/
static void
fbt_provide_module(void *arg, struct modctl *ctl)
{
	struct module *mp = ctl->mod_mp;
	char *modname = ctl->mod_modname;
	char *str = mp->strings;
	int nsyms = mp->nsyms;
	Shdr *symhdr = mp->symhdr;
	size_t symsize;
	char *name;
	int i;
	fbt_probe_t *fbt, *retfbt;
	fbt_trampoline_t tramp;
	uintptr_t offset;
	int primary = 0;
	ctf_file_t *fp = NULL;
	int error;
	int estimate = 1;
	uint32_t faketramp[50];
	size_t fbt_size = 0;

	/*
	 * Employees of dtrace and their families are ineligible.  Void
	 * where prohibited.
	 */
	if (strcmp(modname, "dtrace") == 0)
		return;

	if (ctl->mod_requisites != NULL) {
		struct modctl_list *list;

		list = (struct modctl_list *)ctl->mod_requisites;

		for (; list != NULL; list = list->modl_next) {
			if (strcmp(list->modl_modp->mod_modname, "dtrace") == 0)
				return;
		}
	}

	/*
	 * KMDB is ineligible for instrumentation -- it may execute in
	 * any context, including probe context.
	 */
	if (strcmp(modname, "kmdbmod") == 0)
		return;

	if (str == NULL || symhdr == NULL || symhdr->sh_addr == 0) {
		/*
		 * If this module doesn't (yet) have its string or symbol
		 * table allocated, clear out.
		 */
		return;
	}

	symsize = symhdr->sh_entsize;

	if (mp->fbt_nentries) {
		/*
		 * This module has some FBT entries allocated; we're afraid
		 * to screw with it.
		 */
		return;
	}

	if (mp->fbt_tab != NULL)
		estimate = 0;

	/*
	 * This is a hack for unix/genunix/krtld.
	 */
	primary = vmem_contains(heap_arena, (void *)ctl,
	    sizeof (struct modctl)) == 0;
	kobj_textwin_alloc(mp);

	/*
	 * Open the CTF data for the module.  We'll use this to determine the
	 * functions that can be instrumented.  Note that this call can fail,
	 * in which case we'll use heuristics to determine the functions that
	 * can be instrumented.  (But in particular, leaf functions will not be
	 * instrumented.)
	 */
	fp = ctf_modopen(mp, &error);

forreal:
	if (!estimate) {
		tramp.fbtt_next =
		    (uintptr_t)fbt_trampoline_map((uintptr_t)mp->fbt_tab,
		    mp->fbt_size);
		tramp.fbtt_limit = tramp.fbtt_next + mp->fbt_size;
		tramp.fbtt_va = (uintptr_t)mp->fbt_tab;
	}

	for (i = 1; i < nsyms; i++) {
		ctf_funcinfo_t f;
		uint32_t *instr, *base, *limit;
		Sym *sym = (Sym *)(symhdr->sh_addr + i * symsize);
		int have_ctf = 0, is_leaf = 0, nargs, cti = 0;
		int (*canpatch)(uint32_t *, int, const char *);
		uint32_t (*patch)(uint32_t *, uint32_t *, uint32_t *, int,
		    uint32_t, fbt_trampoline_t *, const char *);

		if (ELF_ST_TYPE(sym->st_info) != STT_FUNC)
			continue;

		/*
		 * Weak symbols are not candidates.  This could be made to
		 * work (where weak functions and their underlying function
		 * appear as two disjoint probes), but it's not simple.
		 */
		if (ELF_ST_BIND(sym->st_info) == STB_WEAK)
			continue;

		name = str + sym->st_name;

		if (strstr(name, "dtrace_") == name &&
		    strstr(name, "dtrace_safe_") != name) {
			/*
			 * Anything beginning with "dtrace_" may be called
			 * from probe context unless it explitly indicates
			 * that it won't be called from probe context by
			 * using the prefix "dtrace_safe_".
			 */
			continue;
		}

		if (strstr(name, "kdi_") == name ||
		    strstr(name, "_kdi_") != NULL) {
			/*
			 * Any function name beginning with "kdi_" or
			 * containing the string "_kdi_" is a part of the
			 * kernel debugger interface and may be called in
			 * arbitrary context -- including probe context.
			 */
			continue;
		}

		if (strstr(name, "__relocatable") != NULL) {
			/*
			 * Anything with the string "__relocatable" anywhere
			 * in the function name is considered to be a function
			 * that may be manually relocated before execution.
			 * Because FBT uses a PC-relative technique for
			 * instrumentation, these functions cannot safely
			 * be instrumented by us.
			 */
			continue;
		}

		if (strstr(name, "ip_ocsum") == name) {
			/*
			 * The ip_ocsum_* family of routines are all ABI
			 * violators.  (They expect incoming arguments in the
			 * globals!)  Break the ABI?  No soup for you!
			 */
			continue;
		}

		/*
		 * We want to scan the function for one (and only one) save.
		 * Any more indicates that something fancy is going on.
		 */
		base = (uint32_t *)sym->st_value;
		limit = (uint32_t *)(sym->st_value + sym->st_size);

		/*
		 * We don't want to interpose on the module stubs.
		 */
		if (base >= (uint32_t *)stubs_base &&
		    base <= (uint32_t *)stubs_end)
			continue;

		/*
		 * We can't safely trace a zero-length function...
		 */
		if (base == limit)
			continue;

		/*
		 * Due to 4524008, _init and _fini may have a bloated st_size.
		 * While this bug was fixed quite some time ago, old drivers
		 * may be lurking.  We need to develop a better solution to
		 * this problem, such that correct _init and _fini functions
		 * (the vast majority) may be correctly traced.  One solution
		 * may be to scan through the entire symbol table to see if
		 * any symbol overlaps with _init.  If none does, set a bit in
		 * the module structure that this module has correct _init and
		 * _fini sizes.  This will cause some pain the first time a
		 * module is scanned, but at least it would be O(N) instead of
		 * O(N log N)...
		 */
		if (strcmp(name, "_init") == 0)
			continue;

		if (strcmp(name, "_fini") == 0)
			continue;

		instr = base;

		/*
		 * While we try hard to only trace safe functions (that is,
		 * functions at TL=0), one unsafe function manages to otherwise
		 * appear safe:  prom_trap().  We could discover prom_trap()
		 * if we added an additional rule:  in order to trace a
		 * function, we must either (a) discover a restore or (b)
		 * determine that the function does not have any unlinked
		 * control transfers to another function (i.e., the function
		 * never returns).  Unfortunately, as of this writing, one
		 * legitimate function (resume_from_zombie()) transfers
		 * control to a different function (_resume_from_idle())
		 * without executing a restore.  Barring a rule to figure out
		 * that resume_from_zombie() is safe while prom_trap() is not,
		 * we resort to hard-coding prom_trap() here.
		 */
		if (strcmp(name, "prom_trap") == 0)
			continue;

		if (fp != NULL && ctf_func_info(fp, i, &f) != CTF_ERR) {
			nargs = f.ctc_argc;
			have_ctf = 1;
		} else {
			nargs = 32;
		}

		/*
		 * If the first instruction of the function is a branch and
		 * it's not a branch-always-not-annulled, we're going to refuse
		 * to patch it.
		 */
		if ((*instr & FBT_OP_MASK) == FBT_OP0 &&
		    (*instr & FBT_FMT2_OP2_MASK) != FBT_FMT2_OP2_SETHI &&
		    (*instr & FBT_FMT2_OP2_MASK) != FBT_FMT2_OP2_BPR) {
			if (!FBT_IS_BA(*instr) && !FBT_IS_BAPCC(*instr)) {
				if (have_ctf) {
					cmn_err(CE_NOTE, "cannot instrument %s:"
					    " begins with non-ba, "
					    "non-br CTI", name);
				}
				continue;
			}
		}

		while (!FBT_IS_SAVE(*instr)) {
			/*
			 * Before we assume that this is a leaf routine, check
			 * forward in the basic block for a save.
			 */
			int op = *instr & FBT_OP_MASK;
			int op2 = *instr & FBT_FMT2_OP2_MASK;

			if (op == FBT_OP0 && op2 != FBT_FMT2_OP2_SETHI) {
				/*
				 * This is a CTI.  If we see a subsequent
				 * save, we will refuse to process this
				 * routine unless both of the following are
				 * true:
				 *
				 *  (a)	The branch is not annulled
				 *
				 *  (b)	The subsequent save is in the delay
				 *	slot of the branch
				 */
				if ((*instr & FBT_ANNUL) ||
				    !FBT_IS_SAVE(*(instr + 1))) {
					cti = 1;
				} else {
					instr++;
					break;
				}
			}

			if (op == FBT_OP1)
				cti = 1;

			if (++instr == limit)
				break;
		}

		if (instr < limit && cti) {
			/*
			 * If we found a CTI before the save, we need to not
			 * do anything.  But if we have CTF information, this
			 * is weird enough that it merits a message.
			 */
			if (!have_ctf)
				continue;

			cmn_err(CE_NOTE, "cannot instrument %s: "
			    "save not in first basic block", name);
			continue;
		}

		if (instr == limit) {
			if (!have_ctf)
				continue;
			is_leaf = 1;

			if (!estimate)
				fbt_leaf_functions++;

			canpatch = fbt_canpatch_retl;
			patch = fbt_patch_retl;
		} else {
			canpatch = fbt_canpatch_return;
			patch = fbt_patch_return;
		}

		if (!have_ctf && !is_leaf) {
			/*
			 * Before we assume that this isn't something tricky,
			 * look for other saves.  If we find them, there are
			 * multiple entry points here (or something), and we'll
			 * leave it alone.
			 */
			while (++instr < limit) {
				if (FBT_IS_SAVE(*instr))
					break;
			}

			if (instr != limit)
				continue;
		}

		instr = base;

		if (FBT_IS_CTI(*instr)) {
			/*
			 * If we have a CTI, we want to be sure that we don't
			 * have a CTI or a PC-relative instruction in the
			 * delay slot -- we want to be able to thunk the
			 * instruction into the trampoline without worrying
			 * about either DCTIs or relocations.  It would be
			 * very odd for the compiler to generate this kind of
			 * code, so we warn about it if we have CTF
			 * information.
			 */
			if (FBT_IS_CTI(*(instr + 1))) {
				if (!have_ctf)
					continue;

				cmn_err(CE_NOTE, "cannot instrument %s: "
				    "CTI in delay slot of first instruction",
				    name);
				continue;
			}

			if (FBT_IS_PCRELATIVE(*(instr + 1))) {
				if (!have_ctf)
					continue;

				cmn_err(CE_NOTE, "cannot instrument %s: "
				    "PC-relative instruction in delay slot of"
				    " first instruction", name);
				continue;
			}
		}

		if (estimate) {
			tramp.fbtt_next = (uintptr_t)faketramp;
			tramp.fbtt_limit = tramp.fbtt_next + sizeof (faketramp);
			(void) fbt_patch_entry(instr, FBT_ESTIMATE_ID,
			    &tramp, nargs);
			fbt_size += tramp.fbtt_next - (uintptr_t)faketramp;
		} else {
			fbt = kmem_zalloc(sizeof (fbt_probe_t), KM_SLEEP);
			fbt->fbtp_name = name;
			fbt->fbtp_ctl = ctl;
			fbt->fbtp_id = dtrace_probe_create(fbt_id, modname,
			    name, FBT_PROBENAME_ENTRY, 1, fbt);
			fbt->fbtp_patchval = FBT_BAA(instr, tramp.fbtt_va);

			if (!fbt_patch_entry(instr, fbt->fbtp_id,
			    &tramp, nargs)) {
				cmn_err(CE_WARN, "unexpectedly short FBT table "
				    "in module %s (sym %d of %d)", modname,
				    i, nsyms);
				break;
			}

			fbt->fbtp_patchpoint =
			    (uint32_t *)((uintptr_t)mp->textwin +
			    ((uintptr_t)instr - (uintptr_t)mp->text));
			fbt->fbtp_savedval = *instr;

			fbt->fbtp_loadcnt = ctl->mod_loadcnt;
			fbt->fbtp_primary = primary;
			fbt->fbtp_symndx = i;
			mp->fbt_nentries++;
		}

		retfbt = NULL;
again:
		if (++instr == limit)
			continue;

		offset = (uintptr_t)instr - (uintptr_t)base;

		if (!(*canpatch)(instr, offset, name))
			goto again;

		if (estimate) {
			tramp.fbtt_next = (uintptr_t)faketramp;
			tramp.fbtt_limit = tramp.fbtt_next + sizeof (faketramp);
			(void) (*patch)(instr, base, limit,
			    offset, FBT_ESTIMATE_ID, &tramp, name);
			fbt_size += tramp.fbtt_next - (uintptr_t)faketramp;

			goto again;
		}

		fbt = kmem_zalloc(sizeof (fbt_probe_t), KM_SLEEP);
		fbt->fbtp_name = name;
		fbt->fbtp_ctl = ctl;

		if (retfbt == NULL) {
			fbt->fbtp_id = dtrace_probe_create(fbt_id, modname,
			    name, FBT_PROBENAME_RETURN, 1, fbt);
		} else {
			retfbt->fbtp_next = fbt;
			fbt->fbtp_id = retfbt->fbtp_id;
		}

		fbt->fbtp_return = 1;
		retfbt = fbt;

		if ((fbt->fbtp_patchval = (*patch)(instr, base, limit, offset,
		    fbt->fbtp_id, &tramp, name)) == FBT_ILLTRAP) {
			cmn_err(CE_WARN, "unexpectedly short FBT table "
			    "in module %s (sym %d of %d)", modname, i, nsyms);
			break;
		}

		fbt->fbtp_patchpoint = (uint32_t *)((uintptr_t)mp->textwin +
		    ((uintptr_t)instr - (uintptr_t)mp->text));
		fbt->fbtp_savedval = *instr;
		fbt->fbtp_loadcnt = ctl->mod_loadcnt;
		fbt->fbtp_primary = primary;
		fbt->fbtp_symndx = i;
		mp->fbt_nentries++;

		goto again;
	}

	if (estimate) {
		/*
		 * Slosh on another entry's worth...
		 */
		fbt_size += FBT_ENT_MAXSIZE;
		mp->fbt_size = fbt_size;
		mp->fbt_tab = kobj_texthole_alloc(mp->text, fbt_size);

		if (mp->fbt_tab == NULL) {
			cmn_err(CE_WARN, "couldn't allocate FBT table "
			    "for module %s", modname);
		} else {
			estimate = 0;
			goto forreal;
		}
	} else {
		fbt_trampoline_unmap();
	}

error:
	if (fp != NULL)
		ctf_close(fp);
}

/*ARGSUSED*/
static void
fbt_destroy(void *arg, dtrace_id_t id, void *parg)
{
	fbt_probe_t *fbt = parg, *next;
	struct modctl *ctl = fbt->fbtp_ctl;

	do {
		if (ctl != NULL && ctl->mod_loadcnt == fbt->fbtp_loadcnt) {
			if ((ctl->mod_loadcnt == fbt->fbtp_loadcnt &&
			    ctl->mod_loaded) || fbt->fbtp_primary) {
				((struct module *)
				    (ctl->mod_mp))->fbt_nentries--;
			}
		}

		next = fbt->fbtp_next;
		kmem_free(fbt, sizeof (fbt_probe_t));
		fbt = next;
	} while (fbt != NULL);
}

/*ARGSUSED*/
static int
fbt_enable(void *arg, dtrace_id_t id, void *parg)
{
	fbt_probe_t *fbt = parg, *f;
	struct modctl *ctl = fbt->fbtp_ctl;

	ctl->mod_nenabled++;

	for (f = fbt; f != NULL; f = f->fbtp_next) {
		if (f->fbtp_patchpoint == NULL) {
			/*
			 * Due to a shortened FBT table, this entry was never
			 * completed; refuse to enable it.
			 */
			if (fbt_verbose) {
				cmn_err(CE_NOTE, "fbt is failing for probe %s "
				    "(short FBT table in %s)",
				    fbt->fbtp_name, ctl->mod_modname);
			}

			return (0);
		}
	}

	/*
	 * If this module has disappeared since we discovered its probes,
	 * refuse to enable it.
	 */
	if (!fbt->fbtp_primary && !ctl->mod_loaded) {
		if (fbt_verbose) {
			cmn_err(CE_NOTE, "fbt is failing for probe %s "
			    "(module %s unloaded)",
			    fbt->fbtp_name, ctl->mod_modname);
		}

		return (0);
	}

	/*
	 * Now check that our modctl has the expected load count.  If it
	 * doesn't, this module must have been unloaded and reloaded -- and
	 * we're not going to touch it.
	 */
	if (ctl->mod_loadcnt != fbt->fbtp_loadcnt) {
		if (fbt_verbose) {
			cmn_err(CE_NOTE, "fbt is failing for probe %s "
			    "(module %s reloaded)",
			    fbt->fbtp_name, ctl->mod_modname);
		}

		return (0);
	}

	for (; fbt != NULL; fbt = fbt->fbtp_next)
		*fbt->fbtp_patchpoint = fbt->fbtp_patchval;

	return (0);
}

/*ARGSUSED*/
static void
fbt_disable(void *arg, dtrace_id_t id, void *parg)
{
	fbt_probe_t *fbt = parg, *f;
	struct modctl *ctl = fbt->fbtp_ctl;

	ASSERT(ctl->mod_nenabled > 0);
	ctl->mod_nenabled--;

	for (f = fbt; f != NULL; f = f->fbtp_next) {
		if (f->fbtp_patchpoint == NULL)
			return;
	}

	if ((!fbt->fbtp_primary && !ctl->mod_loaded) ||
	    (ctl->mod_loadcnt != fbt->fbtp_loadcnt))
		return;

	for (; fbt != NULL; fbt = fbt->fbtp_next)
		*fbt->fbtp_patchpoint = fbt->fbtp_savedval;
}

/*ARGSUSED*/
static void
fbt_suspend(void *arg, dtrace_id_t id, void *parg)
{
	fbt_probe_t *fbt = parg;
	struct modctl *ctl = fbt->fbtp_ctl;

	if (!fbt->fbtp_primary && !ctl->mod_loaded)
		return;

	if (ctl->mod_loadcnt != fbt->fbtp_loadcnt)
		return;

	ASSERT(ctl->mod_nenabled > 0);

	for (; fbt != NULL; fbt = fbt->fbtp_next)
		*fbt->fbtp_patchpoint = fbt->fbtp_savedval;
}

/*ARGSUSED*/
static void
fbt_resume(void *arg, dtrace_id_t id, void *parg)
{
	fbt_probe_t *fbt = parg;
	struct modctl *ctl = fbt->fbtp_ctl;

	if (!fbt->fbtp_primary && !ctl->mod_loaded)
		return;

	if (ctl->mod_loadcnt != fbt->fbtp_loadcnt)
		return;

	ASSERT(ctl->mod_nenabled > 0);

	for (; fbt != NULL; fbt = fbt->fbtp_next)
		*fbt->fbtp_patchpoint = fbt->fbtp_patchval;
}

/*ARGSUSED*/
static void
fbt_getargdesc(void *arg, dtrace_id_t id, void *parg, dtrace_argdesc_t *desc)
{
	fbt_probe_t *fbt = parg;
	struct modctl *ctl = fbt->fbtp_ctl;
	struct module *mp = ctl->mod_mp;
	ctf_file_t *fp = NULL, *pfp;
	ctf_funcinfo_t f;
	int error;
	ctf_id_t argv[32], type;
	int argc = sizeof (argv) / sizeof (ctf_id_t);
	const char *parent;

	if (!ctl->mod_loaded || (ctl->mod_loadcnt != fbt->fbtp_loadcnt))
		goto err;

	if (fbt->fbtp_return && desc->dtargd_ndx == 0) {
		(void) strcpy(desc->dtargd_native, "int");
		return;
	}

	if ((fp = ctf_modopen(mp, &error)) == NULL) {
		/*
		 * We have no CTF information for this module -- and therefore
		 * no args[] information.
		 */
		goto err;
	}

	/*
	 * If we have a parent container, we must manually import it.
	 */
	if ((parent = ctf_parent_name(fp)) != NULL) {
		struct modctl *mp = &modules;
		struct modctl *mod = NULL;

		/*
		 * We must iterate over all modules to find the module that
		 * is our parent.
		 */
		do {
			if (strcmp(mp->mod_modname, parent) == 0) {
				mod = mp;
				break;
			}
		} while ((mp = mp->mod_next) != &modules);

		if (mod == NULL)
			goto err;

		if ((pfp = ctf_modopen(mod->mod_mp, &error)) == NULL)
			goto err;

		if (ctf_import(fp, pfp) != 0) {
			ctf_close(pfp);
			goto err;
		}

		ctf_close(pfp);
	}

	if (ctf_func_info(fp, fbt->fbtp_symndx, &f) == CTF_ERR)
		goto err;

	if (fbt->fbtp_return) {
		if (desc->dtargd_ndx > 1)
			goto err;

		ASSERT(desc->dtargd_ndx == 1);
		type = f.ctc_return;
	} else {
		if (desc->dtargd_ndx + 1 > f.ctc_argc)
			goto err;

		if (ctf_func_args(fp, fbt->fbtp_symndx, argc, argv) == CTF_ERR)
			goto err;

		type = argv[desc->dtargd_ndx];
	}

	if (ctf_type_name(fp, type, desc->dtargd_native,
	    DTRACE_ARGTYPELEN) != NULL) {
		ctf_close(fp);
		return;
	}
err:
	if (fp != NULL)
		ctf_close(fp);

	desc->dtargd_ndx = DTRACE_ARGNONE;
}

static dtrace_pattr_t fbt_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

static dtrace_pops_t fbt_pops = {
	NULL,
	fbt_provide_module,
	fbt_enable,
	fbt_disable,
	fbt_suspend,
	fbt_resume,
	fbt_getargdesc,
	NULL,
	NULL,
	fbt_destroy
};

static int
fbt_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(devi, "fbt", S_IFCHR, 0,
	    DDI_PSEUDO, 0) == DDI_FAILURE ||
	    dtrace_register("fbt", &fbt_attr, DTRACE_PRIV_KERNEL, NULL,
	    &fbt_pops, NULL, &fbt_id) != 0) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}

	ddi_report_dev(devi);
	fbt_devi = devi;
	return (DDI_SUCCESS);
}

static int
fbt_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (dtrace_unregister(fbt_id) != 0)
		return (DDI_FAILURE);

	ddi_remove_minor_node(devi, NULL);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
fbt_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)fbt_devi;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/*ARGSUSED*/
static int
fbt_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	return (0);
}

static struct cb_ops fbt_cb_ops = {
	fbt_open,		/* open */
	nodev,			/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP		/* Driver compatibility flag */
};

static struct dev_ops fbt_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	fbt_info,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	fbt_attach,		/* attach */
	fbt_detach,		/* detach */
	nodev,			/* reset */
	&fbt_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	nodev,			/* dev power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,		/* module type (this is a pseudo driver) */
	"Function Boundary Tracing",	/* name of module */
	&fbt_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
