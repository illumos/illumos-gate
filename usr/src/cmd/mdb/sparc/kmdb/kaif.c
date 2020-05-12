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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The debugger/PROM interface
 */

#include <sys/types.h>
#include <sys/mmu.h>

#ifndef	sun4v
#include <sys/spitregs.h>
#endif	/* sun4v */

#include <sys/machasi.h>
#include <sys/machtrap.h>
#include <sys/trap.h>
#include <sys/privregs.h>

#include <kmdb/kaif.h>
#include <kmdb/kaif_regs.h>
#include <kmdb/kmdb_asmutil.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kmdb_promif_isadep.h>
#include <kmdb/kmdb_dpi_impl.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_nv.h>
#include <mdb/mdb_kreg_impl.h>
#include <mdb/mdb_v9util.h>
#include <mdb/mdb.h>

#define	KAIF_PREGNO_PSTATE	0x6		/* %pstate is priv reg 6 */
#define	KAIF_BRKPT_INSTR	0x91d0207e	/* ta 0x7e */


#define	OP(x)		((x) >> 30)
#define	OP2(x)		(((x) >> 22) & 0x07)
#define	OP3(x)		(((x) >> 19) & 0x3f)
#define	COND(x)		(((x) >> 25) & 0x0f)
#define	RD(x)		(((x) >> 25) & 0x1f)
#define	RS1(x)		(((x) >> 14) & 0x1f)
#define	RS2(x)		((x) & 0x1f)

#define	OP_BRANCH	0x0
#define	OP_ARITH	0x2

#define	OP2_BPcc	0x1
#define	OP2_Bicc	0x2
#define	OP2_BPr		0x3
#define	OP2_FBPfcc	0x5
#define	OP2_FBfcc	0x6

#define	OP3_RDPR	0x2a
#define	OP3_WRPR	0x32

#define	A(x)		(((x) >> 29) & 0x01)
#define	I(x)		(((x) >> 13) & 0x01)
#define	DISP16(x)	((((x) >> 6) & 0xc000) | ((x) & 0x3fff))
#define	DISP22(x)	((x) & 0x3fffff)
#define	DISP19(x)	((x) & 0x7ffff)
#define	SIMM13(x)	((x) & 0x1fff)

static uint64_t		kaif_vwapt_addr;
static uint64_t		kaif_pwapt_addr;

#ifndef	sun4v
static uint64_t		kaif_lsuctl;
#endif	/* sun4v */

kaif_cpusave_t		*kaif_cpusave;
int			kaif_ncpusave;
caddr_t			kaif_dseg;
caddr_t			kaif_dseg_lim;
caddr_t			kaif_tba;		/* table currently in use */
caddr_t			kaif_tba_obp;		/* obp's trap table */
caddr_t			kaif_tba_native;	/* our table; needs khat */
#ifdef	sun4v
caddr_t			kaif_tba_kernel;	/* kernel's trap table */
#endif	/* sun4v */
size_t			kaif_tba_native_sz;
int			*kaif_promexitarmp;
int			kaif_trap_switch;

void (*kaif_modchg_cb)(struct modctl *, int);
void (*kaif_ktrap_install)(int, void (*)(void));
void (*kaif_ktrap_restore)(void);

static int
kaif_get_master_cpuid(void)
{
	return (kaif_master_cpuid);
}

/*ARGSUSED*/
static int
kaif_get_nwin(int cpuid)
{
	return (get_nwin());
}

static kaif_cpusave_t *
kaif_cpuid2save(int cpuid)
{
	kaif_cpusave_t *save;

	if (cpuid == DPI_MASTER_CPUID)
		return (&kaif_cpusave[kaif_master_cpuid]);

	if (cpuid < 0 || cpuid >= kaif_ncpusave) {
		(void) set_errno(EINVAL);
		return (NULL);
	}

	save = &kaif_cpusave[cpuid];

	if (save->krs_cpu_state != KAIF_CPU_STATE_MASTER &&
	    save->krs_cpu_state != KAIF_CPU_STATE_SLAVE) {
		(void) set_errno(EINVAL);
		return (NULL);
	}

	return (save);
}

static int
kaif_get_cpu_state(int cpuid)
{
	kaif_cpusave_t *save;

	if ((save = kaif_cpuid2save(cpuid)) == NULL)
		return (-1); /* errno is set for us */

	switch (save->krs_cpu_state) {
	case KAIF_CPU_STATE_MASTER:
		return (DPI_CPU_STATE_MASTER);
	case KAIF_CPU_STATE_SLAVE:
		return (DPI_CPU_STATE_SLAVE);
	default:
		return (set_errno(EINVAL));
	}
}

static const mdb_tgt_gregset_t *
kaif_get_gregs(int cpuid)
{
	kaif_cpusave_t *save;
	mdb_tgt_gregset_t *gregs;
	int wp, i;

	if ((save = kaif_cpuid2save(cpuid)) == NULL)
		return (NULL); /* errno is set for us */

	gregs = &save->krs_gregs;

	/*
	 * The DPI startup routine populates the register window portions of
	 * the kaif_cpusave_t.  We copy the current set of ins, outs, and
	 * locals to the gregs.  We also extract %pstate from %tstate.
	 */
	wp = gregs->kregs[KREG_CWP];
	for (i = 0; i < 8; i++) {
		gregs->kregs[KREG_L0 + i] = save->krs_rwins[wp].rw_local[i];
		gregs->kregs[KREG_I0 + i] = save->krs_rwins[wp].rw_in[i];
	}

	gregs->kregs[KREG_PSTATE] = KREG_TSTATE_PSTATE(save->krs_tstate);

	if (++wp == kaif_get_nwin(cpuid))
		wp = 0;

	for (i = 0; i < 8; i++)
		gregs->kregs[KREG_O0 + i] = save->krs_rwins[wp].rw_in[i];

	return (gregs);
}

static kreg_t *
kaif_find_regp(kaif_cpusave_t *save, const char *regname)
{
	mdb_tgt_gregset_t *gregs;
	int nwin, i;
	int win;

	nwin = kaif_get_nwin(DPI_MASTER_CPUID);

	gregs = &save->krs_gregs;

	win = gregs->kregs[KREG_CWP];

	if (strcmp(regname, "sp") == 0)
		regname = "o6";
	else if (strcmp(regname, "fp") == 0)
		regname = "i6";

	if (strlen(regname) == 2 && regname[1] >= '0' && regname[1] <= '7') {
		int idx = regname[1] - '0';

		switch (regname[0]) {
		case 'o':
			if (++win == nwin)
				win = 0;
			/*FALLTHROUGH*/
		case 'i':
			return ((kreg_t *)&save->krs_rwins[win].rw_in[idx]);
		case 'l':
			return ((kreg_t *)&save->krs_rwins[win].rw_local[idx]);
		}
	}

	for (i = 0; mdb_sparcv9_kregs[i].rd_name != NULL; i++) {
		const mdb_tgt_regdesc_t *rd = &mdb_sparcv9_kregs[i];

		if (strcmp(rd->rd_name, regname) == 0)
			return (&gregs->kregs[rd->rd_num]);
	}

	(void) set_errno(ENOENT);
	return (NULL);
}

static int
kaif_get_register(const char *regname, kreg_t *valp)
{
	kaif_cpusave_t *save;
	kreg_t *regp;

	save = kaif_cpuid2save(DPI_MASTER_CPUID);

	if (strcmp(regname, "pstate") == 0) {
		*valp = KREG_TSTATE_PSTATE(save->krs_tstate);
		return (0);
	}

	if ((regp = kaif_find_regp(save, regname)) == NULL)
		return (-1);

	*valp = *regp;

	return (0);
}

static int
kaif_set_register(const char *regname, kreg_t val)
{
	kaif_cpusave_t *save;
	kreg_t *regp;

	save = kaif_cpuid2save(DPI_MASTER_CPUID);

	if (strcmp(regname, "g0") == 0) {
		return (0);

	} else if (strcmp(regname, "pstate") == 0) {
		save->krs_tstate &= ~KREG_TSTATE_PSTATE_MASK;
		save->krs_tstate |= (val & KREG_PSTATE_MASK) <<
		    KREG_TSTATE_PSTATE_SHIFT;
		return (0);
	}

	if ((regp = kaif_find_regp(save, regname)) == NULL)
		return (-1);

	*regp = val;

	return (0);
}

static int
kaif_brkpt_arm(uintptr_t addr, mdb_instr_t *instrp)
{
	mdb_instr_t bkpt = KAIF_BRKPT_INSTR;

	if (mdb_tgt_vread(mdb.m_target, instrp, sizeof (mdb_instr_t), addr) !=
	    sizeof (mdb_instr_t))
		return (-1); /* errno is set for us */

	if (mdb_tgt_vwrite(mdb.m_target, &bkpt, sizeof (mdb_instr_t), addr) !=
	    sizeof (mdb_instr_t))
		return (-1); /* errno is set for us */

	return (0);
}

static int
kaif_brkpt_disarm(uintptr_t addr, mdb_instr_t instrp)
{
	if (mdb_tgt_vwrite(mdb.m_target, &instrp, sizeof (mdb_instr_t), addr) !=
	    sizeof (mdb_instr_t))
		return (-1); /* errno is set for us */

	return (0);
}

/*
 * Calculate the watchpoint mask byte (VM or PM, as appropriate).  A 1 bit in
 * the mask indicates that the corresponding byte in the watchpoint address
 * should be used for activation comparison.
 */
/*
 * Sun4v doesn't have watchpoint regs
 */
#ifndef	sun4v
static uchar_t
kaif_wapt_calc_mask(size_t len)
{
	int pow;

	if (len == 8)
		return (0xff);

	for (pow = 0; len > 1; len /= 256, pow++)
		;

	return (~((1 << pow) - 1));
}
#endif

/*
 * UltraSPARC processors have one physical and one virtual watchpoint.  These
 * watchpoints are specified by setting the address in a register, and by
 * setting a selector byte in another register to determine which bytes of the
 * address are to be used for comparison.  For simplicity, we only support
 * selector byte values whose bit patterns match the regexp "1+0*".  Watchpoint
 * addresses must be 8-byte aligned on these chips, so a selector byte of 0xff
 * indicates an 8-byte watchpoint.  Successive valid sizes are powers of 256,
 * starting with 256.
 */
static int
kaif_wapt_validate(kmdb_wapt_t *wp)
{
	if (wp->wp_wflags & MDB_TGT_WA_X) {
		warn("execute watchpoints are not supported on this "
		    "platform\n");
		return (set_errno(EMDB_TGTNOTSUP));
	}

	if (wp->wp_size % 0xff != 0 && wp->wp_size != 8) {
		warn("watchpoint size must be 8 or a power of 256 bytes\n");
		return (set_errno(EINVAL));
	}

	if (wp->wp_addr & (wp->wp_size - 1)) {
		warn("%lu-byte watchpoints must be %lu-byte aligned\n",
		    wp->wp_size, wp->wp_size);
		return (set_errno(EINVAL));
	}

	if (wp->wp_type != DPI_WAPT_TYPE_PHYS &&
	    wp->wp_type != DPI_WAPT_TYPE_VIRT) {
		warn("requested watchpoint type not supported on this "
		    "platform\n");
		return (set_errno(EMDB_TGTHWNOTSUP));
	}

	return (0);
}

static int
kaif_wapt_reserve(kmdb_wapt_t *wp)
{
#ifdef	sun4v
#ifdef	lint
	ASSERT(wp == (kmdb_wapt_t *)wp);
#endif	/* !lint */
	/* Watchpoints not supported */
	return (set_errno(EMDB_TGTHWNOTSUP));
#else
	uint64_t *addrp;

	if (wp->wp_type == DPI_WAPT_TYPE_PHYS)
		addrp = &kaif_pwapt_addr;
	else
		addrp = &kaif_vwapt_addr;

	if (*addrp != 0)
		return (set_errno(EMDB_WPTOOMANY));

	*addrp = wp->wp_addr;

	return (0);
#endif
}

static void
kaif_wapt_release(kmdb_wapt_t *wp)
{
	uint64_t *addrp = (wp->wp_type == DPI_WAPT_TYPE_PHYS ?
	    &kaif_pwapt_addr : &kaif_vwapt_addr);

	ASSERT(*addrp != 0);
	*addrp = 0;
}

/*ARGSUSED*/
static void
kaif_wapt_arm(kmdb_wapt_t *wp)
{
	/*
	 * Sun4v doesn't have watch point regs
	 */
#ifndef	sun4v
	uint64_t mask = kaif_wapt_calc_mask(wp->wp_size);

	if (wp->wp_type == DPI_WAPT_TYPE_PHYS) {
		kaif_lsuctl &= ~KAIF_LSUCTL_PWAPT_MASK;

		if (wp->wp_wflags & MDB_TGT_WA_R)
			kaif_lsuctl |= LSU_PR;
		if (wp->wp_wflags & MDB_TGT_WA_W)
			kaif_lsuctl |= LSU_PW;
		kaif_lsuctl |= ((mask << LSU_PM_SHIFT) & LSU_PM);

	} else if (wp->wp_type == DPI_WAPT_TYPE_VIRT) {
		kaif_lsuctl &= ~KAIF_LSUCTL_VWAPT_MASK;

		if (wp->wp_wflags & MDB_TGT_WA_R)
			kaif_lsuctl |= LSU_VR;
		if (wp->wp_wflags & MDB_TGT_WA_W)
			kaif_lsuctl |= LSU_VW;
		kaif_lsuctl |= ((mask << LSU_VM_SHIFT) & LSU_VM);
	}
#endif	/* sun4v */
}

/*ARGSUSED*/
static void
kaif_wapt_disarm(kmdb_wapt_t *wp)
{
	/*
	 * Sun4v doesn't have watch point regs
	 */
#ifndef	sun4v
	if (wp->wp_type == DPI_WAPT_TYPE_PHYS) {
		ASSERT(kaif_pwapt_addr != NULL);
		kaif_lsuctl &= ~(LSU_PR|LSU_PW);
	} else {
		ASSERT(kaif_vwapt_addr != NULL);
		kaif_lsuctl &= ~(LSU_VR|LSU_VW);
	}
#endif
}

/*
 * `kaif_wapt_arm' and `kaif_wapt_disarm' modify the global state we keep that
 * indicates what the values of the wapt control registers should be.  These
 * values must be individually set and cleared on each active CPU, a task which
 * is performed by `kaif_wapt_clear_regs' and `kaif_wapt_set_regs', invoked as
 * the world is stopped and resumed, respectively.  `kaif_wapt_set_regs' is also
 * used for CPU initialization.
 */
void
kaif_wapt_set_regs(void)
{
	/*
	 * Sun4v doesn't have watch point regs
	 */
#ifndef sun4v
	uint64_t lsu;

	wrasi(ASI_DMMU, MMU_VAW, kaif_vwapt_addr);
	wrasi(ASI_DMMU, MMU_PAW, kaif_pwapt_addr);

	ASSERT((kaif_lsuctl & ~KAIF_LSUCTL_WAPT_MASK) == NULL);

	lsu = rdasi(ASI_LSU, (uintptr_t)NULL);
	lsu &= ~KAIF_LSUCTL_WAPT_MASK;
	lsu |= kaif_lsuctl;
	wrasi(ASI_LSU, (uintptr_t)NULL, lsu);
#endif /* sun4v */
}

void
kaif_wapt_clear_regs(void)
{
	/*
	 * Sun4v doesn't have watch point regs
	 */
#ifndef sun4v
	uint64_t lsu = rdasi(ASI_LSU, (uintptr_t)NULL);
	lsu &= ~KAIF_LSUCTL_WAPT_MASK;
	wrasi(ASI_LSU, (uintptr_t)NULL, lsu);
#endif /* sun4v */
}

/*
 * UltraSPARC has one PA watchpoint and one VA watchpoint.  The trap we get will
 * tell us which one we hit, but it won't tell us where.  We could attempt to
 * dissect the instruction at %pc to see where it was reading from or writing
 * to, but that gets messy in a hurry.  We can, however, make a couple of
 * assumptions:
 *
 * - kaif_set_watchpoint and kaif_delete_watchpoint will enforce the limits as
 *   to the number of watch points.  As such, at most one VA watchpoint and one
 *   PA watchpoint will be on the active list.
 *
 * - We'll only be called on watchpoints that are on the active list.
 *
 * Taking these two assumptions, we can conclude that, if we're stopped due to
 * a watchpoint and we're asked to match against a watchpoint, we must have
 * stopped due to the watchpoint.  This is all very terrifying, but the
 * alternative (taking instructions apart) is worse.
 */
/*ARGSUSED*/
static int
kaif_wapt_match(kmdb_wapt_t *wp)
{
	int state, why, deswhy;

	state = kmdb_dpi_get_state(&why);

	if (wp->wp_type == DPI_WAPT_TYPE_PHYS)
		deswhy = DPI_STATE_WHY_P_WAPT;
	else
		deswhy = DPI_STATE_WHY_V_WAPT;

	return (state == DPI_STATE_FAULTED && why == deswhy);
}

static const char *
regno2name(int idx)
{
	const mdb_tgt_regdesc_t *rd;

	for (rd = mdb_sparcv9_kregs; rd->rd_name != NULL; rd++) {
		if (idx == rd->rd_num)
			return (rd->rd_name);
	}

	ASSERT(rd->rd_name != NULL);

	return ("unknown");
}

/*
 * UltraSPARC doesn't support single-step natively, so we have to do it
 * ourselves, by placing breakpoints at the instruction after the current one.
 * Note that "after" will be %npc in the simple case, but can be one of
 * several places if %pc is a branch.
 *
 * If %pc is an unconditional annulled branch, we put a breakpoint at the branch
 * target.  If it is a conditional annulled branch, we put breakpoints at %pc +
 * 8 and the branch target.  For all other branches, %npc will be set correctly
 * as determined by the branch condition, and thus we can step through the
 * branch by putting a breakpoint at %npc.  If %pc contains a non-branch
 * instruction (with the exception of certain rdpr and wrpr instructions,
 * described more below), we step over it by placing a breakpoint at %npc.
 */
static int
kaif_step(void)
{
	kreg_t pc, npc, brtgt, pstate, tt;
	int bptgt = 0, bpnpc = 0, bppc8 = 0;
	mdb_instr_t svtgt = 0, svnpc = 0, svpc8 = 0;
	mdb_instr_t instr;
	int ie, err;

	(void) kmdb_dpi_get_register("pc", &pc);
	(void) kmdb_dpi_get_register("npc", &npc);

	if (mdb_tgt_vread(mdb.m_target, &instr, sizeof (instr), pc) !=
	    sizeof (instr)) {
		warn("failed to read %%pc at %p for step", (void *)pc);
		return (-1);
	}

	/*
	 * If the current instruction is a read or write of PSTATE we need
	 * to emulate it because we've taken over management of PSTATE and
	 * we need keep interrupts disabled. If it's a branch, we may need
	 * to set two breakpoints -- one at the target and one at the
	 * subsequent instruction.
	 */
	if (OP(instr) == OP_ARITH) {
		if (OP3(instr) == OP3_RDPR &&
		    RS1(instr) == KAIF_PREGNO_PSTATE) {
			const char *tgtreg =
			    mdb_sparcv9_kregs[RD(instr)].rd_name;
			kreg_t pstate;

			(void) kmdb_dpi_get_register("pstate", &pstate);
			(void) kmdb_dpi_set_register(tgtreg, pstate);

			(void) kmdb_dpi_set_register("pc", npc);
			(void) kmdb_dpi_set_register("npc", npc + 4);
			return (0);

		} else if (OP3(instr) == OP3_WRPR &&
		    RD(instr) == KAIF_PREGNO_PSTATE) {
			kreg_t rs1, rs2, val;

			(void) kmdb_dpi_get_register(regno2name(RS1(instr)),
			    &rs1);

			if (I(instr)) {
				int imm = SIMM13(instr);
				imm <<= 19;
				imm >>= 19;
				rs2 = imm;
			} else {
				(void) kmdb_dpi_get_register(
				    regno2name(RS2(instr)), &rs2);
			}

			val = rs1 ^ rs2;

			(void) kmdb_dpi_set_register("pstate", val);

			(void) kmdb_dpi_set_register("pc", npc);
			(void) kmdb_dpi_set_register("npc", npc + 4);
			return (0);

		}

		bpnpc = 1;

	} else if (OP(instr) == OP_BRANCH) {
		int disp, cond, annul;

		switch (OP2(instr)) {
		case OP2_BPcc:
		case OP2_FBPfcc:
			cond = (COND(instr) != 8);

			disp = DISP19(instr);
			disp <<= 13;
			disp >>= 11;
			break;

		case OP2_Bicc:
		case OP2_FBfcc:
			cond = (COND(instr) != 8);

			disp = DISP22(instr);
			disp <<= 10;
			disp >>= 8;
			break;

		case OP2_BPr:
			cond = 1;

			disp = DISP16(instr);
			disp <<= 16;
			disp >>= 14;
			break;

		default:
			bpnpc = 1;
		}

		if (!bpnpc) {
			annul = A(instr);

			if (!cond && annul) {
				brtgt = pc + disp;
				bptgt = 1;
			} else {
				bpnpc = 1;

				if (cond && annul)
					bppc8 = 1;
			}
		}

	} else {
		bpnpc = 1;
	}

	/*
	 * Place the breakpoints and resume this CPU with IE off.  We'll come
	 * back after having encountered either one of the breakpoints we placed
	 * or a trap.
	 */
	err = 0;
	if ((bpnpc && kaif_brkpt_arm(npc, &svnpc) != 0) ||
	    (bppc8 && kaif_brkpt_arm(pc + 8, &svpc8) != 0) ||
	    (bptgt && kaif_brkpt_arm(brtgt, &svtgt) != 0)) {
		err = errno;
		goto step_done;
	}

	(void) kmdb_dpi_get_register("pstate", &pstate);
	ie = pstate & KREG_PSTATE_IE_MASK;
	(void) kmdb_dpi_set_register("pstate", (pstate & ~KREG_PSTATE_IE_MASK));

	kmdb_dpi_resume_master(); /* ... there and back again ... */

	(void) kmdb_dpi_get_register("pstate", &pstate);
	(void) kmdb_dpi_set_register("pstate",
	    ((pstate & ~KREG_PSTATE_IE_MASK) | ie));

	(void) kmdb_dpi_get_register("tt", &tt);

step_done:
	if (svnpc)
		(void) kaif_brkpt_disarm(npc, svnpc);
	if (svpc8)
		(void) kaif_brkpt_disarm(pc + 8, svpc8);
	if (svtgt)
		(void) kaif_brkpt_disarm(brtgt, svtgt);

	return (err == 0 ? 0 : set_errno(err));
}

static uintptr_t
kaif_call(uintptr_t funcva, uint_t argc, const uintptr_t *argv)
{
	kreg_t g6, g7;

	(void) kmdb_dpi_get_register("g6", &g6);
	(void) kmdb_dpi_get_register("g7", &g7);

	return (kaif_invoke(funcva, argc, argv, g6, g7));
}

static const mdb_bitmask_t krm_flag_bits[] = {
	{ "M_W",	KAIF_CRUMB_F_MAIN_OBPWAPT, KAIF_CRUMB_F_MAIN_OBPWAPT },
	{ "M_PE",	KAIF_CRUMB_F_MAIN_OBPPENT, KAIF_CRUMB_F_MAIN_OBPPENT },
	{ "M_NRM",	KAIF_CRUMB_F_MAIN_NORMAL, KAIF_CRUMB_F_MAIN_NORMAL },
	{ "I_RE",	KAIF_CRUMB_F_IVEC_REENTER, KAIF_CRUMB_F_IVEC_REENTER },
	{ "I_OBP",	KAIF_CRUMB_F_IVEC_INOBP, KAIF_CRUMB_F_IVEC_INOBP },
	{ "I_NRM",	KAIF_CRUMB_F_IVEC_NORMAL, KAIF_CRUMB_F_IVEC_NORMAL },
	{ "O_NRM",	KAIF_CRUMB_F_OBP_NORMAL, KAIF_CRUMB_F_OBP_NORMAL },
	{ "O_REVEC",	KAIF_CRUMB_F_OBP_REVECT, KAIF_CRUMB_F_OBP_REVECT },
	{ NULL }
};

static void
dump_crumb(kaif_crumb_t *krmp)
{
	kaif_crumb_t krm;

	if (mdb_vread(&krm, sizeof (kaif_crumb_t), (uintptr_t)krmp) !=
	    sizeof (kaif_crumb_t)) {
		warn("failed to read crumb at %p", krmp);
		return;
	}

	mdb_printf(" src: ");
	switch (krm.krm_src) {
	case KAIF_CRUMB_SRC_OBP:
		mdb_printf("O");
		break;
	case KAIF_CRUMB_SRC_IVEC:
		mdb_printf("I");
		break;
	case KAIF_CRUMB_SRC_MAIN:
		mdb_printf("M");
		break;
	case 0:
		mdb_printf("-");
		break;
	default:
		mdb_printf("%d", krm.krm_src);
	}

	mdb_printf(" tt %3x pc %8p %-20A <%b>\n",
	    krm.krm_tt, krm.krm_pc, krm.krm_pc, krm.krm_flag, krm_flag_bits);
}

static void
dump_crumbs(kaif_cpusave_t *save)
{
	int i;

	for (i = KAIF_NCRUMBS; i > 0; i--) {
		uint_t idx = (save->krs_curcrumbidx + i) % KAIF_NCRUMBS;
		dump_crumb(&save->krs_crumbs[idx]);
	}
}

static void
kaif_dump_crumbs(uintptr_t addr, int cpuid)
{
	int i;

	if (addr != (uintptr_t)NULL) {
		/* dump_crumb will protect us from bogus addresses */
		dump_crumb((kaif_crumb_t *)addr);

	} else if (cpuid != -1) {
		if (cpuid >= kaif_ncpusave)
			return;

		dump_crumbs(&kaif_cpusave[cpuid]);

	} else {
		for (i = 0; i < kaif_ncpusave; i++) {
			kaif_cpusave_t *save = &kaif_cpusave[i];

			if (save->krs_cpu_state == KAIF_CPU_STATE_NONE)
				continue;

			mdb_printf("%sCPU %d crumbs: (curidx %d)\n",
			    (i == 0 ? "" : "\n"), i, save->krs_curcrumbidx);

			dump_crumbs(save);
		}
	}
}

static int
kaif_get_rwin(int cpuid, int win, struct rwindow *rwin)
{
	kaif_cpusave_t *save;

	if ((save = kaif_cpuid2save(cpuid)) == NULL)
		return (-1); /* errno is set for us */

	if (win < 0 || win >= kaif_get_nwin(cpuid))
		return (-1);

	bcopy(&save->krs_rwins[win], rwin, sizeof (struct rwindow));

	return (0);
}

static void
kaif_enter_mon(void)
{
	kmdb_prom_enter_mon();
	kaif_prom_rearm();
	kaif_slave_loop_barrier();
}

static void
kaif_modchg_register(void (*func)(struct modctl *, int))
{
	kaif_modchg_cb = func;
}

static void
kaif_modchg_cancel(void)
{
	ASSERT(kaif_modchg_cb != NULL);

	kaif_modchg_cb = NULL;
}

void
kaif_mod_loaded(struct modctl *modp)
{
	if (kaif_modchg_cb != NULL)
		kaif_modchg_cb(modp, 1);
}

void
kaif_mod_unloading(struct modctl *modp)
{
	if (kaif_modchg_cb != NULL)
		kaif_modchg_cb(modp, 0);
}

void
kaif_trap_set_debugger(void)
{
	(void) set_tba((void *)kaif_tba);
}

void
kaif_trap_set_saved(kaif_cpusave_t *save)
{
	(void) set_tba((void *)save->krs_gregs.kregs[KREG_TBA]);
}

static void
kaif_kernpanic(int cpuid)
{
	struct regs regs;

	/*
	 * We're going to try to panic the system by using the same entry point
	 * used by the PROM when told to `sync'.  The kernel wants a
	 * fully-populated struct regs, which we're going to build using the
	 * state captured at the time of the debugger fault.  Said state lives
	 * in kaif_cb_save, since we haven't yet copied it over to the cpusave
	 * structure for the current master.
	 */

	regs.r_tstate = kaif_cb_save.krs_tstate;

	regs.r_g1 = kaif_cb_save.krs_gregs.kregs[KREG_G1];
	regs.r_g2 = kaif_cb_save.krs_gregs.kregs[KREG_G2];
	regs.r_g3 = kaif_cb_save.krs_gregs.kregs[KREG_G3];
	regs.r_g4 = kaif_cb_save.krs_gregs.kregs[KREG_G4];
	regs.r_g5 = kaif_cb_save.krs_gregs.kregs[KREG_G5];
	regs.r_g6 = kaif_cb_save.krs_gregs.kregs[KREG_G6];
	regs.r_g7 = kaif_cb_save.krs_gregs.kregs[KREG_G7];

	regs.r_o0 = kaif_cb_save.krs_gregs.kregs[KREG_O0];
	regs.r_o1 = kaif_cb_save.krs_gregs.kregs[KREG_O1];
	regs.r_o2 = kaif_cb_save.krs_gregs.kregs[KREG_O2];
	regs.r_o3 = kaif_cb_save.krs_gregs.kregs[KREG_O3];
	regs.r_o4 = kaif_cb_save.krs_gregs.kregs[KREG_O4];
	regs.r_o5 = kaif_cb_save.krs_gregs.kregs[KREG_O5];
	regs.r_o6 = kaif_cb_save.krs_gregs.kregs[KREG_O6];
	regs.r_o7 = kaif_cb_save.krs_gregs.kregs[KREG_O7];

	regs.r_pc = kaif_cb_save.krs_gregs.kregs[KREG_PC];
	regs.r_npc = kaif_cb_save.krs_gregs.kregs[KREG_NPC];
	regs.r_y = kaif_cb_save.krs_gregs.kregs[KREG_Y];

	/*
	 * The %tba is, as ever, different.  We don't want the %tba from the
	 * time of the fault -- that'll be the debugger's.  We want the %tba
	 * saved when the debugger was initially entered.  It'll be saved in
	 * the cpusave area for the current CPU.
	 */
	(void) set_tba((void *)kaif_cpusave[cpuid].krs_gregs.kregs[KREG_TBA]);

	kmdb_kdi_kernpanic(&regs, kaif_cb_save.krs_gregs.kregs[KREG_TT]);
}

static int
kaif_init(kmdb_auxv_t *kav)
{
	struct rwindow *rwins;
	int nwin = get_nwin();
	int i;

	kaif_vwapt_addr = kaif_pwapt_addr = 0;

	kaif_tba = kav->kav_tba_active;
	kaif_tba_obp = kav->kav_tba_obp;
	kaif_tba_native = kav->kav_tba_native;
	kaif_tba_native_sz = kav->kav_tba_native_sz;
#ifdef	sun4v
	kaif_tba_kernel = kav->kav_tba_kernel;
#endif

	/* Allocate the per-CPU save areas */
	kaif_cpusave = mdb_zalloc(sizeof (kaif_cpusave_t) * kav->kav_ncpu,
	    UM_SLEEP);
	kaif_ncpusave = kav->kav_ncpu;

	rwins = mdb_zalloc(sizeof (struct rwindow) * nwin * kav->kav_ncpu,
	    UM_SLEEP);

	for (i = 0; i < kaif_ncpusave; i++) {
		kaif_cpusave_t *save = &kaif_cpusave[i];

		save->krs_cpu_id = i;
		save->krs_rwins = &rwins[nwin * i];
		save->krs_curcrumbidx = KAIF_NCRUMBS - 1;
		save->krs_curcrumb = &save->krs_crumbs[save->krs_curcrumbidx];
	}

	kaif_dseg = kav->kav_dseg;
	kaif_dseg_lim = kav->kav_dseg + kav->kav_dseg_size;

	kaif_promexitarmp = kav->kav_promexitarmp;

	kaif_ktrap_install = kav->kav_ktrap_install;
	kaif_ktrap_restore = kav->kav_ktrap_restore;

	kaif_modchg_cb = NULL;

	kaif_trap_switch = (kav->kav_flags & KMDB_AUXV_FL_NOTRPSWTCH) == 0;

	return (0);
}

dpi_ops_t kmdb_dpi_ops = {
	kaif_init,
	kaif_activate,
	kaif_deactivate,
	kaif_enter_mon,
	kaif_modchg_register,
	kaif_modchg_cancel,
	kaif_get_cpu_state,
	kaif_get_master_cpuid,
	kaif_get_gregs,
	kaif_get_register,
	kaif_set_register,
	kaif_get_rwin,
	kaif_get_nwin,
	kaif_brkpt_arm,
	kaif_brkpt_disarm,
	kaif_wapt_validate,
	kaif_wapt_reserve,
	kaif_wapt_release,
	kaif_wapt_arm,
	kaif_wapt_disarm,
	kaif_wapt_match,
	kaif_step,
	kaif_call,
	kaif_dump_crumbs,
	kaif_kernpanic
};
