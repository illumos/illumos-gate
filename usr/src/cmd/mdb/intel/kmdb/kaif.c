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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The debugger/"PROM" interface layer
 *
 * (it makes more sense on SPARC)
 */

#include <kmdb/kmdb_dpi_impl.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kmdb_umemglue.h>
#include <kmdb/kaif.h>
#include <kmdb/kaif_asmutil.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_isautil.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_kreg.h>
#include <mdb/mdb.h>

#include <sys/types.h>
#include <sys/segments.h>
#include <sys/bitmap.h>

kaif_cpusave_t	*kaif_cpusave;
int		kaif_ncpusave;

kaif_drreg_t	kaif_drreg;

uint32_t	kaif_waptmap;

#ifndef __amd64
/* Used to track the current set of valid kernel selectors. */
uint32_t	kaif_cs;
uint32_t	kaif_ds;
uint32_t	kaif_fs;
uint32_t	kaif_gs;
#endif

uint_t		kaif_msr_wrexit_msr;
uint64_t	*kaif_msr_wrexit_valp;

uintptr_t	kaif_kernel_handler;
uintptr_t	kaif_sys_sysenter;

int		kaif_trap_switch;

void (*kaif_modchg_cb)(struct modctl *, int);

#define	KAIF_MEMRANGES_MAX	2

kaif_memrange_t	kaif_memranges[KAIF_MEMRANGES_MAX];
int		kaif_nmemranges;

enum {
	M_SYSRET	= 0x07, /* after M_ESC */
	M_ESC		= 0x0f,
	M_SYSEXIT	= 0x35, /* after M_ESC */
	M_REX_LO	= 0x40, /* first REX prefix */
	M_REX_HI	= 0x4f, /* last REX prefix */
	M_PUSHF		= 0x9c,	/* pushfl and pushfq */
	M_POPF		= 0x9d,	/* popfl and popfq */
	M_INT3		= 0xcc,
	M_INTX		= 0xcd,
	M_INTO		= 0xce,
	M_IRET		= 0xcf,
	M_CLI		= 0xfa,
	M_STI		= 0xfb
};

#define	KAIF_BREAKPOINT_INSTR	M_INT3

#define	KAIF_WPPRIV2ID(wp)	(int)(uintptr_t)((wp)->wp_priv)

#ifdef __amd64
#define	FLAGS_REG_NAME		"rflags"
#else
#define	FLAGS_REG_NAME		"eflags"
#endif

/*
 * Called during normal debugger operation and during debugger faults.
 */
static void
kaif_enter_mon(void)
{
	char c;

	for (;;) {
		mdb_iob_printf(mdb.m_out,
		    "%s: Do you really want to reboot? (y/n) ",
		    mdb.m_pname);
		mdb_iob_flush(mdb.m_out);

		while (IOP_READ(mdb.m_term, &c, 1) != 1)
			continue;
		mdb_iob_printf(mdb.m_out, "%c%s", c, (c == '\n' ? "" : "\n"));

		if (c == 'n' || c == 'N')
			return;
		else if (c == 'y' || c == 'Y') {
			mdb_iob_printf(mdb.m_out, "Rebooting...\n");

			kmdb_dpi_reboot();
		}
	}
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

static int
kaif_get_master_cpuid(void)
{
	return (kaif_master_cpuid);
}

static const mdb_tgt_gregset_t *
kaif_get_gregs(int cpuid)
{
	kaif_cpusave_t *save;

	if ((save = kaif_cpuid2save(cpuid)) == NULL)
		return (NULL); /* errno is set for us */

	return (save->krs_gregs);
}

typedef struct kaif_reg_synonyms {
	const char *rs_syn;
	const char *rs_name;
} kaif_reg_synonyms_t;

static kreg_t *
kaif_find_regp(const char *regname)
{
	static const kaif_reg_synonyms_t synonyms[] = {
#ifdef __amd64
	    { "pc", "rip" },
	    { "sp", "rsp" },
	    { "fp", "rbp" },
#else
	    { "pc", "eip" },
	    { "sp", "esp" },
	    { "fp", "ebp" },
#endif
	    { "tt", "trapno" }
	};

	kaif_cpusave_t *save;
	int i;

	save = kaif_cpuid2save(DPI_MASTER_CPUID);

	for (i = 0; i < sizeof (synonyms) / sizeof (synonyms[0]); i++) {
		if (strcmp(synonyms[i].rs_syn, regname) == 0)
			regname = synonyms[i].rs_name;
	}

	for (i = 0; mdb_isa_kregs[i].rd_name != NULL; i++) {
		const mdb_tgt_regdesc_t *rd = &mdb_isa_kregs[i];

		if (strcmp(rd->rd_name, regname) == 0)
			return (&save->krs_gregs->kregs[rd->rd_num]);
	}

	(void) set_errno(ENOENT);
	return (NULL);
}

/*ARGSUSED*/
static int
kaif_get_register(const char *regname, kreg_t *valp)
{
	kreg_t *regp;

	if ((regp = kaif_find_regp(regname)) == NULL)
		return (-1);

	*valp = *regp;

	return (0);
}

static int
kaif_set_register(const char *regname, kreg_t val)
{
	kreg_t *regp;

	if ((regp = kaif_find_regp(regname)) == NULL)
		return (-1);

	*regp = val;

	return (0);
}

static int
kaif_brkpt_arm(uintptr_t addr, mdb_instr_t *instrp)
{
	mdb_instr_t bkpt = KAIF_BREAKPOINT_INSTR;

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
 * Intel watchpoints are even more fun than SPARC ones.  The Intel architecture
 * manuals refer to watchpoints as breakpoints.  For consistency  with the
 * terminology used in other portions of kmdb, we will, however, refer to them
 * as watchpoints.
 *
 * Execute, data write, I/O read/write, and data read/write watchpoints are
 * supported by the hardware.  Execute watchpoints must be one byte in length,
 * and must be placed on the first byte of the instruction to be watched.
 * Lengths of other watchpoints are more varied.
 *
 * Given that we already have a breakpoint facility, and given the restrictions
 * placed on execute watchpoints, we're going to disallow the creation of
 * execute watchpoints.  The others will be fully supported.  See the Debugging
 * chapter in both the IA32 and AMD64 System Programming books for more details.
 */

#ifdef __amd64
#define	WAPT_DATA_MAX_SIZE	8
#define	WAPT_DATA_SIZES_MSG	"1, 2, 4, or 8"
#else
#define	WAPT_DATA_MAX_SIZE	4
#define	WAPT_DATA_SIZES_MSG	"1, 2, or 4"
#endif

static int
kaif_wapt_validate(kmdb_wapt_t *wp)
{
	if (wp->wp_type == DPI_WAPT_TYPE_IO) {
		if (wp->wp_wflags != (MDB_TGT_WA_R | MDB_TGT_WA_W)) {
			warn("I/O port watchpoints must be read/write\n");
			return (set_errno(EINVAL));
		}

		if (wp->wp_size != 1 && wp->wp_size != 2 && wp->wp_size != 4) {
			warn("I/O watchpoint size must be 1, 2, or 4 bytes\n");
			return (set_errno(EINVAL));
		}

	} else if (wp->wp_type == DPI_WAPT_TYPE_PHYS) {
		warn("physical address watchpoints are not supported on this "
		    "platform\n");
		return (set_errno(EMDB_TGTHWNOTSUP));

	} else {
		if (wp->wp_wflags != (MDB_TGT_WA_R | MDB_TGT_WA_W) &&
		    wp->wp_wflags != MDB_TGT_WA_W) {
			warn("watchpoints must be read/write or write-only\n");
			return (set_errno(EINVAL));
		}

		if ((wp->wp_size & -(wp->wp_size)) != wp->wp_size ||
		    wp->wp_size > WAPT_DATA_MAX_SIZE) {
			warn("data watchpoint size must be " WAPT_DATA_SIZES_MSG
			    " bytes\n");
			return (set_errno(EINVAL));
		}

	}

	if (wp->wp_addr & (wp->wp_size - 1)) {
		warn("%lu-byte watchpoints must be %lu-byte aligned\n",
		    (ulong_t)wp->wp_size, (ulong_t)wp->wp_size);
		return (set_errno(EINVAL));
	}

	return (0);
}

static int
kaif_wapt_reserve(kmdb_wapt_t *wp)
{
	int id;

	for (id = 0; id <= KREG_MAXWPIDX; id++) {
		if (!BT_TEST(&kaif_waptmap, id)) {
			/* found one */
			BT_SET(&kaif_waptmap, id);
			wp->wp_priv = (void *)(uintptr_t)id;
			return (0);
		}
	}

	return (set_errno(EMDB_WPTOOMANY));
}

static void
kaif_wapt_release(kmdb_wapt_t *wp)
{
	int id = KAIF_WPPRIV2ID(wp);

	ASSERT(BT_TEST(&kaif_waptmap, id));
	BT_CLEAR(&kaif_waptmap, id);
}

/*ARGSUSED*/
static void
kaif_wapt_arm(kmdb_wapt_t *wp)
{
	uint_t rw;
	int hwid = KAIF_WPPRIV2ID(wp);

	ASSERT(BT_TEST(&kaif_waptmap, hwid));

	if (wp->wp_type == DPI_WAPT_TYPE_IO)
		rw = KREG_DRCTL_WP_IORW;
	else if (wp->wp_wflags & MDB_TGT_WA_R)
		rw = KREG_DRCTL_WP_RW;
	else if (wp->wp_wflags & MDB_TGT_WA_X)
		rw = KREG_DRCTL_WP_EXEC;
	else
		rw = KREG_DRCTL_WP_WONLY;

	kaif_drreg.dr_addr[hwid] = wp->wp_addr;

	kaif_drreg.dr_ctl &= ~KREG_DRCTL_WP_MASK(hwid);
	kaif_drreg.dr_ctl |= KREG_DRCTL_WP_LENRW(hwid, wp->wp_size - 1, rw);
	kaif_drreg.dr_ctl |= KREG_DRCTL_WPEN(hwid);
}

/*ARGSUSED*/
static void
kaif_wapt_disarm(kmdb_wapt_t *wp)
{
	int hwid = KAIF_WPPRIV2ID(wp);

	ASSERT(BT_TEST(&kaif_waptmap, hwid));

	kaif_drreg.dr_addr[hwid] = 0;
	kaif_drreg.dr_ctl &= ~(KREG_DRCTL_WP_MASK(hwid) |
	    KREG_DRCTL_WPEN_MASK(hwid));
}

/*ARGSUSED*/
static int
kaif_wapt_match(kmdb_wapt_t *wp)
{
	int hwid = KAIF_WPPRIV2ID(wp);
	uint32_t mask = KREG_DRSTAT_WP_MASK(hwid);
	int n = 0;
	int i;

	ASSERT(BT_TEST(&kaif_waptmap, hwid));

	for (i = 0; i < kaif_ncpusave; i++)
		n += (kaif_cpusave[i].krs_dr.dr_stat & mask) != 0;

	return (n);
}

static int
kaif_step(void)
{
	kreg_t pc, fl, oldfl, newfl, sp;
	mdb_tgt_addr_t npc;
	mdb_instr_t instr;
	int emulated = 0, rchk = 0;
	size_t pcoff = 0;

	(void) kmdb_dpi_get_register("pc", &pc);

	if ((npc = mdb_dis_nextins(mdb.m_disasm, mdb.m_target,
	    MDB_TGT_AS_VIRT, pc)) == pc) {
		warn("failed to decode instruction at %a for step\n", pc);
		return (set_errno(EINVAL));
	}

	/*
	 * Stepping behavior depends on the type of instruction.  It does not
	 * depend on the presence of a REX prefix, as the action we take for a
	 * given instruction doesn't currently vary for 32-bit instructions
	 * versus their 64-bit counterparts.
	 */
	do {
		if (mdb_tgt_vread(mdb.m_target, &instr, sizeof (mdb_instr_t),
		    pc + pcoff) != sizeof (mdb_instr_t)) {
			warn("failed to read at %p for step",
			    (void *)(pc + pcoff));
			return (-1);
		}
	} while (pcoff++, (instr >= M_REX_LO && instr <= M_REX_HI && !rchk++));

	switch (instr) {
	case M_IRET:
		warn("iret cannot be stepped\n");
		return (set_errno(EMDB_TGTNOTSUP));

	case M_INT3:
	case M_INTX:
	case M_INTO:
		warn("int cannot be stepped\n");
		return (set_errno(EMDB_TGTNOTSUP));

	case M_ESC:
		if (mdb_tgt_vread(mdb.m_target, &instr, sizeof (mdb_instr_t),
		    pc + pcoff) != sizeof (mdb_instr_t)) {
			warn("failed to read at %p for step",
			    (void *)(pc + pcoff));
			return (-1);
		}

		switch (instr) {
		case M_SYSRET:
			warn("sysret cannot be stepped\n");
			return (set_errno(EMDB_TGTNOTSUP));
		case M_SYSEXIT:
			warn("sysexit cannot be stepped\n");
			return (set_errno(EMDB_TGTNOTSUP));
		}
		break;

	/*
	 * Some instructions need to be emulated.  We need to prevent direct
	 * manipulations of EFLAGS, so we'll emulate cli, sti.  pushfl and
	 * popfl also receive special handling, as they manipulate both EFLAGS
	 * and %esp.
	 */
	case M_CLI:
		(void) kmdb_dpi_get_register(FLAGS_REG_NAME, &fl);
		fl &= ~KREG_EFLAGS_IF_MASK;
		(void) kmdb_dpi_set_register(FLAGS_REG_NAME, fl);

		emulated = 1;
		break;

	case M_STI:
		(void) kmdb_dpi_get_register(FLAGS_REG_NAME, &fl);
		fl |= (1 << KREG_EFLAGS_IF_SHIFT);
		(void) kmdb_dpi_set_register(FLAGS_REG_NAME, fl);

		emulated = 1;
		break;

	case M_POPF:
		/*
		 * popfl will restore a pushed EFLAGS from the stack, and could
		 * in so doing cause IF to be turned on, if only for a a brief
		 * period.  To avoid this, we'll secretly replace the stack's
		 * EFLAGS with our decaffeinated brand.  We'll then manually
		 * load our EFLAGS copy with the real verion after the step.
		 */
		(void) kmdb_dpi_get_register("sp", &sp);
		(void) kmdb_dpi_get_register(FLAGS_REG_NAME, &fl);

		if (mdb_tgt_vread(mdb.m_target, &newfl, sizeof (kreg_t),
		    sp) != sizeof (kreg_t)) {
			warn("failed to read " FLAGS_REG_NAME
			    " at %p for popfl step\n", (void *)sp);
			return (set_errno(EMDB_TGTNOTSUP)); /* XXX ? */
		}

		fl = (fl & ~KREG_EFLAGS_IF_MASK) | KREG_EFLAGS_TF_MASK;

		if (mdb_tgt_vwrite(mdb.m_target, &fl, sizeof (kreg_t),
		    sp) != sizeof (kreg_t)) {
			warn("failed to update " FLAGS_REG_NAME
			    " at %p for popfl step\n", (void *)sp);
			return (set_errno(EMDB_TGTNOTSUP)); /* XXX ? */
		}
		break;
	}

	if (emulated) {
		(void) kmdb_dpi_set_register("pc", npc);
		return (0);
	}

	/* Do the step with IF off, and TF (step) on */
	(void) kmdb_dpi_get_register(FLAGS_REG_NAME, &oldfl);
	(void) kmdb_dpi_set_register(FLAGS_REG_NAME,
	    ((oldfl | (1 << KREG_EFLAGS_TF_SHIFT)) & ~KREG_EFLAGS_IF_MASK));

	kmdb_dpi_resume_master(); /* ... there and back again ... */

	/* EFLAGS has now changed, and may require tuning */

	switch (instr) {
	case M_POPF:
		/*
		 * Use the EFLAGS we grabbed before the pop - see the pre-step
		 * M_POPFL comment.
		 */
		(void) kmdb_dpi_set_register(FLAGS_REG_NAME, newfl);
		return (0);

	case M_PUSHF:
		/*
		 * We pushed our modified EFLAGS (with IF and TF turned off)
		 * onto the stack.  Replace the pushed version with our
		 * unmodified one.
		 */
		(void) kmdb_dpi_get_register("sp", &sp);

		if (mdb_tgt_vwrite(mdb.m_target, &oldfl, sizeof (kreg_t),
		    sp) != sizeof (kreg_t)) {
			warn("failed to update pushed " FLAGS_REG_NAME
			    " at %p after pushfl step\n", (void *)sp);
			return (set_errno(EMDB_TGTNOTSUP)); /* XXX ? */
		}

		/* Go back to using the EFLAGS we were using before the step */
		(void) kmdb_dpi_set_register(FLAGS_REG_NAME, oldfl);
		return (0);

	default:
		/*
		 * The stepped instruction may have altered EFLAGS.  We only
		 * really care about the value of IF, and we know the stepped
		 * instruction didn't alter it, so we can simply copy the
		 * pre-step value.  We'll also need to turn TF back off.
		 */
		(void) kmdb_dpi_get_register(FLAGS_REG_NAME, &fl);
		(void) kmdb_dpi_set_register(FLAGS_REG_NAME,
		    ((fl & ~(KREG_EFLAGS_TF_MASK|KREG_EFLAGS_IF_MASK)) |
		    (oldfl & KREG_EFLAGS_IF_MASK)));
		return (0);
	}
}

/*
 * The target has already configured the chip for branch step, leaving us to
 * actually make the machine go.  Due to a number of issues involving
 * the potential alteration of system state via instructions like sti, cli,
 * pushfl, and popfl, we're going to treat this like a normal system resume.
 * All CPUs will be released, on the kernel's IDT.  Our primary concern is
 * the alteration/storage of our TF'd EFLAGS via pushfl and popfl.  There's no
 * real workaround - we don't have opcode breakpoints - so the best we can do is
 * to ensure that the world won't end if someone does bad things to EFLAGS.
 *
 * Two things can happen:
 *  1. EFLAGS.TF may be cleared, either maliciously or via a popfl from saved
 *     state.  The CPU will continue execution beyond the branch, and will not
 *     reenter the debugger unless brought/sent in by other means.
 *  2. Someone may pushlf the TF'd EFLAGS, and may stash a copy of it somewhere.
 *     When the saved version is popfl'd back into place, the debugger will be
 *     re-entered on a single-step trap.
 */
static void
kaif_step_branch(void)
{
	kreg_t fl;

	(void) kmdb_dpi_get_register(FLAGS_REG_NAME, &fl);
	(void) kmdb_dpi_set_register(FLAGS_REG_NAME,
	    (fl | (1 << KREG_EFLAGS_TF_SHIFT)));

	kmdb_dpi_resume_master();

	(void) kmdb_dpi_set_register(FLAGS_REG_NAME, fl);
}

/*ARGSUSED*/
static uintptr_t
kaif_call(uintptr_t funcva, uint_t argc, const uintptr_t argv[])
{
	return (kaif_invoke(funcva, argc, argv));
}

static void
dump_crumb(kaif_crumb_t *krmp)
{
	kaif_crumb_t krm;

	if (mdb_vread(&krm, sizeof (kaif_crumb_t), (uintptr_t)krmp) !=
	    sizeof (kaif_crumb_t)) {
		warn("failed to read crumb at %p", krmp);
		return;
	}

	mdb_printf("state: ");
	switch (krm.krm_cpu_state) {
	case KAIF_CPU_STATE_MASTER:
		mdb_printf("M");
		break;
	case KAIF_CPU_STATE_SLAVE:
		mdb_printf("S");
		break;
	default:
		mdb_printf("%d", krm.krm_cpu_state);
	}

	mdb_printf(" trapno %3d sp %08x flag %d pc %p %A\n",
	    krm.krm_trapno, krm.krm_sp, krm.krm_flag, krm.krm_pc, krm.krm_pc);
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

	if (addr != NULL) {
		/* dump_crumb will protect us against bogus addresses */
		dump_crumb((kaif_crumb_t *)addr);

	} else if (cpuid != -1) {
		if (cpuid < 0 || cpuid >= kaif_ncpusave)
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

/*
 * On some processors, we'll need to clear a certain MSR before proceeding into
 * the debugger.  Complicating matters, this MSR must be cleared before we take
 * any branches.  We have patch points in every trap handler, which will cover
 * all entry paths for master CPUs.  We also have a patch point in the slave
 * entry code.
 */
static void
kaif_msr_add_clrentry(uint_t msr)
{
#ifdef __amd64
	uchar_t code[] = {
		0x51, 0x50, 0x52,		/* pushq %rcx, %rax, %rdx */
		0xb9, 0x00, 0x00, 0x00, 0x00,	/* movl $MSRNUM, %ecx */
		0x31, 0xc0,			/* clr %eax */
		0x31, 0xd2,			/* clr %edx */
		0x0f, 0x30,			/* wrmsr */
		0x5a, 0x58, 0x59		/* popq %rdx, %rax, %rcx */
	};
	uchar_t *patch = &code[4];
#else
	uchar_t code[] = {
		0x60,				/* pushal */
		0xb9, 0x00, 0x00, 0x00, 0x00,	/* movl $MSRNUM, %ecx */
		0x31, 0xc0,			/* clr %eax */
		0x31, 0xd2,			/* clr %edx */
		0x0f, 0x30,			/* wrmsr */
		0x61				/* popal */
	};
	uchar_t *patch = &code[2];
#endif

	bcopy(&msr, patch, sizeof (uint32_t));

	kaif_idt_patch((caddr_t)code, sizeof (code));

	bcopy(code, &kaif_slave_entry_patch, sizeof (code));
}

static void
kaif_msr_add_wrexit(uint_t msr, uint64_t *valp)
{
	kaif_msr_wrexit_msr = msr;
	kaif_msr_wrexit_valp = valp;
}

static void
kaif_msr_add(const kmdb_msr_t *msrs)
{
	kmdb_msr_t *save;
	int nmsrs, i;

	ASSERT(kaif_cpusave[0].krs_msr == NULL);

	for (i = 0; msrs[i].msr_num != 0; i++) {
		switch (msrs[i].msr_type) {
		case KMDB_MSR_CLEARENTRY:
			kaif_msr_add_clrentry(msrs[i].msr_num);
			break;

		case KMDB_MSR_WRITEDELAY:
			kaif_msr_add_wrexit(msrs[i].msr_num, msrs[i].msr_valp);
			break;
		}
	}
	nmsrs = i + 1; /* we want to copy the terminating kmdb_msr_t too */

	save = mdb_zalloc(sizeof (kmdb_msr_t) * nmsrs * kaif_ncpusave,
	    UM_SLEEP);

	for (i = 0; i < kaif_ncpusave; i++) {
		bcopy(msrs, &save[nmsrs * i], sizeof (kmdb_msr_t) * nmsrs);
		kaif_cpusave[i].krs_msr = &save[nmsrs * i];
	}
}

static uint64_t
kaif_msr_get(int cpuid, uint_t num)
{
	kaif_cpusave_t *save;
	kmdb_msr_t *msr;
	int i;

	if ((save = kaif_cpuid2save(cpuid)) == NULL)
		return (-1); /* errno is set for us */

	msr = save->krs_msr;

	for (i = 0; msr[i].msr_num != 0; i++) {
		if (msr[i].msr_num == num &&
		    (msr[i].msr_type & KMDB_MSR_READ))
			return (msr[i].msr_val);
	}

	return (0);
}

int
kaif_memrange_add(caddr_t base, size_t len)
{
	kaif_memrange_t *mr = &kaif_memranges[kaif_nmemranges];

	if (kaif_nmemranges == KAIF_MEMRANGES_MAX)
		return (set_errno(ENOSPC));

	/*
	 * In the unlikely event that someone is stepping through this routine,
	 * we need to make sure that kaif_memranges knows about the new range
	 * before umem gets it.  That way the entry code can recognize stacks
	 * allocated from the new region.
	 */
	mr->mr_base = base;
	mr->mr_lim = base + len - 1;
	kaif_nmemranges++;

	if (mdb_umem_add(base, len) < 0) {
		kaif_nmemranges--;
		return (-1); /* errno is set for us */
	}

	return (0);
}

void
kaif_trap_set_debugger(void)
{
	set_idt(&kaif_idtr);
}

void
kaif_trap_set_saved(kaif_cpusave_t *cpusave)
{
	set_idt(&cpusave->krs_idtr);
}

static int
kaif_init(kmdb_auxv_t *kav)
{
	int i;

	/* Allocate the per-CPU save areas */
	kaif_cpusave = mdb_zalloc(sizeof (kaif_cpusave_t) * kav->kav_ncpu,
	    UM_SLEEP);
	kaif_ncpusave = kav->kav_ncpu;

	for (i = 0; i < kaif_ncpusave; i++) {
		kaif_cpusave_t *save = &kaif_cpusave[i];

		save->krs_cpu_id = i;
		save->krs_curcrumbidx = KAIF_NCRUMBS - 1;
		save->krs_curcrumb = &save->krs_crumbs[save->krs_curcrumbidx];
	}

	kaif_idt_init();

	/* The initial selector set.  Updated by the debugger-entry code */
#ifndef __amd64
	kaif_cs = BOOTCODE_SEL;
	kaif_ds = kaif_fs = kaif_gs = BOOTFLAT_SEL;
#endif

	kaif_memranges[0].mr_base = kav->kav_dseg;
	kaif_memranges[0].mr_lim = kav->kav_dseg + kav->kav_dseg_size - 1;
	kaif_nmemranges = 1;

	kaif_modchg_cb = NULL;

	kaif_waptmap = 0;

	kaif_drreg.dr_ctl = KREG_DRCTL_RESERVED;
	kaif_drreg.dr_stat = KREG_DRSTAT_RESERVED;

	kaif_msr_wrexit_msr = 0;
	kaif_msr_wrexit_valp = NULL;

	kaif_trap_switch = (kav->kav_flags & KMDB_AUXV_FL_NOTRPSWTCH) == 0;

	if ((kaif_sys_sysenter = kmdb_kdi_lookup_by_name("unix",
	    "sys_sysenter")) == NULL)
		return (set_errno(ENOENT));

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
	kaif_brkpt_arm,
	kaif_brkpt_disarm,
	kaif_wapt_validate,
	kaif_wapt_reserve,
	kaif_wapt_release,
	kaif_wapt_arm,
	kaif_wapt_disarm,
	kaif_wapt_match,
	kaif_step,
	kaif_step_branch,
	kaif_call,
	kaif_dump_crumbs,
	kaif_memrange_add,
	kaif_msr_add,
	kaif_msr_get,
};
