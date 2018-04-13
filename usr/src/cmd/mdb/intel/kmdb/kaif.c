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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Joyent, Inc.
 */

/*
 * The debugger/"PROM" interface layer
 *
 * It makes more sense on SPARC. In reality, these interfaces deal with three
 * things: setting break/watchpoints, stepping, and interfacing with the KDI to
 * set up kmdb's IDT handlers.
 */

#include <kmdb/kmdb_dpi_impl.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kmdb_umemglue.h>
#include <kmdb/kaif.h>
#include <kmdb/kmdb_io.h>
#include <kmdb/kaif_start.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_isautil.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_kreg_impl.h>
#include <mdb/mdb.h>

#include <sys/types.h>
#include <sys/bitmap.h>
#include <sys/termios.h>
#include <sys/kdi_impl.h>
#include <sys/sysmacros.h>

/*
 * This is the area containing the saved state when we enter
 * via kmdb's IDT entries.
 */
kdi_cpusave_t	*kaif_cpusave;
int		kaif_ncpusave;
kdi_drreg_t	kaif_drreg;

uint32_t	kaif_waptmap;

int		kaif_trap_switch;

void (*kaif_modchg_cb)(struct modctl *, int);

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
		mdb_iob_clearlines(mdb.m_out);

		c = kmdb_getchar();

		if (c == 'n' || c == 'N' || c == CTRL('c'))
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

static mdb_tgt_gregset_t *
kaif_kdi_to_gregs(int cpuid)
{
	kaif_cpusave_t *save;

	if ((save = kaif_cpuid2save(cpuid)) == NULL)
		return (NULL); /* errno is set for us */

	/*
	 * The saved registers are actually identical to an mdb_tgt_gregset,
	 * so we can directly cast here.
	 */
	return ((mdb_tgt_gregset_t *)save->krs_gregs);
}

static const mdb_tgt_gregset_t *
kaif_get_gregs(int cpuid)
{
	return (kaif_kdi_to_gregs(cpuid));
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
	mdb_tgt_gregset_t *regs;
	int i;

	if ((regs = kaif_kdi_to_gregs(DPI_MASTER_CPUID)) == NULL)
		return (NULL);

	for (i = 0; i < sizeof (synonyms) / sizeof (synonyms[0]); i++) {
		if (strcmp(synonyms[i].rs_syn, regname) == 0)
			regname = synonyms[i].rs_name;
	}

	for (i = 0; mdb_isa_kregs[i].rd_name != NULL; i++) {
		const mdb_tgt_regdesc_t *rd = &mdb_isa_kregs[i];

		if (strcmp(rd->rd_name, regname) == 0)
			return (&regs->kregs[rd->rd_num]);
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

/*
 * Refuse to single-step or break within any stub that loads a user %cr3 value.
 * As the KDI traps are not careful to restore such a %cr3, this can all go
 * wrong, both spectacularly and subtly.
 */
static boolean_t
kaif_toxic_text(uintptr_t addr)
{
	static GElf_Sym toxic_syms[2] = { 0, };
	size_t i;

	if (toxic_syms[0].st_name == NULL) {
		if (mdb_tgt_lookup_by_name(mdb.m_target, MDB_TGT_OBJ_EXEC,
		    "tr_iret_user", &toxic_syms[0], NULL) != 0)
			warn("couldn't find tr_iret_user\n");
		if (mdb_tgt_lookup_by_name(mdb.m_target, MDB_TGT_OBJ_EXEC,
		    "tr_mmu_flush_user_range", &toxic_syms[1], NULL) != 0)
			warn("couldn't find tr_mmu_flush_user_range\n");
	}

	for (i = 0; i < ARRAY_SIZE(toxic_syms); i++) {
		if (addr >= toxic_syms[i].st_value &&
		    addr - toxic_syms[i].st_value < toxic_syms[i].st_size)
			return (B_TRUE);
	}

	return (B_FALSE);
}

static int
kaif_brkpt_arm(uintptr_t addr, mdb_instr_t *instrp)
{
	mdb_instr_t bkpt = KAIF_BREAKPOINT_INSTR;

	if (kaif_toxic_text(addr)) {
		warn("%a cannot be a breakpoint target\n", addr);
		return (set_errno(EMDB_TGTNOTSUP));
	}

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

	for (id = 0; id <= KDI_MAXWPIDX; id++) {
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
	kmdb_kdi_update_drreg(&kaif_drreg);
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
	kmdb_kdi_update_drreg(&kaif_drreg);
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

	if (kaif_toxic_text(pc)) {
		warn("%a cannot be stepped\n", pc);
		return (set_errno(EMDB_TGTNOTSUP));
	}

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
		 * in so doing cause IF to be turned on, if only for a brief
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

/*ARGSUSED*/
static uintptr_t
kaif_call(uintptr_t funcva, uint_t argc, const uintptr_t argv[])
{
	return (kaif_invoke(funcva, argc, argv));
}

static void
dump_crumb(kdi_crumb_t *krmp)
{
	kdi_crumb_t krm;

	if (mdb_vread(&krm, sizeof (kdi_crumb_t), (uintptr_t)krmp) !=
	    sizeof (kdi_crumb_t)) {
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

	for (i = KDI_NCRUMBS; i > 0; i--) {
		uint_t idx = (save->krs_curcrumbidx + i) % KDI_NCRUMBS;
		dump_crumb(&save->krs_crumbs[idx]);
	}
}

static void
kaif_dump_crumbs(uintptr_t addr, int cpuid)
{
	int i;

	if (addr != NULL) {
		/* dump_crumb will protect us against bogus addresses */
		dump_crumb((kdi_crumb_t *)addr);

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
kaif_trap_set_debugger(void)
{
	kmdb_kdi_idt_switch(NULL);
}

void
kaif_trap_set_saved(kaif_cpusave_t *cpusave)
{
	kmdb_kdi_idt_switch(cpusave);
}

static void
kaif_vmready(void)
{
}

void
kaif_memavail(caddr_t base, size_t len)
{
	int ret;
	/*
	 * In the unlikely event that someone is stepping through this routine,
	 * we need to make sure that the KDI knows about the new range before
	 * umem gets it.  That way the entry code can recognize stacks
	 * allocated from the new region.
	 */
	kmdb_kdi_memrange_add(base, len);
	ret = mdb_umem_add(base, len);
	ASSERT(ret == 0);
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
kaif_handle_fault(greg_t trapno, greg_t pc, greg_t sp, int cpuid)
{
	kmdb_dpi_handle_fault((kreg_t)trapno, (kreg_t)pc,
	    (kreg_t)sp, cpuid);
}

static kdi_debugvec_t kaif_dvec = {
	NULL,			/* dv_kctl_vmready */
	NULL,			/* dv_kctl_memavail */
	NULL,			/* dv_kctl_modavail */
	NULL,			/* dv_kctl_thravail */
	kaif_vmready,
	kaif_memavail,
	kaif_mod_loaded,
	kaif_mod_unloading,
	kaif_handle_fault
};

void
kaif_kdi_entry(kdi_cpusave_t *cpusave)
{
	int ret = kaif_main_loop(cpusave);
	ASSERT(ret == KAIF_CPU_CMD_RESUME ||
	    ret == KAIF_CPU_CMD_RESUME_MASTER);
}

/*ARGSUSED*/
void
kaif_activate(kdi_debugvec_t **dvecp, uint_t flags)
{
	kmdb_kdi_activate(kaif_kdi_entry, kaif_cpusave, kaif_ncpusave);
	*dvecp = &kaif_dvec;
}

static int
kaif_init(kmdb_auxv_t *kav)
{
	/* Allocate the per-CPU save areas */
	kaif_cpusave = mdb_zalloc(sizeof (kaif_cpusave_t) * kav->kav_ncpu,
	    UM_SLEEP);
	kaif_ncpusave = kav->kav_ncpu;

	kaif_modchg_cb = NULL;

	kaif_waptmap = 0;

	kaif_trap_switch = (kav->kav_flags & KMDB_AUXV_FL_NOTRPSWTCH) == 0;

	return (0);
}

dpi_ops_t kmdb_dpi_ops = {
	kaif_init,
	kaif_activate,
	kmdb_kdi_deactivate,
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
	kaif_call,
	kaif_dump_crumbs,
};
