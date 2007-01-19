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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The debugger/PROM interface layer - debugger activation
 */

#include <kmdb/kmdb_promif_isadep.h>
#include <kmdb/kmdb_start.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kmdb_asmutil.h>
#include <kmdb/kaif.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_kreg.h>

#include <sys/cpuvar.h>
#include <sys/kdi_impl.h>
#include <sys/machtrap.h>

kaif_cpusave_t kaif_cb_save;

static const char kaif_defer_word_tmpl[] =
	/*  1 */ ": kmdb_callback "

	/*
	 * Don't hand control to the debugger if we're coming from OBP's text.
	 */

	/*  2 */ "  %%pc f000.0000 ffff.ffff between if exit then "

	/*
	 * Save registers
	 */

	/*  3 */ "  %%pc h# %x x! "
	/*  4 */ "  %%npc h# %x x! "
	/*  5 */ "  %%g1 h# %x x! "
	/*  6 */ "  %%g2 h# %x x! "
	/*  7 */ "  %%g3 h# %x x! "
	/*  8 */ "  %%g4 h# %x x! "
	/*  9 */ "  %%g5 h# %x x! "
	/* 10 */ "  %%g6 h# %x x! "
	/* 11 */ "  %%g7 h# %x x! "
	/* 12 */ "  1 %%tstate h# %x x! "
	/* 13 */ "  1 %%tt h# %x x! "
	/* 14 */ "  %%tba h# %x x! "
	/* 15 */ "  h# %x set-pc "
	/* 16 */ "    go "
	/* 17 */ "; ";

/*
 * Format the Forth word which tells the prom how to save state for
 * giving control to us.
 */
static char *
kaif_format_word(void)
{
	static char prom_str[550];
	kreg_t *kregs = kaif_cb_save.krs_gregs.kregs;
	int len;

	len = mdb_snprintf(prom_str, sizeof (prom_str), kaif_defer_word_tmpl,
	    &kregs[KREG_PC],			/*  3 */
	    &kregs[KREG_NPC],			/*  4 */
	    &kregs[KREG_G1],			/*  5 */
	    &kregs[KREG_G2],			/*  6 */
	    &kregs[KREG_G3],			/*  7 */
	    &kregs[KREG_G4],			/*  8 */
	    &kregs[KREG_G5],			/*  9 */
	    &kregs[KREG_G6],			/* 10 */
	    &kregs[KREG_G7],			/* 11 */
	    &kaif_cb_save.krs_tstate,		/* 12 */
	    &kregs[KREG_TT],			/* 13 */
	    &kregs[KREG_TBA],			/* 14 */
	    kaif_trap_obp);			/* 15 */

	ASSERT(len <= sizeof (prom_str));

	return (prom_str);
}

static void
kaif_prom_install(void)
{
	kmdb_prom_interpret(kaif_format_word());
	kmdb_prom_interpret(" ['] kmdb_callback init-debugger-hook ");
}

void
kaif_prom_rearm(void)
{
	kmdb_prom_interpret(" ['] kmdb_callback is debugger-hook ");
}

/*ARGSUSED*/
static void
kaif_cpu_init(cpu_t *cp)
{
	kaif_wapt_set_regs();
}

/*ARGSUSED*/
static void
kaif_install_generic(caddr_t tgt, caddr_t arg)
{
	bcopy((caddr_t)kaif_hdlr_generic, tgt, 32);
}

#ifdef	sun4v

/*ARGSUSED*/
static void
kaif_install_goto_tt64(caddr_t tgt, caddr_t arg)
{
	/* LINTED - pointer alignment */
	uint32_t *hdlr = (uint32_t *)tgt;
	uint32_t disp = (T_FAST_INSTR_MMU_MISS - T_INSTR_MMU_MISS) * 0x20;

	*hdlr++ = 0x10480000 | (disp >> 2);	/* ba,pt (to tt64) */
	*hdlr++ = 0x01000000;			/* nop */
}

/*ARGSUSED*/
static void
kaif_install_goto_tt68(caddr_t tgt, caddr_t arg)
{
	/* LINTED - pointer alignment */
	uint32_t *hdlr = (uint32_t *)tgt;
	uint32_t disp = (T_FAST_DATA_MMU_MISS - T_DATA_MMU_MISS) * 0x20;

	*hdlr++ = 0x10480000 | (disp >> 2);	/* ba,pt (to tt68) */
	*hdlr++ = 0x01000000;			/* nop */
}

#endif	/* sun4v */

static void
kaif_install_dmmumiss(caddr_t tgt, caddr_t vatotte)
{
	uint32_t *patch;

	bcopy((caddr_t)kaif_hdlr_dmiss, tgt, 128);

	/* LINTED - pointer alignment */
	patch = (uint32_t *)(tgt + ((uintptr_t)&kaif_hdlr_dmiss_patch -
	    (uintptr_t)kaif_hdlr_dmiss));
	*patch++ |= (uintptr_t)vatotte >> 10;
	*patch |= ((uintptr_t)vatotte) & 0x3ff;
}

static void
kaif_install_immumiss(caddr_t tgt, caddr_t vatotte)
{
	uint32_t *patch;

	bcopy((caddr_t)kaif_hdlr_imiss, tgt, 128);

	/* LINTED - pointer alignment */
	patch = (uint32_t *)(tgt + ((uintptr_t)&kaif_hdlr_imiss_patch -
	    (uintptr_t)kaif_hdlr_imiss));
	*patch++ |= (uintptr_t)vatotte >> 10;
	*patch |= ((uintptr_t)vatotte) & 0x3ff;
}

static struct kaif_trap_handlers {
	uint_t th_tt;
	void (*th_install)(caddr_t, caddr_t);
} kaif_trap_handlers[] = {
	{ T_INSTR_EXCEPTION,			kaif_install_generic },
#ifdef sun4v
	{ T_INSTR_MMU_MISS,			kaif_install_goto_tt64 },
#endif
	{ T_IDIV0,				kaif_install_generic },
	{ T_DATA_EXCEPTION,			kaif_install_generic },
#ifdef sun4v
	{ T_DATA_MMU_MISS,			kaif_install_goto_tt68 },
#endif
	{ T_DATA_ERROR,				kaif_install_generic },
	{ T_ALIGNMENT,				kaif_install_generic },
	{ T_FAST_INSTR_MMU_MISS,		kaif_install_immumiss },
	{ T_FAST_DATA_MMU_MISS,			kaif_install_dmmumiss },
	{ T_FAST_DATA_MMU_PROT,			kaif_install_generic },
#ifdef sun4v
	{ T_INSTR_MMU_MISS + T_TL1,		kaif_install_goto_tt64 },
	{ T_DATA_MMU_MISS + T_TL1,		kaif_install_goto_tt68 },
#endif
	{ T_FAST_INSTR_MMU_MISS + T_TL1,	kaif_install_immumiss },
	{ T_FAST_DATA_MMU_MISS + T_TL1,		kaif_install_dmmumiss },
	{ 0 }
};

static void
kaif_trap_init(void)
{
	caddr_t vatotte = kmdb_kdi_get_trap_vatotte();
	uintptr_t brtgt;
	int i;

	/*
	 * sun4u:
	 * We rely upon OBP for the handling of a great many traps.  As such,
	 * we begin by populating our table with pointers to OBP's handlers.
	 * We then copy in our own handlers where appropriate.  At some point,
	 * when we provide the bulk of the handlers, this process will be
	 * reversed.
	 *
	 * sun4v:
	 * The sun4v kernel dismisses OBP at boot. Both fast and slow TLB
	 * misses are handled by KMDB. Breakpoint traps go directly KMDB.
	 * All other trap entries are redirected to their respective
	 * trap implemenation within the Solaris trap table.
	 */
	for (i = 0; i < kaif_tba_native_sz; i += 0x20) {
		/* LINTED - pointer alignment */
		uint32_t *hdlr = (uint32_t *)(kaif_tba_native + i);
#ifdef	sun4v
		brtgt = (uintptr_t)(kaif_tba_kernel + i);
#else
		brtgt = (uintptr_t)(kaif_tba_obp + i);
#endif
		*hdlr++ = 0x03000000 | (brtgt >> 10);	/* sethi brtgt, %g1 */
		*hdlr++ = 0x81c06000 | (brtgt & 0x3ff);	/* jmp %g1 + brtgt */
		*hdlr++ = 0x01000000;			/* nop */
	}

	for (i = 0; kaif_trap_handlers[i].th_tt != 0; i++) {
		struct kaif_trap_handlers *th = &kaif_trap_handlers[i];
		th->th_install(kaif_tba_native + th->th_tt * 0x20, vatotte);
	}
	membar_producer();
}

/*
 * The kernel is ready for us to switch to our table (the HAT has been
 * initialized, the hments are walkable, and the trap table's pages
 * have been locked into the TLBs.
 */
static void
kaif_vmready(void)
{
	kaif_tba = kaif_tba_native;
}

/*
 * Called on the CPR master CPU.  The driver has taken care of locking the
 * TLB entries.  CPR restored the OBP image which contains kmdb_callback,
 * so there's nothing we need to do.  This function should be removed entirely
 * in a future release.
 */
static void
kaif_cpr_restart(void)
{
}

static kdi_debugvec_t kaif_dvec = {
	NULL,			/* dv_kctl_vmready */
	NULL,			/* dv_kctl_memavail */
	NULL,			/* dv_kctl_modavail */
	NULL,			/* dv_kctl_thravail */
	kaif_vmready,
	NULL,			/* dv_memavail */
	kaif_mod_loaded,
	kaif_mod_unloading,
	NULL,			/* dv_kctl_cpu_init */
	kaif_cpu_init,
	kaif_cpr_restart
};

/*ARGSUSED1*/
void
kaif_activate(kdi_debugvec_t **dvecp, uint_t flags)
{
	kaif_prom_install();

	kaif_ktrap_install(0, kaif_ktrap);
	kaif_trap_init();

	*dvecp = &kaif_dvec;
}

void
kaif_deactivate(void)
{
	kmdb_prom_interpret(" ['] noop is debugger-hook ");

	kaif_ktrap_restore();
}
