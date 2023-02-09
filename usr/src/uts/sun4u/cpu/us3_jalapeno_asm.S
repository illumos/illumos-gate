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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Assembly code support for the jalapeno module
 */

#include "assym.h"

#include <sys/asm_linkage.h>
#include <sys/mmu.h>
#include <vm/hat_sfmmu.h>
#include <sys/machparam.h>
#include <sys/machcpuvar.h>
#include <sys/machthread.h>
#include <sys/machtrap.h>
#include <sys/privregs.h>
#include <sys/asm_linkage.h>
#include <sys/trap.h>
#include <sys/cheetahregs.h>
#include <sys/us3_module.h>
#include <sys/xc_impl.h>
#include <sys/intreg.h>
#include <sys/async.h>
#include <sys/clock.h>
#include <sys/cheetahasm.h>

#ifdef TRAPTRACE
#include <sys/traptrace.h>
#endif /* TRAPTRACE */

/* BEGIN CSTYLED */

#if defined(JALAPENO) && defined(JALAPENO_ERRATA_85)

#define	CHK_JP_ERRATA85_ENABLED(scr, label)				\
	ASM_LD(scr, jp_errata_85_active);				\
	cmp	scr, 1;							\
	bne	%icc, label;						\
	nop

#define	SET_64BIT_PA(dest, scr, hi32, lo32)				\
	set	hi32, scr;						\
	sllx	scr, 32, scr;						\
	sethi	%hi(lo32), dest;					\
	or	dest, %lo(lo32), dest;					\
	or	scr, dest, dest

/*
 * Macro to trigger Jalapeno/Tomatillo speed change 
 *   j_chng_pa - scratch register
 *   scr - scratch register
 */
#define	JP_ESTAR_TRIGGER(j_chng_pa, scr)				\
	SET_64BIT_PA(j_chng_pa, scr, TOM_HIGH_PA, M_T_J_CHNG_INIT_PA);	\
	ldxa	[j_chng_pa]ASI_IO, scr;					\
5:									\
	and	scr, TOM_TRIGGER_MASK, scr;				\
	cmp	scr, TOM_TRIGGER;					\
	be,pt %icc, 5b;			/* wait while 10 */		\
	ldxa	[j_chng_pa]ASI_IO, scr;					\
	andn	scr, TOM_TRIGGER_MASK, scr;				\
	stxa	scr, [j_chng_pa]ASI_IO;	/* clear j_chng[1:0] */		\
	or	scr, TOM_TRIGGER, scr;					\
	stxa	scr, [j_chng_pa]ASI_IO;	/* trigger j_chng */		\
	ldxa	[j_chng_pa]ASI_IO, scr;					\
6:									\
	and	scr, TOM_TRIGGER_MASK, scr;				\
	cmp	scr, TOM_TRIGGER;					\
	be,pt %icc, 6b;			/* wait while 10 */		\
	ldxa	[j_chng_pa]ASI_IO, scr;					\
	andn	scr, TOM_TRIGGER_MASK, scr;				\
	stxa	scr, [j_chng_pa]ASI_IO;	/* deassert j_chng */

/*
 * Macro to set Jalapeno CPU speed
 *   speed - new speed constant
 *   scr1  - scratch register
 *   scr2  - scratch register
 */
#define	SET_JP_SPEED(speed, scr1, scr2)					\
	ldxa	[%g0]ASI_JBUS_CONFIG, scr1;				\
	set	JBUS_CONFIG_ECLK_MASK, scr2;				\
	andn	scr1, scr2, scr1;					\
	set	speed, scr2;						\
	or	scr1, scr2, scr1;					\
	stxa	scr1, [%g0]ASI_JBUS_CONFIG;

/*
 * macro to set Master Tomatillo speed
 *   speed - tomatillo speed constant
 *   tpa   - tomatillo estar control register PA
 *   scr  - scratch register
 */
#define	SET_TOM_SPEED(speed, tpa, scr)					\
	ldxa	[tpa]ASI_IO, scr;					\
	andn	scr, TOM_ESTAR_ELCK_MASK, scr;				\
	or	scr, speed, scr;					\
	stxa	scr, [tpa]ASI_IO;

/*
 * macro to check and set Slave Tomatillo speed
 *   speed - tomatillo speed constant
 *   scr1   - scratch register
 *   scr2   - scratch register
 */

#define	SET_SLAVE_T_SPEED(speed, scr1, scr2)				\
	ldxa	[%g0]ASI_JBUS_CONFIG, scr2;				\
	srlx	scr2, JBUS_SLAVE_T_PORT_BIT, scr2;			\
	btst	1, scr2;						\
	bz,pt	%icc, 4f;						\
	nop;								\
	SET_64BIT_PA(scr1, scr2, TOM_HIGH_PA, S_T_ESTAR_CTRL_PA);	\
	SET_TOM_SPEED(speed, scr1, scr2);				\
4:


/*
 * macro to adjust ASI_MCU_CTL_REG1[26:25] fsm bits according to
 * new cpu speed: fsm[1:0]=11b for full speed, fsm[1:0]=0 for estar speed
 *    value - fsm bit value constant
 *    scr1  - scratch register
 *    scr2  - scratch register
 */
#define	JP_ADJUST_FSM(value, scr1, scr2)				\
	ldxa	[%g0]ASI_MCU_CTRL, scr1;				\
	set	JP_MCU_FSM_MASK, scr2;					\
	andn	scr1, scr2, scr1;					\
	set	value, scr2;						\
	or	scr1, scr2, scr1;					\
	stxa	scr1, [%g0]ASI_MCU_CTRL;				\
	membar	#Sync;

/*
 * JP_FORCE_FULL_SPEED and its fellow macros are for Jalapeno
 * workstation to work around Errata 85. The front portion of
 * it packs JP speed(14..13) and Tomatillo speed(5..0) into one
 * register.
 *
 * Current code assumes that these two fields are non-overlapping.
 * If that assumption changes, then this code won't work. If so, we
 * force a compile time error by not defining the JP_FORCE_FULL_SPEED
 * and JP_RESTORE_SPEED macros below.
 */

#if !(JBUS_CONFIG_ECLK_MASK & TOM_SPEED_MASK)

/*
 * Macro to force Jalapeno/Tomatillo to full speed
 *   old_lvl - register used to save original cpu, tomatillo speed 
 *   scr2 - scratch register
 *   scr3 - scratch register
 *   scr4 - scratch register
 */
#define	JP_FORCE_FULL_SPEED(old_lvl, scr2, scr3, scr4)			\
	ldxa	[%g0]ASI_JBUS_CONFIG, old_lvl;				\
	set	JBUS_CONFIG_ECLK_MASK, scr4;				\
	and	old_lvl, scr4, old_lvl;					\
	SET_64BIT_PA(scr2, scr3, TOM_HIGH_PA, M_T_ESTAR_CTRL_PA);	\
	ldxa	[scr2]ASI_IO, scr3;					\
	set	TOM_ESTAR_ELCK_MASK, scr4;				\
	and	scr3, scr4, scr3;					\
	or	old_lvl, scr3, old_lvl;					\
	/* original jp and tomatillo speed saved in old_lvl */		\
									\
	/* either intended or currently at full speed */		\
	set	JBUS_CONFIG_ECLK_MASK, scr4;				\
	andcc	old_lvl, scr4, %g0;					\
	bz,pt	%icc, 8f;						\
	nop;								\
	/* go through 1/2 speed. */					\
	SET_JP_SPEED(JBUS_CONFIG_ECLK_2, scr3, scr4);			\
	SET_TOM_SPEED(TOM_HALF_SPEED, scr2, scr3);			\
	SET_SLAVE_T_SPEED(TOM_HALF_SPEED, scr3, scr4);			\
	JP_ADJUST_FSM(0, scr3, scr4);					\
	set	jp_estar_tl0_data, scr3;				\
	ldx	[scr3], %g0;						\
	membar	#Sync;		/* or busy wait 1us */			\
	JP_ESTAR_TRIGGER(scr3, scr4);					\
8:									\
	/* bring to 1:1 speed */					\
	SET_JP_SPEED(JBUS_CONFIG_ECLK_1, scr3, scr4);			\
	SET_TOM_SPEED(TOM_FULL_SPEED, scr2, scr3);			\
	SET_SLAVE_T_SPEED(TOM_FULL_SPEED, scr3, scr4);			\
	JP_ADJUST_FSM(JP_MCU_FSM_MASK, scr3, scr4);			\
	JP_ESTAR_TRIGGER(scr3, scr4)


/*
 * Macro to restore Jalapeno/Tomatillo to original speed
 *     old_lvl - register contains saved original cpu, tomatillo speed 
 *     scr2 - scratch register
 *     scr3 - scratch register
 *     scr4 - scratch register
 *
 * If trap had occured in the middle of ppm cpu speed transtion, then
 * old_lvl[31:10] contains the intended new speed written into jbus_config.
 * if old_lvl[9:0] is inconsistent with old_lvl[31:10], then the trap surely
 * interrupted the ppm cpu speed transition, otherwise nothing for sure.  
 * We'll restore the intended/then-current speed, that should cause no
 * trouble to subsequent ppm cpu speed change code.
 */
#define	JP_RESTORE_SPEED(old_lvl, scr2, scr3, scr4)			\
	srlx	old_lvl, JBUS_CONFIG_ECLK_SHIFT, scr2;			\
	and	scr2, 3, scr2;						\
	add	scr2, 1, scr2;						\
	cmp	scr2, 3;						\
	bne,pt	%icc, 7f;						\
	  nop;								\
	set	TOM_SLOW_SPEED, scr2;					\
	/* scr2 contains tom speed according to intended jp speed */	\
7:									\
	andn	old_lvl, TOM_ESTAR_ELCK_MASK, old_lvl;			\
	or	scr2, old_lvl, old_lvl;					\
	/* updated old_lvl to contain intended jp and tom speed */	\
	andcc	old_lvl, TOM_FULL_SPEED, %g0;				\
	bnz,pt	%icc, 9f;	/* intended full, already at full */	\
	nop;								\
									\
	/* go to half speed */						\
	SET_JP_SPEED(JBUS_CONFIG_ECLK_2, scr3, scr4);			\
	SET_64BIT_PA(scr2, scr3, TOM_HIGH_PA, M_T_ESTAR_CTRL_PA);	\
	SET_TOM_SPEED(TOM_HALF_SPEED, scr2, scr3);			\
	SET_SLAVE_T_SPEED(TOM_HALF_SPEED, scr3, scr4);			\
	JP_ADJUST_FSM(0, scr3, scr4);					\
	set	jp_estar_tl0_data, scr3;				\
	ldx	[scr3], %g0;						\
	membar	#Sync;							\
	JP_ESTAR_TRIGGER(scr3, scr4);					\
	andcc	old_lvl, TOM_SLOW_SPEED, %g0;				\
	bz,pt	%icc, 9f;	/* intended 1:2, already at 1:2 */	\
	  nop;								\
									\
	/* go to 1:32 speed */						\
	SET_JP_SPEED(JBUS_CONFIG_ECLK_32, scr3, scr4);			\
	SET_TOM_SPEED(TOM_SLOW_SPEED, scr2, scr3);			\
	SET_SLAVE_T_SPEED(TOM_SLOW_SPEED, scr3, scr4);			\
	JP_ESTAR_TRIGGER(scr3, scr4);					\
9:

#endif /* !(JBUS_CONFIG_ECLK_MASK & TOM_SPEED_MASK) */
#endif	/* JALAPENO && JALAPENO_ERRATA_85 */

/*
 * Jalapeno version to reflush an Ecache line by index.
 * Will flush all 4 ways (with only one scratch register).
 * Note that the code will be faster if we use 2 scratch registers.
 */
#define	ECACHE_REFLUSH_LINE(ec_set_size, index, scr1)			\
	JP_EC_DIAG_ACCESS_MEMBAR;					\
	ldxa	[index]ASI_EC_DIAG, %g0;				\
	JP_EC_DIAG_ACCESS_MEMBAR;					\
	mov	1, scr1;						\
	sllx	scr1, JP_ECFLUSH_EC_WAY_SHIFT, scr1;			\
	add	scr1, index, scr1;					\
	JP_EC_DIAG_ACCESS_MEMBAR;					\
	ldxa	[scr1]ASI_EC_DIAG, %g0;					\
	JP_EC_DIAG_ACCESS_MEMBAR;					\
	mov	2, scr1;						\
	sllx	scr1, JP_ECFLUSH_EC_WAY_SHIFT, scr1;			\
	add	scr1, index, scr1;					\
	JP_EC_DIAG_ACCESS_MEMBAR;					\
	ldxa	[scr1]ASI_EC_DIAG, %g0;					\
	JP_EC_DIAG_ACCESS_MEMBAR;					\
	mov	3, scr1;						\
	sllx	scr1, JP_ECFLUSH_EC_WAY_SHIFT, scr1;			\
	add	scr1, index, scr1;					\
	JP_EC_DIAG_ACCESS_MEMBAR;					\
	ldxa	[scr1]ASI_EC_DIAG, %g0;					\
	JP_EC_DIAG_ACCESS_MEMBAR

/*
 * Jalapeno version of ecache_flush_line.  Uses Jalapeno Ecache Displacement
 * Flush feature to flush all 4 sets/ways.
 */
#define	ECACHE_FLUSH_LINE(physaddr, ec_set_size, scr1, scr2)		\
	CPU_INDEX(scr1, scr2);						\
	sllx	scr1, JP_ECFLUSH_PORTID_SHIFT, scr1;			\
	set	JP_ECACHE_IDX_DISP_FLUSH, scr2;				\
	or	scr2, scr1, scr2;					\
	sub	ec_set_size, 1, scr1;					\
	and	physaddr, scr1, scr1;					\
	or	scr2, scr1, scr1;					\
	ECACHE_REFLUSH_LINE(ec_set_size, scr1, scr2)

/*
 * Macro for getting ecache size from cpunodes structure
 *  scr1:    Scratch, ecache size returned in this
 *  scr2:    Scratch
 */
#define	GET_ECACHE_SIZE(scr1, scr2)					\
	CPU_INDEX(scr1, scr2);						\
	mulx	scr1, CPU_NODE_SIZE, scr1;				\
	set	cpunodes + ECACHE_SIZE, scr2;				\
	ld	[scr1 + scr2], scr1

/* END CSTYLED */

/*
 * Ship mondo to aid using implicit busy/nack pair (bn ignored)
 */
	ENTRY_NP(shipit)
	sll	%o0, IDCR_PID_SHIFT, %g1	! IDCR<18:14> = agent id
	or	%g1, IDCR_OFFSET, %g1		! IDCR<13:0> = 0x70
	stxa	%g0, [%g1]ASI_INTR_DISPATCH	! interrupt vector dispatch
	membar	#Sync
	retl
	nop
	SET_SIZE(shipit)


/*
 * flush_ecache:
 *	%o0 - 64 bit physical address
 *	%o1 - ecache size
 *	%o2 - ecache linesize
 */

	ENTRY(flush_ecache)
#if defined(JALAPENO) && defined(JALAPENO_ERRATA_85)
	CHK_JP_ERRATA85_ENABLED(%g1, flush_ecache_1);
	JP_FORCE_FULL_SPEED(%o3, %g1, %g2, %g3);	/* %o3: saved speed */
flush_ecache_1:
#endif	/* JALAPENO && JALAPENO_ERRATA_85 */

	/*
	 * Flush the entire Ecache using displacement flush.
	 */
	ECACHE_FLUSHALL(%o1, %o2, %o0, %o4)

#if defined(JALAPENO) && defined(JALAPENO_ERRATA_85)
	CHK_JP_ERRATA85_ENABLED(%g1, flush_ecache_2);
	JP_RESTORE_SPEED(%o3, %g1, %g2, %g3);		/* %o3: saved speed */
flush_ecache_2:
#endif	/* JALAPENO && JALAPENO_ERRATA_85 */

	retl
	nop
	SET_SIZE(flush_ecache)


	.section ".text"
	.align	64
	ENTRY_NP(fast_ecc_err)
	
	/*
	 * Turn off CEEN and NCEEN.
	 */
	ldxa	[%g0]ASI_ESTATE_ERR, %g3
	andn	%g3, EN_REG_NCEEN + EN_REG_CEEN, %g4
	stxa	%g4, [%g0]ASI_ESTATE_ERR
	membar	#Sync			! membar sync required

	/*
	 * Do the CPU log out capture.
	 *   %g3 = "failed?" return value.
	 *   %g2 = Input = AFAR. Output the clo_flags info which is passed
	 *         into this macro via %g4. Output only valid if cpu_private
	 *         struct has not been initialized.
	 *   CHPR_FECCTL0_LOGOUT = cpu logout structure offset input
	 *   %g4 = Trap information stored in the cpu logout flags field
	 *   %g5 = scr1
	 *   %g6 = scr2
	 *   %g3 = scr3
	 *   %g4 = scr4
	 */
	and	%g3, EN_REG_CEEN, %g4		! store the CEEN value, TL=0
	set	CHPR_FECCTL0_LOGOUT, %g6
	DO_CPU_LOGOUT(%g3, %g2, %g6, %g4, %g5, %g6, %g3, %g4)

	/*
	 * Flush the Ecache to get the error out of the Ecache.  If the UCC
	 * or UCU is on a dirty line, then the following flush will turn
	 * that into a WDC or WDU, respectively.
	 */
	CPU_INDEX(%g4, %g5)
	mulx	%g4, CPU_NODE_SIZE, %g4
	set	cpunodes, %g5
	add	%g4, %g5, %g4
	ld	[%g4 + ECACHE_LINESIZE], %g5
	ld	[%g4 + ECACHE_SIZE], %g4
#if defined(JALAPENO) && defined(JALAPENO_ERRATA_85)
	CHK_JP_ERRATA85_ENABLED(%g6, fast_ecc_err_1);
        set     jp_estar_tl0_data, %g6
        stx     %g2, [%g6 + 0]
        stx     %g3, [%g6 + 8]
	JP_FORCE_FULL_SPEED(%g2, %g3, %g6, %g7)		/* %g2: saved speed */
fast_ecc_err_1:
#endif	/* JALAPENO && JALAPENO_ERRATA_85 */
	ECACHE_FLUSHALL(%g4, %g5, %g6, %g7)
#if defined(JALAPENO) && defined(JALAPENO_ERRATA_85)
	CHK_JP_ERRATA85_ENABLED(%g6, fast_ecc_err_2);
	JP_RESTORE_SPEED(%g2, %g3, %g6, %g7)		/* %g2: saved speed */
        set     jp_estar_tl0_data, %g6
        ldx     [%g6 + 0], %g2
        ldx     [%g6 + 8], %g3
fast_ecc_err_2:
#endif	/* JALAPENO && JALAPENO_ERRATA_85 */

	/*
	 * Flush the Dcache.  Since bad data could have been installed in
	 * the Dcache we must flush it before re-enabling it.
	 */
	ASM_LD(%g5, dcache_size)
	ASM_LD(%g6, dcache_linesize)
	CH_DCACHE_FLUSHALL(%g5, %g6, %g7)

	/*
	 * Flush the Icache.  Since we turned off the Icache to capture the
	 * Icache line it is now stale or corrupted and we must flush it
	 * before re-enabling it.
	 */
	GET_CPU_PRIVATE_PTR(%g0, %g5, %g7, fast_ecc_err_4);
	ld	[%g5 + CHPR_ICACHE_LINESIZE], %g6
	ba,pt	%icc, 5f
	  ld	[%g5 + CHPR_ICACHE_SIZE], %g5
fast_ecc_err_4:
	ASM_LD(%g5, icache_size)
	ASM_LD(%g6, icache_linesize)
5:
	CH_ICACHE_FLUSHALL(%g5, %g6, %g7, %g4)

	/*
	 * Restore the Dcache and Icache to the previous state.
	 */
	stxa	%g1, [%g0]ASI_DCU
	flush	%g0	/* flush required after changing the IC bit */

	/*
	 * Make sure our CPU logout operation was successful.
	 */
	cmp	%g3, %g0
	be	8f
	  nop

	/*
	 * If the logout structure had been busy, how many times have
	 * we tried to use it and failed (nesting count)? If we have
	 * already recursed a substantial number of times, then we can
	 * assume things are not going to get better by themselves and
	 * so it would be best to panic.
	 */
	cmp	%g3, CLO_NESTING_MAX
	blt	7f
	  nop

        call ptl1_panic
          mov   PTL1_BAD_ECC, %g1

7:
	/*
	 * Otherwise, if the logout structure was busy but we have not
	 * nested more times than our maximum value, then we simply
	 * issue a retry. Our TL=0 trap handler code will check and
	 * clear the AFSR after it is done logging what is currently
	 * in the logout struct and handle this event at that time.
	 */
	retry
8:
	/*
	 * Call cpu_fast_ecc_error via systrap at PIL 14 unless we're
	 * already at PIL 15.
	 */
	set	cpu_fast_ecc_error, %g1
	rdpr	%pil, %g4
	cmp	%g4, PIL_14
	ba	sys_trap
	  movl	%icc, PIL_14, %g4

	SET_SIZE(fast_ecc_err)


/*
 * Fast ECC error at TL>0 handler
 * We get here via trap 70 at TL>0->Software trap 0 at TL>0.  We enter
 * this routine with %g1 and %g2 already saved in %tpc, %tnpc and %tstate.
 * For a complete description of the Fast ECC at TL>0 handling see the
 * comment block "Cheetah/Cheetah+ Fast ECC at TL>0 trap strategy" in
 * us3_common_asm.s
 */

	.section ".text"
	.align	64
	ENTRY_NP(fast_ecc_tl1_err)

	/*
	 * This macro turns off the D$/I$ if they are on and saves their
	 * original state in ch_err_tl1_tmp, saves all the %g registers in the
	 * ch_err_tl1_data structure, updates the ch_err_tl1_flags and saves
	 * the %tpc in ch_err_tl1_tpc.  At the end of this macro, %g1 will
	 * point to the ch_err_tl1_data structure and the original D$/I$ state
	 * will be saved in ch_err_tl1_tmp.  All %g registers except for %g1
	 * will be available.
	 */
	CH_ERR_TL1_FECC_ENTER;

	/*
	 * Get the diagnostic logout data.  %g4 must be initialized to
	 * current CEEN state, %g5 must point to logout structure in
	 * ch_err_tl1_data_t.  %g3 will contain the nesting count upon
	 * return.
	 */
	ldxa	[%g0]ASI_ESTATE_ERR, %g4
	and	%g4, EN_REG_CEEN, %g4
	add	%g1, CH_ERR_TL1_LOGOUT, %g5
	DO_TL1_CPU_LOGOUT(%g3, %g2, %g4, %g5, %g6, %g3, %g4)

	/*
	 * If the logout nesting count is exceeded, we're probably
	 * not making any progress, try to panic instead.
	 */
	cmp	%g3, CLO_NESTING_MAX
	bge	fecc_tl1_err
	  nop

	/*
	 * Save the current CEEN and NCEEN state in %g7 and turn them off
	 * before flushing the Ecache.
	 */
	ldxa	[%g0]ASI_ESTATE_ERR, %g7
	andn	%g7, EN_REG_CEEN | EN_REG_NCEEN, %g5
	stxa	%g5, [%g0]ASI_ESTATE_ERR
	membar	#Sync

	/*
	 * Flush the Ecache, using the largest possible cache size with the
	 * smallest possible line size since we can't get the actual sizes
	 * from the cpu_node due to DTLB misses.
	 */
	set	JP_ECACHE_MAX_SIZE, %g4
#if defined(JALAPENO) && defined(JALAPENO_ERRATA_85)
	CHK_JP_ERRATA85_ENABLED(%g6, fast_ecc_tl1_err_1);
        set     jp_estar_tl1_data, %g6
        stx     %g2, [%g6 + 0]
        stx     %g3, [%g6 + 8]
	JP_FORCE_FULL_SPEED(%g2, %g3, %g5, %g6)
fast_ecc_tl1_err_1:
#endif	/* JALAPENO && JALAPENO_ERRATA_85 */
	ECACHE_FLUSHALL(%g4, JP_ECACHE_MAX_LSIZE, %g5, %g6)
#if defined(JALAPENO) && defined(JALAPENO_ERRATA_85)
	CHK_JP_ERRATA85_ENABLED(%g6, fast_ecc_tl1_err_2);
	JP_RESTORE_SPEED(%g2, %g3, %g5, %g6)
        set     jp_estar_tl1_data, %g6
        ldx     [%g6 + 0], %g2
        ldx     [%g6 + 8], %g3
fast_ecc_tl1_err_2:
#endif	/* JALAPENO && JALAPENO_ERRATA_85 */

	/*
	 * Restore CEEN and NCEEN to the previous state.
	 */
	stxa	%g7, [%g0]ASI_ESTATE_ERR
	membar	#Sync

	/*
	 * If we turned off the D$, then flush it and turn it back on.
	 */
	ldxa	[%g1 + CH_ERR_TL1_TMP]%asi, %g3
	andcc	%g3, CH_ERR_TSTATE_DC_ON, %g0
	bz	%xcc, 3f
	  nop

	/*
	 * Flush the D$.
	 */
	ASM_LD(%g4, dcache_size)
	ASM_LD(%g5, dcache_linesize)
	CH_DCACHE_FLUSHALL(%g4, %g5, %g6)

	/*
	 * Turn the D$ back on.
	 */
	ldxa	[%g0]ASI_DCU, %g3
	or	%g3, DCU_DC, %g3
	stxa	%g3, [%g0]ASI_DCU
	membar	#Sync
3:
	/*
	 * If we turned off the I$, then flush it and turn it back on.
	 */
	ldxa	[%g1 + CH_ERR_TL1_TMP]%asi, %g3
	andcc	%g3, CH_ERR_TSTATE_IC_ON, %g0
	bz	%xcc, 4f
	  nop

	/*
	 * Flush the I$.
	 */
	ASM_LD(%g4, icache_size)
	ASM_LD(%g5, icache_linesize)
	CH_ICACHE_FLUSHALL(%g4, %g5, %g6, %g3)

	/*
	 * Turn the I$ back on.  Changing DCU_IC requires flush.
	 */
	ldxa	[%g0]ASI_DCU, %g3
	or	%g3, DCU_IC, %g3
	stxa	%g3, [%g0]ASI_DCU
	flush	%g0
4:

#ifdef TRAPTRACE
	/*
	 * Get current trap trace entry physical pointer.
	 */
	CPU_INDEX(%g6, %g5)
	sll	%g6, TRAPTR_SIZE_SHIFT, %g6
	set	trap_trace_ctl, %g5
	add	%g6, %g5, %g6
	ld	[%g6 + TRAPTR_LIMIT], %g5
	tst	%g5
	be	%icc, skip_traptrace
	  nop
	ldx	[%g6 + TRAPTR_PBASE], %g5
	ld	[%g6 + TRAPTR_OFFSET], %g4
	add	%g5, %g4, %g5

	/*
	 * Create trap trace entry.
	 */
	rd	%asi, %g7
	wr	%g0, TRAPTR_ASI, %asi
	rd	STICK, %g4
	stxa	%g4, [%g5 + TRAP_ENT_TICK]%asi
	rdpr	%tl, %g4
	stha	%g4, [%g5 + TRAP_ENT_TL]%asi
	rdpr	%tt, %g4
	stha	%g4, [%g5 + TRAP_ENT_TT]%asi
	rdpr	%tpc, %g4
	stna	%g4, [%g5 + TRAP_ENT_TPC]%asi
	rdpr	%tstate, %g4
	stxa	%g4, [%g5 + TRAP_ENT_TSTATE]%asi
	stna	%sp, [%g5 + TRAP_ENT_SP]%asi
	stna	%g0, [%g5 + TRAP_ENT_TR]%asi
	wr	%g0, %g7, %asi
	ldxa	[%g1 + CH_ERR_TL1_SDW_AFAR]%asi, %g3
	ldxa	[%g1 + CH_ERR_TL1_SDW_AFSR]%asi, %g4
	wr	%g0, TRAPTR_ASI, %asi
	stna	%g3, [%g5 + TRAP_ENT_F1]%asi
	stna	%g4, [%g5 + TRAP_ENT_F2]%asi
	wr	%g0, %g7, %asi
	ldxa	[%g1 + CH_ERR_TL1_AFAR]%asi, %g3
	ldxa	[%g1 + CH_ERR_TL1_AFSR]%asi, %g4
	wr	%g0, TRAPTR_ASI, %asi
	stna	%g3, [%g5 + TRAP_ENT_F3]%asi
	stna	%g4, [%g5 + TRAP_ENT_F4]%asi
	wr	%g0, %g7, %asi

	/*
	 * Advance trap trace pointer.
	 */
	ld	[%g6 + TRAPTR_OFFSET], %g5
	ld	[%g6 + TRAPTR_LIMIT], %g4
	st	%g5, [%g6 + TRAPTR_LAST_OFFSET]
	add	%g5, TRAP_ENT_SIZE, %g5
	sub	%g4, TRAP_ENT_SIZE, %g4
	cmp	%g5, %g4
	movge	%icc, 0, %g5
	st	%g5, [%g6 + TRAPTR_OFFSET]
skip_traptrace:
#endif	/* TRAPTRACE */

	/*
	 * If nesting count is not zero, skip all the AFSR/AFAR
	 * handling and just do the necessary cache-flushing.
	 */
	ldxa	[%g1 + CH_ERR_TL1_NEST_CNT]%asi, %g2
	brnz	%g2, 6f
	  nop

	/*
	 * If a UCU followed by a WDU has occurred go ahead and panic
	 * since a UE will occur (on the retry) before the UCU and WDU
	 * messages are enqueued.
	 */
	ldxa	[%g1 + CH_ERR_TL1_AFSR]%asi, %g3
	set	1, %g4
	sllx	%g4, C_AFSR_UCU_SHIFT, %g4
	btst	%g4, %g3		! UCU in original AFSR?
	bz	%xcc, 6f
	  nop
	ldxa	[%g0]ASI_AFSR, %g4	! current AFSR
	or	%g3, %g4, %g3		! %g3 = original + current AFSR
	set	1, %g4
	sllx	%g4, C_AFSR_WDU_SHIFT, %g4
	btst	%g4, %g3		! WDU in original or current AFSR?
	bnz	%xcc, fecc_tl1_err
	  nop

6:
	/*
	 * We fall into this macro if we've successfully logged the error in
	 * the ch_err_tl1_data structure and want the PIL15 softint to pick
	 * it up and log it.  %g1 must point to the ch_err_tl1_data structure.
	 * Restores the %g registers and issues retry.
	 */
	CH_ERR_TL1_EXIT;
	/*
	 * Establish panic exit label.
	 */
	CH_ERR_TL1_PANIC_EXIT(fecc_tl1_err);

	SET_SIZE(fast_ecc_tl1_err)


	ENTRY(get_jbus_config)
	ldxa	[%g0]ASI_JBUS_CONFIG, %o0
	retl
	nop
	SET_SIZE(get_jbus_config)

	ENTRY(set_jbus_config)
	stxa	%o0, [%g0]ASI_JBUS_CONFIG
	membar	#Sync
	retl
	nop
	SET_SIZE(set_jbus_config)


	ENTRY(get_mcu_ctl_reg1)
	ldxa	[%g0]ASI_MCU_CTRL, %o0	! MCU control reg1 is at offset 0
	retl
	nop
	SET_SIZE(get_mcu_ctl_reg1)


	ENTRY(set_mcu_ctl_reg1)
	stxa	%o0, [%g0]ASI_MCU_CTRL	! MCU control reg1 is at offset 0
	membar	#Sync
	retl
	nop
	SET_SIZE(set_mcu_ctl_reg1)


/*
 * scrubphys - Pass in the aligned physical memory address
 * that you want to scrub, along with the ecache set size.
 *
 *	1) Displacement flush the E$ line corresponding to %addr.
 *	   The first ldxa guarantees that the %addr is no longer in
 *	   M, O, or E (goes to I or S (if instruction fetch also happens).
 *	2) "Write" the data using a CAS %addr,%g0,%g0.
 *	   The casxa guarantees a transition from I to M or S to M.
 *	3) Displacement flush the E$ line corresponding to %addr.
 *	   The second ldxa pushes the M line out of the ecache, into the
 *	   writeback buffers, on the way to memory.
 *	4) The "membar #Sync" pushes the cache line out of the writeback
 *	   buffers onto the bus, on the way to dram finally.
 *
 * This is a modified version of the algorithm suggested by Gary Lauterbach.
 * In theory the CAS %addr,%g0,%g0 is supposed to mark the addr's cache line
 * as modified, but then we found out that for spitfire, if it misses in the
 * E$ it will probably install as an M, but if it hits in the E$, then it
 * will stay E, if the store doesn't happen. So the first displacement flush
 * should ensure that the CAS will miss in the E$.  Arrgh.
 */
	ENTRY(scrubphys)
	rdpr	%pstate, %o4
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, %g0, %pstate	! clear IE, AM bits

#if defined(JALAPENO) && defined(JALAPENO_ERRATA_85)
	CHK_JP_ERRATA85_ENABLED(%g1, scrubphys_1);
	JP_FORCE_FULL_SPEED(%o5, %g1, %g2, %g3)		/* %o5: saved speed */
scrubphys_1:
#endif	/* JALAPENO && JALAPENO_ERRATA_85 */

	ECACHE_FLUSH_LINE(%o0, %o1, %o2, %o3)
	casxa	[%o0]ASI_MEM, %g0, %g0
	ECACHE_REFLUSH_LINE(%o1, %o2, %o3)

#if defined(JALAPENO) && defined(JALAPENO_ERRATA_85)
	CHK_JP_ERRATA85_ENABLED(%g1, scrubphys_2);
	JP_RESTORE_SPEED(%o5, %g1, %g2, %g3)		/* %o5: saved speed */
scrubphys_2:
#endif	/* JALAPENO && JALAPENO_ERRATA_85 */

	wrpr	%g0, %o4, %pstate	! restore earlier pstate register value

	retl
	membar	#Sync			! move the data out of the load buffer
	SET_SIZE(scrubphys)

/*
 * clearphys - Pass in the physical memory address of the checkblock
 * that you want to push out, cleared with a recognizable pattern,
 * from the ecache.
 *
 * To ensure that the ecc gets recalculated after the bad data is cleared,
 * we must write out enough data to fill the w$ line (64 bytes). So we read
 * in an entire ecache subblock's worth of data, and write it back out.
 * Then we overwrite the 16 bytes of bad data with the pattern.
 */
	ENTRY(clearphys)
	/* turn off IE, AM bits */
	rdpr	%pstate, %o4
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, %g0, %pstate

	/* turn off NCEEN */
	ldxa	[%g0]ASI_ESTATE_ERR, %o5
	andn	%o5, EN_REG_NCEEN, %o3
	stxa	%o3, [%g0]ASI_ESTATE_ERR
	membar	#Sync

	/* align address passed with 64 bytes subblock size */	
	mov	CH_ECACHE_SUBBLK_SIZE, %o2
	andn	%o0, (CH_ECACHE_SUBBLK_SIZE - 1), %g1
	
	/* move the good data into the W$ */	
1:
	subcc	%o2, 8, %o2
	ldxa	[%g1 + %o2]ASI_MEM, %g2
	bge	1b
	  stxa	%g2, [%g1 + %o2]ASI_MEM

	/* now overwrite the bad data */
	setx	0xbadecc00badecc01, %g1, %g2
	stxa	%g2, [%o0]ASI_MEM
	mov	8, %g1
	stxa	%g2, [%o0 + %g1]ASI_MEM

#if defined(JALAPENO) && defined(JALAPENO_ERRATA_85)
	CHK_JP_ERRATA85_ENABLED(%g1, clearphys_1);
	JP_FORCE_FULL_SPEED(%o5, %g1, %g2, %g3)		/* %o5: saved speed */
clearphys_1:
#endif	/* JALAPENO && JALAPENO_ERRATA_85 */

	ECACHE_FLUSH_LINE(%o0, %o1, %o2, %o3)
	casxa	[%o0]ASI_MEM, %g0, %g0
	ECACHE_REFLUSH_LINE(%o1, %o2, %o3)

#if defined(JALAPENO) && defined(JALAPENO_ERRATA_85)
	CHK_JP_ERRATA85_ENABLED(%g1, clearphys_2);
	JP_RESTORE_SPEED(%o5, %g1, %g2, %g3)		/* %o5: saved speed */
clearphys_2:
#endif	/* JALAPENO && JALAPENO_ERRATA_85 */

	/* clear the AFSR */
	ldxa	[%g0]ASI_AFSR, %o1
	stxa	%o1, [%g0]ASI_AFSR
	membar	#Sync

	/* turn NCEEN back on */
	stxa	%o5, [%g0]ASI_ESTATE_ERR
	membar	#Sync

	/* return and re-enable IE and AM */
	retl
	  wrpr	%g0, %o4, %pstate
	SET_SIZE(clearphys)


/*
 * Jalapeno Ecache displacement flush the specified line from the E$
 *
 * Register usage:
 *	%o0 - 64 bit physical address for flushing
 *	%o1 - Ecache set size
 */
	ENTRY(ecache_flush_line)

#if defined(JALAPENO) && defined(JALAPENO_ERRATA_85)
	CHK_JP_ERRATA85_ENABLED(%g1, ecache_flush_line_1);
	JP_FORCE_FULL_SPEED(%o5, %g1, %g2, %g3)		/* %o5: saved speed */
ecache_flush_line_1:
#endif	/* JALAPENO && JALAPENO_ERRATA_85 */

	ECACHE_FLUSH_LINE(%o0, %o1, %o2, %o3)

#if defined(JALAPENO) && defined(JALAPENO_ERRATA_85)
	CHK_JP_ERRATA85_ENABLED(%g1, ecache_flush_line_2);
	JP_RESTORE_SPEED(%o5, %g1, %g2, %g3)		/* %o5: saved speed */
ecache_flush_line_2:
#endif	/* JALAPENO && JALAPENO_ERRATA_85 */

	retl
	  nop
	SET_SIZE(ecache_flush_line)


/*
 * Perform necessary cpu workaround to ensure jbus ordering.
 * Called only from Fire systems.
 * CPU's internal "invalidate FIFOs" are flushed.
 */

#define	VIS_BLOCKSIZE	64

	.seg    ".data"
	.align  VIS_BLOCKSIZE
	.type   sync_buf, #object
sync_buf:
	.skip   VIS_BLOCKSIZE
	.size   sync_buf, VIS_BLOCKSIZE

	ENTRY(jbus_stst_order)
	set	sync_buf, %o1

	rd	%fprs, %o2			! %o2 = saved fprs
	or	%o2, FPRS_FEF, %o3
	wr	%g0, %o3, %fprs			! make sure fp is enabled
	stda    %d0, [%o1]ASI_BLK_COMMIT_P
	wr	%o2, 0, %fprs			! restore fprs

	retl
	membar  #Sync
	SET_SIZE(jbus_stst_order)

/*
 * This routine will not be called in Jalapeno systems.
 */
	ENTRY(flush_ipb)
	retl
	nop
	SET_SIZE(flush_ipb)

