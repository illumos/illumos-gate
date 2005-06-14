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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>
#include <sys/machparam.h>	/* To get SYSBASE and PAGESIZE */
#include <sys/privregs.h>

#if !defined(lint)

	.seg	".text"
	.align	4

#define	PSR_PIL_BIT	0x8

/*
 * Macro to raise processor priority level.
 * Avoid dropping processor priority if already at high level.
 * Also avoid going below CPU->cpu_base_spl, which could've just been set by
 * a higher-level interrupt thread that just blocked.
 * XXX4U: bring splr inline
 */
#define	RAISE(level) \
	b	splr; \
	mov	((level) << PSR_PIL_BIT), %o0
/*
 * Macro to set the priority to a specified level.
 * Avoid dropping the priority below CPU->cpu_base_spl.
 * XXX4U: bring splx inline
 */
#define SETPRI(level) \
	b	splx; \
	mov	((level) << PSR_PIL_BIT), %o0

#endif	/* lint */

	/*
	 * Berkley 4.3 introduced symbolically named interrupt levels
	 * as a way deal with priority in a machine independent fashion.
	 * Numbered priorities are machine specific, and should be
	 * discouraged where possible.
	 *
	 * Note, for the machine specific priorities there are
	 * examples listed for devices that use a particular priority.
	 * It should not be construed that all devices of that
	 * type should be at that priority.  It is currently were
	 * the current devices fit into the priority scheme based
	 * upon time criticalness.
	 *
	 * The underlying assumption of these assignments is that
	 * SPARC9 IPL 10 is the highest level from which a device
	 * routine can call wakeup.  Devices that interrupt from higher
	 * levels are restricted in what they can do.  If they need
	 * kernels services they should schedule a routine at a lower
	 * level (via software interrupt) to do the required
	 * processing.
	 *
	 * Examples of this higher usage:
	 *	Level	Usage
	 *	15	Asynchronous memory exceptions
	 *	14	Profiling clock (and PROM uart polling clock)
	 *	13	Audio device
	 *	12	Serial ports
	 *	11	Floppy controller
	 *
	 * The serial ports request lower level processing on level 6.
	 * Audio and floppy request lower level processing on level 4.
	 *
	 * Also, almost all splN routines (where N is a number or a
	 * mnemonic) will do a RAISE(), on the assumption that they are
	 * never used to lower our priority.
	 * The exceptions are:
	 *	spl8()		Because you can't be above 15 to begin with!
	 *	splzs()		Because this is used at boot time to lower our
	 *			priority, to allow the PROM to poll the uart.
	 *	spl0()		Used to lower priority to 0.
	 *	splsoftclock()	Used by hardclock to lower priority.
	 */

#if defined(lint)

int splimp(void)	{ return (0); }
int splnet(void)	{ return (0); }

#ifdef	notdef
int spl6(void)		{ return (0); }
int spl5(void)		{ return (0); }
#endif	notdef

#else	/* lint */

	/* locks out all interrupts, including memory errors */
	ENTRY(spl8)
	SETPRI(15)
	SET_SIZE(spl8)

	/* just below the level that profiling runs */
	ALTENTRY(splaudio)
	ENTRY(spl7)
	RAISE(13)
	SET_SIZE(spl7)
	SET_SIZE(splaudio)

	/* sun specific - highest priority onboard serial i/o zs ports */
	ALTENTRY(splzs)
	SETPRI(12)	/* Can't be a RAISE, as it's used to lower us */
	SET_SIZE(splzs)

	/*
	 * should lock out clocks and all interrupts,
	 * as you can see, there are exceptions
	 */
	ALTENTRY(splhigh)
	ALTENTRY(splhi)

	/* the standard clock interrupt priority */
	ALTENTRY(splclock)

	/* highest priority for any tty handling */
	ALTENTRY(spltty)

	/* highest priority required for protection of buffered io system */
	ALTENTRY(splbio)

	/* machine specific */
	ENTRY2(spl6,spl5)
	RAISE(10)
	SET_SIZE(splhigh)
	SET_SIZE(splhi)
	SET_SIZE(splclock)
	SET_SIZE(spltty)
	SET_SIZE(splbio)
	SET_SIZE(spl5)
	SET_SIZE(spl6)

	/*
	 * machine specific
	 * for sun, some frame buffers must be at this priority
	 */
	ENTRY(spl4)
	RAISE(8)
	SET_SIZE(spl4)

	/* highest level that any network device will use */
	ALTENTRY(splimp)

	/*
	 * machine specific
	 * for sun, devices with limited buffering: tapes, ethernet
	 */
	ENTRY(spl3)
	RAISE(6)
	SET_SIZE(splimp)
	SET_SIZE(spl3)

	/*
	 * machine specific - not as time critical as above
	 * for sun, disks
	 */
	ENTRY(spl2)
	RAISE(4)
	SET_SIZE(spl2)

	ENTRY(spl1)
	RAISE(2)
	SET_SIZE(spl1)

	/* highest level that any protocol handler will run */
	ENTRY(splnet)
	RAISE(1)
	SET_SIZE(splnet)

	/* softcall priority */
	/* used by hardclock to LOWER priority */
	ENTRY(splsoftclock)
	SETPRI(1)
	SET_SIZE(splsoftclock)

	/* allow all interrupts */
	ENTRY(spl0)
	SETPRI(0)
	SET_SIZE(spl0)

#endif	/* lint */

/*
 * splx - set PIL back to that indicated by the old %PSR passed as an argument,
 * or to the CPU's base priority, whichever is higher.
 * sys_rtt (in locore.s) relies on this not to use %g1 or %g2.
 */

#if defined(lint)

/* ARGSUSED */
void
splx(int level)
{
}

#else	/* lint */

	ENTRY(splx)
	rdpr	%pil, %o1	! get current pil
	wrpr	%o0, %pil
	retl
	mov	%o1, %o0
	SET_SIZE(splx)

#endif	/* level */

/*
 * splr()
 *
 * splr is like splx but will only raise the priority and never drop it
 * Be careful not to set priority lower than CPU->cpu_base_pri,
 * even though it seems we're raising the priority, it could be set higher
 * at any time by an interrupt routine, so we must block interrupts and
 * look at CPU->cpu_base_pri.
 *
 */

#if defined(lint)
#ifdef	notdef

/* ARGSUSED */
int
splr(int level)
{ return (0); }

#endif	notdef
#else	/* lint */

/*
 * splr(psr_pri_field)
 * splr is like splx but will only raise the priority and never drop it
 */

	ENTRY(splr)
	rdpr	%pil, %o1	! get current pil
	cmp	%o0, %o1
	ble	1f
	nop
	wrpr	%o0, %pil
1:	retl
	mov	%o1, %o0	! return the old pil
	SET_SIZE(splr)

#endif	/* lint */

/*
 * get_ticks()
 */
#if defined(lint)

/* ARGSUSED */
uint64_t
get_ticks(void)
{ return (0); }

#else	/* lint */

	ENTRY(get_ticks)
	rdpr	%tick, %o0
	sllx	%o0, 1, %o0
	retl
	srlx	%o0, 1, %o0		! shake off npt bit
	SET_SIZE(get_ticks)

#endif	/* lint */
