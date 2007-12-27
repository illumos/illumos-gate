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

#include <sys/reboot.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/prom_plat.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/ivintr.h>
#include <sys/kdi.h>
#include <sys/kdi_machimpl.h>
#include <sys/callb.h>
#include <sys/wdt.h>

#ifdef	TRAPTRACE
#include <sys/traptrace.h>
#endif /* TRAPTRACE */

extern void audit_enterprom();
extern void audit_exitprom();

/*
 * Platforms that use CPU signatures need to set cpu_sgn_func
 * to point to a platform specific function.  This needs to
 * be done in set_platform_defaults() within the platmod.
 */
void (*cpu_sgn_func)(ushort_t, uchar_t, uchar_t, int) = NULL;

/*
 * abort_seq_handler required by sysctrl.
 */
void debug_enter(char *);
void (*abort_seq_handler)(char *) = debug_enter;

/*
 * Platform tunable to disable the h/w watchdog timer.
 */
extern void clear_watchdog_on_exit(void);

/*
 * On sun4u platform, abort_sequence_enter() can be called at high PIL
 * and we can't afford to acquire any adaptive mutex or use any
 * condition variables as we are not allowed to sleep while running
 * on interrupt stack. We work around this problem by posting a level
 * 10 soft interrupt and then invoking the "abort_seq_handler" within
 * that soft interrupt context.
 *
 * This has the side effect of not allowing us to drop into debugger
 * when the kernel is stuck at high PIL (PIL > 10).  It's better to
 * be able to break into a hung system even if it means crashing the
 * system.  If a user presses L1-A more than once within a 15 seconds
 * window, and the previous L1-A soft interrupt is still pending, then
 * we directly invoke the abort_sequence_enter.
 *
 * Since the "msg" argument passed to abort_sequence_enter can refer
 * to a message anywhere in memory, including stack, it's copied into
 * abort_seq_msgbuf buffer for processing by the soft interrupt.
 */

#define	ABORT_SEQ_MSGBUFSZ	256
#define	FORCE_ABORT_SEQ_INTERVAL ((hrtime_t)15 * NANOSEC)

static kmutex_t	abort_seq_lock;
static uint64_t	abort_seq_inum;		/* abort seq softintr # */
static hrtime_t	abort_seq_tstamp;	/* hrtime of last abort seq */
static size_t	abort_seq_msglen;	/* abort seq message length */
static char	abort_seq_msgbuf[ABORT_SEQ_MSGBUFSZ];

/*ARGSUSED0*/
static uint_t
abort_seq_softintr(caddr_t arg)
{
	char	*msg;
	char	msgbuf[ABORT_SEQ_MSGBUFSZ];

	mutex_enter(&abort_seq_lock);
	if (abort_enable != 0 && abort_seq_tstamp != 0LL) {
		if (abort_seq_msglen > 0) {
			bcopy(abort_seq_msgbuf, msgbuf, abort_seq_msglen);
			msg = msgbuf;
		} else
			msg = NULL;
		abort_seq_tstamp = 0LL;
		mutex_exit(&abort_seq_lock);
		if (audit_active)
			audit_enterprom(1);
		(*abort_seq_handler)(msg);
		if (audit_active)
			audit_exitprom(1);
	} else {
		mutex_exit(&abort_seq_lock);
		if (audit_active)
			audit_enterprom(0);
	}
	return (1);
}

void
abort_sequence_init(void)
{
	mutex_init(&abort_seq_lock, NULL, MUTEX_SPIN, (void *)PIL_12);
	abort_seq_tstamp = 0LL;
	if (abort_seq_inum == 0)
		abort_seq_inum = add_softintr(LOCK_LEVEL,
		    (softintrfunc)abort_seq_softintr, NULL, SOFTINT_ST);
}

/*
 *	Machine dependent abort sequence handling
 */
void
abort_sequence_enter(char *msg)
{
	int		s, on_intr;
	size_t		msglen;
	hrtime_t	tstamp;

	if (abort_enable != 0) {
		s = splhi();
		on_intr = CPU_ON_INTR(CPU) || (spltoipl(s) > LOCK_LEVEL);
		splx(s);

		tstamp = gethrtime();
		mutex_enter(&abort_seq_lock);

		/*
		 * If we are on an interrupt stack and/or running at
		 * PIL > LOCK_LEVEL, then we post a softint and invoke
		 * abort_seq_handler from there as we can't afford to
		 * acquire any adaptive mutex here. However, if we
		 * already have a pending softint, which was posted
		 * within FORCE_ABORT_SEQ_INTERVAL duration, then we
		 * bypass softint approach as our softint may be blocked
		 * and the user really wants to drop into the debugger.
		 */
		if (on_intr && abort_seq_inum != 0 &&
		    (abort_seq_tstamp == 0LL || tstamp >
		    (abort_seq_tstamp + FORCE_ABORT_SEQ_INTERVAL))) {
			abort_seq_tstamp = tstamp;
			if (msg != NULL) {
				msglen = strlen(msg);
				if (msglen >= ABORT_SEQ_MSGBUFSZ)
					msglen = ABORT_SEQ_MSGBUFSZ - 1;
				bcopy(msg, abort_seq_msgbuf, msglen);
				abort_seq_msgbuf[msglen] = '\0';
				abort_seq_msglen = msglen + 1;
			} else
				abort_seq_msglen = 0;
			mutex_exit(&abort_seq_lock);
			setsoftint(abort_seq_inum);
		} else {
			/*
			 * Ignore any pending abort sequence softint
			 * as we are invoking the abort_seq_handler
			 * here.
			 */
			abort_seq_tstamp = 0LL;
			mutex_exit(&abort_seq_lock);
		if (!on_intr && audit_active)
			audit_enterprom(1);
			(*abort_seq_handler)(msg);
		if (!on_intr && audit_active)
			audit_exitprom(1);
		}
	} else {
		if (audit_active)
			audit_enterprom(0);
	}
}

/*
 * Enter debugger.  Called when the user types L1-A or break or whenever
 * code wants to enter the debugger and possibly resume later.
 * If the debugger isn't present, enter the PROM monitor.
 *
 * If console is a framebuffer which is powered off, it will be powered up
 * before jumping to the debugger.  If we are called above lock level, a
 * softint is triggered to reenter this code and allow the fb to be powered
 * up as in the less than lock level case.  If this code is entered at greater
 * than lock level and the fb is not already powered up, the msg argument
 * will not be displayed.
 */
void
debug_enter(char *msg)
{
	label_t old_pcb;
	int s;
	extern void pm_cfb_powerup(void);
	extern void pm_cfb_rele(void);
	extern void pm_cfb_trigger(void);
	extern int pm_cfb_check_and_hold(void);

	/*
	 * For platforms that use CPU signatures, update the signature
	 * to indicate that we are entering the debugger if we are in
	 * the middle of a panic flow.
	 */
	if (panicstr)
		CPU_SIGNATURE(OS_SIG, SIGST_EXIT, SIGSUBST_DEBUG, -1);

	if (!panicstr)
		(void) callb_execute_class(CB_CL_ENTER_DEBUGGER, 0);

	if (pm_cfb_check_and_hold())
		if (getpil() > LOCK_LEVEL) {
			pm_cfb_trigger();
			return;
		} else
			pm_cfb_powerup();
	if (msg)
		prom_printf("%s\n", msg);

	clear_watchdog_on_exit();

	if ((s = getpil()) < ipltospl(12))
		s = splzs();

	old_pcb = curthread->t_pcb;
	(void) setjmp(&curthread->t_pcb);

	if (boothowto & RB_DEBUG)
		kmdb_enter();
	else
		prom_enter_mon();

	restore_watchdog_on_entry();

	curthread->t_pcb = old_pcb;
	splx(s);
	pm_cfb_rele();

	if (!panicstr)
		(void) callb_execute_class(CB_CL_ENTER_DEBUGGER, 1);

	if (panicstr)
		CPU_SIGNATURE(OS_SIG, SIGST_EXIT, SIGSUBST_PANIC_CONT, -1);
}

/*
 * Halt the machine and return to the monitor
 */
void
halt(char *s)
{
	flush_windows();
	stop_other_cpus();		/* send stop signal to other CPUs */

	if (s)
		prom_printf("(%s) ", s);

	/*
	 * For Platforms that use CPU signatures, we
	 * need to set the signature block to OS and
	 * the state to exiting for all the processors.
	 */
	CPU_SIGNATURE(OS_SIG, SIGST_EXIT, SIGSUBST_HALT, -1);
	prom_exit_to_mon();
	/*NOTREACHED*/
}

/*
 * Halt the machine and power off the system.
 */
void
power_down(const char *s)
{
	flush_windows();
	stop_other_cpus();		/* send stop signal to other CPUs */

	if (s != NULL)
		prom_printf("(%s) ", s);

	/*
	 * For platforms that use CPU signatures, we need to set up the
	 * signature blocks to indicate that we have an environmental
	 * interrupt request to power down, and then exit to the prom monitor.
	 */
	CPU_SIGNATURE(OS_SIG, SIGST_EXIT, SIGSUBST_ENVIRON, -1);
	prom_power_off();
	/*
	 * If here is reached, for some reason prom's power-off command failed.
	 * Prom should have already printed out error messages. Exit to
	 * firmware.
	 */
	prom_exit_to_mon();
	/*NOTREACHED*/
}

void
do_shutdown(void)
{
	proc_t *initpp;

	/*
	 * If we're still booting and init(1) isn't set up yet, simply halt.
	 */
	mutex_enter(&pidlock);
	initpp = prfind(P_INITPID);
	mutex_exit(&pidlock);
	if (initpp == NULL) {
		extern void halt(char *);
		prom_power_off();
		halt("Power off the System");	/* just in case */
	}

	/*
	 * else, graceful shutdown with inittab and all getting involved
	 */
	psignal(initpp, SIGPWR);
}
