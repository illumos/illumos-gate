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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/cpu_sgnblk_defs.h>
#include <vm/seg.h>
#include <sys/iommu.h>
#include <sys/vtrace.h>
#include <sys/intreg.h>
#include <sys/ivintr.h>
#include <sys/cpuvar.h>
#include <sys/systm.h>
#include <sys/machsystm.h>
#include <sys/cyclic.h>
#include <sys/cpu_sgn.h>

extern	cpu_sgnblk_t *cpu_sgnblkp[NCPU];
extern struct cpu *SIGBCPU;
extern	void power_down(const char *);

uint_t bbus_intr_inum;
uint64_t bbus_poll_inum;

/*
 * Support for sgnblk polling.
 */

/* Internal function prototypes */
static void sgnblk_poll_init();
static uint_t bbus_poll(caddr_t arg1, caddr_t arg2);
static void sgnblk_poll_handler(void *unused);
#ifdef THROTTLE
static void sgnblk_poll_throttle(uint64_t interval);
#endif /* THROTTLE */

/*  Default sgnblk polling interval is every 5 seconds. */
#define	ONE_SECOND		(1000000)	/* in usecs */
#ifdef THROTTLE
#define	SGNBLK_POLL_INTERVAL	(5 * ONE_SECOND)
#define	SGNBLK_POLL_FAST	(ONE_SECOND >> 1)
#define	SGNBLK_POLL_FAST_WIN	((60 * ONE_SECOND) / \
					SGNBLK_POLL_FAST)
#else /* THROTTLE */
/*
 * Until we can find a way to throttle back to 0.5 second intervals
 * we're stuck fixed on 2.5 second intervals.
 */
#define	SGNBLK_POLL_INTERVAL	((2 * ONE_SECOND) + (ONE_SECOND >> 1))
#endif /* THROTTLE */

#define	MAX_SGNBLK_POLL_CLNT	5

void (*pollclntfunc[MAX_SGNBLK_POLL_CLNT])();
/*
 * sgnblk_mutex		Protects juggling & sgnblk_poll_refs[].
 * sgnblk_poll_mutex	Protects pollclntfunc[].
 */
kmutex_t	sgnblk_mutex;
kmutex_t	sgnblk_poll_mutex;
static uint64_t	sgnblk_poll_interval = SGNBLK_POLL_INTERVAL;
#ifdef THROTTLE
static uint64_t	sgnblk_poll_fast = SGNBLK_POLL_FAST;
static int64_t	sgnblk_poll_fast_win = SGNBLK_POLL_FAST_WIN;
#endif /* THROTTLE */
static processorid_t	sgnblk_pollcpu = -1;
/*
 * Note that the sigblock polling depends on CY_HIGH_LEVEL
 * being higher than PIL_13 since we ultimately need to
 * dispatch a PIL_13 soft handler.
 * Also, we assume one sgnblk handler for the entire system.
 * Once upon a time we had them per-cpu.  With the Cyclic stuff
 * we would have to bind our cyclic handler to a cpu and doing
 * this prevents that cpu from being offlined.  Since the Cyclic
 * subsystem could indirectly juggle us without us knowing we
 * have to assume we're running from any possible cpu and not
 * always SIGBCPU.
 */
#ifdef THROTTLE
static cyclic_id_t	sgnblk_poll_cycid = CYCLIC_NONE;
#endif /* THROTTLE */
static cyc_handler_t	sgnblk_poll_cychandler = {
	sgnblk_poll_handler,
	NULL,
	CY_HIGH_LEVEL
};
static cyc_time_t	sgnblk_poll_time;

/*
 * Anybody that references the polling (SIGBCPU) can
 * register a callback function that will be called if
 * the polling cpu is juggled, e.g. during a DR operation.
 */
#define	MAX_SGNBLK_POLL_REFS	10

struct sgnblk_poll_refs {
	void	(*callback)(cpu_sgnblk_t *sigbp, void *arg);
	void	*arg;
}	sgnblk_poll_refs[MAX_SGNBLK_POLL_REFS];

/*
 * Bootbus intr handler: Generic handler for all SSP/CBS
 * interrupt requests initiated via the hw bootbus intr
 * mechanism. This is similar to the level15
 * interrupt handling for sigb commands in the CS6400.
 * Most of these code were stolen from the sigb stuff in
 * in CS6400.
 */

extern struct cpu cpu0;

/*ARGSUSED*/
static uint_t
bbus_intr(caddr_t arg)
{
	int	cmd = 0;
	processorid_t	cpu_id = CPU->cpu_id;
	int	retflag;
	int	resp = 0;
	proc_t	*initpp;

	ASSERT(cpu_sgnblkp[cpu_id] != NULL);

	/*
	 * Check for unsolicited messages in the host's mailbox.
	 */
	retflag = cpu_sgnblkp[cpu_id]->sigb_host_mbox.flag;

	switch (retflag) {
	case CBS_TO_HOST:
		retflag = HOST_TO_CBS;
		break;
	default:
		retflag = SIGB_MBOX_EMPTY;
		break;
	}
	if (retflag == SIGB_MBOX_EMPTY)
		return (0);	/* interrupt not claimed */

	/*
	 * We only look for UNSOLICITED messages, i.e. commands.
	 * Responses to these commands are returned into the same
	 * mailbox from which the command was received, i.e. host's.
	 *
	 * If the host should solicit a message from the SSP, that
	 * message/command goes into the SSP's mailbox (sigb_ssp_mbox).
	 * The responses (from the SSP) to these messages will be
	 * read from the ssp mailbox by whomever solicited it, but
	 * will NOT be handled through this level 15 interrupt
	 * mechanism.
	 *
	 * Note that use of the flag field of the signature block mailbox
	 * structure and the mailbox protocol itself, serializes access
	 * to these mailboxes.
	 */

	resp = 0;

	/*
	 * The first sizeof (uint_t) bytes of the data field
	 * is the command.
	 */
	cmd = cpu_sgnblkp[cpu_id]->sigb_host_mbox.cmd;

	switch (cmd) {
		case SSP_GOTO_OBP:
		/*
		 * Let's set the mailbox flag to BUSY while we are in OBP
		 */
		cpu_sgnblkp[cpu_id]->sigb_host_mbox.flag = SIGB_MBOX_BUSY;

		debug_enter("SSP requested (SSP_GOTO_OBP)");
		/*
		 * This command does NOT require a response.
		 */
		resp = 0;
		break;

		case SSP_GOTO_PANIC:
		/*
		 * Let's reset the mailbox flag before we bail.
		 */
		cpu_sgnblkp[cpu_id]->sigb_host_mbox.flag = SIGB_MBOX_EMPTY;

		cmn_err(CE_PANIC, "SSP requested (SSP_GOTO_PANIC)\n");
		/* should never reach this point */

		resp = 0;
		break;
		case SSP_ENVIRON:
		/*
		 * Environmental Interrupt.
		 */

		/*
		 * Send SIGPWR to init(1) it will run rc0, which will uadmin to
		 * powerdown.
		 */

		mutex_enter(&pidlock);
		initpp = prfind(P_INITPID);
		mutex_exit(&pidlock);

		/*
		 * If we're still booting and init(1) isn't set up yet,
		 * simply halt.
		 */
		if (initpp == NULL) {
			extern void halt(char *);
			cmn_err(CE_WARN, "?Environmental Interrupt");
			power_down((char *)NULL);
			halt("Power off the System!\n"); /* just in case */
		}

		/*
		 * else, graceful shutdown with inittab and all getting involved
		 *
		 * XXX: Do we Need to modify the init process for the Cray 6400!
		 */
		psignal(initpp, SIGPWR);

		/*
		 * XXX: kick off a sanity timeout panic in case the /etc/inittab
		 * or /etc/rc0 files are hosed.  The 6400 needs to hang here
		 * when we return from psignal.
		 *
		 * cmn_err(CE_PANIC, "SSP requested (SSP_ENVIRON)\n");
		 * should never reach this point
		 */

		resp = 0;
		break;
		/*
		 * Could handle more mailbox commands right here.
		 */

		default:
		resp = SIGB_BAD_MBOX_CMD;
		break;
	}

	/*
	 * If resp is non-zero then we'll automatically reset
	 * the handler_sigb lock once we've sent the response,
	 * however if no response is needed, then resetlck must
	 * be set so that the handler_sigb lock is reset.
	 */
	if (resp != 0) {
		/*
		 * Had some kind of trouble handling the mailbox
		 * command.  Need to send back an error response
		 * and back out of the cpu_sgnblk handling.
		 */
		cpu_sgnblkp[cpu_id]->sigb_host_mbox.cmd = resp;
		bcopy((caddr_t)&cmd,
			(caddr_t)&cpu_sgnblkp[cpu_id]->sigb_host_mbox.data[0],
			sizeof (cmd));
		cpu_sgnblkp[cpu_id]->sigb_host_mbox.flag = retflag;
	} else {
		/*
		 * No response expected, but we still have to
		 * reset the flag to empty for the next person.
		 */
		cpu_sgnblkp[cpu_id]->sigb_host_mbox.flag = SIGB_MBOX_EMPTY;
	}
	return (1);	/* interrupt claimed */
}

void
register_bbus_intr()
{
	/*
	 * Starfire's ASIC have the capability to generate a mondo
	 * vector. The SSP uses this capability via the Boot Bus to
	 * send an interrupt to a domain.
	 *
	 * The SSP generates a mondo with:
	 *	ign = UPAID_TO_IGN(bootcpu_upaid)
	 *	ino = 0
	 *
	 * An interrupt handler is added for this inum.
	 */
	bbus_intr_inum = UPAID_TO_IGN(cpu0.cpu_id) * MAX_INO;
	VERIFY(add_ivintr(bbus_intr_inum, PIL_13, (intrfunc)bbus_intr,
	    NULL, NULL, NULL) == 0);


	/*
	 * Due to a HW flaw in starfire, liberal use
	 * of bootbus intrs under heavy system load
	 * may cause the machine to arbstop. The workaround
	 * is to provide a polling mechanism thru the signature
	 * block interface to allow another way for the SSP to
	 * interrupt the host. Applications like IDN which generate
	 * a high degree of SSP to host interruptions for
	 * synchronization will need to use the polling facility
	 * instead of the hw bootbus interrupt mechanism.
	 * The HW bootbus intr support is left intact as it
	 * will still be used by existing SSP applications for system
	 * recovery in the event of system hangs etc.. In such situations,
	 * HW bootbus intr is a better mechanism as it is HW generated
	 * level 15 interrupt that has a better chance of kicking
	 * a otherwise hung OS into recovery.
	 *
	 * Polling is done by scheduling a constant tick timer
	 * interrupt at a certain predefined interval.
	 * The handler will do a poll and if there is a
	 * "intr" request, scheduled a soft level 13 intr
	 * to handle it. Allocate the inum for the level
	 * 13 intr here.
	 */
	bbus_poll_inum = add_softintr(PIL_13, bbus_poll, 0, SOFTINT_ST);
}

static void
sgnblk_poll_init()
{
	ASSERT(MUTEX_HELD(&sgnblk_mutex));

	mutex_init(&sgnblk_poll_mutex, NULL,
			MUTEX_SPIN, (void *)ipltospl(PIL_14));
	sgnblk_pollcpu = SIGBCPU->cpu_id;
	mutex_enter(&cpu_lock);
	sgnblk_poll_time.cyt_when = 0ull;
	sgnblk_poll_time.cyt_interval = sgnblk_poll_interval * 1000ull;
#ifdef THROTTLE
	sgnblk_poll_cycid = cyclic_add(&sgnblk_poll_cychandler,
					&sgnblk_poll_time);
#else /* THROTTLE */
	(void) cyclic_add(&sgnblk_poll_cychandler, &sgnblk_poll_time);
#endif /* THROTTLE */
	mutex_exit(&cpu_lock);
	ASSERT(sgnblk_pollcpu == SIGBCPU->cpu_id);
}

int
sgnblk_poll_register(void(*func)(processorid_t cpu_id,
				cpu_sgnblk_t *cpu_sgnblkp))
{
	int i;

	/*
	 * See if we need to initialize
	 * sgnblk polling
	 */
	mutex_enter(&sgnblk_mutex);
	if (sgnblk_pollcpu == -1)
		sgnblk_poll_init();
	mutex_exit(&sgnblk_mutex);

	mutex_enter(&sgnblk_poll_mutex);

	/*
	 * Look for a empty slot
	 */
	for (i = 0; i < MAX_SGNBLK_POLL_CLNT; i++) {
		if (pollclntfunc[i] == NULL) {
			pollclntfunc[i] = func;
			mutex_exit(&sgnblk_poll_mutex);
			return (1);
		}
	}
	mutex_exit(&sgnblk_poll_mutex);
	return (0);	/* failed */
}

int
sgnblk_poll_unregister(void(*func)(processorid_t cpu_id,
				cpu_sgnblk_t *cpu_sgnblkp))
{
	int i;

	mutex_enter(&sgnblk_poll_mutex);

	/*
	 * Look for the slot matching the function passed in.
	 */
	for (i = 0; i < MAX_SGNBLK_POLL_CLNT; i++) {
		if (pollclntfunc[i] == func) {
			pollclntfunc[i] = NULL;
			mutex_exit(&sgnblk_poll_mutex);
			return (1);
		}
	}
	mutex_exit(&sgnblk_poll_mutex);
	return (0);	/* failed */
}


/*
 * For DR support.
 * Juggle poll tick client to another cpu
 * Assumed to be called single threaded.
 */
void
juggle_sgnblk_poll(struct cpu *cp)
{
	int		i;

	mutex_enter(&sgnblk_mutex);

	if (sgnblk_pollcpu == -1 ||
	    (cp != NULL && sgnblk_pollcpu == cp->cpu_id)) {
		mutex_exit(&sgnblk_mutex);
		return;
	}

	/*
	 * Disable by simply returning here
	 * Passing a null cp is assumed to be
	 * sgnpoll disable request.
	 */
	if (cp == NULL) {
		for (i = 0; i < MAX_SGNBLK_POLL_REFS; i++) {
			void	(*func)(), *arg;

			if ((func = sgnblk_poll_refs[i].callback) != NULL) {
				arg = sgnblk_poll_refs[i].arg;
				(*func)(NULL, arg);
			}
		}
		mutex_exit(&sgnblk_mutex);
		return;
	}

	sgnblk_pollcpu = cp->cpu_id;

	for (i = 0; i < MAX_SGNBLK_POLL_REFS; i++) {
		void	(*func)(), *arg;

		if ((func = sgnblk_poll_refs[i].callback) != NULL) {
			arg = sgnblk_poll_refs[i].arg;
			(*func)(cpu_sgnblkp[sgnblk_pollcpu], arg);
		}
	}

	mutex_exit(&sgnblk_mutex);
}

#ifdef THROTTLE
/*ARGSUSED0*/
static void
_sgnblk_poll_throttle(void *unused)
{
	mutex_enter(&cpu_lock);
	if (sgnblk_poll_cycid != CYCLIC_NONE) {
		cyclic_remove(sgnblk_poll_cycid);
		sgnblk_poll_cycid = CYCLIC_NONE;
	}

	if (sgnblk_poll_time.cyt_interval > 0ull)
		sgnblk_poll_cycid = cyclic_add(&sgnblk_poll_cychandler,
						&sgnblk_poll_time);
	mutex_exit(&cpu_lock);
}

/*
 * We don't want to remove the cyclic within the context of
 * the handler so we kick off the throttle in background
 * via a timeout call.
 */
static void
sgnblk_poll_throttle(uint64_t new_interval)
{
	mutex_enter(&cpu_lock);
	sgnblk_poll_time.cyt_when = 0ull;
	sgnblk_poll_time.cyt_interval = new_interval * 1000ull;
	mutex_exit(&cpu_lock);

	(void) timeout(_sgnblk_poll_throttle, NULL, (clock_t)0);
}
#endif /* THROTTLE */

/*
 * High priority interrupt handler (PIL_14)
 * for signature block mbox polling.
 */
/*ARGSUSED0*/
static void
sgnblk_poll_handler(void *unused)
{
	processorid_t	cpuid = SIGBCPU->cpu_id;
#ifdef THROTTLE
	static int64_t	sb_window = -1;
	static uint64_t	sb_interval = 0;
#endif /* THROTTLE */

	if (cpu_sgnblkp[cpuid] == NULL)
		return;

	/*
	 * Poll for SSP requests
	 */
	if (cpu_sgnblkp[cpuid]->sigb_host_mbox.intr == SIGB_INTR_SEND) {
		/* reset the flag - sure hope this is atomic */
		cpu_sgnblkp[cpuid]->sigb_host_mbox.intr = SIGB_INTR_OFF;

#ifdef THROTTLE
		/*
		 * Go into fast poll mode for a short duration
		 * (SGNBLK_POLL_FAST_WIN) in SGNBLK_POLL_FAST interval.
		 * The assumption here is that we just got activity
		 * on the mbox poll, the probability of more coming down
		 * the pipe is high - so let's look more often.
		 */
		if ((sb_window < 0) && (sb_interval > sgnblk_poll_fast)) {
			sb_interval = sgnblk_poll_fast;
			sgnblk_poll_throttle(sb_interval);
		}
		sb_window = sgnblk_poll_fast_win;
#endif /* THROTTLE */

		/* schedule poll processing */
		setsoftint(bbus_poll_inum);

#ifdef THROTTLE
	} else if (sb_window >= 0) {
		/* Revert to slow polling once fast window ends */
		if ((--sb_window < 0) &&
		    (sb_interval < sgnblk_poll_interval)) {
			sb_interval = sgnblk_poll_interval;
			sgnblk_poll_throttle(sb_interval);
		}
#endif /* THROTTLE */
	}
}

/*ARGSUSED*/
static uint_t
bbus_poll(caddr_t arg1, caddr_t arg2)
{
	int i;
	processorid_t cpu_id = SIGBCPU->cpu_id;
	cpu_sgnblk_t *sgnblkp = cpu_sgnblkp[cpu_id];

	/*
	 * Go thru the poll client array and call the
	 * poll client functions one by one
	 */
	mutex_enter(&sgnblk_poll_mutex);

	for (i = 0; i < MAX_SGNBLK_POLL_CLNT; i++) {
		void (*func)(processorid_t cpuid, cpu_sgnblk_t *sgnblkp);

		if ((func = pollclntfunc[i]) != NULL) {
			mutex_exit(&sgnblk_poll_mutex);
			(*func)(cpu_id, sgnblkp);
			mutex_enter(&sgnblk_poll_mutex);
		}
	}
	mutex_exit(&sgnblk_poll_mutex);

	return (1);
}

int
sgnblk_poll_reference(void (*callback)(cpu_sgnblk_t *sigb, void *arg),
	void *arg)
{
	int		i, slot;
	cpu_sgnblk_t	*sigbp;

	if (callback == NULL)
		return (-1);

	mutex_enter(&sgnblk_mutex);
	/*
	 * First verify caller is not already registered.
	 */
	slot = -1;
	for (i = 0; i < MAX_SGNBLK_POLL_REFS; i++) {
		if ((slot == -1) && (sgnblk_poll_refs[i].callback == NULL)) {
			slot = i;
			continue;
		}
		if (sgnblk_poll_refs[i].callback == callback) {
			mutex_exit(&sgnblk_mutex);
			return (-1);
		}
	}
	/*
	 * Now find an empty entry.
	 */
	if (slot == -1) {
		mutex_exit(&sgnblk_mutex);
		return (-1);
	}
	sgnblk_poll_refs[slot].callback = callback;
	sgnblk_poll_refs[slot].arg = arg;

	sigbp = (sgnblk_pollcpu != -1) ? cpu_sgnblkp[sgnblk_pollcpu] : NULL;

	(*callback)(sigbp, arg);

	mutex_exit(&sgnblk_mutex);

	return (0);
}

void
sgnblk_poll_unreference(void (*callback)(cpu_sgnblk_t *sigb, void *arg))
{
	int	i;

	mutex_enter(&sgnblk_mutex);
	for (i = 0; i < MAX_SGNBLK_POLL_REFS; i++) {
		if (sgnblk_poll_refs[i].callback == callback) {
			void	*arg;

			arg = sgnblk_poll_refs[i].arg;
			(*callback)(NULL, arg);
			sgnblk_poll_refs[i].callback = NULL;
			sgnblk_poll_refs[i].arg = NULL;
			break;
		}
	}
	mutex_exit(&sgnblk_mutex);
}
