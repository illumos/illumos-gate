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

/*
 * ntwdt driver
 * ------------
 *
 * Subsystem Overview
 * ------------------
 *
 * This is a pseudo driver for the Netra-1280 watchdog
 * timer (WDT).  It provides for an *application-driven*
 * WDT (AWDT), not a traditional, hardware-based WDT.  A
 * hardware-based feature is already present on the
 * Netra-1280, and it is referred to here as the
 * System WDT (SWDT).
 *
 * ScApp and Solaris cooperate to provide either a SWDT or
 * an AWDT; they are mutually-exclusive.  Once in AWDT
 * mode, one can only transition to SWDT mode via a reboot.
 * This obviously gives priority to the AWDT and was done
 * to handle scenarios where the customer might temporarily
 * terminate their wdog-app in order to do some debugging,
 * or even to load a new version of the wdog-app.
 *
 * The wdog-app does an open() of the /dev/ntwdt device node
 * and then issues ioctl's to control the state of the AWDT.
 * The ioctl's are implemented by this driver.  Only one
 * concurrent instance of open() is allowed.  On the close(),
 * a watchdog timer still in progress is NOT terminated.
 * This allows the global state machine to monitor the
 * progress of a Solaris reboot.  ScApp will reset Solaris
 * (eg, send an XIR) if the actual boot/crashdump latency
 * is larger than the current AWDT timeout.
 *
 * The rationale for implementing an AWDT (vs a SWDT) is
 * that it is more sensitive to system outage scenarios than
 * a SWDT.  Eg, a system could be in such a failed state that
 * even though its clock-interrupt could still run (and the
 * SWDT's watchdog timer therefore re-armed), the system could
 * in effect have a corrupt or very poor dispatch latency.
 * An AWDT would be sensitive to dispatch latency issues, as
 * well as problems with its own execution (eg, a hang or
 * crash).
 *
 * Subsystem Interface Overview
 * ----------------------------
 *
 * This pseudo-driver does not have any 'extern' functions.
 *
 * All system interaction is done via the traditional driver
 * entry points (eg, attach(9e), _init(9e)).
 *
 * All interaction with user is via the entry points in the
 * 'struct cb_ops' vector (eg, open(9e), ioctl(9e), and
 * close(9e)).
 *
 * Subsystem Implementation Overview
 * ---------------------------------
 *
 * ScApp and Solaris (eg, ntwdt) cooperate so that a state
 * machine global to ScApp and ntwdt is either in AWDT mode
 * or in SWDT mode.  These two peers communicate via the SBBC
 * Mailbox that resides in IOSRAM (SBBC_MAILBOX_KEY).
 * They use two new mailbox messages (LW8_MBOX_WDT_GET and
 * LW8_MBOX_WDT_SET) and one new event (LW8_EVENT_SC_RESTARTED).
 *
 * ntwdt implements the AWDT by implementing a "virtual
 * WDT" (VWDT).  Eg, the watchdog timer is not a traditional
 * counter in hardware, it is a variable in ntwdt's
 * softstate.  The wdog-app's actions cause changes to this
 * and other variables in ntwdt's softstate.
 *
 * The wdog-app uses the LOMIOCDOGTIME ioctl to specify
 * the number of seconds in the watchdog timeout (and
 * therefore the VWDT).  The wdog-app then uses the
 * LOMIOCDOGCTL ioctl to enable the wdog.  This causes
 * ntwdt to create a Cyclic that will both decrement
 * the VWDT and check to see if it has expired.  To keep
 * the VWDT from expiring, the wdog-app uses the
 * LOMIOCDOGPAT ioctl to re-arm (or "pat") the watchdog.
 * This sets the VWDT value to that specified in the
 * last LOMIOCDOGTIME ioctl.  The wdog-app can use the
 * LOMIOCDOGSTATE ioctl to query the state of the VWDT.
 *
 * The wdog-app can also specify how Recovery is to be
 * done.  The only choice is whether to do a crashdump
 * or not.  If ntwdt computes a VWDT expiration, then
 * ntwdt initiates the Recovery, else ScApp will.  Eg,
 * a hang in Solaris will be sensed by ScApp and not
 * ntwdt.  The wdog-app specifies the Recovery policy
 * via the DOGCTL ioctl.
 *
 *   Timeout Expiration
 *   ------------------
 *   In our implementation, ScApp senses a watchdog
 *   expiration the same way it historically has:
 *   by reading a well-known area of IOSRAM (SBBC_TOD_KEY)
 *   to see if the timestamp associated with a
 *   Solaris-generated "heartbeat" field is older
 *   than the currently specified timeout (which is
 *   also specified in this same IOSRAM section).
 *
 *   What is different when ntwdt is running is that
 *   ntwdt is responsible for updating the Heartbeat,
 *   and not the normal client (todsg).  When ntwdt
 *   puts the system in AWDT mode, it disables todsg's
 *   updating of the Heartbeat by changing the state of
 *   a pair of kernel tunables (watchdog_activated and
 *   watchdog_enable).  ntwdt then takes responsibility
 *   for updating the Heartbeat.  It does this by
 *   updating the Heartbeat from the Cyclic that is
 *   created when the user enables the AWDT (DOGCTL)
 *   or specifies a new timeout value (DOGTIME).
 *
 *   As long as the AWDT is enabled, ntwdt will update
 *   the real system Heartbeat.  As a result, ScApp
 *   will conclude that Solaris is still running.  If
 *   the user stops re-arming the VWDT or Solaris
 *   hangs (eg), ntwdt will stop updating the Heartbeat.
 *
 *   Note that ntwdt computes expiration via the
 *   repeatedly firing Cyclic, and ScApp computes
 *   expiration via a cessation of Heartbeat update.
 *   Since Heartbeat update stops once user stops
 *   re-arming the VWDT (ie, DOGPAT ioctl), ntwdt
 *   will compute a timeout at t(x), and ScApp will
 *   compute a timeout at t(2x), where 'x' is the
 *   current timeout value.  When ntwdt computes
 *   the expiration, ntwdt masks this asymmetry.
 *
 *   Lifecycle Events
 *   ----------------
 *
 *   ntwdt only handles one of the coarse-grained
 *   "lifecycle events" (eg, entering OBP, shutdown,
 *   power-down, DR) that are possible during a Solaris
 *   session: a panic.  (Note that ScApp handles one
 *   of the others: "entering OBP").  Other than these,
 *   a user choosing such a state transition must first
 *   use the wdog-app to disable the watchdog, else
 *   an expiration could occur.
 *
 *   Solaris handles a panic by registering a handler
 *   that's called during the panic.  The handler will
 *   set the watchdog timeout to the value specified
 *   in the NTWDT_BOOT_TIMEOUT_PROP driver Property.
 *   Again, this value should be greater than the actual
 *   Solaris reboot/crashdump latency.
 *
 *   When the user enters OBP via the System Controller,
 *   ScApp will disable the watchdog (from ScApp's
 *   perspective), but it will not communicate this to
 *   ntwdt.  After having exited OBP, the wdog-app can
 *   be used to enable or disable the watchdog (which
 *   will get both ScApp and ntwdt in-sync).
 *
 *   Locking
 *   -------
 *
 *   ntwdt has code running at three interrupt levels as
 *   well as base level.
 *
 *   The ioctls run at base level in User Context.  The
 *   driver's entry points run at base level in Kernel
 *   Context.
 *
 *   ntwdt's three interrupt levels are used by:
 *
 *    o LOCK_LEVEL :
 *        the Cyclic used to manage the VWDT is initialized
 *        to CY_LOCK_LEVEL
 *
 *    o DDI_SOFTINT_MED :
 *        the SBBC mailbox implementation registers the
 *        specified handlers at this level
 *
 *    o DDI_SOFTINT_LOW :
 *        this level is used by two handlers.  One handler
 *        is triggered by the LOCK_LEVEL Cyclic.  The other
 *        handler is triggered by the DDI_SOFTINT_MED
 *        handler registered to handle SBBC mailbox events.
 *
 *   The centralizing concept is that the ntwdt_wdog_mutex
 *   in the driver's softstate is initialized to have an
 *   interrupt-block-cookie corresponding to DDI_SOFTINT_LOW.
 *
 *   As a result, any base level code grabs ntwdt_wdog_mutex
 *   before doing work.  Also, any handler running at interrupt
 *   level higher than DDI_SOFTINT_LOW "posts down" so that
 *   a DDI_SOFTINT_LOW handler is responsible for executing
 *   the "real work".  Each DDI_SOFTINT_LOW handler also
 *   first grabs ntwdt_wdog_mutex, and so base level is
 *   synchronized with all interrupt levels.
 *
 *   Note there's another mutex in the softstate: ntwdt_mutex.
 *   This mutex has few responsibilities.  However, this
 *   locking order must be followed: ntwdt_wdog_mutex is
 *   held first, and then ntwdt_mutex.  This choice results
 *   from the fact that the number of dynamic call sites
 *   for ntwdt_wdog_mutex is MUCH greater than that of
 *   ntwdt_mutex.  As a result, almost all uses of
 *   ntwdt_wdog_mutex do not even require ntwdt_mutex to
 *   be held, which saves resources.
 *
 *   Driver Properties
 *   -----------------
 *
 *   "ddi-forceattach=1;"
 *    ------------------
 *
 *    Using this allows our driver to be automatically
 *    loaded at boot-time AND to not be removed from memory
 *    solely due to memory-pressure.
 *
 *    Being loaded at boot allows ntwdt to (as soon as
 *    possible) tell ScApp of the current mode of the
 *    state-machine (eg, SWDT).  This is needed for the case
 *    when Solaris is re-loaded while in AWDT mode; having
 *    Solaris communicate ASAP with ScApp reduces the duration
 *    of any "split-brain" scenario where ScApp and Solaris
 *    are not in the same mode.
 *
 *    Having ntwdt remain in memory even after a close()
 *    allows ntwdt to answer any SBBC mailbox commands
 *    that ScApp sends (as the mailbox infrastructure is
 *    not torn down until ntwdt is detach()'d).  Specifically,
 *    ScApp could be re-loaded after AWDT mode had been
 *    entered and the wdog-app had close()'d ntwdt.  ScApp
 *    will then eventually send a LW8_EVENT_SC_RESTARTED
 *    mailbox event in order to learn the current state of
 *    state-machine.  Having ntwdt remain loaded allows this
 *    event to never go unanswered.
 *
 *   "ntwdt-boottimeout=600;"
 *    ----------------------
 *
 *    This specifies the watchdog timeout value (in seconds) to
 *    use when ntwdt is aware of the need to reboot/reload Solaris.
 *
 *    ntwdt will update ScApp by setting the watchdog timeout
 *    to the specified number of seconds when either a) Solaris
 *    panics or b) the VWDT expires.  Note that this is only done
 *    if the user has chosen to enable Reset.
 *
 *    ntwdt boundary-checks the specified value, and if out-of-range,
 *    it initializes the watchdog timeout to a default value of
 *    NTWDT_DEFAULT_BOOT_TIMEOUT seconds.  Note that this is a
 *    default value and is not a *minimum* value.  The valid range
 *    for the watchdog timeout is between one second and
 *    NTWDT_MAX_TIMEOUT seconds, inclusive.
 *
 *    If ntwdt-boottimeout is set to a value less than an actual
 *    Solaris boot's latency, ScApp will reset Solaris during boot.
 *    Note that a continuous series of ScApp-induced resets will
 *    not occur; ScApp only resets Solaris on the first transition
 *    into the watchdog-expired state.
 */

#include <sys/note.h>
#include <sys/types.h>
#include <sys/callb.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/ddi_impldefs.h>
#include <sys/kmem.h>
#include <sys/devops.h>
#include <sys/cyclic.h>
#include <sys/uadmin.h>
#include <sys/lw8_impl.h>
#include <sys/sgsbbc.h>
#include <sys/sgsbbc_iosram.h>
#include <sys/sgsbbc_mailbox.h>
#include <sys/todsg.h>
#include <sys/mem_config.h>
#include <sys/lom_io.h>
#include <sys/reboot.h>
#include <sys/clock.h>


/*
 * tunables
 */
int ntwdt_disable_timeout_action = 0;
#ifdef DEBUG
/*
 * tunable to simulate a Solaris hang. If is non-zero, then
 * no system heartbeats ("hardware patting") will be done,
 * even though all AWDT machinery is functioning OK.
 */
int ntwdt_stop_heart;
#endif

/*
 * Driver Property
 */
#define	NTWDT_BOOT_TIMEOUT_PROP	"ntwdt-boottimeout"

/*
 * watchdog-timeout values (in seconds):
 *
 * NTWDT_DEFAULT_BOOT_TIMEOUT: the default value used if
 *                             this driver is aware of the
 *                             reboot.
 *
 * NTWDT_MAX_TIMEOUT:  max value settable by app (via the
 *                     LOMIOCDOGTIME ioctl)
 */
#define	NTWDT_DEFAULT_BOOT_TIMEOUT	(10*60)
#define	NTWDT_MAX_TIMEOUT		(180*60)


#define	NTWDT_CYCLIC_CHK_PERCENT	(20)
#define	NTWDT_MINOR_NODE	"awdt"
#define	OFFSET(base, field)	((char *)&base.field - (char *)&base)

#define	NTWDT_SUCCESS	0
#define	NTWDT_FAILURE	1

typedef struct {
	callb_id_t	ntwdt_panic_cb;
} ntwdt_callback_ids_t;
static ntwdt_callback_ids_t ntwdt_callback_ids;

/* MBOX_EVENT_LW8 that is sent in IOSRAM Mailbox: */
static lw8_event_t	lw8_event;		/* payload */
static sbbc_msg_t	sbbc_msg;		/* message */

static ddi_softintr_t	ntwdt_mbox_softint_id;
static ddi_softintr_t	ntwdt_cyclic_softint_id;

/*
 * VWDT (i.e., Virtual Watchdog Timer) state
 */
typedef struct {
	kmutex_t		ntwdt_wdog_mutex;
	ddi_iblock_cookie_t	ntwdt_wdog_mtx_cookie;
	int			ntwdt_wdog_enabled;	/* wdog enabled ? */
	int			ntwdt_reset_enabled;	/* reset enabled ? */
	int			ntwdt_timer_running;	/* wdog running ? */
	int			ntwdt_wdog_expired;	/* wdog expired ? */
	int			ntwdt_is_initial_enable; /* 1st wdog-enable? */
	uint32_t		ntwdt_boot_timeout;	/* timeout for boot */
	uint32_t		ntwdt_secs_remaining;	/* expiration timer */
	uint8_t			ntwdt_wdog_action;	/* Reset action */
	uint32_t		ntwdt_wdog_timeout;	/* timeout in seconds */
	hrtime_t		ntwdt_cyclic_interval;	/* cyclic interval */
	cyc_handler_t		ntwdt_cycl_hdlr;
	cyc_time_t		ntwdt_cycl_time;
	kmutex_t		ntwdt_event_lock;	/* lock */
	uint64_t		ntwdt_wdog_flags;
} ntwdt_wdog_t;

/* ntwdt_wdog_flags */
#define	NTWDT_FLAG_SKIP_CYCLIC		0x1	/* skip next Cyclic */

/* macros to set/clear one bit in ntwdt_wdog_flags */
#define	NTWDT_FLAG_SET(p, f)\
	((p)->ntwdt_wdog_flags |= NTWDT_FLAG_##f)
#define	NTWDT_FLAG_CLR(p, f)\
	((p)->ntwdt_wdog_flags &= ~NTWDT_FLAG_##f)


/* softstate */
typedef struct {
	kmutex_t		ntwdt_mutex;
	dev_info_t		*ntwdt_dip;		/* dip */
	int			ntwdt_open_flag;	/* file open ? */
	ntwdt_wdog_t		*ntwdt_wdog_state;	/* wdog state */
	cyclic_id_t		ntwdt_cycl_id;
} ntwdt_state_t;

static	void		*ntwdt_statep;	/* softstate */
static	dev_info_t	*ntwdt_dip;
/*
 * if non-zero, then the app-wdog feature is available on
 * this system configuration.
 */
static	int	ntwdt_watchdog_available;
/*
 * if non-zero, then application has used the LOMIOCDOGCTL
 * ioctl at least once in order to Enable the app-wdog.
 * Also, if this is non-zero, then system is in AWDT mode,
 * else it is in SWDT mode.
 */
static	int	ntwdt_watchdog_activated;

#define	getstate(minor)	\
	((ntwdt_state_t *)ddi_get_soft_state(ntwdt_statep, (minor)))

static int	ntwdt_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int	ntwdt_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int	ntwdt_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		    void **result);
static int	ntwdt_open(dev_t *, int, int, cred_t *);
static int	ntwdt_close(dev_t, int, int, cred_t *);
static int	ntwdt_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static void	ntwdt_reprogram_wd(ntwdt_state_t *);
static boolean_t	ntwdt_panic_cb(void *arg, int code);
static void	ntwdt_start_timer(ntwdt_state_t *);
static void	ntwdt_stop_timer(void *);
static void	ntwdt_stop_timer_lock(void *arg);
static void	ntwdt_add_callbacks(ntwdt_state_t *ntwdt_ptr);
static void	ntwdt_remove_callbacks();
static void	ntwdt_cyclic_pat(void *arg);
static void	ntwdt_enforce_timeout();
static void	ntwdt_pat_hw_watchdog();
static int	ntwdt_set_cfgvar(int var, int val);
static void	ntwdt_set_cfgvar_noreply(int var, int val);
static int	ntwdt_read_props(ntwdt_state_t *);
static int	ntwdt_add_mbox_handlers(ntwdt_state_t *);
static int	ntwdt_set_hw_timeout(uint32_t period);
static int	ntwdt_remove_mbox_handlers(void);
static uint_t	ntwdt_event_data_handler(char *arg);
static uint_t	ntwdt_mbox_softint(char *arg);
static uint_t	ntwdt_cyclic_softint(char *arg);
static int	ntwdt_lomcmd(int cmd, intptr_t arg);
static int	ntwdt_chk_wdog_support();
static int	ntwdt_chk_sc_support();
static int	ntwdt_set_swdt_state();
static void	ntwdt_swdt_to_awdt(ntwdt_wdog_t *);
static void	ntwdt_arm_vwdt(ntwdt_wdog_t *wdog_state);
#ifdef DEBUG
static int	ntwdt_get_cfgvar(int var, int *val);
#endif

struct cb_ops ntwdt_cb_ops = {
	ntwdt_open,	/* open  */
	ntwdt_close,	/* close */
	nulldev,	/* strategy */
	nulldev,	/* print */
	nulldev,	/* dump */
	nulldev,	/* read */
	nulldev,	/* write */
	ntwdt_ioctl,	/* ioctl */
	nulldev,	/* devmap */
	nulldev,	/* mmap */
	nulldev,	/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,	/* cb_prop_op */
	NULL,		/* streamtab  */
	D_MP | D_NEW
};

static struct dev_ops ntwdt_ops = {
	DEVO_REV,		/* Devo_rev */
	0,			/* Refcnt */
	ntwdt_info,		/* Info */
	nulldev,		/* Identify */
	nulldev,		/* Probe */
	ntwdt_attach,		/* Attach */
	ntwdt_detach,		/* Detach */
	nodev,			/* Reset */
	&ntwdt_cb_ops,		/* Driver operations */
	0,			/* Bus operations */
	NULL			/* Power */
};

static struct modldrv modldrv = {
	&mod_driverops,			/* This one is a driver */
	"ntwdt-Netra-T12",		/* Name of the module. */
	&ntwdt_ops,			/* Driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};


/*
 * Flags to set in ntwdt_debug.
 *
 * Use either the NTWDT_DBG or NTWDT_NDBG macros
 */
#define	WDT_DBG_ENTRY	0x00000001	/* drv entry points */
#define	WDT_DBG_HEART	0x00000002	/* system heartbeat */
#define	WDT_DBG_VWDT	0x00000004	/* virtual WDT */
#define	WDT_DBG_EVENT	0x00000010	/* SBBC Mbox events */
#define	WDT_DBG_PROT	0x00000020	/* SC/Solaris protocol */
#define	WDT_DBG_IOCTL	0x00000040	/* ioctl's */

uint64_t ntwdt_debug;	/* enables tracing of module's activity */

/* used in non-debug version of module */
#define	NTWDT_NDBG(flag, msg)	{ if ((ntwdt_debug & (flag)) != 0) \
	(void) printf msg; }

#ifdef DEBUG
typedef struct {
	uint32_t	ntwdt_wd1;
	uint8_t		ntwdt_wd2;
} ntwdt_data_t;

#define	NTWDTIOCSTATE	_IOWR('a', 0xa, ntwdt_data_t)
#define	NTWDTIOCPANIC	_IOR('a',  0xb, uint32_t)

/* used in debug version of module */
#define	NTWDT_DBG(flag, msg)	{ if ((ntwdt_debug & (flag)) != 0) \
	(void) printf msg; }
#else
#define	NTWDT_DBG(flag, msg)
#endif


int
_init(void)
{
	int error = 0;

	NTWDT_DBG(WDT_DBG_ENTRY, ("_init"));

	/* Initialize the soft state structures */
	if ((error = ddi_soft_state_init(&ntwdt_statep,
	    sizeof (ntwdt_state_t), 1)) != 0) {
		return (error);
	}

	/* Install the loadable module */
	if ((error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&ntwdt_statep);
	}
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	NTWDT_DBG(WDT_DBG_ENTRY, ("_info"));

	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int error;

	NTWDT_DBG(WDT_DBG_ENTRY, ("_fini"));

	error = mod_remove(&modlinkage);
	if (error == 0) {
		ddi_soft_state_fini(&ntwdt_statep);
	}

	return (error);
}

static int
ntwdt_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance;
	ntwdt_state_t		*ntwdt_ptr = NULL;
	ntwdt_wdog_t		*wdog_state = NULL;
	cyc_handler_t		*hdlr = NULL;

	NTWDT_DBG(WDT_DBG_ENTRY, ("attach: dip/cmd: 0x%p/%d",
	    (void *)dip, cmd));

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/* see if app-wdog is supported on our config */
	if (ntwdt_chk_wdog_support() != 0)
		return (DDI_FAILURE);

	/* (unsolicitedly) send SWDT state to ScApp via mailbox */
	(void) ntwdt_set_swdt_state();

	instance = ddi_get_instance(dip);
	ASSERT(instance == 0);

	if (ddi_soft_state_zalloc(ntwdt_statep, instance)
	    != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	ntwdt_ptr = ddi_get_soft_state(ntwdt_statep, instance);
	ASSERT(ntwdt_ptr != NULL);

	ntwdt_dip = dip;

	ntwdt_ptr->ntwdt_dip = dip;
	ntwdt_ptr->ntwdt_cycl_id = CYCLIC_NONE;
	mutex_init(&ntwdt_ptr->ntwdt_mutex, NULL,
	    MUTEX_DRIVER, NULL);

	/*
	 * Initialize the watchdog structure
	 */
	ntwdt_ptr->ntwdt_wdog_state =
	    kmem_zalloc(sizeof (ntwdt_wdog_t), KM_SLEEP);
	wdog_state = ntwdt_ptr->ntwdt_wdog_state;

	/*
	 * Create an iblock-cookie so that ntwdt_wdog_mutex can be
	 * used at User Context and Interrupt Context.
	 */
	if (ddi_get_soft_iblock_cookie(dip, DDI_SOFTINT_LOW,
	    &wdog_state->ntwdt_wdog_mtx_cookie) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "init of iblock cookie failed "
		    "for ntwdt_wdog_mutex");
		goto err1;
	} else {
		mutex_init(&wdog_state->ntwdt_wdog_mutex, NULL, MUTEX_DRIVER,
		    (void *)wdog_state->ntwdt_wdog_mtx_cookie);
	}

	mutex_init(&wdog_state->ntwdt_event_lock, NULL,
	    MUTEX_DRIVER, NULL);

	/* Cyclic fires once per second: */
	wdog_state->ntwdt_cyclic_interval = NANOSEC;

	/* interpret our .conf file. */
	(void) ntwdt_read_props(ntwdt_ptr);

	/* init the Cyclic that drives the VWDT */
	hdlr = &wdog_state->ntwdt_cycl_hdlr;
	hdlr->cyh_level = CY_LOCK_LEVEL;
	hdlr->cyh_func = ntwdt_cyclic_pat;
	hdlr->cyh_arg = (void *)ntwdt_ptr;

	/* Register handler for SBBC Mailbox events */
	if (ntwdt_add_mbox_handlers(ntwdt_ptr) != DDI_SUCCESS)
		goto err2;

	/* Softint that will be triggered by Cyclic that drives VWDT */
	if (ddi_add_softintr(dip, DDI_SOFTINT_LOW, &ntwdt_cyclic_softint_id,
	    NULL, NULL, ntwdt_cyclic_softint, (caddr_t)ntwdt_ptr)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "failed to add cyclic softintr");
		goto err3;
	}

	/* Register callbacks for various system events, e.g. panic */
	ntwdt_add_callbacks(ntwdt_ptr);

	/*
	 * Create Minor Node as last activity.  This prevents
	 * application from accessing our implementation until it
	 * is initialized.
	 */
	if (ddi_create_minor_node(dip, NTWDT_MINOR_NODE, S_IFCHR, 0,
	    DDI_PSEUDO, 0) == DDI_FAILURE) {
		cmn_err(CE_WARN, "failed to create Minor Node: %s",
		    NTWDT_MINOR_NODE);
		goto err4;
	}

	/* Display our driver info in the banner */
	ddi_report_dev(dip);

	return (DDI_SUCCESS);

err4:
	ntwdt_remove_callbacks();
	ddi_remove_softintr(ntwdt_cyclic_softint_id);
err3:
	(void) ntwdt_remove_mbox_handlers();
err2:
	mutex_destroy(&wdog_state->ntwdt_event_lock);
	mutex_destroy(&wdog_state->ntwdt_wdog_mutex);
err1:
	kmem_free(wdog_state, sizeof (ntwdt_wdog_t));
	ntwdt_ptr->ntwdt_wdog_state = NULL;

	mutex_destroy(&ntwdt_ptr->ntwdt_mutex);
	ddi_soft_state_free(ntwdt_statep, instance);

	ntwdt_dip = NULL;

	return (DDI_FAILURE);
}

/*
 * Do static checks to see if the app-wdog feature is supported in
 * the current configuration.
 *
 * If the kernel debugger was booted, then we disallow the app-wdog
 * feature, as we assume the user will be interested more in
 * debuggability of system than its ability to support an app-wdog.
 * (Note that the System Watchdog (SWDT) can still be available).
 *
 * If the currently loaded version of ScApp does not understand one
 * of the IOSRAM mailbox messages that is specific to the app-wdog
 * protocol, then we disallow use of the app-wdog feature (else
 * we could have a "split-brain" scenario where Solaris supports
 * app-wdog but ScApp doesn't).
 *
 * Note that there is no *dynamic* checking of whether ScApp supports
 * the wdog protocol.  Eg, if a new version of ScApp was loaded out
 * from under Solaris, then once in AWDT mode, Solaris has no way
 * of knowing that (a possibly older version of) ScApp was loaded.
 */
static int
ntwdt_chk_wdog_support()
{
	int	retval = ENOTSUP;
	int	rv;

	if ((boothowto & RB_DEBUG) != 0) {
		cmn_err(CE_WARN, "kernel debugger was booted; "
		    "application watchdog is not available.");
		return (retval);
	}

	/*
	 * if ScApp does not support the MBOX_GET cmd, then
	 * it does not support the app-wdog feature.  Also,
	 * if there is *any* type of SBBC Mailbox error at
	 * this point, we will disable the app watchdog
	 * feature.
	 */
	if ((rv = ntwdt_chk_sc_support()) != 0) {
		if (rv == EINVAL)
			cmn_err(CE_WARN, "ScApp does not support "
			    "the application watchdog feature.");
		else
			cmn_err(CE_WARN, "SBBC mailbox had error;"
			    "application watchdog is not available.");
		retval = rv;
	} else {
		ntwdt_watchdog_available = 1;
		retval = 0;
	}

	NTWDT_DBG(WDT_DBG_PROT, ("app-wdog is %savailable",
	    (ntwdt_watchdog_available != 0) ? "" : "not "));

	return (retval);
}

/*
 * Check to see if ScApp supports the app-watchdog feature.
 *
 * Do this by sending one of the mailbox commands that is
 * specific to the app-wdog protocol.  If ScApp does not
 * return an error code, we will assume it understands it
 * (as well as the remainder of the app-wdog protocol).
 *
 * Notes:
 *  ntwdt_lomcmd() will return EINVAL if ScApp does not
 *  understand the message.  The underlying sbbc_mbox_
 *  utility function returns SG_MBOX_STATUS_ILLEGAL_PARAMETER
 *  ("illegal ioctl parameter").
 */
static int
ntwdt_chk_sc_support()
{
	lw8_get_wdt_t	get_wdt;

	return (ntwdt_lomcmd(LW8_MBOX_WDT_GET, (intptr_t)&get_wdt));
}

static int
ntwdt_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance = ddi_get_instance(dip);
	ntwdt_state_t	*ntwdt_ptr = NULL;

	NTWDT_DBG(WDT_DBG_ENTRY, ("detach: dip/cmd: 0x%p/%d",
	    (void *)dip, cmd));

	ntwdt_ptr = ddi_get_soft_state(ntwdt_statep, instance);
	if (ntwdt_ptr == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	case DDI_DETACH:
		/*
		 * release resources in opposite (LIFO) order as
		 * were allocated in attach(9f).
		 */
		ddi_remove_minor_node(dip, NULL);

		ntwdt_stop_timer_lock((void *)ntwdt_ptr);

		ntwdt_remove_callbacks();

		ddi_remove_softintr(ntwdt_cyclic_softint_id);

		(void) ntwdt_remove_mbox_handlers();

		mutex_destroy(&ntwdt_ptr->ntwdt_wdog_state->ntwdt_event_lock);
		mutex_destroy(&ntwdt_ptr->ntwdt_wdog_state->ntwdt_wdog_mutex);
		kmem_free(ntwdt_ptr->ntwdt_wdog_state,
		    sizeof (ntwdt_wdog_t));
		ntwdt_ptr->ntwdt_wdog_state = NULL;

		mutex_destroy(&ntwdt_ptr->ntwdt_mutex);

		ddi_soft_state_free(ntwdt_statep, instance);

		ntwdt_dip = NULL;
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*
 * Register the SBBC Mailbox handlers.
 *
 * Currently, only one handler is used.  It processes the MBOX_EVENT_LW8
 * Events that are sent by ScApp.  Of the Events that are sent, only
 * the Event declaring that ScApp is coming up from a reboot
 * (LW8_EVENT_SC_RESTARTED) is processed.
 *
 * sbbc_mbox_reg_intr registers the handler so that it executes at
 * a DDI_SOFTINT_MED priority.
 */
static int
ntwdt_add_mbox_handlers(ntwdt_state_t *ntwdt_ptr)
{
	int	err;

	/*
	 * We need two interrupt handlers to handle the SBBC mbox
	 * events.  The sbbc_mbox_xxx implementation will
	 * trigger our ntwdt_event_data_handler, which itself will
	 * trigger our ntwdt_mbox_softint.  As a result, we'll
	 * register ntwdt_mbox_softint first, to ensure it cannot
	 * be called (until its caller, ntwdt_event_data_handler)
	 * is registered.
	 */

	/*
	 * add the softint that will do the real work of handling the
	 * LW8_SC_RESTARTED_EVENT sent from ScApp.
	 */
	if (ddi_add_softintr(ntwdt_ptr->ntwdt_dip, DDI_SOFTINT_LOW,
	    &ntwdt_mbox_softint_id, NULL, NULL, ntwdt_mbox_softint,
	    (caddr_t)ntwdt_ptr) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Failed to add MBOX_EVENT_LW8 softintr");
		return (DDI_FAILURE);
	}

	/*
	 * Register an interrupt handler with the SBBC mailbox utility.
	 * This handler will get called on each event of each type of
	 * MBOX_EVENT_LW8 events.  However, it will only conditionally
	 * trigger the worker-handler (ntwdt_mbox_softintr).
	 */
	sbbc_msg.msg_buf = (caddr_t)&lw8_event;
	sbbc_msg.msg_len = sizeof (lw8_event);

	err = sbbc_mbox_reg_intr(MBOX_EVENT_LW8, ntwdt_event_data_handler,
	    &sbbc_msg, NULL, &ntwdt_ptr->ntwdt_wdog_state->ntwdt_event_lock);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to register SBBC MBOX_EVENT_LW8"
		    " handler. err=%d", err);

		ddi_remove_softintr(ntwdt_mbox_softint_id);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Unregister the SBBC Mailbox handlers that were registered
 * by ntwdt_add_mbox_handlers.
 */
static int
ntwdt_remove_mbox_handlers(void)
{
	int	rv = DDI_SUCCESS;
	int	err;

	/*
	 * unregister the two handlers that cooperate to handle
	 * the LW8_SC_RESTARTED_EVENT.  Note that they are unregistered
	 * in LIFO order (as compared to how they were registered).
	 */
	err = sbbc_mbox_unreg_intr(MBOX_EVENT_LW8, ntwdt_event_data_handler);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to unregister sbbc MBOX_EVENT_LW8 "
		    "handler. Err=%d", err);
		rv = DDI_FAILURE;
	}

	/* remove the associated softint */
	ddi_remove_softintr(ntwdt_mbox_softint_id);

	return (rv);
}

_NOTE(ARGSUSED(0))
static int
ntwdt_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result)
{
	dev_t	dev;
	int	instance;
	int	error = DDI_SUCCESS;

	if (result == NULL)
		return (DDI_FAILURE);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		if (getminor(dev) == 0)
			*result = (void *)ntwdt_dip;
		else
			error = DDI_FAILURE;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = getminor(dev);
		*result = (void *)(uintptr_t)instance;
		break;

	default:
		error = DDI_FAILURE;
	}

	return (error);
}

/*
 * Open the device this driver manages.
 *
 * Ensure the caller is a privileged process, else
 * a non-privileged user could cause denial-of-service
 * and/or negatively impact reliability/availability.
 *
 * Ensure there is only one concurrent open().
 */
_NOTE(ARGSUSED(1))
static int
ntwdt_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int		inst = getminor(*devp);
	int		ret = 0;
	ntwdt_state_t	*ntwdt_ptr = getstate(inst);

	NTWDT_DBG(WDT_DBG_ENTRY, ("open: inst/soft: %d/0x%p",
	    inst, (void *)ntwdt_ptr));

	/* ensure caller is a privileged process */
	if (drv_priv(credp) != 0)
		return (EPERM);

	/*
	 * Check for a Deferred Attach scenario.
	 * Return ENXIO so DDI framework will call
	 * attach() and then retry the open().
	 */
	if (ntwdt_ptr == NULL)
		return (ENXIO);

	mutex_enter(&ntwdt_ptr->ntwdt_wdog_state->ntwdt_wdog_mutex);
	mutex_enter(&ntwdt_ptr->ntwdt_mutex);
	if (ntwdt_ptr->ntwdt_open_flag != 0)
		ret = EAGAIN;
	else
		ntwdt_ptr->ntwdt_open_flag = 1;
	mutex_exit(&ntwdt_ptr->ntwdt_mutex);
	mutex_exit(&ntwdt_ptr->ntwdt_wdog_state->ntwdt_wdog_mutex);

	return (ret);
}

/*
 * Close the device this driver manages.
 *
 * Notes:
 *
 *  The close() can happen while the AWDT is running !
 *  (and nothing is done, eg, to disable the watchdog
 *  or to stop updating the system heartbeat).  This
 *  is the desired behavior, as this allows for the
 *  case of monitoring a Solaris reboot in terms
 *  of watchdog expiration.
 */
_NOTE(ARGSUSED(1))
static int
ntwdt_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int		inst = getminor(dev);
	ntwdt_state_t	*ntwdt_ptr = getstate(inst);

	NTWDT_DBG(WDT_DBG_ENTRY, ("close: inst/soft: %d/0x%p",
	    inst, (void *)ntwdt_ptr));

	if (ntwdt_ptr == NULL)
		return (ENXIO);

	mutex_enter(&ntwdt_ptr->ntwdt_wdog_state->ntwdt_wdog_mutex);
	mutex_enter(&ntwdt_ptr->ntwdt_mutex);
	if (ntwdt_ptr->ntwdt_open_flag != 0) {
		ntwdt_ptr->ntwdt_open_flag = 0;
	}
	mutex_exit(&ntwdt_ptr->ntwdt_mutex);
	mutex_exit(&ntwdt_ptr->ntwdt_wdog_state->ntwdt_wdog_mutex);

	return (0);
}

_NOTE(ARGSUSED(4))
static int
ntwdt_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	int		inst = getminor(dev);
	int		retval = 0;
	ntwdt_state_t	*ntwdt_ptr = NULL;
	ntwdt_wdog_t	*wdog_state;

	if ((ntwdt_ptr = getstate(inst)) == NULL)
		return (ENXIO);

	/* Only allow ioctl's if Solaris/ScApp support app-wdog */
	if (ntwdt_watchdog_available == 0)
		return (ENXIO);

	wdog_state = ntwdt_ptr->ntwdt_wdog_state;

	switch (cmd) {
	case LOMIOCDOGSTATE: {
		/*
		 * Return the state of the AWDT to the application.
		 */
		lom_dogstate_t lom_dogstate;

		mutex_enter(&wdog_state->ntwdt_wdog_mutex);
		lom_dogstate.reset_enable =
		    wdog_state->ntwdt_reset_enabled;
		lom_dogstate.dog_enable =
		    wdog_state->ntwdt_wdog_enabled;
		lom_dogstate.dog_timeout =
		    wdog_state->ntwdt_wdog_timeout;
		mutex_exit(&wdog_state->ntwdt_wdog_mutex);

		NTWDT_DBG(WDT_DBG_IOCTL, ("DOGSTATE: wdog/reset/timeout:"
		    " %d/%d/%d", lom_dogstate.dog_enable,
		    lom_dogstate.reset_enable, lom_dogstate.dog_timeout));

		if (ddi_copyout((caddr_t)&lom_dogstate, (caddr_t)arg,
		    sizeof (lom_dogstate_t), mode) != 0) {
			retval = EFAULT;
		}
		break;
	}

	case LOMIOCDOGCTL: {
		/*
		 * Allow application to control whether watchdog
		 * is {dis,en}abled and whether Reset is
		 * {dis,en}abled.
		 */
		lom_dogctl_t	lom_dogctl;

		if (ddi_copyin((caddr_t)arg, (caddr_t)&lom_dogctl,
		    sizeof (lom_dogctl_t), mode) != 0) {
			retval = EFAULT;
			break;
		}

		NTWDT_DBG(WDT_DBG_IOCTL, ("DOGCTL: wdog/reset:"
		    " %d/%d", lom_dogctl.dog_enable,
		    lom_dogctl.reset_enable));

		mutex_enter(&wdog_state->ntwdt_wdog_mutex);

		if (wdog_state->ntwdt_wdog_timeout == 0) {
			/*
			 * then LOMIOCDOGTIME has never been used
			 * to setup a valid timeout.
			 */
			retval = EINVAL;
			goto end;
		}

		/*
		 * Return error for the non-sensical combination:
		 * "enable Reset" and "disable watchdog".
		 */
		if (lom_dogctl.dog_enable == 0 &&
		    lom_dogctl.reset_enable != 0) {
			retval = EINVAL;
			goto end;
		}

		/*
		 * Store the user-specified state in our softstate.
		 * Note that our implementation here is stateless.
		 * Eg, we do not disallow an "enable the watchdog"
		 * command when the watchdog is currently enabled.
		 * This is needed (at least in the case) when
		 * the user enters OBP via ScApp/lom.  In that case,
		 * ScApp disables the watchdog, but does not inform
		 * Solaris.  As a result, an ensuing, unfiltered DOGCTL
		 * to enable the watchdog is required.
		 */
		wdog_state->ntwdt_reset_enabled =
		    lom_dogctl.reset_enable;
		wdog_state->ntwdt_wdog_enabled =
		    lom_dogctl.dog_enable;

		if (wdog_state->ntwdt_wdog_enabled != 0) {
			/*
			 * then user wants to enable watchdog.
			 * Arm the watchdog timer and start the
			 * Cyclic, if it is not running.
			 */
			ntwdt_arm_vwdt(wdog_state);

			if (wdog_state->ntwdt_timer_running == 0) {
				ntwdt_start_timer(ntwdt_ptr);
			}
		} else {
			/*
			 * user wants to disable the watchdog.
			 * Note that we do not set ntwdt_secs_remaining
			 * to zero; that could cause a false expiration.
			 */
			if (wdog_state->ntwdt_timer_running != 0) {
				ntwdt_stop_timer(ntwdt_ptr);
			}
		}

		/*
		 * Send a permutation of mailbox commands to
		 * ScApp that describes the current state of the
		 * watchdog timer.  Note that the permutation
		 * depends on whether this is the first
		 * Enabling of the watchdog or not.
		 */
		if (wdog_state->ntwdt_wdog_enabled != 0 &&
		    wdog_state->ntwdt_is_initial_enable == 0) {

			/* switch from SWDT to AWDT mode */
			ntwdt_swdt_to_awdt(wdog_state);

			/* Tell ScApp we're in AWDT mode */
			(void) ntwdt_set_cfgvar(LW8_WDT_PROP_MODE,
			    LW8_PROP_MODE_AWDT);
		}

		/* Inform ScApp of the choices made by the app */
		(void) ntwdt_set_cfgvar(LW8_WDT_PROP_WDT,
		    wdog_state->ntwdt_wdog_enabled);
		(void) ntwdt_set_cfgvar(LW8_WDT_PROP_RECOV,
		    wdog_state->ntwdt_reset_enabled);

		if (wdog_state->ntwdt_wdog_enabled != 0 &&
		    wdog_state->ntwdt_is_initial_enable == 0) {
			/*
			 * Clear tod_iosram_t.tod_timeout_period,
			 * which is used in SWDT part of state
			 * machine.  (If this field is non-zero,
			 * ScApp assumes that Solaris' SWDT is active).
			 *
			 * Clearing this is useful in case SC reboots
			 * while Solaris is running, as ScApp will read
			 * a zero and not assume SWDT is running.
			 */
			(void) ntwdt_set_hw_timeout(0);

			/* "the first watchdog-enable has been seen" */
			wdog_state->ntwdt_is_initial_enable = 1;
		}

		mutex_exit(&wdog_state->ntwdt_wdog_mutex);
		break;
	}

	case LOMIOCDOGTIME: {
		/*
		 * Allow application to set the period (in seconds)
		 * of the watchdog timeout.
		 */
		uint32_t	lom_dogtime;

		if (ddi_copyin((caddr_t)arg, (caddr_t)&lom_dogtime,
		    sizeof (uint32_t), mode) != 0) {
			retval = EFAULT;
			break;
		}

		NTWDT_DBG(WDT_DBG_IOCTL, ("DOGTIME: %u seconds",
		    lom_dogtime));

		/* Ensure specified timeout is within range. */
		if ((lom_dogtime == 0) ||
		    (lom_dogtime > NTWDT_MAX_TIMEOUT)) {
			retval = EINVAL;
			break;
		}

		mutex_enter(&wdog_state->ntwdt_wdog_mutex);

		wdog_state->ntwdt_wdog_timeout = lom_dogtime;

		/*
		 * If watchdog is currently running, re-arm the
		 * watchdog timeout with the specified value.
		 */
		if (wdog_state->ntwdt_timer_running != 0) {
			ntwdt_arm_vwdt(wdog_state);
		}

		/* Tell ScApp of the specified timeout */
		(void) ntwdt_set_cfgvar(LW8_WDT_PROP_TO, lom_dogtime);

		mutex_exit(&wdog_state->ntwdt_wdog_mutex);
		break;
	}

	case LOMIOCDOGPAT: {
		/*
		 * Allow user to re-arm ("pat") the watchdog.
		 */
		NTWDT_DBG(WDT_DBG_IOCTL, ("DOGPAT"));

		mutex_enter(&wdog_state->ntwdt_wdog_mutex);

		/*
		 * If watchdog is not enabled or underlying
		 * Cyclic timer is not running, exit.
		 */
		if (!(wdog_state->ntwdt_wdog_enabled &&
		    wdog_state->ntwdt_timer_running))
			goto end;

		if (wdog_state->ntwdt_wdog_expired == 0) {
			/* then VWDT has not expired; re-arm it */
			ntwdt_arm_vwdt(wdog_state);

			NTWDT_DBG(WDT_DBG_VWDT, ("VWDT re-armed:"
			    " %d seconds",
			    wdog_state->ntwdt_secs_remaining));
		}

		mutex_exit(&wdog_state->ntwdt_wdog_mutex);
		break;
	}

#ifdef DEBUG
	case NTWDTIOCPANIC: {
		/*
		 * Use in unit/integration testing to test our
		 * panic-handler code.
		 */
		cmn_err(CE_PANIC, "NTWDTIOCPANIC: force a panic");
		break;
	}

	case NTWDTIOCSTATE: {
		/*
		 * Allow application to read wdog state from the
		 * SC (and *not* the driver's softstate).
		 *
		 * Return state of:
		 *  o recovery-enabled
		 *  o current timeout value
		 */
		ntwdt_data_t	ntwdt_data;
		int		action;
		int		timeout;
		int		ret;

		mutex_enter(&wdog_state->ntwdt_wdog_mutex);
		ret = ntwdt_get_cfgvar(LW8_WDT_PROP_TO, &timeout);
		ret |= ntwdt_get_cfgvar(LW8_WDT_PROP_RECOV, &action);
		mutex_exit(&wdog_state->ntwdt_wdog_mutex);

		bzero((caddr_t)&ntwdt_data, sizeof (ntwdt_data));

		if (ret != NTWDT_SUCCESS) {
			retval = EIO;
			break;
		}

		NTWDT_DBG(WDT_DBG_IOCTL, ("NTWDTIOCSTATE:"
		    " timeout/action: %d/%d", timeout, action));

		ntwdt_data.ntwdt_wd1 = (uint32_t)timeout;
		ntwdt_data.ntwdt_wd2 = (uint8_t)action;

		if (ddi_copyout((caddr_t)&ntwdt_data, (caddr_t)arg,
		    sizeof (ntwdt_data_t), mode) != 0) {
			retval = EFAULT;
		}
		break;
	}
#endif
	default:
		retval = EINVAL;
		break;
	}

	return (retval);
end:
	mutex_exit(&wdog_state->ntwdt_wdog_mutex);
	return (retval);
}

/*
 * Arm the Virtual Watchdog Timer (VWDT).
 *
 * Assign the current watchdog timeout (ntwdt_wdog_timeout)
 * to the softstate variable representing the watchdog
 * timer (ntwdt_secs_remaining).
 *
 * To ensure (from ntwdt's perspective) that any actual
 * timeout expiration is at least as large as the expected
 * timeout, conditionally set/clear a bit that will be
 * checked in the Cyclic's softint.
 *
 * If the Cyclic has been started, the goal is to ignore
 * the _next_ firing of the Cyclic, as that firing will
 * NOT represent a full, one-second period.  If the Cyclic
 * has NOT been started yet, then do not ignore the next
 * Cyclic's firing, as that's the First One, and it was
 * programmed to fire at a specific time (see ntwdt_start_timer).
 */
static void
ntwdt_arm_vwdt(ntwdt_wdog_t *wdog_state)
{
	/* arm the watchdog timer (VWDT) */
	wdog_state->ntwdt_secs_remaining =
	    wdog_state->ntwdt_wdog_timeout;

	if (wdog_state->ntwdt_timer_running != 0)
		NTWDT_FLAG_SET(wdog_state, SKIP_CYCLIC);
	else
		NTWDT_FLAG_CLR(wdog_state, SKIP_CYCLIC);
}

/*
 * Switch from SWDT mode to AWDT mode.
 */
_NOTE(ARGSUSED(0))
static void
ntwdt_swdt_to_awdt(ntwdt_wdog_t *wdog_state)
{
	ASSERT(wdog_state->ntwdt_is_initial_enable == 0);

	/*
	 * Disable SWDT.  If SWDT is currently active,
	 * display a message so user knows that SWDT Mode
	 * has terminated.
	 */
	if (watchdog_enable != 0 ||
	    watchdog_activated != 0)
		cmn_err(CE_NOTE, "Hardware watchdog disabled");
	watchdog_enable = 0;
	watchdog_activated = 0;

	/* "we are in AWDT mode" */
	ntwdt_watchdog_activated = 1;
	NTWDT_DBG(WDT_DBG_VWDT, ("AWDT is enabled"));
}

/*
 * This is the Cyclic that runs at a multiple of the
 * AWDT's watchdog-timeout period.  This Cyclic runs at
 * LOCK_LEVEL (eg, CY_LOCK_LEVEL) and will post a
 * soft-interrupt in order to complete all processing.
 *
 * Executing at LOCK_LEVEL gives this function a high
 * interrupt priority, while performing its work via
 * a soft-interrupt allows for a consistent (eg, MT-safe)
 * view of driver softstate between User and Interrupt
 * context.
 *
 * Context:
 *  interrupt context: Cyclic framework calls at
 *                     CY_LOCK_LEVEL (=> 10)
 */
_NOTE(ARGSUSED(0))
static void
ntwdt_cyclic_pat(void *arg)
{
	/* post-down to DDI_SOFTINT_LOW */
	ddi_trigger_softintr(ntwdt_cyclic_softint_id);
}

/*
 * This is the soft-interrupt triggered by the AWDT
 * Cyclic.
 *
 * This softint does all the work re: computing whether
 * the VWDT expired.  It grabs ntwdt_wdog_mutex
 * so User Context code (eg, the IOCTLs) cannot run,
 * and then it tests whether the VWDT expired.  If it
 * hasn't, it decrements the VWDT timer by the amount
 * of the Cyclic's period.  If the timer has expired,
 * it initiates Recovery (based on what user specified
 * in LOMIOCDOGCTL).
 *
 * This function also updates the normal system "heartbeat".
 *
 * Context:
 *  interrupt-context: DDI_SOFTINT_LOW
 */
static uint_t
ntwdt_cyclic_softint(char *arg)
{
	ntwdt_state_t	*ntwdt_ptr = (ntwdt_state_t *)arg;
	ntwdt_wdog_t	*wdog_state;

	wdog_state = ntwdt_ptr->ntwdt_wdog_state;

	mutex_enter(&wdog_state->ntwdt_wdog_mutex);

	if ((wdog_state->ntwdt_wdog_flags &
	    NTWDT_FLAG_SKIP_CYCLIC) != 0) {
		/*
		 * then skip all processing by this interrupt.
		 * (see ntwdt_arm_vwdt()).
		 */
		wdog_state->ntwdt_wdog_flags &= ~NTWDT_FLAG_SKIP_CYCLIC;
		goto end;
	}

	if (wdog_state->ntwdt_timer_running == 0 ||
	    (ntwdt_ptr->ntwdt_cycl_id == CYCLIC_NONE) ||
	    (wdog_state->ntwdt_wdog_enabled == 0))
		goto end;

	/* re-arm ("pat") the hardware watchdog */
	ntwdt_pat_hw_watchdog();

	/* Decrement the VWDT and see if it has expired. */
	if (--wdog_state->ntwdt_secs_remaining == 0) {

		cmn_err(CE_WARN, "application-watchdog expired");

		wdog_state->ntwdt_wdog_expired = 1;

		if (wdog_state->ntwdt_reset_enabled != 0) {
			/*
			 * Update ScApp so that the new wdog-timeout
			 * value is as specified in the
			 * NTWDT_BOOT_TIMEOUT_PROP driver Property.
			 * This timeout is assumedly larger than the
			 * actual Solaris reboot time.  This will allow
			 * our forced-reboot to not cause an unplanned
			 * (series of) watchdog expiration(s).
			 */
			if (ntwdt_disable_timeout_action == 0)
				ntwdt_reprogram_wd(ntwdt_ptr);

			mutex_exit(&wdog_state->ntwdt_wdog_mutex);

			NTWDT_DBG(WDT_DBG_VWDT, ("recovery being done"));

			ntwdt_enforce_timeout();
		} else {
			NTWDT_DBG(WDT_DBG_VWDT, ("no recovery being done"));

			wdog_state->ntwdt_wdog_enabled = 0;

			/*
			 * Tell ScApp to disable wdog; this prevents
			 * the "2x-timeout" artifact.  Eg, Solaris
			 * times-out at t(x) and ScApp times-out at t(2x),
			 * where (x==ntwdt_wdog_timeout).
			 */
			(void) ntwdt_set_cfgvar(LW8_WDT_PROP_WDT,
			    wdog_state->ntwdt_wdog_enabled);
		}

		/* Schedule Callout to stop this Cyclic */
		(void) timeout(ntwdt_stop_timer_lock, ntwdt_ptr, 0);

	} else {
		_NOTE(EMPTY)
		NTWDT_DBG(WDT_DBG_VWDT, ("time remaining in VWDT: %d"
		    " seconds", wdog_state->ntwdt_secs_remaining));
	}
end:
	mutex_exit(&wdog_state->ntwdt_wdog_mutex);

	return (DDI_INTR_CLAIMED);
}

/*
 * Program the AWDT watchdog-timeout value to that specified
 * in the NTWDT_BOOT_TIMEOUT_PROP driver Property.  However,
 * only do this if the AWDT is in the correct state.
 *
 * Caller's Context:
 *  o interrupt context: (from software-interrupt)
 *  o during a panic
 */
static void
ntwdt_reprogram_wd(ntwdt_state_t *ntwdt_ptr)
{
	ntwdt_wdog_t *wdog_state = ntwdt_ptr->ntwdt_wdog_state;

	/*
	 * Program the AWDT watchdog-timeout value only if the
	 * watchdog is enabled, the user wants to do recovery,
	 * ("reset is enabled") and the AWDT timer is currently
	 * running.
	 */
	if (wdog_state->ntwdt_wdog_enabled != 0 &&
	    wdog_state->ntwdt_reset_enabled != 0 &&
	    wdog_state->ntwdt_timer_running != 0) {
		if (ddi_in_panic() != 0)
			(void) ntwdt_set_cfgvar_noreply(LW8_WDT_PROP_TO,
			    wdog_state->ntwdt_boot_timeout);
		else
			(void) ntwdt_set_cfgvar(LW8_WDT_PROP_TO,
			    wdog_state->ntwdt_boot_timeout);
	}
}

/*
 * This is the callback that was registered to run during a panic.
 * It will set the watchdog-timeout value to be that as specified
 * in the NTWDT_BOOT_TIMEOUT_PROP driver Property.
 *
 * Note that unless this Property's value specifies a timeout
 * that's larger than the actual reboot latency, ScApp will
 * experience a timeout and initiate Recovery.
 */
_NOTE(ARGSUSED(1))
static boolean_t
ntwdt_panic_cb(void *arg, int code)
{
	ASSERT(ddi_in_panic() != 0);

	ntwdt_reprogram_wd((ntwdt_state_t *)arg);

	return (B_TRUE);
}

/*
 * Initialize the Cyclic that is used to monitor the VWDT.
 */
static void
ntwdt_start_timer(ntwdt_state_t *ntwdt_ptr)
{
	ntwdt_wdog_t	*wdog_state = ntwdt_ptr->ntwdt_wdog_state;
	cyc_handler_t	*hdlr = &wdog_state->ntwdt_cycl_hdlr;
	cyc_time_t	*when = &wdog_state->ntwdt_cycl_time;

	/*
	 * Init Cyclic so its first expiry occurs wdog-timeout
	 * seconds from the current, absolute time.
	 */
	when->cyt_interval = wdog_state->ntwdt_cyclic_interval;
	when->cyt_when = gethrtime() + when->cyt_interval;

	wdog_state->ntwdt_wdog_expired = 0;
	wdog_state->ntwdt_timer_running = 1;

	mutex_enter(&cpu_lock);
	if (ntwdt_ptr->ntwdt_cycl_id == CYCLIC_NONE)
		ntwdt_ptr->ntwdt_cycl_id = cyclic_add(hdlr, when);
	mutex_exit(&cpu_lock);

	NTWDT_DBG(WDT_DBG_VWDT, ("AWDT's cyclic-driven timer is started"));
}

/*
 * Stop the cyclic that is used to monitor the VWDT (and
 * was Started by ntwdt_start_timer).
 *
 * Context: per the Cyclic API, cyclic_remove cannot be called
 *          from interrupt-context.  Note that when this is
 *	    called via a Callout, it's called from base level.
 */
static void
ntwdt_stop_timer(void *arg)
{
	ntwdt_state_t	*ntwdt_ptr = (void *)arg;
	ntwdt_wdog_t	*wdog_state = ntwdt_ptr->ntwdt_wdog_state;

	mutex_enter(&cpu_lock);
	if (ntwdt_ptr->ntwdt_cycl_id != CYCLIC_NONE)
		cyclic_remove(ntwdt_ptr->ntwdt_cycl_id);
	mutex_exit(&cpu_lock);

	wdog_state->ntwdt_timer_running = 0;
	ntwdt_ptr->ntwdt_cycl_id = CYCLIC_NONE;

	NTWDT_DBG(WDT_DBG_VWDT, ("AWDT's cyclic-driven timer is stopped"));
}

/*
 * Stop the cyclic that is used to monitor the VWDT (and
 * do it in a thread-safe manner).
 *
 * This is a wrapper function for the core function,
 * ntwdt_stop_timer.  Both functions are useful, as some
 * callers will already have the appropriate mutex locked, and
 * other callers will not.
 */
static void
ntwdt_stop_timer_lock(void *arg)
{
	ntwdt_state_t	*ntwdt_ptr = (void *)arg;
	ntwdt_wdog_t	*wdog_state = ntwdt_ptr->ntwdt_wdog_state;

	mutex_enter(&wdog_state->ntwdt_wdog_mutex);
	ntwdt_stop_timer(arg);
	mutex_exit(&wdog_state->ntwdt_wdog_mutex);
}

/*
 * Add callbacks needed to react to major system state transitions.
 */
static void
ntwdt_add_callbacks(ntwdt_state_t *ntwdt_ptr)
{
	/* register a callback that's called during a panic */
	ntwdt_callback_ids.ntwdt_panic_cb = callb_add(ntwdt_panic_cb,
	    (void *)ntwdt_ptr, CB_CL_PANIC, "ntwdt_panic_cb");
}

/*
 * Remove callbacks added by ntwdt_add_callbacks.
 */
static void
ntwdt_remove_callbacks()
{
	(void) callb_delete(ntwdt_callback_ids.ntwdt_panic_cb);
}

/*
 * Initiate a Reset (as a result of the VWDT timeout expiring).
 */
static void
ntwdt_enforce_timeout()
{
	if (ntwdt_disable_timeout_action != 0) {
		cmn_err(CE_NOTE, "OS timeout expired, taking no action");
		return;
	}

	NTWDT_DBG(WDT_DBG_VWDT, ("VWDT expired; do a crashdump"));

	(void) kadmin(A_DUMP, AD_BOOT, NULL, kcred);
	cmn_err(CE_PANIC, "kadmin(A_DUMP, AD_BOOT) failed");
	_NOTE(NOTREACHED)
}

/*
 * Interpret the Properties from driver's config file.
 */
static int
ntwdt_read_props(ntwdt_state_t *ntwdt_ptr)
{
	ntwdt_wdog_t	*wdog_state;
	int		boot_timeout;

	wdog_state = ntwdt_ptr->ntwdt_wdog_state;

	/*
	 * interpret Property that specifies how long
	 * the watchdog-timeout should be set to when
	 * Solaris panics.  Assumption is that this value
	 * is larger than the amount of time it takes
	 * to reboot and write crashdump.  If not,
	 * ScApp could induce a reset, due to an expired
	 * watchdog-timeout.
	 */
	wdog_state->ntwdt_boot_timeout =
	    NTWDT_DEFAULT_BOOT_TIMEOUT;

	boot_timeout = ddi_prop_get_int(DDI_DEV_T_ANY,
	    ntwdt_ptr->ntwdt_dip, DDI_PROP_DONTPASS,
	    NTWDT_BOOT_TIMEOUT_PROP, -1);

	if (boot_timeout != -1 && boot_timeout > 0 &&
	    boot_timeout <= NTWDT_MAX_TIMEOUT) {
		wdog_state->ntwdt_boot_timeout =
		    boot_timeout;
	} else {
		_NOTE(EMPTY)
		NTWDT_DBG(WDT_DBG_ENTRY, (NTWDT_BOOT_TIMEOUT_PROP
		    ": using default of %d seconds.",
		    wdog_state->ntwdt_boot_timeout));
	}

	return (DDI_SUCCESS);
}

/*
 * Write state of SWDT to ScApp.
 *
 * Currently, this function is only called on attach()
 * of our driver.
 *
 * Note that we do not need to call this function, eg,
 * in response to a solicitation from ScApp (eg,
 * the LW8_SC_RESTARTED_EVENT).
 *
 * Context:
 *  called in Kernel Context
 */
static int
ntwdt_set_swdt_state()
{
	/*
	 * note that ScApp only needs this one
	 * variable when system is in SWDT mode.
	 */
	(void) ntwdt_set_cfgvar(LW8_WDT_PROP_MODE,
	    LW8_PROP_MODE_SWDT);

	return (0);
}

/*
 * Write all AWDT state to ScApp via the SBBC mailbox
 * in IOSRAM.  Note that the permutation of Writes
 * is as specified in the design spec.
 *
 * Notes: caller must perform synchronization so that
 *        this series of Writes is consistent as viewed
 *        by ScApp (eg, there is no LW8_WDT_xxx mailbox
 *        command that contains "all Properties"; each
 *        Property must be written individually).
 */
static int
ntwdt_set_awdt_state(ntwdt_wdog_t *rstatep)
{
	/* ScApp expects values in this order: */
	(void) ntwdt_set_cfgvar(LW8_WDT_PROP_MODE,
	    ntwdt_watchdog_activated != 0);
	(void) ntwdt_set_cfgvar(LW8_WDT_PROP_TO,
	    rstatep->ntwdt_wdog_timeout);
	(void) ntwdt_set_cfgvar(LW8_WDT_PROP_RECOV,
	    rstatep->ntwdt_reset_enabled);
	(void) ntwdt_set_cfgvar(LW8_WDT_PROP_WDT,
	    rstatep->ntwdt_wdog_enabled);

	return (NTWDT_SUCCESS);
}

/*
 * Write a specified WDT Property (and Value) to ScApp.
 *
 * <Property, Value> is passed in the LW8_MBOX_WDT_SET
 * (SBBC) mailbox message.  The SBBC mailbox resides in
 * IOSRAM.
 *
 * Note that this function is responsible for ensuring that
 * a driver-specific representation of a mailbox <Value> is
 * mapped into the representation that is expected by ScApp
 * (eg, see LW8_WDT_PROP_RECOV).
 */
static int
ntwdt_set_cfgvar(int var, int val)
{
	int		rv;
	int		mbox_val;
	lw8_set_wdt_t	set_wdt;

	switch (var) {
	case LW8_WDT_PROP_RECOV:
#ifdef DEBUG
		NTWDT_DBG(WDT_DBG_PROT, ("MBOX_SET of 'recovery-enabled':"
		    " %s (%d)", (val != 0) ? "enabled" : "disabled", val));
#endif
		mbox_val = (val != 0) ? LW8_PROP_RECOV_ENABLED :
		    LW8_PROP_RECOV_DISABLED;
		break;

	case LW8_WDT_PROP_WDT:
#ifdef DEBUG
		NTWDT_DBG(WDT_DBG_PROT, ("MBOX_SET of 'wdog-enabled':"
		    " %s (%d)", (val != 0) ? "enabled" : "disabled", val));
#endif
		mbox_val = (val != 0) ? LW8_PROP_WDT_ENABLED :
		    LW8_PROP_WDT_DISABLED;
		break;

	case LW8_WDT_PROP_TO:
#ifdef DEBUG
		NTWDT_DBG(WDT_DBG_PROT, ("MBOX_SET of 'wdog-timeout':"
		    " %d seconds", val));
#endif
		mbox_val = val;
		break;

	case LW8_WDT_PROP_MODE:
#ifdef DEBUG
		NTWDT_DBG(WDT_DBG_PROT, ("MBOX_SET of 'wdog-mode':"
		    " %s (%d)", (val != LW8_PROP_MODE_SWDT) ?
		    "AWDT" : "SWDT", val));
#endif
		mbox_val = val;
		break;

	default:
		ASSERT(0);
		_NOTE(NOTREACHED)
	}

	set_wdt.property_id = var;
	set_wdt.value = mbox_val;

	rv = ntwdt_lomcmd(LW8_MBOX_WDT_SET, (intptr_t)&set_wdt);
	if (rv != 0) {
		_NOTE(EMPTY)
		NTWDT_DBG(WDT_DBG_PROT, ("MBOX_SET of prop/val %d/%d "
		    "failed: %d", var, mbox_val, rv));
	}

	return (rv);
}

static void
ntwdt_set_cfgvar_noreply(int var, int val)
{
	(void) ntwdt_set_cfgvar(var, val);
}

#ifdef DEBUG
/*
 * Read a specified WDT Property from ScApp.
 *
 * <Property> is passed in the Request of the LW8_MBOX_WDT_GET
 * (SBBC) mailbox message, and the Property's <Value>
 * is returned in the message's Response.  The SBBC mailbox
 * resides in IOSRAM.
 */
static int
ntwdt_get_cfgvar(int var, int *val)
{
	lw8_get_wdt_t	get_wdt;
	int		rv;

	rv = ntwdt_lomcmd(LW8_MBOX_WDT_GET, (intptr_t)&get_wdt);
	if (rv != 0) {
		_NOTE(EMPTY)
		NTWDT_DBG(WDT_DBG_PROT, ("MBOX_GET failed: %d", rv));
	} else {
		switch (var) {
		case LW8_WDT_PROP_RECOV:
			*val = (uint8_t)get_wdt.recovery_enabled;
			NTWDT_DBG(WDT_DBG_PROT, ("MBOX_GET of 'reset-enabled':"
			    " %s (%d)", (*val != 0) ? "enabled" : "disabled",
			    *val));
			break;

		case LW8_WDT_PROP_WDT:
			*val = (uint8_t)get_wdt.watchdog_enabled;
			NTWDT_DBG(WDT_DBG_PROT, ("MBOX_GET of 'wdog-enabled':"
			    " %s (%d)", (*val != 0) ? "enabled" : "disabled",
			    *val));
			break;

		case LW8_WDT_PROP_TO:
			*val = (uint8_t)get_wdt.timeout;
			NTWDT_DBG(WDT_DBG_PROT, ("MBOX_GET of 'wdog-timeout':"
			    " %d seconds", *val));
			break;

		default:
			ASSERT(0);
			_NOTE(NOTREACHED)
		}
	}

	return (rv);
}
#endif

/*
 * Update the real system "heartbeat", which resides in IOSRAM.
 * This "heartbeat" is normally used in SWDT Mode, but when
 * in AWDT Mode, ScApp also uses its value to determine if Solaris
 * is up-and-running.
 */
static void
ntwdt_pat_hw_watchdog()
{
	tod_iosram_t	tod_buf;
	static uint32_t	i_am_alive = 0;
#ifdef DEBUG
	if (ntwdt_stop_heart != 0)
		return;
#endif
	/* Update the system heartbeat */
	if (i_am_alive == UINT32_MAX)
		i_am_alive = 0;
	else
		i_am_alive++;

	NTWDT_DBG(WDT_DBG_HEART, ("update heartbeat: %d",
	    i_am_alive));

	if (iosram_write(SBBC_TOD_KEY, OFFSET(tod_buf, tod_i_am_alive),
	    (char *)&i_am_alive, sizeof (uint32_t))) {
		cmn_err(CE_WARN, "ntwdt_pat_hw_watchdog(): "
		    "write heartbeat failed");
	}
}

/*
 * Write the specified value to the system's normal (IOSRAM)
 * location that's used to specify Solaris' watchdog-timeout
 * on Serengeti platforms.
 *
 * In SWDT Mode, this location can hold values [0,n).
 * In AWDT Mode, this location must have value 0 (else
 * after a ScApp-reboot, ScApp could mistakenly interpret
 * that the system is in SWDT Mode).
 */
static int
ntwdt_set_hw_timeout(uint32_t period)
{
	tod_iosram_t	tod_buf;
	int		rv;

	rv = iosram_write(SBBC_TOD_KEY, OFFSET(tod_buf, tod_timeout_period),
	    (char *)&period, sizeof (uint32_t));
	if (rv != 0)
		cmn_err(CE_WARN, "write of %d for TOD timeout "
		    "period failed: %d", period, rv);

	return (rv);
}

/*
 * Soft-interrupt handler that is triggered when ScApp wants
 * to know the current state of the app-wdog.
 *
 * Grab ntwdt_wdog_mutex so that we synchronize with any
 * concurrent User Context and Interrupt Context activity.  Call
 * a function that writes a permutation of the watchdog state
 * to the SC, then release the mutex.
 *
 * We grab the mutex not only so that each variable is consistent
 * but also so that the *permutation* of variables is consistent.
 * I.e., any set of one or more variables (that we write to SC
 * using multiple mailbox commands) will truly be seen as a
 * consistent snapshot.  Note that if our protocol had a MBOX_SET
 * command that allowed writing all watchdog state in one
 * command, then the lock-hold latency would be greatly reduced.
 * To our advantage, this softint normally executes very
 * infrequently.
 *
 * Context:
 *  called at Interrupt Context (DDI_SOFTINT_LOW)
 */
static uint_t
ntwdt_mbox_softint(char *arg)
{
	ntwdt_wdog_t	*wdog_state;

	wdog_state = ((ntwdt_state_t *)arg)->ntwdt_wdog_state;

	ASSERT(wdog_state != NULL);

	mutex_enter(&wdog_state->ntwdt_wdog_mutex);

	/* tell ScApp state of AWDT */
	(void) ntwdt_set_awdt_state(wdog_state);

	mutex_exit(&wdog_state->ntwdt_wdog_mutex);

	return (DDI_INTR_CLAIMED);
}

/*
 * Handle MBOX_EVENT_LW8 Events that are sent from ScApp.
 *
 * The only (sub-)type of Event we handle is the
 * LW8_EVENT_SC_RESTARTED Event.  We handle this by triggering
 * a soft-interrupt only if we are in AWDT mode.
 *
 * ScApp sends this Event when it wants to learn the current
 * state of the AWDT variables.  Design-wise, this is used to
 * handle the case where the SC reboots while the system is in
 * AWDT mode (if the SC reboots in SWDT mode, then ScApp
 * already knows all necessary info and therefore won't send
 * this Event).
 *
 * Context:
 *  function is called in Interrupt Context (at DDI_SOFTINT_MED)
 *  and we conditionally trigger a softint that will run at
 *  DDI_SOFTINT_LOW.  Note that function executes at
 *  DDI_SOFTINT_MED due to how this handler was registered by
 *  the implementation of sbbc_mbox_reg_intr().
 *
 * Notes:
 *  Currently, the LW8_EVENT_SC_RESTARTED Event is only sent
 *  by SC when in AWDT mode.
 */
static uint_t
ntwdt_event_data_handler(char *arg)
{
	lw8_event_t	*payload;
	sbbc_msg_t	*msg;

	if (arg == NULL) {
		return (DDI_INTR_CLAIMED);
	}

	msg = (sbbc_msg_t *)arg;
	if (msg->msg_buf == NULL) {
		return (DDI_INTR_CLAIMED);
	}

	payload = (lw8_event_t *)msg->msg_buf;

	switch (payload->event_type) {
	case LW8_EVENT_SC_RESTARTED:
		/*
		 * then SC probably was rebooted, and it therefore
		 * needs to know what the current state of AWDT is.
		 */
		NTWDT_DBG(WDT_DBG_EVENT, ("LW8_EVENT_SC_RESTARTED "
		    "received in %s mode",
		    (ntwdt_watchdog_activated != 0) ? "AWDT" : "SWDT"));

		if (ntwdt_watchdog_activated != 0) {
			/* then system is in AWDT mode */
			ddi_trigger_softintr(ntwdt_mbox_softint_id);
		}
		break;

	default:
		NTWDT_DBG(WDT_DBG_EVENT,
		    ("MBOX_EVENT_LW8: %d", payload->event_type));
		break;
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * Send an SBBC Mailbox command to ScApp.
 *
 * Use the sbbc_mbox_request_response utility function to
 * send the Request and receive the optional Response.
 *
 * Context:
 *  can be called from Interrupt Context or User Context.
 */
static int
ntwdt_lomcmd(int cmd, intptr_t arg)
{
	sbbc_msg_t	request;
	sbbc_msg_t	*reqp;
	sbbc_msg_t	response;
	sbbc_msg_t	*resp;
	int		rv = 0;

	reqp = &request;
	bzero((caddr_t)&request, sizeof (request));
	reqp->msg_type.type = LW8_MBOX;
	reqp->msg_type.sub_type = (uint16_t)cmd;

	resp = &response;
	bzero((caddr_t)&response, sizeof (response));
	resp->msg_type.type = LW8_MBOX;
	resp->msg_type.sub_type = (uint16_t)cmd;

	switch (cmd) {
	case LW8_MBOX_WDT_GET:
		reqp->msg_len = 0;
		reqp->msg_buf = (caddr_t)NULL;
		resp->msg_len = sizeof (lw8_get_wdt_t);
		resp->msg_buf = (caddr_t)arg;
		break;

	case LW8_MBOX_WDT_SET:
		reqp->msg_len = sizeof (lw8_set_wdt_t);
		reqp->msg_buf = (caddr_t)arg;
		resp->msg_len = 0;
		resp->msg_buf = (caddr_t)NULL;
		break;

	default:
		return (EINVAL);
	}

	rv = sbbc_mbox_request_response(reqp, resp,
	    LW8_DEFAULT_MAX_MBOX_WAIT_TIME);

	if ((rv) || (resp->msg_status != SG_MBOX_STATUS_SUCCESS)) {

		NTWDT_NDBG(WDT_DBG_PROT, ("SBBC mailbox error:"
		    " (rv/msg_status)=(%d/%d)", rv, resp->msg_status));

		/* errors from sgsbbc */
		if (resp->msg_status > 0) {
			return (resp->msg_status);
		}

		/* errors from ScApp */
		switch (resp->msg_status) {
		case SG_MBOX_STATUS_ILLEGAL_PARAMETER:
			/* illegal ioctl parameter */
			return (EINVAL);

		default:
			return (EIO);
		}
	}
	return (0);
}
