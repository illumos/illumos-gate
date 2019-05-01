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
 * Copyright 2019 Joyent, Inc.
 */

/*
 * bscv.c - multi-threaded lom driver for the Stiletto platform.
 */

/*
 * Included files.
 */

#include <sys/note.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/stream.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/reboot.h>
#include <sys/modctl.h>
#include <sys/mkdev.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/consdev.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/disp.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/log.h>
#include <sys/utsname.h>
#include <sys/callb.h>
#include <sys/sysevent.h>
#include <sys/nvpair.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/domain.h>
#include <sys/sysevent/env.h>
#include <sys/sysevent/dr.h>

#include <sys/lom_io.h>
#include <sys/bscbus.h>
#include <sys/bscv_impl.h>

/*
 * Variables defined here and visible internally only
 */

static void *bscv_statep = NULL;

/*
 * Forward declarations
 */

static int bscv_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int bscv_attach(dev_info_t *, ddi_attach_cmd_t);
static int bscv_detach(dev_info_t *, ddi_detach_cmd_t);
static int bscv_quiesce(dev_info_t *);
static int bscv_map_regs(bscv_soft_state_t *);
static void bscv_unmap_regs(bscv_soft_state_t *);
static void bscv_map_chan_logical_physical(bscv_soft_state_t *);

static int bscv_open(dev_t *, int, int, cred_t *);
static int bscv_close(dev_t, int, int, cred_t *);
static void bscv_full_stop(bscv_soft_state_t *);

static void bscv_enter(bscv_soft_state_t *);
static int bscv_tryenter(bscv_soft_state_t *ssp);
static void bscv_exit(bscv_soft_state_t *);
#ifdef DEBUG
static int bscv_held(bscv_soft_state_t *);
#endif /* DEBUG */

static void bscv_put8(bscv_soft_state_t *, int, bscv_addr_t, uint8_t);
static void bscv_put16(bscv_soft_state_t *, int, bscv_addr_t, uint16_t);
static void bscv_put32(bscv_soft_state_t *, int, bscv_addr_t, uint32_t);
static uint8_t bscv_get8(bscv_soft_state_t *, int, bscv_addr_t);
static uint16_t bscv_get16(bscv_soft_state_t *, int, bscv_addr_t);
static uint32_t bscv_get32(bscv_soft_state_t *, int, bscv_addr_t);
static void bscv_setclear8(bscv_soft_state_t *, int,
	bscv_addr_t, uint8_t, uint8_t);
static void bscv_setclear8_volatile(bscv_soft_state_t *, int,
	bscv_addr_t, uint8_t, uint8_t);
static void bscv_rep_rw8(bscv_soft_state_t *, int,
	uint8_t *, bscv_addr_t, size_t, uint_t, boolean_t);
static uint8_t bscv_get8_cached(bscv_soft_state_t *, bscv_addr_t);

static uint8_t bscv_get8_locked(bscv_soft_state_t *, int, bscv_addr_t, int *);
static void bscv_rep_get8_locked(bscv_soft_state_t *, int,
	uint8_t *, bscv_addr_t, size_t, uint_t, int *);

static boolean_t bscv_faulty(bscv_soft_state_t *);
static void bscv_clear_fault(bscv_soft_state_t *);
static void bscv_set_fault(bscv_soft_state_t *);
static boolean_t bscv_session_error(bscv_soft_state_t *);
static int bscv_retcode(bscv_soft_state_t *);
static int bscv_should_retry(bscv_soft_state_t *);
static void bscv_locked_result(bscv_soft_state_t *, int *);

static void bscv_put8_once(bscv_soft_state_t *, int, bscv_addr_t, uint8_t);
static uint8_t bscv_get8_once(bscv_soft_state_t *, int, bscv_addr_t);
static uint32_t bscv_probe(bscv_soft_state_t *, int, uint32_t *);
static void bscv_resync_comms(bscv_soft_state_t *, int);

static boolean_t bscv_window_setup(bscv_soft_state_t *);
static int bscv_eerw(bscv_soft_state_t *, uint32_t, uint8_t *,
    unsigned, boolean_t);

static int bscv_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int bscv_ioc_dogstate(bscv_soft_state_t *, intptr_t, int);
static int bscv_ioc_psustate(bscv_soft_state_t *, intptr_t, int);
static int bscv_ioc_fanstate(bscv_soft_state_t *, intptr_t, int);
static int bscv_ioc_fledstate(bscv_soft_state_t *, intptr_t, int);
static int bscv_ioc_ledstate(bscv_soft_state_t *, intptr_t, int);
static int bscv_ioc_info(bscv_soft_state_t *, intptr_t, int);
static int bscv_ioc_mread(bscv_soft_state_t *, intptr_t, int);
static int bscv_ioc_volts(bscv_soft_state_t *, intptr_t, int);
static int bscv_ioc_stats(bscv_soft_state_t *, intptr_t, int);
static int bscv_ioc_temp(bscv_soft_state_t *, intptr_t, int);
static int bscv_ioc_cons(bscv_soft_state_t *, intptr_t, int);
static int bscv_ioc_eventlog2(bscv_soft_state_t *, intptr_t, int);
static int bscv_ioc_info2(bscv_soft_state_t *, intptr_t, int);
static int bscv_ioc_test(bscv_soft_state_t *, intptr_t, int);
static int bscv_ioc_mprog2(bscv_soft_state_t *, intptr_t, int);
static int bscv_ioc_mread2(bscv_soft_state_t *, intptr_t, int);

static void bscv_event_daemon(void *);
static void bscv_start_event_daemon(bscv_soft_state_t *);
static int bscv_stop_event_daemon(bscv_soft_state_t *);
static int bscv_pause_event_daemon(bscv_soft_state_t *);
static void bscv_resume_event_daemon(bscv_soft_state_t *);
static void bscv_event_process(bscv_soft_state_t *ssp, boolean_t);
static int bscv_event_validate(bscv_soft_state_t *, uint32_t, uint8_t);
static void bscv_event_process_one(bscv_soft_state_t *, lom_event_t *);
static void bscv_build_eventstring(bscv_soft_state_t *,
    lom_event_t *, char *, char *);
static int bscv_level_of_event(lom_event_t *);
static void bscv_status(bscv_soft_state_t *, uint8_t, uint8_t);
char *bscv_get_label(char [][MAX_LOM2_NAME_STR], int, int);
static void bscv_generic_sysevent(bscv_soft_state_t *, char *, char *, char *,
    char *, int32_t, char *);
static void bscv_sysevent(bscv_soft_state_t *, lom_event_t *);

static int bscv_prog(bscv_soft_state_t *, intptr_t, int);
static int bscv_prog_image(bscv_soft_state_t *, boolean_t,
    uint8_t *, int, uint32_t);
static int bscv_prog_receive_image(bscv_soft_state_t *, lom_prog_t *,
    uint8_t *, int);
static void bscv_leave_programming_mode(bscv_soft_state_t *, boolean_t);
static int bscv_prog_stop_lom(bscv_soft_state_t *);
static int bscv_prog_start_lom(bscv_soft_state_t *);

static int bscv_attach_common(bscv_soft_state_t *);
static int bscv_cleanup(bscv_soft_state_t *);
static void bscv_setup_capability(bscv_soft_state_t *);
static int bscv_probe_check(bscv_soft_state_t *);
static void bscv_setup_hostname(bscv_soft_state_t *);
static void bscv_read_hostname(bscv_soft_state_t *, char *);
static void bscv_write_hostname(bscv_soft_state_t *, char *, uint8_t);
static void bscv_setup_static_info(bscv_soft_state_t *);
static uint8_t bscv_read_env_name(bscv_soft_state_t *, uint8_t,
    uint8_t, uint8_t, char [][MAX_LOM2_NAME_STR], int);
static void bscv_setup_events(bscv_soft_state_t *);

static void bscv_trace(bscv_soft_state_t *, char, const char *,
    const char *, ...);

#ifdef __sparc
static void bscv_idi_init();
static void bscv_idi_fini();
static void bscv_idi_new_instance(dev_info_t *dip);
static void bscv_idi_clear_err();
void bscv_idi_set(struct bscv_idi_info info);
static boolean_t bscv_idi_err();
static boolean_t bscv_nodename_set(struct bscv_idi_info info);
static boolean_t bscv_sig_set(struct bscv_idi_info info);
static boolean_t bscv_wdog_pat(struct bscv_idi_info info);
static boolean_t bscv_wdog_cfg(struct bscv_idi_info info);
static void bscv_write_sig(bscv_soft_state_t *ssp, bscv_sig_t s);
#endif /* __sparc */

static void bscv_setup_watchdog(bscv_soft_state_t *ssp);
static void bscv_write_wdog_cfg(bscv_soft_state_t *,
    uint_t, boolean_t, uint8_t);

#if defined(__i386) || defined(__amd64)
static void bscv_inform_bsc(bscv_soft_state_t *, uint32_t);
static void bscv_watchdog_pat_request(void *);
static void bscv_watchdog_cfg_request(bscv_soft_state_t *, uint8_t);
static uint_t bscv_set_watchdog_timer(bscv_soft_state_t *, uint_t);
static void bscv_clear_watchdog_timer(bscv_soft_state_t *);

static boolean_t bscv_panic_callback(void *, int);
static void bscv_watchdog_cyclic_add(bscv_soft_state_t *);
static void bscv_watchdog_cyclic_remove(bscv_soft_state_t *);

static uint8_t	wdog_reset_on_timeout = 1;

#define	WDOG_ON			1
#define	WDOG_OFF		0
#define	CLK_WATCHDOG_DEFAULT	10		/* 10 seconds */
#define	WATCHDOG_PAT_INTERVAL	1000000000	/* 1 second */

static int	bscv_watchdog_enable;
static int	bscv_watchdog_available;
static int	watchdog_activated;
static uint_t	bscv_watchdog_timeout_seconds;
#endif /* __i386 || __amd64 */

#ifdef __sparc
struct bscv_idi_callout bscv_idi_callout_table[] = {
	{BSCV_IDI_NODENAME,	&bscv_nodename_set	},
	{BSCV_IDI_SIG,		&bscv_sig_set		},
	{BSCV_IDI_WDOG_PAT,	&bscv_wdog_pat		},
	{BSCV_IDI_WDOG_CFG,	&bscv_wdog_cfg		},
	{BSCV_IDI_NULL,		NULL			}
};

static struct bscv_idi_callout_mgr bscv_idi_mgr;
#endif /* __sparc */

/*
 * Local Definitions
 */
#define	STATUS_READ_LIMIT	8   /* Read up to 8 status changes at a time */
#define	MYNAME			"bscv"
#define	BSCV_INST_TO_MINOR(i)	(i)
#define	BSCV_MINOR_TO_INST(m)	(m)

/*
 * Strings for daemon event reporting
 */

static char *eventSubsysStrings[] =
{	"",				/* 00 */
	"Alarm ",			/* 01 */
	"temperature sensor ",		/* 02 */
	"overheat sensor ",		/* 03 */
	"Fan ",				/* 04 */
	"supply rail ",			/* 05 */
	"circuit breaker ",		/* 06 */
	"PSU ",				/* 07 */
	"user ",			/* 08 */
	"phonehome ",			/* 09; unutilized */
	"LOM ",				/* 0a */
	"host ",			/* 0b */
	"event log ",			/* 0c */
	"",				/* 0d; EVENT_SUBSYS_EXTRA unutilized */
	"LED ",				/* 0e */
};

static char *eventTypeStrings[] =
{
	"[null event]",			/* 00 */
	"ON",				/* 01 */
	"OFF",				/* 02 */
	"state change",			/* 03 */
	"power on",			/* 04 */
	"power off",			/* 05 */
	"powered off unexpectedly",	/* 06 */
	"reset unexpectedly",		/* 07 */
	"booted",			/* 08 */
	"watchdog enabled",		/* 09 */
	"watchdog disabled",		/* 0a */
	"watchdog triggered",		/* 0b */
	"failed",			/* 0c */
	"recovered",			/* 0d */
	"reset",			/* 0e */
	"XIR reset",			/* 0f */
	"console selected",		/* 10 */
	"time reference",		/* 11 */
	"script failure",		/* 12 */
	"modem access failure",		/* 13 */
	"modem dialing failure",	/* 14 */
	"bad checksum",			/* 15 */
	"added",			/* 16 */
	"removed",			/* 17 */
	"changed",			/* 18 */
	"login",			/* 19 */
	"password changed",		/* 1a */
	"login failed",			/* 1b */
	"logout",			/* 1c */
	"flash download",		/* 1d */
	"data lost",			/* 1e */
	"device busy",			/* 1f */
	"fault led state",		/* 20 */
	"overheat",			/* 21 */
	"severe overheat",		/* 22 */
	"no overheat",			/* 23 */
	"SCC",				/* 24 */
	"device inaccessible",		/* 25 */
	"Hostname change",		/* 26 */
	"CPU signature timeout",	/* 27 */
	"Bootmode change",		/* 28 */
	"Watchdog change policy",	/* 29 */
	"Watchdog change timeout",	/* 2a */
};

/*
 * These store to mapping between the logical service, e.g. chan_prog for
 * programming, and the actual Xbus channel which carries that traffic.
 * Any services can be shared on the same channel apart from chan_wdogpat.
 */
static int chan_general;	/* General Traffic */
static int chan_wdogpat;	/* Watchdog Patting */
static int chan_cpusig;		/* CPU signatures */
static int chan_eeprom;		/* EEPROM I/O */
static int chan_prog;		/* Programming */

/*
 * cb_ops structure defining the driver entry points
 */

static struct cb_ops bscv_cb_ops = {
	bscv_open,	/* open */
	bscv_close,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	bscv_ioctl,	/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,	/* prop op */
	NULL,		/* ! STREAMS */
	D_NEW | D_MP	/* MT/MP Safe */
};

/*
 * dev_ops structure defining autoconfiguration driver autoconfiguration
 * routines
 */

static struct dev_ops bscv_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	bscv_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	bscv_attach,		/* devo_attach */
	bscv_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&bscv_cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)0,	/* devo_bus_ops */
	NULL,			/* devo_power */
	bscv_quiesce,		/* devo_quiesce */
};

/*
 * module configuration section
 */

#ifdef DEBUG
#define	BSCV_VERSION_STRING "bscv driver - Debug"
#else /* DEBUG */
#define	BSCV_VERSION_STRING "bscv driver"
#endif /* DEBUG */

static struct modldrv modldrv = {
	&mod_driverops,
	BSCV_VERSION_STRING,
	&bscv_dev_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

#ifdef DEBUG
/* Tracing is enabled if value is non-zero. */
static int bscv_trace_flag = 1;

#define	BSCV_TRACE   if (bscv_trace_flag != 0)	bscv_trace
#else
#define	BSCV_TRACE(...) (void)(0)
#endif

/*
 * kernel accessible routines. These routines are necessarily global so the
 * driver can be loaded, and unloaded successfully
 */

/*
 * function	- _init
 * description	- initializes the driver state structure and installs the
 *		  driver module into the kernel
 * inputs	- none
 * outputs	- success or failure of module installation
 */

int
_init(void)
{
	register int e;

	if ((e = ddi_soft_state_init(&bscv_statep,
	    sizeof (bscv_soft_state_t), 1)) != 0) {
		return (e);
	}

	if ((e = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&bscv_statep);
	}

#ifdef __sparc
	if (e == 0) bscv_idi_init();
#endif /* __sparc */
	return (e);
}

/*
 * function	- _info
 * description	- provide information about a kernel loaded module
 * inputs	- module infomation
 * outputs	- success or failure of information request
 */

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * function	- _fini
 * description	- removes a module from the kernel and frees the driver soft
 *		  state memory
 * inputs	- none
 * outputs	- success or failure of module removal
 */

int
_fini(void)
{
	register int e;

	if ((e = mod_remove(&modlinkage)) != 0) {
		return (e);
	}

#ifdef __sparc
	bscv_idi_fini();
#endif /* __sparc */
	ddi_soft_state_fini(&bscv_statep);

	return (e);
}

/*
 * function	- bscv_getinfo
 * description	- routine used to provide information on the driver
 * inputs	- device information structure, command, command arg, storage
 *		  area for the result
 * outputs	- DDI_SUCCESS or DDI_FAILURE
 */

/*ARGSUSED*/
static int
bscv_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	bscv_soft_state_t *ssp;
	dev_t	dev = (dev_t)arg;
	int	instance;
	int	error;

	instance = DEVICETOINSTANCE(dev);

	switch (cmd) {
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		error = DDI_SUCCESS;
		break;

	case DDI_INFO_DEVT2DEVINFO:
		ssp = ddi_get_soft_state(bscv_statep, instance);
		if (ssp == NULL)
			return (DDI_FAILURE);
		*result = (void *) ssp->dip;
		error = DDI_SUCCESS;
		break;

	default:
		error = DDI_FAILURE;
		break;
	}

	return (error);
}

#ifdef __sparc
void
bscv_idi_init()
{
	bscv_idi_mgr.valid_inst = (uint32_t)~0;    /* No valid instances */
	bscv_idi_mgr.tbl = bscv_idi_callout_table;
	bscv_idi_mgr.errs = 0;

	/*
	 * Now that all fields are initialized, set the magic flag.  This is
	 * a kind of integrity check for the data structure.
	 */
	bscv_idi_mgr.magic = BSCV_IDI_CALLOUT_MAGIC;
}

static void
bscv_idi_clear_err()
{
	ASSERT(bscv_idi_mgr.magic == BSCV_IDI_CALLOUT_MAGIC);

	bscv_idi_mgr.errs = 0;
}

/*
 * function	- bscv_idi_err
 * description	- error messaging service which throttles the number of error
 *		  messages to avoid overflowing storage
 * inputs	- none
 * returns	- boolean to indicate whether a message should be reported
 * side-effects	- updates the error number counter
 */
static boolean_t
bscv_idi_err()
{
	ASSERT(bscv_idi_mgr.magic == BSCV_IDI_CALLOUT_MAGIC);

	bscv_idi_mgr.errs++;

	if (bscv_idi_mgr.errs++ < BSCV_IDI_ERR_MSG_THRESHOLD)
		return (B_TRUE);

	return (B_FALSE);
}

void
bscv_idi_new_instance(dev_info_t *dip)
{
	ASSERT(bscv_idi_mgr.magic == BSCV_IDI_CALLOUT_MAGIC);

	/*
	 * We don't care how many instances we have, or their value, so long
	 * as we have at least one valid value.  This is so service routines
	 * can get any required locks via a soft state pointer.
	 */
	if (bscv_idi_mgr.valid_inst == (uint32_t)~0) {
		bscv_idi_mgr.valid_inst = ddi_get_instance(dip);
	}
}

void
bscv_idi_fini()
{
	bscv_idi_mgr.valid_inst = (uint32_t)~0;    /* No valid instances */
	bscv_idi_mgr.tbl = NULL;
}
#endif /* __sparc */

/*
 * function	- bscv_attach
 * description	- this routine is responsible for setting aside memory for the
 *		  driver data structures, initialising the mutexes and creating
 *		  the device minor nodes. Additionally, this routine calls the
 *		  the callback routine.
 * inputs	- device information structure, DDI_ATTACH command
 * outputs	- DDI_SUCCESS or DDI_FAILURE
 */

int
bscv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	bscv_soft_state_t *ssp;
	int	instance;

	switch (cmd) {
	case DDI_ATTACH:

		instance = ddi_get_instance(dip);

		if (ddi_soft_state_zalloc(bscv_statep, instance) !=
		    DDI_SUCCESS) {
			return (DDI_FAILURE);
		}


		ssp = ddi_get_soft_state(bscv_statep, instance);

		ssp->progress = 0;

		ssp->dip = dip;
		ssp->instance = instance;
		ssp->event_waiting = B_FALSE;
		ssp->status_change = B_FALSE;
		ssp->nodename_change = B_FALSE;
		ssp->cap0 = 0;
		ssp->cap1 = 0;
		ssp->cap2 = 0;
		ssp->prog_mode_only = B_FALSE;
		ssp->programming = B_FALSE;
		ssp->cssp_prog = B_FALSE;
		ssp->task_flags = 0;
		ssp->debug = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "debug", 0);
		ssp->majornum = ddi_driver_major(dip);
		ssp->minornum = BSCV_INST_TO_MINOR(instance);
#if defined(__i386) || defined(__amd64)
		ssp->last_nodename[0] = '\0';
#endif /* __i386 || __amd64 */

		/*
		 * initialise the mutexes
		 */

		mutex_init(&ssp->cmd_mutex, NULL, MUTEX_DRIVER, NULL);

		mutex_init(&ssp->task_mu, NULL, MUTEX_DRIVER, NULL);
		cv_init(&ssp->task_cv, NULL, CV_DRIVER, NULL);
		cv_init(&ssp->task_evnt_cv, NULL, CV_DRIVER, NULL);
		mutex_init(&ssp->prog_mu, NULL, MUTEX_DRIVER, NULL);
		ssp->progress |= BSCV_LOCKS;

		BSCV_TRACE(ssp, 'A', "bscv_attach",
		    "bscv_attach: mutexes and condition vars initialised");

		/* Map in physical communication channels */

		if (bscv_map_regs(ssp) != DDI_SUCCESS) {
			(void) bscv_cleanup(ssp);
			return (DDI_FAILURE);
		}
		ssp->progress |= BSCV_MAPPED_REGS;

		/* Associate logical channels to physical channels */

		bscv_map_chan_logical_physical(ssp);

		bscv_enter(ssp);

		bscv_leave_programming_mode(ssp, B_FALSE);

		if (bscv_attach_common(ssp) == DDI_FAILURE) {
			bscv_exit(ssp);
			(void) bscv_cleanup(ssp);
			return (DDI_FAILURE);
		}

#ifdef __sparc
		/*
		 * At this point the inter-driver-interface is made available.
		 * The IDI uses the event thread service which
		 * bscv_attach_common() sets up.
		 */
		bscv_idi_new_instance(dip);
#endif /* __sparc */

		bscv_exit(ssp);

		/*
		 * now create the minor nodes
		 */
		if (ddi_create_minor_node(ssp->dip, "lom", S_IFCHR,
		    BSCV_INST_TO_MINOR(instance),
		    DDI_PSEUDO, 0) != DDI_SUCCESS) {
			(void) bscv_cleanup(ssp);
			return (DDI_FAILURE);
		}
		BSCV_TRACE(ssp, 'A', "bscv_attach",
		    "bscv_attach: device minor nodes created");
		ssp->progress |= BSCV_NODES;

		if (!ssp->prog_mode_only)
			bscv_start_event_daemon(ssp);

#if defined(__i386) || defined(__amd64)
		bscv_watchdog_enable = 1;
		bscv_watchdog_available = 1;
		watchdog_activated = 0;
		bscv_watchdog_timeout_seconds = CLK_WATCHDOG_DEFAULT;

		if (bscv_watchdog_enable && (boothowto & RB_DEBUG)) {
			bscv_watchdog_available = 0;
			cmn_err(CE_WARN, "bscv: kernel debugger "
			    "detected: hardware watchdog disabled");
		}

		/*
		 * Before we enable the watchdog - register the panic
		 * callback so that we get called to stop the watchdog
		 * in the case of a panic.
		 */
		ssp->callb_id = callb_add(bscv_panic_callback,
		    (void *)ssp, CB_CL_PANIC, "");

		if (bscv_watchdog_available) {
			(void) bscv_set_watchdog_timer(ssp,
			    CLK_WATCHDOG_DEFAULT);
			bscv_enter(ssp);
			bscv_setup_watchdog(ssp);  /* starts cyclic callback */
			bscv_exit(ssp);
		}
#endif /* __i386 || __amd64 */
		ddi_report_dev(dip);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

/*
 * function	- bscv_detach
 * description	- routine that prepares a module to be unloaded. It undoes all
 *		  the work done by the bscv_attach)() routine. This is
 *		  facilitated by the use of the progress indicator
 * inputs	- device information structure, DDI_DETACH command
 * outputs	- DDI_SUCCESS or DDI_FAILURE
 */

/*ARGSUSED*/
static int
bscv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	return (DDI_FAILURE);
}

/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
static int
bscv_quiesce(dev_info_t *dip)
{
	bscv_soft_state_t *ssp;
	int	instance;


	instance = ddi_get_instance(dip);
	ssp = ddi_get_soft_state(bscv_statep, instance);
	if (ssp == NULL) {
		return (DDI_FAILURE);
	}
#ifdef DEBUG
	/* Disable tracing, as we are executing at High-Interrupt level */
	bscv_trace_flag = 0;
#endif
	/* quiesce the device */
	bscv_full_stop(ssp);

	return (DDI_SUCCESS);
}

/*
 * cb_ops routines
 */

/*
 * function	- bscv_open
 * description	- routine to provide association between user fd and device
 *		  minor number. This routine is necessarily simple since a
 *		  read/write interface is not provided. Additionally, the
 *		  driver does not enforce exclusive access (FEXCL) or
 *		  non-blocking during an open (FNDELAY). Deferred attach is
 *		  supported.
 * inputs	- device number, flag specifying open type, device type,
 *		  permissions
 * outputs	- success or failure of operation
 */

/*ARGSUSED*/
static int
bscv_open(dev_t *devp, int flag, int otype, cred_t *cred)
{
	bscv_soft_state_t *ssp;
	int instance;

	instance = DEVICETOINSTANCE(*devp);
	ssp = ddi_get_soft_state(bscv_statep, instance);
	if (ssp == NULL) {
		return (ENXIO);	/* not attached yet */
	}
	BSCV_TRACE(ssp, 'O', "bscv_open", "instance 0x%x", instance);

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	return (0);
}

/*
 * function	- bscv_close
 * description	- routine to perform the final close on the device. As per the
 *		  open routine, neither FEXCL or FNDELAY accesses are enforced
 *		  by the driver.
 * inputs	- device number,flag specifying open type, device type,
 *		  permissions
 * outputs	- success or failure of operation
 */

/*ARGSUSED1*/
static int
bscv_close(dev_t dev, int flag, int otype, cred_t *cred)
{
	bscv_soft_state_t *ssp;
	int instance;

	instance = DEVICETOINSTANCE(dev);
	ssp = ddi_get_soft_state(bscv_statep, instance);
	if (ssp == NULL) {
		return (ENXIO);
	}
	BSCV_TRACE(ssp, 'O', "bscv_close", "instance 0x%x", instance);

	return (0);
}

static int
bscv_map_regs(bscv_soft_state_t *ssp)
{
	int i;
	int retval;
	int *props;
	unsigned int nelements;

	ASSERT(ssp);

	ssp->nchannels = 0;

	/*
	 * Work out how many channels are available by looking at the number
	 * of elements of the regs property array.
	 */
	retval = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, ssp->dip,
	    DDI_PROP_DONTPASS, "reg", &props, &nelements);

	/* We don't need props anymore.  Free memory if it was allocated */
	if (retval == DDI_PROP_SUCCESS)
		ddi_prop_free(props);

	/* Check for sanity of nelements */
	if (retval != DDI_PROP_SUCCESS) {
		BSCV_TRACE(ssp, 'A', "bscv_map_regs", "lookup reg returned"
		    " 0x%x", retval);
		goto cleanup_exit;
	} else if (nelements % LOMBUS_REGSPEC_SIZE != 0) {
		BSCV_TRACE(ssp, 'A', "bscv_map_regs", "nelements %d not"
		    " a multiple of %d", nelements, LOMBUS_REGSPEC_SIZE);
		goto cleanup_exit;
	} else if (nelements > BSCV_MAXCHANNELS * LOMBUS_REGSPEC_SIZE) {
		BSCV_TRACE(ssp, 'A', "bscv_map_regs", "nelements %d too large"
		    ", probably a misconfiguration", nelements);
		goto cleanup_exit;
	} else if (nelements < BSCV_MINCHANNELS * LOMBUS_REGSPEC_SIZE) {
		BSCV_TRACE(ssp, 'A', "bscv_map_regs", "nelements %d too small"
		    ", need to have at least a general and a wdog channel",
		    nelements);
		goto cleanup_exit;
	}

	ssp->nchannels = nelements / LOMBUS_REGSPEC_SIZE;

	ssp->attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	ssp->attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	ssp->attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	for (i = 0; i < ssp->nchannels; i++) {
		retval = ddi_regs_map_setup(ssp->dip, i,
		    (caddr_t *)&ssp->channel[i].regs,
		    0, 0, &ssp->attr, &ssp->channel[i].handle);
		if (retval != DDI_SUCCESS) {
			BSCV_TRACE(ssp, 'A', "bscv_map_regs", "map failure"
			    " 0x%x on space %d", retval, i);

			/* Rewind all current mappings - avoiding failed one */
			i--;
			for (; i >= 0; i--) {
				ddi_regs_map_free(&ssp->channel[i].handle);
			}

			goto cleanup_exit;
		}
	}

	return (DDI_SUCCESS);

cleanup_exit:
	/*
	 * It is important to set nchannels to 0 even if, say, only one of
	 * the two required handles was mapped.  If we cannot achieve our
	 * minimum config its not safe to do any IO; this keeps our failure
	 * mode handling simpler.
	 */
	ssp->nchannels = 0;
	return (DDI_FAILURE);
}

static void
bscv_unmap_regs(bscv_soft_state_t *ssp)
{
	int i;

	ASSERT(ssp);

	for (i = 0; i < ssp->nchannels; i++) {
		ddi_regs_map_free(&ssp->channel[i].handle);
	}
}

/*
 * Map logical services onto physical XBus channels.
 */
static void
bscv_map_chan_logical_physical(bscv_soft_state_t *ssp)
{
	ASSERT(ssp);

	/*
	 * We can assert that there will always be at least two channels,
	 * to allow watchdog pats to be segregated from all other traffic.
	 */
	chan_general = 0;
	chan_wdogpat = 1;

	/*
	 * By default move all other services onto the generic channel unless
	 * the hardware supports additional channels.
	 */

	chan_cpusig = chan_eeprom = chan_prog = chan_general;

	if (ssp->nchannels > 2)
		chan_cpusig = 2;
	if (ssp->nchannels > 3)
		chan_eeprom = 3;
	if (ssp->nchannels > 4)
		chan_prog = 4;
}


/*
 * function	- bscv_full_stop
 * description	- gracefully shut the lom down during panic or reboot.
 *		  Disables the watchdog and sets up serial event reporting.
 * inputs	- soft state pointer
 * outputs	- none
 */
void
bscv_full_stop(bscv_soft_state_t *ssp)
{
	uint8_t bits2set = 0;
	uint8_t bits2clear = 0;
	int obtained_lock;

	BSCV_TRACE(ssp, 'W', "bscv_full_stop",
	    "turning off watchdog");

	/*
	 * Obtain the softstate lock only if it is not already owned,
	 * as this function can be called from a High-level interrupt
	 * context.  As a result, our thread cannot sleep.
	 * At end of function, our thread releases the lock only if
	 * it acquired the lock.
	 */
	obtained_lock = (bscv_tryenter(ssp) != 0);

#if defined(__i386) || defined(__amd64)
	if (ddi_in_panic()) {
		bscv_inform_bsc(ssp, BSC_INFORM_PANIC);
	} else {
		bscv_inform_bsc(ssp, BSC_INFORM_OFFLINE);
	}
#endif /* __i386 || __amd64 */

	/* set serial event reporting */
	switch (ssp->serial_reporting) {
	case LOM_SER_EVENTS_ON:
	case LOM_SER_EVENTS_DEF:
		/* Make sure serial event reporting is on */
		bits2clear = EBUS_ALARM_NOEVENTS;
		break;
	case LOM_SER_EVENTS_OFF:
		/* Make sure serial event reporting is on */
		bits2set = EBUS_ALARM_NOEVENTS;
		break;
	default:
		break;
	}
	bscv_setclear8_volatile(ssp, chan_general,
	    EBUS_IDX_ALARM, bits2set, bits2clear);

	/* Do not free the lock if our thread did not obtain it. */
	if (obtained_lock != 0) {
		bscv_exit(ssp);
	}
}

/*
 * LOM I/O routines.
 *
 * locking
 *
 * Two sets of routines are provided:
 *	normal - must be called after acquiring an appropriate lock.
 *	locked - perform all the locking required and return any error
 *		 code in the supplied 'res' argument. If there is no
 *		 error 'res' is not changed.
 * The locked routines are designed for use in ioctl commands where
 * only a single operation needs to be performed and the overhead of
 * locking and result checking adds significantly to code complexity.
 *
 * locking primitives
 *
 * bscv_enter()    - acquires an I/O lock for the calling thread.
 * bscv_tryenter() - conditionally acquires an I/O lock for calling thread.
 * bscv_exit()     - releases an I/O lock acquired by bscv_enter().
 * bscv_held()     - used to assert ownership of an I/O lock.
 *
 * normal I/O routines
 *
 * Note bscv_{put|get}{16|32} routines are big-endian. This assumes that
 * the firmware works that way too.
 *
 * bscv_put8(), bscv_put16, bscv_put32 - write values to the LOM
 *		and handle any retries if necessary.
 *		16 and 32 bit values are big-endian.
 * bscv_get8(), bscv_get16, bscv_get32 - read values from the LOM
 *		and handle any retries if necessary.
 *		16 and 32 bit values are big-endian.
 * bscv_setclear8() - set or clear the specified bits in the register
 *		at the supplied address.
 * bscv_setclear8_volatile() - set or clear the specified bits in the
 *		register at the supplied address. If the lom reports
 *		that the registers has changed since the last read
 *		re-read and apply the set or clear to the new bits.
 * bscv_get8_cached() - Return a cached register value (addr < 0x80).
 *		Does not access the hardware. A read of the hardware
 *		automatically updates this cache.
 *
 * locked I/O routines
 *
 * bscv_get8_locked(), bscv_rep_get8_locked().
 *
 * Call the indicated function from above, but wrapping it with
 * bscv_enter()/bscv_exit().
 *
 *
 * Fault management
 *
 * LOM communications fault are grouped into three categories:
 * 1) Faulty - the LOM is not responding and no attempt to communicate
 *		with it should be made.
 * 2) Transient fault - something which might recover after a retry
 *		but which doesn't affect our ability to perform other
 *		commands.
 * 3) Command error - an inappropriate command was executed. A retry
 *		will not fix it but the command failed.
 *
 * The current implementation of the bscv driver is not very good at
 * noticing command errors due to the structure of the original code
 * that it is based on. It is possible to extend the driver to do this
 * and would probably involve having a concept of a "session error"
 * which is less severe than a fault but means that a sequence of
 * commands had some fault which cannot be recovered.
 *
 *
 * faults
 *
 * bscv_faulty() - returns B_TRUE if the LOM (communications) have been
 *		declared faulty.
 * bscv_clear_fault() - marks the LOM as not faulty.
 * bscv_set_fault() - marks the LOM as being faulty.
 *
 * bscv_clear_fault and bscv_set_fault should generally not be called
 * directly.
 *
 * command errors/transient faults
 *
 * bscv_retcode() - returns the actual error code of the last operation.
 * bscv_should_retry() - determines if last operation may suceed if
 *		retried.
 * bscv_locked_result() - Set the result of a locked register access.
 *
 * low level I/O primitives
 *
 * These are generally not called directly. These perform a single
 * access to the LOM device. They do not handle retries.
 *
 * bscv_put8_once()
 * bscv_get8_once()
 * bscv_probe() - perform a probe (NOP) operation to check out lom comms.
 * bscv_resync_comms() - resynchronise communications after a transient fault.
 */

static void
bscv_enter(bscv_soft_state_t *ssp)
{
	BSCV_TRACE(ssp, '@', "bscv_enter", "");
	mutex_enter(&ssp->cmd_mutex);
	ssp->had_session_error = B_FALSE;
}

static int
bscv_tryenter(bscv_soft_state_t *ssp)
{
	int rv;

	BSCV_TRACE(ssp, '@', "bscv_tryenter", "");
	if ((rv = mutex_tryenter(&ssp->cmd_mutex)) != 0) {
		ssp->had_session_error = B_FALSE;
	}
	return (rv);
}

static void
bscv_exit(bscv_soft_state_t *ssp)
{
	mutex_exit(&ssp->cmd_mutex);
	BSCV_TRACE(ssp, '@', "bscv_exit", "");
}

#ifdef DEBUG
static int
bscv_held(bscv_soft_state_t *ssp)
{
	return (mutex_owned(&ssp->cmd_mutex));
}
#endif /* DEBUG */

static void
bscv_put8(bscv_soft_state_t *ssp, int chan, bscv_addr_t addr, uint8_t val)
{
	boolean_t needretry;
	int num_failures;

	ASSERT(bscv_held(ssp));

	if (bscv_faulty(ssp)) {
		return;
	}

	BSCV_TRACE(ssp, '@', "bscv_put8",
	    "addr 0x%x.%02x <= 0x%02x", addr >> 8, addr & 0xff, val);

	for (num_failures = 0;
	    num_failures < BSC_FAILURE_RETRY_LIMIT;
	    num_failures++) {
		bscv_put8_once(ssp, chan, addr, val);
		needretry = bscv_should_retry(ssp);
		if (!needretry) {
			break;
		}
	}
	if (ssp->command_error != 0) {
		ssp->had_session_error = B_TRUE;
	}

	if (needretry) {
		/* Failure - we ran out of retries */
		cmn_err(CE_WARN, "bscv_put8: addr 0x%x.%02x retried "
		    "write %d times, giving up",
		    addr >> 8, addr & 0xff, num_failures);
		bscv_set_fault(ssp);
	} else if (num_failures > 0) {
		BSCV_TRACE(ssp, 'R', "bscv_put8",
		    "addr 0x%x.%02x retried write %d times, succeeded",
		    addr >> 8, addr & 0xff, num_failures);
	}
}

static void
bscv_put16(bscv_soft_state_t *ssp, int chan, bscv_addr_t addr, uint16_t val)
{
	ASSERT(bscv_held(ssp));
	BSCV_TRACE(ssp, '@', "bscv_put16",
	    "addr 0x%x.%02x <= %04x", addr >> 8, addr & 0xff, val);
	bscv_put8(ssp, chan, addr, val >> 8);
	bscv_put8(ssp, chan, addr + 1, val & 0xff);
}

static void
bscv_put32(bscv_soft_state_t *ssp, int chan, bscv_addr_t addr, uint32_t val)
{
	ASSERT(bscv_held(ssp));
	BSCV_TRACE(ssp, '@', "bscv_put32",
	    "addr 0x%x.%02x <= %08x", addr >> 8, addr & 0xff, val);
	bscv_put8(ssp, chan, addr, (val >> 24) & 0xff);
	bscv_put8(ssp, chan, addr + 1, (val >> 16) & 0xff);
	bscv_put8(ssp, chan, addr + 2, (val >> 8) & 0xff);
	bscv_put8(ssp, chan, addr + 3, val & 0xff);
}

static uint8_t
bscv_get8(bscv_soft_state_t *ssp, int chan, bscv_addr_t addr)
{
	uint8_t retval;
	boolean_t needretry;
	int num_failures;

	ASSERT(bscv_held(ssp));

	if (bscv_faulty(ssp)) {
		return (0);
	}

	for (num_failures = 0;
	    num_failures < BSC_FAILURE_RETRY_LIMIT;
	    num_failures++) {
		retval = bscv_get8_once(ssp, chan, addr);
		needretry = bscv_should_retry(ssp);
		if (!needretry) {
			break;
		}
	}
	if (ssp->command_error != 0) {
		ssp->had_session_error = B_TRUE;
	}

	if (needretry) {
		/* Failure */
		cmn_err(CE_WARN, "bscv_get8: addr 0x%x.%02x retried "
		    "read %d times, giving up",
		    addr >> 8, addr & 0xff, num_failures);
		bscv_set_fault(ssp);
	} else if (num_failures > 0) {
		BSCV_TRACE(ssp, 'R', "bscv_get8",
		    "addr 0x%x.%02x retried read %d times, succeeded",
		    addr >> 8, addr & 0xff, num_failures);
	}

	BSCV_TRACE(ssp, '@', "bscv_get8",
	    "addr 0x%x.%02x => %02x", addr >> 8, addr & 0xff, retval);
	return (retval);
}

static uint16_t
bscv_get16(bscv_soft_state_t *ssp, int chan, bscv_addr_t addr)
{
	uint16_t retval;

	ASSERT(bscv_held(ssp));

	retval = bscv_get8(ssp, chan, addr) << 8;
	retval |= bscv_get8(ssp, chan, addr + 1);

	BSCV_TRACE(ssp, '@', "bscv_get16",
	    "addr 0x%x.%02x => %04x", addr >> 8, addr & 0xff, retval);
	return (retval);
}

static uint32_t
bscv_get32(bscv_soft_state_t *ssp, int chan, bscv_addr_t addr)
{
	uint32_t retval;

	ASSERT(bscv_held(ssp));

	retval = bscv_get8(ssp, chan, addr) << 24;
	retval |= bscv_get8(ssp, chan, addr + 1) << 16;
	retval |= bscv_get8(ssp, chan, addr + 2) << 8;
	retval |= bscv_get8(ssp, chan, addr + 3);

	BSCV_TRACE(ssp, '@', "bscv_get32",
	    "addr 0x%x.%02x => %08x", addr >> 8, addr & 0xff, retval);
	return (retval);
}

static void
bscv_setclear8(bscv_soft_state_t *ssp, int chan,
    bscv_addr_t addr, uint8_t set, uint8_t clear)
{
	uint8_t val;

	ASSERT(bscv_held(ssp));
	ASSERT(addr < BSC_ADDR_CACHE_LIMIT);

	val = ssp->lom_regs[addr] | set;
	val &= ~clear;

	BSCV_TRACE(ssp, '@', "bscv_setclear8",
	    "addr 0x%x.%02x, set %02x, clear %02x => %02x",
	    addr >> 8, addr & 0xff,
	    set, clear, val);

	bscv_put8(ssp, chan, addr, val);
}

static void
bscv_setclear8_volatile(bscv_soft_state_t *ssp, int chan,
    bscv_addr_t addr, uint8_t set, uint8_t clear)
{
	uint8_t val;
	boolean_t needretry;
	int num_failures;

	ASSERT(bscv_held(ssp));
	ASSERT(addr < BSC_ADDR_CACHE_LIMIT);

	if (bscv_faulty(ssp)) {
		return;
	}

	BSCV_TRACE(ssp, '@', "bscv_setclear8_volatile",
	    "addr 0x%x.%02x => set %02x clear %02x",
	    addr >> 8, addr & 0xff, set, clear);

	val = bscv_get8_cached(ssp, addr);
	for (num_failures = 0;
	    num_failures < BSC_FAILURE_RETRY_LIMIT;
	    num_failures++) {
		val |= set;
		val &= ~clear;
		bscv_put8_once(ssp, chan, addr, val);
		if (ssp->command_error == EBUS_ERROR_STALEDATA) {
			/* Re-read the stale register from the lom */
			val = bscv_get8_once(ssp, chan, addr);
			needretry = 1;
		} else {
			needretry = bscv_should_retry(ssp);
			if (!needretry) {
				break;
			}
		}
	}
	if (ssp->command_error != 0) {
		ssp->had_session_error = B_TRUE;
	}

	if (needretry) {
		/* Failure */
		cmn_err(CE_WARN, "bscv_setclear8_volatile: addr 0x%x.%02x "
		    "retried write %d times, giving up",
		    addr >> 8, addr & 0xff, num_failures);
		if (ssp->command_error != EBUS_ERROR_STALEDATA) {
			bscv_set_fault(ssp);
		}
	} else if (num_failures > 0) {
		BSCV_TRACE(ssp, 'R', "bscv_setclear8_volatile",
		    "addr 0x%x.%02x retried write %d times, succeeded",
		    addr >> 8, addr & 0xff, num_failures);
	}
}

static void
bscv_rep_rw8(bscv_soft_state_t *ssp, int chan, uint8_t *host_addr,
    bscv_addr_t dev_addr, size_t repcount, uint_t flags,
    boolean_t is_write)
{
	size_t inc;

	ASSERT(bscv_held(ssp));

	inc = (flags & DDI_DEV_AUTOINCR) ? 1 : 0;
	for (; repcount--; dev_addr += inc) {
		if (flags & DDI_DEV_AUTOINCR) {
			if (is_write) {
				bscv_put8(ssp, chan, dev_addr, *host_addr++);
			} else {
				*host_addr++ = bscv_get8(ssp, chan, dev_addr);
			}
		} else {
			if (is_write) {
				bscv_put8_once(ssp, chan,
				    dev_addr, *host_addr++);
			} else {
				*host_addr++ = bscv_get8_once(ssp, chan,
				    dev_addr);
			}
			/* We need this because _once routines don't do it */
			if (ssp->command_error != 0) {
				ssp->had_session_error = B_TRUE;
			}
		}
		if (bscv_faulty(ssp) || bscv_session_error(ssp)) {
			/*
			 * No retry here. If we were AUTOINCR then get/put
			 * will have retried. For NO_AUTOINCR we cannot retry
			 * because the data would be corrupted.
			 */
			break;
		}
	}
}

static uint8_t
bscv_get8_cached(bscv_soft_state_t *ssp, bscv_addr_t addr)
{
	ASSERT(addr < BSC_ADDR_CACHE_LIMIT);
	/* Can be called with or without the lock held */

	return (ssp->lom_regs[addr]);
}

static uint8_t
bscv_get8_locked(bscv_soft_state_t *ssp, int chan, bscv_addr_t addr, int *res)
{
	uint8_t retval;

	ASSERT(addr < BSC_ADDR_CACHE_LIMIT);
	bscv_enter(ssp);
	retval = bscv_get8(ssp, chan, addr);
	bscv_locked_result(ssp, res);
	bscv_exit(ssp);
	BSCV_TRACE(ssp, '@', "bscv_get8_locked",
	    "addr 0x%x.%02x => %02x", addr >> 8, addr & 0xff, retval);
	return (retval);
}

static void
bscv_rep_get8_locked(bscv_soft_state_t *ssp, int chan, uint8_t *host_addr,
    bscv_addr_t dev_addr, size_t repcount, uint_t flags, int *res)
{
	bscv_enter(ssp);
	bscv_rep_rw8(ssp, chan, host_addr, dev_addr, repcount,
	    flags, B_FALSE /* read */);
	bscv_locked_result(ssp, res);
	bscv_exit(ssp);
}

static boolean_t
bscv_faulty(bscv_soft_state_t *ssp)
{
	ASSERT(bscv_held(ssp));
	return (ssp->had_fault);
}

static void
bscv_clear_fault(bscv_soft_state_t *ssp)
{
	ASSERT(bscv_held(ssp));
	BSCV_TRACE(ssp, 'J', "bscv_clear_fault", "clearing fault flag");
	ssp->had_fault = B_FALSE;
	ssp->had_session_error = B_FALSE;
}

static void
bscv_set_fault(bscv_soft_state_t *ssp)
{
	ASSERT(bscv_held(ssp));
	BSCV_TRACE(ssp, 'J', "bscv_set_fault", "setting fault flag");
	ssp->had_fault = B_TRUE;
}

static boolean_t
bscv_session_error(bscv_soft_state_t *ssp)
{
	ASSERT(bscv_held(ssp));
	return (ssp->had_session_error);
}

static int
bscv_retcode(bscv_soft_state_t *ssp)
{
	BSCV_TRACE(ssp, '@', "bscv_retcode",
	    "code 0x%x", ssp->command_error);
	return (ssp->command_error);
}

static int
bscv_should_retry(bscv_soft_state_t *ssp)
{
	if ((ssp->command_error == EBUS_ERROR_DEVICEFAIL) ||
	    (ssp->command_error >= LOMBUS_ERR_BASE)) {
		/* This command is due to an I/O fault - retry might fix */
		return (1);
	} else {
		/*
		 * The command itself was bad - there is no point in fixing
		 * Note. Whatever happens we should know that if we were
		 * doing EBUS_IDX_SELFTEST0..EBUS_IDX_SELFTEST7 and we
		 * had 0x80 set then this is a test error not a retry
		 * error.
		 */
		return (0);
	}
}

static void
bscv_locked_result(bscv_soft_state_t *ssp, int *res)
{
	if (bscv_faulty(ssp) || (bscv_retcode(ssp) != 0)) {
		*res = EIO;
	}
}

static void
bscv_put8_once(bscv_soft_state_t *ssp, int chan, bscv_addr_t addr, uint8_t val)
{
	uint32_t fault;

	ASSERT(bscv_held(ssp));

	ssp->command_error = 0;

	if (bscv_faulty(ssp)) {
		/* Bail out things are not working */
		return;
	} else if (ssp->nchannels == 0) {
		/* Didn't manage to map handles so ddi_{get,put}* broken */
		BSCV_TRACE(ssp, '@', "bscv_put8_once",
		    "nchannels is 0x0 so cannot do IO");
		return;
	}

	/* Clear any pending fault */
	ddi_put32(ssp->channel[chan].handle,
	    (uint32_t *)BSC_NEXUS_ADDR(ssp, chan, 0, LOMBUS_FAULT_REG), 0);

	/* Do the access and get fault code - may take a long time */
	ddi_put8(ssp->channel[chan].handle,
	    &ssp->channel[chan].regs[addr], val);
	fault = ddi_get32(ssp->channel[chan].handle,
	    (uint32_t *)BSC_NEXUS_ADDR(ssp, chan, 0, LOMBUS_FAULT_REG));

	ssp->command_error = fault;

	if (fault == 0) {
		/* Things were ok - update cache entry */
		if (addr < BSC_ADDR_CACHE_LIMIT) {
			/* Store cacheable entries */
			ssp->lom_regs[addr] = val;
		}
	} else if (fault >= LOMBUS_ERR_BASE) {
		/* lombus problem - do a resync session */
		cmn_err(CE_WARN, "!bscv_put8_once: Had comms fault "
		    "for address 0x%x.%02x - data 0x%x, fault 0x%x",
		    addr >> 8, addr & 0xff, val, fault);
		/* Attempt to resync with the lom */
		bscv_resync_comms(ssp, chan);
		/*
		 * Note: we do not set fault status here. That
		 * is done if our caller decides to give up talking to
		 * the lom. The observant might notice that this means
		 * that if we mend things on the last attempt we still
		 * get the fault set - we just live with that!
		 */
	}

	BSCV_TRACE(ssp, '@', "bscv_put8_once",
	    "addr 0x%x.%02x <= 0x%02x", addr >> 8, addr & 0xff, val);
}

static uint8_t
bscv_get8_once(bscv_soft_state_t *ssp, int chan, bscv_addr_t addr)
{
	uint8_t val;
	uint32_t fault;

	ASSERT(bscv_held(ssp));

	ssp->command_error = 0;

	if (bscv_faulty(ssp)) {
		/* Bail out things are not working */
		return (0xff);
	} else if (ssp->nchannels == 0) {
		/* Didn't manage to map handles so ddi_{get,put}* broken */
		BSCV_TRACE(ssp, '@', "bscv_get8_once",
		    "nchannels is 0x0 so cannot do IO");
		return (0xff);
	}

	/* Clear any pending fault */
	ddi_put32(ssp->channel[chan].handle,
	    (uint32_t *)BSC_NEXUS_ADDR(ssp, chan, 0, LOMBUS_FAULT_REG), 0);

	/* Do the access and get fault code - may take a long time */
	val = ddi_get8(ssp->channel[chan].handle,
	    &ssp->channel[chan].regs[addr]);
	fault = ddi_get32(ssp->channel[chan].handle,
	    (uint32_t *)BSC_NEXUS_ADDR(ssp, chan, 0, LOMBUS_FAULT_REG));
	ssp->command_error = fault;

	if (fault >= LOMBUS_ERR_BASE) {
		/* lombus problem - do a resync session */
		cmn_err(CE_WARN, "!bscv_get8_once: Had comms fault "
		    "for address 0x%x.%02x - data 0x%x, fault 0x%x",
		    addr >> 8, addr & 0xff, val, fault);
		/* Attempt to resync with the lom */
		bscv_resync_comms(ssp, chan);
		/*
		 * Note: we do not set fault status here. That
		 * is done if our caller decides to give up talking to
		 * the lom. The observant might notice that this means
		 * that if we mend things on the last attempt we still
		 * get the fault set - we just live with that!
		 */
	}
	/*
	 * FIXME - should report error if you get
	 * EBUS_ERROR_DEVICEFAIL reported from the BSC. That gets
	 * logged as a failure in bscv_should_retry and may contribute
	 * to a permanent failure. Reference issues seen by Mitac.
	 */

	if (!bscv_faulty(ssp)) {
		if (addr < BSC_ADDR_CACHE_LIMIT) {
			/* Store cacheable entries */
			ssp->lom_regs[addr] = val;
		}
	}

	BSCV_TRACE(ssp, '@', "bscv_get8_once",
	    "addr 0x%x.%02x => 0x%02x", addr >> 8, addr & 0xff, val);
	return (val);
}

static uint32_t
bscv_probe(bscv_soft_state_t *ssp, int chan, uint32_t *fault)
{
	uint32_t async_reg;

	if (ssp->nchannels == 0) {
		/*
		 * Failed to map handles, so cannot do any IO.  Set the
		 * fault indicator and return a dummy value.
		 */
		BSCV_TRACE(ssp, '@', "bscv_probe",
		    "nchannels is 0x0 so cannot do any IO");
		*fault = LOMBUS_ERR_REG_NUM;
		return ((~(int8_t)0));
	}

	/* Clear faults */
	ddi_put32(ssp->channel[chan].handle,
	    (uint32_t *)BSC_NEXUS_ADDR(ssp, chan, 0, LOMBUS_FAULT_REG), 0);
	/* Probe and Check faults */
	*fault = ddi_get32(ssp->channel[chan].handle,
	    (uint32_t *)BSC_NEXUS_ADDR(ssp, chan, 0, LOMBUS_PROBE_REG));
	/* Read status */
	async_reg = ddi_get32(ssp->channel[chan].handle,
	    (uint32_t *)BSC_NEXUS_ADDR(ssp, chan, 0, LOMBUS_ASYNC_REG));

	BSCV_TRACE(ssp, '@', "bscv_probe",
	    "async status 0x%x, fault 0x%x", async_reg, *fault);
	return (async_reg);
}

static void
bscv_resync_comms(bscv_soft_state_t *ssp, int chan)
{
	int try;
	uint32_t command_error = ssp->command_error;
	uint32_t fault = 0;

	if (ssp->nchannels == 0) {
		/*
		 * Didn't manage to map handles so ddi_{get,put}* broken.
		 * Therefore, there is no way to resync comms.
		 */
		BSCV_TRACE(ssp, '@', "bscv_resync_comms",
		    "nchannels is 0x0 so not possible to resync comms");
		return;
	}
	if (command_error >= LOMBUS_ERR_BASE &&
	    command_error != LOMBUS_ERR_REG_NUM &&
	    command_error != LOMBUS_ERR_REG_SIZE &&
	    command_error != LOMBUS_ERR_TIMEOUT) {
		/* Resync here to make sure that the lom is talking */
		cmn_err(CE_WARN, "!bscv_resync_comms: "
		    "Attempting comms resync after comms fault 0x%x",
		    command_error);
		for (try = 1; try <= 8; try++) {
			/* Probe */
			fault = ddi_get32(ssp->channel[chan].handle,
			    (uint32_t *)BSC_NEXUS_ADDR(ssp, chan, 0,
			    LOMBUS_PROBE_REG));

			if (fault == 0) {
				break;
			} else {
				cmn_err(CE_WARN, "!bscv_resync_comms: "
				    "comms resync (probing) - try 0x%x "
				    "had fault 0x%x", try, fault);
			}
		}
		if (fault != 0) {
			cmn_err(CE_WARN, "!bscv_resync_comms: "
			    "Failed to resync comms - giving up");
			ssp->bad_resync++;
		} else {
			cmn_err(CE_WARN, "!bscv_resync_comms: "
			    "resync comms after 0x%x tries", try);
			ssp->bad_resync = 0;
		}
	}

}


/*
 * LOMLite configuration/event eeprom access routines
 *
 * bscv_window_setup() - Read/Sanity check the eeprom parameters.
 *		This must be called prior to calling bscv_eerw().
 * bscv_eerw() - Read/write data from/to the eeprom.
 */

/*
 * function	- bscv_window_setup
 * description	- this routine reads the eeprom parameters and sanity
 *		  checks them to ensure that the lom is talking sense.
 * inputs	- soft state ptr
 * outputs	- B_TRUE if the eeprom is ok, B_FALSE if the eeprom is not OK.
 */
static boolean_t
bscv_window_setup(bscv_soft_state_t *ssp)
{
	ASSERT(bscv_held(ssp));

	if (ssp->eeinfo_valid) {
		/* Already have good cached values */
		return (ssp->eeinfo_valid);
	}
	ssp->eeprom_size =
	    bscv_get8(ssp, chan_general, EBUS_IDX_EEPROM_SIZE_KB) * 1024;
	ssp->eventlog_start = bscv_get16(ssp, chan_general,
	    EBUS_IDX_LOG_START_HI);

	/*
	 * The log does not run to the end of the EEPROM because it is a
	 * logical partition.  The last 8K partition is reserved for FRUID
	 * usage.
	 */
	ssp->eventlog_size = EBUS_LOG_END - ssp->eventlog_start;

	BSCV_TRACE(ssp, 'I', "bscv_window_setup", "eeprom size 0x%x log_start"
	    " 0x%x log_size 0x%x", ssp->eeprom_size, ssp->eventlog_start,
	    ssp->eventlog_size);

	if (bscv_faulty(ssp) || bscv_session_error(ssp)) {
		ssp->eeinfo_valid = B_FALSE;
	} else if ((ssp->eeprom_size == 0) ||
	    (ssp->eventlog_start >= ssp->eeprom_size)) {
		/* Sanity check values */
		cmn_err(CE_WARN,
		    "!bscv_window_setup: read invalid eeprom parameters");
		ssp->eeinfo_valid = B_FALSE;
	} else {
		ssp->eeinfo_valid = B_TRUE;
	}

	BSCV_TRACE(ssp, 'I', "bscv_window_setup", "returning eeinfo_valid %s",
	    ssp->eeinfo_valid ? "true" : "false");
	return (ssp->eeinfo_valid);
}

/*
 * function	- bscv_eerw
 * description	- this routine reads/write data from/to the eeprom.
 *		  It takes care of setting the window on the eeprom correctly.
 * inputs	- soft state ptr, eeprom offset, data buffer, size, read/write
 * outputs	- B_TRUE if the eeprom is ok, B_FALSE if the eeprom is not OK.
 */
static int
bscv_eerw(bscv_soft_state_t *ssp, uint32_t eeoffset, uint8_t *buf,
    unsigned size, boolean_t is_write)
{
	uint32_t blk_addr = eeoffset;
	unsigned remaining = size;
	uint8_t page_idx;
	uint8_t this_page;
	uint8_t blk_size;
	int res = 0;

	while (remaining > 0) {
		page_idx = blk_addr & 0xff;
		if ((page_idx + remaining) > 0x100) {
			blk_size = 0x100 - page_idx;
		} else {
			blk_size = remaining;
		}

		/* Select correct eeprom page */
		this_page = blk_addr >> 8;
		bscv_put8(ssp, chan_eeprom, EBUS_IDX_EEPROM_PAGESEL, this_page);

		BSCV_TRACE(ssp, 'M', "lom_eerw",
		    "%s data @0x%x.%02x, size 0x%x, 0x%x bytes remaining",
		    is_write ? "writing" : "reading",
		    this_page, page_idx, blk_size, remaining - blk_size);

		bscv_rep_rw8(ssp, chan_eeprom,
		    buf, BSCVA(EBUS_CMD_SPACE_EEPROM, page_idx),
		    blk_size, DDI_DEV_AUTOINCR, is_write);

		if (bscv_faulty(ssp) || bscv_session_error(ssp)) {
			res = EIO;
			break;
		}

		remaining -= blk_size;
		blk_addr += blk_size;
		buf += blk_size;
	}

	return (res);
}

static boolean_t
bscv_is_null_event(bscv_soft_state_t *ssp, lom_event_t *e)
{
	ASSERT(e != NULL);

	if (EVENT_DECODE_SUBSYS(e->ev_subsys) == EVENT_SUBSYS_NONE &&
	    e->ev_event == EVENT_NONE) {
		/*
		 * This marks a NULL event.
		 */
		BSCV_TRACE(ssp, 'E', "bscv_is_null_event",
		    "EVENT_SUBSYS_NONE/EVENT_NONE null event");
		return (B_TRUE);
	} else if (e->ev_subsys == 0xff && e->ev_event == 0xff) {
		/*
		 * Under some circumstances, we've seen all 1s to represent
		 * a manually cleared event log at the BSC prompt.  Only
		 * a test/diagnosis environment is likely to show this.
		 */
		BSCV_TRACE(ssp, 'E', "bscv_is_null_event", "0xffff null event");
		return (B_TRUE);
	} else {
		/*
		 * Not a NULL event.
		 */
		BSCV_TRACE(ssp, 'E', "bscv_is_null_event", "returning False");
		return (B_FALSE);
	}
}

/*
 * *********************************************************************
 * IOCTL Processing
 * *********************************************************************
 */

/*
 * function	- bscv_ioctl
 * description	- routine that acts as a high level manager for ioctls. It
 *		  calls the appropriate handler for ioctls on the alarm:mon and
 *		  alarm:ctl minor nodes respectively
 *
 *		  Unsupported ioctls (now deprecated)
 *			LOMIOCALCTL
 *			LOMIOCALSTATE
 *			LOMIOCCLEARLOG
 *			LOMIOCCTL
 *			LOMIOCCTL2
 *			LOMIOCDAEMON
 *			LOMIOCDMON
 *			LOMIOCDOGCTL, TSIOCDOGCTL
 *			LOMIOCDOGPAT, TSIOCDOGPAT
 *			LOMIOCDOGTIME, TSIOCDOGTIME
 *			LOMIOCEVENTLOG
 *			LOMIOCEVNT
 *			LOMIOCGETMASK
 *			LOMIOCMPROG
 *			LOMIOCNBMON, TSIOCNBMON
 *			LOMIOCSLEEP
 *			LOMIOCUNLOCK, TSIOCUNLOCK
 *			LOMIOCWTMON, TSIOCWTMON
 *
 *		  Supported ioctls
 *			LOMIOCDOGSTATE, TSIOCDOGSTATE
 *			LOMIOCPROG
 *			LOMIOCPSUSTATE
 *			LOMIOCFANSTATE
 *			LOMIOCFLEDSTATE
 *			LOMIOCINFO
 *			LOMIOCMREAD
 *			LOMIOCVOLTS
 *			LOMIOCSTATS
 *			LOMIOCTEMP
 *			LOMIOCCONS
 *			LOMIOCEVENTLOG2
 *			LOMIOCINFO2
 *			LOMIOCTEST
 *			LOMIOCMPROG2
 *			LOMIOCMREAD2
 *
 * inputs	- device number, command, user space arg, filemode, user
 *		  credentials, return value
 * outputs	- the return value propagated back by the lower level routines.
 */

/*ARGSUSED*/
static int
bscv_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	bscv_soft_state_t *ssp;
	int instance;
	int res = 0;

	instance = DEVICETOINSTANCE(dev);
	ssp = ddi_get_soft_state(bscv_statep, instance);
	if (ssp == NULL) {
		return (ENXIO);
	}

	/*
	 * The Combined Switch and Service Processor takes care of configuration
	 * and control.  The CSSP tells the BSC chip about it; therefore the
	 * bscv driver doesn't send such configuration and control to the BSC.
	 * Additionally Watchdog configuration is no longer done from userland
	 * lom.
	 */
	switch (cmd) {
	case LOMIOCALCTL:
	case LOMIOCALSTATE:
	case LOMIOCCLEARLOG:
	case LOMIOCCTL:
	case LOMIOCCTL2:
	case LOMIOCDAEMON:
	case LOMIOCDMON:
	case LOMIOCDOGCTL:
	case LOMIOCDOGPAT:
	case LOMIOCDOGTIME:
	case LOMIOCEVENTLOG:
	case LOMIOCEVNT:
	case LOMIOCGETMASK:
	case LOMIOCMPROG:
	case LOMIOCNBMON:
	case LOMIOCSLEEP:
	case LOMIOCUNLOCK:
	case LOMIOCWTMON:
		return (ENOTSUP);
	}

	/*
	 * set the default result.
	 */

	*rvalp = 0;

	if (ssp->cssp_prog) {
		return (ENXIO);
	} else if ((ssp->prog_mode_only || ssp->programming) &&
	    cmd != LOMIOCPROG) {
		return (ENXIO);
	}

	/*
	 * Check that the caller has appropriate access permissions
	 * (FWRITE set in mode) for those ioctls which change lom
	 * state
	 */
	if (!(mode & FWRITE)) {
		switch (cmd) {
		case LOMIOCMPROG2:
		case LOMIOCMREAD2:
		case LOMIOCPROG:
		case LOMIOCTEST:
			return (EACCES);
			/* NOTREACHED */
		default:
			/* Does not require write access */
			break;
		}
	}

	switch (cmd) {

	case LOMIOCDOGSTATE:
		res = bscv_ioc_dogstate(ssp, arg, mode);
		break;

	case LOMIOCPROG:
		res = bscv_prog(ssp, arg, mode);
		break;

	case LOMIOCPSUSTATE:
		res = bscv_ioc_psustate(ssp, arg, mode);
		break;

	case LOMIOCFANSTATE:
		res = bscv_ioc_fanstate(ssp, arg, mode);
		break;

	case LOMIOCFLEDSTATE:
		res = bscv_ioc_fledstate(ssp, arg, mode);
		break;

	case LOMIOCLEDSTATE:
		res = bscv_ioc_ledstate(ssp, arg, mode);
		break;

	case LOMIOCINFO:
		res = bscv_ioc_info(ssp, arg, mode);
		break;

	case LOMIOCMREAD:
		res = bscv_ioc_mread(ssp, arg, mode);
		break;

	case LOMIOCVOLTS:
		res = bscv_ioc_volts(ssp, arg, mode);
		break;

	case LOMIOCSTATS:
		res = bscv_ioc_stats(ssp, arg, mode);
		break;

	case LOMIOCTEMP:
		res = bscv_ioc_temp(ssp, arg, mode);
		break;

	case LOMIOCCONS:
		res = bscv_ioc_cons(ssp, arg, mode);
		break;

	case LOMIOCEVENTLOG2:
		res = bscv_ioc_eventlog2(ssp, arg, mode);
		break;

	case LOMIOCINFO2:
		res = bscv_ioc_info2(ssp, arg, mode);
		break;

	case LOMIOCTEST:
		res = bscv_ioc_test(ssp, arg, mode);
		break;

	case LOMIOCMPROG2:
		res = bscv_ioc_mprog2(ssp, arg, mode);
		break;

	case LOMIOCMREAD2:
		res = bscv_ioc_mread2(ssp, arg, mode);
		break;

	default:
		BSCV_TRACE(ssp, 'I', "bscv_ioctl", "Invalid IOCTL 0x%x", cmd);
		res = EINVAL;
	}
	return (res);
}

/*
 * LOMIOCDOGSTATE
 * TSIOCDOGSTATE - indicate whether the alarm watchdog and reset
 * circuitry is enabled or not.
 */
static int
bscv_ioc_dogstate(bscv_soft_state_t *ssp, intptr_t arg, int mode)
{
	lom_dogstate_t dogstate;
	uint8_t dogval;
	int res = 0;

	dogval = bscv_get8_locked(ssp, chan_general, EBUS_IDX_WDOG_CTRL, &res);
	dogstate.dog_enable = (dogval & EBUS_WDOG_ENABLE) ? 1 : 0;
	dogstate.reset_enable = (dogval & EBUS_WDOG_RST) ? 1 : 0;
	dogstate.dog_timeout = bscv_get8_locked(ssp, chan_general,
	    EBUS_IDX_WDOG_TIME, &res);

	if ((res == 0) &&
	    (ddi_copyout((caddr_t)&dogstate,
	    (caddr_t)arg, sizeof (dogstate), mode) < 0)) {
		res = EFAULT;
	}
	return (res);
}

/*
 * LOMIOCPSUSTATE - returns full information for 4 PSUs. All this
 * information is available from two bytes of LOMlite RAM, but if
 * on the first read it is noticed that two or more of the PSUs are
 * not present only 1 byte will be read subsequently.
 */
static int
bscv_ioc_psustate(bscv_soft_state_t *ssp, intptr_t arg, int mode)
{
	lom_psudata_t psudata;
	uint8_t psustat;
	int i;
	int res = 0;

	for (i = 0; i < MAX_PSUS; i++) {
		psustat = bscv_get8_locked(ssp, chan_general,
		    EBUS_IDX_PSU1_STAT + i, &res);
		psudata.fitted[i] = psustat & EBUS_PSU_PRESENT;
		psudata.output[i] = psustat & EBUS_PSU_OUTPUT;
		psudata.supplyb[i] = psustat & EBUS_PSU_INPUTB;
		psudata.supplya[i] = psustat & EBUS_PSU_INPUTA;
		psudata.standby[i] = psustat & EBUS_PSU_STANDBY;
	}

	if (ddi_copyout((caddr_t)&psudata, (caddr_t)arg, sizeof (psudata),
	    mode) < 0) {
		res = EFAULT;
	}
	return (res);
}

/*
 * LOMIOCFANSTATE - returns full information including speed for 4
 * fans and the minimum and maximum operating speeds for each fan as
 * stored in the READ ONLY EEPROM data. As this EEPROM data is set
 * at manufacture time, this data should only be read by the driver
 * once and stored locally.
 */
static int
bscv_ioc_fanstate(bscv_soft_state_t *ssp, intptr_t arg, int mode)
{
	lom_fandata_t fandata;
	int numfans;
	int i;
	int res = 0;

	bzero(&fandata, sizeof (lom_fandata_t));
	numfans = EBUS_CONFIG_NFAN_DEC(bscv_get8_locked(ssp,
	    chan_general, EBUS_IDX_CONFIG, &res));
	for (i = 0; (i < numfans) && (res == 0); i++) {
		if (ssp->fanspeed[i] != LOM_FAN_NOT_PRESENT) {
			fandata.fitted[i] = 1;
			fandata.speed[i] = ssp->fanspeed[i];
			fandata.minspeed[i] = bscv_get8_cached(ssp,
			    EBUS_IDX_FAN1_LOW + i);
		}
	}

	if ((res == 0) &&
	    (ddi_copyout((caddr_t)&fandata, (caddr_t)arg, sizeof (fandata),
	    mode) < 0)) {
		res = EFAULT;
	}
	return (res);
}

/*
 * LOMIOCFLEDSTATE - returns the state of the fault LED
 */
static int
bscv_ioc_fledstate(bscv_soft_state_t *ssp, intptr_t arg, int mode)
{
	lom_fled_info_t fled_info;
	uint8_t fledstate;
	int res = 0;

	fledstate = bscv_get8_locked(ssp, chan_general, EBUS_IDX_ALARM, &res);

	/* Decode of 0x0F is off and 0x00-0x07 is on. */
	if (EBUS_ALARM_LED_DEC(fledstate) == 0x0F) {
		fled_info.on = 0;
	} else {
		/* has +1 here - not 2 as in the info ioctl */
		fled_info.on = EBUS_ALARM_LED_DEC(fledstate) + 1;
	}
	if ((res == 0) &&
	    (ddi_copyout((caddr_t)&fled_info, (caddr_t)arg,
	    sizeof (fled_info), mode) < 0)) {
		res = EFAULT;
	}
	return (res);
}

/*
 * LOMIOCLEDSTATE - returns the state of the requested LED
 */
static int
bscv_ioc_ledstate(bscv_soft_state_t *ssp, intptr_t arg, int mode)
{
	lom_led_state_t led_state;
	int fw_led_state;
	int res = 0;

	/* copy in arguments supplied */
	if (ddi_copyin((caddr_t)arg, (caddr_t)&led_state,
	    sizeof (lom_led_state_t), mode) < 0) {
		return (EFAULT);
	}

	/*
	 * check if led index is -1, if so set it to max value for
	 * this implementation.
	 */
	if (led_state.index == -1) {
		led_state.index = MAX_LED_ID;
	}

	/* is the index in a valid range */
	if ((led_state.index > MAX_LED_ID) || (led_state.index < 0)) {
		led_state.state = LOM_LED_OUTOFRANGE;
	} else {
		/* read the relevant led info */
		fw_led_state = bscv_get8_locked(ssp, chan_general,
		    EBUS_IDX_LED1_STATUS + led_state.index, &res);

		/* set the state values accordingly */
		switch (fw_led_state) {
		case LOM_LED_STATE_OFF:
			led_state.state = LOM_LED_OFF;
			led_state.colour = LOM_LED_COLOUR_ANY;
			break;
		case LOM_LED_STATE_ON_STEADY:
			led_state.state = LOM_LED_ON;
			led_state.colour = LOM_LED_COLOUR_ANY;
			break;
		case LOM_LED_STATE_ON_FLASHING:
		case LOM_LED_STATE_ON_SLOWFLASH:
			led_state.state = LOM_LED_BLINKING;
			led_state.colour = LOM_LED_COLOUR_ANY;
			break;
		case LOM_LED_STATE_NOT_PRESENT:
			led_state.state = LOM_LED_NOT_IMPLEMENTED;
			led_state.colour = LOM_LED_COLOUR_NONE;
			break;
		case LOM_LED_STATE_INACCESSIBLE:
		case LOM_LED_STATE_STANDBY:
		default:
			led_state.state = LOM_LED_ACCESS_ERROR;
			led_state.colour = LOM_LED_COLOUR_NONE;
			break;
		}

		/* set the label info */
		(void) strcpy(led_state.label,
		    ssp->led_names[led_state.index]);
	}

	/* copy out lom_state */
	if ((res == 0) &&
	    (ddi_copyout((caddr_t)&led_state, (caddr_t)arg,
	    sizeof (lom_led_state_t), mode) < 0)) {
		res = EFAULT;
	}
	return (res);
}

/*
 * LOMIOCINFO - returns with a structure containing any information
 * stored on the LOMlite which a user should not need to access but
 * may be useful for diagnostic problems. The structure contains: the
 * serial escape character, alarm3 mode, version and checksum read from
 * RAM and the Product revision and ID read from EEPROM.
 */
static int
bscv_ioc_info(bscv_soft_state_t *ssp, intptr_t arg, int mode)
{
	lom_info_t info;
	int i;
	uint16_t csum;
	int res = 0;

	info.ser_char = bscv_get8_locked(ssp, chan_general, EBUS_IDX_ESCAPE,
	    &res);
	info.a3mode = WATCHDOG;
	info.fver = bscv_get8_locked(ssp, chan_general, EBUS_IDX_FW_REV, &res);
	csum = bscv_get8_locked(ssp, chan_general, EBUS_IDX_CHECK_HI, &res)
	    << 8;
	csum |= bscv_get8_locked(ssp, chan_general, EBUS_IDX_CHECK_LO, &res);
	info.fchksum = csum;
	info.prod_rev = bscv_get8_locked(ssp, chan_general, EBUS_IDX_MODEL_REV,
	    &res);
	for (i = 0; i < sizeof (info.prod_id); i++) {
		info.prod_id[i] = bscv_get8_locked(ssp,
		    chan_general, EBUS_IDX_MODEL_ID1 + i, &res);
	}
	if (bscv_get8_locked(ssp, chan_general, EBUS_IDX_ALARM, &res) &
	    EBUS_ALARM_NOEVENTS) {
		info.events = OFF;
	} else {
		info.events = ON;
	}

	if ((res == 0) &&
	    (ddi_copyout((caddr_t)&info, (caddr_t)arg, sizeof (info),
	    mode) < 0)) {
		res = EFAULT;
	}
	return (res);
}

/*
 * LOMIOCMREAD - used to query the LOMlite configuration parameters
 */
static int
bscv_ioc_mread(bscv_soft_state_t *ssp, intptr_t arg, int mode)
{
	lom_mprog_t mprog;
	int i;
	int fanz;
	int res = 0;

	for (i = 0; i < sizeof (mprog.mod_id); i++) {
		mprog.mod_id[i] = bscv_get8_locked(ssp, chan_general,
		    EBUS_IDX_MODEL_ID1 + i, &res);
	}
	mprog.mod_rev = bscv_get8_locked(ssp, chan_general, EBUS_IDX_MODEL_REV,
	    &res);
	mprog.config = bscv_get8_locked(ssp, chan_general, EBUS_IDX_CONFIG,
	    &res);

	/* Read the fan calibration values */
	fanz = sizeof (mprog.fanhz) / sizeof (mprog.fanhz[0]);
	for (i = 0; i < fanz; i++) {
		mprog.fanhz[i] = bscv_get8_cached(ssp,
		    EBUS_IDX_FAN1_CAL + i);
		mprog.fanmin[i] = bscv_get8_cached(ssp,
		    EBUS_IDX_FAN1_LOW + i);
	}

	if ((res == 0) &&
	    (ddi_copyout((caddr_t)&mprog, (caddr_t)arg, sizeof (mprog),
	    mode) < 0)) {
		res = EFAULT;
	}
	return (res);
}

/*
 * LOMIOCVOLTS
 */
static int
bscv_ioc_volts(bscv_soft_state_t *ssp, intptr_t arg, int mode)
{
	int i;
	uint16_t supply;
	int res = 0;

	supply = (bscv_get8_locked(ssp, chan_general, EBUS_IDX_SUPPLY_HI, &res)
	    << 8) | bscv_get8_locked(ssp, chan_general, EBUS_IDX_SUPPLY_LO,
	    &res);

	for (i = 0; i < ssp->volts.num; i++) {
		ssp->volts.status[i] = (supply >> i) & 1;
	}

	if ((res == 0) &&
	    (ddi_copyout((caddr_t)&ssp->volts, (caddr_t)arg,
	    sizeof (ssp->volts), mode) < 0)) {
		res = EFAULT;
	}
	return (res);
}

/*
 * LOMIOCSTATS
 */
static int
bscv_ioc_stats(bscv_soft_state_t *ssp, intptr_t arg, int mode)
{
	int i;
	uint8_t status;
	int res = 0;

	status = bscv_get8_locked(ssp, chan_general, EBUS_IDX_CBREAK_STATUS,
	    &res);
	for (i = 0; i < ssp->sflags.num; i++) {
		ssp->sflags.status[i] = (int)((status >> i) & 1);
	}

	if ((res == 0) &&
	    (ddi_copyout((caddr_t)&ssp->sflags, (caddr_t)arg,
	    sizeof (ssp->sflags), mode) < 0)) {
		res = EFAULT;
	}
	return (res);
}

/*
 * LOMIOCTEMP
 */
static int
bscv_ioc_temp(bscv_soft_state_t *ssp, intptr_t arg, int mode)
{
	int i;
	int idx;
	uint8_t status_ov;
	lom_temp_t temps;
	int res = 0;

	bzero(&temps, sizeof (temps));
	idx = 0;
	for (i = 0; i < ssp->temps.num; i++) {
		if (ssp->temps.temp[i] != LOM_TEMP_STATE_NOT_PRESENT) {
			temps.temp[idx] = ssp->temps.temp[i];
			bcopy(ssp->temps.name[i], temps.name[idx],
			    sizeof (temps.name[idx]));
			temps.warning[idx] = ssp->temps.warning[i];
			temps.shutdown[idx] = ssp->temps.shutdown[i];
			idx++;
		}
	}
	temps.num = idx;

	bcopy(ssp->temps.name_ov, temps.name_ov, sizeof (temps.name_ov));
	temps.num_ov = ssp->temps.num_ov;
	status_ov = bscv_get8_locked(ssp, chan_general, EBUS_IDX_OTEMP_STATUS,
	    &res);
	for (i = 0; i < ssp->temps.num_ov; i++) {
		ssp->temps.status_ov[i] = (status_ov >> i) & 1;
	}

	if ((res == 0) &&
	    (ddi_copyout((caddr_t)&temps, (caddr_t)arg, sizeof (temps),
	    mode) < 0)) {
		res = EFAULT;
	}
	return (res);
}

/*
 * LOMIOCCONS
 */
static int
bscv_ioc_cons(bscv_soft_state_t *ssp, intptr_t arg, int mode)
{
	lom_cbuf_t cbuf;
	int datasize;
	int res = 0;

	bzero(&cbuf, sizeof (cbuf));
	datasize = EBUS_IDX1_CONS_BUF_END - EBUS_IDX1_CONS_BUF_START + 1;
	/* Ensure that we do not overfill cbuf and that it is NUL terminated */
	if (datasize > (sizeof (cbuf) - 1)) {
		datasize = sizeof (cbuf) - 1;
	}
	bscv_rep_get8_locked(ssp, chan_general, (uint8_t *)cbuf.lrbuf,
	    BSCVA(EBUS_CMD_SPACE1, (EBUS_IDX1_CONS_BUF_END - datasize + 1)),
	    datasize, DDI_DEV_AUTOINCR, &res);
	/* This is always within the array due to the checks above */
	cbuf.lrbuf[datasize] = '\0';

	if ((res == 0) &&
	    (ddi_copyout((caddr_t)&cbuf, (caddr_t)arg, sizeof (cbuf),
	    mode) < 0)) {
		res = EFAULT;
	}
	return (res);
}

/*
 * LOMIOCEVENTLOG2
 */
static int
bscv_ioc_eventlog2(bscv_soft_state_t *ssp, intptr_t arg, int mode)
{
	lom_eventlog2_t *eventlog2;
	int events_recorded;
	int level;
	uint16_t next_offset;
	lom_event_t event;
	int res = 0;

	eventlog2 = (lom_eventlog2_t *)kmem_zalloc(sizeof (*eventlog2),
	    KM_SLEEP);

	/*
	 * First get number of events and level requested.
	 */

	if (ddi_copyin((caddr_t)arg, (caddr_t)eventlog2,
	    sizeof (lom_eventlog2_t), mode) < 0) {
		kmem_free((void *)eventlog2, sizeof (*eventlog2));
		return (EFAULT);
	}

	bscv_enter(ssp);

	/*
	 * OK we have full private access to the LOM now so loop
	 * over the eventlog addr spaces until we get the required
	 * number of events.
	 */

	if (!bscv_window_setup(ssp)) {
		res = EIO;
		bscv_exit(ssp);
		kmem_free((void *)eventlog2, sizeof (*eventlog2));
		return (res);
	}

	/*
	 * Read count, next event ptr MSB,LSB. Note a read of count
	 * is necessary to latch values for the next event ptr
	 */
	(void) bscv_get8(ssp, chan_general, EBUS_IDX_UNREAD_EVENTS);
	next_offset = bscv_get16(ssp, chan_general, EBUS_IDX_LOG_PTR_HI);
	BSCV_TRACE(ssp, 'I', "bscv_ioc_eventlog2", "log_ptr_hi 0x%x",
	    next_offset);

	events_recorded = 0;

	while (events_recorded < eventlog2->num) {
		/*
		 * Working backwards - read an event at a time.
		 * next_offset is one event on from where we want to be!
		 * Decrement next_offset and maybe wrap to the end of the
		 * buffer.
		 * Note the unsigned arithmetic, so check values first!
		 */
		if (next_offset <= ssp->eventlog_start) {
			/* Wrap to the end of the buffer */
			next_offset = ssp->eventlog_start + ssp->eventlog_size;
			BSCV_TRACE(ssp, 'I', "bscv_ioc_eventlog2", "wrapping"
			    " around to end of buffer; next_offset 0x%x",
			    next_offset);
		}
		next_offset -= sizeof (event);

		if (bscv_eerw(ssp, next_offset, (uint8_t *)&event,
		    sizeof (event), B_FALSE /* read */) != 0) {
			/* Fault reading data - stop */
			BSCV_TRACE(ssp, 'I', "bscv_ioc_eventlog2", "read"
			    " failure for offset 0x%x", next_offset);
			res = EIO;
			break;
		}

		if (bscv_is_null_event(ssp, &event)) {
			/*
			 * No more events in this log so give up.
			 */
			BSCV_TRACE(ssp, 'I', "bscv_ioc_eventlog2", "no more"
			    " events left at offset 0x%x", next_offset);
			break;
		}

		/*
		 * Are we interested in this event
		 */

		level = bscv_level_of_event(&event);
		if (level <= eventlog2->level) {
			/* Arggh why the funny byte ordering 3, 2, 0, 1 */
			eventlog2->code[events_recorded] =
			    ((unsigned)event.ev_event |
			    ((unsigned)event.ev_subsys << 8) |
			    ((unsigned)event.ev_resource << 16) |
			    ((unsigned)event.ev_detail << 24));

			eventlog2->time[events_recorded] =
			    ((unsigned)event.ev_data[0] |
			    ((unsigned)event.ev_data[1] << 8) |
			    ((unsigned)event.ev_data[3] << 16) |
			    ((unsigned)event.ev_data[2] << 24));

			bscv_build_eventstring(ssp,
			    &event, eventlog2->string[events_recorded],
			    eventlog2->string[events_recorded] +
			    sizeof (eventlog2->string[events_recorded]));
			events_recorded++;
		}
	}

	eventlog2->num = events_recorded;

	bscv_exit(ssp);

	if ((res == 0) &&
	    (ddi_copyout((caddr_t)eventlog2, (caddr_t)arg,
	    sizeof (lom_eventlog2_t), mode) < 0)) {
		res = EFAULT;
	}

	kmem_free((void *)eventlog2, sizeof (lom_eventlog2_t));
	return (res);
}

/*
 * LOMIOCINFO2
 */
static int
bscv_ioc_info2(bscv_soft_state_t *ssp, intptr_t arg, int mode)
{
	lom2_info_t info2;
	int i;
	uint16_t csum;
	int res = 0;

	bzero(&info2, sizeof (info2));

	(void) strncpy(info2.escape_chars, ssp->escape_chars,
	    sizeof (info2.escape_chars));
	info2.serial_events = ssp->reporting_level | ssp->serial_reporting;
	info2.a3mode = WATCHDOG;

	info2.fver = bscv_get8_locked(ssp, chan_general, EBUS_IDX_FW_REV, &res);
	csum = bscv_get8_locked(ssp, chan_general, EBUS_IDX_CHECK_HI, &res)
	    << 8;
	csum |= bscv_get8_locked(ssp, chan_general, EBUS_IDX_CHECK_LO, &res);
	info2.fchksum = csum;
	info2.prod_rev = bscv_get8_locked(ssp, chan_general,
	    EBUS_IDX_MODEL_REV, &res);
	for (i = 0; i < sizeof (info2.prod_id); i++) {
		info2.prod_id[i] = bscv_get8_locked(ssp, chan_general,
		    EBUS_IDX_MODEL_ID1 + i, &res);
	}
	info2.serial_config = bscv_get8_locked(ssp, chan_general,
	    EBUS_IDX_SER_TIMEOUT, &res);
	if (bscv_get8_locked(ssp, chan_general, EBUS_IDX_CONFIG_MISC, &res) &
	    EBUS_CONFIG_MISC_SECURITY_ENABLED) {
		info2.serial_config |= LOM_SER_SECURITY;
	}
	if (bscv_get8_locked(ssp, chan_general, EBUS_IDX_CONFIG_MISC, &res) &
	    EBUS_CONFIG_MISC_AUTO_CONSOLE) {
		info2.serial_config |= LOM_SER_RETURN;
	}
	if (bscv_get8_locked(ssp, chan_general, EBUS_IDX_WDOG_CTRL, &res) &
	    EBUS_WDOG_BREAK_DISABLE) {
		info2.serial_config |= LOM_DISABLE_WDOG_BREAK;
	}
	info2.baud_rate = bscv_get8_locked(ssp, chan_general,
	    EBUS_IDX_SER_BAUD, &res);
	info2.serial_hw_config =
	    ((int)bscv_get8_locked(ssp, chan_general,
	    EBUS_IDX_SER_CHARMODE, &res) |
	    ((int)bscv_get8_locked(ssp, chan_general,
	    EBUS_IDX_SER_FLOWCTL, &res) << 8) |
	    ((int)bscv_get8_locked(ssp, chan_general,
	    EBUS_IDX_SER_MODEMTYPE, &res) << 16));

	/*
	 * There is no phone home support on the blade platform.  We hardcode
	 * FALSE and NUL for config and script respectively.
	 */
	info2.phone_home_config = B_FALSE;
	info2.phone_home_script[0] = '\0';

	for (i = 0; i < ssp->num_fans; i++) {
		(void) strcpy(info2.fan_names[i], ssp->fan_names[i]);
	}

	if ((res == 0) &&
	    (ddi_copyout((caddr_t)&info2, (caddr_t)arg, sizeof (info2),
	    mode) < 0)) {
		res = EFAULT;
	}
	return (res);
}

/*
 * LOMIOCTEST
 */
static int
bscv_ioc_test(bscv_soft_state_t *ssp, intptr_t arg, int mode)
{
	uint32_t test;
	uint8_t testnum;
	uint8_t testarg;
	int res = 0;

	if (ddi_copyin((caddr_t)arg, (caddr_t)&test, sizeof (test),
	    mode) < 0) {
		return (EFAULT);
	}

	/*
	 * Extract num iterations.
	 */

	testarg = (test & 0xff00) >> 8;
	testnum = test & 0xff;

	BSCV_TRACE(ssp, 'F', "bscv_ioc_test",
	    "LOMIOCTEST data 0x%x (test 0x%x, arg 0x%x)",
	    test, (EBUS_IDX_SELFTEST0 + testnum), testarg);

	switch (testnum + EBUS_IDX_SELFTEST0) {
	default:
		/* Invalid test */
		res = EINVAL;
		break;

	case EBUS_IDX_SELFTEST0:	/* power on self-test result */
	case EBUS_IDX_SELFTEST1:	/* not used currently */
	case EBUS_IDX_SELFTEST2:	/* not used currently */
	case EBUS_IDX_SELFTEST3:	/* not used currently */
	case EBUS_IDX_SELFTEST4:	/* not used currently */
	case EBUS_IDX_SELFTEST5:	/* not used currently */
	case EBUS_IDX_SELFTEST6:	/* LED self-test */
	case EBUS_IDX_SELFTEST7:	/* platform-specific tests */
		/* Run the test */

		/* Stop other things and then run the test */
		bscv_enter(ssp);

		/*
		 * Then we simply write the argument to the relevant register
		 * and wait for the return code.
		 */
		bscv_put8(ssp, chan_general,
		    EBUS_IDX_SELFTEST0 + testnum, testarg);
		if (bscv_faulty(ssp)) {
			res = EIO;
		} else {
			/* Get hold of the SunVTS error code */
			test = bscv_retcode(ssp);
		}

		bscv_exit(ssp);
		break;
	}

	BSCV_TRACE(ssp, 'F', "bscv_ioc_test",
	    "LOMIOCTEST status 0x%x, res 0x%x", test, res);
	if ((res == 0) &&
	    (ddi_copyout((caddr_t)&test, (caddr_t)arg, sizeof (test),
	    mode) < 0)) {
		res = EFAULT;
	}
	return (res);
}

/*
 * LOMIOCMPROG2
 */
static int
bscv_ioc_mprog2(bscv_soft_state_t *ssp, intptr_t arg, int mode)
{
	lom2_mprog_t  mprog2;
	uint32_t base_addr;
	uint32_t data_size;
	uint32_t eeprom_size;
	int res = 0;

	if (ddi_copyin((caddr_t)arg, (caddr_t)&mprog2, sizeof (mprog2),
	    mode) < 0) {
		return (EFAULT);
	}

	/*
	 * Note that originally this was accessed as 255 byte pages
	 * in address spaces 240-255. We have to emulate this behaviour.
	 */
	if ((mprog2.addr_space < 240) || (mprog2.addr_space > 255)) {
		return (EINVAL);
	}

	bscv_enter(ssp);

	/* Calculate required data location */
	data_size = 255;
	base_addr = (mprog2.addr_space - 240) * data_size;

	eeprom_size = bscv_get8(ssp, chan_general, EBUS_IDX_EEPROM_SIZE_KB) *
	    1024;

	if (bscv_faulty(ssp)) {
		bscv_exit(ssp);
		return (EIO);
	} else if ((base_addr + data_size) > eeprom_size) {
		BSCV_TRACE(ssp, 'M', "bscv_ioc_mprog2",
		    "Request extends past end of eeprom");
		bscv_exit(ssp);
		return (ENXIO);
	}

	bscv_put8(ssp, chan_general, EBUS_IDX_CMD_RES, EBUS_CMD_UNLOCK1);
	if (bscv_faulty(ssp)) {
		BSCV_TRACE(ssp, 'M', "bscv_ioc_mprog2", "ML1 Write failed");
		bscv_exit(ssp);
		return (EIO);
	}

	bscv_put8(ssp, chan_general, EBUS_IDX_CMD_RES, EBUS_CMD_UNLOCK2);
	if (bscv_faulty(ssp)) {
		BSCV_TRACE(ssp, 'M', "bscv_ioc_mprog2", "ML2 Write failed");
		bscv_exit(ssp);
		return (EIO);
	}

	if (bscv_eerw(ssp, base_addr, &mprog2.data[0],
	    data_size, B_TRUE /* write */) != 0) {
		res = EIO;
	}

	/* Read a probe key to release the lock. */
	(void) bscv_get8(ssp, chan_general, EBUS_IDX_PROBEAA);

	if (bscv_faulty(ssp)) {
		res = EIO;
	}
	bscv_exit(ssp);

	return (res);
}

/*
 * LOMIOCMREAD2
 */
static int
bscv_ioc_mread2(bscv_soft_state_t *ssp, intptr_t arg, int mode)
{
	lom2_mprog_t  mprog2;
	uint32_t base_addr;
	uint32_t data_size;
	uint32_t eeprom_size;
	int res = 0;

	if (ddi_copyin((caddr_t)arg, (caddr_t)&mprog2, sizeof (mprog2),
	    mode) < 0) {
		return (EFAULT);
	}

	/*
	 * Need to stop the queue and then just read
	 * the bytes blind to the relevant addresses.
	 * Note that originally this was accessed as 255 byte pages
	 * in address spaces 240-255. We have to emulate this behaviour.
	 */
	if ((mprog2.addr_space < 240) || (mprog2.addr_space > 255)) {
		return (EINVAL);
	}

	bscv_enter(ssp);

	/* Calculate required data location */
	data_size = 255;
	base_addr = (mprog2.addr_space - 240) * data_size;
	eeprom_size = bscv_get8(ssp, chan_general, EBUS_IDX_EEPROM_SIZE_KB) *
	    1024;

	if (bscv_faulty(ssp)) {
		bscv_exit(ssp);
		return (EIO);
	} else if ((base_addr + data_size) > eeprom_size) {
		BSCV_TRACE(ssp, 'M', "bscv_ioc_mread2",
		    "Request extends past end of eeprom");
		bscv_exit(ssp);
		return (ENXIO);
	}

	if (bscv_eerw(ssp, base_addr, &mprog2.data[0],
	    data_size, B_FALSE /* read */) != 0) {
		res = EIO;
	}

	if (bscv_faulty(ssp)) {
		res = EIO;
	}
	bscv_exit(ssp);

	if ((res == 0) &&
	    (ddi_copyout((caddr_t)&mprog2, (caddr_t)arg, sizeof (mprog2),
	    mode) < 0)) {
		res = EFAULT;
	}
	return (res);
}

static void
bscv_get_state_changes(bscv_soft_state_t *ssp)
{
	int i = STATUS_READ_LIMIT;
	uint8_t change;
	uint8_t detail;

	ASSERT(bscv_held(ssp));

	while (i-- && !ssp->cssp_prog) {
		/* Are there any changes to process? */
		change = bscv_get8(ssp, chan_general, EBUS_IDX_STATE_CHNG);
		change &= EBUS_STATE_MASK;
		if (!change)
			break;

		/* Clarify the pending change */
		detail = bscv_get8(ssp, chan_general, EBUS_IDX_EVENT_DETAIL);

		bscv_status(ssp, change, detail);
	}

	BSCV_TRACE(ssp, 'D', "bscv_get_state_changes",
	    "loop index %d ssp->cssp_prog 0x%x", i, ssp->cssp_prog);
}

/*
 * *********************************************************************
 * Event Processing
 * *********************************************************************
 */

/*
 * function	- bscv_event_daemon
 * description	- Perform periodic lom tasks in a separate thread.
 * inputs	- LOM soft state structure pointer
 * outputs	- none.
 */
static void
bscv_event_daemon(void *arg)
{
	bscv_soft_state_t	*ssp = (void *)arg;
	boolean_t do_events;
	boolean_t do_status;
	boolean_t do_nodename;
	boolean_t do_watchdog;
	uint32_t async_reg;
	uint32_t fault;
	clock_t poll_period = BSC_EVENT_POLL_NORMAL;
	int fault_cnt = 0;

	BSCV_TRACE(ssp, 'D', "bscv_event_daemon",
	    "bscv_event_daemon: started");

	/* Acquire task daemon lock. */
	mutex_enter(&ssp->task_mu);

	ssp->task_flags |= TASK_ALIVE_FLG;

	for (;;) {
		if ((ssp->task_flags & TASK_STOP_FLG) != 0) {
			/* Stop request seen - terminate */
			break;
		}
		if ((ssp->task_flags & TASK_PAUSE_FLG) == 0) {
			/* Poll for events reported to the nexus */
			mutex_exit(&ssp->task_mu);
			/* Probe and Check faults */
			bscv_enter(ssp);
			async_reg = bscv_probe(ssp, chan_general, &fault);
			BSCV_TRACE(ssp, 'D', "bscv_event_daemon",
			    "process event: async_reg 0x%x, fault 0x%x",
			    async_reg, fault);

			if (!fault) {
				/* Treat non-fault conditions */

				if (ssp->cssp_prog || ssp->prog_mode_only) {
					/*
					 * The BSC has become available again.
					 */
					fault_cnt = 0;
					ssp->cssp_prog = B_FALSE;
					ssp->prog_mode_only = B_FALSE;
					(void) bscv_attach_common(ssp);
				} else if (fault_cnt > 0) {
					/* Previous fault has cleared */
					bscv_clear_fault(ssp);
					fault_cnt = 0;
					cmn_err(CE_WARN,
					    "!bscv_event_daemon previous fault "
					    "cleared.");
				} else if (bscv_faulty(ssp)) {
					/* Previous fault has cleared */
					bscv_clear_fault(ssp);
					/* Sleep to avoid busy waiting */
					ssp->event_sleep = B_TRUE;
				}
				poll_period = BSC_EVENT_POLL_NORMAL;

				if (async_reg) {
					ssp->status_change = B_TRUE;
					ssp->event_waiting = B_TRUE;
				}
			} else if (ssp->cssp_prog) {
				/*
				 * Expect radio silence or error values
				 * when the CSSP is upgrading the BSC firmware
				 * so throw away any fault indication.
				 */
				fault = B_FALSE;
			} else if (fault_cnt == BSC_PROBE_FAULT_LIMIT) {
				/* Count previous faults and maybe fail */
				/* Declare the lom broken */
				bscv_set_fault(ssp);
				poll_period = BSC_EVENT_POLL_FAULTY;
				cmn_err(CE_WARN,
				    "!bscv_event_daemon had faults probing "
				    "lom - marking it as faulty.");
				/*
				 * Increment fault_cnt to ensure that
				 * next time we do not report a message
				 * i.e. we drop out of the bottom
				 */
				fault_cnt = BSC_PROBE_FAULT_LIMIT + 1;
				ssp->event_sleep = B_TRUE;
			} else if (fault_cnt < BSC_PROBE_FAULT_LIMIT) {
				if (bscv_faulty(ssp)) {
					poll_period = BSC_EVENT_POLL_FAULTY;
					/*
					 * No recovery messages in this case
					 * because there was never a fault
					 * message here.
					 */
					fault_cnt = 0;
				} else {
					/* Getting ready to explode */
					fault_cnt++;
					cmn_err(CE_WARN,
					    "!bscv_event_daemon had fault 0x%x",
					    fault);
				}
				ssp->event_sleep = B_TRUE;
			}
			bscv_exit(ssp);
			mutex_enter(&ssp->task_mu);
		}

#if defined(__i386) || defined(__amd64)
		/*
		 * we have no platmod hook on Solaris x86 to report
		 * a change to the nodename so we keep a copy so
		 * we can detect a change and request that the bsc
		 * be updated when appropriate.
		 */
		if (strcmp(ssp->last_nodename, utsname.nodename) != 0) {

			BSCV_TRACE(ssp, 'X', "bscv_event_daemon",
			    "utsname.nodename='%s' possible change detected",
			    utsname.nodename);
			ssp->nodename_change = B_TRUE;
			(void) strncpy(ssp->last_nodename, utsname.nodename,
			    sizeof (ssp->last_nodename));
			/* enforce null termination */
			ssp->last_nodename[sizeof (ssp->last_nodename) - 1] =
			    '\0';
		}
#endif /* __i386 || __amd64 */

		if (((ssp->task_flags & TASK_PAUSE_FLG) == 0) &&
		    fault_cnt == 0 && ssp->cssp_prog == B_FALSE &&
		    (ssp->event_waiting || ssp->status_change ||
		    ssp->nodename_change || ssp->watchdog_change)) {

			do_events = ssp->event_waiting;
			ssp->event_waiting = B_FALSE;
			ssp->task_flags |= do_events ?
			    TASK_EVENT_PENDING_FLG : 0;
			do_status = ssp->status_change;
			ssp->status_change = B_FALSE;
			do_nodename = ssp->nodename_change;
			ssp->nodename_change = B_FALSE;
			do_watchdog = ssp->watchdog_change;
			if (ssp->watchdog_change) {
				ssp->watchdog_change = B_FALSE;
			}

			mutex_exit(&ssp->task_mu);
			/*
			 * We must not hold task_mu whilst processing
			 * events because this can lead to priority
			 * inversion and hence our interrupts getting
			 * locked out.
			 */
			bscv_enter(ssp);
			if (do_events) {
				bscv_event_process(ssp, do_events);
			}
			if (do_nodename) {
				BSCV_TRACE(ssp, 'D', "bscv_event_daemon",
				    "do_nodename task");
				bscv_setup_hostname(ssp);
			}
			if (do_watchdog) {
				BSCV_TRACE(ssp, 'D', "bscv_event_daemon",
				    "do_watchdog task");
				bscv_setup_watchdog(ssp);
			}
			/*
			 * Pending status changes are dealt with last because
			 * if we see that the BSC is about to be programmed,
			 * then it will expect us to to quiescent in the
			 * first second so it can cleanly tear down its comms
			 * protocols; this takes ~100 ms.
			 */
			if (do_status) {
				bscv_get_state_changes(ssp);
			}
			if (bscv_session_error(ssp)) {
				/*
				 * Had fault during event session. We always
				 * sleep after one of these because there
				 * may be a problem with the lom which stops
				 * us doing useful work in the event daemon.
				 * If we don't sleep then we may livelock.
				 */
				BSCV_TRACE(ssp, 'D', "bscv_event_daemon",
				    "had session error - sleeping");
				ssp->event_sleep = B_TRUE;
			}
			bscv_exit(ssp);

			mutex_enter(&ssp->task_mu);

			if (ssp->task_flags & TASK_EVENT_PENDING_FLG) {
				/*
				 * We have read any events which were
				 * pending. Let the consumer continue.
				 * Ignore the race condition with new events
				 * arriving - just let the consumer have
				 * whatever was pending when they asked.
				 */
				ssp->event_active_count++;
				ssp->task_flags &= ~(TASK_EVENT_PENDING_FLG |
				    TASK_EVENT_CONSUMER_FLG);
				cv_broadcast(&ssp->task_evnt_cv);
			}
		} else {
			/* There was nothing to do - sleep */
			ssp->event_sleep = B_TRUE;
		}

		if (ssp->event_sleep) {
			ssp->task_flags |= TASK_SLEEPING_FLG;
			/* Sleep until there is something to do */
			(void) cv_reltimedwait(&ssp->task_cv,
			    &ssp->task_mu, poll_period, TR_CLOCK_TICK);
			ssp->task_flags &= ~TASK_SLEEPING_FLG;
			ssp->event_sleep = B_FALSE;
		}
	}

	if (ssp->task_flags & TASK_EVENT_CONSUMER_FLG) {
		/*
		 * We are going away so wake up any event consumer.
		 * Pretend that any pending events have been processed.
		 */
		ssp->event_active_count += 2;
		cv_broadcast(&ssp->task_evnt_cv);
	}

	ASSERT(!(ssp->task_flags & TASK_EVENT_PENDING_FLG));
	ssp->task_flags &=
	    ~(TASK_STOP_FLG | TASK_ALIVE_FLG | TASK_EVENT_CONSUMER_FLG);
	mutex_exit(&ssp->task_mu);

	BSCV_TRACE(ssp, 'D', "bscv_event_daemon",
	    "exiting.");
}

/*
 * function	- bscv_start_event_daemon
 * description	- Create the event daemon thread.
 * inputs	- LOM soft state structure pointer
 * outputs	- none
 */
static void
bscv_start_event_daemon(bscv_soft_state_t *ssp)
{
	if (ssp->progress & BSCV_THREAD)
		return;

	/* Start the event thread after the queue has started */
	(void) thread_create(NULL, 0, (void (*)())bscv_event_daemon, ssp,
	    0, &p0, TS_RUN, minclsyspri);

	ssp->progress |= BSCV_THREAD;
}

/*
 * function	- bscv_stop_event_daemon
 * description	- Attempt to stop the event daemon thread.
 * inputs	- LOM soft state structure pointer
 * outputs	- DDI_SUCCESS OR DDI_FAILURE
 */
static int
bscv_stop_event_daemon(bscv_soft_state_t *ssp)
{
	int try;
	int res = DDI_SUCCESS;

	mutex_enter(&ssp->task_mu);

	/* Wait for task daemon to stop running. */
	for (try = 0;
	    ((ssp->task_flags & TASK_ALIVE_FLG) && try < 10);
	    try++) {
		/* Signal that the task daemon should stop */
		ssp->task_flags |= TASK_STOP_FLG;
		cv_signal(&ssp->task_cv);
		/* Release task daemon lock. */
		mutex_exit(&ssp->task_mu);
		/*
		 * TODO - when the driver is modified to support
		 * system suspend or if this routine gets called
		 * during panic we should use drv_usecwait() rather
		 * than delay in those circumstances.
		 */
		delay(drv_usectohz(1000000));
		mutex_enter(&ssp->task_mu);
	}

	if (ssp->task_flags & TASK_ALIVE_FLG) {
		res = DDI_FAILURE;
	}
	mutex_exit(&ssp->task_mu);

	return (res);
}

/*
 * function	- bscv_pause_event_daemon
 * description	- Attempt to pause the event daemon thread.
 * inputs	- LOM soft state structure pointer
 * outputs	- DDI_SUCCESS OR DDI_FAILURE
 */
static int
bscv_pause_event_daemon(bscv_soft_state_t *ssp)
{
	int try;

	if (!(ssp->progress & BSCV_THREAD)) {
		/* Nothing to do */
		return (BSCV_SUCCESS);
	}

	BSCV_TRACE(ssp, 'D', "bscv_pause_event_daemon",
	    "Attempting to pause event daemon");

	mutex_enter(&ssp->task_mu);
	/* Signal that the task daemon should pause */
	ssp->task_flags |= TASK_PAUSE_FLG;

	/* Wait for task daemon to pause. */
	for (try = 0;
	    (!(ssp->task_flags & TASK_SLEEPING_FLG) &&
	    (ssp->task_flags & TASK_ALIVE_FLG) &&
	    try < 10);
	    try++) {
		/* Paranoia */
		ssp->task_flags |= TASK_PAUSE_FLG;
		cv_signal(&ssp->task_cv);
		/* Release task daemon lock. */
		mutex_exit(&ssp->task_mu);
		delay(drv_usectohz(1000000));
		mutex_enter(&ssp->task_mu);
	}
	if ((ssp->task_flags & TASK_SLEEPING_FLG) ||
	    !(ssp->task_flags & TASK_ALIVE_FLG)) {
		mutex_exit(&ssp->task_mu);
		BSCV_TRACE(ssp, 'D', "bscv_pause_event_daemon",
		    "Pause event daemon - success");
		return (BSCV_SUCCESS);
	}
	mutex_exit(&ssp->task_mu);
	BSCV_TRACE(ssp, 'D', "bscv_pause_event_daemon",
	    "Pause event daemon - failed");
	return (BSCV_FAILURE);
}

/*
 * function	- bscv_resume_event_daemon
 * description	- Resumethe event daemon thread.
 * inputs	- LOM soft state structure pointer
 * outputs	- None.
 */
static void
bscv_resume_event_daemon(bscv_soft_state_t *ssp)
{
	if (!(ssp->progress & BSCV_THREAD)) {
		/* Nothing to do */
		return;
	}

	mutex_enter(&ssp->task_mu);
	/* Allow the task daemon to resume event processing */
	ssp->task_flags &= ~TASK_PAUSE_FLG;
	cv_signal(&ssp->task_cv);
	mutex_exit(&ssp->task_mu);

	BSCV_TRACE(ssp, 'D', "bscv_pause_event_daemon",
	    "Event daemon resumed");
}

/*
 * function	- bscv_event_process
 * description	- process (report) events
 * inputs	- Soft state ptr, process event request
 * outputs	- none
 */
static void
bscv_event_process(bscv_soft_state_t *ssp, boolean_t do_events)
{
	uint32_t currptr;
	unsigned int count;

	/* Raw values read from the lom */
	uint8_t evcount;
	uint16_t logptr;

	lom_event_t event;

	if (do_events) {
		/*
		 * Read count, next event ptr MSB,LSB. Note a read of count
		 * latches values for the next event ptr
		 */
		evcount = bscv_get8(ssp, chan_general, EBUS_IDX_UNREAD_EVENTS);
		logptr = bscv_get16(ssp, chan_general, EBUS_IDX_LOG_PTR_HI);

		/* Sanity check the values from the lom */
		count = bscv_event_validate(ssp, logptr, evcount);

		if (count == -1) {
			/*
			 * Nothing to do - or badly configured event log.
			 * We really do not want to touch the lom in this
			 * case because any data that we access may be bad!
			 * This differs from zero because if we have zero
			 * to read the lom probably things that unread is
			 * non-zero and we want that to be set to zero!
			 * Signal event fault to make the thread wait
			 * before attempting to re-read the log.
			 */
			ssp->event_sleep = B_TRUE;

			goto logdone;
		}
		if (ssp->event_fault_reported) {
			/* Clear down any old status - things are fixed */
			cmn_err(CE_NOTE, "Event pointer fault recovered.");
			ssp->event_fault_reported = B_FALSE;
		}

		/* Compute the first entry that we need to read. */
		currptr = logptr - ssp->eventlog_start;
		currptr += ssp->eventlog_size;
		currptr -= (count * sizeof (event));
		currptr %= ssp->eventlog_size;
		currptr += ssp->eventlog_start;

		BSCV_TRACE(ssp, 'E', "bscv_event_process",
		    "processing %d events from 0x%x in 0x%x:0x%x",
		    count, currptr,
		    ssp->eventlog_start,
		    ssp->eventlog_start + ssp->eventlog_size);

		for (; count > 0; count--) {
			/* Ensure window is positioned correctly */
			if (bscv_eerw(ssp, currptr, (uint8_t *)&event,
			    sizeof (event), B_FALSE /* read */) != 0) {
				/* Fault reading data - stop */
				break;
			}

			bscv_event_process_one(ssp, &event);
			bscv_sysevent(ssp, &event);

			currptr += sizeof (event);
			if (currptr >= ssp->eventlog_start +
			    ssp->eventlog_size) {
				currptr = ssp->eventlog_start;
			}
		}
		/*
		 * Clear event count - write the evcount value to remove that
		 * many from the unread total.
		 * Adjust the value to reflect how many we have left to
		 * read just in case we had a failure reading events.
		 */
		if (count == 0) {
			/*EMPTY*/
			ASSERT(logptr == currptr);
		} else if (count > evcount) {
			evcount = 0;
		} else {
			evcount -= count;
		}
		bscv_put8(ssp, chan_general, EBUS_IDX_UNREAD_EVENTS, evcount);
		    /* Remember where we were for next time */
		ssp->oldeeptr = currptr;
		ssp->oldeeptr_valid = B_TRUE;
logdone:
		;
	}
}

/*
 * function	- bscv_event_validate
 * description	- validate the event data supplied by the lom and determine
 *		  how many (if any) events to read.
 *		  This function performs complex checks to ensure that
 *		  events are not lost due to lom resets or host resets.
 *		  A combination of lom reset and host reset (i.e. power fail)
 *		  may cause some events to not be reported.
 * inputs	- Soft state ptr, next event pointer, number of unread events.
 * outputs	- the number of events to read. -1 on error.
 *		  zero is a valid value because it forces the loms unread
 *		  count to be cleared.
 */
static int
bscv_event_validate(bscv_soft_state_t *ssp, uint32_t newptr, uint8_t unread)
{
	uint32_t oldptr;
	unsigned int count;

	if (!bscv_window_setup(ssp)) {
		/* Problem with lom eeprom setup we cannot do anything */
		return (-1);
	}

	/* Sanity check the event pointers */
	if ((newptr < ssp->eventlog_start) ||
	    (newptr >= (ssp->eventlog_start + ssp->eventlog_size))) {
		if (!ssp->event_fault_reported) {
			cmn_err(CE_WARN, "Event pointer out of range. "
			    "Cannot read events.");
			ssp->event_fault_reported = B_TRUE;
		}
		return (-1);
	}
	oldptr = ssp->oldeeptr;
	/* Now sanity check log pointer against count */
	if (newptr < oldptr) {
		/*
		 * Must have wrapped add eventlog_size to get the
		 * correct relative values - this makes the checks
		 * below work!
		 */
		newptr += ssp->eventlog_size;
	}
	if (!ssp->oldeeptr_valid) {
		/* We have just started up - we have to trust lom */
		count = unread;
	} else if ((unread == 0) && (newptr == oldptr)) {
		/* Nothing to do - we were just polling */
		return (-1);
	} else if (oldptr + (unread * sizeof (lom_event_t)) == newptr) {
		/* Ok - got as many events as we expected */
		count = unread;
	} else if (oldptr + (unread * sizeof (lom_event_t)) > newptr) {
		/*
		 * Errrm more messages than there should have been.
		 * Possible causes:
		 * 1.	the event log has filled - we have been
		 *	away for a long time
		 * 2.	software bug in lom or driver.
		 * 3.	something that I haven't thought of!
		 * Always warn about this we should really never
		 * see it!
		 */
		count = (newptr - oldptr) / sizeof (lom_event_t);
		BSCV_TRACE(ssp, 'E', "bscv_event_process",
		    "bscv_event_process: lom reported "
		    "more events (%d) than expected (%d).",
		    unread, count);
		cmn_err(CE_CONT, "only processing %d events", count);
	} else {
		/* Less messages - perhaps the lom has been reset */
		count = (newptr - oldptr) / sizeof (lom_event_t);
		BSCV_TRACE(ssp, 'E', "bscv_event_process",
		    "lom reported less events (%d) than expected (%d)"
		    " - the lom may have been reset",
		    unread, count);
	}
	/* Whatever happens only read a maximum of 255 entries */
	if ((count >= 0xff)) {
		cmn_err(CE_WARN,
		    "bscv_event_process: too many events (%d) to "
		    "process - some may have been lost", count);
		count = 0xff;
	}
	return (count);
}

/*
 * function	- bscv_event_process_one
 * description	- reports on state changes to the host.
 *
 * inputs	- LOM soft state structure pointer.
 *
 * outputs	- none.
 */

static void
bscv_event_process_one(bscv_soft_state_t *ssp, lom_event_t *event)
{
	int level;
	char eventstr[100];
	int msg_type = 0;

	if (bscv_is_null_event(ssp, event)) {
		/* Cleared entry - do not report it */
		return;
	}

	level = bscv_level_of_event(event);

	switch (level) {
	default:
		msg_type = CE_NOTE;
		break;

	case EVENT_LEVEL_FATAL:
	case EVENT_LEVEL_FAULT:
		msg_type = CE_WARN;
		break;
	}

	bscv_build_eventstring(ssp, event, eventstr, eventstr +
	    sizeof (eventstr));

	if (level <= ssp->reporting_level) {
		/*
		 * The message is important enough to be shown on the console
		 * as well as the log.
		 */
		cmn_err(msg_type, "%s", eventstr);
	} else {
		/*
		 * The message goes only to the log.
		 */
		cmn_err(msg_type, "!%s", eventstr);
	}
}

/*
 * time formats
 *
 * The BSC represents times as seconds since epoch 1970.  Currently it gives
 * us 32 bits, unsigned.  In the future this might change to a 64-bit count,
 * to allow a greater range.
 *
 * Timestamp values below BSC_TIME_SANITY do not represent an absolute time,
 * but instead represent an offset from the last reset.  This must be
 * borne in mind by output routines.
 */

typedef uint32_t bsctime_t;

#define	BSC_TIME_SANITY		1000000000

/*
 * render a formatted time for display
 */

static size_t
bscv_event_snprintgmttime(char *buf, size_t bufsz, todinfo_t t)
{
	int year;

	/* tod_year is base 1900 so this code needs to adjust */
	year = 1900 + t.tod_year;

	return (snprintf(buf, bufsz, "%04d-%02d-%02d %02d:%02d:%02dZ",
	    year, t.tod_month, t.tod_day, t.tod_hour,
	    t.tod_min, t.tod_sec));
}

/*
 * function	- bscv_build_eventstring
 * description	- reports on state changes to the host.
 *
 * inputs	- LOM soft state structure pointer.
 *
 * outputs	- none.
 */

static void
bscv_build_eventstring(bscv_soft_state_t *ssp, lom_event_t *event,
    char *buf, char *bufend)
{
	uint8_t subsystem;
	uint8_t eventtype;
	bsctime_t bsctm;

	BSCV_TRACE(ssp, 'S', "bscv_build_eventstring", "event %2x%2x%2x%2x",
	    event->ev_subsys, event->ev_event,
	    event->ev_resource, event->ev_detail);
	BSCV_TRACE(ssp, 'S', "bscv_build_eventstring", "time %2x%2x%2x%2x",
	    event->ev_data[0], event->ev_data[1],
	    event->ev_data[2], event->ev_data[3]);

	/*
	 * We accept bad subsystems and event type codes here.
	 * The code decodes as much as possible and then produces
	 * suitable output.
	 */
	subsystem = EVENT_DECODE_SUBSYS(event->ev_subsys);
	eventtype = event->ev_event;

	/* time */
	bsctm = (((uint32_t)event->ev_data[0]) << 24) |
	    (((uint32_t)event->ev_data[1]) << 16) |
	    (((uint32_t)event->ev_data[2]) << 8) |
	    ((uint32_t)event->ev_data[3]);
	if (bsctm < BSC_TIME_SANITY) {
		/* offset */
		buf += snprintf(buf, bufend-buf, "+P%dd%02dh%02dm%02ds",
		    (int)(bsctm/86400), (int)(bsctm/3600%24),
		    (int)(bsctm/60%60), (int)(bsctm%60));
	} else {
		/* absolute time */
		mutex_enter(&tod_lock);
		buf += bscv_event_snprintgmttime(buf, bufend-buf,
		    utc_to_tod(bsctm));
		mutex_exit(&tod_lock);
	}
	buf += snprintf(buf, bufend-buf, " ");

	/* subsysp */
	if (subsystem <
	    (sizeof (eventSubsysStrings)/sizeof (*eventSubsysStrings))) {
		buf += snprintf(buf, bufend - buf, "%s",
		    eventSubsysStrings[subsystem]);
	} else {
		buf += snprintf(buf, bufend - buf,
		    "unknown subsystem %d ", subsystem);
	}

	/* resource */
	switch (subsystem) {
	case EVENT_SUBSYS_ALARM:
	case EVENT_SUBSYS_TEMP:
	case EVENT_SUBSYS_OVERTEMP:
	case EVENT_SUBSYS_FAN:
	case EVENT_SUBSYS_SUPPLY:
	case EVENT_SUBSYS_BREAKER:
	case EVENT_SUBSYS_PSU:
		buf += snprintf(buf, bufend - buf, "%d ", event->ev_resource);
		break;
	case EVENT_SUBSYS_LED:
		buf += snprintf(buf, bufend - buf, "%s ", bscv_get_label(
		    ssp->led_names, MAX_LED_ID, event->ev_resource - 1));
		break;
	default:
		break;
	}

	/* fatal */
	if (event->ev_subsys & EVENT_MASK_FAULT) {
		if (event->ev_subsys & EVENT_MASK_FATAL) {
			buf += snprintf(buf, bufend - buf, "FATAL FAULT: ");
		} else {
			buf += snprintf(buf, bufend - buf, "FAULT: ");
		}
	}

	/* eventp */
	if (eventtype <
	    (sizeof (eventTypeStrings)/sizeof (*eventTypeStrings))) {
		buf += snprintf(buf, bufend - buf, "%s",
		    eventTypeStrings[eventtype]);
	} else {
		buf += snprintf(buf, bufend - buf,
		    "unknown event 0x%02x%02x%02x%02x",
		    event->ev_subsys, event->ev_event,
		    event->ev_resource, event->ev_detail);
	}

	/* detail */
	switch (subsystem) {
	case EVENT_SUBSYS_TEMP:
		if ((eventtype != EVENT_RECOVERED) &&
		    eventtype != EVENT_DEVICE_INACCESSIBLE) {
			buf += snprintf(buf, bufend - buf, " - %d degC",
			    (int8_t)event->ev_detail);
		}
		break;
	case EVENT_SUBSYS_FAN:
		if (eventtype == EVENT_FAILED) {
			buf += snprintf(buf, bufend - buf,
			    " %d%%", event->ev_detail);
		}
		break;
	case EVENT_SUBSYS_LOM:
		switch (eventtype) {
		case EVENT_FLASH_DOWNLOAD:
			buf += snprintf(buf, bufend - buf,
			    ": v%d.%d to v%d.%d",
			    (event->ev_resource >> 4),
			    (event->ev_resource & 0x0f),
			    (event->ev_detail >> 4),
			    (event->ev_detail & 0x0f));
			break;
		case EVENT_WATCHDOG_TRIGGER:
			buf += snprintf(buf, bufend - buf,
			    event->ev_detail ? "- soft" : " - hard");
			break;
		case EVENT_UNEXPECTED_RESET:
			if (event->ev_detail &
			    LOM_UNEXPECTEDRESET_MASK_BADTRAP) {
				buf += snprintf(buf, bufend - buf,
				    " - unclaimed exception 0x%x",
				    event->ev_detail &
				    ~LOM_UNEXPECTEDRESET_MASK_BADTRAP);
			}
			break;
		case EVENT_RESET:
			switch (event->ev_detail) {
			case LOM_RESET_DETAIL_BYUSER:
				buf += snprintf(buf, bufend - buf, " by user");
				break;
			case LOM_RESET_DETAIL_REPROGRAMMING:
				buf += snprintf(buf, bufend - buf,
				" after flash download");
				break;
			default:
				buf += snprintf(buf, bufend - buf,
				    " - unknown reason");
				break;
			}
			break;
		default:
			break;
		}
		break;
	case EVENT_SUBSYS_LED:
		switch (event->ev_detail) {
		case LOM_LED_STATE_OFF:
			buf += snprintf(buf, bufend - buf, ": OFF");
			break;
		case LOM_LED_STATE_ON_STEADY:
			buf += snprintf(buf, bufend - buf, ": ON");
			break;
		case LOM_LED_STATE_ON_FLASHING:
		case LOM_LED_STATE_ON_SLOWFLASH:
			buf += snprintf(buf, bufend - buf, ": BLINKING");
			break;
		case LOM_LED_STATE_INACCESSIBLE:
			buf += snprintf(buf, bufend - buf, ": inaccessible");
			break;
		case LOM_LED_STATE_STANDBY:
			buf += snprintf(buf, bufend - buf, ": standby");
			break;
		case LOM_LED_STATE_NOT_PRESENT:
			buf += snprintf(buf, bufend - buf, ": not present");
			break;
		default:
			buf += snprintf(buf, bufend - buf, ": 0x%x",
			    event->ev_resource);
			break;
		}
		break;
	case EVENT_SUBSYS_USER:
		switch (eventtype) {
		case EVENT_USER_ADDED:
		case EVENT_USER_REMOVED:
		case EVENT_USER_PERMSCHANGED:
		case EVENT_USER_LOGIN:
		case EVENT_USER_PASSWORD_CHANGE:
		case EVENT_USER_LOGINFAIL:
		case EVENT_USER_LOGOUT:
			buf += snprintf(buf, bufend - buf, " %d",
			    event->ev_resource);
		default:
			break;
		}
		break;
	case EVENT_SUBSYS_PSU:
		if (event->ev_detail & LOM_PSU_NOACCESS) {
			buf += snprintf(buf, bufend - buf, " - inaccessible");
		} else if ((event->ev_detail & LOM_PSU_STATUS_MASK)
		    == LOM_PSU_STATUS_MASK) {
			buf += snprintf(buf, bufend - buf, " - OK");
		} else {
			buf += snprintf(buf, bufend - buf, " -");
			/*
			 * If both inputs are seen to have failed then simply
			 * indicate that the PSU input has failed
			 */
			if (!(event->ev_detail &
			    (LOM_PSU_INPUT_A_OK | LOM_PSU_INPUT_B_OK))) {
				buf += snprintf(buf, bufend - buf, " Input");
			} else {
				/* At least one input is ok */
				if (!(event->ev_detail & LOM_PSU_INPUT_A_OK)) {
					buf += snprintf(buf, bufend - buf,
					    " InA");
				}
				if (!(event->ev_detail & LOM_PSU_INPUT_B_OK)) {
					buf += snprintf(buf, bufend - buf,
					    " InB");
				}
				/*
				 * Only flag an output error if an input is
				 * still present
				 */
				if (!(event->ev_detail & LOM_PSU_OUTPUT_OK)) {
					buf += snprintf(buf, bufend - buf,
					    " Output");
				}
			}
			buf += snprintf(buf, bufend - buf, " failed");
		}
		break;
	case EVENT_SUBSYS_NONE:
		if (eventtype == EVENT_FAULT_LED) {
			switch (event->ev_detail) {
			case 0:
				buf += snprintf(buf, bufend - buf, " - ON");
				break;
			case 255:
				buf += snprintf(buf, bufend - buf, " - OFF");
				break;
			default:
				buf += snprintf(buf, bufend - buf,
				    " - %dHz", event->ev_detail);
				break;
			}
		}
		break;
	case EVENT_SUBSYS_HOST:
		if (eventtype == EVENT_BOOTMODE_CHANGE) {
			switch (event->ev_detail &
			    ~EBUS_BOOTMODE_FORCE_CONSOLE) {
			case EBUS_BOOTMODE_FORCE_NOBOOT:
				buf += snprintf(buf, bufend - buf,
				    " - no boot");
				break;
			case EBUS_BOOTMODE_RESET_DEFAULT:
				buf += snprintf(buf, bufend - buf,
				    " - reset defaults");
				break;
			case EBUS_BOOTMODE_FULLDIAG:
				buf += snprintf(buf, bufend - buf,
				    " - full diag");
				break;
			case EBUS_BOOTMODE_SKIPDIAG:
				buf += snprintf(buf, bufend - buf,
				    " - skip diag");
				break;
			default:
				break;
			}
		}
		if (eventtype == EVENT_SCC_STATUS) {
			switch (event->ev_detail) {
			case 0:
				buf += snprintf(buf, bufend - buf,
				    " - inserted");
				break;
			case 1:
				buf += snprintf(buf, bufend - buf,
				    " - removed");
				break;
			default:
				break;
			}
		}
		break;

	default:
		break;
	}

	/* shutd */
	if (event->ev_subsys & EVENT_MASK_SHUTDOWN_REQD) {
		buf += snprintf(buf, bufend - buf, " - shutdown req'd");
	}

	buf += snprintf(buf, bufend - buf, "\n");

	if (buf >= bufend) {
		/* Ensure newline at end of string */
		bufend[-2] = '\n';
		bufend[-1] = '\0';
#ifdef DEBUG
		cmn_err(CE_WARN, "!bscv_build_eventstring: buffer too small!");
#endif /* DEBUG */
	}
}

/*
 * function	- bscv_level_of_event
 * description	- This routine determines which level an event should be
 *		  reported at.
 * inputs	- lom event structure pointer
 * outputs	- event level.
 */
static int
bscv_level_of_event(lom_event_t *event)
{
	int level;
	/*
	 * This is the same criteria that the firmware uses except we
	 * log the fault led on as being EVENT_LEVEL_FAULT
	 */
	if (EVENT_DECODE_SUBSYS(event->ev_subsys) == EVENT_SUBSYS_USER) {
		level = EVENT_LEVEL_USER;
	} else if ((EVENT_DECODE_SUBSYS(event->ev_subsys) ==
	    EVENT_SUBSYS_ALARM) && (event->ev_event == EVENT_STATE_ON)) {
		level = EVENT_LEVEL_FAULT;
	} else if ((EVENT_DECODE_SUBSYS(event->ev_subsys) ==
	    EVENT_SUBSYS_NONE) &&
	    (event->ev_event == EVENT_FAULT_LED) &&
	    (event->ev_detail != 0xff)) {
		level = EVENT_LEVEL_FAULT;
	} else if ((EVENT_DECODE_SUBSYS(event->ev_subsys) ==
	    EVENT_SUBSYS_LOM) && event->ev_event == EVENT_TIME_REFERENCE) {
		level = EVENT_LEVEL_NOTICE;
	} else if (event->ev_event == EVENT_RECOVERED) {
		/*
		 * All recovery messages need to be reported to the console
		 * because during boot, the faults which occurred whilst
		 * Solaris was not running are relayed to the console.  There
		 * is a case whereby a fatal fault (eg. over temp) could
		 * have occurred and then recovered.  The recovery condition
		 * needs to be reported so the user doesn't think that the
		 * failure (over temp) is still present.
		 */
		level = EVENT_LEVEL_FAULT;
	} else if (EVENT_DECODE_FAULT(event->ev_subsys) == 0) {
		/* None of FAULT, FATAL or SHUTDOWN REQD are set */
		level = EVENT_LEVEL_NOTICE;
	} else if (EVENT_DECODE_FAULT(event->ev_subsys) == EVENT_MASK_FAULT) {
		/* Only FAULT set i.e not FATAL or SHUTDOWN REQD */
		level = EVENT_LEVEL_FAULT;
	} else {
		level = EVENT_LEVEL_FATAL;
	}

	return (level);
}

/*
 * function	- bscv_status
 * description	- This routine is called when any change in the LOMlite2 status
 *		  is indicated by the status registers.
 *
 * inputs	- LOM soft state structure pointer
 *
 * outputs	- none.
 */
static void
bscv_status(bscv_soft_state_t *ssp, uint8_t state_chng, uint8_t dev_no)
{
	int8_t temp;
	uint8_t fanspeed;

	ASSERT(bscv_held(ssp));

	BSCV_TRACE(ssp, 'D', "bscv_status", "state_chng 0x%x dev_no 0x%x",
	    state_chng, dev_no);

	/*
	 * The device that has changed is given by the state change
	 * register and the event detail register so react
	 * accordingly.
	 */

	if (state_chng == EBUS_STATE_NOTIFY) {
		/*
		 * The BSC is indicating a self state change
		 */
		if (dev_no == EBUS_DETAIL_FLASH) {
			ssp->cssp_prog = B_TRUE;
			BSCV_TRACE(ssp, 'D', "bscv_status",
			    "ssp->cssp_prog changed to 0x%x",
			    ssp->cssp_prog);
			/*
			 * It takes the BSC at least 100 ms to
			 * clear down the comms protocol.
			 * We back-off from talking to the
			 * BSC during this period.
			 */
			delay(BSC_EVENT_POLL_NORMAL);
			BSCV_TRACE(ssp, 'D', "bscv_status",
			    "completed delay");
		} else if (dev_no == EBUS_DETAIL_RESET) {
			/*
			 * The bsc has reset
			 */
			BSCV_TRACE(ssp, 'D', "bscv_status",
			    "BSC reset occured, re-synching");
			(void) bscv_attach_common(ssp);
			BSCV_TRACE(ssp, 'D', "bscv_status",
			    "completed attach_common");
		}

	}

	if ((state_chng & EBUS_STATE_FAN) && ((dev_no - 1) < MAX_FANS)) {
		fanspeed = bscv_get8(ssp, chan_general,
		    EBUS_IDX_FAN1_SPEED + dev_no - 1);
		/*
		 * Only remember fanspeeds which are real values or
		 * NOT PRESENT values.
		 */
		if ((fanspeed <= LOM_FAN_MAX_SPEED) ||
		    (fanspeed == LOM_FAN_NOT_PRESENT)) {
			ssp->fanspeed[dev_no - 1] = fanspeed;
		}
	}

	if ((state_chng & EBUS_STATE_PSU) && ((dev_no - 1) < MAX_PSUS)) {
		(void) bscv_get8(ssp, chan_general,
		    EBUS_IDX_PSU1_STAT + dev_no - 1);
	}

	if (state_chng & EBUS_STATE_GP) {
		(void) bscv_get8(ssp, chan_general, EBUS_IDX_GPIP);
	}

	if (state_chng & EBUS_STATE_CB) {
		(void) bscv_get8(ssp, chan_general, EBUS_IDX_CBREAK_STATUS);
	}

	if ((state_chng & EBUS_STATE_TEMPERATURE) &&
	    ((dev_no - 1) < MAX_TEMPS)) {
		temp = bscv_get8(ssp, chan_general,
		    EBUS_IDX_TEMP1 + dev_no - 1);
		/*
		 * Only remember temperatures which are real values or
		 * a NOT PRESENT value.
		 */
		if ((temp <= LOM_TEMP_MAX_VALUE) ||
		    (temp == LOM_TEMP_STATE_NOT_PRESENT)) {
			ssp->temps.temp[dev_no - 1] = temp;
		}
	}

	if (state_chng & EBUS_STATE_RAIL) {
		(void) bscv_get8(ssp, chan_general, EBUS_IDX_SUPPLY_LO);
		(void) bscv_get8(ssp, chan_general, EBUS_IDX_SUPPLY_HI);
	}
}

char *
bscv_get_label(char labels[][MAX_LOM2_NAME_STR], int limit, int index)
{

	if (labels == NULL)
		return ("");

	if (limit < 0 || index < 0 || index > limit)
		return ("-");

	return (labels[index]);
}

static void
bscv_generic_sysevent(bscv_soft_state_t *ssp, char *class, char *subclass,
    char *fru_id, char *res_id, int32_t fru_state, char *msg)
{
	int rv;
	nvlist_t *attr_list;

	BSCV_TRACE(ssp, 'E', "bscv_generic_sysevent", "%s/%s:(%s,%s,%d) %s",
	    class, subclass, fru_id, res_id, fru_state, msg);


	if (nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE, KM_SLEEP)) {
		BSCV_TRACE(ssp, 'E', "bscv_generic_sysevent",
		    "nvlist alloc failure");
		return;
	}
	if (nvlist_add_uint32(attr_list, ENV_VERSION, 1)) {
		BSCV_TRACE(ssp, 'E', "bscv_generic_sysevent",
		    "nvlist ENV_VERSION failure");
		nvlist_free(attr_list);
		return;
	}
	if (nvlist_add_string(attr_list, ENV_FRU_ID, fru_id)) {
		BSCV_TRACE(ssp, 'E', "bscv_generic_sysevent",
		    "nvlist ENV_FRU_ID failure");
		nvlist_free(attr_list);
		return;
	}
	if (nvlist_add_string(attr_list, ENV_FRU_RESOURCE_ID, res_id)) {
		BSCV_TRACE(ssp, 'E', "bscv_generic_sysevent",
		    "nvlist ENV_FRU_RESOURCE_ID failure");
		nvlist_free(attr_list);
		return;
	}
	if (nvlist_add_string(attr_list, ENV_FRU_DEVICE, ENV_RESERVED_ATTR)) {
		BSCV_TRACE(ssp, 'E', "bscv_generic_sysevent",
		    "nvlist ENV_FRU_DEVICE failure");
		nvlist_free(attr_list);
		return;
	}
	if (nvlist_add_int32(attr_list, ENV_FRU_STATE, fru_state)) {
		BSCV_TRACE(ssp, 'E', "bscv_generic_sysevent",
		    "nvlist ENV_FRU_STATE failure");
		nvlist_free(attr_list);
		return;
	}
	if (nvlist_add_string(attr_list, ENV_MSG, msg)) {
		BSCV_TRACE(ssp, 'E', "bscv_generic_sysevent",
		    "nvlist ENV_MSG failure");
		nvlist_free(attr_list);
		return;
	}

	rv = ddi_log_sysevent(ssp->dip, DDI_VENDOR_SUNW, class,
	    subclass, attr_list, NULL, DDI_SLEEP);

	if (rv == DDI_SUCCESS) {
		BSCV_TRACE(ssp, 'E', "bscv_generic_sysevent", "sent sysevent");
	} else {
		cmn_err(CE_WARN, "!cannot deliver sysevent");
	}

	nvlist_free(attr_list);
}

/*
 * function	- bscv_sysevent
 * description	- send out a sysevent on the given change if needed
 * inputs	- soft state pointer, event to report
 * outputs	- none
 */

static void
bscv_sysevent(bscv_soft_state_t *ssp, lom_event_t *event)
{
	char *class = NULL;
	char *subclass = NULL;
	char *fru_id = "Blade";	/* The blade is only one FRU */
	char *res_id;
	int32_t fru_state = 0;

	BSCV_TRACE(ssp, 'E', "bscv_sysevent", "processing event");

	ASSERT(event != NULL);

	/* Map ev_subsys to sysevent class/sub-class */

	switch (EVENT_DECODE_SUBSYS(event->ev_subsys)) {
		case EVENT_SUBSYS_NONE:
		break;
		case EVENT_SUBSYS_ALARM:
		break;
		case EVENT_SUBSYS_TEMP:
		class = EC_ENV, subclass = ESC_ENV_TEMP;
		res_id = bscv_get_label(ssp->temps.name, ssp->temps.num,
		    event->ev_resource - 1);
		switch (event->ev_event) {
			case EVENT_SEVERE_OVERHEAT:
			fru_state = ENV_FAILED;
			break;
			case EVENT_OVERHEAT:
			fru_state = ENV_WARNING;
			break;
			case EVENT_NO_OVERHEAT:
			fru_state = ENV_OK;
			break;
			default:
			return;
		}
		break;
		case EVENT_SUBSYS_OVERTEMP:
		break;
		case EVENT_SUBSYS_FAN:
		class = EC_ENV, subclass = ESC_ENV_FAN;
		res_id = bscv_get_label(ssp->fan_names, ssp->num_fans,
		    event->ev_resource - 1);
		switch (event->ev_event) {
			case EVENT_FAILED:
			fru_state = ENV_FAILED;
			break;
			case EVENT_RECOVERED:
			fru_state = ENV_OK;
			break;
			default:
			return;
		}
		break;
		case EVENT_SUBSYS_SUPPLY:
		class = EC_ENV, subclass = ESC_ENV_POWER;
		res_id = bscv_get_label(ssp->sflags.name, ssp->sflags.num,
		    event->ev_resource - 1);
		switch (event->ev_event) {
			case EVENT_FAILED:
			fru_state = ENV_FAILED;
			break;
			case EVENT_RECOVERED:
			fru_state = ENV_OK;
			break;
			default:
			return;
		}
		break;
		case EVENT_SUBSYS_BREAKER:
		break;
		case EVENT_SUBSYS_PSU:
		break;
		case EVENT_SUBSYS_USER:
		break;
		case EVENT_SUBSYS_PHONEHOME:
		break;
		case EVENT_SUBSYS_LOM:
		break;
		case EVENT_SUBSYS_HOST:
		break;
		case EVENT_SUBSYS_EVENTLOG:
		break;
		case EVENT_SUBSYS_EXTRA:
		break;
		case EVENT_SUBSYS_LED:
		if (event->ev_event != EVENT_FAULT_LED &&
		    event->ev_event != EVENT_STATE_CHANGE)
			return;
		/*
		 * There are 3 LEDs : Power, Service, Ready-to-Remove on a
		 * JBOS blade.  We'll never report the Power since Solaris
		 * won't be running when it is _switched_ ON.  Ready-to-Remove
		 * will only be lit when we're powered down which also means
		 * Solaris won't be running. We don't want to report it
		 * during system testing / Sun VTS exercising the LEDs.
		 *
		 * Therefore, we only report the Service Required LED.
		 */
		class = EC_ENV, subclass = ESC_ENV_LED;
		res_id = bscv_get_label(ssp->led_names, MAX_LED_ID,
		    event->ev_resource - 1);

		switch (event->ev_detail) {
			case LOM_LED_STATE_ON_STEADY:
			fru_state = ENV_LED_ON;
			break;
			case LOM_LED_STATE_ON_FLASHING:
			case LOM_LED_STATE_ON_SLOWFLASH:
			fru_state = ENV_LED_BLINKING;
			break;
			case LOM_LED_STATE_OFF:
			fru_state = ENV_LED_OFF;
			break;
			case LOM_LED_STATE_INACCESSIBLE:
			fru_state = ENV_LED_INACCESSIBLE;
			break;
			case LOM_LED_STATE_STANDBY:
			fru_state = ENV_LED_STANDBY;
			break;
			case LOM_LED_STATE_NOT_PRESENT:
			fru_state = ENV_LED_NOT_PRESENT;
			break;
			default:
			fru_state = ENV_LED_INACCESSIBLE;
			break;
		}
		break;
		default :
		break;
	}

	if (class == NULL || subclass == NULL) {
		BSCV_TRACE(ssp, 'E', "bscv_sysevent", "class/subclass NULL");
		return;
	}

	bscv_generic_sysevent(ssp, class, subclass, fru_id, res_id, fru_state,
	    ENV_RESERVED_ATTR);
}

/*
 * *********************************************************************
 * Firmware download (programming)
 * *********************************************************************
 */

/*
 * function	- bscv_prog
 * description	- LOMlite2 flash programming code.
 *
 *		  bscv_prog_image - download a complete image to the lom.
 *		  bscv_prog_receive_image - receive data to build up a
 *			complete image.
 *		  bscv_prog_stop_lom - pause the event daemon and prepare
 *			lom for firmware upgrade.
 *		  bscv_prog_start_lom - reinit the driver/lom after upgrade
 *			and restart the event daemon
 *
 * inputs	- soft state pointer, arg ptr, ioctl mode
 * outputs	- status
 */

static int
bscv_prog(bscv_soft_state_t *ssp, intptr_t arg, int mode)
{
	lom_prog_t *prog;
	int res = 0;

	/*
	 * We will get repeatedly called with bits of data first for
	 * loader, then for main image.
	 */
	prog = (lom_prog_t *)kmem_alloc(sizeof (lom_prog_t), KM_SLEEP);

	if (ddi_copyin((caddr_t)arg, (caddr_t)prog, sizeof (*prog),
	    mode) < 0) {
		kmem_free((void *)prog, sizeof (*prog));
		return (EFAULT);
	}

	BSCV_TRACE(ssp, 'U', "bscv_prog",
	    "index 0x%x size 0x%x", prog->index, prog->size);

	mutex_enter(&ssp->prog_mu);
	if (prog->size == 0) {
		if (prog->index == 2) {
			/*
			 * This is the initial request for the chip type so we
			 * know what we are programming.
			 * The type will have been read in at init so just
			 * return it in data[0].
			 */
			prog->data[0] = bscv_get8_cached(ssp,
			    EBUS_IDX_CPU_IDENT);

			if (ddi_copyout((caddr_t)prog, (caddr_t)arg,
			    sizeof (lom_prog_t), mode) < 0) {
				res = EFAULT;
			}
		} else if (prog->index == 0) {
			res = bscv_prog_stop_lom(ssp);
		} else if (prog->index == 1) {
			res = bscv_prog_start_lom(ssp);
		} else {
			res = EINVAL;
		}
	} else {
		if (ssp->image == NULL) {
			ssp->image = (uint8_t *)kmem_zalloc(
			    BSC_IMAGE_MAX_SIZE, KM_SLEEP);
		}
		res = bscv_prog_receive_image(ssp, prog,
		    ssp->image, BSC_IMAGE_MAX_SIZE);
	}
	mutex_exit(&ssp->prog_mu);
	kmem_free((void *)prog, sizeof (lom_prog_t));

	return (res);
}

static int
bscv_check_loader_config(bscv_soft_state_t *ssp, boolean_t is_image2)
{
	BSCV_TRACE(ssp, 'U', "bscv_check_loader_config",
	    "loader_running %d, is_image2 %d",
	    ssp->loader_running, is_image2);

	/*
	 * loader_running TRUE means that we have told the microcontroller to
	 * JUMP into the loader code which has been downloaded into its RAM.
	 * At this point its an error to try and download another loader.  We
	 * should be downloading the actual image at this point.
	 * Conversely, it is an error to download an image when the loader is
	 * not already downloaded and the microcontroller hasn't JUMPed into it.
	 * is_image2 TRUE means the image is being downloaded.
	 * is_image2 FALSE means the loader is being downloaded.
	 */
	if (ssp->loader_running && !is_image2) {
		cmn_err(CE_WARN, "Attempt to download loader image "
		    "with loader image already active");
		cmn_err(CE_CONT, "This maybe an attempt to restart a "
		    "failed firmware download - ignoring download attempt");
		return (B_FALSE);
	} else if (!ssp->loader_running && is_image2) {
		cmn_err(CE_WARN, "Attempt to download firmware image "
		    "without loader image active");
		return (B_FALSE);

	}

	return (B_TRUE);
}

static uint32_t
bscv_get_pagesize(bscv_soft_state_t *ssp)
{
	uint32_t pagesize;

	ASSERT(bscv_held(ssp));

	pagesize = bscv_get32(ssp, chan_prog,
	    BSCVA(EBUS_CMD_SPACE_PROGRAM, EBUS_PROGRAM_PAGE0));

	BSCV_TRACE(ssp, 'U', "bscv_get_pagesize", "pagesize 0x%x", pagesize);

	return (pagesize);
}

/*
 * Sets the pagesize, returning the old value.
 */
static uint32_t
bscv_set_pagesize(bscv_soft_state_t *ssp, uint32_t pagesize)
{
	uint32_t old_pagesize;

	ASSERT(bscv_held(ssp));

	old_pagesize = bscv_get_pagesize(ssp);

	/*
	 * The microcontroller remembers this value until until someone
	 * changes it.
	 */
	bscv_put32(ssp, chan_prog,
	    BSCVA(EBUS_CMD_SPACE_PROGRAM, EBUS_PROGRAM_PSIZ0), pagesize);

	return (old_pagesize);
}

static uint8_t
bscv_enter_programming_mode(bscv_soft_state_t *ssp)
{
	uint8_t retval;

	ASSERT(bscv_held(ssp));

	bscv_put8(ssp, chan_prog,
	    BSCVA(EBUS_CMD_SPACE_PROGRAM, EBUS_PROGRAM_PCSR),
	    EBUS_PROGRAM_PCR_PRGMODE_ON);

	retval = bscv_get8(ssp, chan_prog, BSCVA(EBUS_CMD_SPACE_PROGRAM,
	    EBUS_PROGRAM_PCSR));

	return (retval);
}

static void
bscv_leave_programming_mode(bscv_soft_state_t *ssp, boolean_t with_jmp)
{
	uint8_t reg;
	ASSERT(bscv_held(ssp));

	if (with_jmp) {
		reg = EBUS_PROGRAM_PCR_PROGOFF_JUMPTOADDR;
		BSCV_TRACE(ssp, 'U', "bscv_leave_programming_mode",
		    "jumptoaddr");
	} else {
		reg = EBUS_PROGRAM_PCR_PRGMODE_OFF;
		BSCV_TRACE(ssp, 'U', "bscv_leave_programming_mode",
		    "prgmode_off");
	}

	bscv_put8(ssp, chan_prog,
	    BSCVA(EBUS_CMD_SPACE_PROGRAM, EBUS_PROGRAM_PCSR), reg);
}


static void
bscv_set_jump_to_addr(bscv_soft_state_t *ssp, uint32_t loadaddr)
{
	ASSERT(bscv_held(ssp));

	bscv_put32(ssp, chan_prog,
	    BSCVA(EBUS_CMD_SPACE_PROGRAM, EBUS_PROGRAM_PADR0), loadaddr);

	BSCV_TRACE(ssp, 'U', "bscv_set_jump_to_addr",
	    "set jump to loadaddr 0x%x", loadaddr);
}

static uint8_t
bscv_erase_once(bscv_soft_state_t *ssp, uint32_t loadaddr, uint32_t image_size)
{
	uint8_t retval;

	ASSERT(bscv_held(ssp));

	/*
	 * write PADR, PSIZ to define area to be erased
	 * We do not send erase for zero size because the current
	 * downloader gets this wrong
	 */

	/*
	 * start at 0
	 */
	BSCV_TRACE(ssp, 'U', "bscv_erase_once", "sending erase command");

	bscv_put32(ssp, chan_prog,
	    BSCVA(EBUS_CMD_SPACE_PROGRAM, EBUS_PROGRAM_PADR0),
	    loadaddr);

	/* set PSIZ to full size of image to be programmed */
	bscv_put32(ssp, chan_prog,
	    BSCVA(EBUS_CMD_SPACE_PROGRAM, EBUS_PROGRAM_PSIZ0),
	    image_size);

	/* write ERASE to PCSR */
	bscv_put8(ssp, chan_prog,
	    BSCVA(EBUS_CMD_SPACE_PROGRAM, EBUS_PROGRAM_PCSR),
	    EBUS_PROGRAM_PCR_ERASE);

	/* read PCSR to check status */
	retval = bscv_get8(ssp, chan_prog,
	    BSCVA(EBUS_CMD_SPACE_PROGRAM, EBUS_PROGRAM_PCSR));
	return (retval);
}

static uint8_t
bscv_do_erase(bscv_soft_state_t *ssp, uint32_t loadaddr, uint32_t image_size,
    boolean_t is_image2)
{
	int retryable = BSC_ERASE_RETRY_LIMIT;
	uint8_t retval;

	while (retryable--) {
		retval = bscv_erase_once(ssp, loadaddr, image_size);
		if (PSR_SUCCESS(retval))
			break;
		else
			cmn_err(CE_WARN, "erase error 0x%x, attempt %d"
			    ", base 0x%x, size 0x%x, %s image",
			    retval, BSC_ERASE_RETRY_LIMIT - retryable,
			    loadaddr, image_size,
			    is_image2 ? "main" : "loader");
	}

	return (retval);
}

static uint8_t
bscv_set_page(bscv_soft_state_t *ssp, uint32_t addr)
{
	uint32_t retval;
	int retryable = BSC_PAGE_RETRY_LIMIT;

	ASSERT(bscv_held(ssp));

	while (retryable--) {

		/*
		 * Write the page address and read it back for confirmation.
		 */
		bscv_put32(ssp, chan_prog,
		    BSCVA(EBUS_CMD_SPACE_PROGRAM, EBUS_PROGRAM_PADR0),
		    addr);
		retval = bscv_get32(ssp, chan_prog,
		    BSCVA(EBUS_CMD_SPACE_PROGRAM, EBUS_PROGRAM_PADR0));

		if (retval == addr)
			break;
		else {
			cmn_err(CE_WARN, "programmming error, attempt %d, "
			    "set page 0x%x, read back 0x%x",
			    BSC_PAGE_RETRY_LIMIT - retryable,
			    addr, retval);
		}
	}
	return ((addr == retval) ? EBUS_PROGRAM_PSR_SUCCESS :
	    EBUS_PROGRAM_PSR_INVALID_OPERATION);
}

static uint8_t
bscv_do_page_data_once(bscv_soft_state_t *ssp, uint32_t index,
    uint32_t image_size, uint32_t pagesize, uint8_t *imagep,
    uint16_t *calcd_chksum)
{
	uint32_t size;
	uint16_t chksum;
	int i;
	uint8_t retval;

	ASSERT(bscv_held(ssp));

	BSCV_TRACE(ssp, 'P', "bscv_do_page_data_once", "index 0x%x", index);

	/* write PSIZ bytes to PDAT */
	if (index + pagesize < image_size) {
		bscv_rep_rw8(ssp, chan_prog, imagep + index,
		    BSCVA(EBUS_CMD_SPACE_PROGRAM, EBUS_PROGRAM_DATA),
		    pagesize, DDI_DEV_NO_AUTOINCR, B_TRUE /* write */);
		size = pagesize;
	} else {
		BSCV_TRACE(ssp, 'P', "bscv_do_page_once",
		    "Sending last block, last 0x%x bytes",
		    (image_size % pagesize));
		size = (image_size - index);
		bscv_rep_rw8(ssp, chan_prog, imagep + index,
		    BSCVA(EBUS_CMD_SPACE_PROGRAM, EBUS_PROGRAM_DATA),
		    size, DDI_DEV_NO_AUTOINCR, B_TRUE /* write */);
		/* Now pad the rest of the page with zeros */
		for (i = size; i < pagesize; i++) {
			bscv_put8(ssp, chan_prog,
			    BSCVA(EBUS_CMD_SPACE_PROGRAM,
			    EBUS_PROGRAM_DATA),
			    0);
		}
	}

	/* write the checksum to PCSM */
	chksum = 0;
	for (i = 0; i < size; i++) {
		chksum = ((chksum << 3) | (chksum >> 13)) ^
		    *(imagep + index + i);
	}
	/* Cope with non-pagesize sized bufers */
	for (; i < pagesize; i++) {
		chksum = ((chksum << 3) | (chksum >> 13)) ^ 0;
	}
	bscv_put16(ssp, chan_prog,
	    BSCVA(EBUS_CMD_SPACE_PROGRAM, EBUS_PROGRAM_PCSM0), chksum);

	bscv_put8(ssp, chan_prog,
	    BSCVA(EBUS_CMD_SPACE_PROGRAM, EBUS_PROGRAM_PCSR),
	    EBUS_PROGRAM_PCR_PROGRAM);

	retval = bscv_get8(ssp, chan_prog,
	    BSCVA(EBUS_CMD_SPACE_PROGRAM, EBUS_PROGRAM_PCSR));

	*calcd_chksum = chksum;
	return (retval);
}

static uint8_t bscv_do_page(bscv_soft_state_t *ssp, uint32_t loadaddr,
    uint32_t index, uint32_t image_size, uint32_t pagesize, uint8_t *imagep,
    boolean_t is_image2)
{
	int retryable = BSC_PAGE_RETRY_LIMIT;
	uint8_t retval;
	uint16_t checksum;

	BSCV_TRACE(ssp, 'P', "bscv_do_page", "index 0x%x", index);

	while (retryable--) {
		/*
		 * Set the page address (with retries).  If this is not
		 * successful, then there is no point carrying on and sending
		 * the page's data since that could cause random memory
		 * corruption in the microcontroller.
		 */
		retval = bscv_set_page(ssp, loadaddr + index);
		if (!PSR_SUCCESS(retval)) {
			cmn_err(CE_WARN, "programming error 0x%x, "
			    "could not setup page address 0x%x, %s image",
			    retval, loadaddr + index,
			    is_image2 ? "main" : "loader");
			break;
		}

		/*
		 * Send down the data for the page
		 */

		BSCV_TRACE(ssp, 'P', "bscv_do_page", "sending data for page");

		retval = bscv_do_page_data_once(ssp, index, image_size,
		    pagesize, imagep, &checksum);
		if (PSR_SUCCESS(retval))
			break;
		else
			cmn_err(CE_WARN, "programming error 0x%x,"
			    " attempt %d, index 0x%x, checksum 0x%x, %s image",
			    retval, BSC_PAGE_RETRY_LIMIT - retryable,
			    index, checksum, is_image2 ? "main" : "loader");
	}

	BSCV_TRACE(ssp, 'U', "bscv_do_page", "Returning 0x%x for index 0x%x,"
	    " checksum 0x%x, %s image", retval, index, checksum,
	    is_image2 ? "main" : "loader");

	return (retval);
}

static uint8_t
bscv_do_pages(bscv_soft_state_t *ssp, uint32_t loadaddr, uint32_t image_size,
    uint32_t pagesize, uint8_t *imagep, boolean_t is_image2)
{
	uint8_t retval;
	uint32_t index;

	BSCV_TRACE(ssp, 'P', "bscv_do_pages", "entered");

	for (index = 0; index < image_size; index += pagesize) {
		retval = bscv_do_page(ssp, loadaddr, index, image_size,
		    pagesize, imagep, is_image2);
		if (bscv_faulty(ssp) || !PSR_SUCCESS(retval)) {
			BSCV_TRACE(ssp, 'U', "bscv_do_pages",
			    "Failed to program lom (status 0x%x)", retval);
			break;
		}
	}

	return (retval);
}

static int
bscv_prog_image(bscv_soft_state_t *ssp, boolean_t is_image2,
    uint8_t *imagep, int image_size, uint32_t loadaddr)
{
	uint32_t pagesize;
	int res = 0;
	uint8_t retval;

	BSCV_TRACE(ssp, 'U', "bscv_prog_image",
	    "image 0x%x, imagep %p, size 0x%x",
	    is_image2 ? 2 : 1, imagep, image_size);

	if (!bscv_check_loader_config(ssp, is_image2))
		/*
		 * Return no error to allow userland to continue on with
		 * downloading the image.
		 */
		return (0);

	bscv_enter(ssp);

	pagesize = bscv_get_pagesize(ssp);

	retval = bscv_enter_programming_mode(ssp);
	if (bscv_faulty(ssp) || !PSR_PROG(retval)) {
		cmn_err(CE_WARN, "lom: Failed to enter program mode, error 0x%x"
		    ", %s image", retval, is_image2 ? "main" : "loader");
		res = EIO;
		goto BSCV_PROG_IMAGE_END;
	}
	BSCV_TRACE(ssp, 'U', "bscv_prog_image", "entered programming mode");

	/*
	 * Only issue an erase if we are downloading the image.  The loader
	 * does not need this step.
	 */
	if (is_image2 && (image_size != 0)) {
		retval = bscv_do_erase(ssp, loadaddr, image_size, is_image2);
		if (bscv_faulty(ssp) || !PSR_SUCCESS(retval)) {
			cmn_err(CE_WARN,
			    "lom: Erase failed during programming, status 0x%x",
			    retval);
			res = EIO;
			goto BSCV_PROG_IMAGE_END;
		} else {
			BSCV_TRACE(ssp, 'U', "bscv_prog_image",
			    "erase complete - programming...");

		}
	}

	(void) bscv_set_pagesize(ssp, pagesize);

	retval = bscv_do_pages(ssp, loadaddr, image_size, pagesize, imagep,
	    is_image2);
	if (bscv_faulty(ssp) || !PSR_SUCCESS(retval)) {
		BSCV_TRACE(ssp, 'U', "bscv_prog_image",
		    "Failed to program lom (status 0x%x)", retval);
		res = EIO;
		goto BSCV_PROG_IMAGE_END;
	}

BSCV_PROG_IMAGE_END:
	if (res == 0 && !is_image2) {
		/*
		 * We've downloaded the loader successfully.  Now make the
		 * microcontroller jump to it.
		 */
		bscv_set_jump_to_addr(ssp, loadaddr);
		ssp->loader_running = B_TRUE;
		bscv_leave_programming_mode(ssp, B_TRUE);
	} else {
		/*
		 * We've just downloaded either the loader which failed, or
		 * the image (which may or may not have been successful).
		 */
		bscv_set_jump_to_addr(ssp, 0);

		if (res != 0) {
			BSCV_TRACE(ssp, 'U', "bscv_prog_image",
			    "got error 0x%x - leaving programming mode",
			    res);
			cmn_err(CE_WARN, "programming error 0x%x, %s image",
			    res, is_image2 ? "main" : "loader");
		} else {
			BSCV_TRACE(ssp, 'U', "bscv_prog_image",
			    "programming complete - leaving programming mode");
		}

		bscv_leave_programming_mode(ssp, B_FALSE);
		ssp->loader_running = B_FALSE;
	}

	bscv_exit(ssp);

	return (res);
}


static int
bscv_prog_receive_image(bscv_soft_state_t *ssp, lom_prog_t *prog,
    uint8_t *imagep, int max_size)
{
	int	res = 0;
	uint_t	size;
	int32_t loadaddr;
	lom_prog_data_t *prog_data;

	if ((prog->index & 0x7FFF) != ssp->prog_index) {
		BSCV_TRACE(ssp, 'U', "bscv_prog_receive_image",
		    "Got wrong buffer 0x%x, expected 0x%x",
		    prog->index & 0x7fff, ssp->prog_index);
		return (EINVAL);
	}

	/*
	 * We want to get the whole image and then do the download.
	 * It is assumed the device is now in programming mode.
	 */

	if ((prog->index & 0x7fff) == 0) {
		/* Starting a new image */
		ssp->image_ptr = 0;
	}

	if ((ssp->image_ptr + prog->size) > max_size) {
		cmn_err(CE_WARN,
		    "lom image exceeded maximum size: got 0x%x, maximum 0x%x",
		    (ssp->image_ptr + prog->size), max_size);
		return (EFAULT);
	}
	bcopy(prog->data, &imagep[ssp->image_ptr], prog->size);
	ssp->image_ptr += prog->size;

	ssp->prog_index++;

	if (prog->index & 0x8000) {
		/*
		 * OK we have the whole image so synch up and start download.
		 */
		prog_data = (lom_prog_data_t *)imagep;
		if (prog_data->header.magic != PROG_MAGIC) {
			/* Old style programming data */
			/* Take care image may not fill all of structure */

			/* sign extend loadaddr from 16  to 32 bits */
			loadaddr = (int16_t)((uint16_t)((imagep[2] << 8) +
			    imagep[3]));

			size = (imagep[0] << 8) + imagep[1];
			if (size != (ssp->image_ptr - 4)) {
				cmn_err(CE_WARN, "Image size mismatch:"
				    " expected 0x%x, got 0x%x",
				    size, (ssp->image_ptr - 1));
			}

			res = bscv_prog_image(ssp,
			    ssp->image2_processing,
			    imagep + 4, ssp->image_ptr - 4, loadaddr);

			/*
			 * Done the loading so set the flag to say we are doing
			 * the other image.
			 */
			ssp->image2_processing = !ssp->image2_processing;
		} else if ((ssp->image_ptr < sizeof (*prog_data)) ||
		    (prog_data->platform.bscv.size !=
		    (ssp->image_ptr - sizeof (*prog_data)))) {
			/* Image too small for new style image */
			cmn_err(CE_WARN, "image too small");
			res = EINVAL;
		} else {
			/* New style programming image */
			switch (prog_data->platmagic) {
			case PROG_PLAT_BSCV_IMAGE:
				res = bscv_prog_image(ssp, B_TRUE,
				    imagep + sizeof (*prog_data),
				    prog_data->platform.bscv.size,
				    prog_data->platform.bscv.loadaddr);
				ssp->image2_processing = B_FALSE;
				break;
			case PROG_PLAT_BSCV_LOADER:
				res = bscv_prog_image(ssp, B_FALSE,
				    imagep + sizeof (*prog_data),
				    prog_data->platform.bscv.size,
				    prog_data->platform.bscv.loadaddr);
				ssp->image2_processing = B_TRUE;
				break;
			default:
				cmn_err(CE_WARN, "unknown platmagic 0x%x",
				    prog_data->platmagic);
				res = EINVAL;
				break;
			}
		}
		ssp->prog_index = 0;
		ssp->image_ptr = 0;
	}
	return (res);
}

static int
bscv_prog_stop_lom(bscv_soft_state_t *ssp)
{
	if (ssp->programming) {
		/*
		 * Already programming - this may be a retry of a failed
		 * programming attempt or just a software error!
		 */
		goto queue_stopped;
	}

	if (bscv_pause_event_daemon(ssp) == BSCV_FAILURE) {
		BSCV_TRACE(ssp, 'Q', "bscv_prog_stop_lom",
		    "failed to pause event daemon thread");
		return (EAGAIN);
	}

	bscv_enter(ssp);

	ssp->programming = B_TRUE;

	bscv_exit(ssp);

queue_stopped:

	ssp->prog_index = 0;
	ssp->image2_processing = B_FALSE;

	return (0);
}

static int
bscv_prog_start_lom(bscv_soft_state_t *ssp)
{
	int res = 0;

	if (!ssp->programming) {
		/* Not programming so this is not a valid command */
		return (EINVAL);
	}

	if (ssp->image != NULL) {
		kmem_free((void *)ssp->image, BSC_IMAGE_MAX_SIZE);
		ssp->image = NULL;
	}

	/*
	 * OK we are out of reset now so:
	 * Probe the firmware and set everything up.
	 */

	bscv_enter(ssp);

	/* Explicit clear fault because things may have been mended now */
	bscv_clear_fault(ssp);

	if (ssp->loader_running) {
		cmn_err(CE_WARN, "Firmware upgrade failed to exit loader - "
		    "performing forced exit");
		/* Must try to restart the lom here. */
		/* Ensure prog mode entry to enable PRGMODE_OFF */
		bscv_put8(ssp, chan_prog,
		    BSCVA(EBUS_CMD_SPACE_PROGRAM, EBUS_PROGRAM_PCSR),
		    EBUS_PROGRAM_PCR_PRGMODE_ON);
		bscv_put8(ssp, chan_prog,
		    BSCVA(EBUS_CMD_SPACE_PROGRAM, EBUS_PROGRAM_PCSR),
		    EBUS_PROGRAM_PCR_PRGMODE_OFF);
		ssp->loader_running = B_FALSE;
		/* give the lom chance to recover */
		delay(drv_usectohz(5000000));	/* 5 seconds */
	}

	ssp->prog_mode_only = B_FALSE;
	ssp->programming = B_FALSE;

	if (bscv_attach_common(ssp) == DDI_FAILURE) {
		ssp->prog_mode_only = B_TRUE;
		res = EIO;
	}

	bscv_exit(ssp);

	if (!ssp->prog_mode_only) {
		/*
		 * Start the event thread after the queue has started
		 *
		 * Not sure if this is entirely correct because
		 * the other code at the end of bscv_attach()
		 * does not get run here.
		 */
		bscv_start_event_daemon(ssp);
		bscv_resume_event_daemon(ssp);
	}

	return (res);
}


/*
 * *********************************************************************
 * Attach processing
 * *********************************************************************
 */

/*
 * function	- bscv_attach_common
 * description	- this routine co-ordinates the initialisation of the
 *		  driver both at attach time and after firmware programming.
 * sequence	- bscv_setup_capability - read LOMlite2 capabilities
 *		  bscv_probe_check - test comms and setup register cache
 *		  bscv_setup_hostname - sync stored name in lom with nodename.
 *		  bscv_setup_static_info - read device names etc.
 *		  bscv_setup_events - start event daemon etc.
 *
 * inputs	- device information structure, DDI_ATTACH command
 * outputs	- DDI_SUCCESS or DDI_FAILURE
 */

static int
bscv_attach_common(bscv_soft_state_t *ssp)
{
	ASSERT(bscv_held(ssp));

	BSCV_TRACE(ssp, 'A', "bscv_attach_common:", "");

	/*
	 * Set the threshold for reporting messages to the console to
	 * Warnings or higher.
	 */
	ssp->reporting_level = 2;

	/*
	 * When the system is not running the Operating System, make
	 * the microcontroller print event messages straight onto the
	 * console.
	 */
	ssp->serial_reporting = LOM_SER_EVENTS_DEF;

	/* Setup capabilities */
	bscv_setup_capability(ssp);

	if (bscv_probe_check(ssp) == DDI_FAILURE) {
		cmn_err(CE_WARN, "BSC chip not responding");
		/*
		 * We want lom -G to talk to this driver upon broken firmware
		 * so we prematurely return success here.
		 */
		return (DDI_SUCCESS);
	}

	bscv_setup_hostname(ssp);
	bscv_setup_static_info(ssp);
	bscv_setup_events(ssp);

#if defined(__i386) || defined(__amd64)
	bscv_inform_bsc(ssp, BSC_INFORM_ONLINE);
#endif /* __i386 || __amd64 */
	/*
	 * Watchdog configuration and CPU signatures are sent asynchronously
	 * with respect to attach so only inform the BSC if we've already
	 * sent the data in the past.
	 */

	if (ssp->progress & BSCV_WDOG_CFG)
		bscv_setup_watchdog(ssp);

#ifdef __sparc
	if (ssp->progress & BSCV_SIG_SENT)
		bscv_write_sig(ssp, ssp->last_sig);
#endif /* __sparc */

	return (DDI_SUCCESS);
}

/*
 * function	- bscv_cleanup
 * description	- routine that does the necessary tidying up if the attach
 *		  request fails or the driver is to be detached.
 *		  If the event thread has been started we may fail to
 *		  stop it (because it is busy) so we fail the cleanup
 *		  and hence the detach. All other calls to bscv_cleanup
 *		  are done before the event daemon is started.
 * inputs	- soft state structure address.
 * outputs	- DDI_SUCCESS or DDI_FAILURE.
 */

static int
bscv_cleanup(bscv_soft_state_t *ssp)
{
	int	instance;
	uint8_t bits2set;
	uint8_t bits2clear;

	instance = ssp->instance;

	if (ssp->progress & BSCV_LOCKS) {
		bscv_enter(ssp);
	}

	if (ssp->progress & BSCV_THREAD) {
		if (bscv_stop_event_daemon(ssp) == DDI_FAILURE) {
			/* Fail the cleanup - may be able to cleanup later */
			if (ssp->progress & BSCV_LOCKS) {
				bscv_exit(ssp);
			}
			return (DDI_FAILURE);
		}
	}

	if (ssp->progress & BSCV_NODES) {
		ddi_remove_minor_node(ssp->dip, NULL);
	}

	if (ssp->progress & BSCV_MAPPED_REGS) {
		/*
		 * switch back on serial event reporting - cover all configs.
		 */
		bits2set = 0;
		bits2clear = 0;
		if (ssp->serial_reporting == LOM_SER_EVENTS_ON) {
			bits2clear |= EBUS_ALARM_NOEVENTS;
		} else if (ssp->serial_reporting == LOM_SER_EVENTS_OFF) {
			bits2set |= EBUS_ALARM_NOEVENTS;
		} else if (ssp->serial_reporting == LOM_SER_EVENTS_DEF) {
			bits2clear |= EBUS_ALARM_NOEVENTS;
		}
		bscv_setclear8_volatile(ssp, chan_general, EBUS_IDX_ALARM,
		    bits2set, bits2clear);

		/*
		 * disable the reset function if we have enabled
		 * it. We don't want any nasty surprises like system
		 * rebooting unexpectedly.  If we timeout on the busy
		 * flag we just have to carry on.
		 */

		BSCV_TRACE(ssp, 'W', "bscv_cleanup",
		    "bscv_cleanup - disable wdog");
		if (bscv_get8_cached(ssp, EBUS_IDX_WDOG_CTRL) &
		    EBUS_WDOG_ENABLE) {
			bscv_setclear8(ssp, chan_general, EBUS_IDX_WDOG_CTRL,
			    0, EBUS_WDOG_RST | EBUS_WDOG_ENABLE);
		}
	}

	/*
	 * unmap registers
	 */

	if (ssp->progress & BSCV_MAPPED_REGS) {
		bscv_unmap_regs(ssp);
	}

	/*
	 * release any memory allocated for mutexes and condition
	 * variables before deallocating the structures containing them
	 */

	if (ssp->progress & BSCV_LOCKS) {
		bscv_exit(ssp);
		cv_destroy(&ssp->task_cv);
		cv_destroy(&ssp->task_evnt_cv);
		mutex_destroy(&ssp->task_mu);
		mutex_destroy(&ssp->prog_mu);
		mutex_destroy(&ssp->cmd_mutex);
	}

	if (ssp->image != NULL) {
		kmem_free((void *)ssp->image, BSC_IMAGE_MAX_SIZE);
	}

#if defined(__i386) || defined(__amd64)
	bscv_watchdog_cyclic_remove(ssp);
#endif /* __i386 || __amd64 */
	ddi_soft_state_free(bscv_statep, instance);

	return (DDI_SUCCESS);
}

/*
 * function	- bscv_setup_capability
 * description	- probe the lom find what capabilities are present for
 *		  us to use.
 * inputs	- soft state ptr
 * outputs	- returns DDI_SUCCESS or DDI_FAILURE
 */
static void bscv_setup_capability(bscv_soft_state_t *ssp)
{
	ASSERT(bscv_held(ssp));

	if (ssp->prog_mode_only) {
		/* Turn off all capabilities */
		ssp->cap0 = 0;
		ssp->cap1 = 0;
		ssp->cap2 = 0;
		return;
	}

	ssp->cap0 = bscv_get8(ssp, chan_general, EBUS_IDX_CAP0);
	ssp->cap1 = bscv_get8(ssp, chan_general, EBUS_IDX_CAP1);
	ssp->cap2 = bscv_get8(ssp, chan_general, EBUS_IDX_CAP2);
	if (!bscv_faulty(ssp)) {
		BSCV_TRACE(ssp, 'A', "bscv_setup_capability",
		    "Capability flags cap0=0x%x cap1=0x%x, cap2=0x%x",
		    ssp->cap0, ssp->cap1, ssp->cap2);
	} else {
		cmn_err(CE_WARN, "!Could not read capability flags");
		ssp->cap0 = 0; ssp->cap1 = 0; ssp->cap2 = 0;
	}
}

/*
 * function	- bscv_probe_check
 * description	- probe the lom to check for correct operation
 *		  has a side effect of setting up the cached registers and
 *		  updates ssp->prog_mode_only.
 * inputs	- soft state ptr
 * outputs	- returns DDI_SUCCESS or DDI_FAILURE
 */

static int bscv_probe_check(bscv_soft_state_t *ssp)
{
	int i;
	uint8_t probeval;

	ASSERT(bscv_held(ssp));

	BSCV_TRACE(ssp, 'A', "bscv_probe_check", "");

	if (!ssp->prog_mode_only) {
		/*
		 * Make sure probe location is OK so that we are
		 * in sync.
		 * We want to make sure that this is not faulty so we
		 * do a bscv_clear_fault to clear any existing
		 * fault records down.
		 */
		bscv_clear_fault(ssp);
		probeval = bscv_get8(ssp, chan_general, EBUS_IDX_PROBEAA);
		if (bscv_faulty(ssp)) {
			ssp->prog_mode_only = B_TRUE;
		} else if (probeval != 0xAA) {
			BSCV_TRACE(ssp, 'A', "bscv_probe_check",
			    "LOMlite out of sync");

			/*
			 * It may be that the LOMlite was out of
			 * sync so lets try the read again.
			 */
			probeval = bscv_get8(ssp, chan_general,
			    EBUS_IDX_PROBEAA);
			if (bscv_faulty(ssp)) {
				BSCV_TRACE(ssp, 'A', "bscv_probe_check",
				    "Init readAA1 failed");
				ssp->prog_mode_only = B_TRUE;
			} else if (probeval != 0xAA) {
				/*
				 * OK that is twice we are out so I
				 * guess the LOMlite is in trouble
				 */
				BSCV_TRACE(ssp, 'A', "bscv_probe_check",
				    "Init readAA probe failed - got 0x%x",
				    probeval);
				ssp->prog_mode_only = B_TRUE;
			}
		}
	}

	/*
	 * Read in all page zero lom registers.
	 * Read state change 1st so we dont miss anything and clear it.
	 * Note: we discard the values because we rely on bscv_get8 to
	 * setup the cache of register values.
	 */

	if (!ssp->prog_mode_only) {
		(void) bscv_get8(ssp, chan_general, EBUS_IDX_STATE_CHNG);
		if (bscv_faulty(ssp)) {
			BSCV_TRACE(ssp, 'A', "bscv_probe_check",
			    "Read of state change register failed");
			ssp->prog_mode_only = B_TRUE;
		}
	}

	if (!ssp->prog_mode_only) {
		for (i = 1; i < 0x80; i++) {
			switch (i) {
			case EBUS_IDX_STATE_CHNG:
			case EBUS_IDX_CMD_RES:
			case EBUS_IDX_HNAME_CHAR:
				/*
				 * Should not read these - they have side
				 * effects.
				 */
				break;
			default:
				(void) bscv_get8(ssp, chan_general, i);
				break;
			}
			if (bscv_faulty(ssp)) {
				BSCV_TRACE(ssp, 'A', "bscv_probe_check",
				    "Initial read or register %2x failed", i);
				ssp->prog_mode_only = B_TRUE;
				/* Might as well give up now! */
				break;
			}
		}
	}

	/*
	 * Check the probe keys so we know the lom is OK
	 */

	if (!ssp->prog_mode_only) {
		if ((bscv_get8_cached(ssp, EBUS_IDX_PROBE55) != 0x55) ||
		    (bscv_get8_cached(ssp, EBUS_IDX_PROBEAA) != 0xAA)) {

			BSCV_TRACE(ssp, 'A', "bscv_probe_check",
			    "LOMlite Probe failed");
			for (i = 0; i < 0x8; i++) {
				BSCV_TRACE(ssp, 'A', "bscv_probe_check",
				    "%2x %2x %2x %2x %2x %2x %2x %2x %2x "
				    "%2x %2x %2x %2x %2x %2x %2x %2x %2x",
				    bscv_get8_cached(ssp, i),
				    bscv_get8_cached(ssp, i + 1),
				    bscv_get8_cached(ssp, i + 2),
				    bscv_get8_cached(ssp, i + 3),
				    bscv_get8_cached(ssp, i + 4),
				    bscv_get8_cached(ssp, i + 5),
				    bscv_get8_cached(ssp, i + 6),
				    bscv_get8_cached(ssp, i + 7),
				    bscv_get8_cached(ssp, i + 8),
				    bscv_get8_cached(ssp, i + 9),
				    bscv_get8_cached(ssp, i + 10),
				    bscv_get8_cached(ssp, i + 11),
				    bscv_get8_cached(ssp, i + 12),
				    bscv_get8_cached(ssp, i + 13),
				    bscv_get8_cached(ssp, i + 14),
				    bscv_get8_cached(ssp, i + 15));
			}
			ssp->prog_mode_only = B_TRUE;
		}
	}

	return ((ssp->prog_mode_only == B_FALSE) ? DDI_SUCCESS : DDI_FAILURE);
}

#ifdef __sparc
/*
 * function	- bscv_idi_set
 * description	- bscv inter driver interface set function
 * inputs	- structure which defines type of service required and data
 * ouputs	- none
 *
 * This is the Entry Point function for the platmod driver. It works out which
 * X Bus channel ought to deliver the service requested.
 */
void
bscv_idi_set(struct bscv_idi_info info)
{
	struct bscv_idi_callout *tbl;
	boolean_t retval;

	ASSERT(bscv_idi_mgr.magic == BSCV_IDI_CALLOUT_MAGIC);

	if (bscv_idi_mgr.tbl == NULL) {
		if (bscv_idi_err())
			cmn_err(CE_WARN, "!bscv_idi_set : cannot find "
			    "bscv_callout_table");
		return;
	} else if (bscv_idi_mgr.valid_inst == (uint32_t)~0) {
		if (bscv_idi_err())
			/*
			 * This error message can appear in the context of
			 * another driver, say platmod or todblade.  We want
			 * to clearly indicate the culprit driver so put in
			 * the driver name.
			 */
			cmn_err(CE_WARN, "!bscv_idi_set : no valid "
			    "driver instance of "
			    MYNAME);
		return;
	}

	tbl = bscv_idi_mgr.tbl;

	while (tbl->type != BSCV_IDI_NULL) {
		if (tbl->type == info.type) {
			/*
			 * We service the request with a valid instance number
			 * for the driver.
			 */
			retval = ((tbl->fn) (info));

			/*
			 * If the request was serviced, clear any accumulated
			 * error counters so future warnings will be reported if
			 * seen.
			 */
			if (retval == B_TRUE)
				bscv_idi_clear_err();
			return;
		} else {
			tbl++;
		}
	}

	if (bscv_idi_err())
		cmn_err(CE_WARN, "!bscv_idi_set : cannot match info.type %d",
		    info.type);
}

/*
 * function     - bscv_nodename_set
 * description  - notify the event thread that a nodename change has occurred.
 * inputs       - data from client driver
 * outputs	- none.
 * side-effects - the event thread will schedule an update to the lom firmware.
 */
/*ARGSUSED*/
static boolean_t
bscv_nodename_set(struct bscv_idi_info info)
{
	bscv_soft_state_t *ssp;

	ssp = ddi_get_soft_state(bscv_statep, bscv_idi_mgr.valid_inst);

	if (ssp == NULL) {
		if (bscv_idi_err())
			cmn_err(CE_WARN, "!blade_nodename_set: cannot get ssp");
		return (B_FALSE);
	}

	/* Get a lock on the SSP, notify our change, then exit */
	mutex_enter(&ssp->task_mu);
	ssp->nodename_change = B_TRUE;
	cv_signal(&ssp->task_cv);
	mutex_exit(&ssp->task_mu);

	return (B_TRUE);
}

/*
 * function	- bscv_sig_set
 * description	- write a signature
 * inputs	- data from client driver
 * outputs	- none.
 */
static boolean_t
bscv_sig_set(struct bscv_idi_info info)
{
	bscv_soft_state_t *ssp;
	bscv_sig_t sig;

	ssp = ddi_get_soft_state(bscv_statep, bscv_idi_mgr.valid_inst);

	if (ssp == NULL) {
		if (bscv_idi_err())
			cmn_err(CE_WARN, "!blade_nodename_set: cannot get ssp");
		return (B_FALSE);
	}

	/* Service the request */
	bcopy(info.data, &sig, sizeof (sig));
	bscv_enter(ssp);
	bscv_write_sig(ssp, sig);
	bscv_exit(ssp);

	return (B_TRUE);
}
#endif /* __sparc */

static void
bscv_wdog_do_pat(bscv_soft_state_t *ssp)
{
	uint8_t pat;

	/*
	 * The value of the dog pat is a sequence number which wraps around,
	 * bounded by BSCV_WDOG_PAT_SEQ_MASK.
	 */
	pat = ssp->pat_seq++;
	pat &= EBUS_WDOG_NB_PAT_SEQ_MASK;

	/* Set top nibble to indicate a pat */
	pat |= EBUS_WDOG_NB_PAT;

	/*
	 * Now pat the dog.  This exercises a special protocol in the
	 * bus nexus that offers : non-blocking IO, and timely delivery,
	 * callable from high-level interrupt context.  The requirement
	 * on us is that the channel is not shared for any other use.
	 * This means for chan_wdogpat, nothing may use channel[chan].regs
	 * or channel.[chan].handle.
	 */

	ddi_put8(ssp->channel[chan_wdogpat].handle,
	    ssp->channel[chan_wdogpat].regs, pat);

	BSCV_TRACE(ssp, 'W', "bscv_wdog_pat", "patted the dog with seq %d",
	    pat);
}

#ifdef __sparc
/*
 * function	- bscv_wdog_pat
 * description	- pat the watchdog
 * inputs	- data from client driver
 * outputs	- none.
 */
/*ARGSUSED*/
static boolean_t
bscv_wdog_pat(struct bscv_idi_info info)
{
	/*
	 * This function remembers if it has ever been called with the
	 * configure option set.
	 */
	bscv_soft_state_t *ssp;

	ssp = ddi_get_soft_state(bscv_statep, bscv_idi_mgr.valid_inst);

	if (ssp == NULL) {
		if (bscv_idi_err())
			cmn_err(CE_WARN, "!bscv_wdog_pat: cannot get ssp");
		return (B_FALSE);
	} else if (ssp->nchannels == 0) {
		/* Didn't manage to map handles so ddi_{get,put}* broken */
		if (bscv_idi_err())
			cmn_err(CE_WARN, "!bscv_wdog_pat: handle not mapped");
		return (B_FALSE);
	}

	bscv_wdog_do_pat(ssp);
	return (B_TRUE);
}

/*
 * function	- bscv_wdog_cfg
 * description	- configure the watchdog
 * inputs	- data from client driver
 * outputs	- none.
 */
static boolean_t
bscv_wdog_cfg(struct bscv_idi_info info)
{
	bscv_soft_state_t *ssp;

	ssp = ddi_get_soft_state(bscv_statep, bscv_idi_mgr.valid_inst);

	if (ssp == NULL) {
		if (bscv_idi_err())
			cmn_err(CE_WARN, "!bscv_wdog_cfg: cannot get ssp");
		return (B_FALSE);
	} else if (ssp->nchannels == 0) {
		/* Didn't manage to map handles so ddi_{get,put}* broken */
		if (bscv_idi_err())
			cmn_err(CE_WARN, "!bscv_wdog_cfg: handle not mapped");
		return (B_FALSE);
	}

	if (sizeof (bscv_wdog_t) != info.size) {
		BSCV_TRACE(ssp, 'W', "bscv_wdog_set", "data passed in is size"
		    " %d instead of %d", info.size,
		    sizeof (bscv_wdog_t));
		return (B_FALSE);
	}

	BSCV_TRACE(ssp, 'W', "bscv_wdog_cfg", "enable_wdog %s, "
	    "wdog_timeout_s %d, reset_system_on_timeout %s",
	    ((bscv_wdog_t *)info.data)->enable_wdog ? "enabled" : "disabled",
	    ((bscv_wdog_t *)info.data)->wdog_timeout_s,
	    ((bscv_wdog_t *)info.data)->reset_system_on_timeout ? "yes" : "no");
	bscv_write_wdog_cfg(ssp,
	    ((bscv_wdog_t *)info.data)->wdog_timeout_s,
	    ((bscv_wdog_t *)info.data)->enable_wdog,
	    ((bscv_wdog_t *)info.data)->reset_system_on_timeout);
	return (B_TRUE);
}
#endif /* __sparc */

static void
bscv_write_wdog_cfg(bscv_soft_state_t *ssp,
    uint_t wdog_timeout_s,
    boolean_t enable_wdog,
    uint8_t reset_system_on_timeout)
{
	uint8_t cfg = EBUS_WDOG_NB_CFG;

	/*
	 * Configure the timeout value (1 to 127 seconds).
	 * Note that a policy is implemented at the bsc/ssp which bounds
	 * the value further. The bounding here is to fit the timeout value
	 * into the 7 bits the bsc uses.
	 */
	if (wdog_timeout_s < 1)
		ssp->watchdog_timeout = 1;
	else if (wdog_timeout_s > 127)
		ssp->watchdog_timeout = 127;
	else
		ssp->watchdog_timeout = wdog_timeout_s;

	/*
	 * Configure the watchdog on or off.
	 */
	if (enable_wdog)
		cfg |= EBUS_WDOG_NB_CFG_ENB;
	else
		cfg &= ~EBUS_WDOG_NB_CFG_ENB;

	/*
	 * Configure whether the microcontroller should reset the system when
	 * the watchdog expires.
	 */
	ssp->watchdog_reset_on_timeout = reset_system_on_timeout;

	ddi_put8(ssp->channel[chan_wdogpat].handle,
	    ssp->channel[chan_wdogpat].regs, cfg);

	/* have the event daemon set the timeout value and whether to reset */
	ssp->watchdog_change = B_TRUE;

	BSCV_TRACE(ssp, 'W', "bscv_wdog_cfg",
	    "configured the dog with cfg 0x%x", cfg);
}

/*
 * function	- bscv_setup_watchdog
 * description	- setup the  bsc watchdog
 * inputs	- soft state ptr
 * outputs	-
 */
static void bscv_setup_watchdog(bscv_soft_state_t *ssp)
{
	uint8_t set = 0;
	uint8_t clear = 0;
#ifdef __sparc
	extern int watchdog_activated;
#endif /* __sparc */

	ASSERT(bscv_held(ssp));

	/* Set the timeout */
	bscv_put8(ssp, chan_general,
	    EBUS_IDX_WDOG_TIME, ssp->watchdog_timeout);

	/* Set whether to reset the system on timeout */
	if (ssp->watchdog_reset_on_timeout) {
		set |= EBUS_WDOG_RST;
	} else {
		clear |= EBUS_WDOG_RST;
	}

	if (watchdog_activated) {
		set |= EBUS_WDOG_ENABLE;
	} else {
		clear |= EBUS_WDOG_ENABLE;
	}

	/* Set other host defaults */
	clear |= (EBUS_WDOG_BREAK_DISABLE | EBUS_WDOG_AL3_FANPSU
	    | EBUS_WDOG_AL3_WDOG);

	bscv_setclear8_volatile(ssp, chan_general, EBUS_IDX_WDOG_CTRL,
	    set, clear);

#if defined(__i386) || defined(__amd64)
	/* start the cyclic based watchdog patter */
	bscv_watchdog_cyclic_add(ssp);
#endif /* __i386 || __amd64 */
	ssp->progress |= BSCV_WDOG_CFG;
}


/*
 * function	- bscv_setup_hostname
 * description	- setup the lom hostname if different from the nodename
 * inputs	- soft state ptr
 * outputs	- none
 */

static void bscv_setup_hostname(bscv_soft_state_t *ssp)
{
	char	host_nodename[128];
	char	lom_nodename[128];
	size_t	hostlen;
	size_t	nodelen;

	ASSERT(bscv_held(ssp));

	/*
	 * Check machine label is the same as the
	 * system nodename.
	 */
	(void) strncpy(host_nodename, utsname.nodename,
	    sizeof (host_nodename));

	/* read in lom hostname */
	bscv_read_hostname(ssp, lom_nodename);

	/* Enforce null termination */
	host_nodename[sizeof (host_nodename) - 1] = '\0';
	lom_nodename[sizeof (lom_nodename) - 1] = '\0';

	hostlen = (size_t)bscv_get8(ssp, chan_general, EBUS_IDX_HNAME_LENGTH);
	nodelen = (size_t)strlen(host_nodename);
	if ((nodelen > 0) &&
	    ((hostlen != nodelen) || (strcmp((const char *)&lom_nodename,
	    (const char *)&host_nodename)) ||
	    (hostlen == 0))) {
		BSCV_TRACE(ssp, 'A', "bscv_setup_hostname",
		    "nodename(%s,%d) != bsc label(%s,%d)",
		    host_nodename, nodelen, lom_nodename, hostlen);

		/* Write new label into LOM EEPROM */
		bscv_write_hostname(ssp,
		    host_nodename,
		    (uint8_t)strlen(host_nodename));
	}

	ssp->progress |= BSCV_HOSTNAME_DONE;
}

/*
 * function	- bscv_read_hostname
 * description	- read the current hostname from the lom
 * inputs	- soft state pointer and buffer to store the hostname in.
 * outputs	- none
 */

static void
bscv_read_hostname(bscv_soft_state_t *ssp, char *lom_nodename)
{
	int num_failures;
	boolean_t needretry;
	int length;
	int i;

	ASSERT(bscv_held(ssp));

	/*
	 * We have a special failure case here because a retry of a read
	 * causes data to be lost. Thus we handle the retries ourselves
	 * and are also responsible for detemining if the lom is faulty
	 */
	for (num_failures = 0;
	    num_failures < BSC_FAILURE_RETRY_LIMIT;
	    num_failures++) {
		bscv_clear_fault(ssp);
		length = bscv_get8(ssp, chan_general, EBUS_IDX_HNAME_LENGTH);
		if (bscv_faulty(ssp)) {
			needretry = 1;
		} else {
			needretry = 0;
			for (i = 0; i < length; i++) {
				lom_nodename[i] = bscv_get8_once(ssp,
				    chan_general, EBUS_IDX_HNAME_CHAR);
				/* Retry on any error */
				if (bscv_retcode(ssp) != 0) {
					needretry = 1;
					break;
				}
			}
			/* null terminate for strcmp later */
			lom_nodename[length] = '\0';
		}
		if (!needretry) {
			break;
		}
		/* Force the nodename to be empty */
		lom_nodename[0] = '\0';
	}

	if (needretry) {
		/* Failure - we ran out of retries */
		cmn_err(CE_WARN,
		    "bscv_read_hostname: retried %d times, giving up",
		    num_failures);
		ssp->had_fault = B_TRUE;
	} else if (num_failures > 0) {
		BSCV_TRACE(ssp, 'R', "bscv_read_hostname",
		    "retried %d times, succeeded", num_failures);
	}
}

/*
 * function	- bscv_write_hostname
 * description	- write a new hostname to the lom
 * inputs	- soft state pointer, pointer to new name, name length
 * outputs	- none
 */
static void
bscv_write_hostname(bscv_soft_state_t *ssp,
    char *host_nodename, uint8_t length)
{
	int num_failures;
	boolean_t needretry;
	int i;

	ASSERT(bscv_held(ssp));

	/*
	 * We have a special failure case here because a retry of a read
	 * causes data to be lost. Thus we handle the retries ourselves
	 * and are also responsible for detemining if the lom is faulty
	 */
	for (num_failures = 0;
	    num_failures < BSC_FAILURE_RETRY_LIMIT;
	    num_failures++) {
		bscv_clear_fault(ssp);
		bscv_put8(ssp, chan_general, EBUS_IDX_HNAME_LENGTH, length);
		if (bscv_faulty(ssp)) {
			needretry = 1;
		} else {
			needretry = 0;
			for (i = 0; i < length; i++) {
				bscv_put8_once(ssp, chan_general,
				    EBUS_IDX_HNAME_CHAR, host_nodename[i]);
				/* Retry on any error */
				if (bscv_retcode(ssp) != 0) {
					needretry = 1;
					break;
				}
			}
		}
		if (!needretry) {
			break;
		}
	}

	if (needretry) {
		/* Failure - we ran out of retries */
		cmn_err(CE_WARN,
		    "bscv_write_hostname: retried %d times, giving up",
		    num_failures);
		ssp->had_fault = B_TRUE;
	} else if (num_failures > 0) {
		BSCV_TRACE(ssp, 'R', "bscv_write_hostname",
		    "retried %d times, succeeded", num_failures);
	}
}

/*
 * function	- bscv_setup_static_info
 * description	- read in static information from the lom at attach time.
 * inputs	- soft state ptr
 * outputs	- none
 */

static void
bscv_setup_static_info(bscv_soft_state_t *ssp)
{
	uint8_t	addr_space_ptr;
	uint16_t mask;
	uint8_t fanspeed;
	int oldtemps[MAX_TEMPS];
	int8_t temp;
	int i;

	ASSERT(bscv_held(ssp));

	/*
	 * Finally read in some static info like device names,
	 * shutdown enabled, etc before the queue starts.
	 */

	/*
	 * To get the volts static info we need address space 2
	 */
	bzero(&ssp->volts, sizeof (lom_volts_t));
	ssp->volts.num = EBUS_CONFIG2_NSUPPLY_DEC(
	    bscv_get8(ssp, chan_general, EBUS_IDX_CONFIG2));
	if (ssp->volts.num > MAX_VOLTS) {
		cmn_err(CE_WARN,
		    "lom: firmware reported too many voltage lines. ");
		cmn_err(CE_CONT, "Reported %d, maximum is %d",
		    ssp->volts.num, MAX_VOLTS);
		ssp->volts.num = MAX_VOLTS;
	}

	BSCV_TRACE(ssp, 'A', "bscv_setup_static_info",
	    "num volts %d", ssp->volts.num);
	(void) bscv_read_env_name(ssp,
	    EBUS_CMD_SPACE2,
	    EBUS_IDX2_SUPPLY_NAME_START,
	    EBUS_IDX2_SUPPLY_NAME_END,
	    ssp->volts.name,
	    ssp->volts.num);

	mask = bscv_get8(ssp, chan_general, BSCVA(EBUS_CMD_SPACE2,
	    EBUS_IDX2_SUPPLY_FATAL_MASK1)) << 8;
	mask |= bscv_get8(ssp, chan_general, BSCVA(EBUS_CMD_SPACE2,
	    EBUS_IDX2_SUPPLY_FATAL_MASK2));

	for (i = 0; i < ssp->volts.num; i++) {
		ssp->volts.shutdown_enabled[i] =
		    (((mask >> i) & 1) == 0) ? 0 : 1;
	}

	/*
	 * Get the temperature static info and populate initial temperatures.
	 * Do not destroy old temperature values if the new value is not
	 * known i.e. if the device is inaccessible.
	 */
	bcopy(ssp->temps.temp, oldtemps, sizeof (oldtemps));

	bzero(&ssp->temps, sizeof (lom_temp_t));
	ssp->temps.num = EBUS_CONFIG2_NTEMP_DEC(
	    bscv_get8(ssp, chan_general, EBUS_IDX_CONFIG2));
	if (ssp->temps.num > MAX_TEMPS) {
		cmn_err(CE_WARN,
		    "lom: firmware reported too many temperatures being "
		    "monitored.");
		cmn_err(CE_CONT, "Reported %d, maximum is %d",
		    ssp->temps.num, MAX_TEMPS);
		ssp->temps.num = MAX_TEMPS;
	}
	ssp->temps.num_ov = EBUS_CONFIG3_NOTEMP_DEC(
	    bscv_get8(ssp, chan_general, EBUS_IDX_CONFIG3));
	if (ssp->temps.num_ov > MAX_TEMPS) {
		cmn_err(CE_WARN,
		    "lom: firmware reported too many over temperatures being "
		    "monitored.");
		cmn_err(CE_CONT, "Reported %d, maximum is %d",
		    ssp->temps.num_ov, MAX_TEMPS);
		ssp->temps.num_ov = MAX_TEMPS;
	}
	BSCV_TRACE(ssp, 'A', "bscv_setup_static_info",
	    "num temps %d, over temps %d",
	    ssp->temps.num, ssp->temps.num_ov);

	addr_space_ptr = bscv_read_env_name(ssp,
	    EBUS_CMD_SPACE4,
	    EBUS_IDX4_TEMP_NAME_START,
	    EBUS_IDX4_TEMP_NAME_END,
	    ssp->temps.name,
	    ssp->temps.num);

	for (i = 0; i < ssp->temps.num; i++) {
		ssp->temps.warning[i] = (int8_t)bscv_get8(ssp, chan_general,
		    BSCVA(EBUS_CMD_SPACE4, EBUS_IDX4_TEMP_WARN1 + i));

		/*
		 * If shutdown is not enabled then set it as zero so
		 * it is not displayed by the utility.
		 */
		if ((bscv_get8(ssp, chan_general, BSCVA(EBUS_CMD_SPACE4,
		    EBUS_IDX4_TEMP_FATAL_MASK)) >> i) & 0x01) {
			ssp->temps.shutdown[i] = (int8_t)bscv_get8(ssp,
			    chan_general,
			    BSCVA(EBUS_CMD_SPACE4, EBUS_IDX4_TEMP_SDOWN1 + i));
		} else {
			ssp->temps.shutdown[i] = 0;
		}
	}

	for (i = 0; i < ssp->temps.num; i++) {
		temp = bscv_get8(ssp, chan_general, EBUS_IDX_TEMP1 + i);
		if ((temp <= LOM_TEMP_MAX_VALUE) ||
		    (temp == LOM_TEMP_STATE_NOT_PRESENT)) {
			ssp->temps.temp[i] = temp;
		} else {
			/* New value is not known - use old value */
			ssp->temps.temp[i] = oldtemps[i];
		}
	}

	/*
	 * Check for and skip a single 0xff character between the
	 * temperature and over temperature names
	 */
	if (bscv_get8(ssp, chan_general,
	    BSCVA(EBUS_CMD_SPACE4, addr_space_ptr)) == 0xff) {
		addr_space_ptr++;
	}

	(void) bscv_read_env_name(ssp,
	    EBUS_CMD_SPACE4,
	    addr_space_ptr,
	    EBUS_IDX4_TEMP_NAME_END,
	    ssp->temps.name_ov,
	    ssp->temps.num_ov);

	/*
	 * To get the CB static info we need address space 3
	 */
	bzero(&ssp->sflags, sizeof (lom_sflags_t));
	ssp->sflags.num = EBUS_CONFIG3_NBREAKERS_DEC(bscv_get8(ssp,
	    chan_general, EBUS_IDX_CONFIG3));
	if (ssp->sflags.num > MAX_STATS) {
		cmn_err(CE_WARN,
		    "lom: firmware reported too many status flags.");
		cmn_err(CE_CONT,
		    "Reported %d, maximum is %d",
		    ssp->sflags.num, MAX_STATS);
		ssp->sflags.num = MAX_STATS;
	}
	BSCV_TRACE(ssp, 'A', "bscv_setup_static_info",
	    "num sflags %d", ssp->sflags.num);

	(void) bscv_read_env_name(ssp,
	    EBUS_CMD_SPACE3,
	    EBUS_IDX3_BREAKER_NAME_START,
	    EBUS_IDX3_BREAKER_NAME_END,
	    ssp->sflags.name,
	    ssp->sflags.num);


	/*
	 * To get the fan static info we need address space 5
	 */
	ssp->num_fans = EBUS_CONFIG_NFAN_DEC(
	    bscv_get8(ssp, chan_general, EBUS_IDX_CONFIG));
	if (ssp->num_fans > MAX_FANS) {
		cmn_err(CE_WARN,
		    "lom: firmware reported too many fans. ");
		cmn_err(CE_CONT,
		    "Reported %d, maximum is %d",
		    ssp->num_fans, MAX_FANS);
		ssp->num_fans = MAX_FANS;
	}

	for (i = 0; i < ssp->num_fans; i++) {
		fanspeed = bscv_get8(ssp, chan_general,
		    EBUS_IDX_FAN1_SPEED + i);
		if ((fanspeed <= LOM_FAN_MAX_SPEED) ||
		    (fanspeed == LOM_FAN_NOT_PRESENT)) {
			/*
			 * Do not destroy previous values unless the
			 * value is definitive.
			 */
			ssp->fanspeed[i] = fanspeed;
		}
	}

	BSCV_TRACE(ssp, 'A', "bscv_setup_static_info",
	    "num fans %d", ssp->num_fans);

	(void) bscv_read_env_name(ssp,
	    EBUS_CMD_SPACE5,
	    EBUS_IDX5_FAN_NAME_START,
	    EBUS_IDX5_FAN_NAME_END,
	    ssp->fan_names,
	    ssp->num_fans);

	/* Get led static information from address space 10 */

	(void) bscv_read_env_name(ssp,
	    EBUS_CMD_SPACE_LEDS,
	    EBUS_IDX10_LED_NAME_START,
	    EBUS_IDX10_LED_NAME_END,
	    ssp->led_names,
	    MAX_LED_ID);
}

/*
 * function	- bscv_read_env_name
 * description	- read in static environment names
 *		  warning changes address space and the caller relies
 *		  on this behaviour.
 * inputs	- soft state ptr, chosen address space,
 *		  start of name data, end of name data,
 *		  name storage, number of names.
 * outputs	- next address for reading name data.
 */

static uint8_t
bscv_read_env_name(bscv_soft_state_t *ssp,
    uint8_t addr_space,
    uint8_t addr_start,
    uint8_t addr_end,
    char namebuf[][MAX_LOM2_NAME_STR],
    int numnames)
{
	int i;
	int nameidx;
	int namemax;
	unsigned int addr_space_ptr;
	uint8_t this_char;

	ASSERT(bscv_held(ssp));

	BSCV_TRACE(ssp, 'A', "bscv_read_env_name",
	    "bscv_read_env_name, space %d, start 0x%x, end 0x%x, numnames %d",
	    addr_space, addr_start, addr_end, numnames);

	addr_space_ptr = addr_start;

	for (i = 0; i < numnames; i++) {
		nameidx = 0;
		namemax = sizeof (namebuf[i]);
		bzero(namebuf[i], namemax);

		while (addr_space_ptr <= addr_end) {
			/*
			 * Read the current character.
			 */
			this_char = bscv_get8(ssp, chan_general,
			    BSCVA(addr_space, addr_space_ptr));

			if (this_char == 0xff) {
				/*
				 * Ran out of names - this must
				 * be the end of the name.
				 * This is really an error because
				 * we have just seen either a non-NUL
				 * terminated string or the number of
				 * strings did not match what was
				 * reported.
				 */
				break;
			}
			/*
			 * We increment the buffer pointer now so that
			 * it is ready for the next read
			 */
			addr_space_ptr++;

			if (this_char == '\0') {
				/* Found end of string - done */
				break;
			}
			if (nameidx < (namemax - 1)) {
				/*
				 * Buffer not full - record character
				 * NOTE we always leave room for the NUL
				 * terminator.
				 */
				namebuf[i][nameidx++] = this_char;
			}
		}
		/* Ensure null termination */
		namebuf[i][nameidx] = '\0';
	}
	/* Clamp addr_space_ptr to 0xff because we return uint8_t */
	if (addr_space_ptr > 0xff) {
		addr_space_ptr = 0xff;
	}
	return (addr_space_ptr);
}

/*
 * function	- bscv_setup_events
 * description	- initialise the event reporting code
 * inputs	- soft state ptr
 * outputs	- DDI_SUCCESS or DDI_FAILURE
 */

static void
bscv_setup_events(bscv_soft_state_t *ssp)
{
	uint8_t bits2set;
	uint8_t bits2clear;

	ASSERT(bscv_held(ssp));

	/*
	 * deal with event reporting - cover all cases
	 */

	bits2set = 0;
	bits2clear = 0;
	if (ssp->serial_reporting == LOM_SER_EVENTS_ON) {
		bits2clear |= EBUS_ALARM_NOEVENTS;
	} else if (ssp->serial_reporting == LOM_SER_EVENTS_OFF) {
		bits2set |= EBUS_ALARM_NOEVENTS;
	} else if (ssp->serial_reporting == LOM_SER_EVENTS_DEF) {
		bits2set |= EBUS_ALARM_NOEVENTS;
	}
	bscv_setclear8_volatile(ssp, chan_general, EBUS_IDX_ALARM,
	    bits2set, bits2clear);
}

#ifdef __sparc
/*
 * function	- bscv_write_sig
 * description	- write out a signature, taking care to deal with any strange
 *		    values for CPU ID
 * inputs	- soft state ptr, signature
 * outputs	- none
 */
static void
bscv_write_sig(bscv_soft_state_t *ssp, bscv_sig_t s)
{
	ASSERT(bscv_held(ssp));

	/* Upload the signature */
	bscv_put32(ssp, chan_cpusig,
	    BSCVA(EBUS_CMD_SPACE_CPUSIG, EBUS_IDX11_CPU_SIG_MSB),
	    s.sig_info.signature);

	/*
	 * We always write the CPU ID last because this tells the firmware
	 * that the signature is fully uploaded and therefore to consume the
	 * data.  This is required since the signature is > 1 byte in size
	 * and we transmit data in single bytes.
	 */
	if (s.cpu == ~0) {
		/* ~0 means the signature applies to any CPU. */
		bscv_put8(ssp, chan_cpusig,
		    BSCVA(EBUS_CMD_SPACE_CPUSIG, EBUS_IDX11_CPU_ID),
		    EBUS_ANY_CPU_ID);
	} else {
		if (s.cpu > 255) {
			/*
			 * The CPU ID supplied is unexpectedly large.  Lets
			 * just use the bottom bits, in case other high order
			 * bits are being used for special meaning.
			 */
			cmn_err(CE_WARN, "CPU Signature ID 0x%x > 255", s.cpu);
			s.cpu %= 256;
			cmn_err(CE_CONT, "using ID 0x%x instead ", s.cpu);
		}
		bscv_put8(ssp, chan_cpusig,
		    BSCVA(EBUS_CMD_SPACE_CPUSIG, EBUS_IDX11_CPU_ID),
		    (uint8_t)s.cpu);
	}

	ssp->last_sig = s;
	ssp->progress |= BSCV_SIG_SENT;
}
#endif /* __sparc */

#if defined(__i386) || defined(__amd64)

/*
 * function	- bscv_inform_bsc
 * description	- inform bsc of driver state for logging purposes
 * inputs	- driver soft state, state
 * outputs	- none
 *
 */
static void
bscv_inform_bsc(bscv_soft_state_t *ssp, uint32_t state)
{
	ASSERT(bscv_held(ssp));

	BSCV_TRACE(ssp, 'X', "bscv_inform_bsc",
	    "bscv_inform_bsc: state=%d", state);

	bscv_put32(ssp, chan_general,
	    BSCVA(EBUS_CMD_SPACE_CPUSIG, EBUS_IDX11_CPU_SIG_MSB), state);
	bscv_put8(ssp, chan_cpusig,
	    BSCVA(EBUS_CMD_SPACE_CPUSIG, EBUS_IDX11_CPU_ID), EBUS_ANY_CPU_ID);
}

/*
 * function	- bscv_watchdog_pat_request
 * description	- request a heartbeat pat
 * inputs	- timeout value in seconds
 * outputs	- none
 */
static void
bscv_watchdog_pat_request(void *arg)
{
	bscv_soft_state_t *ssp = (bscv_soft_state_t *)arg;

	bscv_wdog_do_pat(ssp);
}

/*
 * function	- bscv_watchdog_cfg_request
 * description	- request configuration of the bsc hardware watchdog
 * inputs	- new state (0=disabled, 1=enabled)
 * outputs	- one if successful, zero if unsuccesful
 */
static void
bscv_watchdog_cfg_request(bscv_soft_state_t *ssp, uint8_t new_state)
{
	ASSERT(new_state == WDOG_ON || new_state == WDOG_OFF);

	watchdog_activated = new_state;
	BSCV_TRACE(ssp, 'X', "bscv_watchdog_cfg_request",
	    "watchdog_activated=%d", watchdog_activated);
	bscv_write_wdog_cfg(ssp,
	    bscv_watchdog_timeout_seconds,
	    new_state,
	    wdog_reset_on_timeout);
}

/*
 * function	- bscv_set_watchdog_timer
 * description	- setup the heartbeat timeout value
 * inputs	- timeout value in seconds
 * outputs	- zero if the value was not changed
 *                otherwise the current value
 */
static uint_t
bscv_set_watchdog_timer(bscv_soft_state_t *ssp, uint_t timeoutval)
{
	BSCV_TRACE(ssp, 'X', "bscv_set_watchdog_timer:",
	    "timeout=%d", timeoutval);

	/*
	 * We get started during bscv_attach only
	 * if bscv_watchdog_enable is set.
	 */
	if (bscv_watchdog_available && (!watchdog_activated ||
	    (watchdog_activated &&
	    (timeoutval != bscv_watchdog_timeout_seconds)))) {
		bscv_watchdog_timeout_seconds = timeoutval;
		bscv_watchdog_cfg_request(ssp, WDOG_ON);
		return (bscv_watchdog_timeout_seconds);
	}
	return (0);
}

/*
 * function	- bscv_clear_watchdog_timer
 * description	- add the watchdog patter cyclic
 * inputs	- driver soft state
 * outputs	- value of watchdog timeout in seconds
 *
 * This function is a copy of the SPARC implementation
 * in the todblade clock driver.
 */
static void
bscv_clear_watchdog_timer(bscv_soft_state_t *ssp)
{
	BSCV_TRACE(ssp, 'X', "bscv_clear_watchdog_timer", "");

	if (bscv_watchdog_available && watchdog_activated) {
		bscv_watchdog_enable = 0;
		bscv_watchdog_cfg_request(ssp, WDOG_OFF);
	}
}

/*
 * function	- bscv_panic_callback
 * description	- called when we panic so we can disabled the watchdog
 * inputs	- driver soft state pointer
 * outputs	- DDI_SUCCESS
 */
/*ARGSUSED1*/
static boolean_t
bscv_panic_callback(void *arg, int code)
{
	bscv_soft_state_t *ssp = (bscv_soft_state_t *)arg;

	BSCV_TRACE(ssp, 'X', "bscv_panic_callback",
	    "disabling watchdog");

	bscv_clear_watchdog_timer(ssp);
	/*
	 * We dont get interrupts during the panic callback. But bscbus
	 * takes care of all this
	 */
	bscv_full_stop(ssp);
	return (DDI_SUCCESS);
}

/*
 * function	- bscv_watchdog_cyclic_add
 * description	- add the watchdog patter cyclic
 * inputs	- driver soft state
 * outputs	- none
 */
static void
bscv_watchdog_cyclic_add(bscv_soft_state_t *ssp)
{
	if (ssp->periodic_id != NULL) {
		return;
	}

	ssp->periodic_id = ddi_periodic_add(bscv_watchdog_pat_request, ssp,
	    WATCHDOG_PAT_INTERVAL, DDI_IPL_10);

	BSCV_TRACE(ssp, 'X', "bscv_watchdog_cyclic_add:",
	    "cyclic added");
}

/*
 * function	- bscv_watchdog_cyclic_remove
 * description	- remove the watchdog patter cyclic
 * inputs	- soft state ptr
 * outputs	- none
 */
static void
bscv_watchdog_cyclic_remove(bscv_soft_state_t *ssp)
{
	if (ssp->periodic_id == NULL) {
		return;
	}
	ddi_periodic_delete(ssp->periodic_id);
	ssp->periodic_id = NULL;
	BSCV_TRACE(ssp, 'X', "bscv_watchdog_cyclic_remove:",
	    "cyclic removed");
}
#endif /* __i386 || __amd64 */


/*
 *  General utility routines ...
 */

#ifdef DEBUG

static void
bscv_trace(bscv_soft_state_t *ssp, char code, const char *caller,
	const char *fmt, ...)
{
	char buf[256];
	char *p;
	va_list va;

	if (ssp->debug & (1 << (code-'@'))) {
		p = buf;
		(void) snprintf(p, sizeof (buf) - (p - buf),
		    "%s/%s: ", MYNAME, caller);
		p += strlen(p);

		va_start(va, fmt);
		(void) vsnprintf(p, sizeof (buf) - (p - buf), fmt, va);
		va_end(va);

		buf[sizeof (buf) - 1] = '\0';
		(void) strlog((short)ssp->majornum, (short)ssp->minornum, code,
		    SL_TRACE, buf);
	}
}

#else /* DEBUG */

_NOTE(ARGSUSED(0))
static void
bscv_trace(bscv_soft_state_t *ssp, char code, const char *caller,
	const char *fmt, ...)
{
}

#endif /* DEBUG */
