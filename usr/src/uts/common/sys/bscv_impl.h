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

#ifndef _SYS_BSCV_IMPL_H
#define	_SYS_BSCV_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Implementation private header file for bscv driver.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/lom_priv.h>


/*
 * Local #defines
 */

#define	BSCV_SUCCESS	DDI_SUCCESS
#define	BSCV_FAILURE	DDI_FAILURE

/*
 * The following are used as progress indicators in bscv_attach()
 */

#define	BSCV_LOCKS		0x01
#define	BSCV_MAPPED_REGS	0x02
#define	BSCV_NODES		0x04
#define	BSCV_THREAD		0x08
#define	BSCV_HOSTNAME_DONE	0x10
#define	BSCV_WDOG_CFG		0x20
#define	BSCV_SIG_SENT		0x40

/*
 * macros to encode device minors and provide mapping to device instances.
 * The following is designed to get around the problem of a 32-bit app not
 * supporting a 32-bit minor number on an LP64 model system.
 */

#ifdef NBITSMINOR
#undef NBITSMINOR
#define	NBITSMINOR	18
#endif

#define	BSCV_MONITOR_NODE	0
#define	BSCV_CONTROL_NODE	(1 << (NBITSMINOR - 1))

#define	DEVICETOINSTANCE(x)	((getminor(x)) & (~BSCV_CONTROL_NODE));

/*
 * The maximum number of leds which are supported by this lom implementation.
 */
#define	MAX_LED_ID	7

/*
 * general driver configuration constants which may be changed to improve
 * performance/efficiency.
 */

#define	 INIT_BUSY_WAIT		10	/* 10 microsecs */

#define	 MAX_WDOGTIMEOUT	127	/* maximum wdog timout - 127s */


/*
 * Event processing task status flags.
 */
#define	TASK_ALIVE_FLG		0x01
#define	TASK_STOP_FLG		0x02
#define	TASK_SLEEPING_FLG	0x04
#define	TASK_PAUSE_FLG		0x08
#define	TASK_EVENT_PENDING_FLG	0x10
#define	TASK_EVENT_CONSUMER_FLG	0x20

/*
 * strace(1M) prints out the debug data once the debug value is set in
 * the bscv.conf file and the debug driver is installed.
 *
 * Debug flags
 *
 * '@' - Register (@)ccess
 * 'A' - (A)ttach
 * 'B' - (B)lom1 attach extra
 * 'C' - lom1 (C)allback
 * 'D' - (D)aemon
 * 'E' - (E)vents
 * 'F' - Sel(F)test
 * 'I' - (I)octl
 * 'L' - TSa(L)arms
 * 'M' - (M)odel parameters
 * 'N' - I(N)terrupt Service Routine
 * 'O' - (O)pen/Close
 * 'P' - (P)rogramming
 * 'Q' - (Q)ueue things
 * 'R' - Read/Write (R)etry summary.
 * 'S' - Event (S)trings
 * 'U' - Programming ioctls
 * 'V' - ???
 * 'W' - (W)atchdog
 * 'X' - additional X86 functional calls
 * 'Z' - Temporary - just log things
 */

/*
 * Debug tips :
 *
 * strace(1M) prints out the debug data.
 * A nice way to work out the debug value set in bscv.conf is to use mdb
 * Say we want to show 'D' Daemon and 'I' IOCTL processing,
 * you calculate the debug value with the following mdb session :
 * 	# mdb
 * 	> 1<<('D'-'@') | 1<<('I'-'@') = X
 *			210
 *	> $q
 * When you insert "debug=0x210;" into bscv.conf, it causes the next
 * reboot with the debug driver to trace Daemon and IOCTL functionality.
 */

/*
 * Xbus channel access data
 */

struct xbus_channel {
	ddi_acc_handle_t	handle;
	uint8_t			*regs;
};

#define	BSCV_MINCHANNELS	2
#define	BSCV_MAXCHANNELS	16

/*
 * soft state structure
 */

typedef
struct {
	/*
	 * Hardware instance variables
	 */
	uint64_t	debug;		/* debugging turned on */
	major_t		majornum;	/* debugging - major number */
	minor_t		minornum;	/* debugging - minor number */

	dev_info_t	*dip;		/* pointer to device info tree */
	int		instance;	/* instance number for the device */
	ddi_device_acc_attr_t	attr;	/* device access attributes */

	struct xbus_channel	channel[BSCV_MAXCHANNELS];
	int			nchannels;

	int		progress;	/* progress indicator for attach */

	int		bad_resync;	/* Number of bad resyncs */

	/*
	 * lom data variables/arrays
	 */
	uint8_t		lom_regs[0x80]; /* registers on the lomlite */
	int		serial_reporting;
	int		reporting_level;

	/*
	 * lom2 static information.
	 * setup at driver attach and restart after programming.
	 */
	int		num_fans;
	char		fan_names[MAX_FANS][MAX_LOM2_NAME_STR];
	uint8_t		fanspeed[MAX_FANS];
	char		led_names[MAX_LED_ID][MAX_LOM2_NAME_STR];
	lom_volts_t	volts;		/* keep a static copy of this so */
					/* dont have to re-read names */
	lom_temp_t	temps;		/* keep a static copy of this so */
					/* dont have to re-read names */
	lom_sflags_t	sflags;		/* keep a static copy of this so */
					/* dont have to re-read names */
	char		escape_chars[6];	/* local copy */

	uint_t		watchdog_timeout;
	uint8_t		watchdog_reset_on_timeout;

	/*
	 * lom2 firmware communication
	 */

	/*
	 * cmd_mutex protects the lom2 command progress variables.
	 * These should only be read/updated with the mutex held.
	 *
	 * command_error - acts as a return code and may be read
	 * without the mutex held if a command is not in progress.
	 * Note a read only returns failure if the lom does not respond.
	 * So you might need to check the error code to see if things really
	 * did work!
	 *
	 * addr_mu is used to protect stopping and starting of the queue.
	 * BUT when programming it has different semantics and relies
	 * on only the programming thread being in the ioctl routine
	 * whilst programming is in progress. The event queue must also
	 * be paused at this time.
	 */
	kmutex_t	cmd_mutex;	/* LOM command mutual exclusion */

	int		command_error;	/* error code from last command */
					/* valid until the next command */
					/* starts. */

	boolean_t	had_fault;	/* Current command sequence faulted */
	boolean_t	had_session_error;	/* Current session had error */

	uint8_t		pat_seq;	/* Watchdog patting sequence number */
	uint8_t		cap0;		/* capability byte */
	uint8_t		cap1;		/* capability byte */
	uint8_t		cap2;		/* capability byte */

	/*
	 * Programming variables
	 */
	kmutex_t	prog_mu;	/* Programming mutex. - lom 2 */
	boolean_t	prog_mode_only;	/* If true we can only reprogram */
					/* the lom */
	boolean_t	programming;	/* TRUE is actually programming */
					/* the BSC */
	boolean_t	cssp_prog;	/* TRUE is CSSP programming the BSC */

	int		prog_index;	/* data buffer number - bit */
					/* 0x8000 set if last buffer */
	int		image_ptr;	/* ptr to next byte in image buffer */
					/* for programming */
	uint8_t 	*image;		/* ptr to image buffer for */
					/* programming */
	boolean_t	image2_processing;	/* boolean to say which of */
					/* 2 BSC images being processed */
	boolean_t	loader_running;	/* Still have the loader running */

	/*
	 * LOM eeprom window access state
	 * Access under bscv_enter/bscv_exit protection.
	 */
	boolean_t	eeinfo_valid;
	uint32_t	eeprom_size;
	uint32_t	eventlog_start;
	uint32_t	eventlog_size;
	boolean_t	oldeeptr_valid;
	uint16_t	oldeeptr;

	/*
	 * Communication with the event processing thread
	 *
	 * Change these variables with task_mu held and signal task_cv
	 * if an event/task needs processing.
	 */
	kmutex_t	task_mu;	/* mutex for wait on event thread */
	kcondvar_t	task_cv;	/* cv for wait on event thread */
	kcondvar_t	task_evnt_cv;	/* cv for lom2 wait on event */
	int		task_flags;	/* To monitor/stop the event thread */
	volatile int	event_active_count; /* Count of event thread runs */
	boolean_t	event_waiting;	/* New events are waiting in the lom */
	boolean_t	status_change;	/* A status change is waiting */
	boolean_t	nodename_change; /* Nodename has changed */
	boolean_t	event_sleep;	/* Error reading events - wait a bit */
	boolean_t	event_fault_reported;	/* Event fault reported */
	boolean_t	watchdog_change; /* Watchdog config has changed */
#ifdef __sparc
	bscv_sig_t	last_sig;	/* Record of last signature sent */
#endif /* __sparc */
	uint8_t		last_event[8];	/* last event read and reported */
#if defined(__i386) || defined(__amd64)
	ddi_periodic_t 	periodic_id; /* watchdog patter periodical callback */
	callb_id_t	callb_id;	/* Need to store the ID so we can */
					/* unschedule the panic callback */
	char		last_nodename[128]; /* copy of last utsname.nodename */
#endif /* __i386 || __amd64 */
} bscv_soft_state_t;

struct bscv_idi_callout {
	enum bscv_idi_type type;	/* Type of service */
	boolean_t (*fn)(struct bscv_idi_info);	/* Function's address */
};

#define	BSCV_IDI_CALLOUT_MAGIC		0xb5c1ca11
#define	BSCV_IDI_ERR_MSG_THRESHOLD	10
struct bscv_idi_callout_mgr {
	/*
	 * To allow for sanity check.
	 */
	uint32_t magic;

	/*
	 * The instance number of "an" instance of the driver.  This is assigned
	 * during driver attach.
	 */
	uint32_t valid_inst;

	/*
	 * Table of services offered via the idi interface.
	 */
	struct bscv_idi_callout *tbl;

	/*
	 * Error message count since last successful use of the idi interface.
	 */
	uint64_t errs;
};



#define	BSC_IMAGE_MAX_SIZE (0x20000 + sizeof (lom_prog_data_t))

#define	BSC_PROBE_FAULT_LIMIT	8	/* Tries before declaring lom dead */
#define	BSC_EVENT_POLL_NORMAL	(drv_usectohz(1000000))		/* 1 second */
#define	BSC_EVENT_POLL_FAULTY	(drv_usectohz(10000000))	/* 10 second */

#define	BSC_FAILURE_RETRY_LIMIT	5	/* Access retries before giving up */
#define	BSC_ERASE_RETRY_LIMIT	5	/* Erase retries */
#define	BSC_PAGE_RETRY_LIMIT	5	/* Page write retries */

#define	BSC_ADDR_CACHE_LIMIT	\
		(sizeof (((bscv_soft_state_t *)NULL)->lom_regs))
#define	BSC_INFORM_ONLINE	0x4f530100
#define	BSC_INFORM_OFFLINE	0x4f530201
#define	BSC_INFORM_PANIC	0x4f530204

#include <sys/lom_ebuscodes.h>

typedef uint32_t bscv_addr_t;

#define	BSC_NEXUS_ADDR(ssp, chan, as, index) \
	(&((ssp)->channel[chan].regs[((as) * 256) + (index)]))

#define	BSC_NEXUS_OFFSET(as, index) (((as) * 256) + (index))

#define	BSCVA(as, index) (((as) * 256) + (index))

#define	PSR_SUCCESS(status)	(((status) & EBUS_PROGRAM_PSR_STATUS_MASK) == \
    EBUS_PROGRAM_PSR_SUCCESS)

#define	PSR_PROG(status)	(((status) & EBUS_PROGRAM_PSR_PROG_MODE) != 0)
#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_BSCV_IMPL_H */
