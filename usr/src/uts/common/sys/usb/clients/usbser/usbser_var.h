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

#ifndef _SYS_USB_USBSER_VAR_H
#define	_SYS_USB_USBSER_VAR_H


/*
 * USB-to-serial driver definitions
 */

#include <sys/tty.h>
#include <sys/mkdev.h>
#include <sys/sunddi.h>
#include <sys/note.h>

#include <sys/usb/clients/usbser/usbser_dsdi.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct usbser_state	usbser_state_t;
typedef struct usbser_port	usbser_port_t;

/*
 * because put() and srv() routines are not allowed to block, usbser
 * provides each port with two threads: for read and write processing
 * this structure describes the data associated with a usbser thread
 */
typedef struct usbser_thread {
	kcondvar_t	thr_cv;		/* cv for request wait */
	uint_t		thr_flags;	/* state flags */
	usbser_port_t	*thr_port;	/* port owner of this thread */
	void		(*thr_func)(void *);	/* function to be run */
	void		*thr_arg;	/* function argument */
} usbser_thread_t;

/*
 * thr_flags
 */
enum {
	USBSER_THR_RUNNING	= 0x01,	/* thread is running */
	USBSER_THR_WAKE		= 0x02,	/* wake requested */
	USBSER_THR_EXITED	= 0x04	/* thread exited */
};

/*
 * additional device state
 */
#define	USBSER_DEV_INIT		0x80	/* device is being initialized */

/*
 * per instance data
 */
struct usbser_state {
	struct usbser_state *us_next;		/* linked list */
	dev_info_t	*us_dip;		/* device information */
	kmutex_t	us_mutex;		/* structure lock */
	void		*us_statep;		/* soft state anchor */
	int		us_instance;		/* instance number */
	ds_ops_t	*us_ds_ops;		/* DSD operations */
	ds_hdl_t	us_ds_hdl;		/* DSD device handle */
	uint_t		us_port_cnt;		/* port count */
	usbser_port_t	*us_ports;		/* array of port structs */
	uint_t		us_dev_state;		/* USB device state */
	usb_log_handle_t us_lh;			/* USB log handle */
	ddi_taskq_t	*us_taskq;		/* taskq for command handling */
};

_NOTE(MUTEX_PROTECTS_DATA(usbser_state::us_mutex, usbser_state::us_dev_state))

/*
 * per port data
 */
struct usbser_port {
	kmutex_t	port_mutex;		/* structure lock */
	usbser_state_t	*port_usp;		/* back pointer to state */
	char		port_lh_name[16];	/* log handle name */
	usb_log_handle_t port_lh;		/* log handle */
	ds_ops_t	*port_ds_ops;		/* copy from usbser_state */
	ds_hdl_t	port_ds_hdl;		/* copy from usbser_state */
	uint_t		port_num;		/* port number */
	uint_t		port_state;		/* port state */
	uint_t		port_act;		/* current activities on port */
	uint_t		port_flags;		/* port flags */
	kcondvar_t	port_state_cv;		/* port state cv */
	kcondvar_t	port_act_cv;		/* port activity cv */
	kcondvar_t	port_car_cv;		/* port carrier cv */
	uint_t		port_wq_data_cnt;	/* amount of unsent data */
	usbser_thread_t	port_wq_thread;		/* wq thread */
	usbser_thread_t	port_rq_thread;		/* rq thread */
	tty_common_t	port_ttycommon;		/* tty driver common data */
	uchar_t		port_flowc;		/* flow control char */
	timeout_id_t	port_delay_id;		/* delay/break timeout id */
};

_NOTE(MUTEX_PROTECTS_DATA(usbser_port::port_mutex, usbser_port))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usbser_port::{
	port_usp
	port_lh
	port_ds_ops
	port_ds_hdl
	port_num
	port_ttycommon.t_{readq writeq}
}))

_NOTE(LOCK_ORDER(usbser_state::us_mutex usbser_port::port_mutex))

/*
 * port_state:
 *
 *   USBSER_PORT_NOT_INIT
 *          |   ^
 *          |   |
 *     attach   detach
 *          |   |
 *          |   |    +----open[1]----> USBSER_PORT_OPENING_TTY ------+
 *          |   |    |                      |    |                   |
 *          v   |    |                      |    |                   |
 *   USBSER_PORT_CLOSED <---device error---<    overtake[2]          |
 *            |      |                      |    |                   v
 *            |      |                      |    v                   |
 *            |      +----open[1]----> USBSER_PORT_OPENING_OUT       |
 *            |                             |                        |
 *            |                             |    +-------------------+
 *            |                             |    |
 *            |                             v    v
 * USBSER_PORT_CLOSING <-----close----- USBSER_PORT_OPEN <-----------+
 *            ^                             |    ^       --------+   |
 *            |                             |    |               |   |
 *            |                             |    |               |   |
 *            |                             v    |               v   |
 *            +------close----- USBSER_PORT_DISCONNECTED  USBSER_PORT_SUSPENDED
 *
 * Notes:
 *
 * [1] for each physical port N two device nodes are created:
 *
 *       /dev/term/N (tty mode)
 *       /dev/cua/N  (dial-out mode)
 *
 *     the port can only be opened in one of these modes at a time.
 *     difference between the two is that in tty mode the driver
 *     will block in open(9E) until the CD (Carrier Detect) pin comes up,
 *     while in dial-out mode CD is ignored. opening and closing states
 *     help to avoid race conditions between two threads trying to open/close
 *     one physical port in two different modes simultaneously.
 *
 * [2] tty mode open may be blocked waiting for carrier.
 *     if dial-out mode open happens at this time, it is allowed
 *     for it to overtake the port; from zs(7D) man page:
 *
 *	 This allows a modem to be attached to  /dev/term/[n]
 *	 and used for dial-in (by enabling the line for login in /etc/inittab)
 *	 and also used for  dial-out  (by  tip(1) or uucp(1C)) as /dev/cua/[n]
 *	 when no one is logged in on the line.
 */
enum {
	USBSER_PORT_NOT_INIT = 0,	/* port not initialized */
	USBSER_PORT_CLOSED,		/* port is closed */
	USBSER_PORT_OPENING_TTY,	/* tty open in progress */
	USBSER_PORT_OPENING_OUT,	/* dial-out open in progress */
	USBSER_PORT_OPEN,		/* port is open */
	USBSER_PORT_SUSPENDED,		/* port is suspended */
	USBSER_PORT_DISCONNECTED,	/* port is disconnected */
	USBSER_PORT_CLOSING		/* close() is in progress */
};

/* constants used by state machine implementation */
enum {
	USBSER_CONTINUE			= -1,
	USBSER_COMPLETE			= 0
};

/*
 * port_act: current activities on the port.
 * only one activity of each type is allowed at a time.
 */
enum {
	USBSER_ACT_TX		= 0x0001,	/* transmitting data */
	USBSER_ACT_RX		= 0x0002,	/* receiving data */
	USBSER_ACT_CTL		= 0x0004,	/* controlling the device */
	USBSER_ACT_BREAK	= 0x0010,	/* doing break */
	USBSER_ACT_DELAY	= 0x0020,	/* doing delay */
	USBSER_ACT_ALL		= 0xffff	/* all actions (must be >0) */
};

/*
 * port_flags
 */
enum {
	USBSER_FL_OUT		= 0x0001,	/* dial-out */
	USBSER_FL_WOPEN		= 0x0002,	/* waiting in open() */
	USBSER_FL_CARR_ON	= 0x0004,	/* carrier is on */
	USBSER_FL_TX_STOPPED	= 0x0008,	/* output stopped */
	USBSER_FL_RX_STOPPED	= 0x0010,	/* input stopped */
	USBSER_FL_HUNGUP	= 0x0020,	/* stream is hung up */
	USBSER_FL_DSD_OPEN	= 0x0040,	/* DSD is open */
	USBSER_FL_STATUS_CB	= 0x0080,	/* status callback pending */
	USBSER_FL_IGNORE_CD	= 0x0100,	/* ignore carrier detect */
	USBSER_FL_PRESERVE	= USBSER_FL_IGNORE_CD
						/* flags that need to */
						/* be preserved across opens */
};

/*
 * current sun compiler does not seem to inline static leaf routines at O3
 * so we have to use preprocessor macros to make up for compiler disability
 *
 * can we access the port?
 */
#define	USBSER_PORT_ACCESS_OK(pp)	((pp)->port_state == USBSER_PORT_OPEN)

/*
 * is port doing something?
 */
#define	USBSER_PORT_IS_BUSY(pp)		((pp)->port_act != 0)

/* port is busy on TX, delay, break, ctrl */
#define	USBSER_PORT_IS_BUSY_NON_RX(pp)	\
	(((pp)->port_act & (USBSER_ACT_DELAY | USBSER_ACT_CTL | \
	USBSER_ACT_BREAK | USBSER_ACT_TX)) != 0)

/*
 * is the port opening?
 */
#define	USBSER_IS_OPENING(pp)	\
	(((pp)->port_state == USBSER_PORT_OPENING_TTY) || \
	((pp)->port_state == USBSER_PORT_OPENING_OUT))

/*
 * determine, while we are trying to open the port,
 * whether it is currently being open in the opposite mode
 */
#define	USBSER_NO_OTHER_OPEN(pp, minor)	\
	((((minor) & OUTLINE) &&	\
	((pp)->port_state == USBSER_PORT_OPENING_OUT)) ||	\
	(!((minor) & OUTLINE) && ((pp)->port_state == USBSER_PORT_OPENING_TTY)))

/*
 * determine, while we are trying to open the port,
 * whether it is already open in the opposite mode
 */
#define	USBSER_OPEN_IN_OTHER_MODE(pp, minor)	\
	((((minor) & OUTLINE) && !((pp)->port_flags & USBSER_FL_OUT)) || \
	(!((minor) & OUTLINE) && ((pp)->port_flags & USBSER_FL_OUT)))

/*
 * minor number manipulation
 */
enum {
	MAXPORTS_PER_DEVICE_SHIFT	= 4,
	MAXPORTS_PER_DEVICE		= (1 << MAXPORTS_PER_DEVICE_SHIFT),
	MAXPORTS_PER_DEVICE_MASK	= (MAXPORTS_PER_DEVICE - 1),
	OUTLINE				= (1 << (NBITSMINOR32 - 1))
};

#define	USBSER_MAKEMINOR(instance, port, outline)	\
		((port) | ((instance) << MAXPORTS_PER_DEVICE_SHIFT) | (outline))

#define	USBSER_MINOR2INST(minor)	\
	(((minor) & ~(OUTLINE | MAXPORTS_PER_DEVICE_MASK)) \
	>> MAXPORTS_PER_DEVICE_SHIFT)

#define	USBSER_MINOR2PORT(minor)	((minor) & MAXPORTS_PER_DEVICE_MASK)

/*
 * various tunables
 *
 * timeouts are in seconds
 */
enum {
	USBSER_TX_FIFO_DRAIN_TIMEOUT	= 5, /* tx fifo drain timeout */
	USBSER_WQ_DRAIN_TIMEOUT		= 2, /* wq drain timeout */
	USBSER_SUSPEND_TIMEOUT		= 10 /* cpr suspend timeout */
};

/*
 * debug printing masks
 */
#define	DPRINT_ATTACH		0x00000001
#define	DPRINT_DETACH		0x00000002
#define	DPRINT_OPEN		0x00000004
#define	DPRINT_CLOSE		0x00000008
#define	DPRINT_WQ		0x00000010
#define	DPRINT_RQ		0x00000020
#define	DPRINT_IOCTL		0x00000040
#define	DPRINT_RX_CB		0x00000100
#define	DPRINT_TX_CB		0x00000200
#define	DPRINT_STATUS_CB	0x00000400
#define	DPRINT_EVENTS		0x00001000
#define	DPRINT_CPR		0x00002000
#define	DPRINT_MASK_ALL		0xFFFFFFFF

/*
 * misc macros
 */
#define	NELEM(a)	(sizeof (a) / sizeof (*(a)))

/*
 * shortcuts to DSD operations
 */
#define	USBSER_DS_ATTACH(usp, aip)	usp->us_ds_ops->ds_attach(aip)

#define	USBSER_DS_DETACH(usp)	usp->us_ds_ops->ds_detach(usp->us_ds_hdl)

#define	USBSER_DS_OPEN_PORT(usp, port_num)	\
	usp->us_ds_ops->ds_open_port(usp->us_ds_hdl, port_num)

#define	USBSER_DS_CLOSE_PORT(usp, port_num)	\
	usp->us_ds_ops->ds_close_port(usp->us_ds_hdl, port_num)

#define	USBSER_DS_REGISTER_CB(usp, port_num, cb)	\
	usp->us_ds_ops->ds_register_cb(usp->us_ds_hdl, port_num, cb)

#define	USBSER_DS_UNREGISTER_CB(usp, port_num)	\
	usp->us_ds_ops->ds_unregister_cb(usp->us_ds_hdl, port_num)

/* power management */
#define	USBSER_DS_USB_POWER(usp, comp, level, new_statep)	\
	usp->us_ds_ops->ds_usb_power(usp->us_ds_hdl, comp, level, new_statep)

#define	USBSER_DS_SUSPEND(usp)	usp->us_ds_ops->ds_suspend(usp->us_ds_hdl)

#define	USBSER_DS_RESUME(usp)	usp->us_ds_ops->ds_resume(usp->us_ds_hdl)

#define	USBSER_DS_DISCONNECT(usp) usp->us_ds_ops->ds_disconnect(usp->us_ds_hdl)

#define	USBSER_DS_RECONNECT(usp) usp->us_ds_ops->ds_reconnect(usp->us_ds_hdl)

/* standard UART operations */
#define	USBSER_DS_SET_PORT_PARAMS(pp, params)	\
	pp->port_ds_ops->ds_set_port_params(pp->port_ds_hdl, pp->port_num, \
		params)

#define	USBSER_DS_SET_MODEM_CTL(pp, mask, val)	\
	pp->port_ds_ops->ds_set_modem_ctl(pp->port_ds_hdl, pp->port_num, mask, \
		val)

#define	USBSER_DS_GET_MODEM_CTL(pp, mask, valp)	\
	pp->port_ds_ops->ds_get_modem_ctl(pp->port_ds_hdl, pp->port_num, \
		mask, valp)

#define	USBSER_DS_BREAK_CTL(pp, val)		\
	pp->port_ds_ops->ds_break_ctl(pp->port_ds_hdl, pp->port_num, val)

#define	USBSER_DS_LOOPBACK(pp, val)		\
	pp->port_ds_ops->ds_loopback(pp->port_ds_hdl, pp->port_num, val)

/* data xfer */
#define	USBSER_DS_TX(pp, mp)		\
	pp->port_ds_ops->ds_tx(pp->port_ds_hdl, pp->port_num, mp)

#define	USBSER_DS_RX(pp)		\
	pp->port_ds_ops->ds_rx(pp->port_ds_hdl, pp->port_num)

#define	USBSER_DS_STOP(pp, dir)		\
	pp->port_ds_ops->ds_stop(pp->port_ds_hdl, pp->port_num, dir)

#define	USBSER_DS_START(pp, dir)	\
	pp->port_ds_ops->ds_start(pp->port_ds_hdl, pp->port_num, dir)

/* fifos */
#define	USBSER_DS_FIFO_FLUSH(pp, mask)		\
	pp->port_ds_ops->ds_fifo_flush(pp->port_ds_hdl, pp->port_num, mask)

#define	USBSER_DS_FIFO_DRAIN(pp, tmout)		\
	pp->port_ds_ops->ds_fifo_drain(pp->port_ds_hdl, pp->port_num, tmout)


/* check for supported operations */
#define	USBSER_DS_LOOPBACK_SUPPORTED(pp) (pp->port_ds_ops->ds_loopback != 0)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_USBSER_VAR_H */
