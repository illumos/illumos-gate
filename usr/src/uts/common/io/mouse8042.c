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
/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * PS/2 type Mouse Module - Streams
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/signal.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/termio.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strtty.h>
#include <sys/strsun.h>
#include <sys/debug.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h>

#include <sys/promif.h>
#include <sys/cred.h>

#include <sys/i8042.h>
#include <sys/note.h>
#include <sys/mouse.h>

#define	DRIVER_NAME(dip)	ddi_driver_name(dip)

#define	MOUSE8042_INTERNAL_OPEN(minor)	(((minor) & 0x1) == 1)
#define	MOUSE8042_MINOR_TO_INSTANCE(minor)	((minor) / 2)
#define	MOUSE8042_INTERNAL_MINOR(minor)		((minor) + 1)

#define	MOUSE8042_RESET_TIMEOUT_USECS	500000	/* 500 ms */

extern int ddi_create_internal_pathname(dev_info_t *, char *, int, minor_t);
extern void consconfig_link(major_t major, minor_t minor);
extern int consconfig_unlink(major_t major, minor_t minor);


/*
 *
 * Local Static Data
 *
 */

/*
 * We only support one instance.  Yes, it's theoretically possible to
 * plug in more than one, but it's not worth the implementation cost.
 *
 * The introduction of USB keyboards might make it worth reassessing
 * this decision, as they might free up the keyboard port for a second
 * PS/2 style mouse.
 */
static dev_info_t *mouse8042_dip;

/*
 * RESET states
 */
typedef enum {
	MSE_RESET_IDLE,	/* No reset in progress */
	MSE_RESET_PRE,	/* Send reset, waiting for ACK */
	MSE_RESET_ACK,	/* Got ACK, waiting for 0xAA */
	MSE_RESET_AA,	/* Got 0xAA, waiting for 0x00 */
	MSE_RESET_FAILED
} mouse8042_reset_state_e;

struct mouse_state {
	queue_t	*ms_rqp;
	queue_t	*ms_wqp;
	ddi_iblock_cookie_t	ms_iblock_cookie;
	ddi_acc_handle_t	ms_handle;
	uint8_t			*ms_addr;
	kmutex_t		ms_mutex;

	minor_t			ms_minor;
	boolean_t		ms_opened;
	kmutex_t		reset_mutex;
	kcondvar_t		reset_cv;
	mouse8042_reset_state_e	reset_state;
	timeout_id_t		reset_tid;
	int			ready;
	mblk_t			*reply_mp;
	mblk_t			*reset_ack_mp;
	bufcall_id_t		bc_id;
};

static uint_t mouse8042_intr(caddr_t arg);
static int mouse8042_open(queue_t *q, dev_t *devp, int flag, int sflag,
		cred_t *cred_p);
static int mouse8042_close(queue_t *q, int flag, cred_t *cred_p);
static int mouse8042_wsrv(queue_t *qp);
static int mouse8042_wput(queue_t *q, mblk_t *mp);

static int mouse8042_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd,
		void *arg, void **result);
static int mouse8042_attach(dev_info_t *dev, ddi_attach_cmd_t cmd);
static int mouse8042_detach(dev_info_t *dev, ddi_detach_cmd_t cmd);


/*
 * Streams module info.
 */
#define	MODULE_NAME	"mouse8042"

static struct module_info	mouse8042_minfo = {
	23,		/* Module ID number */
	MODULE_NAME,
	0, INFPSZ,	/* minimum & maximum packet sizes */
	256, 128	/* hi and low water marks */
};

static struct qinit mouse8042_rinit = {
	NULL,		/* put */
	NULL,		/* service */
	mouse8042_open,
	mouse8042_close,
	NULL,		/* admin */
	&mouse8042_minfo,
	NULL		/* statistics */
};

static struct qinit mouse8042_winit = {
	mouse8042_wput,	/* put */
	mouse8042_wsrv,	/* service */
	NULL,		/* open */
	NULL,		/* close */
	NULL,		/* admin */
	&mouse8042_minfo,
	NULL		/* statistics */
};

static struct streamtab mouse8042_strinfo = {
	&mouse8042_rinit,
	&mouse8042_winit,
	NULL,		/* muxrinit */
	NULL,		/* muxwinit */
};

/*
 * Local Function Declarations
 */

static struct cb_ops	mouse8042_cb_ops = {
	nodev,			/* open */
	nodev,			/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	&mouse8042_strinfo,	/* streamtab  */
	D_MP | D_NEW
};


static struct dev_ops	mouse8042_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	mouse8042_getinfo,	/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	mouse8042_attach,	/* attach */
	mouse8042_detach,	/* detach */
	nodev,			/* reset */
	&mouse8042_cb_ops,	/* driver operations */
	(struct bus_ops *)0,	/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

extern struct mod_ops mod_driverops;

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a driver */
	"PS/2 Mouse",
	&mouse8042_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

/*
 * This is the driver initialization routine.
 */
int
_init()
{
	int	rv;

	rv = mod_install(&modlinkage);
	return (rv);
}


int
_fini(void)
{
	return (mod_remove(&modlinkage));
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
mouse8042_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct mouse_state *state;
	mblk_t *mp;
	int instance = ddi_get_instance(dip);
	static ddi_device_acc_attr_t attr = {
		DDI_DEVICE_ATTR_V0,
		DDI_NEVERSWAP_ACC,
		DDI_STRICTORDER_ACC,
	};
	int rc;


	if (cmd == DDI_RESUME) {
		state = (struct mouse_state *)ddi_get_driver_private(dip);

		/* Ready to handle inbound data from mouse8042_intr */
		state->ready = 1;

		/*
		 * Send a 0xaa 0x00 upstream.
		 * This causes the vuid module to reset the mouse.
		 */
		if (state->ms_rqp != NULL) {
			if (mp = allocb(1, BPRI_MED)) {
				*mp->b_wptr++ = 0xaa;
				putnext(state->ms_rqp, mp);
			}
			if (mp = allocb(1, BPRI_MED)) {
				*mp->b_wptr++ = 0x0;
				putnext(state->ms_rqp, mp);
			}
		}
		return (DDI_SUCCESS);
	}

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (mouse8042_dip != NULL)
		return (DDI_FAILURE);

	/* allocate and initialize state structure */
	state = kmem_zalloc(sizeof (struct mouse_state), KM_SLEEP);
	state->ms_opened = B_FALSE;
	state->reset_state = MSE_RESET_IDLE;
	state->reset_tid = 0;
	state->bc_id = 0;
	ddi_set_driver_private(dip, state);

	/*
	 * In order to support virtual keyboard/mouse, we should distinguish
	 * between internal virtual open and external physical open.
	 *
	 * When the physical devices are opened by application, they will
	 * be unlinked from the virtual device and their data stream will
	 * not be sent to the virtual device. When the opened physical
	 * devices are closed, they will be relinked to the virtual devices.
	 *
	 * All these automatic switch between virtual and physical are
	 * transparent.
	 *
	 * So we change minor node numbering scheme to be:
	 *	external node minor num == instance * 2
	 *	internal node minor num == instance * 2 + 1
	 */
	rc = ddi_create_minor_node(dip, "mouse", S_IFCHR, instance * 2,
	    DDI_NT_MOUSE, 0);
	if (rc != DDI_SUCCESS) {
		goto fail_1;
	}

	if (ddi_create_internal_pathname(dip, "internal_mouse", S_IFCHR,
	    instance * 2 + 1) != DDI_SUCCESS) {
		goto fail_2;
	}

	rc = ddi_regs_map_setup(dip, 0, (caddr_t *)&state->ms_addr,
	    (offset_t)0, (offset_t)0, &attr, &state->ms_handle);
	if (rc != DDI_SUCCESS) {
		goto fail_2;
	}

	rc = ddi_get_iblock_cookie(dip, 0, &state->ms_iblock_cookie);
	if (rc != DDI_SUCCESS) {
		goto fail_3;
	}

	mutex_init(&state->ms_mutex, NULL, MUTEX_DRIVER,
	    state->ms_iblock_cookie);
	mutex_init(&state->reset_mutex, NULL, MUTEX_DRIVER,
	    state->ms_iblock_cookie);
	cv_init(&state->reset_cv, NULL, CV_DRIVER, NULL);

	rc = ddi_add_intr(dip, 0,
	    (ddi_iblock_cookie_t *)NULL, (ddi_idevice_cookie_t *)NULL,
	    mouse8042_intr, (caddr_t)state);
	if (rc != DDI_SUCCESS) {
		goto fail_3;
	}

	mouse8042_dip = dip;

	/* Ready to handle inbound data from mouse8042_intr */
	state->ready = 1;

	/* Now that we're attached, announce our presence to the world. */
	ddi_report_dev(dip);
	return (DDI_SUCCESS);

fail_3:
	ddi_regs_map_free(&state->ms_handle);

fail_2:
	ddi_remove_minor_node(dip, NULL);

fail_1:
	kmem_free(state, sizeof (struct mouse_state));
	return (rc);
}

/*ARGSUSED*/
static int
mouse8042_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct mouse_state *state;

	state = ddi_get_driver_private(dip);

	switch (cmd) {
	case DDI_SUSPEND:
		/* Ignore all data from mouse8042_intr until we fully resume */
		state->ready = 0;
		return (DDI_SUCCESS);

	case DDI_DETACH:
		ddi_remove_intr(dip, 0, state->ms_iblock_cookie);
		mouse8042_dip = NULL;
		cv_destroy(&state->reset_cv);
		mutex_destroy(&state->reset_mutex);
		mutex_destroy(&state->ms_mutex);
		ddi_prop_remove_all(dip);
		ddi_regs_map_free(&state->ms_handle);
		ddi_remove_minor_node(dip, NULL);
		kmem_free(state, sizeof (struct mouse_state));
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}


/* ARGSUSED */
static int
mouse8042_getinfo(
    dev_info_t *dip,
    ddi_info_cmd_t infocmd,
    void *arg,
    void **result)
{
	dev_t dev = (dev_t)arg;
	minor_t	minor = getminor(dev);
	int	instance = MOUSE8042_MINOR_TO_INSTANCE(minor);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (mouse8042_dip == NULL)
			return (DDI_FAILURE);

		*result = (void *)mouse8042_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		break;
	default:
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
mouse8042_open(
	queue_t	*q,
	dev_t	*devp,
	int	flag,
	int	sflag,
	cred_t	*cred_p)
{
	struct mouse_state *state;
	minor_t	minor = getminor(*devp);
	int rval;

	if (mouse8042_dip == NULL)
		return (ENXIO);

	state = ddi_get_driver_private(mouse8042_dip);

	mutex_enter(&state->ms_mutex);

	if (state->ms_opened) {
		/*
		 * Exit if the same minor node is already open
		 */
		if (state->ms_minor == minor) {
			mutex_exit(&state->ms_mutex);
			return (0);
		}

		/*
		 * Check whether it is switch between physical and virtual
		 *
		 * Opening from virtual while the device is being physically
		 * opened by an application should not happen. So we ASSERT
		 * this in DEBUG version, and return error in the non-DEBUG
		 * case.
		 */
		ASSERT(!MOUSE8042_INTERNAL_OPEN(minor));

		if (MOUSE8042_INTERNAL_OPEN(minor)) {
			mutex_exit(&state->ms_mutex);
			return (EINVAL);
		}

		/*
		 * Opening the physical one while it is being underneath
		 * the virtual one.
		 *
		 * consconfig_unlink is called to unlink this device from
		 * the virtual one, thus the old stream serving for this
		 * device under the virtual one is closed, and then the
		 * lower driver's close routine (here is mouse8042_close)
		 * is also called to accomplish the whole stream close.
		 * Here we have to drop the lock because mouse8042_close
		 * also needs the lock.
		 *
		 * For mouse, the old stream is:
		 *	consms->["pushmod"->]"mouse_vp driver"
		 *
		 * After the consconfig_unlink returns, the old stream is closed
		 * and we grab the lock again to reopen this device as normal.
		 */
		mutex_exit(&state->ms_mutex);

		/*
		 * If unlink fails, fail the physical open.
		 */
		if ((rval = consconfig_unlink(ddi_driver_major(mouse8042_dip),
		    MOUSE8042_INTERNAL_MINOR(minor))) != 0) {
			return (rval);
		}

		mutex_enter(&state->ms_mutex);
	}


	q->q_ptr = (caddr_t)state;
	WR(q)->q_ptr = (caddr_t)state;
	state->ms_rqp = q;
	state->ms_wqp = WR(q);

	qprocson(q);

	state->ms_minor = minor;
	state->ms_opened = B_TRUE;

	mutex_exit(&state->ms_mutex);

	return (0);
}


/*ARGSUSED*/
static int
mouse8042_close(queue_t *q, int flag, cred_t *cred_p)
{
	struct mouse_state *state;
	minor_t	minor;

	state = (struct mouse_state *)q->q_ptr;

	/*
	 * Disable queue processing now, so that another reset cannot get in
	 * after we wait for the current reset (if any) to complete.
	 */
	qprocsoff(q);

	mutex_enter(&state->reset_mutex);
	while (state->reset_state != MSE_RESET_IDLE) {
		/*
		 * Waiting for the previous reset to finish is
		 * non-interruptible.  Some upper-level clients
		 * cannot deal with EINTR and will not close the
		 * STREAM properly, resulting in failure to reopen it
		 * within the same process.
		 */
		cv_wait(&state->reset_cv, &state->reset_mutex);
	}

	if (state->reset_tid != 0) {
		(void) quntimeout(q, state->reset_tid);
		state->reset_tid = 0;
	}

	if (state->reply_mp != NULL) {
		freemsg(state->reply_mp);
		state->reply_mp = NULL;
	}

	if (state->reset_ack_mp != NULL) {
		freemsg(state->reset_ack_mp);
		state->reset_ack_mp = NULL;
	}

	mutex_exit(&state->reset_mutex);

	mutex_enter(&state->ms_mutex);

	if (state->bc_id != 0) {
		(void) qunbufcall(q, state->bc_id);
		state->bc_id = 0;
	}

	q->q_ptr = NULL;
	WR(q)->q_ptr = NULL;
	state->ms_rqp = NULL;
	state->ms_wqp = NULL;

	state->ms_opened = B_FALSE;

	minor = state->ms_minor;

	mutex_exit(&state->ms_mutex);

	if (!MOUSE8042_INTERNAL_OPEN(minor)) {
		/*
		 * Closing physical PS/2 mouse
		 *
		 * Link it back to virtual mouse, and
		 * mouse8042_open will be called as a result
		 * of the consconfig_link call.  Do NOT try
		 * this if the mouse is about to be detached!
		 *
		 * If linking back fails, this specific mouse
		 * will not be available underneath the virtual
		 * mouse, and can only be accessed via physical
		 * open.
		 */
		consconfig_link(ddi_driver_major(mouse8042_dip),
		    MOUSE8042_INTERNAL_MINOR(minor));
	}

	return (0);
}

static void
mouse8042_iocnack(
    queue_t *qp,
    mblk_t *mp,
    struct iocblk *iocp,
    int error,
    int rval)
{
	mp->b_datap->db_type = M_IOCNAK;
	iocp->ioc_rval = rval;
	iocp->ioc_error = error;
	qreply(qp, mp);
}

static void
mouse8042_reset_timeout(void *argp)
{
	struct mouse_state *state = (struct mouse_state *)argp;
	mblk_t *mp;

	mutex_enter(&state->reset_mutex);

	/*
	 * If the interrupt handler hasn't completed the reset handling
	 * (reset_state would be IDLE or FAILED in that case), then
	 * drop the 8042 lock, and send a faked retry reply upstream,
	 * then enable the queue for further message processing.
	 */
	if (state->reset_state != MSE_RESET_IDLE &&
	    state->reset_state != MSE_RESET_FAILED) {

		state->reset_tid = 0;
		state->reset_state = MSE_RESET_IDLE;
		cv_signal(&state->reset_cv);

		(void) ddi_get8(state->ms_handle, state->ms_addr +
		    I8042_UNLOCK);

		mp = state->reply_mp;
		*mp->b_wptr++ = MSERESEND;
		state->reply_mp = NULL;

		if (state->ms_rqp != NULL)
			putnext(state->ms_rqp, mp);
		else
			freemsg(mp);

		ASSERT(state->ms_wqp != NULL);

		enableok(state->ms_wqp);
		qenable(state->ms_wqp);
	}

	mutex_exit(&state->reset_mutex);
}

/*
 * Returns 1 if the caller should put the message (bp) back on the queue
 */
static int
mouse8042_initiate_reset(queue_t *q, mblk_t *mp, struct mouse_state *state)
{
	mutex_enter(&state->reset_mutex);
	/*
	 * If we're in the middle of a reset, put the message back on the queue
	 * for processing later.
	 */
	if (state->reset_state != MSE_RESET_IDLE) {
		/*
		 * We noenable the queue again here in case it was backenabled
		 * by an upper-level module.
		 */
		noenable(q);

		mutex_exit(&state->reset_mutex);
		return (1);
	}

	/*
	 * Drop the reset state lock before allocating the response message and
	 * grabbing the 8042 exclusive-access lock (since those operations
	 * may take an extended period of time to complete).
	 */
	mutex_exit(&state->reset_mutex);

	if (state->reply_mp == NULL)
		state->reply_mp = allocb(2, BPRI_MED);
	if (state->reset_ack_mp == NULL)
		state->reset_ack_mp = allocb(1, BPRI_MED);

	if (state->reply_mp == NULL || state->reset_ack_mp == NULL) {
		/*
		 * Allocation failed -- set up a bufcall to enable the queue
		 * whenever there is enough memory to allocate the response
		 * message.
		 */
		state->bc_id = qbufcall(q, (state->reply_mp == NULL) ? 2 : 1,
		    BPRI_MED, (void (*)(void *))qenable, q);

		if (state->bc_id == 0) {
			/*
			 * If the qbufcall failed, we cannot proceed, so use the
			 * message we were sent to respond with an error.
			 */
			*mp->b_rptr = MSEERROR;
			mp->b_wptr = mp->b_rptr + 1;
			qreply(q, mp);
			return (0);
		}

		return (1);
	} else {
		/* Bufcall completed successfully (or wasn't needed) */
		state->bc_id = 0;
	}

	/*
	 * Gain exclusive access to the 8042 for the duration of the reset.
	 * The unlock will occur when the reset has either completed or timed
	 * out.
	 */
	(void) ddi_get8(state->ms_handle,
	    state->ms_addr + I8042_LOCK);

	mutex_enter(&state->reset_mutex);

	state->reset_state = MSE_RESET_PRE;
	noenable(q);

	state->reset_tid = qtimeout(q,
	    mouse8042_reset_timeout,
	    state,
	    drv_usectohz(
	    MOUSE8042_RESET_TIMEOUT_USECS));

	ddi_put8(state->ms_handle,
	    state->ms_addr +
	    I8042_INT_OUTPUT_DATA, MSERESET);

	mp->b_rptr++;

	mutex_exit(&state->reset_mutex);
	return (1);
}

/*
 * Returns 1 if the caller should stop processing messages
 */
static int
mouse8042_process_data_msg(queue_t *q, mblk_t *mp, struct mouse_state *state)
{
	mblk_t *bp;
	mblk_t *next;

	bp = mp;
	do {
		while (bp->b_rptr < bp->b_wptr) {
			/*
			 * Detect an attempt to reset the mouse.  Lock out any
			 * further mouse writes until the reset has completed.
			 */
			if (*bp->b_rptr == MSERESET) {

				/*
				 * If we couldn't allocate memory and we
				 * we couldn't register a bufcall,
				 * mouse8042_initiate_reset returns 0 and
				 * has already used the message to send an
				 * error reply back upstream, so there is no
				 * need to deallocate or put this message back
				 * on the queue.
				 */
				if (mouse8042_initiate_reset(q, bp, state) == 0)
					return (1);

				/*
				 * If there's no data remaining in this block,
				 * free this block and put the following blocks
				 * of this message back on the queue. If putting
				 * the rest of the message back on the queue
				 * fails, free the the message.
				 */
				if (MBLKL(bp) == 0) {
					next = bp->b_cont;
					freeb(bp);
					bp = next;
				}
				if (bp != NULL) {
					if (!putbq(q, bp))
						freemsg(bp);
				}

				return (1);

			}
			ddi_put8(state->ms_handle,
			    state->ms_addr + I8042_INT_OUTPUT_DATA,
			    *bp->b_rptr++);
		}
		next = bp->b_cont;
		freeb(bp);
	} while ((bp = next) != NULL);

	return (0);
}

static int
mouse8042_process_msg(queue_t *q, mblk_t *mp, struct mouse_state *state)
{
	struct iocblk *iocbp;
	int rv = 0;

	iocbp = (struct iocblk *)mp->b_rptr;

	switch (mp->b_datap->db_type) {
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			flushq(q, FLUSHDATA);
			*mp->b_rptr &= ~FLUSHW;
		}
		if (*mp->b_rptr & FLUSHR) {
			qreply(q, mp);
		} else
			freemsg(mp);
		break;
	case M_IOCTL:
		mouse8042_iocnack(q, mp, iocbp, EINVAL, 0);
		break;
	case M_IOCDATA:
		mouse8042_iocnack(q, mp, iocbp, EINVAL, 0);
		break;
	case M_DATA:
		rv = mouse8042_process_data_msg(q, mp, state);
		break;
	default:
		freemsg(mp);
		break;
	}

	return (rv);
}

/*
 * This is the main mouse input routine.  Commands and parameters
 * from upstream are sent to the mouse device immediately, unless
 * the mouse is in the process of being reset, in which case
 * commands are queued and executed later in the service procedure.
 */
static int
mouse8042_wput(queue_t *q, mblk_t *mp)
{
	struct mouse_state *state;
	state = (struct mouse_state *)q->q_ptr;

	/*
	 * Process all messages immediately, unless a reset is in
	 * progress.  If a reset is in progress, deflect processing to
	 * the service procedure.
	 */
	if (state->reset_state != MSE_RESET_IDLE)
		return (putq(q, mp));

	/*
	 * If there are still messages outstanding in the queue that
	 * the service procedure hasn't processed yet, put this
	 * message in the queue also, to ensure proper message
	 * ordering.
	 */
	if (q->q_first)
		return (putq(q, mp));

	(void) mouse8042_process_msg(q, mp, state);

	return (0);
}

static int
mouse8042_wsrv(queue_t *qp)
{
	mblk_t *mp;
	struct mouse_state *state;
	state = (struct mouse_state *)qp->q_ptr;

	while ((mp = getq(qp)) != NULL) {
		if (mouse8042_process_msg(qp, mp, state) != 0)
			break;
	}

	return (0);
}

/*
 * Returns the next reset state, given the current state and the byte
 * received from the mouse.  Error and Resend codes are handled by the
 * caller.
 */
static mouse8042_reset_state_e
mouse8042_reset_fsm(mouse8042_reset_state_e reset_state, uint8_t mdata)
{
	switch (reset_state) {
	case MSE_RESET_PRE:	/* RESET sent, now we expect an ACK */
		if (mdata == MSE_ACK)	/* Got the ACK */
			return (MSE_RESET_ACK);
		break;

	case MSE_RESET_ACK:	/* ACK received; now we expect 0xAA */
		if (mdata == MSE_AA)	/* Got the 0xAA */
			return (MSE_RESET_AA);
		break;

	case MSE_RESET_AA:	/* 0xAA received; now we expect 0x00 */
		if (mdata == MSE_00)
			return (MSE_RESET_IDLE);
		break;
	}

	return (reset_state);
}

static uint_t
mouse8042_intr(caddr_t arg)
{
	unsigned char    mdata;
	mblk_t *mp;
	struct mouse_state *state = (struct mouse_state *)arg;
	int rc;

	mutex_enter(&state->ms_mutex);

	rc = DDI_INTR_UNCLAIMED;

	for (;;) {

		if (ddi_get8(state->ms_handle,
		    state->ms_addr + I8042_INT_INPUT_AVAIL) == 0) {
			break;
		}

		mdata = ddi_get8(state->ms_handle,
		    state->ms_addr + I8042_INT_INPUT_DATA);

		rc = DDI_INTR_CLAIMED;

		/*
		 * If we're not ready for this data, discard it.
		 */
		if (!state->ready)
			continue;

		mutex_enter(&state->reset_mutex);
		if (state->reset_state != MSE_RESET_IDLE) {

			if (mdata == MSEERROR || mdata == MSERESET) {
				state->reset_state = MSE_RESET_FAILED;
			} else {
				state->reset_state =
				    mouse8042_reset_fsm(state->reset_state,
				    mdata);
			}

			if (state->reset_state == MSE_RESET_ACK) {

			/*
			 * We received an ACK from the mouse, so
			 * send it upstream immediately so that
			 * consumers depending on the immediate
			 * ACK don't time out.
			 */
				if (state->reset_ack_mp != NULL) {

					mp = state->reset_ack_mp;

					state->reset_ack_mp = NULL;

					if (state->ms_rqp != NULL) {
						*mp->b_wptr++ = MSE_ACK;
						putnext(state->ms_rqp, mp);
					} else
						freemsg(mp);
				}

				if (state->ms_wqp != NULL) {
					enableok(state->ms_wqp);
					qenable(state->ms_wqp);
				}

			} else if (state->reset_state == MSE_RESET_IDLE ||
			    state->reset_state == MSE_RESET_FAILED) {

			/*
			 * If we transitioned back to the idle reset state (or
			 * the reset failed), disable the timeout, release the
			 * 8042 exclusive-access lock, then send the response
			 * the the upper-level modules. Finally, enable the
			 * queue and schedule queue service procedures so that
			 * upper-level modules can process the response.
			 * Otherwise, if we're still in the middle of the
			 * reset sequence, do not send the data up (since the
			 * response is sent at the end of the sequence, or
			 * on timeout/error).
			 */

				mutex_exit(&state->reset_mutex);
				(void) quntimeout(state->ms_wqp,
				    state->reset_tid);
				mutex_enter(&state->reset_mutex);

				(void) ddi_get8(state->ms_handle,
				    state->ms_addr + I8042_UNLOCK);

				state->reset_tid = 0;
				if (state->reply_mp != NULL) {
					mp = state->reply_mp;
					if (state->reset_state ==
					    MSE_RESET_FAILED) {
						*mp->b_wptr++ = mdata;
					} else {
						*mp->b_wptr++ = MSE_AA;
						*mp->b_wptr++ = MSE_00;
					}
					state->reply_mp = NULL;
				} else {
					mp = NULL;
				}

				state->reset_state = MSE_RESET_IDLE;
				cv_signal(&state->reset_cv);

				if (mp != NULL) {
					if (state->ms_rqp != NULL)
						putnext(state->ms_rqp, mp);
					else
						freemsg(mp);
				}

				if (state->ms_wqp != NULL) {
					enableok(state->ms_wqp);
					qenable(state->ms_wqp);
				}
			}

			mutex_exit(&state->reset_mutex);
			mutex_exit(&state->ms_mutex);
			return (rc);
		}
		mutex_exit(&state->reset_mutex);

		if (state->ms_rqp != NULL && (mp = allocb(1, BPRI_MED))) {
			*mp->b_wptr++ = mdata;
			putnext(state->ms_rqp, mp);
		}
	}
	mutex_exit(&state->ms_mutex);

	return (rc);
}
