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
/*	  All Rights Reserved  	*/

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/debug.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h>

#include <sys/promif.h>
#include <sys/cred.h>

#include <sys/i8042.h>
#include <sys/note.h>

#define	DRIVER_NAME(dip)	ddi_driver_name(dip)

#ifdef	DEBUG
#define	MOUSE8042_DEBUG
#endif

#define	MOUSE8042_INTERNAL_OPEN(minor)	(((minor) & 0x1) == 1)
#define	MOUSE8042_MINOR_TO_INSTANCE(minor)	((minor) / 2)
#define	MOUSE8042_INTERNAL_MINOR(minor)		((minor) + 1)

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

struct mouse_state {
	queue_t	*ms_rqp;
	queue_t	*ms_wqp;
	ddi_iblock_cookie_t	ms_iblock_cookie;
	ddi_acc_handle_t	ms_handle;
	uint8_t			*ms_addr;
	kmutex_t		ms_mutex;

	minor_t			ms_minor;
	boolean_t		ms_opened;
};

#if	defined(MOUSE8042_DEBUG)
int mouse8042_debug = 0;
int mouse8042_debug_minimal = 0;
#endif

static uint_t mouse8042_intr(caddr_t arg);
static int mouse8042_open(queue_t *q, dev_t *devp, int flag, int sflag,
		cred_t *cred_p);
static int mouse8042_close(queue_t *q, int flag, cred_t *cred_p);
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
	NULL,		/* service */
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


#ifdef MOUSE8042_DEBUG
	if (mouse8042_debug) {
		cmn_err(CE_CONT, MODULE_NAME "_attach entry\n");
	}
#endif

	if (cmd == DDI_RESUME) {
		state = (struct mouse_state *)ddi_get_driver_private(dip);

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
	 * 	external node minor num == instance * 2
	 *	internal node minor num == instance * 2 + 1
	 */
	rc = ddi_create_minor_node(dip, "mouse", S_IFCHR, instance * 2,
	    DDI_NT_MOUSE, NULL);
	if (rc != DDI_SUCCESS) {
#if	defined(MOUSE8042_DEBUG)
		cmn_err(CE_CONT,
		    MODULE_NAME "_attach: ddi_create_minor_node failed\n");
#endif
		goto fail_1;
	}

	if (ddi_create_internal_pathname(dip, "internal_mouse", S_IFCHR,
	    instance * 2 + 1) != DDI_SUCCESS) {
		goto fail_2;
	}

	rc = ddi_regs_map_setup(dip, 0, (caddr_t *)&state->ms_addr,
	    (offset_t)0, (offset_t)0, &attr, &state->ms_handle);
	if (rc != DDI_SUCCESS) {
#if	defined(MOUSE8042_DEBUG)
		cmn_err(CE_WARN, MODULE_NAME "_attach:  can't map registers");
#endif
		goto fail_2;
	}

	rc = ddi_get_iblock_cookie(dip, 0, &state->ms_iblock_cookie);
	if (rc != DDI_SUCCESS) {
#if	defined(MOUSE8042_DEBUG)
		cmn_err(CE_WARN,
		    MODULE_NAME "_attach:  Can't get iblock cookie");
#endif
		goto fail_3;
	}

	mutex_init(&state->ms_mutex, NULL, MUTEX_DRIVER,
	    state->ms_iblock_cookie);

	rc = ddi_add_intr(dip, 0,
	    (ddi_iblock_cookie_t *)NULL, (ddi_idevice_cookie_t *)NULL,
	    mouse8042_intr, (caddr_t)state);
	if (rc != DDI_SUCCESS) {
#if	defined(MOUSE8042_DEBUG)
		cmn_err(CE_WARN, MODULE_NAME "_attach: cannot add interrupt");
#endif
		goto fail_3;
	}

	mouse8042_dip = dip;

	/* Now that we're attached, announce our presence to the world. */
	ddi_report_dev(dip);
#if	defined(MOUSE8042_DEBUG)
	cmn_err(CE_CONT, "?%s #%d\n", DRIVER_NAME(dip), ddi_get_instance(dip));
#endif
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
		return (DDI_SUCCESS);

	case DDI_DETACH:
		ddi_remove_intr(dip, 0, state->ms_iblock_cookie);
		mouse8042_dip = NULL;
		mutex_destroy(&state->ms_mutex);
		ddi_prop_remove_all(dip);
		ddi_regs_map_free(&state->ms_handle);
		ddi_remove_minor_node(dip, NULL);
		kmem_free(state, sizeof (struct mouse_state));
		return (DDI_SUCCESS);

	default:
#ifdef MOUSE8042_DEBUG
		if (mouse8042_debug) {
			cmn_err(CE_CONT,
			    "mouse8042_detach: cmd = %d unknown\n", cmd);
		}
#endif
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

#ifdef MOUSE8042_DEBUG
	if (mouse8042_debug)
		cmn_err(CE_CONT, "mouse8042_getinfo: call\n");
#endif
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

#ifdef MOUSE8042_DEBUG
	if (mouse8042_debug)
		cmn_err(CE_CONT, "mouse8042_open:entered\n");
#endif

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

#ifdef MOUSE8042_DEBUG
	if (mouse8042_debug)
		cmn_err(CE_CONT, "mouse8042_close:entered\n");
#endif

	mutex_enter(&state->ms_mutex);

	qprocsoff(q);

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

static int
mouse8042_wput(queue_t *q, mblk_t *mp)
{
	struct iocblk *iocbp;
	mblk_t *bp;
	mblk_t *next;
	struct mouse_state *state;

	state = (struct mouse_state *)q->q_ptr;

#ifdef MOUSE8042_DEBUG
	if (mouse8042_debug)
		cmn_err(CE_CONT, "mouse8042_wput:entered\n");
#endif
	iocbp = (struct iocblk *)mp->b_rptr;
	switch (mp->b_datap->db_type) {
	case M_FLUSH:
#ifdef MOUSE8042_DEBUG
		if (mouse8042_debug)
			cmn_err(CE_CONT, "mouse8042_wput:M_FLUSH\n");
#endif

		if (*mp->b_rptr & FLUSHW)
			flushq(q, FLUSHDATA);
		qreply(q, mp);
		break;
	case M_IOCTL:
#ifdef MOUSE8042_DEBUG
		if (mouse8042_debug)
			cmn_err(CE_CONT, "mouse8042_wput:M_IOCTL\n");
#endif
		mouse8042_iocnack(q, mp, iocbp, EINVAL, 0);
		break;
	case M_IOCDATA:
#ifdef MOUSE8042_DEBUG
		if (mouse8042_debug)
			cmn_err(CE_CONT, "mouse8042_wput:M_IOCDATA\n");
#endif
		mouse8042_iocnack(q, mp, iocbp, EINVAL, 0);
		break;
	case M_DATA:
		bp = mp;
		do {
			while (bp->b_rptr < bp->b_wptr) {
#if	defined(MOUSE8042_DEBUG)
				if (mouse8042_debug) {
					cmn_err(CE_CONT,
					    "mouse8042:  send %2x\n",
					    *bp->b_rptr);
				}
				if (mouse8042_debug_minimal) {
					cmn_err(CE_CONT, ">a:%2x ",
					    *bp->b_rptr);
				}
#endif
				ddi_put8(state->ms_handle,
				    state->ms_addr + I8042_INT_OUTPUT_DATA,
				    *bp->b_rptr++);
			}
			next = bp->b_cont;
			freeb(bp);
		} while ((bp = next) != NULL);
		break;
	default:
		freemsg(mp);
		break;
	}
#ifdef MOUSE8042_DEBUG
	if (mouse8042_debug)
		cmn_err(CE_CONT, "mouse8042_wput:leaving\n");
#endif
	return (0);	/* ignored */
}

static uint_t
mouse8042_intr(caddr_t arg)
{
	unsigned char    mdata;
	mblk_t *mp;
	struct mouse_state *state = (struct mouse_state *)arg;
	int rc;

	mutex_enter(&state->ms_mutex);

#if	defined(MOUSE8042_DEBUG)
	if (mouse8042_debug)
		cmn_err(CE_CONT, "mouse8042_intr()\n");
#endif
	rc = DDI_INTR_UNCLAIMED;

	for (;;) {

		if (ddi_get8(state->ms_handle,
		    state->ms_addr + I8042_INT_INPUT_AVAIL) == 0) {
			break;
		}

		mdata = ddi_get8(state->ms_handle,
		    state->ms_addr + I8042_INT_INPUT_DATA);

#if	defined(MOUSE8042_DEBUG)
		if (mouse8042_debug)
			cmn_err(CE_CONT, "mouse8042_intr:  got %2x\n", mdata);
		if (mouse8042_debug_minimal)
			cmn_err(CE_CONT, "<A:%2x ", mdata);
#endif

		rc = DDI_INTR_CLAIMED;

		if (state->ms_rqp != NULL && (mp = allocb(1, BPRI_MED))) {
			*mp->b_wptr++ = mdata;
			putnext(state->ms_rqp, mp);
		}
	}
#ifdef MOUSE8042_DEBUG
	if (mouse8042_debug)
		cmn_err(CE_CONT, "mouse8042_intr() ok\n");
#endif
	mutex_exit(&state->ms_mutex);

	return (rc);
}
