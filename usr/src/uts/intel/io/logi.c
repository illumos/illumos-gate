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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Logitech Mouse Module - Streams
 */

#include "sys/param.h"
#include "sys/types.h"
#include "sys/kmem.h"
#include "sys/signal.h"
#include "sys/errno.h"
#include "sys/file.h"
#include "sys/termio.h"
#include "sys/stream.h"
#include "sys/stropts.h"
#include "sys/strtty.h"
#include "sys/debug.h"
#include "sys/ddi.h"
#include "sys/cred.h"
#include <sys/stat.h>
#include <sys/sunddi.h>
#include "sys/proc.h"
#include "sys/cmn_err.h"
#include "sys/mouse.h"
#include "sys/mse.h"

#define	PRF	printf
struct mouseconfig mse_config = {
	0, 0
};


/*
 *
 * Local Static Data
 *
 */
#define	LOGI_MAXUNIT	1
#define	LOGIUNIT(dev)	((dev) & 0xf)

#define	M_OPEN	1

static dev_info_t *logiunits[LOGI_MAXUNIT];

static struct driver_minor_data {
	char	*name;
	int	minor;
	int	type;
} logi_minor_data[] = {
	{"l", 0, S_IFCHR},
	{0}
};
int logidevflag = 1;


/*
 * static struct strmseinfo *logiptr = 0;
 */

static unsigned	BASE_IOA = 0x23C;	/* Set to base I/O addr of bus mouse */

static uint_t logiintr();

static int logiopen(queue_t *q, dev_t *devp, int flag, int sflag,
    cred_t *cred_p);
static int logiclose(queue_t *q, int flag, cred_t *cred_p);
static int logi_wput(queue_t *q, mblk_t *mp);
static int logiinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int logiprobe(dev_info_t *dev);
static int logiattach(dev_info_t *dev, ddi_attach_cmd_t cmd);
static int logidetach(dev_info_t *dev, ddi_detach_cmd_t cmd);
static int logiinit(dev_info_t *dip);

struct module_info	logiminfo = { 23, "logi", 0, INFPSZ, 256, 128};

static struct qinit logi_rinit = {
	NULL, NULL, logiopen, logiclose, NULL, &logiminfo, NULL};

static struct qinit logi_winit = {
	logi_wput, NULL, NULL, NULL, NULL, &logiminfo, NULL};

struct streamtab logi_info = { &logi_rinit, &logi_winit, NULL, NULL};

static	int		xmotion,		/* current position and .. */
			ymotion,		/*  button status, used .. */
			oldbuttons = 1,
			status;			/*  for DOS mode.	*/

extern int nulldev(), nodev();
/*
 * Local Function Declarations
 */

struct cb_ops	logi_cb_ops = {
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
	(&logi_info),			/* streamtab  */
	D_NEW | D_MP | D_MTPERMOD	/* Driver compatibility flag */

};


struct dev_ops	logi_ops = {

	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	logiinfo,		/* info */
	nulldev,		/* identify */
	logiprobe,		/* probe */
	logiattach,		/* attach */
	logidetach,		/* detach */
	nodev,			/* reset */
	&logi_cb_ops,		/* driver operations */
	(struct bus_ops *)0	/* bus operations */

};

#ifndef BUILD_STATIC

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
	"Logitech Mouse driver",
	&logi_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};



/*
 * This is the driver initialization routine.
 */
int
_init(void)
{
	int	rv;

	rv = mod_install(&modlinkage);
	return (rv);
}


#ifdef SUNDEV
int
_fini(void)
{
	return (EBUSY);
}
#else
int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
#endif

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

#endif	/* !BUILD_STATIC */


static int
logiprobe(dev_info_t *dip)
{
	int 	unit;

#ifdef LOGI_DEBUG
	if (logi_debug) {
		PRF("logiprobe: entry\n");
	}
#endif

	unit = ddi_get_instance(dip);
#ifdef LOGI_DEBUG
	if (logi_debug)
		PRF("unit is %x\n", unit);
#endif
	if (unit >= LOGI_MAXUNIT || logiunits[unit])
		return (DDI_PROBE_FAILURE);


	return (logiinit(dip));
}

/*ARGSUSED*/
static int
logiattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int unit;
	struct driver_minor_data *dmdp;
	struct strmseinfo *logiptr = 0;

#ifdef LOGI_DEBUG
	if (logi_debug) {
		PRF("logiattach entry\n");
	}
#endif
	switch (cmd) {
	case DDI_ATTACH:
		unit = ddi_get_instance(dip);

		for (dmdp = logi_minor_data; dmdp->name != NULL; dmdp++) {
			if (ddi_create_minor_node(dip, dmdp->name, dmdp->type,
			    dmdp->minor, DDI_PSEUDO, NULL) == DDI_FAILURE) {

				ddi_remove_minor_node(dip, NULL);
				ddi_prop_remove_all(dip);
#ifdef LOGI_DEBUG
				if (logi_debug)
					PRF("logiattach: "
					    "ddi_create_minor_node failed\n");
#endif
				return (DDI_FAILURE);
			}
		}
		logiunits[unit] = dip;
		/* allocate and initialize state structure */
		logiptr = kmem_zalloc(sizeof (struct strmseinfo), KM_SLEEP);
		logiptr->state = 0;	/* not opened */
		ddi_set_driver_private(dip, logiptr);


		if (ddi_add_intr(dip, (uint_t)0, &logiptr->iblock,
		    (ddi_idevice_cookie_t *)0, logiintr,
		    (caddr_t)logiptr) != DDI_SUCCESS) {

#ifdef LOGI_DEBUG
			if (logi_debug)
				PRF("logiattach: ddi_add_intr failed\n");
#endif
			cmn_err(CE_WARN, "logi: cannot add intr\n");
			return (DDI_FAILURE);
		}

		mutex_init(&logiptr->lock, NULL, MUTEX_DRIVER,
		    (void *)logiptr->iblock);
		ddi_report_dev(dip);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

/*
 * logidetach:
 */
/*ARGSUSED*/
static int
logidetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	dev_info_t	*ldevi;
	struct strmseinfo *logiptr;
	int instance;

	switch (cmd) {

	case DDI_DETACH:

		/*
		 * check if every instance can be unloaded before actually
		 * starting to unload this one; this prevents the needless
		 * detach/re-attach sequence
		 */
		for (instance = 0; instance < LOGI_MAXUNIT; instance++) {
			if (((ldevi = logiunits[instance]) == NULL) ||
			    (logiptr = ddi_get_driver_private(ldevi)) == NULL)
				continue;
		}

/*
 * 		Undo what we did in logiattach & logiprobe, freeing resources
 * 		and removing things we installed.  The system
 * 		framework guarantees we are not active with this devinfo
 * 		node in any other entry points at this time.
 */
		instance = ddi_get_instance(dip);
		if ((instance >= LOGI_MAXUNIT) ||
		    (logiptr = ddi_get_driver_private(dip)) == NULL)
			return (DDI_FAILURE);


		logiunits[instance] = 0;
		ddi_prop_remove_all(dip);
		ddi_remove_minor_node(dip, NULL);
		mutex_destroy(&logiptr->lock);
		ddi_remove_intr(dip, 0, logiptr->iblock);
		kmem_free(logiptr, sizeof (struct strmseinfo));
		return (DDI_SUCCESS);

	default:
#ifdef LOGI_DEBUG
		if (logi_debug) {
			PRF("logidetach: cmd = %d unknown\n", cmd);
		}
#endif
		return (DDI_FAILURE);
	}
}


/* ARGSUSED */
static int
logiinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t dev = (dev_t)arg;
	int unit;
	dev_info_t *devi;

#ifdef LOGI_DEBUG
	if (logi_debug)
		PRF("logiinfo: call\n");
#endif
	if (((unit = LOGIUNIT(dev)) >= LOGI_MAXUNIT) ||
	    (devi = logiunits[unit]) == NULL)
		return (DDI_FAILURE);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)devi;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)unit;
		break;
	default:
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}


static int
logiinit(dev_info_t *dip)
{
	int	i;
	int	ioaddr;
	int	len;
	int	old_probe;

#ifdef LOGI_DEBUG
	if (logi_debug)
		PRF("logiinit: call BASE_IOA = %x\n", BASE_IOA);
#endif
	old_probe = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
		"ignore-hardware-nodes", 0);

	if (old_probe) {
		len = sizeof (int);

		/*
		 * check if ioaddr is set in .conf file, it should be.  If it
		 * isn't then try the default i/o addr
		 */
		if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
		    DDI_PROP_DONTPASS, "ioaddr", (caddr_t)&ioaddr,
		    &len) == DDI_PROP_SUCCESS)
			BASE_IOA = ioaddr;
	} else {
		int reglen, nregs;
		int i;
		struct {
			int bustype;
			int base;
			int size;
		} *reglist;

		/* new probe */
		if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "reg", (caddr_t)&reglist, &reglen) != DDI_PROP_SUCCESS)
			return (DDI_PROBE_FAILURE);
		nregs = reglen / sizeof (*reglist);
		for (i = 0; i < nregs; i++)
			if (reglist[i].bustype == 1) {
				ioaddr = reglist[i].base;
				BASE_IOA = ioaddr;
				break;
			}
		kmem_free(reglist, reglen);
	}
#ifdef LOGI_DEBUG
	if (logi_debug)
		PRF("logiinit: call BASE_IOA = %x\n", BASE_IOA);
#endif
	mse_config.present = 0;
	/* Check if the mouse board exists */
	outb(CONFIGURATOR_PORT, 0x91);
	drv_usecwait(10);
	outb(SIGNATURE_PORT, 0xC);
	drv_usecwait(10);
	i = inb(SIGNATURE_PORT);
	drv_usecwait(10);
	outb(SIGNATURE_PORT, 0x50);
	drv_usecwait(10);
	if (i == 0xC && ((inb(SIGNATURE_PORT)) == 0x50)) {
		mse_config.present = 1;
#ifdef LOGI_DEBUG
	if (logi_debug)
		printf("logiinit:Disable interrupts ioaddr %x\n", BASE_IOA);
#endif
		control_port(INTR_DISABLE);	/* Disable interrupts */
#ifdef LOGI_DEBUG
	if (logi_debug)
		PRF("logiinit: succeeded\n");
#endif
		return (DDI_SUCCESS);
	} else {
#ifdef LOGI_DEBUG
	if (logi_debug)
		PRF("logiinit: failed\n");
#endif
		return (DDI_PROBE_FAILURE);
	}
}

/*ARGSUSED2*/
static int
logiopen(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *cred_p)
{
	struct strmseinfo *logiptr;
	int unit;
	dev_info_t *dip;
#ifdef LOGI_DEBUG
	if (logi_debug)
		printf("logiopen:entered\n");
#endif
	if (((unit = LOGIUNIT(*devp)) >= LOGI_MAXUNIT) ||
		(dip = logiunits[unit]) == NULL)
		return (ENODEV);

	if (!mse_config.present)
		return (EIO);
	if ((logiptr = ddi_get_driver_private(dip)) == NULL)
		return (EIO);
	if (logiptr->state & M_OPEN)
		return (EBUSY);
	mutex_enter(&logiptr->lock);
	if (q->q_ptr != NULL) {
#ifdef LOGI_DEBUG
	if (logi_debug)
		printf("logiopen:already open\n");
#endif
		mutex_exit(&logiptr->lock);
		return (EBUSY);		/* already attached */
	}


	q->q_ptr = (caddr_t)logiptr;
	WR(q)->q_ptr = (caddr_t)logiptr;
	logiptr->rqp = q;
	logiptr->wqp = WR(q);
	qprocson(q);
#ifdef LOGI_DEBUG
	if (logi_debug)
		printf("logiopen:Enable interrupts ioaddr %x\n", BASE_IOA);
#endif
	control_port(0);	/* Enable interrupts */

#ifdef LOGI_DEBUG
	if (logi_debug)
		printf("logiopen:leaving\n");
#endif
	oldbuttons = 0;
	logiptr->state = M_OPEN;
	mutex_exit(&logiptr->lock);
	return (0);
}


/*ARGSUSED1*/
static int
logiclose(queue_t *q, int flag, cred_t *cred_p)
{
	struct strmseinfo *logiptr;

	qprocsoff(q);
#ifdef LOGI_DEBUG
	if (logi_debug)
		printf("logiclose:entered\n");
#endif
	logiptr = q->q_ptr;

	mutex_enter(&logiptr->lock);
#ifdef LOGI_DEBUG
	if (logi_debug)
		printf("logiclose:Disable interrupts ioaddr %x\n", BASE_IOA);
#endif
	control_port(INTR_DISABLE);	/* Disable interrupts */
	q->q_ptr = NULL;
	WR(q)->q_ptr = NULL;
#ifdef LOGI_DEBUG
	if (logi_debug)
		printf("logiclose:leaving\n");
#endif
	logiptr->state = 0;		/* Not opened */
	mutex_exit(&logiptr->lock);
	return (0);
}

static int
logi_wput(queue_t *q, mblk_t *mp)
{
	struct iocblk *iocbp;
	struct strmseinfo *logiptr;

#ifdef LOGI_DEBUG
	if (logi_debug)
		printf("logi_wput:entered\n");
#endif
	logiptr = q->q_ptr;
	if (logiptr == 0) {
		freemsg(mp);
#ifdef LOGI_DEBUG
		if (logi_debug)
			printf("logi_wput:logiptr == NULL\n");
#endif
		return (0);
	}
	iocbp = (struct iocblk *)mp->b_rptr;
	switch (mp->b_datap->db_type) {
		case M_FLUSH:
#ifdef LOGI_DEBUG
			if (logi_debug)
				printf("logi_wput:M_FLUSH\n");
#endif
			if (*mp->b_rptr & FLUSHW)
				flushq(q, FLUSHDATA);
			qreply(q, mp);
			break;
		case M_IOCTL:
#ifdef LOGI_DEBUG
			if (logi_debug)
				printf("logi_wput:M_IOCTL\n");
#endif
			mp->b_datap->db_type = M_IOCNAK;
			iocbp->ioc_rval = 0;
			iocbp->ioc_error = EINVAL;
			qreply(q, mp);
			break;
		case M_IOCDATA:
#ifdef LOGI_DEBUG
			if (logi_debug)
				printf("logi_wput:M_IOCDATA\n");
#endif
			mp->b_datap->db_type = M_IOCNAK;
			iocbp->ioc_rval = 0;
			iocbp->ioc_error = EINVAL;
			qreply(q, mp);
			break;
		default:
			freemsg(mp);
			break;
	}
#ifdef LOGI_DEBUG
	if (logi_debug)
		printf("logi_wput:leaving\n");
#endif
	return (0);
}

static uint_t
logiintr(caddr_t arg)
{
	int	stat = 0;
	char	x_hi,
		x_lo,
		y_hi,
		y_lo,
		buttons,
		x,
		y;
	struct strmseinfo *qp = (struct strmseinfo *)arg;
	mblk_t *bp;


	mutex_enter(&qp->lock);
	if (!(qp->state & M_OPEN)) {
#ifdef LOGI_DEBUG
	if (logi_debug > 5)
		printf("logiintr:Enable interrupts ioaddr %x\n", BASE_IOA);
#endif
		control_port(INTR_DISABLE); /* disable interrupts */
		mutex_exit(&qp->lock);
		return (DDI_INTR_UNCLAIMED);
	}

/* Get the mouse's status and put it into the appropriate virtual structure */
	control_port(INTR_DISABLE | HC | LOW_NIBBLE | X_COUNTER);
	x_lo = data_port;
	buttons = x_lo & (LEFT|MIDDLE|RIGHT);	/* buttons in high nibble */

	control_port(INTR_DISABLE | HC | HIGH_NIBBLE | X_COUNTER);
	x_hi = data_port;

	control_port(INTR_DISABLE | HC | LOW_NIBBLE | Y_COUNTER);
	y_lo =  data_port;

	control_port(INTR_DISABLE | HC | HIGH_NIBBLE | Y_COUNTER);
	y_hi = (data_port);


	/*
	 *	Piece the coordinate nibbles together.
	 */
	x = ((x_hi & 0x0f) << 4) | (x_lo & 0x0f);
	y = ((y_hi & 0x0f) << 4) | (y_lo & 0x0f);

	/* figure button change values */
	if ((buttons & LEFT) != (oldbuttons & LEFT))
		stat |= BUT1CHNG;
	if ((buttons & MIDDLE) != (oldbuttons & MIDDLE))
		stat |= BUT2CHNG;
	if ((buttons & RIGHT) != (oldbuttons & RIGHT))
		stat |= BUT3CHNG;


	/* now convert button status values */
	/* Note that the bit is 1 if the button is NOT pressed */
	if ((buttons & LEFT) == 0)
		stat |= BUT1STAT;
	if ((buttons & MIDDLE) == 0)
		stat |= BUT2STAT;
	if ((buttons & RIGHT) == 0)
		stat |= BUT3STAT;


	/* did movement occur? */
	if (x || y)
		stat |= MOVEMENT;

	/* do we need to deal with PACKETDONE ? */

	/* clear old button status, add in new status */
	status = (status & ~BUTSTATMASK) | stat;
	xmotion += x;
	ymotion += y;

	if (buttons != oldbuttons || x || y) {
		char c;

		/*
		 * Emulate a Mouse Systems Corp. mouse.
		 * push buttons, x, y, x-delta, y-delta onto clist
		 */

		c = (char)0x80;	/* sync byte pattern = 1000 0LMR */
		if (buttons & LEFT)	/* not pressed */
			c |= 0x04;
		if (buttons & MIDDLE)
			c |= 0x02;
		if (buttons & RIGHT)
			c |= 0x01;

		if ((bp = allocb(5, BPRI_MED)) == NULL) {
			mutex_exit(&qp->lock);
			return (DDI_INTR_UNCLAIMED);
		}
		*(bp->b_wptr)++ = c;	/* sync */
		*(bp->b_wptr)++ = x;	/* x coordinate */
		*(bp->b_wptr)++ = -y;  	/* y coordinate */
		*(bp->b_wptr)++ = 0;	/* delta x */
		*(bp->b_wptr)++ = 0;	/* delta y */
		putnext(qp->rqp, bp);

	}

	oldbuttons = buttons;

/* Re-enable interrupts on the mouse and return */
#ifdef LOGI_DEBUG
	if (logi_debug > 5)
		printf("logiintr:Enable interrupts ioaddr %x\n", BASE_IOA);
#endif
	control_port(0);
	mutex_exit(&qp->lock);
	return (DDI_INTR_UNCLAIMED);
}
