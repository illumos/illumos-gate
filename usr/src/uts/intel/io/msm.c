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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Microsoft Bus Mouse Module - Streams
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
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include "sys/proc.h"
#include "sys/cmn_err.h"
#include "sys/mouse.h"
#include "sys/mse.h"

#define	PRF	printf


/*
 *
 * Local Static Data
 *
 */
#define	MSM_MAXUNIT	1
#define	MSMUNIT(dev)	((dev) & 0xf)

static dev_info_t *msmunits[MSM_MAXUNIT];

static struct driver_minor_data {
	char	*name;
	int	minor;
	int	type;
} msm_minor_data[] = {
	{"l", 0, S_IFCHR},
	{0}
};
int msmdevflag = 0;
int msm_debug = 0;


/*
 * static struct strmseinfo *msmptr = 0;
 */

static char mousepresent;
static char mouseinuse;
static char mousemode;
static char mousestatus;
static int xmotion, ymotion;
int	mouse_base = 0x23c;


static uint_t msmintr(caddr_t arg);
static int msmopen(queue_t *q, dev_t *devp, int flag, int sflag,
    struct cred *cred_p);
static int msmclose(queue_t *q, int flag, cred_t *cred_p);
static int msm_wput(queue_t *q, mblk_t *mp);

static int msminit(dev_info_t *dip);
static int msminfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int msmprobe(dev_info_t *dev);
static int msmattach(dev_info_t *dev, ddi_attach_cmd_t cmd);
static int msmdetach(dev_info_t *dev, ddi_detach_cmd_t cmd);

struct module_info	msmminfo = { 23, "msm", 0, INFPSZ, 256, 128};

static struct qinit msm_rinit = {
	NULL, NULL, msmopen, msmclose, NULL, &msmminfo, NULL};

static struct qinit msm_winit = {
	msm_wput, NULL, NULL, NULL, NULL, &msmminfo, NULL};

struct streamtab msm_info = { &msm_rinit, &msm_winit, NULL, NULL};

char	msmclosing = 0;
static	int		xmotion,		/* current position and .. */
			ymotion;		/*  button status, used .. */

/*
 * Local Function Declarations
 */

struct cb_ops	msm_cb_ops = {
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
	(&msm_info),			/* streamtab  */
	D_NEW | D_MP | D_MTPERMOD	/* Driver compatibility flag */

};


struct dev_ops	msm_ops = {

	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	msminfo,		/* info */
	nulldev,		/* identify */
	msmprobe,		/* probe */
	msmattach,		/* attach */
	msmdetach,		/* detach */
	nodev,			/* reset */
	&msm_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a driver */
	"Microsoft Mouse driver",
	&msm_ops,	/* driver ops */
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


extern struct modctl *mod_getctl();
extern char *kobj_getmodname();

#endif

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


static int
msmprobe(dev_info_t *dip)
{
	int 	unit;

#ifdef MSM_DEBUG
	if (msm_debug) {
		PRF("msmprobe: entry\n");
	}
#endif

	unit = ddi_get_instance(dip);
#ifdef MSM_DEBUG
	if (msm_debug)
		PRF("unit is %x\n", unit);
#endif
	if (unit >= MSM_MAXUNIT || msmunits[unit])
		return (DDI_PROBE_FAILURE);

	return (msminit(dip));

}

/*ARGSUSED*/
static int
msmattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int unit;
	struct driver_minor_data *dmdp;
	struct strmseinfo *msmptr = 0;

#ifdef MSM_DEBUG
	if (msm_debug) {
		PRF("msmattach entry\n");
	}
#endif

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	unit = ddi_get_instance(dip);

	for (dmdp = msm_minor_data; dmdp->name != NULL; dmdp++) {
		if (ddi_create_minor_node(dip, dmdp->name, dmdp->type,
		    dmdp->minor, DDI_PSEUDO, NULL) == DDI_FAILURE) {

			ddi_remove_minor_node(dip, NULL);
			ddi_prop_remove_all(dip);
#ifdef MSM_DEBUG
			if (msm_debug)
				PRF("msmattach:"
				    " ddi_create_minor_node failed\n");
#endif
			return (DDI_FAILURE);
		}
	}
	msmunits[unit] = dip;

	/* allocate and initialize state structure */
	msmptr = kmem_zalloc(sizeof (struct strmseinfo), KM_SLEEP);
	msmptr->state = 0;	/* not opened */
	ddi_set_driver_private(dip, msmptr);

	if (ddi_add_intr(dip, (uint_t)0, &msmptr->iblock,
	    (ddi_idevice_cookie_t *)0, msmintr, (caddr_t)msmptr)
	    != DDI_SUCCESS) {
#ifdef MSM_DEBUG
		if (msm_debug)
			PRF("msmattach: ddi_add_intr failed\n");
#endif
		cmn_err(CE_WARN, "msm: cannot add intr\n");
		return (DDI_FAILURE);
	}
	mutex_init(&msmptr->lock, NULL, MUTEX_DRIVER, (void *)msmptr->iblock);
	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

/*
 * msmdetach:
 */
/*ARGSUSED*/
static int
msmdetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	dev_info_t	*ldevi;
	struct strmseinfo *msmptr;
	int instance;

	switch (cmd) {

	case DDI_DETACH:

		/*
		 * check if every instance can be unloaded before actually
		 * starting to unload this one; this prevents the needless
		 * detach/re-attach sequence
		 */
		for (instance = 0; instance < MSM_MAXUNIT; instance++) {
			if (((ldevi = msmunits[instance]) == NULL) ||
			    !(msmptr = ddi_get_driver_private(ldevi))) {
				continue;
			}
		}

/*
 * 		Undo what we did in msmattach & msmprobe, freeing resources
 * 		and removing things we installed.  The system
 * 		framework guarantees we are not active with this devinfo
 * 		node in any other entry points at this time.
 */
		instance = ddi_get_instance(dip);
		if ((instance >= MSM_MAXUNIT) ||
		    !(msmptr = ddi_get_driver_private(dip)))
			return (DDI_FAILURE);

		msmunits[instance] = 0;
		ddi_prop_remove_all(dip);
		ddi_remove_minor_node(dip, NULL);
		mutex_destroy(&msmptr->lock);
		ddi_remove_intr(dip, 0, msmptr->iblock);
		kmem_free(msmptr, sizeof (struct strmseinfo));
		return (DDI_SUCCESS);

	default:
#ifdef MSM_DEBUG
		if (msm_debug) {
			PRF("msmdetach: cmd = %d unknown\n", cmd);
		}
#endif
		return (DDI_FAILURE);
	}
}


/* ARGSUSED */
static int
msminfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t dev = (dev_t)arg;
	int unit;
	dev_info_t *devi;

#ifdef MSM_DEBUG
	if (msm_debug)
		PRF("msminfo: call\n");
#endif
	if ((unit = MSMUNIT(dev)) >= MSM_MAXUNIT ||
	    (devi = msmunits[unit]) == NULL)
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
msminit(dev_info_t *dip)
{
	unsigned char   id1,
	    id2;
	int	ioaddr;
	int	old_probe;


#ifdef MSM_DEBUG
	if (msm_debug)
		PRF("msminit: call mouse_base = %x\n", mouse_base);
#endif
	old_probe = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "ignore-hardware-nodes", 0);

	if (old_probe) {
		int	len = sizeof (int);

		/*
		 * Check if ioaddr is set in .conf file, it should be.  If it
		 * isn't then try the default i/o addr
		 */
		if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
		    DDI_PROP_DONTPASS, "ioaddr", (caddr_t)&ioaddr,
		    &len) == DDI_PROP_SUCCESS) {
			mouse_base = ioaddr;
		}
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
				mouse_base = ioaddr;
				break;
			}
		kmem_free(reglist, reglen);
	}

	/*
	 * Try reading the InPort identification register.  It should
	 * alternate between a signature and a version number.
	 */
	id1 = inb(mouse_base + IDENTREG);
	id2 = inb(mouse_base + IDENTREG);
	if (id1 != id2 && (id1 == SIGN || id2 == SIGN))
		mousepresent = 1;
	else
		return (DDI_PROBE_FAILURE);

	/* Reset the mouse to make sure it does not interrupt */
	outb(mouse_base + ADDRREG, RESET | MODE);

#ifdef MSM_DEBUG
	if (msm_debug)
		PRF("msminit: succeeded\n");
#endif
	return (DDI_SUCCESS);
}

/*ARGSUSED2*/
static int
msmopen(queue_t *q, dev_t *devp, int flag, int sflag,
    struct cred *cred_p)
{
	struct strmseinfo *msmptr;
	dev_info_t *dip;
	int unit;
#ifdef MSM_DEBUG
	if (msm_debug)
		printf("msmopen:entered\n");
#endif
	if (((unit = MSMUNIT(*devp)) >= MSM_MAXUNIT) ||
	    (dip = msmunits[unit]) == NULL)
		return (DDI_FAILURE);

	if (mousepresent == 0) {
		return (EIO);
	}
	if (mouseinuse) {
		return (EBUSY);
	}

	if (!(msmptr = ddi_get_driver_private(dip)))

		if (q->q_ptr != NULL) {
#ifdef MSM_DEBUG
			if (msm_debug)
				printf("msmopen:already open\n");
#endif
			return (0);		/* already attached */
		}

	mutex_enter(&msmptr->lock);

	q->q_ptr = (caddr_t)msmptr;
	WR(q)->q_ptr = (caddr_t)msmptr;
	msmptr->rqp = q;
	msmptr->wqp = WR(q);
	qprocson(q);

#ifdef MSM_DEBUG
	if (msm_debug)
		printf("msmopen:leaving\n");
#endif
	mouseinuse = 1;
	xmotion = ymotion = 0;
	mousestatus = 0;

	/* Set appropriate modes for mouse and enable interrupts */
	mousemode = HZ30 | DATAINT | QUADMODE;
	outb(mouse_base + ADDRREG, MODE);
	outb(mouse_base + DATAREG, mousemode);
	mutex_exit(&msmptr->lock);
	return (0);
}


/*ARGSUSED1*/
static int
msmclose(queue_t *q, int flag, cred_t *cred_p)
{
	struct strmseinfo *msmptr;

	qprocsoff(q);
#ifdef MSM_DEBUG
	if (msm_debug)
		printf("msmclose:entered\n");
#endif
	msmptr = q->q_ptr;
	mutex_enter(&msmptr->lock);
	q->q_ptr = (caddr_t)NULL;
	WR(q)->q_ptr = (caddr_t)NULL;
	msmptr->rqp = NULL;
	msmptr->wqp = NULL;
	/*
	 * Use to reset the mouse to make sure it does not interrupt
	 * Now just turn off interrupts, as ATI VGA Wonder XL24
	 * appeared to get in a mode where it thought an interrupt was
	 * delivered, and wouldn't deliver any more after this was done.
	 */
	mousemode = 0;
	outb(mouse_base + ADDRREG, MODE);
	outb(mouse_base + DATAREG, mousemode);
	mouseinuse = 0;

#ifdef MSM_DEBUG
	if (msm_debug)
		printf("msmclose:leaving\n");
#endif
	mutex_exit(&msmptr->lock);
	return (0);
}

static int
msm_wput(queue_t *q, mblk_t *mp)
{
	struct iocblk *iocbp;
	struct strmseinfo *msmptr;

#ifdef MSM_DEBUG
	if (msm_debug)
		printf("msm_wput:entered\n");
#endif
	msmptr = q->q_ptr;
	if (msmptr == 0) {
		freemsg(mp);
#ifdef MSM_DEBUG
		if (msm_debug)
			printf("msm_wput:msmptr == NULL\n");
#endif
		return (0);
	}
	iocbp = (struct iocblk *)mp->b_rptr;
	switch (mp->b_datap->db_type) {
		case M_FLUSH:
#ifdef MSM_DEBUG
			if (msm_debug)
				printf("msm_wput:M_FLUSH\n");
#endif
			if (*mp->b_rptr & FLUSHW)
				flushq(q, FLUSHDATA);
			qreply(q, mp);
			break;
		case M_IOCTL:
#ifdef MSM_DEBUG
			if (msm_debug)
				printf("msm_wput:M_IOCTL\n");
#endif
			mp->b_datap->db_type = M_IOCNAK;
			iocbp->ioc_rval = 0;
			iocbp->ioc_error = EINVAL;
			qreply(q, mp);
			break;
		case M_IOCDATA:
#ifdef MSM_DEBUG
			if (msm_debug)
				printf("msm_wput:M_IOCDATA\n");
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
#ifdef MSM_DEBUG
	if (msm_debug)
		printf("msm_wput:leaving\n");
#endif
	return (0);
}

static uint_t
msmintr(caddr_t arg)
{
	char    status,
	    x,
	    y;

	struct strmseinfo *qp = (struct strmseinfo *)arg;
	mblk_t *bp;

#ifdef MSM_DEBUG
	if (msm_debug > 5)
		PRF("msmintr:\n");
#endif

	if (!qp || (qp->rqp == NULL)) {
		return (DDI_INTR_UNCLAIMED);
	}
	mutex_enter(&qp->lock);
	if (!mouseinuse) {
		mutex_exit(&qp->lock);
		return (DDI_INTR_UNCLAIMED);
	}
	/* Select mode register and turn on the HOLD data bit */
	outb(mouse_base + ADDRREG, MODE);
	outb(mouse_base + DATAREG, mousemode + HOLD);

	/* Select and read the status register */
	outb(mouse_base + ADDRREG, MSTATUS);
	status = inb(mouse_base + DATAREG);

	/* if mouse moved, save the motion */
	if (status & MOVEMENT) {
		outb(mouse_base + ADDRREG, DATA1);
		x = inb(mouse_base + DATAREG);
		xmotion += x;
		outb(mouse_base + ADDRREG, DATA2);
		y = inb(mouse_base + DATAREG);
		ymotion += y;
	} else
		x = y = 0;
	mousestatus = status | (mousestatus & ~BUTSTATMASK);

	/* Select mode register and turn off the HOLD data bit */
	outb(mouse_base + ADDRREG, MODE);
	outb(mouse_base + DATAREG, mousemode);

	if (status & (MOVEMENT | BUTCHNGMASK)) {
		char c;

		c = (char)0x80;			/* MSC sync value */

		if ((status & BUT1STAT) == 0)	/* button NOT pressed */
			c |= 0x04;		/* left button up */
		if ((status & BUT2STAT) == 0)	/* button NOT pressed */
			c |= 0x02;		/* middle button up */
		if ((status & BUT3STAT) == 0)	/* button NOT pressed */
			c |= 0x01;		/* right button up */

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
	mutex_exit(&qp->lock);
	return (DDI_INTR_UNCLAIMED);
}
