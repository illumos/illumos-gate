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
 * VUIDMICE module:  put mouse events into vuid format
 */

#include <sys/param.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/sad.h>
#include <sys/vuid_event.h>
#include "vuidmice.h"
#include <sys/vuid_wheel.h>
#include <sys/msio.h>

#include <sys/conf.h>
#include <sys/modctl.h>

#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

static int vuidmice_open(queue_t *, dev_t *, int, int, cred_t *);
static int vuidmice_close(queue_t *, int, cred_t *);
static int vuidmice_rput(queue_t *, mblk_t *);
static int vuidmice_rsrv(queue_t *);
static int vuidmice_wput(queue_t *, mblk_t *);
static void vuidmice_miocdata(queue_t *, mblk_t *);
static int vuidmice_handle_wheel_resolution_ioctl(queue_t *, mblk_t *, int);

static int vuidmice_service_wheel_info(mblk_t *);
static int vuidmice_service_wheel_state(queue_t *, mblk_t *, uint_t);

void VUID_QUEUE(queue_t *const, mblk_t *);
int VUID_OPEN(queue_t *const);
void VUID_CLOSE(queue_t *const);

static kmutex_t vuidmice_lock;

static struct module_info vuidmice_iinfo = {
	0,
	VUID_NAME,
	0,
	INFPSZ,
	1000,
	100
};

static struct qinit vuidmice_rinit = {
	vuidmice_rput,
	vuidmice_rsrv,
	vuidmice_open,
	vuidmice_close,
	NULL,
	&vuidmice_iinfo,
	NULL
};

static struct module_info vuidmice_oinfo = {
	0,
	VUID_NAME,
	0,
	INFPSZ,
	1000,
	100
};

static struct qinit vuidmice_winit = {
	vuidmice_wput,
	NULL,
	NULL,
	NULL,
	NULL,
	&vuidmice_oinfo,
	NULL
};

struct streamtab vuidmice_info = {
	&vuidmice_rinit,
	&vuidmice_winit,
	NULL,
	NULL
};

/*
 * This is the loadable module wrapper.
 */

/*
 * D_MTQPAIR effectively makes the module single threaded.
 * There can be only one thread active in the module at any time.
 * It may be a read or write thread.
 */
#define	VUIDMICE_CONF_FLAG	(D_MP | D_MTQPAIR)

static struct fmodsw fsw = {
	VUID_NAME,
	&vuidmice_info,
	VUIDMICE_CONF_FLAG
};

static struct modlstrmod modlstrmod = {
	&mod_strmodops,
	"mouse events to vuid events",
	&fsw
};

/*
 * Module linkage information for the kernel.
 */
static struct modlinkage modlinkage = {
	MODREV_1,
	&modlstrmod,
	NULL
};

static int module_open = 0;	/* allow only one open of this module */

int
_init(void)
{
	register int rc;

	mutex_init(&vuidmice_lock, NULL, MUTEX_DEFAULT, NULL);
	if ((rc = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&vuidmice_lock);
	}
	return (rc);
}

int
_fini(void)
{
	register int rc;

	if ((rc = mod_remove(&modlinkage)) == 0)
		mutex_destroy(&vuidmice_lock);
	return (rc);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/* ARGSUSED1 */
static int
vuidmice_open(queue_t *qp, dev_t *devp, int oflag, int sflag, cred_t *crp)
{
	if (qp->q_ptr != NULL)
		return (0);	 /* reopen */

	mutex_enter(&vuidmice_lock);

	/* Allow only 1 open of this module */
	if (module_open) {
		mutex_exit(&vuidmice_lock);
		return (EBUSY);
	}

	module_open++;
	mutex_exit(&vuidmice_lock);

	/*
	 * Both the read and write queues share the same state structures.
	 */
	qp->q_ptr = kmem_zalloc(sizeof (struct MouseStateInfo), KM_SLEEP);
	WR(qp)->q_ptr = qp->q_ptr;

	/* initialize state */
	STATEP->format = VUID_NATIVE;

	qprocson(qp);

#ifdef	VUID_OPEN
	if (VUID_OPEN(qp) != 0) {
		qprocsoff(qp);

		mutex_enter(&vuidmice_lock);
		module_open--;
		mutex_exit(&vuidmice_lock);
		kmem_free(qp->q_ptr, sizeof (struct MouseStateInfo));
		qp->q_ptr = NULL;
		return (ENXIO);
	}
#endif

	return (0);
}

/* ARGSUSED1 */
static int
vuidmice_close(queue_t *qp, int flag, cred_t *crp)
{
	ASSERT(qp != NULL);

	qprocsoff(qp);
	flushq(qp, FLUSHALL);
	flushq(OTHERQ(qp), FLUSHALL);

#ifdef	VUID_CLOSE
	VUID_CLOSE(qp);
#endif
	mutex_enter(&vuidmice_lock);
	module_open--;
	mutex_exit(&vuidmice_lock);
	kmem_free(qp->q_ptr, sizeof (struct MouseStateInfo));
	qp->q_ptr = NULL;

	return (0);
}

/*
 * Put procedure for input from driver end of stream (read queue).
 */
static int
vuidmice_rput(queue_t *const qp, mblk_t *mp)
{
	ASSERT(qp != NULL);
	ASSERT(mp != NULL);

	/*
	 * Handle all the related high priority messages here, hence
	 * should spend the least amount of time here.
	 */

	if (DB_TYPE(mp) == M_DATA) {
		if ((int)STATEP->format ==  VUID_FIRM_EVENT)
			return (putq(qp, mp));   /* queue message & return */
	} else if (DB_TYPE(mp) == M_FLUSH) {
			if (*mp->b_rptr & FLUSHR)
				flushq(qp, FLUSHALL);
	}

	putnext(qp, mp);	/* pass it on */
	return (0);
}

static int
vuidmice_rsrv(queue_t *const qp)
{
	register mblk_t *mp;

	ASSERT(qp != NULL);

	while ((mp = getq(qp)) != NULL) {
		ASSERT(DB_TYPE(mp) == M_DATA);

		if (!canputnext(qp))
			return (putbq(qp, mp)); /* read side is blocked */

		switch (DB_TYPE(mp)) {
		case M_DATA:
			if ((int)STATEP->format == VUID_FIRM_EVENT)
				(void) VUID_QUEUE(qp, mp);
			else
				(void) putnext(qp, mp);
			break;

		default:
			cmn_err(CE_WARN,
			    "vuidmice_rsrv: bad message type (0x%x)\n",
			    DB_TYPE(mp));

			(void) putnext(qp, mp);
			break;
		}
	}
	return (0);
}

/*
 * Put procedure for write from user end of stream (write queue).
 */
static int
vuidmice_wput(queue_t *const qp, mblk_t *mp)
{
	int	error = 0;

	ASSERT(qp != NULL);
	ASSERT(mp != NULL);

	/*
	 * Handle all the related high priority messages here, hence
	 * should spend the least amount of time here.
	 */
	switch (DB_TYPE(mp)) {	/* handle hi pri messages here */
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW)
			flushq(qp, FLUSHALL);
		putnext(qp, mp);			/* pass it on */
		return (0);

	case M_IOCTL: {
		struct iocblk *iocbp = (void *)mp->b_rptr;

		switch (iocbp->ioc_cmd) {
		case VUIDSFORMAT:

			/*
			 * VUIDSFORMAT is known to the stream head and thus
			 * is guaranteed to be an I_STR ioctl.
			 */
			if (iocbp->ioc_count == TRANSPARENT) {
				miocnak(qp, mp, 0, EINVAL);
				return (0);
			} else {
				int format_type;

				error = miocpullup(mp, sizeof (int));
				if (error != 0) {
					miocnak(qp, mp, 0, error);
					return (0);
				}

				format_type =
				    *(int *)(void *)mp->b_cont->b_rptr;
				STATEP->format = (uchar_t)format_type;
				iocbp->ioc_rval = 0;
				iocbp->ioc_count = 0;
				iocbp->ioc_error = 0;
				mp->b_datap->db_type = M_IOCACK;
			}

			/* return buffer to pool ASAP */
			if (mp->b_cont) {
				freemsg(mp->b_cont);
				mp->b_cont = NULL;
			}

			qreply(qp, mp);
			return (0);

		case VUIDGFORMAT:

			/* return buffer to pool ASAP */
			if (mp->b_cont) {
				freemsg(mp->b_cont); /* over written below */
				mp->b_cont = NULL;
			}

			/*
			 * VUIDGFORMAT is known to the stream head and thus
			 * is guaranteed to be an I_STR ioctl.
			 */
			if (iocbp->ioc_count == TRANSPARENT) {
				miocnak(qp, mp, 0, EINVAL);
				return (0);
			}

			mp->b_cont = allocb(sizeof (int), BPRI_MED);
			if (mp->b_cont == NULL) {
				miocnak(qp, mp, 0, EAGAIN);
				return (0);
			}

			*(int *)(void *)mp->b_cont->b_rptr =
			    (int)STATEP->format;
			mp->b_cont->b_wptr += sizeof (int);

			iocbp->ioc_count = sizeof (int);
			mp->b_datap->db_type = M_IOCACK;
			qreply(qp, mp);
			return (0);

		case VUID_NATIVE:
		case VUIDSADDR:
		case VUIDGADDR:
			miocnak(qp, mp, 0, ENOTTY);
			return (0);

		case MSIOBUTTONS:
			/* return buffer to pool ASAP */
			if (mp->b_cont) {
				freemsg(mp->b_cont); /* over written below */
				mp->b_cont = NULL;
			}

			/*
			 * MSIOBUTTONS is known to streamio.c and this
			 * is assume to be non-I_STR & non-TRANSPARENT ioctl
			 */

			if (iocbp->ioc_count == TRANSPARENT) {
				miocnak(qp, mp, 0, EINVAL);
				return (0);
			}

			if (STATEP->nbuttons == 0) {
				miocnak(qp, mp, 0, EINVAL);
				return (0);
			}

			mp->b_cont = allocb(sizeof (int), BPRI_MED);
			if (mp->b_cont == NULL) {
				miocnak(qp, mp, 0, EAGAIN);
				return (0);
			}

			*(int *)(void *)mp->b_cont->b_rptr =
			    (int)STATEP->nbuttons;
			mp->b_cont->b_wptr += sizeof (int);

			iocbp->ioc_count = sizeof (int);
			mp->b_datap->db_type = M_IOCACK;
			qreply(qp, mp);
			return (0);

		/*
		 * New IOCTL support. Since it's explicitly mentioned
		 * that you can't add more ioctls to stream head's
		 * hard coded list, we have to do the transparent
		 * ioctl processing which is not very exciting.
		 */
		case VUIDGWHEELCOUNT:
		case VUIDGWHEELINFO:
		case VUIDGWHEELSTATE:
		case VUIDSWHEELSTATE:
		case MSIOSRESOLUTION:
			error = vuidmice_handle_wheel_resolution_ioctl(qp,
			    mp, iocbp->ioc_cmd);
			if (!error) {
				return (0);
			} else {
				miocnak(qp, mp, 0, error);
				return (0);
			}
		default:
			putnext(qp, mp);	/* nothing to process here */

			return (0);
		}

	} /* End of case M_IOCTL */

	case M_IOCDATA:
		vuidmice_miocdata(qp, mp);

		return (0);
	default:
		putnext(qp, mp);		/* pass it on */
		return (0);
	}
	/*NOTREACHED*/
}

void
VUID_PUTNEXT(queue_t *const qp, uchar_t event_id, uchar_t event_pair_type,
	uchar_t event_pair, int event_value)
{
	int strikes = 1;
	mblk_t *bp;
	Firm_event *fep;

	/*
	 * Give this event 3 chances to allocate blocks,
	 * otherwise discard this mouse event.  3 Strikes and you're out.
	 */
	while ((bp = allocb((int)sizeof (Firm_event), BPRI_HI)) == NULL) {
		if (++strikes > 3)
			return;
		drv_usecwait(10);
	}

	fep = (void *)bp->b_wptr;
	fep->id = vuid_id_addr(VKEY_FIRST) | vuid_id_offset(event_id);

	fep->pair_type	= event_pair_type;
	fep->pair	= event_pair;
	fep->value	= event_value;
	uniqtime32(&fep->time);
	bp->b_wptr += sizeof (Firm_event);

	if (canput(qp->q_next))
		putnext(qp, bp);
	else
		(void) putbq(qp, bp); /* read side is blocked */
}


/*
 * vuidmice_miocdata
 *	M_IOCDATA processing for IOCTL's: VUIDGWHEELCOUNT, VUIDGWHEELINFO,
 *	VUIDGWHEELSTATE, VUIDSWHEELSTATE & MSIOSRESOLUTION.
 */
static void
vuidmice_miocdata(queue_t *qp, mblk_t  *mp)
{
	struct copyresp		*copyresp;
	struct iocblk		*iocbp;
	mblk_t			*ioctmp;
	mblk_t			*datap;
	Mouse_iocstate_t	*Mouseioc;
	size_t			size;
	int			err = 0;


	copyresp = (void *)mp->b_rptr;
	iocbp = (void *)mp->b_rptr;

	if (copyresp->cp_rval) {
		err = EAGAIN;

		goto err;
	}
	switch (copyresp->cp_cmd) {
	case VUIDGWHEELCOUNT:
		mp->b_datap->db_type = M_IOCACK;
		mp->b_wptr = mp->b_rptr + sizeof (struct iocblk);
		iocbp->ioc_error = 0;
		iocbp->ioc_count = 0;
		iocbp->ioc_rval = 0;
		if (mp->b_cont != NULL) {
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
		}

		break;
	case VUIDGWHEELINFO:
	case VUIDGWHEELSTATE:
		ioctmp = copyresp->cp_private;
		Mouseioc = (void *)ioctmp->b_rptr;
		if (Mouseioc->ioc_state == GETSTRUCT) {
			if (mp->b_cont == NULL) {
				err = EINVAL;

				break;
			}
			datap = mp->b_cont;
			if (copyresp->cp_cmd == VUIDGWHEELSTATE) {
				err = vuidmice_service_wheel_state(qp, datap,
				    VUIDGWHEELSTATE);
			} else {
				err = vuidmice_service_wheel_info(datap);
			}
			if (err) {
				break;
			}

			if (copyresp->cp_cmd == VUIDGWHEELSTATE) {
				size = sizeof (wheel_state);
			} else {
				size = sizeof (wheel_info);
			}

			Mouseioc->ioc_state = GETRESULT;
			ASSERT(Mouseioc->u_addr != NULL);
			mcopyout(mp, ioctmp, size, Mouseioc->u_addr, NULL);
		} else if (Mouseioc->ioc_state == GETRESULT) {
			freemsg(ioctmp);
			mp->b_datap->db_type = M_IOCACK;
			mp->b_wptr = mp->b_rptr + sizeof (struct iocblk);
			iocbp->ioc_error = 0;
			iocbp->ioc_count = 0;
			iocbp->ioc_rval = 0;
			if (mp->b_cont != NULL) {
				freemsg(mp->b_cont);
				mp->b_cont = NULL;
			}
		}

		break;
	case VUIDSWHEELSTATE:
	case MSIOSRESOLUTION:
		ioctmp = copyresp->cp_private;
		Mouseioc = (void *)ioctmp->b_rptr;
		if (mp->b_cont == NULL) {
			err = EINVAL;

			break;
		}
		datap = mp->b_cont;

		if (copyresp->cp_cmd == VUIDSWHEELSTATE) {
			err = vuidmice_service_wheel_state(qp,
			    datap, VUIDSWHEELSTATE);
		}

		if (err) {
			break;
		}

		if (mp->b_cont) {
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
		}
		freemsg(ioctmp);
		iocbp->ioc_count = 0;
		iocbp->ioc_error = 0;
		iocbp->ioc_rval = 0;
		mp->b_datap->db_type = M_IOCACK;

		break;
	default:
		err = EINVAL;

		break;
	}

err:
	if (err) {
		mp->b_datap->db_type = M_IOCNAK;
		if (mp->b_cont) {
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
		}
		if (copyresp->cp_private) {
			freemsg(copyresp->cp_private);
			copyresp->cp_private = NULL;
		}
		iocbp->ioc_count = 0;
		iocbp->ioc_error = err;
	}
	qreply(qp, mp);
}


/*
 * vuidmice_handle_wheel_resolution_ioctl
 *	Handle wheel mouse and MSIOSRESOLUTION ioctls.
 *
 * Here we also support non-transparent way of these ioctls
 * just like usb mouse driver does, so the consms module is
 * very simple to deal with these ioctls.
 */
static int
vuidmice_handle_wheel_resolution_ioctl(queue_t *qp, mblk_t *mp, int cmd)
{
	int			err = 0;
	Mouse_iocstate_t	*Mouseioc;
	caddr_t			useraddr;
	size_t			size;
	mblk_t			*ioctmp;
	mblk_t			*datap;

	struct iocblk *iocbp = (void *)mp->b_rptr;

	if (iocbp->ioc_count == TRANSPARENT) {
		if (mp->b_cont == NULL)
			return (EINVAL);
		useraddr = *((caddr_t *)(void *)mp->b_cont->b_rptr);
		switch (cmd) {
		case VUIDGWHEELCOUNT:
			size = sizeof (int);
			if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL)
				return (EAGAIN);
			*((int *)(void *)datap->b_wptr) =
			    STATEP->vuid_mouse_mode;
			mcopyout(mp, NULL, size, NULL, datap);
			qreply(qp, mp);

			return (err);
		case VUIDGWHEELINFO:
			size = sizeof (wheel_info);
			break;

		case VUIDSWHEELSTATE:
		case VUIDGWHEELSTATE:
			size = sizeof (wheel_state);
			break;

		case MSIOSRESOLUTION:
			size = sizeof (Ms_screen_resolution);
			break;
		}

		if ((ioctmp = allocb(sizeof (Mouse_iocstate_t),
		    BPRI_MED)) == NULL)
			return (EAGAIN);
		Mouseioc = (void *)ioctmp->b_rptr;
		Mouseioc->ioc_state = GETSTRUCT;
		Mouseioc->u_addr = useraddr;
		ioctmp->b_wptr = ioctmp->b_rptr + sizeof (Mouse_iocstate_t);
		mcopyin(mp, ioctmp, size, NULL);
		qreply(qp, mp);

		return (err);
	} else {
		switch (cmd) {
		case VUIDGWHEELCOUNT:
			if (mp->b_cont) {
				freemsg(mp->b_cont);
				mp->b_cont = NULL;
			}
			if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
				err = EAGAIN;
				break;
			}
			*((int *)(void *)datap->b_wptr) =
			    STATEP->vuid_mouse_mode;
			datap->b_wptr +=  sizeof (int);
			mp->b_cont = datap;
			break;

		case VUIDGWHEELINFO:
			if (mp->b_cont == NULL ||
			    iocbp->ioc_count != sizeof (wheel_info)) {
				err = EINVAL;
				break;
			}
			datap = mp->b_cont;
			err = vuidmice_service_wheel_info(datap);
			break;

		case VUIDSWHEELSTATE:
		case VUIDGWHEELSTATE:
			if (mp->b_cont == NULL ||
			    iocbp->ioc_count != sizeof (wheel_state)) {
				err = EINVAL;
				break;
			}
			datap = mp->b_cont;
			err = vuidmice_service_wheel_state(qp, datap, cmd);
			break;

		case MSIOSRESOLUTION:
			/*
			 * Now we just make Xserver and
			 * the virtual mouse happy. Of course,
			 * the screen resolution value may
			 * be used later for absolute PS/2 mouse.
			 */
			err = 0;
			break;
		}

		if (!err) {
			mp->b_datap->db_type = M_IOCACK;
			iocbp->ioc_rval = 0;
			iocbp->ioc_error = 0;
			qreply(qp, mp);
		}

		return (err);
	}
}

static int
vuidmice_service_wheel_info(register mblk_t *datap)
{
	wheel_info		*wi;
	int			err = 0;

	wi = (void *)datap->b_rptr;
	if (wi->vers != VUID_WHEEL_INFO_VERS) {
		err = EINVAL;
		return (err);
	}

	if (wi->id > (VUIDMICE_NUM_WHEELS - 1)) {
		err = EINVAL;
		return (err);
	}
	wi->format = (wi->id == VUIDMICE_VERTICAL_WHEEL_ID) ?
	    VUID_WHEEL_FORMAT_VERTICAL : VUID_WHEEL_FORMAT_HORIZONTAL;

	return (err);
}


static int
vuidmice_service_wheel_state(register queue_t	*qp,
			    register mblk_t	*datap,
			    register uint_t	cmd)
{
	wheel_state	*ws;
	uint_t		err = 0;

	ws = (void *)datap->b_rptr;
	if (ws->vers != VUID_WHEEL_STATE_VERS) {
		err = EINVAL;
		return (err);
	}

	if (ws->id > (VUIDMICE_NUM_WHEELS - 1)) {
		err = EINVAL;
		return (err);
	}

	switch (cmd) {
	case	VUIDGWHEELSTATE:
		ws->stateflags =
		    (STATEP->wheel_state_bf >> ws->id) & 1;

		break;
	case	VUIDSWHEELSTATE:
		STATEP->wheel_state_bf = (ws->stateflags << ws->id) |
		    (STATEP->wheel_state_bf & ~(1 << ws->id));

		break;
	default:
		err = EINVAL;

		return (err);
	}

	return (err);
}
