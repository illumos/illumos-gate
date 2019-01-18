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
 * Streams log driver.  See log(7D).
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/debug.h>
#include <sys/cred.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <sys/log.h>
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/policy.h>
#include <sys/zone.h>

#include <sys/conf.h>
#include <sys/sunddi.h>

static dev_info_t *log_devi;	/* private copy of devinfo pointer */
int log_msgid;			/* log.conf tunable: enable msgid generation */

/* ARGSUSED */
static int
log_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = log_devi;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = 0;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

/* ARGSUSED */
static int
log_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (ddi_create_minor_node(devi, "conslog", S_IFCHR,
	    LOG_CONSMIN, DDI_PSEUDO, 0) == DDI_FAILURE ||
	    ddi_create_minor_node(devi, "log", S_IFCHR,
	    LOG_LOGMIN, DDI_PSEUDO, 0) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}
	log_devi = devi;
	log_msgid = ddi_getprop(DDI_DEV_T_ANY, log_devi,
	    DDI_PROP_CANSLEEP, "msgid", 1);
	return (DDI_SUCCESS);
}

/*
 * log_open can be called for either /dev/log or dev/conslog.
 *
 * In the /dev/conslog case log_alloc() allocates a new minor device from
 * its cache.
 *
 * In the case of /dev/log, LOG_NUMCLONES devices are pre-allocated at zone
 * creation. log_alloc() finds the zone's next available minor device.
 *
 * On entry devp's minor number indicates which device (log or conslog), on
 * successful return it is the device instance.
 */

/* ARGSUSED */
static int
log_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *cr)
{
	log_t *lp;
	minor_t minor;

	if (sflag & (MODOPEN | CLONEOPEN))
		return (ENXIO);

	switch (minor = getminor(*devp)) {
	case LOG_CONSMIN:		/* clone open of /dev/conslog */
		if (flag & FREAD)
			return (EINVAL);	/* write-only device */
		if (q->q_ptr)
			return (0);
		break;

	case LOG_LOGMIN:		/* clone open of /dev/log */
		break;

	default:
		return (ENXIO);
	}

	lp = log_alloc(minor);
	if (lp == NULL)
		return (ENXIO);
	*devp = makedevice(getmajor(*devp), lp->log_minor);
	q->q_ptr = lp;
	WR(q)->q_ptr = lp;
	lp->log_inuse = 1;
	qprocson(q);

	return (0);
}

/* ARGSUSED */
static int
log_close(queue_t *q, int flag, cred_t *cr)
{
	log_t *lp = (log_t *)q->q_ptr;

	qprocsoff(q);

	lp->log_inuse = 0;
	log_update(lp, NULL, 0, NULL);
	freemsg(lp->log_data);
	lp->log_data = NULL;
	if (lp->log_major == LOG_CONSMIN)
		log_free(lp);
	q->q_ptr = NULL;
	WR(q)->q_ptr = NULL;

	return (0);
}

static int
log_wput(queue_t *q, mblk_t *mp)
{
	log_t *lp = (log_t *)q->q_ptr;
	struct iocblk *iocp;
	mblk_t *mp2;
	cred_t *cr = msg_getcred(mp, NULL);
	zoneid_t zoneid;

	/*
	 * Default to global zone if dblk doesn't have a valid cred.
	 * Calls to syslog() go through putmsg(), which does set up
	 * the cred.
	 */
	zoneid = (cr != NULL) ? crgetzoneid(cr) : GLOBAL_ZONEID;

	switch (DB_TYPE(mp)) {
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			flushq(q, FLUSHALL);
			*mp->b_rptr &= ~FLUSHW;
		}
		if (*mp->b_rptr & FLUSHR) {
			flushq(RD(q), FLUSHALL);
			qreply(q, mp);
			return (0);
		}
		break;

	case M_IOCTL:
		iocp = (struct iocblk *)mp->b_rptr;

		if (lp->log_major != LOG_LOGMIN) {
			/* write-only device */
			miocnak(q, mp, 0, EINVAL);
			return (0);
		}

		if (iocp->ioc_count == TRANSPARENT) {
			miocnak(q, mp, 0, EINVAL);
			return (0);
		}

		if (lp->log_flags) {
			miocnak(q, mp, 0, EBUSY);
			return (0);
		}

		freemsg(lp->log_data);
		lp->log_data = mp->b_cont;
		mp->b_cont = NULL;

		switch (iocp->ioc_cmd) {

		case I_CONSLOG:
			log_update(lp, RD(q), SL_CONSOLE, log_console);
			break;

		case I_TRCLOG:
			if (lp->log_data == NULL) {
				miocnak(q, mp, 0, EINVAL);
				return (0);
			}
			log_update(lp, RD(q), SL_TRACE, log_trace);
			break;

		case I_ERRLOG:
			log_update(lp, RD(q), SL_ERROR, log_error);
			break;

		default:
			miocnak(q, mp, 0, EINVAL);
			return (0);
		}
		miocack(q, mp, 0, 0);
		return (0);

	case M_PROTO:
		if (MBLKL(mp) == sizeof (log_ctl_t) && mp->b_cont != NULL) {
			log_ctl_t *lc = (log_ctl_t *)mp->b_rptr;
			/* This code is used by savecore to log dump msgs */
			if (mp->b_band != 0 &&
			    secpolicy_sys_config(CRED(), B_FALSE) == 0) {
				(void) putq(log_consq, mp);
				return (0);
			}
			if ((lc->pri & LOG_FACMASK) == LOG_KERN)
				lc->pri |= LOG_USER;
			mp2 = log_makemsg(LOG_MID, LOG_CONSMIN, lc->level,
			    lc->flags, lc->pri, mp->b_cont->b_rptr,
			    MBLKL(mp->b_cont) + 1, 0);
			if (mp2 != NULL)
				log_sendmsg(mp2, zoneid);
		}
		break;

	case M_DATA:
		mp2 = log_makemsg(LOG_MID, LOG_CONSMIN, 0, SL_CONSOLE,
		    LOG_USER | LOG_INFO, mp->b_rptr, MBLKL(mp) + 1, 0);
		if (mp2 != NULL)
			log_sendmsg(mp2, zoneid);
		break;
	}

	freemsg(mp);
	return (0);
}

static int
log_rsrv(queue_t *q)
{
	mblk_t *mp;
	char *msg, *msgid_start, *msgid_end;
	size_t idlen;

	while (canputnext(q) && (mp = getq(q)) != NULL) {
		if (log_msgid == 0) {
			/*
			 * Strip out the message ID.  If it's a kernel
			 * SL_CONSOLE message, replace msgid with "unix: ".
			 */
			msg = (char *)mp->b_cont->b_rptr;
			if ((msgid_start = strstr(msg, "[ID ")) != NULL &&
			    (msgid_end = strstr(msgid_start, "] ")) != NULL) {
				log_ctl_t *lc = (log_ctl_t *)mp->b_rptr;
				if ((lc->flags & SL_CONSOLE) &&
				    (lc->pri & LOG_FACMASK) == LOG_KERN)
					msgid_start = msg + snprintf(msg,
					    7, "unix: ");
				idlen = msgid_end + 2 - msgid_start;
				ovbcopy(msg, msg + idlen, msgid_start - msg);
				mp->b_cont->b_rptr += idlen;
			}
		}
		mp->b_band = 0;
		putnext(q, mp);
	}
	return (0);
}

static struct module_info logm_info =
	{ LOG_MID, "LOG", LOG_MINPS, LOG_MAXPS, LOG_HIWAT, LOG_LOWAT };

static struct qinit logrinit =
	{ NULL, log_rsrv, log_open, log_close, NULL, &logm_info, NULL };

static struct qinit logwinit =
	{ log_wput, NULL, NULL, NULL, NULL, &logm_info, NULL };

static struct streamtab loginfo = { &logrinit, &logwinit, NULL, NULL };

DDI_DEFINE_STREAM_OPS(log_ops, nulldev, nulldev, log_attach, nodev,
    nodev, log_info, D_NEW | D_MP | D_MTPERMOD, &loginfo,
    ddi_quiesce_not_needed);

static struct modldrv modldrv =
	{ &mod_driverops, "streams log driver", &log_ops };

static struct modlinkage modlinkage = { MODREV_1, (void *)&modldrv, NULL };

int
_init()
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
