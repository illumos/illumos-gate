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
 * Standard module for handling DLPI Style 2 attach/detach
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/strsubr.h>
#include <sys/ddi.h>
#include <sys/dlpi.h>
#include <sys/strsun.h>
#include <sys/policy.h>

static struct streamtab drstab;

static struct fmodsw fsw = {
	DRMODNAME,
	&drstab,
	D_MP
};


/*
 * Module linkage information for the kernel.
 */

static struct modlstrmod modlstrmod = {
	&mod_strmodops, "dr compatibility for DLPI style 2 drivers", &fsw
};


static struct modlinkage modlinkage = {
	MODREV_1, &modlstrmod, NULL
};


int
_init(void)
{
	return (mod_install(&modlinkage));
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


static int	dropen(queue_t *, dev_t *, int, int, cred_t *);
static int	drclose(queue_t *, int, cred_t *);
static int	drrput(queue_t *, mblk_t *);
static int	drwput(queue_t *, mblk_t *);

static struct module_info drinfo = {
	0,
	DRMODNAME,
	0,
	INFPSZ,
	1,
	0
};

static struct qinit drrinit = {
	(int (*)())drrput,
	NULL,
	dropen,
	drclose,
	NULL,
	&drinfo
};

static struct qinit drwinit = {
	(int (*)())drwput,
	NULL,
	NULL,
	NULL,
	NULL,
	&drinfo
};

static struct streamtab drstab = {
	&drrinit,
	&drwinit,
	NULL,
	NULL
};

/*
 * This module is pushed directly on top of the bottom driver
 * in a DLPI style-2 stream by stropen(). It intercepts
 * DL_ATTACH_REQ/DL_DETACH_REQ messages on the write side
 * and acks on the read side, calls qassociate where needed.
 * The primary purpose is to workaround a DR race condition
 * affecting non-DDI compliant DLPI style 2 drivers, which may
 * cause the system to panic.
 *
 * The following action is taken:
 * Write side (drwput):
 *	attach request:	hold driver instance assuming ppa == instance.
 *		This way, the instance cannot be detached while the
 *		driver is processing DL_ATTACH_REQ.
 *
 *		On a successful hold, store the dip in a ring buffer
 *		to be processed lated by the read side.
 *		If hold fails (most likely ppa != instance), we store
 *		NULL in the ring buffer and read side won't take
 *		any action on ack.
 *
 * Read side (drrput):
 *	attach success: if (dip held on write side) associate queue with dip
 *	attach failure:	if (dip held on write side) release hold on dip
 *	detach success: associate queue with NULL
 *	detach failure:	do nothing
 *
 * The module assumes that incoming DL_ATTACH_REQ/DL_DETACH_REQ
 * messages are ordered (non-concurrent) and the bottom
 * driver processes them and sends acknowledgements in the same
 * order. This assumption is reasonable because concurrent
 * association results in non-deterministic queue behavior.
 * The module is coded carefully such that unordered messages
 * do not result in a system panic.
 *
 * The module handles multiple outstanding messages queued
 * in the bottom driver. Messages processed on the write side
 * but not yet arrived at read side are placed in the ring buffer
 * dr_dip[], between dr_nfirst and dr_nlast. The write side is
 * producer and the read side is the consumer. The buffer is full
 * when dr_nfirst == dr_nlast.
 *
 * The current size of the ring buffer is 64 (MAX_DLREQS) per stream.
 * During normal testing, we have not seen outstanding messages
 * above 10.
 */

#define	MAX_DLREQS	64
#define	INCR(x)		{(x)++; if ((x) >= MAX_DLREQS) (x) = 0; }

struct drstate {
	kmutex_t dr_lock;
	major_t dr_major;
	int dr_nfirst;
	int dr_nlast;
	dev_info_t *dr_dip[MAX_DLREQS];
};

/* ARGSUSED1 */
static int
dropen(queue_t *q, dev_t *devp, int oflag, int sflag, cred_t *crp)
{
	struct drstate *dsp;

	if (sflag != MODOPEN) {	/* must be a pushed module */
		return (EINVAL);
	}

	if (secpolicy_net_rawaccess(crp) != 0) {
		return (EPERM);
	}

	if (q->q_ptr != NULL) {
		return (0);	/* already open */
	}

	dsp = kmem_zalloc(sizeof (*dsp), KM_SLEEP);
	dsp->dr_major = getmajor(*devp);
	mutex_init(&dsp->dr_lock, NULL, MUTEX_DEFAULT, NULL);
	q->q_ptr = OTHERQ(q)->q_ptr = dsp;
	qprocson(q);
	ddi_assoc_queue_with_devi(q, NULL);
	return (0);
}

/* ARGSUSED1 */
static int
drclose(queue_t *q, int cflag, cred_t *crp)
{
	struct drstate *dsp = q->q_ptr;

	ASSERT(dsp);
	ddi_assoc_queue_with_devi(q, NULL);
	qprocsoff(q);

	mutex_destroy(&dsp->dr_lock);
	kmem_free(dsp, sizeof (*dsp));
	q->q_ptr = NULL;

	return (0);
}

static int
drrput(queue_t *q, mblk_t *mp)
{
	struct drstate *dsp;
	union DL_primitives *dlp;
	dev_info_t *dip;

	switch (DB_TYPE(mp)) {
	case M_PROTO:
	case M_PCPROTO:
		break;
	default:
		putnext(q, mp);
		return (0);
	}

	/* make sure size is sufficient for dl_primitive */
	if (MBLKL(mp) < sizeof (t_uscalar_t)) {
		putnext(q, mp);
		return (0);
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	switch (dlp->dl_primitive) {
	case DL_OK_ACK: {
		/* check for proper size, let upper layer deal with error */
		if (MBLKL(mp) < DL_OK_ACK_SIZE) {
			putnext(q, mp);
			return (0);
		}

		dsp = q->q_ptr;
		switch (dlp->ok_ack.dl_correct_primitive) {
		case DL_ATTACH_REQ:
			/*
			 * ddi_assoc_queue_with_devi() will hold dip,
			 * so release after association.
			 *
			 * dip is NULL means we didn't hold dip on read side.
			 * (unlikely, but possible), so we do nothing.
			 */
			mutex_enter(&dsp->dr_lock);
			dip = dsp->dr_dip[dsp->dr_nlast];
			dsp->dr_dip[dsp->dr_nlast] = NULL;
			INCR(dsp->dr_nlast);
			mutex_exit(&dsp->dr_lock);
			if (dip) {
				ddi_assoc_queue_with_devi(q, dip);
				ddi_release_devi(dip);
			}
			break;

		case DL_DETACH_REQ:
			ddi_assoc_queue_with_devi(q, NULL);
			break;
		default:
			break;
		}
		break;
	}
	case DL_ERROR_ACK:
		if (dlp->error_ack.dl_error_primitive != DL_ATTACH_REQ)
			break;

		dsp = q->q_ptr;
		mutex_enter(&dsp->dr_lock);
		dip = dsp->dr_dip[dsp->dr_nlast];
		dsp->dr_dip[dsp->dr_nlast] = NULL;
		INCR(dsp->dr_nlast);
		mutex_exit(&dsp->dr_lock);
		/*
		 * Release dip on attach failure
		 */
		if (dip) {
			ddi_release_devi(dip);
		}
		break;
	default:
		break;
	}

	putnext(q, mp);
	return (0);
}

/*
 * Detect dl attach, hold the dip to prevent it from detaching
 */
static int
drwput(queue_t *q, mblk_t *mp)
{
	struct drstate *dsp;
	union DL_primitives *dlp;
	dev_info_t *dip;

	switch (DB_TYPE(mp)) {
	case M_PROTO:
	case M_PCPROTO:
		break;
	default:
		putnext(q, mp);
		return (0);
	}

	/* make sure size is sufficient for dl_primitive */
	if (MBLKL(mp) < sizeof (t_uscalar_t)) {
		putnext(q, mp);
		return (0);
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	switch (dlp->dl_primitive) {
	case DL_ATTACH_REQ:
		/*
		 * Check for proper size of the message.
		 *
		 * If size is correct, get the ppa and attempt to
		 * hold the device assuming ppa is instance.
		 *
		 * If size is wrong, we can't get the ppa, but
		 * still increment dr_nfirst because the read side
		 * will get a error ack on DL_ATTACH_REQ.
		 */
		dip = NULL;
		dsp = q->q_ptr;
		if (MBLKL(mp) >= DL_OK_ACK_SIZE) {
			dip = ddi_hold_devi_by_instance(dsp->dr_major,
			    dlp->attach_req.dl_ppa, E_DDI_HOLD_DEVI_NOATTACH);
		}

		mutex_enter(&dsp->dr_lock);
		dsp->dr_dip[dsp->dr_nfirst] = dip;
		INCR(dsp->dr_nfirst);
		/*
		 * Check if ring buffer is full. If so, assert in debug
		 * kernel and produce a warning in non-debug kernel.
		 */
		ASSERT(dsp->dr_nfirst != dsp->dr_nlast);
		if (dsp->dr_nfirst == dsp->dr_nlast) {
			cmn_err(CE_WARN, "drcompat: internal buffer full");
		}
		mutex_exit(&dsp->dr_lock);
		break;
	default:
		break;
	}

	putnext(q, mp);
	return (0);
}
