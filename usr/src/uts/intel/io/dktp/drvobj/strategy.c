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
 *	Device Strategy
 */
#include <sys/dktp/cm.h>
#include <sys/kstat.h>

#include <sys/dktp/quetypes.h>
#include <sys/dktp/queue.h>
#include <sys/dktp/tgcom.h>
#include <sys/dktp/fctypes.h>
#include <sys/dktp/flowctrl.h>
#include <sys/param.h>
#include <vm/page.h>
#include <sys/modctl.h>

/*
 *	Object Management
 */

static struct buf *qmerge_nextbp(struct que_data *qfp, struct buf *bp_merge,
    int *can_merge);

static struct modlmisc modlmisc = {
	&mod_miscops,	/* Type of module */
	"Device Strategy Objects"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlmisc,
	NULL
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


/*
 *	Common Flow Control functions
 */

/*
 * Local static data
 */
#ifdef	FLC_DEBUG
#define	DENT	0x0001
#define	DERR	0x0002
#define	DIO	0x0004
static	int	flc_debug = DENT|DERR|DIO;

#include <sys/thread.h>
static 	int	flc_malloc_intr = 0;
#endif	/* FLC_DEBUG */

static	int	flc_kstat = 1;

static struct flc_obj *fc_create(struct flc_objops *fcopsp);
static int fc_init(opaque_t queuep, opaque_t tgcom_objp, opaque_t que_objp,
    void *lkarg);
static int fc_free(struct flc_obj *flcobjp);
static int fc_start_kstat(opaque_t queuep, char *devtype, int instance);
static int fc_stop_kstat(opaque_t queuep);

static struct flc_obj *
fc_create(struct flc_objops *fcopsp)
{
	struct	flc_obj *flcobjp;
	struct	fc_data *fcdp;

	flcobjp = kmem_zalloc((sizeof (*flcobjp) + sizeof (*fcdp)), KM_NOSLEEP);
	if (!flcobjp)
		return (NULL);

	fcdp = (struct fc_data *)(flcobjp+1);
	flcobjp->flc_data = (opaque_t)fcdp;
	flcobjp->flc_ops  = fcopsp;

	return ((opaque_t)flcobjp);
}

static int dmult_maxcnt = DMULT_MAXCNT;

static int
fc_init(opaque_t queuep, opaque_t tgcom_objp, opaque_t que_objp, void *lkarg)
{
	struct fc_data *fcdp = (struct fc_data *)queuep;

	mutex_init(&fcdp->ds_mutex, NULL, MUTEX_DRIVER, lkarg);

	fcdp->ds_queobjp   = que_objp;
	fcdp->ds_tgcomobjp = tgcom_objp;
	fcdp->ds_waitcnt   = dmult_maxcnt;

	QUE_INIT(que_objp, lkarg);
	TGCOM_INIT(tgcom_objp);
	return (DDI_SUCCESS);
}

static int
fc_free(struct flc_obj *flcobjp)
{
	struct fc_data *fcdp;

	fcdp = (struct fc_data *)flcobjp->flc_data;
	if (fcdp->ds_queobjp)
		QUE_FREE(fcdp->ds_queobjp);
	if (fcdp->ds_tgcomobjp) {
		TGCOM_FREE(fcdp->ds_tgcomobjp);
		mutex_destroy(&fcdp->ds_mutex);
	}
	kmem_free(flcobjp, (sizeof (*flcobjp) + sizeof (*fcdp)));
	return (0);
}

/*ARGSUSED*/
static int
fc_start_kstat(opaque_t queuep, char *devtype, int instance)
{
	struct fc_data *fcdp = (struct fc_data *)queuep;
	if (!flc_kstat)
		return (0);

	if (!fcdp->ds_kstat) {
		if (fcdp->ds_kstat = kstat_create("cmdk", instance, NULL,
		    "disk", KSTAT_TYPE_IO, 1, KSTAT_FLAG_PERSISTENT)) {
			kstat_install(fcdp->ds_kstat);
		}
	}
	return (0);
}

static int
fc_stop_kstat(opaque_t queuep)
{
	struct fc_data *fcdp = (struct fc_data *)queuep;

	if (fcdp->ds_kstat) {
		kstat_delete(fcdp->ds_kstat);
		fcdp->ds_kstat = NULL;
	}
	return (0);
}


/*
 *	Single Command per Device
 */
/*
 * Local Function Prototypes
 */
static int dsngl_restart();

static int dsngl_enque(opaque_t, struct buf *);
static int dsngl_deque(opaque_t, struct buf *);

struct 	flc_objops dsngl_ops = {
	fc_init,
	fc_free,
	dsngl_enque,
	dsngl_deque,
	fc_start_kstat,
	fc_stop_kstat,
	0, 0
};

struct flc_obj *
dsngl_create()
{
	return (fc_create((struct flc_objops *)&dsngl_ops));
}

static int
dsngl_enque(opaque_t queuep, struct buf *in_bp)
{
	struct fc_data *dsnglp = (struct fc_data *)queuep;
	opaque_t tgcom_objp;
	opaque_t que_objp;

	que_objp   = dsnglp->ds_queobjp;
	tgcom_objp = dsnglp->ds_tgcomobjp;

	if (!in_bp)
		return (0);
	mutex_enter(&dsnglp->ds_mutex);
	if (dsnglp->ds_bp || dsnglp->ds_outcnt) {
		QUE_ADD(que_objp, in_bp);
		if (dsnglp->ds_kstat) {
			kstat_waitq_enter(KSTAT_IO_PTR(dsnglp->ds_kstat));
		}
		mutex_exit(&dsnglp->ds_mutex);
		return (0);
	}
	if (dsnglp->ds_kstat) {
		kstat_waitq_enter(KSTAT_IO_PTR(dsnglp->ds_kstat));
	}
	if (TGCOM_PKT(tgcom_objp, in_bp, dsngl_restart,
	    (caddr_t)dsnglp) != DDI_SUCCESS) {

		dsnglp->ds_bp = in_bp;
		mutex_exit(&dsnglp->ds_mutex);
		return (0);
	}
	dsnglp->ds_outcnt++;
	if (dsnglp->ds_kstat)
		kstat_waitq_to_runq(KSTAT_IO_PTR(dsnglp->ds_kstat));
	mutex_exit(&dsnglp->ds_mutex);
	TGCOM_TRANSPORT(tgcom_objp, in_bp);
	return (0);
}

static int
dsngl_deque(opaque_t queuep, struct buf *in_bp)
{
	struct fc_data *dsnglp = (struct fc_data *)queuep;
	opaque_t tgcom_objp;
	opaque_t que_objp;
	struct	 buf *bp;

	que_objp   = dsnglp->ds_queobjp;
	tgcom_objp = dsnglp->ds_tgcomobjp;

	mutex_enter(&dsnglp->ds_mutex);
	if (in_bp) {
		dsnglp->ds_outcnt--;
		if (dsnglp->ds_kstat) {
			if (in_bp->b_flags & B_READ) {
				KSTAT_IO_PTR(dsnglp->ds_kstat)->reads++;
				KSTAT_IO_PTR(dsnglp->ds_kstat)->nread +=
				    (in_bp->b_bcount - in_bp->b_resid);
			} else {
				KSTAT_IO_PTR(dsnglp->ds_kstat)->writes++;
				KSTAT_IO_PTR(dsnglp->ds_kstat)->nwritten +=
				    (in_bp->b_bcount - in_bp->b_resid);
			}
			kstat_runq_exit(KSTAT_IO_PTR(dsnglp->ds_kstat));
		}
	}
	for (;;) {
		if (!dsnglp->ds_bp)
			dsnglp->ds_bp = QUE_DEL(que_objp);
		if (!dsnglp->ds_bp ||
		    (TGCOM_PKT(tgcom_objp, dsnglp->ds_bp, dsngl_restart,
		    (caddr_t)dsnglp) != DDI_SUCCESS) ||
		    dsnglp->ds_outcnt) {
			mutex_exit(&dsnglp->ds_mutex);
			return (0);
		}
		dsnglp->ds_outcnt++;
		bp = dsnglp->ds_bp;
		dsnglp->ds_bp = QUE_DEL(que_objp);
		if (dsnglp->ds_kstat)
			kstat_waitq_to_runq(KSTAT_IO_PTR(dsnglp->ds_kstat));
		mutex_exit(&dsnglp->ds_mutex);

		TGCOM_TRANSPORT(tgcom_objp, bp);

		if (!mutex_tryenter(&dsnglp->ds_mutex))
			return (0);
	}
}

static int
dsngl_restart(struct fc_data *dsnglp)
{
	(void) dsngl_deque(dsnglp, NULL);
	return (-1);
}


/*
 *	Multiple Commands per Device
 */
/*
 * Local Function Prototypes
 */
static int dmult_restart();

static int dmult_enque(opaque_t, struct buf *);
static int dmult_deque(opaque_t, struct buf *);

struct 	flc_objops dmult_ops = {
	fc_init,
	fc_free,
	dmult_enque,
	dmult_deque,
	fc_start_kstat,
	fc_stop_kstat,
	0, 0
};

struct flc_obj *
dmult_create()
{
	return (fc_create((struct flc_objops *)&dmult_ops));

}


/*
 * Some of the object management functions QUE_ADD() and QUE_DEL()
 * do not accquire lock.
 * They depend on dmult_enque(), dmult_deque() to do all locking.
 * If this changes we have to grab locks in qmerge_add() and qmerge_del().
 */
static int
dmult_enque(opaque_t queuep, struct buf *in_bp)
{
	struct fc_data *dmultp = (struct fc_data *)queuep;
	opaque_t tgcom_objp;
	opaque_t que_objp;

	que_objp   = dmultp->ds_queobjp;
	tgcom_objp = dmultp->ds_tgcomobjp;

	if (!in_bp)
		return (0);
	mutex_enter(&dmultp->ds_mutex);
	if ((dmultp->ds_outcnt >= dmultp->ds_waitcnt) || dmultp->ds_bp) {
		QUE_ADD(que_objp, in_bp);
		if (dmultp->ds_kstat) {
			kstat_waitq_enter(KSTAT_IO_PTR(dmultp->ds_kstat));
		}
		mutex_exit(&dmultp->ds_mutex);
		return (0);
	}
	if (dmultp->ds_kstat) {
		kstat_waitq_enter(KSTAT_IO_PTR(dmultp->ds_kstat));
	}

	if (TGCOM_PKT(tgcom_objp, in_bp, dmult_restart,
	    (caddr_t)dmultp) != DDI_SUCCESS) {

		dmultp->ds_bp = in_bp;
		mutex_exit(&dmultp->ds_mutex);
		return (0);
	}
	dmultp->ds_outcnt++;
	if (dmultp->ds_kstat)
		kstat_waitq_to_runq(KSTAT_IO_PTR(dmultp->ds_kstat));
	mutex_exit(&dmultp->ds_mutex);

	TGCOM_TRANSPORT(tgcom_objp, in_bp);
	return (0);
}

static int
dmult_deque(opaque_t queuep, struct buf *in_bp)
{
	struct fc_data *dmultp = (struct fc_data *)queuep;
	opaque_t tgcom_objp;
	opaque_t que_objp;
	struct	 buf *bp;

	que_objp = dmultp->ds_queobjp;
	tgcom_objp = dmultp->ds_tgcomobjp;

	mutex_enter(&dmultp->ds_mutex);
	if (in_bp) {
		dmultp->ds_outcnt--;
		if (dmultp->ds_kstat) {
			if (in_bp->b_flags & B_READ) {
				KSTAT_IO_PTR(dmultp->ds_kstat)->reads++;
				KSTAT_IO_PTR(dmultp->ds_kstat)->nread +=
				    (in_bp->b_bcount - in_bp->b_resid);
			} else {
				KSTAT_IO_PTR(dmultp->ds_kstat)->writes++;
				KSTAT_IO_PTR(dmultp->ds_kstat)->nwritten +=
				    (in_bp->b_bcount - in_bp->b_resid);
			}
			kstat_runq_exit(KSTAT_IO_PTR(dmultp->ds_kstat));
		}
	}

	for (;;) {

#ifdef	FLC_DEBUG
		if ((curthread->t_intr) && (!dmultp->ds_bp) &&
		    (!dmultp->ds_outcnt))
			flc_malloc_intr++;
#endif

		if (!dmultp->ds_bp)
			dmultp->ds_bp = QUE_DEL(que_objp);
		if (!dmultp->ds_bp ||
		    (TGCOM_PKT(tgcom_objp, dmultp->ds_bp, dmult_restart,
		    (caddr_t)dmultp) != DDI_SUCCESS) ||
		    (dmultp->ds_outcnt >= dmultp->ds_waitcnt)) {
			mutex_exit(&dmultp->ds_mutex);
			return (0);
		}
		dmultp->ds_outcnt++;
		bp = dmultp->ds_bp;
		dmultp->ds_bp = QUE_DEL(que_objp);

		if (dmultp->ds_kstat)
			kstat_waitq_to_runq(KSTAT_IO_PTR(dmultp->ds_kstat));

		mutex_exit(&dmultp->ds_mutex);

		TGCOM_TRANSPORT(tgcom_objp, bp);

		if (!mutex_tryenter(&dmultp->ds_mutex))
			return (0);
	}
}

static int
dmult_restart(struct fc_data *dmultp)
{
	(void) dmult_deque(dmultp, NULL);
	return (-1);
}

/*
 *	Duplexed Commands per Device: Read Queue and Write Queue
 */
/*
 * Local Function Prototypes
 */
static int duplx_restart();

static int duplx_init(opaque_t queuep, opaque_t tgcom_objp, opaque_t que_objp,
    void *lkarg);
static int duplx_free(struct flc_obj *flcobjp);
static int duplx_enque(opaque_t queuep, struct buf *bp);
static int duplx_deque(opaque_t queuep, struct buf *bp);

struct 	flc_objops duplx_ops = {
	duplx_init,
	duplx_free,
	duplx_enque,
	duplx_deque,
	fc_start_kstat,
	fc_stop_kstat,
	0, 0
};

struct flc_obj *
duplx_create()
{
	struct	flc_obj *flcobjp;
	struct	duplx_data *fcdp;

	flcobjp = kmem_zalloc((sizeof (*flcobjp) + sizeof (*fcdp)), KM_NOSLEEP);
	if (!flcobjp)
		return (NULL);

	fcdp = (struct duplx_data *)(flcobjp+1);
	flcobjp->flc_data = (opaque_t)fcdp;
	flcobjp->flc_ops  = &duplx_ops;

	fcdp->ds_writeq.fc_qobjp = qfifo_create();
	if (!(fcdp->ds_writeq.fc_qobjp = qfifo_create())) {
		kmem_free(flcobjp, (sizeof (*flcobjp) + sizeof (*fcdp)));
		return (NULL);
	}
	return (flcobjp);
}

static int
duplx_free(struct flc_obj *flcobjp)
{
	struct duplx_data *fcdp;

	fcdp = (struct duplx_data *)flcobjp->flc_data;
	if (fcdp->ds_writeq.fc_qobjp) {
		QUE_FREE(fcdp->ds_writeq.fc_qobjp);
	}
	if (fcdp->ds_readq.fc_qobjp)
		QUE_FREE(fcdp->ds_readq.fc_qobjp);
	if (fcdp->ds_tgcomobjp) {
		TGCOM_FREE(fcdp->ds_tgcomobjp);
		mutex_destroy(&fcdp->ds_mutex);
	}
	kmem_free(flcobjp, (sizeof (*flcobjp) + sizeof (*fcdp)));
	return (0);
}

static int
duplx_init(opaque_t queuep, opaque_t tgcom_objp, opaque_t que_objp, void *lkarg)
{
	struct duplx_data *fcdp = (struct duplx_data *)queuep;
	fcdp->ds_tgcomobjp = tgcom_objp;
	fcdp->ds_readq.fc_qobjp = que_objp;

	QUE_INIT(que_objp, lkarg);
	QUE_INIT(fcdp->ds_writeq.fc_qobjp, lkarg);
	TGCOM_INIT(tgcom_objp);

	mutex_init(&fcdp->ds_mutex, NULL, MUTEX_DRIVER, lkarg);

	fcdp->ds_writeq.fc_maxcnt = DUPLX_MAXCNT;
	fcdp->ds_readq.fc_maxcnt  = DUPLX_MAXCNT;

	/* queues point to each other for round robin */
	fcdp->ds_readq.next = &fcdp->ds_writeq;
	fcdp->ds_writeq.next = &fcdp->ds_readq;

	return (DDI_SUCCESS);
}

static int
duplx_enque(opaque_t queuep, struct buf *in_bp)
{
	struct duplx_data *duplxp = (struct duplx_data *)queuep;
	opaque_t tgcom_objp;
	struct fc_que *activeq;
	struct buf *bp;

	mutex_enter(&duplxp->ds_mutex);
	if (in_bp) {
		if (duplxp->ds_kstat) {
			kstat_waitq_enter(KSTAT_IO_PTR(duplxp->ds_kstat));
		}
		if (in_bp->b_flags & B_READ)
			activeq = &duplxp->ds_readq;
		else
			activeq = &duplxp->ds_writeq;

		QUE_ADD(activeq->fc_qobjp, in_bp);
	} else {
		activeq = &duplxp->ds_readq;
	}

	tgcom_objp = duplxp->ds_tgcomobjp;

	for (;;) {
		if (!activeq->fc_bp)
			activeq->fc_bp = QUE_DEL(activeq->fc_qobjp);
		if (!activeq->fc_bp ||
		    (TGCOM_PKT(tgcom_objp, activeq->fc_bp, duplx_restart,
		    (caddr_t)duplxp) != DDI_SUCCESS) ||
		    (activeq->fc_outcnt >= activeq->fc_maxcnt)) {

			/* switch read/write queues */
			activeq = activeq->next;
			if (!activeq->fc_bp)
				activeq->fc_bp = QUE_DEL(activeq->fc_qobjp);
			if (!activeq->fc_bp ||
			    (TGCOM_PKT(tgcom_objp, activeq->fc_bp,
			    duplx_restart, (caddr_t)duplxp) != DDI_SUCCESS) ||
			    (activeq->fc_outcnt >= activeq->fc_maxcnt)) {
				mutex_exit(&duplxp->ds_mutex);
				return (0);
			}
		}

		activeq->fc_outcnt++;
		bp = activeq->fc_bp;
		activeq->fc_bp = NULL;

		if (duplxp->ds_kstat)
			kstat_waitq_to_runq(KSTAT_IO_PTR(duplxp->ds_kstat));
		mutex_exit(&duplxp->ds_mutex);

		TGCOM_TRANSPORT(tgcom_objp, bp);

		if (!mutex_tryenter(&duplxp->ds_mutex))
			return (0);

		activeq = activeq->next;
	}
}

static int
duplx_deque(opaque_t queuep, struct buf *in_bp)
{
	struct duplx_data *duplxp = (struct duplx_data *)queuep;
	opaque_t tgcom_objp;
	struct fc_que *activeq;
	struct buf *bp;

	mutex_enter(&duplxp->ds_mutex);

	tgcom_objp = duplxp->ds_tgcomobjp;

	if (in_bp->b_flags & B_READ)
		activeq = &duplxp->ds_readq;
	else
		activeq = &duplxp->ds_writeq;
	activeq->fc_outcnt--;

	if (duplxp->ds_kstat) {
		if (in_bp->b_flags & B_READ) {
			KSTAT_IO_PTR(duplxp->ds_kstat)->reads++;
			KSTAT_IO_PTR(duplxp->ds_kstat)->nread +=
			    (in_bp->b_bcount - in_bp->b_resid);
		} else {
			KSTAT_IO_PTR(duplxp->ds_kstat)->writes++;
			KSTAT_IO_PTR(duplxp->ds_kstat)->nwritten +=
			    (in_bp->b_bcount - in_bp->b_resid);
		}
		kstat_runq_exit(KSTAT_IO_PTR(duplxp->ds_kstat));
	}

	for (;;) {

		/* if needed, try to pull request off a queue */
		if (!activeq->fc_bp)
			activeq->fc_bp = QUE_DEL(activeq->fc_qobjp);

		if (!activeq->fc_bp ||
		    (TGCOM_PKT(tgcom_objp, activeq->fc_bp, duplx_restart,
		    (caddr_t)duplxp) != DDI_SUCCESS) ||
		    (activeq->fc_outcnt >= activeq->fc_maxcnt)) {

			activeq = activeq->next;
			if (!activeq->fc_bp)
				activeq->fc_bp = QUE_DEL(activeq->fc_qobjp);

			if (!activeq->fc_bp ||
			    (TGCOM_PKT(tgcom_objp, activeq->fc_bp,
			    duplx_restart, (caddr_t)duplxp) != DDI_SUCCESS) ||
			    (activeq->fc_outcnt >= activeq->fc_maxcnt)) {
				mutex_exit(&duplxp->ds_mutex);
				return (0);
			}
		}

		activeq->fc_outcnt++;
		bp = activeq->fc_bp;
		activeq->fc_bp = NULL;

		if (duplxp->ds_kstat)
			kstat_waitq_to_runq(KSTAT_IO_PTR(duplxp->ds_kstat));

		mutex_exit(&duplxp->ds_mutex);

		TGCOM_TRANSPORT(tgcom_objp, bp);

		if (!mutex_tryenter(&duplxp->ds_mutex))
			return (0);

		activeq = activeq->next;
	}
}

static int
duplx_restart(struct duplx_data *duplxp)
{
	(void) duplx_enque(duplxp, NULL);
	return (-1);
}

/*
 *	Tagged queueing flow control
 */
/*
 * Local Function Prototypes
 */

struct 	flc_objops adapt_ops = {
	fc_init,
	fc_free,
	dmult_enque,
	dmult_deque,
	fc_start_kstat,
	fc_stop_kstat,
	0, 0
};

struct flc_obj *
adapt_create()
{
	return (fc_create((struct flc_objops *)&adapt_ops));

}

/*
 *	Common Queue functions
 */

/*
 * 	Local static data
 */
#ifdef	Q_DEBUG
#define	DENT	0x0001
#define	DERR	0x0002
#define	DIO	0x0004
static	int	que_debug = DENT|DERR|DIO;

#endif	/* Q_DEBUG */
/*
 * 	Local Function Prototypes
 */
static struct que_obj *que_create(struct que_objops *qopsp);
static int que_init(struct que_data *qfp, void *lkarg);
static int que_free(struct que_obj *queobjp);
static struct buf *que_del(struct que_data *qfp);

static struct que_obj *
que_create(struct que_objops *qopsp)
{
	struct	que_data *qfp;
	struct	que_obj *queobjp;

	queobjp = kmem_zalloc((sizeof (*queobjp) + sizeof (*qfp)), KM_NOSLEEP);
	if (!queobjp)
		return (NULL);

	queobjp->que_ops = qopsp;
	qfp = (struct que_data *)(queobjp+1);
	queobjp->que_data = (opaque_t)qfp;

	return ((opaque_t)queobjp);
}

static int
que_init(struct que_data *qfp, void *lkarg)
{
	mutex_init(&qfp->q_mutex, NULL, MUTEX_DRIVER, lkarg);
	return (DDI_SUCCESS);
}

static int
que_free(struct que_obj *queobjp)
{
	struct	que_data *qfp;

	qfp = (struct que_data *)queobjp->que_data;
	mutex_destroy(&qfp->q_mutex);
	kmem_free(queobjp, (sizeof (*queobjp) + sizeof (struct que_data)));
	return (0);
}

static struct buf *
que_del(struct que_data *qfp)
{
	struct buf *bp;

	bp = qfp->q_tab.b_actf;
	if (bp) {
		qfp->q_tab.b_actf = bp->av_forw;
		if (!qfp->q_tab.b_actf)
			qfp->q_tab.b_actl = NULL;
		bp->av_forw = 0;
	}
	return (bp);
}



/*
 *	Qmerge
 * 	Local Function Prototypes
 */
static int qmerge_add(), qmerge_free();
static struct buf *qmerge_del(struct que_data *qfp);

struct 	que_objops qmerge_ops = {
	que_init,
	qmerge_free,
	qmerge_add,
	qmerge_del,
	0, 0
};

/* fields in diskhd */
#define	hd_cnt			b_back
#define	hd_private		b_forw
#define	hd_flags		b_flags
#define	hd_sync_next		av_forw
#define	hd_async_next		av_back

#define	hd_sync2async		sync_async_ratio

#define	QNEAR_FORWARD		0x01
#define	QNEAR_BACKWARD		0x02
#define	QNEAR_ASYNCONLY		0x04
#define	QNEAR_ASYNCALSO		0x08

#define	DBLK(bp) ((unsigned long)(bp)->b_private)

#define	BP_LT_BP(a, b) (DBLK(a) < DBLK(b))
#define	BP_GT_BP(a, b) (DBLK(a) > DBLK(b))
#define	BP_LT_HD(a, b) (DBLK(a) < (unsigned long)((b)->hd_private))
#define	BP_GT_HD(a, b) (DBLK(a) > (unsigned long)((b)->hd_private))
#define	QNEAR_ASYNC	(QNEAR_ASYNCONLY|QNEAR_ASYNCALSO)

#define	SYNC2ASYNC(a) ((a)->q_tab.hd_cnt)


/*
 * qmerge implements a two priority queue, the low priority queue holding ASYNC
 * write requests, while the rest are queued in the high priority sync queue.
 * Requests on the async queue would be merged if possible.
 * By default qmerge2wayscan is 1, indicating an elevator algorithm. When
 * this variable is set to zero, it has the following side effects.
 * 1. We assume fairness is the number one issue.
 * 2. The next request to be picked indicates current head position.
 *
 * qmerge_sync2async indicates the ratio of scans of high prioriy
 * sync queue to low priority async queue.
 *
 * When qmerge variables have the following values it defaults to qsort
 *
 * qmerge1pri = 1, qmerge2wayscan = 0, qmerge_max_merge = 0
 *
 */
static int	qmerge_max_merge = 128 * 1024;
static intptr_t	qmerge_sync2async = 4;
static int	qmerge2wayscan = 1;
static int	qmerge1pri = 0;
static int	qmerge_merge = 0;

/*
 * 	Local static data
 */
struct que_obj *
qmerge_create()
{
	struct que_data *qfp;
	struct que_obj *queobjp;

	queobjp = kmem_zalloc((sizeof (*queobjp) + sizeof (*qfp)), KM_NOSLEEP);
	if (!queobjp)
		return (NULL);

	queobjp->que_ops = &qmerge_ops;
	qfp = (struct que_data *)(queobjp+1);
	qfp->q_tab.hd_private = 0;
	qfp->q_tab.hd_sync_next = qfp->q_tab.hd_async_next = NULL;
	qfp->q_tab.hd_cnt = (void *)qmerge_sync2async;
	queobjp->que_data = (opaque_t)qfp;

	return ((opaque_t)queobjp);
}

static int
qmerge_free(struct que_obj *queobjp)
{
	struct	que_data *qfp;

	qfp = (struct que_data *)queobjp->que_data;
	mutex_destroy(&qfp->q_mutex);
	kmem_free(queobjp, (sizeof (*queobjp) + sizeof (*qfp)));
	return (0);
}

static int
qmerge_can_merge(bp1, bp2)
struct	buf *bp1, *bp2;
{
	const int paw_flags = B_PAGEIO | B_ASYNC | B_WRITE;

	if ((bp1->b_un.b_addr != 0) || (bp2->b_un.b_addr != 0) ||
	    ((bp1->b_flags & (paw_flags | B_REMAPPED)) != paw_flags) ||
	    ((bp2->b_flags & (paw_flags | B_REMAPPED)) != paw_flags) ||
	    (bp1->b_bcount & PAGEOFFSET) || (bp2->b_bcount & PAGEOFFSET) ||
	    (bp1->b_bcount + bp2->b_bcount > qmerge_max_merge))
		return (0);

	if ((DBLK(bp2) + bp2->b_bcount / DEV_BSIZE == DBLK(bp1)) ||
	    (DBLK(bp1) + bp1->b_bcount / DEV_BSIZE == DBLK(bp2)))
		return (1);
	else
		return (0);
}

static void
qmerge_mergesetup(bp_merge, bp)
struct	buf *bp_merge, *bp;
{
	struct	buf *bp1;
	struct	page *pp, *pp_merge, *pp_merge_prev;
	int	forward;

	qmerge_merge++;
	forward = DBLK(bp_merge) < DBLK(bp);

	bp_merge->b_bcount += bp->b_bcount;

	pp = bp->b_pages;
	pp_merge = bp_merge->b_pages;

	pp_merge_prev = pp_merge->p_prev;

	pp_merge->p_prev->p_next = pp;
	pp_merge->p_prev = pp->p_prev;
	pp->p_prev->p_next = pp_merge;
	pp->p_prev = pp_merge_prev;

	bp1 = bp_merge->b_forw;

	bp1->av_back->av_forw = bp;
	bp->av_back = bp1->av_back;
	bp1->av_back = bp;
	bp->av_forw = bp1;

	if (!forward) {
		bp_merge->b_forw = bp;
		bp_merge->b_pages = pp;
		bp_merge->b_private = bp->b_private;
	}
}

static void
que_insert(struct que_data *qfp, struct buf *bp)
{
	struct buf	*bp1, *bp_start, *lowest_bp, *highest_bp;
	uintptr_t	highest_blk, lowest_blk;
	struct buf	**async_bpp, **sync_bpp, **bpp;
	struct diskhd	*dp = &qfp->q_tab;

	sync_bpp = &dp->hd_sync_next;
	async_bpp = &dp->hd_async_next;
	/*
	 * The ioctl used by the format utility requires that bp->av_back be
	 * preserved.
	 */
	if (bp->av_back)
		bp->b_error = (intptr_t)bp->av_back;
	if (!qmerge1pri &&
	    ((bp->b_flags & (B_ASYNC|B_READ|B_FREE)) == B_ASYNC)) {
		bpp = &dp->hd_async_next;
	} else {
		bpp = &dp->hd_sync_next;
	}


	if ((bp1 = *bpp) == NULL) {
		*bpp = bp;
		bp->av_forw = bp->av_back = bp;
		if ((bpp == async_bpp) && (*sync_bpp == NULL)) {
			dp->hd_flags |= QNEAR_ASYNCONLY;
		} else if (bpp == sync_bpp) {
			dp->hd_flags &= ~QNEAR_ASYNCONLY;
			if (*async_bpp) {
				dp->hd_flags |= QNEAR_ASYNCALSO;
			}
		}
		return;
	}
	bp_start = bp1;
	if (DBLK(bp) < DBLK(bp1)) {
		lowest_blk = DBLK(bp1);
		lowest_bp = bp1;
		do {
			if (DBLK(bp) > DBLK(bp1)) {
				bp->av_forw = bp1->av_forw;
				bp1->av_forw->av_back = bp;
				bp1->av_forw = bp;
				bp->av_back = bp1;

				if (((bpp == async_bpp) &&
				    (dp->hd_flags & QNEAR_ASYNC)) ||
				    (bpp == sync_bpp)) {
					if (!(dp->hd_flags & QNEAR_BACKWARD) &&
					    BP_GT_HD(bp, dp)) {
						*bpp = bp;
					}
				}
				return;
			} else if (DBLK(bp1) < lowest_blk) {
				lowest_bp = bp1;
				lowest_blk = DBLK(bp1);
			}
		} while ((DBLK(bp1->av_back) < DBLK(bp1)) &&
		    ((bp1 = bp1->av_back) != bp_start));
		bp->av_forw = lowest_bp;
		lowest_bp->av_back->av_forw = bp;
		bp->av_back = lowest_bp->av_back;
		lowest_bp->av_back = bp;
		if ((bpp == async_bpp) && !(dp->hd_flags & QNEAR_ASYNC)) {
			*bpp = bp;
		} else if (!(dp->hd_flags & QNEAR_BACKWARD) &&
		    BP_GT_HD(bp, dp)) {
			*bpp = bp;
		}
	} else {
		highest_blk = DBLK(bp1);
		highest_bp = bp1;
		do {
			if (DBLK(bp) < DBLK(bp1)) {
				bp->av_forw = bp1;
				bp1->av_back->av_forw = bp;
				bp->av_back = bp1->av_back;
				bp1->av_back = bp;
				if (((bpp == async_bpp) &&
				    (dp->hd_flags & QNEAR_ASYNC)) ||
				    (bpp == sync_bpp)) {
					if ((dp->hd_flags & QNEAR_BACKWARD) &&
					    BP_LT_HD(bp, dp)) {
						*bpp = bp;
					}
				}
				return;
			} else if (DBLK(bp1) > highest_blk) {
				highest_bp = bp1;
				highest_blk = DBLK(bp1);
			}
		} while ((DBLK(bp1->av_forw) > DBLK(bp1)) &&
		    ((bp1 = bp1->av_forw) != bp_start));
		bp->av_back = highest_bp;
		highest_bp->av_forw->av_back = bp;
		bp->av_forw = highest_bp->av_forw;
		highest_bp->av_forw = bp;

		if (((bpp == sync_bpp) ||
		    ((bpp == async_bpp) && (dp->hd_flags & QNEAR_ASYNC))) &&
		    (dp->hd_flags & QNEAR_BACKWARD) && (BP_LT_HD(bp, dp)))
			*bpp = bp;
	}
}

/*
 * dmult_enque() holds dmultp->ds_mutex lock, so we dont grab
 * lock here. If dmult_enque() changes we will have to visit
 * this function again
 */
static int
qmerge_add(struct que_data *qfp, struct buf *bp)
{

	que_insert(qfp, bp);
	return (++qfp->q_cnt);
}

static int
qmerge_iodone(struct buf *bp)
{
	struct buf *bp1;
	struct	page *pp, *pp1, *tmp_pp;

	if (bp->b_flags & B_REMAPPED)
		bp_mapout(bp);

	bp1 = bp->b_forw;
	do {
		bp->b_forw = bp1->av_forw;
		bp1->av_forw->av_back = bp1->av_back;
		bp1->av_back->av_forw = bp1->av_forw;
		pp = (page_t *)bp1->b_pages;
		pp1 = bp->b_forw->b_pages;

		tmp_pp = pp->p_prev;
		pp->p_prev = pp1->p_prev;
		pp->p_prev->p_next = pp;

		pp1->p_prev = tmp_pp;
		pp1->p_prev->p_next = pp1;

		if (bp->b_flags & B_ERROR) {
			bp1->b_error = bp->b_error;
			bp1->b_flags |= B_ERROR;
		}

		biodone(bp1);
	} while ((bp1 = bp->b_forw) != bp->b_forw->av_forw);

	biodone(bp1);
	kmem_free(bp, sizeof (*bp));
	return (0);
}




static struct buf *
qmerge_nextbp(struct que_data *qfp, struct buf *bp_merge, int *can_merge)
{
	intptr_t	private, cnt;
	int		flags;
	struct		buf *sync_bp, *async_bp, *bp;
	struct		buf **sync_bpp, **async_bpp, **bpp;
	struct		diskhd *dp = &qfp->q_tab;

	if (qfp->q_cnt == 0) {
		return (NULL);
	}
	flags = qfp->q_tab.hd_flags;
	sync_bpp = &qfp->q_tab.hd_sync_next;
	async_bpp = &qfp->q_tab.hd_async_next;

begin_nextbp:
	if (flags & QNEAR_ASYNCONLY) {
		bp = *async_bpp;
		private = DBLK(bp);
		if (bp_merge && !qmerge_can_merge(bp, bp_merge)) {
			return (NULL);
		} else if (bp->av_forw == bp) {
			bp->av_forw = bp->av_back = NULL;
			flags &= ~(QNEAR_ASYNCONLY | QNEAR_BACKWARD);
			private = 0;
		} else if (flags & QNEAR_BACKWARD) {
			if (DBLK(bp) < DBLK(bp->av_back)) {
				flags &= ~QNEAR_BACKWARD;
				private = 0;
			}
		} else if (DBLK(bp) > DBLK(bp->av_forw)) {
			if (qmerge2wayscan) {
				flags |= QNEAR_BACKWARD;
			} else {
				private = 0;
			}
		} else if (qmerge2wayscan == 0) {
			private = DBLK(bp->av_forw);
		}
		bpp = async_bpp;

	} else if (flags & QNEAR_ASYNCALSO) {
		sync_bp = *sync_bpp;
		async_bp = *async_bpp;
		if (flags & QNEAR_BACKWARD) {
			if (BP_GT_HD(sync_bp, dp) && BP_GT_HD(async_bp, dp)) {
				flags &= ~(QNEAR_BACKWARD|QNEAR_ASYNCALSO);
				*sync_bpp = sync_bp->av_forw;
				*async_bpp = async_bp->av_forw;
				SYNC2ASYNC(qfp) = (void *)qmerge_sync2async;
				qfp->q_tab.hd_private = 0;
				goto begin_nextbp;
			}
			if (BP_LT_HD(async_bp, dp) && BP_LT_HD(sync_bp, dp)) {
				if (BP_GT_BP(async_bp, sync_bp)) {
					bpp = async_bpp;
					bp = *async_bpp;
				} else {
					bpp = sync_bpp;
					bp = *sync_bpp;
				}
			} else if (BP_LT_HD(async_bp, dp)) {
				bpp = async_bpp;
				bp = *async_bpp;
			} else {
				bpp = sync_bpp;
				bp = *sync_bpp;
			}
		} else {
			if (BP_LT_HD(sync_bp, dp) && BP_LT_HD(async_bp, dp)) {
				if (qmerge2wayscan) {
					flags |= QNEAR_BACKWARD;
					*sync_bpp = sync_bp->av_back;
					*async_bpp = async_bp->av_back;
					goto begin_nextbp;
				} else {
					flags &= ~QNEAR_ASYNCALSO;
					SYNC2ASYNC(qfp) =
					    (void *)qmerge_sync2async;
					qfp->q_tab.hd_private = 0;
					goto begin_nextbp;
				}
			}
			if (BP_GT_HD(async_bp, dp) && BP_GT_HD(sync_bp, dp)) {
				if (BP_LT_BP(async_bp, sync_bp)) {
					bpp = async_bpp;
					bp = *async_bpp;
				} else {
					bpp = sync_bpp;
					bp = *sync_bpp;
				}
			} else if (BP_GT_HD(async_bp, dp)) {
				bpp = async_bpp;
				bp = *async_bpp;
			} else {
				bpp = sync_bpp;
				bp = *sync_bpp;
			}
		}
		if (bp_merge && !qmerge_can_merge(bp, bp_merge)) {
			return (NULL);
		} else if (bp->av_forw == bp) {
			bp->av_forw = bp->av_back = NULL;
			flags &= ~QNEAR_ASYNCALSO;
			if (bpp == async_bpp) {
				SYNC2ASYNC(qfp) = (void *)qmerge_sync2async;
			} else {
				flags |= QNEAR_ASYNCONLY;
			}
		}
		private = DBLK(bp);
	} else {
		bp = *sync_bpp;
		private = DBLK(bp);
		if (bp_merge && !qmerge_can_merge(bp, bp_merge)) {
			return (NULL);
		} else if (bp->av_forw == bp) {
			private = 0;
			SYNC2ASYNC(qfp) = (void *)qmerge_sync2async;
			bp->av_forw = bp->av_back = NULL;
			flags &= ~QNEAR_BACKWARD;
			if (*async_bpp)
				flags |= QNEAR_ASYNCONLY;
		} else if (flags & QNEAR_BACKWARD) {
			if (DBLK(bp) < DBLK(bp->av_back)) {
				flags &= ~QNEAR_BACKWARD;
				cnt = (intptr_t)SYNC2ASYNC(qfp);
				if (cnt > 0) {
					cnt--;
					SYNC2ASYNC(qfp) = (void *)cnt;
				} else {
					if (*async_bpp)
						flags |= QNEAR_ASYNCALSO;
					SYNC2ASYNC(qfp) =
					    (void *)qmerge_sync2async;
				}
				private = 0;
			}
		} else if (DBLK(bp) > DBLK(bp->av_forw)) {
			private = 0;
			if (qmerge2wayscan) {
				flags |= QNEAR_BACKWARD;
				private = DBLK(bp);
			} else {
				cnt = (intptr_t)SYNC2ASYNC(qfp);
				if (cnt > 0) {
					cnt--;
					SYNC2ASYNC(qfp) = (void *)cnt;
				} else {
					if (*async_bpp)
						flags |= QNEAR_ASYNCALSO;
					SYNC2ASYNC(qfp) =
					    (void *)qmerge_sync2async;
				}
			}
		} else if (qmerge2wayscan == 0) {
			private = DBLK(bp->av_forw);
		}
		bpp = sync_bpp;
	}

	if (bp->av_forw) {
		*can_merge = !(bp->b_flags & B_READ);
		if (flags & QNEAR_BACKWARD) {
			*bpp = bp->av_back;
			if ((DBLK(bp->av_back) +
			    bp->av_back->b_bcount / DEV_BSIZE) != DBLK(bp))
				*can_merge = 0;
		} else {
			*bpp = bp->av_forw;
			if ((DBLK(bp) + bp->b_bcount / DEV_BSIZE) !=
			    DBLK(bp->av_forw))
				*can_merge = 0;
		}
		bp->av_forw->av_back = bp->av_back;
		bp->av_back->av_forw = bp->av_forw;
		bp->av_forw = bp->av_back = NULL;
	} else {
		*bpp = NULL;
		*can_merge = 0;
	}
	qfp->q_tab.hd_private = (void *)private;
	qfp->q_cnt--;
	qfp->q_tab.hd_flags = flags;
	if (bp->b_error) {
		bp->av_back = (void *)(intptr_t)bp->b_error;
		bp->b_error = 0;
	}
	return (bp);
}

static struct buf *
qmerge_del(struct que_data *qfp)
{
	struct	buf *bp, *next_bp, *bp_merge;
	int	alloc_mergebp, merge;

	if (qfp->q_cnt == 0) {
		return (NULL);
	}

	bp_merge = bp = qmerge_nextbp(qfp, NULL, &merge);
	alloc_mergebp = 1;
	while (merge && (next_bp = qmerge_nextbp(qfp, bp_merge, &merge))) {
		if (alloc_mergebp) {
			bp_merge = kmem_alloc(sizeof (*bp_merge), KM_NOSLEEP);
			if (bp_merge == NULL) {
				mutex_exit(&qfp->q_mutex);
				return (bp);
			}
			bcopy(bp, bp_merge, sizeof (*bp_merge));
			bp_merge->b_iodone = qmerge_iodone;
			bp_merge->b_forw = bp;
			bp_merge->b_back = (struct buf *)qfp;
			bp->av_forw = bp->av_back = bp;
			alloc_mergebp = 0;
		}
		qmerge_mergesetup(bp_merge, next_bp);
	}
	return (bp_merge);
}


/*
 *	FIFO Queue functions
 */
/*
 * 	Local Function Prototypes
 */
static int qfifo_add();

struct 	que_objops qfifo_ops = {
	que_init,
	que_free,
	qfifo_add,
	que_del,
	0, 0
};

/*
 * 	Local static data
 */
struct que_obj *
qfifo_create()
{
	return (que_create((struct que_objops *)&qfifo_ops));
}

static int
qfifo_add(struct que_data *qfp, struct buf *bp)
{

	if (!qfp->q_tab.b_actf)
		qfp->q_tab.b_actf = bp;
	else
		qfp->q_tab.b_actl->av_forw = bp;
	qfp->q_tab.b_actl = bp;
	bp->av_forw = NULL;
	return (0);
}

/*
 *	One-Way-Scan Queue functions
 */
/*
 * 	Local Function Prototypes
 */
static int qsort_add();
static struct buf *qsort_del();
static void oneway_scan_binary(struct diskhd *dp, struct buf *bp);

struct 	que_objops qsort_ops = {
	que_init,
	que_free,
	qsort_add,
	qsort_del,
	0, 0
};

/*
 * 	Local static data
 */
struct que_obj *
qsort_create()
{
	return (que_create((struct que_objops *)&qsort_ops));
}

static int
qsort_add(struct que_data *qfp, struct buf *bp)
{
	qfp->q_cnt++;
	oneway_scan_binary(&qfp->q_tab, bp);
	return (0);
}


#define	b_pasf	b_forw
#define	b_pasl	b_back
static void
oneway_scan_binary(struct diskhd *dp, struct buf *bp)
{
	struct buf *ap;

	ap = dp->b_actf;
	if (ap == NULL) {
		dp->b_actf = bp;
		bp->av_forw = NULL;
		return;
	}
	if (DBLK(bp) < DBLK(ap)) {
		ap = dp->b_pasf;
		if ((ap == NULL) || (DBLK(bp) < DBLK(ap))) {
			dp->b_pasf = bp;
			bp->av_forw = ap;
			return;
		}
	}
	while (ap->av_forw) {
		if (DBLK(bp) < DBLK(ap->av_forw))
			break;
		ap = ap->av_forw;
	}
	bp->av_forw = ap->av_forw;
	ap->av_forw = bp;
}

static struct buf *
qsort_del(struct que_data *qfp)
{
	struct buf *bp;

	if (qfp->q_cnt == 0) {
		return (NULL);
	}
	qfp->q_cnt--;
	bp = qfp->q_tab.b_actf;
	qfp->q_tab.b_actf = bp->av_forw;
	bp->av_forw = 0;
	if (!qfp->q_tab.b_actf && qfp->q_tab.b_pasf) {
		qfp->q_tab.b_actf = qfp->q_tab.b_pasf;
		qfp->q_tab.b_pasf = NULL;
	}
	return (bp);
}

/*
 *	Tagged queueing
 */
/*
 * 	Local Function Prototypes
 */

struct 	que_objops qtag_ops = {
	que_init,
	que_free,
	qsort_add,
	qsort_del,
	0, 0
};

/*
 * 	Local static data
 */
struct que_obj *
qtag_create()
{
	return (que_create((struct que_objops *)&qtag_ops));
}
