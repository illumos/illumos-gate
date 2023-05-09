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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/termio.h>
#include <sys/ddi.h>
#include <sys/file.h>
#include <sys/disp.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/sunndi.h>
#include <sys/kbio.h>
#include <sys/prom_plat.h>
#include <sys/oplmsu/oplmsu.h>
#include <sys/oplmsu/oplmsu_proto.h>

extern int ddi_create_internal_pathname(dev_info_t *, char *, int, minor_t);

#define	MOD_ID		0xe145
#define	MOD_NAME	"oplmsu"

#define	META_NAME	"oplmsu"
#define	USER_NAME	"a"

struct module_info oplmsu_mod_info = {
	MOD_ID,
	MOD_NAME,
	0,
	16384,
	14336,
	2048
};

struct qinit oplmsu_urinit = {
	NULL,
	oplmsu_ursrv,
	oplmsu_open,
	oplmsu_close,
	NULL,
	&oplmsu_mod_info,
	NULL
};

struct qinit oplmsu_uwinit = {
	oplmsu_uwput,
	oplmsu_uwsrv,
	oplmsu_open,
	oplmsu_close,
	NULL,
	&oplmsu_mod_info,
	NULL
};

struct qinit oplmsu_lrinit = {
	oplmsu_lrput,
	oplmsu_lrsrv,
	oplmsu_open,
	oplmsu_close,
	NULL,
	&oplmsu_mod_info,
	NULL
};

struct qinit oplmsu_lwinit = {
	NULL,
	oplmsu_lwsrv,
	oplmsu_open,
	oplmsu_close,
	NULL,
	&oplmsu_mod_info,
	NULL
};

struct streamtab oplmsu_info = {
	&oplmsu_urinit,
	&oplmsu_uwinit,
	&oplmsu_lrinit,
	&oplmsu_lwinit
};

static struct cb_ops cb_oplmsu_ops = {
	nulldev,			/* cb_open */
	nulldev,			/* cb_close */
	nodev,				/* cb_strategy */
	nodev,				/* cb_print */
	nodev,				/* cb_dump */
	nodev,				/* cb_read */
	nodev,				/* cb_write */
	nodev,				/* cb_ioctl */
	nodev,				/* cb_devmap */
	nodev,				/* cb_mmap */
	nodev,				/* cb_segmap */
	nochpoll,			/* cb_chpoll */
	ddi_prop_op,			/* cb_prop_op */
	(&oplmsu_info),			/* cb_stream */
	(int)(D_NEW|D_MP|D_HOTPLUG)	/* cb_flag */
};

static struct dev_ops oplmsu_ops = {
	DEVO_REV,			/* devo_rev */
	0,				/* devo_refcnt */
	(oplmsu_getinfo),		/* devo_getinfo */
	(nulldev),			/* devo_identify */
	(nulldev),			/* devo_probe */
	(oplmsu_attach),		/* devo_attach */
	(oplmsu_detach),		/* devo_detach */
	(nodev),			/* devo_reset */
	&(cb_oplmsu_ops),		/* devo_cb_ops */
	(struct bus_ops *)NULL,		/* devo_bus_ops */
	NULL,				/* devo_power */
	ddi_quiesce_not_needed,			/* dev_quiesce */
};

struct modldrv modldrv = {
	&mod_driverops,
	"OPL serial mux driver",
	&oplmsu_ops
};

struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

uinst_t		oplmsu_uinst_local;	/* upper_instance_table structure */
uinst_t		*oplmsu_uinst = &oplmsu_uinst_local;
int		oplmsu_queue_flag;	/* Enable/disable queueing flag */
int		oplmsu_check_su;	/* Check super-user flag */

#ifdef DEBUG
int		oplmsu_debug_mode = 0;	/* Enable/disable debug mode */
int		oplmsu_trace_on;	/* Enable/disable trace */
uint_t		oplmsu_ltrc_size;	/* Trace buffer size */
msu_trc_t	*oplmsu_ltrc_top;	/* Top of trace data area */
msu_trc_t	*oplmsu_ltrc_tail;	/* Tail of trace data area */
msu_trc_t	*oplmsu_ltrc_cur;	/* Current pointer of trace data area */
ulong_t		oplmsu_ltrc_ccnt;	/* Current counter */
kmutex_t	oplmsu_ltrc_lock;	/* Lock table for trace mode */
#endif

/* oplmsu_conf_st */
#define	MSU_CONFIGURED		2
#define	MSU_CONFIGURING		1
#define	MSU_UNCONFIGURED	0

static kmutex_t		oplmsu_bthrd_excl;
static kthread_id_t	oplmsu_bthrd_id = NULL;
static int		oplmsu_conf_st = MSU_UNCONFIGURED;
static kcondvar_t	oplmsu_conf_cv;


/*
 * Locking hierarcy of oplmsu driver. This driver have 5 locks in uinst_t.
 *
 * Each mutex guards as follows.
 *
 *  uinst_t->lock: This mutex is read/write mutex.
 *     read lock : acquired if the member of uinst_t is refered only.
 *     write lock: acquired if the member of uinst_t is changed.
 *
 *  uinst_t->u_lock: This mutex is normal mutex.
 *   This mutex is acquired at reading/changing the member of all upath_t.
 *
 *  uinst_t->l_lock: This mutex is normal mutex.
 *   This mutex is acquired at reading/changing the member of all lpath_t.
 *
 *  uinst_t->c_lock: This mutex is normal mutex.
 *   This mutex is acquired at reading/changing the member of the ctrl_t.
 *
 *  oplmsu_bthrd_excl: This mutex is normal mutex.
 *   This mutex is used only to start/stop the configuring thread of the
 *   multiplexed STREAMS.
 *   This mutex is exclusively acquired with the above-mentioned 4 mutexes.
 *
 * To guard of the deadlock by cross locking, the base locking hierarcy
 * is as follows:
 *
 *     uisnt->lock ==> uinst->u_lock ==> uinst->l_lock ==> uinst->c_lock
 *
 */


int
_init(void)
{
	int	rval;

	/* Initialize R/W lock for uinst_t */
	rw_init(&oplmsu_uinst->lock, "uinst rwlock", RW_DRIVER, NULL);

	/* Initialize mutex for upath_t */
	mutex_init(&oplmsu_uinst->u_lock, "upath lock", MUTEX_DRIVER, NULL);

	/* Initialize mutex for lpath_t */
	mutex_init(&oplmsu_uinst->l_lock, "lpath lock", MUTEX_DRIVER, NULL);

	/* Initialize mutex for ctrl_t */
	mutex_init(&oplmsu_uinst->c_lock, "ctrl lock", MUTEX_DRIVER, NULL);

	/* Initialize mutex for protecting background thread */
	mutex_init(&oplmsu_bthrd_excl, NULL, MUTEX_DRIVER, NULL);

	/* Initialize condition variable */
	cv_init(&oplmsu_conf_cv, NULL, CV_DRIVER, NULL);

	rval = mod_install(&modlinkage);
	if (rval != DDI_SUCCESS) {
		cv_destroy(&oplmsu_conf_cv);
		mutex_destroy(&oplmsu_bthrd_excl);
		mutex_destroy(&oplmsu_uinst->c_lock);
		mutex_destroy(&oplmsu_uinst->l_lock);
		mutex_destroy(&oplmsu_uinst->u_lock);
		rw_destroy(&oplmsu_uinst->lock);
	}
	return (rval);
}

int
_fini(void)
{
	int	rval;

	rval = mod_remove(&modlinkage);
	if (rval == DDI_SUCCESS) {
		cv_destroy(&oplmsu_conf_cv);
		mutex_destroy(&oplmsu_bthrd_excl);
		mutex_destroy(&oplmsu_uinst->c_lock);
		mutex_destroy(&oplmsu_uinst->l_lock);
		mutex_destroy(&oplmsu_uinst->u_lock);
		rw_destroy(&oplmsu_uinst->lock);
	}
	return (rval);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
int
oplmsu_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	dev_t	dev = (dev_t)arg;
	minor_t	inst;
	int	rval = DDI_SUCCESS;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO  :
		if (oplmsu_uinst->msu_dip == NULL) {
			rval = DDI_FAILURE;
		} else {
			*resultp = oplmsu_uinst->msu_dip;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE :
		inst = getminor(dev) & ~(META_NODE_MASK|USER_NODE_MASK);
		*resultp = (void *)(uintptr_t)inst;
		break;

	default :
		rval = DDI_FAILURE;
		break;
	}
	return (rval);
}

int
oplmsu_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	minor_t	meta_minor, user_minor;
	int	rval = 0;
	int	instance;
#define	CNTRL(c) ((c) & 037)
	char	abt_ch_seq[3] = { '\r', '~', CNTRL('b') };

	if (cmd == DDI_RESUME) {
		return (DDI_SUCCESS);
	}

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	if (instance != 0) {
		cmn_err(CE_WARN, "oplmsu: attach: "
		    "Invaild instance => %d", instance);
		return (DDI_FAILURE);
	}

	/* Create minor number for meta control node */
	meta_minor = instance | META_NODE_MASK;
	/* Create minor number for user access node */
	user_minor = instance | USER_NODE_MASK;

	/* Create minor node for user access */
	rval = ddi_create_minor_node(dip, USER_NAME, S_IFCHR, user_minor,
	    DDI_NT_SERIAL, 0);
	if (rval != DDI_SUCCESS) {
		cmn_err(CE_WARN, "oplmsu: attach: "
		    "ddi_create_minor_node failed. errno = %d", rval);
		ddi_remove_minor_node(dip, NULL);
		return (rval);
	}

	/* Create minor node for meta control */
	rval = ddi_create_internal_pathname(dip, META_NAME, S_IFCHR,
	    meta_minor);
	if (rval != DDI_SUCCESS) {
		cmn_err(CE_WARN, "oplmsu: attach: "
		    "ddi_create_internal_pathname failed. errno = %d", rval);
		ddi_remove_minor_node(dip, NULL);
		return (rval);
	}

	rw_enter(&oplmsu_uinst->lock, RW_WRITER);

	/* Get each properties */
	oplmsu_check_su = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    (DDI_PROP_DONTPASS|DDI_PROP_NOTPROM), "check-superuser", 1);

	/*
	 * Initialize members of uinst_t
	 */

	oplmsu_uinst->inst_status = INST_STAT_UNCONFIGURED;
	oplmsu_uinst->path_num = UNDEFINED;
	oplmsu_uinst->msu_dip = dip;
	(void) strcpy(oplmsu_uinst->abts, abt_ch_seq);

#ifdef DEBUG
	oplmsu_trace_on = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    (DDI_PROP_DONTPASS|DDI_PROP_NOTPROM), "trace-mode", 1);
	oplmsu_ltrc_size = (uint_t)ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    (DDI_PROP_DONTPASS|DDI_PROP_NOTPROM), "trace-bufsize", 128);

	if (oplmsu_trace_on == MSU_TRACE_ON) {
		/* Initialize mutex for msu_trc_t */
		mutex_init(&oplmsu_ltrc_lock, "trc lock", MUTEX_DRIVER, NULL);

		mutex_enter(&oplmsu_ltrc_lock);
		oplmsu_ltrc_top = (msu_trc_t *)kmem_zalloc(
		    (sizeof (msu_trc_t) * oplmsu_ltrc_size), KM_SLEEP);
		oplmsu_ltrc_cur = (msu_trc_t *)(oplmsu_ltrc_top - 1);
		oplmsu_ltrc_tail =
		    (msu_trc_t *)(oplmsu_ltrc_top + (oplmsu_ltrc_size - 1));
		mutex_exit(&oplmsu_ltrc_lock);
	}
#endif
	rw_exit(&oplmsu_uinst->lock);
	ddi_report_dev(dip);
	return (rval);
}

int
oplmsu_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	lpath_t	*lpath, *next_lpath;

	if (cmd == DDI_SUSPEND) {
		return (DDI_SUCCESS);
	}

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	rw_enter(&oplmsu_uinst->lock, RW_WRITER);

	/* Delete all upath_t */
	oplmsu_delete_upath_info();

	/* Delete all lpath_t */
	mutex_enter(&oplmsu_uinst->l_lock);
	lpath = oplmsu_uinst->first_lpath;
	oplmsu_uinst->first_lpath = NULL;
	oplmsu_uinst->last_lpath = NULL;
	mutex_exit(&oplmsu_uinst->l_lock);

#ifdef DEBUG
	if (oplmsu_trace_on == MSU_TRACE_ON) {
		mutex_enter(&oplmsu_ltrc_lock);
		if (oplmsu_ltrc_top != NULL) {
			kmem_free(oplmsu_ltrc_top,
			    (sizeof (msu_trc_t) * oplmsu_ltrc_size));
		}
		oplmsu_ltrc_top = NULL;
		oplmsu_ltrc_cur = NULL;
		oplmsu_ltrc_tail = NULL;
		mutex_exit(&oplmsu_ltrc_lock);

		mutex_destroy(&oplmsu_ltrc_lock);
	}
#endif
	rw_exit(&oplmsu_uinst->lock);

	while (lpath) {
		if (lpath->rbuf_id) {
			unbufcall(lpath->rbuf_id);
		}

		if (lpath->rtout_id) {
			(void) untimeout(lpath->rtout_id);
		}

		if (lpath->rbuftbl) {
			kmem_free(lpath->rbuftbl, sizeof (struct buf_tbl));
		}

		cv_destroy(&lpath->sw_cv);
		next_lpath = lpath->l_next;
		kmem_free(lpath, sizeof (lpath_t));
		lpath = next_lpath;
	}
	ddi_remove_minor_node(dip, NULL);
	return (DDI_SUCCESS);
}

/* ARGSUSED */
int
oplmsu_open(queue_t *urq, dev_t *dev, int oflag, int sflag, cred_t *cred_p)
{
	ctrl_t	*ctrl;
	minor_t	mindev = 0;
	minor_t	qmindev = 0;
	major_t	majdev;
	ulong_t	node_flag;

	DBG_PRINT((CE_NOTE, "oplmsu: open: "
	    "devt = 0x%lx, sflag = 0x%x", *dev, sflag));

	if (sflag == CLONEOPEN) {
		return (EINVAL);
	}

	/* Get minor device number */
	qmindev = (minor_t)getminor(*dev);
	/* Get node type */
	node_flag = MSU_NODE_TYPE(qmindev);
	if ((node_flag != MSU_NODE_USER) && (node_flag != MSU_NODE_META)) {
		return (EINVAL);
	}

	mutex_enter(&oplmsu_bthrd_excl);
	if ((node_flag == MSU_NODE_USER) &&
	    (oplmsu_conf_st != MSU_CONFIGURED)) { /* User access & First open */
		int	cv_rval;

		DBG_PRINT((CE_NOTE, "oplmsu: open: "
		    "oplmsu_conf_st = %x", oplmsu_conf_st));

		if (oplmsu_conf_st == MSU_UNCONFIGURED) {
			oplmsu_conf_st = MSU_CONFIGURING;

			/* Start up background thread */
			oplmsu_bthrd_id = thread_create(NULL, 2 * DEFAULTSTKSZ,
			    oplmsu_setup, (void *)oplmsu_uinst, 0, &p0, TS_RUN,
			    minclsyspri);
		}

		/*
		 * Wait with cv_wait_sig() until background thread is
		 * completed.
		 */
		while (oplmsu_conf_st == MSU_CONFIGURING) {
			cv_rval =
			    cv_wait_sig(&oplmsu_conf_cv, &oplmsu_bthrd_excl);
			if (cv_rval == 0) {
				mutex_exit(&oplmsu_bthrd_excl);
				return (EINTR);
			}
		}
	}
	mutex_exit(&oplmsu_bthrd_excl);

	rw_enter(&oplmsu_uinst->lock, RW_WRITER);

	/*
	 *  If the node which will open is meta-control-node or
	 * user-access-node, and q_ptr, this is queue_t queue
	 * table member, is not NULL, then oplmsu returns
	 * SUCCESS immidiately.
	 *  This process is used to protect dual open.
	 */

	if ((urq != NULL) && (urq->q_ptr != NULL)) {
		rw_exit(&oplmsu_uinst->lock);
		return (SUCCESS);
	}

	/*
	 *  If the node which will open is User-Access-Node, and instance
	 * status of oplmsu is no ONLINE, then oplmsu_open process fails
	 * with return value 'EIO'.
	 */

	if ((node_flag == MSU_NODE_USER) &&
	    (oplmsu_uinst->inst_status != INST_STAT_ONLINE)) {
		rw_exit(&oplmsu_uinst->lock);
		return (EIO);
	}

	mindev |= qmindev;			/* Create minor device number */
	majdev = getmajor(*dev);		/* Get major device number */
	*dev = makedevice(majdev, mindev);	/* Make device number */

	/* Allocate kernel memory for ctrl_t */
	ctrl = (ctrl_t *)kmem_zalloc(sizeof (ctrl_t), KM_SLEEP);

	/*
	 * Initialize members of ctrl_t
	 */
	ctrl->minor = (minor_t)mindev;
	ctrl->queue = urq;
	ctrl->sleep_flag = CV_WAKEUP;
	ctrl->node_type = node_flag;
	ctrl->wbuftbl =
	    (struct buf_tbl *)kmem_zalloc(sizeof (struct buf_tbl), KM_SLEEP);
	cv_init(&ctrl->cvp, "oplmsu ctrl_tbl condvar", CV_DRIVER, NULL);

	mutex_enter(&oplmsu_uinst->c_lock);

	if (node_flag == MSU_NODE_USER) {	/* User access node */

		oplmsu_uinst->user_ctrl = ctrl;
		oplmsu_queue_flag = 0;

	} else {	/* Meta control node */

		oplmsu_uinst->meta_ctrl = ctrl;
	}

	RD(urq)->q_ptr = ctrl;
	WR(urq)->q_ptr = ctrl;

	mutex_exit(&oplmsu_uinst->c_lock);
	rw_exit(&oplmsu_uinst->lock);

	OPLMSU_TRACE(urq, (mblk_t *)node_flag, MSU_TRC_OPN);

	qprocson(urq);	/* Enable put and service routine */
	return (SUCCESS);
}

/* ARGSUSED */
int
oplmsu_close(queue_t *urq, int flag, cred_t *cred_p)
{
	ctrl_t		*ctrl;
	minor_t		qmindev = 0;
	lpath_t		*lpath;
	ulong_t		node_flag;
	bufcall_id_t	wbuf_id;
	timeout_id_t	wtout_id;

	rw_enter(&oplmsu_uinst->lock, RW_READER);
	mutex_enter(&oplmsu_uinst->l_lock);
	mutex_enter(&oplmsu_uinst->c_lock);
	if ((ctrl = urq->q_ptr) == NULL) {
		mutex_exit(&oplmsu_uinst->c_lock);
		mutex_exit(&oplmsu_uinst->l_lock);
		rw_exit(&oplmsu_uinst->lock);

		DBG_PRINT((CE_NOTE, "oplmsu: close: "
		    "close has already been completed"));
		return (FAILURE);
	}
	qmindev = ctrl->minor;

	DBG_PRINT((CE_NOTE, "oplmsu: close: ctrl->minor = 0x%x", qmindev));

	node_flag = MSU_NODE_TYPE(qmindev);
	if (node_flag > MSU_NODE_META) {
		mutex_exit(&oplmsu_uinst->c_lock);
		mutex_exit(&oplmsu_uinst->l_lock);
		rw_exit(&oplmsu_uinst->lock);
		return (EINVAL);
	}

	/*
	 *  Check that queue which is waiting for response from lower stream
	 * exist. If queue exists, oplmsu sets CV_SLEEP to sleep_flag.
	 */

	for (lpath = oplmsu_uinst->first_lpath; lpath; ) {
		if (((RD(urq) == lpath->hndl_uqueue) ||
		    (WR(urq) == lpath->hndl_uqueue)) &&
		    (lpath->hndl_mp != NULL)) {
			ctrl->sleep_flag = CV_SLEEP;
			break;
		}

		lpath = lpath->l_next;
	}
	mutex_exit(&oplmsu_uinst->l_lock);
	rw_exit(&oplmsu_uinst->lock);

	/* If sleep_flag is not CV_SLEEP, oplmsu calls cv_wait. */
	if (lpath) {
		while (ctrl->sleep_flag != CV_WAKEUP) {
			cv_wait(&ctrl->cvp, &oplmsu_uinst->c_lock);
		}
	}

	flushq(RD(urq), FLUSHALL);
	flushq(WR(urq), FLUSHALL);
	mutex_exit(&oplmsu_uinst->c_lock);
	qprocsoff(urq);		/* Disable queuing of queue */

	rw_enter(&oplmsu_uinst->lock, RW_WRITER);
	switch (node_flag) {
	case MSU_NODE_USER :	/* User access node */
		oplmsu_uinst->user_ctrl = NULL;
		oplmsu_queue_flag = 0;
		break;

	case MSU_NODE_META :	/* Meta control node */
		oplmsu_uinst->meta_ctrl = NULL;
		break;

	default :
		cmn_err(CE_WARN, "oplmsu: close: node_flag = 0x%lx", node_flag);
	}

	ctrl->minor = 0;
	ctrl->queue = NULL;
	wbuf_id = ctrl->wbuf_id;
	wtout_id = ctrl->wtout_id;
	ctrl->wbuf_id = 0;
	ctrl->wtout_id = 0;

	cv_destroy(&ctrl->cvp);
	kmem_free(ctrl->wbuftbl, sizeof (struct buf_tbl));
	ctrl->wbuftbl = NULL;

	RD(urq)->q_ptr = NULL;
	WR(urq)->q_ptr = NULL;
	rw_exit(&oplmsu_uinst->lock);

	if (wbuf_id != 0) {
		unbufcall(wbuf_id);
	}

	if (wtout_id != 0) {
		(void) untimeout(wtout_id);
	}

	/* Free kernel memory for ctrl_t */
	kmem_free(ctrl, sizeof (ctrl_t));

	OPLMSU_TRACE(urq, (mblk_t *)node_flag, MSU_TRC_CLS);
	return (SUCCESS);
}

/*
 * Upper write put procedure
 */
int
oplmsu_uwput(queue_t *uwq, mblk_t *mp)
{

	if (mp == NULL) {
		return (SUCCESS);
	}

	if ((uwq == NULL) || (uwq->q_ptr == NULL)) {
		freemsg(mp);
		return (SUCCESS);
	}

	OPLMSU_TRACE(uwq, mp, MSU_TRC_UI);

	rw_enter(&oplmsu_uinst->lock, RW_READER);
	if (mp->b_datap->db_type == M_FLUSH) {
		oplmsu_wcmn_flush_hndl(uwq, mp, RW_READER);
	} else if (mp->b_datap->db_type >= QPCTL) {
		ctrl_t	*ctrl;

		mutex_enter(&oplmsu_uinst->c_lock);
		ctrl = (ctrl_t *)uwq->q_ptr;

		/* Link high priority message to local queue */
		oplmsu_link_high_primsg(&ctrl->first_upri_hi,
		    &ctrl->last_upri_hi, mp);

		mutex_exit(&oplmsu_uinst->c_lock);
		oplmsu_wcmn_high_qenable(WR(uwq), RW_READER);
	} else {
		(void) putq(WR(uwq), mp);
	}
	rw_exit(&oplmsu_uinst->lock);
	return (SUCCESS);
}

/*
 * Upper write service procedure
 */
int
oplmsu_uwsrv(queue_t *uwq)
{
	struct iocblk	*iocp = NULL;
	mblk_t		*mp = NULL;
	int		rval;

	if ((uwq == NULL) || (uwq->q_ptr == NULL)) {
		return (FAILURE);
	}

	rw_enter(&oplmsu_uinst->lock, RW_READER);

	/* Handle high priority message */
	while (mp = oplmsu_wcmn_high_getq(uwq)) {
		if (mp->b_datap->db_type == M_FLUSH) {
			oplmsu_wcmn_flush_hndl(uwq, mp, RW_READER);
			continue;
		}

		if (oplmsu_wcmn_through_hndl(uwq, mp, MSU_HIGH, RW_READER) ==
		    FAILURE) {
			rw_exit(&oplmsu_uinst->lock);
			return (SUCCESS);
		}
	}
	rw_exit(&oplmsu_uinst->lock);

	/* Handle normal priority message */
	while (mp = getq(uwq)) {
		rval = SUCCESS;
		switch (mp->b_datap->db_type) {
		case M_IOCTL :
			iocp = (struct iocblk *)mp->b_rptr;
			switch (iocp->ioc_cmd) {
			case I_PLINK :
				if (oplmsu_cmn_pullup_msg(uwq, mp) != FAILURE) {
					rval = oplmsu_uwioctl_iplink(uwq, mp);
				}
				break;

			case I_PUNLINK :
				if (oplmsu_cmn_pullup_msg(uwq, mp) != FAILURE) {
					rval = oplmsu_uwioctl_ipunlink(uwq, mp);
				}
				break;

			case TCSETS :		/* FALLTHRU */
			case TCSETSW :		/* FALLTHRU */
			case TCSETSF :		/* FALLTHRU */
			case TIOCMSET :		/* FALLTHRU */
			case TIOCSPPS :		/* FALLTHRU */
			case TIOCSWINSZ :	/* FALLTHRU */
			case TIOCSSOFTCAR :
				rval = oplmsu_uwioctl_termios(uwq, mp);
				break;

			default :
				rw_enter(&oplmsu_uinst->lock, RW_READER);
				rval = oplmsu_wcmn_through_hndl(uwq, mp,
				    MSU_NORM, RW_READER);
				rw_exit(&oplmsu_uinst->lock);
				break;
			}
			break;

		default :
			rw_enter(&oplmsu_uinst->lock, RW_READER);
			rval = oplmsu_wcmn_through_hndl(uwq, mp, MSU_NORM,
			    RW_READER);
			rw_exit(&oplmsu_uinst->lock);
			break;
		}

		if (rval == FAILURE) {
			break;
		}
	}
	return (SUCCESS);
}

/*
 * Lower write service procedure
 */
int
oplmsu_lwsrv(queue_t *lwq)
{
	mblk_t		*mp;
	queue_t		*dst_queue;
	lpath_t		*lpath;

	rw_enter(&oplmsu_uinst->lock, RW_READER);
	while (mp = getq(lwq)) {
		if (mp->b_datap->db_type >= QPCTL) {
			rw_exit(&oplmsu_uinst->lock);
			OPLMSU_TRACE(WR(lwq), mp, MSU_TRC_LO);
			putnext(WR(lwq), mp);
			rw_enter(&oplmsu_uinst->lock, RW_READER);
			continue;
		}

		dst_queue = WR(lwq);
		if (canputnext(dst_queue)) {
			rw_exit(&oplmsu_uinst->lock);
			OPLMSU_TRACE(dst_queue, mp, MSU_TRC_LO);
			putnext(dst_queue, mp);
			rw_enter(&oplmsu_uinst->lock, RW_READER);
		} else {
			(void) putbq(WR(lwq), mp);
			break;
		}
	}

	mutex_enter(&oplmsu_uinst->l_lock);
	lpath = (lpath_t *)lwq->q_ptr;
	if (lpath->uwq_flag != 0) {
		qenable(WR(lpath->uwq_queue));
		lpath->uwq_flag = 0;
		lpath->uwq_queue = NULL;
	}
	mutex_exit(&oplmsu_uinst->l_lock);
	rw_exit(&oplmsu_uinst->lock);
	return (SUCCESS);
}

/*
 * Lower read put procedure
 */
int
oplmsu_lrput(queue_t *lrq, mblk_t *mp)
{

	if (mp == NULL) {
		return (SUCCESS);
	}

	if ((lrq == NULL) || (lrq->q_ptr == NULL)) {
		freemsg(mp);
		return (SUCCESS);
	}

	OPLMSU_TRACE(lrq, mp, MSU_TRC_LI);

	if (mp->b_datap->db_type == M_FLUSH) {
		rw_enter(&oplmsu_uinst->lock, RW_READER);
		oplmsu_rcmn_flush_hndl(lrq, mp);
		rw_exit(&oplmsu_uinst->lock);
	} else if (mp->b_datap->db_type >= QPCTL) {
		lpath_t	*lpath;

		rw_enter(&oplmsu_uinst->lock, RW_READER);
		mutex_enter(&oplmsu_uinst->l_lock);
		lpath = lrq->q_ptr;

		/* Link high priority message to local queue */
		oplmsu_link_high_primsg(&lpath->first_lpri_hi,
		    &lpath->last_lpri_hi, mp);

		mutex_exit(&oplmsu_uinst->l_lock);
		rw_exit(&oplmsu_uinst->lock);
		oplmsu_rcmn_high_qenable(lrq);
	} else {
		(void) putq(lrq, mp);
	}
	return (SUCCESS);
}

/*
 * Lower read service procedure
 */
int
oplmsu_lrsrv(queue_t *lrq)
{
	mblk_t		*mp;
	boolean_t	aborted;
	int		rval;

	if ((lrq == NULL) || (lrq->q_ptr == NULL)) {
		return (FAILURE);
	}

	/* Handle normal priority message */
	while (mp = getq(lrq)) {
		if (mp->b_datap->db_type >= QPCTL) {
			cmn_err(CE_WARN, "oplmsu: lr-srv: "
			    "Invalid db_type => %x", mp->b_datap->db_type);
		}

		switch (mp->b_datap->db_type) {
		case M_DATA :
			aborted = B_FALSE;
			rw_enter(&oplmsu_uinst->lock, RW_READER);
			if ((abort_enable == KIOCABORTALTERNATE) &&
			    (RD(oplmsu_uinst->lower_queue) == lrq)) {
				uchar_t	*rx_char = mp->b_rptr;
				lpath_t	*lpath;

				mutex_enter(&oplmsu_uinst->l_lock);
				lpath = lrq->q_ptr;
				while (rx_char != mp->b_wptr) {
					if (*rx_char == *lpath->abt_char) {
					lpath->abt_char++;
					if (*lpath->abt_char == '\0') {
						abort_sequence_enter((char *)
						    NULL);
						lpath->abt_char
						    = oplmsu_uinst->abts;
						aborted = B_TRUE;
						break;
					}
					} else {
					lpath->abt_char = (*rx_char ==
					    *oplmsu_uinst->abts) ?
					    oplmsu_uinst->abts + 1 :
					    oplmsu_uinst->abts;
					}
					rx_char++;
				}
				mutex_exit(&oplmsu_uinst->l_lock);
			}
			rw_exit(&oplmsu_uinst->lock);

			if (aborted) {
				freemsg(mp);
				continue;
			}

			/*
			 * When 1st byte of the received M_DATA is XON or,
			 * 1st byte is XOFF and 2nd byte is XON.
			 */

			if ((*(mp->b_rptr) == MSU_XON) ||
			    (((mp->b_wptr - mp->b_rptr) == 2) &&
			    ((*(mp->b_rptr) == MSU_XOFF) &&
			    (*(mp->b_rptr + 1) == MSU_XON)))) {
				/* Path switching by XOFF/XON */
				if (oplmsu_lrdata_xoffxon(lrq, mp) == FAILURE) {
					return (SUCCESS);
				}
			} else {
				rw_enter(&oplmsu_uinst->lock, RW_READER);
				rval =
				    oplmsu_rcmn_through_hndl(lrq, mp, MSU_NORM);
				rw_exit(&oplmsu_uinst->lock);

				if (rval == FAILURE) {
					return (SUCCESS);
				}
			}
			break;

		case M_BREAK :
			if ((mp->b_wptr - mp->b_rptr) == 0 && msgdsize(mp)
			    == 0) {
				rw_enter(&oplmsu_uinst->lock, RW_READER);
				if ((abort_enable != KIOCABORTALTERNATE) &&
				    (RD(oplmsu_uinst->lower_queue) == lrq)) {
					abort_sequence_enter((char *)NULL);
				}
				rw_exit(&oplmsu_uinst->lock);
				freemsg(mp);
				break;
			}
			/* FALLTHRU */

		default :
			rw_enter(&oplmsu_uinst->lock, RW_READER);
			(void) oplmsu_rcmn_through_hndl(lrq, mp, MSU_NORM);
			rw_exit(&oplmsu_uinst->lock);
			break;
		}
	}
	return (SUCCESS);
}

/*
 * Upper read service procedure
 */
int
oplmsu_ursrv(queue_t *urq)
{
	mblk_t	*mp;
	queue_t	*dst_queue;
	lpath_t	*lpath;
	ctrl_t	*ctrl;
	int	res_chk = 0;

	rw_enter(&oplmsu_uinst->lock, RW_READER);
	while (mp = getq(urq)) {
		if (mp->b_datap->db_type >= QPCTL) {
			if ((mp->b_datap->db_type == M_IOCACK) ||
			    (mp->b_datap->db_type == M_IOCNAK)) {
				res_chk = 1;
			}
			rw_exit(&oplmsu_uinst->lock);
			OPLMSU_TRACE(RD(urq), mp, MSU_TRC_UO);
			putnext(RD(urq), mp);

			rw_enter(&oplmsu_uinst->lock, RW_READER);
			mutex_enter(&oplmsu_uinst->l_lock);
			lpath = oplmsu_uinst->first_lpath;
			while (lpath) {
				qenable(RD(lpath->lower_queue));
				lpath = lpath->l_next;
			}
			mutex_exit(&oplmsu_uinst->l_lock);

			if (res_chk == 1) {
				mutex_enter(&oplmsu_uinst->c_lock);
				ctrl = (ctrl_t *)urq->q_ptr;
				if (ctrl != NULL) {
					if (ctrl->wait_queue != NULL) {
						qenable(WR(ctrl->wait_queue));
						ctrl->wait_queue = NULL;
					}
				}
				mutex_exit(&oplmsu_uinst->c_lock);
				res_chk = 0;
			}
			continue;
		}

		dst_queue = RD(urq);
		if (canputnext(dst_queue)) {
			rw_exit(&oplmsu_uinst->lock);
			OPLMSU_TRACE(dst_queue, mp, MSU_TRC_UO);
			putnext(dst_queue, mp);
			rw_enter(&oplmsu_uinst->lock, RW_READER);
		} else {
			(void) putbq(urq, mp);
			break;
		}
	}

	mutex_enter(&oplmsu_uinst->c_lock);
	ctrl = urq->q_ptr;
	if (ctrl->lrq_flag != 0) {
		qenable(ctrl->lrq_queue);
		ctrl->lrq_flag = 0;
		ctrl->lrq_queue = NULL;
	}
	mutex_exit(&oplmsu_uinst->c_lock);
	rw_exit(&oplmsu_uinst->lock);
	return (SUCCESS);
}

int
oplmsu_open_msu(dev_info_t *dip, ldi_ident_t *lip, ldi_handle_t *lhp)
{
	dev_t	devt;
	int	rval;

	/* Allocate LDI identifier */
	rval = ldi_ident_from_dip(dip, lip);
	if (rval != 0) {
		cmn_err(CE_WARN, "oplmsu: open-msu: "
		    "ldi_ident_from_dip failed. errno = %d", rval);
		return (rval);
	}

	/* Open oplmsu(meta ctrl node) */
	devt = makedevice(ddi_driver_major(dip), META_NODE_MASK);
	rval =
	    ldi_open_by_dev(&devt, OTYP_CHR, (FREAD|FWRITE), kcred, lhp, *lip);
	if (rval != 0) {
		cmn_err(CE_WARN, "oplmsu: open-msu: "
		    "ldi_open_by_dev failed. errno = %d", rval);
		ldi_ident_release(*lip);
	}
	return (rval);
}

int
oplmsu_plink_serial(dev_info_t *dip, ldi_handle_t msu_lh, int *id)
{
	ldi_ident_t	li = NULL;
	ldi_handle_t	lh = NULL;
	int		param;
	int		rval;
	char		pathname[MSU_PATHNAME_SIZE];
	char		wrkbuf[MSU_PATHNAME_SIZE];

	/* Create physical path-name for serial */
	(void) ddi_pathname(dip, wrkbuf);
	*(wrkbuf + strlen(wrkbuf)) = '\0';
	(void) sprintf(pathname, "/devices%s:%c", wrkbuf,
	    'a'+ ddi_get_instance(dip));

	/* Allocate LDI identifier */
	rval = ldi_ident_from_dip(dip, &li);
	if (rval != 0) {
		cmn_err(CE_WARN, "oplmsu: plink-serial: "
		    "%s ldi_ident_from_dip failed. errno = %d", pathname, rval);
		return (rval);
	}

	/* Open serial */
	rval = ldi_open_by_name(pathname, (FREAD|FWRITE|FEXCL), kcred, &lh, li);
	if (rval != 0) {
		cmn_err(CE_WARN, "oplmsu: plink-serial: "
		    "%s open failed. errno = %d", pathname, rval);
		ldi_ident_release(li);
		return (rval);
	}

	/* Try to remove the top module from the stream */
	param = 0;
	while ((ldi_ioctl(lh, I_POP, (intptr_t)0, FKIOCTL, kcred, &param))
	    == 0) {
		continue;
	}

	/* Issue ioctl(I_PLINK) */
	param = 0;
	rval = ldi_ioctl(msu_lh, I_PLINK, (intptr_t)lh, FKIOCTL, kcred, &param);
	if (rval != 0) {
		cmn_err(CE_WARN, "oplmsu: plink-serial: "
		    "%s ioctl(I_PLINK) failed. errno = %d", pathname, rval);
	}

	(void) ldi_close(lh, (FREAD|FWRITE|FEXCL), kcred);
	ldi_ident_release(li);

	*id = param;	/* Save link-id */
	return (rval);
}

int
oplmsu_set_lpathnum(int lnk_id, int instance)
{
	lpath_t	*lpath;
	int	rval = SUCCESS;

	rw_enter(&oplmsu_uinst->lock, RW_READER);
	mutex_enter(&oplmsu_uinst->l_lock);
	lpath = oplmsu_uinst->first_lpath;
	while (lpath) {
		if ((lpath->path_no == UNDEFINED) &&
		    (lpath->link_id == lnk_id)) {
			lpath->path_no = instance; /* Set instance number */
			lpath->src_upath = NULL;
			lpath->status = MSU_SETID_NU;
			break;
		}
		lpath = lpath->l_next;
	}
	mutex_exit(&oplmsu_uinst->l_lock);
	rw_exit(&oplmsu_uinst->lock);

	if (lpath == NULL) {
		rval = EINVAL;
	}
	return (rval);
}

int
oplmsu_dr_attach(dev_info_t *dip)
{
	ldi_ident_t	msu_li = NULL;
	ldi_handle_t	msu_lh = NULL;
	upath_t		*upath;
	int		len;
	int		instance;
	int		lnk_id = 0;
	int		param = 0;
	int		rval;

	/* Get instance for serial */
	instance = ddi_get_instance(dip);

	rw_enter(&oplmsu_uinst->lock, RW_WRITER);
	mutex_enter(&oplmsu_uinst->u_lock);

	/* Get current number of paths */
	oplmsu_uinst->path_num = oplmsu_get_pathnum();

	/* Check specified upath_t */
	upath = oplmsu_uinst->first_upath;
	while (upath) {
		if (instance == upath->path_no) {
			break;
		}
		upath = upath->u_next;
	}
	mutex_exit(&oplmsu_uinst->u_lock);
	rw_exit(&oplmsu_uinst->lock);

	if (upath != NULL) {
		cmn_err(CE_WARN, "oplmsu: attach(dr): "
		    "Instance %d already exist", instance);
		return (EINVAL);
	}

	/* Open oplmsu */
	rval = oplmsu_open_msu(oplmsu_uinst->msu_dip, &msu_li, &msu_lh);
	if (rval != 0) {
		cmn_err(CE_WARN, "oplmsu: attach(dr): "
		    "msu open failed. errno = %d", rval);
		return (rval);
	}

	/* Connect two streams */
	rval = oplmsu_plink_serial(dip, msu_lh, &lnk_id);
	if (rval != 0) {
		cmn_err(CE_WARN, "oplmsu: attach(dr): "
		    "i_plink failed. errno = %d", rval);
		(void) ldi_close(msu_lh, (FREAD|FWRITE), kcred);
		ldi_ident_release(msu_li);
		return (rval);
	}

	rval = oplmsu_set_lpathnum(lnk_id, instance);
	if (rval != 0) {
		cmn_err(CE_WARN, "oplmsu: attach(dr): "
		    "Link id %d is not found", lnk_id);
		/* Issue ioctl(I_PUNLINK) */
		(void) ldi_ioctl(msu_lh, I_PUNLINK, (intptr_t)lnk_id, FKIOCTL,
		    kcred, &param);
		(void) ldi_close(msu_lh, (FREAD|FWRITE), kcred);
		ldi_ident_release(msu_li);
		return (rval);
	}

	/* Add the path */
	rval = oplmsu_config_add(dip);
	if (rval != 0) {
		cmn_err(CE_WARN, "oplmsu: attach(dr): "
		    "Failed to add the path. errno = %d", rval);
		/* Issue ioctl(I_PUNLINK) */
		(void) ldi_ioctl(msu_lh, I_PUNLINK, (intptr_t)lnk_id, FKIOCTL,
		    kcred, &param);

		(void) ldi_close(msu_lh, (FREAD|FWRITE), kcred);
		ldi_ident_release(msu_li);
		return (rval);
	}

	/* Start to use the path */
	rval = oplmsu_config_start(instance);
	if (rval != 0) {
		struct msu_path	*mpath;
		struct msu_dev	*mdev;

		cmn_err(CE_WARN, "oplmsu: attach(dr): "
		    "Failed to start the path. errno = %d", rval);

		len = sizeof (struct msu_path) + sizeof (struct msu_dev);
		mpath = (struct msu_path *)kmem_zalloc((size_t)len, KM_SLEEP);
		mpath->num = 1;
		mdev = (struct msu_dev *)(mpath + 1);
		mdev->dip = dip;

		/* Delete the path */
		if ((oplmsu_config_del(mpath)) == 0) {
			/* Issue ioctl(I_PUNLINK) */
			(void) ldi_ioctl(msu_lh, I_PUNLINK, (intptr_t)lnk_id,
			    FKIOCTL, kcred, &param);
		}
		kmem_free(mpath, (size_t)len);
	}

	/* Close oplmsu */
	(void) ldi_close(msu_lh, (FREAD|FWRITE), kcred);
	ldi_ident_release(msu_li);
	return (rval);
}

int
oplmsu_dr_detach(dev_info_t *dip)
{
	ldi_ident_t	msu_li = NULL;
	ldi_handle_t	msu_lh = NULL;
	struct msu_path	*mpath;
	struct msu_dev	*mdev;
	upath_t		*upath;
	lpath_t		*lpath;
	int		len;
	int		instance;
	int		count = 0;
	int		param = 0;
	int		status;
	int		rval;

	/* Get instance for serial */
	instance = ddi_get_instance(dip);

	rw_enter(&oplmsu_uinst->lock, RW_WRITER);
	mutex_enter(&oplmsu_uinst->u_lock);

	/* Get current number of paths */
	oplmsu_uinst->path_num = oplmsu_get_pathnum();

	rval = FAILURE;

	/* Check specified upath_t */
	upath = oplmsu_uinst->first_upath;
	while (upath) {
		if (instance == upath->path_no) {
			/* Save status of specified path */
			status = upath->status;
			rval = SUCCESS;
		}
		upath = upath->u_next;
		count += 1;
	}
	mutex_exit(&oplmsu_uinst->u_lock);
	rw_exit(&oplmsu_uinst->lock);

	if (rval == FAILURE) {
		if (count <= 1) {
			cmn_err(CE_WARN, "oplmsu: detach(dr): "
			    "Instance %d is last path", instance);
		} else {
			cmn_err(CE_WARN, "oplmsu: detach(dr): "
			    "Instance %d doesn't find", instance);
		}
		return (EINVAL);
	}

	/* Check status of specified path */
	if ((status == MSU_PSTAT_ACTIVE) || (status == MSU_PSTAT_STANDBY)) {
		/* Stop to use the path */
		rval = oplmsu_config_stop(instance);
		if (rval != 0) {
			cmn_err(CE_WARN, "oplmsu: detach(dr): "
			    "Failed to stop the path. errno = %d", rval);
			return (rval);
		}
	}

	/* Prepare to unlink the path */
	rval = oplmsu_config_disc(instance);
	if (rval != 0) {
		cmn_err(CE_WARN, "oplmsu: detach(dr): "
		    "Failed to disconnect the path. errno = %d", rval);
		return (rval);
	}

	rw_enter(&oplmsu_uinst->lock, RW_READER);
	mutex_enter(&oplmsu_uinst->l_lock);
	lpath = oplmsu_uinst->first_lpath;
	while (lpath) {
		if (lpath->path_no == instance) { /* Get link ID */
			break;
		}
		lpath = lpath->l_next;
	}
	mutex_exit(&oplmsu_uinst->l_lock);
	rw_exit(&oplmsu_uinst->lock);

	if (lpath == NULL) {
		cmn_err(CE_WARN, "oplmsu: detach(dr): Can not find link ID");
		return (EINVAL);
	}

	/* Open oplmsu */
	rval = oplmsu_open_msu(oplmsu_uinst->msu_dip, &msu_li, &msu_lh);
	if (rval != 0) {
		cmn_err(CE_WARN, "oplmsu: detach(dr): "
		    "msu open failed. errno = %d", rval);
		return (rval);
	}

	/* Issue ioctl(I_PUNLINK) */
	rval = ldi_ioctl(msu_lh, I_PUNLINK, (intptr_t)lpath->link_id, FKIOCTL,
	    kcred, &param);
	if (rval != 0) {
		cmn_err(CE_WARN, "oplmsu: detach(dr): "
		    "ioctl(I_PUNLINK) failed. errno = %d", rval);
		(void) ldi_close(msu_lh, (FREAD|FWRITE), kcred);
		ldi_ident_release(msu_li);
		return (rval);
	}

	/* Close oplmsu(meta node) */
	(void) ldi_close(msu_lh, (FREAD|FWRITE), kcred);
	ldi_ident_release(msu_li);

	len = sizeof (struct msu_path) + sizeof (struct msu_dev);
	mpath = (struct msu_path *)kmem_zalloc((size_t)len, KM_SLEEP);
	mpath->num = 1;
	mdev = (struct msu_dev *)(mpath + 1);
	mdev->dip = dip;

	/* Delete the path */
	rval = oplmsu_config_del(mpath);
	if (rval != 0) {
		cmn_err(CE_WARN, "oplmsu: detach(dr): "
		    "Failed to delete the path. errno = %d", rval);
	}

	kmem_free(mpath, (size_t)len);
	return (rval);
}

/*
 * The ebus and the serial device path under a given CMU_CH chip
 * is expected to be always at the same address. So, it is safe
 * to hard-code the pathnames as below.
 */
#define	EBUS_PATH		"ebus@1"
#define	SERIAL_PATH		"serial@14,400000"
#define	EBUS_SERIAL_PATH	("/" EBUS_PATH "/" SERIAL_PATH)

/*
 * Given the CMU_CH dip, find the serial device dip.
 */
dev_info_t *
oplmsu_find_ser_dip(dev_info_t *cmuch_dip)
{
	dev_info_t	*ebus_dip;
	dev_info_t	*ser_dip = NULL;

	ndi_devi_enter(cmuch_dip);
	ebus_dip = ndi_devi_findchild(cmuch_dip, EBUS_PATH);

	DBG_PRINT((CE_NOTE, "oplmsu: find-serial-dip: "
	    "ebus_dip = %p", (void *)ebus_dip));

	if (ebus_dip != NULL) {
		ndi_devi_enter(ebus_dip);
		ser_dip = ndi_devi_findchild(ebus_dip, SERIAL_PATH);

		DBG_PRINT((CE_NOTE, "oplmsu: find-serial-dip: "
		    "ser_dip = %p", (void *)ser_dip));
		ndi_devi_exit(ebus_dip);
	}
	ndi_devi_exit(cmuch_dip);
	return (ser_dip);
}

/*
 * Find all console related serial devices.
 */
int
oplmsu_find_serial(ser_devl_t **ser_dl)
{
	dev_info_t	*root_dip;
	dev_info_t	*cmuch_dip;
	dev_info_t	*dip;
	ser_devl_t	*wrk_ser_dl;
	int		count = 0;
	char		pathname[MSU_PATHNAME_SIZE];
	dev_t		devt;
	char		*namep;

	root_dip = ddi_root_node();
	ndi_devi_enter(root_dip);
	cmuch_dip = ddi_get_child(root_dip);

	while (cmuch_dip != NULL) {
		namep = ddi_binding_name(cmuch_dip);	/* Get binding name */
		if (namep == NULL) {
			cmuch_dip = ddi_get_next_sibling(cmuch_dip);
			continue;
		}

		DBG_PRINT((CE_NOTE, "oplmsu: find-serial: name => %s", namep));

		if ((strcmp(namep, MSU_CMUCH_FF) != 0) &&
		    (strcmp(namep, MSU_CMUCH_DC) != 0)) {
#ifdef DEBUG
			if (strcmp(namep, MSU_CMUCH_DBG) != 0) {
				cmuch_dip = ddi_get_next_sibling(cmuch_dip);
				continue;
			}
#else
			cmuch_dip = ddi_get_next_sibling(cmuch_dip);
			continue;
#endif
		}

		/*
		 * Online the cmuch_dip so that its in the right state
		 * to get the complete path, that is both name and address.
		 */
		(void) ndi_devi_online(cmuch_dip, 0);
		(void) ddi_pathname(cmuch_dip, pathname);
		DBG_PRINT((CE_NOTE,
		    "oplmsu: find-serial: cmu-ch path => %s", pathname));
		(void) strcat(pathname, EBUS_SERIAL_PATH);

		/*
		 * Call ddi_pathname_to_dev_t to forceload and attach
		 * the required drivers.
		 */
		devt = ddi_pathname_to_dev_t(pathname);
		DBG_PRINT((CE_NOTE, "oplmsu: find-serial: serial device "
		    "dev_t = %lx", devt));
		if ((devt != NODEV) &&
		    ((dip = oplmsu_find_ser_dip(cmuch_dip)) != NULL)) {
			wrk_ser_dl = (ser_devl_t *)
			    kmem_zalloc(sizeof (ser_devl_t), KM_SLEEP);
			wrk_ser_dl->dip = dip;
			count += 1;

			if (*ser_dl != NULL) {
				wrk_ser_dl->next = *ser_dl;
			}
			*ser_dl = wrk_ser_dl;
		}
		cmuch_dip = ddi_get_next_sibling(cmuch_dip);
	}
	ndi_devi_exit(root_dip);
	return (count);
}

/* Configure STREAM */
void
oplmsu_conf_stream(uinst_t *msu_uinst)
{
	ldi_ident_t	msu_li = NULL;
	ldi_handle_t	msu_lh = NULL;
	struct msu_path	*mpath;
	struct msu_dev	*mdev;
	ser_devl_t	*ser_dl = NULL, *next_ser_dl;
	int		*plink_id;
	int		size;
	int		i;
	int		param;
	int		connected = 0;
	int		devcnt = 0;
	int		rval;

	DBG_PRINT((CE_NOTE,
	    "oplmsu: conf-stream: stream configuration start!"));

	/* Find serial devices */
	devcnt = oplmsu_find_serial(&ser_dl);
	if ((devcnt == 0) || (ser_dl == NULL)) {
		cmn_err(CE_WARN, "oplmsu: conf-stream: "
		    "Discovered serial device = %d", devcnt);
		return;
	}

	/* Open oplmsu */
	rval = oplmsu_open_msu(msu_uinst->msu_dip, &msu_li, &msu_lh);
	if (rval != 0) {
		cmn_err(CE_WARN, "oplmsu: conf-stream: "
		    "msu open failed. errno = %d", rval);
		return;
	}

	size = (sizeof (struct msu_path) + (sizeof (struct msu_dev) * devcnt));
	mpath = (struct msu_path *)kmem_zalloc((size_t)size, KM_SLEEP);
	plink_id = (int *)kmem_zalloc((sizeof (int) * devcnt), KM_SLEEP);

	mdev = (struct msu_dev *)(mpath + 1);
	for (i = 0; i < devcnt; i++) {
		/* Connect two streams */
		rval = oplmsu_plink_serial(ser_dl->dip, msu_lh, &plink_id[i]);
		if (rval != 0) {
			cmn_err(CE_WARN, "oplmsu: conf-stream: "
			    "i_plink failed. errno = %d", rval);
			next_ser_dl = ser_dl->next;
			kmem_free(ser_dl, sizeof (ser_devl_t));
			ser_dl = next_ser_dl;
			continue;
		}

		rval = oplmsu_set_lpathnum(plink_id[i],
		    ddi_get_instance(ser_dl->dip));
		if (rval != 0) {
			cmn_err(CE_WARN, "oplmsu: conf-stream: "
			    "Link id %d is not found", plink_id[i]);
			/* Issue ioctl(I_PUNLINK) */
			(void) ldi_ioctl(msu_lh, I_PUNLINK,
			    (intptr_t)plink_id[i], FKIOCTL, kcred, &param);
			next_ser_dl = ser_dl->next;
			kmem_free(ser_dl, sizeof (ser_devl_t));
			ser_dl = next_ser_dl;
			continue;
		}

		mdev->dip = ser_dl->dip;
		next_ser_dl = ser_dl->next;
		kmem_free(ser_dl, sizeof (ser_devl_t));
		ser_dl = next_ser_dl;

		mdev++;
		connected++;
	}

	if (connected == 0) {
		cmn_err(CE_WARN, "oplmsu: conf-stream: "
		    "Connected paths = %d", connected);
		(void) ldi_close(msu_lh, (FREAD|FWRITE), kcred);
		ldi_ident_release(msu_li);
		kmem_free(plink_id, (sizeof (int) * devcnt));
		kmem_free(mpath, size);
		return;
	}

	/* Setup all structure */
	mpath->num = connected;
	rval = oplmsu_config_new(mpath);
	if (rval != 0) {
		cmn_err(CE_WARN, "oplmsu: conf-stream: "
		    "Failed to create all paths. errno = %d", rval);
		oplmsu_unlinks(msu_lh, plink_id, devcnt);
		(void) ldi_close(msu_lh, (FREAD|FWRITE), kcred);
		ldi_ident_release(msu_li);
		kmem_free(plink_id, (sizeof (int) * devcnt));
		kmem_free(mpath, size);
		return;
	}

	/* Start to use all paths */
	rval = oplmsu_config_start(MSU_PATH_ALL);
	if (rval != 0) {
		cmn_err(CE_WARN, "oplmsu: conf-stream: "
		    "Failed to start all paths. errno = %d", rval);

		/* Delete the path */
		rval = oplmsu_config_del(mpath);
		if (rval == 0) {
			oplmsu_unlinks(msu_lh, plink_id, devcnt);
		}
	}

	(void) ldi_close(msu_lh, (FREAD|FWRITE), kcred);
	ldi_ident_release(msu_li);
	kmem_free(plink_id, (sizeof (int) * devcnt));
	kmem_free(mpath, size);

	DBG_PRINT((CE_NOTE, "oplmsu: conf-stream: stream configuration end!"));
}

void
oplmsu_unlinks(ldi_handle_t msu_lh, int *plink_id, int devcnt)
{
	int	i;
	int	param = 0;

	for (i = 0; i < devcnt; i++) {
		if (plink_id[i] == 0) {
			continue;
		}

		/* Issue ioctl(I_PUNLINK) */
		(void) ldi_ioctl(msu_lh, I_PUNLINK, (intptr_t)plink_id[i],
		    FKIOCTL, kcred, &param);
	}
}

void
oplmsu_setup(uinst_t *msu_uinst)
{

	DBG_PRINT((CE_NOTE, "oplmsu: setup: Background thread start!"));

	mutex_enter(&oplmsu_bthrd_excl);
	if (oplmsu_conf_st == MSU_CONFIGURING) {
		mutex_exit(&oplmsu_bthrd_excl);
		oplmsu_conf_stream(msu_uinst);	/* Configure stream */
		mutex_enter(&oplmsu_bthrd_excl);
		oplmsu_conf_st = MSU_CONFIGURED;
		cv_broadcast(&oplmsu_conf_cv);	/* Wake up from cv_wait_sig() */
	}

	if (oplmsu_bthrd_id != NULL) {
		oplmsu_bthrd_id = NULL;
	}
	mutex_exit(&oplmsu_bthrd_excl);

	DBG_PRINT((CE_NOTE, "oplmsu: setup: Background thread end!"));

	thread_exit();
}

int
oplmsu_create_upath(dev_info_t *dip)
{
	upath_t		*upath;
	lpath_t		*lpath;
	dev_info_t	*cmuch_dip;
	int		instance;
	int		lsb;

	cmuch_dip = ddi_get_parent(ddi_get_parent(dip));
	lsb = ddi_prop_get_int(DDI_DEV_T_ANY, cmuch_dip, 0, MSU_BOARD_PROP,
	    FAILURE);
	if (lsb == FAILURE) {
		return (lsb);
	}

	instance = ddi_get_instance(dip);

	mutex_enter(&oplmsu_uinst->l_lock);
	lpath = oplmsu_uinst->first_lpath;
	while (lpath) {
		if (lpath->path_no == instance) {
			break;
		}
		lpath = lpath->l_next;
	}

	if (lpath == NULL) {
		mutex_exit(&oplmsu_uinst->l_lock);
		return (ENODEV);
	}

	upath = (upath_t *)kmem_zalloc(sizeof (upath_t), KM_SLEEP);

	/*
	 * Initialize members of upath_t
	 */

	upath->path_no = instance;
	upath->lpath = lpath;
	upath->ser_devcb.dip = dip;
	upath->ser_devcb.lsb = lsb;
	oplmsu_cmn_set_upath_sts(upath, MSU_PSTAT_STOP, MSU_PSTAT_EMPTY,
	    MSU_STOP);

	lpath->src_upath = NULL;
	lpath->status = MSU_EXT_NOTUSED;
	mutex_exit(&oplmsu_uinst->l_lock);

	oplmsu_link_upath(upath);
	return (SUCCESS);
}

/* Setup new upper instance structure */
int
oplmsu_config_new(struct msu_path *mpath)
{
	struct msu_dev	*mdev;
	int		i;
	int		rval = SUCCESS;

	DBG_PRINT((CE_NOTE, "oplmsu: conf-new: config_new() called"));
	ASSERT(mpath);

	if (mpath->num == 0) {
		cmn_err(CE_WARN, "oplmsu: conf-new: "
		    "Number of paths = %d", mpath->num);
		return (EINVAL);
	}

	rw_enter(&oplmsu_uinst->lock, RW_WRITER);

	mutex_enter(&oplmsu_uinst->l_lock);
	rval = oplmsu_check_lpath_usable();
	mutex_exit(&oplmsu_uinst->l_lock);

	if (rval == BUSY) { /* Check whether Lower path is usable */
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: conf-new: "
		    "Other processing is using this device");
		return (EBUSY);
	}

	/*
	 * Because the OPLMSU instance already exists when the upper path
	 * table exists, the configure_new processing cannot be done.
	 */

	mutex_enter(&oplmsu_uinst->u_lock);

	if ((oplmsu_uinst->first_upath != NULL) ||
	    (oplmsu_uinst->last_upath != NULL)) {
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: conf-new: upath_t already exist");
		return (EINVAL);
	}

	/*
	 * Because the config_new processing has already been done
	 * if oplmsu_uinst->path_num isn't -1, this processing cannot be
	 * continued.
	 */

	if (oplmsu_uinst->path_num != UNDEFINED) {
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: conf-new: "
		    "conf-new processing has already been completed");
		return (EINVAL);
	}

	/*
	 * Only the number of specified paths makes the upper path
	 * information tables.
	 */

	mdev = (struct msu_dev *)(mpath + 1);
	for (i = 0; i < mpath->num; i++) {
		/*
		 * Associate upper path information table with lower path
		 * information table.
		 *
		 * If the upper path information table and the lower path
		 * information table cannot be associated, the link list of
		 * the upper path information table is released.
		 */
		rval = oplmsu_create_upath(mdev->dip);
		if (rval != SUCCESS) {
			oplmsu_delete_upath_info();
			mutex_exit(&oplmsu_uinst->u_lock);
			rw_exit(&oplmsu_uinst->lock);
			cmn_err(CE_WARN, "oplmsu: conf-new: "
			    "Failed to create upath %d", rval);
			return (rval);
		}

		mdev++;
	}

	/*
	 * Setup members of uinst_t
	 */

	oplmsu_uinst->inst_status = oplmsu_get_inst_status();
	oplmsu_uinst->path_num = mpath->num;
	oplmsu_uinst->lower_queue = NULL;
	mutex_exit(&oplmsu_uinst->u_lock);
	rw_exit(&oplmsu_uinst->lock);
	return (SUCCESS);
}

/* Add path information */
int
oplmsu_config_add(dev_info_t *dip)
{
	upath_t	*upath;
	int	instance;
	int	rval = SUCCESS;

	DBG_PRINT((CE_NOTE, "oplmsu: conf-add: config_add() called"));
	ASSERT(dip);

	instance = ddi_get_instance(dip);
	rw_enter(&oplmsu_uinst->lock, RW_WRITER);

	if (oplmsu_uinst->path_num == UNDEFINED) {
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: conf-add: "
		    "conf-new processing has not been completed yet");
		return (EINVAL);
	}

	mutex_enter(&oplmsu_uinst->u_lock);
	upath = oplmsu_search_upath_info(instance);
	if (upath != NULL) {
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: conf-add: "
		    "Proper upath_t doesn't find");
		return (EINVAL);
	}

	rval = oplmsu_create_upath(dip);
	if (rval != SUCCESS) {
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: conf-add: "
		    "Failed to create upath %d", rval);
		return (rval);
	}

	oplmsu_uinst->inst_status = oplmsu_get_inst_status();
	oplmsu_uinst->path_num = oplmsu_get_pathnum();
	mutex_exit(&oplmsu_uinst->u_lock);
	rw_exit(&oplmsu_uinst->lock);
	return (SUCCESS);
}

/* Delete each path information */
int
oplmsu_config_del(struct msu_path *mpath)
{
	struct msu_dev	*mdev;
	upath_t		*upath;
	lpath_t		*lpath;
	int		rval = SUCCESS;
	int		use_flag;
	int		i;

	DBG_PRINT((CE_NOTE, "oplmsu: conf-del: config_del() called"));
	ASSERT(mpath);

	mdev = (struct msu_dev *)(mpath + 1);

	rw_enter(&oplmsu_uinst->lock, RW_WRITER);
	mutex_enter(&oplmsu_uinst->u_lock);
	for (i = 0; i < mpath->num; i++) {
		upath = oplmsu_search_upath_info(ddi_get_instance(mdev->dip));
		if (upath == NULL) {
			cmn_err(CE_WARN, "oplmsu: conf-del: "
			    "Proper upath_t doesn't find");
			rval = ENODEV;
			mdev++;
			continue;
		}

		lpath = upath->lpath;
		if (lpath == NULL) {
			if ((upath->traditional_status == MSU_WSTP_ACK) ||
			    (upath->traditional_status == MSU_WSTR_ACK) ||
			    (upath->traditional_status == MSU_WPTH_CHG) ||
			    (upath->traditional_status == MSU_WTCS_ACK) ||
			    (upath->traditional_status == MSU_WTMS_ACK) ||
			    (upath->traditional_status == MSU_WPPS_ACK) ||
			    (upath->traditional_status == MSU_WWSZ_ACK) ||
			    (upath->traditional_status == MSU_WCAR_ACK)) {
				cmn_err(CE_WARN, "oplmsu: conf-del: "
				    "Other processing is using this device");
				rval = EBUSY;
				mdev++;
				continue;
			}

			if ((upath->status != MSU_PSTAT_DISCON) ||
			    (upath->traditional_status != MSU_DISCON)) {
				cmn_err(CE_WARN, "oplmsu: conf-del: "
				    "Status of path is improper");
				rval = EINVAL;
				mdev++;
				continue;
			}
		} else {
			mutex_enter(&oplmsu_uinst->l_lock);
			use_flag = oplmsu_set_ioctl_path(lpath, NULL, NULL);
			if (use_flag == BUSY) {
				mutex_exit(&oplmsu_uinst->l_lock);
				cmn_err(CE_WARN, "oplmsu: conf-del: "
				    "Other processing is using lower path");
				rval = EBUSY;
				mdev++;
				continue;
			}

			if (((upath->status != MSU_PSTAT_STOP) ||
			    (upath->traditional_status != MSU_STOP)) &&
			    ((upath->status != MSU_PSTAT_FAIL) ||
			    (upath->traditional_status != MSU_FAIL))) {
				oplmsu_clear_ioctl_path(lpath);
				mutex_exit(&oplmsu_uinst->l_lock);
				cmn_err(CE_WARN, "oplmsu: conf-del: "
				    "Status of path isn't 'Offline:stop/fail'");
				rval = EINVAL;
				mdev++;
				continue;
			}
			lpath->src_upath = NULL;
			lpath->status = MSU_SETID_NU;
			oplmsu_clear_ioctl_path(lpath);
			mutex_exit(&oplmsu_uinst->l_lock);
		}
		oplmsu_unlink_upath(upath);	/* Unlink upath_t */
		kmem_free(upath, sizeof (upath_t));
		mdev++;
	}

	oplmsu_uinst->inst_status = oplmsu_get_inst_status();
	oplmsu_uinst->path_num = oplmsu_get_pathnum();
	mutex_exit(&oplmsu_uinst->u_lock);
	rw_exit(&oplmsu_uinst->lock);
	return (rval);
}

/* Stop to use the path */
int
oplmsu_config_stop(int pathnum)
{
	upath_t	*upath, *altn_upath;
	lpath_t	*lpath, *altn_lpath;
	queue_t	*stp_queue = NULL;
	queue_t	*dst_queue = NULL;
	mblk_t	*nmp = NULL, *fmp = NULL;
	ctrl_t	*ctrl;
	int	term_ioctl, term_stat;
	int	use_flag;

	DBG_PRINT((CE_NOTE,
	    "oplmsu: conf-stop: config_stop(%d) called", pathnum));

	if (pathnum == MSU_PATH_ALL) {
		cmn_err(CE_WARN, "oplmsu: conf-stop: "
		    "All path can't be transferred to the status of "
		    "'Offline:stop'");
		return (EINVAL);
	}

	rw_enter(&oplmsu_uinst->lock, RW_WRITER);
	mutex_enter(&oplmsu_uinst->u_lock);

	upath = oplmsu_search_upath_info(pathnum);	/* Search upath_t */
	if (upath == NULL) {
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: conf-stop: "
		    "Proper upath_t doesn't find");
		return (ENODEV);
	}

	lpath = upath->lpath;
	if (lpath == NULL) {
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: conf-stop: "
		    "Proper lpath_t doesn't exist");
		return (ENODEV);
	}

	mutex_enter(&oplmsu_uinst->l_lock);

	/* Check status of lpath_t */
	use_flag = oplmsu_set_ioctl_path(lpath, NULL, NULL);
	if (use_flag == BUSY) {
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: conf-stop: "
		    "Other processing is using lower path");
		return (EBUSY);
	}

	if (upath->status == MSU_PSTAT_FAIL) {
		oplmsu_clear_ioctl_path(lpath);
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		return (EIO);
	} else if ((upath->status == MSU_PSTAT_STOP) &&
	    (upath->traditional_status == MSU_STOP)) {
		oplmsu_clear_ioctl_path(lpath);
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		return (SUCCESS);
	} else if ((upath->status == MSU_PSTAT_STANDBY) &&
	    (upath->traditional_status == MSU_STANDBY)) {
		oplmsu_cmn_set_upath_sts(upath, MSU_PSTAT_STOP,
		    upath->status, MSU_STOP);
		oplmsu_clear_ioctl_path(lpath);
		lpath->src_upath = NULL;
		lpath->status = MSU_EXT_NOTUSED;

		oplmsu_uinst->inst_status = oplmsu_get_inst_status();
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		return (SUCCESS);
	} else if ((upath->status == MSU_PSTAT_ACTIVE) &&
	    (upath->traditional_status == MSU_ACTIVE)) {
		altn_upath = oplmsu_search_standby();
		if (altn_upath == NULL) { /* Alternate path doesn't exist */
			DBG_PRINT((CE_NOTE, "oplmsu: conf-stop: "
			    "Alternate upper path doesn't find"));
			oplmsu_clear_ioctl_path(lpath);
			mutex_exit(&oplmsu_uinst->l_lock);
			mutex_exit(&oplmsu_uinst->u_lock);
			rw_exit(&oplmsu_uinst->lock);
			return (EINVAL);
		}

		if ((fmp = allocb(sizeof (char), BPRI_LO)) == NULL) {
			oplmsu_clear_ioctl_path(lpath);
			mutex_exit(&oplmsu_uinst->l_lock);
			mutex_exit(&oplmsu_uinst->u_lock);
			rw_exit(&oplmsu_uinst->lock);
			return (ENOSR);
		}

		if (oplmsu_stop_prechg(&nmp, &term_ioctl, &term_stat) !=
		    SUCCESS) {
			oplmsu_clear_ioctl_path(lpath);
			mutex_exit(&oplmsu_uinst->l_lock);
			mutex_exit(&oplmsu_uinst->u_lock);
			rw_exit(&oplmsu_uinst->lock);
			freeb(fmp);
			return (ENOSR);
		}

		altn_lpath = altn_upath->lpath;
		use_flag = oplmsu_set_ioctl_path(altn_lpath, NULL, NULL);
		if (use_flag == BUSY) {
			oplmsu_clear_ioctl_path(lpath);
			mutex_exit(&oplmsu_uinst->l_lock);
			mutex_exit(&oplmsu_uinst->u_lock);
			rw_exit(&oplmsu_uinst->lock);

			cmn_err(CE_WARN, "oplmsu: conf-stop: "
			    "Other processing is using alternate lower path");
			freeb(fmp);
			freemsg(nmp);
			return (EBUSY);
		}

		dst_queue = WR(altn_lpath->lower_queue);

		/* termios is not held. Change alternate path to MSU_ACTIVE */
		if (nmp == NULL) {
			altn_upath->traditional_status = term_stat;
			altn_lpath->src_upath = upath;
			altn_lpath->status = MSU_EXT_VOID;

			oplmsu_uinst->lower_queue = NULL;

			ctrl = oplmsu_uinst->user_ctrl;
			if (ctrl != NULL) {
				mutex_enter(&oplmsu_uinst->c_lock);
				stp_queue = WR(ctrl->queue);
				mutex_exit(&oplmsu_uinst->c_lock);
				noenable(stp_queue);
				oplmsu_queue_flag = 1;
			}

			/* Make M_FLUSH and send to alternate path */
			oplmsu_cmn_set_mflush(fmp);
			(void) putq(dst_queue, fmp);

			/* Change status of alternate path */
			oplmsu_cmn_set_upath_sts(altn_upath, MSU_PSTAT_ACTIVE,
			    altn_upath->status, MSU_ACTIVE);

			oplmsu_clear_ioctl_path(altn_lpath);
			altn_lpath->uinst = oplmsu_uinst;
			altn_lpath->src_upath = NULL;
			altn_lpath->status = MSU_EXT_NOTUSED;

			/* Notify of the active path changing */
			(void) prom_opl_switch_console(
			    altn_upath->ser_devcb.lsb);

			/* Send XON to notify active path */
			(void) oplmsu_cmn_put_xoffxon(dst_queue, MSU_XON_4);

			/* Send XOFF to notify all standby paths */
			oplmsu_cmn_putxoff_standby();

			oplmsu_uinst->lower_queue = RD(dst_queue);
			ctrl = oplmsu_uinst->user_ctrl;

			/* Switch active path of oplmsu */
			if (ctrl != NULL) {
				queue_t	*altn_queue;

				mutex_enter(&oplmsu_uinst->c_lock);
				altn_queue = WR(ctrl->queue);
				mutex_exit(&oplmsu_uinst->c_lock);

				/* Restart queuing of user access node */
				enableok(altn_queue);

				oplmsu_queue_flag = 0;
				mutex_exit(&oplmsu_uinst->l_lock);
				mutex_exit(&oplmsu_uinst->u_lock);
				oplmsu_wcmn_high_qenable(altn_queue, RW_WRITER);
				mutex_enter(&oplmsu_uinst->u_lock);
				mutex_enter(&oplmsu_uinst->l_lock);
			}

			/* Stop previous active path */
			oplmsu_cmn_set_upath_sts(upath, MSU_PSTAT_STOP,
			    upath->status, MSU_STOP);

			lpath->uinst = NULL;
			lpath->src_upath = NULL;
			lpath->status = MSU_EXT_NOTUSED;
			oplmsu_clear_ioctl_path(lpath);

			oplmsu_uinst->inst_status = oplmsu_get_inst_status();
			mutex_exit(&oplmsu_uinst->l_lock);
			mutex_exit(&oplmsu_uinst->u_lock);
			rw_exit(&oplmsu_uinst->lock);
			return (SUCCESS);
		}

		/* Send termios information to alternate path */
		if (canput(dst_queue)) {
			altn_upath->traditional_status = term_stat;
			altn_lpath->src_upath = upath;
			altn_lpath->status = MSU_EXT_VOID;

			upath->traditional_status = MSU_WSTP_ACK;
			lpath->uinst = NULL;

			oplmsu_uinst->lower_queue = NULL;

			ctrl = oplmsu_uinst->user_ctrl;
			if (ctrl != NULL) {
				mutex_enter(&oplmsu_uinst->c_lock);
				stp_queue = WR(ctrl->queue);
				mutex_exit(&oplmsu_uinst->c_lock);
				noenable(stp_queue);
				oplmsu_queue_flag = 1;
			}

			mutex_exit(&oplmsu_uinst->l_lock);
			mutex_exit(&oplmsu_uinst->u_lock);
			rw_exit(&oplmsu_uinst->lock);
			oplmsu_cmn_set_mflush(fmp);
			(void) putq(dst_queue, fmp);
			(void) putq(dst_queue, nmp);

			mutex_enter(&oplmsu_uinst->l_lock);
			lpath->sw_flag = 1;
			while (lpath->sw_flag != 0) {
				/* Wait for the completion of path switching */
				cv_wait(&lpath->sw_cv, &oplmsu_uinst->l_lock);
			}
			mutex_exit(&oplmsu_uinst->l_lock);
			return (SUCCESS);
		} else {
			oplmsu_clear_ioctl_path(altn_lpath);
			oplmsu_clear_ioctl_path(lpath);
			mutex_exit(&oplmsu_uinst->l_lock);
			mutex_exit(&oplmsu_uinst->u_lock);
			rw_exit(&oplmsu_uinst->lock);
			freeb(fmp);
			freemsg(nmp);
			return (FAILURE);
		}
		/* NOTREACHED */
	} else {
		oplmsu_clear_ioctl_path(lpath);
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);

		cmn_err(CE_WARN, "oplmsu: conf-stop: "
		    "Status of path is improper");
		return (EINVAL);
	}
	/* NOTREACHED */
}

/* Start to use path */
int
oplmsu_config_start(int pathnum)
{
	upath_t	*upath = NULL;
	lpath_t	*lpath = NULL;
	queue_t	*dst_queue, *main_rq = NULL;
	int	msu_tty_port;

	DBG_PRINT((CE_NOTE,
	    "oplmsu: conf-start: config_start(%d) called", pathnum));

	rw_enter(&oplmsu_uinst->lock, RW_WRITER);
	mutex_enter(&oplmsu_uinst->u_lock);

	if (oplmsu_get_inst_status() == INST_STAT_BUSY) {
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		return (EBUSY);
	}

	if (pathnum == MSU_PATH_ALL) {
		(void) oplmsu_search_min_stop_path();
	}

	for (upath = oplmsu_uinst->first_upath; upath; ) {
		if ((pathnum != MSU_PATH_ALL) && (upath->path_no != pathnum)) {
			upath = upath->u_next;
			continue;
		}

		if (upath->path_no == pathnum) {
			lpath = upath->lpath;
			if (lpath == NULL) {
				mutex_exit(&oplmsu_uinst->u_lock);
				rw_exit(&oplmsu_uinst->lock);
				cmn_err(CE_WARN, "oplmsu: conf-start: "
				    "Proper lpath_t doesn't exist");
				return (EINVAL);
			}

			oplmsu_cmn_set_upath_sts(upath, MSU_PSTAT_STANDBY,
			    upath->status, MSU_STANDBY);

			mutex_enter(&oplmsu_uinst->l_lock);
			lpath->src_upath = NULL;
			lpath->status = MSU_EXT_NOTUSED;
			mutex_exit(&oplmsu_uinst->l_lock);
			mutex_exit(&oplmsu_uinst->u_lock);
			rw_exit(&oplmsu_uinst->lock);
			return (SUCCESS);
		}

		/*
		 * with PATH_ALL
		 */
		lpath = upath->lpath;
		if (lpath == NULL) {
			upath = upath->u_next;

			DBG_PRINT((CE_WARN, "oplmsu: conf-start: "
			    "Proper lpath_t doesn't exist"));
			continue;
		}

		msu_tty_port = ddi_prop_get_int(DDI_DEV_T_ANY,
		    oplmsu_uinst->msu_dip, 0, MSU_TTY_PORT_PROP, -1);

		if (upath->ser_devcb.lsb == msu_tty_port) {
			/* Notify of the active path changing */
			(void) prom_opl_switch_console(upath->ser_devcb.lsb);

			oplmsu_cmn_set_upath_sts(upath, MSU_PSTAT_ACTIVE,
			    upath->status, MSU_ACTIVE);

			mutex_enter(&oplmsu_uinst->l_lock);
			main_rq = RD(lpath->lower_queue);
			dst_queue = WR(lpath->lower_queue);
			lpath->src_upath = NULL;
			lpath->status = MSU_EXT_NOTUSED;
			lpath->uinst = oplmsu_uinst;
			mutex_exit(&oplmsu_uinst->l_lock);

			/* Send XON to notify active path */
			(void) oplmsu_cmn_put_xoffxon(dst_queue, MSU_XON_4);
		} else {
			oplmsu_cmn_set_upath_sts(upath, MSU_PSTAT_STANDBY,
			    upath->status, MSU_STANDBY);

			mutex_enter(&oplmsu_uinst->l_lock);
			lpath->src_upath = NULL;
			lpath->status = MSU_EXT_NOTUSED;
			mutex_exit(&oplmsu_uinst->l_lock);
		}
		upath = upath->u_next;
	}

	if (main_rq == NULL) {
		upath_t	*altn_upath;
		lpath_t	*altn_lpath;

		altn_upath = oplmsu_search_standby();
		if (altn_upath) {
			oplmsu_cmn_set_upath_sts(altn_upath, MSU_PSTAT_ACTIVE,
			    altn_upath->status, MSU_ACTIVE);

			/* Notify of the active path changing */
			(void) prom_opl_switch_console(
			    altn_upath->ser_devcb.lsb);

			altn_lpath = altn_upath->lpath;
			if (altn_lpath) {
				mutex_enter(&oplmsu_uinst->l_lock);
				main_rq = RD(altn_lpath->lower_queue);
				dst_queue = WR(altn_lpath->lower_queue);
				altn_lpath->src_upath = NULL;
				altn_lpath->status = MSU_EXT_NOTUSED;
				altn_lpath->uinst = oplmsu_uinst;
				mutex_exit(&oplmsu_uinst->l_lock);

				/* Send XON to notify active path */
				(void) oplmsu_cmn_put_xoffxon(dst_queue,
				    MSU_XON_4);
			} else {
				cmn_err(CE_WARN, "oplmsu: conf-start: "
				    "Proper alternate lpath_t doesn't exist");
			}
		} else {
			cmn_err(CE_WARN, "oplmsu: conf-start: "
			    "Proper alternate upath_t doesn't exist");
		}
	}

	mutex_enter(&oplmsu_uinst->l_lock);

	/* Send XOFF to notify all standby paths */
	oplmsu_cmn_putxoff_standby();

	/* Change active path of oplmsu */
	oplmsu_uinst->lower_queue = main_rq;
	oplmsu_uinst->inst_status = oplmsu_get_inst_status();
	mutex_exit(&oplmsu_uinst->l_lock);
	mutex_exit(&oplmsu_uinst->u_lock);
	rw_exit(&oplmsu_uinst->lock);
	return (SUCCESS);
}

/* Prepare of unlink path */
int
oplmsu_config_disc(int pathnum)
{
	upath_t	*upath;
	lpath_t	*lpath;
	int	use_flag;

	DBG_PRINT((CE_NOTE,
	    "oplmsu: conf-disc: config_disc(%d) called", pathnum));

	rw_enter(&oplmsu_uinst->lock, RW_READER);
	mutex_enter(&oplmsu_uinst->u_lock);

	upath = oplmsu_search_upath_info(pathnum);
	if (upath == NULL) {
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: conf-disc: "
		    "Proper upath_t doesn't find");
		return (EINVAL);
	}

	if ((upath->status == MSU_PSTAT_DISCON) ||
	    (upath->traditional_status == MSU_DISCON)) {
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		return (SUCCESS);
	} else if (((upath->status != MSU_PSTAT_STOP) ||
	    (upath->traditional_status != MSU_STOP)) &&
	    ((upath->status != MSU_PSTAT_FAIL) ||
	    (upath->traditional_status != MSU_FAIL))) {
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: conf-disc: "
		    "Status of path is improper");
		return (EINVAL);
	}

	lpath = upath->lpath;
	if (lpath == NULL) {
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: conf-disc: "
		    "Proper lpath_t doesn't exist");
		return (ENODEV);
	}

	mutex_enter(&oplmsu_uinst->l_lock);

	/* Check lower path status */
	use_flag = oplmsu_set_ioctl_path(lpath, NULL, NULL);
	if (use_flag == BUSY) {
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: conf-disc: "
		    "Other processing is using lower path");
		return (EBUSY);
	}

	upath->status = MSU_PSTAT_STOP;
	upath->traditional_status = MSU_SETID;

	oplmsu_clear_ioctl_path(lpath);
	mutex_exit(&oplmsu_uinst->l_lock);
	mutex_exit(&oplmsu_uinst->u_lock);
	rw_exit(&oplmsu_uinst->lock);
	return (SUCCESS);
}
