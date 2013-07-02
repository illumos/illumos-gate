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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013, Nexenta Systems, Inc. All rights reserved.
 */

#include <sys/cpuvar.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/nvpair.h>
#include <sys/door.h>
#include <sys/sdt.h>

#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/pppt_ioctl.h>
#include <sys/portif.h>

#include "pppt.h"

#define	PPPT_VERSION		BUILD_DATE "-1.18dev"
#define	PPPT_NAME_VERSION	"COMSTAR PPPT v" PPPT_VERSION

/*
 * DDI entry points.
 */
static int pppt_drv_attach(dev_info_t *, ddi_attach_cmd_t);
static int pppt_drv_detach(dev_info_t *, ddi_detach_cmd_t);
static int pppt_drv_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int pppt_drv_open(dev_t *, int, int, cred_t *);
static int pppt_drv_close(dev_t, int, int, cred_t *);
static boolean_t pppt_drv_busy(void);
static int pppt_drv_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

extern pppt_status_t pppt_ic_so_enable(boolean_t);
extern void pppt_ic_so_disable();
extern void stmf_ic_rx_msg(char *, size_t);

extern struct mod_ops mod_miscops;

static struct cb_ops pppt_cb_ops = {
	pppt_drv_open,	/* cb_open */
	pppt_drv_close,	/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	pppt_drv_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_streamtab */
	D_MP,			/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_awrite */
};

static struct dev_ops pppt_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	pppt_drv_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	pppt_drv_attach,	/* devo_attach */
	pppt_drv_detach,	/* devo_detach */
	nodev,			/* devo_reset */
	&pppt_cb_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,	/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Proxy Port Provider",
	&pppt_dev_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL,
};

pppt_global_t pppt_global;

int pppt_logging = 0;

static int pppt_enable_svc(void);

static void pppt_disable_svc(void);

static int pppt_task_avl_compare(const void *tgt1, const void *tgt2);

static stmf_data_buf_t *pppt_dbuf_alloc(scsi_task_t *task,
    uint32_t size, uint32_t *pminsize, uint32_t flags);

static void pppt_dbuf_free(stmf_dbuf_store_t *ds, stmf_data_buf_t *dbuf);

static void pppt_sess_destroy_task(void *ps_void);

static void pppt_task_sent_status(pppt_task_t *ptask);

static pppt_status_t pppt_task_try_abort(pppt_task_t *ptask);

static void pppt_task_rele(pppt_task_t *ptask);

static void pppt_task_update_state(pppt_task_t *ptask,
    pppt_task_state_t new_state);

/*
 * Lock order:  global --> target --> session --> task
 */

int
_init(void)
{
	int rc;

	mutex_init(&pppt_global.global_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&pppt_global.global_door_lock, NULL, MUTEX_DEFAULT, NULL);
	pppt_global.global_svc_state = PSS_DETACHED;

	if ((rc = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&pppt_global.global_door_lock);
		mutex_destroy(&pppt_global.global_lock);
		return (rc);
	}

	return (rc);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int rc;

	rc = mod_remove(&modlinkage);

	if (rc == 0) {
		mutex_destroy(&pppt_global.global_lock);
		mutex_destroy(&pppt_global.global_door_lock);
	}

	return (rc);
}

/*
 * DDI entry points.
 */

/* ARGSUSED */
static int
pppt_drv_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **result)
{
	ulong_t instance = getminor((dev_t)arg);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = pppt_global.global_dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)instance;
		return (DDI_SUCCESS);

	default:
		break;
	}

	return (DDI_FAILURE);
}

static int
pppt_drv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (ddi_get_instance(dip) != 0) {
		/* we only allow instance 0 to attach */
		return (DDI_FAILURE);
	}

	/* create the minor node */
	if (ddi_create_minor_node(dip, PPPT_MODNAME, S_IFCHR, 0,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "pppt_drv_attach: "
		    "failed creating minor node");
		return (DDI_FAILURE);
	}

	pppt_global.global_svc_state = PSS_DISABLED;
	pppt_global.global_dip = dip;

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
pppt_drv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	PPPT_GLOBAL_LOCK();
	if (pppt_drv_busy()) {
		PPPT_GLOBAL_UNLOCK();
		return (EBUSY);
	}

	ddi_remove_minor_node(dip, NULL);
	ddi_prop_remove_all(dip);

	pppt_global.global_svc_state = PSS_DETACHED;

	PPPT_GLOBAL_UNLOCK();

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
pppt_drv_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int	rc = 0;

	PPPT_GLOBAL_LOCK();

	switch (pppt_global.global_svc_state) {
	case PSS_DISABLED:
		pppt_global.global_svc_state = PSS_ENABLING;
		PPPT_GLOBAL_UNLOCK();
		rc = pppt_enable_svc();
		PPPT_GLOBAL_LOCK();
		if (rc == 0) {
			pppt_global.global_svc_state = PSS_ENABLED;
		} else {
			pppt_global.global_svc_state = PSS_DISABLED;
		}
		break;
	case PSS_DISABLING:
	case PSS_ENABLING:
	case PSS_ENABLED:
		rc = EBUSY;
		break;
	default:
		rc = EFAULT;
		break;
	}

	PPPT_GLOBAL_UNLOCK();

	return (rc);
}

/* ARGSUSED */
static int
pppt_drv_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int rc = 0;

	PPPT_GLOBAL_LOCK();

	switch (pppt_global.global_svc_state) {
	case PSS_ENABLED:
		pppt_global.global_svc_state = PSS_DISABLING;
		PPPT_GLOBAL_UNLOCK();
		pppt_disable_svc();
		PPPT_GLOBAL_LOCK();
		pppt_global.global_svc_state = PSS_DISABLED;
		/*
		 * release the door to the daemon
		 */
		mutex_enter(&pppt_global.global_door_lock);
		if (pppt_global.global_door != NULL) {
			door_ki_rele(pppt_global.global_door);
			pppt_global.global_door = NULL;
		}
		mutex_exit(&pppt_global.global_door_lock);
		break;
	default:
		rc = EFAULT;
		break;
	}

	PPPT_GLOBAL_UNLOCK();

	return (rc);
}

static boolean_t
pppt_drv_busy(void)
{
	switch (pppt_global.global_svc_state) {
	case PSS_DISABLED:
	case PSS_DETACHED:
		return (B_FALSE);
	default:
		return (B_TRUE);
	}
	/* NOTREACHED */
}

/* ARGSUSED */
static int
pppt_drv_ioctl(dev_t drv, int cmd, intptr_t argp, int flag, cred_t *cred,
    int *retval)
{
	int				rc;
	void				*buf;
	size_t				buf_size;
	pppt_iocdata_t			iocd;
	door_handle_t			new_handle;

	if (drv_priv(cred) != 0) {
		return (EPERM);
	}

	rc = ddi_copyin((void *)argp, &iocd, sizeof (iocd), flag);
	if (rc)
		return (EFAULT);

	if (iocd.pppt_version != PPPT_VERSION_1)
		return (EINVAL);

	switch (cmd) {
	case PPPT_MESSAGE:

		/* XXX limit buf_size ? */
		buf_size = (size_t)iocd.pppt_buf_size;
		buf = kmem_alloc(buf_size, KM_SLEEP);
		if (buf == NULL)
			return (ENOMEM);

		rc = ddi_copyin((void *)(unsigned long)iocd.pppt_buf,
		    buf, buf_size, flag);
		if (rc) {
			kmem_free(buf, buf_size);
			return (EFAULT);
		}

		stmf_ic_rx_msg(buf, buf_size);

		kmem_free(buf, buf_size);
		break;
	case PPPT_INSTALL_DOOR:

		new_handle = door_ki_lookup((int)iocd.pppt_door_fd);
		if (new_handle == NULL)
			return (EINVAL);

		mutex_enter(&pppt_global.global_door_lock);
		ASSERT(pppt_global.global_svc_state == PSS_ENABLED);
		if (pppt_global.global_door != NULL) {
			/*
			 * There can only be one door installed
			 */
			mutex_exit(&pppt_global.global_door_lock);
			door_ki_rele(new_handle);
			return (EBUSY);
		}
		pppt_global.global_door = new_handle;
		mutex_exit(&pppt_global.global_door_lock);
		break;
	}

	return (rc);
}

/*
 * pppt_enable_svc
 *
 * registers all the configured targets and target portals with STMF
 */
static int
pppt_enable_svc(void)
{
	stmf_port_provider_t	*pp;
	stmf_dbuf_store_t	*dbuf_store;
	int			rc = 0;

	ASSERT(pppt_global.global_svc_state == PSS_ENABLING);

	/*
	 * Make sure that can tell if we have partially allocated
	 * in case we need to exit and tear down anything allocated.
	 */
	pppt_global.global_dbuf_store = NULL;
	pp = NULL;
	pppt_global.global_pp = NULL;
	pppt_global.global_dispatch_taskq = NULL;
	pppt_global.global_sess_taskq = NULL;

	avl_create(&pppt_global.global_target_list,
	    pppt_tgt_avl_compare, sizeof (pppt_tgt_t),
	    offsetof(pppt_tgt_t, target_global_ln));

	avl_create(&pppt_global.global_sess_list,
	    pppt_sess_avl_compare_by_id, sizeof (pppt_sess_t),
	    offsetof(pppt_sess_t, ps_global_ln));

	/*
	 * Setup STMF dbuf store.  Tf buffers are associated with a particular
	 * lport (FC, SRP) then the dbuf_store should stored in the lport
	 * context, otherwise (iSCSI) the dbuf_store should be global.
	 */
	dbuf_store = stmf_alloc(STMF_STRUCT_DBUF_STORE, 0, 0);
	if (dbuf_store == NULL) {
		rc = ENOMEM;
		goto tear_down_and_return;
	}
	dbuf_store->ds_alloc_data_buf = pppt_dbuf_alloc;
	dbuf_store->ds_free_data_buf = pppt_dbuf_free;
	dbuf_store->ds_port_private = NULL;
	pppt_global.global_dbuf_store = dbuf_store;

	/* Register port provider */
	pp = stmf_alloc(STMF_STRUCT_PORT_PROVIDER, 0, 0);
	if (pp == NULL) {
		rc = ENOMEM;
		goto tear_down_and_return;
	}

	pp->pp_portif_rev = PORTIF_REV_1;
	pp->pp_instance = 0;
	pp->pp_name = PPPT_MODNAME;
	pp->pp_cb = NULL;

	pppt_global.global_pp = pp;

	if (stmf_register_port_provider(pp) != STMF_SUCCESS) {
		rc = EIO;
		goto tear_down_and_return;
	}

	pppt_global.global_dispatch_taskq = taskq_create("pppt_dispatch",
	    1, minclsyspri, 1, INT_MAX, TASKQ_PREPOPULATE);

	pppt_global.global_sess_taskq = taskq_create("pppt_session",
	    1, minclsyspri, 1, INT_MAX, TASKQ_PREPOPULATE);

	return (0);

tear_down_and_return:

	if (pppt_global.global_sess_taskq) {
		taskq_destroy(pppt_global.global_sess_taskq);
		pppt_global.global_sess_taskq = NULL;
	}

	if (pppt_global.global_dispatch_taskq) {
		taskq_destroy(pppt_global.global_dispatch_taskq);
		pppt_global.global_dispatch_taskq = NULL;
	}

	if (pppt_global.global_pp)
		pppt_global.global_pp = NULL;

	if (pp)
		stmf_free(pp);

	if (pppt_global.global_dbuf_store) {
		stmf_free(pppt_global.global_dbuf_store);
		pppt_global.global_dbuf_store = NULL;
	}

	avl_destroy(&pppt_global.global_sess_list);
	avl_destroy(&pppt_global.global_target_list);

	return (rc);
}

/*
 * pppt_disable_svc
 *
 * clean up all existing sessions and deregister targets from STMF
 */
static void
pppt_disable_svc(void)
{
	pppt_tgt_t	*tgt, *next_tgt;
	avl_tree_t	delete_target_list;

	ASSERT(pppt_global.global_svc_state == PSS_DISABLING);

	avl_create(&delete_target_list,
	    pppt_tgt_avl_compare, sizeof (pppt_tgt_t),
	    offsetof(pppt_tgt_t, target_global_ln));

	PPPT_GLOBAL_LOCK();
	for (tgt = avl_first(&pppt_global.global_target_list);
	    tgt != NULL;
	    tgt = next_tgt) {
		next_tgt = AVL_NEXT(&pppt_global.global_target_list, tgt);
		avl_remove(&pppt_global.global_target_list, tgt);
		avl_add(&delete_target_list, tgt);
		pppt_tgt_async_delete(tgt);
	}
	PPPT_GLOBAL_UNLOCK();

	for (tgt = avl_first(&delete_target_list);
	    tgt != NULL;
	    tgt = next_tgt) {
		next_tgt = AVL_NEXT(&delete_target_list, tgt);
		mutex_enter(&tgt->target_mutex);
		while ((tgt->target_refcount > 0) ||
		    (tgt->target_state != TS_DELETING)) {
			cv_wait(&tgt->target_cv, &tgt->target_mutex);
		}
		mutex_exit(&tgt->target_mutex);

		avl_remove(&delete_target_list, tgt);
		pppt_tgt_destroy(tgt);
	}

	taskq_destroy(pppt_global.global_sess_taskq);

	taskq_destroy(pppt_global.global_dispatch_taskq);

	avl_destroy(&pppt_global.global_sess_list);
	avl_destroy(&pppt_global.global_target_list);

	(void) stmf_deregister_port_provider(pppt_global.global_pp);

	stmf_free(pppt_global.global_dbuf_store);
	pppt_global.global_dbuf_store = NULL;

	stmf_free(pppt_global.global_pp);
	pppt_global.global_pp = NULL;
}

/*
 * STMF callbacks
 */

/*ARGSUSED*/
static stmf_data_buf_t *
pppt_dbuf_alloc(scsi_task_t *task, uint32_t size, uint32_t *pminsize,
    uint32_t flags)
{
	stmf_data_buf_t	*result;
	pppt_buf_t	*pbuf;
	uint8_t		*buf;

	/* Get buffer */
	buf = kmem_alloc(size, KM_SLEEP);

	/*
	 *  Allocate stmf buf with private port provider section
	 * (pppt_buf_t)
	 */
	result = stmf_alloc(STMF_STRUCT_DATA_BUF, sizeof (pppt_buf_t), 0);
	if (result != NULL) {
		/* Fill in pppt_buf_t */
		pbuf = result->db_port_private;
		pbuf->pbuf_stmf_buf = result;
		pbuf->pbuf_is_immed = B_FALSE;

		/*
		 * Fill in stmf_data_buf_t.  DB_DONT CACHE tells
		 * stmf not to cache buffers but STMF doesn't do
		 * that yet so it's a no-op.  Port providers like
		 * FC and SRP that have buffers associated with the
		 * target port would want to let STMF cache
		 * the buffers.  Port providers like iSCSI would
		 * not want STMF to cache because the buffers are
		 * really associated with a connection, not an
		 * STMF target port so there is no way for STMF
		 * to cache the buffers effectively.  These port
		 * providers should cache buffers internally if
		 * there is significant buffer setup overhead.
		 *
		 * And of course, since STMF doesn't do any internal
		 * caching right now anyway, all port providers should
		 * do what they can to minimize buffer setup overhead.
		 */
		result->db_flags = DB_DONT_CACHE;
		result->db_buf_size = size;
		result->db_data_size = size;
		result->db_sglist_length = 1;
		result->db_sglist[0].seg_addr = buf;
		result->db_sglist[0].seg_length = size;
		return (result);
	} else {
		/*
		 * Couldn't get the stmf_data_buf_t so free the
		 * buffer
		 */
		kmem_free(buf, size);
	}

	return (NULL);
}

/*ARGSUSED*/
static void
pppt_dbuf_free(stmf_dbuf_store_t *ds, stmf_data_buf_t *dbuf)
{
	pppt_buf_t *pbuf = dbuf->db_port_private;

	if (pbuf->pbuf_is_immed) {
		stmf_ic_msg_free(pbuf->pbuf_immed_msg);
	} else {
		kmem_free(dbuf->db_sglist[0].seg_addr,
		    dbuf->db_sglist[0].seg_length);
		stmf_free(dbuf);
	}
}

/*ARGSUSED*/
stmf_status_t
pppt_lport_xfer_data(scsi_task_t *task, stmf_data_buf_t *dbuf,
    uint32_t ioflags)
{
	pppt_task_t		*pppt_task = task->task_port_private;
	pppt_buf_t		*pbuf = dbuf->db_port_private;
	stmf_ic_msg_t		*msg;
	stmf_ic_msg_status_t	ic_msg_status;

	/*
	 * If we are aborting then we can ignore this request, otherwise
	 * add a reference.
	 */
	if (pppt_task_hold(pppt_task) != PPPT_STATUS_SUCCESS) {
		return (STMF_SUCCESS);
	}

	/*
	 * If it's not immediate data then start the transfer
	 */
	ASSERT(pbuf->pbuf_is_immed == B_FALSE);
	if (dbuf->db_flags & DB_DIRECTION_TO_RPORT) {

		/* Send read data */
		msg = stmf_ic_scsi_data_msg_alloc(
		    pppt_task->pt_task_id,
		    pppt_task->pt_sess->ps_session_id,
		    pppt_task->pt_lun_id,
		    dbuf->db_sglist[0].seg_length,
		    dbuf->db_sglist[0].seg_addr, 0);

		pppt_task->pt_read_buf = pbuf;
		pppt_task->pt_read_xfer_msgid = msg->icm_msgid;

		ic_msg_status = stmf_ic_tx_msg(msg);
		pppt_task_rele(pppt_task);
		if (ic_msg_status != STMF_IC_MSG_SUCCESS) {
			return (STMF_FAILURE);
		} else {
			return (STMF_SUCCESS);
		}
	} else if (dbuf->db_flags & DB_DIRECTION_FROM_RPORT) {
		pppt_task_rele(pppt_task);
		return (STMF_FAILURE);
	}

	pppt_task_rele(pppt_task);

	return (STMF_INVALID_ARG);
}

void
pppt_xfer_read_complete(pppt_task_t *pppt_task, stmf_status_t status)
{
	pppt_buf_t		*pppt_buf;
	stmf_data_buf_t		*dbuf;

	/*
	 * Caller should have taken a task hold (likely via pppt_task_lookup)
	 *
	 * Get pppt_buf_t and stmf_data_buf_t pointers
	 */
	pppt_buf = pppt_task->pt_read_buf;
	dbuf = pppt_buf->pbuf_stmf_buf;
	dbuf->db_xfer_status = (status == STMF_SUCCESS) ?
	    STMF_SUCCESS : STMF_FAILURE;

	/*
	 * COMSTAR currently requires port providers to support
	 * the DB_SEND_STATUS_GOOD flag even if phase collapse is
	 * not supported.  So we will roll our own... pretend we are
	 * COMSTAR and ask for a status message.
	 */
	if ((dbuf->db_flags & DB_SEND_STATUS_GOOD) &&
	    (status == STMF_SUCCESS)) {
		/*
		 * It's possible the task has been aborted since the time we
		 * looked it up.  We need to release the hold before calling
		 * pppt_lport_send_status and as soon as we release the hold
		 * the task may disappear.  Calling pppt_task_done allows us
		 * to determine whether the task has been aborted (in which
		 * case we will stop processing and return) and mark the task
		 * "done" which will prevent the task from being aborted while
		 * we are trying to send the status.
		 */
		if (pppt_task_done(pppt_task) != PPPT_STATUS_SUCCESS) {
			/* STMF will free task and buffer(s) */
			pppt_task_rele(pppt_task);
			return;
		}
		pppt_task_rele(pppt_task);

		if (pppt_lport_send_status(pppt_task->pt_stmf_task, 0)
		    != STMF_SUCCESS) {
			/* Failed to send status */
			dbuf->db_xfer_status = STMF_FAILURE;
			stmf_data_xfer_done(pppt_task->pt_stmf_task, dbuf,
			    STMF_IOF_LPORT_DONE);
		}
	} else {
		pppt_task_rele(pppt_task);
		stmf_data_xfer_done(pppt_task->pt_stmf_task, dbuf, 0);
	}
}

/*ARGSUSED*/
stmf_status_t
pppt_lport_send_status(scsi_task_t *task, uint32_t ioflags)
{
	pppt_task_t *ptask =		task->task_port_private;
	stmf_ic_msg_t			*msg;
	stmf_ic_msg_status_t		ic_msg_status;

	/*
	 * Mark task completed.  If the state indicates it was aborted
	 * then we don't need to respond.
	 */
	if (pppt_task_done(ptask) == PPPT_STATUS_ABORTED) {
		return (STMF_SUCCESS);
	}

	/*
	 * Send status.
	 */
	msg = stmf_ic_scsi_status_msg_alloc(
	    ptask->pt_task_id,
	    ptask->pt_sess->ps_session_id,
	    ptask->pt_lun_id,
	    0,
	    task->task_scsi_status,
	    task->task_status_ctrl, task->task_resid,
	    task->task_sense_length, task->task_sense_data, 0);

	ic_msg_status = stmf_ic_tx_msg(msg);

	if (ic_msg_status != STMF_IC_MSG_SUCCESS) {
		pppt_task_sent_status(ptask);
		stmf_send_status_done(ptask->pt_stmf_task,
		    STMF_FAILURE, STMF_IOF_LPORT_DONE);
		return (STMF_FAILURE);
	} else {
		pppt_task_sent_status(ptask);
		stmf_send_status_done(ptask->pt_stmf_task,
		    STMF_SUCCESS, STMF_IOF_LPORT_DONE);
		return (STMF_SUCCESS);
	}
}

void
pppt_lport_task_free(scsi_task_t *task)
{
	pppt_task_t *ptask = task->task_port_private;
	pppt_sess_t *ps = ptask->pt_sess;

	pppt_task_rele(ptask);
	pppt_sess_rele(ps);
}

/*ARGSUSED*/
stmf_status_t
pppt_lport_abort(stmf_local_port_t *lport, int abort_cmd, void *arg,
    uint32_t flags)
{
	scsi_task_t	*st = (scsi_task_t *)arg;
	pppt_task_t	*ptask;

	ptask = st->task_port_private;

	if (pppt_task_try_abort(ptask) == PPPT_STATUS_DONE) {
		/*
		 * This task is beyond the point where abort makes sense
		 * and we will soon be sending status.  Tell STMF to
		 * go away.
		 */
		return (STMF_BUSY);
	} else {
		return (STMF_ABORT_SUCCESS);
	}
	/*NOTREACHED*/
}

/*ARGSUSED*/
void
pppt_lport_ctl(stmf_local_port_t *lport, int cmd, void *arg)
{
	switch (cmd) {
	case STMF_CMD_LPORT_ONLINE:
	case STMF_CMD_LPORT_OFFLINE:
	case STMF_ACK_LPORT_ONLINE_COMPLETE:
	case STMF_ACK_LPORT_OFFLINE_COMPLETE:
		pppt_tgt_sm_ctl(lport, cmd, arg);
		break;

	default:
		ASSERT(0);
		break;
	}
}

pppt_sess_t *
pppt_sess_lookup_locked(uint64_t session_id,
    scsi_devid_desc_t *lport_devid, stmf_remote_port_t *rport)
{
	pppt_tgt_t				*tgt;
	pppt_sess_t				*ps;
	int					lport_cmp;

	ASSERT(mutex_owned(&pppt_global.global_lock));

	/*
	 * Look for existing session for this ID
	 */
	ps = pppt_sess_lookup_by_id_locked(session_id);
	if (ps == NULL) {
		PPPT_INC_STAT(es_sess_lookup_no_session);
		return (NULL);
	}

	tgt = ps->ps_target;

	mutex_enter(&tgt->target_mutex);

	/* Validate local/remote port names */
	if ((lport_devid->ident_length !=
	    tgt->target_stmf_lport->lport_id->ident_length) ||
	    (rport->rport_tptid_sz !=
	    ps->ps_stmf_sess->ss_rport->rport_tptid_sz)) {
		mutex_exit(&tgt->target_mutex);
		PPPT_INC_STAT(es_sess_lookup_ident_mismatch);
		return (NULL);
	} else {
		lport_cmp = bcmp(lport_devid->ident,
		    tgt->target_stmf_lport->lport_id->ident,
		    lport_devid->ident_length);
		if (lport_cmp != 0 ||
		    (stmf_scsilib_tptid_compare(rport->rport_tptid,
		    ps->ps_stmf_sess->ss_rport->rport_tptid) != B_TRUE)) {
			mutex_exit(&tgt->target_mutex);
			PPPT_INC_STAT(es_sess_lookup_ident_mismatch);
			return (NULL);
		}

		if (tgt->target_state != TS_STMF_ONLINE) {
			mutex_exit(&tgt->target_mutex);
			PPPT_INC_STAT(es_sess_lookup_bad_tgt_state);
			return (NULL);
		}
	}
	mutex_exit(&tgt->target_mutex);

	return (ps);
}

pppt_sess_t *
pppt_sess_lookup_by_id_locked(uint64_t session_id)
{
	pppt_sess_t		tmp_ps;
	pppt_sess_t		*ps;

	ASSERT(mutex_owned(&pppt_global.global_lock));
	tmp_ps.ps_session_id = session_id;
	tmp_ps.ps_closed = 0;
	ps = avl_find(&pppt_global.global_sess_list, &tmp_ps, NULL);
	if (ps != NULL) {
		mutex_enter(&ps->ps_mutex);
		if (!ps->ps_closed) {
			ps->ps_refcnt++;
			mutex_exit(&ps->ps_mutex);
			return (ps);
		}
		mutex_exit(&ps->ps_mutex);
	}

	return (NULL);
}

/* New session */
pppt_sess_t *
pppt_sess_lookup_create(scsi_devid_desc_t *lport_devid,
    scsi_devid_desc_t *rport_devid, stmf_remote_port_t *rport,
    uint64_t session_id, stmf_status_t *statusp)
{
	pppt_tgt_t		*tgt;
	pppt_sess_t		*ps;
	stmf_scsi_session_t	*ss;
	pppt_sess_t		tmp_ps;
	stmf_scsi_session_t	tmp_ss;
	*statusp = STMF_SUCCESS;

	PPPT_GLOBAL_LOCK();

	/*
	 * Look for existing session for this ID
	 */
	ps = pppt_sess_lookup_locked(session_id, lport_devid, rport);

	if (ps != NULL) {
		PPPT_GLOBAL_UNLOCK();
		return (ps);
	}

	/*
	 * No session with that ID, look for another session corresponding
	 * to the same IT nexus.
	 */
	tgt = pppt_tgt_lookup_locked(lport_devid);
	if (tgt == NULL) {
		*statusp = STMF_NOT_FOUND;
		PPPT_GLOBAL_UNLOCK();
		return (NULL);
	}

	mutex_enter(&tgt->target_mutex);
	if (tgt->target_state != TS_STMF_ONLINE) {
		*statusp = STMF_NOT_FOUND;
		mutex_exit(&tgt->target_mutex);
		PPPT_GLOBAL_UNLOCK();
		/* Can't create session to offline target */
		return (NULL);
	}

	bzero(&tmp_ps, sizeof (tmp_ps));
	bzero(&tmp_ss, sizeof (tmp_ss));
	tmp_ps.ps_stmf_sess = &tmp_ss;
	tmp_ss.ss_rport = rport;

	/*
	 * Look for an existing session on this IT nexus
	 */
	ps = avl_find(&tgt->target_sess_list, &tmp_ps, NULL);

	if (ps != NULL) {
		/*
		 * Now check the session ID.  It should not match because if
		 * it did we would have found it on the global session list.
		 * If the session ID in the command is higher than the existing
		 * session ID then we need to tear down the existing session.
		 */
		mutex_enter(&ps->ps_mutex);
		ASSERT(ps->ps_session_id != session_id);
		if (ps->ps_session_id > session_id) {
			/* Invalid session ID */
			mutex_exit(&ps->ps_mutex);
			mutex_exit(&tgt->target_mutex);
			PPPT_GLOBAL_UNLOCK();
			*statusp = STMF_INVALID_ARG;
			return (NULL);
		} else {
			/* Existing session needs to be invalidated */
			if (!ps->ps_closed) {
				pppt_sess_close_locked(ps);
			}
		}
		mutex_exit(&ps->ps_mutex);

		/* Fallthrough and create new session */
	}

	/*
	 * Allocate and fill in pppt_session_t with the appropriate data
	 * for the protocol.
	 */
	ps = kmem_zalloc(sizeof (*ps), KM_SLEEP);

	/* Fill in session fields */
	ps->ps_target = tgt;
	ps->ps_session_id = session_id;

	ss = stmf_alloc(STMF_STRUCT_SCSI_SESSION, 0,
	    0);
	if (ss == NULL) {
		mutex_exit(&tgt->target_mutex);
		PPPT_GLOBAL_UNLOCK();
		kmem_free(ps, sizeof (*ps));
		*statusp = STMF_ALLOC_FAILURE;
		return (NULL);
	}

	ss->ss_rport_id = kmem_zalloc(sizeof (scsi_devid_desc_t) +
	    rport_devid->ident_length + 1, KM_SLEEP);
	bcopy(rport_devid, ss->ss_rport_id,
	    sizeof (scsi_devid_desc_t) + rport_devid->ident_length + 1);

	ss->ss_lport = tgt->target_stmf_lport;

	ss->ss_rport = stmf_remote_port_alloc(rport->rport_tptid_sz);
	bcopy(rport->rport_tptid, ss->ss_rport->rport_tptid,
	    rport->rport_tptid_sz);

	if (stmf_register_scsi_session(tgt->target_stmf_lport, ss) !=
	    STMF_SUCCESS) {
		mutex_exit(&tgt->target_mutex);
		PPPT_GLOBAL_UNLOCK();
		kmem_free(ss->ss_rport_id,
		    sizeof (scsi_devid_desc_t) + rport_devid->ident_length + 1);
		stmf_remote_port_free(ss->ss_rport);
		stmf_free(ss);
		kmem_free(ps, sizeof (*ps));
		*statusp = STMF_TARGET_FAILURE;
		return (NULL);
	}

	ss->ss_port_private = ps;
	mutex_init(&ps->ps_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ps->ps_cv, NULL, CV_DEFAULT, NULL);
	avl_create(&ps->ps_task_list, pppt_task_avl_compare,
	    sizeof (pppt_task_t), offsetof(pppt_task_t, pt_sess_ln));
	ps->ps_refcnt = 1;
	ps->ps_stmf_sess = ss;
	avl_add(&tgt->target_sess_list, ps);
	avl_add(&pppt_global.global_sess_list, ps);
	mutex_exit(&tgt->target_mutex);
	PPPT_GLOBAL_UNLOCK();
	stmf_trace("pppt", "New session %p", (void *)ps);

	return (ps);
}

void
pppt_sess_rele(pppt_sess_t *ps)
{
	mutex_enter(&ps->ps_mutex);
	pppt_sess_rele_locked(ps);
	mutex_exit(&ps->ps_mutex);
}

void
pppt_sess_rele_locked(pppt_sess_t *ps)
{
	ASSERT(mutex_owned(&ps->ps_mutex));
	ps->ps_refcnt--;
	if (ps->ps_refcnt == 0) {
		cv_signal(&ps->ps_cv);
	}
}

static void pppt_sess_destroy_task(void *ps_void)
{
	pppt_sess_t *ps = ps_void;
	stmf_scsi_session_t	*ss;

	stmf_trace("pppt", "Session destroy task %p", (void *)ps);

	ss = ps->ps_stmf_sess;
	mutex_enter(&ps->ps_mutex);
	stmf_deregister_scsi_session(ss->ss_lport, ss);
	kmem_free(ss->ss_rport_id,
	    sizeof (scsi_devid_desc_t) + ss->ss_rport_id->ident_length + 1);
	stmf_remote_port_free(ss->ss_rport);
	avl_destroy(&ps->ps_task_list);
	mutex_exit(&ps->ps_mutex);
	cv_destroy(&ps->ps_cv);
	mutex_destroy(&ps->ps_mutex);
	stmf_free(ps->ps_stmf_sess);
	kmem_free(ps, sizeof (*ps));

	stmf_trace("pppt", "Session destroy task complete %p", (void *)ps);
}

int
pppt_sess_avl_compare_by_id(const void *void_sess1, const void *void_sess2)
{
	const	pppt_sess_t	*psess1 = void_sess1;
	const	pppt_sess_t	*psess2 = void_sess2;

	if (psess1->ps_session_id < psess2->ps_session_id)
		return (-1);
	else if (psess1->ps_session_id > psess2->ps_session_id)
		return (1);

	/* Allow multiple duplicate sessions if one is closed */
	ASSERT(!(psess1->ps_closed && psess2->ps_closed));
	if (psess1->ps_closed)
		return (-1);
	else if (psess2->ps_closed)
		return (1);

	return (0);
}

int
pppt_sess_avl_compare_by_name(const void *void_sess1, const void *void_sess2)
{
	const	pppt_sess_t	*psess1 = void_sess1;
	const	pppt_sess_t	*psess2 = void_sess2;
	int			result;

	/* Compare by tptid size */
	if (psess1->ps_stmf_sess->ss_rport->rport_tptid_sz <
	    psess2->ps_stmf_sess->ss_rport->rport_tptid_sz) {
		return (-1);
	} else if (psess1->ps_stmf_sess->ss_rport->rport_tptid_sz >
	    psess2->ps_stmf_sess->ss_rport->rport_tptid_sz) {
		return (1);
	}

	/* Now compare tptid */
	result = memcmp(psess1->ps_stmf_sess->ss_rport->rport_tptid,
	    psess2->ps_stmf_sess->ss_rport->rport_tptid,
	    psess1->ps_stmf_sess->ss_rport->rport_tptid_sz);

	if (result < 0) {
		return (-1);
	} else if (result > 0) {
		return (1);
	}

	return (0);
}

void
pppt_sess_close_locked(pppt_sess_t *ps)
{
	pppt_tgt_t	*tgt = ps->ps_target;
	pppt_task_t	*ptask;

	stmf_trace("pppt", "Session close %p", (void *)ps);

	ASSERT(mutex_owned(&pppt_global.global_lock));
	ASSERT(mutex_owned(&tgt->target_mutex));
	ASSERT(mutex_owned(&ps->ps_mutex));
	ASSERT(!ps->ps_closed); /* Caller should ensure session is not closed */

	ps->ps_closed = B_TRUE;
	for (ptask = avl_first(&ps->ps_task_list); ptask != NULL;
	    ptask = AVL_NEXT(&ps->ps_task_list, ptask)) {
		mutex_enter(&ptask->pt_mutex);
		if (ptask->pt_state == PTS_ACTIVE) {
			stmf_abort(STMF_QUEUE_TASK_ABORT, ptask->pt_stmf_task,
			    STMF_ABORTED, NULL);
		}
		mutex_exit(&ptask->pt_mutex);
	}

	/*
	 * Now that all the tasks are aborting the session refcnt should
	 * go to 0.
	 */
	while (ps->ps_refcnt != 0) {
		cv_wait(&ps->ps_cv, &ps->ps_mutex);
	}

	avl_remove(&tgt->target_sess_list, ps);
	avl_remove(&pppt_global.global_sess_list, ps);
	(void) taskq_dispatch(pppt_global.global_sess_taskq,
	    &pppt_sess_destroy_task, ps, KM_SLEEP);

	stmf_trace("pppt", "Session close complete %p", (void *)ps);
}

pppt_task_t *
pppt_task_alloc(void)
{
	pppt_task_t	*ptask;
	pppt_buf_t	*immed_pbuf;

	ptask = kmem_alloc(sizeof (pppt_task_t) + sizeof (pppt_buf_t) +
	    sizeof (stmf_data_buf_t), KM_NOSLEEP);
	if (ptask != NULL) {
		ptask->pt_state = PTS_INIT;
		ptask->pt_read_buf = NULL;
		ptask->pt_read_xfer_msgid = 0;
		ptask->pt_refcnt = 0;
		mutex_init(&ptask->pt_mutex, NULL, MUTEX_DRIVER, NULL);
		immed_pbuf = (pppt_buf_t *)(ptask + 1);
		bzero(immed_pbuf, sizeof (*immed_pbuf));
		immed_pbuf->pbuf_is_immed = B_TRUE;
		immed_pbuf->pbuf_stmf_buf = (stmf_data_buf_t *)(immed_pbuf + 1);

		bzero(immed_pbuf->pbuf_stmf_buf, sizeof (stmf_data_buf_t));
		immed_pbuf->pbuf_stmf_buf->db_port_private = immed_pbuf;
		immed_pbuf->pbuf_stmf_buf->db_sglist_length = 1;
		immed_pbuf->pbuf_stmf_buf->db_flags = DB_DIRECTION_FROM_RPORT |
		    DB_DONT_CACHE;
		ptask->pt_immed_data = immed_pbuf;
	}

	return (ptask);

}

void
pppt_task_free(pppt_task_t *ptask)
{
	mutex_enter(&ptask->pt_mutex);
	ASSERT(ptask->pt_refcnt == 0);
	mutex_destroy(&ptask->pt_mutex);
	kmem_free(ptask, sizeof (pppt_task_t) + sizeof (pppt_buf_t) +
	    sizeof (stmf_data_buf_t));
}

pppt_status_t
pppt_task_start(pppt_task_t *ptask)
{
	avl_index_t		where;

	ASSERT(ptask->pt_state == PTS_INIT);

	mutex_enter(&ptask->pt_sess->ps_mutex);
	mutex_enter(&ptask->pt_mutex);
	if (avl_find(&ptask->pt_sess->ps_task_list, ptask, &where) == NULL) {
		pppt_task_update_state(ptask, PTS_ACTIVE);
		/* Manually increment refcnt, sincd we hold the mutex... */
		ptask->pt_refcnt++;
		avl_insert(&ptask->pt_sess->ps_task_list, ptask, where);
		mutex_exit(&ptask->pt_mutex);
		mutex_exit(&ptask->pt_sess->ps_mutex);
		return (PPPT_STATUS_SUCCESS);
	}
	mutex_exit(&ptask->pt_mutex);
	mutex_exit(&ptask->pt_sess->ps_mutex);

	return (PPPT_STATUS_FAIL);
}

pppt_status_t
pppt_task_done(pppt_task_t *ptask)
{
	pppt_status_t	pppt_status = PPPT_STATUS_SUCCESS;
	boolean_t	remove = B_FALSE;

	mutex_enter(&ptask->pt_mutex);

	switch (ptask->pt_state) {
	case PTS_ACTIVE:
		remove = B_TRUE;
		pppt_task_update_state(ptask, PTS_DONE);
		break;
	case PTS_ABORTED:
		pppt_status = PPPT_STATUS_ABORTED;
		break;
	case PTS_DONE:
		/* Repeat calls are OK.  Do nothing, return success */
		break;
	default:
		ASSERT(0);
	}

	mutex_exit(&ptask->pt_mutex);

	if (remove) {
		mutex_enter(&ptask->pt_sess->ps_mutex);
		avl_remove(&ptask->pt_sess->ps_task_list, ptask);
		mutex_exit(&ptask->pt_sess->ps_mutex);
		/* Out of the AVL tree, so drop a reference. */
		pppt_task_rele(ptask);
	}

	return (pppt_status);
}

void
pppt_task_sent_status(pppt_task_t *ptask)
{
	/*
	 * If STMF tries to abort a task after the task state changed to
	 * PTS_DONE (meaning all task processing is complete from
	 * the port provider perspective) then we return STMF_BUSY
	 * from pppt_lport_abort.  STMF will return after a short interval
	 * but our calls to stmf_send_status_done will be ignored since
	 * STMF is aborting the task.  That's where this state comes in.
	 * This state essentially says we are calling stmf_send_status_done
	 * so we will not be touching the task again.  The next time
	 * STMF calls pppt_lport_abort we will return a success full
	 * status and the abort will succeed.
	 */
	mutex_enter(&ptask->pt_mutex);
	pppt_task_update_state(ptask, PTS_SENT_STATUS);
	mutex_exit(&ptask->pt_mutex);
}

pppt_task_t *
pppt_task_lookup(stmf_ic_msgid_t msgid)
{
	pppt_tgt_t	*tgt;
	pppt_sess_t	*sess;
	pppt_task_t	lookup_task;
	pppt_task_t	*result;

	bzero(&lookup_task, sizeof (lookup_task));
	lookup_task.pt_task_id = msgid;
	PPPT_GLOBAL_LOCK();
	for (tgt = avl_first(&pppt_global.global_target_list); tgt != NULL;
	    tgt = AVL_NEXT(&pppt_global.global_target_list, tgt)) {

		mutex_enter(&tgt->target_mutex);
		for (sess = avl_first(&tgt->target_sess_list); sess != NULL;
		    sess = AVL_NEXT(&tgt->target_sess_list, sess)) {
			mutex_enter(&sess->ps_mutex);
			if ((result = avl_find(&sess->ps_task_list,
			    &lookup_task, NULL)) != NULL) {
				if (pppt_task_hold(result) !=
				    PPPT_STATUS_SUCCESS) {
					result = NULL;
				}
				mutex_exit(&sess->ps_mutex);
				mutex_exit(&tgt->target_mutex);
				PPPT_GLOBAL_UNLOCK();
				return (result);
			}
			mutex_exit(&sess->ps_mutex);
		}
		mutex_exit(&tgt->target_mutex);
	}
	PPPT_GLOBAL_UNLOCK();

	return (NULL);
}

static int
pppt_task_avl_compare(const void *void_task1, const void *void_task2)
{
	const pppt_task_t	*ptask1 = void_task1;
	const pppt_task_t	*ptask2 = void_task2;

	if (ptask1->pt_task_id < ptask2->pt_task_id)
		return (-1);
	else if (ptask1->pt_task_id > ptask2->pt_task_id)
		return (1);

	return (0);
}

static pppt_status_t
pppt_task_try_abort(pppt_task_t *ptask)
{
	boolean_t	remove = B_FALSE;
	pppt_status_t	pppt_status = PPPT_STATUS_SUCCESS;

	mutex_enter(&ptask->pt_mutex);

	switch (ptask->pt_state) {
	case PTS_ACTIVE:
		remove = B_TRUE;
		pppt_task_update_state(ptask, PTS_ABORTED);
		break;
	case PTS_DONE:
		pppt_status = PPPT_STATUS_DONE;
		break;
	case PTS_SENT_STATUS:
		/*
		 * Already removed so leave remove set to B_FALSE
		 * and leave status set to PPPT_STATUS_SUCCESS.
		 */
		pppt_task_update_state(ptask, PTS_ABORTED);
		break;
	case PTS_ABORTED:
		break;
	default:
		ASSERT(0);
	}

	mutex_exit(&ptask->pt_mutex);

	if (remove) {
		mutex_enter(&ptask->pt_sess->ps_mutex);
		avl_remove(&ptask->pt_sess->ps_task_list, ptask);
		mutex_exit(&ptask->pt_sess->ps_mutex);
		/* Out of the AVL tree, so drop a reference. */
		pppt_task_rele(ptask);
	}

	return (pppt_status);
}

pppt_status_t
pppt_task_hold(pppt_task_t *ptask)
{
	pppt_status_t	pppt_status = PPPT_STATUS_SUCCESS;

	mutex_enter(&ptask->pt_mutex);
	if (ptask->pt_state == PTS_ACTIVE) {
		ptask->pt_refcnt++;
	} else {
		pppt_status = PPPT_STATUS_FAIL;
	}
	mutex_exit(&ptask->pt_mutex);

	return (pppt_status);
}

static void
pppt_task_rele(pppt_task_t *ptask)
{
	boolean_t freeit;

	mutex_enter(&ptask->pt_mutex);
	ptask->pt_refcnt--;
	freeit = (ptask->pt_refcnt == 0);
	mutex_exit(&ptask->pt_mutex);
	if (freeit)
		pppt_task_free(ptask);
}

static void
pppt_task_update_state(pppt_task_t *ptask,
    pppt_task_state_t new_state)
{
	PPPT_LOG(CE_NOTE, "task %p %d -> %d", (void *)ptask,
	    ptask->pt_state, new_state);

	ASSERT(mutex_owned(&ptask->pt_mutex));
	ptask->pt_state = new_state;
}
