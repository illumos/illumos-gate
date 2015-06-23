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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2012, Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright (c) 2013 by Saso Kiselkov. All rights reserved.
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/generic/persist.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/disp.h>
#include <sys/byteorder.h>
#include <sys/atomic.h>
#include <sys/ethernet.h>
#include <sys/sdt.h>
#include <sys/nvpair.h>
#include <sys/zone.h>
#include <sys/id_space.h>

#include <sys/stmf.h>
#include <sys/lpif.h>
#include <sys/portif.h>
#include <sys/stmf_ioctl.h>
#include <sys/pppt_ic_if.h>

#include "stmf_impl.h"
#include "lun_map.h"
#include "stmf_state.h"
#include "stmf_stats.h"

/*
 * Lock order:
 * stmf_state_lock --> ilport_lock/iss_lockp --> ilu_task_lock
 */

static uint64_t stmf_session_counter = 0;
static uint16_t stmf_rtpid_counter = 0;
/* start messages at 1 */
static uint64_t stmf_proxy_msg_id = 1;
#define	MSG_ID_TM_BIT	0x8000000000000000
#define	ALIGNED_TO_8BYTE_BOUNDARY(i)	(((i) + 7) & ~7)

/*
 * When stmf_io_deadman_enabled is set to B_TRUE, we check that finishing up
 * I/O operations on an offlining LU doesn't take longer than stmf_io_deadman
 * seconds. If it does, we trigger a panic to inform the user of hung I/O
 * blocking us for too long.
 */
boolean_t stmf_io_deadman_enabled = B_TRUE;
int stmf_io_deadman = 1000;			/* seconds */

struct stmf_svc_clocks;

static int stmf_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int stmf_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int stmf_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
	void **result);
static int stmf_open(dev_t *devp, int flag, int otype, cred_t *credp);
static int stmf_close(dev_t dev, int flag, int otype, cred_t *credp);
static int stmf_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
	cred_t *credp, int *rval);
static int stmf_get_stmf_state(stmf_state_desc_t *std);
static int stmf_set_stmf_state(stmf_state_desc_t *std);
static void stmf_abort_task_offline(scsi_task_t *task, int offline_lu,
    char *info);
static int stmf_set_alua_state(stmf_alua_state_desc_t *alua_state);
static void stmf_get_alua_state(stmf_alua_state_desc_t *alua_state);

static void stmf_task_audit(stmf_i_scsi_task_t *itask,
    task_audit_event_t te, uint32_t cmd_or_iof, stmf_data_buf_t *dbuf);

static boolean_t stmf_base16_str_to_binary(char *c, int dplen, uint8_t *dp);
static char stmf_ctoi(char c);
stmf_xfer_data_t *stmf_prepare_tpgs_data(uint8_t ilu_alua);
void stmf_svc_init();
stmf_status_t stmf_svc_fini();
void stmf_svc(void *arg);
static void stmf_wait_ilu_tasks_finish(stmf_i_lu_t *ilu);
void stmf_svc_queue(int cmd, void *obj, stmf_state_change_info_t *info);
static void stmf_svc_kill_obj_requests(void *obj);
static void stmf_svc_timeout(struct stmf_svc_clocks *);
void stmf_check_freetask();
void stmf_abort_target_reset(scsi_task_t *task);
stmf_status_t stmf_lun_reset_poll(stmf_lu_t *lu, struct scsi_task *task,
							int target_reset);
void stmf_target_reset_poll(struct scsi_task *task);
void stmf_handle_lun_reset(scsi_task_t *task);
void stmf_handle_target_reset(scsi_task_t *task);
void stmf_xd_to_dbuf(stmf_data_buf_t *dbuf, int set_rel_off);
int stmf_load_ppd_ioctl(stmf_ppioctl_data_t *ppi, uint64_t *ppi_token,
    uint32_t *err_ret);
int stmf_delete_ppd_ioctl(stmf_ppioctl_data_t *ppi);
int stmf_get_ppd_ioctl(stmf_ppioctl_data_t *ppi, stmf_ppioctl_data_t *ppi_out,
    uint32_t *err_ret);
void stmf_delete_ppd(stmf_pp_data_t *ppd);
void stmf_delete_all_ppds();
void stmf_trace_clear();
void stmf_worker_init();
stmf_status_t stmf_worker_fini();
void stmf_worker_mgmt();
void stmf_worker_task(void *arg);
static void stmf_task_lu_free(scsi_task_t *task, stmf_i_scsi_session_t *iss);
static stmf_status_t stmf_ic_lu_reg(stmf_ic_reg_dereg_lun_msg_t *msg,
    uint32_t type);
static stmf_status_t stmf_ic_lu_dereg(stmf_ic_reg_dereg_lun_msg_t *msg);
static stmf_status_t stmf_ic_rx_scsi_status(stmf_ic_scsi_status_msg_t *msg);
static stmf_status_t stmf_ic_rx_status(stmf_ic_status_msg_t *msg);
static stmf_status_t stmf_ic_rx_scsi_data(stmf_ic_scsi_data_msg_t *msg);
void stmf_task_lu_killall(stmf_lu_t *lu, scsi_task_t *tm_task, stmf_status_t s);

/* pppt modhandle */
ddi_modhandle_t pppt_mod;

/* pppt modload imported functions */
stmf_ic_reg_port_msg_alloc_func_t ic_reg_port_msg_alloc;
stmf_ic_dereg_port_msg_alloc_func_t ic_dereg_port_msg_alloc;
stmf_ic_reg_lun_msg_alloc_func_t ic_reg_lun_msg_alloc;
stmf_ic_dereg_lun_msg_alloc_func_t ic_dereg_lun_msg_alloc;
stmf_ic_lun_active_msg_alloc_func_t ic_lun_active_msg_alloc;
stmf_ic_scsi_cmd_msg_alloc_func_t ic_scsi_cmd_msg_alloc;
stmf_ic_scsi_data_xfer_done_msg_alloc_func_t ic_scsi_data_xfer_done_msg_alloc;
stmf_ic_session_create_msg_alloc_func_t ic_session_reg_msg_alloc;
stmf_ic_session_destroy_msg_alloc_func_t ic_session_dereg_msg_alloc;
stmf_ic_tx_msg_func_t ic_tx_msg;
stmf_ic_msg_free_func_t ic_msg_free;

static void stmf_itl_task_start(stmf_i_scsi_task_t *itask);
static void stmf_itl_lu_new_task(stmf_i_scsi_task_t *itask);
static void stmf_itl_task_done(stmf_i_scsi_task_t *itask);

static void stmf_lport_xfer_start(stmf_i_scsi_task_t *itask,
    stmf_data_buf_t *dbuf);
static void stmf_lport_xfer_done(stmf_i_scsi_task_t *itask,
    stmf_data_buf_t *dbuf);

static void stmf_update_kstat_lu_q(scsi_task_t *, void());
static void stmf_update_kstat_lport_q(scsi_task_t *, void());
static void stmf_update_kstat_lu_io(scsi_task_t *, stmf_data_buf_t *);
static void stmf_update_kstat_lport_io(scsi_task_t *, stmf_data_buf_t *);

static int stmf_irport_compare(const void *void_irport1,
    const void *void_irport2);
static stmf_i_remote_port_t *stmf_irport_create(scsi_devid_desc_t *rport_devid);
static void stmf_irport_destroy(stmf_i_remote_port_t *irport);
static stmf_i_remote_port_t *stmf_irport_register(
    scsi_devid_desc_t *rport_devid);
static stmf_i_remote_port_t *stmf_irport_lookup_locked(
    scsi_devid_desc_t *rport_devid);
static void stmf_irport_deregister(stmf_i_remote_port_t *irport);

extern struct mod_ops mod_driverops;

/* =====[ Tunables ]===== */
/* Internal tracing */
volatile int	stmf_trace_on = 1;
volatile int	stmf_trace_buf_size = (1 * 1024 * 1024);
/*
 * The reason default task timeout is 75 is because we want the
 * host to timeout 1st and mostly host timeout is 60 seconds.
 */
volatile int	stmf_default_task_timeout = 75;
/*
 * Setting this to one means, you are responsible for config load and keeping
 * things in sync with persistent database.
 */
volatile int	stmf_allow_modunload = 0;

volatile int stmf_max_nworkers = 256;
volatile int stmf_min_nworkers = 4;
volatile int stmf_worker_scale_down_delay = 20;

/* === [ Debugging and fault injection ] === */
#ifdef	DEBUG
volatile uint32_t stmf_drop_task_counter = 0;
volatile uint32_t stmf_drop_buf_counter = 0;

#endif

stmf_state_t		stmf_state;
static stmf_lu_t	*dlun0;

static uint8_t stmf_first_zero[] =
	{ 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 0xff };
static uint8_t stmf_first_one[] =
	{ 0xff, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0 };

static kmutex_t	trace_buf_lock;
static int	trace_buf_size;
static int	trace_buf_curndx;
caddr_t	stmf_trace_buf;

static enum {
	STMF_WORKERS_DISABLED = 0,
	STMF_WORKERS_ENABLING,
	STMF_WORKERS_ENABLED
} stmf_workers_state = STMF_WORKERS_DISABLED;
static int stmf_i_max_nworkers;
static int stmf_i_min_nworkers;
static int stmf_nworkers_cur;		/* # of workers currently running */
static int stmf_nworkers_needed;	/* # of workers need to be running */
static int stmf_worker_sel_counter = 0;
static uint32_t stmf_cur_ntasks = 0;
static clock_t stmf_wm_last = 0;
/*
 * This is equal to stmf_nworkers_cur while we are increasing # workers and
 * stmf_nworkers_needed while we are decreasing the worker count.
 */
static int stmf_nworkers_accepting_cmds;
static stmf_worker_t *stmf_workers = NULL;
static clock_t stmf_worker_mgmt_delay = 2;
static clock_t stmf_worker_scale_down_timer = 0;
static int stmf_worker_scale_down_qd = 0;

static struct cb_ops stmf_cb_ops = {
	stmf_open,			/* open */
	stmf_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	stmf_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* chpoll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab */
	D_NEW | D_MP,			/* cb_flag */
	CB_REV,				/* rev */
	nodev,				/* aread */
	nodev				/* awrite */
};

static struct dev_ops stmf_ops = {
	DEVO_REV,
	0,
	stmf_getinfo,
	nulldev,		/* identify */
	nulldev,		/* probe */
	stmf_attach,
	stmf_detach,
	nodev,			/* reset */
	&stmf_cb_ops,
	NULL,			/* bus_ops */
	NULL			/* power */
};

#define	STMF_NAME		"COMSTAR STMF"
#define	STMF_MODULE_NAME	"stmf"

static struct modldrv modldrv = {
	&mod_driverops,
	STMF_NAME,
	&stmf_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int ret;

	ret = mod_install(&modlinkage);
	if (ret)
		return (ret);
	stmf_trace_buf = kmem_zalloc(stmf_trace_buf_size, KM_SLEEP);
	trace_buf_size = stmf_trace_buf_size;
	trace_buf_curndx = 0;
	mutex_init(&trace_buf_lock, NULL, MUTEX_DRIVER, 0);
	bzero(&stmf_state, sizeof (stmf_state_t));
	/* STMF service is off by default */
	stmf_state.stmf_service_running = 0;
	/* default lu/lport states are online */
	stmf_state.stmf_default_lu_state = STMF_STATE_ONLINE;
	stmf_state.stmf_default_lport_state = STMF_STATE_ONLINE;
	mutex_init(&stmf_state.stmf_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&stmf_state.stmf_cv, NULL, CV_DRIVER, NULL);
	stmf_session_counter = (uint64_t)ddi_get_lbolt();
	avl_create(&stmf_state.stmf_irportlist,
	    stmf_irport_compare, sizeof (stmf_i_remote_port_t),
	    offsetof(stmf_i_remote_port_t, irport_ln));
	stmf_state.stmf_ilport_inst_space =
	    id_space_create("lport-instances", 0, MAX_ILPORT);
	stmf_state.stmf_irport_inst_space =
	    id_space_create("rport-instances", 0, MAX_IRPORT);
	stmf_view_init();
	stmf_svc_init();
	stmf_dlun_init();
	return (ret);
}

int
_fini(void)
{
	int ret;
	stmf_i_remote_port_t	*irport;
	void			*avl_dest_cookie = NULL;

	if (stmf_state.stmf_service_running)
		return (EBUSY);
	if ((!stmf_allow_modunload) &&
	    (stmf_state.stmf_config_state != STMF_CONFIG_NONE)) {
		return (EBUSY);
	}
	if (stmf_state.stmf_nlps || stmf_state.stmf_npps) {
		return (EBUSY);
	}
	if (stmf_dlun_fini() != STMF_SUCCESS)
		return (EBUSY);
	if (stmf_worker_fini() != STMF_SUCCESS) {
		stmf_dlun_init();
		return (EBUSY);
	}
	if (stmf_svc_fini() != STMF_SUCCESS) {
		stmf_dlun_init();
		stmf_worker_init();
		return (EBUSY);
	}

	ret = mod_remove(&modlinkage);
	if (ret) {
		stmf_svc_init();
		stmf_dlun_init();
		stmf_worker_init();
		return (ret);
	}

	stmf_view_clear_config();

	while ((irport = avl_destroy_nodes(&stmf_state.stmf_irportlist,
	    &avl_dest_cookie)) != NULL)
		stmf_irport_destroy(irport);
	avl_destroy(&stmf_state.stmf_irportlist);
	id_space_destroy(stmf_state.stmf_ilport_inst_space);
	id_space_destroy(stmf_state.stmf_irport_inst_space);

	kmem_free(stmf_trace_buf, stmf_trace_buf_size);
	mutex_destroy(&trace_buf_lock);
	mutex_destroy(&stmf_state.stmf_lock);
	cv_destroy(&stmf_state.stmf_cv);
	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
stmf_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = stmf_state.stmf_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result =
		    (void *)(uintptr_t)ddi_get_instance(stmf_state.stmf_dip);
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
stmf_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		stmf_state.stmf_dip = dip;

		if (ddi_create_minor_node(dip, "admin", S_IFCHR, 0,
		    DDI_NT_STMF, 0) != DDI_SUCCESS) {
			break;
		}
		ddi_report_dev(dip);
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

static int
stmf_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		ddi_remove_minor_node(dip, 0);
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

/* ARGSUSED */
static int
stmf_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	mutex_enter(&stmf_state.stmf_lock);
	if (stmf_state.stmf_exclusive_open) {
		mutex_exit(&stmf_state.stmf_lock);
		return (EBUSY);
	}
	if (flag & FEXCL) {
		if (stmf_state.stmf_opened) {
			mutex_exit(&stmf_state.stmf_lock);
			return (EBUSY);
		}
		stmf_state.stmf_exclusive_open = 1;
	}
	stmf_state.stmf_opened = 1;
	mutex_exit(&stmf_state.stmf_lock);
	return (0);
}

/* ARGSUSED */
static int
stmf_close(dev_t dev, int flag, int otype, cred_t *credp)
{
	mutex_enter(&stmf_state.stmf_lock);
	stmf_state.stmf_opened = 0;
	if (stmf_state.stmf_exclusive_open &&
	    (stmf_state.stmf_config_state != STMF_CONFIG_INIT_DONE)) {
		stmf_state.stmf_config_state = STMF_CONFIG_NONE;
		stmf_delete_all_ppds();
		stmf_view_clear_config();
		stmf_view_init();
	}
	stmf_state.stmf_exclusive_open = 0;
	mutex_exit(&stmf_state.stmf_lock);
	return (0);
}

int
stmf_copyin_iocdata(intptr_t data, int mode, stmf_iocdata_t **iocd,
						void **ibuf, void **obuf)
{
	int ret;

	*ibuf = NULL;
	*obuf = NULL;
	*iocd = kmem_zalloc(sizeof (stmf_iocdata_t), KM_SLEEP);

	ret = ddi_copyin((void *)data, *iocd, sizeof (stmf_iocdata_t), mode);
	if (ret)
		return (EFAULT);
	if ((*iocd)->stmf_version != STMF_VERSION_1) {
		ret = EINVAL;
		goto copyin_iocdata_done;
	}
	if ((*iocd)->stmf_ibuf_size) {
		*ibuf = kmem_zalloc((*iocd)->stmf_ibuf_size, KM_SLEEP);
		ret = ddi_copyin((void *)((unsigned long)(*iocd)->stmf_ibuf),
		    *ibuf, (*iocd)->stmf_ibuf_size, mode);
	}
	if ((*iocd)->stmf_obuf_size)
		*obuf = kmem_zalloc((*iocd)->stmf_obuf_size, KM_SLEEP);

	if (ret == 0)
		return (0);
	ret = EFAULT;
copyin_iocdata_done:;
	if (*obuf) {
		kmem_free(*obuf, (*iocd)->stmf_obuf_size);
		*obuf = NULL;
	}
	if (*ibuf) {
		kmem_free(*ibuf, (*iocd)->stmf_ibuf_size);
		*ibuf = NULL;
	}
	kmem_free(*iocd, sizeof (stmf_iocdata_t));
	return (ret);
}

int
stmf_copyout_iocdata(intptr_t data, int mode, stmf_iocdata_t *iocd, void *obuf)
{
	int ret;

	if (iocd->stmf_obuf_size) {
		ret = ddi_copyout(obuf, (void *)(unsigned long)iocd->stmf_obuf,
		    iocd->stmf_obuf_size, mode);
		if (ret)
			return (EFAULT);
	}
	ret = ddi_copyout(iocd, (void *)data, sizeof (stmf_iocdata_t), mode);
	if (ret)
		return (EFAULT);
	return (0);
}

/* ARGSUSED */
static int
stmf_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
	cred_t *credp, int *rval)
{
	stmf_iocdata_t *iocd;
	void *ibuf = NULL, *obuf = NULL;
	slist_lu_t *luid_list;
	slist_target_port_t *lportid_list;
	stmf_i_lu_t *ilu;
	stmf_i_local_port_t *ilport;
	stmf_i_scsi_session_t *iss;
	slist_scsi_session_t *iss_list;
	sioc_lu_props_t *lup;
	sioc_target_port_props_t *lportp;
	stmf_ppioctl_data_t *ppi, *ppi_out = NULL;
	uint64_t *ppi_token = NULL;
	uint8_t *p_id, *id;
	stmf_state_desc_t *std;
	stmf_status_t ctl_ret;
	stmf_state_change_info_t ssi;
	int ret = 0;
	uint32_t n;
	int i;
	stmf_group_op_data_t *grp_entry;
	stmf_group_name_t *grpname;
	stmf_view_op_entry_t *ve;
	stmf_id_type_t idtype;
	stmf_id_data_t *id_entry;
	stmf_id_list_t	*id_list;
	stmf_view_entry_t *view_entry;
	stmf_set_props_t *stmf_set_props;
	uint32_t	veid;
	if ((cmd & 0xff000000) != STMF_IOCTL) {
		return (ENOTTY);
	}

	if (drv_priv(credp) != 0) {
		return (EPERM);
	}

	ret = stmf_copyin_iocdata(data, mode, &iocd, &ibuf, &obuf);
	if (ret)
		return (ret);
	iocd->stmf_error = 0;

	switch (cmd) {
	case STMF_IOCTL_LU_LIST:
		/* retrieves both registered/unregistered */
		mutex_enter(&stmf_state.stmf_lock);
		id_list = &stmf_state.stmf_luid_list;
		n = min(id_list->id_count,
		    (iocd->stmf_obuf_size)/sizeof (slist_lu_t));
		iocd->stmf_obuf_max_nentries = id_list->id_count;
		luid_list = (slist_lu_t *)obuf;
		id_entry = id_list->idl_head;
		for (i = 0; i < n; i++) {
			bcopy(id_entry->id_data, luid_list[i].lu_guid, 16);
			id_entry = id_entry->id_next;
		}

		n = iocd->stmf_obuf_size/sizeof (slist_lu_t);
		for (ilu = stmf_state.stmf_ilulist; ilu; ilu = ilu->ilu_next) {
			id = (uint8_t *)ilu->ilu_lu->lu_id;
			if (stmf_lookup_id(id_list, 16, id + 4) == NULL) {
				iocd->stmf_obuf_max_nentries++;
				if (i < n) {
					bcopy(id + 4, luid_list[i].lu_guid,
					    sizeof (slist_lu_t));
					i++;
				}
			}
		}
		iocd->stmf_obuf_nentries = i;
		mutex_exit(&stmf_state.stmf_lock);
		break;

	case STMF_IOCTL_REG_LU_LIST:
		mutex_enter(&stmf_state.stmf_lock);
		iocd->stmf_obuf_max_nentries = stmf_state.stmf_nlus;
		n = min(stmf_state.stmf_nlus,
		    (iocd->stmf_obuf_size)/sizeof (slist_lu_t));
		iocd->stmf_obuf_nentries = n;
		ilu = stmf_state.stmf_ilulist;
		luid_list = (slist_lu_t *)obuf;
		for (i = 0; i < n; i++) {
			uint8_t *id;
			id = (uint8_t *)ilu->ilu_lu->lu_id;
			bcopy(id + 4, luid_list[i].lu_guid, 16);
			ilu = ilu->ilu_next;
		}
		mutex_exit(&stmf_state.stmf_lock);
		break;

	case STMF_IOCTL_VE_LU_LIST:
		mutex_enter(&stmf_state.stmf_lock);
		id_list = &stmf_state.stmf_luid_list;
		n = min(id_list->id_count,
		    (iocd->stmf_obuf_size)/sizeof (slist_lu_t));
		iocd->stmf_obuf_max_nentries = id_list->id_count;
		iocd->stmf_obuf_nentries = n;
		luid_list = (slist_lu_t *)obuf;
		id_entry = id_list->idl_head;
		for (i = 0; i < n; i++) {
			bcopy(id_entry->id_data, luid_list[i].lu_guid, 16);
			id_entry = id_entry->id_next;
		}
		mutex_exit(&stmf_state.stmf_lock);
		break;

	case STMF_IOCTL_TARGET_PORT_LIST:
		mutex_enter(&stmf_state.stmf_lock);
		iocd->stmf_obuf_max_nentries = stmf_state.stmf_nlports;
		n = min(stmf_state.stmf_nlports,
		    (iocd->stmf_obuf_size)/sizeof (slist_target_port_t));
		iocd->stmf_obuf_nentries = n;
		ilport = stmf_state.stmf_ilportlist;
		lportid_list = (slist_target_port_t *)obuf;
		for (i = 0; i < n; i++) {
			uint8_t *id;
			id = (uint8_t *)ilport->ilport_lport->lport_id;
			bcopy(id, lportid_list[i].target, id[3] + 4);
			ilport = ilport->ilport_next;
		}
		mutex_exit(&stmf_state.stmf_lock);
		break;

	case STMF_IOCTL_SESSION_LIST:
		p_id = (uint8_t *)ibuf;
		if ((p_id == NULL) || (iocd->stmf_ibuf_size < 4) ||
		    (iocd->stmf_ibuf_size < (p_id[3] + 4))) {
			ret = EINVAL;
			break;
		}
		mutex_enter(&stmf_state.stmf_lock);
		for (ilport = stmf_state.stmf_ilportlist; ilport; ilport =
		    ilport->ilport_next) {
			uint8_t *id;
			id = (uint8_t *)ilport->ilport_lport->lport_id;
			if ((p_id[3] == id[3]) &&
			    (bcmp(p_id + 4, id + 4, id[3]) == 0)) {
				break;
			}
		}
		if (ilport == NULL) {
			mutex_exit(&stmf_state.stmf_lock);
			ret = ENOENT;
			break;
		}
		iocd->stmf_obuf_max_nentries = ilport->ilport_nsessions;
		n = min(ilport->ilport_nsessions,
		    (iocd->stmf_obuf_size)/sizeof (slist_scsi_session_t));
		iocd->stmf_obuf_nentries = n;
		iss = ilport->ilport_ss_list;
		iss_list = (slist_scsi_session_t *)obuf;
		for (i = 0; i < n; i++) {
			uint8_t *id;
			id = (uint8_t *)iss->iss_ss->ss_rport_id;
			bcopy(id, iss_list[i].initiator, id[3] + 4);
			iss_list[i].creation_time = (uint32_t)
			    iss->iss_creation_time;
			if (iss->iss_ss->ss_rport_alias) {
				(void) strncpy(iss_list[i].alias,
				    iss->iss_ss->ss_rport_alias, 255);
				iss_list[i].alias[255] = 0;
			} else {
				iss_list[i].alias[0] = 0;
			}
			iss = iss->iss_next;
		}
		mutex_exit(&stmf_state.stmf_lock);
		break;

	case STMF_IOCTL_GET_LU_PROPERTIES:
		p_id = (uint8_t *)ibuf;
		if ((iocd->stmf_ibuf_size < 16) ||
		    (iocd->stmf_obuf_size < sizeof (sioc_lu_props_t)) ||
		    (p_id[0] == 0)) {
			ret = EINVAL;
			break;
		}
		mutex_enter(&stmf_state.stmf_lock);
		for (ilu = stmf_state.stmf_ilulist; ilu; ilu = ilu->ilu_next) {
			if (bcmp(p_id, ilu->ilu_lu->lu_id->ident, 16) == 0)
				break;
		}
		if (ilu == NULL) {
			mutex_exit(&stmf_state.stmf_lock);
			ret = ENOENT;
			break;
		}
		lup = (sioc_lu_props_t *)obuf;
		bcopy(ilu->ilu_lu->lu_id->ident, lup->lu_guid, 16);
		lup->lu_state = ilu->ilu_state & 0x0f;
		lup->lu_present = 1; /* XXX */
		(void) strncpy(lup->lu_provider_name,
		    ilu->ilu_lu->lu_lp->lp_name, 255);
		lup->lu_provider_name[254] = 0;
		if (ilu->ilu_lu->lu_alias) {
			(void) strncpy(lup->lu_alias,
			    ilu->ilu_lu->lu_alias, 255);
			lup->lu_alias[255] = 0;
		} else {
			lup->lu_alias[0] = 0;
		}
		mutex_exit(&stmf_state.stmf_lock);
		break;

	case STMF_IOCTL_GET_TARGET_PORT_PROPERTIES:
		p_id = (uint8_t *)ibuf;
		if ((p_id == NULL) ||
		    (iocd->stmf_ibuf_size < (p_id[3] + 4)) ||
		    (iocd->stmf_obuf_size <
		    sizeof (sioc_target_port_props_t))) {
			ret = EINVAL;
			break;
		}
		mutex_enter(&stmf_state.stmf_lock);
		for (ilport = stmf_state.stmf_ilportlist; ilport;
		    ilport = ilport->ilport_next) {
			uint8_t *id;
			id = (uint8_t *)ilport->ilport_lport->lport_id;
			if ((p_id[3] == id[3]) &&
			    (bcmp(p_id+4, id+4, id[3]) == 0))
				break;
		}
		if (ilport == NULL) {
			mutex_exit(&stmf_state.stmf_lock);
			ret = ENOENT;
			break;
		}
		lportp = (sioc_target_port_props_t *)obuf;
		bcopy(ilport->ilport_lport->lport_id, lportp->tgt_id,
		    ilport->ilport_lport->lport_id->ident_length + 4);
		lportp->tgt_state = ilport->ilport_state & 0x0f;
		lportp->tgt_present = 1; /* XXX */
		(void) strncpy(lportp->tgt_provider_name,
		    ilport->ilport_lport->lport_pp->pp_name, 255);
		lportp->tgt_provider_name[254] = 0;
		if (ilport->ilport_lport->lport_alias) {
			(void) strncpy(lportp->tgt_alias,
			    ilport->ilport_lport->lport_alias, 255);
			lportp->tgt_alias[255] = 0;
		} else {
			lportp->tgt_alias[0] = 0;
		}
		mutex_exit(&stmf_state.stmf_lock);
		break;

	case STMF_IOCTL_SET_STMF_STATE:
		if ((ibuf == NULL) ||
		    (iocd->stmf_ibuf_size < sizeof (stmf_state_desc_t))) {
			ret = EINVAL;
			break;
		}
		ret = stmf_set_stmf_state((stmf_state_desc_t *)ibuf);
		break;

	case STMF_IOCTL_GET_STMF_STATE:
		if ((obuf == NULL) ||
		    (iocd->stmf_obuf_size < sizeof (stmf_state_desc_t))) {
			ret = EINVAL;
			break;
		}
		ret = stmf_get_stmf_state((stmf_state_desc_t *)obuf);
		break;

	case STMF_IOCTL_SET_ALUA_STATE:
		if ((ibuf == NULL) ||
		    (iocd->stmf_ibuf_size < sizeof (stmf_alua_state_desc_t))) {
			ret = EINVAL;
			break;
		}
		ret = stmf_set_alua_state((stmf_alua_state_desc_t *)ibuf);
		break;

	case STMF_IOCTL_GET_ALUA_STATE:
		if ((obuf == NULL) ||
		    (iocd->stmf_obuf_size < sizeof (stmf_alua_state_desc_t))) {
			ret = EINVAL;
			break;
		}
		stmf_get_alua_state((stmf_alua_state_desc_t *)obuf);
		break;

	case STMF_IOCTL_SET_LU_STATE:
		ssi.st_rflags = STMF_RFLAG_USER_REQUEST;
		ssi.st_additional_info = NULL;
		std = (stmf_state_desc_t *)ibuf;
		if ((ibuf == NULL) ||
		    (iocd->stmf_ibuf_size < sizeof (stmf_state_desc_t))) {
			ret = EINVAL;
			break;
		}
		p_id = std->ident;
		mutex_enter(&stmf_state.stmf_lock);
		if (stmf_state.stmf_inventory_locked) {
			mutex_exit(&stmf_state.stmf_lock);
			ret = EBUSY;
			break;
		}
		for (ilu = stmf_state.stmf_ilulist; ilu; ilu = ilu->ilu_next) {
			if (bcmp(p_id, ilu->ilu_lu->lu_id->ident, 16) == 0)
				break;
		}
		if (ilu == NULL) {
			mutex_exit(&stmf_state.stmf_lock);
			ret = ENOENT;
			break;
		}
		stmf_state.stmf_inventory_locked = 1;
		mutex_exit(&stmf_state.stmf_lock);
		cmd = (std->state == STMF_STATE_ONLINE) ? STMF_CMD_LU_ONLINE :
		    STMF_CMD_LU_OFFLINE;
		ctl_ret = stmf_ctl(cmd, (void *)ilu->ilu_lu, &ssi);
		if (ctl_ret == STMF_ALREADY)
			ret = 0;
		else if (ctl_ret == STMF_BUSY)
			ret = EBUSY;
		else if (ctl_ret != STMF_SUCCESS)
			ret = EIO;
		mutex_enter(&stmf_state.stmf_lock);
		stmf_state.stmf_inventory_locked = 0;
		mutex_exit(&stmf_state.stmf_lock);
		break;

	case STMF_IOCTL_SET_STMF_PROPS:
		if ((ibuf == NULL) ||
		    (iocd->stmf_ibuf_size < sizeof (stmf_set_props_t))) {
			ret = EINVAL;
			break;
		}
		stmf_set_props = (stmf_set_props_t *)ibuf;
		mutex_enter(&stmf_state.stmf_lock);
		if ((stmf_set_props->default_lu_state_value ==
		    STMF_STATE_OFFLINE) ||
		    (stmf_set_props->default_lu_state_value ==
		    STMF_STATE_ONLINE)) {
			stmf_state.stmf_default_lu_state =
			    stmf_set_props->default_lu_state_value;
		}
		if ((stmf_set_props->default_target_state_value ==
		    STMF_STATE_OFFLINE) ||
		    (stmf_set_props->default_target_state_value ==
		    STMF_STATE_ONLINE)) {
			stmf_state.stmf_default_lport_state =
			    stmf_set_props->default_target_state_value;
		}

		mutex_exit(&stmf_state.stmf_lock);
		break;

	case STMF_IOCTL_SET_TARGET_PORT_STATE:
		ssi.st_rflags = STMF_RFLAG_USER_REQUEST;
		ssi.st_additional_info = NULL;
		std = (stmf_state_desc_t *)ibuf;
		if ((ibuf == NULL) ||
		    (iocd->stmf_ibuf_size < sizeof (stmf_state_desc_t))) {
			ret = EINVAL;
			break;
		}
		p_id = std->ident;
		mutex_enter(&stmf_state.stmf_lock);
		if (stmf_state.stmf_inventory_locked) {
			mutex_exit(&stmf_state.stmf_lock);
			ret = EBUSY;
			break;
		}
		for (ilport = stmf_state.stmf_ilportlist; ilport;
		    ilport = ilport->ilport_next) {
			uint8_t *id;
			id = (uint8_t *)ilport->ilport_lport->lport_id;
			if ((id[3] == p_id[3]) &&
			    (bcmp(id+4, p_id+4, id[3]) == 0)) {
				break;
			}
		}
		if (ilport == NULL) {
			mutex_exit(&stmf_state.stmf_lock);
			ret = ENOENT;
			break;
		}
		stmf_state.stmf_inventory_locked = 1;
		mutex_exit(&stmf_state.stmf_lock);
		cmd = (std->state == STMF_STATE_ONLINE) ?
		    STMF_CMD_LPORT_ONLINE : STMF_CMD_LPORT_OFFLINE;
		ctl_ret = stmf_ctl(cmd, (void *)ilport->ilport_lport, &ssi);
		if (ctl_ret == STMF_ALREADY)
			ret = 0;
		else if (ctl_ret == STMF_BUSY)
			ret = EBUSY;
		else if (ctl_ret != STMF_SUCCESS)
			ret = EIO;
		mutex_enter(&stmf_state.stmf_lock);
		stmf_state.stmf_inventory_locked = 0;
		mutex_exit(&stmf_state.stmf_lock);
		break;

	case STMF_IOCTL_ADD_HG_ENTRY:
		idtype = STMF_ID_TYPE_HOST;
		/* FALLTHROUGH */
	case STMF_IOCTL_ADD_TG_ENTRY:
		if (stmf_state.stmf_config_state == STMF_CONFIG_NONE) {
			ret = EACCES;
			iocd->stmf_error = STMF_IOCERR_UPDATE_NEED_CFG_INIT;
			break;
		}
		if (cmd == STMF_IOCTL_ADD_TG_ENTRY) {
			idtype = STMF_ID_TYPE_TARGET;
		}
		grp_entry = (stmf_group_op_data_t *)ibuf;
		if ((ibuf == NULL) ||
		    (iocd->stmf_ibuf_size < sizeof (stmf_group_op_data_t))) {
			ret = EINVAL;
			break;
		}
		if (grp_entry->group.name[0] == '*') {
			ret = EINVAL;
			break; /* not allowed */
		}
		mutex_enter(&stmf_state.stmf_lock);
		ret = stmf_add_group_member(grp_entry->group.name,
		    grp_entry->group.name_size,
		    grp_entry->ident + 4,
		    grp_entry->ident[3],
		    idtype,
		    &iocd->stmf_error);
		mutex_exit(&stmf_state.stmf_lock);
		break;
	case STMF_IOCTL_REMOVE_HG_ENTRY:
		idtype = STMF_ID_TYPE_HOST;
		/* FALLTHROUGH */
	case STMF_IOCTL_REMOVE_TG_ENTRY:
		if (stmf_state.stmf_config_state == STMF_CONFIG_NONE) {
			ret = EACCES;
			iocd->stmf_error = STMF_IOCERR_UPDATE_NEED_CFG_INIT;
			break;
		}
		if (cmd == STMF_IOCTL_REMOVE_TG_ENTRY) {
			idtype = STMF_ID_TYPE_TARGET;
		}
		grp_entry = (stmf_group_op_data_t *)ibuf;
		if ((ibuf == NULL) ||
		    (iocd->stmf_ibuf_size < sizeof (stmf_group_op_data_t))) {
			ret = EINVAL;
			break;
		}
		if (grp_entry->group.name[0] == '*') {
			ret = EINVAL;
			break; /* not allowed */
		}
		mutex_enter(&stmf_state.stmf_lock);
		ret = stmf_remove_group_member(grp_entry->group.name,
		    grp_entry->group.name_size,
		    grp_entry->ident + 4,
		    grp_entry->ident[3],
		    idtype,
		    &iocd->stmf_error);
		mutex_exit(&stmf_state.stmf_lock);
		break;
	case STMF_IOCTL_CREATE_HOST_GROUP:
		idtype = STMF_ID_TYPE_HOST_GROUP;
		/* FALLTHROUGH */
	case STMF_IOCTL_CREATE_TARGET_GROUP:
		if (stmf_state.stmf_config_state == STMF_CONFIG_NONE) {
			ret = EACCES;
			iocd->stmf_error = STMF_IOCERR_UPDATE_NEED_CFG_INIT;
			break;
		}
		grpname = (stmf_group_name_t *)ibuf;

		if (cmd == STMF_IOCTL_CREATE_TARGET_GROUP)
			idtype = STMF_ID_TYPE_TARGET_GROUP;
		if ((ibuf == NULL) ||
		    (iocd->stmf_ibuf_size < sizeof (stmf_group_name_t))) {
			ret = EINVAL;
			break;
		}
		if (grpname->name[0] == '*') {
			ret = EINVAL;
			break; /* not allowed */
		}
		mutex_enter(&stmf_state.stmf_lock);
		ret = stmf_add_group(grpname->name,
		    grpname->name_size, idtype, &iocd->stmf_error);
		mutex_exit(&stmf_state.stmf_lock);
		break;
	case STMF_IOCTL_REMOVE_HOST_GROUP:
		idtype = STMF_ID_TYPE_HOST_GROUP;
		/* FALLTHROUGH */
	case STMF_IOCTL_REMOVE_TARGET_GROUP:
		if (stmf_state.stmf_config_state == STMF_CONFIG_NONE) {
			ret = EACCES;
			iocd->stmf_error = STMF_IOCERR_UPDATE_NEED_CFG_INIT;
			break;
		}
		grpname = (stmf_group_name_t *)ibuf;
		if (cmd == STMF_IOCTL_REMOVE_TARGET_GROUP)
			idtype = STMF_ID_TYPE_TARGET_GROUP;
		if ((ibuf == NULL) ||
		    (iocd->stmf_ibuf_size < sizeof (stmf_group_name_t))) {
			ret = EINVAL;
			break;
		}
		if (grpname->name[0] == '*') {
			ret = EINVAL;
			break; /* not allowed */
		}
		mutex_enter(&stmf_state.stmf_lock);
		ret = stmf_remove_group(grpname->name,
		    grpname->name_size, idtype, &iocd->stmf_error);
		mutex_exit(&stmf_state.stmf_lock);
		break;
	case STMF_IOCTL_VALIDATE_VIEW:
	case STMF_IOCTL_ADD_VIEW_ENTRY:
		if (stmf_state.stmf_config_state == STMF_CONFIG_NONE) {
			ret = EACCES;
			iocd->stmf_error = STMF_IOCERR_UPDATE_NEED_CFG_INIT;
			break;
		}
		ve = (stmf_view_op_entry_t *)ibuf;
		if ((ibuf == NULL) ||
		    (iocd->stmf_ibuf_size < sizeof (stmf_view_op_entry_t))) {
			ret = EINVAL;
			break;
		}
		if (!ve->ve_lu_number_valid)
			ve->ve_lu_nbr[2] = 0xFF;
		if (ve->ve_all_hosts) {
			ve->ve_host_group.name[0] = '*';
			ve->ve_host_group.name_size = 1;
		}
		if (ve->ve_all_targets) {
			ve->ve_target_group.name[0] = '*';
			ve->ve_target_group.name_size = 1;
		}
		if (ve->ve_ndx_valid)
			veid = ve->ve_ndx;
		else
			veid = 0xffffffff;
		mutex_enter(&stmf_state.stmf_lock);
		if (cmd == STMF_IOCTL_ADD_VIEW_ENTRY) {
			ret = stmf_add_ve(ve->ve_host_group.name,
			    ve->ve_host_group.name_size,
			    ve->ve_target_group.name,
			    ve->ve_target_group.name_size,
			    ve->ve_guid,
			    &veid,
			    ve->ve_lu_nbr,
			    &iocd->stmf_error);
		} else {  /* STMF_IOCTL_VALIDATE_VIEW */
			ret = stmf_validate_lun_ve(ve->ve_host_group.name,
			    ve->ve_host_group.name_size,
			    ve->ve_target_group.name,
			    ve->ve_target_group.name_size,
			    ve->ve_lu_nbr,
			    &iocd->stmf_error);
		}
		mutex_exit(&stmf_state.stmf_lock);
		if (ret == 0 &&
		    (!ve->ve_ndx_valid || !ve->ve_lu_number_valid) &&
		    iocd->stmf_obuf_size >= sizeof (stmf_view_op_entry_t)) {
			stmf_view_op_entry_t *ve_ret =
			    (stmf_view_op_entry_t *)obuf;
			iocd->stmf_obuf_nentries = 1;
			iocd->stmf_obuf_max_nentries = 1;
			if (!ve->ve_ndx_valid) {
				ve_ret->ve_ndx = veid;
				ve_ret->ve_ndx_valid = 1;
			}
			if (!ve->ve_lu_number_valid) {
				ve_ret->ve_lu_number_valid = 1;
				bcopy(ve->ve_lu_nbr, ve_ret->ve_lu_nbr, 8);
			}
		}
		break;
	case STMF_IOCTL_REMOVE_VIEW_ENTRY:
		if (stmf_state.stmf_config_state == STMF_CONFIG_NONE) {
			ret = EACCES;
			iocd->stmf_error = STMF_IOCERR_UPDATE_NEED_CFG_INIT;
			break;
		}
		ve = (stmf_view_op_entry_t *)ibuf;
		if ((ibuf == NULL) ||
		    (iocd->stmf_ibuf_size < sizeof (stmf_view_op_entry_t))) {
			ret = EINVAL;
			break;
		}
		if (!ve->ve_ndx_valid) {
			ret = EINVAL;
			break;
		}
		mutex_enter(&stmf_state.stmf_lock);
		ret = stmf_remove_ve_by_id(ve->ve_guid, ve->ve_ndx,
		    &iocd->stmf_error);
		mutex_exit(&stmf_state.stmf_lock);
		break;
	case STMF_IOCTL_GET_HG_LIST:
		id_list = &stmf_state.stmf_hg_list;
		/* FALLTHROUGH */
	case STMF_IOCTL_GET_TG_LIST:
		if (cmd == STMF_IOCTL_GET_TG_LIST)
			id_list = &stmf_state.stmf_tg_list;
		mutex_enter(&stmf_state.stmf_lock);
		iocd->stmf_obuf_max_nentries = id_list->id_count;
		n = min(id_list->id_count,
		    (iocd->stmf_obuf_size)/sizeof (stmf_group_name_t));
		iocd->stmf_obuf_nentries = n;
		id_entry = id_list->idl_head;
		grpname = (stmf_group_name_t *)obuf;
		for (i = 0; i < n; i++) {
			if (id_entry->id_data[0] == '*') {
				if (iocd->stmf_obuf_nentries > 0) {
					iocd->stmf_obuf_nentries--;
				}
				id_entry = id_entry->id_next;
				continue;
			}
			grpname->name_size = id_entry->id_data_size;
			bcopy(id_entry->id_data, grpname->name,
			    id_entry->id_data_size);
			grpname++;
			id_entry = id_entry->id_next;
		}
		mutex_exit(&stmf_state.stmf_lock);
		break;
	case STMF_IOCTL_GET_HG_ENTRIES:
		id_list = &stmf_state.stmf_hg_list;
		/* FALLTHROUGH */
	case STMF_IOCTL_GET_TG_ENTRIES:
		grpname = (stmf_group_name_t *)ibuf;
		if ((ibuf == NULL) ||
		    (iocd->stmf_ibuf_size < sizeof (stmf_group_name_t))) {
			ret = EINVAL;
			break;
		}
		if (cmd == STMF_IOCTL_GET_TG_ENTRIES) {
			id_list = &stmf_state.stmf_tg_list;
		}
		mutex_enter(&stmf_state.stmf_lock);
		id_entry = stmf_lookup_id(id_list, grpname->name_size,
		    grpname->name);
		if (!id_entry)
			ret = ENODEV;
		else {
			stmf_ge_ident_t *grp_entry;
			id_list = (stmf_id_list_t *)id_entry->id_impl_specific;
			iocd->stmf_obuf_max_nentries = id_list->id_count;
			n = min(id_list->id_count,
			    iocd->stmf_obuf_size/sizeof (stmf_ge_ident_t));
			iocd->stmf_obuf_nentries = n;
			id_entry = id_list->idl_head;
			grp_entry = (stmf_ge_ident_t *)obuf;
			for (i = 0; i < n; i++) {
				bcopy(id_entry->id_data, grp_entry->ident,
				    id_entry->id_data_size);
				grp_entry->ident_size = id_entry->id_data_size;
				id_entry = id_entry->id_next;
				grp_entry++;
			}
		}
		mutex_exit(&stmf_state.stmf_lock);
		break;

	case STMF_IOCTL_GET_VE_LIST:
		n = iocd->stmf_obuf_size/sizeof (stmf_view_op_entry_t);
		mutex_enter(&stmf_state.stmf_lock);
		ve = (stmf_view_op_entry_t *)obuf;
		for (id_entry = stmf_state.stmf_luid_list.idl_head;
		    id_entry; id_entry = id_entry->id_next) {
			for (view_entry = (stmf_view_entry_t *)
			    id_entry->id_impl_specific; view_entry;
			    view_entry = view_entry->ve_next) {
				iocd->stmf_obuf_max_nentries++;
				if (iocd->stmf_obuf_nentries >= n)
					continue;
				ve->ve_ndx_valid = 1;
				ve->ve_ndx = view_entry->ve_id;
				ve->ve_lu_number_valid = 1;
				bcopy(view_entry->ve_lun, ve->ve_lu_nbr, 8);
				bcopy(view_entry->ve_luid->id_data, ve->ve_guid,
				    view_entry->ve_luid->id_data_size);
				if (view_entry->ve_hg->id_data[0] == '*') {
					ve->ve_all_hosts = 1;
				} else {
					bcopy(view_entry->ve_hg->id_data,
					    ve->ve_host_group.name,
					    view_entry->ve_hg->id_data_size);
					ve->ve_host_group.name_size =
					    view_entry->ve_hg->id_data_size;
				}

				if (view_entry->ve_tg->id_data[0] == '*') {
					ve->ve_all_targets = 1;
				} else {
					bcopy(view_entry->ve_tg->id_data,
					    ve->ve_target_group.name,
					    view_entry->ve_tg->id_data_size);
					ve->ve_target_group.name_size =
					    view_entry->ve_tg->id_data_size;
				}
				ve++;
				iocd->stmf_obuf_nentries++;
			}
		}
		mutex_exit(&stmf_state.stmf_lock);
		break;

	case STMF_IOCTL_LU_VE_LIST:
		p_id = (uint8_t *)ibuf;
		if ((iocd->stmf_ibuf_size != 16) ||
		    (iocd->stmf_obuf_size < sizeof (stmf_view_op_entry_t))) {
			ret = EINVAL;
			break;
		}

		n = iocd->stmf_obuf_size/sizeof (stmf_view_op_entry_t);
		mutex_enter(&stmf_state.stmf_lock);
		ve = (stmf_view_op_entry_t *)obuf;
		for (id_entry = stmf_state.stmf_luid_list.idl_head;
		    id_entry; id_entry = id_entry->id_next) {
			if (bcmp(id_entry->id_data, p_id, 16) != 0)
				continue;
			for (view_entry = (stmf_view_entry_t *)
			    id_entry->id_impl_specific; view_entry;
			    view_entry = view_entry->ve_next) {
				iocd->stmf_obuf_max_nentries++;
				if (iocd->stmf_obuf_nentries >= n)
					continue;
				ve->ve_ndx_valid = 1;
				ve->ve_ndx = view_entry->ve_id;
				ve->ve_lu_number_valid = 1;
				bcopy(view_entry->ve_lun, ve->ve_lu_nbr, 8);
				bcopy(view_entry->ve_luid->id_data, ve->ve_guid,
				    view_entry->ve_luid->id_data_size);
				if (view_entry->ve_hg->id_data[0] == '*') {
					ve->ve_all_hosts = 1;
				} else {
					bcopy(view_entry->ve_hg->id_data,
					    ve->ve_host_group.name,
					    view_entry->ve_hg->id_data_size);
					ve->ve_host_group.name_size =
					    view_entry->ve_hg->id_data_size;
				}

				if (view_entry->ve_tg->id_data[0] == '*') {
					ve->ve_all_targets = 1;
				} else {
					bcopy(view_entry->ve_tg->id_data,
					    ve->ve_target_group.name,
					    view_entry->ve_tg->id_data_size);
					ve->ve_target_group.name_size =
					    view_entry->ve_tg->id_data_size;
				}
				ve++;
				iocd->stmf_obuf_nentries++;
			}
			break;
		}
		mutex_exit(&stmf_state.stmf_lock);
		break;

	case STMF_IOCTL_LOAD_PP_DATA:
		if (stmf_state.stmf_config_state == STMF_CONFIG_NONE) {
			ret = EACCES;
			iocd->stmf_error = STMF_IOCERR_UPDATE_NEED_CFG_INIT;
			break;
		}
		ppi = (stmf_ppioctl_data_t *)ibuf;
		if ((ppi == NULL) ||
		    (iocd->stmf_ibuf_size < sizeof (stmf_ppioctl_data_t))) {
			ret = EINVAL;
			break;
		}
		/* returned token */
		ppi_token = (uint64_t *)obuf;
		if ((ppi_token == NULL) ||
		    (iocd->stmf_obuf_size < sizeof (uint64_t))) {
			ret = EINVAL;
			break;
		}
		ret = stmf_load_ppd_ioctl(ppi, ppi_token, &iocd->stmf_error);
		break;

	case STMF_IOCTL_GET_PP_DATA:
		if (stmf_state.stmf_config_state == STMF_CONFIG_NONE) {
			ret = EACCES;
			iocd->stmf_error = STMF_IOCERR_UPDATE_NEED_CFG_INIT;
			break;
		}
		ppi = (stmf_ppioctl_data_t *)ibuf;
		if (ppi == NULL ||
		    (iocd->stmf_ibuf_size < sizeof (stmf_ppioctl_data_t))) {
			ret = EINVAL;
			break;
		}
		ppi_out = (stmf_ppioctl_data_t *)obuf;
		if ((ppi_out == NULL) ||
		    (iocd->stmf_obuf_size < sizeof (stmf_ppioctl_data_t))) {
			ret = EINVAL;
			break;
		}
		ret = stmf_get_ppd_ioctl(ppi, ppi_out, &iocd->stmf_error);
		break;

	case STMF_IOCTL_CLEAR_PP_DATA:
		if (stmf_state.stmf_config_state == STMF_CONFIG_NONE) {
			ret = EACCES;
			iocd->stmf_error = STMF_IOCERR_UPDATE_NEED_CFG_INIT;
			break;
		}
		ppi = (stmf_ppioctl_data_t *)ibuf;
		if ((ppi == NULL) ||
		    (iocd->stmf_ibuf_size < sizeof (stmf_ppioctl_data_t))) {
			ret = EINVAL;
			break;
		}
		ret = stmf_delete_ppd_ioctl(ppi);
		break;

	case STMF_IOCTL_CLEAR_TRACE:
		stmf_trace_clear();
		break;

	case STMF_IOCTL_ADD_TRACE:
		if (iocd->stmf_ibuf_size && ibuf) {
			((uint8_t *)ibuf)[iocd->stmf_ibuf_size - 1] = 0;
			stmf_trace("\nstradm", "%s\n", ibuf);
		}
		break;

	case STMF_IOCTL_GET_TRACE_POSITION:
		if (obuf && (iocd->stmf_obuf_size > 3)) {
			mutex_enter(&trace_buf_lock);
			*((int *)obuf) = trace_buf_curndx;
			mutex_exit(&trace_buf_lock);
		} else {
			ret = EINVAL;
		}
		break;

	case STMF_IOCTL_GET_TRACE:
		if ((iocd->stmf_obuf_size == 0) || (iocd->stmf_ibuf_size < 4)) {
			ret = EINVAL;
			break;
		}
		i = *((int *)ibuf);
		if ((i > trace_buf_size) || ((i + iocd->stmf_obuf_size) >
		    trace_buf_size)) {
			ret = EINVAL;
			break;
		}
		mutex_enter(&trace_buf_lock);
		bcopy(stmf_trace_buf + i, obuf, iocd->stmf_obuf_size);
		mutex_exit(&trace_buf_lock);
		break;

	default:
		ret = ENOTTY;
	}

	if (ret == 0) {
		ret = stmf_copyout_iocdata(data, mode, iocd, obuf);
	} else if (iocd->stmf_error) {
		(void) stmf_copyout_iocdata(data, mode, iocd, obuf);
	}
	if (obuf) {
		kmem_free(obuf, iocd->stmf_obuf_size);
		obuf = NULL;
	}
	if (ibuf) {
		kmem_free(ibuf, iocd->stmf_ibuf_size);
		ibuf = NULL;
	}
	kmem_free(iocd, sizeof (stmf_iocdata_t));
	return (ret);
}

static int
stmf_get_service_state()
{
	stmf_i_local_port_t *ilport;
	stmf_i_lu_t *ilu;
	int online = 0;
	int offline = 0;
	int onlining = 0;
	int offlining = 0;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));
	for (ilport = stmf_state.stmf_ilportlist; ilport != NULL;
	    ilport = ilport->ilport_next) {
		if (ilport->ilport_state == STMF_STATE_OFFLINE)
			offline++;
		else if (ilport->ilport_state == STMF_STATE_ONLINE)
			online++;
		else if (ilport->ilport_state == STMF_STATE_ONLINING)
			onlining++;
		else if (ilport->ilport_state == STMF_STATE_OFFLINING)
			offlining++;
	}

	for (ilu = stmf_state.stmf_ilulist; ilu != NULL;
	    ilu = ilu->ilu_next) {
		if (ilu->ilu_state == STMF_STATE_OFFLINE)
			offline++;
		else if (ilu->ilu_state == STMF_STATE_ONLINE)
			online++;
		else if (ilu->ilu_state == STMF_STATE_ONLINING)
			onlining++;
		else if (ilu->ilu_state == STMF_STATE_OFFLINING)
			offlining++;
	}

	if (stmf_state.stmf_service_running) {
		if (onlining)
			return (STMF_STATE_ONLINING);
		else
			return (STMF_STATE_ONLINE);
	}

	if (offlining) {
		return (STMF_STATE_OFFLINING);
	}

	return (STMF_STATE_OFFLINE);
}

static int
stmf_set_stmf_state(stmf_state_desc_t *std)
{
	stmf_i_local_port_t *ilport;
	stmf_i_lu_t *ilu;
	stmf_state_change_info_t ssi;
	int svc_state;

	ssi.st_rflags = STMF_RFLAG_USER_REQUEST;
	ssi.st_additional_info = NULL;

	mutex_enter(&stmf_state.stmf_lock);
	if (!stmf_state.stmf_exclusive_open) {
		mutex_exit(&stmf_state.stmf_lock);
		return (EACCES);
	}

	if (stmf_state.stmf_inventory_locked) {
		mutex_exit(&stmf_state.stmf_lock);
		return (EBUSY);
	}

	if ((std->state != STMF_STATE_ONLINE) &&
	    (std->state != STMF_STATE_OFFLINE)) {
		mutex_exit(&stmf_state.stmf_lock);
		return (EINVAL);
	}

	svc_state = stmf_get_service_state();
	if ((svc_state == STMF_STATE_OFFLINING) ||
	    (svc_state == STMF_STATE_ONLINING)) {
		mutex_exit(&stmf_state.stmf_lock);
		return (EBUSY);
	}

	if (svc_state == STMF_STATE_OFFLINE) {
		if (std->config_state == STMF_CONFIG_INIT) {
			if (std->state != STMF_STATE_OFFLINE) {
				mutex_exit(&stmf_state.stmf_lock);
				return (EINVAL);
			}
			stmf_state.stmf_config_state = STMF_CONFIG_INIT;
			stmf_delete_all_ppds();
			stmf_view_clear_config();
			stmf_view_init();
			mutex_exit(&stmf_state.stmf_lock);
			return (0);
		}
		if ((stmf_state.stmf_config_state == STMF_CONFIG_INIT) ||
		    (stmf_state.stmf_config_state == STMF_CONFIG_NONE)) {
			if (std->config_state != STMF_CONFIG_INIT_DONE) {
				mutex_exit(&stmf_state.stmf_lock);
				return (EINVAL);
			}
			stmf_state.stmf_config_state = STMF_CONFIG_INIT_DONE;
		}
		if (std->state == STMF_STATE_OFFLINE) {
			mutex_exit(&stmf_state.stmf_lock);
			return (0);
		}
		if (stmf_state.stmf_config_state == STMF_CONFIG_INIT) {
			mutex_exit(&stmf_state.stmf_lock);
			return (EINVAL);
		}
		stmf_state.stmf_inventory_locked = 1;
		stmf_state.stmf_service_running = 1;
		mutex_exit(&stmf_state.stmf_lock);

		for (ilport = stmf_state.stmf_ilportlist; ilport != NULL;
		    ilport = ilport->ilport_next) {
			if (stmf_state.stmf_default_lport_state !=
			    STMF_STATE_ONLINE)
				continue;
			(void) stmf_ctl(STMF_CMD_LPORT_ONLINE,
			    ilport->ilport_lport, &ssi);
		}

		for (ilu = stmf_state.stmf_ilulist; ilu != NULL;
		    ilu = ilu->ilu_next) {
			if (stmf_state.stmf_default_lu_state !=
			    STMF_STATE_ONLINE)
				continue;
			(void) stmf_ctl(STMF_CMD_LU_ONLINE, ilu->ilu_lu, &ssi);
		}
		mutex_enter(&stmf_state.stmf_lock);
		stmf_state.stmf_inventory_locked = 0;
		mutex_exit(&stmf_state.stmf_lock);
		return (0);
	}

	/* svc_state is STMF_STATE_ONLINE here */
	if ((std->state != STMF_STATE_OFFLINE) ||
	    (std->config_state == STMF_CONFIG_INIT)) {
		mutex_exit(&stmf_state.stmf_lock);
		return (EACCES);
	}

	stmf_state.stmf_inventory_locked = 1;
	stmf_state.stmf_service_running = 0;

	mutex_exit(&stmf_state.stmf_lock);
	for (ilport = stmf_state.stmf_ilportlist; ilport != NULL;
	    ilport = ilport->ilport_next) {
		if (ilport->ilport_state != STMF_STATE_ONLINE)
			continue;
		(void) stmf_ctl(STMF_CMD_LPORT_OFFLINE,
		    ilport->ilport_lport, &ssi);
	}

	for (ilu = stmf_state.stmf_ilulist; ilu != NULL;
	    ilu = ilu->ilu_next) {
		if (ilu->ilu_state != STMF_STATE_ONLINE)
			continue;
		(void) stmf_ctl(STMF_CMD_LU_OFFLINE, ilu->ilu_lu, &ssi);
	}
	mutex_enter(&stmf_state.stmf_lock);
	stmf_state.stmf_inventory_locked = 0;
	mutex_exit(&stmf_state.stmf_lock);
	return (0);
}

static int
stmf_get_stmf_state(stmf_state_desc_t *std)
{
	mutex_enter(&stmf_state.stmf_lock);
	std->state = stmf_get_service_state();
	std->config_state = stmf_state.stmf_config_state;
	mutex_exit(&stmf_state.stmf_lock);

	return (0);
}

/*
 * handles registration message from pppt for a logical unit
 */
stmf_status_t
stmf_ic_lu_reg(stmf_ic_reg_dereg_lun_msg_t *msg, uint32_t type)
{
	stmf_i_lu_provider_t	*ilp;
	stmf_lu_provider_t	*lp;
	mutex_enter(&stmf_state.stmf_lock);
	for (ilp = stmf_state.stmf_ilplist; ilp != NULL; ilp = ilp->ilp_next) {
		if (strcmp(msg->icrl_lu_provider_name,
		    ilp->ilp_lp->lp_name) == 0) {
			lp = ilp->ilp_lp;
			mutex_exit(&stmf_state.stmf_lock);
			lp->lp_proxy_msg(msg->icrl_lun_id, msg->icrl_cb_arg,
			    msg->icrl_cb_arg_len, type);
			return (STMF_SUCCESS);
		}
	}
	mutex_exit(&stmf_state.stmf_lock);
	return (STMF_SUCCESS);
}

/*
 * handles de-registration message from pppt for a logical unit
 */
stmf_status_t
stmf_ic_lu_dereg(stmf_ic_reg_dereg_lun_msg_t *msg)
{
	stmf_i_lu_provider_t	*ilp;
	stmf_lu_provider_t	*lp;
	mutex_enter(&stmf_state.stmf_lock);
	for (ilp = stmf_state.stmf_ilplist; ilp != NULL; ilp = ilp->ilp_next) {
		if (strcmp(msg->icrl_lu_provider_name,
		    ilp->ilp_lp->lp_name) == 0) {
			lp = ilp->ilp_lp;
			mutex_exit(&stmf_state.stmf_lock);
			lp->lp_proxy_msg(msg->icrl_lun_id, NULL, 0,
			    STMF_MSG_LU_DEREGISTER);
			return (STMF_SUCCESS);
		}
	}
	mutex_exit(&stmf_state.stmf_lock);
	return (STMF_SUCCESS);
}

/*
 * helper function to find a task that matches a task_msgid
 */
scsi_task_t *
find_task_from_msgid(uint8_t *lu_id, stmf_ic_msgid_t task_msgid)
{
	stmf_i_lu_t *ilu;
	stmf_i_scsi_task_t *itask;

	mutex_enter(&stmf_state.stmf_lock);
	for (ilu = stmf_state.stmf_ilulist; ilu != NULL; ilu = ilu->ilu_next) {
		if (bcmp(lu_id, ilu->ilu_lu->lu_id->ident, 16) == 0) {
			break;
		}
	}

	if (ilu == NULL) {
		mutex_exit(&stmf_state.stmf_lock);
		return (NULL);
	}

	mutex_enter(&ilu->ilu_task_lock);
	for (itask = ilu->ilu_tasks; itask != NULL;
	    itask = itask->itask_lu_next) {
		if (itask->itask_flags & (ITASK_IN_FREE_LIST |
		    ITASK_BEING_ABORTED)) {
			continue;
		}
		if (itask->itask_proxy_msg_id == task_msgid) {
			break;
		}
	}
	mutex_exit(&ilu->ilu_task_lock);
	mutex_exit(&stmf_state.stmf_lock);

	if (itask != NULL) {
		return (itask->itask_task);
	} else {
		/* task not found. Likely already aborted. */
		return (NULL);
	}
}

/*
 * message received from pppt/ic
 */
stmf_status_t
stmf_msg_rx(stmf_ic_msg_t *msg)
{
	mutex_enter(&stmf_state.stmf_lock);
	if (stmf_state.stmf_alua_state != 1) {
		mutex_exit(&stmf_state.stmf_lock);
		cmn_err(CE_WARN, "stmf alua state is disabled");
		ic_msg_free(msg);
		return (STMF_FAILURE);
	}
	mutex_exit(&stmf_state.stmf_lock);

	switch (msg->icm_msg_type) {
		case STMF_ICM_REGISTER_LUN:
			(void) stmf_ic_lu_reg(
			    (stmf_ic_reg_dereg_lun_msg_t *)msg->icm_msg,
			    STMF_MSG_LU_REGISTER);
			break;
		case STMF_ICM_LUN_ACTIVE:
			(void) stmf_ic_lu_reg(
			    (stmf_ic_reg_dereg_lun_msg_t *)msg->icm_msg,
			    STMF_MSG_LU_ACTIVE);
			break;
		case STMF_ICM_DEREGISTER_LUN:
			(void) stmf_ic_lu_dereg(
			    (stmf_ic_reg_dereg_lun_msg_t *)msg->icm_msg);
			break;
		case STMF_ICM_SCSI_DATA:
			(void) stmf_ic_rx_scsi_data(
			    (stmf_ic_scsi_data_msg_t *)msg->icm_msg);
			break;
		case STMF_ICM_SCSI_STATUS:
			(void) stmf_ic_rx_scsi_status(
			    (stmf_ic_scsi_status_msg_t *)msg->icm_msg);
			break;
		case STMF_ICM_STATUS:
			(void) stmf_ic_rx_status(
			    (stmf_ic_status_msg_t *)msg->icm_msg);
			break;
		default:
			cmn_err(CE_WARN, "unknown message received %d",
			    msg->icm_msg_type);
			ic_msg_free(msg);
			return (STMF_FAILURE);
	}
	ic_msg_free(msg);
	return (STMF_SUCCESS);
}

stmf_status_t
stmf_ic_rx_status(stmf_ic_status_msg_t *msg)
{
	stmf_i_local_port_t *ilport;

	if (msg->ics_msg_type != STMF_ICM_REGISTER_PROXY_PORT) {
		/* for now, ignore other message status */
		return (STMF_SUCCESS);
	}

	if (msg->ics_status != STMF_SUCCESS) {
		return (STMF_SUCCESS);
	}

	mutex_enter(&stmf_state.stmf_lock);
	for (ilport = stmf_state.stmf_ilportlist; ilport != NULL;
	    ilport = ilport->ilport_next) {
		if (msg->ics_msgid == ilport->ilport_reg_msgid) {
			ilport->ilport_proxy_registered = 1;
			break;
		}
	}
	mutex_exit(&stmf_state.stmf_lock);
	return (STMF_SUCCESS);
}

/*
 * handles scsi status message from pppt
 */
stmf_status_t
stmf_ic_rx_scsi_status(stmf_ic_scsi_status_msg_t *msg)
{
	scsi_task_t *task;

	/* is this a task management command */
	if (msg->icss_task_msgid & MSG_ID_TM_BIT) {
		return (STMF_SUCCESS);
	}

	task = find_task_from_msgid(msg->icss_lun_id, msg->icss_task_msgid);

	if (task == NULL) {
		return (STMF_SUCCESS);
	}

	task->task_scsi_status = msg->icss_status;
	task->task_sense_data = msg->icss_sense;
	task->task_sense_length = msg->icss_sense_len;
	(void) stmf_send_scsi_status(task, STMF_IOF_LU_DONE);

	return (STMF_SUCCESS);
}

/*
 * handles scsi data message from pppt
 */
stmf_status_t
stmf_ic_rx_scsi_data(stmf_ic_scsi_data_msg_t *msg)
{
	stmf_i_scsi_task_t *itask;
	scsi_task_t *task;
	stmf_xfer_data_t *xd = NULL;
	stmf_data_buf_t *dbuf;
	uint32_t sz, minsz, xd_sz, asz;

	/* is this a task management command */
	if (msg->icsd_task_msgid & MSG_ID_TM_BIT) {
		return (STMF_SUCCESS);
	}

	task = find_task_from_msgid(msg->icsd_lun_id, msg->icsd_task_msgid);
	if (task == NULL) {
		stmf_ic_msg_t *ic_xfer_done_msg = NULL;
		static uint64_t data_msg_id;
		stmf_status_t ic_ret = STMF_FAILURE;
		mutex_enter(&stmf_state.stmf_lock);
		data_msg_id = stmf_proxy_msg_id++;
		mutex_exit(&stmf_state.stmf_lock);
		/*
		 * send xfer done status to pppt
		 * for now, set the session id to 0 as we cannot
		 * ascertain it since we cannot find the task
		 */
		ic_xfer_done_msg = ic_scsi_data_xfer_done_msg_alloc(
		    msg->icsd_task_msgid, 0, STMF_FAILURE, data_msg_id);
		if (ic_xfer_done_msg) {
			ic_ret = ic_tx_msg(ic_xfer_done_msg);
			if (ic_ret != STMF_IC_MSG_SUCCESS) {
				cmn_err(CE_WARN, "unable to xmit proxy msg");
			}
		}
		return (STMF_FAILURE);
	}

	itask = (stmf_i_scsi_task_t *)task->task_stmf_private;
	dbuf = itask->itask_proxy_dbuf;

	task->task_cmd_xfer_length += msg->icsd_data_len;

	if (task->task_additional_flags &
	    TASK_AF_NO_EXPECTED_XFER_LENGTH) {
		task->task_expected_xfer_length =
		    task->task_cmd_xfer_length;
	}

	sz = min(task->task_expected_xfer_length,
	    task->task_cmd_xfer_length);

	xd_sz = msg->icsd_data_len;
	asz = xd_sz + sizeof (*xd) - 4;
	xd = (stmf_xfer_data_t *)kmem_zalloc(asz, KM_NOSLEEP);

	if (xd == NULL) {
		stmf_abort(STMF_QUEUE_TASK_ABORT, task,
		    STMF_ALLOC_FAILURE, NULL);
		return (STMF_FAILURE);
	}

	xd->alloc_size = asz;
	xd->size_left = xd_sz;
	bcopy(msg->icsd_data, xd->buf, xd_sz);

	sz = min(sz, xd->size_left);
	xd->size_left = sz;
	minsz = min(512, sz);

	if (dbuf == NULL)
		dbuf = stmf_alloc_dbuf(task, sz, &minsz, 0);
	if (dbuf == NULL) {
		kmem_free(xd, xd->alloc_size);
		stmf_abort(STMF_QUEUE_TASK_ABORT, task,
		    STMF_ALLOC_FAILURE, NULL);
		return (STMF_FAILURE);
	}
	dbuf->db_lu_private = xd;
	dbuf->db_relative_offset = task->task_nbytes_transferred;
	stmf_xd_to_dbuf(dbuf, 0);

	dbuf->db_flags = DB_DIRECTION_TO_RPORT;
	(void) stmf_xfer_data(task, dbuf, 0);
	return (STMF_SUCCESS);
}

stmf_status_t
stmf_proxy_scsi_cmd(scsi_task_t *task, stmf_data_buf_t *dbuf)
{
	stmf_i_scsi_task_t *itask =
	    (stmf_i_scsi_task_t *)task->task_stmf_private;
	stmf_i_local_port_t *ilport =
	    (stmf_i_local_port_t *)task->task_lport->lport_stmf_private;
	stmf_ic_msg_t *ic_cmd_msg;
	stmf_ic_msg_status_t ic_ret;
	stmf_status_t ret = STMF_FAILURE;

	if (stmf_state.stmf_alua_state != 1) {
		cmn_err(CE_WARN, "stmf alua state is disabled");
		return (STMF_FAILURE);
	}

	if (ilport->ilport_proxy_registered == 0) {
		return (STMF_FAILURE);
	}

	mutex_enter(&stmf_state.stmf_lock);
	itask->itask_proxy_msg_id = stmf_proxy_msg_id++;
	mutex_exit(&stmf_state.stmf_lock);
	itask->itask_proxy_dbuf = dbuf;

	/*
	 * stmf will now take over the task handling for this task
	 * but it still needs to be treated differently from other
	 * default handled tasks, hence the ITASK_PROXY_TASK.
	 * If this is a task management function, we're really just
	 * duping the command to the peer. Set the TM bit so that
	 * we can recognize this on return since we won't be completing
	 * the proxied task in that case.
	 */
	if (task->task_mgmt_function) {
		itask->itask_proxy_msg_id |= MSG_ID_TM_BIT;
	} else {
		uint32_t new, old;
		do {
			new = old = itask->itask_flags;
			if (new & ITASK_BEING_ABORTED)
				return (STMF_FAILURE);
			new |= ITASK_DEFAULT_HANDLING | ITASK_PROXY_TASK;
		} while (atomic_cas_32(&itask->itask_flags, old, new) != old);
	}
	if (dbuf) {
		ic_cmd_msg = ic_scsi_cmd_msg_alloc(itask->itask_proxy_msg_id,
		    task, dbuf->db_data_size, dbuf->db_sglist[0].seg_addr,
		    itask->itask_proxy_msg_id);
	} else {
		ic_cmd_msg = ic_scsi_cmd_msg_alloc(itask->itask_proxy_msg_id,
		    task, 0, NULL, itask->itask_proxy_msg_id);
	}
	if (ic_cmd_msg) {
		ic_ret = ic_tx_msg(ic_cmd_msg);
		if (ic_ret == STMF_IC_MSG_SUCCESS) {
			ret = STMF_SUCCESS;
		}
	}
	return (ret);
}


stmf_status_t
pppt_modload()
{
	int error;

	if (pppt_mod == NULL && ((pppt_mod =
	    ddi_modopen("drv/pppt", KRTLD_MODE_FIRST, &error)) == NULL)) {
		cmn_err(CE_WARN, "Unable to load pppt");
		return (STMF_FAILURE);
	}

	if (ic_reg_port_msg_alloc == NULL && ((ic_reg_port_msg_alloc =
	    (stmf_ic_reg_port_msg_alloc_func_t)
	    ddi_modsym(pppt_mod, "stmf_ic_reg_port_msg_alloc",
	    &error)) == NULL)) {
		cmn_err(CE_WARN,
		    "Unable to find symbol - stmf_ic_reg_port_msg_alloc");
		return (STMF_FAILURE);
	}


	if (ic_dereg_port_msg_alloc == NULL && ((ic_dereg_port_msg_alloc =
	    (stmf_ic_dereg_port_msg_alloc_func_t)
	    ddi_modsym(pppt_mod, "stmf_ic_dereg_port_msg_alloc",
	    &error)) == NULL)) {
		cmn_err(CE_WARN,
		    "Unable to find symbol - stmf_ic_dereg_port_msg_alloc");
		return (STMF_FAILURE);
	}

	if (ic_reg_lun_msg_alloc == NULL && ((ic_reg_lun_msg_alloc =
	    (stmf_ic_reg_lun_msg_alloc_func_t)
	    ddi_modsym(pppt_mod, "stmf_ic_reg_lun_msg_alloc",
	    &error)) == NULL)) {
		cmn_err(CE_WARN,
		    "Unable to find symbol - stmf_ic_reg_lun_msg_alloc");
		return (STMF_FAILURE);
	}

	if (ic_lun_active_msg_alloc == NULL && ((ic_lun_active_msg_alloc =
	    (stmf_ic_lun_active_msg_alloc_func_t)
	    ddi_modsym(pppt_mod, "stmf_ic_lun_active_msg_alloc",
	    &error)) == NULL)) {
		cmn_err(CE_WARN,
		    "Unable to find symbol - stmf_ic_lun_active_msg_alloc");
		return (STMF_FAILURE);
	}

	if (ic_dereg_lun_msg_alloc == NULL && ((ic_dereg_lun_msg_alloc =
	    (stmf_ic_dereg_lun_msg_alloc_func_t)
	    ddi_modsym(pppt_mod, "stmf_ic_dereg_lun_msg_alloc",
	    &error)) == NULL)) {
		cmn_err(CE_WARN,
		    "Unable to find symbol - stmf_ic_dereg_lun_msg_alloc");
		return (STMF_FAILURE);
	}

	if (ic_scsi_cmd_msg_alloc == NULL && ((ic_scsi_cmd_msg_alloc =
	    (stmf_ic_scsi_cmd_msg_alloc_func_t)
	    ddi_modsym(pppt_mod, "stmf_ic_scsi_cmd_msg_alloc",
	    &error)) == NULL)) {
		cmn_err(CE_WARN,
		    "Unable to find symbol - stmf_ic_scsi_cmd_msg_alloc");
		return (STMF_FAILURE);
	}

	if (ic_scsi_data_xfer_done_msg_alloc == NULL &&
	    ((ic_scsi_data_xfer_done_msg_alloc =
	    (stmf_ic_scsi_data_xfer_done_msg_alloc_func_t)
	    ddi_modsym(pppt_mod, "stmf_ic_scsi_data_xfer_done_msg_alloc",
	    &error)) == NULL)) {
		cmn_err(CE_WARN,
		    "Unable to find symbol -"
		    "stmf_ic_scsi_data_xfer_done_msg_alloc");
		return (STMF_FAILURE);
	}

	if (ic_session_reg_msg_alloc == NULL &&
	    ((ic_session_reg_msg_alloc =
	    (stmf_ic_session_create_msg_alloc_func_t)
	    ddi_modsym(pppt_mod, "stmf_ic_session_create_msg_alloc",
	    &error)) == NULL)) {
		cmn_err(CE_WARN,
		    "Unable to find symbol -"
		    "stmf_ic_session_create_msg_alloc");
		return (STMF_FAILURE);
	}

	if (ic_session_dereg_msg_alloc == NULL &&
	    ((ic_session_dereg_msg_alloc =
	    (stmf_ic_session_destroy_msg_alloc_func_t)
	    ddi_modsym(pppt_mod, "stmf_ic_session_destroy_msg_alloc",
	    &error)) == NULL)) {
		cmn_err(CE_WARN,
		    "Unable to find symbol -"
		    "stmf_ic_session_destroy_msg_alloc");
		return (STMF_FAILURE);
	}

	if (ic_tx_msg == NULL && ((ic_tx_msg =
	    (stmf_ic_tx_msg_func_t)ddi_modsym(pppt_mod, "stmf_ic_tx_msg",
	    &error)) == NULL)) {
		cmn_err(CE_WARN, "Unable to find symbol - stmf_ic_tx_msg");
		return (STMF_FAILURE);
	}

	if (ic_msg_free == NULL && ((ic_msg_free =
	    (stmf_ic_msg_free_func_t)ddi_modsym(pppt_mod, "stmf_ic_msg_free",
	    &error)) == NULL)) {
		cmn_err(CE_WARN, "Unable to find symbol - stmf_ic_msg_free");
		return (STMF_FAILURE);
	}
	return (STMF_SUCCESS);
}

static void
stmf_get_alua_state(stmf_alua_state_desc_t *alua_state)
{
	mutex_enter(&stmf_state.stmf_lock);
	alua_state->alua_node = stmf_state.stmf_alua_node;
	alua_state->alua_state = stmf_state.stmf_alua_state;
	mutex_exit(&stmf_state.stmf_lock);
}


static int
stmf_set_alua_state(stmf_alua_state_desc_t *alua_state)
{
	stmf_i_local_port_t *ilport;
	stmf_i_lu_t *ilu;
	stmf_lu_t *lu;
	stmf_ic_msg_status_t ic_ret;
	stmf_ic_msg_t *ic_reg_lun, *ic_reg_port;
	stmf_local_port_t *lport;
	int ret = 0;

	if (alua_state->alua_state > 1 || alua_state->alua_node > 1) {
		return (EINVAL);
	}

	mutex_enter(&stmf_state.stmf_lock);
	if (alua_state->alua_state == 1) {
		if (pppt_modload() == STMF_FAILURE) {
			ret = EIO;
			goto err;
		}
		if (alua_state->alua_node != 0) {
			/* reset existing rtpids to new base */
			stmf_rtpid_counter = 255;
		}
		stmf_state.stmf_alua_node = alua_state->alua_node;
		stmf_state.stmf_alua_state = 1;
		/* register existing local ports with ppp */
		for (ilport = stmf_state.stmf_ilportlist; ilport != NULL;
		    ilport = ilport->ilport_next) {
			/* skip standby ports and non-alua participants */
			if (ilport->ilport_standby == 1 ||
			    ilport->ilport_alua == 0) {
				continue;
			}
			if (alua_state->alua_node != 0) {
				ilport->ilport_rtpid =
				    atomic_inc_16_nv(&stmf_rtpid_counter);
			}
			lport = ilport->ilport_lport;
			ic_reg_port = ic_reg_port_msg_alloc(
			    lport->lport_id, ilport->ilport_rtpid,
			    0, NULL, stmf_proxy_msg_id);
			if (ic_reg_port) {
				ic_ret = ic_tx_msg(ic_reg_port);
				if (ic_ret == STMF_IC_MSG_SUCCESS) {
					ilport->ilport_reg_msgid =
					    stmf_proxy_msg_id++;
				} else {
					cmn_err(CE_WARN,
					    "error on port registration "
					    "port - %s",
					    ilport->ilport_kstat_tgt_name);
				}
			}
		}
		/* register existing logical units */
		for (ilu = stmf_state.stmf_ilulist; ilu != NULL;
		    ilu = ilu->ilu_next) {
			if (ilu->ilu_access != STMF_LU_ACTIVE) {
				continue;
			}
			/* register with proxy module */
			lu = ilu->ilu_lu;
			if (lu->lu_lp && lu->lu_lp->lp_lpif_rev == LPIF_REV_2 &&
			    lu->lu_lp->lp_alua_support) {
				ilu->ilu_alua = 1;
				/* allocate the register message */
				ic_reg_lun = ic_reg_lun_msg_alloc(
				    lu->lu_id->ident, lu->lu_lp->lp_name,
				    lu->lu_proxy_reg_arg_len,
				    (uint8_t *)lu->lu_proxy_reg_arg,
				    stmf_proxy_msg_id);
				/* send the message */
				if (ic_reg_lun) {
					ic_ret = ic_tx_msg(ic_reg_lun);
					if (ic_ret == STMF_IC_MSG_SUCCESS) {
						stmf_proxy_msg_id++;
					}
				}
			}
		}
	} else {
		stmf_state.stmf_alua_state = 0;
	}

err:
	mutex_exit(&stmf_state.stmf_lock);
	return (ret);
}


typedef struct {
	void	*bp;	/* back pointer from internal struct to main struct */
	int	alloc_size;
} __istmf_t;

typedef struct {
	__istmf_t	*fp;	/* Framework private */
	void		*cp;	/* Caller private */
	void		*ss;	/* struct specific */
} __stmf_t;

static struct {
	int shared;
	int fw_private;
} stmf_sizes[] = { { 0, 0 },
	{ GET_STRUCT_SIZE(stmf_lu_provider_t),
		GET_STRUCT_SIZE(stmf_i_lu_provider_t) },
	{ GET_STRUCT_SIZE(stmf_port_provider_t),
		GET_STRUCT_SIZE(stmf_i_port_provider_t) },
	{ GET_STRUCT_SIZE(stmf_local_port_t),
		GET_STRUCT_SIZE(stmf_i_local_port_t) },
	{ GET_STRUCT_SIZE(stmf_lu_t),
		GET_STRUCT_SIZE(stmf_i_lu_t) },
	{ GET_STRUCT_SIZE(stmf_scsi_session_t),
		GET_STRUCT_SIZE(stmf_i_scsi_session_t) },
	{ GET_STRUCT_SIZE(scsi_task_t),
		GET_STRUCT_SIZE(stmf_i_scsi_task_t) },
	{ GET_STRUCT_SIZE(stmf_data_buf_t),
		GET_STRUCT_SIZE(__istmf_t) },
	{ GET_STRUCT_SIZE(stmf_dbuf_store_t),
		GET_STRUCT_SIZE(__istmf_t) }

};

void *
stmf_alloc(stmf_struct_id_t struct_id, int additional_size, int flags)
{
	int stmf_size;
	int kmem_flag;
	__stmf_t *sh;

	if ((struct_id == 0) || (struct_id >= STMF_MAX_STRUCT_IDS))
		return (NULL);

	if ((curthread->t_flag & T_INTR_THREAD) || (flags & AF_FORCE_NOSLEEP)) {
		kmem_flag = KM_NOSLEEP;
	} else {
		kmem_flag = KM_SLEEP;
	}

	additional_size = (additional_size + 7) & (~7);
	stmf_size = stmf_sizes[struct_id].shared +
	    stmf_sizes[struct_id].fw_private + additional_size;

	if (flags & AF_DONTZERO)
		sh = (__stmf_t *)kmem_alloc(stmf_size, kmem_flag);
	else
		sh = (__stmf_t *)kmem_zalloc(stmf_size, kmem_flag);

	if (sh == NULL)
		return (NULL);

	/*
	 * In principle, the implementation inside stmf_alloc should not
	 * be changed anyway. But the original order of framework private
	 * data and caller private data does not support sglist in the caller
	 * private data.
	 * To work around this, the memory segments of framework private
	 * data and caller private data are re-ordered here.
	 * A better solution is to provide a specific interface to allocate
	 * the sglist, then we will not need this workaround any more.
	 * But before the new interface is available, the memory segment
	 * ordering should be kept as is.
	 */
	sh->cp = GET_BYTE_OFFSET(sh, stmf_sizes[struct_id].shared);
	sh->fp = (__istmf_t *)GET_BYTE_OFFSET(sh,
	    stmf_sizes[struct_id].shared + additional_size);

	sh->fp->bp = sh;
	/* Just store the total size instead of storing additional size */
	sh->fp->alloc_size = stmf_size;

	return (sh);
}

void
stmf_free(void *ptr)
{
	__stmf_t *sh = (__stmf_t *)ptr;

	/*
	 * So far we dont need any struct specific processing. If such
	 * a need ever arises, then store the struct id in the framework
	 * private section and get it here as sh->fp->struct_id.
	 */
	kmem_free(ptr, sh->fp->alloc_size);
}

/*
 * Given a pointer to stmf_lu_t, verifies if this lu is registered with the
 * framework and returns a pointer to framework private data for the lu.
 * Returns NULL if the lu was not found.
 */
stmf_i_lu_t *
stmf_lookup_lu(stmf_lu_t *lu)
{
	stmf_i_lu_t *ilu;
	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	for (ilu = stmf_state.stmf_ilulist; ilu != NULL; ilu = ilu->ilu_next) {
		if (ilu->ilu_lu == lu)
			return (ilu);
	}
	return (NULL);
}

/*
 * Given a pointer to stmf_local_port_t, verifies if this lport is registered
 * with the framework and returns a pointer to framework private data for
 * the lport.
 * Returns NULL if the lport was not found.
 */
stmf_i_local_port_t *
stmf_lookup_lport(stmf_local_port_t *lport)
{
	stmf_i_local_port_t *ilport;
	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	for (ilport = stmf_state.stmf_ilportlist; ilport != NULL;
	    ilport = ilport->ilport_next) {
		if (ilport->ilport_lport == lport)
			return (ilport);
	}
	return (NULL);
}

stmf_status_t
stmf_register_lu_provider(stmf_lu_provider_t *lp)
{
	stmf_i_lu_provider_t *ilp = (stmf_i_lu_provider_t *)lp->lp_stmf_private;
	stmf_pp_data_t *ppd;
	uint32_t cb_flags;

	if (lp->lp_lpif_rev != LPIF_REV_1 && lp->lp_lpif_rev != LPIF_REV_2)
		return (STMF_FAILURE);

	mutex_enter(&stmf_state.stmf_lock);
	ilp->ilp_next = stmf_state.stmf_ilplist;
	stmf_state.stmf_ilplist = ilp;
	stmf_state.stmf_nlps++;

	/* See if we need to do a callback */
	for (ppd = stmf_state.stmf_ppdlist; ppd != NULL; ppd = ppd->ppd_next) {
		if (strcmp(ppd->ppd_name, lp->lp_name) == 0) {
			break;
		}
	}
	if ((ppd == NULL) || (ppd->ppd_nv == NULL)) {
		goto rlp_bail_out;
	}
	ilp->ilp_ppd = ppd;
	ppd->ppd_provider = ilp;
	if (lp->lp_cb == NULL)
		goto rlp_bail_out;
	ilp->ilp_cb_in_progress = 1;
	cb_flags = STMF_PCB_PREG_COMPLETE;
	if (stmf_state.stmf_config_state == STMF_CONFIG_INIT)
		cb_flags |= STMF_PCB_STMF_ONLINING;
	mutex_exit(&stmf_state.stmf_lock);
	lp->lp_cb(lp, STMF_PROVIDER_DATA_UPDATED, ppd->ppd_nv, cb_flags);
	mutex_enter(&stmf_state.stmf_lock);
	ilp->ilp_cb_in_progress = 0;

rlp_bail_out:
	mutex_exit(&stmf_state.stmf_lock);

	return (STMF_SUCCESS);
}

stmf_status_t
stmf_deregister_lu_provider(stmf_lu_provider_t *lp)
{
	stmf_i_lu_provider_t	**ppilp;
	stmf_i_lu_provider_t *ilp = (stmf_i_lu_provider_t *)lp->lp_stmf_private;

	mutex_enter(&stmf_state.stmf_lock);
	if (ilp->ilp_nlus || ilp->ilp_cb_in_progress) {
		mutex_exit(&stmf_state.stmf_lock);
		return (STMF_BUSY);
	}
	for (ppilp = &stmf_state.stmf_ilplist; *ppilp != NULL;
	    ppilp = &((*ppilp)->ilp_next)) {
		if (*ppilp == ilp) {
			*ppilp = ilp->ilp_next;
			stmf_state.stmf_nlps--;
			if (ilp->ilp_ppd) {
				ilp->ilp_ppd->ppd_provider = NULL;
				ilp->ilp_ppd = NULL;
			}
			mutex_exit(&stmf_state.stmf_lock);
			return (STMF_SUCCESS);
		}
	}
	mutex_exit(&stmf_state.stmf_lock);
	return (STMF_NOT_FOUND);
}

stmf_status_t
stmf_register_port_provider(stmf_port_provider_t *pp)
{
	stmf_i_port_provider_t *ipp =
	    (stmf_i_port_provider_t *)pp->pp_stmf_private;
	stmf_pp_data_t *ppd;
	uint32_t cb_flags;

	if (pp->pp_portif_rev != PORTIF_REV_1)
		return (STMF_FAILURE);

	mutex_enter(&stmf_state.stmf_lock);
	ipp->ipp_next = stmf_state.stmf_ipplist;
	stmf_state.stmf_ipplist = ipp;
	stmf_state.stmf_npps++;
	/* See if we need to do a callback */
	for (ppd = stmf_state.stmf_ppdlist; ppd != NULL; ppd = ppd->ppd_next) {
		if (strcmp(ppd->ppd_name, pp->pp_name) == 0) {
			break;
		}
	}
	if ((ppd == NULL) || (ppd->ppd_nv == NULL)) {
		goto rpp_bail_out;
	}
	ipp->ipp_ppd = ppd;
	ppd->ppd_provider = ipp;
	if (pp->pp_cb == NULL)
		goto rpp_bail_out;
	ipp->ipp_cb_in_progress = 1;
	cb_flags = STMF_PCB_PREG_COMPLETE;
	if (stmf_state.stmf_config_state == STMF_CONFIG_INIT)
		cb_flags |= STMF_PCB_STMF_ONLINING;
	mutex_exit(&stmf_state.stmf_lock);
	pp->pp_cb(pp, STMF_PROVIDER_DATA_UPDATED, ppd->ppd_nv, cb_flags);
	mutex_enter(&stmf_state.stmf_lock);
	ipp->ipp_cb_in_progress = 0;

rpp_bail_out:
	mutex_exit(&stmf_state.stmf_lock);

	return (STMF_SUCCESS);
}

stmf_status_t
stmf_deregister_port_provider(stmf_port_provider_t *pp)
{
	stmf_i_port_provider_t *ipp =
	    (stmf_i_port_provider_t *)pp->pp_stmf_private;
	stmf_i_port_provider_t **ppipp;

	mutex_enter(&stmf_state.stmf_lock);
	if (ipp->ipp_npps || ipp->ipp_cb_in_progress) {
		mutex_exit(&stmf_state.stmf_lock);
		return (STMF_BUSY);
	}
	for (ppipp = &stmf_state.stmf_ipplist; *ppipp != NULL;
	    ppipp = &((*ppipp)->ipp_next)) {
		if (*ppipp == ipp) {
			*ppipp = ipp->ipp_next;
			stmf_state.stmf_npps--;
			if (ipp->ipp_ppd) {
				ipp->ipp_ppd->ppd_provider = NULL;
				ipp->ipp_ppd = NULL;
			}
			mutex_exit(&stmf_state.stmf_lock);
			return (STMF_SUCCESS);
		}
	}
	mutex_exit(&stmf_state.stmf_lock);
	return (STMF_NOT_FOUND);
}

int
stmf_load_ppd_ioctl(stmf_ppioctl_data_t *ppi, uint64_t *ppi_token,
    uint32_t *err_ret)
{
	stmf_i_port_provider_t		*ipp;
	stmf_i_lu_provider_t		*ilp;
	stmf_pp_data_t			*ppd;
	nvlist_t			*nv;
	int				s;
	int				ret;

	*err_ret = 0;

	if ((ppi->ppi_lu_provider + ppi->ppi_port_provider) != 1) {
		return (EINVAL);
	}

	mutex_enter(&stmf_state.stmf_lock);
	for (ppd = stmf_state.stmf_ppdlist; ppd != NULL; ppd = ppd->ppd_next) {
		if (ppi->ppi_lu_provider) {
			if (!ppd->ppd_lu_provider)
				continue;
		} else if (ppi->ppi_port_provider) {
			if (!ppd->ppd_port_provider)
				continue;
		}
		if (strncmp(ppi->ppi_name, ppd->ppd_name, 254) == 0)
			break;
	}

	if (ppd == NULL) {
		/* New provider */
		s = strlen(ppi->ppi_name);
		if (s > 254) {
			mutex_exit(&stmf_state.stmf_lock);
			return (EINVAL);
		}
		s += sizeof (stmf_pp_data_t) - 7;

		ppd = kmem_zalloc(s, KM_NOSLEEP);
		if (ppd == NULL) {
			mutex_exit(&stmf_state.stmf_lock);
			return (ENOMEM);
		}
		ppd->ppd_alloc_size = s;
		(void) strcpy(ppd->ppd_name, ppi->ppi_name);

		/* See if this provider already exists */
		if (ppi->ppi_lu_provider) {
			ppd->ppd_lu_provider = 1;
			for (ilp = stmf_state.stmf_ilplist; ilp != NULL;
			    ilp = ilp->ilp_next) {
				if (strcmp(ppi->ppi_name,
				    ilp->ilp_lp->lp_name) == 0) {
					ppd->ppd_provider = ilp;
					ilp->ilp_ppd = ppd;
					break;
				}
			}
		} else {
			ppd->ppd_port_provider = 1;
			for (ipp = stmf_state.stmf_ipplist; ipp != NULL;
			    ipp = ipp->ipp_next) {
				if (strcmp(ppi->ppi_name,
				    ipp->ipp_pp->pp_name) == 0) {
					ppd->ppd_provider = ipp;
					ipp->ipp_ppd = ppd;
					break;
				}
			}
		}

		/* Link this ppd in */
		ppd->ppd_next = stmf_state.stmf_ppdlist;
		stmf_state.stmf_ppdlist = ppd;
	}

	/*
	 * User is requesting that the token be checked.
	 * If there was another set after the user's get
	 * it's an error
	 */
	if (ppi->ppi_token_valid) {
		if (ppi->ppi_token != ppd->ppd_token) {
			*err_ret = STMF_IOCERR_PPD_UPDATED;
			mutex_exit(&stmf_state.stmf_lock);
			return (EINVAL);
		}
	}

	if ((ret = nvlist_unpack((char *)ppi->ppi_data,
	    (size_t)ppi->ppi_data_size, &nv, KM_NOSLEEP)) != 0) {
		mutex_exit(&stmf_state.stmf_lock);
		return (ret);
	}

	/* Free any existing lists and add this one to the ppd */
	if (ppd->ppd_nv)
		nvlist_free(ppd->ppd_nv);
	ppd->ppd_nv = nv;

	/* set the token for writes */
	ppd->ppd_token++;
	/* return token to caller */
	if (ppi_token) {
		*ppi_token = ppd->ppd_token;
	}

	/* If there is a provider registered, do the notifications */
	if (ppd->ppd_provider) {
		uint32_t cb_flags = 0;

		if (stmf_state.stmf_config_state == STMF_CONFIG_INIT)
			cb_flags |= STMF_PCB_STMF_ONLINING;
		if (ppi->ppi_lu_provider) {
			ilp = (stmf_i_lu_provider_t *)ppd->ppd_provider;
			if (ilp->ilp_lp->lp_cb == NULL)
				goto bail_out;
			ilp->ilp_cb_in_progress = 1;
			mutex_exit(&stmf_state.stmf_lock);
			ilp->ilp_lp->lp_cb(ilp->ilp_lp,
			    STMF_PROVIDER_DATA_UPDATED, ppd->ppd_nv, cb_flags);
			mutex_enter(&stmf_state.stmf_lock);
			ilp->ilp_cb_in_progress = 0;
		} else {
			ipp = (stmf_i_port_provider_t *)ppd->ppd_provider;
			if (ipp->ipp_pp->pp_cb == NULL)
				goto bail_out;
			ipp->ipp_cb_in_progress = 1;
			mutex_exit(&stmf_state.stmf_lock);
			ipp->ipp_pp->pp_cb(ipp->ipp_pp,
			    STMF_PROVIDER_DATA_UPDATED, ppd->ppd_nv, cb_flags);
			mutex_enter(&stmf_state.stmf_lock);
			ipp->ipp_cb_in_progress = 0;
		}
	}

bail_out:
	mutex_exit(&stmf_state.stmf_lock);

	return (0);
}

void
stmf_delete_ppd(stmf_pp_data_t *ppd)
{
	stmf_pp_data_t **pppd;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));
	if (ppd->ppd_provider) {
		if (ppd->ppd_lu_provider) {
			((stmf_i_lu_provider_t *)
			    ppd->ppd_provider)->ilp_ppd = NULL;
		} else {
			((stmf_i_port_provider_t *)
			    ppd->ppd_provider)->ipp_ppd = NULL;
		}
		ppd->ppd_provider = NULL;
	}

	for (pppd = &stmf_state.stmf_ppdlist; *pppd != NULL;
	    pppd = &((*pppd)->ppd_next)) {
		if (*pppd == ppd)
			break;
	}

	if (*pppd == NULL)
		return;

	*pppd = ppd->ppd_next;
	if (ppd->ppd_nv)
		nvlist_free(ppd->ppd_nv);

	kmem_free(ppd, ppd->ppd_alloc_size);
}

int
stmf_delete_ppd_ioctl(stmf_ppioctl_data_t *ppi)
{
	stmf_pp_data_t *ppd;
	int ret = ENOENT;

	if ((ppi->ppi_lu_provider + ppi->ppi_port_provider) != 1) {
		return (EINVAL);
	}

	mutex_enter(&stmf_state.stmf_lock);

	for (ppd = stmf_state.stmf_ppdlist; ppd != NULL; ppd = ppd->ppd_next) {
		if (ppi->ppi_lu_provider) {
			if (!ppd->ppd_lu_provider)
				continue;
		} else if (ppi->ppi_port_provider) {
			if (!ppd->ppd_port_provider)
				continue;
		}
		if (strncmp(ppi->ppi_name, ppd->ppd_name, 254) == 0)
			break;
	}

	if (ppd) {
		ret = 0;
		stmf_delete_ppd(ppd);
	}
	mutex_exit(&stmf_state.stmf_lock);

	return (ret);
}

int
stmf_get_ppd_ioctl(stmf_ppioctl_data_t *ppi, stmf_ppioctl_data_t *ppi_out,
    uint32_t *err_ret)
{
	stmf_pp_data_t *ppd;
	size_t req_size;
	int ret = ENOENT;
	char *bufp = (char *)ppi_out->ppi_data;

	if ((ppi->ppi_lu_provider + ppi->ppi_port_provider) != 1) {
		return (EINVAL);
	}

	mutex_enter(&stmf_state.stmf_lock);

	for (ppd = stmf_state.stmf_ppdlist; ppd != NULL; ppd = ppd->ppd_next) {
		if (ppi->ppi_lu_provider) {
			if (!ppd->ppd_lu_provider)
				continue;
		} else if (ppi->ppi_port_provider) {
			if (!ppd->ppd_port_provider)
				continue;
		}
		if (strncmp(ppi->ppi_name, ppd->ppd_name, 254) == 0)
			break;
	}

	if (ppd && ppd->ppd_nv) {
		ppi_out->ppi_token = ppd->ppd_token;
		if ((ret = nvlist_size(ppd->ppd_nv, &req_size,
		    NV_ENCODE_XDR)) != 0) {
			goto done;
		}
		ppi_out->ppi_data_size = req_size;
		if (req_size > ppi->ppi_data_size) {
			*err_ret = STMF_IOCERR_INSUFFICIENT_BUF;
			ret = EINVAL;
			goto done;
		}

		if ((ret = nvlist_pack(ppd->ppd_nv, &bufp, &req_size,
		    NV_ENCODE_XDR, 0)) != 0) {
			goto done;
		}
		ret = 0;
	}

done:
	mutex_exit(&stmf_state.stmf_lock);

	return (ret);
}

void
stmf_delete_all_ppds()
{
	stmf_pp_data_t *ppd, *nppd;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));
	for (ppd = stmf_state.stmf_ppdlist; ppd != NULL; ppd = nppd) {
		nppd = ppd->ppd_next;
		stmf_delete_ppd(ppd);
	}
}

/*
 * 16 is the max string length of a protocol_ident, increase
 * the size if needed.
 */
#define	STMF_KSTAT_LU_SZ	(STMF_GUID_INPUT + 1 + 256)
#define	STMF_KSTAT_TGT_SZ	(256 * 2 + 16)

/*
 * This array matches the Protocol Identifier in stmf_ioctl.h
 */
#define	MAX_PROTO_STR_LEN	32

char *protocol_ident[PROTOCOL_ANY] = {
	"Fibre Channel",
	"Parallel SCSI",
	"SSA",
	"IEEE_1394",
	"SRP",
	"iSCSI",
	"SAS",
	"ADT",
	"ATAPI",
	"UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN"
};

/*
 * Update the lun wait/run queue count
 */
static void
stmf_update_kstat_lu_q(scsi_task_t *task, void func())
{
	stmf_i_lu_t		*ilu;
	kstat_io_t		*kip;

	if (task->task_lu == dlun0)
		return;
	ilu = (stmf_i_lu_t *)task->task_lu->lu_stmf_private;
	if (ilu != NULL && ilu->ilu_kstat_io != NULL) {
		kip = KSTAT_IO_PTR(ilu->ilu_kstat_io);
		if (kip != NULL) {
			func(kip);
		}
	}
}

/*
 * Update the target(lport) wait/run queue count
 */
static void
stmf_update_kstat_lport_q(scsi_task_t *task, void func())
{
	stmf_i_local_port_t	*ilp;
	kstat_io_t		*kip;

	ilp = (stmf_i_local_port_t *)task->task_lport->lport_stmf_private;
	if (ilp != NULL && ilp->ilport_kstat_io != NULL) {
		kip = KSTAT_IO_PTR(ilp->ilport_kstat_io);
		if (kip != NULL) {
			mutex_enter(ilp->ilport_kstat_io->ks_lock);
			func(kip);
			mutex_exit(ilp->ilport_kstat_io->ks_lock);
		}
	}
}

static void
stmf_update_kstat_lport_io(scsi_task_t *task, stmf_data_buf_t *dbuf)
{
	stmf_i_local_port_t	*ilp;
	kstat_io_t		*kip;

	ilp = (stmf_i_local_port_t *)task->task_lport->lport_stmf_private;
	if (ilp != NULL && ilp->ilport_kstat_io != NULL) {
		kip = KSTAT_IO_PTR(ilp->ilport_kstat_io);
		if (kip != NULL) {
			mutex_enter(ilp->ilport_kstat_io->ks_lock);
			STMF_UPDATE_KSTAT_IO(kip, dbuf);
			mutex_exit(ilp->ilport_kstat_io->ks_lock);
		}
	}
}

static void
stmf_update_kstat_lu_io(scsi_task_t *task, stmf_data_buf_t *dbuf)
{
	stmf_i_lu_t		*ilu;
	kstat_io_t		*kip;

	ilu = (stmf_i_lu_t *)task->task_lu->lu_stmf_private;
	if (ilu != NULL && ilu->ilu_kstat_io != NULL) {
		kip = KSTAT_IO_PTR(ilu->ilu_kstat_io);
		if (kip != NULL) {
			mutex_enter(ilu->ilu_kstat_io->ks_lock);
			STMF_UPDATE_KSTAT_IO(kip, dbuf);
			mutex_exit(ilu->ilu_kstat_io->ks_lock);
		}
	}
}

static void
stmf_create_kstat_lu(stmf_i_lu_t *ilu)
{
	char				ks_nm[KSTAT_STRLEN];
	stmf_kstat_lu_info_t		*ks_lu;

	/* create kstat lun info */
	ks_lu = (stmf_kstat_lu_info_t *)kmem_zalloc(STMF_KSTAT_LU_SZ,
	    KM_NOSLEEP);
	if (ks_lu == NULL) {
		cmn_err(CE_WARN, "STMF: kmem_zalloc failed");
		return;
	}

	bzero(ks_nm, sizeof (ks_nm));
	(void) sprintf(ks_nm, "stmf_lu_%"PRIxPTR"", (uintptr_t)ilu);
	if ((ilu->ilu_kstat_info = kstat_create(STMF_MODULE_NAME, 0,
	    ks_nm, "misc", KSTAT_TYPE_NAMED,
	    sizeof (stmf_kstat_lu_info_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL)) == NULL) {
		kmem_free(ks_lu, STMF_KSTAT_LU_SZ);
		cmn_err(CE_WARN, "STMF: kstat_create lu failed");
		return;
	}

	ilu->ilu_kstat_info->ks_data_size = STMF_KSTAT_LU_SZ;
	ilu->ilu_kstat_info->ks_data = ks_lu;

	kstat_named_init(&ks_lu->i_lun_guid, "lun-guid",
	    KSTAT_DATA_STRING);
	kstat_named_init(&ks_lu->i_lun_alias, "lun-alias",
	    KSTAT_DATA_STRING);

	/* convert guid to hex string */
	int		i;
	uint8_t		*p = ilu->ilu_lu->lu_id->ident;
	bzero(ilu->ilu_ascii_hex_guid, sizeof (ilu->ilu_ascii_hex_guid));
	for (i = 0; i < STMF_GUID_INPUT / 2; i++) {
		(void) sprintf(&ilu->ilu_ascii_hex_guid[i * 2], "%02x", p[i]);
	}
	kstat_named_setstr(&ks_lu->i_lun_guid,
	    (const char *)ilu->ilu_ascii_hex_guid);
	kstat_named_setstr(&ks_lu->i_lun_alias,
	    (const char *)ilu->ilu_lu->lu_alias);
	kstat_install(ilu->ilu_kstat_info);

	/* create kstat lun io */
	bzero(ks_nm, sizeof (ks_nm));
	(void) sprintf(ks_nm, "stmf_lu_io_%"PRIxPTR"", (uintptr_t)ilu);
	if ((ilu->ilu_kstat_io = kstat_create(STMF_MODULE_NAME, 0,
	    ks_nm, "io", KSTAT_TYPE_IO, 1, 0)) == NULL) {
		cmn_err(CE_WARN, "STMF: kstat_create lu_io failed");
		return;
	}
	mutex_init(&ilu->ilu_kstat_lock, NULL, MUTEX_DRIVER, 0);
	ilu->ilu_kstat_io->ks_lock = &ilu->ilu_kstat_lock;
	kstat_install(ilu->ilu_kstat_io);
}

static void
stmf_create_kstat_lport(stmf_i_local_port_t *ilport)
{
	char				ks_nm[KSTAT_STRLEN];
	stmf_kstat_tgt_info_t		*ks_tgt;
	int				id, len;

	/* create kstat lport info */
	ks_tgt = (stmf_kstat_tgt_info_t *)kmem_zalloc(STMF_KSTAT_TGT_SZ,
	    KM_NOSLEEP);
	if (ks_tgt == NULL) {
		cmn_err(CE_WARN, "STMF: kmem_zalloc failed");
		return;
	}

	bzero(ks_nm, sizeof (ks_nm));
	(void) sprintf(ks_nm, "stmf_tgt_%"PRIxPTR"", (uintptr_t)ilport);
	if ((ilport->ilport_kstat_info = kstat_create(STMF_MODULE_NAME,
	    0, ks_nm, "misc", KSTAT_TYPE_NAMED,
	    sizeof (stmf_kstat_tgt_info_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL)) == NULL) {
		kmem_free(ks_tgt, STMF_KSTAT_TGT_SZ);
		cmn_err(CE_WARN, "STMF: kstat_create target failed");
		return;
	}

	ilport->ilport_kstat_info->ks_data_size = STMF_KSTAT_TGT_SZ;
	ilport->ilport_kstat_info->ks_data = ks_tgt;

	kstat_named_init(&ks_tgt->i_tgt_name, "target-name",
	    KSTAT_DATA_STRING);
	kstat_named_init(&ks_tgt->i_tgt_alias, "target-alias",
	    KSTAT_DATA_STRING);
	kstat_named_init(&ks_tgt->i_protocol, "protocol",
	    KSTAT_DATA_STRING);

	/* ident might not be null terminated */
	len = ilport->ilport_lport->lport_id->ident_length;
	bcopy(ilport->ilport_lport->lport_id->ident,
	    ilport->ilport_kstat_tgt_name, len);
	ilport->ilport_kstat_tgt_name[len + 1] = NULL;
	kstat_named_setstr(&ks_tgt->i_tgt_name,
	    (const char *)ilport->ilport_kstat_tgt_name);
	kstat_named_setstr(&ks_tgt->i_tgt_alias,
	    (const char *)ilport->ilport_lport->lport_alias);
	/* protocol */
	if ((id = ilport->ilport_lport->lport_id->protocol_id) > PROTOCOL_ANY) {
		cmn_err(CE_WARN, "STMF: protocol_id out of bound");
		id = PROTOCOL_ANY;
	}
	kstat_named_setstr(&ks_tgt->i_protocol, protocol_ident[id]);
	kstat_install(ilport->ilport_kstat_info);

	/* create kstat lport io */
	bzero(ks_nm, sizeof (ks_nm));
	(void) sprintf(ks_nm, "stmf_tgt_io_%"PRIxPTR"", (uintptr_t)ilport);
	if ((ilport->ilport_kstat_io = kstat_create(STMF_MODULE_NAME, 0,
	    ks_nm, "io", KSTAT_TYPE_IO, 1, 0)) == NULL) {
		cmn_err(CE_WARN, "STMF: kstat_create target_io failed");
		return;
	}
	mutex_init(&ilport->ilport_kstat_lock, NULL, MUTEX_DRIVER, 0);
	ilport->ilport_kstat_io->ks_lock = &ilport->ilport_kstat_lock;
	kstat_install(ilport->ilport_kstat_io);
}

/*
 * set the asymmetric access state for a logical unit
 * caller is responsible for establishing SCSI unit attention on
 * state change
 */
stmf_status_t
stmf_set_lu_access(stmf_lu_t *lu, uint8_t access_state)
{
	stmf_i_lu_t *ilu;
	uint8_t *p1, *p2;

	if ((access_state != STMF_LU_STANDBY) &&
	    (access_state != STMF_LU_ACTIVE)) {
		return (STMF_INVALID_ARG);
	}

	p1 = &lu->lu_id->ident[0];
	mutex_enter(&stmf_state.stmf_lock);
	if (stmf_state.stmf_inventory_locked) {
		mutex_exit(&stmf_state.stmf_lock);
		return (STMF_BUSY);
	}

	for (ilu = stmf_state.stmf_ilulist; ilu != NULL; ilu = ilu->ilu_next) {
		p2 = &ilu->ilu_lu->lu_id->ident[0];
		if (bcmp(p1, p2, 16) == 0) {
			break;
		}
	}

	if (!ilu) {
		ilu = (stmf_i_lu_t *)lu->lu_stmf_private;
	} else {
		/*
		 * We're changing access state on an existing logical unit
		 * Send the proxy registration message for this logical unit
		 * if we're in alua mode.
		 * If the requested state is STMF_LU_ACTIVE, we want to register
		 * this logical unit.
		 * If the requested state is STMF_LU_STANDBY, we're going to
		 * abort all tasks for this logical unit.
		 */
		if (stmf_state.stmf_alua_state == 1 &&
		    access_state == STMF_LU_ACTIVE) {
			stmf_ic_msg_status_t ic_ret = STMF_IC_MSG_SUCCESS;
			stmf_ic_msg_t *ic_reg_lun;
			if (lu->lu_lp && lu->lu_lp->lp_lpif_rev == LPIF_REV_2 &&
			    lu->lu_lp->lp_alua_support) {
				ilu->ilu_alua = 1;
				/* allocate the register message */
				ic_reg_lun = ic_lun_active_msg_alloc(p1,
				    lu->lu_lp->lp_name,
				    lu->lu_proxy_reg_arg_len,
				    (uint8_t *)lu->lu_proxy_reg_arg,
				    stmf_proxy_msg_id);
				/* send the message */
				if (ic_reg_lun) {
					ic_ret = ic_tx_msg(ic_reg_lun);
					if (ic_ret == STMF_IC_MSG_SUCCESS) {
						stmf_proxy_msg_id++;
					}
				}
			}
		} else if (stmf_state.stmf_alua_state == 1 &&
		    access_state == STMF_LU_STANDBY) {
			/* abort all tasks for this lu */
			stmf_task_lu_killall(lu, NULL, STMF_ABORTED);
		}
	}

	ilu->ilu_access = access_state;

	mutex_exit(&stmf_state.stmf_lock);
	return (STMF_SUCCESS);
}


stmf_status_t
stmf_register_lu(stmf_lu_t *lu)
{
	stmf_i_lu_t *ilu;
	uint8_t *p1, *p2;
	stmf_state_change_info_t ssci;
	stmf_id_data_t *luid;

	if ((lu->lu_id->ident_type != ID_TYPE_NAA) ||
	    (lu->lu_id->ident_length != 16) ||
	    ((lu->lu_id->ident[0] & 0xf0) != 0x60)) {
		return (STMF_INVALID_ARG);
	}
	p1 = &lu->lu_id->ident[0];
	mutex_enter(&stmf_state.stmf_lock);
	if (stmf_state.stmf_inventory_locked) {
		mutex_exit(&stmf_state.stmf_lock);
		return (STMF_BUSY);
	}

	for (ilu = stmf_state.stmf_ilulist; ilu != NULL; ilu = ilu->ilu_next) {
		p2 = &ilu->ilu_lu->lu_id->ident[0];
		if (bcmp(p1, p2, 16) == 0) {
			mutex_exit(&stmf_state.stmf_lock);
			return (STMF_ALREADY);
		}
	}

	ilu = (stmf_i_lu_t *)lu->lu_stmf_private;
	luid = stmf_lookup_id(&stmf_state.stmf_luid_list,
	    lu->lu_id->ident_length, lu->lu_id->ident);
	if (luid) {
		luid->id_pt_to_object = (void *)ilu;
		ilu->ilu_luid = luid;
	}
	ilu->ilu_alias = NULL;

	ilu->ilu_next = stmf_state.stmf_ilulist;
	ilu->ilu_prev = NULL;
	if (ilu->ilu_next)
		ilu->ilu_next->ilu_prev = ilu;
	stmf_state.stmf_ilulist = ilu;
	stmf_state.stmf_nlus++;
	if (lu->lu_lp) {
		((stmf_i_lu_provider_t *)
		    (lu->lu_lp->lp_stmf_private))->ilp_nlus++;
	}
	ilu->ilu_cur_task_cntr = &ilu->ilu_task_cntr1;
	STMF_EVENT_ALLOC_HANDLE(ilu->ilu_event_hdl);
	cv_init(&ilu->ilu_offline_pending_cv, NULL, CV_DRIVER, NULL);
	stmf_create_kstat_lu(ilu);
	/*
	 * register with proxy module if available and logical unit
	 * is in active state
	 */
	if (stmf_state.stmf_alua_state == 1 &&
	    ilu->ilu_access == STMF_LU_ACTIVE) {
		stmf_ic_msg_status_t ic_ret = STMF_IC_MSG_SUCCESS;
		stmf_ic_msg_t *ic_reg_lun;
		if (lu->lu_lp && lu->lu_lp->lp_lpif_rev == LPIF_REV_2 &&
		    lu->lu_lp->lp_alua_support) {
			ilu->ilu_alua = 1;
			/* allocate the register message */
			ic_reg_lun = ic_reg_lun_msg_alloc(p1,
			    lu->lu_lp->lp_name, lu->lu_proxy_reg_arg_len,
			    (uint8_t *)lu->lu_proxy_reg_arg, stmf_proxy_msg_id);
			/* send the message */
			if (ic_reg_lun) {
				ic_ret = ic_tx_msg(ic_reg_lun);
				if (ic_ret == STMF_IC_MSG_SUCCESS) {
					stmf_proxy_msg_id++;
				}
			}
		}
	}
	mutex_exit(&stmf_state.stmf_lock);

	/*  check the default state for lu */
	if (stmf_state.stmf_default_lu_state == STMF_STATE_OFFLINE) {
		ilu->ilu_prev_state = STMF_STATE_OFFLINE;
	} else {
		ilu->ilu_prev_state = STMF_STATE_ONLINE;
		if (stmf_state.stmf_service_running) {
			ssci.st_rflags = 0;
			ssci.st_additional_info = NULL;
			(void) stmf_ctl(STMF_CMD_LU_ONLINE, lu, &ssci);
		}
	}

	/* XXX: Generate event */
	return (STMF_SUCCESS);
}

stmf_status_t
stmf_deregister_lu(stmf_lu_t *lu)
{
	stmf_i_lu_t *ilu;

	mutex_enter(&stmf_state.stmf_lock);
	if (stmf_state.stmf_inventory_locked) {
		mutex_exit(&stmf_state.stmf_lock);
		return (STMF_BUSY);
	}
	ilu = stmf_lookup_lu(lu);
	if (ilu == NULL) {
		mutex_exit(&stmf_state.stmf_lock);
		return (STMF_INVALID_ARG);
	}
	if (ilu->ilu_state == STMF_STATE_OFFLINE) {
		ASSERT(ilu->ilu_ntasks == ilu->ilu_ntasks_free);
		while (ilu->ilu_flags & ILU_STALL_DEREGISTER) {
			cv_wait(&stmf_state.stmf_cv, &stmf_state.stmf_lock);
		}
		if (ilu->ilu_ntasks) {
			stmf_i_scsi_task_t *itask, *nitask;

			nitask = ilu->ilu_tasks;
			do {
				itask = nitask;
				nitask = itask->itask_lu_next;
				lu->lu_task_free(itask->itask_task);
				stmf_free(itask->itask_task);
			} while (nitask != NULL);

			ilu->ilu_tasks = ilu->ilu_free_tasks = NULL;
			ilu->ilu_ntasks = ilu->ilu_ntasks_free = 0;
		}
		/* de-register with proxy if available */
		if (ilu->ilu_access == STMF_LU_ACTIVE &&
		    stmf_state.stmf_alua_state == 1) {
			/* de-register with proxy module */
			stmf_ic_msg_status_t ic_ret = STMF_IC_MSG_SUCCESS;
			stmf_ic_msg_t *ic_dereg_lun;
			if (lu->lu_lp && lu->lu_lp->lp_lpif_rev == LPIF_REV_2 &&
			    lu->lu_lp->lp_alua_support) {
				ilu->ilu_alua = 1;
				/* allocate the de-register message */
				ic_dereg_lun = ic_dereg_lun_msg_alloc(
				    lu->lu_id->ident, lu->lu_lp->lp_name, 0,
				    NULL, stmf_proxy_msg_id);
				/* send the message */
				if (ic_dereg_lun) {
					ic_ret = ic_tx_msg(ic_dereg_lun);
					if (ic_ret == STMF_IC_MSG_SUCCESS) {
						stmf_proxy_msg_id++;
					}
				}
			}
		}

		if (ilu->ilu_next)
			ilu->ilu_next->ilu_prev = ilu->ilu_prev;
		if (ilu->ilu_prev)
			ilu->ilu_prev->ilu_next = ilu->ilu_next;
		else
			stmf_state.stmf_ilulist = ilu->ilu_next;
		stmf_state.stmf_nlus--;

		if (ilu == stmf_state.stmf_svc_ilu_draining) {
			stmf_state.stmf_svc_ilu_draining = ilu->ilu_next;
		}
		if (ilu == stmf_state.stmf_svc_ilu_timing) {
			stmf_state.stmf_svc_ilu_timing = ilu->ilu_next;
		}
		if (lu->lu_lp) {
			((stmf_i_lu_provider_t *)
			    (lu->lu_lp->lp_stmf_private))->ilp_nlus--;
		}
		if (ilu->ilu_luid) {
			((stmf_id_data_t *)ilu->ilu_luid)->id_pt_to_object =
			    NULL;
			ilu->ilu_luid = NULL;
		}
		STMF_EVENT_FREE_HANDLE(ilu->ilu_event_hdl);
	} else {
		mutex_exit(&stmf_state.stmf_lock);
		return (STMF_BUSY);
	}
	if (ilu->ilu_kstat_info) {
		kmem_free(ilu->ilu_kstat_info->ks_data,
		    ilu->ilu_kstat_info->ks_data_size);
		kstat_delete(ilu->ilu_kstat_info);
	}
	if (ilu->ilu_kstat_io) {
		kstat_delete(ilu->ilu_kstat_io);
		mutex_destroy(&ilu->ilu_kstat_lock);
	}
	cv_destroy(&ilu->ilu_offline_pending_cv);
	mutex_exit(&stmf_state.stmf_lock);
	return (STMF_SUCCESS);
}

void
stmf_set_port_standby(stmf_local_port_t *lport, uint16_t rtpid)
{
	stmf_i_local_port_t *ilport =
	    (stmf_i_local_port_t *)lport->lport_stmf_private;
	ilport->ilport_rtpid = rtpid;
	ilport->ilport_standby = 1;
}

void
stmf_set_port_alua(stmf_local_port_t *lport)
{
	stmf_i_local_port_t *ilport =
	    (stmf_i_local_port_t *)lport->lport_stmf_private;
	ilport->ilport_alua = 1;
}

stmf_status_t
stmf_register_local_port(stmf_local_port_t *lport)
{
	stmf_i_local_port_t *ilport;
	stmf_state_change_info_t ssci;
	int start_workers = 0;

	mutex_enter(&stmf_state.stmf_lock);
	if (stmf_state.stmf_inventory_locked) {
		mutex_exit(&stmf_state.stmf_lock);
		return (STMF_BUSY);
	}
	ilport = (stmf_i_local_port_t *)lport->lport_stmf_private;
	rw_init(&ilport->ilport_lock, NULL, RW_DRIVER, NULL);

	ilport->ilport_instance =
	    id_alloc_nosleep(stmf_state.stmf_ilport_inst_space);
	if (ilport->ilport_instance == -1) {
		mutex_exit(&stmf_state.stmf_lock);
		return (STMF_FAILURE);
	}
	ilport->ilport_next = stmf_state.stmf_ilportlist;
	ilport->ilport_prev = NULL;
	if (ilport->ilport_next)
		ilport->ilport_next->ilport_prev = ilport;
	stmf_state.stmf_ilportlist = ilport;
	stmf_state.stmf_nlports++;
	if (lport->lport_pp) {
		((stmf_i_port_provider_t *)
		    (lport->lport_pp->pp_stmf_private))->ipp_npps++;
	}
	ilport->ilport_tg =
	    stmf_lookup_group_for_target(lport->lport_id->ident,
	    lport->lport_id->ident_length);

	/*
	 * rtpid will/must be set if this is a standby port
	 * only register ports that are not standby (proxy) ports
	 * and ports that are alua participants (ilport_alua == 1)
	 */
	if (ilport->ilport_standby == 0) {
		ilport->ilport_rtpid = atomic_inc_16_nv(&stmf_rtpid_counter);
	}

	if (stmf_state.stmf_alua_state == 1 &&
	    ilport->ilport_standby == 0 &&
	    ilport->ilport_alua == 1) {
		stmf_ic_msg_t *ic_reg_port;
		stmf_ic_msg_status_t ic_ret;
		stmf_local_port_t *lport;
		lport = ilport->ilport_lport;
		ic_reg_port = ic_reg_port_msg_alloc(
		    lport->lport_id, ilport->ilport_rtpid,
		    0, NULL, stmf_proxy_msg_id);
		if (ic_reg_port) {
			ic_ret = ic_tx_msg(ic_reg_port);
			if (ic_ret == STMF_IC_MSG_SUCCESS) {
				ilport->ilport_reg_msgid = stmf_proxy_msg_id++;
			} else {
				cmn_err(CE_WARN, "error on port registration "
				"port - %s", ilport->ilport_kstat_tgt_name);
			}
		}
	}
	STMF_EVENT_ALLOC_HANDLE(ilport->ilport_event_hdl);
	stmf_create_kstat_lport(ilport);
	if (stmf_workers_state == STMF_WORKERS_DISABLED) {
		stmf_workers_state = STMF_WORKERS_ENABLING;
		start_workers = 1;
	}
	mutex_exit(&stmf_state.stmf_lock);

	if (start_workers)
		stmf_worker_init();

	/*  the default state of LPORT */

	if (stmf_state.stmf_default_lport_state == STMF_STATE_OFFLINE) {
		ilport->ilport_prev_state = STMF_STATE_OFFLINE;
	} else {
		ilport->ilport_prev_state = STMF_STATE_ONLINE;
		if (stmf_state.stmf_service_running) {
			ssci.st_rflags = 0;
			ssci.st_additional_info = NULL;
			(void) stmf_ctl(STMF_CMD_LPORT_ONLINE, lport, &ssci);
		}
	}

	/* XXX: Generate event */
	return (STMF_SUCCESS);
}

stmf_status_t
stmf_deregister_local_port(stmf_local_port_t *lport)
{
	stmf_i_local_port_t *ilport;

	mutex_enter(&stmf_state.stmf_lock);
	if (stmf_state.stmf_inventory_locked) {
		mutex_exit(&stmf_state.stmf_lock);
		return (STMF_BUSY);
	}

	/* dequeue all object requests from active queue */
	stmf_svc_kill_obj_requests(lport);

	ilport = (stmf_i_local_port_t *)lport->lport_stmf_private;

	/*
	 * deregister ports that are not standby (proxy)
	 */
	if (stmf_state.stmf_alua_state == 1 &&
	    ilport->ilport_standby == 0 &&
	    ilport->ilport_alua == 1) {
		stmf_ic_msg_t *ic_dereg_port;
		stmf_ic_msg_status_t ic_ret;
		ic_dereg_port = ic_dereg_port_msg_alloc(
		    lport->lport_id, 0, NULL, stmf_proxy_msg_id);
		if (ic_dereg_port) {
			ic_ret = ic_tx_msg(ic_dereg_port);
			if (ic_ret == STMF_IC_MSG_SUCCESS) {
				stmf_proxy_msg_id++;
			}
		}
	}

	if (ilport->ilport_nsessions == 0) {
		if (ilport->ilport_next)
			ilport->ilport_next->ilport_prev = ilport->ilport_prev;
		if (ilport->ilport_prev)
			ilport->ilport_prev->ilport_next = ilport->ilport_next;
		else
			stmf_state.stmf_ilportlist = ilport->ilport_next;
		id_free(stmf_state.stmf_ilport_inst_space,
		    ilport->ilport_instance);
		rw_destroy(&ilport->ilport_lock);
		stmf_state.stmf_nlports--;
		if (lport->lport_pp) {
			((stmf_i_port_provider_t *)
			    (lport->lport_pp->pp_stmf_private))->ipp_npps--;
		}
		ilport->ilport_tg = NULL;
		STMF_EVENT_FREE_HANDLE(ilport->ilport_event_hdl);
	} else {
		mutex_exit(&stmf_state.stmf_lock);
		return (STMF_BUSY);
	}
	if (ilport->ilport_kstat_info) {
		kmem_free(ilport->ilport_kstat_info->ks_data,
		    ilport->ilport_kstat_info->ks_data_size);
		kstat_delete(ilport->ilport_kstat_info);
	}
	if (ilport->ilport_kstat_io) {
		kstat_delete(ilport->ilport_kstat_io);
		mutex_destroy(&ilport->ilport_kstat_lock);
	}
	mutex_exit(&stmf_state.stmf_lock);
	return (STMF_SUCCESS);
}

/*
 * Rport id/instance mappings remain valid until STMF is unloaded
 */
static int
stmf_irport_compare(const void *void_irport1, const void *void_irport2)
{
	const	stmf_i_remote_port_t	*irport1 = void_irport1;
	const	stmf_i_remote_port_t	*irport2 = void_irport2;
	int			result;

	/* Sort by code set then ident */
	if (irport1->irport_id->code_set <
	    irport2->irport_id->code_set) {
		return (-1);
	} else if (irport1->irport_id->code_set >
	    irport2->irport_id->code_set) {
		return (1);
	}

	/* Next by ident length */
	if (irport1->irport_id->ident_length <
	    irport2->irport_id->ident_length) {
		return (-1);
	} else if (irport1->irport_id->ident_length >
	    irport2->irport_id->ident_length) {
		return (1);
	}

	/* Code set and ident length both match, now compare idents */
	result = memcmp(irport1->irport_id->ident,
	    irport2->irport_id->ident,
	    irport1->irport_id->ident_length);

	if (result < 0) {
		return (-1);
	} else if (result > 0) {
		return (1);
	}

	return (0);
}

static stmf_i_remote_port_t *
stmf_irport_create(scsi_devid_desc_t *rport_devid)
{
	int			alloc_len;
	stmf_i_remote_port_t	*irport;

	/*
	 * Lookup will bump the refcnt if there's an existing rport
	 * context for this identifier.
	 */
	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	alloc_len = sizeof (*irport) + sizeof (scsi_devid_desc_t) +
	    rport_devid->ident_length - 1;
	irport = kmem_zalloc(alloc_len, KM_NOSLEEP);
	if (irport == NULL) {
		return (NULL);
	}

	irport->irport_instance =
	    id_alloc_nosleep(stmf_state.stmf_irport_inst_space);
	if (irport->irport_instance == -1) {
		kmem_free(irport, alloc_len);
		return (NULL);
	}

	irport->irport_id =
	    (struct scsi_devid_desc *)(irport + 1); /* Ptr. Arith. */
	bcopy(rport_devid, irport->irport_id,
	    sizeof (scsi_devid_desc_t) + rport_devid->ident_length - 1);
	irport->irport_refcnt = 1;
	mutex_init(&irport->irport_mutex, NULL, MUTEX_DEFAULT, NULL);

	return (irport);
}

static void
stmf_irport_destroy(stmf_i_remote_port_t *irport)
{
	id_free(stmf_state.stmf_irport_inst_space, irport->irport_instance);
	mutex_destroy(&irport->irport_mutex);
	kmem_free(irport, sizeof (*irport) + sizeof (scsi_devid_desc_t) +
	    irport->irport_id->ident_length - 1);
}

static stmf_i_remote_port_t *
stmf_irport_register(scsi_devid_desc_t *rport_devid)
{
	stmf_i_remote_port_t	*irport;

	mutex_enter(&stmf_state.stmf_lock);

	/*
	 * Lookup will bump the refcnt if there's an existing rport
	 * context for this identifier.
	 */
	if ((irport = stmf_irport_lookup_locked(rport_devid)) != NULL) {
		mutex_exit(&stmf_state.stmf_lock);
		return (irport);
	}

	irport = stmf_irport_create(rport_devid);
	if (irport == NULL) {
		mutex_exit(&stmf_state.stmf_lock);
		return (NULL);
	}

	avl_add(&stmf_state.stmf_irportlist, irport);
	mutex_exit(&stmf_state.stmf_lock);

	return (irport);
}

static stmf_i_remote_port_t *
stmf_irport_lookup_locked(scsi_devid_desc_t *rport_devid)
{
	stmf_i_remote_port_t	*irport;
	stmf_i_remote_port_t	tmp_irport;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));
	tmp_irport.irport_id = rport_devid;
	irport = avl_find(&stmf_state.stmf_irportlist, &tmp_irport, NULL);
	if (irport != NULL) {
		mutex_enter(&irport->irport_mutex);
		irport->irport_refcnt++;
		mutex_exit(&irport->irport_mutex);
	}

	return (irport);
}

static void
stmf_irport_deregister(stmf_i_remote_port_t *irport)
{
	/*
	 * If we were actually going to remove unreferenced remote ports
	 * we would want to acquire stmf_state.stmf_lock before getting
	 * the irport mutex.
	 *
	 * Instead we're just going to leave it there even if unreferenced.
	 */
	mutex_enter(&irport->irport_mutex);
	irport->irport_refcnt--;
	mutex_exit(&irport->irport_mutex);
}

/*
 * Port provider has to make sure that register/deregister session and
 * port are serialized calls.
 */
stmf_status_t
stmf_register_scsi_session(stmf_local_port_t *lport, stmf_scsi_session_t *ss)
{
	stmf_i_scsi_session_t *iss;
	stmf_i_local_port_t *ilport = (stmf_i_local_port_t *)
	    lport->lport_stmf_private;
	uint8_t		lun[8];

	/*
	 * Port state has to be online to register a scsi session. It is
	 * possible that we started an offline operation and a new SCSI
	 * session started at the same time (in that case also we are going
	 * to fail the registeration). But any other state is simply
	 * a bad port provider implementation.
	 */
	if (ilport->ilport_state != STMF_STATE_ONLINE) {
		if (ilport->ilport_state != STMF_STATE_OFFLINING) {
			stmf_trace(lport->lport_alias, "Port is trying to "
			    "register a session while the state is neither "
			    "online nor offlining");
		}
		return (STMF_FAILURE);
	}
	bzero(lun, 8);
	iss = (stmf_i_scsi_session_t *)ss->ss_stmf_private;
	if ((iss->iss_irport = stmf_irport_register(ss->ss_rport_id)) == NULL) {
		stmf_trace(lport->lport_alias, "Could not register "
		    "remote port during session registration");
		return (STMF_FAILURE);
	}

	iss->iss_flags |= ISS_BEING_CREATED;

	if (ss->ss_rport == NULL) {
		iss->iss_flags |= ISS_NULL_TPTID;
		ss->ss_rport = stmf_scsilib_devid_to_remote_port(
		    ss->ss_rport_id);
		if (ss->ss_rport == NULL) {
			iss->iss_flags &= ~(ISS_NULL_TPTID | ISS_BEING_CREATED);
			stmf_trace(lport->lport_alias, "Device id to "
			    "remote port conversion failed");
			return (STMF_FAILURE);
		}
	} else {
		if (!stmf_scsilib_tptid_validate(ss->ss_rport->rport_tptid,
		    ss->ss_rport->rport_tptid_sz, NULL)) {
			iss->iss_flags &= ~ISS_BEING_CREATED;
			stmf_trace(lport->lport_alias, "Remote port "
			    "transport id validation failed");
			return (STMF_FAILURE);
		}
	}

	/* sessions use the ilport_lock. No separate lock is required */
	iss->iss_lockp = &ilport->ilport_lock;

	if (iss->iss_sm != NULL)
		cmn_err(CE_PANIC, "create lun map called with non NULL map");
	iss->iss_sm = (stmf_lun_map_t *)kmem_zalloc(sizeof (stmf_lun_map_t),
	    KM_SLEEP);

	mutex_enter(&stmf_state.stmf_lock);
	rw_enter(&ilport->ilport_lock, RW_WRITER);
	(void) stmf_session_create_lun_map(ilport, iss);
	ilport->ilport_nsessions++;
	iss->iss_next = ilport->ilport_ss_list;
	ilport->ilport_ss_list = iss;
	rw_exit(&ilport->ilport_lock);
	mutex_exit(&stmf_state.stmf_lock);

	iss->iss_creation_time = ddi_get_time();
	ss->ss_session_id = atomic_inc_64_nv(&stmf_session_counter);
	iss->iss_flags &= ~ISS_BEING_CREATED;
	/* XXX should we remove ISS_LUN_INVENTORY_CHANGED on new session? */
	iss->iss_flags &= ~ISS_LUN_INVENTORY_CHANGED;
	DTRACE_PROBE2(session__online, stmf_local_port_t *, lport,
	    stmf_scsi_session_t *, ss);
	return (STMF_SUCCESS);
}

void
stmf_deregister_scsi_session(stmf_local_port_t *lport, stmf_scsi_session_t *ss)
{
	stmf_i_local_port_t *ilport = (stmf_i_local_port_t *)
	    lport->lport_stmf_private;
	stmf_i_scsi_session_t *iss, **ppss;
	int found = 0;
	stmf_ic_msg_t *ic_session_dereg;
	stmf_status_t ic_ret = STMF_FAILURE;

	DTRACE_PROBE2(session__offline, stmf_local_port_t *, lport,
	    stmf_scsi_session_t *, ss);

	iss = (stmf_i_scsi_session_t *)ss->ss_stmf_private;
	if (ss->ss_rport_alias) {
		ss->ss_rport_alias = NULL;
	}

try_dereg_ss_again:
	mutex_enter(&stmf_state.stmf_lock);
	atomic_and_32(&iss->iss_flags,
	    ~(ISS_LUN_INVENTORY_CHANGED | ISS_GOT_INITIAL_LUNS));
	if (iss->iss_flags & ISS_EVENT_ACTIVE) {
		mutex_exit(&stmf_state.stmf_lock);
		delay(1);
		goto try_dereg_ss_again;
	}

	/* dereg proxy session if not standby port */
	if (stmf_state.stmf_alua_state == 1 &&
	    ilport->ilport_standby == 0 &&
	    ilport->ilport_alua == 1) {
		ic_session_dereg = ic_session_dereg_msg_alloc(
		    ss, stmf_proxy_msg_id);
		if (ic_session_dereg) {
			ic_ret = ic_tx_msg(ic_session_dereg);
			if (ic_ret == STMF_IC_MSG_SUCCESS) {
				stmf_proxy_msg_id++;
			}
		}
	}

	rw_enter(&ilport->ilport_lock, RW_WRITER);
	for (ppss = &ilport->ilport_ss_list; *ppss != NULL;
	    ppss = &((*ppss)->iss_next)) {
		if (iss == (*ppss)) {
			*ppss = (*ppss)->iss_next;
			found = 1;
			break;
		}
	}
	if (!found) {
		cmn_err(CE_PANIC, "Deregister session called for non existent"
		    " session");
	}
	ilport->ilport_nsessions--;

	stmf_irport_deregister(iss->iss_irport);
	(void) stmf_session_destroy_lun_map(ilport, iss);
	rw_exit(&ilport->ilport_lock);
	mutex_exit(&stmf_state.stmf_lock);

	if (iss->iss_flags & ISS_NULL_TPTID) {
		stmf_remote_port_free(ss->ss_rport);
	}
}

stmf_i_scsi_session_t *
stmf_session_id_to_issptr(uint64_t session_id, int stay_locked)
{
	stmf_i_local_port_t *ilport;
	stmf_i_scsi_session_t *iss;

	mutex_enter(&stmf_state.stmf_lock);
	for (ilport = stmf_state.stmf_ilportlist; ilport != NULL;
	    ilport = ilport->ilport_next) {
		rw_enter(&ilport->ilport_lock, RW_WRITER);
		for (iss = ilport->ilport_ss_list; iss != NULL;
		    iss = iss->iss_next) {
			if (iss->iss_ss->ss_session_id == session_id) {
				if (!stay_locked)
					rw_exit(&ilport->ilport_lock);
				mutex_exit(&stmf_state.stmf_lock);
				return (iss);
			}
		}
		rw_exit(&ilport->ilport_lock);
	}
	mutex_exit(&stmf_state.stmf_lock);
	return (NULL);
}

void
stmf_release_itl_handle(stmf_lu_t *lu, stmf_itl_data_t *itl)
{
	stmf_itl_data_t **itlpp;
	stmf_i_lu_t *ilu;

	ASSERT(itl->itl_flags & STMF_ITL_BEING_TERMINATED);

	ilu = (stmf_i_lu_t *)lu->lu_stmf_private;
	mutex_enter(&ilu->ilu_task_lock);
	for (itlpp = &ilu->ilu_itl_list; (*itlpp) != NULL;
	    itlpp = &(*itlpp)->itl_next) {
		if ((*itlpp) == itl)
			break;
	}
	ASSERT((*itlpp) != NULL);
	*itlpp = itl->itl_next;
	mutex_exit(&ilu->ilu_task_lock);
	lu->lu_abort(lu, STMF_LU_ITL_HANDLE_REMOVED, itl->itl_handle,
	    (uint32_t)itl->itl_hdlrm_reason);

	kmem_free(itl, sizeof (*itl));
}

stmf_status_t
stmf_register_itl_handle(stmf_lu_t *lu, uint8_t *lun,
    stmf_scsi_session_t *ss, uint64_t session_id, void *itl_handle)
{
	stmf_itl_data_t *itl;
	stmf_i_scsi_session_t *iss;
	stmf_lun_map_ent_t *lun_map_ent;
	stmf_i_lu_t *ilu;
	uint16_t n;

	ilu = (stmf_i_lu_t *)lu->lu_stmf_private;
	if (ss == NULL) {
		iss = stmf_session_id_to_issptr(session_id, 1);
		if (iss == NULL)
			return (STMF_NOT_FOUND);
	} else {
		iss = (stmf_i_scsi_session_t *)ss->ss_stmf_private;
	}

	mutex_enter(&stmf_state.stmf_lock);
	rw_enter(iss->iss_lockp, RW_WRITER);
	n = ((uint16_t)lun[1] | (((uint16_t)(lun[0] & 0x3F)) << 8));
	lun_map_ent = (stmf_lun_map_ent_t *)
	    stmf_get_ent_from_map(iss->iss_sm, n);
	if ((lun_map_ent == NULL) || (lun_map_ent->ent_lu != lu)) {
		rw_exit(iss->iss_lockp);
		mutex_exit(&stmf_state.stmf_lock);
		return (STMF_NOT_FOUND);
	}
	if (lun_map_ent->ent_itl_datap != NULL) {
		rw_exit(iss->iss_lockp);
		mutex_exit(&stmf_state.stmf_lock);
		return (STMF_ALREADY);
	}

	itl = (stmf_itl_data_t *)kmem_zalloc(sizeof (*itl), KM_NOSLEEP);
	if (itl == NULL) {
		rw_exit(iss->iss_lockp);
		mutex_exit(&stmf_state.stmf_lock);
		return (STMF_ALLOC_FAILURE);
	}

	itl->itl_ilu = ilu;
	itl->itl_session = iss;
	itl->itl_counter = 1;
	itl->itl_lun = n;
	itl->itl_handle = itl_handle;

	mutex_enter(&ilu->ilu_task_lock);
	itl->itl_next = ilu->ilu_itl_list;
	ilu->ilu_itl_list = itl;
	mutex_exit(&ilu->ilu_task_lock);
	lun_map_ent->ent_itl_datap = itl;
	rw_exit(iss->iss_lockp);
	mutex_exit(&stmf_state.stmf_lock);

	return (STMF_SUCCESS);
}

void
stmf_do_itl_dereg(stmf_lu_t *lu, stmf_itl_data_t *itl, uint8_t hdlrm_reason)
{
	uint8_t old, new;

	do {
		old = new = itl->itl_flags;
		if (old & STMF_ITL_BEING_TERMINATED)
			return;
		new |= STMF_ITL_BEING_TERMINATED;
	} while (atomic_cas_8(&itl->itl_flags, old, new) != old);
	itl->itl_hdlrm_reason = hdlrm_reason;

	ASSERT(itl->itl_counter);

	if (atomic_dec_32_nv(&itl->itl_counter))
		return;

	stmf_release_itl_handle(lu, itl);
}

stmf_status_t
stmf_deregister_all_lu_itl_handles(stmf_lu_t *lu)
{
	stmf_i_lu_t *ilu;
	stmf_i_local_port_t *ilport;
	stmf_i_scsi_session_t *iss;
	stmf_lun_map_t *lm;
	stmf_lun_map_ent_t *ent;
	uint32_t nmaps, nu;
	stmf_itl_data_t **itl_list;
	int i;

	ilu = (stmf_i_lu_t *)lu->lu_stmf_private;

dereg_itl_start:;
	nmaps = ilu->ilu_ref_cnt;
	if (nmaps == 0)
		return (STMF_NOT_FOUND);
	itl_list = (stmf_itl_data_t **)kmem_zalloc(
	    nmaps * sizeof (stmf_itl_data_t *), KM_SLEEP);
	mutex_enter(&stmf_state.stmf_lock);
	if (nmaps != ilu->ilu_ref_cnt) {
		/* Something changed, start all over */
		mutex_exit(&stmf_state.stmf_lock);
		kmem_free(itl_list, nmaps * sizeof (stmf_itl_data_t *));
		goto dereg_itl_start;
	}
	nu = 0;
	for (ilport = stmf_state.stmf_ilportlist; ilport != NULL;
	    ilport = ilport->ilport_next) {
		rw_enter(&ilport->ilport_lock, RW_WRITER);
		for (iss = ilport->ilport_ss_list; iss != NULL;
		    iss = iss->iss_next) {
			lm = iss->iss_sm;
			if (!lm)
				continue;
			for (i = 0; i < lm->lm_nentries; i++) {
				if (lm->lm_plus[i] == NULL)
					continue;
				ent = (stmf_lun_map_ent_t *)lm->lm_plus[i];
				if ((ent->ent_lu == lu) &&
				    (ent->ent_itl_datap)) {
					itl_list[nu++] = ent->ent_itl_datap;
					ent->ent_itl_datap = NULL;
					if (nu == nmaps) {
						rw_exit(&ilport->ilport_lock);
						goto dai_scan_done;
					}
				}
			} /* lun table for a session */
		} /* sessions */
		rw_exit(&ilport->ilport_lock);
	} /* ports */

dai_scan_done:
	mutex_exit(&stmf_state.stmf_lock);

	for (i = 0; i < nu; i++) {
		stmf_do_itl_dereg(lu, itl_list[i],
		    STMF_ITL_REASON_DEREG_REQUEST);
	}
	kmem_free(itl_list, nmaps * sizeof (stmf_itl_data_t *));

	return (STMF_SUCCESS);
}

stmf_status_t
stmf_get_itl_handle(stmf_lu_t *lu, uint8_t *lun, stmf_scsi_session_t *ss,
    uint64_t session_id, void **itl_handle_retp)
{
	stmf_i_scsi_session_t *iss;
	stmf_lun_map_ent_t *ent;
	stmf_lun_map_t *lm;
	stmf_status_t ret;
	int i;
	uint16_t n;

	if (ss == NULL) {
		iss = stmf_session_id_to_issptr(session_id, 1);
		if (iss == NULL)
			return (STMF_NOT_FOUND);
	} else {
		iss = (stmf_i_scsi_session_t *)ss->ss_stmf_private;
		rw_enter(iss->iss_lockp, RW_WRITER);
	}

	ent = NULL;
	if (lun == NULL) {
		lm = iss->iss_sm;
		for (i = 0; i < lm->lm_nentries; i++) {
			if (lm->lm_plus[i] == NULL)
				continue;
			ent = (stmf_lun_map_ent_t *)lm->lm_plus[i];
			if (ent->ent_lu == lu)
				break;
		}
	} else {
		n = ((uint16_t)lun[1] | (((uint16_t)(lun[0] & 0x3F)) << 8));
		ent = (stmf_lun_map_ent_t *)
		    stmf_get_ent_from_map(iss->iss_sm, n);
		if (lu && (ent->ent_lu != lu))
			ent = NULL;
	}
	if (ent && ent->ent_itl_datap) {
		*itl_handle_retp = ent->ent_itl_datap->itl_handle;
		ret = STMF_SUCCESS;
	} else {
		ret = STMF_NOT_FOUND;
	}

	rw_exit(iss->iss_lockp);
	return (ret);
}

stmf_data_buf_t *
stmf_alloc_dbuf(scsi_task_t *task, uint32_t size, uint32_t *pminsize,
    uint32_t flags)
{
	stmf_i_scsi_task_t *itask =
	    (stmf_i_scsi_task_t *)task->task_stmf_private;
	stmf_local_port_t *lport = task->task_lport;
	stmf_data_buf_t *dbuf;
	uint8_t ndx;

	ndx = stmf_first_zero[itask->itask_allocated_buf_map];
	if (ndx == 0xff)
		return (NULL);
	dbuf = itask->itask_dbufs[ndx] = lport->lport_ds->ds_alloc_data_buf(
	    task, size, pminsize, flags);
	if (dbuf) {
		task->task_cur_nbufs++;
		itask->itask_allocated_buf_map |= (1 << ndx);
		dbuf->db_flags &= ~DB_LPORT_XFER_ACTIVE;
		dbuf->db_handle = ndx;
		return (dbuf);
	}

	return (NULL);
}

stmf_status_t
stmf_setup_dbuf(scsi_task_t *task, stmf_data_buf_t *dbuf, uint32_t flags)
{
	stmf_i_scsi_task_t *itask =
	    (stmf_i_scsi_task_t *)task->task_stmf_private;
	stmf_local_port_t *lport = task->task_lport;
	uint8_t ndx;
	stmf_status_t ret;

	ASSERT(task->task_additional_flags & TASK_AF_ACCEPT_LU_DBUF);
	ASSERT(lport->lport_ds->ds_setup_dbuf != NULL);
	ASSERT(dbuf->db_flags & DB_LU_DATA_BUF);

	if ((task->task_additional_flags & TASK_AF_ACCEPT_LU_DBUF) == 0)
		return (STMF_FAILURE);
	if (lport->lport_ds->ds_setup_dbuf == NULL)
		return (STMF_FAILURE);

	ndx = stmf_first_zero[itask->itask_allocated_buf_map];
	if (ndx == 0xff)
		return (STMF_FAILURE);
	ret = lport->lport_ds->ds_setup_dbuf(task, dbuf, flags);
	if (ret == STMF_FAILURE)
		return (STMF_FAILURE);
	itask->itask_dbufs[ndx] = dbuf;
	task->task_cur_nbufs++;
	itask->itask_allocated_buf_map |= (1 << ndx);
	dbuf->db_handle = ndx;

	return (STMF_SUCCESS);
}

void
stmf_teardown_dbuf(scsi_task_t *task, stmf_data_buf_t *dbuf)
{
	stmf_i_scsi_task_t *itask =
	    (stmf_i_scsi_task_t *)task->task_stmf_private;
	stmf_local_port_t *lport = task->task_lport;

	ASSERT(task->task_additional_flags & TASK_AF_ACCEPT_LU_DBUF);
	ASSERT(lport->lport_ds->ds_teardown_dbuf != NULL);
	ASSERT(dbuf->db_flags & DB_LU_DATA_BUF);

	itask->itask_allocated_buf_map &= ~(1 << dbuf->db_handle);
	task->task_cur_nbufs--;
	lport->lport_ds->ds_teardown_dbuf(lport->lport_ds, dbuf);
}

void
stmf_free_dbuf(scsi_task_t *task, stmf_data_buf_t *dbuf)
{
	stmf_i_scsi_task_t *itask =
	    (stmf_i_scsi_task_t *)task->task_stmf_private;
	stmf_local_port_t *lport = task->task_lport;

	itask->itask_allocated_buf_map &= ~(1 << dbuf->db_handle);
	task->task_cur_nbufs--;
	lport->lport_ds->ds_free_data_buf(lport->lport_ds, dbuf);
}

stmf_data_buf_t *
stmf_handle_to_buf(scsi_task_t *task, uint8_t h)
{
	stmf_i_scsi_task_t *itask;

	itask = (stmf_i_scsi_task_t *)task->task_stmf_private;
	if (h > 3)
		return (NULL);
	return (itask->itask_dbufs[h]);
}

/* ARGSUSED */
struct scsi_task *
stmf_task_alloc(struct stmf_local_port *lport, stmf_scsi_session_t *ss,
			uint8_t *lun, uint16_t cdb_length_in, uint16_t ext_id)
{
	stmf_lu_t *lu;
	stmf_i_scsi_session_t *iss;
	stmf_i_lu_t *ilu;
	stmf_i_scsi_task_t *itask;
	stmf_i_scsi_task_t **ppitask;
	scsi_task_t *task;
	uint8_t	*l;
	stmf_lun_map_ent_t *lun_map_ent;
	uint16_t cdb_length;
	uint16_t luNbr;
	uint8_t new_task = 0;

	/*
	 * We allocate 7 extra bytes for CDB to provide a cdb pointer which
	 * is guaranteed to be 8 byte aligned. Some LU providers like OSD
	 * depend upon this alignment.
	 */
	if (cdb_length_in >= 16)
		cdb_length = cdb_length_in + 7;
	else
		cdb_length = 16 + 7;
	iss = (stmf_i_scsi_session_t *)ss->ss_stmf_private;
	luNbr = ((uint16_t)lun[1] | (((uint16_t)(lun[0] & 0x3F)) << 8));
	rw_enter(iss->iss_lockp, RW_READER);
	lun_map_ent =
	    (stmf_lun_map_ent_t *)stmf_get_ent_from_map(iss->iss_sm, luNbr);
	if (!lun_map_ent) {
		lu = dlun0;
	} else {
		lu = lun_map_ent->ent_lu;
	}
	ilu = lu->lu_stmf_private;
	if (ilu->ilu_flags & ILU_RESET_ACTIVE) {
		rw_exit(iss->iss_lockp);
		return (NULL);
	}
	ASSERT(lu == dlun0 || (ilu->ilu_state != STMF_STATE_OFFLINING &&
	    ilu->ilu_state != STMF_STATE_OFFLINE));
	do {
		if (ilu->ilu_free_tasks == NULL) {
			new_task = 1;
			break;
		}
		mutex_enter(&ilu->ilu_task_lock);
		for (ppitask = &ilu->ilu_free_tasks; (*ppitask != NULL) &&
		    ((*ppitask)->itask_cdb_buf_size < cdb_length);
		    ppitask = &((*ppitask)->itask_lu_free_next))
			;
		if (*ppitask) {
			itask = *ppitask;
			*ppitask = (*ppitask)->itask_lu_free_next;
			ilu->ilu_ntasks_free--;
			if (ilu->ilu_ntasks_free < ilu->ilu_ntasks_min_free)
				ilu->ilu_ntasks_min_free = ilu->ilu_ntasks_free;
		} else {
			new_task = 1;
		}
		mutex_exit(&ilu->ilu_task_lock);
	/* CONSTCOND */
	} while (0);

	if (!new_task) {
		/*
		 * Save the task_cdb pointer and zero per cmd fields.
		 * We know the task_cdb_length is large enough by task
		 * selection process above.
		 */
		uint8_t *save_cdb;
		uintptr_t t_start, t_end;

		task = itask->itask_task;
		save_cdb = task->task_cdb;	/* save */
		t_start = (uintptr_t)&task->task_flags;
		t_end = (uintptr_t)&task->task_extended_cmd;
		bzero((void *)t_start, (size_t)(t_end - t_start));
		task->task_cdb = save_cdb;	/* restore */
		itask->itask_ncmds = 0;
	} else {
		task = (scsi_task_t *)stmf_alloc(STMF_STRUCT_SCSI_TASK,
		    cdb_length, AF_FORCE_NOSLEEP);
		if (task == NULL) {
			rw_exit(iss->iss_lockp);
			return (NULL);
		}
		task->task_lu = lu;
		l = task->task_lun_no;
		l[0] = lun[0];
		l[1] = lun[1];
		l[2] = lun[2];
		l[3] = lun[3];
		l[4] = lun[4];
		l[5] = lun[5];
		l[6] = lun[6];
		l[7] = lun[7];
		task->task_cdb = (uint8_t *)task->task_port_private;
		if ((ulong_t)(task->task_cdb) & 7ul) {
			task->task_cdb = (uint8_t *)(((ulong_t)
			    (task->task_cdb) + 7ul) & ~(7ul));
		}
		itask = (stmf_i_scsi_task_t *)task->task_stmf_private;
		itask->itask_cdb_buf_size = cdb_length;
		mutex_init(&itask->itask_audit_mutex, NULL, MUTEX_DRIVER, NULL);
	}
	task->task_session = ss;
	task->task_lport = lport;
	task->task_cdb_length = cdb_length_in;
	itask->itask_flags = ITASK_IN_TRANSITION;
	itask->itask_waitq_time = 0;
	itask->itask_lu_read_time = itask->itask_lu_write_time = 0;
	itask->itask_lport_read_time = itask->itask_lport_write_time = 0;
	itask->itask_read_xfer = itask->itask_write_xfer = 0;
	itask->itask_audit_index = 0;

	if (new_task) {
		if (lu->lu_task_alloc(task) != STMF_SUCCESS) {
			rw_exit(iss->iss_lockp);
			stmf_free(task);
			return (NULL);
		}
		mutex_enter(&ilu->ilu_task_lock);
		if (ilu->ilu_flags & ILU_RESET_ACTIVE) {
			mutex_exit(&ilu->ilu_task_lock);
			rw_exit(iss->iss_lockp);
			stmf_free(task);
			return (NULL);
		}
		itask->itask_lu_next = ilu->ilu_tasks;
		if (ilu->ilu_tasks)
			ilu->ilu_tasks->itask_lu_prev = itask;
		ilu->ilu_tasks = itask;
		/* kmem_zalloc automatically makes itask->itask_lu_prev NULL */
		ilu->ilu_ntasks++;
		mutex_exit(&ilu->ilu_task_lock);
	}

	itask->itask_ilu_task_cntr = ilu->ilu_cur_task_cntr;
	atomic_inc_32(itask->itask_ilu_task_cntr);
	itask->itask_start_time = ddi_get_lbolt();

	if ((lun_map_ent != NULL) && ((itask->itask_itl_datap =
	    lun_map_ent->ent_itl_datap) != NULL)) {
		atomic_inc_32(&itask->itask_itl_datap->itl_counter);
		task->task_lu_itl_handle = itask->itask_itl_datap->itl_handle;
	} else {
		itask->itask_itl_datap = NULL;
		task->task_lu_itl_handle = NULL;
	}

	rw_exit(iss->iss_lockp);
	return (task);
}

static void
stmf_task_lu_free(scsi_task_t *task, stmf_i_scsi_session_t *iss)
{
	stmf_i_scsi_task_t *itask =
	    (stmf_i_scsi_task_t *)task->task_stmf_private;
	stmf_i_lu_t *ilu = (stmf_i_lu_t *)task->task_lu->lu_stmf_private;

	ASSERT(rw_lock_held(iss->iss_lockp));
	itask->itask_flags = ITASK_IN_FREE_LIST;
	itask->itask_proxy_msg_id = 0;
	mutex_enter(&ilu->ilu_task_lock);
	itask->itask_lu_free_next = ilu->ilu_free_tasks;
	ilu->ilu_free_tasks = itask;
	ilu->ilu_ntasks_free++;
	if (ilu->ilu_ntasks == ilu->ilu_ntasks_free)
		cv_signal(&ilu->ilu_offline_pending_cv);
	mutex_exit(&ilu->ilu_task_lock);
	atomic_dec_32(itask->itask_ilu_task_cntr);
}

void
stmf_task_lu_check_freelist(stmf_i_lu_t *ilu)
{
	uint32_t	num_to_release, ndx;
	stmf_i_scsi_task_t *itask;
	stmf_lu_t	*lu = ilu->ilu_lu;

	ASSERT(ilu->ilu_ntasks_min_free <= ilu->ilu_ntasks_free);

	/* free half of the minimal free of the free tasks */
	num_to_release = (ilu->ilu_ntasks_min_free + 1) / 2;
	if (!num_to_release) {
		return;
	}
	for (ndx = 0; ndx < num_to_release; ndx++) {
		mutex_enter(&ilu->ilu_task_lock);
		itask = ilu->ilu_free_tasks;
		if (itask == NULL) {
			mutex_exit(&ilu->ilu_task_lock);
			break;
		}
		ilu->ilu_free_tasks = itask->itask_lu_free_next;
		ilu->ilu_ntasks_free--;
		mutex_exit(&ilu->ilu_task_lock);

		lu->lu_task_free(itask->itask_task);
		mutex_enter(&ilu->ilu_task_lock);
		if (itask->itask_lu_next)
			itask->itask_lu_next->itask_lu_prev =
			    itask->itask_lu_prev;
		if (itask->itask_lu_prev)
			itask->itask_lu_prev->itask_lu_next =
			    itask->itask_lu_next;
		else
			ilu->ilu_tasks = itask->itask_lu_next;

		ilu->ilu_ntasks--;
		mutex_exit(&ilu->ilu_task_lock);
		stmf_free(itask->itask_task);
	}
}

/*
 * Called with stmf_lock held
 */
void
stmf_check_freetask()
{
	stmf_i_lu_t *ilu;
	clock_t	endtime = ddi_get_lbolt() + drv_usectohz(10000);

	/* stmf_svc_ilu_draining may get changed after stmf_lock is released */
	while ((ilu = stmf_state.stmf_svc_ilu_draining) != NULL) {
		stmf_state.stmf_svc_ilu_draining = ilu->ilu_next;
		if (!ilu->ilu_ntasks_min_free) {
			ilu->ilu_ntasks_min_free = ilu->ilu_ntasks_free;
			continue;
		}
		ilu->ilu_flags |= ILU_STALL_DEREGISTER;
		mutex_exit(&stmf_state.stmf_lock);
		stmf_task_lu_check_freelist(ilu);
		/*
		 * we do not care about the accuracy of
		 * ilu_ntasks_min_free, so we don't lock here
		 */
		ilu->ilu_ntasks_min_free = ilu->ilu_ntasks_free;
		mutex_enter(&stmf_state.stmf_lock);
		ilu->ilu_flags &= ~ILU_STALL_DEREGISTER;
		cv_broadcast(&stmf_state.stmf_cv);
		if (ddi_get_lbolt() >= endtime)
			break;
	}
}

void
stmf_do_ilu_timeouts(stmf_i_lu_t *ilu)
{
	clock_t l = ddi_get_lbolt();
	clock_t ps = drv_usectohz(1000000);
	stmf_i_scsi_task_t *itask;
	scsi_task_t *task;
	uint32_t to;

	mutex_enter(&ilu->ilu_task_lock);
	for (itask = ilu->ilu_tasks; itask != NULL;
	    itask = itask->itask_lu_next) {
		if (itask->itask_flags & (ITASK_IN_FREE_LIST |
		    ITASK_BEING_ABORTED)) {
			continue;
		}
		task = itask->itask_task;
		if (task->task_timeout == 0)
			to = stmf_default_task_timeout;
		else
			to = task->task_timeout;
		if ((itask->itask_start_time + (to * ps)) > l)
			continue;
		stmf_abort(STMF_QUEUE_TASK_ABORT, task,
		    STMF_TIMEOUT, NULL);
	}
	mutex_exit(&ilu->ilu_task_lock);
}

/*
 * Called with stmf_lock held
 */
void
stmf_check_ilu_timing()
{
	stmf_i_lu_t *ilu;
	clock_t	endtime = ddi_get_lbolt() + drv_usectohz(10000);

	/* stmf_svc_ilu_timing may get changed after stmf_lock is released */
	while ((ilu = stmf_state.stmf_svc_ilu_timing) != NULL) {
		stmf_state.stmf_svc_ilu_timing = ilu->ilu_next;
		if (ilu->ilu_cur_task_cntr == (&ilu->ilu_task_cntr1)) {
			if (ilu->ilu_task_cntr2 == 0) {
				ilu->ilu_cur_task_cntr = &ilu->ilu_task_cntr2;
				continue;
			}
		} else {
			if (ilu->ilu_task_cntr1 == 0) {
				ilu->ilu_cur_task_cntr = &ilu->ilu_task_cntr1;
				continue;
			}
		}
		/*
		 * If we are here then it means that there is some slowdown
		 * in tasks on this lu. We need to check.
		 */
		ilu->ilu_flags |= ILU_STALL_DEREGISTER;
		mutex_exit(&stmf_state.stmf_lock);
		stmf_do_ilu_timeouts(ilu);
		mutex_enter(&stmf_state.stmf_lock);
		ilu->ilu_flags &= ~ILU_STALL_DEREGISTER;
		cv_broadcast(&stmf_state.stmf_cv);
		if (ddi_get_lbolt() >= endtime)
			break;
	}
}

/*
 * Kills all tasks on a lu except tm_task
 */
void
stmf_task_lu_killall(stmf_lu_t *lu, scsi_task_t *tm_task, stmf_status_t s)
{
	stmf_i_lu_t *ilu = (stmf_i_lu_t *)lu->lu_stmf_private;
	stmf_i_scsi_task_t *itask;

	mutex_enter(&ilu->ilu_task_lock);

	for (itask = ilu->ilu_tasks; itask != NULL;
	    itask = itask->itask_lu_next) {
		if (itask->itask_flags & ITASK_IN_FREE_LIST)
			continue;
		if (itask->itask_task == tm_task)
			continue;
		stmf_abort(STMF_QUEUE_TASK_ABORT, itask->itask_task, s, NULL);
	}
	mutex_exit(&ilu->ilu_task_lock);
}

void
stmf_free_task_bufs(stmf_i_scsi_task_t *itask, stmf_local_port_t *lport)
{
	int i;
	uint8_t map;

	if ((map = itask->itask_allocated_buf_map) == 0)
		return;
	for (i = 0; i < 4; i++) {
		if (map & 1) {
			stmf_data_buf_t *dbuf;

			dbuf = itask->itask_dbufs[i];
			if (dbuf->db_xfer_start_timestamp) {
				stmf_lport_xfer_done(itask, dbuf);
			}
			if (dbuf->db_flags & DB_LU_DATA_BUF) {
				/*
				 * LU needs to clean up buffer.
				 * LU is required to free the buffer
				 * in the xfer_done handler.
				 */
				scsi_task_t *task = itask->itask_task;
				stmf_lu_t *lu = task->task_lu;

				lu->lu_dbuf_free(task, dbuf);
				ASSERT(((itask->itask_allocated_buf_map>>i)
				    & 1) == 0); /* must be gone */
			} else {
				ASSERT(dbuf->db_lu_private == NULL);
				dbuf->db_lu_private = NULL;
				lport->lport_ds->ds_free_data_buf(
				    lport->lport_ds, dbuf);
			}
		}
		map >>= 1;
	}
	itask->itask_allocated_buf_map = 0;
}

void
stmf_task_free(scsi_task_t *task)
{
	stmf_local_port_t *lport = task->task_lport;
	stmf_i_scsi_task_t *itask = (stmf_i_scsi_task_t *)
	    task->task_stmf_private;
	stmf_i_scsi_session_t *iss = (stmf_i_scsi_session_t *)
	    task->task_session->ss_stmf_private;

	stmf_task_audit(itask, TE_TASK_FREE, CMD_OR_IOF_NA, NULL);

	stmf_free_task_bufs(itask, lport);
	stmf_itl_task_done(itask);
	DTRACE_PROBE2(stmf__task__end, scsi_task_t *, task,
	    hrtime_t,
	    itask->itask_done_timestamp - itask->itask_start_timestamp);
	if (itask->itask_itl_datap) {
		if (atomic_dec_32_nv(&itask->itask_itl_datap->itl_counter) ==
		    0) {
			stmf_release_itl_handle(task->task_lu,
			    itask->itask_itl_datap);
		}
	}

	rw_enter(iss->iss_lockp, RW_READER);
	lport->lport_task_free(task);
	if (itask->itask_worker) {
		atomic_dec_32(&stmf_cur_ntasks);
		atomic_dec_32(&itask->itask_worker->worker_ref_count);
	}
	/*
	 * After calling stmf_task_lu_free, the task pointer can no longer
	 * be trusted.
	 */
	stmf_task_lu_free(task, iss);
	rw_exit(iss->iss_lockp);
}

void
stmf_post_task(scsi_task_t *task, stmf_data_buf_t *dbuf)
{
	stmf_i_scsi_task_t *itask = (stmf_i_scsi_task_t *)
	    task->task_stmf_private;
	stmf_i_lu_t *ilu = (stmf_i_lu_t *)task->task_lu->lu_stmf_private;
	int nv;
	uint32_t old, new;
	uint32_t ct;
	stmf_worker_t *w, *w1;
	uint8_t tm;

	if (task->task_max_nbufs > 4)
		task->task_max_nbufs = 4;
	task->task_cur_nbufs = 0;
	/* Latest value of currently running tasks */
	ct = atomic_inc_32_nv(&stmf_cur_ntasks);

	/* Select the next worker using round robin */
	nv = (int)atomic_inc_32_nv((uint32_t *)&stmf_worker_sel_counter);
	if (nv >= stmf_nworkers_accepting_cmds) {
		int s = nv;
		do {
			nv -= stmf_nworkers_accepting_cmds;
		} while (nv >= stmf_nworkers_accepting_cmds);
		if (nv < 0)
			nv = 0;
		/* Its ok if this cas fails */
		(void) atomic_cas_32((uint32_t *)&stmf_worker_sel_counter,
		    s, nv);
	}
	w = &stmf_workers[nv];

	/*
	 * A worker can be pinned by interrupt. So select the next one
	 * if it has lower load.
	 */
	if ((nv + 1) >= stmf_nworkers_accepting_cmds) {
		w1 = stmf_workers;
	} else {
		w1 = &stmf_workers[nv + 1];
	}
	if (w1->worker_queue_depth < w->worker_queue_depth)
		w = w1;

	mutex_enter(&w->worker_lock);
	if (((w->worker_flags & STMF_WORKER_STARTED) == 0) ||
	    (w->worker_flags & STMF_WORKER_TERMINATE)) {
		/*
		 * Maybe we are in the middle of a change. Just go to
		 * the 1st worker.
		 */
		mutex_exit(&w->worker_lock);
		w = stmf_workers;
		mutex_enter(&w->worker_lock);
	}
	itask->itask_worker = w;
	/*
	 * Track max system load inside the worker as we already have the
	 * worker lock (no point implementing another lock). The service
	 * thread will do the comparisons and figure out the max overall
	 * system load.
	 */
	if (w->worker_max_sys_qdepth_pu < ct)
		w->worker_max_sys_qdepth_pu = ct;

	do {
		old = new = itask->itask_flags;
		new |= ITASK_KNOWN_TO_TGT_PORT | ITASK_IN_WORKER_QUEUE;
		if (task->task_mgmt_function) {
			tm = task->task_mgmt_function;
			if ((tm == TM_TARGET_RESET) ||
			    (tm == TM_TARGET_COLD_RESET) ||
			    (tm == TM_TARGET_WARM_RESET)) {
				new |= ITASK_DEFAULT_HANDLING;
			}
		} else if (task->task_cdb[0] == SCMD_REPORT_LUNS) {
			new |= ITASK_DEFAULT_HANDLING;
		}
		new &= ~ITASK_IN_TRANSITION;
	} while (atomic_cas_32(&itask->itask_flags, old, new) != old);

	stmf_itl_task_start(itask);

	itask->itask_worker_next = NULL;
	if (w->worker_task_tail) {
		w->worker_task_tail->itask_worker_next = itask;
	} else {
		w->worker_task_head = itask;
	}
	w->worker_task_tail = itask;
	if (++(w->worker_queue_depth) > w->worker_max_qdepth_pu) {
		w->worker_max_qdepth_pu = w->worker_queue_depth;
	}
	/* Measure task waitq time */
	itask->itask_waitq_enter_timestamp = gethrtime();
	atomic_inc_32(&w->worker_ref_count);
	itask->itask_cmd_stack[0] = ITASK_CMD_NEW_TASK;
	itask->itask_ncmds = 1;
	stmf_task_audit(itask, TE_TASK_START, CMD_OR_IOF_NA, dbuf);
	if (dbuf) {
		itask->itask_allocated_buf_map = 1;
		itask->itask_dbufs[0] = dbuf;
		dbuf->db_handle = 0;
	} else {
		itask->itask_allocated_buf_map = 0;
		itask->itask_dbufs[0] = NULL;
	}

	if ((w->worker_flags & STMF_WORKER_ACTIVE) == 0) {
		w->worker_signal_timestamp = gethrtime();
		DTRACE_PROBE2(worker__signal, stmf_worker_t *, w,
		    scsi_task_t *, task);
		cv_signal(&w->worker_cv);
	}
	mutex_exit(&w->worker_lock);

	/*
	 * This can only happen if during stmf_task_alloc(), ILU_RESET_ACTIVE
	 * was set between checking of ILU_RESET_ACTIVE and clearing of the
	 * ITASK_IN_FREE_LIST flag. Take care of these "sneaked-in" tasks here.
	 */
	if (ilu->ilu_flags & ILU_RESET_ACTIVE) {
		stmf_abort(STMF_QUEUE_TASK_ABORT, task, STMF_ABORTED, NULL);
	}
}

static void
stmf_task_audit(stmf_i_scsi_task_t *itask,
    task_audit_event_t te, uint32_t cmd_or_iof, stmf_data_buf_t *dbuf)
{
	stmf_task_audit_rec_t *ar;

	mutex_enter(&itask->itask_audit_mutex);
	ar = &itask->itask_audit_records[itask->itask_audit_index++];
	itask->itask_audit_index &= (ITASK_TASK_AUDIT_DEPTH - 1);
	ar->ta_event = te;
	ar->ta_cmd_or_iof = cmd_or_iof;
	ar->ta_itask_flags = itask->itask_flags;
	ar->ta_dbuf = dbuf;
	gethrestime(&ar->ta_timestamp);
	mutex_exit(&itask->itask_audit_mutex);
}


/*
 * ++++++++++++++ ABORT LOGIC ++++++++++++++++++++
 * Once ITASK_BEING_ABORTED is set, ITASK_KNOWN_TO_LU can be reset already
 * i.e. before ITASK_BEING_ABORTED being set. But if it was not, it cannot
 * be reset until the LU explicitly calls stmf_task_lu_aborted(). Of course
 * the LU will make this call only if we call the LU's abort entry point.
 * we will only call that entry point if ITASK_KNOWN_TO_LU was set.
 *
 * Same logic applies for the port.
 *
 * Also ITASK_BEING_ABORTED will not be allowed to set if both KNOWN_TO_LU
 * and KNOWN_TO_TGT_PORT are reset.
 *
 * +++++++++++++++++++++++++++++++++++++++++++++++
 */

stmf_status_t
stmf_xfer_data(scsi_task_t *task, stmf_data_buf_t *dbuf, uint32_t ioflags)
{
	stmf_status_t ret = STMF_SUCCESS;

	stmf_i_scsi_task_t *itask =
	    (stmf_i_scsi_task_t *)task->task_stmf_private;

	stmf_task_audit(itask, TE_XFER_START, ioflags, dbuf);

	if (ioflags & STMF_IOF_LU_DONE) {
		uint32_t new, old;
		do {
			new = old = itask->itask_flags;
			if (new & ITASK_BEING_ABORTED)
				return (STMF_ABORTED);
			new &= ~ITASK_KNOWN_TO_LU;
		} while (atomic_cas_32(&itask->itask_flags, old, new) != old);
	}
	if (itask->itask_flags & ITASK_BEING_ABORTED)
		return (STMF_ABORTED);
#ifdef	DEBUG
	if (!(ioflags & STMF_IOF_STATS_ONLY) && stmf_drop_buf_counter > 0) {
		if (atomic_dec_32_nv(&stmf_drop_buf_counter) == 1)
			return (STMF_SUCCESS);
	}
#endif

	stmf_update_kstat_lu_io(task, dbuf);
	stmf_update_kstat_lport_io(task, dbuf);
	stmf_lport_xfer_start(itask, dbuf);
	if (ioflags & STMF_IOF_STATS_ONLY) {
		stmf_lport_xfer_done(itask, dbuf);
		return (STMF_SUCCESS);
	}

	dbuf->db_flags |= DB_LPORT_XFER_ACTIVE;
	ret = task->task_lport->lport_xfer_data(task, dbuf, ioflags);

	/*
	 * Port provider may have already called the buffer callback in
	 * which case dbuf->db_xfer_start_timestamp will be 0.
	 */
	if (ret != STMF_SUCCESS) {
		dbuf->db_flags &= ~DB_LPORT_XFER_ACTIVE;
		if (dbuf->db_xfer_start_timestamp != 0)
			stmf_lport_xfer_done(itask, dbuf);
	}

	return (ret);
}

void
stmf_data_xfer_done(scsi_task_t *task, stmf_data_buf_t *dbuf, uint32_t iof)
{
	stmf_i_scsi_task_t *itask =
	    (stmf_i_scsi_task_t *)task->task_stmf_private;
	stmf_i_local_port_t *ilport;
	stmf_worker_t *w = itask->itask_worker;
	uint32_t new, old;
	uint8_t update_queue_flags, free_it, queue_it;

	stmf_lport_xfer_done(itask, dbuf);

	stmf_task_audit(itask, TE_XFER_DONE, iof, dbuf);

	/* Guard against unexpected completions from the lport */
	if (dbuf->db_flags & DB_LPORT_XFER_ACTIVE) {
		dbuf->db_flags &= ~DB_LPORT_XFER_ACTIVE;
	} else {
		/*
		 * This should never happen.
		 */
		ilport = task->task_lport->lport_stmf_private;
		ilport->ilport_unexpected_comp++;
		cmn_err(CE_PANIC, "Unexpected xfer completion task %p dbuf %p",
		    (void *)task, (void *)dbuf);
		return;
	}

	mutex_enter(&w->worker_lock);
	do {
		new = old = itask->itask_flags;
		if (old & ITASK_BEING_ABORTED) {
			mutex_exit(&w->worker_lock);
			return;
		}
		free_it = 0;
		if (iof & STMF_IOF_LPORT_DONE) {
			new &= ~ITASK_KNOWN_TO_TGT_PORT;
			task->task_completion_status = dbuf->db_xfer_status;
			free_it = 1;
		}
		/*
		 * If the task is known to LU then queue it. But if
		 * it is already queued (multiple completions) then
		 * just update the buffer information by grabbing the
		 * worker lock. If the task is not known to LU,
		 * completed/aborted, then see if we need to
		 * free this task.
		 */
		if (old & ITASK_KNOWN_TO_LU) {
			free_it = 0;
			update_queue_flags = 1;
			if (old & ITASK_IN_WORKER_QUEUE) {
				queue_it = 0;
			} else {
				queue_it = 1;
				new |= ITASK_IN_WORKER_QUEUE;
			}
		} else {
			update_queue_flags = 0;
			queue_it = 0;
		}
	} while (atomic_cas_32(&itask->itask_flags, old, new) != old);

	if (update_queue_flags) {
		uint8_t cmd = (dbuf->db_handle << 5) | ITASK_CMD_DATA_XFER_DONE;

		ASSERT(itask->itask_ncmds < ITASK_MAX_NCMDS);
		itask->itask_cmd_stack[itask->itask_ncmds++] = cmd;
		if (queue_it) {
			itask->itask_worker_next = NULL;
			if (w->worker_task_tail) {
				w->worker_task_tail->itask_worker_next = itask;
			} else {
				w->worker_task_head = itask;
			}
			w->worker_task_tail = itask;
			/* Measure task waitq time */
			itask->itask_waitq_enter_timestamp = gethrtime();
			if (++(w->worker_queue_depth) >
			    w->worker_max_qdepth_pu) {
				w->worker_max_qdepth_pu = w->worker_queue_depth;
			}
			if ((w->worker_flags & STMF_WORKER_ACTIVE) == 0)
				cv_signal(&w->worker_cv);
		}
	}
	mutex_exit(&w->worker_lock);

	if (free_it) {
		if ((itask->itask_flags & (ITASK_KNOWN_TO_LU |
		    ITASK_KNOWN_TO_TGT_PORT | ITASK_IN_WORKER_QUEUE |
		    ITASK_BEING_ABORTED)) == 0) {
			stmf_task_free(task);
		}
	}
}

stmf_status_t
stmf_send_scsi_status(scsi_task_t *task, uint32_t ioflags)
{
	DTRACE_PROBE1(scsi__send__status, scsi_task_t *, task);

	stmf_i_scsi_task_t *itask =
	    (stmf_i_scsi_task_t *)task->task_stmf_private;

	stmf_task_audit(itask, TE_SEND_STATUS, ioflags, NULL);

	if (ioflags & STMF_IOF_LU_DONE) {
		uint32_t new, old;
		do {
			new = old = itask->itask_flags;
			if (new & ITASK_BEING_ABORTED)
				return (STMF_ABORTED);
			new &= ~ITASK_KNOWN_TO_LU;
		} while (atomic_cas_32(&itask->itask_flags, old, new) != old);
	}

	if (!(itask->itask_flags & ITASK_KNOWN_TO_TGT_PORT)) {
		return (STMF_SUCCESS);
	}

	if (itask->itask_flags & ITASK_BEING_ABORTED)
		return (STMF_ABORTED);

	if (task->task_additional_flags & TASK_AF_NO_EXPECTED_XFER_LENGTH) {
		task->task_status_ctrl = 0;
		task->task_resid = 0;
	} else if (task->task_cmd_xfer_length >
	    task->task_expected_xfer_length) {
		task->task_status_ctrl = TASK_SCTRL_OVER;
		task->task_resid = task->task_cmd_xfer_length -
		    task->task_expected_xfer_length;
	} else if (task->task_nbytes_transferred <
	    task->task_expected_xfer_length) {
		task->task_status_ctrl = TASK_SCTRL_UNDER;
		task->task_resid = task->task_expected_xfer_length -
		    task->task_nbytes_transferred;
	} else {
		task->task_status_ctrl = 0;
		task->task_resid = 0;
	}
	return (task->task_lport->lport_send_status(task, ioflags));
}

void
stmf_send_status_done(scsi_task_t *task, stmf_status_t s, uint32_t iof)
{
	stmf_i_scsi_task_t *itask =
	    (stmf_i_scsi_task_t *)task->task_stmf_private;
	stmf_worker_t *w = itask->itask_worker;
	uint32_t new, old;
	uint8_t free_it, queue_it;

	stmf_task_audit(itask, TE_SEND_STATUS_DONE, iof, NULL);

	mutex_enter(&w->worker_lock);
	do {
		new = old = itask->itask_flags;
		if (old & ITASK_BEING_ABORTED) {
			mutex_exit(&w->worker_lock);
			return;
		}
		free_it = 0;
		if (iof & STMF_IOF_LPORT_DONE) {
			new &= ~ITASK_KNOWN_TO_TGT_PORT;
			free_it = 1;
		}
		/*
		 * If the task is known to LU then queue it. But if
		 * it is already queued (multiple completions) then
		 * just update the buffer information by grabbing the
		 * worker lock. If the task is not known to LU,
		 * completed/aborted, then see if we need to
		 * free this task.
		 */
		if (old & ITASK_KNOWN_TO_LU) {
			free_it = 0;
			queue_it = 1;
			if (old & ITASK_IN_WORKER_QUEUE) {
				cmn_err(CE_PANIC, "status completion received"
				    " when task is already in worker queue "
				    " task = %p", (void *)task);
			}
			new |= ITASK_IN_WORKER_QUEUE;
		} else {
			queue_it = 0;
		}
	} while (atomic_cas_32(&itask->itask_flags, old, new) != old);
	task->task_completion_status = s;


	if (queue_it) {
		ASSERT(itask->itask_ncmds < ITASK_MAX_NCMDS);
		itask->itask_cmd_stack[itask->itask_ncmds++] =
		    ITASK_CMD_STATUS_DONE;
		itask->itask_worker_next = NULL;
		if (w->worker_task_tail) {
			w->worker_task_tail->itask_worker_next = itask;
		} else {
			w->worker_task_head = itask;
		}
		w->worker_task_tail = itask;
		/* Measure task waitq time */
		itask->itask_waitq_enter_timestamp = gethrtime();
		if (++(w->worker_queue_depth) > w->worker_max_qdepth_pu) {
			w->worker_max_qdepth_pu = w->worker_queue_depth;
		}
		if ((w->worker_flags & STMF_WORKER_ACTIVE) == 0)
			cv_signal(&w->worker_cv);
	}
	mutex_exit(&w->worker_lock);

	if (free_it) {
		if ((itask->itask_flags & (ITASK_KNOWN_TO_LU |
		    ITASK_KNOWN_TO_TGT_PORT | ITASK_IN_WORKER_QUEUE |
		    ITASK_BEING_ABORTED)) == 0) {
			stmf_task_free(task);
		} else {
			cmn_err(CE_PANIC, "LU is done with the task but LPORT "
			    " is not done, itask %p itask_flags %x",
			    (void *)itask, itask->itask_flags);
		}
	}
}

void
stmf_task_lu_done(scsi_task_t *task)
{
	stmf_i_scsi_task_t *itask =
	    (stmf_i_scsi_task_t *)task->task_stmf_private;
	stmf_worker_t *w = itask->itask_worker;
	uint32_t new, old;

	mutex_enter(&w->worker_lock);
	do {
		new = old = itask->itask_flags;
		if (old & ITASK_BEING_ABORTED) {
			mutex_exit(&w->worker_lock);
			return;
		}
		if (old & ITASK_IN_WORKER_QUEUE) {
			cmn_err(CE_PANIC, "task_lu_done received"
			    " when task is in worker queue "
			    " task = %p", (void *)task);
		}
		new &= ~ITASK_KNOWN_TO_LU;
	} while (atomic_cas_32(&itask->itask_flags, old, new) != old);

	mutex_exit(&w->worker_lock);

	if ((itask->itask_flags & (ITASK_KNOWN_TO_LU |
	    ITASK_KNOWN_TO_TGT_PORT | ITASK_IN_WORKER_QUEUE |
	    ITASK_BEING_ABORTED)) == 0) {
		stmf_task_free(task);
	} else {
		cmn_err(CE_PANIC, "stmf_lu_done should be the last stage but "
		    " the task is still not done, task = %p", (void *)task);
	}
}

void
stmf_queue_task_for_abort(scsi_task_t *task, stmf_status_t s)
{
	stmf_i_scsi_task_t *itask =
	    (stmf_i_scsi_task_t *)task->task_stmf_private;
	stmf_worker_t *w;
	uint32_t old, new;

	stmf_task_audit(itask, TE_TASK_ABORT, CMD_OR_IOF_NA, NULL);

	do {
		old = new = itask->itask_flags;
		if ((old & ITASK_BEING_ABORTED) ||
		    ((old & (ITASK_KNOWN_TO_TGT_PORT |
		    ITASK_KNOWN_TO_LU)) == 0)) {
			return;
		}
		new |= ITASK_BEING_ABORTED;
	} while (atomic_cas_32(&itask->itask_flags, old, new) != old);
	task->task_completion_status = s;
	itask->itask_start_time = ddi_get_lbolt();

	if (((w = itask->itask_worker) == NULL) ||
	    (itask->itask_flags & ITASK_IN_TRANSITION)) {
		return;
	}

	/* Queue it and get out */
	mutex_enter(&w->worker_lock);
	if (itask->itask_flags & ITASK_IN_WORKER_QUEUE) {
		mutex_exit(&w->worker_lock);
		return;
	}
	atomic_or_32(&itask->itask_flags, ITASK_IN_WORKER_QUEUE);
	itask->itask_worker_next = NULL;
	if (w->worker_task_tail) {
		w->worker_task_tail->itask_worker_next = itask;
	} else {
		w->worker_task_head = itask;
	}
	w->worker_task_tail = itask;
	if (++(w->worker_queue_depth) > w->worker_max_qdepth_pu) {
		w->worker_max_qdepth_pu = w->worker_queue_depth;
	}
	if ((w->worker_flags & STMF_WORKER_ACTIVE) == 0)
		cv_signal(&w->worker_cv);
	mutex_exit(&w->worker_lock);
}

void
stmf_abort(int abort_cmd, scsi_task_t *task, stmf_status_t s, void *arg)
{
	stmf_i_scsi_task_t *itask = NULL;
	uint32_t old, new, f, rf;

	DTRACE_PROBE2(scsi__task__abort, scsi_task_t *, task,
	    stmf_status_t, s);

	switch (abort_cmd) {
	case STMF_QUEUE_ABORT_LU:
		stmf_task_lu_killall((stmf_lu_t *)arg, task, s);
		return;
	case STMF_QUEUE_TASK_ABORT:
		stmf_queue_task_for_abort(task, s);
		return;
	case STMF_REQUEUE_TASK_ABORT_LPORT:
		rf = ITASK_TGT_PORT_ABORT_CALLED;
		f = ITASK_KNOWN_TO_TGT_PORT;
		break;
	case STMF_REQUEUE_TASK_ABORT_LU:
		rf = ITASK_LU_ABORT_CALLED;
		f = ITASK_KNOWN_TO_LU;
		break;
	default:
		return;
	}
	itask = (stmf_i_scsi_task_t *)task->task_stmf_private;
	f |= ITASK_BEING_ABORTED | rf;
	do {
		old = new = itask->itask_flags;
		if ((old & f) != f) {
			return;
		}
		new &= ~rf;
	} while (atomic_cas_32(&itask->itask_flags, old, new) != old);
}

void
stmf_task_lu_aborted(scsi_task_t *task, stmf_status_t s, uint32_t iof)
{
	char			 info[STMF_CHANGE_INFO_LEN];
	stmf_i_scsi_task_t	*itask = TASK_TO_ITASK(task);
	unsigned long long	st;

	stmf_task_audit(itask, TE_TASK_LU_ABORTED, iof, NULL);

	st = s;	/* gcc fix */
	if ((s != STMF_ABORT_SUCCESS) && (s != STMF_NOT_FOUND)) {
		(void) snprintf(info, sizeof (info),
		    "task %p, lu failed to abort ret=%llx", (void *)task, st);
	} else if ((iof & STMF_IOF_LU_DONE) == 0) {
		(void) snprintf(info, sizeof (info),
		    "Task aborted but LU is not finished, task ="
		    "%p, s=%llx, iof=%x", (void *)task, st, iof);
	} else {
		/*
		 * LU abort successfully
		 */
		atomic_and_32(&itask->itask_flags, ~ITASK_KNOWN_TO_LU);
		return;
	}

	stmf_abort_task_offline(task, 1, info);
}

void
stmf_task_lport_aborted(scsi_task_t *task, stmf_status_t s, uint32_t iof)
{
	char			info[STMF_CHANGE_INFO_LEN];
	stmf_i_scsi_task_t	*itask = TASK_TO_ITASK(task);
	unsigned long long	st;
	uint32_t		old, new;

	stmf_task_audit(itask, TE_TASK_LPORT_ABORTED, iof, NULL);

	st = s;
	if ((s != STMF_ABORT_SUCCESS) && (s != STMF_NOT_FOUND)) {
		(void) snprintf(info, sizeof (info),
		    "task %p, tgt port failed to abort ret=%llx", (void *)task,
		    st);
	} else if ((iof & STMF_IOF_LPORT_DONE) == 0) {
		(void) snprintf(info, sizeof (info),
		    "Task aborted but tgt port is not finished, "
		    "task=%p, s=%llx, iof=%x", (void *)task, st, iof);
	} else {
		/*
		 * LPORT abort successfully
		 */
		do {
			old = new = itask->itask_flags;
			if (!(old & ITASK_KNOWN_TO_TGT_PORT))
				return;
			new &= ~ITASK_KNOWN_TO_TGT_PORT;
		} while (atomic_cas_32(&itask->itask_flags, old, new) != old);
		return;
	}

	stmf_abort_task_offline(task, 0, info);
}

stmf_status_t
stmf_task_poll_lu(scsi_task_t *task, uint32_t timeout)
{
	stmf_i_scsi_task_t *itask = (stmf_i_scsi_task_t *)
	    task->task_stmf_private;
	stmf_worker_t *w = itask->itask_worker;
	int i;

	ASSERT(itask->itask_flags & ITASK_KNOWN_TO_LU);
	mutex_enter(&w->worker_lock);
	if (itask->itask_ncmds >= ITASK_MAX_NCMDS) {
		mutex_exit(&w->worker_lock);
		return (STMF_BUSY);
	}
	for (i = 0; i < itask->itask_ncmds; i++) {
		if (itask->itask_cmd_stack[i] == ITASK_CMD_POLL_LU) {
			mutex_exit(&w->worker_lock);
			return (STMF_SUCCESS);
		}
	}
	itask->itask_cmd_stack[itask->itask_ncmds++] = ITASK_CMD_POLL_LU;
	if (timeout == ITASK_DEFAULT_POLL_TIMEOUT) {
		itask->itask_poll_timeout = ddi_get_lbolt() + 1;
	} else {
		clock_t t = drv_usectohz(timeout * 1000);
		if (t == 0)
			t = 1;
		itask->itask_poll_timeout = ddi_get_lbolt() + t;
	}
	if ((itask->itask_flags & ITASK_IN_WORKER_QUEUE) == 0) {
		itask->itask_worker_next = NULL;
		if (w->worker_task_tail) {
			w->worker_task_tail->itask_worker_next = itask;
		} else {
			w->worker_task_head = itask;
		}
		w->worker_task_tail = itask;
		if (++(w->worker_queue_depth) > w->worker_max_qdepth_pu) {
			w->worker_max_qdepth_pu = w->worker_queue_depth;
		}
		atomic_or_32(&itask->itask_flags, ITASK_IN_WORKER_QUEUE);
		if ((w->worker_flags & STMF_WORKER_ACTIVE) == 0)
			cv_signal(&w->worker_cv);
	}
	mutex_exit(&w->worker_lock);
	return (STMF_SUCCESS);
}

stmf_status_t
stmf_task_poll_lport(scsi_task_t *task, uint32_t timeout)
{
	stmf_i_scsi_task_t *itask = (stmf_i_scsi_task_t *)
	    task->task_stmf_private;
	stmf_worker_t *w = itask->itask_worker;
	int i;

	ASSERT(itask->itask_flags & ITASK_KNOWN_TO_TGT_PORT);
	mutex_enter(&w->worker_lock);
	if (itask->itask_ncmds >= ITASK_MAX_NCMDS) {
		mutex_exit(&w->worker_lock);
		return (STMF_BUSY);
	}
	for (i = 0; i < itask->itask_ncmds; i++) {
		if (itask->itask_cmd_stack[i] == ITASK_CMD_POLL_LPORT) {
			mutex_exit(&w->worker_lock);
			return (STMF_SUCCESS);
		}
	}
	itask->itask_cmd_stack[itask->itask_ncmds++] = ITASK_CMD_POLL_LPORT;
	if (timeout == ITASK_DEFAULT_POLL_TIMEOUT) {
		itask->itask_poll_timeout = ddi_get_lbolt() + 1;
	} else {
		clock_t t = drv_usectohz(timeout * 1000);
		if (t == 0)
			t = 1;
		itask->itask_poll_timeout = ddi_get_lbolt() + t;
	}
	if ((itask->itask_flags & ITASK_IN_WORKER_QUEUE) == 0) {
		itask->itask_worker_next = NULL;
		if (w->worker_task_tail) {
			w->worker_task_tail->itask_worker_next = itask;
		} else {
			w->worker_task_head = itask;
		}
		w->worker_task_tail = itask;
		if (++(w->worker_queue_depth) > w->worker_max_qdepth_pu) {
			w->worker_max_qdepth_pu = w->worker_queue_depth;
		}
		if ((w->worker_flags & STMF_WORKER_ACTIVE) == 0)
			cv_signal(&w->worker_cv);
	}
	mutex_exit(&w->worker_lock);
	return (STMF_SUCCESS);
}

void
stmf_do_task_abort(scsi_task_t *task)
{
	stmf_i_scsi_task_t	*itask = TASK_TO_ITASK(task);
	stmf_lu_t		*lu;
	stmf_local_port_t	*lport;
	unsigned long long	 ret;
	uint32_t		 old, new;
	uint8_t			 call_lu_abort, call_port_abort;
	char			 info[STMF_CHANGE_INFO_LEN];

	lu = task->task_lu;
	lport = task->task_lport;
	do {
		old = new = itask->itask_flags;
		if ((old & (ITASK_KNOWN_TO_LU | ITASK_LU_ABORT_CALLED)) ==
		    ITASK_KNOWN_TO_LU) {
			new |= ITASK_LU_ABORT_CALLED;
			call_lu_abort = 1;
		} else {
			call_lu_abort = 0;
		}
	} while (atomic_cas_32(&itask->itask_flags, old, new) != old);

	if (call_lu_abort) {
		if ((itask->itask_flags & ITASK_DEFAULT_HANDLING) == 0) {
			ret = lu->lu_abort(lu, STMF_LU_ABORT_TASK, task, 0);
		} else {
			ret = dlun0->lu_abort(lu, STMF_LU_ABORT_TASK, task, 0);
		}
		if ((ret == STMF_ABORT_SUCCESS) || (ret == STMF_NOT_FOUND)) {
			stmf_task_lu_aborted(task, ret, STMF_IOF_LU_DONE);
		} else if (ret == STMF_BUSY) {
			atomic_and_32(&itask->itask_flags,
			    ~ITASK_LU_ABORT_CALLED);
		} else if (ret != STMF_SUCCESS) {
			(void) snprintf(info, sizeof (info),
			    "Abort failed by LU %p, ret %llx", (void *)lu, ret);
			stmf_abort_task_offline(task, 1, info);
		}
	} else if (itask->itask_flags & ITASK_KNOWN_TO_LU) {
		if (ddi_get_lbolt() > (itask->itask_start_time +
		    STMF_SEC2TICK(lu->lu_abort_timeout?
		    lu->lu_abort_timeout : ITASK_DEFAULT_ABORT_TIMEOUT))) {
			(void) snprintf(info, sizeof (info),
			    "lu abort timed out");
			stmf_abort_task_offline(itask->itask_task, 1, info);
		}
	}

	do {
		old = new = itask->itask_flags;
		if ((old & (ITASK_KNOWN_TO_TGT_PORT |
		    ITASK_TGT_PORT_ABORT_CALLED)) == ITASK_KNOWN_TO_TGT_PORT) {
			new |= ITASK_TGT_PORT_ABORT_CALLED;
			call_port_abort = 1;
		} else {
			call_port_abort = 0;
		}
	} while (atomic_cas_32(&itask->itask_flags, old, new) != old);
	if (call_port_abort) {
		ret = lport->lport_abort(lport, STMF_LPORT_ABORT_TASK, task, 0);
		if ((ret == STMF_ABORT_SUCCESS) || (ret == STMF_NOT_FOUND)) {
			stmf_task_lport_aborted(task, ret, STMF_IOF_LPORT_DONE);
		} else if (ret == STMF_BUSY) {
			atomic_and_32(&itask->itask_flags,
			    ~ITASK_TGT_PORT_ABORT_CALLED);
		} else if (ret != STMF_SUCCESS) {
			(void) snprintf(info, sizeof (info),
			    "Abort failed by tgt port %p ret %llx",
			    (void *)lport, ret);
			stmf_abort_task_offline(task, 0, info);
		}
	} else if (itask->itask_flags & ITASK_KNOWN_TO_TGT_PORT) {
		if (ddi_get_lbolt() > (itask->itask_start_time +
		    STMF_SEC2TICK(lport->lport_abort_timeout?
		    lport->lport_abort_timeout :
		    ITASK_DEFAULT_ABORT_TIMEOUT))) {
			(void) snprintf(info, sizeof (info),
			    "lport abort timed out");
			stmf_abort_task_offline(itask->itask_task, 0, info);
		}
	}
}

stmf_status_t
stmf_ctl(int cmd, void *obj, void *arg)
{
	stmf_status_t			ret;
	stmf_i_lu_t			*ilu;
	stmf_i_local_port_t		*ilport;
	stmf_state_change_info_t	*ssci = (stmf_state_change_info_t *)arg;

	mutex_enter(&stmf_state.stmf_lock);
	ret = STMF_INVALID_ARG;
	if (cmd & STMF_CMD_LU_OP) {
		ilu = stmf_lookup_lu((stmf_lu_t *)obj);
		if (ilu == NULL) {
			goto stmf_ctl_lock_exit;
		}
		DTRACE_PROBE3(lu__state__change,
		    stmf_lu_t *, ilu->ilu_lu,
		    int, cmd, stmf_state_change_info_t *, ssci);
	} else if (cmd & STMF_CMD_LPORT_OP) {
		ilport = stmf_lookup_lport((stmf_local_port_t *)obj);
		if (ilport == NULL) {
			goto stmf_ctl_lock_exit;
		}
		DTRACE_PROBE3(lport__state__change,
		    stmf_local_port_t *, ilport->ilport_lport,
		    int, cmd, stmf_state_change_info_t *, ssci);
	} else {
		goto stmf_ctl_lock_exit;
	}

	switch (cmd) {
	case STMF_CMD_LU_ONLINE:
		switch (ilu->ilu_state) {
			case STMF_STATE_OFFLINE:
				ret = STMF_SUCCESS;
				break;
			case STMF_STATE_ONLINE:
			case STMF_STATE_ONLINING:
				ret = STMF_ALREADY;
				break;
			case STMF_STATE_OFFLINING:
				ret = STMF_BUSY;
				break;
			default:
				ret = STMF_BADSTATE;
				break;
		}
		if (ret != STMF_SUCCESS)
			goto stmf_ctl_lock_exit;

		ilu->ilu_state = STMF_STATE_ONLINING;
		mutex_exit(&stmf_state.stmf_lock);
		stmf_svc_queue(cmd, obj, (stmf_state_change_info_t *)arg);
		break;

	case STMF_CMD_LU_ONLINE_COMPLETE:
		if (ilu->ilu_state != STMF_STATE_ONLINING) {
			ret = STMF_BADSTATE;
			goto stmf_ctl_lock_exit;
		}
		if (((stmf_change_status_t *)arg)->st_completion_status ==
		    STMF_SUCCESS) {
			ilu->ilu_state = STMF_STATE_ONLINE;
			mutex_exit(&stmf_state.stmf_lock);
			((stmf_lu_t *)obj)->lu_ctl((stmf_lu_t *)obj,
			    STMF_ACK_LU_ONLINE_COMPLETE, arg);
			mutex_enter(&stmf_state.stmf_lock);
			stmf_add_lu_to_active_sessions((stmf_lu_t *)obj);
		} else {
			/* XXX: should throw a meesage an record more data */
			ilu->ilu_state = STMF_STATE_OFFLINE;
		}
		ret = STMF_SUCCESS;
		goto stmf_ctl_lock_exit;

	case STMF_CMD_LU_OFFLINE:
		switch (ilu->ilu_state) {
			case STMF_STATE_ONLINE:
				ret = STMF_SUCCESS;
				break;
			case STMF_STATE_OFFLINE:
			case STMF_STATE_OFFLINING:
				ret = STMF_ALREADY;
				break;
			case STMF_STATE_ONLINING:
				ret = STMF_BUSY;
				break;
			default:
				ret = STMF_BADSTATE;
				break;
		}
		if (ret != STMF_SUCCESS)
			goto stmf_ctl_lock_exit;
		ilu->ilu_state = STMF_STATE_OFFLINING;
		mutex_exit(&stmf_state.stmf_lock);
		stmf_svc_queue(cmd, obj, (stmf_state_change_info_t *)arg);
		break;

	case STMF_CMD_LU_OFFLINE_COMPLETE:
		if (ilu->ilu_state != STMF_STATE_OFFLINING) {
			ret = STMF_BADSTATE;
			goto stmf_ctl_lock_exit;
		}
		if (((stmf_change_status_t *)arg)->st_completion_status ==
		    STMF_SUCCESS) {
			ilu->ilu_state = STMF_STATE_OFFLINE;
			mutex_exit(&stmf_state.stmf_lock);
			((stmf_lu_t *)obj)->lu_ctl((stmf_lu_t *)obj,
			    STMF_ACK_LU_OFFLINE_COMPLETE, arg);
			mutex_enter(&stmf_state.stmf_lock);
		} else {
			ilu->ilu_state = STMF_STATE_ONLINE;
			stmf_add_lu_to_active_sessions((stmf_lu_t *)obj);
		}
		mutex_exit(&stmf_state.stmf_lock);
		break;

	/*
	 * LPORT_ONLINE/OFFLINE has nothing to do with link offline/online.
	 * It's related with hardware disable/enable.
	 */
	case STMF_CMD_LPORT_ONLINE:
		switch (ilport->ilport_state) {
			case STMF_STATE_OFFLINE:
				ret = STMF_SUCCESS;
				break;
			case STMF_STATE_ONLINE:
			case STMF_STATE_ONLINING:
				ret = STMF_ALREADY;
				break;
			case STMF_STATE_OFFLINING:
				ret = STMF_BUSY;
				break;
			default:
				ret = STMF_BADSTATE;
				break;
		}
		if (ret != STMF_SUCCESS)
			goto stmf_ctl_lock_exit;

		/*
		 * Only user request can recover the port from the
		 * FORCED_OFFLINE state
		 */
		if (ilport->ilport_flags & ILPORT_FORCED_OFFLINE) {
			if (!(ssci->st_rflags & STMF_RFLAG_USER_REQUEST)) {
				ret = STMF_FAILURE;
				goto stmf_ctl_lock_exit;
			}
		}

		/*
		 * Avoid too frequent request to online
		 */
		if (ssci->st_rflags & STMF_RFLAG_USER_REQUEST) {
			ilport->ilport_online_times = 0;
			ilport->ilport_avg_interval = 0;
		}
		if ((ilport->ilport_avg_interval < STMF_AVG_ONLINE_INTERVAL) &&
		    (ilport->ilport_online_times >= 4)) {
			ret = STMF_FAILURE;
			ilport->ilport_flags |= ILPORT_FORCED_OFFLINE;
			stmf_trace(NULL, "stmf_ctl: too frequent request to "
			    "online the port");
			cmn_err(CE_WARN, "stmf_ctl: too frequent request to "
			    "online the port, set FORCED_OFFLINE now");
			goto stmf_ctl_lock_exit;
		}
		if (ilport->ilport_online_times > 0) {
			if (ilport->ilport_online_times == 1) {
				ilport->ilport_avg_interval = ddi_get_lbolt() -
				    ilport->ilport_last_online_clock;
			} else {
				ilport->ilport_avg_interval =
				    (ilport->ilport_avg_interval +
				    ddi_get_lbolt() -
				    ilport->ilport_last_online_clock) >> 1;
			}
		}
		ilport->ilport_last_online_clock = ddi_get_lbolt();
		ilport->ilport_online_times++;

		/*
		 * Submit online service request
		 */
		ilport->ilport_flags &= ~ILPORT_FORCED_OFFLINE;
		ilport->ilport_state = STMF_STATE_ONLINING;
		mutex_exit(&stmf_state.stmf_lock);
		stmf_svc_queue(cmd, obj, (stmf_state_change_info_t *)arg);
		break;

	case STMF_CMD_LPORT_ONLINE_COMPLETE:
		if (ilport->ilport_state != STMF_STATE_ONLINING) {
			ret = STMF_BADSTATE;
			goto stmf_ctl_lock_exit;
		}
		if (((stmf_change_status_t *)arg)->st_completion_status ==
		    STMF_SUCCESS) {
			ilport->ilport_state = STMF_STATE_ONLINE;
			mutex_exit(&stmf_state.stmf_lock);
			((stmf_local_port_t *)obj)->lport_ctl(
			    (stmf_local_port_t *)obj,
			    STMF_ACK_LPORT_ONLINE_COMPLETE, arg);
			mutex_enter(&stmf_state.stmf_lock);
		} else {
			ilport->ilport_state = STMF_STATE_OFFLINE;
		}
		ret = STMF_SUCCESS;
		goto stmf_ctl_lock_exit;

	case STMF_CMD_LPORT_OFFLINE:
		switch (ilport->ilport_state) {
			case STMF_STATE_ONLINE:
				ret = STMF_SUCCESS;
				break;
			case STMF_STATE_OFFLINE:
			case STMF_STATE_OFFLINING:
				ret = STMF_ALREADY;
				break;
			case STMF_STATE_ONLINING:
				ret = STMF_BUSY;
				break;
			default:
				ret = STMF_BADSTATE;
				break;
		}
		if (ret != STMF_SUCCESS)
			goto stmf_ctl_lock_exit;

		ilport->ilport_state = STMF_STATE_OFFLINING;
		mutex_exit(&stmf_state.stmf_lock);
		stmf_svc_queue(cmd, obj, (stmf_state_change_info_t *)arg);
		break;

	case STMF_CMD_LPORT_OFFLINE_COMPLETE:
		if (ilport->ilport_state != STMF_STATE_OFFLINING) {
			ret = STMF_BADSTATE;
			goto stmf_ctl_lock_exit;
		}
		if (((stmf_change_status_t *)arg)->st_completion_status ==
		    STMF_SUCCESS) {
			ilport->ilport_state = STMF_STATE_OFFLINE;
			mutex_exit(&stmf_state.stmf_lock);
			((stmf_local_port_t *)obj)->lport_ctl(
			    (stmf_local_port_t *)obj,
			    STMF_ACK_LPORT_OFFLINE_COMPLETE, arg);
			mutex_enter(&stmf_state.stmf_lock);
		} else {
			ilport->ilport_state = STMF_STATE_ONLINE;
		}
		mutex_exit(&stmf_state.stmf_lock);
		break;

	default:
		cmn_err(CE_WARN, "Invalid ctl cmd received %x", cmd);
		ret = STMF_INVALID_ARG;
		goto stmf_ctl_lock_exit;
	}

	return (STMF_SUCCESS);

stmf_ctl_lock_exit:;
	mutex_exit(&stmf_state.stmf_lock);
	return (ret);
}

/* ARGSUSED */
stmf_status_t
stmf_info_impl(uint32_t cmd, void *arg1, void *arg2, uint8_t *buf,
						uint32_t *bufsizep)
{
	return (STMF_NOT_SUPPORTED);
}

/* ARGSUSED */
stmf_status_t
stmf_info(uint32_t cmd, void *arg1, void *arg2, uint8_t *buf,
						uint32_t *bufsizep)
{
	uint32_t cl = SI_GET_CLASS(cmd);

	if (cl == SI_STMF) {
		return (stmf_info_impl(cmd, arg1, arg2, buf, bufsizep));
	}
	if (cl == SI_LPORT) {
		return (((stmf_local_port_t *)arg1)->lport_info(cmd, arg1,
		    arg2, buf, bufsizep));
	} else if (cl == SI_LU) {
		return (((stmf_lu_t *)arg1)->lu_info(cmd, arg1, arg2, buf,
		    bufsizep));
	}

	return (STMF_NOT_SUPPORTED);
}

/*
 * Used by port providers. pwwn is 8 byte wwn, sdid is the devid used by
 * stmf to register local ports. The ident should have 20 bytes in buffer
 * space to convert the wwn to "wwn.xxxxxxxxxxxxxxxx" string.
 */
void
stmf_wwn_to_devid_desc(scsi_devid_desc_t *sdid, uint8_t *wwn,
    uint8_t protocol_id)
{
	char wwn_str[20+1];

	sdid->protocol_id = protocol_id;
	sdid->piv = 1;
	sdid->code_set = CODE_SET_ASCII;
	sdid->association = ID_IS_TARGET_PORT;
	sdid->ident_length = 20;
	/* Convert wwn value to "wwn.XXXXXXXXXXXXXXXX" format */
	(void) snprintf(wwn_str, sizeof (wwn_str),
	    "wwn.%02X%02X%02X%02X%02X%02X%02X%02X",
	    wwn[0], wwn[1], wwn[2], wwn[3], wwn[4], wwn[5], wwn[6], wwn[7]);
	bcopy(wwn_str, (char *)sdid->ident, 20);
}


stmf_xfer_data_t *
stmf_prepare_tpgs_data(uint8_t ilu_alua)
{
	stmf_xfer_data_t *xd;
	stmf_i_local_port_t *ilport;
	uint8_t *p;
	uint32_t sz, asz, nports = 0, nports_standby = 0;

	mutex_enter(&stmf_state.stmf_lock);
	/* check if any ports are standby and create second group */
	for (ilport = stmf_state.stmf_ilportlist; ilport;
	    ilport = ilport->ilport_next) {
		if (ilport->ilport_standby == 1) {
			nports_standby++;
		} else {
			nports++;
		}
	}

	/* The spec only allows for 255 ports to be reported per group */
	nports = min(nports, 255);
	nports_standby = min(nports_standby, 255);
	sz = (nports * 4) + 12;
	if (nports_standby && ilu_alua) {
		sz += (nports_standby * 4) + 8;
	}
	asz = sz + sizeof (*xd) - 4;
	xd = (stmf_xfer_data_t *)kmem_zalloc(asz, KM_NOSLEEP);
	if (xd == NULL) {
		mutex_exit(&stmf_state.stmf_lock);
		return (NULL);
	}
	xd->alloc_size = asz;
	xd->size_left = sz;

	p = xd->buf;

	*((uint32_t *)p) = BE_32(sz - 4);
	p += 4;
	p[0] = 0x80;	/* PREF */
	p[1] = 5;	/* AO_SUP, S_SUP */
	if (stmf_state.stmf_alua_node == 1) {
		p[3] = 1;	/* Group 1 */
	} else {
		p[3] = 0;	/* Group 0 */
	}
	p[7] = nports & 0xff;
	p += 8;
	for (ilport = stmf_state.stmf_ilportlist; ilport;
	    ilport = ilport->ilport_next) {
		if (ilport->ilport_standby == 1) {
			continue;
		}
		((uint16_t *)p)[1] = BE_16(ilport->ilport_rtpid);
		p += 4;
	}
	if (nports_standby && ilu_alua) {
		p[0] = 0x02;	/* Non PREF, Standby */
		p[1] = 5;	/* AO_SUP, S_SUP */
		if (stmf_state.stmf_alua_node == 1) {
			p[3] = 0;	/* Group 0 */
		} else {
			p[3] = 1;	/* Group 1 */
		}
		p[7] = nports_standby & 0xff;
		p += 8;
		for (ilport = stmf_state.stmf_ilportlist; ilport;
		    ilport = ilport->ilport_next) {
			if (ilport->ilport_standby == 0) {
				continue;
			}
			((uint16_t *)p)[1] = BE_16(ilport->ilport_rtpid);
			p += 4;
		}
	}

	mutex_exit(&stmf_state.stmf_lock);

	return (xd);
}

struct scsi_devid_desc *
stmf_scsilib_get_devid_desc(uint16_t rtpid)
{
	scsi_devid_desc_t *devid = NULL;
	stmf_i_local_port_t *ilport;

	mutex_enter(&stmf_state.stmf_lock);

	for (ilport = stmf_state.stmf_ilportlist; ilport;
	    ilport = ilport->ilport_next) {
		if (ilport->ilport_rtpid == rtpid) {
			scsi_devid_desc_t *id = ilport->ilport_lport->lport_id;
			uint32_t id_sz = sizeof (scsi_devid_desc_t) +
			    id->ident_length;
			devid = (scsi_devid_desc_t *)kmem_zalloc(id_sz,
			    KM_NOSLEEP);
			if (devid != NULL) {
				bcopy(id, devid, id_sz);
			}
			break;
		}
	}

	mutex_exit(&stmf_state.stmf_lock);
	return (devid);
}

uint16_t
stmf_scsilib_get_lport_rtid(struct scsi_devid_desc *devid)
{
	stmf_i_local_port_t	*ilport;
	scsi_devid_desc_t	*id;
	uint16_t		rtpid = 0;

	mutex_enter(&stmf_state.stmf_lock);
	for (ilport = stmf_state.stmf_ilportlist; ilport;
	    ilport = ilport->ilport_next) {
		id = ilport->ilport_lport->lport_id;
		if ((devid->ident_length == id->ident_length) &&
		    (memcmp(devid->ident, id->ident, id->ident_length) == 0)) {
			rtpid = ilport->ilport_rtpid;
			break;
		}
	}
	mutex_exit(&stmf_state.stmf_lock);
	return (rtpid);
}

static uint16_t stmf_lu_id_gen_number = 0;

stmf_status_t
stmf_scsilib_uniq_lu_id(uint32_t company_id, scsi_devid_desc_t *lu_id)
{
	return (stmf_scsilib_uniq_lu_id2(company_id, 0, lu_id));
}

stmf_status_t
stmf_scsilib_uniq_lu_id2(uint32_t company_id, uint32_t host_id,
    scsi_devid_desc_t *lu_id)
{
	uint8_t *p;
	struct timeval32 timestamp32;
	uint32_t *t = (uint32_t *)&timestamp32;
	struct ether_addr mac;
	uint8_t *e = (uint8_t *)&mac;
	int hid = (int)host_id;
	uint16_t gen_number;

	if (company_id == COMPANY_ID_NONE)
		company_id = COMPANY_ID_SUN;

	if (lu_id->ident_length != 0x10)
		return (STMF_INVALID_ARG);

	p = (uint8_t *)lu_id;

	gen_number = atomic_inc_16_nv(&stmf_lu_id_gen_number);

	p[0] = 0xf1; p[1] = 3; p[2] = 0; p[3] = 0x10;
	p[4] = ((company_id >> 20) & 0xf) | 0x60;
	p[5] = (company_id >> 12) & 0xff;
	p[6] = (company_id >> 4) & 0xff;
	p[7] = (company_id << 4) & 0xf0;
	if (hid == 0 && !localetheraddr((struct ether_addr *)NULL, &mac)) {
		hid = BE_32((int)zone_get_hostid(NULL));
	}
	if (hid != 0) {
		e[0] = (hid >> 24) & 0xff;
		e[1] = (hid >> 16) & 0xff;
		e[2] = (hid >> 8) & 0xff;
		e[3] = hid & 0xff;
		e[4] = e[5] = 0;
	}
	bcopy(e, p+8, 6);
	uniqtime32(&timestamp32);
	*t = BE_32(*t);
	bcopy(t, p+14, 4);
	p[18] = (gen_number >> 8) & 0xff;
	p[19] = gen_number & 0xff;

	return (STMF_SUCCESS);
}

/*
 * saa is sense key, ASC, ASCQ
 */
void
stmf_scsilib_send_status(scsi_task_t *task, uint8_t st, uint32_t saa)
{
	uint8_t sd[18];
	task->task_scsi_status = st;
	if (st == 2) {
		bzero(sd, 18);
		sd[0] = 0x70;
		sd[2] = (saa >> 16) & 0xf;
		sd[7] = 10;
		sd[12] = (saa >> 8) & 0xff;
		sd[13] = saa & 0xff;
		task->task_sense_data = sd;
		task->task_sense_length = 18;
	} else {
		task->task_sense_data = NULL;
		task->task_sense_length = 0;
	}
	(void) stmf_send_scsi_status(task, STMF_IOF_LU_DONE);
}

uint32_t
stmf_scsilib_prepare_vpd_page83(scsi_task_t *task, uint8_t *page,
    uint32_t page_len, uint8_t byte0, uint32_t vpd_mask)
{
	uint8_t		*p = NULL;
	uint8_t		small_buf[32];
	uint32_t	sz = 0;
	uint32_t	n = 4;
	uint32_t	m = 0;
	uint32_t	last_bit = 0;

	if (page_len < 4)
		return (0);
	if (page_len > 65535)
		page_len = 65535;

	page[0] = byte0;
	page[1] = 0x83;

	/* CONSTCOND */
	while (1) {
		m += sz;
		if (sz && (page_len > n)) {
			uint32_t copysz;
			copysz = page_len > (n + sz) ? sz : page_len - n;
			bcopy(p, page + n, copysz);
			n += copysz;
		}
		vpd_mask &= ~last_bit;
		if (vpd_mask == 0)
			break;

		if (vpd_mask & STMF_VPD_LU_ID) {
			last_bit = STMF_VPD_LU_ID;
			sz = task->task_lu->lu_id->ident_length + 4;
			p = (uint8_t *)task->task_lu->lu_id;
			continue;
		} else if (vpd_mask & STMF_VPD_TARGET_ID) {
			last_bit = STMF_VPD_TARGET_ID;
			sz = task->task_lport->lport_id->ident_length + 4;
			p = (uint8_t *)task->task_lport->lport_id;
			continue;
		} else if (vpd_mask & STMF_VPD_TP_GROUP) {
			stmf_i_local_port_t *ilport;
			last_bit = STMF_VPD_TP_GROUP;
			p = small_buf;
			bzero(p, 8);
			p[0] = 1;
			p[1] = 0x15;
			p[3] = 4;
			ilport = (stmf_i_local_port_t *)
			    task->task_lport->lport_stmf_private;
			/*
			 * If we're in alua mode, group 1 contains all alua
			 * participating ports and all standby ports
			 * > 255. Otherwise, if we're in alua mode, any local
			 * ports (non standby/pppt) are also in group 1 if the
			 * alua node is 1. Otherwise the group is 0.
			 */
			if ((stmf_state.stmf_alua_state &&
			    (ilport->ilport_alua || ilport->ilport_standby) &&
			    ilport->ilport_rtpid > 255) ||
			    (stmf_state.stmf_alua_node == 1 &&
			    ilport->ilport_standby != 1)) {
				p[7] = 1;	/* Group 1 */
			}
			sz = 8;
			continue;
		} else if (vpd_mask & STMF_VPD_RELATIVE_TP_ID) {
			stmf_i_local_port_t *ilport;

			last_bit = STMF_VPD_RELATIVE_TP_ID;
			p = small_buf;
			bzero(p, 8);
			p[0] = 1;
			p[1] = 0x14;
			p[3] = 4;
			ilport = (stmf_i_local_port_t *)
			    task->task_lport->lport_stmf_private;
			p[6] = (ilport->ilport_rtpid >> 8) & 0xff;
			p[7] = ilport->ilport_rtpid & 0xff;
			sz = 8;
			continue;
		} else {
			cmn_err(CE_WARN, "Invalid vpd_mask");
			break;
		}
	}

	page[2] = (m >> 8) & 0xff;
	page[3] = m & 0xff;

	return (n);
}

void
stmf_scsilib_handle_report_tpgs(scsi_task_t *task, stmf_data_buf_t *dbuf)
{
	stmf_i_scsi_task_t *itask =
	    (stmf_i_scsi_task_t *)task->task_stmf_private;
	stmf_i_lu_t *ilu =
	    (stmf_i_lu_t *)task->task_lu->lu_stmf_private;
	stmf_xfer_data_t *xd;
	uint32_t sz, minsz;

	itask->itask_flags |= ITASK_DEFAULT_HANDLING;
	task->task_cmd_xfer_length =
	    ((((uint32_t)task->task_cdb[6]) << 24) |
	    (((uint32_t)task->task_cdb[7]) << 16) |
	    (((uint32_t)task->task_cdb[8]) << 8) |
	    ((uint32_t)task->task_cdb[9]));

	if (task->task_additional_flags &
	    TASK_AF_NO_EXPECTED_XFER_LENGTH) {
		task->task_expected_xfer_length =
		    task->task_cmd_xfer_length;
	}

	if (task->task_cmd_xfer_length == 0) {
		stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}
	if (task->task_cmd_xfer_length < 4) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}

	sz = min(task->task_expected_xfer_length,
	    task->task_cmd_xfer_length);

	xd = stmf_prepare_tpgs_data(ilu->ilu_alua);

	if (xd == NULL) {
		stmf_abort(STMF_QUEUE_TASK_ABORT, task,
		    STMF_ALLOC_FAILURE, NULL);
		return;
	}

	sz = min(sz, xd->size_left);
	xd->size_left = sz;
	minsz = min(512, sz);

	if (dbuf == NULL)
		dbuf = stmf_alloc_dbuf(task, sz, &minsz, 0);
	if (dbuf == NULL) {
		kmem_free(xd, xd->alloc_size);
		stmf_abort(STMF_QUEUE_TASK_ABORT, task,
		    STMF_ALLOC_FAILURE, NULL);
		return;
	}
	dbuf->db_lu_private = xd;
	stmf_xd_to_dbuf(dbuf, 1);

	dbuf->db_flags = DB_DIRECTION_TO_RPORT;
	(void) stmf_xfer_data(task, dbuf, 0);

}

void
stmf_scsilib_handle_task_mgmt(scsi_task_t *task)
{

	switch (task->task_mgmt_function) {
	/*
	 * For now we will abort all I/Os on the LU in case of ABORT_TASK_SET
	 * and ABORT_TASK. But unlike LUN_RESET we will not reset LU state
	 * in these cases. This needs to be changed to abort only the required
	 * set.
	 */
	case TM_ABORT_TASK:
	case TM_ABORT_TASK_SET:
	case TM_CLEAR_TASK_SET:
	case TM_LUN_RESET:
		stmf_handle_lun_reset(task);
		/* issue the reset to the proxy node as well */
		if (stmf_state.stmf_alua_state == 1) {
			(void) stmf_proxy_scsi_cmd(task, NULL);
		}
		return;
	case TM_TARGET_RESET:
	case TM_TARGET_COLD_RESET:
	case TM_TARGET_WARM_RESET:
		stmf_handle_target_reset(task);
		return;
	default:
		/* We dont support this task mgmt function */
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CMD_IU);
		return;
	}
}

void
stmf_handle_lun_reset(scsi_task_t *task)
{
	stmf_i_scsi_task_t *itask;
	stmf_i_lu_t *ilu;

	itask = (stmf_i_scsi_task_t *)task->task_stmf_private;
	ilu = (stmf_i_lu_t *)task->task_lu->lu_stmf_private;

	/*
	 * To sync with target reset, grab this lock. The LU is not going
	 * anywhere as there is atleast one task pending (this task).
	 */
	mutex_enter(&stmf_state.stmf_lock);

	if (ilu->ilu_flags & ILU_RESET_ACTIVE) {
		mutex_exit(&stmf_state.stmf_lock);
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_OPERATION_IN_PROGRESS);
		return;
	}
	atomic_or_32(&ilu->ilu_flags, ILU_RESET_ACTIVE);
	mutex_exit(&stmf_state.stmf_lock);

	/*
	 * Mark this task as the one causing LU reset so that we know who
	 * was responsible for setting the ILU_RESET_ACTIVE. In case this
	 * task itself gets aborted, we will clear ILU_RESET_ACTIVE.
	 */
	itask->itask_flags |= ITASK_DEFAULT_HANDLING | ITASK_CAUSING_LU_RESET;

	/* Initiatiate abort on all commands on this LU except this one */
	stmf_abort(STMF_QUEUE_ABORT_LU, task, STMF_ABORTED, task->task_lu);

	/* Start polling on this task */
	if (stmf_task_poll_lu(task, ITASK_DEFAULT_POLL_TIMEOUT)
	    != STMF_SUCCESS) {
		stmf_abort(STMF_QUEUE_TASK_ABORT, task, STMF_ALLOC_FAILURE,
		    NULL);
		return;
	}
}

void
stmf_handle_target_reset(scsi_task_t *task)
{
	stmf_i_scsi_task_t *itask;
	stmf_i_lu_t *ilu;
	stmf_i_scsi_session_t *iss;
	stmf_lun_map_t *lm;
	stmf_lun_map_ent_t *lm_ent;
	int i, lf;

	itask = (stmf_i_scsi_task_t *)task->task_stmf_private;
	iss = (stmf_i_scsi_session_t *)task->task_session->ss_stmf_private;
	ilu = (stmf_i_lu_t *)task->task_lu->lu_stmf_private;

	/*
	 * To sync with LUN reset, grab this lock. The session is not going
	 * anywhere as there is atleast one task pending (this task).
	 */
	mutex_enter(&stmf_state.stmf_lock);

	/* Grab the session lock as a writer to prevent any changes in it */
	rw_enter(iss->iss_lockp, RW_WRITER);

	if (iss->iss_flags & ISS_RESET_ACTIVE) {
		rw_exit(iss->iss_lockp);
		mutex_exit(&stmf_state.stmf_lock);
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_OPERATION_IN_PROGRESS);
		return;
	}
	atomic_or_32(&iss->iss_flags, ISS_RESET_ACTIVE);

	/*
	 * Now go through each LUN in this session and make sure all of them
	 * can be reset.
	 */
	lm = iss->iss_sm;
	for (i = 0, lf = 0; i < lm->lm_nentries; i++) {
		if (lm->lm_plus[i] == NULL)
			continue;
		lf++;
		lm_ent = (stmf_lun_map_ent_t *)lm->lm_plus[i];
		ilu = (stmf_i_lu_t *)(lm_ent->ent_lu->lu_stmf_private);
		if (ilu->ilu_flags & ILU_RESET_ACTIVE) {
			atomic_and_32(&iss->iss_flags, ~ISS_RESET_ACTIVE);
			rw_exit(iss->iss_lockp);
			mutex_exit(&stmf_state.stmf_lock);
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_OPERATION_IN_PROGRESS);
			return;
		}
	}
	if (lf == 0) {
		/* No luns in this session */
		atomic_and_32(&iss->iss_flags, ~ISS_RESET_ACTIVE);
		rw_exit(iss->iss_lockp);
		mutex_exit(&stmf_state.stmf_lock);
		stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}

	/* ok, start the damage */
	itask->itask_flags |= ITASK_DEFAULT_HANDLING |
	    ITASK_CAUSING_TARGET_RESET;
	for (i = 0; i < lm->lm_nentries; i++) {
		if (lm->lm_plus[i] == NULL)
			continue;
		lm_ent = (stmf_lun_map_ent_t *)lm->lm_plus[i];
		ilu = (stmf_i_lu_t *)(lm_ent->ent_lu->lu_stmf_private);
		atomic_or_32(&ilu->ilu_flags, ILU_RESET_ACTIVE);
	}

	for (i = 0; i < lm->lm_nentries; i++) {
		if (lm->lm_plus[i] == NULL)
			continue;
		lm_ent = (stmf_lun_map_ent_t *)lm->lm_plus[i];
		stmf_abort(STMF_QUEUE_ABORT_LU, task, STMF_ABORTED,
		    lm_ent->ent_lu);
	}

	rw_exit(iss->iss_lockp);
	mutex_exit(&stmf_state.stmf_lock);

	/* Start polling on this task */
	if (stmf_task_poll_lu(task, ITASK_DEFAULT_POLL_TIMEOUT)
	    != STMF_SUCCESS) {
		stmf_abort(STMF_QUEUE_TASK_ABORT, task, STMF_ALLOC_FAILURE,
		    NULL);
		return;
	}
}

int
stmf_handle_cmd_during_ic(stmf_i_scsi_task_t *itask)
{
	scsi_task_t *task = itask->itask_task;
	stmf_i_scsi_session_t *iss = (stmf_i_scsi_session_t *)
	    task->task_session->ss_stmf_private;

	rw_enter(iss->iss_lockp, RW_WRITER);
	if (((iss->iss_flags & ISS_LUN_INVENTORY_CHANGED) == 0) ||
	    (task->task_cdb[0] == SCMD_INQUIRY)) {
		rw_exit(iss->iss_lockp);
		return (0);
	}
	atomic_and_32(&iss->iss_flags,
	    ~(ISS_LUN_INVENTORY_CHANGED | ISS_GOT_INITIAL_LUNS));
	rw_exit(iss->iss_lockp);

	if (task->task_cdb[0] == SCMD_REPORT_LUNS) {
		return (0);
	}
	stmf_scsilib_send_status(task, STATUS_CHECK,
	    STMF_SAA_REPORT_LUN_DATA_HAS_CHANGED);
	return (1);
}

void
stmf_worker_init()
{
	uint32_t i;

	/* Make local copy of global tunables */
	stmf_i_max_nworkers = stmf_max_nworkers;
	stmf_i_min_nworkers = stmf_min_nworkers;

	ASSERT(stmf_workers == NULL);
	if (stmf_i_min_nworkers < 4) {
		stmf_i_min_nworkers = 4;
	}
	if (stmf_i_max_nworkers < stmf_i_min_nworkers) {
		stmf_i_max_nworkers = stmf_i_min_nworkers;
	}
	stmf_workers = (stmf_worker_t *)kmem_zalloc(
	    sizeof (stmf_worker_t) * stmf_i_max_nworkers, KM_SLEEP);
	for (i = 0; i < stmf_i_max_nworkers; i++) {
		stmf_worker_t *w = &stmf_workers[i];
		mutex_init(&w->worker_lock, NULL, MUTEX_DRIVER, NULL);
		cv_init(&w->worker_cv, NULL, CV_DRIVER, NULL);
	}
	stmf_worker_mgmt_delay = drv_usectohz(20 * 1000);
	stmf_workers_state = STMF_WORKERS_ENABLED;

	/* Workers will be started by stmf_worker_mgmt() */

	/* Lets wait for atleast one worker to start */
	while (stmf_nworkers_cur == 0)
		delay(drv_usectohz(20 * 1000));
	stmf_worker_mgmt_delay = drv_usectohz(3 * 1000 * 1000);
}

stmf_status_t
stmf_worker_fini()
{
	int i;
	clock_t sb;

	if (stmf_workers_state == STMF_WORKERS_DISABLED)
		return (STMF_SUCCESS);
	ASSERT(stmf_workers);
	stmf_workers_state = STMF_WORKERS_DISABLED;
	stmf_worker_mgmt_delay = drv_usectohz(20 * 1000);
	cv_signal(&stmf_state.stmf_cv);

	sb = ddi_get_lbolt() + drv_usectohz(10 * 1000 * 1000);
	/* Wait for all the threads to die */
	while (stmf_nworkers_cur != 0) {
		if (ddi_get_lbolt() > sb) {
			stmf_workers_state = STMF_WORKERS_ENABLED;
			return (STMF_BUSY);
		}
		delay(drv_usectohz(100 * 1000));
	}
	for (i = 0; i < stmf_i_max_nworkers; i++) {
		stmf_worker_t *w = &stmf_workers[i];
		mutex_destroy(&w->worker_lock);
		cv_destroy(&w->worker_cv);
	}
	kmem_free(stmf_workers, sizeof (stmf_worker_t) * stmf_i_max_nworkers);
	stmf_workers = NULL;

	return (STMF_SUCCESS);
}

void
stmf_worker_task(void *arg)
{
	stmf_worker_t *w;
	stmf_i_scsi_session_t *iss;
	scsi_task_t *task;
	stmf_i_scsi_task_t *itask;
	stmf_data_buf_t *dbuf;
	stmf_lu_t *lu;
	clock_t wait_timer = 0;
	clock_t wait_ticks, wait_delta = 0;
	uint32_t old, new;
	uint8_t curcmd;
	uint8_t abort_free;
	uint8_t wait_queue;
	uint8_t dec_qdepth;

	w = (stmf_worker_t *)arg;
	wait_ticks = drv_usectohz(10000);

	DTRACE_PROBE1(worker__create, stmf_worker_t, w);
	mutex_enter(&w->worker_lock);
	w->worker_flags |= STMF_WORKER_STARTED | STMF_WORKER_ACTIVE;
stmf_worker_loop:;
	if ((w->worker_ref_count == 0) &&
	    (w->worker_flags & STMF_WORKER_TERMINATE)) {
		w->worker_flags &= ~(STMF_WORKER_STARTED |
		    STMF_WORKER_ACTIVE | STMF_WORKER_TERMINATE);
		w->worker_tid = NULL;
		mutex_exit(&w->worker_lock);
		DTRACE_PROBE1(worker__destroy, stmf_worker_t, w);
		thread_exit();
	}
	/* CONSTCOND */
	while (1) {
		dec_qdepth = 0;
		if (wait_timer && (ddi_get_lbolt() >= wait_timer)) {
			wait_timer = 0;
			wait_delta = 0;
			if (w->worker_wait_head) {
				ASSERT(w->worker_wait_tail);
				if (w->worker_task_head == NULL)
					w->worker_task_head =
					    w->worker_wait_head;
				else
					w->worker_task_tail->itask_worker_next =
					    w->worker_wait_head;
				w->worker_task_tail = w->worker_wait_tail;
				w->worker_wait_head = w->worker_wait_tail =
				    NULL;
			}
		}
		if ((itask = w->worker_task_head) == NULL) {
			break;
		}
		task = itask->itask_task;
		DTRACE_PROBE2(worker__active, stmf_worker_t, w,
		    scsi_task_t *, task);
		w->worker_task_head = itask->itask_worker_next;
		if (w->worker_task_head == NULL)
			w->worker_task_tail = NULL;

		wait_queue = 0;
		abort_free = 0;
		if (itask->itask_ncmds > 0) {
			curcmd = itask->itask_cmd_stack[itask->itask_ncmds - 1];
		} else {
			ASSERT(itask->itask_flags & ITASK_BEING_ABORTED);
		}
		do {
			old = itask->itask_flags;
			if (old & ITASK_BEING_ABORTED) {
				itask->itask_ncmds = 1;
				curcmd = itask->itask_cmd_stack[0] =
				    ITASK_CMD_ABORT;
				goto out_itask_flag_loop;
			} else if ((curcmd & ITASK_CMD_MASK) ==
			    ITASK_CMD_NEW_TASK) {
				/*
				 * set ITASK_KSTAT_IN_RUNQ, this flag
				 * will not reset until task completed
				 */
				new = old | ITASK_KNOWN_TO_LU |
				    ITASK_KSTAT_IN_RUNQ;
			} else {
				goto out_itask_flag_loop;
			}
		} while (atomic_cas_32(&itask->itask_flags, old, new) != old);

out_itask_flag_loop:

		/*
		 * Decide if this task needs to go to a queue and/or if
		 * we can decrement the itask_cmd_stack.
		 */
		if (curcmd == ITASK_CMD_ABORT) {
			if (itask->itask_flags & (ITASK_KNOWN_TO_LU |
			    ITASK_KNOWN_TO_TGT_PORT)) {
				wait_queue = 1;
			} else {
				abort_free = 1;
			}
		} else if ((curcmd & ITASK_CMD_POLL) &&
		    (itask->itask_poll_timeout > ddi_get_lbolt())) {
			wait_queue = 1;
		}

		if (wait_queue) {
			itask->itask_worker_next = NULL;
			if (w->worker_wait_tail) {
				w->worker_wait_tail->itask_worker_next = itask;
			} else {
				w->worker_wait_head = itask;
			}
			w->worker_wait_tail = itask;
			if (wait_timer == 0) {
				wait_timer = ddi_get_lbolt() + wait_ticks;
				wait_delta = wait_ticks;
			}
		} else if ((--(itask->itask_ncmds)) != 0) {
			itask->itask_worker_next = NULL;
			if (w->worker_task_tail) {
				w->worker_task_tail->itask_worker_next = itask;
			} else {
				w->worker_task_head = itask;
			}
			w->worker_task_tail = itask;
		} else {
			atomic_and_32(&itask->itask_flags,
			    ~ITASK_IN_WORKER_QUEUE);
			/*
			 * This is where the queue depth should go down by
			 * one but we delay that on purpose to account for
			 * the call into the provider. The actual decrement
			 * happens after the worker has done its job.
			 */
			dec_qdepth = 1;
			itask->itask_waitq_time +=
			    gethrtime() - itask->itask_waitq_enter_timestamp;
		}

		/* We made it here means we are going to call LU */
		if ((itask->itask_flags & ITASK_DEFAULT_HANDLING) == 0)
			lu = task->task_lu;
		else
			lu = dlun0;
		dbuf = itask->itask_dbufs[ITASK_CMD_BUF_NDX(curcmd)];
		mutex_exit(&w->worker_lock);
		curcmd &= ITASK_CMD_MASK;
		stmf_task_audit(itask, TE_PROCESS_CMD, curcmd, dbuf);
		switch (curcmd) {
		case ITASK_CMD_NEW_TASK:
			iss = (stmf_i_scsi_session_t *)
			    task->task_session->ss_stmf_private;
			stmf_itl_lu_new_task(itask);
			if (iss->iss_flags & ISS_LUN_INVENTORY_CHANGED) {
				if (stmf_handle_cmd_during_ic(itask))
					break;
			}
#ifdef	DEBUG
			if (stmf_drop_task_counter > 0) {
				if (atomic_dec_32_nv(&stmf_drop_task_counter)
				    == 1)
					break;
			}
#endif
			DTRACE_PROBE1(scsi__task__start, scsi_task_t *, task);
			lu->lu_new_task(task, dbuf);
			break;
		case ITASK_CMD_DATA_XFER_DONE:
			lu->lu_dbuf_xfer_done(task, dbuf);
			break;
		case ITASK_CMD_STATUS_DONE:
			lu->lu_send_status_done(task);
			break;
		case ITASK_CMD_ABORT:
			if (abort_free) {
				stmf_task_free(task);
			} else {
				stmf_do_task_abort(task);
			}
			break;
		case ITASK_CMD_POLL_LU:
			if (!wait_queue) {
				lu->lu_task_poll(task);
			}
			break;
		case ITASK_CMD_POLL_LPORT:
			if (!wait_queue)
				task->task_lport->lport_task_poll(task);
			break;
		case ITASK_CMD_SEND_STATUS:
		/* case ITASK_CMD_XFER_DATA: */
			break;
		}
		mutex_enter(&w->worker_lock);
		if (dec_qdepth) {
			w->worker_queue_depth--;
		}
	}
	if ((w->worker_flags & STMF_WORKER_TERMINATE) && (wait_timer == 0)) {
		if (w->worker_ref_count == 0)
			goto stmf_worker_loop;
		else {
			wait_timer = ddi_get_lbolt() + 1;
			wait_delta = 1;
		}
	}
	w->worker_flags &= ~STMF_WORKER_ACTIVE;
	if (wait_timer) {
		DTRACE_PROBE1(worker__timed__sleep, stmf_worker_t, w);
		(void) cv_reltimedwait(&w->worker_cv, &w->worker_lock,
		    wait_delta, TR_CLOCK_TICK);
	} else {
		DTRACE_PROBE1(worker__sleep, stmf_worker_t, w);
		cv_wait(&w->worker_cv, &w->worker_lock);
	}
	DTRACE_PROBE1(worker__wakeup, stmf_worker_t, w);
	w->worker_flags |= STMF_WORKER_ACTIVE;
	goto stmf_worker_loop;
}

void
stmf_worker_mgmt()
{
	int i;
	int workers_needed;
	uint32_t qd;
	clock_t tps, d = 0;
	uint32_t cur_max_ntasks = 0;
	stmf_worker_t *w;

	/* Check if we are trying to increase the # of threads */
	for (i = stmf_nworkers_cur; i < stmf_nworkers_needed; i++) {
		if (stmf_workers[i].worker_flags & STMF_WORKER_STARTED) {
			stmf_nworkers_cur++;
			stmf_nworkers_accepting_cmds++;
		} else {
			/* Wait for transition to complete */
			return;
		}
	}
	/* Check if we are trying to decrease the # of workers */
	for (i = (stmf_nworkers_cur - 1); i >= stmf_nworkers_needed; i--) {
		if ((stmf_workers[i].worker_flags & STMF_WORKER_STARTED) == 0) {
			stmf_nworkers_cur--;
			/*
			 * stmf_nworkers_accepting_cmds has already been
			 * updated by the request to reduce the # of workers.
			 */
		} else {
			/* Wait for transition to complete */
			return;
		}
	}
	/* Check if we are being asked to quit */
	if (stmf_workers_state != STMF_WORKERS_ENABLED) {
		if (stmf_nworkers_cur) {
			workers_needed = 0;
			goto worker_mgmt_trigger_change;
		}
		return;
	}
	/* Check if we are starting */
	if (stmf_nworkers_cur < stmf_i_min_nworkers) {
		workers_needed = stmf_i_min_nworkers;
		goto worker_mgmt_trigger_change;
	}

	tps = drv_usectohz(1 * 1000 * 1000);
	if ((stmf_wm_last != 0) &&
	    ((d = ddi_get_lbolt() - stmf_wm_last) > tps)) {
		qd = 0;
		for (i = 0; i < stmf_nworkers_accepting_cmds; i++) {
			qd += stmf_workers[i].worker_max_qdepth_pu;
			stmf_workers[i].worker_max_qdepth_pu = 0;
			if (stmf_workers[i].worker_max_sys_qdepth_pu >
			    cur_max_ntasks) {
				cur_max_ntasks =
				    stmf_workers[i].worker_max_sys_qdepth_pu;
			}
			stmf_workers[i].worker_max_sys_qdepth_pu = 0;
		}
	}
	stmf_wm_last = ddi_get_lbolt();
	if (d <= tps) {
		/* still ramping up */
		return;
	}
	/* max qdepth cannot be more than max tasks */
	if (qd > cur_max_ntasks)
		qd = cur_max_ntasks;

	/* See if we have more workers */
	if (qd < stmf_nworkers_accepting_cmds) {
		/*
		 * Since we dont reduce the worker count right away, monitor
		 * the highest load during the scale_down_delay.
		 */
		if (qd > stmf_worker_scale_down_qd)
			stmf_worker_scale_down_qd = qd;
		if (stmf_worker_scale_down_timer == 0) {
			stmf_worker_scale_down_timer = ddi_get_lbolt() +
			    drv_usectohz(stmf_worker_scale_down_delay *
			    1000 * 1000);
			return;
		}
		if (ddi_get_lbolt() < stmf_worker_scale_down_timer) {
			return;
		}
		/* Its time to reduce the workers */
		if (stmf_worker_scale_down_qd < stmf_i_min_nworkers)
			stmf_worker_scale_down_qd = stmf_i_min_nworkers;
		if (stmf_worker_scale_down_qd > stmf_i_max_nworkers)
			stmf_worker_scale_down_qd = stmf_i_max_nworkers;
		if (stmf_worker_scale_down_qd == stmf_nworkers_cur)
			return;
		workers_needed = stmf_worker_scale_down_qd;
		stmf_worker_scale_down_qd = 0;
		goto worker_mgmt_trigger_change;
	}
	stmf_worker_scale_down_qd = 0;
	stmf_worker_scale_down_timer = 0;
	if (qd > stmf_i_max_nworkers)
		qd = stmf_i_max_nworkers;
	if (qd < stmf_i_min_nworkers)
		qd = stmf_i_min_nworkers;
	if (qd == stmf_nworkers_cur)
		return;
	workers_needed = qd;
	goto worker_mgmt_trigger_change;

	/* NOTREACHED */
	return;

worker_mgmt_trigger_change:
	ASSERT(workers_needed != stmf_nworkers_cur);
	if (workers_needed > stmf_nworkers_cur) {
		stmf_nworkers_needed = workers_needed;
		for (i = stmf_nworkers_cur; i < workers_needed; i++) {
			w = &stmf_workers[i];
			w->worker_tid = thread_create(NULL, 0, stmf_worker_task,
			    (void *)&stmf_workers[i], 0, &p0, TS_RUN,
			    minclsyspri);
		}
		return;
	}
	/* At this point we know that we are decreasing the # of workers */
	stmf_nworkers_accepting_cmds = workers_needed;
	stmf_nworkers_needed = workers_needed;
	/* Signal the workers that its time to quit */
	for (i = (stmf_nworkers_cur - 1); i >= stmf_nworkers_needed; i--) {
		w = &stmf_workers[i];
		ASSERT(w && (w->worker_flags & STMF_WORKER_STARTED));
		mutex_enter(&w->worker_lock);
		w->worker_flags |= STMF_WORKER_TERMINATE;
		if ((w->worker_flags & STMF_WORKER_ACTIVE) == 0)
			cv_signal(&w->worker_cv);
		mutex_exit(&w->worker_lock);
	}
}

/*
 * Fills out a dbuf from stmf_xfer_data_t (contained in the db_lu_private).
 * If all the data has been filled out, frees the xd and makes
 * db_lu_private NULL.
 */
void
stmf_xd_to_dbuf(stmf_data_buf_t *dbuf, int set_rel_off)
{
	stmf_xfer_data_t *xd;
	uint8_t *p;
	int i;
	uint32_t s;

	xd = (stmf_xfer_data_t *)dbuf->db_lu_private;
	dbuf->db_data_size = 0;
	if (set_rel_off)
		dbuf->db_relative_offset = xd->size_done;
	for (i = 0; i < dbuf->db_sglist_length; i++) {
		s = min(xd->size_left, dbuf->db_sglist[i].seg_length);
		p = &xd->buf[xd->size_done];
		bcopy(p, dbuf->db_sglist[i].seg_addr, s);
		xd->size_left -= s;
		xd->size_done += s;
		dbuf->db_data_size += s;
		if (xd->size_left == 0) {
			kmem_free(xd, xd->alloc_size);
			dbuf->db_lu_private = NULL;
			return;
		}
	}
}

/* ARGSUSED */
stmf_status_t
stmf_dlun0_task_alloc(scsi_task_t *task)
{
	return (STMF_SUCCESS);
}

void
stmf_dlun0_new_task(scsi_task_t *task, stmf_data_buf_t *dbuf)
{
	uint8_t *cdbp = (uint8_t *)&task->task_cdb[0];
	stmf_i_scsi_session_t *iss;
	uint32_t sz, minsz;
	uint8_t *p;
	stmf_xfer_data_t *xd;
	uint8_t inq_page_length = 31;

	if (task->task_mgmt_function) {
		stmf_scsilib_handle_task_mgmt(task);
		return;
	}

	switch (cdbp[0]) {
	case SCMD_INQUIRY:
		/*
		 * Basic protocol checks.  In addition, only reply to
		 * standard inquiry.  Otherwise, the LU provider needs
		 * to respond.
		 */

		if (cdbp[2] || (cdbp[1] & 1) || cdbp[5]) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
			return;
		}

		task->task_cmd_xfer_length =
		    (((uint32_t)cdbp[3]) << 8) | cdbp[4];

		if (task->task_additional_flags &
		    TASK_AF_NO_EXPECTED_XFER_LENGTH) {
			task->task_expected_xfer_length =
			    task->task_cmd_xfer_length;
		}

		sz = min(task->task_expected_xfer_length,
		    min(36, task->task_cmd_xfer_length));
		minsz = 36;

		if (sz == 0) {
			stmf_scsilib_send_status(task, STATUS_GOOD, 0);
			return;
		}

		if (dbuf && (dbuf->db_sglist[0].seg_length < 36)) {
			/*
			 * Ignore any preallocated dbuf if the size is less
			 * than 36. It will be freed during the task_free.
			 */
			dbuf = NULL;
		}
		if (dbuf == NULL)
			dbuf = stmf_alloc_dbuf(task, minsz, &minsz, 0);
		if ((dbuf == NULL) || (dbuf->db_sglist[0].seg_length < sz)) {
			stmf_abort(STMF_QUEUE_TASK_ABORT, task,
			    STMF_ALLOC_FAILURE, NULL);
			return;
		}
		dbuf->db_lu_private = NULL;

		p = dbuf->db_sglist[0].seg_addr;

		/*
		 * Standard inquiry handling only.
		 */

		bzero(p, inq_page_length + 5);

		p[0] = DPQ_SUPPORTED | DTYPE_UNKNOWN;
		p[2] = 5;
		p[3] = 0x12;
		p[4] = inq_page_length;
		p[6] = 0x80;

		(void) strncpy((char *)p+8, "SUN     ", 8);
		(void) strncpy((char *)p+16, "COMSTAR	       ", 16);
		(void) strncpy((char *)p+32, "1.0 ", 4);

		dbuf->db_data_size = sz;
		dbuf->db_relative_offset = 0;
		dbuf->db_flags = DB_DIRECTION_TO_RPORT;
		(void) stmf_xfer_data(task, dbuf, 0);

		return;

	case SCMD_REPORT_LUNS:
		task->task_cmd_xfer_length =
		    ((((uint32_t)task->task_cdb[6]) << 24) |
		    (((uint32_t)task->task_cdb[7]) << 16) |
		    (((uint32_t)task->task_cdb[8]) << 8) |
		    ((uint32_t)task->task_cdb[9]));

		if (task->task_additional_flags &
		    TASK_AF_NO_EXPECTED_XFER_LENGTH) {
			task->task_expected_xfer_length =
			    task->task_cmd_xfer_length;
		}

		sz = min(task->task_expected_xfer_length,
		    task->task_cmd_xfer_length);

		if (sz < 16) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
			return;
		}

		iss = (stmf_i_scsi_session_t *)
		    task->task_session->ss_stmf_private;
		rw_enter(iss->iss_lockp, RW_WRITER);
		xd = stmf_session_prepare_report_lun_data(iss->iss_sm);
		rw_exit(iss->iss_lockp);

		if (xd == NULL) {
			stmf_abort(STMF_QUEUE_TASK_ABORT, task,
			    STMF_ALLOC_FAILURE, NULL);
			return;
		}

		sz = min(sz, xd->size_left);
		xd->size_left = sz;
		minsz = min(512, sz);

		if (dbuf == NULL)
			dbuf = stmf_alloc_dbuf(task, sz, &minsz, 0);
		if (dbuf == NULL) {
			kmem_free(xd, xd->alloc_size);
			stmf_abort(STMF_QUEUE_TASK_ABORT, task,
			    STMF_ALLOC_FAILURE, NULL);
			return;
		}
		dbuf->db_lu_private = xd;
		stmf_xd_to_dbuf(dbuf, 1);

		atomic_and_32(&iss->iss_flags,
		    ~(ISS_LUN_INVENTORY_CHANGED | ISS_GOT_INITIAL_LUNS));
		dbuf->db_flags = DB_DIRECTION_TO_RPORT;
		(void) stmf_xfer_data(task, dbuf, 0);
		return;
	}

	stmf_scsilib_send_status(task, STATUS_CHECK, STMF_SAA_INVALID_OPCODE);
}

void
stmf_dlun0_dbuf_done(scsi_task_t *task, stmf_data_buf_t *dbuf)
{
	stmf_i_scsi_task_t *itask =
	    (stmf_i_scsi_task_t *)task->task_stmf_private;

	if (dbuf->db_xfer_status != STMF_SUCCESS) {
		stmf_abort(STMF_QUEUE_TASK_ABORT, task,
		    dbuf->db_xfer_status, NULL);
		return;
	}
	task->task_nbytes_transferred += dbuf->db_data_size;
	if (dbuf->db_lu_private) {
		/* There is more */
		stmf_xd_to_dbuf(dbuf, 1);
		(void) stmf_xfer_data(task, dbuf, 0);
		return;
	}

	stmf_free_dbuf(task, dbuf);
	/*
	 * If this is a proxy task, it will need to be completed from the
	 * proxy port provider. This message lets pppt know that the xfer
	 * is complete. When we receive the status from pppt, we will
	 * then relay that status back to the lport.
	 */
	if (itask->itask_flags & ITASK_PROXY_TASK) {
		stmf_ic_msg_t *ic_xfer_done_msg = NULL;
		stmf_status_t ic_ret = STMF_FAILURE;
		uint64_t session_msg_id;
		mutex_enter(&stmf_state.stmf_lock);
		session_msg_id = stmf_proxy_msg_id++;
		mutex_exit(&stmf_state.stmf_lock);
		/* send xfer done status to pppt */
		ic_xfer_done_msg = ic_scsi_data_xfer_done_msg_alloc(
		    itask->itask_proxy_msg_id,
		    task->task_session->ss_session_id,
		    STMF_SUCCESS, session_msg_id);
		if (ic_xfer_done_msg) {
			ic_ret = ic_tx_msg(ic_xfer_done_msg);
			if (ic_ret != STMF_IC_MSG_SUCCESS) {
				cmn_err(CE_WARN, "unable to xmit session msg");
			}
		}
		/* task will be completed from pppt */
		return;
	}
	stmf_scsilib_send_status(task, STATUS_GOOD, 0);
}

/* ARGSUSED */
void
stmf_dlun0_status_done(scsi_task_t *task)
{
}

/* ARGSUSED */
void
stmf_dlun0_task_free(scsi_task_t *task)
{
}

/* ARGSUSED */
stmf_status_t
stmf_dlun0_abort(struct stmf_lu *lu, int abort_cmd, void *arg, uint32_t flags)
{
	scsi_task_t *task = (scsi_task_t *)arg;
	stmf_i_scsi_task_t *itask =
	    (stmf_i_scsi_task_t *)task->task_stmf_private;
	stmf_i_lu_t *ilu = (stmf_i_lu_t *)task->task_lu->lu_stmf_private;
	int i;
	uint8_t map;

	if ((task->task_mgmt_function) && (itask->itask_flags &
	    (ITASK_CAUSING_LU_RESET | ITASK_CAUSING_TARGET_RESET))) {
		switch (task->task_mgmt_function) {
		case TM_ABORT_TASK:
		case TM_ABORT_TASK_SET:
		case TM_CLEAR_TASK_SET:
		case TM_LUN_RESET:
			atomic_and_32(&ilu->ilu_flags, ~ILU_RESET_ACTIVE);
			break;
		case TM_TARGET_RESET:
		case TM_TARGET_COLD_RESET:
		case TM_TARGET_WARM_RESET:
			stmf_abort_target_reset(task);
			break;
		}
		return (STMF_ABORT_SUCCESS);
	}

	/*
	 * OK so its not a task mgmt. Make sure we free any xd sitting
	 * inside any dbuf.
	 */
	if ((map = itask->itask_allocated_buf_map) != 0) {
		for (i = 0; i < 4; i++) {
			if ((map & 1) &&
			    ((itask->itask_dbufs[i])->db_lu_private)) {
				stmf_xfer_data_t *xd;
				stmf_data_buf_t *dbuf;

				dbuf = itask->itask_dbufs[i];
				xd = (stmf_xfer_data_t *)dbuf->db_lu_private;
				dbuf->db_lu_private = NULL;
				kmem_free(xd, xd->alloc_size);
			}
			map >>= 1;
		}
	}
	return (STMF_ABORT_SUCCESS);
}

void
stmf_dlun0_task_poll(struct scsi_task *task)
{
	/* Right now we only do this for handling task management functions */
	ASSERT(task->task_mgmt_function);

	switch (task->task_mgmt_function) {
	case TM_ABORT_TASK:
	case TM_ABORT_TASK_SET:
	case TM_CLEAR_TASK_SET:
	case TM_LUN_RESET:
		(void) stmf_lun_reset_poll(task->task_lu, task, 0);
		return;
	case TM_TARGET_RESET:
	case TM_TARGET_COLD_RESET:
	case TM_TARGET_WARM_RESET:
		stmf_target_reset_poll(task);
		return;
	}
}

/* ARGSUSED */
void
stmf_dlun0_ctl(struct stmf_lu *lu, int cmd, void *arg)
{
	/* This function will never be called */
	cmn_err(CE_WARN, "stmf_dlun0_ctl called with cmd %x", cmd);
}

void
stmf_dlun_init()
{
	stmf_i_lu_t *ilu;

	dlun0 = stmf_alloc(STMF_STRUCT_STMF_LU, 0, 0);
	dlun0->lu_task_alloc = stmf_dlun0_task_alloc;
	dlun0->lu_new_task = stmf_dlun0_new_task;
	dlun0->lu_dbuf_xfer_done = stmf_dlun0_dbuf_done;
	dlun0->lu_send_status_done = stmf_dlun0_status_done;
	dlun0->lu_task_free = stmf_dlun0_task_free;
	dlun0->lu_abort = stmf_dlun0_abort;
	dlun0->lu_task_poll = stmf_dlun0_task_poll;
	dlun0->lu_ctl = stmf_dlun0_ctl;

	ilu = (stmf_i_lu_t *)dlun0->lu_stmf_private;
	ilu->ilu_cur_task_cntr = &ilu->ilu_task_cntr1;
}

stmf_status_t
stmf_dlun_fini()
{
	stmf_i_lu_t *ilu;

	ilu = (stmf_i_lu_t *)dlun0->lu_stmf_private;

	ASSERT(ilu->ilu_ntasks == ilu->ilu_ntasks_free);
	if (ilu->ilu_ntasks) {
		stmf_i_scsi_task_t *itask, *nitask;

		nitask = ilu->ilu_tasks;
		do {
			itask = nitask;
			nitask = itask->itask_lu_next;
			dlun0->lu_task_free(itask->itask_task);
			stmf_free(itask->itask_task);
		} while (nitask != NULL);

	}
	stmf_free(dlun0);
	return (STMF_SUCCESS);
}

void
stmf_abort_target_reset(scsi_task_t *task)
{
	stmf_i_scsi_session_t *iss = (stmf_i_scsi_session_t *)
	    task->task_session->ss_stmf_private;
	stmf_lun_map_t *lm;
	stmf_lun_map_ent_t *lm_ent;
	stmf_i_lu_t *ilu;
	int i;

	rw_enter(iss->iss_lockp, RW_READER);
	lm = iss->iss_sm;
	for (i = 0; i < lm->lm_nentries; i++) {
		if (lm->lm_plus[i] == NULL)
			continue;
		lm_ent = (stmf_lun_map_ent_t *)lm->lm_plus[i];
		ilu = (stmf_i_lu_t *)lm_ent->ent_lu->lu_stmf_private;
		if (ilu->ilu_flags & ILU_RESET_ACTIVE) {
			atomic_and_32(&ilu->ilu_flags, ~ILU_RESET_ACTIVE);
		}
	}
	atomic_and_32(&iss->iss_flags, ~ISS_RESET_ACTIVE);
	rw_exit(iss->iss_lockp);
}

/*
 * The return value is only used by function managing target reset.
 */
stmf_status_t
stmf_lun_reset_poll(stmf_lu_t *lu, struct scsi_task *task, int target_reset)
{
	stmf_i_lu_t *ilu = (stmf_i_lu_t *)lu->lu_stmf_private;
	int ntasks_pending;

	ntasks_pending = ilu->ilu_ntasks - ilu->ilu_ntasks_free;
	/*
	 * This function is also used during Target reset. The idea is that
	 * once all the commands are aborted, call the LU's reset entry
	 * point (abort entry point with a reset flag). But if this Task
	 * mgmt is running on this LU then all the tasks cannot be aborted.
	 * one task (this task) will still be running which is OK.
	 */
	if ((ntasks_pending == 0) || ((task->task_lu == lu) &&
	    (ntasks_pending == 1))) {
		stmf_status_t ret;

		if ((task->task_mgmt_function == TM_LUN_RESET) ||
		    (task->task_mgmt_function == TM_TARGET_RESET) ||
		    (task->task_mgmt_function == TM_TARGET_WARM_RESET) ||
		    (task->task_mgmt_function == TM_TARGET_COLD_RESET)) {
			ret = lu->lu_abort(lu, STMF_LU_RESET_STATE, task, 0);
		} else {
			ret = STMF_SUCCESS;
		}
		if (ret == STMF_SUCCESS) {
			atomic_and_32(&ilu->ilu_flags, ~ILU_RESET_ACTIVE);
		}
		if (target_reset) {
			return (ret);
		}
		if (ret == STMF_SUCCESS) {
			stmf_scsilib_send_status(task, STATUS_GOOD, 0);
			return (ret);
		}
		if (ret != STMF_BUSY) {
			stmf_abort(STMF_QUEUE_TASK_ABORT, task, ret, NULL);
			return (ret);
		}
	}

	if (target_reset) {
		/* Tell target reset polling code that we are not done */
		return (STMF_BUSY);
	}

	if (stmf_task_poll_lu(task, ITASK_DEFAULT_POLL_TIMEOUT)
	    != STMF_SUCCESS) {
		stmf_abort(STMF_QUEUE_TASK_ABORT, task,
		    STMF_ALLOC_FAILURE, NULL);
		return (STMF_SUCCESS);
	}

	return (STMF_SUCCESS);
}

void
stmf_target_reset_poll(struct scsi_task *task)
{
	stmf_i_scsi_session_t *iss = (stmf_i_scsi_session_t *)
	    task->task_session->ss_stmf_private;
	stmf_lun_map_t *lm;
	stmf_lun_map_ent_t *lm_ent;
	stmf_i_lu_t *ilu;
	stmf_status_t ret;
	int i;
	int not_done = 0;

	ASSERT(iss->iss_flags & ISS_RESET_ACTIVE);

	rw_enter(iss->iss_lockp, RW_READER);
	lm = iss->iss_sm;
	for (i = 0; i < lm->lm_nentries; i++) {
		if (lm->lm_plus[i] == NULL)
			continue;
		lm_ent = (stmf_lun_map_ent_t *)lm->lm_plus[i];
		ilu = (stmf_i_lu_t *)lm_ent->ent_lu->lu_stmf_private;
		if (ilu->ilu_flags & ILU_RESET_ACTIVE) {
			rw_exit(iss->iss_lockp);
			ret = stmf_lun_reset_poll(lm_ent->ent_lu, task, 1);
			rw_enter(iss->iss_lockp, RW_READER);
			if (ret == STMF_SUCCESS)
				continue;
			not_done = 1;
			if (ret != STMF_BUSY) {
				rw_exit(iss->iss_lockp);
				stmf_abort(STMF_QUEUE_TASK_ABORT, task,
				    STMF_ABORTED, NULL);
				return;
			}
		}
	}
	rw_exit(iss->iss_lockp);

	if (not_done) {
		if (stmf_task_poll_lu(task, ITASK_DEFAULT_POLL_TIMEOUT)
		    != STMF_SUCCESS) {
			stmf_abort(STMF_QUEUE_TASK_ABORT, task,
			    STMF_ALLOC_FAILURE, NULL);
			return;
		}
		return;
	}

	atomic_and_32(&iss->iss_flags, ~ISS_RESET_ACTIVE);

	stmf_scsilib_send_status(task, STATUS_GOOD, 0);
}

stmf_status_t
stmf_lu_add_event(stmf_lu_t *lu, int eventid)
{
	stmf_i_lu_t *ilu = (stmf_i_lu_t *)lu->lu_stmf_private;

	if ((eventid < 0) || (eventid >= STMF_MAX_NUM_EVENTS)) {
		return (STMF_INVALID_ARG);
	}

	STMF_EVENT_ADD(ilu->ilu_event_hdl, eventid);
	return (STMF_SUCCESS);
}

stmf_status_t
stmf_lu_remove_event(stmf_lu_t *lu, int eventid)
{
	stmf_i_lu_t *ilu = (stmf_i_lu_t *)lu->lu_stmf_private;

	if (eventid == STMF_EVENT_ALL) {
		STMF_EVENT_CLEAR_ALL(ilu->ilu_event_hdl);
		return (STMF_SUCCESS);
	}

	if ((eventid < 0) || (eventid >= STMF_MAX_NUM_EVENTS)) {
		return (STMF_INVALID_ARG);
	}

	STMF_EVENT_REMOVE(ilu->ilu_event_hdl, eventid);
	return (STMF_SUCCESS);
}

stmf_status_t
stmf_lport_add_event(stmf_local_port_t *lport, int eventid)
{
	stmf_i_local_port_t *ilport =
	    (stmf_i_local_port_t *)lport->lport_stmf_private;

	if ((eventid < 0) || (eventid >= STMF_MAX_NUM_EVENTS)) {
		return (STMF_INVALID_ARG);
	}

	STMF_EVENT_ADD(ilport->ilport_event_hdl, eventid);
	return (STMF_SUCCESS);
}

stmf_status_t
stmf_lport_remove_event(stmf_local_port_t *lport, int eventid)
{
	stmf_i_local_port_t *ilport =
	    (stmf_i_local_port_t *)lport->lport_stmf_private;

	if (eventid == STMF_EVENT_ALL) {
		STMF_EVENT_CLEAR_ALL(ilport->ilport_event_hdl);
		return (STMF_SUCCESS);
	}

	if ((eventid < 0) || (eventid >= STMF_MAX_NUM_EVENTS)) {
		return (STMF_INVALID_ARG);
	}

	STMF_EVENT_REMOVE(ilport->ilport_event_hdl, eventid);
	return (STMF_SUCCESS);
}

void
stmf_generate_lu_event(stmf_i_lu_t *ilu, int eventid, void *arg, uint32_t flags)
{
	if (STMF_EVENT_ENABLED(ilu->ilu_event_hdl, eventid) &&
	    (ilu->ilu_lu->lu_event_handler != NULL)) {
		ilu->ilu_lu->lu_event_handler(ilu->ilu_lu, eventid, arg, flags);
	}
}

void
stmf_generate_lport_event(stmf_i_local_port_t *ilport, int eventid, void *arg,
				uint32_t flags)
{
	if (STMF_EVENT_ENABLED(ilport->ilport_event_hdl, eventid) &&
	    (ilport->ilport_lport->lport_event_handler != NULL)) {
		ilport->ilport_lport->lport_event_handler(
		    ilport->ilport_lport, eventid, arg, flags);
	}
}

/*
 * With the possibility of having multiple itl sessions pointing to the
 * same itl_kstat_info, the ilu_kstat_lock mutex is used to synchronize
 * the kstat update of the ilu_kstat_io, itl_kstat_taskq and itl_kstat_lu_xfer
 * statistics.
 */
void
stmf_itl_task_start(stmf_i_scsi_task_t *itask)
{
	stmf_itl_data_t	*itl = itask->itask_itl_datap;
	scsi_task_t	*task = itask->itask_task;
	stmf_i_lu_t	*ilu;

	if (itl == NULL || task->task_lu == dlun0)
		return;
	ilu = (stmf_i_lu_t *)task->task_lu->lu_stmf_private;
	itask->itask_start_timestamp = gethrtime();
	if (ilu->ilu_kstat_io != NULL) {
		mutex_enter(ilu->ilu_kstat_io->ks_lock);
		stmf_update_kstat_lu_q(itask->itask_task, kstat_waitq_enter);
		mutex_exit(ilu->ilu_kstat_io->ks_lock);
	}

	stmf_update_kstat_lport_q(itask->itask_task, kstat_waitq_enter);
}

void
stmf_itl_lu_new_task(stmf_i_scsi_task_t *itask)
{
	stmf_itl_data_t	*itl = itask->itask_itl_datap;
	scsi_task_t	*task = itask->itask_task;
	stmf_i_lu_t	*ilu;

	if (itl == NULL || task->task_lu == dlun0)
		return;
	ilu = (stmf_i_lu_t *)task->task_lu->lu_stmf_private;
	if (ilu->ilu_kstat_io != NULL) {
		mutex_enter(ilu->ilu_kstat_io->ks_lock);
		stmf_update_kstat_lu_q(itask->itask_task, kstat_waitq_to_runq);
		mutex_exit(ilu->ilu_kstat_io->ks_lock);
	}

	stmf_update_kstat_lport_q(itask->itask_task, kstat_waitq_to_runq);
}

void
stmf_itl_task_done(stmf_i_scsi_task_t *itask)
{
	stmf_itl_data_t		*itl = itask->itask_itl_datap;
	scsi_task_t		*task = itask->itask_task;
	stmf_i_lu_t	*ilu;

	itask->itask_done_timestamp = gethrtime();

	if (itl == NULL || task->task_lu == dlun0)
		return;
	ilu = (stmf_i_lu_t *)task->task_lu->lu_stmf_private;

	if (ilu->ilu_kstat_io == NULL)
		return;

	mutex_enter(ilu->ilu_kstat_io->ks_lock);

	if (itask->itask_flags & ITASK_KSTAT_IN_RUNQ) {
		stmf_update_kstat_lu_q(task, kstat_runq_exit);
		mutex_exit(ilu->ilu_kstat_io->ks_lock);
		stmf_update_kstat_lport_q(task, kstat_runq_exit);
	} else {
		stmf_update_kstat_lu_q(task, kstat_waitq_exit);
		mutex_exit(ilu->ilu_kstat_io->ks_lock);
		stmf_update_kstat_lport_q(task, kstat_waitq_exit);
	}
}

static void
stmf_lport_xfer_start(stmf_i_scsi_task_t *itask, stmf_data_buf_t *dbuf)
{
	stmf_itl_data_t		*itl = itask->itask_itl_datap;

	if (itl == NULL)
		return;

	DTRACE_PROBE2(scsi__xfer__start, scsi_task_t *, itask->itask_task,
	    stmf_data_buf_t *, dbuf);

	dbuf->db_xfer_start_timestamp = gethrtime();
}

static void
stmf_lport_xfer_done(stmf_i_scsi_task_t *itask, stmf_data_buf_t *dbuf)
{
	stmf_itl_data_t		*itl = itask->itask_itl_datap;
	hrtime_t		elapsed_time;
	uint64_t		xfer_size;

	if (itl == NULL)
		return;

	xfer_size = (dbuf->db_xfer_status == STMF_SUCCESS) ?
	    dbuf->db_data_size : 0;

	elapsed_time = gethrtime() - dbuf->db_xfer_start_timestamp;
	if (dbuf->db_flags & DB_DIRECTION_TO_RPORT) {
		atomic_add_64((uint64_t *)&itask->itask_lport_read_time,
		    elapsed_time);
		atomic_add_64((uint64_t *)&itask->itask_read_xfer,
		    xfer_size);
	} else {
		atomic_add_64((uint64_t *)&itask->itask_lport_write_time,
		    elapsed_time);
		atomic_add_64((uint64_t *)&itask->itask_write_xfer,
		    xfer_size);
	}

	DTRACE_PROBE3(scsi__xfer__end, scsi_task_t *, itask->itask_task,
	    stmf_data_buf_t *, dbuf, hrtime_t, elapsed_time);

	dbuf->db_xfer_start_timestamp = 0;
}

void
stmf_svc_init()
{
	if (stmf_state.stmf_svc_flags & STMF_SVC_STARTED)
		return;
	stmf_state.stmf_svc_tailp = &stmf_state.stmf_svc_active;
	stmf_state.stmf_svc_taskq = ddi_taskq_create(0, "STMF_SVC_TASKQ", 1,
	    TASKQ_DEFAULTPRI, 0);
	(void) ddi_taskq_dispatch(stmf_state.stmf_svc_taskq,
	    stmf_svc, 0, DDI_SLEEP);
}

stmf_status_t
stmf_svc_fini()
{
	uint32_t i;

	mutex_enter(&stmf_state.stmf_lock);
	if (stmf_state.stmf_svc_flags & STMF_SVC_STARTED) {
		stmf_state.stmf_svc_flags |= STMF_SVC_TERMINATE;
		cv_signal(&stmf_state.stmf_cv);
	}
	mutex_exit(&stmf_state.stmf_lock);

	/* Wait for 5 seconds */
	for (i = 0; i < 500; i++) {
		if (stmf_state.stmf_svc_flags & STMF_SVC_STARTED)
			delay(drv_usectohz(10000));
		else
			break;
	}
	if (i == 500)
		return (STMF_BUSY);

	ddi_taskq_destroy(stmf_state.stmf_svc_taskq);

	return (STMF_SUCCESS);
}

struct stmf_svc_clocks {
	clock_t drain_start, drain_next;
	clock_t timing_start, timing_next;
	clock_t worker_delay;
};

/* ARGSUSED */
void
stmf_svc(void *arg)
{
	stmf_svc_req_t *req;
	stmf_lu_t *lu;
	stmf_i_lu_t *ilu;
	stmf_local_port_t *lport;
	struct stmf_svc_clocks clks = { 0 };

	mutex_enter(&stmf_state.stmf_lock);
	stmf_state.stmf_svc_flags |= STMF_SVC_STARTED | STMF_SVC_ACTIVE;

	while (!(stmf_state.stmf_svc_flags & STMF_SVC_TERMINATE)) {
		if (stmf_state.stmf_svc_active == NULL) {
			stmf_svc_timeout(&clks);
			continue;
		}

		/*
		 * Pop the front request from the active list.  After this,
		 * the request will no longer be referenced by global state,
		 * so it should be safe to access it without holding the
		 * stmf state lock.
		 */
		req = stmf_state.stmf_svc_active;
		stmf_state.stmf_svc_active = req->svc_next;

		if (stmf_state.stmf_svc_active == NULL)
			stmf_state.stmf_svc_tailp = &stmf_state.stmf_svc_active;

		switch (req->svc_cmd) {
		case STMF_CMD_LPORT_ONLINE:
			/* Fallthrough */
		case STMF_CMD_LPORT_OFFLINE:
			mutex_exit(&stmf_state.stmf_lock);
			lport = (stmf_local_port_t *)req->svc_obj;
			lport->lport_ctl(lport, req->svc_cmd, &req->svc_info);
			break;
		case STMF_CMD_LU_ONLINE:
			mutex_exit(&stmf_state.stmf_lock);
			lu = (stmf_lu_t *)req->svc_obj;
			lu->lu_ctl(lu, req->svc_cmd, &req->svc_info);
			break;
		case STMF_CMD_LU_OFFLINE:
			/* Remove all mappings of this LU */
			stmf_session_lu_unmapall((stmf_lu_t *)req->svc_obj);
			/* Kill all the pending I/Os for this LU */
			mutex_exit(&stmf_state.stmf_lock);
			stmf_task_lu_killall((stmf_lu_t *)req->svc_obj, NULL,
			    STMF_ABORTED);
			lu = (stmf_lu_t *)req->svc_obj;
			ilu = (stmf_i_lu_t *)lu->lu_stmf_private;
			stmf_wait_ilu_tasks_finish(ilu);
			lu->lu_ctl(lu, req->svc_cmd, &req->svc_info);
			break;
		default:
			cmn_err(CE_PANIC, "stmf_svc: unknown cmd %d",
			    req->svc_cmd);
		}

		kmem_free(req, req->svc_req_alloc_size);
		mutex_enter(&stmf_state.stmf_lock);
	}

	stmf_state.stmf_svc_flags &= ~(STMF_SVC_STARTED | STMF_SVC_ACTIVE);
	mutex_exit(&stmf_state.stmf_lock);
}

static void
stmf_svc_timeout(struct stmf_svc_clocks *clks)
{
	clock_t td;
	stmf_i_local_port_t *ilport, *next_ilport;
	stmf_i_scsi_session_t *iss;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	td = drv_usectohz(20000);

	/* Do timeouts */
	if (stmf_state.stmf_nlus &&
	    ((!clks->timing_next) || (ddi_get_lbolt() >= clks->timing_next))) {
		if (!stmf_state.stmf_svc_ilu_timing) {
			/* we are starting a new round */
			stmf_state.stmf_svc_ilu_timing =
			    stmf_state.stmf_ilulist;
			clks->timing_start = ddi_get_lbolt();
		}

		stmf_check_ilu_timing();
		if (!stmf_state.stmf_svc_ilu_timing) {
			/* we finished a complete round */
			clks->timing_next =
			    clks->timing_start + drv_usectohz(5*1000*1000);
		} else {
			/* we still have some ilu items to check */
			clks->timing_next =
			    ddi_get_lbolt() + drv_usectohz(1*1000*1000);
		}

		if (stmf_state.stmf_svc_active)
			return;
	}

	/* Check if there are free tasks to clear */
	if (stmf_state.stmf_nlus &&
	    ((!clks->drain_next) || (ddi_get_lbolt() >= clks->drain_next))) {
		if (!stmf_state.stmf_svc_ilu_draining) {
			/* we are starting a new round */
			stmf_state.stmf_svc_ilu_draining =
			    stmf_state.stmf_ilulist;
			clks->drain_start = ddi_get_lbolt();
		}

		stmf_check_freetask();
		if (!stmf_state.stmf_svc_ilu_draining) {
			/* we finished a complete round */
			clks->drain_next =
			    clks->drain_start + drv_usectohz(10*1000*1000);
		} else {
			/* we still have some ilu items to check */
			clks->drain_next =
			    ddi_get_lbolt() + drv_usectohz(1*1000*1000);
		}

		if (stmf_state.stmf_svc_active)
			return;
	}

	/* Check if we need to run worker_mgmt */
	if (ddi_get_lbolt() > clks->worker_delay) {
		stmf_worker_mgmt();
		clks->worker_delay = ddi_get_lbolt() +
		    stmf_worker_mgmt_delay;
	}

	/* Check if any active session got its 1st LUN */
	if (stmf_state.stmf_process_initial_luns) {
		int stmf_level = 0;
		int port_level;

		for (ilport = stmf_state.stmf_ilportlist; ilport;
		    ilport = next_ilport) {
			int ilport_lock_held;
			next_ilport = ilport->ilport_next;

			if ((ilport->ilport_flags &
			    ILPORT_SS_GOT_INITIAL_LUNS) == 0)
				continue;

			port_level = 0;
			rw_enter(&ilport->ilport_lock, RW_READER);
			ilport_lock_held = 1;

			for (iss = ilport->ilport_ss_list; iss;
			    iss = iss->iss_next) {
				if ((iss->iss_flags &
				    ISS_GOT_INITIAL_LUNS) == 0)
					continue;

				port_level++;
				stmf_level++;
				atomic_and_32(&iss->iss_flags,
				    ~ISS_GOT_INITIAL_LUNS);
				atomic_or_32(&iss->iss_flags,
				    ISS_EVENT_ACTIVE);
				rw_exit(&ilport->ilport_lock);
				ilport_lock_held = 0;
				mutex_exit(&stmf_state.stmf_lock);
				stmf_generate_lport_event(ilport,
				    LPORT_EVENT_INITIAL_LUN_MAPPED,
				    iss->iss_ss, 0);
				atomic_and_32(&iss->iss_flags,
				    ~ISS_EVENT_ACTIVE);
				mutex_enter(&stmf_state.stmf_lock);
				/*
				 * scan all the ilports again as the
				 * ilport list might have changed.
				 */
				next_ilport = stmf_state.stmf_ilportlist;
				break;
			}

			if (port_level == 0)
				atomic_and_32(&ilport->ilport_flags,
				    ~ILPORT_SS_GOT_INITIAL_LUNS);
			/* drop the lock if we are holding it. */
			if (ilport_lock_held == 1)
				rw_exit(&ilport->ilport_lock);

			/* Max 4 session at a time */
			if (stmf_level >= 4)
				break;
		}

		if (stmf_level == 0)
			stmf_state.stmf_process_initial_luns = 0;
	}

	stmf_state.stmf_svc_flags &= ~STMF_SVC_ACTIVE;
	(void) cv_reltimedwait(&stmf_state.stmf_cv,
	    &stmf_state.stmf_lock, td, TR_CLOCK_TICK);
	stmf_state.stmf_svc_flags |= STMF_SVC_ACTIVE;
}

/*
 * Waits for ongoing I/O tasks to finish on an LU in preparation for
 * the LU's offlining. The LU should already be in an Offlining state
 * (otherwise I/O to the LU might never end). There is an additional
 * enforcement of this via a deadman timer check.
 */
static void
stmf_wait_ilu_tasks_finish(stmf_i_lu_t *ilu)
{
	clock_t start, now, deadline;

	start = now = ddi_get_lbolt();
	deadline = start + drv_usectohz(stmf_io_deadman * 1000000llu);
	mutex_enter(&ilu->ilu_task_lock);
	while (ilu->ilu_ntasks != ilu->ilu_ntasks_free) {
		(void) cv_timedwait(&ilu->ilu_offline_pending_cv,
		    &ilu->ilu_task_lock, deadline);
		now = ddi_get_lbolt();
		if (now > deadline) {
			if (stmf_io_deadman_enabled) {
				cmn_err(CE_PANIC, "stmf_svc: I/O deadman hit "
				    "on STMF_CMD_LU_OFFLINE after %d seconds",
				    stmf_io_deadman);
			} else {
				/* keep on spinning */
				deadline = now + drv_usectohz(stmf_io_deadman *
				    1000000llu);
			}
		}
	}
	mutex_exit(&ilu->ilu_task_lock);
	DTRACE_PROBE1(deadman__timeout__wait, clock_t, now - start);
}

void
stmf_svc_queue(int cmd, void *obj, stmf_state_change_info_t *info)
{
	stmf_svc_req_t *req;
	int s;

	ASSERT(!mutex_owned(&stmf_state.stmf_lock));
	s = sizeof (stmf_svc_req_t);
	if (info->st_additional_info) {
		s += strlen(info->st_additional_info) + 1;
	}
	req = kmem_zalloc(s, KM_SLEEP);

	req->svc_cmd = cmd;
	req->svc_obj = obj;
	req->svc_info.st_rflags = info->st_rflags;
	if (info->st_additional_info) {
		req->svc_info.st_additional_info = (char *)(GET_BYTE_OFFSET(req,
		    sizeof (stmf_svc_req_t)));
		(void) strcpy(req->svc_info.st_additional_info,
		    info->st_additional_info);
	}
	req->svc_req_alloc_size = s;
	req->svc_next = NULL;

	mutex_enter(&stmf_state.stmf_lock);
	*stmf_state.stmf_svc_tailp = req;
	stmf_state.stmf_svc_tailp = &req->svc_next;
	if ((stmf_state.stmf_svc_flags & STMF_SVC_ACTIVE) == 0) {
		cv_signal(&stmf_state.stmf_cv);
	}
	mutex_exit(&stmf_state.stmf_lock);
}

static void
stmf_svc_kill_obj_requests(void *obj)
{
	stmf_svc_req_t *prev_req = NULL;
	stmf_svc_req_t *next_req;
	stmf_svc_req_t *req;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	for (req = stmf_state.stmf_svc_active; req != NULL; req = next_req) {
		next_req = req->svc_next;

		if (req->svc_obj == obj) {
			if (prev_req != NULL)
				prev_req->svc_next = next_req;
			else
				stmf_state.stmf_svc_active = next_req;

			if (next_req == NULL)
				stmf_state.stmf_svc_tailp = (prev_req != NULL) ?
				    &prev_req->svc_next :
				    &stmf_state.stmf_svc_active;

			kmem_free(req, req->svc_req_alloc_size);
		} else {
			prev_req = req;
		}
	}
}

void
stmf_trace(caddr_t ident, const char *fmt, ...)
{
	va_list args;
	char tbuf[160];
	int len;

	if (!stmf_trace_on)
		return;
	len = snprintf(tbuf, 158, "%s:%07lu: ", ident ? ident : "",
	    ddi_get_lbolt());
	va_start(args, fmt);
	len += vsnprintf(tbuf + len, 158 - len, fmt, args);
	va_end(args);

	if (len > 158) {
		len = 158;
	}
	tbuf[len++] = '\n';
	tbuf[len] = 0;

	mutex_enter(&trace_buf_lock);
	bcopy(tbuf, &stmf_trace_buf[trace_buf_curndx], len+1);
	trace_buf_curndx += len;
	if (trace_buf_curndx > (trace_buf_size - 320))
		trace_buf_curndx = 0;
	mutex_exit(&trace_buf_lock);
}

void
stmf_trace_clear()
{
	if (!stmf_trace_on)
		return;
	mutex_enter(&trace_buf_lock);
	trace_buf_curndx = 0;
	if (trace_buf_size > 0)
		stmf_trace_buf[0] = 0;
	mutex_exit(&trace_buf_lock);
}

static void
stmf_abort_task_offline(scsi_task_t *task, int offline_lu, char *info)
{
	stmf_state_change_info_t	change_info;
	void				*ctl_private;
	uint32_t			ctl_cmd;
	int				msg = 0;

	stmf_trace("FROM STMF", "abort_task_offline called for %s: %s",
	    offline_lu ? "LU" : "LPORT", info ? info : "no additional info");
	change_info.st_additional_info = info;
	if (offline_lu) {
		change_info.st_rflags = STMF_RFLAG_RESET |
		    STMF_RFLAG_LU_ABORT;
		ctl_private = task->task_lu;
		if (((stmf_i_lu_t *)
		    task->task_lu->lu_stmf_private)->ilu_state ==
		    STMF_STATE_ONLINE) {
			msg = 1;
		}
		ctl_cmd = STMF_CMD_LU_OFFLINE;
	} else {
		change_info.st_rflags = STMF_RFLAG_RESET |
		    STMF_RFLAG_LPORT_ABORT;
		ctl_private = task->task_lport;
		if (((stmf_i_local_port_t *)
		    task->task_lport->lport_stmf_private)->ilport_state ==
		    STMF_STATE_ONLINE) {
			msg = 1;
		}
		ctl_cmd = STMF_CMD_LPORT_OFFLINE;
	}

	if (msg) {
		stmf_trace(0, "Calling stmf_ctl to offline %s : %s",
		    offline_lu ? "LU" : "LPORT", info ? info :
		    "<no additional info>");
	}
	(void) stmf_ctl(ctl_cmd, ctl_private, &change_info);
}

static char
stmf_ctoi(char c)
{
	if ((c >= '0') && (c <= '9'))
		c -= '0';
	else if ((c >= 'A') && (c <= 'F'))
		c = c - 'A' + 10;
	else if ((c >= 'a') && (c <= 'f'))
		c = c - 'a' + 10;
	else
		c = -1;
	return (c);
}

/* Convert from Hex value in ASCII format to the equivalent bytes */
static boolean_t
stmf_base16_str_to_binary(char *c, int dplen, uint8_t *dp)
{
	int		ii;

	for (ii = 0; ii < dplen; ii++) {
		char nibble1, nibble2;
		char enc_char = *c++;
		nibble1 = stmf_ctoi(enc_char);

		enc_char = *c++;
		nibble2 = stmf_ctoi(enc_char);
		if (nibble1 == -1 || nibble2 == -1)
			return (B_FALSE);

		dp[ii] = (nibble1 << 4) | nibble2;
	}
	return (B_TRUE);
}

boolean_t
stmf_scsilib_tptid_validate(scsi_transport_id_t *tptid, uint32_t total_sz,
				uint16_t *tptid_sz)
{
	uint16_t tpd_len = SCSI_TPTID_SIZE;

	if (tptid_sz)
		*tptid_sz = 0;
	if (total_sz < sizeof (scsi_transport_id_t))
		return (B_FALSE);

	switch (tptid->protocol_id) {

	case PROTOCOL_FIBRE_CHANNEL:
		/* FC Transport ID validation checks. SPC3 rev23, Table 284 */
		if (total_sz < tpd_len || tptid->format_code != 0)
			return (B_FALSE);
		break;

	case PROTOCOL_iSCSI:
		{
		iscsi_transport_id_t	*iscsiid;
		uint16_t		adn_len, name_len;

		/* Check for valid format code, SPC3 rev 23 Table 288 */
		if ((total_sz < tpd_len) ||
		    (tptid->format_code != 0 && tptid->format_code != 1))
			return (B_FALSE);

		iscsiid = (iscsi_transport_id_t *)tptid;
		adn_len = READ_SCSI16(iscsiid->add_len, uint16_t);
		tpd_len = sizeof (iscsi_transport_id_t) + adn_len - 1;

		/*
		 * iSCSI Transport ID validation checks.
		 * As per SPC3 rev 23 Section 7.5.4.6 and Table 289 & Table 290
		 */
		if (adn_len < 20 || (adn_len % 4 != 0))
			return (B_FALSE);

		name_len = strnlen(iscsiid->iscsi_name, adn_len);
		if (name_len == 0 || name_len >= adn_len)
			return (B_FALSE);

		/* If the format_code is 1 check for ISID seperator */
		if ((tptid->format_code == 1) && (strstr(iscsiid->iscsi_name,
		    SCSI_TPTID_ISCSI_ISID_SEPERATOR) == NULL))
			return (B_FALSE);

		}
		break;

	case PROTOCOL_SRP:
		/* SRP Transport ID validation checks. SPC3 rev23, Table 287 */
		if (total_sz < tpd_len || tptid->format_code != 0)
			return (B_FALSE);
		break;

	case PROTOCOL_PARALLEL_SCSI:
	case PROTOCOL_SSA:
	case PROTOCOL_IEEE_1394:
	case PROTOCOL_SAS:
	case PROTOCOL_ADT:
	case PROTOCOL_ATAPI:
	default:
		{
		stmf_dflt_scsi_tptid_t *dflttpd;

		tpd_len = sizeof (stmf_dflt_scsi_tptid_t);
		if (total_sz < tpd_len)
			return (B_FALSE);
		dflttpd = (stmf_dflt_scsi_tptid_t *)tptid;
		tpd_len = tpd_len + SCSI_READ16(&dflttpd->ident_len) - 1;
		if (total_sz < tpd_len)
			return (B_FALSE);
		}
		break;
	}
	if (tptid_sz)
		*tptid_sz = tpd_len;
	return (B_TRUE);
}

boolean_t
stmf_scsilib_tptid_compare(scsi_transport_id_t *tpd1,
				scsi_transport_id_t *tpd2)
{
	if ((tpd1->protocol_id != tpd2->protocol_id) ||
	    (tpd1->format_code != tpd2->format_code))
		return (B_FALSE);

	switch (tpd1->protocol_id) {

	case PROTOCOL_iSCSI:
		{
		iscsi_transport_id_t *iscsitpd1, *iscsitpd2;
		uint16_t len;

		iscsitpd1 = (iscsi_transport_id_t *)tpd1;
		iscsitpd2 = (iscsi_transport_id_t *)tpd2;
		len = SCSI_READ16(&iscsitpd1->add_len);
		if ((memcmp(iscsitpd1->add_len, iscsitpd2->add_len, 2) != 0) ||
		    (memcmp(iscsitpd1->iscsi_name, iscsitpd2->iscsi_name, len)
		    != 0))
			return (B_FALSE);
		}
		break;

	case PROTOCOL_SRP:
		{
		scsi_srp_transport_id_t *srptpd1, *srptpd2;

		srptpd1 = (scsi_srp_transport_id_t *)tpd1;
		srptpd2 = (scsi_srp_transport_id_t *)tpd2;
		if (memcmp(srptpd1->srp_name, srptpd2->srp_name,
		    sizeof (srptpd1->srp_name)) != 0)
			return (B_FALSE);
		}
		break;

	case PROTOCOL_FIBRE_CHANNEL:
		{
		scsi_fc_transport_id_t *fctpd1, *fctpd2;

		fctpd1 = (scsi_fc_transport_id_t *)tpd1;
		fctpd2 = (scsi_fc_transport_id_t *)tpd2;
		if (memcmp(fctpd1->port_name, fctpd2->port_name,
		    sizeof (fctpd1->port_name)) != 0)
			return (B_FALSE);
		}
		break;

	case PROTOCOL_PARALLEL_SCSI:
	case PROTOCOL_SSA:
	case PROTOCOL_IEEE_1394:
	case PROTOCOL_SAS:
	case PROTOCOL_ADT:
	case PROTOCOL_ATAPI:
	default:
		{
		stmf_dflt_scsi_tptid_t *dflt1, *dflt2;
		uint16_t len;

		dflt1 = (stmf_dflt_scsi_tptid_t *)tpd1;
		dflt2 = (stmf_dflt_scsi_tptid_t *)tpd2;
		len = SCSI_READ16(&dflt1->ident_len);
		if ((memcmp(dflt1->ident_len, dflt2->ident_len, 2) != 0) ||
		    (memcmp(dflt1->ident, dflt2->ident, len) != 0))
			return (B_FALSE);
		}
		break;
	}
	return (B_TRUE);
}

/*
 * Changes devid_desc to corresponding TransportID format
 * Returns :- pointer to stmf_remote_port_t
 * Note    :- Allocates continous memory for stmf_remote_port_t and TransportID,
 *            This memory need to be freed when this remote_port is no longer
 *            used.
 */
stmf_remote_port_t *
stmf_scsilib_devid_to_remote_port(scsi_devid_desc_t *devid)
{
	struct scsi_fc_transport_id	*fc_tpd;
	struct iscsi_transport_id	*iscsi_tpd;
	struct scsi_srp_transport_id	*srp_tpd;
	struct stmf_dflt_scsi_tptid	*dflt_tpd;
	uint16_t ident_len,  sz = 0;
	stmf_remote_port_t *rpt = NULL;

	ident_len = devid->ident_length;
	ASSERT(ident_len);
	switch (devid->protocol_id) {
	case PROTOCOL_FIBRE_CHANNEL:
		sz = sizeof (scsi_fc_transport_id_t);
		rpt = stmf_remote_port_alloc(sz);
		rpt->rport_tptid->format_code = 0;
		rpt->rport_tptid->protocol_id = devid->protocol_id;
		fc_tpd = (scsi_fc_transport_id_t *)rpt->rport_tptid;
		/*
		 * convert from "wwn.xxxxxxxxxxxxxxxx" to 8-byte binary
		 * skip first 4 byte for "wwn."
		 */
		ASSERT(strncmp("wwn.", (char *)devid->ident, 4) == 0);
		if ((ident_len < SCSI_TPTID_FC_PORT_NAME_SIZE * 2 + 4) ||
		    !stmf_base16_str_to_binary((char *)devid->ident + 4,
		    SCSI_TPTID_FC_PORT_NAME_SIZE, fc_tpd->port_name))
			goto devid_to_remote_port_fail;
		break;

	case PROTOCOL_iSCSI:
		sz = ALIGNED_TO_8BYTE_BOUNDARY(sizeof (iscsi_transport_id_t) +
		    ident_len - 1);
		rpt = stmf_remote_port_alloc(sz);
		rpt->rport_tptid->format_code = 0;
		rpt->rport_tptid->protocol_id = devid->protocol_id;
		iscsi_tpd = (iscsi_transport_id_t *)rpt->rport_tptid;
		SCSI_WRITE16(iscsi_tpd->add_len, ident_len);
		(void) memcpy(iscsi_tpd->iscsi_name, devid->ident, ident_len);
		break;

	case PROTOCOL_SRP:
		sz = sizeof (scsi_srp_transport_id_t);
		rpt = stmf_remote_port_alloc(sz);
		rpt->rport_tptid->format_code = 0;
		rpt->rport_tptid->protocol_id = devid->protocol_id;
		srp_tpd = (scsi_srp_transport_id_t *)rpt->rport_tptid;
		/*
		 * convert from "eui.xxxxxxxxxxxxxxx" to 8-byte binary
		 * skip first 4 byte for "eui."
		 * Assume 8-byte initiator-extension part of srp_name is NOT
		 * stored in devid and hence will be set as zero
		 */
		ASSERT(strncmp("eui.", (char *)devid->ident, 4) == 0);
		if ((ident_len < (SCSI_TPTID_SRP_PORT_NAME_LEN - 8) * 2 + 4) ||
		    !stmf_base16_str_to_binary((char *)devid->ident+4,
		    SCSI_TPTID_SRP_PORT_NAME_LEN, srp_tpd->srp_name))
			goto devid_to_remote_port_fail;
		break;

	case PROTOCOL_PARALLEL_SCSI:
	case PROTOCOL_SSA:
	case PROTOCOL_IEEE_1394:
	case PROTOCOL_SAS:
	case PROTOCOL_ADT:
	case PROTOCOL_ATAPI:
	default :
		ident_len = devid->ident_length;
		sz = ALIGNED_TO_8BYTE_BOUNDARY(sizeof (stmf_dflt_scsi_tptid_t) +
		    ident_len - 1);
		rpt = stmf_remote_port_alloc(sz);
		rpt->rport_tptid->format_code = 0;
		rpt->rport_tptid->protocol_id = devid->protocol_id;
		dflt_tpd = (stmf_dflt_scsi_tptid_t *)rpt->rport_tptid;
		SCSI_WRITE16(dflt_tpd->ident_len, ident_len);
		(void) memcpy(dflt_tpd->ident, devid->ident, ident_len);
		break;
	}
	return (rpt);

devid_to_remote_port_fail:
	stmf_remote_port_free(rpt);
	return (NULL);

}

stmf_remote_port_t *
stmf_remote_port_alloc(uint16_t tptid_sz) {
	stmf_remote_port_t *rpt;
	rpt = (stmf_remote_port_t *)kmem_zalloc(
	    sizeof (stmf_remote_port_t) + tptid_sz, KM_SLEEP);
	rpt->rport_tptid_sz = tptid_sz;
	rpt->rport_tptid = (scsi_transport_id_t *)(rpt + 1);
	return (rpt);
}

void
stmf_remote_port_free(stmf_remote_port_t *rpt)
{
	/*
	 * Note: stmf_scsilib_devid_to_remote_port() function allocates
	 *	remote port structures for all transports in the same way, So
	 *	it is safe to deallocate it in a protocol independent manner.
	 *	If any of the allocation method changes, corresponding changes
	 *	need to be made here too.
	 */
	kmem_free(rpt, sizeof (stmf_remote_port_t) + rpt->rport_tptid_sz);
}
