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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Joyent, Inc.
 */

/*
 * The sol_ucma driver provides the API for librdmacm library for RDMACM
 * functionality.
 *
 * sol_uverbs will create a minor node with prefix ":ucma",
 * which can be opened only by the kernel (cred == kcred).
 *
 * sol_cma driver will open and close the sol_uverb minor
 * device using the Layered Driver Interfaces (See PSARC
 * 2001/769).
 */

/* Standard driver includes */
#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/sunldi.h>
#include <sys/modctl.h>

/* Common header files */
#include <sys/ib/clients/of/sol_ofs/sol_ofs_common.h>
#include <sys/ib/clients/of/sol_uverbs/sol_uverbs2ucma.h>
#include <sys/ib/clients/of/ofed_kernel.h>

/* Kernel Headers for User rdma_cm API */
#include <sys/ib/clients/of/rdma/ib_addr.h>
#include <sys/ib/clients/of/rdma/rdma_user_cm.h>

/* Kernel rdma_cm API */
#include <sys/ib/clients/of/rdma/rdma_cm.h>

/* sol_ucma internal Header files */
#include <sys/ib/clients/of/sol_ucma/sol_ucma.h>

/* entry point function prototype declarations */
static int sol_ucma_attach(dev_info_t *, ddi_attach_cmd_t);
static int sol_ucma_detach(dev_info_t *, ddi_detach_cmd_t);
static int sol_ucma_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int sol_ucma_open(dev_t *, int, int, cred_t *);
static int sol_ucma_close(dev_t, int, int, cred_t *);
static int sol_ucma_write(dev_t, struct uio *,  cred_t *);
static int sol_ucma_poll(dev_t, short, int, short *, struct pollhead **);

/* Driver entry points */
static struct cb_ops	sol_ucma_cb_ops = {
	sol_ucma_open,		/* open */
	sol_ucma_close,		/* close */
	nodev,			/* strategy (block) */
	nodev,			/* print (block) */
	nodev,			/* dump (block) */
	nodev,			/* read */
	sol_ucma_write,		/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	sol_ucma_poll,		/* chpoll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* streams */
	D_NEW | D_MP | D_64BIT,	/* flags */
	CB_REV			/* rev */
};

/* Driver operations */
static struct dev_ops	sol_ucma_dev_ops = {
	DEVO_REV,		/* struct rev */
	0,			/* refcnt */
	sol_ucma_getinfo,	/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	sol_ucma_attach,	/* attach */
	sol_ucma_detach,	/* detach */
	nodev,			/* reset */
	&sol_ucma_cb_ops,	/* cb_ops */
	NULL,			/* bus_ops */
	nodev,			/* power */
	ddi_quiesce_not_needed	/* quiesce */
};

/* Module Driver Info */
static struct modldrv sol_ucma_modldrv = {
	&mod_driverops,
	"Solaris User RDMACM driver",
	&sol_ucma_dev_ops
};

/* Module Linkage */
static struct modlinkage sol_ucma_modlinkage = {
	MODREV_1,
	&sol_ucma_modldrv,
	NULL,
};

static char	*sol_ucma_dbg_str = "sol_ucma";
sol_ofs_uobj_table_t	ucma_file_uo_tbl;
sol_ofs_uobj_table_t	ucma_ctx_uo_tbl;
sol_ofs_uobj_table_t	ucma_mcast_uo_tbl;

/* Function pointers for uverbs functions */
static uverbs_get_clnt_hdl_t		uverbs_get_hdl_fp = NULL;
static uverbs_qpnum2qphdl_t		uverbs_qpnum2qphdl_fp = NULL;
static uverbs_disable_uqpn_mod_t	uverbs_disable_uqpn_modify_fp = NULL;
static uverbs_uqpn_cq_ctrl_t		uverbs_uqpn_cq_ctrl_fp = NULL;
static uverbs_set_qp_free_state_t	uverbs_set_qp_free_state_fp = NULL;
static uverbs_flush_qp_t		uverbs_flush_qp_fp = NULL;

/* Global Variables */
sol_ucma_t	sol_ucma;

/* RDMACM Functions  */
static int	sol_ucma_create_id(dev_t, void *, struct uio *);
static int	sol_ucma_destroy_id(dev_t, void *, struct uio *);
static int	sol_ucma_bind_addr(dev_t, void *, struct uio *);
static int	sol_ucma_resolve_addr(dev_t, void *, struct uio *);
static int	sol_ucma_resolve_route(dev_t, void *, struct uio *);
static int	sol_ucma_query_route(dev_t, void *, struct uio *);
static int	sol_ucma_connect(dev_t, void *, struct uio *);
static int	sol_ucma_listen(dev_t, void *, struct uio *);
static int	sol_ucma_accept(dev_t, void *, struct uio *);
static int	sol_ucma_reject(dev_t, void *, struct uio *);
static int	sol_ucma_disconnect(dev_t, void *, struct uio *);
static int	sol_ucma_init_qp_attr(dev_t, void *, struct uio *);
static int	sol_ucma_get_event(dev_t, void *, struct uio *);
static int	sol_ucma_set_option(dev_t, void *, struct uio *);
static int	sol_ucma_notify(dev_t, void *, struct uio *);
static int	sol_ucma_join_mcast(dev_t, void *, struct uio *);
static int	sol_ucma_leave_mcast(dev_t, void *, struct uio *);

/*
 * Event callback from sol_cma
 */
int sol_ucma_evt_hdlr(struct rdma_cm_id *, struct rdma_cm_event *);

/*
 * Internal functions.
 */
static sol_ucma_file_t	*
ucma_alloc_file(minor_t *);

static sol_ucma_chan_t *
ucma_alloc_chan(sol_ucma_file_t *, sol_ucma_create_id_t *);

static void
ucma_free_chan(sol_ucma_chan_t *, int);

static int
get_file_chan(uint32_t, sol_ucma_file_t **, sol_ucma_chan_t **, char *, int);

static void
rdma2usr_route(struct rdma_cm_id *, sol_ucma_query_route_resp_t *);

static void
usr2rdma_conn_param(struct rdma_ucm_conn_param *, struct rdma_conn_param *);

static void
rdma2usr_conn_param(struct rdma_conn_param *, struct rdma_ucm_conn_param *);

static void
rdma2usr_ud_param(struct rdma_ud_param *, sol_ucma_ud_param_t *);

static void	sol_ucma_user_objs_init();
static void	sol_ucma_user_objs_fini();

int
_init(void)
{
	int error;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "_init()");
	sol_ucma_user_objs_init();
	mutex_init(&sol_ucma.ucma_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&sol_ucma.ucma_open_cv, NULL, CV_DRIVER, NULL);

	if ((error = ldi_ident_from_mod(&sol_ucma_modlinkage,
	    &sol_ucma.ucma_ldi_ident)) != 0) {
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
		    "ldi_ident_from_mod() failed");
		mutex_destroy(&sol_ucma.ucma_mutex);
		cv_destroy(&sol_ucma.ucma_open_cv);
		sol_ucma_user_objs_fini();
		return (error);
	}
	sol_ucma.ucma_clnt_hdl_flag = SOL_UCMA_CLNT_HDL_UNINITIALIZED;
	error = mod_install(&sol_ucma_modlinkage);
	if (error) {
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str, "mod_install() failed");
		ldi_ident_release(sol_ucma.ucma_ldi_ident);
		mutex_destroy(&sol_ucma.ucma_mutex);
		cv_destroy(&sol_ucma.ucma_open_cv);
		sol_ucma_user_objs_fini();
		return (error);
	}
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "_init(): ret");
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&sol_ucma_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "_fini()");
	if ((ret = mod_remove(&sol_ucma_modlinkage)) != 0) {
		SOL_OFS_DPRINTF_L3(sol_ucma_dbg_str,
		    "sol_ucma, _fini : mod_remove failed");
		return (ret);
	}
	ldi_ident_release(sol_ucma.ucma_ldi_ident);
	mutex_destroy(&sol_ucma.ucma_mutex);
	cv_destroy(&sol_ucma.ucma_open_cv);
	sol_ucma_user_objs_fini();
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "_fini(): ret");
	return (DDI_SUCCESS);
}

static int
sol_ucma_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int	rval;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "attach(%p, %x)", dip, cmd);

	switch (cmd) {
	case DDI_ATTACH:
		mutex_enter(&sol_ucma.ucma_mutex);
		if (sol_ucma.ucma_dip != NULL) {
			mutex_exit(&sol_ucma.ucma_mutex);
			SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
			    "attach: failed, > 1 instance");
			return (DDI_FAILURE);
		}
		sol_ucma.ucma_dip = dip;
		mutex_exit(&sol_ucma.ucma_mutex);

		rval = ddi_create_minor_node(dip, "sol_ucma", S_IFCHR,
		    0, DDI_PSEUDO, 0);
		if (rval != DDI_SUCCESS) {
			SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
			    "attach: ddi_create_minor_node failed");
			mutex_enter(&sol_ucma.ucma_mutex);
			sol_ucma.ucma_dip = NULL;
			mutex_exit(&sol_ucma.ucma_mutex);
			return (DDI_FAILURE);
		}

		SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str,
		    "attach : DDI_ATTACH success");
		return (DDI_SUCCESS);
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static int
sol_ucma_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "detach(%p, %x)", dip, cmd);

	switch (cmd) {
	case DDI_DETACH:
		mutex_enter(&sol_ucma.ucma_mutex);
		if (sol_ucma.ucma_num_file) {
			SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
			    "detach : %x files not closed",
			    sol_ucma.ucma_num_file);
			mutex_exit(&sol_ucma.ucma_mutex);
			return (DDI_FAILURE);
		}
		sol_ucma.ucma_dip = NULL;
		mutex_exit(&sol_ucma.ucma_mutex);

		ddi_remove_minor_node(dip, "sol_ucma");

		SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str,
		    "detach : DDI_DETACH success");
		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
sol_ucma_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **resultp)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = (void *)sol_ucma.ucma_dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)0;
		return (DDI_SUCCESS);
	default :
		return (DDI_FAILURE);
	}
}

static int
sol_ucma_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	sol_ucma_file_t	*new_filep;
	minor_t		new_minor;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "open(%p, %x, %x, %p)",
	    devp, flag, otype, credp);

	new_filep = ucma_alloc_file(&new_minor);
	if (new_filep == NULL)
		return (EAGAIN);
	SOL_OFS_DPRINTF_L4(sol_ucma_dbg_str, "sol_ucma new minor %x",
	    new_minor);

	/*
	 * For the first open, ensure that the sol_uverbs driver is attached.
	 * Also get the function pointers for uverbs API functions using
	 * ddi_modopen() and ddi_modsym() for the sol_uverbs driver.
	 *
	 * ldi_open() is done to ensure that sol_uverbs driver is attached,
	 * even though ddi_modopen is sufficient to get the function pointers
	 * for the uverbs APIs
	 */
	mutex_enter(&sol_ucma.ucma_mutex);
	if (sol_ucma.ucma_clnt_hdl_flag == SOL_UCMA_CLNT_HDL_UNINITIALIZED) {
		int	rval, ret_errno;

		sol_ucma.ucma_clnt_hdl_flag =
		    SOL_UCMA_CLNT_HDL_INITIALIZING;
		if ((rval = ldi_open_by_name(SOL_UCMA_UVERBS_PATH,
		    FREAD | FWRITE, kcred, &sol_ucma.ucma_ldi_hdl,
		    sol_ucma.ucma_ldi_ident)) != 0) {
			SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
			    "ldi_open_by_name(%s, ...) failed with rval %x",
			    SOL_UCMA_UVERBS_PATH, rval);
			sol_ofs_uobj_free(&new_filep->file_uobj);
			sol_ucma.ucma_clnt_hdl_flag =
			    SOL_UCMA_CLNT_HDL_UNINITIALIZED;
			mutex_exit(&sol_ucma.ucma_mutex);
			return (ENODEV);
		}
		if ((sol_ucma.ucma_mod_hdl = ddi_modopen("drv/sol_uverbs",
		    KRTLD_MODE_FIRST, &ret_errno)) == NULL) {
			SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
			    "ddi_modopen(%s, ...) failed", "drv/sol_uverbs");
			(void) ldi_close(sol_ucma.ucma_ldi_hdl,
			    FREAD | FWRITE, kcred);
			sol_ofs_uobj_free(&new_filep->file_uobj);
			sol_ucma.ucma_clnt_hdl_flag =
			    SOL_UCMA_CLNT_HDL_UNINITIALIZED;
			mutex_exit(&sol_ucma.ucma_mutex);
			return (ret_errno);
		}
		if ((uverbs_get_hdl_fp = (uverbs_get_clnt_hdl_t)ddi_modsym(
		    sol_ucma.ucma_mod_hdl, SOL_UVERBS_GET_CLNT_HDL, &ret_errno))
		    == NULL) {
			SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
			    "ddi_modsym(%s, ...) failed",
			    SOL_UVERBS_GET_CLNT_HDL);
			(void) ddi_modclose(sol_ucma.ucma_mod_hdl);
			(void) ldi_close(sol_ucma.ucma_ldi_hdl,
			    FREAD | FWRITE, kcred);
			sol_ofs_uobj_free(&new_filep->file_uobj);
			sol_ucma.ucma_clnt_hdl_flag =
			    SOL_UCMA_CLNT_HDL_UNINITIALIZED;
			mutex_exit(&sol_ucma.ucma_mutex);
			return (ret_errno);
		}
		if ((uverbs_qpnum2qphdl_fp = (uverbs_qpnum2qphdl_t)ddi_modsym(
		    sol_ucma.ucma_mod_hdl, SOL_UVERBS_QPNUM2QPHDL, &ret_errno))
		    == NULL) {
			SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
			    "ddi_modsym(%s, ...) failed",
			    SOL_UVERBS_QPNUM2QPHDL);
			(void) ddi_modclose(sol_ucma.ucma_mod_hdl);
			(void) ldi_close(sol_ucma.ucma_ldi_hdl,
			    FREAD | FWRITE, kcred);
			sol_ofs_uobj_free(&new_filep->file_uobj);
			sol_ucma.ucma_clnt_hdl_flag =
			    SOL_UCMA_CLNT_HDL_UNINITIALIZED;
			mutex_exit(&sol_ucma.ucma_mutex);
			return (ret_errno);
		}
		if ((uverbs_disable_uqpn_modify_fp =
		    (uverbs_disable_uqpn_mod_t)ddi_modsym(
		    sol_ucma.ucma_mod_hdl, SOL_UVERBS_DISABLE_UQPN_MODIFY,
		    &ret_errno)) == NULL) {
			SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
			    "ddi_modsym(%s, ...) failed",
			    SOL_UVERBS_DISABLE_UQPN_MODIFY);
			(void) ddi_modclose(sol_ucma.ucma_mod_hdl);
			(void) ldi_close(sol_ucma.ucma_ldi_hdl,
			    FREAD | FWRITE, kcred);
			sol_ofs_uobj_free(&new_filep->file_uobj);
			sol_ucma.ucma_clnt_hdl_flag =
			    SOL_UCMA_CLNT_HDL_UNINITIALIZED;
			mutex_exit(&sol_ucma.ucma_mutex);
			return (ret_errno);
		}
		if ((uverbs_uqpn_cq_ctrl_fp =
		    (uverbs_uqpn_cq_ctrl_t)ddi_modsym(
		    sol_ucma.ucma_mod_hdl, SOL_UVERBS_UQPN_CQ_CTRL,
		    &ret_errno)) == NULL) {
			SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
			    "ddi_modsym(%s, ...) failed",
			    SOL_UVERBS_UQPN_CQ_CTRL);
			(void) ddi_modclose(sol_ucma.ucma_mod_hdl);
			(void) ldi_close(sol_ucma.ucma_ldi_hdl,
			    FREAD | FWRITE, kcred);
			sol_ofs_uobj_free(&new_filep->file_uobj);
			sol_ucma.ucma_clnt_hdl_flag =
			    SOL_UCMA_CLNT_HDL_UNINITIALIZED;
			mutex_exit(&sol_ucma.ucma_mutex);
			return (ret_errno);
		}
		if ((uverbs_set_qp_free_state_fp =
		    (uverbs_set_qp_free_state_t)ddi_modsym(
		    sol_ucma.ucma_mod_hdl, SOL_UVERBS_SET_QPFREE_STATE,
		    &ret_errno)) == NULL) {
			SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
			    "ddi_modsym(%s, ...) failed",
			    SOL_UVERBS_SET_QPFREE_STATE);
			(void) ddi_modclose(sol_ucma.ucma_mod_hdl);
			(void) ldi_close(sol_ucma.ucma_ldi_hdl,
			    FREAD | FWRITE, kcred);
			sol_ofs_uobj_free(&new_filep->file_uobj);
			sol_ucma.ucma_clnt_hdl_flag =
			    SOL_UCMA_CLNT_HDL_UNINITIALIZED;
			mutex_exit(&sol_ucma.ucma_mutex);
			return (ret_errno);
		}
		if ((uverbs_flush_qp_fp =
		    (uverbs_flush_qp_t)ddi_modsym(
		    sol_ucma.ucma_mod_hdl, SOL_UVERBS_FLUSH_QP,
		    &ret_errno)) == NULL) {
			SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
			    "ddi_modsym(%s, ...) failed",
			    SOL_UVERBS_FLUSH_QP);
			(void) ddi_modclose(sol_ucma.ucma_mod_hdl);
			(void) ldi_close(sol_ucma.ucma_ldi_hdl,
			    FREAD | FWRITE, kcred);
			sol_ofs_uobj_free(&new_filep->file_uobj);
			sol_ucma.ucma_clnt_hdl_flag =
			    SOL_UCMA_CLNT_HDL_UNINITIALIZED;
			mutex_exit(&sol_ucma.ucma_mutex);
			return (ret_errno);
		}

		(*uverbs_get_hdl_fp) (&sol_ucma.ucma_ib_clnt_hdl,
		    &sol_ucma.ucma_iw_clnt_hdl);
		if (sol_ucma.ucma_ib_clnt_hdl == NULL &&
		    sol_ucma.ucma_iw_clnt_hdl == NULL) {
			SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
			    "uverbs_get_clnt_hdl failed");
			(void) ddi_modclose(sol_ucma.ucma_mod_hdl);
			(void) ldi_close(sol_ucma.ucma_ldi_hdl,
			    FREAD | FWRITE, kcred);
			sol_ofs_uobj_free(&new_filep->file_uobj);
			sol_ucma.ucma_clnt_hdl_flag =
			    SOL_UCMA_CLNT_HDL_UNINITIALIZED;
			mutex_exit(&sol_ucma.ucma_mutex);
			return (ENODEV);
		}
		sol_ucma.ucma_clnt_hdl_flag =
		    SOL_UCMA_CLNT_HDL_INITIALIZED;
		cv_broadcast(&sol_ucma.ucma_open_cv);
	} else if (sol_ucma.ucma_clnt_hdl_flag ==
	    SOL_UCMA_CLNT_HDL_INITIALIZING) {
		cv_wait(&sol_ucma.ucma_open_cv, &sol_ucma.ucma_mutex);
	}
	mutex_exit(&sol_ucma.ucma_mutex);
	*devp = makedevice(getmajor(*devp), new_minor);

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "open Success");
	return (0);
}

static int
sol_ucma_close(dev_t dev, int flag, int otype, cred_t *credp)
{
	minor_t		minor;
	sol_ucma_file_t	*filep;
	genlist_entry_t	*entry;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "close(%x, %x, %x, %p)",
	    dev, flag, otype, credp);

	minor = getminor(dev);
	filep =  (sol_ucma_file_t *)sol_ofs_uobj_get_read(
	    &ucma_file_uo_tbl, minor);
	if (!filep) {
		SOL_OFS_DPRINTF_L4(sol_ucma_dbg_str, "close, no dev_t %x",
		    dev);
		return (0);
	}

	/* Disable further event handling for this CM event channel */
	mutex_enter(&filep->file_mutex);
	if (filep->file_evt_close_flag == SOL_UCMA_EVT_PROGRESS) {
		cv_wait(&filep->file_evt_close_cv, &filep->file_mutex);
	}
	filep->file_evt_close_flag = SOL_UCMA_EVT_DISABLED;
	mutex_exit(&filep->file_mutex);

	/*
	 * Destroy CM IDs which have not been destroyed.
	 * For CMIDs which have been connected, call
	 * uverbs_set_qp_free_state(SOL_UVERBS2UCMA_ENABLE_QP_FREE)
	 * so that QP free will be done when appropriate,
	 */
	entry = remove_genlist_head(&filep->file_id_list);
	while (entry) {
		sol_ucma_chan_t	*chanp;
		void		*qphdl;

		chanp = (sol_ucma_chan_t *)entry->data;
		mutex_enter(&chanp->chan_mutex);
		if (chanp->chan_rdma_id)
			(chanp->chan_rdma_id)->context = NULL;
		mutex_exit(&chanp->chan_mutex);
		rdma_destroy_id(chanp->chan_rdma_id);

		mutex_enter(&chanp->chan_mutex);
		qphdl = chanp->chan_qp_hdl;
		chanp->chan_qp_hdl = NULL;
		mutex_exit(&chanp->chan_mutex);
		if (qphdl)
			(*uverbs_set_qp_free_state_fp) (
			    SOL_UVERBS2UCMA_ENABLE_QP_FREE, 0, qphdl);
		ucma_free_chan(chanp, 1);

		entry = remove_genlist_head(&filep->file_id_list);
	}

	/* Flush out any events that have not been acknowledged. */
	mutex_enter(&filep->file_mutex);
	if (filep->file_pending_evt_cnt) {
		sol_ucma_event_t	*evtp;

		SOL_OFS_DPRINTF_L3(sol_ucma_dbg_str,
		    "close : %d Events not reported to userland",
		    filep->file_pending_evt_cnt);
		entry = remove_genlist_head(&filep->file_evt_list);
		while (entry) {
			evtp = (sol_ucma_event_t *)entry->data;
			kmem_free(evtp, sizeof (sol_ucma_event_t));
			kmem_free(entry, sizeof (genlist_entry_t));
			entry = remove_genlist_head(&filep->file_evt_list);
		};
		mutex_exit(&filep->file_mutex);
	}

	/*
	 * Module close for sol_uverbs when the last file is closed.
	 * Set the function pointers to sol_uverbs API to NULL
	 * ddi_modclose() and ldi_close() - sol_uverbs driver
	 */
	mutex_enter(&sol_ucma.ucma_mutex);
	if (sol_ucma.ucma_num_file == 1) {
		sol_ucma.ucma_clnt_hdl_flag =
		    SOL_UCMA_CLNT_HDL_UNINITIALIZED;
		uverbs_get_hdl_fp = NULL;
		uverbs_qpnum2qphdl_fp = NULL;
		uverbs_disable_uqpn_modify_fp = NULL;
		uverbs_uqpn_cq_ctrl_fp = NULL;
		uverbs_uqpn_cq_ctrl_fp  = NULL;
		uverbs_set_qp_free_state_fp = NULL;
		uverbs_flush_qp_fp = NULL;
		sol_ucma.ucma_ib_clnt_hdl = NULL;
		sol_ucma.ucma_iw_clnt_hdl = NULL;
		(void) ddi_modclose(sol_ucma.ucma_mod_hdl);
		(void) ldi_close(sol_ucma.ucma_ldi_hdl,
		    FREAD | FWRITE, kcred);
	}
	sol_ucma.ucma_num_file--;
	mutex_exit(&sol_ucma.ucma_mutex);

	kmem_free(filep->file_pollhead, sizeof (struct pollhead));
	sol_ofs_uobj_put(&filep->file_uobj);
	mutex_destroy(&filep->file_mutex);
	cv_destroy(&filep->file_evt_cv);
	cv_destroy(&filep->file_evt_close_cv);
	rw_enter(&(filep->file_uobj.uo_lock), RW_WRITER);
	(void) sol_ofs_uobj_remove(&ucma_file_uo_tbl, &(filep->file_uobj));
	rw_exit(&(filep->file_uobj.uo_lock));
	sol_ofs_uobj_free(&(filep->file_uobj));
	return (0);
}

typedef struct sol_ucma_cmd_table_s {
	int	(*sol_ucma_cmd_fnc)	(dev_t, void *, struct uio *);
	uint16_t	sol_ucma_in_len;
	uint16_t	sol_ucma_out_len;
} sol_ucma_cmd_table_t;

static  sol_ucma_cmd_table_t	sol_ucma_cmd_table[] = {
	[RDMA_USER_CM_CMD_CREATE_ID]	= sol_ucma_create_id,
	    sizeof (sol_ucma_create_id_t),
	    sizeof (sol_ucma_create_id_resp_t),
	[RDMA_USER_CM_CMD_DESTROY_ID]	= sol_ucma_destroy_id,
	    sizeof (sol_ucma_destroy_id_t),
	    sizeof (sol_ucma_destroy_id_resp_t),
	[RDMA_USER_CM_CMD_BIND_ADDR]	= sol_ucma_bind_addr,
	    sizeof (sol_ucma_bind_addr_t),
	    0,
	[RDMA_USER_CM_CMD_RESOLVE_ADDR]	= sol_ucma_resolve_addr,
	    sizeof (sol_ucma_resolve_addr_t),
	    0,
	[RDMA_USER_CM_CMD_RESOLVE_ROUTE] = sol_ucma_resolve_route,
	    sizeof (sol_ucma_resolve_route_t),
	    0,
	[RDMA_USER_CM_CMD_QUERY_ROUTE]	= sol_ucma_query_route,
	    sizeof (sol_ucma_query_route_t),
	    sizeof (sol_ucma_query_route_resp_t),
	[RDMA_USER_CM_CMD_CONNECT]	= sol_ucma_connect,
	    sizeof (sol_ucma_connect_t),
	    0,
	[RDMA_USER_CM_CMD_LISTEN]	= sol_ucma_listen,
	    sizeof (sol_ucma_listen_t),
	    0,
	[RDMA_USER_CM_CMD_ACCEPT]	= sol_ucma_accept,
	    sizeof (sol_ucma_accept_t),
	    0,
	[RDMA_USER_CM_CMD_REJECT]	= sol_ucma_reject,
	    sizeof (sol_ucma_reject_t),
	    0,
	[RDMA_USER_CM_CMD_DISCONNECT]	= sol_ucma_disconnect,
	    sizeof (sol_ucma_disconnect_t),
	    0,
	[RDMA_USER_CM_CMD_INIT_QP_ATTR]	= sol_ucma_init_qp_attr,
	    sizeof (sol_ucma_init_qp_attr_t),
	    sizeof (struct ib_uverbs_qp_attr),
	[RDMA_USER_CM_CMD_GET_EVENT]	= sol_ucma_get_event,
	    sizeof (sol_ucma_get_event_t),
	    sizeof (sol_ucma_event_resp_t),
	[RDMA_USER_CM_CMD_GET_OPTION]	= NULL,
	    0,
	    0,
	[RDMA_USER_CM_CMD_SET_OPTION]	= sol_ucma_set_option,
	    sizeof (sol_ucma_set_option_t),
	    0,
	[RDMA_USER_CM_CMD_NOTIFY]	= sol_ucma_notify,
	    sizeof (sol_ucma_notify_t),
	    0,
	[RDMA_USER_CM_CMD_JOIN_MCAST]	= sol_ucma_join_mcast,
	    sizeof (sol_ucma_join_mcast_t),
	    sizeof (sol_ucma_create_id_resp_t),
	[RDMA_USER_CM_CMD_LEAVE_MCAST]	= sol_ucma_leave_mcast,
	    sizeof (sol_ucma_destroy_id_t),
	    sizeof (sol_ucma_destroy_id_resp_t)
};

#define	SOL_UCMA_MAX_CMD_DATA    512
static int
sol_ucma_write(dev_t dev, struct uio *uio,  cred_t *credp)
{
	sol_ucma_cmd_hdr_t	*user_hdrp;
	int			ret;
	void			*data_buf = NULL;
	char			uio_data[SOL_UCMA_MAX_CMD_DATA];
	size_t			uio_data_len = uio->uio_resid;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "write(%x, %p, %p)",
	    dev, uio, credp);

	ret = uiomove((caddr_t)&uio_data, uio_data_len, UIO_WRITE, uio);
	user_hdrp = (sol_ucma_cmd_hdr_t *)uio_data;

	if (ret != 0) {
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str, "write: uiomove failed");
		return (ret);
	}

	if (user_hdrp->cmd >=
	    sizeof (sol_ucma_cmd_table) / sizeof (sol_ucma_cmd_table_t)) {
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
		    "open : cmd out of bound 0x%x", user_hdrp->cmd);
		return (EINVAL);
	}
	if (!(sol_ucma_cmd_table[user_hdrp->cmd].sol_ucma_cmd_fnc)) {
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
		    "open : Unsupported cmd 0x%x", user_hdrp->cmd);
		return (EINVAL);
	}

	/*
	 * Check the user passed IN-OUT buffer length, with expected lengths
	 */
	if (sol_ucma_cmd_table[user_hdrp->cmd].sol_ucma_in_len !=
	    (user_hdrp->in)) {
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
		    "write : Invalid Input length cmd %x, in %x expected %x",
		    user_hdrp->cmd, user_hdrp->in,
		    sol_ucma_cmd_table[user_hdrp->cmd].sol_ucma_in_len);
		return (EINVAL);
	}

	if (sol_ucma_cmd_table[user_hdrp->cmd].sol_ucma_out_len !=
	    (user_hdrp->out)) {
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
		    "write : Invalid Output length cmd %x, in %x expected %x",
		    user_hdrp->cmd, user_hdrp->out,
		    sol_ucma_cmd_table[user_hdrp->cmd].sol_ucma_out_len);
		return (EINVAL);
	}


	if (user_hdrp->in) {
		data_buf = (void *)((char *)uio_data +
		    sizeof (sol_ucma_cmd_hdr_t));
	}

	ret = (sol_ucma_cmd_table[user_hdrp->cmd].sol_ucma_cmd_fnc)
	    (dev, data_buf, uio);

	/* If the command fails, set back the uio_resid */
	if (ret)
		uio->uio_resid += uio_data_len;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "write : ret %x", ret);
	return (ret);
}

static int
sol_ucma_poll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	minor_t		minor = getminor(dev);
	sol_ucma_file_t	*filep;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "poll(%x, %x)",
	    dev, events);
	if (!(events & (POLLIN | POLLRDNORM)))
		return (EINVAL);

	filep =  (sol_ucma_file_t *)sol_ofs_uobj_get_read(
	    &ucma_file_uo_tbl, minor);
	ASSERT(filep);

	if (filep->file_pending_evt_cnt) {
		*reventsp = POLLIN | POLLRDNORM;
	} else {
		*reventsp = 0;
	}
	if ((*reventsp == 0 && !anyyet) || (events && POLLET)) {
		*phpp = filep->file_pollhead;
	}
	sol_ofs_uobj_put(&filep->file_uobj);

	return (0);
}

/*
 * RDMACM functions.
 */
/*ARGSUSED*/
static int
sol_ucma_create_id(dev_t dev, void *io_buf, struct uio *uio)
{
	minor_t		minor = getminor(dev);
	sol_ucma_file_t	*filep;
	sol_ucma_chan_t *chanp;
	sol_ucma_create_id_t		*ucma_id_inp;
	sol_ucma_create_id_resp_t	ucma_id_resp;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "create_id(%x, %p), minor %x",
	    dev, io_buf, minor);

	ucma_id_inp = (sol_ucma_create_id_t *)io_buf;
	ASSERT(ucma_id_inp);
	ASSERT(ucma_id_inp->response.r_laddr);

	filep =  (sol_ucma_file_t *)sol_ofs_uobj_get_read(&ucma_file_uo_tbl,
	    minor);
	ASSERT(filep);

	chanp = ucma_alloc_chan(filep, ucma_id_inp);
	if (chanp == NULL)  {
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
		    "create_id: No free Channel");
		sol_ofs_uobj_put(&filep->file_uobj);
		return (ENODEV);
	}
	ucma_id_resp.id = chanp->chan_id;

#ifdef	_LP64
	if (copyout(&ucma_id_resp, (void *)(ucma_id_inp->response.r_laddr),
	    sizeof (sol_ucma_create_id_resp_t))) {
#else
	if (copyout(&ucma_id_resp, (void *)(ucma_id_inp->response.r_addr),
	    sizeof (sol_ucma_create_id_resp_t))) {
#endif
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
		    "create_id: copyout fault");
		ucma_free_chan(chanp, 1);
		sol_ofs_uobj_put(&filep->file_uobj);
		return (EFAULT);
	}
/* */

	chanp->chan_rdma_id = rdma_create_id(sol_ucma_evt_hdlr,
	    chanp, ucma_id_inp->ps);
	if (chanp->chan_rdma_id == NULL) {
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
		    "create_id: rdma_create_id failed");
		ucma_free_chan(chanp, 1);
		sol_ofs_uobj_put(&filep->file_uobj);
		return (EINVAL);
	}
	mutex_enter(&chanp->chan_mutex);
	(chanp->chan_rdma_id)->context = chanp;
	mutex_exit(&chanp->chan_mutex);
	rdma_map_id2clnthdl(chanp->chan_rdma_id, sol_ucma.ucma_ib_clnt_hdl,
	    sol_ucma.ucma_iw_clnt_hdl);

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "create_id: Return SUCCESS");
	sol_ofs_uobj_put(&filep->file_uobj);
	return (0);
}

/*ARGSUSED*/
static int
sol_ucma_destroy_id(dev_t dev, void *io_buf, struct uio *uio)
{
	sol_ucma_chan_t 	*chanp;
	uint32_t		ucma_id;
	sol_ucma_file_t		*filep;
	sol_ucma_destroy_id_t	*id_inp;
	minor_t			minor;
	genlist_entry_t		*entry;
	sol_ucma_destroy_id_resp_t	id_resp;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "destroy_id(%x, %p)",
	    dev, io_buf);

	id_inp = (sol_ucma_destroy_id_t *)io_buf;
	ucma_id = id_inp->id;
	if (!get_file_chan(ucma_id, &filep, &chanp, "destroy_id", 0)) {
		minor = getminor(dev);
		filep =  (sol_ucma_file_t *)sol_ofs_uobj_get_read(
		    &ucma_file_uo_tbl, minor);
		if (!filep) {
			SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
			    "destroy_id : filep NULL");
			return (EINVAL);
		}
	} else {
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str, "destroy_id : "
		    "ucma_id %x invalid", ucma_id);
		return (0);
	}
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "destroy_id: chanp %p", chanp);

	/*
	 * Event handling, Flush out events pending
	 * return the number of events that were acked. Free events not acked.
	 */
	ASSERT(filep);
	mutex_enter(&filep->file_mutex);
	if (filep->file_pending_evt_cnt != 0) {
		SOL_OFS_DPRINTF_L4(sol_ucma_dbg_str,
		    "destroy_id: pending events");
		entry = remove_genlist_head(&filep->file_evt_list);
		while (entry) {
			kmem_free((void *) (entry->data),
			    sizeof (sol_ucma_event_t));
			kmem_free(entry, sizeof (genlist_entry_t));
			entry = remove_genlist_head(&filep->file_evt_list);
		};
		filep->file_pending_evt_cnt = 0;
	}
	if (chanp) {
		mutex_enter(&chanp->chan_mutex);
		id_resp.events_reported = chanp->chan_evt_cnt;
		mutex_exit(&chanp->chan_mutex);
	} else {
		id_resp.events_reported = 0;
	}
	mutex_exit(&filep->file_mutex);
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "destroy_id : chanp %p, "
	    "evts %x", chanp, id_resp.events_reported);

#ifdef	_LP64
	if (copyout(&id_resp, (void *) (id_inp->response.r_laddr),
	    sizeof (sol_ucma_destroy_id_resp_t))) {
#else
	if (copyout(&id_resp, (void *) (id_inp->response.r_addr),
	    sizeof (sol_ucma_destroy_id_resp_t))) {
#endif
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
		    "destroy_id: copyout fault");
		sol_ofs_uobj_put(&filep->file_uobj);
		return (EFAULT);
	}
/* */

	if (chanp) {
		mutex_enter(&chanp->chan_mutex);
		if (chanp->chan_rdma_id)
			(chanp->chan_rdma_id)->context = NULL;
		mutex_exit(&chanp->chan_mutex);
		rdma_destroy_id(chanp->chan_rdma_id);
		ucma_free_chan(chanp, 1);
	}

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "destroy_id: Success");
	sol_ofs_uobj_put(&filep->file_uobj);
	return (0);
}

/*ARGSUSED*/
static int
sol_ucma_bind_addr(dev_t dev, void *io_buf, struct uio *uio)
{
	int		ret;
	sol_ucma_chan_t	*chanp;
	uint32_t	ucma_id;
	sol_ucma_bind_addr_t	*bind_addrp;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "bind_addr(%x, %p)",
	    dev, io_buf);

	bind_addrp = (sol_ucma_bind_addr_t *)io_buf;
	ucma_id = bind_addrp->id;
	if (get_file_chan(ucma_id, NULL, &chanp, "bind_addr", 1))
		return (EINVAL);
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "bind_addr - chanp %p", chanp);

	ret = rdma_bind_addr(chanp->chan_rdma_id,
	    (struct sockaddr *)&bind_addrp->addr);
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "bind_addr: ret %x", ret);
	return (ret);
}

/*ARGSUSED*/
static int
sol_ucma_resolve_addr(dev_t dev, void *io_buf, struct uio *uio)
{
	sol_ucma_chan_t	*chanp;
	uint32_t	ucma_id;
	int		ret;
	sol_ucma_resolve_addr_t	*resolve_addrp;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "resolve_addr(%x, %p)",
	    dev, io_buf);

	resolve_addrp = (sol_ucma_resolve_addr_t *)io_buf;
	ucma_id  = resolve_addrp->id;
	if (get_file_chan(ucma_id, NULL, &chanp, "resolve_addr", 1)) {
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
		    "resolve_addr: ucma_id %x invalid", ucma_id);
		return (EINVAL);
	}
	ASSERT(chanp);
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "resolve_addr - chanp %p", chanp);

	ret = rdma_resolve_addr(chanp->chan_rdma_id,
	    (struct sockaddr *)&resolve_addrp->src_addr,
	    (struct sockaddr *)&resolve_addrp->dst_addr,
	    resolve_addrp->timeout_ms);
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "resolve_addr: ret %x", ret);
	return (ret);
}

/*ARGSUSED*/
static int
sol_ucma_resolve_route(dev_t dev, void *io_buf, struct uio *uio)
{
	sol_ucma_chan_t	*chanp;
	uint32_t	ucma_id;
	int		ret;
	sol_ucma_resolve_route_t	*resolve_routep;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str,
	    "resolve_route(%x, %p)", dev, io_buf);

	resolve_routep = (sol_ucma_resolve_route_t *)io_buf;
	ucma_id  = resolve_routep->id;
	if (get_file_chan(ucma_id, NULL, &chanp, "resolve_route", 1))
		return (EINVAL);
	ASSERT(chanp);
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "resolve_route - chanp %p",
	    chanp);

	ret = rdma_resolve_route(chanp->chan_rdma_id,
	    resolve_routep->timeout_ms);
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "resolve_route: ret %x", ret);
	return (ret);
}

/*ARGSUSED*/
static int
sol_ucma_query_route(dev_t dev, void *io_buf, struct uio *uio)
{
	sol_ucma_chan_t			*chanp;
	uint32_t			ucma_id;
	struct rdma_cm_id		*idp;
	sol_ucma_query_route_t		*query_routep;
	sol_ucma_query_route_resp_t	route_info;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "query_route(%x, %p)",
	    dev, io_buf);

	query_routep = (sol_ucma_query_route_t *)io_buf;
	ucma_id  = query_routep->id;
	if (get_file_chan(ucma_id, NULL, &chanp, "query_route", 1))
		return (EINVAL);
	ASSERT(chanp);
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "query_route - chanp %p", chanp);
	idp = chanp->chan_rdma_id;

	bzero(&route_info, sizeof (route_info));
	rdma2usr_route(idp, &route_info);

#ifdef	_LP64
	if (copyout(&route_info, (void *) (query_routep->response.r_laddr),
	    sizeof (sol_ucma_query_route_resp_t))) {
#else
	if (copyout(&route_info, (void *) (query_routep->response.r_addr),
	    sizeof (sol_ucma_query_route_resp_t))) {
#endif
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
		    "query_route: copyout fault");
		return (EFAULT);
	}
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "query_route: Succcess");
	return (0);
}

/*ARGSUSED*/
static int
sol_ucma_connect(dev_t dev, void *io_buf, struct uio *uio)
{
	sol_ucma_chan_t		*chanp;
	uint32_t		ucma_id;
	int			ret;
	void			*qphdl;
	sol_ucma_connect_t	*connectp;
	struct rdma_conn_param	conn_param;
	struct rdma_cm_id	*idp;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "connect(%x, %p)",
	    dev, io_buf);

	connectp = (sol_ucma_connect_t *)io_buf;
	ucma_id  = connectp->id;
	if (get_file_chan(ucma_id, NULL, &chanp, "connect", 1))
		return (EINVAL);
	ASSERT(chanp);
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "connect - chanp %p", chanp);

	usr2rdma_conn_param(&(connectp->conn_param), &conn_param);
	ASSERT(uverbs_qpnum2qphdl_fp);
	ASSERT(uverbs_disable_uqpn_modify_fp);
	ASSERT(uverbs_uqpn_cq_ctrl_fp);
	qphdl = (*uverbs_qpnum2qphdl_fp) (conn_param.qp_num);
	if (qphdl == NULL) {
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str, "connect: "
		    "invalid QPNum %x", conn_param.qp_num);
		return (EINVAL);
	}
	(*uverbs_disable_uqpn_modify_fp) (conn_param.qp_num);
	rdma_map_id2qphdl(chanp->chan_rdma_id, qphdl);
	idp = chanp->chan_rdma_id;
	if (idp->ps == RDMA_PS_TCP)
		(void) (*uverbs_uqpn_cq_ctrl_fp) (conn_param.qp_num,
		    SOL_UVERBS2UCMA_CQ_NOTIFY_DISABLE);
	chanp->chan_qp_num = conn_param.qp_num;
	ret = rdma_connect(chanp->chan_rdma_id, &conn_param);

	/*
	 * rdma_connect() initiated for this CMID, disable sol_uverbs to
	 * free the QP assosiated with this CM ID.
	 */
	if (ret == 0 && idp->ps == RDMA_PS_TCP) {
		mutex_enter(&chanp->chan_mutex);
		chanp->chan_qp_hdl = qphdl;
		chanp->chan_flags |= SOL_UCMA_CHAN_CONNECT_FLAG;
		mutex_exit(&chanp->chan_mutex);
		(*uverbs_set_qp_free_state_fp) (
		    SOL_UVERBS2UCMA_DISABLE_QP_FREE, conn_param.qp_num,
		    NULL);
	}
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "connect: ret %x", ret);
	return (ret);
}

/*ARGSUSED*/
static int
sol_ucma_listen(dev_t dev, void *io_buf, struct uio *uio)
{
	sol_ucma_chan_t		*chanp;
	uint32_t		ucma_id;
	int			ret;
	sol_ucma_listen_t	*listenp;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "listen(%x, %p)",
	    dev, io_buf);

	listenp = (sol_ucma_listen_t *)io_buf;
	ucma_id  = listenp->id;
	if (get_file_chan(ucma_id, NULL, &chanp, "listen", 1))
		return (EINVAL);
	ASSERT(chanp);
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "listen - chanp %p", chanp);

	listenp->backlog = (listenp->backlog == 0 ||
	    listenp->backlog > SOL_UCMA_MAX_LISTEN) ?
	    SOL_UCMA_MAX_LISTEN : listenp->backlog;
	chanp->chan_backlog = listenp->backlog;

	ret = rdma_listen(chanp->chan_rdma_id, listenp->backlog);
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "listen: ret %x", ret);
	return (ret);
}

/*ARGSUSED*/
static int
sol_ucma_accept(dev_t dev, void *io_buf, struct uio *uio)
{
	int				ret;
	uint32_t		ucma_id;
	sol_ucma_chan_t	*chanp;
	void			*qphdl;
	sol_ucma_accept_t		*acpt;
	struct rdma_conn_param	conn_param;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "accept(%x, %p)",
	    dev, io_buf);

	acpt = (sol_ucma_accept_t *)io_buf;
	ucma_id = acpt->id;
	if (get_file_chan(ucma_id, NULL, &chanp, "accept", 1))
		return (EINVAL);
	ASSERT(chanp);
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "accept - chanp %p", chanp);

	if ((acpt->conn_param).valid) {
		struct rdma_cm_id	*idp;

		chanp->chan_user_id = acpt->uid;
		usr2rdma_conn_param(&acpt->conn_param, &conn_param);

		ASSERT(uverbs_qpnum2qphdl_fp);
		qphdl = (*uverbs_qpnum2qphdl_fp) (conn_param.qp_num);
		if (qphdl == NULL) {
			SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str, "accept: "
			    "invalid QPNum %x", conn_param.qp_num);
			return (EINVAL);
		}
		(*uverbs_disable_uqpn_modify_fp) (conn_param.qp_num);
		rdma_map_id2qphdl(chanp->chan_rdma_id, qphdl);
		idp = chanp->chan_rdma_id;
		if (idp->ps == RDMA_PS_TCP)
			(void) (*uverbs_uqpn_cq_ctrl_fp) (conn_param.qp_num,
			    SOL_UVERBS2UCMA_CQ_NOTIFY_DISABLE);
		chanp->chan_qp_num = conn_param.qp_num;
		ret = rdma_accept(chanp->chan_rdma_id, &conn_param);
	} else
		ret = rdma_accept(chanp->chan_rdma_id, NULL);

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "accept: ret %x", ret);
	return (ret);
}

/*ARGSUSED*/
static int
sol_ucma_reject(dev_t dev, void *io_buf, struct uio *uio)
{
	int		ret;
	uint32_t	ucma_id;
	sol_ucma_chan_t	*chanp;
	sol_ucma_reject_t	*rjct;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "reject(%x, %p)", dev, io_buf);

	rjct = (sol_ucma_reject_t *)io_buf;
	ucma_id = rjct->id;
	if (get_file_chan(ucma_id, NULL, &chanp, "reject", 1))
		return (EINVAL);
	ASSERT(chanp);
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "reject - chanp %p", chanp);

	ret = rdma_reject(chanp->chan_rdma_id, rjct->private_data,
	    rjct->private_data_len);

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "reject: ret %x", ret);
	return (ret);
}

/*ARGSUSED*/
static int
sol_ucma_init_qp_attr(dev_t dev, void *io_buf, struct uio *uio)
{
	int				ret;
	uint32_t			ucma_id;
	uint32_t			qp_attr_mask;
	sol_ucma_chan_t			*chanp;
	sol_ucma_init_qp_attr_t		*qp_attr_inp;
	struct ib_uverbs_qp_attr	uverbs_qp_attr;
	struct ib_qp_attr		qp_attr;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "init_qp_attr(%x, %p)",
	    dev, io_buf);

	qp_attr_inp = (sol_ucma_init_qp_attr_t *)io_buf;
	ucma_id = qp_attr_inp->id;
	if (get_file_chan(ucma_id, NULL, &chanp, "init_qp_attr", 1))
		return (EINVAL);
	ASSERT(chanp);
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "init_qp_attr - chanp %p", chanp);

	qp_attr.qp_state = qp_attr_inp->qp_state;
	if ((ret = rdma_init_qp_attr(chanp->chan_rdma_id, &qp_attr,
	    (int *)&qp_attr_mask)) != 0) {
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str, "init_qp_attr: ret %x, "
		    "mask %x", ret, qp_attr_mask);
		return (EINVAL);
	}
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "init_qp_attr: ret %x, mask %x",
	    ret, qp_attr_mask);

	bzero(&uverbs_qp_attr, sizeof (uverbs_qp_attr));
	uverbs_qp_attr.qp_attr_mask = qp_attr_mask;
	uverbs_qp_attr.qp_state = qp_attr.qp_state;
	uverbs_qp_attr.pkey_index = qp_attr.pkey_index;
	uverbs_qp_attr.port_num = qp_attr.port_num;
	uverbs_qp_attr.qp_access_flags = qp_attr.qp_access_flags;
	uverbs_qp_attr.qkey = qp_attr.qkey;
	uverbs_qp_attr.path_mtu = qp_attr.path_mtu;
	uverbs_qp_attr.dest_qp_num = qp_attr.dest_qp_num;
	uverbs_qp_attr.rq_psn = qp_attr.rq_psn;
	uverbs_qp_attr.max_dest_rd_atomic = qp_attr.max_dest_rd_atomic;
	uverbs_qp_attr.min_rnr_timer = qp_attr.min_rnr_timer;
	uverbs_qp_attr.ah_attr.dlid = qp_attr.ah_attr.dlid;
	if (qp_attr.ah_attr.ah_flags) {
		uverbs_qp_attr.ah_attr.is_global = 1;
		bcopy(&(qp_attr.ah_attr.grh.dgid),
		    &(uverbs_qp_attr.ah_attr.grh.dgid), 16);
		uverbs_qp_attr.ah_attr.grh.flow_label =
		    qp_attr.ah_attr.grh.flow_label;
		uverbs_qp_attr.ah_attr.grh.sgid_index =
		    qp_attr.ah_attr.grh.sgid_index;
		uverbs_qp_attr.ah_attr.grh.hop_limit =
		    qp_attr.ah_attr.grh.hop_limit;
		uverbs_qp_attr.ah_attr.grh.traffic_class =
		    qp_attr.ah_attr.grh.traffic_class;
	}
	uverbs_qp_attr.ah_attr.sl = qp_attr.ah_attr.sl;
	uverbs_qp_attr.ah_attr.src_path_bits = qp_attr.ah_attr.src_path_bits;
	uverbs_qp_attr.ah_attr.static_rate = qp_attr.ah_attr.static_rate;
	uverbs_qp_attr.ah_attr.port_num = qp_attr.ah_attr.port_num;

#ifdef	_LP64
	if (copyout(&uverbs_qp_attr, (void *) (qp_attr_inp->response.r_laddr),
	    sizeof (uverbs_qp_attr))) {
#else
	if (copyout(&uverbs_qp_attr, (void *) (qp_attr_inp->response.r_addr),
	    sizeof (uverbs_qp_attr))) {
#endif
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str, "init_qp_attr : copyout "
		    "failed");
		return (EFAULT);
	}
	return (0);
}

static int
sol_ucma_get_event(dev_t dev, void *io_buf, struct uio *uio)
{
	minor_t			minor;
	sol_ucma_file_t		*filep;
	sol_ucma_chan_t		*evt_chanp;
	genlist_entry_t		*entry;
	struct rdma_ucm_get_event	*user_evt_inp;
	sol_ucma_event_t		*queued_evt;
	struct rdma_ucm_event_resp	*user_evt_resp;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "get_event(%x, %p)", dev, io_buf);
	user_evt_inp = (struct rdma_ucm_get_event *)io_buf;

	minor = getminor(dev);
	filep =  (sol_ucma_file_t *)sol_ofs_uobj_get_read(&ucma_file_uo_tbl,
	    minor);
	ASSERT(filep);

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "get_event fmode %x",
	    uio->uio_fmode);

	mutex_enter(&filep->file_mutex);
	while (filep->file_pending_evt_cnt == 0) {
		SOL_OFS_DPRINTF_L4(sol_ucma_dbg_str, "get_event: No events");
		if (uio->uio_fmode & (FNONBLOCK | FNDELAY)) {
			mutex_exit(&filep->file_mutex);
			sol_ofs_uobj_put(&filep->file_uobj);
			SOL_OFS_DPRINTF_L4(sol_ucma_dbg_str,
			    "get_event: No events, nonblocking");
			return (EAGAIN);
		}
		if (!cv_wait_sig(&filep->file_evt_cv, &filep->file_mutex)) {
			mutex_exit(&filep->file_mutex);
			sol_ofs_uobj_put(&filep->file_uobj);
			SOL_OFS_DPRINTF_L3(sol_ucma_dbg_str,
			    "get_event: Got Sig");
			return (EINTR);
		}
	}

	entry = remove_genlist_head(&filep->file_evt_list);
	mutex_exit(&filep->file_mutex);
	ASSERT(entry);
	queued_evt = (sol_ucma_event_t *)entry->data;
	ASSERT(queued_evt);
	user_evt_resp = &queued_evt->event_resp;
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "event2usr "
	    "uid %llx, id %x, event %x, status %x", user_evt_resp->uid,
	    user_evt_resp->id, user_evt_resp->event, user_evt_resp->status);
#ifdef	_LP64
	if (copyout((void *)user_evt_resp,
	    (void *)(user_evt_inp->response.r_laddr),
	    sizeof (sol_ucma_event_resp_t))) {
#else
	if (copyout((void *)user_evt_resp,
	    (void *)(user_evt_inp->response.r_addr),
	    sizeof (sol_ucma_event_resp_t))) {
#endif
		SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "get_event: copyout "
		    "failed");
		sol_ofs_uobj_put(&filep->file_uobj);
		kmem_free(entry, sizeof (genlist_entry_t));
		return (EFAULT);
	}
	mutex_enter(&filep->file_mutex);
	filep->file_pending_evt_cnt--;
	if (queued_evt->event_mcast)
		(queued_evt->event_mcast)->mcast_events++;
	evt_chanp = queued_evt->event_chan;
	if (evt_chanp) {
		/*
		 * If the event is RDMA_CM_EVENT_CONNECT_RESPONSE or
		 * RDMA_CM_EVENT_ESTABLISHED and the CM ID is for RC,
		 * enable completion notifications for the QP.
		 */
		if (user_evt_resp->event == RDMA_CM_EVENT_CONNECT_RESPONSE ||
		    user_evt_resp->event == RDMA_CM_EVENT_ESTABLISHED) {
			struct rdma_cm_id	*idp;
			int	rc;

			idp = evt_chanp->chan_rdma_id;
			if (idp->ps == RDMA_PS_TCP) {
				ASSERT(uverbs_uqpn_cq_ctrl_fp);
				rc = (*uverbs_uqpn_cq_ctrl_fp)(
				    evt_chanp->chan_qp_num,
				    SOL_UVERBS2UCMA_CQ_NOTIFY_ENABLE);
				if (rc) {
					SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
					    "uverbs_uqpn_cq_ctrl_fp(%X) "
					    "failed!!",
					    evt_chanp->chan_qp_num);
					mutex_exit(&filep->file_mutex);
					filep->file_pending_evt_cnt++;
					return (EIO);
				}
			}
		}

		/* Bump up backlog for CONNECT_REQUEST events */
		mutex_enter(&evt_chanp->chan_mutex);
		if (user_evt_resp->event == RDMA_CM_EVENT_CONNECT_REQUEST)
			evt_chanp->chan_backlog++;

		evt_chanp->chan_evt_cnt++;
		mutex_exit(&evt_chanp->chan_mutex);
		SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "get_event : "
		    "chan %p, cnt %x", evt_chanp, evt_chanp->chan_evt_cnt);
	}
	mutex_exit(&filep->file_mutex);
	kmem_free(entry, sizeof (genlist_entry_t));
	kmem_free(queued_evt, sizeof (sol_ucma_event_t));

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "get_event: Success");
	sol_ofs_uobj_put(&filep->file_uobj);
	return (0);
}

/*
 * This is used when ULP wants to set the QOS option. This is *not*
 * supported by Solaris IB stack, return failure.
 */
/*ARGSUSED*/
static int
sol_ucma_set_option(dev_t dev, void *io_buf, struct uio *uio)
{
		return (EINVAL);
}

/*
 * This is used when ULP uses librdmacm but uses out of band connection for CM.
 */
/*ARGSUSED*/
static int
sol_ucma_notify(dev_t dev, void *io_buf, struct uio *uio)
{
	sol_ucma_notify_t	*notifyp;
	uint32_t			ucma_id;
	sol_ucma_chan_t		*chan;
	int					ret;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "notify(%x, %p)", dev, io_buf);
	notifyp = (sol_ucma_notify_t *)io_buf;
	ucma_id = notifyp->id;
	if (get_file_chan(ucma_id, NULL, &chan, "notify", 1))
		return (EINVAL);
	ASSERT(chan);

	ret = rdma_notify(chan->chan_rdma_id, notifyp->event);
	if (ret)
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str, "notify failed %x", ret);
	else
		SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "notify Success");
	return (ret);
}

/*ARGSUSED*/
static int
sol_ucma_join_mcast(dev_t dev, void *io_buf, struct uio *uio)
{
	sol_ucma_join_mcast_t		*join_buf;
	sol_ucma_create_id_resp_t	join_resp;
	sol_ucma_chan_t			*chanp;
	sol_ucma_mcast_t		*mcastp;
	int		rc;
	uint32_t	ucma_id;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "join_mcast(%x, %p)",
	    dev, io_buf);
	join_buf = (sol_ucma_join_mcast_t *)io_buf;
	ucma_id = join_buf->id;
	if (get_file_chan(ucma_id, NULL, &chanp, "join_mcast", 1))
		return (EINVAL);

	mcastp = kmem_zalloc(sizeof (sol_ucma_mcast_t), KM_SLEEP);
	bcopy((void *)(&(join_buf->addr)), (void *)(&(mcastp->mcast_addr)),
	    sizeof (struct sockaddr));
	mcastp->mcast_chan = chanp;
	sol_ofs_uobj_init(&mcastp->mcast_uobj, NULL, SOL_UCMA_MCAST_TYPE);
	if (sol_ofs_uobj_add(&ucma_mcast_uo_tbl, &mcastp->mcast_uobj) != 0) {
		sol_ofs_uobj_free(&mcastp->mcast_uobj);
		return (ENOMEM);
	}
	mcastp->mcast_uobj.uo_live = 1;
	mcastp->mcast_id = join_resp.id = mcastp->mcast_uobj.uo_id;
	mcastp->mcast_uid = join_buf->uid;

	rc = rdma_join_multicast(chanp->chan_rdma_id,
	    (struct sockaddr *)(&(join_buf->addr)), mcastp);
	if (rc) {
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
		    "join_mcast: rdma_join_multicast ret %x", rc);
		rw_enter(&(mcastp->mcast_uobj.uo_lock), RW_WRITER);
		(void) sol_ofs_uobj_remove(&ucma_mcast_uo_tbl,
		    &mcastp->mcast_uobj);
		rw_exit(&(mcastp->mcast_uobj.uo_lock));
		sol_ofs_uobj_free(&mcastp->mcast_uobj);
		return (rc);
	}

#ifdef	_LP64
	if (copyout(&join_resp, (void *) (join_buf->response.r_laddr),
	    sizeof (sol_ucma_create_id_resp_t))) {
#else
	if (copyout(&join_resp, (void *) (join_buf->response.r_addr),
	    sizeof (sol_ucma_create_id_resp_t))) {
#endif
		SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "join_mcast: copyout "
		    "failed");
		rdma_leave_multicast(chanp->chan_rdma_id,
		    (struct sockaddr *)(&(join_buf->addr)));
		rw_enter(&(mcastp->mcast_uobj.uo_lock), RW_WRITER);
		(void) sol_ofs_uobj_remove(&ucma_mcast_uo_tbl,
		    &mcastp->mcast_uobj);
		rw_exit(&(mcastp->mcast_uobj.uo_lock));
		sol_ofs_uobj_free(&mcastp->mcast_uobj);
		return (EFAULT);
	}
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "join_mcast: Return Success");
	return (0);
}

/*ARGSUSED*/
static int
sol_ucma_leave_mcast(dev_t dev, void *io_buf, struct uio *uio)
{
	sol_ucma_destroy_id_t		*id_inp;
	sol_ucma_destroy_id_resp_t	id_resp;
	sol_ucma_mcast_t		*mcastp;
	sol_ucma_chan_t			*chanp;
	uint32_t			ucma_id;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "leave_mcast(%x, %p)",
	    dev, io_buf);
	id_inp = (sol_ucma_destroy_id_t *)io_buf;
	ucma_id = id_inp->id;
	mcastp = (sol_ucma_mcast_t *)sol_ofs_uobj_get_read(&ucma_mcast_uo_tbl,
	    ucma_id);
	if (mcastp == NULL) {
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str, "leave_mcast: invalid "
		    "ID %x", ucma_id);
		return (EINVAL);
	}
	chanp = mcastp->mcast_chan;

	rdma_leave_multicast(chanp->chan_rdma_id, &mcastp->mcast_addr);
	id_resp.events_reported = mcastp->mcast_events;

#ifdef	_LP64
	if (copyout(&id_resp, (void *) (id_inp->response.r_laddr),
	    sizeof (sol_ucma_destroy_id_resp_t))) {
#else
	if (copyout(&id_resp, (void *) (id_inp->response.r_addr),
	    sizeof (sol_ucma_destroy_id_resp_t))) {
#endif
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str, "leave_mcast: copyout "
		    "fault");
		sol_ofs_uobj_put(&mcastp->mcast_uobj);
		return (EFAULT);
	}
	sol_ofs_uobj_put(&mcastp->mcast_uobj);
	rw_enter(&(mcastp->mcast_uobj.uo_lock), RW_WRITER);
	(void) sol_ofs_uobj_remove(&ucma_mcast_uo_tbl, &mcastp->mcast_uobj);
	rw_exit(&(mcastp->mcast_uobj.uo_lock));
	sol_ofs_uobj_free(&mcastp->mcast_uobj);
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "leave_mcast: ret 0");
	return (0);
}

/*ARGSUSED*/
static int
sol_ucma_disconnect(dev_t dev, void *io_buf, struct uio *uio)
{
	sol_ucma_disconnect_t	*disconnectp;
	uint32_t	ucma_id;
	sol_ucma_chan_t	*chan;
	int		ret;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "disconnect(%x, %p)",
	    dev, io_buf);
	disconnectp = (sol_ucma_disconnect_t *)io_buf;
	ucma_id = disconnectp->id;
	if (get_file_chan(ucma_id, NULL, &chan, "disconnect", 1))
		return (EINVAL);
	ASSERT(chan);

	/*
	 * For a TCP CMID, which has got the DISCONNECT event, call
	 * ibt_flush_qp(), to transition QP to error state.
	 */
	mutex_enter(&chan->chan_mutex);
	if (chan->chan_flush_qp_flag == SOL_UCMA_FLUSH_QP_PENDING) {
		chan->chan_flush_qp_flag = SOL_UCMA_FLUSH_QP_DONE;
		mutex_exit(&chan->chan_mutex);
		(*uverbs_flush_qp_fp)(chan->chan_qp_num);
	} else
		mutex_exit(&chan->chan_mutex);

	ret = rdma_disconnect(chan->chan_rdma_id);
	mutex_enter(&chan->chan_mutex);
	chan->chan_flush_qp_flag = SOL_UCMA_FLUSH_QP_DONE;
	mutex_exit(&chan->chan_mutex);
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "disconnect: ret %x", ret);
	return (ret);
}

/*
 * RDMA ID Event handler
 */
int
sol_ucma_evt_hdlr(struct rdma_cm_id *idp, struct rdma_cm_event *eventp)
{
	sol_ucma_chan_t		*chan, *req_chan;
	sol_ucma_file_t		*file;
	sol_ucma_event_t	*ucma_evt;
	sol_ucma_create_id_t	ucma_create_id;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "ucma_evt_hdlr(%p, %p), "
	    "event %x, status %x", idp, eventp, eventp->event,
	    eventp->status);
	chan = (sol_ucma_chan_t *)idp->context;
	if (!chan) {
		SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str, "ucma_evt_hdlr() - "
		    "after destroy - %p", idp);
		return (0);
	}
	mutex_enter(&chan->chan_mutex);
	file = chan->chan_file;
	if (!file) {
		SOL_OFS_DPRINTF_L3(sol_ucma_dbg_str, "ucma_evt_hdlr() - "
		    "after file destroy - idp %p", idp);
		mutex_exit(&chan->chan_mutex);
		return (0);
	}
	mutex_exit(&chan->chan_mutex);

	mutex_enter(&file->file_mutex);
	if (file->file_evt_close_flag == SOL_UCMA_EVT_DISABLED) {
		SOL_OFS_DPRINTF_L3(sol_ucma_dbg_str, "ucma_evt_hdlr() - "
		    "after file close - idp %p", idp);
		mutex_exit(&file->file_mutex);
		return (0);
	}
	file->file_evt_close_flag = SOL_UCMA_EVT_PROGRESS;
	mutex_exit(&file->file_mutex);

	/*
	 * If the event is RDMA_CM_EVENT_CONNECT_REQUEST, allocate a
	 * new chan. The rdma_cm_id for this chan has already been
	 * allocated by sol_ofs.
	 */
	ucma_evt = kmem_zalloc(sizeof (sol_ucma_event_t), KM_SLEEP);
	ucma_evt->event_chan = chan;
	if (eventp->event == RDMA_CM_EVENT_CONNECT_REQUEST) {
		mutex_enter(&chan->chan_mutex);
		if (!chan->chan_backlog) {
			SOL_OFS_DPRINTF_L3(sol_ucma_dbg_str,
			    "backlog exceeded");
			mutex_exit(&chan->chan_mutex);
			mutex_enter(&file->file_mutex);
			file->file_evt_close_flag = SOL_UCMA_EVT_NONE;
			cv_broadcast(&file->file_evt_close_cv);
			mutex_exit(&file->file_mutex);
			kmem_free(ucma_evt, sizeof (sol_ucma_event_t));
			return (-1);
		}
		chan->chan_backlog--;
		mutex_exit(&chan->chan_mutex);
		ucma_create_id.uid = chan->chan_user_id;
		req_chan = ucma_alloc_chan(file, &ucma_create_id);
		if (req_chan == NULL)  {
			SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
			    "evt hdlr: No free Channel");
			sol_ofs_uobj_put(&file->file_uobj);
			mutex_enter(&file->file_mutex);
			file->file_evt_close_flag = SOL_UCMA_EVT_NONE;
			cv_broadcast(&file->file_evt_close_cv);
			mutex_exit(&file->file_mutex);
			return (-1);
		}
		req_chan->chan_rdma_id = idp;
		mutex_enter(&req_chan->chan_mutex);
		idp->context = req_chan;
		mutex_exit(&req_chan->chan_mutex);
		chan = req_chan;
	} else if (eventp->event == RDMA_CM_EVENT_DISCONNECTED ||
	    eventp->event == RDMA_CM_EVENT_REJECTED) {
		void	*qphdl;

		/*
		 * Connection has been rejected or disconnected,
		 * Enable uverbs to free QP, if it had been disabled
		 * before. sol_uverbs will free the QP appropriately.
		 */
		mutex_enter(&chan->chan_mutex);
		qphdl = chan->chan_qp_hdl;
		chan->chan_qp_hdl = NULL;
		if (idp->ps == RDMA_PS_TCP &&
		    chan->chan_flush_qp_flag != SOL_UCMA_FLUSH_QP_DONE &&
		    eventp->event == RDMA_CM_EVENT_DISCONNECTED) {
			chan->chan_flush_qp_flag =
			    SOL_UCMA_FLUSH_QP_PENDING;
		}
		mutex_exit(&chan->chan_mutex);

		if (idp->ps == RDMA_PS_TCP && qphdl)
			(*uverbs_set_qp_free_state_fp) (
			    SOL_UVERBS2UCMA_ENABLE_QP_FREE, 0, qphdl);
	} else if (eventp->event == RDMA_CM_EVENT_ESTABLISHED &&
	    chan->chan_flags & SOL_UCMA_CHAN_CONNECT_FLAG)
		eventp->event = RDMA_CM_EVENT_CONNECT_RESPONSE;

	ucma_evt->event_resp.event = eventp->event;
	ucma_evt->event_resp.status = eventp->status;
	if (idp->ps == RDMA_PS_UDP || idp->ps == RDMA_PS_IPOIB)
		rdma2usr_ud_param(&(eventp->param.ud),
		    &(ucma_evt->event_resp.param.ud));
	else
		rdma2usr_conn_param(&(eventp->param.conn),
		    &(ucma_evt->event_resp.param.conn));

	if (eventp->event == RDMA_CM_EVENT_MULTICAST_JOIN || eventp->event ==
	    RDMA_CM_EVENT_MULTICAST_ERROR) {
		ucma_evt->event_mcast = (sol_ucma_mcast_t *)
		    eventp->param.ud.private_data;
		ucma_evt->event_resp.uid = (ucma_evt->event_mcast)->mcast_uid;
		ucma_evt->event_resp.id = (ucma_evt->event_mcast)->mcast_id;
	} else {
		ucma_evt->event_resp.uid = chan->chan_user_id;
		ucma_evt->event_resp.id = chan->chan_id;
	}

	mutex_enter(&file->file_mutex);
	(void) add_genlist(&file->file_evt_list, (uintptr_t)ucma_evt, NULL);
	file->file_pending_evt_cnt++;
	mutex_exit(&file->file_mutex);
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "ucma_evt_hdlr-pollwakeup");
	pollwakeup(file->file_pollhead, POLLIN | POLLRDNORM);
	mutex_enter(&file->file_mutex);
	cv_broadcast(&file->file_evt_cv);
	mutex_exit(&file->file_mutex);

	mutex_enter(&file->file_mutex);
	file->file_evt_close_flag = SOL_UCMA_EVT_NONE;
	cv_broadcast(&file->file_evt_close_cv);
	mutex_exit(&file->file_mutex);
	return (0);
}

/*
 * Local Functions
 */
static sol_ucma_file_t *
ucma_alloc_file(minor_t *new_minorp)
{
	sol_ucma_file_t	*new_file;

	new_file = kmem_zalloc(sizeof (sol_ucma_file_t), KM_SLEEP);
	sol_ofs_uobj_init(&new_file->file_uobj, NULL, SOL_UCMA_EVT_FILE_TYPE);
	if (sol_ofs_uobj_add(&ucma_file_uo_tbl, &new_file->file_uobj) != 0) {
		sol_ofs_uobj_free(&new_file->file_uobj);
		return (NULL);
	}
	new_file->file_uobj.uo_live = 1;
	init_genlist(&new_file->file_id_list);
	init_genlist(&new_file->file_evt_list);

	mutex_enter(&sol_ucma.ucma_mutex);
	sol_ucma.ucma_num_file++;
	mutex_exit(&sol_ucma.ucma_mutex);
	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "new file num %x, %p",
	    (new_file->file_uobj).uo_id, new_file);

	mutex_init(&new_file->file_mutex, NULL,
	    MUTEX_DRIVER, NULL);
	cv_init(&new_file->file_evt_cv, NULL, CV_DRIVER,
	    NULL);
	cv_init(&new_file->file_evt_close_cv, NULL, CV_DRIVER,
	    NULL);
	new_file->file_pollhead = kmem_zalloc(sizeof (struct pollhead),
	    KM_SLEEP);

	*new_minorp = (minor_t)((new_file->file_uobj).uo_id);
	return (new_file);
}

static sol_ucma_chan_t *
ucma_alloc_chan(sol_ucma_file_t *filep, sol_ucma_create_id_t *create_id_inp)
{
	sol_ucma_chan_t		*new_chanp;

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "_alloc_chan(%p, %p)",
	    filep, create_id_inp);

	new_chanp = kmem_zalloc(sizeof (sol_ucma_chan_t), KM_SLEEP);
	sol_ofs_uobj_init(&new_chanp->chan_uobj, NULL, SOL_UCMA_CM_ID_TYPE);
	if (sol_ofs_uobj_add(&ucma_ctx_uo_tbl, &new_chanp->chan_uobj) != 0) {
		sol_ofs_uobj_free(&new_chanp->chan_uobj);
		return (NULL);
	}
	mutex_init(&new_chanp->chan_mutex, NULL, MUTEX_DRIVER, NULL);

	new_chanp->chan_uobj.uo_live = 1;
	mutex_enter(&filep->file_mutex);
	new_chanp->chan_list_ent = add_genlist(&filep->file_id_list,
	    (uintptr_t)new_chanp, NULL);
	mutex_exit(&filep->file_mutex);

	SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str, "_alloc_chan - filep %p, "
	    "chan_num %x, new_chan %p", filep, (new_chanp->chan_uobj).uo_id,
	    new_chanp);

	new_chanp->chan_file = filep;
	new_chanp->chan_user_id = create_id_inp->uid;
	new_chanp->chan_id = (new_chanp->chan_uobj).uo_id;

	return (new_chanp);
}

static void
ucma_free_chan(sol_ucma_chan_t *chanp, int delete_list)
{
	sol_ucma_file_t	*filep;

	ASSERT(chanp);
	if (delete_list) {
		filep = chanp->chan_file;
		ASSERT(filep);
		mutex_enter(&filep->file_mutex);
		delete_genlist(&filep->file_id_list, chanp->chan_list_ent);
		mutex_exit(&filep->file_mutex);
	}

	mutex_destroy(&chanp->chan_mutex);
	rw_enter(&(chanp->chan_uobj.uo_lock), RW_WRITER);
	(void) sol_ofs_uobj_remove(&ucma_ctx_uo_tbl, &(chanp->chan_uobj));
	rw_exit(&(chanp->chan_uobj.uo_lock));
	sol_ofs_uobj_free(&(chanp->chan_uobj));
}

static int
get_file_chan(uint32_t ucma_id, sol_ucma_file_t **filep,
    sol_ucma_chan_t **chanp, char *caller, int flag_err)
{
	sol_ucma_chan_t	*chan;

	if (filep)
		*filep = NULL;
	if (chanp)
		*chanp = NULL;

	chan = (sol_ucma_chan_t *)sol_ofs_uobj_get_read(&ucma_ctx_uo_tbl,
	    ucma_id);
	if (chan == NULL) {
		if (flag_err)
			SOL_OFS_DPRINTF_L2(sol_ucma_dbg_str,
			    "%s, ucma_id %x invalid", caller, ucma_id);
		else
			SOL_OFS_DPRINTF_L5(sol_ucma_dbg_str,
			    "%s, ucma_id %x invalid", caller, ucma_id);
		return (-1);
	}

	if (filep)
		*filep = chan->chan_file;
	if (chanp)
		*chanp = chan;

	sol_ofs_uobj_put(&chan->chan_uobj);
	return (0);
}

static void
rdma2usr_pathrec(struct ib_sa_path_rec *kern_path,
    struct ib_user_path_rec *usr_path)
{
	bcopy(&kern_path->dgid, &usr_path->dgid, 16);
	bcopy(&kern_path->sgid, &usr_path->sgid, 16);
	usr_path->dlid = kern_path->dlid;
	usr_path->slid = kern_path->slid;
	usr_path->raw_traffic = kern_path->raw_traffic;
	usr_path->flow_label = kern_path->flow_label;
	usr_path->reversible = kern_path->reversible;
	usr_path->mtu = kern_path->mtu;
	usr_path->pkey = kern_path->pkey;
	usr_path->hop_limit = kern_path->hop_limit;
	usr_path->traffic_class = kern_path->traffic_class;
	usr_path->sl = kern_path->sl;
	usr_path->mtu_selector = kern_path->mtu_selector;
	usr_path->rate_selector = kern_path->rate_selector;
	usr_path->rate = kern_path->rate;
	usr_path->packet_life_time_selector =
	    kern_path->packet_life_time_selector;
	usr_path->packet_life_time = kern_path->packet_life_time;
	usr_path->preference = kern_path->preference;
	usr_path->numb_path = kern_path->numb_path;
}

static void
rdma2usr_route(struct rdma_cm_id *idp, sol_ucma_query_route_resp_t *resp)
{
	struct rdma_route	*routep;
	int	i;

	routep = &(idp->route);
	if (idp->device) {
		resp->node_guid = idp->device->node_guid;
		resp->port_num = idp->port_num;
	}
	bcopy(&(routep->addr.src_addr), &resp->src_addr,
	    sizeof (struct sockaddr_in6));
	bcopy(&(routep->addr.dst_addr), &resp->dst_addr,
	    sizeof (struct sockaddr_in6));
	resp->num_paths = routep->num_paths;
	for (i = 0; i < resp->num_paths; i++) {
		rdma2usr_pathrec(&(routep->path_rec[i]),
		    &(resp->ib_route[i]));
	}
}

static void
usr2rdma_conn_param(struct rdma_ucm_conn_param *usr_conn_paramp,
    struct rdma_conn_param *conn_paramp)
{
	conn_paramp->private_data = usr_conn_paramp->private_data;
	conn_paramp->private_data_len = usr_conn_paramp->private_data_len;
	conn_paramp->responder_resources = usr_conn_paramp->responder_resources;
	conn_paramp->initiator_depth = usr_conn_paramp->initiator_depth;
	conn_paramp->flow_control = usr_conn_paramp->flow_control;
	conn_paramp->retry_count = usr_conn_paramp->retry_count;
	conn_paramp->rnr_retry_count = usr_conn_paramp->rnr_retry_count;
	conn_paramp->srq = usr_conn_paramp->srq;
	conn_paramp->qp_num = usr_conn_paramp->qp_num;
}

static void
rdma2usr_conn_param(struct rdma_conn_param *conn_paramp,
    struct rdma_ucm_conn_param *usr_conn_paramp)
{
	usr_conn_paramp->private_data_len = conn_paramp->private_data_len;

	bzero(usr_conn_paramp->private_data, RDMA_MAX_PRIVATE_DATA);
	if (conn_paramp->private_data)
		bcopy(conn_paramp->private_data,
		    usr_conn_paramp->private_data,
		    usr_conn_paramp->private_data_len);
	usr_conn_paramp->responder_resources = conn_paramp->responder_resources;
	usr_conn_paramp->initiator_depth = conn_paramp->initiator_depth;
	usr_conn_paramp->flow_control = conn_paramp->flow_control;
	usr_conn_paramp->retry_count = conn_paramp->retry_count;
	usr_conn_paramp->rnr_retry_count = conn_paramp->rnr_retry_count;
	usr_conn_paramp->srq = conn_paramp->srq;
	usr_conn_paramp->qp_num = conn_paramp->qp_num;
}

static void
rdma2usr_ud_param(struct rdma_ud_param *ud_paramp,
    sol_ucma_ud_param_t *usr_ud_paramp)
{
	struct ib_ah_attr		*ah_attrp;
	struct ib_uverbs_ah_attr	*usr_ah_attrp;

	usr_ud_paramp->private_data_len = ud_paramp->private_data_len;

	bzero(usr_ud_paramp->private_data, RDMA_MAX_PRIVATE_DATA);
	if (ud_paramp->private_data)
		bcopy(ud_paramp->private_data,
		    usr_ud_paramp->private_data,
		    usr_ud_paramp->private_data_len);
	usr_ud_paramp->qp_num = ud_paramp->qp_num;
	usr_ud_paramp->qkey = ud_paramp->qkey;

	ah_attrp = &(ud_paramp->ah_attr);
	usr_ah_attrp = &(usr_ud_paramp->ah_attr);
	bcopy(&(ah_attrp->grh.dgid), &(usr_ah_attrp->grh.dgid[0]), 16);
	usr_ah_attrp->grh.flow_label = ah_attrp->grh.flow_label;
	usr_ah_attrp->grh.sgid_index = ah_attrp->grh.sgid_index;
	usr_ah_attrp->grh.hop_limit = ah_attrp->grh.hop_limit;
	usr_ah_attrp->grh.traffic_class = ah_attrp->grh.traffic_class;
	usr_ah_attrp->dlid = ah_attrp->dlid;
	usr_ah_attrp->sl = ah_attrp->sl;
	usr_ah_attrp->src_path_bits = ah_attrp->src_path_bits;
	usr_ah_attrp->static_rate = ah_attrp->static_rate;
	usr_ah_attrp->is_global = ah_attrp->ah_flags;
	usr_ah_attrp->port_num = ah_attrp->port_num;
}

static void
sol_ucma_user_objs_init()
{
	sol_ofs_uobj_tbl_init(&ucma_file_uo_tbl, sizeof (sol_ucma_file_t));
	sol_ofs_uobj_tbl_init(&ucma_ctx_uo_tbl, sizeof (sol_ucma_chan_t));
	sol_ofs_uobj_tbl_init(&ucma_mcast_uo_tbl, sizeof (sol_ucma_mcast_t));
}

static void
sol_ucma_user_objs_fini()
{
	sol_ofs_uobj_tbl_fini(&ucma_file_uo_tbl);
	sol_ofs_uobj_tbl_fini(&ucma_ctx_uo_tbl);
	sol_ofs_uobj_tbl_fini(&ucma_mcast_uo_tbl);
}
