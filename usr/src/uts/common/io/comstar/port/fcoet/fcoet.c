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
 */

/*
 * The following notice accompanied the original version of this file:
 *
 * BSD LICENSE
 *
 * Copyright(c) 2007 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Driver kernel header files
 */
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/cred.h>
#include <sys/byteorder.h>
#include <sys/atomic.h>
#include <sys/modhash.h>
#include <sys/scsi/scsi.h>
#include <sys/ethernet.h>

/*
 * COMSTAR header files
 */
#include <sys/stmf_defines.h>
#include <sys/fct_defines.h>
#include <sys/stmf.h>
#include <sys/portif.h>
#include <sys/fct.h>

/*
 * FCoE header files
 */
#include <sys/fcoe/fcoe_common.h>

/*
 * Driver's own header files
 */
#include "fcoet.h"
#include "fcoet_eth.h"
#include "fcoet_fc.h"

/*
 * static function forward declaration
 */
static int fcoet_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int fcoet_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int fcoet_open(dev_t *devp, int flag, int otype, cred_t *credp);
static int fcoet_close(dev_t dev, int flag, int otype, cred_t *credp);
static int fcoet_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *credp, int *rval);
static fct_status_t fcoet_attach_init(fcoet_soft_state_t *ss);
static fct_status_t fcoet_detach_uninit(fcoet_soft_state_t *ss);
static void fcoet_watchdog(void *arg);
static void fcoet_handle_sol_flogi(fcoet_soft_state_t *ss);
static stmf_data_buf_t *fcoet_dbuf_alloc(fct_local_port_t *port,
    uint32_t size, uint32_t *pminsize, uint32_t flags);
static void fcoet_dbuf_free(fct_dbuf_store_t *fds, stmf_data_buf_t *dbuf);
static int fcoet_dbuf_init(fcoet_soft_state_t *ss);
static void fcoet_dbuf_destroy(fcoet_soft_state_t *ss);
static uint_t
fcoet_sol_oxid_hash_empty(mod_hash_key_t key, mod_hash_val_t *val, void *arg);
static uint_t
fcoet_unsol_rxid_hash_empty(mod_hash_key_t key, mod_hash_val_t *val, void *arg);

/*
 * Driver identificaton stuff
 */
static struct cb_ops fcoet_cb_ops = {
	fcoet_open,
	fcoet_close,
	nodev,
	nodev,
	nodev,
	nodev,
	nodev,
	fcoet_ioctl,
	nodev,
	nodev,
	nodev,
	nochpoll,
	ddi_prop_op,
	0,
	D_MP | D_NEW
};

static struct dev_ops fcoet_ops = {
	DEVO_REV,
	0,
	nodev,
	nulldev,
	nulldev,
	fcoet_attach,
	fcoet_detach,
	nodev,
	&fcoet_cb_ops,
	NULL,
	ddi_power,
	ddi_quiesce_not_needed
};

static struct modldrv modldrv = {
	&mod_driverops,
	FCOET_MOD_NAME,
	&fcoet_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

/*
 * Driver's global variables
 */
static kmutex_t	 fcoet_mutex;
static void	*fcoet_state = NULL;

int fcoet_use_ext_log = 1;
static char				 fcoet_provider_name[] = "fcoet";
static struct stmf_port_provider	*fcoet_pp	= NULL;

/*
 * Common loadable module entry points _init, _fini, _info
 */

int
_init(void)
{
	int ret;

	ret = ddi_soft_state_init(&fcoet_state, sizeof (fcoet_soft_state_t), 0);
	if (ret == 0) {
		fcoet_pp = (stmf_port_provider_t *)
		    stmf_alloc(STMF_STRUCT_PORT_PROVIDER, 0, 0);
		fcoet_pp->pp_portif_rev = PORTIF_REV_1;
		fcoet_pp->pp_name = fcoet_provider_name;
		if (stmf_register_port_provider(fcoet_pp) != STMF_SUCCESS) {
			stmf_free(fcoet_pp);
			ddi_soft_state_fini(&fcoet_state);
			return (EIO);
		}

		mutex_init(&fcoet_mutex, 0, MUTEX_DRIVER, 0);
		ret = mod_install(&modlinkage);
		if (ret) {
			(void) stmf_deregister_port_provider(fcoet_pp);
			stmf_free(fcoet_pp);
			mutex_destroy(&fcoet_mutex);
			ddi_soft_state_fini(&fcoet_state);
		}
	}

	FCOET_LOG("_init", "exit _init with %x", ret);
	return (ret);
}

int
_fini(void)
{
	int ret;

	ret = mod_remove(&modlinkage);
	if (ret == 0) {
		(void) stmf_deregister_port_provider(fcoet_pp);
		stmf_free(fcoet_pp);
		mutex_destroy(&fcoet_mutex);
		ddi_soft_state_fini(&fcoet_state);
	}

	FCOET_LOG("_fini", "exit _fini with %x", ret);
	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Autoconfiguration entry points: attach, detach, getinfo
 */

static int
fcoet_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			 ret = DDI_FAILURE;
	int			 instance;
	fcoet_soft_state_t	*ss;

	instance = ddi_get_instance(dip);
	FCOET_LOG("fcoet_attach", "get instance %d", instance);

	switch (cmd) {
	case DDI_ATTACH:
		ret = ddi_soft_state_zalloc(fcoet_state, instance);
		if (ret != DDI_SUCCESS) {
			return (ret);
		}

		ss = ddi_get_soft_state(fcoet_state, instance);
		ss->ss_instance = instance;
		ss->ss_dip = dip;

		ret = fcoet_attach_init(ss);
		if (ret != FCOE_SUCCESS) {
			ddi_soft_state_free(fcoet_state, instance);
			ret = DDI_FAILURE;
		}

		FCOET_LOG("fcoet_attach", "end with-%x", ret);
		break;

	case DDI_RESUME:
		ret = DDI_SUCCESS;
		break;

	default:
		FCOET_LOG("fcoet_attach", "unspported attach cmd-%x", cmd);
		break;
	}

	return (ret);
}

static int
fcoet_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int			 ret = DDI_FAILURE;
	int			 fcoe_ret;
	int			 instance;
	fcoet_soft_state_t	*ss;

	instance = ddi_get_instance(dip);
	ss = ddi_get_soft_state(fcoet_state, instance);
	if (ss == NULL) {
		return (ret);
	}

	switch (cmd) {
	case DDI_DETACH:
		fcoe_ret = fcoet_detach_uninit(ss);
		if (fcoe_ret == FCOE_SUCCESS) {
			ret = DDI_SUCCESS;
		}

		FCOET_LOG("fcoet_detach", "fcoet_detach_uninit end with-%x",
		    fcoe_ret);
		break;

	case DDI_SUSPEND:
		ret = DDI_SUCCESS;
		break;

	default:
		FCOET_LOG("fcoet_detach", "unsupported detach cmd-%x", cmd);
		break;
	}

	return (ret);
}

/*
 * Device access entry points
 */
static int
fcoet_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	int			 instance;
	fcoet_soft_state_t	*ss;

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	/*
	 * Since this is for debugging only, only allow root to issue ioctl now
	 */
	if (drv_priv(credp)) {
		return (EPERM);
	}

	instance = (int)getminor(*devp);
	ss = ddi_get_soft_state(fcoet_state, instance);
	if (ss == NULL) {
		return (ENXIO);
	}

	mutex_enter(&ss->ss_ioctl_mutex);
	if (ss->ss_ioctl_flags & FCOET_IOCTL_FLAG_EXCL) {
		/*
		 * It is already open for exclusive access.
		 * So shut the door on this caller.
		 */
		mutex_exit(&ss->ss_ioctl_mutex);
		return (EBUSY);
	}

	if (flag & FEXCL) {
		if (ss->ss_ioctl_flags & FCOET_IOCTL_FLAG_OPEN) {
			/*
			 * Exclusive operation not possible
			 * as it is already opened
			 */
			mutex_exit(&ss->ss_ioctl_mutex);
			return (EBUSY);
		}
		ss->ss_ioctl_flags |= FCOET_IOCTL_FLAG_EXCL;
	}
	ss->ss_ioctl_flags |= FCOET_IOCTL_FLAG_OPEN;
	mutex_exit(&ss->ss_ioctl_mutex);

	return (0);
}

/* ARGSUSED */
static int
fcoet_close(dev_t dev, int flag, int otype, cred_t *credp)
{
	int			 instance;
	fcoet_soft_state_t	*ss;

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	instance = (int)getminor(dev);
	ss = ddi_get_soft_state(fcoet_state, instance);
	if (ss == NULL) {
		return (ENXIO);
	}

	mutex_enter(&ss->ss_ioctl_mutex);
	if ((ss->ss_ioctl_flags & FCOET_IOCTL_FLAG_OPEN) == 0) {
		mutex_exit(&ss->ss_ioctl_mutex);
		return (ENODEV);
	}

	/*
	 * It looks there's one hole here, maybe there could several concurrent
	 * shareed open session, but we never check this case.
	 * But it will not hurt too much, disregard it now.
	 */
	ss->ss_ioctl_flags &= ~FCOET_IOCTL_FLAG_MASK;
	mutex_exit(&ss->ss_ioctl_mutex);

	return (0);
}

/* ARGSUSED */
static int
fcoet_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *credp, int *rval)
{
	fcoet_soft_state_t	*ss;
	int		 ret = 0;

	if (drv_priv(credp) != 0) {
		return (EPERM);
	}

	ss = ddi_get_soft_state(fcoet_state, (int32_t)getminor(dev));
	if (ss == NULL) {
		return (ENXIO);
	}

	switch (cmd) {
	default:
		FCOET_LOG("fcoet_ioctl", "ioctl-0x%02X", cmd);
		ret = ENOTTY;
		break;
	}

	*rval = ret;
	return (ret);
}

static fct_status_t
fcoet_attach_init(fcoet_soft_state_t *ss)
{
	fcoe_client_t		 client_fcoet;
	fcoe_port_t		*eport;
	fct_local_port_t	*port;
	fct_dbuf_store_t	*fds;
	char			 taskq_name[FCOET_TASKQ_NAME_LEN];
	int			 ret;

	/*
	 * FCoE (fcoe is fcoet's dependent driver)
	 * First we need register fcoet to FCoE as one client
	 */
	client_fcoet.ect_eport_flags = EPORT_FLAG_TGT_MODE |
	    EPORT_FLAG_IS_DIRECT_P2P;
	client_fcoet.ect_max_fc_frame_size = 2136;
	client_fcoet.ect_private_frame_struct_size = sizeof (fcoet_frame_t);
	client_fcoet.ect_rx_frame = fcoet_rx_frame;
	client_fcoet.ect_port_event = fcoet_port_event;
	client_fcoet.ect_release_sol_frame = fcoet_release_sol_frame;
	client_fcoet.ect_client_port_struct = ss;
	client_fcoet.ect_fcoe_ver = FCOE_VER_NOW;
	FCOET_LOG(__FUNCTION__, "version: %x %x", FCOE_VER_NOW, fcoe_ver_now);
	ret = ddi_prop_get_int(DDI_DEV_T_ANY, ss->ss_dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "mac_id", -1);
	if (ret == -1) {
		FCOET_LOG("fcoet_attach_init", "get mac_id failed");
		return (DDI_FAILURE);
	} else {
		client_fcoet.ect_channelid = ret;
	}
	FCOET_LOG("fcoet_attach_init", "channel_id is %d",
	    client_fcoet.ect_channelid);

	/*
	 * It's FCoE's responsiblity to initialize eport's all elements
	 */
	eport = fcoe_register_client(&client_fcoet);
	if (eport == NULL) {
		goto fail_register_client;
	}

	/*
	 * Now it's time to register local port to FCT
	 */
	if (fcoet_dbuf_init(ss) != FCOE_SUCCESS) {
		goto fail_init_dbuf;
	}

	fds = (fct_dbuf_store_t *)fct_alloc(FCT_STRUCT_DBUF_STORE, 0, 0);
	if (fds == NULL) {
		goto fail_alloc_dbuf;
	} else {
		fds->fds_alloc_data_buf = fcoet_dbuf_alloc;
		fds->fds_free_data_buf = fcoet_dbuf_free;
		fds->fds_fca_private = (void *)ss;
	}

	port = (fct_local_port_t *)fct_alloc(FCT_STRUCT_LOCAL_PORT, 0, 0);
	if (port == NULL) {
		goto fail_alloc_port;
	} else {
		/*
		 * Do ss's initialization now
		 */
		(void) snprintf(ss->ss_alias, sizeof (ss->ss_alias), "fcoet%d",
		    ss->ss_instance);
		ret = ddi_create_minor_node(ss->ss_dip, "admin",
		    S_IFCHR, ss->ss_instance, DDI_NT_STMF_PP, 0);
		if (ret != DDI_SUCCESS) {
			goto fail_minor_node;
		}

		ss->ss_state = FCT_STATE_OFFLINE;
		ss->ss_state_not_acked = 1;
		ss->ss_flags = 0;
		ss->ss_port = port;
		ss->ss_eport = eport;
		FCOE_SET_DEFAULT_FPORT_ADDR(eport->eport_efh_dst);

		ss->ss_rportid_in_dereg = 0;
		ss->ss_rport_dereg_state = 0;

		ss->ss_next_sol_oxid = 0xFFFF;
		ss->ss_next_unsol_rxid = 0xFFFF;
		ss->ss_sol_oxid_hash = mod_hash_create_idhash(
		    "ss_sol_oxid_hash", FCOET_SOL_HASH_SIZE,
		    mod_hash_null_valdtor);
		ss->ss_unsol_rxid_hash = mod_hash_create_idhash(
		    "ss_unsol_rxid_hash", FCOET_SOL_HASH_SIZE,
		    mod_hash_null_valdtor);

		ss->ss_watch_count = 0;
		mutex_init(&ss->ss_watch_mutex, 0, MUTEX_DRIVER, 0);
		cv_init(&ss->ss_watch_cv, NULL, CV_DRIVER, NULL);

		list_create(&ss->ss_abort_xchg_list, sizeof (fcoet_exchange_t),
		    offsetof(fcoet_exchange_t, xch_abort_node));

		ss->ss_sol_flogi = NULL;
		ss->ss_sol_flogi_state = SFS_WAIT_LINKUP;

		bzero(&ss->ss_link_info, sizeof (fct_link_info_t));

		ss->ss_ioctl_flags = 0;
		mutex_init(&ss->ss_ioctl_mutex, 0, MUTEX_DRIVER, 0);

		ss->ss_change_state_flags = 0;
	}

	/*
	 * Do port's initialization
	 *
	 * port_fct_private and port_lport have been initialized by fct_alloc
	 */
	port->port_fca_private = ss;
	port->port_fca_version = FCT_FCA_MODREV_1;
	bcopy(ss->ss_eport->eport_nodewwn, port->port_nwwn, 8);
	bcopy(ss->ss_eport->eport_portwwn, port->port_pwwn, 8);
	port->port_default_alias = ss->ss_alias;
	port->port_sym_node_name = NULL;
	port->port_sym_port_name = NULL;

	port->port_pp = fcoet_pp;

	port->port_hard_address = 0;
	port->port_max_logins = FCOET_MAX_LOGINS;
	port->port_max_xchges = FCOET_MAX_XCHGES;
	port->port_fca_fcp_cmd_size = sizeof (fcoet_exchange_t);
	port->port_fca_rp_private_size = 0;
	port->port_fca_sol_els_private_size = sizeof (fcoet_exchange_t);
	port->port_fca_sol_ct_private_size = sizeof (fcoet_exchange_t);

	port->port_fca_abort_timeout = 5 * 1000;	/* 5 seconds */
	port->port_fds = fds;

	port->port_get_link_info = fcoet_get_link_info;
	port->port_register_remote_port = fcoet_register_remote_port;
	port->port_deregister_remote_port = fcoet_deregister_remote_port;
	port->port_send_cmd = fcoet_send_cmd;
	port->port_xfer_scsi_data = fcoet_xfer_scsi_data;
	port->port_send_cmd_response = fcoet_send_cmd_response;
	port->port_abort_cmd = fcoet_abort_cmd;
	port->port_ctl = fcoet_ctl;
	port->port_flogi_xchg = fcoet_do_flogi;
	port->port_populate_hba_details = fcoet_populate_hba_fru_details;
	if (fct_register_local_port(port) != FCT_SUCCESS) {
		goto fail_register_port;
	}

	/*
	 * Start watchdog thread
	 */
	(void) snprintf(taskq_name, sizeof (taskq_name),
	    "stmf_fct_fcoet_%d_taskq", ss->ss_instance);
	if ((ss->ss_watchdog_taskq = ddi_taskq_create(NULL,
	    taskq_name, 2, TASKQ_DEFAULTPRI, 0)) == NULL) {
		goto fail_create_taskq;
	}

	atomic_and_32(&ss->ss_flags, ~SS_FLAG_TERMINATE_WATCHDOG);
	(void) ddi_taskq_dispatch(ss->ss_watchdog_taskq,
	    fcoet_watchdog, ss, DDI_SLEEP);
	while ((ss->ss_flags & SS_FLAG_WATCHDOG_RUNNING) == 0) {
		delay(10);
	}

	ddi_report_dev(ss->ss_dip);
	return (DDI_SUCCESS);

fail_create_taskq:
	if (ss->ss_flags & SS_FLAG_WATCHDOG_RUNNING) {
		atomic_or_32(&ss->ss_flags, SS_FLAG_TERMINATE_WATCHDOG);
		cv_broadcast(&ss->ss_watch_cv);
		while (ss->ss_flags & SS_FLAG_WATCHDOG_RUNNING) {
			delay(10);
		}
	}

	ddi_taskq_destroy(ss->ss_watchdog_taskq);
	FCOET_LOG("fcoet_attach_init", "fail_register_port");

fail_register_port:
	mutex_destroy(&ss->ss_ioctl_mutex);
	mutex_destroy(&ss->ss_watch_mutex);
	cv_destroy(&ss->ss_watch_cv);
	mod_hash_destroy_hash(ss->ss_sol_oxid_hash);
	mod_hash_destroy_hash(ss->ss_unsol_rxid_hash);
	list_destroy(&ss->ss_abort_xchg_list);
	FCOET_LOG("fcoet_attach_init", "fail_create_taskq");

fail_minor_node:
	fct_free(port);
	FCOET_LOG("fcoet_attach_init", "fail_minor_node");

fail_alloc_port:
	fct_free(fds);
	FCOET_LOG("fcoet_attach_init", "fail_alloc_port");

fail_alloc_dbuf:
	fcoet_dbuf_destroy(ss);
	FCOET_LOG("fcoet_attach_init", "fail_alloc_dbuf");

fail_init_dbuf:
	ss->ss_eport->eport_deregister_client(ss->ss_eport);
	FCOET_LOG("fcoet_attach_init", "fail_init_dbuf");

fail_register_client:
	FCOET_LOG("fcoet_attach_init", "fail_register_client");
	return (DDI_FAILURE);
}

static fct_status_t
fcoet_detach_uninit(fcoet_soft_state_t *ss)
{
	if ((ss->ss_state != FCT_STATE_OFFLINE) ||
	    ss->ss_state_not_acked) {
		return (FCOE_FAILURE);
	}

	/*
	 * Avoid modunload before running fcinfo remove-target-port
	 */
	if (ss->ss_eport != NULL &&
	    ss->ss_eport->eport_flags & EPORT_FLAG_MAC_IN_USE) {
		return (FCOE_FAILURE);
	}

	if (ss->ss_port == NULL) {
		return (FCOE_SUCCESS);
	}

	ss->ss_sol_oxid_hash_empty = 1;
	ss->ss_unsol_rxid_hash_empty = 1;
	mod_hash_walk(ss->ss_sol_oxid_hash, fcoet_sol_oxid_hash_empty, ss);
	mod_hash_walk(ss->ss_unsol_rxid_hash, fcoet_unsol_rxid_hash_empty, ss);
	if ((!ss->ss_sol_oxid_hash_empty) || (!ss->ss_unsol_rxid_hash_empty)) {
		return (FCOE_FAILURE);
	}

	/*
	 * We need offline the port manually, before we want to detach it
	 * or it will not succeed.
	 */
	if (fct_deregister_local_port(ss->ss_port) != FCT_SUCCESS) {
		FCOET_LOG("fcoet_detach_uninit",
		    "fct_deregister_local_port failed");
		return (FCOE_FAILURE);
	}

	/*
	 * Stop watchdog
	 */
	if (ss->ss_flags & SS_FLAG_WATCHDOG_RUNNING) {
		atomic_or_32(&ss->ss_flags, SS_FLAG_TERMINATE_WATCHDOG);
		cv_broadcast(&ss->ss_watch_cv);
		while (ss->ss_flags & SS_FLAG_WATCHDOG_RUNNING) {
			delay(10);
		}
	}

	ddi_taskq_destroy(ss->ss_watchdog_taskq);

	/*
	 * Release all resources
	 */
	mutex_destroy(&ss->ss_ioctl_mutex);
	mutex_destroy(&ss->ss_watch_mutex);
	cv_destroy(&ss->ss_watch_cv);
	mod_hash_destroy_hash(ss->ss_sol_oxid_hash);
	mod_hash_destroy_hash(ss->ss_unsol_rxid_hash);
	list_destroy(&ss->ss_abort_xchg_list);

	fct_free(ss->ss_port->port_fds);
	fct_free(ss->ss_port);
	ss->ss_port = NULL;

	fcoet_dbuf_destroy(ss);

	if (ss->ss_eport != NULL &&
	    ss->ss_eport->eport_deregister_client != NULL) {
		ss->ss_eport->eport_deregister_client(ss->ss_eport);
	}
	ddi_soft_state_free(fcoet_state, ss->ss_instance);
	return (FCOE_SUCCESS);
}

static void
fcoet_watchdog(void *arg)
{
	fcoet_soft_state_t	*ss = (fcoet_soft_state_t *)arg;
	clock_t			 tmp_delay = 0;
	fcoet_exchange_t	*xchg, *xchg_next;

	FCOET_LOG("fcoet_watchdog", "fcoet_soft_state is %p", ss);

	mutex_enter(&ss->ss_watch_mutex);
	atomic_or_32(&ss->ss_flags, SS_FLAG_WATCHDOG_RUNNING);
	tmp_delay = STMF_SEC2TICK(1)/2;

	while ((ss->ss_flags & SS_FLAG_TERMINATE_WATCHDOG) == 0) {
		ss->ss_watch_count++;

		if (ss->ss_sol_flogi_state != SFS_FLOGI_DONE) {
			fcoet_handle_sol_flogi(ss);
		}
		for (xchg = list_head(&ss->ss_abort_xchg_list); xchg; ) {
			xchg_next = list_next(&ss->ss_abort_xchg_list, xchg);
			if (xchg->xch_ref == 0) {
				list_remove(&ss->ss_abort_xchg_list, xchg);
				mutex_exit(&ss->ss_watch_mutex);
				/* xchg abort done */
				if (xchg->xch_dbuf_num) {
					kmem_free((void*)xchg->xch_dbufs,
					    xchg->xch_dbuf_num *
					    sizeof (void *));
					xchg->xch_dbufs = NULL;
					xchg->xch_dbuf_num = 0;
				}
				fct_cmd_fca_aborted(xchg->xch_cmd,
				    FCT_ABORT_SUCCESS, FCT_IOF_FCA_DONE);
				mutex_enter(&ss->ss_watch_mutex);
			}
			xchg = xchg_next;
		}

		atomic_or_32(&ss->ss_flags, SS_FLAG_DOG_WAITING);
		(void) cv_reltimedwait(&ss->ss_watch_cv, &ss->ss_watch_mutex,
		    (clock_t)tmp_delay, TR_CLOCK_TICK);
		atomic_and_32(&ss->ss_flags, ~SS_FLAG_DOG_WAITING);
	}

	/*
	 * Ensure no ongoing FLOGI, before terminate the watchdog
	 */
	if (ss->ss_sol_flogi) {
		fcoet_clear_sol_exchange(ss->ss_sol_flogi);
		fct_free(ss->ss_sol_flogi->xch_cmd);
		ss->ss_sol_flogi = NULL;
	}

	atomic_and_32(&ss->ss_flags, ~SS_FLAG_WATCHDOG_RUNNING);
	mutex_exit(&ss->ss_watch_mutex);
}

static void
fcoet_handle_sol_flogi(fcoet_soft_state_t *ss)
{
	clock_t			twosec = STMF_SEC2TICK(2);

check_state_again:
	if (ss->ss_flags & SS_FLAG_PORT_DISABLED) {
		ss->ss_sol_flogi_state = SFS_WAIT_LINKUP;
	}

	switch (ss->ss_sol_flogi_state) {
	case SFS_WAIT_LINKUP:
		if (ss->ss_sol_flogi) {
			if (ss->ss_sol_flogi->xch_ref == 0) {
				fcoet_clear_sol_exchange(ss->ss_sol_flogi);
				fct_free(ss->ss_sol_flogi->xch_cmd);
				ss->ss_sol_flogi = NULL;
			}
		}
		break;

	case SFS_FLOGI_INIT:
		if (ss->ss_sol_flogi) {
			/*
			 * wait for the response to finish
			 */
			ss->ss_sol_flogi_state = SFS_CLEAR_FLOGI;
			break;
		}
		fcoet_send_sol_flogi(ss);
		ss->ss_sol_flogi_state++;
		break;

	case SFS_FLOGI_CHECK_TIMEOUT:
		if ((ss->ss_sol_flogi->xch_start_time + twosec) <
		    ddi_get_lbolt()) {
			ss->ss_sol_flogi_state++;
		}
		break;

	case SFS_ABTS_INIT:
		fcoet_send_sol_abts(ss->ss_sol_flogi);
		ss->ss_sol_flogi_state++;
		break;

	case SFS_CLEAR_FLOGI:
		if (ss->ss_sol_flogi) {
			if (ss->ss_sol_flogi->xch_ref) {
				break;
			}
			fcoet_clear_sol_exchange(ss->ss_sol_flogi);
			fct_free(ss->ss_sol_flogi->xch_cmd);
			ss->ss_sol_flogi = NULL;
		}
		ss->ss_sol_flogi_state = SFS_FLOGI_INIT;
		goto check_state_again;

	case SFS_FLOGI_ACC:
		ss->ss_sol_flogi_state++;
		goto check_state_again;

	case SFS_FLOGI_DONE:
		if (!(ss->ss_flags & SS_FLAG_PORT_DISABLED) &&
		    ss->ss_sol_flogi) {
			fcoet_clear_sol_exchange(ss->ss_sol_flogi);
			fct_free(ss->ss_sol_flogi->xch_cmd);
			ss->ss_sol_flogi = NULL;
		}

		/*
		 * We'd better to offline it first, and delay 0.1 seconds,
		 * before we say it's on again.
		 */
		fct_handle_event(ss->ss_port,
		    FCT_EVENT_LINK_DOWN, 0, NULL);
		delay(STMF_SEC2TICK(1)/10);
		fct_handle_event(ss->ss_port,
		    FCT_EVENT_LINK_UP, 0, NULL);
		break;

	default:
		ASSERT(0);
		break;
	}
}

/* ARGSUSED */
static int
fcoet_dbuf_init(fcoet_soft_state_t *ss)
{
	return (FCOE_SUCCESS);
}

/* ARGSUSED */
static void
fcoet_dbuf_destroy(fcoet_soft_state_t *ss)
{

}

/* ARGSUSED */
static stmf_data_buf_t *
fcoet_dbuf_alloc(fct_local_port_t *port, uint32_t size, uint32_t *pminsize,
    uint32_t flags)
{
	stmf_data_buf_t	*dbuf;
	int		 add_size;
	int		 sge_num;
	int		 sge_size;
	int		 idx;
	int		 ii;
	void		*netb;
	uint8_t		*fc_buf;
	fcoet_soft_state_t	*ss =
	    (fcoet_soft_state_t *)port->port_fca_private;

	if (size > FCOET_MAX_DBUF_LEN) {
		if (*pminsize > FCOET_MAX_DBUF_LEN) {
			return (NULL);
		}

		size = FCOET_MAX_DBUF_LEN;
	}

	sge_num = (size - 1) / ss->ss_fcp_data_payload_size + 1;
	add_size = (sge_num - 1) * sizeof (struct stmf_sglist_ent) +
	    sge_num * sizeof (mblk_t *);
	dbuf = stmf_alloc(STMF_STRUCT_DATA_BUF, add_size, 0);
	if (dbuf == NULL) {
		return (NULL);
	}
	dbuf->db_buf_size = size;
	dbuf->db_data_size = size;
	dbuf->db_sglist_length = 0;
	dbuf->db_flags |= DB_DONT_REUSE;
	FCOET_SET_SEG_NUM(dbuf, sge_num);

	/*
	 * Initialize non-last sg entries
	 */
	for (idx = 0; idx < sge_num - 1; idx++) {
		sge_size = ss->ss_fcp_data_payload_size;
		netb = ss->ss_eport->eport_alloc_netb(
		    ss->ss_eport, sizeof (fcoe_fc_frame_header_t) +
		    sge_size, &fc_buf);
		if (netb == NULL) {
			for (ii = 0; ii < idx; ii++) {
				ss->ss_eport->eport_free_netb(
				    FCOET_GET_NETB(dbuf, ii));
			}
			stmf_free(dbuf);
			FCOET_LOG("fcoe_dbuf_alloc", "no netb");
			return (NULL);
		}
		FCOET_SET_NETB(dbuf, idx, netb);
		dbuf->db_sglist[idx].seg_addr = fc_buf +
		    sizeof (fcoe_fc_frame_header_t);
		dbuf->db_sglist[idx].seg_length = sge_size;
	}

	/*
	 * Initialize the last sg entry
	 */
	if (size % ss->ss_fcp_data_payload_size) {
		sge_size = P2ROUNDUP(size % ss->ss_fcp_data_payload_size, 4);
	} else {
		sge_size = ss->ss_fcp_data_payload_size;
	}

	netb = ss->ss_eport->eport_alloc_netb(
	    ss->ss_eport,
	    sizeof (fcoe_fc_frame_header_t) +
	    sge_size, &fc_buf);
	if (netb == NULL) {
		for (ii = 0; ii < idx; ii++) {
			ss->ss_eport->eport_free_netb(
			    FCOET_GET_NETB(dbuf, ii));
		}
		stmf_free(dbuf);
		FCOET_LOG("fcoe_dbuf_alloc", "no netb");
		return (NULL);
	}

	FCOET_SET_NETB(dbuf, idx, netb);
	dbuf->db_sglist[idx].seg_addr = fc_buf +
	    sizeof (fcoe_fc_frame_header_t);
	dbuf->db_sglist[idx].seg_length = sge_size;

	/*
	 * Let COMSTAR know how many sg entries we will use
	 */
	dbuf->db_sglist_length = idx + 1;

	return (dbuf);
}

static void
fcoet_dbuf_free(fct_dbuf_store_t *fds, stmf_data_buf_t *dbuf)
{
	int	idx;
	fcoet_soft_state_t	*ss =
	    (fcoet_soft_state_t *)fds->fds_fca_private;

	for (idx = 0; idx < FCOET_GET_SEG_NUM(dbuf); idx++) {
		if (FCOET_GET_NETB(dbuf, idx)) {
			ss->ss_eport->eport_free_netb(
			    FCOET_GET_NETB(dbuf, idx));
		}
	}

	stmf_free(dbuf);
}

/*
 * We should have initialized fcoe_frame_t before
 */
void
fcoet_init_tfm(fcoe_frame_t *frm, fcoet_exchange_t *xch)
{
	FRM2TFM(frm)->tfm_fcoe_frame = frm;
	FRM2TFM(frm)->tfm_xch = xch;
	FRM2TFM(frm)->tfm_seq = NULL;
}

/* ARGSUSED */
static uint_t
fcoet_sol_oxid_hash_empty(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	fcoet_soft_state_t	*ss = (fcoet_soft_state_t *)arg;

	ss->ss_sol_oxid_hash_empty = 0;
	FCOET_LOG("fcoet_sol_oxid_hash_empty", "one ongoing xch: %p", val);
	return (MH_WALK_CONTINUE);
}

/* ARGSUSED */
static uint_t
fcoet_unsol_rxid_hash_empty(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	fcoet_soft_state_t	*ss = (fcoet_soft_state_t *)arg;

	ss->ss_sol_oxid_hash_empty = 0;
	FCOET_LOG("fcoet_unsol_rxid_hash_empty", "one ongoing xch: %p", val);
	return (MH_WALK_CONTINUE);
}

/* ARGSUSED */
void
fcoet_modhash_find_cb(mod_hash_key_t key, mod_hash_val_t val)
{
	ASSERT(val != NULL);
	fcoet_exchange_t *xch = (fcoet_exchange_t *)val;
	FCOET_BUSY_XCHG(xch);
}
