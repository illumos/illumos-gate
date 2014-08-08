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
#include <sys/scsi/scsi.h>
#include <sys/mac_client.h>
#include <sys/modhash.h>

/*
 * leadville header files
 */
#include <sys/fibre-channel/fc.h>
#include <sys/fibre-channel/impl/fc_fcaif.h>

/*
 * fcoe header files
 */
#include <sys/fcoe/fcoe_common.h>

/*
 * fcoei header files
 */
#include <fcoei.h>

/*
 * forward declaration of stack functions
 */
static uint32_t fcoei_xch_check(
	mod_hash_key_t key, mod_hash_val_t *val, void *arg);
static int fcoei_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int fcoei_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int fcoei_open(dev_t *devp, int flag, int otype, cred_t *credp);
static int fcoei_close(dev_t dev, int flag, int otype, cred_t *credp);
static int fcoei_ioctl(
	dev_t dev, int cmd, intptr_t data, int mode, cred_t *credp, int *rval);
static int fcoei_attach_init(fcoei_soft_state_t *ss);
static int fcoei_detach_uninit(fcoei_soft_state_t *ss);
static void fcoei_watchdog(void *arg);
static void fcoei_process_events(fcoei_soft_state_t *ss);
static void fcoei_trigger_fp_attach(void *arg);
static void fcoei_abts_exchange(fcoei_exchange_t *xch);
static void fcoei_clear_watchdog_jobs(fcoei_soft_state_t *ss);

/*
 * Driver identificaton stuff
 */
static struct cb_ops fcoei_cb_ops = {
	fcoei_open,
	fcoei_close,
	nodev,
	nodev,
	nodev,
	nodev,
	nodev,
	fcoei_ioctl,
	nodev,
	nodev,
	nodev,
	nochpoll,
	ddi_prop_op,
	0,
	D_MP | D_NEW | D_HOTPLUG,
	CB_REV,
	nodev,
	nodev
};

static struct dev_ops fcoei_ops = {
	DEVO_REV,
	0,
	nodev,
	nulldev,
	nulldev,
	fcoei_attach,
	fcoei_detach,
	nodev,
	&fcoei_cb_ops,
	NULL,
	ddi_power,
	ddi_quiesce_not_needed
};

static struct modldrv modldrv = {
	&mod_driverops,
	FCOEI_NAME_VERSION,
	&fcoei_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * Driver's global variables
 */
void	*fcoei_state	   = NULL;
int	 fcoei_use_ext_log = 0;

/*
 * Common loadable module entry points _init, _fini, _info
 */
int
_init(void)
{
	int ret;

	ret = ddi_soft_state_init(&fcoei_state, sizeof (fcoei_soft_state_t), 0);
	if (ret != DDI_SUCCESS) {
		FCOEI_LOG(__FUNCTION__, "soft state init failed: %x", ret);
		return (ret);
	}

	ret = mod_install(&modlinkage);
	if (ret != 0) {
		ddi_soft_state_fini(&fcoei_state);
		FCOEI_LOG(__FUNCTION__, "fcoei mod_install failed: %x", ret);
		return (ret);
	}

	/*
	 * Let FCTL initialize devo_bus_ops
	 */
	fc_fca_init(&fcoei_ops);

	FCOEI_LOG(__FUNCTION__, "fcoei _init succeeded");
	return (ret);
}

int
_fini(void)
{
	int ret;

	ret = mod_remove(&modlinkage);
	if (ret != 0) {
		FCOEI_EXT_LOG(__FUNCTION__, "fcoei mod_remove failed: %x", ret);
		return (ret);
	}

	ddi_soft_state_fini(&fcoei_state);
	FCOEI_LOG(__FUNCTION__, "fcoei _fini succeeded");
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
fcoei_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			 ret;
	int			 fcoe_ret;
	int			 instance;
	fcoei_soft_state_t	*ss;

	instance = ddi_get_instance(dip);
	FCOEI_LOG(__FUNCTION__, "instance is %d", instance);
	switch (cmd) {
	case DDI_ATTACH:
		ret = ddi_soft_state_zalloc(fcoei_state, instance);
		if (ret != DDI_SUCCESS) {
			FCOEI_LOG(__FUNCTION__, "ss zalloc failed: %x", ret);
			return (ret);
		}

		/*
		 * Get the soft state, and do basic initialization with dip
		 */
		ss = ddi_get_soft_state(fcoei_state, instance);
		ss->ss_dip = dip;

		fcoe_ret = fcoei_attach_init(ss);
		if (fcoe_ret != FCOE_SUCCESS) {
			ddi_soft_state_free(fcoei_state, instance);
			FCOEI_LOG(__FUNCTION__, "fcoei_attach_init failed: "
			    "%x", fcoe_ret);
			return (DDI_FAILURE);
		}

		ss->ss_flags |= SS_FLAG_TRIGGER_FP_ATTACH;
		(void) timeout(fcoei_trigger_fp_attach, ss, FCOE_SEC2TICK(1));
		FCOEI_LOG(__FUNCTION__, "fcoei_attach succeeded: dip-%p, "
		    "cmd-%x", dip, cmd);
		return (DDI_SUCCESS);

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		FCOEI_LOG(__FUNCTION__, "unsupported attach cmd-%X", cmd);
		return (DDI_FAILURE);
	}
}

static int
fcoei_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int			 fcoe_ret;
	int			 instance;
	fcoei_soft_state_t	*ss;

	instance = ddi_get_instance(dip);
	ss = ddi_get_soft_state(fcoei_state, instance);
	if (ss == NULL) {
		FCOEI_LOG(__FUNCTION__, "get ss failed: dip-%p", dip);
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		if (ss->ss_flags & SS_FLAG_TRIGGER_FP_ATTACH) {
			FCOEI_LOG(__FUNCTION__, "still await fp attach");
			return (DDI_FAILURE);
		}

		if (ss->ss_flags & SS_FLAG_LV_BOUND) {
			FCOEI_LOG(__FUNCTION__, "fp is not detached yet");
			return (DDI_FAILURE);
		}

		fcoe_ret = fcoei_detach_uninit(ss);
		if (fcoe_ret != FCOE_SUCCESS) {
			FCOEI_LOG(__FUNCTION__, "fcoei_detach_uninit failed:"
			    " dip-%p, fcoe_ret-%d", dip, fcoe_ret);
			return (DDI_FAILURE);
		}

		FCOEI_LOG(__FUNCTION__, "succeeded: dip-%p, cmd-%x", dip, cmd);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		FCOEI_LOG(__FUNCTION__, "unspported detach cmd-%X", cmd);
		return (DDI_FAILURE);
	}
}

/*
 * Device access entry points: open, close, ioctl
 */

static int
fcoei_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	fcoei_soft_state_t	*ss;

	if (otype != OTYP_CHR) {
		FCOEI_LOG(__FUNCTION__, "flag: %x", flag);
		return (EINVAL);
	}

	if (drv_priv(credp)) {
		return (EPERM);
	}

	/*
	 * First of all, get related soft state
	 */
	ss = ddi_get_soft_state(fcoei_state, (int)getminor(*devp));
	if (ss == NULL) {
		return (ENXIO);
	}

	mutex_enter(&ss->ss_ioctl_mutex);
	if (ss->ss_ioctl_flags & FCOEI_IOCTL_FLAG_OPEN) {
		/*
		 * We don't support concurrent open
		 */
		mutex_exit(&ss->ss_ioctl_mutex);
		return (EBUSY);
	}

	ss->ss_ioctl_flags |= FCOEI_IOCTL_FLAG_OPEN;
	mutex_exit(&ss->ss_ioctl_mutex);

	return (0);
}

static int
fcoei_close(dev_t dev, int flag, int otype, cred_t *credp)
{
	fcoei_soft_state_t	*ss;

	if (otype != OTYP_CHR) {
		FCOEI_LOG(__FUNCTION__, "flag: %x, %p", flag, credp);
		return (EINVAL);
	}

	/*
	 * First of all, get related soft state
	 */
	ss = ddi_get_soft_state(fcoei_state, (int)getminor(dev));
	if (ss == NULL) {
		return (ENXIO);
	}

	mutex_enter(&ss->ss_ioctl_mutex);
	if (!(ss->ss_ioctl_flags & FCOEI_IOCTL_FLAG_OPEN)) {
		/*
		 * If it's not open, we can exit
		 */

		mutex_exit(&ss->ss_ioctl_mutex);
		return (ENODEV);
	}

	ss->ss_ioctl_flags &= ~FCOEI_IOCTL_FLAG_OPEN;
	mutex_exit(&ss->ss_ioctl_mutex);

	return (0);
}

static int
fcoei_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *credp, int *rval)
{
	fcoei_soft_state_t	*ss;
	int			 ret = 0;

	if (drv_priv(credp) != 0) {
		FCOEI_LOG(__FUNCTION__, "data: %p, %x", data, mode);
		return (EPERM);
	}

	/*
	 * Get related soft state
	 */
	ss = ddi_get_soft_state(fcoei_state, (int32_t)getminor(dev));
	if (!ss) {
		return (ENXIO);
	}

	/*
	 * Process ioctl
	 */
	switch (cmd) {

	default:
		FCOEI_LOG(__FUNCTION__, "ioctl-0x%02X", cmd);
		ret = ENOTTY;
	}

	/*
	 * Set return value
	 */
	*rval = ret;
	return (ret);
}

/*
 * fcoei_attach_init
 *	init related stuff of the soft state
 *
 * Input:
 *	ss = the soft state that will be processed
 *
 * Return:
 *	if it succeeded or not
 *
 * Comment:
 *	N/A
 */
static int
fcoei_attach_init(fcoei_soft_state_t *ss)
{
	fcoe_port_t		*eport;
	fcoe_client_t		 client_fcoei;
	char			 taskq_name[32];
	int			 ret;
	la_els_logi_t		*els = &ss->ss_els_logi;
	svc_param_t		*class3_param;

	/*
	 * Register fcoei to FCOE as its client
	 */
	client_fcoei.ect_eport_flags = EPORT_FLAG_INI_MODE |
	    EPORT_FLAG_IS_DIRECT_P2P;
	client_fcoei.ect_max_fc_frame_size = FCOE_MAX_FC_FRAME_SIZE;
	client_fcoei.ect_private_frame_struct_size = sizeof (fcoei_frame_t);
	fcoei_init_ect_vectors(&client_fcoei);
	client_fcoei.ect_client_port_struct = ss;
	client_fcoei.ect_fcoe_ver = FCOE_VER_NOW;
	FCOEI_LOG(__FUNCTION__, "version: %x %x", FCOE_VER_NOW, fcoe_ver_now);
	ret = ddi_prop_get_int(DDI_DEV_T_ANY, ss->ss_dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "mac_id", -1);
	if (ret == -1) {
		FCOEI_LOG(__FUNCTION__, "get mac_id failed");
		return (DDI_FAILURE);
	} else {
		client_fcoei.ect_channelid = ret;
	}

	/*
	 * It's fcoe's responsiblity to initialize eport's all elements,
	 * so we needn't do eport initialization
	 */
	eport = fcoe_register_client(&client_fcoei);
	if (eport == NULL) {
		goto fail_register_client;
	} else {
		ss->ss_eport = eport;
		FCOE_SET_DEFAULT_FPORT_ADDR(eport->eport_efh_dst);
	}

	/*
	 * Now it's time to register fca_tran to FCTL
	 * Remember fc_local_port is transparent to FCA (fcoei)
	 */
	ss->ss_fca_tran.fca_version  = FCTL_FCA_MODREV_5;
	ss->ss_fca_tran.fca_numports = 1;
	ss->ss_fca_tran.fca_pkt_size = sizeof (fcoei_exchange_t);
	ss->ss_fca_tran.fca_cmd_max  = 2048;

	/*
	 * scsi_tran_hba_setup could need these stuff
	 */
	ss->ss_fca_tran.fca_dma_lim  = NULL;
	ss->ss_fca_tran.fca_iblock   = NULL;
	ss->ss_fca_tran.fca_dma_attr = NULL;
	ss->ss_fca_tran.fca_acc_attr = NULL;

	/*
	 * Initialize vectors
	 */
	fcoei_init_fcatran_vectors(&ss->ss_fca_tran);

	/*
	 * fc_fca_attach only sets driver's private, it has nothing to with
	 * common port object between fcoei and leadville.
	 * After this attach, fp_attach will be triggered, and it will call
	 * fca_bind_port to let fcoei to know about common port object.
	 */
	if (fc_fca_attach(ss->ss_dip, &ss->ss_fca_tran) != DDI_SUCCESS) {
		goto fail_fca_attach;
	}

	/*
	 * It's time to do ss initialization
	 */
	ret = ddi_create_minor_node(ss->ss_dip, "admin",
	    S_IFCHR, ddi_get_instance(ss->ss_dip), DDI_NT_NEXUS, 0);
	if (ret != DDI_SUCCESS) {
		goto fail_minor_node;
	}

	ss->ss_flags	   = 0;
	ss->ss_port	   = NULL;
	/*
	 * ss->ss_eport has been initialized
	 */

	ss->ss_sol_oxid_hash = mod_hash_create_idhash(
	    "fcoei_sol_oxid_hash", FCOEI_SOL_HASH_SIZE,
	    mod_hash_null_valdtor);
	ss->ss_unsol_rxid_hash = mod_hash_create_idhash(
	    "fcoei_unsol_rxid_hash", FCOEI_UNSOL_HASH_SIZE,
	    mod_hash_null_valdtor);
	list_create(&ss->ss_comp_xch_list, sizeof (fcoei_exchange_t),
	    offsetof(fcoei_exchange_t, xch_comp_node));
	ss->ss_next_sol_oxid   = 0xFFFF;
	ss->ss_next_unsol_rxid = 0xFFFF;

	mutex_init(&ss->ss_watchdog_mutex, 0, MUTEX_DRIVER, 0);
	cv_init(&ss->ss_watchdog_cv, NULL, CV_DRIVER, NULL);
	(void) snprintf(taskq_name, 32, "leadville_fcoei_%d_taskq",
	    ddi_get_instance(ss->ss_dip));
	taskq_name[31] = 0;
	ss->ss_taskq = ddi_taskq_create(ss->ss_dip,
	    taskq_name, 64, TASKQ_DEFAULTPRI, DDI_SLEEP);

	ss->ss_link_state	  = FC_STATE_OFFLINE;
	ss->ss_link_speed	  = 0;
	ss->ss_port_event_counter = 0;

	list_create(&ss->ss_event_list, sizeof (fcoei_event_t),
	    offsetof(fcoei_event_t, ae_node));

	ss->ss_sol_cnt1   = 0;
	ss->ss_sol_cnt2   = 0;
	ss->ss_sol_cnt	   = &ss->ss_sol_cnt1;
	ss->ss_unsol_cnt1 = 0;
	ss->ss_unsol_cnt2 = 0;
	ss->ss_unsol_cnt  = &ss->ss_unsol_cnt1;
	ss->ss_ioctl_flags = 0;

	mutex_init(&ss->ss_ioctl_mutex, 0, MUTEX_DRIVER, 0);

	bcopy(eport->eport_portwwn, els->nport_ww_name.raw_wwn, 8);
	bcopy(eport->eport_nodewwn, els->node_ww_name.raw_wwn, 8);
	els->common_service.fcph_version = 0x2008;
	els->common_service.btob_credit = 3;
	els->common_service.cmn_features = 0x8800;
	els->common_service.conc_sequences = 0xff;
	els->common_service.relative_offset = 3;
	els->common_service.e_d_tov = 0x07d0;
	class3_param = (svc_param_t *)&els->class_3;
	class3_param->class_opt = 0x8800;
	class3_param->rcv_size = els->common_service.rx_bufsize = 2048;
	class3_param->conc_sequences = 0xff;
	class3_param->open_seq_per_xchng = 1;

	/*
	 * Fill out RNID Management Information
	 */
	bcopy(ss->ss_eport->eport_portwwn, ss->ss_rnid.global_id, 8);
	ss->ss_rnid.unit_type  = FCOEI_RNID_HBA;
	ss->ss_rnid.ip_version = FCOEI_RNID_IPV4;

	/*
	 * Start our watchdog
	 */
	(void) ddi_taskq_dispatch(ss->ss_taskq,
	    fcoei_watchdog, ss, DDI_SLEEP);
	while (!(ss->ss_flags & SS_FLAG_WATCHDOG_RUNNING)) {
		delay(50);
	}

	/*
	 * Report the device to the system
	 */
	ddi_report_dev(ss->ss_dip);
	return (DDI_SUCCESS);


fail_minor_node:
	FCOEI_LOG(__FUNCTION__, "fail_minor_node");
	(void) fc_fca_detach(ss->ss_dip);

fail_fca_attach:
	eport->eport_deregister_client(eport);
	FCOEI_LOG(__FUNCTION__, "fail_fca_attach");

fail_register_client:
	FCOEI_LOG(__FUNCTION__, "fail_register_client");
	return (DDI_FAILURE);
}

/*
 * fcoei_detach_uninit
 *	uninit related stuff of the soft state
 *
 * Input:
 *	ss = the soft state that will be processed
 *
 * Return:
 *	if it succeeded or not
 *
 * Comment:
 *	N/A
 */
int
fcoei_detach_uninit(fcoei_soft_state_t *ss)
{
	/*
	 * Stop watchdog first
	 */
	if (ss->ss_flags & SS_FLAG_WATCHDOG_RUNNING) {
		ss->ss_flags |= SS_FLAG_TERMINATE_WATCHDOG;
		cv_broadcast(&ss->ss_watchdog_cv);
	}

	/*
	 * Destroy the taskq
	 */
	ddi_taskq_wait(ss->ss_taskq);
	ddi_taskq_destroy(ss->ss_taskq);

	/*
	 * Release all allocated resources
	 */
	mutex_destroy(&ss->ss_ioctl_mutex);
	mutex_destroy(&ss->ss_watchdog_mutex);
	cv_destroy(&ss->ss_watchdog_cv);
	mod_hash_destroy_idhash(ss->ss_sol_oxid_hash);
	mod_hash_destroy_idhash(ss->ss_unsol_rxid_hash);
	list_destroy(&ss->ss_event_list);
	ss->ss_eport->eport_deregister_client(ss->ss_eport);
	ddi_remove_minor_node(ss->ss_dip, NULL);

	/*
	 * Release itself
	 */
	ddi_soft_state_free(fcoei_state, ddi_get_instance(ss->ss_dip));
	return (FCOE_SUCCESS);
}

/*
 * fcoei_watchdog
 *	Perform periodic checking and routine tasks
 *
 * Input:
 *	arg = the soft state that will be processed
 *
 * Return:
 *	N/A
 *
 * Comment:
 *	N/A
 */
static void
fcoei_watchdog(void *arg)
{
	fcoei_soft_state_t	*ss;
	clock_t			 tmp_delay;
	clock_t			 start_clock;
	clock_t			 last_clock;

	/*
	 * For debugging
	 */
	ss = (fcoei_soft_state_t *)arg;
	FCOEI_LOG(__FUNCTION__, "ss %p", ss);
	FCOEI_LOG(__FUNCTION__, "sol_hash %p", ss->ss_sol_oxid_hash);
	FCOEI_LOG(__FUNCTION__, "unsol_hash %p", ss->ss_unsol_rxid_hash);
	ss->ss_flags |= SS_FLAG_WATCHDOG_RUNNING;
	tmp_delay = FCOE_SEC2TICK(1) / 2;
	last_clock = CURRENT_CLOCK;

	/*
	 * If nobody reqeusts to terminate the watchdog, we will work forever
	 */
	while (!(ss->ss_flags & SS_FLAG_TERMINATE_WATCHDOG)) {
		/*
		 * We handle all asynchronous events serially
		 */
		fcoei_process_events(ss);

		/*
		 * To avoid to check timing too freqently, we check
		 * if we need skip timing stuff.
		 */
		start_clock = CURRENT_CLOCK;
		if ((start_clock - last_clock) < tmp_delay) {
			goto end_timing;
		} else {
			last_clock = start_clock;
		}

		/*
		 * It's time to do timeout checking of solicited exchanges
		 */
		if (ss->ss_sol_cnt == (&ss->ss_sol_cnt1)) {
			if (ss->ss_sol_cnt2 == 0) {
				ss->ss_sol_cnt = &ss->ss_sol_cnt2;
			} else {
				mod_hash_walk(ss->ss_sol_oxid_hash,
				    fcoei_xch_check, ss);
			}
		} else {
			if (ss->ss_sol_cnt1 == 0) {
				ss->ss_sol_cnt = &ss->ss_sol_cnt1;
			} else {
				mod_hash_walk(ss->ss_sol_oxid_hash,
				    fcoei_xch_check, ss);
			}
		}

		/*
		 * It's time to do timeout checking of unsolicited exchange
		 */
		if (ss->ss_unsol_cnt == (&ss->ss_unsol_cnt1)) {
			if (ss->ss_unsol_cnt2 == 0) {
				ss->ss_unsol_cnt = &ss->ss_unsol_cnt2;
			} else {
				mod_hash_walk(ss->ss_unsol_rxid_hash,
				    fcoei_xch_check, ss);
			}
		} else {
			if (ss->ss_unsol_cnt1 == 0) {
				ss->ss_unsol_cnt = &ss->ss_unsol_cnt1;
			} else {
				mod_hash_walk(ss->ss_unsol_rxid_hash,
				    fcoei_xch_check, ss);
			}
		}

		/*
		 * Check if there are exchanges which are ready to complete
		 */
		fcoei_handle_comp_xch_list(ss);

	end_timing:
		/*
		 * Wait for next cycle
		 */
		mutex_enter(&ss->ss_watchdog_mutex);
		ss->ss_flags |= SS_FLAG_WATCHDOG_IDLE;
		if (!list_is_empty(&ss->ss_event_list)) {
			goto skip_wait;
		}

		(void) cv_timedwait(&ss->ss_watchdog_cv,
		    &ss->ss_watchdog_mutex, CURRENT_CLOCK +
		    (clock_t)tmp_delay);
	skip_wait:
		ss->ss_flags &= ~SS_FLAG_WATCHDOG_IDLE;
		mutex_exit(&ss->ss_watchdog_mutex);
	}

	/*
	 * Do clear work before exit
	 */
	fcoei_clear_watchdog_jobs(ss);

	/*
	 * Watchdog has stopped
	 */
	ss->ss_flags &= ~SS_FLAG_WATCHDOG_RUNNING;
}

static void
fcoei_clear_watchdog_jobs(fcoei_soft_state_t *ss)
{
	fcoei_event_t 		*ae;
	fcoe_frame_t		*frm;

	mutex_enter(&ss->ss_watchdog_mutex);
	while (!list_is_empty(&ss->ss_event_list)) {
		ae = (fcoei_event_t *)list_head(&ss->ss_event_list);
		list_remove(&ss->ss_event_list, ae);
		switch (ae->ae_type) {
		case AE_EVENT_SOL_FRAME:
			frm = (fcoe_frame_t *)ae->ae_obj;
			frm->frm_eport->eport_release_frame(frm);
			break;

		case AE_EVENT_UNSOL_FRAME:
			frm = (fcoe_frame_t *)ae->ae_obj;
			frm->frm_eport->eport_free_netb(frm->frm_netb);
			frm->frm_eport->eport_release_frame(frm);
			break;

		case AE_EVENT_PORT:
			atomic_dec_32(&ss->ss_port_event_counter);
			/* FALLTHROUGH */

		case AE_EVENT_RESET:
			kmem_free(ae, sizeof (fcoei_event_t));
			break;

		case AE_EVENT_EXCHANGE:
			/* FALLTHROUGH */

		default:
			break;
		}
	}

	mod_hash_clear(ss->ss_unsol_rxid_hash);
	mod_hash_clear(ss->ss_sol_oxid_hash);

	while (!list_is_empty(&ss->ss_comp_xch_list)) {
		(void) list_remove_head(&ss->ss_comp_xch_list);
	}
	mutex_exit(&ss->ss_watchdog_mutex);
}

/*
 * fcoei_process_events
 *	Process the events one by one
 *
 * Input:
 *	ss = the soft state that will be processed
 *
 * Return:
 *	N/A
 *
 * Comment:
 *	N/A
 */
static void
fcoei_process_events(fcoei_soft_state_t *ss)
{
	fcoei_event_t	*ae = NULL;

	/*
	 * It's the only place to delete node from ss_event_list, so we needn't
	 * hold mutex to check if the list is empty.
	 */
	ASSERT(!MUTEX_HELD(&ss->ss_watchdog_mutex));
	while (list_is_empty(&ss->ss_event_list) == B_FALSE) {
		mutex_enter(&ss->ss_watchdog_mutex);
		ae = (fcoei_event_t *)list_remove_head(&ss->ss_event_list);
		mutex_exit(&ss->ss_watchdog_mutex);

		switch (ae->ae_type) {
		case AE_EVENT_SOL_FRAME:
			fcoei_handle_sol_frame_done((fcoe_frame_t *)ae->ae_obj);
			break;

		case AE_EVENT_UNSOL_FRAME:
			fcoei_process_unsol_frame((fcoe_frame_t *)ae->ae_obj);
			break;

		case AE_EVENT_EXCHANGE:
			fcoei_process_event_exchange(ae);
			break;

		case AE_EVENT_PORT:
			fcoei_process_event_port(ae);
			break;

		case AE_EVENT_RESET:
			fcoei_process_event_reset(ae);
			break;

		default:
			FCOEI_LOG(__FUNCTION__, "unsupported events");
		}

	}
}

/*
 * fcoei_handle_tmout_xch_list
 *	Complete every exchange in the timed-out xch list of the soft state
 *
 * Input:
 *	ss = the soft state that need be handled
 *
 * Return:
 *	N/A
 *
 * Comment:
 *	When mod_hash_walk is in progress, we can't change the hashtable.
 *	This is post-walk handling of exchange timing
 */
void
fcoei_handle_comp_xch_list(fcoei_soft_state_t *ss)
{
	fcoei_exchange_t	*xch	  = NULL;

	while ((xch = list_remove_head(&ss->ss_comp_xch_list)) != NULL) {
		fcoei_complete_xch(xch, NULL, xch->xch_fpkt->pkt_state,
		    xch->xch_fpkt->pkt_reason);
	}
}

/*
 * fcoei_xch_check
 *	Check if the exchange timed out or link is down
 *
 * Input:
 *	key = rxid of the unsolicited exchange
 *	val = the unsolicited exchange
 *	arg = the soft state
 *
 * Return:
 *	MH_WALK_CONTINUE = continue to walk
 *
 * Comment:
 *	We need send ABTS for timed-out for solicited exchange
 *	If it's solicited FLOGI, we need set SS_FLAG_FLOGI_FAILED
 *	If the link is down, we think it has timed out too.
 */
/* ARGSUSED */
static uint32_t
fcoei_xch_check(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	fcoei_exchange_t	*xch = (fcoei_exchange_t *)val;

	ASSERT(xch->xch_ss == arg);
	if ((xch->xch_end_tick < CURRENT_CLOCK) &&
	    (xch->xch_ss->ss_link_state != FC_STATE_OFFLINE)) {
		if (xch->xch_flags & XCH_FLAG_IN_SOL_HASH) {
			ASSERT(xch->xch_oxid == CMHK(key));
			/*
			 * It's solicited exchange
			 */
			fcoei_abts_exchange(xch);
			if (LA_ELS_FLOGI == ((ls_code_t *)(void *)
			    xch->xch_fpkt->pkt_cmd)->ls_code) {
				/*
				 * It's solicited FLOGI
				 */
				xch->xch_ss->ss_flags |= SS_FLAG_FLOGI_FAILED;
			}
		}

		FCOEI_LOG(__FUNCTION__, "oxid-%x/rxid-%x  timed out",
		    xch->xch_oxid, xch->xch_rxid);
		xch->xch_flags |= XCH_FLAG_TMOUT;
		xch->xch_fpkt->pkt_state = FC_PKT_TIMEOUT;
		xch->xch_fpkt->pkt_reason = FC_REASON_ABORTED;
		list_insert_tail(&xch->xch_ss->ss_comp_xch_list, xch);
	} else if (xch->xch_ss->ss_link_state == FC_STATE_OFFLINE) {
		FCOEI_LOG(__FUNCTION__, "oxid-%x/rxid-%x  offline complete",
		    xch->xch_oxid, xch->xch_rxid);
		xch->xch_flags |= XCH_FLAG_TMOUT;
		xch->xch_fpkt->pkt_state = FC_PKT_PORT_OFFLINE;
		xch->xch_fpkt->pkt_reason = FC_REASON_OFFLINE;
		list_insert_tail(&xch->xch_ss->ss_comp_xch_list, xch);
	}

	return (MH_WALK_CONTINUE);
}

/*
 * fcoei_init_ifm
 *	initialize fcoei_frame
 *
 * Input:
 *	frm = the frame that ifm need link to
 *	xch = the exchange that ifm need link to
 *
 * Return:
 *	N/A
 *
 * Comment:
 *	For solicited frames, it's called after FC frame header initialization
 *	For unsolicited frames, it's called just after the frame enters fcoei
 */
void
fcoei_init_ifm(fcoe_frame_t *frm, fcoei_exchange_t *xch)
{
	FRM2IFM(frm)->ifm_frm = frm;
	FRM2IFM(frm)->ifm_xch = xch;
	FRM2IFM(frm)->ifm_rctl = FRM_R_CTL(frm);
}

/*
 * fcoei_trigger_fp_attach
 *	Trigger fp_attach for this fcoei port
 *
 * Input:
 *	arg = the soft state that fp will attach
 *
 * Return:
 *	N/A
 *
 * Comment:
 *	N/A
 */
static void
fcoei_trigger_fp_attach(void * arg)
{
	fcoei_soft_state_t	*ss    = (fcoei_soft_state_t *)arg;
	dev_info_t		*child = NULL;
	int			 rval  = NDI_FAILURE;

	ndi_devi_alloc_sleep(ss->ss_dip, "fp", DEVI_PSEUDO_NODEID, &child);
	if (child == NULL) {
		FCOEI_LOG(__FUNCTION__, "can't alloc dev_info");
		return;
	}

	/*
	 * fp/fctl need this property
	 */
	if (ddi_prop_update_string(DDI_DEV_T_NONE, child,
	    "bus-addr", "0,0") != DDI_PROP_SUCCESS) {
		FCOEI_LOG(__FUNCTION__, "update bus-addr failed");
		(void) ndi_devi_free(child);
		return;
	}

	/*
	 * If it's physical HBA, fp.conf will register the property.
	 * fcoei is one software HBA, so we need register it manually
	 */
	if (ddi_prop_update_int(DDI_DEV_T_NONE, child,
	    "port", 0) != DDI_PROP_SUCCESS) {
		FCOEI_LOG(__FUNCTION__, "update port failed");
		(void) ndi_devi_free(child);
		return;
	}

	/*
	 * It will call fp_attach eventually
	 */
	rval = ndi_devi_online(child, NDI_ONLINE_ATTACH);
	ss->ss_flags &= ~SS_FLAG_TRIGGER_FP_ATTACH;
	if (rval != NDI_SUCCESS) {
		FCOEI_LOG(__FUNCTION__, "devi_online: %d", rval);
	} else {
		FCOEI_LOG(__FUNCTION__, "triggered successfully");
	}
}

/*
 * fcoei_abts_exchange
 *	Send ABTS to abort solicited exchange
 *
 * Input:
 *	xch = the exchange that will be aborted
 *
 * Return:
 *	N/A
 *
 * Comment:
 *	ABTS frame uses the same oxid as the exchange
 */
static void
fcoei_abts_exchange(fcoei_exchange_t *xch)
{
	fc_packet_t	*fpkt = xch->xch_fpkt;
	fcoe_frame_t	*frm  = NULL;

	/*
	 * BLS_ABTS doesn't contain any other payload except FCFH
	 */
	frm = xch->xch_ss->ss_eport->eport_alloc_frame(xch->xch_ss->ss_eport,
	    FCFH_SIZE, NULL);
	if (frm == NULL) {
		FCOEI_LOG(__FUNCTION__, "can't alloc frame: %p", xch);
		return;
	}

	FFM_R_CTL(0x81, frm);
	FFM_D_ID(fpkt->pkt_cmd_fhdr.d_id, frm);
	FFM_S_ID(fpkt->pkt_cmd_fhdr.s_id, frm);
	FFM_F_CTL(0x090000, frm);
	FFM_SEQ_ID(0x01, frm);
	FFM_OXID(xch->xch_oxid, frm);
	FFM_RXID(xch->xch_rxid, frm);
	fcoei_init_ifm(frm, xch);
	xch->xch_ss->ss_eport->eport_tx_frame(frm);
}

/*
 * fcoei_complete_xch
 *	Complete the exchange
 *
 * Input:
 *	xch = the exchange that will be completed
 *	frm = newly-allocated frame that has not been submitted
 *	pkt_state = LV fpkt state
 *	pkt_reason = LV fpkt reason
 *
 * Return:
 *	N/A
 *
 * Comment:
 *	N/A
 */
void
fcoei_complete_xch(fcoei_exchange_t *xch, fcoe_frame_t *frm,
    uint8_t pkt_state, uint8_t pkt_reason)
{
	mod_hash_val_t val;

	if (pkt_state != FC_PKT_SUCCESS) {
		FCOEI_LOG(__FUNCTION__, "FHDR: %x/%x/%x, %x/%x/%x",
		    xch->xch_fpkt->pkt_cmd_fhdr.r_ctl,
		    xch->xch_fpkt->pkt_cmd_fhdr.f_ctl,
		    xch->xch_fpkt->pkt_cmd_fhdr.type,
		    xch->xch_fpkt->pkt_resp_fhdr.r_ctl,
		    xch->xch_fpkt->pkt_resp_fhdr.f_ctl,
		    xch->xch_fpkt->pkt_resp_fhdr.type);
		FCOEI_LOG(__FUNCTION__, "%p/%p/%x/%x",
		    xch, frm, pkt_state, pkt_reason);
	}

	if (frm != NULL) {
		/*
		 * It's newly-allocated frame , which we haven't sent out
		 */
		xch->xch_ss->ss_eport->eport_free_netb(frm->frm_netb);
		xch->xch_ss->ss_eport->eport_release_frame(frm);
		FCOEI_LOG(__FUNCTION__, "xch: %p, not submitted", xch);
	}

	/*
	 * If xch is in hash table, we need remove it
	 */
	if (xch->xch_flags & XCH_FLAG_IN_SOL_HASH) {
		(void) mod_hash_remove(xch->xch_ss->ss_sol_oxid_hash,
		    FMHK(xch->xch_oxid), &val);
		ASSERT((fcoei_exchange_t *)val == xch);
		xch->xch_flags &= ~XCH_FLAG_IN_SOL_HASH;
	} else if (xch->xch_flags & XCH_FLAG_IN_UNSOL_HASH) {
		(void) mod_hash_remove(xch->xch_ss->ss_unsol_rxid_hash,
		    FMHK(xch->xch_rxid), &val);
		ASSERT((fcoei_exchange_t *)val == xch);
		xch->xch_flags &= ~XCH_FLAG_IN_UNSOL_HASH;
	} else {
		FCOEI_LOG(__FUNCTION__, "xch not in any hash: %p", xch);
	}

	xch->xch_fpkt->pkt_state = pkt_state;
	xch->xch_fpkt->pkt_reason = pkt_reason;
	if (xch->xch_fpkt->pkt_tran_flags & FC_TRAN_NO_INTR) {
		FCOEI_LOG(__FUNCTION__, "polled xch is done: %p", xch);
		sema_v(&xch->xch_sema);
	} else {
		xch->xch_fpkt->pkt_comp(xch->xch_fpkt);
	}
}
