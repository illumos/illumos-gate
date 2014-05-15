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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * ibdm.c
 *
 * This file contains the InifiniBand Device Manager (IBDM) support functions.
 * IB nexus driver will only be the client for the IBDM module.
 *
 * IBDM registers with IBTF for HCA arrival/removal notification.
 * IBDM registers with SA access to send DM MADs to discover the IOC's behind
 * the IOU's.
 *
 * IB nexus driver registers with IBDM to find the information about the
 * HCA's and IOC's (behind the IOU) present on the IB fabric.
 */

#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/taskq.h>
#include <sys/ib/mgt/ibdm/ibdm_impl.h>
#include <sys/ib/mgt/ibmf/ibmf_impl.h>
#include <sys/ib/ibtl/impl/ibtl_ibnex.h>
#include <sys/modctl.h>

/* Function Prototype declarations */
static int	ibdm_free_iou_info(ibdm_dp_gidinfo_t *, ibdm_iou_info_t **);
static int	ibdm_fini(void);
static int	ibdm_init(void);
static int	ibdm_get_reachable_ports(ibdm_port_attr_t *,
			ibdm_hca_list_t *);
static ibdm_dp_gidinfo_t *ibdm_check_dgid(ib_guid_t, ib_sn_prefix_t);
static ibdm_dp_gidinfo_t *ibdm_check_dest_nodeguid(ibdm_dp_gidinfo_t *);
static boolean_t ibdm_is_cisco(ib_guid_t);
static boolean_t ibdm_is_cisco_switch(ibdm_dp_gidinfo_t *);
static void	ibdm_wait_cisco_probe_completion(ibdm_dp_gidinfo_t *);
static int	ibdm_set_classportinfo(ibdm_dp_gidinfo_t *);
static int	ibdm_send_classportinfo(ibdm_dp_gidinfo_t *);
static int	ibdm_send_iounitinfo(ibdm_dp_gidinfo_t *);
static int	ibdm_is_dev_mgt_supported(ibdm_dp_gidinfo_t *);
static int	ibdm_get_node_port_guids(ibmf_saa_handle_t, ib_lid_t,
		    ib_guid_t *, ib_guid_t *);
static int	ibdm_retry_command(ibdm_timeout_cb_args_t *);
static int	ibdm_get_diagcode(ibdm_dp_gidinfo_t *, int);
static int	ibdm_verify_mad_status(ib_mad_hdr_t *);
static int	ibdm_handle_redirection(ibmf_msg_t *,
		    ibdm_dp_gidinfo_t *, int *);
static void	ibdm_wait_probe_completion(void);
static void	ibdm_sweep_fabric(int);
static void	ibdm_probe_gid_thread(void *);
static void	ibdm_wakeup_probe_gid_cv(void);
static void	ibdm_port_attr_ibmf_init(ibdm_port_attr_t *, ib_pkey_t, int);
static int	ibdm_port_attr_ibmf_fini(ibdm_port_attr_t *, int);
static void	ibdm_update_port_attr(ibdm_port_attr_t *);
static void	ibdm_handle_hca_attach(ib_guid_t);
static void	ibdm_handle_srventry_mad(ibmf_msg_t *,
		    ibdm_dp_gidinfo_t *, int *);
static void	ibdm_ibmf_recv_cb(ibmf_handle_t, ibmf_msg_t *, void *);
static void	ibdm_recv_incoming_mad(void *);
static void	ibdm_process_incoming_mad(ibmf_handle_t, ibmf_msg_t *, void *);
static void	ibdm_ibmf_send_cb(ibmf_handle_t, ibmf_msg_t *, void *);
static void	ibdm_pkt_timeout_hdlr(void *arg);
static void	ibdm_initialize_port(ibdm_port_attr_t *);
static void	ibdm_update_port_pkeys(ibdm_port_attr_t *port);
static void	ibdm_handle_diagcode(ibmf_msg_t *, ibdm_dp_gidinfo_t *, int *);
static void	ibdm_probe_gid(ibdm_dp_gidinfo_t *);
static void	ibdm_alloc_send_buffers(ibmf_msg_t *);
static void	ibdm_free_send_buffers(ibmf_msg_t *);
static void	ibdm_handle_hca_detach(ib_guid_t);
static void	ibdm_handle_port_change_event(ibt_async_event_t *);
static int	ibdm_fini_port(ibdm_port_attr_t *);
static int	ibdm_uninit_hca(ibdm_hca_list_t *);
static void	ibdm_handle_setclassportinfo(ibmf_handle_t, ibmf_msg_t *,
		    ibdm_dp_gidinfo_t *, int *);
static void	ibdm_handle_iounitinfo(ibmf_handle_t,
		    ibmf_msg_t *, ibdm_dp_gidinfo_t *, int *);
static void	ibdm_handle_ioc_profile(ibmf_handle_t,
		    ibmf_msg_t *, ibdm_dp_gidinfo_t *, int *);
static void	ibdm_event_hdlr(void *, ibt_hca_hdl_t,
		    ibt_async_code_t, ibt_async_event_t *);
static void	ibdm_handle_classportinfo(ibmf_handle_t,
		    ibmf_msg_t *, ibdm_dp_gidinfo_t *, int *);
static void	ibdm_update_ioc_port_gidlist(ibdm_ioc_info_t *,
		    ibdm_dp_gidinfo_t *);

static ibdm_hca_list_t		*ibdm_dup_hca_attr(ibdm_hca_list_t *);
static ibdm_ioc_info_t		*ibdm_dup_ioc_info(ibdm_ioc_info_t *,
				    ibdm_dp_gidinfo_t *gid_list);
static void			ibdm_probe_ioc(ib_guid_t, ib_guid_t, int);
static ibdm_ioc_info_t		*ibdm_is_ioc_present(ib_guid_t,
				    ibdm_dp_gidinfo_t *, int *);
static ibdm_port_attr_t		*ibdm_get_port_attr(ibt_async_event_t *,
				    ibdm_hca_list_t **);
static sa_node_record_t		*ibdm_get_node_records(ibmf_saa_handle_t,
				    size_t *, ib_guid_t);
static int			ibdm_get_node_record_by_port(ibmf_saa_handle_t,
				    ib_guid_t, sa_node_record_t **, size_t *);
static sa_portinfo_record_t	*ibdm_get_portinfo(ibmf_saa_handle_t, size_t *,
				    ib_lid_t);
static ibdm_dp_gidinfo_t	*ibdm_create_gid_info(ibdm_port_attr_t *,
				    ib_gid_t, ib_gid_t);
static ibdm_dp_gidinfo_t	*ibdm_find_gid(ib_guid_t, ib_guid_t);
static int	ibdm_send_ioc_profile(ibdm_dp_gidinfo_t *, uint8_t);
static ibdm_ioc_info_t	*ibdm_update_ioc_gidlist(ibdm_dp_gidinfo_t *, int);
static void	ibdm_saa_event_cb(ibmf_saa_handle_t, ibmf_saa_subnet_event_t,
		    ibmf_saa_event_details_t *, void *);
static void	ibdm_reprobe_update_port_srv(ibdm_ioc_info_t *,
    ibdm_dp_gidinfo_t *);
static ibdm_dp_gidinfo_t *ibdm_handle_gid_rm(ibdm_dp_gidinfo_t *);
static void ibdm_rmfrom_glgid_list(ibdm_dp_gidinfo_t *,
    ibdm_dp_gidinfo_t *);
static void ibdm_addto_gidlist(ibdm_gid_t **, ibdm_gid_t *);
static void ibdm_free_gid_list(ibdm_gid_t *);
static void ibdm_rescan_gidlist(ib_guid_t *ioc_guid);
static void ibdm_notify_newgid_iocs(ibdm_dp_gidinfo_t *);
static void ibdm_saa_event_taskq(void *);
static void ibdm_free_saa_event_arg(ibdm_saa_event_arg_t *);
static void ibdm_get_next_port(ibdm_hca_list_t **,
    ibdm_port_attr_t **, int);
static void ibdm_add_to_gl_gid(ibdm_dp_gidinfo_t *,
    ibdm_dp_gidinfo_t *);
static void ibdm_addto_glhcalist(ibdm_dp_gidinfo_t *,
    ibdm_hca_list_t *);
static void ibdm_delete_glhca_list(ibdm_dp_gidinfo_t *);
static void ibdm_saa_handle_new_gid(void *);
static void ibdm_reset_all_dgids(ibmf_saa_handle_t);
static void ibdm_reset_gidinfo(ibdm_dp_gidinfo_t *);
static void ibdm_delete_gidinfo(ibdm_dp_gidinfo_t *);
static void ibdm_fill_srv_attr_mod(ib_mad_hdr_t *, ibdm_timeout_cb_args_t *);
static void ibdm_bump_transactionID(ibdm_dp_gidinfo_t *);
static ibdm_ioc_info_t	*ibdm_handle_prev_iou();
static int ibdm_serv_cmp(ibdm_srvents_info_t *, ibdm_srvents_info_t *,
    int);
static ibdm_ioc_info_t *ibdm_get_ioc_info_with_gid(ib_guid_t,
    ibdm_dp_gidinfo_t **);

int	ibdm_dft_timeout	= IBDM_DFT_TIMEOUT;
int	ibdm_dft_retry_cnt	= IBDM_DFT_NRETRIES;
#ifdef DEBUG
int	ibdm_ignore_saa_event = 0;
#endif
int	ibdm_enumerate_iocs = 0;

/* Modload support */
static struct modlmisc ibdm_modlmisc	= {
	&mod_miscops,
	"InfiniBand Device Manager"
};

struct modlinkage ibdm_modlinkage = {
	MODREV_1,
	(void *)&ibdm_modlmisc,
	NULL
};

static ibt_clnt_modinfo_t ibdm_ibt_modinfo = {
	IBTI_V_CURR,
	IBT_DM,
	ibdm_event_hdlr,
	NULL,
	"ibdm"
};

/* Global variables */
ibdm_t	ibdm;
int	ibdm_taskq_enable = IBDM_ENABLE_TASKQ_HANDLING;
char	*ibdm_string = "ibdm";

_NOTE(SCHEME_PROTECTS_DATA("Serialized access by cv",
    ibdm.ibdm_dp_gidlist_head))

/*
 * _init
 *	Loadable module init, called before any other module.
 *	Initialize mutex
 *	Register with IBTF
 */
int
_init(void)
{
	int		err;

	IBTF_DPRINTF_L4("ibdm", "\t_init: addr of ibdm %p", &ibdm);

	if ((err = ibdm_init()) != IBDM_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm", "_init: ibdm_init failed 0x%x", err);
		(void) ibdm_fini();
		return (DDI_FAILURE);
	}

	if ((err = mod_install(&ibdm_modlinkage)) != 0) {
		IBTF_DPRINTF_L2("ibdm", "_init: mod_install failed 0x%x", err);
		(void) ibdm_fini();
	}
	return (err);
}


int
_fini(void)
{
	int err;

	if ((err = ibdm_fini()) != IBDM_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm", "_fini: ibdm_fini failed 0x%x", err);
		(void) ibdm_init();
		return (EBUSY);
	}

	if ((err = mod_remove(&ibdm_modlinkage)) != 0) {
		IBTF_DPRINTF_L2("ibdm", "_fini: mod_remove failed 0x%x", err);
		(void) ibdm_init();
	}
	return (err);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ibdm_modlinkage, modinfop));
}


/*
 * ibdm_init():
 * 	Register with IBTF
 *	Allocate memory for the HCAs
 *	Allocate minor-nodes for the HCAs
 */
static int
ibdm_init(void)
{
	int			i, hca_count;
	ib_guid_t		*hca_guids;
	ibt_status_t		status;

	IBTF_DPRINTF_L4("ibdm", "\tibdm_init:");
	if (!(ibdm.ibdm_state & IBDM_LOCKS_ALLOCED)) {
		mutex_init(&ibdm.ibdm_mutex, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&ibdm.ibdm_hl_mutex, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&ibdm.ibdm_ibnex_mutex, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&ibdm.ibdm_port_settle_cv, NULL, CV_DRIVER, NULL);
		mutex_enter(&ibdm.ibdm_mutex);
		ibdm.ibdm_state |= IBDM_LOCKS_ALLOCED;
	}

	if (!(ibdm.ibdm_state & IBDM_IBT_ATTACHED)) {
		if ((status = ibt_attach(&ibdm_ibt_modinfo, NULL, NULL,
		    (void *)&ibdm.ibdm_ibt_clnt_hdl)) != IBT_SUCCESS) {
			IBTF_DPRINTF_L2("ibdm", "ibdm_init: ibt_attach "
			    "failed %x", status);
			mutex_exit(&ibdm.ibdm_mutex);
			return (IBDM_FAILURE);
		}

		ibdm.ibdm_state |= IBDM_IBT_ATTACHED;
		mutex_exit(&ibdm.ibdm_mutex);
	}


	if (!(ibdm.ibdm_state & IBDM_HCA_ATTACHED)) {
		hca_count = ibt_get_hca_list(&hca_guids);
		IBTF_DPRINTF_L4("ibdm", "ibdm_init: num_hcas = %d", hca_count);
		for (i = 0; i < hca_count; i++)
			(void) ibdm_handle_hca_attach(hca_guids[i]);
		if (hca_count)
			ibt_free_hca_list(hca_guids, hca_count);

		mutex_enter(&ibdm.ibdm_mutex);
		ibdm.ibdm_state |= IBDM_HCA_ATTACHED;
		mutex_exit(&ibdm.ibdm_mutex);
	}

	if (!(ibdm.ibdm_state & IBDM_CVS_ALLOCED)) {
		cv_init(&ibdm.ibdm_probe_cv, NULL, CV_DRIVER, NULL);
		cv_init(&ibdm.ibdm_busy_cv, NULL, CV_DRIVER, NULL);
		mutex_enter(&ibdm.ibdm_mutex);
		ibdm.ibdm_state |= IBDM_CVS_ALLOCED;
		mutex_exit(&ibdm.ibdm_mutex);
	}
	return (IBDM_SUCCESS);
}


static int
ibdm_free_iou_info(ibdm_dp_gidinfo_t *gid_info, ibdm_iou_info_t **ioup)
{
	int			ii, k, niocs;
	size_t			size;
	ibdm_gid_t		*delete, *head;
	timeout_id_t		timeout_id;
	ibdm_ioc_info_t		*ioc;
	ibdm_iou_info_t		*gl_iou = *ioup;

	ASSERT(mutex_owned(&gid_info->gl_mutex));
	if (gl_iou == NULL) {
		IBTF_DPRINTF_L4("ibdm", "\tibdm_free_iou_info: No IOU");
		return (0);
	}

	niocs = gl_iou->iou_info.iou_num_ctrl_slots;
	IBTF_DPRINTF_L4("ibdm", "\tfree_iou_info: gid_info = %p, niocs %d",
	    gid_info, niocs);

	for (ii = 0; ii < niocs; ii++) {
		ioc = (ibdm_ioc_info_t *)&gl_iou->iou_ioc_info[ii];

		/* handle the case where an ioc_timeout_id is scheduled */
		if (ioc->ioc_timeout_id) {
			timeout_id = ioc->ioc_timeout_id;
			ioc->ioc_timeout_id = 0;
			mutex_exit(&gid_info->gl_mutex);
			IBTF_DPRINTF_L5("ibdm", "free_iou_info: "
			    "ioc_timeout_id = 0x%x", timeout_id);
			if (untimeout(timeout_id) == -1) {
				IBTF_DPRINTF_L2("ibdm", "free_iou_info: "
				    "untimeout ioc_timeout_id failed");
				mutex_enter(&gid_info->gl_mutex);
				return (-1);
			}
			mutex_enter(&gid_info->gl_mutex);
		}

		/* handle the case where an ioc_dc_timeout_id is scheduled */
		if (ioc->ioc_dc_timeout_id) {
			timeout_id = ioc->ioc_dc_timeout_id;
			ioc->ioc_dc_timeout_id = 0;
			mutex_exit(&gid_info->gl_mutex);
			IBTF_DPRINTF_L5("ibdm", "free_iou_info: "
			    "ioc_dc_timeout_id = 0x%x", timeout_id);
			if (untimeout(timeout_id) == -1) {
				IBTF_DPRINTF_L2("ibdm", "free_iou_info: "
				    "untimeout ioc_dc_timeout_id failed");
				mutex_enter(&gid_info->gl_mutex);
				return (-1);
			}
			mutex_enter(&gid_info->gl_mutex);
		}

		/* handle the case where serv[k].se_timeout_id is scheduled */
		for (k = 0; k < ioc->ioc_profile.ioc_service_entries; k++) {
			if (ioc->ioc_serv[k].se_timeout_id) {
				timeout_id = ioc->ioc_serv[k].se_timeout_id;
				ioc->ioc_serv[k].se_timeout_id = 0;
				mutex_exit(&gid_info->gl_mutex);
				IBTF_DPRINTF_L5("ibdm", "free_iou_info: "
				    "ioc->ioc_serv[%d].se_timeout_id = 0x%x",
				    k, timeout_id);
				if (untimeout(timeout_id) == -1) {
					IBTF_DPRINTF_L2("ibdm", "free_iou_info:"
					    " untimeout se_timeout_id failed");
					mutex_enter(&gid_info->gl_mutex);
					return (-1);
				}
				mutex_enter(&gid_info->gl_mutex);
			}
		}

		/* delete GID list in IOC */
		head = ioc->ioc_gid_list;
		while (head) {
			IBTF_DPRINTF_L4("ibdm", "\tibdm_free_iou_info: "
			    "Deleting gid_list struct %p", head);
			delete = head;
			head = head->gid_next;
			kmem_free(delete, sizeof (ibdm_gid_t));
		}
		ioc->ioc_gid_list = NULL;

		/* delete ioc_serv */
		size = ioc->ioc_profile.ioc_service_entries *
		    sizeof (ibdm_srvents_info_t);
		if (ioc->ioc_serv && size) {
			kmem_free(ioc->ioc_serv, size);
			ioc->ioc_serv = NULL;
		}
	}
	/*
	 * Clear the IBDM_CISCO_PROBE_DONE flag to get the IO Unit information
	 * via the switch during the probe process.
	 */
	gid_info->gl_flag &= ~IBDM_CISCO_PROBE_DONE;

	IBTF_DPRINTF_L4("ibdm", "\tibdm_free_iou_info: deleting IOU & IOC");
	size = sizeof (ibdm_iou_info_t) + niocs * sizeof (ibdm_ioc_info_t);
	kmem_free(gl_iou, size);
	*ioup = NULL;
	return (0);
}


/*
 * ibdm_fini():
 * 	Un-register with IBTF
 *	De allocate memory for the GID info
 */
static int
ibdm_fini()
{
	int			ii;
	ibdm_hca_list_t		*hca_list, *temp;
	ibdm_dp_gidinfo_t	*gid_info, *tmp;
	ibdm_gid_t		*head, *delete;

	IBTF_DPRINTF_L4("ibdm", "\tibdm_fini");

	mutex_enter(&ibdm.ibdm_hl_mutex);
	if (ibdm.ibdm_state & IBDM_IBT_ATTACHED) {
		if (ibt_detach(ibdm.ibdm_ibt_clnt_hdl) != IBT_SUCCESS) {
			IBTF_DPRINTF_L2("ibdm", "\t_fini: ibt_detach failed");
			mutex_exit(&ibdm.ibdm_hl_mutex);
			return (IBDM_FAILURE);
		}
		ibdm.ibdm_state &= ~IBDM_IBT_ATTACHED;
		ibdm.ibdm_ibt_clnt_hdl = NULL;
	}

	hca_list = ibdm.ibdm_hca_list_head;
	IBTF_DPRINTF_L4("ibdm", "\tibdm_fini: nhcas %d", ibdm.ibdm_hca_count);
	for (ii = 0; ii < ibdm.ibdm_hca_count; ii++) {
		temp = hca_list;
		hca_list = hca_list->hl_next;
		IBTF_DPRINTF_L4("ibdm", "\tibdm_fini: hca %p", temp);
		if (ibdm_uninit_hca(temp) != IBDM_SUCCESS) {
			IBTF_DPRINTF_L2("ibdm", "\tibdm_fini: "
			    "uninit_hca %p failed", temp);
			mutex_exit(&ibdm.ibdm_hl_mutex);
			return (IBDM_FAILURE);
		}
	}
	mutex_exit(&ibdm.ibdm_hl_mutex);

	mutex_enter(&ibdm.ibdm_mutex);
	if (ibdm.ibdm_state & IBDM_HCA_ATTACHED)
		ibdm.ibdm_state &= ~IBDM_HCA_ATTACHED;

	gid_info = ibdm.ibdm_dp_gidlist_head;
	while (gid_info) {
		mutex_enter(&gid_info->gl_mutex);
		(void) ibdm_free_iou_info(gid_info, &gid_info->gl_iou);
		mutex_exit(&gid_info->gl_mutex);
		ibdm_delete_glhca_list(gid_info);

		tmp = gid_info;
		gid_info = gid_info->gl_next;
		mutex_destroy(&tmp->gl_mutex);
		head = tmp->gl_gid;
		while (head) {
			IBTF_DPRINTF_L4("ibdm",
			    "\tibdm_fini: Deleting gid structs");
			delete = head;
			head = head->gid_next;
			kmem_free(delete, sizeof (ibdm_gid_t));
		}
		kmem_free(tmp, sizeof (ibdm_dp_gidinfo_t));
	}
	mutex_exit(&ibdm.ibdm_mutex);

	if (ibdm.ibdm_state & IBDM_LOCKS_ALLOCED) {
		ibdm.ibdm_state &= ~IBDM_LOCKS_ALLOCED;
		mutex_destroy(&ibdm.ibdm_mutex);
		mutex_destroy(&ibdm.ibdm_hl_mutex);
		mutex_destroy(&ibdm.ibdm_ibnex_mutex);
		cv_destroy(&ibdm.ibdm_port_settle_cv);
	}
	if (ibdm.ibdm_state & IBDM_CVS_ALLOCED) {
		ibdm.ibdm_state &= ~IBDM_CVS_ALLOCED;
		cv_destroy(&ibdm.ibdm_probe_cv);
		cv_destroy(&ibdm.ibdm_busy_cv);
	}
	return (IBDM_SUCCESS);
}


/*
 * ibdm_event_hdlr()
 *
 *	IBDM registers  this asynchronous event handler at the time of
 *	ibt_attach. IBDM support the following async events. For other
 *	event, simply returns success.
 *	IBT_HCA_ATTACH_EVENT:
 *		Retrieves the  information about all the port that are
 *		present on this HCA,  allocates  the  port  attributes
 *		structure  and calls IB  nexus  callback  routine with
 *		the port attributes structure as an input argument.
 *	IBT_HCA_DETACH_EVENT:
 *		Retrieves the information about all the ports that are
 *		present on  this HCA and  calls IB nexus callback with
 *		port guid as an argument
 *	IBT_EVENT_PORT_UP:
 *		Register with IBMF and SA access
 *		Setup IBMF receive callback routine
 *	IBT_EVENT_PORT_DOWN:
 *		Un-Register with IBMF and SA access
 *		Teardown IBMF receive callback routine
 */
/*ARGSUSED*/
static void
ibdm_event_hdlr(void *clnt_hdl,
    ibt_hca_hdl_t hca_hdl, ibt_async_code_t code, ibt_async_event_t *event)
{
	ibdm_hca_list_t		*hca_list;
	ibdm_port_attr_t	*port;
	ibmf_saa_handle_t	port_sa_hdl;

	IBTF_DPRINTF_L4("ibdm", "\tevent_hdlr: async code 0x%x", code);

	switch (code) {
	case IBT_HCA_ATTACH_EVENT:	/* New HCA registered with IBTF */
		ibdm_handle_hca_attach(event->ev_hca_guid);
		break;

	case IBT_HCA_DETACH_EVENT:	/* HCA unregistered with IBTF */
		ibdm_handle_hca_detach(event->ev_hca_guid);
		mutex_enter(&ibdm.ibdm_ibnex_mutex);
		if (ibdm.ibdm_ibnex_callback != NULL) {
			(*ibdm.ibdm_ibnex_callback)((void *)
			    &event->ev_hca_guid, IBDM_EVENT_HCA_REMOVED);
		}
		mutex_exit(&ibdm.ibdm_ibnex_mutex);
		break;

	case IBT_EVENT_PORT_UP:
		IBTF_DPRINTF_L4("ibdm", "\tevent_hdlr: PORT_UP");
		mutex_enter(&ibdm.ibdm_hl_mutex);
		port = ibdm_get_port_attr(event, &hca_list);
		if (port == NULL) {
			IBTF_DPRINTF_L2("ibdm",
			    "\tevent_hdlr: HCA not present");
			mutex_exit(&ibdm.ibdm_hl_mutex);
			break;
		}
		ibdm_initialize_port(port);
		hca_list->hl_nports_active++;
		cv_broadcast(&ibdm.ibdm_port_settle_cv);
		mutex_exit(&ibdm.ibdm_hl_mutex);

		/* Inform IB nexus driver */
		mutex_enter(&ibdm.ibdm_ibnex_mutex);
		if (ibdm.ibdm_ibnex_callback != NULL) {
			(*ibdm.ibdm_ibnex_callback)((void *)
			    &event->ev_hca_guid, IBDM_EVENT_PORT_UP);
		}
		mutex_exit(&ibdm.ibdm_ibnex_mutex);
		break;

	case IBT_ERROR_PORT_DOWN:
		IBTF_DPRINTF_L4("ibdm", "\tevent_hdlr: PORT_DOWN");
		mutex_enter(&ibdm.ibdm_hl_mutex);
		port = ibdm_get_port_attr(event, &hca_list);
		if (port == NULL) {
			IBTF_DPRINTF_L2("ibdm",
			    "\tevent_hdlr: HCA not present");
			mutex_exit(&ibdm.ibdm_hl_mutex);
			break;
		}
		hca_list->hl_nports_active--;
		port_sa_hdl = port->pa_sa_hdl;
		(void) ibdm_fini_port(port);
		port->pa_state = IBT_PORT_DOWN;
		cv_broadcast(&ibdm.ibdm_port_settle_cv);
		mutex_exit(&ibdm.ibdm_hl_mutex);
		ibdm_reset_all_dgids(port_sa_hdl);
		break;

	case IBT_PORT_CHANGE_EVENT:
		IBTF_DPRINTF_L4("ibdm", "\tevent_hdlr: PORT_CHANGE");
		if (event->ev_port_flags & IBT_PORT_CHANGE_PKEY)
			ibdm_handle_port_change_event(event);
		break;

	default:		/* Ignore all other events/errors */
		break;
	}
}

static void
ibdm_handle_port_change_event(ibt_async_event_t *event)
{
	ibdm_port_attr_t	*port;
	ibdm_hca_list_t		*hca_list;

	IBTF_DPRINTF_L2("ibdm", "\tibdm_handle_port_change_event:"
	    " HCA guid  %llx", event->ev_hca_guid);
	mutex_enter(&ibdm.ibdm_hl_mutex);
	port = ibdm_get_port_attr(event, &hca_list);
	if (port == NULL) {
		IBTF_DPRINTF_L2("ibdm", "\tevent_hdlr: HCA not present");
		mutex_exit(&ibdm.ibdm_hl_mutex);
		return;
	}
	ibdm_update_port_pkeys(port);
	cv_broadcast(&ibdm.ibdm_port_settle_cv);
	mutex_exit(&ibdm.ibdm_hl_mutex);

	/* Inform IB nexus driver */
	mutex_enter(&ibdm.ibdm_ibnex_mutex);
	if (ibdm.ibdm_ibnex_callback != NULL) {
		(*ibdm.ibdm_ibnex_callback)((void *)
		    &event->ev_hca_guid, IBDM_EVENT_PORT_PKEY_CHANGE);
	}
	mutex_exit(&ibdm.ibdm_ibnex_mutex);
}

/*
 * ibdm_update_port_pkeys()
 *	Update the pkey table
 *	Update the port attributes
 */
static void
ibdm_update_port_pkeys(ibdm_port_attr_t *port)
{
	uint_t				nports, size;
	uint_t				pkey_idx, opkey_idx;
	uint16_t			npkeys;
	ibt_hca_portinfo_t		*pinfop;
	ib_pkey_t			pkey;
	ibdm_pkey_tbl_t			*pkey_tbl;
	ibdm_port_attr_t		newport;

	IBTF_DPRINTF_L4("ibdm", "\tupdate_port_pkeys:");
	ASSERT(MUTEX_HELD(&ibdm.ibdm_hl_mutex));

	/* Check whether the port is active */
	if (ibt_get_port_state(port->pa_hca_hdl, port->pa_port_num, NULL,
	    NULL) != IBT_SUCCESS)
		return;

	if (ibt_query_hca_ports(port->pa_hca_hdl, port->pa_port_num,
	    &pinfop, &nports, &size) != IBT_SUCCESS) {
		/* This should not occur */
		port->pa_npkeys = 0;
		port->pa_pkey_tbl = NULL;
		return;
	}

	npkeys = pinfop->p_pkey_tbl_sz;
	pkey_tbl = kmem_zalloc(npkeys * sizeof (ibdm_pkey_tbl_t), KM_SLEEP);
	newport.pa_pkey_tbl = pkey_tbl;
	newport.pa_ibmf_hdl = port->pa_ibmf_hdl;

	for (pkey_idx = 0; pkey_idx < npkeys; pkey_idx++) {
		pkey = pkey_tbl[pkey_idx].pt_pkey =
		    pinfop->p_pkey_tbl[pkey_idx];
		/*
		 * Is this pkey present in the current table ?
		 */
		for (opkey_idx = 0; opkey_idx < port->pa_npkeys; opkey_idx++) {
			if (pkey == port->pa_pkey_tbl[opkey_idx].pt_pkey) {
				pkey_tbl[pkey_idx].pt_qp_hdl =
				    port->pa_pkey_tbl[opkey_idx].pt_qp_hdl;
				port->pa_pkey_tbl[opkey_idx].pt_qp_hdl = NULL;
				break;
			}
		}

		if (opkey_idx == port->pa_npkeys) {
			pkey = pkey_tbl[pkey_idx].pt_pkey;
			if (IBDM_INVALID_PKEY(pkey)) {
				pkey_tbl[pkey_idx].pt_qp_hdl = NULL;
				continue;
			}
			ibdm_port_attr_ibmf_init(&newport, pkey, pkey_idx);
		}
	}

	for (opkey_idx = 0; opkey_idx < port->pa_npkeys; opkey_idx++) {
		if (port->pa_pkey_tbl[opkey_idx].pt_qp_hdl != NULL) {
			if (ibdm_port_attr_ibmf_fini(port, opkey_idx) !=
			    IBDM_SUCCESS) {
				IBTF_DPRINTF_L2("ibdm", "\tupdate_port_pkeys: "
				    "ibdm_port_attr_ibmf_fini failed for "
				    "port pkey 0x%x",
				    port->pa_pkey_tbl[opkey_idx].pt_pkey);
			}
		}
	}

	if (port->pa_pkey_tbl != NULL) {
		kmem_free(port->pa_pkey_tbl,
		    port->pa_npkeys * sizeof (ibdm_pkey_tbl_t));
	}

	port->pa_npkeys = npkeys;
	port->pa_pkey_tbl = pkey_tbl;
	port->pa_sn_prefix = pinfop->p_sgid_tbl[0].gid_prefix;
	port->pa_state = pinfop->p_linkstate;
	ibt_free_portinfo(pinfop, size);
}

/*
 * ibdm_initialize_port()
 *	Register with IBMF
 *	Register with SA access
 *	Register a receive callback routine with IBMF. IBMF invokes
 *	this routine whenever a MAD arrives at this port.
 *	Update the port attributes
 */
static void
ibdm_initialize_port(ibdm_port_attr_t *port)
{
	int				ii;
	uint_t				nports, size;
	uint_t				pkey_idx;
	ib_pkey_t			pkey;
	ibt_hca_portinfo_t		*pinfop;
	ibmf_register_info_t		ibmf_reg;
	ibmf_saa_subnet_event_args_t	event_args;

	IBTF_DPRINTF_L4("ibdm", "\tinitialize_port:");
	ASSERT(MUTEX_HELD(&ibdm.ibdm_hl_mutex));

	/* Check whether the port is active */
	if (ibt_get_port_state(port->pa_hca_hdl, port->pa_port_num, NULL,
	    NULL) != IBT_SUCCESS)
		return;

	if (port->pa_sa_hdl != NULL || port->pa_pkey_tbl != NULL)
		return;

	if (ibt_query_hca_ports(port->pa_hca_hdl, port->pa_port_num,
	    &pinfop, &nports, &size) != IBT_SUCCESS) {
		/* This should not occur */
		port->pa_npkeys		= 0;
		port->pa_pkey_tbl	= NULL;
		return;
	}
	port->pa_sn_prefix = pinfop->p_sgid_tbl[0].gid_prefix;

	port->pa_state		= pinfop->p_linkstate;
	port->pa_npkeys		= pinfop->p_pkey_tbl_sz;
	port->pa_pkey_tbl	= (ibdm_pkey_tbl_t *)kmem_zalloc(
	    port->pa_npkeys * sizeof (ibdm_pkey_tbl_t), KM_SLEEP);

	for (pkey_idx = 0; pkey_idx < port->pa_npkeys; pkey_idx++)
		port->pa_pkey_tbl[pkey_idx].pt_pkey =
		    pinfop->p_pkey_tbl[pkey_idx];

	ibt_free_portinfo(pinfop, size);

	if (ibdm_enumerate_iocs) {
		event_args.is_event_callback = ibdm_saa_event_cb;
		event_args.is_event_callback_arg = port;
		if (ibmf_sa_session_open(port->pa_port_guid, 0, &event_args,
		    IBMF_VERSION, 0, &port->pa_sa_hdl) != IBMF_SUCCESS) {
			IBTF_DPRINTF_L2("ibdm", "\tinitialize_port: "
			    "sa access registration failed");
			(void) ibdm_fini_port(port);
			return;
		}

		ibmf_reg.ir_ci_guid		= port->pa_hca_guid;
		ibmf_reg.ir_port_num		= port->pa_port_num;
		ibmf_reg.ir_client_class	= DEV_MGT_MANAGER;

		if (ibmf_register(&ibmf_reg, IBMF_VERSION, 0, NULL, NULL,
		    &port->pa_ibmf_hdl, &port->pa_ibmf_caps) != IBMF_SUCCESS) {
			IBTF_DPRINTF_L2("ibdm", "\tinitialize_port: "
			    "IBMF registration failed");
			(void) ibdm_fini_port(port);
			return;
		}

		if (ibmf_setup_async_cb(port->pa_ibmf_hdl,
		    IBMF_QP_HANDLE_DEFAULT,
		    ibdm_ibmf_recv_cb, 0, 0) != IBMF_SUCCESS) {
			IBTF_DPRINTF_L2("ibdm", "\tinitialize_port: "
			    "IBMF setup recv cb failed");
			(void) ibdm_fini_port(port);
			return;
		}
	} else {
		port->pa_sa_hdl = NULL;
		port->pa_ibmf_hdl = NULL;
	}

	for (ii = 0; ii < port->pa_npkeys; ii++) {
		pkey = port->pa_pkey_tbl[ii].pt_pkey;
		if (IBDM_INVALID_PKEY(pkey)) {
			port->pa_pkey_tbl[ii].pt_qp_hdl = NULL;
			continue;
		}
		ibdm_port_attr_ibmf_init(port, pkey, ii);
	}
}


/*
 * ibdm_port_attr_ibmf_init:
 *	With IBMF - Alloc QP Handle and Setup Async callback
 */
static void
ibdm_port_attr_ibmf_init(ibdm_port_attr_t *port, ib_pkey_t pkey, int ii)
{
	int ret;

	if (ibdm_enumerate_iocs == 0) {
		port->pa_pkey_tbl[ii].pt_qp_hdl = NULL;
		return;
	}

	if ((ret = ibmf_alloc_qp(port->pa_ibmf_hdl, pkey, IB_GSI_QKEY,
	    IBMF_ALT_QP_MAD_NO_RMPP, &port->pa_pkey_tbl[ii].pt_qp_hdl)) !=
	    IBMF_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm", "\tport_attr_ibmf_init: "
		    "IBMF failed to alloc qp %d", ret);
		port->pa_pkey_tbl[ii].pt_qp_hdl = NULL;
		return;
	}

	IBTF_DPRINTF_L4("ibdm", "\tport_attr_ibmf_init: QP handle is %p",
	    port->pa_ibmf_hdl);

	if ((ret = ibmf_setup_async_cb(port->pa_ibmf_hdl,
	    port->pa_pkey_tbl[ii].pt_qp_hdl, ibdm_ibmf_recv_cb, 0, 0)) !=
	    IBMF_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm", "\tport_attr_ibmf_init: "
		    "IBMF setup recv cb failed %d", ret);
		(void) ibmf_free_qp(port->pa_ibmf_hdl,
		    &port->pa_pkey_tbl[ii].pt_qp_hdl, 0);
		port->pa_pkey_tbl[ii].pt_qp_hdl = NULL;
	}
}


/*
 * ibdm_get_port_attr()
 *	Get port attributes from HCA guid and port number
 *	Return pointer to ibdm_port_attr_t on Success
 *	and NULL on failure
 */
static ibdm_port_attr_t *
ibdm_get_port_attr(ibt_async_event_t *event, ibdm_hca_list_t **retval)
{
	ibdm_hca_list_t		*hca_list;
	ibdm_port_attr_t	*port_attr;
	int			ii;

	IBTF_DPRINTF_L4("ibdm", "\tget_port_attr: port# %d", event->ev_port);
	ASSERT(MUTEX_HELD(&ibdm.ibdm_hl_mutex));
	hca_list = ibdm.ibdm_hca_list_head;
	while (hca_list) {
		if (hca_list->hl_hca_guid == event->ev_hca_guid) {
			for (ii = 0; ii < hca_list->hl_nports; ii++) {
				port_attr = &hca_list->hl_port_attr[ii];
				if (port_attr->pa_port_num == event->ev_port) {
					*retval = hca_list;
					return (port_attr);
				}
			}
		}
		hca_list = hca_list->hl_next;
	}
	return (NULL);
}


/*
 * ibdm_update_port_attr()
 *	Update the port attributes
 */
static void
ibdm_update_port_attr(ibdm_port_attr_t *port)
{
	uint_t			nports, size;
	uint_t			pkey_idx;
	ibt_hca_portinfo_t	*portinfop;

	IBTF_DPRINTF_L4("ibdm", "\tupdate_port_attr: Begin");
	if (ibt_query_hca_ports(port->pa_hca_hdl,
	    port->pa_port_num, &portinfop, &nports, &size) != IBT_SUCCESS) {
		/* This should not occur */
		port->pa_npkeys		= 0;
		port->pa_pkey_tbl	= NULL;
		return;
	}
	port->pa_sn_prefix = portinfop->p_sgid_tbl[0].gid_prefix;

	port->pa_state		= portinfop->p_linkstate;

	/*
	 * PKey information in portinfo valid only if port is
	 * ACTIVE. Bail out if not.
	 */
	if (port->pa_state != IBT_PORT_ACTIVE) {
		port->pa_npkeys		= 0;
		port->pa_pkey_tbl	= NULL;
		ibt_free_portinfo(portinfop, size);
		return;
	}

	port->pa_npkeys		= portinfop->p_pkey_tbl_sz;
	port->pa_pkey_tbl	= (ibdm_pkey_tbl_t *)kmem_zalloc(
	    port->pa_npkeys * sizeof (ibdm_pkey_tbl_t), KM_SLEEP);

	for (pkey_idx = 0; pkey_idx < port->pa_npkeys; pkey_idx++) {
		port->pa_pkey_tbl[pkey_idx].pt_pkey =
		    portinfop->p_pkey_tbl[pkey_idx];
	}
	ibt_free_portinfo(portinfop, size);
}


/*
 * ibdm_handle_hca_attach()
 */
static void
ibdm_handle_hca_attach(ib_guid_t hca_guid)
{
	uint_t			size;
	uint_t			ii, nports;
	ibt_status_t		status;
	ibt_hca_hdl_t		hca_hdl;
	ibt_hca_attr_t		*hca_attr;
	ibdm_hca_list_t		*hca_list, *temp;
	ibdm_port_attr_t	*port_attr;
	ibt_hca_portinfo_t	*portinfop;

	IBTF_DPRINTF_L4("ibdm",
	    "\thandle_hca_attach: hca_guid = 0x%llX", hca_guid);

	/* open the HCA first */
	if ((status = ibt_open_hca(ibdm.ibdm_ibt_clnt_hdl, hca_guid,
	    &hca_hdl)) != IBT_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm", "\thandle_hca_attach: "
		    "open_hca failed, status 0x%x", status);
		return;
	}

	hca_attr = (ibt_hca_attr_t *)
	    kmem_alloc(sizeof (ibt_hca_attr_t), KM_SLEEP);
	/* ibt_query_hca always returns IBT_SUCCESS */
	(void) ibt_query_hca(hca_hdl, hca_attr);

	IBTF_DPRINTF_L4("ibdm", "\tvid: 0x%x, pid: 0x%x, ver: 0x%x,"
	    " #ports: %d", hca_attr->hca_vendor_id, hca_attr->hca_device_id,
	    hca_attr->hca_version_id, hca_attr->hca_nports);

	if ((status = ibt_query_hca_ports(hca_hdl, 0, &portinfop, &nports,
	    &size)) != IBT_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm", "\thandle_hca_attach: "
		    "ibt_query_hca_ports failed, status 0x%x", status);
		kmem_free(hca_attr, sizeof (ibt_hca_attr_t));
		(void) ibt_close_hca(hca_hdl);
		return;
	}
	hca_list = (ibdm_hca_list_t *)
	    kmem_zalloc((sizeof (ibdm_hca_list_t)), KM_SLEEP);
	hca_list->hl_port_attr = (ibdm_port_attr_t *)kmem_zalloc(
	    (sizeof (ibdm_port_attr_t) * hca_attr->hca_nports), KM_SLEEP);
	hca_list->hl_hca_guid = hca_attr->hca_node_guid;
	hca_list->hl_nports = hca_attr->hca_nports;
	hca_list->hl_attach_time = gethrtime();
	hca_list->hl_hca_hdl = hca_hdl;

	/*
	 * Init a dummy port attribute for the HCA node
	 * This is for Per-HCA Node. Initialize port_attr :
	 * 	hca_guid & port_guid -> hca_guid
	 *	npkeys, pkey_tbl is NULL
	 *	port_num, sn_prefix is 0
	 *	vendorid, product_id, dev_version from HCA
	 *	pa_state is IBT_PORT_ACTIVE
	 */
	hca_list->hl_hca_port_attr = (ibdm_port_attr_t *)kmem_zalloc(
	    sizeof (ibdm_port_attr_t), KM_SLEEP);
	port_attr = hca_list->hl_hca_port_attr;
	port_attr->pa_vendorid  = hca_attr->hca_vendor_id;
	port_attr->pa_productid	= hca_attr->hca_device_id;
	port_attr->pa_dev_version = hca_attr->hca_version_id;
	port_attr->pa_hca_guid	= hca_attr->hca_node_guid;
	port_attr->pa_hca_hdl	= hca_list->hl_hca_hdl;
	port_attr->pa_port_guid	= hca_attr->hca_node_guid;
	port_attr->pa_state	= IBT_PORT_ACTIVE;


	for (ii = 0; ii < nports; ii++) {
		port_attr		= &hca_list->hl_port_attr[ii];
		port_attr->pa_vendorid	= hca_attr->hca_vendor_id;
		port_attr->pa_productid	= hca_attr->hca_device_id;
		port_attr->pa_dev_version = hca_attr->hca_version_id;
		port_attr->pa_hca_guid	= hca_attr->hca_node_guid;
		port_attr->pa_hca_hdl	= hca_list->hl_hca_hdl;
		port_attr->pa_port_guid	= portinfop[ii].p_sgid_tbl->gid_guid;
		port_attr->pa_sn_prefix	= portinfop[ii].p_sgid_tbl->gid_prefix;
		port_attr->pa_port_num	= portinfop[ii].p_port_num;
		port_attr->pa_state	= portinfop[ii].p_linkstate;

		/*
		 * Register with IBMF, SA access when the port is in
		 * ACTIVE state. Also register a callback routine
		 * with IBMF to receive incoming DM MAD's.
		 * The IBDM event handler takes care of registration of
		 * port which are not active.
		 */
		IBTF_DPRINTF_L4("ibdm",
		    "\thandle_hca_attach: port guid %llx Port state 0x%x",
		    port_attr->pa_port_guid, portinfop[ii].p_linkstate);

		if (portinfop[ii].p_linkstate == IBT_PORT_ACTIVE) {
			mutex_enter(&ibdm.ibdm_hl_mutex);
			hca_list->hl_nports_active++;
			ibdm_initialize_port(port_attr);
			cv_broadcast(&ibdm.ibdm_port_settle_cv);
			mutex_exit(&ibdm.ibdm_hl_mutex);
		}
	}
	mutex_enter(&ibdm.ibdm_hl_mutex);
	for (temp = ibdm.ibdm_hca_list_head; temp; temp = temp->hl_next) {
		if (temp->hl_hca_guid == hca_guid) {
			IBTF_DPRINTF_L2("ibdm", "hca_attach: HCA %llX "
			    "already seen by IBDM", hca_guid);
			mutex_exit(&ibdm.ibdm_hl_mutex);
			(void) ibdm_uninit_hca(hca_list);
			return;
		}
	}
	ibdm.ibdm_hca_count++;
	if (ibdm.ibdm_hca_list_head == NULL) {
		ibdm.ibdm_hca_list_head = hca_list;
		ibdm.ibdm_hca_list_tail = hca_list;
	} else {
		ibdm.ibdm_hca_list_tail->hl_next = hca_list;
		ibdm.ibdm_hca_list_tail = hca_list;
	}
	mutex_exit(&ibdm.ibdm_hl_mutex);
	mutex_enter(&ibdm.ibdm_ibnex_mutex);
	if (ibdm.ibdm_ibnex_callback != NULL) {
		(*ibdm.ibdm_ibnex_callback)((void *)
		    &hca_guid, IBDM_EVENT_HCA_ADDED);
	}
	mutex_exit(&ibdm.ibdm_ibnex_mutex);

	kmem_free(hca_attr, sizeof (ibt_hca_attr_t));
	ibt_free_portinfo(portinfop, size);
}


/*
 * ibdm_handle_hca_detach()
 */
static void
ibdm_handle_hca_detach(ib_guid_t hca_guid)
{
	ibdm_hca_list_t		*head, *prev = NULL;
	size_t			len;
	ibdm_dp_gidinfo_t	*gidinfo;
	ibdm_port_attr_t	*port_attr;
	int			i;

	IBTF_DPRINTF_L4("ibdm",
	    "\thandle_hca_detach: hca_guid = 0x%llx", hca_guid);

	/* Make sure no probes are running */
	mutex_enter(&ibdm.ibdm_mutex);
	while (ibdm.ibdm_busy & IBDM_BUSY)
		cv_wait(&ibdm.ibdm_busy_cv, &ibdm.ibdm_mutex);
	ibdm.ibdm_busy |= IBDM_BUSY;
	mutex_exit(&ibdm.ibdm_mutex);

	mutex_enter(&ibdm.ibdm_hl_mutex);
	head = ibdm.ibdm_hca_list_head;
	while (head) {
		if (head->hl_hca_guid == hca_guid) {
			if (prev == NULL)
				ibdm.ibdm_hca_list_head = head->hl_next;
			else
				prev->hl_next = head->hl_next;
			if (ibdm.ibdm_hca_list_tail == head)
				ibdm.ibdm_hca_list_tail = prev;
			ibdm.ibdm_hca_count--;
			break;
		}
		prev = head;
		head = head->hl_next;
	}
	mutex_exit(&ibdm.ibdm_hl_mutex);
	if (ibdm_uninit_hca(head) != IBDM_SUCCESS)
		(void) ibdm_handle_hca_attach(hca_guid);

#ifdef DEBUG
	if (ibdm_enumerate_iocs == 0) {
		ASSERT(ibdm.ibdm_dp_gidlist_head == NULL);
	}
#endif

	/*
	 * Now clean up the HCA lists in the gidlist.
	 */
	for (gidinfo = ibdm.ibdm_dp_gidlist_head; gidinfo; gidinfo =
	    gidinfo->gl_next) {
		prev = NULL;
		head = gidinfo->gl_hca_list;
		while (head) {
			if (head->hl_hca_guid == hca_guid) {
				if (prev == NULL)
					gidinfo->gl_hca_list =
					    head->hl_next;
				else
					prev->hl_next = head->hl_next;
				for (i = 0; i < head->hl_nports; i++) {
					port_attr = &head->hl_port_attr[i];
					if (port_attr->pa_pkey_tbl != NULL)
						kmem_free(
						    port_attr->pa_pkey_tbl,
						    port_attr->pa_npkeys *
						    sizeof (ibdm_pkey_tbl_t));
				}
				len = sizeof (ibdm_hca_list_t) +
				    (head->hl_nports *
				    sizeof (ibdm_port_attr_t));
				kmem_free(head, len);

				break;
			}
			prev = head;
			head = head->hl_next;
		}
	}

	mutex_enter(&ibdm.ibdm_mutex);
	ibdm.ibdm_busy &= ~IBDM_BUSY;
	cv_broadcast(&ibdm.ibdm_busy_cv);
	mutex_exit(&ibdm.ibdm_mutex);
}


static int
ibdm_uninit_hca(ibdm_hca_list_t *head)
{
	int			ii;
	ibdm_port_attr_t	*port_attr;

	for (ii = 0; ii < head->hl_nports; ii++) {
		port_attr = &head->hl_port_attr[ii];
		if (ibdm_fini_port(port_attr) != IBDM_SUCCESS) {
			IBTF_DPRINTF_L2("ibdm", "uninit_hca: HCA %p port 0x%x "
			    "ibdm_fini_port() failed", head, ii);
			return (IBDM_FAILURE);
		}
	}
	if (head->hl_hca_hdl)
		if (ibt_close_hca(head->hl_hca_hdl) != IBT_SUCCESS) {
			IBTF_DPRINTF_L2("ibdm", "uninit_hca: "
			    "ibt_close_hca() failed");
			return (IBDM_FAILURE);
		}
	kmem_free(head->hl_port_attr,
	    head->hl_nports * sizeof (ibdm_port_attr_t));
	kmem_free(head->hl_hca_port_attr, sizeof (ibdm_port_attr_t));
	kmem_free(head, sizeof (ibdm_hca_list_t));
	return (IBDM_SUCCESS);
}


/*
 * For each port on the HCA,
 *	1) Teardown IBMF receive callback function
 *	2) Unregister with IBMF
 *	3) Unregister with SA access
 */
static int
ibdm_fini_port(ibdm_port_attr_t *port_attr)
{
	int	ii, ibmf_status;

	for (ii = 0; ii < port_attr->pa_npkeys; ii++) {
		if (port_attr->pa_pkey_tbl == NULL)
			break;
		if (!port_attr->pa_pkey_tbl[ii].pt_qp_hdl)
			continue;
		if (ibdm_port_attr_ibmf_fini(port_attr, ii) != IBDM_SUCCESS) {
			IBTF_DPRINTF_L4("ibdm", "\tfini_port: "
			    "ibdm_port_attr_ibmf_fini failed for "
			    "port pkey 0x%x", ii);
			return (IBDM_FAILURE);
		}
	}

	if (port_attr->pa_ibmf_hdl) {
		ibmf_status = ibmf_tear_down_async_cb(port_attr->pa_ibmf_hdl,
		    IBMF_QP_HANDLE_DEFAULT, 0);
		if (ibmf_status != IBMF_SUCCESS) {
			IBTF_DPRINTF_L4("ibdm", "\tfini_port: "
			    "ibmf_tear_down_async_cb failed %d", ibmf_status);
			return (IBDM_FAILURE);
		}

		ibmf_status = ibmf_unregister(&port_attr->pa_ibmf_hdl, 0);
		if (ibmf_status != IBMF_SUCCESS) {
			IBTF_DPRINTF_L2("ibdm", "\tfini_port: "
			    "ibmf_unregister failed %d", ibmf_status);
			return (IBDM_FAILURE);
		}

		port_attr->pa_ibmf_hdl = NULL;
	}

	if (port_attr->pa_sa_hdl) {
		ibmf_status = ibmf_sa_session_close(&port_attr->pa_sa_hdl, 0);
		if (ibmf_status != IBMF_SUCCESS) {
			IBTF_DPRINTF_L2("ibdm", "\tfini_port: "
			    "ibmf_sa_session_close failed %d", ibmf_status);
			return (IBDM_FAILURE);
		}
		port_attr->pa_sa_hdl = NULL;
	}

	if (port_attr->pa_pkey_tbl != NULL) {
		kmem_free(port_attr->pa_pkey_tbl,
		    port_attr->pa_npkeys * sizeof (ibdm_pkey_tbl_t));
		port_attr->pa_pkey_tbl = NULL;
		port_attr->pa_npkeys = 0;
	}

	return (IBDM_SUCCESS);
}


/*
 * ibdm_port_attr_ibmf_fini:
 *	With IBMF - Tear down Async callback and free QP Handle
 */
static int
ibdm_port_attr_ibmf_fini(ibdm_port_attr_t *port_attr, int ii)
{
	int ibmf_status;

	IBTF_DPRINTF_L5("ibdm", "\tport_attr_ibmf_fini:");

	if (ibdm_enumerate_iocs == 0) {
		ASSERT(port_attr->pa_pkey_tbl[ii].pt_qp_hdl == NULL);
		return (IBDM_SUCCESS);
	}

	if (port_attr->pa_pkey_tbl[ii].pt_qp_hdl) {
		ibmf_status = ibmf_tear_down_async_cb(port_attr->pa_ibmf_hdl,
		    port_attr->pa_pkey_tbl[ii].pt_qp_hdl, 0);
		if (ibmf_status != IBMF_SUCCESS) {
			IBTF_DPRINTF_L4("ibdm", "\tport_attr_ibmf_fini: "
			    "ibmf_tear_down_async_cb failed %d", ibmf_status);
			return (IBDM_FAILURE);
		}
		ibmf_status = ibmf_free_qp(port_attr->pa_ibmf_hdl,
		    &port_attr->pa_pkey_tbl[ii].pt_qp_hdl, 0);
		if (ibmf_status != IBMF_SUCCESS) {
			IBTF_DPRINTF_L4("ibdm", "\tport_attr_ibmf_fini: "
			    "ibmf_free_qp failed %d", ibmf_status);
			return (IBDM_FAILURE);
		}
		port_attr->pa_pkey_tbl[ii].pt_qp_hdl = NULL;
	}
	return (IBDM_SUCCESS);
}


/*
 * ibdm_gid_decr_pending:
 *	decrement gl_pending_cmds. If zero wakeup sleeping threads
 */
static void
ibdm_gid_decr_pending(ibdm_dp_gidinfo_t *gidinfo)
{
	mutex_enter(&ibdm.ibdm_mutex);
	mutex_enter(&gidinfo->gl_mutex);
	if (--gidinfo->gl_pending_cmds == 0) {
		/*
		 * Handle DGID getting removed.
		 */
		if (gidinfo->gl_disconnected) {
			mutex_exit(&gidinfo->gl_mutex);
			mutex_exit(&ibdm.ibdm_mutex);

			IBTF_DPRINTF_L3(ibdm_string, "\tgid_decr_pending: "
			    "gidinfo %p hot removal", gidinfo);
			ibdm_delete_gidinfo(gidinfo);

			mutex_enter(&ibdm.ibdm_mutex);
			ibdm.ibdm_ngid_probes_in_progress--;
			ibdm_wait_probe_completion();
			mutex_exit(&ibdm.ibdm_mutex);
			return;
		}
		mutex_exit(&gidinfo->gl_mutex);
		mutex_exit(&ibdm.ibdm_mutex);
		ibdm_notify_newgid_iocs(gidinfo);
		mutex_enter(&ibdm.ibdm_mutex);
		mutex_enter(&gidinfo->gl_mutex);

		ibdm.ibdm_ngid_probes_in_progress--;
		ibdm_wait_probe_completion();
	}
	mutex_exit(&gidinfo->gl_mutex);
	mutex_exit(&ibdm.ibdm_mutex);
}


/*
 * ibdm_wait_probe_completion:
 *	wait for probing to complete
 */
static void
ibdm_wait_probe_completion(void)
{
	ASSERT(MUTEX_HELD(&ibdm.ibdm_mutex));
	if (ibdm.ibdm_ngid_probes_in_progress) {
		IBTF_DPRINTF_L4("ibdm",	"\twait for probe complete");
		ibdm.ibdm_busy |= IBDM_PROBE_IN_PROGRESS;
		while (ibdm.ibdm_busy & IBDM_PROBE_IN_PROGRESS)
			cv_wait(&ibdm.ibdm_probe_cv, &ibdm.ibdm_mutex);
	}
}


/*
 * ibdm_wait_cisco_probe_completion:
 *	wait for the reply from the Cisco FC GW switch after a setclassportinfo
 *	request is sent. This wait can be achieved on each gid.
 */
static void
ibdm_wait_cisco_probe_completion(ibdm_dp_gidinfo_t *gidinfo)
{
	ASSERT(MUTEX_HELD(&gidinfo->gl_mutex));
	IBTF_DPRINTF_L4("ibdm",	"\twait for cisco probe complete");
	gidinfo->gl_flag |= IBDM_CISCO_PROBE;
	while (gidinfo->gl_flag & IBDM_CISCO_PROBE)
		cv_wait(&gidinfo->gl_probe_cv, &gidinfo->gl_mutex);
}


/*
 * ibdm_wakeup_probe_gid_cv:
 *	wakeup waiting threads (based on ibdm_ngid_probes_in_progress)
 */
static void
ibdm_wakeup_probe_gid_cv(void)
{
	ASSERT(MUTEX_HELD(&ibdm.ibdm_mutex));
	if (!ibdm.ibdm_ngid_probes_in_progress) {
		IBTF_DPRINTF_L4("ibdm", "wakeup_probe_gid_thread: Wakeup");
		ibdm.ibdm_busy &= ~IBDM_PROBE_IN_PROGRESS;
		cv_broadcast(&ibdm.ibdm_probe_cv);
	}

}


/*
 * ibdm_sweep_fabric(reprobe_flag)
 *	Find all possible Managed IOU's and their IOC's that are visible
 *	to the host. The algorithm used is as follows
 *
 *	Send a "bus walk" request for each port on the host HCA to SA access
 *	SA returns complete set of GID's that are reachable from
 *	source port. This is done in parallel.
 *
 *	Initialize GID state to IBDM_GID_PROBE_NOT_DONE
 *
 *	Sort the GID list and eliminate duplicate GID's
 *		1) Use DGID for sorting
 *		2) use PortGuid for sorting
 *			Send SA query to retrieve NodeRecord and
 *			extract PortGuid from that.
 *
 *	Set GID state to IBDM_GID_PROBE_FAILED to all the ports that dont
 *	support DM MAD's
 *		Send a "Portinfo" query to get the port capabilities and
 *		then check for DM MAD's support
 *
 *	Send "ClassPortInfo" request for all the GID's in parallel,
 *	set the GID state to IBDM_GET_CLASSPORTINFO and wait on the
 *	cv_signal to complete.
 *
 *	When DM agent on the remote GID sends back the response, IBMF
 *	invokes DM callback routine.
 *
 *	If the response is proper, send "IOUnitInfo" request and set
 *	GID state to IBDM_GET_IOUNITINFO.
 *
 *	If the response is proper, send "IocProfileInfo" request to
 *	all the IOC simultaneously and set GID state to IBDM_GET_IOC_DETAILS.
 *
 *	Send request to get Service entries simultaneously
 *
 *	Signal the waiting thread when received response for all the commands.
 *
 *	Set the GID state to IBDM_GID_PROBE_FAILED when received a error
 *	response during the probing period.
 *
 *	Note:
 *	ibdm.ibdm_ngid_probes_in_progress and ibdm_gid_list_t:gl_pending_cmds
 *	keep track of number commands in progress at any point of time.
 *	MAD transaction ID is used to identify a particular GID
 *	TBD: Consider registering the IBMF receive callback on demand
 *
 *	Note: This routine must be called with ibdm.ibdm_mutex held
 *	TBD: Re probe the failure GID (for certain failures) when requested
 *	     for fabric sweep next time
 *
 *	Parameters : If reprobe_flag is set, All IOCs will be reprobed.
 */
static void
ibdm_sweep_fabric(int reprobe_flag)
{
	int			ii;
	int			new_paths = 0;
	uint8_t			niocs;
	taskqid_t		tid;
	ibdm_ioc_info_t		*ioc;
	ibdm_hca_list_t		*hca_list = NULL;
	ibdm_port_attr_t	*port = NULL;
	ibdm_dp_gidinfo_t 	*gid_info;

	IBTF_DPRINTF_L4("ibdm", "\tsweep_fabric: Enter");
	ASSERT(MUTEX_HELD(&ibdm.ibdm_mutex));

	/*
	 * Check whether a sweep already in progress. If so, just
	 * wait for the fabric sweep to complete
	 */
	while (ibdm.ibdm_busy & IBDM_BUSY)
		cv_wait(&ibdm.ibdm_busy_cv, &ibdm.ibdm_mutex);
	ibdm.ibdm_busy |= IBDM_BUSY;
	mutex_exit(&ibdm.ibdm_mutex);

	ibdm_dump_sweep_fabric_timestamp(0);

	/* Rescan the GID list for any removed GIDs for reprobe */
	if (reprobe_flag)
		ibdm_rescan_gidlist(NULL);

	/*
	 * Get list of all the ports reachable from the local known HCA
	 * ports which are active
	 */
	mutex_enter(&ibdm.ibdm_hl_mutex);
	for (ibdm_get_next_port(&hca_list, &port, 1); port;
	    ibdm_get_next_port(&hca_list, &port, 1)) {
		/*
		 * Get PATHS to all the reachable ports from
		 * SGID and update the global ibdm structure.
		 */
		new_paths = ibdm_get_reachable_ports(port, hca_list);
		ibdm.ibdm_ngids += new_paths;
	}
	mutex_exit(&ibdm.ibdm_hl_mutex);

	mutex_enter(&ibdm.ibdm_mutex);
	ibdm.ibdm_ngid_probes_in_progress += ibdm.ibdm_ngids;
	mutex_exit(&ibdm.ibdm_mutex);

	/* Send a request to probe GIDs asynchronously. */
	for (gid_info = ibdm.ibdm_dp_gidlist_head; gid_info;
	    gid_info = gid_info->gl_next) {
		mutex_enter(&gid_info->gl_mutex);
		gid_info->gl_reprobe_flag = reprobe_flag;
		mutex_exit(&gid_info->gl_mutex);

		/* process newly encountered GIDs */
		tid = taskq_dispatch(system_taskq, ibdm_probe_gid_thread,
		    (void *)gid_info, TQ_NOSLEEP);
		IBTF_DPRINTF_L4("ibdm", "\tsweep_fabric: gid_info = %p"
		    " taskq_id = %x", gid_info, tid);
		/* taskq failed to dispatch call it directly */
		if (tid == NULL)
			ibdm_probe_gid_thread((void *)gid_info);
	}

	mutex_enter(&ibdm.ibdm_mutex);
	ibdm_wait_probe_completion();

	/*
	 * Update the properties, if reprobe_flag is set
	 * Skip if gl_reprobe_flag is set, this will be
	 * a re-inserted / new GID, for which notifications
	 * have already been send.
	 */
	if (reprobe_flag) {
		for (gid_info = ibdm.ibdm_dp_gidlist_head; gid_info;
		    gid_info = gid_info->gl_next) {
			if (gid_info->gl_iou == NULL)
				continue;
			if (gid_info->gl_reprobe_flag) {
				gid_info->gl_reprobe_flag = 0;
				continue;
			}

			niocs = gid_info->gl_iou->iou_info.iou_num_ctrl_slots;
			for (ii = 0; ii < niocs; ii++) {
				ioc = IBDM_GIDINFO2IOCINFO(gid_info, ii);
				if (ioc)
					ibdm_reprobe_update_port_srv(ioc,
					    gid_info);
			}
		}
	} else if (ibdm.ibdm_prev_iou) {
		ibdm_ioc_info_t	*ioc_list;

		/*
		 * Get the list of IOCs which have changed.
		 * If any IOCs have changed, Notify IBNexus
		 */
		ibdm.ibdm_prev_iou = 0;
		ioc_list = ibdm_handle_prev_iou();
		if (ioc_list) {
			if (ibdm.ibdm_ibnex_callback != NULL) {
				(*ibdm.ibdm_ibnex_callback)(
				    (void *)ioc_list,
				    IBDM_EVENT_IOC_PROP_UPDATE);
			}
		}
	}

	ibdm_dump_sweep_fabric_timestamp(1);

	ibdm.ibdm_busy &= ~IBDM_BUSY;
	cv_broadcast(&ibdm.ibdm_busy_cv);
	IBTF_DPRINTF_L5("ibdm", "\tsweep_fabric: EXIT");
}


/*
 * ibdm_is_cisco:
 * 	Check if this is a Cisco device or not.
 */
static boolean_t
ibdm_is_cisco(ib_guid_t guid)
{
	if ((guid >> IBDM_OUI_GUID_SHIFT) == IBDM_CISCO_COMPANY_ID)
		return (B_TRUE);
	return (B_FALSE);
}


/*
 * ibdm_is_cisco_switch:
 * 	Check if this switch is a CISCO switch or not.
 * 	Note that if this switch is already activated, ibdm_is_cisco_switch()
 * 	returns B_FALSE not to re-activate it again.
 */
static boolean_t
ibdm_is_cisco_switch(ibdm_dp_gidinfo_t *gid_info)
{
	int company_id, device_id;
	ASSERT(gid_info != 0);
	ASSERT(MUTEX_HELD(&gid_info->gl_mutex));

	/*
	 * If this switch is already activated, don't re-activate it.
	 */
	if (gid_info->gl_flag & IBDM_CISCO_PROBE_DONE)
		return (B_FALSE);

	/*
	 * Check if this switch is a Cisco FC GW or not.
	 * Use the node guid (the OUI part) instead of the vendor id
	 * since the vendor id is zero in practice.
	 */
	company_id = gid_info->gl_nodeguid >> IBDM_OUI_GUID_SHIFT;
	device_id = gid_info->gl_devid;

	if (company_id == IBDM_CISCO_COMPANY_ID &&
	    device_id == IBDM_CISCO_DEVICE_ID)
		return (B_TRUE);
	return (B_FALSE);
}


/*
 * ibdm_probe_gid_thread:
 *	thread that does the actual work for sweeping the fabric
 *	for a given GID
 */
static void
ibdm_probe_gid_thread(void *args)
{
	int			reprobe_flag;
	ib_guid_t		node_guid;
	ib_guid_t		port_guid;
	ibdm_dp_gidinfo_t	*gid_info;

	gid_info = (ibdm_dp_gidinfo_t *)args;
	reprobe_flag = gid_info->gl_reprobe_flag;
	IBTF_DPRINTF_L4("ibdm", "\tprobe_gid_thread: gid_info = %p, flag = %d",
	    gid_info, reprobe_flag);
	ASSERT(gid_info != NULL);
	ASSERT(gid_info->gl_pending_cmds == 0);

	if (gid_info->gl_state != IBDM_GID_PROBE_NOT_DONE &&
	    reprobe_flag == 0) {
		/*
		 * This GID may have been already probed. Send
		 * in a CLP to check if IOUnitInfo changed?
		 * Explicitly set gl_reprobe_flag to 0 so that
		 * IBnex is not notified on completion
		 */
		if (gid_info->gl_state == IBDM_GID_PROBING_COMPLETE) {
			IBTF_DPRINTF_L4("ibdm", "\tprobe_gid_thread: "
			    "get new IOCs information");
			mutex_enter(&gid_info->gl_mutex);
			gid_info->gl_pending_cmds++;
			gid_info->gl_state = IBDM_GET_IOUNITINFO;
			gid_info->gl_reprobe_flag = 0;
			mutex_exit(&gid_info->gl_mutex);
			if (ibdm_send_iounitinfo(gid_info) != IBDM_SUCCESS) {
				mutex_enter(&gid_info->gl_mutex);
				--gid_info->gl_pending_cmds;
				mutex_exit(&gid_info->gl_mutex);
				mutex_enter(&ibdm.ibdm_mutex);
				--ibdm.ibdm_ngid_probes_in_progress;
				ibdm_wakeup_probe_gid_cv();
				mutex_exit(&ibdm.ibdm_mutex);
			}
		} else {
			mutex_enter(&ibdm.ibdm_mutex);
			--ibdm.ibdm_ngid_probes_in_progress;
			ibdm_wakeup_probe_gid_cv();
			mutex_exit(&ibdm.ibdm_mutex);
		}
		return;
	} else if (reprobe_flag && gid_info->gl_state ==
	    IBDM_GID_PROBING_COMPLETE) {
		/*
		 * Reprobe all IOCs for the GID which has completed
		 * probe. Skip other port GIDs to same IOU.
		 * Explicitly set gl_reprobe_flag to 0 so that
		 * IBnex is not notified on completion
		 */
		ibdm_ioc_info_t *ioc_info;
		uint8_t		niocs, ii;

		ASSERT(gid_info->gl_iou);
		mutex_enter(&gid_info->gl_mutex);
		niocs = gid_info->gl_iou->iou_info.iou_num_ctrl_slots;
		gid_info->gl_state = IBDM_GET_IOC_DETAILS;
		gid_info->gl_pending_cmds += niocs;
		gid_info->gl_reprobe_flag = 0;
		mutex_exit(&gid_info->gl_mutex);
		for (ii = 0; ii < niocs; ii++) {
			uchar_t			slot_info;
			ib_dm_io_unitinfo_t	*giou_info;

			/*
			 * Check whether IOC is present in the slot
			 * Series of nibbles (in the field
			 * iou_ctrl_list) represents a slot in the
			 * IOU.
			 * Byte format: 76543210
			 * Bits 0-3 of first byte represent Slot 2
			 * bits 4-7 of first byte represent slot 1,
			 * bits 0-3 of second byte represent slot 4
			 * and so on
			 * Each 4-bit nibble has the following meaning
			 * 0x0 : IOC not installed
			 * 0x1 : IOC is present
			 * 0xf : Slot does not exist
			 * and all other values are reserved.
			 */
			ioc_info = IBDM_GIDINFO2IOCINFO(gid_info, ii);
			giou_info = &gid_info->gl_iou->iou_info;
			slot_info = giou_info->iou_ctrl_list[(ii/2)];
			if ((ii % 2) == 0)
				slot_info = (slot_info >> 4);

			if ((slot_info & 0xf) != 1) {
				ioc_info->ioc_state =
				    IBDM_IOC_STATE_PROBE_FAILED;
				ibdm_gid_decr_pending(gid_info);
				continue;
			}

			if (ibdm_send_ioc_profile(gid_info, ii) !=
			    IBDM_SUCCESS) {
				ibdm_gid_decr_pending(gid_info);
			}
		}

		return;
	} else if (gid_info->gl_state != IBDM_GID_PROBE_NOT_DONE) {
		mutex_enter(&ibdm.ibdm_mutex);
		--ibdm.ibdm_ngid_probes_in_progress;
		ibdm_wakeup_probe_gid_cv();
		mutex_exit(&ibdm.ibdm_mutex);
		return;
	}

	/*
	 * Check whether the destination GID supports DM agents. If
	 * not, stop probing the GID and continue with the next GID
	 * in the list.
	 */
	if (ibdm_is_dev_mgt_supported(gid_info) != IBDM_SUCCESS) {
		mutex_enter(&gid_info->gl_mutex);
		gid_info->gl_state = IBDM_GID_PROBING_FAILED;
		gid_info->gl_is_dm_capable = B_FALSE;
		mutex_exit(&gid_info->gl_mutex);
		ibdm_delete_glhca_list(gid_info);
		mutex_enter(&ibdm.ibdm_mutex);
		--ibdm.ibdm_ngid_probes_in_progress;
		ibdm_wakeup_probe_gid_cv();
		mutex_exit(&ibdm.ibdm_mutex);
		return;
	}

	/*
	 * This GID is Device management capable
	 */
	mutex_enter(&gid_info->gl_mutex);
	gid_info->gl_is_dm_capable = B_TRUE;
	mutex_exit(&gid_info->gl_mutex);

	/* Get the nodeguid and portguid of the port */
	if (ibdm_get_node_port_guids(gid_info->gl_sa_hdl, gid_info->gl_dlid,
	    &node_guid, &port_guid) != IBDM_SUCCESS) {
		mutex_enter(&gid_info->gl_mutex);
		gid_info->gl_state = IBDM_GID_PROBING_FAILED;
		mutex_exit(&gid_info->gl_mutex);
		ibdm_delete_glhca_list(gid_info);
		mutex_enter(&ibdm.ibdm_mutex);
		--ibdm.ibdm_ngid_probes_in_progress;
		ibdm_wakeup_probe_gid_cv();
		mutex_exit(&ibdm.ibdm_mutex);
		return;
	}

	/*
	 * Check whether we already knew about this NodeGuid
	 * If so, do not probe the GID and continue with the
	 * next  GID  in the gid  list. Set the GID state to
	 * probing done.
	 */
	mutex_enter(&ibdm.ibdm_mutex);
	gid_info->gl_nodeguid = node_guid;
	gid_info->gl_portguid = port_guid;
	if (ibdm_check_dest_nodeguid(gid_info) != NULL) {
		mutex_exit(&ibdm.ibdm_mutex);
		mutex_enter(&gid_info->gl_mutex);
		gid_info->gl_state = IBDM_GID_PROBING_SKIPPED;
		mutex_exit(&gid_info->gl_mutex);
		ibdm_delete_glhca_list(gid_info);
		mutex_enter(&ibdm.ibdm_mutex);
		--ibdm.ibdm_ngid_probes_in_progress;
		ibdm_wakeup_probe_gid_cv();
		mutex_exit(&ibdm.ibdm_mutex);
		return;
	}
	ibdm_add_to_gl_gid(gid_info, gid_info);
	mutex_exit(&ibdm.ibdm_mutex);

	/*
	 * New or reinserted GID : Enable notification to IBnex
	 */
	mutex_enter(&gid_info->gl_mutex);
	gid_info->gl_reprobe_flag = 1;

	/*
	 * A Cisco FC GW needs the special handling to get IOUnitInfo.
	 */
	if (ibdm_is_cisco_switch(gid_info)) {
		gid_info->gl_pending_cmds++;
		gid_info->gl_state = IBDM_SET_CLASSPORTINFO;
		mutex_exit(&gid_info->gl_mutex);

		if (ibdm_set_classportinfo(gid_info) != IBDM_SUCCESS) {
			mutex_enter(&gid_info->gl_mutex);
			gid_info->gl_state = IBDM_GID_PROBING_FAILED;
			--gid_info->gl_pending_cmds;
			mutex_exit(&gid_info->gl_mutex);

			/* free the hca_list on this gid_info */
			ibdm_delete_glhca_list(gid_info);

			mutex_enter(&ibdm.ibdm_mutex);
			--ibdm.ibdm_ngid_probes_in_progress;
			ibdm_wakeup_probe_gid_cv();
			mutex_exit(&ibdm.ibdm_mutex);

			return;
		}

		mutex_enter(&gid_info->gl_mutex);
		ibdm_wait_cisco_probe_completion(gid_info);

		IBTF_DPRINTF_L4("ibdm", "\tibdm_probe_gid_thread: "
		    "CISCO Wakeup signal received");
	}

	/* move on to the 'GET_CLASSPORTINFO' stage */
	gid_info->gl_pending_cmds++;
	gid_info->gl_state = IBDM_GET_CLASSPORTINFO;
	mutex_exit(&gid_info->gl_mutex);

	IBTF_DPRINTF_L3(ibdm_string, "\tibdm_probe_gid_thread: "
	    "%d: gid_info %p gl_state %d pending_cmds %d",
	    __LINE__, gid_info, gid_info->gl_state,
	    gid_info->gl_pending_cmds);

	/*
	 * Send ClassPortInfo request to the GID asynchronously.
	 */
	if (ibdm_send_classportinfo(gid_info) != IBDM_SUCCESS) {

		mutex_enter(&gid_info->gl_mutex);
		gid_info->gl_state = IBDM_GID_PROBING_FAILED;
		--gid_info->gl_pending_cmds;
		mutex_exit(&gid_info->gl_mutex);

		/* free the hca_list on this gid_info */
		ibdm_delete_glhca_list(gid_info);

		mutex_enter(&ibdm.ibdm_mutex);
		--ibdm.ibdm_ngid_probes_in_progress;
		ibdm_wakeup_probe_gid_cv();
		mutex_exit(&ibdm.ibdm_mutex);

		return;
	}
}


/*
 * ibdm_check_dest_nodeguid
 *	Searches for the NodeGuid in the GID list
 *	Returns matching gid_info if found and otherwise NULL
 *
 *	This function is called to handle new GIDs discovered
 *	during device sweep / probe or for GID_AVAILABLE event.
 *
 *	Parameter :
 *		gid_info	GID to check
 */
static ibdm_dp_gidinfo_t *
ibdm_check_dest_nodeguid(ibdm_dp_gidinfo_t *gid_info)
{
	ibdm_dp_gidinfo_t	*gid_list;
	ibdm_gid_t		*tmp;

	IBTF_DPRINTF_L4("ibdm", "\tcheck_dest_nodeguid");

	gid_list = ibdm.ibdm_dp_gidlist_head;
	while (gid_list) {
		if ((gid_list != gid_info) &&
		    (gid_info->gl_nodeguid == gid_list->gl_nodeguid)) {
			IBTF_DPRINTF_L4("ibdm",
			    "\tcheck_dest_nodeguid: NodeGuid is present");

			/* Add to gid_list */
			tmp = kmem_zalloc(sizeof (ibdm_gid_t),
			    KM_SLEEP);
			tmp->gid_dgid_hi = gid_info->gl_dgid_hi;
			tmp->gid_dgid_lo = gid_info->gl_dgid_lo;
			tmp->gid_next = gid_list->gl_gid;
			gid_list->gl_gid = tmp;
			gid_list->gl_ngids++;
			return (gid_list);
		}

		gid_list = gid_list->gl_next;
	}

	return (NULL);
}


/*
 * ibdm_is_dev_mgt_supported
 *	Get the PortInfo attribute (SA Query)
 *	Check "CompatabilityMask" field in the Portinfo.
 *	Return IBDM_SUCCESS if DM MAD's supported (if bit 19 set)
 *	by the port, otherwise IBDM_FAILURE
 */
static int
ibdm_is_dev_mgt_supported(ibdm_dp_gidinfo_t *gid_info)
{
	int			ret;
	size_t			length = 0;
	sa_portinfo_record_t	req, *resp = NULL;
	ibmf_saa_access_args_t	qargs;

	bzero(&req, sizeof (sa_portinfo_record_t));
	req.EndportLID	= gid_info->gl_dlid;

	qargs.sq_attr_id	= SA_PORTINFORECORD_ATTRID;
	qargs.sq_access_type	= IBMF_SAA_RETRIEVE;
	qargs.sq_component_mask = SA_PORTINFO_COMPMASK_PORTLID;
	qargs.sq_template	= &req;
	qargs.sq_callback	= NULL;
	qargs.sq_callback_arg	= NULL;

	ret = ibmf_sa_access(gid_info->gl_sa_hdl,
	    &qargs, 0, &length, (void **)&resp);

	if ((ret != IBMF_SUCCESS) || (length == 0) || (resp == NULL)) {
		IBTF_DPRINTF_L2("ibdm", "\tis_dev_mgt_supported:"
		    "failed to get PORTINFO attribute %d", ret);
		return (IBDM_FAILURE);
	}

	if (resp->PortInfo.CapabilityMask & SM_CAP_MASK_IS_DM_SUPPD) {
		IBTF_DPRINTF_L4("ibdm", "\tis_dev_mgt_supported: SUPPD !!");
		ret = IBDM_SUCCESS;
	} else {
		IBTF_DPRINTF_L4("ibdm", "\tis_dev_mgt_supported: "
		    "Not SUPPD !!, cap 0x%x", resp->PortInfo.CapabilityMask);
		ret = IBDM_FAILURE;
	}
	kmem_free(resp, length);
	return (ret);
}


/*
 * ibdm_get_node_port_guids()
 *	Get the NodeInfoRecord of the port
 *	Save NodeGuid and PortGUID values in the GID list structure.
 *	Return IBDM_SUCCESS/IBDM_FAILURE
 */
static int
ibdm_get_node_port_guids(ibmf_saa_handle_t sa_hdl, ib_lid_t dlid,
    ib_guid_t *node_guid, ib_guid_t *port_guid)
{
	int			ret;
	size_t			length = 0;
	sa_node_record_t	req, *resp = NULL;
	ibmf_saa_access_args_t	qargs;

	IBTF_DPRINTF_L4("ibdm", "\tget_node_port_guids");

	bzero(&req, sizeof (sa_node_record_t));
	req.LID = dlid;

	qargs.sq_attr_id	= SA_NODERECORD_ATTRID;
	qargs.sq_access_type	= IBMF_SAA_RETRIEVE;
	qargs.sq_component_mask = SA_NODEINFO_COMPMASK_NODELID;
	qargs.sq_template	= &req;
	qargs.sq_callback	= NULL;
	qargs.sq_callback_arg	= NULL;

	ret = ibmf_sa_access(sa_hdl, &qargs, 0, &length, (void **)&resp);
	if ((ret != IBMF_SUCCESS) || (length == 0) || (resp == NULL)) {
		IBTF_DPRINTF_L2("ibdm", "\tget_node_port_guids:"
		    " SA Retrieve Failed: %d", ret);
		return (IBDM_FAILURE);
	}
	IBTF_DPRINTF_L4("ibdm", "\tget_node_port_guids: NodeGuid %llx Port"
	    "GUID %llx", resp->NodeInfo.NodeGUID, resp->NodeInfo.NodeGUID);

	*node_guid = resp->NodeInfo.NodeGUID;
	*port_guid = resp->NodeInfo.PortGUID;
	kmem_free(resp, length);
	return (IBDM_SUCCESS);
}


/*
 * ibdm_get_reachable_ports()
 *	Get list of the destination GID (and its path  records) by
 *	querying the SA access.
 *
 *	Returns Number paths
 */
static int
ibdm_get_reachable_ports(ibdm_port_attr_t *portinfo, ibdm_hca_list_t *hca)
{
	uint_t			ii, jj, nrecs;
	uint_t			npaths = 0;
	size_t			length;
	ib_gid_t		sgid;
	ibdm_pkey_tbl_t		*pkey_tbl;
	sa_path_record_t	*result;
	sa_path_record_t	*precp;
	ibdm_dp_gidinfo_t	*gid_info;

	ASSERT(MUTEX_HELD(&ibdm.ibdm_hl_mutex));
	IBTF_DPRINTF_L4("ibdm", "\tget_reachable_ports: portinfo %p", portinfo);

	sgid.gid_prefix = portinfo->pa_sn_prefix;
	sgid.gid_guid	= portinfo->pa_port_guid;

	/* get reversible paths */
	if (portinfo->pa_sa_hdl && ibmf_saa_paths_from_gid(portinfo->pa_sa_hdl,
	    sgid, IBMF_SAA_PKEY_WC, B_TRUE, 0, &nrecs, &length, &result)
	    != IBMF_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm",
		    "\tget_reachable_ports: Getting path records failed");
		return (0);
	}

	for (ii = 0; ii < nrecs; ii++) {
		sa_node_record_t *nrec;
		size_t length;

		precp = &result[ii];
		if ((gid_info = ibdm_check_dgid(precp->DGID.gid_guid,
		    precp->DGID.gid_prefix)) != NULL) {
			IBTF_DPRINTF_L5("ibdm", "\tget_reachable_ports: "
			    "Already exists nrecs %d, ii %d", nrecs, ii);
			ibdm_addto_glhcalist(gid_info, hca);
			continue;
		}
		/*
		 * This is a new GID. Allocate a GID structure and
		 * initialize the structure
		 * gl_state is initialized to IBDM_GID_PROBE_NOT_DONE (0)
		 * by kmem_zalloc call
		 */
		gid_info = kmem_zalloc(sizeof (ibdm_dp_gidinfo_t), KM_SLEEP);
		mutex_init(&gid_info->gl_mutex, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&gid_info->gl_probe_cv, NULL, CV_DRIVER, NULL);
		gid_info->gl_dgid_hi		= precp->DGID.gid_prefix;
		gid_info->gl_dgid_lo		= precp->DGID.gid_guid;
		gid_info->gl_sgid_hi		= precp->SGID.gid_prefix;
		gid_info->gl_sgid_lo		= precp->SGID.gid_guid;
		gid_info->gl_p_key		= precp->P_Key;
		gid_info->gl_sa_hdl		= portinfo->pa_sa_hdl;
		gid_info->gl_ibmf_hdl		= portinfo->pa_ibmf_hdl;
		gid_info->gl_slid		= precp->SLID;
		gid_info->gl_dlid		= precp->DLID;
		gid_info->gl_transactionID	= (++ibdm.ibdm_transactionID)
		    << IBDM_GID_TRANSACTIONID_SHIFT;
		gid_info->gl_min_transactionID  = gid_info->gl_transactionID;
		gid_info->gl_max_transactionID  = (ibdm.ibdm_transactionID +1)
		    << IBDM_GID_TRANSACTIONID_SHIFT;
		gid_info->gl_SL			= precp->SL;

		/*
		 * get the node record with this guid if the destination
		 * device is a Cisco one.
		 */
		if (ibdm_is_cisco(precp->DGID.gid_guid) &&
		    (gid_info->gl_nodeguid == 0 || gid_info->gl_devid == 0) &&
		    ibdm_get_node_record_by_port(portinfo->pa_sa_hdl,
		    precp->DGID.gid_guid, &nrec, &length) == IBDM_SUCCESS) {
			gid_info->gl_nodeguid = nrec->NodeInfo.NodeGUID;
			gid_info->gl_devid = nrec->NodeInfo.DeviceID;
			kmem_free(nrec, length);
		}

		ibdm_addto_glhcalist(gid_info,  hca);

		ibdm_dump_path_info(precp);

		gid_info->gl_qp_hdl = NULL;
		ASSERT(portinfo->pa_pkey_tbl != NULL &&
		    portinfo->pa_npkeys != 0);

		for (jj = 0; jj < portinfo->pa_npkeys; jj++) {
			pkey_tbl = &portinfo->pa_pkey_tbl[jj];
			if ((gid_info->gl_p_key == pkey_tbl->pt_pkey) &&
			    (pkey_tbl->pt_qp_hdl != NULL)) {
				gid_info->gl_qp_hdl = pkey_tbl->pt_qp_hdl;
				break;
			}
		}

		/*
		 * QP handle for GID not initialized. No matching Pkey
		 * was found!! ibdm should *not* hit this case. Flag an
		 * error and drop the GID if ibdm does encounter this.
		 */
		if (gid_info->gl_qp_hdl == NULL) {
			IBTF_DPRINTF_L2(ibdm_string,
			    "\tget_reachable_ports: No matching Pkey");
			ibdm_delete_gidinfo(gid_info);
			continue;
		}
		if (ibdm.ibdm_dp_gidlist_head == NULL) {
			ibdm.ibdm_dp_gidlist_head = gid_info;
			ibdm.ibdm_dp_gidlist_tail = gid_info;
		} else {
			ibdm.ibdm_dp_gidlist_tail->gl_next = gid_info;
			gid_info->gl_prev = ibdm.ibdm_dp_gidlist_tail;
			ibdm.ibdm_dp_gidlist_tail = gid_info;
		}
		npaths++;
	}
	kmem_free(result, length);
	IBTF_DPRINTF_L4("ibdm", "\tget_reachable_ports: npaths = %d", npaths);
	return (npaths);
}


/*
 * ibdm_check_dgid()
 *	Look in the global list to check whether we know this DGID already
 *	Return IBDM_GID_PRESENT/IBDM_GID_NOT_PRESENT
 */
static ibdm_dp_gidinfo_t *
ibdm_check_dgid(ib_guid_t guid, ib_sn_prefix_t prefix)
{
	ibdm_dp_gidinfo_t	*gid_list;

	for (gid_list = ibdm.ibdm_dp_gidlist_head; gid_list;
	    gid_list = gid_list->gl_next) {
		if ((guid == gid_list->gl_dgid_lo) &&
		    (prefix == gid_list->gl_dgid_hi)) {
			break;
		}
	}
	return (gid_list);
}


/*
 * ibdm_find_gid()
 *	Look in the global list to find a GID entry with matching
 *	port & node GUID.
 *	Return pointer to gidinfo if found, else return NULL
 */
static ibdm_dp_gidinfo_t *
ibdm_find_gid(ib_guid_t nodeguid, ib_guid_t portguid)
{
	ibdm_dp_gidinfo_t	*gid_list;

	IBTF_DPRINTF_L4("ibdm", "ibdm_find_gid(%llx, %llx)\n",
	    nodeguid, portguid);

	for (gid_list = ibdm.ibdm_dp_gidlist_head; gid_list;
	    gid_list = gid_list->gl_next) {
		if ((portguid == gid_list->gl_portguid) &&
		    (nodeguid == gid_list->gl_nodeguid)) {
			break;
		}
	}

	IBTF_DPRINTF_L4("ibdm", "ibdm_find_gid : returned %p\n",
	    gid_list);
	return (gid_list);
}


/*
 * ibdm_set_classportinfo()
 *	ibdm_set_classportinfo() is a function to activate a Cisco FC GW
 *	by sending the setClassPortInfo request with the trapLID, trapGID
 *	and etc. to the gateway since the gateway doesn't provide the IO
 *	Unit Information othewise. This behavior is the Cisco specific one,
 *	and this function is called to a Cisco FC GW only.
 *	Returns IBDM_SUCCESS/IBDM_FAILURE
 */
static int
ibdm_set_classportinfo(ibdm_dp_gidinfo_t *gid_info)
{
	ibmf_msg_t		*msg;
	ib_mad_hdr_t		*hdr;
	ibdm_timeout_cb_args_t	*cb_args;
	void			*data;
	ib_mad_classportinfo_t *cpi;

	IBTF_DPRINTF_L4("ibdm",
	    "\tset_classportinfo: gid info 0x%p", gid_info);

	/*
	 * Send command to set classportinfo attribute. Allocate a IBMF
	 * packet and initialize the packet.
	 */
	if (ibmf_alloc_msg(gid_info->gl_ibmf_hdl, IBMF_ALLOC_SLEEP,
	    &msg) != IBMF_SUCCESS) {
		IBTF_DPRINTF_L4("ibdm", "\tset_classportinfo: pkt alloc fail");
		return (IBDM_FAILURE);
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*msg))
	ibdm_alloc_send_buffers(msg);
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*msg))

	msg->im_local_addr.ia_local_lid		= gid_info->gl_slid;
	msg->im_local_addr.ia_remote_lid	= gid_info->gl_dlid;
	msg->im_local_addr.ia_remote_qno	= 1;
	msg->im_local_addr.ia_p_key		= gid_info->gl_p_key;
	msg->im_local_addr.ia_q_key		= IB_GSI_QKEY;
	msg->im_local_addr.ia_service_level	= gid_info->gl_SL;

	hdr			= IBDM_OUT_IBMFMSG_MADHDR(msg);
	hdr->BaseVersion	= MAD_CLASS_BASE_VERS_1;
	hdr->MgmtClass		= MAD_MGMT_CLASS_DEV_MGT;
	hdr->ClassVersion	= IB_DM_CLASS_VERSION_1;
	hdr->R_Method		= IB_DM_DEVMGT_METHOD_SET;
	hdr->Status		= 0;
	hdr->TransactionID	= h2b64(gid_info->gl_transactionID);
	hdr->AttributeID	= h2b16(IB_DM_ATTR_CLASSPORTINFO);
	hdr->AttributeModifier	= 0;

	data = msg->im_msgbufs_send.im_bufs_cl_data;
	cpi = (ib_mad_classportinfo_t *)data;

	/*
	 * Set the classportinfo values to activate this Cisco FC GW.
	 */
	cpi->TrapGID_hi = h2b64(gid_info->gl_sgid_hi);
	cpi->TrapGID_lo = h2b64(gid_info->gl_sgid_lo);
	cpi->TrapLID = h2b16(gid_info->gl_slid);
	cpi->TrapSL = gid_info->gl_SL;
	cpi->TrapP_Key = h2b16(gid_info->gl_p_key);
	cpi->TrapQP = h2b32((((ibmf_alt_qp_t *)gid_info->gl_qp_hdl)->isq_qpn));
	cpi->TrapQ_Key = h2b32((((ibmf_alt_qp_t *)
	    gid_info->gl_qp_hdl)->isq_qkey));

	cb_args = &gid_info->gl_cpi_cb_args;
	cb_args->cb_gid_info = gid_info;
	cb_args->cb_retry_count	= ibdm_dft_retry_cnt;
	cb_args->cb_req_type = IBDM_REQ_TYPE_CLASSPORTINFO;

	mutex_enter(&gid_info->gl_mutex);
	gid_info->gl_timeout_id = timeout(ibdm_pkt_timeout_hdlr,
	    cb_args, IBDM_TIMEOUT_VALUE(ibdm_dft_timeout));
	mutex_exit(&gid_info->gl_mutex);

	IBTF_DPRINTF_L5("ibdm", "\tset_classportinfo: "
	    "timeout id %x", gid_info->gl_timeout_id);

	if (ibmf_msg_transport(gid_info->gl_ibmf_hdl, gid_info->gl_qp_hdl,
	    msg, NULL, ibdm_ibmf_send_cb, cb_args, 0) != IBMF_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm",
		    "\tset_classportinfo: ibmf send failed");
		ibdm_ibmf_send_cb(gid_info->gl_ibmf_hdl, msg, cb_args);
	}

	return (IBDM_SUCCESS);
}


/*
 * ibdm_send_classportinfo()
 *	Send classportinfo request. When the request is completed
 *	IBMF calls ibdm_classportinfo_cb routine to inform about
 *	the completion.
 *	Returns IBDM_SUCCESS/IBDM_FAILURE
 */
static int
ibdm_send_classportinfo(ibdm_dp_gidinfo_t *gid_info)
{
	ibmf_msg_t		*msg;
	ib_mad_hdr_t		*hdr;
	ibdm_timeout_cb_args_t	*cb_args;

	IBTF_DPRINTF_L4("ibdm",
	    "\tsend_classportinfo: gid info 0x%p", gid_info);

	/*
	 * Send command to get classportinfo attribute. Allocate a IBMF
	 * packet and initialize the packet.
	 */
	if (ibmf_alloc_msg(gid_info->gl_ibmf_hdl, IBMF_ALLOC_SLEEP,
	    &msg) != IBMF_SUCCESS) {
		IBTF_DPRINTF_L4("ibdm", "\tsend_classportinfo: pkt alloc fail");
		return (IBDM_FAILURE);
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*msg))
	ibdm_alloc_send_buffers(msg);
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*msg))

	msg->im_local_addr.ia_local_lid		= gid_info->gl_slid;
	msg->im_local_addr.ia_remote_lid	= gid_info->gl_dlid;
	msg->im_local_addr.ia_remote_qno	= 1;
	msg->im_local_addr.ia_p_key		= gid_info->gl_p_key;
	msg->im_local_addr.ia_q_key		= IB_GSI_QKEY;
	msg->im_local_addr.ia_service_level	= gid_info->gl_SL;

	hdr			= IBDM_OUT_IBMFMSG_MADHDR(msg);
	hdr->BaseVersion	= MAD_CLASS_BASE_VERS_1;
	hdr->MgmtClass		= MAD_MGMT_CLASS_DEV_MGT;
	hdr->ClassVersion	= IB_DM_CLASS_VERSION_1;
	hdr->R_Method		= IB_DM_DEVMGT_METHOD_GET;
	hdr->Status		= 0;
	hdr->TransactionID	= h2b64(gid_info->gl_transactionID);
	hdr->AttributeID	= h2b16(IB_DM_ATTR_CLASSPORTINFO);
	hdr->AttributeModifier	= 0;

	cb_args = &gid_info->gl_cpi_cb_args;
	cb_args->cb_gid_info = gid_info;
	cb_args->cb_retry_count	= ibdm_dft_retry_cnt;
	cb_args->cb_req_type = IBDM_REQ_TYPE_CLASSPORTINFO;

	mutex_enter(&gid_info->gl_mutex);
	gid_info->gl_timeout_id = timeout(ibdm_pkt_timeout_hdlr,
	    cb_args, IBDM_TIMEOUT_VALUE(ibdm_dft_timeout));
	mutex_exit(&gid_info->gl_mutex);

	IBTF_DPRINTF_L5("ibdm", "\tsend_classportinfo: "
	    "timeout id %x", gid_info->gl_timeout_id);

	if (ibmf_msg_transport(gid_info->gl_ibmf_hdl, gid_info->gl_qp_hdl,
	    msg, NULL, ibdm_ibmf_send_cb, cb_args, 0) != IBMF_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm",
		    "\tsend_classportinfo: ibmf send failed");
		ibdm_ibmf_send_cb(gid_info->gl_ibmf_hdl, msg, cb_args);
	}

	return (IBDM_SUCCESS);
}


/*
 * ibdm_handle_setclassportinfo()
 *	Invoked by the IBMF when setClassPortInfo request is completed.
 */
static void
ibdm_handle_setclassportinfo(ibmf_handle_t ibmf_hdl,
    ibmf_msg_t *msg, ibdm_dp_gidinfo_t *gid_info, int *flag)
{
	void			*data;
	timeout_id_t		timeout_id;
	ib_mad_classportinfo_t *cpi;

	IBTF_DPRINTF_L4("ibdm", "\thandle_setclassportinfo:ibmf hdl "
	    "%p msg %p gid info %p", ibmf_hdl, msg, gid_info);

	if (IBDM_IN_IBMFMSG_ATTR(msg) != IB_DM_ATTR_CLASSPORTINFO) {
		IBTF_DPRINTF_L4("ibdm", "\thandle_setclassportinfo: "
		    "Not a ClassPortInfo resp");
		*flag |= IBDM_IBMF_PKT_UNEXP_RESP;
		return;
	}

	/*
	 * Verify whether timeout handler is created/active.
	 * If created/ active,  cancel the timeout  handler
	 */
	mutex_enter(&gid_info->gl_mutex);
	if (gid_info->gl_state != IBDM_SET_CLASSPORTINFO) {
		IBTF_DPRINTF_L2("ibdm", "\thandle_setclassportinfo:DUP resp");
		*flag |= IBDM_IBMF_PKT_DUP_RESP;
		mutex_exit(&gid_info->gl_mutex);
		return;
	}
	ibdm_bump_transactionID(gid_info);

	gid_info->gl_iou_cb_args.cb_req_type = 0;
	if (gid_info->gl_timeout_id) {
		timeout_id = gid_info->gl_timeout_id;
		mutex_exit(&gid_info->gl_mutex);
		IBTF_DPRINTF_L5("ibdm", "handle_setlassportinfo: "
		    "gl_timeout_id = 0x%x", timeout_id);
		if (untimeout(timeout_id) == -1) {
			IBTF_DPRINTF_L2("ibdm", "handle_setclassportinfo: "
			    "untimeout gl_timeout_id failed");
		}
		mutex_enter(&gid_info->gl_mutex);
		gid_info->gl_timeout_id = 0;
	}
	mutex_exit(&gid_info->gl_mutex);

	data = msg->im_msgbufs_recv.im_bufs_cl_data;
	cpi = (ib_mad_classportinfo_t *)data;

	ibdm_dump_classportinfo(cpi);
}


/*
 * ibdm_handle_classportinfo()
 *	Invoked by the IBMF when the classportinfo request is completed.
 */
static void
ibdm_handle_classportinfo(ibmf_handle_t ibmf_hdl,
    ibmf_msg_t *msg, ibdm_dp_gidinfo_t *gid_info, int *flag)
{
	void			*data;
	timeout_id_t		timeout_id;
	ib_mad_hdr_t		*hdr;
	ib_mad_classportinfo_t *cpi;

	IBTF_DPRINTF_L4("ibdm", "\thandle_classportinfo:ibmf hdl "
	    "%p msg %p gid info %p", ibmf_hdl, msg, gid_info);

	if (IBDM_IN_IBMFMSG_ATTR(msg) != IB_DM_ATTR_CLASSPORTINFO) {
		IBTF_DPRINTF_L4("ibdm", "\thandle_classportinfo: "
		    "Not a ClassPortInfo resp");
		*flag |= IBDM_IBMF_PKT_UNEXP_RESP;
		return;
	}

	/*
	 * Verify whether timeout handler is created/active.
	 * If created/ active,  cancel the timeout  handler
	 */
	mutex_enter(&gid_info->gl_mutex);
	ibdm_bump_transactionID(gid_info);
	if (gid_info->gl_state != IBDM_GET_CLASSPORTINFO) {
		IBTF_DPRINTF_L2("ibdm", "\thandle_classportinfo:DUP resp");
		*flag |= IBDM_IBMF_PKT_DUP_RESP;
		mutex_exit(&gid_info->gl_mutex);
		return;
	}
	gid_info->gl_iou_cb_args.cb_req_type = 0;
	if (gid_info->gl_timeout_id) {
		timeout_id = gid_info->gl_timeout_id;
		mutex_exit(&gid_info->gl_mutex);
		IBTF_DPRINTF_L5("ibdm", "handle_ioclassportinfo: "
		    "gl_timeout_id = 0x%x", timeout_id);
		if (untimeout(timeout_id) == -1) {
			IBTF_DPRINTF_L2("ibdm", "handle_classportinfo: "
			    "untimeout gl_timeout_id failed");
		}
		mutex_enter(&gid_info->gl_mutex);
		gid_info->gl_timeout_id = 0;
	}
	gid_info->gl_state = IBDM_GET_IOUNITINFO;
	gid_info->gl_pending_cmds++;
	mutex_exit(&gid_info->gl_mutex);

	data = msg->im_msgbufs_recv.im_bufs_cl_data;
	cpi = (ib_mad_classportinfo_t *)data;

	/*
	 * Cache the "RespTimeValue" and redirection information in the
	 * global gid list data structure. This cached information will
	 * be used to send any further requests to the GID.
	 */
	gid_info->gl_resp_timeout	=
	    (b2h32(cpi->RespTimeValue) & 0x1F);

	gid_info->gl_redirected		= ((IBDM_IN_IBMFMSG_STATUS(msg) &
	    MAD_STATUS_REDIRECT_REQUIRED) ? B_TRUE: B_FALSE);
	gid_info->gl_redirect_dlid	= b2h16(cpi->RedirectLID);
	gid_info->gl_redirect_QP	= (b2h32(cpi->RedirectQP) & 0xffffff);
	gid_info->gl_redirect_pkey	= b2h16(cpi->RedirectP_Key);
	gid_info->gl_redirect_qkey	= b2h32(cpi->RedirectQ_Key);
	gid_info->gl_redirectGID_hi	= b2h64(cpi->RedirectGID_hi);
	gid_info->gl_redirectGID_lo	= b2h64(cpi->RedirectGID_lo);
	gid_info->gl_redirectSL		= cpi->RedirectSL;

	ibdm_dump_classportinfo(cpi);

	/*
	 * Send IOUnitInfo request
	 * Reuse previously allocated IBMF packet for sending ClassPortInfo
	 * Check whether DM agent on the remote node requested redirection
	 * If so, send the request to the redirect DGID/DLID/PKEY/QP.
	 */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*msg))
	ibdm_alloc_send_buffers(msg);
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*msg))
	msg->im_local_addr.ia_local_lid	= gid_info->gl_slid;
	msg->im_local_addr.ia_remote_lid	= gid_info->gl_dlid;

	if (gid_info->gl_redirected == B_TRUE) {
		if (gid_info->gl_redirect_dlid != 0) {
			msg->im_local_addr.ia_remote_lid =
			    gid_info->gl_redirect_dlid;
		}
		msg->im_local_addr.ia_remote_qno = gid_info->gl_redirect_QP;
		msg->im_local_addr.ia_p_key = gid_info->gl_redirect_pkey;
		msg->im_local_addr.ia_q_key = gid_info->gl_redirect_qkey;
		msg->im_local_addr.ia_service_level = gid_info->gl_redirectSL;
	} else {
		msg->im_local_addr.ia_remote_qno = 1;
		msg->im_local_addr.ia_p_key = gid_info->gl_p_key;
		msg->im_local_addr.ia_q_key = IB_GSI_QKEY;
		msg->im_local_addr.ia_service_level = gid_info->gl_SL;
	}

	hdr			= IBDM_OUT_IBMFMSG_MADHDR(msg);
	hdr->BaseVersion	= MAD_CLASS_BASE_VERS_1;
	hdr->MgmtClass		= MAD_MGMT_CLASS_DEV_MGT;
	hdr->ClassVersion	= IB_DM_CLASS_VERSION_1;
	hdr->R_Method		= IB_DM_DEVMGT_METHOD_GET;
	hdr->Status		= 0;
	hdr->TransactionID	= h2b64(gid_info->gl_transactionID);
	hdr->AttributeID	= h2b16(IB_DM_ATTR_IO_UNITINFO);
	hdr->AttributeModifier	= 0;

	gid_info->gl_iou_cb_args.cb_req_type = IBDM_REQ_TYPE_IOUINFO;
	gid_info->gl_iou_cb_args.cb_gid_info = gid_info;
	gid_info->gl_iou_cb_args.cb_retry_count = ibdm_dft_retry_cnt;

	mutex_enter(&gid_info->gl_mutex);
	gid_info->gl_timeout_id = timeout(ibdm_pkt_timeout_hdlr,
	    &gid_info->gl_iou_cb_args, IBDM_TIMEOUT_VALUE(ibdm_dft_timeout));
	mutex_exit(&gid_info->gl_mutex);

	IBTF_DPRINTF_L5("ibdm", "handle_classportinfo:"
	    "timeout %x", gid_info->gl_timeout_id);

	if (ibmf_msg_transport(ibmf_hdl, gid_info->gl_qp_hdl, msg, NULL,
	    ibdm_ibmf_send_cb, &gid_info->gl_iou_cb_args, 0) != IBMF_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm",
		    "\thandle_classportinfo: msg transport failed");
		ibdm_ibmf_send_cb(ibmf_hdl, msg, &gid_info->gl_iou_cb_args);
	}
	(*flag) |= IBDM_IBMF_PKT_REUSED;
}


/*
 * ibdm_send_iounitinfo:
 *	Sends a DM request to get IOU unitinfo.
 */
static int
ibdm_send_iounitinfo(ibdm_dp_gidinfo_t *gid_info)
{
	ibmf_msg_t	*msg;
	ib_mad_hdr_t	*hdr;

	IBTF_DPRINTF_L4("ibdm", "\tsend_iounitinfo: gid info 0x%p", gid_info);

	/*
	 * Send command to get iounitinfo attribute. Allocate a IBMF
	 * packet and initialize the packet.
	 */
	if (ibmf_alloc_msg(gid_info->gl_ibmf_hdl, IBMF_ALLOC_SLEEP, &msg) !=
	    IBMF_SUCCESS) {
		IBTF_DPRINTF_L4("ibdm", "\tsend_iounitinfo: pkt alloc fail");
		return (IBDM_FAILURE);
	}

	mutex_enter(&gid_info->gl_mutex);
	ibdm_bump_transactionID(gid_info);
	mutex_exit(&gid_info->gl_mutex);


	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*msg))
	ibdm_alloc_send_buffers(msg);
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*msg))
	msg->im_local_addr.ia_local_lid		= gid_info->gl_slid;
	msg->im_local_addr.ia_remote_lid	= gid_info->gl_dlid;
	msg->im_local_addr.ia_remote_qno	= 1;
	msg->im_local_addr.ia_p_key		= gid_info->gl_p_key;
	msg->im_local_addr.ia_q_key		= IB_GSI_QKEY;
	msg->im_local_addr.ia_service_level	= gid_info->gl_SL;

	hdr			= IBDM_OUT_IBMFMSG_MADHDR(msg);
	hdr->BaseVersion	= MAD_CLASS_BASE_VERS_1;
	hdr->MgmtClass		= MAD_MGMT_CLASS_DEV_MGT;
	hdr->ClassVersion	= IB_DM_CLASS_VERSION_1;
	hdr->R_Method		= IB_DM_DEVMGT_METHOD_GET;
	hdr->Status		= 0;
	hdr->TransactionID	= h2b64(gid_info->gl_transactionID);
	hdr->AttributeID	= h2b16(IB_DM_ATTR_IO_UNITINFO);
	hdr->AttributeModifier	= 0;

	gid_info->gl_iou_cb_args.cb_gid_info = gid_info;
	gid_info->gl_iou_cb_args.cb_retry_count = ibdm_dft_retry_cnt;
	gid_info->gl_iou_cb_args.cb_req_type = IBDM_REQ_TYPE_IOUINFO;

	mutex_enter(&gid_info->gl_mutex);
	gid_info->gl_timeout_id = timeout(ibdm_pkt_timeout_hdlr,
	    &gid_info->gl_iou_cb_args, IBDM_TIMEOUT_VALUE(ibdm_dft_timeout));
	mutex_exit(&gid_info->gl_mutex);

	IBTF_DPRINTF_L5("ibdm", "send_iouunitinfo:"
	    "timeout %x", gid_info->gl_timeout_id);

	if (ibmf_msg_transport(gid_info->gl_ibmf_hdl, gid_info->gl_qp_hdl, msg,
	    NULL, ibdm_ibmf_send_cb, &gid_info->gl_iou_cb_args, 0) !=
	    IBMF_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm", "\tsend_iounitinfo: ibmf send failed");
		ibdm_ibmf_send_cb(gid_info->gl_ibmf_hdl,
		    msg, &gid_info->gl_iou_cb_args);
	}
	return (IBDM_SUCCESS);
}

/*
 * ibdm_handle_iounitinfo()
 *	Invoked by the IBMF when IO Unitinfo request is completed.
 */
static void
ibdm_handle_iounitinfo(ibmf_handle_t ibmf_hdl,
    ibmf_msg_t *msg, ibdm_dp_gidinfo_t *gid_info, int *flag)
{
	int			ii, first = B_TRUE;
	int			num_iocs;
	size_t			size;
	uchar_t			slot_info;
	timeout_id_t		timeout_id;
	ib_mad_hdr_t		*hdr;
	ibdm_ioc_info_t		*ioc_info;
	ib_dm_io_unitinfo_t	*iou_info;
	ib_dm_io_unitinfo_t	*giou_info;
	ibdm_timeout_cb_args_t	*cb_args;

	IBTF_DPRINTF_L4("ibdm", "\thandle_iouintinfo:"
	    " ibmf hdl %p pkt %p gid info %p", ibmf_hdl, msg, gid_info);

	if (IBDM_IN_IBMFMSG_ATTR(msg) != IB_DM_ATTR_IO_UNITINFO) {
		IBTF_DPRINTF_L4("ibdm", "\thandle_iounitinfo: "
		    "Unexpected response");
		(*flag) |= IBDM_IBMF_PKT_UNEXP_RESP;
		return;
	}

	mutex_enter(&gid_info->gl_mutex);
	if (gid_info->gl_state != IBDM_GET_IOUNITINFO) {
		IBTF_DPRINTF_L4("ibdm",
		    "\thandle_iounitinfo: DUP resp");
		mutex_exit(&gid_info->gl_mutex);
		(*flag) = IBDM_IBMF_PKT_DUP_RESP;
		return;
	}
	gid_info->gl_iou_cb_args.cb_req_type = 0;
	if (gid_info->gl_timeout_id) {
		timeout_id = gid_info->gl_timeout_id;
		mutex_exit(&gid_info->gl_mutex);
		IBTF_DPRINTF_L5("ibdm", "handle_iounitinfo: "
		    "gl_timeout_id = 0x%x", timeout_id);
		if (untimeout(timeout_id) == -1) {
			IBTF_DPRINTF_L2("ibdm", "handle_iounitinfo: "
			    "untimeout gl_timeout_id failed");
		}
		mutex_enter(&gid_info->gl_mutex);
		gid_info->gl_timeout_id = 0;
	}
	gid_info->gl_state = IBDM_GET_IOC_DETAILS;

	iou_info = IBDM_IN_IBMFMSG2IOU(msg);
	ibdm_dump_iounitinfo(iou_info);
	num_iocs = iou_info->iou_num_ctrl_slots;
	/*
	 * check if number of IOCs reported is zero? if yes, return.
	 * when num_iocs are reported zero internal IOC database needs
	 * to be updated. To ensure that save the number of IOCs in
	 * the new field "gl_num_iocs". Use a new field instead of
	 * "giou_info->iou_num_ctrl_slots" as that would prevent
	 * an unnecessary kmem_alloc/kmem_free when num_iocs is 0.
	 */
	if (num_iocs == 0 && gid_info->gl_num_iocs == 0) {
		IBTF_DPRINTF_L4("ibdm", "\thandle_iounitinfo: no IOC's");
		mutex_exit(&gid_info->gl_mutex);
		return;
	}
	IBTF_DPRINTF_L4("ibdm", "\thandle_iounitinfo: num_iocs = %d", num_iocs);

	/*
	 * if there is an existing gl_iou (IOU has been probed before)
	 * check if the "iou_changeid" is same as saved entry in
	 * "giou_info->iou_changeid".
	 * (note: this logic can prevent IOC enumeration if a given
	 * vendor doesn't support setting iou_changeid field for its IOU)
	 *
	 * if there is an existing gl_iou and iou_changeid has changed :
	 * free up existing gl_iou info and its related structures.
	 * reallocate gl_iou info all over again.
	 * if we donot free this up; then this leads to memory leaks
	 */
	if (gid_info->gl_iou) {
		giou_info = &gid_info->gl_iou->iou_info;
		if (b2h16(iou_info->iou_changeid) ==
		    giou_info->iou_changeid) {
			IBTF_DPRINTF_L3("ibdm",
			    "\thandle_iounitinfo: no IOCs changed");
			gid_info->gl_state = IBDM_GID_PROBING_COMPLETE;
			mutex_exit(&gid_info->gl_mutex);
			return;
		}

		/*
		 * Store the iou info as prev_iou to be used after
		 * sweep is done.
		 */
		ASSERT(gid_info->gl_prev_iou == NULL);
		IBTF_DPRINTF_L4(ibdm_string,
		    "\thandle_iounitinfo: setting gl_prev_iou %p",
		    gid_info->gl_prev_iou);
		gid_info->gl_prev_iou = gid_info->gl_iou;
		ibdm.ibdm_prev_iou = 1;
		gid_info->gl_iou = NULL;
	}

	size = sizeof (ibdm_iou_info_t) + num_iocs * sizeof (ibdm_ioc_info_t);
	gid_info->gl_iou = (ibdm_iou_info_t *)kmem_zalloc(size, KM_SLEEP);
	giou_info = &gid_info->gl_iou->iou_info;
	gid_info->gl_iou->iou_ioc_info = (ibdm_ioc_info_t *)
	    ((char *)gid_info->gl_iou + sizeof (ibdm_iou_info_t));

	giou_info->iou_num_ctrl_slots	= gid_info->gl_num_iocs	= num_iocs;
	giou_info->iou_flag		= iou_info->iou_flag;
	bcopy(iou_info->iou_ctrl_list, giou_info->iou_ctrl_list, 128);
	giou_info->iou_changeid	= b2h16(iou_info->iou_changeid);
	gid_info->gl_pending_cmds++; /* for diag code */
	mutex_exit(&gid_info->gl_mutex);

	if (ibdm_get_diagcode(gid_info, 0) != IBDM_SUCCESS) {
		mutex_enter(&gid_info->gl_mutex);
		gid_info->gl_pending_cmds--;
		mutex_exit(&gid_info->gl_mutex);
	}
	/*
	 * Parallelize getting IOC controller profiles from here.
	 * Allocate IBMF packets and send commands to get IOC profile for
	 * each IOC present on the IOU.
	 */
	for (ii = 0; ii < num_iocs; ii++) {
		/*
		 * Check whether IOC is present in the slot
		 * Series of nibbles (in the field iou_ctrl_list) represents
		 * a slot in the IOU.
		 * Byte format: 76543210
		 * Bits 0-3 of first byte represent Slot 2
		 * bits 4-7 of first byte represent slot 1,
		 * bits 0-3 of second byte represent slot 4 and so on
		 * Each 4-bit nibble has the following meaning
		 * 0x0 : IOC not installed
		 * 0x1 : IOC is present
		 * 0xf : Slot does not exist
		 * and all other values are reserved.
		 */
		ioc_info = IBDM_GIDINFO2IOCINFO(gid_info, ii);
		slot_info = giou_info->iou_ctrl_list[(ii/2)];
		if ((ii % 2) == 0)
			slot_info = (slot_info >> 4);

		if ((slot_info & 0xf) != 1) {
			IBTF_DPRINTF_L4("ibdm", "\thandle_iouintinfo: "
			    "No IOC is present in the slot = %d", ii);
			ioc_info->ioc_state = IBDM_IOC_STATE_PROBE_FAILED;
			continue;
		}

		mutex_enter(&gid_info->gl_mutex);
		ibdm_bump_transactionID(gid_info);
		mutex_exit(&gid_info->gl_mutex);

		/*
		 * Re use the already allocated packet (for IOUnitinfo) to
		 * send the first IOC controller attribute. Allocate new
		 * IBMF packets for the rest of the IOC's
		 */
		if (first != B_TRUE) {
			msg = NULL;
			if (ibmf_alloc_msg(ibmf_hdl, IBMF_ALLOC_SLEEP,
			    &msg) != IBMF_SUCCESS) {
				IBTF_DPRINTF_L4("ibdm", "\thandle_iouintinfo: "
				    "IBMF packet allocation failed");
				continue;
			}

		}

		/* allocate send buffers for all messages */
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*msg))
		ibdm_alloc_send_buffers(msg);
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*msg))

		msg->im_local_addr.ia_local_lid	= gid_info->gl_slid;
		msg->im_local_addr.ia_remote_lid	= gid_info->gl_dlid;
		if (gid_info->gl_redirected == B_TRUE) {
			if (gid_info->gl_redirect_dlid != 0) {
				msg->im_local_addr.ia_remote_lid =
				    gid_info->gl_redirect_dlid;
			}
			msg->im_local_addr.ia_remote_qno =
			    gid_info->gl_redirect_QP;
			msg->im_local_addr.ia_p_key =
			    gid_info->gl_redirect_pkey;
			msg->im_local_addr.ia_q_key =
			    gid_info->gl_redirect_qkey;
			msg->im_local_addr.ia_service_level =
			    gid_info->gl_redirectSL;
		} else {
			msg->im_local_addr.ia_remote_qno = 1;
			msg->im_local_addr.ia_p_key = gid_info->gl_p_key;
			msg->im_local_addr.ia_q_key = IB_GSI_QKEY;
			msg->im_local_addr.ia_service_level = gid_info->gl_SL;
		}

		hdr			= IBDM_OUT_IBMFMSG_MADHDR(msg);
		hdr->BaseVersion	= MAD_CLASS_BASE_VERS_1;
		hdr->MgmtClass		= MAD_MGMT_CLASS_DEV_MGT;
		hdr->ClassVersion	= IB_DM_CLASS_VERSION_1;
		hdr->R_Method		= IB_DM_DEVMGT_METHOD_GET;
		hdr->Status		= 0;
		hdr->TransactionID	= h2b64(gid_info->gl_transactionID);
		hdr->AttributeID	= h2b16(IB_DM_ATTR_IOC_CTRL_PROFILE);
		hdr->AttributeModifier 	= h2b32(ii + 1);

		ioc_info->ioc_state	= IBDM_IOC_STATE_PROBE_INVALID;
		cb_args			= &ioc_info->ioc_cb_args;
		cb_args->cb_gid_info	= gid_info;
		cb_args->cb_retry_count	= ibdm_dft_retry_cnt;
		cb_args->cb_req_type	= IBDM_REQ_TYPE_IOCINFO;
		cb_args->cb_ioc_num	= ii;

		mutex_enter(&gid_info->gl_mutex);
		gid_info->gl_pending_cmds++; /* for diag code */

		ioc_info->ioc_timeout_id = timeout(ibdm_pkt_timeout_hdlr,
		    cb_args, IBDM_TIMEOUT_VALUE(ibdm_dft_timeout));
		mutex_exit(&gid_info->gl_mutex);

		IBTF_DPRINTF_L5("ibdm", "\thandle_iounitinfo:"
		    "timeout 0x%x, ioc_num %d", ioc_info->ioc_timeout_id, ii);

		if (ibmf_msg_transport(ibmf_hdl, gid_info->gl_qp_hdl, msg,
		    NULL, ibdm_ibmf_send_cb, cb_args, 0) != IBMF_SUCCESS) {
			IBTF_DPRINTF_L2("ibdm",
			    "\thandle_iounitinfo: msg transport failed");
			ibdm_ibmf_send_cb(ibmf_hdl, msg, cb_args);
		}
		(*flag) |= IBDM_IBMF_PKT_REUSED;
		first = B_FALSE;
		gid_info->gl_iou->iou_niocs_probe_in_progress++;
	}
}


/*
 * ibdm_handle_ioc_profile()
 *	Invoked by the IBMF when the IOCControllerProfile request
 *	gets completed
 */
static void
ibdm_handle_ioc_profile(ibmf_handle_t ibmf_hdl,
    ibmf_msg_t *msg, ibdm_dp_gidinfo_t *gid_info, int *flag)
{
	int				first = B_TRUE, reprobe = 0;
	uint_t				ii, ioc_no, srv_start;
	uint_t				nserv_entries;
	timeout_id_t			timeout_id;
	ib_mad_hdr_t			*hdr;
	ibdm_ioc_info_t			*ioc_info;
	ibdm_timeout_cb_args_t		*cb_args;
	ib_dm_ioc_ctrl_profile_t	*ioc, *gioc;

	IBTF_DPRINTF_L4("ibdm", "\thandle_ioc_profile:"
	    " ibmf hdl %p msg %p gid info %p", ibmf_hdl, msg, gid_info);

	ioc = IBDM_IN_IBMFMSG2IOC(msg);
	/*
	 * Check whether we know this IOC already
	 * This will return NULL if reprobe is in progress
	 * IBDM_IOC_STATE_REPROBE_PROGRESS will be set.
	 * Do not hold mutexes here.
	 */
	if (ibdm_is_ioc_present(ioc->ioc_guid, gid_info, flag) != NULL) {
		IBTF_DPRINTF_L4("ibdm", "\thandle_ioc_profile:"
		    "IOC guid %llx is present", ioc->ioc_guid);
		return;
	}
	ioc_no = IBDM_IN_IBMFMSG_ATTRMOD(msg);
	IBTF_DPRINTF_L4("ibdm", "\thandle_ioc_profile: ioc_no = %d", ioc_no-1);

	/* Make sure that IOC index is with the valid range */
	if (IBDM_IS_IOC_NUM_INVALID(ioc_no, gid_info)) {
		IBTF_DPRINTF_L2("ibdm", "\thandle_ioc_profile: "
		    "IOC index Out of range, index %d", ioc);
		(*flag) |= IBDM_IBMF_PKT_UNEXP_RESP;
		return;
	}
	ioc_info = &gid_info->gl_iou->iou_ioc_info[ioc_no - 1];
	ioc_info->ioc_iou_info = gid_info->gl_iou;

	mutex_enter(&gid_info->gl_mutex);
	if (ioc_info->ioc_state == IBDM_IOC_STATE_REPROBE_PROGRESS) {
		reprobe = 1;
		ioc_info->ioc_prev_serv = ioc_info->ioc_serv;
		ioc_info->ioc_serv = NULL;
		ioc_info->ioc_prev_serv_cnt =
		    ioc_info->ioc_profile.ioc_service_entries;
	} else if (ioc_info->ioc_state != IBDM_IOC_STATE_PROBE_INVALID) {
		IBTF_DPRINTF_L2("ibdm", "\thandle_ioc_profile: DUP response"
		    "ioc %d, ioc_state %x", ioc_no - 1, ioc_info->ioc_state);
		mutex_exit(&gid_info->gl_mutex);
		(*flag) |= IBDM_IBMF_PKT_DUP_RESP;
		return;
	}
	ioc_info->ioc_cb_args.cb_req_type = 0;
	if (ioc_info->ioc_timeout_id) {
		timeout_id = ioc_info->ioc_timeout_id;
		ioc_info->ioc_timeout_id = 0;
		mutex_exit(&gid_info->gl_mutex);
		IBTF_DPRINTF_L5("ibdm", "handle_ioc_profile: "
		    "ioc_timeout_id = 0x%x", timeout_id);
		if (untimeout(timeout_id) == -1) {
			IBTF_DPRINTF_L2("ibdm", "handle_ioc_profile: "
			    "untimeout ioc_timeout_id failed");
		}
		mutex_enter(&gid_info->gl_mutex);
	}

	ioc_info->ioc_state = IBDM_IOC_STATE_PROBE_SUCCESS;
	if (reprobe == 0) {
		ioc_info->ioc_iou_guid = gid_info->gl_nodeguid;
		ioc_info->ioc_nodeguid = gid_info->gl_nodeguid;
	}

	/*
	 * Save all the IOC information in the global structures.
	 * Note the wire format is Big Endian and the Sparc process also
	 * big endian. So, there is no need to convert the data fields
	 * The conversion routines used below are ineffective on Sparc
	 * machines where as they will be effective on little endian
	 * machines such as Intel processors.
	 */
	gioc = (ib_dm_ioc_ctrl_profile_t *)&ioc_info->ioc_profile;

	/*
	 * Restrict updates to onlyport GIDs and service entries during reprobe
	 */
	if (reprobe == 0) {
		gioc->ioc_guid			= b2h64(ioc->ioc_guid);
		gioc->ioc_vendorid		=
		    ((b2h32(ioc->ioc_vendorid) & IB_DM_VENDORID_MASK)
		    >> IB_DM_VENDORID_SHIFT);
		gioc->ioc_deviceid		= b2h32(ioc->ioc_deviceid);
		gioc->ioc_device_ver		= b2h16(ioc->ioc_device_ver);
		gioc->ioc_subsys_vendorid	=
		    ((b2h32(ioc->ioc_subsys_vendorid) & IB_DM_VENDORID_MASK)
		    >> IB_DM_VENDORID_SHIFT);
		gioc->ioc_subsys_id		= b2h32(ioc->ioc_subsys_id);
		gioc->ioc_io_class		= b2h16(ioc->ioc_io_class);
		gioc->ioc_io_subclass		= b2h16(ioc->ioc_io_subclass);
		gioc->ioc_protocol		= b2h16(ioc->ioc_protocol);
		gioc->ioc_protocol_ver		= b2h16(ioc->ioc_protocol_ver);
		gioc->ioc_send_msg_qdepth	=
		    b2h16(ioc->ioc_send_msg_qdepth);
		gioc->ioc_rdma_read_qdepth	=
		    b2h16(ioc->ioc_rdma_read_qdepth);
		gioc->ioc_send_msg_sz		= b2h32(ioc->ioc_send_msg_sz);
		gioc->ioc_rdma_xfer_sz		= b2h32(ioc->ioc_rdma_xfer_sz);
		gioc->ioc_ctrl_opcap_mask	= ioc->ioc_ctrl_opcap_mask;
		bcopy(ioc->ioc_id_string, gioc->ioc_id_string,
		    IB_DM_IOC_ID_STRING_LEN);

		ioc_info->ioc_iou_diagcode = gid_info->gl_iou->iou_diagcode;
		ioc_info->ioc_iou_dc_valid = gid_info->gl_iou->iou_dc_valid;
		ioc_info->ioc_diagdeviceid = (IB_DM_IOU_DEVICEID_MASK &
		    gid_info->gl_iou->iou_info.iou_flag) ? B_TRUE : B_FALSE;

		if (ioc_info->ioc_diagdeviceid == B_TRUE) {
			gid_info->gl_pending_cmds++;
			IBTF_DPRINTF_L3(ibdm_string,
			    "\tibdm_handle_ioc_profile: "
			    "%d: gid_info %p gl_state %d pending_cmds %d",
			    __LINE__, gid_info, gid_info->gl_state,
			    gid_info->gl_pending_cmds);
		}
	}
	gioc->ioc_service_entries	= ioc->ioc_service_entries;
	mutex_exit(&gid_info->gl_mutex);

	ibdm_dump_ioc_profile(gioc);

	if ((ioc_info->ioc_diagdeviceid == B_TRUE) && (reprobe == 0)) {
		if (ibdm_get_diagcode(gid_info, ioc_no) != IBDM_SUCCESS) {
			mutex_enter(&gid_info->gl_mutex);
			gid_info->gl_pending_cmds--;
			mutex_exit(&gid_info->gl_mutex);
		}
	}
	ioc_info->ioc_serv = (ibdm_srvents_info_t *)kmem_zalloc(
	    (gioc->ioc_service_entries * sizeof (ibdm_srvents_info_t)),
	    KM_SLEEP);

	/*
	 * In one single request, maximum number of requests that can be
	 * obtained is 4. If number of service entries are more than four,
	 * calculate number requests needed and send them parallelly.
	 */
	nserv_entries = ioc->ioc_service_entries;
	ii = 0;
	while (nserv_entries) {
		mutex_enter(&gid_info->gl_mutex);
		gid_info->gl_pending_cmds++;
		ibdm_bump_transactionID(gid_info);
		mutex_exit(&gid_info->gl_mutex);

		if (first != B_TRUE) {
			if (ibmf_alloc_msg(ibmf_hdl, IBMF_ALLOC_SLEEP,
			    &msg) != IBMF_SUCCESS) {
				continue;
			}

		}
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*msg))
		ibdm_alloc_send_buffers(msg);
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*msg))
		msg->im_local_addr.ia_local_lid	= gid_info->gl_slid;
		msg->im_local_addr.ia_remote_lid	= gid_info->gl_dlid;
		if (gid_info->gl_redirected == B_TRUE) {
			if (gid_info->gl_redirect_dlid != 0) {
				msg->im_local_addr.ia_remote_lid =
				    gid_info->gl_redirect_dlid;
			}
			msg->im_local_addr.ia_remote_qno =
			    gid_info->gl_redirect_QP;
			msg->im_local_addr.ia_p_key =
			    gid_info->gl_redirect_pkey;
			msg->im_local_addr.ia_q_key =
			    gid_info->gl_redirect_qkey;
			msg->im_local_addr.ia_service_level =
			    gid_info->gl_redirectSL;
		} else {
			msg->im_local_addr.ia_remote_qno = 1;
			msg->im_local_addr.ia_p_key = gid_info->gl_p_key;
			msg->im_local_addr.ia_q_key = IB_GSI_QKEY;
			msg->im_local_addr.ia_service_level = gid_info->gl_SL;
		}

		hdr			= IBDM_OUT_IBMFMSG_MADHDR(msg);
		hdr->BaseVersion	= MAD_CLASS_BASE_VERS_1;
		hdr->MgmtClass		= MAD_MGMT_CLASS_DEV_MGT;
		hdr->ClassVersion	= IB_DM_CLASS_VERSION_1;
		hdr->R_Method		= IB_DM_DEVMGT_METHOD_GET;
		hdr->Status		= 0;
		hdr->TransactionID	= h2b64(gid_info->gl_transactionID);
		hdr->AttributeID	= h2b16(IB_DM_ATTR_SERVICE_ENTRIES);

		srv_start = ii * 4;
		cb_args = &ioc_info->ioc_serv[srv_start].se_cb_args;
		cb_args->cb_gid_info	= gid_info;
		cb_args->cb_retry_count	= ibdm_dft_retry_cnt;
		cb_args->cb_req_type	= IBDM_REQ_TYPE_SRVENTS;
		cb_args->cb_srvents_start = srv_start;
		cb_args->cb_ioc_num	= ioc_no - 1;

		if (nserv_entries >= IBDM_MAX_SERV_ENTRIES_PER_REQ) {
			nserv_entries -= IBDM_MAX_SERV_ENTRIES_PER_REQ;
			cb_args->cb_srvents_end = (cb_args->cb_srvents_start +
			    IBDM_MAX_SERV_ENTRIES_PER_REQ - 1);
		} else {
			cb_args->cb_srvents_end =
			    (cb_args->cb_srvents_start + nserv_entries - 1);
			nserv_entries = 0;
		}
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*hdr))
		ibdm_fill_srv_attr_mod(hdr, cb_args);
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*hdr))

		mutex_enter(&gid_info->gl_mutex);
		ioc_info->ioc_serv[srv_start].se_timeout_id = timeout(
		    ibdm_pkt_timeout_hdlr, cb_args,
		    IBDM_TIMEOUT_VALUE(ibdm_dft_timeout));
		mutex_exit(&gid_info->gl_mutex);

		IBTF_DPRINTF_L5("ibdm", "\thandle_ioc_profile:"
		    "timeout %x, ioc %d srv %d",
		    ioc_info->ioc_serv[srv_start].se_timeout_id,
		    ioc_no - 1, srv_start);

		if (ibmf_msg_transport(ibmf_hdl, gid_info->gl_qp_hdl, msg,
		    NULL, ibdm_ibmf_send_cb, cb_args, 0) != IBMF_SUCCESS) {
			IBTF_DPRINTF_L2("ibdm",
			    "\thandle_ioc_profile: msg send failed");
			ibdm_ibmf_send_cb(ibmf_hdl, msg, cb_args);
		}
		(*flag) |= IBDM_IBMF_PKT_REUSED;
		first = B_FALSE;
		ii++;
	}
}


/*
 * ibdm_handle_srventry_mad()
 */
static void
ibdm_handle_srventry_mad(ibmf_msg_t *msg,
    ibdm_dp_gidinfo_t *gid_info, int *flag)
{
	uint_t			ii, ioc_no, attrmod;
	uint_t			nentries, start, end;
	timeout_id_t		timeout_id;
	ib_dm_srv_t		*srv_ents;
	ibdm_ioc_info_t		*ioc_info;
	ibdm_srvents_info_t	*gsrv_ents;

	IBTF_DPRINTF_L4("ibdm", "\thandle_srventry_mad:"
	    " IBMF msg %p gid info %p", msg, gid_info);

	srv_ents = IBDM_IN_IBMFMSG2SRVENT(msg);
	/*
	 * Get the start and end index of the service entries
	 * Upper 16 bits identify the IOC
	 * Lower 16 bits specify the range of service entries
	 * 	LSB specifies (Big endian) end of the range
	 * 	MSB specifies (Big endian) start of the range
	 */
	attrmod = IBDM_IN_IBMFMSG_ATTRMOD(msg);
	ioc_no	= ((attrmod >> 16) & IBDM_16_BIT_MASK);
	end	= ((attrmod >> 8) & IBDM_8_BIT_MASK);
	start	= (attrmod & IBDM_8_BIT_MASK);

	/* Make sure that IOC index is with the valid range */
	if ((ioc_no < 1) |
	    (ioc_no > gid_info->gl_iou->iou_info.iou_num_ctrl_slots)) {
		IBTF_DPRINTF_L2("ibdm", "\thandle_srventry_mad: "
		    "IOC index Out of range, index %d", ioc_no);
		(*flag) |= IBDM_IBMF_PKT_UNEXP_RESP;
		return;
	}
	ioc_info = IBDM_GIDINFO2IOCINFO(gid_info, (ioc_no -1));

	/*
	 * Make sure that the "start" and "end" service indexes are
	 * with in the valid range
	 */
	nentries = ioc_info->ioc_profile.ioc_service_entries;
	if ((start > end) | (start >= nentries) | (end >= nentries)) {
		IBTF_DPRINTF_L2("ibdm", "\thandle_srventry_mad: "
		    "Attr modifier 0x%x, #Serv entries %d", attrmod, nentries);
		(*flag) |= IBDM_IBMF_PKT_UNEXP_RESP;
		return;
	}
	gsrv_ents = &ioc_info->ioc_serv[start];
	mutex_enter(&gid_info->gl_mutex);
	if (gsrv_ents->se_state != IBDM_SE_INVALID) {
		IBTF_DPRINTF_L2("ibdm", "\thandle_srventry_mad: "
		    "already known, ioc %d, srv %d, se_state %x",
		    ioc_no - 1, start, gsrv_ents->se_state);
		mutex_exit(&gid_info->gl_mutex);
		(*flag) |= IBDM_IBMF_PKT_DUP_RESP;
		return;
	}
	ioc_info->ioc_serv[start].se_cb_args.cb_req_type = 0;
	if (ioc_info->ioc_serv[start].se_timeout_id) {
		IBTF_DPRINTF_L2("ibdm",
		    "\thandle_srventry_mad: ioc %d start %d", ioc_no, start);
		timeout_id = ioc_info->ioc_serv[start].se_timeout_id;
		ioc_info->ioc_serv[start].se_timeout_id = 0;
		mutex_exit(&gid_info->gl_mutex);
		IBTF_DPRINTF_L5("ibdm", "handle_srverntry_mad: "
		    "se_timeout_id = 0x%x", timeout_id);
		if (untimeout(timeout_id) == -1) {
			IBTF_DPRINTF_L2("ibdm", "handle_srventry_mad: "
			    "untimeout se_timeout_id failed");
		}
		mutex_enter(&gid_info->gl_mutex);
	}

	gsrv_ents->se_state = IBDM_SE_VALID;
	mutex_exit(&gid_info->gl_mutex);
	for (ii = start; ii <= end; ii++, srv_ents++, gsrv_ents++) {
		gsrv_ents->se_attr.srv_id = b2h64(srv_ents->srv_id);
		bcopy(srv_ents->srv_name,
		    gsrv_ents->se_attr.srv_name, IB_DM_MAX_SVC_NAME_LEN);
		ibdm_dump_service_entries(&gsrv_ents->se_attr);
	}
}


/*
 * ibdm_get_diagcode:
 *	Send request to get IOU/IOC diag code
 *	Returns IBDM_SUCCESS/IBDM_FAILURE
 */
static int
ibdm_get_diagcode(ibdm_dp_gidinfo_t *gid_info, int attr)
{
	ibmf_msg_t		*msg;
	ib_mad_hdr_t		*hdr;
	ibdm_ioc_info_t		*ioc;
	ibdm_timeout_cb_args_t	*cb_args;
	timeout_id_t		*timeout_id;

	IBTF_DPRINTF_L4("ibdm", "\tget_diagcode: gid info %p, attr = %d",
	    gid_info, attr);

	if (ibmf_alloc_msg(gid_info->gl_ibmf_hdl, IBMF_ALLOC_SLEEP,
	    &msg) != IBMF_SUCCESS) {
		IBTF_DPRINTF_L4("ibdm", "\tget_diagcode: pkt alloc fail");
		return (IBDM_FAILURE);
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*msg))
	ibdm_alloc_send_buffers(msg);
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*msg))

	mutex_enter(&gid_info->gl_mutex);
	ibdm_bump_transactionID(gid_info);
	mutex_exit(&gid_info->gl_mutex);

	msg->im_local_addr.ia_local_lid	= gid_info->gl_slid;
	msg->im_local_addr.ia_remote_lid	= gid_info->gl_dlid;
	if (gid_info->gl_redirected == B_TRUE) {
		if (gid_info->gl_redirect_dlid != 0) {
			msg->im_local_addr.ia_remote_lid =
			    gid_info->gl_redirect_dlid;
		}

		msg->im_local_addr.ia_remote_qno = gid_info->gl_redirect_QP;
		msg->im_local_addr.ia_p_key = gid_info->gl_redirect_pkey;
		msg->im_local_addr.ia_q_key = gid_info->gl_redirect_qkey;
		msg->im_local_addr.ia_service_level = gid_info->gl_redirectSL;
	} else {
		msg->im_local_addr.ia_remote_qno = 1;
		msg->im_local_addr.ia_p_key = gid_info->gl_p_key;
		msg->im_local_addr.ia_q_key = IB_GSI_QKEY;
		msg->im_local_addr.ia_service_level = gid_info->gl_SL;
	}

	hdr			= IBDM_OUT_IBMFMSG_MADHDR(msg);
	hdr->BaseVersion	= MAD_CLASS_BASE_VERS_1;
	hdr->MgmtClass		= MAD_MGMT_CLASS_DEV_MGT;
	hdr->ClassVersion	= IB_DM_CLASS_VERSION_1;
	hdr->R_Method		= IB_DM_DEVMGT_METHOD_GET;
	hdr->Status		= 0;
	hdr->TransactionID	= h2b64(gid_info->gl_transactionID);

	hdr->AttributeID	= h2b16(IB_DM_ATTR_DIAG_CODE);
	hdr->AttributeModifier	= h2b32(attr);

	if (attr == 0) {
		cb_args = &gid_info->gl_iou_cb_args;
		gid_info->gl_iou->iou_dc_valid = B_FALSE;
		cb_args->cb_ioc_num	= 0;
		cb_args->cb_req_type	= IBDM_REQ_TYPE_IOU_DIAGCODE;
		timeout_id = &gid_info->gl_timeout_id;
	} else {
		ioc = IBDM_GIDINFO2IOCINFO(gid_info, (attr - 1));
		ioc->ioc_dc_valid = B_FALSE;
		cb_args = &ioc->ioc_dc_cb_args;
		cb_args->cb_ioc_num	= attr - 1;
		cb_args->cb_req_type	= IBDM_REQ_TYPE_IOC_DIAGCODE;
		timeout_id = &ioc->ioc_dc_timeout_id;
	}
	cb_args->cb_gid_info	= gid_info;
	cb_args->cb_retry_count	= ibdm_dft_retry_cnt;
	cb_args->cb_srvents_start = 0;

	mutex_enter(&gid_info->gl_mutex);
	*timeout_id = timeout(ibdm_pkt_timeout_hdlr,
	    cb_args, IBDM_TIMEOUT_VALUE(ibdm_dft_timeout));
	mutex_exit(&gid_info->gl_mutex);

	IBTF_DPRINTF_L5("ibdm", "\tget_diagcode:"
	    "timeout %x, ioc %d", *timeout_id, cb_args->cb_ioc_num);

	if (ibmf_msg_transport(gid_info->gl_ibmf_hdl, gid_info->gl_qp_hdl,
	    msg, NULL, ibdm_ibmf_send_cb, cb_args, 0) != IBMF_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm", "\tget_diagcode: ibmf send failed");
		ibdm_ibmf_send_cb(gid_info->gl_ibmf_hdl, msg, cb_args);
	}
	return (IBDM_SUCCESS);
}

/*
 * ibdm_handle_diagcode:
 *	Process the DiagCode MAD response and update local DM
 *	data structure.
 */
static void
ibdm_handle_diagcode(ibmf_msg_t *ibmf_msg,
    ibdm_dp_gidinfo_t *gid_info, int *flag)
{
	uint16_t	attrmod, *diagcode;
	ibdm_iou_info_t	*iou;
	ibdm_ioc_info_t	*ioc;
	timeout_id_t	timeout_id;
	ibdm_timeout_cb_args_t	*cb_args;

	diagcode = (uint16_t *)ibmf_msg->im_msgbufs_recv.im_bufs_cl_data;

	mutex_enter(&gid_info->gl_mutex);
	attrmod = IBDM_IN_IBMFMSG_ATTRMOD(ibmf_msg);
	iou = gid_info->gl_iou;
	if (attrmod == 0) {
		if (iou->iou_dc_valid != B_FALSE) {
			(*flag) |= IBDM_IBMF_PKT_DUP_RESP;
			IBTF_DPRINTF_L4("ibdm",
			    "\thandle_diagcode: Duplicate IOU DiagCode");
			mutex_exit(&gid_info->gl_mutex);
			return;
		}
		cb_args = &gid_info->gl_iou_cb_args;
		cb_args->cb_req_type = 0;
		iou->iou_diagcode = b2h16(*diagcode);
		iou->iou_dc_valid = B_TRUE;
		if (gid_info->gl_timeout_id) {
			timeout_id = gid_info->gl_timeout_id;
			mutex_exit(&gid_info->gl_mutex);
			IBTF_DPRINTF_L5("ibdm", "\thandle_diagcode: "
			    "gl_timeout_id = 0x%x", timeout_id);
			if (untimeout(timeout_id) == -1) {
				IBTF_DPRINTF_L2("ibdm", "handle_diagcode: "
				    "untimeout gl_timeout_id failed");
			}
			mutex_enter(&gid_info->gl_mutex);
			gid_info->gl_timeout_id = 0;
		}
	} else {
		ioc = IBDM_GIDINFO2IOCINFO(gid_info, (attrmod - 1));
		if (ioc->ioc_dc_valid != B_FALSE) {
			(*flag) |= IBDM_IBMF_PKT_DUP_RESP;
			IBTF_DPRINTF_L4("ibdm",
			    "\thandle_diagcode: Duplicate IOC DiagCode");
			mutex_exit(&gid_info->gl_mutex);
			return;
		}
		cb_args = &ioc->ioc_dc_cb_args;
		cb_args->cb_req_type = 0;
		ioc->ioc_diagcode = b2h16(*diagcode);
		ioc->ioc_dc_valid = B_TRUE;
		timeout_id = iou->iou_ioc_info[attrmod - 1].ioc_dc_timeout_id;
		if (timeout_id) {
			iou->iou_ioc_info[attrmod - 1].ioc_dc_timeout_id = 0;
			mutex_exit(&gid_info->gl_mutex);
			IBTF_DPRINTF_L5("ibdm", "handle_diagcode: "
			    "timeout_id = 0x%x", timeout_id);
			if (untimeout(timeout_id) == -1) {
				IBTF_DPRINTF_L2("ibdm", "\thandle_diagcode: "
				    "untimeout ioc_dc_timeout_id failed");
			}
			mutex_enter(&gid_info->gl_mutex);
		}
	}
	mutex_exit(&gid_info->gl_mutex);

	IBTF_DPRINTF_L4("ibdm", "\thandle_diagcode: DiagCode : 0x%x"
	    "attrmod : 0x%x", b2h16(*diagcode), attrmod);
}


/*
 * ibdm_is_ioc_present()
 *	Return ibdm_ioc_info_t if IOC guid is found in the global gid list
 */
static ibdm_ioc_info_t *
ibdm_is_ioc_present(ib_guid_t ioc_guid,
    ibdm_dp_gidinfo_t *gid_info, int *flag)
{
	int				ii;
	ibdm_ioc_info_t			*ioc;
	ibdm_dp_gidinfo_t		*head;
	ib_dm_io_unitinfo_t		*iou;

	mutex_enter(&ibdm.ibdm_mutex);
	head = ibdm.ibdm_dp_gidlist_head;
	while (head) {
		mutex_enter(&head->gl_mutex);
		if (head->gl_iou == NULL) {
			mutex_exit(&head->gl_mutex);
			head = head->gl_next;
			continue;
		}
		iou = &head->gl_iou->iou_info;
		for (ii = 0; ii < iou->iou_num_ctrl_slots; ii++) {
			ioc = IBDM_GIDINFO2IOCINFO(head, ii);
			if ((ioc->ioc_state == IBDM_IOC_STATE_PROBE_SUCCESS) &&
			    (ioc->ioc_profile.ioc_guid == ioc_guid)) {
				if (gid_info == head) {
					*flag |= IBDM_IBMF_PKT_DUP_RESP;
				} else if (ibdm_check_dgid(head->gl_dgid_lo,
				    head->gl_dgid_hi) != NULL) {
					IBTF_DPRINTF_L4("ibdm", "\tis_ioc_"
					    "present: gid not present");
					ibdm_add_to_gl_gid(gid_info, head);
				}
				mutex_exit(&head->gl_mutex);
				mutex_exit(&ibdm.ibdm_mutex);
				return (ioc);
			}
		}
		mutex_exit(&head->gl_mutex);
		head = head->gl_next;
	}
	mutex_exit(&ibdm.ibdm_mutex);
	return (NULL);
}


/*
 * ibdm_ibmf_send_cb()
 *	IBMF invokes this callback routine after posting the DM MAD to
 *	the HCA.
 */
/*ARGSUSED*/
static void
ibdm_ibmf_send_cb(ibmf_handle_t ibmf_hdl, ibmf_msg_t *ibmf_msg, void *arg)
{
	ibdm_dump_ibmf_msg(ibmf_msg, 1);
	ibdm_free_send_buffers(ibmf_msg);
	if (ibmf_free_msg(ibmf_hdl, &ibmf_msg) != IBMF_SUCCESS) {
		IBTF_DPRINTF_L4("ibdm",
		    "\tibmf_send_cb: IBMF free msg failed");
	}
}


/*
 * ibdm_ibmf_recv_cb()
 *	Invoked by the IBMF when a response to the one of the DM requests
 *	is received.
 */
/*ARGSUSED*/
static void
ibdm_ibmf_recv_cb(ibmf_handle_t ibmf_hdl, ibmf_msg_t *msg, void *arg)
{
	ibdm_taskq_args_t	*taskq_args;

	/*
	 * If the taskq enable is set then dispatch a taskq to process
	 * the MAD, otherwise just process it on this thread
	 */
	if (ibdm_taskq_enable != IBDM_ENABLE_TASKQ_HANDLING) {
		ibdm_process_incoming_mad(ibmf_hdl, msg, arg);
		return;
	}

	/*
	 * create a taskq and dispatch it to process the incoming MAD
	 */
	taskq_args = kmem_alloc(sizeof (ibdm_taskq_args_t), KM_NOSLEEP);
	if (taskq_args == NULL) {
		IBTF_DPRINTF_L2("ibdm", "ibmf_recv_cb: kmem_alloc failed for"
		    "taskq_args");
		if (ibmf_free_msg(ibmf_hdl, &msg) != IBMF_SUCCESS) {
			IBTF_DPRINTF_L4("ibmf_recv_cb",
			    "\tibmf_recv_cb: IBMF free msg failed");
		}
		return;
	}
	taskq_args->tq_ibmf_handle = ibmf_hdl;
	taskq_args->tq_ibmf_msg = msg;
	taskq_args->tq_args = arg;

	if (taskq_dispatch(system_taskq, ibdm_recv_incoming_mad, taskq_args,
	    TQ_NOSLEEP) == 0) {
		IBTF_DPRINTF_L2("ibdm", "ibmf_recv_cb: taskq_dispatch failed");
		if (ibmf_free_msg(ibmf_hdl, &msg) != IBMF_SUCCESS) {
			IBTF_DPRINTF_L4("ibmf_recv_cb",
			    "\tibmf_recv_cb: IBMF free msg failed");
		}
		kmem_free(taskq_args, sizeof (ibdm_taskq_args_t));
		return;
	}

	/* taskq_args are deleted in ibdm_recv_incoming_mad() */
}


void
ibdm_recv_incoming_mad(void *args)
{
	ibdm_taskq_args_t	*taskq_args;

	taskq_args = (ibdm_taskq_args_t *)args;

	IBTF_DPRINTF_L4("ibdm", "\tibdm_recv_incoming_mad: "
	    "Processing incoming MAD via taskq");

	ibdm_process_incoming_mad(taskq_args->tq_ibmf_handle,
	    taskq_args->tq_ibmf_msg, taskq_args->tq_args);

	kmem_free(taskq_args, sizeof (ibdm_taskq_args_t));
}


/*
 * Calls ibdm_process_incoming_mad with all function arguments  extracted
 * from args
 */
/*ARGSUSED*/
static void
ibdm_process_incoming_mad(ibmf_handle_t ibmf_hdl, ibmf_msg_t *msg, void *arg)
{
	int			flag = 0;
	int			ret;
	uint64_t		transaction_id;
	ib_mad_hdr_t		*hdr;
	ibdm_dp_gidinfo_t	*gid_info = NULL;

	IBTF_DPRINTF_L4("ibdm",
	    "\tprocess_incoming_mad: ibmf hdl %p pkt %p", ibmf_hdl, msg);
	ibdm_dump_ibmf_msg(msg, 0);

	/*
	 * IBMF calls this routine for every DM MAD that arrives at this port.
	 * But we handle only the responses for requests we sent. We drop all
	 * the DM packets that does not have response bit set in the MAD
	 * header(this eliminates all the requests sent to this port).
	 * We handle only DM class version 1 MAD's
	 */
	hdr = IBDM_IN_IBMFMSG_MADHDR(msg);
	if (ibdm_verify_mad_status(hdr) != IBDM_SUCCESS) {
		if (ibmf_free_msg(ibmf_hdl, &msg) != IBMF_SUCCESS) {
			IBTF_DPRINTF_L2("ibdm", "\tprocess_incoming_mad: "
			    "IBMF free msg failed DM request drop it");
		}
		return;
	}

	transaction_id = b2h64(hdr->TransactionID);

	mutex_enter(&ibdm.ibdm_mutex);
	gid_info = ibdm.ibdm_dp_gidlist_head;
	while (gid_info) {
		if ((gid_info->gl_transactionID  &
		    IBDM_GID_TRANSACTIONID_MASK) ==
		    (transaction_id & IBDM_GID_TRANSACTIONID_MASK))
			break;
		gid_info = gid_info->gl_next;
	}
	mutex_exit(&ibdm.ibdm_mutex);

	if (gid_info == NULL) {
		/* Drop the packet */
		IBTF_DPRINTF_L2("ibdm", "process_incoming_mad: transaction ID"
		    " does not match: 0x%llx", transaction_id);
		if (ibmf_free_msg(ibmf_hdl, &msg) != IBMF_SUCCESS) {
			IBTF_DPRINTF_L2("ibdm", "process_incoming_mad: "
			    "IBMF free msg failed DM request drop it");
		}
		return;
	}

	/* Handle redirection for all the MAD's, except ClassPortInfo */
	if (((IBDM_IN_IBMFMSG_STATUS(msg) & MAD_STATUS_REDIRECT_REQUIRED)) &&
	    (IBDM_IN_IBMFMSG_ATTR(msg) != IB_DM_ATTR_CLASSPORTINFO)) {
		ret = ibdm_handle_redirection(msg, gid_info, &flag);
		if (ret == IBDM_SUCCESS) {
			return;
		}
	} else {
		uint_t gl_state;

		mutex_enter(&gid_info->gl_mutex);
		gl_state = gid_info->gl_state;
		mutex_exit(&gid_info->gl_mutex);

		switch (gl_state) {

		case IBDM_SET_CLASSPORTINFO:
			ibdm_handle_setclassportinfo(
			    ibmf_hdl, msg, gid_info, &flag);
			break;

		case IBDM_GET_CLASSPORTINFO:
			ibdm_handle_classportinfo(
			    ibmf_hdl, msg, gid_info, &flag);
			break;

		case IBDM_GET_IOUNITINFO:
			ibdm_handle_iounitinfo(ibmf_hdl, msg, gid_info, &flag);
			break;

		case IBDM_GET_IOC_DETAILS:
			switch (IBDM_IN_IBMFMSG_ATTR(msg)) {

			case IB_DM_ATTR_SERVICE_ENTRIES:
				ibdm_handle_srventry_mad(msg, gid_info, &flag);
				break;

			case IB_DM_ATTR_IOC_CTRL_PROFILE:
				ibdm_handle_ioc_profile(
				    ibmf_hdl, msg, gid_info, &flag);
				break;

			case IB_DM_ATTR_DIAG_CODE:
				ibdm_handle_diagcode(msg, gid_info, &flag);
				break;

			default:
				IBTF_DPRINTF_L2("ibdm", "process_incoming_mad: "
				    "Error state, wrong attribute :-(");
				(void) ibmf_free_msg(ibmf_hdl, &msg);
				return;
			}
			break;
		default:
			IBTF_DPRINTF_L2("ibdm",
			    "process_incoming_mad: Dropping the packet"
			    " gl_state %x", gl_state);
			if (ibmf_free_msg(ibmf_hdl, &msg) != IBMF_SUCCESS) {
				IBTF_DPRINTF_L2("ibdm", "process_incoming_mad: "
				    "IBMF free msg failed DM request drop it");
			}
			return;
		}
	}

	if ((flag & IBDM_IBMF_PKT_DUP_RESP) ||
	    (flag & IBDM_IBMF_PKT_UNEXP_RESP)) {
		IBTF_DPRINTF_L2("ibdm",
		    "\tprocess_incoming_mad:Dup/unexp resp : 0x%x", flag);
		if (ibmf_free_msg(ibmf_hdl, &msg) != IBMF_SUCCESS) {
			IBTF_DPRINTF_L2("ibdm", "process_incoming_mad: "
			    "IBMF free msg failed DM request drop it");
		}
		return;
	}

	mutex_enter(&gid_info->gl_mutex);
	if (gid_info->gl_pending_cmds < 1) {
		IBTF_DPRINTF_L2("ibdm",
		    "\tprocess_incoming_mad: pending commands negative");
	}
	if (--gid_info->gl_pending_cmds) {
		IBTF_DPRINTF_L4("ibdm", "\tprocess_incoming_mad: "
		    "gid_info %p pending cmds %d",
		    gid_info, gid_info->gl_pending_cmds);
		mutex_exit(&gid_info->gl_mutex);
	} else {
		uint_t prev_state;
		IBTF_DPRINTF_L4("ibdm", "\tprocess_incoming_mad: Probing DONE");
		prev_state = gid_info->gl_state;
		gid_info->gl_state = IBDM_GID_PROBING_COMPLETE;
		if (prev_state == IBDM_SET_CLASSPORTINFO) {
			IBTF_DPRINTF_L4("ibdm",
			    "\tprocess_incoming_mad: "
			    "Setclassportinfo for Cisco FC GW is done.");
			gid_info->gl_flag &= ~IBDM_CISCO_PROBE;
			gid_info->gl_flag |= IBDM_CISCO_PROBE_DONE;
			mutex_exit(&gid_info->gl_mutex);
			cv_broadcast(&gid_info->gl_probe_cv);
		} else {
			mutex_exit(&gid_info->gl_mutex);
			ibdm_notify_newgid_iocs(gid_info);
			mutex_enter(&ibdm.ibdm_mutex);
			if (--ibdm.ibdm_ngid_probes_in_progress == 0) {
				IBTF_DPRINTF_L4("ibdm",
				    "\tprocess_incoming_mad: Wakeup");
				ibdm.ibdm_busy &= ~IBDM_PROBE_IN_PROGRESS;
				cv_broadcast(&ibdm.ibdm_probe_cv);
			}
			mutex_exit(&ibdm.ibdm_mutex);
		}
	}

	/*
	 * Do not deallocate the IBMF packet if atleast one request
	 * is posted. IBMF packet is reused.
	 */
	if (!(flag & IBDM_IBMF_PKT_REUSED)) {
		if (ibmf_free_msg(ibmf_hdl, &msg) != IBMF_SUCCESS) {
			IBTF_DPRINTF_L2("ibdm", "\tprocess_incoming_mad: "
			    "IBMF free msg failed DM request drop it");
		}
	}
}


/*
 * ibdm_verify_mad_status()
 *	Verifies the MAD status
 *	Returns IBDM_SUCCESS if status is correct
 *	Returns IBDM_FAILURE for bogus MAD status
 */
static int
ibdm_verify_mad_status(ib_mad_hdr_t *hdr)
{
	int	ret = 0;

	if ((hdr->R_Method != IB_DM_DEVMGT_METHOD_GET_RESP) ||
	    (hdr->ClassVersion != IB_DM_CLASS_VERSION_1)) {
		return (IBDM_FAILURE);
	}

	if (b2h16(hdr->Status) == 0)
		ret = IBDM_SUCCESS;
	else if ((b2h16(hdr->Status) & 0x1f) == MAD_STATUS_REDIRECT_REQUIRED)
		ret = IBDM_SUCCESS;
	else {
		IBTF_DPRINTF_L2("ibdm",
		    "\tverify_mad_status: Status : 0x%x", b2h16(hdr->Status));
		ret = IBDM_FAILURE;
	}
	return (ret);
}



/*
 * ibdm_handle_redirection()
 *	Returns IBDM_SUCCESS/IBDM_FAILURE
 */
static int
ibdm_handle_redirection(ibmf_msg_t *msg,
    ibdm_dp_gidinfo_t *gid_info, int *flag)
{
	int			attrmod, ioc_no, start;
	void			*data;
	timeout_id_t		*timeout_id;
	ib_mad_hdr_t		*hdr;
	ibdm_ioc_info_t		*ioc = NULL;
	ibdm_timeout_cb_args_t	*cb_args;
	ib_mad_classportinfo_t	*cpi;

	IBTF_DPRINTF_L4("ibdm", "\thandle_redirection: Enter");
	mutex_enter(&gid_info->gl_mutex);
	switch (gid_info->gl_state) {
	case IBDM_GET_IOUNITINFO:
		cb_args		= &gid_info->gl_iou_cb_args;
		timeout_id	= &gid_info->gl_timeout_id;
		break;

	case IBDM_GET_IOC_DETAILS:
		attrmod	= IBDM_IN_IBMFMSG_ATTRMOD(msg);
		switch (IBDM_IN_IBMFMSG_ATTR(msg)) {

		case IB_DM_ATTR_DIAG_CODE:
			if (attrmod == 0) {
				cb_args = &gid_info->gl_iou_cb_args;
				timeout_id = &gid_info->gl_timeout_id;
				break;
			}
			if (IBDM_IS_IOC_NUM_INVALID(attrmod, gid_info)) {
				IBTF_DPRINTF_L2("ibdm", "\thandle_redirction:"
				    "IOC# Out of range %d", attrmod);
				(*flag) |= IBDM_IBMF_PKT_UNEXP_RESP;
				mutex_exit(&gid_info->gl_mutex);
				return (IBDM_FAILURE);
			}
			ioc	= IBDM_GIDINFO2IOCINFO(gid_info, (attrmod -1));
			cb_args = &ioc->ioc_dc_cb_args;
			timeout_id = &ioc->ioc_dc_timeout_id;
			break;

		case IB_DM_ATTR_IOC_CTRL_PROFILE:
			if (IBDM_IS_IOC_NUM_INVALID(attrmod, gid_info)) {
				IBTF_DPRINTF_L2("ibdm", "\thandle_redirction:"
				    "IOC# Out of range %d", attrmod);
				(*flag) |= IBDM_IBMF_PKT_UNEXP_RESP;
				mutex_exit(&gid_info->gl_mutex);
				return (IBDM_FAILURE);
			}
			ioc	= IBDM_GIDINFO2IOCINFO(gid_info, (attrmod -1));
			cb_args = &ioc->ioc_cb_args;
			timeout_id = &ioc->ioc_timeout_id;
			break;

		case IB_DM_ATTR_SERVICE_ENTRIES:
			ioc_no	= ((attrmod >> 16) & IBDM_16_BIT_MASK);
			if (IBDM_IS_IOC_NUM_INVALID(ioc_no, gid_info)) {
				IBTF_DPRINTF_L2("ibdm", "\thandle_redirction:"
				    "IOC# Out of range %d", ioc_no);
				(*flag) |= IBDM_IBMF_PKT_UNEXP_RESP;
				mutex_exit(&gid_info->gl_mutex);
				return (IBDM_FAILURE);
			}
			start 	= (attrmod & IBDM_8_BIT_MASK);
			ioc	= IBDM_GIDINFO2IOCINFO(gid_info, (ioc_no -1));
			if (start > ioc->ioc_profile.ioc_service_entries) {
				IBTF_DPRINTF_L2("ibdm", "\thandle_redirction:"
				    " SE index Out of range %d", start);
				(*flag) |= IBDM_IBMF_PKT_UNEXP_RESP;
				mutex_exit(&gid_info->gl_mutex);
				return (IBDM_FAILURE);
			}
			cb_args = &ioc->ioc_serv[start].se_cb_args;
			timeout_id = &ioc->ioc_serv[start].se_timeout_id;
			break;

		default:
			/* ERROR State */
			IBTF_DPRINTF_L2("ibdm",
			    "\thandle_redirection: wrong attribute :-(");
			(*flag) |= IBDM_IBMF_PKT_UNEXP_RESP;
			mutex_exit(&gid_info->gl_mutex);
			return (IBDM_FAILURE);
		}
		break;
	default:
		/* ERROR State */
		IBTF_DPRINTF_L2("ibdm",
		    "\thandle_redirection: Error state :-(");
		(*flag) |= IBDM_IBMF_PKT_UNEXP_RESP;
		mutex_exit(&gid_info->gl_mutex);
		return (IBDM_FAILURE);
	}
	if ((*timeout_id) != 0) {
		mutex_exit(&gid_info->gl_mutex);
		if (untimeout(*timeout_id) == -1) {
			IBTF_DPRINTF_L2("ibdm", "\thandle_redirection: "
			    "untimeout failed %x", *timeout_id);
		} else {
			IBTF_DPRINTF_L5("ibdm",
			    "\thandle_redirection: timeout %x", *timeout_id);
		}
		mutex_enter(&gid_info->gl_mutex);
		*timeout_id = 0;
	}

	data = msg->im_msgbufs_recv.im_bufs_cl_data;
	cpi = (ib_mad_classportinfo_t *)data;

	gid_info->gl_resp_timeout	=
	    (b2h32(cpi->RespTimeValue) & 0x1F);

	gid_info->gl_redirected		= B_TRUE;
	gid_info->gl_redirect_dlid	= b2h16(cpi->RedirectLID);
	gid_info->gl_redirect_QP	= (b2h32(cpi->RedirectQP) & 0xffffff);
	gid_info->gl_redirect_pkey	= b2h16(cpi->RedirectP_Key);
	gid_info->gl_redirect_qkey	= b2h32(cpi->RedirectQ_Key);
	gid_info->gl_redirectGID_hi	= b2h64(cpi->RedirectGID_hi);
	gid_info->gl_redirectGID_lo	= b2h64(cpi->RedirectGID_lo);
	gid_info->gl_redirectSL		= cpi->RedirectSL;

	if (gid_info->gl_redirect_dlid != 0) {
		msg->im_local_addr.ia_remote_lid =
		    gid_info->gl_redirect_dlid;
	}
	ibdm_bump_transactionID(gid_info);
	mutex_exit(&gid_info->gl_mutex);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*msg, *hdr))
	ibdm_alloc_send_buffers(msg);

	hdr			= IBDM_OUT_IBMFMSG_MADHDR(msg);
	hdr->BaseVersion	= MAD_CLASS_BASE_VERS_1;
	hdr->MgmtClass		= MAD_MGMT_CLASS_DEV_MGT;
	hdr->ClassVersion	= IB_DM_CLASS_VERSION_1;
	hdr->R_Method		= IB_DM_DEVMGT_METHOD_GET;
	hdr->Status		= 0;
	hdr->TransactionID	= h2b64(gid_info->gl_transactionID);
	hdr->AttributeID	=
	    msg->im_msgbufs_recv.im_bufs_mad_hdr->AttributeID;
	hdr->AttributeModifier	=
	    msg->im_msgbufs_recv.im_bufs_mad_hdr->AttributeModifier;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*msg, *hdr))

	msg->im_local_addr.ia_remote_qno = gid_info->gl_redirect_QP;
	msg->im_local_addr.ia_p_key = gid_info->gl_redirect_pkey;
	msg->im_local_addr.ia_q_key = gid_info->gl_redirect_qkey;
	msg->im_local_addr.ia_service_level = gid_info->gl_redirectSL;

	mutex_enter(&gid_info->gl_mutex);
	*timeout_id = timeout(ibdm_pkt_timeout_hdlr,
	    cb_args, IBDM_TIMEOUT_VALUE(ibdm_dft_timeout));
	mutex_exit(&gid_info->gl_mutex);

	IBTF_DPRINTF_L5("ibdm", "\thandle_redirect:"
	    "timeout %x", *timeout_id);

	if (ibmf_msg_transport(gid_info->gl_ibmf_hdl, gid_info->gl_qp_hdl,
	    msg, NULL, ibdm_ibmf_send_cb, cb_args, 0) != IBMF_SUCCESS) {
		IBTF_DPRINTF_L4("ibdm", "\thandle_redirection:"
		    "message transport failed");
		ibdm_ibmf_send_cb(gid_info->gl_ibmf_hdl, msg, cb_args);
	}
	(*flag) |= IBDM_IBMF_PKT_REUSED;
	IBTF_DPRINTF_L4("ibdm", "\thandle_redirection: Exit");
	return (IBDM_SUCCESS);
}


/*
 * ibdm_pkt_timeout_hdlr
 *	This  timeout  handler is  registed for every  IBMF  packet that is
 *	sent through the IBMF.  It gets called when no response is received
 *	within the specified time for the packet. No retries for the failed
 *	commands  currently.  Drops the failed  IBMF packet and  update the
 *	pending list commands.
 */
static void
ibdm_pkt_timeout_hdlr(void *arg)
{
	ibdm_iou_info_t		*iou;
	ibdm_ioc_info_t		*ioc;
	ibdm_timeout_cb_args_t	*cb_args = arg;
	ibdm_dp_gidinfo_t	*gid_info;
	int			srv_ent;
	uint_t			new_gl_state;

	IBTF_DPRINTF_L2("ibdm", "\tpkt_timeout_hdlr: gid_info: %p "
	    "rtype 0x%x iocidx 0x%x srvidx %d", cb_args->cb_gid_info,
	    cb_args->cb_req_type, cb_args->cb_ioc_num,
	    cb_args->cb_srvents_start);

	gid_info = cb_args->cb_gid_info;
	mutex_enter(&gid_info->gl_mutex);

	if ((gid_info->gl_state == IBDM_GID_PROBING_COMPLETE) ||
	    (cb_args->cb_req_type == 0)) {

		IBTF_DPRINTF_L2("ibdm", "\tpkt_timeout_hdlr: req completed"
		    "rtype 0x%x iocidx 0x%x srvidx %d", cb_args->cb_req_type,
		    cb_args->cb_ioc_num, cb_args->cb_srvents_start);

		if (gid_info->gl_timeout_id)
			gid_info->gl_timeout_id = 0;
		mutex_exit(&gid_info->gl_mutex);
		return;
	}
	if (cb_args->cb_retry_count) {
		cb_args->cb_retry_count--;
		/*
		 * A new timeout_id is set inside ibdm_retry_command().
		 * When the function returns an error, the timeout_id
		 * is reset (to zero) in the switch statement below.
		 */
		if (ibdm_retry_command(cb_args) == IBDM_SUCCESS) {
			mutex_exit(&gid_info->gl_mutex);
			return;
		}
		cb_args->cb_retry_count = 0;
	}

	IBTF_DPRINTF_L2("ibdm", "\tpkt_timeout_hdlr: command failed: gid %p"
	    " rtype 0x%x iocidx 0x%x srvidx %d", cb_args->cb_gid_info,
	    cb_args->cb_req_type, cb_args->cb_ioc_num,
	    cb_args->cb_srvents_start);

	switch (cb_args->cb_req_type) {

	case IBDM_REQ_TYPE_CLASSPORTINFO:
	case IBDM_REQ_TYPE_IOUINFO:
		new_gl_state = IBDM_GID_PROBING_FAILED;
		if (gid_info->gl_timeout_id)
			gid_info->gl_timeout_id = 0;
		break;

	case IBDM_REQ_TYPE_IOCINFO:
		new_gl_state = IBDM_GID_PROBING_COMPLETE;
		iou = gid_info->gl_iou;
		ioc = &iou->iou_ioc_info[cb_args->cb_ioc_num];
		ioc->ioc_state = IBDM_IOC_STATE_PROBE_FAILED;
		if (ioc->ioc_timeout_id)
			ioc->ioc_timeout_id = 0;
		break;

	case IBDM_REQ_TYPE_SRVENTS:
		new_gl_state = IBDM_GID_PROBING_COMPLETE;
		iou = gid_info->gl_iou;
		ioc = &iou->iou_ioc_info[cb_args->cb_ioc_num];
		ioc->ioc_state = IBDM_IOC_STATE_PROBE_FAILED;
		srv_ent = cb_args->cb_srvents_start;
		if (ioc->ioc_serv[srv_ent].se_timeout_id)
			ioc->ioc_serv[srv_ent].se_timeout_id = 0;
		break;

	case IBDM_REQ_TYPE_IOU_DIAGCODE:
		new_gl_state = IBDM_GID_PROBING_COMPLETE;
		iou = gid_info->gl_iou;
		iou->iou_dc_valid = B_FALSE;
		if (gid_info->gl_timeout_id)
			gid_info->gl_timeout_id = 0;
		break;

	case IBDM_REQ_TYPE_IOC_DIAGCODE:
		new_gl_state = IBDM_GID_PROBING_COMPLETE;
		iou = gid_info->gl_iou;
		ioc = &iou->iou_ioc_info[cb_args->cb_ioc_num];
		ioc->ioc_dc_valid = B_FALSE;
		if (ioc->ioc_dc_timeout_id)
			ioc->ioc_dc_timeout_id = 0;
		break;

	default: /* ERROR State */
		new_gl_state = IBDM_GID_PROBING_FAILED;
		if (gid_info->gl_timeout_id)
			gid_info->gl_timeout_id = 0;
		IBTF_DPRINTF_L2("ibdm",
		    "\tpkt_timeout_hdlr: wrong request type.");
		break;
	}

	--gid_info->gl_pending_cmds; /* decrease the counter */

	if (gid_info->gl_pending_cmds == 0) {
		gid_info->gl_state = new_gl_state;
		mutex_exit(&gid_info->gl_mutex);
		/*
		 * Delete this gid_info if the gid probe fails.
		 */
		if (new_gl_state == IBDM_GID_PROBING_FAILED) {
			ibdm_delete_glhca_list(gid_info);
		}
		ibdm_notify_newgid_iocs(gid_info);
		mutex_enter(&ibdm.ibdm_mutex);
		if (--ibdm.ibdm_ngid_probes_in_progress == 0) {
			IBTF_DPRINTF_L4("ibdm", "\tpkt_timeout_hdlr: Wakeup");
			ibdm.ibdm_busy &= ~IBDM_PROBE_IN_PROGRESS;
			cv_broadcast(&ibdm.ibdm_probe_cv);
		}
		mutex_exit(&ibdm.ibdm_mutex);
	} else {
		/*
		 * Reset gl_pending_cmd if the extra timeout happens since
		 * gl_pending_cmd becomes negative as a result.
		 */
		if (gid_info->gl_pending_cmds < 0) {
			gid_info->gl_pending_cmds = 0;
			IBTF_DPRINTF_L2("ibdm",
			    "\tpkt_timeout_hdlr: extra timeout request."
			    " reset gl_pending_cmds");
		}
		mutex_exit(&gid_info->gl_mutex);
		/*
		 * Delete this gid_info if the gid probe fails.
		 */
		if (new_gl_state == IBDM_GID_PROBING_FAILED) {
			ibdm_delete_glhca_list(gid_info);
		}
	}
}


/*
 * ibdm_retry_command()
 *	Retries the failed command.
 *	Returns IBDM_FAILURE/IBDM_SUCCESS
 */
static int
ibdm_retry_command(ibdm_timeout_cb_args_t *cb_args)
{
	int			ret;
	ibmf_msg_t		*msg;
	ib_mad_hdr_t		*hdr;
	ibdm_dp_gidinfo_t	*gid_info = cb_args->cb_gid_info;
	timeout_id_t		*timeout_id;
	ibdm_ioc_info_t		*ioc;
	int			ioc_no;
	ASSERT(MUTEX_HELD(&gid_info->gl_mutex));

	IBTF_DPRINTF_L2("ibdm", "\tretry_command: gid_info: %p "
	    "rtype 0x%x iocidx 0x%x srvidx %d", cb_args->cb_gid_info,
	    cb_args->cb_req_type, cb_args->cb_ioc_num,
	    cb_args->cb_srvents_start);

	ret = ibmf_alloc_msg(gid_info->gl_ibmf_hdl, IBMF_ALLOC_NOSLEEP, &msg);


	/*
	 * Reset the gid if alloc_msg failed with BAD_HANDLE
	 * ibdm_reset_gidinfo reinits the gid_info
	 */
	if (ret == IBMF_BAD_HANDLE) {
		IBTF_DPRINTF_L3(ibdm_string, "\tretry_command: gid %p hdl bad",
		    gid_info);

		mutex_exit(&gid_info->gl_mutex);
		ibdm_reset_gidinfo(gid_info);
		mutex_enter(&gid_info->gl_mutex);

		/* Retry alloc */
		ret = ibmf_alloc_msg(gid_info->gl_ibmf_hdl, IBMF_ALLOC_NOSLEEP,
		    &msg);
	}

	if (ret != IBDM_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm", "\tretry_command: alloc failed: %p "
		    "rtype 0x%x iocidx 0x%x srvidx %d", cb_args->cb_gid_info,
		    cb_args->cb_req_type, cb_args->cb_ioc_num,
		    cb_args->cb_srvents_start);
		return (IBDM_FAILURE);
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*msg))
	ibdm_alloc_send_buffers(msg);
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*msg))

	ibdm_bump_transactionID(gid_info);

	msg->im_local_addr.ia_local_lid	= gid_info->gl_slid;
	msg->im_local_addr.ia_remote_lid	= gid_info->gl_dlid;
	if (gid_info->gl_redirected == B_TRUE) {
		if (gid_info->gl_redirect_dlid != 0) {
			msg->im_local_addr.ia_remote_lid =
			    gid_info->gl_redirect_dlid;
		}
		msg->im_local_addr.ia_remote_qno = gid_info->gl_redirect_QP;
		msg->im_local_addr.ia_p_key = gid_info->gl_redirect_pkey;
		msg->im_local_addr.ia_q_key = gid_info->gl_redirect_qkey;
		msg->im_local_addr.ia_service_level = gid_info->gl_redirectSL;
	} else {
		msg->im_local_addr.ia_remote_qno = 1;
		msg->im_local_addr.ia_p_key = gid_info->gl_p_key;
		msg->im_local_addr.ia_q_key = IB_GSI_QKEY;
		msg->im_local_addr.ia_service_level = gid_info->gl_SL;
	}
	hdr = IBDM_OUT_IBMFMSG_MADHDR(msg);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*hdr))
	hdr->BaseVersion	= MAD_CLASS_BASE_VERS_1;
	hdr->MgmtClass		= MAD_MGMT_CLASS_DEV_MGT;
	hdr->ClassVersion	= IB_DM_CLASS_VERSION_1;
	hdr->R_Method		= IB_DM_DEVMGT_METHOD_GET;
	hdr->Status		= 0;
	hdr->TransactionID	= h2b64(gid_info->gl_transactionID);

	switch (cb_args->cb_req_type) {
	case IBDM_REQ_TYPE_CLASSPORTINFO:
		hdr->AttributeID = h2b16(IB_DM_ATTR_CLASSPORTINFO);
		hdr->AttributeModifier = 0;
		timeout_id = &gid_info->gl_timeout_id;
		break;
	case IBDM_REQ_TYPE_IOUINFO:
		hdr->AttributeID = h2b16(IB_DM_ATTR_IO_UNITINFO);
		hdr->AttributeModifier = 0;
		timeout_id = &gid_info->gl_timeout_id;
		break;
	case IBDM_REQ_TYPE_IOCINFO:
		hdr->AttributeID = h2b16(IB_DM_ATTR_IOC_CTRL_PROFILE);
		hdr->AttributeModifier = h2b32(cb_args->cb_ioc_num + 1);
		ioc = IBDM_GIDINFO2IOCINFO(gid_info, cb_args->cb_ioc_num);
		timeout_id = &ioc->ioc_timeout_id;
		break;
	case IBDM_REQ_TYPE_SRVENTS:
		hdr->AttributeID = h2b16(IB_DM_ATTR_SERVICE_ENTRIES);
		ibdm_fill_srv_attr_mod(hdr, cb_args);
		ioc = IBDM_GIDINFO2IOCINFO(gid_info, cb_args->cb_ioc_num);
		timeout_id =
		    &ioc->ioc_serv[cb_args->cb_srvents_start].se_timeout_id;
		break;
	case IBDM_REQ_TYPE_IOU_DIAGCODE:
		hdr->AttributeID = h2b16(IB_DM_ATTR_DIAG_CODE);
		hdr->AttributeModifier = 0;
		timeout_id = &gid_info->gl_timeout_id;
		break;
	case IBDM_REQ_TYPE_IOC_DIAGCODE:
		hdr->AttributeID = h2b16(IB_DM_ATTR_DIAG_CODE);
		hdr->AttributeModifier = h2b32(cb_args->cb_ioc_num + 1);
		ioc_no = cb_args->cb_ioc_num;
		ioc = &gid_info->gl_iou->iou_ioc_info[ioc_no];
		timeout_id = &ioc->ioc_dc_timeout_id;
		break;
	}
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*hdr))

	*timeout_id = timeout(ibdm_pkt_timeout_hdlr,
	    cb_args, IBDM_TIMEOUT_VALUE(ibdm_dft_timeout));

	mutex_exit(&gid_info->gl_mutex);

	IBTF_DPRINTF_L5("ibdm", "\tretry_command: %p,%x,%d,%d:"
	    "timeout %x", cb_args->cb_req_type, cb_args->cb_ioc_num,
	    cb_args->cb_srvents_start, *timeout_id);

	if (ibmf_msg_transport(gid_info->gl_ibmf_hdl,
	    gid_info->gl_qp_hdl, msg, NULL, ibdm_ibmf_send_cb,
	    cb_args, 0) != IBMF_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm", "\tretry_command: send failed: %p "
		    "rtype 0x%x iocidx 0x%x srvidx %d", cb_args->cb_gid_info,
		    cb_args->cb_req_type, cb_args->cb_ioc_num,
		    cb_args->cb_srvents_start);
		ibdm_ibmf_send_cb(gid_info->gl_ibmf_hdl, msg, cb_args);
	}
	mutex_enter(&gid_info->gl_mutex);
	return (IBDM_SUCCESS);
}


/*
 * ibdm_update_ioc_port_gidlist()
 */
static void
ibdm_update_ioc_port_gidlist(ibdm_ioc_info_t *dest,
    ibdm_dp_gidinfo_t *gid_info)
{
	int		ii, ngid_ents;
	ibdm_gid_t	*tmp;
	ibdm_hca_list_t	*gid_hca_head, *temp;
	ibdm_hca_list_t	*ioc_head = NULL;
	ASSERT(MUTEX_HELD(&gid_info->gl_mutex));

	IBTF_DPRINTF_L5("ibdm", "\tupdate_ioc_port_gidlist: Enter");

	ngid_ents = gid_info->gl_ngids;
	dest->ioc_nportgids = ngid_ents;
	dest->ioc_gid_list = kmem_zalloc(sizeof (ibdm_gid_t) *
	    ngid_ents, KM_SLEEP);
	tmp = gid_info->gl_gid;
	for (ii = 0; (ii < ngid_ents) && (tmp); ii++) {
		dest->ioc_gid_list[ii].gid_dgid_hi = tmp->gid_dgid_hi;
		dest->ioc_gid_list[ii].gid_dgid_lo = tmp->gid_dgid_lo;
		tmp = tmp->gid_next;
	}

	gid_hca_head = gid_info->gl_hca_list;
	while (gid_hca_head) {
		temp = ibdm_dup_hca_attr(gid_hca_head);
		temp->hl_next = ioc_head;
		ioc_head = temp;
		gid_hca_head = gid_hca_head->hl_next;
	}
	dest->ioc_hca_list = ioc_head;
}


/*
 * ibdm_alloc_send_buffers()
 *	Allocates memory for the IBMF send buffer to send and/or receive
 *	the Device Management MAD packet.
 */
static void
ibdm_alloc_send_buffers(ibmf_msg_t *msgp)
{
	msgp->im_msgbufs_send.im_bufs_mad_hdr =
	    kmem_zalloc(IBDM_MAD_SIZE, KM_SLEEP);

	msgp->im_msgbufs_send.im_bufs_cl_hdr = (uchar_t *)
	    msgp->im_msgbufs_send.im_bufs_mad_hdr + sizeof (ib_mad_hdr_t);
	msgp->im_msgbufs_send.im_bufs_cl_hdr_len = IBDM_DM_MAD_HDR_SZ;

	msgp->im_msgbufs_send.im_bufs_cl_data =
	    ((char *)msgp->im_msgbufs_send.im_bufs_cl_hdr + IBDM_DM_MAD_HDR_SZ);
	msgp->im_msgbufs_send.im_bufs_cl_data_len =
	    IBDM_MAD_SIZE - sizeof (ib_mad_hdr_t) - IBDM_DM_MAD_HDR_SZ;
}


/*
 * ibdm_alloc_send_buffers()
 *	De-allocates memory for the IBMF send buffer
 */
static void
ibdm_free_send_buffers(ibmf_msg_t *msgp)
{
	if (msgp->im_msgbufs_send.im_bufs_mad_hdr != NULL)
		kmem_free(msgp->im_msgbufs_send.im_bufs_mad_hdr, IBDM_MAD_SIZE);
}

/*
 * ibdm_probe_ioc()
 *  	1. Gets the node records for the port GUID. This detects all the port
 *  		to the IOU.
 *	2. Selectively probes all the IOC, given it's node GUID
 *	3. In case of reprobe, only the IOC to be reprobed is send the IOC
 *		Controller Profile asynchronously
 */
/*ARGSUSED*/
static void
ibdm_probe_ioc(ib_guid_t nodeguid, ib_guid_t ioc_guid, int reprobe_flag)
{
	int			ii, nrecords;
	size_t			nr_len = 0, pi_len = 0;
	ib_gid_t		sgid, dgid;
	ibdm_hca_list_t		*hca_list = NULL;
	sa_node_record_t	*nr, *tmp;
	ibdm_port_attr_t	*port = NULL;
	ibdm_dp_gidinfo_t	*reprobe_gid, *new_gid, *node_gid;
	ibdm_dp_gidinfo_t	*temp_gidinfo;
	ibdm_gid_t		*temp_gid;
	sa_portinfo_record_t	*pi;

	IBTF_DPRINTF_L4("ibdm", "\tprobe_ioc(%llx, %llx, %x): Begin",
	    nodeguid, ioc_guid, reprobe_flag);

	/* Rescan the GID list for any removed GIDs for reprobe */
	if (reprobe_flag)
		ibdm_rescan_gidlist(&ioc_guid);

	mutex_enter(&ibdm.ibdm_hl_mutex);
	for (ibdm_get_next_port(&hca_list, &port, 1); port;
	    ibdm_get_next_port(&hca_list, &port, 1)) {
		reprobe_gid = new_gid = node_gid = NULL;

		nr = ibdm_get_node_records(port->pa_sa_hdl, &nr_len, nodeguid);
		if (nr == NULL) {
			IBTF_DPRINTF_L4("ibdm", "\tprobe_ioc: no records");
			continue;
		}
		nrecords = (nr_len / sizeof (sa_node_record_t));
		for (tmp = nr, ii = 0;  (ii < nrecords); ii++, tmp++) {
			if ((pi = ibdm_get_portinfo(
			    port->pa_sa_hdl, &pi_len, tmp->LID)) ==  NULL) {
				IBTF_DPRINTF_L4("ibdm",
				    "\tibdm_get_portinfo: no portinfo recs");
				continue;
			}

			/*
			 * If Device Management is not supported on
			 * this port, skip the rest.
			 */
			if (!(pi->PortInfo.CapabilityMask &
			    SM_CAP_MASK_IS_DM_SUPPD)) {
				kmem_free(pi, pi_len);
				continue;
			}

			/*
			 * For reprobes: Check if GID, already in
			 * the list. If so, set the state to SKIPPED
			 */
			if (((temp_gidinfo = ibdm_find_gid(nodeguid,
			    tmp->NodeInfo.PortGUID)) != NULL) &&
			    temp_gidinfo->gl_state ==
			    IBDM_GID_PROBING_COMPLETE) {
				ASSERT(reprobe_gid == NULL);
				ibdm_addto_glhcalist(temp_gidinfo,
				    hca_list);
				reprobe_gid = temp_gidinfo;
				kmem_free(pi, pi_len);
				continue;
			} else if (temp_gidinfo != NULL) {
				kmem_free(pi, pi_len);
				ibdm_addto_glhcalist(temp_gidinfo,
				    hca_list);
				continue;
			}

			IBTF_DPRINTF_L4("ibdm", "\tprobe_ioc : "
			    "create_gid : prefix %llx, guid %llx\n",
			    pi->PortInfo.GidPrefix,
			    tmp->NodeInfo.PortGUID);

			sgid.gid_prefix = port->pa_sn_prefix;
			sgid.gid_guid = port->pa_port_guid;
			dgid.gid_prefix = pi->PortInfo.GidPrefix;
			dgid.gid_guid = tmp->NodeInfo.PortGUID;
			new_gid = ibdm_create_gid_info(port, sgid,
			    dgid);
			if (new_gid == NULL) {
				IBTF_DPRINTF_L2("ibdm", "\tprobe_ioc: "
				    "create_gid_info failed\n");
				kmem_free(pi, pi_len);
				continue;
			}
			if (node_gid == NULL) {
				node_gid = new_gid;
				ibdm_add_to_gl_gid(node_gid, node_gid);
			} else {
				IBTF_DPRINTF_L4("ibdm",
				    "\tprobe_ioc: new gid");
				temp_gid = kmem_zalloc(
				    sizeof (ibdm_gid_t), KM_SLEEP);
				temp_gid->gid_dgid_hi =
				    new_gid->gl_dgid_hi;
				temp_gid->gid_dgid_lo =
				    new_gid->gl_dgid_lo;
				temp_gid->gid_next = node_gid->gl_gid;
				node_gid->gl_gid = temp_gid;
				node_gid->gl_ngids++;
			}
			new_gid->gl_is_dm_capable = B_TRUE;
			new_gid->gl_nodeguid = nodeguid;
			new_gid->gl_portguid = dgid.gid_guid;
			ibdm_addto_glhcalist(new_gid, hca_list);

			/*
			 * Set the state to skipped as all these
			 * gids point to the same node.
			 * We (re)probe only one GID below and reset
			 * state appropriately
			 */
			new_gid->gl_state = IBDM_GID_PROBING_SKIPPED;
			new_gid->gl_devid = (*tmp).NodeInfo.DeviceID;
			kmem_free(pi, pi_len);
		}
		kmem_free(nr, nr_len);

		IBTF_DPRINTF_L4("ibdm", "\tprobe_ioc : reprobe_flag %d "
		    "reprobe_gid %p new_gid %p node_gid %p",
		    reprobe_flag, reprobe_gid, new_gid, node_gid);

		if (reprobe_flag != 0 && reprobe_gid != NULL) {
			int	niocs, jj;
			ibdm_ioc_info_t *tmp_ioc;
			int ioc_matched = 0;

			mutex_exit(&ibdm.ibdm_hl_mutex);
			mutex_enter(&reprobe_gid->gl_mutex);
			reprobe_gid->gl_state = IBDM_GET_IOC_DETAILS;
			niocs =
			    reprobe_gid->gl_iou->iou_info.iou_num_ctrl_slots;
			reprobe_gid->gl_pending_cmds++;
			mutex_exit(&reprobe_gid->gl_mutex);

			for (jj = 0; jj < niocs; jj++) {
				tmp_ioc =
				    IBDM_GIDINFO2IOCINFO(reprobe_gid, jj);
				if (tmp_ioc->ioc_profile.ioc_guid != ioc_guid)
					continue;

				ioc_matched = 1;

				/*
				 * Explicitly set gl_reprobe_flag to 0 so that
				 * IBnex is not notified on completion
				 */
				mutex_enter(&reprobe_gid->gl_mutex);
				reprobe_gid->gl_reprobe_flag = 0;
				mutex_exit(&reprobe_gid->gl_mutex);

				mutex_enter(&ibdm.ibdm_mutex);
				ibdm.ibdm_ngid_probes_in_progress++;
				mutex_exit(&ibdm.ibdm_mutex);
				if (ibdm_send_ioc_profile(reprobe_gid, jj) !=
				    IBDM_SUCCESS) {
					IBTF_DPRINTF_L4("ibdm",
					    "\tprobe_ioc: "
					    "send_ioc_profile failed "
					    "for ioc %d", jj);
					ibdm_gid_decr_pending(reprobe_gid);
					break;
				}
				mutex_enter(&ibdm.ibdm_mutex);
				ibdm_wait_probe_completion();
				mutex_exit(&ibdm.ibdm_mutex);
				break;
			}
			if (ioc_matched == 0)
				ibdm_gid_decr_pending(reprobe_gid);
			else {
				mutex_enter(&ibdm.ibdm_hl_mutex);
				break;
			}
		} else if (new_gid != NULL) {
			mutex_exit(&ibdm.ibdm_hl_mutex);
			node_gid = node_gid ? node_gid : new_gid;

			/*
			 * New or reinserted GID : Enable notification
			 * to IBnex
			 */
			mutex_enter(&node_gid->gl_mutex);
			node_gid->gl_reprobe_flag = 1;
			mutex_exit(&node_gid->gl_mutex);

			ibdm_probe_gid(node_gid);

			mutex_enter(&ibdm.ibdm_hl_mutex);
		}
	}
	mutex_exit(&ibdm.ibdm_hl_mutex);
	IBTF_DPRINTF_L4("ibdm", "\tprobe_ioc : End\n");
}


/*
 * ibdm_probe_gid()
 *	Selectively probes the GID
 */
static void
ibdm_probe_gid(ibdm_dp_gidinfo_t *gid_info)
{
	IBTF_DPRINTF_L4("ibdm", "\tprobe_gid:");

	/*
	 * A Cisco FC GW needs the special handling to get IOUnitInfo.
	 */
	mutex_enter(&gid_info->gl_mutex);
	if (ibdm_is_cisco_switch(gid_info)) {
		gid_info->gl_pending_cmds++;
		gid_info->gl_state = IBDM_SET_CLASSPORTINFO;
		mutex_exit(&gid_info->gl_mutex);

		if (ibdm_set_classportinfo(gid_info) != IBDM_SUCCESS) {

			mutex_enter(&gid_info->gl_mutex);
			gid_info->gl_state = IBDM_GID_PROBING_FAILED;
			--gid_info->gl_pending_cmds;
			mutex_exit(&gid_info->gl_mutex);

			/* free the hca_list on this gid_info */
			ibdm_delete_glhca_list(gid_info);
			gid_info = gid_info->gl_next;
			return;
		}

		mutex_enter(&gid_info->gl_mutex);
		ibdm_wait_cisco_probe_completion(gid_info);

		IBTF_DPRINTF_L4("ibdm",
		    "\tprobe_gid: CISCO Wakeup signal received");
	}

	/* move on to the 'GET_CLASSPORTINFO' stage */
	gid_info->gl_pending_cmds++;
	gid_info->gl_state = IBDM_GET_CLASSPORTINFO;
	mutex_exit(&gid_info->gl_mutex);

	if (ibdm_send_classportinfo(gid_info) != IBDM_SUCCESS) {

		mutex_enter(&gid_info->gl_mutex);
		gid_info->gl_state = IBDM_GID_PROBING_FAILED;
		--gid_info->gl_pending_cmds;
		mutex_exit(&gid_info->gl_mutex);

		/* free the hca_list on this gid_info */
		ibdm_delete_glhca_list(gid_info);
		gid_info = gid_info->gl_next;
		return;
	}

	mutex_enter(&ibdm.ibdm_mutex);
	ibdm.ibdm_ngid_probes_in_progress++;
	gid_info = gid_info->gl_next;
	ibdm_wait_probe_completion();
	mutex_exit(&ibdm.ibdm_mutex);

	IBTF_DPRINTF_L4("ibdm", "\tprobe_gid: Wakeup signal received");
}


/*
 * ibdm_create_gid_info()
 *	Allocates a gid_info structure and initializes
 *	Returns pointer to the structure on success
 *	and NULL on failure
 */
static ibdm_dp_gidinfo_t *
ibdm_create_gid_info(ibdm_port_attr_t *port, ib_gid_t sgid, ib_gid_t dgid)
{
	uint8_t			ii, npaths;
	sa_path_record_t	*path;
	size_t			len;
	ibdm_pkey_tbl_t		*pkey_tbl;
	ibdm_dp_gidinfo_t	*gid_info = NULL;
	int			ret;

	IBTF_DPRINTF_L4("ibdm", "\tcreate_gid_info: Begin");
	npaths = 1;

	/* query for reversible paths */
	if (port->pa_sa_hdl)
		ret = ibmf_saa_gid_to_pathrecords(port->pa_sa_hdl,
		    sgid, dgid, IBMF_SAA_PKEY_WC, 0, B_TRUE, &npaths, 0,
		    &len, &path);
	else
		return (NULL);

	if (ret == IBMF_SUCCESS && path) {
		ibdm_dump_path_info(path);

		gid_info = kmem_zalloc(
		    sizeof (ibdm_dp_gidinfo_t), KM_SLEEP);
		mutex_init(&gid_info->gl_mutex, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&gid_info->gl_probe_cv, NULL, CV_DRIVER, NULL);
		gid_info->gl_dgid_hi		= path->DGID.gid_prefix;
		gid_info->gl_dgid_lo		= path->DGID.gid_guid;
		gid_info->gl_sgid_hi		= path->SGID.gid_prefix;
		gid_info->gl_sgid_lo		= path->SGID.gid_guid;
		gid_info->gl_p_key		= path->P_Key;
		gid_info->gl_sa_hdl		= port->pa_sa_hdl;
		gid_info->gl_ibmf_hdl		= port->pa_ibmf_hdl;
		gid_info->gl_slid		= path->SLID;
		gid_info->gl_dlid		= path->DLID;
		gid_info->gl_transactionID	= (++ibdm.ibdm_transactionID)
		    << IBDM_GID_TRANSACTIONID_SHIFT;
		gid_info->gl_min_transactionID  = gid_info->gl_transactionID;
		gid_info->gl_max_transactionID  = (ibdm.ibdm_transactionID +1)
		    << IBDM_GID_TRANSACTIONID_SHIFT;
		gid_info->gl_SL			= path->SL;

		gid_info->gl_qp_hdl = IBMF_QP_HANDLE_DEFAULT;
		for (ii = 0; ii < port->pa_npkeys; ii++) {
			if (port->pa_pkey_tbl == NULL)
				break;

			pkey_tbl = &port->pa_pkey_tbl[ii];
			if ((gid_info->gl_p_key == pkey_tbl->pt_pkey) &&
			    (pkey_tbl->pt_qp_hdl != NULL)) {
				gid_info->gl_qp_hdl = pkey_tbl->pt_qp_hdl;
				break;
			}
		}
		kmem_free(path, len);

		/*
		 * QP handle for GID not initialized. No matching Pkey
		 * was found!! ibdm should *not* hit this case. Flag an
		 * error and drop the GID if ibdm does encounter this.
		 */
		if (gid_info->gl_qp_hdl == NULL) {
			IBTF_DPRINTF_L2(ibdm_string,
			    "\tcreate_gid_info: No matching Pkey");
			ibdm_delete_gidinfo(gid_info);
			return (NULL);
		}

		ibdm.ibdm_ngids++;
		if (ibdm.ibdm_dp_gidlist_head == NULL) {
			ibdm.ibdm_dp_gidlist_head = gid_info;
			ibdm.ibdm_dp_gidlist_tail = gid_info;
		} else {
			ibdm.ibdm_dp_gidlist_tail->gl_next = gid_info;
			gid_info->gl_prev = ibdm.ibdm_dp_gidlist_tail;
			ibdm.ibdm_dp_gidlist_tail = gid_info;
		}
	}

	return (gid_info);
}


/*
 * ibdm_get_node_records
 *	Sends a SA query to get the NODE record
 *	Returns pointer to the sa_node_record_t on success
 *	and NULL on failure
 */
static sa_node_record_t *
ibdm_get_node_records(ibmf_saa_handle_t sa_hdl, size_t *length, ib_guid_t guid)
{
	sa_node_record_t	req, *resp = NULL;
	ibmf_saa_access_args_t	args;
	int			ret;

	IBTF_DPRINTF_L4("ibdm", "\tget_node_records: Begin");

	bzero(&req, sizeof (sa_node_record_t));
	req.NodeInfo.NodeGUID = guid;

	args.sq_attr_id		= SA_NODERECORD_ATTRID;
	args.sq_access_type 	= IBMF_SAA_RETRIEVE;
	args.sq_component_mask 	= SA_NODEINFO_COMPMASK_NODEGUID;
	args.sq_template	= &req;
	args.sq_callback	= NULL;
	args.sq_callback_arg 	= NULL;

	ret = ibmf_sa_access(sa_hdl, &args, 0, length, (void **) &resp);
	if (ret != IBMF_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm", "\tget_node_records:"
		    " SA Retrieve Failed: %d", ret);
		return (NULL);
	}
	if ((resp == NULL) || (*length == 0)) {
		IBTF_DPRINTF_L2("ibdm", "\tget_node_records: No records");
		return (NULL);
	}

	IBTF_DPRINTF_L4("ibdm", "\tget_node_records: NodeGuid %llx "
	    "PortGUID %llx", resp->NodeInfo.NodeGUID, resp->NodeInfo.PortGUID);

	return (resp);
}


/*
 * ibdm_get_portinfo()
 *	Sends a SA query to get the PortInfo record
 *	Returns pointer to the sa_portinfo_record_t on success
 *	and NULL on failure
 */
static sa_portinfo_record_t *
ibdm_get_portinfo(ibmf_saa_handle_t sa_hdl, size_t *length, ib_lid_t lid)
{
	sa_portinfo_record_t	req, *resp = NULL;
	ibmf_saa_access_args_t	args;
	int			ret;

	IBTF_DPRINTF_L4("ibdm", "\tget_portinfo: Begin");

	bzero(&req, sizeof (sa_portinfo_record_t));
	req.EndportLID	= lid;

	args.sq_attr_id		= SA_PORTINFORECORD_ATTRID;
	args.sq_access_type	= IBMF_SAA_RETRIEVE;
	args.sq_component_mask	= SA_PORTINFO_COMPMASK_PORTLID;
	args.sq_template	= &req;
	args.sq_callback	= NULL;
	args.sq_callback_arg	= NULL;

	ret = ibmf_sa_access(sa_hdl, &args, 0, length, (void **) &resp);
	if (ret != IBMF_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm", "\tget_portinfo:"
		    " SA Retrieve Failed: 0x%X", ret);
		return (NULL);
	}
	if ((*length == 0) || (resp == NULL))
		return (NULL);

	IBTF_DPRINTF_L4("ibdm", "\tget_portinfo: GidPrefix %llx Cap 0x%x",
	    resp->PortInfo.GidPrefix, resp->PortInfo.CapabilityMask);
	return (resp);
}


/*
 * ibdm_ibnex_register_callback
 *	IB nexus callback routine for HCA attach and detach notification
 */
void
ibdm_ibnex_register_callback(ibdm_callback_t ibnex_dm_callback)
{
	IBTF_DPRINTF_L4("ibdm", "\tibnex_register_callbacks");
	mutex_enter(&ibdm.ibdm_ibnex_mutex);
	ibdm.ibdm_ibnex_callback = ibnex_dm_callback;
	mutex_exit(&ibdm.ibdm_ibnex_mutex);
}


/*
 * ibdm_ibnex_unregister_callbacks
 */
void
ibdm_ibnex_unregister_callback()
{
	IBTF_DPRINTF_L4("ibdm", "\tibnex_unregister_callbacks");
	mutex_enter(&ibdm.ibdm_ibnex_mutex);
	ibdm.ibdm_ibnex_callback = NULL;
	mutex_exit(&ibdm.ibdm_ibnex_mutex);
}

/*
 * ibdm_get_waittime()
 *	Calculates the wait time based on the last HCA attach time
 */
static clock_t
ibdm_get_waittime(ib_guid_t hca_guid, int dft_wait_sec)
{
	const hrtime_t	dft_wait = dft_wait_sec * NANOSEC;
	hrtime_t	temp, wait_time = 0;
	clock_t		usecs;
	int		i;
	ibdm_hca_list_t	*hca;

	IBTF_DPRINTF_L4("ibdm", "\tget_waittime hcaguid:%llx"
	    "\tport settling time %d", hca_guid, dft_wait);

	ASSERT(mutex_owned(&ibdm.ibdm_hl_mutex));

	hca = ibdm.ibdm_hca_list_head;

	for (i = 0; i < ibdm.ibdm_hca_count; i++, hca = hca->hl_next) {
		if (hca->hl_nports == hca->hl_nports_active)
			continue;

		if (hca_guid && (hca_guid != hca->hl_hca_guid))
			continue;

		temp = gethrtime() - hca->hl_attach_time;
		temp = MAX(0, (dft_wait - temp));

		if (hca_guid) {
			wait_time = temp;
			break;
		}

		wait_time = MAX(temp, wait_time);
	}

	/* convert to microseconds */
	usecs = MIN(wait_time, dft_wait) / (NANOSEC / MICROSEC);

	IBTF_DPRINTF_L2("ibdm", "\tget_waittime: wait_time = %ld usecs",
	    (long)usecs);

	return (drv_usectohz(usecs));
}

void
ibdm_ibnex_port_settle_wait(ib_guid_t hca_guid, int dft_wait)
{
	clock_t wait_time;

	mutex_enter(&ibdm.ibdm_hl_mutex);

	while ((wait_time = ibdm_get_waittime(hca_guid, dft_wait)) > 0)
		(void) cv_reltimedwait(&ibdm.ibdm_port_settle_cv,
		    &ibdm.ibdm_hl_mutex, wait_time, TR_CLOCK_TICK);

	mutex_exit(&ibdm.ibdm_hl_mutex);
}


/*
 * ibdm_ibnex_probe_hcaport
 *	Probes the presence of HCA port (with HCA dip and port number)
 *	Returns port attributes structure on SUCCESS
 */
ibdm_port_attr_t *
ibdm_ibnex_probe_hcaport(ib_guid_t hca_guid, uint8_t port_num)
{
	int			ii, jj;
	ibdm_hca_list_t		*hca_list;
	ibdm_port_attr_t	*port_attr;

	IBTF_DPRINTF_L4("ibdm", "\tibnex_probe_hcaport:");

	mutex_enter(&ibdm.ibdm_hl_mutex);
	hca_list = ibdm.ibdm_hca_list_head;
	for (ii = 0; ii < ibdm.ibdm_hca_count; ii++) {
		if (hca_list->hl_hca_guid == hca_guid) {
			for (jj = 0; jj < hca_list->hl_nports; jj++) {
				if (hca_list->hl_port_attr[jj].pa_port_num ==
				    port_num) {
					break;
				}
			}
			if (jj != hca_list->hl_nports)
				break;
		}
		hca_list = hca_list->hl_next;
	}
	if (ii == ibdm.ibdm_hca_count) {
		IBTF_DPRINTF_L2("ibdm", "\tibnex_probe_hcaport: not found");
		mutex_exit(&ibdm.ibdm_hl_mutex);
		return (NULL);
	}
	port_attr = (ibdm_port_attr_t *)kmem_zalloc(
	    sizeof (ibdm_port_attr_t), KM_SLEEP);
	bcopy((char *)&hca_list->hl_port_attr[jj],
	    port_attr, sizeof (ibdm_port_attr_t));
	ibdm_update_port_attr(port_attr);

	mutex_exit(&ibdm.ibdm_hl_mutex);
	return (port_attr);
}


/*
 * ibdm_ibnex_get_port_attrs
 *	Scan all HCAs for a matching port_guid.
 *	Returns "port attributes" structure on success.
 */
ibdm_port_attr_t *
ibdm_ibnex_get_port_attrs(ib_guid_t port_guid)
{
	int			ii, jj;
	ibdm_hca_list_t		*hca_list;
	ibdm_port_attr_t	*port_attr;

	IBTF_DPRINTF_L4("ibdm", "\tibnex_get_port_attrs:");

	mutex_enter(&ibdm.ibdm_hl_mutex);
	hca_list = ibdm.ibdm_hca_list_head;

	for (ii = 0; ii < ibdm.ibdm_hca_count; ii++) {
		for (jj = 0; jj < hca_list->hl_nports; jj++) {
			if (hca_list->hl_port_attr[jj].pa_port_guid ==
			    port_guid) {
				break;
			}
		}
		if (jj != hca_list->hl_nports)
			break;
		hca_list = hca_list->hl_next;
	}

	if (ii == ibdm.ibdm_hca_count) {
		IBTF_DPRINTF_L2("ibdm", "\tibnex_get_port_attrs: not found");
		mutex_exit(&ibdm.ibdm_hl_mutex);
		return (NULL);
	}

	port_attr = (ibdm_port_attr_t *)kmem_alloc(sizeof (ibdm_port_attr_t),
	    KM_SLEEP);
	bcopy((char *)&hca_list->hl_port_attr[jj], port_attr,
	    sizeof (ibdm_port_attr_t));
	ibdm_update_port_attr(port_attr);

	mutex_exit(&ibdm.ibdm_hl_mutex);
	return (port_attr);
}


/*
 * ibdm_ibnex_free_port_attr()
 */
void
ibdm_ibnex_free_port_attr(ibdm_port_attr_t *port_attr)
{
	IBTF_DPRINTF_L4("ibdm", "\tibnex_free_port_attr:");
	if (port_attr) {
		if (port_attr->pa_pkey_tbl != NULL) {
			kmem_free(port_attr->pa_pkey_tbl,
			    (port_attr->pa_npkeys * sizeof (ibdm_pkey_tbl_t)));
		}
		kmem_free(port_attr, sizeof (ibdm_port_attr_t));
	}
}


/*
 * ibdm_ibnex_get_hca_list()
 *	Returns portinfo for all the port for all the HCA's
 */
void
ibdm_ibnex_get_hca_list(ibdm_hca_list_t **hca, int *count)
{
	ibdm_hca_list_t		*head = NULL, *temp, *temp1;
	int			ii;

	IBTF_DPRINTF_L4("ibdm", "\tibnex_get_hca_list:");

	mutex_enter(&ibdm.ibdm_hl_mutex);
	temp = ibdm.ibdm_hca_list_head;
	for (ii = 0; ii < ibdm.ibdm_hca_count; ii++) {
		temp1 = ibdm_dup_hca_attr(temp);
		temp1->hl_next = head;
		head = temp1;
		temp = temp->hl_next;
	}
	*count = ibdm.ibdm_hca_count;
	*hca = head;
	mutex_exit(&ibdm.ibdm_hl_mutex);
}


/*
 * ibdm_ibnex_get_hca_info_by_guid()
 */
ibdm_hca_list_t	*
ibdm_ibnex_get_hca_info_by_guid(ib_guid_t hca_guid)
{
	ibdm_hca_list_t		*head = NULL, *hca = NULL;

	IBTF_DPRINTF_L4("ibdm", "\tibnex_get_hca_info_by_dip");

	mutex_enter(&ibdm.ibdm_hl_mutex);
	head = ibdm.ibdm_hca_list_head;
	while (head) {
		if (head->hl_hca_guid == hca_guid) {
			hca = ibdm_dup_hca_attr(head);
			hca->hl_next = NULL;
			break;
		}
		head = head->hl_next;
	}
	mutex_exit(&ibdm.ibdm_hl_mutex);
	IBTF_DPRINTF_L4("ibdm", "\tibnex_get_hca_info_by_dip %p", hca);
	return (hca);
}


/*
 * ibdm_dup_hca_attr()
 *	Allocate a new HCA attribute strucuture and initialize
 *	hca attribute structure with the incoming HCA attributes
 *	returned the allocated hca attributes.
 */
static ibdm_hca_list_t *
ibdm_dup_hca_attr(ibdm_hca_list_t *in_hca)
{
	int			len;
	ibdm_hca_list_t		*out_hca;

	len = sizeof (ibdm_hca_list_t) +
	    (in_hca->hl_nports * sizeof (ibdm_port_attr_t));
	IBTF_DPRINTF_L4("ibdm", "\tdup_hca_attr len %d", len);
	out_hca = (ibdm_hca_list_t *)kmem_alloc(len, KM_SLEEP);
	bcopy((char *)in_hca,
	    (char *)out_hca, sizeof (ibdm_hca_list_t));
	if (in_hca->hl_nports) {
		out_hca->hl_port_attr = (ibdm_port_attr_t *)
		    ((char *)out_hca + sizeof (ibdm_hca_list_t));
		bcopy((char *)in_hca->hl_port_attr,
		    (char *)out_hca->hl_port_attr,
		    (in_hca->hl_nports * sizeof (ibdm_port_attr_t)));
		for (len = 0; len < out_hca->hl_nports; len++)
			ibdm_update_port_attr(&out_hca->hl_port_attr[len]);
	}
	return (out_hca);
}


/*
 * ibdm_ibnex_free_hca_list()
 *	Free one/more HCA lists
 */
void
ibdm_ibnex_free_hca_list(ibdm_hca_list_t *hca_list)
{
	int			ii;
	size_t			len;
	ibdm_hca_list_t 	*temp;
	ibdm_port_attr_t	*port;

	IBTF_DPRINTF_L4("ibdm", "\tibnex_free_hca_list:");
	ASSERT(hca_list);
	while (hca_list) {
		temp = hca_list;
		hca_list = hca_list->hl_next;
		for (ii = 0; ii < temp->hl_nports; ii++) {
			port = &temp->hl_port_attr[ii];
			len = (port->pa_npkeys * sizeof (ibdm_pkey_tbl_t));
			if (len != 0)
				kmem_free(port->pa_pkey_tbl, len);
		}
		len = sizeof (ibdm_hca_list_t) + (temp->hl_nports *
		    sizeof (ibdm_port_attr_t));
		kmem_free(temp, len);
	}
}


/*
 * ibdm_ibnex_probe_iocguid()
 *	Probes the IOC on the fabric and returns the IOC information
 *	if present. Otherwise, NULL is returned
 */
/* ARGSUSED */
ibdm_ioc_info_t *
ibdm_ibnex_probe_ioc(ib_guid_t iou, ib_guid_t ioc_guid, int reprobe_flag)
{
	int			k;
	ibdm_ioc_info_t		*ioc_info;
	ibdm_dp_gidinfo_t	*gid_info; /* used as index and arg */
	timeout_id_t		*timeout_id;

	IBTF_DPRINTF_L4("ibdm", "\tibnex_probe_ioc: (%llX, %llX, %d) Begin",
	    iou, ioc_guid, reprobe_flag);

	if (ibdm_enumerate_iocs == 0)
		return (NULL);

	/* Check whether we know this already */
	ioc_info = ibdm_get_ioc_info_with_gid(ioc_guid, &gid_info);
	if (ioc_info == NULL) {
		mutex_enter(&ibdm.ibdm_mutex);
		while (ibdm.ibdm_busy & IBDM_BUSY)
			cv_wait(&ibdm.ibdm_busy_cv, &ibdm.ibdm_mutex);
		ibdm.ibdm_busy |= IBDM_BUSY;
		mutex_exit(&ibdm.ibdm_mutex);
		ibdm_probe_ioc(iou, ioc_guid, 0);
		mutex_enter(&ibdm.ibdm_mutex);
		ibdm.ibdm_busy &= ~IBDM_BUSY;
		cv_broadcast(&ibdm.ibdm_busy_cv);
		mutex_exit(&ibdm.ibdm_mutex);
		ioc_info = ibdm_get_ioc_info_with_gid(ioc_guid, &gid_info);
	} else if (reprobe_flag) {	/* Handle Reprobe for the IOC */
		ASSERT(gid_info != NULL);
		/* Free the ioc_list before reprobe; and cancel any timers */
		mutex_enter(&ibdm.ibdm_mutex);
		mutex_enter(&gid_info->gl_mutex);
		if (ioc_info->ioc_timeout_id) {
			timeout_id = ioc_info->ioc_timeout_id;
			ioc_info->ioc_timeout_id = 0;
			mutex_exit(&gid_info->gl_mutex);
			IBTF_DPRINTF_L5("ibdm", "\tprobe_ioc: "
			    "ioc_timeout_id = 0x%x", timeout_id);
			if (untimeout(timeout_id) == -1) {
				IBTF_DPRINTF_L2("ibdm", "\tprobe_ioc: "
				    "untimeout ioc_timeout_id failed");
			}
			mutex_enter(&gid_info->gl_mutex);
		}
		if (ioc_info->ioc_dc_timeout_id) {
			timeout_id = ioc_info->ioc_dc_timeout_id;
			ioc_info->ioc_dc_timeout_id = 0;
			mutex_exit(&gid_info->gl_mutex);
			IBTF_DPRINTF_L5("ibdm", "\tprobe_ioc: "
			    "ioc_dc_timeout_id = 0x%x", timeout_id);
			if (untimeout(timeout_id) == -1) {
				IBTF_DPRINTF_L2("ibdm", "\tprobe_ioc: "
				    "untimeout ioc_dc_timeout_id failed");
			}
			mutex_enter(&gid_info->gl_mutex);
		}
		for (k = 0; k < ioc_info->ioc_profile.ioc_service_entries; k++)
			if (ioc_info->ioc_serv[k].se_timeout_id) {
				timeout_id = ioc_info->ioc_serv[k].
				    se_timeout_id;
				ioc_info->ioc_serv[k].se_timeout_id = 0;
				mutex_exit(&gid_info->gl_mutex);
				IBTF_DPRINTF_L5("ibdm", "\tprobe_ioc: "
				    "ioc_info->ioc_serv[k].se_timeout_id = %x",
				    k, timeout_id);
				if (untimeout(timeout_id) == -1) {
					IBTF_DPRINTF_L2("ibdm", "\tprobe_ioc: "
					    "untimeout se_timeout_id %d "
					    "failed", k);
				}
				mutex_enter(&gid_info->gl_mutex);
			}
		mutex_exit(&gid_info->gl_mutex);
		mutex_exit(&ibdm.ibdm_mutex);
		ibdm_ibnex_free_ioc_list(ioc_info);

		mutex_enter(&ibdm.ibdm_mutex);
		while (ibdm.ibdm_busy & IBDM_BUSY)
			cv_wait(&ibdm.ibdm_busy_cv, &ibdm.ibdm_mutex);
		ibdm.ibdm_busy |= IBDM_BUSY;
		mutex_exit(&ibdm.ibdm_mutex);

		ibdm_probe_ioc(iou, ioc_guid, 1);

		/*
		 * Skip if gl_reprobe_flag is set, this will be
		 * a re-inserted / new GID, for which notifications
		 * have already been send.
		 */
		for (gid_info = ibdm.ibdm_dp_gidlist_head; gid_info;
		    gid_info = gid_info->gl_next) {
			uint8_t			ii, niocs;
			ibdm_ioc_info_t		*ioc;

			if (gid_info->gl_iou == NULL)
				continue;

			if (gid_info->gl_reprobe_flag) {
				gid_info->gl_reprobe_flag = 0;
				continue;
			}

			niocs = gid_info->gl_iou->iou_info.iou_num_ctrl_slots;
			for (ii = 0; ii < niocs; ii++) {
				ioc = IBDM_GIDINFO2IOCINFO(gid_info, ii);
				if (ioc->ioc_profile.ioc_guid == ioc_guid) {
					mutex_enter(&ibdm.ibdm_mutex);
					ibdm_reprobe_update_port_srv(ioc,
					    gid_info);
					mutex_exit(&ibdm.ibdm_mutex);
				}
			}
		}
		mutex_enter(&ibdm.ibdm_mutex);
		ibdm.ibdm_busy &= ~IBDM_BUSY;
		cv_broadcast(&ibdm.ibdm_busy_cv);
		mutex_exit(&ibdm.ibdm_mutex);

		ioc_info = ibdm_get_ioc_info_with_gid(ioc_guid, &gid_info);
	}
	return (ioc_info);
}


/*
 * ibdm_get_ioc_info_with_gid()
 *	Returns pointer to ibdm_ioc_info_t if it finds
 *	matching record for the ioc_guid. Otherwise NULL is returned.
 *	The pointer to gid_info is set to the second argument in case that
 *	the non-NULL value returns (and the second argument is not NULL).
 *
 * Note. use the same strings as "ibnex_get_ioc_info" in
 *       IBTF_DPRINTF() to keep compatibility.
 */
static ibdm_ioc_info_t *
ibdm_get_ioc_info_with_gid(ib_guid_t ioc_guid,
    ibdm_dp_gidinfo_t **gid_info)
{
	int			ii;
	ibdm_ioc_info_t		*ioc = NULL, *tmp = NULL;
	ibdm_dp_gidinfo_t	*gid_list;
	ib_dm_io_unitinfo_t	*iou;

	IBTF_DPRINTF_L4("ibdm", "\tibnex_get_ioc_info: GUID %llx", ioc_guid);

	mutex_enter(&ibdm.ibdm_mutex);
	while (ibdm.ibdm_busy & IBDM_BUSY)
		cv_wait(&ibdm.ibdm_busy_cv, &ibdm.ibdm_mutex);
	ibdm.ibdm_busy |= IBDM_BUSY;

	if (gid_info)
		*gid_info = NULL; /* clear the value of gid_info */

	gid_list = ibdm.ibdm_dp_gidlist_head;
	while (gid_list) {
		mutex_enter(&gid_list->gl_mutex);
		if (gid_list->gl_state != IBDM_GID_PROBING_COMPLETE) {
			mutex_exit(&gid_list->gl_mutex);
			gid_list = gid_list->gl_next;
			continue;
		}
		if (gid_list->gl_iou == NULL) {
			IBTF_DPRINTF_L2("ibdm",
			    "\tget_ioc_info: No IOU info");
			mutex_exit(&gid_list->gl_mutex);
			gid_list = gid_list->gl_next;
			continue;
		}
		iou = &gid_list->gl_iou->iou_info;
		for (ii = 0; ii < iou->iou_num_ctrl_slots; ii++) {
			tmp = IBDM_GIDINFO2IOCINFO(gid_list, ii);
			if ((tmp->ioc_profile.ioc_guid == ioc_guid) &&
			    (tmp->ioc_state == IBDM_IOC_STATE_PROBE_SUCCESS)) {
				ioc = ibdm_dup_ioc_info(tmp, gid_list);
				if (gid_info)
					*gid_info = gid_list; /* set this ptr */
				mutex_exit(&gid_list->gl_mutex);
				ibdm.ibdm_busy &= ~IBDM_BUSY;
				cv_broadcast(&ibdm.ibdm_busy_cv);
				mutex_exit(&ibdm.ibdm_mutex);
				IBTF_DPRINTF_L4("ibdm", "\tget_ioc_info: End");
				return (ioc);
			}
		}
		if (ii == iou->iou_num_ctrl_slots)
			ioc = NULL;

		mutex_exit(&gid_list->gl_mutex);
		gid_list = gid_list->gl_next;
	}

	ibdm.ibdm_busy &= ~IBDM_BUSY;
	cv_broadcast(&ibdm.ibdm_busy_cv);
	mutex_exit(&ibdm.ibdm_mutex);
	IBTF_DPRINTF_L4("ibdm", "\tget_ioc_info: failure End");
	return (ioc);
}

/*
 * ibdm_ibnex_get_ioc_info()
 *	Returns pointer to ibdm_ioc_info_t if it finds
 *	matching record for the ioc_guid, otherwise NULL
 *	is returned
 *
 * Note. this is a wrapper function to ibdm_get_ioc_info_with_gid() now.
 */
ibdm_ioc_info_t *
ibdm_ibnex_get_ioc_info(ib_guid_t ioc_guid)
{
	if (ibdm_enumerate_iocs == 0)
		return (NULL);

	/* will not use the gid_info pointer, so the second arg is NULL */
	return (ibdm_get_ioc_info_with_gid(ioc_guid, NULL));
}

/*
 * ibdm_ibnex_get_ioc_count()
 *	Returns number of ibdm_ioc_info_t it finds
 */
int
ibdm_ibnex_get_ioc_count(void)
{
	int			count = 0, k;
	ibdm_ioc_info_t		*ioc;
	ibdm_dp_gidinfo_t	*gid_list;

	if (ibdm_enumerate_iocs == 0)
		return (0);

	mutex_enter(&ibdm.ibdm_mutex);
	ibdm_sweep_fabric(0);

	while (ibdm.ibdm_busy & IBDM_BUSY)
		cv_wait(&ibdm.ibdm_busy_cv, &ibdm.ibdm_mutex);
	ibdm.ibdm_busy |= IBDM_BUSY;

	for (gid_list = ibdm.ibdm_dp_gidlist_head; gid_list;
	    gid_list = gid_list->gl_next) {
		mutex_enter(&gid_list->gl_mutex);
		if ((gid_list->gl_state != IBDM_GID_PROBING_COMPLETE) ||
		    (gid_list->gl_iou == NULL)) {
			mutex_exit(&gid_list->gl_mutex);
			continue;
		}
		for (k = 0; k < gid_list->gl_iou->iou_info.iou_num_ctrl_slots;
		    k++) {
			ioc = IBDM_GIDINFO2IOCINFO(gid_list, k);
			if (ioc->ioc_state == IBDM_IOC_STATE_PROBE_SUCCESS)
				++count;
		}
		mutex_exit(&gid_list->gl_mutex);
	}
	ibdm.ibdm_busy &= ~IBDM_BUSY;
	cv_broadcast(&ibdm.ibdm_busy_cv);
	mutex_exit(&ibdm.ibdm_mutex);

	IBTF_DPRINTF_L4("ibdm", "\tget_ioc_count: count = %d", count);
	return (count);
}


/*
 * ibdm_ibnex_get_ioc_list()
 *	Returns information about all the IOCs present on the fabric.
 *	Reprobes the IOCs and the GID list if list_flag is set to REPROBE_ALL.
 *	Does not sweep fabric if DONOT_PROBE is set
 */
ibdm_ioc_info_t *
ibdm_ibnex_get_ioc_list(ibdm_ibnex_get_ioclist_mtd_t list_flag)
{
	int			ii;
	ibdm_ioc_info_t		*ioc_list = NULL, *tmp, *ioc;
	ibdm_dp_gidinfo_t	*gid_list;
	ib_dm_io_unitinfo_t	*iou;

	IBTF_DPRINTF_L4("ibdm", "\tget_ioc_list: Enter");

	if (ibdm_enumerate_iocs == 0)
		return (NULL);

	mutex_enter(&ibdm.ibdm_mutex);
	if (list_flag != IBDM_IBNEX_DONOT_PROBE)
		ibdm_sweep_fabric(list_flag == IBDM_IBNEX_REPROBE_ALL);

	while (ibdm.ibdm_busy & IBDM_BUSY)
		cv_wait(&ibdm.ibdm_busy_cv, &ibdm.ibdm_mutex);
	ibdm.ibdm_busy |= IBDM_BUSY;

	gid_list = ibdm.ibdm_dp_gidlist_head;
	while (gid_list) {
		mutex_enter(&gid_list->gl_mutex);
		if (gid_list->gl_state != IBDM_GID_PROBING_COMPLETE) {
			mutex_exit(&gid_list->gl_mutex);
			gid_list = gid_list->gl_next;
			continue;
		}
		if (gid_list->gl_iou == NULL) {
			IBTF_DPRINTF_L2("ibdm",
			    "\tget_ioc_list: No IOU info");
			mutex_exit(&gid_list->gl_mutex);
			gid_list = gid_list->gl_next;
			continue;
		}
		iou = &gid_list->gl_iou->iou_info;
		for (ii = 0; ii < iou->iou_num_ctrl_slots; ii++) {
			ioc = IBDM_GIDINFO2IOCINFO(gid_list, ii);
			if (ioc->ioc_state == IBDM_IOC_STATE_PROBE_SUCCESS) {
				tmp = ibdm_dup_ioc_info(ioc, gid_list);
				tmp->ioc_next = ioc_list;
				ioc_list = tmp;
			}
		}
		mutex_exit(&gid_list->gl_mutex);
		gid_list = gid_list->gl_next;
	}
	ibdm.ibdm_busy &= ~IBDM_BUSY;
	cv_broadcast(&ibdm.ibdm_busy_cv);
	mutex_exit(&ibdm.ibdm_mutex);

	IBTF_DPRINTF_L4("ibdm", "\tget_ioc_list: End");
	return (ioc_list);
}

/*
 * ibdm_dup_ioc_info()
 *	Duplicate the IOC information and return the IOC
 *	information.
 */
static ibdm_ioc_info_t *
ibdm_dup_ioc_info(ibdm_ioc_info_t *in_ioc, ibdm_dp_gidinfo_t *gid_list)
{
	ibdm_ioc_info_t	*out_ioc;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*out_ioc));
	ASSERT(MUTEX_HELD(&gid_list->gl_mutex));

	out_ioc = kmem_alloc(sizeof (ibdm_ioc_info_t), KM_SLEEP);
	bcopy(in_ioc, out_ioc, sizeof (ibdm_ioc_info_t));
	ibdm_update_ioc_port_gidlist(out_ioc, gid_list);
	out_ioc->ioc_iou_dc_valid = gid_list->gl_iou->iou_dc_valid;
	out_ioc->ioc_iou_diagcode = gid_list->gl_iou->iou_diagcode;

	return (out_ioc);
}


/*
 * ibdm_free_ioc_list()
 *	Deallocate memory for IOC list structure
 */
void
ibdm_ibnex_free_ioc_list(ibdm_ioc_info_t *ioc)
{
	ibdm_ioc_info_t *temp;

	IBTF_DPRINTF_L4("ibdm", "\tibnex_free_ioc_list:");
	while (ioc) {
		temp = ioc;
		ioc = ioc->ioc_next;
		kmem_free(temp->ioc_gid_list,
		    (sizeof (ibdm_gid_t) * temp->ioc_nportgids));
		if (temp->ioc_hca_list)
			ibdm_ibnex_free_hca_list(temp->ioc_hca_list);
		kmem_free(temp, sizeof (ibdm_ioc_info_t));
	}
}


/*
 * ibdm_ibnex_update_pkey_tbls
 *	Updates the DM P_Key database.
 *	NOTE: Two cases are handled here: P_Key being added or removed.
 *
 * Arguments		: NONE
 * Return Values	: NONE
 */
void
ibdm_ibnex_update_pkey_tbls(void)
{
	int			h, pp, pidx;
	uint_t			nports;
	uint_t			size;
	ib_pkey_t		new_pkey;
	ib_pkey_t		*orig_pkey;
	ibdm_hca_list_t		*hca_list;
	ibdm_port_attr_t	*port;
	ibt_hca_portinfo_t	*pinfop;

	IBTF_DPRINTF_L4("ibdm", "\tibnex_update_pkey_tbls:");

	mutex_enter(&ibdm.ibdm_hl_mutex);
	hca_list = ibdm.ibdm_hca_list_head;

	for (h = 0; h < ibdm.ibdm_hca_count; h++) {

		/* This updates P_Key Tables for all ports of this HCA */
		(void) ibt_query_hca_ports(hca_list->hl_hca_hdl, 0, &pinfop,
		    &nports, &size);

		/* number of ports shouldn't have changed */
		ASSERT(nports == hca_list->hl_nports);

		for (pp = 0; pp < hca_list->hl_nports; pp++) {
			port = &hca_list->hl_port_attr[pp];

			/*
			 * First figure out the P_Keys from IBTL.
			 * Three things could have happened:
			 *	New P_Keys added
			 *	Existing P_Keys removed
			 *	Both of the above two
			 *
			 * Loop through the P_Key Indices and check if a
			 * give P_Key_Ix matches that of the one seen by
			 * IBDM. If they match no action is needed.
			 *
			 * If they don't match:
			 *	1. if orig_pkey is invalid and new_pkey is valid
			 *		---> add new_pkey to DM database
			 *	2. if orig_pkey is valid and new_pkey is invalid
			 *		---> remove orig_pkey from DM database
			 *	3. if orig_pkey and new_pkey are both valid:
			 *		---> remov orig_pkey from DM database
			 *		---> add new_pkey to DM database
			 *	4. if orig_pkey and new_pkey are both invalid:
			 *		---> do nothing. Updated DM database.
			 */

			for (pidx = 0; pidx < port->pa_npkeys; pidx++) {
				new_pkey = pinfop[pp].p_pkey_tbl[pidx];
				orig_pkey = &port->pa_pkey_tbl[pidx].pt_pkey;

				/* keys match - do nothing */
				if (*orig_pkey == new_pkey)
					continue;

				if (IBDM_INVALID_PKEY(*orig_pkey) &&
				    !IBDM_INVALID_PKEY(new_pkey)) {
					/* P_Key was added */
					IBTF_DPRINTF_L5("ibdm",
					    "\tibnex_update_pkey_tbls: new "
					    "P_Key added = 0x%x", new_pkey);
					*orig_pkey = new_pkey;
					ibdm_port_attr_ibmf_init(port,
					    new_pkey, pp);
				} else if (!IBDM_INVALID_PKEY(*orig_pkey) &&
				    IBDM_INVALID_PKEY(new_pkey)) {
					/* P_Key was removed */
					IBTF_DPRINTF_L5("ibdm",
					    "\tibnex_update_pkey_tbls: P_Key "
					    "removed = 0x%x", *orig_pkey);
					*orig_pkey = new_pkey;
					(void) ibdm_port_attr_ibmf_fini(port,
					    pidx);
				} else if (!IBDM_INVALID_PKEY(*orig_pkey) &&
				    !IBDM_INVALID_PKEY(new_pkey)) {
					/* P_Key were replaced */
					IBTF_DPRINTF_L5("ibdm",
					    "\tibnex_update_pkey_tbls: P_Key "
					    "replaced 0x%x with 0x%x",
					    *orig_pkey, new_pkey);
					(void) ibdm_port_attr_ibmf_fini(port,
					    pidx);
					*orig_pkey = new_pkey;
					ibdm_port_attr_ibmf_init(port,
					    new_pkey, pp);
				} else {
					/*
					 * P_Keys are invalid
					 * set anyway to reflect if
					 * INVALID_FULL was changed to
					 * INVALID_LIMITED or vice-versa.
					 */
					*orig_pkey = new_pkey;
				} /* end of else */

			} /* loop of p_key index */

		} /* loop of #ports of HCA */

		ibt_free_portinfo(pinfop, size);
		hca_list = hca_list->hl_next;

	} /* loop for all HCAs in the system */

	mutex_exit(&ibdm.ibdm_hl_mutex);
}


/*
 * ibdm_send_ioc_profile()
 *	Send IOC Controller Profile request. When the request is completed
 *	IBMF calls ibdm_process_incoming_mad routine to inform about
 *	the completion.
 */
static int
ibdm_send_ioc_profile(ibdm_dp_gidinfo_t *gid_info, uint8_t ioc_no)
{
	ibmf_msg_t		*msg;
	ib_mad_hdr_t	*hdr;
	ibdm_ioc_info_t	*ioc_info = &(gid_info->gl_iou->iou_ioc_info[ioc_no]);
	ibdm_timeout_cb_args_t	*cb_args;

	IBTF_DPRINTF_L4("ibdm", "\tsend_ioc_profile: "
	    "gid info 0x%p, ioc_no = %d", gid_info, ioc_no);

	/*
	 * Send command to get IOC profile.
	 * Allocate a IBMF packet and initialize the packet.
	 */
	if (ibmf_alloc_msg(gid_info->gl_ibmf_hdl, IBMF_ALLOC_SLEEP,
	    &msg) != IBMF_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm", "\tsend_ioc_profile: pkt alloc fail");
		return (IBDM_FAILURE);
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*msg))
	ibdm_alloc_send_buffers(msg);
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*msg))

	mutex_enter(&gid_info->gl_mutex);
	ibdm_bump_transactionID(gid_info);
	mutex_exit(&gid_info->gl_mutex);

	msg->im_local_addr.ia_local_lid	= gid_info->gl_slid;
	msg->im_local_addr.ia_remote_lid	= gid_info->gl_dlid;
	if (gid_info->gl_redirected == B_TRUE) {
		if (gid_info->gl_redirect_dlid != 0) {
			msg->im_local_addr.ia_remote_lid =
			    gid_info->gl_redirect_dlid;
		}
		msg->im_local_addr.ia_remote_qno = gid_info->gl_redirect_QP;
		msg->im_local_addr.ia_p_key = gid_info->gl_redirect_pkey;
		msg->im_local_addr.ia_q_key = gid_info->gl_redirect_qkey;
		msg->im_local_addr.ia_service_level = gid_info->gl_redirectSL;
	} else {
		msg->im_local_addr.ia_remote_qno = 1;
		msg->im_local_addr.ia_p_key = gid_info->gl_p_key;
		msg->im_local_addr.ia_q_key = IB_GSI_QKEY;
		msg->im_local_addr.ia_service_level = gid_info->gl_SL;
	}

	hdr			= IBDM_OUT_IBMFMSG_MADHDR(msg);
	hdr->BaseVersion	= MAD_CLASS_BASE_VERS_1;
	hdr->MgmtClass		= MAD_MGMT_CLASS_DEV_MGT;
	hdr->ClassVersion	= IB_DM_CLASS_VERSION_1;
	hdr->R_Method		= IB_DM_DEVMGT_METHOD_GET;
	hdr->Status		= 0;
	hdr->TransactionID	= h2b64(gid_info->gl_transactionID);
	hdr->AttributeID	= h2b16(IB_DM_ATTR_IOC_CTRL_PROFILE);
	hdr->AttributeModifier 	= h2b32(ioc_no + 1);

	ioc_info->ioc_state	= IBDM_IOC_STATE_REPROBE_PROGRESS;
	cb_args			= &ioc_info->ioc_cb_args;
	cb_args->cb_gid_info	= gid_info;
	cb_args->cb_retry_count	= ibdm_dft_retry_cnt;
	cb_args->cb_req_type	= IBDM_REQ_TYPE_IOCINFO;
	cb_args->cb_ioc_num	= ioc_no;

	mutex_enter(&gid_info->gl_mutex);
	ioc_info->ioc_timeout_id = timeout(ibdm_pkt_timeout_hdlr,
	    cb_args, IBDM_TIMEOUT_VALUE(ibdm_dft_timeout));
	mutex_exit(&gid_info->gl_mutex);

	IBTF_DPRINTF_L5("ibdm", "\tsend_ioc_profile:"
	    "timeout %x", ioc_info->ioc_timeout_id);

	if (ibmf_msg_transport(gid_info->gl_ibmf_hdl, gid_info->gl_qp_hdl, msg,
	    NULL, ibdm_ibmf_send_cb, cb_args, 0) != IBMF_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm",
		    "\tsend_ioc_profile: msg transport failed");
		ibdm_ibmf_send_cb(gid_info->gl_ibmf_hdl, msg, cb_args);
	}
	ioc_info->ioc_state = IBDM_IOC_STATE_REPROBE_PROGRESS;
	return (IBDM_SUCCESS);
}


/*
 * ibdm_port_reachable
 *	Returns B_TRUE if the port GID is reachable by sending
 *	a SA query to get the NODE record for this port GUID.
 */
static boolean_t
ibdm_port_reachable(ibmf_saa_handle_t sa_hdl, ib_guid_t guid)
{
	sa_node_record_t *resp;
	size_t length;

	/*
	 * Verify if it's reachable by getting the node record.
	 */
	if (ibdm_get_node_record_by_port(sa_hdl, guid, &resp, &length) ==
	    IBDM_SUCCESS) {
		kmem_free(resp, length);
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * ibdm_get_node_record_by_port
 *	Sends a SA query to get the NODE record for port GUID
 *	Returns IBDM_SUCCESS if the port GID is reachable.
 *
 *      Note: the caller must be responsible for freeing the resource
 *      by calling kmem_free(resp, length) later.
 */
static int
ibdm_get_node_record_by_port(ibmf_saa_handle_t sa_hdl, ib_guid_t guid,
    sa_node_record_t **resp, size_t *length)
{
	sa_node_record_t	req;
	ibmf_saa_access_args_t	args;
	int			ret;
	ASSERT(resp != NULL && length != NULL);

	IBTF_DPRINTF_L4("ibdm", "\tport_reachable: port_guid %llx",
	    guid);

	bzero(&req, sizeof (sa_node_record_t));
	req.NodeInfo.PortGUID = guid;

	args.sq_attr_id		= SA_NODERECORD_ATTRID;
	args.sq_access_type 	= IBMF_SAA_RETRIEVE;
	args.sq_component_mask 	= SA_NODEINFO_COMPMASK_PORTGUID;
	args.sq_template	= &req;
	args.sq_callback	= NULL;
	args.sq_callback_arg 	= NULL;

	ret = ibmf_sa_access(sa_hdl, &args, 0, length, (void **) resp);
	if (ret != IBMF_SUCCESS) {
		IBTF_DPRINTF_L2("ibdm", "\tport_reachable:"
		    " SA Retrieve Failed: %d", ret);
		return (IBDM_FAILURE);
	}
	if (*resp == NULL || *length == 0) {
		IBTF_DPRINTF_L2("ibdm", "\tport_reachable: No records");
		return (IBDM_FAILURE);
	}
	/*
	 * There is one NodeRecord on each endport on a subnet.
	 */
	ASSERT(*length == sizeof (sa_node_record_t));

	return (IBDM_SUCCESS);
}


/*
 * Update the gidlist for all affected IOCs when GID becomes
 * available/unavailable.
 *
 * Parameters :
 *	gidinfo - Incoming / Outgoing GID.
 *	add_flag - 1 for GID added, 0 for GID removed.
 *		- (-1) : IOC gid list updated, ioc_list required.
 *
 * This function gets the GID for the node GUID corresponding to the
 * port GID. Gets the IOU info
 */
static ibdm_ioc_info_t *
ibdm_update_ioc_gidlist(ibdm_dp_gidinfo_t *gid_info, int avail_flag)
{
	ibdm_dp_gidinfo_t	*node_gid = NULL;
	uint8_t	niocs, ii;
	ibdm_ioc_info_t	*ioc, *ioc_list = NULL, *tmp;

	IBTF_DPRINTF_L4("ibdm", "\tupdate_ioc_gidlist");

	switch (avail_flag) {
		case 1 :
			node_gid = ibdm_check_dest_nodeguid(gid_info);
			break;
		case 0 :
			node_gid = ibdm_handle_gid_rm(gid_info);
			break;
		case -1 :
			node_gid = gid_info;
			break;
		default :
			break;
	}

	if (node_gid == NULL) {
		IBTF_DPRINTF_L4("ibdm", "\tupdate_ioc_gidlist: "
		    "No node GID found, port gid 0x%p, avail_flag %d",
		    gid_info, avail_flag);
		return (NULL);
	}

	mutex_enter(&node_gid->gl_mutex);
	if ((node_gid->gl_state != IBDM_GID_PROBING_COMPLETE &&
	    node_gid->gl_state != IBDM_GID_PROBING_SKIPPED) ||
	    node_gid->gl_iou == NULL) {
		IBTF_DPRINTF_L4("ibdm", "\tupdate_ioc_gidlist "
		    "gl_state %x, gl_iou %p", node_gid->gl_state,
		    node_gid->gl_iou);
		mutex_exit(&node_gid->gl_mutex);
		return (NULL);
	}

	niocs = node_gid->gl_iou->iou_info.iou_num_ctrl_slots;
	IBTF_DPRINTF_L4("ibdm", "\tupdate_ioc_gidlist : niocs %x",
	    niocs);
	for (ii = 0; ii < niocs; ii++) {
		ioc = IBDM_GIDINFO2IOCINFO(node_gid, ii);
		/*
		 * Skip IOCs for which probe is not complete or
		 * reprobe is progress
		 */
		if (ioc->ioc_state == IBDM_IOC_STATE_PROBE_SUCCESS) {
			tmp = ibdm_dup_ioc_info(ioc, node_gid);
			tmp->ioc_info_updated.ib_gid_prop_updated = 1;
			tmp->ioc_next = ioc_list;
			ioc_list = tmp;
		}
	}
	mutex_exit(&node_gid->gl_mutex);

	IBTF_DPRINTF_L4("ibdm", "\tupdate_ioc_gidlist : return %p",
	    ioc_list);
	return (ioc_list);
}

/*
 * ibdm_saa_event_cb :
 *	Event handling which does *not* require ibdm_hl_mutex to be
 *	held are executed in the same thread. This is to prevent
 *	deadlocks with HCA port down notifications which hold the
 *	ibdm_hl_mutex.
 *
 *	GID_AVAILABLE event is handled here. A taskq is spawned to
 *	handle GID_UNAVAILABLE.
 *
 *	A new mutex ibdm_ibnex_mutex has been introduced to protect
 *	ibnex_callback. This has been done to prevent any possible
 *	deadlock (described above) while handling GID_AVAILABLE.
 *
 *	IBMF calls the event callback for a HCA port. The SA handle
 *	for this port would be valid, till the callback returns.
 *	IBDM calling IBDM using the above SA handle should be valid.
 *
 *	IBDM will additionally  check (SA handle != NULL), before
 *	calling IBMF.
 */
/*ARGSUSED*/
static void
ibdm_saa_event_cb(ibmf_saa_handle_t ibmf_saa_handle,
    ibmf_saa_subnet_event_t ibmf_saa_event,
    ibmf_saa_event_details_t *event_details, void *callback_arg)
{
	ibdm_saa_event_arg_t *event_arg;
	ib_gid_t		sgid, dgid;
	ibdm_port_attr_t	*hca_port;
	ibdm_dp_gidinfo_t	*gid_info, *node_gid_info = NULL;
	sa_node_record_t *nrec;
	size_t length;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*event_arg));

	hca_port = (ibdm_port_attr_t *)callback_arg;

	IBTF_DPRINTF_L4("ibdm", "\tsaa_event_cb(%x, %x, %x, %x)\n",
	    ibmf_saa_handle, ibmf_saa_event, event_details,
	    callback_arg);

#ifdef DEBUG
	if (ibdm_ignore_saa_event)
		return;
#endif

	if (ibmf_saa_event == IBMF_SAA_EVENT_GID_AVAILABLE) {
		/*
		 * Ensure no other probe / sweep fabric is in
		 * progress.
		 */
		mutex_enter(&ibdm.ibdm_mutex);
		while (ibdm.ibdm_busy & IBDM_BUSY)
			cv_wait(&ibdm.ibdm_busy_cv, &ibdm.ibdm_mutex);
		ibdm.ibdm_busy |= IBDM_BUSY;
		mutex_exit(&ibdm.ibdm_mutex);

		/*
		 * If we already know about this GID, return.
		 * GID_AVAILABLE may be reported for multiple HCA
		 * ports.
		 */
		if ((ibdm_check_dgid(event_details->ie_gid.gid_guid,
		    event_details->ie_gid.gid_prefix))  != NULL) {
			mutex_enter(&ibdm.ibdm_mutex);
			ibdm.ibdm_busy &= ~IBDM_BUSY;
			cv_broadcast(&ibdm.ibdm_busy_cv);
			mutex_exit(&ibdm.ibdm_mutex);
			return;
		}

		IBTF_DPRINTF_L4("ibdm", "\tGID (prefix %x, guid %llx) "
		    "Insertion notified",
		    event_details->ie_gid.gid_prefix,
		    event_details->ie_gid.gid_guid);

		/* This is a new gid, insert it to GID list */
		sgid.gid_prefix = hca_port->pa_sn_prefix;
		sgid.gid_guid = hca_port->pa_port_guid;
		dgid.gid_prefix = event_details->ie_gid.gid_prefix;
		dgid.gid_guid = event_details->ie_gid.gid_guid;
		gid_info = ibdm_create_gid_info(hca_port, sgid, dgid);
		if (gid_info == NULL) {
			IBTF_DPRINTF_L4("ibdm", "\tGID_AVAILABLE: "
			    "create_gid_info returned NULL");
			mutex_enter(&ibdm.ibdm_mutex);
			ibdm.ibdm_busy &= ~IBDM_BUSY;
			cv_broadcast(&ibdm.ibdm_busy_cv);
			mutex_exit(&ibdm.ibdm_mutex);
			return;
		}
		mutex_enter(&gid_info->gl_mutex);
		gid_info->gl_state = IBDM_GID_PROBING_SKIPPED;
		mutex_exit(&gid_info->gl_mutex);

		/* Get the node GUID */
		if (ibdm_get_node_record_by_port(ibmf_saa_handle, dgid.gid_guid,
		    &nrec, &length) != IBDM_SUCCESS) {
			/*
			 * Set the state to PROBE_NOT_DONE for the
			 * next sweep to probe it
			 */
			IBTF_DPRINTF_L2("ibdm", "\tsaa_event_taskq: "
			    "Skipping GID : port GUID not found");
			mutex_enter(&gid_info->gl_mutex);
			gid_info->gl_state = IBDM_GID_PROBE_NOT_DONE;
			mutex_exit(&gid_info->gl_mutex);
			mutex_enter(&ibdm.ibdm_mutex);
			ibdm.ibdm_busy &= ~IBDM_BUSY;
			cv_broadcast(&ibdm.ibdm_busy_cv);
			mutex_exit(&ibdm.ibdm_mutex);
			return;
		}
		gid_info->gl_nodeguid = nrec->NodeInfo.NodeGUID;
		gid_info->gl_devid = nrec->NodeInfo.DeviceID;
		kmem_free(nrec, length);
		gid_info->gl_portguid = dgid.gid_guid;

		/*
		 * Get the gid info with the same node GUID.
		 */
		mutex_enter(&ibdm.ibdm_mutex);
		node_gid_info = ibdm.ibdm_dp_gidlist_head;
		while (node_gid_info) {
			if (node_gid_info->gl_nodeguid ==
			    gid_info->gl_nodeguid &&
			    node_gid_info->gl_iou != NULL) {
				break;
			}
			node_gid_info = node_gid_info->gl_next;
		}
		mutex_exit(&ibdm.ibdm_mutex);

		/*
		 * Handling a new GID requires filling of gl_hca_list.
		 * This require ibdm hca_list to be parsed and hence
		 * holding the ibdm_hl_mutex. Spawning a new thread to
		 * handle this.
		 */
		if (node_gid_info == NULL) {
			if (taskq_dispatch(system_taskq,
			    ibdm_saa_handle_new_gid, (void *)gid_info,
			    TQ_NOSLEEP) == NULL) {
				IBTF_DPRINTF_L2("ibdm", "\tsaa_event_cb: "
				    "new_gid taskq_dispatch failed");
				return;
			}
		}

		mutex_enter(&ibdm.ibdm_mutex);
		ibdm.ibdm_busy &= ~IBDM_BUSY;
		cv_broadcast(&ibdm.ibdm_busy_cv);
		mutex_exit(&ibdm.ibdm_mutex);
		return;
	}

	if (ibmf_saa_event != IBMF_SAA_EVENT_GID_UNAVAILABLE)
		return;

	/*
	 * GID UNAVAIL EVENT: Try to locate the GID in the GID list.
	 * If we don't find it we just return.
	 */
	mutex_enter(&ibdm.ibdm_mutex);
	gid_info = ibdm.ibdm_dp_gidlist_head;
	while (gid_info) {
		if (gid_info->gl_portguid ==
		    event_details->ie_gid.gid_guid) {
			break;
		}
		gid_info = gid_info->gl_next;
	}
	mutex_exit(&ibdm.ibdm_mutex);
	if (gid_info == NULL) {
		IBTF_DPRINTF_L2("ibdm", "\tsaa_event_cb: "
		    "GID for GUID %llX not found during GID UNAVAIL event",
		    event_details->ie_gid.gid_guid);
		return;
	}

	/*
	 * If this GID is DM capable, we'll have to check whether this DGID
	 * is reachable via another port.
	 */
	if (gid_info->gl_is_dm_capable == B_TRUE) {
		event_arg = (ibdm_saa_event_arg_t *)kmem_alloc(
		    sizeof (ibdm_saa_event_arg_t), KM_SLEEP);
		event_arg->ibmf_saa_handle = ibmf_saa_handle;
		event_arg->ibmf_saa_event = ibmf_saa_event;
		bcopy(event_details, &event_arg->event_details,
		    sizeof (ibmf_saa_event_details_t));
		event_arg->callback_arg = callback_arg;

		if (taskq_dispatch(system_taskq, ibdm_saa_event_taskq,
		    (void *)event_arg, TQ_NOSLEEP) == NULL) {
			IBTF_DPRINTF_L2("ibdm", "\tsaa_event_cb: "
			    "taskq_dispatch failed");
			ibdm_free_saa_event_arg(event_arg);
			return;
		}
	}
}

/*
 * Handle a new GID discovered by GID_AVAILABLE saa event.
 */
void
ibdm_saa_handle_new_gid(void *arg)
{
	ibdm_dp_gidinfo_t	*gid_info;
	ibdm_hca_list_t		*hca_list = NULL;
	ibdm_port_attr_t	*port = NULL;
	ibdm_ioc_info_t		*ioc_list = NULL;

	IBTF_DPRINTF_L4(ibdm_string, "\tsaa_handle_new_gid(%p)", arg);

	gid_info = (ibdm_dp_gidinfo_t *)arg;

	/*
	 * Ensure that no other sweep / probe has completed
	 * probing this gid.
	 */
	mutex_enter(&gid_info->gl_mutex);
	if (gid_info->gl_state != IBDM_GID_PROBE_NOT_DONE) {
		mutex_exit(&gid_info->gl_mutex);
		return;
	}
	mutex_exit(&gid_info->gl_mutex);

	/*
	 * Parse HCAs to fill gl_hca_list
	 */
	mutex_enter(&ibdm.ibdm_hl_mutex);
	for (ibdm_get_next_port(&hca_list, &port, 1); port;
	    ibdm_get_next_port(&hca_list, &port, 1)) {
		if (ibdm_port_reachable(port->pa_sa_hdl,
		    gid_info->gl_portguid) == B_TRUE) {
			ibdm_addto_glhcalist(gid_info, hca_list);
		}
	}
	mutex_exit(&ibdm.ibdm_hl_mutex);

	/*
	 * Ensure no other probe / sweep fabric is in
	 * progress.
	 */
	mutex_enter(&ibdm.ibdm_mutex);
	while (ibdm.ibdm_busy & IBDM_BUSY)
		cv_wait(&ibdm.ibdm_busy_cv, &ibdm.ibdm_mutex);
	ibdm.ibdm_busy |= IBDM_BUSY;
	mutex_exit(&ibdm.ibdm_mutex);

	/*
	 * New IOU probe it, to check if new IOCs
	 */
	IBTF_DPRINTF_L4(ibdm_string, "\tsaa_handle_new_gid: "
	    "new GID : probing");
	mutex_enter(&ibdm.ibdm_mutex);
	ibdm.ibdm_ngid_probes_in_progress++;
	mutex_exit(&ibdm.ibdm_mutex);
	mutex_enter(&gid_info->gl_mutex);
	gid_info->gl_reprobe_flag = 0;
	gid_info->gl_state = IBDM_GID_PROBE_NOT_DONE;
	mutex_exit(&gid_info->gl_mutex);
	ibdm_probe_gid_thread((void *)gid_info);

	mutex_enter(&ibdm.ibdm_mutex);
	ibdm_wait_probe_completion();
	mutex_exit(&ibdm.ibdm_mutex);

	if (gid_info->gl_iou == NULL) {
		mutex_enter(&ibdm.ibdm_mutex);
		ibdm.ibdm_busy &= ~IBDM_BUSY;
		cv_broadcast(&ibdm.ibdm_busy_cv);
		mutex_exit(&ibdm.ibdm_mutex);
		return;
	}

	/*
	 * Update GID list in all IOCs affected by this
	 */
	ioc_list = ibdm_update_ioc_gidlist(gid_info, 1);

	/*
	 * Pass on the IOCs with updated GIDs to IBnexus
	 */
	if (ioc_list) {
		mutex_enter(&ibdm.ibdm_ibnex_mutex);
		if (ibdm.ibdm_ibnex_callback != NULL) {
			(*ibdm.ibdm_ibnex_callback)((void *)ioc_list,
			    IBDM_EVENT_IOC_PROP_UPDATE);
		}
		mutex_exit(&ibdm.ibdm_ibnex_mutex);
	}

	mutex_enter(&ibdm.ibdm_mutex);
	ibdm.ibdm_busy &= ~IBDM_BUSY;
	cv_broadcast(&ibdm.ibdm_busy_cv);
	mutex_exit(&ibdm.ibdm_mutex);
}

/*
 * ibdm_saa_event_taskq :
 *	GID_UNAVAILABLE Event handling requires ibdm_hl_mutex to be
 *	held. The GID_UNAVAILABLE handling is done in a taskq to
 *	prevent deadlocks with HCA port down notifications which hold
 *	ibdm_hl_mutex.
 */
void
ibdm_saa_event_taskq(void *arg)
{
	ibdm_saa_event_arg_t *event_arg;
	ibmf_saa_handle_t ibmf_saa_handle;
	ibmf_saa_subnet_event_t ibmf_saa_event;
	ibmf_saa_event_details_t *event_details;
	void *callback_arg;

	ibdm_dp_gidinfo_t	*gid_info;
	ibdm_port_attr_t	*hca_port, *port = NULL;
	ibdm_hca_list_t		*hca_list = NULL;
	int	sa_handle_valid = 0;
	ibdm_ioc_info_t		*ioc_list = NULL;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*event_arg));

	event_arg = (ibdm_saa_event_arg_t *)arg;
	ibmf_saa_handle = event_arg->ibmf_saa_handle;
	ibmf_saa_event = event_arg->ibmf_saa_event;
	event_details = &event_arg->event_details;
	callback_arg = event_arg->callback_arg;

	ASSERT(callback_arg != NULL);
	ASSERT(ibmf_saa_event == IBMF_SAA_EVENT_GID_UNAVAILABLE);
	IBTF_DPRINTF_L4("ibdm", "\tsaa_event_taskq(%x, %x, %x, %x)",
	    ibmf_saa_handle, ibmf_saa_event, event_details,
	    callback_arg);

	hca_port = (ibdm_port_attr_t *)callback_arg;

	/* Check if the port_attr is still valid */
	mutex_enter(&ibdm.ibdm_hl_mutex);
	for (ibdm_get_next_port(&hca_list, &port, 0); port;
	    ibdm_get_next_port(&hca_list, &port, 0)) {
		if (port == hca_port && port->pa_port_guid ==
		    hca_port->pa_port_guid) {
			if (ibmf_saa_handle == hca_port->pa_sa_hdl)
				sa_handle_valid = 1;
			break;
		}
	}
	mutex_exit(&ibdm.ibdm_hl_mutex);
	if (sa_handle_valid == 0) {
		ibdm_free_saa_event_arg(event_arg);
		return;
	}

	if (hca_port && (hca_port->pa_sa_hdl == NULL ||
	    ibmf_saa_handle != hca_port->pa_sa_hdl)) {
		ibdm_free_saa_event_arg(event_arg);
		return;
	}
	hca_list = NULL;
	port = NULL;

	/*
	 * Check if the GID is visible to other HCA ports.
	 * Return if so.
	 */
	mutex_enter(&ibdm.ibdm_hl_mutex);
	for (ibdm_get_next_port(&hca_list, &port, 1); port;
	    ibdm_get_next_port(&hca_list, &port, 1)) {
		if (ibdm_port_reachable(port->pa_sa_hdl,
		    event_details->ie_gid.gid_guid) == B_TRUE) {
			mutex_exit(&ibdm.ibdm_hl_mutex);
			ibdm_free_saa_event_arg(event_arg);
			return;
		}
	}
	mutex_exit(&ibdm.ibdm_hl_mutex);

	/*
	 * Ensure no other probe / sweep fabric is in
	 * progress.
	 */
	mutex_enter(&ibdm.ibdm_mutex);
	while (ibdm.ibdm_busy & IBDM_BUSY)
		cv_wait(&ibdm.ibdm_busy_cv, &ibdm.ibdm_mutex);
	ibdm.ibdm_busy |= IBDM_BUSY;
	mutex_exit(&ibdm.ibdm_mutex);

	/*
	 * If this GID is no longer in GID list, return
	 * GID_UNAVAILABLE may be reported for multiple HCA
	 * ports.
	 */
	mutex_enter(&ibdm.ibdm_mutex);
	gid_info = ibdm.ibdm_dp_gidlist_head;
	while (gid_info) {
		if (gid_info->gl_portguid ==
		    event_details->ie_gid.gid_guid) {
			break;
		}
		gid_info = gid_info->gl_next;
	}
	mutex_exit(&ibdm.ibdm_mutex);
	if (gid_info == NULL) {
		mutex_enter(&ibdm.ibdm_mutex);
		ibdm.ibdm_busy &= ~IBDM_BUSY;
		cv_broadcast(&ibdm.ibdm_busy_cv);
		mutex_exit(&ibdm.ibdm_mutex);
		ibdm_free_saa_event_arg(event_arg);
		return;
	}

	IBTF_DPRINTF_L4("ibdm", "\tGID (prefix %x, guid %llx) "
	    "Unavailable notification",
	    event_details->ie_gid.gid_prefix,
	    event_details->ie_gid.gid_guid);

	/*
	 * Update GID list in all IOCs affected by this
	 */
	if (gid_info->gl_state == IBDM_GID_PROBING_SKIPPED ||
	    gid_info->gl_state == IBDM_GID_PROBING_COMPLETE)
		ioc_list = ibdm_update_ioc_gidlist(gid_info, 0);

	/*
	 * Remove GID from the global GID list
	 * Handle the case where all port GIDs for an
	 * IOU have been hot-removed. Check both gid_info
	 * & ioc_info for checking ngids.
	 */
	mutex_enter(&ibdm.ibdm_mutex);
	if (gid_info->gl_iou != NULL && gid_info->gl_ngids == 0) {
		mutex_enter(&gid_info->gl_mutex);
		(void) ibdm_free_iou_info(gid_info, &gid_info->gl_iou);
		mutex_exit(&gid_info->gl_mutex);
	}
	if (gid_info->gl_prev != NULL)
		gid_info->gl_prev->gl_next = gid_info->gl_next;
	if (gid_info->gl_next != NULL)
		gid_info->gl_next->gl_prev = gid_info->gl_prev;

	if (gid_info == ibdm.ibdm_dp_gidlist_head)
		ibdm.ibdm_dp_gidlist_head = gid_info->gl_next;
	if (gid_info == ibdm.ibdm_dp_gidlist_tail)
		ibdm.ibdm_dp_gidlist_tail = gid_info->gl_prev;
	ibdm.ibdm_ngids--;

	ibdm.ibdm_busy &= ~IBDM_BUSY;
	cv_broadcast(&ibdm.ibdm_busy_cv);
	mutex_exit(&ibdm.ibdm_mutex);

	/* free the hca_list on this gid_info */
	ibdm_delete_glhca_list(gid_info);

	mutex_destroy(&gid_info->gl_mutex);
	kmem_free(gid_info, sizeof (ibdm_dp_gidinfo_t));

	/*
	 * Pass on the IOCs with updated GIDs to IBnexus
	 */
	if (ioc_list) {
		IBTF_DPRINTF_L4("ibdm", "\tGID_UNAVAILABLE "
		    "IOC_PROP_UPDATE for %p\n", ioc_list);
		mutex_enter(&ibdm.ibdm_ibnex_mutex);
		if (ibdm.ibdm_ibnex_callback != NULL) {
			(*ibdm.ibdm_ibnex_callback)((void *)
			    ioc_list, IBDM_EVENT_IOC_PROP_UPDATE);
		}
		mutex_exit(&ibdm.ibdm_ibnex_mutex);
	}

	ibdm_free_saa_event_arg(event_arg);
}


static int
ibdm_cmp_gid_list(ibdm_gid_t *new, ibdm_gid_t *prev)
{
	ibdm_gid_t		*scan_new, *scan_prev;
	int	cmp_failed = 0;

	ASSERT(new != NULL);
	ASSERT(prev != NULL);

	/*
	 * Search for each new gid anywhere in the prev GID list.
	 * Note that the gid list could have been re-ordered.
	 */
	for (scan_new = new; scan_new; scan_new = scan_new->gid_next) {
		for (scan_prev = prev, cmp_failed = 1; scan_prev;
		    scan_prev = scan_prev->gid_next) {
			if (scan_prev->gid_dgid_hi == scan_new->gid_dgid_hi &&
			    scan_prev->gid_dgid_lo == scan_new->gid_dgid_lo) {
				cmp_failed = 0;
				break;
			}
		}

		if (cmp_failed)
			return (1);
	}
	return (0);
}

/*
 * This is always called in a single thread
 * This function updates the gid_list and serv_list of IOC
 * The current gid_list is in ioc_info_t(contains only port
 * guids for which probe is done) & gidinfo_t(other port gids)
 * The gids in both locations are used for comparision.
 */
static void
ibdm_reprobe_update_port_srv(ibdm_ioc_info_t *ioc, ibdm_dp_gidinfo_t *gidinfo)
{
	ibdm_gid_t		*cur_gid_list;
	uint_t			cur_nportgids;

	ASSERT(MUTEX_HELD(&ibdm.ibdm_mutex));

	ioc->ioc_info_updated.ib_prop_updated = 0;


	/* Current GID list in gid_info only */
	cur_gid_list = gidinfo->gl_gid;
	cur_nportgids = gidinfo->gl_ngids;

	if (ioc->ioc_prev_serv_cnt !=
	    ioc->ioc_profile.ioc_service_entries ||
	    ibdm_serv_cmp(&ioc->ioc_serv[0], &ioc->ioc_prev_serv[0],
	    ioc->ioc_prev_serv_cnt))
		ioc->ioc_info_updated.ib_srv_prop_updated = 1;

	if (ioc->ioc_prev_nportgids != cur_nportgids ||
	    ioc->ioc_prev_gid_list == NULL || cur_gid_list == NULL) {
		ioc->ioc_info_updated.ib_gid_prop_updated = 1;
	} else if (ibdm_cmp_gid_list(ioc->ioc_prev_gid_list, cur_gid_list)) {
		ioc->ioc_info_updated.ib_gid_prop_updated = 1;
	}

	/* Zero out previous entries */
	ibdm_free_gid_list(ioc->ioc_prev_gid_list);
	if (ioc->ioc_prev_serv)
		kmem_free(ioc->ioc_prev_serv, ioc->ioc_prev_serv_cnt *
		    sizeof (ibdm_srvents_info_t));
	ioc->ioc_prev_serv_cnt = 0;
	ioc->ioc_prev_nportgids = 0;
	ioc->ioc_prev_serv = NULL;
	ioc->ioc_prev_gid_list = NULL;
}

/*
 * Handle GID removal. This returns gid_info of an GID for the same
 * node GUID, if found.  For an GID with IOU information, the same
 * gid_info is returned if no gid_info with same node_guid is found.
 */
static ibdm_dp_gidinfo_t *
ibdm_handle_gid_rm(ibdm_dp_gidinfo_t *rm_gid)
{
	ibdm_dp_gidinfo_t	*gid_list;

	IBTF_DPRINTF_L4("ibdm", "\thandle_gid_rm(0x%p)", rm_gid);

	if (rm_gid->gl_iou == NULL) {
		IBTF_DPRINTF_L4("ibdm", "\thandle_gid_rm NO iou");
		/*
		 * Search for a GID with same node_guid and
		 * gl_iou != NULL
		 */
		for (gid_list = ibdm.ibdm_dp_gidlist_head; gid_list;
		    gid_list = gid_list->gl_next) {
			if (gid_list->gl_iou != NULL && (gid_list->gl_nodeguid
			    == rm_gid->gl_nodeguid))
				break;
		}

		if (gid_list)
			ibdm_rmfrom_glgid_list(gid_list, rm_gid);

		IBTF_DPRINTF_L4("ibdm", "\thandle_gid_rm ret %p", gid_list);
		return (gid_list);
	} else {
		/*
		 * Search for a GID with same node_guid and
		 * gl_iou == NULL
		 */
		IBTF_DPRINTF_L4("ibdm", "\thandle_gid_rm with iou");
		for (gid_list = ibdm.ibdm_dp_gidlist_head; gid_list;
		    gid_list = gid_list->gl_next) {
			if (gid_list->gl_iou == NULL && (gid_list->gl_nodeguid
			    == rm_gid->gl_nodeguid))
				break;
		}

		if (gid_list) {
			/*
			 * Copy the following fields from rm_gid :
			 *	1. gl_state
			 *	2. gl_iou
			 *	3. gl_gid & gl_ngids
			 *
			 * Note :	Function is synchronized by
			 *			ibdm_busy flag.
			 *
			 * Note :	Redirect info is initialized if
			 *			any MADs for the GID fail
			 */
			IBTF_DPRINTF_L4("ibdm", "\thandle_gid_rm "
			    "copying info to GID with gl_iou != NULl");
			gid_list->gl_state = rm_gid->gl_state;
			gid_list->gl_iou = rm_gid->gl_iou;
			gid_list->gl_gid = rm_gid->gl_gid;
			gid_list->gl_ngids = rm_gid->gl_ngids;

			/* Remove the GID from gl_gid list */
			ibdm_rmfrom_glgid_list(gid_list, rm_gid);
		} else {
			/*
			 * Handle a case where all GIDs to the IOU have
			 * been removed.
			 */
			IBTF_DPRINTF_L4("ibdm", "\thandle_gid_rm 0 GID "
			    "to IOU");

			ibdm_rmfrom_glgid_list(rm_gid, rm_gid);
			return (rm_gid);
		}
		IBTF_DPRINTF_L4("ibdm", "\thandle_gid_rm ret %p", gid_list);
		return (gid_list);
	}
}

static void
ibdm_rmfrom_glgid_list(ibdm_dp_gidinfo_t *gid_info,
    ibdm_dp_gidinfo_t *rm_gid)
{
	ibdm_gid_t 		*tmp, *prev;

	IBTF_DPRINTF_L4("ibdm", "\trmfrom_glgid (%p, %p)",
	    gid_info, rm_gid);

	for (tmp = gid_info->gl_gid, prev = NULL; tmp; ) {
		if (tmp->gid_dgid_hi == rm_gid->gl_dgid_hi &&
		    tmp->gid_dgid_lo == rm_gid->gl_dgid_lo) {
			if (prev == NULL)
				gid_info->gl_gid = tmp->gid_next;
			else
				prev->gid_next = tmp->gid_next;

			kmem_free(tmp, sizeof (ibdm_gid_t));
			gid_info->gl_ngids--;
			break;
		} else {
			prev = tmp;
			tmp = tmp->gid_next;
		}
	}
}

static void
ibdm_addto_gidlist(ibdm_gid_t **src_ptr, ibdm_gid_t *dest)
{
	ibdm_gid_t *head = NULL, *new, *tail;

	/* First copy the destination */
	for (; dest; dest = dest->gid_next) {
		new = kmem_zalloc(sizeof (ibdm_gid_t), KM_SLEEP);
		new->gid_dgid_hi = dest->gid_dgid_hi;
		new->gid_dgid_lo = dest->gid_dgid_lo;
		new->gid_next = head;
		head = new;
	}

	/* Insert this to the source */
	if (*src_ptr == NULL)
		*src_ptr = head;
	else {
		for (tail = *src_ptr; tail->gid_next != NULL;
		    tail = tail->gid_next)
			;

		tail->gid_next = head;
	}
}

static void
ibdm_free_gid_list(ibdm_gid_t	*head)
{
	ibdm_gid_t	*delete;

	for (delete = head; delete; ) {
		head = delete->gid_next;
		kmem_free(delete, sizeof (ibdm_gid_t));
		delete = head;
	}
}

/*
 * This function rescans the DM capable GIDs (gl_state is
 * GID_PROBE_COMPLETE or IBDM_GID_PROBING_SKIPPED.This
 * basically checks if the DM capable GID is reachable. If
 * not this is handled the same way as GID_UNAVAILABLE,
 * except that notifications are not send to IBnexus.
 *
 * This function also initializes the ioc_prev_list for
 * a particular IOC (when called from probe_ioc, with
 * ioc_guidp != NULL) or all IOCs for the gid (called from
 * sweep_fabric, ioc_guidp == NULL).
 */
static void
ibdm_rescan_gidlist(ib_guid_t *ioc_guidp)
{
	ibdm_dp_gidinfo_t	*gid_info, *tmp;
	int ii, niocs, found;
	ibdm_hca_list_t *hca_list = NULL;
	ibdm_port_attr_t *port = NULL;
	ibdm_ioc_info_t *ioc_list;

	for (gid_info = ibdm.ibdm_dp_gidlist_head; gid_info; ) {
		found = 0;
		if (gid_info->gl_state != IBDM_GID_PROBING_SKIPPED &&
		    gid_info->gl_state != IBDM_GID_PROBING_COMPLETE) {
			gid_info = gid_info->gl_next;
			continue;
		}

		/*
		 * Check if the GID is visible to any HCA ports.
		 * Return if so.
		 */
		mutex_enter(&ibdm.ibdm_hl_mutex);
		for (ibdm_get_next_port(&hca_list, &port, 1); port;
		    ibdm_get_next_port(&hca_list, &port, 1)) {
			if (ibdm_port_reachable(port->pa_sa_hdl,
			    gid_info->gl_dgid_lo) == B_TRUE) {
				found = 1;
				break;
			}
		}
		mutex_exit(&ibdm.ibdm_hl_mutex);

		if (found) {
			if (gid_info->gl_iou == NULL) {
				gid_info = gid_info->gl_next;
				continue;
			}

			/* Intialize the ioc_prev_gid_list */
			niocs =
			    gid_info->gl_iou->iou_info.iou_num_ctrl_slots;
			for (ii = 0; ii < niocs; ii++) {
				ioc_list = IBDM_GIDINFO2IOCINFO(gid_info, ii);

				if (ioc_guidp == NULL || (*ioc_guidp ==
				    ioc_list->ioc_profile.ioc_guid)) {
					/* Add info of GIDs in gid_info also */
					ibdm_addto_gidlist(
					    &ioc_list->ioc_prev_gid_list,
					    gid_info->gl_gid);
					ioc_list->ioc_prev_nportgids =
					    gid_info->gl_ngids;
				}
			}
			gid_info = gid_info->gl_next;
			continue;
		}

		IBTF_DPRINTF_L4("ibdm", "\trescan_gidlist "
		    "deleted port GUID %llx",
		    gid_info->gl_dgid_lo);

		/*
		 * Update GID list in all IOCs affected by this
		 */
		ioc_list = ibdm_update_ioc_gidlist(gid_info, 0);

		/*
		 * Remove GID from the global GID list
		 * Handle the case where all port GIDs for an
		 * IOU have been hot-removed.
		 */
		mutex_enter(&ibdm.ibdm_mutex);
		if (gid_info->gl_iou != NULL && gid_info->gl_ngids == 0) {
			mutex_enter(&gid_info->gl_mutex);
			(void) ibdm_free_iou_info(gid_info, &gid_info->gl_iou);
			mutex_exit(&gid_info->gl_mutex);
		}

		tmp = gid_info->gl_next;
		if (gid_info->gl_prev != NULL)
			gid_info->gl_prev->gl_next = gid_info->gl_next;
		if (gid_info->gl_next != NULL)
			gid_info->gl_next->gl_prev = gid_info->gl_prev;

		if (gid_info == ibdm.ibdm_dp_gidlist_head)
			ibdm.ibdm_dp_gidlist_head = gid_info->gl_next;
		if (gid_info == ibdm.ibdm_dp_gidlist_tail)
			ibdm.ibdm_dp_gidlist_tail = gid_info->gl_prev;
		ibdm.ibdm_ngids--;
		mutex_exit(&ibdm.ibdm_mutex);

		/* free the hca_list on this gid_info */
		ibdm_delete_glhca_list(gid_info);

		mutex_destroy(&gid_info->gl_mutex);
		kmem_free(gid_info, sizeof (ibdm_dp_gidinfo_t));

		gid_info = tmp;

		/*
		 * Pass on the IOCs with updated GIDs to IBnexus
		 */
		if (ioc_list) {
			IBTF_DPRINTF_L4("ibdm", "\trescan_gidlist "
			    "IOC_PROP_UPDATE for %p\n", ioc_list);
			mutex_enter(&ibdm.ibdm_ibnex_mutex);
			if (ibdm.ibdm_ibnex_callback != NULL) {
				(*ibdm.ibdm_ibnex_callback)((void *)
				    ioc_list, IBDM_EVENT_IOC_PROP_UPDATE);
			}
			mutex_exit(&ibdm.ibdm_ibnex_mutex);
		}
	}
}

/*
 * This function notifies IBnex of IOCs on this GID.
 * Notification is for GIDs with gl_reprobe_flag set.
 * The flag is set when IOC probe / fabric sweep
 * probes a GID starting from CLASS port info.
 *
 * IBnexus will have information of a reconnected IOC
 * if it had probed it before. If this is a new IOC,
 * IBnexus ignores the notification.
 *
 * This function should be called with no locks held.
 */
static void
ibdm_notify_newgid_iocs(ibdm_dp_gidinfo_t *gid_info)
{
	ibdm_ioc_info_t	*ioc_list;

	if (gid_info->gl_reprobe_flag == 0 ||
	    gid_info->gl_iou == NULL)
		return;

	ioc_list = ibdm_update_ioc_gidlist(gid_info, -1);

	/*
	 * Pass on the IOCs with updated GIDs to IBnexus
	 */
	if (ioc_list) {
		mutex_enter(&ibdm.ibdm_ibnex_mutex);
		if (ibdm.ibdm_ibnex_callback != NULL) {
			(*ibdm.ibdm_ibnex_callback)((void *)ioc_list,
			    IBDM_EVENT_IOC_PROP_UPDATE);
		}
		mutex_exit(&ibdm.ibdm_ibnex_mutex);
	}
}


static void
ibdm_free_saa_event_arg(ibdm_saa_event_arg_t *arg)
{
	if (arg != NULL)
		kmem_free(arg, sizeof (ibdm_saa_event_arg_t));
}

/*
 * This function parses the list of HCAs and HCA ports
 * to return the port_attr of the next HCA port. A port
 * connected to IB fabric (port_state active) is returned,
 * if connected_flag is set.
 */
static void
ibdm_get_next_port(ibdm_hca_list_t **inp_hcap,
    ibdm_port_attr_t **inp_portp, int connect_flag)
{
	int ii;
	ibdm_port_attr_t *port, *next_port = NULL;
	ibdm_port_attr_t *inp_port;
	ibdm_hca_list_t	 *hca_list;
	int found = 0;

	ASSERT(MUTEX_HELD(&ibdm.ibdm_hl_mutex));
	IBTF_DPRINTF_L4(ibdm_string, "\tget_next_port(%p, %p, %x)",
	    inp_hcap, inp_portp, connect_flag);

	hca_list = *inp_hcap;
	inp_port = *inp_portp;

	if (hca_list == NULL)
		hca_list = ibdm.ibdm_hca_list_head;

	for (; hca_list; hca_list = hca_list->hl_next) {
		for (ii = 0; ii < hca_list->hl_nports; ii++) {
			port = &hca_list->hl_port_attr[ii];

			/*
			 * inp_port != NULL;
			 * 	Skip till we find the matching port
			 */
			if (inp_port && !found) {
				if (inp_port == port)
					found = 1;
				continue;
			}

			if (!connect_flag) {
				next_port = port;
				break;
			}

			if (port->pa_sa_hdl == NULL)
				ibdm_initialize_port(port);
			if (port->pa_sa_hdl == NULL)
				(void) ibdm_fini_port(port);
			else if (next_port == NULL &&
			    port->pa_sa_hdl != NULL &&
			    port->pa_state == IBT_PORT_ACTIVE) {
				next_port = port;
				break;
			}
		}

		if (next_port)
			break;
	}

	IBTF_DPRINTF_L4(ibdm_string, "\tget_next_port : "
	    "returns hca_list %p port %p", hca_list, next_port);
	*inp_hcap = hca_list;
	*inp_portp = next_port;
}

static void
ibdm_add_to_gl_gid(ibdm_dp_gidinfo_t *nodegid, ibdm_dp_gidinfo_t *addgid)
{
	ibdm_gid_t	*tmp;

	tmp = kmem_zalloc(sizeof (ibdm_gid_t), KM_SLEEP);
	tmp->gid_dgid_hi = addgid->gl_dgid_hi;
	tmp->gid_dgid_lo = addgid->gl_dgid_lo;

	mutex_enter(&nodegid->gl_mutex);
	tmp->gid_next = nodegid->gl_gid;
	nodegid->gl_gid = tmp;
	nodegid->gl_ngids++;
	mutex_exit(&nodegid->gl_mutex);
}

static void
ibdm_addto_glhcalist(ibdm_dp_gidinfo_t *gid_info,
    ibdm_hca_list_t *hca)
{
	ibdm_hca_list_t		*head, *prev = NULL, *temp;

	IBTF_DPRINTF_L4(ibdm_string, "\taddto_glhcalist(%p, %p) "
	    ": gl_hca_list %p", gid_info, hca, gid_info->gl_hca_list);
	ASSERT(!MUTEX_HELD(&gid_info->gl_mutex));

	mutex_enter(&gid_info->gl_mutex);
	head = gid_info->gl_hca_list;
	if (head == NULL) {
		head = ibdm_dup_hca_attr(hca);
		head->hl_next = NULL;
		gid_info->gl_hca_list = head;
		mutex_exit(&gid_info->gl_mutex);
		IBTF_DPRINTF_L4(ibdm_string, "\tadd_to_glhcalist: "
		    "gid %p, gl_hca_list %p", gid_info,
		    gid_info->gl_hca_list);
		return;
	}

	/* Check if already in the list */
	while (head) {
		if (head->hl_hca_guid == hca->hl_hca_guid) {
			mutex_exit(&gid_info->gl_mutex);
			IBTF_DPRINTF_L4(ibdm_string,
			    "\taddto_glhcalist : gid %p hca %p dup",
			    gid_info, hca);
			return;
		}
		prev = head;
		head = head->hl_next;
	}

	/* Add this HCA to gl_hca_list */
	temp =  ibdm_dup_hca_attr(hca);
	temp->hl_next = NULL;
	prev->hl_next = temp;
	mutex_exit(&gid_info->gl_mutex);

	IBTF_DPRINTF_L4(ibdm_string, "\tadd_to_glhcalist: "
	    "gid %p, gl_hca_list %p", gid_info, gid_info->gl_hca_list);
}

static void
ibdm_delete_glhca_list(ibdm_dp_gidinfo_t *gid_info)
{
	ASSERT(!MUTEX_HELD(&gid_info->gl_mutex));
	ASSERT(!MUTEX_HELD(&ibdm.ibdm_mutex));

	mutex_enter(&gid_info->gl_mutex);
	if (gid_info->gl_hca_list)
		ibdm_ibnex_free_hca_list(gid_info->gl_hca_list);
	gid_info->gl_hca_list = NULL;
	mutex_exit(&gid_info->gl_mutex);
}


static void
ibdm_reset_all_dgids(ibmf_saa_handle_t port_sa_hdl)
{
	IBTF_DPRINTF_L4(ibdm_string, "\treset_all_dgids(%X)",
	    port_sa_hdl);

	if (ibdm_enumerate_iocs == 0)
		return;

	ASSERT(!MUTEX_HELD(&ibdm.ibdm_mutex));
	ASSERT(!MUTEX_HELD(&ibdm.ibdm_hl_mutex));

	/* Check : Not busy in another probe / sweep */
	mutex_enter(&ibdm.ibdm_mutex);
	if ((ibdm.ibdm_busy & IBDM_BUSY) == 0) {
		ibdm_dp_gidinfo_t	*gid_info;

		ibdm.ibdm_busy |= IBDM_BUSY;
		mutex_exit(&ibdm.ibdm_mutex);

		/*
		 * Check if any GID is using the SA & IBMF handle
		 * of HCA port going down. Reset ibdm_dp_gidinfo_t
		 * using another HCA port which can reach the GID.
		 * This is for DM capable GIDs only, no need to do
		 * this for others
		 *
		 * Delete the GID if no alternate HCA port to reach
		 * it is found.
		 */
		for (gid_info = ibdm.ibdm_dp_gidlist_head; gid_info; ) {
			ibdm_dp_gidinfo_t *tmp;

			IBTF_DPRINTF_L4(ibdm_string, "\tevent_hdlr "
			    "checking gidinfo %p", gid_info);

			if (gid_info->gl_sa_hdl == port_sa_hdl) {
				IBTF_DPRINTF_L3(ibdm_string,
				    "\tevent_hdlr: down HCA port hdl "
				    "matches gid %p", gid_info);

				/*
				 * The non-DM GIDs can come back
				 * with a new subnet prefix, when
				 * the HCA port commes up again. To
				 * avoid issues, delete non-DM
				 * capable GIDs, if the gid was
				 * discovered using the HCA port
				 * going down. This is ensured by
				 * setting gl_disconnected to 1.
				 */
				if (gid_info->gl_is_dm_capable == B_FALSE)
					gid_info->gl_disconnected = 1;
				else
					ibdm_reset_gidinfo(gid_info);

				if (gid_info->gl_disconnected) {
					IBTF_DPRINTF_L3(ibdm_string,
					    "\tevent_hdlr: deleting"
					    " gid %p", gid_info);
					tmp = gid_info;
					gid_info = gid_info->gl_next;
					ibdm_delete_gidinfo(tmp);
				} else
					gid_info = gid_info->gl_next;
			} else
				gid_info = gid_info->gl_next;
		}

		mutex_enter(&ibdm.ibdm_mutex);
		ibdm.ibdm_busy &= ~IBDM_BUSY;
		cv_signal(&ibdm.ibdm_busy_cv);
	}
	mutex_exit(&ibdm.ibdm_mutex);
}

static void
ibdm_reset_gidinfo(ibdm_dp_gidinfo_t *gidinfo)
{
	ibdm_hca_list_t	*hca_list = NULL;
	ibdm_port_attr_t	*port = NULL;
	int	gid_reinited = 0;
	sa_node_record_t	*nr, *tmp;
	sa_portinfo_record_t	*pi;
	size_t	nr_len = 0, pi_len = 0;
	size_t	path_len;
	ib_gid_t	sgid, dgid;
	int	ret, ii, nrecords;
	sa_path_record_t	*path;
	uint8_t	npaths = 1;
	ibdm_pkey_tbl_t		*pkey_tbl;

	IBTF_DPRINTF_L4(ibdm_string, "\treset_gidinfo(%p)", gidinfo);

	/*
	 * Get list of all the ports reachable from the local known HCA
	 * ports which are active
	 */
	mutex_enter(&ibdm.ibdm_hl_mutex);
	for (ibdm_get_next_port(&hca_list, &port, 1); port;
	    ibdm_get_next_port(&hca_list, &port, 1)) {


		/*
		 * Get the path and re-populate the gidinfo.
		 * Getting the path is the same probe_ioc
		 * Init the gid info as in ibdm_create_gidinfo()
		 */
		nr = ibdm_get_node_records(port->pa_sa_hdl, &nr_len,
		    gidinfo->gl_nodeguid);
		if (nr == NULL) {
			IBTF_DPRINTF_L4(ibdm_string,
			    "\treset_gidinfo : no records");
			continue;
		}

		nrecords = (nr_len / sizeof (sa_node_record_t));
		for (tmp = nr, ii = 0;  (ii < nrecords); ii++, tmp++) {
			if (tmp->NodeInfo.PortGUID == gidinfo->gl_portguid)
				break;
		}

		if (ii == nrecords) {
			IBTF_DPRINTF_L4(ibdm_string,
			    "\treset_gidinfo : no record for portguid");
			kmem_free(nr, nr_len);
			continue;
		}

		pi = ibdm_get_portinfo(port->pa_sa_hdl, &pi_len, tmp->LID);
		if (pi == NULL) {
			IBTF_DPRINTF_L4(ibdm_string,
			    "\treset_gidinfo : no portinfo");
			kmem_free(nr, nr_len);
			continue;
		}

		sgid.gid_prefix = port->pa_sn_prefix;
		sgid.gid_guid = port->pa_port_guid;
		dgid.gid_prefix = pi->PortInfo.GidPrefix;
		dgid.gid_guid = tmp->NodeInfo.PortGUID;

		ret = ibmf_saa_gid_to_pathrecords(port->pa_sa_hdl, sgid, dgid,
		    IBMF_SAA_PKEY_WC, 0, B_TRUE, &npaths, 0, &path_len, &path);

		if ((ret != IBMF_SUCCESS) || path == NULL) {
			IBTF_DPRINTF_L4(ibdm_string,
			    "\treset_gidinfo : no paths");
			kmem_free(pi, pi_len);
			kmem_free(nr, nr_len);
			continue;
		}

		gidinfo->gl_dgid_hi	= path->DGID.gid_prefix;
		gidinfo->gl_dgid_lo	= path->DGID.gid_guid;
		gidinfo->gl_sgid_hi	= path->SGID.gid_prefix;
		gidinfo->gl_sgid_lo	= path->SGID.gid_guid;
		gidinfo->gl_p_key	= path->P_Key;
		gidinfo->gl_sa_hdl	= port->pa_sa_hdl;
		gidinfo->gl_ibmf_hdl	= port->pa_ibmf_hdl;
		gidinfo->gl_slid	= path->SLID;
		gidinfo->gl_dlid	= path->DLID;
		/* Reset redirect info, next MAD will set if redirected */
		gidinfo->gl_redirected	= 0;
		gidinfo->gl_devid	= (*tmp).NodeInfo.DeviceID;
		gidinfo->gl_SL		= path->SL;

		gidinfo->gl_qp_hdl = IBMF_QP_HANDLE_DEFAULT;
		for (ii = 0; ii < port->pa_npkeys; ii++) {
			if (port->pa_pkey_tbl == NULL)
				break;

			pkey_tbl = &port->pa_pkey_tbl[ii];
			if ((gidinfo->gl_p_key == pkey_tbl->pt_pkey) &&
			    (pkey_tbl->pt_qp_hdl != NULL)) {
				gidinfo->gl_qp_hdl = pkey_tbl->pt_qp_hdl;
				break;
			}
		}

		if (gidinfo->gl_qp_hdl == NULL)
			IBTF_DPRINTF_L2(ibdm_string,
			    "\treset_gid_info: No matching Pkey");
		else
			gid_reinited = 1;

		kmem_free(path, path_len);
		kmem_free(pi, pi_len);
		kmem_free(nr, nr_len);
		break;
	}
	mutex_exit(&ibdm.ibdm_hl_mutex);

	if (!gid_reinited)
		gidinfo->gl_disconnected = 1;
}

static void
ibdm_delete_gidinfo(ibdm_dp_gidinfo_t *gidinfo)
{
	ibdm_ioc_info_t *ioc_list;
	int	in_gidlist = 0;

	/*
	 * Check if gidinfo has been inserted into the
	 * ibdm_dp_gidlist_head list. gl_next or gl_prev
	 * != NULL, if gidinfo is the list.
	 */
	if (gidinfo->gl_prev != NULL ||
	    gidinfo->gl_next != NULL ||
	    ibdm.ibdm_dp_gidlist_head == gidinfo)
		in_gidlist = 1;

	ioc_list = ibdm_update_ioc_gidlist(gidinfo, 0);

	/*
	 * Remove GID from the global GID list
	 * Handle the case where all port GIDs for an
	 * IOU have been hot-removed.
	 */
	mutex_enter(&ibdm.ibdm_mutex);
	if (gidinfo->gl_iou != NULL && gidinfo->gl_ngids == 0) {
		mutex_enter(&gidinfo->gl_mutex);
		(void) ibdm_free_iou_info(gidinfo, &gidinfo->gl_iou);
		mutex_exit(&gidinfo->gl_mutex);
	}

	/* Delete gl_hca_list */
	mutex_exit(&ibdm.ibdm_mutex);
	ibdm_delete_glhca_list(gidinfo);
	mutex_enter(&ibdm.ibdm_mutex);

	if (in_gidlist) {
		if (gidinfo->gl_prev != NULL)
			gidinfo->gl_prev->gl_next = gidinfo->gl_next;
		if (gidinfo->gl_next != NULL)
			gidinfo->gl_next->gl_prev = gidinfo->gl_prev;

		if (gidinfo == ibdm.ibdm_dp_gidlist_head)
			ibdm.ibdm_dp_gidlist_head = gidinfo->gl_next;
		if (gidinfo == ibdm.ibdm_dp_gidlist_tail)
			ibdm.ibdm_dp_gidlist_tail = gidinfo->gl_prev;
		ibdm.ibdm_ngids--;
	}
	mutex_exit(&ibdm.ibdm_mutex);

	mutex_destroy(&gidinfo->gl_mutex);
	cv_destroy(&gidinfo->gl_probe_cv);
	kmem_free(gidinfo, sizeof (ibdm_dp_gidinfo_t));

	/*
	 * Pass on the IOCs with updated GIDs to IBnexus
	 */
	if (ioc_list) {
		IBTF_DPRINTF_L4("ibdm", "\tdelete_gidinfo "
		    "IOC_PROP_UPDATE for %p\n", ioc_list);
		mutex_enter(&ibdm.ibdm_ibnex_mutex);
		if (ibdm.ibdm_ibnex_callback != NULL) {
			(*ibdm.ibdm_ibnex_callback)((void *)
			    ioc_list, IBDM_EVENT_IOC_PROP_UPDATE);
		}
		mutex_exit(&ibdm.ibdm_ibnex_mutex);
	}
}


static void
ibdm_fill_srv_attr_mod(ib_mad_hdr_t *hdr, ibdm_timeout_cb_args_t *cb_args)
{
	uint32_t	attr_mod;

	attr_mod = (cb_args->cb_ioc_num + 1) << 16;
	attr_mod |= cb_args->cb_srvents_start;
	attr_mod |= (cb_args->cb_srvents_end) << 8;
	hdr->AttributeModifier = h2b32(attr_mod);
}

static void
ibdm_bump_transactionID(ibdm_dp_gidinfo_t *gid_info)
{
	ASSERT(MUTEX_HELD(&gid_info->gl_mutex));
	gid_info->gl_transactionID++;
	if (gid_info->gl_transactionID == gid_info->gl_max_transactionID) {
		IBTF_DPRINTF_L4(ibdm_string,
		    "\tbump_transactionID(%p), wrapup", gid_info);
		gid_info->gl_transactionID = gid_info->gl_min_transactionID;
	}
}

/*
 * gl_prev_iou is set for *non-reprobe* sweeep requests, which
 * detected that ChangeID in IOU info has changed. The service
 * entry also may have changed. Check if service entry in IOC
 * has changed wrt the prev iou, if so notify to IB Nexus.
 */
static ibdm_ioc_info_t *
ibdm_handle_prev_iou()
{
	ibdm_dp_gidinfo_t *gid_info;
	ibdm_ioc_info_t	*ioc_list_head = NULL, *ioc_list;
	ibdm_ioc_info_t	*prev_ioc, *ioc;
	int		ii, jj, niocs, prev_niocs;

	ASSERT(MUTEX_HELD(&ibdm.ibdm_mutex));

	IBTF_DPRINTF_L4(ibdm_string, "\thandle_prev_iou enter");
	for (gid_info = ibdm.ibdm_dp_gidlist_head; gid_info;
	    gid_info = gid_info->gl_next) {
		if (gid_info->gl_prev_iou == NULL)
			continue;

		IBTF_DPRINTF_L4(ibdm_string, "\thandle_prev_iou gid %p",
		    gid_info);
		niocs = gid_info->gl_iou->iou_info.iou_num_ctrl_slots;
		prev_niocs =
		    gid_info->gl_prev_iou->iou_info.iou_num_ctrl_slots;
		for (ii = 0; ii < niocs; ii++) {
			ioc = IBDM_GIDINFO2IOCINFO(gid_info, ii);

			/* Find matching IOC */
			for (jj = 0; jj < prev_niocs; jj++) {
				prev_ioc = (ibdm_ioc_info_t *)
				    &gid_info->gl_prev_iou->iou_ioc_info[jj];
				if (prev_ioc->ioc_profile.ioc_guid ==
				    ioc->ioc_profile.ioc_guid)
					break;
			}
			if (jj == prev_niocs)
				prev_ioc = NULL;
			if (ioc == NULL || prev_ioc == NULL)
				continue;
			if ((ioc->ioc_profile.ioc_service_entries !=
			    prev_ioc->ioc_profile.ioc_service_entries) ||
			    ibdm_serv_cmp(&ioc->ioc_serv[0],
			    &prev_ioc->ioc_serv[0],
			    ioc->ioc_profile.ioc_service_entries) != 0) {
				IBTF_DPRINTF_L4(ibdm_string,
				    "/thandle_prev_iou modified IOC: "
				    "current ioc %p, old ioc %p",
				    ioc, prev_ioc);
				mutex_enter(&gid_info->gl_mutex);
				ioc_list = ibdm_dup_ioc_info(ioc, gid_info);
				mutex_exit(&gid_info->gl_mutex);
				ioc_list->ioc_info_updated.ib_prop_updated
				    = 0;
				ioc_list->ioc_info_updated.ib_srv_prop_updated
				    = 1;

				if (ioc_list_head == NULL)
					ioc_list_head = ioc_list;
				else {
					ioc_list_head->ioc_next = ioc_list;
					ioc_list_head = ioc_list;
				}
			}
		}

		mutex_enter(&gid_info->gl_mutex);
		(void) ibdm_free_iou_info(gid_info, &gid_info->gl_prev_iou);
		mutex_exit(&gid_info->gl_mutex);
	}
	IBTF_DPRINTF_L4(ibdm_string, "\thandle_prev_iouret %p",
	    ioc_list_head);
	return (ioc_list_head);
}

/*
 * Compares two service entries lists, returns 0 if same, returns 1
 * if no match.
 */
static int
ibdm_serv_cmp(ibdm_srvents_info_t *serv1, ibdm_srvents_info_t *serv2,
    int nserv)
{
	int	ii;

	IBTF_DPRINTF_L4(ibdm_string, "\tserv_cmp: enter");
	for (ii = 0; ii < nserv; ii++, serv1++, serv2++) {
		if (serv1->se_attr.srv_id != serv2->se_attr.srv_id ||
		    bcmp(serv1->se_attr.srv_name,
		    serv2->se_attr.srv_name,
		    IB_DM_MAX_SVC_NAME_LEN) != 0) {
			IBTF_DPRINTF_L4(ibdm_string, "\tserv_cmp: ret 1");
			return (1);
		}
	}
	IBTF_DPRINTF_L4(ibdm_string, "\tserv_cmp: ret 0");
	return (0);
}

/* For debugging purpose only */
#ifdef	DEBUG
void
ibdm_dump_mad_hdr(ib_mad_hdr_t	*mad_hdr)
{
	IBTF_DPRINTF_L4("ibdm", "\t\t MAD Header info");
	IBTF_DPRINTF_L4("ibdm", "\t\t ---------------");

	IBTF_DPRINTF_L4("ibdm", "\tBase version  : 0x%x"
	    "\tMgmt Class : 0x%x", mad_hdr->BaseVersion, mad_hdr->MgmtClass);
	IBTF_DPRINTF_L4("ibdm", "\tClass version : 0x%x"
	    "\tR Method           : 0x%x",
	    mad_hdr->ClassVersion, mad_hdr->R_Method);
	IBTF_DPRINTF_L4("ibdm", "\tMAD  Status   : 0x%x"
	    "\tTransaction ID     : 0x%llx",
	    b2h16(mad_hdr->Status), b2h64(mad_hdr->TransactionID));
	IBTF_DPRINTF_L4("ibdm", "\t Attribute ID  : 0x%x"
	    "\tAttribute Modified : 0x%lx",
	    b2h16(mad_hdr->AttributeID), b2h32(mad_hdr->AttributeModifier));
}


void
ibdm_dump_ibmf_msg(ibmf_msg_t *ibmf_msg, int flag)
{
	ib_mad_hdr_t	*mad_hdr;

	IBTF_DPRINTF_L4("ibdm", "\t\t(IBMF_PKT): Local address info");
	IBTF_DPRINTF_L4("ibdm", "\t\t            ------------------");

	IBTF_DPRINTF_L4("ibdm", "\tLocal Lid  : 0x%x\tRemote Lid : 0x%x"
	    " Remote Qp  : 0x%x", ibmf_msg->im_local_addr.ia_local_lid,
	    ibmf_msg->im_local_addr.ia_remote_lid,
	    ibmf_msg->im_local_addr.ia_remote_qno);
	IBTF_DPRINTF_L4("ibdm", "\tP_key      : 0x%x\tQ_key      : 0x%x"
	    " SL  : 0x%x", ibmf_msg->im_local_addr.ia_p_key,
	    ibmf_msg->im_local_addr.ia_q_key,
	    ibmf_msg->im_local_addr.ia_service_level);

	if (flag)
		mad_hdr = (ib_mad_hdr_t *)IBDM_OUT_IBMFMSG_MADHDR(ibmf_msg);
	else
		mad_hdr = IBDM_IN_IBMFMSG_MADHDR(ibmf_msg);

	ibdm_dump_mad_hdr(mad_hdr);
}


void
ibdm_dump_path_info(sa_path_record_t *path)
{
	IBTF_DPRINTF_L4("ibdm", "\t\t Path information");
	IBTF_DPRINTF_L4("ibdm", "\t\t ----------------");

	IBTF_DPRINTF_L4("ibdm", "\t DGID hi  : %llx\tDGID lo  : %llx",
	    path->DGID.gid_prefix, path->DGID.gid_guid);
	IBTF_DPRINTF_L4("ibdm", "\t SGID hi  : %llx\tSGID lo  : %llx",
	    path->SGID.gid_prefix, path->SGID.gid_guid);
	IBTF_DPRINTF_L4("ibdm", "\t SLID     : %x\t\tDlID     : %x",
	    path->SLID, path->DLID);
	IBTF_DPRINTF_L4("ibdm", "\t P Key    : %x\t\tSL       : %x",
	    path->P_Key, path->SL);
}


void
ibdm_dump_classportinfo(ib_mad_classportinfo_t *classportinfo)
{
	IBTF_DPRINTF_L4("ibdm", "\t\t CLASSPORT INFO");
	IBTF_DPRINTF_L4("ibdm", "\t\t --------------");

	IBTF_DPRINTF_L4("ibdm", "\t Response Time Value : 0x%x",
	    ((b2h32(classportinfo->RespTimeValue)) & 0x1F));

	IBTF_DPRINTF_L4("ibdm", "\t Redirected GID hi   : 0x%llx",
	    b2h64(classportinfo->RedirectGID_hi));
	IBTF_DPRINTF_L4("ibdm", "\t Redirected GID lo   : 0x%llx",
	    b2h64(classportinfo->RedirectGID_lo));
	IBTF_DPRINTF_L4("ibdm", "\t Redirected TC       : 0x%x",
	    classportinfo->RedirectTC);
	IBTF_DPRINTF_L4("ibdm", "\t Redirected SL       : 0x%x",
	    classportinfo->RedirectSL);
	IBTF_DPRINTF_L4("ibdm", "\t Redirected FL       : 0x%x",
	    classportinfo->RedirectFL);
	IBTF_DPRINTF_L4("ibdm", "\t Redirected LID      : 0x%x",
	    b2h16(classportinfo->RedirectLID));
	IBTF_DPRINTF_L4("ibdm", "\t Redirected P KEY    : 0x%x",
	    b2h16(classportinfo->RedirectP_Key));
	IBTF_DPRINTF_L4("ibdm", "\t Redirected QP       : 0x%x",
	    classportinfo->RedirectQP);
	IBTF_DPRINTF_L4("ibdm", "\t Redirected Q KEY    : 0x%x",
	    b2h32(classportinfo->RedirectQ_Key));
	IBTF_DPRINTF_L4("ibdm", "\t Trap GID hi         : 0x%llx",
	    b2h64(classportinfo->TrapGID_hi));
	IBTF_DPRINTF_L4("ibdm", "\t Trap GID lo         : 0x%llx",
	    b2h64(classportinfo->TrapGID_lo));
	IBTF_DPRINTF_L4("ibdm", "\t Trap TC             : 0x%x",
	    classportinfo->TrapTC);
	IBTF_DPRINTF_L4("ibdm", "\t Trap SL             : 0x%x",
	    classportinfo->TrapSL);
	IBTF_DPRINTF_L4("ibdm", "\t Trap FL             : 0x%x",
	    classportinfo->TrapFL);
	IBTF_DPRINTF_L4("ibdm", "\t Trap LID            : 0x%x",
	    b2h16(classportinfo->TrapLID));
	IBTF_DPRINTF_L4("ibdm", "\t Trap P_Key          : 0x%x",
	    b2h16(classportinfo->TrapP_Key));
	IBTF_DPRINTF_L4("ibdm", "\t Trap HL             : 0x%x",
	    classportinfo->TrapHL);
	IBTF_DPRINTF_L4("ibdm", "\t Trap QP             : 0x%x",
	    classportinfo->TrapQP);
	IBTF_DPRINTF_L4("ibdm", "\t Trap Q_Key          : 0x%x",
	    b2h32(classportinfo->TrapQ_Key));
}


void
ibdm_dump_iounitinfo(ib_dm_io_unitinfo_t *iou_info)
{
	IBTF_DPRINTF_L4("ibdm", "\t\t I/O UnitInfo");
	IBTF_DPRINTF_L4("ibdm", "\t\t ------------");

	IBTF_DPRINTF_L4("ibdm", "\tChange ID            : 0x%x",
	    b2h16(iou_info->iou_changeid));
	IBTF_DPRINTF_L4("ibdm", "\t#of ctrl slots       : %d",
	    iou_info->iou_num_ctrl_slots);
	IBTF_DPRINTF_L4("ibdm", "\tIOU flag             : 0x%x",
	    iou_info->iou_flag);
	IBTF_DPRINTF_L4("ibdm", "\tContrl list byte 0   : 0x%x",
	    iou_info->iou_ctrl_list[0]);
	IBTF_DPRINTF_L4("ibdm", "\tContrl list byte 1   : 0x%x",
	    iou_info->iou_ctrl_list[1]);
	IBTF_DPRINTF_L4("ibdm", "\tContrl list byte 2   : 0x%x",
	    iou_info->iou_ctrl_list[2]);
}


void
ibdm_dump_ioc_profile(ib_dm_ioc_ctrl_profile_t *ioc)
{
	IBTF_DPRINTF_L4("ibdm", "\t\t IOC Controller Profile");
	IBTF_DPRINTF_L4("ibdm", "\t\t ----------------------");

	IBTF_DPRINTF_L4("ibdm", "\tIOC Guid    : %llx", ioc->ioc_guid);
	IBTF_DPRINTF_L4("ibdm", "\tVendorID    : 0x%x", ioc->ioc_vendorid);
	IBTF_DPRINTF_L4("ibdm", "\tDevice Id   : 0x%x", ioc->ioc_deviceid);
	IBTF_DPRINTF_L4("ibdm", "\tDevice Ver  : 0x%x", ioc->ioc_device_ver);
	IBTF_DPRINTF_L4("ibdm", "\tSubsys ID   : 0x%x", ioc->ioc_subsys_id);
	IBTF_DPRINTF_L4("ibdm", "\tIO class    : 0x%x", ioc->ioc_io_class);
	IBTF_DPRINTF_L4("ibdm", "\tIO subclass : 0x%x", ioc->ioc_io_subclass);
	IBTF_DPRINTF_L4("ibdm", "\tProtocol    : 0x%x", ioc->ioc_protocol);
	IBTF_DPRINTF_L4("ibdm", "\tProtocolV   : 0x%x", ioc->ioc_protocol_ver);
	IBTF_DPRINTF_L4("ibdm", "\tmsg qdepth  : %d", ioc->ioc_send_msg_qdepth);
	IBTF_DPRINTF_L4("ibdm", "\trdma qdepth : %d",
	    ioc->ioc_rdma_read_qdepth);
	IBTF_DPRINTF_L4("ibdm", "\tsndmsg sz   : %d", ioc->ioc_send_msg_sz);
	IBTF_DPRINTF_L4("ibdm", "\trdma xfersz : %d", ioc->ioc_rdma_xfer_sz);
	IBTF_DPRINTF_L4("ibdm", "\topcal mask  : 0x%x",
	    ioc->ioc_ctrl_opcap_mask);
	IBTF_DPRINTF_L4("ibdm", "\tsrventries  : %x", ioc->ioc_service_entries);
}


void
ibdm_dump_service_entries(ib_dm_srv_t *srv_ents)
{
	IBTF_DPRINTF_L4("ibdm",
	    "\thandle_srventry_mad: service id : %llx", srv_ents->srv_id);

	IBTF_DPRINTF_L4("ibdm", "\thandle_srventry_mad: "
	    "Service Name : %s", srv_ents->srv_name);
}

int ibdm_allow_sweep_fabric_timestamp = 1;

void
ibdm_dump_sweep_fabric_timestamp(int flag)
{
	static hrtime_t x;
	if (flag) {
		if (ibdm_allow_sweep_fabric_timestamp) {
			IBTF_DPRINTF_L4("ibdm", "\tTime taken to complete "
			    "sweep %lld ms", ((gethrtime() - x)/ 1000000));
		}
		x = 0;
	} else
		x = gethrtime();
}
#endif
