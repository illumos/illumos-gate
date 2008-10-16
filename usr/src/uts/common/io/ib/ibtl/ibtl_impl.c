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
 * ibtl_impl.c
 *
 * This file contains the IBTF module's initialization and
 * IBTF Clients/Modules registration routines.
 */

#include <sys/modctl.h>
#include <sys/sunndi.h>
#include <sys/sunmdi.h>
#include <sys/ib/ibtl/impl/ibtl.h>
#include <sys/ib/ibtl/impl/ibtl_ibnex.h>

/*
 * Globals.
 */
static char ibtf[] = "ibtl_impl";

extern ibtl_ibnex_callback_t	ibtl_ibnex_callback_routine;

/*
 * ibtl_clnt_list:
 *
 *	Head of the list of IBT Client Instances. The IBT Client List
 *	is modified by IBTF on an IBT client's ibt_attach/ibt_detach call.
 *
 * ibtl_hca_list:
 *
 *	Head of the list of HCA devices. The HCA List is modified by IBTF on
 *	a CI's ibc_attach/ibc_detach call.
 *	The datap of the list elements points to an ibtl_hca_devinfo_s
 *	structure.
 *
 *				(ibc_attach)
 *  ibtl_hca_list	-> ibtl_hca_devinfo_t--> ...	-->ibtl_hca_devinfo_t
 *	[per-hca_dev]		|	^			{nth HCA Dev}
 *				|	|
 *				|  ibtl_hca_t (ibt_open_hca)
 *				|	^  |
 *				|	|  |
 *				v	|  V
 *  ibtl_clnt_list	->	ibtl_clnt_t--> ...--> {n'th Module}
 *	[per-client_instance]	(ibt_attach)
 *
 */

/* Global List of IBT Client Instances, and associated mutex. */
struct ibtl_clnt_s *ibtl_clnt_list = NULL;
kmutex_t ibtl_clnt_list_mutex;

/* Lock for the race between the client and CM to free QPs. */
kmutex_t ibtl_free_qp_mutex;

/* Lock for the race between the client closing the HCA and QPN being freed. */
kcondvar_t ibtl_close_hca_cv;

/* Global List of HCA Devices, and associated mutex. */
struct ibtl_hca_devinfo_s *ibtl_hca_list = NULL;

/* Well-known async handlers and associated client private. */
ibt_async_handler_t ibtl_cm_async_handler;
ibt_async_handler_t ibtl_dm_async_handler;
ibt_async_handler_t ibtl_ibma_async_handler;
void	*ibtl_cm_clnt_private;
void	*ibtl_dm_clnt_private;
void	*ibtl_ibma_clnt_private;

extern int ib_hw_status;
_NOTE(SCHEME_PROTECTS_DATA("Scheme protects data", ib_hw_status))

/*
 * Misc Module Declarations.
 */
extern struct mod_ops mod_miscops;
static struct modlmisc modlmisc = {
	&mod_miscops,			/* Type of module - misc. */
	"IB Transport Layer"		/* Name of the Module. */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};


/*
 * IBTF Loadable Module Routines.
 */

int
_init(void)
{
	int rval;

	if ((rval = mod_install(&modlinkage)) != 0)
		return (rval);

	/*
	 * initialize IBTL ib2usec table
	 */
	ibtl_ib2usec_init();

	/*
	 * Initialize Logging
	 */
	ibtl_logging_initialization();

	/*
	 * Initialize the Alloc QP States.
	 */
	ibtl_init_cep_states();

	/*
	 * Initialize all Global Link Lists.
	 */
	mutex_init(&ibtl_clnt_list_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ibtl_free_qp_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ibtl_close_hca_cv, NULL, CV_DEFAULT, NULL);

	mutex_init(&ibtl_qp_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ibtl_qp_cv, NULL, CV_DEFAULT, NULL);

	ibtl_thread_init();

	return (rval);
}


/*
 * The IBTF Module is never unloaded. Actually there is no need of this
 * routine, but provided just in case.
 */
int
_fini(void)
{
	int rval;

	if ((rval = mod_remove(&modlinkage)) != 0) {
		return (rval);
	}

	ibtl_thread_fini();

	mutex_destroy(&ibtl_clnt_list_mutex);
	mutex_destroy(&ibtl_free_qp_mutex);
	cv_destroy(&ibtl_close_hca_cv);
	mutex_destroy(&ibtl_qp_mutex);
	cv_destroy(&ibtl_qp_cv);

	/*
	 * Stop Logging
	 */
	ibtl_logging_destroy();

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	/* Return the Module Information. */
	return (mod_info(&modlinkage, modinfop));
}


/*
 * IBTF Client Registration Routines.
 */

/*
 * Function:
 *	ibt_attach
 * Input:
 *	modinfop	- Client Module info structure.
 *	arg		- usually client's dip
 *	clnt_private	- client's private data pointer.
 * Output:
 *	ibt_hdl_p	- pointer to client's specific IBT handle,
 *			 which is opaque to clients.
 * Returns:
 *	IBT_SUCCESS
 *	IBT_INVALID_PARAM
 * Called by:
 *	IBTF Client module during its attach() to register its instance
 *	to IBTF.
 * Description:
 *	Registers the IBTF client module instance and returns an opaque
 *	handler to the client to be used for future calls to IBTF.
 *	Adds this client module instance to ibtl_clnt_list list.
 *	Records well-known async handlers.
 */
ibt_status_t
ibt_attach(ibt_clnt_modinfo_t *mod_infop, dev_info_t *arg, void *clnt_private,
    ibt_clnt_hdl_t *ibt_hdl_p)
{
	dev_info_t	*pdip;
	ibtl_clnt_t	*clntp;

	IBTF_DPRINTF_L3(ibtf, "ibt_attach(%p, %p, %p)",
	    mod_infop, arg, clnt_private);

	if (mod_infop->mi_clnt_name == NULL) {
		IBTF_DPRINTF_L1(ibtf, "ibt_attach: "
		    "IB client needs to specify its name");
		return (IBT_INVALID_PARAM);
	}

	/*
	 * Validate the Transport API version.
	 */
	if (mod_infop->mi_ibt_version != IBTI_V2) {
		IBTF_DPRINTF_L1(ibtf, "ibt_attach: IB client '%s' has an "
		    "invalid IB TI Version '%d'", mod_infop->mi_clnt_name,
		    mod_infop->mi_ibt_version);
		return (IBT_NOT_SUPPORTED);
	}

	if (mod_infop->mi_async_handler == NULL) {
		IBTF_DPRINTF_L2(ibtf, "ibt_attach: Client '%s' has not\n"
		    "        provided an Asynchronous Event Handler.\n"
		    "        This will be required soon.",
		    mod_infop->mi_clnt_name);
	}

	/*
	 * Check out Client's Class information. If it is not of mgmt class,
	 * we expect 'arg' to be Not NULL and point to client driver's
	 * device info struct.
	 */
	if ((!IBT_CLNT_MGMT_CLASS(mod_infop->mi_clnt_class)) &&
	    (arg == NULL)) {
		IBTF_DPRINTF_L1(ibtf, "ibt_attach: "
		    "arg not set with driver's dip.");
		return (IBT_INVALID_PARAM);
	}

	if (!IBT_CLNT_MGMT_CLASS(mod_infop->mi_clnt_class)) {
		pdip = ddi_get_parent(arg);
		if (pdip == NULL ||
		    ibtl_ibnex_valid_hca_parent(pdip) != IBT_SUCCESS) {
			IBTF_DPRINTF_L2(ibtf, "ibt_attach: "
			    "client %s is not a child of IB nexus driver.",
			    ddi_driver_name(arg));
			return (IBT_INVALID_PARAM);
		}
	}

	mutex_enter(&ibtl_clnt_list_mutex);
	if (mod_infop->mi_clnt_class == IBT_CM) {
		if (ibtl_cm_async_handler != NULL) {
			IBTF_DPRINTF_L1(ibtf, "ibt_attach: "
			    "CM is already attached.");
			mutex_exit(&ibtl_clnt_list_mutex);
			return (IBT_INVALID_PARAM);
		}
		ibtl_cm_async_handler = mod_infop->mi_async_handler;
		ibtl_cm_clnt_private = clnt_private;
	} else if (mod_infop->mi_clnt_class == IBT_DM) {
		if (ibtl_dm_async_handler != NULL) {
			IBTF_DPRINTF_L1(ibtf, "ibt_attach: "
			    "DM is already attached.");
			mutex_exit(&ibtl_clnt_list_mutex);
			return (IBT_INVALID_PARAM);
		}
		ibtl_dm_async_handler = mod_infop->mi_async_handler;
		ibtl_dm_clnt_private = clnt_private;
	} else if (mod_infop->mi_clnt_class == IBT_IBMA) {
		if (ibtl_ibma_async_handler != NULL) {
			IBTF_DPRINTF_L1(ibtf, "ibt_attach: "
			    "IBMF is already attached.");
			mutex_exit(&ibtl_clnt_list_mutex);
			return (IBT_INVALID_PARAM);
		}
		ibtl_ibma_async_handler = mod_infop->mi_async_handler;
		ibtl_ibma_clnt_private = clnt_private;
	}

	/* Allocate the memory for per-client-device info structure */
	clntp = kmem_zalloc(sizeof (ibtl_clnt_t), KM_SLEEP);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(clntp->clnt_modinfop,
	    clntp->clnt_dip, clntp->clnt_name, clntp->clnt_async_cnt,
	    clntp->clnt_private))
	/* Update the Client info structure */
	clntp->clnt_modinfop = mod_infop;	/* IBT Client's Mod Info */
	clntp->clnt_private = clnt_private;	/* IBT Client's private */
	clntp->clnt_dip = arg;			/* IBT Client's dip */
	clntp->clnt_async_cnt = 0;
	/* using a count of 7 below guarantees it is NULL terminated */
	(void) strncpy(clntp->clnt_name, mod_infop->mi_clnt_name, 7);
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(clntp->clnt_modinfop,
	    clntp->clnt_dip, clntp->clnt_name, clntp->clnt_async_cnt,
	    clntp->clnt_private))

	/*
	 * Update Client Device Instance List.
	 */
	clntp->clnt_list_link = ibtl_clnt_list;
	ibtl_clnt_list = clntp;
	mutex_exit(&ibtl_clnt_list_mutex);

	/*
	 * The ibt_hdl_p is a opaque handle which is the address of
	 * ibt_clnt_t structure passed back to the clients.
	 * The client will pass on this handle in its future calls to IBTF.
	 */
	*ibt_hdl_p = clntp;

	return (IBT_SUCCESS);
}


/*
 * Function:
 *	ibt_detach
 * Input:
 *	ibt_hdl - IBT Handle as returned during ibt_attach call.
 * Output:
 *	none
 * Returns:
 *	IBT_SUCCESS
 *	IBT_INVALID_PARAM.
 * Called by:
 *	IBTF Client module during its detach() to de-register its instance
 *	from IBTF.
 * Description:
 *	Deregisters the IBTF client module instance from the IBTF.
 *	All resources and any reference to this ibt_hdl will be removed.
 */
ibt_status_t
ibt_detach(ibt_clnt_hdl_t ibt_hdl)
{
	ibtl_clnt_t **clntpp;

	IBTF_DPRINTF_L3(ibtf, "ibt_detach(%p)", ibt_hdl);

	mutex_enter(&ibtl_clnt_list_mutex);
	clntpp = &ibtl_clnt_list;
	for (; *clntpp != NULL; clntpp = &(*clntpp)->clnt_list_link)
		if (*clntpp == ibt_hdl)
			break;
	if (*clntpp == NULL) {
		IBTF_DPRINTF_L1(ibtf, "ibt_detach: Client @ %p Not Found",
		    ibt_hdl);
		mutex_exit(&ibtl_clnt_list_mutex);
		return (IBT_INVALID_PARAM);
	}

	/*
	 * Check out whether the client has freed all its resources.
	 * If not done, then fail the detach.
	 *
	 * viz. A client has to close all the HCA they have opened,
	 * i.e. the HCA List maintained for clients has to be empty.
	 * If this list is not empty, then the client has not performed
	 * complete clean-up, so fail the detach.
	 */
	if (ibt_hdl->clnt_hca_list != NULL) {
		mutex_exit(&ibtl_clnt_list_mutex);

		IBTF_DPRINTF_L2(ibtf, "ibt_detach: "
		    "ERROR: Client '%s' has not closed all of its HCAs",
		    ibt_hdl->clnt_modinfop->mi_clnt_name);
		return (IBT_HCA_RESOURCES_NOT_FREED);
	}

	if (ibt_hdl->clnt_srv_cnt != 0) {
		mutex_exit(&ibtl_clnt_list_mutex);
		IBTF_DPRINTF_L2(ibtf, "ibt_detach: client '%s' still has "
		    "services or subnet_notices registered",
		    ibt_hdl->clnt_modinfop->mi_clnt_name);
		return (IBT_HCA_RESOURCES_NOT_FREED);
	}

	/*
	 * Delete the entry of this module from the ibtl_clnt_list List.
	 */
	*clntpp = ibt_hdl->clnt_list_link;	/* remove us */

	/* make sure asyncs complete before freeing */
	ibtl_free_clnt_async_check(ibt_hdl);

	if (ibt_hdl->clnt_modinfop->mi_clnt_class == IBT_CM) {
		ibtl_cm_async_handler = NULL;
		ibtl_cm_clnt_private = NULL;
	} else if (ibt_hdl->clnt_modinfop->mi_clnt_class == IBT_DM) {
		ibtl_dm_async_handler = NULL;
		ibtl_dm_clnt_private = NULL;
	} else if (ibt_hdl->clnt_modinfop->mi_clnt_class == IBT_IBMA) {
		ibtl_ibma_async_handler = NULL;
		ibtl_ibma_clnt_private = NULL;
	}
	mutex_exit(&ibtl_clnt_list_mutex);

	/* Free up the memory of per-client info struct. */
	kmem_free(ibt_hdl, sizeof (ibtl_clnt_t));

	return (IBT_SUCCESS);
}

static void
ibtl_set_ibhw_status()
{
	ib_hw_status++;
}

static void
ibtl_clear_ibhw_status()
{
	ib_hw_status--;
}

/*
 * Function:
 *	ibc_init
 * Input:
 *	modlp		- Pointer to IBC client module linkage structure
 * Output:
 *	None
 * Returns:
 *	0 always for now
 * Called by:
 *	CI client calls IBTF during its _init() to register HCA with
 *	Solaris I/O framework.
 * Description:
 *	Initializes the CI clients module linkage structure with
 *	default bus_ops structure
 */
int
ibc_init(struct modlinkage *modlp)
{
	ibtl_ibnex_cb_args_t	cb_args;

	mutex_enter(&ibtl_clnt_list_mutex);
	cb_args.cb_flag = IBTL_IBNEX_IBC_INIT;
	cb_args.cb_modlp = modlp;
	if (ibtl_ibnex_callback_routine) {
		(void) ((*ibtl_ibnex_callback_routine)(&cb_args));
	}
	mutex_exit(&ibtl_clnt_list_mutex);
	return (0);
}


/*
 * Function:
 *	ibc_fini
 * Input:
 *	modlp		- Pointer to IBC client module linkage structure
 * Output:
 *	None
 * Returns:
 *	None
 * Called by:
 *	CI client calls IBTF during its _fini() to remove HCA with
 *	Solaris I/O framework.
 * Description:
 *	Undo what is done during ibc_init
 */
void
ibc_fini(struct modlinkage *modlp)
{
	ibtl_ibnex_cb_args_t	cb_args;

	mutex_enter(&ibtl_clnt_list_mutex);
	cb_args.cb_flag = IBTL_IBNEX_IBC_FINI;
	cb_args.cb_modlp = modlp;
	if (ibtl_ibnex_callback_routine) {
		(void) ((*ibtl_ibnex_callback_routine)(&cb_args));
	}
	mutex_exit(&ibtl_clnt_list_mutex);
}

/*
 * Function:
 *	ibc_attach
 * Input:
 *	info_p		- IBC HCA Info.
 * Output:
 *	ibc_hdl_p	- IBC Client's HCA Handle.
 * Returns:
 *	IBC_SUCCESS
 *	IBC_FAILURE
 * Called by:
 *	CI calls IBTF during its attach() to register HCA Device with IBTF.
 * Description:
 *	Registers the presence of HCA device by providing the HCA device info
 *  	structure and provides an opaque HCA handler for future calls to this
 *  	HCA device.
 */
ibc_status_t
ibc_attach(ibc_clnt_hdl_t *ibc_hdl_p, ibc_hca_info_t *info_p)
{
	ibtl_hca_devinfo_t	*hca_devp;
	uint_t			nports;
	ibt_status_t		status;

	IBTF_DPRINTF_L2(ibtf, "ibc_attach(%p, %p)", ibc_hdl_p, info_p);

	/* Validate the Transport API version */
	if (info_p->hca_ci_vers != IBCI_V2) {
		IBTF_DPRINTF_L1(ibtf, "ibc_attach: Invalid IB CI Version '%d'",
		    info_p->hca_ci_vers);
		return (IBC_FAILURE);
	}

	if (info_p->hca_attr == NULL) {
		IBTF_DPRINTF_L1(ibtf, "ibc_attach: "
		    "HCA Attributes must be specified.");
		return (IBC_FAILURE);
	}

	nports = info_p->hca_attr->hca_nports;
	if (nports == 0) {
		IBTF_DPRINTF_L1(ibtf, "ibc_attach: "
		    "Number of ports must be valid");
		return (IBC_FAILURE);
	}

	if (info_p->hca_attr->hca_max_port_pkey_tbl_sz == 0) {
		IBTF_DPRINTF_L1(ibtf, "ibc_attach: "
		    "Number of Partitions must be at least 1");
		return (IBC_FAILURE);
	}

	if ((info_p->hca_attr->hca_flags & IBT_HCA_CURRENT_QP_STATE) == 0) {
		IBTF_DPRINTF_L1(ibtf, "ibc_attach: "
		    "HCA driver must support QP current state checking");
		return (IBC_FAILURE);
	}

	if ((info_p->hca_attr->hca_flags & IBT_HCA_PORT_UP) == 0) {
		IBTF_DPRINTF_L1(ibtf, "ibc_attach: "
		    "HCA driver must support PORT_UP async events");
		return (IBC_FAILURE);
	}

	/*
	 * Install IB nexus driver (if not installed already)
	 */
	ibtl_set_ibhw_status();
	if (ndi_devi_config_vhci("ib", 0) == NULL) {
		IBTF_DPRINTF_L2(ibtf, "ibc_attach: IB nexus attach failed");
		ibtl_clear_ibhw_status();
		return (IBC_FAILURE);
	}

	ibtl_thread_init2();

	/* Allocate the memory for per-client info structure */
	hca_devp = kmem_zalloc(sizeof (ibtl_hca_devinfo_t) +
	    (nports - 1) * sizeof (ibtl_async_port_status_t), KM_SLEEP);

	mutex_enter(&ibtl_clnt_list_mutex);

	/* Update HCA dev info structure */
	hca_devp->hd_ibc_hca_hdl = info_p->hca_handle;
	hca_devp->hd_ibc_ops	= info_p->hca_ops;
	hca_devp->hd_hca_attr	= info_p->hca_attr;
	hca_devp->hd_hca_dip	= info_p->hca_dip;

	status = ibtl_init_hca_portinfo(hca_devp);
	if (status != IBT_SUCCESS) {
		mutex_exit(&ibtl_clnt_list_mutex);
		IBTF_DPRINTF_L1(ibtf, "ibc_attach: call to ibc_query_hca_ports "
		    "failed: status = %d", status);
		kmem_free(hca_devp, sizeof (ibtl_hca_devinfo_t) +
		    (nports - 1) * sizeof (ibtl_async_port_status_t));
		return (IBC_FAILURE);
	}

	/* Register the with MPxIO as PHCI */
	if (mdi_phci_register(MDI_HCI_CLASS_IB, info_p->hca_dip, 0) !=
	    MDI_SUCCESS) {
		mutex_exit(&ibtl_clnt_list_mutex);
		IBTF_DPRINTF_L1(ibtf, "ibc_attach: MPxIO register failed");
		kmem_free(hca_devp, sizeof (ibtl_hca_devinfo_t) +
		    (nports - 1) * sizeof (ibtl_async_port_status_t));
		return (IBC_FAILURE);
	}

	/* Initialize the Client List for this HCA. */
	hca_devp->hd_state	= IBTL_HCA_DEV_ATTACHED;

	/* lock out asyncs until after we announce the new HCA */
	hca_devp->hd_async_busy = 1;

	cv_init(&hca_devp->hd_async_task_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&hca_devp->hd_async_busy_cv, NULL, CV_DEFAULT, NULL);

	/* init portinfo locking variables */
	hca_devp->hd_portinfo_locked_port = 0;
	cv_init(&hca_devp->hd_portinfo_cv, NULL, CV_DEFAULT, NULL);

	mutex_exit(&ibtl_clnt_list_mutex);

	/*
	 * The ibc_hdl_p points to an opaque handle which is the address
	 * of ibt_hca_devinfo_t structure passed back to the CI.
	 * The CI will pass on this handle in its future upcalls to IBTF.
	 */
	*ibc_hdl_p = hca_devp;

	return (IBC_SUCCESS);
}


/*
 * Function:
 *	ibc_post_attach
 * Input:
 *	ibc_hdl		- IBC Client's HCA Handle.
 * Returns:
 *	none
 * Called by:
 *	CI calls IBTF during its attach() after a successful ibc_attach().
 * Description:
 *	Announces to all known clients the existence of this HCA (by GUID).
 */
void
ibc_post_attach(ibc_clnt_hdl_t ibc_hdl)
{
	IBTF_DPRINTF_L2(ibtf, "ibc_post_attach(%p)", ibc_hdl);

	/*
	 * Update the HCA Device List.
	 */
	mutex_enter(&ibtl_clnt_list_mutex);
	ibc_hdl->hd_hca_dev_link = ibtl_hca_list;
	ibtl_hca_list = ibc_hdl;
	mutex_exit(&ibtl_clnt_list_mutex);

	/* notify all IBT Client Device Instances of the new HCA Device */
	ibtl_announce_new_hca(ibc_hdl);
}


/*
 * Function:
 *	ibc_pre_detach
 * Input:
 *	ibc_clnt_hdl	- IBC HCA Handle as returned during ibc_attach call.
 *  	cmd		- DDI_DETACH/DDI_SUSPEND command.
 * Output:
 *	none
 * Returns:
 *	IBC_SUCCESS
 *	IBC_FAILURE.
 * Called by:
 *	CI to try to get all IBTF clients to close the HCA device.
 * Description:
 *	Attempts to deregister the HCA device entry from the IBTF.
 *	If all resources are freed by the IBTF clients and this HCA
 *	is closed, then IBC_SUCCESS is returned.
 */
ibc_status_t
ibc_pre_detach(ibc_clnt_hdl_t hca_devp, ddi_detach_cmd_t cmd)
{
	ibtl_hca_devinfo_t **hcapp, *hcap;

	IBTF_DPRINTF_L2(ibtf, "ibc_pre_detach(%p, 0x%x)", hca_devp, cmd);

	/*
	 * Return failure, if command is not DDI_DETACH
	 */
	switch (cmd) {
	case DDI_DETACH:
		break;
	default:
		return (IBC_FAILURE); /* TBD: DDI_FAILURE */
	}

	/* Make sure this HCA is on the HCA Device List.  */
	mutex_enter(&ibtl_clnt_list_mutex);
	hcap = ibtl_hca_list;
	while (hcap != NULL) {
		if (hcap == hca_devp)
			break;
		hcap = hcap->hd_hca_dev_link;
	}
	if (hcap == NULL) {
		mutex_exit(&ibtl_clnt_list_mutex);
		return (IBC_FAILURE);
	}

	/*
	 * Initially set the state to "Detaching".
	 */
	hca_devp->hd_state = IBTL_HCA_DEV_DETACHING;

	/*
	 * Try to detach all IBTI clients, and continue only if all
	 * of the detaches succeed.
	 */
	if (ibtl_detach_all_clients(hca_devp)) {
		hca_devp->hd_state = IBTL_HCA_DEV_ATTACHED; /* fix hd_state */
		mutex_exit(&ibtl_clnt_list_mutex);

		return (IBC_FAILURE);
	}

	/*
	 * Check to see if all clients closed this HCA, or not.
	 * We only succeed if all clients cooperated.
	 */
	if (hca_devp->hd_clnt_list != NULL) {
		hca_devp->hd_state = IBTL_HCA_DEV_ATTACHED;
		mutex_exit(&ibtl_clnt_list_mutex);
		IBTF_DPRINTF_L2(ibtf, "ibc_pre_detach: HCA still has attached "
		    "clients");
		return (IBC_FAILURE);
	}

	/*
	 * mark this device as detached
	 */
	hca_devp->hd_state = IBTL_HCA_DEV_DETACHED;

	/* Delete the entry for this hca_devp from hca_head_list */
	hcapp = &ibtl_hca_list;
	while (*hcapp != NULL) {
		if (*hcapp == hca_devp)
			break;
		hcapp = &(*hcapp)->hd_hca_dev_link;
	}

	if (mdi_phci_unregister(hca_devp->hd_hca_dip, 0) != MDI_SUCCESS) {
		hca_devp->hd_state = IBTL_HCA_DEV_ATTACHED; /* fix hd_state */
		mutex_exit(&ibtl_clnt_list_mutex);
		IBTF_DPRINTF_L1(ibtf, "ibc_pre_detach: PHCI unregister failed");
		return (IBC_FAILURE);
	}

	if (*hcapp == NULL) {
		hca_devp->hd_state = IBTL_HCA_DEV_ATTACHED; /* fix hd_state */
		mutex_exit(&ibtl_clnt_list_mutex);
		IBTF_DPRINTF_L1(ibtf, "ibc_pre_detach: HCA not attached");
		return (IBC_FAILURE);
	}
	*hcapp = hca_devp->hd_hca_dev_link;
	ibtl_fast_gid_cache_valid = B_FALSE;	/* invalidate fast_gid_cache */
	mutex_exit(&ibtl_clnt_list_mutex);

	return (IBC_SUCCESS);
}

/*
 * Function:
 *	ibc_detach
 * Input:
 *	ibc_clnt_hdl	- IBC HCA Handle as returned during ibc_attach call.
 * Output:
 *	none
 * Returns:
 *	None
 * Called by:
 *	CI to detach the HCA device from IBTF.
 * Description:
 *	Do the second step of detaching the HCA, which is required
 *	after a successful ibc_pre_detach.
 */
void
ibc_detach(ibc_clnt_hdl_t hca_devp)
{
	IBTF_DPRINTF_L2(ibtf, "ibc_detach(%p)", hca_devp);

	mutex_enter(&ibtl_clnt_list_mutex);
	if (hca_devp->hd_state != IBTL_HCA_DEV_DETACHED) {
		mutex_exit(&ibtl_clnt_list_mutex);
		IBTF_DPRINTF_L0(ibtf, "ibc_detach: HCA has not successfully "
		    "pre-detached");
		return;
	}

	cv_destroy(&hca_devp->hd_async_task_cv);
	cv_destroy(&hca_devp->hd_async_busy_cv);
	cv_destroy(&hca_devp->hd_portinfo_cv);

	kmem_free(hca_devp->hd_portinfop, hca_devp->hd_portinfo_len);
	mutex_exit(&ibtl_clnt_list_mutex);

	/* Free up the memory of per-client info struct */
	kmem_free(hca_devp, sizeof (ibtl_hca_devinfo_t) +
	    (hca_devp->hd_hca_attr->hca_nports - 1) *
	    sizeof (ibtl_async_port_status_t));
	ibtl_clear_ibhw_status();
}

/*
 * Function:
 *	ibt_ci_data_in()
 *
 * Input:
 *	hca_hdl			HCA Handle.
 *	flags			IBT_COMPLETE_ALLOC - Finish a deferred alloc.
 *      object                  Identifies the type object pointed to by
 *                              ibt_object_handle.
 *
 *      ibt_object_handle       The handle of the object to be associated with
 *				the data in/out
 *
 *	data_p			Pointer data passed in to the CI. The buffer
 *				should be allocated by the caller.
 *
 *	data_sz			The size of the buffer pointed to by
 *				data_p.
 * Output:
 *
 * Returns:
 *	IBT_SUCCESS
 *	IBT_NOT_SUPPORTED	Feature not supported.
 *	IBT_INVALID_PARAM	Invalid object type specified.
 *	IBT_HCA_HDL_INVALID
 *	IBT_AH_HDL_INVALID/IBT_UD_DEST_HDL_INVALID
 *	IBT_CHAN_HDL_INVALID/IBT_QP_HDL_INVALID
 *	IBT_CQ_HDL_INVALID
 *	IBT_EEC_HDL_INVALID
 *	IBT_RDD_HDL_INVALID
 *	IBT_MW_HDL_INVALID
 *	IBT_PD_HDL_INVALID
 *	IBT_SRQ_HDL_INVALID
 *
 * Description:
 *	Exchange CI private data for the specified CI object.
 */
ibt_status_t
ibt_ci_data_in(ibt_hca_hdl_t hca, ibt_ci_data_flags_t flags,
    ibt_object_type_t object, void *ibt_object_handle, void *data_p,
    size_t data_sz)
{
	ibt_status_t		retval;
	void			*ci_obj_hdl;

	IBTF_DPRINTF_L3(ibtf, "ibt_ci_data_in(%p, %x, %d, %p, %p, %d)",
	    hca, flags, object, ibt_object_handle, data_p, data_sz);

	switch (object) {
	case IBT_HDL_HCA:
		ci_obj_hdl = (void *)
		    (IBTL_HCA2CIHCA(((ibt_hca_hdl_t)ibt_object_handle)));
		break;

	case IBT_HDL_CHANNEL:
		ci_obj_hdl = (void *)
		    (IBTL_CHAN2CIQP(((ibt_channel_hdl_t)ibt_object_handle)));
		break;

	case IBT_HDL_CQ:
		ci_obj_hdl = (void *)
		    (((ibt_cq_hdl_t)(ibt_object_handle))->cq_ibc_cq_hdl);
		break;

	case IBT_HDL_EEC:
		ci_obj_hdl = (void *)
		    (((ibt_eec_hdl_t)(ibt_object_handle))->eec_ibc_eec_hdl);
		break;

	case IBT_HDL_UD_DEST:
		ci_obj_hdl = (void *)
		    (((ibt_ud_dest_hdl_t)(ibt_object_handle))->ud_ah);
		break;

	case IBT_HDL_SRQ:
		ci_obj_hdl = (void *)
		    (((ibt_srq_hdl_t)(ibt_object_handle))->srq_ibc_srq_hdl);
		break;

	default:
		ci_obj_hdl = ibt_object_handle;
		break;
	}

	retval = (IBTL_HCA2CIHCAOPS_P(hca)->ibc_ci_data_in)(IBTL_HCA2CIHCA(hca),
	    flags, object, ci_obj_hdl, data_p, data_sz);

	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf, "ibt_ci_data_in: Failed : %d", retval);
	}
	return (retval);
}

/*
 * Function:
 *	ibt_ci_data_out()
 *
 * Input:
 *	hca_hdl			HCA Handle.
 *	flags			IBT_COMPLETE_ALLOC - Finish a deferred alloc.
 *      object                  Identifies the type object pointed to by
 *                              ibt_object_handle.
 *
 *      ibt_object_handle       The handle of the object to be associated with
 *				the data in/out
 *
 *	data_p			Pointer to a buffer in which to return the CI
 *				private data. The buffer should be allocated
 *				by the caller.
 *
 *	data_sz			The size of the buffer pointed to by
 *				data_p.
 * Output:
 *
 * Returns:
 *	IBT_SUCCESS
 *	IBT_NOT_SUPPORTED	Feature not supported.
 *	IBT_INSUFF_RESOURCE	The buffer pointed to by data_p was too
 *				small to hold the data.
 *	IBT_INVALID_PARAM	Invalid object type specified.
 *	IBT_HCA_HDL_INVALID
 *	IBT_AH_HDL_INVALID/IBT_UD_DEST_HDL_INVALID
 *	IBT_CHAN_HDL_INVALID/IBT_QP_HDL_INVALID
 *	IBT_CQ_HDL_INVALID
 *	IBT_EEC_HDL_INVALID
 *	IBT_RDD_HDL_INVALID
 *	IBT_MW_HDL_INVALID
 *	IBT_PD_HDL_INVALID
 *	IBT_SRQ_HDL_INVALID
 *
 * Description:
 *	Exchange CI private data for the specified CI object.
 */
ibt_status_t
ibt_ci_data_out(ibt_hca_hdl_t hca, ibt_ci_data_flags_t flags,
    ibt_object_type_t object, void *ibt_object_handle, void *data_p,
    size_t data_sz)
{
	ibt_status_t		retval;
	void			*ci_obj_hdl;

	IBTF_DPRINTF_L3(ibtf, "ibt_ci_data_out(%p, %x, %d, %p, %p, %d)",
	    hca, flags, object, ibt_object_handle, data_p, data_sz);

	switch (object) {
	case  IBT_HDL_HCA:
		ci_obj_hdl = (void *)
		    (IBTL_HCA2CIHCA(((ibt_hca_hdl_t)ibt_object_handle)));
		break;

	case IBT_HDL_CHANNEL:
		ci_obj_hdl = (void *)
		    (IBTL_CHAN2CIQP(((ibt_channel_hdl_t)ibt_object_handle)));
		break;

	case IBT_HDL_CQ:
		ci_obj_hdl = (void *)
		    (((ibt_cq_hdl_t)(ibt_object_handle))->cq_ibc_cq_hdl);
		break;

	case IBT_HDL_EEC:
		ci_obj_hdl = (void *)
		    (((ibt_eec_hdl_t)(ibt_object_handle))->eec_ibc_eec_hdl);
		break;

	case IBT_HDL_UD_DEST:
		ci_obj_hdl = (void *)
		    (((ibt_ud_dest_hdl_t)(ibt_object_handle))->ud_ah);
		break;

	case IBT_HDL_SRQ:
		ci_obj_hdl = (void *)
		    (((ibt_srq_hdl_t)(ibt_object_handle))->srq_ibc_srq_hdl);
		break;

	default:
		ci_obj_hdl = ibt_object_handle;
		break;
	}

	retval = (IBTL_HCA2CIHCAOPS_P(hca)->ibc_ci_data_out)
	    (IBTL_HCA2CIHCA(hca), flags, object, ci_obj_hdl, data_p, data_sz);

	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf, "ibt_ci_data_out: Failed : %d", retval);
	}
	return (retval);
}


/*
 * FMA Support functions.
 */

#define	IBTL_ENA_MASK		0xC0000000
#define	IBTL_ENA_POSSIBLE	0x80000000
#define	IBTL_TYPE_SHIFT		27

/*
 * Function:
 *	ibt_get_module_failure()
 *
 * Input:
 *	type			Identifies the failing IB module.
 *	ena			'0' or the data for Fault Management
 *				Architecture (ENA).
 *
 * Returns:
 *	status			Special IB failure status.
 *
 * Description:
 *	XXX Just stubbed out to return failures with no data for Fault
 *	Management Architecture (ENAs) at the moment XXX
 */
ibt_status_t
ibt_get_module_failure(ibt_failure_type_t type, uint64_t ena)
{
	ibt_status_t	ret;

	IBTF_DPRINTF_L3(ibtf, "ibt_get_module_failure(%d, 0x%llX)", type, ena);

	switch (type) {
	case IBT_FAILURE_CI:
	case IBT_FAILURE_IBMF:
	case IBT_FAILURE_IBCM:
	case IBT_FAILURE_IBDM:
	case IBT_FAILURE_IBTL:
	case IBT_FAILURE_IBSM:
		ret = IBTL_ENA_POSSIBLE | (type << IBTL_TYPE_SHIFT);
		break;
	default:
		ret = IBT_FAILURE;
	}
	IBTF_DPRINTF_L3(ibtf, "ibt_get_module_failure: ret = 0x%lX", ret);
	return (ret);
}


/*
 * Function:
 *	ibc_get_ci_failure()
 *
 * Input:
 *	ena			'0' or the data for Fault Management
 *				Architecture (ENA).
 *
 * Returns:
 *	status			Special CI failure status.
 *
 * Description:
 *	Just use the function above to do the job.
 */
ibt_status_t
ibc_get_ci_failure(uint64_t ena)
{
	return (ibt_get_module_failure(IBT_FAILURE_CI, ena));
}


/*
 * ibt_check_failure()
 *	Function to test for special case failures.
 *
 *	status		An ibt_status_t returned from an IBTF function call.
 *
 *	reserved_p	NULL, or a pointer to where we store the data for
 *			Fault Management Architecture (ENA).
 *
 * Description:
 *	XXX Still need to determine the data for Fault Management Architecture
 *	(ENA), using 0 for now XXX
 */
ibt_failure_type_t
ibt_check_failure(ibt_status_t status, uint64_t *reserved_p)
{
	ibt_failure_type_t type;

	IBTF_DPRINTF_L3(ibtf, "ibt_check_failure(%X)", status);

	if ((status & IBTL_ENA_MASK) == IBTL_ENA_POSSIBLE) {
		type = status & ~IBTL_ENA_POSSIBLE >> IBTL_TYPE_SHIFT;

		/* XXX Need more work here... */
		if (reserved_p != NULL)
			*reserved_p = 0;
	} else {
		type = IBT_FAILURE_STANDARD;
		if (reserved_p != NULL)
			*reserved_p = 0;	/* No FMA Data Available. */
	}
	IBTF_DPRINTF_L3(ibtf, "ibt_check_failure: type = 0x%X", type);
	return (type);
}
