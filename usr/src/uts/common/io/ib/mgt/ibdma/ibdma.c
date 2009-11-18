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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Infiniband Device Management Agent for IB storage.
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/priv.h>
#include <sys/sysmacros.h>

#include <sys/ib/ibtl/ibti.h>		/* IB public interfaces */

#include <sys/ib/mgt/ibdma/ibdma.h>
#include <sys/ib/mgt/ibdma/ibdma_impl.h>

/*
 * NOTE: The IB Device Management Agent function, like other IB
 * managers and agents is best implemented as a kernel misc.
 * module.
 * Eventually we could modify IBT_DM_AGENT so that we don't need to
 * open each HCA to receive asynchronous events.
 */

#define	IBDMA_NAME_VERSION	"IB Device Management Agent"

extern struct mod_ops mod_miscops;

static void ibdma_ibt_async_handler(void *clnt, ibt_hca_hdl_t hdl,
	ibt_async_code_t code, ibt_async_event_t *event);

static void ibdma_mad_recv_cb(ibmf_handle_t ibmf_hdl,
	ibmf_msg_t *msgp, void *args);
static void ibdma_create_resp_mad(ibmf_msg_t *msgp);

/*
 * Misc. kernel module for now.
 */
static struct modlmisc modlmisc = {
	&mod_miscops,
	IBDMA_NAME_VERSION
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

static ibt_clnt_modinfo_t ibdma_ibt_modinfo = {
	IBTI_V_CURR,
	IBT_DM_AGENT,
	ibdma_ibt_async_handler,
	NULL,
	"ibdma"
};

/*
 * Module global state allocated at init().
 */
static ibdma_mod_state_t	*ibdma = NULL;

/*
 * Init/Fini handlers and IBTL HCA management prototypes.
 */
static int ibdma_init();
static int ibdma_fini();
static int ibdma_ibt_init();
static void ibdma_ibt_fini();
static ibdma_hca_t *ibdma_hca_init(ib_guid_t guid);
static void ibdma_hca_fini(ibdma_hca_t *hca);
static ibdma_hca_t *ibdma_find_hca(ib_guid_t guid);

/*
 * DevMgmt Agent MAD attribute handlers prototypes.
 */
static void ibdma_get_class_portinfo(ibmf_msg_t *msg);
static void ibdma_get_io_unitinfo(ibdma_hca_t *hca, ibmf_msg_t *msg);
static void ibdma_get_ioc_profile(ibdma_hca_t *hca, ibmf_msg_t *msg);
static void ibdma_get_ioc_services(ibdma_hca_t *hca, ibmf_msg_t *msg);

/*
 * _init()
 */
int
_init(void)
{
	int status;

	ASSERT(ibdma == NULL);

	ibdma = kmem_zalloc(sizeof (*ibdma), KM_SLEEP);
	ASSERT(ibdma != NULL);

	status = ibdma_init();
	if (status != DDI_SUCCESS) {
		kmem_free(ibdma, sizeof (*ibdma));
		ibdma = NULL;
		return (status);
	}

	status = mod_install(&modlinkage);
	if (status != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "_init, mod_install error (%d)", status);
		(void) ibdma_fini();
		kmem_free(ibdma, sizeof (*ibdma));
		ibdma = NULL;
	}
	return (status);
}

/*
 * _info()
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * _fini()
 */
int
_fini(void)
{
	int		status;
	int		slot;
	ibdma_hca_t	*hca;

	status = mod_remove(&modlinkage);
	if (status != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "_fini, mod_remove error (%d)", status);
		return (status);
	}

	/*
	 * Sanity check to see if anyone is not cleaning
	 * up appropriately.
	 */
	mutex_enter(&ibdma->ms_hca_list_lock);
	hca = list_head(&ibdma->ms_hca_list);
	while (hca != NULL) {
		for (slot = 0; slot < IBDMA_MAX_IOC; slot++) {
			if (hca->ih_ioc[slot].ii_inuse) {
				cmn_err(CE_NOTE, "_fini, IOC %d still attached"
				    " for (0x%0llx)", slot+1,
				    (u_longlong_t)hca->ih_iou_guid);
			}
		}
		hca = list_next(&ibdma->ms_hca_list, hca);
	}
	mutex_exit(&ibdma->ms_hca_list_lock);

	(void) ibdma_fini();
	kmem_free(ibdma, sizeof (*ibdma));
	return (status);
}

/*
 * ibdma_init()
 *
 * Initialize I/O Unit structure, generate initial HCA list and register
 * it port with the IBMF.
 */
static int
ibdma_init()
{
	int		status;

	/*
	 * Global lock and I/O Unit initialization.
	 */
	mutex_init(&ibdma->ms_hca_list_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Discover IB hardware and setup for device management agent
	 * support.
	 */
	status = ibdma_ibt_init();
	if (status != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "ibdma_init, ibt_attach failed (%d)",
		    status);
		mutex_destroy(&ibdma->ms_hca_list_lock);
		return (status);
	}

	return (status);
}

/*
 * ibdma_fini()
 *
 * Release resource if we are no longer in use.
 */
static int
ibdma_fini()
{
	ibdma_ibt_fini();
	mutex_destroy(&ibdma->ms_hca_list_lock);
	return (DDI_SUCCESS);
}

/*
 * ibdma_ibt_async_handler()
 */
/* ARGSUSED */
static void
ibdma_ibt_async_handler(void *clnt, ibt_hca_hdl_t hdl,
	ibt_async_code_t code, ibt_async_event_t *event)
{
	ibdma_hca_t	*hca;

	switch (code) {

	case IBT_EVENT_PORT_UP:
	case IBT_ERROR_PORT_DOWN:
		break;

	case IBT_HCA_ATTACH_EVENT:
		mutex_enter(&ibdma->ms_hca_list_lock);
		hca = ibdma_hca_init(event->ev_hca_guid);
		if (hca != NULL) {
			list_insert_tail(&ibdma->ms_hca_list, hca);
			cmn_err(CE_NOTE, "hca ibt hdl (%p)",
			    (void *)hca->ih_ibt_hdl);
			ibdma->ms_num_hcas++;
		}
		mutex_exit(&ibdma->ms_hca_list_lock);
		break;

	case IBT_HCA_DETACH_EVENT:
		mutex_enter(&ibdma->ms_hca_list_lock);
		hca = ibdma_find_hca(event->ev_hca_guid);
		if (hca != NULL) {
			list_remove(&ibdma->ms_hca_list, hca);
			cmn_err(CE_NOTE, "removing hca (%p) (0x%llx)",
			    (void *)hca, hca ?
			    (u_longlong_t)hca->ih_iou_guid : 0x0ll);
			ibdma_hca_fini(hca);
		}
		mutex_exit(&ibdma->ms_hca_list_lock);
		break;

	default:
		cmn_err(CE_NOTE, "ibt_async_handler, unhandled event(%d)",
		    code);
		break;
	}

}

/*
 * ibdma_ibt_init()
 */
static int
ibdma_ibt_init()
{
	int		status;
	int		hca_cnt;
	int		hca_ndx;
	ib_guid_t	*guid;
	ibdma_hca_t	*hca;

	/*
	 * Attach to IBTF and get HCA list.
	 */
	status = ibt_attach(&ibdma_ibt_modinfo, NULL,
	    ibdma, &ibdma->ms_ibt_hdl);
	if (status != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "ibt_init, ibt_attach failed (%d)",
		    status);
		return (status);
	}

	hca_cnt = ibt_get_hca_list(&guid);
	if (hca_cnt < 1) {
#ifdef	DEBUG_IBDMA
		cmn_err(CE_NOTE, "ibt_init, no HCA(s) found");
#endif
		(void) ibt_detach(ibdma->ms_ibt_hdl);
		return (DDI_FAILURE);
	}

	list_create(&ibdma->ms_hca_list, sizeof (ibdma_hca_t),
	    offsetof(ibdma_hca_t, ih_node));

	mutex_enter(&ibdma->ms_hca_list_lock);

	for (hca_ndx = 0; hca_ndx < hca_cnt; hca_ndx++) {
#ifdef	DEBUG_IBDMA
		cmn_err(CE_NOTE, "adding hca GUID(0x%llx)",
		    (u_longlong_t)guid[hca_ndx]);
#endif

		hca = ibdma_hca_init(guid[hca_ndx]);
		if (hca == NULL) {
			cmn_err(CE_NOTE, "ibt_init, hca_init GUID(0x%llx)"
			    " failed", (u_longlong_t)guid[hca_ndx]);
			continue;
		}
		list_insert_tail(&ibdma->ms_hca_list, hca);
		ibdma->ms_num_hcas++;
	}

	mutex_exit(&ibdma->ms_hca_list_lock);

	ibt_free_hca_list(guid, hca_cnt);
#ifdef	DEBUG_IBDMA
	cmn_err(CE_NOTE, "Added %d HCA(s)",
	    ibdma->ms_num_hcas);
#endif
	return (DDI_SUCCESS);
}

/*
 * ibdma_ibt_fini()
 */
static void
ibdma_ibt_fini()
{
	ibdma_hca_t		*hca;
	ibdma_hca_t		*next;

	mutex_enter(&ibdma->ms_hca_list_lock);
	hca = list_head(&ibdma->ms_hca_list);
	while (hca != NULL) {
		next = list_next(&ibdma->ms_hca_list, hca);
		list_remove(&ibdma->ms_hca_list, hca);
#ifdef	DEBUG_IBDMA
		cmn_err(CE_NOTE, "removing hca (%p) (0x%llx)",
		    (void *)hca, hca ?
		    (u_longlong_t)hca->ih_iou_guid : 0x0ll);
		cmn_err(CE_NOTE, "hca ibt hdl (%p)",
		    (void *)hca->ih_ibt_hdl);
#endif
		ibdma_hca_fini(hca);
		hca = next;
	}
	list_destroy(&ibdma->ms_hca_list);

	ibt_detach(ibdma->ms_ibt_hdl);
	ibdma->ms_ibt_hdl   = NULL;
	ibdma->ms_num_hcas  = 0;
	mutex_exit(&ibdma->ms_hca_list_lock);
}

/*
 * ibdma_find_hca()
 */
static ibdma_hca_t *
ibdma_find_hca(ib_guid_t guid)
{
	ibdma_hca_t	*hca;

	ASSERT(mutex_owned(&ibdma->ms_hca_list_lock));

	hca = list_head(&ibdma->ms_hca_list);
	while (hca != NULL) {
		if (hca->ih_iou_guid == guid) {
			break;
		}
		hca = list_next(&ibdma->ms_hca_list, hca);
	}
	return (hca);
}

/*
 * ibdma_hca_init()
 */
static ibdma_hca_t *
ibdma_hca_init(ib_guid_t guid)
{
	ibt_status_t		status;
	ibdma_hca_t		*hca;
	ibdma_port_t		*port;
	ibt_hca_attr_t		hca_attr;
	int			ndx;

	ASSERT(mutex_owned(&ibdma->ms_hca_list_lock));

	status = ibt_query_hca_byguid(guid, &hca_attr);
	if (status != IBT_SUCCESS) {
		cmn_err(CE_NOTE, "hca_init HCA query error (%d)",
		    status);
		return (NULL);
	}

	if (ibdma_find_hca(guid) != NULL) {
#ifdef	DEBUG_IBDMA
		cmn_err(CE_NOTE, "hca_init HCA already exists");
#endif
		return (NULL);
	}

	hca = kmem_zalloc(sizeof (ibdma_hca_t) +
	    (hca_attr.hca_nports-1)*sizeof (ibdma_port_t), KM_SLEEP);
	ASSERT(hca != NULL);

	hca->ih_nports   = hca_attr.hca_nports;

	rw_init(&hca->ih_iou_rwlock, NULL, RW_DRIVER, NULL);
	rw_enter(&hca->ih_iou_rwlock, RW_WRITER);
	hca->ih_iou_guid		= guid;
	hca->ih_iou.iou_changeid	= h2b16(1);
	hca->ih_iou.iou_num_ctrl_slots	= IBDMA_MAX_IOC;
	hca->ih_iou.iou_flag		= IB_DM_IOU_OPTIONROM_ABSENT;

	list_create(&hca->ih_hdl_list, sizeof (ibdma_hdl_impl_t),
	    offsetof(ibdma_hdl_impl_t, ih_node));
	rw_exit(&hca->ih_iou_rwlock);

	/*
	 * It would be better to not open, but IBTL is setup to only allow
	 * certain managers to get async call backs if not open.
	 */
	status = ibt_open_hca(ibdma->ms_ibt_hdl, guid, &hca->ih_ibt_hdl);
	if (status != IBT_SUCCESS) {
		cmn_err(CE_NOTE, "hca_init() IBT open failed (%d)",
		    status);

		list_destroy(&hca->ih_hdl_list);
		rw_destroy(&hca->ih_iou_rwlock);
		kmem_free(hca, sizeof (ibdma_hca_t) +
		    (hca_attr.hca_nports-1)*sizeof (ibdma_port_t));
		return (NULL);
	}

	/*
	 * Register with the IB Management Framework and setup MAD call-back.
	 */
	for (ndx = 0; ndx < hca->ih_nports; ndx++) {
		port = &hca->ih_port[ndx];
		port->ip_hcap = hca;
		port->ip_ibmf_reg.ir_ci_guid	= hca->ih_iou_guid;
		port->ip_ibmf_reg.ir_port_num	= ndx + 1;
		port->ip_ibmf_reg.ir_client_class = DEV_MGT_AGENT;

		status = ibmf_register(&port->ip_ibmf_reg, IBMF_VERSION,
		    0, NULL, NULL, &port->ip_ibmf_hdl, &port->ip_ibmf_caps);
		if (status != IBMF_SUCCESS) {
			cmn_err(CE_NOTE, "hca_init, IBMF register failed (%d)",
			    status);
			port->ip_ibmf_hdl = NULL;
			ibdma_hca_fini(hca);
			return (NULL);
		}

		status = ibmf_setup_async_cb(port->ip_ibmf_hdl,
		    IBMF_QP_HANDLE_DEFAULT, ibdma_mad_recv_cb, port, 0);
		if (status != IBMF_SUCCESS) {
			cmn_err(CE_NOTE, "hca_init, IBMF cb setup failed (%d)",
			    status);
			ibdma_hca_fini(hca);
			return (NULL);
		}

		status = ibt_modify_port_byguid(hca->ih_iou_guid,
		    ndx+1, IBT_PORT_SET_DEVMGT, 0);
		if (status != IBT_SUCCESS) {
			cmn_err(CE_NOTE, "hca_init, IBT modify port caps"
			    " error (%d)", status);
			ibdma_hca_fini(hca);
			return (NULL);
		}
	}
	return (hca);
}

/*
 * ibdma_hca_fini()
 */
static void
ibdma_hca_fini(ibdma_hca_t *hca)
{
	int			status;
	int			ndx;
	ibdma_port_t		*port;
	ibdma_hdl_impl_t	*hdl;
	ibdma_hdl_impl_t	*hdl_next;

	ASSERT(mutex_owned(&ibdma->ms_hca_list_lock));
	ASSERT(hca != NULL);

	rw_enter(&hca->ih_iou_rwlock, RW_WRITER);

	/*
	 * All handles should have been de-registered, but release
	 * any that are outstanding.
	 */
	hdl = list_head(&hca->ih_hdl_list);
	while (hdl != NULL) {
		hdl_next = list_next(&hca->ih_hdl_list, hdl);
		list_remove(&hca->ih_hdl_list, hdl);
		cmn_err(CE_NOTE, "hca_fini, unexpected ibdma user handle"
		    " exists");
		kmem_free(hdl, sizeof (*hdl));
		hdl = hdl_next;
	}
	list_destroy(&hca->ih_hdl_list);

	/*
	 * Un-register with the IBMF.
	 */
	for (ndx = 0; ndx < hca->ih_nports; ndx++) {
		port = &hca->ih_port[ndx];
		port->ip_hcap = NULL;

		status = ibt_modify_port_byguid(hca->ih_iou_guid,
		    ndx+1, IBT_PORT_RESET_DEVMGT, 0);
		if (status != IBT_SUCCESS)
			cmn_err(CE_NOTE, "hca_fini, IBT modify port caps"
			    " error (%d)", status);

		if (port->ip_ibmf_hdl == NULL)
			continue;

		status = ibmf_tear_down_async_cb(port->ip_ibmf_hdl,
		    IBMF_QP_HANDLE_DEFAULT, 0);
		if (status != IBMF_SUCCESS)
			cmn_err(CE_NOTE, "hca_fini, IBMF tear down cb"
			    " error (%d)", status);

		status = ibmf_unregister(&port->ip_ibmf_hdl, 0);
		if (status != IBMF_SUCCESS)
			cmn_err(CE_NOTE, "hca_fini, IBMF un-register"
			    " error (%d)", status);
		port->ip_ibmf_hdl = NULL;
	}

	status = ibt_close_hca(hca->ih_ibt_hdl);
	if (status != IBT_SUCCESS)
		cmn_err(CE_NOTE, "hca_fini close error (%d)", status);

	rw_exit(&hca->ih_iou_rwlock);
	rw_destroy(&hca->ih_iou_rwlock);
	kmem_free(hca, sizeof (ibdma_hca_t) +
	    (hca->ih_nports-1) * sizeof (ibdma_port_t));
}

/* DM IBMF MAD handlers */
/*
 * ibdma_create_resp_mad()
 */
static void
ibdma_create_resp_mad(ibmf_msg_t *msgp)
{
	/*
	 * Allocate send buffer fix up hdr for response.
	 */
	msgp->im_msgbufs_send.im_bufs_mad_hdr =
	    kmem_zalloc(IBDMA_MAD_SIZE, KM_SLEEP);

	msgp->im_msgbufs_send.im_bufs_cl_hdr = (uchar_t *)
	    msgp->im_msgbufs_send.im_bufs_mad_hdr + sizeof (ib_mad_hdr_t);
	msgp->im_msgbufs_send.im_bufs_cl_hdr_len = IBDMA_DM_MAD_HDR_SIZE;
	msgp->im_msgbufs_send.im_bufs_cl_data =
	    ((char *)msgp->im_msgbufs_send.im_bufs_cl_hdr +
	    IBDMA_DM_MAD_HDR_SIZE);
	msgp->im_msgbufs_send.im_bufs_cl_data_len =
	    IBDMA_MAD_SIZE - sizeof (ib_mad_hdr_t) - IBDMA_DM_MAD_HDR_SIZE;
	(void) memcpy(msgp->im_msgbufs_send.im_bufs_mad_hdr,
	    msgp->im_msgbufs_recv.im_bufs_mad_hdr, IBDMA_MAD_SIZE);

	/*
	 * We may want to support a GRH since this is a GMP; not
	 * required for current SRP device manager platforms.
	 */
#if 0
	if (msgp->im_msg_flags & IBMF_MSG_FLAGS_GLOBAL_ADDRESS) {
		ib_gid_t	temp = msgp->im_global_addr.ig_recver_gid;

		msgp->im_global_addr.ig_recver_gid =
		    msgp->im_global_addr.ig_sender_gid;
		msgp->im_global_addr.ig_sender_gid = temp;
	}
#endif
}

/*
 * ibdma_mad_send_cb()
 */
/* ARGSUSED */
static void
ibdma_mad_send_cb(ibmf_handle_t ibmf_hdl, ibmf_msg_t *msgp, void *arg)
{
	/*
	 * Just free the buffers and release the message.
	 */
	if (msgp->im_msgbufs_send.im_bufs_mad_hdr != NULL) {
		kmem_free(msgp->im_msgbufs_send.im_bufs_mad_hdr,
		    IBDMA_MAD_SIZE);
		msgp->im_msgbufs_send.im_bufs_mad_hdr = NULL;
	}
	if (ibmf_free_msg(ibmf_hdl, &msgp) != IBMF_SUCCESS) {
		cmn_err(CE_NOTE, "mad_send_cb, IBMF message free error");
	}
}

/*
 * ibdma_mad_recv_cb()
 */
static void
ibdma_mad_recv_cb(ibmf_handle_t ibmf_hdl, ibmf_msg_t *msgp, void *args)
{
	int		status;
	ib_mad_hdr_t	*in_mad;
	ib_mad_hdr_t	*out_mad;
	ibdma_port_t	*port = args;

	ASSERT(msgp != NULL);
	ASSERT(port != NULL);

	if (msgp->im_msg_status != IBMF_SUCCESS) {
		cmn_err(CE_NOTE, "mad_recv_cb, bad MAD receive status (%d)",
		    msgp->im_msg_status);
		goto drop;
	}

	in_mad = msgp->im_msgbufs_recv.im_bufs_mad_hdr;

	if (in_mad->MgmtClass != MAD_MGMT_CLASS_DEV_MGT) {
#ifdef	DEBUG_IBDMA
		cmn_err(CE_NOTE, "mad_recv_cb, MAD not of Dev Mgmt Class");
#endif
		goto drop;
	}

	ibdma_create_resp_mad(msgp);
	out_mad = msgp->im_msgbufs_send.im_bufs_mad_hdr;

	out_mad->R_Method = IB_DM_DEVMGT_METHOD_GET_RESP;
	out_mad->Status   = 0;

	if (in_mad->R_Method == MAD_METHOD_SET) {
#ifdef	DEBUG_IBDMA
		cmn_err(CE_NOTE, "mad_recv_cb, no attributes supported"
		    " for set");
#endif
		out_mad->Status = MAD_STATUS_UNSUPP_METHOD_ATTR;
		goto send_resp;
	}

	if (in_mad->R_Method != MAD_METHOD_GET) {
#ifdef	DEBUG_IBDMA
		cmn_err(CE_NOTE, "mad_recv_cb, no attributes supported"
		    " for set");
#endif
		out_mad->Status = MAD_STATUS_UNSUPP_METHOD;
		goto send_resp;
	}

	/*
	 * Process a GET method.
	 */
	switch (b2h16(in_mad->AttributeID)) {

	case IB_DM_ATTR_CLASSPORTINFO:
		ibdma_get_class_portinfo(msgp);
		break;

	case IB_DM_ATTR_IO_UNITINFO:
		ibdma_get_io_unitinfo(port->ip_hcap, msgp);
		break;

	case IB_DM_ATTR_IOC_CTRL_PROFILE:
		ibdma_get_ioc_profile(port->ip_hcap, msgp);
		break;

	case IB_DM_ATTR_SERVICE_ENTRIES:
		ibdma_get_ioc_services(port->ip_hcap, msgp);
		break;

	default:
		out_mad->Status = MAD_STATUS_UNSUPP_METHOD_ATTR;
		break;
	}

send_resp:
	status = ibmf_msg_transport(ibmf_hdl, IBMF_QP_HANDLE_DEFAULT,
	    msgp, NULL, ibdma_mad_send_cb, NULL, 0);
	if (status != IBMF_SUCCESS) {
		cmn_err(CE_NOTE, "mad_recv_cb, send error (%d)", status);
		ibdma_mad_send_cb(ibmf_hdl, msgp, NULL);
	}
	return;

drop:
	status = ibmf_free_msg(ibmf_hdl, &msgp);
	if (status != IBMF_SUCCESS) {
		cmn_err(CE_NOTE, "mad_recv_cb, error dropping (%d)",
		    status);
	}
}

/*
 * ibdma_get_class_portinfo()
 */
static void
ibdma_get_class_portinfo(ibmf_msg_t *msg)
{
	ib_mad_classportinfo_t	*cpip;

	cpip = (ib_mad_classportinfo_t *)msg->im_msgbufs_send.im_bufs_cl_data;
	bzero(cpip, sizeof (*cpip));
	cpip->BaseVersion   = MAD_CLASS_BASE_VERS_1;
	cpip->ClassVersion  = IB_DM_CLASS_VERSION_1;
	cpip->RespTimeValue = h2b32(IBDMA_DM_RESP_TIME);
}

/*
 * ibdma_get_io_unitinfo()
 */
static void
ibdma_get_io_unitinfo(ibdma_hca_t *hca, ibmf_msg_t *msg)
{
	ib_dm_io_unitinfo_t	*uip;

	uip = (ib_dm_io_unitinfo_t *)msg->im_msgbufs_send.im_bufs_cl_data;
	rw_enter(&hca->ih_iou_rwlock, RW_READER);
	bcopy(&hca->ih_iou, uip, sizeof (ib_dm_io_unitinfo_t));
	rw_exit(&hca->ih_iou_rwlock);
}

/*
 * ibdma_get_ioc_profile()
 */
static void
ibdma_get_ioc_profile(ibdma_hca_t *hca, ibmf_msg_t *msg)
{
	ib_dm_ioc_ctrl_profile_t	*iocp;
	uint32_t			slot;

	ASSERT(msg != NULL);

	slot = b2h32(msg->im_msgbufs_recv.im_bufs_mad_hdr->AttributeModifier);
	iocp = (ib_dm_ioc_ctrl_profile_t *)
	    msg->im_msgbufs_send.im_bufs_cl_data;
	if (slot == 0 || slot > IBDMA_MAX_IOC) {
		msg->im_msgbufs_send.im_bufs_mad_hdr->Status =
		    MAD_STATUS_INVALID_FIELD;
		return;
	}

	slot--;
	rw_enter(&hca->ih_iou_rwlock, RW_READER);
	if (ibdma_get_ioc_state(hca, slot) == IBDMA_IOC_PRESENT) {
		bcopy(&hca->ih_ioc[slot].ii_profile, iocp,
		    sizeof (ib_dm_ioc_ctrl_profile_t));
	} else {
		msg->im_msgbufs_send.im_bufs_mad_hdr->Status =
		    IB_DM_DEVMGT_MAD_STAT_NORESP;
	}
	rw_exit(&hca->ih_iou_rwlock);
}

/*
 * ibdma_get_ioc_services()
 */
static void
ibdma_get_ioc_services(ibdma_hca_t *hca, ibmf_msg_t *msg)
{
	ib_dm_srv_t	*to_svcp;
	ib_dm_srv_t	*from_svcp;
	uint32_t	slot;
	uint8_t		hi;
	uint8_t		low;

	ASSERT(msg != NULL);

	slot = b2h32(msg->im_msgbufs_recv.im_bufs_mad_hdr->AttributeModifier);
	hi   = (slot >> 8) & 0x00FF;
	low  = slot  & 0x00FF;
	slot = (slot >> 16) & 0x0FFFF;
	if (slot == 0 || slot > IBDMA_MAX_IOC) {
		msg->im_msgbufs_send.im_bufs_mad_hdr->Status =
		    MAD_STATUS_INVALID_FIELD;
		return;
	}

	slot--;

	rw_enter(&hca->ih_iou_rwlock, RW_READER);
	if (ibdma_get_ioc_state(hca, slot) != IBDMA_IOC_PRESENT) {
		msg->im_msgbufs_send.im_bufs_mad_hdr->Status =
		    IB_DM_DEVMGT_MAD_STAT_NORESP;
		rw_exit(&hca->ih_iou_rwlock);
		return;
	}

	if ((low > hi) || (hi - low > 4)) {
		msg->im_msgbufs_send.im_bufs_mad_hdr->Status =
		    MAD_STATUS_INVALID_FIELD;
		rw_exit(&hca->ih_iou_rwlock);
		return;
	}

	if (hi > hca->ih_ioc[slot].ii_profile.ioc_service_entries) {
		msg->im_msgbufs_send.im_bufs_mad_hdr->Status =
		    MAD_STATUS_INVALID_FIELD;
		rw_exit(&hca->ih_iou_rwlock);
		return;
	}

	to_svcp = (ib_dm_srv_t *)msg->im_msgbufs_send.im_bufs_cl_data;
	from_svcp = hca->ih_ioc[slot].ii_srvcs + low;
	bcopy(from_svcp, to_svcp, sizeof (ib_dm_srv_t) * (hi - low + 1));
	rw_exit(&hca->ih_iou_rwlock);
}


/*
 * Client API internal helpers
 */

/*
 * ibdma_hdl_to_ioc()
 */
ibdma_hdl_impl_t *
ibdma_get_hdl_impl(ibdma_hdl_t hdl)
{
	ibdma_hca_t		*hca;
	ibdma_hdl_impl_t	*hdl_tmp = hdl;
	ibdma_hdl_impl_t	*hdl_impl;

	ASSERT(mutex_owned(&ibdma->ms_hca_list_lock));

	if (hdl_tmp == NULL) {
		cmn_err(CE_NOTE, "get_hdl_impl, NULL handle");
		return (NULL);
	}

	hca = ibdma_find_hca(hdl_tmp->ih_iou_guid);
	if (hca == NULL) {
		cmn_err(CE_NOTE, "get_hdl_impl, invalid handle, bad IOU");
		return (NULL);
	}

	hdl_impl = list_head(&hca->ih_hdl_list);
	while (hdl_impl != NULL) {
		if (hdl_impl == hdl_tmp) {
			break;
		}
		hdl_impl = list_next(&hca->ih_hdl_list, hdl_impl);
	}
	return (hdl_impl);
}

/*
 * ibdma_set_ioc_state()
 *
 * slot should be 0 based (not DM 1 based slot).
 *
 * I/O Unit write lock should be held outside of this function.
 */
static void
ibdma_set_ioc_state(ibdma_hca_t *hca, int slot, ibdma_ioc_state_t state)
{
	uint8_t		cur;
	uint16_t	id;

	cur = hca->ih_iou.iou_ctrl_list[slot >> 1];
	if (slot & 1) {
		cur = (cur & 0xF0) | state;
	} else {
		cur = (cur & 0x0F) | (state << 4);
	}
	hca->ih_iou.iou_ctrl_list[slot >> 1] = cur;
	id = b2h16(hca->ih_iou.iou_changeid);
	id++;
	hca->ih_iou.iou_changeid = h2b16(id);
#ifdef	DEBUG_IBDMA
	cmn_err(CE_NOTE, "set_ioc_state, slot offset(%d), value(%d)",
	    slot, hca->ih_iou.iou_ctrl_list[slot >> 1]);
#endif
}

/*
 * ibdma_get_ioc_state()
 *
 * slot should be 0 based (not DM 1 based slot).
 *
 * I/O Unit read lock should be held outside of this function.
 */
static ibdma_ioc_state_t
ibdma_get_ioc_state(ibdma_hca_t *hca, int slot)
{
	uint8_t		cur;

	if (slot >= IBDMA_MAX_IOC)
		return (0xFF);

	cur = hca->ih_iou.iou_ctrl_list[slot >> 1];
	cur = slot & 1 ?  cur & 0x0F : cur >> 4;
	return (cur);
}

/* CLIENT API Implementation */
/*
 * ibdma_ioc_register()
 *
 */
ibdma_hdl_t
ibdma_ioc_register(ib_guid_t iou_guid, ib_dm_ioc_ctrl_profile_t *profile,
	ib_dm_srv_t *services)
{
	int			free_slot = -1;
	int			svc_entries;
	int			slot;
	ibdma_hca_t		*hca;
	ibdma_hdl_impl_t	*hdl;

	if (profile == NULL || services == NULL) {
		cmn_err(CE_NOTE, "ioc_register, bad parameter");
		return (NULL);
	}

	svc_entries = profile->ioc_service_entries;
	if (svc_entries == 0) {
		cmn_err(CE_NOTE, "ioc_register, bad profile no service");
		return (NULL);
	}

	/*
	 * Find the associated I/O Unit.
	 */
	mutex_enter(&ibdma->ms_hca_list_lock);
	hca = ibdma_find_hca(iou_guid);
	if (hca == NULL) {
		mutex_exit(&ibdma->ms_hca_list_lock);
		cmn_err(CE_NOTE, "ioc_register, bad I/O Unit GUID (0x%llx)",
		    (u_longlong_t)iou_guid);
		return (NULL);
	}

	rw_enter(&hca->ih_iou_rwlock, RW_WRITER);
	for (slot = 0; slot < IBDMA_MAX_IOC; slot++) {
		if (hca->ih_ioc[slot].ii_inuse == 0) {
			if (free_slot == -1) {
				free_slot = slot;
			}
			continue;
		}

		if (profile->ioc_guid ==
		    hca->ih_ioc[slot].ii_profile.ioc_guid) {
			rw_exit(&hca->ih_iou_rwlock);
			mutex_exit(&ibdma->ms_hca_list_lock);
#ifdef	DEBUG_IBDMA
			cmn_err(CE_NOTE, "ioc_register, IOC previously"
			    " registered");
#endif
			return (NULL);
		}
	}

	if (free_slot < 0) {
		rw_exit(&hca->ih_iou_rwlock);
		cmn_err(CE_NOTE, "ioc_register, error - I/O Unit full");
		return (NULL);
	}
#ifdef	DEBUG_IBDMA
	cmn_err(CE_NOTE, "ibdma_ioc_register, assigned to 0 based slot (%d)",
	    free_slot);
#endif

	hca->ih_ioc[free_slot].ii_inuse = 1;
	hca->ih_ioc[free_slot].ii_slot  = free_slot;
	hca->ih_ioc[free_slot].ii_hcap  = hca;

	/*
	 * Allocate local copy of profile and services.
	 */
	hca->ih_ioc[free_slot].ii_srvcs =
	    kmem_zalloc(sizeof (ib_dm_srv_t) * svc_entries, KM_SLEEP);
	bcopy(profile, &hca->ih_ioc[free_slot].ii_profile,
	    sizeof (ib_dm_ioc_ctrl_profile_t));
	bcopy(services, hca->ih_ioc[free_slot].ii_srvcs,
	    sizeof (ib_dm_srv_t) * svc_entries);

	/*
	 * Update the profile copy with the I/O controller slot assigned.
	 * The slot occupies the lower 8 biths of the vendor ID/slot 32bit
	 * field.
	 */
	profile->ioc_vendorid |= h2b32(free_slot);

	ibdma_set_ioc_state(hca, free_slot, IBDMA_IOC_PRESENT);

	hdl = kmem_alloc(sizeof (*hdl), KM_SLEEP);
	hdl->ih_iou_guid = hca->ih_iou_guid;
	hdl->ih_ioc_ndx = (uint8_t)free_slot;
	list_insert_tail(&hca->ih_hdl_list, hdl);

	rw_exit(&hca->ih_iou_rwlock);
	mutex_exit(&ibdma->ms_hca_list_lock);

	return ((ibdma_hdl_t)hdl);
}

/*
 * ibdma_ioc_unregister()
 *
 */
ibdma_status_t
ibdma_ioc_unregister(ibdma_hdl_t hdl)
{
	ibdma_ioc_t		*ioc;
	ibdma_hca_t		*hca;
	int			slot;
	ibdma_hdl_impl_t	*hdl_tmp = hdl;
	ibdma_hdl_impl_t	*hdl_impl;

	if (hdl == NULL) {
		cmn_err(CE_NOTE, "ioc_unregister, NULL handle");
		return (IBDMA_BAD_PARAM);
	}

	mutex_enter(&ibdma->ms_hca_list_lock);
	hca = ibdma_find_hca(hdl_tmp->ih_iou_guid);
	if (hca == NULL) {
		cmn_err(CE_NOTE, "ioc_unregsiter, invalid handle, IOU"
		    " not found");
		mutex_exit(&ibdma->ms_hca_list_lock);
		return (IBDMA_BAD_PARAM);
	}

	hdl_impl = list_head(&hca->ih_hdl_list);
	while (hdl_impl != NULL) {
		if (hdl_impl == hdl_tmp) {
			break;
		}
		hdl_impl = list_next(&hca->ih_hdl_list, hdl_impl);
	}

	if (hdl_impl == NULL) {
		cmn_err(CE_NOTE, "ioc_unregsiter, invalid handle, not found");
		mutex_exit(&ibdma->ms_hca_list_lock);
		return (IBDMA_BAD_PARAM);
	}

	list_remove(&hca->ih_hdl_list, hdl_impl);

	if (hdl_impl->ih_ioc_ndx >= IBDMA_MAX_IOC) {
		cmn_err(CE_NOTE, "ioc_unregister, corrupted handle");
		kmem_free(hdl_impl, sizeof (*hdl_impl));
		mutex_exit(&ibdma->ms_hca_list_lock);
		return (IBDMA_BAD_PARAM);
	}
	ioc = &hca->ih_ioc[hdl_impl->ih_ioc_ndx];
	kmem_free(hdl_impl, sizeof (*hdl_impl));

	if (ioc->ii_slot > IBDMA_MAX_IOC) {
		cmn_err(CE_NOTE, "ioc_unregister, IOC corrupted, bad"
		    " slot in IOC");
		mutex_exit(&ibdma->ms_hca_list_lock);
		return (IBDMA_BAD_PARAM);
	}

	rw_enter(&ioc->ii_hcap->ih_iou_rwlock, RW_WRITER);
	if (ioc->ii_inuse == 0) {
		rw_exit(&ioc->ii_hcap->ih_iou_rwlock);
		mutex_exit(&ibdma->ms_hca_list_lock);
		cmn_err(CE_NOTE, "ioc_unregister, slot not in use (%d)",
		    ioc->ii_slot+1);
		return (IBDMA_BAD_PARAM);
	}

	ASSERT(ioc->ii_srvcs != NULL);

	slot = ioc->ii_slot;
	hca  = ioc->ii_hcap;
	kmem_free(ioc->ii_srvcs, sizeof (ib_dm_srv_t) *
	    ioc->ii_profile.ioc_service_entries);
	bzero(ioc, sizeof (ibdma_ioc_t));
	ibdma_set_ioc_state(hca, slot, IBDMA_IOC_NOT_INSTALLED);

	rw_exit(&hca->ih_iou_rwlock);
	mutex_exit(&ibdma->ms_hca_list_lock);

	return (IBDMA_SUCCESS);
}

/*
 * ibdma_ioc_update()
 *
 */
ibdma_status_t
ibdma_ioc_update(ibdma_hdl_t hdl, ib_dm_ioc_ctrl_profile_t *profile,
	ib_dm_srv_t *services)
{
	ibdma_ioc_t		*ioc;
	ibdma_hca_t		*hca;
	ibdma_hdl_impl_t	*hdl_tmp = hdl;
	ibdma_hdl_impl_t	*hdl_impl;

	if (hdl == NULL) {
		cmn_err(CE_NOTE, "ioc_update, NULL handle");
		return (IBDMA_BAD_PARAM);
	}

	if (profile == NULL || services == NULL) {
		cmn_err(CE_NOTE, "ioc_update, NULL parameter");
		return (IBDMA_BAD_PARAM);
	}

	mutex_enter(&ibdma->ms_hca_list_lock);
	hca = ibdma_find_hca(hdl_tmp->ih_iou_guid);
	if (hca == NULL) {
		cmn_err(CE_NOTE, "ioc_update, invalid handle, IOU not found");
		mutex_exit(&ibdma->ms_hca_list_lock);
		return (IBDMA_BAD_PARAM);
	}

	hdl_impl = list_head(&hca->ih_hdl_list);
	while (hdl_impl != NULL) {
		if (hdl_impl == hdl_tmp) {
			break;
		}
		hdl_impl = list_next(&hca->ih_hdl_list, hdl_impl);
	}

	if (hdl_impl == NULL) {
		cmn_err(CE_NOTE, "ioc_update, invalid handle, not found");
		mutex_exit(&ibdma->ms_hca_list_lock);
		return (IBDMA_BAD_PARAM);
	}

	if (hdl_impl->ih_ioc_ndx >= IBDMA_MAX_IOC) {
		cmn_err(CE_NOTE, "ioc_update, corrupted handle");
		mutex_exit(&ibdma->ms_hca_list_lock);
		return (IBDMA_BAD_PARAM);
	}
	ioc = &hca->ih_ioc[hdl_impl->ih_ioc_ndx];

	if (ioc->ii_slot >= IBDMA_MAX_IOC || ioc->ii_hcap == NULL) {
		cmn_err(CE_NOTE, "ioc_update, bad handle (%p)",
		    (void *)hdl);
		mutex_exit(&ibdma->ms_hca_list_lock);
		return (IBDMA_BAD_PARAM);
	}

	rw_enter(&ioc->ii_hcap->ih_iou_rwlock, RW_WRITER);
	if (ioc->ii_inuse == 0) {
		rw_exit(&ioc->ii_hcap->ih_iou_rwlock);
		mutex_exit(&ibdma->ms_hca_list_lock);
		cmn_err(CE_NOTE, "ioc_udate slot not in use (%d)",
		    ioc->ii_slot+1);
		return (IBDMA_BAD_PARAM);
	}

	ASSERT(ioc->ii_srvcs != NULL);

	kmem_free(ioc->ii_srvcs, ioc->ii_profile.ioc_service_entries *
	    sizeof (ib_dm_srv_t));
	ioc->ii_srvcs = kmem_zalloc(profile->ioc_service_entries  *
	    sizeof (ib_dm_srv_t), KM_SLEEP);

	bcopy(profile, &ioc->ii_profile, sizeof (ib_dm_ioc_ctrl_profile_t));
	bcopy(services, ioc->ii_srvcs, sizeof (ib_dm_srv_t) *
	    profile->ioc_service_entries);
	/*
	 * Update the profile copy with the I/O controller slot assigned.
	 * The slot occupies the lower 8 biths of the vendor ID/slot 32bit
	 * field.
	 */
	profile->ioc_vendorid |= h2b32(ioc->ii_slot);
	ibdma_set_ioc_state(ioc->ii_hcap, ioc->ii_slot, IBDMA_IOC_PRESENT);
	rw_exit(&ioc->ii_hcap->ih_iou_rwlock);
	mutex_exit(&ibdma->ms_hca_list_lock);

	return (IBDMA_SUCCESS);
}
