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
 * This file defines interfaces between FCOE and LEADVILLE
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
#include <sys/scsi/scsi.h>
#include <sys/mac_client.h>
#include <sys/modhash.h>

/*
 * LEADVILLE header files
 */
#include <sys/fibre-channel/fc.h>
#include <sys/fibre-channel/impl/fc_fcaif.h>

/*
 * COMSTAR head files (BIT_* macro)
 */
#include <sys/stmf_defines.h>

/*
 * FCOE header files
 */
#include <sys/fcoe/fcoe_common.h>

/*
 * Driver's own header files
 */
#include <fcoei.h>

/*
 * forward declaration of static functions
 */
static void fcoei_port_enabled(void *arg);

static void fcoei_populate_hba_fru_details(fcoei_soft_state_t *ss,
    fc_fca_port_info_t *port_info);

static void fcoei_initiate_ct_req(fcoei_exchange_t *xch);
static void fcoei_initiate_fcp_cmd(fcoei_exchange_t *xch);
static void fcoei_initiate_els_req(fcoei_exchange_t *xch);
static void fcoei_initiate_els_resp(fcoei_exchange_t *xch);

static void fcoei_fill_els_logi_cmd(fc_packet_t *fpkt, fcoe_frame_t *frm);
static void fcoei_fill_els_prli_cmd(fc_packet_t *fpkt, fcoe_frame_t *frm);
static void fcoei_fill_els_logo_cmd(fc_packet_t *fpkt, fcoe_frame_t *frm);
static void fcoei_fill_els_scr_cmd(fc_packet_t *fpkt, fcoe_frame_t *frm);
static void fcoei_fill_els_adisc_cmd(fc_packet_t *fpkt, fcoe_frame_t *frm);
static void fcoei_fill_els_linit_cmd(fc_packet_t *fpkt, fcoe_frame_t *frm);
static void fcoei_fill_els_rls_cmd(fc_packet_t *fpkt, fcoe_frame_t *frm);
static void fcoei_fill_els_rnid_cmd(fc_packet_t *fpkt, fcoe_frame_t *frm);

static void fcoei_fill_els_acc_resp(fc_packet_t *fpkt, fcoe_frame_t *frm);
static void fcoei_fill_els_rjt_resp(fc_packet_t *fpkt, fcoe_frame_t *frm);
static void fcoei_fill_els_logi_resp(fc_packet_t *fpkt, fcoe_frame_t *frm);
static void fcoei_fill_els_prli_resp(fc_packet_t *fpkt, fcoe_frame_t *frm);
static void fcoei_fill_els_logo_resp(fc_packet_t *fpkt, fcoe_frame_t *frm);
static void fcoei_fill_els_adisc_resp(fc_packet_t *fpkt, fcoe_frame_t *frm);

static void fcoei_logo_peer(void *arg);
static void fcoei_fpkt_comp(fc_packet_t *fpkt);

static uint32_t
fcoei_xch_abort(mod_hash_key_t key, mod_hash_val_t *val, void *arg);


/*
 * fcoei_bind_port
 *	Bind LV port instance with fcoei soft state
 *
 * Input:
 *	dip = dev info of fcoei soft state
 *	port_info = fcoei specific parameters about LV port
 *	bind_info = LV specific parameters about fcoei soft state
 *
 * Returns:
 *	The pointer to fcoei soft state
 *
 * Comments:
 *	Unpon the completion of this call, the port must be offline.
 *	fcoei_port_enabled could trigger it to online
 */
static void *
fcoei_bind_port(dev_info_t *dip, fc_fca_port_info_t *port_info,
    fc_fca_bind_info_t *bind_info)
{
	fcoei_soft_state_t	*ss;

	/*
	 * get state info based on the dip
	 */
	ss = (fcoei_soft_state_t *)
	    ddi_get_soft_state(fcoei_state, ddi_get_instance(dip));
	if (!ss) {
		FCOEI_LOG(__FUNCTION__, "ss is NULL");
		return (NULL);
	}

	/*
	 * make sure this port isn't bound
	 */
	if (ss->ss_flags & SS_FLAG_LV_BOUND) {
		port_info->pi_error = FC_ALREADY;
		FCOEI_LOG(__FUNCTION__, "ss has been bound");
		return (NULL);
	}

	if (bind_info->port_num) {
		/*
		 * make sure request is in bounds
		 */
		port_info->pi_error = FC_OUTOFBOUNDS;
		FCOEI_LOG(__FUNCTION__, "port_num is not 0");
		return (NULL);
	}

	/*
	 * stash the ss_bind_info supplied by the FC Transport
	 */
	bcopy(bind_info, &ss->ss_bind_info, sizeof (fc_fca_bind_info_t));
	ss->ss_port = bind_info->port_handle;

	/*
	 * RNID parameter
	 */
	port_info->pi_rnid_params.status = FC_FAILURE;

	/*
	 * populate T11 FC-HBA details
	 */
	fcoei_populate_hba_fru_details(ss, port_info);

	/*
	 * set port's current state, and it is always offline before binding
	 *
	 * We hack pi_port_state to tell LV if it's NODMA_FCA
	 */
	port_info->pi_port_state = FC_STATE_FCA_IS_NODMA;

	/*
	 * copy login param
	 */
	bcopy(&ss->ss_els_logi, &port_info->pi_login_params,
	    sizeof (la_els_logi_t));

	/*
	 * Mark it as bound
	 */
	atomic_or_32(&ss->ss_flags, SS_FLAG_LV_BOUND);

	/*
	 * Let fcoe to report the link status
	 */
	fcoei_port_enabled((void *)ss);

	FCOEI_LOG(__FUNCTION__, "Exit fcoei_bind_port: %p", ss);
	return (ss);
}

/*
 * fcoei_unbind_port
 *	Un-bind the fcoei port
 *
 * Input:
 *	fca_handle = fcoei soft state set in fcoei_bind_port
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	Clear binding flag
 */
static void
fcoei_unbind_port(void *fca_handle)
{
	fcoei_soft_state_t *ss = (fcoei_soft_state_t *)fca_handle;

	atomic_and_32(&ss->ss_flags, ~SS_FLAG_LV_BOUND);
	ss->ss_eport->eport_ctl(ss->ss_eport, FCOE_CMD_PORT_OFFLINE, NULL);
	FCOEI_LOG(__FUNCTION__, "Exit fcoei_unbind_port: %p", ss);
}

/*
 * fcoei_init_pkt
 *	Initialize fcoei related part of fc_packet
 *
 * Input:
 *	fca_handle = fcoei soft state set in fcoei_bind_port
 *	fpkt = The pointer to fc_packet
 *	sleep = This call can sleep or not
 *
 * Returns:
 *	FC_SUCCESS - Initialization completed successfully
 *
 * Comments:
 *	Link the exchange elements with proper objects
 */
/* ARGSUSED */
static int
fcoei_init_pkt(void *fca_handle, fc_packet_t *fpkt, int sleep)
{
	fcoei_soft_state_t	*ss  = (fcoei_soft_state_t *)fca_handle;
	fcoei_exchange_t	*xch = FPKT2XCH(fpkt);

	ASSERT(sleep + 1);
	xch->xch_ss = ss;
	xch->xch_fpkt = fpkt;
	xch->xch_flags = 0;
	return (FC_SUCCESS);
}

/*
 * fcoei_un_init_pkt
 *	Uninitialize fcoei related part of fc_packet
 *
 * Input:
 *	fca_handle = fcoei soft state set in fcoei_bind_port
 *	fpkt = The pointer to fc_packet
 *
 * Returns:
 *	FC_SUCCESS - Uninitialize successfully
 *
 * Comments:
 *	Very simple, just return successfully
 */
/* ARGSUSED */
static int
fcoei_un_init_pkt(void *fca_handle, fc_packet_t *fpkt)
{
	ASSERT(fca_handle && fpkt);
	return (FC_SUCCESS);
}

/*
 * fcoei_get_cap
 *	Export FCA hardware and software capability.
 *
 * Input:
 *	fca_handle = fcoei soft state set in fcoei_bind_port
 *	cap = pointer to the capability string
 *	ptr = buffer pointer for returning capability
 *
 * Returns:
 *	FC_CAP_ERROR - no such capability
 *	FC_CAP_FOUND - the capability was returned and cannot be set
 *
 * Comments:
 *	FC_CAP_UNSOL_BUF is one important capability, it will affect the
 *	implementation of fcoei_ub_alloc/free.
 */
static int
fcoei_get_cap(void * fca_handle, char *cap, void *ptr)
{
	fcoei_soft_state_t	*ss   = (fcoei_soft_state_t *)fca_handle;
	uint32_t		*rptr = (uint32_t *)ptr;
	int			 rval = FC_CAP_FOUND;

	ASSERT(fca_handle);
	FCOEI_LOG(__FUNCTION__, "cap: %s", cap);
	if (strcmp(cap, FC_NODE_WWN) == 0) {
		bcopy(&ss->ss_els_logi.node_ww_name.raw_wwn[0], ptr, 8);
	} else if (strcmp(cap, FC_LOGIN_PARAMS) == 0) {
		bcopy((void *)&ss->ss_els_logi, ptr, sizeof (la_els_logi_t));
	} else if (strcmp(cap, FC_CAP_UNSOL_BUF) == 0) {
		*rptr = (uint32_t)0;
	} else if (strcmp(cap, FC_CAP_NOSTREAM_ON_UNALIGN_BUF) == 0) {
		*rptr = (uint32_t)FC_ALLOW_STREAMING;
	} else if (strcmp(cap, FC_CAP_PAYLOAD_SIZE) == 0) {
		*rptr = (uint32_t)2136;
	} else if (strcmp(cap, FC_CAP_POST_RESET_BEHAVIOR) == 0) {
		*rptr = FC_RESET_RETURN_ALL;
	} else if (strcmp(cap, FC_CAP_FCP_DMA) == 0) {
		*rptr = FC_NO_DVMA_SPACE;
	} else {
		rval = FC_CAP_ERROR;
		FCOEI_LOG(__FUNCTION__, "not supported");
	}

	return (rval);
}

/*
 * fcoei_set_cap
 *	Allow the FC Transport to set FCA capabilities if possible
 *
 * Input:
 *	fca_handle = fcoei soft state set in fcoei_bind_port
 *	cap = pointer to the capabilities string.
 *	ptr = buffer pointer for capability.
 *
 * Returns:
 *	FC_CAP_ERROR - no such capability
 *
 * Comments:
 *	Currently, all capabilities can't be changed.
 */
static int
fcoei_set_cap(void * fca_handle, char *cap, void *ptr)
{
	FCOEI_LOG(__FUNCTION__, "cap: %s, %p, %p", cap, fca_handle, ptr);
	return (FC_CAP_ERROR);
}

/*
 * fcoei_getmap
 *	Get lilp map
 *
 * Input:
 *	fca_handle = fcoei soft state set in fcoei_bind_port
 *	mapbuf = the buffer to store lilp map
 *
 * Returns:
 *	FC_FAILURE - Can't get the lilp map
 *
 * Comments:
 *	fcoei can't work in loop topology, so it should never get called
 */
static int
fcoei_getmap(void * fca_handle, fc_lilpmap_t *mapbuf)
{
	FCOEI_LOG(__FUNCTION__, "not: %p-%p", fca_handle, mapbuf);
	return (FC_FAILURE);
}

/*
 * fcoei_ub_alloc
 *	Pre-allocate unsolicited buffers at the request of LV
 *
 * Input:
 *	fca_handle = fcoei soft state set in fcoei_bind_port
 *	tokens = token array for each buffer.
 *	size = number of tokens
 *	count = the acutual number of allocated unsolicited buffers
 *	type = unsolicited buffer type
 *
 * Returns:
 *	FC_SUCCESS - The requested buffers have been freeed
 *
 * Comments:
 *	fcoei_get_cap will set UNSOL_BUF to 0, so it should never get called.
 */
static int
fcoei_ub_alloc(void * fca_handle, uint64_t tokens[], uint32_t size,
    uint32_t *count, uint32_t type)
{
	FCOEI_LOG(__FUNCTION__, "not: %p-%p-%x-%p-%x", fca_handle, tokens,
	    size, count, type);
	return (FC_SUCCESS);
}

/*
 * fcoei_ub_free
 *	Free the pre-allocated unsolicited buffers at the request of LV
 *
 * Input:
 *	fca_handle = fcoei soft state set in fcoei_bind_port
 *	count = number of buffers.
 *	tokens = token array for each buffer.
 *
 * Returns:
 *	FC_SUCCESS - The requested buffers have been freeed
 *
 * Comments:
 *	fcoei_get_cap will set UNSOL_BUF to 0, so it should never get called.
 */
static int
fcoei_ub_free(void * fca_handle, uint32_t count, uint64_t tokens[])
{
	FCOEI_EXT_LOG(__FUNCTION__, "not: %p-%x-%p", fca_handle, count, tokens);
	return (FC_SUCCESS);
}

/*
 * fcoei_ub_release
 *	Release unsolicited buffers from FC Transport to FCA for future use
 *
 * Input:
 *	fca_handle = fcoei soft state set in fcoei_bind_port
 *	count = number of buffers.
 *	tokens = token array for each buffer.
 *
 * Returns:
 *	FC_SUCCESS - The requested buffers have been released.
 *	FC_FAILURE - The requested buffers have not been released.
 *
 * Comments:
 *	It will always succeed. It has nothing to do with fcoei_ub_alloc/free.
 */
static int
fcoei_ub_release(void * fca_handle, uint32_t count, uint64_t tokens[])
{
	fc_unsol_buf_t *ub = *((fc_unsol_buf_t **)tokens);

	if (count != 1) {
		FCOEI_LOG(__FUNCTION__, "count is not 1: %p", fca_handle);
		return (FC_FAILURE);
	}

	kmem_free(ub->ub_buffer, ub->ub_bufsize);
	kmem_free(ub, sizeof (fc_unsol_buf_t));
	FCOEI_EXT_LOG(__FUNCTION__, "ub is freeed");
	return (FC_SUCCESS);
}

/*
 * fcoei_abort
 *	Direct FCA driver to abort an outstanding exchange associated with a
 *	specified fc_packet_t struct
 *
 * Input:
 *	fca_handle - fcoei soft state set in fcoei_bind_port
 *	fpkt - A pointer to the fc_packet_t for the exchange to be aborted.
 *	flags - Set to KM_SLEEP if the function may sleep, or KM_NOSLEEP if
 *		the function may not sleep.
 *
 * Returns:
 *	FC_ABORTED - The specified exchange was successfully aborted.
 *	FC_ABORTING - The specified exchange is being aborted.
 *	FC_ABORT_FAILED - The specified exchange could not be aborted.
 *	FC_TRANSPORT_ERROR - A transport error occurred while attempting to
 *		abort the specified exchange.
 *	FC_BADEXCHANGE - The specified exchange does not exist.
 *
 * Comments:
 *	After the exchange is aborted, the FCA driver must update the relevant
 *	fields in the fc_packet_t struct as per normal exchange completion and
 *	call the pkt_comp function to return the fc_packet_t struct to the FC
 *	Transport.
 *	When an exchange is successfully aborted, the FCA driver must set the
 *	pkt_reason field in the fc_packet_t to FC_REASON_ABORTED and the
 *	pkt_state field in the fc_packet_t to FC_PKT_LOCAL_RJT before returning
 *	the fc_packet_t to the FC Transport.
 *
 *	Unfortunately, LV doesn't conform to the spec. It will take all these
 *	legal return value as failure to abort.
 */
static int
fcoei_abort(void * fca_handle, fc_packet_t *fpkt, int flags)
{
	FCOEI_LOG(__FUNCTION__, "not: %p-%p-%x", fca_handle, fpkt, flags);
	return (FC_SUCCESS);
}

/*
 * fcoei_reset
 *	Reset link or hardware
 *
 * Input:
 *	fca_handle = fcoei soft state set in fcoei_bind_port
 *	cmd = reset type command
 *
 * Returns:
 *	FC_SUCCESS - Reset has completed successfully
 *	FC_FAILURE - Reset has failed
 *
 * Comments:
 *	N/A
 */
static int
fcoei_reset(void * fca_handle, uint32_t cmd)
{
	int			 rval = FC_SUCCESS;
	fcoei_soft_state_t	*ss   = (fcoei_soft_state_t *)fca_handle;
	fcoei_event_t *ae;

	switch (cmd) {
	case FC_FCA_LINK_RESET:
		if (ss->ss_link_state != FC_STATE_ONLINE) {
			FCOEI_LOG(__FUNCTION__, "not online now: ss-%p", ss);
			rval = FC_FAILURE;
			break;
		}

		/*
		 * This is linkreset phase I
		 */
		fcoei_logo_peer(ss);
		delay(FCOE_SEC2TICK(1) / 10);
		ss->ss_eport->eport_ctl(ss->ss_eport, FCOE_CMD_PORT_OFFLINE, 0);
		fcoei_port_event(ss->ss_eport, FCOE_NOTIFY_EPORT_LINK_DOWN);

		/*
		 * Perpare linkreset phase II
		 */
		ae = kmem_zalloc(sizeof (*ae), KM_SLEEP);
		ae->ae_type = AE_EVENT_RESET;
		ae->ae_obj = ss;

		mutex_enter(&ss->ss_watchdog_mutex);
		list_insert_tail(&ss->ss_event_list, ae);
		mutex_exit(&ss->ss_watchdog_mutex);
		break;

	case FC_FCA_RESET:
		break;

	case FC_FCA_CORE:
		break;

	case FC_FCA_RESET_CORE:
		break;

	default:
		rval = FC_FAILURE;
		FCOEI_LOG(__FUNCTION__, "cmd-%x not supported", cmd);
		break;
	}

	return (rval);
}

/*
 * fcoei_port_manage
 *	Perform various port management operations at the request of LV
 *
 * Input:
 *	fca_handle = fcoei soft state set in fcoei_bind_port
 *	pm = the pointer to the struct specifying the port management operation
 *
 * Returns:
 *	FC_SUCCESS - The request completed successfully
 *	FC_FAILURE - The request did not complete successfully
 *
 * Comments:
 *	N/A
 */
static int
fcoei_port_manage(void * fca_handle, fc_fca_pm_t *pm)
{
	int	rval = FC_FAILURE;
	fcoei_soft_state_t	*ss = (fcoei_soft_state_t *)fca_handle;

	if (fca_handle == NULL || pm == NULL) {
		return (rval);
	}

	FCOEI_LOG(__FUNCTION__, "code0x%x, %p", pm->pm_cmd_code, fca_handle);
	switch (pm->pm_cmd_code) {

	case FC_PORT_GET_NODE_ID:
	{
		if (pm->pm_data_len < sizeof (fc_rnid_t)) {
			rval = FC_NOMEM;
			break;
		}
		ss->ss_rnid.port_id = ss->ss_p2p_info.fca_d_id;
		bcopy((void *)&ss->ss_rnid,
		    pm->pm_data_buf, sizeof (fc_rnid_t));
		rval = FC_SUCCESS;
		break;
	}

	case FC_PORT_SET_NODE_ID:
	{
		if (pm->pm_data_len < sizeof (fc_rnid_t)) {
			rval = FC_NOMEM;
			break;
		}
		bcopy(pm->pm_data_buf,
		    (void *)&ss->ss_rnid, sizeof (fc_rnid_t));
		rval = FC_SUCCESS;
		break;
	}

	default:
		FCOEI_LOG(__FUNCTION__, "unsupported cmd-%x", pm->pm_cmd_code);
		rval = FC_INVALID_REQUEST;
		break;
	}

	return (rval);
}

/*
 * fcoei_get_device
 *	Get fcoei remote port with FCID of d_id
 *
 * Input:
 *	fca_handle = fcoei soft state set in fcoei_bind_port
 *	d_id = 24-bit FCID of remote port
 *
 * Returns:
 *	The pointer to fcoei remote port
 *
 * Comments:
 *	fcoei has no remote port device
 */
static void *
fcoei_get_device(void *fca_handle, fc_portid_t d_id)
{
	FCOEI_EXT_LOG(__FUNCTION__, "not supported: %p-%x", fca_handle, d_id);
	return (NULL);
}

/*
 * fcoei_notify
 *	Notify the change of target device
 *
 * Input:
 *	fca_handle = fcoei soft state set in fcoei_bind_port
 *	cmd = detailed cmd
 *
 * Returns:
 *	FC_SUCCESS - Notification completed successfully
 *
 * Comments:
 *	It's only needed to support non-COMSTAR FC target, so it should
 *	never get called.
 */
static int
fcoei_notify(void *fca_handle, uint32_t cmd)
{
	FCOEI_LOG(__FUNCTION__, "not supported: %p-%x", fca_handle, cmd);
	return (FC_SUCCESS);
}

/*
 * fcoei_transport
 *	Submit FCP/CT requests
 *
 * Input:
 *	fca_handle - fcoei soft state set in fcoei_bind_port
 *	fpkt - LV fc_packet
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static int
fcoei_transport(void *fca_handle, fc_packet_t *fpkt)
{
	fcoei_soft_state_t	*ss  = (fcoei_soft_state_t *)fca_handle;
	fcoei_exchange_t	*xch = FPKT2XCH(fpkt);
	uint16_t		 pkt_tran_flags = fpkt->pkt_tran_flags;

	xch->xch_start_tick = ddi_get_lbolt();
	xch->xch_end_tick = xch->xch_start_tick +
	    FCOE_SEC2TICK(fpkt->pkt_timeout);
	xch->xch_ae.ae_type = AE_EVENT_EXCHANGE;
	xch->xch_ae.ae_obj = xch;

	if (pkt_tran_flags & FC_TRAN_NO_INTR) {
		FCOEI_LOG(__FUNCTION__, "AaA polling: %p-%p", fpkt, xch);
		sema_init(&xch->xch_sema, 0, NULL, SEMA_DRIVER, NULL);
	}

	mutex_enter(&ss->ss_watchdog_mutex);
	list_insert_tail(&ss->ss_event_list, &xch->xch_ae);
	if (ss->ss_flags & SS_FLAG_WATCHDOG_IDLE) {
		cv_signal(&ss->ss_watchdog_cv);
	}
	mutex_exit(&ss->ss_watchdog_mutex);

	if (pkt_tran_flags & FC_TRAN_NO_INTR) {
		FCOEI_LOG(__FUNCTION__, "BaB polling: %p-%p", fpkt, xch);
		sema_p(&xch->xch_sema);
		sema_destroy(&xch->xch_sema);
		FCOEI_LOG(__FUNCTION__, "after polling: %p-%p", fpkt, xch);
	}

	return (FC_SUCCESS);
}

/*
 * fcoei_els_send
 *	Submit ELS request or response
 *
 * Input:
 *	fca_handle - fcoei soft state set in fcoei_bind_port
 *	fpkt = LV fc_packet
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static int
fcoei_els_send(void *fca_handle, fc_packet_t *fpkt)
{
	fcoei_soft_state_t	*ss  = (fcoei_soft_state_t *)fca_handle;
	fcoei_exchange_t	*xch = FPKT2XCH(fpkt);

	if (fpkt->pkt_tran_flags & FC_TRAN_NO_INTR) {
		FCOEI_LOG(__FUNCTION__, "ELS poll mode is not supported");
		return (FC_BADPACKET);
	}

	xch->xch_start_tick = ddi_get_lbolt();
	xch->xch_end_tick = xch->xch_start_tick +
	    FCOE_SEC2TICK(fpkt->pkt_timeout);
	xch->xch_ae.ae_type = AE_EVENT_EXCHANGE;
	xch->xch_ae.ae_obj = xch;

	/*
	 * LV could release ub after this call, so we must save the ub type
	 * for later use
	 */
	if (fpkt->pkt_cmd_fhdr.r_ctl == R_CTL_ELS_RSP) {
		((uint8_t *)&fpkt->pkt_fca_rsvd1)[0] =
		    ((fc_unsol_buf_t *)fpkt->pkt_ub_resp_token)->ub_buffer[0];
	}

	mutex_enter(&ss->ss_watchdog_mutex);
	list_insert_tail(&ss->ss_event_list, &xch->xch_ae);
	if (ss->ss_flags & SS_FLAG_WATCHDOG_IDLE) {
		cv_signal(&ss->ss_watchdog_cv);
	}
	mutex_exit(&ss->ss_watchdog_mutex);

	return (FC_SUCCESS);
}

/*
 * fcoei_populate_hba_fru_details
 *	Fill detailed information about HBA
 *
 * Input:
 *	ss - fcoei soft state
 *	port_info = fc_fca_port_info_t that need be updated
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_populate_hba_fru_details(fcoei_soft_state_t *ss,
    fc_fca_port_info_t *port_info)
{
	fca_port_attrs_t *port_attrs = &(port_info->pi_attrs);
	int	instance;

	ASSERT(ss != NULL);
	(void) snprintf(port_attrs->manufacturer, FCHBA_MANUFACTURER_LEN,
	    "Sun Microsystems, Inc.");
	(void) snprintf(port_attrs->driver_name, FCHBA_DRIVER_NAME_LEN,
	    "%s", FCOEI_NAME_VERSION);
	(void) snprintf(port_attrs->driver_version, FCHBA_DRIVER_VERSION_LEN,
	    "%s", FCOEI_VERSION);
	(void) strcpy(port_attrs->serial_number, "N/A");
	(void) strcpy(port_attrs->hardware_version, "N/A");
	(void) strcpy(port_attrs->model, "FCoE Virtual FC HBA");
	(void) strcpy(port_attrs->model_description, "N/A");
	(void) strcpy(port_attrs->firmware_version, "N/A");
	(void) strcpy(port_attrs->option_rom_version, "N/A");

	port_attrs->vendor_specific_id = 0xFC0E;
	port_attrs->max_frame_size = FCOE_MAX_FC_FRAME_SIZE;
	port_attrs->supported_cos = 0x10000000;
	port_attrs->supported_speed = FC_HBA_PORTSPEED_1GBIT |
	    FC_HBA_PORTSPEED_10GBIT;
	instance = ddi_get_instance(ss->ss_dip);
	port_attrs->hba_fru_details.high =
	    (short)((instance & 0xffff0000) >> 16);
	port_attrs->hba_fru_details.low =
	    (short)(instance & 0x0000ffff);
}

/*
 * fcoei_port_enabled
 *	Notify fcoe that the port has been enabled
 *
 * Input:
 *	arg = the related soft state
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	Only after this, fcoe will report the link status to us
 */
static void
fcoei_port_enabled(void *arg)
{
	fcoei_soft_state_t	*ss  = (fcoei_soft_state_t *)arg;

	ss->ss_eport->eport_ctl(ss->ss_eport, FCOE_CMD_PORT_ONLINE, NULL);
}


/*
 * fcoei_initiate_ct_req
 *	Fill and submit CT request
 *
 * Input:
 *	xch - the exchange that will be initiated
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_initiate_ct_req(fcoei_exchange_t *xch)
{
	fc_packet_t	*fpkt	 = xch->xch_fpkt;
	fc_ct_header_t	*ct	 = (fc_ct_header_t *)(void *)fpkt->pkt_cmd;
	uint8_t		*bp	 = (uint8_t *)fpkt->pkt_cmd;
	fcoe_frame_t	*frm;
	int		 offset;
	int		 idx;
	uint32_t	 cmd_len = fpkt->pkt_cmdlen;

	/*
	 * Ensure it's 4-byte aligned
	 */
	cmd_len = P2ROUNDUP(cmd_len, 4);

	/*
	 * Allocate CT request frame
	 */
	frm = xch->xch_ss->ss_eport->eport_alloc_frame(xch->xch_ss->ss_eport,
	    cmd_len + FCFH_SIZE, NULL);
	if (frm == NULL) {
		FCOEI_LOG(__FUNCTION__, "failed to alloc: %p", xch);
		return;
	}

	bzero(frm->frm_payload, cmd_len);
	xch->xch_cnt = xch->xch_ss->ss_sol_cnt;
	atomic_inc_32(xch->xch_cnt);

	FFM_R_CTL(fpkt->pkt_cmd_fhdr.r_ctl, frm);
	FFM_D_ID(fpkt->pkt_cmd_fhdr.d_id, frm);
	FFM_S_ID(fpkt->pkt_cmd_fhdr.s_id, frm);
	FFM_TYPE(fpkt->pkt_cmd_fhdr.type, frm);
	FFM_F_CTL(fpkt->pkt_cmd_fhdr.f_ctl, frm);
	FFM_OXID(xch->xch_oxid, frm);
	FFM_RXID(xch->xch_rxid, frm);
	fcoei_init_ifm(frm, xch);

	/*
	 * CT header (FC payload)
	 */
	offset = 0;
	FCOE_V2B_1(ct->ct_rev, FPLD + offset);

	offset = 1;
	FCOE_V2B_3(ct->ct_inid, FPLD + offset);

	offset = 4;
	FCOE_V2B_1(ct->ct_fcstype, FPLD + offset);

	offset = 5;
	FCOE_V2B_1(ct->ct_fcssubtype, FPLD + offset);

	offset = 6;
	FCOE_V2B_1(ct->ct_options, FPLD + offset);

	offset = 8;
	FCOE_V2B_2(ct->ct_cmdrsp, FPLD + offset);

	offset = 10;
	FCOE_V2B_2(ct->ct_aiusize, FPLD + offset);

	offset = 13;
	FCOE_V2B_1(ct->ct_reason, FPLD + offset);

	offset = 14;
	FCOE_V2B_1(ct->ct_expln, FPLD + offset);

	offset = 15;
	FCOE_V2B_1(ct->ct_vendor, FPLD + offset);

	/*
	 * CT payload (FC payload)
	 */
	switch (ct->ct_fcstype) {
	case FCSTYPE_DIRECTORY:
		switch (ct->ct_cmdrsp) {
		case NS_GA_NXT:
		case NS_GPN_ID:
		case NS_GNN_ID:
		case NS_GCS_ID:
		case NS_GFT_ID:
		case NS_GSPN_ID:
		case NS_GPT_ID:
		case NS_GID_FT:
		case NS_GID_PT:
		case NS_DA_ID:
			offset = 16;
			FCOE_V2B_4(((uint32_t *)(intptr_t)(bp + offset))[0],
			    FPLD + offset);
			break;

		case NS_GID_PN:
			offset = 16;
			bcopy(bp + offset, FPLD + offset, 8);
			break;

		case NS_RNN_ID:
		case NS_RPN_ID:
			offset = 16;
			FCOE_V2B_4(((uint32_t *)(intptr_t)(bp + offset))[0],
			    FPLD + offset);

			offset = 20;
			bcopy(bp + offset, FPLD + offset, 8);
			break;

		case NS_RSPN_ID:
			offset = 16;
			FCOE_V2B_4(((uint32_t *)(intptr_t)(bp + offset))[0],
			    FPLD + offset);

			offset = 20;
			bcopy(bp + offset, FPLD + offset, bp[20] + 1);
			break;

		case NS_RSNN_NN:
			offset = 16;
			bcopy(bp + offset, FPLD + offset, 8);

			offset = 24;
			bcopy(bp + offset, FPLD + offset, bp[24] + 1);
			break;

		case NS_RFT_ID:
			offset = 16;
			FCOE_V2B_4(((uint32_t *)(intptr_t)(bp + offset))[0],
			    FPLD + offset);

			/*
			 * fp use bcopy to copy fp_fc4_types,
			 * we need to swap order for each integer
			 */
			offset = 20;
			for (idx = 0; idx < 8; idx++) {
				FCOE_V2B_4(
				    ((uint32_t *)(intptr_t)(bp + offset))[0],
				    FPLD + offset);
				offset += 4;
			}
			break;

		case NS_RCS_ID:
		case NS_RPT_ID:
			offset = 16;
			FCOE_V2B_4(((uint32_t *)(intptr_t)(bp + offset))[0],
			    FPLD + offset);

			offset = 20;
			FCOE_V2B_4(((uint32_t *)(intptr_t)(bp + offset))[0],
			    FPLD + offset);
			break;

		case NS_RIP_NN:
			offset = 16;
			bcopy(bp + offset, FPLD + offset, 24);
			break;

		default:
			fcoei_complete_xch(xch, frm, FC_PKT_FAILURE,
			    FC_REASON_CMD_UNSUPPORTED);
			break;
		}
		break; /* FCSTYPE_DIRECTORY */

	case FCSTYPE_MGMTSERVICE:
		switch (ct->ct_cmdrsp) {
		case MS_GIEL:
			FCOEI_LOG(__FUNCTION__,
			    "MS_GIEL ct_fcstype %x, ct_cmdrsp: %x",
			    ct->ct_fcstype, ct->ct_cmdrsp);
			break;

		default:
			fcoei_complete_xch(xch, frm, FC_PKT_FAILURE,
			    FC_REASON_CMD_UNSUPPORTED);
			break;
		}
		break; /* FCSTYPE_MGMTSERVICE */

	default:
		fcoei_complete_xch(xch, frm, FC_PKT_FAILURE,
		    FC_REASON_CMD_UNSUPPORTED);
		break;
	}
	xch->xch_ss->ss_eport->eport_tx_frame(frm);
}

/*
 * fcoei_initiate_fcp_cmd
 *	Submit FCP command
 *
 * Input:
 *	xch - the exchange to be submitted
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_initiate_fcp_cmd(fcoei_exchange_t *xch)
{
	fc_packet_t	*fpkt = xch->xch_fpkt;
	fcoe_frame_t	*frm;
	fcp_cmd_t	*fcp_cmd_iu = (fcp_cmd_t *)(void *)fpkt->pkt_cmd;
	int		 offset = 0;

	ASSERT((fpkt->pkt_cmdlen % 4) == 0);
	frm = xch->xch_ss->ss_eport->eport_alloc_frame(xch->xch_ss->ss_eport,
	    fpkt->pkt_cmdlen + FCFH_SIZE, NULL);
	if (!frm) {
		ASSERT(0);
	} else {
		fcoei_init_ifm(frm, xch);
		bzero(frm->frm_payload, fpkt->pkt_cmdlen);
	}

	/*
	 * This will affect timing check
	 */
	xch->xch_cnt = xch->xch_ss->ss_sol_cnt;
	atomic_inc_32(xch->xch_cnt);

	/*
	 * Set exchange residual bytes
	 */
	xch->xch_resid = (int)fpkt->pkt_datalen;

	/*
	 * Fill FCP command IU
	 *
	 * fcp_ent_addr
	 */
	FCOE_V2B_2(fcp_cmd_iu->fcp_ent_addr.ent_addr_0,
	    frm->frm_payload + offset);
	offset += 2;
	FCOE_V2B_2(fcp_cmd_iu->fcp_ent_addr.ent_addr_1,
	    frm->frm_payload + offset);
	offset += 2;
	FCOE_V2B_2(fcp_cmd_iu->fcp_ent_addr.ent_addr_2,
	    frm->frm_payload + offset);
	offset += 2;
	FCOE_V2B_2(fcp_cmd_iu->fcp_ent_addr.ent_addr_3,
	    frm->frm_payload + offset);
	/*
	 * fcp_cntl
	 */
	offset = offsetof(fcp_cmd_t, fcp_cntl);
	frm->frm_payload[offset] = 0;

	offset += 1;
	frm->frm_payload[offset] = fcp_cmd_iu->fcp_cntl.cntl_qtype & 0x07;
	offset += 1;
	frm->frm_payload[offset] =
	    (fcp_cmd_iu->fcp_cntl.cntl_kill_tsk << 7) |
	    (fcp_cmd_iu->fcp_cntl.cntl_clr_aca << 6) |
	    (fcp_cmd_iu->fcp_cntl.cntl_reset_tgt << 5) |
	    (fcp_cmd_iu->fcp_cntl.cntl_reset_lun << 4) |
	    (fcp_cmd_iu->fcp_cntl.cntl_clr_tsk << 2) |
	    (fcp_cmd_iu->fcp_cntl.cntl_abort_tsk << 1);
	offset += 1;
	frm->frm_payload[offset] =
	    (fcp_cmd_iu->fcp_cntl.cntl_read_data << 1) |
	    (fcp_cmd_iu->fcp_cntl.cntl_write_data);
	/*
	 * fcp_cdb
	 */
	offset = offsetof(fcp_cmd_t, fcp_cdb);
	bcopy(fcp_cmd_iu->fcp_cdb, frm->frm_payload + offset, FCP_CDB_SIZE);
	/*
	 * fcp_data_len
	 */
	offset += FCP_CDB_SIZE;
	FCOE_V2B_4(fcp_cmd_iu->fcp_data_len, frm->frm_payload + offset);

	/*
	 * FC frame header
	 */
	FRM2IFM(frm)->ifm_rctl = fpkt->pkt_cmd_fhdr.r_ctl;

	FFM_R_CTL(fpkt->pkt_cmd_fhdr.r_ctl, frm);
	FFM_D_ID(fpkt->pkt_cmd_fhdr.d_id, frm);
	FFM_S_ID(fpkt->pkt_cmd_fhdr.s_id, frm);
	FFM_TYPE(fpkt->pkt_cmd_fhdr.type, frm);
	FFM_F_CTL(0x290000, frm);
	FFM_OXID(xch->xch_oxid, frm);
	FFM_RXID(xch->xch_rxid, frm);

	xch->xch_ss->ss_eport->eport_tx_frame(frm);
}

/*
 * fcoei_initiate_els_req
 *	Initiate ELS request
 *
 * Input:
 *	xch = the exchange that will be initiated
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_initiate_els_req(fcoei_exchange_t *xch)
{
	fc_packet_t	*fpkt = xch->xch_fpkt;
	fcoe_frame_t	*frm;
	ls_code_t	*els_code;

	ASSERT((fpkt->pkt_cmdlen % 4) == 0);
	frm = xch->xch_ss->ss_eport->eport_alloc_frame(xch->xch_ss->ss_eport,
	    fpkt->pkt_cmdlen + FCFH_SIZE, NULL);
	if (!frm) {
		ASSERT(0);
	} else {
		fcoei_init_ifm(frm, xch);
		bzero(frm->frm_payload, fpkt->pkt_cmdlen);
	}

	/*
	 * This will affect timing check
	 */
	xch->xch_cnt = xch->xch_ss->ss_sol_cnt;
	atomic_inc_32(xch->xch_cnt);

	els_code = (ls_code_t *)(void *)fpkt->pkt_cmd;
	switch (els_code->ls_code) {
	case LA_ELS_FLOGI:
		/*
		 * For FLOGI, we expect response within E_D_TOV
		 */
		xch->xch_start_tick = ddi_get_lbolt();
		xch->xch_end_tick = xch->xch_start_tick +
		    FCOE_SEC2TICK(2);
		xch->xch_ss->ss_flags &= ~SS_FLAG_FLOGI_FAILED;
		/* FALLTHROUGH */

	case LA_ELS_PLOGI:
		fcoei_fill_els_logi_cmd(fpkt, frm);
		break;

	case LA_ELS_PRLI:
		fcoei_fill_els_prli_cmd(fpkt, frm);
		break;

	case LA_ELS_SCR:
		fcoei_fill_els_scr_cmd(fpkt, frm);
		break;

	case LA_ELS_LINIT:
		fcoei_fill_els_linit_cmd(fpkt, frm);
		break;

	case LA_ELS_ADISC:
		fcoei_fill_els_adisc_cmd(fpkt, frm);
		break;

	case LA_ELS_LOGO:
		/*
		 * For LOGO, we expect response within E_D_TOV
		 */
		xch->xch_start_tick = ddi_get_lbolt();
		xch->xch_end_tick = xch->xch_start_tick +
		    FCOE_SEC2TICK(2);
		fcoei_fill_els_logo_cmd(fpkt, frm);
		break;
	case LA_ELS_RLS:
		fcoei_fill_els_rls_cmd(fpkt, frm);
		break;
	case LA_ELS_RNID:
		fcoei_fill_els_rnid_cmd(fpkt, frm);
		break;
	default:
		fcoei_complete_xch(xch, frm, FC_PKT_FAILURE,
		    FC_REASON_CMD_UNSUPPORTED);
		return;
	}

	/*
	 * set ifm_rtcl
	 */
	FRM2IFM(frm)->ifm_rctl = fpkt->pkt_cmd_fhdr.r_ctl;

	/*
	 * FCPH
	 */
	FFM_R_CTL(fpkt->pkt_cmd_fhdr.r_ctl, frm);
	FFM_D_ID(fpkt->pkt_cmd_fhdr.d_id, frm);
	FFM_S_ID(fpkt->pkt_cmd_fhdr.s_id, frm);
	FFM_TYPE(fpkt->pkt_cmd_fhdr.type, frm);
	FFM_F_CTL(0x290000, frm);
	FFM_OXID(xch->xch_oxid, frm);
	FFM_RXID(xch->xch_rxid, frm);

	xch->xch_ss->ss_eport->eport_tx_frame(frm);
}

/*
 * fcoei_initiate_els_resp
 *	Originate ELS response
 *
 * Input:
 *	xch = the associated exchange
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_initiate_els_resp(fcoei_exchange_t *xch)
{
	fc_packet_t	*fpkt = xch->xch_fpkt;
	fcoe_frame_t	*frm;

	ASSERT((fpkt->pkt_cmdlen % 4) == 0);
	frm = xch->xch_ss->ss_eport->eport_alloc_frame(xch->xch_ss->ss_eport,
	    fpkt->pkt_cmdlen + FCFH_SIZE, NULL);
	if (!frm) {
		ASSERT(0);
	} else {
		fcoei_init_ifm(frm, xch);
		bzero(frm->frm_payload, fpkt->pkt_cmdlen);
	}

	/*
	 * This will affect timing check
	 */
	xch->xch_cnt = xch->xch_ss->ss_unsol_cnt;
	atomic_inc_32(xch->xch_cnt);

	/*
	 * Set ifm_rctl
	 */
	FRM2IFM(frm)->ifm_rctl = fpkt->pkt_cmd_fhdr.r_ctl;

	/*
	 * FCPH
	 */
	FFM_R_CTL(fpkt->pkt_cmd_fhdr.r_ctl, frm);
	FFM_D_ID(fpkt->pkt_cmd_fhdr.d_id, frm);
	FFM_S_ID(fpkt->pkt_cmd_fhdr.s_id, frm);
	FFM_TYPE(fpkt->pkt_cmd_fhdr.type, frm);
	FFM_F_CTL(0x980000, frm);
	FFM_OXID(xch->xch_oxid, frm);
	FFM_RXID(xch->xch_rxid, frm);

	switch (((uint8_t *)&fpkt->pkt_fca_rsvd1)[0]) {
	case LA_ELS_FLOGI:
		fcoei_fill_els_logi_resp(fpkt, frm);
		break;

	case LA_ELS_PLOGI:
		if (FRM2SS(frm)->ss_eport->eport_flags &
		    EPORT_FLAG_IS_DIRECT_P2P) {
			FRM2SS(frm)->ss_p2p_info.fca_d_id = FRM_S_ID(frm);
			FRM2SS(frm)->ss_p2p_info.d_id = FRM_D_ID(frm);
		}

		fcoei_fill_els_logi_resp(fpkt, frm);
		break;

	case LA_ELS_PRLI:
		fcoei_fill_els_prli_resp(fpkt, frm);
		break;

	case LA_ELS_ADISC:
		fcoei_fill_els_adisc_resp(fpkt, frm);
		break;

	case LA_ELS_LOGO:
		fcoei_fill_els_logo_resp(fpkt, frm);
		break;
	case LA_ELS_RSCN:
		fcoei_fill_els_acc_resp(fpkt, frm);
		break;

	default:
		fcoei_complete_xch(xch, frm, FC_PKT_FAILURE,
		    FC_REASON_CMD_UNSUPPORTED);
		return;
	}

	xch->xch_ss->ss_eport->eport_tx_frame(frm);
}

/*
 * fcoei_fill_els_logi_cmd
 *	Fill SCR (state change register) command frame
 *
 * Input:
 *	fpkt = LV fc_packet
 *	frm = Unsolicited frame containing LOGI response
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_fill_els_logi_cmd(fc_packet_t *fpkt, fcoe_frame_t *frm)
{
	la_els_logi_t	*els_logi = (la_els_logi_t *)(void *)fpkt->pkt_cmd;
	int		 offset;

	/*
	 * fill ls_code
	 */
	offset = 0;
	FCOE_V2B_1(els_logi->ls_code.ls_code, FPLD + offset);

	/*
	 * fill common service parameters
	 */
	offset = 4;
	FCOE_V2B_2(els_logi->common_service.fcph_version, FPLD + offset);

	offset = 6;
	FCOE_V2B_2(els_logi->common_service.btob_credit, FPLD + offset);

	offset = 8;
	FCOE_V2B_2(els_logi->common_service.cmn_features, FPLD + offset);

	offset = 10;
	FCOE_V2B_2(els_logi->common_service.rx_bufsize, FPLD + offset);

	offset = 12;
	FCOE_V2B_2(els_logi->common_service.conc_sequences, FPLD + offset);

	offset = 14;
	FCOE_V2B_2(els_logi->common_service.relative_offset, FPLD + offset);

	offset = 16;
	FCOE_V2B_4(els_logi->common_service.e_d_tov, FPLD + offset);

	/*
	 * port/node wwn
	 */
	offset = 20;
	bcopy(&els_logi->nport_ww_name, FPLD + offset, 8);

	offset = 28;
	bcopy(&els_logi->node_ww_name, FPLD + offset, 8);

	/*
	 * class_3
	 */
	offset = 68;
	FCOE_V2B_2(els_logi->class_3.class_opt, FPLD + offset);

	offset = 70;
	FCOE_V2B_2(els_logi->class_3.initiator_ctl, FPLD + offset);

	offset = 72;
	FCOE_V2B_2(els_logi->class_3.recipient_ctl, FPLD + offset);

	offset = 74;
	FCOE_V2B_2(els_logi->class_3.rcv_size, FPLD + offset);

	offset = 76;
	FCOE_V2B_2(els_logi->class_3.conc_sequences, FPLD + offset);

	offset = 78;
	FCOE_V2B_2(els_logi->class_3.n_port_e_to_e_credit, FPLD + offset);

	offset = 80;
	FCOE_V2B_2(els_logi->class_3.open_seq_per_xchng, FPLD + offset);
	/*
	 * needn't touch other fields
	 */
}

/*
 * fcoei_fill_prli_cmd
 *	Fill PRLI command frame
 *
 * Input:
 *	fpkt = LV fc_packet
 *	frm = Unsolicited frame containing PRLI response
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_fill_els_prli_cmd(fc_packet_t *fpkt, fcoe_frame_t *frm)
{
	int		 offset	    = 0;
	la_els_prli_t	*els_prli   = (la_els_prli_t *)(void *)fpkt->pkt_cmd;
	struct fcp_prli *fcp_spp    =
	    (struct fcp_prli *)(void *)els_prli->service_params;

	/*
	 * fill basic PRLI fields
	 */
	offset = 0;
	FCOE_V2B_1(els_prli->ls_code, FPLD + offset);

	offset = 1;
	FCOE_V2B_1(els_prli->page_length, FPLD + offset);

	offset = 2;
	FCOE_V2B_2(els_prli->payload_length, FPLD + offset);

	/*
	 * fill FCP service parameters page
	 */
	offset = 4;
	FCOE_V2B_1(fcp_spp->type, FPLD + offset);

	/*
	 * PRLI flags, only 3 bits are valid
	 */
	offset = 6;

	FCOE_V2B_2(((fcp_spp->orig_process_assoc_valid << 15) |
	    (fcp_spp->resp_process_assoc_valid << 14) |
	    (fcp_spp->establish_image_pair << 13)), FPLD + offset);

	/*
	 * process associator
	 */
	offset = 8;
	FCOE_V2B_4(fcp_spp->orig_process_associator, FPLD + offset);

	offset = 12;
	FCOE_V2B_4(fcp_spp->resp_process_associator, FPLD + offset);

	/*
	 * FC-4 type
	 */
	offset = 16;
	FCOE_V2B_4((fcp_spp->retry << 8) |
	    (fcp_spp->confirmed_compl_allowed << 7) |
	    (fcp_spp->data_overlay_allowed << 6) |
	    (fcp_spp->initiator_fn << 5) | (fcp_spp->target_fn << 4) |
	    (fcp_spp->read_xfer_rdy_disabled << 1) |
	    (fcp_spp->write_xfer_rdy_disabled), FPLD + offset);
}

/*
 * fcoei_fill_els_scr_cmd
 *	Fill SCR (state change register) command frame
 *
 * Input:
 *	fpkt = LV fc_packet
 *	frm = Unsolicited frame containing SCR command
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_fill_els_scr_cmd(fc_packet_t *fpkt, fcoe_frame_t *frm)
{
	fc_scr_req_t	*els_scr = (fc_scr_req_t *)(void *)fpkt->pkt_cmd;
	int		 offset;

	offset = 0;
	FCOE_V2B_1(els_scr->ls_code.ls_code, FPLD + offset);

	offset = 7;
	FCOE_V2B_1(els_scr->scr_func, FPLD + offset);
}

/*
 * fcoei_fill_els_adisc_cmd
 *	Fill ADISC command frame
 *
 * Input:
 *	fpkt = LV fc_packet
 *	frm = Unsolicited frame containing ADISC command
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_fill_els_adisc_cmd(fc_packet_t *fpkt, fcoe_frame_t *frm)
{
	la_els_adisc_t	*els_adisc = (la_els_adisc_t *)(void *)fpkt->pkt_cmd;
	int		 offset;

	offset = 0;
	FCOE_V2B_1(els_adisc->ls_code.ls_code, FPLD + offset);

	offset = 5;
	FCOE_V2B_3(els_adisc->hard_addr.hard_addr, FPLD + offset);

	offset = 8;
	bcopy(&els_adisc->port_wwn, FPLD + offset, 8);

	offset = 16;
	bcopy(&els_adisc->node_wwn, FPLD + offset, 8);

	offset = 25;
	FCOE_V2B_3(els_adisc->nport_id.port_id, FPLD + offset);
}

/*
 * fcoei_fill_els_linit_cmd
 *	Fill LINIT command frame
 *
 * Input:
 *	fpkt = LV fc_packet
 *	frm = Unsolicited frame containing LINIT command
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
/* ARGSUSED */
static void
fcoei_fill_els_linit_cmd(fc_packet_t *fpkt, fcoe_frame_t *frm)
{
	ASSERT(fpkt && frm);
}

/*
 * fcoei_fill_els_logo_cmd
 *	Fill LOGO command frame
 *
 * Input:
 *	fpkt = LV fc_packet
 *	frm = Unsolicited frame containing LOGO command
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_fill_els_logo_cmd(fc_packet_t *fpkt, fcoe_frame_t *frm)
{
	la_els_logo_t	*els_logo   = (la_els_logo_t *)(void *)fpkt->pkt_cmd;
	int		 offset;

	offset = 0;
	FCOE_V2B_1(els_logo->ls_code.ls_code, FPLD + offset);

	offset = 5;
	FCOE_V2B_3(els_logo->nport_id.port_id, FPLD + offset);

	offset = 8;
	bcopy(&els_logo->nport_ww_name, FPLD + offset, 8);
}

static void
fcoei_fill_els_rls_cmd(fc_packet_t *fpkt, fcoe_frame_t *frm)
{
	la_els_rls_t	*els_rls = (la_els_rls_t *)(void *)fpkt->pkt_cmd;
	int		offset;

	offset = 0;
	FCOE_V2B_1(els_rls->ls_code.ls_code, FPLD + offset);

	offset = 5;
	FCOE_V2B_3(els_rls->rls_portid.port_id, FPLD + offset);
}

static void
fcoei_fill_els_rnid_cmd(fc_packet_t *fpkt, fcoe_frame_t *frm)
{
	la_els_rnid_t *els_rnid = (la_els_rnid_t *)(void *)fpkt->pkt_cmd;
	int		offset;

	offset = 0;
	FCOE_V2B_1(els_rnid->ls_code.ls_code, FPLD + offset);

	offset = 4;
	bcopy(&els_rnid->data_format, FPLD + offset, 1);
}
/*
 * fcoei_fill_els_acc_resp
 *	Fill ELS ACC response frame
 *
 * Input:
 *	fpkt = LV fc_packet
 *	frm = Unsolicited frame containing ELS ACC response
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_fill_els_acc_resp(fc_packet_t *fpkt, fcoe_frame_t *frm)
{
	ls_code_t	*els_code = (ls_code_t *)(void *)fpkt->pkt_cmd;
	int		 offset;

	offset = 0;
	FCOE_V2B_1(els_code->ls_code, FPLD + offset);

	offset = 1;
	FCOE_V2B_3(els_code->mbz, FPLD + offset);
}

/*
 * fcoei_fill_els_rjt_resp
 *	Fill ELS RJT response frame
 *
 * Input:
 *	fpkt = LV fc_packet
 *	frm = Unsolicited frame containg ELS RJT response
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_fill_els_rjt_resp(fc_packet_t *fpkt, fcoe_frame_t *frm)
{
	la_els_rjt_t	*els_rjt = (la_els_rjt_t *)(void *)fpkt->pkt_cmd;
	int		 offset;

	offset = 0; /* reset ls code */
	FCOE_V2B_1(els_rjt->ls_code.ls_code, FPLD + offset);

	offset = 5; /* reason code */
	FCOE_V2B_1(els_rjt->action, FPLD + offset);

	offset = 6; /* reason explanation */
	FCOE_V2B_1(els_rjt->reason, FPLD + offset);

	offset = 7; /* vendor unique */
	FCOE_V2B_1(els_rjt->vu, FPLD + offset);
}

/*
 * fcoei_fill_els_adisc_resp
 *	Fill ADISC response frame
 *
 * Input:
 *	fpkt = LV fc_packet
 *	frm = Unsolicited frame containing ADISC response
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_fill_els_adisc_resp(fc_packet_t *fpkt, fcoe_frame_t *frm)
{
	la_els_adisc_t	*els_adisc = (la_els_adisc_t *)(void *)fpkt->pkt_cmd;
	int		 offset;

	if (els_adisc->ls_code.ls_code == LA_ELS_RJT) {
		fcoei_fill_els_rjt_resp(fpkt, frm);
	} else {
		offset = 0;
		FCOE_V2B_1(els_adisc->ls_code.ls_code, FPLD + offset);

		offset = 5;
		FCOE_V2B_3(els_adisc->hard_addr.hard_addr, FPLD + offset);

		offset = 8;
		bcopy(&els_adisc->port_wwn, FPLD + offset, FC_WWN_SIZE);

		offset = 16;
		bcopy(&els_adisc->node_wwn, FPLD + offset, FC_WWN_SIZE);

		offset = 25;
		FCOE_V2B_3(els_adisc->nport_id.port_id, FPLD + offset);
	}
}

/*
 * fcoei_fill_els_logi_resp
 *	Fill FLOGI/PLOGI response frame
 *
 * Input:
 *	fpkt = LV fc_packet
 *	frm = Unsolicited frame containing LOGI response
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_fill_els_logi_resp(fc_packet_t *fpkt, fcoe_frame_t *frm)
{
	ls_code_t	*els_code = (ls_code_t *)(void *)fpkt->pkt_cmd;

	if (els_code->ls_code == LA_ELS_RJT) {
		fcoei_fill_els_rjt_resp(fpkt, frm);
	} else {
		fcoei_fill_els_logi_cmd(fpkt, frm);
	}
}

/*
 * fcoei_fill_els_prli_resp
 *	Fill PRLI response frame
 *
 * Input:
 *	fpkt = LV fc_packet
 *	frm = Unsolicited frame containing PRLI response
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_fill_els_prli_resp(fc_packet_t *fpkt, fcoe_frame_t *frm)
{
	ls_code_t	*els_code = (ls_code_t *)(void *)fpkt->pkt_cmd;

	if (els_code->ls_code == LA_ELS_RJT) {
		fcoei_fill_els_rjt_resp(fpkt, frm);
	} else {
		fcoei_fill_els_prli_cmd(fpkt, frm);
	}
}

/*
 * fcoei_fill_els_logo_resp
 *	Fill LOGO response frame
 *
 * Input:
 *	fpkt = LV fc_packet
 *	frm = Unsolicited frame containing LOGO response
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_fill_els_logo_resp(fc_packet_t *fpkt, fcoe_frame_t *frm)
{
	ls_code_t	*els_code   = (ls_code_t *)(void *)fpkt->pkt_cmd;

	if (els_code->ls_code == LA_ELS_RJT) {
		fcoei_fill_els_rjt_resp(fpkt, frm);
	} else {
		fcoei_fill_els_acc_resp(fpkt, frm);
	}
}

/*
 * fcoei_logo_peer
 *	Send LOGO to the peer to emulate link offline event
 *
 * Input:
 *	arg - fcoei soft state set in fcoei_bind_port
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_logo_peer(void *arg)
{
	fcoei_soft_state_t	*ss = (fcoei_soft_state_t *)arg;
	fc_packet_t		*fpkt;
	fcoei_exchange_t	*xch;
	la_els_logo_t		*els_logo;

	/*
	 * Allocate space for exchange
	 */
	xch = kmem_zalloc(sizeof (*xch), KM_SLEEP);

	/*
	 * Allocate space for fc_packet
	 */
	fpkt = kmem_zalloc(sizeof (fc_packet_t), KM_SLEEP);
	fpkt->pkt_cmdlen = 20;
	fpkt->pkt_cmd = kmem_zalloc(fpkt->pkt_cmdlen, KM_SLEEP);
	fpkt->pkt_rsplen = 20;
	fpkt->pkt_resp = kmem_zalloc(fpkt->pkt_rsplen, KM_SLEEP);

	/*
	 * Link them together
	 */
	fpkt->pkt_fca_private = xch;
	(void) fcoei_init_pkt(ss, fpkt, 0);

	/*
	 * Initialize FC frame header
	 */
	if (ss->ss_eport->eport_flags & EPORT_FLAG_IS_DIRECT_P2P) {
		fpkt->pkt_cmd_fhdr.d_id = ss->ss_p2p_info.d_id;
	} else {
		fpkt->pkt_cmd_fhdr.d_id = 0xFFFFFE;
	}

	fpkt->pkt_cmd_fhdr.s_id = ss->ss_p2p_info.fca_d_id;
	fpkt->pkt_cmd_fhdr.r_ctl = R_CTL_ELS_REQ;
	fpkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
	fpkt->pkt_cmd_fhdr.f_ctl = 0x290000;
	fpkt->pkt_timeout = 1;

	/*
	 * Initialize LOGO payload
	 */
	els_logo = (la_els_logo_t *)(void *)fpkt->pkt_cmd;
	els_logo->ls_code.ls_code = LA_ELS_LOGO;
	els_logo->nport_id.port_id = ss->ss_p2p_info.fca_d_id;
	bcopy(ss->ss_eport->eport_portwwn, &els_logo->nport_ww_name, 8);

	/*
	 * Set the completion function
	 */
	fpkt->pkt_comp = fcoei_fpkt_comp;
	if (fcoei_transport(ss, fpkt) != FC_SUCCESS) {
		FCOEI_LOG(__FUNCTION__, "fcoei_transport LOGO failed");
		fcoei_fpkt_comp(fpkt);
	}
}

/*
 * fcoei_fpkt_comp
 *	internal exchange completion
 *
 * Input:
 *	fpkt - fc_packet_t to be completed
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *
 */
static void
fcoei_fpkt_comp(fc_packet_t *fpkt)
{
	fcoei_exchange_t	*xch = FPKT2XCH(fpkt);

	FCOEI_LOG(__FUNCTION__, "internal exchange is completed: %p", xch);

	(void) fcoei_un_init_pkt(xch->xch_ss, xch->xch_fpkt);
	kmem_free(xch->xch_fpkt->pkt_cmd, xch->xch_fpkt->pkt_cmdlen);
	kmem_free(xch->xch_fpkt->pkt_resp, xch->xch_fpkt->pkt_rsplen);
	kmem_free(xch->xch_fpkt, sizeof (fc_packet_t));
	kmem_free(xch, sizeof (fcoei_exchange_t));
}

/*
 * fcoei_xch_abort
 *	Prepare to abort the exchange
 *
 * Input:
 *	key = oxid/rxid of the exchange
 *	val = the exchange
 *	arg = the soft state
 *
 * Returns:
 *	MH_WALK_CONTINUE = continue to walk
 *
 * Comments:
 *	N/A
 */
/* ARGSUSED */
static uint32_t
fcoei_xch_abort(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	fcoei_exchange_t	*xch = (fcoei_exchange_t *)val;

	ASSERT(arg == xch->xch_ss);
	ASSERT(CMHK(key) != 0xFFFF);
	xch->xch_flags |= XCH_FLAG_ABORT;
	xch->xch_fpkt->pkt_state = FC_PKT_LOCAL_RJT;
	xch->xch_fpkt->pkt_reason = FC_REASON_OFFLINE;
	list_insert_tail(&xch->xch_ss->ss_comp_xch_list, xch);
	return (MH_WALK_CONTINUE);
}

/*
 * fcoei_init_fcatran_vectors
 *	Initialize fc_fca_tran vectors that are defined in this file
 *
 * Input:
 *	fcatran - fc_fca_tran of the soft state
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
void
fcoei_init_fcatran_vectors(fc_fca_tran_t *fcatran)
{
	fcatran->fca_bind_port	 = fcoei_bind_port;
	fcatran->fca_unbind_port = fcoei_unbind_port;
	fcatran->fca_init_pkt	 = fcoei_init_pkt;
	fcatran->fca_un_init_pkt = fcoei_un_init_pkt;
	fcatran->fca_els_send	 = fcoei_els_send;
	fcatran->fca_get_cap	 = fcoei_get_cap;
	fcatran->fca_set_cap	 = fcoei_set_cap;
	fcatran->fca_getmap	 = fcoei_getmap;
	fcatran->fca_transport	 = fcoei_transport;
	fcatran->fca_ub_alloc	 = fcoei_ub_alloc;
	fcatran->fca_ub_free	 = fcoei_ub_free;
	fcatran->fca_ub_release	 = fcoei_ub_release;
	fcatran->fca_abort	 = fcoei_abort;
	fcatran->fca_reset	 = fcoei_reset;
	fcatran->fca_port_manage = fcoei_port_manage;
	fcatran->fca_get_device	 = fcoei_get_device;
	fcatran->fca_notify	 = fcoei_notify;
}

/*
 * fcoei_process_event_reset
 *	link reset phase II
 *
 * Input:
 *	arg - fcoei soft state set in fcoei_bind_port
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *
 */
void
fcoei_process_event_reset(fcoei_event_t *ae)
{
	fcoei_soft_state_t	*ss = (fcoei_soft_state_t *)ae->ae_obj;

	ASSERT(!MUTEX_HELD(&ss->ss_watchdog_mutex));
	kmem_free(ae, sizeof (*ae));

	mod_hash_walk(ss->ss_sol_oxid_hash, fcoei_xch_abort, ss);
	mod_hash_walk(ss->ss_unsol_rxid_hash, fcoei_xch_abort, ss);
	fcoei_handle_comp_xch_list(ss);

	/*
	 * Notify LV that the link is up now
	 */
	ss->ss_eport->eport_ctl(ss->ss_eport, FCOE_CMD_PORT_ONLINE, 0);
}

/*
 * fcoei_process_event_exchange
 *	Process exchange in the single thread context
 *
 * Input:
 *	ae = the exchange event
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
void
fcoei_process_event_exchange(fcoei_event_t *ae)
{
	fcoei_exchange_t	*xch  = (fcoei_exchange_t *)ae->ae_obj;
	fcoei_exchange_t	*xch_tmp;
	fc_packet_t		*fpkt = xch->xch_fpkt;

	/*
	 * These 4 elements need reset, pkt_state & pkt_reason will be set
	 */
	fpkt->pkt_action = 0;
	fpkt->pkt_expln = 0;
	fpkt->pkt_data_resid = 0;
	fpkt->pkt_resp_resid = 0;

	/*
	 * port state sanity checking
	 */
	if ((xch->xch_ss->ss_link_state != FC_STATE_ONLINE) ||
	    xch->xch_ss->ss_port_event_counter) {
		/*
		 * LV will retry it after one second
		 */
		fcoei_complete_xch(xch, NULL, FC_PKT_PORT_OFFLINE,
		    FC_REASON_OFFLINE);
		return;
	}

	switch (fpkt->pkt_cmd_fhdr.r_ctl) {
	case R_CTL_COMMAND:
		FCOEI_INIT_SOL_ID_HASH(xch, xch_tmp);
		fcoei_initiate_fcp_cmd(xch);
		break;

	case R_CTL_ELS_REQ:
		FCOEI_INIT_SOL_ID_HASH(xch, xch_tmp);
		fcoei_initiate_els_req(xch);
		break;

	case R_CTL_UNSOL_CONTROL:
		FCOEI_INIT_SOL_ID_HASH(xch, xch_tmp);
		fcoei_initiate_ct_req(xch);
		break;

	case R_CTL_ELS_RSP:
		/*
		 * Caution: in leadville, it still uses pkt_cmd_fhdr
		 * oxid & rxid have been decided when we get unsolicited frames.
		 * pkt_cmd_fhdr has contained the right oxid and rxid now.
		 */
		FCOEI_INIT_UNSOL_ID_HASH(xch);
		fcoei_initiate_els_resp(xch);
		break;

	default:
		fcoei_complete_xch(xch, NULL, FC_PKT_FAILURE,
		    FC_REASON_CMD_UNSUPPORTED);
	}
}
