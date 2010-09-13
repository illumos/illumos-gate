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
 * hermon_agents.c
 *    Hermon InfiniBand Management Agent (SMA, PMA, BMA) routines
 *
 *    Implements all the routines necessary for initializing, handling,
 *    and (later) tearing down all the infrastructure necessary for Hermon
 *    MAD processing.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>

#include <sys/ib/adapters/hermon/hermon.h>
#include <sys/ib/mgt/ibmf/ibmf.h>
#include <sys/disp.h>

static void hermon_agent_request_cb(ibmf_handle_t ibmf_handle,
    ibmf_msg_t *msgp, void *args);
static void hermon_agent_handle_req(void *cb_args);
static void hermon_agent_response_cb(ibmf_handle_t ibmf_handle,
    ibmf_msg_t *msgp, void *args);
static int hermon_agent_list_init(hermon_state_t *state);
static void hermon_agent_list_fini(hermon_state_t *state);
static int hermon_agent_register_all(hermon_state_t *state);
static int hermon_agent_unregister_all(hermon_state_t *state, int num_reg);
static void hermon_agent_mad_resp_handling(hermon_state_t *state,
    ibmf_msg_t *msgp, uint_t port);

/*
 * hermon_agent_handlers_init()
 *    Context: Only called from attach() and/or detach() path contexts
 */
int
hermon_agent_handlers_init(hermon_state_t *state)
{
	int		status;
	char		*rsrc_name;

	/* Determine if we need to register any agents with the IBMF */
	if ((state->hs_cfg_profile->cp_qp0_agents_in_fw) &&
	    (state->hs_cfg_profile->cp_qp1_agents_in_fw)) {
		return (DDI_SUCCESS);
	}

	/*
	 * Build a unique name for the Hermon task queue from the Hermon driver
	 * instance number and HERMON_TASKQ_NAME
	 */
	rsrc_name = (char *)kmem_zalloc(HERMON_RSRC_NAME_MAXLEN, KM_SLEEP);
	HERMON_RSRC_NAME(rsrc_name, HERMON_TASKQ_NAME);

	/* Initialize the Hermon IB management agent list */
	status = hermon_agent_list_init(state);
	if (status != DDI_SUCCESS) {
		goto agentsinit_fail;
	}

	/*
	 * Initialize the agent handling task queue.  Note: We set the task
	 * queue priority to the minimum system priority.  At this point this
	 * is considered acceptable because MADs are unreliable datagrams
	 * and could get lost (in general) anyway.
	 */
	state->hs_taskq_agents = ddi_taskq_create(state->hs_dip,
	    rsrc_name, HERMON_TASKQ_NTHREADS, TASKQ_DEFAULTPRI, 0);
	if (state->hs_taskq_agents == NULL) {
		hermon_agent_list_fini(state);
		goto agentsinit_fail;
	}

	/* Now attempt to register all of the agents with the IBMF */
	status = hermon_agent_register_all(state);
	if (status != DDI_SUCCESS) {
		ddi_taskq_destroy(state->hs_taskq_agents);
		hermon_agent_list_fini(state);
		goto agentsinit_fail;
	}

	kmem_free(rsrc_name, HERMON_RSRC_NAME_MAXLEN);
	return (DDI_SUCCESS);

agentsinit_fail:
	kmem_free(rsrc_name, HERMON_RSRC_NAME_MAXLEN);
	return (status);
}


/*
 * hermon_agent_handlers_fini()
 *    Context: Only called from detach() path context
 */
int
hermon_agent_handlers_fini(hermon_state_t *state)
{
	int		status;

	/* Determine if we need to unregister any agents from the IBMF */
	if ((state->hs_cfg_profile->cp_qp0_agents_in_fw) &&
	    (state->hs_cfg_profile->cp_qp1_agents_in_fw)) {
		return (DDI_SUCCESS);
	}

	/* Now attempt to unregister all of the agents from the IBMF */
	status = hermon_agent_unregister_all(state, state->hs_num_agents);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * Destroy the task queue.  The task queue destroy is guaranteed to
	 * wait until any scheduled tasks have completed.  We are able to
	 * guarantee that no _new_ tasks will be added the task queue while
	 * we are in the ddi_taskq_destroy() call because we have
	 * (at this point) successfully unregistered from IBMF (in
	 * hermon_agent_unregister_all() above).
	 */
	ddi_taskq_destroy(state->hs_taskq_agents);

	/* Teardown the Hermon IB management agent list */
	hermon_agent_list_fini(state);

	return (DDI_SUCCESS);
}


/*
 * hermon_agent_request_cb()
 *    Context: Called from the IBMF context
 */
static void
hermon_agent_request_cb(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
    void *args)
{
	hermon_agent_handler_arg_t	*cb_args;
	hermon_agent_list_t		*curr;
	hermon_state_t			*state;
	int				status;

	curr  = (hermon_agent_list_t *)args;
	state = curr->agl_state;

	/*
	 * Allocate space to hold the callback args (for passing to the
	 * task queue).  Note: If we are unable to allocate space for the
	 * the callback args here, then we just return.  But we must ensure
	 * that we call ibmf_free_msg() to free up the message.
	 */
	cb_args = (hermon_agent_handler_arg_t *)kmem_zalloc(
	    sizeof (hermon_agent_handler_arg_t), KM_NOSLEEP);
	if (cb_args == NULL) {
		(void) ibmf_free_msg(ibmf_handle, &msgp);
		return;
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*cb_args))

	/* Fill in the callback args */
	cb_args->ahd_ibmfhdl	= ibmf_handle;
	cb_args->ahd_ibmfmsg	= msgp;
	cb_args->ahd_agentlist	= args;

	/*
	 * Dispatch the message to the task queue.  Note: Just like above,
	 * if this request fails for any reason then make sure to free up
	 * the IBMF message and then return
	 */
	status = ddi_taskq_dispatch(state->hs_taskq_agents,
	    hermon_agent_handle_req, cb_args, DDI_NOSLEEP);
	if (status == DDI_FAILURE) {
		kmem_free(cb_args, sizeof (hermon_agent_handler_arg_t));
		(void) ibmf_free_msg(ibmf_handle, &msgp);
	}
}

/*
 * hermon_get_smlid()
 *	Simple helper function for hermon_agent_handle_req() below.
 *	Get the portinfo and extract the smlid.
 */
static ib_lid_t
hermon_get_smlid(hermon_state_t *state, uint_t port)
{
	sm_portinfo_t			portinfo;
	int				status;

	status = hermon_getportinfo_cmd_post(state, port,
	    HERMON_SLEEPFLAG_FOR_CONTEXT(), &portinfo);
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Hermon: GetPortInfo (port %02d) command "
		    "failed: %08x\n", port, status);
		return (0);
	}
	return (portinfo.MasterSMLID);
}

/*
 * hermon_get_port_change_flags()
 * 	Helper function to determine the changes in the incoming MAD's portinfo
 * 	for the Port Change event.
 */
static ibt_port_change_t
hermon_port_change_flags(sm_portinfo_t *curpinfo, sm_portinfo_t *madpinfo)
{
	int SMDisabled, ReregSuppd;
	ibt_port_change_t flags = 0;

	SMDisabled = curpinfo->CapabilityMask & SM_CAP_MASK_IS_SM_DISABLED;
	ReregSuppd = curpinfo->CapabilityMask & SM_CAP_MASK_IS_CLNT_REREG_SUPPD;

	if (curpinfo->MasterSMLID != madpinfo->MasterSMLID) {
		flags |= IBT_PORT_CHANGE_SM_LID;
	}
	if (curpinfo->MasterSMSL != madpinfo->MasterSMSL) {
		flags |= IBT_PORT_CHANGE_SM_SL;
	}
	if (curpinfo->SubnetTimeOut != madpinfo->SubnetTimeOut) {
		flags |= IBT_PORT_CHANGE_SUB_TIMEOUT;
	}
	if ((madpinfo->CapabilityMask & SM_CAP_MASK_IS_SM_DISABLED)
	    ^ SMDisabled) {
		flags |= IBT_PORT_CHANGE_SM_FLAG;
	}
	if ((madpinfo->CapabilityMask & SM_CAP_MASK_IS_CLNT_REREG_SUPPD)
	    ^ ReregSuppd) {
		flags |= IBT_PORT_CHANGE_REREG;
	}
	return (flags);
}

int
hermon_set_port_capability(hermon_state_t *state, uint8_t port,
    sm_portinfo_t *portinfo, ibt_port_change_t flags)
{
	uint32_t		capmask;
	int			status;
	hermon_hw_set_port_t	set_port;

	bzero(&set_port, sizeof (set_port));

	/* Validate that specified port number is legal */
	if (!hermon_portnum_is_valid(state, port)) {
		return (IBT_HCA_PORT_INVALID);
	}

	/*
	 * Convert InfiniBand-defined port capability flags to the format
	 * specified by the IBTF.  Specifically, we modify the capability
	 * mask based on the specified values.
	 */
	capmask = portinfo->CapabilityMask;

	if (flags & IBT_PORT_CHANGE_SM_FLAG)
		capmask ^= SM_CAP_MASK_IS_SM;

	if (flags & IBT_PORT_CHANGE_REREG)
		capmask ^= SM_CAP_MASK_IS_CLNT_REREG_SUPPD;
	set_port.cap_mask = capmask;

	/*
	 * Use the Hermon SET_PORT command to update the capability mask and
	 * (possibly) reset the QKey violation counter for the specified port.
	 * Note: In general, this operation shouldn't fail.  If it does, then
	 * it is an indication that something (probably in HW, but maybe in
	 * SW) has gone seriously wrong.
	 */
	status = hermon_set_port_cmd_post(state, &set_port, port,
	    HERMON_SLEEPFLAG_FOR_CONTEXT());
	if (status != HERMON_CMD_SUCCESS) {
		HERMON_WARNING(state, "failed to modify port capabilities");
		cmn_err(CE_CONT, "Hermon: SET_IB (port %02d) command failed: "
		    "%08x\n", port, status);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * hermon_agent_handle_req()
 *    Context: Called with priority of taskQ thread
 */
static void
hermon_agent_handle_req(void *cb_args)
{
	hermon_agent_handler_arg_t	*agent_args;
	hermon_agent_list_t		*curr;
	ibc_async_event_t		event;
	ibt_async_code_t		type, code;
	sm_portinfo_t			curpinfo, tmadpinfo;
	sm_portinfo_t			*madpinfop;
	hermon_state_t			*state;
	ibmf_handle_t			ibmf_handle;
	ibmf_msg_t			*msgp;
	ibmf_msg_bufs_t			*recv_msgbufp;
	ibmf_msg_bufs_t			*send_msgbufp;
	ib_mad_hdr_t			*madhdrp;
	ibmf_retrans_t			retrans;
	uint_t				port;
	int				status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*((sm_portinfo_t *)madpinfop)))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(curpinfo))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(tmadpinfo))
	/* Extract the necessary info from the callback args parameter */
	agent_args  = (hermon_agent_handler_arg_t *)cb_args;
	ibmf_handle = agent_args->ahd_ibmfhdl;
	msgp	    = agent_args->ahd_ibmfmsg;
	curr	    = agent_args->ahd_agentlist;
	state	    = curr->agl_state;
	port	    = curr->agl_port;

	/*
	 * Set the message send buffer pointers to the message receive buffer
	 * pointers to reuse the IBMF provided buffers for the sender
	 * information.
	 */
	recv_msgbufp = &msgp->im_msgbufs_recv;
	send_msgbufp = &msgp->im_msgbufs_send;
	bcopy(recv_msgbufp, send_msgbufp, sizeof (ibmf_msg_bufs_t));

	/*
	 * Check if the incoming packet is a special "Hermon Trap" MAD.  If it
	 * is, then do the special handling.  If it isn't, then simply pass it
	 * on to the firmware and forward the response back to the IBMF.
	 *
	 * Note: Hermon has a unique method for handling internally generated
	 * Traps.  All internally detected/generated Trap messages are
	 * automatically received by the IBMF (as receive completions on QP0),
	 * which (because all Hermon Trap MADs have SLID == 0) detects it as a
	 * special "Hermon Trap" and forwards it here to the driver's SMA.
	 * It is then our responsibility here to fill in the Trap MAD's DLID
	 * for forwarding to the real Master SM (as programmed in the port's
	 * PortInfo.MasterSMLID field.)
	 */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(msgp->im_local_addr))
	if (HERMON_IS_SPECIAL_TRAP_MAD(msgp)) {
		msgp->im_local_addr.ia_remote_lid =
		    hermon_get_smlid(state, port);
	} else {
		int isSMSet, isReregSuppd;
		uint_t attr_id, method, mgmt_class;

		madhdrp = recv_msgbufp->im_bufs_mad_hdr;
		method = madhdrp->R_Method;
		attr_id = b2h16(madhdrp->AttributeID);
		mgmt_class = madhdrp->MgmtClass;

		/*
		 * Is this a Subnet Manager MAD with SET method ? If so
		 * we will have to get the current portinfo to generate
		 * events based on what has changed in portinfo.
		 */
		isSMSet = (((mgmt_class == MAD_MGMT_CLASS_SUBN_LID_ROUTED)||
		    (mgmt_class == MAD_MGMT_CLASS_SUBN_DIRECT_ROUTE)) &&
		    (method == MAD_METHOD_SET));

		/*
		 * Get the current portinfo to compare with the portinfo
		 * received in the MAD for PortChange event.
		 */
		if (isSMSet && (attr_id == SM_PORTINFO_ATTRID) ||
		    (attr_id == SM_PKEY_TABLE_ATTRID) ||
		    (attr_id == SM_GUIDINFO_ATTRID)) {
			madpinfop = recv_msgbufp->im_bufs_cl_data;
			tmadpinfo = *madpinfop;
			HERMON_GETPORTINFO_SWAP(&tmadpinfo);
			status = hermon_getportinfo_cmd_post(state, port,
			    HERMON_SLEEPFLAG_FOR_CONTEXT(), &curpinfo);
			if (status != HERMON_CMD_SUCCESS) {
				cmn_err(CE_CONT, "Hermon: GetPortInfo "
				    "(port %02d) command failed: %08x\n", port,
				    status);
				goto hermon_agent_handle_req_skip_response;
			}
		}

		/*
		 * Post the command to the firmware (using the MAD_IFC
		 * command).  Note: We also reuse the command that was passed
		 * in.  We pass the pointer to the original MAD payload as if
		 * it were both the source of the incoming MAD as well as the
		 * destination for the response.  This is acceptable and saves
		 * us the step of one additional copy.  Note:  If this command
		 * fails for any reason other than HERMON_CMD_BAD_PKT, it
		 * probably indicates a serious problem.
		 */
		status = hermon_mad_ifc_cmd_post(state, port,
		    HERMON_CMD_SLEEP_NOSPIN,
		    (uint32_t *)recv_msgbufp->im_bufs_mad_hdr,
		    (uint32_t *)send_msgbufp->im_bufs_mad_hdr);
		if (status != HERMON_CMD_SUCCESS) {
			if ((status != HERMON_CMD_BAD_PKT) &&
			    (status != HERMON_CMD_INSUFF_RSRC)) {
				cmn_err(CE_CONT, "Hermon: MAD_IFC (port %02d) "
				    "command failed: %08x\n", port, status);
			}

			/* finish cleanup */
			goto hermon_agent_handle_req_skip_response;
		}

		if (isSMSet) {
			event.ev_port_flags = 0;
			type = 0;
			event.ev_port = (uint8_t)port;

			switch (attr_id) {
			case SM_PORTINFO_ATTRID:
				/*
				 * This is a SM SET method with portinfo
				 * attribute. If ClientRereg bit was set in
				 * the MADs portinfo this is a REREG event
				 * (see section 14.4.11 in IB Spec 1.2.1). Else
				 * compare the current (before MAD_IFC command)
				 * portinfo with the portinfo in the MAD and
				 * signal PORT_CHANGE event with the proper
				 * ev_port_flags.
				 *
				 */
				isReregSuppd = curpinfo.CapabilityMask &
				    SM_CAP_MASK_IS_CLNT_REREG_SUPPD;

				madpinfop = recv_msgbufp->im_bufs_cl_data;
				if (tmadpinfo.ClientRereg && isReregSuppd) {
					type |= IBT_CLNT_REREG_EVENT;
				}

				type |= IBT_PORT_CHANGE_EVENT;
				event.ev_port_flags = hermon_port_change_flags(
				    &curpinfo, &tmadpinfo);
				if (event.ev_port_flags &
				    (IBT_PORT_CHANGE_REREG |
				    IBT_PORT_CHANGE_SM_FLAG)) {
					if (hermon_set_port_capability(state,
					    port, &curpinfo,
					    event.ev_port_flags)
					    != DDI_SUCCESS) {
						cmn_err(CE_CONT, "HERMON: Port "
						    "%d capability reset "
						    "failed\n", port);
					}
				}

				/*
				 * If we have a SMLID change event but
				 * capability mask doesn't have Rereg support
				 * bit set, we have to do the Rereg part too.
				 */
				if ((event.ev_port_flags &
				    IBT_PORT_CHANGE_SM_LID) && !isReregSuppd)
					type |= IBT_CLNT_REREG_EVENT;
				break;
			case SM_PKEY_TABLE_ATTRID:
				type |= IBT_PORT_CHANGE_EVENT;
				event.ev_port_flags = IBT_PORT_CHANGE_PKEY;
				break;
			case SM_GUIDINFO_ATTRID:
				type |= IBT_PORT_CHANGE_EVENT;
				event.ev_port_flags = IBT_PORT_CHANGE_SGID;
				break;
			default:
				break;

			}

			/*
			 * NOTE: here we call ibc_async_handler directly without
			 * using the HERMON_DO_IBTF_ASYNC_CALLB, since hermon
			 * can not be unloaded till ibmf_unregiter is done and
			 * this thread (hs_taskq_agents) will be destroyed
			 * before ibmf_uregister is called.
			 *
			 * The hermon event queue based hs_in_evcallb flag
			 * assumes that we will pick one event after another
			 * and dispatch them sequentially. If we use
			 * HERMON_DO_IBTF_ASYNC_CALLB, we will break this
			 * assumption make hs_in_evcallb inconsistent.
			 */
			while (type != 0) {
				if (type & IBT_PORT_CHANGE_EVENT) {
					code = IBT_PORT_CHANGE_EVENT;
					type &= ~IBT_PORT_CHANGE_EVENT;
				} else {
					code = IBT_CLNT_REREG_EVENT;
					type = 0;
				}
				ibc_async_handler(state->hs_ibtfpriv, code,
				    &event);
			}
		}
	}

	/*
	 * If incoming MAD was "TrapRepress", then no response is necessary.
	 * Free the IBMF message and return.
	 */
	if (HERMON_IS_TRAP_REPRESS_MAD(msgp)) {
		goto hermon_agent_handle_req_skip_response;
	}

	/*
	 * Modify the response MAD as necessary (for any special cases).
	 * Specifically, if this MAD was a directed route MAD, then some
	 * additional packet manipulation may be necessary because the Hermon
	 * firmware does not do all the required steps to respond to the
	 * MAD.
	 */
	hermon_agent_mad_resp_handling(state, msgp, port);

	/*
	 * Send response (or forwarded "Trap" MAD) back to IBMF.  We use the
	 * "response callback" to indicate when it is appropriate (later) to
	 * free the IBMF msg.
	 */
	status = ibmf_msg_transport(ibmf_handle, IBMF_QP_HANDLE_DEFAULT,
	    msgp, &retrans, hermon_agent_response_cb, state, 0);
	if (status != IBMF_SUCCESS) {
		goto hermon_agent_handle_req_skip_response;
	}

	/* Free up the callback args parameter */
	kmem_free(agent_args, sizeof (hermon_agent_handler_arg_t));
	return;

hermon_agent_handle_req_skip_response:
	/* Free up the ibmf message */
	(void) ibmf_free_msg(ibmf_handle, &msgp);

	/* Free up the callback args parameter */
	kmem_free(agent_args, sizeof (hermon_agent_handler_arg_t));
}


/*
 * hermon_agent_response_cb()
 *    Context: Called from the IBMF context
 */
/* ARGSUSED */
static void
hermon_agent_response_cb(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
    void *args)
{
	/*
	 * It is the responsibility of each IBMF callback recipient to free
	 * the packets that it has been given.  Now that we are in the
	 * response callback, we can be assured that it is safe to do so.
	 */
	(void) ibmf_free_msg(ibmf_handle, &msgp);
}


/*
 * hermon_agent_list_init()
 *    Context: Only called from attach() path context
 */
static int
hermon_agent_list_init(hermon_state_t *state)
{
	hermon_agent_list_t	*curr;
	uint_t			num_ports, num_agents, num_agents_per_port;
	uint_t			num_sma_agents = 0;
	uint_t			num_pma_agents = 0;
	uint_t			num_bma_agents = 0;
	uint_t			do_qp0, do_qp1;
	int			i, j, indx;

	/*
	 * Calculate the number of registered agents for each port
	 * (SMA, PMA, and BMA) and determine whether or not to register
	 * a given agent with the IBMF (or whether to let the Hermon firmware
	 * handle it)
	 */
	num_ports	    = state->hs_cfg_profile->cp_num_ports;
	num_agents	    = 0;
	num_agents_per_port = 0;
	do_qp0		    = state->hs_cfg_profile->cp_qp0_agents_in_fw;
	do_qp1		    = state->hs_cfg_profile->cp_qp1_agents_in_fw;
	if (do_qp0 == 0) {
		num_agents += (num_ports * HERMON_NUM_QP0_AGENTS_PER_PORT);
		num_agents_per_port += HERMON_NUM_QP0_AGENTS_PER_PORT;
		num_sma_agents = num_ports;
	}
	if (do_qp1 == 0) {
		num_agents += (num_ports * HERMON_NUM_QP1_AGENTS_PER_PORT);
		num_agents_per_port += HERMON_NUM_QP1_AGENTS_PER_PORT;
		num_pma_agents = num_ports;
		/*
		 * The following line is commented out because the Hermon
		 * firmware does not currently support a BMA.  If it did,
		 * then we would want to register the agent with the IBMF.
		 * (We would also need to have HERMON_NUM_QP1_AGENTS_PER_PORT
		 * set to 2, instead of 1.)
		 *
		 * num_bma_agents = num_ports;
		 */
	}

	state->hs_num_agents = num_agents;

	/*
	 * Allocate the memory for all of the agent list entries
	 */
	state->hs_agents = (hermon_agent_list_t *)kmem_zalloc(num_agents *
	    sizeof (hermon_agent_list_t), KM_SLEEP);
	if (state->hs_agents == NULL) {
		return (DDI_FAILURE);
	}

	/*
	 * Fill in each of the agent list entries with the agent's
	 * MgmtClass, port number, and Hermon softstate pointer
	 */
	indx = 0;
	for (i = 0; i < num_agents_per_port; i++) {
		for (j = 0; j < num_ports; j++) {
			curr = &state->hs_agents[indx];
			curr->agl_state = state;
			curr->agl_port  = j + 1;

			if ((do_qp0 == 0) && num_sma_agents) {
				curr->agl_mgmtclass = SUBN_AGENT;
				num_sma_agents--;
				indx++;
			} else if ((do_qp1 == 0) && (num_pma_agents)) {
				curr->agl_mgmtclass = PERF_AGENT;
				num_pma_agents--;
				indx++;
			} else if ((do_qp1 == 0) && (num_bma_agents)) {
				curr->agl_mgmtclass = BM_AGENT;
				num_bma_agents--;
				indx++;
			}
		}
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_agent_list_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
static void
hermon_agent_list_fini(hermon_state_t *state)
{
	/* Free up the memory for the agent list entries */
	kmem_free(state->hs_agents,
	    state->hs_num_agents * sizeof (hermon_agent_list_t));
}


/*
 * hermon_agent_register_all()
 *    Context: Only called from attach() path context
 */
static int
hermon_agent_register_all(hermon_state_t *state)
{
	hermon_agent_list_t	*curr;
	ibmf_register_info_t	ibmf_reg;
	ibmf_impl_caps_t	impl_caps;
	ib_guid_t		nodeguid;
	int			i, status, num_registered;

	/* Get the Hermon NodeGUID from the softstate */
	nodeguid = state->hs_ibtfinfo.hca_attr->hca_node_guid;

	/*
	 * Register each of the agents with the IBMF (and add callbacks for
	 * each to the hermon_agent_request_cb() routine).  Note:  If we
	 * fail somewhere along the line here, we attempt to cleanup as much
	 * of the mess as we can and then jump to hermon_agent_unregister_all()
	 * to cleanup the rest.
	 */
	num_registered = 0;

	if (state->hs_num_agents == 0) {
		return (DDI_SUCCESS);
	}

	for (i = 0; i < state->hs_num_agents; i++) {
		/* Register each agent with the IBMF */
		curr = &state->hs_agents[i];
		ibmf_reg.ir_ci_guid	 = nodeguid;
		ibmf_reg.ir_port_num	 = curr->agl_port;
		ibmf_reg.ir_client_class = curr->agl_mgmtclass;

		status = ibmf_register(&ibmf_reg, IBMF_VERSION, 0,
		    NULL, NULL, &curr->agl_ibmfhdl, &impl_caps);
		if (status != IBMF_SUCCESS) {
			goto agents_reg_fail;
		}

		/* Setup callbacks with the IBMF */
		status  = ibmf_setup_async_cb(curr->agl_ibmfhdl,
		    IBMF_QP_HANDLE_DEFAULT, hermon_agent_request_cb, curr, 0);
		if (status != IBMF_SUCCESS) {
			(void) ibmf_unregister(&curr->agl_ibmfhdl, 0);
			goto agents_reg_fail;
		}
		num_registered++;
	}

	return (DDI_SUCCESS);

agents_reg_fail:
	(void) hermon_agent_unregister_all(state, num_registered);
	return (DDI_FAILURE);
}


/*
 * hermon_agent_unregister_all()
 *    Context: Only called from detach() path context
 */
static int
hermon_agent_unregister_all(hermon_state_t *state, int num_reg)
{
	hermon_agent_list_t	*curr;
	int			i, status;

	if (num_reg == 0) {
		return (DDI_SUCCESS);
	}

	/*
	 * For each registered agent in the agent list, teardown the
	 * callbacks from the IBMF and unregister.
	 */
	for (i = 0; i < num_reg; i++) {
		curr = &state->hs_agents[i];

		/* Teardown the IBMF callback */
		status = ibmf_tear_down_async_cb(curr->agl_ibmfhdl,
		    IBMF_QP_HANDLE_DEFAULT, 0);
		if (status != IBMF_SUCCESS) {
			return (DDI_FAILURE);
		}

		/* Unregister the agent from the IBMF */
		status = ibmf_unregister(&curr->agl_ibmfhdl, 0);
		if (status != IBMF_SUCCESS) {
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_agent_mad_resp_handling()
 *    Context: Called with priority of taskQ thread
 */
/* ARGSUSED */
static void
hermon_agent_mad_resp_handling(hermon_state_t *state, ibmf_msg_t *msgp,
    uint_t port)
{
	ib_mad_hdr_t	*rmadhdrp = msgp->im_msgbufs_recv.im_bufs_mad_hdr;
	ib_mad_hdr_t	*smadhdrp = msgp->im_msgbufs_send.im_bufs_mad_hdr;
	uint_t		hop_count, hop_point;
	uchar_t		*resp, *ret_path;

	resp = (uchar_t *)msgp->im_msgbufs_send.im_bufs_cl_data;

	/*
	 * Handle directed route MADs as a special case.  Hermon firmware
	 * does not update the "direction" bit, "hop pointer", "Return
	 * Path" or, in fact, any of the "directed route" parameters.  So
	 * the responsibility falls on Hermon driver software to inspect the
	 * MADs and update those fields as appropriate (see section 14.2.2
	 * of the IBA specification, rev 1.1)
	 */
	if (HERMON_MAD_IS_DR(rmadhdrp)) {

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*((sm_dr_mad_hdr_t *)rmadhdrp)))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*((sm_dr_mad_hdr_t *)smadhdrp)))

		/*
		 * Set the "Direction" bit to one.  This indicates that this
		 * is now directed route response
		 */
		HERMON_DRMAD_SET_DIRECTION(rmadhdrp);

		/* Extract the "hop pointer" and "hop count" from the MAD */
		hop_count = HERMON_DRMAD_GET_HOPCOUNT(rmadhdrp);
		hop_point = HERMON_DRMAD_GET_HOPPOINTER(rmadhdrp);

		/* Append the port we came in on to the "Return Path" */
		if ((hop_count != 0) && ((hop_point == hop_count) ||
		    (hop_point == hop_count + 1))) {
			ret_path = &resp[HERMON_DRMAD_RETURN_PATH_OFFSET];
			ret_path[hop_point] = (uchar_t)port;
		}

		/* Then increment the "hop pointer" in the MAD */
		hop_point++;
		HERMON_DRMAD_SET_HOPPOINTER(smadhdrp, (uint8_t)hop_point);
	}
}
