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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * tavor_agents.c
 *    Tavor InfiniBand Management Agent (SMA, PMA, BMA) routines
 *
 *    Implements all the routines necessary for initializing, handling,
 *    and (later) tearing down all the infrastructure necessary for Tavor
 *    MAD processing.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>

#include <sys/ib/adapters/tavor/tavor.h>
#include <sys/ib/mgt/ibmf/ibmf.h>
#include <sys/disp.h>

static void tavor_agent_request_cb(ibmf_handle_t ibmf_handle,
    ibmf_msg_t *msgp, void *args);
static void tavor_agent_handle_req(void *cb_args);
static void tavor_agent_response_cb(ibmf_handle_t ibmf_handle,
    ibmf_msg_t *msgp, void *args);
static int tavor_agent_list_init(tavor_state_t *state);
static void tavor_agent_list_fini(tavor_state_t *state);
static int tavor_agent_register_all(tavor_state_t *state);
static int tavor_agent_unregister_all(tavor_state_t *state, int num_reg);
static void tavor_agent_mad_resp_handling(tavor_state_t *state,
    ibmf_msg_t *msgp, uint_t port);

/*
 * tavor_agent_handlers_init()
 *    Context: Only called from attach() and/or detach() path contexts
 */
int
tavor_agent_handlers_init(tavor_state_t *state)
{
	int		status;
	char		*rsrc_name;

	/* Determine if we need to register any agents with the IBMF */
	if ((state->ts_cfg_profile->cp_qp0_agents_in_fw) &&
	    (state->ts_cfg_profile->cp_qp1_agents_in_fw)) {
		return (DDI_SUCCESS);
	}

	/*
	 * Build a unique name for the Tavor task queue from the Tavor driver
	 * instance number and TAVOR_TASKQ_NAME
	 */
	rsrc_name = (char *)kmem_zalloc(TAVOR_RSRC_NAME_MAXLEN, KM_SLEEP);
	TAVOR_RSRC_NAME(rsrc_name, TAVOR_TASKQ_NAME);

	/* Initialize the Tavor IB management agent list */
	status = tavor_agent_list_init(state);
	if (status != DDI_SUCCESS) {
		goto agentsinit_fail;
	}

	/*
	 * Initialize the agent handling task queue.  Note: We set the task
	 * queue priority to the minimum system priority.  At this point this
	 * is considered acceptable because MADs are unreliable datagrams
	 * and could get lost (in general) anyway.
	 */
	state->ts_taskq_agents = ddi_taskq_create(state->ts_dip,
	    rsrc_name, TAVOR_TASKQ_NTHREADS, TASKQ_DEFAULTPRI, 0);
	if (state->ts_taskq_agents == NULL) {
		tavor_agent_list_fini(state);
		goto agentsinit_fail;
	}

	/* Now attempt to register all of the agents with the IBMF */
	status = tavor_agent_register_all(state);
	if (status != DDI_SUCCESS) {
		ddi_taskq_destroy(state->ts_taskq_agents);
		tavor_agent_list_fini(state);
		goto agentsinit_fail;
	}

	kmem_free(rsrc_name, TAVOR_RSRC_NAME_MAXLEN);
	return (DDI_SUCCESS);

agentsinit_fail:
	kmem_free(rsrc_name, TAVOR_RSRC_NAME_MAXLEN);
	return (status);
}


/*
 * tavor_agent_handlers_fini()
 *    Context: Only called from detach() path context
 */
int
tavor_agent_handlers_fini(tavor_state_t *state)
{
	int		status;

	/* Determine if we need to unregister any agents from the IBMF */
	if ((state->ts_cfg_profile->cp_qp0_agents_in_fw) &&
	    (state->ts_cfg_profile->cp_qp1_agents_in_fw)) {
		return (DDI_SUCCESS);
	}

	/* Now attempt to unregister all of the agents from the IBMF */
	status = tavor_agent_unregister_all(state, state->ts_num_agents);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * Destroy the task queue.  The task queue destroy is guaranteed to
	 * wait until any scheduled tasks have completed.  We are able to
	 * guarantee that no _new_ tasks will be added the task queue while
	 * we are in the ddi_taskq_destroy() call because we have
	 * (at this point) successfully unregistered from IBMF (in
	 * tavor_agent_unregister_all() above).
	 */
	ddi_taskq_destroy(state->ts_taskq_agents);

	/* Teardown the Tavor IB management agent list */
	tavor_agent_list_fini(state);

	return (DDI_SUCCESS);
}


/*
 * tavor_agent_request_cb()
 *    Context: Called from the IBMF context
 */
static void
tavor_agent_request_cb(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
    void *args)
{
	tavor_agent_handler_arg_t	*cb_args;
	tavor_agent_list_t		*curr;
	tavor_state_t			*state;
	int				status;

	curr  = (tavor_agent_list_t *)args;
	state = curr->agl_state;

	/*
	 * Allocate space to hold the callback args (for passing to the
	 * task queue).  Note: If we are unable to allocate space for the
	 * the callback args here, then we just return.  But we must ensure
	 * that we call ibmf_free_msg() to free up the message.
	 */
	cb_args = (tavor_agent_handler_arg_t *)kmem_zalloc(
	    sizeof (tavor_agent_handler_arg_t), KM_NOSLEEP);
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
	status = ddi_taskq_dispatch(state->ts_taskq_agents,
	    tavor_agent_handle_req, cb_args, DDI_NOSLEEP);
	if (status == DDI_FAILURE) {
		kmem_free(cb_args, sizeof (tavor_agent_handler_arg_t));
		(void) ibmf_free_msg(ibmf_handle, &msgp);
	}
}

/*
 * tavor_agent_handle_req()
 *    Context: Called with priority of taskQ thread
 */
static void
tavor_agent_handle_req(void *cb_args)
{
	tavor_agent_handler_arg_t	*agent_args;
	tavor_agent_list_t		*curr;
	tavor_state_t			*state;
	ibmf_handle_t			ibmf_handle;
	ibmf_msg_t			*msgp;
	ibmf_msg_bufs_t			*recv_msgbufp;
	ibmf_msg_bufs_t			*send_msgbufp;
	ibmf_retrans_t			retrans;
	uint_t				port;
	int				status;

	/* Extract the necessary info from the callback args parameter */
	agent_args  = (tavor_agent_handler_arg_t *)cb_args;
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
	 * Check if the incoming packet is a special "Tavor Trap" MAD.  If it
	 * is, then do the special handling.  If it isn't, then simply pass it
	 * on to the firmware and forward the response back to the IBMF.
	 *
	 * Note: Tavor has a unique method for handling internally generated
	 * Traps.  All internally detected/generated Trap messages are
	 * automatically received by the IBMF (as receive completions on QP0),
	 * which (because all Tavor Trap MADs have SLID == 0) detects it as a
	 * special "Tavor Trap" and forwards it here to the driver's SMA.
	 * It is then our responsibility here to fill in the Trap MAD's DLID
	 * for forwarding to the real Master SM (as programmed in the port's
	 * PortInfo.MasterSMLID field.)
	 */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(msgp->im_local_addr))
	if (TAVOR_IS_SPECIAL_TRAP_MAD(msgp)) {
		msgp->im_local_addr.ia_remote_lid =
		    TAVOR_PORT_MASTERSMLID_GET(state, port - 1);
	} else {
		/*
		 * Post the command to the firmware (using the MAD_IFC
		 * command).  Note: We also reuse the command that was passed
		 * in.  We pass the pointer to the original MAD payload as if
		 * it were both the source of the incoming MAD as well as the
		 * destination for the response.  This is acceptable and saves
		 * us the step of one additional copy.  Note:  If this command
		 * fails for any reason other than TAVOR_CMD_BAD_PKT, it
		 * probably indicates a serious problem.
		 */
		status = tavor_mad_ifc_cmd_post(state, port,
		    TAVOR_CMD_SLEEP_NOSPIN,
		    (uint32_t *)recv_msgbufp->im_bufs_mad_hdr,
		    (uint32_t *)send_msgbufp->im_bufs_mad_hdr);
		if (status != TAVOR_CMD_SUCCESS) {
			if ((status != TAVOR_CMD_BAD_PKT) &&
			    (status != TAVOR_CMD_INSUFF_RSRC)) {
				cmn_err(CE_CONT, "Tavor: MAD_IFC (port %02d) "
				    "command failed: %08x\n", port, status);
			}

			/* finish cleanup */
			goto tavor_agent_handle_req_skip_response;
		}
	}

	/*
	 * If incoming MAD was "TrapRepress", then no response is necessary.
	 * Free the IBMF message and return.
	 */
	if (TAVOR_IS_TRAP_REPRESS_MAD(msgp)) {
		goto tavor_agent_handle_req_skip_response;
	}

	/*
	 * Modify the response MAD as necessary (for any special cases).
	 * Specifically, if this MAD was a directed route MAD, then some
	 * additional packet manipulation may be necessary because the Tavor
	 * firmware does not do all the required steps to respond to the
	 * MAD.
	 */
	tavor_agent_mad_resp_handling(state, msgp, port);

	/*
	 * Send response (or forwarded "Trap" MAD) back to IBMF.  We use the
	 * "response callback" to indicate when it is appropriate (later) to
	 * free the IBMF msg.
	 */
	status = ibmf_msg_transport(ibmf_handle, IBMF_QP_HANDLE_DEFAULT,
	    msgp, &retrans, tavor_agent_response_cb, state, 0);
	if (status != IBMF_SUCCESS) {
		goto tavor_agent_handle_req_skip_response;
	}

	/* Free up the callback args parameter */
	kmem_free(agent_args, sizeof (tavor_agent_handler_arg_t));
	return;

tavor_agent_handle_req_skip_response:
	/* Free up the ibmf message */
	status = ibmf_free_msg(ibmf_handle, &msgp);
	/* Free up the callback args parameter */
	kmem_free(agent_args, sizeof (tavor_agent_handler_arg_t));
}


/*
 * tavor_agent_response_cb()
 *    Context: Called from the IBMF context
 */
/* ARGSUSED */
static void
tavor_agent_response_cb(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
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
 * tavor_agent_list_init()
 *    Context: Only called from attach() path context
 */
static int
tavor_agent_list_init(tavor_state_t *state)
{
	tavor_agent_list_t	*curr;
	uint_t			num_ports, num_agents, num_agents_per_port;
	uint_t			num_sma_agents = 0;
	uint_t			num_pma_agents = 0;
	uint_t			num_bma_agents = 0;
	uint_t			do_qp0, do_qp1;
	int			i, j, indx;

	/*
	 * Calculate the number of registered agents for each port
	 * (SMA, PMA, and BMA) and determine whether or not to register
	 * a given agent with the IBMF (or whether to let the Tavor firmware
	 * handle it)
	 */
	num_ports	    = state->ts_cfg_profile->cp_num_ports;
	num_agents	    = 0;
	num_agents_per_port = 0;
	do_qp0		    = state->ts_cfg_profile->cp_qp0_agents_in_fw;
	do_qp1		    = state->ts_cfg_profile->cp_qp1_agents_in_fw;
	if (do_qp0 == 0) {
		num_agents += (num_ports * TAVOR_NUM_QP0_AGENTS_PER_PORT);
		num_agents_per_port += TAVOR_NUM_QP0_AGENTS_PER_PORT;
		num_sma_agents = num_ports;
	}
	if (do_qp1 == 0) {
		num_agents += (num_ports * TAVOR_NUM_QP1_AGENTS_PER_PORT);
		num_agents_per_port += TAVOR_NUM_QP1_AGENTS_PER_PORT;
		num_pma_agents = num_ports;
		/*
		 * The following line is commented out because the Tavor
		 * firmware does not currently support a BMA.  If it did,
		 * then we would want to register the agent with the IBMF.
		 * (We would also need to have TAVOR_NUM_QP1_AGENTS_PER_PORT
		 * set to 2, instead of 1.)
		 *
		 * num_bma_agents = num_ports;
		 */
	}

	state->ts_num_agents = num_agents;

	/*
	 * Allocate the memory for all of the agent list entries
	 */
	state->ts_agents = (tavor_agent_list_t *)kmem_zalloc(num_agents *
	    sizeof (tavor_agent_list_t), KM_SLEEP);
	if (state->ts_agents == NULL) {
		return (DDI_FAILURE);
	}

	/*
	 * Fill in each of the agent list entries with the agent's
	 * MgmtClass, port number, and Tavor softstate pointer
	 */
	indx = 0;
	for (i = 0; i < num_agents_per_port; i++) {
		for (j = 0; j < num_ports; j++) {
			curr = &state->ts_agents[indx];
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
 * tavor_agent_list_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
static void
tavor_agent_list_fini(tavor_state_t *state)
{
	/* Free up the memory for the agent list entries */
	kmem_free(state->ts_agents,
	    state->ts_num_agents * sizeof (tavor_agent_list_t));
}


/*
 * tavor_agent_register_all()
 *    Context: Only called from attach() path context
 */
static int
tavor_agent_register_all(tavor_state_t *state)
{
	tavor_agent_list_t	*curr;
	ibmf_register_info_t	ibmf_reg;
	ibmf_impl_caps_t	impl_caps;
	ib_guid_t		nodeguid;
	int			i, status, num_registered;

	/* Get the Tavor NodeGUID from the softstate */
	nodeguid = state->ts_ibtfinfo.hca_attr->hca_node_guid;

	/*
	 * Register each of the agents with the IBMF (and add callbacks for
	 * each to the tavor_agent_request_cb() routine).  Note:  If we
	 * fail somewhere along the line here, we attempt to cleanup as much
	 * of the mess as we can and then jump to tavor_agent_unregister_all()
	 * to cleanup the rest.
	 */
	num_registered = 0;
	for (i = 0; i < state->ts_num_agents; i++) {

		/* Register each agent with the IBMF */
		curr = &state->ts_agents[i];
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
		    IBMF_QP_HANDLE_DEFAULT, tavor_agent_request_cb, curr, 0);
		if (status != IBMF_SUCCESS) {
			(void) ibmf_unregister(&curr->agl_ibmfhdl, 0);
			goto agents_reg_fail;
		}
		num_registered++;
	}

	return (DDI_SUCCESS);

agents_reg_fail:
	(void) tavor_agent_unregister_all(state, num_registered);
	return (DDI_FAILURE);
}


/*
 * tavor_agent_unregister_all()
 *    Context: Only called from detach() path context
 */
static int
tavor_agent_unregister_all(tavor_state_t *state, int num_reg)
{
	tavor_agent_list_t	*curr;
	int			i, status;

	/*
	 * For each registered agent in the agent list, teardown the
	 * callbacks from the IBMF and unregister.
	 */
	for (i = 0; i < num_reg; i++) {
		curr = &state->ts_agents[i];

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
 * tavor_agent_mad_resp_handling()
 *    Context: Called with priority of taskQ thread
 */
/* ARGSUSED */
static void
tavor_agent_mad_resp_handling(tavor_state_t *state, ibmf_msg_t *msgp,
    uint_t port)
{
	ib_mad_hdr_t	*rmadhdrp = msgp->im_msgbufs_recv.im_bufs_mad_hdr;
	ib_mad_hdr_t	*smadhdrp = msgp->im_msgbufs_send.im_bufs_mad_hdr;
	uint_t		hop_count, hop_point;
	uchar_t		*resp, *ret_path;

	resp = (uchar_t *)msgp->im_msgbufs_send.im_bufs_cl_data;

	/*
	 * Handle directed route MADs as a special case.  Tavor firmware
	 * does not update the "direction" bit, "hop pointer", "Return
	 * Path" or, in fact, any of the "directed route" parameters.  So
	 * the responsibility falls on Tavor driver software to inspect the
	 * MADs and update those fields as appropriate (see section 14.2.2
	 * of the IBA specification, rev 1.1)
	 */
	if (TAVOR_MAD_IS_DR(rmadhdrp)) {

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*((sm_dr_mad_hdr_t *)rmadhdrp)))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*((sm_dr_mad_hdr_t *)smadhdrp)))

		/*
		 * Set the "Direction" bit to one.  This indicates that this
		 * is now directed route response
		 */
		TAVOR_DRMAD_SET_DIRECTION(rmadhdrp);

		/* Extract the "hop pointer" and "hop count" from the MAD */
		hop_count = TAVOR_DRMAD_GET_HOPCOUNT(rmadhdrp);
		hop_point = TAVOR_DRMAD_GET_HOPPOINTER(rmadhdrp);

		/* Append the port we came in on to the "Return Path" */
		if ((hop_count != 0) && ((hop_point == hop_count) ||
		    (hop_point == hop_count + 1))) {
			ret_path = &resp[TAVOR_DRMAD_RETURN_PATH_OFFSET];
			ret_path[hop_point] = port;
		}

		/* Then increment the "hop pointer" in the MAD */
		hop_point++;
		TAVOR_DRMAD_SET_HOPPOINTER(smadhdrp, hop_point);
	}
}
