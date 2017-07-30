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
 * Copyright 2017 Nexenta Systems, Inc.
 */

#include <sys/cpuvar.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/socket.h>
#include <sys/strsubr.h>
#include <inet/tcp.h>
#include <sys/nvpair.h>

#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>
#include <sys/idm/idm.h>
#include <sys/idm/idm_conn_sm.h>
#include <sys/idm/idm_text.h>
#include <sys/idm/idm_so.h>

#include "iscsit_isns.h"
#include "iscsit.h"

#define	IPADDRSTRLEN	INET6_ADDRSTRLEN	/* space for ipaddr string */
#define	PORTALSTRLEN	(IPADDRSTRLEN+16)	/* add space for :port,tag */

void
iscsit_text_cmd_fini(iscsit_conn_t *ict);

static void
iscsit_bump_ttt(iscsit_conn_t *ict)
{
	/*
	 * Set the target task tag. The value will be zero when
	 * the connection is created. Increment it and wrap it
	 * back to one if we hit the reserved value.
	 *
	 * The TTT is fabricated since there is no real task associated
	 * with a text request. The idm task range is reused here since
	 * no real tasks can be started from a discovery session and
	 * thus no conflicts are possible.
	 */
	if (++ict->ict_text_rsp_ttt == IDM_TASKIDS_MAX)
		ict->ict_text_rsp_ttt = 1;
}

static void
iscsit_text_resp_complete_cb(idm_pdu_t *pdu, idm_status_t status)
{
	iscsit_conn_t *ict = pdu->isp_private;

	idm_pdu_free(pdu);
	if (status != IDM_STATUS_SUCCESS) {
		/*
		 * Could not send the last text response.
		 * Clear any state and bump the TTT so subsequent
		 * requests will not match.
		 */
		iscsit_text_cmd_fini(ict);
		iscsit_bump_ttt(ict);
	}
	iscsit_conn_rele(ict);
}

static void
iscsit_text_reject(idm_pdu_t *req_pdu, uint8_t reason_code)
{
	iscsit_conn_t		*ict = req_pdu->isp_ic->ic_handle;

	/*
	 * A reject means abandoning this text request.
	 * Cleanup any state from the request and increment the TTT
	 * in case the initiator does not get the reject response
	 * and attempts to resume this request.
	 */
	iscsit_text_cmd_fini(ict);
	iscsit_bump_ttt(ict);
	iscsit_send_reject(ict, req_pdu, reason_code);
	idm_pdu_complete(req_pdu, IDM_STATUS_SUCCESS);

}


/*
 * Add individual <TargetAddress=ipaddr> tuple to the nvlist
 */
static void
iscsit_add_portal(struct sockaddr_storage *ss, int tag, nvlist_t *nv_resp)
{
	char ipaddr[IPADDRSTRLEN];	/* ip address string */
	char ta_value[PORTALSTRLEN];	/* target address value */
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	switch (ss->ss_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)ss;
		(void) inet_ntop(AF_INET, &sin->sin_addr, ipaddr,
		    sizeof (ipaddr));
		(void) snprintf(ta_value, sizeof (ta_value), "%s:%d,%d",
		    ipaddr, ntohs(sin->sin_port), tag);
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)ss;
		(void) inet_ntop(AF_INET6, &sin6->sin6_addr, ipaddr,
		    sizeof (ipaddr));
		(void) snprintf(ta_value, sizeof (ta_value), "[%s]:%d,%d",
		    ipaddr, ntohs(sin6->sin6_port), tag);
		break;
	default:
		ASSERT(0);
		return;
	}
	(void) nvlist_add_string(nv_resp, "TargetAddress", ta_value);
}

/*
 * Process the special case of the default portal group.
 * Network addresses are obtained from the network stack and
 * require some reformatting.
 */
static void
iscsit_add_default_portals(iscsit_conn_t *ict, idm_addr_list_t *ipaddr_p,
    nvlist_t *nv_resp)
{
	int pass, i;
	idm_addr_t *tip;
	struct sockaddr_storage ss;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	/*
	 * If this request was received on one of the portals,
	 * output that portal first. Most initiators will try to
	 * connect on the first portal in the SendTargets response.
	 * For example, this will avoid the confusing situation of a
	 * discovery coming in on an IB interface and the initiator
	 * then doing the normal login on an ethernet interface.
	 */
	sin = (struct sockaddr_in *)&ss;
	sin6 = (struct sockaddr_in6 *)&ss;
	for (pass = 1; pass <= 2; pass++) {
		tip = &ipaddr_p->al_addrs[0];
		for (i = 0; i < ipaddr_p->al_out_cnt; i++, tip++) {
			/* Convert the address into sockaddr_storage format */
			switch (tip->a_addr.i_insize) {
			case sizeof (struct in_addr):
				sin->sin_family = AF_INET;
				sin->sin_port = htons(ISCSI_LISTEN_PORT);
				sin->sin_addr = tip->a_addr.i_addr.in4;
				break;
			case sizeof (struct in6_addr):
				sin6->sin6_family = AF_INET6;
				sin6->sin6_port = htons(ISCSI_LISTEN_PORT);
				sin6->sin6_addr = tip->a_addr.i_addr.in6;
				break;
			default:
				ASSERT(0);
				continue;
			}
			switch (pass) {
			case 1:
				/*
				 * On the first pass, skip portals that
				 * do not match the incoming connection.
				 */
				if (idm_ss_compare(&ss, &ict->ict_ic->ic_laddr,
				    B_TRUE, B_TRUE) != 0)
					continue;
				break;
			case 2:
				/*
				 * On the second pass, process the
				 * remaining portals.
				 */
				if (idm_ss_compare(&ss, &ict->ict_ic->ic_laddr,
				    B_TRUE, B_TRUE) == 0)
					continue;
				break;
			}
			/*
			 * Add portal to the response list.
			 * By convention, the default portal group tag == 1
			 */
			iscsit_add_portal(&ss, 1, nv_resp);
		}
	}
}

/*
 * Process a portal group from the configuration database.
 */
static void
iscsit_add_portals(iscsit_conn_t *ict, iscsit_tpgt_t *tpg_list,
    nvlist_t *nv_resp)
{
	int pass;
	iscsit_portal_t *portal, *next_portal;
	iscsit_tpg_t *tpg;
	struct sockaddr_storage *ss;

	/*
	 * As with the default portal group, output the portal used by
	 * the incoming request first.
	 */
	tpg = tpg_list->tpgt_tpg;
	for (pass = 1; pass <= 2; pass++) {
		for (portal = avl_first(&tpg->tpg_portal_list);
		    portal != NULL;
		    portal = next_portal) {

			next_portal = AVL_NEXT(&tpg->tpg_portal_list, portal);
			ss = &portal->portal_addr;
			switch (pass) {
			case 1:
				/*
				 * On the first pass, skip portals that
				 * do not match the incoming connection.
				 */
				if (idm_ss_compare(ss, &ict->ict_ic->ic_laddr,
				    B_TRUE, B_TRUE) != 0)
					continue;
				break;
			case 2:
				/*
				 * On the second pass, process the
				 * remaining portals.
				 */
				if (idm_ss_compare(ss, &ict->ict_ic->ic_laddr,
				    B_TRUE, B_TRUE) == 0)
					continue;
				break;
			}
			/* Add portal to the response list */
			iscsit_add_portal(ss, tpg_list->tpgt_tag, nv_resp);
		}
	}
}

/*
 * Process all the portal groups bound to a particular target.
 */
static void
iscsit_add_tpgs(iscsit_conn_t *ict, iscsit_tgt_t *target,
    idm_addr_list_t *ipaddr_p,  nvlist_t *nv_resp)
{
	iscsit_tpgt_t *tpg_list;

	/*
	 * Look through the portal groups associated with this target.
	 */
	mutex_enter(&target->target_mutex);
	tpg_list = avl_first(&target->target_tpgt_list);

	/* check for the default portal group */
	if (tpg_list->tpgt_tpg == iscsit_global.global_default_tpg) {
		/*
		 * The default portal group is a special case and will
		 * return all reasonable interfaces on this node.
		 *
		 * A target cannot be bound to other portal groups
		 * if it is bound to the default portal group.
		 */
		ASSERT(AVL_NEXT(&target->target_tpgt_list, tpg_list) == NULL);

		if (ipaddr_p != NULL) {
			/* convert the ip address list to nvlist format */
			iscsit_add_default_portals(ict, ipaddr_p, nv_resp);
		}
		mutex_exit(&target->target_mutex);
		return;
	}

	/*
	 * Not the default portal group - process the user defined tpgs
	 */
	ASSERT(tpg_list != NULL);
	while (tpg_list != NULL) {

		ASSERT(tpg_list->tpgt_tpg != iscsit_global.global_default_tpg);

		/*
		 * Found a defined portal group - add each portal address.
		 * As with the default portal group, make 2 passes over
		 * the addresses in order to output the connection
		 * address first.
		 */
		iscsit_add_portals(ict, tpg_list, nv_resp);

		tpg_list = AVL_NEXT(&target->target_tpgt_list, tpg_list);
	}
	mutex_exit(&target->target_mutex);
}

#ifdef DEBUG
/*
 * To test with smaller PDUs in order to force multi-PDU responses,
 * set this value such that: 0 < test_max_len < 8192
 */
uint32_t iscsit_text_max_len = ISCSI_DEFAULT_MAX_RECV_SEG_LEN;
#endif

/*
 * Format a text response PDU from the text buffer and send it.
 */
static void
iscsit_send_next_text_response(iscsit_conn_t *ict, idm_pdu_t *rx_pdu)
{
	iscsi_text_hdr_t *th_req = (iscsi_text_hdr_t *)rx_pdu->isp_hdr;
	iscsi_text_rsp_hdr_t *th_resp;
	idm_pdu_t	*resp;
	uint32_t	len, remainder, max_len;
	char		*base;
	boolean_t	final;

	max_len = ISCSI_DEFAULT_MAX_RECV_SEG_LEN;
#ifdef DEBUG
	if (iscsit_text_max_len > 0 && iscsit_text_max_len < max_len)
		max_len = iscsit_text_max_len;
#endif
	do {
		remainder = ict->ict_text_rsp_valid_len - ict->ict_text_rsp_off;
		if (remainder <= max_len) {
			len = remainder;
			final = B_TRUE;
		} else {
			len = max_len;
			final = B_FALSE;
		}
		/*
		 * Allocate a PDU and copy in text response buffer
		 */
		resp = idm_pdu_alloc(sizeof (iscsi_hdr_t), len);
		idm_pdu_init(resp, ict->ict_ic, ict,
		    iscsit_text_resp_complete_cb);
		/* Advance the StatSN for each Text Response sent */
		resp->isp_flags |= IDM_PDU_SET_STATSN | IDM_PDU_ADVANCE_STATSN;
		base = ict->ict_text_rsp_buf + ict->ict_text_rsp_off;
		bcopy(base, resp->isp_data, len);
		/*
		 * Fill in the response header
		 */
		th_resp = (iscsi_text_rsp_hdr_t *)resp->isp_hdr;
		bzero(th_resp, sizeof (*th_resp));
		th_resp->opcode = ISCSI_OP_TEXT_RSP;
		th_resp->itt = th_req->itt;
		hton24(th_resp->dlength, len);
		if (final) {
			th_resp->flags = ISCSI_FLAG_FINAL;
			th_resp->ttt = ISCSI_RSVD_TASK_TAG;
			kmem_free(ict->ict_text_rsp_buf, ict->ict_text_rsp_len);
			ict->ict_text_rsp_buf = NULL;
			ict->ict_text_rsp_len = 0;
			ict->ict_text_rsp_valid_len = 0;
			ict->ict_text_rsp_off = 0;
		} else {
			th_resp->flags = ISCSI_FLAG_TEXT_CONTINUE;
			th_resp->ttt = ict->ict_text_rsp_ttt;
			ict->ict_text_rsp_off += len;
		}
		/* Send the response on its way */
		iscsit_conn_hold(ict);
		iscsit_pdu_tx(resp);
	} while (!final);
	/* Free the request pdu */
	idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
}

/*
 * Clean-up the text buffer if it exists.
 */
void
iscsit_text_cmd_fini(iscsit_conn_t *ict)
{
	if (ict->ict_text_rsp_buf != NULL) {
		ASSERT(ict->ict_text_rsp_len != 0);
		kmem_free(ict->ict_text_rsp_buf, ict->ict_text_rsp_len);
	}
	ict->ict_text_rsp_buf = NULL;
	ict->ict_text_rsp_len = 0;
	ict->ict_text_rsp_valid_len = 0;
	ict->ict_text_rsp_off = 0;
}

/*
 * Process an iSCSI text command.
 *
 * This code only handles the common case of a text command
 * containing the single tuple SendTargets=All issued during
 * a discovery session. The request will always arrive in a
 * single PDU, but the response may span multiple PDUs if the
 * configuration is large. I.e. many targets and portals.
 *
 * The request is checked for correctness and then the response
 * is generated from the global target into nvlist format. Then
 * the nvlist is reformatted into idm textbuf format which reflects
 * the iSCSI defined <name=value> specification. Finally, the
 * textbuf is sent to the initiator in one or more text response PDUs
 */
void
iscsit_pdu_op_text_cmd(iscsit_conn_t *ict, idm_pdu_t *rx_pdu)
{
	iscsi_text_hdr_t *th_req = (iscsi_text_hdr_t *)rx_pdu->isp_hdr;
	nvlist_t *nv_resp;
	char *kv_pair;
	int flags;
	char *textbuf;
	int textbuflen;
	int validlen;
	int rc;

	flags =  th_req->flags;
	if ((flags & ISCSI_FLAG_FINAL) != ISCSI_FLAG_FINAL) {
		/* Cannot handle multi-PDU requests now */
		iscsit_text_reject(rx_pdu, ISCSI_REJECT_CMD_NOT_SUPPORTED);
		return;
	}
	if (th_req->ttt != ISCSI_RSVD_TASK_TAG) {
		/*
		 * This is the initiator acknowledging our last PDU and
		 * indicating it is ready for the next PDU in the sequence.
		 */
		/*
		 * There can only be one outstanding text request on a
		 * connection. Make sure this one PDU has the current TTT.
		 */
		/* XXX combine the following 3 checks after testing */
		if (th_req->ttt != ict->ict_text_rsp_ttt) {
			/* Not part of this sequence */
			iscsit_text_reject(rx_pdu,
			    ISCSI_REJECT_CMD_NOT_SUPPORTED);
			return;
		}
		/*
		 * ITT should match what was saved from first PDU.
		 */
		if (th_req->itt != ict->ict_text_req_itt) {
			/* Not part of this sequence */
			iscsit_text_reject(rx_pdu,
			    ISCSI_REJECT_CMD_NOT_SUPPORTED);
			return;
		}
		/*
		 * Cannot deal with more key/value pairs now.
		 */
		if (rx_pdu->isp_datalen != 0) {
			iscsit_text_reject(rx_pdu,
			    ISCSI_REJECT_CMD_NOT_SUPPORTED);
			return;
		}
		iscsit_send_next_text_response(ict, rx_pdu);
		return;
	}

	/*
	 * Initiator has started a new text request. Only
	 * one can be active at a time, so abandon any previous
	 * text request on this connection.
	 */
	iscsit_text_cmd_fini(ict);

	/* Set the target task tag. */
	iscsit_bump_ttt(ict);

	/* Save the initiator task tag */
	ict->ict_text_req_itt = th_req->itt;

	/*
	 * Make sure this is a proper SendTargets request
	 */
	textbuf = (char *)rx_pdu->isp_data;
	textbuflen = rx_pdu->isp_datalen;
	kv_pair = "SendTargets=All";
	if (textbuflen >= strlen(kv_pair) &&
	    strcmp(kv_pair, textbuf) == 0 &&
	    ict->ict_op.op_discovery_session == B_TRUE) {
		/*
		 * Most common case of SendTargets=All during discovery.
		 */
		idm_addr_list_t *ipaddr_p;
		iscsit_tgt_t *tgt, *ntgt;
		int ipsize;


		/* Create an nvlist for response */
		if (nvlist_alloc(&nv_resp, 0, KM_SLEEP) != 0) {
			iscsit_text_reject(rx_pdu,
			    ISCSI_REJECT_CMD_NOT_SUPPORTED);
			return;
		}

		/* Get the list of local interface addresses */
		ipsize = idm_get_ipaddr(&ipaddr_p);

		/* Add targets to the response list */
		ISCSIT_GLOBAL_LOCK(RW_READER);
		for (tgt = avl_first(&iscsit_global.global_target_list);
		    tgt != NULL; tgt = ntgt) {
			struct sockaddr_storage v4sa, *sa;
			iscsit_tgt_state_t state;
			iscsit_portal_t *portal;
			iscsit_tpgt_t *tpgt;

			ntgt = AVL_NEXT(&iscsit_global.global_target_list, tgt);

			/* Only report online and onlining targets */
			state = tgt->target_state;
			if (state != TS_ONLINING && state != TS_ONLINE &&
			    state != TS_STMF_ONLINE)
				continue;

			/*
			 * Report target if:
			 * - it is bound to default TPG
			 * - one of the addresses of TPGs the target is bound
			 *   to matches incoming connection dst address
			 */
			sa = &ict->ict_ic->ic_laddr;
			mutex_enter(&tgt->target_mutex);
			tpgt = avl_first(&tgt->target_tpgt_list);
			if (!(IS_DEFAULT_TPGT(tpgt))) {
				portal = iscsit_tgt_lookup_portal(tgt, sa,
				    &tpgt);
				if (portal == NULL &&
				    iscsit_is_v4_mapped(sa, &v4sa)) {
					portal = iscsit_tgt_lookup_portal(tgt,
					    &v4sa, &tpgt);
				}
				if (portal == NULL) {
					mutex_exit(&tgt->target_mutex);
					continue;
				}
				iscsit_portal_rele(portal);
				iscsit_tpgt_rele(tpgt);
			}
			mutex_exit(&tgt->target_mutex);

			if (nvlist_add_string(nv_resp, "TargetName",
			    tgt->target_name) == 0) {
				/* Add the portal groups bound to this target */
				iscsit_add_tpgs(ict, tgt, ipaddr_p, nv_resp);
			}
		}
		ISCSIT_GLOBAL_UNLOCK();
		if (ipsize > 0)
			kmem_free(ipaddr_p, ipsize);

		/* Convert the response nvlist into an idm text buffer */
		textbuf = 0;
		textbuflen = 0;
		validlen = 0;
		rc = idm_nvlist_to_textbuf(nv_resp, &textbuf,
		    &textbuflen, &validlen);
		nvlist_free(nv_resp);
		if (rc != 0) {
			if (textbuf && textbuflen)
				kmem_free(textbuf, textbuflen);
			iscsit_text_reject(rx_pdu,
			    ISCSI_REJECT_CMD_NOT_SUPPORTED);
			return;
		}
		ict->ict_text_rsp_buf = textbuf;
		ict->ict_text_rsp_len = textbuflen;
		ict->ict_text_rsp_valid_len = validlen;
		ict->ict_text_rsp_off = 0;
		iscsit_send_next_text_response(ict, rx_pdu);
	} else {
		/*
		 * Other cases to handle
		 *    Discovery session:
		 *	SendTargets=<target_name>
		 *    Normal session
		 *	SendTargets=<NULL> - assume target name of session
		 *    All others
		 *	Error
		 */
		iscsit_text_reject(rx_pdu, ISCSI_REJECT_CMD_NOT_SUPPORTED);
		return;
	}
}
