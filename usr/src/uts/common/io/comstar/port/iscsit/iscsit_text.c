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
#include <iscsit_isns.h>
#include <iscsit.h>

#define	IPADDRSTRLEN	INET6_ADDRSTRLEN	/* space for ipaddr string */
#define	PORTALSTRLEN	(IPADDRSTRLEN+16)	/* add space for :port,tag */

/*
 * The kernel inet_ntop() function formats ipv4 address fields with
 * leading zeros which the win2k initiator interprets as octal.
 */

static void iscsit_v4_ntop(struct in_addr *in, char a[], int size)
{
	unsigned char *p = (unsigned char *) in;

	(void) snprintf(a, size, "%d.%d.%d.%d", *p, *(p+1), *(p+2), *(p+3));
}

static void
iscsit_send_reject(idm_pdu_t *req_pdu, uint8_t reason_code)
{
	idm_pdu_t		*reject_pdu;
	iscsi_reject_rsp_hdr_t	*rej_hdr;

	reject_pdu = idm_pdu_alloc(sizeof (iscsi_hdr_t), req_pdu->isp_hdrlen);
	if (reject_pdu == NULL) {
		/* Just give up.. the initiator will timeout */
		idm_pdu_complete(req_pdu, IDM_STATUS_SUCCESS);
		return;
	}

	/* Payload contains the header from the bad PDU */
	idm_pdu_init(reject_pdu, req_pdu->isp_ic, NULL, NULL);
	bcopy(req_pdu->isp_hdr, reject_pdu->isp_data, req_pdu->isp_hdrlen);

	rej_hdr = (iscsi_reject_rsp_hdr_t *)reject_pdu->isp_hdr;
	bzero(rej_hdr, sizeof (*rej_hdr));
	rej_hdr->opcode = ISCSI_OP_REJECT_MSG;
	rej_hdr->flags = ISCSI_FLAG_FINAL;
	rej_hdr->reason = reason_code;
	hton24(rej_hdr->dlength, req_pdu->isp_hdrlen);
	rej_hdr->must_be_ff[0] = 0xff;
	rej_hdr->must_be_ff[1] = 0xff;
	rej_hdr->must_be_ff[2] = 0xff;
	rej_hdr->must_be_ff[3] = 0xff;

	iscsit_pdu_tx(reject_pdu);
	idm_pdu_complete(req_pdu, IDM_STATUS_SUCCESS);
}

static void
iscsit_add_target_portals(nvlist_t *nv_resp, iscsit_tgt_t *target)
{
	iscsit_tpgt_t *tpg_list;
	iscsit_tpg_t *tpg;
	idm_addr_list_t *ipaddr_p;
	idm_addr_t *tip;
	iscsit_portal_t *portal;
	int ipsize, i;
	char *name = "TargetAddress";
	char a[IPADDRSTRLEN];
	char v[PORTALSTRLEN];
	struct sockaddr_storage *ss;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct in_addr *in;
	struct in6_addr *in6;
	int type;


	/*
	 * Look through the portal groups associated with this target.
	 */
	mutex_enter(&target->target_mutex);
	tpg_list = avl_first(&target->target_tpgt_list);
	while (tpg_list != NULL) {
		tpg = tpg_list->tpgt_tpg;
		/*
		 * The default portal group will match any current interface.
		 * A target cannot listen on other portal groups if it
		 * listens on the default portal group.
		 */
		if (tpg == iscsit_global.global_default_tpg) {
			/*
			 * get the list of plumbed interfaces
			 */
			ipsize = idm_get_ipaddr(&ipaddr_p);
			if (ipsize == 0) {
				mutex_exit(&target->target_mutex);
				return;
			}
			tip = &ipaddr_p->al_addrs[0];
			for (i = 0; i < ipaddr_p->al_out_cnt; i++, tip++) {
				if (tip->a_addr.i_insize ==
				    sizeof (struct in_addr)) {
					type = AF_INET;
					in = &tip->a_addr.i_addr.in4;
					iscsit_v4_ntop(in, a, sizeof (a));
					(void) snprintf(v, sizeof (v),
						"%s,1", a);
				} else if (tip->a_addr.i_insize ==
				    sizeof (struct in6_addr)) {
					type = AF_INET6;
					in6 = &tip->a_addr.i_addr.in6;
					(void) inet_ntop(type, in6, a,
						sizeof (a));
					(void) snprintf(v, sizeof (v),
						"[%s],1", a);
				} else {
					break;
				}
				/*
				 * Add the TargetAddress=<addr> nvpair
				 */
				(void) nvlist_add_string(nv_resp, name, v);
			}
			kmem_free(ipaddr_p, ipsize);
			/*
			 * Cannot listen on other portal groups.
			 */
			mutex_exit(&target->target_mutex);
			return;
		}
		/*
		 * Found a defined portal group - add each portal address.
		 */
		portal = avl_first(&tpg->tpg_portal_list);
		while (portal != NULL) {
			ss = &portal->portal_addr;
			type = ss->ss_family;
			switch (type) {
			case AF_INET:
				sin = (struct sockaddr_in *)ss;
				in = &sin->sin_addr;
				iscsit_v4_ntop(in, a, sizeof (a));
				(void) snprintf(v, sizeof (v), "%s:%d,%d", a,
				    ntohs(sin->sin_port),
				    tpg_list->tpgt_tag);
				(void) nvlist_add_string(nv_resp, name, v);
				break;
			case AF_INET6:
				sin6 = (struct sockaddr_in6 *)ss;
				in6 = &sin6->sin6_addr;
				(void) inet_ntop(type, in6, a, sizeof (a));
				(void) snprintf(v, sizeof (v), "[%s]:%d,%d", a,
				    sin6->sin6_port,
				    tpg_list->tpgt_tag);
				(void) nvlist_add_string(nv_resp, name, v);
				break;
			default:
				break;
			}
			portal = AVL_NEXT(&tpg->tpg_portal_list, portal);
		}
		tpg_list = AVL_NEXT(&target->target_tpgt_list, tpg_list);
	}
	mutex_exit(&target->target_mutex);
}

void
iscsit_pdu_op_text_cmd(iscsit_conn_t	*ict, idm_pdu_t *rx_pdu)
{
	iscsi_text_hdr_t *th_req = (iscsi_text_hdr_t *)rx_pdu->isp_hdr;
	iscsi_text_rsp_hdr_t *th_resp;
	nvlist_t *nv_resp;
	char *textbuf;
	char *kv_name, *kv_pair;
	int flags;
	int textbuflen;
	int rc;
	idm_pdu_t *resp;

	flags =  th_req->flags;
	if ((flags & ISCSI_FLAG_FINAL) != ISCSI_FLAG_FINAL) {
		/* Cannot handle multi-PDU messages now */
		iscsit_send_reject(rx_pdu, ISCSI_REJECT_CMD_NOT_SUPPORTED);
		return;
	}
	if (th_req->ttt != ISCSI_RSVD_TASK_TAG) {
		/* Last of a multi-PDU message */
		iscsit_send_reject(rx_pdu, ISCSI_REJECT_CMD_NOT_SUPPORTED);
		return;
	}

	/*
	 * At this point we have a single PDU text command
	 */

	textbuf = (char *)rx_pdu->isp_data;
	textbuflen = rx_pdu->isp_datalen;
	kv_name = "SendTargets=";
	kv_pair = "SendTargets=All";
	if (strncmp(kv_name, textbuf, strlen(kv_name)) != 0) {
		/* Not a Sendtargets command */
		iscsit_send_reject(rx_pdu, ISCSI_REJECT_CMD_NOT_SUPPORTED);
		return;
	}
	if (strcmp(kv_pair, textbuf) == 0 &&
	    ict->ict_op.op_discovery_session == B_TRUE) {
		iscsit_tgt_t *target;
		int validlen;

		/*
		 * Most common case of SendTargets=All during discovery.
		 */
		/*
		 * Create an nvlist for response.
		 */
		if (nvlist_alloc(&nv_resp, 0, KM_SLEEP) != 0) {
			iscsit_send_reject(rx_pdu,
			    ISCSI_REJECT_CMD_NOT_SUPPORTED);
			return;
		}

		ISCSIT_GLOBAL_LOCK(RW_READER);
		target = avl_first(&iscsit_global.global_target_list);
		while (target != NULL) {
			char *name = "TargetName";
			char *val = target->target_name;

			(void) nvlist_add_string(nv_resp, name, val);
			iscsit_add_target_portals(nv_resp, target);
			target = AVL_NEXT(&iscsit_global.global_target_list,
			    target);
		}
		ISCSIT_GLOBAL_UNLOCK();

		/*
		 * Convert the reponse nv list into text buffer.
		 */
		textbuf = 0;
		textbuflen = 0;
		validlen = 0;
		rc = idm_nvlist_to_textbuf(nv_resp, &textbuf,
		    &textbuflen, &validlen);
		nvlist_free(nv_resp);
		if (rc != 0) {
			if (textbuf && textbuflen)
				kmem_free(textbuf, textbuflen);
			iscsit_send_reject(rx_pdu,
			    ISCSI_REJECT_CMD_NOT_SUPPORTED);
			return;
		}
		/*
		 * Allocate a PDU and copy in text response buffer
		 */
		resp = idm_pdu_alloc(sizeof (iscsi_hdr_t), validlen);
		idm_pdu_init(resp, ict->ict_ic, NULL, NULL);
		bcopy(textbuf, resp->isp_data, validlen);
		kmem_free(textbuf, textbuflen);
		/*
		 * Fill in the response header
		 */
		th_resp = (iscsi_text_rsp_hdr_t *)resp->isp_hdr;
		bzero(th_resp, sizeof (*th_resp));
		th_resp->opcode = ISCSI_OP_TEXT_RSP;
		th_resp->flags = ISCSI_FLAG_FINAL;
		th_resp->ttt = ISCSI_RSVD_TASK_TAG;
		th_resp->itt = th_req->itt;
		hton24(th_resp->dlength, validlen);
	} else {
		/*
		 * Other cases to handle
		 *    Discovery session:
		 *	SendTargets=<target_name>
		 *    Normal session
		 *	SendTargets=<target_name> - should match session
		 *	SendTargets=<NULL> - assume target name of session
		 *    All others
		 *	Error
		 */
		iscsit_send_reject(rx_pdu, ISCSI_REJECT_CMD_NOT_SUPPORTED);
		return;
	}

	/* Send the response on its way */
	iscsit_pdu_tx(resp);
	idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
}
