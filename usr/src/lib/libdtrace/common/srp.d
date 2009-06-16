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

#pragma	D depends_on library net.d
#pragma D depends_on library scsi.d
#pragma D depends_on module genunix
#pragma	D depends_on module srpt

typedef struct srp_portinfo {
	/* initiator */
	string  pi_initiator;	/* Initiator: eui.xxxxxxxxxxxxxxx */
	string	pi_i_sid;	/* Initiator session id */

	/* target */
	string	pi_target;	/* Target: eui.xxxxxxxxxxxxxxx */
	string  pi_t_sid;	/* Target session id */

	uintptr_t pi_chan_id;	/* Channel identifier */
} srp_portinfo_t;

#pragma D binding "1.5" translator
translator conninfo_t < srpt_session_t *P > {
	ci_local = P->ss_t_gid;
	ci_remote = P->ss_i_gid;
	ci_protocol = "ib";
};

#pragma D binding "1.5" translator
translator srp_portinfo_t < srpt_session_t *P > {
	pi_initiator = P->ss_i_name;
	pi_i_sid = P->ss_i_alias;
	pi_target = P->ss_t_name;
	pi_t_sid = P->ss_t_alias;
	pi_chan_id = 0; 
};

#pragma D binding "1.5" translator
translator conninfo_t < srpt_channel_t *P > {
	ci_local = P->ch_session->ss_i_gid;
	ci_remote = P->ch_session->ss_t_gid;
};

#pragma D binding "1.5" translator
translator srp_portinfo_t < srpt_channel_t *P > {
	pi_initiator = P->ch_session->ss_i_name;
	pi_i_sid = P->ch_session->ss_i_alias;
	pi_target = P->ch_session->ss_t_name;
	pi_t_sid = P->ch_session->ss_t_alias;
	pi_chan_id = (uintptr_t)P->ch_chan_hdl;
};

typedef struct srp_logininfo {
	uint64_t li_task_tag;	   /* SRP task tag */
	uint32_t li_max_it_iu_len; /* Maximum iu length that initiator can
				      send to target */
	uint32_t li_max_ti_iu_len; /* Maximum iu length that target can
				      send to initiator */
	uint32_t li_request_limit; /* Maximun number of SRP requests 
				      that initiator can send on a channel */
	uint32_t li_reason_code;   /* Reason code */
} srp_logininfo_t;

#pragma D binding "1.5" translator
translator srp_logininfo_t < srp_login_req_t *P > {
	li_task_tag = P->lreq_tag; 
	li_max_it_iu_len = ntohl(P->lreq_req_it_iu_len);
	li_max_ti_iu_len = 0;
	li_request_limit = 0;
	li_reason_code = 0;
};

#pragma D binding "1.5" translator
translator srp_logininfo_t < srp_login_rsp_t *P > {
	li_task_tag = P->lrsp_tag; 
	li_max_it_iu_len = ntohl(P->lrsp_max_it_iu_len);
	li_max_ti_iu_len = ntohl(P->lrsp_max_ti_iu_len);
	li_request_limit = ntohl(P->lrsp_req_limit_delta);
	li_reason_code = ntohl(((srp_login_rej_t *)arg2)->lrej_reason);
};

typedef struct srp_taskinfo {
	uint64_t ti_task_tag;	/* SRP task tag */
	uint64_t ti_lun;	/* Target logical unit number */
	uint8_t  ti_function;	/* Task management function */
	uint32_t ti_req_limit_delta; /* Increment of channel's request limit */
	uint8_t  ti_flag;	     /* bit 2: DOOVER */
	                             /* bit 3: DOUNDER */
	                             /* bit 4: DIOVER */
	                             /* bit 5: DIUNDER */
	uint32_t ti_do_resid_cnt;    /* Data-out residual count */
	uint32_t ti_di_resid_cnt;    /* Data-in residual count */
	uint8_t  ti_status;     /* Status of this task */
} srp_taskinfo_t;

#pragma D binding "1.5" translator
translator srp_taskinfo_t < srp_cmd_req_t *P > {
	ti_task_tag = P->cr_tag;
	ti_lun = (ntohl(*((uint32_t *)P->cr_lun)) << 32) +
	    ntohl(*((uint32_t *)&P->cr_lun[4]));
	ti_function = P->cr_type == 1 ?  /* 1: MGMT CMD 2: SRP CMD */
	    ((srp_tsk_mgmt_t *)P)->tm_function : 0;
	ti_req_limit_delta = 0;
	ti_flag = 0;
	ti_do_resid_cnt = 0;
	ti_di_resid_cnt = 0;
	ti_status = 0;
};

#pragma D binding "1.5" translator
translator srp_taskinfo_t < srp_rsp_t *P > {
	ti_task_tag = P->rsp_tag;
	ti_lun = ntohll(*(uint64_t *)((scsi_task_t *)arg2)->task_lun_no);
	ti_function = ((scsi_task_t *)arg2)->task_mgmt_function;
	ti_req_limit_delta = ntohl(P->rsp_req_limit_delta);
	ti_flag = P->rsp_flags;
	ti_do_resid_cnt = ntohl(P->rsp_do_resid_cnt);
	ti_di_resid_cnt = ntohl(P->rsp_di_resid_cnt);
	ti_status = arg3;
};

#pragma D binding "1.5" translator
translator srp_taskinfo_t < srpt_iu_t *P > {
	ti_task_tag = P->iu_tag;
	ti_lun = ntohll(*(uint64_t *)P->iu_stmf_task->task_lun_no);
	ti_function = 0;
	ti_req_limit_delta = 0;
	ti_flag = 0;
	ti_do_resid_cnt = 0;
	ti_di_resid_cnt = 0;
	ti_status = 0;
};

#pragma D binding "1.5" translator
translator xferinfo_t < ibt_wr_ds_t *P > {
	xfer_laddr = P->ds_va + arg4;
	xfer_lkey = P->ds_key;
	xfer_raddr = (arg3 == 0) ? 0 :
	    ((ibt_send_wr_t *)arg3)->wr.rc.rcwr.rdma.rdma_raddr;
	xfer_rkey = (arg3 == 0) ? 0 :
	    ((ibt_send_wr_t *)arg3)->wr.rc.rcwr.rdma.rdma_rkey;
	xfer_len = arg4;
	xfer_loffset = arg5;
	xfer_roffset = arg6;
	xfer_type = arg7;
};
