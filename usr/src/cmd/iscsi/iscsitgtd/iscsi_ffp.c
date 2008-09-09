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
 * This file contains methods to handle the iSCSI Full Feature Phase aspects
 * of the protocol.
 */

#include <unistd.h>
#include <poll.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <utility.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/iscsi_protocol.h>

#include <arpa/inet.h>

#include "iscsi_ffp.h"
#include "iscsi_cmd.h"
#include "t10_spc.h"
#include "utility.h"
#include "iscsi_provider_impl.h"

static Boolean_t handle_text_msg(iscsi_conn_t *, iscsi_hdr_t *, char *, int);
static Boolean_t handle_logout_msg(iscsi_conn_t *, iscsi_hdr_t *, char *, int);
static Boolean_t handle_scsi_cmd(iscsi_conn_t *, iscsi_hdr_t *, char *, int);
static Boolean_t handle_noop_cmd(iscsi_conn_t *, iscsi_hdr_t *, char *, int);
static Boolean_t handle_scsi_data(iscsi_conn_t *, iscsi_hdr_t *, char *, int);
static Boolean_t handle_task_mgt(iscsi_conn_t *, iscsi_hdr_t *, char *, int);
static Boolean_t dataout_delayed(iscsi_cmd_t *cmd, msg_type_t type);
void dataout_callback(t10_cmd_t *t, char *data, size_t *xfer);

Boolean_t
iscsi_full_feature(iscsi_conn_t *c)
{
	iscsi_hdr_t	h;
	Boolean_t	rval		= False;
	char		debug[128];
	char		*ahs		= NULL;
	int		cc;
	int		ahslen;

	if ((cc = recv(c->c_fd, &h, sizeof (h), MSG_WAITALL)) != sizeof (h)) {
		if (errno == ECONNRESET) {
			(void) snprintf(debug, sizeof (debug),
			    "CON%x  full_feature -- initiator reset socket\n",
			    c->c_num);
		} else {
			(void) snprintf(debug, sizeof (debug),
			    "CON%x full_feature(got-%d, expect-%d), errno=%d\n",
			    c->c_num, cc, sizeof (h), errno);
		}
		queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);
		conn_state(c, T8);
		return (False);
	}

	/*
	 * Look to see if there's an Additional Header Segment available.
	 * If so, read it in.
	 */
	if ((ahslen = (h.hlength * sizeof (uint32_t))) != 0) {
		if ((ahs = malloc(ahslen)) == NULL)
			return (False);
		if (recv(c->c_fd, ahs, ahslen, MSG_WAITALL) != ahslen) {
			(void) snprintf(debug, sizeof (debug),
			    "CON%x  Failed to read in AHS", c->c_num);
			queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);
			free(ahs);
			return (False);
		}
	}

	(void) pthread_mutex_lock(&c->c_state_mutex);
	if (c->c_state != S5_LOGGED_IN && c->c_state != S7_LOGOUT_REQUESTED) {
		(void) snprintf(debug, sizeof (debug),
		    "CON%x  full_feature -- not in S5_LOGGED_IN state\n",
		    c->c_num);
		queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);
		if (ahs != NULL)
			free(ahs);
		(void) pthread_mutex_unlock(&c->c_state_mutex);
		return (False);
	}
	(void) pthread_mutex_unlock(&c->c_state_mutex);

	if (c->c_header_digest == True) {
		uint32_t	crc_actual;
		uint32_t	crc_calculated;

		(void) recv(c->c_fd, (char *)&crc_actual,
		    sizeof (crc_actual), MSG_WAITALL);
		crc_calculated = iscsi_crc32c((void *)&h, sizeof (h));
		if (ahslen)
			crc_calculated = iscsi_crc32c_continued(ahs,
			    ahslen, crc_calculated);
		if (crc_actual != crc_calculated) {
			(void) snprintf(debug, sizeof (debug),
			    "CON%x  CRC error: actual 0x%x v. calc 0x%x",
			    c->c_num, crc_actual, crc_calculated);
			queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);
			if (ahs != NULL)
				free(ahs);
			return (False);
		}
	}

	if (c->c_sess->s_type == SessionDiscovery) {
		switch (h.opcode & ISCSI_OPCODE_MASK) {
		default:
			/*
			 * Need to handle the error case here.
			 */
			(void) snprintf(debug, sizeof (debug),
			    "CON%x  Wrong opcode for Discovery, %d",
			    c->c_num, h.opcode & ISCSI_OPCODE_MASK);
			queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);
			rval = False;
			break;

		case ISCSI_OP_LOGOUT_CMD:
			/*
			 * This will transition from S5_LOGGED_IN
			 * to S6_IN_LOGOUT to S1_FREE;
			 */
			rval = handle_logout_msg(c, &h, ahs, ahslen);
			break;

		case ISCSI_OP_TEXT_CMD:
			rval = handle_text_msg(c, &h, ahs, ahslen);
			break;
		}
	} else {
		iscsi_cmd_remove(c, ntohl(h.expstatsn));
		switch (h.opcode & ISCSI_OPCODE_MASK) {
		case ISCSI_OP_NOOP_OUT:
			rval = handle_noop_cmd(c, &h, ahs, ahslen);
			break;

		case ISCSI_OP_SCSI_CMD:
			rval = handle_scsi_cmd(c, &h, ahs, ahslen);
			break;

		case ISCSI_OP_SCSI_TASK_MGT_MSG:
			rval = handle_task_mgt(c, &h, ahs, ahslen);
			break;

		case ISCSI_OP_LOGIN_CMD:
			/*
			 * This is an illegal state transition. Should
			 * we drop the connection?
			 */
			break;

		case ISCSI_OP_TEXT_CMD:
			rval = handle_text_msg(c, &h, ahs, ahslen);
			break;

		case ISCSI_OP_SCSI_DATA:
			rval = handle_scsi_data(c, &h, ahs, ahslen);
			break;

		case ISCSI_OP_LOGOUT_CMD:
			/*
			 * This will transition from S5_LOGGED_IN
			 * to S6_IN_LOGOUT.
			 */
			rval = handle_logout_msg(c, &h, ahs, ahslen);
			break;

		case ISCSI_OP_SNACK_CMD:
		default:
			(void) snprintf(debug, sizeof (debug),
			    "CON%x  Opcode: %d not handled",
			    c->c_num, h.opcode & ISCSI_OPCODE_MASK);
			queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);
			conn_state(c, T8);
			rval = True;
			break;
		}
	}

	if (ahs != NULL)
		free(ahs);
	return (rval);
}

/*ARGSUSED*/
static Boolean_t
handle_task_mgt(iscsi_conn_t *c, iscsi_hdr_t *p, char *ahs, int ahslen)
{
	iscsi_scsi_task_mgt_hdr_t	*hp = (iscsi_scsi_task_mgt_hdr_t *)p;
	iscsi_scsi_task_mgt_rsp_hdr_t	*rsp;
	iscsi_cmd_t			*cmd;
	uint32_t			lun;
	Boolean_t			lu_reset	= False;

	if (spc_decode_lu_addr(&hp->lun[0], 8, &lun) == False)
		return (False);

	if (ISCSI_TASK_COMMAND_ENABLED()) {
		uiscsiproto_t info;

		info.uip_target_addr = &c->c_target_sockaddr;
		info.uip_initiator_addr = &c->c_initiator_sockaddr;

		info.uip_target = c->c_sess->s_t_name;
		info.uip_initiator = c->c_sess->s_i_name;
		info.uip_lun = lun;

		info.uip_itt = hp->itt;
		info.uip_ttt = hp->itt;

		info.uip_cmdsn = ntohl(hp->cmdsn);
		info.uip_statsn = ntohl(hp->expstatsn);
		info.uip_datasn = ntohl(hp->expdatasn);

		info.uip_datalen = ntoh24(hp->dlength);
		info.uip_flags = 0;

		ISCSI_TASK_COMMAND(&info);
	}

	if ((rsp = calloc(1, sizeof (*rsp))) == NULL)
		return (False);

	rsp->opcode	= ISCSI_OP_SCSI_TASK_MGT_RSP;
	rsp->flags	= ISCSI_FLAG_FINAL;
	rsp->itt	= hp->itt;

	(void) pthread_mutex_lock(&c->c_mutex);
	rsp->statsn	= htonl(c->c_statsn++);
	(void) pthread_mutex_unlock(&c->c_mutex);

	(void) pthread_mutex_lock(&c->c_sess->s_mutex);
	if (ntohl(hp->cmdsn) > c->c_sess->s_seencmdsn)
		c->c_sess->s_seencmdsn = ntohl(hp->cmdsn);
	(void) pthread_mutex_unlock(&c->c_sess->s_mutex);

	queue_prt(c->c_mgmtq, Q_CONN_NONIO,
	    "CON%x  PDU(Task Mgt): %s, cmdsn 0x%x\n",
	    c->c_num,
	    task_to_str(hp->function & ISCSI_FLAG_TASK_MGMT_FUNCTION_MASK),
	    ntohl(hp->cmdsn));

	switch (hp->function & ISCSI_FLAG_TASK_MGMT_FUNCTION_MASK) {
	case ISCSI_TM_FUNC_ABORT_TASK:
		queue_prt(c->c_mgmtq, Q_CONN_NONIO,
		    "CON%x  Abort ITT 0x%x\n", c->c_num, hp->rtt);
		if ((cmd = iscsi_cmd_find(c, hp->rtt, FindITT)) == NULL) {
			queue_prt(c->c_mgmtq, Q_CONN_ERRS,
			    "CON%x  Invalid AbortTask rtt 0x%x\n",
			    c->c_num, hp->rtt);
			rsp->response = SCSI_TCP_TM_RESP_NO_TASK;
		} else {
			(void) pthread_mutex_lock(&c->c_mutex);
			iscsi_cmd_cancel(c, cmd);
			(void) pthread_mutex_unlock(&c->c_mutex);
			rsp->response = SCSI_TCP_TM_RESP_COMPLETE;
		}
		break;

	case ISCSI_TM_FUNC_ABORT_TASK_SET:
		/* ---- This is actually "Function not support" ---- */
		rsp->response = SCSI_TCP_TM_RESP_IN_PRGRESS;
		break;

	case ISCSI_TM_FUNC_CLEAR_ACA:
		/* ---- This is actually "Function not support" ---- */
		rsp->response = SCSI_TCP_TM_RESP_IN_PRGRESS;
		break;

	case ISCSI_TM_FUNC_CLEAR_TASK_SET:
		/* ---- This is actually "Function not support" ---- */
		rsp->response = SCSI_TCP_TM_RESP_IN_PRGRESS;
		break;

	case ISCSI_TM_FUNC_LOGICAL_UNIT_RESET:
		lu_reset	= True;
	/*FALLTHRU*/
	case ISCSI_TM_FUNC_TARGET_WARM_RESET:
		(void) pthread_mutex_lock(&c->c_mutex);
		for (cmd = c->c_cmd_head; cmd; cmd = cmd->c_next) {
			if (((hp->function &
			    ISCSI_FLAG_TASK_MGMT_FUNCTION_MASK) ==
			    ISCSI_TM_FUNC_TARGET_WARM_RESET) ||
			    (lun == cmd->c_lun)) {
				iscsi_cmd_cancel(c, cmd);

			}
		}
		(void) pthread_mutex_unlock(&c->c_mutex);

		if (lu_reset == True)
			queue_message_set(c->c_sessq, 0, msg_reset_lu,
			    (void *)(uintptr_t)lun);
		else
			queue_message_set(c->c_sessq, 0, msg_reset_targ, 0);
		rsp->response = SCSI_TCP_TM_RESP_COMPLETE;
		break;

	case ISCSI_TM_FUNC_TARGET_COLD_RESET:
		/*
		 * According to the specification a cold reset should
		 * close *all* connections on the target, not just those
		 * for this current session.
		 */
		queue_message_set(c->c_sessq, 0, msg_reset_targ, (void *)1);
		conn_state(c, T8);
		break;

	case ISCSI_TM_FUNC_TASK_REASSIGN:
	default:
		/* ---- This is actually "Function not support" ---- */
		rsp->response = SCSI_TCP_TM_RESP_IN_PRGRESS;
		break;
	}

	(void) pthread_mutex_lock(&c->c_state_mutex);
	if (c->c_state == S5_LOGGED_IN)
		queue_message_set(c->c_dataq,
		    hp->opcode & ISCSI_OP_IMMEDIATE ? Q_HIGH : 0,
		    msg_send_pkt, rsp);
	(void) pthread_mutex_unlock(&c->c_state_mutex);
	return (True);
}

/*ARGSUSED*/
static Boolean_t
handle_noop_cmd(iscsi_conn_t *c, iscsi_hdr_t *p, char *ahs, int ahslen)
{
	iscsi_nop_out_hdr_t	*hp = (iscsi_nop_out_hdr_t *)p;
	iscsi_nop_in_hdr_t	*in;

	if (ISCSI_NOP_RECEIVE_ENABLED()) {
		uiscsiproto_t info;

		info.uip_target_addr = &c->c_target_sockaddr;
		info.uip_initiator_addr = &c->c_initiator_sockaddr;

		info.uip_target = c->c_sess->s_t_name;
		info.uip_initiator = c->c_sess->s_i_name;
		info.uip_lun = 0;

		info.uip_itt = hp->itt;
		info.uip_ttt = hp->ttt;

		info.uip_cmdsn = ntohl(hp->cmdsn);
		info.uip_statsn = ntohl(hp->expstatsn);
		info.uip_datasn = 0;

		info.uip_datalen = ntoh24(hp->dlength);
		info.uip_flags = hp->flags;

		ISCSI_NOP_RECEIVE(&info);
	}

	/*
	 * Just an answer to our ping
	 */
	if (hp->ttt != ISCSI_RSVD_TASK_TAG)
		return (True);

	if ((in = calloc(1, sizeof (*in))) == NULL) {
		queue_prt(c->c_mgmtq, Q_CONN_ERRS,
		    "CON%x  NopIn -- failed to malloc space for header",
		    c->c_num);
		return (False);
	}

	in->opcode = ISCSI_OP_NOOP_IN;
	in->flags = ISCSI_FLAG_FINAL;
	/*
	 * Need to handle possible data associated with NOP-Out
	 */
	bcopy(hp->lun, in->lun, 8);
	in->itt		= hp->itt;
	in->ttt		= ISCSI_RSVD_TASK_TAG;
	(void) pthread_mutex_lock(&c->c_sess->s_mutex);
	if (ntohl(hp->cmdsn) > c->c_sess->s_seencmdsn)
		c->c_sess->s_seencmdsn = ntohl(hp->cmdsn);
	(void) pthread_mutex_unlock(&c->c_sess->s_mutex);

	(void) pthread_mutex_lock(&c->c_state_mutex);
	if (c->c_state == S5_LOGGED_IN)
		queue_message_set(c->c_dataq,
		    hp->opcode & ISCSI_OP_IMMEDIATE ? Q_HIGH : 0,
		    msg_send_pkt, in);
	(void) pthread_mutex_unlock(&c->c_state_mutex);
	return (True);
}

/*ARGSUSED*/
static Boolean_t
handle_scsi_data(iscsi_conn_t *c, iscsi_hdr_t *p, char *ahs, int ahslen)
{
	iscsi_data_hdr_t	*hp = (iscsi_data_hdr_t *)p;
	int			dlen = ntoh24(hp->dlength);
	iscsi_cmd_t		*cmd;

	if (ISCSI_DATA_RECEIVE_ENABLED()) {
		uiscsiproto_t info;

		info.uip_target_addr = &c->c_target_sockaddr;
		info.uip_initiator_addr = &c->c_initiator_sockaddr;

		info.uip_target = c->c_sess->s_t_name;
		info.uip_initiator = c->c_sess->s_i_name;
		info.uip_lun = 0;

		info.uip_itt = hp->itt;
		info.uip_ttt = hp->itt;

		info.uip_cmdsn = 0;
		info.uip_statsn = ntohl(hp->expstatsn);
		info.uip_datasn = ntohl(hp->datasn);

		info.uip_datalen = dlen;
		info.uip_flags = hp->flags;

		ISCSI_DATA_RECEIVE(&info);
	}

	if ((cmd = iscsi_cmd_find(c, hp->ttt, FindTTT)) == NULL) {
		queue_prt(c->c_mgmtq, Q_CONN_ERRS,
		    "CON%x  failed to find ttt 0x%x\n", c->c_num, hp->ttt);
		/*
		 * Need to handle error case.
		 */
		return (False);
	}
	cmd->c_opcode = hp->opcode & ISCSI_OPCODE_MASK;

	/*
	 * assert(cmd->c_lun == hp->lun[1]);
	 * Previously this check was done, but is caused a problem with
	 * the RedHat initiator. There was a discussion on the IPS alias
	 * around this very topic. Even though section 10.7.4 states:
	 *    "If the Target Transfer Tag is provided, then the LUN field
	 *    MUST hold a valid value and be consistent with whatever was
	 *    specified with the command; otherwise, the LUN field is
	 *    reserved."
	 * Everyone agreed though that for a DataOut command the LUN field
	 * wasn't required to be valid because the TTT gives the Target
	 * enough information to complete the command.
	 */
	assert(cmd->c_allegiance == c);
	assert(cmd->c_itt == hp->itt);

	cmd->c_offset_out	= ntohl(hp->offset);
	cmd->c_data_len		= dlen;
	(void) pthread_mutex_lock(&c->c_mutex);
	(void) pthread_mutex_lock(&c->c_state_mutex);
	if (c->c_state == S5_LOGGED_IN) {
		if (cmd->c_state != CmdCanceled) {
			t10_cmd_shoot_event(cmd->c_t10_cmd, T10_Cmd_T4);
		}
	}
	(void) pthread_mutex_unlock(&c->c_state_mutex);
	(void) pthread_mutex_unlock(&c->c_mutex);

#ifdef FULL_DEBUG
	queue_prt(c->c_mgmtq, Q_CONN_IO,
	    "CON%x  PDU(DataOut) TTT 0x%x, offset=0x%x, len=0x%x\n",
	    c->c_num, cmd->c_ttt, cmd->c_t10_cmd->c_offset, dlen);
#endif

	return (dataout_delayed(cmd, msg_cmd_data_out));
}

static Boolean_t
handle_scsi_cmd(iscsi_conn_t *c, iscsi_hdr_t *p, char *ahs, int ahslen)
{
	iscsi_scsi_cmd_hdr_t	*hp	= (iscsi_scsi_cmd_hdr_t *)p;
	int			dlen	= ntoh24(hp->dlength);
	iscsi_cmd_t		*cmd;

	(void) pthread_mutex_lock(&c->c_sess->s_mutex);
	if (ntohl(hp->cmdsn) > c->c_sess->s_seencmdsn)
		c->c_sess->s_seencmdsn = ntohl(hp->cmdsn);
	(void) pthread_mutex_unlock(&c->c_sess->s_mutex);

	if ((cmd = iscsi_cmd_alloc(c, hp->opcode & ISCSI_OPCODE_MASK)) == NULL)
		return (False);

	bcopy(hp->scb, cmd->c_scb_default, sizeof (cmd->c_scb_default));
	cmd->c_scb	= cmd->c_scb_default;
	cmd->c_scb_len	= sizeof (cmd->c_scb_default);
	cmd->c_data_len	= dlen;

	if (ahslen) {

		/*
		 * Additional Header Section ----
		 *
		 * For Object Storage Devices the SCB is quite large. On
		 * the order of 140 bytes which means the data must be
		 * found in the AHS.
		 */
		uint16_t	hslen;
		uint16_t	next_seg;
		uint8_t		hstyp;

		do {
			/*
			 * Find this header segment's length and type
			 */
			bcopy(ahs, &hslen, sizeof (hslen));
			hslen = ntohs(hslen);
			hstyp = ahs[2];

			switch (hstyp) {
			/* ---- Extended CDB ---- */
			case 1:
				/*
				 * The hslen accounts for the reserved
				 * data byte in the segment. So the first
				 * sixteen bytes are in hp->scb with the
				 * remainder here. By only adding 15 bytes
				 * we allocate the correct amount of space
				 */
				cmd->c_scb_extended = malloc(hslen + 15);
				cmd->c_scb_len = hslen + 15;
				if (cmd->c_scb_extended == NULL)
					return (False);

				/*
				 * First 16 bytes of extended SCB are
				 * found in the normal location.
				 */
				bcopy(hp->scb, cmd->c_scb_extended, 16);
				bcopy(&ahs[4], &cmd->c_scb_extended[16],
				    hslen - 16);
				cmd->c_scb = cmd->c_scb_extended;
				break;

			/* ---- Expected bidirectional read data len ---- */
			case 2:
				/*
				 * We shouldn't need this since we're
				 * not prealloc'ing resources. If that should
				 * change or the need for error checking
				 * here's the spot to locate the data.
				 */
				break;
			}

			/*
			 * hslen contains the effective length in bytes of
			 * segment, excluding type and length (not including
			 * padding). Each segment is padded to a 4 byte
			 * boundary.
			 */
			next_seg = ((hslen + sizeof (hslen) +
			    sizeof (hstyp) + 3) & ~3);
			ahs += next_seg;
			ahslen -= next_seg;

		} while (ahslen);
	}

	/*
	 * XXX Need to handle error case better.
	 */
	if (spc_decode_lu_addr(&hp->lun[0], sizeof (hp->lun), &cmd->c_lun) ==
	    False) {
		return (False);
	}

	if (ISCSI_SCSI_COMMAND_ENABLED()) {
		uiscsiproto_t info;
		uiscsicmd_t uc;

		info.uip_target_addr = &c->c_target_sockaddr;
		info.uip_initiator_addr = &c->c_initiator_sockaddr;

		info.uip_target = c->c_sess->s_t_name;
		info.uip_initiator = c->c_sess->s_i_name;
		info.uip_lun = cmd->c_lun;

		info.uip_itt = hp->itt;
		info.uip_ttt = ISCSI_RSVD_TASK_TAG;

		info.uip_cmdsn = ntohl(hp->cmdsn);
		info.uip_statsn = ntohl(hp->expstatsn);
		info.uip_datasn = 0;

		info.uip_datalen = dlen;
		info.uip_flags = hp->flags;

		uc.uic_len = cmd->c_scb_len;
		uc.uic_cdb = cmd->c_scb;

		ISCSI_SCSI_COMMAND(&info, &uc);
	}

	cmd->c_itt		= hp->itt;
	cmd->c_cmdsn		= ntohl(hp->cmdsn);
	cmd->c_dlen_expected	= ntohl(hp->data_length);
	cmd->c_writeop		= hp->flags & ISCSI_FLAG_CMD_WRITE ?
	    True : False;

#ifdef FULL_DEBUG
	queue_prt(c->c_mgmtq, Q_CONN_IO,
	    "CON%x  PDU(SCSI Cmd, TA=%d) CmdSN 0x%x ITT 0x%x TTT 0x%x "
	    "LUN[%02x] id=%p\n", c->c_num,
	    hp->flags & ISCSI_FLAG_CMD_ATTR_MASK, cmd->c_cmdsn, cmd->c_itt,
	    cmd->c_ttt, cmd->c_lun, cmd);
#endif

	if (dlen && (hp->flags & ISCSI_FLAG_CMD_WRITE)) {
		/*
		 * NOTE: This should only occur if ImmediateData==Yes.
		 * We can handle this even if the initiator violates
		 * the specification so no need to worry. Use the rule
		 * of "Be strict in what is sent, but lenient in what
		 * is accepted."
		 */
		return (dataout_delayed(cmd, msg_cmd_send));
	} else {
		(void) pthread_mutex_lock(&c->c_state_mutex);
		if (c->c_state == S5_LOGGED_IN)
			queue_message_set(c->c_sessq, 0,
			    msg_cmd_send, (void *)cmd);
		(void) pthread_mutex_unlock(&c->c_state_mutex);
		return (True);
	}
}

/*
 * []----
 * | handle_text_msg -- process incoming test parameters
 * |
 * | NOTE: Need to handle continuation packets sent by the initiator.
 * []----
 */
/*ARGSUSED*/
static Boolean_t
handle_text_msg(iscsi_conn_t *c, iscsi_hdr_t *p, char *ahs, int ahslen)
{
	iscsi_text_rsp_hdr_t	rsp;
	iscsi_text_hdr_t	*hp		= (iscsi_text_hdr_t *)p;
	char			*text		= NULL;
	int			text_length	= 0;
	Boolean_t		release_at_end	= False;
	int			dlen		= ntoh24(hp->dlength);

	if (ISCSI_TEXT_COMMAND_ENABLED()) {
		uiscsiproto_t info;
		char nil = '\0';

		info.uip_initiator = c->c_sess->s_i_name;
		info.uip_target_addr = &c->c_target_sockaddr;
		info.uip_initiator_addr = &c->c_initiator_sockaddr;

		info.uip_target = c->c_sess->s_t_name;
		info.uip_initiator = c->c_sess->s_i_name;
		info.uip_target = &nil;
		info.uip_lun = 0;

		info.uip_itt = hp->itt;
		info.uip_ttt = hp->ttt;

		info.uip_cmdsn = ntohl(hp->cmdsn);
		info.uip_statsn = ntohl(hp->expstatsn);
		info.uip_datasn = 0;

		info.uip_datalen = dlen;
		info.uip_flags = hp->flags;

		ISCSI_TEXT_COMMAND(&info);
	}

	bzero(&rsp, sizeof (rsp));
	rsp.opcode	= ISCSI_OP_TEXT_RSP;
	rsp.itt		= hp->itt;

	queue_prt(c->c_mgmtq, Q_CONN_NONIO, "CON%x  PDU(Text Message)\n",
	    c->c_num);

	/*
	 * Need to determine if this incoming text PDU is an initial message
	 * or a continuation.
	 */
	if (hp->ttt == ISCSI_RSVD_TASK_TAG) {

		/* ---- Initial text PDU, so parse the incoming data ---- */
		if (parse_text(c, dlen, &text, &text_length, NULL) == False) {
			queue_prt(c->c_mgmtq, Q_CONN_ERRS,
			    "Failed to parse Text\n");
			if (text) {
				/*
				 * It's possible that we started to create
				 * a response, but yet an error occurred.
				 * Release the partial text response if that
				 * occurred.
				 */
				free(text);
			}
			return (False);
		}

		/*
		 * 10.11.4 --
		 * When the target receives a Text Request with the Target
		 * Transfer Tag set to the reserved value of 0xffffffff, it
		 * resets its internal information (resets state) associated
		 * with the given Initiator Task Tag (restarts the negotiation).
		 */
		if (c->c_text_area != NULL)
			free(c->c_text_area);

		c->c_text_area = text;
		if (text_length > c->c_max_recv_data) {

			/*
			 * Too much data to send at once, break it up into
			 * multiple transfers.
			 */
			rsp.flags	= ISCSI_FLAG_TEXT_CONTINUE;
			rsp.ttt		= 1;
			c->c_text_len	= text_length;
			text_length	= c->c_max_recv_data;
			c->c_text_sent	= text_length;
		} else {
			rsp.flags	= ISCSI_FLAG_FINAL;
			rsp.ttt		= ISCSI_RSVD_TASK_TAG;
			release_at_end	= True;
		}
	} else {

		/* ---- Continuation of previous text request ---- */
		text_length	= c->c_text_len - c->c_text_sent;
		text		= c->c_text_area + c->c_text_sent;
		if (text_length > c->c_max_recv_data) {
			rsp.flags	= ISCSI_FLAG_TEXT_CONTINUE;
			rsp.ttt		= 1;
			text_length	= c->c_max_recv_data;
			c->c_text_sent	+= text_length;
		} else {
			rsp.flags	= ISCSI_FLAG_FINAL;
			rsp.ttt		= ISCSI_RSVD_TASK_TAG;
			release_at_end	= True;
		}
	}

	queue_prt(c->c_mgmtq, Q_CONN_NONIO,
	    "CON%x  Text PDU: flags=0x%02x, ttt=0x%08x, len=%d\n",
	    c->c_num, rsp.flags, rsp.ttt, text_length);

	hton24(rsp.dlength, text_length);
	(void) pthread_mutex_lock(&c->c_mutex);
	rsp.statsn	= htonl(c->c_statsn++);
	(void) pthread_mutex_lock(&c->c_sess->s_mutex);
	if (ntohl(hp->cmdsn) > c->c_sess->s_seencmdsn)
		c->c_sess->s_seencmdsn = ntohl(hp->cmdsn);
	rsp.maxcmdsn	= htonl(iscsi_cmd_window(c) + c->c_sess->s_seencmdsn);
	rsp.expcmdsn	= htonl(c->c_sess->s_seencmdsn + 1);
	(void) pthread_mutex_unlock(&c->c_sess->s_mutex);
	(void) pthread_mutex_unlock(&c->c_mutex);

	if (ISCSI_TEXT_RESPONSE_ENABLED()) {
		uiscsiproto_t info;
		char nil = '\0';

		info.uip_target_addr = &c->c_target_sockaddr;
		info.uip_initiator_addr = &c->c_initiator_sockaddr;

		info.uip_target = c->c_sess->s_t_name;
		info.uip_initiator = c->c_sess->s_i_name;
		info.uip_initiator = c->c_sess->s_i_name;
		info.uip_target = &nil;
		info.uip_lun = 0;

		info.uip_itt = rsp.itt;
		info.uip_ttt = rsp.ttt;

		info.uip_cmdsn = ntohl(rsp.expcmdsn);
		info.uip_statsn = ntohl(rsp.statsn);
		info.uip_datasn = 0;

		info.uip_datalen = text_length;
		info.uip_flags = rsp.flags;

		ISCSI_TEXT_RESPONSE(&info);
	}

	send_iscsi_pkt(c, (iscsi_hdr_t *)&rsp, text);

	if (release_at_end == True) {
		free(c->c_text_area);
		c->c_text_area = NULL;
	}
	return (True);
}

/*ARGSUSED*/
static Boolean_t
handle_logout_msg(iscsi_conn_t *c, iscsi_hdr_t *p, char *ahs, int ahslen)
{
	iscsi_logout_rsp_hdr_t	*rsp;
	iscsi_logout_hdr_t	*hp = (iscsi_logout_hdr_t *)p;
	char			debug[80];

	if (ISCSI_LOGOUT_COMMAND_ENABLED()) {
		uiscsiproto_t info;
		char nil = '\0';

		info.uip_target_addr = &c->c_target_sockaddr;
		info.uip_initiator_addr = &c->c_initiator_sockaddr;

		info.uip_target = c->c_sess->s_t_name;
		info.uip_initiator = c->c_sess->s_i_name;
		info.uip_initiator = c->c_sess->s_i_name;
		info.uip_target = &nil;
		info.uip_lun = 0;

		info.uip_itt = hp->itt;
		info.uip_ttt = ISCSI_RSVD_TASK_TAG;

		info.uip_cmdsn = ntohl(hp->cmdsn);
		info.uip_statsn = ntohl(hp->expstatsn);
		info.uip_datasn = 0;

		info.uip_datalen = ntoh24(hp->dlength);
		info.uip_flags = hp->flags;

		ISCSI_LOGOUT_COMMAND(&info);
	}

	if ((rsp = calloc(1, sizeof (*rsp))) == NULL)
		return (False);

	(void) snprintf(debug, sizeof (debug),
	    "CON%x  PDU(Logout Request)", c->c_num);
	queue_str(c->c_mgmtq, Q_CONN_NONIO, msg_log, debug);

	(void) pthread_mutex_lock(&c->c_mutex);
	(void) pthread_mutex_lock(&c->c_sess->s_mutex);
	if (hp->cmdsn > c->c_sess->s_seencmdsn)
		c->c_sess->s_seencmdsn = htonl(hp->cmdsn);
	rsp->expcmdsn = htonl(c->c_sess->s_seencmdsn + 1);
	rsp->maxcmdsn = htonl(iscsi_cmd_window(c) +
	    c->c_sess->s_seencmdsn);
	(void) pthread_mutex_unlock(&c->c_sess->s_mutex);
	(void) pthread_mutex_unlock(&c->c_mutex);

	rsp->opcode	= ISCSI_OP_LOGOUT_RSP;
	rsp->flags	= ISCSI_FLAG_FINAL;
	rsp->itt	= hp->itt;
	(void) pthread_mutex_lock(&c->c_mutex);
	rsp->statsn	= htonl(c->c_statsn++);
	(void) pthread_mutex_unlock(&c->c_mutex);

	c->c_last_pkg	= (iscsi_hdr_t *)rsp;

	/*
	 * Call the state transition last. This will send out
	 * an asynchronous message to shutdown the session and STE.
	 * Once that's complete a shutdown reply will be sent to
	 * the transmit connection thread. That will cause another
	 * transition to T13 which expects to send out this logout
	 * response.
	 */
	if (c->c_state == S7_LOGOUT_REQUESTED)
		conn_state(c, T10);
	else
		conn_state(c, T9);

	return (True);
}

/*
 * dataout_delayed -- possibly copy data from initiator
 *
 * If DataDigests are enabled copy the data from the socket into a buffer
 * and perform the CRC check now.
 *
 * If MaxConnections==1 don't copy the data now and wait until the STE is
 * ready to copy the data directly from the socket to it's final location.
 * This is extremely beneficial when using mmap'd data.
 * NOTE:
 *    (1) For this to work we must not use the queues and instead
 *        call the STE functions directly. If the queues are used
 *        this routine must pause until STE processes the data to
 *        prevent this thread from attempting to read data from
 *        the socket as if it's the next PDU header.
 *    (2) Currently we don't call STE directly. To prevent a performance
 *        issue we'll have the code in place to support calling
 *        STE directly, but any time MaxConnections is greater than 0
 *        we'll copy the buffer. This will be removed at some future
 *        point.
 */
static Boolean_t
dataout_delayed(iscsi_cmd_t *cmd, msg_type_t type)
{
	iscsi_conn_t	*c	= cmd->c_allegiance;
	int		dlen	= cmd->c_data_len;
	int		cc;
	uint32_t	crc_calc;
	uint32_t	crc_actual;
	char		pad_buf[ISCSI_PAD_WORD_LEN - 1];
	char		pad_len;
	char		debug[80];

	cmd->c_dataout_cb = dataout_callback;

	if (cmd->c_data == NULL) {
		if ((cmd->c_data = (char *)malloc(dlen)) == NULL) {
			(void) pthread_mutex_lock(&c->c_mutex);
			t10_cmd_shoot_event(cmd->c_t10_cmd, T10_Cmd_T5);
			iscsi_cmd_free(c, cmd);
			(void) pthread_mutex_unlock(&c->c_mutex);
			return (False);
		}
		cmd->c_data_alloc = True;
	}

	if ((cc = recv(c->c_fd, cmd->c_data, dlen, MSG_WAITALL)) != dlen) {
		if (errno == ECONNRESET) {
			queue_prt(c->c_mgmtq, Q_CONN_ERRS,
			    "CON%x  dataout_delayed -- "
			    "initiator reset socket\n", c->c_num);
		} else {
			queue_prt(c->c_mgmtq, Q_CONN_ERRS,
			    "CON%x  recv(got-%d, expect-%d), errno=%d\n",
			    c->c_num, cc, dlen, errno);
		}

		(void) pthread_mutex_lock(&c->c_mutex);
		t10_cmd_shoot_event(cmd->c_t10_cmd, T10_Cmd_T5);
		iscsi_cmd_free(c, cmd);
		(void) pthread_mutex_unlock(&c->c_mutex);
		conn_state(c, T8);
		return (True);
	}

	pad_len = ((ISCSI_PAD_WORD_LEN -
	    (dlen & (ISCSI_PAD_WORD_LEN - 1))) & (ISCSI_PAD_WORD_LEN - 1));

	if (pad_len) {
		if (recv(c->c_fd, pad_buf, pad_len, MSG_WAITALL) != pad_len) {
			if (errno == ECONNRESET) {
				queue_prt(c->c_mgmtq, Q_CONN_ERRS,
				    "CON%x  dataout_delayed -- "
				    "initiator reset socket\n", c->c_num);
			} else {
				queue_prt(c->c_mgmtq, Q_CONN_ERRS,
				    "CON%x Pad Word read errno=%d\n", c->c_num,
				    errno);
			}

			(void) pthread_mutex_lock(&c->c_mutex);
			t10_cmd_shoot_event(cmd->c_t10_cmd, T10_Cmd_T5);
			iscsi_cmd_free(c, cmd);
			(void) pthread_mutex_unlock(&c->c_mutex);
			conn_state(c, T8);
			return (True);
		}
	}

	if (c->c_data_digest == True) {
		if (recv(c->c_fd, (char *)&crc_actual, sizeof (crc_actual),
		    MSG_WAITALL) != sizeof (crc_actual)) {
			if (errno == ECONNRESET) {
				queue_prt(c->c_mgmtq, Q_CONN_ERRS,
				    "CON%x  dataout_delayed -- "
				    "initiator reset socket\n", c->c_num);
			} else {
				queue_prt(c->c_mgmtq, Q_CONN_ERRS,
				    "CON%x  CRC32 read errno=%d\n", c->c_num,
				    errno);
			}

			(void) pthread_mutex_lock(&c->c_mutex);
			t10_cmd_shoot_event(cmd->c_t10_cmd, T10_Cmd_T5);
			iscsi_cmd_free(c, cmd);
			(void) pthread_mutex_unlock(&c->c_mutex);
			conn_state(c, T8);
			return (True);
		}
		crc_calc = iscsi_crc32c((void *)cmd->c_data, dlen);
		if (crc_calc != crc_actual) {

			(void) snprintf(debug, sizeof (debug),
			    "CON%x  CRC Error: actual %x vs. calc 0x%x",
			    c->c_num, crc_actual, crc_calc);

			/*
			 * NOTE: Need to think about this one some more.
			 * Just because we get a data error doesn't mean
			 * we should drop the connection. Look at the
			 * spec and determine what's the appropriate
			 * error recovery for this issue.
			 */
			(void) pthread_mutex_lock(&c->c_mutex);
			t10_cmd_shoot_event(cmd->c_t10_cmd, T10_Cmd_T5);
			iscsi_cmd_free(c, cmd);
			(void) pthread_mutex_unlock(&c->c_mutex);
			conn_state(c, T8);
			return (True);
		}
	}

	/*
	 * We'll update the offset with the amount of data that
	 * has been received. During a SCSI response PDU this value
	 * will be used to determine if there's an overrun condition.
	 */
	cmd->c_offset_out += dlen;

	(void) pthread_mutex_lock(&c->c_mutex);
	(void) pthread_mutex_lock(&c->c_state_mutex);
	if (c->c_state == S5_LOGGED_IN) {
		if ((cmd->c_state == CmdCanceled) &&
		    (type == msg_cmd_data_out))
			t10_cmd_shoot_event(cmd->c_t10_cmd, T10_Cmd_T5);
		else
			queue_message_set(c->c_sessq, 0, type, (void *)cmd);
	} else if (cmd->c_state == CmdCanceled) {
		t10_cmd_shoot_event(cmd->c_t10_cmd, T10_Cmd_T5);
	}
	(void) pthread_mutex_unlock(&c->c_state_mutex);
	(void) pthread_mutex_unlock(&c->c_mutex);

	/*
	 * The else case here is if we're calling STE directly and the data
	 * will be read from the socket when STE is ready for it.
	 */

	return (True);
}

/*
 * []----
 * | dataout_callback -- copy data from socket to emulation buffer
 * []----
 */
void
dataout_callback(t10_cmd_t *t, char *data, size_t *xfer)
{
	iscsi_cmd_t	*cmd	= (iscsi_cmd_t *)T10_TRANS_ID(t);
	iscsi_conn_t	*c	= cmd->c_allegiance;
	int		dlen	= cmd->c_data_len;
	int		cc;
	char		pad_buf[ISCSI_PAD_WORD_LEN - 1];
	char		pad_len = 0;

	pad_len = ((ISCSI_PAD_WORD_LEN -
	    (dlen & (ISCSI_PAD_WORD_LEN - 1))) &
	    (ISCSI_PAD_WORD_LEN - 1));


	if (T10_DATA(t) != NULL) {
		assert(T10_DATA(t) == cmd->c_data);
		assert(cmd->c_data_alloc == True);
		free(T10_DATA(t));
		T10_DATA(t)		= NULL;
		cmd->c_data		= NULL;
		cmd->c_data_alloc	= False;
		return;
	}

	if ((cc = recv(c->c_fd, data, dlen, MSG_WAITALL)) != dlen) {
		if (errno == ECONNRESET) {
			queue_prt(c->c_mgmtq, Q_CONN_ERRS,
			    "CON%x  data_callback -- initiator reset socket\n",
			    c->c_num);
		} else {
			queue_prt(c->c_mgmtq, Q_CONN_ERRS,
			    "CON%x  recv(got-%d, expect-%d) errno=%d",
			    c->c_num, cc, dlen, errno);
		}

		conn_state(c, T8);
		goto finish;
	}

	if (pad_len) {
		if (recv(c->c_fd, pad_buf, pad_len, MSG_WAITALL) != pad_len) {
			if (errno == ECONNRESET) {
				queue_prt(c->c_mgmtq, Q_CONN_ERRS,
				    "CON%x  data_callback -- "
				    "initiator reset socket\n", c->c_num);
			} else {
				queue_prt(c->c_mgmtq, Q_CONN_ERRS,
				    "CON%x data_callback -- "
				    "pad read errno=%d\n", c->c_num, errno);
			}
			conn_state(c, T8);
			goto finish;
		}
	}

finish:
	*xfer = cc;
	/* ---- Send msg that receive side of the connection can go ---- */
	(void) sema_post(&c->c_datain);
}
