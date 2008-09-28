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

#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>

#include <iscsitgt_impl.h>
#include "iscsi_conn.h"
#include "iscsi_sess.h"
#include "t10.h"
#include "utility.h"
#include "target.h"

pthread_mutex_t	sess_mutex;
/*
 * This value is used as the TSIH which must be non-zero.
 */
int		sess_num	= 1;
iscsi_sess_t	*sess_head;

static void session_free(struct iscsi_sess *s);
static void sess_set_auth(iscsi_sess_t *isp);
static void *sess_from_t10(void *v);
static void *sess_process(void *v);

/*
 * []----
 * | session_init -- initialize global variables and mutexs
 * []----
 */
void
session_init()
{
	(void) pthread_mutex_init(&sess_mutex, NULL);
}

/*
 * []----
 * | session_alloc -- create a new session attached to the lead connection
 * []----
 */
Boolean_t
session_alloc(iscsi_conn_t *c, uint8_t *isid)
{
	iscsi_sess_t	*s, *n;

	if (c->c_sess != NULL)
		return (True);

	s = (iscsi_sess_t *)calloc(sizeof (iscsi_sess_t), 1);
	if (s == NULL)
		return (False);

	bcopy(isid, s->s_isid, 6);

	(void) pthread_mutex_init(&s->s_mutex, NULL);
	c->c_sess	= s;
	s->s_conn_head	= c;
	s->s_sessq	= queue_alloc();
	s->s_t10q	= queue_alloc();
	c->c_sessq	= s->s_sessq;
	s->s_mgmtq	= c->c_mgmtq;
	s->s_type	= SessionNormal;

	sess_set_auth(s);

	(void) pthread_mutex_lock(&sess_mutex);
	s->s_num	= sess_num++;
	s->s_tsid	= s->s_num;
	s->s_state	= SS_STARTED;

	if (sess_head == NULL)
		sess_head = s;
	else {
		for (n = sess_head; n->s_next; n = n->s_next)
			;
		n->s_next = s;
	}
	(void) pthread_mutex_unlock(&sess_mutex);

	(void) pthread_create(&s->s_thr_id_t10, NULL, sess_from_t10, s);
	(void) pthread_create(&s->s_thr_id_conn, NULL, sess_process, s);

	util_title(s->s_mgmtq, Q_SESS_LOGIN, s->s_num, "Start Session");

	return (True);
}

/*
 * []----
 * | session_free -- remove connection from session
 * []----
 */
static void
session_free(iscsi_sess_t *s)
{
	iscsi_sess_t	*n;

	/*
	 * Early errors in connection setup can still call this routine
	 * which means the session hasn't been called.
	 */
	if (s == NULL)
		return;

	(void) pthread_mutex_lock(&sess_mutex);
	if (s->s_i_name)
		free(s->s_i_name);
	if (s->s_t_name)
		free(s->s_t_name);
	if (s->s_i_alias)
		free(s->s_i_alias);

	if (sess_head == s)
		sess_head = s->s_next;
	else {
		for (n = sess_head; n; n = n->s_next) {
			if (n->s_next == s) {
				n->s_next = s->s_next;
				break;
			}
		}
		if (n == NULL) {
			queue_prt(s->s_mgmtq, Q_SESS_ERRS,
			    "SES%x  NOT IN SESSION LIST!\n", s->s_num);
		}
	}
	(void) pthread_mutex_unlock(&sess_mutex);
}

/*
 * []----
 * | session_remove_connection -- removes conn from sess list
 * |
 * | Returns True if this was the last connection which is always the case
 * | for now. In the future with multiple connections per session it'll be
 * | different.
 * []----
 */
/*ARGSUSED*/
static Boolean_t
session_remove_connection(iscsi_sess_t *s, iscsi_conn_t *c)
{
	bzero(s->s_isid, 6);
	return (True);
}

/*
 * []----
 * | convert_i_local -- Return a local name for the initiator if avilable.
 * |
 * | NOTE: If this routine returns true, it's the callers responsibility
 * | to free the memory.
 * []----
 */
Boolean_t
convert_i_local(char *ip, char **rtn)
{
	tgt_node_t	*inode = NULL;
	char		*iname, *name;

	while ((inode = tgt_node_next_child(main_config, XML_ELEMENT_INIT,
	    inode)) != NULL) {
		if (tgt_find_value_str(inode, XML_ELEMENT_INAME, &iname) ==
		    False) {
			continue;
		}
		if (strcmp(iname, ip) == 0) {
			if (tgt_find_value_str(inode, XML_ELEMENT_INIT,
			    &name) == False) {
				free(iname);
				return (False);
			} else
				free(iname);
			*rtn = name;
			return (True);
		} else
			free(iname);
	}
	return (False);
}

/*
 * []----
 * | sess_from_t10 -- handle messages from the T10 layer
 * []----
 */
void *
sess_from_t10(void *v)
{
	iscsi_sess_t	*s	= (iscsi_sess_t *)v;
	msg_t		*m;
	Boolean_t	process	= True;
	t10_conn_shutdown_t t_c_s;
	Boolean_t	sent_wait_for_destroy = False;

	t_c_s.t10_to_conn_q = NULL;
	t_c_s.conn_to_t10_q = NULL;

	while (process == True) {
		m = queue_message_get(s->s_t10q);
		switch (m->msg_type) {
		case msg_cmd_data_rqst:
			queue_message_set(s->s_conn_head->c_dataq, 0,
			    msg_cmd_data_rqst, m->msg_data);
			break;

		case msg_cmd_data_in:
			queue_message_set(s->s_conn_head->c_dataq, 0,
			    msg_cmd_data_in, m->msg_data);
			break;

		case msg_cmd_cmplt:
			queue_message_set(s->s_conn_head->c_dataq, 0,
			    msg_cmd_cmplt, m->msg_data);
			break;

		case msg_shutdown_rsp:

			if (s->s_t10) {
				if (!sent_wait_for_destroy) {
					if (t_c_s.t10_to_conn_q == NULL) {
						t_c_s.t10_to_conn_q =
						    queue_alloc();
						if (t_c_s.t10_to_conn_q
						    == NULL) {
							queue_message_set(
							    s->s_t10q, 0,
							    msg_shutdown_rsp,
							    m->msg_data);
							break;
						}
					}
					if (t_c_s.conn_to_t10_q == NULL) {
						t_c_s.conn_to_t10_q =
						    queue_alloc();
						if (t_c_s.conn_to_t10_q ==
						    NULL) {
							queue_message_set(
							    s->s_t10q, 0,
							    msg_shutdown_rsp,
							    m->msg_data);
							break;
						}
					}
					queue_message_set(
					    s->s_conn_head->c_dataq, 0,
					    msg_wait_for_destroy,
					    (void *)&t_c_s);
					queue_message_free(queue_message_get(
					    t_c_s.conn_to_t10_q));
					sent_wait_for_destroy = True;
				}

				if (t10_handle_destroy(s->s_t10, False) != 0) {
					/*
					 * Destroy couldn't complete,
					 * put the message back on our
					 * own queue to be picked up
					 * later and tried again.
					 */
					queue_message_set(s->s_t10q, 0,
					    msg_shutdown_rsp,
					    m->msg_data);
					break;
				}
				s->s_t10 = NULL;
				queue_message_set(t_c_s.t10_to_conn_q,
				    0, 1, (void *)NULL);
				queue_message_free(queue_message_get(
				    t_c_s.conn_to_t10_q));
				queue_free(t_c_s.t10_to_conn_q, NULL);
				queue_free(t_c_s.conn_to_t10_q, NULL);
				sent_wait_for_destroy = False;
			}

			(void) pthread_mutex_lock(&s->s_mutex);
			s->s_state = SS_SHUTDOWN_CMPLT;
			(void) pthread_mutex_unlock(&s->s_mutex);

			session_free(s);

			/*
			 * Let the connection, which is the last, know
			 * about our completion of the shutdown.
			 */
			queue_message_set(s->s_conn_head->c_dataq, 0,
			    msg_shutdown_rsp, (void *)True);
			process		= False;
			s->s_state	= SS_FREE;
			break;

		default:
			queue_prt(s->s_mgmtq, Q_SESS_ERRS,
			    "SES%x  Unknown msg type (%d) from T10\n",
			    s->s_num, m->msg_type);
			queue_message_set(s->s_conn_head->c_dataq, 0,
			    m->msg_type, m->msg_data);
				break;
		}
		queue_message_free(m);
	}
	queue_message_set(s->s_mgmtq, 0, msg_pthread_join,
	    (void *)(uintptr_t)pthread_self());
	queue_free(s->s_t10q, NULL);
	util_title(s->s_mgmtq, Q_SESS_LOGIN, s->s_num, "End Session");
	free(s);
	return (NULL);
}

/*
 * []----
 * | sess_process -- handle messages from the connection(s)
 * []----
 */
static void *
sess_process(void *v)
{
	iscsi_sess_t	*s = (iscsi_sess_t *)v;
	iscsi_conn_t	*c;
	iscsi_cmd_t	*cmd;
	msg_t		*m;
	Boolean_t	process = True;
	mgmt_request_t	*mgmt;
	name_request_t	*nr;
	t10_cmd_t	*t10_cmd;
	char		**buf, local_buf[16];
	int		lun;
	extern void dataout_callback(t10_cmd_t *t, char *data, size_t *xfer);

	(void) pthread_mutex_lock(&s->s_mutex);
	s->s_state = SS_RUNNING;
	(void) pthread_mutex_unlock(&s->s_mutex);
	do {
		m = queue_message_get(s->s_sessq);
		switch (m->msg_type) {
		case msg_cmd_send:
			cmd = (iscsi_cmd_t *)m->msg_data;
			if (s->s_t10 == NULL) {

				/*
				 * The value of 0x960 comes from T10.
				 * See SPC-4, revision 1a, section 6.4.2,
				 * table 87
				 *
				 * XXX Need to rethink how I should do
				 * the callback.
				 */
				s->s_t10 = t10_handle_create(
				    s->s_t_name, s->s_i_name, T10_TRANS_ISCSI,
				    s->s_conn_head->c_tpgt,
				    s->s_conn_head->c_max_burst_len,
				    s->s_t10q, dataout_callback);
			}
			if (t10_cmd_create(s->s_t10, cmd->c_lun, cmd->c_scb,
			    cmd->c_scb_len, (transport_t)cmd,
			    &t10_cmd) == False) {

				/*
				 * If the command create failed, the T10 layer
				 * will attempt to create a sense buffer
				 * telling the initiator what went wrong. If
				 * that layer was unable to accomplish that
				 * things are really bad and we need to just
				 * close the connection.
				 */
				if (t10_cmd != NULL) {
					queue_message_set(
					    cmd->c_allegiance->c_dataq,
					    0, msg_cmd_cmplt, t10_cmd);
				} else {
					queue_prt(s->s_mgmtq, Q_SESS_ERRS,
					    "SES%x  FAILED to create cmd\n",
					    s->s_num);
					conn_state(cmd->c_allegiance, T11);
				}
			} else {
				(void) pthread_mutex_lock(
				    &cmd->c_allegiance->c_mutex);
				if (cmd->c_state != CmdCanceled) {
					cmd->c_t10_cmd = t10_cmd;
					(void) t10_cmd_send(s->s_t10,
					    cmd->c_t10_cmd, cmd->c_data,
					    cmd->c_data_len);
				} else {
					t10_cmd_shoot_event(t10_cmd,
					    T10_Cmd_T6);
				}
				(void) pthread_mutex_unlock(
				    &cmd->c_allegiance->c_mutex);
			}
			break;

		case msg_cmd_data_out:
			cmd = (iscsi_cmd_t *)m->msg_data;
			if (s->s_t10 != NULL)
				(void) t10_cmd_data(s->s_t10, cmd->c_t10_cmd,
				    cmd->c_offset_out, cmd->c_data,
				    cmd->c_data_len);
			break;

		case msg_targ_inventory_change:
			if (s->s_t10 != NULL)
				(void) t10_task_mgmt(s->s_t10, InventoryChange,
				    0, 0);
			break;

		case msg_lu_capacity_change:
			lun = (int)(uintptr_t)m->msg_data;
			if (s->s_t10 != NULL)
				(void) t10_task_mgmt(s->s_t10, CapacityChange,
				    lun, 0);
			break;

		case msg_reset_targ:
			if (s->s_t10 != NULL)
				(void) t10_task_mgmt(s->s_t10, ResetTarget,
				    0, 0);
			break;

		case msg_reset_lu:
			if (s->s_t10 != NULL)
				(void) t10_task_mgmt(s->s_t10, ResetLun,
				    (int)(uintptr_t)m->msg_data, 0);
			break;

		case msg_shutdown:
			(void) pthread_mutex_lock(&s->s_mutex);
			s->s_state = SS_SHUTDOWN_START;
			(void) pthread_mutex_unlock(&s->s_mutex);

			/*
			 * Shutdown rquest comming from a connection. Only
			 * shutdown the STE if this is the last connection
			 * for this session.
			 */
			c = (iscsi_conn_t *)m->msg_data;
			if (session_remove_connection(s, c) == True) {
				queue_prt(s->s_mgmtq, Q_SESS_NONIO,
				    "SES%x  Starting shutdown\n", s->s_num);

				/*
				 * If this is the last connection for this
				 * session send a message to the SAM-3 layer to
				 * shutdown.
				 */
				if (s->s_t10 != NULL) {
					t10_handle_disable(s->s_t10);
				}
				/*
				 * Do all work using the session pointer before
				 * sending the shutdown response msg. The
				 * session struct can get freed by the thread
				 * that picks up and handles the shutdown
				 * response.
				 */
				queue_message_set(s->s_mgmtq, 0,
				    msg_pthread_join,
				    (void *)(uintptr_t)pthread_self());
				queue_message_set(s->s_t10q, 0,
				    msg_shutdown_rsp, 0);
				process = False;
			} else {

				/*
				 * Since this isn't the last connection for
				 * the session, acknowledge the connection
				 * request now since it's references from
				 * this session have been removed.
				 */
				queue_message_set(c->c_dataq, 0,
				    msg_shutdown_rsp, (void *)False);
			}
			break;

		case msg_initiator_name:
			nr = (name_request_t *)m->msg_data;
			s->s_i_name = strdup(nr->nr_name);

			/*
			 * Acknowledge the request by sending back an empty
			 * message.
			 */
			queue_message_set(nr->nr_q, 0, msg_initiator_name, 0);
			break;

		case msg_initiator_alias:
			nr = (name_request_t *)m->msg_data;
			s->s_i_alias = strdup(nr->nr_name);

			/*
			 * Acknowledge the request by sending back an empty
			 * message.
			 */
			queue_message_set(nr->nr_q, 0, msg_initiator_alias, 0);
			break;

		case msg_target_name:
			nr = (name_request_t *)m->msg_data;
			s->s_t_name = strdup(nr->nr_name);

			/*
			 * Acknowledge the request by sending back an empty
			 * message.
			 */
			queue_message_set(nr->nr_q, 0, msg_target_name, 0);
			break;

		case msg_mgmt_rqst:
			mgmt		= (mgmt_request_t *)m->msg_data;
			m->msg_data	= NULL;

			(void) pthread_mutex_lock(&mgmt->m_resp_mutex);
			buf = mgmt->m_u.m_resp;

			if ((s->s_type == SessionNormal) &&
			    (mgmt->m_request == mgmt_full_phase_statistics) &&
			    (strcmp(s->s_t_name, mgmt->m_targ_name) == 0)) {

				tgt_buf_add_tag(buf, XML_ELEMENT_CONN,
				    Tag_Start);
				tgt_buf_add_tag(buf, s->s_i_name, Tag_String);
				if (s->s_i_alias != NULL) {
					tgt_buf_add(buf, XML_ELEMENT_ALIAS,
					    s->s_i_alias);
				}

				/*
				 * Need to loop through the connections
				 * and create one time_connected tag for
				 * each. This will be needed once MC/S support
				 * is added.
				 */
				(void) snprintf(local_buf, sizeof (local_buf),
				    "%d",
				    mgmt->m_time - s->s_conn_head->c_up_at);
				tgt_buf_add(buf, XML_ELEMENT_TIMECON,
				    local_buf);

				tgt_buf_add_tag(buf, XML_ELEMENT_STATS,
				    Tag_Start);

				t10_targ_stat(s->s_t10, buf);

				tgt_buf_add_tag(buf, XML_ELEMENT_STATS,
				    Tag_End);
				tgt_buf_add_tag(buf, XML_ELEMENT_CONN, Tag_End);
			}

			(void) pthread_mutex_unlock(&mgmt->m_resp_mutex);

			queue_message_set(mgmt->m_q, 0, msg_mgmt_rply, 0);

			break;

		default:
			queue_prt(s->s_mgmtq, Q_SESS_ERRS,
			    "SES%x  Unknown msg type (%d) from Connection\n",
			    s->s_num, m->msg_type);
			break;
		}
		queue_message_free(m);
	} while (process == True);

	queue_message_set(mgmtq, 0, msg_pthread_join,
	    (void *)(uintptr_t)pthread_self());
	return (NULL);
}

/*
 * []----
 * | session_validate -- do what the name says
 * |
 * | At this point the connection has processed the login command so that
 * | we have InitiatorName and ISID at a minimum. Check to see if there
 * | are other sessions which match. If so, log that one out and proceed with
 * | this session. If nothing matches, then link this into a global list.
 * |
 * | Once we support multiple connections per session need to scan list
 * | to see if other connection have the same CID. If so, log out that
 * | connection.
 * []----
 */
Boolean_t
session_validate(iscsi_sess_t *s)
{
	iscsi_sess_t	*check;

	queue_prt(s->s_mgmtq, Q_SESS_NONIO,
	    "SES%x  %s ISID[%02x%02x%02x%02x%02x%02x]\n",
	    s->s_num, s->s_i_alias == NULL ? s->s_i_name : s->s_i_alias,
	    s->s_isid[0], s->s_isid[1], s->s_isid[2],
	    s->s_isid[3], s->s_isid[4], s->s_isid[5]);


	/*
	 * SessionType=Discovery which means no target name and therefore
	 * this is okay.
	 */
	if (s->s_t_name == NULL)
		return (True);

	(void) pthread_mutex_lock(&sess_mutex);
	for (check = sess_head; check; check = check->s_next) {
		/*
		 * Ignore ourselves in this check.
		 */
		if (check == s)
			continue;
		if ((check->s_t_name == NULL) ||
		    (strcmp(check->s_t_name, s->s_t_name) != 0))
			continue;
		if (strcmp(check->s_i_name, s->s_i_name) != 0)
			continue;
		if (check->s_conn_head->c_tpgt != s->s_conn_head->c_tpgt)
			continue;
		/*
		 * Section 5.3.5
		 * Session reinstatement is the process of the initiator
		 * logging in with an ISID that is possible active from
		 * the target's perspective. Thus implicitly logging out
		 * the session that corresponds to the ISID and
		 * reinstating a new iSCSI session in its place (with the
		 * same ISID).
		 */
		if (bcmp(check->s_isid, s->s_isid, 6) == 0) {
			queue_prt(s->s_mgmtq, Q_SESS_NONIO,
			    "SES%x  Implicit shutdown\n", check->s_num);
			if (check->s_conn_head->c_state == S5_LOGGED_IN)
				conn_state(check->s_conn_head, T8);
			else
				conn_state(check->s_conn_head, T7);
			break;
		}
	}
	(void) pthread_mutex_unlock(&sess_mutex);

	return (True);
}

/*
 * []----
 * | static iscsi_sess_set_auth -
 * []----
 */
static void
sess_set_auth(iscsi_sess_t *isp)
{
	IscsiAuthClient		*auth_client	= NULL;
	tgt_node_t		*node		= NULL;

	if (isp == (iscsi_sess_t *)NULL)
		return;

	/* Zero out the session authentication structure */
	bzero(&isp->sess_auth, sizeof (iscsi_auth_t));
	isp->sess_auth.auth_enabled = B_TRUE;

	/* Load CHAP name */
	node = tgt_node_next_child(main_config, XML_ELEMENT_CHAPNAME, NULL);
	if (node != NULL && node->x_value != NULL) {
		(void) strcpy(isp->sess_auth.username, node->x_value);
	}

	/* Load CHAP secret */
	node = tgt_node_next_child(main_config, XML_ELEMENT_CHAPSECRET, NULL);
	if (node != NULL && node->x_value != NULL) {
		(void) strcpy((char *)isp->sess_auth.password, node->x_value);
		isp->sess_auth.password_length = strlen(node->x_value);
	}

	/*
	 * Set up authentication buffers always.   We don't know if
	 * initiator will request CHAP until later.
	 */
	isp->sess_auth.num_auth_buffers = 5;
	isp->sess_auth.auth_buffers[0].address =
	    &(isp->sess_auth.auth_client_block);
	isp->sess_auth.auth_buffers[0].length =
	    sizeof (isp->sess_auth.auth_client_block);
	isp->sess_auth.auth_buffers[1].address =
	    &(isp->sess_auth.auth_recv_string_block);
	isp->sess_auth.auth_buffers[1].length =
	    sizeof (isp->sess_auth.auth_recv_string_block);
	isp->sess_auth.auth_buffers[2].address =
	    &(isp->sess_auth.auth_send_string_block);
	isp->sess_auth.auth_buffers[2].length =
	    sizeof (isp->sess_auth.auth_send_string_block);
	isp->sess_auth.auth_buffers[3].address =
	    &(isp->sess_auth.auth_recv_binary_block);
	isp->sess_auth.auth_buffers[3].length =
	    sizeof (isp->sess_auth.auth_recv_binary_block);
	isp->sess_auth.auth_buffers[4].address =
	    &(isp->sess_auth.auth_send_binary_block);
	isp->sess_auth.auth_buffers[4].length =
	    sizeof (isp->sess_auth.auth_send_binary_block);

	if (isp->sess_auth.auth_buffers &&
	    isp->sess_auth.num_auth_buffers) {

		auth_client = (IscsiAuthClient *)isp->
		    sess_auth.auth_buffers[0].address;

		/*
		 * prepare for authentication
		 */
		if (iscsiAuthClientInit(iscsiAuthNodeTypeTarget,
		    isp->sess_auth.num_auth_buffers,
		    isp->sess_auth.auth_buffers) !=
		    iscsiAuthStatusNoError) {
			syslog(LOG_ERR, "iscsi connection login failed - "
			    "unable to initialize authentication\n");
			return;
		}

		if (iscsiAuthClientSetVersion(auth_client,
		    iscsiAuthVersionRfc) != iscsiAuthStatusNoError) {
			syslog(LOG_ERR, "iscsi connection login failed - "
			    "unable to set version\n");
			return;
		}

		if (isp->sess_auth.username &&
		    (iscsiAuthClientSetUsername(auth_client,
		    isp->sess_auth.username) !=
		    iscsiAuthStatusNoError)) {
			syslog(LOG_ERR, "iscsi connection login failed - "
			    "unable to set username\n");
			return;
		}

		if (isp->sess_auth.password &&
		    (iscsiAuthClientSetPassword(auth_client,
		    isp->sess_auth.password, isp->sess_auth.password_length) !=
		    iscsiAuthStatusNoError)) {
			syslog(LOG_ERR, "iscsi connection login failed - "
			    "unable to set password\n");
			return;
		}

		/*
		 * FIXME: we disable the minimum size check for now
		 */
		if (iscsiAuthClientSetIpSec(auth_client, 1) !=
		    iscsiAuthStatusNoError) {
			syslog(LOG_ERR, "iscsi connection login failed - "
			    "unable to set ipsec\n");
			return;
		}

		if (iscsiAuthClientSetAuthRemote(auth_client,
		    isp->sess_auth.auth_enabled) != iscsiAuthStatusNoError) {
			syslog(LOG_ERR, "iscsi connection login failed - "
			    "unable to set remote authentication\n");
			return;
		}
	}
}
