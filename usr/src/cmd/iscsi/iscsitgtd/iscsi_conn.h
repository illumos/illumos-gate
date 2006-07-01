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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _TARGET_CONN_H
#define	_TARGET_CONN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Block comment which describes the contents of this file.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/iscsi_protocol.h>
#include <sys/socket.h>
#include "queue.h"
#include "iscsi_sess.h"
#include "iscsi_cmd.h"

#define	LBUFSIZE 80

#define	TARGET_LOCATION			"targets"
/*
 * Currently I'm having some problems with network reads/write when the
 * data size is larger than 8k. To work around this problem I set the
 * various negotiation parameters during login to limit things to 8k.
 */

#define	NETWORK_SNDRCV		65536
#define	NETWORK_SNDRCV_STR	"65536"

typedef enum iscsi_state {
	S1_FREE,
	/* S2_XPT_WAIT, Not possible for target */
	S3_XPT_UP,
	S4_IN_LOGIN,
	S5_LOGGED_IN,
	S6_IN_LOGOUT,
	S7_LOGOUT_REQUESTED,
	S8_CLEANUP_WAIT
} iscsi_state_t;

typedef enum iscsi_transition {
	T3, T4, T5, T6, T7, T8,
	T9, T10, T11, T12, T13, T15,
	T16, T17, T18
} iscsi_transition_t;

/*
 * When grabbing mutex's make sure to grab c_mutex before c_mutex_state
 * if you need to grab both.
 */
typedef struct iscsi_conn {
	int		c_fd;

	/*
	 * This is a linked list of all connections. Not just the connections
	 * associated with a particular session.
	 */
	struct iscsi_conn	*c_next,
				*c_prev;

	target_queue_t	*c_mgmtq;

	/*
	 * Time as reported by time(2) when this connection was started.
	 */
	time_t		c_up_at;

	/*
	 * This queue is used to accept notification that incoming packets
	 * are available and command completion status from Session.
	 */
	target_queue_t	*c_dataq;

	/*
	 * Messages are sent to Session, and from there onto STE, using
	 * this queue.
	 */
	target_queue_t	*c_sessq;

	iscsi_sess_t	*c_sess;

	pthread_mutex_t	c_state_mutex;
	iscsi_state_t	c_state;

	/*
	 * Protected by c_mutex
	 */
	int		c_statsn;

	int		c_cid;

	/*
	 * Pointer to data buffer used to store text messages which have
	 * the 'C' bit set. Since the text data separates name/value pairs
	 * with a '\0' strlen can't be used to determine the amount of space
	 * used so we keep the length in c_text_len;
	 */
	char		*c_text_area;
	int		c_text_len;
	int		c_text_sent;

	sema_t		c_datain;
	pthread_t	c_thr_id_poller,
			c_thr_id_process;

	pthread_mutex_t	c_mutex;
	iscsi_cmd_t	*c_cmd_head;
	iscsi_cmd_t	*c_cmd_tail;

	struct sockaddr_storage	c_initiator_sockaddr;
	struct sockaddr_storage c_target_sockaddr;

	int		c_num;

	int		c_auth_pass	: 1;

	int		c_cmds_active;

	/*
	 * A performance issue has been found when the backing store
	 * is UFS. Because of the indirect blocks used by UFS large files
	 * (many GBs in size) perform poorly. This in turn can cause the
	 * initiator to issue commands which don't complete in time. So,
	 * we'll monitor the completion times for commands if if it's
	 * increasing the command window will be reduced.
	 * The avg_sum is in nanoseconds. This will wrap once every 584
	 * years.
	 */
	uint64_t	c_cmds_avg_cnt;
	hrtime_t	c_cmds_avg_sum;

	/*
	 * During an orderly shutdown the logout response is created when
	 * we receive the logout request. We must however wait for all I/O
	 * to complete before processing the data else we'll loose data
	 * which the initiator believes was successfully transferred.
	 * Once the STE and sessions have closed they will send a shutdown
	 * complete message. At that point the transmit side of the connection
	 * will set the state to T13 which pushes this message out.
	 * Unfortunately we need information from the Logout Request PDU
	 * to create the Logout Response PDU. Otherwise the response could
	 * be generated on the fly in the T13 state handler. By creating
	 * the response PDU and saving a pointer gives us some flexibility
	 * in the future if the final outgoing packet needs to change.
	 * Otherwise, storing that one bit of information from the request
	 * PDU might become dated.
	 */
	iscsi_hdr_t	*c_last_pkg;

	/*
	 * Connection parameters
	 */
	Boolean_t	c_header_digest,
			c_data_digest,
			c_ifmarker,
			c_ofmarker,
			c_initialR2T,
			c_immediate_data,
			c_data_pdu_in_order,
			c_data_sequence_in_order;
	int		c_tpgt,
			c_maxcmdsn,
			c_max_recv_data,
			c_default_time_2_wait,
			c_default_time_2_retain,
			c_erl,
			c_max_burst_len,
			c_first_burst_len,
			c_max_outstanding_r2t,
			c_max_connections;
	char		*c_targ_alias,
			*auth_text;
	int		auth_text_length;

} iscsi_conn_t;

void *conn_process(void *v);
void conn_state(iscsi_conn_t *c, iscsi_transition_t t);
void send_iscsi_pkt(iscsi_conn_t *c, iscsi_hdr_t *h, char *opt_text);
int read_retry(int fd, char *buf, int count);
void iscsi_inventory_change(char *targ_name);
void iscsi_capacity_change(char *targ_name, int lun);

#ifdef __cplusplus
}
#endif

#endif /* _TARGET_CONN_H */
