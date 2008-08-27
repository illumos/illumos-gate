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

#ifndef _TARGET_QUEUE_H
#define	_TARGET_QUEUE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <sys/time.h>
#include <stdarg.h>
#include <synch.h>
#include <door.h>

#include <iscsitgt_impl.h>

/* Connections */
#define	Q_CONN_ERRS	0x00000001
#define	Q_CONN_LOGIN	0x00000002
#define	Q_CONN_NONIO	0x00000004
#define	Q_CONN_IO	0x00000008

/* Sessions */
#define	Q_SESS_ERRS	0x00000010
#define	Q_SESS_LOGIN	0x00000020
#define	Q_SESS_NONIO	0x00000040
#define	Q_SESS_IO	0x00000080

/* SCSI Target Emulation */
#define	Q_STE_ERRS	0x00000100
#define	Q_STE_NONIO	0x00000200
#define	Q_STE_IO	0x00000400

/* General Errors */
#define	Q_GEN_ERRS	0x00001000
#define	Q_GEN_DETAILS	0x00002000

/* ISCSI Debugging */
#define	Q_ISNS_DBG	0x00004000

/* Persistent Reservations */
#define	Q_PR_ERRS	0x00010000
#define	Q_PR_NONIO	0x00020000
#define	Q_PR_IO		0x00040000

/*
 * When used the queue request will be place at the head of the queue.
 */
#define	Q_HIGH		0x80000000

extern int qlog_lvl;

typedef enum {
	/*
	 * []----------------------------------------------------------------
	 * | Messages internal to the SAM-3 portion. When the transport calls
	 * | the SAM-3 interfaces messages are enqueued to the LU. The LU
	 * | thread then dequeues these messages and calls the appropriate
	 * | function for the emulator.
	 */

	/* ---- from transport ---- */
	msg_cmd_send,
	msg_cmd_data_out,

	/* ---- from emulation ---- */
	msg_cmd_data_in,
	msg_cmd_data_rqst,
	msg_cmd_cmplt,

	/* ---- Internal SAM-3 messages ---- */
	msg_lu_add,
	msg_lu_remove,
	msg_lu_online,
	msg_lu_aio_done,

	/*
	 * | End of SAM-3 messages
	 * []----------------------------------------------------------------
	 */

	msg_reset_lu,
	msg_reset_targ,
	msg_targ_inventory_change,
	msg_lu_capacity_change,

	/*
	 * The ConnectionReader will send packet ready messages when
	 * data is available. If the socket has an error or is closed
	 * a conn_lost message will be sent. Packet ready will have the
	 * number of bytes currently available on the connection. Don't
	 * free.
	 */
	msg_conn_lost,
	msg_packet_ready,

	/*
	 * Shutdowns happen from the bottom up. The replies are in place
	 * so that threads can wait for the top end to disappear, at least
	 * they must no longer reference any common structures such as
	 * message queues.
	 */
	msg_drain_complete,
	msg_shutdown,
	msg_shutdown_rsp,

	/*
	 * Here's a special error condition for STE. When using mmap
	 * to access the backing store of a LUN which is larger than
	 * the underlying storage it's possible to run out of room
	 * on the device (no duh). When that happens the OS will send
	 * the daemon a SIGSBUS. The STE thread catches that signal,
	 * sends a UNIT ATTENTION to the other side, and closes down
	 * the STE thread in a special manner. The transport layer
	 * can then restart another STE thread with the same queues
	 * which mean outstanding I/O restarts.
	 */
	msg_ste_media_error,

	/*
	 * A NopIn request could be sent on the connection receive thread
	 * except for one little issue. Since both the receive and transmit
	 * threads could be issuing packets and data to the socket at the
	 * same time we must protect those writes so that all of the data
	 * for a single PDU (hdr, checksum, data, checksum) go out together.
	 * It's possible for the socket to receive so much incoming data
	 * that writes will be blocked until some of that data has been
	 * read. If the transmit grabs the lock, attempts to write, and is
	 * blocked we find a condition where the receiver is also blocked
	 * processing a nop command because it can't get the lock. So, instead
	 * we build up the packet and queue it.
	 *
	 * This will also occur with Task Management Requests.
	 */
	msg_send_pkt,

	/*
	 * During login when the TargetName name/value pair is processed
	 * the value will be sent to STE through the session layer.
	 * STE can use the information however it sees fit.
	 * The InitiatorName will also be sent which STE can use to
	 * validate login properties.
	 */
	msg_target_name,
	msg_initiator_name,
	msg_initiator_alias,

	/*
	 * Issued when causing full allocation of backing store.
	 * This is an internal message used by t10_sam.c
	 */
	msg_thick_provo,

	/*
	 * ---------------- Debug/Management type messages ----------------
	 */
	/*
	 * When a thread shutdowns someone must call pthread_join else
	 * the thread will remain in a zombie state taking up some
	 * amount of memory.
	 */
	msg_pthread_join,

	/*
	 * Requests from and replys to the management host will be done using
	 * these messages.
	 */
	msg_mgmt_rqst,
	msg_mgmt_rply,

	/*
	 * General debug messages.
	 */
	msg_log,

	/*
	 * Problem message by some of the auxiliary threads indication
	 * problems.
	 */
	msg_status,

	msg_wait_for_destroy

} msg_type_t;

typedef struct msg {
	struct msg	*msg_next,
			*msg_prev;
	struct msg	*msg_all_next;

	msg_type_t	msg_type;
	void		*msg_data;

	/*
	 * This can be used either to insert a message higher into the queue
	 * or as debug level flags.
	 */
	uint32_t	msg_pri_level;
} msg_t;

typedef struct target_queue {
	msg_t		*q_head,
			*q_tail;
	pthread_mutex_t	q_mutex;
	sema_t		q_sema;
	int		q_num;
} target_queue_t;

typedef enum mgmt_type {
	mgmt_full_phase_statistics,
	mgmt_discovery_statistics,
	mgmt_lun_information,
	mgmt_parse_xml,
	mgmt_logout
} mgmt_type_t;

typedef struct mgmt_request {
	target_queue_t	*m_q;
	mgmt_type_t	m_request;
	time_t		m_time;
	char		*m_targ_name;
	ucred_t		*m_cred;

	/*
	 * This mutex protects the m_buf pointer from multiple connections
	 * attempting to update the response at the same time. One management
	 * request structure is sent to possible multiple connections when
	 * gathering statistics. The connections/sessions will lock access
	 * to the buffer.
	 */
	pthread_mutex_t	m_resp_mutex;
	union {
		char		**m_resp;
		tgt_node_t	*m_node;
	} m_u;
} mgmt_request_t;

typedef struct name_request {
	target_queue_t	*nr_q;
	char		*nr_name;
} name_request_t;

void queue_init();
target_queue_t *queue_alloc();
void queue_message_set(target_queue_t *, uint32_t lvl, msg_type_t, void *);
msg_t *queue_message_get(target_queue_t *);
msg_t *queue_message_try_get(target_queue_t *q);
void queue_message_free(msg_t *);
void queue_walker_free(target_queue_t *q,
    Boolean_t (*func)(msg_t *, void *v), void *v1);
void queue_free(target_queue_t *, void (*free_func)(msg_t *));
void queue_reset(target_queue_t *q);
void queue_prt(target_queue_t *q, int type, char *fmt, ...);
void queue_str(target_queue_t *, uint32_t lvl, msg_type_t, char *);
void queue_log(Boolean_t on_off);
void ste_queue_data_remove(msg_t *m);
void conn_queue_data_remove(msg_t *m);
void sess_queue_data_remove(msg_t *m);

#ifdef __cplusplus
}
#endif

#endif /* _TARGET_QUEUE_H */
