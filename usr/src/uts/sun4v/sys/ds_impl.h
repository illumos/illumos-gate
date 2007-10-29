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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DS_IMPL_H
#define	_DS_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The Domain Services Protocol
 *
 * The DS protocol is divided into two parts. The first is fixed and
 * must remain exactly the same for *all* versions of the DS protocol.
 * The only messages supported by the fixed portion of the protocol are
 * to negotiate a version to use for the rest of the protocol.
 */

/*
 * Domain Services Header
 */
typedef struct ds_hdr {
	uint32_t	msg_type;	/* message type */
	uint32_t	payload_len;	/* payload length */
} ds_hdr_t;

#define	DS_HDR_SZ	(sizeof (ds_hdr_t))

/*
 * DS Fixed Message Types
 */
#define	DS_INIT_REQ		0x0	/* initiate DS connection */
#define	DS_INIT_ACK		0x1	/* initiation acknowledgment */
#define	DS_INIT_NACK		0x2	/* initiation negative acknowledgment */

/*
 * DS Fixed Initialization Messages
 */
typedef struct ds_init_req {
	uint16_t	major_vers;	/* requested major version */
	uint16_t	minor_vers;	/* requested minor version */
} ds_init_req_t;

typedef struct ds_init_ack {
	uint16_t	minor_vers;	/* highest supported minor version */
} ds_init_ack_t;

typedef struct ds_init_nack {
	uint16_t	major_vers;	/* alternate supported major version */
} ds_init_nack_t;

/*
 * DS Message Types for Version 1.0
 */
#define	DS_REG_REQ		0x3	/* register a service */
#define	DS_REG_ACK		0x4	/* register acknowledgment */
#define	DS_REG_NACK		0x5	/* register failed */
#define	DS_UNREG		0x6	/* unregister a service */
#define	DS_UNREG_ACK		0x7	/* unregister acknowledgment */
#define	DS_UNREG_NACK		0x8	/* unregister failed */
#define	DS_DATA			0x9	/* data message */
#define	DS_NACK			0xa	/* data error */

/* result codes */
#define	DS_OK			0x0	/* success */
#define	DS_REG_VER_NACK		0x1	/* unsupported major version */
#define	DS_REG_DUP		0x2	/* duplicate registration attempted */
#define	DS_INV_HDL		0x3	/* service handle not valid */
#define	DS_TYPE_UNKNOWN		0x4	/* unknown message type received */

/*
 * Service Register Messages
 */
typedef struct ds_reg_req {
	uint64_t	svc_handle;	/* service handle to register */
	uint16_t	major_vers;	/* requested major version */
	uint16_t	minor_vers;	/* requested minor version */
	char		svc_id[1];	/* service identifier string */
} ds_reg_req_t;

typedef struct ds_reg_ack {
	uint64_t	svc_handle;	/* service handle sent in register */
	uint16_t	minor_vers;	/* highest supported minor version */
} ds_reg_ack_t;

typedef struct ds_reg_nack {
	uint64_t	svc_handle;	/* service handle sent in register */
	uint64_t	result;		/* reason for the failure */
	uint16_t	major_vers;	/* alternate supported major version */
} ds_reg_nack_t;

/*
 * Service Unregister Messages
 */
typedef struct ds_unreg_req {
	uint64_t	svc_handle;	/* service handle to unregister */
} ds_unreg_req_t;

typedef struct ds_unreg_ack {
	uint64_t	svc_handle;	/* service handle sent in unregister */
} ds_unreg_ack_t;

typedef struct ds_unreg_nack {
	uint64_t	svc_handle;	/* service handle sent in unregister */
} ds_unreg_nack_t;

/*
 * Data Transfer Messages
 */
typedef struct ds_data_handle {
	uint64_t	svc_handle;	/* service handle for data */
} ds_data_handle_t;

typedef struct ds_data_nack {
	uint64_t	svc_handle;	/* service handle sent in data msg */
	uint64_t	result;		/* reason for failure */
} ds_data_nack_t;

/*
 * Message Processing Utilities
 */
#define	DS_MSG_TYPE_VALID(type)		((type) <= DS_NACK)
#define	DS_MSG_LEN(ds_type)		(sizeof (ds_hdr_t) + sizeof (ds_type))


/*
 * Domain Service Port
 *
 * A DS port is a logical representation of an LDC dedicated to
 * communication between DS endpoints. The ds_port_t maintains state
 * associated with a connection to a remote endpoint. This includes
 * the state of the port, the LDC state, the current version of the
 * DS protocol in use on the port, and other port properties.
 *
 * Locking: The port is protected by a single mutex. It must be held
 *   while the port structure is being accessed and also when data is
 *   being read or written using the port
 */
typedef enum {
	DS_PORT_FREE,			/* port structure not in use */
	DS_PORT_INIT,			/* port structure created */
	DS_PORT_LDC_INIT,		/* ldc successfully initialized */
	DS_PORT_INIT_REQ,		/* initialization handshake sent */
	DS_PORT_READY			/* init handshake completed */
} ds_port_state_t;

typedef struct ds_ldc {
	uint64_t	id;		/* LDC id */
	ldc_handle_t	hdl;		/* LDC handle */
	ldc_status_t	state;		/* current LDC state */
} ds_ldc_t;

typedef struct ds_port {
	kmutex_t	lock;		/* port lock */
	uint64_t	id;		/* port id from MD */
	ds_port_state_t	state;		/* state of the port */
	ds_ver_t	ver;		/* DS protocol version in use */
	uint32_t	ver_idx;	/* index of version during handshake */
	ds_ldc_t	ldc;		/* LDC for this port */
} ds_port_t;

/*
 * A DS portset is a bitmap that represents a collection of DS
 * ports. Each bit represent a particular port id. The current
 * implementation constrains the maximum number of ports to 64.
 */
typedef uint64_t ds_portset_t;

#define	DS_MAX_PORTS			((sizeof (ds_portset_t)) * 8)
#define	DS_MAX_PORT_ID			(DS_MAX_PORTS - 1)

#define	DS_PORT_SET(port)		(1UL << (port))
#define	DS_PORT_IN_SET(set, port)	((set) & DS_PORT_SET(port))
#define	DS_PORTSET_ADD(set, port)	((void)((set) |= DS_PORT_SET(port)))
#define	DS_PORTSET_DEL(set, port)	((void)((set) &= ~DS_PORT_SET(port)))
#define	DS_PORTSET_ISNULL(set)		((set) == 0)
#define	DS_PORTSET_DUP(set1, set2)	((void)((set1) = (set2)))

/*
 * LDC Information
 */
#define	DS_STREAM_MTU		4096

/*
 * Machine Description Constants
 */
#define	DS_MD_ROOT_NAME		"domain-services"
#define	DS_MD_PORT_NAME		"domain-services-port"
#define	DS_MD_CHAN_NAME		"channel-endpoint"

/*
 * DS Services
 *
 * A DS Service is a mapping between a DS capability and a client
 * of the DS framework that provides that capability. It includes
 * information on the state of the service, the currently negotiated
 * version of the capability specific protocol, the port that is
 * currently in use by the capability, etc.
 */

typedef enum {
	DS_SVC_INVAL,			/* svc structure uninitialized */
	DS_SVC_FREE,			/* svc structure not in use */
	DS_SVC_INACTIVE,		/* svc not registered */
	DS_SVC_REG_PENDING,		/* register message sent */
	DS_SVC_ACTIVE			/* register message acknowledged */
} ds_svc_state_t;

typedef struct ds_svc {
	ds_capability_t	cap;		/* capability information */
	ds_clnt_ops_t	ops;		/* client ops vector */
	ds_svc_hdl_t	hdl;		/* handle assigned by DS */
	ds_svc_state_t	state;		/* current service state */
	ds_ver_t	ver;		/* svc protocol version in use */
	uint_t		ver_idx;	/* index into client version array */
	ds_port_t	*port;		/* port for this service */
	ds_portset_t	avail;		/* ports available to this service */
} ds_svc_t;

#define	DS_SVC_ISFREE(svc)	((svc == NULL) || (svc->state == DS_SVC_FREE))

/*
 * A service handle is a 64 bit value with two pieces of information
 * encoded in it. The upper 32 bits is the index into the table of
 * a particular service structure. The lower 32 bits is a counter
 * that is incremented each time a service structure is reused.
 */
#define	DS_IDX_SHIFT			32
#define	DS_COUNT_MASK			0xfffffffful

#define	DS_ALLOC_HDL(_idx, _count)	(((uint64_t)_idx << DS_IDX_SHIFT) | \
					((uint64_t)(_count + 1) &	    \
					DS_COUNT_MASK))
#define	DS_HDL2IDX(hdl)			(hdl >> DS_IDX_SHIFT)
#define	DS_HDL2COUNT(hdl)		(hdl & DS_COUNT_MASK)

/*
 * DS Message Logging
 *
 * The DS framework logs all incoming and outgoing messages to a
 * ring buffer. This provides the ability to reconstruct a trace
 * of DS activity for use in debugging. In addition to the message
 * data, each log entry contains a timestamp and the destination
 * of the message. The destination is based on the port number the
 * message passed through (port number + 1). The sign of the dest
 * field distinguishes incoming messages from outgoing messages.
 * Incoming messages have a negative destination field.
 */

typedef struct ds_log_entry {
	struct ds_log_entry	*next;		/* next in log or free list */
	struct ds_log_entry	*prev;		/* previous in log */
	time_t			timestamp;	/* time message added to log */
	size_t			datasz;		/* size of the data */
	void			*data;		/* the data itself */
	int32_t			dest;		/* message destination */
} ds_log_entry_t;

#define	DS_LOG_IN(pid)		(-(pid + 1))
#define	DS_LOG_OUT(pid)		(pid + 1)

/*
 * DS Log Limits:
 *
 * The size of the log is controlled by two limits. The first is
 * a soft limit that is configurable by the user (via the global
 * variable ds_log_sz). When this limit is exceeded, each new
 * message that is added to the log replaces the oldest message.
 *
 * The second is a hard limit that is calculated based on the soft
 * limit (DS_LOG_LIMIT). It is defined to be ~3% above the soft limit.
 * Once this limit is exceeded, a thread is scheduled to delete old
 * messages until the size of the log is below the soft limit.
 */
#define	DS_LOG_DEFAULT_SZ	(4 * 1024 * 1024)	/* 4 MB */

#define	DS_LOG_LIMIT		(ds_log_sz + (ds_log_sz >> 5))

#define	DS_LOG_ENTRY_SZ(ep)	(sizeof (ds_log_entry_t) + (ep)->datasz)

/*
 * DS Log Memory Usage:
 *
 * The log free list is initialized from a pre-allocated pool of entry
 * structures (the global ds_log_entry_pool). The number of entries
 * in the pool (DS_LOG_NPOOL) is the number of entries that would
 * take up half the default size of the log.
 *
 * As messages are added to the log, entry structures are pulled from
 * the free list. If the free list is empty, memory is allocated for
 * the entry. When entries are removed from the log, they are placed
 * on the free list. Allocated memory is only deallocated when the
 * entire log is destroyed.
 */
#define	DS_LOG_NPOOL		((DS_LOG_DEFAULT_SZ >> 1) / \
				sizeof (ds_log_entry_t))

#define	DS_LOG_POOL_END		(ds_log_entry_pool + DS_LOG_NPOOL)

#define	DS_IS_POOL_ENTRY(ep)	(((ep) >= ds_log_entry_pool) && \
				((ep) <= &(ds_log_entry_pool[DS_LOG_NPOOL])))

#ifdef __cplusplus
}
#endif

#endif /* _DS_IMPL_H */
