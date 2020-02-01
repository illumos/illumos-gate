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

#ifndef _DS_IMPL_H
#define	_DS_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/bitmap.h>
#include <sys/ldoms.h>


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
#define	DS_INIT_ACK		0x1	/* initiation acknowledgement */
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
#define	DS_REG_ACK		0x4	/* register acknowledgement */
#define	DS_REG_NACK		0x5	/* register failed */
#define	DS_UNREG		0x6	/* unregister a service */
#define	DS_UNREG_ACK		0x7	/* unregister acknowledgement */
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

typedef uint64_t ds_domain_hdl_t;

#define	DS_DHDL_INVALID			((ds_domain_hdl_t)0xffffffff)

/* port flags */
#define	DS_PORT_MUTEX_INITED	0x1	/* mutexes inited? */

typedef struct ds_port {
	uint32_t	flags;		/* port flags */
	kmutex_t	lock;		/* port and service state lock */
	kmutex_t	tx_lock;	/* tx port lock */
	kmutex_t	rcv_lock;	/* rcv port lock */
	uint64_t	id;		/* port id from MD */
	ds_port_state_t	state;		/* state of the port */
	ds_ver_t	ver;		/* DS protocol version in use */
	uint32_t	ver_idx;	/* index of version during handshake */
	ds_ldc_t	ldc;		/* LDC for this port */
	ds_domain_hdl_t	domain_hdl;	/* LDOMs domain hdl assoc. with port */
	char		*domain_name;	/* LDOMs domain name assoc. with port */
} ds_port_t;

#define	IS_DS_PORT(port)	1	/* VBSC code compatability */
#define	PORTID(port)		((ulong_t)((port)->id))
#define	PTR_TO_LONG(ptr)	((uint64_t)(ptr))

/*
 * A DS portset is a bitmap that represents a collection of DS
 * ports. Each bit represent a particular port id.  We need
 * to allocate for the max. number of domains supported,
 * plus a small number (e.g. for the SP connection).
 */
#define	DS_EXTRA_PORTS			16
#define	DS_MAX_PORTS			(LDOMS_MAX_DOMAINS + DS_EXTRA_PORTS)
#define	DS_PORTSET_SIZE			BT_BITOUL(DS_MAX_PORTS)

typedef ulong_t ds_portset_t[DS_PORTSET_SIZE];

extern ds_portset_t ds_nullport;

#define	DS_PORTID_INVALID		((uint64_t)-1)

/* DS SP Port ID */
extern uint64_t ds_sp_port_id;

#define	DS_MAX_PORT_ID			(DS_MAX_PORTS - 1)

#define	DS_PORT_IN_SET(set, port)	BT_TEST((set), (port))
#define	DS_PORTSET_ADD(set, port)	BT_SET((set), (port))
#define	DS_PORTSET_DEL(set, port)	BT_CLEAR((set), (port))
#define	DS_PORTSET_ISNULL(set)		(memcmp((set), ds_nullport, \
					    sizeof (set)) == 0)
#define	DS_PORTSET_SETNULL(set)		((void)memset((set), 0, sizeof (set)))
#define	DS_PORTSET_DUP(set1, set2)	((void)memcpy((set1), (set2), \
					    sizeof (set1)))

/*
 * A DS event consists of a buffer on a port.  We explictly use a link to
 * enequeue/dequeue on non-Solaris environments.  On Solaris we use taskq.
 */
typedef struct ds_event {
	ds_port_t	*port;
	char		*buf;
	size_t		buflen;
} ds_event_t;

/*
 * LDC Information
 */
#define	DS_STREAM_MTU	4096

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
	DS_SVC_ACTIVE,			/* register message acknowledged */
	DS_SVC_UNREG_PENDING		/* unregister is pending */
} ds_svc_state_t;

/* ds_svc flags bits */
#define	DSSF_ISCLIENT		0x0001	/* client service */
#define	DSSF_ISUSER		0x0002	/* user land service */
#define	DSSF_REGCB_VALID	0x0004	/* ops register callback is valid */
#define	DSSF_UNREGCB_VALID	0x0008	/* ops unregister callback is valid */
#define	DSSF_DATACB_VALID	0x0010	/* ops data callback is valid */
#define	DSSF_LOOPBACK		0x0020	/* loopback */
#define	DSSF_PEND_UNREG		0x0040	/* pending unregister */
#define	DSSF_ANYCB_VALID	(DSSF_REGCB_VALID | DSSF_UNREGCB_VALID | \
				    DSSF_DATACB_VALID)
#define	DSSF_USERFLAGS		(DSSF_ISCLIENT | DSSF_ISUSER | DSSF_ANYCB_VALID)

typedef struct ds_svc {
	ds_capability_t	cap;		/* capability information */
	ds_clnt_ops_t	ops;		/* client ops vector */
	ds_svc_hdl_t	hdl;		/* handle assigned by DS */
	ds_svc_hdl_t	svc_hdl;	/* remote svc hdl if client svc */
	ds_svc_state_t	state;		/* current service state */
	ds_ver_t	ver;		/* svc protocol version in use */
	uint_t		ver_idx;	/* index into client version array */
	ds_port_t	*port;		/* port for this service */
	ds_portset_t	avail;		/* ports available to this service */
	ds_portset_t	tried;		/* ports tried by this service */
	int		fixed;		/* is svc fixed to port */
	uint_t		flags;		/* service flags */
	ds_cb_arg_t	uarg;		/* user arg for user callbacks */
	uint_t		drvi;		/* driver instance */
	void		*drv_psp;	/* driver per svc ptr */
} ds_svc_t;

typedef struct ds_svcs {
	ds_svc_t	**tbl;		/* ptr to table */
	kmutex_t	lock;
	uint_t		maxsvcs;	/* size of the table */
	uint_t		nsvcs;		/* current number of items */
} ds_svcs_t;

#define	DS_SVC_ISFREE(svc)	((svc == NULL) || (svc->state == DS_SVC_FREE))
#ifndef	DS_MAXSVCS_INIT
#define	DS_MAXSVCS_INIT	32
#endif

/*
 * A service handle is a 64 bit value with three pieces of information
 * encoded in it. The upper 32 bits is the index into the table of
 * a particular service structure. Bit 31 indicates whether the handle
 * represents a service privider or service client. The lower 31 bits is
 * a counter that is incremented each time a service structure is reused.
 */
#define	DS_IDX_SHIFT			32
#define	DS_COUNT_MASK			0x7fffffffull
#define	DS_HDL_ISCLIENT_BIT		0x80000000ull

#define	DS_ALLOC_HDL(_idx, _count)	(((uint64_t)_idx << DS_IDX_SHIFT) | \
					((uint64_t)(_count + 1) &	    \
					DS_COUNT_MASK))
#define	DS_HDL2IDX(hdl)			(hdl >> DS_IDX_SHIFT)
#define	DS_HDL2COUNT(hdl)		(hdl & DS_COUNT_MASK)
#define	DS_HDL_ISCLIENT(hdl)		((hdl) & DS_HDL_ISCLIENT_BIT)
#define	DS_HDL_SET_ISCLIENT(hdl)	((hdl) |= DS_HDL_ISCLIENT_BIT)

#define	DS_INVALID_INSTANCE		(-1)

/* enable/disable taskq processing */
extern boolean_t ds_enabled;

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
				((ep) < &(ds_log_entry_pool[DS_LOG_NPOOL])))

/* VBSC code compatability related defines */

/* VBSC malloc/free are similar to user malloc/free */
#define	DS_MALLOC(size)		kmem_zalloc(size, KM_SLEEP)
#define	DS_FREE(ptr, size)	kmem_free(ptr, size)

/* VBSC debug print needs newline, Solaris cmn_err doesn't */
#define	DS_EOL

/*
 * Results of checking version array with ds_vers_isvalid()
 */
typedef enum {
	DS_VERS_OK,
	DS_VERS_INCREASING_MAJOR_ERR,
	DS_VERS_INCREASING_MINOR_ERR
} ds_vers_check_t;

/* System specific interfaces */
extern void ds_sys_port_init(ds_port_t *port);
extern void ds_sys_port_fini(ds_port_t *port);
extern void ds_sys_drain_events(ds_port_t *port);
extern int ds_sys_dispatch_func(void (func)(void *), void *arg);
extern void ds_sys_ldc_init(ds_port_t *port);

/* vlds cb access to svc structure */
void ds_cbarg_get_hdl(ds_cb_arg_t arg, ds_svc_hdl_t *hdlp);
void ds_cbarg_get_flags(ds_cb_arg_t arg, uint32_t *flagsp);
void ds_cbarg_get_drv_info(ds_cb_arg_t arg, int *drvip);
void ds_cbarg_get_drv_per_svc_ptr(ds_cb_arg_t arg, void **dpspp);
void ds_cbarg_get_domain(ds_cb_arg_t arg, ds_domain_hdl_t *dhdlp);
void ds_cbarg_get_service_id(ds_cb_arg_t arg, char **servicep);
void ds_cbarg_set_drv_per_svc_ptr(ds_cb_arg_t arg, void *dpsp);
int ds_hdl_get_cbarg(ds_svc_hdl_t hdl, ds_cb_arg_t *cbargp);
void ds_cbarg_set_cookie(ds_svc_t *svc);
int ds_is_my_hdl(ds_svc_hdl_t hdl, int instance);
void ds_set_my_dom_hdl_name(ds_domain_hdl_t dhdl, char *name);

/* initialization functions */
void ds_common_init(void);
int ds_ldc_fini(ds_port_t *port);
void ds_init_svcs_tbl(uint_t nentries);

/* message sending functions */
void ds_send_init_req(ds_port_t *port);
int ds_send_unreg_req(ds_svc_t *svc);

/* walker functions */
typedef int (*svc_cb_t)(ds_svc_t *svc, void *arg);
int ds_walk_svcs(svc_cb_t svc_cb, void *arg);
int ds_svc_ismatch(ds_svc_t *svc, void *arg);
int ds_svc_free(ds_svc_t *svc, void *arg);
int ds_svc_register(ds_svc_t *svc, void *arg);

/* service utilities */
ds_svc_t *ds_alloc_svc(void);
ds_svc_t *ds_sys_find_svc_by_id_port(char *svc_id, ds_port_t *port,
    int is_client);
ds_svc_t *ds_get_svc(ds_svc_hdl_t hdl);

/* port utilities */
void ds_port_common_init(ds_port_t *port);
void ds_port_common_fini(ds_port_t *port);

/* misc utilities */
ds_vers_check_t ds_vers_isvalid(ds_ver_t *vers, int nvers);
char *ds_errno_to_str(int ds_errno, char *ebuf);
char *ds_strdup(char *str);
boolean_t negotiate_version(int num_versions, ds_ver_t *sup_versionsp,
    uint16_t req_major, uint16_t *new_majorp, uint16_t *new_minorp);

/* log functions */
int ds_log_add_msg(int32_t dest, uint8_t *msg, size_t sz);

/* vlds driver interfaces to ds module */
int ds_ucap_init(ds_capability_t *cap, ds_clnt_ops_t *ops, uint_t flags,
    int instance, ds_svc_hdl_t *hdlp);
int ds_unreg_hdl(ds_svc_hdl_t hdl);
int ds_hdl_lookup(char *service, uint_t is_client, ds_svc_hdl_t *hdlp,
    uint_t maxhdls, uint_t *nhdlsp);
int ds_service_lookup(ds_svc_hdl_t hdl, char **servicep, uint_t *is_client);
int ds_domain_lookup(ds_svc_hdl_t hdl, ds_domain_hdl_t *dhdlp);
int ds_hdl_isready(ds_svc_hdl_t hdl, uint_t *is_ready);
void ds_unreg_all(int instance);
int ds_dom_name_to_hdl(char *domain_name, ds_domain_hdl_t *dhdlp);
int ds_dom_hdl_to_name(ds_domain_hdl_t dhdl, char **domain_namep);
int ds_add_port(uint64_t port_id, uint64_t ldc_id, ds_domain_hdl_t dhdl,
    char *dom_name, int verbose);
int ds_remove_port(uint64_t portid, int is_fini);

/* ds_ucap_init flags */
#define	DS_UCAP_CLNT		0x0	/* Service is Client */
#define	DS_UCAP_SVC		0x1	/* Service is Server */

/*
 * Error buffer size for ds_errno_to_str
 */
#define	DS_EBUFSIZE	80

/*
 * Debugging Features
 */
#ifdef DEBUG

#define	DS_DBG_BASIC			0x001
#define	DS_DBG_FLAG_LDC			0x002
#define	DS_DBG_FLAG_LOG			0x004
#define	DS_DBG_DUMP_LDC_MSG		0x008
#define	DS_DBG_FLAG_MD			0x010
#define	DS_DBG_FLAG_USR			0x020
#define	DS_DBG_FLAG_VLDS		0x040
#define	DS_DBG_FLAG_PRCL		0x080
#define	DS_DBG_FLAG_RCVQ		0x100
#define	DS_DBG_FLAG_LOOP		0x200

#define	DS_DBG				if (ds_debug & DS_DBG_BASIC) cmn_err
#define	DS_DBG_LDC			if (ds_debug & DS_DBG_FLAG_LDC) cmn_err
#define	DS_DBG_LOG			if (ds_debug & DS_DBG_FLAG_LOG) cmn_err
#define	DS_DBG_MD			if (ds_debug & DS_DBG_FLAG_MD) cmn_err
#define	DS_DBG_USR			if (ds_debug & DS_DBG_FLAG_USR) cmn_err
#define	DS_DBG_VLDS			if (ds_debug & DS_DBG_FLAG_VLDS) cmn_err
#define	DS_DBG_PRCL			if (ds_debug & DS_DBG_FLAG_PRCL) cmn_err
#define	DS_DBG_RCVQ			if (ds_debug & DS_DBG_FLAG_RCVQ) cmn_err
#define	DS_DBG_LOOP			if (ds_debug & DS_DBG_FLAG_LOOP) cmn_err

#define	DS_DUMP_MSG(flags, buf, len)	if (ds_debug & (flags)) \
					    ds_dump_msg(buf, len)

extern uint_t ds_debug;
void ds_dump_msg(void *buf, size_t len);

#define	DS_BADHDL1			(ds_svc_hdl_t)(0xdeadbed1deadbed1ull)
#define	DS_BADHDL2			(ds_svc_hdl_t)(0x2deadbed2deadbedull)

#else /* DEBUG */

#define	DS_DBG				if (0) cmn_err
#define	DS_DBG_LDC			DS_DBG
#define	DS_DBG_LOG			DS_DBG
#define	DS_DBG_MD			DS_DBG
#define	DS_DBG_USR			DS_DBG
#define	DS_DBG_VLDS			DS_DBG
#define	DS_DBG_PRCL			DS_DBG
#define	DS_DBG_RCVQ			DS_DBG
#define	DS_DBG_LOOP			DS_DBG
#define	DS_DUMP_MSG(flags, buf, len)
#define	DS_DUMP_LDC_MSG(buf, len)

#define	DS_BADHDL1			(ds_svc_hdl_t)0
#define	DS_BADHDL2			(ds_svc_hdl_t)0

#endif /* DEBUG */

#ifdef __cplusplus
}
#endif

#endif /* _DS_IMPL_H */
