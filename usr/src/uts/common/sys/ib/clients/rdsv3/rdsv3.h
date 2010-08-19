/*
 * This file contains definitions imported from the OFED rds header rds.h.
 * Oracle elects to have and use the contents of rds.h under and
 * governed by the OpenIB.org BSD license.
 */

/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _RDSV3_RDSV3_H
#define	_RDSV3_RDSV3_H

/*
 * The name of this file is rds.h in ofed.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/sunndi.h>
#include <netinet/in.h>
#include <sys/synch.h>
#include <sys/stropts.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <inet/ip.h>
#include <sys/avl.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/rds.h>

#include <sys/ib/ibtl/ibti.h>
#include <sys/ib/clients/of/rdma/ib_verbs.h>
#include <sys/ib/clients/of/rdma/ib_addr.h>
#include <sys/ib/clients/of/rdma/rdma_cm.h>
#include <sys/ib/clients/rdsv3/rdsv3_impl.h>
#include <sys/ib/clients/rdsv3/info.h>

#include <sys/cpuvar.h>
#include <sys/disp.h>

#define	NIPQUAD(addr)					\
	(unsigned char)((ntohl(addr) >> 24) & 0xFF),	\
	(unsigned char)((ntohl(addr) >> 16) & 0xFF),	\
	(unsigned char)((ntohl(addr) >>  8) & 0xFF),	\
	(unsigned char)(ntohl(addr) & 0xFF)

/*
 * RDS Network protocol version
 */
#define	RDS_PROTOCOL_3_0	0x0300
#define	RDS_PROTOCOL_3_1	0x0301
#define	RDS_PROTOCOL_VERSION	RDS_PROTOCOL_3_1
#define	RDS_PROTOCOL_MAJOR(v)	((v) >> 8)
#define	RDS_PROTOCOL_MINOR(v)	((v) & 255)
#define	RDS_PROTOCOL(maj, min)	(((maj) << 8) | min)

/*
 * XXX randomly chosen, but at least seems to be unused:
 * #               18464-18768 Unassigned
 * We should do better.  We want a reserved port to discourage unpriv'ed
 * userspace from listening.
 *
 * port 18633 was the version that had ack frames on the wire.
 */
#define	RDSV3_PORT	18634

#define	RDSV3_REAPER_WAIT_SECS		(5*60)
#define	RDSV3_REAPER_WAIT_JIFFIES	SEC_TO_TICK(RDSV3_REAPER_WAIT_SECS)

static inline ulong_t
ceil(ulong_t x, ulong_t y)
{
	return ((x + y - 1) / y);
}

#define	RDSV3_FRAG_SHIFT	12
#define	RDSV3_FRAG_SIZE	((unsigned int)(1 << RDSV3_FRAG_SHIFT))

#define	RDSV3_CONG_MAP_BYTES	(65536 / 8)
#define	RDSV3_CONG_MAP_LONGS	(RDSV3_CONG_MAP_BYTES / sizeof (unsigned long))
#define	RDSV3_CONG_MAP_PAGES	(RDSV3_CONG_MAP_BYTES / PAGE_SIZE)
#define	RDSV3_CONG_MAP_PAGE_BITS	(PAGE_SIZE * 8)

struct rdsv3_cong_map {
	struct avl_node		m_rb_node;
	uint32_be_t		m_addr;
	rdsv3_wait_queue_t	m_waitq;
	struct list		m_conn_list;
	unsigned long		m_page_addrs[RDSV3_CONG_MAP_PAGES];
};

/*
 * This is how we will track the connection state:
 * A connection is always in one of the following
 * states. Updates to the state are atomic and imply
 * a memory barrier.
 */
enum {
	RDSV3_CONN_DOWN = 0,
	RDSV3_CONN_CONNECTING,
	RDSV3_CONN_DISCONNECTING,
	RDSV3_CONN_UP,
	RDSV3_CONN_ERROR,
};

/* Bits for c_flags */
#define	RDSV3_LL_SEND_FULL	0
#define	RDSV3_RECONNECT_PENDING	1

struct rdsv3_connection {
	struct avl_node		c_hash_node;
	struct rdsv3_ip_bucket	*c_bucketp;
	uint32_be_t		c_laddr;
	uint32_be_t		c_faddr;
	unsigned int		c_loopback:1;
	struct rdsv3_connection	*c_passive;

	struct rdsv3_cong_map	*c_lcong;
	struct rdsv3_cong_map	*c_fcong;

	struct mutex		c_send_lock;    /* protect send ring */
	atomic_t		c_send_generation;
	atomic_t		c_senders;

	struct rdsv3_message	*c_xmit_rm;
	unsigned long		c_xmit_sg;
	unsigned int		c_xmit_hdr_off;
	unsigned int		c_xmit_data_off;
	unsigned int		c_xmit_rdma_sent;

	kmutex_t		c_lock;		/* protect msg queues */
	uint64_t		c_next_tx_seq;
	struct list		c_send_queue;
	struct list		c_retrans;

	uint64_t		c_next_rx_seq;

	struct rdsv3_transport	*c_trans;
	void			*c_transport_data;

	atomic_t		c_state;
	unsigned long		c_flags;
	unsigned long		c_reconnect_jiffies;
	clock_t			c_last_connect_jiffies;

	struct rdsv3_delayed_work_s	c_send_w;
	struct rdsv3_delayed_work_s	c_recv_w;
	struct rdsv3_delayed_work_s	c_conn_w;
	struct rdsv3_delayed_work_s	c_reap_w;
	struct rdsv3_work_s	c_down_w;
	struct mutex		c_cm_lock;	/* protect conn state & cm */

	struct list_node	c_map_item;
	unsigned long		c_map_queued;
	unsigned long		c_map_offset;
	unsigned long		c_map_bytes;

	unsigned int		c_unacked_packets;
	unsigned int		c_unacked_bytes;

	/* Protocol version */
	unsigned int		c_version;
};

#define	RDSV3_FLAG_CONG_BITMAP		0x01
#define	RDSV3_FLAG_ACK_REQUIRED		0x02
#define	RDSV3_FLAG_RETRANSMITTED	0x04
#define	RDSV3_MAX_ADV_CREDIT		127

/*
 * Maximum space available for extension headers.
 */
#define	RDSV3_HEADER_EXT_SPACE    16

struct rdsv3_header {
	uint64_be_t	h_sequence;
	uint64_be_t	h_ack;
	uint32_be_t	h_len;
	uint16_be_t	h_sport;
	uint16_be_t	h_dport;
	uint8_t		h_flags;
	uint8_t		h_credit;
	uint8_t		h_padding[4];
	uint16_be_t	h_csum;

	uint8_t		h_exthdr[RDSV3_HEADER_EXT_SPACE];
};

/* Reserved - indicates end of extensions */
#define	RDSV3_EXTHDR_NONE		0

/*
 * This extension header is included in the very
 * first message that is sent on a new connection,
 * and identifies the protocol level. This will help
 * rolling updates if a future change requires breaking
 * the protocol.
 */
#define	RDSV3_EXTHDR_VERSION	1
struct rdsv3_ext_header_version {
	uint32_be_t	h_version;
};

/*
 * This extension header is included in the RDS message
 * chasing an RDMA operation.
 */
#define	RDSV3_EXTHDR_RDMA		2
struct rdsv3_ext_header_rdma {
	uint32_be_t	h_rdma_rkey;
};

/*
 * This extension header tells the peer about the
 * destination <R_Key,offset> of the requested RDMA
 * operation.
 */
#define	RDSV3_EXTHDR_RDMA_DEST    3
struct rdsv3_ext_header_rdma_dest {
	uint32_be_t		h_rdma_rkey;
	uint32_be_t		h_rdma_offset;
};

#define	__RDSV3_EXTHDR_MAX	16 /* for now */

struct rdsv3_incoming {
	atomic_t		i_refcount;
	struct list_node	i_item;
	struct rdsv3_connection	*i_conn;
	struct rdsv3_header	i_hdr;
	unsigned long		i_rx_jiffies;
	uint32_be_t		i_saddr;

	rds_rdma_cookie_t	i_rdma_cookie;
};

/*
 * m_sock_item and m_conn_item are on lists that are serialized under
 * conn->c_lock.  m_sock_item has additional meaning in that once it is empty
 * the message will not be put back on the retransmit list after being sent.
 * messages that are canceled while being sent rely on this.
 *
 * m_inc is used by loopback so that it can pass an incoming message straight
 * back up into the rx path.  It embeds a wire header which is also used by
 * the send path, which is kind of awkward.
 *
 * m_sock_item indicates the message's presence on a socket's send or receive
 * queue.  m_rs will point to that socket.
 *
 * m_daddr is used by cancellation to prune messages to a given destination.
 *
 * The RDS_MSG_ON_SOCK and RDS_MSG_ON_CONN flags are used to avoid lock
 * nesting.  As paths iterate over messages on a sock, or conn, they must
 * also lock the conn, or sock, to remove the message from those lists too.
 * Testing the flag to determine if the message is still on the lists lets
 * us avoid testing the list_head directly.  That means each path can use
 * the message's list_head to keep it on a local list while juggling locks
 * without confusing the other path.
 *
 * m_ack_seq is an optional field set by transports who need a different
 * sequence number range to invalidate.  They can use this in a callback
 * that they pass to rdsv3_send_drop_acked() to see if each message has been
 * acked.  The HAS_ACK_SEQ flag can be used to detect messages which haven't
 * had ack_seq set yet.
 */
#define	RDSV3_MSG_ON_SOCK		1
#define	RDSV3_MSG_ON_CONN		2
#define	RDSV3_MSG_HAS_ACK_SEQ		3
#define	RDSV3_MSG_ACK_REQUIRED		4
#define	RDSV3_MSG_RETRANSMITTED		5
#define	RDSV3_MSG_MAPPED		6
#define	RDSV3_MSG_PAGEVEC		7

struct rdsv3_message {
	atomic_t		m_refcount;
	struct list_node	m_sock_item;
	struct list_node	m_conn_item;
	struct rdsv3_incoming	m_inc;
	uint64_t		m_ack_seq;
	uint32_be_t		m_daddr;
	unsigned long		m_flags;

	/*
	 * Never access m_rs without holding m_rs_lock.
	 * Lock nesting is
	 *  rm->m_rs_lock
	 *   -> rs->rs_lock
	 */
	kmutex_t		m_rs_lock;
	rdsv3_wait_queue_t	m_flush_wait;

	struct rdsv3_sock	*m_rs;
	struct rdsv3_rdma_op	*m_rdma_op;
	rds_rdma_cookie_t	m_rdma_cookie;
	struct rdsv3_mr		*m_rdma_mr;
	unsigned int		m_nents;
	unsigned int		m_count;
	struct rdsv3_scatterlist	m_sg[1];
};

/*
 * The RDS notifier is used (optionally) to tell the application about
 * completed RDMA operations. Rather than keeping the whole rds message
 * around on the queue, we allocate a small notifier that is put on the
 * socket's notifier_list. Notifications are delivered to the application
 * through control messages.
 */
struct rdsv3_notifier {
	list_node_t	n_list;
	uint64_t	n_user_token;
	int		n_status;
};

/*
 * struct rdsv3_transport -  transport specific behavioural hooks
 *
 * @xmit: .xmit is called by rdsv3_send_xmit() to tell the transport to send
 *	  part of a message.  The caller serializes on the send_sem so this
 *	  doesn't need to be reentrant for a given conn.  The header must be
 *	  sent before the data payload.  .xmit must be prepared to send a
 *	  message with no data payload.  .xmit should return the number of
 *	  bytes that were sent down the connection, including header bytes.
 *	  Returning 0 tells the caller that it doesn't need to perform any
 *	  additional work now.  This is usually the case when the transport has
 *	  filled the sending queue for its connection and will handle
 *	  triggering the rds thread to continue the send when space becomes
 *	  available.  Returning -EAGAIN tells the caller to retry the send
 *	  immediately.  Returning -ENOMEM tells the caller to retry the send at
 *	  some point in the future.
 *
 * @conn_shutdown: conn_shutdown stops traffic on the given connection.  Once
 *		   it returns the connection can not call rdsv3_recv_incoming().
 *		   This will only be called once after conn_connect returns
 *		   non-zero success and will The caller serializes this with
 *		   the send and connecting paths (xmit_* and conn_*).  The
 *		   transport is responsible for other serialization, including
 *		   rdsv3_recv_incoming().  This is called in process context but
 *		   should try hard not to block.
 *
 * @xmit_cong_map: This asks the transport to send the local bitmap down the
 *		   given connection.  XXX get a better story about the bitmap
 *		   flag and header.
 */

#define	RDS_TRANS_IB    0
#define	RDS_TRANS_IWARP 1
#define	RDS_TRANS_TCP   2
#define	RDS_TRANS_COUNT 3

struct rdsv3_transport {
	char			t_name[TRANSNAMSIZ];
	struct list_node	t_item;
	unsigned int		t_type;
	unsigned int		t_prefer_loopback:1;

	int (*laddr_check)(uint32_be_t addr);
	int (*conn_alloc)(struct rdsv3_connection *conn, int gfp);
	void (*conn_free)(void *data);
	int (*conn_connect)(struct rdsv3_connection *conn);
	void (*conn_shutdown)(struct rdsv3_connection *conn);
	void (*xmit_prepare)(struct rdsv3_connection *conn);
	void (*xmit_complete)(struct rdsv3_connection *conn);
	int (*xmit)(struct rdsv3_connection *conn, struct rdsv3_message *rm,
	    unsigned int hdr_off, unsigned int sg, unsigned int off);
	int (*xmit_cong_map)(struct rdsv3_connection *conn,
	    struct rdsv3_cong_map *map, unsigned long offset);
	int (*xmit_rdma)(struct rdsv3_connection *conn,
	    struct rdsv3_rdma_op *op);
	int (*recv)(struct rdsv3_connection *conn);
	int (*inc_copy_to_user)(struct rdsv3_incoming *inc, uio_t *uio,
	    size_t size);
	void (*inc_free)(struct rdsv3_incoming *inc);

	int (*cm_handle_connect)(struct rdma_cm_id *cm_id,
	    struct rdma_cm_event *event);
	int (*cm_initiate_connect)(struct rdma_cm_id *cm_id);
	void (*cm_connect_complete)(struct rdsv3_connection *conn,
	    struct rdma_cm_event *event);

	unsigned int (*stats_info_copy)(struct rdsv3_info_iterator *iter,
	    unsigned int avail);
	void (*exit)(void);
	void *(*get_mr)(struct rds_iovec *sg, unsigned long nr_sg,
	    struct rdsv3_sock *rs, uint32_t *key_ret);
	void (*sync_mr)(void *trans_private, int direction);
	void (*free_mr)(void *trans_private, int invalidate);
	void (*flush_mrs)(void);
};

struct rdsv3_sock {
	struct rsock		*rs_sk;
	uint64_t		rs_user_addr;
	uint64_t		rs_user_bytes;

	/*
	 * bound_addr used for both incoming and outgoing, no INADDR_ANY
	 * support.
	 */
	struct avl_node		rs_bound_node;
	uint32_be_t		rs_bound_addr;
	uint32_be_t		rs_conn_addr;
	uint16_be_t		rs_bound_port;
	uint16_be_t		rs_conn_port;

	/*
	 * This is only used to communicate the transport between bind and
	 * initiating connections. All other trans use is referenced through
	 * the connection.
	 */
	struct rdsv3_transport	*rs_transport;

	/*
	 * rdsv3_sendmsg caches the conn it used the last time around.
	 * This helps avoid costly lookups.
	 */
	struct rdsv3_connection	*rs_conn;
	kmutex_t 		rs_conn_lock;

	/* flag indicating we were congested or not */
	int			rs_congested;
	/* seen congestion (ENOBUFS) when sending? */
	int			rs_seen_congestion;
	kmutex_t 		rs_congested_lock;
	kcondvar_t		rs_congested_cv;

	/* rs_lock protects all these adjacent members before the newline */
	kmutex_t		rs_lock;
	struct list		rs_send_queue;
	uint32_t		rs_snd_bytes;
	int			rs_rcv_bytes;
	/* currently used for failed RDMAs */
	struct list		rs_notify_queue;

	/*
	 * Congestion wake_up. If rs_cong_monitor is set, we use cong_mask
	 * to decide whether the application should be woken up.
	 * If not set, we use rs_cong_track to find out whether a cong map
	 * update arrived.
	 */
	uint64_t		rs_cong_mask;
	uint64_t		rs_cong_notify;
	struct list_node	rs_cong_list;
	unsigned long		rs_cong_track;

	/*
	 * rs_recv_lock protects the receive queue, and is
	 * used to serialize with rdsv3_release.
	 */
	krwlock_t		rs_recv_lock;
	struct list		rs_recv_queue;

	/* just for stats reporting */
	struct list_node	rs_item;

	/* these have their own lock */
	kmutex_t		rs_rdma_lock;
	struct avl_tree		rs_rdma_keys;

	/* Socket options - in case there will be more */
	unsigned char		rs_recverr,
				rs_cong_monitor;

	cred_t			*rs_cred;
	zoneid_t		rs_zoneid;
};

static inline struct rdsv3_sock *
rdsv3_sk_to_rs(const struct rsock *sk)
{
	return ((struct rdsv3_sock *)sk->sk_protinfo);
}

static inline struct rsock *
rdsv3_rs_to_sk(const struct rdsv3_sock *rs)
{
	return ((struct rsock *)rs->rs_sk);
}

/*
 * The stack assigns sk_sndbuf and sk_rcvbuf to twice the specified value
 * to account for overhead.  We don't account for overhead, we just apply
 * the number of payload bytes to the specified value.
 */
static inline int
rdsv3_sk_sndbuf(struct rdsv3_sock *rs)
{
	/* XXX */
	return (rdsv3_rs_to_sk(rs)->sk_sndbuf);
}

static inline int
rdsv3_sk_rcvbuf(struct rdsv3_sock *rs)
{
	/* XXX */
	return (rdsv3_rs_to_sk(rs)->sk_rcvbuf);
}

struct rdsv3_statistics {
	uint64_t	s_conn_reset;
	uint64_t	s_recv_drop_bad_checksum;
	uint64_t	s_recv_drop_old_seq;
	uint64_t	s_recv_drop_no_sock;
	uint64_t	s_recv_drop_dead_sock;
	uint64_t	s_recv_deliver_raced;
	uint64_t	s_recv_delivered;
	uint64_t	s_recv_queued;
	uint64_t	s_recv_immediate_retry;
	uint64_t	s_recv_delayed_retry;
	uint64_t	s_recv_ack_required;
	uint64_t	s_recv_rdma_bytes;
	uint64_t	s_recv_ping;
	uint64_t	s_send_queue_empty;
	uint64_t	s_send_queue_full;
	uint64_t	s_send_sem_contention;
	uint64_t	s_send_sem_queue_raced;
	uint64_t	s_send_immediate_retry;
	uint64_t	s_send_delayed_retry;
	uint64_t	s_send_drop_acked;
	uint64_t	s_send_ack_required;
	uint64_t	s_send_queued;
	uint64_t	s_send_rdma;
	uint64_t	s_send_rdma_bytes;
	uint64_t	s_send_pong;
	uint64_t	s_page_remainder_hit;
	uint64_t	s_page_remainder_miss;
	uint64_t	s_copy_to_user;
	uint64_t	s_copy_from_user;
	uint64_t	s_cong_update_queued;
	uint64_t	s_cong_update_received;
	uint64_t	s_cong_send_error;
	uint64_t	s_cong_send_blocked;
};

/* af_rds.c */
void rdsv3_sock_addref(struct rdsv3_sock *rs);
void rdsv3_sock_put(struct rdsv3_sock *rs);
void rdsv3_wake_sk_sleep(struct rdsv3_sock *rs);
void __rdsv3_wake_sk_sleep(struct rsock *sk);

/* bind.c */
int rdsv3_bind(sock_lower_handle_t proto_handle, struct sockaddr *sa,
    socklen_t len, cred_t *cr);
void rdsv3_remove_bound(struct rdsv3_sock *rs);
struct rdsv3_sock *rdsv3_find_bound(struct rdsv3_connection *conn,
    uint16_be_t port);
struct rdsv3_ip_bucket *rdsv3_find_ip_bucket(ipaddr_t, zoneid_t);

/* conn.c */
int rdsv3_conn_init(void);
void rdsv3_conn_exit(void);
struct rdsv3_connection *rdsv3_conn_create(uint32_be_t laddr, uint32_be_t faddr,
    struct rdsv3_transport *trans, int gfp);
struct rdsv3_connection *rdsv3_conn_create_outgoing(uint32_be_t laddr,
    uint32_be_t faddr,
    struct rdsv3_transport *trans, int gfp);
void rdsv3_conn_shutdown(struct rdsv3_connection *conn);
void rdsv3_conn_destroy(struct rdsv3_connection *conn);
void rdsv3_conn_reset(struct rdsv3_connection *conn);
void rdsv3_conn_drop(struct rdsv3_connection *conn);
void rdsv3_for_each_conn_info(struct rsock *sock, unsigned int len,
    struct rdsv3_info_iterator *iter,
    struct rdsv3_info_lengths *lens,
    int (*visitor)(struct rdsv3_connection *, void *),
    size_t item_len);

static inline int
rdsv3_conn_transition(struct rdsv3_connection *conn, int old, int new)
{
	return (atomic_cmpxchg(&conn->c_state, old, new) == old);
}

static inline int
rdsv3_conn_state(struct rdsv3_connection *conn)
{
	return (atomic_get(&conn->c_state));
}

static inline int
rdsv3_conn_up(struct rdsv3_connection *conn)
{
	return (atomic_get(&conn->c_state) == RDSV3_CONN_UP);
}

static inline int
rdsv3_conn_connecting(struct rdsv3_connection *conn)
{
	return (atomic_get(&conn->c_state) == RDSV3_CONN_CONNECTING);
}

/* recv.c */
void rdsv3_inc_init(struct rdsv3_incoming *inc, struct rdsv3_connection *conn,
    uint32_be_t saddr);
void rdsv3_inc_addref(struct rdsv3_incoming *inc);
void rdsv3_inc_put(struct rdsv3_incoming *inc);
void rdsv3_recv_incoming(struct rdsv3_connection *conn, uint32_be_t saddr,
    uint32_be_t daddr,
    struct rdsv3_incoming *inc, int gfp);
int rdsv3_recvmsg(struct rdsv3_sock *rs, uio_t *uio,
    struct msghdr *msg, size_t size, int msg_flags);
void rdsv3_clear_recv_queue(struct rdsv3_sock *rs);
int rdsv3_notify_queue_get(struct rdsv3_sock *rs, struct msghdr *msg);
void rdsv3_inc_info_copy(struct rdsv3_incoming *inc,
    struct rdsv3_info_iterator *iter,
    uint32_be_t saddr, uint32_be_t daddr, int flip);

/* page.c */
int rdsv3_page_remainder_alloc(struct rdsv3_scatterlist *scat,
    unsigned long bytes, int gfp);

/* send.c */
int rdsv3_sendmsg(struct rdsv3_sock *rs, uio_t *uio, struct nmsghdr *msg,
    size_t payload_len);
void rdsv3_send_reset(struct rdsv3_connection *conn);
int rdsv3_send_xmit(struct rdsv3_connection *conn);
struct sockaddr_in;
void rdsv3_send_drop_to(struct rdsv3_sock *rs, struct sockaddr_in *dest);
typedef int (*is_acked_func)(struct rdsv3_message *rm, uint64_t ack);
void rdsv3_send_drop_acked(struct rdsv3_connection *conn, uint64_t ack,
    is_acked_func is_acked);
int rdsv3_send_acked_before(struct rdsv3_connection *conn, uint64_t seq);
void rdsv3_send_remove_from_sock(struct list *messages, int status);
int rdsv3_send_pong(struct rdsv3_connection *conn, uint16_be_t dport);
struct rdsv3_message *rdsv3_send_get_message(struct rdsv3_connection *,
    struct rdsv3_rdma_op *);

/* rdma.c */
void rdsv3_rdma_unuse(struct rdsv3_sock *rs, uint32_t r_key, int force);

/* cong.c */
void rdsv3_cong_init(void);
int rdsv3_cong_get_maps(struct rdsv3_connection *conn);
void rdsv3_cong_add_conn(struct rdsv3_connection *conn);
void rdsv3_cong_remove_conn(struct rdsv3_connection *conn);
void rdsv3_cong_set_bit(struct rdsv3_cong_map *map, uint16_be_t port);
void rdsv3_cong_clear_bit(struct rdsv3_cong_map *map, uint16_be_t port);
int rdsv3_cong_wait(struct rdsv3_cong_map *map, uint16_be_t port, int nonblock,
    struct rdsv3_sock *rs);
void rdsv3_cong_queue_updates(struct rdsv3_cong_map *map);
void rdsv3_cong_map_updated(struct rdsv3_cong_map *map, uint64_t);
int rdsv3_cong_updated_since(unsigned long *recent);
void rdsv3_cong_add_socket(struct rdsv3_sock *);
void rdsv3_cong_remove_socket(struct rdsv3_sock *);
void rdsv3_cong_exit(void);
struct rdsv3_message *rdsv3_cong_update_alloc(struct rdsv3_connection *conn);

/* stats.c */
extern uint_t	nr_cpus;
extern struct rdsv3_statistics	*rdsv3_stats;
#define	rdsv3_per_cpu(var, cpu)  var[cpu]
#define	rdsv3_stats_add_which(which, member, count) do {	\
	rdsv3_per_cpu(which, CPU->cpu_seqid).member += count;	\
} while (0)
#define	rdsv3_stats_inc(member) \
	rdsv3_stats_add_which(rdsv3_stats, member, 1)
#define	rdsv3_stats_add(member, count)	\
	rdsv3_stats_add_which(rdsv3_stats, member, count)
int rdsv3_stats_init(void);
void rdsv3_stats_exit(void);
void rdsv3_stats_info_copy(struct rdsv3_info_iterator *iter,
    uint64_t *values, char **names, size_t nr);


/* sysctl.c */
int rdsv3_sysctl_init(void);
void rdsv3_sysctl_exit(void);
extern unsigned long rdsv3_sysctl_sndbuf_min;
extern unsigned long rdsv3_sysctl_sndbuf_default;
extern unsigned long rdsv3_sysctl_sndbuf_max;
extern unsigned long rdsv3_sysctl_reconnect_min_jiffies;
extern unsigned long rdsv3_sysctl_reconnect_max_jiffies;
extern unsigned int  rdsv3_sysctl_max_unacked_packets;
extern unsigned int  rdsv3_sysctl_max_unacked_bytes;
extern unsigned int  rdsv3_sysctl_ping_enable;
extern unsigned long rdsv3_sysctl_trace_flags;
extern unsigned int  rdsv3_sysctl_trace_level;

/* threads.c */
int rdsv3_threads_init();
void rdsv3_threads_exit(void);
extern struct rdsv3_workqueue_struct_s *rdsv3_wq;
void rdsv3_queue_reconnect(struct rdsv3_connection *conn);
void rdsv3_connect_worker(struct rdsv3_work_s *);
void rdsv3_shutdown_worker(struct rdsv3_work_s *);
void rdsv3_send_worker(struct rdsv3_work_s *);
void rdsv3_recv_worker(struct rdsv3_work_s *);
void rdsv3_reaper_worker(struct rdsv3_work_s *);
void rdsv3_connect_complete(struct rdsv3_connection *conn);

/* transport.c */
int rdsv3_trans_register(struct rdsv3_transport *trans);
void rdsv3_trans_unregister(struct rdsv3_transport *trans);
struct rdsv3_transport *rdsv3_trans_get_preferred(uint32_be_t addr);
unsigned int rdsv3_trans_stats_info_copy(struct rdsv3_info_iterator *iter,
    unsigned int avail);
void rdsv3_trans_exit(void);

/* message.c */
struct rdsv3_message *rdsv3_message_alloc(unsigned int nents, int gfp);
struct rdsv3_message *rdsv3_message_copy_from_user(struct uio *uiop,
    size_t total_len);
struct rdsv3_message *rdsv3_message_map_pages(unsigned long *page_addrs,
    unsigned int total_len);
void rdsv3_message_populate_header(struct rdsv3_header *hdr, uint16_be_t sport,
    uint16_be_t dport, uint64_t seq);
int rdsv3_message_add_extension(struct rdsv3_header *hdr,
    unsigned int type, const void *data, unsigned int len);
int rdsv3_message_next_extension(struct rdsv3_header *hdr,
    unsigned int *pos, void *buf, unsigned int *buflen);
int rdsv3_message_add_version_extension(struct rdsv3_header *hdr,
    unsigned int version);
int rdsv3_message_get_version_extension(struct rdsv3_header *hdr,
    unsigned int *version);
int rdsv3_message_add_rdma_dest_extension(struct rdsv3_header *hdr,
    uint32_t r_key, uint32_t offset);
int rdsv3_message_inc_copy_to_user(struct rdsv3_incoming *inc,
    uio_t *uio, size_t size);
void rdsv3_message_inc_free(struct rdsv3_incoming *inc);
void rdsv3_message_addref(struct rdsv3_message *rm);
void rdsv3_message_put(struct rdsv3_message *rm);
void rdsv3_message_wait(struct rdsv3_message *rm);
void rdsv3_message_unmapped(struct rdsv3_message *rm);

static inline void
rdsv3_message_make_checksum(struct rdsv3_header *hdr)
{
	hdr->h_csum = 0;
	hdr->h_csum =
	    rdsv3_ip_fast_csum((void *)hdr, sizeof (*hdr) >> 2);
}

static inline int
rdsv3_message_verify_checksum(const struct rdsv3_header *hdr)
{
	return (!hdr->h_csum ||
	    rdsv3_ip_fast_csum((void *)hdr, sizeof (*hdr) >> 2) == 0);
}

/* rdsv3_sc.c */
extern boolean_t rdsv3_if_lookup_by_name(char *if_name);
extern int rdsv3_sc_path_lookup(ipaddr_t *localip, ipaddr_t *remip);
extern ipaddr_t rdsv3_scaddr_to_ibaddr(ipaddr_t addr);

#ifdef	__cplusplus
}
#endif

#endif /* _RDSV3_RDSV3_H */
