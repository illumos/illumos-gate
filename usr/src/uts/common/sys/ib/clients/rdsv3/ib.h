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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _RDSV3_IB_H
#define	_RDSV3_IB_H

#include <sys/rds.h>

#include <sys/ib/clients/rdsv3/rdsv3.h>
#include <sys/ib/clients/rdsv3/rdma_transport.h>

#define	RDSV3_FMR_SIZE			256
#define	RDSV3_FMR_POOL_SIZE		(12 * 1024)

#define	RDSV3_IB_SEND_WRS		64

#define	RDSV3_IB_MAX_SGE		8
#define	RDSV3_IB_RECV_SGE 		2

#define	RDSV3_IB_DEFAULT_RECV_WR	1024
#define	RDSV3_IB_DEFAULT_SEND_WR	256

#define	RDSV3_IB_DEFAULT_RETRY_COUNT	2

/* minor versions supported */
#define	RDSV3_IB_SUPPORTED_PROTOCOLS	0x00000003

extern struct list rdsv3_ib_devices;

/*
 * IB posts RDSV3_FRAG_SIZE fragments of pages to the receive queues to
 * try and minimize the amount of memory tied up both the device and
 * socket receive queues.
 */
/* page offset of the final full frag that fits in the page */
#define	RDSV3_PAGE_LAST_OFF	\
	(((PAGE_SIZE  / RDSV3_FRAG_SIZE) - 1) * RDSV3_FRAG_SIZE)
struct rdsv3_page_frag {
	struct list_node	f_item;
	caddr_t			f_page;
	unsigned long		f_offset;
	ibt_mi_hdl_t 		f_mapped;
};

struct rdsv3_ib_incoming {
	struct list		ii_frags;
	struct rdsv3_incoming	ii_inc;
};

struct rdsv3_ib_connect_private {
	/* Add new fields at the end, and don't permute existing fields. */
	uint32_be_t		dp_saddr;
	uint32_be_t		dp_daddr;
	uint8_t			dp_protocol_major;
	uint8_t			dp_protocol_minor;
	uint16_be_t		dp_protocol_minor_mask; /* bitmask */
	uint32_be_t		dp_reserved1;
	uint32_be_t		dp_ack_seq;
	uint32_be_t		dp_credit;	/* non-zero enables flow ctl */
};

struct rdsv3_ib_send_work {
	struct rdsv3_message	*s_rm;
	struct rdsv3_rdma_op	*s_op;
	ibt_wrc_opcode_t	s_opcode;
	unsigned long		s_queued;
};

struct rdsv3_ib_recv_work {
	struct rdsv3_ib_incoming 	*r_ibinc;
	struct rdsv3_page_frag	*r_frag;
	ibt_all_wr_t		r_wr;
	ibt_wr_ds_t		r_sge[2];
};

struct rdsv3_ib_work_ring {
	uint32_t	w_nr;
	uint32_t	w_alloc_ptr;
	uint32_t	w_alloc_ctr;
	uint32_t	w_free_ptr;
	atomic_t	w_free_ctr;
};

struct rdsv3_ib_device;

struct rdsv3_ib_connection {

	struct list_node	ib_node;
	struct rdsv3_ib_device	*rds_ibdev;
	struct rdsv3_connection	*conn;

	/* alphabet soup, IBTA style */
	struct rdma_cm_id	*i_cm_id;
	struct ib_pd		*i_pd;
	struct rdsv3_hdrs_mr	*i_mr;
	struct ib_cq		*i_send_cq;
	struct ib_cq		*i_recv_cq;

	/* tx */
	struct rdsv3_ib_work_ring	i_send_ring;
	struct rdsv3_message	*i_rm;
	struct rdsv3_header	*i_send_hdrs;
	uint64_t		i_send_hdrs_dma;
	struct rdsv3_ib_send_work *i_sends;
	ibt_send_wr_t		*i_send_wrs;

	/* rx */
	ddi_taskq_t		*i_recv_tasklet;
	struct mutex		i_recv_mutex;
	struct rdsv3_ib_work_ring	i_recv_ring;
	struct rdsv3_ib_incoming	*i_ibinc;
	uint32_t		i_recv_data_rem;
	struct rdsv3_header	*i_recv_hdrs;
	uint64_t		i_recv_hdrs_dma;
	struct rdsv3_ib_recv_work *i_recvs;
	struct rdsv3_page_frag	i_frag;
	uint64_t		i_ack_recv;	/* last ACK received */
	processorid_t		i_recv_tasklet_cpuid;
	/* CPU to which the tasklet taskq should be bound */

	/* sending acks */
	unsigned long		i_ack_flags;
#ifndef KERNEL_HAS_ATOMIC64
	kmutex_t		i_ack_lock;	/* protect i_ack_next */
	uint64_t		i_ack_next;	/* next ACK to send */
#else
	atomic64_t		i_ack_next;	/* next ACK to send */
#endif
	struct rdsv3_header	*i_ack;
	ibt_send_wr_t		i_ack_wr;
	ibt_wr_ds_t		i_ack_sge;
	uint64_t		i_ack_dma;
	unsigned long		i_ack_queued;

	/*
	 * Flow control related information
	 *
	 * Our algorithm uses a pair variables that we need to access
	 * atomically - one for the send credits, and one posted
	 * recv credits we need to transfer to remote.
	 * Rather than protect them using a slow spinlock, we put both into
	 * a single atomic_t and update it using cmpxchg
	 */
	atomic_t		i_credits;

	/* Protocol version specific information */
	unsigned int		i_flowctl:1;	/* enable/disable flow ctl */

	/* Batched completions */
	unsigned int		i_unsignaled_wrs;
	long			i_unsignaled_bytes;
};

/* This assumes that atomic_t is at least 32 bits */
#define	IB_GET_SEND_CREDITS(v)	((v) & 0xffff)
#define	IB_GET_POST_CREDITS(v)	((v) >> 16)
#define	IB_SET_SEND_CREDITS(v)	((v) & 0xffff)
#define	IB_SET_POST_CREDITS(v)	((v) << 16)

struct rdsv3_ib_ipaddr {
	struct list_node	list;
	uint32_be_t		ipaddr;
};

struct rdsv3_ib_device {
	struct list_node	list;
	struct list		ipaddr_list;
	struct list		conn_list;
	ib_device_t		*dev;
	struct ib_pd		*pd;
	ibt_lkey_t		local_dma_lkey;
	struct rds_ib_mr_pool	*mr_pool;
	unsigned int		fmr_max_remaps;
	unsigned int		max_fmrs;
	unsigned int		fmr_message_size;
	int			max_sge;
	unsigned int		max_wrs;
	ibt_fmr_pool_hdl_t	fmr_pool_hdl;
	kmutex_t		spinlock;	/* protect the above */
	ibt_hca_attr_t		hca_attr;
};

/* bits for i_ack_flags */
#define	IB_ACK_IN_FLIGHT	0
#define	IB_ACK_REQUESTED	1

/* Magic WR_ID for ACKs */
#define	RDSV3_IB_ACK_WR_ID	(~(uint64_t)0)

struct rdsv3_ib_statistics {
	uint64_t	s_ib_connect_raced;
	uint64_t	s_ib_listen_closed_stale;
	uint64_t	s_ib_tx_cq_call;
	uint64_t	s_ib_tx_cq_event;
	uint64_t	s_ib_tx_ring_full;
	uint64_t	s_ib_tx_throttle;
	uint64_t	s_ib_tx_sg_mapping_failure;
	uint64_t	s_ib_tx_stalled;
	uint64_t	s_ib_tx_credit_updates;
	uint64_t	s_ib_rx_cq_call;
	uint64_t	s_ib_rx_cq_event;
	uint64_t	s_ib_rx_ring_empty;
	uint64_t	s_ib_rx_refill_from_cq;
	uint64_t	s_ib_rx_refill_from_thread;
	uint64_t	s_ib_rx_alloc_limit;
	uint64_t	s_ib_rx_credit_updates;
	uint64_t	s_ib_ack_sent;
	uint64_t	s_ib_ack_send_failure;
	uint64_t	s_ib_ack_send_delayed;
	uint64_t	s_ib_ack_send_piggybacked;
	uint64_t	s_ib_ack_received;
	uint64_t	s_ib_rdma_mr_alloc;
	uint64_t	s_ib_rdma_mr_free;
	uint64_t	s_ib_rdma_mr_used;
	uint64_t	s_ib_rdma_mr_pool_flush;
	uint64_t	s_ib_rdma_mr_pool_wait;
	uint64_t	s_ib_rdma_mr_pool_depleted;
};

extern struct rdsv3_workqueue_struct_s *rds_ib_wq;

/* ib.c */
extern struct rdsv3_transport rdsv3_ib_transport;
extern void rdsv3_ib_add_one(ib_device_t *device);
extern void rdsv3_ib_remove_one(ib_device_t *device);
extern struct ib_client rdsv3_ib_client;

extern unsigned int fmr_pool_size;
extern unsigned int fmr_message_size;
extern unsigned int rdsv3_ib_retry_count;

extern kmutex_t ib_nodev_conns_lock;
extern struct list ib_nodev_conns;

/* ib_cm.c */
int rdsv3_ib_conn_alloc(struct rdsv3_connection *conn, int gfp);
void rdsv3_ib_conn_free(void *arg);
int rdsv3_ib_conn_connect(struct rdsv3_connection *conn);
void rdsv3_ib_conn_shutdown(struct rdsv3_connection *conn);
void rdsv3_conn_drop(struct rdsv3_connection *conn);
int rdsv3_ib_cm_handle_connect(struct rdma_cm_id *cm_id,
    struct rdma_cm_event *event);
int rdsv3_ib_cm_initiate_connect(struct rdma_cm_id *cm_id);
void rdsv3_ib_cm_connect_complete(struct rdsv3_connection *conn,
    struct rdma_cm_event *event);

/* ib_rdma.c */
int rdsv3_ib_update_ipaddr(struct rdsv3_ib_device *rds_ibdev,
    uint32_be_t ipaddr);
void rdsv3_ib_add_conn(struct rdsv3_ib_device *rds_ibdev,
    struct rdsv3_connection *conn);
void rdsv3_ib_remove_conn(struct rdsv3_ib_device *rds_ibdev,
    struct rdsv3_connection *conn);
void __rdsv3_ib_destroy_conns(struct list *list, kmutex_t *list_lock);
static inline void rdsv3_ib_destroy_nodev_conns(void)
{
	__rdsv3_ib_destroy_conns(&ib_nodev_conns, &ib_nodev_conns_lock);
}
static inline void rdsv3_ib_destroy_conns(struct rdsv3_ib_device *rds_ibdev)
{
	__rdsv3_ib_destroy_conns(&rds_ibdev->conn_list, &rds_ibdev->spinlock);
}

int rdsv3_ib_create_mr_pool(struct rdsv3_ib_device *);
void rdsv3_ib_destroy_mr_pool(struct rdsv3_ib_device *);
void rdsv3_ib_get_mr_info(struct rdsv3_ib_device *rds_ibdev,
	struct rdsv3_info_rdma_connection *iinfo);
void *rdsv3_ib_get_mr(struct rdsv3_iovec *args, unsigned long nents,
	struct rdsv3_sock *rs, uint32_t *key_ret);
void rdsv3_ib_sync_mr(void *trans_private, int dir);
void rdsv3_ib_free_mr(void *trans_private, int invalidate);
void rdsv3_ib_flush_mrs(void);

/* ib_recv.c */
int rdsv3_ib_recv_init(void);
void rdsv3_ib_recv_exit(void);
int rdsv3_ib_recv(struct rdsv3_connection *conn);
int rdsv3_ib_recv_refill(struct rdsv3_connection *conn, int kptr_gfp,
    int page_gfp, int prefill);
void rdsv3_ib_inc_purge(struct rdsv3_incoming *inc);
void rdsv3_ib_inc_free(struct rdsv3_incoming *inc);
int rdsv3_ib_inc_copy_to_user(struct rdsv3_incoming *inc, uio_t *uiop,
    size_t size);
void rdsv3_ib_recv_cq_comp_handler(struct ib_cq *cq, void *context);
void rdsv3_ib_recv_tasklet_fn(void *data);
void rdsv3_ib_recv_init_ring(struct rdsv3_ib_connection *ic);
void rdsv3_ib_recv_clear_ring(struct rdsv3_ib_connection *ic);
void rdsv3_ib_recv_init_ack(struct rdsv3_ib_connection *ic);
void rdsv3_ib_attempt_ack(struct rdsv3_ib_connection *ic);
void rdsv3_ib_ack_send_complete(struct rdsv3_ib_connection *ic);
uint64_t rdsv3_ib_piggyb_ack(struct rdsv3_ib_connection *ic);

/* ib_ring.c */
void rdsv3_ib_ring_init(struct rdsv3_ib_work_ring *ring, uint32_t nr);
void rdsv3_ib_ring_resize(struct rdsv3_ib_work_ring *ring, uint32_t nr);
uint32_t rdsv3_ib_ring_alloc(struct rdsv3_ib_work_ring *ring, uint32_t val,
    uint32_t *pos);
void rdsv3_ib_ring_free(struct rdsv3_ib_work_ring *ring, uint32_t val);
void rdsv3_ib_ring_unalloc(struct rdsv3_ib_work_ring *ring, uint32_t val);
int rdsv3_ib_ring_empty(struct rdsv3_ib_work_ring *ring);
int rdsv3_ib_ring_low(struct rdsv3_ib_work_ring *ring);
uint32_t rdsv3_ib_ring_oldest(struct rdsv3_ib_work_ring *ring);
uint32_t rdsv3_ib_ring_completed(struct rdsv3_ib_work_ring *ring,
    uint32_t wr_id, uint32_t oldest);
extern rdsv3_wait_queue_t rdsv3_ib_ring_empty_wait;

/* ib_send.c */
void rdsv3_ib_xmit_complete(struct rdsv3_connection *conn);
int rdsv3_ib_xmit(struct rdsv3_connection *conn, struct rdsv3_message *rm,
    unsigned int hdr_off, unsigned int sg, unsigned int off);
void rdsv3_ib_send_cq_comp_handler(struct ib_cq *cq, void *context);
void rdsv3_ib_send_init_ring(struct rdsv3_ib_connection *ic);
void rdsv3_ib_send_clear_ring(struct rdsv3_ib_connection *ic);
int rdsv3_ib_xmit_rdma(struct rdsv3_connection *conn, struct rdsv3_rdma_op *op);
void rdsv3_ib_send_add_credits(struct rdsv3_connection *conn,
    unsigned int credits);
void rdsv3_ib_advertise_credits(struct rdsv3_connection *conn,
    unsigned int posted);
int rdsv3_ib_send_grab_credits(struct rdsv3_ib_connection *ic, uint32_t wanted,
    uint32_t *adv_credits, int need_posted, int max_posted);

/* ib_stats.c */
RDSV3_DECLARE_PER_CPU(struct rdsv3_ib_statistics, rdsv3_ib_stats);
#define	rdsv3_ib_stats_inc(member) rdsv3_stats_inc_which(rdsv3_ib_stats, member)
unsigned int rdsv3_ib_stats_info_copy(struct rdsv3_info_iterator *iter,
    unsigned int avail);

/* ib_sysctl.c */
int rdsv3_ib_sysctl_init(void);
void rdsv3_ib_sysctl_exit(void);
extern unsigned long rdsv3_ib_sysctl_max_send_wr;
extern unsigned long rdsv3_ib_sysctl_max_recv_wr;
extern unsigned long rdsv3_ib_sysctl_max_unsig_wrs;
extern unsigned long rdsv3_ib_sysctl_max_unsig_bytes;
extern unsigned long rdsv3_ib_sysctl_max_recv_allocation;
extern unsigned int rdsv3_ib_sysctl_flow_control;

#endif /* _RDSV3_IB_H */
