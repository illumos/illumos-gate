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
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _RDSV3_IMPL_H
#define	_RDSV3_IMPL_H

#include <sys/atomic.h>

/*
 * This file is only present in Solaris
 */

#ifdef __cplusplus
extern "C" {
#endif

extern dev_info_t	*rdsv3_dev_info;

#define	uint16_be_t	uint16_t
#define	uint32_be_t	uint32_t
#define	uint64_be_t	uint64_t

/*
 * RDS Well known service id
 * Format: 0x1h00144Fhhhhhhhh
 *         "00144F" is the Sun OUI
 * 'h' can be any hex-decimal digit.
 */
#define	RDS_SERVICE_ID		0x1000144F00000001ULL

/*
 * Atomic operations
 */
typedef unsigned int	atomic_t;
#define	ATOMIC_INIT(a)	a

#define	atomic_get(p)	(*(p))

#define	atomic_cmpset_long(p, c, n) \
	((c == atomic_cas_uint(p, c, n)) ? c : -1)

#define	atomic_dec_and_test(a)			\
	(atomic_dec_uint_nv((a)) == 0)

#define	atomic_cmpxchg(a, o, n)			\
	atomic_cas_uint(a, o, n)

#ifdef _LP64
#define	set_bit(b, p) \
	atomic_or_ulong(((volatile ulong_t *)(void *)(p)) + ((b) >> 6), \
	1ul << ((b) & 0x3f))

#define	clear_bit(b, p) \
	atomic_and_ulong(((volatile ulong_t *)(void *)(p)) + ((b) >> 6), \
	~(1ul << ((b) & 0x3f)))

#define	test_bit(b, p) \
	(((volatile ulong_t *)(void *)(p))[(b) >> 6] & (1ul << ((b) & 0x3f)))

#define	test_and_set_bit(b, p) \
	atomic_set_long_excl(((ulong_t *)(void *)(p)) +		\
	    ((b) >> 6), ((b) & 0x3f))
#define	test_and_clear_bit(b, p) \
	!atomic_clear_long_excl(((ulong_t *)(void *)(p)) + ((b) >> 6), \
	((b) & 0x3f))
#else
#define	set_bit(b, p) \
	atomic_or_uint(((volatile uint_t *)(void *)p) + (b >> 5), \
	1ul << (b & 0x1f))

#define	clear_bit(b, p) \
	atomic_and_uint(((volatile uint_t *)(void *)p) + (b >> 5), \
	~(1ul << (b & 0x1f)))

#define	test_bit(b, p) \
	(((volatile uint_t *)(void *)p)[b >> 5] & (1ul << (b & 0x1f)))

#define	test_and_set_bit(b, p) \
	atomic_set_long_excl(((ulong_t *)(void *)p) + (b >> 5), (b & 0x1f))
#define	test_and_clear_bit(b, p) \
	!atomic_clear_long_excl(((ulong_t *)(void *)p) + (b >> 5), (b & 0x1f))
#endif

/*
 * These macros and/or constants are used instead of Linux
 * generic_{test,__{clear,set}}_le_bit().
 */
#if defined(sparc)
#define	LE_BIT_XOR	((BITS_PER_LONG-1) & ~0x7)
#else
#define	LE_BIT_XOR	0
#endif

#define	set_le_bit(b, p)	set_bit(b ^ LE_BIT_XOR, p)
#define	clear_le_bit(b, p)	clear_bit(b ^ LE_BIT_XOR, p)
#define	test_le_bit(b, p)	test_bit(b ^ LE_BIT_XOR, p)

uint_t	rdsv3_one_sec_in_hz;

#define	jiffies	100
#define	HZ	(drv_hztousec(1))
/* setting this to PAGESIZE throws build errors */
#define	PAGE_SIZE	4096 /* xxx - fix this */
#define	BITS_PER_LONG	(sizeof (unsigned long) * 8)

/* debug */
#define	RDSV3_PANIC()		cmn_err(CE_PANIC, "Panic forced by RDSV3");

/* ERR */
#define	MAX_ERRNO	4095
#define	ERR_PTR(x)	((void *)(uintptr_t)x)
#define	IS_ERR(ptr)	(((uintptr_t)ptr) >= (uintptr_t)-MAX_ERRNO)
#define	PTR_ERR(ptr)	(int)(uintptr_t)ptr

#define	MAX_SCHEDULE_TIMEOUT	(~0UL>>1)

/* list */
/* copied and modified list_remove_node */
#define	list_remove_node(node)						\
	if ((node)->list_next != NULL) {				\
		(node)->list_prev->list_next = (node)->list_next;	\
		(node)->list_next->list_prev = (node)->list_prev;	\
		(node)->list_next = (node)->list_prev = NULL;		\
	}

#define	list_splice(src, dst)	{				\
	list_create(dst, (src)->list_size, (src)->list_offset);	\
	list_move_tail(dst, src);				\
	}

#define	RDSV3_FOR_EACH_LIST_NODE(objp, listp, member)	\
	for (objp = list_head(listp); objp; objp = list_next(listp, objp))
#define	RDSV3_FOR_EACH_LIST_NODE_SAFE(objp, tmp, listp, member)	\
	for (objp = list_head(listp), tmp = (objp != NULL) ?	\
	    list_next(listp, objp) : NULL;			\
	    objp;						\
	    objp = tmp, tmp = (objp != NULL) ?			\
	    list_next(listp, objp) : NULL)

/* simulate wait_queue_head_t */
typedef struct rdsv3_wait_queue_s {
	kmutex_t	waitq_mutex;
	kcondvar_t	waitq_cv;
	uint_t		waitq_waiters;
} rdsv3_wait_queue_t;

#define	rdsv3_init_waitqueue(waitqp)					\
	mutex_init(&(waitqp)->waitq_mutex, NULL, MUTEX_DRIVER, NULL);	\
	cv_init(&(waitqp)->waitq_cv, NULL, CV_DRIVER, NULL);		\
	(waitqp)->waitq_waiters = 0

#define	rdsv3_exit_waitqueue(waitqp)					\
	ASSERT((waitqp)->waitq_waiters == 0);				\
	mutex_destroy(&(waitqp)->waitq_mutex);				\
	cv_destroy(&(waitqp)->waitq_cv)

#define	rdsv3_wake_up(waitqp)	{					\
	mutex_enter(&(waitqp)->waitq_mutex);				\
	if ((waitqp)->waitq_waiters)					\
		cv_signal(&(waitqp)->waitq_cv);				\
	mutex_exit(&(waitqp)->waitq_mutex);				\
	}

#define	rdsv3_wake_up_all(waitqp)	{				\
	mutex_enter(&(waitqp)->waitq_mutex);				\
	if ((waitqp)->waitq_waiters)					\
		cv_broadcast(&(waitqp)->waitq_cv);			\
	mutex_exit(&(waitqp)->waitq_mutex);				\
	}

/* analogous to cv_wait */
#define	rdsv3_wait_event(waitq, condition)				\
{									\
	mutex_enter(&(waitq)->waitq_mutex);				\
	(waitq)->waitq_waiters++;					\
	while (!(condition)) {						\
		cv_wait(&(waitq)->waitq_cv, &(waitq)->waitq_mutex);	\
	}								\
	(waitq)->waitq_waiters--;					\
	mutex_exit(&(waitq)->waitq_mutex);				\
}

/* analogous to cv_wait_sig */
#define	rdsv3_wait_sig(waitqp, condition)				\
(									\
{									\
	int cv_return = 1;						\
	mutex_enter(&(waitqp)->waitq_mutex);				\
	(waitqp)->waitq_waiters++;					\
	while (!(condition)) {						\
		cv_return = cv_wait_sig(&(waitqp)->waitq_cv,		\
		    &(waitqp)->waitq_mutex);				\
		if (cv_return == 0) {					\
			break;						\
		}							\
	}								\
	(waitqp)->waitq_waiters--;					\
	mutex_exit(&(waitqp)->waitq_mutex);				\
	cv_return;							\
}									\
)

#define	SOCK_DEAD	1ul

/* socket */
typedef struct rsock {
	sock_upper_handle_t	sk_upper_handle;
	sock_upcalls_t		*sk_upcalls;

	kmutex_t		sk_lock;
	ulong_t			sk_flag;
	rdsv3_wait_queue_t	*sk_sleep; /* Also protected by rs_recv_lock */
	int			sk_sndbuf;
	int			sk_rcvbuf;
	atomic_t		sk_refcount;

	struct rdsv3_sock	*sk_protinfo;
} rsock_t;

typedef struct rdsv3_conn_info_s {
	uint32_be_t  c_laddr;
	uint32_be_t  c_faddr;
} rdsv3_conn_info_t;

/* WQ */
typedef struct rdsv3_workqueue_struct_s {
	kmutex_t wq_lock;
	uint_t	wq_state;
	int	wq_pending;
	list_t	wq_queue;
} rdsv3_workqueue_struct_t;

struct rdsv3_work_s;
typedef void (*rdsv3_work_func_t)(struct rdsv3_work_s *);
typedef struct rdsv3_work_s {
	list_node_t	work_item;
	rdsv3_work_func_t	func;
} rdsv3_work_t;

/* simulate delayed_work */
typedef struct rdsv3_delayed_work_s {
	kmutex_t		lock;
	rdsv3_work_t		work;
	timeout_id_t		timeid;
	rdsv3_workqueue_struct_t	*wq;
} rdsv3_delayed_work_t;

#define	RDSV3_INIT_WORK(wp, f)	(wp)->func = f
#define	RDSV3_INIT_DELAYED_WORK(dwp, f)				\
	(dwp)->work.func = f;					\
	mutex_init(&(dwp)->lock, NULL, MUTEX_DRIVER, NULL);	\
	(dwp)->timeid = 0

/* simulate scatterlist */
struct rdsv3_scatterlist {
	caddr_t		vaddr;
	uint_t		length;
	ibt_wr_ds_t	*sgl;
	ibt_mi_hdl_t	mihdl;
};
#define	rdsv3_sg_page(scat)	(scat)->vaddr
#define	rdsv3_sg_len(scat)	(scat)->length
#define	rdsv3_sg_set_page(scat, pg, len, off)		\
	(scat)->vaddr = (caddr_t)(pg + off);		\
	(scat)->length = len
#define	rdsv3_ib_sg_dma_len(dev, scat)	rdsv3_sg_len(scat)

/* copied from sys/socket.h */
#if defined(__sparc)
/* To maintain backward compatibility, alignment needs to be 8 on sparc. */
#define	_CMSG_HDR_ALIGNMENT	8
#else
/* for __i386 (and other future architectures) */
#define	_CMSG_HDR_ALIGNMENT	4
#endif	/* defined(__sparc) */

/*
 * The cmsg headers (and macros dealing with them) were made available as
 * part of UNIX95 and hence need to be protected with a _XPG4_2 define.
 */
#define	_CMSG_DATA_ALIGNMENT	(sizeof (int))
#define	_CMSG_HDR_ALIGN(x)	(((uintptr_t)(x) + _CMSG_HDR_ALIGNMENT - 1) & \
				    ~(_CMSG_HDR_ALIGNMENT - 1))
#define	_CMSG_DATA_ALIGN(x)	(((uintptr_t)(x) + _CMSG_DATA_ALIGNMENT - 1) & \
				    ~(_CMSG_DATA_ALIGNMENT - 1))
#define	CMSG_DATA(c)							\
	((unsigned char *)_CMSG_DATA_ALIGN((struct cmsghdr *)(c) + 1))

#define	CMSG_FIRSTHDR(m)						\
	(((m)->msg_controllen < sizeof (struct cmsghdr)) ?		\
	    (struct cmsghdr *)0 : (struct cmsghdr *)((m)->msg_control))

#define	CMSG_NXTHDR(m, c)						\
	(((c) == 0) ? CMSG_FIRSTHDR(m) :			\
	((((uintptr_t)_CMSG_HDR_ALIGN((char *)(c) +			\
	((struct cmsghdr *)(c))->cmsg_len) + sizeof (struct cmsghdr)) >	\
	(((uintptr_t)((struct msghdr *)(m))->msg_control) +		\
	((uintptr_t)((struct msghdr *)(m))->msg_controllen))) ?		\
	((struct cmsghdr *)0) :						\
	((struct cmsghdr *)_CMSG_HDR_ALIGN((char *)(c) +		\
	    ((struct cmsghdr *)(c))->cmsg_len))))

/* Amount of space + padding needed for a message of length l */
#define	CMSG_SPACE(l)							\
	((unsigned int)_CMSG_HDR_ALIGN(sizeof (struct cmsghdr) + (l)))

/* Value to be used in cmsg_len, does not include trailing padding */
#define	CMSG_LEN(l)							\
	((unsigned int)_CMSG_DATA_ALIGN(sizeof (struct cmsghdr)) + (l))

/* OFUV -> IB */
#define	RDSV3_IBDEV2HCAHDL(device)	(device)->hca_hdl
#define	RDSV3_QP2CHANHDL(qp)		(qp)->ibt_qp
#define	RDSV3_PD2PDHDL(pd)		(pd)->ibt_pd
#define	RDSV3_CQ2CQHDL(cq)		(cq)->ibt_cq

struct rdsv3_hdrs_mr {
	ibt_lkey_t	lkey;
	caddr_t		addr;
	size_t		size;
	ibt_mr_hdl_t	hdl;
};

/* rdsv3_impl.c */
void rdsv3_trans_init();
boolean_t rdsv3_capable_interface(struct lifreq *lifrp);
int rdsv3_do_ip_ioctl(ksocket_t so4, void **ipaddrs, int *size, int *nifs);
int rdsv3_do_ip_ioctl_old(ksocket_t so4, void **ipaddrs, int *size, int *nifs);
boolean_t rdsv3_isloopback(ipaddr_t addr);
void rdsv3_cancel_delayed_work(rdsv3_delayed_work_t *dwp);
void rdsv3_flush_workqueue(rdsv3_workqueue_struct_t *wq);
void rdsv3_queue_work(rdsv3_workqueue_struct_t *wq, rdsv3_work_t *wp);
void rdsv3_queue_delayed_work(rdsv3_workqueue_struct_t *wq,
    rdsv3_delayed_work_t *dwp, uint_t delay);
struct rsock *rdsv3_sk_alloc();
void rdsv3_sock_init_data(struct rsock *sk);
void rdsv3_sock_exit_data(struct rsock *sk);
void rdsv3_destroy_task_workqueue(rdsv3_workqueue_struct_t *wq);
rdsv3_workqueue_struct_t *rdsv3_create_task_workqueue(char *name);
int rdsv3_conn_constructor(void *buf, void *arg, int kmflags);
void rdsv3_conn_destructor(void *buf, void *arg);
int rdsv3_conn_compare(const void *conn1, const void *conn2);
void rdsv3_loop_init();
int rdsv3_mr_compare(const void *mr1, const void *mr2);
int rdsv3_put_cmsg(struct nmsghdr *msg, int level, int type, size_t size,
    void *payload);
int rdsv3_verify_bind_address(ipaddr_t addr);
uint16_t rdsv3_ip_fast_csum(void *buffer, size_t length);
uint_t rdsv3_ib_dma_map_sg(struct ib_device *dev, struct rdsv3_scatterlist
	*scat, uint_t num);
void rdsv3_ib_dma_unmap_sg(ib_device_t *dev, struct rdsv3_scatterlist *scat,
    uint_t num);
static inline void
rdsv3_sk_sock_hold(struct rsock *sk)
{
	atomic_inc_32(&sk->sk_refcount);
}
static inline void
rdsv3_sk_sock_put(struct rsock *sk)
{
	if (atomic_dec_and_test(&sk->sk_refcount))
		rdsv3_sock_exit_data(sk);
}
static inline int
rdsv3_sk_sock_flag(struct rsock *sk, uint_t flag)
{
	return (test_bit(flag, &sk->sk_flag));
}
static inline void
rdsv3_sk_sock_orphan(struct rsock *sk)
{
	set_bit(SOCK_DEAD, &sk->sk_flag);
}

#define	rdsv3_sndtimeo(a, b)	b ? 0 : 3600	/* check this value on linux */
#define	rdsv3_rcvtimeo(a, b)	b ? 0 : 3600	/* check this value on linux */

void rdsv3_ib_free_conn(void *arg);

#ifdef	__cplusplus
}
#endif

#endif /* _RDSV3_IMPL_H */
