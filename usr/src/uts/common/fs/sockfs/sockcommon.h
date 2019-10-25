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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef	_SOCKCOMMON_H_
#define	_SOCKCOMMON_H_

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/filio.h>
#include <sys/socket_proto.h>

struct sonode;

extern kmem_cache_t *socket_cache;

/*
 * Socket access functions
 *
 * The following functions should only be used by sockfs, and are common
 * functions that can be used both by kernel sockets (i.e., no file
 * descriptors should ever be expected, or created), and to implement
 * the socket system calls.
 */
extern struct sonode *socket_create(int, int, int, char *, char *, int, int,
    struct cred *, int *);
extern struct sonode *socket_newconn(struct sonode *, sock_lower_handle_t,
    sock_downcalls_t *, int, int *);
extern int socket_bind(struct sonode *, struct sockaddr *, socklen_t, int,
    struct cred *);
extern int socket_accept(struct sonode *, int, struct cred *, struct sonode **);
extern int socket_listen(struct sonode *, int, struct cred *);
extern int socket_connect(struct sonode *, struct sockaddr *,
    socklen_t, int, int, struct cred *);
extern int socket_getpeername(struct sonode *, struct sockaddr *, socklen_t *,
    boolean_t, struct cred *);
extern int socket_getsockname(struct sonode *, struct sockaddr *, socklen_t *,
    struct cred *);
extern int socket_shutdown(struct sonode *, int, struct cred *);
extern int socket_getsockopt(struct sonode *, int, int, void *, socklen_t *,
    int, struct cred *);
extern int socket_setsockopt(struct sonode *, int, int, const void *,
    socklen_t, struct cred *);
extern int socket_recvmsg(struct sonode *, struct nmsghdr *, struct uio *,
    struct cred *);
extern int socket_sendmsg(struct sonode *, struct nmsghdr *, struct uio *,
    struct cred *);
extern int socket_sendmblk(struct sonode *, struct nmsghdr *, int,
    struct cred *, mblk_t **);
extern int socket_ioctl(struct sonode *, int, intptr_t, int, struct cred *,
    int32_t *);
extern int socket_poll(struct sonode *, short, int, short *,
    struct pollhead **);
extern int socket_close(struct sonode *, int, struct cred *);
extern void socket_destroy(struct sonode *);

/*
 * Cancel the socket push timer.
 */
#define	SOCKET_TIMER_CANCEL(so) {					\
	timeout_id_t tid;						\
									\
	ASSERT(MUTEX_HELD(&(so)->so_lock));				\
	if ((so)->so_rcv_timer_tid != 0) {				\
		tid = (so)->so_rcv_timer_tid;				\
		(so)->so_rcv_timer_tid = 0;				\
		mutex_exit(&(so)->so_lock);				\
									\
		(void) untimeout(tid);					\
									\
		mutex_enter(&(so)->so_lock);				\
	}								\
}

#define	SOCKET_TIMER_START(so) {					\
	ASSERT(MUTEX_HELD(&(so)->so_lock));				\
	if ((so)->so_rcv_timer_interval != SOCKET_NO_RCVTIMER) {	\
		(so)->so_rcv_timer_tid = timeout(so_timer_callback,	\
		    (so), MSEC_TO_TICK((so)->so_rcv_timer_interval));	\
	}								\
}

/* Common sonode ops not support */
extern int so_listen_notsupp(struct sonode *, int, struct cred *);
extern int so_accept_notsupp(struct sonode *, int, struct cred *,
    struct sonode **);
extern int so_getpeername_notsupp(struct sonode *, struct sockaddr *,
    socklen_t *, boolean_t, struct cred *);
extern int so_shutdown_notsupp(struct sonode *, int, struct cred *);
extern int so_sendmblk_notsupp(struct sonode *, struct nmsghdr *,
    int, struct cred *, mblk_t **);

/* Common sonode ops */
extern int so_init(struct sonode *, struct sonode *, struct cred *, int);
extern int so_accept(struct sonode *, int, struct cred *, struct sonode **);
extern int so_bind(struct sonode *, struct sockaddr *, socklen_t, int,
    struct cred *);
extern int so_listen(struct sonode *, int, struct cred *);
extern int so_connect(struct sonode *, struct sockaddr *,
    socklen_t, int, int, struct cred *);
extern int so_getsockopt(struct sonode *, int, int, void *,
    socklen_t *, int, struct cred *);
extern int so_setsockopt(struct sonode *, int, int, const void *,
    socklen_t, struct cred *);
extern int so_getpeername(struct sonode *, struct sockaddr *,
    socklen_t *, boolean_t, struct cred *);
extern int so_getsockname(struct sonode *, struct sockaddr *,
    socklen_t *, struct cred *);
extern int so_ioctl(struct sonode *, int, intptr_t, int, struct cred *,
    int32_t *);
extern int so_poll(struct sonode *, short, int, short *,
    struct pollhead **);
extern int so_sendmsg(struct sonode *, struct nmsghdr *, struct uio *,
    struct cred *);
extern int so_sendmblk_impl(struct sonode *, struct nmsghdr *, int,
    struct cred *, mblk_t **, struct sof_instance *, boolean_t);
extern int so_sendmblk(struct sonode *, struct nmsghdr *, int,
    struct cred *, mblk_t **);
extern int so_recvmsg(struct sonode *, struct nmsghdr *, struct uio *,
    struct cred *);
extern int so_shutdown(struct sonode *, int, struct cred *);
extern int so_close(struct sonode *, int, struct cred *);

extern int so_tpi_fallback(struct sonode *, struct cred *);

/* Common upcalls */
extern sock_upper_handle_t so_newconn(sock_upper_handle_t,
    sock_lower_handle_t, sock_downcalls_t *, struct cred *, pid_t,
    sock_upcalls_t **);
extern void	so_set_prop(sock_upper_handle_t,
	struct sock_proto_props *);
extern ssize_t	so_queue_msg(sock_upper_handle_t, mblk_t *, size_t, int,
    int *, boolean_t *);
extern ssize_t	so_queue_msg_impl(struct sonode *, mblk_t *, size_t, int,
    int *, boolean_t *, struct sof_instance *);
extern void	so_signal_oob(sock_upper_handle_t, ssize_t);

extern void	so_connected(sock_upper_handle_t, sock_connid_t, struct cred *,
    pid_t);
extern int	so_disconnected(sock_upper_handle_t, sock_connid_t, int);
extern void	so_txq_full(sock_upper_handle_t, boolean_t);
extern void	so_opctl(sock_upper_handle_t, sock_opctl_action_t, uintptr_t);
extern vnode_t *so_get_vnode(sock_upper_handle_t);

/* Common misc. functions */

	/* accept queue */
extern int	so_acceptq_enqueue(struct sonode *, struct sonode *);
extern int	so_acceptq_enqueue_locked(struct sonode *, struct sonode *);
extern int	so_acceptq_dequeue(struct sonode *, boolean_t,
    struct sonode **);
extern void	so_acceptq_flush(struct sonode *, boolean_t);

	/* connect */
extern int	so_wait_connected(struct sonode *, boolean_t, sock_connid_t);

	/* send */
extern int	so_snd_wait_qnotfull(struct sonode *, boolean_t);
extern void	so_snd_qfull(struct sonode *so);
extern void	so_snd_qnotfull(struct sonode *so);

extern int	socket_chgpgrp(struct sonode *, pid_t);
extern void	socket_sendsig(struct sonode *, int);
extern int	so_dequeue_msg(struct sonode *, mblk_t **, struct uio *,
    rval_t *, int);
extern void	so_enqueue_msg(struct sonode *, mblk_t *, size_t);
extern void	so_process_new_message(struct sonode *, mblk_t *, mblk_t *);
extern boolean_t	so_check_flow_control(struct sonode *);

extern mblk_t	*socopyinuio(uio_t *, ssize_t, size_t, ssize_t, size_t, int *);
extern mblk_t	*socopyoutuio(mblk_t *, struct uio *, ssize_t, int *);

extern boolean_t somsghasdata(mblk_t *);
extern void	so_rcv_flush(struct sonode *);
extern int	sorecvoob(struct sonode *, struct nmsghdr *, struct uio *,
		    int, boolean_t);

extern void	so_timer_callback(void *);

extern struct sonode *socket_sonode_create(struct sockparams *, int, int, int,
    int, int, int *, struct cred *);

extern void socket_sonode_destroy(struct sonode *);
extern int socket_init_common(struct sonode *, struct sonode *, int flags,
    struct cred *);
extern int socket_getopt_common(struct sonode *, int, int, void *, socklen_t *,
    int);
extern int socket_ioctl_common(struct sonode *, int, intptr_t, int,
    struct cred *, int32_t *);
extern int socket_strioc_common(struct sonode *, int, intptr_t, int,
    struct cred *, int32_t *);

extern int so_zcopy_wait(struct sonode *);
extern int so_get_mod_version(struct sockparams *);

/* Notification functions */
extern void	so_notify_connected(struct sonode *);
extern void	so_notify_disconnecting(struct sonode *);
extern void	so_notify_disconnected(struct sonode *, boolean_t, int);
extern void	so_notify_writable(struct sonode *);
extern void	so_notify_data(struct sonode *, size_t);
extern void	so_notify_oobsig(struct sonode *);
extern void	so_notify_oobdata(struct sonode *, boolean_t);
extern void	so_notify_eof(struct sonode *);
extern void	so_notify_newconn(struct sonode *);
extern void	so_notify_shutdown(struct sonode *);
extern void	so_notify_error(struct sonode *);

/* Common sonode functions */
extern int	sonode_constructor(void *, void *, int);
extern void	sonode_destructor(void *, void *);
extern void	sonode_init(struct sonode *, struct sockparams *,
    int, int, int, sonodeops_t *);
extern void	sonode_fini(struct sonode *);

/*
 * Event flags to socket_sendsig().
 */
#define	SOCKETSIG_WRITE	0x1
#define	SOCKETSIG_READ	0x2
#define	SOCKETSIG_URG	0x4

extern sonodeops_t so_sonodeops;
extern sock_upcalls_t so_upcalls;

#ifdef	__cplusplus
}
#endif
#endif /* _SOCKCOMMON_H_ */
