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
 */

#ifndef _SYS_SOCKET_PROTO_H_
#define	_SYS_SOCKET_PROTO_H_

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/socket.h>
#include <sys/stream.h>

/*
 * Generation count
 */
typedef uint64_t sock_connid_t;

#define	SOCK_CONNID_INIT(id) {	\
	(id) = 0;		\
}
#define	SOCK_CONNID_BUMP(id)		(++(id))
#define	SOCK_CONNID_LT(id1, id2)	((int64_t)((id1)-(id2)) < 0)

/* Socket protocol properties */
struct sock_proto_props {
	uint_t sopp_flags;		/* options to set */
	ushort_t sopp_wroff;		/* write offset */
	ssize_t sopp_txhiwat;		/* tx hi water mark */
	ssize_t sopp_txlowat;		/* tx lo water mark */
	ssize_t	sopp_rxhiwat;		/* recv high water mark */
	ssize_t	sopp_rxlowat;		/* recv low water mark */
	ssize_t sopp_maxblk;		/* maximum message block size */
	ssize_t sopp_maxpsz;		/* maximum packet size */
	ssize_t sopp_minpsz;		/* minimum packet size */
	ushort_t sopp_tail;		/* space available at the end */
	uint_t	sopp_zcopyflag;		/* zero copy flag */
	boolean_t sopp_oobinline;	/* OOB inline */
	uint_t sopp_rcvtimer;		/* delayed recv notification (time) */
	uint32_t sopp_rcvthresh;	/* delayed recv notification (bytes) */
	socklen_t sopp_maxaddrlen;	/* maximum size of protocol address */
	boolean_t sopp_loopback;	/* loopback connection */
};

/* flags to determine which socket options are set */
#define	SOCKOPT_WROFF		0x0001	/* set write offset */
#define	SOCKOPT_RCVHIWAT	0x0002	/* set read side high water */
#define	SOCKOPT_RCVLOWAT	0x0004	/* set read side high water */
#define	SOCKOPT_MAXBLK		0x0008	/* set maximum message block size */
#define	SOCKOPT_TAIL		0x0010	/* set the extra allocated space */
#define	SOCKOPT_ZCOPY		0x0020	/* set/unset zero copy for sendfile */
#define	SOCKOPT_MAXPSZ		0x0040	/* set maxpsz for protocols */
#define	SOCKOPT_OOBINLINE	0x0080	/* set oob inline processing */
#define	SOCKOPT_RCVTIMER	0x0100
#define	SOCKOPT_RCVTHRESH	0x0200
#define	SOCKOPT_MAXADDRLEN	0x0400	/* set max address length */
#define	SOCKOPT_MINPSZ		0x0800	/* set minpsz for protocols */
#define	SOCKOPT_LOOPBACK	0x1000	/* set loopback */

#define	IS_SO_OOB_INLINE(so)	((so)->so_proto_props.sopp_oobinline)

#ifdef _KERNEL

struct T_capability_ack;

typedef struct sock_upcalls_s sock_upcalls_t;
typedef struct sock_downcalls_s sock_downcalls_t;

/*
 * Upcall and downcall handle for sockfs and transport layer.
 */
typedef struct __sock_upper_handle *sock_upper_handle_t;
typedef struct __sock_lower_handle *sock_lower_handle_t;

struct sock_downcalls_s {
	void	(*sd_activate)(sock_lower_handle_t, sock_upper_handle_t,
		    sock_upcalls_t *, int, cred_t *);
	int	(*sd_accept)(sock_lower_handle_t, sock_lower_handle_t,
		    sock_upper_handle_t, cred_t *);
	int	(*sd_bind)(sock_lower_handle_t, struct sockaddr *, socklen_t,
		    cred_t *);
	int	(*sd_listen)(sock_lower_handle_t, int, cred_t *);
	int	(*sd_connect)(sock_lower_handle_t, const struct sockaddr *,
		    socklen_t, sock_connid_t *, cred_t *);
	int	(*sd_getpeername)(sock_lower_handle_t, struct sockaddr *,
		    socklen_t *, cred_t *);
	int	(*sd_getsockname)(sock_lower_handle_t, struct sockaddr *,
		    socklen_t *, cred_t *);
	int	(*sd_getsockopt)(sock_lower_handle_t, int, int, void *,
		    socklen_t *, cred_t *);
	int	(*sd_setsockopt)(sock_lower_handle_t, int, int, const void *,
		    socklen_t, cred_t *);
	int	(*sd_send)(sock_lower_handle_t, mblk_t *, struct nmsghdr *,
		    cred_t *);
	int	(*sd_send_uio)(sock_lower_handle_t, uio_t *, struct nmsghdr *,
		    cred_t *);
	int	(*sd_recv_uio)(sock_lower_handle_t, uio_t *, struct nmsghdr *,
		    cred_t *);
	short	(*sd_poll)(sock_lower_handle_t, short, int, cred_t *);
	int	(*sd_shutdown)(sock_lower_handle_t, int, cred_t *);
	void	(*sd_clr_flowctrl)(sock_lower_handle_t);
	int	(*sd_ioctl)(sock_lower_handle_t, int, intptr_t, int,
		    int32_t *, cred_t *);
	int	(*sd_close)(sock_lower_handle_t, int, cred_t *);
};

typedef sock_lower_handle_t (*so_proto_create_func_t)(int, int, int,
    sock_downcalls_t **, uint_t *, int *, int, cred_t *);

typedef struct sock_quiesce_arg {
	mblk_t *soqa_exdata_mp;
	mblk_t *soqa_urgmark_mp;
} sock_quiesce_arg_t;
typedef mblk_t *(*so_proto_quiesced_cb_t)(sock_upper_handle_t,
    sock_quiesce_arg_t *, struct T_capability_ack *, struct sockaddr *,
    socklen_t, struct sockaddr *, socklen_t, short);
typedef int (*so_proto_fallback_func_t)(sock_lower_handle_t, queue_t *,
    boolean_t, so_proto_quiesced_cb_t, sock_quiesce_arg_t *);

/*
 * These functions return EOPNOTSUPP and are intended for the sockfs
 * developer that doesn't wish to supply stubs for every function themselves.
 */
extern int sock_accept_notsupp(sock_lower_handle_t, sock_lower_handle_t,
    sock_upper_handle_t, cred_t *);
extern int sock_bind_notsupp(sock_lower_handle_t, struct sockaddr *,
    socklen_t, cred_t *);
extern int sock_listen_notsupp(sock_lower_handle_t, int, cred_t *);
extern int sock_connect_notsupp(sock_lower_handle_t,
    const struct sockaddr *, socklen_t, sock_connid_t *, cred_t *);
extern int sock_getpeername_notsupp(sock_lower_handle_t, struct sockaddr *,
    socklen_t *, cred_t *);
extern int sock_getsockname_notsupp(sock_lower_handle_t, struct sockaddr *,
    socklen_t *, cred_t *);
extern int sock_getsockopt_notsupp(sock_lower_handle_t, int, int, void *,
    socklen_t *, cred_t *);
extern int sock_setsockopt_notsupp(sock_lower_handle_t, int, int,
    const void *, socklen_t, cred_t *);
extern int sock_send_notsupp(sock_lower_handle_t, mblk_t *,
    struct nmsghdr *, cred_t *);
extern int sock_send_uio_notsupp(sock_lower_handle_t, uio_t *,
    struct nmsghdr *, cred_t *);
extern int sock_recv_uio_notsupp(sock_lower_handle_t, uio_t *,
    struct nmsghdr *, cred_t *);
extern short sock_poll_notsupp(sock_lower_handle_t, short, int, cred_t *);
extern int sock_shutdown_notsupp(sock_lower_handle_t, int, cred_t *);
extern void sock_clr_flowctrl_notsupp(sock_lower_handle_t);
extern int sock_ioctl_notsupp(sock_lower_handle_t, int, intptr_t, int,
    int32_t *, cred_t *);
extern int sock_close_notsupp(sock_lower_handle_t, int, cred_t *);

/*
 * Upcalls and related information
 */

/*
 * su_opctl() actions
 */
typedef enum sock_opctl_action {
	SOCK_OPCTL_ENAB_ACCEPT = 0,
	SOCK_OPCTL_SHUT_SEND,
	SOCK_OPCTL_SHUT_RECV
} sock_opctl_action_t;

struct sock_upcalls_s {
	sock_upper_handle_t (*su_newconn)(sock_upper_handle_t,
	    sock_lower_handle_t, sock_downcalls_t *, cred_t *, pid_t,
	    sock_upcalls_t **);
	void	(*su_connected)(sock_upper_handle_t, sock_connid_t, cred_t *,
	    pid_t);
	int	(*su_disconnected)(sock_upper_handle_t, sock_connid_t, int);
	void	(*su_opctl)(sock_upper_handle_t, sock_opctl_action_t,
	    uintptr_t);
	ssize_t	(*su_recv)(sock_upper_handle_t, mblk_t *, size_t, int,
		    int *, boolean_t *);
	void	(*su_set_proto_props)(sock_upper_handle_t,
		    struct sock_proto_props *);
	void	(*su_txq_full)(sock_upper_handle_t, boolean_t);
	void	(*su_signal_oob)(sock_upper_handle_t, ssize_t);
	void	(*su_zcopy_notify)(sock_upper_handle_t);
	void	(*su_set_error)(sock_upper_handle_t, int);
	void	(*su_closed)(sock_upper_handle_t);
};

#define	SOCK_UC_VERSION		sizeof (sock_upcalls_t)
#define	SOCK_DC_VERSION		sizeof (sock_downcalls_t)

#define	SOCKET_RECVHIWATER	(48 * 1024)
#define	SOCKET_RECVLOWATER	1024

#define	SOCKET_NO_RCVTIMER	0
#define	SOCKET_TIMER_INTERVAL	50

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SOCKET_PROTO_H_ */
