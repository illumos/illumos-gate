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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_KSOCKET_H_
#define	_SYS_KSOCKET_H_

#ifdef	__cplusplus
extern "C" {
#endif

/* Opaque kernel socket type */
typedef struct __ksocket *ksocket_t;
struct nmsghdr;
struct msgb;	/* avoiding sys/stream.h here */

/* flag bit for each Callback Event */
#define	KSOCKET_CB_CONNECTED		0x00000001
#define	KSOCKET_CB_CONNECTFAILED	0x00000002
#define	KSOCKET_CB_DISCONNECTED		0x00000004
#define	KSOCKET_CB_NEWDATA		0x00000008
#define	KSOCKET_CB_NEWCONN		0x00000010
#define	KSOCKET_CB_CANSEND		0x00000020
#define	KSOCKET_CB_OOBDATA		0x00000040
#define	KSOCKET_CB_CANTSENDMORE		0x00000080
#define	KSOCKET_CB_CANTRECVMORE		0x00000100
#define	KSOCKET_CB_ERROR		0x00000200

/*
 * Kernel Socket Callback Events
 */
typedef enum ksocket_event {
	KSOCKET_EV_CONNECTED,
	KSOCKET_EV_CONNECTFAILED,
	KSOCKET_EV_DISCONNECTED,
	KSOCKET_EV_OOBDATA,
	KSOCKET_EV_NEWDATA,
	KSOCKET_EV_NEWCONN,
	KSOCKET_EV_CANSEND,
	KSOCKET_EV_CANTSENDMORE,
	KSOCKET_EV_CANTRECVMORE,
	KSOCKET_EV_ERROR
} ksocket_callback_event_t;

typedef	void (*ksocket_callback_t)(ksocket_t, ksocket_callback_event_t,
    void *, uintptr_t);

typedef struct ksocket_callbacks {
	uint32_t		ksock_cb_flags;
	ksocket_callback_t	ksock_cb_connected;
	ksocket_callback_t	ksock_cb_connectfailed;
	ksocket_callback_t	ksock_cb_disconnected;
	ksocket_callback_t	ksock_cb_newdata;
	ksocket_callback_t	ksock_cb_newconn;
	ksocket_callback_t	ksock_cb_cansend;
	ksocket_callback_t	ksock_cb_oobdata;
	ksocket_callback_t	ksock_cb_cantsendmore;
	ksocket_callback_t	ksock_cb_cantrecvmore;
	ksocket_callback_t	ksock_cb_error;
} ksocket_callbacks_t;

#define	KSOCKET_SLEEP	SOCKET_SLEEP
#define	KSOCKET_NOSLEEP	SOCKET_NOSLEEP

extern int 	ksocket_socket(ksocket_t *, int, int, int, int, struct cred *);
extern int 	ksocket_bind(ksocket_t, struct sockaddr *, socklen_t,
		    struct cred *);
extern int 	ksocket_listen(ksocket_t, int, struct cred *);
extern int 	ksocket_accept(ksocket_t, struct sockaddr *, socklen_t *,
		    ksocket_t *, struct cred *);
extern int 	ksocket_connect(ksocket_t, struct sockaddr *, socklen_t,
		    struct cred *);
extern int 	ksocket_send(ksocket_t, void *, size_t, int, size_t *,
		    struct cred *);
extern int	ksocket_sendto(ksocket_t, void *, size_t, int,
		    struct sockaddr *, socklen_t, size_t *, struct cred *);
extern int 	ksocket_sendmsg(ksocket_t, struct nmsghdr *, int, size_t *,
		    struct cred *);
extern int	ksocket_sendmblk(ksocket_t, struct nmsghdr *, int,
		    struct msgb **, struct cred *);
extern int 	ksocket_recv(ksocket_t, void *, size_t, int, size_t *,
		    struct cred *);
extern int	ksocket_recvfrom(ksocket_t, void *, size_t, int,
		    struct sockaddr *, socklen_t *, size_t *, struct cred *);
extern int	ksocket_recvmsg(ksocket_t, struct nmsghdr *, int, size_t *,
		    struct cred *);
extern int	ksocket_shutdown(ksocket_t, int, struct cred *);
extern int 	ksocket_setsockopt(ksocket_t, int, int, const void *, int,
		    struct cred *);
extern int 	ksocket_getsockopt(ksocket_t, int, int, void *, int *,
		    struct cred *);
extern int 	ksocket_getpeername(ksocket_t, struct sockaddr *, socklen_t *,
		    struct cred *);
extern int 	ksocket_getsockname(ksocket_t, struct sockaddr *, socklen_t *,
		    struct cred *);
extern int	ksocket_ioctl(ksocket_t, int, intptr_t, int *, struct cred *);
extern int	ksocket_spoll(ksocket_t, int, short, short *, struct cred *);
extern int	ksocket_setcallbacks(ksocket_t, ksocket_callbacks_t *, void *,
		    struct cred *);
extern int 	ksocket_close(ksocket_t, struct cred *);
extern void	ksocket_hold(ksocket_t);
extern void	ksocket_rele(ksocket_t);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_KSOCKET_H_ */
