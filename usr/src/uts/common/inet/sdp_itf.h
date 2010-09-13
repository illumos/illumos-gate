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

#ifndef	_INET_SDP_ITF_H
#define	_INET_SDP_ITF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Kernel SDP programming interface.  Note that this interface
 * is private to Sun and can be changed without notice.
 */

#ifdef _KERNEL

/*
 * The version number of the SDP kernel interface.  Use it with
 * sdp_itf_ver() to verify if the kernel supports the correct
 * version of the interface.
 *
 * NOTE: do not assume backward compatibility of the interface.
 * If the return value of sdp_itf_ver() is different from what
 * is expected, do not call any of the routines.
 */
#define	SDP_ITF_VER	1

/*
 * This struct holds all the upcalls the SDP kernel module will
 * invoke for different events.  When calling sdp_create() to create
 * a SDP handle, the caller must provide this information.
 */
typedef struct sdp_upcalls_s {
	void *	(*su_newconn)(void *parenthandle, void *connind);
	void	(*su_connected)(void *handle);
	void	(*su_disconnected)(void *handle, int error);
	void	(*su_connfailed)(void *handle, int error);
	int	(*su_recv)(void *handle, mblk_t *mp, int flags);
	void	(*su_xmitted)(void *handle, int writeable);
	void	(*su_urgdata)(void *handle);
	void	(*su_ordrel)(void *handle);
} sdp_upcalls_t;


/*
 * This struct holds various flow control limits the caller of
 * sdp_create() should observe when interacting with SDP.
 */
typedef struct sdp_sockbuf_limits_s {
	int sbl_rxbuf;
	int sbl_rxlowat;
	int sbl_txbuf;
	int sbl_txlowat;
} sdp_sockbuf_limits_t;

struct sdp_conn_struct_t;

/*
 * The list of routines the SDP kernel module provides.
 */
extern int sdp_bind(struct sdp_conn_struct_t *conn, struct sockaddr *addr,
    socklen_t addrlen);
extern void sdp_close(struct sdp_conn_struct_t *conn);
extern int sdp_connect(struct sdp_conn_struct_t *conn,
    const struct sockaddr *dst, socklen_t addrlen);
extern struct sdp_conn_struct_t *sdp_create(void *newhandle,
    struct sdp_conn_struct_t *parent, int family, int flags,
    const sdp_upcalls_t *su, sdp_sockbuf_limits_t *sbl, cred_t *cr,
    int *error);
extern int sdp_disconnect(struct sdp_conn_struct_t *conn, int flags);
extern int sdp_shutdown(struct sdp_conn_struct_t *conn, int flag);
extern int sdp_polldata(struct sdp_conn_struct_t *conn, int flag);
extern int sdp_get_opt(struct sdp_conn_struct_t *conn, int level, int opt,
    void *opts, socklen_t *optlen);
extern int sdp_getpeername(struct sdp_conn_struct_t *conn,
    struct sockaddr *addr, socklen_t *addrlen);
extern int sdp_getsockname(struct sdp_conn_struct_t *conn,
    struct sockaddr *addr, socklen_t *addrlen);
extern int sdp_itf_ver(int);
extern int sdp_listen(struct sdp_conn_struct_t *conn, int backlog);
extern int sdp_send(struct sdp_conn_struct_t *conn, struct msghdr *msg,
    size_t size, int flags, struct uio *uiop);
extern int sdp_recv(struct sdp_conn_struct_t *conn, struct msghdr *msg,
    size_t size, int flags, struct uio *uiop);
extern int sdp_set_opt(struct sdp_conn_struct_t *conn, int level, int opt,
    const void *opts, socklen_t optlen);
extern int sdp_ioctl(struct sdp_conn_struct_t *conn, int cmd, int32_t *value,
    struct cred *cr);


/* Flags for sdp_create() */
#define	SDP_CAN_BLOCK			0x01

#define	SDP_READ 0x01
#define	SDP_XMIT 0x02

#endif /* _KERNEL */

#define	SDP_NODELAY 0x01

#ifdef __cplusplus
}
#endif

#endif /* _INET_SDP_ITF_H */
