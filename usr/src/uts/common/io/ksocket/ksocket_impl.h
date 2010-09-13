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

#ifndef	_INET_KSOCKET_KSOCKET_IMPL_H
#define	_INET_KSOCKET_KSOCKET_IMPL_H

#define	KSTOSO(ks)	((struct sonode *)(ks))
#define	SOTOKS(so)	((ksocket_t)(uintptr_t)(so))

#define	IS_KERNEL_SOCKET(so)	((so)->so_mode & SM_KERNEL)

#define	KSOCKET_MOD_VERSION	"kernel socket module"

#define	__KSOCKET_EV_connected		KSOCKET_EV_CONNECTED
#define	__KSOCKET_EV_connectfailed	KSOCKET_EV_CONNECTFAILED
#define	__KSOCKET_EV_disconnected	KSOCKET_EV_DISCONNECTED
#define	__KSOCKET_EV_oobdata		KSOCKET_EV_OOBDATA
#define	__KSOCKET_EV_newdata		KSOCKET_EV_NEWDATA
#define	__KSOCKET_EV_newconn		KSOCKET_EV_NEWCONN
#define	__KSOCKET_EV_cansend		KSOCKET_EV_CANSEND
#define	__KSOCKET_EV_cantsendmore	KSOCKET_EV_CANTSENDMORE
#define	__KSOCKET_EV_cantrecvmore	KSOCKET_EV_CANTRECVMORE
#define	__KSOCKET_EV_error		KSOCKET_EV_ERROR

#define	KSOCKET_CALLBACK(so, cbfn, arg) 				\
	if ((so)->so_ksock_callbacks.ksock_cb_##cbfn != NULL) {		\
		(*(so)->so_ksock_callbacks.ksock_cb_##cbfn)(SOTOKS(so),	\
		    __KSOCKET_EV_##cbfn, (so)->so_ksock_cb_arg, (arg));	\
	}

#define	KSOCKET_FMODE(so)	FREAD|FWRITE|	\
	((KSTOSO(so)->so_state & (SS_NDELAY|SS_NONBLOCK)) ? FNDELAY : 0)

#define	KSOCKET_VALID(ks)	\
	((ks) != NULL && (KSTOSO(ks))->so_mode & SM_KERNEL &&		\
	    !((KSTOSO(ks))->so_state & SS_CLOSING))

#define	SETCALLBACK(so, cb, cbfn, cbflg)			\
	if ((cb)->ksock_cb_flags & (cbflg)) {			\
		(so)->so_ksock_callbacks.ksock_cb_##cbfn	\
		    = (cb)->ksock_cb_##cbfn;			\
		if ((cb)->ksock_cb_##cbfn == NULL)		\
			(so)->so_ksock_callbacks.ksock_cb_flags \
			    &= ~(cbflg);			\
		else						\
			(so)->so_ksock_callbacks.ksock_cb_flags \
			    |= (cbflg);				\
	}


#endif /* _INET_KSOCKET_KSOCKET_IMPL_H */
