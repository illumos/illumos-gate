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

#ifndef	_TRANSPORT_SERVICES_H
#define	_TRANSPORT_SERVICES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/socket.h>
#include <sys/types.h>

typedef struct transport_services {
	/*
	 * TCP configuration.
	 */
	struct {
		boolean_t valid;
		int sndbuf;
		int rcvbuf;
		int nodelay;
		int conn_notify_threshold;
		int conn_abort_threshold;
		int abort_threshold;
	} tcp_conf;

	void* (*socket)(int domain, int, int);
	int (*bind)(void *, struct sockaddr *, int, int, int);
	int (*connect)(void *, struct sockaddr *, int, int, int);
	int (*listen)(void *, int);
	void* (*accept)(void *, struct sockaddr *, int *);
	ssize_t (*sendmsg)(void *, struct msghdr *, int);
	ssize_t (*recvmsg)(void *, struct msghdr *, int);
	int (*getsockname)(void *);
	int (*getsockopt)(void *, int, int, void *, int *, int);
	int (*setsockopt)(void *, int, int, void *, int);
	int (*shutdown)(void *, int);
	void (*close)(void *);
	int (*poll)(void *, clock_t);
} transport_services_t;

void transport_reg(transport_services_t *transport, uint8_t *lhba_handle);

void transport_dereg(uint8_t *lhba_handle);

transport_services_t *transport_lookup(uint8_t *lhba_handle);

#ifdef __cplusplus
}
#endif

#endif /* _TRANSPORT_SERVICES_H */
