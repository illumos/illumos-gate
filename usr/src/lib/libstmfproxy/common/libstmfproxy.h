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

#ifndef	_LIBSTMFPROXY_H
#define	_LIBSTMFPROXY_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

struct _pt_ops {
	void *(*stmf_proxy_connect)(int server_node, char *server);
	ssize_t (*stmf_proxy_send)(void *, void *, size_t);
	ssize_t (*stmf_proxy_recv)(void *, void *, size_t);
};

typedef struct _pt_ops pt_ops_t;

int
stmf_proxy_transport_init(char *transport, pt_ops_t **pt_ops);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSTMFPROXY_H */
