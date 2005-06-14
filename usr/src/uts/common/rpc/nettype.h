/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

/*
 * nettype.h, Nettype definitions.
 * All for the topmost layer of rpc
 *
 */

#ifndef	_RPC_NETTYPE_H
#define	_RPC_NETTYPE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netconfig.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	_RPC_NONE		0
#define	_RPC_NETPATH		1
#define	_RPC_VISIBLE		2
#define	_RPC_CIRCUIT_V		3
#define	_RPC_DATAGRAM_V		4
#define	_RPC_CIRCUIT_N		5
#define	_RPC_DATAGRAM_N		6
#define	_RPC_TCP		7
#define	_RPC_UDP		8
#define	_RPC_LOCAL		9
#define	_RPC_DOOR		10
#define	_RPC_DOOR_LOCAL		11
#define	_RPC_DOOR_NETPATH	12

#ifdef __STDC__
extern void *__rpc_setconf(char *);
extern void __rpc_endconf(void *);
extern struct netconfig *__rpc_getconf(void *);
extern struct netconfig *__rpc_getconfip(char *);
#else
extern void *__rpc_setconf();
extern void __rpc_endconf();
extern struct netconfig *__rpc_getconf();
extern struct netconfig *__rpc_getconfip();
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* !_RPC_NETTYPE_H */
