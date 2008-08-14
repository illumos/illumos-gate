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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _CSI_RPC_HEADER_
#define	_CSI_RPC_HEADER_

#ifndef _CSI_HEADER_
#include "csi_header.h"
#endif

#define	CSI_NETADDR_SIZE	 6

typedef struct {
	unsigned long	program;
	unsigned long	version;
	unsigned long	proc;
	struct sockaddr_in	raddr;
} CSI_HANDLE_RPC;

typedef struct {
	unsigned char addr[CSI_NETADDR_SIZE];
	unsigned int		pid;
	unsigned long seq_num;
} CSI_XID_RPC;

typedef struct {
	CSI_XID_RPC	xid;
	unsigned long	ssi_identifier;
	CSI_SYNTAX	csi_syntax;
	CSI_PROTOCOL	csi_proto;
	CSI_CONNECT	csi_ctype;
	CSI_HANDLE_RPC	csi_handle;
} CSI_HEADER_RPC;

#endif /* _CSI_RPC_HEADER_ */
