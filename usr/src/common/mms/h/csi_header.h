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


#ifndef _CSI_HEADER_
#define	_CSI_HEADER_

#include <rpc/rpc.h>

typedef enum {
	CSI_SYNTAX_NONE		= 0,
	CSI_SYNTAX_XDR
} CSI_SYNTAX;

typedef enum {
	CSI_PROTOCOL_TCP		= 1,
	CSI_PROTOCOL_UDP		= 2,
	CSI_PROTOCOL_ADI		= 3
} CSI_PROTOCOL;

typedef enum {
	CSI_CONNECT_RPCSOCK		= 1,
	CSI_CONNECT_ADI		= 2
} CSI_CONNECT;


#ifndef ADI

#ifndef _CSI_RPC_HEADER_
#include "csi_rpc_header.h"
#endif

#define	CSI_HEADER 	CSI_HEADER_RPC
#define	CSI_XID		CSI_XID_RPC

#else

#ifndef _CSI_ADI_HEADER_
#include "csi_adi_header.h"
#endif

#define	CSI_HEADER 	CSI_HEADER_ADI
#define	CSI_XID		CSI_XID_ADI

#endif

#endif /* _CSI_HEADER_ */
