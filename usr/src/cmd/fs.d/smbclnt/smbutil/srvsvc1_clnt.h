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
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SRVSVC1_CLNT_H
#define	_SRVSVC1_CLNT_H

/*
 * Excerpts from lib/smbsrv/libmlsvc
 * Just enough for share enumeration.
 */

#include <libmlrpc/libmlrpc.h>
#include "srvsvc1.ndl"

void srvsvc1_initialize(void);
int srvsvc_net_share_enum(mlrpc_handle_t *handle, char *server,
	int level, union mslm_NetShareEnum_ru *resp);
int srvsvc_net_server_getinfo(mlrpc_handle_t *handle, char *server,
	int level, union mslm_NetServerGetInfo_ru *resp);

#endif	/* _SRVSVC1_CLNT_H */
