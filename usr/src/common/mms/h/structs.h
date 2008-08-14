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

#ifndef _STRUCTS_
#define	_STRUCTS_

#ifndef _DEFS_
#include "defs.h"
#endif

#ifndef _IDENTIFIER_
#include "identifier.h"
#endif

#ifndef _IPC_HDR_API_
#include "api/ipc_hdr_api.h"
#endif

#ifndef _STRUCTS_API_
#include "api/structs_api.h"
#endif

typedef struct {
	IPC_HEADER		ipc_header;
	LOG_OPTION		log_options;
	char		event_message[MAX_MESSAGE_SIZE];
} EVENT_LOG_MESSAGE;

typedef struct {
	IPC_HEADER		ipc_header;
	MESSAGE_HEADER		message_header;
	RESPONSE_STATUS message_status;
	unsigned short		error;
} UNSOLICITED_MESSAGE;

#endif /* _STRUCTS_ */
