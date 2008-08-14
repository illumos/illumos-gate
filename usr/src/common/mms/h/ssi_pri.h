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


#ifndef _SSI_PRI_
#define	_SSI_PRI_
#ifndef _CSI_STRUCTS_
#include "csi_structs.h"
#endif

#ifndef _CSI_V0_STRUCTS_
#include "csi_v0_structs.h"
#endif


typedef struct {
	CSI_REQUEST_HEADER csi_request_header;
	RESPONSE_STATUS		message_status;
} CSI_RESPONSE_HEADER;

typedef struct {
	CSI_V0_REQUEST_HEADER csi_request_header;
	RESPONSE_STATUS		message_status;
} CSI_V0_RESPONSE_HEADER;


#endif /* _SSI_PRI_ */
