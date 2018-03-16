/*
 * Copyright (c) 2011 - 2012 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _NETSMB_SMB2_RQ_H_
#define	_NETSMB_SMB2_RQ_H_

#include <sys/types.h>

/*
 * Note: Pad all structures to 8 byte boundaries
 */

int smb2_rq_parsehdr(struct smb_rq *rqp);
void smb2_rq_fillhdr(struct smb_rq *rqp);

int smb2_rq_simple(struct smb_rq *rqp);
int smb2_rq_simple_timed(struct smb_rq *rqp, int timeout);
int smb2_rq_internal(struct smb_rq *rqp, int timeout);

#endif	/* _NETSMB_SMB2_RQ_H_ */
