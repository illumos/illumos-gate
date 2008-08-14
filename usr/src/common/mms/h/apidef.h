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


#ifndef _APIDEF_H_
#define	_APIDEF_H_

typedef unsigned short	SEQ_NO;
typedef MESSAGE_ID	REQ_ID;


#define	ACSAPI_PACKET_VERSION "ACSAPI_PACKET_VERSION"

#define	TEST_ACSLM "t_acslm"

#define	NUM_RECENT_VERSIONS 3

#define	DRIVE_TYPE_4480 0
#define	MEDIA_TYPE_3480 0

typedef  enum {
    RT_FIRST,
    RT_ACKNOWLEDGE,
    RT_INTERMEDIATE,
    RT_NONE,
    RT_FINAL,
    RT_LAST
} ACS_RESPONSE_TYPE;
#endif /* _APIDEF_H_ */
