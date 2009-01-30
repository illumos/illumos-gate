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

#ifndef _FEATURE_H
#define	_FEATURE_H

#include <sys/types.h>
#include "iscsi_conn.h"

/*
 * The number of seconds that an initiator has to respond to our
 * asynchronous logout request before we just drop the connection.
 */
#define	ASYNC_LOGOUT_TIMEOUT	10

Boolean_t iscsi_full_feature(iscsi_conn_t *c);

uint32_t iscsi_crc32c(void *address, unsigned long length);
uint32_t iscsi_crc32c_continued(void *address, unsigned long length,
    uint32_t crc);

#endif /* _FEATURE_H */
