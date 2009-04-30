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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dapl_ring_buffer_util.h
 *
 * PURPOSE: Utility defs & routines for the ring buffer data structure
 *
 * $Id: dapl_ring_buffer_util.h,v 1.5 2003/06/13 12:21:11 sjs2 Exp $
 *
 */

#ifndef _DAPL_RING_BUFFER_H_
#define	_DAPL_RING_BUFFER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "dapl.h"

/*
 * Prototypes
 */
DAT_RETURN dapls_rbuf_alloc(
	DAPL_RING_BUFFER		*rbuf,
	DAT_COUNT			 size);

DAT_RETURN dapls_rbuf_realloc(
	DAPL_RING_BUFFER		*rbuf,
	DAT_COUNT			 size);

void dapls_rbuf_destroy(
	DAPL_RING_BUFFER		*rbuf);

DAT_RETURN dapls_rbuf_add(
	DAPL_RING_BUFFER		*rbuf,
	void				*entry);

void * dapls_rbuf_remove(
	DAPL_RING_BUFFER		*rbuf);

DAT_COUNT dapls_rbuf_count(
	DAPL_RING_BUFFER		*rbuf);


/*
 * Simple functions
 */
#define	dapls_rbuf_empty(rbuf)	((rbuf)->head == (rbuf)->tail)

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_RING_BUFFER_H_ */
