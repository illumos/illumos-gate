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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dapl_cookie.h
 *
 * PURPOSE: Utility defs & routines for the cookie data structure
 *
 * $Id: dapl_cookie.h,v 1.7 2003/06/13 12:21:02 sjs2 Exp $
 *
 */

#ifndef _DAPL_COOKIE_H_
#define	_DAPL_COOKIE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "dapl.h"

extern DAT_RETURN
dapls_cb_create(
    DAPL_COOKIE_BUFFER		*buffer,
    void			*queue,
    DAPL_COOKIE_QUEUE_TYPE	type,
    DAT_COUNT			size);

extern DAT_RETURN
dapls_cb_resize(
    IN	DAPL_COOKIE_BUFFER	*curr_buffer,
    IN	DAT_COUNT		new_size,
    IN	DAPL_COOKIE_BUFFER	*new_buffer);

extern void
dapls_cb_free(
    DAPL_COOKIE_BUFFER		*buffer);

extern DAT_RETURN
dapls_rmr_cookie_alloc(
    IN  DAPL_COOKIE_BUFFER	*buffer,
    IN 	DAPL_RMR		*rmr,
    IN 	DAT_RMR_COOKIE		user_cookie,
    OUT DAPL_COOKIE 		**cookie_ptr);

extern DAT_RETURN
dapls_dto_cookie_alloc(
    IN  DAPL_COOKIE_BUFFER	*buffer,
    IN  DAPL_DTO_TYPE		type,
    IN 	DAT_DTO_COOKIE		user_cookie,
    OUT DAPL_COOKIE 		**cookie_ptr);

extern void
dapls_cookie_dealloc(
    IN  DAPL_COOKIE_BUFFER	*buffer,
    IN 	DAPL_COOKIE		*cookie);

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_COOKIE_H_ */
