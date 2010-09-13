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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef _ISCSIT_AUTH_H_
#define	_ISCSIT_AUTH_H_

typedef kv_status_t (*iscsit_auth_handler_t)(iscsit_conn_t *, nvpair_t *,
    const idm_kv_xlate_t *);

iscsit_auth_handler_t
iscsit_auth_get_handler(iscsit_auth_client_t *, iscsikey_id_t);

#endif /* _ISCSIT_AUTH_H_ */
