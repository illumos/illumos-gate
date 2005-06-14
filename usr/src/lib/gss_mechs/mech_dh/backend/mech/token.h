/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *	token.h
 *
 *	Copyright (c) 1997, by Sun Microsystems, Inc.
 *	All rights reserved.
 *
 */

#ifndef _TOKEN_H_
#define	_TOKEN_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "dh_gssapi.h"
#include "dhmech_prot.h"

OM_uint32
__make_ap_token(gss_buffer_t, gss_OID, dh_token_t, dh_key_set_t);

OM_uint32
__make_token(gss_buffer_t, gss_buffer_t, dh_token_t, dh_key_set_t);

OM_uint32
__get_ap_token(gss_buffer_t, gss_OID, dh_token_t, dh_signature_t);

OM_uint32
__get_token(gss_buffer_t, gss_buffer_t, dh_token_t, dh_key_set_t);

#ifdef __cplusplus
}
#endif

#endif /* _TOKEN_H_ */
