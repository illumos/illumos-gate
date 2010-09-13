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
 *	oid.h
 *
 *	Copyright (c) 1997, by Sun Microsystems, Inc.
 *	All rights reserved.
 *
 */

#ifndef _OID_H_
#define	_OID_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

int __OID_equal(const gss_OID_desc * const  oid1,
    const gss_OID_desc * const oid2);
int __OID_nel(const gss_OID_desc * const oid);
OM_uint32 __OID_copy_desc(gss_OID dest, const gss_OID_desc * const source);
OM_uint32 __OID_copy(gss_OID *dest, const gss_OID_desc * const source);
int __OID_is_member(gss_OID_set set, const gss_OID_desc * const element);
OM_uint32  __OID_copy_set(gss_OID_set *dest, gss_OID_set source);

OM_uint32
__OID_copy_set_from_array(gss_OID_set *dest,
    const gss_OID_desc *array[], size_t nel);

OM_uint32 __OID_to_OID_set(gss_OID_set *set, const gss_OID_desc * const oid);

#ifdef __cplusplus
}
#endif

#endif /* _OID_H_ */
