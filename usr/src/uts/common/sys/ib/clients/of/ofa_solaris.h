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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 *
 * NAME: ofa_solaris.h
 *
 * DESC: OFED Solaris wrapper
 *
 */
#ifndef _SYS_IB_CLIENTS_OFA_SOLARIS_H
#define	_SYS_IB_CLIENTS_OFA_SOLARIS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#include <sys/types.h>
#include <sys/byteorder.h>

typedef struct ofv_resp_addr_t {
	union {
		uint64_t	_r_ll;
		uint32_t	_r_la[2];
	} _resp_un;
} ofv_resp_addr_t;

#define	r_laddr		_resp_un._r_ll
#ifdef	_LONG_LONG_HTOL
#define	r_notused	_resp_un._r_la[0]
#define	r_addr		_resp_un._r_la[1]
#else
#define	r_addr		_resp_un._r_la[0]
#define	r_notused	_resp_un._r_la[1]
#endif	/* _LONG_LONG_HTOL */

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_CLIENTS_OFA_SOLARIS_H */
