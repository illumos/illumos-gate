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
 * Copyright (c) 1996,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_RPCSEC_DEFS_H
#define	_RPCSEC_DEFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Id: auth_gssapi.h,v 1.11 1994/10/27 12:39:14 jik Exp $
 */

#ifndef _KERNEL
#include <libintl.h>
#include <locale.h>
#endif
#include <gssapi/gssapi.h>
#include <rpc/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#if defined(DEBUG) && !defined(RPCGSS_DEBUG)
#define	RPCGSS_DEBUG
#endif

#ifdef RPCGSS_DEBUG
extern uint_t rpcgss_log;

#define	RPCGSS_LOG1(A, B, C, D) \
	((void)((rpcgss_log) && (rpcgss_log & (A)) && (printf((B), \
	    (C), (D)), TRUE)))
#define	RPCGSS_LOG(A, B, C) \
	((void)((rpcgss_log) && (rpcgss_log & (A)) && (printf((B), (C)), TRUE)))
#define	RPCGSS_LOG0(A, B)   \
	((void)((rpcgss_log) && (rpcgss_log & (A)) && (printf(B), TRUE)))
#else
#define	RPCGSS_LOG1(A, B, C, D)
#define	RPCGSS_LOG(A, B, C)
#define	RPCGSS_LOG0(A, B)
#endif

#else /* _KERNEL */

extern bool_t locale_set;
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SUNW_OST_OSCMD"
#endif

#endif /* _KERNEL */


typedef struct _rpc_gss_creds {
	uint_t version;
	uint_t gss_proc;
	uint_t seq_num;
	rpc_gss_service_t service;
	gss_buffer_desc ctx_handle;
} rpc_gss_creds;

typedef gss_buffer_desc rpc_gss_init_arg;

typedef struct _rpc_gss_init_res {
	gss_buffer_desc ctx_handle;
	OM_uint32 gss_major, gss_minor;
	OM_uint32 seq_window;
	gss_buffer_desc token;
} rpc_gss_init_res;


/*
 * Convenience macros.
 */

#define	GSS_COPY_BUFFER(dest, src) { \
	(dest).length = (src).length; \
	(dest).value = (src).value; }

#define	GSS_DUP_BUFFER(dest, src) { \
	(dest).length = (src).length; \
	(dest).value = (void *) mem_alloc((dest).length); \
	bcopy((src).value, (dest).value, (dest).length); }

#define	GSS_BUFFERS_EQUAL(b1, b2) (((b1).length == (b2).length) && \
			(bcmp((b1).value, (b2).value, (b1.length)) == 0))

#define	GSS_OIDS_EQUAL(o1, o2) \
	((((gss_OID)(o1))->length == ((gss_OID)(o2))->length) && \
		(bcmp(((gss_OID)(o1))->elements, ((gss_OID)(o2))->elements, \
			((gss_OID)(o1))->length) == 0))

#define	MAX_GSS_NAME			128

/*
 * Private interfaces for user and kernel space.
 */
bool_t __xdr_gss_buf();
bool_t __xdr_rpc_gss_creds();
bool_t __xdr_rpc_gss_init_arg();
bool_t __xdr_rpc_gss_init_res();

bool_t __rpc_gss_wrap_data();
bool_t __rpc_gss_unwrap_data();

#ifdef	_KERNEL
/*
 * kernel-level RPCSEC_GSS definitions.
 */

void __rpc_gss_dup_oid(gss_OID, gss_OID *);
bool_t __rpc_gss_oids_equal(gss_OID oid1, gss_OID oid2);
void rpc_gss_display_status(OM_uint32 major, OM_uint32 minor,
			    rpc_gss_OID mechanism, uid_t uid,
			    char *function_name);
#else
/*
 * user-level RPCSEC_GSS definitions.
 */

#define	MAX_MECH_OID_PAIRS		32

typedef struct _rpc_gss_name {
	char *name;
	rpc_gss_OID type;
} rpc_gss_name;

#ifdef	_REENTRANT
extern rpc_gss_error_t	*__rpc_gss_err();
#define	rpc_gss_err	(*(__rpc_gss_err()))
#else
extern rpc_gss_error_t rpc_gss_err;
#endif	/* _REENTRANT */

/*
 * Private interfaces in user space.
 */
bool_t __rpc_gss_qop_to_num();
char *__rpc_gss_num_to_qop();
bool_t __rpc_gss_mech_to_oid();
char *__rpc_gss_oid_to_mech();
bool_t __rpc_gss_svc_to_num();
char *__rpc_gss_num_to_svc();

void __rpc_gss_xdrdynamic_create();
caddr_t __rpc_gss_xdrdynamic_getdata();

bool_t __rpcsec_init();
rpc_gss_OID __get_gss_oid();
void __rpc_gss_bind_error();
int __find_max_data_length(rpc_gss_service_t service, gss_ctx_id_t context,
	OM_uint32 qop, int max_tp_unit_len);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _RPCSEC_DEFS_H */
