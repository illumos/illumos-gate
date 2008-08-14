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


#ifndef _CSI_XDR_
#define	_CSI_XDR_

#ifndef _rpc_xdr_h
#include <rpc/xdr.h>
#endif

void 	xdrmem_create(XDR *, char *, uint_t, enum xdr_op);
bool_t	xdr_void(void);
bool_t	xdr_int(XDR *, int *);
bool_t	xdr_uint_t(XDR *, uint_t *);
bool_t	xdr_long(XDR *, long *);
bool_t	xdr_u_long(XDR *, ulong_t *);
bool_t	xdr_short(XDR *, short *);
bool_t	xdr_u_short(XDR *, ushort_t *);
bool_t	xdr_bool(XDR *, bool_t *);
bool_t	xdr_enum(XDR *, enum_t *);
bool_t	xdr_array(XDR *, char **, uint_t *, uint_t, uint_t, xdrproc_t);
bool_t	xdr_bytes(XDR *, char **, uint_t *, uint_t);
bool_t	xdr_opaque(XDR *, caddr_t, uint_t);
bool_t	xdr_string(XDR *, char **, uint_t);
bool_t	xdr_char(XDR *, char *);
bool_t	xdr_wrapstring(XDR *, char **);
bool_t	xdr_reference(XDR *, caddr_t *, uint_t, xdrproc_t);
bool_t	xdr_pointer(XDR *, char **, uint_t, xdrproc_t);
bool_t	xdr_u_char(XDR *, uchar_t *);
bool_t	xdr_vector(XDR *, char *, uint_t, uint_t, xdrproc_t);
bool_t	xdr_float(XDR *, float *);
bool_t	xdr_double(XDR *, double *);
void	xdr_free(xdrproc_t, char *);
#endif /* _CSI_XDR_ */
