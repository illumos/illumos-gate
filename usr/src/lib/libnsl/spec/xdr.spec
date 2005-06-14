#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

function	xdr_getpos
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	u_int xdr_getpos(const XDR *xdrs)
version		SUNW_0.7
end

function	xdr_inline
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	long *xdr_inline(XDR *xdrs, const int len)
version		SUNW_0.7
exception	$return == 0
end

function	xdrrec_endofrecord
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdrrec_endofrecord(XDR *xdrs, int sendnow)
version		SUNW_0.7
exception	$return == FALSE
end

function	xdrrec_eof
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdrrec_eof(XDR *xdrs)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdrrec_readbytes
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	uint_t xdrrec_readbytes(XDR *xdrs, caddr_t addr, uint_t nbytes)
version		SUNW_0.7
exception	$return == -1
end

function	xdrrec_skiprecord
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdrrec_skiprecord(XDR *xdrs)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_setpos
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_setpos(XDR *xdrs, const u_int pos)
version		SUNW_0.7
exception	$return == FALSE
end

function	xdr_sizeof
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	unsigned int xdr_sizeof(xdrproc_t func, void *data)
version		SUNW_0.7
exception	$return == 0
end

function	xdr_array
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_array(XDR *xdrs, caddr_t *arrp, u_int *sizep, \
			const u_int maxsize, const u_int elsize, \
			const xdrproc_t elproc)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_bytes
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_bytes(XDR *xdrs, char **sp, u_int *sizep, \
			const u_int maxsize)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_opaque
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_opaque(XDR *xdrs, caddr_t cp, const u_int cnt)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_pointer
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_pointer(XDR *xdrs, char **objpp, u_int objsize, \
			const xdrproc_t xdrobj)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_reference
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_reference(XDR *xdrs, caddr_t *pp, u_int size, \
			const xdrproc_t proc)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_string
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_string(XDR *xdrs, char **sp, const  u_int  maxsize)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_union
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_union(XDR *xdrs, enum_t *dscmp, char *unp, \
			const struct xdr_discrim *choices,  \
			const xdrproc_t defaultarm)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_vector
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_vector(XDR *xdrs, char *arrp, const u_int size, \
			const u_int elsize, const xdrproc_t elproc)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_wrapstring
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_wrapstring(XDR *xdrs, char **sp)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_destroy
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	void xdr_destroy(XDR *xdrs)
version		SUNW_0.7
end

function	xdrmem_create
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	void xdrmem_create(XDR *xdrs, const caddr_t addr, \
			const u_int size, const enum xdr_op op)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	xdrrec_create
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	void xdrrec_create(XDR *xdrs, const uint_t sendsz, \
			const uint_t recvsz, const caddr_t handle, \
			int (*readit)(void *read_handle, caddr_t buf, int len), \
			int (*writeit)(void *write_handle, caddr_t buf, int len))
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	xdrstdio_create
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	void xdrstdio_create(XDR *xdrs, FILE *file, \
			const enum xdr_op op)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	xdr_bool
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_bool(XDR *xdrs, bool_t *bp)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_char
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_char(XDR *xdrs, char *cp)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_double
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_double(XDR *xdrs, double *dp)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_enum
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_enum(XDR *xdrs, enum_t *ep)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_float
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_float(XDR *xdrs, float *fp)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_free
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	void xdr_free(xdrproc_t proc, char *objp)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	xdr_hyper
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_hyper(XDR *xdrs, longlong_t *llp)
version		SUNW_0.7
exception	$return == FALSE
end

function	xdr_int
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_int(XDR *xdrs, int *ip)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_long
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_long(XDR *xdrs, long *lp)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_longlong_t
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_longlong_t(XDR *xdrs, longlong_t *llp)
version		SUNW_0.7
exception	$return == FALSE
end

function	xdr_quadruple
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_quadruple(XDR *xdrs, long double *pq)
version		SUNW_0.7
exception	$return == FALSE
end

function	xdr_short
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_short(XDR *xdrs, short *sp)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_u_char
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_u_char(XDR *xdrs, unsigned char *ucp)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_u_hyper
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_u_hyper(XDR *xdrs, u_longlong_t *ullp)
version		SUNW_0.7
exception	$return == FALSE
end

function	xdr_u_int
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_u_int(XDR *xdrs, unsigned *up)
version		SUNW_0.7
exception	$return == FALSE
end

function	xdr_u_long
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_u_long(XDR *xdrs, unsigned long *ulp)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_u_longlong_t
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_u_longlong_t(XDR *xdrs, u_longlong_t *ullp)
version		SUNW_0.7
exception	$return == FALSE
end

function	xdr_u_short
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_u_short(XDR *xdrs, unsigned short *usp)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_void
include		<rpc/types.h>
include		<rpc/xdr.h>
declaration	bool_t xdr_void(void)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_int16_t
version		SUNWprivate_1.1
end

function	xdr_int32_t
version		SUNWprivate_1.1
end

function	xdr_int64_t
version		SUNWprivate_1.1
end

function	xdr_int8_t
version		SUNWprivate_1.1
end

function	xdr_uint16_t
version		SUNWprivate_1.1
end

function	xdr_uint32_t
version		SUNWprivate_1.1
end

function	xdr_uint64_t
version		SUNWprivate_1.1
end

function	xdr_uint8_t
version		SUNWprivate_1.1
end
