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
 *
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * xdr_array.c, Generic XDR routines impelmentation.
 *
 * These are the "non-trivial" xdr primitives used to serialize and de-serialize
 * arrays.  See xdr.h for more info on the interface to xdr.
 */

#include <sys/types.h>
#include <rpc/trace.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <memory.h>

#define	LASTUNSIGNED	((uint_t)0-1)

char mem_err_msg_arr[] = "xdr_array: out of memory";
/*
 * XDR an array of arbitrary elements
 * *addrp is a pointer to the array, *sizep is the number of elements.
 * If *addrp is NULL (*sizep * elsize) bytes are allocated.
 * elsize is the size (in bytes) of each element, and elproc is the
 * xdr procedure to call to handle each element of the array.
 */
bool_t
xdr_array(XDR *xdrs, caddr_t *addrp, uint_t *sizep, uint_t maxsize,
	uint_t elsize, xdrproc_t elproc)
{
	register uint_t i;
	register caddr_t target = *addrp;
	register uint_t c;  /* the actual element count */
	register bool_t stat = TRUE;
	register uint_t nodesize;

	trace3(TR_xdr_array, 0, maxsize, elsize);
	/* like strings, arrays are really counted arrays */
	if (! xdr_u_int(xdrs, sizep)) {
		trace1(TR_xdr_array, 1);
		return (FALSE);
	}
	c = *sizep;
	if ((c > maxsize || LASTUNSIGNED / elsize < c) &&
	    xdrs->x_op != XDR_FREE) {
		trace1(TR_xdr_array, 1);
		return (FALSE);
	}
	nodesize = c * elsize;

	/*
	 * if we are deserializing, we may need to allocate an array.
	 * We also save time by checking for a null array if we are freeing.
	 */
	if (target == NULL)
		switch (xdrs->x_op) {
		case XDR_DECODE:
			if (c == 0) {
				trace1(TR_xdr_array, 1);
				return (TRUE);
			}
			*addrp = target = (caddr_t)mem_alloc(nodesize);
			if (target == NULL) {
				(void) syslog(LOG_ERR, mem_err_msg_arr);
				trace1(TR_xdr_array, 1);
				return (FALSE);
			}
			(void) memset(target, 0, nodesize);
			break;

		case XDR_FREE:
			trace1(TR_xdr_array, 1);
			return (TRUE);
	}

	/*
	 * now we xdr each element of array
	 */
	for (i = 0; (i < c) && stat; i++) {
		stat = (*elproc)(xdrs, target);
		target += elsize;
	}

	/*
	 * the array may need freeing
	 */
	if (xdrs->x_op == XDR_FREE) {
		mem_free(*addrp, nodesize);
		*addrp = NULL;
	}
	trace1(TR_xdr_array, 1);
	return (stat);
}

/*
 * xdr_vector():
 *
 * XDR a fixed length array. Unlike variable-length arrays,
 * the storage of fixed length arrays is static and unfreeable.
 * > basep: base of the array
 * > size: size of the array
 * > elemsize: size of each element
 * > xdr_elem: routine to XDR each element
 */
bool_t
xdr_vector(XDR *xdrs, char *basep, uint_t nelem,
	uint_t elemsize, xdrproc_t xdr_elem)
{
	register uint_t i;
	register char *elptr;

	trace3(TR_xdr_vector, 0, nelem, elemsize);
	elptr = basep;
	for (i = 0; i < nelem; i++) {
		if (! (*xdr_elem)(xdrs, elptr, LASTUNSIGNED)) {
			trace1(TR_xdr_vector, 1);
			return (FALSE);
		}
		elptr += elemsize;
	}
	trace1(TR_xdr_vector, 1);
	return (TRUE);
}
