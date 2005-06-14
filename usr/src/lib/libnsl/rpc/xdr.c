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
 * xdr.c, Generic XDR routines implementation.
 *
 * These are the "generic" xdr routines used to serialize and de-serialize
 * most common data items.  See xdr.h for more info on the interface to
 * xdr.
 */
#include <sys/types.h>
#include <sys/isa_defs.h>
#include <rpc/trace.h>

#ifdef KERNEL
#include <sys/param.h>
#include <sys/systm.h>
#else
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#include <limits.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <inttypes.h>
#include <sys/sysmacros.h>

#pragma weak xdr_int64_t = xdr_hyper
#pragma weak xdr_uint64_t = xdr_u_hyper
#pragma weak xdr_int32_t = xdr_int
#pragma weak xdr_uint32_t = xdr_u_int
#pragma weak xdr_int16_t = xdr_short
#pragma weak xdr_uint16_t = xdr_u_short
#pragma weak xdr_int8_t = xdr_char
#pragma weak xdr_uint8_t = xdr_u_char

/*
 * constants specific to the xdr "protocol"
 */
#define	XDR_FALSE	((uint_t)0)
#define	XDR_TRUE	((uint_t)1)
#define	LASTUNSIGNED	((uint_t)0-1)

/* fragment size to use when doing an xdr_string() */
#define	FRAGMENT	65536

/*
 * for unit alignment
 */
static const char xdr_zero[BYTES_PER_XDR_UNIT]	= { 0 };

#ifndef KERNEL
/*
 * Free a data structure using XDR
 * Not a filter, but a convenient utility nonetheless
 */
void
xdr_free(xdrproc_t proc, char *objp)
{
	XDR x;

	trace1(TR_xdr_free, 0);
	x.x_op = XDR_FREE;
	(*proc)(&x, objp);
	trace1(TR_xdr_free, 1);
}
#endif

/*
 * XDR nothing
 */
bool_t
xdr_void()
{
	trace1(TR_xdr_void, 0);
	trace1(TR_xdr_void, 1);
	return (TRUE);
}

/*
 * xdr_time_t  sends time_t value over the wire.
 * Due to RPC Protocol limitation, it can only send
 * up to 32-bit integer quantity over the wire.
 *
 */
bool_t
xdr_time_t(XDR *xdrs, time_t *tp)
{
	bool_t dummy;
	int32_t i;

	trace1(TR_xdr_time_t, 0);
	switch (xdrs->x_op) {
	case XDR_ENCODE:
	/*
	 * Check for the time overflow, when encoding it.
	 * Don't want to send OTW the time value too large to
	 * handle by the protocol.
	 */
#if defined(_LP64)
	if (*tp > INT32_MAX)
		*tp = INT32_MAX;
	else if (*tp < INT32_MIN)
		*tp = INT32_MIN;
#endif
		i =  (int32_t)*tp;
		dummy = XDR_PUTINT32(xdrs, &i);
		trace1(TR_xdr_time_t, 1);
		return (dummy);

	case XDR_DECODE:
		if (!XDR_GETINT32(xdrs, &i)) {
			trace1(TR_xdr_time_t, 1);
			return (FALSE);
		}
		*tp = (time_t)i;
		trace1(TR_xdr_time_t, 1);
		return (TRUE);

	case XDR_FREE:
		trace1(TR_xdr_time_t, 1);
		return (TRUE);
	}
	trace1(TR_xdr_time_t, 1);
	return (FALSE);
}

/*
 * XDR integers
 */
bool_t
xdr_int(XDR *xdrs, int *ip)
{
	trace1(TR_xdr_int, 0);
	if (xdrs->x_op == XDR_ENCODE)
		return (XDR_PUTINT32(xdrs, ip));

	if (xdrs->x_op == XDR_DECODE)
		return (XDR_GETINT32(xdrs, ip));

	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	trace1(TR_xdr_int, 1);
	return (FALSE);
}

/*
 * XDR unsigned integers
 */
bool_t
xdr_u_int(XDR *xdrs, uint_t *up)
{
	trace1(TR_xdr_u_int, 0);
	if (xdrs->x_op == XDR_ENCODE)
		return (XDR_PUTINT32(xdrs, (int *)up));

	if (xdrs->x_op == XDR_DECODE)
		return (XDR_GETINT32(xdrs, (int *)up));

	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	trace1(TR_xdr_u_int, 1);
	return (FALSE);
}

#ifndef KERNEL
static const char xdrlong_err[] =
			"xdr_%s: value too large to be stored in data type";
#endif

/*
 * The definition of xdr_long()/xdr_u_long() is kept for backward
 * compatibitlity.
 * XDR long integers, same as xdr_u_long
 */

bool_t
xdr_long(XDR *xdrs, long *lp)
{
	bool_t dummy;
	int32_t i;

	trace1(TR_xdr_long, 0);
	if (xdrs->x_op == XDR_ENCODE) {
#if defined(_LP64)
		if ((*lp > INT32_MAX) || (*lp < INT32_MIN)) {
			return (FALSE);
		}
#endif
		i = (int32_t)*lp;
		dummy = XDR_PUTINT32(xdrs, &i);
	} else if (xdrs->x_op == XDR_DECODE) {
		dummy = XDR_GETINT32(xdrs, &i);
		*lp = (long)i;
	} else if (xdrs->x_op == XDR_FREE)
		dummy = TRUE;
	else
		dummy = FALSE;
	trace1(TR_xdr_long, 1);
	return (dummy);
}

/*
 * XDR unsigned long integers
 * same as xdr_long
 */
bool_t
xdr_u_long(XDR *xdrs, ulong_t *ulp)
{
	bool_t dummy;
	uint32_t ui;

	trace1(TR_xdr_u_long, 0);
	if (xdrs->x_op == XDR_ENCODE) {
#if defined(_LP64)
		if (*ulp > UINT32_MAX) {
			return (FALSE);
		}
#endif
		ui = (uint32_t)*ulp;
		dummy = XDR_PUTINT32(xdrs, (int32_t *)&ui);
	} else if (xdrs->x_op == XDR_DECODE) {
		dummy = XDR_GETINT32(xdrs, (int32_t *)&ui);
		*ulp = (ulong_t)ui;
	} else if (xdrs->x_op == XDR_FREE)
		dummy = TRUE;
	else
		dummy = FALSE;
	trace1(TR_xdr_u_long, 1);
	return (dummy);
}

/*
 * XDR short integers
 */
bool_t
xdr_short(XDR *xdrs, short *sp)
{
	int32_t l;
	bool_t dummy;

	trace1(TR_xdr_short, 0);
	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (int32_t)*sp;
		dummy = XDR_PUTINT32(xdrs, &l);
		trace1(TR_xdr_short, 1);
		return (dummy);

	case XDR_DECODE:
		if (!XDR_GETINT32(xdrs, &l)) {
			trace1(TR_xdr_short, 1);
			return (FALSE);
		}
		*sp = (short)l;
		trace1(TR_xdr_short, 1);
		return (TRUE);

	case XDR_FREE:
		trace1(TR_xdr_short, 1);
		return (TRUE);
	}
	trace1(TR_xdr_short, 1);
	return (FALSE);
}

/*
 * XDR unsigned short integers
 */
bool_t
xdr_u_short(XDR *xdrs, ushort_t *usp)
{
	uint_t i;
	bool_t dummy;


	trace1(TR_xdr_u_short, 0);
	switch (xdrs->x_op) {

	case XDR_ENCODE:
		i = (uint_t)*usp;
		dummy = XDR_PUTINT32(xdrs, (int *)&i);
		trace1(TR_xdr_u_short, 1);
		return (dummy);

	case XDR_DECODE:
		if (!XDR_GETINT32(xdrs, (int *)&i)) {
#ifdef KERNEL
			printf("xdr_u_short: decode FAILED\n");
#endif
			trace1(TR_xdr_u_short, 1);
			return (FALSE);
		}
		*usp = (ushort_t)i;
		trace1(TR_xdr_u_short, 1);
		return (TRUE);

	case XDR_FREE:
		trace1(TR_xdr_u_short, 1);
		return (TRUE);
	}
#ifdef KERNEL
	printf("xdr_u_short: bad op FAILED\n");
#endif
	trace1(TR_xdr_u_short, 1);
	return (FALSE);
}


/*
 * XDR a char
 */
bool_t
xdr_char(XDR *xdrs, char *cp)
{
	int i;

	trace1(TR_xdr_char, 0);

	if (xdrs->x_op == XDR_ENCODE)
		i = (*cp);

	if (! xdr_int(xdrs, &i)) {
		trace1(TR_xdr_char, 1);
		return (FALSE);
	}
	if (xdrs->x_op == XDR_DECODE)
		*cp = (char)i;
	trace1(TR_xdr_char, 1);
	return (TRUE);
}

#ifndef KERNEL
/*
 * XDR an unsigned char
 */
bool_t
xdr_u_char(XDR *xdrs, uchar_t *cp)
{
	int i;

	trace1(TR_xdr_u_char, 0);
	if (xdrs->x_op == XDR_ENCODE)
		i = (*cp);
	if (! xdr_int(xdrs, &i)) {
		trace1(TR_xdr_u_char, 1);
		return (FALSE);
	}
	if (xdrs->x_op == XDR_DECODE)
		*cp = (uchar_t)i;
	trace1(TR_xdr_u_char, 1);
	return (TRUE);
}
#endif /* !KERNEL */

/*
 * XDR booleans
 */
bool_t
xdr_bool(XDR *xdrs, bool_t *bp)
{
	int i;
	bool_t dummy;

	trace1(TR_xdr_bool, 0);
	switch (xdrs->x_op) {

	case XDR_ENCODE:
		i = *bp ? XDR_TRUE : XDR_FALSE;
		dummy = XDR_PUTINT32(xdrs, &i);
		trace1(TR_xdr_bool, 1);
		return (dummy);

	case XDR_DECODE:
		if (!XDR_GETINT32(xdrs, &i)) {
#ifdef KERNEL
			printf("xdr_bool: decode FAILED\n");
#endif
			trace1(TR_xdr_bool, 1);
			return (FALSE);
		}
		*bp = (i == XDR_FALSE) ? FALSE : TRUE;
		trace1(TR_xdr_bool, 1);
		return (TRUE);

	case XDR_FREE:
		trace1(TR_xdr_bool, 1);
		return (TRUE);
	}
#ifdef KERNEL
	printf("xdr_bool: bad op FAILED\n");
#endif
	trace1(TR_xdr_bool, 1);
	return (FALSE);
}

/*
 * XDR enumerations
 */
bool_t
xdr_enum(XDR *xdrs, enum_t *ep)
{
	bool_t dummy;

#ifndef lint
	enum sizecheck { SIZEVAL };	/* used to find the size of an enum */

	/*
	 * enums are treated as ints
	 */
	trace1(TR_xdr_enum, 0);
	if (sizeof (enum sizecheck) == sizeof (int32_t)) {
		dummy = xdr_int(xdrs, (int *)ep);
		trace1(TR_xdr_enum, 1);
		return (dummy);
	} else if (sizeof (enum sizecheck) == sizeof (short)) {
		dummy = xdr_short(xdrs, (short *)ep);
		trace1(TR_xdr_enum, 1);
		return (dummy);
	} else if (sizeof (enum sizecheck) == sizeof (char)) {
		dummy = xdr_char(xdrs, (char *)ep);
		trace1(TR_xdr_enum, 1);
		return (dummy);
	} else {
		trace1(TR_xdr_enum, 1);
		return (FALSE);
	}
#else
	trace1(TR_xdr_enum, 0);
	(void) (xdr_char(xdrs, (char *)ep));
	(void) (xdr_short(xdrs, (short *)ep));
	dummy = xdr_int(xdrs, (int32_t *)ep);
	trace1(TR_xdr_enum, 1);
	return (dummy);
#endif
}

/*
 * XDR opaque data
 * Allows the specification of a fixed size sequence of opaque bytes.
 * cp points to the opaque object and cnt gives the byte length.
 */
bool_t
xdr_opaque(XDR *xdrs, caddr_t cp, uint_t cnt)
{
	bool_t dummy;
	register uint_t rndup;
	char crud[BYTES_PER_XDR_UNIT];

	/*
	 * if no data we are done
	 */
	trace2(TR_xdr_opaque, 0, cnt);
	if (cnt == 0) {
		trace1(TR_xdr_opaque, 1);
		return (TRUE);
	}

	/*
	 * round byte count to full xdr units
	 */
	rndup = cnt % BYTES_PER_XDR_UNIT;
	if ((int)rndup > 0)
		rndup = BYTES_PER_XDR_UNIT - rndup;

	if (xdrs->x_op == XDR_DECODE) {
		if (!XDR_GETBYTES(xdrs, cp, cnt)) {
#ifdef KERNEL
			printf("xdr_opaque: decode FAILED\n");
#endif
			trace1(TR_xdr_opaque, 1);
			return (FALSE);
		}
		if (rndup == 0) {
			trace1(TR_xdr_opaque, 1);
			return (TRUE);
		}
		dummy = XDR_GETBYTES(xdrs, crud, rndup);
		trace1(TR_xdr_opaque, 1);
		return (dummy);
	}

	if (xdrs->x_op == XDR_ENCODE) {

		if (!XDR_PUTBYTES(xdrs, cp, cnt)) {
#ifdef KERNEL
			printf("xdr_opaque: encode FAILED\n");
#endif
			trace1(TR_xdr_opaque, 1);
			return (FALSE);
		}
		if (rndup == 0) {
			trace1(TR_xdr_opaque, 1);
			return (TRUE);
		}
		dummy = XDR_PUTBYTES(xdrs, (caddr_t)&xdr_zero[0], rndup);
		trace1(TR_xdr_opaque, 1);
		return (dummy);
	}

	if (xdrs->x_op == XDR_FREE) {
		trace1(TR_xdr_opaque, 1);
		return (TRUE);
	}

#ifdef KERNEL
	printf("xdr_opaque: bad op FAILED\n");
#endif
	trace1(TR_xdr_opaque, 1);
	return (FALSE);
}

/*
 * XDR counted bytes
 * *cpp is a pointer to the bytes, *sizep is the count.
 * If *cpp is NULL maxsize bytes are allocated
 */

#ifndef KERNEL
static const char xdr_err[] = "xdr_%s: out of memory";
#endif

bool_t
xdr_bytes(XDR *xdrs, char **cpp, uint_t *sizep, uint_t maxsize)
{
	bool_t dummy;
	register char *sp = *cpp;  /* sp is the actual string pointer */
	register uint_t nodesize;

	/*
	 * first deal with the length since xdr bytes are counted
	 * We decided not to use MACRO XDR_U_INT here, because the
	 * advantages here will be miniscule compared to xdr_bytes.
	 * This saved us 100 bytes in the library size.
	 */
	trace2(TR_xdr_bytes, 0, maxsize);
	if (! xdr_u_int(xdrs, sizep)) {
#ifdef KERNEL
		printf("xdr_bytes: size FAILED\n");
#endif
		trace1(TR_xdr_bytes, 1);
		return (FALSE);
	}
	nodesize = *sizep;
	if ((nodesize > maxsize) && (xdrs->x_op != XDR_FREE)) {
#ifdef KERNEL
		printf("xdr_bytes: bad size FAILED\n");
#endif
		trace1(TR_xdr_bytes, 1);
		return (FALSE);
	}

	/*
	 * now deal with the actual bytes
	 */
	switch (xdrs->x_op) {

	case XDR_DECODE:
		if (nodesize == 0) {
			trace1(TR_xdr_bytes, 1);
			return (TRUE);
		}
		if (sp == NULL) {
			*cpp = sp = (char *)mem_alloc(nodesize);
		}
#ifndef KERNEL
		if (sp == NULL) {
			(void) syslog(LOG_ERR, xdr_err, (const char *)"bytes");
			trace1(TR_xdr_bytes, 1);
			return (FALSE);
		}
#endif
		/*FALLTHROUGH*/

	case XDR_ENCODE:
		dummy = xdr_opaque(xdrs, sp, nodesize);
		trace1(TR_xdr_bytes, 1);
		return (dummy);

	case XDR_FREE:
		if (sp != NULL) {
			mem_free(sp, nodesize);
			*cpp = NULL;
		}
		trace1(TR_xdr_bytes, 1);
		return (TRUE);
	}
#ifdef KERNEL
	printf("xdr_bytes: bad op FAILED\n");
#endif
	trace1(TR_xdr_bytes, 1);
	return (FALSE);
}

/*
 * Implemented here due to commonality of the object.
 */
bool_t
xdr_netobj(XDR *xdrs, struct netobj *np)
{
	bool_t dummy;

	trace1(TR_xdr_netobj, 0);
	dummy = xdr_bytes(xdrs, &np->n_bytes, &np->n_len, MAX_NETOBJ_SZ);
	trace1(TR_xdr_netobj, 1);
	return (dummy);
}

/*
 * XDR a descriminated union
 * Support routine for discriminated unions.
 * You create an array of xdrdiscrim structures, terminated with
 * an entry with a null procedure pointer.  The routine gets
 * the discriminant value and then searches the array of xdrdiscrims
 * looking for that value.  It calls the procedure given in the xdrdiscrim
 * to handle the discriminant.  If there is no specific routine a default
 * routine may be called.
 * If there is no specific or default routine an error is returned.
 */
bool_t
xdr_union(XDR *xdrs, enum_t *dscmp, char *unp,
		const struct xdr_discrim *choices, xdrproc_t dfault)
{
	register enum_t dscm;
	bool_t dummy;

	/*
	 * we deal with the discriminator;  it's an enum
	 */
	trace1(TR_xdr_union, 0);
	if (! xdr_enum(xdrs, dscmp)) {
#ifdef KERNEL
		printf("xdr_enum: dscmp FAILED\n");
#endif
		trace1(TR_xdr_union, 1);
		return (FALSE);
	}
	dscm = *dscmp;

	/*
	 * search choices for a value that matches the discriminator.
	 * if we find one, execute the xdr routine for that value.
	 */
	for (; choices->proc != NULL_xdrproc_t; choices++) {
		if (choices->value == dscm) {
			dummy = (*(choices->proc))(xdrs, unp, LASTUNSIGNED);
			trace1(TR_xdr_union, 1);
			return (dummy);
		}
	}

	/*
	 * no match - execute the default xdr routine if there is one
	 */
	dummy = (dfault == NULL_xdrproc_t) ? FALSE :
	    (*dfault)(xdrs, unp, LASTUNSIGNED);
	trace1(TR_xdr_union, 1);
	return (dummy);
}


/*
 * Non-portable xdr primitives.
 * Care should be taken when moving these routines to new architectures.
 */


/*
 * XDR null terminated ASCII strings
 * xdr_string deals with "C strings" - arrays of bytes that are
 * terminated by a NULL character.  The parameter cpp references a
 * pointer to storage; If the pointer is null, then the necessary
 * storage is allocated.  The last parameter is the max allowed length
 * of the string as specified by a protocol.
 */
bool_t
xdr_string(XDR *xdrs, char **cpp, uint_t maxsize)
{
	bool_t dummy;
	register char *newsp, *sp = *cpp;  /* sp is the actual string pointer */
	uint_t size, block;
	uint64_t bytesread;

	/*
	 * first deal with the length since xdr strings are counted-strings
	 */
	trace2(TR_xdr_string, 0, maxsize);
	switch (xdrs->x_op) {
	case XDR_FREE:
		if (sp == NULL) {
			trace1(TR_xdr_string, 1);
			return (TRUE);	/* already free */
		}
		/*FALLTHROUGH*/
	case XDR_ENCODE:
		size = (sp != NULL) ? (uint_t)strlen(sp) : 0;
		break;
	}
	/*
	 * We decided not to use MACRO XDR_U_INT here, because the
	 * advantages here will be miniscule compared to xdr_string.
	 * This saved us 100 bytes in the library size.
	 */
	if (! xdr_u_int(xdrs, &size)) {
		trace1(TR_xdr_string, 1);
		return (FALSE);
	}
	if (size > maxsize) {
		trace1(TR_xdr_string, 1);
		return (FALSE);
	}

	/*
	 * now deal with the actual bytes
	 */
	switch (xdrs->x_op) {

	case XDR_DECODE:
		/* if buffer is already given, call xdr_opaque() directly */
		if (sp != NULL) {
			dummy = xdr_opaque(xdrs, sp, size);
			sp[size] = 0;
			trace1(TR_xdr_string, 1);
			return (dummy);
		}

		/*
		 * We have to allocate a buffer of size 'size'. To avoid
		 * malloc()ing one huge chunk, we'll read the bytes in max
		 * FRAGMENT size blocks and keep realloc()ing. 'block' is
		 * the number of bytes to read in each xdr_opaque() and
		 * 'bytesread' is what we have already read. sp is NULL
		 * when we are in the loop for the first time.
		 */
		bytesread = 0;
		do {
			block = MIN(size - bytesread, FRAGMENT);
			/*
			 * allocate enough for 'bytesread + block' bytes and
			 * one extra for the terminating NULL.
			 */
			newsp = realloc(sp, bytesread + block + 1);
			if (newsp == NULL) {
				if (sp != NULL)
					free(sp);
				trace1(TR_xdr_string, 1);
				return (FALSE);
			}
			sp = newsp;
			if (!xdr_opaque(xdrs, &sp[bytesread], block)) {
				free(sp);
				trace1(TR_xdr_string, 1);
				return (FALSE);
			}
			bytesread += block;
		} while (bytesread < size);

		sp[bytesread] = 0; /* terminate the string with a NULL */
		*cpp = sp;
		trace1(TR_xdr_string, 1);
		return (TRUE);
	case XDR_ENCODE:
		dummy = xdr_opaque(xdrs, sp, size);
		trace1(TR_xdr_string, 1);
		return (dummy);
	case XDR_FREE:
		free(sp);
		*cpp = NULL;
		trace1(TR_xdr_string, 1);
		return (TRUE);
	}
#ifdef KERNEL
	printf("xdr_string: bad op FAILED\n");
#endif
	trace1(TR_xdr_string, 1);
	return (FALSE);
}

bool_t
xdr_hyper(XDR *xdrs, longlong_t *hp)
{
	bool_t	dummy;

	trace1(TR_xdr_hyper, 0);
	if (xdrs->x_op == XDR_ENCODE) {
#if defined(_LONG_LONG_HTOL)
		if (XDR_PUTINT32(xdrs, (int *)hp) == TRUE) {
			dummy = XDR_PUTINT32(xdrs, (int *)((char *)hp +
				BYTES_PER_XDR_UNIT));
			trace1(TR_xdr_hyper, 1);
			return (dummy);
		}

#else
		if (XDR_PUTINT32(xdrs, (int *)((char *)hp +
			BYTES_PER_XDR_UNIT)) == TRUE) {
			dummy = XDR_PUTINT32(xdrs, (int32_t *)hp);
			trace1(TR_xdr_hyper, 1);
			return (dummy);
		}

#endif
		trace1(TR_xdr_hyper, 1);
		return (FALSE);

	} else if (xdrs->x_op == XDR_DECODE) {
#if defined(_LONG_LONG_HTOL)
		if (XDR_GETINT32(xdrs, (int *)hp) == FALSE ||
		    (XDR_GETINT32(xdrs, (int *)((char *)hp +
				BYTES_PER_XDR_UNIT)) == FALSE)) {
			trace1(TR_xdr_hyper, 1);
			return (FALSE);
		}
#else
		if ((XDR_GETINT32(xdrs, (int *)((char *)hp +
				BYTES_PER_XDR_UNIT)) == FALSE) ||
				(XDR_GETINT32(xdrs, (int *)hp) == FALSE)) {
			trace1(TR_xdr_hyper, 1);
			return (FALSE);
		}
#endif
		trace1(TR_xdr_hyper, 1);
		return (TRUE);
	}
	trace1(TR_xdr_hyper, 1);
	return (TRUE);
}

bool_t
xdr_u_hyper(XDR *xdrs, u_longlong_t *hp)
{
	bool_t dummy;

	trace1(TR_xdr_u_hyper, 0);
	dummy = xdr_hyper(xdrs, (longlong_t *)hp);
	trace1(TR_xdr_u_hyper, 1);
	return (dummy);
}

bool_t
xdr_longlong_t(XDR *xdrs, longlong_t *hp)
{
	bool_t dummy;

	trace1(TR_xdr_longlong_t, 0);
	dummy = xdr_hyper(xdrs, hp);
	trace1(TR_xdr_longlong_t, 1);
	return (dummy);
}

bool_t
xdr_u_longlong_t(XDR *xdrs, u_longlong_t *hp)
{
	bool_t dummy;

	trace1(TR_xdr_u_longlong_t, 0);
	dummy = xdr_hyper(xdrs, (longlong_t *)hp);
	trace1(TR_xdr_u_longlong_t, 1);
	return (dummy);
}
/*
 * The following routine is part of a workaround for bug
 * #1128007.  When it is fixed, this routine should be
 * removed.
 */
bool_t
xdr_ulonglong_t(XDR *xdrs, u_longlong_t *hp)
{
	bool_t dummy;

	trace1(TR_xdr_u_longlong_t, 0);
	dummy = xdr_hyper(xdrs, (longlong_t *)hp);
	trace1(TR_xdr_u_longlong_t, 1);
	return (dummy);
}

#ifndef KERNEL
/*
 * Wrapper for xdr_string that can be called directly from
 * routines like clnt_call
 */
bool_t
xdr_wrapstring(XDR *xdrs, char **cpp)
{
	trace1(TR_xdr_wrapstring, 0);
	if (xdr_string(xdrs, cpp, LASTUNSIGNED)) {
		trace1(TR_xdr_wrapstring, 1);
		return (TRUE);
	}
	trace1(TR_xdr_wrapstring, 1);
	return (FALSE);
}
#endif /* !KERNEL */
