/*
 * Copyright (C) 2004, 2007, 2008  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 1998, 1999, 2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: bitypes.h,v 1.7 2008/11/14 02:54:35 tbox Exp $ */

#ifndef __BIT_TYPES_DEFINED__
#define __BIT_TYPES_DEFINED__

	/*
	 * Basic integral types.  Omit the typedef if
	 * not possible for a machine/compiler combination.
	 */

#ifdef NEED_SOLARIS_BITTYPES
	typedef /*signed*/ char            int8_t;
	typedef short                     int16_t;
	typedef int                       int32_t;
#endif
	typedef unsigned char            u_int8_t;
	typedef unsigned short          u_int16_t;
	typedef unsigned int            u_int32_t;

#endif	/* __BIT_TYPES_DEFINED__ */
