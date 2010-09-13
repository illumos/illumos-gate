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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This code is conformant to RFC 3542.
 */

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include <stdio.h>

#define	bufpos(p) ((p) - (uint8_t *)extbuf)

/*
 * Section 10.1 RFC3542.  This function returns the size of the empty
 * extension header.  If extbuf is not NULL then it initializes its length
 * field.  If extlen is invalid then -1 is returned.
 */
int
inet6_opt_init(void *extbuf, socklen_t extlen)
{
	if (extbuf && ((extlen < 0) || (extlen % 8))) {
		return (-1);
	}

	if (extbuf) {
		*(uint8_t *)extbuf = 0;
		*((uint8_t *)extbuf + 1) = extlen/8 - 1;
	}

	return (2);
}

/*
 * Section 10.2 RFC3542.  This function appends an option to an already
 * initialized option buffer.  inet6_opt_append() returns the total length
 * after adding the option.
 */
int
inet6_opt_append(void *extbuf, socklen_t extlen, int offset, uint8_t type,
	socklen_t len, uint_t align, void **databufp)
{
	uint8_t *p;
	socklen_t endlen;
	int remainder, padbytes;

	if (align > len ||
	    (align != 1 && align != 2 && align != 4 && align != 8) ||
	    len < 0 || len > 255 || type < 2) {
		return (-1);
	}

	if (extbuf) {
		/*
		 * The length of the buffer is the minimum of the length
		 * passed in and the length stamped onto the buffer.  The
		 * length stamped onto the buffer is the number of 8 byte
		 * octets in the buffer minus 1.
		 */
		extlen = MIN(extlen, (*((uint8_t *)extbuf + 1) + 1) * 8);
	}

	remainder = (offset + 2 + len) % align;
	if (remainder == 0) {
		padbytes = 0;
	} else {
		padbytes = align - remainder;
	}

	endlen = offset + padbytes + 2 + len;
	if ((endlen > extlen) || !extbuf) {
		if (extbuf) {
			return (-1);
		} else {
			return (endlen);
		}
	}

	p = (uint8_t *)extbuf + offset;
	if (padbytes != 0) {
		/*
		 * Pad out the buffer here with pad options.  If its only
		 * one byte then there is a special TLV with no L or V, just
		 * a zero to say skip this byte.  For two bytes or more
		 * we have a special TLV with type 0 and length the number of
		 * padbytes.
		 */
		if (padbytes == 1) {
			*p = IP6OPT_PAD1;
		} else {
			*p = IP6OPT_PADN;
			*(p + 1) = padbytes - 2;
			memset(p + 2, 0, padbytes - 2);
		}
		p += padbytes;
	}

	*p++ = type;
	*p++ = len;
	if (databufp) {
		*databufp = p;
	}
	return (endlen);
}

/*
 * Section 10.3 RFC3542.  This function returns the updated total length.
 * This functions inserts pad options to complete the option header as
 * needed.
 */
int
inet6_opt_finish(void *extbuf, socklen_t extlen, int offset)
{
	uint8_t *p;
	int padbytes;

	if (extbuf) {
	/*
	 * The length of the buffer is the minimum of the length
	 * passed in and the length stamped onto the buffer.  The
	 * length stamped onto the buffer is the number of 8 byte
	 * octets in the buffer minus 1.
	 */
		extlen = MIN(extlen, (*((uint8_t *)extbuf + 1) + 1) * 8);
	}

	padbytes = 8 - (offset % 8);
	if (padbytes == 8)
		padbytes = 0;

	if ((offset + padbytes > extlen) || !extbuf) {
		if (extbuf) {
			return (-1);
		} else {
			return (offset + padbytes);
		}
	}

	p = (uint8_t *)extbuf + offset;
	if (padbytes != 0) {
		/*
		 * Pad out the buffer here with pad options.  If its only
		 * one byte then there is a special TLV with no L or V, just
		 * a zero to say skip this byte.  For two bytes or more
		 * we have a special TLV with type 0 and length the number of
		 * padbytes.
		 */
		if (padbytes == 1) {
			*p = IP6OPT_PAD1;
		} else {
			*p = IP6OPT_PADN;
			*(p + 1) = padbytes - 2;
			memset(p + 2, 0, padbytes - 2);
		}
		p += padbytes;
	}

	return (offset + padbytes);
}

/*
 * Section 10.4 RFC3542.  Ths function takes a pointer to the data as
 * returned by inet6_opt_append and inserts the data.
 */
int
inet6_opt_set_val(void *databuf, int offset, void *val, socklen_t vallen)
{
	memcpy((uint8_t *)databuf + offset, val, vallen);
	return (offset + vallen);
}

/*
 * Section 10.5 RFC 3542.  Starting walking the option header offset into the
 * header.  Returns where we left off.  You take the output of this function
 * and pass it back in as offset to iterate. -1 is returned on error.
 *
 * We use the fact that the first unsigned 8 bit quantity in the option
 * header is the type and the second is the length.
 */
int
inet6_opt_next(void *extbuf, socklen_t extlen, int offset, uint8_t *typep,
	socklen_t *lenp, void **databufp)
{
	uint8_t *p;
	uint8_t *end;

	/*
	 * The length of the buffer is the minimum of the length
	 * passed in and the length stamped onto the buffer.  The
	 * length stamped onto the buffer is the number of 8 byte
	 * octets in the buffer minus 1.
	 */
	extlen = MIN(extlen, (*((uint8_t *)extbuf + 1) + 1) * 8);
	end = (uint8_t *)extbuf + extlen;
	if (offset == 0) {
		offset = 2;
	}

	/* assumption: IP6OPT_PAD1 == 0 and IP6OPT_PADN == 1 */
	p = (uint8_t *)extbuf + offset;
	while (*p == IP6OPT_PAD1 || *p == IP6OPT_PADN) {
		switch (*p) {
		case IP6OPT_PAD1:
			p++;
			break;
		case IP6OPT_PADN:
			/* *(p + 1) is the length of the option. */
			if (p + 2 + *(p + 1) >= end)
				return (-1);
			p += *(p + 1) + 2;
			break;
		}
	}

	/* type, len, and data must fit... */
	if ((p + 2 >= end) || (p + 2 + *(p + 1) > end)) {
		return (-1);
	}

	if (typep) {
		*typep = *p;
	}
	if (lenp) {
		*lenp = *(p + 1);
	}
	if (databufp) {
		*databufp = p + 2;
	}

	return ((p - (uint8_t *)extbuf) + 2 + *lenp);
}

/*
 * Section 10.6 RFC 3542.  Starting walking the option header offset into the
 * header.  Returns where we left off.  You take the output of this function
 * and pass it back in as offset to iterate. -1 is returned on error.
 *
 * We use the fact that the first unsigned 8 bit quantity in the option
 * header is the type and the second is the length.
 */
int
inet6_opt_find(void *extbuf, socklen_t extlen, int offset, uint8_t type,
	socklen_t *lenp, void **databufp)
{
	uint8_t newtype;

	do {
		offset = inet6_opt_next(extbuf, extlen, offset, &newtype, lenp,
		    databufp);

		if (offset == -1)
			return (-1);
	} while (newtype != type);

	/* value to feed back into inet6_opt_find() as offset */
	return (offset);
}

/*
 * Section 10.7 RFC 3542.  databuf should be a pointer as returned by
 * inet6_opt_next or inet6_opt_find.  The data is extracted from the option
 * at that point.
 */
int
inet6_opt_get_val(void *databuf, int offset, void *val, socklen_t vallen)
{
	memcpy(val, (uint8_t *)databuf + offset, vallen);
	return (offset + vallen);
}
