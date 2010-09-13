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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * nlsaddr.c:
 *
 * name/address conversion routines for listener and nlsadmin
 * and other user processes.  Converts internal address <--> external addr
 *
 * internal address is any number of octets. (length must be provided)
 * external address is ascii/hex string. (implicit length)
 *
 *
 * nlscalloc:	dynamically allocates a t_call structure large enough
 *		to hold the external representations of addr, opt and udata.
 *		Use t_free to release the call structure.
 *
 * nlsaddr2c:	Convert internal address to external form.
 *
 * nlsc2addr:	Convert external address to internal form.
 *
 */

#include <ctype.h>
#include <sys/tiuser.h>

#ifndef	T_NONE
#define	T_NONE	0
#endif

/*
 * define DEBUGMODE for diagnostic printf's to stderr
 */

/* #define	DEBUGMODE */

#ifdef	DEBUGMODE
#include <stdio.h>
#endif

/* use to debug in listener *only* (not in user programs) */
/* #define DEBUG(args)	debug args */

#ifndef	DEBUG
#define DEBUG(args)
#endif


/*
 * asctohex(X):  convert char X to integer value
 *		 assumes isxdigit(X). returns integer value.
 *		 Note that 'a' > 'A'.  See usage in code below.
 */

#define asctohex(X)	\
    ((int)(isdigit(X) ? (int)(X-'0') : (X>='a') ? (X-'a')+10 : (X-'A')+10))

/*
 * externsz(I):	returns the number of chars required to hold an external
 *		address whose internal representation contains I octets.
 *		Adds enough space for a 16 char environ name to be prepended
 *		to the external name for the listener.
 */

#define	externsz(I)	(unsigned int)((I<<1) + 41)


/*
 * nlscalloc:	allocate a call structure large enough to hold the
 *		external representation of the addr, opt and udata fields.
 *		similar to the way t_alloc works for the internal 
 *		representation of an address.
 *
 *		returns a pointer to the t_call strucure if successful,
 *		a NULL pointer indicates failure. The external integer
 *		t_errno will contain an error code.
 *
 */

struct t_call *
nlscalloc(fd)
int fd;
{
	struct t_info info;
	struct t_call *call;
	register unsigned size;
	register char *p;
	extern char *malloc(), *t_alloc();
	extern int t_getinfo();
	extern char *malloc();
	extern int t_errno, errno;

	if (t_getinfo(fd, &info) == -1)  {
		DEBUG((5, "nlscalloc: t_getinfo failed, t_errno %d errno %d"));
		return ((struct t_call *)0);
	}

	if (!(call = (struct t_call *)t_alloc(fd, T_CALL, T_NONE)))  {
		DEBUG((5, "nlscalloc: t_alloc failed, t_errno %d errno %d"));
		return ((struct t_call *)0);
	}

	if (size = externsz((unsigned)info.addr))
		if (!(p = malloc(size)))
			goto fail;
	if (call->addr.maxlen = size)
		call->addr.buf = p;

	if (size = externsz((unsigned)info.options))
		if (!(p = malloc(size)))
			goto fail;
	if (call->opt.maxlen = size)
		call->opt.buf = p;

	if (size = externsz((unsigned)info.connect))
		if (!(p = malloc(size)))
			goto fail;
	if (call->udata.maxlen = size)
		call->udata.buf = p;

	return(call);

fail:
	DEBUG((1, "nlscalloc: malloc failed!"));
	t_free((char *)call, T_CALL);	/* t_free will release allocated mem*/
	t_errno = TSYSERR;		/* errno must be ENOMEM	*/
	return((struct t_call *)0);
}


/*
 * nlsaddr2c:	given a pointer to a logical address and it's length
 *		and a receiving buffer, addr2char converts the
 *		logical address to the hex/ascii char
 *		representation of that address.
 *
 * WARNING:	The receiving buffer must be large enough.
 *		rcv buffer must be at least (2*len)+1 bytes.
 *
 */

static char hex_digits[] = "0123456789ABCDEF";

void
nlsaddr2c(charaddr, addr, len)
char *charaddr, *addr;
int len;
{
	register unsigned i;

	while (len--)  {
		i = (unsigned)*addr++;
		*charaddr++ = hex_digits[(i>>4) & 0xf];
		*charaddr++ = hex_digits[i & 0xf];
	}
	*charaddr = (char)0;
}


/*
 * nlsc2addr:	Given a buffer containing the hex/ascii representation
 *		of a logical address, the buffer's size and an address
 *		of a receiving buffer, char2addr converts the logical
 *		addr to internal format and returns the size of the logical
 *		address.  A negative value is returned and the receiving
 *		buffers contents are undefined if:
 *
 *		A.  The receiving buffer is not large enough. (rc = -1)
 *		B.  If 'charaddr' does not contain a series of octets 
 *		    (strlen(charaddr) must be even). (rc = -2)
 *		C.  Any character in 'charaddr' is not an ASCII hex digit.
 *		    (rc = -3)
 *
 *	NOTE: that even if the internal representation of an address is
 *	an ASCII string, there is no guarantee that the output will be
 *	null terminated, thus the returned length must be used when
 *	accessing the internal address.
 */


int
nlsc2addr(addr, maxlen, charaddr)
char *addr, *charaddr;
int maxlen;
{
	int len;
	int i;
	char c;
	unsigned char val;

	if (strlen(charaddr) & 1)
		return(-1);

	for (len = 0; ((maxlen--) && (*charaddr)); ++len)  {
		for (i = 2,  val = 0;  i--;  )  {
			c = *charaddr++;
			if (!(isxdigit(c)))
				return(-3);
			val = (val << 4) | (unsigned char)asctohex(c);
	    	}

		*addr++ = (char)val;
	}

#ifdef	DEBUGMODE
	fprintf(stderr, "nlsc2addr: returned length = %d\n", len);
#endif

	return(*charaddr ? -2 : len);
}

