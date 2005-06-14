/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Cylink Corporation © 1998
 * 
 * This software is licensed by Cylink to the Internet Software Consortium to
 * promote implementation of royalty free public key cryptography within IETF
 * standards.  Cylink wishes to expressly thank the contributions of Dr.
 * Martin Hellman, Whitfield Diffie, Ralph Merkle and Stanford University for
 * their contributions to Internet Security.  In accordance with the terms of
 * this license, ISC is authorized to distribute and sublicense this software
 * for the practice of IETF standards.  
 *
 * The software includes BigNum, written by Colin Plumb and licensed by Philip
 * R. Zimmermann for royalty free use and distribution with Cylink's
 * software.  Use of BigNum as a stand alone product or component is
 * specifically prohibited.
 *
 * Disclaimer of All Warranties. THIS SOFTWARE IS BEING PROVIDED "AS IS",
 * WITHOUT ANY EXPRESSED OR IMPLIED WARRANTY OF ANY KIND WHATSOEVER. IN
 * PARTICULAR, WITHOUT LIMITATION ON THE GENERALITY OF THE FOREGOING, CYLINK
 * MAKES NO REPRESENTATION OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 *
 * Cylink or its representatives shall not be liable for tort, indirect,
 * special or consequential damages such as loss of profits or loss of
 * goodwill from the use or inability to use the software for any purpose or
 * for any reason whatsoever.
 *
 * EXPORT LAW: Export of the Foundations Suite may be subject to compliance
 * with the rules and regulations promulgated from time to time by the Bureau
 * of Export Administration, United States Department of Commerce, which
 * restrict the export and re-export of certain products and technical data.
 * If the export of the Foundations Suite is controlled under such rules and
 * regulations, then the Foundations Suite shall not be exported or
 * re-exported, directly or indirectly, (a) without all export or re-export
 * licenses and governmental approvals required by any applicable laws, or (b)
 * in violation of any applicable prohibition against the export or re-export
 * of any part of the Foundations Suite. All export licenses for software
 * containing the Foundations Suite are the sole responsibility of the licensee.
 */
 
/*
 * lbnmem.c - low-level bignum memory handling.
 *
 * Copyright (c) 1995  Colin Plumb.  All rights reserved.
 * For licensing and other legal details, see the file legal.c.
 *
 * Note that in all cases, the pointers passed around
 * are pointers to the *least* significant end of the word.
 * On big-endian machines, these are pointers to the *end*
 * of the allocated range.
 *
 * BNSECURE is a simple level of security; for more security
 * change these function to use locked unswappable memory.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "port_before.h"

#ifndef HAVE_CONFIG_H
#define HAVE_CONFIG_H 0
#endif
#if HAVE_CONFIG_H
#include "config.h"
#endif

/*
 * Some compilers complain about #if FOO if FOO isn't defined,
 * so do the ANSI-mandated thing explicitly...
 */
#ifndef NO_STDLIB_H
#define NO_STDLIB_H 0
#endif
#ifndef NO_STRING_H
#define NO_STRING_H 0
#endif
#ifndef HAVE_STRINGS_H
#define HAVE_STRINGS_H 0
#endif
#ifndef NEED_MEMORY_H
#define NEED_MEMORY_H 0
#endif

#if !NO_STDLIB_H
#include <stdlib.h>	/* For malloc() & co. */
#else
void *malloc();
void *realloc();
void free();
#endif

#if !NO_STRING_H
#include <string.h>	/* For memset */
#elif HAVE_STRINGS_H
#include <strings.h>
#endif
#if NEED_MEMORY_H
#include <memory.h>
#endif

#ifndef DBMALLOC
#define DBMALLOC 0
#endif
#if DBMALLOC
/* Development debugging */
#include "../dbmalloc/malloc.h"
#endif

#include "lbn.h"
#include "lbnmem.h"

#include "kludge.h"

#ifndef lbnMemWipe
void
lbnMemWipe(void *ptr, unsigned bytes)
{
	memset(ptr, 0, bytes);
}
#define lbnMemWipe(ptr, bytes) memset(ptr, 0, bytes)
#endif

#ifndef lbnMemAlloc
void *
lbnMemAlloc(unsigned bytes)
{
	return malloc(bytes);
}
#define lbnMemAlloc(bytes) malloc(bytes)
#endif

#ifndef lbnMemFree
void
lbnMemFree(void *ptr, unsigned bytes)
{
	lbnMemWipe(ptr, bytes);
	free(ptr);
}
#endif

#ifndef lbnRealloc
#if defined(lbnMemRealloc) || !BNSECURE
void *
lbnRealloc(void *ptr, unsigned oldbytes, unsigned newbytes)
{
	if (ptr) {
		BIG(ptr = (char *)ptr - oldbytes;)
		if (newbytes < oldbytes)
			memmove(ptr, (char *)ptr + oldbytes-newbytes, oldbytes);
	}
#ifdef lbnMemRealloc
	ptr = lbnMemRealloc(ptr, oldbytes, newbytes);
#else
	ptr = realloc(ptr, newbytes);
#endif
	if (ptr) {
		if (newbytes > oldbytes)
			memmove((char *)ptr + newbytes-oldbytes, ptr, oldbytes);
		BIG(ptr = (char *)ptr + newbytes;)
	}

	return ptr;
}

#else /* BNSECURE */

void *
lbnRealloc(void *oldptr, unsigned oldbytes, unsigned newbytes)
{
	void *newptr = lbnMemAlloc(newbytes);

	if (!newptr)
		return newptr;
	if (!oldptr)
		return BIGLITTLE((char *)newptr+newbytes, newptr);

	/*
	 * The following copies are a bit non-obvious in the big-endian case
	 * because one of the pointers points to the *end* of allocated memory.
	 */
	if (newbytes > oldbytes) {	/* Copy all of old into part of new */
		BIG(newptr = (char *)newptr + newbytes;)
		BIG(oldptr = (char *)oldptr - oldbytes;)
		memcpy(BIGLITTLE((char *)newptr-oldbytes, newptr), oldptr,
		       oldbytes);
	} else {	/* Copy part of old into all of new */
		memcpy(newptr, BIGLITTLE((char *)oldptr-newbytes, oldptr),
		       newbytes);
		BIG(newptr = (char *)newptr + newbytes;)
		BIG(oldptr = (char *)oldptr - oldbytes;)
	}

	lbnMemFree(oldptr, oldbytes);
	return newptr;
}
#endif /* BNSECURE */
#endif /* !lbnRealloc */
