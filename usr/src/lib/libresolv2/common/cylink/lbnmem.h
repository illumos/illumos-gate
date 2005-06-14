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
 
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Operations on the usual buffers of bytes
 */
#ifndef BNSECURE
#define BNSECURE 1
#endif

/*
 * These operations act on buffers of memory, just like malloc & free.
 * One exception: it is not legal to pass a NULL pointer to lbnMemFree.
 */

#ifndef lbnMemAlloc
void *lbnMemAlloc(unsigned bytes);
#endif

#ifndef lbnMemFree
void lbnMemFree(void *ptr, unsigned bytes);
#endif

/* This wipes out a buffer of bytes if necessary needed. */

#ifndef lbnMemWipe
#if BNSECURE
void lbnMemWipe(void *ptr, unsigned bytes);
#else
#define lbnMemWipe(ptr, bytes) (void)(ptr,bytes)
#endif
#endif /* !lbnMemWipe */

/*
 * lbnRealloc is NOT like realloc(); it's endian-sensitive!
 * If lbnMemRealloc is #defined, lbnRealloc will be defined in terms of it.
 * It is legal to pass a NULL pointer to lbnRealloc, although oldbytes
 * will always be sero.
 */
#ifndef lbnRealloc
void *lbnRealloc(void *ptr, unsigned oldbytes, unsigned newbytes);
#endif


/*
 * These macros are the ones actually used most often in the math library.
 * They take and return pointers to the *end* of the given buffer, and
 * take sizes in terms of words, not bytes.
 *
 * Note that LBNALLOC takes the pointer as an argument instead of returning
 * the value.
 *
 * Note also that these macros are only useable if you have included
 * lbn.h (for the BIG and BIGLITTLE macros), which this file does NOT include.
 */

#define LBNALLOC(p,words) BIGLITTLE( \
	if ( ((p) = lbnMemAlloc((words)*sizeof*(p))) != 0) (p) += (words), \
	(p) = lbnMemAlloc((words) * sizeof*(p)) \
	)
#define LBNFREE(p,words) lbnMemFree((p) BIG(-(words)), (words) * sizeof*(p))
#define LBNREALLOC(p,old,new) \
	lbnRealloc(p, (old) * sizeof*(p), (new) * sizeof*(p))
#define LBNWIPE(p,words) lbnMemWipe((p) BIG(-(words)), (words) * sizeof*(p))

