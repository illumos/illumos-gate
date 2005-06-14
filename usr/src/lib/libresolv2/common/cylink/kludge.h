/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef KLUDGE_H
#define KLUDGE_H

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
 * Kludges for not-quite-ANSI systems.
 * This should always be the last file included, because it may
 * mess up some system header files.
 */

/*
 * Some compilers complain about #if FOO if FOO isn't defined,
 * so do the ANSI-mandated thing explicitly...
 */
#ifndef ASSERT_NEEDS_STDIO
#define ASSERT_NEEDS_STDIO 0
#endif
#ifndef ASSERT_NEEDS_STDLIB
#define ASSERT_NEEDS_STDLIB 0
#endif
#ifndef NO_STDLIB_H
#define NO_STDLIB_H 0
#endif

/* SunOS 4.1.x <assert.h> needs "stderr" defined, and "exit" declared... */
#ifdef assert
#if ASSERT_NEEDS_STDIO
#include <stdio.h>
#endif
#if ASSERT_NEEDS_STDLIB
#if !NO_STDLIB_H
#include <stdlib.h>
#endif
#endif
#endif

#ifndef NO_MEMMOVE
#define NO_MEMMOVE 0
#endif
#if NO_MEMMOVE	/* memove() not in libraries */
#define memmove(dest,src,len) bcopy(src,dest,len)
#endif

#ifndef NO_MEMCPY
#define NO_MEMCPY 0
#endif
#if NO_MEMCPY	/* memcpy() not in libraries */
#define memcpy(dest,src,len) bcopy(src,dest,len)
#endif

#ifndef MEM_PROTOS_BROKEN
#define MEM_PROTOS_BROKEN 0
#endif
#if MEM_PROTOS_BROKEN
#define memcpy(d,s,l) memcpy((void *)(d), (void const *)(s), l)
#define memmove(d,s,l) memmove((void *)(d), (void const *)(s), l)
#define memcmp(d,s,l) memcmp((void const *)(d), (void const *)(s), l)
#define memset(d,v,l) memset((void *)(d), v, l)
#endif

/*
 * If there are no prototypes for the stdio functions, use these to
 * reduce compiler warnings.  Uses EOF as a giveaway to indicate
 * that <stdio.h> was #included.
 */
#ifndef NO_STDIO_PROTOS
#define NO_STDIO_PROTOS 0
#endif
#if NO_STDIO_PROTOS	/* Missing prototypes for "simple" functions */
#ifdef EOF
#ifdef __cplusplus
extern "C" {
#endif
int (puts)(char const *);
int (fputs)(char const *, FILE *);
int (fflush)(FILE *);
int (printf)(char const *, ...);
int (fprintf)(FILE *, char const *, ...);
/* If we have a sufficiently old-fashioned stdio, it probably uses these... */
int (_flsbuf)(int, FILE *);
int (_filbuf)(FILE *);
#ifdef __cplusplus
}
#endif
#endif /* EOF */
#endif /* NO_STDIO_PROTOS */

/*
 * Borland C seems to think that it's a bad idea to decleare a
 * structure tag and not declare the contents.  I happen to think
 * it's a *good* idea to use such "opaque" structures wherever
 * possible.  So shut up.
 */
#ifdef __BORLANDC__
#pragma warn -stu
#ifndef MSDOS
#define MSDOS 1
#endif
#endif

/* Turn off warning about negation of unsigned values */
#ifdef _MSC_VER
#pragma warning(disable:4146)
#endif

/* Cope with people forgetting to define the OS, if possible... */

#ifndef MSDOS
#ifdef __MSDOS
#define MSDOS 1
#endif
#endif
#ifndef MSDOS
#ifdef __MSDOS__
#define MSDOS 1
#endif
#endif

#endif /* KLUDGE_H */
