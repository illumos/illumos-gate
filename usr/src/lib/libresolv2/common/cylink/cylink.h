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
 
/**********************************************************************\
*  FILENAME:  cylink.h     PRODUCT NAME: 
*
*  DESCRIPTION:  Company standard include file
*
*  USAGE:          File should be #included
*
*
*         Copyright (c) Cylink Corporation 1994. All rights reserved.
*
*  REVISION  HISTORY:
*
\**********************************************************************/

#ifndef CYLINK_H  /* Prevent multiple inclusions of same header file */
#define CYLINK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#if (!defined(BSD)) || (BSD < 199306)
# include <sys/bitypes.h>
#else
# include <sys/types.h>
#endif

#if	! ( defined(__alpha) && defined(__osf__) ) /* in sys/types.h */
#if !defined(_H_INTTYPES) && !defined (_H_TYPES)   /* AIX puts this in inttypes.h */
typedef unsigned char  uchar;
#endif /* _H_INTTYPES */
#endif

typedef u_int16_t USHORT;
typedef u_int32_t ULONG;

#define              FALSE                   0
#define        TRUE            1

/*-- ANSI-recommended NULL Pointer definition --*/
#ifndef              NULL
#define             NULL    (void *) 0
#endif

#endif     /* CYLINK_H */
