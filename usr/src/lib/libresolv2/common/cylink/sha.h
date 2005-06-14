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
 
/****************************************************************************
*  FILENAME:  sha.h           PRODUCT NAME: CRYPTOGRAPHIC TOOLKIT
*
*  FILE STATUS:
*
*  DESCRIPTION:     Cryptographic Toolkit Internal Functions Header File
*
*  USAGE:           File should be included in Toolkit functions files
*
*
*       Copyright (c) Cylink Corporation 1994. All rights reserved.
*
*  REVISION  HISTORY:
*
*  24 Sep 94  KPZ             Initial release
*
****************************************************************************/
#ifndef SHA_H
#define SHA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "cylink.h"

#define       SHS_BLOCKSIZE      64
/*
#define FSHA(x,y,z) ( ( x & y ) | ( ~x & z ) )
#define GSHA(x,y,z) ( x ^ y ^ z )
#define HSHA(x,y,z) ( ( x & y ) | ( x & z ) | ( y & z ) )
#define ISHA(x,y,z) (x ^ y ^ z)
*/
/*#define f1(x,y,z)     ( (x & y) | (~x & z) )          // Rounds  0-19 */
#define f1(x,y,z)     ( z ^ (x & (y ^ z) ) )          /* Rounds  0-19 */
#define f2(x,y,z)     ( x ^ y ^ z )                   /* Rounds 20-39 */
/*#define f3(x,y,z)   ( (x & y) | (x & z) | (y & z) ) // Rounds 40-59 */
#define f3(x,y,z)     ( (x & y) | (z & (x | y) ) )    /* Rounds 40-59 */
#define f4(x,y,z)     ( x ^ y ^ z )                   /* Rounds 60-79 */


#define RotateLeft(x,n) (( x << n )|( x >> (32-n) ) )  /*Circular left shift operation*/

/*
 * Note: for on28 port, and to silence compiler warnings when the value is
 *       larger than or equal to 0x80000000, change constants to be U rather
 *       than L.
 */

/*SHS Constants */
#define k1SHA  0x5a827999U
#define k2SHA  0x6ed9eba1U
#define k3SHA  0x8f1bbcdcU
#define k4SHA  0xca62c1d6U

/*SHS initial value */
#define h0SHA  0x67452301U
#define h1SHA  0xefcdab89U
#define h2SHA  0x98badcfeU
#define h3SHA  0x10325476U
#define h4SHA  0xc3d2e1f0U

/*The initial expanding function*/
#define expand(count) \
   {\
        W[count] = W[count-3] ^ W[count-8] ^ W[count-14] ^ W[count-16];\
        W[count] = RotateLeft( W[count], 1 );\
        }

/*New variant */
#define subRound(a, b, c, d, e, f, k, data) \
  ( e += RotateLeft(a,5) + f(b, c, d) + k + data, b = RotateLeft( b,30) )



/*The four sub_rounds*/
/*
#define subR1(count) \
  {\
   temp=RotateLeft(A,5) + FSHA(B,C,D) + E +W[count] +k1SHA;\
   E = D; \
   D = C; \
   C = RotateLeft(B,30); \
   B = A; \
   A = temp; \
  }

#define subR2(count) \
  {\
   temp=RotateLeft(A,5) + GSHA(B,C,D) + E +W[count] +k2SHA;\
   E = D; \
   D = C; \
   C = RotateLeft(B,30);\
   B = A; \
   A = temp; \
  }

#define subR3(count) \
  {\
   temp=RotateLeft(A,5) + HSHA(B,C,D) + E +W[count] +k3SHA;\
   E = D; \
   D = C; \
   C = RotateLeft(B,30);\
   B = A; \
   A = temp; \
  }

#define subR4(count) \
  {\
   temp=RotateLeft(A,5) + ISHA(B,C,D) + E + W[count] +k4SHA;\
   E = D; \
   D = C; \
   C = RotateLeft(B,30);\
   B = A; \
   A = temp; \
  }
*/
#endif  /* SHA_H */

