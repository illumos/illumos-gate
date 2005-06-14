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
 * lbn68000.h - 16-bit bignum primitives for the 68000 (or 68010) processors.
 *
 * These primitives use little-endian word order.
 * (The order of bytes within words is irrelevant.)
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define BN_LITTLE_ENDIAN 1

typedef unsigned short bnword16
#define BNWORD16 bnword16

bnword16 lbnSub1_16(bnword16 *num, unsigned len, bnword16 borrow);
bnword16 lbnAdd1_16(bnword16 *num, unsigned len, bnword16 carry);
void lbnMulN1_16(bnword16 *out, bnword16 const *in, unsigned len, bnword16 k);
bnword16
lbnMulAdd1_16(bnword16 *out, bnword16 const *in, unsigned len, bnword16 k);
bnword16
lbnMulSub1_16(bnword16 *out, bnword16 const *in, unsigned len, bnword16 k);
bnword16 lbnDiv21_16(bnword16 *q, bnword16 nh, bnword16 nl, bnword16 d);
unsigned lbnModQ_16(bnword16 const *n, unsigned len, bnword16 d);

int is68020(void);

/* #define the values to exclude the C versions */
#define lbnSub1_16 lbnSub1_16
#define lbnAdd1_16 lbnAdd1_16
#define lbnMulN1_16 lbnMulN1_16
#define lbnMulAdd1_16 lbnMulAdd1_16
#define lbnMulSub1_16 lbnMulSub1_16
#define lbnDiv21_16 lbnDiv21_16
#define lbnModQ_16 lbnModQ_16

/* Also include the 68020 definitions for 16/32 bit switching versions. */
#include <lbn68020.h>
