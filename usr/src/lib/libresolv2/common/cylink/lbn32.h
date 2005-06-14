/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef LBN32_H
#define LBN32_H

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

#include "lbn.h"

#ifndef BNWORD32
#error 32-bit bignum library requires a 32-bit data type
#endif

#ifndef lbnCopy_32
void lbnCopy_32(BNWORD32 *dest, BNWORD32 const *src, unsigned len);
#endif
#ifndef lbnZero_32
void lbnZero_32(BNWORD32 *num, unsigned len);
#endif
#ifndef lbnNeg_32
void lbnNeg_32(BNWORD32 *num, unsigned len);
#endif

#ifndef lbnAdd1_32
BNWORD32 lbnAdd1_32(BNWORD32 *num, unsigned len, BNWORD32 carry);
#endif
#ifndef lbnSub1_32
BNWORD32 lbnSub1_32(BNWORD32 *num, unsigned len, BNWORD32 borrow);
#endif

#ifndef lbnAddN_32
BNWORD32 lbnAddN_32(BNWORD32 *num1, BNWORD32 const *num2, unsigned len);
#endif
#ifndef lbnSubN_32
BNWORD32 lbnSubN_32(BNWORD32 *num1, BNWORD32 const *num2, unsigned len);
#endif

#ifndef lbnCmp_32
int lbnCmp_32(BNWORD32 const *num1, BNWORD32 const *num2, unsigned len);
#endif

#ifndef lbnMulN1_32
void lbnMulN1_32(BNWORD32 *out, BNWORD32 const *in, unsigned len, BNWORD32 k);
#endif
#ifndef lbnMulAdd1_32
BNWORD32
lbnMulAdd1_32(BNWORD32 *out, BNWORD32 const *in, unsigned len, BNWORD32 k);
#endif
#ifndef lbnMulSub1_32
BNWORD32 lbnMulSub1_32(BNWORD32 *out, BNWORD32 const *in, unsigned len, BNWORD32 k);
#endif

#ifndef lbnLshift_32
BNWORD32 lbnLshift_32(BNWORD32 *num, unsigned len, unsigned shift);
#endif
#ifndef lbnDouble_32
BNWORD32 lbnDouble_32(BNWORD32 *num, unsigned len);
#endif
#ifndef lbnRshift_32
BNWORD32 lbnRshift_32(BNWORD32 *num, unsigned len, unsigned shift);
#endif

#ifndef lbnMul_32
void lbnMul_32(BNWORD32 *prod, BNWORD32 const *num1, unsigned len1,
	BNWORD32 const *num2, unsigned len2);
#endif
#ifndef lbnSquare_32
void lbnSquare_32(BNWORD32 *prod, BNWORD32 const *num, unsigned len);
#endif

#ifndef lbnNorm_32
unsigned lbnNorm_32(BNWORD32 const *num, unsigned len);
#endif
#ifndef lbnBits_32
unsigned lbnBits_32(BNWORD32 const *num, unsigned len);
#endif

#ifndef lbnExtractBigBytes_32
void lbnExtractBigBytes_32(BNWORD32 const *bn, unsigned char *buf,
	unsigned lsbyte, unsigned buflen);
#endif
#ifndef lbnInsertBigytes_32
void lbnInsertBigBytes_32(BNWORD32 *n, unsigned char const *buf,
	unsigned lsbyte,  unsigned buflen);
#endif
#ifndef lbnExtractLittleBytes_32
void lbnExtractLittleBytes_32(BNWORD32 const *bn, unsigned char *buf,
	unsigned lsbyte, unsigned buflen);
#endif
#ifndef lbnInsertLittleBytes_32
void lbnInsertLittleBytes_32(BNWORD32 *n, unsigned char const *buf,
	unsigned lsbyte,  unsigned buflen);
#endif

#ifndef lbnDiv21_32
BNWORD32 lbnDiv21_32(BNWORD32 *q, BNWORD32 nh, BNWORD32 nl, BNWORD32 d);
#endif
#ifndef lbnDiv1_32
BNWORD32 lbnDiv1_32(BNWORD32 *q, BNWORD32 *rem,
	BNWORD32 const *n, unsigned len, BNWORD32 d);
#endif
#ifndef lbnModQ_32
unsigned lbnModQ_32(BNWORD32 const *n, unsigned len, unsigned d);
#endif
#ifndef lbnDiv_32
BNWORD32
lbnDiv_32(BNWORD32 *q, BNWORD32 *n, unsigned nlen, BNWORD32 *d, unsigned dlen);
#endif

#ifndef lbnMontInv1_32
BNWORD32 lbnMontInv1_32(BNWORD32 const x);
#endif
#ifndef lbnMontReduce_32
void lbnMontReduce_32(BNWORD32 *n, BNWORD32 const *mod, unsigned const mlen,
                BNWORD32 inv);
#endif
#ifndef lbnToMont_32
void lbnToMont_32(BNWORD32 *n, unsigned nlen, BNWORD32 *mod, unsigned mlen);
#endif
#ifndef lbnFromMont_32
void lbnFromMont_32(BNWORD32 *n, BNWORD32 *mod, unsigned len);
#endif

#ifndef lbnExpMod_32
int lbnExpMod_32(BNWORD32 *result, BNWORD32 const *n, unsigned nlen,
	BNWORD32 const *exp, unsigned elen, BNWORD32 *mod, unsigned mlen);
#endif
#ifndef lbnDoubleExpMod_32
int lbnDoubleExpMod_32(BNWORD32 *result,
	BNWORD32 const *n1, unsigned n1len, BNWORD32 const *e1, unsigned e1len,
	BNWORD32 const *n2, unsigned n2len, BNWORD32 const *e2, unsigned e2len,
	BNWORD32 *mod, unsigned mlen);
#endif
#ifndef lbnTwoExpMod_32
int lbnTwoExpMod_32(BNWORD32 *n, BNWORD32 const *exp, unsigned elen,
	BNWORD32 *mod, unsigned mlen);
#endif
#ifndef lbnGcd_32
int lbnGcd_32(BNWORD32 *a, unsigned alen, BNWORD32 *b, unsigned blen);
#endif
#ifndef lbnInv_32
int lbnInv_32(BNWORD32 *a, unsigned alen, BNWORD32 const *mod, unsigned mlen);
#endif

#endif /* LBN32_H */
