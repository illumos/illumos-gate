/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef LBN16_H
#define LBN16_H

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

#ifndef BNWORD16
#error 16-bit bignum library requires a 16-bit data type
#endif

#ifndef lbnCopy_16
void lbnCopy_16(BNWORD16 *dest, BNWORD16 const *src, unsigned len);
#endif
#ifndef lbnZero_16
void lbnZero_16(BNWORD16 *num, unsigned len);
#endif
#ifndef lbnNeg_16
void lbnNeg_16(BNWORD16 *num, unsigned len);
#endif

#ifndef lbnAdd1_16
BNWORD16 lbnAdd1_16(BNWORD16 *num, unsigned len, BNWORD16 carry);
#endif
#ifndef lbnSub1_16
BNWORD16 lbnSub1_16(BNWORD16 *num, unsigned len, BNWORD16 borrow);
#endif

#ifndef lbnAddN_16
BNWORD16 lbnAddN_16(BNWORD16 *num1, BNWORD16 const *num2, unsigned len);
#endif
#ifndef lbnSubN_16
BNWORD16 lbnSubN_16(BNWORD16 *num1, BNWORD16 const *num2, unsigned len);
#endif

#ifndef lbnCmp_16
int lbnCmp_16(BNWORD16 const *num1, BNWORD16 const *num2, unsigned len);
#endif

#ifndef lbnMulN1_16
void lbnMulN1_16(BNWORD16 *out, BNWORD16 const *in, unsigned len, BNWORD16 k);
#endif
#ifndef lbnMulAdd1_16
BNWORD16
lbnMulAdd1_16(BNWORD16 *out, BNWORD16 const *in, unsigned len, BNWORD16 k);
#endif
#ifndef lbnMulSub1_16
BNWORD16 lbnMulSub1_16(BNWORD16 *out, BNWORD16 const *in, unsigned len, BNWORD16 k);
#endif

#ifndef lbnLshift_16
BNWORD16 lbnLshift_16(BNWORD16 *num, unsigned len, unsigned shift);
#endif
#ifndef lbnDouble_16
BNWORD16 lbnDouble_16(BNWORD16 *num, unsigned len);
#endif
#ifndef lbnRshift_16
BNWORD16 lbnRshift_16(BNWORD16 *num, unsigned len, unsigned shift);
#endif

#ifndef lbnMul_16
void lbnMul_16(BNWORD16 *prod, BNWORD16 const *num1, unsigned len1,
	BNWORD16 const *num2, unsigned len2);
#endif
#ifndef lbnSquare_16
void lbnSquare_16(BNWORD16 *prod, BNWORD16 const *num, unsigned len);
#endif

#ifndef lbnNorm_16
unsigned lbnNorm_16(BNWORD16 const *num, unsigned len);
#endif
#ifndef lbnBits_16
unsigned lbnBits_16(BNWORD16 const *num, unsigned len);
#endif

#ifndef lbnExtractBigBytes_16
void lbnExtractBigBytes_16(BNWORD16 const *bn, unsigned char *buf,
	unsigned lsbyte, unsigned buflen);
#endif
#ifndef lbnInsertBigytes_16
void lbnInsertBigBytes_16(BNWORD16 *n, unsigned char const *buf,
	unsigned lsbyte,  unsigned buflen);
#endif
#ifndef lbnExtractLittleBytes_16
void lbnExtractLittleBytes_16(BNWORD16 const *bn, unsigned char *buf,
	unsigned lsbyte, unsigned buflen);
#endif
#ifndef lbnInsertLittleBytes_16
void lbnInsertLittleBytes_16(BNWORD16 *n, unsigned char const *buf,
	unsigned lsbyte,  unsigned buflen);
#endif

#ifndef lbnDiv21_16
BNWORD16 lbnDiv21_16(BNWORD16 *q, BNWORD16 nh, BNWORD16 nl, BNWORD16 d);
#endif
#ifndef lbnDiv1_16
BNWORD16 lbnDiv1_16(BNWORD16 *q, BNWORD16 *rem,
	BNWORD16 const *n, unsigned len, BNWORD16 d);
#endif
#ifndef lbnModQ_16
unsigned lbnModQ_16(BNWORD16 const *n, unsigned len, unsigned d);
#endif
#ifndef lbnDiv_16
BNWORD16
lbnDiv_16(BNWORD16 *q, BNWORD16 *n, unsigned nlen, BNWORD16 *d, unsigned dlen);
#endif

#ifndef lbnMontInv1_16
BNWORD16 lbnMontInv1_16(BNWORD16 const x);
#endif
#ifndef lbnMontReduce_16
void lbnMontReduce_16(BNWORD16 *n, BNWORD16 const *mod, unsigned const mlen,
                BNWORD16 inv);
#endif
#ifndef lbnToMont_16
void lbnToMont_16(BNWORD16 *n, unsigned nlen, BNWORD16 *mod, unsigned mlen);
#endif
#ifndef lbnFromMont_16
void lbnFromMont_16(BNWORD16 *n, BNWORD16 *mod, unsigned len);
#endif

#ifndef lbnExpMod_16
int lbnExpMod_16(BNWORD16 *result, BNWORD16 const *n, unsigned nlen,
	BNWORD16 const *exp, unsigned elen, BNWORD16 *mod, unsigned mlen);
#endif
#ifndef lbnDoubleExpMod_16
int lbnDoubleExpMod_16(BNWORD16 *result,
	BNWORD16 const *n1, unsigned n1len, BNWORD16 const *e1, unsigned e1len,
	BNWORD16 const *n2, unsigned n2len, BNWORD16 const *e2, unsigned e2len,
	BNWORD16 *mod, unsigned mlen);
#endif
#ifndef lbnTwoExpMod_16
int lbnTwoExpMod_16(BNWORD16 *n, BNWORD16 const *exp, unsigned elen,
	BNWORD16 *mod, unsigned mlen);
#endif
#ifndef lbnGcd_16
int lbnGcd_16(BNWORD16 *a, unsigned alen, BNWORD16 *b, unsigned blen);
#endif
#ifndef lbnInv_16
int lbnInv_16(BNWORD16 *a, unsigned alen, BNWORD16 const *mod, unsigned mlen);
#endif

#endif /* LBN16_H */
