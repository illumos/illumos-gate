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
 * bn16.h - interface to 16-bit bignum routines.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

struct BigNum;

void bnInit_16(void);
void bnEnd_16(struct BigNum *bn);
int bnPrealloc_16(struct BigNum *bn, unsigned bits);
int bnCopy_16(struct BigNum *dest, struct BigNum const *src);
int bnSwap_16(struct BigNum *a, struct BigNum *b);
void bnNorm_16(struct BigNum *bn);
void bnExtractBigBytes_16(struct BigNum const *bn, unsigned char *dest,
	unsigned lsbyte, unsigned dlen);
int bnInsertBigBytes_16(struct BigNum *bn, unsigned char const *src,
	unsigned lsbyte, unsigned len);
void bnExtractLittleBytes_16(struct BigNum const *bn, unsigned char *dest,
	unsigned lsbyte, unsigned dlen);
int bnInsertLittleBytes_16(struct BigNum *bn, unsigned char const *src,
	unsigned lsbyte, unsigned len);
unsigned bnLSWord_16(struct BigNum const *src);
unsigned bnBits_16(struct BigNum const *src);
int bnAdd_16(struct BigNum *dest, struct BigNum const *src);
int bnSub_16(struct BigNum *dest, struct BigNum const *src);
int bnCmpQ_16(struct BigNum const *a, unsigned b);
int bnSetQ_16(struct BigNum *dest, unsigned src);
int bnAddQ_16(struct BigNum *dest, unsigned src);
int bnSubQ_16(struct BigNum *dest, unsigned src);
int bnCmp_16(struct BigNum const *a, struct BigNum const *b);
int bnSquare_16(struct BigNum *dest, struct BigNum const *src);
int bnMul_16(struct BigNum *dest, struct BigNum const *a,
	struct BigNum const *b);
int bnMulQ_16(struct BigNum *dest, struct BigNum const *a, unsigned b);
int bnDivMod_16(struct BigNum *q, struct BigNum *r, struct BigNum const *n,
	struct BigNum const *d);
int bnMod_16(struct BigNum *dest, struct BigNum const *src,
	struct BigNum const *d);
unsigned bnModQ_16(struct BigNum const *src, unsigned d);
int bnExpMod_16(struct BigNum *dest, struct BigNum const *n,
	struct BigNum const *exp, struct BigNum const *mod);
int bnDoubleExpMod_16(struct BigNum *dest,
	struct BigNum const *n1, struct BigNum const *e1,
	struct BigNum const *n2, struct BigNum const *e2,
	struct BigNum const *mod);
int bnTwoExpMod_16(struct BigNum *n, struct BigNum const *exp,
	struct BigNum const *mod);
int bnGcd_16(struct BigNum *dest, struct BigNum const *a,
	struct BigNum const *b);
int bnInv_16(struct BigNum *dest, struct BigNum const *src,
	struct BigNum const *mod);
int bnLShift_16(struct BigNum *dest, unsigned amt);
void bnRShift_16(struct BigNum *dest, unsigned amt);
unsigned bnMakeOdd_16(struct BigNum *n);
