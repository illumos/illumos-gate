/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef LBNPPC_H
#define LBNPPC_H
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
 * Assembly-language routines for the Power PC processor.
 * Annoyingly, the Power PC does not have 64/32->32 bit divide,
 * so the C code should be reasonably fast.  But it does have
 * 32x32->64-bit multiplies, and these routines provide access
 * to that.
 *
 * In versions of CodeWarrior before 8.0, there was no PPC assembler,
 * so a kludged-up one in CPP is used.  This requires casting an
 * array of unsigneds to function pointer type, and a function pointer
 * is not a pointer to the code, but rather a pointer to a (code,TOC)
 * pointer pair which we fake up.
 *
 * CodeWarrior 8.0 supports PCC assembly, which is used directly.
 */

/*
 * Bignums are stored in arrays of 32-bit words, and the least
 * significant 32-bit word has the lowest address, thus "little-endian".
 * The C code is slightly more efficient this way, so unless the
 * processor cares (the PowerPC, like most RISCs, doesn't), it is
 * best to use BN_LITTLE_ENDIAN.
 * Note that this has NOTHING to do with the order of bytes within a 32-bit
 * word; the math library is insensitive to that.
 */
#define BN_LITTLE_ENDIAN 1

typedef unsigned bnword32;
#define BNWORD32 bnword32

#if __MWERKS__ < 0x800

/* Shared transition vector array */
extern unsigned const * const lbnPPC_tv[];

/* A function pointer on the PowerPC is a pointer to a transition vector */
#define lbnMulN1_32 \
((void (*)(bnword32 *, bnword32 const *, unsigned, bnword32))(lbnPPC_tv+0))
#define lbnMulAdd1_32 \
((bnword32 (*)(bnword32 *, bnword32 const *, unsigned, bnword32))(lbnPPC_tv+1))
#define lbnMulSub1_32 \
((bnword32 (*)(bnword32 *, bnword32 const *, unsigned, bnword32))(lbnPPC_tv+2))

#else /* __MWERKS__ >= 0x800 */

void lbnMulN1_32(bnword32 *, bnword32 const *, unsigned, bnword32);
#define lbnMulN1_32 lbnMulN1_32
bnword32 lbnMulAdd1_32(bnword32 *, bnword32 const *, unsigned, bnword32);
#define lbnMulAdd1_32 lbnMulAdd1_32
bnword32 lbnMulSub1_32(bnword32 *, bnword32 const *, unsigned, bnword32);
#define lbnMulSub1_32 lbnMulSub1_32

#endif /* __MWERKS__ >= 0x800 */

#endif /* LBNPPC_H */
