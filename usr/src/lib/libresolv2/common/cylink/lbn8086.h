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
 * lbn8086.h - This file defines the interfaces to the 8086
 * assembly primitives for 16-bit MS-DOS environments.
 * It is intended to be included in "lbn.h"
 * via the "#include BNINCLUDE" mechanism.
 */
 
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define BN_LITTLE_ENDIAN 1

#ifdef __cplusplus
/* These assembly-language primitives use C names */
extern "C" {
#endif

/* Set up the appropriate types */
typedef unsigned short bnword16;
#define BNWORD16 bnword16
typedef unsigned long bnword32;
#define BNWORD32 bnword32

void __cdecl __far
lbnMulN1_16(bnword16 __far *out, bnword16 const __far *in,
            unsigned len, bnword16 k);
#define lbnMulN1_16 lbnMulN1_16
            
bnword16 __cdecl __far
lbnMulAdd1_16(bnword16 __far *out, bnword16 const __far *in,
              unsigned len, bnword16 k);
#define lbnMulAdd1_16 lbnMulAdd1_16
       
bnword16 __cdecl __far
lbnMulSub1_16(bnword16 __far *out, bnword16 const __far *in,
              unsigned len, bnword16 k);
#define lbnMulSub1_16 lbnMulSub1_16

bnword16 __cdecl __far
lbnDiv21_16(bnword16 __far *q, bnword16 nh, bnword16 nl, bnword16 d);
#define lbnDiv21_16 lbnDiv21_16

bnword16 __cdecl __far
lbnModQ_16(bnword16 const __far *n, unsigned len, bnword16 d);
#define lbnModQ_16 lbnModQ_16



void __cdecl __far
lbnMulN1_32(bnword32 __far *out, bnword32 const __far *in,
            unsigned len, bnword32 k);
#define lbnMulN1_32 lbnMulN1_32
            
bnword32 __cdecl __far
lbnMulAdd1_32(bnword32 __far *out, bnword32 const __far *in,
              unsigned len, bnword32 k);
#define lbnMulAdd1_32 lbnMulAdd1_32
       
bnword32 __cdecl __far
lbnMulSub1_32(bnword32 __far *out, bnword32 const __far *in,
              unsigned len, bnword32 k);
#define lbnMulSub1_32 lbnMulSub1_32

bnword32 __cdecl __far
lbnDiv21_32(bnword32 __far *q, bnword32 nh, bnword32 nl, bnword32 d);
#define lbnDiv21_32 lbnDiv21_32

bnword16 __cdecl __far
lbnModQ_32(bnword32 const __far *n, unsigned len, bnword32 d);
#define lbnModQ_32 lbnModQ_32

int __cdecl __far not386(void);

#ifdef __cplusplus
}
#endif
