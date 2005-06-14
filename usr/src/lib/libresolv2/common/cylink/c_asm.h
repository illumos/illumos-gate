/*
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
*  FILENAME:  c_asm.h        PRODUCT NAME: CRYPTOGRAPHIC TOOLKIT
*
*  FILE STATUS:
*
*  DESCRIPTION:     C / ASM Header File
*
*  USAGE:           File should be included to use Toolkit Functions
*
*
*   Copyright (c) Cylink Corporation 1994. All rights reserved.
*
*  REVISION  HISTORY:
*
*  14 Oct 94    GKL     For Second version (big endian support)
*  26 Oct 94    GKL     (alignment for big endian support )
*
****************************************************************************/
#if !defined( C_ASM_H )
#define C_ASM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include "cylink.h"
#include "ctk_endian.h"

#ifdef  __cplusplus
extern  "C" {
#endif


 int Sum_big (ord *X,
              ord *Y,
         ord *Z,
         int len_X );
 int Sum (ord *X, ord *Y, ushort len_X );
  int Sub_big (ord *X,
              ord *Y,
         ord *Z,
         int len_X );
/*
  void  Mul_big( ord *X, ord *Y,ord *XY,
            ushort lx, ushort ly,
           ushort  elements_in_X,
          ushort  elements_in_Y);*/
  void  Mul_big( ord *X, ord *Y,ord *XY,
               ushort lx, ushort ly);

  void  PReLo_big( ord *X, ord *P,
                    ushort len_X, ushort el);

  void  Div_big( ord *X, ord *P,
           ushort len_X, ushort el,
                ord *div);

int LeftMostBit_big ( ord X );
int LeftMostEl_big( ord *X, ushort len_X );
void  RShiftL_big( ord  *X, u_int32_t len_X, u_int32_t  n_bit );
void  LShiftL_big( ord *X, u_int32_t len_X, u_int32_t n_bit );
int RShiftMostBit(ord *a, u_int32_t len);
void ByteLong(uchar *X, u_int32_t X_bytes, u_int32_t *Y);
void ByteOrd(uchar *X, u_int32_t X_bytes, ord *Y);
void OrdByte(ord *X, u_int32_t X_bytes, uchar *Y);
void LongByte(u_int32_t *X, u_int32_t X_bytes, uchar  *Y);
int BitValue_big( ord  *X, ushort n_bits );
int BitsValue_big( ord  *X, ushort n_bits, ushort bit_count );
void ByteSwap32_big( uchar  *X, ushort X_len );
void Complement_big( ord *X, ushort X_longs);
void Diagonal_big (ord *X, ushort X_len, ord *X2);
void Square_big( ord *X, ushort X_len, ord *X2);
void  Mul_big_1( ord  X, ord *Y, ord *XY, ushort ly );
int Sum_Q(ord *X, ushort src, ushort len_X );



/* In-place DES encryption */
  void DES_encrypt(uchar *keybuf, uchar *block);

/* In-place DES decryption */
  void DES_decrypt(uchar *keybuf, uchar *block);

/* In-place KAPPA encryption */
  void KAPPA_encrypt(uchar *a, uchar *k, ushort r);

/* In-place KAPPA decryption */
  void KAPPA_decrypt(uchar *a, uchar *k, ushort r);

#ifdef  __cplusplus
}
#endif


#endif   /*C_ASM_H*/

