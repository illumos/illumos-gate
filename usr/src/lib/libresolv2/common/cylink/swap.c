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
*  FILENAME: swap.c   PRODUCT NAME: CRYPTOGRAPHIC TOOLKIT
*
*  FILE STATUS:
*
*  DESCRIPTION: Byte and Word Swap functions 
*
*  PUBLIC FUNCTIONS:
*
*
*  PRIVATE FUNCTIONS:
*
*  REVISION  HISTORY:
*
*  14 Oct 94   GKL     Initial release
*  26 Oct 94   GKL     (alignment for big endian support )
*
****************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/****************************************************************************
*  INCLUDE FILES
****************************************************************************/
/* system files */

#include "port_before.h"
#ifdef VXD
#include <vtoolsc.h>
#else
#include <stdlib.h>
#include <string.h>
#endif
/* program files */
#include "cylink.h"
#include "ctk_endian.h"
#include "toolkit.h"
#include "port_after.h"

u_int16_t DataOrder = 0;

/*Reset bytes in long*/
/*extern void ByteSwap32_asm( uchar  *X, u_int16_t X_len );*/ /*kz*/

/****************************************************************************
*  NAME:     void ByteSwap32 (uchar  *array,
*                             u_int16_t X_len )
*
*  DESCRIPTION:  Perform byte reversal on an array of longword.
*
*  INPUTS:
*          PARAMETERS:
*            uchar  *X            Pointer to array
*                        u_int16_t X_len             Number of bytes
*  OUTPUT:
*            uchar  *X            Pointer to array
*
*  REVISION HISTORY:
*
*  24 Sep 94    KPZ             Initial release
*  14 Oct 94    GKL     Second version (big endian support)
*
****************************************************************************/


void ByteSwap32( uchar  *X, u_int16_t X_len )
{
  u_int16_t i;        /*counter*/
  uchar a;      /*temporary char*/
        for ( i = 0; i < X_len; i += 4)
 {
               a = X[i];
               X[i] = X[i+3];
	       X[i+3] = a;
	       a = X[i+1];
	       X[i+1] = X[i+2];
	       X[i+2] = a;
     }
/*#endif*/ /*kz*/
}


/****************************************************************************
*  NAME:     void ByteSwap (uchar  *array,
*                           u_int16_t X_len )
*
*  DESCRIPTION:  Perform byte reversal on an array of longword or shortword.
*
*  INPUTS:
*          PARAMETERS:
*            uchar  *X            Pointer to array
*            u_int16_t X_len             Number of bytes
*  OUTPUT:
*            uchar  *X            Pointer to array
*
*  REVISION HISTORY:
*
*  24 Sep 94    KPZ             Initial release
*  14 Oct 94    GKL     Second version (big endian support)
*
****************************************************************************/

void ByteSwap( uchar  *X,
               u_int16_t X_len )
{
#ifdef ORD_16
    u_int16_t i;        /*counter*/
    uchar a;      /*tempriory char for revers*/
	for ( i = 0; i < X_len; i += 2)
    {
		a = X[i];
        X[i] = X[i+1];
        X[i+1] = a;
    }
#endif
#ifdef ORD_32
      ByteSwap32(X,X_len);
#endif
}

/*kz longbyte deleted */

/****************************************************************************
*  NAME:     void WordSwap (uchar  *array,
*                           u_int16_t X_len )
*
*  DESCRIPTION:  Perform short reversal on an array of longword.
*
*  INPUTS:
*          PARAMETERS:
*            uchar  *X            Pointer to array
*                        u_int16_t X_len             Number of bytes
*  OUTPUT:
*            uchar  *X            Pointer to array
*
*  REVISION HISTORY:
*
*  14 Oct 94    GKL     Initial release
*
****************************************************************************/
void WordSwap( uchar  *X,
               u_int16_t X_len )
{
	u_int16_t i;        /*counter*/
    u_int16_t a;      /*tempriory u_int16_t*/

    for ( i = 0; i < X_len; i += 4)
    {
        a = *(u_int16_t*)(&X[i]);
        *(u_int16_t*)(&X[i])=*(u_int16_t*)(&X[i+2]);
        *(u_int16_t*)(&X[i+2])=a;
    }
}

void BigSwap( uchar *buffer,
              u_int16_t bufferLength)
{
    uchar temp;
    u_int16_t i;

    for (i = 0; i < (u_int16_t)(bufferLength/2); i++)
    {
        temp = buffer[i];
        buffer[i] = buffer[bufferLength - 1 - i]; 
        buffer[bufferLength - 1 - i] = temp; 
    }
}

void SetDataOrder ( u_int16_t dataOrder)
{
    DataOrder = dataOrder;
}
