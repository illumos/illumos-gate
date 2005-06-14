/*
 * Copyright (c) 2001 by Sun Microsystems, Inc.
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
*  FILENAME:  ctk_endian.h     PRODUCT NAME:
*
*  DESCRIPTION:  header file of defines
*
*  USAGE:      Platform-dependend compilation modes header
*
*
*          Copyright (c) Cylink Corporation 1994. All rights reserved.
*
*  REVISION  HISTORY:
*
\**********************************************************************/

#ifndef CTK_ENDIAN_H  /* Prevent multiple inclusions of same header file */
#define CTK_ENDIAN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <ctype.h>
#include <arpa/nameser_compat.h>
#include "lbn.h"

#if (defined(BIG_ENDIAN) || defined(_BIG_ENDIAN)) && !(defined(LITTLE_ENDIAN) || defined(_LITTLE_ENDIAN))
#  undef BIG_ENDIAN
#  undef _BIG_ENDIAN
#  define BIG_ENDIAN 4321
#  define LITTLE_ENDIAN 1234
#  define BYTE_ORDER BIG_ENDIAN

#elif !(defined(BIG_ENDIAN) || defined(_BIG_ENDIAN)) && (defined(LITTLE_ENDIAN) || defined(_LITTLE_ENDIAN))
#  undef LITTLE_ENDIAN
#  undef _LITTLE_ENDIAN
#  define BIG_ENDIAN 4321
#  define LITTLE_ENDIAN 1234
#  define BYTE_ORDER LITTLE_ENDIAN
#endif

#if !defined(BYTE_ORDER) || \
    (BYTE_ORDER != BIG_ENDIAN && BYTE_ORDER != LITTLE_ENDIAN)
        /* you must determine what the correct bit order is for
         * your compiler - the next line is an intentional error
         * which will force your compiles to bomb until you fix
         * the above macros.
         */
# if !defined(CTK_LITTLE_ENDIAN) && !defined(CTK_BIG_ENDIAN)
#  error "Undefined or invalid BYTE_ORDER";
# endif
#endif

#if !defined(CTK_BIG_ENDIAN) && !defined(CTK_LITTLE_ENDIAN)
#  ifdef BYTE_ORDER
#    if (BYTE_ORDER == LITTLE_ENDIAN) 
#      define CTK_LITTLE_ENDIAN
#    elif (BYTE_ORDER == BIG_ENDIAN)
#      define CTK_BIG_ENDIAN
#    else 
#      error CAN NOT determine ENDIAN with BYTE_ORDER
#    endif
#  elif defined(_LITTLE_ENDIAN) 
#    define CTK_LITTLE_ENDIAN
#  elif defined(_BIG_ENDIAN)
#    define CTK_BIG_ENDIAN
#  else 
#      error CAN NOT determine ENDIAN 
#  endif
#endif 

#if !defined(CTK_BIG_ENDIAN) && !defined(CTK_LITTLE_ENDIAN)
#  error NO CTK_???_ENDIAN defined
#endif

#if defined( CTK_LITTLE_ENDIAN ) && defined( CTK_BIG_ENDIAN )
#  error Use only one define CPU type CTK_LITTLE or BIG ENDIAN.
#endif

#if  !defined( ORD_32 ) && !defined( ORD_16 )
#  ifdef BNSIZE64
#     error BNSIZE64 do not know how to do this
#  elif defined(BNSIZE32)
#     define ORD_32
#  elif defined(BNSIZE16)
#     define ORD_16
#  elif  !defined( UINT_MAX) /* No <limits.h> */
#    define ORD_16 /* default */
#  else 
#    if ULONG_MAX == 0xffffffff
#      define ORD_16
#    else
#      define ORD_32
#    endif
#  endif
#endif

#if  !defined( ORD_32 ) && !defined( ORD_16 )
#error Not defined basic word type ORD_32 or ORD_16.
#endif

#if  defined( ORD_32 ) && defined( ORD_16 )
#error Use only one define basic word type ORD_32 or ORD_16.
#endif


#ifdef ORD_16
/* typedef unsigned short ord; deleted by ogud@tis.com 1998/9/14 */
typedef u_int16_t ord;
#define BITS_COUNT 16
#define MAXDIGIT (ord)(0xFFFF)
#endif

#ifdef ORD_32
/* typedef unsigned long ord; deleted by ogud@tis.com 1998/9/14 */
typedef u_int32_t ord;
#define BITS_COUNT 32
#define MAXDIGIT (ord)(0xFFFFFFFF)
#endif /* ORD_32 */



#define CALLOC(var,type,len)                    \
                          var=(type *)calloc(len,1);     \
                                if (var==NULL)                 \
                                         status=ERR_ALLOC
#ifdef CTK_BIG_ENDIAN
#define ALIGN_CALLOC(i,o,l)                     \
                             CALLOC(o,ord,l)
#define ALIGN_CALLOC_COPY(i,o,l)                \
                                CALLOC(o,ord,l);               \
                                if (o) ByteOrd(i,l,o)
#define ALIGN_CALLOC_MOVE(i,o,l)                \
                          CALLOC(o,ord,l);               \
                                if (o) memcpy(o,i,l)
#define ALIGN_FREE(o)                           \
                           free ( o )
#define ALIGN_COPY_FREE(o,i,l)                  \
                             if ((o) && (status==SUCCESS))  \
                                       OrdByte(o,l,i);             \
                            free (o)
#define ALIGN_MOVE_FREE(o,i,l)                  \
                               if ((o) && (status==SUCCESS))  \
                                       memcpy(i,o,l);              \
                                   memset(o,0,l);  \
                                       free (o)
#else
#define ALIGN_CALLOC(i,o,l) o=(ord *)i
#define ALIGN_CALLOC_COPY(i,o,l) o=(ord *)i
#define ALIGN_CALLOC_MOVE(i,o,l) o=(ord *)i
#define ALIGN_FREE(o)  ;
#define ALIGN_COPY_FREE(o,i,l) ;
#define ALIGN_MOVE_FREE(o,i,l) ;
#endif
#define DSS_P_ALIGN_CALLOC_COPY(i,o,l)          \
              if (i)                            \
             { ALIGN_CALLOC_COPY(i,o,l);}      \
              else                              \
                o = &DSS_P_NUMBERS[DSS_NUM_INDEX[(l-DSS_LENGTH_MIN)/LENGTH_STEP]]

#define DSS_G_ALIGN_CALLOC_COPY(i,o,l)          \
              if (i)                            \
              { ALIGN_CALLOC_COPY(i,o,l);}      \
        else                              \
                o = &DSS_G_NUMBERS[DSS_NUM_INDEX[(l-DSS_LENGTH_MIN)/LENGTH_STEP]]

#define DSS_Q_ALIGN_CALLOC_COPY(i,o,l)          \
              if (i)                            \
              { ALIGN_CALLOC_COPY(i,o,l);}      \
              else                              \
                o = DSS_Q_NUMBER

#define DSS_ALIGN_FREE(o,i)           \
              if (i)                  \
              { ALIGN_FREE(o);}
#endif     /* CTK_ENDIAN_H */
