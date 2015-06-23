/*******************************************************************************
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2014 QLogic Corporation
 * The contents of this file are subject to the terms of the
 * QLogic End User License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://www.qlogic.com/Resources/Documents/DriverDownloadHelp/
 * QLogic_End_User_Software_License.txt
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 ****************************************************************************/
#ifndef __bcmtype_h__
#define __bcmtype_h__

#if defined(UEFI) && defined (EVEREST_DIAG)
#include <machine/endian.h>
#endif

#ifndef IN
#define IN
#endif /* IN */

#ifndef OUT
#define OUT
#endif /* OUT */

#ifndef INOUT
#define INOUT
#endif /* INOUT */

#ifndef OPTIONAL
#define OPTIONAL
#endif /* OPTIONAL */

#if defined(__LINUX) || defined (USER_LINUX)

#ifdef __LINUX

#ifdef __BIG_ENDIAN
#ifndef BIG_ENDIAN
#define BIG_ENDIAN
#endif
#else /* __LITTLE_ENDIAN */
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN
#endif
#endif

/*
 * define underscore-t types
 */
typedef u64 u64_t;
typedef u32 u32_t;
typedef u16 u16_t;
typedef u8  u8_t;

typedef s64 s64_t;
typedef s32 s32_t;
typedef s16 s16_t;
typedef s8  s8_t;

typedef unsigned long int_ptr_t;

#else /* USER_LINUX */

#if __BYTE_ORDER == __LITTLE_ENDIAN
#undef BIG_ENDIAN
#undef __BIG_ENDIAN
#else
#undef LITTLE_ENDIAN
#undef __LITTLE_ENDIAN
#endif

/*
 * define underscore-t types
 */
typedef u_int64_t u64_t;
typedef u_int32_t u32_t;
typedef u_int16_t u16_t;
typedef u_int8_t  u8_t;

typedef int64_t s64_t;
typedef int32_t s32_t;
typedef int16_t s16_t;
typedef int8_t  s8_t;

typedef u_int64_t u64;
typedef u_int32_t u32;
typedef u_int16_t u16;
typedef u_int8_t  u8;

typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t  s8;

typedef unsigned long int_ptr_t;

/* Define upper case types */

typedef u64_t 	U64;
typedef u32_t 	U32;
typedef u16_t 	U16;
typedef u8_t  	U8;

typedef s64_t	S64;
typedef s32_t	S32;
typedef s16_t	S16;
typedef s8_t	S8;

#endif



#else
/*
 * define the data model
 */
#if !defined(LP64) && !defined(P64) && !defined(LLP64)
  /* VC 32-bit compiler 5.0 or later */
  #if (defined(_MSC_VER) && (_MSC_VER > 800)) || defined(TARGET_WINDOWS)
    #define P64
  #elif defined(__sun)
    /* Solaris */
    #define LP64
  #elif defined(_HPUX_SOURCE)
    /* HP/UX */
    #define LP64
  #elif defined(__FreeBSD__)
    /* FreeBSD */
    #define LP64
  #elif defined(LINUX)
    /* Linux */
    #define LP64
  #elif defined(__bsdi__)
    /* BSDI */
    #define LP64
  #elif defined(_IRIX)
    /* IRIX */
    #define LP64
  #elif defined(UNIXWARE)
    /* UnixWare */
    #define LP64
  #endif /* UNIXWARE */
#endif /* !LP64 && !P64 && !LLP64 */

/*
 * define sized type
 */
#if defined(P64) || defined(LLP64)
  /* P64 */
  typedef unsigned __int64    U64;
  typedef unsigned int        U32;
  typedef unsigned short      U16;
  typedef unsigned char       U8;
  typedef signed __int64      S64;
  typedef signed int          S32;
  typedef signed short        S16;
  typedef signed char         S8;

  #if defined(IA64)  || defined(AMD64)
        typedef U64  int_ptr_t;
  #else   
    #ifndef UEFI64    
        typedef unsigned long       int_ptr_t; 
    #endif
  #endif
#elif defined(LP64)
  /* LP64: Sun, HP and etc */
  typedef unsigned long long  U64;
  typedef unsigned int        U32;
  typedef unsigned short      U16;
  typedef unsigned char       U8;
  typedef signed long long    S64;
  typedef signed int          S32;
  typedef signed short        S16;
  typedef signed char         S8;
  typedef unsigned long       int_ptr_t; 
#elif defined(__WATCOMC__) 
  typedef unsigned __int64    U64;
  typedef unsigned long       U32;
  typedef unsigned short      U16;
  typedef unsigned char       U8;
  typedef signed __int64      S64;
  typedef signed long         S32;
  typedef signed short        S16;
  typedef signed char         S8;
  typedef unsigned long       int_ptr_t;  
#else
  /* assume others: 16-bit */
  typedef unsigned char       U64[8];
  typedef unsigned long       U32;
  typedef unsigned short      U16;
  typedef unsigned char       U8;
  typedef signed char         S64[8];
  typedef signed long         S32;
  typedef signed short        S16;
  typedef signed char         S8;     
  typedef unsigned long       int_ptr_t;  
#endif /*  */

 

/*
 * define lower case types
 */
typedef U64 u64_t;
typedef U32 u32_t;
typedef U16 u16_t;
typedef U8  u8_t;

typedef S64 s64_t;
typedef S32 s32_t;
typedef S16 s16_t;
typedef S8  s8_t;

#ifndef LINUX
typedef U64 u64;
typedef U32 u32;
typedef U16 u16;
typedef U8  u8;

typedef S64 s64;
typedef S32 s32;
typedef S16 s16;
typedef S8  s8;
#endif

#endif

#ifdef UEFI
#if BYTE_ORDER == LITTLE_ENDIAN
#undef BIG_ENDIAN
#endif
#ifdef UEFI64
typedef u64_t  int_ptr_t;
#endif
#endif

#ifdef LITTLE_ENDIAN
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#endif /* __LITTLE_ENDIAN */
#endif /* LITTLE_ENDIAN */

#ifdef BIG_ENDIAN
#ifndef __BIG_ENDIAN
#define  __BIG_ENDIAN  BIG_ENDIAN
#endif /* __BIG_ENDIAN */
#endif /* BIG_ENDIAN */

#ifdef __FreeBSD__
#if _BYTE_ORDER == _LITTLE_ENDIAN
#undef BIG_ENDIAN
#undef __BIG_ENDIAN
#else
#undef LITTLE_ENDIAN
#undef __LITTLE_ENDIAN
#endif
#endif /* __FreeBSD__ */

/* Signed subtraction macros with no sign extending.  */
#define S64_SUB(_a, _b)     ((s64_t) ((s64_t) (_a) - (s64_t) (_b)))
#define u64_SUB(_a, _b)     ((u64_t) ((s64_t) (_a) - (s64_t) (_b)))
#define S32_SUB(_a, _b)     ((s32_t) ((s32_t) (_a) - (s32_t) (_b)))
#define uS32_SUB(_a, _b)    ((u32_t) ((s32_t) (_a) - (s32_t) (_b)))
#define S16_SUB(_a, _b)     ((s16_t) ((s16_t) (_a) - (s16_t) (_b)))
#define u16_SUB(_a, _b)     ((u16_t) ((s16_t) (_a) - (s16_t) (_b)))
#define PTR_SUB(_a, _b)     ((u8_t *) (_a) - (u8_t *) (_b))

#if (!defined LINUX ) && (!defined MFW)
#define __builtin_offsetof(path1_nvm_image_t, f) (u32_t)((int_ptr_t)(&(((path1_nvm_image_t *)0)->f)))
#endif

#endif/* __bcmtype_h__ */

