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
 *
 * Module Description:
 *  This file should include pure ANSI C defines
 *
 * History:
 *    04/03/07 Alon Elhanani        Inception.
 ******************************************************************************/

#ifndef __utils_h__
#define __utils_h__

#ifndef BITS_PER_BYTE
#define BITS_PER_BYTE                        (8)
#endif //BITS_PER_BYTE
/*
XXX_FLAGS
bitwise flags operations, for readability of the code
*/

// get specific flags
#define GET_FLAGS(flags,bits)                   ((flags) & (bits))
#define GET_FLAGS_WITH_OFFSET(flags,bits,offset)    (((flags) & (bits)) >> (offset))
// set specific flags
#define SET_FLAGS(flags,bits)                   ((flags) |= (bits))
// reset specific flags
#define RESET_FLAGS(flags,bits)                 ((flags) &= ~(bits))
// clear flags
#define CLEAR_FLAGS(flags)                      ((flags)=0)

// macros for a single bit
#define SET_BIT( _bits, _val )   SET_FLAGS  ( _bits,   (0x1ULL << _val) )
#define RESET_BIT( _bits, _val ) RESET_FLAGS( _bits,   (0x1ULL << _val) )
#define GET_BIT( _bits, _val )   GET_FLAGS  ( _bits,   (0x1ULL << _val) )

/**
 * \brief offset of byte next to specified struct member
 *
 * Find the size of the structure members, up-to and including
 * the specified meber (_m).
 *
 * \param _s            structure type
 * \param _m            struct member
 */

#define LAST_BYTE_OF(_s,_m)   (OFFSETOF(_s,_m)+sizeof( ((_s *)0)->_m))

/*
ARRSIZE:
used to calcualte item count of an array
this macro is used to prevent compile warning for unreferenced parametes
*/
#ifndef ARRSIZE
#define ARRSIZE(a)                   (sizeof(a)/sizeof((a)[0]))
#endif // ARRSIZE

/*
UNREFERENCED_PARAMETER
this macro is used to prevent compile warning for unreferenced parametes
*/
#ifndef UNREFERENCED_PARAMETER_
#define UNREFERENCED_PARAMETER_(P)\
    /*lint -save -e527 -e530 */  \
    { \
        (P) = (P); \
    }
#endif // UNREFERENCED_PARAMETER_


/*
ASSERT_STATIC
this macro is used to raise COMPILE time assertions
e.g: ASSERT_STATIC( sizeof(S08) == 1 )
relevant errors that compilers gives in such case:
build.exe (MS)     - "error  C2196: case value '0' already used"
WMAKE.exe (Watcom) - "Error! E1039: Duplicate case value '0' found"
*/
#ifndef ASSERT_STATIC
#define ASSERT_STATIC(cond) \
    {   \
        const unsigned char dummy_zero = 0 ; \
        switch(dummy_zero){case 0:case (cond):;} \
    }
#ifdef __SUNPRO_C /* Sun's cc can't deal with this clever hack */
#undef ASSERT_STATIC
#define ASSERT_STATIC(cond)
#endif
#endif // ASSERT_STATIC(cond)

/*
RANGE
this macro is used to check that a certain variable is within a given range
e.g: RANGE_INCLUDE(a, 10, 100)    - is the following true : 10<=a<=100
*/
#define IN_RANGE(_var, _min, _max)  ( ((_var) >= (_min)) && ((_var) <= (_max)) )

/*
IS_DIGIT 
this macro is used to check that a char is a digit 
example IS_DIGIT('4') - is '4' a digit will return TRUE. 
*/
#ifndef IS_DIGIT
#define IS_DIGIT(c) ( ((c) >= '0') && ((c) <= '9') )
#endif

/*
Define standard min and max macros
*/
#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

#if defined(__LINUX) || defined(USER_LINUX)
#undef max
#endif // LINUX

#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif // !max

#if defined(__LINUX) || defined(USER_LINUX)
#undef DIV_ROUND_UP_BITS
#endif // LINUX
// Round up a divied operation more optimal way base on bits.
// It is the same opration as d == (1<<bits).
// DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#ifndef BITS_ROUND_UP
#define DIV_ROUND_UP_BITS(n,bits) (((n) + (1 << (bits)) - 1) >> (bits))
#endif
/*
Define for pragma message output with file name and line number
usage: #pragma message (MSGSTR("blah blah blah"))
*/
#define _STR(x) #x
#define _STR2(x) _STR(x)
#define MSGSTR(msg) __FILE__ "(" _STR2(__LINE__)"): message - " ##msg


#ifndef POWER_OF_2
// known algorithm
#define POWER_OF_2(x)       ((0 != x) && (0 == (x &(x-1))))
#endif // !POWER_OF_2



#ifndef FAST_PATH_MODULO
// a = b (mod n)
// If a==b the compiler will omit the last line.
#define FAST_PATH_MODULO(a,b,n)     \
    do                              \
    {                               \
        while ((b) > ((n) -1))      \
            (b) = (b) - (n);        \
        (a)=(b);                    \
    }                               \
    while(0)
#endif // !FAST_PATH_MODULO

#ifndef MINCHAR
#define MINCHAR     0x80
#endif
#ifndef MAXCHAR
#define MAXCHAR     0x7f
#endif
#ifndef MINSHORT
#define MINSHORT    0x8000
#endif
#ifndef MAXSHORT
#define MAXSHORT    0x7fff
#endif
#ifndef MINLONG
#define MINLONG     0x80000000
#endif
#ifndef MAXLONG
#define MAXLONG     0x7fffffff
#endif
#ifndef MAXBYTE
#define MAXBYTE     0xff
#endif
#ifndef MAXWORD
#define MAXWORD     0xffff
#endif
#ifndef MAXDWORD
#define MAXDWORD    0xffffffff
#endif

#define CLEAR_MSB32(_val32) (_val32 & MAXLONG)

// Calculate the size of a field in a structure of type type, without
// knowing or stating the type of the field.
// based on NTDDK RTL_FIELD_SIZE
#ifndef FIELD_SIZE
#define FIELD_SIZE(type, field) (sizeof(((type *)0)->field))
#endif

#endif /* __utils_h__ */
