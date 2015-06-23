/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 */
/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_INT_FMTIO_H
#define	_SYS_INT_FMTIO_H

/*
 * This file, <sys/int_fmtio.h>, is part of the Sun Microsystems implementation
 * of <inttypes.h> as defined by the ISO C Standard, ISO/IEC 9899:1999
 * Programming language - C.
 *
 * ISO  International Organization for Standardization.
 *
 * Programs/Modules should not directly include this file.  Access to the
 * types defined in this file should be through the inclusion of one of the
 * following files:
 *
 *	<sys/inttypes.h>	Provides the Kernel and Driver appropriate
 *				components of <inttypes.h>.
 *
 *	<inttypes.h>		For use by applications.
 *
 * See these files for more details.
 */

#include <sys/feature_tests.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Formatted I/O
 *
 * The following macros can be used even when an implementation has not
 * extended the printf/scanf family of functions.
 *
 * The form of the names of the macros is either "PRI" for printf specifiers
 * or "SCN" for scanf specifiers, followed by the conversion specifier letter
 * followed by the datatype size. For example, PRId32 is the macro for
 * the printf d conversion specifier with the flags for 32 bit datatype.
 *
 * An example using one of these macros:
 *
 *	uint64_t u;
 *	printf("u = %016" PRIx64 "\n", u);
 *
 * For the purpose of example, the definitions of the printf/scanf macros
 * below have the values appropriate for a machine with 8 bit shorts, 16
 * bit shorts, 32 bit ints, 32 or 64 bit longs depending on compilation
 * mode, and 64 bit long longs.
 */

/*
 * fprintf macros for signed integers
 */
#if defined(_KERNEL)
#define	_MODF8	""
#define	_MODF16	""
#else
#define	_MODF8	"hh"
#define	_MODF16	"h"
#endif

#define	_PRId	"d"
#define	_PRIi	"i"
#define	_PRIo	"o"
#define	_PRIu	"u"
#define	_PRIx	"x"
#define	_PRIX	"X"

#define	PRId8			_MODF8 _PRId
#define	PRIdLEAST8		PRId8
#define	PRIdFAST8		PRId8
#define	PRId16			_MODF16 _PRId
#define	PRIdLEAST16		PRId16
#define	PRId32			"d"
#define	PRIdFAST16		PRId32
#define	PRIdLEAST32		PRId32
#define	PRIdFAST32		PRId32
#ifdef  _LP64
#define	PRId64			"ld"
#else   /* _ILP32 */
#if defined(_LONGLONG_TYPE)
#define	PRId64			"lld"
#endif
#endif
#ifdef PRId64
#define	PRIdLEAST64		PRId64
#define	PRIdFAST64		PRId64
#endif

#define	PRIi8			_MODF8 _PRIi
#define	PRIiLEAST8		PRIi8
#define	PRIiFAST8		PRIi8
#define	PRIi16			_MODF16 _PRIi
#define	PRIiLEAST16		PRIi16
#define	PRIi32			"i"
#define	PRIiFAST16		PRIi32
#define	PRIiLEAST32		PRIi32
#define	PRIiFAST32		PRIi32
#ifdef  _LP64
#define	PRIi64			"li"
#else   /* _ILP32 */
#if defined(_LONGLONG_TYPE)
#define	PRIi64			"lli"
#endif
#endif
#ifdef PRIi64
#define	PRIiLEAST64		PRIi64
#define	PRIiFAST64		PRIi64
#endif

/*
 * fprintf macros for unsigned integers
 */

#define	PRIo8			_MODF8 _PRIo
#define	PRIoLEAST8		PRIo8
#define	PRIoFAST8		PRIo8
#define	PRIo16			_MODF16 _PRIo
#define	PRIoLEAST16		PRIo16
#define	PRIo32			"o"
#define	PRIoFAST16		PRIo32
#define	PRIoLEAST32		PRIo32
#define	PRIoFAST32		PRIo32
#ifdef  _LP64
#define	PRIo64			"lo"
#else	/* _ILP32 */
#if defined(_LONGLONG_TYPE)
#define	PRIo64			"llo"
#endif
#endif
#ifdef PRIo64
#define	PRIoLEAST64		PRIo64
#define	PRIoFAST64		PRIo64
#endif

#define	PRIu8			_MODF8 _PRIu
#define	PRIuLEAST8		PRIu8
#define	PRIuFAST8		PRIu8
#define	PRIu16			_MODF16 _PRIu
#define	PRIuLEAST16		PRIu16
#define	PRIu32			"u"
#define	PRIuFAST16		PRIu32
#define	PRIuLEAST32		PRIu32
#define	PRIuFAST32		PRIu32
#ifdef  _LP64
#define	PRIu64			"lu"
#else   /* _ILP32 */
#if defined(_LONGLONG_TYPE)
#define	PRIu64			"llu"
#endif
#endif
#ifdef PRIu64
#define	PRIuLEAST64		PRIu64
#define	PRIuFAST64		PRIu64
#endif

#define	PRIx8			_MODF8 _PRIx
#define	PRIxLEAST8		PRIx8
#define	PRIxFAST8		PRIx8
#define	PRIx16			_MODF16 _PRIx
#define	PRIxLEAST16		PRIx16
#define	PRIx32			"x"
#define	PRIxFAST16		PRIx32
#define	PRIxLEAST32		PRIx32
#define	PRIxFAST32		PRIx32
#ifdef  _LP64
#define	PRIx64			"lx"
#else   /* _ILP32 */
#if defined(_LONGLONG_TYPE)
#define	PRIx64			"llx"
#endif
#endif
#ifdef PRIx64
#define	PRIxLEAST64		PRIx64
#define	PRIxFAST64		PRIx64
#endif

#define	PRIX8			_MODF8 _PRIX
#define	PRIXLEAST8		PRIX8
#define	PRIXFAST8		PRIX8
#define	PRIX16			_MODF16 _PRIX
#define	PRIXLEAST16		PRIX16
#define	PRIX32			"X"
#define	PRIXFAST16		PRIX32
#define	PRIXLEAST32		PRIX32
#define	PRIXFAST32		PRIX32
#ifdef  _LP64
#define	PRIX64			"lX"
#else   /* _ILP32 */
#if defined(_LONGLONG_TYPE)
#define	PRIX64			"llX"
#endif
#endif
#ifdef PRIX64
#define	PRIXLEAST64		PRIX64
#define	PRIXFAST64		PRIX64
#endif

/*
 * fprintf macros for pointers
 */

#if defined(_LP64) || defined(_I32LPx)
#define	PRIdPTR			"ld"
#define	PRIiPTR			"li"
#define	PRIoPTR			"lo"
#define	PRIuPTR			"lu"
#define	PRIxPTR			"lx"
#define	PRIXPTR			"lX"
#else
#define	PRIdPTR			"d"
#define	PRIiPTR			"i"
#define	PRIoPTR			"o"
#define	PRIuPTR			"u"
#define	PRIxPTR			"x"
#define	PRIXPTR			"X"
#endif /* defined(_LP64) || defined(_I32LPx) */

/*
 * fscanf macros for signed integers
 */
#define	SCNd8			"hhd"
#define	SCNdLEAST8		SCNd8
#define	SCNdFAST8		SCNd8
#define	SCNd16			"hd"
#define	SCNdLEAST16		SCNd16
#define	SCNd32			"d"
#define	SCNdFAST16		SCNd32
#define	SCNdLEAST32		SCNd32
#define	SCNdFAST32		SCNd32
#ifdef PRId64
#define	SCNd64			PRId64
#define	SCNdLEAST64		PRId64
#define	SCNdFAST64		PRId64
#endif
#define	SCNdPTR			PRIdPTR

#define	SCNi8			"hhi"
#define	SCNiLEAST8		SCNi8
#define	SCNiFAST8		SCNi8
#define	SCNi16			"hi"
#define	SCNiLEAST16		SCNi16
#define	SCNi32			"i"
#define	SCNiFAST16		SCNi32
#define	SCNiLEAST32		SCNi32
#define	SCNiFAST32		SCNi32
#ifdef PRIi64
#define	SCNi64			PRIi64
#define	SCNiLEAST64		PRIi64
#define	SCNiFAST64		PRIi64
#endif
#define	SCNiPTR			PRIiPTR

/*
 * fscanf macros for unsigned integers
 */
#define	SCNo8			"hho"
#define	SCNoLEAST8		SCNo8
#define	SCNoFAST8		SCNo8
#define	SCNo16			"ho"
#define	SCNoLEAST16		SCNo16
#define	SCNo32			"o"
#define	SCNoFAST16		SCNo32
#define	SCNoLEAST32		SCNo32
#define	SCNoFAST32		SCNo32
#ifdef PRIo64
#define	SCNo64			PRIo64
#define	SCNoLEAST64		PRIo64
#define	SCNoFAST64		PRIo64
#endif
#define	SCNoPTR			PRIoPTR

#define	SCNu8			"hhu"
#define	SCNuLEAST8		SCNu8
#define	SCNuFAST8		SCNu8
#define	SCNu16			"hu"
#define	SCNuLEAST16		SCNu16
#define	SCNu32			"u"
#define	SCNuFAST16		SCNu32
#define	SCNuLEAST32		SCNu32
#define	SCNuFAST32		SCNu32
#ifdef PRIu64
#define	SCNu64			PRIu64
#define	SCNuLEAST64		PRIu64
#define	SCNuFAST64		PRIu64
#endif
#define	SCNuPTR			PRIuPTR

#define	SCNx8			"hhx"
#define	SCNxLEAST8		SCNx8
#define	SCNxFAST8		SCNx8
#define	SCNx16			"hx"
#define	SCNxLEAST16		SCNx16
#define	SCNx32			"x"
#define	SCNxFAST16		SCNx32
#define	SCNxLEAST32		SCNx32
#define	SCNxFAST32		SCNx32
#ifdef PRIx64
#define	SCNx64			PRIx64
#define	SCNxLEAST64		PRIx64
#define	SCNxFAST64		PRIx64
#endif
#define	SCNxPTR			PRIxPTR

#define	SCNX8			"hhX"
#define	SCNXLEAST8		SCNX8
#define	SCNXFAST8		SCNX8
#define	SCNX16			"hX"
#define	SCNXLEAST16		SCNX16
#define	SCNX32			"X"
#define	SCNXFAST16		SCNX32
#define	SCNXLEAST32		SCNX32
#define	SCNXFAST32		SCNX32
#ifdef PRIX64
#define	SCNX64			PRIX64
#define	SCNXLEAST64		PRIX64
#define	SCNXFAST64		PRIX64
#endif
#define	SCNXPTR			PRIXPTR

/*
 * The following macros define I/O formats for intmax_t and uintmax_t.
 */
#if !defined(_LP64) && defined(_LONGLONG_TYPE)
#define	PRIdMAX			"lld"
#define	PRIiMAX			"lli"
#define	PRIoMAX			"llo"
#define	PRIxMAX			"llx"
#define	PRIuMAX			"llu"
#define	PRIXMAX			"llX"
#else
#define	PRIdMAX			"ld"
#define	PRIiMAX			"li"
#define	PRIoMAX			"lo"
#define	PRIxMAX			"lx"
#define	PRIuMAX			"lu"
#define	PRIXMAX			"lX"
#endif	/* !defined(_LP64) && defined(_LONGLONG_TYPE) */

#define	SCNdMAX			PRIdMAX
#define	SCNiMAX			PRIiMAX
#define	SCNoMAX			PRIoMAX
#define	SCNxMAX			PRIxMAX
#define	SCNuMAX			PRIuMAX
#define	SCNXMAX			PRIXMAX

#ifdef __cplusplus
}
#endif

#endif /* _SYS_INT_FMTIO_H */
