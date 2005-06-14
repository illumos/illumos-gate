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
 * Copyright (c) 1998-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_APPTRACE_H
#define	_APPTRACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <link.h>
#include <signal.h>
#include <synch.h>
#include <wchar.h>
#include <thread.h>
#include <apptrace_impl.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Extract the verbosity flag.
 */
#define	ABI_VFLAG(lib, symbol) \
	__abi_ ## lib ## _ ## symbol ## _sym.a_vflag

/*
 * Extract the function pointer to the real ABI function.
 */
#define	ABI_REAL(lib, symbol) \
	__abi_ ## lib ## _ ## symbol ## _sym.a_real

/*
 * Macro to create the part of a function call prior
 * to the arg list.
 *   cast is a full cast expression for a _pointer_ to
 *   the ABI function being called.
 *
 * e.g.  ABI_CALL_REAL(libc, getpid, (pid_t (*)(void)))  ();
 */
#define	ABI_CALL_REAL(lib, sym, cast) \
	(cast __abi_ ## lib ## _ ## sym ## _sym.a_real)

#define	ABISTREAM	__abi_outfile
#define	ABIPUTS(x)	(void) fputs((x), ABISTREAM)

/*
 * The following declarations and macros are needed for
 * anybody needing the vprintf family of calls where they
 * MUST come from the BASE link map instead of the auditing
 * link map.
 */
#define	ABI_VSNPRINTF	__abi_real_vsnprintf
#define	ABI_VSWPRINTF	__abi_real_vswprintf
#define	ABI_VWPRINTF	__abi_real_vwprintf
#define	ABI_VFPRINTF	__abi_real_vfprintf
#define	ABI_VFWPRINTF	__abi_real_vfwprintf
#define	ABI_VPRINTF	__abi_real_vprintf
#define	ABI_VSPRINTF	__abi_real_vsprintf
#define	ABI_ERRNO	(*(__abi_real_errno()))

/* From libstabspf */
typedef enum {
	STAB_SUCCESS	= 0,	/* All is well. */
	STAB_FAIL	= -1,	/* Parsing error. */
	STAB_NA		= -2,	/* Information is Not Applicable. */
	STAB_NOMEM	= -3	/* Out of Memory! */
} stabsret_t;

extern int (*ABI_VFPRINTF)(FILE *, const char *, va_list);
extern int (*ABI_VFWPRINTF)(FILE *, const wchar_t *, va_list);
extern int (*ABI_VPRINTF)(const char *, va_list);
extern int (*ABI_VSNPRINTF)(char *, size_t, const char *, va_list);
extern int (*ABI_VSPRINTF)(char *, const char *, va_list);
extern int (*ABI_VSWPRINTF)(wchar_t *, size_t, const wchar_t *, va_list);
extern int (*ABI_VWPRINTF)(const wchar_t *, va_list);
extern int *(*__abi_real_errno)(void);

extern void *abi_malloc(size_t);
extern void *abi_calloc(size_t, size_t);
extern void *abi_realloc(void *, size_t);
extern int  abi_putc(int, FILE *);
extern int  abi_fputs(const char *, FILE *);
extern void abi_free(void *);

/* From libstabspf */
extern stabsret_t spf_load_stabs(const char *);
extern int spf_prtype(FILE *, char const *, int, void const *);

extern int abi_strpsz;	/* size constraint for string printing */

#ifdef	__cplusplus
}
#endif

#endif	/* _APPTRACE_H */
