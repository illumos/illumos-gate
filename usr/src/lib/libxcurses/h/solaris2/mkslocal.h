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
 * <mkslocal.h>, Solaris2 Version - local <mks.h> requirements
 *
 * Copyright 1995-1996 (c) Sun Microsystems Inc.
 * All rights reserved.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#define	_ALL_SOURCE

#include <sys/types.h>

#include <stdlib.h>
#include <limits.h>
#include <wchar.h>
#include <widec.h>
#include <wctype.h>

typedef	unsigned char	uchar;

#define	SYSV	1		/* System V compatible */

#ifndef VERSION
/* Used for in sh, vi ... */
#define	VERSION		"MKS InterOpen IXCU 4.3 MB - SUN/SOLARIS2"
#endif

/*
 * Assume that rootname() is called to prepend the proper path prefix
 */
#define	M_CS_PATH	"/usr/xpg4/bin"		/* posix.2 utilities */
#define	M_CS_SHELL	"/usr/xpg4/bin/sh"	/* posix.2 sh */

#define	M_CS_BINDIR	"/usr/bin"
#define	M_CS_ETCDIR	"/etc"
#define	M_CS_LIBDIR	"/usr/lib"
#define	M_CS_SPOOLDIR   "/var/spool"
#define	M_CS_MANPATH    "/usr/man"
#define	M_CS_TMPDIR	"/tmp"
#define	M_CS_NLSDIR	"/usr/lib/locale"

#define	M_BINDIR(path)		M_CS_BINDIR"/" #path
#define	M_ETCDIR(path)		M_CS_ETCDIR"/" #path
#define	M_LIBDIR(path)		M_CS_LIBDIR"/" #path
#define	M_SPOOLDIR(path)	M_CS_SPOOLDIR"/" #path
#define	M_NLSDIR(path)		M_CS_NLSDIR"/" #path

/*
 * M_MANPATH - list of pathnames to be used by man utility
 * M_TMPDIR - pathname of temporary
 */
#define	M_MANPATH		M_CS_MANPATH"/"
#define	M_TMPDIR		M_CS_TMPDIR"/"
#define	M_SYSTEM_TMPDIR		"/tmp"

#define	M_NL_DOM		"mks"
#define	DEF_NLSPATH		"/usr/lib/locale/%L/LC_MESSAGES"

#define	M_RCS_NORCSLIB		1	/* don't use rcslib or its includes */

#define	M_MALLOC	1
#define	M_REALLOC	1
#ifdef M_REALLOC
#define	M_WANT_ANSI_REALLOC	1
#endif

#define	__LDATA__	1	/* Deprecated */
#define	M_LDATA		1

#define	halloc(n, s)	malloc((size_t)((n)*(s)))
#define	hfree(ptr)	free(ptr)
#define	M_FSDELIM(c)	((c) == '/')

/* On POSIX and UNIX there is nothing special to do */
#define	m_cp(src, dest, ssb, flags)	(M_CP_NOOP)

#define	__POSIX_JOB_CONTROL		/* POSIX.1 job control */
#define	__POSIX_WAIT_NOHANG		/* waitpid WNOHANG available */
#define	__POSIX_SAVED_IDS	_POSIX_SAVED_IDS
#define	__POSIX_NO_TRUNC	-1	/* automatic truncation */
#define	__POSIX_VDISABLE	0x00	/* Disable function in termios.h */

/*
 * added for optional facility configuration values
 */
#define	M_POSIX2_C_BIND		1
#define	M_POSIX2_C_DEV		1
#define	M_POSIX2_FORT_DEV	1
#undef	M_POSIX2_FORT_RUN
#define	M_POSIX2_LOCALEDEF	1
#define	M_POSIX2_SW_DEV		1
#define	M_POSIX2_UPE		1
#define	M_POSIX2_CHAR_TERM	1

#undef	M_FCLOSE_NOT_POSIX_1	/* Not POSIX.1 section 8.2 */
#undef	M_FFLUSH_NOT_POSIX_1	/* Not POSIX.1 section 8.2 */

#define	M_BSD_SPRINTF		0	/* sprintf on this system has BSD */
					/* semantics, does not return length */
#define	M_ENDPWENT		1	/* set to 1 if system provides a */
					/* getpwent() routine */
#define	M_MATHERR		1	/* math library supports matherr() */

#define	M_LOGGER_CONSOLE	"/dev/console"

#define	M_SVFS_INO	1

/*
 * Set I18N flags
 */
#define	M_I18N		1	/* turn on internationalizaion */
#define	I18N		1	/* OBSOLESCENT version of M_I18N */

#define	M_I18N_M_	1	/* Uses m_ on MKS i18n extension routines */
#define	M_I18N_MKS_XPG	1	/* Use NL info from XPG4 */
#define	M_I18N_MKS_FULL	0	/* Full mks extensions */
#define	M_I18N_MB	1	/* Enable multibyte compilation */
#undef	M_I18N_LOCKING_SHIFT	/* No locking-shift character sets. */
#undef	M_VARIANTS		/* Invariant characters are */

/*
 * Interopen Curses for Solaris2
 */
#undef	M_CURSES_MEMMAPPED
#define	M_TERM_NAME		"vt100"
#define	M_TERMINFO_DIR		"/usr/share/lib/terminfo"
#define	M_CURSES_VERSION	"MKS I/XCU 4.3 Curses"

#define	M_ULIMIT_AVAIL	1	/* <ulimit.h> file available */
#define	M_EXPR_POSIX	1	/* decimal only on the expr command line */

#define	M_PATH_MAX	PATH_MAX

/*
 * Solaris 2 does not use stateful encoding, so we will just convert these
 * to their stateless equivalent.
 */
#ifndef	_MBSTATE_T
#define	_MBSTATE_T
typedef int	mbstate_t;
#endif	/* ! _MBSTATE_T */

#define	mbrlen(c, n, ps)	mblen(c, n)
#define	wcrtomb(c, w, s)	wctomb(c, w)
#define	mbrtowc(p, w, n, s)	mbtowc(p, w, n)

#define	wcsrtombs(w, c, n, s)	wcstombs(w, c, n)
#define	mbsrtowcs(c, w, n, s)	mbstowcs(c, w, n)
