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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PWD_H
#define	_PWD_H

#include <sys/feature_tests.h>

#include <sys/types.h>

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
#include <stdio.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

struct passwd {
	char	*pw_name;
	char	*pw_passwd;
	uid_t	pw_uid;
	gid_t	pw_gid;
	char	*pw_age;
	char	*pw_comment;
	char	*pw_gecos;
	char	*pw_dir;
	char	*pw_shell;
};

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
struct comment {
	char	*c_dept;
	char	*c_name;
	char	*c_acct;
	char	*c_bin;
};
#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

extern struct passwd *getpwuid(uid_t);		/* MT-unsafe */
extern struct passwd *getpwnam(const char *);	/* MT-unsafe */

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
extern struct passwd *getpwent_r(struct passwd *, char *, int);
extern struct passwd *fgetpwent_r(FILE *, struct passwd *, char *, int);
extern struct passwd *fgetpwent(FILE *);	/* MT-unsafe */
extern int putpwent(const struct passwd *, FILE *);
#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

#if !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) || \
	defined(__EXTENSIONS__)
extern void endpwent(void);
extern struct passwd *getpwent(void);		/* MT-unsafe */
extern void setpwent(void);
#endif /* !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) ... */

/*
 * getpwuid_r() & getpwnam_r() prototypes are defined here.
 */

/*
 * Previous releases of Solaris, starting at 2.3, provided definitions of
 * various functions as specified in POSIX.1c, Draft 6.  For some of these
 * functions, the final POSIX 1003.1c standard had a different number of
 * arguments and return values.
 *
 * The following segment of this header provides support for the standard
 * interfaces while supporting applications written under earlier
 * releases.  The application defines appropriate values of the feature
 * test macros _POSIX_C_SOURCE and _POSIX_PTHREAD_SEMANTICS to indicate
 * whether it was written to expect the Draft 6 or standard versions of
 * these interfaces, before including this header.  This header then
 * provides a mapping from the source version of the interface to an
 * appropriate binary interface.  Such mappings permit an application
 * to be built from libraries and objects which have mixed expectations
 * of the definitions of these functions.
 *
 * For applications using the Draft 6 definitions, the binary symbol is the
 * same as the source symbol, and no explicit mapping is needed.  For the
 * standard interface, the function func() is mapped to the binary symbol
 * _posix_func().  The preferred mechanism for the remapping is a compiler
 * #pragma.  If the compiler does not provide such a #pragma, the header file
 * defines a static function func() which calls the _posix_func() version;
 * this has to be done instead of #define since POSIX specifies that an
 * application can #undef the symbol and still be bound to the correct
 * implementation.  Unfortunately, the statics confuse lint so we fallback to
 * #define in that case.
 *
 * NOTE: Support for the Draft 6 definitions is provided for compatibility
 * only.  New applications/libraries should use the standard definitions.
 */

#if !defined(__XOPEN_OR_POSIX) || (_POSIX_C_SOURCE - 0 >= 199506L) || \
	defined(_POSIX_PTHREAD_SEMANTICS) || defined(__EXTENSIONS__)

#if (_POSIX_C_SOURCE - 0 >= 199506L) || defined(_POSIX_PTHREAD_SEMANTICS)

#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname getpwuid_r __posix_getpwuid_r
#pragma redefine_extname getpwnam_r __posix_getpwnam_r
extern int getpwuid_r(uid_t, struct passwd *, char *, int, struct passwd **);
extern int getpwnam_r(const char *, struct passwd *, char *,
							int, struct passwd **);
#else  /* __PRAGMA_REDEFINE_EXTNAME */

extern int __posix_getpwuid_r(uid_t, struct passwd *, char *, size_t,
    struct passwd **);
extern int __posix_getpwnam_r(const char *, struct passwd *, char *,
    size_t, struct passwd **);

#ifdef __lint

#define	getpwuid_r __posix_getpwuid_r
#define	getpwnam_r __posix_getpwnam_r

#else	/* !__lint */

static int
getpwuid_r(uid_t __uid, struct passwd *__pwd, char *__buf, int __len,
    struct passwd **__res)
{
	return (__posix_getpwuid_r(__uid, __pwd, __buf, __len, __res));
}
static int
getpwnam_r(const char *__cb, struct passwd *__pwd, char *__buf, int __len,
    struct passwd **__res)
{
	return (__posix_getpwnam_r(__cb, __pwd, __buf, __len, __res));
}

#endif /* !__lint */
#endif /* __PRAGMA_REDEFINE_EXTNAME */

#else  /* (_POSIX_C_SOURCE - 0 >= 199506L) || ... */

extern struct passwd *getpwuid_r(uid_t, struct passwd *, char *, int);
extern struct passwd *getpwnam_r(const char *, struct passwd *, char *, int);

#endif  /* (_POSIX_C_SOURCE - 0 >= 199506L) || ... */

#endif /* !defined(__XOPEN_OR_POSIX) || (_POSIX_C_SOURCE - 0 >= 199506L)... */

#ifdef	__cplusplus
}
#endif

#endif /* _PWD_H */
