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

#ifndef _GRP_H
#define	_GRP_H

#include <sys/feature_tests.h>

#include <sys/types.h>

#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX)
#include <stdio.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

struct	group {	/* see getgrent(3C) */
	char	*gr_name;
	char	*gr_passwd;
	gid_t	gr_gid;
	char	**gr_mem;
};

extern struct group *getgrgid(gid_t);		/* MT-unsafe */
extern struct group *getgrnam(const char *);	/* MT-unsafe */

#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX)
extern struct group *getgrent_r(struct group *, char *, int);
extern struct group *fgetgrent_r(FILE *, struct group *, char *, int);


extern struct group *fgetgrent(FILE *);		/* MT-unsafe */
extern int initgroups(const char *, gid_t);
#endif /* defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) */

#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2)
extern void endgrent(void);
extern void setgrent(void);
extern struct group *getgrent(void);		/* MT-unsafe */
#endif /* defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX)... */

/*
 * getgrgid_r() & getgrnam_r() prototypes are defined here.
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

#if	defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) || \
	(_POSIX_C_SOURCE - 0 >= 199506L) || defined(_POSIX_PTHREAD_SEMANTICS)

#if	(_POSIX_C_SOURCE - 0 >= 199506L) || defined(_POSIX_PTHREAD_SEMANTICS)

#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname getgrgid_r __posix_getgrgid_r
#pragma redefine_extname getgrnam_r __posix_getgrnam_r
extern int getgrgid_r(gid_t, struct group *, char *, int, struct group **);
extern int getgrnam_r(const char *, struct group *, char *, int,
							struct group **);
#else  /* __PRAGMA_REDEFINE_EXTNAME */

extern int __posix_getgrgid_r(gid_t, struct group *, char *, size_t,
    struct group **);
extern int __posix_getgrnam_r(const char *, struct group *, char *, size_t,
    struct group **);

#ifdef __lint

#define	getgrgid_r __posix_getgrgid_r
#define	getgrnam_r __posix_getgrnam_r

#else	/* !__lint */

static int
getgrgid_r(gid_t __gid, struct group *__grp, char *__buf, int __len,
    struct group **__res)
{
	return (__posix_getgrgid_r(__gid, __grp, __buf, __len, __res));
}
static int
getgrnam_r(const char *__cb, struct group *__grp, char *__buf, int __len,
    struct group **__res)
{
	return (__posix_getgrnam_r(__cb, __grp, __buf, __len, __res));
}

#endif /* !__lint */
#endif /* __PRAGMA_REDEFINE_EXTNAME */

#else  /* (_POSIX_C_SOURCE - 0 >= 199506L) || ... */

extern struct group *getgrgid_r(gid_t, struct group *, char *, int);
extern struct group *getgrnam_r(const char *, struct group *, char *, int);

#endif  /* (_POSIX_C_SOURCE - 0 >= 199506L) || ... */

#endif /* defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX)... */

#ifdef	__cplusplus
}
#endif

#endif	/* _GRP_H */
