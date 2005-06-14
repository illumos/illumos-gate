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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * logadm/err.h -- public definitions for error module
 */

#ifndef	_LOGADM_ERR_H
#define	_LOGADM_ERR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <setjmp.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* basic error handling routines */
void err_init(const char *myname);
void err_fileline(const char *file, int line);
void err(int flags, const char *fmt, ...);
void out(const char *fmt, ...);
void err_fromfd(int fd);
void err_done(int exitcode);
void err_exitcode(int exitcode);
void err_mailto(const char *recipient);

/* flags for err() */
#define	EF_WARN	0x01	/* print warning and return */
#define	EF_FILE	0x02	/* prepend file:line from last err_fileline() call */
#define	EF_SYS	0x04	/* append errno text to message */
#define	EF_JMP	0x08	/* longjmp through Error_env after printing error */
#define	EF_RAW	0x10	/* don't prepend/append anything to message */

jmp_buf Err_env;

#define	SETJMP	setjmp(Err_env)

#define	MALLOC(nbytes) err_malloc(nbytes, __FILE__, __LINE__)
void *err_malloc(int nbytes, const char *fname, int line);

#define	REALLOC(ptr, nbytes) err_realloc(ptr, nbytes, __FILE__, __LINE__)
void *err_realloc(void *ptr, int nbytes, const char *fname, int line);

#define	FREE(ptr) err_free(ptr, __FILE__, __LINE__)
void err_free(void *ptr, const char *fname, int line);

#define	STRDUP(ptr) err_strdup(ptr, __FILE__, __LINE__)
char *err_strdup(const char *ptr, const char *fname, int line);

int Debug;	/* replace with #define to zero to compile out Debug code */

#ifdef	__cplusplus
}
#endif

#endif	/* _LOGADM_ERR_H */
