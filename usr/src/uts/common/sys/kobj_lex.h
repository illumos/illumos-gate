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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2015 PALO, Richard.  All rights reserved.
 */

#ifndef _SYS_KOBJ_LEX_H
#define	_SYS_KOBJ_LEX_H

#include <sys/ctype.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file contains declarations for lex and its associated functions that
 * are used by the kernel to parse the contents of system files.
 *
 * These lex functions are for a few selected kernel modules that are required
 * to parse contents of file(s) on disk. This file is not for general kernel
 * usage.
 */

#define	isunary(ch)	((ch) == '~' || (ch) == '-')

#define	iswhite(ch)	((ch) == ' ' || (ch) == '\t')

#define	isnewline(ch)	((ch) == '\n' || (ch) == '\r' || (ch) == '\f')

#define	isalphanum(ch)	(isalpha(ch) || isdigit(ch))

#define	isnamechar(ch)	(isalphanum(ch) || (ch) == '_' || (ch) == '-')

typedef enum {
	UNEXPECTED = -1,
	EQUALS,
	AMPERSAND,
	BIT_OR,
	STAR,
	POUND,
	COLON,
	SEMICOLON,
	COMMA,
	SLASH,
	WHITE_SPACE,
	NEWLINE,
	EOF,
	STRING,
	HEXVAL,
	DECVAL,
	NAME
} token_t;

#ifdef DEBUG
/* string values for token_t */
extern char *tokennames[];
#endif /* DEBUG */

/*
 * return 1 with sptr pointing to the string represented by token
 * On error returns NULL. The memory pointed to by sptr should be
 * freed using free_string function.
 */
int kobj_get_string(u_longlong_t *sptr, char *token);
void kobj_free_string(void *ptr, int len);

/*
 * returns decimal/octal/hex number in valuep
 * return 0 on success, -1 on failure
 */
int kobj_getvalue(const char *token, u_longlong_t *valuep);

/* prints a formated message via cmn_err */
/*PRINTFLIKE3*/
extern void kobj_file_err(int type,  struct _buf *file, char *fmt, ...)
	__KPRINTFLIKE(3);

/*
 * returns the next token in the file on success,
 * return -1 on failure
 */
token_t kobj_lex(struct _buf *file, char *val, size_t size);

void kobj_find_eol(struct _buf *file);

#ifdef	__cplusplus
}
#endif

#endif /* !_SYS_KOBJ_LEX_H */
