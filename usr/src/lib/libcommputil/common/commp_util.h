/*
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
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _COMMP_UTIL_H
#define	_COMMP_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	COMMP_CRLF			"\r\n"
#define	COMMP_LF			"\n"
#define	COMMP_SKIP_CRLF(msg_ptr)	((msg_ptr) = (msg_ptr) + 2)
#define	COMMP_SKIP_LF(msg_ptr)		((msg_ptr) = (msg_ptr) + 1)

#define	COMMP_SECS_IN_DAY		86400
#define	COMMP_SECS_IN_HOUR		3600
#define	COMMP_SECS_IN_MIN		60

#define	COMMP_SP			' '
#define	COMMP_CR			'\r'
#define	COMMP_COLON			':'
#define	COMMP_SLASH			'/'
#define	COMMP_EQUALS			'='
#define	COMMP_ADDRTYPE_IP4		"IP4"
#define	COMMP_ADDRTYPE_IP6		"IP6"

#define	COMMP_COPY_STR(dst, src, len) { 		\
	(dst) = calloc(1, (len) + 1);			\
	if ((dst) != NULL) {				\
		(void) strncpy((dst), (src), (len));	\
	}						\
}

extern int	commp_skip_white_space(const char **, const char *);
extern int	commp_find_token(const char **, const char **, const char *,
		    char, boolean_t);
extern int	commp_atoi(const char *, const char *, int *);
extern int	commp_strtoull(const char *, const char *, uint64_t *);
extern int	commp_strtoub(const char *, const char *, uint8_t *);
extern int	commp_atoui(const char *, const char *, uint_t *);
extern int	commp_time_to_secs(const char *, const char *, uint64_t *);
extern int 	commp_add_str(char **, const char *, int);

#ifdef __cplusplus
}
#endif

#endif /* _COMMP_UTIL_H */
