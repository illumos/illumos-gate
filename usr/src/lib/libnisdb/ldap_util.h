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
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdarg.h>
#include <syslog.h>

#include "ldap_structs.h"

#ifndef	_LDAP_UTIL_H
#define	_LDAP_UTIL_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	T	1
#define	F	0

#define	NIL(s)	(((s) != 0) ? (s) : "<nil>")
#define	MAX(a, b)	(((a) > (b)) ? (a) : (b))

/* Message types */
#define	MSG_ALWAYS		-1
#define	MSG_NOTIMECHECK		0
#define	MSG_NOMEM		1
#define	MSG_MEMPARAM		2
#define	MSG_TSDERR		3
#define	MSG_BER			4
#define	MSG_INVALIDDELDISP	5
#define	MSG_NORULEVALUE		6
#define	MSG_NONPCOLDSTART	7
#define	MSG_VLV_INSUFF_ACC	8
#define	MSG_LASTMSG		9

/* Error numbers (NPL is NisPlusLdap) */
#define	NPL_NOERROR	0
#define	NPL_NOMEM	1
#define	NPL_TSDERR	2
#define	NPL_BERENCODE	3
#define	NPL_BERDECODE	4

/* Structure used to maintain a buffer with a length */
typedef struct {
	char	*buf;
	int	len;
} __nis_buffer_t;

/* Generic print buffer */
extern __nis_buffer_t	pb;

/* Deferred error reporting buffer (TSD) */
typedef struct {
	int		error;
	char		*message;
}  __nis_deferred_error_t;

/* Exported symbols */
extern unsigned long	numMisaligned;

/* Exported functions */
void	logmsg(int msgtype, int priority, const char *fmt, ...);
void	reportError(int error, char *fmt, ...);
int	getError(char **message);
void	clearError(void);
void	logError(int priority);
void	*am(const char *msg, int size);
int	slen(const char *str);
char	*sdup(const char *msg, int allocate, char *str);
char	*scat(const char *msg, int deallocate, char *s1, char *s2);
void	sfree(void *ptr);
char	lastChar(__nis_single_value_t *v);
void	*appendString2SingleVal(char *str, __nis_single_value_t *v,
		int *newLen);
int	scmp(char *s, __nis_single_value_t *v);
int	scasecmp(char *s, __nis_single_value_t *v);
int	vp2buf(const char *msg, char **buf, int buflen, const char *fmt,
    va_list ap);
void	p2buf(char *msg, char *fmt, ...);
void	bp2buf(const char *msg, __nis_buffer_t *b, const char *fmt, ...);
void	bc2buf(const char *msg, void *buf, int len, __nis_buffer_t *b);
void	sbc2buf(const char *msg, void *buf, int len, __nis_buffer_t *b);
void	c2buf(char *msg, void *buf, int len);
void	sc2buf(char *msg, void *buf, int len);
void	printbuf(void);
void	*extendArray(void *array, int newsize);
int	checkIPaddress(char *addr, int len, char **newaddr);
int	sstrncmp(const char *s1, const char *s2, int n);
char	*trimWhiteSpaces(char *str, int *len, int deallocate);
int	escapeSpecialChars(__nis_value_t *val);
void	removeEscapeChars(__nis_value_t *val);


#ifdef	__cplusplus
}
#endif	/* __cplusplus */

#endif	/* _LDAP_UTIL_H */
