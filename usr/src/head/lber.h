/*
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4
 *
 * The contents of this file are subject to the Netscape Public License
 * Version 1.0(the "NPL"); you may not use this file except in
 * compliance with the NPL.  You may obtain a copy of the NPL at
 * http:/ /www.mozilla.org/NPL/
 *
 * Software distributed under the NPL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the NPL
 * for the specific language governing rights and limitations under the
 * NPL.
 *
 * The Initial Developer of this code under the NPL is Netscape
 * Communications Corporation.  Portions created by Netscape are
 * Copyright(C) 1998 Netscape Communications Corporation.  All Rights
 * Reserved.
 */

#ifndef	_LBER_H
#define	_LBER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_SOLARIS_SDK
#define	_SOLARIS_SDK
#endif

#include <stdlib.h>	/* to pick up size_t typedef */

#ifdef	_SOLARIS_SDK
#ifdef	sunos4
#define	SAFEMEMCPY(d, s, n)   bcopy(s, d, n)
#else /* sunos4 */
#define	SAFEMEMCPY(d, s, n)   memmove(d, s, n)
#endif /* sunos4 */
#endif /* _SOLARIS_SDK */
/*
 * Note that LBER_ERROR and LBER_DEFAULT are values that can never appear
 * as valid BER tags, and so it is safe to use them to report errors.  In
 * fact, any tag for which the following is true is invalid:
 *     (( tag & 0x00000080 ) != 0 ) && (( tag & 0xFFFFFF00 ) != 0 )
 */
#define	LBER_ERROR		0xffffffffU
#define	LBER_DEFAULT		0xffffffffU
#define	LBER_END_OF_SEQORSET	0xfffffffeU
/* BER classes and mask */
#define	LBER_CLASS_UNIVERSAL    0x00
#define	LBER_CLASS_APPLICATION  0x40
#define	LBER_CLASS_CONTEXT	0x80
#define	LBER_CLASS_PRIVATE	0xc0
#define	LBER_CLASS_MASK		0xc0

/* BER encoding type and mask */
#define	LBER_PRIMITIVE		0x00
#define	LBER_CONSTRUCTED	0x20
#define	LBER_ENCODING_MASK	0x20

#define	LBER_BIG_TAG_MASK	0x1f
#define	LBER_MORE_TAG_MASK	0x80

/* general BER types we know about */
#define	LBER_BOOLEAN		0x01
#define	LBER_INTEGER		0x02
#define	LBER_BITSTRING		0x03
#define	LBER_OCTETSTRING	0x04
#define	LBER_NULL		0x05
#define	LBER_ENUMERATED		0x0a
#define	LBER_SEQUENCE		0x30
#define	LBER_SET		0x31


typedef unsigned int	ber_len_t;   /* for BER len */
typedef unsigned int	ber_tag_t;   /* for BER tags */
typedef int		ber_int_t;   /* for BER ints, enums, and Booleans */
typedef unsigned int	ber_uint_t; /* unsigned equivalent of ber_int_t */
typedef int		ber_slen_t; /* signed equivalent of ber_len_t */

typedef struct berval {
	ber_len_t	bv_len;
	char		*bv_val;
} BerValue;

typedef struct berelement BerElement;

#ifdef	_SOLARIS_SDK
#define	NULLBER ((BerElement *)NULL)
#endif

typedef int (*BERTranslateProc)(char **bufp, ber_uint_t *buflenp,
	int free_input);
#ifndef	macintosh
#if defined(_WINDOWS) || defined(_WIN32) || defined(_CONSOLE)
#include <winsock.h> /* for SOCKET */
typedef SOCKET LBER_SOCKET;
#else
typedef int LBER_SOCKET;
#endif /* _WINDOWS */
#else /* macintosh */
typedef void *LBER_SOCKET;
#endif /* macintosh */

/* calling conventions used by library */
#ifndef	LDAP_CALL
#if defined(_WINDOWS) || defined(_WIN32)
#define	LDAP_C __cdecl
#ifndef	_WIN32
#define	__stdcall _far _pascal
#define	LDAP_CALLBACK _loadds
#else
#define	LDAP_CALLBACK
#endif /* _WIN32 */
#define	LDAP_PASCAL __stdcall
#define	LDAP_CALL LDAP_PASCAL
#else /* _WINDOWS */
#define	LDAP_C
#define	LDAP_CALLBACK
#define	LDAP_PASCAL
#define	LDAP_CALL
#endif /* _WINDOWS */
#endif /* LDAP_CALL */

/*
 * function prototypes for lber library
 */
#ifndef	LDAP_API
#if defined(_WINDOWS) || defined(_WIN32)
#define	LDAP_API(rt) rt
#else /* _WINDOWS */
#define	LDAP_API(rt) rt
#endif /* _WINDOWS */
#endif /* LDAP_API */

/*
 * decode routines
 */
ber_tag_t LDAP_CALL ber_get_tag(BerElement *ber);
ber_tag_t LDAP_CALL ber_skip_tag(BerElement *ber,
	ber_len_t *len);
ber_tag_t LDAP_CALL ber_peek_tag(BerElement *ber,
	ber_len_t *len);
ber_tag_t LDAP_CALL ber_get_int(BerElement *ber, ber_int_t *num);
ber_tag_t LDAP_CALL ber_get_stringb(BerElement *ber, char *buf,
	ber_len_t *len);
ber_tag_t LDAP_CALL ber_get_stringa(BerElement *ber,
	char **buf);
ber_tag_t LDAP_CALL ber_get_stringal(BerElement *ber,
	struct berval **bv);
ber_tag_t ber_get_bitstringa(BerElement *ber,
	char **buf, ber_len_t *len);
ber_tag_t LDAP_CALL ber_get_null(BerElement *ber);
ber_tag_t LDAP_CALL ber_get_boolean(BerElement *ber,
	int *boolval);
ber_tag_t LDAP_CALL ber_first_element(BerElement *ber,
	ber_len_t *len, char **last);
ber_tag_t LDAP_CALL ber_next_element(BerElement *ber,
	ber_len_t *len, char *last);
ber_tag_t LDAP_C ber_scanf(BerElement *ber, const char *fmt,
	...);
LDAP_API(void) LDAP_CALL ber_bvfree(struct berval *bv);
LDAP_API(void) LDAP_CALL ber_bvecfree(struct berval **bv);
struct berval *LDAP_CALL ber_bvdup(const struct berval *bv);
LDAP_API(void) LDAP_CALL ber_set_string_translators(BerElement *ber,
	BERTranslateProc encode_proc, BERTranslateProc decode_proc);
LDAP_API(BerElement *) LDAP_CALL ber_init(const struct berval *bv);

/*
 * encoding routines
 */
int LDAP_CALL ber_put_enum(BerElement *ber, ber_int_t num,
	ber_tag_t tag);
int LDAP_CALL ber_put_int(BerElement *ber, ber_int_t num,
	ber_tag_t tag);
int LDAP_CALL ber_put_ostring(BerElement *ber, char *str,
	ber_len_t len, ber_tag_t tag);
int LDAP_CALL ber_put_string(BerElement *ber, char *str,
	ber_tag_t tag);
int LDAP_CALL ber_put_bitstring(BerElement *ber, char *str,
	ber_len_t bitlen, ber_tag_t tag);
int LDAP_CALL ber_put_null(BerElement *ber, ber_tag_t tag);
int LDAP_CALL ber_put_boolean(BerElement *ber, int boolval,
	ber_tag_t tag);
int LDAP_CALL ber_start_seq(BerElement *ber, ber_tag_t tag);
int LDAP_CALL ber_start_set(BerElement *ber, ber_tag_t tag);
int LDAP_CALL ber_put_seq(BerElement *ber);
int LDAP_CALL ber_put_set(BerElement *ber);
int LDAP_C ber_printf(BerElement *ber, const char *fmt, ...);
int LDAP_CALL ber_flatten(BerElement *ber,
	struct berval **bvPtr);

/*
 * miscellaneous routines
 */
LDAP_API(void) LDAP_CALL ber_free(BerElement *ber, int freebuf);
LDAP_API(BerElement*) LDAP_CALL ber_alloc(void);
LDAP_API(BerElement*) LDAP_CALL der_alloc(void);
LDAP_API(BerElement*) LDAP_CALL ber_alloc_t(int options);
LDAP_API(BerElement*) LDAP_CALL ber_dup(BerElement *ber);
ber_int_t LDAP_CALL ber_read(BerElement *ber, char *buf,
	ber_len_t len);
ber_int_t LDAP_CALL ber_write(BerElement *ber, char *buf,
	ber_len_t len, int nosos);
LDAP_API(void) LDAP_CALL ber_reset(BerElement *ber, int was_writing);

#ifdef	__cplusplus
}
#endif

#endif /* _LBER_H */
