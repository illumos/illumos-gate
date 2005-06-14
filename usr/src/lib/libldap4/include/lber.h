/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#ifndef _LBER_H
#define	_LBER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(NEEDPROTOS) && defined(__STDC__)
#define	NEEDPROTOS	1
#endif

/* BER classes and mask */
#define	LBER_CLASS_UNIVERSAL	0x00
#define	LBER_CLASS_APPLICATION	0x40
#define	LBER_CLASS_CONTEXT	0x80
#define	LBER_CLASS_PRIVATE	0xc0
#define	LBER_CLASS_MASK		0xc0

/* BER encoding type and mask */
#define	LBER_PRIMITIVE		0x00
#define	LBER_CONSTRUCTED	0x20
#define	LBER_ENCODING_MASK	0x20

#define	LBER_BIG_TAG_MASK	0x1f
#define	LBER_MORE_TAG_MASK	0x80

/*
 * Note that LBER_ERROR and LBER_DEFAULT are values that can never appear
 * as valid BER tags, and so it is safe to use them to report errors.  In
 * fact, any tag for which the following is true is invalid:
 *     (( tag & 0x00000080 ) != 0 ) && (( tag & 0xFFFFFF00 ) != 0 )
 */
#define	LBER_ERROR		0xffffffff
#define	LBER_DEFAULT		0xffffffff

/* general BER types we know about */
#define	LBER_BOOLEAN		0x01
#define	LBER_INTEGER		0x02
#define	LBER_BITSTRING		0x03
#define	LBER_OCTETSTRING	0x04
#define	LBER_NULL		0x05
#define	LBER_ENUMERATED		0x0a
#define	LBER_SEQUENCE		0x30	/* constructed */
#define	LBER_SET		0x31	/* constructed */

#define	OLD_LBER_SEQUENCE	0x10	/* w/o constructed bit - broken */
#define	OLD_LBER_SET		0x11	/* w/o constructed bit - broken */

#ifdef NEEDPROTOS
typedef int (*BERTranslateProc)(char **bufp, unsigned int *buflenp,
	int free_input);
#else /* NEEDPROTOS */
typedef int (*BERTranslateProc)();
#endif /* NEEDPROTOS */

typedef struct berelement BerElement; /* Opaque BerElement structure */
#define	NULLBER ((BerElement *) 0)

#ifdef LDAP_SSL
#include <security/ssl.h>
#endif /* LDAP_SSL */

/*
 * Structure Sockbuf which used to be defined in this header file, is
 * removed since the c-api draft does not define the structure and it
 * is only used internal to the library
 */

typedef struct seqorset {
	BerElement	*sos_ber;
	unsigned int	sos_clen;
	unsigned int	sos_tag;
	char		*sos_first;
	char		*sos_ptr;
	struct seqorset	*sos_next;
} Seqorset;
#define	NULLSEQORSET	((Seqorset *) 0)

typedef unsigned int	ber_len_t;   /* for BER len */
typedef unsigned int	ber_tag_t;   /* for BER tags */
typedef int		ber_int_t;   /* for BER ints, enums, and Booleans */
typedef unsigned int	ber_uint_t; /* unsigned equivalent of ber_int_t */
typedef int		ber_slen_t; /* signed equivalent of ber_len_t */

/* structure for returning a sequence of octet strings + length */
typedef struct berval {
	ber_len_t	bv_len;
	char		*bv_val;
} BerValue;

#ifndef NEEDPROTOS
extern BerElement *ber_alloc();
extern BerElement *der_alloc();
extern BerElement *ber_alloc_t();
extern BerElement *ber_dup();
extern BerElement *ber_init();
extern int lber_debug;
extern void ber_bvfree();
extern void ber_bvecfree();
extern struct berval *ber_bvdup();
extern void ber_dump();
extern void ber_sos_dump();
extern void lber_bprint();
extern void ber_reset();
extern void ber_zero_init();
#else /* NEEDPROTOS */

/*
 * in bprint.c:
 */
void lber_bprint(char *data, int len);

/*
 * in decode.c:
 */
ber_tag_t ber_get_tag(BerElement *ber);
ber_tag_t ber_skip_tag(BerElement *ber, ber_len_t *len);
ber_tag_t ber_peek_tag(BerElement *ber, ber_len_t *len);
unsigned int ber_get_int(BerElement *ber, int *num);
unsigned int ber_get_stringb(BerElement *ber, char *buf,
	ber_len_t *len);
unsigned int ber_get_stringa(BerElement *ber, char **buf);
unsigned int ber_get_stringal(BerElement *ber, struct berval **bv);
unsigned int ber_get_bitstringa(BerElement *ber, char **buf,
	ber_len_t *len);
unsigned int ber_get_null(BerElement *ber);
unsigned int ber_get_boolean(BerElement *ber, int *boolval);
ber_tag_t ber_first_element(BerElement *ber, ber_len_t *len,
	char **last);
ber_tag_t ber_next_element(BerElement *ber, ber_len_t *len,
	char *last);
#if defined(MACOS) || defined(BC31) || defined(_WIN32) || defined(__sun)
ber_tag_t ber_scanf(BerElement *ber, char *fmt, ...);
#else
ber_tag_t ber_scanf();
#endif
void ber_bvfree(struct berval *bv);
void ber_bvecfree(struct berval **bv);
struct berval *ber_bvdup(struct berval *bv);
#ifdef STR_TRANSLATION
void ber_set_string_translators(BerElement *ber,
	BERTranslateProc encode_proc, BERTranslateProc decode_proc);
#endif /* STR_TRANSLATION */
int ber_flatten(BerElement *ber, struct berval **bvPtr);

/*
 * in encode.c
 */
int ber_put_enum(BerElement *ber, int num, ber_tag_t tag);
int ber_put_int(BerElement *ber, int num, ber_tag_t tag);
int ber_put_ostring(BerElement *ber, char *str, ber_len_t len, ber_tag_t tag);
int ber_put_string(BerElement *ber, char *str, ber_tag_t tag);
int ber_put_bitstring(BerElement *ber, char *str,
	unsigned int bitlen, ber_tag_t tag);
int ber_put_null(BerElement *ber, ber_tag_t tag);
int ber_put_boolean(BerElement *ber, int boolval, ber_tag_t tag);
int ber_start_seq(BerElement *ber, ber_tag_t tag);
int ber_start_set(BerElement *ber, ber_tag_t tag);
int ber_put_seq(BerElement *ber);
int ber_put_set(BerElement *ber);
#if defined(MACOS) || defined(BC31) || defined(_WIN32) || defined(__sun)
int ber_printf(BerElement *ber, char *fmt, ...);
#else
int ber_printf();
#endif

/*
 * in io.c:
 *
 * ber_flush() and ber_get_next() functions are obsolete and removed
 * from this library/header file
 */
int ber_read(BerElement *ber, char *buf, ber_len_t len);
int ber_write(BerElement *ber, char *buf, ber_len_t len, int nosos);
void ber_free(BerElement *ber, int freebuf);
BerElement *ber_alloc(void);
BerElement *der_alloc(void);
BerElement *ber_alloc_t(int options);
BerElement *ber_dup(BerElement *ber);
BerElement *ber_init(struct berval *bv);
void ber_dump(BerElement *ber, int inout);
void ber_sos_dump(Seqorset *sos);
void ber_zero_init(BerElement *ber, int options);
void ber_reset(BerElement *ber, int was_writing);

#ifdef NEEDGETOPT
/*
 * in getopt.c
 */
int getopt(int nargc, char **nargv, char *ostr);
#endif /* NEEDGETOPT */
#endif /* NEEDPROTOS */

#define	LBER_HTONL(l) htonl(l)
#define	LBER_NTOHL(l) ntohl(l)

/*
 * SAFEMEMCPY is an overlap-safe copy from s to d of n bytes
 */
#ifdef sunos4
#define	SAFEMEMCPY(d, s, n)	bcopy(s, d, n)
#else /* sunos4 */
#define	SAFEMEMCPY(d, s, n)	memmove(d, s, n)
#endif /* sunos4 */

#ifdef SUN

/* I18N support */
#include <locale.h>
#include <nl_types.h>

extern	nl_catd	slapdcat;		/* for I18N support */
extern void i18n_catopen(char *);

#endif

#ifdef __cplusplus
}
#endif

#endif /* _LBER_H */
