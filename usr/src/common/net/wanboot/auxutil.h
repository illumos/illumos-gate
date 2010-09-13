/*
 * Copyright 2002, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_AUXUTIL_H
#define	_AUXUTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#undef	NULL
#define	NULL ((void *) 0)

ASN1_BMPSTRING *asc2bmpstring(const char *, int);

uchar_t *utf82ascstr(ASN1_UTF8STRING *);

int set_results(STACK_OF(EVP_PKEY) **, STACK_OF(EVP_PKEY) **, STACK_OF(X509) **,
    STACK_OF(X509) **, STACK_OF(X509) **, STACK_OF(X509) **,
    STACK_OF(EVP_PKEY) **, STACK_OF(EVP_PKEY) **);

int find_attr(int, ASN1_STRING *, STACK_OF(EVP_PKEY) *, EVP_PKEY **,
    STACK_OF(X509) *, X509 **);

int find_attr_by_nid(STACK_OF(X509_ATTRIBUTE) *, int);

int get_key_cert(int, STACK_OF(EVP_PKEY) *, EVP_PKEY **, STACK_OF(X509) *,
    X509 **);

X509_ATTRIBUTE *type2attrib(ASN1_TYPE *, int);

ASN1_TYPE *attrib2type(X509_ATTRIBUTE *);

int move_certs(STACK_OF(X509) *, STACK_OF(X509) *);

int print_time(FILE *, ASN1_TIME *);


#ifdef	__cplusplus
}
#endif

#endif	/* _AUXUTIL_H */
