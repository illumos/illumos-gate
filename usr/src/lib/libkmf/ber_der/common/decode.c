/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 *
 * The contents of this file are subject to the Netscape Public License
 * Version 1.0 (the "NPL"); you may not use this file except in
 * compliance with the NPL.  You may obtain a copy of the NPL at
 * http://www.mozilla.org/NPL/
 *
 * Software distributed under the NPL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the NPL
 * for the specific language governing rights and limitations under the
 * NPL.
 *
 * The Initial Developer of this code under the NPL is Netscape
 * Communications Corporation.  Portions created by Netscape are
 * Copyright (C) 1998 Netscape Communications Corporation.  All Rights
 * Reserved.
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

/* decode.c - ber input decoding routines */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <strings.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

#include <ber_der.h>
#include "kmfber_int.h"

static void
ber_svecfree(char **vals)
{
	int	i;

	if (vals == NULL)
		return;
	for (i = 0; vals[i] != NULL; i++)
		free(vals[i]);
	free((char *)vals);
}

/*
 * Note: kmfber_get_tag() only uses the ber_end and ber_ptr elements of ber.
 * If that changes, the kmfber_peek_tag() and/or
 * kmfkmfber_skip_tag() implementations will need to be changed.
 */
/* return the tag - KMFBER_DEFAULT returned means trouble */
static ber_tag_t
kmfber_get_tag(BerElement *ber)
{
	unsigned char	xbyte;
	ber_tag_t	tag;
	char		*tagp;
	int		i;

	if (kmfber_read(ber, (char *)&xbyte, 1) != 1)
		return (KMFBER_DEFAULT);

	if ((xbyte & KMFBER_BIG_TAG_MASK) != KMFBER_BIG_TAG_MASK)
		return ((ber_uint_t)xbyte);

	tagp = (char *)&tag;
	tagp[0] = xbyte;
	for (i = 1; i < sizeof (ber_int_t); i++) {
		if (kmfber_read(ber, (char *)&xbyte, 1) != 1)
			return (KMFBER_DEFAULT);

		tagp[i] = xbyte;

		if (! (xbyte & KMFBER_MORE_TAG_MASK))
			break;
	}

	/* tag too big! */
	if (i == sizeof (ber_int_t))
		return (KMFBER_DEFAULT);

	/* want leading, not trailing 0's */
	return (tag >> (sizeof (ber_int_t)- i - 1));
}

/*
 * Note: kmfber_skip_tag() only uses the ber_end and ber_ptr elements of ber.
 * If that changes, the implementation of kmfber_peek_tag() will need to
 * be changed.
 */
ber_tag_t
kmfber_skip_tag(BerElement *ber, ber_len_t *len)
{
	ber_tag_t	tag;
	unsigned char	lc;
	int		noctets, diff;
	uint32_t	netlen;

	/*
	 * Any ber element looks like this: tag length contents.
	 * Assuming everything's ok, we return the tag byte (we
	 * can assume a single byte), and return the length in len.
	 *
	 * Assumptions:
	 *	1) definite lengths
	 *	2) primitive encodings used whenever possible
	 */

	/*
	 * First, we read the tag.
	 */

	if ((tag = kmfber_get_tag(ber)) == KMFBER_DEFAULT)
		return (KMFBER_DEFAULT);

	/*
	 * Next, read the length.  The first byte contains the length of
	 * the length.  If bit 8 is set, the length is the long form,
	 * otherwise it's the short form.  We don't allow a length that's
	 * greater than what we can hold in an unsigned long.
	 */

	*len = 0;
	netlen = 0;
	if (kmfber_read(ber, (char *)&lc, 1) != 1)
		return (KMFBER_DEFAULT);
	if (lc & 0x80) {
		noctets = (lc & 0x7f);
		if (noctets > sizeof (ber_uint_t))
			return (KMFBER_DEFAULT);
		diff = sizeof (ber_int_t) - noctets;
		if (kmfber_read(ber, (char *)&netlen + diff, noctets)
		    != noctets)
			return (KMFBER_DEFAULT);
		*len = ntohl(netlen);
	} else {
		*len = lc;
	}

	return (tag);
}


/*
 * Note: Previously, we passed the "ber" parameter directly to
 * kmfber_skip_tag(), saving and restoring the ber_ptr element only.
 * We now take advantage of the fact that the only ber structure
 * elements touched by kmfber_skip_tag() are ber_end and ber_ptr.
 * If that changes, this code must change too.
 */
static ber_tag_t
kmfber_peek_tag(BerElement *ber, ber_len_t *len)
{
	BerElement	bercopy;

	bercopy.ber_end = ber->ber_end;
	bercopy.ber_ptr = ber->ber_ptr;
	return (kmfber_skip_tag(&bercopy, len));
}

static int
ber_getnint(BerElement *ber, ber_int_t *num, ber_slen_t len)
{
	int i;
	ber_int_t value;
	unsigned char buffer[sizeof (ber_int_t)];
	/*
	 * The tag and length have already been stripped off.  We should
	 * be sitting right before len bytes of 2's complement integer,
	 * ready to be read straight into an int.  We may have to sign
	 * extend after we read it in.
	 */

	if (len > sizeof (ber_slen_t))
		return (-1);

	/* read into the low-order bytes of netnum */
	if (kmfber_read(ber, (char *)buffer, len) != len)
		return (-1);

	/* This sets the required sign extension */
	if (len != 0) {
		value = 0x80 & buffer[0] ? (-1) : 0;
	} else {
		value = 0;
	}

	for (i = 0; i < len; i++)
		value = (value << 8) | buffer[i];

	*num = value;

	return (len);
}

static ber_tag_t
kmfber_get_int(BerElement *ber, ber_int_t *num)
{
	ber_tag_t	tag;
	ber_len_t	len;

	if ((tag = kmfber_skip_tag(ber, &len)) == KMFBER_DEFAULT)
		return (KMFBER_DEFAULT);

	/*
	 * len is being demoted to a long here --  possible conversion error
	 */

	if (ber_getnint(ber, num, (int)len) != (ber_slen_t)len)
		return (KMFBER_DEFAULT);
	else
		return (tag);
}

static ber_tag_t
kmfber_get_stringb(BerElement *ber, char *buf, ber_len_t *len)
{
	ber_len_t	datalen;
	ber_tag_t	tag;
#ifdef STR_TRANSLATION
	char		*transbuf;
#endif /* STR_TRANSLATION */

	if ((tag = kmfber_skip_tag(ber, &datalen)) == KMFBER_DEFAULT)
		return (KMFBER_DEFAULT);
	if (datalen > (*len - 1))
		return (KMFBER_DEFAULT);

	/*
	 * datalen is being demoted to a long here --  possible conversion error
	 */

	if (kmfber_read(ber, buf, datalen) != (ber_slen_t)datalen)
		return (KMFBER_DEFAULT);

	buf[datalen] = '\0';

#ifdef STR_TRANSLATION
	if (datalen > 0 && (ber->ber_options & KMFBER_OPT_TRANSLATE_STRINGS)
	    != 0 && ber->ber_decode_translate_proc != NULL) {

		transbuf = buf;
		++datalen;
		if ((*(ber->ber_decode_translate_proc))(&transbuf, &datalen,
		    0) != 0) {
			return (KMFBER_DEFAULT);
		}
		if (datalen > *len) {
			free(transbuf);
			return (KMFBER_DEFAULT);
		}
		(void) memmove(buf, transbuf, datalen);
		free(transbuf);
		--datalen;
	}
#endif /* STR_TRANSLATION */

	*len = datalen;
	return (tag);
}

static ber_tag_t
kmfber_get_stringa(BerElement *ber, char **buf)
{
	ber_len_t	datalen;
	ber_tag_t	tag;

	if ((tag = kmfber_skip_tag(ber, &datalen)) == KMFBER_DEFAULT)
		return (KMFBER_DEFAULT);

	if ((*buf = (char *)malloc((size_t)datalen + 1)) == NULL)
		return (KMFBER_DEFAULT);

	/*
	 * datalen is being demoted to a long here --  possible conversion error
	 */
	if (kmfber_read(ber, *buf, datalen) != (ber_slen_t)datalen)
		return (KMFBER_DEFAULT);
	(*buf)[datalen] = '\0';

	return (tag);
}

ber_tag_t
ber_get_oid(BerElement *ber, struct berval *oid)
{
	ber_len_t	len;
	ber_tag_t	tag;

	if ((tag = kmfber_skip_tag(ber, &len)) != 0x06) {
		return (KMFBER_DEFAULT);
	}

	if ((oid->bv_val = (char *)malloc((size_t)len + 1)) == NULL) {
		return (KMFBER_DEFAULT);
	}
	oid->bv_len = len;

	if (kmfber_read(ber, oid->bv_val, oid->bv_len) !=
	    (ber_slen_t)oid->bv_len)
		return (KMFBER_DEFAULT);

	return (tag);
}

ber_tag_t
ber_get_bigint(BerElement *ber, struct berval **bv)
{
	ber_len_t	len;
	ber_tag_t	tag;

	if ((*bv = (struct berval *)malloc(sizeof (struct berval)))
	    == NULL) {
		return (KMFBER_DEFAULT);
	}
	(*bv)->bv_len = 0;
	(*bv)->bv_val = NULL;

	if ((tag = kmfber_skip_tag(ber, &len)) != BER_INTEGER) {
		return (KMFBER_DEFAULT);
	}

	if (((*bv)->bv_val = (char *)malloc((size_t)len + 1))
	    == NULL) {
		return (KMFBER_DEFAULT);
	}

	/*
	 * len is being demoted to a long here --  possible conversion error
	 */
	if (kmfber_read(ber, (*bv)->bv_val, len) != (ber_slen_t)len)
		return (KMFBER_DEFAULT);

	(*bv)->bv_len = len;

	/* If DER encoding, strip leading 0's */
	if (ber->ber_options & KMFBER_OPT_USE_DER) {
		char *p = (*bv)->bv_val;
		while ((*p == 0x00) && ((*bv)->bv_len > 0)) {
			p++;
			(*bv)->bv_len--;
		}
		/*
		 * Shift the buffer to the beginning of the allocated space
		 * so it can be properly freed later.
		 */
		if ((p > (*bv)->bv_val) && ((*bv)->bv_len > 0))
			(void) bcopy(p, (*bv)->bv_val, (*bv)->bv_len);
	}

	return (tag);
}

static ber_tag_t
kmfber_get_stringal(BerElement *ber, struct berval **bv)
{
	ber_len_t	len;
	ber_tag_t	tag;

	if ((*bv = (struct berval *)malloc(sizeof (struct berval)))
	    == NULL) {
		return (KMFBER_DEFAULT);
	}

	if ((tag = kmfber_skip_tag(ber, &len)) == KMFBER_DEFAULT) {
		return (KMFBER_DEFAULT);
	}

	if (((*bv)->bv_val = (char *)malloc((size_t)len + 1))
	    == NULL) {
		return (KMFBER_DEFAULT);
	}

	/*
	 * len is being demoted to a long here --  possible conversion error
	 */
	if (kmfber_read(ber, (*bv)->bv_val, len) != (ber_slen_t)len)
		return (KMFBER_DEFAULT);
	((*bv)->bv_val)[len] = '\0';
	(*bv)->bv_len = len;

	return (tag);
}

static ber_tag_t
kmfber_get_bitstringa(BerElement *ber, char **buf, ber_len_t *blen)
{
	ber_len_t	datalen;
	ber_tag_t	tag;
	unsigned char	unusedbits;

	if ((tag = kmfber_skip_tag(ber, &datalen)) == KMFBER_DEFAULT)
		return (KMFBER_DEFAULT);

	if ((*buf = (char *)malloc((size_t)datalen - 1)) == NULL)
		return (KMFBER_DEFAULT);

	if (kmfber_read(ber, (char *)&unusedbits, 1) != 1)
		return (KMFBER_DEFAULT);

	/* Subtract 1 for the unused bits */
	datalen--;

	/*
	 * datalen is being demoted to a long here --  possible conversion error
	 */
	if (kmfber_read(ber, *buf, datalen) != (ber_slen_t)datalen)
		return (KMFBER_DEFAULT);

	*blen = datalen * 8 - unusedbits;
	return (tag);
}

static ber_tag_t
kmfber_get_null(BerElement *ber)
{
	ber_len_t	len;
	ber_tag_t tag;

	if ((tag = kmfber_skip_tag(ber, &len)) == KMFBER_DEFAULT)
		return (KMFBER_DEFAULT);

	if (len != 0)
		return (KMFBER_DEFAULT);

	return (tag);
}

static ber_tag_t
kmfber_get_boolean(BerElement *ber, int *boolval)
{
	ber_int_t	longbool;
	int		rc;

	rc = kmfber_get_int(ber, &longbool);
	*boolval = longbool;

	return (rc);
}

ber_tag_t
kmfber_first_element(BerElement *ber, ber_len_t *len, char **last)
{
	/* skip the sequence header, use the len to mark where to stop */
	if (kmfber_skip_tag(ber, len) == KMFBER_DEFAULT) {
		return (KMFBER_ERROR);
	}

	*last = ber->ber_ptr + *len;

	if (*last == ber->ber_ptr) {
		return (KMFBER_END_OF_SEQORSET);
	}

	return (kmfber_peek_tag(ber, len));
}

ber_tag_t
kmfber_next_element(BerElement *ber, ber_len_t *len, char *last)
{
	if (ber->ber_ptr == last) {
		return (KMFBER_END_OF_SEQORSET);
	}

	return (kmfber_peek_tag(ber, len));
}

void
kmfber_bvfree(struct berval *bv)
{
	if (bv != NULL) {
		if (bv->bv_val != NULL) {
			free(bv->bv_val);
		}
		free((char *)bv);
	}
}

void
kmfber_bvecfree(struct berval **bv)
{
	int	i;

	if (bv != NULL) {
		for (i = 0; bv[i] != NULL; i++) {
			kmfber_bvfree(bv[i]);
		}
		free((char *)bv);
	}
}

/* VARARGS */
ber_tag_t
kmfber_scanf(BerElement *ber, const char *fmt, ...)
{
	va_list		ap;
	char		*last, *p;
	char		*s, **ss, ***sss;
	struct berval 	***bv, **bvp, *bval;
	int		*i, j;
	ber_slen_t	*l;
	ber_int_t	rc, tag, *b_int;
	ber_tag_t	*t;
	ber_len_t	len;
	size_t		array_size;

	va_start(ap, fmt);

	for (rc = 0, p = (char *)fmt; *p && rc != KMFBER_DEFAULT; p++) {
	switch (*p) {
		case 'a':	/* octet string - allocate storage as needed */
		ss = va_arg(ap, char **);
		rc = kmfber_get_stringa(ber, ss);
		break;

		case 'b':	/* boolean */
		i = va_arg(ap, int *);
		rc = kmfber_get_boolean(ber, i);
		break;

		case 'D':	/* Object ID */
		bval = va_arg(ap, struct berval *);
		rc = ber_get_oid(ber, bval);
		break;
		case 'e':	/* enumerated */
		case 'i':	/* int */
		b_int = va_arg(ap, ber_int_t *);
		rc = kmfber_get_int(ber, b_int);
		break;

		case 'l':	/* length of next item */
		l = va_arg(ap, ber_slen_t *);
		rc = kmfber_peek_tag(ber, (ber_len_t *)l);
		break;

		case 'n':	/* null */
		rc = kmfber_get_null(ber);
		break;

		case 's':	/* octet string - in a buffer */
		s = va_arg(ap, char *);
		l = va_arg(ap, ber_slen_t *);
		rc = kmfber_get_stringb(ber, s, (ber_len_t *)l);
		break;

		case 'o':	/* octet string in a supplied berval */
		bval = va_arg(ap, struct berval *);
		(void) kmfber_peek_tag(ber, &bval->bv_len);
		rc = kmfber_get_stringa(ber, &bval->bv_val);
		break;

		case 'I': /* variable length Integer */
		/* Treat INTEGER same as an OCTET string, but ignore the tag */
		bvp = va_arg(ap, struct berval **);
		rc = ber_get_bigint(ber, bvp);
		break;
		case 'O': /* octet string - allocate & include length */
		bvp = va_arg(ap, struct berval **);
		rc = kmfber_get_stringal(ber, bvp);
		break;

		case 'B':	/* bit string - allocate storage as needed */
		ss = va_arg(ap, char **);
		l = va_arg(ap, ber_slen_t *); /* for length, in bits */
		rc = kmfber_get_bitstringa(ber, ss, (ber_len_t *)l);
		break;

		case 't':	/* tag of next item */
		t = va_arg(ap, ber_tag_t *);
		*t = kmfber_peek_tag(ber, &len);
		rc = (ber_int_t)(*t);
		break;

		case 'T':	/* skip tag of next item */
		t = va_arg(ap, ber_tag_t *);
		*t = kmfber_skip_tag(ber, &len);
		rc = (ber_int_t)(*t);
		break;

		case 'v':	/* sequence of strings */
		sss = va_arg(ap, char ***);
		if (sss == NULL)
			break;
		*sss = NULL;
		j = 0;
		array_size = 0;
		for (tag = kmfber_first_element(ber, &len, &last);
		    (tag != KMFBER_DEFAULT &&
		    tag != KMFBER_END_OF_SEQORSET &&
		    rc != KMFBER_DEFAULT);
		    tag = kmfber_next_element(ber, &len, last)) {
			if (*sss == NULL) {
				/* Make room for at least 15 strings */
				*sss = (char **)malloc(16 * sizeof (char *));
				array_size = 16;
			} else {
				if ((size_t)(j+2) > array_size) {
					/* We'v overflowed our buffer */
					*sss = (char **)realloc(*sss,
					    (array_size * 2) * sizeof (char *));
					array_size = array_size * 2;
				}
			}
			rc = kmfber_get_stringa(ber, &((*sss)[j]));
			j++;
		}
		if (rc != KMFBER_DEFAULT && tag != KMFBER_END_OF_SEQORSET) {
			rc = KMFBER_DEFAULT;
		}
		if (j > 0)
			(*sss)[j] = NULL;
		break;

		case 'V':	/* sequence of strings + lengths */
		bv = va_arg(ap, struct berval ***);
		*bv = NULL;
		j = 0;
		for (tag = kmfber_first_element(ber, &len, &last);
		    (tag != KMFBER_DEFAULT &&
		    tag != KMFBER_END_OF_SEQORSET &&
		    rc != KMFBER_DEFAULT);
		    tag = kmfber_next_element(ber, &len, last)) {
			if (*bv == NULL) {
				*bv = (struct berval **)malloc(
				    2 * sizeof (struct berval *));
			} else {
				*bv = (struct berval **)realloc(*bv,
				    (j + 2) * sizeof (struct berval *));
			}
			rc = kmfber_get_stringal(ber, &((*bv)[j]));
			j++;
		}
		if (rc != KMFBER_DEFAULT &&
		    tag != KMFBER_END_OF_SEQORSET) {
			rc = KMFBER_DEFAULT;
		}
		if (j > 0)
			(*bv)[j] = NULL;
		break;

		case 'x':	/* skip the next element - whatever it is */
		if ((rc = kmfber_skip_tag(ber, &len)) == KMFBER_DEFAULT)
			break;
		ber->ber_ptr += len;
		break;

		case '{':	/* begin sequence */
		case '[':	/* begin set */
		if (*(p + 1) != 'v' && *(p + 1) != 'V')
			rc = kmfber_skip_tag(ber, &len);
		break;

		case '}':	/* end sequence */
		case ']':	/* end set */
		break;

		default:
		rc = KMFBER_DEFAULT;
		break;
		}
	}


	va_end(ap);
	if (rc == KMFBER_DEFAULT) {
	va_start(ap, fmt);
	for (p--; fmt < p && *fmt; fmt++) {
		switch (*fmt) {
		case 'a':	/* octet string - allocate storage as needed */
			ss = va_arg(ap, char **);
			if (ss != NULL && *ss != NULL) {
				free(*ss);
				*ss = NULL;
			}
			break;

		case 'b':	/* boolean */
			i = va_arg(ap, int *);
			break;

		case 'e':	/* enumerated */
		case 'i':	/* int */
			l = va_arg(ap, ber_slen_t *);
			break;

		case 'l':	/* length of next item */
			l = va_arg(ap, ber_slen_t *);
			break;

		case 'n':	/* null */
			break;

		case 's':	/* octet string - in a buffer */
			s = va_arg(ap, char *);
			l = va_arg(ap, ber_slen_t *);
			break;

		case 'o':	/* octet string in a supplied berval */
			bval = va_arg(ap, struct berval *);
			if (bval->bv_val) free(bval->bv_val);
			(void) memset(bval, 0, sizeof (struct berval));
			break;

		case 'O':	/* octet string - allocate & include length */
			bvp = va_arg(ap, struct berval **);
			kmfber_bvfree(*bvp);
			bvp = NULL;
			break;

		case 'B':	/* bit string - allocate storage as needed */
			ss = va_arg(ap, char **);
			l = va_arg(ap, ber_slen_t *); /* for length, in bits */
			if (ss != NULL && *ss != NULL) {
				free(*ss);
				*ss = NULL;
			}
			break;

		case 't':	/* tag of next item */
			t = va_arg(ap, ber_tag_t *);
			break;
		case 'T':	/* skip tag of next item */
			t = va_arg(ap, ber_tag_t *);
			break;

		case 'v':	/* sequence of strings */
			sss = va_arg(ap, char ***);
			if (sss != NULL && *sss != NULL) {
				ber_svecfree(*sss);
				*sss = NULL;
			}
			break;

		case 'V':	/* sequence of strings + lengths */
			bv = va_arg(ap, struct berval ***);
			kmfber_bvecfree(*bv);
			*bv = NULL;
			break;

		case 'x':	/* skip the next element - whatever it is */
			break;

		case '{':	/* begin sequence */
		case '[':	/* begin set */
			break;

		case '}':	/* end sequence */
		case ']':	/* end set */
			break;

		default:
			break;
		}
	} /* for */
	va_end(ap);
	} /* if */

	return (rc);
}

struct berval *
kmfber_bvdup(const struct berval *bv)
{
	struct berval	*new;

	if ((new = (struct berval *)malloc(sizeof (struct berval)))
	    == NULL) {
		return (NULL);
	}
	if (bv->bv_val == NULL) {
		new->bv_val = NULL;
		new->bv_len = 0;
	} else {
		if ((new->bv_val = (char *)malloc(bv->bv_len + 1))
		    == NULL) {
			return (NULL);
		}
		(void) memmove(new->bv_val, bv->bv_val, (size_t)bv->bv_len);
		new->bv_val[bv->bv_len] = '\0';
		new->bv_len = bv->bv_len;
	}

	return (new);
}
