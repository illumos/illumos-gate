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
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <ber_der.h>
#include "kmfber_int.h"

#define	EXBUFSIZ	1024

/*
 * Note: kmfber_read() only uses the ber_end and ber_ptr elements of ber.
 * Functions like kmfber_get_tag(), kmfber_skip_tag, and kmfber_peek_tag()
 * rely on that fact, so if this code is changed to use any additional
 * elements of the ber structure, those functions will need to be changed
 * as well.
 */
ber_int_t
kmfber_read(BerElement *ber, char *buf, ber_len_t len)
{
	size_t	actuallen;
	size_t	nleft;

	nleft = ber->ber_end - ber->ber_ptr;
	actuallen = nleft < len ? nleft : len;

	(void) memmove(buf, ber->ber_ptr, (size_t)actuallen);

	ber->ber_ptr += actuallen;

	return ((ber_int_t)actuallen);
}

/*
 * enlarge the ber buffer.
 * return 0 on success, -1 on error.
 */
int
kmfber_realloc(BerElement *ber, ber_len_t len)
{
	ber_uint_t	need, have, total;
	size_t		have_bytes;
	Seqorset	*s;
	size_t		off;
	char		*oldbuf;

	have_bytes = ber->ber_end - ber->ber_buf;
	have = have_bytes / EXBUFSIZ;
	need = (len < EXBUFSIZ ? 1 : (len + (EXBUFSIZ - 1)) / EXBUFSIZ);
	total = have * EXBUFSIZ + need * EXBUFSIZ;

	oldbuf = ber->ber_buf;

	if (ber->ber_buf == NULL) {
		if ((ber->ber_buf = (char *)malloc((size_t)total))
		    == NULL) {
			return (-1);
		}
		ber->ber_flags &= ~KMFBER_FLAG_NO_FREE_BUFFER;
	} else {
		if (ber->ber_flags & KMFBER_FLAG_NO_FREE_BUFFER) {
			/* transition to malloc'd buffer */
			if ((ber->ber_buf = (char *)malloc(
			    (size_t)total)) == NULL) {
				return (-1);
			}
			ber->ber_flags &= ~KMFBER_FLAG_NO_FREE_BUFFER;

			/* copy existing data into new malloc'd buffer */
			(void) memmove(ber->ber_buf, oldbuf, have_bytes);
		} else {
			if ((ber->ber_buf = (char *)realloc(
			    oldbuf, (size_t)total)) == NULL) {
				free(oldbuf);
				return (-1);
			}
		}
	}

	ber->ber_end = ber->ber_buf + total;

	/*
	 * If the stinking thing was moved, we need to go through and
	 * reset all the sos and ber pointers.  Offsets would've been
	 * a better idea... oh well.
	 */
	if (ber->ber_buf != oldbuf) {
		ber->ber_ptr = ber->ber_buf + (ber->ber_ptr - oldbuf);

		for (s = ber->ber_sos; s != NULLSEQORSET; s = s->sos_next) {
			off = s->sos_first - oldbuf;
			s->sos_first = ber->ber_buf + off;

			off = s->sos_ptr - oldbuf;
			s->sos_ptr = ber->ber_buf + off;
		}
	}

	return (0);
}

/*
 * returns "len" on success and -1 on failure.
 */
ber_int_t
kmfber_write(BerElement *ber, char *buf, ber_len_t len, int nosos)
{
	if (nosos || ber->ber_sos == NULL) {
		if (ber->ber_ptr + len > ber->ber_end) {
			if (kmfber_realloc(ber, len) != 0)
				return (-1);
		}
		(void) memmove(ber->ber_ptr, buf, (size_t)len);
		ber->ber_ptr += len;
		return (len);
	} else {
		if (ber->ber_sos->sos_ptr + len > ber->ber_end) {
			if (kmfber_realloc(ber, len) != 0)
				return (-1);
		}
		(void) memmove(ber->ber_sos->sos_ptr, buf, (size_t)len);
		ber->ber_sos->sos_ptr += len;
		ber->ber_sos->sos_clen += len;
		return (len);
	}
}

void
kmfber_free(BerElement *ber, int freebuf)
{
	if (ber != NULL) {
		if (freebuf &&
		    !(ber->ber_flags & KMFBER_FLAG_NO_FREE_BUFFER))
			free(ber->ber_buf);
		free((char *)ber);
	}
}

/* we pre-allocate a buffer to save the extra malloc later */
BerElement *
kmfber_alloc_t(int options)
{
	BerElement	*ber;

	if ((ber = (BerElement*)calloc(1,
	    sizeof (struct berelement) + EXBUFSIZ)) == NULL) {
		return (NULL);
	}

	ber->ber_tag = KMFBER_DEFAULT;
	ber->ber_options = options;
	ber->ber_buf = (char *)ber + sizeof (struct berelement);
	ber->ber_ptr = ber->ber_buf;
	ber->ber_end = ber->ber_buf + EXBUFSIZ;
	ber->ber_flags = KMFBER_FLAG_NO_FREE_BUFFER;

	return (ber);
}


BerElement *
kmfber_alloc()
{
	return (kmfber_alloc_t(0));
}

BerElement *
kmfder_alloc()
{
	return (kmfber_alloc_t(KMFBER_OPT_USE_DER));
}

BerElement *
kmfber_dup(BerElement *ber)
{
	BerElement	*new;

	if ((new = kmfber_alloc()) == NULL)
		return (NULL);

	*new = *ber;

	return (new);
}


void
ber_init_w_nullchar(BerElement *ber, int options)
{
	(void) memset((char *)ber, '\0', sizeof (struct berelement));
	ber->ber_tag = KMFBER_DEFAULT;

	ber->ber_options = options;
}


void
kmfber_reset(BerElement *ber, int was_writing)
{
	if (was_writing) {
		ber->ber_end = ber->ber_ptr;
		ber->ber_ptr = ber->ber_buf;
	} else {
		ber->ber_ptr = ber->ber_end;
	}

	ber->ber_rwptr = NULL;
}


#ifdef KMFBER_DEBUG

void
ber_dump(BerElement *ber, int inout)
{
	char msg[128];
	sprintf(msg, "ber_dump: buf 0x%lx, ptr 0x%lx, rwptr 0x%lx, end 0x%lx\n",
	    ber->ber_buf, ber->ber_ptr, ber->ber_rwptr, ber->ber_end);
	ber_err_print(msg);
	if (inout == 1) {
		sprintf(msg, "          current len %ld, contents:\n",
		    ber->ber_end - ber->ber_ptr);
		ber_err_print(msg);
		lber_bprint(ber->ber_ptr, ber->ber_end - ber->ber_ptr);
	} else {
		sprintf(msg, "          current len %ld, contents:\n",
		    ber->ber_ptr - ber->ber_buf);
		ber_err_print(msg);
		lber_bprint(ber->ber_buf, ber->ber_ptr - ber->ber_buf);
	}
}

void
ber_sos_dump(Seqorset *sos)
{
	char msg[80];
	ber_err_print("*** sos dump ***\n");
	while (sos != NULLSEQORSET) {
		sprintf(msg, "ber_sos_dump: clen %ld first 0x%lx ptr 0x%lx\n",
		    sos->sos_clen, sos->sos_first, sos->sos_ptr);
		ber_err_print(msg);
		sprintf(msg, "              current len %ld contents:\n",
		    sos->sos_ptr - sos->sos_first);
		ber_err_print(msg);
		lber_bprint(sos->sos_first, sos->sos_ptr - sos->sos_first);

		sos = sos->sos_next;
	}
	ber_err_print("*** end dump ***\n");
}

#endif

/* new dboreham code below: */
struct byte_buffer  {
	unsigned char *p;
	int offset;
	int length;
};
typedef struct byte_buffer byte_buffer;

/*
 * The kmfber_flatten routine allocates a struct berval whose contents
 * are a BER encoding taken from the ber argument. The bvPtr pointer
 * points to the returned berval, which must be freed using
 * kmfber_bvfree().  This routine returns 0 on success and -1 on error.
 * The use of kmfber_flatten on a BerElement in which all '{' and '}'
 * format modifiers have not been properly matched can result in a
 * berval whose contents are not a valid BER encoding.
 * Note that the ber_ptr is not modified.
 */
int
kmfber_flatten(BerElement *ber, struct berval **bvPtr)
{
	struct berval *new;
	ber_len_t len;

	/* allocate a struct berval */
	new = (struct berval *)malloc((size_t)(sizeof (struct berval)));
	if (new == NULL) {
		return (-1);
	}
	(void) memset(new, 0, sizeof (struct berval));

	/*
	 * Copy everything from the BerElement's ber_buf to ber_ptr
	 * into the berval structure.
	 */
	if (ber == NULL) {
		new->bv_val = NULL;
		new->bv_len = 0;
	} else {
		len = ber->ber_ptr - ber->ber_buf;
		new->bv_val = (char *)malloc((size_t)(len + 1));
		if (new->bv_val == NULL) {
			kmfber_bvfree(new);
			return (-1);
		}
		(void) memmove(new->bv_val, ber->ber_buf, (size_t)len);
		new->bv_val[len] = '\0';
		new->bv_len = len;
	}

	/* set bvPtr pointer to point to the returned berval */
	*bvPtr = new;

	return (0);
}

BerElement *
kmfder_init(const struct berval *bv)
{
	BerElement *ber;

	/* construct BerElement */
	if ((ber = kmfber_alloc_t(KMFBER_OPT_USE_DER)) != NULL) {
		/* copy data from the bv argument into BerElement */
		/* XXXmcs: had to cast unsigned long bv_len to long */
		if ((kmfber_write(ber, bv->bv_val, bv->bv_len, 0)) !=
		    (ber_slen_t)bv->bv_len) {
			kmfber_free(ber, 1);
			return (NULL);
		}
	}
	/*
	 * reset ber_ptr back to the beginning of buffer so that this new
	 * and initialized ber element can be READ
	 */
	kmfber_reset(ber, 1);

	/*
	 * return a ptr to a new BerElement containing a copy of the data
	 * in the bv argument or a null pointer on error
	 */
	return (ber);
}

BerElement *
kmfber_init(const struct berval *bv)
{
	BerElement *ber;

	/* construct BerElement */
	if ((ber = kmfber_alloc_t(0)) != NULL) {
		/* copy data from the bv argument into BerElement */
		/* XXXmcs: had to cast unsigned long bv_len to long */
		if ((kmfber_write(ber, bv->bv_val, bv->bv_len, 0)) !=
		    (ber_slen_t)bv->bv_len) {
			kmfber_free(ber, 1);
			return (NULL);
		}
	}
	/*
	 * reset ber_ptr back to the beginning of buffer so that this new
	 * and initialized ber element can be READ
	 */
	kmfber_reset(ber, 1);

	/*
	 * return a ptr to a new BerElement containing a copy of the data
	 * in the bv argument or a null pointer on error
	 */
	return (ber);
}
