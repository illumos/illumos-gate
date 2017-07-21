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
 *  nl_types.h
 *
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright (c) 1991,1997,2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	All Rights Reserved	*/

#ifndef	_NL_TYPES_H
#define	_NL_TYPES_H

#include <sys/isa_defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	NL_SETD			1    /* XPG3 Conformant Default set number. */
#define	NL_CAT_LOCALE		(-1) /* XPG4 requirement */

#define	_CAT_MAGIC		0xFF88FF89
#define	_CAT_HDR_SIZE		sizeof (struct _cat_hdr)
#define	_CAT_SET_HDR_SIZE	sizeof (struct _cat_set_hdr)
#define	_CAT_MSG_HDR_SIZE	sizeof (struct _cat_msg_hdr)

struct _cat_hdr
{
#if	!defined(_LP64)
	long __hdr_magic;		/* must contain CAT_MAGIC */
#else
	int	__hdr_magic;		/* must contain CAT_MAGIC */
#endif
	int __nsets;		/* the number of sets in the catalogue */
	int __mem;		/* the size of the catalogue; the size	   */
				/* does not include the size of the header */
#if	!defined(_LP64)
	long __msg_hdr_offset;	/* the byte offset of the first message */
				/* header */
	long __msg_text_offset;	/* the byte offset of the message text area */
#else
	int __msg_hdr_offset;	/* the byte offset of the first message */
				/* header */
	int __msg_text_offset;	/* the byte offset of the message text area */
#endif
};

struct _cat_set_hdr
{
	int __set_no;	/* the set number; must be greater than 0;   */
			/* should be less than or equal to NL_SETMAX */
	int __nmsgs;	/* the number of msgs in the set */
	int __first_msg_hdr;	/* the index of the first message header in */
				/* the set; the value is not a byte offset, */
				/* it is a 0-based index		    */
};

struct _cat_msg_hdr
{
	int __msg_no;	/* the message number; must be greater than 0; */
			/* should be less than or equal to NL_MSGMAX   */
	int __msg_len;	/* the length of the message; must be greater */
			/* than or equal to zero; should be less than */
			/* or equal to NL_TEXTMAX */
	int __msg_offset; /* the byte offset of the message in the message */
			/* area; the offset is relative to the start of  */
			/* the message area, not to the start of the	 */
			/* catalogue.					 */
};

struct _nl_catd_struct {
	void	*__content;	/* mmaped catalogue contents */
	int	__size;		/* Size of catalogue file */
	int	__trust;	/* File is from a trusted location */
};

typedef struct _nl_catd_struct *nl_catd;
typedef int nl_item;	/* XPG3 Conformant for nl_langinfo(). */

/* The following is just for the compatibility between OSF and Solaris */
/* Need to be removed later */
typedef	nl_item	__nl_item;

int	catclose(nl_catd);
char	*catgets(nl_catd, int, int, const char *);
nl_catd catopen(const char *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _NL_TYPES_H */
