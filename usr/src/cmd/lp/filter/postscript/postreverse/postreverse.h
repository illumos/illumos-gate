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
 * Copyright (c) 1993-2001 by Sun Microsystems, Inc.
 *	All Rights Reserved
 */

#ident	"%Z%%M%	%I%	%E% SMI"

/**
 * Structures and definitions needed for PostScript page manipulation
 **/
#if !defined(_POSTREVERSE_H)
#define _POSTREVERSE_H

/* PS DSC comments of interest */
#define PS_PAGE		"\n%%Page:"
#define PS_TRAILER	"\n%%Trailer"
#define PS_BEGIN_GLOBAL	"\n%%BeginGlobal"
#define PS_END_GLOBAL	"\n%%EndGlobal"

#define	BLOCKSIZE	10

struct _global {
  caddr_t start;
  size_t size;
};
typedef struct _global GLOBAL;

struct _page {
  unsigned int number;
  char *label;
  caddr_t start;
  size_t size;
};
typedef struct _page PAGE;

struct _header {
  char *label;
  caddr_t start;
  size_t size;
};
typedef struct _header HEADER;

struct _trailer {
  char *label;
  caddr_t start;
  size_t size;
};
typedef struct _trailer TRAILER;

struct _document {
  char *name;
  caddr_t start;
  size_t size;
  HEADER *header;
  PAGE **page;
  GLOBAL **global;
  long pages;
  TRAILER *trailer;
};
typedef struct _document DOCUMENT;

#endif /* _POSTREVERSE_H */
