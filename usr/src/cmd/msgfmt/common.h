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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_COMMON_H
#define	_COMMON_H

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <libintl.h>
#include <stdlib.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* implementation dependent default domain name */
#define	DEFAULT_DOMAIN	"messages"
#define	DEFAULT_DOMAIN_MO	"messages.mo"

#define	ERR_ERROR \
	"ERROR: "

#define	WARN_WARNING \
	"WARNING: "

#define	ERR_MALLOC \
	"failed to allocate memory\n"

#define	ERR_OPEN_FAILED \
	"Cannot open file %s.\n"

#define	ERR_READ_FAILED \
	"Error in reading %s.\n"

#define	DIAG_START_PROC \
	"Processing file \"%s\"...\n"

struct flags {
	char	*idir;
	char	*ofile;
	int	fuzzy;
	int	verbose;
	int	strict;
	int	gnu_p;
	int	sun_p;
};

extern int	parse_option(int *, char ***, struct flags *);

extern void	error(char *, ...) __NORETURN;
extern void	warning(char *, ...);
extern void	diag(char *, ...);
extern void *Xmalloc(size_t);
extern void *Xcalloc(size_t, size_t);
extern void *Xrealloc(void *, size_t);
extern char *Xstrdup(const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _COMMON_H */
