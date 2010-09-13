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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SALIB_H
#define	_SYS_SALIB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/memlist.h>

/*
 * This header file contains most of the libc-like interfaces exported by
 * standalone's "libsa" library, and a few other odds and ends (witness the
 * externs below).  This file should *only* be included from code that is
 * built *exclusively* for use in the standalone environment.  Even then, it's
 * perfectly acceptable to instead just use the traditional libc names for
 * #include files (as we do below), since all standalone code is built against
 * an alternate set of C headers (located under $SRC/stand/lib/sa).
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <libintl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern void init_boot_time(void);
extern void *bkmem_alloc(size_t);
extern void *bkmem_zalloc(size_t);
extern void bkmem_free(void *, size_t);

/* memlist.c */
extern caddr_t tablep;
extern void print_memlist(struct memlist *);
extern void *getlink(uint_t);
extern struct memlist *get_memlist_struct(void);
extern void add_to_freelist(struct memlist *);

/* standalloc.c */
extern caddr_t kern_resalloc(caddr_t, size_t, int);
extern void kern_resfree(caddr_t, size_t);
extern int get_progmemory(caddr_t, size_t, int);

#ifdef __sparc
/* prom_misc.c */
enum encode_how	{ ENCODE_BYTES, ENCODE_STRING };
extern void	prom_create_encoded_prop(char *, void *, int, enum encode_how);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SALIB_H */
