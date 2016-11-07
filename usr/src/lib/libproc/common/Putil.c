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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <limits.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>

#include "Pcontrol.h"
#include "Putil.h"

/*
 * Place the new element on the list prior to the existing element.
 */
void
list_link(void *new, void *existing)
{
	plist_t *p = new;
	plist_t *q = existing;

	if (q) {
		p->list_forw = q;
		p->list_back = q->list_back;
		q->list_back->list_forw = p;
		q->list_back = p;
	} else {
		p->list_forw = p->list_back = p;
	}
}

/*
 * Unchain the specified element from a list.
 */
void
list_unlink(void *old)
{
	plist_t *p = old;

	if (p->list_forw != p) {
		p->list_back->list_forw = p->list_forw;
		p->list_forw->list_back = p->list_back;
	}
	p->list_forw = p->list_back = p;
}

/*
 * Routines to manipulate sigset_t, fltset_t, or sysset_t.  These routines
 * are provided as equivalents for the <sys/procfs.h> macros prfillset,
 * premptyset, praddset, and prdelset.  These functions are preferable
 * because they are not macros which rely on using sizeof (*sp), and thus
 * can be used to create common code to manipulate event sets.  The set
 * size must be passed explicitly, e.g. : prset_fill(&set, sizeof (set));
 */
void
prset_fill(void *sp, size_t size)
{
	size_t i = size / sizeof (uint32_t);

	while (i != 0)
		((uint32_t *)sp)[--i] = (uint32_t)0xFFFFFFFF;
}

void
prset_empty(void *sp, size_t size)
{
	size_t i = size / sizeof (uint32_t);

	while (i != 0)
		((uint32_t *)sp)[--i] = (uint32_t)0;
}

void
prset_add(void *sp, size_t size, uint_t flag)
{
	if (flag - 1 < 32 * size / sizeof (uint32_t))
		((uint32_t *)sp)[(flag - 1) / 32] |= 1U << ((flag - 1) % 32);
}

void
prset_del(void *sp, size_t size, uint_t flag)
{
	if (flag - 1 < 32 * size / sizeof (uint32_t))
		((uint32_t *)sp)[(flag - 1) / 32] &= ~(1U << ((flag - 1) % 32));
}

int
prset_ismember(void *sp, size_t size, uint_t flag)
{
	return ((flag - 1 < 32 * size / sizeof (uint32_t)) &&
	    (((uint32_t *)sp)[(flag - 1) / 32] & (1U << ((flag - 1) % 32))));
}

/*
 * If _libproc_debug is set, printf the debug message to stderr
 * with an appropriate prefix.
 */
/*PRINTFLIKE1*/
void
dprintf(const char *format, ...)
{
	if (_libproc_debug) {
		va_list alist;

		va_start(alist, format);
		(void) fputs("libproc DEBUG: ", stderr);
		(void) vfprintf(stderr, format, alist);
		va_end(alist);
	}
}

/*
 * Printf-style error reporting function.  This is used to supplement the error
 * return codes from various libproc functions with additional text.  Since we
 * are a library, and should not be spewing messages to stderr, we provide a
 * default version of this function that does nothing, but by calling this
 * function we allow the client program to define its own version of the
 * function that will interpose on our empty default.  This may be useful for
 * clients that wish to display such messages to the user.
 */
/*ARGSUSED*/
/*PRINTFLIKE2*/
void
Perror_printf(struct ps_prochandle *P, const char *format, ...)
{
	/* nothing to do here */
}

/*
 * Default operations.
 */
static ssize_t
Pdefault_ssizet()
{
	return (-1);
}

static int
Pdefault_int()
{
	return (-1);
}

static void
Pdefault_void()
{
}

static void *
Pdefault_voidp()
{
	return (NULL);
}

static const ps_ops_t P_default_ops = {
	.pop_pread	= (pop_pread_t)Pdefault_ssizet,
	.pop_pwrite	= (pop_pwrite_t)Pdefault_ssizet,
	.pop_read_maps	= (pop_read_maps_t)Pdefault_int,
	.pop_read_aux	= (pop_read_aux_t)Pdefault_void,
	.pop_cred	= (pop_cred_t)Pdefault_int,
	.pop_priv	= (pop_priv_t)Pdefault_int,
	.pop_psinfo	= (pop_psinfo_t)Pdefault_voidp,
	.pop_status	= (pop_status_t)Pdefault_void,
	.pop_lstatus	= (pop_lstatus_t)Pdefault_voidp,
	.pop_lpsinfo	= (pop_lpsinfo_t)Pdefault_voidp,
	.pop_fini	= (pop_fini_t)Pdefault_void,
	.pop_platform	= (pop_platform_t)Pdefault_voidp,
	.pop_uname	= (pop_uname_t)Pdefault_int,
	.pop_zonename	= (pop_zonename_t)Pdefault_voidp,
	.pop_execname	= (pop_execname_t)Pdefault_voidp,
	.pop_secflags	= (pop_secflags_t)Pdefault_int,
#if defined(__i386) || defined(__amd64)
	.pop_ldt	= (pop_ldt_t)Pdefault_int
#endif
};

/*
 * Initialize the destination ops vector with functions from the source.
 * Functions which are NULL in the source ops vector are set to corresponding
 * default function in the destination vector.
 */
void
Pinit_ops(ps_ops_t *dst, const ps_ops_t *src)
{
	*dst = P_default_ops;

	if (src->pop_pread != NULL)
		dst->pop_pread = src->pop_pread;
	if (src->pop_pwrite != NULL)
		dst->pop_pwrite = src->pop_pwrite;
	if (src->pop_read_maps != NULL)
		dst->pop_read_maps = src->pop_read_maps;
	if (src->pop_read_aux != NULL)
		dst->pop_read_aux = src->pop_read_aux;
	if (src->pop_cred != NULL)
		dst->pop_cred = src->pop_cred;
	if (src->pop_priv != NULL)
		dst->pop_priv = src->pop_priv;
	if (src->pop_psinfo != NULL)
		dst->pop_psinfo = src->pop_psinfo;
	if (src->pop_status != NULL)
		dst->pop_status = src->pop_status;
	if (src->pop_lstatus != NULL)
		dst->pop_lstatus = src->pop_lstatus;
	if (src->pop_lpsinfo != NULL)
		dst->pop_lpsinfo = src->pop_lpsinfo;
	if (src->pop_fini != NULL)
		dst->pop_fini = src->pop_fini;
	if (src->pop_platform != NULL)
		dst->pop_platform = src->pop_platform;
	if (src->pop_uname != NULL)
		dst->pop_uname = src->pop_uname;
	if (src->pop_zonename != NULL)
		dst->pop_zonename = src->pop_zonename;
	if (src->pop_execname != NULL)
		dst->pop_execname = src->pop_execname;
	if (src->pop_secflags != NULL)
		dst->pop_secflags = src->pop_secflags;
#if defined(__i386) || defined(__amd64)
	if (src->pop_ldt != NULL)
		dst->pop_ldt = src->pop_ldt;
#endif
}
