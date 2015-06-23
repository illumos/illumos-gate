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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Joshua M. Clulow <josh@sysmgr.org>
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#include <libdisasm.h>
#include <stdlib.h>
#ifdef DIS_STANDALONE
#include <mdb/mdb_modapi.h>
#define	_MDB
#include <mdb/mdb_io.h>
#else
#include <stdio.h>
#endif

#include "libdisasm_impl.h"

static int _dis_errno;

/*
 * If we're building the standalone library, then we only want to
 * include support for disassembly of the native architecture.
 * The regular shared library should include support for all
 * architectures.
 */
#if !defined(DIS_STANDALONE) || defined(__i386) || defined(__amd64)
extern dis_arch_t dis_arch_i386;
#endif
#if !defined(DIS_STANDALONE) || defined(__sparc)
extern dis_arch_t dis_arch_sparc;
#endif

static dis_arch_t *dis_archs[] = {
#if !defined(DIS_STANDALONE) || defined(__i386) || defined(__amd64)
	&dis_arch_i386,
#endif
#if !defined(DIS_STANDALONE) || defined(__sparc)
	&dis_arch_sparc,
#endif
	NULL
};

/*
 * For the standalone library, we need to link against mdb's malloc/free.
 * Otherwise, use the standard malloc/free.
 */
#ifdef DIS_STANDALONE
void *
dis_zalloc(size_t bytes)
{
	return (mdb_zalloc(bytes, UM_SLEEP));
}

void
dis_free(void *ptr, size_t bytes)
{
	mdb_free(ptr, bytes);
}
#else
void *
dis_zalloc(size_t bytes)
{
	return (calloc(1, bytes));
}

/*ARGSUSED*/
void
dis_free(void *ptr, size_t bytes)
{
	free(ptr);
}
#endif

int
dis_seterrno(int error)
{
	_dis_errno = error;
	return (-1);
}

int
dis_errno(void)
{
	return (_dis_errno);
}

const char *
dis_strerror(int error)
{
	switch (error) {
	case E_DIS_NOMEM:
		return ("out of memory");
	case E_DIS_INVALFLAG:
		return ("invalid flags for this architecture");
	case E_DIS_UNSUPARCH:
		return ("unsupported machine architecture");
	default:
		return ("unknown error");
	}
}

void
dis_set_data(dis_handle_t *dhp, void *data)
{
	dhp->dh_data = data;
}

void
dis_flags_set(dis_handle_t *dhp, int f)
{
	dhp->dh_flags |= f;
}

void
dis_flags_clear(dis_handle_t *dhp, int f)
{
	dhp->dh_flags &= ~f;
}

void
dis_handle_destroy(dis_handle_t *dhp)
{
	dhp->dh_arch->da_handle_detach(dhp);
	dis_free(dhp, sizeof (dis_handle_t));
}

dis_handle_t *
dis_handle_create(int flags, void *data, dis_lookup_f lookup_func,
    dis_read_f read_func)
{
	dis_handle_t *dhp;
	dis_arch_t *arch = NULL;
	int i;

	/* Select an architecture based on flags */
	for (i = 0; dis_archs[i] != NULL; i++) {
		if (dis_archs[i]->da_supports_flags(flags)) {
			arch = dis_archs[i];
			break;
		}
	}
	if (arch == NULL) {
		(void) dis_seterrno(E_DIS_UNSUPARCH);
		return (NULL);
	}

	if ((dhp = dis_zalloc(sizeof (dis_handle_t))) == NULL) {
		(void) dis_seterrno(E_DIS_NOMEM);
		return (NULL);
	}
	dhp->dh_arch = arch;
	dhp->dh_lookup = lookup_func;
	dhp->dh_read = read_func;
	dhp->dh_flags = flags;
	dhp->dh_data = data;

	/*
	 * Allow the architecture-specific code to allocate
	 * its private data.
	 */
	if (arch->da_handle_attach(dhp) != 0) {
		dis_free(dhp, sizeof (dis_handle_t));
		/* dis errno already set */
		return (NULL);
	}

	return (dhp);
}

int
dis_disassemble(dis_handle_t *dhp, uint64_t addr, char *buf, size_t buflen)
{
	return (dhp->dh_arch->da_disassemble(dhp, addr, buf, buflen));
}

uint64_t
dis_previnstr(dis_handle_t *dhp, uint64_t pc, int n)
{
	return (dhp->dh_arch->da_previnstr(dhp, pc, n));
}

int
dis_min_instrlen(dis_handle_t *dhp)
{
	return (dhp->dh_arch->da_min_instrlen(dhp));
}

int
dis_max_instrlen(dis_handle_t *dhp)
{
	return (dhp->dh_arch->da_max_instrlen(dhp));
}

int
dis_instrlen(dis_handle_t *dhp, uint64_t pc)
{
	return (dhp->dh_arch->da_instrlen(dhp, pc));
}

int
dis_vsnprintf(char *restrict s, size_t n, const char *restrict format,
    va_list args)
{
#ifdef DIS_STANDALONE
	return (mdb_iob_vsnprintf(s, n, format, args));
#else
	return (vsnprintf(s, n, format, args));
#endif
}

int
dis_snprintf(char *restrict s, size_t n, const char *restrict format, ...)
{
	va_list args;

	va_start(args, format);
	n = dis_vsnprintf(s, n, format, args);
	va_end(args);

	return (n);
}
