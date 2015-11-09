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
#if !defined(DIS_STANDALONE) || defined(__s390) || defined(__s390x)
extern dis_arch_t dis_arch_s390;
#endif

static dis_arch_t *dis_archs[] = {
#if !defined(DIS_STANDALONE) || defined(__i386) || defined(__amd64)
	&dis_arch_i386,
#endif
#if !defined(DIS_STANDALONE) || defined(__sparc)
	&dis_arch_sparc,
#endif
#if !defined(DIS_STANDALONE) || defined(__s390) || defined(__s390x)
	&dis_arch_s390,
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
	if (dhp->dh_arch->da_handle_detach != NULL)
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
	if (arch->da_handle_attach != NULL &&
	    arch->da_handle_attach(dhp) != 0) {
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

/*
 * On some instruction sets (e.g., x86), we have no choice except to
 * disassemble everything from the start of the symbol, and stop when we
 * have reached our instruction address.  If we're not in the middle of a
 * known symbol, then we return the same address to indicate failure.
 */
static uint64_t
dis_generic_previnstr(dis_handle_t *dhp, uint64_t pc, int n)
{
	uint64_t *hist, addr, start;
	int cur, nseen;
	uint64_t res = pc;

	if (n <= 0)
		return (pc);

	if (dhp->dh_lookup(dhp->dh_data, pc, NULL, 0, &start, NULL) != 0 ||
	    start == pc)
		return (res);

	hist = dis_zalloc(sizeof (uint64_t) * n);

	for (cur = 0, nseen = 0, addr = start; addr < pc; addr = dhp->dh_addr) {
		hist[cur] = addr;
		cur = (cur + 1) % n;
		nseen++;

		/* if we cannot make forward progress, give up */
		if (dis_disassemble(dhp, addr, NULL, 0) != 0)
			goto done;
	}

	if (addr != pc) {
		/*
		 * We scanned past %pc, but didn't find an instruction that
		 * started at %pc.  This means that either the caller specified
		 * an invalid address, or we ran into something other than code
		 * during our scan.  Virtually any combination of bytes can be
		 * construed as a valid Intel instruction, so any non-code bytes
		 * we encounter will have thrown off the scan.
		 */
		goto done;
	}

	res = hist[(cur + n - MIN(n, nseen)) % n];

done:
	dis_free(hist, sizeof (uint64_t) * n);
	return (res);
}

/*
 * Return the nth previous instruction's address.  Return the same address
 * to indicate failure.
 */
uint64_t
dis_previnstr(dis_handle_t *dhp, uint64_t pc, int n)
{
	if (dhp->dh_arch->da_previnstr == NULL)
		return (dis_generic_previnstr(dhp, pc, n));

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

static int
dis_generic_instrlen(dis_handle_t *dhp, uint64_t pc)
{
	if (dis_disassemble(dhp, pc, NULL, 0) != 0)
		return (-1);

	return (dhp->dh_addr - pc);
}

int
dis_instrlen(dis_handle_t *dhp, uint64_t pc)
{
	if (dhp->dh_arch->da_instrlen == NULL)
		return (dis_generic_instrlen(dhp, pc));

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
