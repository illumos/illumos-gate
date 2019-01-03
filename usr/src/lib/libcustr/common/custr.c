/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * String utility functions with dynamic memory management.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/debug.h>

#include "libcustr.h"

/*
 * libcustr is used by some things in usr/src/tools.  If we are building
 * on an older platform, __unused might not be defined on the build host.
 * We define it here if needed.
 */
#ifndef __unused
#if __GNUC_VERSION >= 20700
#define	__unused __attribute__((_unused__))
#else
#define	__unused
#endif /* __GNUC_VERSION */
#endif /* __unused */

typedef enum {
	CUSTR_FIXEDBUF	= 0x01
} custr_flags_t;

struct custr {
	size_t cus_strlen;
	size_t cus_datalen;
	char *cus_data;
	custr_flags_t cus_flags;
	custr_alloc_t *cus_alloc;
};
#define	CUSTR_ALLOC(_cus, _len) \
	(_cus)->cus_alloc->cua_ops->custr_ao_alloc((_cus)->cus_alloc, (_len))
#define	CUSTR_FREE(_cus, _p, _len) \
	(_cus)->cus_alloc->cua_ops->custr_ao_free((_cus)->cus_alloc, \
	(_p), (_len))

#define	STRING_CHUNK_SIZE	64

static void *custr_def_alloc(custr_alloc_t *, size_t);
static void custr_def_free(custr_alloc_t *, void *, size_t);

static custr_alloc_ops_t custr_alloc_ops_default = {
	NULL,			/* custr_ao_init */
	NULL,			/* custr_ao_fini */
	custr_def_alloc,	/* custr_ao_alloc */
	custr_def_free		/* custr_ao_free */
};

static custr_alloc_t custr_alloc_default = {
	CUSTR_VERSION,			/* cua_version */
	&custr_alloc_ops_default,	/* cua_ops */
	NULL				/* cua_arg */
};

void
custr_reset(custr_t *cus)
{
	if (cus->cus_data == NULL)
		return;

	cus->cus_strlen = 0;
	cus->cus_data[0] = '\0';
}

size_t
custr_len(custr_t *cus)
{
	return (cus->cus_strlen);
}

const char *
custr_cstr(custr_t *cus)
{
	if (cus->cus_data == NULL) {
		VERIFY(cus->cus_strlen == 0);
		VERIFY(cus->cus_datalen == 0);

		/*
		 * This function should never return NULL.  If no buffer has
		 * been allocated, return a pointer to a zero-length string.
		 */
		return ("");
	}
	return (cus->cus_data);
}

int
custr_append_vprintf(custr_t *cus, const char *fmt, va_list ap)
{
	int len = vsnprintf(NULL, 0, fmt, ap);
	size_t chunksz = STRING_CHUNK_SIZE;

	if (len == -1)
		return (len);

	while (chunksz < len) {
		chunksz *= 2;
	}

	if (len + cus->cus_strlen + 1 >= cus->cus_datalen) {
		char *new_data;
		size_t new_datalen = cus->cus_datalen + chunksz;

		if (cus->cus_flags & CUSTR_FIXEDBUF) {
			errno = EOVERFLOW;
			return (-1);
		}

		/*
		 * Allocate replacement memory:
		 */
		if ((new_data = CUSTR_ALLOC(cus, new_datalen)) == NULL) {
			return (-1);
		}

		/*
		 * Copy existing data into replacement memory and free
		 * the old memory.
		 */
		if (cus->cus_data != NULL) {
			(void) memcpy(new_data, cus->cus_data,
			    cus->cus_strlen + 1);
			CUSTR_FREE(cus, cus->cus_data, cus->cus_datalen);
		}

		/*
		 * Swap in the replacement buffer:
		 */
		cus->cus_data = new_data;
		cus->cus_datalen = new_datalen;
	}
	/*
	 * Append new string to existing string:
	 */
	len = vsnprintf(cus->cus_data + cus->cus_strlen,
	    (uintptr_t)cus->cus_data - (uintptr_t)cus->cus_strlen, fmt, ap);
	if (len == -1)
		return (len);
	cus->cus_strlen += len;

	return (0);
}

int
custr_appendc(custr_t *cus, char newc)
{
	return (custr_append_printf(cus, "%c", newc));
}

int
custr_append_printf(custr_t *cus, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = custr_append_vprintf(cus, fmt, ap);
	va_end(ap);

	return (ret);
}

int
custr_append(custr_t *cus, const char *name)
{
	return (custr_append_printf(cus, "%s", name));
}

int
custr_alloc_init(custr_alloc_t *cua, const custr_alloc_ops_t *ops, ...)
{
	int ret = 0;

	if (cua->cua_version != CUSTR_VERSION || ops->custr_ao_alloc == NULL ||
	    ops->custr_ao_free == NULL) {
		errno = EINVAL;
		return (-1);
	}

	cua->cua_ops = ops;
	cua->cua_arg = NULL;

	if (ops->custr_ao_init != NULL) {
		va_list ap;

		va_start(ap, ops);
		ret = ops->custr_ao_init(cua, ap);
		va_end(ap);
	}

	return ((ret == 0) ? 0 : -1);
}

void
custr_alloc_fini(custr_alloc_t *cua)
{
	if (cua->cua_ops->custr_ao_fini != NULL)
		cua->cua_ops->custr_ao_fini(cua);
}

int
custr_xalloc(custr_t **cus, custr_alloc_t *cao)
{
	custr_t *t;

	if (cao == NULL)
		cao = &custr_alloc_default;

	if ((t = cao->cua_ops->custr_ao_alloc(cao, sizeof (*t))) == NULL) {
		*cus = NULL;
		return (-1);
	}
	(void) memset(t, 0, sizeof (*t));

	t->cus_alloc = cao;
	*cus = t;
	return (0);
}

int
custr_alloc(custr_t **cus)
{
	return (custr_xalloc(cus, NULL));
}

int
custr_xalloc_buf(custr_t **cus, void *buf, size_t buflen, custr_alloc_t *cao)
{
	int ret;

	if (buflen == 0 || buf == NULL) {
		errno = EINVAL;
		return (-1);
	}

	if ((ret = custr_xalloc(cus, cao)) != 0)
		return (ret);

	(*cus)->cus_data = buf;
	(*cus)->cus_datalen = buflen;
	(*cus)->cus_strlen = 0;
	(*cus)->cus_flags = CUSTR_FIXEDBUF;
	(*cus)->cus_data[0] = '\0';

	return (0);
}

int
custr_alloc_buf(custr_t **cus, void *buf, size_t buflen)
{
	return (custr_xalloc_buf(cus, buf, buflen, NULL));
}

void
custr_free(custr_t *cus)
{
	custr_alloc_t *cao;

	if (cus == NULL)
		return;

	if ((cus->cus_flags & CUSTR_FIXEDBUF) == 0)
		CUSTR_FREE(cus, cus->cus_data, cus->cus_datalen);

	cao = cus->cus_alloc;
	cao->cua_ops->custr_ao_free(cao, cus, sizeof (*cus));
}

/*ARGSUSED*/
static void *
custr_def_alloc(custr_alloc_t *cao __unused, size_t len)
{
	return (malloc(len));
}

/*ARGSUSED*/
static void
custr_def_free(custr_alloc_t *cao __unused, void *p, size_t len __unused)
{
	free(p);
}
