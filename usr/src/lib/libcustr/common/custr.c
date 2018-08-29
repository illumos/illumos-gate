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
 * Copyright 2018 Joyent, Inc.
 */

#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/debug.h>

#include "libcustr.h"

typedef enum {
	CUSTR_FIXEDBUF	= 0x01
} custr_flags_t;

struct custr {
	size_t cus_strlen;
	size_t cus_datalen;
	char *cus_data;
	custr_flags_t cus_flags;
};

#define	STRING_CHUNK_SIZE	64

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
		if ((new_data = malloc(new_datalen)) == NULL) {
			return (-1);
		}

		/*
		 * Copy existing data into replacement memory and free
		 * the old memory.
		 */
		if (cus->cus_data != NULL) {
			(void) memcpy(new_data, cus->cus_data,
			    cus->cus_strlen + 1);
			free(cus->cus_data);
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
custr_alloc(custr_t **cus)
{
	custr_t *t;

	if ((t = calloc(1, sizeof (*t))) == NULL) {
		*cus = NULL;
		return (-1);
	}

	*cus = t;
	return (0);
}

int
custr_alloc_buf(custr_t **cus, void *buf, size_t buflen)
{
	int ret;

	if (buflen == 0 || buf == NULL) {
		errno = EINVAL;
		return (-1);
	}

	if ((ret = custr_alloc(cus)) != 0)
		return (ret);

	(*cus)->cus_data = buf;
	(*cus)->cus_datalen = buflen;
	(*cus)->cus_strlen = 0;
	(*cus)->cus_flags = CUSTR_FIXEDBUF;
	(*cus)->cus_data[0] = '\0';

	return (0);
}

void
custr_free(custr_t *cus)
{
	if (cus == NULL)
		return;

	if ((cus->cus_flags & CUSTR_FIXEDBUF) == 0)
		free(cus->cus_data);
	free(cus);
}
