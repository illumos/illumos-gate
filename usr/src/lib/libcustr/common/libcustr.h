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
 * Copyright 2018, Joyent, Inc.
 */

#ifndef _LIBCUSTR_H
#define	_LIBCUSTR_H

#include <stdarg.h>
#include <sys/types.h>

/* dynamic string utilities */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct custr custr_t;

/*
 * Allocate and free a "custr_t" dynamic string object.  Returns 0 on success
 * and -1 otherwise.
 */
int custr_alloc(custr_t **);
void custr_free(custr_t *);

/*
 * Allocate a "custr_t" dynamic string object that operates on a fixed external
 * buffer.
 */
int custr_alloc_buf(custr_t **, void *, size_t);

/*
 * Append a single character, or a NUL-terminated string of characters, to a
 * dynamic string.  Returns 0 on success and -1 otherwise.  The dynamic string
 * will be unmodified if the function returns -1.
 */
int custr_appendc(custr_t *, char);
int custr_append(custr_t *, const char *);

/*
 * Append a format string and arguments as though the contents were being parsed
 * through snprintf. Returns 0 on success and -1 otherwise.  The dynamic string
 * will be unmodified if the function returns -1.
 */
int custr_append_printf(custr_t *, const char *, ...);
int custr_append_vprintf(custr_t *, const char *, va_list);

/*
 * Determine the length in bytes, not including the NUL terminator, of the
 * dynamic string.
 */
size_t custr_len(custr_t *);

/*
 * Clear the contents of a dynamic string.  Does not free the underlying
 * memory.
 */
void custr_reset(custr_t *);

/*
 * Retrieve a const pointer to a NUL-terminated string version of the contents
 * of the dynamic string.  Storage for this string should not be freed, and
 * the pointer will be invalidated by any mutations to the dynamic string.
 */
const char *custr_cstr(custr_t *str);

#ifdef __cplusplus
}
#endif

#endif /* _LIBCUSTR_H */
