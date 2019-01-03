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
 * Copyright 2019, Joyent, Inc.
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
typedef struct custr_alloc_ops custr_alloc_ops_t;
typedef struct custr_alloc custr_alloc_t;

/*
 * A custom allocator instance.  To use a custom allocator, the user provides
 * the memory for a given custr_alloc_t and calls custr_alloc_init() with the
 * address of the instance to initialize it.  custr_alloc_init() will invoke
 * the init op (if defined) with any additional arguments.  The user can then
 * save any desired state for the allocator instance in cua_arg.  If a
 * custom allocator instance needs to do any cleanup after it's no longer
 * needed, it should also define the fini op and invoke custr_alloc_fini() to
 * do the cleanup.
 */
#define	CUSTR_VERSION 1
struct custr_alloc {
	uint_t			cua_version;
	const custr_alloc_ops_t	*cua_ops;
	void			*cua_arg;
};

struct custr_alloc_ops {
	/*
	 * Optional allocator constructor.  Returns 0 on success, -1
	 * on failure (and should set errno on failure).
	 */
	int (*custr_ao_init)(custr_alloc_t *, va_list);
	/*
	 * Optional allocator destructor.
	 */
	void (*custr_ao_fini)(custr_alloc_t *);
	/*
	 * Returns at least size_t bytes of allocated memory, or NULL.
	 * It should also set errno on failure.
	 */
	void *(*custr_ao_alloc)(custr_alloc_t *, size_t);
	/*
	 * Free the memory previously allocated with custr_ao_alloc.
	 */
	void (*custr_ao_free)(custr_alloc_t *, void *, size_t);
};

/*
 * Initializes a custr allocator.  custr_alloc_t->cua_version should be set to
 * CUSTR_VERSION prior to calling custr_alloc_init().  Both the custr_ao_alloc
 * and custr_ao_free functions must be defined in custr_alloc_ops_t (the
 * init and fini functions are both optional).  If an init function is
 * provided, it will be called with a va_list parameter initialized to
 * point to any arguments after the custr_alloc_ops_t * argument.
 *
 * If cua_version is not CUSTR_VERSION, or if the custr_ao_alloc or
 * custr_ao_free functions are missing, -1 is returned and errno is set to
 * EINVAL.  If an init function was given and it fails (returns -1 -- see
 * the struct custr_alloc_ops definition aboive), -1 is returned and any
 * value of errno set by the init function is left unchanged.
 *
 * On success, 0 is returned.
 */
int custr_alloc_init(custr_alloc_t *, const custr_alloc_ops_t *, ...);

/*
 * If a fini function was given in the custr_alloc_init() call that initalized
 * the given custr_alloc_t instance, it is called to perform any custom
 * cleanup needed.
 */
void custr_alloc_fini(custr_alloc_t *);

/*
 * Allocate and free a "custr_t" dynamic string object.  Returns 0 on success
 * and -1 otherwise.
 */
int custr_alloc(custr_t **);
int custr_xalloc(custr_t **, custr_alloc_t *);
void custr_free(custr_t *);

/*
 * Allocate a "custr_t" dynamic string object that operates on a fixed external
 * buffer.
 */
int custr_alloc_buf(custr_t **, void *, size_t);

/*
 * Like custr_alloc_buf(), except the given allocator is used to allocate
 * the custr_t * instance (but still uses a fixed external buffer for the
 * string contents).
 */
int custr_xalloc_buf(custr_t **, void *, size_t, custr_alloc_t *);

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
