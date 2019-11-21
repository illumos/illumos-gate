#ifndef UTILS_H
#define UTILS_H

///
// Miscellaneous utilities
// -----------------------

#include <stddef.h>
#include <stdarg.h>

///
// duplicate a memory buffer in a newly allocated buffer.
// @src: a pointer to the memory buffer to be duplicated
// @len: the size of the memory buffer to be duplicated
// @return: a pointer to a copy of @src allocated via
//	:func:`__alloc_bytes()`.
void *xmemdup(const void *src, size_t len);

///
// duplicate a null-terminated string in a newly allocated buffer.
// @src: a pointer to string to be duplicated
// @return: a pointer to a copy of @str allocated via
//	:func:`__alloc_bytes()`.
char *xstrdup(const char *src);

///
// printf to allocated string
// @fmt: the format followed by its arguments.
// @return: the allocated & formatted string.
// This function is similar to asprintf() but the resulting string
// is allocated with __alloc_bytes().
char *xasprintf(const char *fmt, ...);

///
// vprintf to allocated string
// @fmt: the format
// @ap: the variadic arguments
// @return: the allocated & formatted string.
// This function is similar to asprintf() but the resulting string
// is allocated with __alloc_bytes().
char *xvasprintf(const char *fmt, va_list ap);

#endif
