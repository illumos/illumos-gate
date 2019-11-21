// SPDX-License-Identifier: MIT
// Copyright (C) 2018 Luc Van Oostenryck

#include "utils.h"
#include "allocate.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>


void *xmemdup(const void *src, size_t len)
{
	return memcpy(__alloc_bytes(len), src, len);
}

char *xstrdup(const char *src)
{
	return xmemdup(src, strlen(src) + 1);
}

char *xvasprintf(const char *fmt, va_list ap)
{
	va_list ap2;
	char *str;
	int n;

	va_copy(ap2, ap);
	n = vsnprintf(NULL, 0, fmt, ap2) + 1;
	va_end(ap2);

	str = __alloc_bytes(n);
	vsnprintf(str, n, fmt, ap);

	return str;
}

char *xasprintf(const char *fmt, ...)
{
	va_list ap;
	char *str;

	va_start(ap, fmt);
	str = xvasprintf(fmt, ap);
	va_end(ap);

	return str;
}
