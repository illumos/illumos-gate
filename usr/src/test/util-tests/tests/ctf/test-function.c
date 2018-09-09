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
 * Copyright (c) 2019, Joyent, Inc.
 */

#include <sys/types.h>
#include <string.h>

/*
 * Test various function and function pointer cases.
 */

static void
simple_func(void)
{
}

static void
one(int v)
{
}

static void
two(int v, const char *a)
{
}

static void
three(int v, const char *a, float b)
{
}

static const char *
noarg(void)
{
	return ("hello, world");
}

static const char *
argument(uintptr_t base)
{
	return ((const char *)(base + 1));
}

static void
vararg(const char *foo, ...)
{

}

static uintptr_t
vararg_ret(const char *foo, ...)
{
	return ((uintptr_t)foo);
}

typedef int (*strfunc_t)(const char *, const char *);
typedef void (*vararg_t)(const char *, ...);

strfunc_t s = strcmp;
vararg_t v = vararg;
