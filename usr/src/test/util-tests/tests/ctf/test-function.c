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
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/types.h>
#include <string.h>

/*
 * Test various function and function pointer cases.
 */

void
simple_func(void)
{
}

void
one(int v)
{
}

void
two(int v, const char *a)
{
}

void
three(int v, const char *a, float b)
{
}

const char *
noarg(void)
{
	return ("hello, world");
}

const char *
argument(uintptr_t base)
{
	return ((const char *)(base + 1));
}

void
vararg(const char *foo, ...)
{

}

uintptr_t
vararg_ret(const char *foo, ...)
{
	return ((uintptr_t)foo);
}

int
vla1(int n, int arr[n])
{
	return (arr[1]);
}

int
vla2(int n, int arr[n][n])
{
	return (arr[1][2]);
}

int
vla3(int n, int arr[n][7])
{
	return (arr[1][2]);
}

int
vla4(int n, int arr[23][n])
{
	return (arr[1][2]);
}

int
vla5(int a, int b, int arr[a][3][b])
{
	return (arr[1][2][3]);
}

int
vla6(int a, int b, int arr[a][b][4])
{
	return (arr[1][2][3]);
}

typedef int (*strfunc_t)(const char *, const char *);
typedef void (*vararg_t)(const char *, ...);

strfunc_t s = strcmp;
vararg_t v = vararg;
