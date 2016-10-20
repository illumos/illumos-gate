/* The meat of this file is a copy of the FreeBSD sys/link_set.h */
/*
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 1999 John D. Polstra
 * Copyright (c) 1999,2001 Peter Wemm <peter@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <stdio.h>

#define	MAKE_SET(set, sym)					\
	__asm__(".globl __start_set_" #set);			\
	__asm__(".globl __stop_set_" #set);			\
	static __attribute__((section("set_" #set), used))	\
	void const *__set_##set##_sym_##sym = &(sym)

/*
 * Initialize before referring to a given linker set.
 */
#define	SET_DECLARE(set, ptype)						\
	extern  __attribute__((weak)) ptype *__start_set_ ## set;	\
	extern __attribute__((weak)) ptype *__stop_set_ ## set

#define	SET_BEGIN(set)	(&__start_set_ ## set)
#define	SET_LIMIT(set)	(&__stop_set_ ## set)

/*
 * Iterate over all the elements of a set.
 *
 * Sets always contain addresses of things, and "pvar" points to words
 * containing those addresses.  Thus is must be declared as "type **pvar",
 * and the address of each set item is obtained inside the loop by "*pvar".
 */
#define	SET_FOREACH(pvar, set)						\
	for (pvar = SET_BEGIN(set); pvar < SET_LIMIT(set); pvar++)

#define	SET_ITEM(set, i)						\
	((SET_BEGIN(set))[i])

/*
 * Provide a count of the items in a set.
 */
#define	SET_COUNT(set)							\
	(SET_LIMIT(set) - SET_BEGIN(set))

struct foo {
	char buf[128];
};

SET_DECLARE(foo, struct foo);

struct foo a = { "foo" };
struct foo b = { "bar" };
struct foo c = { "baz" };

MAKE_SET(foo, a);
MAKE_SET(foo, b);
MAKE_SET(foo, c);

int
main(int __attribute__((unused)) argc, char __attribute__((unused)) **argv)
{
	struct foo **c;
	int i = 0;

	printf("Set count: %d\n", SET_COUNT(foo));


	printf("a: %s\n", ((struct foo *)__set_foo_sym_a)->buf);
	printf("b: %s\n", ((struct foo *)__set_foo_sym_b)->buf);
	printf("c: %s\n", ((struct foo *)__set_foo_sym_c)->buf);

	printf("item(foo, 0): %s\n", SET_ITEM(foo, 0)->buf);
	printf("item(foo, 1): %s\n", SET_ITEM(foo, 1)->buf);
	printf("item(foo, 2): %s\n", SET_ITEM(foo, 2)->buf);

	SET_FOREACH(c, foo) {
		printf("foo[%d]: %s\n", i, (*c)->buf);
		i++;
	}
}
