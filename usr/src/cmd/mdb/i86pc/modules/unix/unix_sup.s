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
 * Copyright 2015 Joyent, Inc.
 */

#if !defined(__lint)
	.file	"unix_sup.s"
#endif /* __lint */

/*
 * Support routines for the unix kmdb module
 */

#include <sys/asm_linkage.h>

#if defined(__lint)

#include <sys/types.h>

ulong_t
kmdb_unix_getcr0(void)
{ return (0); }

ulong_t
kmdb_unix_getcr4(void)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)
	ENTRY(kmdb_unix_getcr0)
	movq %cr0, %rax
	ret
	SET_SIZE(kmdb_unix_getcr0)

	ENTRY(kmdb_unix_getcr4)
	movq %cr4, %rax
	ret
	SET_SIZE(kmdb_unix_getcr4)

#elif defined (__i386)
	ENTRY(kmdb_unix_getcr0)
	movl %cr0, %eax
	ret
	SET_SIZE(kmdb_unix_getcr0)

	ENTRY(kmdb_unix_getcr4)
	movl %cr4, %eax
	ret
	SET_SIZE(kmdb_unix_getcr4)

#endif	/* __i386 */

#endif /* __lint */
